#!/usr/bin/env bash
# BGP neighbour hot-reload smoke test — the management-plane property that a running
# wren adds and removes BGP neighbours on SIGHUP *without* restarting the daemon or
# disturbing unchanged sessions (extends hot-reload-smoke.sh, which covered only the
# static-route delta). Fully self-contained and rootless, like the bgp-*-smoke.sh
# scripts: it runs inside throwaway `unshare -Urn` namespaces and never touches the
# host's interfaces.
#
# Topology: A (AS 65001) actively dials its neighbours. B (AS 65002, passive) and
# C (AS 65003, passive) wait to be dialled. B originates 10.20.0.0/24 and C originates
# 10.30.0.0/24. A starts configured with B only.
#
#   phase 1 (baseline): A<->B Established, A has learned 10.20.0.0/24; C is unknown.
#   phase 2 (ADD C):    rewrite A's config to add neighbour C, SIGHUP A. We assert
#                       C Establishes AND A learns 10.30.0.0/24, while B stays
#                       Established and 10.20.0.0/24 is undisturbed.
#   phase 3 (REMOVE C): rewrite A's config back to B-only, SIGHUP A. We assert C's
#                       session tears down (gone from `show bgp neighbors`) and
#                       10.30.0.0/24 is withdrawn, while B stays Established and
#                       10.20.0.0/24 is still there.
#
# Usage:  bash scripts/bgp-hot-reload-smoke.sh
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
WREN="$REPO/target/debug/wren"

if [[ ! -x "$WREN" ]]; then
  echo "building wren (debug) ..."
  (cd "$REPO" && cargo build -p wren-daemon)
fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# A's baseline config: active eBGP to B only, no neighbour C yet.
cat >"$WORK/a.toml" <<EOF
router-id = "10.0.0.1"
[bgp]
enabled  = true
local-as = 65001
[[bgp.neighbor]]
address   = "10.0.0.2"
remote-as = 65002
EOF

# A's config with neighbour C ADDED (B unchanged, so its session is untouched).
cat >"$WORK/a-add-c.toml" <<EOF
router-id = "10.0.0.1"
[bgp]
enabled  = true
local-as = 65001
[[bgp.neighbor]]
address   = "10.0.0.2"
remote-as = 65002
[[bgp.neighbor]]
address   = "10.0.1.2"
remote-as = 65003
EOF

# B: passive, originates 10.20.0.0/24.
cat >"$WORK/b.toml" <<EOF
router-id = "10.0.0.2"
[bgp]
enabled   = true
local-as  = 65002
network   = ["10.20.0.0/24"]
[[bgp.neighbor]]
address   = "10.0.0.1"
remote-as = 65001
passive   = true
EOF

# C: passive, originates 10.30.0.0/24.
cat >"$WORK/c.toml" <<EOF
router-id = "10.0.1.2"
[bgp]
enabled   = true
local-as  = 65003
network   = ["10.30.0.0/24"]
[[bgp.neighbor]]
address   = "10.0.1.1"
remote-as = 65001
passive   = true
EOF

export WREN WORK
unshare -Urn bash -c '
  set -e
  ip link set lo up
  # Two peer namespaces (B and C), each an idle `sleep` holding a fresh net ns.
  setsid unshare -n -- sleep 60 & BPID=$!
  setsid unshare -n -- sleep 60 & CPID=$!
  sleep 0.3

  # A<->B link.
  ip link add veth0 type veth peer name veth1
  ip link set veth1 netns $BPID
  ip addr add 10.0.0.1/24 dev veth0; ip link set veth0 up
  nsenter -t $BPID -n ip addr add 10.0.0.2/24 dev veth1
  nsenter -t $BPID -n ip link set veth1 up
  nsenter -t $BPID -n ip link set lo up

  # A<->C link.
  ip link add veth2 type veth peer name veth3
  ip link set veth3 netns $CPID
  ip addr add 10.0.1.1/24 dev veth2; ip link set veth2 up
  nsenter -t $CPID -n ip addr add 10.0.1.2/24 dev veth3
  nsenter -t $CPID -n ip link set veth3 up
  nsenter -t $CPID -n ip link set lo up

  # Start A (config: B only), plus B and C (both passive).
  "$WREN" --config "$WORK/a.toml" --backend kernel --socket "$WORK/a.sock" >"$WORK/a.log" 2>&1 & APID=$!
  nsenter -t $BPID -n "$WREN" --config "$WORK/b.toml" --backend kernel --socket "$WORK/b.sock" >"$WORK/b.log" 2>&1 &
  nsenter -t $CPID -n "$WREN" --config "$WORK/c.toml" --backend kernel --socket "$WORK/c.sock" >"$WORK/c.log" 2>&1 &
  sleep 6

  ok=1

  echo "=== phase 1: baseline (A knows only B) ==="
  n1="$("$WREN" --socket "$WORK/a.sock" show bgp neighbors)"; echo "$n1"
  r1="$("$WREN" --socket "$WORK/a.sock" show routes)"
  echo "$n1" | grep -q "10.0.0.2 AS 65002 Established" || { echo "FAIL: B not Established at baseline"; ok=0; }
  echo "$r1" | grep -q "10.20.0.0/24.*proto bgp"       || { echo "FAIL: A has not learned 10.20.0.0/24 at baseline"; ok=0; }
  echo "$n1" | grep -q "10.0.1.2"                       && { echo "FAIL: C present before it was configured"; ok=0; } || true
  echo "$r1" | grep -q "10.30.0.0/24"                   && { echo "FAIL: 10.30.0.0/24 present before C configured"; ok=0; } || true

  # phase 2: ADD neighbour C and SIGHUP.
  cp "$WORK/a-add-c.toml" "$WORK/a.toml"
  echo "=== phase 2: SIGHUP A after ADDING neighbour C ==="
  kill -HUP $APID
  sleep 6
  n2="$("$WREN" --socket "$WORK/a.sock" show bgp neighbors)"; echo "$n2"
  r2="$("$WREN" --socket "$WORK/a.sock" show routes)"
  echo "$n2" | grep -q "10.0.1.2 AS 65003 Established" || { echo "FAIL: added neighbour C did not Establish"; ok=0; }
  echo "$r2" | grep -q "10.30.0.0/24.*proto bgp"       || { echo "FAIL: A did not learn 10.30.0.0/24 from C"; ok=0; }
  # The unchanged neighbour B must be undisturbed.
  echo "$n2" | grep -q "10.0.0.2 AS 65002 Established" || { echo "FAIL: B flapped across the ADD reload"; ok=0; }
  echo "$r2" | grep -q "10.20.0.0/24.*proto bgp"       || { echo "FAIL: B-learned route lost across the ADD reload"; ok=0; }

  # phase 3: REMOVE neighbour C (config back to B-only) and SIGHUP.
  cat >"$WORK/a.toml" <<CFG
router-id = "10.0.0.1"
[bgp]
enabled  = true
local-as = 65001
[[bgp.neighbor]]
address   = "10.0.0.2"
remote-as = 65002
CFG
  echo "=== phase 3: SIGHUP A after REMOVING neighbour C ==="
  kill -HUP $APID
  sleep 4
  n3="$("$WREN" --socket "$WORK/a.sock" show bgp neighbors)"; echo "$n3"
  r3="$("$WREN" --socket "$WORK/a.sock" show routes)"
  echo "$n3" | grep -q "10.0.1.2"                       && { echo "FAIL: C still present after removal"; ok=0; } || true
  echo "$r3" | grep -q "10.30.0.0/24"                   && { echo "FAIL: 10.30.0.0/24 not withdrawn after removal"; ok=0; } || true
  # B must still be up and its route intact.
  echo "$n3" | grep -q "10.0.0.2 AS 65002 Established" || { echo "FAIL: B flapped across the REMOVE reload"; ok=0; }
  echo "$r3" | grep -q "10.20.0.0/24.*proto bgp"       || { echo "FAIL: B-learned route lost across the REMOVE reload"; ok=0; }

  if [[ $ok -ne 1 ]]; then echo "--- A log ---"; cat "$WORK/a.log"; echo "--- C log ---"; cat "$WORK/c.log"; fi
  kill $APID 2>/dev/null || true
  kill $BPID 2>/dev/null || true
  kill $CPID 2>/dev/null || true
  exit $(( ok == 1 ? 0 : 1 ))
'
echo "bgp-hot-reload smoke test: OK"
