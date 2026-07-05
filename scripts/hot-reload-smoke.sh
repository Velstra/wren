#!/usr/bin/env bash
# SIGHUP config hot-reload smoke test — the management-plane property that a
# running wren re-reads its config on SIGHUP and applies the delta *without*
# restarting the daemon or tearing down unaffected protocol sessions. Fully
# self-contained and rootless, like the bgp-*-smoke.sh scripts: it runs inside
# throwaway `unshare -Urn` namespaces and never touches the host's interfaces.
#
# Topology: A (AS 65001, passive) <-eBGP-> B (AS 65002, active). B originates
# 10.20.0.0/24. Once the session is Established and A has learned the route, we
# rewrite A's config file to ADD a static route (keeping the BGP neighbour
# unchanged) and send A a SIGHUP. We assert:
#   * A's BGP session to B is STILL Established after the reload  — an untouched
#     session must not flap;
#   * A still has the BGP-learned 10.20.0.0/24                    — routes learned
#     over that session survive the reload;
#   * A's `show routes` now contains the newly-added static       — the delta was
#     applied live.
#
# Usage:  bash scripts/hot-reload-smoke.sh
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
WREN="$REPO/target/debug/wren"

if [[ ! -x "$WREN" ]]; then
  echo "building wren (debug) ..."
  (cd "$REPO" && cargo build -p wren-daemon)
fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# A's initial config: eBGP to B, no static routes yet.
cat >"$WORK/a.toml" <<EOF
router-id = "10.0.0.1"
[bgp]
enabled  = true
local-as = 65001
[[bgp.neighbor]]
address   = "10.0.0.2"
remote-as = 65002
passive   = true
EOF

# A's reloaded config: identical BGP block (so the session is untouched) plus a
# new static route. Written now, applied only on SIGHUP.
cat >"$WORK/a-reloaded.toml" <<EOF
router-id = "10.0.0.1"
[bgp]
enabled  = true
local-as = 65001
[[bgp.neighbor]]
address   = "10.0.0.2"
remote-as = 65002
passive   = true
[[static]]
prefix = "192.168.99.0/24"
via    = "10.0.0.2"
EOF

cat >"$WORK/b.toml" <<EOF
router-id = "10.0.0.2"
[bgp]
enabled   = true
local-as  = 65002
network   = ["10.20.0.0/24"]
[[bgp.neighbor]]
address   = "10.0.0.1"
remote-as = 65001
EOF

export WREN WORK
unshare -Urn bash -c '
  set -e
  ip link set lo up
  setsid unshare -n -- sleep 40 & BPID=$!
  sleep 0.3
  ip link add veth0 type veth peer name veth1
  ip link set veth1 netns $BPID
  ip addr add 10.0.0.1/24 dev veth0; ip link set veth0 up
  nsenter -t $BPID -n ip addr add 10.0.0.2/24 dev veth1
  nsenter -t $BPID -n ip link set veth1 up
  nsenter -t $BPID -n ip link set lo up

  # Start A (passive) and B (active); let the session come up and the route flow.
  "$WREN" --config "$WORK/a.toml" --backend kernel --socket "$WORK/a.sock" >"$WORK/a.log" 2>&1 & APID=$!
  nsenter -t $BPID -n "$WREN" --config "$WORK/b.toml" --backend kernel --socket "$WORK/b.sock" >"$WORK/b.log" 2>&1 &
  sleep 6

  echo "=== phase 1: before reload (show bgp neighbors on A) ==="
  before="$("$WREN" --socket "$WORK/a.sock" show bgp neighbors)"; echo "$before"
  ok=1
  echo "$before" | grep -q "10.0.0.2 AS 65002 Established" || { echo "FAIL: B not Established before reload"; ok=0; }
  "$WREN" --socket "$WORK/a.sock" show routes | grep -q "10.20.0.0/24.*proto bgp" \
    || { echo "FAIL: A has not learned 10.20.0.0/24 before reload"; ok=0; }
  # The static must NOT be present yet.
  "$WREN" --socket "$WORK/a.sock" show routes | grep -q "192.168.99.0/24" \
    && { echo "FAIL: static present before reload (unexpected)"; ok=0; } || true

  # Swap in the config with the extra static route and SIGHUP A.
  cp "$WORK/a-reloaded.toml" "$WORK/a.toml"
  echo "=== sending SIGHUP to A (pid $APID) ==="
  kill -HUP $APID
  sleep 2

  echo "=== phase 2: after reload (show routes on A) ==="
  routes="$("$WREN" --socket "$WORK/a.sock" show routes)"; echo "$routes"
  echo "=== phase 2: after reload (show bgp neighbors on A) ==="
  after="$("$WREN" --socket "$WORK/a.sock" show bgp neighbors)"; echo "$after"

  # The delta was applied: the new static is in the RIB.
  echo "$routes" | grep -q "192.168.99.0/24.*proto static" \
    || { echo "FAIL: static route not applied on SIGHUP"; ok=0; }
  # The untouched BGP session stayed up across the reload.
  echo "$after"  | grep -q "10.0.0.2 AS 65002 Established" \
    || { echo "FAIL: BGP session flapped across the reload"; ok=0; }
  # And the route learned over it survived.
  echo "$routes" | grep -q "10.20.0.0/24.*proto bgp" \
    || { echo "FAIL: BGP-learned route lost across the reload"; ok=0; }

  if [[ $ok -ne 1 ]]; then echo "--- A log ---"; cat "$WORK/a.log"; fi
  kill $APID  2>/dev/null || true
  kill $BPID  2>/dev/null || true
  exit $(( ok == 1 ? 0 : 1 ))
'
echo "hot-reload smoke test: OK"
