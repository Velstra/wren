#!/usr/bin/env bash
# BGP redistribution smoke test — the router pushes RIB best-path routes into BGP,
# which re-originates them to peers. Fully self-contained and rootless.
#
# Like the other bgp-*-smoke.sh scripts it runs inside throwaway `unshare -Urn`
# namespaces and never touches the host's interfaces or uplink. Per-daemon control
# sockets live under a temp dir (Unix sockets, not the network).
#
# Topology: A (AS 65001, active) <-eBGP-> B (AS 65002, passive). A has a *static*
# route 10.99.0.0/24 in its RIB. Two phases prove the redistribution is what
# carries it into BGP:
#   * phase 1 — A has NO `redistribute`: B must NOT learn 10.99.0.0/24;
#   * phase 2 — A has `redistribute = ["static"]`: B must learn 10.99.0.0/24 via
#     BGP (as-path 65001) and install it into its kernel table `proto bgp`.
#
# This exercises the whole new pipeline: router best-path push → BGP origination
# set → central→session snapshot on Established → UPDATE → peer Loc-RIB + FIB.
#
# Usage:  bash scripts/bgp-redistribute-smoke.sh
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
WREN="$REPO/target/debug/wren"

if [[ ! -x "$WREN" ]]; then
  echo "building wren (debug) ..."
  (cd "$REPO" && cargo build -p wren-daemon)
fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# B is identical across both phases.
cat >"$WORK/b.toml" <<EOF
router-id = "10.0.0.2"
[bgp]
enabled   = true
local-as  = 65002
[[bgp.neighbor]]
address   = "10.0.0.1"
remote-as = 65001
passive   = true
EOF

# A phase 1: a static route, but no redistribution.
cat >"$WORK/a1.toml" <<EOF
router-id = "10.0.0.1"
[[static]]
prefix = "10.99.0.0/24"
via    = "10.0.0.2"
[bgp]
enabled  = true
local-as = 65001
[[bgp.neighbor]]
address   = "10.0.0.2"
remote-as = 65002
EOF

# A phase 2: the same static, now redistributed into BGP.
cat >"$WORK/a2.toml" <<EOF
router-id = "10.0.0.1"
[[static]]
prefix = "10.99.0.0/24"
via    = "10.0.0.2"
[bgp]
enabled      = true
local-as     = 65001
redistribute = ["static"]
[[bgp.neighbor]]
address   = "10.0.0.2"
remote-as = 65002
EOF

export WREN WORK
unshare -Urn bash -c '
  set -e
  ip link set lo up
  setsid unshare -n -- sleep 60 & BPID=$!
  sleep 0.3
  ip link add veth0 type veth peer name veth1
  ip link set veth1 netns $BPID
  ip addr add 10.0.0.1/24 dev veth0; ip link set veth0 up
  nsenter -t $BPID -n ip addr add 10.0.0.2/24 dev veth1
  nsenter -t $BPID -n ip link set veth1 up
  nsenter -t $BPID -n ip link set lo up

  run_phase() {
    acfg="$1"; label="$2"
    nsenter -t $BPID -n "$WREN" --config "$WORK/b.toml" --backend kernel --socket "$WORK/b.sock" >"$WORK/b.log" 2>&1 &
    apid=$!
    "$WREN" --config "$acfg" --backend kernel --socket "$WORK/a.sock" >"$WORK/a.log" 2>&1 &
    bpid_a=$!
    sleep 6
    echo "=== phase $label: wren show bgp (on B) ==="
    nsenter -t $BPID -n "$WREN" --socket "$WORK/b.sock" show bgp || true
    echo "=== phase $label: ip route (on B) ==="
    nsenter -t $BPID -n ip route show proto bgp || true
    kill $apid $bpid_a 2>/dev/null || true
    sleep 0.5
  }

  ok=1

  # Phase 1: no redistribution — B must not see the static.
  run_phase "$WORK/a1.toml" "1 (no redistribute)" > "$WORK/p1.out" 2>&1
  cat "$WORK/p1.out"
  if grep -q "10.99.0.0/24" "$WORK/p1.out"; then
    echo "FAIL: B learned 10.99.0.0/24 without redistribution"; ok=0
  fi

  # Phase 2: redistribute static — B must learn and install it proto bgp.
  run_phase "$WORK/a2.toml" "2 (redistribute static)" > "$WORK/p2.out" 2>&1
  cat "$WORK/p2.out"
  grep -q "10.99.0.0/24 via 10.0.0.1" "$WORK/p2.out"     || { echo "FAIL: B missing redistributed route in BGP RIB"; ok=0; }
  grep -q "as-path 65001"             "$WORK/p2.out"     || { echo "FAIL: redistributed route missing as-path 65001"; ok=0; }
  # `ip route show proto bgp` already filters to proto bgp, so the kernel line
  # (with the dev) appearing under it proves the FIB install.
  grep -q "10.99.0.0/24 via 10.0.0.1 dev" "$WORK/p2.out" || { echo "FAIL: redistributed route not installed proto bgp on B"; ok=0; }

  if [[ $ok -ne 1 ]]; then echo "--- A log ---"; cat "$WORK/a.log"; echo "--- B log ---"; cat "$WORK/b.log"; fi
  kill $BPID 2>/dev/null || true
  exit $(( ok == 1 ? 0 : 1 ))
'
echo "bgp redistribute smoke test: OK"
