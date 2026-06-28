#!/usr/bin/env bash
# BGP route propagation smoke test — a transit speaker re-advertises a route it
# learned from one eBGP peer to another (the Adj-RIB-Out), prepending its AS.
# Fully self-contained and rootless.
#
# Like the other bgp-*-smoke.sh scripts it runs inside throwaway `unshare -Urn`
# namespaces and never touches the host's interfaces or uplink. Per-daemon control
# sockets live under a temp dir (Unix sockets, not the network).
#
# Topology — an eBGP chain of three speakers in three namespaces:
#
#   A (AS 65001) --10.0.1.0/24-- B (AS 65002) --10.0.2.0/24-- C (AS 65003)
#
# A originates 10.10.0.0/24. B is NOT configured to originate or redistribute
# anything — it learns the route from A and must *propagate* it onward to C with
# its own AS prepended and next-hop-self. The test asserts:
#   * C learns 10.10.0.0/24 via B (10.0.2.1) with as-path "65002 65001"; and
#   * C installs it into the kernel table `proto bgp`.
#
# This exercises the propagation path: learned Loc-RIB best path -> central
# Adj-RIB-Out fan-out -> per-peer UPDATE (AS prepend, next-hop-self) at the far peer.
#
# Usage:  bash scripts/bgp-propagate-smoke.sh
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
WREN="$REPO/target/debug/wren"

if [[ ! -x "$WREN" ]]; then
  echo "building wren (debug) ..."
  (cd "$REPO" && cargo build -p wren-daemon)
fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# A (active toward B) originates the test network.
cat >"$WORK/a.toml" <<EOF
router-id = "10.0.1.1"
[bgp]
enabled  = true
local-as = 65001
network  = ["10.10.0.0/24"]
[[bgp.neighbor]]
address   = "10.0.1.2"
remote-as = 65002
EOF

# B (passive toward A, active toward C) originates nothing — it only transits.
cat >"$WORK/b.toml" <<EOF
router-id = "10.0.2.1"
[bgp]
enabled  = true
local-as = 65002
[[bgp.neighbor]]
address   = "10.0.1.1"
remote-as = 65001
passive   = true
[[bgp.neighbor]]
address   = "10.0.2.2"
remote-as = 65003
EOF

# C (passive toward B) should learn A's route via B.
cat >"$WORK/c.toml" <<EOF
router-id = "10.0.2.2"
[bgp]
enabled  = true
local-as = 65003
[[bgp.neighbor]]
address   = "10.0.2.1"
remote-as = 65002
passive   = true
EOF

export WREN WORK
unshare -Urn bash -c '
  set -e
  ip link set lo up
  # A and C live in their own namespaces; B is this (the middle) namespace.
  setsid unshare -n -- sleep 120 & APID=$!
  setsid unshare -n -- sleep 120 & CPID=$!
  sleep 0.3

  # A <-> B link (B side = 10.0.1.2).
  ip link add veth_ba type veth peer name veth_ab
  ip link set veth_ab netns $APID
  ip addr add 10.0.1.2/24 dev veth_ba; ip link set veth_ba up
  nsenter -t $APID -n ip addr add 10.0.1.1/24 dev veth_ab
  nsenter -t $APID -n ip link set veth_ab up
  nsenter -t $APID -n ip link set lo up

  # B <-> C link (B side = 10.0.2.1).
  ip link add veth_bc type veth peer name veth_cb
  ip link set veth_cb netns $CPID
  ip addr add 10.0.2.1/24 dev veth_bc; ip link set veth_bc up
  nsenter -t $CPID -n ip addr add 10.0.2.2/24 dev veth_cb
  nsenter -t $CPID -n ip link set veth_cb up
  nsenter -t $CPID -n ip link set lo up

  nsenter -t $APID -n "$WREN" --config "$WORK/a.toml" --backend kernel --socket "$WORK/a.sock" >"$WORK/a.log" 2>&1 &
  "$WREN" --config "$WORK/b.toml" --backend kernel --socket "$WORK/b.sock" >"$WORK/b.log" 2>&1 &
  nsenter -t $CPID -n "$WREN" --config "$WORK/c.toml" --backend kernel --socket "$WORK/c.sock" >"$WORK/c.log" 2>&1 &
  sleep 9

  ok=1
  {
    echo "=== wren show bgp neighbors (on B) ==="
    "$WREN" --socket "$WORK/b.sock" show bgp neighbors || true
    echo "=== wren show bgp (on C) ==="
    nsenter -t $CPID -n "$WREN" --socket "$WORK/c.sock" show bgp || true
    echo "=== ip route show proto bgp (on C) ==="
    nsenter -t $CPID -n ip route show proto bgp || true
  } > "$WORK/out.txt" 2>&1
  cat "$WORK/out.txt"

  grep -q "10.10.0.0/24 via 10.0.2.1"          "$WORK/out.txt" || { echo "FAIL: C did not learn the propagated route via B"; ok=0; }
  grep -q "as-path 65002 65001"                "$WORK/out.txt" || { echo "FAIL: propagated route missing as-path 65002 65001 (AS not prepended)"; ok=0; }
  grep -q "10.10.0.0/24 via 10.0.2.1 dev"      "$WORK/out.txt" || { echo "FAIL: propagated route not installed proto bgp on C"; ok=0; }

  if [[ $ok -ne 1 ]]; then
    echo "--- A log ---"; cat "$WORK/a.log"
    echo "--- B log ---"; cat "$WORK/b.log"
    echo "--- C log ---"; cat "$WORK/c.log"
  fi
  kill $APID $CPID 2>/dev/null || true
  exit $(( ok == 1 ? 0 : 1 ))
'
echo "bgp propagate smoke test: OK"
