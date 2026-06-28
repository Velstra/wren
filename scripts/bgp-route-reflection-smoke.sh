#!/usr/bin/env bash
# BGP route reflection smoke test (RFC 4456) — a route reflector relays a route
# between two iBGP clients that do not peer with each other. Fully self-contained
# and rootless.
#
# Like the other bgp-*-smoke.sh scripts it runs inside throwaway `unshare -Urn`
# namespaces and never touches the host's interfaces or uplink. Per-daemon control
# sockets live under a temp dir (Unix sockets, not the network).
#
# Topology — one AS (65010) on one shared L2 segment (a bridge in the RR
# namespace), with a reflector RR and two clients in three namespaces:
#
#                 RR (10.0.0.254)
#                   |  bridge br0  (10.0.0.0/24)
#          +--------+--------+
#       C1 (10.0.0.1)     C2 (10.0.0.2)
#
# All three are iBGP (same AS). C1 originates 10.10.0.0/24. C1 and C2 each peer
# ONLY with RR (never with each other), so under plain iBGP split horizon C2 would
# never see the route. RR has both as `route-reflector-client`s, so it reflects
# C1's route to C2 (stamping ORIGINATOR_ID / CLUSTER_LIST). The shared segment
# makes the preserved iBGP next hop (C1, 10.0.0.1) on-link for C2, so it installs.
# The test asserts:
#   * C2 learns 10.10.0.0/24 via 10.0.0.1 (only possible via reflection); and
#   * C2 installs it into the kernel table `proto bgp`.
#
# Usage:  bash scripts/bgp-route-reflection-smoke.sh
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
WREN="$REPO/target/debug/wren"

if [[ ! -x "$WREN" ]]; then
  echo "building wren (debug) ..."
  (cd "$REPO" && cargo build -p wren-daemon)
fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# RR (active toward both clients) reflects between them.
cat >"$WORK/rr.toml" <<EOF
router-id = "10.0.0.254"
[bgp]
enabled  = true
local-as = 65010
[[bgp.neighbor]]
address                = "10.0.0.1"
remote-as              = 65010
route-reflector-client = true
[[bgp.neighbor]]
address                = "10.0.0.2"
remote-as              = 65010
route-reflector-client = true
EOF

# C1 (passive) originates the test network.
cat >"$WORK/c1.toml" <<EOF
router-id = "10.0.0.1"
[bgp]
enabled  = true
local-as = 65010
network  = ["10.10.0.0/24"]
[[bgp.neighbor]]
address   = "10.0.0.254"
remote-as = 65010
passive   = true
EOF

# C2 (passive) should learn C1's network only via the reflector.
cat >"$WORK/c2.toml" <<EOF
router-id = "10.0.0.2"
[bgp]
enabled  = true
local-as = 65010
[[bgp.neighbor]]
address   = "10.0.0.254"
remote-as = 65010
passive   = true
EOF

export WREN WORK
unshare -Urn bash -c '
  set -e
  ip link set lo up
  # C1 and C2 live in their own namespaces; RR is this namespace and hosts the
  # shared L2 bridge all three sit on.
  setsid unshare -n -- sleep 120 & C1PID=$!
  setsid unshare -n -- sleep 120 & C2PID=$!
  sleep 0.3

  ip link add br0 type bridge
  ip addr add 10.0.0.254/24 dev br0
  ip link set br0 up

  # C1 onto the bridge.
  ip link add veth_c1 type veth peer name veth_1
  ip link set veth_1 netns $C1PID
  ip link set veth_c1 master br0; ip link set veth_c1 up
  nsenter -t $C1PID -n ip addr add 10.0.0.1/24 dev veth_1
  nsenter -t $C1PID -n ip link set veth_1 up
  nsenter -t $C1PID -n ip link set lo up

  # C2 onto the bridge.
  ip link add veth_c2 type veth peer name veth_2
  ip link set veth_2 netns $C2PID
  ip link set veth_c2 master br0; ip link set veth_c2 up
  nsenter -t $C2PID -n ip addr add 10.0.0.2/24 dev veth_2
  nsenter -t $C2PID -n ip link set veth_2 up
  nsenter -t $C2PID -n ip link set lo up

  "$WREN" --config "$WORK/rr.toml" --backend kernel --socket "$WORK/rr.sock" >"$WORK/rr.log" 2>&1 &
  nsenter -t $C1PID -n "$WREN" --config "$WORK/c1.toml" --backend kernel --socket "$WORK/c1.sock" >"$WORK/c1.log" 2>&1 &
  nsenter -t $C2PID -n "$WREN" --config "$WORK/c2.toml" --backend kernel --socket "$WORK/c2.sock" >"$WORK/c2.log" 2>&1 &
  sleep 9

  ok=1
  {
    echo "=== wren show bgp neighbors (on RR) ==="
    "$WREN" --socket "$WORK/rr.sock" show bgp neighbors || true
    echo "=== wren show bgp (on C2) ==="
    nsenter -t $C2PID -n "$WREN" --socket "$WORK/c2.sock" show bgp || true
    echo "=== ip route show proto bgp (on C2) ==="
    nsenter -t $C2PID -n ip route show proto bgp || true
  } > "$WORK/out.txt" 2>&1
  cat "$WORK/out.txt"

  grep -q "10.0.0.1 AS 65010 Established"   "$WORK/out.txt" || { echo "FAIL: RR-C1 session not Established"; ok=0; }
  grep -q "10.0.0.2 AS 65010 Established"   "$WORK/out.txt" || { echo "FAIL: RR-C2 session not Established"; ok=0; }
  grep -q "10.10.0.0/24 via 10.0.0.1"       "$WORK/out.txt" || { echo "FAIL: C2 did not learn the reflected route"; ok=0; }
  grep -q "10.10.0.0/24 via 10.0.0.1 dev"   "$WORK/out.txt" || { echo "FAIL: reflected route not installed proto bgp on C2"; ok=0; }

  if [[ $ok -ne 1 ]]; then
    echo "--- RR log ---"; cat "$WORK/rr.log"
    echo "--- C1 log ---"; cat "$WORK/c1.log"
    echo "--- C2 log ---"; cat "$WORK/c2.log"
  fi
  kill $C1PID $C2PID 2>/dev/null || true
  exit $(( ok == 1 ? 0 : 1 ))
'
echo "bgp route reflection smoke test: OK"
