#!/usr/bin/env bash
# IS-IS operational `show` commands — `wren show isis neighbors` and
# `wren show isis interfaces`, answered by the IS-IS task itself out of its live
# state (its interfaces, their per-level adjacencies and the DIS election).
# Self-contained, rootless.
#
# Like the other smoke scripts it runs inside throwaway `unshare -Urn` namespaces
# and never touches the host's interfaces or uplink. IS-IS uses an AF_PACKET
# (802.2 LLC) socket per interface, which needs CAP_NET_RAW — held by the
# netns-root inside `unshare -Urn`. Per-daemon control sockets live under a temp
# dir (Unix sockets, not the network).
#
# Topology: A (0000.0000.0001) <--IS-IS point-to-point, L1L2--> B (0000.0000.0002)
# over a veth. Once the adjacency comes up we query A:
#   * `show isis neighbors` must list B (0000.0000.0002) Up at level 1;
#   * `show isis interfaces` must list veth0 as a point-to-point l1l2 circuit.
#
# Usage:  bash scripts/isis-show-smoke.sh
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
WREN="$REPO/target/debug/wren"

if [[ ! -x "$WREN" ]]; then
  echo "building wren (debug) ..."
  (cd "$REPO" && cargo build -p wren-daemon)
fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

cat >"$WORK/a.toml" <<EOF
router-id = "10.0.0.1"
[isis]
enabled = true
interfaces = ["veth0"]
system-id = "0000.0000.0001"
network-type = "point-to-point"
hello-interval = 3
EOF

cat >"$WORK/b.toml" <<EOF
router-id = "10.0.0.2"
[isis]
enabled = true
interfaces = ["veth1"]
system-id = "0000.0000.0002"
network-type = "point-to-point"
hello-interval = 3
EOF

export WREN WORK
unshare -Urn bash -c '
  set -e
  ip link set lo up
  setsid unshare -n -- sleep 120 & BPID=$!
  sleep 0.3
  ip link add veth0 type veth peer name veth1
  ip link set veth1 netns $BPID
  ip addr add 2001:db8::1/64 dev veth0; ip link set veth0 up
  nsenter -t $BPID -n ip addr add 2001:db8::2/64 dev veth1
  nsenter -t $BPID -n ip link set veth1 up
  nsenter -t $BPID -n ip link set lo up
  sleep 2

  nsenter -t $BPID -n "$WREN" --config "$WORK/b.toml" --backend kernel --socket "$WORK/b.sock" >"$WORK/b.log" 2>&1 &
  "$WREN" --config "$WORK/a.toml" --backend kernel --socket "$WORK/a.sock" >"$WORK/a.log" 2>&1 &
  # IS-IS forms an adjacency over a few Hellos.
  sleep 22

  echo "=== wren show isis neighbors (on A) ==="
  "$WREN" --socket "$WORK/a.sock" show isis neighbors 2>&1 | tee "$WORK/nbr.out" || true
  echo "=== wren show isis interfaces (on A) ==="
  "$WREN" --socket "$WORK/a.sock" show isis interfaces 2>&1 | tee "$WORK/iface.out" || true

  ok=1
  grep -Eq "0000.0000.0002 via .* dev veth0 level 1 state Up" "$WORK/nbr.out" \
    || { echo "FAIL: neighbor B not Up at level 1 on A"; ok=0; }
  grep -q "veth0 type point-to-point level l1l2" "$WORK/iface.out" \
    || { echo "FAIL: interface veth0 not shown as p2p l1l2 on A"; ok=0; }

  if [[ $ok -ne 1 ]]; then echo "--- A log ---"; cat "$WORK/a.log"; echo "--- B log ---"; cat "$WORK/b.log"; fi
  pkill -f "$WORK/a.sock" 2>/dev/null || true
  nsenter -t $BPID -n pkill -f "$WORK/b.sock" 2>/dev/null || true
  kill $BPID 2>/dev/null || true
  exit $(( ok == 1 ? 0 : 1 ))
'
echo "isis show smoke test: OK"
