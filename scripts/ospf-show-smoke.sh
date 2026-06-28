#!/usr/bin/env bash
# OSPF operational `show` commands — `wren show ospf neighbors` and
# `wren show ospf interfaces`, answered by the OSPF task itself out of its live
# state (its interfaces, their neighbours and the DR election). Self-contained,
# rootless.
#
# Like the other smoke scripts it runs inside throwaway `unshare -Urn` namespaces
# and never touches the host's interfaces or uplink. OSPF uses a raw IPPROTO_OSPF
# (89) socket, which needs CAP_NET_RAW — held by the netns-root inside
# `unshare -Urn`. Per-daemon control sockets live under a temp dir (Unix sockets).
#
# Topology: A (router-id 10.0.0.1) <--OSPF point-to-point--> B (10.0.0.2) over a
# veth, area 0.0.0.0. Once the adjacency reaches Full we query A:
#   * `show ospf neighbors` must list B (10.0.0.2) in state Full;
#   * `show ospf interfaces` must list veth0 in area 0.0.0.0, state PtP.
#
# Usage:  bash scripts/ospf-show-smoke.sh
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
[ospf]
enabled = true
interfaces = ["veth0"]
network-type = "point-to-point"
EOF

cat >"$WORK/b.toml" <<EOF
router-id = "10.0.0.2"
[ospf]
enabled = true
interfaces = ["veth1"]
network-type = "point-to-point"
EOF

export WREN WORK
unshare -Urn bash -c '
  set -e
  ip link set lo up
  setsid unshare -n -- sleep 120 & BPID=$!
  sleep 0.3
  ip link add veth0 type veth peer name veth1
  ip link set veth1 netns $BPID
  ip addr add 10.0.0.1/24 dev veth0; ip link set veth0 up
  nsenter -t $BPID -n ip addr add 10.0.0.2/24 dev veth1
  nsenter -t $BPID -n ip link set veth1 up
  nsenter -t $BPID -n ip link set lo up

  nsenter -t $BPID -n "$WREN" --config "$WORK/b.toml" --backend kernel --socket "$WORK/b.sock" >"$WORK/b.log" 2>&1 &
  "$WREN" --config "$WORK/a.toml" --backend kernel --socket "$WORK/a.sock" >"$WORK/a.log" 2>&1 &
  # Let the adjacency reach Full (hellos + database exchange).
  sleep 32

  echo "=== wren show ospf neighbors (on A) ==="
  "$WREN" --socket "$WORK/a.sock" show ospf neighbors 2>&1 | tee "$WORK/nbr.out" || true
  echo "=== wren show ospf interfaces (on A) ==="
  "$WREN" --socket "$WORK/a.sock" show ospf interfaces 2>&1 | tee "$WORK/iface.out" || true

  ok=1
  grep -q "10.0.0.2 via 10.0.0.2 dev veth0 state Full" "$WORK/nbr.out" \
    || { echo "FAIL: neighbor B not Full on A"; ok=0; }
  grep -q "veth0 area 0.0.0.0 10.0.0.1 state PtP" "$WORK/iface.out" \
    || { echo "FAIL: interface veth0 not shown PtP on A"; ok=0; }

  if [[ $ok -ne 1 ]]; then echo "--- A log ---"; cat "$WORK/a.log"; echo "--- B log ---"; cat "$WORK/b.log"; fi
  pkill -f "$WORK/a.sock" 2>/dev/null || true
  nsenter -t $BPID -n pkill -f "$WORK/b.sock" 2>/dev/null || true
  kill $BPID 2>/dev/null || true
  exit $(( ok == 1 ? 0 : 1 ))
'
echo "ospf show smoke test: OK"
