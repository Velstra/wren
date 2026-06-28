#!/usr/bin/env bash
# OSPFv3 operational `show` commands — `wren show ospf3 neighbors` and
# `wren show ospf3 interfaces`, answered by the OSPFv3 task itself out of its live
# state (its interfaces, their neighbours and the DR election). Self-contained,
# rootless.
#
# This is also the first live exercise of the OSPFv3 runner end to end: two
# routers form an adjacency over a veth and reach Full, then we query one of them.
#
# Like the other smoke scripts it runs inside throwaway `unshare -Urn` namespaces
# and never touches the host interfaces or uplink. OSPFv3 uses a raw IPPROTO_OSPF
# (89) socket over IPv6, which needs CAP_NET_RAW — held by the netns-root inside
# `unshare -Urn`. Per-daemon control sockets live under a temp dir (Unix sockets).
#
# Topology: A (router-id 10.0.0.1) <--OSPFv3 point-to-point--> B (10.0.0.2) over a
# veth, area 0.0.0.0, adjacency over IPv6 link-local. Once it reaches Full we query
# A:
#   * `show ospf3 neighbors` must list B (10.0.0.2) via a link-local in state Full;
#   * `show ospf3 interfaces` must list veth0 in area 0.0.0.0, state PtP.
#
# Usage:  bash scripts/ospf3-show-smoke.sh
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
[ospf3]
enabled = true
interfaces = ["veth0"]
network-type = "point-to-point"
EOF

cat >"$WORK/b.toml" <<EOF
router-id = "10.0.0.2"
[ospf3]
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
  ip addr add 2001:db8::1/64 dev veth0; ip link set veth0 up
  nsenter -t $BPID -n ip addr add 2001:db8::2/64 dev veth1
  nsenter -t $BPID -n ip link set veth1 up
  nsenter -t $BPID -n ip link set lo up
  # Let IPv6 DAD settle so the link-local addresses are usable.
  sleep 2

  nsenter -t $BPID -n "$WREN" --config "$WORK/b.toml" --backend kernel --socket "$WORK/b.sock" >"$WORK/b.log" 2>&1 &
  "$WREN" --config "$WORK/a.toml" --backend kernel --socket "$WORK/a.sock" >"$WORK/a.log" 2>&1 &
  # Let the adjacency reach Full (hellos + database exchange).
  sleep 35

  echo "=== wren show ospf3 neighbors (on A) ==="
  "$WREN" --socket "$WORK/a.sock" show ospf3 neighbors 2>&1 | tee "$WORK/nbr.out" || true
  echo "=== wren show ospf3 interfaces (on A) ==="
  "$WREN" --socket "$WORK/a.sock" show ospf3 interfaces 2>&1 | tee "$WORK/iface.out" || true

  ok=1
  grep -qE "10.0.0.2 via fe80.* dev veth0 state Full" "$WORK/nbr.out" \
    || { echo "FAIL: neighbor B not Full on A"; ok=0; }
  grep -qE "veth0 area 0.0.0.0 fe80.* state PtP" "$WORK/iface.out" \
    || { echo "FAIL: interface veth0 not shown PtP on A"; ok=0; }

  if [[ $ok -ne 1 ]]; then echo "--- A log ---"; cat "$WORK/a.log"; echo "--- B log ---"; cat "$WORK/b.log"; fi
  pkill -f "$WORK/a.sock" 2>/dev/null || true
  nsenter -t $BPID -n pkill -f "$WORK/b.sock" 2>/dev/null || true
  kill $BPID 2>/dev/null || true
  exit $(( ok == 1 ? 0 : 1 ))
'
echo "ospf3 show smoke test: OK"
