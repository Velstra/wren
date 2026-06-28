#!/usr/bin/env bash
# OSPF link-state database inspection smoke test — `wren show ospf database` dumps the
# LSDB the OSPF task owns: every LSA in every area, plus the AS-external (type-5) LSAs.
# Self-contained, rootless.
#
# Like the other ospf-*-smoke.sh scripts it runs inside throwaway `unshare -Urn`
# namespaces and never touches the host's interfaces or uplink. OSPF's raw IPPROTO_OSPF
# (89) sockets need CAP_NET_RAW, which the netns-root inside `unshare -Urn` holds.
#
# Topology: A (router-id 10.0.0.1, an ASBR redistributing a static 10.99.0.0/24) <--OSPF
# p2p, area 0--> B (router-id 10.0.0.2) over a veth. After convergence both routers'
# databases must hold: both Router-LSAs (flooded within the area) and A's AS-external
# LSA for 10.99.0.0/24 (flooded AS-wide).
#
# OSPF convergence (Hello 10s / Dead 40s) means a ~32s wait.
#
# Usage:  bash scripts/ospf-database-smoke.sh
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
WREN="$REPO/target/debug/wren"

if [[ ! -x "$WREN" ]]; then
  echo "building wren (debug) ..."
  (cd "$REPO" && cargo build -p wren-daemon)
fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# A — ASBR: redistributes a static into OSPF as an AS-external LSA.
cat >"$WORK/a.toml" <<EOF
router-id = "10.0.0.1"
[[static]]
prefix = "10.99.0.0/24"
via    = "10.0.0.2"
[ospf]
enabled      = true
interfaces   = ["veth0"]
network-type = "point-to-point"
redistribute = ["static"]
EOF

# B — plain OSPF on the p2p link.
cat >"$WORK/b.toml" <<EOF
router-id = "10.0.0.2"
[ospf]
enabled      = true
interfaces   = ["veth1"]
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

  "$WREN" --config "$WORK/a.toml" --backend kernel --socket "$WORK/a.sock" >"$WORK/a.log" 2>&1 &
  nsenter -t $BPID -n "$WREN" --config "$WORK/b.toml" --backend kernel --socket "$WORK/b.sock" >"$WORK/b.log" 2>&1 &
  sleep 32
  "$WREN" --socket "$WORK/a.sock" show ospf database >"$WORK/a_db.txt" 2>&1 || true
  nsenter -t $BPID -n "$WREN" --socket "$WORK/b.sock" show ospf database >"$WORK/b_db.txt" 2>&1 || true
  pkill -f "$WORK/a.sock" 2>/dev/null || true
  nsenter -t $BPID -n pkill -f "$WORK/b.sock" 2>/dev/null || true
  kill $BPID 2>/dev/null || true
'

ok=1
for who in a b; do
  echo "=== $who: show ospf database ==="; cat "$WORK/${who}_db.txt"
  # Both Router-LSAs are present in each database (flooded within the area).
  grep -q "router id 10.0.0.1 adv-router 10.0.0.1" "$WORK/${who}_db.txt" \
    || { echo "FAIL: $who is missing A's Router-LSA"; ok=0; }
  grep -q "router id 10.0.0.2 adv-router 10.0.0.2" "$WORK/${who}_db.txt" \
    || { echo "FAIL: $who is missing B's Router-LSA"; ok=0; }
  # A's redistributed static appears as an AS-external LSA (flooded AS-wide).
  grep -q "as-external external id 10.99.0.0 adv-router 10.0.0.1" "$WORK/${who}_db.txt" \
    || { echo "FAIL: $who is missing the AS-external LSA for 10.99.0.0"; ok=0; }
done

if [[ $ok -ne 1 ]]; then echo "--- A log ---"; tail -8 "$WORK/a.log"; echo "--- B log ---"; tail -8 "$WORK/b.log"; fi
[[ $ok -eq 1 ]] || exit 1
echo "ospf database smoke test: OK"
