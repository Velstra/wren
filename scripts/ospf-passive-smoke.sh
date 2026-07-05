#!/usr/bin/env bash
# OSPF passive-interface smoke test — a passive interface still advertises its
# subnet into the link-state database (a stub link in the Router-LSA), but sends
# and processes no Hellos, so no adjacency ever forms on it. Self-contained, rootless.
#
# Like the other ospf-*-smoke.sh scripts it runs inside throwaway `unshare -Urn`
# namespaces and never touches the host's interfaces or uplink. OSPF's raw
# IPPROTO_OSPF (89) sockets need CAP_NET_RAW, which the netns-root inside
# `unshare -Urn` holds.
#
# Topology (all area 0.0.0.0, point-to-point):
#   B (10.0.0.2) <--veth, active--> A (10.0.0.1) <--veth, PASSIVE--> C (10.0.0.3)
# A's link toward C (10.50.0.1/24) is passive. Expectations after convergence:
#   * B learns 10.50.0.0/24 via A  — A advertised the passive subnet into the LSDB;
#   * A's neighbour table lists B (10.0.0.2) but NOT C (10.0.0.3) — no adjacency on
#     the passive link;
#   * C's neighbour table never sees A (10.0.0.1) — A emits no Hellos on the passive
#     interface.
#
# OSPF convergence (Hello 10s / Dead 40s) means a ~34s wait.
#
# Usage:  bash scripts/ospf-passive-smoke.sh
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
WREN="$REPO/target/debug/wren"

if [[ ! -x "$WREN" ]]; then
  echo "building wren (debug) ..."
  (cd "$REPO" && cargo build -p wren-daemon)
fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# A — veth0 active toward B, veth2 passive toward C (its 10.50.0.0/24 subnet is
# still advertised, but no Hello leaves it and none is processed).
cat >"$WORK/a.toml" <<EOF
router-id = "10.0.0.1"
[ospf]
enabled            = true
network-type       = "point-to-point"
interfaces         = ["veth0", "veth2"]
passive-interfaces = ["veth2"]
EOF

# B — plain OSPF on the active link to A.
cat >"$WORK/b.toml" <<EOF
router-id = "10.0.0.2"
[ospf]
enabled      = true
network-type = "point-to-point"
interfaces   = ["veth1"]
EOF

# C — plain OSPF on the far side of A's passive link. It should never form an
# adjacency with A, because A is silent on that interface.
cat >"$WORK/c.toml" <<EOF
router-id = "10.0.0.3"
[ospf]
enabled      = true
network-type = "point-to-point"
interfaces   = ["veth3"]
EOF

export WREN WORK
unshare -Urn bash -c '
  set -e
  ip link set lo up
  setsid unshare -n -- sleep 180 & BPID=$!
  setsid unshare -n -- sleep 180 & CPID=$!
  sleep 0.3

  # A<->B link.
  ip link add veth0 type veth peer name veth1
  ip link set veth1 netns $BPID
  ip addr add 10.0.1.1/24 dev veth0; ip link set veth0 up
  nsenter -t $BPID -n ip addr add 10.0.1.2/24 dev veth1
  nsenter -t $BPID -n ip link set veth1 up
  nsenter -t $BPID -n ip link set lo up

  # A<->C link (passive on A).
  ip link add veth2 type veth peer name veth3
  ip link set veth3 netns $CPID
  ip addr add 10.50.0.1/24 dev veth2; ip link set veth2 up
  nsenter -t $CPID -n ip addr add 10.50.0.2/24 dev veth3
  nsenter -t $CPID -n ip link set veth3 up
  nsenter -t $CPID -n ip link set lo up

  "$WREN" --config "$WORK/a.toml" --backend kernel --socket "$WORK/a.sock" >"$WORK/a.log" 2>&1 &
  nsenter -t $BPID -n "$WREN" --config "$WORK/b.toml" --backend kernel --socket "$WORK/b.sock" >"$WORK/b.log" 2>&1 &
  nsenter -t $CPID -n "$WREN" --config "$WORK/c.toml" --backend kernel --socket "$WORK/c.sock" >"$WORK/c.log" 2>&1 &
  sleep 34

  echo "=== A: show ospf neighbors ==="
  "$WREN" --socket "$WORK/a.sock" show ospf neighbors >"$WORK/a_nbr.txt" 2>&1 || true
  cat "$WORK/a_nbr.txt"
  echo "=== C: show ospf neighbors ==="
  nsenter -t $CPID -n "$WREN" --socket "$WORK/c.sock" show ospf neighbors >"$WORK/c_nbr.txt" 2>&1 || true
  cat "$WORK/c_nbr.txt"
  echo "=== B: ip route proto ospf ==="
  nsenter -t $BPID -n ip route show proto ospf >"$WORK/b_route.txt" 2>&1 || true
  cat "$WORK/b_route.txt"

  pkill -f "$WORK/a.sock" 2>/dev/null || true
  nsenter -t $BPID -n pkill -f "$WORK/b.sock" 2>/dev/null || true
  nsenter -t $CPID -n pkill -f "$WORK/c.sock" 2>/dev/null || true
  kill $BPID $CPID 2>/dev/null || true
'

ok=1
# B learns the passive subnet — proof A advertised it into the LSDB.
grep -q "10.50.0.0/24" "$WORK/b_route.txt" \
  || { echo "FAIL: B did not learn the passive subnet 10.50.0.0/24"; ok=0; }
# A formed an adjacency with B (active link) ...
grep -q "10.0.0.2" "$WORK/a_nbr.txt" \
  || { echo "FAIL: A has no adjacency with B on the active link"; ok=0; }
# ... but NOT with C over the passive interface.
grep -q "10.0.0.3" "$WORK/a_nbr.txt" \
  && { echo "FAIL: A formed an adjacency with C on the passive interface"; ok=0; }
# C never heard a Hello from A, so it has no adjacency either.
grep -q "10.0.0.1" "$WORK/c_nbr.txt" \
  && { echo "FAIL: C heard OSPF from A on the passive link (A should be silent)"; ok=0; }

if [[ $ok -ne 1 ]]; then echo "--- A log ---"; tail -12 "$WORK/a.log"; echo "--- B log ---"; tail -12 "$WORK/b.log"; echo "--- C log ---"; tail -12 "$WORK/c.log"; fi
[[ $ok -eq 1 ]] || exit 1
echo "ospf passive interface smoke test: OK"
