#!/usr/bin/env bash
# OSPF NSSA smoke test (RFC 3101) — an ASBR inside a not-so-stubby area originates
# type-7 LSAs, and the area border router translates them to type-5 for the rest of
# the AS. Self-contained, rootless.
#
# Like the other ospf-*-smoke.sh scripts it runs inside throwaway `unshare -Urn`
# namespaces and never touches the host's interfaces or uplink. OSPF's raw
# IPPROTO_OSPF (89) sockets need CAP_NET_RAW, which the netns-root holds.
#
# Topology (three routers, two p2p links):
#
#     B ──(area 0.0.0.1, NSSA)── A ──(area 0.0.0.0, backbone)── C
#
#   * B (10.0.0.2) is a pure NSSA-internal router AND an ASBR: it redistributes a
#     static 10.99.0.0/24, which it must originate as a type-7 LSA (not type-5).
#   * A (10.0.0.1 / 10.1.0.1) is the ABR: it learns 10.99.0.0/24 from B's type-7
#     and translates it into a type-5 flooded into the backbone.
#   * C (10.1.0.2) is a backbone-internal router: it must learn 10.99.0.0/24 as a
#     translated AS-external, proving the type-7 → type-5 translation reached the AS.
#
# The N-bit must match on A↔B (both NSSA) and the E-bit on A↔C (both normal), or the
# adjacencies would not form — so the routes flowing at all proves that too.
#
# OSPF convergence (Hello 10s / Dead 40s) means a single ~40s wait.
#
# Usage:  bash scripts/ospf-nssa-smoke.sh
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
WREN="$REPO/target/debug/wren"

if [[ ! -x "$WREN" ]]; then
  echo "building wren (debug) ..."
  (cd "$REPO" && cargo build -p wren-daemon)
fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# A — the ABR / translator: veth_ab in the NSSA, veth_ac in the backbone.
cat >"$WORK/a.toml" <<EOF
router-id = "10.0.0.1"
[ospf]
enabled      = true
network-type = "point-to-point"
nssa-areas   = ["0.0.0.1"]
[[ospf.interface]]
name = "veth_ab"
area = "0.0.0.1"
[[ospf.interface]]
name = "veth_ac"
area = "0.0.0.0"
EOF

# B — NSSA-internal ASBR redistributing a static (becomes a type-7).
cat >"$WORK/b.toml" <<EOF
router-id = "10.0.0.2"
[[static]]
prefix = "10.99.0.0/24"
via    = "10.0.0.1"
[ospf]
enabled      = true
network-type = "point-to-point"
area         = "0.0.0.1"
interfaces   = ["veth_ba"]
nssa-areas   = ["0.0.0.1"]
redistribute = ["static"]
EOF

# C — backbone-internal router.
cat >"$WORK/c.toml" <<EOF
router-id = "10.0.0.3"
[ospf]
enabled      = true
network-type = "point-to-point"
area         = "0.0.0.0"
interfaces   = ["veth_ca"]
EOF

export WREN WORK
unshare -Urn bash -c '
  set -e
  ip link set lo up
  setsid unshare -n -- sleep 120 & BPID=$!
  setsid unshare -n -- sleep 120 & CPID=$!
  sleep 0.3

  # A↔B link (NSSA), A↔C link (backbone).
  ip link add veth_ab type veth peer name veth_ba
  ip link add veth_ac type veth peer name veth_ca
  ip link set veth_ba netns $BPID
  ip link set veth_ca netns $CPID
  ip addr add 10.0.0.1/24 dev veth_ab; ip link set veth_ab up
  ip addr add 10.1.0.1/24 dev veth_ac; ip link set veth_ac up
  nsenter -t $BPID -n ip addr add 10.0.0.2/24 dev veth_ba
  nsenter -t $BPID -n ip link set veth_ba up; nsenter -t $BPID -n ip link set lo up
  nsenter -t $CPID -n ip addr add 10.1.0.2/24 dev veth_ca
  nsenter -t $CPID -n ip link set veth_ca up; nsenter -t $CPID -n ip link set lo up

  nsenter -t $BPID -n "$WREN" --config "$WORK/b.toml" --backend kernel --socket "$WORK/b.sock" >"$WORK/b.log" 2>&1 &
  nsenter -t $CPID -n "$WREN" --config "$WORK/c.toml" --backend kernel --socket "$WORK/c.sock" >"$WORK/c.log" 2>&1 &
  "$WREN" --config "$WORK/a.toml" --backend kernel --socket "$WORK/a.sock" >"$WORK/a.log" 2>&1 &
  sleep 40

  # Capture every output to files (the namespace pids work here, right after the
  # wait); the outer shell does the assertions, sidestepping a SHELLOPTS/nounset
  # quirk that bites variable use later inside this inherited bash.
  "$WREN" --socket "$WORK/a.sock" show routes ospf >"$WORK/a_routes.txt" 2>&1 || true
  "$WREN" --socket "$WORK/a.sock" show ospf neighbors >"$WORK/a_neigh.txt" 2>&1 || true
  nsenter -t $CPID -n "$WREN" --socket "$WORK/c.sock" show routes ospf >"$WORK/c_routes.txt" 2>&1 || true
  nsenter -t $CPID -n ip route show proto ospf >"$WORK/c_kernel.txt" 2>&1 || true
  kill $BPID $CPID 2>/dev/null || true
'

ok=1
echo "=== A (ABR) routes ospf ===";       cat "$WORK/a_routes.txt"
echo "=== A ospf neighbors ===";          cat "$WORK/a_neigh.txt"
echo "=== C (backbone) routes ospf ===";  cat "$WORK/c_routes.txt"
echo "=== C ip route proto ospf ===";     cat "$WORK/c_kernel.txt"

# A must learn the NSSA external from B's type-7.
grep -q "10.99.0.0/24 via 10.0.0.2" "$WORK/a_routes.txt" \
  || { echo "FAIL: A did not learn 10.99.0.0/24 from the type-7"; ok=0; }
# C must learn it as a translated type-5 (via A), and install it.
grep -q "10.99.0.0/24 via 10.1.0.1" "$WORK/c_routes.txt" \
  || { echo "FAIL: C did not learn the translated type-5 external"; ok=0; }
grep -q "10.99.0.0/24 via 10.1.0.1" "$WORK/c_kernel.txt" \
  || { echo "FAIL: C did not install the translated external proto ospf"; ok=0; }

if [[ $ok -ne 1 ]]; then echo "--- A log ---"; cat "$WORK/a.log" 2>/dev/null || true; fi
[[ $ok -eq 1 ]] || exit 1
echo "ospf nssa smoke test: OK"
