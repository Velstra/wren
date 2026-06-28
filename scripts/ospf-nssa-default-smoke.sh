#!/usr/bin/env bash
# OSPF plain-NSSA default-route injection smoke test (RFC 3101 §2.3). A plain
# not-so-stubby area carries no AS-external (type-5) LSAs, so its internal routers
# have no path to AS-external destinations unless the area border router injects a
# default. Listing the area in `nssa-default-areas` makes the ABR originate a
# type-7 `0.0.0.0/0` default into it WHILE STILL carrying the ordinary inter-area
# (type-3) summaries — the distinction from a totally-NSSA, which suppresses them.
# Self-contained, rootless.
#
# Like the other ospf-*-smoke.sh scripts it runs inside throwaway `unshare -Urn`
# namespaces and never touches the host's interfaces or uplink. OSPF's raw
# IPPROTO_OSPF (89) sockets need CAP_NET_RAW, which the netns-root holds.
#
# Topology: A is an ABR — dummy0 in the backbone area 0.0.0.0 carrying 10.50.0.0/24,
# veth0 in the NSSA area 0.0.0.1. B is a pure area-0.0.0.1 internal router over the
# veth.
#
# Two phases differ only in how area 0.0.0.1 is configured (each starts both daemons
# fresh and flushes proto-ospf routes in between):
#   * phase 1 — plain NSSA, no default: B learns the inter-area summary 10.50.0.0/24
#     but gets NO default route (an NSSA carries no externals, and the ABR injects no
#     default). The contrast that proves the next phase actually injects one.
#   * phase 2 — NSSA + nssa-default: B now also gets a type-7 0.0.0.0/0 default the
#     ABR injects, and the inter-area summary 10.50.0.0/24 is still present.
#
# Usage:  bash scripts/ospf-nssa-default-smoke.sh
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
WREN="$REPO/target/debug/wren"

if [[ ! -x "$WREN" ]]; then
  echo "building wren (debug) ..."
  (cd "$REPO" && cargo build -p wren-daemon)
fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# A — ABR (dummy0 backbone + veth0 NSSA area1). The area-type lines are filled in
# per phase.
write_a() {  # $1 = area-type toml lines, $2 = tag
  cat >"$WORK/a_$2.toml" <<EOF
router-id = "10.0.0.1"
[ospf]
enabled           = true
network-type      = "point-to-point"
interfaces        = ["dummy0"]
stub-default-cost = 5
$1
[[ospf.interface]]
name = "veth0"
area = "0.0.0.1"
EOF
}
write_b() {  # $1 = area-type toml lines, $2 = tag
  cat >"$WORK/b_$2.toml" <<EOF
router-id = "10.0.0.2"
[ospf]
enabled      = true
network-type = "point-to-point"
area         = "0.0.0.1"
interfaces   = ["veth1"]
$1
EOF
}

write_a 'nssa-areas         = ["0.0.0.1"]'                              plain
write_a 'nssa-areas         = ["0.0.0.1"]
nssa-default-areas = ["0.0.0.1"]'                                      withdef
# B is a plain NSSA internal router in both phases (only the ABR injects a default).
write_b 'nssa-areas         = ["0.0.0.1"]'                              plain
write_b 'nssa-areas         = ["0.0.0.1"]'                              withdef

export WREN WORK
unshare -Urn bash -c '
  set -e
  ip link set lo up
  setsid unshare -n -- sleep 240 & BPID=$!
  sleep 0.3
  ip link add veth0 type veth peer name veth1
  ip link set veth1 netns $BPID
  ip link add dummy0 type dummy
  ip addr add 10.50.0.1/24 dev dummy0; ip link set dummy0 up
  ip addr add 10.0.0.1/24 dev veth0; ip link set veth0 up
  nsenter -t $BPID -n ip addr add 10.0.0.2/24 dev veth1
  nsenter -t $BPID -n ip link set veth1 up
  nsenter -t $BPID -n ip link set lo up

  run_phase() {
    tag="$1"
    nsenter -t $BPID -n "$WREN" --config "$WORK/b_$tag.toml" --backend kernel --socket "$WORK/b.sock" >"$WORK/b_$tag.log" 2>&1 &
    "$WREN" --config "$WORK/a_$tag.toml" --backend kernel --socket "$WORK/a.sock" >"$WORK/a_$tag.log" 2>&1 &
    sleep 30
    nsenter -t $BPID -n "$WREN" --socket "$WORK/b.sock" show routes ospf >"$WORK/${tag}_routes.txt" 2>&1 || true
    nsenter -t $BPID -n ip route show proto ospf >"$WORK/${tag}_kernel.txt" 2>&1 || true
    pkill -f "$WORK/a.sock" 2>/dev/null || true
    nsenter -t $BPID -n pkill -f "$WORK/b.sock" 2>/dev/null || true
    sleep 1
    nsenter -t $BPID -n ip route flush proto ospf 2>/dev/null || true
    ip route flush proto ospf 2>/dev/null || true
  }

  run_phase plain
  run_phase withdef
  kill $BPID 2>/dev/null || true
'

ok=1
for tag in plain withdef; do
  echo "=== phase $tag: B show routes ospf ===";  cat "$WORK/${tag}_routes.txt"
  echo "=== phase $tag: B ip route proto ospf ==="; cat "$WORK/${tag}_kernel.txt"
done

# Phase 1 (plain NSSA, no default): inter-area summary present, NO default.
grep -q "10.50.0.0/24 via 10.0.0.1" "$WORK/plain_routes.txt" \
  || { echo "FAIL: plain NSSA — B did not learn the inter-area summary 10.50.0.0/24"; ok=0; }
if grep -q "0.0.0.0/0" "$WORK/plain_routes.txt"; then
  echo "FAIL: plain NSSA — B has a default route (none should be injected yet)"; ok=0
fi

# Phase 2 (NSSA + nssa-default): type-7 default present AND summary still present.
grep -q "0.0.0.0/0 via 10.0.0.1" "$WORK/withdef_routes.txt" \
  || { echo "FAIL: nssa-default — B has no injected type-7 default"; ok=0; }
grep -q "10.50.0.0/24 via 10.0.0.1" "$WORK/withdef_routes.txt" \
  || { echo "FAIL: nssa-default — the inter-area summary 10.50.0.0/24 was lost"; ok=0; }
grep -q "default via 10.0.0.1" "$WORK/withdef_kernel.txt" \
  || { echo "FAIL: nssa-default — default not installed proto ospf"; ok=0; }

if [[ $ok -ne 1 ]]; then echo "--- A withdef log ---"; cat "$WORK/a_withdef.log" 2>/dev/null || true; fi
[[ $ok -eq 1 ]] || exit 1
echo "ospf plain-NSSA default-injection smoke test: OK"
