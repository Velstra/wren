#!/usr/bin/env bash
# OSPF totally-stubby / totally-NSSA smoke test — a "no-summary" area, into which
# the area border router suppresses inter-area (type-3) summaries and injects only
# a default route (a type-3 default for a totally-stubby area, a type-7 default for
# a totally-NSSA area). Self-contained, rootless.
#
# Like the other ospf-*-smoke.sh scripts it runs inside throwaway `unshare -Urn`
# namespaces and never touches the host's interfaces or uplink. OSPF's raw
# IPPROTO_OSPF (89) sockets need CAP_NET_RAW, which the netns-root holds.
#
# Topology: A is an ABR (dummy0 in the backbone area 0.0.0.0 carrying 10.50.0.0/24,
# veth0 in area 0.0.0.1) and an ASBR (redistributes a static 10.99.0.0/24). B is a
# pure area-0.0.0.1 internal router over the veth.
#
# Three phases differ only in how area 0.0.0.1 is configured (each starts both
# daemons fresh and flushes proto-ospf routes in between):
#   * phase 1 — plain STUB: B gets the default AND the inter-area summary
#     10.50.0.0/24, but not the external 10.99.0.0/24. (The contrast that proves the
#     next phase actually suppresses the summary.)
#   * phase 2 — TOTALLY-STUBBY: B gets only the default; the inter-area 10.50.0.0/24
#     is now suppressed, and the external is still gone.
#   * phase 3 — TOTALLY-NSSA: B gets a default again (a type-7 the ABR injects), and
#     the inter-area 10.50.0.0/24 stays suppressed.
#
# Usage:  bash scripts/ospf-totally-stubby-smoke.sh
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
WREN="$REPO/target/debug/wren"

if [[ ! -x "$WREN" ]]; then
  echo "building wren (debug) ..."
  (cd "$REPO" && cargo build -p wren-daemon)
fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# A — ABR (dummy0 backbone + veth0 area1) and ASBR (redistributes a static). The
# area-type line is filled per phase.
write_a() {  # $1 = area-type toml line, $2 = tag
  cat >"$WORK/a_$2.toml" <<EOF
router-id = "10.0.0.1"
[[static]]
prefix = "10.99.0.0/24"
via    = "10.0.0.2"
[ospf]
enabled           = true
network-type      = "point-to-point"
interfaces        = ["dummy0"]
redistribute      = ["static"]
stub-default-cost = 5
$1
[[ospf.interface]]
name = "veth0"
area = "0.0.0.1"
EOF
}
write_b() {  # $1 = area-type toml line, $2 = tag
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

write_a 'stub-areas           = ["0.0.0.1"]'           stub
write_a 'totally-stubby-areas = ["0.0.0.1"]'           tstub
write_a 'totally-nssa-areas   = ["0.0.0.1"]'           tnssa
write_b 'stub-areas           = ["0.0.0.1"]'           stub
write_b 'totally-stubby-areas = ["0.0.0.1"]'           tstub
write_b 'totally-nssa-areas   = ["0.0.0.1"]'           tnssa

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

  run_phase stub
  run_phase tstub
  run_phase tnssa
  kill $BPID 2>/dev/null || true
'

ok=1
for tag in stub tstub tnssa; do
  echo "=== phase $tag: B show routes ospf ===";  cat "$WORK/${tag}_routes.txt"
  echo "=== phase $tag: B ip route proto ospf ==="; cat "$WORK/${tag}_kernel.txt"
done

# Phase 1 (plain stub): default present, inter-area summary present, external gone.
grep -q "0.0.0.0/0 via 10.0.0.1" "$WORK/stub_routes.txt" \
  || { echo "FAIL: plain stub — B has no injected default"; ok=0; }
grep -q "10.50.0.0/24 via 10.0.0.1" "$WORK/stub_routes.txt" \
  || { echo "FAIL: plain stub — B did not learn the inter-area summary 10.50.0.0/24"; ok=0; }
if grep -q "10.99.0.0/24" "$WORK/stub_routes.txt"; then
  echo "FAIL: plain stub — B learned the external 10.99.0.0/24 (should be suppressed)"; ok=0
fi

# Phase 2 (totally-stubby): default present, inter-area summary SUPPRESSED, no external.
grep -q "0.0.0.0/0 via 10.0.0.1" "$WORK/tstub_routes.txt" \
  || { echo "FAIL: totally-stubby — B has no injected default"; ok=0; }
if grep -q "10.50.0.0/24" "$WORK/tstub_routes.txt"; then
  echo "FAIL: totally-stubby — inter-area 10.50.0.0/24 NOT suppressed"; ok=0
fi
grep -q "default via 10.0.0.1" "$WORK/tstub_kernel.txt" \
  || { echo "FAIL: totally-stubby — default not installed proto ospf"; ok=0; }

# Phase 3 (totally-NSSA): a type-7 default present, inter-area summary suppressed.
grep -q "0.0.0.0/0 via 10.0.0.1" "$WORK/tnssa_routes.txt" \
  || { echo "FAIL: totally-NSSA — B has no injected type-7 default"; ok=0; }
if grep -q "10.50.0.0/24" "$WORK/tnssa_routes.txt"; then
  echo "FAIL: totally-NSSA — inter-area 10.50.0.0/24 NOT suppressed"; ok=0
fi

if [[ $ok -ne 1 ]]; then echo "--- A tnssa log ---"; cat "$WORK/a_tnssa.log" 2>/dev/null || true; fi
[[ $ok -eq 1 ]] || exit 1
echo "ospf totally-stubby / totally-nssa smoke test: OK"
