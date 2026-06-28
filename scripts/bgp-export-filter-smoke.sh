#!/usr/bin/env bash
# BGP per-neighbour outbound export-filter smoke test. A named [[filter]] referenced by
# a neighbour's `export =` is applied to every route advertised TO that peer — both
# originated and propagated transit routes. Reject suppresses the advertisement; accept
# sends it with any set-community (and, for a transit route over iBGP, set-preference
# →LOCAL_PREF) modifications applied.
#
# This exercises the transit/propagation path — the primary "don't leak / re-tag on the
# way out" use case. Like the other bgp-*-smoke.sh scripts it runs inside throwaway
# `unshare -Urn` namespaces and never touches the host's interfaces or uplink.
#
# Topology (linear, A in the main netns, B and C in child netns):
#   A (AS 65001, 10.0.1.1) --eBGP-- B (AS 65002, 10.0.1.2 / 10.0.2.1) --iBGP-- C (AS 65002, 10.0.2.2)
# A originates 10.50.1.0/24 and 10.50.2.0/24. B re-advertises them to its iBGP peer C,
# optionally through an export filter. We inspect what C learns (its Loc-RIB; the iBGP
# next hop is A's address, which C cannot resolve, so we assert on `show bgp routes`,
# not the kernel).
#
# Two phases (each restarts all three daemons fresh, proto-bgp flushed between):
#   * phase off — B has no export filter: C learns both /24s (localpref 100, no community).
#   * phase on  — B exports `to-c`: 10.50.2.0/24 is rejected (absent at C), 10.50.1.0/24
#                 arrives with localpref 200 and community 65002:222.
#
# Usage:  bash scripts/bgp-export-filter-smoke.sh
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
WREN="$REPO/target/debug/wren"

if [[ ! -x "$WREN" ]]; then
  echo "building wren (debug) ..."
  (cd "$REPO" && cargo build -p wren-daemon)
fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# A — eBGP origin; identical in both phases.
cat >"$WORK/a.toml" <<EOF
router-id = "10.0.0.1"
[bgp]
enabled  = true
local-as = 65001
network  = ["10.50.1.0/24", "10.50.2.0/24"]
[[bgp.neighbor]]
address   = "10.0.1.2"
remote-as = 65002
EOF

# C — iBGP receiver; identical in both phases.
cat >"$WORK/c.toml" <<EOF
router-id = "10.0.0.3"
[bgp]
enabled  = true
local-as = 65002
[[bgp.neighbor]]
address   = "10.0.2.1"
remote-as = 65002
EOF

# B — transit: eBGP to A, iBGP to C. The export filter on the C neighbour is per phase.
write_b() {  # $1 = export line for the C neighbour, $2 = tag, $3 = extra filter block
  cat >"$WORK/b_$2.toml" <<EOF
router-id = "10.0.0.2"
$3
[bgp]
enabled  = true
local-as = 65002
[[bgp.neighbor]]
address   = "10.0.1.1"
remote-as = 65001
[[bgp.neighbor]]
address   = "10.0.2.2"
remote-as = 65002
$1
EOF
}
write_b '' off ''
FILTER='[[filter]]
name    = "to-c"
default = "accept"

[[filter.rule]]
prefix = ["10.50.2.0/24"]
action = "reject"

[[filter.rule]]
prefix         = ["10.50.1.0/24"]
set-preference = 200
set-community  = ["65002:222"]
action         = "accept"
'
write_b 'export = "to-c"' on "$FILTER"

export WREN WORK
unshare -Urn bash -c '
  set -e
  ip link set lo up
  setsid unshare -n -- sleep 200 & BPID=$!
  setsid unshare -n -- sleep 200 & CPID=$!
  sleep 0.3

  # A (main) <-> B (child1) on 10.0.1.0/24
  ip link add ab0 type veth peer name ab1
  ip link set ab1 netns $BPID
  ip addr add 10.0.1.1/24 dev ab0; ip link set ab0 up
  nsenter -t $BPID -n ip addr add 10.0.1.2/24 dev ab1
  nsenter -t $BPID -n ip link set ab1 up

  # B (child1) <-> C (child2) on 10.0.2.0/24
  ip link add bc0 type veth peer name bc1
  ip link set bc0 netns $BPID
  ip link set bc1 netns $CPID
  nsenter -t $BPID -n ip addr add 10.0.2.1/24 dev bc0
  nsenter -t $BPID -n ip link set bc0 up
  nsenter -t $CPID -n ip addr add 10.0.2.2/24 dev bc1
  nsenter -t $CPID -n ip link set bc1 up
  nsenter -t $BPID -n ip link set lo up
  nsenter -t $CPID -n ip link set lo up

  run_phase() {
    tag="$1"
    "$WREN" --config "$WORK/a.toml" --backend kernel --socket "$WORK/a.sock" >"$WORK/a_$tag.log" 2>&1 &
    nsenter -t $BPID -n "$WREN" --config "$WORK/b_$tag.toml" --backend kernel --socket "$WORK/b.sock" >"$WORK/b_$tag.log" 2>&1 &
    nsenter -t $CPID -n "$WREN" --config "$WORK/c.toml" --backend kernel --socket "$WORK/c.sock" >"$WORK/c_$tag.log" 2>&1 &
    sleep 20
    nsenter -t $CPID -n "$WREN" --socket "$WORK/c.sock" show bgp routes >"$WORK/${tag}_c_bgp.txt" 2>&1 || true
    pkill -f "$WORK/a.sock" 2>/dev/null || true
    nsenter -t $BPID -n pkill -f "$WORK/b.sock" 2>/dev/null || true
    nsenter -t $CPID -n pkill -f "$WORK/c.sock" 2>/dev/null || true
    sleep 1
  }

  run_phase off
  run_phase on
  kill $BPID $CPID 2>/dev/null || true
'

ok=1
for tag in off on; do
  echo "=== phase $tag: C show bgp routes ==="; cat "$WORK/${tag}_c_bgp.txt"
done

# phase off — both /24s reach C, unchanged.
grep -q "10.50.1.0/24" "$WORK/off_c_bgp.txt" && grep -q "10.50.2.0/24" "$WORK/off_c_bgp.txt" \
  || { echo "FAIL: off — C did not learn both /24s through the transit"; ok=0; }
if grep -q "65002:222" "$WORK/off_c_bgp.txt"; then
  echo "FAIL: off — C saw a community with no export filter"; ok=0
fi

# phase on — .2.0 rejected on the way out, .1.0 re-tagged + repreferenced.
if grep -q "10.50.2.0/24" "$WORK/on_c_bgp.txt"; then
  echo "FAIL: on — C still learned 10.50.2.0/24 (export filter should reject it)"; ok=0
fi
line="$(grep "10.50.1.0/24" "$WORK/on_c_bgp.txt" || true)"
echo "$line" | grep -q "localpref 200" || { echo "FAIL: on — 10.50.1.0/24 missing localpref 200"; ok=0; }
echo "$line" | grep -q "65002:222"     || { echo "FAIL: on — 10.50.1.0/24 missing community 65002:222"; ok=0; }

[[ $ok -eq 1 ]] || { echo "--- logs ---"; tail -6 "$WORK"/a_*.log "$WORK"/b_*.log "$WORK"/c_*.log 2>/dev/null; exit 1; }
echo "bgp export-filter smoke test: OK"
