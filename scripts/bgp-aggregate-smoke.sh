#!/usr/bin/env bash
# BGP address-aggregation smoke test (RFC 4271 §9.2.2.2). With `[[bgp.aggregate]]`
# configured, Wren advertises a covering prefix to its peers whenever a more-specific
# locally-originated route contributes to it, carrying ATOMIC_AGGREGATE + AGGREGATOR.
# With `summary-only` the contributing more-specifics are suppressed. The aggregate is
# advertise-only: it is never installed in the originating router's own FIB.
#
# Like the other bgp-*-smoke.sh scripts it runs inside throwaway `unshare -Urn`
# namespaces and never touches the host's interfaces or uplink. BGP binds TCP 179
# (CAP_NET_BIND_SERVICE), held by the netns-root.
#
# Topology: A (AS 65001, 10.0.0.1) originates two more-specifics 10.50.1.0/24 and
# 10.50.2.0/24 (both inside 10.50.0.0/16) and peers eBGP with B (AS 65002, 10.0.0.2)
# over a direct veth. We inspect what B learns.
#
# Three phases (each restarts both daemons fresh, proto-bgp flushed between):
#   * phase off     — no aggregate: B learns only the two /24s, never the /16.
#   * phase on      — aggregate 10.50.0.0/16 (not summary-only): B learns the /16 AND
#                     both /24s; A does not install the /16 in its own kernel.
#   * phase summary — aggregate 10.50.0.0/16 summary-only: B learns only the /16,
#                     the contributing /24s are suppressed.
#
# Usage:  bash scripts/bgp-aggregate-smoke.sh
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
WREN="$REPO/target/debug/wren"

if [[ ! -x "$WREN" ]]; then
  echo "building wren (debug) ..."
  (cd "$REPO" && cargo build -p wren-daemon)
fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# A — originates the two more-specifics; the aggregate block is filled per phase.
write_a() {  # $1 = aggregate block, $2 = tag
  cat >"$WORK/a_$2.toml" <<EOF
router-id = "10.0.0.1"
[bgp]
enabled  = true
local-as = 65001
network  = ["10.50.1.0/24", "10.50.2.0/24"]
$1
[[bgp.neighbor]]
address   = "10.0.0.2"
remote-as = 65002
EOF
}
write_a ''                                                          off
write_a $'[[bgp.aggregate]]\nprefix = "10.50.0.0/16"'               on
write_a $'[[bgp.aggregate]]\nprefix = "10.50.0.0/16"\nsummary-only = true' summary

# B — the receiver; identical in every phase.
cat >"$WORK/b.toml" <<EOF
router-id = "10.0.0.2"
[bgp]
enabled  = true
local-as = 65002
[[bgp.neighbor]]
address   = "10.0.0.1"
remote-as = 65001
EOF

export WREN WORK
unshare -Urn bash -c '
  set -e
  ip link set lo up
  setsid unshare -n -- sleep 180 & BPID=$!
  sleep 0.3
  ip link add veth0 type veth peer name veth1
  ip link set veth1 netns $BPID
  ip addr add 10.0.0.1/24 dev veth0; ip link set veth0 up
  nsenter -t $BPID -n ip addr add 10.0.0.2/24 dev veth1
  nsenter -t $BPID -n ip link set veth1 up
  nsenter -t $BPID -n ip link set lo up

  run_phase() {
    tag="$1"
    "$WREN" --config "$WORK/a_$tag.toml" --backend kernel --socket "$WORK/a.sock" >"$WORK/a_$tag.log" 2>&1 &
    nsenter -t $BPID -n "$WREN" --config "$WORK/b.toml" --backend kernel --socket "$WORK/b.sock" >"$WORK/b_$tag.log" 2>&1 &
    sleep 16
    nsenter -t $BPID -n "$WREN" --socket "$WORK/b.sock" show bgp routes >"$WORK/${tag}_b_bgp.txt" 2>&1 || true
    nsenter -t $BPID -n ip route show proto bgp >"$WORK/${tag}_b_kernel.txt" 2>&1 || true
    ip route show proto bgp >"$WORK/${tag}_a_kernel.txt" 2>&1 || true
    pkill -f "$WORK/a.sock" 2>/dev/null || true
    nsenter -t $BPID -n pkill -f "$WORK/b.sock" 2>/dev/null || true
    sleep 1
    ip route flush proto bgp 2>/dev/null || true
    nsenter -t $BPID -n ip route flush proto bgp 2>/dev/null || true
  }

  run_phase off
  run_phase on
  run_phase summary
  kill $BPID 2>/dev/null || true
'

ok=1
for tag in off on summary; do
  echo "=== phase $tag: B show bgp routes ==="; cat "$WORK/${tag}_b_bgp.txt"
done

# phase off — no aggregate: B has both /24s, never the /16.
grep -q "10.50.1.0/24" "$WORK/off_b_bgp.txt" && grep -q "10.50.2.0/24" "$WORK/off_b_bgp.txt" \
  || { echo "FAIL: off — B did not learn the more-specific /24s"; ok=0; }
if grep -q "10.50.0.0/16" "$WORK/off_b_bgp.txt"; then
  echo "FAIL: off — B learned an aggregate /16 with no aggregate configured"; ok=0
fi

# phase on — aggregate (not summary-only): B has the /16 AND both /24s.
grep -q "10.50.0.0/16" "$WORK/on_b_bgp.txt" \
  || { echo "FAIL: on — B did not learn the aggregate 10.50.0.0/16"; ok=0; }
grep -q "10.50.1.0/24" "$WORK/on_b_bgp.txt" && grep -q "10.50.2.0/24" "$WORK/on_b_bgp.txt" \
  || { echo "FAIL: on — B lost the more-specifics (should be kept without summary-only)"; ok=0; }
grep -q "10.50.0.0/16 via 10.0.0.1" "$WORK/on_b_kernel.txt" \
  || { echo "FAIL: on — B did not install the aggregate proto bgp"; ok=0; }
# Advertise-only: A never installs the aggregate it merely originates.
if grep -q "10.50.0.0/16" "$WORK/on_a_kernel.txt"; then
  echo "FAIL: on — A installed the aggregate locally (it is advertise-only)"; ok=0
fi

# phase summary — summary-only: B has only the /16, the /24s are suppressed.
grep -q "10.50.0.0/16" "$WORK/summary_b_bgp.txt" \
  || { echo "FAIL: summary — B did not learn the aggregate 10.50.0.0/16"; ok=0; }
if grep -q "10.50.1.0/24\|10.50.2.0/24" "$WORK/summary_b_bgp.txt"; then
  echo "FAIL: summary — B still sees a more-specific (summary-only should suppress it)"; ok=0
fi

[[ $ok -eq 1 ]] || { echo "--- logs ---"; tail -5 "$WORK"/a_*.log "$WORK"/b_*.log 2>/dev/null; exit 1; }
echo "bgp aggregate-address smoke test: OK"
