#!/usr/bin/env bash
# BGP multipath smoke test — a router that learns the same prefix over two eBGP
# sessions with an identical AS_PATH installs both next hops as kernel ECMP when
# `[bgp] multipath` is set, instead of just the single best path. Self-contained,
# rootless.
#
# Like the other bgp-*-smoke.sh scripts it runs inside throwaway `unshare -Urn`
# namespaces and never touches the host's interfaces or uplink. Per-daemon control
# sockets live under a temp dir (Unix sockets, not the network).
#
# Topology (three routers, two p2p links):
#
#     A (AS 65001) ──10.0.0.0/24── R (AS 65000) ──10.1.0.0/24── B (AS 65001)
#
#   * A (10.0.0.1) and B (10.1.0.1) are in the SAME AS 65001 and each ORIGINATE
#     the same network 10.99.0.0/24, so R receives two paths whose AS_PATH is an
#     identical [65001] — equal-cost for multipath.
#   * R (10.0.0.2 / 10.1.0.2, AS 65000) eBGP-peers with both. It is the router
#     under test: it installs 10.99.0.0/24 into its own kernel FIB.
#
# Two phases differ only in R's config:
#   * phase 1 — R has no `multipath`: it installs ONE next hop (the best path, which
#     tie-breaks to A's lower router id 10.0.0.1) and NOT B's.
#   * phase 2 — R has `multipath = 2`: it installs BOTH next hops as an ECMP route.
#
# A and B run throughout; only R restarts between phases (its proto-bgp routes are
# flushed in between so phase 2 starts clean).
#
# Usage:  bash scripts/bgp-multipath-smoke.sh
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
WREN="$REPO/target/debug/wren"

if [[ ! -x "$WREN" ]]; then
  echo "building wren (debug) ..."
  (cd "$REPO" && cargo build -p wren-daemon)
fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# A — AS 65001, originates 10.99.0.0/24, passively peers with R.
cat >"$WORK/a.toml" <<EOF
router-id = "10.0.0.1"
[bgp]
enabled   = true
local-as  = 65001
network   = ["10.99.0.0/24"]
[[bgp.neighbor]]
address   = "10.0.0.2"
remote-as = 65000
passive   = true
EOF

# B — AS 65001 too, same originated network, passively peers with R.
cat >"$WORK/b.toml" <<EOF
router-id = "10.1.0.1"
[bgp]
enabled   = true
local-as  = 65001
network   = ["10.99.0.0/24"]
[[bgp.neighbor]]
address   = "10.1.0.2"
remote-as = 65000
passive   = true
EOF

# R phase 1 — no multipath: single best path installed.
cat >"$WORK/r1.toml" <<EOF
router-id = "10.0.0.2"
[bgp]
enabled   = true
local-as  = 65000
[[bgp.neighbor]]
address   = "10.0.0.1"
remote-as = 65001
[[bgp.neighbor]]
address   = "10.1.0.1"
remote-as = 65001
EOF

# R phase 2 — multipath: up to two equal-cost paths installed as ECMP.
cat >"$WORK/r2.toml" <<EOF
router-id = "10.0.0.2"
[bgp]
enabled   = true
local-as  = 65000
multipath = 2
[[bgp.neighbor]]
address   = "10.0.0.1"
remote-as = 65001
[[bgp.neighbor]]
address   = "10.1.0.1"
remote-as = 65001
EOF

export WREN WORK
unshare -Urn bash -c '
  set -e
  ip link set lo up
  setsid unshare -n -- sleep 180 & APID=$!
  setsid unshare -n -- sleep 180 & BPID=$!
  sleep 0.3

  # R↔A link and R↔B link.
  ip link add veth_ra type veth peer name veth_ar
  ip link add veth_rb type veth peer name veth_br
  ip link set veth_ar netns $APID
  ip link set veth_br netns $BPID
  ip addr add 10.0.0.2/24 dev veth_ra; ip link set veth_ra up
  ip addr add 10.1.0.2/24 dev veth_rb; ip link set veth_rb up
  nsenter -t $APID -n ip addr add 10.0.0.1/24 dev veth_ar
  nsenter -t $APID -n ip link set veth_ar up; nsenter -t $APID -n ip link set lo up
  nsenter -t $BPID -n ip addr add 10.1.0.1/24 dev veth_br
  nsenter -t $BPID -n ip link set veth_br up; nsenter -t $BPID -n ip link set lo up

  # Each phase starts ALL THREE daemons fresh and tears them all down, so no stale
  # sessions or leftover routes carry across the R-config change under test.
  run_phase() {
    rcfg="$1"; tag="$2"
    nsenter -t $APID -n "$WREN" --config "$WORK/a.toml" --backend kernel --socket "$WORK/a.sock" >"$WORK/a.log" 2>&1 &
    ap=$!
    nsenter -t $BPID -n "$WREN" --config "$WORK/b.toml" --backend kernel --socket "$WORK/b.sock" >"$WORK/b.log" 2>&1 &
    bp=$!
    "$WREN" --config "$rcfg" --backend kernel --socket "$WORK/r.sock" >"$WORK/r_$tag.log" 2>&1 &
    rp=$!
    sleep 11
    ip route show 10.99.0.0/24 >"$WORK/${tag}_route.txt" 2>&1 || true
    "$WREN" --socket "$WORK/r.sock" show bgp routes >"$WORK/${tag}_bgp.txt" 2>&1 || true
    kill $ap $bp $rp 2>/dev/null || true
    sleep 1
    ip route flush proto bgp 2>/dev/null || true
  }

  run_phase "$WORK/r1.toml" r1   # phase 1 — no multipath
  run_phase "$WORK/r2.toml" r2   # phase 2 — multipath = 2

  kill $APID $BPID 2>/dev/null || true
'

ok=1
echo "=== phase 1 (no multipath): R kernel route 10.99.0.0/24 ==="; cat "$WORK/r1_route.txt"
echo "=== phase 1: R show bgp routes ==="; cat "$WORK/r1_bgp.txt"
echo "=== phase 2 (multipath=2): R kernel route 10.99.0.0/24 ==="; cat "$WORK/r2_route.txt"
echo "=== phase 2: R show bgp routes ==="; cat "$WORK/r2_bgp.txt"

# Phase 1: exactly the single best path (A, lower router id) — and NOT B's.
grep -q "via 10.0.0.1" "$WORK/r1_route.txt" \
  || { echo "FAIL: phase 1 — R did not install the best path via 10.0.0.1"; ok=0; }
if grep -q "via 10.1.0.1" "$WORK/r1_route.txt"; then
  echo "FAIL: phase 1 — R installed a second next hop without multipath"; ok=0
fi

# Phase 2: BOTH next hops present (ECMP) and the route is proto bgp.
grep -q "via 10.0.0.1" "$WORK/r2_route.txt" \
  || { echo "FAIL: phase 2 — R missing ECMP next hop via 10.0.0.1"; ok=0; }
grep -q "via 10.1.0.1" "$WORK/r2_route.txt" \
  || { echo "FAIL: phase 2 — R missing ECMP next hop via 10.1.0.1"; ok=0; }
grep -q "proto bgp" "$WORK/r2_route.txt" \
  || { echo "FAIL: phase 2 — ECMP route not installed proto bgp"; ok=0; }

if [[ $ok -ne 1 ]]; then echo "--- R phase2 log ---"; cat "$WORK/r_r2.log" 2>/dev/null || true; fi
[[ $ok -eq 1 ]] || exit 1
echo "bgp multipath smoke test: OK"
