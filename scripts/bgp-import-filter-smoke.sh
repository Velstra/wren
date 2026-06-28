#!/usr/bin/env bash
# BGP per-neighbour inbound import-filter smoke test. A named [[filter]] referenced by
# a neighbour's `import =` is applied to every route received from that peer before it
# enters the RIB: reject drops the route, accept admits it with any set-preference
# (→LOCAL_PREF) / set-metric (→MED) / set-community modifications folded in.
#
# Like the other bgp-*-smoke.sh scripts it runs inside throwaway `unshare -Urn`
# namespaces and never touches the host's interfaces or uplink. BGP binds TCP 179
# (CAP_NET_BIND_SERVICE), held by the netns-root.
#
# Topology: A (AS 65001, 10.0.0.1) originates 10.50.1.0/24 and 10.50.2.0/24 and peers
# eBGP with B (AS 65002, 10.0.0.2) over a direct veth. B optionally applies an inbound
# import filter to the session toward A.
#
# Two phases (each restarts both daemons fresh, proto-bgp flushed between):
#   * phase off — B has no import filter: it learns both /24s unchanged (localpref 100,
#                 no community).
#   * phase on  — B imports `from-a`: 10.50.2.0/24 is rejected (absent), 10.50.1.0/24 is
#                 accepted with localpref 200 and community 65002:777.
#
# Usage:  bash scripts/bgp-import-filter-smoke.sh
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
WREN="$REPO/target/debug/wren"

if [[ ! -x "$WREN" ]]; then
  echo "building wren (debug) ..."
  (cd "$REPO" && cargo build -p wren-daemon)
fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# A — originates the two /24s; identical in both phases.
cat >"$WORK/a.toml" <<EOF
router-id = "10.0.0.1"
[bgp]
enabled  = true
local-as = 65001
network  = ["10.50.1.0/24", "10.50.2.0/24"]
[[bgp.neighbor]]
address   = "10.0.0.2"
remote-as = 65002
EOF

# B (phase off) — plain receiver, no import filter.
cat >"$WORK/b_off.toml" <<EOF
router-id = "10.0.0.2"
[bgp]
enabled  = true
local-as = 65002
[[bgp.neighbor]]
address   = "10.0.0.1"
remote-as = 65001
EOF

# B (phase on) — an import filter that rejects one /24 and tags+repreferences the other.
cat >"$WORK/b_on.toml" <<EOF
router-id = "10.0.0.2"

[[filter]]
name    = "from-a"
default = "accept"

[[filter.rule]]
prefix = ["10.50.2.0/24"]
action = "reject"

[[filter.rule]]
prefix         = ["10.50.1.0/24"]
set-preference = 200
set-community  = ["65002:777"]
action         = "accept"

[bgp]
enabled  = true
local-as = 65002

[[bgp.neighbor]]
address   = "10.0.0.1"
remote-as = 65001
import    = "from-a"
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

  run_phase() {
    tag="$1"
    "$WREN" --config "$WORK/a.toml" --backend kernel --socket "$WORK/a.sock" >"$WORK/a_$tag.log" 2>&1 &
    nsenter -t $BPID -n "$WREN" --config "$WORK/b_$tag.toml" --backend kernel --socket "$WORK/b.sock" >"$WORK/b_$tag.log" 2>&1 &
    sleep 16
    nsenter -t $BPID -n "$WREN" --socket "$WORK/b.sock" show bgp routes >"$WORK/${tag}_b_bgp.txt" 2>&1 || true
    nsenter -t $BPID -n ip route show proto bgp >"$WORK/${tag}_b_kernel.txt" 2>&1 || true
    pkill -f "$WORK/a.sock" 2>/dev/null || true
    nsenter -t $BPID -n pkill -f "$WORK/b.sock" 2>/dev/null || true
    sleep 1
    ip route flush proto bgp 2>/dev/null || true
    nsenter -t $BPID -n ip route flush proto bgp 2>/dev/null || true
  }

  run_phase off
  run_phase on
  kill $BPID 2>/dev/null || true
'

ok=1
for tag in off on; do
  echo "=== phase $tag: B show bgp routes ==="; cat "$WORK/${tag}_b_bgp.txt"
done

# phase off — both /24s learned, unchanged.
grep -q "10.50.1.0/24" "$WORK/off_b_bgp.txt" && grep -q "10.50.2.0/24" "$WORK/off_b_bgp.txt" \
  || { echo "FAIL: off — B did not learn both /24s"; ok=0; }
if grep -q "65002:777" "$WORK/off_b_bgp.txt"; then
  echo "FAIL: off — B tagged a community with no import filter"; ok=0
fi

# phase on — .2.0 rejected, .1.0 accepted with localpref 200 + community.
if grep -q "10.50.2.0/24" "$WORK/on_b_bgp.txt"; then
  echo "FAIL: on — B kept 10.50.2.0/24 (import filter should reject it)"; ok=0
fi
line="$(grep "10.50.1.0/24" "$WORK/on_b_bgp.txt" || true)"
echo "$line" | grep -q "localpref 200" || { echo "FAIL: on — 10.50.1.0/24 missing localpref 200"; ok=0; }
echo "$line" | grep -q "65002:777"     || { echo "FAIL: on — 10.50.1.0/24 missing community 65002:777"; ok=0; }
grep -q "10.50.1.0/24 via 10.0.0.1" "$WORK/on_b_kernel.txt" \
  || { echo "FAIL: on — B did not install the accepted /24 proto bgp"; ok=0; }
if grep -q "10.50.2.0/24" "$WORK/on_b_kernel.txt"; then
  echo "FAIL: on — B installed the rejected /24 in the kernel"; ok=0
fi

[[ $ok -eq 1 ]] || { echo "--- logs ---"; tail -5 "$WORK"/a_*.log "$WORK"/b_*.log 2>/dev/null; exit 1; }
echo "bgp import-filter smoke test: OK"
