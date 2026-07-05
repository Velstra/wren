#!/usr/bin/env bash
# BGP RFC 8212 strict default-deny smoke test. With `[bgp] ebgp-require-policy = true`,
# an eBGP neighbour with no explicit `import` policy accepts no routes, and one with no
# explicit `export` policy re-advertises no transit routes. iBGP and locally-originated
# routes are unaffected.
#
# Like the other bgp-*-smoke.sh scripts it runs inside throwaway `unshare -Urn`
# namespaces and never touches the host's interfaces or uplink. BGP binds TCP 179
# (CAP_NET_BIND_SERVICE), held by the netns-root.
#
# Topology (a shared L2 bridge; B is the middle speaker with strict mode on):
#   A (AS 65001, 10.0.0.1)  originates 10.60.1.0/24
#   B (AS 65002, 10.0.0.2)  ebgp-require-policy = true; peers eBGP with A and C
#   C (AS 65003, 10.0.0.3)  plain receiver
#
# Two phases (each restarts all three daemons fresh, proto-bgp flushed between):
#   * deny  — B has NO import and NO export policy: it must NOT learn A's /24 (import
#             default-deny), so C never sees it either.
#   * mixed — B imports `from-a` (accept) but still has NO export policy: it DOES learn
#             A's /24 (an explicit policy re-enables ingress), yet must NOT re-advertise
#             it to C (export default-deny).
#
# Usage:  bash scripts/bgp-default-deny-smoke.sh
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
WREN="$REPO/target/debug/wren"

if [[ ! -x "$WREN" ]]; then
  echo "building wren (debug) ..."
  (cd "$REPO" && cargo build -p wren-daemon)
fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# A — originates the /24; identical in both phases.
cat >"$WORK/a.toml" <<EOF
router-id = "10.0.0.1"
[bgp]
enabled  = true
local-as = 65001
network  = ["10.60.1.0/24"]
[[bgp.neighbor]]
address   = "10.0.0.2"
remote-as = 65002
EOF

# C — plain receiver; identical in both phases.
cat >"$WORK/c.toml" <<EOF
router-id = "10.0.0.3"
[bgp]
enabled  = true
local-as = 65003
[[bgp.neighbor]]
address   = "10.0.0.2"
remote-as = 65002
EOF

# B (deny) — strict mode, no import/export on either eBGP peer.
cat >"$WORK/b_deny.toml" <<EOF
router-id = "10.0.0.2"
[bgp]
enabled             = true
local-as            = 65002
ebgp-require-policy = true
[[bgp.neighbor]]
address   = "10.0.0.1"
remote-as = 65001
[[bgp.neighbor]]
address   = "10.0.0.3"
remote-as = 65003
EOF

# B (mixed) — strict mode; an accept-all import from A, but still NO export toward C.
cat >"$WORK/b_mixed.toml" <<EOF
router-id = "10.0.0.2"

[[filter]]
name    = "from-a"
default = "accept"

[bgp]
enabled             = true
local-as            = 65002
ebgp-require-policy = true
[[bgp.neighbor]]
address   = "10.0.0.1"
remote-as = 65001
import    = "from-a"
[[bgp.neighbor]]
address   = "10.0.0.3"
remote-as = 65003
EOF

export WREN WORK
unshare -Urn bash -c '
  set -e
  ip link set lo up
  # A and C live in their own namespaces; B is this namespace and hosts the shared
  # L2 bridge all three sit on.
  setsid unshare -n -- sleep 180 & APID=$!
  setsid unshare -n -- sleep 180 & CPID=$!
  sleep 0.3

  ip link add br0 type bridge
  ip addr add 10.0.0.2/24 dev br0
  ip link set br0 up

  ip link add veth_a type veth peer name veth_a1
  ip link set veth_a1 netns $APID
  ip link set veth_a master br0; ip link set veth_a up
  nsenter -t $APID -n ip addr add 10.0.0.1/24 dev veth_a1
  nsenter -t $APID -n ip link set veth_a1 up
  nsenter -t $APID -n ip link set lo up

  ip link add veth_c type veth peer name veth_c1
  ip link set veth_c1 netns $CPID
  ip link set veth_c master br0; ip link set veth_c up
  nsenter -t $CPID -n ip addr add 10.0.0.3/24 dev veth_c1
  nsenter -t $CPID -n ip link set veth_c1 up
  nsenter -t $CPID -n ip link set lo up

  run_phase() {
    tag="$1"
    nsenter -t $APID -n "$WREN" --config "$WORK/a.toml" --backend kernel --socket "$WORK/a.sock" >"$WORK/a_$tag.log" 2>&1 &
    "$WREN" --config "$WORK/b_$tag.toml" --backend kernel --socket "$WORK/b.sock" >"$WORK/b_$tag.log" 2>&1 &
    nsenter -t $CPID -n "$WREN" --config "$WORK/c.toml" --backend kernel --socket "$WORK/c.sock" >"$WORK/c_$tag.log" 2>&1 &
    sleep 16
    "$WREN" --socket "$WORK/b.sock" show bgp routes >"$WORK/${tag}_b_bgp.txt" 2>&1 || true
    nsenter -t $CPID -n "$WREN" --socket "$WORK/c.sock" show bgp routes >"$WORK/${tag}_c_bgp.txt" 2>&1 || true
    nsenter -t $APID -n pkill -f "$WORK/a.sock" 2>/dev/null || true
    pkill -f "$WORK/b.sock" 2>/dev/null || true
    nsenter -t $CPID -n pkill -f "$WORK/c.sock" 2>/dev/null || true
    sleep 1
    nsenter -t $APID -n ip route flush proto bgp 2>/dev/null || true
    ip route flush proto bgp 2>/dev/null || true
    nsenter -t $CPID -n ip route flush proto bgp 2>/dev/null || true
  }

  run_phase deny
  run_phase mixed
  kill $APID $CPID 2>/dev/null || true
'

ok=1
for tag in deny mixed; do
  echo "=== phase $tag: B routes ==="; cat "$WORK/${tag}_b_bgp.txt"
  echo "=== phase $tag: C routes ==="; cat "$WORK/${tag}_c_bgp.txt"
done

# phase deny — B must NOT learn A's /24 (import default-deny), and C sees nothing.
if grep -q "10.60.1.0/24" "$WORK/deny_b_bgp.txt"; then
  echo "FAIL: deny — B learned 10.60.1.0/24 despite no import policy (RFC 8212)"; ok=0
fi
if grep -q "10.60.1.0/24" "$WORK/deny_c_bgp.txt"; then
  echo "FAIL: deny — C learned 10.60.1.0/24 (B should not have propagated it)"; ok=0
fi

# phase mixed — B DOES learn A's /24 (explicit import), but must NOT export it to C.
grep -q "10.60.1.0/24" "$WORK/mixed_b_bgp.txt" \
  || { echo "FAIL: mixed — B did not learn 10.60.1.0/24 with an accept-all import"; ok=0; }
if grep -q "10.60.1.0/24" "$WORK/mixed_c_bgp.txt"; then
  echo "FAIL: mixed — C learned 10.60.1.0/24 despite B having no export policy (RFC 8212)"; ok=0
fi

[[ $ok -eq 1 ]] || { echo "--- logs ---"; tail -8 "$WORK"/a_*.log "$WORK"/b_*.log "$WORK"/c_*.log 2>/dev/null; exit 1; }
echo "bgp default-deny (RFC 8212) smoke test: OK"
