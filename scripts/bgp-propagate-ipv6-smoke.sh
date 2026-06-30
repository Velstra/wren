#!/usr/bin/env bash
# BGP IPv6 route propagation smoke test — a transit speaker re-advertises an IPv6
# route it learned from one eBGP peer to another (MP-BGP transit), prepending its
# AS and setting next-hop-self6. Fully self-contained and rootless.
#
# Like the other bgp-*-smoke.sh scripts it runs inside throwaway `unshare -Urn`
# namespaces and never touches the host's interfaces or uplink. Per-daemon control
# sockets live under a temp dir (Unix sockets, not the network).
#
# Topology — an eBGP chain of three speakers in three namespaces. The TCP sessions
# ride IPv4; each link also carries IPv6 globals so the MP_REACH next hop resolves:
#
#   A (AS 65001) ==link1== B (AS 65002) ==link2== C (AS 65003)
#     link1: IPv4 10.0.1.0/24, IPv6 2001:db8:1::/64
#     link2: IPv4 10.0.2.0/24, IPv6 2001:db8:2::/64
#
# A originates the IPv6 network 2001:db8:99::/64 (next-hop-self 2001:db8:1::1). B
# originates nothing — it learns the route over MP-BGP and must *propagate* it
# onward to C with its own AS prepended and next-hop-self6 (global 2001:db8:2::1,
# its address on link2). B and C share link2, so B advertises a 32-octet next hop
# (global + link-local) per RFC 2545 §3 and C forwards over B's `fe80::`
# link-local pinned to link2. The test asserts:
#   * C learns 2001:db8:99::/64 via B's link-local with as-path "65002 65001"; and
#   * C installs it into the kernel IPv6 table `proto bgp`.
#
# Usage:  bash scripts/bgp-propagate-ipv6-smoke.sh
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
WREN="$REPO/target/debug/wren"

if [[ ! -x "$WREN" ]]; then
  echo "building wren (debug) ..."
  (cd "$REPO" && cargo build -p wren-daemon)
fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# A (active toward B) originates the IPv6 network.
cat >"$WORK/a.toml" <<EOF
router-id = "10.0.1.1"
[bgp]
enabled   = true
local-as  = 65001
network   = ["2001:db8:99::/64"]
next-hop6 = "2001:db8:1::1"
[[bgp.neighbor]]
address   = "10.0.1.2"
remote-as = 65002
EOF

# B (passive toward A, active toward C) originates nothing — it only transits. Its
# next-hop-self6 is its address on link2, so C can resolve it on-link.
cat >"$WORK/b.toml" <<EOF
router-id = "10.0.2.1"
[bgp]
enabled   = true
local-as  = 65002
next-hop6 = "2001:db8:2::1"
[[bgp.neighbor]]
address   = "10.0.1.1"
remote-as = 65001
passive   = true
[[bgp.neighbor]]
address   = "10.0.2.2"
remote-as = 65003
EOF

# C (passive toward B) should learn A's IPv6 route via B.
cat >"$WORK/c.toml" <<EOF
router-id = "10.0.2.2"
[bgp]
enabled   = true
local-as  = 65003
[[bgp.neighbor]]
address   = "10.0.2.1"
remote-as = 65002
passive   = true
EOF

export WREN WORK
unshare -Urn bash -c '
  set -e
  ip link set lo up
  setsid unshare -n -- sleep 120 & APID=$!
  setsid unshare -n -- sleep 120 & CPID=$!
  sleep 0.3

  # A <-> B link (B side .2). IPv4 transport + IPv6 global next hop, nodad.
  ip link add veth_ba type veth peer name veth_ab
  ip link set veth_ab netns $APID
  ip addr add 10.0.1.2/24 dev veth_ba
  ip -6 addr add 2001:db8:1::2/64 dev veth_ba nodad
  ip link set veth_ba up
  nsenter -t $APID -n ip addr add 10.0.1.1/24 dev veth_ab
  nsenter -t $APID -n ip -6 addr add 2001:db8:1::1/64 dev veth_ab nodad
  nsenter -t $APID -n ip link set veth_ab up
  nsenter -t $APID -n ip link set lo up

  # B <-> C link (B side .1).
  ip link add veth_bc type veth peer name veth_cb
  ip link set veth_cb netns $CPID
  ip addr add 10.0.2.1/24 dev veth_bc
  ip -6 addr add 2001:db8:2::1/64 dev veth_bc nodad
  ip link set veth_bc up
  nsenter -t $CPID -n ip addr add 10.0.2.2/24 dev veth_cb
  nsenter -t $CPID -n ip -6 addr add 2001:db8:2::2/64 dev veth_cb nodad
  nsenter -t $CPID -n ip link set veth_cb up
  nsenter -t $CPID -n ip link set lo up

  nsenter -t $APID -n "$WREN" --config "$WORK/a.toml" --backend kernel --socket "$WORK/a.sock" >"$WORK/a.log" 2>&1 &
  "$WREN" --config "$WORK/b.toml" --backend kernel --socket "$WORK/b.sock" >"$WORK/b.log" 2>&1 &
  nsenter -t $CPID -n "$WREN" --config "$WORK/c.toml" --backend kernel --socket "$WORK/c.sock" >"$WORK/c.log" 2>&1 &
  sleep 9

  ok=1
  {
    echo "=== wren show bgp neighbors (on B) ==="
    "$WREN" --socket "$WORK/b.sock" show bgp neighbors || true
    echo "=== wren show bgp (on C) ==="
    nsenter -t $CPID -n "$WREN" --socket "$WORK/c.sock" show bgp || true
    echo "=== ip -6 route show proto bgp (on C) ==="
    nsenter -t $CPID -n ip -6 route show proto bgp || true
  } > "$WORK/out.txt" 2>&1
  cat "$WORK/out.txt"

  # B and C share link2, so C forwards over the advertiser link-local (RFC 2545 §3),
  # pinned to the ingress interface — not the global next hop.
  grep -q "2001:db8:99::/64 via fe80:"               "$WORK/out.txt" || { echo "FAIL: C did not learn the propagated IPv6 route via B"; ok=0; }
  grep -q "as-path 65002 65001"                      "$WORK/out.txt" || { echo "FAIL: propagated route missing as-path 65002 65001"; ok=0; }
  grep -q "2001:db8:99::/64 via fe80:[0-9a-f:]* dev" "$WORK/out.txt" || { echo "FAIL: propagated IPv6 route not installed proto bgp on C"; ok=0; }

  if [[ $ok -ne 1 ]]; then
    echo "--- A log ---"; cat "$WORK/a.log"
    echo "--- B log ---"; cat "$WORK/b.log"
    echo "--- C log ---"; cat "$WORK/c.log"
  fi
  kill $APID $CPID 2>/dev/null || true
  exit $(( ok == 1 ? 0 : 1 ))
'
echo "bgp propagate ipv6 smoke test: OK"
