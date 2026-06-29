#!/usr/bin/env bash
# BGP unnumbered (IPv6 transport, RFC 5549) smoke test — run a full BGP session over
# an IPv6-ONLY link (no IPv4 on the veth at all), and carry an IPv4 route across it via
# Extended Next Hop Encoding, installing it through the IPv6 gateway (RTA_VIA).
#
# This is the transport counterpart to bgp-extended-nexthop-smoke.sh: there the BGP TCP
# session ran over IPv4 and only the *advertised next hop* was IPv6; here the session
# itself rides IPv6 — the unnumbered case where the link has no IPv4 address whatsoever.
#
# Self-contained and rootless: it runs inside throwaway `unshare -Urn` namespaces and
# never touches the host's interfaces or uplink. Binding TCP 179 needs
# CAP_NET_BIND_SERVICE and installing an IPv4-via-IPv6 route needs CAP_NET_ADMIN, both
# held by the netns-root inside `unshare -Urn`. Per-daemon control sockets are Unix
# sockets under a temp dir, not the network.
#
# Topology: A (AS 65001) <-eBGP-> B (AS 65002, passive), over an IPv6-only veth carrying
# 2001:db8::1/64 (A) and 2001:db8::2/64 (B) — and NO IPv4. A dials B at [2001:db8::2]:179
# (its address is given as a plain IPv6 literal in the config). B originates the IPv4
# prefix 10.99.0.0/24 and, with extended-nexthop negotiated, advertises it in
# MP_REACH_NLRI (AFI IPv4) with its IPv6 next-hop-self. On a directly-connected link the
# speaker sends a 32-octet next hop (global + link-local, RFC 2545); A forwards over the
# link-local pinned to the ingress interface, so it installs:
#
#     10.99.0.0/24 via inet6 fe80::… dev veth0 proto bgp
#
# NOTE on shell options: the outer `set -euo pipefail` exports SHELLOPTS (incl. nounset)
# into the inner `unshare -Urn bash -c` block; the netns block only writes output files
# and the assertions run in the OUTER shell afterwards.
#
# Usage:  bash scripts/bgp-unnumbered-smoke.sh
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
WREN="$REPO/target/debug/wren"

if [[ ! -x "$WREN" ]]; then
  echo "building wren (debug) ..."
  (cd "$REPO" && cargo build -p wren-daemon)
fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# A — eBGP over IPv6 transport, extended-nexthop on, installs IPv4-via-IPv6 routes.
# The router-id stays a 32-bit value even though the session itself is IPv6.
cat >"$WORK/a.toml" <<EOF
router-id = "10.0.0.1"
[bgp]
enabled  = true
local-as = 65001
[[bgp.neighbor]]
address          = "2001:db8::2"
remote-as        = 65002
extended-nexthop = true
EOF

# B — originates 10.99.0.0/24, advertises it with its IPv6 next-hop-self, passive.
cat >"$WORK/b.toml" <<EOF
router-id = "10.0.0.2"
[bgp]
enabled   = true
local-as  = 65002
network   = ["10.99.0.0/24"]
next-hop6 = "2001:db8::2"
[[bgp.neighbor]]
address          = "2001:db8::1"
remote-as        = 65001
passive          = true
extended-nexthop = true
EOF

export WREN WORK
unshare -Urn bash -c '
  set -e
  ip link set lo up
  setsid unshare -n -- sleep 40 & BPID=$!
  sleep 0.3
  ip link add veth0 type veth peer name veth1
  ip link set veth1 netns $BPID
  # IPv6-ONLY link: no IPv4 address is ever assigned to the veth, so the BGP TCP
  # session has nothing but IPv6 to ride on (the unnumbered case).
  ip addr add 2001:db8::1/64 dev veth0
  ip link set veth0 up
  nsenter -t $BPID -n ip addr add 2001:db8::2/64 dev veth1
  nsenter -t $BPID -n ip link set veth1 up
  nsenter -t $BPID -n ip link set lo up
  # Let IPv6 DAD settle so 2001:db8::1/2 are usable for the session + as a gateway.
  sleep 2

  nsenter -t $BPID -n "$WREN" --config "$WORK/b.toml" --backend kernel --socket "$WORK/b.sock" >"$WORK/b.log" 2>&1 &
  "$WREN" --config "$WORK/a.toml" --backend kernel --socket "$WORK/a.sock" >"$WORK/a.log" 2>&1 &
  sleep 8

  "$WREN" --socket "$WORK/a.sock" show bgp >"$WORK/a_bgp.txt" 2>&1 || true
  "$WREN" --socket "$WORK/a.sock" show bgp neighbors >"$WORK/a_nbr.txt" 2>&1 || true
  ip -4 route show proto bgp >"$WORK/a_kernel.txt" 2>&1 || true

  pkill -f "$WORK/a.sock" 2>/dev/null || true
  nsenter -t $BPID -n pkill -f "$WORK/b.sock" 2>/dev/null || true
  kill $BPID 2>/dev/null || true
'

echo "=== A: wren show bgp ==="
cat "$WORK/a_bgp.txt"
echo "=== A: wren show bgp neighbors ==="
cat "$WORK/a_nbr.txt"
echo "=== A: ip -4 route show proto bgp ==="
cat "$WORK/a_kernel.txt"

ok=1
# The session itself came up over IPv6 transport — A reports the IPv6 peer Established.
grep -Eq "2001:db8::2 AS 65002 Established" "$WORK/a_nbr.txt" \
  || { echo "FAIL: A has no Established session to the IPv6 peer 2001:db8::2"; ok=0; }
# A learned the IPv4 prefix with an IPv6 next hop in its BGP RIB (the link-local next
# hop the directly-connected speaker advertised, RFC 2545 + RFC 5549).
grep -Eq "10.99.0.0/24 via (2001:db8::2|fe80:)" "$WORK/a_bgp.txt" \
  || { echo "FAIL: A's BGP RIB missing 10.99.0.0/24 via an IPv6 next hop"; ok=0; }
# …and installed it in the kernel via that IPv6 gateway (RTA_VIA → 'via inet6'),
# pinned to the ingress interface for the link-local next hop.
grep -Eq "10.99.0.0/24 via inet6 (2001:db8::2|fe80:[0-9a-f:]+) dev veth0" "$WORK/a_kernel.txt" \
  || { echo "FAIL: A did not install 10.99.0.0/24 via inet6 <gw> dev veth0"; ok=0; }

if [[ $ok -ne 1 ]]; then echo "--- A log ---"; tail -20 "$WORK/a.log"; echo "--- B log ---"; tail -20 "$WORK/b.log"; fi
[[ $ok -eq 1 ]] || exit 1
echo "bgp unnumbered (IPv6 transport, RFC 5549) smoke test: OK"
