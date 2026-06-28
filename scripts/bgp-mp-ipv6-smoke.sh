#!/usr/bin/env bash
# MP-BGP IPv6-unicast smoke test (RFC 4760) — BGP carries an IPv6 prefix over an
# IPv4 transport session using the Multiprotocol capability and MP_REACH_NLRI.
# Fully self-contained and rootless.
#
# Like the other bgp-*-smoke.sh scripts it runs inside throwaway `unshare -Urn`
# namespaces and never touches the host's interfaces or uplink. Per-daemon control
# sockets live under a temp dir (Unix sockets, not the network).
#
# Topology: A (AS 65001, active) <-eBGP-> B (AS 65002, passive). The TCP session
# rides IPv4 (10.0.0.1 <-> 10.0.0.2); the shared veth ALSO carries IPv6 globals
# (2001:db8::1 on A, 2001:db8::2 on B). A originates the IPv6 network
# 2001:db8:99::/64 with `next-hop6 = 2001:db8::1`. The test asserts:
#   * both speakers negotiate the IPv6 multiprotocol capability and reach
#     Established (so A actually sends MP_REACH_NLRI);
#   * B learns 2001:db8:99::/64 via 2001:db8::1 in its BGP Loc-RIB; and
#   * B installs it into the kernel IPv6 table `proto bgp`.
#
# This exercises the whole MP-BGP path: capability negotiation in the OPEN, the
# MP_REACH_NLRI advertise path with next-hop-self, the receive path that pulls the
# v6 next hop out of MP_REACH, the v6 Loc-RIB, and the v6 kernel FIB install.
#
# Usage:  bash scripts/bgp-mp-ipv6-smoke.sh
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
WREN="$REPO/target/debug/wren"

if [[ ! -x "$WREN" ]]; then
  echo "building wren (debug) ..."
  (cd "$REPO" && cargo build -p wren-daemon)
fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# A (active) originates an IPv6 network, advertised next-hop-self over MP-BGP.
cat >"$WORK/a.toml" <<EOF
router-id = "10.0.0.1"
[bgp]
enabled   = true
local-as  = 65001
network   = ["2001:db8:99::/64"]
next-hop6 = "2001:db8::1"
[[bgp.neighbor]]
address   = "10.0.0.2"
remote-as = 65002
EOF

# B (passive) just peers; it should learn the IPv6 prefix.
cat >"$WORK/b.toml" <<EOF
router-id = "10.0.0.2"
[bgp]
enabled   = true
local-as  = 65002
[[bgp.neighbor]]
address   = "10.0.0.1"
remote-as = 65001
passive   = true
EOF

export WREN WORK
unshare -Urn bash -c '
  set -e
  ip link set lo up
  setsid unshare -n -- sleep 60 & BPID=$!
  sleep 0.3
  ip link add veth0 type veth peer name veth1
  ip link set veth1 netns $BPID
  # IPv4 (the BGP transport) + IPv6 global (the MP_REACH next hop) on each side.
  # `nodad` skips Duplicate Address Detection so the v6 addresses are usable at once.
  ip addr add 10.0.0.1/24 dev veth0
  ip -6 addr add 2001:db8::1/64 dev veth0 nodad
  ip link set veth0 up
  nsenter -t $BPID -n ip addr add 10.0.0.2/24 dev veth1
  nsenter -t $BPID -n ip -6 addr add 2001:db8::2/64 dev veth1 nodad
  nsenter -t $BPID -n ip link set veth1 up
  nsenter -t $BPID -n ip link set lo up

  nsenter -t $BPID -n "$WREN" --config "$WORK/b.toml" --backend kernel --socket "$WORK/b.sock" >"$WORK/b.log" 2>&1 &
  "$WREN" --config "$WORK/a.toml" --backend kernel --socket "$WORK/a.sock" >"$WORK/a.log" 2>&1 &
  sleep 6

  ok=1
  {
    echo "=== wren show bgp neighbors (on B) ==="
    nsenter -t $BPID -n "$WREN" --socket "$WORK/b.sock" show bgp neighbors || true
    echo "=== wren show bgp (on B) ==="
    nsenter -t $BPID -n "$WREN" --socket "$WORK/b.sock" show bgp || true
    echo "=== ip -6 route show proto bgp (on B) ==="
    nsenter -t $BPID -n ip -6 route show proto bgp || true
  } > "$WORK/out.txt" 2>&1
  cat "$WORK/out.txt"

  grep -q "10.0.0.1 AS 65001 Established"            "$WORK/out.txt" || { echo "FAIL: session not Established"; ok=0; }
  grep -q "2001:db8:99::/64 via 2001:db8::1"         "$WORK/out.txt" || { echo "FAIL: B missing IPv6 route in BGP Loc-RIB"; ok=0; }
  # `ip -6 route show proto bgp` already filters to proto bgp, so the kernel line
  # (with the dev) appearing under it proves the v6 FIB install.
  grep -q "2001:db8:99::/64 via 2001:db8::1 dev"     "$WORK/out.txt" || { echo "FAIL: IPv6 route not installed proto bgp on B"; ok=0; }

  if [[ $ok -ne 1 ]]; then echo "--- A log ---"; cat "$WORK/a.log"; echo "--- B log ---"; cat "$WORK/b.log"; fi
  kill $BPID 2>/dev/null || true
  exit $(( ok == 1 ? 0 : 1 ))
'
echo "bgp mp-ipv6 smoke test: OK"
