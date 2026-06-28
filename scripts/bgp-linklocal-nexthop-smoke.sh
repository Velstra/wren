#!/usr/bin/env bash
# MP-BGP link-local next-hop smoke test (RFC 2545 §3) — a speaker advertising an
# IPv6 route over a directly-connected eBGP session sends a 32-octet next hop
# (its global address followed by its link-local), and the receiver installs the
# route via that *link-local*, pinned to the interface it arrived on. Fully
# self-contained and rootless.
#
# Like the other bgp-*-smoke.sh scripts it runs inside throwaway `unshare -Urn`
# namespaces and never touches the host's interfaces or uplink. Per-daemon control
# sockets live under a temp dir (Unix sockets, not the network).
#
# Topology: A (AS 65001, active) <-eBGP-> B (AS 65002, passive). The TCP session
# rides IPv4 (10.0.0.1 <-> 10.0.0.2); the shared veth also carries IPv6 globals
# (2001:db8::1/::2) and the kernel's automatic link-locals (fe80::/64). A
# originates 2001:db8:99::/64 with `next-hop6 = 2001:db8::1`. Because A and B share
# the subnet, A appends its link-local to the MP_REACH next hop (RFC 2545), so B
# must forward over A's *link-local*, not the global. The test asserts:
#   * the session reaches Established; and
#   * B learns and installs 2001:db8:99::/64 via a `fe80::` next hop pinned to its
#     veth (`dev veth1`) — proving the 32-octet next hop and interface pinning,
#     not the global 2001:db8::1.
#
# Usage:  bash scripts/bgp-linklocal-nexthop-smoke.sh
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
WREN="$REPO/target/debug/wren"

if [[ ! -x "$WREN" ]]; then
  echo "building wren (debug) ..."
  (cd "$REPO" && cargo build -p wren-daemon)
fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# A (active) originates the IPv6 network; next-hop-self is its global on the link,
# and the link-local is appended automatically because the peer shares the subnet.
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

# B (passive) peers and should learn the prefix via A's link-local.
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
  ip addr add 10.0.0.1/24 dev veth0
  ip -6 addr add 2001:db8::1/64 dev veth0 nodad
  ip link set veth0 up
  nsenter -t $BPID -n ip addr add 10.0.0.2/24 dev veth1
  nsenter -t $BPID -n ip -6 addr add 2001:db8::2/64 dev veth1 nodad
  nsenter -t $BPID -n ip link set veth1 up
  nsenter -t $BPID -n ip link set lo up

  # Let the kernel-assigned link-locals (fe80::, used for the RFC 2545 next hop)
  # finish coming up before the daemons resolve their interface.
  sleep 1.5

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

  grep -q "10.0.0.1 AS 65001 Established"           "$WORK/out.txt" || { echo "FAIL: session not Established"; ok=0; }
  # The Loc-RIB and kernel route must use a link-local next hop pinned to the dev,
  # NOT the global 2001:db8::1 — that is the RFC 2545 behaviour under test.
  grep -q "2001:db8:99::/64 via fe80:"              "$WORK/out.txt" || { echo "FAIL: B did not learn the route via a link-local next hop"; ok=0; }
  grep -q "2001:db8:99::/64 via fe80:[0-9a-f:]* dev veth1" "$WORK/out.txt" || { echo "FAIL: link-local route not installed pinned to the interface on B"; ok=0; }
  if grep -q "2001:db8:99::/64 via 2001:db8::1" "$WORK/out.txt"; then echo "FAIL: route used the global next hop, not the link-local"; ok=0; fi

  if [[ $ok -ne 1 ]]; then echo "--- A log ---"; cat "$WORK/a.log"; echo "--- B log ---"; cat "$WORK/b.log"; fi
  kill $BPID 2>/dev/null || true
  exit $(( ok == 1 ? 0 : 1 ))
'
echo "bgp link-local next-hop smoke test: OK"
