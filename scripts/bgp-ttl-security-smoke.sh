#!/usr/bin/env bash
# BGP GTSM / TTL-security smoke test (RFC 5082). A speaker with GTSM enabled sends
# with IP TTL 255 and rejects any received packet whose TTL is below 255 − (hops − 1),
# so an off-path peer further than `hops` away — whose packets arrive with a
# decremented TTL — cannot keep a session up. Self-contained, rootless.
#
# Like the other *-smoke.sh scripts it runs inside throwaway `unshare -Urn`
# namespaces and never touches the host's interfaces or uplink. BGP binds TCP 179,
# which needs CAP_NET_BIND_SERVICE — the netns-root holds it.
#
# Topology: A and B are eBGP peers TWO hops apart, with a plain forwarding router M
# between them (M runs no wren, just ip_forward). Every A→B / B→A packet crosses M,
# so its TTL is decremented by one on the way:
#
#     A (AS 65001, 10.0.1.1) ──[10.0.1.0/24]── M ──[10.0.2.0/24]── B (AS 65002, 10.0.2.1)
#
# Three phases (each restarts A and B fresh, M stays up, proto-bgp flushed between):
#   * phase 1 — no GTSM: the 2-hop eBGP session comes up (wren does not pin eBGP to
#     directly-connected, so a multihop session is allowed). The baseline.
#   * phase 2 — ttl-security = 1: both sides now send TTL 255 and demand a min TTL of
#     255, but M decremented the packets to 254 — the kernel drops them and the
#     session can NOT establish. This is the security property.
#   * phase 3 — ttl-security = 2: the min TTL is now 254, which the once-decremented
#     packets meet, so the session comes up again — GTSM admits a peer at the
#     configured distance and only rejects ones beyond it.
#
# Usage:  bash scripts/bgp-ttl-security-smoke.sh
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
WREN="$REPO/target/debug/wren"

if [[ ! -x "$WREN" ]]; then
  echo "building wren (debug) ..."
  (cd "$REPO" && cargo build -p wren-daemon)
fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# A (AS 65001) peers with B at 10.0.2.1; the ttl-security line is filled per phase.
write_a() {  # $1 = ttl line, $2 = tag
  cat >"$WORK/a_$2.toml" <<EOF
router-id = "10.0.0.1"
[bgp]
enabled  = true
local-as = 65001
[[bgp.neighbor]]
address   = "10.0.2.1"
remote-as = 65002
$1
EOF
}
# B (AS 65002) peers with A at 10.0.1.1.
write_b() {  # $1 = ttl line, $2 = tag
  cat >"$WORK/b_$2.toml" <<EOF
router-id = "10.0.0.2"
[bgp]
enabled  = true
local-as = 65002
[[bgp.neighbor]]
address   = "10.0.1.1"
remote-as = 65001
$1
EOF
}
write_a ''                       none
write_a 'ttl-security = 1'       h1
write_a 'ttl-security = 2'       h2
write_b ''                       none
write_b 'ttl-security = 1'       h1
write_b 'ttl-security = 2'       h2

export WREN WORK
unshare -Urn bash -c '
  set -e
  ip link set lo up
  setsid unshare -n -- sleep 200 & MPID=$!   # M, the forwarding router
  setsid unshare -n -- sleep 200 & BPID=$!   # B
  sleep 0.3

  # A↔M link (10.0.1.0/24) and M↔B link (10.0.2.0/24).
  ip link add veth_am type veth peer name veth_ma
  ip link add veth_mb type veth peer name veth_bm
  ip link set veth_ma netns $MPID
  ip link set veth_mb netns $MPID
  ip link set veth_bm netns $BPID

  # A (this namespace): 10.0.1.1, route to B-subnet via M.
  ip addr add 10.0.1.1/24 dev veth_am; ip link set veth_am up
  ip route add 10.0.2.0/24 via 10.0.1.2

  # M: both links + forwarding on.
  nsenter -t $MPID -n ip link set lo up
  nsenter -t $MPID -n ip addr add 10.0.1.2/24 dev veth_ma
  nsenter -t $MPID -n ip addr add 10.0.2.2/24 dev veth_mb
  nsenter -t $MPID -n ip link set veth_ma up
  nsenter -t $MPID -n ip link set veth_mb up
  nsenter -t $MPID -n sysctl -wq net.ipv4.ip_forward=1

  # B: 10.0.2.1, route to A-subnet via M.
  nsenter -t $BPID -n ip link set lo up
  nsenter -t $BPID -n ip addr add 10.0.2.1/24 dev veth_bm
  nsenter -t $BPID -n ip link set veth_bm up
  nsenter -t $BPID -n ip route add 10.0.1.0/24 via 10.0.2.2

  run_phase() {
    tag="$1"
    nsenter -t $BPID -n "$WREN" --config "$WORK/b_$tag.toml" --backend kernel --socket "$WORK/b.sock" >"$WORK/b_$tag.log" 2>&1 &
    "$WREN" --config "$WORK/a_$tag.toml" --backend kernel --socket "$WORK/a.sock" >"$WORK/a_$tag.log" 2>&1 &
    sleep 22
    nsenter -t $BPID -n "$WREN" --socket "$WORK/b.sock" show bgp neighbors >"$WORK/${tag}_b_neigh.txt" 2>&1 || true
    "$WREN" --socket "$WORK/a.sock" show bgp neighbors >"$WORK/${tag}_a_neigh.txt" 2>&1 || true
    pkill -f "$WORK/a.sock" 2>/dev/null || true
    nsenter -t $BPID -n pkill -f "$WORK/b.sock" 2>/dev/null || true
    sleep 1
  }

  run_phase none
  run_phase h1
  run_phase h2
  kill $MPID $BPID 2>/dev/null || true
'

ok=1
for tag in none h1 h2; do
  echo "=== phase $tag: B show bgp neighbors ==="; cat "$WORK/${tag}_b_neigh.txt"
  echo "=== phase $tag: A show bgp neighbors ==="; cat "$WORK/${tag}_a_neigh.txt"
done

# Phase 1 (no GTSM): the 2-hop session establishes.
grep -q "Established" "$WORK/none_b_neigh.txt" \
  || { echo "FAIL: no-GTSM — the 2-hop eBGP session did not establish"; ok=0; }

# Phase 2 (ttl-security=1): packets arrive at TTL 254 < min 255 → no session.
if grep -q "Established" "$WORK/h1_b_neigh.txt"; then
  echo "FAIL: ttl-security=1 — the 2-hop session established despite the TTL check"; ok=0
fi

# Phase 3 (ttl-security=2): min TTL 254 admits the once-decremented packets again.
grep -q "Established" "$WORK/h2_b_neigh.txt" \
  || { echo "FAIL: ttl-security=2 — the 2-hop session did not re-establish at the right distance"; ok=0; }

if [[ $ok -ne 1 ]]; then echo "--- B h1 log ---"; cat "$WORK/b_h1.log" 2>/dev/null || true; fi
[[ $ok -eq 1 ]] || exit 1
echo "bgp ttl-security (GTSM) smoke test: OK"
