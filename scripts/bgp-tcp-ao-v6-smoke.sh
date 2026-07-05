#!/usr/bin/env bash
# BGP TCP-AO over IPv6 transport smoke test (RFC 5925, A8-rest) — the IPv6 counterpart
# of bgp-tcp-ao-smoke.sh. The BGP TCP session itself rides IPv6 (the neighbour address is
# a plain IPv6 literal, an IPv6-only link — no IPv4 on the veth at all), and Wren installs
# a TCP-AO master key (TCP_AO_ADD_KEY, HMAC-SHA-1, /128 host match) on the session socket
# — on BOTH the connect side (hand-built AF_INET6 connect) and the listen side (the
# dual-stack listener installs each peer's key before `listen`) — before the handshake.
# A peer without the key, or with the wrong one, cannot complete the handshake.
#
# Like the other *-smoke.sh scripts it runs inside throwaway `unshare -Urn` namespaces
# and never touches the host's interfaces or uplink. BGP binds TCP 179
# (CAP_NET_BIND_SERVICE); TCP-AO needs a CONFIG_TCP_AO kernel (Linux 5.18+) — if the
# kernel lacks it the test reports that and exits rather than failing falsely.
#
# Topology: A (AS 65001, 2001:db8::1) and B (AS 65002, 2001:db8::2), directly connected
# by an IPv6-only veth — a one-hop eBGP session over IPv6 transport; only the AO key
# matters here. Both peers are active, so the AO key is exercised on both the dialled
# (connect) and accepted (listen) side across the pair.
#
# Three phases (each restarts both daemons fresh):
#   * phase aook   — both share ao-key "aosecret" (key id 100): the session establishes.
#   * phase aobad  — A uses "aosecret", B uses "wrongkey": the MACs never match, the
#     handshake is dropped, and the session can NOT establish.
#   * phase onesided — A uses "aosecret", B has none: A demands AO on the session and
#     B's unsigned segments are rejected (and vice-versa), so again no session.
#
# Usage:  bash scripts/bgp-tcp-ao-v6-smoke.sh
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
WREN="$REPO/target/debug/wren"

if [[ ! -x "$WREN" ]]; then
  echo "building wren (debug) ..."
  (cd "$REPO" && cargo build -p wren-daemon)
fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

write_a() {  # $1 = ao toml lines, $2 = tag
  cat >"$WORK/a_$2.toml" <<EOF
router-id = "10.0.0.1"
[bgp]
enabled  = true
local-as = 65001
[[bgp.neighbor]]
address   = "2001:db8::2"
remote-as = 65002
$1
EOF
}
write_b() {  # $1 = ao toml lines, $2 = tag
  cat >"$WORK/b_$2.toml" <<EOF
router-id = "10.0.0.2"
[bgp]
enabled  = true
local-as = 65002
[[bgp.neighbor]]
address   = "2001:db8::1"
remote-as = 65001
$1
EOF
}
write_a 'ao-key = "aosecret"
ao-key-id = 100'                        aook
write_b 'ao-key = "aosecret"
ao-key-id = 100'                        aook
write_a 'ao-key = "aosecret"
ao-key-id = 100'                        aobad
write_b 'ao-key = "wrongkey"
ao-key-id = 100'                        aobad
write_a 'ao-key = "aosecret"
ao-key-id = 100'                        onesided
write_b ''                              onesided

export WREN WORK
unshare -Urn bash -c '
  set -e
  ip link set lo up
  setsid unshare -n -- sleep 200 & BPID=$!
  sleep 0.3
  ip link add veth0 type veth peer name veth1
  ip link set veth1 netns $BPID
  # IPv6-ONLY link: the BGP TCP session has nothing but IPv6 to ride on.
  ip addr add 2001:db8::1/64 dev veth0; ip link set veth0 up
  nsenter -t $BPID -n ip addr add 2001:db8::2/64 dev veth1
  nsenter -t $BPID -n ip link set veth1 up
  nsenter -t $BPID -n ip link set lo up
  # Let IPv6 DAD settle so 2001:db8::1/2 are usable for the session.
  sleep 2

  run_phase() {
    tag="$1"
    nsenter -t $BPID -n "$WREN" --config "$WORK/b_$tag.toml" --backend kernel --socket "$WORK/b.sock" >"$WORK/b_$tag.log" 2>&1 &
    "$WREN" --config "$WORK/a_$tag.toml" --backend kernel --socket "$WORK/a.sock" >"$WORK/a_$tag.log" 2>&1 &
    sleep 18
    "$WREN" --socket "$WORK/a.sock" show bgp neighbors >"$WORK/${tag}_a_neigh.txt" 2>&1 || true
    nsenter -t $BPID -n "$WREN" --socket "$WORK/b.sock" show bgp neighbors >"$WORK/${tag}_b_neigh.txt" 2>&1 || true
    pkill -f "$WORK/a.sock" 2>/dev/null || true
    nsenter -t $BPID -n pkill -f "$WORK/b.sock" 2>/dev/null || true
    sleep 1
  }

  run_phase aook
  run_phase aobad
  run_phase onesided
  kill $BPID 2>/dev/null || true
'

ok=1
for tag in aook aobad onesided; do
  echo "=== phase $tag: A show bgp neighbors ==="; cat "$WORK/${tag}_a_neigh.txt"
  echo "=== phase $tag: B show bgp neighbors ==="; cat "$WORK/${tag}_b_neigh.txt"
done

# Kernel-support sanity: if even the matching phase fails, the kernel likely lacks
# CONFIG_TCP_AO — report rather than fail falsely.
if ! grep -q "Established" "$WORK/aook_a_neigh.txt"; then
  echo "NOTE: matching-key session did not establish — does this kernel have CONFIG_TCP_AO (Linux 5.18+)?"
  echo "--- A aook log ---"; cat "$WORK/a_aook.log" 2>/dev/null || true
  exit 1
fi

# Phase aook: matching AO keys over IPv6 transport → session up.
grep -Eq "2001:db8::2 AS 65002 Established" "$WORK/aook_a_neigh.txt" \
  || { echo "FAIL: matching AO keys (IPv6) — session did not establish"; ok=0; }

# Phase aobad: different keys → no session.
if grep -Eq "2001:db8::2 AS 65002 Established" "$WORK/aobad_a_neigh.txt"; then
  echo "FAIL: mismatched AO keys (IPv6) — session established despite the MAC mismatch"; ok=0
fi

# Phase onesided: only A has a key → no session.
if grep -Eq "2001:db8::2 AS 65002 Established" "$WORK/onesided_a_neigh.txt"; then
  echo "FAIL: one-sided AO (IPv6) — session established though B had no key"; ok=0
fi

[[ $ok -eq 1 ]] || exit 1
echo "bgp tcp-ao over IPv6 transport (RFC 5925) smoke test: OK"
