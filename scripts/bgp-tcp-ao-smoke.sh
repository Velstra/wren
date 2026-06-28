#!/usr/bin/env bash
# BGP TCP-AO smoke test (RFC 5925) — the modern successor to TCP-MD5. With an `ao-key`
# set on a neighbour, Wren installs a TCP-AO master key on the session socket before
# the handshake (TCP_AO_ADD_KEY, HMAC-SHA-1); the kernel then authenticates every
# segment with per-connection traffic keys. A peer without the key — or with the wrong
# one — cannot complete the handshake. Self-contained, rootless.
#
# Like the other *-smoke.sh scripts it runs inside throwaway `unshare -Urn`
# namespaces and never touches the host's interfaces or uplink. BGP binds TCP 179
# (CAP_NET_BIND_SERVICE); TCP-AO needs a CONFIG_TCP_AO kernel (Linux 5.18+) — if the
# kernel lacks it the test reports that and exits rather than failing falsely.
#
# Topology: A (AS 65001, 10.0.0.1) and B (AS 65002, 10.0.0.2), directly connected by a
# veth — a one-hop eBGP session; only the AO key matters here.
#
# Three phases (each restarts both daemons fresh, proto-bgp flushed between):
#   * phase aook   — both share ao-key "aosecret" (key id 100): the session establishes.
#   * phase aobad  — A uses "aosecret", B uses "wrongkey": the MACs never match, the
#     handshake is dropped, and the session can NOT establish.
#   * phase onesided — A uses "aosecret", B has none: A demands AO on the session and
#     B's unsigned segments are rejected (and vice-versa), so again no session.
#
# Usage:  bash scripts/bgp-tcp-ao-smoke.sh
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
address   = "10.0.0.2"
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
address   = "10.0.0.1"
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
  ip addr add 10.0.0.1/24 dev veth0; ip link set veth0 up
  nsenter -t $BPID -n ip addr add 10.0.0.2/24 dev veth1
  nsenter -t $BPID -n ip link set veth1 up
  nsenter -t $BPID -n ip link set lo up

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

# Phase aook: matching AO keys → session up.
grep -q "Established" "$WORK/aook_a_neigh.txt" \
  || { echo "FAIL: matching AO keys — session did not establish"; ok=0; }

# Phase aobad: different keys → no session.
if grep -q "Established" "$WORK/aobad_a_neigh.txt"; then
  echo "FAIL: mismatched AO keys — session established despite the MAC mismatch"; ok=0
fi

# Phase onesided: only A has a key → no session.
if grep -q "Established" "$WORK/onesided_a_neigh.txt"; then
  echo "FAIL: one-sided AO — session established though B had no key"; ok=0
fi

[[ $ok -eq 1 ]] || exit 1
echo "bgp tcp-ao (RFC 5925) smoke test: OK"
