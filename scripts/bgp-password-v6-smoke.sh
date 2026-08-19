#!/usr/bin/env bash
# BGP TCP-MD5 signature over IPv6 transport smoke test (RFC 2385, A8-rest) — the IPv6
# counterpart of bgp-password-smoke.sh. The BGP TCP session itself rides IPv6 (the
# neighbour address is a plain IPv6 literal, an IPv6-only link), and Wren installs a
# TCP-MD5 key (TCP_MD5SIG, sockaddr_in6) on the session socket — on BOTH the connect side
# (hand-built AF_INET6 connect) and the listen side (the dual-stack listener installs
# each peer's key before `listen`) — before the handshake. A peer without the key, or
# with the wrong one, cannot complete the handshake. Self-contained, rootless.
#
# Runs inside throwaway `unshare -Urn` namespaces; never touches the host's interfaces.
# BGP binds TCP 179 (CAP_NET_BIND_SERVICE); TCP-MD5 needs a CONFIG_TCP_MD5SIG kernel — if
# the kernel lacks it the test reports that and exits rather than failing falsely.
#
# Topology: A (AS 65001, 2001:db8::1) and B (AS 65002, 2001:db8::2), directly connected
# by an IPv6-only veth — a one-hop eBGP session over IPv6 transport; both peers active,
# so the key is exercised on both the dialled (connect) and accepted (listen) side.
#
# Three phases (each restarts both daemons fresh):
#   * phase match    — both sides share password "hunter2": the session establishes.
#   * phase mismatch — A uses "hunter2", B uses "wrongkey": no session.
#   * phase onesided — A uses "hunter2", B has none: no session.
#
# Usage:  bash scripts/bgp-password-v6-smoke.sh
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
WREN="$REPO/target/debug/wren"

if [[ ! -x "$WREN" ]]; then
  echo "building wren (debug) ..."
  (cd "$REPO" && cargo build -p wren-daemon)
fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

write_a() {  # $1 = password line, $2 = tag
  cat >"$WORK/a_$2.toml" <<EOF
router-id = "10.0.0.1"
[bgp]
enabled             = true
local-as            = 65001
ebgp-require-policy = false
[[bgp.neighbor]]
address   = "2001:db8::2"
remote-as = 65002
$1
EOF
}
write_b() {  # $1 = password line, $2 = tag
  cat >"$WORK/b_$2.toml" <<EOF
router-id = "10.0.0.2"
[bgp]
enabled             = true
local-as            = 65002
ebgp-require-policy = false
[[bgp.neighbor]]
address   = "2001:db8::1"
remote-as = 65001
$1
EOF
}
write_a 'password = "hunter2"'   match
write_b 'password = "hunter2"'   match
write_a 'password = "hunter2"'   mismatch
write_b 'password = "wrongkey"'  mismatch
write_a 'password = "hunter2"'   onesided
write_b ''                       onesided

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
  sleep 2  # let IPv6 DAD settle

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

  run_phase match
  run_phase mismatch
  run_phase onesided
  kill $BPID 2>/dev/null || true
'

ok=1
for tag in match mismatch onesided; do
  echo "=== phase $tag: A show bgp neighbors ==="; cat "$WORK/${tag}_a_neigh.txt"
  echo "=== phase $tag: B show bgp neighbors ==="; cat "$WORK/${tag}_b_neigh.txt"
done

# Kernel-support sanity: if even the matching phase fails, the kernel likely lacks
# CONFIG_TCP_MD5SIG — report rather than fail falsely.
if ! grep -q "Established" "$WORK/match_a_neigh.txt"; then
  echo "NOTE: matching-password session did not establish — does this kernel have CONFIG_TCP_MD5SIG?"
  echo "--- A match log ---"; cat "$WORK/a_match.log" 2>/dev/null || true
  exit 1
fi

# Phase match: matching passwords over IPv6 transport → session up.
grep -Eq "2001:db8::2 AS 65002 Established" "$WORK/match_a_neigh.txt" \
  || { echo "FAIL: matching TCP-MD5 (IPv6) — session did not establish"; ok=0; }

# Phase mismatch: different passwords → no session.
if grep -Eq "2001:db8::2 AS 65002 Established" "$WORK/mismatch_a_neigh.txt"; then
  echo "FAIL: mismatched TCP-MD5 (IPv6) — session established despite the signature mismatch"; ok=0
fi

# Phase onesided: only A has a password → no session.
if grep -Eq "2001:db8::2 AS 65002 Established" "$WORK/onesided_a_neigh.txt"; then
  echo "FAIL: one-sided TCP-MD5 (IPv6) — session established though B had no password"; ok=0
fi

[[ $ok -eq 1 ]] || exit 1
echo "bgp tcp-md5 over IPv6 transport (RFC 2385) smoke test: OK"
