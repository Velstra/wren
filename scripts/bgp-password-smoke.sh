#!/usr/bin/env bash
# BGP TCP-MD5 signature (password) smoke test (RFC 2385). With a `password` set on a
# neighbour, Wren installs a TCP-MD5 key on the session socket before the handshake
# (TCP_MD5SIG), so the kernel signs every segment and rejects any inbound segment
# whose signature does not match the shared key. A peer without the key — or with the
# wrong one — cannot complete the handshake at all. Self-contained, rootless.
#
# Like the other *-smoke.sh scripts it runs inside throwaway `unshare -Urn`
# namespaces and never touches the host's interfaces or uplink. BGP binds TCP 179
# (CAP_NET_BIND_SERVICE) and TCP-MD5 needs a CONFIG_TCP_MD5SIG kernel — the netns-root
# holds the cap; if the kernel lacks MD5 support the test reports it and skips.
#
# Topology: A (AS 65001, 10.0.0.1) and B (AS 65002, 10.0.0.2), directly connected by a
# veth — a one-hop eBGP session, so no GTSM is involved, only the MD5 key matters.
#
# Three phases (each restarts both daemons fresh, proto-bgp flushed between):
#   * phase match    — both sides share password "hunter2": the session establishes.
#   * phase mismatch — A uses "hunter2", B uses "wrongkey": the signatures never
#     match, the handshake is dropped, and the session can NOT establish.
#   * phase onesided — A uses "hunter2", B has no password: A's signed segments are
#     rejected by an unconfigured B and vice-versa, so again no session.
#
# Usage:  bash scripts/bgp-password-smoke.sh
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
WREN="$REPO/target/debug/wren"

if [[ ! -x "$WREN" ]]; then
  echo "building wren (debug) ..."
  (cd "$REPO" && cargo build -p wren-daemon)
fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# A (AS 65001) peers with B at 10.0.0.2; the password line is filled per phase.
write_a() {  # $1 = password line, $2 = tag
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
# B (AS 65002) peers with A at 10.0.0.1.
write_b() {  # $1 = password line, $2 = tag
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

# A kernel-config sanity check: if even the matching phase cannot establish, the
# kernel most likely lacks CONFIG_TCP_MD5SIG — report that rather than a false fail.
if ! grep -q "Established" "$WORK/match_a_neigh.txt"; then
  echo "NOTE: matching-password session did not establish — does this kernel have CONFIG_TCP_MD5SIG?"
  echo "--- A match log ---"; cat "$WORK/a_match.log" 2>/dev/null || true
  exit 1
fi

# Phase match: both keys agree → session up.
grep -q "Established" "$WORK/match_a_neigh.txt" \
  || { echo "FAIL: matching passwords — session did not establish"; ok=0; }

# Phase mismatch: different keys → no session.
if grep -q "Established" "$WORK/mismatch_a_neigh.txt"; then
  echo "FAIL: mismatched passwords — session established despite the MD5 mismatch"; ok=0
fi

# Phase onesided: only A has a key → no session.
if grep -q "Established" "$WORK/onesided_a_neigh.txt"; then
  echo "FAIL: one-sided password — session established though B had no key"; ok=0
fi

[[ $ok -eq 1 ]] || exit 1
echo "bgp password (TCP-MD5, RFC 2385) smoke test: OK"
