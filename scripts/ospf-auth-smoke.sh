#!/usr/bin/env bash
# OSPFv2 packet authentication smoke test (RFC 2328 §D). With auth configured, every
# OSPF packet carries either a cleartext password (auth-type "text", AuType 1) or a
# keyed-MD5 digest (auth-type "md5", AuType 2); a router whose key or scheme does not
# match has its packets rejected and never forms an adjacency. Self-contained,
# rootless.
#
# Like the other ospf-*-smoke.sh scripts it runs inside throwaway `unshare -Urn`
# namespaces and never touches the host's interfaces or uplink. OSPF's raw
# IPPROTO_OSPF (89) sockets need CAP_NET_RAW, which the netns-root holds.
#
# Topology: A (10.0.0.1) and B (10.0.0.2), directly connected by a veth, point-to-
# point (no DR election, fast convergence).
#
# Three phases (each restarts both daemons fresh, proto-ospf flushed between):
#   * phase md5ok  — both run auth-type "md5" with key "ospfkey": adjacency reaches
#     Full.
#   * phase md5bad — A uses "ospfkey", B uses "wrongkey": the digests never verify,
#     packets are dropped, and no adjacency forms.
#   * phase textok — both run auth-type "text" with password "plainpw": adjacency
#     reaches Full again, proving the simple-password scheme too.
#
# Usage:  bash scripts/ospf-auth-smoke.sh
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
WREN="$REPO/target/debug/wren"

if [[ ! -x "$WREN" ]]; then
  echo "building wren (debug) ..."
  (cd "$REPO" && cargo build -p wren-daemon)
fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

write_a() {  # $1 = auth toml lines, $2 = tag
  cat >"$WORK/a_$2.toml" <<EOF
router-id = "10.0.0.1"
[ospf]
enabled      = true
network-type = "point-to-point"
area         = "0.0.0.0"
interfaces   = ["veth0"]
$1
EOF
}
write_b() {  # $1 = auth toml lines, $2 = tag
  cat >"$WORK/b_$2.toml" <<EOF
router-id = "10.0.0.2"
[ospf]
enabled      = true
network-type = "point-to-point"
area         = "0.0.0.0"
interfaces   = ["veth1"]
$1
EOF
}
write_a 'auth-type = "md5"
auth-key  = "ospfkey"'                  md5ok
write_b 'auth-type = "md5"
auth-key  = "ospfkey"'                  md5ok
write_a 'auth-type = "md5"
auth-key  = "ospfkey"'                  md5bad
write_b 'auth-type = "md5"
auth-key  = "wrongkey"'                 md5bad
write_a 'auth-type = "text"
auth-key  = "plainpw"'                  textok
write_b 'auth-type = "text"
auth-key  = "plainpw"'                  textok

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
    sleep 25
    "$WREN" --socket "$WORK/a.sock" show ospf neighbors >"$WORK/${tag}_a_neigh.txt" 2>&1 || true
    pkill -f "$WORK/a.sock" 2>/dev/null || true
    nsenter -t $BPID -n pkill -f "$WORK/b.sock" 2>/dev/null || true
    sleep 1
    nsenter -t $BPID -n ip route flush proto ospf 2>/dev/null || true
    ip route flush proto ospf 2>/dev/null || true
  }

  run_phase md5ok
  run_phase md5bad
  run_phase textok
  kill $BPID 2>/dev/null || true
'

ok=1
for tag in md5ok md5bad textok; do
  echo "=== phase $tag: A show ospf neighbors ==="; cat "$WORK/${tag}_a_neigh.txt"
done

# Phase md5ok: matching MD5 keys → adjacency Full.
grep -q "state Full" "$WORK/md5ok_a_neigh.txt" \
  || { echo "FAIL: md5 matching keys — adjacency did not reach Full"; ok=0; }

# Phase md5bad: mismatched MD5 keys → no Full adjacency.
if grep -q "state Full" "$WORK/md5bad_a_neigh.txt"; then
  echo "FAIL: md5 mismatched keys — adjacency reached Full despite the auth mismatch"; ok=0
fi

# Phase textok: matching simple passwords → adjacency Full.
grep -q "state Full" "$WORK/textok_a_neigh.txt" \
  || { echo "FAIL: text matching password — adjacency did not reach Full"; ok=0; }

if [[ $ok -ne 1 ]]; then echo "--- A md5bad log ---"; cat "$WORK/a_md5bad.log" 2>/dev/null || true; fi
[[ $ok -eq 1 ]] || exit 1
echo "ospf authentication (RFC 2328 D) smoke test: OK"
