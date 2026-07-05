#!/usr/bin/env bash
# OSPFv2 cryptographic anti-replay smoke test (RFC 2328 §D.3). With MD5 authentication
# every packet carries a keyed digest *and* a cryptographic sequence number. The digest
# alone does not stop a replay — a captured packet's digest still verifies — so a
# receiver must additionally reject packets whose sequence number regressed below the
# highest already accepted from that neighbour. This test proves Wren does exactly that,
# and that the `auth-replay-protection = false` knob disables the check. Self-contained,
# rootless.
#
# Like the other ospf-*-smoke.sh scripts it runs inside throwaway `unshare -Urn`
# namespaces and never touches the host's interfaces or uplink.
#
# Topology: WREN (10.0.0.2) on veth0, and a tiny Python packet injector (10.0.0.1) on
# veth1 in a second netns. The injector hand-builds valid MD5-authenticated OSPF Hellos
# (correct digest for the shared key "ospfkey") and multicasts them to 224.0.0.5, so the
# only cryptographic OSPF packets Wren sees are the ones we control the sequence of.
#
# Two phases (Wren restarted fresh, debug logging on so the drop is observable):
#   * phase on  — replay protection at its default (on). The injector sends seq=5000
#     (accepted, seeds the counter), then seq=4000 (a replay: lower → dropped), then
#     seq=6000 (advances → accepted). Wren must log exactly one replay drop, for 4000.
#   * phase off — `auth-replay-protection = false`. The same seq=5000 then seq=4000: the
#     stale packet must NOT be dropped, proving the knob turns the check off.
#
# Usage:  bash scripts/ospf-antireplay-smoke.sh
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
WREN="$REPO/target/debug/wren"

if [[ ! -x "$WREN" ]]; then
  echo "building wren (debug) ..."
  (cd "$REPO" && cargo build -p wren-daemon)
fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

cat >"$WORK/on.toml" <<EOF
router-id = "10.0.0.2"
[ospf]
enabled      = true
network-type = "point-to-point"
area         = "0.0.0.0"
interfaces   = ["veth0"]
auth-type    = "md5"
auth-key     = "ospfkey"
EOF
cat >"$WORK/off.toml" <<EOF
router-id = "10.0.0.2"
[ospf]
enabled                 = true
network-type            = "point-to-point"
area                    = "0.0.0.0"
interfaces              = ["veth0"]
auth-type               = "md5"
auth-key                = "ospfkey"
auth-replay-protection  = false
EOF

# The injector: hand-build a valid MD5-authenticated OSPF Hello with a chosen crypto
# sequence number and multicast it to AllSPFRouters. Argument: one or more seq numbers.
cat >"$WORK/inject.py" <<'PY'
import hashlib, socket, struct, sys, time

KEY = b"ospfkey"
KEY_ID = 1
ROUTER_ID = "10.0.0.1"
AREA = "0.0.0.0"
SRC_IF = "10.0.0.1"

def hello_md5(seq):
    # Hello body (§A.3.2), 20 bytes, no neighbours.
    body = struct.pack("!4sHBBI4s4s",
        socket.inet_aton("255.255.255.0"), 10, 0x02, 1, 40,
        b"\x00\x00\x00\x00", b"\x00\x00\x00\x00")
    length = 24 + len(body)
    # Common header: ver, type(Hello=1), length, router-id, area, checksum(0 for MD5),
    # autype(2), then the 8-byte auth field: 0,0,key-id,digest-len(16),seq(4).
    header = struct.pack("!BBH4s4sHH", 2, 1, length,
        socket.inet_aton(ROUTER_ID), socket.inet_aton(AREA), 0, 2)
    header += struct.pack("!BBBBI", 0, 0, KEY_ID, 16, seq)
    packet = header + body
    key16 = KEY.ljust(16, b"\x00")[:16]
    return packet + hashlib.md5(packet + key16).digest()

s = socket.socket(socket.AF_INET, socket.SOCK_RAW, 89)
s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(SRC_IF))
s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 1)
for arg in sys.argv[1:]:
    s.sendto(hello_md5(int(arg)), ("224.0.0.5", 0))
    time.sleep(0.8)
PY

export WREN WORK
unshare -Urn bash -c '
  set -e
  ip link set lo up
  setsid unshare -n -- sleep 200 & BPID=$!
  sleep 0.3
  ip link add veth0 type veth peer name veth1
  ip link set veth1 netns $BPID
  ip addr add 10.0.0.2/24 dev veth0; ip link set veth0 up
  nsenter -t $BPID -n ip addr add 10.0.0.1/24 dev veth1
  nsenter -t $BPID -n ip link set veth1 up
  nsenter -t $BPID -n ip link set lo up

  run_phase() {
    tag="$1"; shift
    RUST_LOG=wren=debug "$WREN" --config "$WORK/$tag.toml" --backend kernel --socket "$WORK/$tag.sock" >"$WORK/$tag.log" 2>&1 &
    sleep 3
    nsenter -t $BPID -n python3 "$WORK/inject.py" "$@"
    sleep 1
    pkill -f "$WORK/$tag.sock" 2>/dev/null || true
    sleep 0.5
    ip route flush proto ospf 2>/dev/null || true
  }

  run_phase on  5000 4000 6000
  run_phase off 5000 4000
  kill $BPID 2>/dev/null || true
'

ok=1

# tracing writes ANSI colour codes that split "seq=4000" apart; strip them first.
sed -r 's/\x1b\[[0-9;]*m//g' "$WORK/on.log"  >"$WORK/on.clean"
sed -r 's/\x1b\[[0-9;]*m//g' "$WORK/off.log" >"$WORK/off.clean"

echo "=== phase on: replay drops ==="
grep "dropping replayed OSPF packet" "$WORK/on.clean" || echo "(none)"

# Phase on: exactly one replay drop, and it is the stale seq=4000 — not 5000 or 6000.
drops=$(grep -c "dropping replayed OSPF packet" "$WORK/on.clean" || true)
[[ "$drops" -eq 1 ]] \
  || { echo "FAIL: expected exactly 1 replay drop with protection on, got $drops"; ok=0; }
grep -q "dropping replayed OSPF packet.*seq=4000" "$WORK/on.clean" \
  || { echo "FAIL: the stale seq=4000 packet was not the one dropped"; ok=0; }
if grep -qE "dropping replayed OSPF packet.*seq=(5000|6000)" "$WORK/on.clean"; then
  echo "FAIL: an in-order packet (5000/6000) was wrongly dropped as a replay"; ok=0
fi

echo "=== phase off: replay drops (expected none) ==="
grep "dropping replayed OSPF packet" "$WORK/off.clean" || echo "(none)"

# Phase off: the knob disables the check, so the same stale seq=4000 is NOT dropped.
if grep -q "dropping replayed OSPF packet" "$WORK/off.clean"; then
  echo "FAIL: auth-replay-protection=false still dropped a replay"; ok=0
fi

if [[ $ok -ne 1 ]]; then echo "--- on.log tail ---"; tail -30 "$WORK/on.clean" 2>/dev/null || true; fi
[[ $ok -eq 1 ]] || exit 1
echo "ospf cryptographic anti-replay (RFC 2328 D.3) smoke test: OK"
