#!/usr/bin/env bash
# Observe real gratuitous ARP retries, late refresh and withdrawal in netns.
set -euo pipefail
REPO="$(cd "$(dirname "$0")/.." && pwd)"
WREN="${WREN:-$REPO/target/debug/wren}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
cat >"$WORK/router.toml" <<EOF
router-id = "192.0.2.1"
[[vrrp]]
interface = "veth0"
vrid = 51
priority = 255
advert-interval = 100
virtual-address = ["192.0.2.254"]
prefix-length = 24
EOF
cat >"$WORK/capture.py" <<'PY'
import socket
import sys
import time

sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0806))
sock.bind(("veth1", 0))
sock.settimeout(0.2)
vip = socket.inet_aton("192.0.2.254")
open(sys.argv[1], "w").close()
deadline = time.monotonic() + float(sys.argv[2])
count = 0
while time.monotonic() < deadline:
    try:
        frame = sock.recv(2048)
    except socket.timeout:
        continue
    # Ethernet + Ethernet/IPv4 ARP; sender and target both equal the VIP.
    if (len(frame) >= 42 and frame[12:20] == bytes.fromhex("0806000108000604")
            and frame[28:32] == vip and frame[38:42] == vip):
        count += 1
minimum, maximum = map(int, sys.argv[3:5])
print(f"Observed {count} VIP announcements; expected {minimum}..{maximum}", flush=True)
assert minimum <= count <= maximum
PY
export WREN WORK
unshare -Urn bash -c '
  set -euo pipefail
  unshare -n -- sleep 120 & BPID=$!
  APID=; CAPID=
  cleanup() {
    for pid in "$APID" "$CAPID" "$BPID"; do
      [[ -z "$pid" ]] || kill "$pid" 2>/dev/null || true
    done
  }
  trap cleanup EXIT
  sleep .3
  ip link set lo up
  ip link add veth0 type veth peer name veth1
  ip link set veth1 netns "$BPID"
  ip link set veth0 up
  ip addr add 192.0.2.1/24 dev veth0
  nsenter -t "$BPID" -n ip link set veth1 up
  capture() {
    rm -f "$WORK/listening"
    nsenter -t "$BPID" -n python3 "$WORK/capture.py" "$WORK/listening" "$@" & CAPID=$!
    for ((n=0; n<50; n++)); do
      [[ ! -e "$WORK/listening" ]] || return 0
      sleep .1
    done
    return 1
  }
  capture 4 3 3
  "$WREN" --config "$WORK/router.toml" --backend kernel --socket "$WORK/router.sock" >"$WORK/router.log" 2>&1 & APID=$!
  wait "$CAPID"
  echo "PASS: master sends initial announcement and two retries"
  capture 31 1 1
  wait "$CAPID"
  echo "PASS: a late observer receives a periodic announcement"
  ip addr del 192.0.2.1/24 dev veth0
  for ((n=0; n<30; n++)); do
    if "$WREN" --socket "$WORK/router.sock" show vrrp | grep -q initialize; then break; fi
    sleep .1
  done
  ! ip -4 addr show veth0 | grep -q 192.0.2.254
  capture 32 0 0
  wait "$CAPID"
  kill -0 "$APID"
  echo "PASS: a running router stops announcements after releasing ownership"
'
