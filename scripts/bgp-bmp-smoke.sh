#!/usr/bin/env bash
# BMP (RFC 7854) smoke test — wren streams its BGP state to a monitoring station,
# fully self-contained and rootless.
#
# Like the other bgp-*-smoke.sh scripts it runs inside throwaway `unshare -Urn`
# namespaces and never touches the host's interfaces or uplink. A tiny independent
# Python BMP station (it only frames the Common Header — a foreign decoder, not
# wren's own codec) listens on 127.0.0.1:11019 inside A's namespace.
#
# Topology: A (AS 65001, active) <-eBGP-> B (AS 65002, passive). B originates
# 10.20.0.0/24. A is configured with `[bgp.bmp]` pointing at the station. The
# station must observe, on A's BMP feed:
#   * an Initiation message (type 4);
#   * a Peer Up Notification (type 3) for B;
#   * a Route Monitoring message (type 0) embedding B's 10.20.0.0/24 NLRI.
#
# Usage:  bash scripts/bgp-bmp-smoke.sh
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
WREN="$REPO/target/debug/wren"

echo "building wren (debug) ..."
(cd "$REPO" && cargo build -p wren-daemon)

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

cat >"$WORK/a.toml" <<EOF
router-id = "10.0.0.1"
[bgp]
enabled  = true
local-as = 65001
[bgp.bmp]
station  = "127.0.0.1:11019"
sys-name = "router-a"
[[bgp.neighbor]]
address   = "10.0.0.2"
remote-as = 65002
EOF

cat >"$WORK/b.toml" <<EOF
router-id = "10.0.0.2"
[bgp]
enabled   = true
local-as  = 65002
network   = ["10.20.0.0/24"]
[[bgp.neighbor]]
address   = "10.0.0.1"
remote-as = 65001
passive   = true
EOF

# A minimal BMP station: accept one connection, frame messages by the 6-byte Common
# Header, record the message types seen and whether a Route Monitoring message
# carried B's 10.20.0.0/24 NLRI (encoded as the bytes 24,10,20,0). Serve once, then exit.
cat >"$WORK/station.py" <<'PY'
import socket, sys, time
srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", 11019))
srv.listen(1)
srv.settimeout(15)
types, saw_route = set(), False
try:
    conn, _ = srv.accept()
except socket.timeout:
    open(sys.argv[1], "w").write("types=[] route=False\n")
    sys.exit(0)
conn.settimeout(8)
buf = b""
deadline = time.time() + 8
while time.time() < deadline:
    try:
        chunk = conn.recv(4096)
    except socket.timeout:
        break
    if not chunk:
        break
    buf += chunk
    while len(buf) >= 6:
        if buf[0] != 3:          # BMP version must be 3
            buf = buf[1:]
            continue
        total = int.from_bytes(buf[1:5], "big")
        if total < 6 or len(buf) < total:
            break
        msg, buf = buf[:total], buf[total:]
        mtype = msg[5]
        types.add(mtype)
        if mtype == 0 and bytes([24, 10, 20, 0]) in msg:
            saw_route = True
    if {0, 3, 4} <= types and saw_route:
        break
open(sys.argv[1], "w").write("types=%s route=%s\n" % (sorted(types), saw_route))
PY

export WREN WORK
timeout 80 unshare -Urn bash -c '
  set -e
  ip link set lo up
  setsid unshare -n -- sleep 40 & BPID=$!
  sleep 0.3
  ip link add veth0 type veth peer name veth1
  ip link set veth1 netns $BPID
  ip addr add 10.0.0.1/24 dev veth0; ip link set veth0 up
  nsenter -t $BPID -n ip addr add 10.0.0.2/24 dev veth1
  nsenter -t $BPID -n ip link set veth1 up
  nsenter -t $BPID -n ip link set lo up

  # Start the BMP station first (A dials out to it), then B, then A.
  python3 "$WORK/station.py" "$WORK/result.txt" >"$WORK/station.log" 2>&1 & SPID=$!
  sleep 0.5
  nsenter -t $BPID -n "$WREN" --config "$WORK/b.toml" --backend kernel --socket "$WORK/b.sock" >"$WORK/b.log" 2>&1 &
  "$WREN" --config "$WORK/a.toml" --backend kernel --socket "$WORK/a.sock" >"$WORK/a.log" 2>&1 &

  wait $SPID 2>/dev/null || true
  kill $BPID 2>/dev/null || true
'

echo "=== BMP station observed ==="
cat "$WORK/result.txt" 2>/dev/null || { echo "FAIL: station produced no result"; exit 1; }

ok=1
grep -q "route=True" "$WORK/result.txt" || { echo "FAIL: no Route Monitoring for 10.20.0.0/24"; ok=0; }
# types must include Initiation(4), Peer Up(3) and Route Monitoring(0).
for t in 0 3 4; do
  grep -Eq "types=\[.*\b$t\b.*\]" "$WORK/result.txt" || { echo "FAIL: missing BMP message type $t"; ok=0; }
done
if [[ $ok -ne 1 ]]; then echo "--- A log ---"; cat "$WORK/a.log"; fi
[[ $ok -eq 1 ]] && echo "BMP smoke test: OK"
exit $(( ok == 1 ? 0 : 1 ))
