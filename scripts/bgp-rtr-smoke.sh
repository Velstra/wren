#!/usr/bin/env bash
# BGP RPKI-to-Router (RTR, RFC 8210) smoke test — fetch ROAs live from a validating
# cache and use them to validate a peer's routes, instead of static `[[bgp.roa]]`.
#
# The cache is a tiny independent Python implementation of the RTR wire protocol (it
# encodes the PDUs by hand), so this exercises wren's RTR client against a *foreign*
# encoder — a real interop check, not a self-round-trip.
#
# Self-contained and rootless: it runs inside throwaway `unshare -Urn` namespaces and
# never touches the host's interfaces or uplink. The mock cache and router A share A's
# network namespace and talk over 127.0.0.1; B is in a second namespace across a veth.
#
# Topology: A (AS 65001, validating, rpki-reject-invalid) <-eBGP-> B (AS 65002, origin),
# over an IPv4 veth. A has NO static ROAs — it learns them from the RTR cache, which
# announces:
#   - 10.99.0.0/24 maxlen 24 AS 65002  → B's 10.99.0.0/24 is Valid   → accepted
#   - 10.88.0.0/24 maxlen 24 AS 65003  → B's 10.88.0.0/24 is Invalid → rejected
#
# NOTE on shell options: the outer `set -euo pipefail` exports SHELLOPTS (incl. nounset)
# into the inner `unshare -Urn bash -c` block; the netns block only writes output files
# and the assertions run in the OUTER shell afterwards.
#
# Usage:  bash scripts/bgp-rtr-smoke.sh
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
WREN="$REPO/target/debug/wren"

if [[ ! -x "$WREN" ]]; then
  echo "building wren (debug) ..."
  (cd "$REPO" && cargo build -p wren-daemon)
fi

command -v python3 >/dev/null || { echo "python3 is required for the mock RTR cache"; exit 1; }

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# A minimal RTR cache (RFC 8210): on each connection it sends a Cache Response, two
# IPv4 Prefix PDUs (announce), and an End of Data, then holds the socket open.
cat >"$WORK/rtr_cache.py" <<'PY'
import socket, struct, sys, time

PORT = int(sys.argv[1])
V = 1  # protocol version (RFC 8210)

def hdr(ptype, u16, length):
    return struct.pack("!BBHI", V, ptype, u16, length)

def cache_response(sid):           return hdr(3, sid, 8)
def end_of_data(sid, serial):      return hdr(7, sid, 24) + struct.pack("!IIII", serial, 3600, 600, 7200)
def ipv4_prefix(plen, maxlen, addr, asn):
    return hdr(4, 0, 20) + struct.pack("!BBBB", 1, plen, maxlen, 0) + socket.inet_aton(addr) + struct.pack("!I", asn)

srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", PORT))
srv.listen(1)
# Serve exactly one session (the router connects once and stays synced), then exit so
# the test never leaves a process blocked in accept().
conn, _ = srv.accept()
conn.recv(8)  # drain the Reset Query
conn.sendall(cache_response(0))
conn.sendall(ipv4_prefix(24, 24, "10.99.0.0", 65002))
conn.sendall(ipv4_prefix(24, 24, "10.88.0.0", 65003))
conn.sendall(end_of_data(0, 1))
time.sleep(12)  # keep the session open while the test runs, then exit
PY

# A — validating, learns ROAs over RTR (no static [[bgp.roa]]).
cat >"$WORK/a.toml" <<EOF
router-id = "10.0.0.1"
[bgp]
enabled             = true
local-as            = 65001
rpki-reject-invalid = true
[bgp.rtr]
server  = "127.0.0.1:3323"
refresh = 3600
[[bgp.neighbor]]
address   = "10.0.0.2"
remote-as = 65002
EOF

# B — origin: announces both prefixes (origin AS 65002).
cat >"$WORK/b.toml" <<EOF
router-id = "10.0.0.2"
[bgp]
enabled  = true
local-as = 65002
network  = ["10.99.0.0/24", "10.88.0.0/24"]
[[bgp.neighbor]]
address   = "10.0.0.1"
remote-as = 65001
passive   = true
EOF

export WREN WORK
# An outer timeout guards the whole netns block so a stuck child can never wedge the
# test; the assertions below run on whatever output was captured.
timeout 60 unshare -Urn bash -c '
  set -e
  ip link set lo up
  setsid unshare -n -- sleep 40 & BPID=$!
  sleep 0.3
  ip link add veth0 type veth peer name veth1
  ip link set veth1 netns $BPID
  ip addr add 10.0.0.1/24 dev veth0
  ip link set veth0 up
  nsenter -t $BPID -n ip addr add 10.0.0.2/24 dev veth1
  nsenter -t $BPID -n ip link set veth1 up
  nsenter -t $BPID -n ip link set lo up

  # The mock RTR cache runs in As namespace, reachable over 127.0.0.1:3323.
  python3 "$WORK/rtr_cache.py" 3323 >"$WORK/rtr.log" 2>&1 &
  sleep 0.5

  nsenter -t $BPID -n "$WREN" --config "$WORK/b.toml" --backend kernel --socket "$WORK/b.sock" >"$WORK/b.log" 2>&1 &
  "$WREN" --config "$WORK/a.toml" --backend kernel --socket "$WORK/a.sock" >"$WORK/a.log" 2>&1 &
  sleep 9

  timeout 5 "$WREN" --socket "$WORK/a.sock" show bgp roa >"$WORK/a_roa.txt" 2>&1 || true
  timeout 5 "$WREN" --socket "$WORK/a.sock" show bgp     >"$WORK/a_bgp.txt" 2>&1 || true
  ip -4 route show proto bgp >"$WORK/a_kernel.txt" 2>&1 || true

  pkill -f "$WORK/a.sock" 2>/dev/null || true
  nsenter -t $BPID -n pkill -f "$WORK/b.sock" 2>/dev/null || true
  kill $BPID 2>/dev/null || true
' || true

echo "=== A: wren show bgp roa (learned over RTR) ==="
cat "$WORK/a_roa.txt"
echo "=== A: wren show bgp ==="
cat "$WORK/a_bgp.txt"
echo "=== A: ip -4 route show proto bgp ==="
cat "$WORK/a_kernel.txt"

ok=1
# The ROAs arrived over RTR — the table is populated even though A configured none.
grep -Eq "10.99.0.0/24 maxlen 24 as 65002" "$WORK/a_roa.txt" \
  || { echo "FAIL: A did not learn the 10.99.0.0/24 ROA over RTR"; ok=0; }
grep -Eq "10.88.0.0/24 maxlen 24 as 65003" "$WORK/a_roa.txt" \
  || { echo "FAIL: A did not learn the 10.88.0.0/24 ROA over RTR"; ok=0; }
# The RTR-Valid route is accepted and tagged; the RTR-Invalid one is dropped.
grep -Eq "10.99.0.0/24 .* rpki valid" "$WORK/a_bgp.txt" \
  || { echo "FAIL: A did not accept 10.99.0.0/24 as RPKI valid (via RTR)"; ok=0; }
grep -q "10.88.0.0/24" "$WORK/a_bgp.txt" \
  && { echo "FAIL: A accepted the RTR-invalid 10.88.0.0/24 into its RIB"; ok=0; }
grep -q "10.99.0.0/24" "$WORK/a_kernel.txt" \
  || { echo "FAIL: A did not install the valid 10.99.0.0/24 in the kernel"; ok=0; }
grep -q "10.88.0.0/24" "$WORK/a_kernel.txt" \
  && { echo "FAIL: A installed the RTR-invalid 10.88.0.0/24 in the kernel"; ok=0; }

if [[ $ok -ne 1 ]]; then echo "--- A log ---"; tail -20 "$WORK/a.log"; echo "--- RTR log ---"; tail -10 "$WORK/rtr.log"; fi
[[ $ok -eq 1 ]] || exit 1
echo "bgp rpki-to-router (RTR, RFC 8210) smoke test: OK"
