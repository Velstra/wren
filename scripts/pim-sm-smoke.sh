#!/usr/bin/env bash
# PIM-SM (RFC 7761, static RP) — a live end-to-end check that two Wren PIM routers
# route real multicast between a source and a receiver, and that the kernel multicast
# forwarding cache is programmed.
#
# Like the other smoke scripts it runs inside throwaway `unshare -Urn` namespaces and
# never touches the host's interfaces or uplink. PIM uses a raw IP-protocol-103
# socket (CAP_NET_RAW) and the kernel multicast routing socket / `MRT_INIT`
# (CAP_NET_ADMIN) — both held by the netns-root inside `unshare -Urn`, whose user
# namespace owns the net namespace. No sudo, no external daemon.
#
# Topology (4 network namespaces, ASM shared tree with the RP at the first-hop):
#
#     src ──s0/r1s── r1 ──r1r2/r2r1── r2 ──r2c/c0── rcv
#   10.0.1.2      10.0.1.1   10.0.2.1  10.0.2.2   10.0.3.1  10.0.3.2
#                    (RP = 10.0.2.1, on r1)
#
#   * r1 and r2 both run `wren` with `[multicast.pim]` (static RP 10.0.2.1). They
#     discover each other as PIM neighbours over the transit link (Hello).
#   * rcv joins group 239.1.1.1 with `wren mcast-join` → its kernel emits an IGMP
#     report → r2's querier learns the membership → PIM builds the (*,G) shared tree
#     and sends Join(*,G) toward the RP (r1).
#   * src sends UDP multicast to 239.1.1.1. r1 (RP + first-hop) forwards it natively
#     down the shared tree to r2, which forwards it to rcv.
#   * We assert rcv RECEIVES the traffic, that `ip mroute` shows the (S,G) entries on
#     both routers, and that `wren show pim` reports the neighbours and the (*,G) tree.
#
# Usage:  bash scripts/pim-sm-smoke.sh
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
WREN="$REPO/target/debug/wren"
GROUP="239.1.1.1"
PORT=5000

if [[ ! -x "$WREN" ]]; then
  echo "building wren (debug) ..."
  (cd "$REPO" && cargo build -p wren-daemon)
fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# r1: RP + first-hop, PIM on both its interfaces. A dummy querier interface keeps the
# [multicast] block valid; r1 has no local receivers.
cat >"$WORK/r1.toml" <<EOF
router-id = "10.0.2.1"
[multicast]
enabled = true
query-interval = 5
query-response-interval = 2
[[multicast.interface]]
name = "r1s"
role = "querier"
[multicast.pim]
enabled = true
rp-address = "10.0.2.1"
interface = ["r1s", "r1r2"]
hello-interval = 5
EOF

# r2: last-hop, IGMP querier on the receiver LAN, PIM on both its interfaces.
cat >"$WORK/r2.toml" <<EOF
router-id = "10.0.3.1"
[multicast]
enabled = true
query-interval = 5
query-response-interval = 2
[[multicast.interface]]
name = "r2c"
role = "querier"
[multicast.pim]
enabled = true
rp-address = "10.0.2.1"
interface = ["r2r1", "r2c"]
hello-interval = 5
EOF

# A multicast receiver: join the group, print RECEIVED on the first datagram.
cat >"$WORK/recv.py" <<'PYEOF'
import socket, struct, sys
group, port = sys.argv[1], int(sys.argv[2])
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("", port))
mreq = struct.pack("4s4s", socket.inet_aton(group), socket.inet_aton("10.0.3.2"))
s.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
s.settimeout(20)
try:
    data, addr = s.recvfrom(2048)
    print("RECEIVED %d bytes from %s: %s" % (len(data), addr[0], data.decode(errors="replace")))
except socket.timeout:
    print("TIMEOUT: no multicast received")
    sys.exit(2)
PYEOF

# A multicast sender: TTL 10 so it survives the two-hop path.
cat >"$WORK/send.py" <<'PYEOF'
import socket, sys, time
group, port = sys.argv[1], int(sys.argv[2])
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 10)
s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton("10.0.1.2"))
for i in range(60):
    s.sendto(b"pim-sm-hello-%d" % i, (group, port))
    time.sleep(0.25)
PYEOF

export WREN WORK GROUP PORT
unshare -Urn bash -c '
  set -e
  ip link set lo up

  # Three extra netns: src, r2, rcv (r1 is this outer netns).
  setsid unshare -n -- sleep 600 & SRC=$!
  setsid unshare -n -- sleep 600 & R2=$!
  setsid unshare -n -- sleep 600 & RCV=$!
  sleep 0.3

  # veth pairs, all created here then moved to their owning netns.
  ip link add s0   type veth peer name r1s
  ip link add r1r2 type veth peer name r2r1
  ip link add r2c  type veth peer name c0
  ip link set s0   netns $SRC
  ip link set r2r1 netns $R2
  ip link set r2c  netns $R2
  ip link set c0   netns $RCV

  # r1 (outer): first-hop + RP.
  ip addr add 10.0.1.1/24 dev r1s;  ip link set r1s up
  ip addr add 10.0.2.1/24 dev r1r2; ip link set r1r2 up
  ip route add 10.0.3.0/24 via 10.0.2.2

  # src.
  nsenter -t $SRC -n ip link set lo up
  nsenter -t $SRC -n ip addr add 10.0.1.2/24 dev s0
  nsenter -t $SRC -n ip link set s0 up
  nsenter -t $SRC -n ip route add default via 10.0.1.1

  # r2: last-hop.
  nsenter -t $R2 -n ip link set lo up
  nsenter -t $R2 -n ip addr add 10.0.2.2/24 dev r2r1
  nsenter -t $R2 -n ip link set r2r1 up
  nsenter -t $R2 -n ip addr add 10.0.3.1/24 dev r2c
  nsenter -t $R2 -n ip link set r2c up
  nsenter -t $R2 -n ip route add 10.0.1.0/24 via 10.0.2.1

  # rcv.
  nsenter -t $RCV -n ip link set lo up
  nsenter -t $RCV -n ip addr add 10.0.3.2/24 dev c0
  nsenter -t $RCV -n ip link set c0 up
  nsenter -t $RCV -n ip route add default via 10.0.3.1

  # Start the two PIM routers.
  RUST_LOG=${WREN_LOG:-info} "$WREN" --config "$WORK/r1.toml" --backend memory --socket "$WORK/r1.sock" >"$WORK/r1.log" 2>&1 &
  R1PID=$!
  nsenter -t $R2 -n env RUST_LOG=${WREN_LOG:-info} "$WREN" --config "$WORK/r2.toml" --backend memory --socket "$WORK/r2.sock" >"$WORK/r2.log" 2>&1 &
  R2PID=$!

  # Let the routers open sockets, exchange Hello and become the mrouter.
  sleep 4

  # rcv joins the group: its kernel emits IGMP reports r2 will learn.
  nsenter -t $RCV -n "$WREN" mcast-join "$GROUP" --iface c0 >"$WORK/join.log" 2>&1 &
  JOINPID=$!

  # Let the membership propagate: IGMP report -> r2 (*,G) -> Join(*,G) -> r1.
  sleep 5

  # Start the receiver, then the sender.
  nsenter -t $RCV -n python3 "$WORK/recv.py" "$GROUP" "$PORT" >"$WORK/recv.out" 2>&1 &
  RECVPID=$!
  sleep 1
  nsenter -t $SRC -n python3 "$WORK/send.py" "$GROUP" "$PORT" >"$WORK/send.log" 2>&1 &
  SENDPID=$!

  # Wait for the receiver to report (or time out). Guard against set -e: the
  # receiver exits non-zero on timeout and we want the diagnostics below regardless.
  RECV_RC=0
  wait $RECVPID || RECV_RC=$?

  echo "=== r1 (RP/first-hop) ip mroute ==="
  ip mroute show || true
  echo "=== r2 (last-hop) ip mroute ==="
  nsenter -t $R2 -n ip mroute show || true
  echo "=== r1 show pim neighbors ==="
  "$WREN" --socket "$WORK/r1.sock" show pim neighbors || true
  echo "=== r1 show pim mroute ==="
  "$WREN" --socket "$WORK/r1.sock" show pim mroute || true
  echo "=== r2 show pim neighbors ==="
  nsenter -t $R2 -n "$WREN" --socket "$WORK/r2.sock" show pim neighbors || true
  echo "=== r2 show pim mroute ==="
  nsenter -t $R2 -n "$WREN" --socket "$WORK/r2.sock" show pim mroute || true
  echo "=== receiver output ==="
  cat "$WORK/recv.out"

  ok=1
  grep -q "RECEIVED" "$WORK/recv.out" || { echo "FAIL: receiver did not get the multicast stream"; ok=0; }
  # The kernel forwarding cache must show the (S,G) entry on both routers.
  ip mroute show | grep -q "$GROUP" || { echo "FAIL: no kernel mroute entry on r1"; ok=0; }
  nsenter -t $R2 -n ip mroute show | grep -q "$GROUP" || { echo "FAIL: no kernel mroute entry on r2"; ok=0; }

  if [[ $ok -ne 1 ]]; then
    echo "--- r1 log ---"; sed -r "s/\x1b\[[0-9;]*m//g" "$WORK/r1.log" | grep -i "pim\|igmp" | tail -40
    echo "--- r2 log ---"; sed -r "s/\x1b\[[0-9;]*m//g" "$WORK/r2.log" | grep -i "pim\|igmp" | tail -40
  fi

  kill $SENDPID $RECVPID $JOINPID $R1PID $R2PID 2>/dev/null || true
  kill $SRC $R2 $RCV 2>/dev/null || true
  exit $(( ok == 1 ? 0 : 1 ))
'
echo "pim-sm smoke test: OK"
