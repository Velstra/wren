#!/usr/bin/env bash
# BGP EVPN smoke test (RFC 7432 + RFC 8365 over VXLAN) — a route reflector relays
# EVPN routes between two leaf VTEPs that peer only with the RR. Fully self-contained
# and rootless.
#
# Like the other bgp-*-smoke.sh scripts it runs inside throwaway `unshare -Urn`
# namespaces and never touches the host's interfaces or uplink. Per-daemon control
# sockets live under a temp dir (Unix sockets, not the network).
#
# Topology — one AS (65010) on one shared L2 segment (a bridge in the RR
# namespace), a reflector RR and two leaf VTEPs in three namespaces:
#
#                 RR (10.0.0.254)   — reflects EVPN, no local VTEP
#                   |  bridge br0  (10.0.0.0/24)
#          +--------+--------+
#     Leaf1 (10.0.0.1)   Leaf2 (10.0.0.2)   — VTEPs in EVI 100 / vni 10100
#
# All three are iBGP (same AS) with `evpn = true` toward each session. Leaf1 and
# Leaf2 peer ONLY with RR; both are `route-reflector-client`s, so RR reflects each
# leaf's EVPN routes to the other (next hop unchanged, RFC 7432 §7.7). Each leaf
# originates a type-3 IMET (its VTEP) and a type-2 MAC/IP (a static MAC). Both EVIs
# share the auto Route Target rt:65010:10100, so each leaf imports the other's
# routes into its MAC-VRF.
#
# The test asserts, on Leaf2:
#   * the session to RR is Established; and
#   * `show bgp evpn` carries Leaf1's routes via 10.0.0.1 (only possible via
#     reflection); and
#   * `show evpn` shows Leaf1's MAC and VTEP imported into the EVI 100 MAC-VRF; and
#   * `monitor evpn` streams Leaf1's MAC and flood VTEP as `+ evpn ...` lines (the
#     FPM-style EVPN↔fabric bridge feed the fabric controller consumes).
#
# Usage:  bash scripts/bgp-evpn-smoke.sh
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
WREN="$REPO/target/debug/wren"

if [[ ! -x "$WREN" ]]; then
  echo "building wren (debug) ..."
  (cd "$REPO" && cargo build -p wren-daemon)
fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# RR (active toward both leaves) reflects EVPN between them. It has no local VTEP —
# just the two EVPN-activated, reflector-client sessions.
cat >"$WORK/rr.toml" <<EOF
router-id = "10.0.0.254"
[bgp]
enabled  = true
local-as = 65010
[[bgp.neighbor]]
address                = "10.0.0.1"
remote-as              = 65010
route-reflector-client = true
evpn                   = true
[[bgp.neighbor]]
address                = "10.0.0.2"
remote-as              = 65010
route-reflector-client = true
evpn                   = true
EOF

# Leaf1 (passive) — VTEP 10.0.0.1, EVI 100 / vni 10100, advertises one static MAC.
cat >"$WORK/l1.toml" <<EOF
router-id = "10.0.0.1"
[bgp]
enabled  = true
local-as = 65010
[[bgp.neighbor]]
address   = "10.0.0.254"
remote-as = 65010
passive   = true
evpn      = true
[bgp.evpn]
vtep-ip = "10.0.0.1"
[[bgp.evpn.instance]]
evi = 100
vni = 10100
advertise-mac = ["02:00:5e:00:00:01/10.100.0.1"]
EOF

# Leaf2 (passive) — VTEP 10.0.0.2, same EVI/vni (so it imports Leaf1's routes),
# advertises its own static MAC.
cat >"$WORK/l2.toml" <<EOF
router-id = "10.0.0.2"
[bgp]
enabled  = true
local-as = 65010
[[bgp.neighbor]]
address   = "10.0.0.254"
remote-as = 65010
passive   = true
evpn      = true
[bgp.evpn]
vtep-ip = "10.0.0.2"
[[bgp.evpn.instance]]
evi = 100
vni = 10100
advertise-mac = ["02:00:5e:00:00:02/10.100.0.2"]
EOF

export WREN WORK
unshare -Urn bash -c '
  set -e
  ip link set lo up
  # Leaf1 and Leaf2 live in their own namespaces; RR is this namespace and hosts the
  # shared L2 bridge all three sit on.
  setsid unshare -n -- sleep 120 & L1PID=$!
  setsid unshare -n -- sleep 120 & L2PID=$!
  sleep 0.3

  ip link add br0 type bridge
  ip addr add 10.0.0.254/24 dev br0
  ip link set br0 up

  # Leaf1 onto the bridge.
  ip link add veth_l1 type veth peer name veth_1
  ip link set veth_1 netns $L1PID
  ip link set veth_l1 master br0; ip link set veth_l1 up
  nsenter -t $L1PID -n ip addr add 10.0.0.1/24 dev veth_1
  nsenter -t $L1PID -n ip link set veth_1 up
  nsenter -t $L1PID -n ip link set lo up

  # Leaf2 onto the bridge.
  ip link add veth_l2 type veth peer name veth_2
  ip link set veth_2 netns $L2PID
  ip link set veth_l2 master br0; ip link set veth_l2 up
  nsenter -t $L2PID -n ip addr add 10.0.0.2/24 dev veth_2
  nsenter -t $L2PID -n ip link set veth_2 up
  nsenter -t $L2PID -n ip link set lo up

  "$WREN" --config "$WORK/rr.toml" --backend kernel --socket "$WORK/rr.sock" >"$WORK/rr.log" 2>&1 &
  nsenter -t $L1PID -n "$WREN" --config "$WORK/l1.toml" --backend kernel --socket "$WORK/l1.sock" >"$WORK/l1.log" 2>&1 &
  nsenter -t $L2PID -n "$WREN" --config "$WORK/l2.toml" --backend kernel --socket "$WORK/l2.sock" >"$WORK/l2.log" 2>&1 &
  sleep 9

  # B4b: dynamically originate a type-2 MAC/IP route on Leaf1 at runtime — the
  # write-side control API the fabric datapath drives as it learns local MACs.
  # Leaf2 must import this MAC just like the static one, proving the dynamic
  # origination reaches the run loop, updates the origination set, and advertises
  # to the already-Established EVPN session.
  nsenter -t $L1PID -n "$WREN" --socket "$WORK/l1.sock" evpn advertise 10100 02:00:5e:00:00:09 10.100.0.9 || true
  sleep 2

  ok=1
  {
    echo "=== wren show bgp neighbors (on RR) ==="
    "$WREN" --socket "$WORK/rr.sock" show bgp neighbors || true
    echo "=== wren show bgp evpn (on Leaf2) ==="
    nsenter -t $L2PID -n "$WREN" --socket "$WORK/l2.sock" show bgp evpn || true
    echo "=== wren show evpn (on Leaf2) ==="
    nsenter -t $L2PID -n "$WREN" --socket "$WORK/l2.sock" show evpn || true
    # The EVPN↔fabric bridge feed: a 3s snapshot of the FPM-style monitor stream
    # the fabric controller consumes. Leaf2 must stream Leaf1s imported MAC and
    # flood VTEP as `+ evpn ...` lines.
    echo "=== wren monitor evpn (on Leaf2, 3s snapshot) ==="
    timeout 3 nsenter -t $L2PID -n "$WREN" --socket "$WORK/l2.sock" monitor evpn || true
  } > "$WORK/out.txt" 2>&1
  cat "$WORK/out.txt"

  grep -q "10.0.0.1 AS 65010 Established"         "$WORK/out.txt" || { echo "FAIL: RR-Leaf1 session not Established"; ok=0; }
  grep -q "10.0.0.2 AS 65010 Established"         "$WORK/out.txt" || { echo "FAIL: RR-Leaf2 session not Established"; ok=0; }
  grep -q "via 10.0.0.1"                          "$WORK/out.txt" || { echo "FAIL: Leaf2 did not learn Leaf1 EVPN routes (via 10.0.0.1)"; ok=0; }
  grep -q "02:00:5e:00:00:01 -> vtep 10.0.0.1"    "$WORK/out.txt" || { echo "FAIL: Leaf1 MAC not imported into Leaf2 MAC-VRF"; ok=0; }
  grep -q "02:00:5e:00:00:09 -> vtep 10.0.0.1"    "$WORK/out.txt" || { echo "FAIL: dynamically-advertised Leaf1 MAC (evpn advertise) not imported into Leaf2 MAC-VRF"; ok=0; }
  grep -q "flood -> 10.0.0.1"                      "$WORK/out.txt" || { echo "FAIL: Leaf1 VTEP not in Leaf2 flood set"; ok=0; }
  grep -Eq "\+ evpn vni 10100 mac 02:00:5e:00:00:01 .*vtep 10.0.0.1" "$WORK/out.txt" || { echo "FAIL: monitor evpn did not stream Leaf1 MAC"; ok=0; }
  grep -q "+ evpn vni 10100 flood 10.0.0.1"        "$WORK/out.txt" || { echo "FAIL: monitor evpn did not stream Leaf1 flood VTEP"; ok=0; }

  if [[ $ok -ne 1 ]]; then
    echo "--- RR log ---";    cat "$WORK/rr.log"
    echo "--- Leaf1 log ---"; cat "$WORK/l1.log"
    echo "--- Leaf2 log ---"; cat "$WORK/l2.log"
  fi
  kill $L1PID $L2PID 2>/dev/null || true
  exit $(( ok == 1 ? 0 : 1 ))
'
echo "bgp evpn smoke test: OK"
