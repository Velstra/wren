#!/usr/bin/env bash
# Dynamic VRF routing with BGP — the last dynamic protocol to run inside a VRF. A BGP
# instance bound to a VRF binds its session sockets to the VRF's L3 master device
# (SO_BINDTODEVICE) so the TCP sessions use the VRF's routing table, and installs every
# route it learns into the VRF's kernel table, not the main table. This is a plain VRF,
# not an MPLS L3VPN. Self-contained, rootless.
#
# Runs inside throwaway `unshare -Urn` namespaces (netns-root holds CAP_NET_RAW +
# CAP_NET_ADMIN, so it can create a VRF device and program the FIB) and never touches
# the host.
#
# Topology: A (10.9.0.1, AS 65001) <-eBGP, in VRF "blue" (table 100)-> B (10.9.0.2,
# AS 65002). Each daemon has its veth enslaved to a local `blue` VRF device and runs
# BGP bound to that VRF. A has a static route 10.99.0.0/24 in blue and redistributes
# it into BGP. B must learn 10.99.0.0/24 over BGP and install it into **table 100**,
# not the main table — proving the BGP session runs in the VRF and its routes are
# VRF-scoped.
#
# Usage:  bash scripts/vrf-bgp-smoke.sh
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
WREN="$REPO/target/debug/wren"

echo "building wren (debug) ..."
(cd "$REPO" && cargo build -p wren-daemon)

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

cat >"$WORK/a.toml" <<EOF
router-id = "10.0.0.1"
[[vrf]]
name  = "blue"
table = 100
[[static]]
prefix = "10.99.0.0/24"
via    = "10.9.0.100"
vrf    = "blue"
[bgp]
enabled      = true
local-as     = 65001
vrf          = "blue"
redistribute = ["static"]
[[bgp.neighbor]]
address   = "10.9.0.2"
remote-as = 65002
EOF

cat >"$WORK/b.toml" <<EOF
router-id = "10.0.0.2"
[[vrf]]
name  = "blue"
table = 100
[bgp]
enabled  = true
local-as = 65002
vrf      = "blue"
[[bgp.neighbor]]
address   = "10.9.0.1"
remote-as = 65001
passive   = true
EOF

export WREN WORK
timeout 80 unshare -Urn bash -c '
  set -e
  ip link set lo up
  setsid unshare -n -- sleep 70 & B=$!
  sleep 0.3
  # A side: VRF blue, veth0 enslaved.
  ip link add blue type vrf table 100; ip link set blue up
  ip link add veth0 type veth peer name veth1
  ip link set veth1 netns $B
  ip link set veth0 master blue
  ip addr add 10.9.0.1/24 dev veth0; ip link set veth0 up
  # B side: its own VRF blue, veth1 enslaved.
  nsenter -t $B -n ip link set lo up
  nsenter -t $B -n ip link add blue type vrf table 100
  nsenter -t $B -n ip link set blue up
  nsenter -t $B -n ip link set veth1 master blue
  nsenter -t $B -n ip addr add 10.9.0.2/24 dev veth1
  nsenter -t $B -n ip link set veth1 up

  nsenter -t $B -n "$WREN" --config "$WORK/b.toml" --backend kernel --socket "$WORK/b.sock" >"$WORK/b.log" 2>&1 &
  "$WREN" --config "$WORK/a.toml" --backend kernel --socket "$WORK/a.sock" >"$WORK/a.log" 2>&1 &

  learned=0
  for _ in $(seq 1 50); do  # up to ~25s
    if nsenter -t $B -n ip route show table 100 | grep -q "10.99.0.0/24"; then learned=1; break; fi
    sleep 0.5
  done

  echo "=== B: ip route show table 100 (VRF blue) ==="; nsenter -t $B -n ip route show table 100 | tee "$WORK/t100.out"
  echo "=== B: ip route show (main) ==="; nsenter -t $B -n ip route show | tee "$WORK/main.out"
  echo "=== B: wren show routes ==="; nsenter -t $B -n "$WREN" --socket "$WORK/b.sock" show routes | tee "$WORK/routes.out"
  echo "=== B: wren show bgp routes ==="; nsenter -t $B -n "$WREN" --socket "$WORK/b.sock" show bgp routes | tee "$WORK/bgp.out"
  echo "learned=$learned" >"$WORK/result.txt"
  if [[ $learned -ne 1 ]]; then echo "--- A ---"; cat "$WORK/a.log"; echo "--- B ---"; cat "$WORK/b.log"; fi
  kill $B 2>/dev/null || true
'

echo "=== checks ==="
ok=1
check() { if eval "$2"; then echo "OK: $1"; else echo "FAIL: $1"; ok=0; fi; }

check "B learned 10.99.0.0/24 via BGP into table 100"  "grep -q '10.99.0.0/24 via 10.9.0.1' '$WORK/t100.out'"
check "the learned route is proto bgp"                 "grep -q '10.99.0.0/24 .*proto bgp' '$WORK/t100.out'"
check "10.99.0.0/24 is NOT in B's main table"          "! grep -q '10.99.0.0/24' '$WORK/main.out'"
check "show routes tags it table 100 proto bgp"        "grep -Eq '10.99.0.0/24 .*table 100 proto bgp' '$WORK/routes.out'"
check "show bgp routes shows it with as-path 65001"    "grep -Eq '10.99.0.0/24 .*65001' '$WORK/bgp.out'"

[[ $ok -eq 1 ]] && echo "dynamic VRF (BGP) smoke test: OK"
exit $(( ok == 1 ? 0 : 1 ))
