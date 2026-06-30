#!/usr/bin/env bash
# Dynamic VRF routing with Babel — the fourth (and last IGP) dynamic protocol to run
# inside a VRF, completing the IGP set (RIP, OSPF, IS-IS, Babel). A Babel instance
# bound to a VRF installs every route it computes into that VRF's kernel table, not
# the main table. Self-contained, rootless.
#
# Runs inside throwaway `unshare -Urn` namespaces (netns-root holds CAP_NET_RAW +
# CAP_NET_ADMIN, so it can create a VRF device, SO_BINDTODEVICE Babel's per-interface
# UDP socket, and program the FIB) and never touches the host.
#
# Topology: A (2001:db8::1) <--Babel, in VRF "blue" (table 100)--> B (2001:db8::2).
# Each daemon has its veth enslaved to a local `blue` VRF device and runs Babel bound
# to that VRF. A has a static route 2001:db8:99::/64 in blue and redistributes it
# into Babel. B must learn 2001:db8:99::/64 over Babel and install it into **table
# 100**, not the main table — proving Babel's routes are VRF-scoped.
#
# (An IPv6 static is used so B installs it via a link-local next hop; a v4 route via
# a v6 next hop needs RTA_VIA, which wren-netlink does not have yet.)
#
# Usage:  bash scripts/vrf-babel-smoke.sh
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
prefix = "2001:db8:99::/64"
via    = "2001:db8::2"
vrf    = "blue"
[babel]
enabled      = true
interfaces   = ["veth0"]
vrf          = "blue"
redistribute = ["static"]
EOF

cat >"$WORK/b.toml" <<EOF
router-id = "10.0.0.2"
[[vrf]]
name  = "blue"
table = 100
[babel]
enabled    = true
interfaces = ["veth1"]
vrf        = "blue"
EOF

export WREN WORK
timeout 100 unshare -Urn bash -c '
  set -e
  ip link set lo up
  setsid unshare -n -- sleep 90 & B=$!
  sleep 0.3
  # A side: VRF blue, veth0 enslaved.
  ip link add blue type vrf table 100; ip link set blue up
  ip link add veth0 type veth peer name veth1
  ip link set veth1 netns $B
  ip link set veth0 master blue
  ip addr add 2001:db8::1/64 dev veth0; ip link set veth0 up
  # B side: its own VRF blue, veth1 enslaved.
  nsenter -t $B -n ip link set lo up
  nsenter -t $B -n ip link add blue type vrf table 100
  nsenter -t $B -n ip link set blue up
  nsenter -t $B -n ip link set veth1 master blue
  nsenter -t $B -n ip addr add 2001:db8::2/64 dev veth1
  nsenter -t $B -n ip link set veth1 up
  # Let DAD settle so the global + link-local addresses are usable.
  sleep 2

  nsenter -t $B -n "$WREN" --config "$WORK/b.toml" --backend kernel --socket "$WORK/b.sock" >"$WORK/b.log" 2>&1 &
  "$WREN" --config "$WORK/a.toml" --backend kernel --socket "$WORK/a.sock" >"$WORK/a.log" 2>&1 &

  # Babel converges more slowly (Hello 4s + IHU, Updates every 16s); allow a window.
  learned=0
  for _ in $(seq 1 80); do  # up to ~40s
    if nsenter -t $B -n ip -6 route show table 100 | grep -q "2001:db8:99::/64"; then learned=1; break; fi
    sleep 0.5
  done

  echo "=== B: ip -6 route show table 100 (VRF blue) ==="; nsenter -t $B -n ip -6 route show table 100 | tee "$WORK/t100.out"
  echo "=== B: ip -6 route show (main) ==="; nsenter -t $B -n ip -6 route show | tee "$WORK/main.out"
  echo "=== B: wren show routes ==="; nsenter -t $B -n "$WREN" --socket "$WORK/b.sock" show routes | tee "$WORK/routes.out"
  echo "learned=$learned" >"$WORK/result.txt"
  if [[ $learned -ne 1 ]]; then echo "--- A ---"; cat "$WORK/a.log"; echo "--- B ---"; cat "$WORK/b.log"; fi
  kill $B 2>/dev/null || true
'

echo "=== checks ==="
ok=1
check() { if eval "$2"; then echo "OK: $1"; else echo "FAIL: $1"; ok=0; fi; }

check "B learned 2001:db8:99::/64 via Babel into table 100"  "grep -q '2001:db8:99::/64 via fe80' '$WORK/t100.out'"
check "the learned route is proto babel"                     "grep -q '2001:db8:99::/64 .*proto babel' '$WORK/t100.out'"
check "2001:db8:99::/64 is NOT in B's main table"            "! grep -q '2001:db8:99::/64' '$WORK/main.out'"
check "show routes tags it table 100 proto babel"            "grep -Eq '2001:db8:99::/64 .*table 100 proto babel' '$WORK/routes.out'"

[[ $ok -eq 1 ]] && echo "dynamic VRF (Babel) smoke test: OK"
exit $(( ok == 1 ? 0 : 1 ))
