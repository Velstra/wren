#!/usr/bin/env bash
# VRF smoke test — static routes placed in a named VRF install into that VRF's kernel
# routing table, overlapping prefixes in different VRFs stay separate, a VRF route-map
# filters routes entering the VRF, and `show vrf` reports it. Self-contained, rootless.
#
# Runs inside a throwaway `unshare -Urn` namespace (netns-root holds CAP_NET_ADMIN, so
# it can create a VRF device and program the kernel FIB) and never touches the host.
#
# Topology, one daemon:
#   * VRF "blue" = table 100, with veth0 (10.9.0.1/24) enslaved → its connected route
#     and the static routes in blue land in table 100;
#   * veth1 (10.8.0.1/24) stays in the default VRF (main table).
# Static routes:
#   * 10.99.0.0/24 via 10.9.0.2 in blue   → table 100
#   * 10.77.0.0/24 via 10.9.0.2 in blue   → REJECTED by blue's import route-map
#   * 10.88.0.0/24 via 10.8.0.2 (default) → main table
#   * 10.50.0.0/24 in BOTH blue and main  → overlapping prefix, one per table
#
# Usage:  bash scripts/vrf-smoke.sh
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
name       = "blue"
table      = 100
rd         = "65000:1"
interfaces = ["veth0"]
import     = "blue-in"

[[filter]]
name    = "blue-in"
default = "accept"
[[filter.rule]]
prefix = ["10.77.0.0/24"]
action = "reject"

[[static]]
prefix = "10.99.0.0/24"
via    = "10.9.0.2"
vrf    = "blue"
[[static]]
prefix = "10.77.0.0/24"
via    = "10.9.0.2"
vrf    = "blue"
[[static]]
prefix = "10.88.0.0/24"
via    = "10.8.0.2"
[[static]]
prefix = "10.50.0.0/24"
via    = "10.8.0.2"
[[static]]
prefix = "10.50.0.0/24"
via    = "10.9.0.2"
vrf    = "blue"
EOF

export WREN WORK
timeout 60 unshare -Urn bash -c '
  set -e
  ip link set lo up
  # VRF device blue → table 100.
  ip link add blue type vrf table 100
  ip link set blue up
  ip link add veth0 type veth peer name veth1
  ip link set veth0 master blue          # veth0 lives in VRF blue
  ip addr add 10.9.0.1/24 dev veth0; ip link set veth0 up
  ip addr add 10.8.0.1/24 dev veth1; ip link set veth1 up

  "$WREN" --config "$WORK/a.toml" --backend kernel --socket "$WORK/a.sock" >"$WORK/a.log" 2>&1 &
  sleep 3

  echo "=== ip route show table 100 (VRF blue) ===" ; ip route show table 100 | tee "$WORK/t100.out"
  echo "=== ip route show (main) ===" ;               ip route show          | tee "$WORK/main.out"
  echo "=== wren show vrf ===" ;                       "$WREN" --socket "$WORK/a.sock" show vrf | tee "$WORK/vrf.out"
  echo "=== wren show routes ===" ;                    "$WREN" --socket "$WORK/a.sock" show routes | tee "$WORK/routes.out"
  pkill -f "$WORK/a.sock" 2>/dev/null || true
'

echo "=== checks ==="
ok=1
check() { if eval "$2"; then echo "OK: $1"; else echo "FAIL: $1"; ok=0; fi; }

# The VRF static installs into table 100, the plain one into main.
check "10.99.0.0/24 in VRF table 100"        "grep -q '10.99.0.0/24' '$WORK/t100.out'"
check "10.88.0.0/24 in main table"           "grep -q '10.88.0.0/24' '$WORK/main.out'"
check "10.99.0.0/24 NOT in main table"       "! grep -q '10.99.0.0/24' '$WORK/main.out'"
# The VRF import route-map rejected 10.77.0.0/24.
check "10.77.0.0/24 rejected by route-map"   "! grep -q '10.77.0.0/24' '$WORK/t100.out'"
# Overlapping prefix: one copy per table, via the right gateway.
check "10.50.0.0/24 via 10.9.0.2 in blue"    "grep -q '10.50.0.0/24 via 10.9.0.2' '$WORK/t100.out'"
check "10.50.0.0/24 via 10.8.0.2 in main"    "grep -q '10.50.0.0/24 via 10.8.0.2' '$WORK/main.out'"
# show vrf reports blue with its table and RD.
check "show vrf lists blue/100/65000:1"      "grep -Eq 'blue +100 +65000:1' '$WORK/vrf.out'"

if [[ $ok -ne 1 ]]; then echo '--- daemon log ---'; cat "$WORK/a.log"; fi
[[ $ok -eq 1 ]] && echo "VRF smoke test: OK"
exit $(( ok == 1 ? 0 : 1 ))
