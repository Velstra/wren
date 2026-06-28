#!/usr/bin/env bash
# BGP confederation smoke test (RFC 5065) — a route crosses a confederation
# sub-AS boundary and leaves the confederation, exercising the AS_PATH transforms.
# Fully self-contained and rootless.
#
# Like the other bgp-*-smoke.sh scripts it runs inside throwaway `unshare -Urn`
# namespaces and never touches the host's interfaces or uplink. Per-daemon control
# sockets live under a temp dir (Unix sockets, not the network).
#
# Topology — confederation 65000 with two Member-ASes (65001, 65002) and one true
# external AS (64500), in a line:
#
#     A (AS 65001) ──10.12.0.0/24── B (AS 65002) ──10.23.0.0/24── C (AS 64500)
#      member of confed 65000        member of confed 65000        outside; sees
#      originates 10.1.0.0/24        (the confederation egress)     confed as 65000
#                                                                   originates 10.3.0.0/24
#
#   * A↔B is confed-eBGP (different Member-AS, same confederation): each presents
#     its Member-AS in the OPEN, and prepends its Member-AS to an AS_CONFED_SEQUENCE.
#   * B↔C is true eBGP: B presents the Confederation Identifier (65000) to C, and on
#     egress strips the internal AS_CONFED_SEQUENCE and prepends 65000.
#
# The test asserts:
#   * A's 10.1.0.0/24 reaches C, and C sees AS_PATH "65000" — the internal Member-AS
#     65001 is hidden (stripped + confed-id prepended on egress); C installs it
#     `proto bgp` (next hop B is on-link); and
#   * C's 10.3.0.0/24 reaches A's Loc-RIB with AS_PATH "(65002) 64500" — B prepended
#     its Member-AS into an AS_CONFED_SEQUENCE crossing the sub-AS boundary.
#
# Usage:  bash scripts/bgp-confederation-smoke.sh
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
WREN="$REPO/target/debug/wren"

if [[ ! -x "$WREN" ]]; then
  echo "building wren (debug) ..."
  (cd "$REPO" && cargo build -p wren-daemon)
fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# A — Member-AS 65001 of confederation 65000; originates 10.1.0.0/24; dials B.
cat >"$WORK/a.toml" <<EOF
router-id = "10.12.0.1"
[bgp]
enabled               = true
local-as              = 65001
confederation-id      = 65000
confederation-members = [65002]
network               = ["10.1.0.0/24"]
[[bgp.neighbor]]
address   = "10.12.0.2"
remote-as = 65002
EOF

# B — Member-AS 65002 of confederation 65000; the confederation egress. Waits for
# both A (confed-eBGP) and C (true eBGP).
cat >"$WORK/b.toml" <<EOF
router-id = "10.23.0.2"
[bgp]
enabled               = true
local-as              = 65002
confederation-id      = 65000
confederation-members = [65001]
[[bgp.neighbor]]
address   = "10.12.0.1"
remote-as = 65001
passive   = true
[[bgp.neighbor]]
address   = "10.23.0.3"
remote-as = 64500
passive   = true
EOF

# C — true external AS 64500; sees the confederation as a single AS (65000); dials B.
cat >"$WORK/c.toml" <<EOF
router-id = "10.23.0.3"
[bgp]
enabled  = true
local-as = 64500
network  = ["10.3.0.0/24"]
[[bgp.neighbor]]
address   = "10.23.0.2"
remote-as = 65000
EOF

export WREN WORK
unshare -Urn bash -c '
  set -e
  ip link set lo up
  # B is this (outer) namespace; A and C live in their own namespaces.
  setsid unshare -n -- sleep 120 & APID=$!
  setsid unshare -n -- sleep 120 & CPID=$!
  sleep 0.3

  # A ── B link (10.12.0.0/24): B keeps veth_b_a, A gets veth_a.
  ip link add veth_b_a type veth peer name veth_a
  ip link set veth_a netns $APID
  ip addr add 10.12.0.2/24 dev veth_b_a; ip link set veth_b_a up
  nsenter -t $APID -n ip addr add 10.12.0.1/24 dev veth_a
  nsenter -t $APID -n ip link set veth_a up
  nsenter -t $APID -n ip link set lo up

  # C ── B link (10.23.0.0/24): B keeps veth_b_c, C gets veth_c.
  ip link add veth_b_c type veth peer name veth_c
  ip link set veth_c netns $CPID
  ip addr add 10.23.0.2/24 dev veth_b_c; ip link set veth_b_c up
  nsenter -t $CPID -n ip addr add 10.23.0.3/24 dev veth_c
  nsenter -t $CPID -n ip link set veth_c up
  nsenter -t $CPID -n ip link set lo up

  nsenter -t $APID -n "$WREN" --config "$WORK/a.toml" --backend kernel --socket "$WORK/a.sock" >"$WORK/a.log" 2>&1 &
                    "$WREN" --config "$WORK/b.toml" --backend kernel --socket "$WORK/b.sock" >"$WORK/b.log" 2>&1 &
  nsenter -t $CPID -n "$WREN" --config "$WORK/c.toml" --backend kernel --socket "$WORK/c.sock" >"$WORK/c.log" 2>&1 &
  sleep 13

  ok=1
  {
    echo "=== wren show bgp neighbors (on B) ==="
    "$WREN" --socket "$WORK/b.sock" show bgp neighbors || true
    echo "=== wren show bgp (on C) ==="
    nsenter -t $CPID -n "$WREN" --socket "$WORK/c.sock" show bgp || true
    echo "=== ip route show proto bgp (on C) ==="
    nsenter -t $CPID -n ip route show proto bgp || true
    echo "=== wren show bgp (on A) ==="
    nsenter -t $APID -n "$WREN" --socket "$WORK/a.sock" show bgp || true
  } > "$WORK/out.txt" 2>&1
  cat "$WORK/out.txt"

  # Sessions up: A↔B (confed-eBGP, B sees A as 65001) and B↔C (true eBGP, 64500).
  grep -q "10.12.0.1 AS 65001 Established" "$WORK/out.txt" || { echo "FAIL: B-A confed session not Established"; ok=0; }
  grep -q "10.23.0.3 AS 64500 Established" "$WORK/out.txt" || { echo "FAIL: B-C eBGP session not Established"; ok=0; }

  # A→C: C sees 10.1.0.0/24 with AS_PATH 65000 (confed-id), NOT the hidden 65001.
  if grep -q "10.1.0.0/24 .* as-path 65000 " "$WORK/out.txt"; then :; else
    echo "FAIL: C did not learn 10.1.0.0/24 with as-path 65000"; ok=0; fi
  if grep "10.1.0.0/24 " "$WORK/out.txt" | grep -q "65001"; then
    echo "FAIL: C leaked the internal Member-AS 65001"; ok=0; fi
  grep -q "10.1.0.0/24 via 10.23.0.2 dev" "$WORK/out.txt" || { echo "FAIL: C did not install 10.1.0.0/24 proto bgp"; ok=0; }

  # C→A: A learns 10.3.0.0/24 with AS_PATH "(65002) 64500" (confed sequence prefix).
  grep -qF "10.3.0.0/24 via 10.23.0.3 as-path (65002) 64500" "$WORK/out.txt" \
    || { echo "FAIL: A did not learn 10.3.0.0/24 with as-path (65002) 64500"; ok=0; }

  if [[ $ok -ne 1 ]]; then
    echo "--- A log ---"; cat "$WORK/a.log"
    echo "--- B log ---"; cat "$WORK/b.log"
    echo "--- C log ---"; cat "$WORK/c.log"
  fi
  kill $APID $CPID 2>/dev/null || true
  exit $(( ok == 1 ? 0 : 1 ))
'
echo "bgp confederation smoke test: OK"
