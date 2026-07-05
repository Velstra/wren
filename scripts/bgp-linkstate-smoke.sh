#!/usr/bin/env bash
# BGP-LS (AFI 16388 / SAFI 71, RFC 7752) smoke test. A speaker advertises a
# Link-State topology — a Node, a Link and a Prefix object — over BGP-LS; a receiver
# (a controller) negotiates SAFI 71, installs the objects into its BGP-LS RIB, and
# `show bgp link-state` displays the topology with each object's key attributes.
#
# Like the other bgp-*-smoke.sh scripts it runs inside throwaway `unshare -Urn`
# namespaces and never touches the host's interfaces or uplink. BGP binds TCP 179
# (CAP_NET_BIND_SERVICE), held by the netns-root.
#
# Topology: R1 (AS 65000, 10.0.0.1) originates three static `[[bgp.link-state]]`
# objects (a node r1, a link r1->r2, and a prefix 10.20.30.0/24) and peers iBGP with
# CTRL (AS 65000, 10.0.0.2) over a direct veth, both with `link-state = true`.
#
# Exporting the *live* OSPF/IS-IS topology into BGP-LS is future work; these static
# objects stand in for it. The wren-side deliverable is the RECEIVE + RIB + show path:
# a controller consuming a topology.
#
# Usage:  bash scripts/bgp-linkstate-smoke.sh
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
WREN="$REPO/target/debug/wren"

if [[ ! -x "$WREN" ]]; then
  echo "building wren (debug) ..."
  (cd "$REPO" && cargo build -p wren-daemon)
fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# R1 — originates the Link-State topology.
cat >"$WORK/r1.toml" <<EOF
router-id = "10.0.0.1"
[bgp]
enabled  = true
local-as = 65000

[[bgp.link-state]]
type      = "node"
protocol  = "ospf"
router-id = "10.0.0.1"
as        = 65000
name      = "r1"

[[bgp.link-state]]
type             = "link"
router-id        = "10.0.0.1"
remote-router-id = "10.0.0.2"
local-interface  = "192.0.2.1"
remote-interface = "192.0.2.2"
igp-metric       = 10
admin-group      = 5

[[bgp.link-state]]
type       = "prefix"
router-id  = "10.0.0.1"
prefix     = "10.20.30.0/24"
igp-metric = 20

[[bgp.neighbor]]
address    = "10.0.0.2"
remote-as  = 65000
link-state = true
EOF

# CTRL — the controller: installs whatever Link-State topology it learns.
cat >"$WORK/ctrl.toml" <<EOF
router-id = "10.0.0.2"
[bgp]
enabled  = true
local-as = 65000
[[bgp.neighbor]]
address    = "10.0.0.1"
remote-as  = 65000
link-state = true
EOF

export WREN WORK
unshare -Urn bash -c '
  set -e
  ip link set lo up
  setsid unshare -n -- sleep 120 & CPID=$!
  sleep 0.3
  ip link add veth0 type veth peer name veth1
  ip link set veth1 netns $CPID
  ip addr add 10.0.0.1/24 dev veth0; ip link set veth0 up
  nsenter -t $CPID -n ip addr add 10.0.0.2/24 dev veth1
  nsenter -t $CPID -n ip link set veth1 up
  nsenter -t $CPID -n ip link set lo up

  "$WREN" --config "$WORK/r1.toml" --backend kernel --socket "$WORK/r1.sock" >"$WORK/r1.log" 2>&1 &
  nsenter -t $CPID -n "$WREN" --config "$WORK/ctrl.toml" --backend kernel --socket "$WORK/ctrl.sock" >"$WORK/ctrl.log" 2>&1 &
  sleep 16

  {
    echo "=== R1: show bgp neighbors ==="
    "$WREN" --socket "$WORK/r1.sock" show bgp neighbors || true
    echo "=== CTRL: show bgp link-state ==="
    nsenter -t $CPID -n "$WREN" --socket "$WORK/ctrl.sock" show bgp link-state || true
  } >"$WORK/out.txt" 2>&1

  pkill -f "$WORK/r1.sock" 2>/dev/null || true
  nsenter -t $CPID -n pkill -f "$WORK/ctrl.sock" 2>/dev/null || true
  kill $CPID 2>/dev/null || true
'

cat "$WORK/out.txt"

ok=1
# The iBGP session came up (SAFI 71 negotiated in the OPEN).
grep -q "10.0.0.2 AS 65000 Established" "$WORK/out.txt" \
  || { echo "FAIL: R1-CTRL session not Established"; ok=0; }

# The controller installed the three objects with their key attributes.
node="$(grep "^node " "$WORK/out.txt" || true)"
[[ -n "$node" ]] || { echo "FAIL: CTRL did not install the node object"; ok=0; }
echo "$node" | grep -q "10.0.0.1"  || { echo "FAIL: node missing router-id"; ok=0; }
echo "$node" | grep -q "name r1"   || { echo "FAIL: node missing name r1"; ok=0; }

link="$(grep "^link " "$WORK/out.txt" || true)"
[[ -n "$link" ]] || { echo "FAIL: CTRL did not install the link object"; ok=0; }
echo "$link" | grep -q "10.0.0.1 -> 10.0.0.2" || { echo "FAIL: link missing endpoints"; ok=0; }
echo "$link" | grep -q "metric 10"            || { echo "FAIL: link missing igp metric"; ok=0; }

prefix="$(grep "^ipv4-prefix " "$WORK/out.txt" || true)"
[[ -n "$prefix" ]] || { echo "FAIL: CTRL did not install the prefix object"; ok=0; }
echo "$prefix" | grep -q "10.20.30.0/24"      || { echo "FAIL: prefix object missing the prefix"; ok=0; }

[[ $ok -eq 1 ]] || { echo "--- logs ---"; tail -8 "$WORK"/r1.log "$WORK"/ctrl.log 2>/dev/null; exit 1; }
echo "bgp BGP-LS (SAFI 71, RFC 7752) smoke test: OK"
