#!/usr/bin/env bash
# BGP RFC 9234 roles + Only-To-Customer (OTC) route-leak smoke test. Each neighbour is
# given a BGP Role; the roles are negotiated in OPEN (a mismatch would refuse the
# session) and the OTC attribute is applied so a route learned from a provider is never
# leaked to a lateral peer.
#
# Like the other bgp-*-smoke.sh scripts it runs inside throwaway `unshare -Urn`
# namespaces and never touches the host's interfaces or uplink. BGP binds TCP 179
# (CAP_NET_BIND_SERVICE), held by the netns-root.
#
# Topology (a shared L2 bridge; MID is the middle speaker):
#   PROV (AS 65001, 10.0.0.1)  originates 203.0.113.0/24; role toward MID = provider
#   MID  (AS 65002, 10.0.0.2)  originates 198.51.100.0/24; role toward PROV = customer,
#                              role toward PEER = peer
#   PEER (AS 65003, 10.0.0.3)  role toward MID = peer
#
# Expected (RFC 9234 §5):
#   * PROV → MID: 203.0.113.0/24 is tagged OTC = 65001 on egress (to a customer).
#   * MID learns it (OTC from a provider is legitimate) and re-originates 198.51.100.0/24.
#   * MID → PEER: 203.0.113.0/24 carries OTC and MUST NOT be advertised to a peer (leak
#     stop), while the locally-originated 198.51.100.0/24 IS advertised (tagged OTC).
#   => PEER has 198.51.100.0/24 but NOT 203.0.113.0/24.
#
# Usage:  bash scripts/bgp-otc-smoke.sh
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
WREN="$REPO/target/debug/wren"

if [[ ! -x "$WREN" ]]; then
  echo "building wren (debug) ..."
  (cd "$REPO" && cargo build -p wren-daemon)
fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# PROV — the upstream provider; originates 203.0.113.0/24.
cat >"$WORK/prov.toml" <<EOF
router-id = "10.0.0.1"
[bgp]
enabled  = true
local-as = 65001
network  = ["203.0.113.0/24"]
[[bgp.neighbor]]
address   = "10.0.0.2"
remote-as = 65002
role      = "provider"
EOF

# MID — customer of PROV, lateral peer of PEER; originates a control /24.
cat >"$WORK/mid.toml" <<EOF
router-id = "10.0.0.2"
[bgp]
enabled  = true
local-as = 65002
network  = ["198.51.100.0/24"]
[[bgp.neighbor]]
address   = "10.0.0.1"
remote-as = 65001
role      = "customer"
[[bgp.neighbor]]
address   = "10.0.0.3"
remote-as = 65003
role      = "peer"
EOF

# PEER (match) — MID's lateral peer, correct complementary role.
cat >"$WORK/peer_match.toml" <<EOF
router-id = "10.0.0.3"
[bgp]
enabled  = true
local-as = 65003
[[bgp.neighbor]]
address   = "10.0.0.2"
remote-as = 65002
role      = "peer"
EOF

# PEER (mismatch) — advertises role `customer` where MID expects `peer`; the session must
# be refused with an RFC 9234 §4.2 Role Mismatch and never reach Established.
cat >"$WORK/peer_mismatch.toml" <<EOF
router-id = "10.0.0.3"
[bgp]
enabled  = true
local-as = 65003
[[bgp.neighbor]]
address   = "10.0.0.2"
remote-as = 65002
role      = "customer"
EOF

export WREN WORK
unshare -Urn bash -c '
  set -e
  ip link set lo up
  # PROV and PEER live in their own namespaces; MID is this namespace and hosts the
  # shared L2 bridge all three sit on.
  setsid unshare -n -- sleep 120 & PPID_=$!
  setsid unshare -n -- sleep 120 & QPID=$!
  sleep 0.3

  ip link add br0 type bridge
  ip addr add 10.0.0.2/24 dev br0
  ip link set br0 up

  ip link add veth_p type veth peer name veth_p1
  ip link set veth_p1 netns $PPID_
  ip link set veth_p master br0; ip link set veth_p up
  nsenter -t $PPID_ -n ip addr add 10.0.0.1/24 dev veth_p1
  nsenter -t $PPID_ -n ip link set veth_p1 up
  nsenter -t $PPID_ -n ip link set lo up

  ip link add veth_q type veth peer name veth_q1
  ip link set veth_q1 netns $QPID
  ip link set veth_q master br0; ip link set veth_q up
  nsenter -t $QPID -n ip addr add 10.0.0.3/24 dev veth_q1
  nsenter -t $QPID -n ip link set veth_q1 up
  nsenter -t $QPID -n ip link set lo up

  run_phase() {
    tag="$1"
    nsenter -t $PPID_ -n "$WREN" --config "$WORK/prov.toml" --backend kernel --socket "$WORK/prov.sock" >"$WORK/prov_$tag.log" 2>&1 &
    "$WREN" --config "$WORK/mid.toml" --backend kernel --socket "$WORK/mid.sock" >"$WORK/mid_$tag.log" 2>&1 &
    nsenter -t $QPID -n "$WREN" --config "$WORK/peer_$tag.toml" --backend kernel --socket "$WORK/peer.sock" >"$WORK/peer_$tag.log" 2>&1 &
    sleep 16
    {
      echo "=== MID: show bgp neighbors ==="
      "$WREN" --socket "$WORK/mid.sock" show bgp neighbors || true
      echo "=== MID: show bgp routes ==="
      "$WREN" --socket "$WORK/mid.sock" show bgp routes || true
      echo "=== PEER: show bgp routes ==="
      nsenter -t $QPID -n "$WREN" --socket "$WORK/peer.sock" show bgp routes || true
    } >"$WORK/${tag}_out.txt" 2>&1
    nsenter -t $PPID_ -n pkill -f "$WORK/prov.sock" 2>/dev/null || true
    pkill -f "$WORK/mid.sock" 2>/dev/null || true
    nsenter -t $QPID -n pkill -f "$WORK/peer.sock" 2>/dev/null || true
    sleep 1
    nsenter -t $PPID_ -n ip route flush proto bgp 2>/dev/null || true
    ip route flush proto bgp 2>/dev/null || true
    nsenter -t $QPID -n ip route flush proto bgp 2>/dev/null || true
  }

  run_phase match
  run_phase mismatch
  kill $PPID_ $QPID 2>/dev/null || true
'

echo "=== match phase ==="; cat "$WORK/match_out.txt"
echo "=== mismatch phase ==="; cat "$WORK/mismatch_out.txt"
cp "$WORK/match_out.txt" "$WORK/out.txt"

# Split the match-phase output so a route in one section is not mistaken for another.
awk '/=== PEER: show bgp routes ===/{p=1;next} /^=== /{p=0} p' "$WORK/match_out.txt" >"$WORK/peer_routes.txt"
awk '/=== MID: show bgp routes ===/{m=1;next} /^=== /{m=0} m' "$WORK/match_out.txt" >"$WORK/mid_routes.txt"
awk '/=== MID: show bgp neighbors ===/{n=1;next} /^=== /{n=0} n' "$WORK/match_out.txt" >"$WORK/match_neigh.txt"
awk '/=== MID: show bgp neighbors ===/{n=1;next} /^=== /{n=0} n' "$WORK/mismatch_out.txt" >"$WORK/mismatch_neigh.txt"

ok=1
# --- match phase: roles complementary, OTC route-leak prevention ---
# Sanity: the provider→middle session came up (roles negotiated) and MID learnt the route.
grep -q "10.0.0.1 AS 65001 Established" "$WORK/match_neigh.txt" \
  || { echo "FAIL: match — MID-PROV session not Established (role negotiation?)"; ok=0; }
grep -q "10.0.0.3 AS 65003 Established" "$WORK/match_neigh.txt" \
  || { echo "FAIL: match — MID-PEER session not Established (role negotiation?)"; ok=0; }
grep -q "203.0.113.0/24" "$WORK/mid_routes.txt" \
  || { echo "FAIL: match — MID did not learn 203.0.113.0/24 from PROV"; ok=0; }

# The leak stop: PEER must NOT have the provider route (OTC blocks peer re-advertisement).
if grep -q "203.0.113.0/24" "$WORK/peer_routes.txt"; then
  echo "FAIL: match — PEER learned 203.0.113.0/24; OTC route leak NOT prevented (RFC 9234)"; ok=0
fi

# The control: PEER DOES get MID's locally-originated /24 (normal peer advertisement).
grep -q "198.51.100.0/24" "$WORK/peer_routes.txt" \
  || { echo "FAIL: match — PEER did not learn MID's own 198.51.100.0/24 (control broke)"; ok=0; }

# --- mismatch phase: PEER advertises role `customer` where MID expects `peer` ---
# The MID-PROV session (still complementary) stays up, but the MID-PEER session must be
# refused with a Role Mismatch and never reach Established.
grep -q "10.0.0.1 AS 65001 Established" "$WORK/mismatch_neigh.txt" \
  || { echo "FAIL: mismatch — MID-PROV session should still be Established"; ok=0; }
if grep -q "10.0.0.3 AS 65003 Established" "$WORK/mismatch_neigh.txt"; then
  echo "FAIL: mismatch — MID-PEER reached Established despite a role mismatch (RFC 9234 §4.2)"; ok=0
fi

[[ $ok -eq 1 ]] || { echo "--- logs ---"; tail -8 "$WORK"/prov_*.log "$WORK"/mid_*.log "$WORK"/peer_*.log 2>/dev/null; exit 1; }
echo "bgp OTC (RFC 9234) role + route-leak smoke test: OK"
