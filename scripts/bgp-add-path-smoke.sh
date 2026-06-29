#!/usr/bin/env bash
# BGP ADD-PATH (RFC 7911) smoke test — a speaker advertises, and a peer keeps,
# MORE THAN ONE path for the same destination. Self-contained, rootless.
#
# Like the other bgp-*-smoke.sh scripts it runs inside throwaway `unshare -Urn`
# namespaces and never touches the host's interfaces or uplink. BGP binds TCP 179
# (CAP_NET_BIND_SERVICE, held by the netns-root inside `unshare -Urn`); per-daemon
# control sockets are Unix sockets under a temp dir, not the network.
#
# Topology (A in the outer netns; B, C, D each in their own child netns, on three
# point-to-point links to A):
#
#     B (AS65002, 10.50.0.0/24) --eBGP-- \
#                                         A (AS65001) --iBGP-- D (AS65001)
#     C (AS65003, 10.50.0.0/24) --eBGP-- /
#
# Both B and C originate 10.50.0.0/24, so A's Adj-RIB-In holds TWO paths for it
# (next-hop 10.1.0.2 via B, next-hop 10.2.0.2 via C). A reflects to its iBGP peer D.
#
#   Phase 1 (ADD-PATH off): A advertises only its single best path, so D holds ONE
#                           path for 10.50.0.0/24.
#   Phase 2 (ADD-PATH on) : A advertises BOTH paths under distinct Path Identifiers,
#                           so D holds TWO paths for 10.50.0.0/24 — impossible from a
#                           single iBGP peer without ADD-PATH.
#
# We assert on D's `show bgp paths` (the Adj-RIB-In view) in each phase.
#
# NOTE on shell options: the outer `set -euo pipefail` exports SHELLOPTS (incl.
# nounset) into the inner `unshare -Urn bash -c` block; the netns block only writes
# output files and the assertions run in the OUTER shell afterwards.
#
# Usage:  bash scripts/bgp-add-path-smoke.sh
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
WREN="$REPO/target/debug/wren"

if [[ ! -x "$WREN" ]]; then
  echo "building wren (debug) ..."
  (cd "$REPO" && cargo build -p wren-daemon)
fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# B and C: each originates 10.50.0.0/24 and peers (passively) with A over eBGP.
cat >"$WORK/b.toml" <<EOF
router-id = "10.0.0.2"
[bgp]
enabled  = true
local-as = 65002
network  = ["10.50.0.0/24"]
[[bgp.neighbor]]
address   = "10.1.0.1"
remote-as = 65001
passive   = true
EOF

cat >"$WORK/c.toml" <<EOF
router-id = "10.0.0.3"
[bgp]
enabled  = true
local-as = 65003
network  = ["10.50.0.0/24"]
[[bgp.neighbor]]
address   = "10.2.0.1"
remote-as = 65001
passive   = true
EOF

# A: two eBGP peers (B, C) and one iBGP peer (D). The argument toggles ADD-PATH
# toward D.
gen_a() { # $1 = add-path line for the D neighbour ("" or "add-path = true")
cat >"$WORK/a.toml" <<EOF
router-id = "10.0.0.1"
[bgp]
enabled  = true
local-as = 65001
[[bgp.neighbor]]
address   = "10.1.0.2"
remote-as = 65002
[[bgp.neighbor]]
address   = "10.2.0.2"
remote-as = 65003
[[bgp.neighbor]]
address   = "10.3.0.2"
remote-as = 65001
$1
EOF
}

gen_d() { # $1 = add-path line for the A neighbour
cat >"$WORK/d.toml" <<EOF
router-id = "10.0.0.4"
[bgp]
enabled  = true
local-as = 65001
[[bgp.neighbor]]
address   = "10.3.0.1"
remote-as = 65001
passive   = true
$1
EOF
}

# Pre-stage both phases' A/D configs; B/C are identical across phases.
gen_a "add-path = true"; cp "$WORK/a.toml" "$WORK/a_on.toml"
gen_d "add-path = true"; cp "$WORK/d.toml" "$WORK/d_on.toml"
gen_a "";                cp "$WORK/a.toml" "$WORK/a_off.toml"
gen_d "";                cp "$WORK/d.toml" "$WORK/d_off.toml"

export WREN WORK
unshare -Urn bash -c '
  set -e
  ip link set lo up

  # Three child netns: B, C, D.
  setsid unshare -n -- sleep 120 & BPID=$!
  setsid unshare -n -- sleep 120 & CPID=$!
  setsid unshare -n -- sleep 120 & DPID=$!
  sleep 0.3

  # A<->B link (10.1.0.0/24).
  ip link add vab type veth peer name vba
  ip link set vba netns $BPID
  ip addr add 10.1.0.1/24 dev vab; ip link set vab up
  nsenter -t $BPID -n ip addr add 10.1.0.2/24 dev vba
  nsenter -t $BPID -n ip link set vba up
  nsenter -t $BPID -n ip link set lo up

  # A<->C link (10.2.0.0/24).
  ip link add vac type veth peer name vca
  ip link set vca netns $CPID
  ip addr add 10.2.0.1/24 dev vac; ip link set vac up
  nsenter -t $CPID -n ip addr add 10.2.0.2/24 dev vca
  nsenter -t $CPID -n ip link set vca up
  nsenter -t $CPID -n ip link set lo up

  # A<->D link (10.3.0.0/24).
  ip link add vad type veth peer name vda
  ip link set vda netns $DPID
  ip addr add 10.3.0.1/24 dev vad; ip link set vad up
  nsenter -t $DPID -n ip addr add 10.3.0.2/24 dev vda
  nsenter -t $DPID -n ip link set vda up
  nsenter -t $DPID -n ip link set lo up

  run_phase() {
    acfg="$1"; dcfg="$2"; out="$3"
    nsenter -t $BPID -n "$WREN" --config "$WORK/b.toml" --backend kernel --socket "$WORK/b.sock" >"$WORK/b.log" 2>&1 &
    nsenter -t $CPID -n "$WREN" --config "$WORK/c.toml" --backend kernel --socket "$WORK/c.sock" >"$WORK/c.log" 2>&1 &
    nsenter -t $DPID -n "$WREN" --config "$dcfg" --backend kernel --socket "$WORK/d.sock" >"$WORK/d.log" 2>&1 &
    "$WREN" --config "$acfg" --backend kernel --socket "$WORK/a.sock" >"$WORK/a.log" 2>&1 &
    sleep 14
    nsenter -t $DPID -n "$WREN" --socket "$WORK/d.sock" show bgp paths >"$out" 2>&1 || true
    pkill -f "$WORK/a.sock" 2>/dev/null || true
    nsenter -t $BPID -n pkill -f "$WORK/b.sock" 2>/dev/null || true
    nsenter -t $CPID -n pkill -f "$WORK/c.sock" 2>/dev/null || true
    nsenter -t $DPID -n pkill -f "$WORK/d.sock" 2>/dev/null || true
    sleep 1
  }

  run_phase "$WORK/a_off.toml" "$WORK/d_off.toml" "$WORK/d_off.txt"
  run_phase "$WORK/a_on.toml"  "$WORK/d_on.toml"  "$WORK/d_on.txt"

  kill $BPID $CPID $DPID 2>/dev/null || true
'

echo "=== Phase 1 (ADD-PATH off): D show bgp paths ==="
cat "$WORK/d_off.txt"
echo "=== Phase 2 (ADD-PATH on):  D show bgp paths ==="
cat "$WORK/d_on.txt"

ok=1
# Phase 1: D holds exactly ONE path for 10.50.0.0/24.
n_off=$(grep -c "10.50.0.0/24" "$WORK/d_off.txt" || true)
[[ "$n_off" == "1" ]] || { echo "FAIL: phase 1 expected 1 path for 10.50.0.0/24, got $n_off"; ok=0; }
# Phase 2: D holds TWO paths — one via B (10.1.0.2), one via C (10.2.0.2) — under
# distinct Path Identifiers. Only ADD-PATH can deliver two paths from one iBGP peer.
n_on=$(grep -c "10.50.0.0/24" "$WORK/d_on.txt" || true)
[[ "$n_on" == "2" ]] || { echo "FAIL: phase 2 expected 2 paths for 10.50.0.0/24, got $n_on"; ok=0; }
grep -q "10.50.0.0/24 path-id .* via 10.1.0.2" "$WORK/d_on.txt" || { echo "FAIL: phase 2 missing path via B (10.1.0.2)"; ok=0; }
grep -q "10.50.0.0/24 path-id .* via 10.2.0.2" "$WORK/d_on.txt" || { echo "FAIL: phase 2 missing path via C (10.2.0.2)"; ok=0; }

if [[ $ok -ne 1 ]]; then
  echo "--- A log ---"; tail -15 "$WORK/a.log"
  echo "--- D log ---"; tail -15 "$WORK/d.log"
fi
[[ $ok -eq 1 ]] || exit 1
echo "bgp add-path smoke test: OK"
