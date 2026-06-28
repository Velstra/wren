#!/usr/bin/env bash
# BGP connection-collision detection smoke test (RFC 4271 §6.8) — two speakers that
# both actively dial *and* accept end up racing two TCP connections to each other.
# §6.8 keeps the one opened by the higher BGP Identifier and Ceases the other, so
# the peering converges to a single stable session instead of two fighting ones.
# Fully self-contained and rootless.
#
# Like the other bgp-*-smoke.sh scripts it runs inside throwaway `unshare -Urn`
# namespaces and never touches the host's interfaces or uplink. Per-daemon control
# sockets live under a temp dir (Unix sockets, not the network).
#
# Topology: A (router-id 10.0.0.1, AS 65001) <-eBGP-> B (router-id 10.0.0.2, AS
# 65002) on a veth. NEITHER peer is `passive`, so both dial port 179 and both
# accept — a simultaneous open. B has the higher identifier, so the surviving
# connection is the one B initiated (B->A). The test asserts:
#   * both sides reach Established and install each other's network `proto bgp`; and
#   * the peering is STILL Established and the routes are STILL present after a
#     pause — i.e. it does not flap, which is what an unresolved collision causes.
#
# That stable both-active convergence IS the §6.8 evidence: before collision
# detection one side ended up Idle (a stale connection's Down evicted the survivor).
# (The daemons' own debug logs aren't asserted on — tracing writes to a
# block-buffered stdout that is lost when the daemon is killed, so the files end up
# empty; the behavioural check above is the real signal.)
#
# Usage:  bash scripts/bgp-collision-smoke.sh
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
WREN="$REPO/target/debug/wren"

if [[ ! -x "$WREN" ]]; then
  echo "building wren (debug) ..."
  (cd "$REPO" && cargo build -p wren-daemon)
fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# A actively dials B (not passive) AND accepts inbound — both ends do.
cat >"$WORK/a.toml" <<EOF
router-id = "10.0.0.1"
[bgp]
enabled   = true
local-as  = 65001
network   = ["10.1.0.0/24"]
[[bgp.neighbor]]
address   = "10.0.0.2"
remote-as = 65002
EOF

cat >"$WORK/b.toml" <<EOF
router-id = "10.0.0.2"
[bgp]
enabled   = true
local-as  = 65002
network   = ["10.2.0.0/24"]
[[bgp.neighbor]]
address   = "10.0.0.1"
remote-as = 65001
EOF

export WREN WORK
unshare -Urn bash -c '
  set -e
  ip link set lo up
  setsid unshare -n -- sleep 60 & BPID=$!
  sleep 0.3
  ip link add veth0 type veth peer name veth1
  ip link set veth1 netns $BPID
  ip addr add 10.0.0.1/24 dev veth0
  ip link set veth0 up
  nsenter -t $BPID -n ip addr add 10.0.0.2/24 dev veth1
  nsenter -t $BPID -n ip link set veth1 up
  nsenter -t $BPID -n ip link set lo up

  nsenter -t $BPID -n "$WREN" --config "$WORK/b.toml" --backend kernel --socket "$WORK/b.sock" >"$WORK/b.log" 2>&1 &
  "$WREN" --config "$WORK/a.toml" --backend kernel --socket "$WORK/a.sock" >"$WORK/a.log" 2>&1 &

  # Let the simultaneous-open race happen and converge.
  sleep 8
  echo "=== neighbors after convergence ==="
  A1=$("$WREN" --socket "$WORK/a.sock" show bgp neighbors 2>/dev/null || true)
  B1=$(nsenter -t $BPID -n "$WREN" --socket "$WORK/b.sock" show bgp neighbors 2>/dev/null || true)
  echo "A: $A1"; echo "B: $B1"

  # Re-check after a pause: an unresolved collision flaps; §6.8 stays put.
  sleep 5
  {
    echo "=== A neighbors (stable?) ===";  "$WREN" --socket "$WORK/a.sock" show bgp neighbors || true
    echo "=== B neighbors (stable?) ===";  nsenter -t $BPID -n "$WREN" --socket "$WORK/b.sock" show bgp neighbors || true
    echo "=== A kernel routes ===";        ip route show proto bgp || true
    echo "=== B kernel routes ===";        nsenter -t $BPID -n ip route show proto bgp || true
  } > "$WORK/out.txt" 2>&1
  cat "$WORK/out.txt"

  ok=1
  grep -q "10.0.0.2 AS 65002 Established" "$WORK/out.txt" || { echo "FAIL: A not Established with B (stable check)"; ok=0; }
  grep -q "10.0.0.1 AS 65001 Established" "$WORK/out.txt" || { echo "FAIL: B not Established with A (stable check)"; ok=0; }
  grep -q "10.2.0.0/24 via 10.0.0.2"      "$WORK/out.txt" || { echo "FAIL: A did not install B network proto bgp"; ok=0; }
  grep -q "10.1.0.0/24 via 10.0.0.1"      "$WORK/out.txt" || { echo "FAIL: B did not install A network proto bgp"; ok=0; }

  if [[ $ok -ne 1 ]]; then echo "--- A log ---"; cat "$WORK/a.log"; echo "--- B log ---"; cat "$WORK/b.log"; fi
  kill $BPID 2>/dev/null || true
  exit $(( ok == 1 ? 0 : 1 ))
'
echo "bgp collision smoke test: OK"
