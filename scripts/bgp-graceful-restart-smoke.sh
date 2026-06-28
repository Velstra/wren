#!/usr/bin/env bash
# BGP Graceful Restart smoke test (RFC 4724) — a helper keeps a restarting peer's
# routes in service (and in the kernel FIB) across the peer's restart, instead of
# withdrawing them the moment the session drops. Self-contained and rootless.
#
# Like the other bgp-*-smoke.sh scripts it runs inside throwaway `unshare -Urn`
# namespaces and never touches the host interfaces or uplink. Per-daemon control
# sockets live under a temp dir (Unix sockets, not the network).
#
# Topology: A (AS 65001, 10.0.0.1) <--eBGP--> B (AS 65002, 10.0.0.2) over a veth.
# Both advertise the Graceful Restart capability in their OPEN. B originates
# 10.20.0.0/24, which A learns and installs `proto bgp`. A is the GR helper.
#
# Phase 1 (retention): kill B's daemon with SIGKILL (a hard restart). A's session
#   to B drops, but because B advertised GR with the forwarding state preserved, A
#   RETAINS 10.20.0.0/24 (helper) rather than withdrawing it. The test asserts that
#   shortly after the kill A shows B no longer Established yet still has the route
#   `proto bgp` — the whole point of graceful restart.
# Phase 2 (reconvergence): restart B. A reconnects, B re-advertises 10.20.0.0/24
#   and sends its End-of-RIB marker, and A finalises the restart. The test asserts
#   B is Established again and the route is still present (it never flapped).
#
# Usage:  bash scripts/bgp-graceful-restart-smoke.sh
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
WREN="$REPO/target/debug/wren"

if [[ ! -x "$WREN" ]]; then
  echo "building wren (debug) ..."
  (cd "$REPO" && cargo build -p wren-daemon)
fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# A (active) is the helper; it learns B's network.
cat >"$WORK/a.toml" <<EOF
router-id = "10.0.0.1"
[bgp]
enabled  = true
local-as = 65001
[[bgp.neighbor]]
address   = "10.0.0.2"
remote-as = 65002
EOF

# B (passive) originates the network and is the one that restarts.
cat >"$WORK/b.toml" <<EOF
router-id = "10.0.0.2"
[bgp]
enabled  = true
local-as = 65002
network  = ["10.20.0.0/24"]
[[bgp.neighbor]]
address   = "10.0.0.1"
remote-as = 65001
passive   = true
EOF

export WREN WORK
unshare -Urn bash -c '
  set -e
  ip link set lo up
  setsid unshare -n -- sleep 120 & BPID=$!
  sleep 0.3
  ip link add veth0 type veth peer name veth1
  ip link set veth1 netns $BPID
  ip addr add 10.0.0.1/24 dev veth0; ip link set veth0 up
  nsenter -t $BPID -n ip addr add 10.0.0.2/24 dev veth1
  nsenter -t $BPID -n ip link set veth1 up
  nsenter -t $BPID -n ip link set lo up

  start_b() {
    nsenter -t $BPID -n "$WREN" --config "$WORK/b.toml" --backend kernel --socket "$WORK/b.sock" >>"$WORK/b.log" 2>&1 &
  }

  "$WREN" --config "$WORK/a.toml" --backend kernel --socket "$WORK/a.sock" >"$WORK/a.log" 2>&1 &
  start_b
  sleep 8

  ok=1
  echo "=== phase 1: established (show bgp neighbors on A) ==="
  est="$("$WREN" --socket "$WORK/a.sock" show bgp neighbors)"; echo "$est"
  echo "$est" | grep -q "10.0.0.2 AS 65002 Established" || { echo "FAIL: B not Established on A"; ok=0; }
  echo "=== A kernel route (proto bgp) before restart ==="
  ip route show proto bgp | tee "$WORK/before"
  grep -q "10.20.0.0/24 via 10.0.0.2" "$WORK/before" || { echo "FAIL: A never learned 10.20.0.0/24"; ok=0; }

  echo "=== killing B (hard restart) ==="
  pkill -9 -f "$WORK/b.toml" || true
  sleep 3

  echo "=== phase 1 assert: session down but route RETAINED (helper) ==="
  down="$("$WREN" --socket "$WORK/a.sock" show bgp neighbors)"; echo "$down"
  echo "$down" | grep -q "10.0.0.2 AS 65002 Established" \
    && { echo "FAIL: A still thinks B is Established (did not notice the drop)"; ok=0; }
  echo "--- A kernel route (proto bgp) after kill ---"
  ip route show proto bgp | tee "$WORK/after"
  grep -q "10.20.0.0/24 via 10.0.0.2" "$WORK/after" \
    || { echo "FAIL: A withdrew 10.20.0.0/24 instead of retaining it (graceful restart broken)"; ok=0; }

  echo "=== phase 2: restart B, expect reconvergence without a flap ==="
  start_b
  sleep 16
  recon="$("$WREN" --socket "$WORK/a.sock" show bgp neighbors)"; echo "$recon"
  echo "$recon" | grep -q "10.0.0.2 AS 65002 Established" || { echo "FAIL: B did not re-establish"; ok=0; }
  echo "--- A kernel route (proto bgp) after reconverge ---"
  ip route show proto bgp | tee "$WORK/recon"
  grep -q "10.20.0.0/24 via 10.0.0.2" "$WORK/recon" \
    || { echo "FAIL: route gone after reconvergence"; ok=0; }

  if [[ $ok -ne 1 ]]; then echo "--- A log ---"; cat "$WORK/a.log"; echo "--- B log ---"; cat "$WORK/b.log"; fi
  kill $BPID 2>/dev/null || true
  pkill -9 -f "$WORK/b.toml" 2>/dev/null || true
  exit $(( ok == 1 ? 0 : 1 ))
'
echo "bgp graceful restart smoke test: OK"
