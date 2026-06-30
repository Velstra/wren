#!/usr/bin/env bash
# Route-export stream smoke test — `wren monitor routes`, the FPM-style feed an
# external forwarding plane (e.g. the Velstra eBPF datapath) consumes to mirror
# Wren's routing decisions. Fully self-contained and rootless.
#
# Like the bgp-*-smoke.sh scripts it runs inside throwaway `unshare -Urn`
# namespaces and never touches the host's interfaces or uplink. The control
# sockets are Unix sockets under a temp dir, not the network.
#
# Topology: A (AS 65001, passive) <-eBGP-> B (AS 65002, active). B originates
# 10.20.0.0/24. We subscribe to A's route-export stream *while B is still down*,
# so the snapshot is empty; then we start B, and A learns 10.20.0.0/24 — which
# streams as a LIVE `+` event. (A clean ADD, so no graceful-restart machinery is
# involved.) We assert:
#   * `% end-of-dump`                                  — the snapshot terminator;
#   * `+ 10.20.0.0/24 … proto bgp` after end-of-dump   — the route, streamed live.
#
# Usage:  bash scripts/route-export-smoke.sh
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
WREN="$REPO/target/debug/wren"

if [[ ! -x "$WREN" ]]; then
  echo "building wren (debug) ..."
  (cd "$REPO" && cargo build -p wren-daemon)
fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

cat >"$WORK/a.toml" <<EOF
router-id = "10.0.0.1"
[bgp]
enabled  = true
local-as = 65001
[[bgp.neighbor]]
address   = "10.0.0.2"
remote-as = 65002
passive   = true
EOF

cat >"$WORK/b.toml" <<EOF
router-id = "10.0.0.2"
[bgp]
enabled   = true
local-as  = 65002
network   = ["10.20.0.0/24"]
[[bgp.neighbor]]
address   = "10.0.0.1"
remote-as = 65001
EOF

export WREN WORK
unshare -Urn bash -c '
  set -e
  ip link set lo up
  setsid unshare -n -- sleep 30 & BPID=$!
  sleep 0.3
  ip link add veth0 type veth peer name veth1
  ip link set veth1 netns $BPID
  ip addr add 10.0.0.1/24 dev veth0; ip link set veth0 up
  nsenter -t $BPID -n ip addr add 10.0.0.2/24 dev veth1
  nsenter -t $BPID -n ip link set veth1 up
  nsenter -t $BPID -n ip link set lo up

  # Start A (passive) only; subscribe while B is still down → empty snapshot.
  "$WREN" --config "$WORK/a.toml" --backend kernel --socket "$WORK/a.sock" >"$WORK/a.log" 2>&1 &
  sleep 1.5
  timeout 12 "$WREN" --socket "$WORK/a.sock" monitor routes >"$WORK/mon.out" 2>&1 & MONPID=$!
  sleep 1.5

  # Now start B (active): it connects to A and advertises 10.20.0.0/24, which A
  # learns and streams live to the subscriber.
  nsenter -t $BPID -n "$WREN" --config "$WORK/b.toml" --backend kernel --socket "$WORK/b.sock" >"$WORK/b.log" 2>&1 &
  sleep 6

  echo "=== wren monitor routes (on A) ==="
  cat "$WORK/mon.out"

  ok=1
  grep -q "^% end-of-dump"             "$WORK/mon.out" || { echo "FAIL: no end-of-dump terminator"; ok=0; }
  grep -q "^+ 10.20.0.0/24.*proto bgp" "$WORK/mon.out" || { echo "FAIL: BGP route not exported"; ok=0; }
  # Liveness: the route must arrive AFTER the (empty) snapshot terminator.
  eod=$(grep -n "^% end-of-dump"  "$WORK/mon.out" | head -1 | cut -d: -f1)
  add=$(grep -n "^+ 10.20.0.0/24" "$WORK/mon.out" | head -1 | cut -d: -f1)
  if [[ -z "$eod" || -z "$add" || "$add" -le "$eod" ]]; then
    echo "FAIL: route did not arrive live after end-of-dump (add=$add eod=$eod)"; ok=0
  fi

  if [[ $ok -ne 1 ]]; then echo "--- A log ---"; cat "$WORK/a.log"; fi
  kill $MONPID 2>/dev/null || true
  kill $BPID   2>/dev/null || true
  exit $(( ok == 1 ? 0 : 1 ))
'
echo "route-export smoke test: OK"
