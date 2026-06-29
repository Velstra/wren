#!/usr/bin/env bash
# `wren show metrics` smoke test — Prometheus text-exposition output over the
# control socket, fully self-contained and rootless.
#
# Like the other bgp-*-smoke.sh scripts it runs inside throwaway `unshare -Urn`
# namespaces and never touches the host's interfaces or uplink. Per-daemon control
# sockets live under a temp dir (Unix sockets, not the network).
#
# Topology: A (AS 65001, active) <-eBGP-> B (AS 65002, passive). B originates
# 10.20.0.0/24. We then scrape A's control socket with `show metrics` and assert
# the exposition carries:
#   * wren_bgp_neighbor_up{neighbor="10.0.0.2",asn="65002"} 1 (the session is up);
#   * wren_bgp_neighbors_established 1;
#   * wren_rib_routes{protocol="bgp"} (the per-protocol RIB count from the merged
#     RIB) — proving the router and BGP families combine into one exposition.
#
# Usage:  bash scripts/bgp-metrics-smoke.sh
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
WREN="$REPO/target/debug/wren"

echo "building wren (debug) ..."
(cd "$REPO" && cargo build -p wren-daemon)

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

cat >"$WORK/a.toml" <<EOF
router-id = "10.0.0.1"
[bgp]
enabled  = true
local-as = 65001
network  = ["10.10.0.0/24"]
[[bgp.neighbor]]
address   = "10.0.0.2"
remote-as = 65002
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
passive   = true
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

  nsenter -t $BPID -n "$WREN" --config "$WORK/b.toml" --backend kernel --socket "$WORK/b.sock" >"$WORK/b.log" 2>&1 &
  "$WREN" --config "$WORK/a.toml" --backend kernel --socket "$WORK/a.sock" >"$WORK/a.log" 2>&1 &
  sleep 6

  echo "=== wren show metrics (on A) ==="
  metrics="$("$WREN" --socket "$WORK/a.sock" show metrics)"
  echo "$metrics"

  ok=1
  echo "$metrics" | grep -q "wren_bgp_neighbor_up{neighbor=\"10.0.0.2\",asn=\"65002\"} 1" || { echo "FAIL: session not up in metrics"; ok=0; }
  echo "$metrics" | grep -q "wren_bgp_neighbors_established 1" || { echo "FAIL: established count wrong"; ok=0; }
  echo "$metrics" | grep -q "wren_rib_routes{protocol=\"bgp\"} 1" || { echo "FAIL: no bgp RIB count"; ok=0; }
  echo "$metrics" | grep -q "# TYPE wren_bgp_rib_routes gauge" || { echo "FAIL: missing bgp rib gauge family"; ok=0; }

  if [[ $ok -ne 1 ]]; then echo "--- A log ---"; cat "$WORK/a.log"; fi
  kill $BPID 2>/dev/null || true
  exit $(( ok == 1 ? 0 : 1 ))
'
echo "show metrics smoke test: OK"
