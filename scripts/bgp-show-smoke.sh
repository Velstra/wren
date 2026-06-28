#!/usr/bin/env bash
# `wren show bgp` smoke test — operational visibility into the BGP RIB and
# neighbour table, fully self-contained and rootless.
#
# Like the other bgp-*-smoke.sh scripts it runs inside throwaway `unshare -Urn`
# namespaces and never touches the host's interfaces or uplink. Per-daemon
# control sockets live under a temp dir (Unix sockets, not the network).
#
# Topology: A (AS 65001, active) <-eBGP-> B (AS 65002, passive). B originates
# 10.20.0.0/24 tagged community 65002:100. We then query A's control socket:
#   * `show bgp neighbors` must list B as Established;
#   * `show bgp` must show 10.20.0.0/24 via B with as-path 65002 and the
#     community — proving received attributes are retained and rendered.
#
# Usage:  bash scripts/bgp-show-smoke.sh
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
community = ["65002:100"]
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

  echo "=== wren show bgp neighbors (on A) ==="
  nbrs="$("$WREN" --socket "$WORK/a.sock" show bgp neighbors)"
  echo "$nbrs"
  echo "=== wren show bgp (on A) ==="
  routes="$("$WREN" --socket "$WORK/a.sock" show bgp)"
  echo "$routes"

  ok=1
  echo "$nbrs"  | grep -q "10.0.0.2 AS 65002 Established" || { echo "FAIL: B not Established"; ok=0; }
  echo "$routes" | grep -q "10.20.0.0/24 via 10.0.0.2"   || { echo "FAIL: missing route"; ok=0; }
  echo "$routes" | grep -q "as-path 65002"               || { echo "FAIL: missing as-path"; ok=0; }
  echo "$routes" | grep -q "communities 65002:100"       || { echo "FAIL: missing community"; ok=0; }

  if [[ $ok -ne 1 ]]; then echo "--- A log ---"; cat "$WORK/a.log"; fi
  kill $BPID 2>/dev/null || true
  exit $(( ok == 1 ? 0 : 1 ))
'
echo "show bgp smoke test: OK"
