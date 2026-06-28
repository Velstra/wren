#!/usr/bin/env bash
# BGP Route Refresh smoke test (RFC 2918) — a peer asks us to re-advertise our
# Adj-RIB-Out with a ROUTE-REFRESH, and we honour it without dropping the session.
# Self-contained and rootless.
#
# Like the other bgp-*-smoke.sh scripts it runs inside throwaway `unshare -Urn`
# namespaces and never touches the host interfaces or uplink. Per-daemon control
# sockets live under a temp dir (Unix sockets, not the network).
#
# Topology: A (AS 65001, 10.0.0.1) <--eBGP--> B (AS 65002, 10.0.0.2) over a veth.
# Both advertise the Route Refresh capability in their OPEN. A originates
# 10.1.0.0/24, which B learns. We then run `bgp refresh 10.0.0.1` on B: B sends a
# ROUTE-REFRESH to A, A re-advertises its Adj-RIB-Out, and A counts the request.
# The test asserts:
#   * before the refresh, A shows B Established with no refresh counter;
#   * `bgp refresh` on B reports the ROUTE-REFRESH was sent;
#   * after it, A shows B Established with `refreshes 1` (it honoured the request);
#   * B still has 10.1.0.0/24 installed `proto bgp` (the session never flapped).
#
# Usage:  bash scripts/bgp-route-refresh-smoke.sh
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
WREN="$REPO/target/debug/wren"

if [[ ! -x "$WREN" ]]; then
  echo "building wren (debug) ..."
  (cd "$REPO" && cargo build -p wren-daemon)
fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# A (active) originates the test network.
cat >"$WORK/a.toml" <<EOF
router-id = "10.0.0.1"
[bgp]
enabled  = true
local-as = 65001
network  = ["10.1.0.0/24"]
[[bgp.neighbor]]
address   = "10.0.0.2"
remote-as = 65002
EOF

# B (passive) learns it, and is the one that issues the ROUTE-REFRESH.
cat >"$WORK/b.toml" <<EOF
router-id = "10.0.0.2"
[bgp]
enabled  = true
local-as = 65002
[[bgp.neighbor]]
address   = "10.0.0.1"
remote-as = 65001
passive   = true
EOF

export WREN WORK
unshare -Urn bash -c '
  set -e
  ip link set lo up
  setsid unshare -n -- sleep 60 & BPID=$!
  sleep 0.3
  ip link add veth0 type veth peer name veth1
  ip link set veth1 netns $BPID
  ip addr add 10.0.0.1/24 dev veth0; ip link set veth0 up
  nsenter -t $BPID -n ip addr add 10.0.0.2/24 dev veth1
  nsenter -t $BPID -n ip link set veth1 up
  nsenter -t $BPID -n ip link set lo up

  nsenter -t $BPID -n "$WREN" --config "$WORK/b.toml" --backend kernel --socket "$WORK/b.sock" >"$WORK/b.log" 2>&1 &
  "$WREN" --config "$WORK/a.toml" --backend kernel --socket "$WORK/a.sock" >"$WORK/a.log" 2>&1 &
  sleep 8

  ok=1
  before="$("$WREN" --socket "$WORK/a.sock" show bgp neighbors)"
  echo "=== before refresh: show bgp neighbors (on A) ==="; echo "$before"
  echo "$before" | grep -q "10.0.0.2 AS 65002 Established" || { echo "FAIL: B not Established on A"; ok=0; }
  echo "$before" | grep -q "refreshes" && { echo "FAIL: refresh counter set before any refresh"; ok=0; }

  echo "=== bgp refresh 10.0.0.1 (on B) ==="
  sent="$(nsenter -t $BPID -n "$WREN" --socket "$WORK/b.sock" bgp refresh 10.0.0.1)"
  echo "$sent"
  echo "$sent" | grep -q "route refresh sent to 10.0.0.1" || { echo "FAIL: refresh not reported sent"; ok=0; }
  sleep 2

  # `bgp refresh` sends one ROUTE-REFRESH per negotiated family (IPv4 + IPv6 here),
  # so A counts one per message — assert it honoured at least one.
  after="$("$WREN" --socket "$WORK/a.sock" show bgp neighbors)"
  echo "=== after refresh: show bgp neighbors (on A) ==="; echo "$after"
  echo "$after" | grep -qE "10.0.0.2 AS 65002 Established refreshes [1-9]" \
    || { echo "FAIL: A did not count the ROUTE-REFRESH"; ok=0; }

  echo "=== ip route show proto bgp (on B) ==="
  broutes="$(nsenter -t $BPID -n ip route show proto bgp)"; echo "$broutes"
  echo "$broutes" | grep -q "10.1.0.0/24 via 10.0.0.1" \
    || { echo "FAIL: B lost 10.1.0.0/24 (session flapped?)"; ok=0; }

  if [[ $ok -ne 1 ]]; then echo "--- A log ---"; cat "$WORK/a.log"; echo "--- B log ---"; cat "$WORK/b.log"; fi
  kill $BPID 2>/dev/null || true
  exit $(( ok == 1 ? 0 : 1 ))
'
echo "bgp route refresh smoke test: OK"
