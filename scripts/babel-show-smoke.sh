#!/usr/bin/env bash
# Babel operational `show` command — `wren show babel neighbors`, answered by the
# Babel task itself out of its live neighbour table (the Hello/IHU link costs).
# Self-contained, rootless.
#
# Like the other smoke scripts it runs inside throwaway `unshare -Urn` namespaces
# and never touches the host's interfaces or uplink. Babel uses a UDP socket on
# [ff02::1:6]:6696 with SO_BINDTODEVICE, which needs CAP_NET_RAW — held by the
# netns-root inside `unshare -Urn`. Per-daemon control sockets live under a temp
# dir (Unix sockets, not the network).
#
# Topology: A <--Babel--> B over a veth. B redistributes a static into Babel.
# Once Hellos + IHUs have been exchanged, A's neighbour table holds B's link-local
# with a finite link cost, and A has learned B's route, so:
#   * `wren show babel neighbors` on A reports the neighbour;
#   * `wren show babel routes`    on A reports the learned route.
#
# Usage:  bash scripts/babel-show-smoke.sh
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
[babel]
enabled = true
interfaces = ["veth0"]
EOF

cat >"$WORK/b.toml" <<EOF
router-id = "10.0.0.2"
[[static]]
prefix = "2001:db8:99::/64"
via    = "2001:db8::1"
[babel]
enabled = true
interfaces = ["veth1"]
redistribute = ["static"]
EOF

export WREN WORK
unshare -Urn bash -c '
  set -e
  ip link set lo up
  setsid unshare -n -- sleep 120 & BPID=$!
  sleep 0.3
  ip link add veth0 type veth peer name veth1
  ip link set veth1 netns $BPID
  ip addr add 2001:db8::1/64 dev veth0; ip link set veth0 up
  nsenter -t $BPID -n ip addr add 2001:db8::2/64 dev veth1
  nsenter -t $BPID -n ip link set veth1 up
  nsenter -t $BPID -n ip link set lo up
  # Let DAD settle so the link-local addresses are usable.
  sleep 2

  nsenter -t $BPID -n "$WREN" --config "$WORK/b.toml" --backend kernel --socket "$WORK/b.sock" >"$WORK/b.log" 2>&1 &
  "$WREN" --config "$WORK/a.toml" --backend kernel --socket "$WORK/a.sock" >"$WORK/a.log" 2>&1 &
  # Babel: Hello every ~4s, then IHU before a neighbour cost goes finite.
  sleep 18

  echo "=== wren show babel neighbors (on A) ==="
  "$WREN" --socket "$WORK/a.sock" show babel neighbors 2>&1 | tee "$WORK/nbr.out" || true
  echo "=== wren show babel routes (on A) ==="
  "$WREN" --socket "$WORK/a.sock" show babel routes 2>&1 | tee "$WORK/rt.out" || true

  ok=1
  # B is learned by its link-local source address, with a finite (numeric) cost.
  grep -Eq "fe80.* rxcost [0-9]+ cost [0-9]+" "$WORK/nbr.out" \
    || { echo "FAIL: B not shown as a babel neighbour with a finite cost on A"; ok=0; }
  # A learned B's redistributed route, via B's link-local, with a finite metric.
  grep -Eq "2001:db8:99::/64 via fe80.* metric [0-9]+" "$WORK/rt.out" \
    || { echo "FAIL: A did not learn 2001:db8:99::/64 in show babel routes"; ok=0; }

  if [[ $ok -ne 1 ]]; then echo "--- A log ---"; cat "$WORK/a.log"; echo "--- B log ---"; cat "$WORK/b.log"; fi
  pkill -f "$WORK/a.sock" 2>/dev/null || true
  nsenter -t $BPID -n pkill -f "$WORK/b.sock" 2>/dev/null || true
  kill $BPID 2>/dev/null || true
  exit $(( ok == 1 ? 0 : 1 ))
'
echo "babel show smoke test: OK"
