#!/usr/bin/env bash
# OSPF + BFD (RFC 5880 / RFC 5882) smoke test — a BFD session drives sub-second
# OSPF adjacency teardown, far faster than the dead interval. Self-contained,
# rootless.
#
# Like the other smoke scripts it runs inside throwaway `unshare -Urn` namespaces
# and never touches the host's interfaces or uplink. OSPF uses a raw IPPROTO_OSPF
# (89) socket and BFD a UDP socket; both work as the netns-root inside
# `unshare -Urn`. Per-daemon control sockets live under a temp dir.
#
# Topology: A (router-id 10.0.0.1) <--OSPF point-to-point--> B (10.0.0.2) over a
# veth, area 0.0.0.0, both with `[ospf] bfd = true` and `[bfd]` at 200 ms ×3
# (Detection Time ~600 ms) against the 40 s OSPF dead interval.
#
# The test:
#   1. brings the adjacency to Full and the BFD session Up on A;
#   2. silently blackholes the path by downing B's interface (B's Hellos stop, but
#      no signal reaches A — only BFD, not the slow dead-interval, can notice fast);
#   3. asserts A's neighbour leaves Full in well under a second — far faster than the
#      40 s dead interval ever would.
#
# Usage:  bash scripts/ospf-bfd-smoke.sh
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
WREN="$REPO/target/debug/wren"

echo "building wren (debug) ..."
(cd "$REPO" && cargo build -p wren-daemon)

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

cat >"$WORK/a.toml" <<EOF
router-id = "10.0.0.1"
[bfd]
min-tx      = 200
min-rx      = 200
detect-mult = 3
[ospf]
enabled = true
interfaces = ["veth0"]
network-type = "point-to-point"
bfd = true
EOF

cat >"$WORK/b.toml" <<EOF
router-id = "10.0.0.2"
[bfd]
min-tx      = 200
min-rx      = 200
detect-mult = 3
[ospf]
enabled = true
interfaces = ["veth1"]
network-type = "point-to-point"
bfd = true
EOF

export WREN WORK
timeout 90 unshare -Urn bash -c '
  set -e
  ip link set lo up
  setsid unshare -n -- sleep 80 & BPID=$!
  sleep 0.3
  ip link add veth0 type veth peer name veth1
  ip link set veth1 netns $BPID
  ip addr add 10.0.0.1/24 dev veth0; ip link set veth0 up
  nsenter -t $BPID -n ip addr add 10.0.0.2/24 dev veth1
  nsenter -t $BPID -n ip link set veth1 up
  nsenter -t $BPID -n ip link set lo up

  nsenter -t $BPID -n "$WREN" --config "$WORK/b.toml" --backend kernel --socket "$WORK/b.sock" >"$WORK/b.log" 2>&1 &
  "$WREN" --config "$WORK/a.toml" --backend kernel --socket "$WORK/a.sock" >"$WORK/a.log" 2>&1 &

  nbr_a() { "$WREN" --socket "$WORK/a.sock" show ospf neighbors 2>/dev/null || true; }
  bfd_a() { "$WREN" --socket "$WORK/a.sock" show bfd 2>/dev/null || true; }

  # Phase 1 — wait (up to ~50s) for the adjacency to reach Full AND BFD to come Up.
  up=0
  for _ in $(seq 1 250); do
    if nbr_a | grep -q "10.0.0.2.*state Full" && bfd_a | grep -qE "10\.0\.0\.2 +Up"; then
      up=1; break
    fi
    sleep 0.2
  done
  echo "=== A: show ospf neighbors (converged) ==="; nbr_a
  echo "=== A: show bfd (converged) ==="; bfd_a
  if [[ $up -ne 1 ]]; then echo "PHASE1_FAIL" >"$WORK/result.txt"; echo "--- A ---"; cat "$WORK/a.log"; echo "--- B ---"; cat "$WORK/b.log"; kill $BPID 2>/dev/null || true; exit 0; fi

  # Phase 2 — silently blackhole the path: down B`s interface.
  t0=$(date +%s%3N)
  nsenter -t $BPID -n ip link set veth1 down

  # Wait for A`s OSPF neighbour to leave Full (the adjacency is removed).
  down_ms=-1
  for _ in $(seq 1 60); do  # up to ~6s
    if ! nbr_a | grep -q "10.0.0.2.*state Full"; then
      down_ms=$(( $(date +%s%3N) - t0 )); break
    fi
    sleep 0.1
  done

  echo "=== A: show ospf neighbors (after blackhole) ==="; nbr_a
  echo "=== A: show bfd (after blackhole) ==="; bfd_a
  printf "down_ms=%s\n" "$down_ms" >"$WORK/result.txt"

  kill $BPID 2>/dev/null || true
'

echo "=== result ==="
cat "$WORK/result.txt" 2>/dev/null || { echo "FAIL: no result produced"; exit 1; }

if grep -q "PHASE1_FAIL" "$WORK/result.txt"; then
  echo "FAIL: OSPF adjacency / BFD did not converge"; exit 1
fi

# shellcheck disable=SC1090
eval "$(cat "$WORK/result.txt")"  # sets down_ms
ok=1
if [[ "${down_ms:--1}" -lt 0 ]]; then
  echo "FAIL: OSPF neighbour never left Full after the blackhole"; ok=0
elif [[ "$down_ms" -gt 5000 ]]; then
  echo "FAIL: took ${down_ms}ms to drop the adjacency (expected well under a second)"; ok=0
else
  echo "OK: BFD dropped the OSPF adjacency in ${down_ms}ms (dead interval is 40000ms)"
fi

[[ $ok -eq 1 ]] && echo "OSPF BFD smoke test: OK"
exit $(( ok == 1 ? 0 : 1 ))
