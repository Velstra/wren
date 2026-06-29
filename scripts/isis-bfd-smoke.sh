#!/usr/bin/env bash
# IS-IS + BFD (RFC 5880 / RFC 5882) smoke test — a BFD session drives sub-second
# IS-IS adjacency teardown, far faster than the holding time. Self-contained,
# rootless.
#
# IS-IS adjacencies run over SNPA/MAC, not IP, so the neighbour's IP for BFD is
# learned from the IP Interface Address TLV (132/232) in its Hellos. This test puts
# IPv4 on the link, so BFD runs to the neighbour's advertised IPv4 address.
#
# Like the other smoke scripts it runs inside throwaway `unshare -Urn` namespaces and
# never touches the host's interfaces or uplink. IS-IS uses an AF_PACKET (802.2 LLC)
# socket per interface and BFD a UDP socket; both work as the netns-root inside
# `unshare -Urn` (which grants CAP_NET_RAW). Per-daemon control sockets live under a
# temp dir.
#
# Topology: A (system 0000.0000.0001) <--IS-IS point-to-point L1L2--> B
# (0000.0000.0002) over a veth, both with `[isis] bfd = true` and `[bfd]` at 200 ms ×3
# (Detection Time ~600 ms) against the IS-IS holding time (hello-interval 3 × 3 = 9 s).
#
# The test:
#   1. brings the adjacency Up and the BFD session Up on A;
#   2. silently blackholes the path by downing B's interface (B's Hellos and BFD
#      packets stop, but no signal reaches A — only BFD, not the slower holding
#      timer, can notice fast);
#   3. asserts A's neighbour leaves Up in well under a second — far faster than the
#      9 s holding time ever would.
#
# Usage:  bash scripts/isis-bfd-smoke.sh
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
[isis]
enabled = true
interfaces = ["veth0"]
system-id = "0000.0000.0001"
network-type = "point-to-point"
hello-interval = 3
bfd = true
EOF

cat >"$WORK/b.toml" <<EOF
router-id = "10.0.0.2"
[bfd]
min-tx      = 200
min-rx      = 200
detect-mult = 3
[isis]
enabled = true
interfaces = ["veth1"]
system-id = "0000.0000.0002"
network-type = "point-to-point"
hello-interval = 3
bfd = true
EOF

export WREN WORK
timeout 120 unshare -Urn bash -c '
  set -e
  ip link set lo up
  setsid unshare -n -- sleep 110 & BPID=$!
  sleep 0.3
  ip link add veth0 type veth peer name veth1
  ip link set veth1 netns $BPID
  ip addr add 10.0.0.1/24 dev veth0; ip link set veth0 up
  nsenter -t $BPID -n ip addr add 10.0.0.2/24 dev veth1
  nsenter -t $BPID -n ip link set veth1 up
  nsenter -t $BPID -n ip link set lo up

  nsenter -t $BPID -n "$WREN" --config "$WORK/b.toml" --backend kernel --socket "$WORK/b.sock" >"$WORK/b.log" 2>&1 &
  "$WREN" --config "$WORK/a.toml" --backend kernel --socket "$WORK/a.sock" >"$WORK/a.log" 2>&1 &

  nbr_a() { "$WREN" --socket "$WORK/a.sock" show isis neighbors 2>/dev/null || true; }
  bfd_a() { "$WREN" --socket "$WORK/a.sock" show bfd 2>/dev/null || true; }

  # Phase 1 — wait (up to ~50s) for the adjacency to come Up AND BFD to come Up.
  up=0
  for _ in $(seq 1 250); do
    if nbr_a | grep -qE "0000.0000.0002 .* state Up" && bfd_a | grep -qE "10\.0\.0\.2 +Up"; then
      up=1; break
    fi
    sleep 0.2
  done
  echo "=== A: show isis neighbors (converged) ==="; nbr_a
  echo "=== A: show bfd (converged) ==="; bfd_a
  if [[ $up -ne 1 ]]; then echo "PHASE1_FAIL" >"$WORK/result.txt"; echo "--- A ---"; cat "$WORK/a.log"; echo "--- B ---"; cat "$WORK/b.log"; kill $BPID 2>/dev/null || true; exit 0; fi

  # Phase 2 — silently blackhole the path: down B is interface.
  t0=$(date +%s%3N)
  nsenter -t $BPID -n ip link set veth1 down

  # Wait for A is IS-IS neighbour to leave Up (the adjacency is removed).
  down_ms=-1
  for _ in $(seq 1 60); do  # up to ~6s
    if ! nbr_a | grep -qE "0000.0000.0002 .* state Up"; then
      down_ms=$(( $(date +%s%3N) - t0 )); break
    fi
    sleep 0.1
  done

  echo "=== A: show isis neighbors (after blackhole) ==="; nbr_a
  echo "=== A: show bfd (after blackhole) ==="; bfd_a
  printf "down_ms=%s\n" "$down_ms" >"$WORK/result.txt"

  kill $BPID 2>/dev/null || true
'

echo "=== result ==="
cat "$WORK/result.txt" 2>/dev/null || { echo "FAIL: no result produced"; exit 1; }

if grep -q "PHASE1_FAIL" "$WORK/result.txt"; then
  echo "FAIL: IS-IS adjacency / BFD did not converge"; exit 1
fi

# shellcheck disable=SC1090
eval "$(cat "$WORK/result.txt")"  # sets down_ms
ok=1
if [[ "${down_ms:--1}" -lt 0 ]]; then
  echo "FAIL: IS-IS neighbour never left Up after the blackhole"; ok=0
elif [[ "$down_ms" -gt 5000 ]]; then
  echo "FAIL: took ${down_ms}ms to drop the adjacency (expected well under a second)"; ok=0
else
  echo "OK: BFD dropped the IS-IS adjacency in ${down_ms}ms (holding time is 9000ms)"
fi

[[ $ok -eq 1 ]] && echo "IS-IS BFD smoke test: OK"
exit $(( ok == 1 ? 0 : 1 ))
