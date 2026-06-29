#!/usr/bin/env bash
# BFD (RFC 5880) smoke test — a BFD session drives sub-second BGP failover,
# fully self-contained and rootless.
#
# Like the other bgp-*-smoke.sh scripts it runs inside throwaway `unshare -Urn`
# namespaces and never touches the host's interfaces or uplink. Per-daemon control
# sockets live under a temp dir (Unix sockets, not the network).
#
# Topology: A (AS 65001, active) <-eBGP-> B (AS 65002, passive). Both enable
# `bfd = true` on the neighbour and a long BGP hold-time (180 s), so without BFD a
# blackholed path would take ~3 minutes to detect. With `[bfd]` at 200 ms ×3 the
# Detection Time is ~600 ms.
#
# The test:
#   1. brings both BGP sessions Established and the BFD session Up on A;
#   2. silently blackholes the path by downing B's interface (no TCP FIN reaches
#      A, so only BFD — not TCP/hold — can notice);
#   3. asserts A's BFD session goes Down in well under a second, and that A then
#      tears its BGP session to B down (no longer Established) — far faster than the
#      180 s hold timer ever would.
#
# Usage:  bash scripts/bgp-bfd-smoke.sh
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
[bgp]
enabled   = true
local-as  = 65001
hold-time = 180
[[bgp.neighbor]]
address   = "10.0.0.2"
remote-as = 65002
bfd       = true
EOF

cat >"$WORK/b.toml" <<EOF
router-id = "10.0.0.2"
[bfd]
min-tx      = 200
min-rx      = 200
detect-mult = 3
[bgp]
enabled   = true
local-as  = 65002
hold-time = 180
network   = ["10.20.0.0/24"]
[[bgp.neighbor]]
address   = "10.0.0.1"
remote-as = 65001
passive   = true
bfd       = true
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

  bfd_a()  { "$WREN" --socket "$WORK/a.sock" show bfd 2>/dev/null || true; }
  nbrs_a() { "$WREN" --socket "$WORK/a.sock" show bgp neighbors 2>/dev/null || true; }

  # Phase 1 — wait (up to ~25s) for BGP Established AND BFD Up on A.
  up=0
  for _ in $(seq 1 125); do
    if bfd_a | grep -qE "10\.0\.0\.2 +Up" && nbrs_a | grep -q "10.0.0.2 AS 65002 Established"; then
      up=1; break
    fi
    sleep 0.2
  done
  echo "=== A: show bfd (converged) ==="; bfd_a
  echo "=== A: show bgp neighbors (converged) ==="; nbrs_a
  if [[ $up -ne 1 ]]; then echo "PHASE1_FAIL" >"$WORK/result.txt"; echo "--- A ---"; cat "$WORK/a.log"; echo "--- B ---"; cat "$WORK/b.log"; kill $BPID 2>/dev/null || true; exit 0; fi

  # Phase 2 — silently blackhole the path: down B`s interface. No FIN reaches A.
  t0=$(date +%s%3N)
  nsenter -t $BPID -n ip link set veth1 down

  # Wait for A`s BFD session to leave Up (it should go Down within ~Detection Time).
  bfd_down_ms=-1
  for _ in $(seq 1 50); do  # up to ~10s
    if ! bfd_a | grep -qE "10\.0\.0\.2 +Up"; then
      bfd_down_ms=$(( $(date +%s%3N) - t0 )); break
    fi
    sleep 0.1
  done

  # And A should then tear the BGP session down (no longer Established).
  bgp_torn=0
  for _ in $(seq 1 50); do  # up to ~10s
    if ! nbrs_a | grep -q "10.0.0.2 AS 65002 Established"; then bgp_torn=1; break; fi
    sleep 0.1
  done

  echo "=== A: show bfd (after blackhole) ==="; bfd_a
  echo "=== A: show bgp neighbors (after blackhole) ==="; nbrs_a
  printf "bfd_down_ms=%s bgp_torn=%s\n" "$bfd_down_ms" "$bgp_torn" >"$WORK/result.txt"

  kill $BPID 2>/dev/null || true
'

echo "=== result ==="
cat "$WORK/result.txt" 2>/dev/null || { echo "FAIL: no result produced"; exit 1; }

if grep -q "PHASE1_FAIL" "$WORK/result.txt"; then
  echo "FAIL: BGP/BFD did not converge"; exit 1
fi

# shellcheck disable=SC1090
eval "$(cat "$WORK/result.txt")"  # sets bfd_down_ms, bgp_torn
ok=1
if [[ "${bfd_down_ms:--1}" -lt 0 ]]; then
  echo "FAIL: A BFD session never left Up after the blackhole"; ok=0
elif [[ "$bfd_down_ms" -gt 4000 ]]; then
  echo "FAIL: BFD took ${bfd_down_ms}ms to detect the failure (expected well under a second)"; ok=0
else
  echo "OK: BFD detected the blackholed path in ${bfd_down_ms}ms (hold-time is 180000ms)"
fi
if [[ "${bgp_torn:-0}" -ne 1 ]]; then
  echo "FAIL: BGP session to B was not torn down after BFD went down"; ok=0
else
  echo "OK: BGP session to B torn down by BFD (not the hold timer)"
fi

[[ $ok -eq 1 ]] && echo "BFD smoke test: OK"
exit $(( ok == 1 ? 0 : 1 ))
