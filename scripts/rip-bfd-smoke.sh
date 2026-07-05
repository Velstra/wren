#!/usr/bin/env bash
# RIP + BFD (RFC 5880) smoke test — a BFD session drives sub-second RIP route
# teardown instead of the 180-second route timeout. Self-contained, rootless.
#
# Like the other *-bfd-smoke.sh scripts it runs inside throwaway `unshare -Urn`
# namespaces and never touches the host's interfaces or uplink. Per-daemon control
# sockets live under a temp dir (Unix sockets, not the network).
#
# Topology: A (10.0.0.1) <--RIP, veth--> B (10.0.0.2). Each also owns a dummy
# network (A: 10.10.0.0/24, B: 10.20.0.0/24) it advertises over RIP, so each learns
# a route through the other and both register a BFD session to their gateway.
#
# The test:
#   1. brings RIP converged (A learns 10.20.0.0/24 via B) and the BFD session Up;
#   2. silently blackholes the path by downing B's interface (no RIP poison reaches
#      A, so only BFD — not the 180 s route timeout — can notice);
#   3. asserts A's BFD session goes Down in well under a second, and that A then
#      expires its RIP route to 10.20.0.0/24 (`show rip` reports it unreachable) —
#      far faster than the 180 s route timeout.
#
# The assertion reads RIP's own route table (`show rip`), not the kernel FIB: like
# the BGP-BFD smoke checks session state rather than routes, this isolates the
# protocol-layer teardown from unrelated netlink behaviour (deleting a route whose
# link just went down returns ESRCH and is retried).
#
# Usage:  bash scripts/rip-bfd-smoke.sh
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
[bfd]
min-tx      = 200
min-rx      = 200
detect-mult = 3
[rip]
enabled    = true
interfaces = ["veth0", "dummy0"]
bfd        = true
EOF

cat >"$WORK/b.toml" <<EOF
router-id = "10.0.0.2"
[bfd]
min-tx      = 200
min-rx      = 200
detect-mult = 3
[rip]
enabled    = true
interfaces = ["veth1", "dummy0"]
bfd        = true
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
  ip link add dummy0 type dummy; ip addr add 10.10.0.1/24 dev dummy0; ip link set dummy0 up
  nsenter -t $BPID -n ip addr add 10.0.0.2/24 dev veth1
  nsenter -t $BPID -n ip link set veth1 up
  nsenter -t $BPID -n ip link set lo up
  nsenter -t $BPID -n ip link add dummy0 type dummy
  nsenter -t $BPID -n ip addr add 10.20.0.1/24 dev dummy0
  nsenter -t $BPID -n ip link set dummy0 up

  nsenter -t $BPID -n "$WREN" --config "$WORK/b.toml" --backend kernel --socket "$WORK/b.sock" >"$WORK/b.log" 2>&1 &
  "$WREN" --config "$WORK/a.toml" --backend kernel --socket "$WORK/a.sock" >"$WORK/a.log" 2>&1 &

  bfd_a()   { "$WREN" --socket "$WORK/a.sock" show bfd 2>/dev/null || true; }
  rip_a()   { "$WREN" --socket "$WORK/a.sock" show rip 2>/dev/null || true; }

  # Phase 1 — wait (up to ~30s) for A to learn 10.20.0.0/24 reachable AND BFD Up.
  up=0
  for _ in $(seq 1 150); do
    if bfd_a | grep -qE "10\.0\.0\.2 +Up" && rip_a | grep -qE "10\.20\.0\.0/24 .* metric [0-9]"; then
      up=1; break
    fi
    sleep 0.2
  done
  echo "=== A: show bfd (converged) ==="; bfd_a
  echo "=== A: show rip (converged) ==="; rip_a
  if [[ $up -ne 1 ]]; then echo "PHASE1_FAIL" >"$WORK/result.txt"; echo "--- A ---"; tail -20 "$WORK/a.log"; echo "--- B ---"; tail -20 "$WORK/b.log"; kill $BPID 2>/dev/null || true; exit 0; fi

  # Phase 2 — silently blackhole the path: down B`s interface. No RIP poison reaches A.
  t0=$(date +%s%3N)
  nsenter -t $BPID -n ip link set veth1 down

  # A`s BFD session should leave Up within ~Detection Time.
  bfd_down_ms=-1
  for _ in $(seq 1 60); do  # up to ~12s
    if ! bfd_a | grep -qE "10\.0\.0\.2 +Up"; then
      bfd_down_ms=$(( $(date +%s%3N) - t0 )); break
    fi
    sleep 0.1
  done

  # And A should then expire its RIP route to 10.20.0.0/24 (BFD-driven, → unreachable).
  route_gone=0
  for _ in $(seq 1 60); do  # up to ~12s
    if rip_a | grep -qE "10\.20\.0\.0/24 .* metric unreachable"; then route_gone=1; break; fi
    sleep 0.1
  done

  echo "=== A: show bfd (after blackhole) ==="; bfd_a
  echo "=== A: show rip (after blackhole) ==="; rip_a
  printf "bfd_down_ms=%s route_gone=%s\n" "$bfd_down_ms" "$route_gone" >"$WORK/result.txt"

  kill $BPID 2>/dev/null || true
'

echo "=== result ==="
cat "$WORK/result.txt" 2>/dev/null || { echo "FAIL: no result produced"; exit 1; }

if grep -q "PHASE1_FAIL" "$WORK/result.txt"; then
  echo "FAIL: RIP/BFD did not converge"; exit 1
fi

# shellcheck disable=SC1090
eval "$(cat "$WORK/result.txt")"  # sets bfd_down_ms, route_gone
ok=1
if [[ "${bfd_down_ms:--1}" -lt 0 ]]; then
  echo "FAIL: A BFD session never left Up after the blackhole"; ok=0
elif [[ "$bfd_down_ms" -gt 4000 ]]; then
  echo "FAIL: BFD took ${bfd_down_ms}ms to detect the failure (expected well under a second)"; ok=0
else
  echo "OK: BFD detected the blackholed path in ${bfd_down_ms}ms (route timeout is 180000ms)"
fi
if [[ "${route_gone:-0}" -ne 1 ]]; then
  echo "FAIL: RIP route to 10.20.0.0/24 was not dropped after BFD went down"; ok=0
else
  echo "OK: RIP route to 10.20.0.0/24 expired by BFD (not the 180 s timeout)"
fi

[[ $ok -eq 1 ]] && echo "RIP BFD smoke test: OK"
exit $(( ok == 1 ? 0 : 1 ))
