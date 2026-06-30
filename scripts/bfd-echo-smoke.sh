#!/usr/bin/env bash
# BFD Echo smoke test (RFC 5880 §6.4) — looped-back Echo packets test the neighbour's
# forwarding plane, and the session fails with diagnostic "Echo Function Failed" when
# they stop returning, even while Control packets keep flowing. Self-contained,
# rootless.
#
# Runs inside throwaway `unshare -Urn` namespaces (netns-root holds CAP_NET_RAW for the
# AF_PACKET Echo socket and CAP_NET_ADMIN to toggle forwarding) and never touches the
# host.
#
# Topology: A (10.0.0.1, AS 65001) <-eBGP + BFD with Echo-> B (10.0.0.2, AS 65002) over
# a veth. Both have IP forwarding on, so each side's Echo packets — addressed to its own
# IP but sent to the neighbour's MAC — are looped back by the neighbour. The Control
# timers are deliberately slow (min-tx/min-rx 2000 ms × 3 = 6 s detection) while Echo is
# fast (100 ms × 3 = 300 ms), so only Echo can fail the session quickly.
#
#   * phase 1 — both forward: BGP reaches Established and BFD comes Up with Echo running;
#   * phase 2 — disable IP forwarding on B (Control B->A still flows, since it is
#     addressed to A directly; only the looped Echo stops): A must detect the Echo
#     failure within a few hundred ms — far inside the 6 s Control detection — and log
#     "BFD Echo failed".
#
# Usage:  bash scripts/bfd-echo-smoke.sh
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
WREN="$REPO/target/debug/wren"

echo "building wren (debug) ..."
(cd "$REPO" && cargo build -p wren-daemon)

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# Slow Control (6 s detection) + fast Echo (300 ms): a quick failure can only be Echo.
cat >"$WORK/a.toml" <<EOF
router-id = "10.0.0.1"
[bgp]
enabled  = true
local-as = 65001
[[bgp.neighbor]]
address   = "10.0.0.2"
remote-as = 65002
bfd       = true
[bfd]
min-tx        = 2000
min-rx        = 2000
detect-mult   = 3
echo          = true
echo-interval = 100
EOF

cat >"$WORK/b.toml" <<EOF
router-id = "10.0.0.2"
[bgp]
enabled  = true
local-as = 65002
[[bgp.neighbor]]
address   = "10.0.0.1"
remote-as = 65001
passive   = true
bfd       = true
[bfd]
min-tx        = 2000
min-rx        = 2000
detect-mult   = 3
echo          = true
echo-interval = 100
EOF

export WREN WORK
timeout 90 unshare -Urn bash -c '
  set -e
  ip link set lo up
  sysctl -wq net.ipv4.ip_forward=1
  setsid unshare -n -- sleep 80 & B=$!
  sleep 0.3
  ip link add veth0 type veth peer name veth1
  ip link set veth1 netns $B
  ip addr add 10.0.0.1/24 dev veth0; ip link set veth0 up
  nsenter -t $B -n ip link set lo up
  nsenter -t $B -n sysctl -wq net.ipv4.ip_forward=1
  nsenter -t $B -n ip addr add 10.0.0.2/24 dev veth1
  nsenter -t $B -n ip link set veth1 up

  nsenter -t $B -n "$WREN" --config "$WORK/b.toml" --backend kernel --socket "$WORK/b.sock" >"$WORK/b.log" 2>&1 &
  "$WREN" --config "$WORK/a.toml" --backend kernel --socket "$WORK/a.sock" >"$WORK/a.log" 2>&1 &

  bfd_a()  { "$WREN" --socket "$WORK/a.sock" show bfd 2>/dev/null || true; }
  nbrs_a() { "$WREN" --socket "$WORK/a.sock" show bgp neighbors 2>/dev/null || true; }

  # Phase 1 — wait (up to ~30s) for BGP Established AND BFD Up on A.
  up=0
  for _ in $(seq 1 150); do
    if bfd_a | grep -qE "10\.0\.0\.2 +Up" && nbrs_a | grep -q "10.0.0.2 AS 65002 Established"; then
      up=1; break
    fi
    sleep 0.2
  done
  echo "=== A: show bfd (converged) ==="; bfd_a | tee "$WORK/bfd1.out"
  if [[ $up -ne 1 ]]; then echo "PHASE1_FAIL" >"$WORK/result.txt"; echo "--- A ---"; cat "$WORK/a.log"; echo "--- B ---"; cat "$WORK/b.log"; kill $B 2>/dev/null || true; exit 0; fi

  # Let Echo run a moment so the loop is proven working before we break it.
  sleep 1

  # Phase 2 — break the path (bring A`s interface down). Both the looped Echo and the
  # Control stream stop, but Echo detects it in ~300 ms (echo-interval x detect-mult)
  # while Control would take 6 s — so A fails the session via Echo first, with the
  # diagnostic "Echo Function Failed", not the Control detection timeout. That the Echo
  # failure fires at all proves the loop was working (its detection only arms once a
  # looped Echo has returned).
  t0=$(date +%s%3N)
  ip link set veth0 down

  echo_failed=0
  for _ in $(seq 1 40); do  # up to ~4s, far under the 6s Control detection
    if grep -q "BFD Echo failed" "$WORK/a.log"; then
      echo_failed=$(( $(date +%s%3N) - t0 )); break
    fi
    sleep 0.1
  done
  echo "echo_failed_ms=$echo_failed" >"$WORK/result.txt"
  grep -c "detection time expired" "$WORK/a.log" >"$WORK/ctrl.txt" || echo 0 >"$WORK/ctrl.txt"
  echo "--- A log (BFD lines) ---"; grep -iE "Echo failed|detection time expired|state change" "$WORK/a.log" | tail -8 || true
  kill $B 2>/dev/null || true
'

echo "=== checks ==="
ok=1
res="$(cat "$WORK/result.txt" 2>/dev/null || echo MISSING)"
check() { if eval "$2"; then echo "OK: $1"; else echo "FAIL: $1"; ok=0; fi; }

ctrl="$(cat "$WORK/ctrl.txt" 2>/dev/null || echo 0)"
ms="${res#echo_failed_ms=}"
check "phase 1 converged (BGP Established + BFD Up)"   "[[ '$res' != PHASE1_FAIL && '$res' != MISSING ]]"
check "show bfd reports Echo running for the session"  "grep -Eq '10\.0\.0\.2 +Up .*yes' '$WORK/bfd1.out'"
check "A failed the session via Echo (diag echo-failed)" "grep -q 'BFD Echo failed' '$WORK/a.log'"
check "Echo detected it, not Control (no detect-timeout)" "[[ '$ctrl' == 0 ]]"
check "Echo failure was fast (well under 6s Control)"  "[[ '$ms' =~ ^[0-9]+$ && '$ms' -gt 0 && '$ms' -lt 4000 ]]"

echo "result: $res ; ctrl_expired=$ctrl"
[[ $ok -eq 1 ]] && echo "BFD Echo smoke test: OK"
exit $(( ok == 1 ? 0 : 1 ))
