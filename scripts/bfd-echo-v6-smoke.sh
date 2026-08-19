#!/usr/bin/env bash
# BFD IPv6 Echo smoke test (RFC 5880 §6.4) — the IPv6 sibling of scripts/bfd-echo-smoke.sh.
# Looped-back Echo packets test the neighbour's IPv6 forwarding plane, and the session
# fails with diagnostic "Echo Function Failed" when they stop returning, even while
# Control packets keep flowing. Self-contained, rootless.
#
# Runs inside throwaway `unshare -Urn` namespaces (netns-root holds CAP_NET_RAW for the
# AF_PACKET Echo socket and the RTM_GETNEIGH netlink dump, and CAP_NET_ADMIN to toggle
# forwarding) and never touches the host.
#
# The Echo trick needs the neighbour to forward the looped packet, so it uses **global**
# IPv6 addresses (2001:db8::/64) — link-local traffic is never forwarded, so Echo cannot
# loop over it. The neighbour MAC is resolved from the IPv6 neighbour cache over netlink
# (there is no /proc/net/arp for IPv6).
#
# Topology: A (2001:db8::1, AS 65001) <-eBGP + BFD with Echo over IPv6-> B (2001:db8::2,
# AS 65002) over a veth. Both have IPv6 forwarding on, so each side's Echo packets —
# addressed to its own IPv6 but sent to the neighbour's MAC — are looped back. The
# Control timers are deliberately slow (min-tx/min-rx 2000 ms × 3 = 6 s detection) while
# Echo is fast (100 ms × 3 = 300 ms), so only Echo can fail the session quickly.
#
#   * phase 1 — both forward: BGP reaches Established and BFD comes Up with Echo running;
#   * phase 2 — down A's interface: the looped Echo stops and A must detect the Echo
#     failure within a few hundred ms — far inside the 6 s Control detection — logging
#     "BFD Echo failed".
#
# Usage:  bash scripts/bfd-echo-v6-smoke.sh
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
WREN="$REPO/target/debug/wren"

if [[ ! -x "$WREN" ]]; then
  echo "building wren (debug) ..."
  (cd "$REPO" && cargo build -p wren-daemon)
fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# Slow Control (6 s detection) + fast Echo (300 ms): a quick failure can only be Echo.
cat >"$WORK/a.toml" <<EOF
router-id = "10.0.0.1"
[bgp]
enabled             = true
local-as            = 65001
ebgp-require-policy = false
[[bgp.neighbor]]
address   = "2001:db8::2"
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
enabled             = true
local-as            = 65002
ebgp-require-policy = false
[[bgp.neighbor]]
address   = "2001:db8::1"
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
  sysctl -wq net.ipv6.conf.all.forwarding=1
  setsid unshare -n -- sleep 80 & B=$!
  sleep 0.3
  ip link add veth0 type veth peer name veth1
  ip link set veth1 netns $B
  # nodad: skip Duplicate Address Detection so the addresses are usable at once.
  ip -6 addr add 2001:db8::1/64 dev veth0 nodad; ip link set veth0 up
  nsenter -t $B -n ip link set lo up
  nsenter -t $B -n sysctl -wq net.ipv6.conf.all.forwarding=1
  nsenter -t $B -n ip -6 addr add 2001:db8::2/64 dev veth1 nodad
  nsenter -t $B -n ip link set veth1 up

  nsenter -t $B -n "$WREN" --config "$WORK/b.toml" --backend kernel --socket "$WORK/b.sock" >"$WORK/b.log" 2>&1 &
  "$WREN" --config "$WORK/a.toml" --backend kernel --socket "$WORK/a.sock" >"$WORK/a.log" 2>&1 &

  bfd_a()  { "$WREN" --socket "$WORK/a.sock" show bfd 2>/dev/null || true; }
  nbrs_a() { "$WREN" --socket "$WORK/a.sock" show bgp neighbors 2>/dev/null || true; }

  # Phase 1 — wait (up to ~40s) for BGP Established AND BFD Up on A.
  up=0
  for _ in $(seq 1 200); do
    if bfd_a | grep -qE "2001:db8::2 +Up" && nbrs_a | grep -q "2001:db8::2 AS 65002 Established"; then
      up=1; break
    fi
    sleep 0.2
  done
  echo "=== A: show bfd (converged) ==="; bfd_a | tee "$WORK/bfd1.out"
  if [[ $up -ne 1 ]]; then echo "PHASE1_FAIL" >"$WORK/result.txt"; echo "--- A ---"; cat "$WORK/a.log"; echo "--- B ---"; cat "$WORK/b.log"; kill $B 2>/dev/null || true; exit 0; fi

  # Let Echo run a moment so the loop is proven working before we break it. The Echo
  # detection only arms once a looped Echo has actually returned.
  sleep 1.5

  # Phase 2 — break the path (bring A`s interface down). Both the looped Echo and the
  # Control stream stop, but Echo detects it in ~300 ms while Control would take 6 s.
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
  echo "--- A log (BFD lines) ---"; grep -iE "Echo failed|detection time expired|state change|Echo sent|Echo returned" "$WORK/a.log" | tail -8 || true
  kill $B 2>/dev/null || true
'

echo "=== checks ==="
ok=1
res="$(cat "$WORK/result.txt" 2>/dev/null || echo MISSING)"
check() { if eval "$2"; then echo "OK: $1"; else echo "FAIL: $1"; ok=0; fi; }

ctrl="$(cat "$WORK/ctrl.txt" 2>/dev/null || echo 0)"
ms="${res#echo_failed_ms=}"
check "phase 1 converged (BGP Established + BFD Up over IPv6)" "[[ '$res' != PHASE1_FAIL && '$res' != MISSING ]]"
check "show bfd reports Echo running for the v6 session"       "grep -Eq '2001:db8::2 +Up .*yes' '$WORK/bfd1.out'"
check "A failed the session via Echo (diag echo-failed)"       "grep -q 'BFD Echo failed' '$WORK/a.log'"
check "Echo detected it, not Control (no detect-timeout)"      "[[ '$ctrl' == 0 ]]"
check "Echo failure was fast (well under 6s Control)"          "[[ '$ms' =~ ^[0-9]+$ && '$ms' -gt 0 && '$ms' -lt 4000 ]]"

if [[ $ok -ne 1 ]]; then echo "--- A log ---"; cat "$WORK/a.log" 2>/dev/null | tail -40 || true; fi
[[ $ok -eq 1 ]] || exit 1
echo "BFD IPv6 Echo smoke test: OK"
