#!/usr/bin/env bash
# Per-session BFD authentication (RFC 5880 §6.7) smoke test — one router runs two BFD
# sessions with *different* keys (and different algorithms), proving the key is
# per-session, not one global key for the whole box. Self-contained, rootless.
#
# Runs inside throwaway `unshare -Urn` namespaces and never touches the host's
# interfaces or uplink. Three daemons over two veth links:
#
#     B (65002) ---10.0.1.0/24--- A (65001) ---10.0.2.0/24--- C (65003)
#
# A peers both B and C over eBGP with `bfd = true`, but a distinct per-neighbour key:
#   * to B — `meticulous-sha1`, key "key-for-bee";
#   * to C — `keyed-md5`,       key "key-for-cee".
# B and C are each configured with their matching key. Both BFD sessions must reach
# **Up** on A — which can only happen if A authenticates each session with its own
# key. (A wrong/global-only key would leave at least one session stuck Down.)
#
# Usage:  bash scripts/bfd-auth-per-session-smoke.sh
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
enabled  = true
local-as = 65001
[[bgp.neighbor]]
address       = "10.0.1.2"
remote-as     = 65002
bfd           = true
bfd-auth-type = "meticulous-sha1"
bfd-auth-key  = "key-for-bee"
[[bgp.neighbor]]
address       = "10.0.2.2"
remote-as     = 65003
bfd           = true
bfd-auth-type = "keyed-md5"
bfd-auth-key  = "key-for-cee"
EOF

cat >"$WORK/b.toml" <<EOF
router-id = "10.0.0.2"
[bfd]
min-tx      = 200
min-rx      = 200
detect-mult = 3
[bgp]
enabled  = true
local-as = 65002
[[bgp.neighbor]]
address       = "10.0.1.1"
remote-as     = 65001
bfd           = true
bfd-auth-type = "meticulous-sha1"
bfd-auth-key  = "key-for-bee"
EOF

cat >"$WORK/c.toml" <<EOF
router-id = "10.0.0.3"
[bfd]
min-tx      = 200
min-rx      = 200
detect-mult = 3
[bgp]
enabled  = true
local-as = 65003
[[bgp.neighbor]]
address       = "10.0.2.1"
remote-as     = 65001
bfd           = true
bfd-auth-type = "keyed-md5"
bfd-auth-key  = "key-for-cee"
EOF

export WREN WORK
timeout 120 unshare -Urn bash -c '
  set -e
  ip link set lo up
  setsid unshare -n -- sleep 110 & B=$!
  setsid unshare -n -- sleep 110 & C=$!
  sleep 0.3
  ip link add vab type veth peer name vba
  ip link add vac type veth peer name vca
  ip link set vba netns $B
  ip link set vca netns $C
  ip addr add 10.0.1.1/24 dev vab; ip link set vab up
  ip addr add 10.0.2.1/24 dev vac; ip link set vac up
  nsenter -t $B -n ip addr add 10.0.1.2/24 dev vba; nsenter -t $B -n ip link set vba up; nsenter -t $B -n ip link set lo up
  nsenter -t $C -n ip addr add 10.0.2.2/24 dev vca; nsenter -t $C -n ip link set vca up; nsenter -t $C -n ip link set lo up

  nsenter -t $B -n "$WREN" --config "$WORK/b.toml" --backend kernel --socket "$WORK/b.sock" >"$WORK/b.log" 2>&1 &
  nsenter -t $C -n "$WREN" --config "$WORK/c.toml" --backend kernel --socket "$WORK/c.sock" >"$WORK/c.log" 2>&1 &
  "$WREN" --config "$WORK/a.toml" --backend kernel --socket "$WORK/a.sock" >"$WORK/a.log" 2>&1 &

  bfd_a() { "$WREN" --socket "$WORK/a.sock" show bfd 2>/dev/null || true; }

  # Wait (up to ~40s) for BOTH sessions to come Up on A.
  both=0
  for _ in $(seq 1 200); do
    if bfd_a | grep -qE "10\.0\.1\.2 +Up" && bfd_a | grep -qE "10\.0\.2\.2 +Up"; then both=1; break; fi
    sleep 0.2
  done
  echo "=== A: show bfd ==="; bfd_a
  echo "both_up=$both" >"$WORK/result.txt"
  if [[ $both -ne 1 ]]; then echo "--- A ---"; cat "$WORK/a.log"; echo "--- B ---"; cat "$WORK/b.log"; echo "--- C ---"; cat "$WORK/c.log"; fi
  kill $B $C 2>/dev/null || true
'

echo "=== result ==="
cat "$WORK/result.txt" 2>/dev/null || { echo "FAIL: no result produced"; exit 1; }

# shellcheck disable=SC1090
eval "$(grep -E '^both_up=' "$WORK/result.txt")"
if [[ "${both_up:-0}" -ne 1 ]]; then
  echo "FAIL: not both per-session-authenticated BFD sessions came Up"; exit 1
fi
echo "OK: two BFD sessions with different keys/algorithms both Up (per-session auth)"
echo "BFD per-session auth smoke test: OK"
