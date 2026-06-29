#!/usr/bin/env bash
# BFD authentication (RFC 5880 §6.7) smoke test — a Meticulous Keyed SHA1 session
# comes Up only when both ends share the key, and a mismatched key is rejected.
# Self-contained, rootless.
#
# Runs inside throwaway `unshare -Urn` namespaces and never touches the host's
# interfaces or uplink. The two routers run OSPFv2 (point-to-point) with BFD enabled,
# so a BFD session is brought up to the Full neighbour; OSPF and BFD use raw sockets
# that work as the netns-root inside `unshare -Urn` (which grants CAP_NET_RAW).
#
# Topology: A (10.0.0.1) <--OSPF point-to-point--> B (10.0.0.2) over a veth.
#   * Phase 1 — A and B share `auth-key = "correct horse"`: A's BFD session to B must
#     reach **Up** (the authenticated handshake succeeds).
#   * Phase 2 — B is restarted with a *different* key: A's BFD session must NOT reach
#     Up (every packet from B fails authentication and is discarded).
#
# Usage:  bash scripts/bfd-auth-smoke.sh
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
WREN="$REPO/target/debug/wren"

echo "building wren (debug) ..."
(cd "$REPO" && cargo build -p wren-daemon)

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# A is identical across both phases: OSPF p2p + BFD with the "correct" key.
cat >"$WORK/a.toml" <<EOF
router-id = "10.0.0.1"
[bfd]
min-tx      = 200
min-rx      = 200
detect-mult = 3
auth-type   = "meticulous-sha1"
auth-key-id = 1
auth-key    = "correct horse"
[ospf]
enabled = true
interfaces = ["veth0"]
network-type = "point-to-point"
bfd = true
EOF

# B phase 1: the matching key.
cat >"$WORK/b-match.toml" <<EOF
router-id = "10.0.0.2"
[bfd]
min-tx      = 200
min-rx      = 200
detect-mult = 3
auth-type   = "meticulous-sha1"
auth-key-id = 1
auth-key    = "correct horse"
[ospf]
enabled = true
interfaces = ["veth1"]
network-type = "point-to-point"
bfd = true
EOF

# B phase 2: a different key — A must reject every packet.
sed 's/correct horse/battery staple/' "$WORK/b-match.toml" >"$WORK/b-wrong.toml"

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

  bfd_a() { "$WREN" --socket "$WORK/a.sock" show bfd 2>/dev/null || true; }

  run_phase() {
    bcfg="$1"
    nsenter -t $BPID -n "$WREN" --config "$bcfg" --backend kernel --socket "$WORK/b.sock" >"$WORK/b.log" 2>&1 &
    "$WREN" --config "$WORK/a.toml" --backend kernel --socket "$WORK/a.sock" >"$WORK/a.log" 2>&1 &
    up=0
    for _ in $(seq 1 200); do  # up to ~40s
      if bfd_a | grep -qE "10\.0\.0\.2 +Up"; then up=1; break; fi
      sleep 0.2
    done
    echo "$up"
    pkill -f "$WORK/a.sock" 2>/dev/null || true
    nsenter -t $BPID -n pkill -f "$WORK/b.sock" 2>/dev/null || true
    sleep 1
  }

  # Phase 1 — matching keys: BFD must come Up.
  p1=$(run_phase "$WORK/b-match.toml")
  echo "=== phase 1 (matching key): bfd ==="; bfd_a
  echo "match_up=$p1" >"$WORK/result.txt"

  # Phase 2 — mismatched key: BFD must NOT come Up.
  p2=$(run_phase "$WORK/b-wrong.toml")
  echo "=== phase 2 (mismatched key): bfd ==="; bfd_a
  echo "mismatch_up=$p2" >>"$WORK/result.txt"

  kill $BPID 2>/dev/null || true
'

echo "=== result ==="
cat "$WORK/result.txt" 2>/dev/null || { echo "FAIL: no result produced"; exit 1; }

# shellcheck disable=SC1090
eval "$(grep -E '^(match_up|mismatch_up)=' "$WORK/result.txt")"
ok=1
if [[ "${match_up:-0}" -ne 1 ]]; then
  echo "FAIL: authenticated BFD session did not come Up with matching keys"; ok=0
else
  echo "OK: matching keys → BFD session Up (authenticated)"
fi
if [[ "${mismatch_up:-1}" -ne 0 ]]; then
  echo "FAIL: BFD came Up despite a mismatched key (authentication not enforced)"; ok=0
else
  echo "OK: mismatched key → BFD session rejected (never Up)"
fi

[[ $ok -eq 1 ]] && echo "BFD auth smoke test: OK"
exit $(( ok == 1 ? 0 : 1 ))
