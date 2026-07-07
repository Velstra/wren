#!/usr/bin/env bash
# BGP per-neighbour session-option smoke test. Exercises the per-neighbour knobs that
# mirror FRR/IOS `neighbor` sub-commands, all set on one side of a two-router eBGP
# session and observed from both ends:
#
#   * local-as       — R1 overrides its AS for this session only (global 65001 → 65099).
#                      R2 is configured with `remote-as = 65099`, so the session
#                      establishes ONLY because R1's OPEN carried the overridden My-AS
#                      (a My-AS of 65001 would be rejected as an AS mismatch) — that is
#                      the proof the override reached the wire.
#   * update-source  — R1 binds its dialled connection to a secondary address (10.0.0.11)
#                      on its veth; R2 knows R1 by that address, so the session that comes
#                      up is the one sourced from it.
#   * hold-time      — R1 proposes 30s, R2 proposes 90s → the negotiated Hold is 30s,
#                      shown as `hold 30` in `show bgp neighbors` on both ends.
#   * description    — R1 labels the neighbour; it appears in `show bgp neighbors`.
#   * shutdown       — a second phase restarts R1 with `shutdown = true` on the neighbour:
#                      R1 never initiates and refuses R2's inbound, the session stays
#                      down, and R1 shows the neighbour as `admin-shutdown`.
#
# Like the other *-smoke.sh scripts it runs inside throwaway `unshare -Urn` namespaces
# and never touches the host's interfaces or uplink. BGP binds TCP 179
# (CAP_NET_BIND_SERVICE), which the netns-root holds. Rootless, no sudo.
#
# Topology: R1 (10.0.0.1, plus secondary 10.0.0.11) and R2 (10.0.0.2), directly
# connected by a veth — a one-hop eBGP session.
#
# Usage:  bash scripts/bgp-neighbor-opts-smoke.sh
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
# Honour CARGO_TARGET_DIR so the binary built in an out-of-tree target dir is reused;
# fall back to the in-tree target/ like the sibling smoke scripts.
TARGET_DIR="${CARGO_TARGET_DIR:-$REPO/target}"
WREN="$TARGET_DIR/debug/wren"

if [[ ! -x "$WREN" ]]; then
  echo "building wren (debug) ..."
  (cd "$REPO" && cargo build -p wren-daemon)
fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# R1 (global AS 65001) peers with R2 at 10.0.0.2, overriding its AS to 65099 for the
# session, sourcing the connection from its secondary 10.0.0.11, proposing a 30s Hold,
# and labelling the neighbour. `$1` is the neighbour's shutdown line (empty or set).
write_r1() {  # $1 = extra neighbour line, $2 = tag
  cat >"$WORK/r1_$2.toml" <<EOF
router-id = "10.0.0.1"
[bgp]
enabled  = true
local-as = 65001
[[bgp.neighbor]]
address       = "10.0.0.2"
remote-as     = 65002
local-as      = 65099
update-source = "10.0.0.11"
hold-time     = 30
description   = "R2 transit uplink"
$1
EOF
}
# R2 (AS 65002) peers with R1 by its update-source address 10.0.0.11, and expects R1's
# OVERRIDDEN AS (65099) — not R1's real 65001. Proposes a 90s Hold (so the negotiated
# value is R1's lower 30s).
write_r2() {  # $1 = tag
  cat >"$WORK/r2_$1.toml" <<EOF
router-id = "10.0.0.2"
[bgp]
enabled  = true
local-as = 65002
[[bgp.neighbor]]
address   = "10.0.0.11"
remote-as = 65099
hold-time = 90
EOF
}

write_r1 ''                 up
write_r1 'shutdown = true'  down
write_r2 up
write_r2 down

export WREN WORK
unshare -Urn bash -c '
  set -e
  ip link set lo up
  setsid unshare -n -- sleep 300 & BPID=$!
  sleep 0.3
  ip link add veth0 type veth peer name veth1
  ip link set veth1 netns $BPID
  ip addr add 10.0.0.1/24 dev veth0
  ip addr add 10.0.0.11/24 dev veth0   # secondary: R1s update-source
  ip link set veth0 up
  nsenter -t $BPID -n ip addr add 10.0.0.2/24 dev veth1
  nsenter -t $BPID -n ip link set veth1 up
  nsenter -t $BPID -n ip link set lo up

  run_phase() {
    tag="$1"
    nsenter -t $BPID -n "$WREN" --config "$WORK/r2_$tag.toml" --backend kernel --socket "$WORK/r2.sock" >"$WORK/r2_$tag.log" 2>&1 &
    "$WREN" --config "$WORK/r1_$tag.toml" --backend kernel --socket "$WORK/r1.sock" >"$WORK/r1_$tag.log" 2>&1 &
    sleep 20
    "$WREN" --socket "$WORK/r1.sock" show bgp neighbors >"$WORK/${tag}_r1_neigh.txt" 2>&1 || true
    nsenter -t $BPID -n "$WREN" --socket "$WORK/r2.sock" show bgp neighbors >"$WORK/${tag}_r2_neigh.txt" 2>&1 || true
    pkill -f "$WORK/r1.sock" 2>/dev/null || true
    nsenter -t $BPID -n pkill -f "$WORK/r2.sock" 2>/dev/null || true
    sleep 1
  }

  run_phase up
  run_phase down
  kill $BPID 2>/dev/null || true
'

for tag in up down; do
  echo "=== phase $tag: R1 show bgp neighbors ==="; cat "$WORK/${tag}_r1_neigh.txt"
  echo "=== phase $tag: R2 show bgp neighbors ==="; cat "$WORK/${tag}_r2_neigh.txt"
done

ok=1

# --- phase up: the session establishes with every option in effect. ---
# If even this fails, print the logs to aid diagnosis and fail hard.
if ! grep -q "Established" "$WORK/up_r1_neigh.txt"; then
  echo "NOTE: the session did not establish; R1 log follows"
  cat "$WORK/r1_up.log" 2>/dev/null || true
  echo "--- R2 log ---"; cat "$WORK/r2_up.log" 2>/dev/null || true
  exit 1
fi

# R1: neighbour Established, the negotiated Hold is 30s (min of 30/90), and the
# description shows.
grep -Eq '10\.0\.0\.2 AS 65002 Established hold 30 .*"R2 transit uplink"' "$WORK/up_r1_neigh.txt" \
  || { echo "FAIL: R1 neighbour line missing Established / hold 30 / description"; ok=0; }

# R2: it established with R1 under the OVERRIDDEN AS 65099 (proof local-as reached the
# OPEN), and sees the same negotiated Hold of 30s.
grep -Eq '10\.0\.0\.11 AS 65099 Established hold 30' "$WORK/up_r2_neigh.txt" \
  || { echo "FAIL: R2 did not establish with R1 under the overridden AS 65099 / hold 30"; ok=0; }

# --- phase down: R1 admin-shutdown → no session, shown as admin-shutdown on R1. ---
grep -Eq '10\.0\.0\.2 AS 65002 admin-shutdown' "$WORK/down_r1_neigh.txt" \
  || { echo "FAIL: R1 neighbour is not shown admin-shutdown after shutdown = true"; ok=0; }
if grep -q "Established" "$WORK/down_r1_neigh.txt"; then
  echo "FAIL: R1 established a session despite shutdown = true"; ok=0
fi
# R2 keeps trying but R1 refuses/never dials, so R2 stays down (not Established).
if grep -q "Established" "$WORK/down_r2_neigh.txt"; then
  echo "FAIL: R2 established with an admin-shutdown R1"; ok=0
fi

[[ $ok -eq 1 ]] || exit 1
echo "bgp per-neighbour session-options smoke test: OK"
