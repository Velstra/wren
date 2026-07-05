#!/usr/bin/env bash
# IGMP querier election (RFC 3376 §6) — two queriers on one segment must elect the
# one with the lowest IP; the other steps down to Non-Querier and stops sending
# General Queries.
#
# Runs inside throwaway `unshare -Urn` namespaces, no sudo. Two Wren daemons act as
# IGMP queriers on a veth: A = 10.0.0.1 (lower) and B = 10.0.0.2 (higher). Each
# sends a startup General Query to 224.0.0.1; both join 224.0.0.1 so they hear each
# other. B sees A's lower-addressed query and yields; A sees B's higher-addressed
# query and stays querier. We assert B logs "yielding querier role" and A does not.
#
# Usage:  bash scripts/igmp-querier-election-smoke.sh
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
[multicast]
enabled = true
query-interval = 5
[[multicast.interface]]
name = "veth0"
role = "querier"
EOF

cat >"$WORK/b.toml" <<EOF
router-id = "10.0.0.2"
[multicast]
enabled = true
query-interval = 5
[[multicast.interface]]
name = "veth1"
role = "querier"
EOF

export WREN WORK
unshare -Urn bash -c '
  set -e
  ip link set lo up
  setsid unshare -n -- sleep 120 & BPID=$!
  sleep 0.3
  ip link add veth0 type veth peer name veth1
  ip link set veth1 netns $BPID
  ip addr add 10.0.0.1/24 dev veth0; ip link set veth0 up
  nsenter -t $BPID -n ip addr add 10.0.0.2/24 dev veth1
  nsenter -t $BPID -n ip link set veth1 up
  nsenter -t $BPID -n ip link set lo up

  RUST_LOG=info nsenter -t $BPID -n "$WREN" --config "$WORK/b.toml" --backend memory --socket "$WORK/b.sock" >"$WORK/b.log" 2>&1 &
  RUST_LOG=info "$WREN" --config "$WORK/a.toml" --backend memory --socket "$WORK/a.sock" >"$WORK/a.log" 2>&1 &

  # Let them exchange a couple of General Queries and run the election.
  sleep 6

  sed -r "s/\x1b\[[0-9;]*m//g" "$WORK/a.log" >"$WORK/a.clean"
  sed -r "s/\x1b\[[0-9;]*m//g" "$WORK/b.log" >"$WORK/b.clean"

  echo "=== A (10.0.0.1) election lines ==="; grep -i "querier role" "$WORK/a.clean" || echo "(none — A stays querier)"
  echo "=== B (10.0.0.2) election lines ==="; grep -i "querier role" "$WORK/b.clean" || true

  ok=1
  grep -Eiq "yielding querier role to lower address .*other=10.0.0.1" "$WORK/b.clean" \
    || { echo "FAIL: B did not step down to the lower-addressed querier A"; ok=0; }
  grep -Eiq "yielding querier role" "$WORK/a.clean" \
    && { echo "FAIL: A (lowest IP) wrongly stepped down"; ok=0; } || true

  if [[ $ok -ne 1 ]]; then echo "--- A log ---"; cat "$WORK/a.log"; echo "--- B log ---"; cat "$WORK/b.log"; fi

  pkill -f "$WORK/a.sock" 2>/dev/null || true
  nsenter -t $BPID -n pkill -f "$WORK/b.sock" 2>/dev/null || true
  kill $BPID 2>/dev/null || true
  exit $(( ok == 1 ? 0 : 1 ))
'
echo "igmp querier election smoke test: OK"
