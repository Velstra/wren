#!/usr/bin/env bash
# IGMP querier (RFC 3376) — a live end-to-end check that a Wren IGMPv3 querier
# hears a host's membership report and records the group in its per-interface
# membership table.
#
# Like the other smoke scripts it runs inside throwaway `unshare -Urn` namespaces
# and never touches the host's interfaces or uplink. IGMP uses a raw IPPROTO_IGMP
# (2) socket, which needs CAP_NET_RAW — held by the netns-root inside `unshare
# -Urn`. No sudo, no second daemon.
#
# Topology: A (the querier) <--veth--> B (a host). A runs `wren` with a
# `[multicast]` querier on veth0; B joins group 239.1.2.3 with the `wren
# mcast-join` helper, which makes B's kernel emit a genuine IGMPv3 membership
# report to 224.0.0.22. A joins 224.0.0.22, receives the report, feeds it into its
# membership table and logs "IGMP membership joined". We assert that log line names
# the group.
#
# Usage:  bash scripts/igmp-querier-smoke.sh
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
WREN="$REPO/target/debug/wren"
GROUP="239.1.2.3"

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
# Query fast so the querier prods the host promptly (the host also reports
# unsolicited on join, so this is belt-and-braces).
query-interval = 4
query-response-interval = 2
[[multicast.interface]]
name = "veth0"
role = "querier"
EOF

export WREN WORK GROUP
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

  # A: the querier.
  RUST_LOG=info "$WREN" --config "$WORK/a.toml" --backend memory --socket "$WORK/a.sock" >"$WORK/a.log" 2>&1 &
  APID=$!
  # Let the querier open its socket and send the startup General Query.
  sleep 2

  # B: join the group — B'\''s kernel now emits IGMPv3 reports for it.
  nsenter -t $BPID -n "$WREN" mcast-join "$GROUP" --iface veth1 >"$WORK/b.log" 2>&1 &
  BJOIN=$!

  # Give the report(s) time to reach A and be processed (unsolicited reports are
  # spaced ~1s apart; the periodic query is every 4s).
  sleep 8

  # Strip ANSI colour codes tracing may emit so the assertions match plain text.
  sed -r "s/\x1b\[[0-9;]*m//g" "$WORK/a.log" >"$WORK/a.clean"

  echo "=== A querier log (membership lines) ==="
  grep -i "IGMP membership" "$WORK/a.clean" || true

  ok=1
  grep -Eq "IGMP membership joined .*group=$GROUP" "$WORK/a.clean" \
    || { echo "FAIL: querier A did not record group $GROUP"; ok=0; }

  if [[ $ok -ne 1 ]]; then echo "--- full A log ---"; cat "$WORK/a.log"; echo "--- B log ---"; cat "$WORK/b.log"; fi

  kill $BJOIN 2>/dev/null || true
  kill $APID  2>/dev/null || true
  nsenter -t $BPID -n true 2>/dev/null || true
  kill $BPID  2>/dev/null || true
  exit $(( ok == 1 ? 0 : 1 ))
'
echo "igmp querier smoke test: OK"
