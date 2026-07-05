#!/usr/bin/env bash
# MLDv2 querier (RFC 3810) — the IPv6 sibling of igmp-querier-smoke.sh. A live
# end-to-end check that a Wren MLDv2 querier hears a host's Multicast Listener
# Report and records the IPv6 group in its per-interface membership table.
#
# Runs inside throwaway `unshare -Urn` namespaces, no sudo. MLD uses a raw
# IPPROTO_ICMPV6 socket, which needs CAP_NET_RAW — held by the netns-root inside
# `unshare -Urn` (same as the vrrp6 smoke).
#
# Topology: A (the MLD querier) <--veth--> B (a host). A runs `wren` with a
# `[multicast]` MLD querier on veth0; B joins the IPv6 group ff15::1234 with the
# `wren mcast-join` helper, which makes B's kernel emit a genuine MLDv2 report to
# ff02::16. A joins ff02::16, receives the report, feeds it into its membership
# table and logs "MLD membership joined". We assert that log line names the group.
#
# Usage:  bash scripts/mld-querier-smoke.sh
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
WREN="$REPO/target/debug/wren"
GROUP="ff15::1234"

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
igmp = false
mld = true
query-interval = 4
query-response-interval = 2
[[multicast.interface]]
name = "veth0"
role = "querier"
EOF

export WREN WORK GROUP
unshare -Urn bash -c '
  set -e
  # Make IPv6 link-local addresses usable immediately (skip DAD delay).
  sysctl -wq net.ipv6.conf.all.dad_transmits=0 2>/dev/null || true
  sysctl -wq net.ipv6.conf.default.dad_transmits=0 2>/dev/null || true
  ip link set lo up
  setsid unshare -n -- sleep 120 & BPID=$!
  sleep 0.3
  nsenter -t $BPID -n sysctl -wq net.ipv6.conf.all.dad_transmits=0 2>/dev/null || true
  ip link add veth0 type veth peer name veth1
  ip link set veth1 netns $BPID
  ip link set veth0 up
  nsenter -t $BPID -n ip link set veth1 up
  nsenter -t $BPID -n ip link set lo up

  # Let IPv6 link-local addresses come up on both ends.
  sleep 2

  # A: the MLD querier.
  RUST_LOG=info "$WREN" --config "$WORK/a.toml" --backend memory --socket "$WORK/a.sock" >"$WORK/a.log" 2>&1 &
  APID=$!
  sleep 2

  # B: join the IPv6 group — B'\''s kernel now emits MLDv2 reports for it.
  nsenter -t $BPID -n "$WREN" mcast-join "$GROUP" --iface veth1 >"$WORK/b.log" 2>&1 &
  BJOIN=$!

  # Give the report(s) time to reach A and be processed.
  sleep 8

  # Strip ANSI colour codes so the assertions match plain text.
  sed -r "s/\x1b\[[0-9;]*m//g" "$WORK/a.log" >"$WORK/a.clean"

  echo "=== A querier log (membership lines) ==="
  grep -i "MLD membership" "$WORK/a.clean" || true

  ok=1
  grep -Eiq "MLD membership joined .*group=$GROUP" "$WORK/a.clean" \
    || { echo "FAIL: MLD querier A did not record group $GROUP"; ok=0; }

  if [[ $ok -ne 1 ]]; then echo "--- full A log ---"; cat "$WORK/a.log"; echo "--- B log ---"; cat "$WORK/b.log"; fi

  kill $BJOIN 2>/dev/null || true
  kill $APID  2>/dev/null || true
  kill $BPID  2>/dev/null || true
  exit $(( ok == 1 ? 0 : 1 ))
'
echo "mld querier smoke test: OK"
