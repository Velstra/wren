#!/usr/bin/env bash
# BGP FlowSpec smoke test (RFC 8955) — an originator advertises a flow rule and a
# peer installs it into its FlowSpec RIB. Fully self-contained and rootless.
#
# Like the other bgp-*-smoke.sh scripts it runs inside throwaway `unshare -Urn`
# namespaces and never touches the host's interfaces or uplink. Per-daemon control
# sockets live under a temp dir (Unix sockets, not the network).
#
# Topology — one iBGP AS (65020) on one shared L2 segment:
#
#     Origin (10.0.0.1)  ── br0 (10.0.0.0/24) ──  Peer (10.0.0.2)
#     originates a flow rule            installs it into its FlowSpec RIB
#
# Both sides set `flowspec = true` on the session, so they negotiate SAFI 133. The
# Origin has a `[bgp.flowspec]` rule: match dst 10.50.0.0/24, proto tcp (6), dport 22
# → action discard. The Peer originates nothing; it just receives, installs and shows.
#
# The test asserts, on Peer:
#   * the session to Origin is Established; and
#   * `show bgp flowspec` carries the rule (match components + `discard` action) learned
#     from 10.0.0.1; and
#   * `monitor flowspec` streams that rule as a `+ flowspec ...` line — the feed a
#     forwarding datapath consumes to enforce it. The monitor attaches after the rule
#     was learned, so the line comes from the subscriber snapshot, not a live event.
#
# SCOPE: this exercises the wren side — the FlowSpec RIB, `show` and the monitor feed.
# Enforcing a rule in a forwarding datapath (the fabric eBPF flow classifier) is a
# separate privileged step and is intentionally NOT part of this smoke.
#
# Usage:  bash scripts/bgp-flowspec-smoke.sh
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
WREN="$REPO/target/debug/wren"

if [[ ! -x "$WREN" ]]; then
  echo "building wren (debug) ..."
  (cd "$REPO" && cargo build -p wren-daemon)
fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# Origin (active) — originates one FlowSpec rule to its flowspec-activated peer.
cat >"$WORK/origin.toml" <<EOF
router-id = "10.0.0.1"
[bgp]
enabled  = true
local-as = 65020
[[bgp.neighbor]]
address   = "10.0.0.2"
remote-as = 65020
flowspec  = true
[bgp.flowspec]
[[bgp.flowspec.rule]]
dest      = "10.50.0.0/24"
protocol  = [6]
dest-port = [22]
action    = "discard"
EOF

# Peer (passive) — installs whatever the Origin advertises; originates nothing.
cat >"$WORK/peer.toml" <<EOF
router-id = "10.0.0.2"
[bgp]
enabled  = true
local-as = 65020
[[bgp.neighbor]]
address   = "10.0.0.1"
remote-as = 65020
passive   = true
flowspec  = true
EOF

export WREN WORK
unshare -Urn bash -c '
  set -e
  ip link set lo up
  # Peer lives in its own namespace; Origin is this namespace and hosts the shared
  # L2 bridge both sit on.
  setsid unshare -n -- sleep 120 & PEERPID=$!
  sleep 0.3

  ip link add br0 type bridge
  ip addr add 10.0.0.1/24 dev br0
  ip link set br0 up

  # Peer onto the bridge.
  ip link add veth_p type veth peer name veth_2
  ip link set veth_2 netns $PEERPID
  ip link set veth_p master br0; ip link set veth_p up
  nsenter -t $PEERPID -n ip addr add 10.0.0.2/24 dev veth_2
  nsenter -t $PEERPID -n ip link set veth_2 up
  nsenter -t $PEERPID -n ip link set lo up

  "$WREN" --config "$WORK/origin.toml" --backend kernel --socket "$WORK/origin.sock" >"$WORK/origin.log" 2>&1 &
  nsenter -t $PEERPID -n "$WREN" --config "$WORK/peer.toml" --backend kernel --socket "$WORK/peer.sock" >"$WORK/peer.log" 2>&1 &
  sleep 8

  ok=1
  {
    echo "=== wren show bgp neighbors (on Origin) ==="
    "$WREN" --socket "$WORK/origin.sock" show bgp neighbors || true
    echo "=== wren show bgp flowspec (on Peer) ==="
    nsenter -t $PEERPID -n "$WREN" --socket "$WORK/peer.sock" show bgp flowspec || true
    # The mitigation feed: a 3s snapshot of the monitor stream a forwarding
    # datapath consumes. The Peer must stream the learned rule as a
    # `+ flowspec ...` line, terminated by the snapshot marker.
    echo "=== wren monitor flowspec (on Peer, 3s snapshot) ==="
    timeout 3 nsenter -t $PEERPID -n "$WREN" --socket "$WORK/peer.sock" monitor flowspec || true
  } > "$WORK/out.txt" 2>&1
  cat "$WORK/out.txt"

  grep -q "10.0.0.2 AS 65020 Established"                     "$WORK/out.txt" || { echo "FAIL: Origin-Peer session not Established"; ok=0; }
  # The Peer must have installed the rule with its match components and discard action,
  # learned from the Origin (10.0.0.1). `show bgp flowspec` renders the match first,
  # then `-> discard`, then `from 10.0.0.1`.
  grep -Eq "dst 10.50.0.0/24 proto =6 dport =22 .*-> .*discard .*from 10.0.0.1" "$WORK/out.txt" || { echo "FAIL: Peer did not install the FlowSpec rule from Origin"; ok=0; }
  # The monitor line: the action is a compact token BEFORE the variable-length
  # match section, which is what makes the feed machine-parseable.
  grep -Eq "^\+ flowspec action discard match dst 10.50.0.0/24 proto =6 dport =22" "$WORK/out.txt" || { echo "FAIL: monitor flowspec did not stream the rule"; ok=0; }
  grep -q "% end-of-dump" "$WORK/out.txt" || { echo "FAIL: monitor flowspec snapshot not terminated"; ok=0; }

  if [[ $ok -ne 1 ]]; then
    echo "--- Origin log ---"; cat "$WORK/origin.log"
    echo "--- Peer log ---";   cat "$WORK/peer.log"
  fi
  kill $PEERPID 2>/dev/null || true
  exit $(( ok == 1 ? 0 : 1 ))
'
echo "bgp flowspec smoke test: OK"
