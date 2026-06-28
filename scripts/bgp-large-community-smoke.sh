#!/usr/bin/env bash
# BGP large communities (RFC 8092) — the 12-octet LARGE_COMMUNITY attribute,
# attached both globally (to every originated network via `[bgp] large-community`)
# and per-prefix (via an `[export] bgp` filter's `set-large-community`). This
# exercises the wire codec end to end: a peer must receive each prefix carrying
# the large community it was tagged with. Self-contained and rootless.
#
# Like the other bgp-*-smoke.sh scripts it runs inside throwaway `unshare -Urn`
# namespaces and never touches the host's interfaces or uplink. Per-daemon
# control sockets live under a temp dir (Unix sockets, not the network).
#
# Topology: A (AS 65001, active) <-eBGP-> B (AS 65002, passive). A originates one
# network with a global large community, and redistributes a static through an
# export filter that stamps a per-prefix large community:
#   * 10.10.0.0/24 -> [bgp] large-community = ["65001:1:1"]   (global)
#   * 10.99.0.0/24 -> set-large-community ["65001:7:7"]       (per-prefix filter)
#
# One phase proves both paths:
#   * B must learn 10.10.0.0/24 WITH `large-communities 65001:1:1`;
#   * B must learn 10.99.0.0/24 WITH `large-communities 65001:7:7`.
#
# Usage:  bash scripts/bgp-large-community-smoke.sh
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
WREN="$REPO/target/debug/wren"

if [[ ! -x "$WREN" ]]; then
  echo "building wren (debug) ..."
  (cd "$REPO" && cargo build -p wren-daemon)
fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

cat >"$WORK/b.toml" <<EOF
router-id = "10.0.0.2"
[bgp]
enabled   = true
local-as  = 65002
[[bgp.neighbor]]
address   = "10.0.0.1"
remote-as = 65001
passive   = true
EOF

cat >"$WORK/a.toml" <<EOF
router-id = "10.0.0.1"
[[static]]
prefix = "10.99.0.0/24"
via    = "10.0.0.2"
[bgp]
enabled         = true
local-as        = 65001
network         = ["10.10.0.0/24"]
large-community = ["65001:1:1"]
redistribute    = ["static"]
[[bgp.neighbor]]
address   = "10.0.0.2"
remote-as = 65002
[export]
bgp = "tag"
[[filter]]
name    = "tag"
default = "accept"
[[filter.rule]]
prefix              = ["10.99.0.0/24"]
set-large-community = ["65001:7:7"]
action              = "accept"
EOF

export WREN WORK
unshare -Urn bash -c '
  set -e
  ip link set lo up
  setsid unshare -n -- sleep 60 & BPID=$!
  sleep 0.3
  ip link add veth0 type veth peer name veth1
  ip link set veth1 netns $BPID
  ip addr add 10.0.0.1/24 dev veth0; ip link set veth0 up
  nsenter -t $BPID -n ip addr add 10.0.0.2/24 dev veth1
  nsenter -t $BPID -n ip link set veth1 up
  nsenter -t $BPID -n ip link set lo up

  nsenter -t $BPID -n "$WREN" --config "$WORK/b.toml" --backend kernel --socket "$WORK/b.sock" >"$WORK/b.log" 2>&1 &
  "$WREN" --config "$WORK/a.toml" --backend kernel --socket "$WORK/a.sock" >"$WORK/a.log" 2>&1 &
  sleep 6

  echo "=== wren show bgp routes (on B) ==="
  nsenter -t $BPID -n "$WREN" --socket "$WORK/b.sock" show bgp routes 2>&1 | tee "$WORK/b.out" || true

  ok=1
  grep -q "10.10.0.0/24 via 10.0.0.1 .*large-communities 65001:1:1" "$WORK/b.out" \
    || { echo "FAIL: 10.10.0.0/24 missing global large-community 65001:1:1"; ok=0; }
  grep -q "10.99.0.0/24 via 10.0.0.1 .*large-communities 65001:7:7" "$WORK/b.out" \
    || { echo "FAIL: 10.99.0.0/24 missing per-prefix large-community 65001:7:7"; ok=0; }

  if [[ $ok -ne 1 ]]; then echo "--- A log ---"; cat "$WORK/a.log"; echo "--- B log ---"; cat "$WORK/b.log"; fi
  pkill -f "$WORK/a.sock" 2>/dev/null || true
  nsenter -t $BPID -n pkill -f "$WORK/b.sock" 2>/dev/null || true
  kill $BPID 2>/dev/null || true
  exit $(( ok == 1 ? 0 : 1 ))
'
echo "bgp large community smoke test: OK"
