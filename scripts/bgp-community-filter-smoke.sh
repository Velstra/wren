#!/usr/bin/env bash
# Per-prefix BGP communities via the export filter — the `[export] bgp` filter
# sets (or clears) the COMMUNITIES attribute per prefix on routes redistributed
# into BGP, instead of the all-or-nothing global `[bgp] community`. Fully
# self-contained and rootless.
#
# Like the other bgp-*-smoke.sh scripts it runs inside throwaway `unshare -Urn`
# namespaces and never touches the host's interfaces or uplink. Per-daemon
# control sockets live under a temp dir (Unix sockets, not the network).
#
# Topology: A (AS 65001, active) <-eBGP-> B (AS 65002, passive). A has three
# *static* routes and redistributes them into BGP through a named export filter:
#   * 10.99.0.0/24 -> set-community ["65001:777"]   (tagged)
#   * 10.77.0.0/24 -> set-community ["no-export"]    (suppressed toward eBGP B)
#   * 10.88.0.0/24 -> (no rule, default accept)      (untagged)
#
# One phase proves per-prefix communities end to end:
#   * B must learn 10.99.0.0/24 WITH `communities 65001:777`;
#   * B must learn 10.88.0.0/24 WITHOUT any communities;
#   * B must NOT learn 10.77.0.0/24 at all (the well-known no-export community is
#     honoured per-prefix: an eBGP peer never receives it).
#
# Usage:  bash scripts/bgp-community-filter-smoke.sh
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
WREN="$REPO/target/debug/wren"

if [[ ! -x "$WREN" ]]; then
  echo "building wren (debug) ..."
  (cd "$REPO" && cargo build -p wren-daemon)
fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# B: a plain passive eBGP peer.
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

# A: three statics, redistributed into BGP through the `tag` export filter that
# stamps per-prefix communities.
cat >"$WORK/a.toml" <<EOF
router-id = "10.0.0.1"
[[static]]
prefix = "10.99.0.0/24"
via    = "10.0.0.2"
[[static]]
prefix = "10.88.0.0/24"
via    = "10.0.0.2"
[[static]]
prefix = "10.77.0.0/24"
via    = "10.0.0.2"
[bgp]
enabled      = true
local-as     = 65001
redistribute = ["static"]
[[bgp.neighbor]]
address   = "10.0.0.2"
remote-as = 65002
[export]
bgp = "tag"
[[filter]]
name    = "tag"
default = "accept"
[[filter.rule]]
prefix        = ["10.99.0.0/24"]
set-community = ["65001:777"]
action        = "accept"
[[filter.rule]]
prefix        = ["10.77.0.0/24"]
set-community = ["no-export"]
action        = "accept"
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
  # The tagged prefix arrives carrying its community.
  grep -q "10.99.0.0/24 via 10.0.0.1 .*communities 65001:777" "$WORK/b.out" \
    || { echo "FAIL: 10.99.0.0/24 missing community 65001:777"; ok=0; }
  # The untagged prefix arrives, but with no communities.
  grep -q "10.88.0.0/24 via 10.0.0.1" "$WORK/b.out" \
    || { echo "FAIL: 10.88.0.0/24 not learned"; ok=0; }
  if grep "10.88.0.0/24" "$WORK/b.out" | grep -q "communities"; then
    echo "FAIL: 10.88.0.0/24 unexpectedly carries communities"; ok=0
  fi
  # The no-export prefix is suppressed toward the eBGP peer entirely.
  if grep -q "10.77.0.0/24" "$WORK/b.out"; then
    echo "FAIL: 10.77.0.0/24 (no-export) leaked to eBGP peer B"; ok=0
  fi

  if [[ $ok -ne 1 ]]; then echo "--- A log ---"; cat "$WORK/a.log"; echo "--- B log ---"; cat "$WORK/b.log"; fi
  pkill -f "$WORK/a.sock" 2>/dev/null || true
  nsenter -t $BPID -n pkill -f "$WORK/b.sock" 2>/dev/null || true
  kill $BPID 2>/dev/null || true
  exit $(( ok == 1 ? 0 : 1 ))
'
echo "bgp community filter smoke test: OK"
