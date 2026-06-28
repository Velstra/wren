#!/usr/bin/env bash
# BGP NO_EXPORT community smoke test (RFC 1997), fully self-contained.
#
# Like bgp-4octet-smoke.sh it runs entirely inside throwaway `unshare -Urn`
# network namespaces — it never touches the host's real interfaces or uplink and
# needs no root.
#
# Two phases over the same eBGP topology (A: AS 65001 active, originates
# 10.10.0.0/24; B: AS 65002 passive):
#   1. control — A originates with NO community → B installs 10.10.0.0/24.
#   2. no-export — A originates with community = ["no-export"] → because B is an
#      eBGP peer, A must NOT advertise the route, so B does NOT install it.
#
# Usage:  bash scripts/bgp-community-smoke.sh
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
WREN="$REPO/target/debug/wren"

if [[ ! -x "$WREN" ]]; then
  echo "building wren (debug) ..."
  (cd "$REPO" && cargo build -p wren-daemon)
fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

write_configs() {
  local community_line="$1"
  cat >"$WORK/a.toml" <<EOF
# Router A — AS 65001, active connector, originates 10.10.0.0/24
router-id = "10.0.0.1"
[bgp]
enabled  = true
local-as = 65001
network  = ["10.10.0.0/24"]
$community_line
[[bgp.neighbor]]
address   = "10.0.0.2"
remote-as = 65002
EOF
  cat >"$WORK/b.toml" <<EOF
# Router B — AS 65002, passive listener
router-id = "10.0.0.2"
[bgp]
enabled  = true
local-as = 65002
[[bgp.neighbor]]
address   = "10.0.0.1"
remote-as = 65001
passive   = true
EOF
}

# Run one phase inside a throwaway netns pair; echoes "PRESENT" or "ABSENT" for
# whether B installed 10.10.0.0/24 via BGP.
run_phase() {
  export WREN WORK
  unshare -Urn bash -c '
    set -e
    ip link set lo up
    setsid unshare -n -- sleep 30 & BPID=$!
    sleep 0.3
    ip link add veth0 type veth peer name veth1
    ip link set veth1 netns $BPID
    ip addr add 10.0.0.1/24 dev veth0; ip link set veth0 up
    nsenter -t $BPID -n ip addr add 10.0.0.2/24 dev veth1
    nsenter -t $BPID -n ip link set veth1 up
    nsenter -t $BPID -n ip link set lo up
    nsenter -t $BPID -n "$WREN" --config "$WORK/b.toml" --backend kernel >"$WORK/b.log" 2>&1 &
    "$WREN" --config "$WORK/a.toml" --backend kernel >"$WORK/a.log" 2>&1 &
    sleep 6
    if nsenter -t $BPID -n ip route | grep -q "10.10.0.0/24.*proto bgp"; then
      echo PRESENT
    else
      echo ABSENT
    fi
    kill $BPID 2>/dev/null || true
  '
}

echo "=== Phase 1: control (no community) ==="
write_configs ""
got1="$(run_phase | tail -1)"
echo "B sees 10.10.0.0/24: $got1"

echo "=== Phase 2: community = [\"no-export\"] ==="
write_configs 'community = ["no-export"]'
got2="$(run_phase | tail -1)"
echo "B sees 10.10.0.0/24: $got2"

if [[ "$got1" == "PRESENT" && "$got2" == "ABSENT" ]]; then
  echo "PASS: NO_EXPORT suppressed the eBGP advertisement; control was advertised."
  exit 0
else
  echo "FAIL: expected PRESENT then ABSENT, got '$got1' then '$got2'"
  echo "--- A log (phase 2) ---"; cat "$WORK/a.log"
  exit 1
fi
