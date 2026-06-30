#!/usr/bin/env bash
# VRRP (RFC 5798) interface-tracking smoke test — the firewall-HA failover that
# matters: a master whose tracked uplink fails demotes so a healthier backup takes
# over. Rootless and self-contained.
#
# Topology: A (priority 200, tracks dummy0, decrement 150) and B (priority 100) on
# a veth, both backing VRID 51 / 10.0.0.254.
#   phase 1: dummy0 up  → A effective 200 → A master, holds the VIP.
#   phase 2: dummy0 down → A effective 50 < 100 → B preempts → B master, holds VIP.
#   phase 3: dummy0 up  → A effective 200 → A preempts back → A master again.
#
# Usage:  bash scripts/vrrp-track-smoke.sh
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
[[vrrp]]
interface          = "veth0"
vrid               = 51
priority           = 200
advert-interval    = 300
virtual-address    = ["10.0.0.254"]
prefix-length      = 24
track-interface    = ["dummy0"]
priority-decrement = 150
EOF

cat >"$WORK/b.toml" <<EOF
router-id = "10.0.0.2"
[[vrrp]]
interface       = "veth1"
vrid            = 51
priority        = 100
advert-interval = 300
virtual-address = ["10.0.0.254"]
prefix-length   = 24
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
  ip link add dummy0 type dummy; ip link set dummy0 up        # A`s tracked uplink
  nsenter -t $BPID -n ip addr add 10.0.0.2/24 dev veth1
  nsenter -t $BPID -n ip link set veth1 up
  nsenter -t $BPID -n ip link set lo up

  nsenter -t $BPID -n "$WREN" --config "$WORK/b.toml" --backend kernel --socket "$WORK/b.sock" >"$WORK/b.log" 2>&1 &
  "$WREN" --config "$WORK/a.toml" --backend kernel --socket "$WORK/a.sock" >"$WORK/a.log" 2>&1 &
  sleep 3

  ok=1
  echo "=== phase 1: dummy0 up → A master ==="
  va="$("$WREN" --socket "$WORK/a.sock" show vrrp)"; echo "$va"
  echo "$va" | grep -Eq "51 .*veth0 .*master " || { echo "FAIL: A is not master initially"; ok=0; }
  ip -4 addr show dev veth0 | grep -q "10.0.0.254" || { echo "FAIL: A does not hold the VIP"; ok=0; }

  echo "=== phase 2: dummy0 DOWN → B takes over ==="
  ip link set dummy0 down
  sleep 3
  vb="$(nsenter -t $BPID -n "$WREN" --socket "$WORK/b.sock" show vrrp)"; echo "$vb"
  echo "$vb" | grep -Eq "51 .*veth1 .*master " || { echo "FAIL: B did not take over after A uplink failed"; ok=0; }
  nsenter -t $BPID -n ip -4 addr show dev veth1 | grep -q "10.0.0.254" || { echo "FAIL: B did not assume the VIP"; ok=0; }

  echo "=== phase 3: dummy0 UP → A preempts back ==="
  ip link set dummy0 up
  sleep 3
  va2="$("$WREN" --socket "$WORK/a.sock" show vrrp)"; echo "$va2"
  echo "$va2" | grep -Eq "51 .*veth0 .*master " || { echo "FAIL: A did not preempt back after recovery"; ok=0; }
  ip -4 addr show dev veth0 | grep -q "10.0.0.254" || { echo "FAIL: A did not reassume the VIP after recovery"; ok=0; }

  if [[ $ok -ne 1 ]]; then echo "--- A log ---"; cat "$WORK/a.log"; echo "--- B log ---"; cat "$WORK/b.log"; fi
  kill $BPID 2>/dev/null || true
  exit $(( ok == 1 ? 0 : 1 ))
'
echo "vrrp interface-tracking smoke test: OK"
