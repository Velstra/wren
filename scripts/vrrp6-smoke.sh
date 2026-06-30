#!/usr/bin/env bash
# VRRP (RFC 5798) IPv6 smoke test — dual-stack first-hop redundancy, rootless.
#
# Same as vrrp-smoke.sh but for an IPv6 virtual address: the advertisements go to
# ff02::12 sourced from the interface link-local, and the master announces the VIP
# with an unsolicited neighbor advertisement instead of a gratuitous ARP.
#
# Topology: A (priority 200) and B (priority 100) on a veth, both backing VRID 51
# / virtual IP 2001:db8::ff. A wins and owns the VIP; B is backup. Kill A and B
# takes over.
#
# Usage:  bash scripts/vrrp6-smoke.sh
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
interface       = "veth0"
vrid            = 51
priority        = 200
advert-interval = 300
virtual-address = ["2001:db8::ff"]
prefix-length   = 64
EOF

cat >"$WORK/b.toml" <<EOF
router-id = "10.0.0.2"
[[vrrp]]
interface       = "veth1"
vrid            = 51
priority        = 100
advert-interval = 300
virtual-address = ["2001:db8::ff"]
prefix-length   = 64
EOF

export WREN WORK
unshare -Urn bash -c '
  set -e
  ip link set lo up
  setsid unshare -n -- sleep 60 & BPID=$!
  sleep 0.3
  ip link add veth0 type veth peer name veth1
  ip link set veth1 netns $BPID
  ip -6 addr add 2001:db8::1/64 dev veth0; ip link set veth0 up
  nsenter -t $BPID -n ip -6 addr add 2001:db8::2/64 dev veth1
  nsenter -t $BPID -n ip link set veth1 up
  nsenter -t $BPID -n ip link set lo up

  # Wait for IPv6 duplicate-address detection on the link-local addresses.
  sleep 3

  nsenter -t $BPID -n "$WREN" --config "$WORK/b.toml" --backend kernel --socket "$WORK/b.sock" >"$WORK/b.log" 2>&1 &
  "$WREN" --config "$WORK/a.toml" --backend kernel --socket "$WORK/a.sock" >"$WORK/a.log" 2>&1 &
  sleep 3

  echo "=== phase 1: show vrrp (A) ==="
  va="$("$WREN" --socket "$WORK/a.sock" show vrrp)"; echo "$va"
  echo "=== phase 1: show vrrp (B) ==="
  vb="$(nsenter -t $BPID -n "$WREN" --socket "$WORK/b.sock" show vrrp)"; echo "$vb"

  ok=1
  echo "$va" | grep -Eq "51 .*veth0 .*master .*200 " || { echo "FAIL: A is not master"; ok=0; }
  echo "$vb" | grep -Eq "51 .*veth1 .*backup .*100 " || { echo "FAIL: B is not backup"; ok=0; }
  ip -6 addr show dev veth0 | grep -q "2001:db8::ff"                   || { echo "FAIL: master A does not hold the IPv6 VIP"; ok=0; }
  nsenter -t $BPID -n ip -6 addr show dev veth1 | grep -q "2001:db8::ff" && { echo "FAIL: backup B wrongly holds the VIP"; ok=0; } || true

  echo "=== phase 2: killing A ==="
  pkill -f "$WORK/a.toml" 2>/dev/null || true
  sleep 3

  echo "=== phase 2: show vrrp (B) ==="
  vb2="$(nsenter -t $BPID -n "$WREN" --socket "$WORK/b.sock" show vrrp)"; echo "$vb2"
  echo "$vb2" | grep -Eq "51 .*veth1 .*master " || { echo "FAIL: B did not take over as master"; ok=0; }
  nsenter -t $BPID -n ip -6 addr show dev veth1 | grep -q "2001:db8::ff" || { echo "FAIL: B did not assume the IPv6 VIP after failover"; ok=0; }

  if [[ $ok -ne 1 ]]; then echo "--- A log ---"; cat "$WORK/a.log"; echo "--- B log ---"; cat "$WORK/b.log"; fi
  kill $BPID 2>/dev/null || true
  exit $(( ok == 1 ? 0 : 1 ))
'
echo "vrrp6 smoke test: OK"
