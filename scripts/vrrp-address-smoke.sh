#!/usr/bin/env bash
# Real VRRP address-loss/recovery regression in disposable network namespaces.
set -euo pipefail
REPO="$(cd "$(dirname "$0")/.." && pwd)"
WREN="${WREN:-$REPO/target/debug/wren}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
for peer in a b; do
  if [[ "$peer" == a ]]; then iface=veth0; priority=200; else iface=veth1; priority=100; fi
  cat >"$WORK/$peer.toml" <<EOF
router-id = "192.0.2.1"
[[vrrp]]
interface = "$iface"
vrid = 51
priority = $priority
advert-interval = 300
virtual-address = ["192.0.2.254"]
prefix-length = 24
EOF
done
export WREN WORK
unshare -Urn bash -c '
  set -euo pipefail
  ip link set lo up
  unshare -n -- sleep 120 & BPID=$!
  APID=; DPID=
  cleanup() {
    for pid in "$APID" "$DPID" "$BPID"; do
      [[ -z "$pid" ]] || kill "$pid" 2>/dev/null || true
    done
  }
  trap cleanup EXIT
  sleep .3
  ip link add veth0 type veth peer name veth1
  ip link set veth1 netns "$BPID"
  ip link set veth0 up
  nsenter -t "$BPID" -n ip link set lo up
  nsenter -t "$BPID" -n ip link set veth1 up
  nsenter -t "$BPID" -n ip addr add 192.0.2.2/24 dev veth1
  "$WREN" --config "$WORK/a.toml" --backend kernel --socket "$WORK/a.sock" >"$WORK/a.log" 2>&1 & APID=$!
  nsenter -t "$BPID" -n "$WREN" --config "$WORK/b.toml" --backend kernel --socket "$WORK/b.sock" >"$WORK/b.log" 2>&1 & DPID=$!
  a() { "$WREN" --socket "$WORK/a.sock" show vrrp; }
  b() { nsenter -t "$BPID" -n "$WREN" --socket "$WORK/b.sock" show vrrp; }
  wait_for() {
    local command="$1"
    for ((n=0; n<20; n++)); do
      if eval "$command" 2>/dev/null; then return 0; fi
      sleep .5
    done
    cat "$WORK/a.log" "$WORK/b.log"
    return 1
  }
  wait_for "b | grep -Eq \"51 .*master .*100 .*192.0.2.2\""
  a | grep -Eq "51 .*initialize"
  ! ip -4 addr show veth0 | grep -q 192.0.2.254
  echo "PASS: unaddressed router holds no VIP; peer serves it"
  ip addr add 192.0.2.1/24 dev veth0
  wait_for "a | grep -Eq \"51 .*master .*200 .*192.0.2.1\""
  wait_for "b | grep -Eq \"51 .*backup\""
  ip -4 addr show veth0 | grep -q 192.0.2.254
  echo "PASS: initial address acquisition starts election automatically"
  ip addr del 192.0.2.1/24 dev veth0
  wait_for "a | grep -Eq \"51 .*initialize\""
  ! ip -4 addr show veth0 | grep -q 192.0.2.254
  wait_for "b | grep -Eq \"51 .*master\""
  echo "PASS: address loss relinquishes VIP despite remaining virtual address"
  ip addr add 192.0.2.3/24 dev veth0
  wait_for "a | grep -Eq \"51 .*master .*200 .*192.0.2.3\""
  wait_for "b | grep -Eq \"51 .*backup\""
  ! nsenter -t "$BPID" -n ip -4 addr show veth1 | grep -q 192.0.2.254
  echo "PASS: changed address restores one owner without daemon restart"
'
