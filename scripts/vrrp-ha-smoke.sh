#!/usr/bin/env bash
# VIP ownership follows the declared links, including deletion/recreation.
# All network changes run in a disposable user/network namespace.
set -euo pipefail
REPO="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO"
cargo build -p wren-daemon --locked
cargo test -p wren-daemon --locked --no-run
WREN="${CARGO_TARGET_DIR:-$REPO/target}/debug/wren"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
export WREN WORK
cat >"$WORK/router.toml" <<'EOF'
router-id = "10.0.0.1"
[[vrrp]]
interface = "sync0"
address-interface = "lan0"
vrid = 20
priority = 255
advert-interval = 100
virtual-address = ["192.0.2.100"]
prefix-length = 24
[[vrrp]]
interface = "sync0"
address-interface = "lan0"
vrid = 21
priority = 255
advert-interval = 100
virtual-address = ["2001:db8::100"]
prefix-length = 64
EOF
timeout 30 unshare -Urn bash -euo pipefail <<'TEST'
daemon_pid=""
cleanup() {
  if [[ -n "$daemon_pid" ]]; then kill "$daemon_pid" 2>/dev/null || true; wait "$daemon_pid" 2>/dev/null || true; fi
}
trap cleanup EXIT
trap 'cat "$WORK/router.log" >&2' ERR
ip link set lo up
cargo test -p wren-daemon --locked --offline -- --ignored --exact vrrp::tests::raw_socket_rejects_routed_advertisements_in_both_families
sync_link() {
  ip link add sync0 type dummy
  ip link set sync0 up
  ip address add 10.0.0.1/24 dev sync0
  ip -6 address add fe80::1/64 dev sync0 nodad
}
served_link() { ip link add lan0 type dummy; ip link set lan0 up; }
wait_vips() {
  for _ in $(seq 1 100); do
    if ip -4 -o address show dev lan0 | grep -q '192.0.2.100/24' &&
       ip -6 -o address show dev lan0 | grep '2001:db8::100/64' | grep -qvE 'tentative|dadfailed'; then return; fi
    sleep 0.02
  done
  return 1
}
assert_inactive() {
  for _ in $(seq 1 100); do
    if [[ "$("$WREN" --socket "$WORK/router.sock" show vrrp 2>/dev/null | grep -c initialize || true)" == 2 ]]; then return; fi
    sleep 0.02
  done
  return 1
}
sync_link
# Missing served link must not put either VIP on the heartbeat link.
"$WREN" --config "$WORK/router.toml" --backend kernel --socket "$WORK/router.sock" >"$WORK/router.log" 2>&1 &
daemon_pid=$!
assert_inactive
! ip -o address show dev sync0 | grep -qE '192.0.2.100|2001:db8::100'
served_link
wait_vips
ip address del 192.0.2.100/24 dev lan0
ip -6 address del 2001:db8::100/64 dev lan0
wait_vips
ip link set lan0 down
assert_inactive
! ip -o address show dev lan0 | grep -qE '192.0.2.100|2001:db8::100'
ip link set lan0 up
wait_vips
ip link delete lan0
assert_inactive
! ip -o address show dev sync0 | grep -qE '192.0.2.100|2001:db8::100'
served_link
wait_vips
ip link delete sync0
assert_inactive
sync_link
wait_vips
kill "$daemon_pid"
wait "$daemon_pid"
daemon_pid=""
! ip -o address show dev lan0 | grep -qE '192.0.2.100|2001:db8::100'
echo 'VRRP ownership, link recovery, immediate IPv6 and shutdown: PASS'
TEST
