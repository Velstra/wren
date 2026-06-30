#!/usr/bin/env bash
# VRRP (RFC 5798) smoke test — first-hop redundancy / firewall HA, fully
# self-contained and rootless.
#
# Runs inside throwaway `unshare -Urn` namespaces (CAP_NET_RAW for the raw
# IPPROTO_VRRP socket + CAP_NET_ADMIN to assign the virtual IP) and never touches
# the host's interfaces or uplink. Per-daemon control sockets are Unix sockets
# under a temp dir.
#
# Topology: A (priority 200) and B (priority 100) on a veth, both backing VRID 51
# / virtual IP 10.0.0.254. A wins the election and owns the VIP; B is backup. We
# then kill A and assert B takes the VIP over (the failover).
#
#   phase 1: A == master and holds 10.0.0.254; B == backup and does not.
#   phase 2: A killed → B == master and now holds 10.0.0.254.
#
# Usage:  bash scripts/vrrp-smoke.sh
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
virtual-address = ["10.0.0.254"]
prefix-length   = 24
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
  nsenter -t $BPID -n ip addr add 10.0.0.2/24 dev veth1
  nsenter -t $BPID -n ip link set veth1 up
  nsenter -t $BPID -n ip link set lo up

  nsenter -t $BPID -n "$WREN" --config "$WORK/b.toml" --backend kernel --socket "$WORK/b.sock" >"$WORK/b.log" 2>&1 &
  "$WREN" --config "$WORK/a.toml" --backend kernel --socket "$WORK/a.sock" >"$WORK/a.log" 2>&1 &

  # Let the election settle (advert 300ms; A promotes in ~1s, B stays backup).
  sleep 3

  echo "=== phase 1: show vrrp (A) ==="
  va="$("$WREN" --socket "$WORK/a.sock" show vrrp)"; echo "$va"
  echo "=== phase 1: show vrrp (B) ==="
  vb="$(nsenter -t $BPID -n "$WREN" --socket "$WORK/b.sock" show vrrp)"; echo "$vb"

  ok=1
  echo "$va" | grep -Eq "51 .*veth0 .*master .*200 " || { echo "FAIL: A is not master"; ok=0; }
  echo "$vb" | grep -Eq "51 .*veth1 .*backup .*100 " || { echo "FAIL: B is not backup"; ok=0; }
  ip -4 addr show dev veth0 | grep -q "10.0.0.254"                   || { echo "FAIL: master A does not hold the VIP"; ok=0; }
  nsenter -t $BPID -n ip -4 addr show dev veth1 | grep -q "10.0.0.254" && { echo "FAIL: backup B wrongly holds the VIP"; ok=0; } || true

  # phase 2: kill A → B must take over (master-down ~1.08s for priority 100).
  echo "=== phase 2: killing A ==="
  pkill -f "$WORK/a.toml" 2>/dev/null || true
  sleep 3

  echo "=== phase 2: show vrrp (B) ==="
  vb2="$(nsenter -t $BPID -n "$WREN" --socket "$WORK/b.sock" show vrrp)"; echo "$vb2"
  echo "$vb2" | grep -Eq "51 .*veth1 .*master " || { echo "FAIL: B did not take over as master"; ok=0; }
  nsenter -t $BPID -n ip -4 addr show dev veth1 | grep -q "10.0.0.254" || { echo "FAIL: B did not assume the VIP after failover"; ok=0; }

  if [[ $ok -ne 1 ]]; then echo "--- A log ---"; cat "$WORK/a.log"; echo "--- B log ---"; cat "$WORK/b.log"; fi
  kill $BPID 2>/dev/null || true
  exit $(( ok == 1 ? 0 : 1 ))
'
echo "vrrp smoke test: OK"
