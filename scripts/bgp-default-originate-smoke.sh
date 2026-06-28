#!/usr/bin/env bash
# BGP default-originate smoke test. With `default-originate = true` on a neighbour,
# Wren advertises a default route (0.0.0.0/0) to that peer unconditionally — with this
# router as the next hop — without installing it locally. Common on the upstream edge
# toward a stub customer. Self-contained, rootless.
#
# Like the other bgp-*-smoke.sh scripts it runs inside throwaway `unshare -Urn`
# namespaces and never touches the host's interfaces or uplink. BGP binds TCP 179
# (CAP_NET_BIND_SERVICE), held by the netns-root.
#
# Topology: A (AS 65001, 10.0.0.1) is the stub; B (AS 65002, 10.0.0.2) is its upstream,
# directly connected by a veth. B optionally originates a default toward A.
#
# Two phases (each restarts both daemons fresh, proto-bgp flushed between):
#   * phase off — B does NOT default-originate: A receives no default route.
#   * phase on  — B default-originates: A installs 0.0.0.0/0 via B, and B itself does
#     not install the default (it is advertised, not learned).
#
# Usage:  bash scripts/bgp-default-originate-smoke.sh
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
WREN="$REPO/target/debug/wren"

if [[ ! -x "$WREN" ]]; then
  echo "building wren (debug) ..."
  (cd "$REPO" && cargo build -p wren-daemon)
fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# A — the stub; same in both phases.
cat >"$WORK/a.toml" <<EOF
router-id = "10.0.0.1"
[bgp]
enabled  = true
local-as = 65001
[[bgp.neighbor]]
address   = "10.0.0.2"
remote-as = 65002
EOF

# B — the upstream; the default-originate line is filled per phase.
write_b() {  # $1 = default-originate line, $2 = tag
  cat >"$WORK/b_$2.toml" <<EOF
router-id = "10.0.0.2"
[bgp]
enabled  = true
local-as = 65002
[[bgp.neighbor]]
address   = "10.0.0.1"
remote-as = 65001
$1
EOF
}
write_b ''                          off
write_b 'default-originate = true'  on

export WREN WORK
unshare -Urn bash -c '
  set -e
  ip link set lo up
  setsid unshare -n -- sleep 120 & BPID=$!
  sleep 0.3
  ip link add veth0 type veth peer name veth1
  ip link set veth1 netns $BPID
  ip addr add 10.0.0.1/24 dev veth0; ip link set veth0 up
  nsenter -t $BPID -n ip addr add 10.0.0.2/24 dev veth1
  nsenter -t $BPID -n ip link set veth1 up
  nsenter -t $BPID -n ip link set lo up

  run_phase() {
    tag="$1"
    nsenter -t $BPID -n "$WREN" --config "$WORK/b_$tag.toml" --backend kernel --socket "$WORK/b.sock" >"$WORK/b_$tag.log" 2>&1 &
    "$WREN" --config "$WORK/a.toml" --backend kernel --socket "$WORK/a.sock" >"$WORK/a_$tag.log" 2>&1 &
    sleep 16
    "$WREN" --socket "$WORK/a.sock" show routes bgp >"$WORK/${tag}_a_routes.txt" 2>&1 || true
    ip route show proto bgp >"$WORK/${tag}_a_kernel.txt" 2>&1 || true
    nsenter -t $BPID -n ip route show proto bgp >"$WORK/${tag}_b_kernel.txt" 2>&1 || true
    pkill -f "$WORK/a.sock" 2>/dev/null || true
    nsenter -t $BPID -n pkill -f "$WORK/b.sock" 2>/dev/null || true
    sleep 1
    ip route flush proto bgp 2>/dev/null || true
    nsenter -t $BPID -n ip route flush proto bgp 2>/dev/null || true
  }

  run_phase off
  run_phase on
  kill $BPID 2>/dev/null || true
'

ok=1
for tag in off on; do
  echo "=== phase $tag: A show routes bgp ==="; cat "$WORK/${tag}_a_routes.txt"
  echo "=== phase $tag: A ip route proto bgp ==="; cat "$WORK/${tag}_a_kernel.txt"
done

# Phase off: A has no default route.
if grep -q "0.0.0.0/0\|^default" "$WORK/off_a_routes.txt" "$WORK/off_a_kernel.txt"; then
  echo "FAIL: no default-originate — A learned a default it should not have"; ok=0
fi

# Phase on: A installs the default via B, and B did not install it itself.
grep -q "0.0.0.0/0 via 10.0.0.2" "$WORK/on_a_routes.txt" \
  || { echo "FAIL: default-originate — A did not learn 0.0.0.0/0 via B"; ok=0; }
grep -q "default via 10.0.0.2" "$WORK/on_a_kernel.txt" \
  || { echo "FAIL: default-originate — A did not install the default proto bgp"; ok=0; }
if grep -q "default" "$WORK/on_b_kernel.txt"; then
  echo "FAIL: default-originate — B installed the default locally (should only advertise it)"; ok=0
fi

if [[ $ok -ne 1 ]]; then echo "--- A on routes ---"; cat "$WORK/on_a_routes.txt" 2>/dev/null || true; fi
[[ $ok -eq 1 ]] || exit 1
echo "bgp default-originate smoke test: OK"
