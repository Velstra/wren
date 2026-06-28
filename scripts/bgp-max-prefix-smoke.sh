#!/usr/bin/env bash
# BGP maximum-prefix smoke test (RFC 4486 §4). With `max-prefix = N` on a neighbour,
# Wren tears the session down with a Cease "Maximum Number of Prefixes Reached" once
# the peer advertises more than N prefixes, and keeps it down — a safety net against a
# misconfigured or hostile peer flooding the RIB. Self-contained, rootless.
#
# Like the other bgp-*-smoke.sh scripts it runs inside throwaway `unshare -Urn`
# namespaces and never touches the host's interfaces or uplink. BGP binds TCP 179
# (CAP_NET_BIND_SERVICE), held by the netns-root.
#
# Topology: A (AS 65001, 10.0.0.1) originates THREE networks; B (AS 65002, 10.0.0.2)
# is its directly-connected eBGP peer with a configurable max-prefix.
#
# Two phases (each restarts both daemons fresh, proto-bgp flushed between):
#   * phase under — B max-prefix = 10: all three prefixes fit, the session stays up
#     and B installs them.
#   * phase over  — B max-prefix = 2: the third prefix trips the limit, B tears the
#     session down (Idle) and installs none of A's routes.
#
# Usage:  bash scripts/bgp-max-prefix-smoke.sh
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
WREN="$REPO/target/debug/wren"

if [[ ! -x "$WREN" ]]; then
  echo "building wren (debug) ..."
  (cd "$REPO" && cargo build -p wren-daemon)
fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# A originates three /24s; same in both phases.
cat >"$WORK/a.toml" <<EOF
router-id = "10.0.0.1"
[bgp]
enabled  = true
local-as = 65001
network  = ["10.99.1.0/24", "10.99.2.0/24", "10.99.3.0/24"]
[[bgp.neighbor]]
address   = "10.0.0.2"
remote-as = 65002
EOF

write_b() {  # $1 = max-prefix line, $2 = tag
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
write_b 'max-prefix = 10'   under
write_b 'max-prefix = 2'    over

export WREN WORK
unshare -Urn bash -c '
  set -e
  ip link set lo up
  setsid unshare -n -- sleep 200 & BPID=$!
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
    sleep 18
    nsenter -t $BPID -n "$WREN" --socket "$WORK/b.sock" show bgp neighbors >"$WORK/${tag}_b_neigh.txt" 2>&1 || true
    nsenter -t $BPID -n "$WREN" --socket "$WORK/b.sock" show routes bgp >"$WORK/${tag}_b_routes.txt" 2>&1 || true
    nsenter -t $BPID -n ip route show proto bgp >"$WORK/${tag}_b_kernel.txt" 2>&1 || true
    pkill -f "$WORK/a.sock" 2>/dev/null || true
    nsenter -t $BPID -n pkill -f "$WORK/b.sock" 2>/dev/null || true
    sleep 1
    nsenter -t $BPID -n ip route flush proto bgp 2>/dev/null || true
  }

  run_phase under
  run_phase over
  kill $BPID 2>/dev/null || true
'

ok=1
for tag in under over; do
  echo "=== phase $tag: B show bgp neighbors ==="; cat "$WORK/${tag}_b_neigh.txt"
  echo "=== phase $tag: B ip route proto bgp ===";  cat "$WORK/${tag}_b_kernel.txt"
done

# Phase under (limit 10): session up, all three prefixes installed.
grep -q "Established" "$WORK/under_b_neigh.txt" \
  || { echo "FAIL: under-limit — session did not establish"; ok=0; }
for n in 1 2 3; do
  grep -q "10.99.$n.0/24" "$WORK/under_b_kernel.txt" \
    || { echo "FAIL: under-limit — B did not install 10.99.$n.0/24"; ok=0; }
done

# Phase over (limit 2): session torn down, NONE of A's prefixes installed.
if grep -q "Established" "$WORK/over_b_neigh.txt"; then
  echo "FAIL: over-limit — session stayed Established despite exceeding max-prefix"; ok=0
fi
if grep -q "10.99." "$WORK/over_b_kernel.txt"; then
  echo "FAIL: over-limit — B installed routes from a peer that blew its max-prefix"; ok=0
fi

if [[ $ok -ne 1 ]]; then echo "--- B over log ---"; grep -i "max-prefix\|cease" "$WORK/b_over.log" 2>/dev/null | tail || true; fi
[[ $ok -eq 1 ]] || exit 1
echo "bgp max-prefix (RFC 4486) smoke test: OK"
