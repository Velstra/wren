#!/usr/bin/env bash
# IS-IS L1<->L2 route-leaking smoke test (RFC 5302) — an L1L2 router leaks the
# prefixes it learns at one level into the other. Self-contained, rootless.
#
# Like the other isis-*-smoke.sh scripts it runs inside throwaway `unshare -Urn`
# namespaces and never touches the host's interfaces or uplink. IS-IS uses an
# AF_PACKET (802.2 LLC) socket per interface, needing CAP_NET_RAW — held by the
# netns-root inside `unshare -Urn`.
#
# Topology (all point-to-point):
#   X (L1, area 49.0001) <--L1--> A (L1L2, area 49.0001) <--L2--> B (L2, area 49.0002)
# X advertises a connected 10.100.0.0/24 (L1 intra-area); B advertises 10.200.0.0/24
# (into L2). A is the L1L2 border router that leaks between the levels.
#
# Two phases differ only in A's `l2-to-l1-leaking` knob:
#   * phase 1 (default, off): B learns X's 10.100.0.0/24 (L1->L2 is always on), but
#     X does NOT learn B's 10.200.0.0/24 (L2->L1 off);
#   * phase 2 (l2-to-l1-leaking = true): B still learns 10.100.0.0/24, and now X
#     learns 10.200.0.0/24 (leaked down into L1 with the up/down bit set).
#
# IS-IS convergence over hello-interval 3 means each phase waits ~22s.
#
# Usage:  bash scripts/isis-l1l2-leak-smoke.sh
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
WREN="$REPO/target/debug/wren"

if [[ ! -x "$WREN" ]]; then
  echo "building wren (debug) ..."
  (cd "$REPO" && cargo build -p wren-daemon)
fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# X — Level-1 only, in area 49.0001. dummy0 carries the intra-area 10.100.0.0/24.
cat >"$WORK/x.toml" <<EOF
router-id = "10.0.0.1"
[isis]
enabled        = true
interfaces     = ["veth1", "dummy0"]
system-id      = "0000.0000.0001"
area           = "49.0001"
level          = "l1"
network-type   = "point-to-point"
hello-interval = 3
EOF

# B — Level-2 only, in area 49.0002. dummy0 carries the backbone 10.200.0.0/24.
cat >"$WORK/b.toml" <<EOF
router-id = "10.0.0.3"
[isis]
enabled        = true
interfaces     = ["veth3", "dummy0"]
system-id      = "0000.0000.0003"
area           = "49.0002"
level          = "l2"
network-type   = "point-to-point"
hello-interval = 3
EOF

# A phase 1 — L1L2 border in area 49.0001, default leaking (L1->L2 only).
cat >"$WORK/a1.toml" <<EOF
router-id = "10.0.0.2"
[isis]
enabled        = true
interfaces     = ["veth0", "veth2"]
system-id      = "0000.0000.0002"
area           = "49.0001"
level          = "l1l2"
network-type   = "point-to-point"
hello-interval = 3
EOF

# A phase 2 — same, but also leak L2 backbone prefixes down into L1.
cat >"$WORK/a2.toml" <<EOF
router-id = "10.0.0.2"
[isis]
enabled          = true
interfaces       = ["veth0", "veth2"]
system-id        = "0000.0000.0002"
area             = "49.0001"
level            = "l1l2"
network-type     = "point-to-point"
hello-interval   = 3
l2-to-l1-leaking = true
EOF

export WREN WORK
unshare -Urn bash -c '
  set -e
  ip link set lo up
  setsid unshare -n -- sleep 200 & XPID=$!
  setsid unshare -n -- sleep 200 & BPID=$!
  sleep 0.3

  # A<->X link (L1).
  ip link add veth0 type veth peer name veth1
  ip link set veth1 netns $XPID
  ip addr add 10.12.0.1/24 dev veth0; ip link set veth0 up
  nsenter -t $XPID -n ip addr add 10.12.0.2/24 dev veth1
  nsenter -t $XPID -n ip link set veth1 up
  nsenter -t $XPID -n ip link set lo up
  nsenter -t $XPID -n ip link add dummy0 type dummy
  nsenter -t $XPID -n ip addr add 10.100.0.1/24 dev dummy0
  nsenter -t $XPID -n ip link set dummy0 up

  # A<->B link (L2).
  ip link add veth2 type veth peer name veth3
  ip link set veth3 netns $BPID
  ip addr add 10.23.0.1/24 dev veth2; ip link set veth2 up
  nsenter -t $BPID -n ip addr add 10.23.0.2/24 dev veth3
  nsenter -t $BPID -n ip link set veth3 up
  nsenter -t $BPID -n ip link set lo up
  nsenter -t $BPID -n ip link add dummy0 type dummy
  nsenter -t $BPID -n ip addr add 10.200.0.1/24 dev dummy0
  nsenter -t $BPID -n ip link set dummy0 up

  run_phase() {
    acfg="$1"; label="$2"
    nsenter -t $XPID -n "$WREN" --config "$WORK/x.toml" --backend kernel --socket "$WORK/x.sock" >"$WORK/x.log" 2>&1 &
    nsenter -t $BPID -n "$WREN" --config "$WORK/b.toml" --backend kernel --socket "$WORK/b.sock" >"$WORK/b.log" 2>&1 &
    "$WREN" --config "$acfg" --backend kernel --socket "$WORK/a.sock" >"$WORK/a.log" 2>&1 &
    sleep 24
    # Assert on the router RIB (`show routes isis`), which holds every learned route
    # — the semantic "the far router learns it" — independent of whether the kernel
    # FIB accepts the multi-nexthop route.
    echo "=== phase $label: on B, show routes isis (expects L1->L2 leak) ==="
    nsenter -t $BPID -n "$WREN" --socket "$WORK/b.sock" show routes isis || true
    echo "=== phase $label: on X, show routes isis (expects L2->L1 leak only in phase 2) ==="
    nsenter -t $XPID -n "$WREN" --socket "$WORK/x.sock" show routes isis || true
    pkill -f "$WORK/a.sock" 2>/dev/null || true
    nsenter -t $XPID -n pkill -f "$WORK/x.sock" 2>/dev/null || true
    nsenter -t $BPID -n pkill -f "$WORK/b.sock" 2>/dev/null || true
    sleep 1
  }

  ok=1

  # Phase 1: default leaking — L1->L2 on, L2->L1 off.
  run_phase "$WORK/a1.toml" "1 (default: L1->L2 only)" > "$WORK/p1.out" 2>&1
  cat "$WORK/p1.out"
  grep -q "10.100.0.0/24" "$WORK/p1.out" \
    || { echo "FAIL: phase 1: B did not learn L1 prefix 10.100.0.0/24 leaked into L2"; ok=0; }
  # X must NOT have B'\''s backbone prefix (L2->L1 leaking is off by default).
  awk "/on X,/{x=1} /on B,/{x=0} x" "$WORK/p1.out" | grep -q "10.200.0.0/24" \
    && { echo "FAIL: phase 1: X learned 10.200.0.0/24 with L2->L1 leaking off"; ok=0; }

  # Phase 2: enable L2->L1 leaking — X now learns the backbone prefix too.
  run_phase "$WORK/a2.toml" "2 (l2-to-l1-leaking on)" > "$WORK/p2.out" 2>&1
  cat "$WORK/p2.out"
  grep -q "10.100.0.0/24" "$WORK/p2.out" \
    || { echo "FAIL: phase 2: B did not learn L1 prefix 10.100.0.0/24 leaked into L2"; ok=0; }
  awk "/on X,/{x=1} /on B,/{x=0} x" "$WORK/p2.out" | grep -q "10.200.0.0/24" \
    || { echo "FAIL: phase 2: X did not learn 10.200.0.0/24 leaked down into L1"; ok=0; }

  if [[ $ok -ne 1 ]]; then echo "--- A log ---"; tail -15 "$WORK/a.log"; echo "--- X log ---"; tail -15 "$WORK/x.log"; echo "--- B log ---"; tail -15 "$WORK/b.log"; fi
  kill $XPID $BPID 2>/dev/null || true
  exit $(( ok == 1 ? 0 : 1 ))
'
echo "isis l1l2 leak smoke test: OK"
