#!/usr/bin/env bash
# Full-configuration SIGHUP hot-reload smoke test — the management-plane property that
# a running wren re-reads its whole config on SIGHUP and applies the delta *without*
# restarting the daemon process, including *starting a protocol engine that was off at
# startup*. Self-contained and rootless, like the other smoke scripts: it runs inside
# throwaway `unshare -Urn` namespaces and never touches the host's interfaces. OSPF
# uses a raw IPPROTO_OSPF (89) socket, which needs CAP_NET_RAW — held by the netns-root
# inside `unshare -Urn`.
#
# Topology: A (router-id 10.0.0.1) <--veth--> B (10.0.0.2), OSPF point-to-point area 0.
# B runs OSPF from the start and redistributes a static 10.99.0.0/24 into OSPF as an
# AS-external route. A starts with OSPF DISABLED and one static (192.168.1.0/24). We
# then rewrite A's config to (a) ENABLE OSPF on veth0 and (b) ADD a second static
# (192.168.2.0/24), and send A a single SIGHUP. We assert:
#   * before reload: A has neither 10.99.0.0/24 (OSPF off) nor 192.168.2.0/24;
#   * after reload:  A's newly-started OSPF forms the adjacency and learns
#                    10.99.0.0/24 `proto ospf` — proving a protocol was started live;
#   * after reload:  A's `show routes` now has the added static 192.168.2.0/24;
#   * A's process (PID and start-time) is UNCHANGED across the reload — only the OSPF
#     engine task was spawned, not the daemon.
#
# Usage:  bash scripts/config-hotreload-smoke.sh
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
WREN="$REPO/target/debug/wren"

if [[ ! -x "$WREN" ]]; then
  echo "building wren (debug) ..."
  (cd "$REPO" && cargo build -p wren-daemon)
fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# A's initial config: a single static, OSPF present but DISABLED (router-id set so the
# engine can start cleanly on reload). No adjacency, no learned routes yet.
cat >"$WORK/a.toml" <<EOF
router-id = "10.0.0.1"
[[static]]
prefix = "192.168.1.0/24"
via    = "10.0.0.2"
[ospf]
enabled      = false
interfaces   = ["veth0"]
network-type = "point-to-point"
EOF

# A's reloaded config: OSPF now ENABLED on veth0, plus an extra static. Written now,
# applied only on SIGHUP.
cat >"$WORK/a-reloaded.toml" <<EOF
router-id = "10.0.0.1"
[[static]]
prefix = "192.168.1.0/24"
via    = "10.0.0.2"
[[static]]
prefix = "192.168.2.0/24"
via    = "10.0.0.2"
[ospf]
enabled      = true
interfaces   = ["veth0"]
network-type = "point-to-point"
EOF

# B: OSPF from the start, redistributing its static 10.99.0.0/24 into OSPF.
cat >"$WORK/b.toml" <<EOF
router-id = "10.0.0.2"
[[static]]
prefix = "10.99.0.0/24"
via    = "10.0.0.1"
[ospf]
enabled      = true
interfaces   = ["veth1"]
network-type = "point-to-point"
redistribute = ["static"]
EOF

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

  nsenter -t $BPID -n "$WREN" --config "$WORK/b.toml" --backend kernel --socket "$WORK/b.sock" >"$WORK/b.log" 2>&1 &
  "$WREN" --config "$WORK/a.toml" --backend kernel --socket "$WORK/a.sock" >"$WORK/a.log" 2>&1 & APID=$!
  sleep 5

  # Record A''s process identity (PID + kernel start-time) so we can prove the daemon
  # itself never restarted across the reload — only its OSPF engine task was spawned.
  A_START_BEFORE="$(awk "{print \$22}" /proc/$APID/stat)"

  ok=1
  echo "=== phase 1: before reload (show routes on A) ==="
  before="$("$WREN" --socket "$WORK/a.sock" show routes)"; echo "$before"
  echo "$before" | grep -q "192.168.1.0/24.*proto static" \
    || { echo "FAIL: initial static missing before reload"; ok=0; }
  echo "$before" | grep -q "10.99.0.0/24" \
    && { echo "FAIL: OSPF route present before reload (OSPF should be off)"; ok=0; } || true
  echo "$before" | grep -q "192.168.2.0/24" \
    && { echo "FAIL: second static present before reload (unexpected)"; ok=0; } || true

  # Swap in the config that enables OSPF and adds a static, then SIGHUP A once.
  cp "$WORK/a-reloaded.toml" "$WORK/a.toml"
  echo "=== sending SIGHUP to A (pid $APID) ==="
  kill -HUP $APID
  # Give the newly-started OSPF engine time to form the PtP adjacency and receive the
  # AS-external LSA (hellos + database exchange).
  sleep 40

  echo "=== phase 2: after reload (show routes on A) ==="
  routes="$("$WREN" --socket "$WORK/a.sock" show routes)"; echo "$routes"

  # The daemon must be the SAME process (never restarted): PID alive and start-time equal.
  if ! kill -0 $APID 2>/dev/null; then echo "FAIL: A process died across the reload"; ok=0; fi
  A_START_AFTER="$(awk "{print \$22}" /proc/$APID/stat 2>/dev/null || echo GONE)"
  [[ "$A_START_AFTER" == "$A_START_BEFORE" ]] \
    || { echo "FAIL: A process restarted (start-time $A_START_BEFORE -> $A_START_AFTER)"; ok=0; }

  # The newly-started OSPF formed the adjacency and learned B''s redistributed route.
  echo "$routes" | grep -q "10.99.0.0/24.*proto ospf" \
    || { echo "FAIL: OSPF not started/adjacency not formed on SIGHUP (no learned route)"; ok=0; }
  # The added static took effect live.
  echo "$routes" | grep -q "192.168.2.0/24.*proto static" \
    || { echo "FAIL: added static not applied on SIGHUP"; ok=0; }
  # The pre-existing static survived the reload.
  echo "$routes" | grep -q "192.168.1.0/24.*proto static" \
    || { echo "FAIL: pre-existing static lost across the reload"; ok=0; }

  if [[ $ok -ne 1 ]]; then echo "--- A log ---"; cat "$WORK/a.log"; echo "--- B log ---"; cat "$WORK/b.log"; fi
  kill $APID 2>/dev/null || true
  nsenter -t $BPID -n pkill -f "$WORK/b.sock" 2>/dev/null || true
  kill $BPID 2>/dev/null || true
  exit $(( ok == 1 ? 0 : 1 ))
'
echo "config hot-reload smoke test: OK"
