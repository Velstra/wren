#!/usr/bin/env bash
# `wren monitor routes` streaming smoke test — the FPM-style RIB feed a fabric
# controller (e.g. the Velstra eBPF datapath) subscribes to so it mirrors every
# route add/withdraw as it happens. Fully self-contained and rootless.
#
# This is the single-daemon companion to route-export-smoke.sh (which drives the
# same feed over BGP): it exercises the snapshot + live-event path directly and,
# in the process, the SIGHUP hot-reload fan-out. No network is needed — the
# in-memory forwarding plane still drives the RIB → export-stream pipeline — but
# we still run inside a throwaway `unshare -Urn` namespace for isolation.
#
# We start wren with one static route, subscribe to `monitor routes`, then rewrite
# the config to ADD a second static and SIGHUP the daemon. We assert:
#   * the initial static appears in the SNAPSHOT (before `% end-of-dump`);
#   * `% end-of-dump` terminates the snapshot;
#   * the SIGHUP-added static streams as a LIVE `+ … proto static` event, after
#     end-of-dump.
#
# Usage:  bash scripts/monitor-routes-smoke.sh
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
WREN="$REPO/target/debug/wren"

if [[ ! -x "$WREN" ]]; then
  echo "building wren (debug) ..."
  (cd "$REPO" && cargo build -p wren-daemon)
fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# Initial config: one static route (seeded at startup, so it appears in the
# subscriber's snapshot).
cat >"$WORK/w.toml" <<EOF
router-id = "10.0.0.1"
[[static]]
prefix = "10.10.0.0/24"
via    = "10.0.0.254"
EOF

# Reloaded config: keeps the first static and adds a second — the live event.
cat >"$WORK/w-reloaded.toml" <<EOF
router-id = "10.0.0.1"
[[static]]
prefix = "10.10.0.0/24"
via    = "10.0.0.254"
[[static]]
prefix = "10.20.0.0/24"
via    = "10.0.0.254"
EOF

export WREN WORK
unshare -Urn bash -c '
  set -e
  ip link set lo up

  # In-memory backend: no kernel/netlink needed, but the RIB → export-stream path
  # is fully exercised.
  "$WREN" --config "$WORK/w.toml" --backend memory --socket "$WORK/w.sock" >"$WORK/w.log" 2>&1 & WPID=$!
  sleep 1.5

  # Subscribe: the snapshot replays the seeded static, then end-of-dump.
  timeout 12 "$WREN" --socket "$WORK/w.sock" monitor routes >"$WORK/mon.out" 2>&1 & MONPID=$!
  sleep 1.5

  # Add a second static and SIGHUP: it streams live to the open subscription.
  cp "$WORK/w-reloaded.toml" "$WORK/w.toml"
  echo "=== sending SIGHUP to wren (pid $WPID) ==="
  kill -HUP $WPID
  sleep 2.5

  echo "=== wren monitor routes ==="
  cat "$WORK/mon.out"

  ok=1
  grep -q "^% end-of-dump"              "$WORK/mon.out" || { echo "FAIL: no end-of-dump terminator"; ok=0; }
  grep -q "^+ 10.10.0.0/24.*proto static" "$WORK/mon.out" || { echo "FAIL: seeded static missing from stream"; ok=0; }
  grep -q "^+ 10.20.0.0/24.*proto static" "$WORK/mon.out" || { echo "FAIL: SIGHUP-added static not streamed"; ok=0; }

  # Snapshot ordering: the seeded static is in the snapshot (before end-of-dump);
  # the SIGHUP-added one is live (after it).
  eod=$(grep -n "^% end-of-dump"     "$WORK/mon.out" | head -1 | cut -d: -f1)
  seed=$(grep -n "^+ 10.10.0.0/24"   "$WORK/mon.out" | head -1 | cut -d: -f1)
  live=$(grep -n "^+ 10.20.0.0/24"   "$WORK/mon.out" | head -1 | cut -d: -f1)
  if [[ -z "$eod" || -z "$seed" || "$seed" -ge "$eod" ]]; then
    echo "FAIL: seeded static not in the snapshot (seed=$seed eod=$eod)"; ok=0
  fi
  if [[ -z "$live" || "$live" -le "$eod" ]]; then
    echo "FAIL: added static did not arrive live after end-of-dump (live=$live eod=$eod)"; ok=0
  fi

  if [[ $ok -ne 1 ]]; then echo "--- wren log ---"; cat "$WORK/w.log"; fi
  kill $MONPID 2>/dev/null || true
  kill $WPID   2>/dev/null || true
  exit $(( ok == 1 ? 0 : 1 ))
'
echo "monitor-routes smoke test: OK"
