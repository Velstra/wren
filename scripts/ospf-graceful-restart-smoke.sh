#!/usr/bin/env bash
# OSPF graceful restart (RFC 3623) smoke test — a restarting router floods a Grace-LSA so
# its neighbour acts as a helper and keeps forwarding through the restart, instead of
# tearing the adjacency down on the dead interval and flapping the route. Self-contained,
# rootless.
#
# Like the other ospf-*-smoke.sh scripts it runs inside throwaway `unshare -Urn`
# namespaces and never touches the host's interfaces or uplink.
#
# Topology: A (10.0.0.1) <--OSPF point-to-point--> B (10.0.0.2) over a veth, area 0. A
# also owns a passive stub network 10.99.0.0/24 (a dummy interface), which it advertises,
# so B installs a route to 10.99.0.0/24 via A. The timers are deliberately fast —
# hello 1 s, dead 4 s — so a neighbour that goes silent is normally dropped within 4 s.
#
# A restart = SIGINT the A daemon (wren's *planned/graceful* shutdown) and leave it down
# past the dead interval. The observable is B's OSPF adjacency to A over an 8 s window
# (two dead intervals) after A is stopped, plus B's route to A's stub 10.99.0.0/24:
#   * phase gr   — A runs `graceful-restart = true`: on shutdown it floods a Grace-LSA
#     (grace period 30 s). B enters helper mode and HOLDS the adjacency for the whole
#     window (no inactivity teardown), so the route to 10.99.0.0/24 stays installed.
#   * phase nogr — A runs without graceful restart: shutdown floods no Grace-LSA, so B
#     expires A on the 4 s dead interval and tears the adjacency down.
# The discriminator is B's "OSPF neighbour dead (inactivity)" event: absent under GR
# (the helper suppresses it), present without GR.
#
# Usage:  bash scripts/ospf-graceful-restart-smoke.sh
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
WREN="$REPO/target/debug/wren"

if [[ ! -x "$WREN" ]]; then
  echo "building wren (debug) ..."
  (cd "$REPO" && cargo build -p wren-daemon)
fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

write_a() {  # $1 = extra ospf lines, $2 = tag
  cat >"$WORK/a_$2.toml" <<EOF
router-id = "10.0.0.1"
[ospf]
enabled            = true
network-type       = "point-to-point"
area               = "0.0.0.0"
interfaces         = ["veth0", "dummy0"]
passive-interfaces = ["dummy0"]
hello-interval     = 1
dead-interval      = 4
$1
EOF
}
cat >"$WORK/b.toml" <<EOF
router-id = "10.0.0.2"
[ospf]
enabled        = true
network-type   = "point-to-point"
area           = "0.0.0.0"
interfaces     = ["veth1"]
hello-interval = 1
dead-interval  = 4
EOF
write_a 'graceful-restart        = true
graceful-restart-period = 30' gr
write_a '' nogr

export WREN WORK
timeout 120 unshare -Urn bash -c '
  set -e
  ip link set lo up
  setsid unshare -n -- sleep 110 & BPID=$!
  sleep 0.3
  ip link add veth0 type veth peer name veth1
  ip link set veth1 netns $BPID
  ip addr add 10.0.0.1/24 dev veth0; ip link set veth0 up
  ip link add dummy0 type dummy; ip addr add 10.99.0.1/24 dev dummy0; ip link set dummy0 up
  nsenter -t $BPID -n ip addr add 10.0.0.2/24 dev veth1
  nsenter -t $BPID -n ip link set veth1 up
  nsenter -t $BPID -n ip link set lo up

  run_phase() {
    tag="$1"
    # B (the helper) runs the whole phase; A is (re)started per phase.
    RUST_LOG=wren=info nsenter -t $BPID -n "$WREN" --config "$WORK/b.toml" --backend kernel --socket "$WORK/b_$tag.sock" >"$WORK/b_$tag.log" 2>&1 &
    BW=$!
    RUST_LOG=wren=info "$WREN" --config "$WORK/a_$tag.toml" --backend kernel --socket "$WORK/a_$tag.sock" >"$WORK/a_$tag.log" 2>&1 &

    # Wait (up to ~30s) for B to install the route to A`s stub 10.99.0.0/24.
    up=0
    for _ in $(seq 1 60); do
      if nsenter -t $BPID -n ip route show 10.99.0.0/24 | grep -q "proto ospf"; then up=1; break; fi
      sleep 0.5
    done
    echo "phase $tag: route-installed=$up" >>"$WORK/summary.txt"
    if [[ $up -ne 1 ]]; then pkill -f "$WORK/a_$tag.sock" 2>/dev/null || true; kill $BW 2>/dev/null || true; return; fi

    # Stop A with SIGINT (wren`s graceful shutdown) and leave it down; sample B`s route
    # for 8s. On graceful shutdown A floods its Grace-LSA (when GR is enabled) before exit.
    pkill -INT -f "$WORK/a_$tag.sock" 2>/dev/null || true
    missing=0; samples=0
    for _ in $(seq 1 16); do   # 16 x 0.5s = 8s = 2 dead intervals
      samples=$((samples+1))
      if ! nsenter -t $BPID -n ip route show 10.99.0.0/24 | grep -q "proto ospf"; then
        missing=$((missing+1))
      fi
      sleep 0.5
    done
    echo "phase $tag: missing=$missing/$samples" >>"$WORK/summary.txt"
    kill $BW 2>/dev/null || true
    nsenter -t $BPID -n ip route flush proto ospf 2>/dev/null || true
    sleep 0.5
  }

  run_phase gr
  run_phase nogr
  kill $BPID 2>/dev/null || true
'

echo "=== summary ==="
cat "$WORK/summary.txt" 2>/dev/null || { echo "FAIL: no summary produced"; exit 1; }
echo "=== B helper log (gr) ==="
sed -r 's/\x1b\[[0-9;]*m//g' "$WORK/b_gr.log" | grep -i "graceful-restart helper" || echo "(no helper log)"

ok=1
get() { grep "phase $1: $2=" "$WORK/summary.txt" | sed "s/.*$2=//"; }
b_gr="$(sed -r 's/\x1b\[[0-9;]*m//g' "$WORK/b_gr.log")"
b_nogr="$(sed -r 's/\x1b\[[0-9;]*m//g' "$WORK/b_nogr.log")"

# Both phases must have installed the route to begin with.
[[ "$(get gr route-installed)" == 1 ]]   || { echo "FAIL: gr phase never installed the stub route"; ok=0; }
[[ "$(get nogr route-installed)" == 1 ]] || { echo "FAIL: nogr phase never installed the stub route"; ok=0; }

# GR phase: B enters helper mode on the Grace-LSA...
grep -q "entering helper mode" <<<"$b_gr" \
  || { echo "FAIL: B never entered graceful-restart helper mode"; ok=0; }
# ...holds the adjacency (no inactivity teardown of A during the window)...
if grep -q "neighbour dead (inactivity).*neighbor=10.0.0.1" <<<"$b_gr"; then
  echo "FAIL: graceful restart still tore the adjacency down (inactivity) — helper did not hold"; ok=0
fi
# ...and so the route to A's stub stays installed the whole 8s window.
gr_missing="$(get gr missing | cut -d/ -f1)"
[[ "$gr_missing" == 0 ]] \
  || { echo "FAIL: graceful restart flapped the route ($gr_missing missing samples)"; ok=0; }

# Control phase: without a Grace-LSA, B expires A on the dead interval — the discriminator.
grep -q "neighbour dead (inactivity).*neighbor=10.0.0.1" <<<"$b_nogr" \
  || { echo "FAIL: control (no GR) did not expire the adjacency — test not discriminating"; ok=0; }
# And the control must NOT have entered helper mode (no Grace-LSA was sent).
if grep -q "entering helper mode" <<<"$b_nogr"; then
  echo "FAIL: control (no GR) entered helper mode despite no Grace-LSA"; ok=0
fi

if [[ $ok -ne 1 ]]; then
  echo "--- A gr log ---"; sed -r 's/\x1b\[[0-9;]*m//g' "$WORK/a_gr.log" | tail -20
  echo "--- B gr log ---"; sed -r 's/\x1b\[[0-9;]*m//g' "$WORK/b_gr.log" | tail -20
fi
[[ $ok -eq 1 ]] || exit 1
echo "ospf graceful restart (RFC 3623) smoke test: OK"
