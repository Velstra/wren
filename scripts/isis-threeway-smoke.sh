#!/usr/bin/env bash
# IS-IS point-to-point three-way handshake (RFC 5303) end to end.
#
# Two routers form an IS-IS point-to-point adjacency over a veth, like
# `isis-show-smoke.sh`. Both now advertise the Point-to-Point Three-Way Adjacency
# TLV (type 240) and gate the adjacency on it: a p2p link reaches Up ONLY once each
# side sees the other echo its System ID + Extended Local Circuit ID (RFC 5303 §3),
# i.e. the handshake converged Down -> Initializing -> Up. So the adjacency simply
# reaching `state Up` is the proof that the three-way handshake works on the wire —
# with a broken gate it would never leave Initializing.
#
# Like the other smoke scripts it runs rootless inside throwaway `unshare -Urn`
# namespaces (which grant CAP_NET_RAW) and never touches the host's interfaces.
#
# Topology: A (0000.0000.0001) <--IS-IS point-to-point, L1L2--> B (0000.0000.0002)
# over a veth.
#
# Usage:  bash scripts/isis-threeway-smoke.sh
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
[isis]
enabled = true
interfaces = ["veth0"]
system-id = "0000.0000.0001"
network-type = "point-to-point"
hello-interval = 3
EOF

cat >"$WORK/b.toml" <<EOF
router-id = "10.0.0.2"
[isis]
enabled = true
interfaces = ["veth1"]
system-id = "0000.0000.0002"
network-type = "point-to-point"
hello-interval = 3
EOF

export WREN WORK
unshare -Urn bash -c '
  set -e
  ip link set lo up
  setsid unshare -n -- sleep 120 & BPID=$!
  sleep 0.3
  ip link add veth0 type veth peer name veth1
  ip link set veth1 netns $BPID
  ip addr add 2001:db8::1/64 dev veth0; ip link set veth0 up
  nsenter -t $BPID -n ip addr add 2001:db8::2/64 dev veth1
  nsenter -t $BPID -n ip link set veth1 up
  nsenter -t $BPID -n ip link set lo up
  sleep 2

  nsenter -t $BPID -n "$WREN" --config "$WORK/b.toml" --backend kernel --socket "$WORK/b.sock" >"$WORK/b.log" 2>&1 &
  "$WREN" --config "$WORK/a.toml" --backend kernel --socket "$WORK/a.sock" >"$WORK/a.log" 2>&1 &
  # The three-way handshake completes over a few Hellos (Down -> Init -> Up).
  sleep 22

  echo "=== wren show isis neighbors (on A) ==="
  "$WREN" --socket "$WORK/a.sock" show isis neighbors 2>&1 | tee "$WORK/nbr_a.out" || true
  echo "=== wren show isis neighbors (on B) ==="
  nsenter -t $BPID -n "$WREN" --socket "$WORK/b.sock" show isis neighbors 2>&1 | tee "$WORK/nbr_b.out" || true

  ok=1
  # Both directions must reach Up: three-way is bidirectional, so a one-sided Up
  # (the exact failure three-way exists to prevent) would fail here.
  grep -Eq "0000.0000.0002 via .* dev veth0 level 1 state Up" "$WORK/nbr_a.out" \
    || { echo "FAIL: A does not see B Up (three-way did not converge on A)"; ok=0; }
  grep -Eq "0000.0000.0001 via .* dev veth1 level 1 state Up" "$WORK/nbr_b.out" \
    || { echo "FAIL: B does not see A Up (three-way did not converge on B)"; ok=0; }

  if [[ $ok -ne 1 ]]; then echo "--- A log ---"; cat "$WORK/a.log"; echo "--- B log ---"; cat "$WORK/b.log"; fi
  pkill -f "$WORK/a.sock" 2>/dev/null || true
  nsenter -t $BPID -n pkill -f "$WORK/b.sock" 2>/dev/null || true
  kill $BPID 2>/dev/null || true
  exit $(( ok == 1 ? 0 : 1 ))
'
echo "isis three-way smoke test: OK"
