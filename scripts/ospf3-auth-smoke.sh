#!/usr/bin/env bash
# OSPFv3 authentication (RFC 7166 HMAC-SHA-256 Authentication Trailer) end to end.
#
# Two routers form an OSPFv3 point-to-point adjacency over a veth, exactly like
# `ospf3-show-smoke.sh`, but with `[ospf3] auth-type = "hmac-sha256"` configured.
# Run in two scenarios:
#   1. Matching keys  -> the adjacency reaches Full (authenticated Hellos and the
#      database exchange verify), proving the trailer round-trips on the wire.
#   2. Mismatched keys -> the adjacency never forms (every packet is dropped as
#      BadAuth), proving authentication is actually enforced, not cosmetic.
#
# Like the other smoke scripts it runs inside throwaway `unshare -Urn` namespaces
# and never touches the host interfaces or uplink. OSPFv3 uses a raw IPPROTO_OSPF
# (89) socket over IPv6, needing CAP_NET_RAW — held by the netns-root inside
# `unshare -Urn`. Per-daemon control sockets are Unix sockets under a temp dir.
#
# Topology: A (router-id 10.0.0.1) <--OSPFv3 point-to-point--> B (10.0.0.2) over a
# veth, area 0.0.0.0, adjacency over IPv6 link-local.
#
# Usage:  bash scripts/ospf3-auth-smoke.sh
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
WREN="$REPO/target/debug/wren"

if [[ ! -x "$WREN" ]]; then
  echo "building wren (debug) ..."
  (cd "$REPO" && cargo build -p wren-daemon)
fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# Run one scenario. $1 = A's key, $2 = B's key, $3 = "full" | "nofull", $4 = label.
run_scenario() {
  local a_key="$1" b_key="$2" expect="$3" label="$4"
  echo "=== scenario: $label (A key=$a_key, B key=$b_key, expect=$expect) ==="

  cat >"$WORK/a.toml" <<EOF
router-id = "10.0.0.1"
[ospf3]
enabled = true
interfaces = ["veth0"]
network-type = "point-to-point"
auth-type = "hmac-sha256"
auth-key = "$a_key"
EOF

  cat >"$WORK/b.toml" <<EOF
router-id = "10.0.0.2"
[ospf3]
enabled = true
interfaces = ["veth1"]
network-type = "point-to-point"
auth-type = "hmac-sha256"
auth-key = "$b_key"
EOF

  export WREN WORK expect
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
    # Let IPv6 DAD settle so the link-local addresses are usable.
    sleep 2

    nsenter -t $BPID -n "$WREN" --config "$WORK/b.toml" --backend kernel --socket "$WORK/b.sock" >"$WORK/b.log" 2>&1 &
    "$WREN" --config "$WORK/a.toml" --backend kernel --socket "$WORK/a.sock" >"$WORK/a.log" 2>&1 &
    # Let the adjacency reach Full (hellos + database exchange), or fail to.
    sleep 35

    echo "--- wren show ospf3 neighbors (on A) ---"
    "$WREN" --socket "$WORK/a.sock" show ospf3 neighbors 2>&1 | tee "$WORK/nbr.out" || true

    ok=1
    if grep -qE "10.0.0.2 via fe80.* dev veth0 state Full" "$WORK/nbr.out"; then
      seen=full
    else
      seen=nofull
    fi
    if [[ "$seen" != "$expect" ]]; then
      echo "FAIL: expected $expect but saw $seen"
      echo "--- A log ---"; cat "$WORK/a.log"
      echo "--- B log ---"; cat "$WORK/b.log"
      ok=0
    fi

    pkill -f "$WORK/a.sock" 2>/dev/null || true
    nsenter -t $BPID -n pkill -f "$WORK/b.sock" 2>/dev/null || true
    kill $BPID 2>/dev/null || true
    exit $(( ok == 1 ? 0 : 1 ))
  '
}

# 1. Matching keys authenticate and the adjacency reaches Full.
run_scenario "a-shared-secret" "a-shared-secret" full "matching keys"
# 2. A mismatched key is rejected: no adjacency forms.
run_scenario "a-shared-secret" "the-wrong-key" nofull "mismatched keys"

echo "ospf3 auth smoke test: OK"
