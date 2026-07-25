#!/usr/bin/env bash
# IS-IS cryptographic authentication (RFC 5310) end to end.
#
# Two routers form an IS-IS point-to-point adjacency over a veth, like
# `isis-threeway-smoke.sh`, but with `auth-type = "hmac-sha256"` configured. Every
# PDU then carries an Authentication TLV (type 10, auth type 3) holding a Key ID
# and an HMAC-SHA-256 over the encoded PDU, and a PDU whose digest does not verify
# is dropped before it is even parsed.
#
# That gives the test its two halves, and both are needed: a run where the keys
# MATCH proves the digest is computed and verified consistently (a broken seal
# would leave the Apad placeholder on the wire and no adjacency would ever come
# up), and a run where they DIFFER proves the check actually rejects — an
# implementation that authenticated nothing would pass the first half alone.
#
# Like the other smoke scripts it runs rootless inside throwaway `unshare -Urn`
# namespaces (which grant CAP_NET_RAW) and never touches the host's interfaces.
#
# Topology: A (0000.0000.0001) <--IS-IS point-to-point, L1L2--> B (0000.0000.0002)
# over a veth.
#
# Usage:  bash scripts/isis-auth-smoke.sh
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
WREN="$REPO/target/debug/wren"

if [[ ! -x "$WREN" ]]; then
  echo "building wren (debug) ..."
  (cd "$REPO" && cargo build -p wren-daemon)
fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# Run one two-router scenario. $1 names it, $2 is B's key, $3 is "up" or "down":
# whether the adjacency is expected to come up.
run_case() {
  local name="$1" b_key="$2" expect="$3"
  local dir="$WORK/$name"
  mkdir -p "$dir"

  cat >"$dir/a.toml" <<EOF
router-id = "10.0.0.1"
[isis]
enabled = true
interfaces = ["veth0"]
system-id = "0000.0000.0001"
network-type = "point-to-point"
hello-interval = 3
auth-type = "hmac-sha256"
auth-key = "correct horse battery staple"
auth-key-id = 7
EOF

  cat >"$dir/b.toml" <<EOF
router-id = "10.0.0.2"
[isis]
enabled = true
interfaces = ["veth1"]
system-id = "0000.0000.0002"
network-type = "point-to-point"
hello-interval = 3
auth-type = "hmac-sha256"
auth-key = "$b_key"
auth-key-id = 7
EOF

  echo "=== case: $name (expecting the adjacency to stay/come $expect) ==="
  WREN="$WREN" DIR="$dir" EXPECT="$expect" unshare -Urn bash -c '
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

    nsenter -t $BPID -n "$WREN" --config "$DIR/b.toml" --backend kernel --socket "$DIR/b.sock" >"$DIR/b.log" 2>&1 &
    "$WREN" --config "$DIR/a.toml" --backend kernel --socket "$DIR/a.sock" >"$DIR/a.log" 2>&1 &
    # The three-way handshake completes over a few Hellos (Down -> Init -> Up).
    sleep 22

    echo "--- wren show isis neighbors (on A) ---"
    "$WREN" --socket "$DIR/a.sock" show isis neighbors 2>&1 | tee "$DIR/nbr_a.out" || true
    echo "--- wren show isis neighbors (on B) ---"
    nsenter -t $BPID -n "$WREN" --socket "$DIR/b.sock" show isis neighbors 2>&1 | tee "$DIR/nbr_b.out" || true

    ok=1
    a_up=0; b_up=0
    grep -Eq "0000.0000.0002 via .* dev veth0 level 1 state Up" "$DIR/nbr_a.out" && a_up=1
    grep -Eq "0000.0000.0001 via .* dev veth1 level 1 state Up" "$DIR/nbr_b.out" && b_up=1

    if [[ "$EXPECT" == up ]]; then
      # Matching keys: authentication must be transparent to adjacency formation.
      [[ $a_up -eq 1 ]] || { echo "FAIL: A does not see B Up despite matching keys"; ok=0; }
      [[ $b_up -eq 1 ]] || { echo "FAIL: B does not see A Up despite matching keys"; ok=0; }
    else
      # Mismatched keys: every PDU fails its digest check and is dropped, so neither
      # side may ever reach Up. A single Up here means authentication is not enforced.
      [[ $a_up -eq 0 ]] || { echo "FAIL: A reached Up with a mismatched key"; ok=0; }
      [[ $b_up -eq 0 ]] || { echo "FAIL: B reached Up with a mismatched key"; ok=0; }
    fi

    if [[ $ok -ne 1 ]]; then echo "--- A log ---"; cat "$DIR/a.log"; echo "--- B log ---"; cat "$DIR/b.log"; fi
    pkill -f "$DIR/a.sock" 2>/dev/null || true
    nsenter -t $BPID -n pkill -f "$DIR/b.sock" 2>/dev/null || true
    kill $BPID 2>/dev/null || true
    exit $(( ok == 1 ? 0 : 1 ))
  '
}

run_case matching "correct horse battery staple" up
run_case mismatched "a different secret entirely" down

echo "isis authentication smoke test: OK"
