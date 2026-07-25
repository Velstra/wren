#!/usr/bin/env bash
# IS-IS cryptographic authentication (RFC 5310) end to end.
#
# Two routers form an IS-IS point-to-point adjacency over a veth, like
# `isis-threeway-smoke.sh`, but with authentication configured. Every PDU then
# carries an Authentication TLV (type 10) holding a digest over the encoded PDU, and
# a PDU whose digest does not verify is dropped before it is even parsed. Both keyed
# schemes are covered: HMAC-SHA-256 (RFC 5310, auth type 3, with a Key ID) and
# HMAC-MD5 (RFC 5304, auth type 54, no Key ID).
#
# Four cases, and each rules out a different way of being wrong:
#   - matching keys must come UP — a broken seal would leave the placeholder on the
#     wire and no adjacency would ever form;
#   - mismatched keys must stay DOWN — an implementation that authenticated nothing
#     would sail through the first case alone;
#   - the same again for HMAC-MD5, whose digest input differs from RFC 5310's (the
#     Authentication Value is zeroed, not Apad-filled);
#   - and two routers using DIFFERENT schemes must not form an adjacency either.
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

KEY="correct horse battery staple"

# Run one two-router scenario. $1 names it, $2/$3 are A's and B's auth-type, $4 is
# B's key, $5 is "up" or "down": whether the adjacency is expected to come up.
run_case() {
  local name="$1" a_auth="$2" b_auth="$3" b_key="$4" expect="$5"
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
auth-type = "$a_auth"
auth-key = "$KEY"
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
auth-type = "$b_auth"
auth-key = "$b_key"
auth-key-id = 7
EOF

  echo "=== case: $name — A=$a_auth B=$b_auth (expecting the adjacency $expect) ==="
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
      # Matching config: authentication must be transparent to adjacency formation.
      [[ $a_up -eq 1 ]] || { echo "FAIL: A does not see B Up despite matching keys"; ok=0; }
      [[ $b_up -eq 1 ]] || { echo "FAIL: B does not see A Up despite matching keys"; ok=0; }
    else
      # Mismatched key or scheme: every PDU fails its check and is dropped, so neither
      # side may ever reach Up. A single Up here means authentication is not enforced.
      [[ $a_up -eq 0 ]] || { echo "FAIL: A reached Up despite the mismatch"; ok=0; }
      [[ $b_up -eq 0 ]] || { echo "FAIL: B reached Up despite the mismatch"; ok=0; }
    fi

    if [[ $ok -ne 1 ]]; then echo "--- A log ---"; cat "$DIR/a.log"; echo "--- B log ---"; cat "$DIR/b.log"; fi
    pkill -f "$DIR/a.sock" 2>/dev/null || true
    nsenter -t $BPID -n pkill -f "$DIR/b.sock" 2>/dev/null || true
    kill $BPID 2>/dev/null || true
    exit $(( ok == 1 ? 0 : 1 ))
  '
}

run_case sha256-matching   hmac-sha256 hmac-sha256 "$KEY"                        up
run_case sha256-mismatched hmac-sha256 hmac-sha256 "a different secret entirely" down
run_case md5-matching      hmac-md5    hmac-md5    "$KEY"                        up
# Same secret, different scheme: the digests differ in width, layout and input, so
# neither side may accept the other's PDUs.
run_case scheme-mismatch   hmac-sha256 hmac-md5    "$KEY"                        down

echo "isis authentication smoke test: OK"
