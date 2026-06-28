#!/usr/bin/env bash
# RIP / RIPng operational `show` smoke test — `wren show rip` and `wren show ripng`
# render the distance-vector table out of the running engine. Self-contained and
# rootless.
#
# Like the other *-smoke.sh scripts it runs inside throwaway `unshare -Urn`
# namespaces and never touches the host's interfaces or uplink. RIP's per-interface
# UDP sockets use SO_BINDTODEVICE (CAP_NET_RAW, held by the netns-root inside
# `unshare -Urn`); the control sockets are Unix sockets under a temp dir.
#
# Topology: A <--RIP+RIPng--> B over one veth (dual-stack 10.0.0.0/24 +
# 2001:db8::/64). A has a static IPv4 and IPv6 route and redistributes both into
# RIP / RIPng, so B learns them. The test then queries each engine's table over the
# control socket and asserts:
#   * `show rip`   on B lists 10.99.0.0/24 via 10.0.0.1 at metric 2;
#   * `show ripng` on B lists 2001:db8:99::/64 via a link-local at metric 2;
#   * `show rip`   on A tags its own networks (connected) / (redistributed).
#
# Usage:  bash scripts/rip-show-smoke.sh
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
WREN="$REPO/target/debug/wren"

if [[ ! -x "$WREN" ]]; then
  echo "building wren (debug) ..."
  (cd "$REPO" && cargo build -p wren-daemon)
fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# A — dual-stack RIP+RIPng, redistributing a static IPv4 and IPv6 route.
cat >"$WORK/a.toml" <<EOF
router-id = "10.0.0.1"
[[static]]
prefix = "10.99.0.0/24"
via    = "10.0.0.2"
[[static]]
prefix = "2001:db8:99::/64"
via    = "2001:db8::2"
[rip]
enabled      = true
interfaces   = ["veth0"]
redistribute = ["static"]
[ripng]
enabled      = true
interfaces   = ["veth0"]
redistribute = ["static"]
EOF

# B — plain dual-stack RIP+RIPng; learns A's redistributed networks.
cat >"$WORK/b.toml" <<EOF
router-id = "10.0.0.2"
[rip]
enabled    = true
interfaces = ["veth1"]
[ripng]
enabled    = true
interfaces = ["veth1"]
EOF

export WREN WORK
unshare -Urn bash -c '
  set -e
  ip link set lo up
  setsid unshare -n -- sleep 90 & BPID=$!
  sleep 0.3
  ip link add veth0 type veth peer name veth1
  ip link set veth1 netns $BPID
  ip addr add 10.0.0.1/24 dev veth0
  ip addr add 2001:db8::1/64 dev veth0
  ip link set veth0 up
  nsenter -t $BPID -n ip addr add 10.0.0.2/24 dev veth1
  nsenter -t $BPID -n ip addr add 2001:db8::2/64 dev veth1
  nsenter -t $BPID -n ip link set veth1 up
  nsenter -t $BPID -n ip link set lo up
  # Let IPv6 DAD settle so the global + link-local addresses are usable.
  sleep 2

  "$WREN" --config "$WORK/a.toml" --backend kernel --socket "$WORK/a.sock" >"$WORK/a.log" 2>&1 &
  nsenter -t $BPID -n "$WREN" --config "$WORK/b.toml" --backend kernel --socket "$WORK/b.sock" >"$WORK/b.log" 2>&1 &
  sleep 13

  ok=1
  {
    echo "=== wren show rip (on B) ==="
    nsenter -t $BPID -n "$WREN" --socket "$WORK/b.sock" show rip || true
    echo "=== wren show ripng (on B) ==="
    nsenter -t $BPID -n "$WREN" --socket "$WORK/b.sock" show ripng || true
    echo "=== wren show rip (on A) ==="
    "$WREN" --socket "$WORK/a.sock" show rip || true
    echo "=== wren show ripng (on A) ==="
    "$WREN" --socket "$WORK/a.sock" show ripng || true
  } > "$WORK/out.txt" 2>&1
  cat "$WORK/out.txt"

  # B learned A’s redistributed networks, via RIP (IPv4) and RIPng (IPv6).
  grep -q "10.99.0.0/24 via 10.0.0.1 dev veth1 metric 2" "$WORK/out.txt" \
    || { echo "FAIL: show rip on B missing 10.99.0.0/24 via 10.0.0.1 metric 2"; ok=0; }
  # (The next hop is the neighbour address as RIPng advertised it — a link-local,
  # or a global depending on the kernel source-address choice for the dual-stack
  # link; show ripng renders whichever the table holds, so match either.)
  grep -qE "2001:db8:99::/64 via .* dev veth1 metric 2" "$WORK/out.txt" \
    || { echo "FAIL: show ripng on B missing 2001:db8:99::/64 via … metric 2"; ok=0; }

  # A tags its own table: the veth network connected, the static redistributed.
  grep -q "10.0.0.0/24 dev veth0 metric 1 (connected)" "$WORK/out.txt" \
    || { echo "FAIL: show rip on A missing the connected veth network"; ok=0; }
  grep -q "10.99.0.0/24 metric 1 (redistributed)" "$WORK/out.txt" \
    || { echo "FAIL: show rip on A missing the redistributed static"; ok=0; }

  if [[ $ok -ne 1 ]]; then
    echo "--- A log ---"; cat "$WORK/a.log"
    echo "--- B log ---"; cat "$WORK/b.log"
  fi
  kill $BPID 2>/dev/null || true
  exit $(( ok == 1 ? 0 : 1 ))
'
echo "rip/ripng show smoke test: OK"
