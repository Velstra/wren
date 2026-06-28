#!/usr/bin/env bash
# RIPng redistribution smoke test — the router pushes RIB best-path routes into
# RIPng, which advertises them to neighbours over IPv6. Self-contained, rootless.
#
# The IPv6 sibling of rip-redistribute-smoke.sh: it runs inside throwaway
# `unshare -Urn` namespaces and never touches the host's interfaces or uplink.
# RIPng's per-interface UDP sockets use SO_BINDTODEVICE, which needs CAP_NET_RAW —
# held by the netns-root inside `unshare -Urn`.
#
# Topology: A <--RIPng--> B over a veth, both on [ff02::9]:521. A has a *static*
# IPv6 route 2001:db8:99::/64 in its RIB. Two phases prove redistribution carries
# it:
#   * phase 1 — A has NO `redistribute`: B must NOT learn 2001:db8:99::/64;
#   * phase 2 — A has `redistribute = ["static"]`: B must learn 2001:db8:99::/64
#     over RIPng and install it `proto rip`.
#
# Usage:  bash scripts/ripng-redistribute-smoke.sh
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
WREN="$REPO/target/debug/wren"

if [[ ! -x "$WREN" ]]; then
  echo "building wren (debug) ..."
  (cd "$REPO" && cargo build -p wren-daemon)
fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# B is identical across both phases: plain RIPng on the link.
cat >"$WORK/b.toml" <<EOF
router-id = "10.0.0.2"
[ripng]
enabled = true
interfaces = ["veth1"]
EOF

# A phase 1: a static IPv6 route, but no redistribution.
cat >"$WORK/a1.toml" <<EOF
router-id = "10.0.0.1"
[[static]]
prefix = "2001:db8:99::/64"
via    = "2001:db8::2"
[ripng]
enabled = true
interfaces = ["veth0"]
EOF

# A phase 2: the same static, now redistributed into RIPng.
cat >"$WORK/a2.toml" <<EOF
router-id = "10.0.0.1"
[[static]]
prefix = "2001:db8:99::/64"
via    = "2001:db8::2"
[ripng]
enabled      = true
interfaces   = ["veth0"]
redistribute = ["static"]
EOF

export WREN WORK
unshare -Urn bash -c '
  set -e
  ip link set lo up
  setsid unshare -n -- sleep 90 & BPID=$!
  sleep 0.3
  ip link add veth0 type veth peer name veth1
  ip link set veth1 netns $BPID
  ip addr add 2001:db8::1/64 dev veth0; ip link set veth0 up
  nsenter -t $BPID -n ip addr add 2001:db8::2/64 dev veth1
  nsenter -t $BPID -n ip link set veth1 up
  nsenter -t $BPID -n ip link set lo up
  # Let DAD settle so the global + link-local addresses are usable.
  sleep 2

  run_phase() {
    acfg="$1"; label="$2"
    nsenter -t $BPID -n "$WREN" --config "$WORK/b.toml" --backend kernel --socket "$WORK/b.sock" >"$WORK/b.log" 2>&1 &
    "$WREN" --config "$acfg" --backend kernel --socket "$WORK/a.sock" >"$WORK/a.log" 2>&1 &
    sleep 12
    echo "=== phase $label: wren show routes rip (on B) ==="
    nsenter -t $BPID -n "$WREN" --socket "$WORK/b.sock" show routes rip || true
    echo "=== phase $label: ip -6 route proto rip (on B) ==="
    nsenter -t $BPID -n ip -6 route show proto rip || true
    pkill -f "$WORK/a.sock" 2>/dev/null || true
    nsenter -t $BPID -n pkill -f "$WORK/b.sock" 2>/dev/null || true
    sleep 1
  }

  ok=1

  # Phase 1: no redistribution — B must not see the static.
  run_phase "$WORK/a1.toml" "1 (no redistribute)" > "$WORK/p1.out" 2>&1
  cat "$WORK/p1.out"
  if grep -q "2001:db8:99::/64" "$WORK/p1.out"; then
    echo "FAIL: B learned 2001:db8:99::/64 without redistribution"; ok=0
  fi

  # Phase 2: redistribute static — B must learn and install it proto rip.
  run_phase "$WORK/a2.toml" "2 (redistribute static)" > "$WORK/p2.out" 2>&1
  cat "$WORK/p2.out"
  grep -q "2001:db8:99::/64" "$WORK/p2.out"          || { echo "FAIL: B missing redistributed route"; ok=0; }
  grep -q "2001:db8:99::/64 via fe80" "$WORK/p2.out" || { echo "FAIL: route not installed proto rip on B"; ok=0; }

  if [[ $ok -ne 1 ]]; then echo "--- A log ---"; cat "$WORK/a.log"; echo "--- B log ---"; cat "$WORK/b.log"; fi
  kill $BPID 2>/dev/null || true
  exit $(( ok == 1 ? 0 : 1 ))
'
echo "ripng redistribute smoke test: OK"
