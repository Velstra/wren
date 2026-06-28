#!/usr/bin/env bash
# OSPF redistribution smoke test — the router pushes RIB best-path routes into
# OSPF, which originates them as AS-external (type-5) LSAs. Self-contained, rootless.
#
# Like the bgp-*-smoke.sh scripts it runs inside throwaway `unshare -Urn`
# namespaces and never touches the host's interfaces or uplink. OSPF's raw
# IPPROTO_OSPF (89) sockets need CAP_NET_RAW, which the netns-root inside
# `unshare -Urn` holds.
#
# Topology: A <--OSPF p2p, area 0--> B over a veth. A has a *static* route
# 10.99.0.0/24 in its RIB. Two phases prove redistribution carries it into OSPF:
#   * phase 1 — A has NO `redistribute`: B must NOT learn 10.99.0.0/24;
#   * phase 2 — A has `redistribute = ["static"]`: B must learn 10.99.0.0/24 as an
#     OSPF AS-external route and install it `proto ospf`.
#
# OSPF convergence (Hello 10s / Dead 40s) means each phase waits ~30s.
#
# Usage:  bash scripts/ospf-redistribute-smoke.sh
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
WREN="$REPO/target/debug/wren"

if [[ ! -x "$WREN" ]]; then
  echo "building wren (debug) ..."
  (cd "$REPO" && cargo build -p wren-daemon)
fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# B is identical across both phases: plain OSPF on the p2p link.
cat >"$WORK/b.toml" <<EOF
router-id = "10.0.0.2"
[ospf]
enabled = true
interfaces = ["veth1"]
network-type = "point-to-point"
EOF

# A phase 1: a static route, but no redistribution.
cat >"$WORK/a1.toml" <<EOF
router-id = "10.0.0.1"
[[static]]
prefix = "10.99.0.0/24"
via    = "10.0.0.2"
[ospf]
enabled = true
interfaces = ["veth0"]
network-type = "point-to-point"
EOF

# A phase 2: the same static, now redistributed into OSPF.
cat >"$WORK/a2.toml" <<EOF
router-id = "10.0.0.1"
[[static]]
prefix = "10.99.0.0/24"
via    = "10.0.0.2"
[ospf]
enabled      = true
interfaces   = ["veth0"]
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

  run_phase() {
    acfg="$1"; label="$2"
    nsenter -t $BPID -n "$WREN" --config "$WORK/b.toml" --backend kernel --socket "$WORK/b.sock" >"$WORK/b.log" 2>&1 &
    "$WREN" --config "$acfg" --backend kernel --socket "$WORK/a.sock" >"$WORK/a.log" 2>&1 &
    sleep 32
    echo "=== phase $label: wren show routes ospf (on B) ==="
    nsenter -t $BPID -n "$WREN" --socket "$WORK/b.sock" show routes ospf || true
    echo "=== phase $label: ip route proto ospf (on B) ==="
    nsenter -t $BPID -n ip route show proto ospf || true
    pkill -f "$WORK/a.sock" 2>/dev/null || true
    nsenter -t $BPID -n pkill -f "$WORK/b.sock" 2>/dev/null || true
    sleep 1
  }

  ok=1

  # Phase 1: no redistribution — B must not see the static.
  run_phase "$WORK/a1.toml" "1 (no redistribute)" > "$WORK/p1.out" 2>&1
  cat "$WORK/p1.out"
  if grep -q "10.99.0.0/24" "$WORK/p1.out"; then
    echo "FAIL: B learned 10.99.0.0/24 without redistribution"; ok=0
  fi

  # Phase 2: redistribute static — B must learn and install it proto ospf.
  run_phase "$WORK/a2.toml" "2 (redistribute static)" > "$WORK/p2.out" 2>&1
  cat "$WORK/p2.out"
  grep -q "10.99.0.0/24" "$WORK/p2.out"            || { echo "FAIL: B missing redistributed external route"; ok=0; }
  grep -q "10.99.0.0/24 via 10.0.0.1 dev" "$WORK/p2.out" || { echo "FAIL: route not installed proto ospf on B"; ok=0; }

  if [[ $ok -ne 1 ]]; then echo "--- A log ---"; cat "$WORK/a.log"; echo "--- B log ---"; cat "$WORK/b.log"; fi
  kill $BPID 2>/dev/null || true
  exit $(( ok == 1 ? 0 : 1 ))
'
echo "ospf redistribute smoke test: OK"
