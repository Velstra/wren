#!/usr/bin/env bash
# OSPF stub-area smoke test (RFC 2328 §3.6) — a stub area carries no AS-external
# (type-5) LSAs; its area border router injects a default route instead.
# Self-contained, rootless.
#
# Like the other ospf-*-smoke.sh scripts it runs inside throwaway `unshare -Urn`
# namespaces and never touches the host's interfaces or uplink. OSPF's raw
# IPPROTO_OSPF (89) sockets need CAP_NET_RAW, which the netns-root inside
# `unshare -Urn` holds.
#
# Topology: A is an ABR (dummy0 in the backbone area 0.0.0.0 carrying 10.50.0.0/24,
# veth0 in area 0.0.0.1) and an ASBR (it redistributes a static 10.99.0.0/24 as a
# type-5 LSA). B is a pure area-0.0.0.1 internal router over the veth.
#
# Two phases differ only in whether area 0.0.0.1 is a stub:
#   * phase 1 — area 0.0.0.1 is a NORMAL area: B learns the external 10.99.0.0/24
#     (type-5) and gets NO default route;
#   * phase 2 — area 0.0.0.1 is a STUB area: B must NOT learn 10.99.0.0/24, and
#     instead gets a default 0.0.0.0/0 injected by A (type-3 summary). The
#     inter-area route 10.50.0.0/24 still flows (a plain stub, not totally stubby).
#
# OSPF convergence (Hello 10s / Dead 40s) means each phase waits ~34s.
#
# Usage:  bash scripts/ospf-stub-area-smoke.sh
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
WREN="$REPO/target/debug/wren"

if [[ ! -x "$WREN" ]]; then
  echo "building wren (debug) ..."
  (cd "$REPO" && cargo build -p wren-daemon)
fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# A (ABR + ASBR): dummy0 in the backbone, veth0 in area 0.0.0.1, redistributes a
# static. Phase 1 leaves the area normal; phase 2 marks it a stub.
cat >"$WORK/a1.toml" <<EOF
router-id = "10.0.0.1"
[[static]]
prefix = "10.99.0.0/24"
via    = "10.0.0.2"
[ospf]
enabled      = true
network-type = "point-to-point"
interfaces   = ["dummy0"]
redistribute = ["static"]
[[ospf.interface]]
name = "veth0"
area = "0.0.0.1"
EOF

cat >"$WORK/a2.toml" <<EOF
router-id = "10.0.0.1"
[[static]]
prefix = "10.99.0.0/24"
via    = "10.0.0.2"
[ospf]
enabled           = true
network-type      = "point-to-point"
interfaces        = ["dummy0"]
redistribute      = ["static"]
stub-areas        = ["0.0.0.1"]
stub-default-cost = 5
[[ospf.interface]]
name = "veth0"
area = "0.0.0.1"
EOF

# B (internal): only veth1, in area 0.0.0.1. Phase 2 agrees the area is a stub
# (both ends must, or the E-bit mismatch stops the adjacency).
cat >"$WORK/b1.toml" <<EOF
router-id = "10.0.0.2"
[ospf]
enabled      = true
network-type = "point-to-point"
area         = "0.0.0.1"
interfaces   = ["veth1"]
EOF

cat >"$WORK/b2.toml" <<EOF
router-id = "10.0.0.2"
[ospf]
enabled      = true
network-type = "point-to-point"
area         = "0.0.0.1"
interfaces   = ["veth1"]
stub-areas   = ["0.0.0.1"]
EOF

export WREN WORK
unshare -Urn bash -c '
  set -e
  ip link set lo up
  setsid unshare -n -- sleep 180 & BPID=$!
  sleep 0.3
  ip link add veth0 type veth peer name veth1
  ip link set veth1 netns $BPID
  ip link add dummy0 type dummy
  ip addr add 10.50.0.1/24 dev dummy0; ip link set dummy0 up
  ip addr add 10.0.0.1/24 dev veth0; ip link set veth0 up
  nsenter -t $BPID -n ip addr add 10.0.0.2/24 dev veth1
  nsenter -t $BPID -n ip link set veth1 up
  nsenter -t $BPID -n ip link set lo up

  run_phase() {
    acfg="$1"; bcfg="$2"; label="$3"
    nsenter -t $BPID -n "$WREN" --config "$bcfg" --backend kernel --socket "$WORK/b.sock" >"$WORK/b.log" 2>&1 &
    "$WREN" --config "$acfg" --backend kernel --socket "$WORK/a.sock" >"$WORK/a.log" 2>&1 &
    sleep 34
    echo "=== phase $label: wren show routes ospf (on B) ==="
    nsenter -t $BPID -n "$WREN" --socket "$WORK/b.sock" show routes ospf || true
    echo "=== phase $label: ip route proto ospf (on B) ==="
    nsenter -t $BPID -n ip route show proto ospf || true
    pkill -f "$WORK/a.sock" 2>/dev/null || true
    nsenter -t $BPID -n pkill -f "$WORK/b.sock" 2>/dev/null || true
    sleep 1
    # Clear any installed OSPF routes so the next phase starts from a clean slate.
    nsenter -t $BPID -n ip route flush proto ospf 2>/dev/null || true
    ip route flush proto ospf 2>/dev/null || true
  }

  ok=1

  # Phase 1: normal area — B sees the external, no default.
  run_phase "$WORK/a1.toml" "$WORK/b1.toml" "1 (normal area)" > "$WORK/p1.out" 2>&1
  cat "$WORK/p1.out"
  grep -q "10.99.0.0/24" "$WORK/p1.out" || { echo "FAIL: normal area: B did not learn external 10.99.0.0/24"; ok=0; }
  grep -qE "0.0.0.0/0|default" "$WORK/p1.out" && { echo "FAIL: normal area: B got an unexpected default route"; ok=0; }

  # Phase 2: stub area — no external, but an injected default; inter-area still flows.
  run_phase "$WORK/a2.toml" "$WORK/b2.toml" "2 (stub area)" > "$WORK/p2.out" 2>&1
  cat "$WORK/p2.out"
  grep -q "10.99.0.0/24" "$WORK/p2.out" && { echo "FAIL: stub area: B learned external 10.99.0.0/24 (should be suppressed)"; ok=0; }
  grep -qE "0.0.0.0/0 via 10.0.0.1|default via 10.0.0.1" "$WORK/p2.out" || { echo "FAIL: stub area: B did not get the injected default route"; ok=0; }
  grep -q "10.50.0.0/24 via 10.0.0.1" "$WORK/p2.out" || echo "NOTE: inter-area 10.50.0.0/24 not seen (soft)"

  if [[ $ok -ne 1 ]]; then echo "--- A log ---"; cat "$WORK/a.log"; echo "--- B log ---"; cat "$WORK/b.log"; fi
  kill $BPID 2>/dev/null || true
  exit $(( ok == 1 ? 0 : 1 ))
'
echo "ospf stub area smoke test: OK"
