#!/usr/bin/env bash
# IS-IS link-state database inspection smoke test — `wren show isis database`
# dumps the per-level link-state database the IS-IS task owns: every LSP held,
# grouped per level, with its ID, sequence number, checksum, lifetime and flags.
# Self-contained, rootless.
#
# Like the other isis-*-smoke.sh scripts it runs inside throwaway `unshare -Urn`
# namespaces and never touches the host's interfaces or uplink. IS-IS uses an
# AF_PACKET (802.2 LLC) socket per interface, which needs CAP_NET_RAW — held by
# the netns-root inside `unshare -Urn`. Per-daemon control sockets are Unix
# sockets under a temp dir, not the network.
#
# Topology: A (0000.0000.0001) <--IS-IS point-to-point, L1L2--> B (0000.0000.0002)
# over a veth. Once the L1L2 adjacency comes up and the databases synchronise,
# each router's database must hold BOTH routers' LSPs at BOTH levels:
#   level 1 lsp 0000.0000.0001 / 0000.0000.0002
#   level 2 lsp 0000.0000.0001 / 0000.0000.0002
#
# NOTE on shell options: the outer `set -euo pipefail` exports SHELLOPTS (incl.
# nounset) into the inner `unshare -Urn bash -c` block. To avoid that biting the
# assertions, the netns block only writes output files; the greps run in the
# OUTER shell afterwards.
#
# Usage:  bash scripts/isis-database-smoke.sh
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
  # IS-IS forms the adjacency over a few Hellos, then CSNP/PSNP synchronise the DBs.
  sleep 24

  "$WREN" --socket "$WORK/a.sock" show isis database >"$WORK/a_db.txt" 2>&1 || true
  nsenter -t $BPID -n "$WREN" --socket "$WORK/b.sock" show isis database >"$WORK/b_db.txt" 2>&1 || true

  pkill -f "$WORK/a.sock" 2>/dev/null || true
  nsenter -t $BPID -n pkill -f "$WORK/b.sock" 2>/dev/null || true
  kill $BPID 2>/dev/null || true
'

ok=1
for who in a b; do
  echo "=== $who: show isis database ==="; cat "$WORK/${who}_db.txt"
  # Both routers' LSPs must be present at both levels in each database.
  for level in 1 2; do
    for sys in 0000.0000.0001 0000.0000.0002; do
      grep -Eq "level $level lsp $sys\.00-00 seq 0x" "$WORK/${who}_db.txt" \
        || { echo "FAIL: $who is missing level $level LSP for $sys"; ok=0; }
    done
  done
done

if [[ $ok -ne 1 ]]; then echo "--- A log ---"; tail -10 "$WORK/a.log"; echo "--- B log ---"; tail -10 "$WORK/b.log"; fi
[[ $ok -eq 1 ]] || exit 1
echo "isis database smoke test: OK"
