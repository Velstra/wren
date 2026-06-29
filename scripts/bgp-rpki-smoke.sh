#!/usr/bin/env bash
# BGP RPKI route-origin validation (RFC 6811) smoke test — a validating router accepts a
# route whose origin matches a ROA (Valid) and drops one whose origin does not (Invalid).
#
# Self-contained and rootless: it runs inside throwaway `unshare -Urn` namespaces and
# never touches the host's interfaces or uplink. Binding TCP 179 needs
# CAP_NET_BIND_SERVICE and installing a route needs CAP_NET_ADMIN, both held by the
# netns-root inside `unshare -Urn`. Per-daemon control sockets are Unix sockets.
#
# Topology: A (AS 65001, validating) <-eBGP-> B (AS 65002, passive, origin), over an
# IPv4 veth (10.0.0.0/24). B originates two prefixes:
#   - 10.99.0.0/24 — a ROA on A authorises AS 65002 for it → Valid → accepted + installed
#   - 10.88.0.0/24 — a ROA on A authorises only AS 65003 for it → Invalid → rejected
# A has `rpki-reject-invalid = true`, so the Invalid route never enters its RIB or the
# kernel, while the Valid route is installed `proto bgp`.
#
# NOTE on shell options: the outer `set -euo pipefail` exports SHELLOPTS (incl. nounset)
# into the inner `unshare -Urn bash -c` block; the netns block only writes output files
# and the assertions run in the OUTER shell afterwards.
#
# Usage:  bash scripts/bgp-rpki-smoke.sh
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
WREN="$REPO/target/debug/wren"

if [[ ! -x "$WREN" ]]; then
  echo "building wren (debug) ..."
  (cd "$REPO" && cargo build -p wren-daemon)
fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# A — validating router: rejects RPKI-Invalid routes; two ROAs (one matches B, one not).
cat >"$WORK/a.toml" <<EOF
router-id = "10.0.0.1"
[bgp]
enabled             = true
local-as            = 65001
rpki-reject-invalid = true
[[bgp.roa]]
prefix    = "10.99.0.0/24"
max-length = 24
origin-as = 65002
[[bgp.roa]]
prefix    = "10.88.0.0/24"
max-length = 24
origin-as = 65003
[[bgp.neighbor]]
address   = "10.0.0.2"
remote-as = 65002
EOF

# B — origin: announces both prefixes (both with AS 65002 as the origin).
cat >"$WORK/b.toml" <<EOF
router-id = "10.0.0.2"
[bgp]
enabled  = true
local-as = 65002
network  = ["10.99.0.0/24", "10.88.0.0/24"]
[[bgp.neighbor]]
address   = "10.0.0.1"
remote-as = 65001
passive   = true
EOF

export WREN WORK
unshare -Urn bash -c '
  set -e
  ip link set lo up
  setsid unshare -n -- sleep 40 & BPID=$!
  sleep 0.3
  ip link add veth0 type veth peer name veth1
  ip link set veth1 netns $BPID
  ip addr add 10.0.0.1/24 dev veth0
  ip link set veth0 up
  nsenter -t $BPID -n ip addr add 10.0.0.2/24 dev veth1
  nsenter -t $BPID -n ip link set veth1 up
  nsenter -t $BPID -n ip link set lo up

  nsenter -t $BPID -n "$WREN" --config "$WORK/b.toml" --backend kernel --socket "$WORK/b.sock" >"$WORK/b.log" 2>&1 &
  "$WREN" --config "$WORK/a.toml" --backend kernel --socket "$WORK/a.sock" >"$WORK/a.log" 2>&1 &
  sleep 8

  "$WREN" --socket "$WORK/a.sock" show bgp roa >"$WORK/a_roa.txt" 2>&1 || true
  "$WREN" --socket "$WORK/a.sock" show bgp     >"$WORK/a_bgp.txt" 2>&1 || true
  ip -4 route show proto bgp >"$WORK/a_kernel.txt" 2>&1 || true

  pkill -f "$WORK/a.sock" 2>/dev/null || true
  nsenter -t $BPID -n pkill -f "$WORK/b.sock" 2>/dev/null || true
  kill $BPID 2>/dev/null || true
'

echo "=== A: wren show bgp roa ==="
cat "$WORK/a_roa.txt"
echo "=== A: wren show bgp ==="
cat "$WORK/a_bgp.txt"
echo "=== A: ip -4 route show proto bgp ==="
cat "$WORK/a_kernel.txt"

ok=1
# The ROA table is visible operationally.
grep -Eq "10.99.0.0/24 maxlen 24 as 65002" "$WORK/a_roa.txt" \
  || { echo "FAIL: show bgp roa missing the 10.99.0.0/24 ROA"; ok=0; }
# The Valid route is accepted and tagged 'rpki valid'.
grep -Eq "10.99.0.0/24 .* rpki valid" "$WORK/a_bgp.txt" \
  || { echo "FAIL: A did not accept 10.99.0.0/24 as RPKI valid"; ok=0; }
# The Invalid route was dropped at import — it is not in A's BGP RIB at all.
grep -q "10.88.0.0/24" "$WORK/a_bgp.txt" \
  && { echo "FAIL: A accepted the RPKI-invalid 10.88.0.0/24 into its RIB"; ok=0; }
# …and the Valid route is in the kernel while the Invalid one is not.
grep -q "10.99.0.0/24" "$WORK/a_kernel.txt" \
  || { echo "FAIL: A did not install the valid 10.99.0.0/24 in the kernel"; ok=0; }
grep -q "10.88.0.0/24" "$WORK/a_kernel.txt" \
  && { echo "FAIL: A installed the RPKI-invalid 10.88.0.0/24 in the kernel"; ok=0; }

if [[ $ok -ne 1 ]]; then echo "--- A log ---"; tail -20 "$WORK/a.log"; echo "--- B log ---"; tail -20 "$WORK/b.log"; fi
[[ $ok -eq 1 ]] || exit 1
echo "bgp rpki origin-validation (RFC 6811) smoke test: OK"
