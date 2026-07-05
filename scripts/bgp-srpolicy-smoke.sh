#!/usr/bin/env bash
# BGP SR Policy (SAFI 73, RFC 9256) smoke test. A controller advertises an SR Policy
# candidate path over BGP SR Policy; a headend receiver negotiates SAFI 73, installs
# the candidate into its SR Policy RIB, and `show bgp sr-policy` displays the selected
# policy with its binding SID and SRv6 segment list.
#
# Like the other bgp-*-smoke.sh scripts it runs inside throwaway `unshare -Urn`
# namespaces and never touches the host's interfaces or uplink. BGP binds TCP 179
# (CAP_NET_BIND_SERVICE), held by the netns-root.
#
# Topology: CTRL (AS 65000, 10.0.0.1) originates one SR Policy — colour 100, endpoint
# 10.0.0.9, preference 200, an SRv6 binding SID and a two-SID SRv6 segment list — and
# peers iBGP with HEAD (AS 65000, 10.0.0.2) over a direct veth, both with
# `srpolicy = true`.
#
# The wren-side deliverable stops at the RIB and its `show`; programming the SID list
# into a forwarding datapath (the fabric eBPF steering) is a separate, privileged step
# done elsewhere.
#
# Usage:  bash scripts/bgp-srpolicy-smoke.sh
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
WREN="$REPO/target/debug/wren"

if [[ ! -x "$WREN" ]]; then
  echo "building wren (debug) ..."
  (cd "$REPO" && cargo build -p wren-daemon)
fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# CTRL — the SR Policy controller: originates one candidate path.
cat >"$WORK/ctrl.toml" <<EOF
router-id = "10.0.0.1"
[bgp]
enabled  = true
local-as = 65000
[[bgp.srpolicy]]
color        = 100
endpoint     = "10.0.0.9"
preference   = 200
binding-sid  = "2001:db8:b::1"
name         = "blue-te"
segment-list = ["2001:db8:1::1", "2001:db8:2::1"]
weight       = 1
[[bgp.neighbor]]
address   = "10.0.0.2"
remote-as = 65000
srpolicy  = true
EOF

# HEAD — the headend receiver: installs whatever SR Policies it learns.
cat >"$WORK/head.toml" <<EOF
router-id = "10.0.0.2"
[bgp]
enabled  = true
local-as = 65000
[[bgp.neighbor]]
address   = "10.0.0.1"
remote-as = 65000
srpolicy  = true
EOF

export WREN WORK
unshare -Urn bash -c '
  set -e
  ip link set lo up
  setsid unshare -n -- sleep 120 & HPID=$!
  sleep 0.3
  ip link add veth0 type veth peer name veth1
  ip link set veth1 netns $HPID
  ip addr add 10.0.0.1/24 dev veth0; ip link set veth0 up
  nsenter -t $HPID -n ip addr add 10.0.0.2/24 dev veth1
  nsenter -t $HPID -n ip link set veth1 up
  nsenter -t $HPID -n ip link set lo up

  "$WREN" --config "$WORK/ctrl.toml" --backend kernel --socket "$WORK/ctrl.sock" >"$WORK/ctrl.log" 2>&1 &
  nsenter -t $HPID -n "$WREN" --config "$WORK/head.toml" --backend kernel --socket "$WORK/head.sock" >"$WORK/head.log" 2>&1 &
  sleep 16

  {
    echo "=== CTRL: show bgp neighbors ==="
    "$WREN" --socket "$WORK/ctrl.sock" show bgp neighbors || true
    echo "=== HEAD: show bgp sr-policy ==="
    nsenter -t $HPID -n "$WREN" --socket "$WORK/head.sock" show bgp sr-policy || true
    echo "=== HEAD: show sr-policy ==="
    nsenter -t $HPID -n "$WREN" --socket "$WORK/head.sock" show sr-policy || true
  } >"$WORK/out.txt" 2>&1

  pkill -f "$WORK/ctrl.sock" 2>/dev/null || true
  nsenter -t $HPID -n pkill -f "$WORK/head.sock" 2>/dev/null || true
  kill $HPID 2>/dev/null || true
'

cat "$WORK/out.txt"

ok=1
# The iBGP session came up (SAFI 73 negotiated in the OPEN).
grep -q "10.0.0.2 AS 65000 Established" "$WORK/out.txt" \
  || { echo "FAIL: CTRL-HEAD session not Established"; ok=0; }

# The headend installed the policy with its colour, endpoint, preference, binding SID,
# name and both SRv6 segment SIDs.
line="$(grep "color 100 endpoint 10.0.0.9" "$WORK/out.txt" | head -1 || true)"
[[ -n "$line" ]] || { echo "FAIL: HEAD did not install the SR Policy (colour/endpoint)"; ok=0; }
echo "$line" | grep -q "pref 200"            || { echo "FAIL: SR Policy missing preference 200"; ok=0; }
echo "$line" | grep -q "bsid 2001:db8:b::1"  || { echo "FAIL: SR Policy missing binding SID"; ok=0; }
echo "$line" | grep -q "name blue-te"        || { echo "FAIL: SR Policy missing name"; ok=0; }
echo "$line" | grep -q "2001:db8:1::1"       || { echo "FAIL: SR Policy missing first segment SID"; ok=0; }
echo "$line" | grep -q "2001:db8:2::1"       || { echo "FAIL: SR Policy missing second segment SID"; ok=0; }

[[ $ok -eq 1 ]] || { echo "--- logs ---"; tail -8 "$WORK"/ctrl.log "$WORK"/head.log 2>/dev/null; exit 1; }
echo "bgp SR Policy (SAFI 73, RFC 9256) smoke test: OK"
