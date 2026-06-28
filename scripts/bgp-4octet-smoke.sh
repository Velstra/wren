#!/usr/bin/env bash
# Two-router 4-octet-ASN eBGP smoke test (RFC 6793), fully self-contained.
#
# It runs entirely inside throwaway network namespaces created by `unshare -Urn`
# — it never touches the host's real interfaces, routes or uplink, and needs no
# root (the user+net namespace grants CAP_NET_ADMIN / CAP_NET_BIND_SERVICE inside
# itself only). It can also be run as root; either way nothing outside the
# throwaway namespaces is modified.
#
# Two wren speakers peer over a veth with **4-octet** ASNs that do NOT fit in 16
# bits (196618 and 4200000000). A route only installs if the 4-octet AS Number
# capability was negotiated and `effective_as()` read the real AS back from the
# capability — a legacy 2-octet code path would see AS_TRANS (23456), mismatch
# `remote-as`, and never reach Established. So a clean run proves the negotiation
# end to end.
#
# Usage:  bash scripts/bgp-4octet-smoke.sh
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
# Router A — AS 196618 (4-octet), active connector
router-id = "10.0.0.1"
[bgp]
enabled  = true
local-as = 196618
network  = ["10.10.0.0/24"]
[[bgp.neighbor]]
address   = "10.0.0.2"
remote-as = 4200000000
EOF

cat >"$WORK/b.toml" <<EOF
# Router B — AS 4200000000 (4-octet), passive listener
router-id = "10.0.0.2"
[bgp]
enabled  = true
local-as = 4200000000
network  = ["10.20.0.0/24"]
[[bgp.neighbor]]
address   = "10.0.0.1"
remote-as = 196618
passive   = true
EOF

export WREN WORK
unshare -Urn bash -c '
  set -e
  ip link set lo up
  # Router B lives in its own netns held open by a sleeper process.
  setsid unshare -n -- sleep 60 & BPID=$!
  sleep 0.3

  ip link add veth0 type veth peer name veth1
  ip link set veth1 netns $BPID
  ip addr add 10.0.0.1/24 dev veth0; ip link set veth0 up
  nsenter -t $BPID -n ip addr add 10.0.0.2/24 dev veth1
  nsenter -t $BPID -n ip link set veth1 up
  nsenter -t $BPID -n ip link set lo up

  # B (passive) first, then A (active connector).
  nsenter -t $BPID -n "$WREN" --config "$WORK/b.toml" --backend kernel \
      >"$WORK/b.log" 2>&1 &
  "$WREN" --config "$WORK/a.toml" --backend kernel >"$WORK/a.log" 2>&1 &

  # Give the session time to reach Established and exchange UPDATEs.
  sleep 6

  echo "=== Router A (AS 196618) routes ==="
  ip route
  echo "=== Router B (AS 4200000000) routes ==="
  nsenter -t $BPID -n ip route

  ok=1
  if ip route | grep -q "10.20.0.0/24.*proto bgp"; then
    echo "PASS: A installed B'\''s 10.20.0.0/24 via BGP"
  else
    echo "FAIL: A is missing B'\''s network"; ok=0
  fi
  if nsenter -t $BPID -n ip route | grep -q "10.10.0.0/24.*proto bgp"; then
    echo "PASS: B installed A'\''s 10.10.0.0/24 via BGP"
  else
    echo "FAIL: B is missing A'\''s network"; ok=0
  fi

  if [[ $ok -ne 1 ]]; then
    echo "--- A log ---"; cat "$WORK/a.log"
    echo "--- B log ---"; cat "$WORK/b.log"
  fi

  kill $BPID 2>/dev/null || true
  exit $(( ok == 1 ? 0 : 1 ))
'
echo "4-octet ASN BGP smoke test: OK"
