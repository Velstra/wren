#!/usr/bin/env bash
# BGP RFC 8212 default-deny smoke test. An eBGP session with no configured policy
# exchanges nothing in either direction — and that is the behaviour of a router with
# nothing said about it, not something to switch on. Routes are received and discarded
# (§3), never a session reset, so the peer stays up and its withdrawals still land.
#
# Like the other bgp-*-smoke.sh scripts it runs inside throwaway `unshare -Urn`
# namespaces and never touches the host's interfaces or uplink. BGP binds TCP 179
# (CAP_NET_BIND_SERVICE), held by the netns-root.
#
# Topology: A (AS 65001, 10.0.0.1) originates 10.60.1.0/24 with `network` and peers
# eBGP with B (AS 65002, 10.0.0.2) over a direct veth.
#
# Six phases (each restarts both daemons fresh, proto-bgp flushed between). The two
# middle phases give exactly one side a policy, so each gate is proved on its own
# rather than by a single "nothing happened" that either gate could explain:
#   * deny       — nothing configured at all: the /24 does not cross. Both routers say
#                  so in the log, naming both silenced directions.
#   * exportgate — B imports accept-all, A still has NO export: the /24 does not cross,
#                  so A withheld a route it originates itself. The RFC gates the
#                  Adj-RIB-Out, not merely re-advertised transit.
#   * importgate — A exports accept-all, B still has NO import: A does send the /24 and
#                  B discards it, which is the phase where B's per-neighbour
#                  `policy-denied` counter has to move.
#   * policy     — both sides have a policy: the /24 crosses and is installed.
#   * optout     — no policy anywhere, but both neighbours set `require-policy = false`:
#                  the deliberate permit-all a lab or route server wants.
#   * global     — the same permit-all said speaker-wide with `[bgp]
#                  ebgp-require-policy = false` instead of per neighbour.
#
# Usage:  bash scripts/bgp-default-deny-smoke.sh
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
WREN="$REPO/target/debug/wren"

if [[ ! -x "$WREN" ]]; then
  echo "building wren (debug) ..."
  (cd "$REPO" && cargo build -p wren-daemon)
fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# An accept-all policy. Both routers reference it by name in the phases that have one;
# RFC 8212 asks only that a policy be *applied*, not that it filter anything.
allow_all='
[[filter]]
name    = "allow-all"
default = "accept"
'

# A — originates the /24 in every phase. `export = "allow-all"` is what changes.
write_a() { # write_a <tag> <extra neighbour lines> [extra [bgp] lines]
  cat >"$WORK/a_$1.toml" <<EOF
router-id = "10.0.0.1"
$allow_all
[bgp]
enabled  = true
local-as = 65001
network  = ["10.60.1.0/24"]
${3-}

[[bgp.neighbor]]
address   = "10.0.0.2"
remote-as = 65002
$2
EOF
}

# B — the receiver. `import = "allow-all"` is what changes.
write_b() { # write_b <tag> <extra neighbour lines> [extra [bgp] lines]
  cat >"$WORK/b_$1.toml" <<EOF
router-id = "10.0.0.2"
$allow_all
[bgp]
enabled  = true
local-as = 65002
${3-}

[[bgp.neighbor]]
address   = "10.0.0.1"
remote-as = 65001
$2
EOF
}

write_a deny       ""
write_b deny       ""
write_a exportgate ""
write_b exportgate 'import = "allow-all"'
write_a importgate 'export = "allow-all"'
write_b importgate ""
write_a policy     'export = "allow-all"'
write_b policy     'import = "allow-all"'
write_a optout     "require-policy = false"
write_b optout     "require-policy = false"
# The speaker-wide key instead of the per-neighbour one. It shares a code path with
# the per-neighbour opt-out, but it is the knob a lab or test rig actually reaches
# for — and the one every other script in scripts/ now depends on — so it is worth
# proving live rather than only in `effective_require_policy`'s unit test.
write_a global     "" "ebgp-require-policy = false"
write_b global     "" "ebgp-require-policy = false"

export WREN WORK
unshare -Urn bash -c '
  set -e
  ip link set lo up
  setsid unshare -n -- sleep 300 & BPID=$!
  sleep 0.3
  ip link add veth0 type veth peer name veth1
  ip link set veth1 netns $BPID
  ip addr add 10.0.0.1/24 dev veth0; ip link set veth0 up
  nsenter -t $BPID -n ip addr add 10.0.0.2/24 dev veth1
  nsenter -t $BPID -n ip link set veth1 up
  nsenter -t $BPID -n ip link set lo up

  run_phase() {
    tag="$1"
    "$WREN" --config "$WORK/a_$tag.toml" --backend kernel --socket "$WORK/a.sock" >"$WORK/a_$tag.log" 2>&1 &
    nsenter -t $BPID -n "$WREN" --config "$WORK/b_$tag.toml" --backend kernel --socket "$WORK/b.sock" >"$WORK/b_$tag.log" 2>&1 &
    sleep 16
    nsenter -t $BPID -n "$WREN" --socket "$WORK/b.sock" show bgp routes >"$WORK/${tag}_b_bgp.txt" 2>&1 || true
    nsenter -t $BPID -n "$WREN" --socket "$WORK/b.sock" show bgp neighbors >"$WORK/${tag}_b_nbr.txt" 2>&1 || true
    nsenter -t $BPID -n ip route show proto bgp >"$WORK/${tag}_b_kernel.txt" 2>&1 || true
    pkill -f "$WORK/a.sock" 2>/dev/null || true
    nsenter -t $BPID -n pkill -f "$WORK/b.sock" 2>/dev/null || true
    sleep 1
    ip route flush proto bgp 2>/dev/null || true
    nsenter -t $BPID -n ip route flush proto bgp 2>/dev/null || true
  }

  for phase in deny exportgate importgate policy optout global; do
    run_phase $phase
  done
  kill $BPID 2>/dev/null || true
'

ok=1
for tag in deny exportgate importgate policy optout global; do
  echo "=== phase $tag: B routes ==="; cat "$WORK/${tag}_b_bgp.txt"
  echo "=== phase $tag: B neighbors ==="; cat "$WORK/${tag}_b_nbr.txt"
done

# The session must come up in every phase — RFC 8212 discards routes, it does not
# refuse the peer. A test that passed because BGP never connected would prove nothing.
for tag in deny exportgate importgate policy optout global; do
  grep -q "Established" "$WORK/${tag}_b_nbr.txt" \
    || { echo "FAIL: $tag — the BGP session is not Established (8212 must not reset it)"; ok=0; }
done

# phase deny — nothing crosses, and both routers say why, naming both directions.
if grep -q "10.60.1.0/24" "$WORK/deny_b_bgp.txt"; then
  echo "FAIL: deny — B learned 10.60.1.0/24 with no policy configured anywhere (RFC 8212)"; ok=0
fi
for r in a b; do
  grep -q "RFC 8212" "$WORK/${r}_deny.log" \
    || { echo "FAIL: deny — router $r logged no RFC 8212 warning at establishment"; ok=0; }
  grep -q "import and export" "$WORK/${r}_deny.log" \
    || { echo "FAIL: deny — router $r did not name both silenced directions"; ok=0; }
done

# phase exportgate — B would accept anything, so A withholding its own originated
# /24 is the export gate covering `network`, not only re-advertised transit.
if grep -q "10.60.1.0/24" "$WORK/exportgate_b_bgp.txt"; then
  echo "FAIL: exportgate — A advertised its originated /24 with no export policy (RFC 8212)"; ok=0
fi

# phase importgate — A sends, B discards: the route is absent and the counter moved.
if grep -q "10.60.1.0/24" "$WORK/importgate_b_bgp.txt"; then
  echo "FAIL: importgate — B accepted 10.60.1.0/24 with no import policy (RFC 8212)"; ok=0
fi
grep -q "policy-denied" "$WORK/importgate_b_nbr.txt" \
  || { echo "FAIL: importgate — B discarded a route but shows no policy-denied counter"; ok=0; }

# phase policy — a policy on both sides re-enables the exchange end to end.
grep -q "10.60.1.0/24" "$WORK/policy_b_bgp.txt" \
  || { echo "FAIL: policy — B did not learn 10.60.1.0/24 with policies on both sides"; ok=0; }
grep -q "10.60.1.0/24 via 10.0.0.1" "$WORK/policy_b_kernel.txt" \
  || { echo "FAIL: policy — B did not install 10.60.1.0/24 proto bgp"; ok=0; }
# Nothing was denied in this phase, so the counter must stay off the line entirely.
if grep -q "policy-denied" "$WORK/policy_b_nbr.txt"; then
  echo "FAIL: policy — B reports policy-denied on a peer that has a policy"; ok=0
fi

# phase optout — the explicit "I really do mean permit-all", per neighbour.
grep -q "10.60.1.0/24" "$WORK/optout_b_bgp.txt" \
  || { echo "FAIL: optout — require-policy = false did not restore permit-all"; ok=0; }
if grep -q "RFC 8212" "$WORK/b_optout.log"; then
  echo "FAIL: optout — B warned about a policy it was told not to require"; ok=0
fi

# phase global — the speaker-wide key reaches a neighbour that says nothing itself.
# This is the spelling every other script in scripts/ relies on, so it is asserted
# here rather than left to the unit test.
grep -q "10.60.1.0/24" "$WORK/global_b_bgp.txt" \
  || { echo "FAIL: global — [bgp] ebgp-require-policy = false did not restore permit-all"; ok=0; }
if grep -q "RFC 8212" "$WORK/b_global.log"; then
  echo "FAIL: global — B warned despite the speaker-wide opt-out"; ok=0
fi

[[ $ok -eq 1 ]] || { echo "--- logs ---"; tail -8 "$WORK"/a_*.log "$WORK"/b_*.log 2>/dev/null; exit 1; }
echo "bgp default-deny (RFC 8212) smoke test: OK"
