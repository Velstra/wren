#!/usr/bin/env bash
# Run Wren's whole test suite and summarise pass/fail at the end:
#
#   1. the cargo workspace unit/integration tests, then
#   2. every `scripts/*-smoke.sh` live test (in alphabetical order),
#
# excluding `publish.sh` (a release tool, not a test) and this runner itself.
#
# The smoke tests are rootless — each spins up its own throwaway `unshare -Urn`
# network namespaces and never touches the host — but they do need user-namespace +
# CAP_NET_RAW/CAP_NET_ADMIN inside that namespace (the default on a normal Linux box).
# Several converge slowly (OSPF/IS-IS/Babel/BFD), so the full run takes a while
# (roughly 25-40 minutes); each test has its own internal timeout.
#
# Output of each test goes to a per-test log under a temp dir; on failure its tail is
# printed inline, and the final summary lists every result. Exit status is non-zero if
# anything failed.
#
# Usage:
#   bash scripts/run-all-tests.sh             # run everything
#   bash scripts/run-all-tests.sh bgp ospf    # only tests whose name matches a filter
set -uo pipefail   # deliberately NOT -e: run every test, then summarise

REPO="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO"

FILTERS=("$@")
matches() {
  [[ ${#FILTERS[@]} -eq 0 ]] && return 0
  local name="$1" f
  for f in "${FILTERS[@]}"; do [[ "$name" == *"$f"* ]] && return 0; done
  return 1
}

LOGDIR="$(mktemp -d)"
echo "logs: $LOGDIR"
echo "building wren once up front ..."
if ! cargo build -p wren-daemon >"$LOGDIR/_build.log" 2>&1; then
  echo "FATAL: initial build failed:"; tail -20 "$LOGDIR/_build.log"; exit 1
fi

names=(); statuses=(); durations=()

run() {
  local name="$1"; shift
  matches "$name" || return 0
  printf '%-44s ... ' "$name"
  local start end st
  start=$(date +%s)
  if "$@" >"$LOGDIR/$name.log" 2>&1; then st="OK"; else st="FAIL"; fi
  end=$(date +%s)
  names+=("$name"); statuses+=("$st"); durations+=("$((end - start))")
  printf '%s (%ds)\n' "$st" "$((end - start))"
  if [[ "$st" == "FAIL" ]]; then
    echo "  --- last 8 lines of $name ---"
    tail -8 "$LOGDIR/$name.log" | sed 's/^/  /'
  fi
}

# 1. Cargo workspace tests.
run "cargo-test-workspace" cargo test --workspace --quiet

# 2. Every smoke test except publish.sh and this runner.
self="$(basename "$0")"
for s in scripts/*-smoke.sh scripts/*-test.sh; do
  [[ -e "$s" ]] || continue
  base="$(basename "$s")"
  [[ "$base" == "publish.sh" || "$base" == "$self" ]] && continue
  run "${base%.sh}" bash "$s"
done

# 3. Summary.
echo
echo "================ SUMMARY ================"
pass=0; fail=0; failed_names=()
total_dur=0
for i in "${!names[@]}"; do
  printf '%-44s %s (%ds)\n' "${names[$i]}" "${statuses[$i]}" "${durations[$i]}"
  total_dur=$((total_dur + durations[$i]))
  if [[ "${statuses[$i]}" == "OK" ]]; then pass=$((pass + 1)); else fail=$((fail + 1)); failed_names+=("${names[$i]}"); fi
done
echo "----------------------------------------"
printf 'total: %d   passed: %d   failed: %d   (%dm%02ds)\n' \
  "$((pass + fail))" "$pass" "$fail" "$((total_dur / 60))" "$((total_dur % 60))"
if [[ $fail -gt 0 ]]; then
  echo "FAILED: ${failed_names[*]}"
  echo "logs retained at: $LOGDIR"
  exit 1
fi
echo "ALL TESTS PASSED"
echo "logs at: $LOGDIR"
