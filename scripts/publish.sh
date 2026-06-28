#!/usr/bin/env bash
# Publish the Wren crates to crates.io in dependency order.
#
#   bash scripts/publish.sh             # PLAN ONLY — prints the order, publishes nothing
#   bash scripts/publish.sh --execute   # actually publish (IRREVERSIBLE: versions are permanent)
#
# Prerequisites:
#   * `cargo login`  (token from https://crates.io/settings/tokens; verified email)
#   * a CLEAN, COMMITTED tree at the commit you want to publish — cargo packages
#     the working tree, and refuses a dirty tree without --allow-dirty.
#
# Publish order: wren-core (Apache-2.0) first, then the protocol/platform libs
# (each depends only on wren-core), then the wren-daemon binary last. A crate can
# only be published once every crate it depends on is already on crates.io.
#
# To publish ONLY the embeddable core for now (the conservative option), run:
#   cargo publish -p wren-core
set -euo pipefail
cd "$(dirname "$0")/.."

CRATES=(
  wren-core                                                   # Apache-2.0, no deps
  wren-netlink wren-filter wren-config                        # libs (depend on core)
  wren-rip wren-ospf wren-ospfv3 wren-isis wren-bgp wren-babel
  wren-daemon                                                 # binary, depends on all
)

MODE="${1:-plan}"

if [[ "$MODE" != "--execute" ]]; then
  echo "PLAN (nothing will be published). Publish order:"
  printf '  %s\n' "${CRATES[@]}"
  echo
  echo "Validate the core:  cargo publish -p wren-core --dry-run"
  echo "Publish for real:   bash scripts/publish.sh --execute"
  exit 0
fi

echo "About to publish ${#CRATES[@]} crates to crates.io. This is PERMANENT"
echo "(a version can be yanked but never deleted or reused)."
read -r -p "Type 'publish' to continue: " ans
[[ "$ans" == "publish" ]] || { echo "aborted."; exit 1; }

for c in "${CRATES[@]}"; do
  echo "=== publishing $c ==="
  cargo publish -p "$c"
  # cargo (>=1.66) waits for the new version to land in the index before it
  # returns, so the next crate's dependency resolves; the sleep is belt-and-braces.
  sleep 5
done
echo "all ${#CRATES[@]} crates published."
