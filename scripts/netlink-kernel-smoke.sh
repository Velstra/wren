#!/usr/bin/env bash
# Run the privileged Netlink acceptance tests in a disposable user/network
# namespace. Build first so dependency downloads do not need namespace routing.
set -euo pipefail
cd "$(dirname "$0")/.."
cargo test -p wren-netlink --locked --no-run

unshare -Urn bash -euo pipefail -c '
  ip link set lo up
  ip link add d0 type dummy
  ip address add 192.168.1.1/24 dev d0
  ip address add 2001:db8::1/64 dev d0
  ip link set d0 up
  ip link add d1 type dummy
  ip address add 192.168.2.1/24 dev d1
  ip link set d1 up
  cargo test -p wren-netlink --locked --offline -- --ignored --nocapture
'
