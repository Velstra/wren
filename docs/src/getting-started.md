# Getting Started

## Requirements

- A recent **stable** Rust toolchain (the workspace pins stable via
  `rust-toolchain.toml`). Wren's control plane uses no nightly features.
- Linux, for the kernel FIB backend (it talks rtnetlink over a raw netlink
  socket). The library crates and their tests build and run on any platform.

## Build & test

```sh
cargo build --release          # builds the `wren` binary into target/release/
cargo test                     # the library crates need no network
cargo clippy --all-targets     # lint
```

The release binary lands at `target/release/wren`.

## Running

Wren reads a single TOML file (see the [Configuration](configuration.md)
reference) and drives one of two forwarding-plane **backends**:

| Backend | Flag | Effect |
|---|---|---|
| In-memory (default) | `--backend memory` or `--dry-run` | Computes routes and logs them; never touches the kernel. Safe anywhere. |
| Kernel | `--backend kernel` | Installs and withdraws real routes over netlink. Needs `CAP_NET_ADMIN`. |

```sh
# Dry run — compute routes in memory, never touch the kernel:
./target/release/wren --config ./examples/wren.toml --dry-run

# Real install — program the kernel routing table:
sudo ./target/release/wren --config ./examples/wren.toml --backend kernel
```

The default config path is `/etc/wren/wren.toml`; override it with `--config`.

### Logging

Wren logs through [`tracing`](https://docs.rs/tracing). Set `RUST_LOG` to choose
the verbosity — for example `RUST_LOG=info` (the default), `RUST_LOG=debug`, or a
per-module filter like `RUST_LOG=wren::bgp=debug,info`.

## Try it without root

Most of Wren can be exercised unprivileged inside a throwaway **user + network
namespace** (`unshare -Urn`), which grants `CAP_NET_RAW`/`CAP_NET_ADMIN` *inside
the namespace* without real root:

```sh
unshare -Urn sh -c '
  ip link add dummy0 type dummy
  ip addr add 10.9.9.1/24 dev dummy0
  ip link set dummy0 up
  ./target/debug/wren --config ./examples/wren.toml --backend kernel &
  sleep 1
  ip route'
```

### Two-router tests

Protocols that exchange packets with a neighbour need **two** network namespaces
joined by a virtual link — a single namespace short-circuits delivery in the
kernel before a bound socket ever sees the packet. The pattern used throughout
Wren's development (no real root required):

```sh
unshare -Urn bash -c '
  ip link set lo up
  # A holder process in its own netns becomes "router B".
  setsid unshare -n -- sleep 300 & BPID=$!
  sleep 0.3
  # A veth pair: one end stays here (router A), the other moves to B by PID.
  ip link add veth0 type veth peer name veth1
  ip link set veth1 netns $BPID
  ip addr add 10.0.0.1/24 dev veth0; ip link set veth0 up
  nsenter -t $BPID -n ip addr add 10.0.0.2/24 dev veth1
  nsenter -t $BPID -n ip link set veth1 up
  nsenter -t $BPID -n ip link set lo up
  # Run a wren in each namespace, then inspect "ip route" on both sides.
'
```

Each protocol chapter gives a concrete two-router smoke test built on this
harness. Rootless `ip netns add` cannot write `/run/netns`, so the holder-PID +
`nsenter` approach above is used instead of named namespaces.
