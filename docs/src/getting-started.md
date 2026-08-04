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

## Building a subset (cargo features)

By default the daemon includes every routing protocol. Each one is behind a cargo
feature, so an embedder (e.g. [Sentinel](core.md)) that only needs a couple can
compile the rest out entirely — smaller binary, faster builds, fewer dependencies:

| Feature | Protocol(s) |
|---|---|
| `ospf`  | OSPFv2 |
| `ospf3` | OSPFv3 |
| `rip`   | RIPv2 + RIPng |
| `babel` | Babel |
| `isis`  | IS-IS |

`default = ["ospf", "ospf3", "rip", "babel", "isis"]`. **BGP and the core** (the RIB,
FIB, filters, config and netlink) are always built in — they are the floor.

```sh
# Only BGP + core — no OSPF/RIP/Babel/IS-IS compiled at all:
cargo build --release -p wren-daemon --no-default-features

# BGP + core + just OSPFv2 and IS-IS:
cargo build --release -p wren-daemon --no-default-features --features "ospf,isis"
```

A disabled protocol's `[section]` in the config is simply inert, and its `show`
command returns the unknown-command help — the daemon still runs everything you did
build in.

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

### Checking a configuration

`wren check` reads a file, resolves everything that can be resolved without a
network, and exits — parse, compile the filters, resolve the import/export
attachments and the VRF route-maps, build the static routes and the BGP
neighbour set. That is the same work a `SIGHUP` reload does before it commits, so
a file that passes here is one the running daemon would accept.

Nothing is started, no socket is opened and the kernel is not touched, which
means it is safe on a box that is already routing. The alternative is finding
out by restarting.

```sh
$ wren check -c ./examples/wren.toml
./examples/wren.toml is valid
  router-id       10.0.0.1
  static routes   2
  vrfs            0
  filters         0
  import filters  0
  bgp             disabled
  vrrp            0
```

The counts are what was *resolved*, not what was written. They happen to agree
here, but a static route that a VRF's import route-map rejects is written and not
counted — and that difference is the one worth seeing before a restart rather
than after.

A file that does not pass says what is wrong with it and exits non-zero, which is
what makes this usable from a script or a deployment pipeline:

```sh
$ wren check -c broken.toml
Error: reading broken.toml

Caused by:
    invalid config: static route 198.51.100.0/24 is a blackhole and cannot also have a next-hop
```

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
