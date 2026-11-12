# Wren

Rust routing daemon for BGP, OSPFv2/v3, IS-IS, RIP/RIPng and Babel, with BFD,
VRRP, VRFs and Linux kernel route installation.

## Build

Install Rust through Rustup. Linux is required for kernel routing and live
protocol tests; the core libraries can be tested without it.

```sh
git clone https://github.com/Velstra/wren.git
cd wren
cargo build --release --locked
./target/release/wren check --config examples/wren.toml
```

`check` validates the file without starting protocols or changing routes.

## Run

Edit [examples/wren.toml](examples/wren.toml) for your interfaces and peers.
On an isolated lab host:

```sh
sudo ./target/release/wren --config examples/wren.toml --backend kernel
```

This opens protocol sockets and changes the kernel routing table. In another
terminal, inspect the running daemon:

```sh
sudo ./target/release/wren show routes
sudo ./target/release/wren show bgp neighbors
sudo ./target/release/wren show ospf neighbors
```

## Test

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
```

For live protocol exchanges in disposable Linux network namespaces:

```sh
bash scripts/run-all-tests.sh
```

These need `iproute2` and enabled user/network namespaces.
[Fuzzing](fuzz/README.md) is a separate nightly-toolchain workflow.

## Documentation

[Getting started](docs/src/getting-started.md) ·
[Configuration](docs/src/configuration.md) ·
[Protocols](docs/src/SUMMARY.md) ·
[Architecture](docs/src/architecture.md) ·
[Monitoring](docs/src/monitoring.md)

## License

`wren-core`: [Apache-2.0](LICENSE-APACHE).
Daemon and other crates: [GPL-2.0-or-later](LICENSE).
Contributions use the same licenses; no CLA is required.
