# Wire-decoder fuzzing

Standalone cargo-fuzz workspace for protocol decoders. It is separate from
the root workspace's stable-Rust tests.

From the repository root, with Rustup installed:

```sh
rustup toolchain install nightly
cargo install cargo-fuzz --locked
cargo +nightly fuzz list
cargo +nightly fuzz run bgp_message -- -max_total_time=60
```

Replace `bgp_message` with a target from `fuzz list`.
[Cargo.toml](Cargo.toml) lists each target and its decoder source.

To check compilation without running the fuzzer:

```sh
cargo +nightly check --manifest-path fuzz/Cargo.toml
```

Seeds live in `corpus/<target>/`; crashes are written to `artifacts/<target>/`.
Keep regression seeds, including the overlong BGP length case. Turn a new
crash into a regression test and retain its reproducer before fixing it.
