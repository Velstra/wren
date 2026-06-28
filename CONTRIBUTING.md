# Contributing to Wren

Thanks for your interest in Wren — a small, RFC-correct routing daemon in Rust.
Bug reports, fixes, protocol refinements and documentation are all welcome.

## Licensing of contributions

Wren uses an **open-core split** (see [the License section](README.md#license)):

- `wren-core` is **Apache-2.0**;
- the daemon and every other crate are **GPL-2.0-or-later**.

Contributions are accepted **inbound = outbound**: by submitting a pull request
you agree that your contribution is licensed under the same license as the crate
it touches (Apache-2.0 for `wren-core`, GPL-2.0-or-later for the rest). **No CLA
is required.** A `Signed-off-by` line (`git commit -s`, the
[DCO](https://developercertificate.org/)) is appreciated but not mandatory.

## Before you open a pull request

Wren aims to be RFC-correct and dependency-light. Please make sure:

- `cargo build --workspace` succeeds;
- `cargo clippy --workspace --all-targets -- -D warnings` is clean;
- `cargo test --workspace` passes (the library tests need no network);
- new behaviour has tests — pure unit tests where possible, and a convergence
  **smoke script** under `scripts/` for anything that needs two routers on the
  wire (see below);
- protocol changes keep the docs in `docs/src/` in sync.

`wren-core` must stay **dependency-free** (pure `std`) so it can be embedded
anywhere. New third-party dependencies belong in the daemon or protocol crates,
not the core.

## Running the convergence smoke tests

The protocol runners are exercised live by the scripts in `scripts/`. They are
**rootless** — each runs inside a throwaway `unshare -Urn` network namespace and
never touches your host's interfaces or uplink:

```sh
bash scripts/ospf-show-smoke.sh
bash scripts/bgp-large-community-smoke.sh
# ... etc
```

These are not run in CI (they need `CAP_NET_RAW`), so please run the relevant
ones locally when you touch a protocol runner.

## Commit style

Conventional, imperative commit subjects (`bgp: add large communities (RFC 8092)`)
are preferred. Keep the `git log` readable — one logical change per commit.

## Reporting security issues

Please do **not** open public issues for security problems — see
[`SECURITY.md`](SECURITY.md).
