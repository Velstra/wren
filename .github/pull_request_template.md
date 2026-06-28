## What this changes

<!-- A short description of the change and why. Link any related issue. -->

## Checklist

- [ ] `cargo clippy --workspace --all-targets -- -D warnings` is clean
- [ ] `cargo test --workspace` passes
- [ ] Docs in `docs/src/` updated if behaviour/config changed
- [ ] For protocol-runner changes: the relevant `scripts/*-smoke.sh` was run
      locally (rootless, via `unshare -Urn`) and passes
- [ ] `wren-core` still has **no** third-party dependencies (if touched)
- [ ] I agree my contribution is licensed inbound = outbound (Apache-2.0 for
      `wren-core`, GPL-2.0-or-later for the rest) — see CONTRIBUTING.md
