# Build and check Wren {#getting-started}

## Build the daemon {#build--test}

<a id="requirements"></a>

Install Git, a C linker, and stable Rust with Cargo. Use Linux for the kernel backend. All commands below run from the checkout root.

```sh
git clone https://github.com/Velstra/wren.git
cd wren
cargo build --locked -p wren-daemon --bin wren
export PATH="$PWD/target/debug:$PATH"
wren --version
```

The build produces `target/debug/wren`. To evaluate a release, check out its tag before building and use its copy of the example scripts.

## Validate an example {#checking-a-configuration}

```sh
wren check -c examples/wren.toml
```

Look for `examples/wren.toml is valid`, router ID `10.0.0.1` and two resolved static routes. An invalid file exits nonzero. This check reads the configuration without opening protocol sockets or changing routes.

## Inspect a running instance {#running}

Use a fresh working directory and a dedicated socket. This complete configuration has only a static route. Keep terminal A open.

```sh
work=$(mktemp -d)
cd "$work"
cat >router.toml <<'TOML'
router-id = "192.0.2.10"
[[static]]
prefix = "198.51.100.0/24"
via = "192.0.2.1"
TOML
printf 'Lab directory: %s\n' "$PWD"
wren --config router.toml --backend memory --socket "$PWD/wren.sock"
```

In terminal B, add the checkout’s absolute `target/debug` path to `PATH` and enter the printed lab directory:

```sh
wren --socket "$PWD/wren.sock" show routes
```

Look for `198.51.100.0/24` with next hop `192.0.2.1` and protocol `static`. The memory backend keeps the forwarding decision in process. Stop the daemon with Ctrl-C.

## Run a two-router lab {#try-it-without-root}

<a id="two-router-tests"></a>

On Linux, install iproute2 and util-linux. The scripts use unprivileged user/network namespaces and create their own interfaces. Run these from the checkout root:

```sh
bash scripts/bgp-unnumbered-smoke.sh
bash scripts/bgp-hot-reload-smoke.sh
```

The first lab checks an IPv4 route with an IPv6 next hop in the actual kernel table. The second checks which sessions and routes survive adding and removing a peer.

## Build a smaller binary {#building-a-subset-cargo-features}

```sh
cargo build --release --locked -p wren-daemon --bin wren --no-default-features
```

Add features such as `--features ospf,isis` when those protocols are required. The [daemon manifest](https://github.com/Velstra/wren/blob/main/crates/wren-daemon/Cargo.toml) lists the default set.

## Logging

Set `RUST_LOG=debug` when starting the daemon to inspect protocol startup. The [monitoring guide](monitoring.md) covers state queries, metrics, and reloads.
