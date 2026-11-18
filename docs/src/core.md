# Embed the routing core {#the-core-rib-fib--embedding}

## Select and apply a route {#embedding-wren-core}

The `wren-core` crate has no third-party dependencies. A caller feeds candidates to `Rib` and applies the returned change to a `Fib` implementation. This example keeps the FIB in memory.

```rust
use wren_core::{Rib, Route, Protocol, Prefix, NextHop, Fib, MemoryFib};

let mut rib = Rib::new();
let mut fib = MemoryFib::default();   // or your own Fib implementation

let route = Route::new(
    "10.0.0.0/24".parse::<Prefix>().unwrap(),
    Protocol::Static,
    vec![NextHop::via("192.0.2.1".parse().unwrap())],
    0,                                 // metric
);

if let Some(change) = rib.update(route) {
    fib.apply(&change).unwrap();       // program your data plane
}
```

## Identify a candidate {#the-data-model}

Within a routing table the candidate’s identity includes its prefix, origin protocol and source discriminator. Updating the same candidate replaces it. A different candidate may become the winner after a withdrawal.

## Interpret the result {#the-rib}

| RIB change | Consumer action |
| --- | --- |
| `Some(FibChange::Install(...))` | Install or replace the selected route. |
| `Some(FibChange::Remove(...))` (on withdrawal) | Remove the prefix after its last eligible route disappears. |
| `None` | The selected forwarding entry is unchanged. |

## Choose the backend {#the-fib-abstraction}

Use `MemoryFib` for in-process tests. A separate integration can implement `Fib` or consume the daemon’s [route stream](monitoring.md#streaming-the-forwarding-table--wren-monitor-routes). To exercise route selection independently of Linux, run `cargo test --locked -p wren-core` from the workspace root. [Core API and tests](https://github.com/Velstra/wren/blob/main/crates/wren-core/src/lib.rs)
