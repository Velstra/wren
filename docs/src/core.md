# The Core: RIB, FIB & Embedding

`wren-core` is the heart of Wren and, on purpose, has **no dependencies** — only
the Rust standard library. That is what lets it link straight into other control
planes (such as the Velstra Sentinel appliance) without dragging in an async
runtime or any third-party crate.

## The data model

**`Prefix`** — an IPv4 or IPv6 CIDR (`addr/len`), with host bits normalised, and
`FromStr` / `Display` / `Ord`. It is the key everything else is organised by.

**`Protocol`** — the source of a route, each with a BIRD-style *preference*
(higher wins): Connected 240, Static 200, OSPF 150, RIP 120, Babel 115, BGP 100,
Kernel 10. The preference is also mapped to the standard rtnetlink protocol ids so
the kernel attributes routes correctly (`proto rip`, `proto ospf`, `proto bgp`, …).

**`NextHop`** — a gateway and/or an interface, with a weight, so multipath (ECMP)
routes are expressible.

**`Route`** — a prefix plus one or more next hops, its protocol, preference and
metric, and a `source` discriminator. Within the RIB a route is identified by
`(prefix, protocol, source)`: an update with the same identity replaces the prior
one, and a withdraw removes it. `source` distinguishes several instances of one
protocol (for example, several RIP neighbours).

## The RIB

`Rib` keeps, per prefix, every candidate route, and selects the **best** one by
preference (higher wins) then metric (lower wins). `update` and `withdraw` return
an `Option<FibChange>` describing what the *installed* route became:

- `FibChange::Install(route)` — the best route for a prefix appeared or changed;
- `FibChange::Remove(prefix)` — the last route for a prefix is gone.

Returning a change only when the installed best actually moves means the forwarding
plane is touched the minimum number of times.

## The FIB abstraction

`Fib` is a small trait — apply a `FibChange` — with two implementations:

- **`MemoryFib`** (in `wren-core`) — records changes in memory; the dry-run
  backend, and the test double.
- **`KernelFib`** (in `wren-netlink`) — installs and withdraws real routes by
  hand-rolling rtnetlink messages (`RTM_NEWROUTE` create-or-replace,
  `RTM_DELROUTE`) over a raw `AF_NETLINK` socket via `libc`. This is the only crate
  that uses `unsafe`, and it is synchronous — no async dependency.

Because the backend is a trait object (`Box<dyn Fib>`), the same router loop drives
either the kernel or the in-memory plane depending on `--backend`.

## Embedding `wren-core`

The whole select-and-program cycle is usable from another program without the
daemon:

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

Implementing `Fib` for your own data plane is the intended integration point. For
Sentinel this is how Wren's chosen routes will be handed to the eBPF/XDP forwarding
path: a future `Fib` implementation writes the winning routes into a BPF LPM-trie
map. The protocol engines themselves stay in user space — only the FIB backend
touches eBPF.
