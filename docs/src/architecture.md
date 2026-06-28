# Architecture

Wren follows FRR's separation of a central route manager (*zebra*) from the
protocol engines, but as a **single process** built from layered crates. The
protocol engines never touch the routing table directly: they run in their own
async tasks and send route updates down a channel to one central loop that owns
the RIB and the forwarding plane.

```text
          ┌─────────────┐   ┌─────────────┐   ┌─────────────┐
protocols │  wren-rip   │   │  wren-ospf  │   │  wren-bgp   │   announce Routes
          └──────┬──────┘   └──────┬──────┘   └──────┬──────┘
                 └──────────────┐  │  ┌──────────────┘
                                ▼  ▼  ▼
                          ┌───────────────────┐
              core (RIB)  │     wren-core     │  best-path selection
                          │  Rib · Route ·    │  → FibChange stream
                          │  Prefix · Fib     │
                          └─────────┬─────────┘
                                    ▼
                          ┌───────────────────┐
              forwarding  │   FIB backend     │  KernelFib (netlink) /
                          │                   │  MemoryFib (dry-run)
                          └───────────────────┘
```

## The central router loop

`wren-daemon`'s `router.rs` is the equivalent of zebra: the **sole owner** of the
`Rib` and the `Box<dyn Fib>`. Protocol engines emit `RouteUpdate`s —
`Announce(Route)` or `Withdraw { prefix, protocol, source }` — over an `mpsc`
channel, and this loop is the only place that calls `Rib::update`/`Rib::withdraw`
and drains the resulting `FibChange`s into the forwarding plane. Keeping best-path
selection and FIB programming single-threaded and serialized makes the daemon easy
to reason about, however many protocols feed it.

This loop is also where **filters** (the `wren-filter` crate) apply: an announced
route is first run through its protocol's *import* filter, so a rejected route never
reaches the RIB (and any prior copy is withdrawn); and a best-path change is run
through the FIB *export* filter before programming, so a rejected route stays in the
RIB but is kept out of the kernel. See [Configuration](configuration.md).

The same best-path change is also **redistributed**: the loop fans it out to any
protocol engines that asked for it (a *redistribution target*), so a route one
protocol learned can be re-originated by another — BGP advertising the connected,
static or IGP routes the RIB holds, for instance. Each target names the source
protocols it wants and an optional export filter (the same `wren-filter` engine);
the router pushes accepted routes down a channel to that protocol's task and
withdraws them when their best path goes away. A protocol never redistributes its
own routes. See [BGP redistribution](protocols/bgp.md#redistribution).

Directly-connected routes are a special case: the kernel already owns them (they
come from interface addressing), so the router tracks them in the RIB for
best-path and redistribution but never reprograms them.

At **startup** the daemon reconciles: it reads back the routes the forwarding
plane already holds that wren owns (the kernel backend dumps the routing table and
keeps only routes tagged with wren's own protocol ids — never foreign kernel,
DHCP or connected routes) and removes any whose prefix the current configuration
no longer programs. That clears stale routes a previous instance left behind on a
non-graceful restart; dynamic protocols re-install theirs as they reconverge.

The same loop also answers **operational queries**. The daemon serves a small
Unix-domain control socket (`--socket`, default `/run/wren/wren.sock`); a `wren
show routes [protocol]` client connects, sends one command line, and prints the
reply. Crucially the socket server never touches the RIB — it forwards each parsed
query to the router loop over a channel and waits for the rendered answer on a
oneshot, so `show` shares the RIB the same single-threaded way protocol updates
and FIB programming do, with no locking.

The BGP task owns its own RIB (the Loc-RIB and the neighbour table), so it answers
`wren show bgp [routes|neighbors]` the same way — the control socket forwards those
queries to the BGP task, which renders the best paths (with their AS_PATH,
communities, LOCAL_PREF and origin) and neighbour states off the state it alone
owns. Each `show` is thus answered by whichever task owns the data, never by
reaching across tasks into a shared structure.

## The crates

Wren is a Cargo workspace, deliberately split so the control-plane *core* carries
no dependencies and can be embedded, while the daemon, protocols and platform glue
layer their dependencies on top.

| Crate | Role | Dependencies |
|---|---|---|
| [`wren-core`](core.md) | `Prefix`, `Route`, `Protocol`, the `Rib` (best-path) and the `Fib` trait + `MemoryFib`. | **none** (pure `std`, embeddable) |
| `wren-rip` | RIPv2 (RFC 2453) + RIPng (RFC 2080) codecs and the shared distance-vector table. | `wren-core` |
| `wren-ospf` | OSPFv2 (RFC 2328) — packet/LSA wire codec, link-state database, SPF, the §9/§10 state machines and the §13 flooding decision. | `wren-core` |
| `wren-ospfv3` | OSPFv3 (RFC 5340) — OSPF for IPv6: the same machinery rebuilt around IPv6, with topology separated from addressing. | `wren-core` |
| `wren-isis` | IS-IS (ISO/IEC 10589, RFC 1195) — the PDU/TLV wire codec, the link-state database with CSNP/PSNP sync, the adjacency FSM with DIS election, and the §7.2 SPF (dual-stack, L1/L2 hierarchy with the attached-bit default). Driven by an `AF_PACKET` (layer-2) runner in `wren-daemon`. | `wren-core` |
| `wren-babel` | Babel (RFC 8966) — the loop-avoiding distance-vector protocol over IPv6. | `wren-core` |
| `wren-bgp` | BGP-4 (RFC 4271) with 4-octet ASNs (RFC 6793) and communities (RFC 1997) — message/path-attribute wire codec, the §9 decision process, the §3.2 RIBs, the §8 session FSM, the 4-octet AS capability / AS4_PATH machinery and the COMMUNITIES attribute. | `wren-core` |
| `wren-filter` | BIRD-style route filters — prefix-pattern lists, match conditions and accept/reject/modify rules, applied as per-protocol import policy. | `wren-core` |
| `wren-config` | The TOML configuration model. | `wren-core`, `serde`, `toml` |
| `wren-netlink` | The Linux kernel FIB backend (`KernelFib`) — installs routes over rtnetlink. | `wren-core`, `libc` |
| `wren-daemon` | The `wren` binary: config → RIB → FIB, the async event loop, and the per-protocol socket runners. | all + `tokio`, `clap`, `tracing` |

## Pure logic vs. I/O

A recurring split runs through every protocol crate: **all protocol decisions live
in a dependency-free library**, and **all I/O lives in the daemon**.

- The library crates (`wren-rip`, `wren-ospf`, `wren-bgp`) hold the wire codecs,
  the state machines, the database and best-path logic as pure functions and
  values — no sockets, no clock (time is passed in). This makes them exhaustively
  unit-testable.
- The async **runners** in `wren-daemon` (`rip.rs`, `ripng.rs`, `ospf.rs`,
  `bgp.rs`) open the sockets, drive the timers, feed events into the library state
  machines, and carry out the actions those machines return.

The result is that the hard logic is tested without a network, and the runners
stay thin. Each protocol chapter calls out exactly where this line falls.

## Best-path selection

When several protocols offer a route to the same prefix, `wren-core` picks the
winner by a BIRD-style **preference** (higher wins), then the protocol **metric**
(lower wins):

| Source | Preference |
|---|---|
| Connected | 240 |
| Static | 200 |
| OSPF | 150 |
| RIP | 120 |
| Babel | 115 |
| BGP | 100 |
| Kernel | 10 |

A best route may carry **several next-hops** — the link-state SPFs produce these by
merging equal-cost paths. The kernel backend installs them all as an `RTA_MULTIPATH`
(ECMP) route, preserving each next-hop's weight, rather than keeping only the first.

See [The Core](core.md) for the exact data model and how the RIB turns updates
into forwarding-table changes.
