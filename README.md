# Wren

[![CI](https://github.com/velstra/wren/actions/workflows/ci.yml/badge.svg)](https://github.com/velstra/wren/actions/workflows/ci.yml)
[![crates.io](https://img.shields.io/crates/v/wren-core.svg)](https://crates.io/crates/wren-core)
[![docs.rs](https://img.shields.io/docsrs/wren-core)](https://docs.rs/wren-core)
[![License](https://img.shields.io/badge/license-Apache--2.0%20%2F%20GPL--2.0--or--later-blue.svg)](#license)

**A routing daemon in Rust.** Wren speaks the standard routing protocols (per
their RFCs) and programs the kernel forwarding table — the job of
[BIRD](https://github.com/CZ-NIC/bird) and
[FRR](https://github.com/FRRouting/frr), rebuilt in safe Rust with a small,
embeddable core.

It is being built both as a **standalone daemon** and as a control plane that
can be embedded into the [Velstra **Sentinel**](https://github.com/velstra)
appliance, whose eBPF/XDP data plane can consume Wren's chosen routes.

> Status: **early** (`0.0.x`). The control-plane core, **RIPv2 (RFC 2453)** and
> **RIPng (RFC 2080)** end to end (a shared distance-vector engine, per-protocol
> wire codecs, and live multicast socket/timer runners that learn routes from
> neighbours, redistribute connected networks, and install everything into the
> kernel), the config model, the **netlink kernel FIB backend**, and the daemon
> are in place and tested. **OSPFv2 (RFC 2328)** now works end to end —
> point-to-point and broadcast links, DR/BDR election, Router/Network/Summary-LSA
> flooding, and **multi-area** routing through an area border router — with SPF
> routes installed into the RIB, verified two- and three-router in network
> namespaces. **BGP-4 (RFC 4271)** now works end to end too — eBGP/iBGP sessions over
> TCP port 179, best-path selection and routes installed into the kernel RIB,
> verified two-router across two ASes. **Babel (RFC 8966)** now works end to end as
> well — a loop-avoiding distance-vector protocol over IPv6 (UDP 6696, `ff02::1:6`)
> with the feasibility condition and Hello/IHU link costing, verified two-router in
> network namespaces. **OSPFv3 (RFC 5340)** — OSPF for IPv6 — is now in place end to
end as well: the `wren-ospfv3` library (IPv6 packet/LSA wire codec, link-state
database, state machines, §13 flooding, the §4.8 SPF over the address-free graph
with link-local next hops from the Link-LSAs) plus a raw IPv6 protocol-89 runner
that brings two routers to Full and exchanges routes, on point-to-point and
broadcast links, single- and multi-area, with ASBR redistribution. Other protocol
extensions come after — see the roadmap.

## Architecture

Wren follows FRR's separation of a central RIB/FIB manager (*zebra*) from the
protocol engines, but as one process built from layered crates:

```
          ┌─────────────┐   ┌─────────────┐   ┌─────────────┐
protocols │  wren-rip   │   │  (ospf…)    │   │  (bgp…)     │   announce Routes
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
              forwarding  │  FIB backend      │  KernelFib (netlink) /
                          │                   │  MemoryFib (dry-run)
                          └───────────────────┘
```

| Crate | Role | Deps |
|---|---|---|
| `wren-core` | `Prefix`, `Route`, `Protocol`, the `Rib` (best-path) and the `Fib` trait + `MemoryFib`. | **none** (pure `std`, embeddable) |
| `wren-rip` | RIP (RFC 2453) + RIPng (RFC 2080) codecs and the shared, address-neutral distance-vector table. | `wren-core` |
| `wren-ospf` | OSPFv2 (RFC 2328) — packet/LSA wire codec, LSDB, SPF and the runner state. | `wren-core` |
| `wren-ospfv3` | OSPFv3 (RFC 5340) — the IPv6 packet/LSA wire codec, LSDB, state machines, flooding and SPF. The runner is in `wren-daemon`. | `wren-core` |
| `wren-isis` | IS-IS (ISO/IEC 10589, RFC 1195) — the PDU/TLV wire codec, the link-state database with CSNP/PSNP sync, the adjacency FSM with DIS election, and the §7.2 SPF (dual-stack, L1/L2 hierarchy with the attached-bit default). Driven by an `AF_PACKET` (layer-2) runner in `wren-daemon`. | `wren-core` |
| `wren-bgp` | BGP-4 (RFC 4271) + 4-octet ASNs (RFC 6793) + communities (RFC 1997 / 8092 / 4360) — message/path-attribute wire codec, capability negotiation, decision process, RIBs and session FSM. | `wren-core` |
| `wren-babel` | Babel (RFC 8966) — packet/TLV wire codec, source/route table with the feasibility condition, and the neighbour (Hello/IHU) link-cost table. | `wren-core` |
| `wren-filter` | BIRD-style route filters — prefix-pattern lists + match/accept/reject/modify rules, applied as per-protocol import policy. | `wren-core` |
| `wren-config` | TOML configuration model. | `wren-core`, `serde`, `toml` |
| `wren-netlink` | Linux kernel FIB backend (`KernelFib`) — installs routes over rtnetlink. | `wren-core`, `libc` |
| `wren-daemon` | the `wren` binary: config → RIB → FIB, async event loop. | all + `tokio`, `clap`, `tracing` |

**Best-path selection** uses a BIRD-style *preference* (higher wins), then the
protocol metric (lower wins). Defaults: connected 240 → static 200 → OSPF 150 →
RIP 120 → Babel 115 → BGP 100.

`wren-core` has **no dependencies on purpose**, so it links straight into other
control planes (such as Sentinel) without dragging in an async runtime.

## Roadmap

Protocols, each to be implemented to its RFC:

- [x] Static routes
- [x] Connected (direct) networks — interface subnets discovered via
  `getifaddrs`, tracked in the RIB and redistributed into RIP
- [x] RIPv2 (RFC 2453) — wire codec, distance-vector table, multicast
  socket/timer runner (periodic + triggered updates, split horizon, route
  timeout/garbage timers). **RIB-based redistribution** (`[rip] redistribute =
  ["connected", "static", "ospf", …]`, with an optional `[export] rip` filter)
  advertises other protocols' routes to neighbours and poisons them on withdrawal
  — verified live (rootless) by `scripts/rip-redistribute-smoke.sh`
- [x] RIPng (RFC 2080, IPv6) — shares the distance-vector engine with RIPv2;
  its own wire codec, UDP 521 / `FF02::9` runner, and IPv6 connected
  redistribution. **RIB-based redistribution** (`[ripng] redistribute = […]`,
  with an optional `[export] ripng` filter) carries IPv6 routes from other
  protocols over the same address-neutral engine — verified live (rootless) by
  `scripts/ripng-redistribute-smoke.sh`
- [x] OSPFv2 (RFC 2328) — **end-to-end**: point-to-point *and* broadcast links,
  single-area, multi-area (inter-area via an ABR) and AS-external (an ASBR
  redistributing static routes as type-5 LSAs). The full wire codec, database,
  SPF and state machines are in place (the 24-byte common header with the IP packet checksum
  and all five packet bodies — Hello, Database Description, Link State Request,
  Link State Update and Link State Acknowledgment; all four LSA bodies —
  router/network/summary/external — under the 20-byte LSA header with the
  Fletcher LS checksum; the link-state database with the §13.1 recency test and
  LSA aging; the intra-area Dijkstra SPF (§16.1) with §16.1.1 next-hop/stub
  handling; the neighbour (§10) and interface (§9) state machines with the DR/BDR
  election (§9.4); and the flooding procedure (§13)). The daemon runner ties them
  together over a raw IP proto-89 socket per interface (multicast 224.0.0.5/.6,
  `CAP_NET_RAW`): Hellos and neighbour discovery, the DR/BDR election, the
  master/slave Database Exchange (§10.8) through LSR/LSU to **Full**, Router-LSA
  *and* Network-LSA (DR) origination with flooding, and SPF routes announced into
  the RIB — verified two-router on both a point-to-point and a broadcast segment
  in network namespaces (each learns the other's subnet). **Multi-area** is wired
  too: a link-state database per area, an SPF per area, an area border router that
  originates Summary-LSAs (type 3) into each area and the §16.2 inter-area route
  calculation — verified across a three-router / two-area topology (a router in a
  non-backbone area and one on the backbone each learn the other's subnet as an
  inter-area route through the ABR). **AS-external** routing is wired too: an ASBR
  redistributes static routes as AS-wide type-5 LSAs (E1/E2 metrics, §16.4), and
  other routers install them as external routes — verified two-router.
  **RIB-based redistribution** (`[ospf] redistribute = ["connected", "static",
  "bgp", …]`, with an optional `[export] ospf` filter) originates type-5 externals
  *dynamically* as the central router pushes best-path changes, beyond the
  from-config `redistribute-static` — verified live (rootless) by
  `scripts/ospf-redistribute-smoke.sh` (a static appears on the peer as `proto
  ospf` only once redistribution is enabled). Open refinements: stub/NSSA areas,
  type-4 ASBR summaries across areas, an explicit type-5 forwarding address, and
  authentication.
- [x] OSPFv3 (RFC 5340) — **end to end** (library in `wren-ospfv3`): the 16-byte
  IPv6 common header with the standard IPv6 pseudo-header (upper-layer) checksum and
  an Instance ID; all five packet bodies (Hello/DD/LSR/LSU/LSAck), now without a
  network mask or auth trailer; the 20-byte LSA header carrying a **scoped 16-bit
  LS Type** (link-local / area / AS flooding scope, with unknown types preserved so
  they still flood); the compact **IPv6 prefix encoding** (§A.4.1, packed into
  32-bit words); and all seven LSA bodies — Router/Network (topology only, by
  interface and router ID), Inter-Area-Prefix/Inter-Area-Router (the summaries),
  AS-External, Link (link-local address + on-link prefixes) and Intra-Area-Prefix
  (the addressing split out of the topology LSAs). The **link-state database**
  (§12.2, the §13.1 recency rules unchanged from OSPFv2, one per flooding scope)
  is in place too, as are the **neighbour and interface state machines** (§10/§9)
  and the **DR/BDR election** (§9.4) — ported from OSPFv2, which RFC 5340 leaves
  unchanged. The **SPF** (§4.8) is in place as well: a Dijkstra over the
  address-free Router/Network graph, with prefixes attached afterwards from the
  Intra-Area-Prefix-LSAs and link-local next hops resolved from the Link-LSAs,
  plus the inter-area and AS-external (E1/E2) stages. The **runner** (in
  `wren-daemon`) drives it over a raw IPv6 protocol-89 socket joined to
  `ff02::5`/`ff02::6`, sourcing packets from the link-local address: Hellos and DR
  election, the Database Exchange to Full, the origination and scoped flooding of
  our Router/Network/Intra-Area-Prefix/Link LSAs, and an SPF per area announced to
  the RIB — point-to-point and broadcast, single- and multi-area, with ASBR
  redistribution of IPv6 statics.
- [x] IS-IS (ISO/IEC 10589, RFC 1195) — **end to end and live-verified** (two
  routers form a point-to-point adjacency over a veth and install each other's
  routes `proto isis`). In `wren-isis`:
  the 8-byte common header (the `0x83` discriminator, lengths, version and Maximum
  Area Addresses) and all nine PDU types — the LAN and point-to-point Hellos, the
  Level-1/Level-2 LSPs (with the **ISO 8473 Fletcher checksum** computed on encode
  and verified on decode) and the CSNP/PSNP — plus the **TLV** framework and the
  core TLVs for modern dual IPv4/IPv6 wide-metric operation (Area Addresses,
  Protocols Supported, IS Neighbours, Extended IS Reachability, Extended IP
  Reachability, IPv6 Reachability, the interface-address and LSP-Entries TLVs), with
  unknown types preserved verbatim. The **link-state database** is in place too: the
  LSP store keyed by LSP ID, with the §7.3.16 recency rules (sequence number, then
  purge-wins, then checksum), countdown lifetime ageing, and the §7.3.15 CSNP/PSNP
  sequence-number synchronisation (request/send/in-sync decisions over an LSP-ID
  range). The **adjacency state machine** (the Down→Initializing→Up three-way
  handshake, RFC 5303) and the **DIS election** (LAN-only, preemptive, no backup,
  priority then SNPA tie-break) are in place too. The **SPF** (§7.2) is in place as
  well: a Dijkstra over one level's address-free node graph (pseudonodes as transit
  LANs, the two-way check, overload transit avoidance), with dual-stack prefixes
  attached from the reachability TLVs and the Level-1 attached-bit default route
  towards the backbone. The **runner** (`wren-daemon`'s `isis.rs`) is Wren's first
  layer-2 transport: an `AF_PACKET`/`SOCK_DGRAM` socket per interface (802.2 LLC
  frames to the IS-IS multicast MACs), driving Hellos and the DIS election, LSP
  origination and flooding, CSNP/PSNP reconciliation, and the per-level SPF feeding
  the RIB, configured with an `[isis]` block. **RIB-based redistribution** (`[isis]
  redistribute = […]`, with an optional `[export] isis` filter) carries other
  protocols' routes in our own LSP as Extended-IP (RFC 5305) / IPv6 (RFC 5308)
  reachability — verified live (rootless) by `scripts/isis-redistribute-smoke.sh`.
- [x] Babel (RFC 8966) — **end to end**. The packet/TLV wire codec is in place (the
  4-byte packet header and the TLVs Pad1/PadN, Hello, IHU, Router-ID, Next Hop,
  Update, Route Request, Seqno Request and Ack/Ack-Request; the AE 0/1/2/3 address
  encodings; and §4.5 prefix de-compression of Updates on receive). So is the route
  table with the **feasibility condition** (§3.5): the source table's feasibility
  distance per `(prefix, router-id)`, the seqno-then-metric feasibility test, route
  selection by smallest metric (advertised metric + link cost), and the loop-free
  retention of the selected route. So is the **neighbour table** (§3.4): the Hello
  reception history, the "2-out-of-3" link-quality rule, the txcost learned from
  IHUs and the resulting per-neighbour link cost, with Hello/IHU expiry. The daemon
  runner ties them together over UDP **6696** (one IPv6 socket per interface, joined
  to `ff02::1:6`): periodic Hellos with an increasing seqno, an IHU per neighbour
  advertising our receive cost, and Updates originating our own networks plus
  re-advertising selected routes; received Hellos/IHUs drive the neighbour table and
  received Updates — costed by the link to the sending neighbour — drive the route
  table, with selection changes installed into the RIB and a lost neighbour flushing
  its routes. Verified two-router in network namespaces (each learns and installs the
  other's network via the link-local next hop). **RIB-based redistribution** (`[babel]
  redistribute = […]`, with an optional `[export] babel` filter) originates other
  protocols' routes under our Router-ID and retracts them at metric infinity on
  withdrawal — dual-stack (both IPv4 and IPv6) — verified live (rootless) by
  `scripts/babel-redistribute-smoke.sh`. Open refinements: ETX costing for
  lossy links, seqno/route-request handling, prefix compression on send, IPv4 routes
  over the IPv6 transport (RTA_VIA next hops), and source-specific routing.
- [x] BGP-4 (RFC 4271) — **end to end** for IPv4 unicast. The message wire codec
  (the 19-byte header and the OPEN, UPDATE, NOTIFICATION and KEEPALIVE messages;
  the path attributes ORIGIN, AS_PATH, NEXT_HOP, MED, LOCAL_PREF, ATOMIC_AGGREGATE
  and AGGREGATOR; the NLRI prefix encoding), the decision process / best-path
  (§9.1.2.2: LOCAL_PREF → AS_PATH length → ORIGIN → MED → eBGP-over-iBGP → IGP
  metric → peer id/address), the Adj-RIB-In / Loc-RIB with per-prefix path
  selection (§3.2) and the per-peer session state machine (§8: Idle→Connect→
  Active→OpenSent→OpenConfirm→Established with the hold/keepalive/connect-retry
  timers) are all in place. The daemon runner ties them together over **TCP port
  179** (Wren's first non-multicast transport): a listener plus an active
  connector per peer, length-prefixed message framing, OPEN negotiation (AS check,
  Hold Time = min of the two), Keepalive/Hold timers driving the FSM, originated
  `network`s advertised on reaching Established, and received UPDATEs folded into a
  shared BGP RIB whose best-path changes are announced into the kernel RIB —
  verified two-router across two ASes (eBGP) in network namespaces, each speaker
  learning and installing the other's network. **4-octet ASNs (RFC 6793)** are
  supported: the 4-octet AS Number capability (code 65) is negotiated in the OPEN,
  AS_PATH is encoded 4-octet-wide between capable speakers, and AS4_PATH /
  AS4_AGGREGATOR (with the §4.2.3 reconstruction) carry the true ASNs through
  legacy 2-octet peers — verified live (rootless, two ASNs above 65535) by
  `scripts/bgp-4octet-smoke.sh`. **Communities (RFC 1997)** are supported too: the
  COMMUNITIES attribute, retained on received paths and attachable to originated
  networks via `[bgp] community`, with the well-known `no-export` / `no-advertise`
  propagation rules (an originated `no-export` route is withheld from eBGP peers)
  — verified live by `scripts/bgp-community-smoke.sh`. **Redistribution** lets BGP
  re-originate the connected/static/IGP routes the RIB holds (`[bgp] redistribute =
  ["connected", "static", "ospf", …]`, IPv4-only, never its own routes, with an
  optional `[export] bgp` filter): the central router loop pushes RIB best-path
  changes into BGP, which advertises them to established peers and withdraws them
  when they go away — verified live by `scripts/bgp-redistribute-smoke.sh`. That
  export filter can stamp **per-prefix communities** (`set-community` /
  `add-community` in a `[[filter.rule]]`), beyond the global all-or-nothing `[bgp]
  community` — verified live by `scripts/bgp-community-filter-smoke.sh`. **Large
  communities (RFC 8092)** are supported in parallel: the LARGE_COMMUNITY attribute
  (`global:local1:local2`), attached globally via `[bgp] large-community` or
  per-prefix via a filter's `set-large-community` — verified live by
  `scripts/bgp-large-community-smoke.sh`. **Extended communities (RFC 4360 /
  RFC 5668)** too: the EXTENDED_COMMUNITIES attribute (Route Target / Route Origin,
  `rt:`/`ro:`), global via `[bgp] ext-community` or per-prefix via
  `set-ext-community` — verified live by `scripts/bgp-ext-community-smoke.sh`.
  Still to come: MP-BGP (RFC 4760) and route reflection.

Platform / core:

- [x] **Netlink FIB backend** (Linux `rtnetlink`) — installs/withdraws real
  kernel routes, attributed by origin protocol (`proto rip`/`ospf`/`bgp`/…)
- [x] **ECMP / multipath** — multi-next-hop routes (from the link-state SPFs)
  install as kernel `RTA_MULTIPATH` routes, with per-path weights
- [~] Import/export **filters** (BIRD-style policy) — the `wren-filter` engine,
  per-protocol **import** filters (`[[filter]]` + `[import]`) and the kernel-FIB
  **export** filter (`[export] kernel`) are in place; **redistribution** (the
  router pushing RIB routes back into a protocol to re-originate) is wired for BGP
  (`[bgp] redistribute`), OSPF (`[ospf] redistribute`, dynamic AS-external type-5
  LSAs), RIP (`[rip] redistribute`), RIPng (`[ripng] redistribute`), Babel
  (`[babel] redistribute`, dual-stack) and IS-IS (`[isis] redistribute`, carried
  in the LSP as RFC 5305/5308 reachability) — **every routing protocol** — each
  with an optional `[export] <proto>` filter
- [ ] Multiple routing tables / VRFs
- [~] A management interface and operational `show` commands — the daemon serves a
  Unix control socket; `wren show routes [protocol]` renders the central RIB,
  `wren show bgp [routes|neighbors]` renders the BGP Loc-RIB (AS_PATH, communities,
  LOCAL_PREF, origin) and neighbour states, `wren show ospf [neighbors|interfaces]`
  renders the OSPF adjacencies and interfaces (area, state, elected DR/BDR), and
  `wren show isis [neighbors|interfaces]` renders the IS-IS per-level adjacencies
  and circuits (type, level, elected DIS), and `wren show babel [neighbors|routes]`
  renders the Babel neighbours (link costs) and selected routes, each answered by
  the task that owns the data; more commands and a richer API to come
- [~] **Startup reconciliation** — the kernel backend reads the routing table back
  on boot and removes routes a previous instance left behind that the current
  config no longer programs; full graceful restart is still to come
- [ ] Route redistribution between protocols

## Build & run

```sh
cargo build --release
cargo test                       # the library crates need no network

# Dry run — compute routes in memory, never touch the kernel:
./target/release/wren --config ./examples/wren.toml --dry-run

# Real install — program the kernel routing table (needs CAP_NET_ADMIN):
sudo ./target/release/wren --config ./examples/wren.toml --backend kernel

# Ask a running daemon what it has chosen (over its control socket):
./target/release/wren show routes          # every best route, à la `ip route`
./target/release/wren show routes ospf     # only OSPF-learned routes
./target/release/wren show bgp             # the BGP Loc-RIB with path attributes
./target/release/wren show bgp neighbors   # configured peers and session state
./target/release/wren show ospf neighbors  # OSPF adjacencies and their state
./target/release/wren show ospf interfaces # OSPF interfaces, area and elected DR/BDR
./target/release/wren show isis neighbors  # IS-IS per-level adjacencies and their state
./target/release/wren show isis interfaces # IS-IS circuits, level and elected DIS
./target/release/wren show babel neighbors # Babel neighbours and their link costs
./target/release/wren show babel routes    # the selected Babel routes (next hop, metric)

# Try it unprivileged in a throwaway network namespace:
unshare -Urn sh -c '
  ip link add dummy0 type dummy; ip addr add 10.9.9.1/24 dev dummy0; ip link set dummy0 up
  ./target/debug/wren --config ./examples/wren.toml --backend kernel & sleep 1; ip route'
```

Example `wren.toml`:

```toml
router-id = "10.0.0.1"

[[static]]
prefix = "0.0.0.0/0"
via = "192.0.2.1"

[[static]]
prefix = "10.20.0.0/16"
dev = "eth1"
metric = 10

[rip]
enabled = true
interfaces = ["eth1", "eth2"]

[ripng]                 # RIP for IPv6 (RFC 2080)
enabled = true
interfaces = ["eth1", "eth2"]
```

## Documentation

A full handbook lives in [`docs/`](docs/) as an [mdBook](https://rust-lang.github.io/mdBook/)
— introduction, architecture, a complete `wren.toml` reference, a chapter per
protocol (with config and two-namespace test recipes), and the embeddable-core
guide. Build and read it locally:

```sh
cargo install mdbook        # once
mdbook serve docs --open    # live-reloading HTML at http://localhost:3000
# or a one-shot static build into docs/book/:
mdbook build docs
```

## License

Copyright (C) 2026 The Wren authors.

Wren follows an **open-core split**:

- **`wren-core`** — the dependency-free control-plane core (RIB, route types, the
  FIB abstraction) — is **Apache-2.0** ([`LICENSE-APACHE`](LICENSE-APACHE)), so it
  can be embedded anywhere, including downstream proprietary or AGPL projects (such
  as the Velstra Sentinel appliance).
- **The daemon and every other crate** (`wren-daemon`, `wren-rip`, `wren-ospf`,
  `wren-ospfv3`, `wren-isis`, `wren-bgp`, `wren-babel`, `wren-filter`,
  `wren-config`, `wren-netlink`) are **GPL-2.0-or-later** ([`LICENSE`](LICENSE)) —
  the same copyleft as BIRD, keeping the routing stack fully open and protected
  against proprietary forks.

Contributions are accepted **inbound = outbound** under these same licenses; no
CLA is required. (The Velstra Sentinel appliance, which is a separate project, is
AGPL with its own CLA — that does not apply here.)
