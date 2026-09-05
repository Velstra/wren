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

> **Status: 0.4.0 — a full multi-protocol routing daemon.** Wren runs **BGP-4**
> (MP-BGP for IPv4/IPv6, route reflection, confederations, communities, add-path,
> RPKI/RTR, BMP, and the EVPN, SRv6 service-SID, BGP-LS and FlowSpec address
> families), **OSPFv2** and **OSPFv3**, **IS-IS**, **RIPv2/RIPng**, **Babel**,
> **BFD** and **VRRP**, with **VRFs**, **multicast** (IGMPv3/MLDv2 querier + proxy
> and PIM-SM sparse mode), BIRD-style route filters and cross-protocol
> redistribution, a **netlink kernel FIB** with ECMP, live `SIGHUP` configuration
> reload, and a Unix control socket for operational `show` commands. Every protocol
> is verified end to end by rootless two-router smokes in network namespaces, and
> the dependency-free `wren-core` embeds into other control planes (such as the
> Velstra Sentinel appliance) with no async runtime.

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

## Features

Wren implements the following, each to its RFC.

**Routing protocols**

- **Static routes** and **connected** (direct) networks — interface subnets
  discovered via `getifaddrs`, tracked in the RIB and redistributed into every
  protocol.
- **RIPv2 (RFC 2453)** — the wire codec and shared distance-vector table over a
  multicast socket/timer runner (periodic + triggered updates, split horizon,
  route timeout/garbage timers), with RIB-based redistribution and an optional
  `[export] rip` filter.
- **RIPng (RFC 2080)** — RIP for IPv6, sharing the distance-vector engine with
  RIPv2 over its own UDP 521 / `FF02::9` runner, with IPv6 connected
  redistribution.
- **OSPFv2 (RFC 2328)** — point-to-point and broadcast links, DR/BDR election,
  Router/Network/Summary/External-LSA flooding, the intra-area Dijkstra SPF,
  multi-area routing through an area border router (Summary-LSAs + the §16.2
  inter-area calculation) and AS-external routing through an ASBR (type-5 LSAs,
  E1/E2 metrics). **Stub / totally-stubby / NSSA / totally-NSSA areas** (RFC 3101)
  with type-7 LSAs, packet **authentication** (simple password and MD5, RFC 2328
  Appendix D, with anti-replay), **passive interfaces**, and **graceful restart**
  (RFC 3623 — helper and restarting sides over the RFC 5250 opaque-LSA
  infrastructure). Runs over a raw IP proto-89 socket, with SPF routes installed
  into the RIB and RIB-based redistribution as dynamic type-5 externals.
- **OSPFv3 (RFC 5340)** — OSPF for IPv6: the IPv6 packet/LSA wire codec with a
  scoped 16-bit LS Type and the compact prefix encoding, all seven LSA bodies, the
  per-scope link-state database, the neighbour/interface state machines with DR/BDR
  election, and the §4.8 SPF with link-local next hops from the Link-LSAs —
  point-to-point and broadcast, single- and multi-area, with ASBR redistribution
  of IPv6 statics. Driven by a raw IPv6 proto-89 runner in the daemon.
- **IS-IS (ISO/IEC 10589, RFC 1195)** — the common header and all nine PDU types
  with the ISO 8473 Fletcher checksum, the TLV framework for modern dual IPv4/IPv6
  wide-metric operation, the link-state database with §7.3.15 CSNP/PSNP
  synchronisation, the adjacency FSM (RFC 5303) and DIS election, the §7.2
  dual-stack SPF with the L1/L2 hierarchy and attached-bit default, and **L1↔L2
  route leaking** (RFC 5302). Runs over an `AF_PACKET` layer-2 runner, with
  RIB-based redistribution carried as RFC 5305/5308 reachability.
- **BGP-4 (RFC 4271)** — eBGP/iBGP over TCP 179 with the full decision process and
  best-path selection, **4-octet ASNs** (RFC 6793), **MP-BGP** for IPv4 and IPv6
  unicast (RFC 4760) with **link-local next hops** (RFC 2545) and **Extended Next
  Hop / IPv4-over-IPv6** (RFC 5549 / 8950), **route reflection** (RFC 4456) and
  **confederations** (RFC 5065), **communities** (RFC 1997), **large communities**
  (RFC 8092) and **extended communities** (RFC 4360 / 5668), **ADD-PATH**
  (RFC 7911) with ECMP install, **address aggregation**, per-neighbour
  **default-originate** and **maximum-prefix** limits, per-neighbour inbound and
  outbound route filters, and per-neighbour session options (local-AS,
  update-source, eBGP-multihop, description, shutdown, hold-time). Security:
  **TTL security / GTSM** (RFC 5082), **TCP-MD5** (RFC 2385) and **TCP-AO**
  (RFC 5925) — including over IPv6 transport — **RPKI origin validation**
  (RFC 6811) over a live **RTR** feed (RFC 8210), **BMP** monitoring (RFC 7854),
  **default-deny** (RFC 8212) and **roles + Only-To-Customer** (RFC 9234).
  Additional address families: **FlowSpec** (RFC 8955), **SR-Policy** (RFC 9256),
  **BGP-LS** (RFC 7752), **EVPN** (RFC 7432 / 8365) and **SRv6 service SIDs**
  (RFC 9252).
- **Babel (RFC 8966)** — the packet/TLV wire codec, the route table with the
  feasibility condition (§3.5), and the neighbour table with Hello/IHU link
  costing, over a UDP 6696 / `ff02::1:6` runner, with dual-stack RIB-based
  redistribution.
- **Multicast** — **IGMPv3** (RFC 3376) and **MLDv2** (RFC 3810) queriers sharing
  one membership state machine with an **RFC 4605** upstream proxy, and **PIM-SM**
  sparse mode (RFC 7761) with a static RP, `(*,G)`/`(S,G)` tree state and the
  kernel multicast forwarding cache.
- **VRRP (RFC 5798)** — virtual-router first-hop redundancy with interface/route
  tracking.
- **BFD (RFC 5880 / 5881)** — single-hop asynchronous, dual-stack, with **echo
  mode**, authentication and per-session keys, driving BGP / OSPFv2 / OSPFv3 /
  IS-IS / RIP / Babel adjacency teardown far faster than the protocols' own timers.

**Platform & core**

- **Netlink FIB backend** (Linux `rtnetlink`) — installs and withdraws real kernel
  routes, attributed by origin protocol (`proto rip`/`ospf`/`bgp`/…), with **ECMP /
  multipath** (`RTA_MULTIPATH`, per-path weights) and startup route reconciliation.
- **VRFs** — named, isolated routing tables keyed by `(table, prefix)`, with a
  Route Distinguisher identity (RFC 4364), per-VRF import/export route-maps and
  per-VRF static routes installed into the VRF's own kernel table (`RTA_TABLE`).
- **Route filters** — BIRD-style import/export policy with prefix patterns,
  protocol/metric matches and metric/preference/community rewrites, and **RIB-based
  redistribution** into every routing protocol, each with an optional per-protocol
  `[export] <proto>` filter.
- **Cargo features** — each protocol compiles in or out for a slim build; BGP and
  the core are the always-on floor.
- **Management interface** — a Unix control socket answering `wren show` for the
  central RIB and each protocol's state (the BGP Loc-RIB with path attributes and
  neighbour states, OSPF/IS-IS adjacencies and interfaces, Babel neighbours and
  routes, VRFs), plus **Prometheus metrics** (`wren show metrics`).
- **Hot-reload** — `SIGHUP` reloads the full configuration live, including static
  routes and BGP neighbours, without restarting the daemon.

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
