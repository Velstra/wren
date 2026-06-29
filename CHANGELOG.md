# Changelog

All notable changes to Wren are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/), and from `0.1.0` the project
follows [Semantic Versioning](https://semver.org/).

## [0.1.0] — 2026-06-30

A large step up from the first release: BGP grows into a full-featured
implementation, **BFD** lands across every IGP, **VRFs** arrive, and the daemon
gains monitoring and a much wider operational surface. The data model now keys the
RIB and forwarding plane by `(table, prefix)`, the foundation for VRFs.

### BGP

- **MP-BGP for IPv6 unicast** (RFC 4760) end to end, with **link-local next hops**
  (RFC 2545) and route propagation (transit) between peers.
- **Extended Next Hop / IPv4-over-IPv6** (RFC 5549 / RFC 8950) and **fully
  unnumbered** sessions over IPv6 transport.
- **Route reflection** (RFC 4456) and **confederations** with `AS_CONFED_SEQUENCE`
  / `AS_CONFED_SET` path segments (RFC 5065).
- **Connection-collision detection** (RFC 4271 §6.8), **route refresh** (RFC 2918)
  and a **graceful-restart** helper (RFC 4724).
- **ADD-PATH** — multiple paths per destination (RFC 7911) — and **ECMP** install.
- **Address aggregation** (RFC 4271 §9.2.2.2), per-neighbour **default-originate**
  and a per-neighbour **maximum-prefix** limit (RFC 4486).
- Per-neighbour **inbound and outbound route filters**.
- Authentication: **TTL security / GTSM** (RFC 5082), **TCP-MD5** (RFC 2385) and
  **TCP-AO** (RFC 5925).
- **RPKI route-origin validation** (RFC 6811) fed by a live **RPKI-to-Router**
  (RTR) ROA feed (RFC 8210).
- **BMP** — stream BGP state to a monitoring station (RFC 7854).

### OSPF

- **Stub** and **totally-stubby** areas, **NSSA** and **totally-NSSA** areas with
  type-7 LSAs (RFC 2328 §3.6, RFC 3101), including injecting a type-7 default.
- Packet **authentication** — simple password and MD5 (RFC 2328 Appendix D).
- First live OSPFv3 verification.

### BFD (new)

- **Bidirectional Forwarding Detection** (RFC 5880 / RFC 5881) — single-hop
  asynchronous, **dual-stack** (IPv4 and IPv6), for sub-second failure detection.
- Drives **BGP, OSPFv2, OSPFv3 and IS-IS** adjacency teardown on a path failure
  (RFC 5882), far faster than the protocols' own timers.
- **Authentication** — Simple Password and Keyed/Meticulous MD5 & SHA-1 (RFC 5880
  §6.7), with **per-session keys** (e.g. a distinct password per BGP neighbour).

### VRFs (new)

- Named, isolated **routing tables**: the RIB and forwarding plane are keyed by
  `(table, prefix)`, so the same prefix can exist in several VRFs at once.
- `[[vrf]]` blocks with a **Route Distinguisher** (RFC 4364) identity and per-VRF
  **import/export route-maps**.
- **Static routes per VRF**, installed into the VRF's kernel table (rtnetlink
  `RTA_TABLE`), with per-table startup reconciliation; `wren show vrf`.

### Platform & operations

- **Cargo features** — each protocol can be compiled in or out for a slim build;
  BGP and the core are the always-on floor.
- **Prometheus metrics** over the existing control socket (`wren show metrics`).
- A wider operational surface: `show rip` / `show ripng`, `show ospf3`,
  `show babel [neighbors|routes]`, and `show ospf` / `show isis` **database**.

## [0.0.1] — 2026-06-28

The first public release. Wren is a small, RFC-correct routing daemon in Rust —
the job of BIRD/FRR, rebuilt with a dependency-free, embeddable core.

### Routing protocols

- **Static** routes and **connected** (direct) networks, tracked in the RIB and
  redistributable.
- **RIPv2** (RFC 2453) and **RIPng** (RFC 2080) over a shared distance-vector
  engine.
- **OSPFv2** (RFC 2328) — point-to-point and broadcast links, multi-area via an
  ABR, AS-external via an ASBR.
- **OSPFv3** (RFC 5340) — OSPF for IPv6, end to end.
- **IS-IS** (ISO/IEC 10589 + RFC 1195) — dual-stack wide metrics, L1/L2, the
  adjacency FSM, DIS election and SPF, over an `AF_PACKET` layer-2 runner.
- **BGP-4** (RFC 4271) — eBGP/iBGP over TCP 179, with **4-octet ASNs** (RFC 6793),
  **communities** (RFC 1997) and **large communities** (RFC 8092).
- **Babel** (RFC 8966) — loop-avoiding distance-vector over IPv6.

### Platform & policy

- **Netlink FIB backend** (Linux rtnetlink) with **ECMP / multipath** and
  startup route reconciliation.
- **Route filters** (BIRD-style import/export policy) with prefix patterns,
  protocol/metric matches, and metric/preference/community rewrites.
- **RIB-based redistribution** into every protocol, with optional per-protocol
  export filters.
- **Management interface**: a Unix control socket answering `wren show routes`,
  `show bgp [routes|neighbors]`, `show ospf [neighbors|interfaces]` and
  `show isis [neighbors|interfaces]`.

### Project

- **Open-core licensing**: the dependency-free `wren-core` is **Apache-2.0**
  (embeddable anywhere); the daemon and every other crate are
  **GPL-2.0-or-later** (like BIRD).
- An **mdBook handbook** under `docs/`, and rootless two-router convergence
  **smoke scripts** under `scripts/` (each runs in a throwaway `unshare -Urn`
  network namespace).

[0.1.0]: https://github.com/velstra/wren/releases/tag/v0.1.0
[0.0.1]: https://github.com/velstra/wren/releases/tag/v0.0.1
