# Changelog

All notable changes to Wren are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/), and from `0.1.0` the project
follows [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.3.1] — 2026-07-11

A bug-fix release: graceful shutdown now runs under an init system, not only on
an interactive Ctrl-C.

### Fixed

- **Graceful shutdown on `SIGTERM`, not just `SIGINT`.** The shutdown path — the
  protocol goodbyes (M10) and VRRP relinquishing mastership + releasing its
  virtual IP — previously fired only on `SIGINT`. `systemctl stop` (and container
  runtimes) send `SIGTERM`, which that path never caught, so the daemon was
  hard-killed and none of it ran. It now shuts down cleanly on either signal: a
  VRRP master stopped via systemd hands its virtual IP to the backup in about a
  second (a priority-0 advertisement) instead of waiting out the master-down
  timeout.

## [0.3.0] — 2026-07-07

Per-neighbour BGP session control, IPv6 BGP authentication, live configuration
reload, and **PIM-SM** sparse-mode multicast routing. A feature release with no
breaking API changes; every slice ships with unit tests and, where it touches the
wire, a rootless `unshare -Urn` smoke.

### BGP

- **Per-neighbour session options** — `local-as`, `update-source`,
  `ebgp-multihop`, `description`, `shutdown` and `hold-time`, configured per peer.
- **TCP-AO / TCP-MD5 over IPv6 transport** — the authenticated-session support
  that previously covered only IPv4 BGP now applies to IPv6 peers too (closing the
  0.2.0 deferred item).
- **Live neighbour hot-reload** — `SIGHUP` adds, removes and reconfigures BGP
  neighbours on a running daemon, without dropping the sessions that did not change.

### OSPF

- **OSPFv3 link-local next-hop fix** — pin the outgoing interface when the next hop
  is a link-local address, so IPv6 SPF routes install into the kernel FIB correctly
  on multi-interface routers.

### Multicast

- **PIM-SM sparse mode** (RFC 7761, static RP) — a new dependency-free
  **`wren-pim`** crate (wire codec, neighbour/Hello table and the `(*,G)`/`(S,G)`
  shared-/source-tree state machine) plus a daemon runner over a raw IP-protocol-103
  socket that programs the kernel multicast forwarding cache (`MRT_*`). Consumes the
  IGMP membership feed, delivering real inter-router multicast forwarding.

### Platform

- **Full-configuration `SIGHUP` hot-reload** — reload the whole running
  configuration live, starting with static routes and BGP neighbours, without
  restarting the daemon.
- **Fuzz targets** — libFuzzer targets for the newer wire parsers, run out of the
  standalone `fuzz/` cargo-fuzz workspace (E7).

## [0.2.0] — 2026-07-05

A broad Track-A expansion: BGP gains four new address families and route-leak
protection, **multicast** arrives (IGMP + MLD), and OSPF learns **graceful
restart**. Every slice ships with a rootless `unshare -Urn` smoke and unit tests.

### BGP

- **FlowSpec** (RFC 8955) — Flow Specification NLRI (AFI 1/2, SAFI 133) with a
  per-peer FlowSpec RIB, capability negotiation, `[bgp.flowspec]` rule
  origination (discard / rate-limit / mark), and `show bgp flowspec`.
- **SR Policy over BGP** (RFC 9256, SAFI 73) — the SR-Policy candidate model and
  wire codec (SAFI-73 NLRI + Tunnel Encapsulation attribute, RFC 9012, reusing
  the SRv6 SID structures), an SR-Policy RIB with best-candidate selection per
  `(colour, endpoint)`, and `show bgp sr-policy`.
- **BGP-LS** (RFC 7752, SAFI 71) — Link-State NLRI + BGP-LS Attribute codec
  (Node / Link / Prefix objects, loss-free TLVs incl. the SR TLVs), a Link-State
  RIB, static `[[bgp.link-state]]` origination, and `show bgp link-state`.
- **Routing security** — **eBGP default-deny** (RFC 8212, `ebgp-require-policy`)
  and **BGP roles + Only-To-Customer** (RFC 9234): role capability negotiation
  (Role Mismatch on conflict) and OTC ingress/egress procedures that stop
  provider→peer route leaks.

### Multicast (new)

- A new dependency-free **`wren-igmp`** crate speaking both families:
  **IGMPv3** (RFC 3376) over IPv4 and **MLDv2** (RFC 3810) over ICMPv6, sharing
  one address-generic §6 membership state machine and an **RFC 4605** upstream
  proxy.
- Daemon **querier runners** (raw IGMP / ICMPv6 sockets), a `[multicast]` config
  with per-family toggles, **querier election** (lowest-address wins) and §6.4
  **Last-Member-Query** fast-leave.

### OSPF

- **Graceful restart** (RFC 3623) — the opaque-LSA (RFC 5250) infrastructure, the
  **Grace-LSA** codec, **helper** mode (holds a neighbour's adjacency through its
  restart) and the **restarting** side (originate Grace-LSAs, preserve the FIB
  across the restart).
- **Cryptographic anti-replay** (RFC 2328 Appendix D) — reject replayed MD5
  packets whose sequence number regressed.
- **Passive interfaces** — advertise a subnet without forming adjacencies on it.

### BFD & IGP polish

- **BFD Echo over IPv6** (RFC 5880 §6.4), alongside the existing IPv4 echo.
- **IS-IS L1↔L2 route leaking** (RFC 5302 up/down bit).
- **RIP** and **Babel** register neighbours with the BFD engine for sub-second
  failure detection.

### Deferred

- The eBPF/XDP data-plane consumers of FlowSpec and SR Policy (flow
  classification / dataplane steering) — the BGP signalling is complete, the
  enforcement lives in the fabric data plane. Live IGP→BGP-LS export, TCP-AO/MD5
  for IPv6 transport, and gNMI/hot-reload remain on the roadmap.

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

[0.3.0]: https://github.com/velstra/wren/releases/tag/v0.3.0
[0.2.0]: https://github.com/velstra/wren/releases/tag/v0.2.0
[0.1.0]: https://github.com/velstra/wren/releases/tag/v0.1.0
[0.0.1]: https://github.com/velstra/wren/releases/tag/v0.0.1
