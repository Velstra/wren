# Roadmap

Wren is `0.0.x`. This page tracks what exists and what is planned. Each protocol is
implemented to its RFC.

## Protocols

- [x] **Static routes**
- [x] **Connected (direct) networks** — discovered via `getifaddrs`, tracked in the
  RIB and redistributed
- [x] **RIPv2** (RFC 2453) — wire codec, distance-vector table, multicast
  socket/timer runner
- [x] **RIPng** (RFC 2080, IPv6) — shares the distance-vector engine with RIPv2
- [x] **OSPFv2** (RFC 2328) — point-to-point and broadcast links, single-area,
  multi-area (inter-area via an ABR) and AS-external (an ASBR redistributing
  statics as type-5 LSAs)
- [x] **BGP-4** (RFC 4271) — IPv4 **and IPv6** unicast (the latter via **MP-BGP**,
  RFC 4760: the Multiprotocol capability negotiated in the OPEN, IPv6 reachability
  in MP_REACH_NLRI with a next-hop-self and withdrawals in MP_UNREACH_NLRI),
  eBGP and iBGP, over TCP 179, with
  **4-octet ASNs** (RFC 6793): the 4-octet AS Number capability is negotiated in
  the OPEN, AS_PATH is 4-octet between capable speakers, and AS4_PATH /
  AS4_AGGREGATOR (+ the §4.2.3 reconstruction) carry the true ASNs through legacy
  2-octet peers — **communities** (RFC 1997): the COMMUNITIES attribute with
  the well-known `no-export` / `no-advertise` propagation rules; **large
  communities** (RFC 8092): the LARGE_COMMUNITY attribute (`global:local1:local2`),
  attached globally or per-prefix via a filter; and **extended communities**
  (RFC 4360 / RFC 5668): the EXTENDED_COMMUNITIES attribute (Route Target / Route
  Origin, `rt:`/`ro:`), likewise global or per-prefix
- [x] **Babel** (RFC 8966) — loop-avoiding distance-vector over IPv6 (UDP 6696,
  `ff02::1:6`), with the feasibility condition and Hello/IHU link costing
- [x] **OSPFv3** (RFC 5340) — OSPF for IPv6, end to end. The `wren-ospfv3` library
  has the IPv6 packet/LSA wire codec (the scoped 16-bit LS Type, the compact IPv6
  prefix encoding, all seven LSA bodies with the pseudo-header checksum), the
  link-state database, the neighbour/interface state machines with DR/BDR election,
  the §13 flooding decision and the §4.8 SPF (a Dijkstra over the address-free
  Router/Network graph, prefixes attached from the Intra-Area-Prefix-LSAs and
  link-local next hops from the Link-LSAs, plus the inter-area and AS-external
  stages). The `wren-daemon` runner drives it over a raw IPv6 protocol-89 socket:
  point-to-point and broadcast links, single- and multi-area (inter-area via an
  ABR) and AS-external (an ASBR redistributing IPv6 statics).
- [x] **IS-IS** (ISO/IEC 10589, RFC 1195) — the other major link-state IGP, end to
  end and **live-verified** (two routers form a point-to-point adjacency over a
  veth, exchange LSPs and install each other's routes `proto isis`, exercised by
  `scripts/isis-redistribute-smoke.sh`). The
  PDU/TLV wire codec is in place (`wren-isis`): the common header and all nine PDU
  types (LAN/P2P Hellos, L1/L2 LSPs with the ISO 8473 Fletcher checksum, CSNP/PSNP),
  and the core TLVs for dual-stack wide-metric operation (Area Addresses, Protocols
  Supported, IS Neighbours, Extended IS Reachability, Extended IP Reachability and
  IPv6 Reachability, interface addresses, LSP Entries). The **link-state database**
  is in place too: the LSP store with the §7.3.16 recency rules, lifetime ageing,
  and the §7.3.15 CSNP/PSNP sequence-number synchronisation (request/send/in-sync
  decisions over an LSP-ID range). The **adjacency state machine** (§8.2, the
  Down→Initializing→Up three-way handshake of RFC 5303) and the **DIS election**
  (§8.4.5, preemptive, no backup, priority then SNPA tie-break) are in place too.
  The **SPF** (§7.2) is in place as well: a Dijkstra over one level's address-free
  node graph (pseudonodes as transit, the two-way check, overload transit
  avoidance), with dual-stack prefixes attached from the reachability TLVs and the
  Level-1 attached-bit default route towards the backbone. The **runner**
  (`wren-daemon`'s `isis.rs`) drives it all over an `AF_PACKET`/`SOCK_DGRAM` socket
  per interface (802.2 LLC frames to the IS-IS multicast MACs — Wren's first
  layer-2 transport): Hellos and the DIS election, LSP origination and flooding,
  CSNP/PSNP reconciliation, and the per-level SPF feeding the RIB, configured with
  an `[isis]` block.

### Protocol refinements

- OSPF: stub / NSSA areas, type-4 ASBR-summaries across areas, explicit type-5
  forwarding-address resolution, authentication
- BGP: route reflection (RFC 4456), connection-collision detection (§6.8),
  MP-BGP link-local next hops (RFC 2545 — IPv6 routing over a link-local next hop
  with interface pinning, beyond the global next hop carried today)
- Babel: ETX costing for lossy links, Route/Seqno-Request handling, prefix
  compression on send, IPv4 routes over the IPv6 transport (`RTA_VIA` next hops),
  source-specific routing

## Platform & core

- [x] **Netlink FIB backend** (Linux rtnetlink) — installs/withdraws real kernel
  routes, attributed by origin protocol
- [x] **ECMP / multipath** — routes with several next-hops (as the link-state SPFs
  produce by merging equal-cost paths) are programmed as kernel `RTA_MULTIPATH`
  routes, so every path is installed, not just the first; weights are carried too
- [~] Import / export **filters** (BIRD-style policy) — the `wren-filter` engine is
  in place (prefix-pattern lists with exact/or-longer/range, protocol and metric
  matches, accept/reject with metric/preference and **community** (`set-community`
  / `add-community`) rewrites). **Import** filters are
  wired per-protocol (`[[filter]]` + `[import]`), and the **export** filter to the
  kernel FIB (`[export] kernel`) is wired too. **Redistribution** — the router
  pushing RIB best-path routes back into a protocol to re-originate — is wired for
  **BGP** (`[bgp] redistribute = [...]`), **OSPF** (`[ospf] redistribute = [...]`,
  dynamic AS-external type-5 LSAs from the RIB rather than only the from-config
  `redistribute-static`), **RIP** (`[rip] redistribute = [...]`, advertised to
  neighbours and poisoned on withdrawal), **RIPng** (`[ripng] redistribute =
  [...]`, the IPv6 counterpart over the same address-neutral distance-vector
  engine), **Babel** (`[babel] redistribute = [...]`, originated under our
  Router-ID and retracted at metric infinity on withdrawal, dual-stack) and
  **IS-IS** (`[isis] redistribute = [...]`, carried in our own LSP as Extended-IP
  (RFC 5305) / IPv6 (RFC 5308) reachability, re-originated and flooded on change),
  each with an optional `[export] <proto>` filter reusing the same engine.
  Redistribution now covers **every routing protocol** Wren speaks. That export
  filter can also **rewrite** the routes: `set-community` / `add-community` give
  routes redistributed into BGP **per-prefix communities** (RFC 1997), beyond the
  global all-or-nothing `[bgp] community`, honouring the well-known `no-export` /
  `no-advertise` rules per prefix.
- [ ] Multiple routing tables / **VRFs**
- [~] A **management interface** and operational `show` commands — the daemon
  serves a Unix-domain control socket (`--socket`, default `/run/wren/wren.sock`).
  `wren show routes [protocol]` renders the central RIB's best routes à la `ip
  route`, `wren show bgp [routes|neighbors]` renders the BGP Loc-RIB (with
  AS_PATH, communities, LOCAL_PREF, origin) and neighbour states, `wren show
  ospf [neighbors|interfaces]` renders the OSPF adjacencies (Router ID, address,
  state) and interfaces (area, state, elected DR/BDR), and `wren show isis
  [neighbors|interfaces]` renders the IS-IS adjacencies (System ID, SNPA, per-level
  state) and circuits (type, level, elected DIS), and `wren show babel [neighbors|routes]`
  renders the Babel neighbours (Hello/IHU link costs) and selected routes. Each query is
  answered by the task that owns the data (the router loop / the BGP / OSPF / IS-IS
  / Babel task), with no shared access. More commands (other per-protocol
  neighbour/interface views) and a richer API are to come.
- [~] **Startup reconciliation** — on boot the kernel backend reads the routing
  table back (`RTM_GETROUTE` dump) and removes routes a previous wren instance
  left behind that the current config no longer programs, so a restart never
  leaves stale routes. Full **graceful restart** (holding routes across a restart
  while protocols reconverge, rather than a clean reconcile) is still to come.
- [ ] A `Fib` backend that writes routes into an **eBPF map** for the Sentinel
  XDP data plane

## On the radar (longer-term)

Wren's ambition is to be a full BIRD/FRR-class routing stack. The following are
tracked but not yet scheduled, grouped by area:

- **IGPs & link-state:** OSPFv3 NSSA + address families (RFC 5838), IS-IS
  refinements (the RFC 5303 p2p three-way TLV, L1↔L2 route leaking), RIFT, EIGRP;
  IGMP/MLD for multicast group membership.
- **BGP breadth:** unnumbered (RFC 5549), EVPN (RFC 7432), multipath / add-path
  (RFC 7911), route-refresh (RFC 2918), graceful restart + long-lived GR, route
  reflectors, confederations, extended communities, BMP
  (RFC 7854), FlowSpec (RFC 8955), RPKI origin validation, RTC (RFC 4684).
- **Data-plane & overlays:** MPLS, SR-MPLS, SRv6, VXLAN, BFD (RFC 5880),
  MLAG, anycast gateway, dual-stack.
- **Forwarding & policy:** VRFs, policy-based routing, route maps, prefix lists,
  route policies, prefix limits, max-AS-path.
- **Security:** TTL security (GTSM, RFC 5082), TCP-AO (RFC 5925), BGPsec (RFC 8205).
- **Management:** YANG models, NETCONF, RESTCONF, gNMI.

## Testing

The library crates are unit-tested with no network. Live convergence is verified
with the two-namespace harness described in
[Getting Started](getting-started.md). A future upgrade is an automated
two-router convergence test (veth + two namespaces, both running `wren`) wired
into CI, beyond the current manual smoke scripts.
