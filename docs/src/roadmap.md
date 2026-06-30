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
  in MP_REACH_NLRI with a next-hop-self and withdrawals in MP_UNREACH_NLRI; toward
  a directly-connected peer the next hop is a 32-octet global+link-local pair
  (RFC 2545), and a received link-local next hop is installed pinned to its
  interface), eBGP and iBGP, over TCP 179, with
  **4-octet ASNs** (RFC 6793): the 4-octet AS Number capability is negotiated in
  the OPEN, AS_PATH is 4-octet between capable speakers, and AS4_PATH /
  AS4_AGGREGATOR (+ the §4.2.3 reconstruction) carry the true ASNs through legacy
  2-octet peers — **communities** (RFC 1997): the COMMUNITIES attribute with
  the well-known `no-export` / `no-advertise` propagation rules; **large
  communities** (RFC 8092): the LARGE_COMMUNITY attribute (`global:local1:local2`),
  attached globally or per-prefix via a filter; and **extended communities**
  (RFC 4360 / RFC 5668): the EXTENDED_COMMUNITIES attribute (Route Target / Route
  Origin, `rt:`/`ro:`), likewise global or per-prefix. Learned best paths are
  **propagated** onward to the other peers (transit, IPv4 and IPv6): the local AS
  is prepended and next-hop-self set toward eBGP, with the iBGP split-horizon rule
  applied — and **route reflection** (RFC 4456): an iBGP peer marked a client has
  its routes reflected to the other iBGP peers (ORIGINATOR_ID / CLUSTER_LIST loop
  avoidance) — and **confederations** (RFC 5065): a confederation is split into
  Member-ASes (`confederation-id` + `confederation-members`), each peer being iBGP
  (same Member-AS), confed-eBGP (a different Member-AS in the confederation — the
  Member-AS is prepended to an AS_CONFED_SEQUENCE, LOCAL_PREF and next hop kept) or
  true eBGP (outside — the internal confederation segments are stripped and the
  Confederation Identifier prepended, so the confederation is seen as one AS);
  confederation segments are excluded from AS_PATH length, the OPEN presents the
  Member-AS to confederation peers and the Confederation Identifier to external
  ones, and a route looping back into our Member-AS is dropped — and **route
  refresh** (RFC 2918): the capability is negotiated in the OPEN, a received
  ROUTE-REFRESH makes us re-advertise our Adj-RIB-Out to that peer, and `wren bgp
  refresh <peer>` sends one — and **graceful restart** (RFC 4724): the capability
  is negotiated in the OPEN (advertising the forwarding state preserved across a
  restart and a Restart Time), an End-of-RIB marker is sent once the initial
  advertisement to a peer completes, and as a **helper** wren retains a restarting
  peer's routes in service (and in the kernel FIB) instead of withdrawing them when
  the session drops — reconciled when the peer returns and sends its End-of-RIB, or
  flushed when the Restart Timer expires. Live-verified by
  `scripts/bgp-graceful-restart-smoke.sh` (a peer is hard-killed and its routes
  survive the restart) — and **ADD-PATH** (RFC 7911): the capability is negotiated
  per neighbour (`add-path = true`, Send+Receive for IPv4 unicast), every NLRI then
  carries a 4-octet Path Identifier, the Adj-RIB-In keeps multiple paths per
  destination (keyed by `(peer, path-id)`), and a send-side peer is advertised every
  candidate path (not just the best) under a stable Path Identifier — `show bgp
  paths` lists them, live-verified by `scripts/bgp-add-path-smoke.sh` (a peer learns
  two paths for one prefix from a single iBGP neighbour) — and **Extended Next Hop /
  IPv4-over-IPv6** (RFC 5549 / RFC 8950): the Extended Next Hop Encoding capability is
  negotiated per neighbour (`extended-nexthop = true`), IPv4 routes are advertised in
  MP_REACH_NLRI (AFI IPv4) with an IPv6 next-hop-self, and a received IPv4 route with
  an IPv6 next hop is installed via that gateway using the kernel's `RTA_VIA`
  (`via inet6 …`) — live-verified by `scripts/bgp-extended-nexthop-smoke.sh` against
  the real kernel FIB — and **full unnumbered (IPv6 transport)**: the BGP TCP session
  itself rides IPv6 (a neighbour `address` may be an IPv6 literal, or a link-local
  `fe80::1%eth0` with an interface scope), bound on a single dual-stack listener, with
  the BGP Identifier still a 32-bit `router-id` — live-verified over an IPv6-only veth
  (no IPv4 on the link) by `scripts/bgp-unnumbered-smoke.sh` — and **RPKI origin
  validation** (RFC 6811): received routes are classified Valid / Invalid / NotFound
  against a static ROA table (`[[bgp.roa]]`), `rpki-reject-invalid` drops Invalid
  routes at import, and `show bgp` / `show bgp roa` expose the validity and the table
  — live-verified by `scripts/bgp-rpki-smoke.sh` (a feed of one valid + one invalid
  origin; the latter never reaches the RIB or kernel) — and the **RPKI-to-Router (RTR)
  protocol** (RFC 8210): a client fetches ROAs live from a validating cache (Reset /
  Serial Query, Prefix PDUs, End of Data, Cache Reset) and feeds them into the same
  ROA table (merged with any static `[[bgp.roa]]`), refreshing and reconnecting as
  needed — live-verified by `scripts/bgp-rtr-smoke.sh` against an independent Python
  cache
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
  ABR) and AS-external (an ASBR redistributing IPv6 statics). The runner is
  **live-verified**: two routers form a point-to-point adjacency over a veth and
  reach Full (`scripts/ospf3-show-smoke.sh`).
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

- OSPF: the RFC 3101 §3.2 NSSA translator election, type-4 ASBR-summaries across
  areas, explicit type-5 forwarding-address resolution. **Authentication (RFC 2328 §D)
  is done**: `[ospf] auth-type` selects `none`, a `text` simple password (AuType 1), or
  `md5` keyed-MD5 (AuType 2, in-process digest) — a mismatched key or scheme drops the
  packet and no adjacency forms (MD5 anti-replay sequencing is the one remaining gap).
  **Stub areas
  (RFC 2328 §3.6) are done**: an area marked `stub` carries no AS-external (type-5)
  LSAs — the E-bit is cleared in its Hellos and Database Descriptions so only
  stub-agreeing neighbours adjacency-up, and an ABR injects a default route (a type-3
  `0.0.0.0/0` summary) into it in place of the externals it never sees. **NSSA areas
  (RFC 3101) are done**: an area marked `nssa` likewise carries no type-5, but an
  ASBR inside it originates type-7 LSAs (N-bit matched in Hellos), and the area
  border router translates those to type-5 and floods them into the rest of the AS.
  **The "no-summary" variants are done too**: a `totally-stubby` area also has its
  inter-area (type-3) summaries suppressed by the ABR (only the default remains),
  and a `totally-nssa` area likewise suppresses summaries and has the ABR inject a
  **type-7 default** (P-bit clear, so it is not translated AS-wide). **A plain NSSA
  can also opt into a default** via `nssa-default-areas`: the ABR injects the same
  type-7 `0.0.0.0/0` default but keeps the summaries, giving the area a path to the
  AS-external destinations an NSSA never carries.
- Babel: ETX costing for lossy links, Route/Seqno-Request handling, prefix
  compression on send, IPv4 routes over the IPv6 transport (`RTA_VIA` next hops),
  source-specific routing

## Platform & core

- [x] **Netlink FIB backend** (Linux rtnetlink) — installs/withdraws real kernel
  routes, attributed by origin protocol
- [x] **ECMP / multipath** — routes with several next-hops (as the link-state SPFs
  produce by merging equal-cost paths) are programmed as kernel `RTA_MULTIPATH`
  routes, so every path is installed, not just the first; weights are carried too.
  **BGP multipath** feeds the same machinery: with `[bgp] multipath = N` a router
  installs up to `N` equal-cost BGP paths (identical LOCAL_PREF / AS_PATH / ORIGIN /
  MED / eBGP-iBGP class / IGP cost) for a prefix as one ECMP route, while still
  advertising only the single best path onward
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
- [~] Multiple routing tables / **VRFs** — the foundation is **done**: the RIB and
  forwarding plane are keyed by `(table, prefix)` so overlapping prefixes coexist;
  `[[vrf]]` defines a named VRF (kernel `table`, RFC 4364 **Route Distinguisher**, a
  per-VRF `import`/`export` **route-map**); `[[static]] vrf = "…"` installs a static
  into the VRF's kernel table (via rtnetlink `RTA_TABLE`); `show vrf` reports them and
  startup reconciliation runs per table. Live-verified by `scripts/vrf-smoke.sh`
  (static into table 100, overlapping prefix isolated per table, route-map rejection,
  `show vrf`). **Dynamic routing in a VRF** covers **every protocol**: **RIP** (`[rip]
  vrf = "…"`), **OSPF** (`[ospf] vrf = "…"`), **IS-IS** (`[isis] vrf = "…"`), **Babel**
  (`[babel] vrf = "…"`) and **BGP** (`[bgp] vrf = "…"`) stamp the VRF's table on every
  route they produce (`RouteUpdate` carries the table end to end), so their routes land
  in the VRF's kernel table; BGP additionally binds its session sockets to the VRF
  (`SO_BINDTODEVICE`) so the peerings use the VRF's routing table. Live-verified by
  `scripts/vrf-dynamic-smoke.sh` (RIP), `scripts/vrf-ospf-smoke.sh` (OSPF),
  `scripts/vrf-isis-smoke.sh` (IS-IS), `scripts/vrf-babel-smoke.sh` (Babel) and
  `scripts/vrf-bgp-smoke.sh` (BGP) — B learns A's route into table 100, not the main
  table. The remaining big piece is **BGP/MPLS L3VPN** (VPNv4 AFI, RD on the wire,
  route targets). See [VRFs & Route Distinguishers](vrf.md).
- [~] A **management interface** and operational `show` commands — the daemon
  serves a Unix-domain control socket (`--socket`, default `/run/wren/wren.sock`).
  `wren show routes [protocol]` renders the central RIB's best routes à la `ip
  route`, `wren show bgp [routes|paths|neighbors]` renders the BGP Loc-RIB (with
  AS_PATH, communities, LOCAL_PREF, origin), the full Adj-RIB-In (every candidate
  path with its ADD-PATH Path Identifier) and neighbour states, `wren show
  ospf [neighbors|interfaces|database]` renders the OSPF adjacencies (Router ID,
  address, state), interfaces (area, state, elected DR/BDR) and the link-state
  database (every LSA's type, Link State ID, advertising router, sequence, age),
  `wren show ospf3
  [neighbors|interfaces]` does the same for OSPFv3 (neighbours by Router ID over
  their IPv6 link-local, interfaces by area and state), `wren show isis
  [neighbors|interfaces|database]` renders the IS-IS adjacencies (System ID, SNPA,
  per-level state), circuits (type, level, elected DIS) and the per-level
  link-state database (every LSP's ID, sequence, checksum, lifetime, att/p/ol
  flags), `wren show babel [neighbors|routes]`
  renders the Babel neighbours (Hello/IHU link costs) and selected routes, and
  `wren show rip` / `wren show ripng` render the RIPv2 / RIPng distance-vector table
  (destination, metric, gateway, interface). Each query is answered by the task that
  owns the data (the router loop / the per-protocol task), with no shared access —
  the send/await plumbing is one generic helper, so a new `show <proto>` is a parser
  plus a render branch. Beyond `show`, `wren bgp refresh <peer>` sends that peer a
  ROUTE-REFRESH (RFC 2918). More per-protocol detail views and a richer API are to
  come.
- [~] **Startup reconciliation** — on boot the kernel backend reads the routing
  table back (`RTM_GETROUTE` dump) and removes routes a previous wren instance
  left behind that the current config no longer programs, so a restart never
  leaves stale routes. **BGP graceful restart** (RFC 4724) builds on this: wren's
  kernel FIB outlives the process, so a BGP peer that helps wren keeps forwarding to
  it across the restart while wren re-advertises and sends End-of-RIB — and wren is
  itself a helper for restarting peers (see the BGP entry). Signalling the Restart
  State (R) flag in the first OPEN after our own restart, and graceful restart for
  the IGPs, are still to come.
- [ ] A `Fib` backend that writes routes into an **eBPF map** for the Sentinel
  XDP data plane

## On the radar (longer-term)

Wren's ambition is to be a full BIRD/FRR-class routing stack. The following are
tracked but not yet scheduled, grouped by area:

- **IGPs & link-state:** OSPFv3 NSSA + address families (RFC 5838), IS-IS
  refinements (the RFC 5303 p2p three-way TLV, L1↔L2 route leaking), RIFT, EIGRP;
  IGMP/MLD for multicast group membership.
- **BGP breadth:** EVPN (RFC 7432), long-lived graceful restart (RFC 9494),
  RTC (RFC 4684). (**FlowSpec** (RFC 8955) is **in progress** — the flow-specification
  NLRI codec (the §4.2 components with their numeric/bitmask operators, the §4 length
  prefix) and the §7 traffic-filtering action extended communities (rate-limit /
  discard, marking) are **done** and unit-tested in `wren-bgp::flowspec`; the MP-BGP
  SAFI 133 exchange, a FlowSpec RIB, `show bgp flowspec` and kernel application via
  nftables are the next steps.) (**BMP** (RFC 7854) — streaming BGP state
  (Initiation, Peer Up, Route Monitoring, Peer Down) to a monitoring station via
  `[bgp.bmp]` — is **done**; see [Monitoring](monitoring.md).)
  (**Extended Next Hop / IPv4-over-IPv6** (RFC 5549 / RFC 8950) — advertising IPv4
  routes with an IPv6 next hop and installing them via the kernel's `RTA_VIA`,
  negotiated per neighbour with `extended-nexthop = true` — is **done**, including
  **full unnumbered**: the BGP session may run over an IPv6 (or link-local
  `fe80::…%iface`) transport on an IPv6-only link. **ADD-PATH** (RFC 7911) — advertising and keeping several paths
  per prefix, each under a 4-octet Path Identifier, negotiated per neighbour with
  `add-path = true` for IPv4 unicast — is **done** (IPv6/MP add-path is a future
  extension). Per-peer `default-originate` — advertising `0.0.0.0/0` to a neighbour —
  is **done**.
  **Address aggregation** (RFC 4271 §9.2.2.2) — a `[[bgp.aggregate]]` covering prefix
  advertised with ATOMIC_AGGREGATE/AGGREGATOR once a more-specific originated route
  contributes, with optional `summary-only` suppression — is **done** (for locally
  originated/redistributed contributors; no `as-set`, no learned-route aggregation).)
- **Data-plane & overlays:** MPLS, SR-MPLS, SRv6, VXLAN, MLAG, anycast gateway,
  dual-stack. (**BFD** (RFC 5880 / RFC 5881) — sub-second forwarding-path failure
  detection — is **done** for single-hop asynchronous mode (IPv4 **and IPv6**, no
  auth/Echo): the dependency-free `wren-bfd` crate (Control-packet codec + the
  §6.8.6 session FSM) and a dual-stack UDP runner driving it on port 3784 with
  TTL/hop-limit-255 single-hop packets, keyed by `(source, scope)` so IPv6
  link-local peers stay distinct. Sessions are dynamic and multi-consumer. **BGP**
  (a neighbour with `bfd = true`), **OSPFv2** (`[ospf] bfd = true`), **OSPFv3**
  (`[ospf3] bfd = true`) and **IS-IS** (`[isis] bfd = true`) all use it — a session
  per adjacent neighbour: a BFD-down tears the BGP session down (instead of the Hold
  Timer) or the OSPF/OSPFv3/IS-IS adjacency down (instead of the dead/holding timer,
  RFC 5882 §4.4). IS-IS runs over SNPA/MAC, so the neighbour's IP for BFD is taken
  from the IP Interface Address TLV in its Hellos. `[bfd]` sets the timing and
  `show bfd` lists the sessions. Live-verified by `scripts/bgp-bfd-smoke.sh` (a
  blackholed path drops BGP in ~0.6 s against a 180 s hold time),
  `scripts/ospf-bfd-smoke.sh`, `scripts/ospf3-bfd-smoke.sh` and
  `scripts/isis-bfd-smoke.sh` (drop the OSPF / OSPFv3 / IS-IS adjacency in ~0.5–0.65 s
  against a 9–40 s dead/holding timer). **Authentication** (RFC 5880 §6.7) is
  implemented — Simple Password and Keyed/Meticulous MD5 & SHA-1 (the hashes
  hand-rolled to keep `wren-bfd` dependency-free), configured per `[bfd]`
  (`auth-type`/`auth-key`) and verified including the replay window, live-tested by
  `scripts/bfd-auth-smoke.sh` (matching keys form the session, a mismatched key is
  rejected). The **Echo function** (RFC 5880 §6.4, IPv4) is implemented — `[bfd] echo
  = true` runs looped-back Echo packets (over a raw `AF_PACKET` socket, since the
  loop carries the local address as source and destination) through the neighbour's
  forwarding plane at a fast `echo-interval`, failing the session with diagnostic Echo
  Function Failed when they stop returning, well before Control detection; live-tested
  by `scripts/bfd-echo-smoke.sh` (a path break is caught via Echo in ~0.3 s against a
  6 s Control detection). Demand mode is the remaining future extension. See
  [BFD](protocols/bfd.md).)
- **Forwarding & policy:** VRFs, policy-based routing, route maps, prefix lists,
  route policies, max-AS-path. (Per-neighbour BGP `max-prefix` prefix-limiting with a
  Cease teardown (RFC 4486) is **done**. **Per-neighbour import *and* export filters**
  are **done** — a neighbour's `import =` / `export =` name `[[filter]]` blocks applied
  to every route received from / advertised to that peer (reject drops/suppresses it;
  accept folds set-metric→MED, set-preference→LOCAL_PREF and set-community into the
  path), covering both originated and propagated transit routes outbound.)
- **Security:** **TTL security (GTSM, RFC 5082) is done** — a per-neighbour
  `ttl-security = <hops>` makes a BGP session send with TTL 255 and reject received
  packets below `255 − (hops − 1)`, so a peer further than `hops` away cannot inject
  into it. **TCP-MD5 authentication (RFC 2385) is done too** — a per-neighbour
  `password` installs a `TCP_MD5SIG` key on the connector and the listener, so the
  kernel signs and verifies every segment and an unkeyed peer cannot even complete
  the handshake. **TCP-AO (RFC 5925) is done too** — a per-neighbour `ao-key` installs
  an HMAC-SHA-1 key via `TCP_AO_ADD_KEY` (its modern, per-connection-keyed successor),
  mutually exclusive with `password`. Still open: BGPsec (RFC 8205).
- **Management:** YANG models, NETCONF, RESTCONF, gNMI.

## Testing

The library crates are unit-tested with no network. Live convergence is verified
with the two-namespace harness described in
[Getting Started](getting-started.md). A future upgrade is an automated
two-router convergence test (veth + two namespaces, both running `wren`) wired
into CI, beyond the current manual smoke scripts.
