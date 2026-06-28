# OSPFv3

Wren implements **OSPFv3** ([RFC 5340](https://www.rfc-editor.org/rfc/rfc5340)) —
OSPF for IPv6 — in the `wren-ospfv3` crate. It keeps OSPFv2's algorithms (the
link-state flooding, the database recency rules, the shortest-path-first
calculation) but rebuilds the wire format around IPv6. The library lives in the
`wren-ospfv3` crate and the raw-IPv6 socket runner in `wren-daemon`; together they
bring two routers to a Full adjacency and exchange routes, just like OSPFv2.

> OSPFv3 is **not** "OSPFv2 with longer addresses". Its key idea is to *separate
> topology from addressing*: the graph (who connects to whom) is described without
> any IP prefixes, and the prefixes are advertised separately. This lets the same
> machinery route IPv6 — and, with address families (RFC 5838), IPv4 too.

## What changed from OSPFv2

Three structural changes drive the new wire format ([§2–§3](https://www.rfc-editor.org/rfc/rfc5340#section-2)):

- **It runs over IPv6.** Packets come from a link-local source address and go to
  `ff02::5` (`AllSPFRouters`) / `ff02::6` (`AllDRouters`). The common header drops
  from 24 to 16 bytes: there is **no authentication** (OSPFv3 leans on IPv6's own
  AH/ESP) and a new **Instance ID** lets several OSPFv3 instances share one link.
  The checksum is the standard IPv6 **upper-layer checksum**, taken over a
  pseudo-header — so encoding and decoding a packet need its source and
  destination addresses.
- **Topology is separated from addressing.** Router- and Network-LSAs describe the
  graph using **interface IDs** and **router IDs** only — no prefixes. Addresses
  travel in two new LSAs: **Link-LSAs** (link-local scope, one per link, carrying a
  router's link-local next-hop address and the prefixes on that link) and
  **Intra-Area-Prefix-LSAs** (the prefixes attached to a Router- or Network-LSA).
- **LSAs are explicitly scoped.** The LS Type is now a 16-bit field whose top bits
  give the flooding scope (link-local / area / AS) and how to treat an unknown
  type, so a router can flood LSA types it does not understand.

## What is implemented

**The packet codec** (§A.3) — the 16-byte common header and all five packet
bodies: Hello (§A.3.2, now with an Interface ID and a 24-bit Options field, and no
network mask), Database Description (§A.3.3), Link State Request (§A.3.4), Link
State Update (§A.3.5) and Link State Acknowledgment (§A.3.6). Every body
round-trips through `Packet::encode`/`decode`, which take the IPv6 source and
destination so they can fill and verify the pseudo-header checksum.

**The LSA codec** (§A.4) — the 20-byte LSA header (§A.4.2) with its scoped 16-bit
LS Type and the Fletcher LS checksum, the compact **IPv6 prefix encoding** (§A.4.1,
a prefix length plus only the significant address bytes, padded to 32-bit words),
and all seven LSA bodies:

| LS Type | Function | Scope | Carries |
|---|---|---|---|
| `0x2001` | Router | Area | the router's links, by interface/router ID |
| `0x2002` | Network | Area | the routers on a transit link (DR-originated) |
| `0x2003` | Inter-Area-Prefix | Area | an inter-area route to a prefix (ABR) |
| `0x2004` | Inter-Area-Router | Area | an inter-area route to an ASBR (ABR) |
| `0x4005` | AS-External | AS | a route outside the AS (ASBR) |
| `0x0008` | Link | Link-local | a link-local next hop + on-link prefixes |
| `0x2009` | Intra-Area-Prefix | Area | the prefixes of a Router-/Network-LSA |

Unknown LS types are preserved verbatim (header and body bytes) so they continue
to flood within their scope, exactly as the protocol intends.

**The link-state database** (§12.2) — a keyed store of LSAs with the §13.1
"which instance is newer" test deciding what replaces what, plus aging that reports
the LSAs which have reached MaxAge and must be flushed. The recency rules are
unchanged from OSPFv2; one database is held per flooding scope (one per interface
for Link-LSAs, one per area, one AS-wide for AS-external).

**The neighbour and interface state machines** (§10 / §9) and the **DR/BDR
election** (§9.4) — RFC 5340 leaves these unchanged from OSPFv2, so they are
ported directly. Two OSPFv3 touches: a neighbour's DR/BDR are Router IDs in the
Hello (no interface-address mapping), and the neighbour record keeps the peer's
Interface ID for building Router-LSA links.

**The shortest-path-first calculation** (§4.8) — a Dijkstra over the address-free
graph, split in two to match the v3 LSA layout:

- The **tree** is built from Router- and Network-LSAs alone, which carry only
  interface IDs and router IDs. A transit network is identified by its DR's
  `(router ID, interface ID)` rather than an interface address. Each edge is
  checked for a link *back* and MaxAge LSAs are skipped, exactly as in OSPFv2.
- **Prefixes are attached afterwards** from the Intra-Area-Prefix-LSAs: each
  references a Router- or Network-LSA on the tree and contributes its prefixes at
  `vertex distance + prefix metric`. There are no stub links or network masks to
  harvest as in OSPFv2 — every intra-area prefix arrives this way. `NU`
  (no-unicast) prefixes are dropped.
- **Next hops are link-local addresses** (§4.8.2), resolved from the first-hop
  router's Link-LSA; equal-cost paths merge into ECMP. The inter-area
  (Inter-Area-Prefix-LSA) and AS-external (E1/E2) stages reuse the per-router
  distances the tree produces, just like the OSPFv2 SPF.

**The socket runner** (`wren-daemon`) — one raw IPv6 protocol-89 socket per
interface, joined to `ff02::5`/`ff02::6` and pinned to the link, sourcing packets
from the interface's link-local address (the checksum is the IPv6 upper-layer sum,
so the destination is recovered on receive to verify it). It drives the Hellos and
DR election, the Database Exchange to Full, and the origination and flooding of
this router's LSAs — the address-free **Router-LSA**, the **Network-LSA** as DR,
the **Intra-Area-Prefix-LSAs** carrying the IPv6 prefixes, and a per-link
**Link-LSA** advertising the link-local next hop and on-link prefixes — each within
its scope (link-local / area / AS). It runs an SPF per area, folds in the
inter-area and AS-external routes, and announces them (with link-local next hops)
to the router. It is configured under [`[ospf3]`](../configuration.md), supports
point-to-point and broadcast links, multiple areas (an ABR originates
Inter-Area-Prefix-LSAs) and redistributing IPv6 statics (an ASBR).

## Not yet implemented

NSSA (type-7) LSAs, OSPFv3 address families (RFC 5838) and the stub/virtual-link
refinements tracked in the [Roadmap](../roadmap.md).
