# IS-IS

Wren is growing **IS-IS** ([ISO/IEC 10589](https://www.iso.org/standard/30932.html),
with IP routing from [RFC 1195](https://www.rfc-editor.org/rfc/rfc1195) and wide
metrics from [RFC 5305](https://www.rfc-editor.org/rfc/rfc5305) /
[RFC 5308](https://www.rfc-editor.org/rfc/rfc5308)) in the `wren-isis` crate — the
other major link-state IGP, alongside OSPF. It is built RFC-section by
RFC-section; the **PDU/TLV wire codec**, the **link-state database**, the
**adjacency state machine with DIS election**, the **SPF** and the **`AF_PACKET`
runner** are all in place — IS-IS is end to end.

> IS-IS and OSPF solve the same problem — flood link state, run Dijkstra — but
> IS-IS comes from the OSI world, and its shape shows it: it runs straight over the
> data link (no IP), names routers by a 6-byte **System ID** inside an OSI area,
> and carries *everything* — neighbours, addresses, reachability — as **TLVs**.
> That last point is its quiet superpower: the same PDUs carried IPv6 (RFC 5308) by
> adding TLVs, with no new protocol version.

## How it differs from OSPF

- **It runs over layer 2, not IP.** PDUs travel in IEEE 802.2 LLC frames
  (DSAP = SSAP = `0xFE`) to the multicast MACs `01:80:c2:00:00:14` (all L1 ISs) and
  `01:80:c2:00:00:15` (all L2 ISs), so the runner will use an `AF_PACKET` socket
  rather than an IP socket.
- **Two levels.** Level 1 routes within an area, Level 2 forms the backbone between
  areas; a router can be L1, L2 or both. Each level keeps its own Hellos, its own
  database of **LSPs** (the IS-IS analogue of OSPF's LSAs) and its own
  sequence-number PDUs.
- **The database syncs with sequence-number PDUs.** A **CSNP** lists the sender's
  whole database (as LSP summaries) so a neighbour can spot what it is missing; a
  **PSNP** asks for — or acknowledges — specific LSPs. There is no separate
  OSPF-style adjacency database exchange.

## What is implemented

**The PDU codec** (`pdu`) — the 8-byte common header (the `0x83` discriminator,
the lengths, the version and Maximum Area Addresses) and all nine PDU types: the
**LAN** and **point-to-point Hellos** (IIH), the Level-1/Level-2 **LSPs**, and the
**CSNP**/**PSNP**. Each round-trips through `Pdu::encode`/`Pdu::decode`, which fill
in the PDU-length field and, for an LSP, compute and verify the **ISO 8473 Fletcher
checksum** over the LSP body.

**The TLV codec** (`tlv`) — the type-length-value framework and the TLVs IS-IS
needs for modern dual-stack operation, with any unrecognised type preserved
verbatim so a PDU still round-trips:

| Type | TLV | Carries |
|---|---|---|
| 1 | Area Addresses | the area(s) the originator belongs to |
| 6 | IS Neighbours | a LAN neighbour's SNPA (MAC), to prove two-way reachability |
| 8 | Padding | bytes padding a Hello to the MTU |
| 9 | LSP Entries | LSP summaries in a CSNP/PSNP |
| 10 | Authentication | the authentication type and data |
| 22 | Extended IS Reachability | wide-metric links to neighbours (RFC 5305) |
| 129 | Protocols Supported | the NLPIDs (IPv4 `0xCC`, IPv6 `0x8E`) |
| 132 | IP Interface Addresses | the originator's IPv4 addresses |
| 135 | Extended IP Reachability | wide-metric IPv4 prefixes (RFC 5305) |
| 232 | IPv6 Interface Addresses | the originator's IPv6 addresses (RFC 5308) |
| 236 | IPv6 Reachability | wide-metric IPv6 prefixes (RFC 5308) |

The prefixes in the reachability TLVs are packed to whole bytes (`ceil(len/8)`),
exactly as on the wire, and the up/down and external bits are modelled.

**The link-state database** (`lsdb`) — the LSP store for one level, with the
ISO 10589 §7.3 machinery on top:

- **Recency (§7.3.16).** `install` keeps the most recent copy of each LSP, keyed
  by its 8-byte LSP ID: a higher sequence number wins; on a tie, a zero Remaining
  Lifetime (a purge) beats a live copy; on a further tie, the larger checksum is
  the deterministic discriminator. The outcome (`New`/`Newer`/`Same`/`HaveNewer`)
  tells the caller whether to flood the LSP onward and re-run SPF.
- **Ageing.** Unlike OSPF's age, which counts *up* to `MaxAge`, an IS-IS Remaining
  Lifetime counts *down*; `age` decrements every LSP and reports the IDs that just
  reached zero, for purging from the domain.
- **CSNP/PSNP synchronisation (§7.3.15).** `summary` describes the database as the
  LSP Entries of a CSNP; `evaluate_entry` classifies one neighbour entry as
  *request* (we lack it or hold an older copy), *send* (ours is newer) or
  *in-sync*; and `evaluate_csnp` runs the full comparison over a CSNP's
  `[start, end]` range — including treating any LSP we hold in that range but the
  CSNP never listed as one the sender is missing.

**The adjacency state machine** (`adjacency`) — the per-neighbour, per-level
conversation (ISO 10589 §8.2 with the [RFC 5303](https://www.rfc-editor.org/rfc/rfc5303)
point-to-point three-way handshake). It is far simpler than OSPF's eight-state
neighbour FSM, because IS-IS has no master/slave Database Description exchange —
the CSNP/PSNP sync above does that work — so the whole machine is just **Down →
Initializing → Up**. The pivot is *two-way reachability*: a router proves it hears
a neighbour by listing it back (the neighbour's SNPA in the IS Neighbours TLV on a
LAN, the three-way TLV on a point-to-point link), so `Adjacency::handle` only needs
to know whether a received Hello **lists us** — the IS-IS analogue of OSPF's
one-way/two-way split — and returns the actions to arm the holding timer,
(re)originate LSPs, re-run SPF and re-run the DIS election.

**The DIS election** (`dis`) — the LAN-only, per-level election of the Designated
Intermediate System that originates the pseudonode LSP (ISO 10589 §8.4.5). Two
things make it simpler than OSPF's DR/BDR election: it is **preemptive** (a
higher-priority router that appears takes over at once — no "established DR keeps
the role" rule, so the election is a plain maximum) and there is **no backup** (a
lost DIS is just re-elected, the DIS's frequent CSNPs keeping the database tight).
The winner is the highest priority, ties broken on the highest **SNPA** (the LAN
MAC, *not* the System ID); every router is eligible, so even a lone priority-0
router becomes its own DIS.

**The SPF** (`spf`) — the Decision Process (ISO 10589 §7.2): a pure Dijkstra over
one level's database. Like OSPFv3 it runs over an **address-free graph** — the
vertices are *nodes* named by a 7-byte ID (a System ID plus a pseudonode number),
and IP addressing is attached afterwards:

- **Edges come from Extended IS Reachability** (TLV 22). A LAN is a **pseudonode**
  — exactly the role OSPF's transit-network vertex plays: members point at the
  pseudonode at the interface metric, the pseudonode points back at every member at
  metric 0. Each edge is kept only if the neighbour advertises a link *back* (the
  two-way check), and a purged (zero-lifetime) LSP is treated as absent, so a
  half-converged database never poisons the tree.
- **The overload bit means "do not transit me."** A node that set the LSP Database
  Overload bit still has its own prefixes reached, but the SPF never routes
  *through* it.
- **Prefixes are attached dual-stack**: every settled node contributes its Extended
  IP Reachability (TLV 135, IPv4) and IPv6 Reachability (TLV 236) prefixes at
  `node_distance + prefix_metric`, merging equal-cost next hops into ECMP.
- **The attached bit draws a default route** (RFC 1195 §3.2 / RFC 5308). Run for
  **Level 1**, every reachable L1L2 router that set the ATT bit yields a default
  route (`0.0.0.0/0` and/or `::/0`, per the address families it advertises support
  for) towards the backbone — the L1/L2 hierarchy's exit. Run for Level 2 the
  attached bit is inert.

Next hops are resolved best-effort from the database alone (a first-hop router's
interface addresses, TLV 132 / 232); a directly-attached LAN or unnumbered link
yields an on-link route. IS-IS truly binds the next hop to the adjacency's SNPA, so
the runner refines these with the addresses it learned in the Hello exchange.

**The runner** (`wren-daemon`'s `isis.rs`) is Wren's **first layer-2 runner** —
IS-IS rides directly on the data link, not on IP. It opens one
`AF_PACKET`/`SOCK_DGRAM` socket per interface, joined to the IS-IS multicast MACs
`AllL1ISs`/`AllL2ISs`; frames are IEEE 802.2 LLC (DSAP = SSAP = `0xFE`, control =
`0x03`) wrapping the PDU, and the kernel adds and strips the 802.3 MAC header for
us so a received frame's source MAC is the neighbour's SNPA. It runs Hellos to
bring up adjacencies (broadcast and point-to-point) and the LAN DIS election,
originates this router's LSP (and, as DIS, the pseudonode LSP) and floods it,
reconciles the databases with periodic CSNPs and PSNPs, runs the SPF per level and
announces the resulting routes to the central router. It is configured with an
`[isis]` block:

```toml
[isis]
enabled = true
interfaces = ["eth1", "eth2"]
system-id = "1921.6800.1001"   # or derived from the top-level router-id
area = "49.0001"
level = "l1l2"                  # "l1" | "l2" | "l1l2"
network-type = "broadcast"     # or "point-to-point"
```

### Redistribution from the RIB

Beyond its own connected networks, IS-IS can advertise the routes other protocols
hold in the RIB — statics, or routes learned by another IGP or BGP — by naming
their protocols under `redistribute`:

```toml
[isis]
enabled      = true
interfaces   = ["eth1"]
redistribute = ["connected", "static", "bgp"]   # RIB source protocols
redistribute-metric = 20                         # defaults to the interface metric
```

This is the same router → protocol push that feeds [BGP](bgp.md#redistribution),
[OSPF](ospf.md#redistribution-from-the-rib), [RIP](rip.md#redistribution-from-the-rib)
and [Babel](babel.md#redistribution-from-the-rib) redistribution: the [central
router loop](../architecture.md) offers each best-path change to IS-IS, which adds
it to **its own LSP** as reachability — an Extended IP Reachability entry (type
135, RFC 5305) for IPv4 or an IPv6 Reachability entry with the **external bit**
(type 236, RFC 5308) for IPv6 — re-originating and flooding the LSP (a sequence-
number bump) on each change, and removing the entry again when the best path goes
away. Both IPv4 and IPv6 are carried; a prefix IS-IS already advertises as a
connected network takes precedence; it never redistributes its own routes; and an
optional `[export] isis = "name"` filter (the same `wren-filter` engine) gates and
rewrites the routes first.

`scripts/isis-redistribute-smoke.sh` exercises it live (rootless): an IPv6 static
is withheld from the peer without `redistribute`, then carried in the LSP and
installed `proto isis` once `redistribute = ["static"]` is set. This is also the
**first end-to-end verification of the IS-IS runner itself**, two routers forming
a point-to-point adjacency over a veth and exchanging LSPs.

## Inspecting it

The daemon answers two IS-IS `show` commands over its
[control socket](../configuration.md), each rendered by the IS-IS task itself out
of the live state it owns (its interfaces, their per-level adjacencies and the DIS
election) — no shared access, exactly like `show routes`, `show bgp` and `show
ospf`:

```console
$ wren show isis neighbors
0000.0000.0002 via aa:8f:c2:a7:39:e7 dev veth0 level 1 state Up
0000.0000.0002 via aa:8f:c2:a7:39:e7 dev veth0 level 2 state Up

$ wren show isis interfaces
veth0 type point-to-point level l1l2
```

`show isis neighbors` lists every adjacency — one line per neighbour **per level**
(an L1L2 circuit forms a separate L1 and L2 adjacency), with the neighbour's
System ID, its SNPA (the MAC on a LAN), the local interface, the level and the
state (`Down` / `Init` / `Up`). `show isis interfaces` lists each circuit with its
type (`broadcast` / `point-to-point`), the level(s) it runs and, on a broadcast
circuit, the elected `dis-l1` / `dis-l2` LAN ID (marked `(self)` when this router
won the election). `scripts/isis-show-smoke.sh` exercises both live (rootless):
two routers form a point-to-point L1L2 adjacency and the queries report both levels
Up.

## Not yet implemented

Refinements tracked in the [Roadmap](../roadmap.md): the RFC 5303 point-to-point
three-way-handshake TLV (p2p adjacencies come up classic two-way today), SRM/SSN
retransmit lists (flooding is reflood-on-change plus periodic CSNP reconciliation),
LSP fragmentation, and L1↔L2 route leaking beyond the attached-bit default.
