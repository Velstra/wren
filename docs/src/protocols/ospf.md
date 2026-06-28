# OSPFv2

Wren implements **OSPFv2** ([RFC 2328](https://www.rfc-editor.org/rfc/rfc2328))
end to end: it forms adjacencies, floods link-state advertisements, runs the
shortest-path-first calculation, and installs the resulting routes. OSPF rides
directly on IP (protocol 89), using the multicast groups `224.0.0.5` (AllSPFRouters)
and `224.0.0.6` (AllDRouters).

## What is implemented

**The wire format** — the 24-byte common header (with the IP-style packet
checksum) and all five packet types: Hello, Database Description, Link State
Request, Link State Update and Link State Acknowledgment. All four LSA bodies —
Router, Network, Summary (type 3/4) and AS-external (type 5) — sit under the
20-byte LSA header with the Fletcher checksum (RFC 1008).

**The link-state database** — one database per flooding scope, with the §13.1
recency test (sequence → checksum → age) driving install decisions, and LSA aging
to MaxAge.

**The state machines** — the neighbour FSM (§10: Down → Init → 2-Way → ExStart →
Exchange → Loading → Full) and the interface FSM (§9), including the **DR/BDR
election** (§9.4) with its tie-breaks and non-preemption.

**Flooding** (§13) — a pure decision kernel deciding install / acknowledge /
re-flood, plus the §13.3 scope rules (which multicast group, and when to suppress).

**SPF** — the intra-area Dijkstra (§16.1) with §16.1.1 next-hop and stub handling,
the §16.2 inter-area calculation across Summary-LSAs, and the §16.4 AS-external
calculation (E1/E2 metrics).

The **runner** ties these together over a raw IP socket per interface: Hellos and
neighbour discovery, the DR/BDR election, the master/slave Database Exchange
(§10.8) through LSR/LSU to Full, Router-LSA and (as DR) Network-LSA origination
with flooding, and SPF routes announced into the RIB.

## Topologies that work today

- **Point-to-point and broadcast links**, single area — two routers each learn the
  other's subnet; on a broadcast segment this waits for the DR election.
- **Multi-area** — a link-state database and SPF per area, plus an **area border
  router** that originates Summary-LSAs (type 3) into each area and runs the
  inter-area route calculation. Verified across a three-router / two-area topology.
- **AS-external** — an **ASBR** redistributes static routes as AS-wide type-5 LSAs
  (E1/E2 metrics), and other routers install them as external routes.

## Configuration

A single-area broadcast setup:

```toml
router-id = "10.0.0.1"

[ospf]
enabled    = true
interfaces = ["eth1"]
area       = "0.0.0.0"
cost       = 10
```

An area border router with one interface on the backbone and one in area 1:

```toml
router-id = "2.2.2.2"

[ospf]
enabled = true
area    = "0.0.0.1"

[[ospf.interface]]
name = "eth_backbone"
area = "0.0.0.0"

[[ospf.interface]]
name = "eth_area1"
area = "0.0.0.1"
```

An ASBR redistributing statics as type-5 externals:

```toml
[[static]]
prefix = "192.168.99.0/24"
dev    = "dummy0"

[ospf]
enabled             = true
interfaces          = ["eth1"]
redistribute-static = true
redistribute-metric = 20
```

See the [Configuration](../configuration.md) reference for every field.

### Redistribution from the RIB

`redistribute-static` above injects the *configured* static routes once at
startup. The more general form is `redistribute`, which names the **RIB source
protocols** whose best-path routes OSPF re-originates as AS-external (type-5)
LSAs **dynamically** — as they appear, change and disappear:

```toml
[ospf]
enabled      = true
interfaces   = ["eth1"]
redistribute = ["connected", "static", "bgp"]   # RIB source protocols
redistribute-metric = 20                         # the type-2 external metric
```

This is the same router → protocol push that feeds [BGP
redistribution](bgp.md#redistribution): the [central router
loop](../architecture.md) offers each best-path change to OSPF, which adds the
prefix to its external set (re-flooding its type-5 LSAs and re-running SPF) and
withdraws it again when the route's best path goes away. Only IPv4 routes are
redistributed; OSPF never redistributes its own routes; and an optional `[export]
ospf = "name"` filter (the same `wren-filter` engine) gates and rewrites the
routes before they become externals. `scripts/ospf-redistribute-smoke.sh`
exercises it live (rootless): a static is withheld from the peer without
`redistribute`, then learned as an OSPF external and installed `proto ospf` once
`redistribute = ["static"]` is set.

## Testing it

On a point-to-point veth between two namespaces (each also holding a dummy stub
subnet), both routers reach `adjacency Full` and install the other's stub:

```text
10.20.0.0/24 via 10.0.0.2 proto ospf metric 20   # = link cost 10 + stub cost 10
```

> **Timing.** Broadcast DR election waits one `RouterDeadInterval` (40 s by
> default) on a cold start before a DR appears, so a broadcast smoke test needs to
> run for ~45 s. Point-to-point links have no election and converge immediately.

## Inspecting it

The daemon answers two OSPF `show` commands over its
[control socket](../configuration.md), each rendered by the OSPF task itself out
of the live state it owns (its interfaces, their neighbours and the DR election) —
no shared access, exactly like `show routes` and `show bgp`:

```console
$ wren show ospf neighbors
10.0.0.2 via 10.0.0.2 dev veth0 state Full

$ wren show ospf interfaces
veth0 area 0.0.0.0 10.0.0.1 state PtP pri 1
```

`show ospf neighbors` lists every neighbour on every interface — its Router ID,
its interface address, the local interface and the adjacency state (`Down` …
`Full`). `show ospf interfaces` lists each OSPF interface with its area, address,
state (`PtP`, `DROther`, `Backup`, `DR`, …), this router's priority and, on a
multi-access network, the elected `dr` / `bdr`. `scripts/ospf-show-smoke.sh`
exercises both live (rootless): two routers form a point-to-point adjacency and
the queries report it reaching Full.

## Stub areas (RFC 2328 §3.6)

A **stub area** keeps the link-state database small by carrying no AS-external
(type-5) LSAs: routers inside it reach external destinations through a single
default route the area border router injects, rather than learning every external
prefix. Mark an area a stub by listing its id:

```toml
[ospf]
enabled           = true
interfaces        = ["eth1"]
area              = "1.0.0.0"
stub-areas        = ["1.0.0.0"]   # this area carries no externals
stub-default-cost = 5             # the metric an ABR gives the injected default
```

Every router with an interface in the area — the ABR included — must agree it is a
stub, so `stub-areas` is set on all of them. Concretely Wren then:

- **clears the E-bit** (AS-external-capable) in the Hellos *and* Database
  Description packets it sends in the area, and refuses to form an adjacency with a
  neighbour whose E-bit disagrees (§10.5) — so a stub and a non-stub router never
  partially adjacency-up;
- **never floods type-5 LSAs** into the area, leaves them out of the Database
  Description summary there (otherwise a neighbour would request a type-5 that never
  arrives and hang in `Loading`), and drops any type-5 that still arrives on a stub
  interface;
- as an **ABR, injects a default route** — a type-3 `0.0.0.0/0` summary at
  `stub-default-cost` — into the area. Ordinary inter-area (type-3) summaries are
  still sent too; this is a plain stub, not a totally-stubby area.

A stub router then installs `0.0.0.0/0` via the ABR and none of the externals.
`scripts/ospf-stub-area-smoke.sh` exercises this live (rootless): the same topology
is run with the area normal (the internal router learns the external `10.99.0.0/24`
and no default) and then as a stub (the external is gone, replaced by a
`default via` the ABR, with the ordinary inter-area route still present).

## Not yet implemented

NSSA areas (type-7), totally-stubby areas, type-4 ASBR-summaries reaching an ASBR
across areas, explicit type-5 forwarding-address resolution, and authentication
(Wren uses null authentication today). These are tracked in the
[Roadmap](../roadmap.md).
