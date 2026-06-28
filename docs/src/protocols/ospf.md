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

## NSSA areas (RFC 3101)

A **not-so-stubby area** (NSSA) is a stub-like area that can still contain its own
ASBR. Like a stub it carries no AS-external (type-5) LSAs, but an ASBR inside it
originates **type-7** LSAs (same body as a type-5, but area-scoped), and the area
border router **translates** them into type-5 LSAs flooded into the rest of the AS.
This lets an edge area redistribute a few external routes without importing the
whole AS's external table. Mark an area an NSSA by listing its id:

```toml
[ospf]
enabled      = true
interfaces   = ["eth1"]
area         = "1.0.0.0"
nssa-areas   = ["1.0.0.0"]    # an area is either stub or nssa, not both
redistribute = ["static"]     # an ASBR here originates type-7, not type-5
```

In an NSSA Wren:

- sets the **N-bit** (and clears the E-bit) in the Hellos and Database Descriptions
  it sends there, and only forms an adjacency with a neighbour whose N-bit agrees;
- as an **ASBR inside the NSSA**, originates each redistributed destination as a
  **type-7** LSA into the area (not a type-5), with a `0.0.0.0` forwarding address
  (forward via the originator);
- computes routes to the area's type-7 destinations like AS-externals;
- as the **ABR**, **translates** every type-7 in the area into a type-5 LSA
  (re-originated under its own Router ID) and floods it AS-wide, so routers in the
  backbone and other areas learn the route as an ordinary external.

`scripts/ospf-nssa-smoke.sh` exercises this live (rootless) with three routers —
`B ──(NSSA)── A ──(backbone)── C`: B redistributes `10.99.0.0/24` as a type-7, A
(the ABR) learns it and translates it, and C in the backbone installs the
translated `10.99.0.0/24` external `proto ospf`.

### Injecting a default into a plain NSSA (RFC 3101 §2.3)

Because a plain NSSA carries no AS-external (type-5) LSAs, its internal routers
have no path to AS-external destinations — the inter-area (type-3) summaries an ABR
sends only cover destinations *inside* the AS. To give them one, list the area in
`nssa-default-areas`, and its ABR originates a **type-7 `0.0.0.0/0` default** into
it (at `stub-default-cost`) while still carrying the ordinary summaries:

```toml
[ospf]
enabled            = true
interfaces         = ["eth1"]
area               = "1.0.0.0"
nssa-areas         = ["1.0.0.0"]
nssa-default-areas = ["1.0.0.0"]   # this NSSA's ABR also injects a type-7 default
stub-default-cost  = 5
```

The default's P-bit is left clear, so — like the default an ASBR-less stub gets —
the ABR never translates it into a type-5 for the rest of the AS. This differs from
a **totally-NSSA** only in that the summaries are kept: a totally-NSSA suppresses
them and relies on the same default for *every* outside destination, whereas a
default-injecting plain NSSA uses the default purely for the AS-external ones.
`scripts/ospf-nssa-default-smoke.sh` exercises it live (rootless): the same NSSA is
run without the option (B has the inter-area summary but no default) and then with
it (B additionally gets the type-7 default, the summary still present).

## Totally-stubby and totally-NSSA areas

A **totally-stubby** area is a stub from which the ABR additionally suppresses the
inter-area (type-3) summaries, so its internal routers reach *everything* outside
the area — inter-area and AS-external alike — through the single injected default. A
**totally-NSSA** area is the NSSA counterpart: it keeps the NSSA's own type-7s but
likewise drops the inter-area summaries, and the ABR injects a **type-7** default in
their place. List the areas:

```toml
[ospf]
enabled              = true
area                 = "1.0.0.0"
interfaces           = ["eth1"]
totally-stubby-areas = ["1.0.0.0"]   # a stub, with type-3 summaries also suppressed
stub-default-cost    = 5             # the metric of the injected default
# …or, for the NSSA variant:
# totally-nssa-areas = ["1.0.0.0"]
```

An area listed in `totally-stubby-areas` is treated as a stub, and one in
`totally-nssa-areas` as an NSSA — so the E-bit / N-bit handling and adjacency rules
are exactly those of the plain variants; only the ABR's origination differs:

- into a **totally-stubby** area it injects the type-3 `0.0.0.0/0` default (at
  `stub-default-cost`) but **no other** type-3 summaries;
- into a **totally-NSSA** area it injects a type-7 `0.0.0.0/0` default with the
  **P-bit clear** — so the ABR does not translate the default into a type-5 for the
  rest of the AS — and no type-3 summaries.

`scripts/ospf-totally-stubby-smoke.sh` exercises both live (rootless): the same
A-(area 0.0.0.1)-B topology is run with the area a plain stub (B learns the default
*and* an inter-area summary), then totally-stubby (the summary is gone, only the
default remains), then totally-NSSA (B gets a type-7 default and the summary stays
suppressed).

## Authentication (RFC 2328 §D)

Every OSPF packet carries a 16-bit AuType and a 64-bit authentication field, so a
link can require its routers to prove a shared secret before they form an adjacency.
Wren supports all three schemes, configured once under `[ospf]` and applied to every
interface (the routers on a link must agree):

```toml
[ospf]
enabled    = true
interfaces = ["eth1"]
auth-type  = "md5"        # "none" (default), "text", or "md5"
auth-key   = "s3cr3t"     # ≤ 8 bytes for text, ≤ 16 bytes for md5
auth-key-id = 1           # md5 only; lets keys be rolled (default 1)
```

- **`none`** (AuType 0) — no authentication; the auth field is zero. The default.
- **`text`** (AuType 1) — a **simple password**: the cleartext key (up to 8 bytes) is
  placed in the auth field of every packet and compared on receipt. It only stops a
  *misconfigured* neighbour — anyone who can see the link can read the password.
- **`md5`** (AuType 2) — **cryptographic authentication**: a keyed MD5 digest of the
  packet and the secret is appended after the body, and the auth field carries the key
  id and a sequence number. The checksum is left zero (the digest replaces it). An
  attacker without the key cannot forge a packet the digest will accept, so this is the
  one to use on an untrusted link. (MD5 is computed in-process by a small, dependency-
  free implementation; the cryptographic sequence number is sent but anti-replay
  sequencing is not yet enforced on receipt.)

A packet whose AuType or authentication data does not match the configured scheme is
dropped, so it never reaches the neighbour state machine — a mismatched key simply
means the adjacency never forms. `scripts/ospf-auth-smoke.sh` exercises this live
(rootless): two point-to-point routers reach `Full` with matching MD5 keys, fail to
form an adjacency when the keys differ, and reach `Full` again with a matching simple
password.

## Not yet implemented

The RFC 3101 §3.2 translator election (a single ABR translates today), type-4
ASBR-summaries reaching an ASBR across areas, explicit type-5 forwarding-address
resolution, and MD5 cryptographic-authentication anti-replay (the sequence number is
sent but not yet checked on receipt). These are tracked in the
[Roadmap](../roadmap.md).
