# BGP-4

Wren implements **BGP-4** ([RFC 4271](https://www.rfc-editor.org/rfc/rfc4271)) for
IPv4 unicast — the first protocol in Wren to run over **TCP** (port 179) rather
than UDP or raw IP. It supports both **eBGP** (a neighbour in a different AS) and
**iBGP** (the same AS).

> Autonomous System numbers are **2-octet** here, the base RFC 4271 encoding.
> 4-octet ASNs (RFC 6793) are a capability extension and a later milestone.

## What is implemented

**The message codec** — the 19-byte header (the all-ones marker, length and type)
and the four messages OPEN, UPDATE, NOTIFICATION and KEEPALIVE, plus the NLRI /
withdrawn-route prefix encoding. The UPDATE path attributes covered are ORIGIN,
AS_PATH, NEXT_HOP, MULTI_EXIT_DISC, LOCAL_PREF, ATOMIC_AGGREGATE and AGGREGATOR;
unknown attributes are preserved verbatim.

**The decision process** (§9.1.2.2) — the standard best-path order:

1. highest **LOCAL_PREF**
2. shortest **AS_PATH**
3. lowest **ORIGIN** (IGP < EGP < Incomplete)
4. lowest **MED** (only between paths from the same neighbouring AS)
5. **eBGP over iBGP**
6. lowest **IGP metric** to the NEXT_HOP
7. lowest peer **router-id**, then peer **address**

**The RIBs** (§3.2) — an Adj-RIB-In holding every offered path per destination
(keyed by `(peer, path-id)`, so ADD-PATH can keep several paths from one peer), and a
Loc-RIB selecting the single best, emitting a change event only when a prefix's best
path actually appears, changes or disappears.

**The session FSM** (§8) — `Idle → Connect → Active → OpenSent → OpenConfirm →
Established`, with the ConnectRetry, Hold and Keepalive timers and clean teardown
(Cease / Hold-timer-expired NOTIFICATIONs).

**The TCP runner** (in `wren-daemon`) ties them together:

- a **listener** on port 179 plus an active **connector** per non-passive peer;
- length-prefixed message framing (read the 19-byte header for the length, then
  the body, then decode);
- **OPEN negotiation** — the peer's (effective, 4-octet) AS is checked against
  `remote-as`, the 4-octet AS Number capability (RFC 6793) is detected, and the
  Hold Time becomes the smaller of the two proposals (Keepalive = Hold / 3);
- the Hold and Keepalive timers driving the FSM;
- originated `network`s advertised on reaching Established, optionally summarised by
  `[[bgp.aggregate]]` covering prefixes (RFC 4271 §9.2.2.2);
- received UPDATEs folded into the shared BGP RIB, whose best-path changes are
  announced into the kernel RIB as `proto bgp`;
- learned best paths **propagated** onward to the other peers (transit), prepending
  our AS toward eBGP with next-hop-self, applying iBGP split horizon — see
  [Propagation](#propagation-transit);
- **ADD-PATH** (RFC 7911) negotiated per neighbour: keep and advertise more than one
  path per destination — see [ADD-PATH](#add-path-rfc-7911).

A central task owns the BGP RIB and serialises every change; each peer's session
runs in its own task owning its socket and FSM.

## Configuration

A two-router eBGP setup. Side A actively connects and originates a network; side B
waits passively:

```toml
# Router A — AS 65001
router-id = "10.0.0.1"

[bgp]
enabled  = true
local-as = 65001
network  = ["10.10.0.0/24"]

[[bgp.neighbor]]
address   = "10.0.0.2"
remote-as = 65002
```

```toml
# Router B — AS 65002
router-id = "10.0.0.2"

[bgp]
enabled  = true
local-as = 65002
network  = ["10.20.0.0/24"]

[[bgp.neighbor]]
address   = "10.0.0.1"
remote-as = 65001
passive   = true
```

For **iBGP**, set the neighbour's `remote-as` equal to `local-as`; Wren then
leaves the AS_PATH empty and carries LOCAL_PREF, as iBGP requires.

`local-as` / `remote-as` are **4-octet** (RFC 6793): any value up to 4294967295
is accepted (asplain notation).

## 4-octet AS numbers (RFC 6793)

ASNs are held 4-octet-wide throughout. Wren always advertises the **4-octet AS
Number capability** (code 65) in its OPEN, carrying its real AS; its 2-octet
`My Autonomous System` field holds the AS directly when it fits, or `AS_TRANS`
(23456) otherwise. A peer's *effective* AS — the capability value when present,
else the 2-octet field — is what `remote-as` is checked against.

The AS_PATH wire width is then per-session:

- **between two 4-octet-capable speakers** (the common case) AS_PATH is encoded
  4-octet-wide and carries real ASNs directly;
- **toward a legacy 2-octet peer** AS_PATH is 2-octet (with `AS_TRANS` standing
  in for any AS above 65535) and the true values ride alongside in the optional-
  transitive **AS4_PATH** / **AS4_AGGREGATOR** attributes. On receipt Wren merges
  AS4_PATH back over the `AS_TRANS` placeholders (the §4.2.3 reconstruction).

> **Binding port 179** needs `CAP_NET_BIND_SERVICE`. Inside an `unshare -Urn`
> namespace the namespace-root has it; otherwise run the listener side with the
> capability (or as root). If the bind fails Wren logs a warning and continues in
> active-connect-only mode.

## IPv6 unicast — MP-BGP (RFC 4760)

Beyond IPv4, BGP carries **IPv6 unicast** via the multiprotocol extensions. Wren
always advertises the **Multiprotocol capability** (code 1) for `(AFI IPv6,
SAFI unicast)` in its OPEN, so a session negotiates IPv6 support automatically;
toward a peer that does not advertise it back, Wren simply never sends IPv6 NLRI.

IPv6 reachability rides in **MP_REACH_NLRI** (the prefixes plus the next hop) and
withdrawals in **MP_UNREACH_NLRI**, rather than the base NEXT_HOP / NLRI / Withdrawn
fields (which stay IPv4). The TCP session itself is unchanged — it still runs over
the IPv4 transport to the neighbour `address`; only the carried NLRI is IPv6.

To **originate or redistribute** IPv6 routes a speaker must know the next hop to
advertise for them (next-hop-self), since the base NEXT_HOP attribute is IPv4-only.
Set it with `next-hop6` — typically this router's own global address on the peering
link:

```toml
[bgp]
enabled   = true
local-as  = 65001
network   = ["2001:db8:99::/64"]   # an IPv6 network to originate
next-hop6 = "2001:db8::1"          # next-hop-self for IPv6 NLRI
[[bgp.neighbor]]
address   = "10.0.0.2"             # the session is still IPv4 transport
remote-as = 65002
```

The same `next-hop6` applies to any IPv6 route pulled in by `redistribute` — BGP
is now dual-stack, so an IPv6 static or IGP route is re-originated over MP-BGP just
as an IPv4 one is. The peer installs the learned prefix `proto bgp` via the
advertised next hop.

### Link-local next hops (RFC 2545)

The MP_REACH next hop is normally just the 16-octet **global** address from
`next-hop6`. When a route is advertised to a **directly-connected** peer (the
session rides an interface for which Wren has an IPv6 link-local), Wren appends its
link-local, sending the 32-octet **global + link-local** next hop RFC 2545 §3
prescribes. The receiver then forwards over the link-local — which is not globally
unique, so the route is installed **pinned to the interface** it arrived on
(`via fe80::… dev <iface>`) rather than via the global. This is what lets two
routers exchange IPv6 routes without configuring global next-hop addresses that are
reachable end to end. The interface is resolved from the session's local transport
address; on a peering with no resolvable link-local, the next hop stays global-only.

A self-contained, rootless live test is in `scripts/bgp-mp-ipv6-smoke.sh`: two
speakers peer over IPv4 on a veth that also carries IPv6 globals, one originates an
IPv6 network, and the other learns it and installs it into its kernel IPv6 table.
`scripts/bgp-linklocal-nexthop-smoke.sh` is the RFC 2545 variant: the receiver
installs the route via the advertiser's `fe80::` link-local pinned to its veth, not
via the global next hop.

## Testing it

With the configs above on a veth between two namespaces, both speakers reach
Established over real TCP and install each other's network:

```text
# on A:
10.20.0.0/24 via 10.0.0.2 proto bgp
# on B:
10.10.0.0/24 via 10.0.0.1 proto bgp
```

A self-contained, rootless live test of the 4-octet path (two speakers with ASNs
above 65535 peering over a veth in throwaway namespaces) is in
`scripts/bgp-4octet-smoke.sh`.

## Multipath (ECMP)

By default a prefix learned over several BGP sessions is installed via its single
best path — the rest are kept in the Adj-RIB-In as backups. Setting

```toml
[bgp]
multipath = 2          # install up to two equal-cost paths as one ECMP route
```

makes the router install **up to that many equal-cost paths** for a prefix as a
single multipath (ECMP) kernel route, balancing forwarding across them. Two paths
are equal-cost when they tie on every attribute the decision process uses to pick a
winner: the same LOCAL_PREF, the same **whole** AS_PATH (so they share a
neighbouring AS and never form an ECMP across unrelated upstreams — the
conservative default, matching Cisco / FRR without `as-path multipath-relax`), the
same ORIGIN, MED, eBGP-vs-iBGP class and IGP cost to the next hop. The remaining
tie-breaks (cluster-list length, peer id/address) still pick a single winner — but
only for what is **advertised** onward: multipath widens forwarding, not the routes
re-advertised to peers, so `show bgp routes` continues to show the one best path
while the kernel route carries every next hop.

This feeds the same `RTA_MULTIPATH` machinery the link-state SPFs use, so the kernel
route looks like any other ECMP route:

```text
10.99.0.0/24 proto bgp metric 1
	nexthop via 10.0.0.1 dev veth_ra weight 1
	nexthop via 10.1.0.1 dev veth_rb weight 1
```

`scripts/bgp-multipath-smoke.sh` exercises it live (rootless): two routers in the
same AS each originate the same prefix to a third over separate eBGP sessions; the
third installs the single best path without `multipath`, and both next hops as one
ECMP route with `multipath = 2`.

## Communities (RFC 1997)

Routes can carry **communities** — 32-bit tags written `asn:value` — in the
optional-transitive COMMUNITIES attribute. Communities received on a path are
retained; communities listed under `[bgp]` are attached to every originated
network:

```toml
[bgp]
enabled   = true
local-as  = 65001
network   = ["10.10.0.0/24"]
community = ["65001:100", "no-export"]
```

The well-known communities change propagation:

- **`no-advertise`** (`0xFFFFFF02`) — never advertise the route to any peer;
- **`no-export`** (`0xFFFFFF01`) / **`no-export-subconfed`** (`0xFFFFFF03`) — do
  not advertise it to an **eBGP** peer (it still goes to iBGP peers).

So an originated network tagged `no-export` reaches iBGP neighbours but is
withheld from eBGP ones. `scripts/bgp-community-smoke.sh` demonstrates this live
(rootless): a control run advertises the network, a `no-export` run withholds it
from the eBGP peer.

### Per-prefix communities (via the export filter)

The `[bgp] community` list above is **global** — it tags *every* originated
network the same way. To set communities **per prefix**, attach a
[route filter](../configuration.md#route-filters--filter-and-import) to the BGP
export and have a rule rewrite the COMMUNITIES of the routes it matches. A rule's
`set-community` replaces the route's communities, `add-community` appends to them
(both take `asn:value` or a well-known name), and the rewrite rides along the same
router → BGP redistribution push, so the routes are originated carrying exactly
those communities:

```toml
[bgp]
enabled      = true
local-as     = 65001
redistribute = ["static"]

[export]
bgp = "tag"

[[filter]]
name    = "tag"
default = "accept"
[[filter.rule]]
prefix        = ["10.99.0.0/24"]
set-community = ["65001:777"]      # this prefix only
action        = "accept"
[[filter.rule]]
prefix        = ["10.77.0.0/24"]
set-community = ["no-export"]      # keep this one off eBGP peers
action        = "accept"
```

The well-known propagation rules above are honoured per prefix: the route tagged
`no-export` is withheld from eBGP peers while its untagged siblings are
advertised normally. `scripts/bgp-community-filter-smoke.sh` exercises this live
(rootless): a peer learns the tagged prefix *with* `communities 65001:777`, an
untagged prefix with none, and never sees the `no-export` one.

## Large communities (RFC 8092)

RFC 1997's community packs a 16-bit ASN beside a 16-bit value — too small for a
4-octet ASN. The **large community** carries three 32-bit values,
`global:local1:local2` (the LARGE_COMMUNITY attribute, type 32, optional
transitive), giving a 4-octet AS a natural `ASN:function:parameter` tag. Wren
handles them exactly like RFC 1997 communities, in parallel: received large
communities are retained and re-advertised; `[bgp] large-community` attaches a set
to every originated network; and a filter's `set-large-community` /
`add-large-community` stamp them **per prefix** on redistributed routes. There are
no well-known large communities.

```toml
[bgp]
enabled         = true
local-as        = 65001
network         = ["10.10.0.0/24"]
large-community = ["65001:1:1"]        # global: on every originated network
redistribute    = ["static"]

[export]
bgp = "tag"
[[filter.rule]]
prefix              = ["10.99.0.0/24"]
set-large-community = ["65001:7:7"]    # per prefix
action              = "accept"
```

`show bgp routes` renders them as `large-communities 65001:1:1`.
`scripts/bgp-large-community-smoke.sh` exercises both paths live (rootless): a
peer learns the originated network carrying `65001:1:1` and the redistributed
prefix carrying `65001:7:7`.

## Extended communities (RFC 4360)

The **extended community** is an 8-octet tag with a structured type — the most
important being the **Route Target** (`rt`) and **Route Origin** (`ro`) used to
control route distribution (e.g. in L3VPNs). The administrator field can be a
2-octet AS, a 4-octet AS (RFC 5668) or an IPv4 address, chosen automatically from
how you write it:

| Text | Encoding |
|---|---|
| `rt:65001:100` | two-octet AS specific |
| `rt:65536:100` | four-octet AS specific (AS > 65535) |
| `rt:192.0.2.1:100` | IPv4 address specific |
| `ro:…` | the same, as a Route Origin |

Wren handles them exactly like the other community kinds, in parallel: received
extended communities are retained and re-advertised; `[bgp] ext-community`
attaches a set to every originated network; and a filter's `set-ext-community` /
`add-ext-community` stamp them **per prefix**. Unrecognised types round-trip on the
wire and render as a raw `0x…` value.

```toml
[bgp]
ext-community = ["rt:65001:100"]      # global: on every originated network

[export]
bgp = "tag"
[[filter.rule]]
prefix            = ["10.99.0.0/24"]
set-ext-community = ["ro:65001:7"]    # per prefix
action            = "accept"
```

`show bgp routes` renders them as `ext-communities rt:65001:100`.
`scripts/bgp-ext-community-smoke.sh` exercises both paths live (rootless): a peer
learns the originated network carrying `rt:65001:100` and the redistributed prefix
carrying `ro:65001:7`.

## Redistribution

BGP can re-originate routes the rest of the daemon already knows — connected
networks, statics, or routes learned by an IGP — by listing their protocols under
`redistribute`:

```toml
[bgp]
enabled      = true
local-as     = 65001
redistribute = ["connected", "static", "ospf"]
[[bgp.neighbor]]
address   = "10.0.0.2"
remote-as = 65002
```

The mechanism is the general router → protocol push: the [central router
loop](../architecture.md) owns the RIB, and on every best-path change it offers the
route to each redistribution target. BGP, as a target, folds a redistributed
prefix into its origination set and advertises it to every established peer (and
to peers that connect later, via the same snapshot the configured `network`s use).
When the route's best path goes away — or moves to a protocol no longer in the
list — the prefix is withdrawn from peers again.

Notes and limits:

- **Dual-stack**: both IPv4 and IPv6 RIB routes are redistributed. An IPv6 route
  is re-originated over [MP-BGP](#ipv6-unicast--mp-bgp-rfc-4760) and needs
  `next-hop6` set, just like a configured IPv6 `network`.
- **BGP never redistributes its own routes** (that would loop); `bgp` is rejected
  in the `redistribute` list.
- A configured `network` always wins: redistribution never overrides or withdraws
  a prefix you originate explicitly.
- An optional **export filter** reuses the `wren-filter` engine — `[export] bgp =
  "name"` runs each redistributed route through the named filter (reject to drop,
  or rewrite) before it is originated, exactly as `[export] kernel` gates the FIB.

`scripts/bgp-redistribute-smoke.sh` exercises this live (rootless): a static route
on one speaker is withheld from the peer without `redistribute`, then learned over
BGP and installed `proto bgp` once `redistribute = ["static"]` is set.

## Operational visibility

The BGP task owns its RIB and neighbour table, and answers `show bgp` queries over
the daemon's [control socket](../architecture.md) — the same channel-and-oneshot
design as `show routes`, so nothing reaches across tasks into shared state:

```text
$ wren show bgp neighbors
10.0.0.2 AS 65002 Established

$ wren show bgp
10.20.0.0/24 via 10.0.0.2 as-path 65002 communities 65002:100 localpref 100 origin igp
```

`show bgp` (or `show bgp routes`) lists the Loc-RIB best paths with their AS_PATH,
communities, LOCAL_PREF, MED and origin; `show bgp paths` lists **every** candidate
path in the Adj-RIB-In (all paths per destination, each with its received ADD-PATH
Path Identifier and marked `*` when it is the selected best); `show bgp neighbors`
(or `summary`) lists each configured peer with its AS and session state.
`scripts/bgp-show-smoke.sh` exercises them live (rootless).

## ADD-PATH (RFC 7911)

Without ADD-PATH a BGP speaker advertises only its single best path per destination,
and a peer keeps only one path per `(prefix, neighbour)` — so a second path for a
prefix from the same peer overwrites the first. ADD-PATH lifts that: every NLRI on
the wire is prefixed with a 4-octet **Path Identifier**, so a speaker can advertise,
and a peer can hold, several paths for one destination at once. This is what lets a
route reflector hand its clients more than the single best path (faster convergence,
better multipath).

Enable it per neighbour:

```toml
[[bgp.neighbor]]
address   = "10.3.0.2"
remote-as = 65001
add-path  = true       # negotiate ADD-PATH (send + receive) for IPv4 unicast
```

`add-path = true` advertises the ADD-PATH capability for IPv4 unicast with both the
Send and Receive flags (RFC 7911 §4). The directions actually used are the
intersection with the peer's capability: Wren **sends** multiple paths when the peer
can receive, and **receives** (keeps) multiple paths when the peer can send. On a
session where send is in effect, Wren advertises every candidate path in its
Adj-RIB-In for a prefix (subject to the usual propagation rules and the export
filter), each under a stable Path Identifier; on one where receive is in effect, it
stores each received path under its Path Identifier so they coexist as selection
candidates. ADD-PATH is negotiated for IPv4 unicast here; the IPv6 (MP) family is a
future extension. `show bgp paths` shows the retained paths and their ids.

`scripts/bgp-add-path-smoke.sh` exercises it live (rootless): two routers (B, C) each
originate `10.50.0.0/24` to a third (A) over eBGP, and A reflects to an iBGP peer D.
Without ADD-PATH, D learns one path; with `add-path = true` on the A–D session, D
learns **both** paths under distinct Path Identifiers — impossible from a single
iBGP peer otherwise.

## Extended Next Hop / IPv4-over-IPv6 (RFC 5549)

Normally an IPv4 route is advertised with an IPv4 next hop and an IPv6 route with an
IPv6 one. RFC 5549 (clarified by RFC 8950) lets a speaker advertise **IPv4** NLRI
with an **IPv6** next hop — the basis of *BGP unnumbered*, where peers exchange IPv4
routes over a link that has only IPv6 addressing. The kernel installs such a route
through its IPv6 gateway using `RTA_VIA` (`ip route` shows `via inet6 …`).

Enable it per neighbour:

```toml
[bgp]
next-hop6 = "2001:db8::2"   # the IPv6 next-hop-self for advertised IPv4 routes

[[bgp.neighbor]]
address          = "10.0.0.2"
remote-as        = 65002
extended-nexthop = true     # negotiate Extended Next Hop Encoding (RFC 5549)
```

`extended-nexthop = true` advertises the Extended Next Hop Encoding capability for
`(IPv4 unicast, IPv6 next hop)`. When the peer agrees and a `[bgp] next-hop6` is
configured, Wren advertises its IPv4 routes to that peer in MP_REACH_NLRI (AFI IPv4)
with that IPv6 next-hop-self instead of the usual IPv4 NEXT_HOP. In the other
direction it always accepts a received IPv4-with-IPv6-next-hop UPDATE (the encoding
is self-describing) and installs each IPv4 prefix via the IPv6 gateway — over the
peer's link-local pinned to the ingress interface on a shared link (RFC 2545), or the
global next hop otherwise.

`scripts/bgp-extended-nexthop-smoke.sh` exercises it live (rootless): two routers
peer over a dual-stack link; one originates `10.99.0.0/24` and advertises it with its
IPv6 next hop, and the other installs `10.99.0.0/24 via inet6 fe80::… dev veth0` in
the kernel — verified against the real kernel FIB. (The genuinely-missing data-plane
piece, the kernel `RTA_VIA` encoding for a cross-family gateway, lives in
`wren-netlink` and has its own kernel-acceptance test.)

### IPv6 transport (true unnumbered)

The same neighbour can be reached over an **IPv6** transport — the BGP TCP session
itself rides IPv6, on a link that need not have any IPv4 address at all. Give the
neighbour an IPv6 `address`; combined with `extended-nexthop` and `next-hop6`, IPv4
routes still flow across the link (carried in MP_REACH_NLRI as above):

```toml
[[bgp.neighbor]]
address          = "2001:db8::2"     # IPv6 transport — the session rides IPv6
remote-as        = 65002
extended-nexthop = true
```

A **link-local** peer address needs the egress interface as a scope, written with the
usual `%iface` suffix:

```toml
address = "fe80::1%eth0"
```

The `router-id` stays a 32-bit value (a dotted quad) even for an IPv6 session — it is
the BGP Identifier, not a transport address. Wren binds a single dual-stack listener
(`[::]:179`, accepting both IPv4-mapped and IPv6 inbound), and the §6.8
connection-collision logic still keys on the BGP Identifier, so a mixed v4/v6 peering
set behaves identically. **TCP-MD5 / TCP-AO** (below) are wired for IPv4 transport only
here; a key configured on an IPv6 peer is ignored with a warning (IPv6 transport
authentication is future work).

`scripts/bgp-unnumbered-smoke.sh` exercises it live (rootless): two routers peer over
an **IPv6-only** veth — no IPv4 on the link whatsoever — the session reaches
Established over IPv6, and one router still installs the other's IPv4 prefix
`10.99.0.0/24 via inet6 fe80::… dev veth0` in the kernel.

## Propagation (transit)

Beyond originating its own `network`s and redistributed routes, Wren **propagates**
the routes it learns: whenever a prefix's Loc-RIB best path appears, changes or is
withdrawn, the change is re-advertised to the other peers (the Adj-RIB-Out), so a
speaker peering with several neighbours acts as transit between them. The standard
rules apply per outgoing peer:

- a route is **never echoed back** to the peer it was learned from;
- toward an **eBGP** peer the local AS is **prepended** to the AS_PATH and the next
  hop is set to ourselves (next-hop-self);
- toward an **iBGP** peer the AS_PATH and next hop are left unchanged and LOCAL_PREF
  (and MED) are carried;
- a route learned from an **iBGP** peer is **not** re-advertised to another iBGP
  peer (the iBGP split-horizon rule — relaxing it is what route reflection, on the
  roadmap, will add);
- the well-known communities (`no-export`, `no-advertise`) are honoured per peer.

Propagation is **dual-stack**: an IPv6 best path is re-advertised in MP_REACH_NLRI
(and withdrawn in MP_UNREACH_NLRI), with the next hop preserved toward iBGP or set
to `next-hop6` toward eBGP — the IPv4 rules above, over the multiprotocol encoding.

`scripts/bgp-propagate-smoke.sh` exercises this live (rootless): an eBGP chain
`A (AS 65001) — B (AS 65002) — C (AS 65003)` where A originates a network, B
originates nothing, and C learns it via B with the AS_PATH `65002 65001` and
installs it `proto bgp`. `scripts/bgp-propagate-ipv6-smoke.sh` is the IPv6
counterpart (A originates an IPv6 network, C installs it from B over MP-BGP).

## Route reflection (RFC 4456)

The iBGP split-horizon rule above means a route learned from one iBGP peer is not
passed to another — so a full iBGP mesh would otherwise be required. A **route
reflector** relaxes that: mark an iBGP peer as a **client**, and the reflector
re-advertises routes between its clients and the rest of the iBGP peers.

```toml
[bgp]
enabled    = true
local-as   = 65010
cluster-id = "10.0.0.254"   # optional; defaults to the BGP router-id
[[bgp.neighbor]]
address                = "10.0.0.1"
remote-as              = 65010   # iBGP
route-reflector-client = true
[[bgp.neighbor]]
address                = "10.0.0.2"
remote-as              = 65010
route-reflector-client = true
```

The reflection rules (§3.2) the reflector applies are:

- a route from a **client** is reflected to **all** other iBGP peers (clients and
  non-clients) and to eBGP peers;
- a route from a **non-client** iBGP peer is reflected to **clients only**;
- a route from an **eBGP** peer is advertised to everyone, as usual.

When it reflects an iBGP route to an iBGP peer the reflector leaves AS_PATH,
NEXT_HOP and LOCAL_PREF untouched but stamps two loop-avoidance attributes
(§7–8): **ORIGINATOR_ID** (the router that first introduced the route into the AS,
preserved if already present) and **CLUSTER_LIST** (the reflector prepends its
`cluster-id`). On receipt a speaker drops any route whose ORIGINATOR_ID is its own
router-id or whose CLUSTER_LIST already names its own cluster id, and a shorter
CLUSTER_LIST is a best-path tie-break (§9).

`scripts/bgp-route-reflection-smoke.sh` exercises this live (rootless): one AS on a
shared segment with a reflector and two clients that do not peer with each other —
one client originates a network and the other learns it only by reflection, then
installs it `proto bgp`.

## Connection-collision detection (RFC 4271 §6.8)

When two BGP speakers both actively dial *and* accept, they can open two TCP
connections to each other at once (a simultaneous open). §6.8 resolves this so
exactly one survives: the connection opened by the speaker with the **higher BGP
Identifier** is kept, and the other is closed with a Cease NOTIFICATION
(subcode 7, *Connection Collision Resolution*). Both ends reach the same verdict,
so they agree on which connection to keep.

Wren tags each connection as inbound (accepted) or outbound (dialled) and gives it
a unique id. When a second connection to a peer reaches Established, the central
task keeps the one matching the §6.8 rule — from our side that is the inbound
connection when our identifier is the lower of the two — and tells the loser to
Cease. Because both connections share the peer's address, the loser's eventual
*Down* carries its connection id and is ignored unless it is still the current
connection, so a closing loser can never evict the surviving session.

`scripts/bgp-collision-smoke.sh` exercises this live (rootless): two speakers that
both dial and accept converge to a single stable session and exchange routes,
without the flap an unresolved collision would cause.

## TTL security (GTSM, RFC 5082)

A BGP session rides on TCP, so an off-path attacker who can spoof the peer's source
address can try to inject or reset it. The **Generalized TTL Security Mechanism**
defends a session whose peer is a known, small number of hops away: both ends send
their packets with the IP TTL set to its maximum (255) and reject any received
packet whose TTL is below `255 − (hops − 1)`. Because a router decrements the TTL at
every hop, a packet forged by an attacker more than `hops` away arrives with a TTL
too low to pass — and the check is essentially free, because the kernel drops the
packet before BGP ever sees it. Enable it per neighbour with the maximum hop count
(1 for a directly-connected eBGP peer):

```toml
[[bgp.neighbor]]
address      = "10.0.0.2"
remote-as    = 65002
ttl-security = 1     # directly connected: send TTL 255, require received TTL 255
```

Wren sets `IP_TTL` to 255 on the session's socket and `IP_MINTTL` to `255 − (hops − 1)`
(so `ttl-security = 1` demands a minimum TTL of 255), on both the dialled and the
accepted connection. Both peers must enable it — each only protects its own receive
side. `scripts/bgp-ttl-security-smoke.sh` exercises it live (rootless) with two eBGP
speakers placed **two hops apart** behind a forwarding router: the session comes up
with GTSM off, fails to establish with `ttl-security = 1` (the once-decremented
packets fall below the minimum), and comes up again with `ttl-security = 2` — GTSM
admits a peer at the configured distance and rejects only ones beyond it.

## TCP-MD5 authentication (passwords, RFC 2385)

Where GTSM raises the bar for an off-path attacker, a **TCP-MD5 signature** keeps one
out entirely: each segment carries an MD5 digest of the segment and a shared secret,
so a peer that does not hold the key cannot forge a segment the kernel will accept —
not even the SYN. Set a shared `password` on the neighbour (both ends must match):

```toml
[[bgp.neighbor]]
address   = "10.0.0.2"
remote-as = 65002
password  = "correct horse"     # up to 80 bytes; the peer needs the same key
```

The key must be on the socket *before* the handshake, since it signs the SYN, so Wren
installs it with the `TCP_MD5SIG` socket option as the connection is built — on the
**connector** (the dialled socket, before connecting) and on the **listener** (one
key per password-protected peer, before `listen`, so inbound SYNs are verified). The
kernel does the signing and checking; a mismatched or missing key makes the handshake
fail, so the session never leaves `Idle`. This needs a kernel built with
`CONFIG_TCP_MD5SIG` (the usual case). `scripts/bgp-password-smoke.sh` exercises it
live (rootless): two directly-connected eBGP speakers establish with matching
passwords, and fail to establish both when the passwords differ and when only one
side sets one.

> TCP-MD5 and GTSM are independent and combine: GTSM cheaply discards far-away
> packets at the IP layer, while TCP-MD5 authenticates the ones that remain.

## TCP-AO authentication (RFC 5925)

**TCP-AO** is the modern successor to TCP-MD5: instead of a fixed MD5 digest it uses a
stronger MAC (HMAC-SHA-1) and derives a *per-connection* traffic key from the master
key and the connection's identifiers, which closes the replay and key-reuse weaknesses
of TCP-MD5. Configure a shared master key and key id on the neighbour (both peers must
match):

```toml
[[bgp.neighbor]]
address   = "10.0.0.2"
remote-as = 65002
ao-key    = "correct horse"   # up to 80 bytes; the peer needs the same key
ao-key-id = 100               # SendID and RecvID (default 100); the peer must match
```

Like TCP-MD5 the key must be installed before the handshake, so Wren builds the socket
by hand and sets it with the `TCP_AO_ADD_KEY` socket option on both the connector and
the listener; the kernel does the per-segment MAC. The key id is used as both the
SendID and the RecvID (RFC 5925 §3.1), so a symmetric `ao-key-id` on each side
interoperates. A mismatched or missing key makes the handshake fail, so the session
never leaves `Idle`. `ao-key` and `password` are mutually exclusive, and TCP-AO needs a
kernel with `CONFIG_TCP_AO` (Linux 5.18+). `scripts/bgp-tcp-ao-smoke.sh` exercises it
live (rootless): two directly-connected eBGP speakers establish with matching keys, and
fail to establish both when the keys differ and when only one side sets one.

## Default-originate

On the upstream edge toward a stub customer it is common to hand the customer a single
default route rather than the whole table. Set `default-originate` on the neighbour and
Wren advertises `0.0.0.0/0` to it **unconditionally** — whether or not Wren itself has a
default — with this router as the next hop:

```toml
[[bgp.neighbor]]
address          = "10.0.0.2"
remote-as        = 65002
default-originate = true     # advertise 0.0.0.0/0 to this peer
```

The default is advertised only to that peer; it is **not** installed in the local FIB
and **not** sent to any other neighbour. `scripts/bgp-default-originate-smoke.sh`
exercises it live (rootless): a stub peer learns no default without the option, and
installs `0.0.0.0/0` via the upstream once it is set — while the upstream itself never
installs the default it merely advertises.

## Address aggregation (RFC 4271 §9.2.2.2)

Instead of advertising many adjacent more-specifics, you can advertise a single covering
prefix. Each `[[bgp.aggregate]]` declares a covering prefix; Wren advertises it — to
**every** peer — as soon as at least one strictly-more-specific route in its own
origination set (configured `network`s and redistributed prefixes) falls inside it. The
aggregate carries `ATOMIC_AGGREGATE` and `AGGREGATOR` (this router's AS and id; toward a
legacy 2-octet peer the real 4-octet AS rides in `AS4_AGGREGATOR`, RFC 6793 §3).

```toml
[bgp]
local-as = 65001
network  = ["10.50.1.0/24", "10.50.2.0/24"]   # the contributing more-specifics

[[bgp.aggregate]]
prefix       = "10.50.0.0/16"   # advertised once a contributor inside it exists
summary-only = true             # …and suppress the contributing more-specifics
```

With `summary-only` the contributing more-specifics are withheld from advertisement,
leaving only the aggregate; without it the aggregate is advertised **alongside** the
more-specifics. The set is recomputed on every origination change, so an aggregate
appears when its first contributor arrives and is withdrawn when the last one leaves
(restoring any suppressed more-specifics).

Two deliberate limitations:

* The aggregate is **advertise-only** — it is never installed in the local FIB (no
  discard/`Null0` route), and it never aggregates routes **learned from other BGP
  peers**, only this speaker's own originated/redistributed prefixes.
* The aggregate carries an empty `AS_PATH` of its own (it originates here); `as-set`
  summarisation of contributor AS paths is not done.

`scripts/bgp-aggregate-smoke.sh` exercises it live (rootless) across three phases: with
no aggregate a peer learns only the `/24`s; with the aggregate it learns the `/16`
**and** the `/24`s (and the originator never installs the `/16` itself); with
`summary-only` it learns only the `/16`.

## Route policy — per-neighbour import / export filters

A neighbour can carry an `import =` and/or an `export =` that name
[`[[filter]]`](../configuration.md) blocks — the inbound and outbound halves of a
route-map. `import` is applied to **every route received from the peer** before it
enters the RIB; `export` is applied to **every route advertised to the peer** (both
originated/aggregate routes and propagated transit routes) as it leaves. Reject
drops/suppresses the route; accept admits/sends it, with the filter's modifications
folded back into the path:

| Filter field | BGP attribute it maps to |
|---|---|
| `set-metric` / `metric-le` / `metric-ge` | MULTI_EXIT_DISC (MED) |
| `set-preference` | LOCAL_PREF (higher wins) |
| `set-community` / `add-community` (+ large / ext) | the path's communities |
| `prefix` patterns | the received prefix |

```toml
[[filter]]
name    = "from-upstream"
default = "accept"            # accept anything not matched below
[[filter.rule]]
prefix = ["10.50.2.0/24"]
action = "reject"             # never accept this prefix from the peer
[[filter.rule]]
prefix         = ["10.50.1.0/24"]
set-preference = 200          # bump LOCAL_PREF
set-community  = ["65002:777"]
action         = "accept"

[[bgp.neighbor]]
address   = "10.0.0.1"
remote-as = 65001
import    = "from-upstream"   # routes learned from this neighbour
export    = "to-upstream"     # routes advertised to this neighbour
```

On **import**, a prefix that was accepted before but is rejected on a later
re-advertisement is withdrawn from the RIB, so the policy is honoured incrementally. On
**export**, the modifications follow the usual attribute rules — a set-community is sent
to every peer type, while set-preference (LOCAL_PREF) and set-metric (MED) are carried
only to iBGP and confed-eBGP peers (LOCAL_PREF and MED are not sent across a true eBGP
edge). An originated route carries no MED or LOCAL_PREF of its own, so an export filter
on it only decides the prefix and rewrites communities.

The filter is the same engine used by `[import]` and the redistribution `[export]`
filters, operating on a `Route` view of the path (prefix, MED-as-metric,
LOCAL_PREF-as-preference, communities). Two live (rootless) checks:
`scripts/bgp-import-filter-smoke.sh` rejects/re-tags routes a peer sends us, and
`scripts/bgp-export-filter-smoke.sh` rejects/re-tags routes a transit router passes to
its iBGP peer (one `/24` suppressed, the other arriving with `localpref 200` and a
community).

## Maximum-prefix limit (RFC 4486)

A misconfigured or hostile peer can flood the RIB by advertising far more routes than
it should. A per-neighbour `max-prefix` caps how many prefixes Wren accepts from it;
once the peer would exceed the cap, Wren tears the session down with a Cease
"Maximum Number of Prefixes Reached" (RFC 4486 §4) and keeps it down:

```toml
[[bgp.neighbor]]
address    = "10.0.0.2"
remote-as  = 65002
max-prefix = 100000     # accept at most 100000 prefixes from this peer
```

The limit is checked *before* the over-limit routes are installed, so they never reach
the kernel even transiently. When it trips, Wren withdraws whatever the peer had
already advertised, sends the Cease, and **damps** the peer: any reconnection is shut
straight back down and its UPDATEs are ignored, so a flapping peer cannot keep
re-flooding. The session stays down until the daemon is reconfigured (there is no
auto-restart timer yet). `scripts/bgp-max-prefix-smoke.sh` exercises it live
(rootless): a peer originating three networks is accepted under a limit of 10 and
installed, then — under a limit of 2 — trips the limit, and the neighbour is left
`Idle` with none of its routes in the table.

## Route refresh (RFC 2918)

Without route refresh, re-applying an inbound policy means bouncing the session (a
hard clear) — disruptive. The **Route Refresh** capability lets a speaker instead
ask a peer to **re-send its Adj-RIB-Out**, so the receiver can re-run its import
policy against a fresh copy of the routes, with no flap.

Wren advertises the capability (code 2) in every OPEN, so a peer may send us a
ROUTE-REFRESH at any time while Established. On receiving one we re-advertise our
whole Adj-RIB-Out to that peer — the originated networks plus the Loc-RIB best
paths, with the usual propagation rules re-applied — and bump a per-neighbour
counter shown by `show bgp neighbors`. To drive the other direction, ask a peer to
re-send to us with:

```console
$ wren bgp refresh 10.0.0.2
route refresh sent to 10.0.0.2
```

One ROUTE-REFRESH is sent per negotiated address family (IPv4 unicast, and IPv6
unicast when the Multiprotocol capability was negotiated). The session stays
Established throughout — that is the whole point over a hard clear.

`scripts/bgp-route-refresh-smoke.sh` exercises this live (rootless): one peer
issues `bgp refresh`, the other honours it (its `show bgp neighbors` shows the
refresh counter rise) and the learned route stays installed across the exchange —
the session never flaps.

## Confederations (RFC 5065)

A confederation lets a large AS be split into several smaller **Member-ASes** while
still appearing to the outside world as a single AS — the **Confederation
Identifier**. Inside, the Member-ASes run eBGP-like sessions between them
(*confed-eBGP*) which avoids the full-iBGP-mesh requirement, while each Member-AS
still runs ordinary iBGP within itself.

```toml
[bgp]
enabled               = true
local-as              = 65002   # this router's Member-AS
confederation-id      = 65000   # the AS the confederation presents externally
confederation-members = [65001] # the other Member-ASes inside the confederation
[[bgp.neighbor]]
address   = "10.12.0.1"
remote-as = 65001               # a different Member-AS → confed-eBGP
[[bgp.neighbor]]
address   = "10.23.0.3"
remote-as = 64500               # outside the confederation → true eBGP
```

Each neighbour is classified from its `remote-as`: the same AS is **iBGP**, an AS
listed in `confederation-members` is **confed-eBGP**, and anything else is **true
eBGP**. That class drives three things:

- **The OPEN's My-AS** (§4.2): a confederation peer (iBGP or confed-eBGP) sees our
  **Member-AS**; a true external peer sees the **Confederation Identifier**, so it
  configures `remote-as = <confederation-id>` and the whole confederation looks like
  one AS to it.
- **AS_PATH on egress** (§5.3, §6): to a confed-eBGP peer we prepend our Member-AS
  to an **AS_CONFED_SEQUENCE** (an internal segment) and keep LOCAL_PREF and the
  next hop, since the confederation shares one decision domain. To a true eBGP peer
  we **strip every AS_CONFED_SEQUENCE / AS_CONFED_SET** and prepend the
  Confederation Identifier to the ordinary AS_SEQUENCE, set next-hop-self and drop
  LOCAL_PREF — the internal Member-AS hops never leak outside.
- **Decision and loop avoidance**: confederation segments are **not counted** in
  AS_PATH length (§5.3), a confed-eBGP route is interior for the decision (treated
  like iBGP for *prefer-eBGP*, LOCAL_PREF honoured) yet propagated onward without
  the iBGP split-horizon restriction, and a received route whose AS_CONFED_SEQUENCE
  / AS_CONFED_SET already names our Member-AS is dropped as a confederation loop
  (§5.4). The well-known communities follow suit: `no-export` keeps a route inside
  the confederation (blocks only true eBGP) while `no-export-subconfed` keeps it
  inside the Member-AS (blocks confed-eBGP too).

`scripts/bgp-confederation-smoke.sh` exercises this live (rootless): a confederation
(65000) of two Member-ASes (65001, 65002) plus one external AS (64500) in a line.
A network originated in 65001 reaches the external peer with AS_PATH `65000` (the
internal 65001 hidden), and a network from the external peer reaches 65001 with
AS_PATH `(65002) 64500` (the Member-AS prepended in an AS_CONFED_SEQUENCE).

## Graceful restart (RFC 4724)

When a BGP session drops, the default is to withdraw every route learned over it at
once — which tears down forwarding even when the peer is only **restarting** and
its data plane is still up. Graceful restart lets a speaker signal that its
forwarding state **survives** a control-plane restart, so a neighbour can keep using
those routes for a bounded window instead of withdrawing them.

Wren advertises the Graceful Restart capability (code 64) in every OPEN, carrying:

- the **Restart State (R)** flag — wren leaves it clear (it does not yet persist a
  "just restarted" marker across its own restart);
- a **Restart Time** (`DEFAULT_RESTART_TIME`, 120 s) — how long a helper should wait
  for it to return;
- the **forwarding-state-preserved (F)** flag set for both IPv4- and IPv6-unicast,
  because wren's kernel FIB outlives the daemon process.

Once the initial advertisement to a peer is complete, wren sends an **End-of-RIB**
marker (an empty UPDATE for IPv4 unicast; an empty `MP_UNREACH_NLRI` for IPv6) so
the other side knows the dump has finished.

### Helper behaviour

As a **helper** — when a peer that advertised GR with the F flag drops — wren does
**not** withdraw that peer's routes. It instead:

1. **retains** them in the Loc-RIB and the kernel FIB (forwarding continues), marks
   them *stale*, and starts the peer's **Restart Timer**;
2. when the peer returns and re-advertises, each re-advertised prefix **refreshes**
   (un-stales) in place;
3. on the peer's **End-of-RIB** it flushes whatever is still stale (routes the peer
   no longer has) — the restart is complete with no flap for the routes that stayed;
4. if the Restart Timer expires first, the still-stale routes are flushed.

A peer that did **not** advertise GR (or set F=0) is handled the old way: an
immediate withdrawal on session down.

`scripts/bgp-graceful-restart-smoke.sh` exercises this live (rootless): a peer that
originates `10.20.0.0/24` is **hard-killed** (`SIGKILL`); the helper shows the
session leave Established yet keeps `10.20.0.0/24 proto bgp` installed, and when the
peer restarts the route is still there — it never left the FIB.

## RPKI origin validation (RFC 6811)

Origin validation checks that the AS originating a prefix is actually authorised to,
using **ROAs** (Route Origin Authorizations). Each ROA — a Validated ROA Payload —
authorises one origin AS to announce a prefix and any more-specific within it up to a
`max-length`. Wren validates every received route's `{ prefix, origin AS }` against the
configured ROA table and classifies it (RFC 6811 §2):

- **Valid** — at least one ROA *matches* (covers the prefix within `max-length`, and the
  origin AS is equal);
- **Invalid** — at least one ROA *covers* the prefix but none matches (wrong origin AS,
  or the prefix is longer than every covering ROA's `max-length`);
- **NotFound** — no ROA covers the prefix.

The route's origin AS is the right-most AS of its `AS_PATH` (RFC 6811 §2).

ROAs are configured statically; combined with `rpki-reject-invalid`, an **Invalid**
route is dropped at import — it never enters the RIB, the kernel FIB, or the
Adj-RIB-Out (so it is not re-advertised). `Valid` and `NotFound` routes are always
accepted; without `rpki-reject-invalid` everything is accepted and only *shown*.

```toml
[bgp]
rpki-reject-invalid = true            # drop RPKI-Invalid routes (default false)

[[bgp.roa]]
prefix     = "10.99.0.0/24"
max-length = 24                       # defaults to the prefix length if omitted
origin-as  = 65002

[[bgp.roa]]
prefix     = "2001:db8::/32"
max-length = 48
origin-as  = 65001
```

`show bgp roa` lists the ROA table, and — when any ROA is configured — `show bgp` tags
each route with its validity:

```
> show bgp
10.99.0.0/24 via 10.0.0.2 as-path 65002 localpref 100 origin igp rpki valid
```

`scripts/bgp-rpki-smoke.sh` exercises it live (rootless): a validating router learns
two prefixes from a peer — one authorised by a ROA (Valid, installed `proto bgp`) and
one not (Invalid), and with `rpki-reject-invalid` the Invalid prefix is absent from
both its RIB and the kernel.

Fetching ROAs live from a validating cache over the **RTR protocol** (RFC 8210),
rather than configuring them statically, is the natural follow-up.
