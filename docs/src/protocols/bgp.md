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

**The RIBs** (§3.2) — an Adj-RIB-In holding every peer's offered path per
destination, and a Loc-RIB selecting the single best, emitting a change event only
when a prefix's best path actually appears, changes or disappears.

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
- originated `network`s advertised on reaching Established;
- received UPDATEs folded into the shared BGP RIB, whose best-path changes are
  announced into the kernel RIB as `proto bgp`.

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

- **IPv4 unicast only** here, so non-IPv4 RIB routes are skipped.
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
communities, LOCAL_PREF, MED and origin; `show bgp neighbors` (or `summary`) lists
each configured peer with its AS and session state. `scripts/bgp-show-smoke.sh`
exercises both live (rootless).

## Not yet implemented

MP-BGP / IPv6 (RFC 4760), extended / large communities, route reflection and
connection-collision detection (§6.8). These are tracked in the
[Roadmap](../roadmap.md).
