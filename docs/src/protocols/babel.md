# Babel

Wren implements **Babel** ([RFC 8966](https://www.rfc-editor.org/rfc/rfc8966)) — a
loop-avoiding distance-vector protocol that works well on both wired and wireless
links. Babel carries IPv4 **and** IPv6 routes over a single **IPv6** transport
(UDP port **6696**, link-local multicast **`ff02::1:6`**), so a neighbour is
identified by its link-local address and the packet's source address is the
implicit next hop.

> Babel's strength is its **feasibility condition**: it never installs a route
> that could form a loop, which lets it converge without counting to infinity and
> makes it safe on dynamic, meshy topologies where RIP would misbehave.

## What is implemented

**The packet/TLV codec** — the 4-byte packet header (Magic 42, Version 2, body
length) and the body as a sequence of TLVs: Pad1/PadN, Hello, IHU, Router-ID,
Next Hop, Update, Route Request, Seqno Request and Acknowledgment(-Request). The
address encodings AE 0 (wildcard) / 1 (IPv4) / 2 (IPv6) / 3 (link-local IPv6) are
supported, including §4.5 **prefix de-compression** of Updates on receive (the
per-address-family "default prefix" register). Unknown TLVs are preserved verbatim.

**The route table and feasibility condition** (§3.5) — a *source table* keeps the
feasibility distance per `(prefix, router-id)`; a received `(seqno, metric)` is
feasible only if it is strictly better (a newer seqno, or the same seqno with a
smaller metric), or the source is new, or it is a retraction. The *route table*
keeps every neighbour's offered route and selects, per prefix, the feasible route
of smallest metric (advertised metric + the link cost to the neighbour). The
selected route is kept feasible by definition, so its own refreshes never retract
it.

**The neighbour table and link cost** (§3.4) — per neighbour, a **Hello reception
history** and the **txcost** it reports about us in its IHUs. From the history we
compute our **rxcost** with the wired **"2-out-of-3"** rule (nominal cost 256 when
at least two of the last three expected Hellos arrived, else infinite) and
advertise it back in our own IHUs; the link **cost** is the neighbour's txcost when
both directions are usable. Stale IHUs make the cost infinite; stale Hellos drop
the neighbour and flush its routes.

**The UDP runner** (in `wren-daemon`) ties them together — one IPv6 socket per
interface, bound to `[::]:6696` and joined to `ff02::1:6`:

- periodic **Hellos** with an increasing sequence number, plus an **IHU** per
  neighbour advertising our receive cost for it (so both directions converge);
- periodic **Updates** originating our own (connected + configured) networks and
  re-advertising the routes we have selected, grouped under their origin Router-ID;
- on receipt, Hellos/IHUs drive the neighbour table and Updates — costed by the
  link to the sending neighbour and fed through the feasibility condition — drive
  the route table; selection changes are installed into the RIB as `proto babel`;
- a learned route's link-local next hop is **pinned to the receiving interface**
  before it goes to the kernel.

## Configuration

A two-router setup over a shared link. Each side originates its directly-connected
networks automatically; `network` adds extra prefixes.

```toml
# Router A
router-id = "10.0.0.1"

[babel]
enabled    = true
interfaces = ["eth1"]
```

```toml
# Router B
router-id = "10.0.0.2"

[babel]
enabled    = true
interfaces = ["eth1"]
```

The 8-octet Babel Router-ID is derived from `router-id` (the dotted quad packed
into the low four octets); set `[babel].router-id` to override it.

> **Binding the socket** uses `SO_BINDTODEVICE`, which needs `CAP_NET_RAW`. Inside
> an `unshare -Urn` namespace the namespace-root has it; otherwise run with the
> capability (or as root).

### Redistribution from the RIB

Beyond its own connected and configured networks, Babel can originate the routes
other protocols hold in the RIB — statics, or routes learned by an IGP or BGP — by
naming their protocols under `redistribute`:

```toml
[babel]
enabled      = true
interfaces   = ["eth1"]
redistribute = ["connected", "static", "ospf3"]   # RIB source protocols
redistribute-metric = 0                            # the metric "at the source"
```

This is the same router → protocol push that feeds [BGP](bgp.md#redistribution),
[OSPF](ospf.md#redistribution-from-the-rib) and [RIP](rip.md#redistribution-from-the-rib)
redistribution: the [central router loop](../architecture.md) offers each
best-path change to Babel, which **originates** it as one of its own routes (under
our Router-ID, at `redistribute-metric`) and **retracts** it (an Update at metric
infinity, §3.5.5) when its best path goes away. Babel is genuinely dual-stack, so
**both IPv4 and IPv6** routes are carried (unlike RIP/RIPng, which each take only
their own family); a network Babel already originates itself takes precedence, it
never redistributes its own routes, and an optional `[export] babel = "name"`
filter (the same `wren-filter` engine) gates and rewrites the routes first.

`scripts/babel-redistribute-smoke.sh` exercises it live (rootless): an IPv6 static
is withheld from the peer without `redistribute`, then originated over Babel and
installed `proto babel` once `redistribute = ["static"]` is set. (An IPv4 static
is originated too, but installing it at a peer via the IPv6 next hop needs the
`RTA_VIA` support that is still on the roadmap — so the smoke uses IPv6.)

## Testing it

With a global IPv6 network on each side of a veth between two namespaces, both
routers learn and install each other's network:

```text
# on A:
2001:db8:b::/64 via fe80::… dev eth1 proto babel
# on B:
2001:db8:a::/64 via fe80::… dev eth1 proto babel
```

## Inspecting it

The daemon answers two Babel `show` commands over its
[control socket](../configuration.md), rendered by the Babel task itself out of
its live state — no shared access, like the other protocols' `show` commands:

```console
$ wren show babel neighbors
fe80::ee:ccff:fe22:1182 rxcost 256 cost 256

$ wren show babel routes
2001:db8:99::/64 via fe80::ee:ccff:fe22:1182 metric 256
```

`show babel neighbors` lists each neighbour (by its link-local address), the
**rxcost** it reported to us in its IHU (§3.4.3), and the **cost** we use towards
it (`inf` if the link is currently unusable). `show babel routes` lists the
**selected** routes (the Babel RIB) with their next hop and metric.
`scripts/babel-show-smoke.sh` exercises both live (rootless): two routers exchange
Hellos and IHUs, one redistributes a route, and the queries report the neighbour
and the learned route.

## Not yet implemented

ETX costing for lossy/wireless links (only the wired "2-out-of-3" rule today),
explicit handling of received Route/Seqno Requests, prefix **compression on send**
(receive already de-compresses), **IPv4 routes over the IPv6 transport** (which
need `RTA_VIA` next hops in the kernel FIB backend), and source-specific routing.
These are tracked in the [Roadmap](../roadmap.md).
