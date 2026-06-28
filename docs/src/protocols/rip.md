# RIP & RIPng

Wren implements **RIPv2** ([RFC 2453](https://www.rfc-editor.org/rfc/rfc2453),
IPv4) and **RIPng** ([RFC 2080](https://www.rfc-editor.org/rfc/rfc2080), IPv6).
Both share one distance-vector engine; only the wire codec and transport differ.

| | RIPv2 | RIPng |
|---|---|---|
| Transport | UDP 520 | UDP 521 |
| Multicast group | `224.0.0.9` | `ff02::9` |
| Address family | IPv4 | IPv6 |

## What is implemented

- **The wire codec** — `Request`/`Response` messages and their route entries,
  encode and decode, the full-table request (§3.9.1), and netmask ⇆ prefix-length
  conversion. RIPng adds the IPv6 20-byte route-table entries and **next-hop
  entries** (RFC 2080 §2.1.1).
- **The distance-vector table** (`RipTable`) — the pure engine (RFC 2453 §3.9–10),
  with time passed in as a value so it is fully unit-testable:
  - metric accounting (add the interface cost, cap at metric 16 = unreachable);
  - the update rules (a better metric, or any update from the current source,
    replaces the route);
  - the timers — a 180 s timeout poisons a stale route (metric 16) and starts a
    120 s garbage timer, after which it is removed;
  - **split horizon with poisoned reverse** — a route is advertised back out the
    interface it was learned on with metric 16;
  - periodic (30 s) and **triggered** updates.
- **The socket runner** (in `wren-daemon`) — one multicast UDP socket per
  interface, the startup full-table request, the periodic and housekeeping timers,
  and answers to neighbours' full-table requests. RIP presents a single best route
  per prefix to the central RIB.

Each protocol presents exactly one best route per prefix to the RIB; the RIB then
arbitrates across protocols by [preference](../core.md).

## Configuration

```toml
[rip]
enabled    = true
interfaces = ["eth1", "eth2"]

[ripng]                 # RIP for IPv6
enabled    = true
interfaces = ["eth1", "eth2"]
```

Connected networks on the listed interfaces are redistributed automatically (see
[Static & Connected Routes](static-connected.md)).

### Redistribution from the RIB

Beyond its own connected networks, RIP can advertise the routes other protocols
hold in the RIB — statics, or routes learned by an IGP or BGP — by naming their
protocols under `redistribute`:

```toml
[rip]
enabled      = true
interfaces   = ["eth1"]
redistribute = ["connected", "static", "ospf"]   # RIB source protocols
redistribute-metric = 1                           # RIP metric for them (1..=15)
```

This is the same router → protocol push that feeds [BGP](bgp.md#redistribution)
and [OSPF](ospf.md#redistribution-from-the-rib) redistribution: the [central
router loop](../architecture.md) offers each best-path change to RIP, which holds
it as one of its own routes (advertised at `redistribute-metric`, immune to a
neighbour's advertisement) and **poisons** it (metric 16) when its best path goes
away. Only IPv4 routes are redistributed; RIP never redistributes its own routes;
and an optional `[export] rip = "name"` filter (the same `wren-filter` engine)
gates and rewrites the routes first. `scripts/rip-redistribute-smoke.sh` exercises
it live (rootless): a static is withheld from the peer without `redistribute`,
then learned over RIP and installed `proto rip` once `redistribute = ["static"]`
is set.

**RIPng** redistributes the same way over IPv6 — the distance-vector engine is
address-neutral, so `[ripng] redistribute` / `redistribute-metric` and an
optional `[export] ripng` filter behave exactly as above, except **only IPv6
routes** are carried (an IPv4 best-path change is offered but ignored, just as
RIP ignores IPv6 ones):

```toml
[ripng]
enabled      = true
interfaces   = ["eth1"]
redistribute = ["connected", "static", "ospf3"]   # IPv6 RIB source protocols
redistribute-metric = 1
```

`scripts/ripng-redistribute-smoke.sh` is the IPv6 counterpart: an IPv6 static is
learned over RIPng and installed `proto rip` with a link-local next hop once
`redistribute = ["static"]` is set.

## Testing it

Using the two-namespace harness from [Getting Started](getting-started.md), run a
`wren` with `[rip]` enabled on each side of a veth. The neighbour's multicast
Response is learned and installed into the kernel:

```text
10.5.0.0/16 via 10.0.0.2 dev veth0 metric 2 proto rip
```

> **Note.** Put the two veth ends in *separate* namespaces. If both ends live in
> one namespace the kernel delivers locally and short-circuits the path before the
> interface-bound RIP socket sees the packet — so nothing is learned.

For RIPng the same applies over IPv6 (link-local `fe80::` source, a learned
route's link-local next hop pinned to the receiving interface so the kernel can
install it).
