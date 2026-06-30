# VRFs & Route Distinguishers

A **VRF** (Virtual Routing and Forwarding instance) is a named, isolated routing
table. Routes and interfaces placed in a VRF use its own kernel routing table, so the
same IP prefix can exist in several VRFs at once without colliding — the basis of
multi-tenant routing and L3VPNs.

Wren models a VRF as a `(table, prefix)` key throughout the RIB and the forwarding
plane: every [`Route`](core.md) carries the kernel table it belongs to (the default
VRF is the main table, `254`), best-path selection runs per `(table, prefix)`, and the
kernel backend programs each route into its table via the rtnetlink `RTA_TABLE`
attribute. Overlapping address space therefore stays separate end to end.

> **Scope.** **Static** routes, **RIP** and **OSPF** can be placed in a VRF today: a
> static with `vrf = "…"`, a RIP instance with `[rip] vrf = "…"`, or an OSPF instance
> with `[ospf] vrf = "…"` install their routes into the VRF's kernel table, with the
> VRF's Route Distinguisher and route-maps. The remaining dynamic protocols (BGP,
> IS-IS, …) still run in the default VRF — they reuse the same per-runner mechanism (a
> VRF table stamped on every route a runner produces), so wiring them up is
> incremental. BGP/MPLS L3VPN is future work.

## Configuration

A `[[vrf]]` block names a VRF and the kernel routing table it programs into:

```toml
[[vrf]]
name       = "blue"
table      = 100             # the kernel routing table id
rd         = "65000:1"       # the Route Distinguisher (RFC 4364) — the VRF's identity
interfaces = ["eth1"]        # interfaces bound to this VRF (informational here)
import     = "blue-in"       # a route-map applied to routes entering the VRF
export     = "blue-out"      # a route-map applied to routes leaving the VRF to the kernel
```

A static route joins a VRF by naming it:

```toml
[[static]]
prefix = "10.99.0.0/24"
via    = "10.9.0.2"
vrf    = "blue"              # installs into table 100, not the main table
```

A **dynamic protocol** joins a VRF the same way. A RIP instance bound to a VRF runs
its sockets over the VRF's (enslaved) interfaces and installs every route it learns —
and its connected routes — into the VRF's table:

```toml
[rip]
enabled    = true
interfaces = ["eth1"]
vrf        = "blue"          # learned + connected routes go into table 100
```

OSPF joins a VRF identically — every route its SPF computes (intra-area, inter-area
and AS-external) is installed into the VRF's table:

```toml
[ospf]
enabled      = true
interfaces   = ["eth1"]
network-type = "point-to-point"
vrf          = "blue"        # SPF results go into table 100
```

For the VRF to be a real forwarding context, create the Linux VRF device and enslave
its interfaces with `ip` (or networkd) — Wren installs into the table, it does not
create the device:

```sh
ip link add blue type vrf table 100
ip link set blue up
ip link set eth1 master blue
```

### Route Distinguishers

The `rd` is a [RFC 4364](https://www.rfc-editor.org/rfc/rfc4364) §4.2 Route
Distinguisher — an 8-octet value that makes a VRF's routes globally unique. Wren
accepts all three text encodings and validates them at startup:

| Form | Type | Example |
|---|---|---|
| `<2-octet AS>:<number>` | 0 | `65000:1` |
| `<IPv4>:<number>` | 1 | `192.0.2.1:1` |
| `<4-octet AS>:<number>` | 2 | `4200000000:1` |

It is the VRF's identity (shown by `show vrf`); it is the same wire shape as a BGP
Route Target extended community but a distinct field.

### Route-maps

A VRF's `import` route-map is applied to every route as it enters the VRF (a rejected
route is dropped, an accepted one may be rewritten — metric, preference, …); the
`export` route-map gates routes on their way from the VRF's RIB to the kernel. Both
reference a named `[[filter]]`, the same engine used for protocol import/export
policy:

```toml
[[filter]]
name    = "blue-in"
default = "accept"
[[filter.rule]]
prefix = ["10.77.0.0/24"]    # keep this prefix out of the VRF
action = "reject"
```

## Operational view

`wren show vrf` lists the configured VRFs with their table, Route Distinguisher and the
number of best routes currently in each:

```sh
$ wren show vrf
vrf                 table rd                   routes
blue                  100 65000:1                   2
```

`wren show routes` tags a route with its table when it is not in the default VRF:

```sh
$ wren show routes
10.99.0.0/24 via 10.9.0.2 table 100 proto static metric 0
10.88.0.0/24 via 10.8.0.2 proto static metric 0
```

At startup Wren also reconciles stale routes **per table**, so a route a previous
instance left in a VRF table is cleaned up just like a main-table one.
