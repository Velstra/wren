# EVPN

BGP EVPN (RFC 7432) is how wren carries **layer-2 reachability** in BGP instead of
flooding it. A VTEP advertises the MACs behind it, the subnets it can route to,
and which peers must receive its broadcast traffic — all as ordinary BGP routes,
subject to the same policy, route reflection and next-hop machinery as anything
else in the table.

The intended consumer is a data plane that programs forwarding from these routes:
a VXLAN or SRv6 overlay learns where a MAC lives, suppresses ARP locally, and
routes between subnets without ever flooding. wren does the control plane; the
`monitor evpn` stream ([below](#the-monitor-stream)) is the hand-off.

## What is implemented

| Route type | RFC | Purpose |
|---|---|---|
| Type 2 — MAC/IP Advertisement | 7432 §7.2 | where a MAC lives; the optional IP feeds ARP/ND suppression |
| Type 3 — Inclusive Multicast (IMET) | 7432 §7.3 | the BUM flood set: which VTEPs get broadcast traffic |
| Type 5 — IP Prefix | 9136 | a routed subnet, for inter-subnet forwarding (symmetric IRB) |

Plus the attributes that make them usable: the **MAC Mobility** extended
community (RFC 7432 §7.7) so a moved workload's newer advertisement wins, the
**Router's MAC** extended community (RFC 9135 §4) so a peer knows which inner
destination MAC to write, the **Encapsulation** extended community (RFC 9012),
and **SRv6 Service TLVs** (RFC 9252) when the overlay is SRv6 rather than VXLAN.

Import is Route-Target based, per instance, as RFC 7432 §7.10.1 prescribes.

## Two entities, not one

An EVPN configuration has two kinds of container, and conflating them is the
usual source of confusion:

- an **EVI** (`[[bgp.evpn.instance]]`) is a MAC-VRF — one bridged segment, one
  **L2 VNI**. It holds MACs and a flood set.
- an **IP-VRF** (`[[bgp.evpn.ip-vrf]]`) is a routed context — one **L3 VNI**. It
  holds subnets.

Several bridged VNIs normally share one routed VNI, which is why they are separate
blocks with their own Route Distinguishers and Route Targets rather than extra
fields on one. In a real deployment the RTs differ: an operator who wants a tenant
to bridge within its segments *and* route between them imports two distinct sets.

An L3 VNI numerically equal to some L2 VNI is a **different context**, not the
same one — they live in separate number spaces.

## Configuration

```toml
[bgp]
local-as  = 65001
router-id = "10.0.0.1"

[bgp.evpn]
vtep-ip = "10.0.0.1"          # advertised as the next hop / IMET originating IP

# One bridged segment.
[[bgp.evpn.instance]]
evi = 1
vni = 10100
# rd        = "10.0.0.1:1"                # default: router-id:evi
# rt-import = ["rt:65001:10100"]          # default: rt:<local-as>:<vni>
# rt-export = ["rt:65001:10100"]
advertise-mac = [
    "02:00:00:00:00:aa",                  # MAC only
    "02:00:00:00:00:bb/192.168.100.10",   # MAC + IP, for ARP/ND suppression
]

# The tenant's routed context over those segments.
[[bgp.evpn.ip-vrf]]
name       = "tenant-a"
l3-vni     = 50100
router-mac = "02:00:5e:00:00:aa"
advertise-prefix = ["10.20.0.0/24"]
# rd/rt-import/rt-export default to router-id:l3-vni and rt:<local-as>:<l3-vni>
```

A peer carries these routes once the address family is enabled on it:

```toml
[[bgp.neighbor]]
address   = "10.0.0.2"
remote-as = 65001
evpn      = true          # negotiate the L2VPN/EVPN address family with this peer
```

### `router-mac` is not optional under VXLAN

`advertise-prefix` without `router-mac` is a **configuration error**, and
deliberately so. RFC 9136 §4.4.1 is explicit: *"The EVPN Router's MAC Extended
Community must be sent if the route is associated with an Ethernet NVO tunnel"*.
Without it the route still propagates, but no VXLAN peer can forward on it —
there is no inner destination MAC to address the encapsulated frame to. wren
refuses the config rather than advertising a subnet nobody can use.

An `srv6-locator` lifts the requirement: `End.DT4`/`End.DT6` decapsulates
straight into an IP lookup, so there is no inner Ethernet header to write.

### Type-5 uses the interface-less model

wren originates IP Prefix routes in RFC 9136 §4.4.1's **interface-less
IP-VRF-to-IP-VRF** model: gateway IP all-zero (§3.1: *"The GW IP field MUST be
all bytes zero if it is not used as an Overlay Index"*), ESI zero, and the label
carrying the L3 VNI. The Router's MAC extended community is what the receiving PE
uses as the inner destination MAC — this is **symmetric IRB**: traffic is routed
into the tenant's L3 VNI, not bridged into the destination's L2 VNI.

## EVPN over SRv6

Set a locator and every originated route carries an SRv6 Service TLV (RFC 9252)
instead of relying on a VXLAN VNI:

```toml
[bgp.evpn]
vtep-ip      = "10.0.0.1"
srv6-locator = "fc00:0:1::/48"
```

The service SID is derived from the locator, a per-service-type discriminator and
the VNI, so it is stable and needs no separate allocation. Each route type gets
the behaviour that matches what a receiver must do with it:

| Route | Service TLV | Behaviour |
|---|---|---|
| type 2 (MAC/IP) | L2 | `End.DT2U` — decapsulate and bridge to one MAC |
| type 3 (IMET) | L2 | `End.DT2M` — decapsulate and flood |
| type 5 (IP Prefix) | L3 | `End.DT4` / `End.DT6` by address family |

The L2/L3 distinction matters on the wire: a receiver looking for an L3 service
skips an L2 TLV entirely.

The locator must be a byte-aligned IPv6 prefix of length 8–96.

## Operational visibility

`show evpn` prints the import view — what this router has *learned*, per
container:

```
$ wren show evpn
EVI 1 vni 10100 rd 10.0.0.1:1
  mac 02:00:00:00:00:bb -> vtep 10.0.0.2 ip 192.168.100.10
  flood -> 10.0.0.2
IP-VRF tenant-a l3vni 50100 rd 10.0.0.1:50100
  prefix 10.20.0.0/24 -> vtep 10.0.0.1 router-mac 02:00:5e:00:00:aa
```

A prefix whose remote L3 VNI differs from ours prints `remote-l3vni <n>`. RFC 9136
permits the two ends to use different values, and a mismatch is exactly the kind
of thing `show evpn` exists to surface.

### The monitor stream

`monitor evpn` is the machine-readable feed a data plane consumes. It opens with a
**snapshot** of the current tables, terminated by `% end-of-dump`, then streams live
changes — so a consumer that reconnects rebuilds its whole forwarding state
without a separate query.

```
+ evpn vni <vni> mac <mac> [ip <ip>] vtep <vtep> [srv6 <sid>]
- evpn vni <vni> mac <mac>
+ evpn vni <vni> flood <vtep>
- evpn vni <vni> flood <vtep>
+ evpn l3vni <vni> prefix <p> vtep <v> [router-mac <m>] [gw <g>] [srv6 <sid>]
- evpn l3vni <vni> prefix <p>
% end-of-dump
```

The format is **append-only**: new optional fields are appended to a line, never
inserted, so an older consumer keeps parsing what it understands. Note that the
routed lines say `l3vni`, not `vni` — a deliberately distinct keyword, so a
consumer that only speaks L2 skips them instead of misreading a routed update as
a bridging one.

### Advertising at runtime

`evpn advertise|withdraw <vni> <mac> [ip]` originates or withdraws a type-2 route
without a config change — the write-side counterpart to the read feed. This is how
a data plane advertises the MACs it has learned locally:

```
$ wren evpn advertise 10100 02:00:00:00:00:cc 192.168.100.20
$ wren evpn withdraw 10100 02:00:00:00:00:cc
```

`advertise-mac` in the config file serves gateways, anycast addresses and tests —
anything static enough to belong in the configuration.

## Not yet implemented

Type-1 (Ethernet Auto-Discovery) and type-4 (Ethernet Segment) routes, and with
them multi-homing, ESI-based load balancing and split-horizon filtering. A VTEP
is single-homed today.
