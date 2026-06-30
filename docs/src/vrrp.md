# VRRP — First-Hop Redundancy (RFC 5798)

The Virtual Router Redundancy Protocol gives a LAN a highly-available default
gateway (or any shared service address): two or more routers back a single
*virtual* IP, electing one **master** that owns it while the others wait as
**backup**s. If the master fails, a backup assumes the virtual IP within a few
advertisement intervals. It is the first-hop-redundancy half of a firewall HA
pair — Wren's equivalent of FRR's `vrrpd` or keepalived's VRRP.

Wren implements **VRRP version 3** (RFC 5798). The older VRRPv2 (RFC 3768,
IPv4-only) is not implemented; v3 supersedes it.

## How it works

Each router multicasts an **advertisement** (raw IP protocol 112, to `224.0.0.18`,
TTL 255) carrying its priority. The highest priority wins the election and becomes
master; ties break on the higher primary interface address. A backup runs a
*master-down* timer — `3 × advertisement-interval + skew`, where the skew shrinks
with higher priority — and promotes itself if it lapses without hearing from the
master.

On becoming master Wren **assigns the virtual IP** to the interface (via netlink)
and **announces it** so switches and hosts immediately relearn the address at the
new router — a gratuitous ARP for IPv4, an unsolicited neighbor advertisement for
IPv6. On becoming backup it removes the address.

VRRP is **dual-stack**: a virtual router backs either IPv4 or IPv6 addresses (one
family per `[[vrrp]]` block). IPv6 advertisements go to `ff02::12`, sourced from
the interface's link-local address.

## Configuration

```toml
[[vrrp]]
interface       = "eth0"          # the link the virtual router runs on
vrid            = 51              # 1–255, shared by both routers
priority        = 200            # 1–254; highest wins (255 = address owner)
advert-interval = 1000           # milliseconds (default 1000)
preempt         = true           # take over from a lower-priority master
virtual-address = ["10.0.0.254"] # the shared IP(s); all IPv4 or all IPv6
prefix-length   = 24             # assigned with the VIP (default 24 v4 / 64 v6)
```

For an IPv6 virtual router, give IPv6 `virtual-address`es (e.g.
`["2001:db8::ff"]`); the prefix length defaults to 64.

The backup is identical but with a lower `priority` (e.g. `100`) on its own
interface. Set `priority = 255` on the router that natively owns the address to
make it the permanent master while it is up. Multiple `[[vrrp]]` blocks run
independent virtual routers (different VRIDs, or different interfaces).

> VRRP needs `CAP_NET_RAW` (the protocol-112 socket) and `CAP_NET_ADMIN` (to
> assign the virtual IP).

## Operational view

```sh
$ wren show vrrp
vrid  interface  state       priority  master           virtual-ips
51    eth0       master           200  10.0.0.1         10.0.0.254
```

`state` is `initialize`, `backup` or `master`; `master` is the address of the
current master (this router itself when it is master).

## Scope

The runner is dual-stack (IPv4 and IPv6). Optional extensions — a dedicated
virtual MAC (`00-00-5E-00-01-{vrid}`) instead of announcing the real interface
MAC, and tracking a WAN interface or route to lower priority on failure — are
future work.
