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

### Tracking an uplink

For a real firewall pair the master should step aside when *its own* uplink
fails, so the backup — whose uplink still works — takes the gateway over. Track
interfaces and the effective priority drops while any of them is down:

```toml
[[vrrp]]
interface          = "lan0"
vrid               = 51
priority           = 200
virtual-address    = ["10.0.0.254"]
track-interface    = ["wan0"]   # the uplink to watch
priority-decrement = 150        # subtracted while wan0 is down (default 50)
```

If `wan0` goes down the priority falls to `200 − 150 = 50`; a backup at priority
100 then preempts and becomes master. When `wan0` recovers the priority returns to
200 and (with `preempt = true`) this router takes the gateway back.

### Electing on one link, serving on another

A firewall with many tagged segments has one link it shares with its peer and a
dozen it serves. If the election and the address had to be the same link, every
segment would need a virtual router and a VRID of its own — a lot of protocol for
one question, *who is master*, that has the same answer everywhere.

`address-interface` separates them:

```toml
[[vrrp]]
interface         = "sync0"        # advertisements go here
vrid              = 51
priority          = 200
virtual-address   = ["10.0.20.254"]
address-interface = "lan20"        # the address is installed here
```

The advertisements stay on the link that is guaranteed to be up between the pair;
the address is installed on the link that serves it, and the gratuitous ARP and
the unsolicited neighbour advertisement go out there too — with *that* link's
MAC. That last part is the one worth saying out loud: a host on the served
segment has to learn the address against a MAC it can send to, and the election
link's MAC is not it.

An `address-interface` that does not exist at start-up is a warning and a
fallback to the advertisement link, not a refusal. A virtual router that will not
start because one of a dozen segments is missing is worse than one that runs and
says so.

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

## Appliance HA: witness or explicit two-node mode

An appliance `[ha]` configuration replaces the independent VRRP elections above
with one forwarding authority for all configured VIPs. This requires the
compatible data-plane HA agent and kernel guard: a running Wren process or a
reachable peer alone is not permission to forward. Agent boot identity, policy
digest, state readiness and bounded local kernel deadlines remain mandatory.

`mode = "witness"` is the default and requires an independent authenticated
witness. Existing configurations with `witness` and no `mode` retain this
behavior. The alternative `mode = "two-node"` uses authenticated peer heartbeats
without a witness. There is **no automatic fallback** between the two modes;
configuring both a witness and two-node peers is rejected.

**Two-node mode is availability-oriented, not quorum fencing. If every control
path is partitioned, both healthy members can eventually become active.** On
reconnection, deterministic priority/node ordering fences the losing member.
Use witness mode when ownership must remain exclusive through a total member
partition. Two VLANs sharing one NIC or switch do not provide independent
physical failure paths.

The following is the Wren runtime format for member 1. On a managed Sentinel
appliance, use its HA configuration/enrollment workflow instead of editing the
generated Wren file. Provision a real shared derived runtime key securely;
the example key below is not a credential.

```toml
[ha]
mode = "two-node"
cluster = "example-cluster-0001"
node = 1
secret = "EXAMPLE-ONLY-never-use-this-runtime-key"
priority = 200
preempt = false
lease_ms = 250
io_ms = 80

[ha.two_node]
listen = ["10.3.0.1:5441"]
peers = ["10.3.0.2:5441"]
peer_timeout_ms = 1000
startup_delay_ms = 3000

[[vrrp]]
interface = "lan0"
vrid = 51
virtual-address = ["10.0.0.254"]
prefix-length = 24
```

Member 2 uses `node = 2`, its own priority (for example 100), and reciprocal
`listen`/`peers` addresses. Both members need the same cluster and derived key,
compatible policy, and configured state replication. Up to four matching
local/peer paths are supported. Heartbeats use **TCP**, conventionally port
5441, with expected-source-IP admission and mutually authenticated nonce-HMAC
sessions; sequence/boot-epoch checks reject replay. Authentication does not
encrypt metadata, so use private control links. Permit the selected TCP
endpoints only between the intended members; state replication has its own
transport and configuration.

The default peer timeout is 1000 ms; accepted values are 750–1200 ms and must
fit the configured lease/I/O budget and the data-plane replica freshness
budget. Startup delay must be at least twice the peer timeout. An eligible
cold bootstrap is distinct from warm takeover: a stale or incomplete warm
snapshot is not silently promoted as an empty table. With preemption disabled,
a healthy connected incumbent stays active. Explicit preemption requires the
challenger's matching warm state; equal priorities favor member 1.

During startup, Sentinel may temporarily remove control addresses while it
reattaches the data plane. Wren publishes a closed role and retries only a
missing-local-address bind error every 100 ms, honoring shutdown. The election
startup quarantine begins only after every configured listener binds. Other
errors (including port conflicts and permissions) fail explicitly; Wren never
uses wildcard/freebind listeners to bypass address readiness. Unit tests cover
delayed availability, cancellation, fatal errors and partial-bind cleanup.
Actual appliance VM/hardware tests must additionally prove kernel/Agent
readiness, VIP ownership, live-flow failover and total-path-partition recovery.

## Scope

The runner is dual-stack (IPv4 and IPv6) with interface tracking. The remaining
optional extension is a dedicated virtual MAC (`00-00-5E-00-01-{vrid}`) instead of
announcing the real interface MAC; tracking a route (rather than an interface) to
demote on upstream failure is a small follow-on.
