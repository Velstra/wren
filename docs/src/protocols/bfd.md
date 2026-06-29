# BFD

Wren implements **Bidirectional Forwarding Detection**
([RFC 5880](https://www.rfc-editor.org/rfc/rfc5880), single-hop encapsulation
[RFC 5881](https://www.rfc-editor.org/rfc/rfc5881)) — a lightweight,
protocol-independent hello mechanism that detects a forwarding-path failure in
**well under a second**, far faster than a routing protocol's own hold timer.

> A BGP session with a 180-second hold time would take up to three minutes to
> notice a silently blackholed path (one where no TCP reset is ever delivered).
> A BFD session over the same path notices in a few hundred milliseconds and tells
> BGP to tear the session down at once.

Two systems exchange small UDP Control packets at a sub-second rate. When a system
stops hearing its neighbour for `detect-mult` receive intervals it declares the
session **Down**, and the protocols riding that path drop their adjacency
immediately rather than waiting for the hold / dead timer. **BGP**, **OSPFv2** and
**OSPFv3** all use it.

Scope: **single-hop asynchronous mode**, **IPv4 and IPv6**, no authentication and no
Echo — the configuration that drives routing-protocol failover. The Demand and Echo
modes, authentication (§6.7), and BFD for IS-IS are future extensions.

## What is implemented

**The Control-packet codec** (RFC 5880 §4.1) — the 24-octet mandatory section:
Version, Diagnostic, State, the P/F/C/A/D/M flags, Detect Mult, the My/Your
Discriminators and the three microsecond interval fields. The reception checks that
can be made on a packet alone are enforced on decode (version 1, a sane Length, a
non-zero Detect Mult and My Discriminator, the Multipoint bit clear, and a Your
Discriminator that may only be zero while the sender is Down/AdminDown).
Authenticated packets are rejected. This lives in the dependency-free `wren-bfd`
crate and is unit-tested with no I/O.

**The session state machine** (§6.8.6) — the `Down → Init → Up` handshake, with a
neighbour signalling Down or a detection timeout taking an Up session back to Down
(diagnostics Neighbor Signaled Session Down and Control Detection Time Expired). A
received Poll is answered with the Final bit (§6.8.7). The Desired Min TX Interval
is floored to one second while the session is not Up (§6.8.3), so forming or failed
sessions are cheap, and drops to the configured rate once Up. The transmit interval
carries the §6.8.7 jitter; the Detection Time is `detect-mult ×` the negotiated
receive interval (§6.8.4).

**The UDP runner** (in `wren-daemon`) ties them together — shared receive sockets on
UDP port **3784** for **both IPv4 and IPv6** (the latter bound `IPV6_V6ONLY` so the
two coexist), a connected transmit socket per peer sending with **TTL / hop limit
255** (the GTSM check single-hop BFD relies on, RFC 5881 §5), per-session transmit
and detection timers, and demultiplexing received packets to a session by
`(source address, scope)`. The **scope** is the receiving interface index, which is
what keeps IPv6 **link-local** peers distinct — exactly how OSPFv3 identifies its
neighbours. Sessions are **dynamic and multi-consumer**: a protocol registers a peer
(BGP statically at startup, the OSPF IGPs as a neighbour reaches Full), and the
runner creates the session on first registration and tears it down when the last
subscriber deregisters. A peer shared by two protocols has one session. When a
session that had come up goes down, every subscribed protocol is notified and tears
its adjacency to that peer down at once.

## Configuration

The timing is shared by every session and comes from a global `[bfd]` block (all
optional); BFD is then enabled per protocol.

```toml
[bfd]
min-tx      = 300   # Desired Min TX Interval, milliseconds (default 300)
min-rx      = 300   # Required Min RX Interval, milliseconds (default 300)
detect-mult = 3     # session fails after this many missed intervals (default 3)
```

At the defaults the Detection Time is `300 ms × 3 = 900 ms`. The peer must also be
configured to run BFD.

**BGP** — enable it per neighbour. A BFD-down tears the BGP session down (rather
than waiting for the Hold Timer); the connector re-establishes when the path
recovers:

```toml
[[bgp.neighbor]]
address   = "10.0.0.2"
remote-as = 65002
bfd       = true
```

**OSPFv2** — enable it for the instance with `[ospf] bfd = true`. A session is
brought up to each neighbour that reaches **Full**, and a BFD-down tears that
adjacency down at once (RFC 5882 §4.4) instead of waiting for the dead interval:

```toml
[ospf]
enabled    = true
interfaces = ["eth1"]
bfd        = true
```

**OSPFv3** — the same, with `[ospf3] bfd = true`. OSPFv3 neighbours are IPv6
link-local addresses, so each session runs over IPv6 (the engine binds an IPv6
control socket and keys the session by the neighbour's link-local address and the
interface scope); nothing else differs:

```toml
[ospf3]
enabled    = true
interfaces = ["eth1"]
bfd        = true
```

## Operational view

`wren show bfd` lists the sessions and their state, straight from the task that
owns them:

```sh
$ wren show bfd
peer               state      local-discr remote-discr       tx   detect
10.0.0.2           Up                   1            1    270ms    900ms
```

When the path fails, the session goes `Down` (and `remote-discr` clears) within the
Detection Time, and the BGP session to that peer is torn down — visible as the
neighbour leaving `Established` in `wren show bgp neighbors` far sooner than the
hold timer would allow.
