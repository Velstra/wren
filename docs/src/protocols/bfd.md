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
session **Down**, and the protocol riding that path (here BGP) drops its adjacency
immediately rather than waiting for the hold timer.

Scope: **single-hop asynchronous mode**, IPv4, no authentication and no Echo — the
configuration that drives BGP failover. The Demand and Echo modes, authentication
(§6.7), and BFD for the IGPs are future extensions.

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

**The UDP runner** (in `wren-daemon`) ties them together — a shared receive socket
on UDP port **3784**, a connected transmit socket per peer sending with **IP TTL
255** (the GTSM check single-hop BFD relies on, RFC 5881 §5), per-session transmit
and detection timers, and demultiplexing received packets to a session by source
address. When a session that had come up goes down, the runner reports it to the
BGP engine, which tears the BGP session to that peer down at once.

## Configuration

BFD is enabled **per BGP neighbour** with `bfd = true`; the timing is shared by
every session and comes from a global `[bfd]` block (all optional):

```toml
[bfd]
min-tx      = 300   # Desired Min TX Interval, milliseconds (default 300)
min-rx      = 300   # Required Min RX Interval, milliseconds (default 300)
detect-mult = 3     # session fails after this many missed intervals (default 3)

[bgp]
enabled  = true
local-as = 65001
[[bgp.neighbor]]
address   = "10.0.0.2"
remote-as = 65002
bfd       = true     # run a BFD session to this peer; drop BGP fast when it fails
```

At the defaults the Detection Time is `300 ms × 3 = 900 ms`. The peer must also be
configured to run BFD.

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
