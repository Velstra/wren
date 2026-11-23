# Changelog

All notable changes to Wren are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/), and from `0.1.0` the project
follows [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.5.0] — 2026-11-24

This is the state shipped in Sentinel 1.0.0: the tag `sentinel-v1.0.0` names
the same commit. It is a minor release because HA behaviour changed — the
lease alone decides who holds the VIPs, a takeover announces sooner, a
preemption waits for the takeover it follows, and a WireGuard successor's
clock is stepped by a separate helper — and because eBGP now defaults to
RFC 8212 deny.

### Breaking and behaviour changes

- **BREAKING: an eBGP peer with no policy now exchanges nothing, by default.**
  RFC 8212's default-deny has been in Wren since 0.4.0, but as `[bgp]
  ebgp-require-policy = true` — off unless asked for, which is the one setting
  everybody who needs it has never heard of. It is now the default, as the RFC
  has required since 2017: an eBGP neighbour with no `import` policy accepts no
  routes, and one with no `export` policy advertises none. iBGP and
  confederation sessions are untouched — the RFC is about external peers.

  Two things follow that will surprise an existing configuration. **Upgrading a
  policy-less eBGP config silences it**: the session still establishes, and no
  routes cross it. And **a locally-originated route is no longer exempt** — the
  `network` statements, redistribution, aggregates and `default-originate` of a
  speaker with no export policy stay home too. The old implementation gated
  transit routes and let a speaker's own out, which is precisely the leak the
  RFC exists to stop: "Routes SHALL NOT be added to an Adj-RIB-Out associated
  with an EBGP peer if no explicit Export Policy has been applied" draws no such
  line.

  Nothing is silent about it. The session logs, once, at establishment, which
  directions are denied and how to change it; `show bgp neighbors` grows a
  `policy-denied <n>` count of what was discarded on receipt, and the same
  number is exported as `wren_bgp_policy_denied_received_total`. An
  Established-but-empty peer now says why in three places, rather than looking
  identical to a broken one.

  To keep permit-all where you mean it: `require-policy = false` on a single
  `[[bgp.neighbor]]` — the route server or lab peer that really is meant to
  exchange everything — or `[bgp] ebgp-require-policy = false` for a whole
  speaker at once. The per-neighbour key wins over the global one, so one
  session can opt out while the rest of the router keeps the protection, and one
  can be re-armed on a speaker that has opted out globally.
- **The lease, not a second look at the agent, decides whether a member holds
  its VIPs.** A new owner no longer drops its VIPs for up to one lease right
  after a takeover because one agent report arrived late during a witness
  exchange. A wedged or ineligible agent now keeps the VIPs until the lease
  it last renewed ends: at most the 100 ms freshness bound plus one 250 ms
  lease, and the release follows on the next poll after the exchange in
  flight (about 0.45 s after the agent stops). Its stale or ineligible reports stop the renewals, and its data
  plane is already fenced: by process exit, by ineligibility, or (for a
  wedged agent) by the kernel deadline it no longer extends. In two-node mode
  the election refuses an ineligible request and zeroes the deadline, so the
  VIPs go on the next tick there; the second agent check after the exchange
  is gone in both modes.
- **A preemption no longer interrupts the takeover it follows.** In witness
  mode a higher-priority member could preempt a new owner as soon as it held
  that owner's snapshot. After the owner's Wren crashed, its restarted
  coordinator took the pair back 3 to 4 s after the fault, as soon as its
  agent held the successor's snapshot. A WireGuard takeover still waiting for
  a handshake retry then lost the pair before it forwarded: two handovers
  for one fault (3.95 s of outage). The witness
  now honours a preemption only once the owner has held its authority for
  10 s (`PREEMPT_HOLD_MS`). Failover is unchanged; only the return of a
  preempting member waits.
- **The first announcement after a takeover no longer waits for the next
  witness exchange.** The new owner sends its gratuitous ARP and neighbour
  advertisements as soon as its agent acknowledges forwarding the new term,
  while its lease for that term is still running. The exchange it used to
  wait for is the slowest of a takeover (the witness records the
  acknowledgement durably), so a takeover reaches clients 50 to 70 ms sooner
  in witness mode. Holding and releasing the VIPs are decided as before. The
  WireGuard promote still starts before that first announcement.
- **A WireGuard successor's wall clock is stepped up to its predecessor's by a
  new helper, `wren-ha-clock-step`.** Both members share one WireGuard
  identity, and a member whose clock lagged (a resumed VM, 8.9 s behind in the
  measured case) had its promotion handshake dropped as a replay. The helper
  is a separate `wren-daemon` binary, socket-activated on
  `/run/velstra-ha-clock.sock` and long-running; Wren holds no clock
  privilege, connects at promotion, waits at most 2 s and promotes whatever
  the answer. The helper reads the agent's replicated reading from
  `/run/velstra/ha-clock/peer.json` and steps only forward, not for a lag
  under 100 ms, at most 60 s when both clocks claim NTP synchronisation and
  10 min otherwise, never on a reading older than 5 s, and at most 10 min in
  total per boot. Each decision is recorded in `/run/velstra/ha/clock.json`.
- **The lease witness is stricter.** A lone survivor may claim the lease after
  peer silence only within an established cluster (authority term above 0),
  never open a new one; the witness serves only its configured members; and it
  authenticates with a derived key instead of the admin secret.
- **A reload completes when only learned routes are refused, and is
  acknowledged only once converged.** See *Routing* below; the reload states
  are now `converged`, `degraded` and `pending`.
- **`wren_ospfv3::spf::SpfRoute::to_route` returns `Option<Route>`** (see the
  OSPFv3 fix below), a source change for code embedding the crate.

### HA

- **Witnessless two-node HA coordination**, alongside the witness mode, with VRRP
  guard tests.
- **HA coordinates with durable witness leases**: exact warm and cold grant
  claims are persisted before ownership is acknowledged, the lease and
  I/O-timeout budget are recorded in the witness state, data VPNs are
  reconstructed, reloads and bootstrap retries stay bound to the correct actor
  and agent, and a failed start clock no longer yields a lease without end.
- `show vrrp` reports standby readiness. Bounded WireGuard promotion failures
  are reported without exposing private configuration.
- **Logging no longer blocks the daemon.** Log lines were written straight to
  stdout, a pipe to journald under systemd. When journald stopped reading
  (synchronous console forwarding, disk pressure, rate limiting) every task
  that logged blocked on the stdout lock — the HA lease coordinator included,
  so its 25 ms renewals stalled past the 250 ms witness lease and the pair
  failed over with no fault. Lines now go through a bounded queue (4096 lines)
  drained by a dedicated writer thread; while the output is blocked new lines
  are dropped instead of waited for, counted in the new metric
  `wren_log_lines_dropped_total`, and reported on the log as soon as it
  drains. A daemon exit waits up to 500 ms for the queued lines. The queue
  size can be set with `WREN_LOG_QUEUE_LINES` (1–65536).
- **VRRP:** elections recover when interface addresses change, a master
  refreshes its VIP neighbour announcements, and virtual addresses stay on
  usable declared links.
- **VRRP can hold the virtual address on a link other than the one it elects
  on.** `address-interface` on a `[[vrrp]]` separates the two: advertisements
  stay on the link that is guaranteed to be up between the pair, while the
  address is installed on the link that serves it. The gratuitous ARP and the
  unsolicited neighbour advertisement go out there too, with *that* link's MAC —
  a host on the served segment has to learn the address against a MAC it can
  actually send to. Without this, a firewall with a dozen tagged segments needed
  a virtual router and a VRID per segment to answer one question, "who is
  master", that has the same answer on all of them. An `address-interface` that
  does not exist at start-up warns and falls back to the advertisement link
  rather than refusing to start.

### Routing

- **A route the kernel refuses no longer holds every routing reload open.** A
  reload completed only when every prefix was in the kernel, so one refused
  learned route (any protocol) kept each new generation `pending`: `wren
  reload` timed out after 30 s, deferred protocol reconfiguration never ran,
  and every Sentinel commit failed while it lasted. A reconciliation pass that
  completes with only learned routes refused now settles as `degraded` — the
  configuration is applied, the refused routes are retried every reconcile
  tick — and `wren reload` succeeds. A refused configured static route still
  keeps the generation `pending`, as the operator's own change is not in the
  kernel. Receipts and `show reload` name each refused route on a
  `failed-route <table> <prefix> <protocol>` line (at most 16, the rest
  counted), including the receipt a timed-out reload prints.
- **Owned FIB state is reconciled** with exact route identities, failed kernel
  updates are recovered, a reload is acknowledged only once it has converged,
  static imports are enforced and exactly the owned routes are withdrawn, and
  the kernel's IPv6 default metric (0 read back as 1024) is recognised on
  readback.
- **OSPF's Router-LSA flags are in the byte RFC 2328 A.4.2 names.** The V/E/B
  bits were written to byte 1, and read back from it, so wren agreed with
  itself while telling every other implementation it was neither an ABR nor an
  ASBR — FRR kept its AS-external LSAs and installed none of them. The
  Router-LSA is re-originated when the ASBR status changes, and `show ip ospf
  database` prints the flags by name. OSPFv3 was already correct.
- **Three OSPF faults only another implementation found:** an LSA was flooded
  without its length and checksum stamped, a neighbour was identified by the
  wrong field for the interface type (RFC 2328 §10), and removing a route
  deleted the link's own connected route with it.
- **OSPFv3 redistribution follows a reload.** `[ospf3] redistribute_static`
  advertised the static routes configured when the engine started and nothing
  else: a reload that removed one left its AS-external LSA in every
  neighbour's database (and the route in their FIBs), and one that added a
  static was never advertised. OSPFv3 now takes the central router's
  redistribution feed, as OSPFv2 and the other IGPs do, and originates or
  flushes (MaxAge) the external LSA as the static comes and goes, without
  restarting the engine or its adjacencies.
- **OSPFv3 no longer installs routes for directly attached prefixes.** A
  prefix on a link the router sits on (two routers on one shared /64, or the
  router's own) came out of the SPF with no next hop and was handed to the
  kernel as a route with neither a gateway nor an interface. Netlink refused
  it ("route nexthop has neither gateway nor interface"), the router retried it
  forever, and every routing reload stayed pending. Such prefixes are now left
  out, as OSPFv2 and IS-IS already did — the kernel's connected route covers
  them — and a link-local next hop whose interface cannot be named is dropped
  rather than installed unpinned. `wren_ospfv3::spf::SpfRoute::to_route` now
  returns `Option<Route>`.
- **OSPFv2/v3 withdraw their own LSAs on a normal shutdown.** Configuration
  restarts now flood MaxAge instances at the original link, area and AS scopes,
  then accept acknowledgments and retry within a bounded shutdown window.
  Removing a redistributed static route no longer leaves a stale route on
  neighbours until MaxAge. Reaching Full also refloods fresh external LSAs so
  rapid withdrawal/re-addition converges after database exchange. Cached own
  external LSAs that are no longer desired are purged when received after a
  restart, including graceful restarts. OSPFv3 clears requests for reclaimed
  self-originated LSAs so synchronization does not stall in Loading. Foreign
  advertisements remain untouched; an enabled
  OSPFv2 graceful restart keeps its existing Grace-LSA behavior.
- **OSPF ignores a Hello from off its own subnet (RFC 2328 §8.2).** A router
  with two subnets on one LAN runs an OSPF interface per address and sends a
  Hello from each, both with its Router ID. The one from the other subnet was
  let in: it sat in Init as a second neighbour entry, and it took part in the
  DR election under the same Router ID. Whichever entry the election read
  first decided the DR *address* our Router-LSA named on its transit link —
  and when that was the address on the other subnet, no Network-LSA matched
  it, the SPF tree ended at this router, and not one route was computed while
  every database was in perfect agreement. Against FRR that was one restart
  in two. On broadcast and NBMA links a packet whose source is not on the
  interface's network is now dropped at the door, as the RFC says; the
  comparison is not made on point-to-point links.
- **OSPF no longer asks the kernel for a route with no next hop.** The SPF
  hands back the segment this router sits on (and any destination whose
  gateway it could not resolve) with an empty gateway set, and the runner
  passed that on as an on-link route with no interface. The netlink backend
  wrote it with interface index 0, the kernel answered `No such device`, and
  the router retried it every reconcile tick for as long as the adjacency
  lasted — `FIB install failed; queued for retry` every fifteen seconds on
  every OSPF box. Such a prefix stays off the announced set: the kernel's own
  connected route already covers the segment, and a route without a next hop
  is not a route. Each SPF run now also logs, at info, how many routers the
  tree reached and how many routes came out of it; the routes themselves are
  at debug.
- **BGP:** the IPv4-unicast multiprotocol capability is advertised (the IPv6
  entry alone made a peer find no IPv4 in the set), and a configured network
  list too large for one UPDATE (about 815 IPv4 /32s) is split across as few
  UPDATEs with identical attributes as the 4096-octet limit allows instead of
  resetting the session.
- **IS-IS:** the LSP IS Type has its own codec; it used the Hello Circuit Type
  numbering, so every Level-2 LSP carried an unused value and a neighbour's 3
  decoded as L1L2.
- **A type-3 IMET route's SRv6 SID reaches the EVPN monitor stream.** The flood
  lines were `+ evpn vni <vni> flood <vtep>` with no room for a service SID, so a
  consumer on an SRv6 data plane learned *who* to flood to and had nothing to
  flood *at*: the VTEP address identifies the advertiser, and an SRv6 datapath
  cannot encapsulate toward it. The line is now
  `+ evpn vni <vni> flood <vtep> [srv6 <sid>]`, and `EviTable` keeps each flood
  peer's advertised `End.DT2M` SID alongside it.

  The SID is deliberately a different one from the `End.DT2U` SID a type-2 route
  carries: RFC 9252 binds a SID to exactly one behaviour, so a BUM copy sent to
  the unicast SID is bridged to a single MAC on arrival and every other workload
  on the segment misses it.

  Re-advertisement with a *changed* SID now counts as a forwarding change too. It
  did not before — membership alone decided — so a peer that moved its locator, or
  moved between SRv6 and VXLAN, kept being flooded to a SID it no longer
  terminates.
- **Blackhole static routes and administrative distance.** `blackhole = true` on
  a `[[static]]` discards what matches instead of forwarding it — the standard
  way to null-route a prefix, and what makes a BGP summary stick without also
  announcing the more specifics inside it. It takes no `via`/`dev`, and saying
  both is refused rather than silently resolved. `distance` ranks two routes to
  the same prefix in the usual convention where lower wins, which is how a
  floating static sits behind a learned route and takes over only when that goes
  away.
- **A filter can send a route somewhere else.** `set-next-hop <address>` on a
  `[[filter.rule]]`. Route maps could already change a route's metric,
  preference and communities — everything about how it is *chosen* — but not
  where it is forwarded, which is the one an operator reaches for when a path
  has to move without the routing changing underneath it. It replaces the
  route's whole next-hop set: a multipath route sent via one named gateway has
  one next hop by definition. Giving a next hop to a route that had none stops
  it discarding, which is documented rather than refused.
- **`wren check` — resolve a configuration without starting anything.** Parse,
  compile the filters, resolve the import/export attachments and the VRF
  route-maps, build the static routes and the BGP neighbour set, print a summary,
  exit. It is the same work a `SIGHUP` reload does before it commits, so a file
  that passes is one the running daemon would accept — and because nothing is
  started, no socket is opened and the kernel is not touched, it is safe to run
  on a box that is already routing. A file that fails names what is wrong and
  exits non-zero. `--config` became a global argument so `wren check -c f.toml`
  works as well as `wren -c f.toml check`.
- Export writes are bounded, monitor and reload lifecycles are cleaned up, and
  raw socket registration follows the updated Tokio safety contract.

### Security fixes

- **BGP receive-side validation.** ORIGIN and AS_PATH are required on an
  UPDATE carrying only MP_REACH (the check never ran for IPv6, EVPN, FlowSpec,
  SR-Policy or Link-State); an unrecognised (AFI, SAFI) is refused instead of
  decoded as IPv4; the MP_REACH next-hop length is checked per family; AS 0
  and a zero BGP Identifier in OPEN are rejected; the 4096-octet message
  ceiling is imposed. An UPDATE whose AS path already holds our own AS is
  dropped (RFC 4271 §9.1.2).
- **BFD's authentication replay window survives the sequence wrap.** After one
  wrap every authenticated packet was rejected for ever, tearing the session
  down; serial-number arithmetic is used now, and the A-bit length floor of
  RFC 5880 §6.8.6 is enforced.
- Encoders clamp an out-of-range prefix length from decoded input instead of
  slicing out of bounds.
- The lease witness admits only its configured members and no longer
  authenticates with the admin secret (see above). The clock-step helper keeps
  the clock privilege out of Wren, which parses untrusted BGP, OSPF and IS-IS:
  a compromised Wren can trigger a decision on the agent's reading, but can
  neither supply the reading nor exceed the per-boot budget.

### Documentation

- The operator handbook is rewritten around tested routing scenarios, with
  Mermaid diagrams of how Wren fits, route selection, the import and export
  filters, and protocol state machines and sequences; the README gained an
  architecture diagram and a tighter quickstart and was shortened to link
  focused setup guides; Wren branding.
- The reference documents `blackhole` and `distance`, `set-next-hop` and
  VRRP's `address-interface`; the roadmap and README say what shipped.

### CI and release tooling

- crates.io release workflow: opt-in single-operator approval mode
  (`RELEASE_SINGLE_OPERATOR`); the two-person rule stays the default.
- CI enforces workspace formatting, runs the kernel route tests in isolation,
  and loads (and if needed installs) the `veth`, `dummy` and `vrf` modules the
  rootless smokes create; `actions/checkout` moved to v7.
- `scripts/bgp-aggregate-smoke.sh` tested nothing in two of its three phases:
  the aggregate block was written above `ebgp-require-policy`, and a
  `[[bgp.aggregate]]` header swallows every key after it. The key now precedes
  the block.
- `crates-release.yml` qualifies the standalone `wren-core` crate and publishes
  it only on an independently approved manual dispatch.
- Dependency updates: anyhow, clap, libc, serde, Tokio (1.54.1), toml (1.2)
  and base64 (0.23.1).

## [0.4.0] — 2026-08-01

A large release: EVPN grows a layer-3 half, IS-IS learns to authenticate, and a
standing audit of the link-state and BGP paths is closed out. Almost everything
under **Fixed** is a conformance bug found by reading the RFCs against the code
rather than by a failing test — the kind that only shows up against another
vendor's implementation, at three in the morning.

### Added

- **EVPN inter-subnet routing (RFC 9136 / 9135).** A tenant is no longer one
  broadcast domain: `[[evpn.ip_vrf]]` declares an IP-VRF, its subnets are
  originated as **type-5 IP Prefix** routes, and received type-5 routes are
  imported into that VRF's table. The **Router's MAC** extended community
  (RFC 9135) rides along, which is what lets a symmetric-IRB peer rewrite the
  inner destination MAC without an ARP for a host it will never see. Tenant
  prefixes are streamed to a forwarding data plane over the monitor API, so the
  anycast gateway is programmed from the routes rather than from a second copy
  of the configuration.
- **MAC Mobility, honoured rather than parsed (RFC 7432 §7.7).** A MAC that
  moves is accepted on sequence number, and a **sticky** MAC refuses to move at
  all — which is the whole point of marking one sticky.
- **IS-IS authentication, three ways.** Cleartext (ISO 10589 §9.8), **HMAC-MD5**
  (RFC 5304) and **HMAC-SHA-256** (RFC 5310). The two cryptographic modes differ
  in a way that is easy to get wrong and impossible to notice against yourself:
  RFC 5304 zeroes the digest field before computing, RFC 5310 fills it with the
  Apad constant. Both go through a single `encode_pdu` choke point, so a PDU
  type cannot be authenticated on one path and not on another. MD5 and
  HMAC-SHA-256 moved into `wren-core` rather than being carried per-protocol.
- **OSPFv3 authentication with an RFC 7166 HMAC trailer**, replacing the
  assumption that IPsec is there.
- **IS-IS three-way handshake on point-to-point links (RFC 5303).** Without it
  an adjacency can come up in one direction only, and the SPF then routes into
  a link that cannot answer.
- **BGP FlowSpec rules streamed to a forwarding data plane**, so a filter
  learned from a peer can be enforced by something other than wren.
- **Unknown transitive attributes are propagated with the Partial bit
  (RFC 7606 §8)** instead of being dropped, which is what lets a feature wren
  does not implement survive a hop through it.

### Fixed

- **Self-originated link state is refreshed and re-aged.** OSPF LSAs and IS-IS
  LSPs were originated once and then left; a neighbour that keeps its own timers
  correctly would age them out and remove the route, roughly half an hour after
  everything looked fine. IS-IS pseudonode LSPs had the same gap.
- **Flooding and database exchange, brought to the letter of RFC 2328** (v2 and
  v3): MinLSArrival on received LSAs (§13 step 5a), received-LSA checksum
  verification (§13 step 1), implied acknowledgments and send-back in the flood
  decision (§13.7-8), link-state **retransmission lists** (§13.5), resync on a
  Database Description sequence mismatch (§10.6), and the DD MTU check. Each of
  these is a way for two routers to disagree about the database and never
  converge.
- **ECMP is preserved across equal-cost transit networks (§16.1)**, and a
  prefix length is derived from a mask's **leading run** rather than by counting
  its bits — `255.255.0.255` is not a /24.
- **IS-IS: DIS re-election when an up neighbour's priority changes** (§8.4.5),
  **CSNPs fragmented to the link MTU** (§9.10), a maximum-metric link excluded
  from the SPF (RFC 5305 §3), zero-lifetime purge LSPs accepted without checksum
  verification, and a hold-time overflow.
- **BGP error handling per RFC 7606**, completed: attribute-length, duplicate
  and flags checks; wrong-length aggregate/originator attributes rejected;
  a malformed aggregate **discarded** rather than triggering a withdraw; the
  eBGP LOCAL_PREF filter and deterministic MED; and an unexpected message
  in-state treated as an FSM error (RFC 4271 §6.5).
- **The central BGP task can no longer be blocked by one slow peer.** A full
  send queue used to stall the task that feeds every other session — a
  self-inflicted denial of service that gets worse the more peers you have.
  A peer that will not drain is torn down instead.
- **ORIGINATOR_ID is used in the best-path tie-break**, and the ADD-PATH
  send-id table is bounded.
- **The authenticated BGP listener stays dual-stack**, so TCP-MD5/AO does not
  quietly cost you IPv6 sessions.
- **Multicast:** PIM Register checksums cover only the first 8 octets, the MFC
  incoming interface is programmed from the RPF result rather than from where
  the packet happened to arrive, IGMP/MLD carry the Router Alert option, and
  SSM sources are withdrawn on leave.
- **Bounded allocation** on the paths an attacker chooses the length of: OSPF
  LSU/Link-LSA decode, IGMP reports, and the RTR ROA set. AS 0 is rejected in
  an AS_PATH, and OSPF MD5 verification is constant-time.
- **Route deletion wildcards protocol and scope**, so a route wren did not
  install exactly the way it expects is still removed.

### Documentation

- EVPN is documented in the handbook.

## [0.3.1] — 2026-07-11

A bug-fix release: graceful shutdown now runs under an init system, not only on
an interactive Ctrl-C.

### Fixed

- **Graceful shutdown on `SIGTERM`, not just `SIGINT`.** The shutdown path — the
  protocol goodbyes (M10) and VRRP relinquishing mastership + releasing its
  virtual IP — previously fired only on `SIGINT`. `systemctl stop` (and container
  runtimes) send `SIGTERM`, which that path never caught, so the daemon was
  hard-killed and none of it ran. It now shuts down cleanly on either signal: a
  VRRP master stopped via systemd hands its virtual IP to the backup in about a
  second (a priority-0 advertisement) instead of waiting out the master-down
  timeout.

## [0.3.0] — 2026-07-07

Per-neighbour BGP session control, IPv6 BGP authentication, live configuration
reload, and **PIM-SM** sparse-mode multicast routing. A feature release with no
breaking API changes; every slice ships with unit tests and, where it touches the
wire, a rootless `unshare -Urn` smoke.

### BGP

- **Per-neighbour session options** — `local-as`, `update-source`,
  `ebgp-multihop`, `description`, `shutdown` and `hold-time`, configured per peer.
- **TCP-AO / TCP-MD5 over IPv6 transport** — the authenticated-session support
  that previously covered only IPv4 BGP now applies to IPv6 peers too (closing the
  0.2.0 deferred item).
- **Live neighbour hot-reload** — `SIGHUP` adds, removes and reconfigures BGP
  neighbours on a running daemon, without dropping the sessions that did not change.

### OSPF

- **OSPFv3 link-local next-hop fix** — pin the outgoing interface when the next hop
  is a link-local address, so IPv6 SPF routes install into the kernel FIB correctly
  on multi-interface routers.

### Multicast

- **PIM-SM sparse mode** (RFC 7761, static RP) — a new dependency-free
  **`wren-pim`** crate (wire codec, neighbour/Hello table and the `(*,G)`/`(S,G)`
  shared-/source-tree state machine) plus a daemon runner over a raw IP-protocol-103
  socket that programs the kernel multicast forwarding cache (`MRT_*`). Consumes the
  IGMP membership feed, delivering real inter-router multicast forwarding.

### Platform

- **Full-configuration `SIGHUP` hot-reload** — reload the whole running
  configuration live, starting with static routes and BGP neighbours, without
  restarting the daemon.
- **Fuzz targets** — libFuzzer targets for the newer wire parsers, run out of the
  standalone `fuzz/` cargo-fuzz workspace (E7).

## [0.2.0] — 2026-07-05

A broad Track-A expansion: BGP gains four new address families and route-leak
protection, **multicast** arrives (IGMP + MLD), and OSPF learns **graceful
restart**. Every slice ships with a rootless `unshare -Urn` smoke and unit tests.

### BGP

- **FlowSpec** (RFC 8955) — Flow Specification NLRI (AFI 1/2, SAFI 133) with a
  per-peer FlowSpec RIB, capability negotiation, `[bgp.flowspec]` rule
  origination (discard / rate-limit / mark), and `show bgp flowspec`.
- **SR Policy over BGP** (RFC 9256, SAFI 73) — the SR-Policy candidate model and
  wire codec (SAFI-73 NLRI + Tunnel Encapsulation attribute, RFC 9012, reusing
  the SRv6 SID structures), an SR-Policy RIB with best-candidate selection per
  `(colour, endpoint)`, and `show bgp sr-policy`.
- **BGP-LS** (RFC 7752, SAFI 71) — Link-State NLRI + BGP-LS Attribute codec
  (Node / Link / Prefix objects, loss-free TLVs incl. the SR TLVs), a Link-State
  RIB, static `[[bgp.link-state]]` origination, and `show bgp link-state`.
- **Routing security** — **eBGP default-deny** (RFC 8212, `ebgp-require-policy`)
  and **BGP roles + Only-To-Customer** (RFC 9234): role capability negotiation
  (Role Mismatch on conflict) and OTC ingress/egress procedures that stop
  provider→peer route leaks.

### Multicast (new)

- A new dependency-free **`wren-igmp`** crate speaking both families:
  **IGMPv3** (RFC 3376) over IPv4 and **MLDv2** (RFC 3810) over ICMPv6, sharing
  one address-generic §6 membership state machine and an **RFC 4605** upstream
  proxy.
- Daemon **querier runners** (raw IGMP / ICMPv6 sockets), a `[multicast]` config
  with per-family toggles, **querier election** (lowest-address wins) and §6.4
  **Last-Member-Query** fast-leave.

### OSPF

- **Graceful restart** (RFC 3623) — the opaque-LSA (RFC 5250) infrastructure, the
  **Grace-LSA** codec, **helper** mode (holds a neighbour's adjacency through its
  restart) and the **restarting** side (originate Grace-LSAs, preserve the FIB
  across the restart).
- **Cryptographic anti-replay** (RFC 2328 Appendix D) — reject replayed MD5
  packets whose sequence number regressed.
- **Passive interfaces** — advertise a subnet without forming adjacencies on it.

### BFD & IGP polish

- **BFD Echo over IPv6** (RFC 5880 §6.4), alongside the existing IPv4 echo.
- **IS-IS L1↔L2 route leaking** (RFC 5302 up/down bit).
- **RIP** and **Babel** register neighbours with the BFD engine for sub-second
  failure detection.

### Deferred

- The eBPF/XDP data-plane consumers of FlowSpec and SR Policy (flow
  classification / dataplane steering) — the BGP signalling is complete, the
  enforcement lives in the fabric data plane. Live IGP→BGP-LS export, TCP-AO/MD5
  for IPv6 transport, and gNMI/hot-reload remain on the roadmap.

## [0.1.0] — 2026-06-30

A large step up from the first release: BGP grows into a full-featured
implementation, **BFD** lands across every IGP, **VRFs** arrive, and the daemon
gains monitoring and a much wider operational surface. The data model now keys the
RIB and forwarding plane by `(table, prefix)`, the foundation for VRFs.

### BGP

- **MP-BGP for IPv6 unicast** (RFC 4760) end to end, with **link-local next hops**
  (RFC 2545) and route propagation (transit) between peers.
- **Extended Next Hop / IPv4-over-IPv6** (RFC 5549 / RFC 8950) and **fully
  unnumbered** sessions over IPv6 transport.
- **Route reflection** (RFC 4456) and **confederations** with `AS_CONFED_SEQUENCE`
  / `AS_CONFED_SET` path segments (RFC 5065).
- **Connection-collision detection** (RFC 4271 §6.8), **route refresh** (RFC 2918)
  and a **graceful-restart** helper (RFC 4724).
- **ADD-PATH** — multiple paths per destination (RFC 7911) — and **ECMP** install.
- **Address aggregation** (RFC 4271 §9.2.2.2), per-neighbour **default-originate**
  and a per-neighbour **maximum-prefix** limit (RFC 4486).
- Per-neighbour **inbound and outbound route filters**.
- Authentication: **TTL security / GTSM** (RFC 5082), **TCP-MD5** (RFC 2385) and
  **TCP-AO** (RFC 5925).
- **RPKI route-origin validation** (RFC 6811) fed by a live **RPKI-to-Router**
  (RTR) ROA feed (RFC 8210).
- **BMP** — stream BGP state to a monitoring station (RFC 7854).

### OSPF

- **Stub** and **totally-stubby** areas, **NSSA** and **totally-NSSA** areas with
  type-7 LSAs (RFC 2328 §3.6, RFC 3101), including injecting a type-7 default.
- Packet **authentication** — simple password and MD5 (RFC 2328 Appendix D).
- First live OSPFv3 verification.

### BFD (new)

- **Bidirectional Forwarding Detection** (RFC 5880 / RFC 5881) — single-hop
  asynchronous, **dual-stack** (IPv4 and IPv6), for sub-second failure detection.
- Drives **BGP, OSPFv2, OSPFv3 and IS-IS** adjacency teardown on a path failure
  (RFC 5882), far faster than the protocols' own timers.
- **Authentication** — Simple Password and Keyed/Meticulous MD5 & SHA-1 (RFC 5880
  §6.7), with **per-session keys** (e.g. a distinct password per BGP neighbour).

### VRFs (new)

- Named, isolated **routing tables**: the RIB and forwarding plane are keyed by
  `(table, prefix)`, so the same prefix can exist in several VRFs at once.
- `[[vrf]]` blocks with a **Route Distinguisher** (RFC 4364) identity and per-VRF
  **import/export route-maps**.
- **Static routes per VRF**, installed into the VRF's kernel table (rtnetlink
  `RTA_TABLE`), with per-table startup reconciliation; `wren show vrf`.

### Platform & operations

- **Cargo features** — each protocol can be compiled in or out for a slim build;
  BGP and the core are the always-on floor.
- **Prometheus metrics** over the existing control socket (`wren show metrics`).
- A wider operational surface: `show rip` / `show ripng`, `show ospf3`,
  `show babel [neighbors|routes]`, and `show ospf` / `show isis` **database**.

## [0.0.1] — 2026-06-28

The first public release. Wren is a small, RFC-correct routing daemon in Rust —
the job of BIRD/FRR, rebuilt with a dependency-free, embeddable core.

### Routing protocols

- **Static** routes and **connected** (direct) networks, tracked in the RIB and
  redistributable.
- **RIPv2** (RFC 2453) and **RIPng** (RFC 2080) over a shared distance-vector
  engine.
- **OSPFv2** (RFC 2328) — point-to-point and broadcast links, multi-area via an
  ABR, AS-external via an ASBR.
- **OSPFv3** (RFC 5340) — OSPF for IPv6, end to end.
- **IS-IS** (ISO/IEC 10589 + RFC 1195) — dual-stack wide metrics, L1/L2, the
  adjacency FSM, DIS election and SPF, over an `AF_PACKET` layer-2 runner.
- **BGP-4** (RFC 4271) — eBGP/iBGP over TCP 179, with **4-octet ASNs** (RFC 6793),
  **communities** (RFC 1997) and **large communities** (RFC 8092).
- **Babel** (RFC 8966) — loop-avoiding distance-vector over IPv6.

### Platform & policy

- **Netlink FIB backend** (Linux rtnetlink) with **ECMP / multipath** and
  startup route reconciliation.
- **Route filters** (BIRD-style import/export policy) with prefix patterns,
  protocol/metric matches, and metric/preference/community rewrites.
- **RIB-based redistribution** into every protocol, with optional per-protocol
  export filters.
- **Management interface**: a Unix control socket answering `wren show routes`,
  `show bgp [routes|neighbors]`, `show ospf [neighbors|interfaces]` and
  `show isis [neighbors|interfaces]`.

### Project

- **Open-core licensing**: the dependency-free `wren-core` is **Apache-2.0**
  (embeddable anywhere); the daemon and every other crate are
  **GPL-2.0-or-later** (like BIRD).
- An **mdBook handbook** under `docs/`, and rootless two-router convergence
  **smoke scripts** under `scripts/` (each runs in a throwaway `unshare -Urn`
  network namespace).

[0.3.0]: https://github.com/velstra/wren/releases/tag/v0.3.0
[0.2.0]: https://github.com/velstra/wren/releases/tag/v0.2.0
[0.1.0]: https://github.com/velstra/wren/releases/tag/v0.1.0
[0.0.1]: https://github.com/velstra/wren/releases/tag/v0.0.1
