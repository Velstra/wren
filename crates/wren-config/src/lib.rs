//! # wren-config — the declarative configuration
//!
//! Wren's configuration is a single TOML document. This crate is the model +
//! parser; it converts the textual config into validated [`wren_core`] types the
//! daemon installs.
//!
//! ```toml
//! router-id = "10.0.0.1"
//!
//! [[static]]
//! prefix = "0.0.0.0/0"
//! via = "192.0.2.1"
//!
//! [[static]]
//! prefix = "10.20.0.0/16"
//! dev = "eth1"
//! metric = 10
//!
//! [rip]
//! enabled = true
//! interfaces = ["eth1", "eth2"]
//! ```

#![forbid(unsafe_code)]

use std::fmt;
use std::net::{IpAddr, Ipv4Addr};
use std::path::Path;

use serde::Deserialize;
use wren_core::{NextHop, Prefix, Protocol, Route};

/// The whole appliance configuration.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// The router id (a 32-bit id, conventionally written as an IPv4 address).
    #[serde(rename = "router-id")]
    pub router_id: Option<String>,
    /// Operator-configured static routes.
    #[serde(default, rename = "static")]
    pub statics: Vec<StaticRoute>,
    /// VRF (Virtual Routing and Forwarding) instances — named isolated routing tables.
    #[serde(default, rename = "vrf")]
    pub vrfs: Vec<VrfDef>,
    /// RIP (IPv4) configuration, if the protocol is used.
    #[serde(default)]
    pub rip: Option<Rip>,
    /// RIPng (IPv6) configuration, if the protocol is used.
    #[serde(default)]
    pub ripng: Option<Ripng>,
    /// OSPFv2 configuration, if the protocol is used.
    #[serde(default)]
    pub ospf: Option<Ospf>,
    /// OSPFv3 (IPv6) configuration, if the protocol is used.
    #[serde(default)]
    pub ospf3: Option<Ospf3>,
    /// BGP-4 configuration, if the protocol is used.
    #[serde(default)]
    pub bgp: Option<Bgp>,
    /// Babel configuration, if the protocol is used.
    #[serde(default)]
    pub babel: Option<Babel>,
    /// IS-IS configuration, if the protocol is used.
    #[serde(default)]
    pub isis: Option<Isis>,
    /// Named route filters (BIRD-style import/export policy).
    #[serde(default, rename = "filter")]
    pub filters: Vec<FilterDef>,
    /// Per-protocol import filters: protocol name → filter name. The named filter
    /// is applied to every route that protocol announces, before it enters the RIB.
    #[serde(default)]
    pub import: std::collections::BTreeMap<String, String>,
    /// Export filters: applied to best-path routes leaving the RIB.
    #[serde(default)]
    pub export: Option<Export>,
    /// BFD (RFC 5880) timing defaults, shared by every session a protocol starts
    /// (currently the per-neighbour BGP sessions enabled with `bfd = true`).
    #[serde(default)]
    pub bfd: Option<Bfd>,
    /// VRRP (RFC 5798) virtual routers — first-hop redundancy / firewall HA.
    #[serde(default, rename = "vrrp")]
    pub vrrp: Vec<VrrpDef>,
    /// Multicast — the IGMP querier (RFC 3376) and IGMP proxy (RFC 4605), used for
    /// IPTV and other multicast behind the firewall.
    #[serde(default)]
    pub multicast: Option<Multicast>,
}

/// The `[multicast]` block: the IGMP querier and RFC 4605 proxy configuration.
///
/// ```toml
/// [multicast]
/// enabled = true
/// robustness = 2
/// query-interval = 125
///
/// # A LAN the router is the elected IGMP querier for.
/// [[multicast.interface]]
/// name = "lan0"
/// role = "querier"
///
/// # RFC 4605 proxy: pull streams from "wan0" for members seen on "lan0".
/// [[multicast.interface]]
/// name = "wan0"
/// role = "upstream"
/// [[multicast.interface]]
/// name = "lan0"
/// role = "downstream"
/// ```
#[derive(Debug, Clone, Default, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Multicast {
    /// Whether multicast (IGMP/MLD) is enabled.
    #[serde(default)]
    pub enabled: bool,
    /// Run the IGMP querier/proxy (IPv4). Defaults to true.
    pub igmp: Option<bool>,
    /// Run the MLDv2 querier/proxy (IPv6, RFC 3810) on the same interfaces/roles.
    /// Defaults to false.
    pub mld: Option<bool>,
    /// IGMP version to speak by default (2 or 3). Per-interface `igmp-version`
    /// overrides this. Defaults to 3.
    #[serde(rename = "igmp-version")]
    pub igmp_version: Option<u8>,
    /// The Robustness Variable (QRV), RFC 3376 §8.1. Defaults to 2.
    pub robustness: Option<u8>,
    /// The Query Interval in seconds, RFC 3376 §8.2. Defaults to 125.
    #[serde(rename = "query-interval")]
    pub query_interval: Option<u32>,
    /// The Query Response Interval (max response time) in seconds, §8.3. Defaults to 10.
    #[serde(rename = "query-response-interval")]
    pub query_response_interval: Option<u32>,
    /// The interfaces multicast runs on, each with a role.
    #[serde(default, rename = "interface")]
    pub interfaces: Vec<MulticastInterface>,
    /// PIM-SM (RFC 7761) sparse-mode inter-router multicast routing, static RP.
    /// When absent, only the IGMP/MLD querier + RFC 4605 proxy above run.
    #[serde(default)]
    pub pim: Option<Pim>,
}

/// The `[multicast.pim]` block: PIM-SM (RFC 7761) sparse mode with a statically
/// configured Rendezvous Point (BSR/Auto-RP are deferred). PIM runs the shared tree
/// `(*,G)` toward the RP and the source tree `(S,G)` toward a source, programming the
/// kernel multicast forwarding cache so multicast is routed between routers.
///
/// ```toml
/// [multicast.pim]
/// enabled = true
/// rp-address = "10.0.9.9"     # the static Rendezvous Point
/// interface = ["lan0", "wan0"]
/// ```
#[derive(Debug, Clone, Default, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Pim {
    /// Whether PIM-SM is enabled.
    #[serde(default)]
    pub enabled: bool,
    /// The statically configured Rendezvous Point address (the root of the shared
    /// tree). Required when `enabled`.
    #[serde(rename = "rp-address")]
    pub rp_address: Option<Ipv4Addr>,
    /// The interfaces PIM speaks on (sends Hello, Join/Prune; RPF candidates). Each
    /// must also be a multicast interface (typically a `querier`/`downstream` LAN and
    /// the transit link toward other PIM routers).
    #[serde(default, rename = "interface")]
    pub interfaces: Vec<String>,
    /// The Hello period in seconds (RFC 7761 §4.11). Defaults to 30.
    #[serde(rename = "hello-interval")]
    pub hello_interval: Option<u16>,
    /// The SPT-switchover threshold in kbps: an ASM `(*,G)` flow above this switches
    /// to the source tree. `0` means "switch on the first packet"; when unset the
    /// shared tree is kept (ASM SPT switchover deferred — see the `wren-pim` docs).
    #[serde(rename = "spt-threshold")]
    pub spt_threshold: Option<u32>,
}

/// One `[[multicast.interface]]`: an interface and the role it plays.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct MulticastInterface {
    /// The interface name.
    pub name: String,
    /// The role this interface plays. Defaults to `querier`.
    #[serde(default)]
    pub role: MulticastRole,
    /// IGMP version for this interface (2 or 3), overriding the `[multicast]`
    /// default. Unset inherits.
    #[serde(rename = "igmp-version")]
    pub igmp_version: Option<u8>,
}

/// The role a multicast interface plays.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum MulticastRole {
    /// Act as the IGMP querier on this LAN: send queries and track membership.
    #[default]
    Querier,
    /// The RFC 4605 proxy upstream interface: streams are pulled from here.
    Upstream,
    /// An RFC 4605 proxy downstream interface: membership here drives upstream joins.
    Downstream,
}

/// One VRRP virtual router (`[[vrrp]]`). Two or more routers sharing a `vrid` on a
/// link back the same `virtual-address`; the highest-priority one is master.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct VrrpDef {
    /// The interface the virtual router runs on.
    pub interface: String,
    /// Virtual Router ID (1–255), shared by every router backing this address.
    pub vrid: u8,
    /// This router's priority (1–254; 255 means it owns the address). Highest wins.
    #[serde(default = "default_vrrp_priority")]
    pub priority: u8,
    /// Advertisement interval in milliseconds (rounded to centiseconds on the wire).
    #[serde(default = "default_vrrp_advert_ms", rename = "advert-interval")]
    pub advert_interval_ms: u32,
    /// Whether to preempt a lower-priority master once we are available.
    #[serde(default = "default_true")]
    pub preempt: bool,
    /// The virtual IP address(es) this router backs (all IPv4 *or* all IPv6).
    #[serde(rename = "virtual-address")]
    pub virtual_addresses: Vec<String>,
    /// The interface the virtual address(es) live on, when that is *not* the
    /// interface the advertisements go out of. Unset means the same link.
    ///
    /// Two routers can agree on who is master over one link while the address
    /// they are arguing about sits on another — a design a firewall with many
    /// tagged segments arrives at quickly, because otherwise every segment needs
    /// its own virtual router and its own vrid. The election stays on the link
    /// that is guaranteed to be up between the pair; the address, the gratuitous
    /// ARP and the unsolicited neighbour advertisement all go where the hosts
    /// that use it can see them.
    #[serde(default, rename = "address-interface")]
    pub address_interface: Option<String>,
    /// The prefix length to assign each virtual address with. Defaults per family
    /// (24 for IPv4, 64 for IPv6) when unset.
    #[serde(default, rename = "prefix-length")]
    pub prefix_length: Option<u8>,
    /// Interfaces to track: if any of them is down, this router's effective
    /// priority drops by `priority-decrement`, so a peer with healthy uplinks can
    /// take over (e.g. track the WAN so a master with a failed uplink demotes).
    #[serde(default, rename = "track-interface")]
    pub track_interfaces: Vec<String>,
    /// How much to subtract from `priority` while a tracked interface is down.
    #[serde(default = "default_vrrp_decrement", rename = "priority-decrement")]
    pub priority_decrement: u8,
}

fn default_vrrp_priority() -> u8 {
    100
}
fn default_vrrp_advert_ms() -> u32 {
    1000
}
fn default_vrrp_decrement() -> u8 {
    50
}
fn default_true() -> bool {
    true
}

/// BFD (RFC 5880) global timing defaults (`[bfd]`). These apply to every BFD
/// session Wren brings up; per-session enablement is on the protocol side (a BGP
/// neighbour's `bfd = true`). Single-hop asynchronous mode.
#[derive(Debug, Clone, Default, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Bfd {
    /// Desired Min TX Interval in milliseconds — how fast we transmit Control
    /// packets once a session is Up. Defaults to 300.
    #[serde(rename = "min-tx")]
    pub min_tx: Option<u32>,
    /// Required Min RX Interval in milliseconds — the fastest we are willing to
    /// receive (the neighbour will not transmit faster than this). Defaults to 300.
    #[serde(rename = "min-rx")]
    pub min_rx: Option<u32>,
    /// Detect Mult — the session fails after this many missed receive intervals.
    /// Defaults to 3 (so detection ≈ `min-rx × 3`, e.g. 900 ms at the defaults).
    #[serde(rename = "detect-mult")]
    pub detect_mult: Option<u8>,
    /// Authentication type (RFC 5880 §6.7): `"simple"` (Simple Password),
    /// `"keyed-md5"`, `"meticulous-md5"`, `"keyed-sha1"` or `"meticulous-sha1"`.
    /// Unset (the default) runs sessions without authentication. Requires `auth-key`;
    /// the peer must use the same type and key.
    #[serde(rename = "auth-type")]
    pub auth_type: Option<String>,
    /// The authentication key id advertised on the wire (0–255). Defaults to 1.
    #[serde(rename = "auth-key-id")]
    pub auth_key_id: Option<u8>,
    /// The shared secret: the password (Simple) or keying material (digest types).
    /// Required when `auth-type` is set.
    #[serde(rename = "auth-key")]
    pub auth_key: Option<String>,
    /// Enable the Echo function (RFC 5880 §6.4) on every IPv4 session: looped-back Echo
    /// packets test the neighbour's forwarding plane directly, failing the session (with
    /// diagnostic Echo Function Failed) if they stop returning. The neighbour must have
    /// IP forwarding enabled. Defaults to false.
    #[serde(default)]
    pub echo: bool,
    /// The interval between transmitted Echo packets, in milliseconds (Echo detection
    /// ≈ `echo-interval × detect-mult`). Defaults to 100.
    #[serde(rename = "echo-interval")]
    pub echo_interval: Option<u32>,
}

/// Export filter attachments (`[export]`): which named filter gates routes on
/// their way out of the RIB to each consumer.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Export {
    /// The filter applied to best-path routes before they are programmed into the
    /// kernel forwarding table (BIRD's `kernel` protocol export filter).
    pub kernel: Option<String>,
    /// The filter applied to best-path routes before they are redistributed into
    /// BGP (the routes named by `[bgp] redistribute`). A rejected route is not
    /// originated; an accepted one may be rewritten first.
    pub bgp: Option<String>,
    /// The filter applied to best-path routes before they are redistributed into
    /// OSPF as AS-external LSAs (the routes named by `[ospf] redistribute`).
    pub ospf: Option<String>,
    /// The filter applied to best-path routes before they are redistributed into
    /// RIP (the routes named by `[rip] redistribute`).
    pub rip: Option<String>,
    /// The filter applied to best-path routes before they are redistributed into
    /// RIPng (the routes named by `[ripng] redistribute`).
    pub ripng: Option<String>,
    /// The filter applied to best-path routes before they are redistributed into
    /// Babel (the routes named by `[babel] redistribute`).
    pub babel: Option<String>,
    /// The filter applied to best-path routes before they are redistributed into
    /// IS-IS (the routes named by `[isis] redistribute`).
    pub isis: Option<String>,
}

/// One static route entry.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StaticRoute {
    /// Destination prefix (`addr/len`).
    pub prefix: String,
    /// Gateway address to forward via.
    pub via: Option<String>,
    /// Outgoing interface (for an on-link route, or to pin a gateway).
    pub dev: Option<String>,
    /// Route metric (lower wins). Defaults to 0.
    #[serde(default)]
    pub metric: u32,
    /// The VRF this route belongs to (a `[[vrf]]` name). Unset means the default VRF
    /// (the main table); a named VRF installs the route into that VRF's table.
    pub vrf: Option<String>,
    /// Discard what matches instead of forwarding it. A blackhole route takes no
    /// `via`/`dev` — having nowhere to send is the whole point — and is the
    /// standard way to null-route a prefix or to make a BGP summary stick
    /// without also announcing the more specifics inside it.
    #[serde(default)]
    pub blackhole: bool,
    /// Administrative distance, in the usual convention where **lower wins**.
    /// Unset ⇒ the protocol's own preference. Two routes to the same prefix from
    /// different sources are ranked by this, which is how a floating static
    /// route sits behind a learned one and only takes over when it goes away.
    pub distance: Option<u32>,
}

/// A Virtual Routing and Forwarding instance (`[[vrf]]`): a named, isolated routing
/// table. Routes and interfaces placed in the VRF use its kernel routing `table`, so
/// overlapping address space in different VRFs stays separate.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VrfDef {
    /// The VRF's name, referenced by `[[static]] vrf` and the VRF's interface list.
    pub name: String,
    /// The kernel routing table id this VRF programs its routes into.
    pub table: u32,
    /// The VRF's Route Distinguisher (RFC 4364, e.g. `"65000:1"`) — its identity.
    /// Optional; shown by `show vrf`.
    pub rd: Option<String>,
    /// Interfaces bound to this VRF: their connected routes go into the VRF's table.
    #[serde(default)]
    pub interfaces: Vec<String>,
    /// A named route filter (route-map) applied to routes as they enter this VRF.
    pub import: Option<String>,
    /// A named route filter (route-map) applied to routes leaving this VRF towards
    /// the kernel forwarding plane.
    pub export: Option<String>,
}

/// RIP protocol configuration.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rip {
    /// Whether RIP is enabled.
    #[serde(default)]
    pub enabled: bool,
    /// Interfaces RIP runs on.
    #[serde(default)]
    pub interfaces: Vec<String>,
    /// Protocols whose RIB best-path routes are redistributed into RIP and
    /// advertised to neighbours, dynamically as they appear and change, e.g.
    /// `["connected", "static", "ospf"]`. Only IPv4 routes are redistributed; an
    /// optional `[export] rip` filter gates them. RIP never redistributes its own
    /// routes.
    #[serde(default)]
    pub redistribute: Vec<String>,
    /// The RIP metric (1..=15) advertised for redistributed routes. Defaults to 1.
    #[serde(rename = "redistribute-metric")]
    pub redistribute_metric: Option<u32>,
    /// Run BFD (RFC 5880) to each RIP neighbour we forward through and expire its
    /// routes at once when BFD reports the path failed, rather than waiting for the
    /// 180-second route timeout. The neighbour is the gateway of the routes it
    /// advertised; timing comes from the global `[bfd]` defaults. Defaults to false.
    #[serde(default)]
    pub bfd: bool,
    /// The VRF this RIP instance runs in (a `[[vrf]]` name). Its learned and connected
    /// routes are installed into that VRF's kernel table; the interfaces should be
    /// enslaved to the VRF device. Unset runs RIP in the default VRF (main table).
    pub vrf: Option<String>,
}

/// RIPng (IPv6) protocol configuration.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Ripng {
    /// Whether RIPng is enabled.
    #[serde(default)]
    pub enabled: bool,
    /// Interfaces RIPng runs on.
    #[serde(default)]
    pub interfaces: Vec<String>,
    /// Protocols whose RIB best-path routes are redistributed into RIPng and
    /// advertised to neighbours, dynamically as they appear and change, e.g.
    /// `["connected", "static", "ospf3"]`. Only IPv6 routes are redistributed; an
    /// optional `[export] ripng` filter gates them. RIPng never redistributes its
    /// own routes.
    #[serde(default)]
    pub redistribute: Vec<String>,
    /// The RIPng metric (1..=15) advertised for redistributed routes. Defaults to 1.
    #[serde(rename = "redistribute-metric")]
    pub redistribute_metric: Option<u32>,
}

/// OSPFv2 protocol configuration.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Ospf {
    /// Whether OSPF is enabled.
    #[serde(default)]
    pub enabled: bool,
    /// Interfaces OSPF runs on (all placed in [`Ospf::area`]).
    #[serde(default)]
    pub interfaces: Vec<String>,
    /// The area these interfaces belong to (dotted, e.g. `"0.0.0.0"`). Defaults
    /// to the backbone `0.0.0.0` when unset.
    pub area: Option<String>,
    /// This router's priority for DR election on these interfaces (0 = never DR).
    /// Defaults to 1.
    #[serde(rename = "router-priority")]
    pub router_priority: Option<u8>,
    /// The output cost advertised for these interfaces. Defaults to 10.
    pub cost: Option<u16>,
    /// The network type of these interfaces: `"broadcast"` (default, elects a DR)
    /// or `"point-to-point"` (a direct link to one neighbour, no DR).
    #[serde(rename = "network-type")]
    pub network_type: Option<String>,
    /// Per-interface entries with their own area (for an area border router that
    /// has interfaces in several areas). Interfaces listed in [`Ospf::interfaces`]
    /// use [`Ospf::area`]; these override the area per interface.
    #[serde(default)]
    pub interface: Vec<OspfInterface>,
    /// Interfaces on which OSPF runs **passively**: their subnet is still advertised
    /// into the link-state database (as a stub link in this router's Router-LSA), but
    /// no Hellos are sent or processed on them, so no adjacency ever forms. Typical
    /// for edge/access links that carry no OSPF peers yet whose prefix should be
    /// reachable AS-wide. Each name here must also be an OSPF interface (listed in
    /// [`Ospf::interfaces`] or a `[[ospf.interface]]` entry).
    #[serde(default, rename = "passive-interfaces")]
    pub passive_interfaces: Vec<String>,
    /// Redistribute the configured static routes into OSPF as AS-external (type-5)
    /// LSAs (making this router an ASBR).
    #[serde(default, rename = "redistribute-static")]
    pub redistribute_static: bool,
    /// Protocols whose RIB best-path routes are redistributed into OSPF as
    /// AS-external (type-5) LSAs, dynamically as they appear and change, e.g.
    /// `["connected", "static", "bgp"]`. Only IPv4 routes are redistributed; an
    /// optional `[export] ospf` filter gates them. OSPF never redistributes its own
    /// routes. This is the RIB-based counterpart to `redistribute-static`.
    #[serde(default)]
    pub redistribute: Vec<String>,
    /// The external metric advertised for redistributed routes. Defaults to 20.
    #[serde(rename = "redistribute-metric")]
    pub redistribute_metric: Option<u32>,
    /// Areas configured as **stub** areas (RFC 2328 §3.6), listed by id (dotted
    /// quad, e.g. `["1.0.0.0"]`). A stub area carries no AS-external (type-5) LSAs;
    /// an area border router injects a default route into it instead. Stub routers
    /// clear the E-bit in their Hellos and only form adjacencies with neighbours
    /// that agree the area is a stub.
    #[serde(default, rename = "stub-areas")]
    pub stub_areas: Vec<String>,
    /// The metric an area border router advertises for the default route it injects
    /// into each stub area (the type-3 `0.0.0.0/0` summary). Defaults to 1.
    #[serde(rename = "stub-default-cost")]
    pub stub_default_cost: Option<u32>,
    /// Areas configured as **not-so-stubby** areas (NSSA, RFC 3101), listed by id.
    /// Like a stub an NSSA carries no AS-external (type-5) LSAs, but an ASBR inside
    /// it may originate type-7 LSAs that the area border router translates to type-5
    /// for the rest of the AS. An area may be a stub or an NSSA, not both.
    #[serde(default, rename = "nssa-areas")]
    pub nssa_areas: Vec<String>,
    /// Areas configured as **totally-stubby** ("no-summary" stub) areas, listed by
    /// id. Like a stub they carry no AS-external LSAs, and additionally the area
    /// border router suppresses inter-area (type-3) summaries, leaving only the
    /// injected default. An area listed here is treated as a stub.
    #[serde(default, rename = "totally-stubby-areas")]
    pub totally_stubby_areas: Vec<String>,
    /// Areas configured as **totally-NSSA** ("no-summary" NSSA) areas, listed by id.
    /// Like an NSSA they carry no type-5 LSAs and may hold type-7s, and additionally
    /// the area border router suppresses inter-area (type-3) summaries and injects a
    /// type-7 default route. An area listed here is treated as an NSSA.
    #[serde(default, rename = "totally-nssa-areas")]
    pub totally_nssa_areas: Vec<String>,
    /// Areas (plain NSSAs) into which the area border router additionally injects a
    /// type-7 default route (RFC 3101 §2.3), listed by id. Unlike a totally-NSSA the
    /// area keeps its inter-area (type-3) summaries; the default merely gives the
    /// area's internal routers a path to AS-external destinations the NSSA never
    /// carries. An area listed here is treated as an NSSA.
    #[serde(default, rename = "nssa-default-areas")]
    pub nssa_default_areas: Vec<String>,
    /// Packet authentication scheme (RFC 2328 §D), applied to every OSPF interface:
    /// `"none"` (the default), `"text"` for a simple cleartext password, or `"md5"`
    /// for a cryptographic keyed-MD5 digest. The peers on a link must agree.
    #[serde(rename = "auth-type")]
    pub auth_type: Option<String>,
    /// The shared authentication key — the cleartext password (≤ 8 bytes) for
    /// `auth-type = "text"`, or the secret (≤ 16 bytes) for `auth-type = "md5"`.
    #[serde(rename = "auth-key")]
    pub auth_key: Option<String>,
    /// The MD5 key identifier (`auth-type = "md5"` only), letting keys be rolled.
    /// Defaults to 1.
    #[serde(rename = "auth-key-id")]
    pub auth_key_id: Option<u8>,
    /// Enforce RFC 2328 §D.3 anti-replay for `auth-type = "md5"`: drop a received
    /// packet whose cryptographic sequence number is lower than the last accepted from
    /// that neighbour, so a captured packet cannot be replayed. Ignored for the other
    /// auth types. Defaults to true.
    #[serde(rename = "auth-replay-protection")]
    pub auth_replay_protection: Option<bool>,
    /// Seconds between Hellos on every OSPF interface (must match a neighbour's).
    /// Defaults to the RFC 2328 recommendation (10 s).
    #[serde(rename = "hello-interval")]
    pub hello_interval: Option<u16>,
    /// Seconds of silence after which a neighbour is declared down (must match a
    /// neighbour's; conventionally four Hello intervals). Defaults to 40 s.
    #[serde(rename = "dead-interval")]
    pub dead_interval: Option<u32>,
    /// Act as a graceful-restart (RFC 3623) **restarting** router: on a planned
    /// shutdown, flood a Grace-LSA asking neighbours to keep forwarding through the
    /// restart instead of tearing the adjacency down. Neighbours always act as helpers
    /// on receipt regardless of this flag. Defaults to false.
    #[serde(default, rename = "graceful-restart")]
    pub graceful_restart: bool,
    /// The grace period (seconds) advertised in the Grace-LSA — how long neighbours are
    /// asked to hold the adjacency while this router restarts. Defaults to 120.
    #[serde(rename = "graceful-restart-period")]
    pub graceful_restart_period: Option<u32>,
    /// Run a BFD (RFC 5880) session to each OSPF neighbour for fast failure
    /// detection. When a neighbour reaches Full, a BFD session is brought up to it;
    /// if BFD goes down the adjacency is torn down at once instead of waiting for the
    /// dead interval. Timing comes from the global `[bfd]` defaults. Defaults to
    /// false.
    #[serde(default)]
    pub bfd: bool,
    /// The VRF this OSPF instance runs in, named by a `[[vrf]]` block. Its sockets
    /// operate over the VRF's (enslaved) interfaces and every route it computes is
    /// installed into the VRF's kernel table instead of the main table. Unset runs
    /// OSPF in the default VRF (main table).
    pub vrf: Option<String>,
}

/// One OSPF interface placed in a specific area (`[[ospf.interface]]`).
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OspfInterface {
    /// The interface name.
    pub name: String,
    /// The area it belongs to (dotted quad); defaults to [`Ospf::area`].
    pub area: Option<String>,
}

/// OSPFv3 (IPv6) protocol configuration (`[ospf3]`, RFC 5340). Mirrors [`Ospf`],
/// but the interfaces are routed for IPv6 and it adds an Instance ID.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Ospf3 {
    /// Whether OSPFv3 is enabled.
    #[serde(default)]
    pub enabled: bool,
    /// Interfaces OSPFv3 runs on (all placed in [`Ospf3::area`]).
    #[serde(default)]
    pub interfaces: Vec<String>,
    /// The area these interfaces belong to (dotted quad, e.g. `"0.0.0.0"`).
    /// Defaults to the backbone `0.0.0.0` when unset.
    pub area: Option<String>,
    /// This router's priority for DR election on these interfaces (0 = never DR).
    /// Defaults to 1.
    #[serde(rename = "router-priority")]
    pub router_priority: Option<u8>,
    /// The output cost advertised for these interfaces. Defaults to 10.
    pub cost: Option<u16>,
    /// The network type of these interfaces: `"broadcast"` (default, elects a DR)
    /// or `"point-to-point"` (a direct link to one neighbour, no DR).
    #[serde(rename = "network-type")]
    pub network_type: Option<String>,
    /// The Instance ID — lets several OSPFv3 instances share one link (§2.11).
    /// Defaults to 0.
    #[serde(rename = "instance-id")]
    pub instance_id: Option<u8>,
    /// Per-interface entries with their own area (for an area border router that
    /// has interfaces in several areas). Reuses the [`OspfInterface`] shape.
    #[serde(default)]
    pub interface: Vec<OspfInterface>,
    /// Redistribute the configured static routes into OSPFv3 as AS-external LSAs
    /// (making this router an ASBR). Only IPv6 statics are redistributed.
    #[serde(default, rename = "redistribute-static")]
    pub redistribute_static: bool,
    /// The external metric advertised for redistributed routes. Defaults to 20.
    #[serde(rename = "redistribute-metric")]
    pub redistribute_metric: Option<u32>,
    /// Run BFD (RFC 5880) to each Full neighbour and tear the adjacency down at once
    /// when BFD reports the path failed (RFC 5882), rather than waiting for the dead
    /// interval. Requires a peer that also runs BFD; timing comes from `[bfd]`.
    #[serde(default)]
    pub bfd: bool,
    /// Packet authentication scheme (RFC 7166 Authentication Trailer), applied to
    /// every OSPFv3 interface: `"none"` (the default) or `"hmac-sha256"` for a
    /// keyed HMAC-SHA-256 digest. The peers on a link must agree. Unlike OSPFv2,
    /// OSPFv3 has no cleartext-password mode.
    #[serde(rename = "auth-type")]
    pub auth_type: Option<String>,
    /// The shared HMAC key (`auth-type = "hmac-sha256"`). Any length — it is fed
    /// straight into HMAC (keys longer than the 64-byte block are hashed first).
    #[serde(rename = "auth-key")]
    pub auth_key: Option<String>,
    /// The RFC 7166 Security Association identifier stamped into the trailer,
    /// letting keys be rolled. Defaults to 1.
    #[serde(rename = "auth-sa-id")]
    pub auth_sa_id: Option<u16>,
    /// Enforce RFC 7166 anti-replay: drop a received packet whose cryptographic
    /// sequence number is not greater than the last accepted from that neighbour,
    /// so a captured packet cannot be replayed. Defaults to true.
    #[serde(rename = "auth-replay-protection")]
    pub auth_replay_protection: Option<bool>,
}

/// BGP-4 protocol configuration (`[bgp]`).
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Bgp {
    /// Whether BGP is enabled.
    #[serde(default)]
    pub enabled: bool,
    /// This speaker's Autonomous System number (4-octet, RFC 6793).
    #[serde(rename = "local-as")]
    pub local_as: u32,
    /// This speaker's BGP Identifier (router id). Defaults to the top-level
    /// `router-id` when unset.
    #[serde(rename = "router-id")]
    pub router_id: Option<String>,
    /// The Hold Time proposed in OPEN, in seconds. Defaults to 180.
    #[serde(rename = "hold-time")]
    pub hold_time: Option<u16>,
    /// Networks this speaker originates (advertises) into BGP, as `addr/len`. Both
    /// IPv4 and IPv6 prefixes are accepted; the IPv6 ones are advertised via
    /// MP_REACH_NLRI (RFC 4760) and need `next-hop6` set.
    #[serde(default)]
    pub network: Vec<String>,
    /// The IPv6 next hop (next-hop-self) advertised for the IPv6 unicast NLRI this
    /// speaker originates or redistributes (RFC 4760). Required to advertise any
    /// IPv6 route; typically this router's global address on the peering link.
    #[serde(rename = "next-hop6")]
    pub next_hop6: Option<String>,
    /// This route reflector's CLUSTER_ID (RFC 4456), as a dotted quad. Defaults to
    /// the BGP `router-id` when unset; only relevant when any neighbor is a
    /// `route-reflector-client`.
    #[serde(rename = "cluster-id")]
    pub cluster_id: Option<String>,
    /// The Confederation Identifier (RFC 5065): the AS number this confederation
    /// presents to true external (eBGP) peers. When set, `local-as` is this
    /// router's **Member-AS** *within* the confederation, and a neighbour whose
    /// `remote-as` is listed in `confederation-members` is a confederation-internal
    /// (confed-eBGP) peer rather than a true external one. Unset means no
    /// confederation: `local-as` is the externally visible AS.
    #[serde(rename = "confederation-id")]
    pub confederation_id: Option<u32>,
    /// The Member-AS numbers of the *other* sub-ASes in this confederation
    /// (RFC 5065). A neighbour whose `remote-as` is in this list is a
    /// confederation-internal (confed-eBGP) peer; any other differing `remote-as`
    /// is a true external peer. Ignored when `confederation-id` is unset.
    #[serde(default, rename = "confederation-members")]
    pub confederation_members: Vec<u32>,
    /// COMMUNITIES (RFC 1997) attached to every originated route, as `asn:value`
    /// or a well-known name (`no-export`, `no-advertise`, `no-export-subconfed`).
    #[serde(default)]
    pub community: Vec<String>,
    /// LARGE_COMMUNITY (RFC 8092) tags attached to every originated route, as
    /// `global:local1:local2`.
    #[serde(default, rename = "large-community")]
    pub large_community: Vec<String>,
    /// EXTENDED_COMMUNITIES (RFC 4360) attached to every originated route, as
    /// `rt:asn:n` / `ro:asn:n` / `rt:ipv4:n`.
    #[serde(default, rename = "ext-community")]
    pub ext_community: Vec<String>,
    /// Protocols whose RIB best-path routes are redistributed into BGP (originated
    /// to peers as they appear and change), e.g. `["connected", "static", "ospf"]`.
    /// Only IPv4 routes are redistributed; an optional `[export] bgp` filter gates
    /// them. BGP never redistributes its own routes.
    #[serde(default)]
    pub redistribute: Vec<String>,
    /// The maximum number of equal-cost paths to install per destination as ECMP
    /// (BGP multipath). Unset or `1` is classic single-best-path forwarding; a
    /// higher value installs up to that many paths that tie on the decision
    /// attributes (same LOCAL_PREF, AS_PATH, ORIGIN, MED, eBGP/iBGP class, IGP cost).
    #[serde(rename = "multipath")]
    pub multipath: Option<usize>,
    /// Address aggregates (RFC 4271 §9.2.2.2): a covering prefix advertised whenever
    /// a more-specific, locally-originated/redistributed route falls inside it.
    #[serde(default, rename = "aggregate")]
    pub aggregate: Vec<BgpAggregate>,
    /// The configured peers.
    /// Static RPKI ROAs (Validated ROA Payloads, RFC 6811) to validate the origin of
    /// received routes against. Fetching them live over RTR (RFC 8210) is future work.
    #[serde(default, rename = "roa")]
    pub roa: Vec<BgpRoa>,
    /// Reject (drop, never enter the RIB) any received route that RPKI origin
    /// validation classifies as **Invalid** (RFC 6811). `Valid` and `NotFound` routes
    /// are always accepted. Defaults to false (validate and show, but accept all).
    #[serde(default, rename = "rpki-reject-invalid")]
    pub rpki_reject_invalid: bool,
    /// RFC 8212 strict default-deny for eBGP: when enabled, an eBGP neighbour with **no**
    /// explicit `import` policy accepts no routes, and one with no explicit `export`
    /// policy re-advertises no transit routes (locally-originated `network`/redistribute
    /// and `default-originate` routes are exempt, as are iBGP sessions). The RFC
    /// recommends this be on; wren defaults it **off** so existing configurations keep
    /// their current behaviour — set `true` to require a policy on every eBGP peer.
    #[serde(default, rename = "ebgp-require-policy")]
    pub ebgp_require_policy: bool,
    /// An RTR (RFC 8210) validating cache to fetch ROAs from live, instead of (or in
    /// addition to) the static `[[bgp.roa]]` entries. Unset disables RTR.
    pub rtr: Option<BgpRtr>,
    /// A BMP (RFC 7854) monitoring station to stream this speaker's BGP state to.
    /// Unset disables BMP.
    pub bmp: Option<BgpBmp>,
    /// The VRF this BGP instance runs in, named by a `[[vrf]]` block. Its session
    /// sockets bind to the VRF's L3 master device (`SO_BINDTODEVICE`) so the TCP
    /// connections to peers use the VRF's routing table, and every route it installs
    /// goes into the VRF's kernel table instead of the main table. Unset runs BGP in
    /// the default VRF (main table). This is a plain VRF, not an MPLS L3VPN.
    pub vrf: Option<String>,
    /// The configured peers.
    #[serde(default)]
    pub neighbor: Vec<BgpNeighbor>,
    /// EVPN address-family configuration (RFC 7432 over VXLAN, RFC 8365). Present
    /// enables originating this router's EVPN routes; the family is spoken only
    /// with neighbours that set `evpn = true`.
    pub evpn: Option<BgpEvpn>,
    /// FlowSpec address-family configuration (RFC 8955). Present enables originating
    /// this router's flow rules; the family is spoken only with neighbours that set
    /// `flowspec = true`.
    pub flowspec: Option<BgpFlowSpec>,
    /// SR Policies (RFC 9256) this speaker originates over BGP SR Policy (SAFI 73).
    /// Each is advertised as one candidate path to neighbours that set
    /// `srpolicy = true`.
    #[serde(default, rename = "srpolicy")]
    pub srpolicy: Vec<BgpSrPolicy>,
    /// Static BGP-LS (RFC 7752) Link-State objects this speaker originates over
    /// SAFI 71. Exporting the *live* OSPF/IS-IS topology into BGP-LS is future work;
    /// these static objects let a controller be fed a topology (and drive the smoke).
    /// Advertised to neighbours that set `link-state = true`.
    #[serde(default, rename = "link-state")]
    pub link_state: Vec<BgpLinkState>,
}

/// One `[[bgp.srpolicy]]`: an SR Policy candidate path this speaker originates
/// (RFC 9256). Advertised as a BGP SR Policy route (SAFI 73) with a Tunnel
/// Encapsulation attribute carrying the segment list.
#[derive(Debug, Clone, Default, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BgpSrPolicy {
    /// The policy colour — the intent a steering route's Color extended community
    /// matches against.
    pub color: u32,
    /// The policy endpoint (tail-end), an IPv4 or IPv6 address.
    pub endpoint: String,
    /// The candidate-path distinguisher (defaults to 1).
    pub distinguisher: Option<u32>,
    /// The candidate-path preference — higher wins (defaults to 100).
    pub preference: Option<u32>,
    /// The candidate's binding SID: an SRv6 SID (IPv6 address) or an MPLS label
    /// (a bare integer). Optional.
    #[serde(rename = "binding-sid")]
    pub binding_sid: Option<String>,
    /// The candidate-path priority (used on topology changes). Optional.
    pub priority: Option<u8>,
    /// A symbolic policy name. Optional.
    pub name: Option<String>,
    /// The ordered segment list — each entry an SRv6 SID (IPv6 address) or an MPLS
    /// label (a bare integer). Pushed onto steered packets in order.
    #[serde(default, rename = "segment-list")]
    pub segment_list: Vec<String>,
    /// The load-balancing weight for this segment list. Optional.
    pub weight: Option<u32>,
}

/// One `[[bgp.link-state]]`: a static BGP-LS object (RFC 7752) this speaker
/// originates — a Node, Link or Prefix, with the descriptors and attributes given.
#[derive(Debug, Clone, Default, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BgpLinkState {
    /// The object kind: `node`, `link` or `prefix`.
    #[serde(rename = "type")]
    pub kind: String,
    /// The IGP the object is attributed to: `ospf` (default), `ospfv3`, `isis-l1`,
    /// `isis-l2`, `direct` or `static`.
    pub protocol: Option<String>,
    /// The local node's IGP Router-ID (a dotted quad — an OSPF router-id).
    #[serde(rename = "router-id")]
    pub router_id: String,
    /// The local node's Autonomous System, if any.
    #[serde(rename = "as")]
    pub autonomous_system: Option<u32>,
    /// Node Name attribute (a `node` object).
    pub name: Option<String>,
    /// IGP Metric attribute (a `link` or `prefix` object).
    #[serde(rename = "igp-metric")]
    pub igp_metric: Option<u32>,
    /// Administrative Group / colour bitmask attribute (a `link` object).
    #[serde(rename = "admin-group")]
    pub admin_group: Option<u32>,
    /// The remote node's IGP Router-ID (a `link` object, a dotted quad).
    #[serde(rename = "remote-router-id")]
    pub remote_router_id: Option<String>,
    /// The link's local interface IPv4 address (a `link` object).
    #[serde(rename = "local-interface")]
    pub local_interface: Option<String>,
    /// The link's remote (neighbor) interface IPv4 address (a `link` object).
    #[serde(rename = "remote-interface")]
    pub remote_interface: Option<String>,
    /// The reachable prefix (a `prefix` object), as `addr/len`.
    pub prefix: Option<String>,
}

/// The `[bgp.evpn]` section: this VTEP's identity plus the EVPN instances
/// (MAC-VRFs) it participates in.
#[derive(Debug, Clone, Default, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BgpEvpn {
    /// This router's VTEP address: advertised as the BGP next hop of every EVPN
    /// route it originates and as the type-3 (IMET) originating router IP —
    /// remote PEs tunnel VXLAN traffic here.
    #[serde(rename = "vtep-ip")]
    pub vtep_ip: String,
    /// Optional SRv6 locator prefix (e.g. `"fc00:0:1::/48"`). When set, every EVPN
    /// route this VTEP originates carries an SRv6 L2 Service TLV (RFC 9252) — i.e.
    /// EVPN-over-SRv6 instead of plain VXLAN. Must be a byte-aligned IPv6 prefix of
    /// length 8..=96.
    #[serde(default, rename = "srv6-locator")]
    pub srv6_locator: Option<String>,
    /// The EVPN instances (one per MAC-VRF / VNI).
    #[serde(default)]
    pub instance: Vec<BgpEvpnInstance>,
    /// The tenant IP-VRFs (one per L3 VNI) for inter-subnet forwarding.
    #[serde(default, rename = "ip-vrf")]
    pub ip_vrf: Vec<BgpEvpnIpVrf>,
}

/// One `[[bgp.evpn.ip-vrf]]`: a tenant IP-VRF, the L3 context symmetric IRB routes
/// in (RFC 9136). It is a **separate entity from an instance**, not extra fields on
/// one: an IP-VRF carries its own Route Distinguisher and its own Route Targets,
/// which in a real deployment differ from the MAC-VRF's — several bridged VNIs
/// usually share one routed VNI. Type-5 IP Prefix routes are imported here.
#[derive(Debug, Clone, Default, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BgpEvpnIpVrf {
    /// A name for this IP-VRF, used in `show` output and diagnostics.
    pub name: String,
    /// The **L3** VNI this tenant routes in — the value stamped on type-5 routes
    /// and used to encapsulate inter-subnet traffic. Distinct from an instance's
    /// L2 VNI, which bridges within one subnet.
    #[serde(rename = "l3-vni")]
    pub l3_vni: u32,
    /// Route Distinguisher override, as `ip:value` or `asn:value`. Defaults to the
    /// auto-derived `router-id:l3-vni`.
    pub rd: Option<String>,
    /// Route Targets to import, in the `[[filter]]` ext-community syntax. Defaults
    /// to the auto-derived `rt:<local-as>:<l3-vni>`.
    #[serde(default, rename = "rt-import")]
    pub rt_import: Vec<String>,
    /// Route Targets to attach on export. Defaults like `rt-import`.
    #[serde(default, rename = "rt-export")]
    pub rt_export: Vec<String>,
    /// Local subnets to advertise as type-5 IP Prefix routes, each `addr/len`.
    /// These are the tenant's directly-attached networks; remote PEs route toward
    /// them through this VTEP's L3 VNI.
    #[serde(default, rename = "advertise-prefix")]
    pub advertise_prefix: Vec<String>,
    /// The MAC of this router's IRB interface in this tenant, as
    /// `aa:bb:cc:dd:ee:ff`. Advertised as the Router's MAC Extended Community
    /// (RFC 9135) so a remote PE knows which inner destination MAC to write when
    /// it encapsulates routed traffic toward us. Required alongside
    /// `advertise-prefix` under VXLAN — RFC 9136 §4.4.1: "The EVPN Router's MAC
    /// Extended Community must be sent if the route is associated with an
    /// Ethernet NVO tunnel". An SRv6 locator makes it optional: End.DT4/DT6
    /// decapsulates to an IP lookup with no inner Ethernet header to address.
    #[serde(default, rename = "router-mac")]
    pub router_mac: Option<String>,
}

/// One `[[bgp.evpn.instance]]`: an EVPN instance (EVI) bridging one VNI.
#[derive(Debug, Clone, Default, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BgpEvpnInstance {
    /// The EVPN instance identifier. Also the value of the auto-derived type-1
    /// Route Distinguisher `router-id:evi`.
    pub evi: u16,
    /// The VXLAN Network Identifier this instance bridges (24-bit).
    pub vni: u32,
    /// Route Distinguisher override, as `ip:value` or `asn:value`. Defaults to
    /// the auto-derived `router-id:evi`.
    pub rd: Option<String>,
    /// Route Targets to import, as `rt:asn:value` / `rt:ipv4:value` (the
    /// `[[filter]]` ext-community syntax). Defaults to the auto-derived
    /// `rt:<local-as>:<vni>` (RFC 7432 §7.10.1).
    #[serde(default, rename = "rt-import")]
    pub rt_import: Vec<String>,
    /// Route Targets to attach on export. Defaults like `rt-import`.
    #[serde(default, rename = "rt-export")]
    pub rt_export: Vec<String>,
    /// Local MACs to advertise as type-2 MAC/IP routes, each as
    /// `aa:bb:cc:dd:ee:ff` or `aa:bb:cc:dd:ee:ff/ip` (the IP feeds remote
    /// ARP/ND suppression). Dynamic learning arrives with the fabric bridge;
    /// static entries serve gateways and smoke tests.
    #[serde(default, rename = "advertise-mac")]
    pub advertise_mac: Vec<String>,
}

/// The `[bgp.flowspec]` section: the flow rules this speaker originates (RFC 8955).
/// Each rule is advertised to every neighbour with `flowspec = true`, its
/// traffic-filtering action riding as an extended community on the same UPDATE.
#[derive(Debug, Clone, Default, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BgpFlowSpec {
    /// The flow rules to originate.
    #[serde(default)]
    pub rule: Vec<BgpFlowSpecRule>,
}

/// One `[[bgp.flowspec.rule]]`: a flow specification (its match components) plus the
/// action to apply to matching traffic (RFC 8955 §4 + §7). Every component is
/// optional; an empty rule matches nothing and is rejected at resolution.
#[derive(Debug, Clone, Default, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BgpFlowSpecRule {
    /// Destination-prefix match (type 1), as `addr/len` (IPv4 only for now).
    pub dest: Option<String>,
    /// Source-prefix match (type 2), as `addr/len`.
    pub source: Option<String>,
    /// IP-protocol match (type 3): the set of protocol numbers (e.g. `[6]` for TCP).
    #[serde(default)]
    pub protocol: Vec<u16>,
    /// Port match (type 4): either source or destination port equals one of these.
    #[serde(default)]
    pub port: Vec<u16>,
    /// Destination-port match (type 5).
    #[serde(default, rename = "dest-port")]
    pub dest_port: Vec<u16>,
    /// Source-port match (type 6).
    #[serde(default, rename = "source-port")]
    pub source_port: Vec<u16>,
    /// The action for matching traffic (RFC 8955 §7): `"discard"`,
    /// `"rate-limit:<bytes-per-second>"` (a float; `0` is discard) or
    /// `"mark:<dscp>"`. Defaults to `"discard"`.
    pub action: Option<String>,
}

/// A BMP monitoring station to stream BGP state to (`[bgp.bmp]`, RFC 7854). Wren
/// connects out to the station and sends Initiation, then Peer Up / Route Monitoring
/// / Peer Down as sessions and routes change.
#[derive(Debug, Clone, Default, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BgpBmp {
    /// The station's `host:port` (the BMP port is conventionally 11019).
    pub station: String,
    /// The sysName reported in the Initiation message. Defaults to the router id.
    #[serde(rename = "sys-name")]
    pub sys_name: Option<String>,
    /// The sysDescr reported in the Initiation message. Defaults to `"wren"`.
    #[serde(rename = "sys-descr")]
    pub sys_descr: Option<String>,
}

/// An RTR validating cache to fetch RPKI ROAs from (`[bgp.rtr]`, RFC 8210).
#[derive(Debug, Clone, Default, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BgpRtr {
    /// The cache's `host:port` (the RTR port is conventionally 3323).
    pub server: String,
    /// The refresh interval in seconds (how often to Serial Query for the delta).
    /// Unset uses the interval the cache advertises in its End of Data.
    pub refresh: Option<u32>,
}

/// One static RPKI ROA (`[[bgp.roa]]`, RFC 6811): an authorisation that `origin_as`
/// may originate `prefix` and more-specifics within it up to `max-length`.
#[derive(Debug, Clone, Default, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BgpRoa {
    /// The authorised prefix, as `addr/len`.
    pub prefix: String,
    /// The longest prefix length the origin may announce within `prefix`. Defaults to
    /// the prefix's own length (an exact-match ROA).
    #[serde(rename = "max-length")]
    pub max_length: Option<u8>,
    /// The Autonomous System authorised to originate it (4-octet, RFC 6793).
    #[serde(rename = "origin-as")]
    pub origin_as: u32,
}

/// One BGP address aggregate (`[[bgp.aggregate]]`, RFC 4271 §9.2.2.2).
#[derive(Debug, Clone, Default, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BgpAggregate {
    /// The covering prefix to advertise, as `addr/len`.
    pub prefix: String,
    /// Suppress the contributing more-specifics, advertising only the aggregate.
    #[serde(default, rename = "summary-only")]
    pub summary_only: bool,
}

/// One BGP peer (`[[bgp.neighbor]]`).
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BgpNeighbor {
    /// The peer's IP address.
    pub address: String,
    /// The peer's Autonomous System number (eBGP if it differs from `local-as`),
    /// 4-octet (RFC 6793).
    #[serde(rename = "remote-as")]
    pub remote_as: u32,
    /// Override the speaker's Autonomous System for **this session only** (like FRR/IOS
    /// `neighbor X local-as`): the given AS is used as the My-AS in the OPEN we send this
    /// peer, in the eBGP/iBGP classification of the session (a peer whose `remote-as`
    /// equals it becomes iBGP), and — for an eBGP session — as the AS prepended to the
    /// AS_PATH of routes advertised to it, in place of the global `[bgp] local-as`. A
    /// simple *full replacement* of the session AS; the FRR `no-prepend` / `replace-as`
    /// refinements are not modelled (a plain override always fully replaces). Unset uses
    /// the global `[bgp] local-as`.
    #[serde(rename = "local-as")]
    pub local_as: Option<u32>,
    /// Whether to wait for the peer to connect rather than initiating the TCP
    /// connection ourselves. Defaults to false (we actively connect).
    #[serde(default)]
    pub passive: bool,
    /// Bind the outgoing TCP connection to this **source address** before dialling the
    /// peer (like FRR/IOS `neighbor X update-source`) — for example a loopback used as a
    /// stable session endpoint. Its address family must match the neighbour's: an IPv4
    /// neighbour needs an IPv4 source, an IPv6 neighbour an IPv6 source. Applies only to
    /// the connection we initiate (not a `passive` peer's inbound one). Unset lets the
    /// kernel pick the source per the outgoing route.
    #[serde(rename = "update-source")]
    pub update_source: Option<String>,
    /// The session IP TTL for a **multihop eBGP** peer (RFC-style `ebgp-multihop`), 1–255:
    /// a non-directly-connected eBGP neighbour is reached over several hops, so the
    /// session packets are sent with this TTL instead of the default. Mutually exclusive
    /// with `ttl-security` (GTSM) — the two use opposite TTL disciplines, so configuring
    /// both on one neighbour is a configuration error (RFC 5082 practice). Unset leaves
    /// the system default TTL.
    #[serde(rename = "ebgp-multihop")]
    pub ebgp_multihop: Option<u8>,
    /// A free-form label for this neighbour, shown in `show bgp neighbors`. Purely
    /// descriptive; it has no effect on the session. Unset shows no description.
    pub description: Option<String>,
    /// Administratively shut this neighbour **down**: Wren never initiates a session to
    /// it and refuses any inbound connection from it, and it is shown as
    /// `admin-shutdown` in `show bgp neighbors`. Clearing it (back to the default false)
    /// re-enables the session. Defaults to false.
    #[serde(default)]
    pub shutdown: bool,
    /// The Hold Time (seconds) proposed in the OPEN to **this** peer, overriding the
    /// global `[bgp] hold-time` for this session; the KeepAlive interval is derived from
    /// the negotiated hold time as usual (a third of it). 0 disables the Hold and
    /// KeepAlive timers for the session (RFC 4271 §4.2). Unset uses the global default.
    #[serde(rename = "hold-time")]
    pub hold_time: Option<u16>,
    /// Whether this (iBGP) peer is a **route-reflector client** (RFC 4456): routes
    /// learned from it are reflected to all other iBGP peers, and routes from other
    /// iBGP peers are reflected to it. Ignored for eBGP peers. Defaults to false.
    #[serde(default, rename = "route-reflector-client")]
    pub route_reflector_client: bool,
    /// Enable the Generalized TTL Security Mechanism (GTSM, RFC 5082) for this peer,
    /// giving the **maximum number of hops** to the peer (1 for a directly-connected
    /// eBGP neighbour). Wren then sends with IP TTL 255 and rejects any received
    /// packet whose TTL is below `255 − (hops − 1)`, so an off-path attacker more than
    /// `hops` away cannot inject into the session. Unset disables GTSM.
    #[serde(rename = "ttl-security")]
    pub ttl_security: Option<u8>,
    /// A TCP-MD5 signature password (RFC 2385) for this peer's session. When set, Wren
    /// installs the key on the connection (via `TCP_MD5SIG`) so the kernel signs every
    /// segment it sends and rejects any received segment whose signature does not
    /// match — a spoofed packet without the shared key cannot disturb the session. The
    /// peer must be configured with the same password. Up to 80 bytes. Unset disables
    /// authentication. Mutually exclusive with `ao-key`.
    pub password: Option<String>,
    /// A TCP-AO (RFC 5925) master key for this peer's session — the modern successor to
    /// TCP-MD5, with HMAC-SHA-1 and per-connection traffic keys. When set, Wren installs
    /// the key on the connection (via `TCP_AO_ADD_KEY`) before the handshake; the kernel
    /// then authenticates every segment with HMAC-SHA-1-96. The peer must share the same
    /// key and key id. Up to 80 bytes. Mutually exclusive with `password`; requires a
    /// kernel with `CONFIG_TCP_AO` (Linux 5.18+).
    #[serde(rename = "ao-key")]
    pub ao_key: Option<String>,
    /// The TCP-AO key id, used as both the SendID and the RecvID (RFC 5925 §3.1), so the
    /// two peers must configure the same value. Defaults to 100. Ignored without `ao-key`.
    #[serde(rename = "ao-key-id")]
    pub ao_key_id: Option<u8>,
    /// The maximum number of prefixes to accept from this peer (RFC 4486 §4). When the
    /// peer advertises more, Wren tears the session down with a Cease "Maximum Number of
    /// Prefixes Reached" and keeps it down. Unset (or 0) means no limit.
    #[serde(rename = "max-prefix")]
    pub max_prefix: Option<u32>,
    /// Advertise a default route (`0.0.0.0/0`) to this peer unconditionally — regardless
    /// of whether Wren itself has a default — with this router as the next hop. Common on
    /// the upstream edge toward a stub customer. Defaults to false.
    #[serde(default, rename = "default-originate")]
    pub default_originate: bool,
    /// Negotiate ADD-PATH (RFC 7911) with this neighbour for IPv4 unicast: advertise
    /// the ability to both send and receive multiple paths per destination. When the
    /// peer also supports it, Wren keeps every path the peer sends (rather than the
    /// second overwriting the first) and advertises all of its candidate paths to the
    /// peer (rather than only the single best). Defaults to false.
    #[serde(default, rename = "add-path")]
    pub add_path: bool,
    /// Negotiate Extended Next Hop Encoding (RFC 5549 / RFC 8950) with this neighbour:
    /// advertise the ability to exchange IPv4 unicast routes with an IPv6 next hop.
    /// When set (and the peer agrees) and a `[bgp] next-hop6` is configured, IPv4
    /// routes are advertised to this peer with that IPv6 next hop, and received IPv4
    /// routes with an IPv6 next hop are installed via that gateway (kernel RTA_VIA).
    /// Defaults to false.
    #[serde(default, rename = "extended-nexthop")]
    pub extended_nexthop: bool,
    /// Negotiate the EVPN address family (AFI 25 / SAFI 70, RFC 7432) with this
    /// neighbour: exchange EVPN routes for the instances configured under
    /// `[bgp.evpn]`. Defaults to false.
    #[serde(default)]
    pub evpn: bool,
    /// Negotiate the FlowSpec address family (AFI 1/2 · SAFI 133, RFC 8955) with this
    /// neighbour: exchange the flow rules configured under `[bgp.flowspec]`, and
    /// install the ones this neighbour advertises. Defaults to false.
    #[serde(default)]
    pub flowspec: bool,
    /// Negotiate the SR Policy address family (AFI 1/2 · SAFI 73, RFC 9256) with this
    /// neighbour: advertise the `[[bgp.srpolicy]]` policies to it, and install the SR
    /// Policies it advertises into the SR Policy RIB. Defaults to false.
    #[serde(default)]
    pub srpolicy: bool,
    /// Negotiate the BGP-LS address family (AFI 16388 · SAFI 71, RFC 7752) with this
    /// neighbour: advertise the static `[[bgp.link-state]]` objects to it, and install
    /// the Link-State objects it advertises into the BGP-LS RIB. Defaults to false.
    #[serde(default, rename = "link-state")]
    pub link_state: bool,
    /// Inbound route policy: the name of a `[[filter]]` applied to every route received
    /// from this neighbour before it enters the RIB (an import route-map). Reject drops
    /// the route; accept admits it, with any set-metric (→MED), set-preference
    /// (→LOCAL_PREF) or set-community modifications applied. Unset accepts everything.
    pub import: Option<String>,
    /// Outbound route policy: the name of a `[[filter]]` applied to every route this
    /// router advertises to this neighbour (an export route-map) — both originated and
    /// propagated transit routes. Reject suppresses the advertisement; accept sends it
    /// with any set-community (and, for transit routes, set-metric/set-preference)
    /// modifications applied. Unset advertises everything.
    pub export: Option<String>,
    /// This local speaker's BGP Role toward this neighbour (RFC 9234 §4), one of
    /// `provider`, `customer`, `peer`, `rs-server` or `rs-client`. It is advertised in
    /// the Role capability and must be the complement of the peer's role (Provider ↔
    /// Customer, RS-Server ↔ RS-Client, Peer ↔ Peer) or the session is refused with a
    /// Role Mismatch. Once set, the Only-To-Customer (OTC) route-leak procedures (§5)
    /// apply to routes exchanged with this neighbour. Unset disables roles/OTC for it.
    pub role: Option<String>,
    /// Run a BFD (RFC 5880) session to this neighbour for fast failure detection.
    /// When the BFD session goes down, the BGP session to this peer is torn down at
    /// once instead of waiting for the Hold Timer. Timing comes from the global
    /// `[bfd]` defaults. Defaults to false.
    #[serde(default)]
    pub bfd: bool,
    /// Per-neighbour BFD authentication type, overriding the global `[bfd]` key for
    /// this peer's session (so different peers can use different passwords). One of
    /// `simple`, `keyed-md5`, `meticulous-md5`, `keyed-sha1`, `meticulous-sha1`.
    /// Unset inherits the global `[bfd]` authentication (if any).
    #[serde(rename = "bfd-auth-type")]
    pub bfd_auth_type: Option<String>,
    /// The wire key id for this neighbour's BFD authentication (default 1).
    #[serde(rename = "bfd-auth-key-id")]
    pub bfd_auth_key_id: Option<u8>,
    /// The shared secret for this neighbour's BFD authentication. Required when
    /// `bfd-auth-type` is set on the neighbour.
    #[serde(rename = "bfd-auth-key")]
    pub bfd_auth_key: Option<String>,
}

/// Babel protocol configuration (`[babel]`, RFC 8966).
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Babel {
    /// Whether Babel is enabled.
    #[serde(default)]
    pub enabled: bool,
    /// Interfaces Babel runs on.
    #[serde(default)]
    pub interfaces: Vec<String>,
    /// Networks this router originates into Babel beyond its connected ones, as
    /// `addr/len`.
    #[serde(default)]
    pub network: Vec<String>,
    /// The 8-octet Router-ID, given as a dotted quad (packed into the low four
    /// octets). Defaults to the top-level `router-id` when unset.
    #[serde(rename = "router-id")]
    pub router_id: Option<String>,
    /// Protocols whose RIB best-path routes are redistributed into Babel and
    /// originated to neighbours (under our Router-ID), dynamically as they appear
    /// and change, e.g. `["connected", "static", "ospf3"]`. Babel is dual-stack,
    /// so both IPv4 and IPv6 routes are carried; an optional `[export] babel`
    /// filter gates them. Babel never redistributes its own routes.
    #[serde(default)]
    pub redistribute: Vec<String>,
    /// The Babel metric advertised for redistributed routes (the metric "at the
    /// source"). Defaults to 0, like a directly-originated network.
    #[serde(rename = "redistribute-metric")]
    pub redistribute_metric: Option<u16>,
    /// Run BFD (RFC 5880) to each Babel neighbour and expire the neighbour at once
    /// when BFD reports the path failed, rather than waiting for the Hello-timeout.
    /// The neighbour's address is its (link-local) source address; timing comes from
    /// the global `[bfd]` defaults. Defaults to false.
    #[serde(default)]
    pub bfd: bool,
    /// The VRF this Babel instance runs in, named by a `[[vrf]]` block. Its sockets
    /// operate over the VRF's (enslaved) interfaces and every route it computes is
    /// installed into the VRF's kernel table instead of the main table. Unset runs
    /// Babel in the default VRF (main table).
    pub vrf: Option<String>,
}

/// IS-IS protocol configuration (`[isis]`, ISO/IEC 10589 + RFC 1195).
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Isis {
    /// Whether IS-IS is enabled.
    #[serde(default)]
    pub enabled: bool,
    /// Interfaces IS-IS runs on.
    #[serde(default)]
    pub interfaces: Vec<String>,
    /// This router's 6-byte System ID as three dotted 16-bit groups, e.g.
    /// `"1921.6800.1001"`. Defaults to one derived from the top-level `router-id`.
    #[serde(rename = "system-id")]
    pub system_id: Option<String>,
    /// The area address as hex (dots ignored), e.g. `"49.0001"`. Defaults to
    /// `"49.0000"`.
    pub area: Option<String>,
    /// The level(s) this router runs: `"l1"`, `"l2"` or `"l1l2"` (default).
    pub level: Option<String>,
    /// This router's DIS-election priority (0–127). Defaults to 64.
    pub priority: Option<u8>,
    /// The metric advertised for each interface's links. Defaults to 10.
    pub metric: Option<u32>,
    /// HelloInterval in seconds. Defaults to 10.
    #[serde(rename = "hello-interval")]
    pub hello_interval: Option<u64>,
    /// The network type of these interfaces: `"broadcast"` (default, elects a DIS)
    /// or `"point-to-point"`.
    #[serde(rename = "network-type")]
    pub network_type: Option<String>,
    /// Protocols whose RIB best-path routes are redistributed into IS-IS and
    /// advertised as IP/IPv6 reachability in our own LSP, dynamically as they
    /// appear and change, e.g. `["connected", "static", "bgp"]`. Both IPv4 and IPv6
    /// routes are carried; an optional `[export] isis` filter gates them. IS-IS
    /// never redistributes its own routes.
    #[serde(default)]
    pub redistribute: Vec<String>,
    /// The metric advertised for redistributed routes. Defaults to the interface
    /// `metric`.
    #[serde(rename = "redistribute-metric")]
    pub redistribute_metric: Option<u32>,
    /// Leak Level-2 (backbone) prefixes down into this router's Level-1 area (RFC
    /// 5302), advertised with the up/down bit set so no other L1L2 router leaks them
    /// back up into L2. Only an `l1l2` router leaks; the reverse direction (L1
    /// intra-area prefixes up into L2) is always on. Defaults to false.
    #[serde(default, rename = "l2-to-l1-leaking")]
    pub l2_to_l1_leaking: bool,
    /// Run BFD (RFC 5880) to each neighbour with an up adjacency and tear the
    /// adjacency down at once when BFD reports the path failed (RFC 5882), rather
    /// than waiting for the holding time. The neighbour's IP comes from the IP
    /// Interface Address TLV in its Hellos; timing comes from `[bfd]`.
    #[serde(default)]
    pub bfd: bool,
    /// The VRF this IS-IS instance runs in, named by a `[[vrf]]` block. Its sockets
    /// operate over the VRF's (enslaved) interfaces and every route it computes is
    /// installed into the VRF's kernel table instead of the main table. Unset runs
    /// IS-IS in the default VRF (main table).
    pub vrf: Option<String>,
    /// A cleartext authentication password (ISO 10589 §9.8 / RFC 1195). When set,
    /// every PDU we send carries an Authentication TLV with this password and every
    /// PDU we receive must carry a matching one, or it is dropped — so an on-link
    /// attacker cannot form adjacencies or inject LSPs. Unset ⇒ no authentication.
    /// Equivalent to `auth-type = "text"` with this string as `auth-key`.
    pub password: Option<String>,
    /// Packet authentication scheme: `"text"` for the cleartext password above,
    /// `"hmac-md5"` for RFC 5304, or `"hmac-sha256"` for the Generic Cryptographic
    /// Authentication of RFC 5310. Prefer a keyed scheme: a cleartext password is
    /// visible to anyone who can observe the link and can be replayed, whereas the
    /// HMAC signs the encoded PDU. `"hmac-md5"` is the older and weaker of the two,
    /// but it is what most other vendors default to. Unset (the default) falls back
    /// to `password`.
    #[serde(rename = "auth-type")]
    pub auth_type: Option<String>,
    /// The shared secret — the password (`"text"`) or the HMAC key (either keyed
    /// scheme, any length). Required when `auth-type` is set; falls back to
    /// `password`.
    #[serde(rename = "auth-key")]
    pub auth_key: Option<String>,
    /// The Key ID advertised in the clear alongside the digest (`"hmac-sha256"`
    /// only, RFC 5310 §3.1), so keys can be rolled without an outage. Defaults to 1.
    /// RFC 5304 has no Key ID, so `"hmac-md5"` ignores this.
    #[serde(rename = "auth-key-id")]
    pub auth_key_id: Option<u16>,
}

/// A named route filter (`[[filter]]`): an ordered list of rules plus a default
/// action. Compiled by the daemon into a `wren_filter::Filter`.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FilterDef {
    /// The filter's name, referenced from `[import]`.
    pub name: String,
    /// The action when no rule matches: `"accept"` (default) or `"reject"`.
    pub default: Option<String>,
    /// The rules, evaluated in order (first match wins).
    #[serde(default)]
    pub rule: Vec<FilterRule>,
}

/// One rule of a [`FilterDef`] (`[[filter.rule]]`). Conditions present are ANDed;
/// `set-*`/`add-metric` modify a matching route before `action` is taken.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FilterRule {
    /// Prefix patterns (any-match), e.g. `["10.0.0.0/8+", "192.168.0.0/16{24,32}"]`.
    #[serde(default)]
    pub prefix: Vec<String>,
    /// Match this protocol name (`connected`/`static`/`rip`/`ospf`/`isis`/`babel`/
    /// `bgp`/`kernel`).
    pub protocol: Option<String>,
    /// The route's metric must be ≤ this.
    #[serde(rename = "metric-le")]
    pub metric_le: Option<u32>,
    /// The route's metric must be ≥ this.
    #[serde(rename = "metric-ge")]
    pub metric_ge: Option<u32>,
    /// Set the matching route's metric to this.
    #[serde(rename = "set-metric")]
    pub set_metric: Option<u32>,
    /// Add this signed delta to the matching route's metric.
    #[serde(rename = "add-metric")]
    pub add_metric: Option<i64>,
    /// Set the matching route's administrative preference to this.
    #[serde(rename = "set-preference")]
    pub set_preference: Option<u32>,
    /// Send the matching route via this address instead of wherever it said.
    /// Either family: an IPv4 route via an IPv6 next hop is RFC 5549.
    #[serde(rename = "set-next-hop")]
    pub set_next_hop: Option<String>,
    /// Replace the matching route's communities with these (`asn:value` or a
    /// well-known name like `no-export`). Consumed by BGP origination.
    #[serde(rename = "set-community")]
    pub set_community: Option<Vec<String>>,
    /// Append these communities to the matching route (`asn:value` or a
    /// well-known name), after any `set-community`.
    #[serde(rename = "add-community", default)]
    pub add_community: Vec<String>,
    /// Replace the matching route's large communities with these
    /// (`global:local1:local2`, RFC 8092). Consumed by BGP origination.
    #[serde(rename = "set-large-community")]
    pub set_large_community: Option<Vec<String>>,
    /// Append these large communities to the matching route, after any
    /// `set-large-community`.
    #[serde(rename = "add-large-community", default)]
    pub add_large_community: Vec<String>,
    /// Replace the matching route's extended communities with these (`rt:asn:n`,
    /// `ro:asn:n`, `rt:ipv4:n`, …; RFC 4360). Consumed by BGP origination.
    #[serde(rename = "set-ext-community")]
    pub set_ext_community: Option<Vec<String>>,
    /// Append these extended communities to the matching route, after any
    /// `set-ext-community`.
    #[serde(rename = "add-ext-community", default)]
    pub add_ext_community: Vec<String>,
    /// Whether a matching route is `"accept"`ed or `"reject"`ed.
    pub action: String,
}

/// Why a configuration could not be loaded or resolved.
#[derive(Debug, Clone)]
pub enum ConfigError {
    /// The file could not be read.
    Io(String),
    /// The TOML did not parse / had unknown keys.
    Toml(String),
    /// A field held an invalid value (e.g. an unparsable prefix).
    Invalid(String),
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConfigError::Io(e) => write!(f, "reading config: {e}"),
            ConfigError::Toml(e) => write!(f, "parsing config: {e}"),
            ConfigError::Invalid(e) => write!(f, "invalid config: {e}"),
        }
    }
}

impl std::error::Error for ConfigError {}

impl Config {
    /// Parse and (lightly) validate a config from TOML text.
    pub fn from_toml(text: &str) -> Result<Self, ConfigError> {
        let cfg: Config = toml::from_str(text).map_err(|e| ConfigError::Toml(e.to_string()))?;
        // Surface obvious errors early rather than at install time.
        let _ = cfg.static_routes()?;
        Ok(cfg)
    }

    /// Read and parse a config file.
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| ConfigError::Io(format!("{}: {e}", path.display())))?;
        Self::from_toml(&text)
    }

    /// Resolve the static routes into core [`Route`]s.
    pub fn static_routes(&self) -> Result<Vec<Route>, ConfigError> {
        let mut out = Vec::with_capacity(self.statics.len());
        for s in &self.statics {
            let prefix: Prefix = s
                .prefix
                .parse()
                .map_err(|e| ConfigError::Invalid(format!("static prefix {:?}: {e}", s.prefix)))?;
            // A discard route carries no next-hop at all: the FIB installs a
            // route with an empty next-hop list as the kernel's own blackhole
            // type, so "nowhere to send" needs no second way of saying it.
            let nexthops = if s.blackhole {
                if s.via.is_some() || s.dev.is_some() {
                    return Err(ConfigError::Invalid(format!(
                        "static route {prefix} is a blackhole and cannot also have a next-hop"
                    )));
                }
                Vec::new()
            } else {
                vec![match (&s.via, &s.dev) {
                (Some(via), dev) => {
                    let gw: IpAddr = via.parse().map_err(|_| {
                        ConfigError::Invalid(format!("static via {via:?} is not an IP address"))
                    })?;
                    match dev {
                        Some(d) => NextHop::via_dev(gw, d.clone()),
                        None => NextHop::via(gw),
                    }
                }
                (None, Some(dev)) => NextHop::dev(dev.clone()),
                (None, None) => {
                    return Err(ConfigError::Invalid(format!(
                        "static route {prefix} needs `via`, `dev` or `blackhole`"
                    )))
                }
                }]
            };
            let mut route = Route::new(prefix, Protocol::Static, nexthops, s.metric);
            // Distance counts down where preference counts up, so a smaller
            // distance has to become a larger preference. 255 is the widest
            // administrative distance anyone writes, which makes it the mirror.
            if let Some(d) = s.distance {
                if d > 255 {
                    return Err(ConfigError::Invalid(format!(
                        "static route {prefix} distance {d}: 0-255"
                    )));
                }
                route.preference = 255 - d;
            }
            // Place the route in its VRF's table, if it names one.
            if let Some(vrf) = &s.vrf {
                let table = self.vrf_table(vrf).ok_or_else(|| {
                    ConfigError::Invalid(format!(
                        "static route {prefix} references unknown vrf {vrf:?}"
                    ))
                })?;
                route = route.with_table(table);
            }
            out.push(route);
        }
        Ok(out)
    }

    /// The kernel routing table of the VRF named `name`, or `None` if no such VRF is
    /// configured.
    pub fn vrf_table(&self, name: &str) -> Option<u32> {
        self.vrfs.iter().find(|v| v.name == name).map(|v| v.table)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_and_resolves_static_routes() {
        let cfg = Config::from_toml(
            r#"
            router-id = "10.0.0.1"
            [[static]]
            prefix = "0.0.0.0/0"
            via = "192.0.2.1"
            [[static]]
            prefix = "10.20.0.0/16"
            dev = "eth1"
            metric = 10
            [rip]
            enabled = true
            interfaces = ["eth1"]
            "#,
        )
        .expect("valid config");
        assert_eq!(cfg.router_id.as_deref(), Some("10.0.0.1"));
        assert!(cfg.rip.as_ref().unwrap().enabled);
        let routes = cfg.static_routes().unwrap();
        assert_eq!(routes.len(), 2);
        assert_eq!(routes[0].prefix.to_string(), "0.0.0.0/0");
        assert_eq!(routes[1].metric, 10);
    }

    #[test]
    fn parses_multicast_igmp_querier_and_proxy() {
        let cfg = Config::from_toml(
            r#"
            router-id = "10.0.0.1"
            [multicast]
            enabled = true
            mld = true
            robustness = 2
            query-interval = 30
            [[multicast.interface]]
            name = "lan0"
            role = "querier"
            [[multicast.interface]]
            name = "wan0"
            role = "upstream"
            igmp-version = 3
            [[multicast.interface]]
            name = "lan1"
            role = "downstream"
            "#,
        )
        .expect("valid config");
        let mc = cfg.multicast.expect("multicast block present");
        assert!(mc.enabled);
        assert_eq!(mc.mld, Some(true));
        assert_eq!(mc.robustness, Some(2));
        assert_eq!(mc.query_interval, Some(30));
        assert_eq!(mc.interfaces.len(), 3);
        assert_eq!(mc.interfaces[0].name, "lan0");
        assert_eq!(mc.interfaces[0].role, MulticastRole::Querier);
        assert_eq!(mc.interfaces[1].role, MulticastRole::Upstream);
        assert_eq!(mc.interfaces[1].igmp_version, Some(3));
        assert_eq!(mc.interfaces[2].role, MulticastRole::Downstream);
    }

    #[test]
    fn parses_multicast_pim_static_rp() {
        let cfg = Config::from_toml(
            r#"
            router-id = "10.0.0.1"
            [multicast]
            enabled = true
            [[multicast.interface]]
            name = "lan0"
            role = "querier"
            [multicast.pim]
            enabled = true
            rp-address = "10.0.9.9"
            interface = ["lan0", "wan0"]
            hello-interval = 30
            "#,
        )
        .expect("valid config");
        let pim = cfg.multicast.unwrap().pim.expect("pim block present");
        assert!(pim.enabled);
        assert_eq!(pim.rp_address, Some("10.0.9.9".parse().unwrap()));
        assert_eq!(pim.interfaces, vec!["lan0", "wan0"]);
        assert_eq!(pim.hello_interval, Some(30));
    }

    #[test]
    fn multicast_role_defaults_to_querier() {
        let cfg = Config::from_toml(
            r#"
            [multicast]
            enabled = true
            [[multicast.interface]]
            name = "lan0"
            "#,
        )
        .expect("valid config");
        let mc = cfg.multicast.unwrap();
        assert_eq!(mc.interfaces[0].role, MulticastRole::Querier);
    }

    #[test]
    fn parses_filter_rule_communities() {
        let cfg = Config::from_toml(
            r#"
            [[filter]]
            name = "tag-bgp"
            default = "accept"
            [[filter.rule]]
            prefix = ["10.99.0.0/16+"]
            set-community = ["65000:100", "no-export"]
            add-community = ["65000:200"]
            set-large-community = ["65000:1:2"]
            add-large-community = ["65000:3:4"]
            set-ext-community = ["rt:65000:100"]
            add-ext-community = ["ro:65000:1"]
            action = "accept"
            "#,
        )
        .expect("valid config");
        let rule = &cfg.filters[0].rule[0];
        assert_eq!(
            rule.set_community.as_deref(),
            Some(&["65000:100".to_string(), "no-export".to_string()][..])
        );
        assert_eq!(rule.add_community, vec!["65000:200".to_string()]);
        assert_eq!(
            rule.set_large_community.as_deref(),
            Some(&["65000:1:2".to_string()][..])
        );
        assert_eq!(rule.add_large_community, vec!["65000:3:4".to_string()]);
        assert_eq!(
            rule.set_ext_community.as_deref(),
            Some(&["rt:65000:100".to_string()][..])
        );
        assert_eq!(rule.add_ext_community, vec!["ro:65000:1".to_string()]);
    }

    #[test]
    fn rejects_static_route_without_via_or_dev() {
        let err = Config::from_toml(
            r#"
            [[static]]
            prefix = "10.0.0.0/24"
            "#,
        )
        .unwrap_err();
        assert!(matches!(err, ConfigError::Invalid(_)));
    }

    #[test]
    fn rejects_unknown_keys() {
        assert!(Config::from_toml("bogus = true").is_err());
    }

    #[test]
    fn parses_bgp_section() {
        let cfg = Config::from_toml(
            r#"
            router-id = "10.0.0.1"
            [bgp]
            enabled = true
            local-as = 65001
            hold-time = 90
            network = ["10.10.0.0/24"]
            [[bgp.neighbor]]
            address = "10.0.0.2"
            remote-as = 65002
            [[bgp.neighbor]]
            address = "10.0.0.3"
            remote-as = 65001
            passive = true
            "#,
        )
        .expect("valid config");
        let bgp = cfg.bgp.expect("bgp present");
        assert!(bgp.enabled);
        assert_eq!(bgp.local_as, 65001);
        assert_eq!(bgp.hold_time, Some(90));
        assert_eq!(bgp.network, vec!["10.10.0.0/24"]);
        assert_eq!(bgp.neighbor.len(), 2);
        assert_eq!(bgp.neighbor[0].remote_as, 65002);
        assert!(!bgp.neighbor[0].passive);
        assert!(bgp.neighbor[1].passive);
        assert_eq!(bgp.neighbor[0].ttl_security, None);
    }

    #[test]
    fn parses_bgp_ttl_security() {
        let cfg = Config::from_toml(
            r#"
            router-id = "10.0.0.1"
            [bgp]
            enabled = true
            local-as = 65001
            [[bgp.neighbor]]
            address = "10.0.0.2"
            remote-as = 65002
            ttl-security = 1
            "#,
        )
        .expect("valid config");
        let bgp = cfg.bgp.expect("bgp present");
        assert_eq!(bgp.neighbor[0].ttl_security, Some(1));
    }

    #[test]
    fn parses_bgp_password() {
        let cfg = Config::from_toml(
            r#"
            router-id = "10.0.0.1"
            [bgp]
            enabled = true
            local-as = 65001
            [[bgp.neighbor]]
            address = "10.0.0.2"
            remote-as = 65002
            password = "s3cr3t"
            "#,
        )
        .expect("valid config");
        let bgp = cfg.bgp.expect("bgp present");
        assert_eq!(bgp.neighbor[0].password.as_deref(), Some("s3cr3t"));
    }

    #[test]
    fn parses_bgp_neighbor_session_options() {
        let cfg = Config::from_toml(
            r#"
            router-id = "10.0.0.1"
            [bgp]
            enabled = true
            local-as = 65001
            [[bgp.neighbor]]
            address = "10.0.0.2"
            remote-as = 65002
            local-as = 65099
            update-source = "10.0.0.9"
            ebgp-multihop = 5
            description = "transit uplink"
            shutdown = true
            hold-time = 30
            "#,
        )
        .expect("valid config");
        let n = &cfg.bgp.expect("bgp present").neighbor[0];
        assert_eq!(n.local_as, Some(65099));
        assert_eq!(n.update_source.as_deref(), Some("10.0.0.9"));
        assert_eq!(n.ebgp_multihop, Some(5));
        assert_eq!(n.description.as_deref(), Some("transit uplink"));
        assert!(n.shutdown);
        assert_eq!(n.hold_time, Some(30));
    }

    #[test]
    fn bgp_neighbor_session_options_default_unset() {
        let cfg = Config::from_toml(
            r#"
            router-id = "10.0.0.1"
            [bgp]
            enabled = true
            local-as = 65001
            [[bgp.neighbor]]
            address = "10.0.0.2"
            remote-as = 65002
            "#,
        )
        .expect("valid config");
        let n = &cfg.bgp.expect("bgp present").neighbor[0];
        assert_eq!(n.local_as, None);
        assert_eq!(n.update_source, None);
        assert_eq!(n.ebgp_multihop, None);
        assert_eq!(n.description, None);
        assert!(!n.shutdown);
        assert_eq!(n.hold_time, None);
    }

    #[test]
    fn parses_bgp_tcp_ao() {
        let cfg = Config::from_toml(
            r#"
            router-id = "10.0.0.1"
            [bgp]
            enabled = true
            local-as = 65001
            [[bgp.neighbor]]
            address = "10.0.0.2"
            remote-as = 65002
            ao-key = "aosecret"
            ao-key-id = 42
            "#,
        )
        .expect("valid config");
        let bgp = cfg.bgp.expect("bgp present");
        assert_eq!(bgp.neighbor[0].ao_key.as_deref(), Some("aosecret"));
        assert_eq!(bgp.neighbor[0].ao_key_id, Some(42));
    }

    #[test]
    fn parses_bgp_bfd_and_defaults() {
        let cfg = Config::from_toml(
            r#"
            router-id = "10.0.0.1"
            [bfd]
            min-tx = 250
            min-rx = 250
            detect-mult = 4
            [bgp]
            enabled = true
            local-as = 65001
            [[bgp.neighbor]]
            address = "10.0.0.2"
            remote-as = 65002
            bfd = true
            [[bgp.neighbor]]
            address = "10.0.0.3"
            remote-as = 65003
            "#,
        )
        .expect("valid config");
        let bfd = cfg.bfd.expect("bfd present");
        assert_eq!(bfd.min_tx, Some(250));
        assert_eq!(bfd.min_rx, Some(250));
        assert_eq!(bfd.detect_mult, Some(4));
        let bgp = cfg.bgp.expect("bgp present");
        assert!(bgp.neighbor[0].bfd);
        assert!(!bgp.neighbor[1].bfd); // defaults to false
    }

    #[test]
    fn parses_bfd_authentication() {
        let cfg = Config::from_toml(
            r#"
            router-id = "10.0.0.1"
            [bfd]
            auth-type   = "meticulous-sha1"
            auth-key-id = 7
            auth-key    = "s3cret"
            "#,
        )
        .expect("valid config");
        let bfd = cfg.bfd.expect("bfd present");
        assert_eq!(bfd.auth_type.as_deref(), Some("meticulous-sha1"));
        assert_eq!(bfd.auth_key_id, Some(7));
        assert_eq!(bfd.auth_key.as_deref(), Some("s3cret"));
        // All three default to unset (no authentication).
        let cfg = Config::from_toml("router-id = \"10.0.0.1\"\n[bfd]\nmin-tx = 200\n")
            .expect("valid config");
        let bfd = cfg.bfd.expect("bfd present");
        assert!(bfd.auth_type.is_none() && bfd.auth_key.is_none() && bfd.auth_key_id.is_none());
    }

    #[test]
    fn parses_bgp_max_prefix() {
        let cfg = Config::from_toml(
            r#"
            router-id = "10.0.0.1"
            [bgp]
            enabled = true
            local-as = 65001
            [[bgp.neighbor]]
            address = "10.0.0.2"
            remote-as = 65002
            max-prefix = 1000
            "#,
        )
        .expect("valid config");
        let bgp = cfg.bgp.expect("bgp present");
        assert_eq!(bgp.neighbor[0].max_prefix, Some(1000));
    }

    #[test]
    fn parses_bgp_default_originate() {
        let cfg = Config::from_toml(
            r#"
            router-id = "10.0.0.1"
            [bgp]
            enabled = true
            local-as = 65001
            [[bgp.neighbor]]
            address = "10.0.0.2"
            remote-as = 65002
            default-originate = true
            "#,
        )
        .expect("valid config");
        let bgp = cfg.bgp.expect("bgp present");
        assert!(bgp.neighbor[0].default_originate);
    }

    #[test]
    fn parses_bgp_add_path() {
        let cfg = Config::from_toml(
            r#"
            router-id = "10.0.0.1"
            [bgp]
            enabled = true
            local-as = 65001
            [[bgp.neighbor]]
            address = "10.0.0.2"
            remote-as = 65002
            add-path = true
            "#,
        )
        .expect("valid config");
        let bgp = cfg.bgp.expect("bgp present");
        assert!(bgp.neighbor[0].add_path);
        assert!(!bgp.neighbor[0].extended_nexthop); // unrelated, defaults false
        // Defaults to false when unset.
        let cfg2 = Config::from_toml(
            r#"
            router-id = "10.0.0.1"
            [bgp]
            enabled = true
            local-as = 65001
            [[bgp.neighbor]]
            address = "10.0.0.3"
            remote-as = 65003
            "#,
        )
        .expect("valid config");
        assert!(!cfg2.bgp.expect("bgp present").neighbor[0].add_path);
    }

    #[test]
    fn parses_bgp_extended_nexthop() {
        let cfg = Config::from_toml(
            r#"
            router-id = "10.0.0.1"
            [bgp]
            enabled = true
            local-as = 65001
            [[bgp.neighbor]]
            address = "10.0.0.2"
            remote-as = 65002
            extended-nexthop = true
            "#,
        )
        .expect("valid config");
        assert!(cfg.bgp.expect("bgp present").neighbor[0].extended_nexthop);
    }

    #[test]
    fn parses_bgp_aggregate() {
        let cfg = Config::from_toml(
            r#"
            router-id = "10.0.0.1"
            [bgp]
            enabled = true
            local-as = 65001
            [[bgp.aggregate]]
            prefix = "10.0.0.0/16"
            summary-only = true
            [[bgp.aggregate]]
            prefix = "192.168.0.0/16"
            "#,
        )
        .expect("valid config");
        let bgp = cfg.bgp.expect("bgp present");
        assert_eq!(bgp.aggregate.len(), 2);
        assert_eq!(bgp.aggregate[0].prefix, "10.0.0.0/16");
        assert!(bgp.aggregate[0].summary_only);
        assert_eq!(bgp.aggregate[1].prefix, "192.168.0.0/16");
        assert!(!bgp.aggregate[1].summary_only); // defaults to false
    }

    #[test]
    fn parses_bgp_neighbor_import() {
        let cfg = Config::from_toml(
            r#"
            router-id = "10.0.0.1"
            [bgp]
            enabled = true
            local-as = 65001
            [[bgp.neighbor]]
            address = "10.0.0.2"
            remote-as = 65002
            import = "from-peer"
            "#,
        )
        .expect("valid config");
        let bgp = cfg.bgp.expect("bgp present");
        assert_eq!(bgp.neighbor[0].import.as_deref(), Some("from-peer"));
    }

    #[test]
    fn parses_bgp_neighbor_export() {
        let cfg = Config::from_toml(
            r#"
            router-id = "10.0.0.1"
            [bgp]
            enabled = true
            local-as = 65001
            [[bgp.neighbor]]
            address = "10.0.0.2"
            remote-as = 65002
            export = "to-peer"
            "#,
        )
        .expect("valid config");
        let bgp = cfg.bgp.expect("bgp present");
        assert_eq!(bgp.neighbor[0].export.as_deref(), Some("to-peer"));
    }

    #[test]
    fn parses_four_octet_asns() {
        // ASNs beyond 16 bits (RFC 6793) must parse: a 32-bit local AS and a
        // dotted-notation-equivalent remote AS expressed as a plain integer.
        let cfg = Config::from_toml(
            r#"
            router-id = "10.0.0.1"
            [bgp]
            enabled = true
            local-as = 196618
            [[bgp.neighbor]]
            address = "10.0.0.2"
            remote-as = 4200000000
            "#,
        )
        .expect("valid config");
        let bgp = cfg.bgp.expect("bgp present");
        assert_eq!(bgp.local_as, 196_618);
        assert_eq!(bgp.neighbor[0].remote_as, 4_200_000_000);
    }

    #[test]
    fn parses_bgp_communities() {
        let cfg = Config::from_toml(
            r#"
            router-id = "10.0.0.1"
            [bgp]
            enabled  = true
            local-as = 65001
            network  = ["10.10.0.0/24"]
            community = ["65001:100", "no-export"]
            "#,
        )
        .expect("valid config");
        let bgp = cfg.bgp.expect("bgp present");
        assert_eq!(bgp.community, vec!["65001:100", "no-export"]);
    }

    /// A discard route is a route with nowhere to send, and that is how it
    /// reaches the FIB: an empty next-hop list, which the netlink layer installs
    /// as the kernel's own blackhole type. Distance counts down where
    /// preference counts up, so the two have to be mirrored.
    #[test]
    fn a_blackhole_route_has_no_nexthop_and_distance_inverts_preference() {
        let cfg: Config = toml::from_str(
            r#"
[[static]]
prefix = "203.0.113.0/24"
blackhole = true
distance = 254
"#,
        )
        .expect("parses");
        let routes = cfg.static_routes().expect("resolves");
        assert_eq!(routes.len(), 1);
        assert!(
            routes[0].nexthops.is_empty(),
            "a blackhole route must carry no next-hop"
        );
        assert_eq!(routes[0].preference, 1, "distance 254 is preference 1");

        // …and it cannot also have somewhere to send.
        let both: Config = toml::from_str(
            "[[static]]\nprefix = \"203.0.113.0/24\"\nblackhole = true\nvia = \"192.0.2.1\"\n",
        )
        .expect("parses");
        assert!(both.static_routes().is_err(), "blackhole + via was accepted");
    }

    #[test]
    fn parses_bgp_redistribute_and_export() {
        let cfg = Config::from_toml(
            r#"
            router-id = "10.0.0.1"
            [bgp]
            enabled  = true
            local-as = 65001
            redistribute = ["connected", "static", "ospf"]
            [[bgp.neighbor]]
            address = "10.0.0.2"
            remote-as = 65002
            [export]
            bgp = "to-peers"
            "#,
        )
        .expect("valid config");
        let bgp = cfg.bgp.expect("bgp present");
        assert_eq!(bgp.redistribute, vec!["connected", "static", "ospf"]);
        assert_eq!(cfg.export.unwrap().bgp.as_deref(), Some("to-peers"));
    }

    #[test]
    fn parses_bgp_multipath() {
        let cfg = Config::from_toml(
            r#"
            router-id = "10.0.0.1"
            [bgp]
            enabled   = true
            local-as  = 65000
            multipath = 4
            [[bgp.neighbor]]
            address = "10.0.0.2"
            remote-as = 65001
            "#,
        )
        .expect("valid config");
        assert_eq!(cfg.bgp.expect("bgp present").multipath, Some(4));

        // Absent → None (classic single-best-path).
        let cfg = Config::from_toml(
            "router-id = \"10.0.0.1\"\n[bgp]\nenabled = true\nlocal-as = 65000\n",
        )
        .expect("valid config");
        assert_eq!(cfg.bgp.expect("bgp present").multipath, None);
    }

    #[test]
    fn parses_rip_redistribute_and_export() {
        let cfg = Config::from_toml(
            r#"
            router-id = "10.0.0.1"
            [rip]
            enabled = true
            interfaces = ["eth1"]
            redistribute = ["connected", "static"]
            redistribute-metric = 3
            [export]
            rip = "to-rip"
            "#,
        )
        .expect("valid config");
        let rip = cfg.rip.expect("rip present");
        assert_eq!(rip.redistribute, vec!["connected", "static"]);
        assert_eq!(rip.redistribute_metric, Some(3));
        assert_eq!(cfg.export.unwrap().rip.as_deref(), Some("to-rip"));
    }

    #[test]
    fn parses_ripng_redistribute_and_export() {
        let cfg = Config::from_toml(
            r#"
            router-id = "10.0.0.1"
            [ripng]
            enabled = true
            interfaces = ["eth1"]
            redistribute = ["connected", "static"]
            redistribute-metric = 2
            [export]
            ripng = "to-ripng"
            "#,
        )
        .expect("valid config");
        let ripng = cfg.ripng.expect("ripng present");
        assert_eq!(ripng.redistribute, vec!["connected", "static"]);
        assert_eq!(ripng.redistribute_metric, Some(2));
        assert_eq!(cfg.export.unwrap().ripng.as_deref(), Some("to-ripng"));
    }

    #[test]
    fn parses_babel_redistribute_and_export() {
        let cfg = Config::from_toml(
            r#"
            router-id = "10.0.0.1"
            [babel]
            enabled = true
            interfaces = ["eth1"]
            redistribute = ["connected", "static"]
            redistribute-metric = 96
            [export]
            babel = "to-babel"
            "#,
        )
        .expect("valid config");
        let babel = cfg.babel.expect("babel present");
        assert_eq!(babel.redistribute, vec!["connected", "static"]);
        assert_eq!(babel.redistribute_metric, Some(96));
        assert_eq!(cfg.export.unwrap().babel.as_deref(), Some("to-babel"));
    }

    #[test]
    fn parses_isis_redistribute_and_export() {
        let cfg = Config::from_toml(
            r#"
            router-id = "10.0.0.1"
            [isis]
            enabled = true
            interfaces = ["eth1"]
            redistribute = ["connected", "static"]
            redistribute-metric = 20
            [export]
            isis = "to-isis"
            "#,
        )
        .expect("valid config");
        let isis = cfg.isis.expect("isis present");
        assert_eq!(isis.redistribute, vec!["connected", "static"]);
        assert_eq!(isis.redistribute_metric, Some(20));
        assert_eq!(cfg.export.unwrap().isis.as_deref(), Some("to-isis"));
    }

    #[test]
    fn parses_ospf_redistribute_and_export() {
        let cfg = Config::from_toml(
            r#"
            router-id = "10.0.0.1"
            [ospf]
            enabled = true
            interfaces = ["eth1"]
            redistribute = ["connected", "static"]
            redistribute-metric = 50
            [export]
            ospf = "to-area"
            "#,
        )
        .expect("valid config");
        let ospf = cfg.ospf.expect("ospf present");
        assert_eq!(ospf.redistribute, vec!["connected", "static"]);
        assert_eq!(ospf.redistribute_metric, Some(50));
        assert_eq!(cfg.export.unwrap().ospf.as_deref(), Some("to-area"));
    }

    #[test]
    fn parses_ospf_stub_areas() {
        let cfg = Config::from_toml(
            r#"
            router-id = "10.0.0.1"
            [ospf]
            enabled = true
            interfaces = ["eth1"]
            stub-areas = ["1.0.0.0", "2.0.0.0"]
            stub-default-cost = 5
            "#,
        )
        .expect("valid config");
        let ospf = cfg.ospf.expect("ospf present");
        assert_eq!(ospf.stub_areas, vec!["1.0.0.0", "2.0.0.0"]);
        assert_eq!(ospf.stub_default_cost, Some(5));
    }

    #[test]
    fn parses_ospf_nssa_areas() {
        let cfg = Config::from_toml(
            r#"
            router-id = "10.0.0.1"
            [ospf]
            enabled = true
            interfaces = ["eth1"]
            nssa-areas = ["3.0.0.0"]
            "#,
        )
        .expect("valid config");
        assert_eq!(cfg.ospf.expect("ospf present").nssa_areas, vec!["3.0.0.0"]);
    }

    #[test]
    fn parses_ospf_totally_stubby_and_nssa_areas() {
        let cfg = Config::from_toml(
            r#"
            router-id = "10.0.0.1"
            [ospf]
            enabled = true
            interfaces = ["eth1"]
            totally-stubby-areas = ["1.0.0.0"]
            totally-nssa-areas   = ["3.0.0.0"]
            "#,
        )
        .expect("valid config");
        let ospf = cfg.ospf.expect("ospf present");
        assert_eq!(ospf.totally_stubby_areas, vec!["1.0.0.0"]);
        assert_eq!(ospf.totally_nssa_areas, vec!["3.0.0.0"]);
    }

    #[test]
    fn parses_ospf_authentication() {
        let cfg = Config::from_toml(
            r#"
            router-id = "10.0.0.1"
            [ospf]
            enabled = true
            interfaces = ["eth1"]
            auth-type = "md5"
            auth-key = "secret"
            auth-key-id = 3
            "#,
        )
        .expect("valid config");
        let ospf = cfg.ospf.expect("ospf present");
        assert_eq!(ospf.auth_type.as_deref(), Some("md5"));
        assert_eq!(ospf.auth_key.as_deref(), Some("secret"));
        assert_eq!(ospf.auth_key_id, Some(3));
    }

    #[test]
    fn parses_ospf_bfd() {
        let cfg = Config::from_toml(
            r#"
            router-id = "10.0.0.1"
            [ospf]
            enabled = true
            interfaces = ["eth1"]
            bfd = true
            "#,
        )
        .expect("valid config");
        assert!(cfg.ospf.expect("ospf present").bfd);
        // Defaults to false when unset.
        let cfg = Config::from_toml(
            "router-id = \"10.0.0.1\"\n[ospf]\nenabled = true\ninterfaces = [\"eth1\"]\n",
        )
        .expect("valid config");
        assert!(!cfg.ospf.expect("ospf present").bfd);
    }

    #[test]
    fn parses_ospf_passive_interfaces() {
        let cfg = Config::from_toml(
            r#"
            router-id = "10.0.0.1"
            [ospf]
            enabled = true
            interfaces = ["eth1", "eth2"]
            passive-interfaces = ["eth2"]
            "#,
        )
        .expect("valid config");
        let ospf = cfg.ospf.expect("ospf present");
        assert_eq!(ospf.passive_interfaces, vec!["eth2".to_string()]);
        // Defaults to empty when unset.
        let cfg = Config::from_toml(
            "router-id = \"10.0.0.1\"\n[ospf]\nenabled = true\ninterfaces = [\"eth1\"]\n",
        )
        .expect("valid config");
        assert!(cfg.ospf.expect("ospf present").passive_interfaces.is_empty());
    }

    #[test]
    fn parses_ospf3_bfd() {
        let cfg = Config::from_toml(
            r#"
            router-id = "10.0.0.1"
            [ospf3]
            enabled = true
            interfaces = ["eth1"]
            bfd = true
            "#,
        )
        .expect("valid config");
        assert!(cfg.ospf3.expect("ospf3 present").bfd);
        // Defaults to false when unset.
        let cfg = Config::from_toml(
            "router-id = \"10.0.0.1\"\n[ospf3]\nenabled = true\ninterfaces = [\"eth1\"]\n",
        )
        .expect("valid config");
        assert!(!cfg.ospf3.expect("ospf3 present").bfd);
    }

    #[test]
    fn parses_ospf3_authentication() {
        let cfg = Config::from_toml(
            r#"
            router-id = "10.0.0.1"
            [ospf3]
            enabled = true
            interfaces = ["eth1"]
            auth-type = "hmac-sha256"
            auth-key = "a-shared-secret"
            auth-sa-id = 7
            auth-replay-protection = false
            "#,
        )
        .expect("valid config");
        let ospf3 = cfg.ospf3.expect("ospf3 present");
        assert_eq!(ospf3.auth_type.as_deref(), Some("hmac-sha256"));
        assert_eq!(ospf3.auth_key.as_deref(), Some("a-shared-secret"));
        assert_eq!(ospf3.auth_sa_id, Some(7));
        assert_eq!(ospf3.auth_replay_protection, Some(false));
        // The auth fields default to None when the section omits them.
        let cfg = Config::from_toml(
            "router-id = \"10.0.0.1\"\n[ospf3]\nenabled = true\ninterfaces = [\"eth1\"]\n",
        )
        .expect("valid config");
        let ospf3 = cfg.ospf3.expect("ospf3 present");
        assert_eq!(ospf3.auth_type, None);
        assert_eq!(ospf3.auth_key, None);
    }

    #[test]
    fn parses_vrf_and_static_in_vrf() {
        let cfg = Config::from_toml(
            r#"
            router-id = "10.0.0.1"
            [[vrf]]
            name = "blue"
            table = 100
            rd = "65000:1"
            interfaces = ["eth1"]
            [[static]]
            prefix = "10.9.0.0/24"
            via    = "10.0.0.2"
            vrf    = "blue"
            [[static]]
            prefix = "10.8.0.0/24"
            via    = "10.0.0.3"
            "#,
        )
        .expect("valid config");
        assert_eq!(cfg.vrf_table("blue"), Some(100));
        assert_eq!(cfg.vrf_table("nope"), None);
        let routes = cfg.static_routes().expect("static routes");
        // The VRF static lands in table 100; the plain one stays in the main table.
        let in_vrf = routes.iter().find(|r| r.prefix.to_string() == "10.9.0.0/24").unwrap();
        assert_eq!(in_vrf.table, 100);
        let in_main = routes.iter().find(|r| r.prefix.to_string() == "10.8.0.0/24").unwrap();
        assert_eq!(in_main.table, wren_core::RT_TABLE_MAIN);
    }

    #[test]
    fn rejects_static_in_unknown_vrf() {
        // Loading validates the statics, so an unknown VRF reference fails at load.
        let err = Config::from_toml(
            "router-id = \"10.0.0.1\"\n[[static]]\nprefix = \"10.9.0.0/24\"\nvia = \"10.0.0.2\"\nvrf = \"ghost\"\n",
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("unknown vrf"), "got {err:?}");
    }

    #[test]
    fn parses_isis_bfd() {
        let cfg = Config::from_toml(
            r#"
            router-id = "10.0.0.1"
            [isis]
            enabled = true
            interfaces = ["eth1"]
            bfd = true
            "#,
        )
        .expect("valid config");
        assert!(cfg.isis.expect("isis present").bfd);
        // Defaults to false when unset.
        let cfg = Config::from_toml(
            "router-id = \"10.0.0.1\"\n[isis]\nenabled = true\ninterfaces = [\"eth1\"]\n",
        )
        .expect("valid config");
        assert!(!cfg.isis.expect("isis present").bfd);
    }

    #[test]
    fn parses_rip_and_babel_bfd() {
        let cfg = Config::from_toml(
            r#"
            router-id = "10.0.0.1"
            [rip]
            enabled = true
            interfaces = ["eth1"]
            bfd = true
            [babel]
            enabled = true
            interfaces = ["eth1"]
            bfd = true
            "#,
        )
        .expect("valid config");
        assert!(cfg.rip.expect("rip present").bfd);
        assert!(cfg.babel.expect("babel present").bfd);
        // Both default to false when unset.
        let cfg = Config::from_toml(
            "router-id = \"10.0.0.1\"\n[rip]\nenabled = true\ninterfaces = [\"eth1\"]\n[babel]\nenabled = true\ninterfaces = [\"eth1\"]\n",
        )
        .expect("valid config");
        assert!(!cfg.rip.expect("rip present").bfd);
        assert!(!cfg.babel.expect("babel present").bfd);
    }

    #[test]
    fn parses_isis_l2_to_l1_leaking() {
        let cfg = Config::from_toml(
            r#"
            router-id = "10.0.0.1"
            [isis]
            enabled = true
            interfaces = ["eth1"]
            l2-to-l1-leaking = true
            "#,
        )
        .expect("valid config");
        assert!(cfg.isis.expect("isis present").l2_to_l1_leaking);
        // Defaults to false when unset.
        let cfg = Config::from_toml(
            "router-id = \"10.0.0.1\"\n[isis]\nenabled = true\ninterfaces = [\"eth1\"]\n",
        )
        .expect("valid config");
        assert!(!cfg.isis.expect("isis present").l2_to_l1_leaking);
    }

    #[test]
    fn parses_ospf_nssa_default_areas() {
        let cfg = Config::from_toml(
            r#"
            router-id = "10.0.0.1"
            [ospf]
            enabled = true
            interfaces = ["eth1"]
            nssa-areas         = ["1.0.0.0"]
            nssa-default-areas = ["1.0.0.0"]
            "#,
        )
        .expect("valid config");
        let ospf = cfg.ospf.expect("ospf present");
        assert_eq!(ospf.nssa_default_areas, vec!["1.0.0.0"]);
    }

    #[test]
    fn parses_babel_section() {
        let cfg = Config::from_toml(
            r#"
            router-id = "10.0.0.1"
            [babel]
            enabled = true
            interfaces = ["eth1", "eth2"]
            network = ["10.10.0.0/24"]
            "#,
        )
        .expect("valid config");
        let babel = cfg.babel.expect("babel present");
        assert!(babel.enabled);
        assert_eq!(babel.interfaces, vec!["eth1", "eth2"]);
        assert_eq!(babel.network, vec!["10.10.0.0/24"]);
        assert!(babel.router_id.is_none());
    }
}
