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
use std::net::IpAddr;
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
    /// An RTR (RFC 8210) validating cache to fetch ROAs from live, instead of (or in
    /// addition to) the static `[[bgp.roa]]` entries. Unset disables RTR.
    pub rtr: Option<BgpRtr>,
    /// A BMP (RFC 7854) monitoring station to stream this speaker's BGP state to.
    /// Unset disables BMP.
    pub bmp: Option<BgpBmp>,
    /// The configured peers.
    #[serde(default)]
    pub neighbor: Vec<BgpNeighbor>,
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
    /// Whether to wait for the peer to connect rather than initiating the TCP
    /// connection ourselves. Defaults to false (we actively connect).
    #[serde(default)]
    pub passive: bool,
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
            let nexthop = match (&s.via, &s.dev) {
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
                        "static route {prefix} needs `via` and/or `dev`"
                    )))
                }
            };
            let mut route = Route::new(prefix, Protocol::Static, vec![nexthop], s.metric);
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
