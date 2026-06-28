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
    /// The configured peers.
    #[serde(default)]
    pub neighbor: Vec<BgpNeighbor>,
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
            out.push(Route::new(
                prefix,
                Protocol::Static,
                vec![nexthop],
                s.metric,
            ));
        }
        Ok(out)
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
