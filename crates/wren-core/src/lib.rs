//! # wren-core — the routing control-plane core
//!
//! A dependency-free (`std`-only) library holding the pieces every routing
//! daemon is built around, modelled after BIRD and FRR but in safe Rust:
//!
//! * [`Prefix`] — an IPv4/IPv6 CIDR network, always normalised to its base
//!   address (host bits cleared), like a route's destination.
//! * [`Route`] — a destination plus one or more [`NextHop`]s, tagged with the
//!   [`Protocol`] that produced it and its administrative *preference*/metric.
//! * [`Rib`] — the Routing Information Base: every protocol announces its routes
//!   here and the RIB picks the **best** route per prefix (BIRD-style: highest
//!   preference, then lowest metric) and emits [`FibChange`]s.
//! * [`Fib`] — the Forwarding Information Base abstraction: a sink that installs
//!   the chosen routes (a real one writes the kernel table over netlink; the
//!   bundled [`MemoryFib`] just records them, for tests and `--dry-run`).
//!
//! The split mirrors FRR's *zebra* (RIB/FIB) vs. the protocol daemons: protocols
//! depend only on this crate and feed [`Route`]s into a [`Rib`]; the platform
//! layer drains [`FibChange`]s into a [`Fib`]. Being `std`-only it links straight
//! into other control planes — including Velstra Sentinel, which can read Wren's
//! best routes and program them into its eBPF/XDP data plane.

#![forbid(unsafe_code)]

pub mod rd;
pub use rd::RouteDistinguisher;

use std::collections::BTreeMap;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

// ===========================================================================
// Prefix — an IP CIDR network
// ===========================================================================

/// An IPv4 or IPv6 network prefix (`addr/len`), always stored with host bits
/// cleared so that two prefixes describing the same network compare equal and
/// hash the same (`10.0.0.5/24` and `10.0.0.0/24` both normalise to the latter).
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Prefix {
    addr: IpAddr,
    len: u8,
}

/// Why a [`Prefix`] could not be constructed or parsed.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum PrefixError {
    /// The prefix length exceeds the address family's maximum (32 / 128).
    LenTooLong { len: u8, max: u8 },
    /// The textual form was not `addr/len`.
    Malformed(String),
}

impl fmt::Display for PrefixError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PrefixError::LenTooLong { len, max } => {
                write!(f, "prefix length /{len} exceeds /{max}")
            }
            PrefixError::Malformed(s) => write!(f, "malformed prefix {s:?} (expected addr/len)"),
        }
    }
}

impl std::error::Error for PrefixError {}

impl Prefix {
    /// Build a prefix, validating the length and normalising the address.
    pub fn new(addr: IpAddr, len: u8) -> Result<Self, PrefixError> {
        let max = max_len(&addr);
        if len > max {
            return Err(PrefixError::LenTooLong { len, max });
        }
        Ok(Self {
            addr: mask(addr, len),
            len,
        })
    }

    /// A host route (`/32` or `/128`) for `addr`.
    pub fn host(addr: IpAddr) -> Self {
        let len = max_len(&addr);
        Self { addr, len }
    }

    /// The (normalised) network address.
    pub fn addr(&self) -> IpAddr {
        self.addr
    }

    /// The prefix length in bits.
    // Not a collection length — `is_empty` would be meaningless (use `is_default`
    // for the `/0` case), so the clippy companion-method lint does not apply.
    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> u8 {
        self.len
    }

    /// The maximum length for this prefix's address family (32 or 128).
    pub fn max_len(&self) -> u8 {
        max_len(&self.addr)
    }

    /// Whether this is the default route (`0.0.0.0/0` or `::/0`).
    pub fn is_default(&self) -> bool {
        self.len == 0
    }

    /// Whether this prefix is IPv4.
    pub fn is_ipv4(&self) -> bool {
        self.addr.is_ipv4()
    }

    /// Whether `ip` falls inside this prefix (same family and matching network).
    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.addr, ip) {
            (IpAddr::V4(_), IpAddr::V4(_)) | (IpAddr::V6(_), IpAddr::V6(_)) => {
                mask(ip, self.len) == self.addr
            }
            _ => false,
        }
    }
}

/// The maximum prefix length for `addr`'s family.
fn max_len(addr: &IpAddr) -> u8 {
    match addr {
        IpAddr::V4(_) => 32,
        IpAddr::V6(_) => 128,
    }
}

/// Clear the host bits of `addr` below `len`, yielding the network address.
fn mask(addr: IpAddr, len: u8) -> IpAddr {
    match addr {
        IpAddr::V4(a) => {
            let m = if len == 0 { 0 } else { u32::MAX << (32 - len as u32) };
            IpAddr::V4(Ipv4Addr::from(u32::from(a) & m))
        }
        IpAddr::V6(a) => {
            let m = if len == 0 {
                0
            } else {
                u128::MAX << (128 - len as u32)
            };
            IpAddr::V6(Ipv6Addr::from(u128::from(a) & m))
        }
    }
}

impl fmt::Display for Prefix {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.addr, self.len)
    }
}

impl fmt::Debug for Prefix {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self}")
    }
}

impl FromStr for Prefix {
    type Err = PrefixError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (addr_s, len_s) = s
            .split_once('/')
            .ok_or_else(|| PrefixError::Malformed(s.to_string()))?;
        let addr: IpAddr = addr_s
            .parse()
            .map_err(|_| PrefixError::Malformed(s.to_string()))?;
        let len: u8 = len_s
            .parse()
            .map_err(|_| PrefixError::Malformed(s.to_string()))?;
        Prefix::new(addr, len)
    }
}

// `BTreeMap` keys need a total order; sort by (family, address, length) so
// dumps are deterministic and longest-prefix grouping is natural.
impl PartialOrd for Prefix {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Prefix {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        fn key(p: &Prefix) -> (u8, u128, u8) {
            let (fam, bits) = match p.addr {
                IpAddr::V4(a) => (0u8, u32::from(a) as u128),
                IpAddr::V6(a) => (1u8, u128::from(a)),
            };
            (fam, bits, p.len)
        }
        key(self).cmp(&key(other))
    }
}

// ===========================================================================
// Route — a destination + next-hops, attributed to a protocol
// ===========================================================================

/// The protocol (route source) that contributed a route. The numeric
/// *preference* (higher wins) follows BIRD's defaults, so without any operator
/// tuning a directly-connected route beats a static route, which beats an IGP,
/// which beats BGP.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
pub enum Protocol {
    /// A directly-attached network (an interface's subnet).
    Connected,
    /// An operator-configured static route.
    Static,
    /// A route read back from / owned by the kernel.
    Kernel,
    /// RIP (RFC 2453).
    Rip,
    /// OSPF (RFC 2328 / RFC 5340).
    Ospf,
    /// IS-IS (ISO/IEC 10589 / RFC 1195).
    Isis,
    /// Babel (RFC 8966).
    Babel,
    /// BGP (RFC 4271).
    Bgp,
}

impl Protocol {
    /// BIRD-style default preference (higher is more trusted).
    pub fn default_preference(self) -> u32 {
        match self {
            Protocol::Connected => 240,
            Protocol::Static => 200,
            Protocol::Ospf => 150,
            Protocol::Isis => 145,
            Protocol::Rip => 120,
            Protocol::Babel => 115,
            Protocol::Bgp => 100,
            Protocol::Kernel => 10,
        }
    }

    /// A short, stable name (for logs and the CLI).
    pub fn name(self) -> &'static str {
        match self {
            Protocol::Connected => "connected",
            Protocol::Static => "static",
            Protocol::Kernel => "kernel",
            Protocol::Rip => "rip",
            Protocol::Ospf => "ospf",
            Protocol::Isis => "isis",
            Protocol::Babel => "babel",
            Protocol::Bgp => "bgp",
        }
    }
}

/// One next-hop of a route: a gateway address, an outgoing interface, or both
/// (an interface alone is an on-link/connected next-hop). `weight` supports
/// weighted ECMP when a route carries several next-hops.
#[derive(Clone, PartialEq, Eq, Debug, Hash)]
pub struct NextHop {
    /// The gateway (router) to send to, if any.
    pub gateway: Option<IpAddr>,
    /// The outgoing interface name, if pinned.
    pub iface: Option<String>,
    /// Relative weight for weighted multipath (1 = unweighted).
    pub weight: u16,
}

impl NextHop {
    /// A next-hop via a gateway address.
    pub fn via(gateway: IpAddr) -> Self {
        Self {
            gateway: Some(gateway),
            iface: None,
            weight: 1,
        }
    }

    /// An on-link next-hop out of an interface (no gateway).
    pub fn dev(iface: impl Into<String>) -> Self {
        Self {
            gateway: None,
            iface: Some(iface.into()),
            weight: 1,
        }
    }

    /// A next-hop via `gateway` pinned to `iface`.
    pub fn via_dev(gateway: IpAddr, iface: impl Into<String>) -> Self {
        Self {
            gateway: Some(gateway),
            iface: Some(iface.into()),
            weight: 1,
        }
    }
}

/// The Linux **main** routing table id (the default VRF). A route without an explicit
/// VRF lives here, matching the kernel's `RT_TABLE_MAIN`.
pub const RT_TABLE_MAIN: u32 = 254;

/// A candidate route to a [`Prefix`], as offered by one protocol instance.
///
/// Within the RIB, a route is identified by `(prefix, protocol, source)`:
/// re-announcing the same triple **replaces** the previous candidate, and a
/// withdraw removes it. `source` distinguishes several routers/instances of one
/// protocol (e.g. two RIP neighbours offering the same prefix).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Route {
    /// Destination network.
    pub prefix: Prefix,
    /// The kernel routing table the route lives in — its **VRF**. Defaults to
    /// [`RT_TABLE_MAIN`] (the global/default VRF); a route placed in a named VRF
    /// carries that VRF's table id, so the same prefix can exist in several VRFs at
    /// once. Part of the route's identity (RIB and FIB are keyed by `(table, prefix)`).
    pub table: u32,
    /// One or more next-hops (multipath when more than one).
    pub nexthops: Vec<NextHop>,
    /// The protocol that produced this route.
    pub protocol: Protocol,
    /// Administrative preference (higher wins); defaults from [`Protocol`].
    pub preference: u32,
    /// Protocol metric (lower wins, used as the tie-break after preference).
    pub metric: u32,
    /// Source discriminator within the protocol (e.g. neighbour/router id).
    pub source: u64,
    /// Route tags carried alongside the path (32-bit BGP community values, RFC
    /// 1997). Generic in the core — set by filters and read by BGP origination;
    /// other protocols ignore them. Empty means no communities.
    pub communities: Vec<u32>,
    /// Large route tags (RFC 8092 BGP large communities, `(global, local1,
    /// local2)`). Like [`Route::communities`] — set by filters, read by BGP
    /// origination, ignored by other protocols.
    pub large_communities: Vec<(u32, u32, u32)>,
    /// Extended route tags (RFC 4360 BGP extended communities, raw 8 octets, e.g.
    /// a Route Target). Like [`Route::communities`] — set by filters, read by BGP
    /// origination, ignored by other protocols.
    pub ext_communities: Vec<[u8; 8]>,
}

impl Route {
    /// A route using the protocol's default preference and `source = 0`, in the
    /// default VRF ([`RT_TABLE_MAIN`]).
    pub fn new(prefix: Prefix, protocol: Protocol, nexthops: Vec<NextHop>, metric: u32) -> Self {
        Self {
            prefix,
            table: RT_TABLE_MAIN,
            nexthops,
            protocol,
            preference: protocol.default_preference(),
            metric,
            source: 0,
            communities: Vec::new(),
            large_communities: Vec::new(),
            ext_communities: Vec::new(),
        }
    }

    /// Place this route in the VRF whose kernel routing table is `table` (builder).
    pub fn with_table(mut self, table: u32) -> Self {
        self.table = table;
        self
    }

    /// The identity used to replace/withdraw this route in the RIB.
    fn key(&self) -> (Protocol, u64) {
        (self.protocol, self.source)
    }

    /// Whether `self` is a strictly better path than `other`: higher preference
    /// first, then lower metric. Ties are broken by the caller (stable order).
    fn is_better_than(&self, other: &Route) -> bool {
        match self.preference.cmp(&other.preference) {
            std::cmp::Ordering::Greater => true,
            std::cmp::Ordering::Less => false,
            std::cmp::Ordering::Equal => self.metric < other.metric,
        }
    }
}

// ===========================================================================
// RIB — the routing information base + FIB change stream
// ===========================================================================

/// A change the RIB wants reflected in the forwarding plane.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum FibChange {
    /// Install (or replace) the best route for a `(table, prefix)` — the route
    /// carries its own table (VRF).
    Install(Route),
    /// Remove a prefix entirely from a VRF's table (its last route was withdrawn).
    Remove {
        /// The VRF's kernel routing table.
        table: u32,
        /// The prefix removed.
        prefix: Prefix,
    },
}

/// Per-prefix set of candidate routes from the various protocols.
#[derive(Clone, Default)]
struct RibEntry {
    candidates: Vec<Route>,
}

impl RibEntry {
    /// The current best candidate (highest preference, lowest metric), or `None`
    /// if empty. Stable: equal candidates keep insertion order.
    fn best(&self) -> Option<&Route> {
        let mut best: Option<&Route> = None;
        for c in &self.candidates {
            match best {
                Some(b) if !c.is_better_than(b) => {}
                _ => best = Some(c),
            }
        }
        best
    }
}

/// The Routing Information Base: every protocol's candidate routes, with
/// best-path selection per prefix. Mutating it returns the [`FibChange`]s needed
/// to keep a [`Fib`] in sync — the caller applies them.
#[derive(Clone, Default)]
pub struct Rib {
    entries: BTreeMap<(u32, Prefix), RibEntry>,
}

impl Rib {
    /// An empty RIB.
    pub fn new() -> Self {
        Self::default()
    }

    /// Announce (add or replace) `route`. Returns the resulting FIB change, if
    /// the best route for the route's `(table, prefix)` changed.
    pub fn update(&mut self, route: Route) -> Option<FibChange> {
        let (table, prefix) = (route.table, route.prefix);
        let entry = self.entries.entry((table, prefix)).or_default();
        let before = entry.best().cloned();

        // Replace any existing candidate with the same (protocol, source).
        let key = route.key();
        if let Some(slot) = entry.candidates.iter_mut().find(|c| c.key() == key) {
            *slot = route;
        } else {
            entry.candidates.push(route);
        }

        let after = entry.best().cloned();
        Self::diff(table, prefix, before, after)
    }

    /// Withdraw the route for `(table, prefix)` owned by `(protocol, source)`. Returns
    /// the resulting FIB change, if the best route changed (or the prefix emptied).
    pub fn withdraw(
        &mut self,
        table: u32,
        prefix: Prefix,
        protocol: Protocol,
        source: u64,
    ) -> Option<FibChange> {
        let entry = self.entries.get_mut(&(table, prefix))?;
        let before = entry.best().cloned();
        entry.candidates.retain(|c| c.key() != (protocol, source));
        let after = entry.best().cloned();
        if entry.candidates.is_empty() {
            self.entries.remove(&(table, prefix));
        }
        Self::diff(table, prefix, before, after)
    }

    /// The current best route for `prefix` in the default VRF, if any.
    pub fn best(&self, prefix: &Prefix) -> Option<&Route> {
        self.best_in(RT_TABLE_MAIN, prefix)
    }

    /// The current best route for `prefix` in the VRF whose table is `table`.
    pub fn best_in(&self, table: u32, prefix: &Prefix) -> Option<&Route> {
        self.entries.get(&(table, *prefix)).and_then(RibEntry::best)
    }

    /// Iterate every prefix's best route, in prefix order.
    pub fn iter_best(&self) -> impl Iterator<Item = &Route> {
        self.entries.values().filter_map(RibEntry::best)
    }

    /// Number of prefixes with at least one route.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the RIB holds no routes.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Turn a (before, after) best-route pair into the FIB change it implies:
    /// install the new best when it differs, remove when the prefix emptied,
    /// nothing when the installed route is unchanged.
    fn diff(
        table: u32,
        prefix: Prefix,
        before: Option<Route>,
        after: Option<Route>,
    ) -> Option<FibChange> {
        match after {
            Some(best) => {
                if before.as_ref() == Some(&best) {
                    None
                } else {
                    Some(FibChange::Install(best))
                }
            }
            None => before.map(|_| FibChange::Remove { table, prefix }),
        }
    }
}

// ===========================================================================
// FIB — the forwarding-plane sink
// ===========================================================================

/// An error installing a route into the forwarding plane.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct FibError(pub String);

impl fmt::Display for FibError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "fib error: {}", self.0)
    }
}

impl std::error::Error for FibError {}

/// A sink for [`FibChange`]s — the forwarding plane the RIB drives. A real
/// implementation programs the kernel routing table (netlink); [`MemoryFib`] is
/// an in-memory stand-in for tests and `--dry-run`.
pub trait Fib {
    /// Apply one change.
    fn apply(&mut self, change: &FibChange) -> Result<(), FibError>;

    /// Apply many changes in order (default: one-by-one).
    fn apply_all(&mut self, changes: &[FibChange]) -> Result<(), FibError> {
        for c in changes {
            self.apply(c)?;
        }
        Ok(())
    }

    /// The routes this forwarding plane currently holds that *this daemon* could
    /// have installed itself (i.e. owns). Read at startup to reconcile away routes
    /// a previous instance left behind. The default returns none — a plane with no
    /// readback; [`MemoryFib`] returns what it has recorded, and the kernel backend
    /// returns the kernel routes tagged with Wren's own protocol ids.
    fn owned_routes(&mut self) -> Result<Vec<Route>, FibError> {
        Ok(Vec::new())
    }
}

/// An in-memory [`Fib`] that simply records the currently-installed best route
/// per prefix. Useful for `--dry-run` and as the assertion target in tests.
#[derive(Clone, Default)]
pub struct MemoryFib {
    /// The installed route per `(table, prefix)` — so the same prefix in two VRFs is
    /// tracked independently.
    pub installed: BTreeMap<(u32, Prefix), Route>,
}

impl Fib for MemoryFib {
    fn apply(&mut self, change: &FibChange) -> Result<(), FibError> {
        match change {
            FibChange::Install(r) => {
                self.installed.insert((r.table, r.prefix), r.clone());
            }
            FibChange::Remove { table, prefix } => {
                self.installed.remove(&(*table, *prefix));
            }
        }
        Ok(())
    }

    fn owned_routes(&mut self) -> Result<Vec<Route>, FibError> {
        Ok(self.installed.values().cloned().collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(s: &str) -> Prefix {
        s.parse().unwrap()
    }
    fn gw(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn prefix_normalises_host_bits() {
        assert_eq!(p("10.0.0.5/24"), p("10.0.0.0/24"));
        assert_eq!(p("10.0.0.0/24").to_string(), "10.0.0.0/24");
        assert_eq!(p("2001:db8::1/32"), p("2001:db8::/32"));
        assert!(p("0.0.0.0/0").is_default());
    }

    #[test]
    fn prefix_rejects_overlong_and_malformed() {
        assert!(Prefix::new(gw("10.0.0.0"), 33).is_err());
        assert!("10.0.0.0".parse::<Prefix>().is_err());
        assert!("10.0.0.0/x".parse::<Prefix>().is_err());
        assert!("nope/24".parse::<Prefix>().is_err());
    }

    #[test]
    fn prefix_contains_matches_only_same_family_network() {
        let net = p("10.1.2.0/24");
        assert!(net.contains(gw("10.1.2.200")));
        assert!(!net.contains(gw("10.1.3.1")));
        assert!(!net.contains(gw("::1"))); // different family
        assert!(p("0.0.0.0/0").contains(gw("8.8.8.8")));
    }

    #[test]
    fn protocol_preferences_order_connected_static_igp_bgp() {
        assert!(
            Protocol::Connected.default_preference() > Protocol::Static.default_preference()
        );
        assert!(Protocol::Static.default_preference() > Protocol::Rip.default_preference());
        assert!(Protocol::Ospf.default_preference() > Protocol::Bgp.default_preference());
    }

    #[test]
    fn rib_installs_first_route_and_picks_best_on_contention() {
        let mut rib = Rib::new();
        let dst = p("10.0.0.0/24");

        // First route → install.
        let rip = Route::new(dst, Protocol::Rip, vec![NextHop::via(gw("192.0.2.1"))], 5);
        let change = rib.update(rip).unwrap();
        assert!(matches!(change, FibChange::Install(ref r) if r.protocol == Protocol::Rip));

        // A static route (higher preference) supersedes it → install the static.
        let stat = Route::new(dst, Protocol::Static, vec![NextHop::via(gw("192.0.2.254"))], 0);
        let change = rib.update(stat).unwrap();
        assert!(matches!(change, FibChange::Install(ref r) if r.protocol == Protocol::Static));

        // A worse BGP route changes nothing (static still best).
        let bgp = Route::new(dst, Protocol::Bgp, vec![NextHop::via(gw("192.0.2.9"))], 0);
        assert!(rib.update(bgp).is_none());

        assert_eq!(rib.best(&dst).unwrap().protocol, Protocol::Static);
    }

    #[test]
    fn rib_metric_breaks_preference_ties() {
        let mut rib = Rib::new();
        let dst = p("203.0.113.0/24");
        rib.update(Route {
            source: 1,
            ..Route::new(dst, Protocol::Rip, vec![NextHop::via(gw("198.51.100.1"))], 10)
        });
        let better = rib
            .update(Route {
                source: 2,
                ..Route::new(dst, Protocol::Rip, vec![NextHop::via(gw("198.51.100.2"))], 3)
            })
            .unwrap();
        assert!(matches!(better, FibChange::Install(ref r) if r.metric == 3));
    }

    #[test]
    fn rib_withdraw_falls_back_then_removes() {
        let mut rib = Rib::new();
        let dst = p("10.0.0.0/24");
        rib.update(Route::new(dst, Protocol::Static, vec![NextHop::via(gw("192.0.2.1"))], 0));
        rib.update(Route::new(dst, Protocol::Rip, vec![NextHop::via(gw("192.0.2.2"))], 5));

        // Withdraw the static → RIP becomes best (install change).
        let change = rib.withdraw(RT_TABLE_MAIN, dst, Protocol::Static, 0).unwrap();
        assert!(matches!(change, FibChange::Install(ref r) if r.protocol == Protocol::Rip));

        // Withdraw the last route → remove.
        assert_eq!(rib.withdraw(RT_TABLE_MAIN, dst, Protocol::Rip, 0).unwrap(), FibChange::Remove { table: RT_TABLE_MAIN, prefix: dst });
        assert!(rib.is_empty());
    }

    #[test]
    fn memory_fib_tracks_installs_and_removes() {
        let mut rib = Rib::new();
        let mut fib = MemoryFib::default();
        let dst = p("10.9.0.0/16");
        if let Some(c) = rib.update(Route::new(dst, Protocol::Static, vec![NextHop::dev("eth0")], 0))
        {
            fib.apply(&c).unwrap();
        }
        assert_eq!(fib.installed.len(), 1);
        if let Some(c) = rib.withdraw(RT_TABLE_MAIN, dst, Protocol::Static, 0) {
            fib.apply(&c).unwrap();
        }
        assert!(fib.installed.is_empty());
    }
}
