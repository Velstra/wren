//! # wren-rip — RIPv2 (RFC 2453)
//!
//! The Routing Information Protocol, version 2. This module is the **wire
//! codec** — encoding and decoding the on-the-wire message exactly as RFC 2453
//! §4 lays it out — plus the glue that turns a received route entry into a
//! [`wren_core::Route`]. It is deliberately transport-free and `std`-only; the
//! UDP socket, the distance-vector update logic and the timers (a follow-up,
//! [`UPDATE_SECS`]/[`TIMEOUT_SECS`]/[`GARBAGE_SECS`]) live in the daemon on top.
//!
//! ## Message format (RFC 2453 §4)
//!
//! ```text
//!  0                   1                   2                   3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |  command (1)  |  version (1)  |       must be zero (2)        |
//! +---------------+---------------+-------------------------------+
//! | ~ up to 25 route table entries (20 octets each) ~            |
//! ```
//!
//! Each route table entry (RTE):
//!
//! ```text
//! | address family identifier (2) |        route tag (2)          |
//! |                         IPv4 address (4)                      |
//! |                          subnet mask (4)                      |
//! |                          next hop (4)                         |
//! |                           metric (4)                          |
//! ```

#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr};

use wren_core::{NextHop, Prefix, Protocol, Route};

pub mod ng;

/// The well-known UDP port RIP listens on (RFC 2453 §3.1).
pub const PORT: u16 = 520;
/// RIP version 2.
pub const VERSION_2: u8 = 2;
/// Address Family Identifier for IPv4 in an RTE.
pub const AF_INET: u16 = 2;
/// The metric meaning "unreachable" (RFC 2453 §3.1): 16 = infinity.
pub const METRIC_INFINITY: u32 = 16;
/// The maximum number of RTEs in one datagram (RFC 2453 §4).
pub const MAX_ENTRIES: usize = 25;
/// Fixed message header length, octets.
pub const HEADER_LEN: usize = 4;
/// One RTE's length, octets.
pub const ENTRY_LEN: usize = 20;

/// Default update timer (RFC 2453 §3.8), seconds.
pub const UPDATE_SECS: u64 = 30;
/// Default route timeout (RFC 2453 §3.8), seconds.
pub const TIMEOUT_SECS: u64 = 180;
/// Default garbage-collection timer (RFC 2453 §3.8), seconds.
pub const GARBAGE_SECS: u64 = 120;

/// The RIP command: a request for routes, or a response carrying them.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Command {
    /// Ask a neighbour for (some or all of) its routes.
    Request,
    /// Advertise routes (solicited or a periodic/triggered update).
    Response,
}

impl Command {
    pub(crate) fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(Command::Request),
            2 => Some(Command::Response),
            _ => None,
        }
    }
    pub(crate) fn as_u8(self) -> u8 {
        match self {
            Command::Request => 1,
            Command::Response => 2,
        }
    }
}

/// One route table entry as carried on the wire.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Entry {
    /// Address family (2 = IPv4; 0 in the "give me everything" request).
    pub family: u16,
    /// Route tag, used to carry an attribute across the RIP domain (RFC 2453 §4).
    pub tag: u16,
    /// Destination IPv4 address.
    pub addr: Ipv4Addr,
    /// Subnet mask (RIPv2 is classless).
    pub mask: Ipv4Addr,
    /// Next hop; `0.0.0.0` means "use the originator of this datagram".
    pub next_hop: Ipv4Addr,
    /// Metric, 1..=16 (16 = infinity / unreachable).
    pub metric: u32,
}

impl Entry {
    /// An IPv4 route entry with no tag and an implicit next hop.
    pub fn route(addr: Ipv4Addr, mask: Ipv4Addr, metric: u32) -> Self {
        Self {
            family: AF_INET,
            tag: 0,
            addr,
            mask,
            next_hop: Ipv4Addr::UNSPECIFIED,
            metric,
        }
    }

    /// The prefix length implied by `mask`, if it is a valid contiguous netmask.
    pub fn prefix_len(&self) -> Option<u8> {
        netmask_to_len(self.mask)
    }

    /// The destination as a [`Prefix`], if the mask is a valid netmask.
    pub fn prefix(&self) -> Option<Prefix> {
        Prefix::new(IpAddr::V4(self.addr), self.prefix_len()?).ok()
    }

    /// Whether this entry advertises an unreachable route (metric ≥ 16).
    pub fn is_infinity(&self) -> bool {
        self.metric >= METRIC_INFINITY
    }

    /// Convert a received entry into a core [`Route`]. `learned_from` is the
    /// neighbour that sent the datagram (used when `next_hop` is unspecified, per
    /// RFC 2453 §4); `source` distinguishes neighbours in the RIB. Returns `None`
    /// for a non-IPv4 entry or an invalid netmask.
    pub fn to_route(&self, learned_from: Ipv4Addr, source: u64) -> Option<Route> {
        if self.family != AF_INET {
            return None;
        }
        let prefix = self.prefix()?;
        let gw = if self.next_hop.is_unspecified() {
            learned_from
        } else {
            self.next_hop
        };
        let mut r = Route::new(
            prefix,
            Protocol::Rip,
            vec![NextHop::via(IpAddr::V4(gw))],
            self.metric,
        );
        r.source = source;
        Some(r)
    }
}

/// A full RIP message: a header plus its route entries.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Message {
    /// Request or Response.
    pub command: Command,
    /// Protocol version (2 for RIPv2).
    pub version: u8,
    /// The route table entries.
    pub entries: Vec<Entry>,
}

/// Why a RIP datagram could not be decoded.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum RipError {
    /// Shorter than the 4-octet header.
    TooShort,
    /// The body length is not a whole number of 20-octet RTEs.
    BadLength(usize),
    /// The command byte was neither Request (1) nor Response (2).
    UnknownCommand(u8),
}

impl fmt::Display for RipError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RipError::TooShort => write!(f, "datagram shorter than the RIP header"),
            RipError::BadLength(n) => write!(f, "RIP body of {n} octets is not a multiple of 20"),
            RipError::UnknownCommand(c) => write!(f, "unknown RIP command {c}"),
        }
    }
}

impl std::error::Error for RipError {}

impl Message {
    /// A Response carrying `entries`.
    pub fn response(entries: Vec<Entry>) -> Self {
        Self {
            command: Command::Response,
            version: VERSION_2,
            entries,
        }
    }

    /// The special "send me your whole table" request (RFC 2453 §3.9.1): a single
    /// RTE with address family 0 and metric = infinity.
    pub fn request_full_table() -> Self {
        Self {
            command: Command::Request,
            version: VERSION_2,
            entries: vec![Entry {
                family: 0,
                tag: 0,
                addr: Ipv4Addr::UNSPECIFIED,
                mask: Ipv4Addr::UNSPECIFIED,
                next_hop: Ipv4Addr::UNSPECIFIED,
                metric: METRIC_INFINITY,
            }],
        }
    }

    /// Whether this is the whole-table request above.
    pub fn is_full_table_request(&self) -> bool {
        self.command == Command::Request
            && self.entries.len() == 1
            && self.entries[0].family == 0
            && self.entries[0].metric == METRIC_INFINITY
    }

    /// Encode to the on-the-wire octets.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HEADER_LEN + self.entries.len() * ENTRY_LEN);
        out.push(self.command.as_u8());
        out.push(self.version);
        out.extend_from_slice(&[0, 0]); // must be zero
        for e in &self.entries {
            out.extend_from_slice(&e.family.to_be_bytes());
            out.extend_from_slice(&e.tag.to_be_bytes());
            out.extend_from_slice(&e.addr.octets());
            out.extend_from_slice(&e.mask.octets());
            out.extend_from_slice(&e.next_hop.octets());
            out.extend_from_slice(&e.metric.to_be_bytes());
        }
        out
    }

    /// Decode from on-the-wire octets. Validates the header and that the body is
    /// a whole number of RTEs; entry-level semantics (metric range, family) are
    /// left to the protocol logic, which per RFC 2453 §3.9.2 ignores bad RTEs
    /// rather than dropping the whole datagram.
    pub fn decode(buf: &[u8]) -> Result<Self, RipError> {
        if buf.len() < HEADER_LEN {
            return Err(RipError::TooShort);
        }
        let command = Command::from_u8(buf[0]).ok_or(RipError::UnknownCommand(buf[0]))?;
        let version = buf[1];
        let body = &buf[HEADER_LEN..];
        if body.len() % ENTRY_LEN != 0 {
            return Err(RipError::BadLength(body.len()));
        }
        let mut entries = Vec::with_capacity(body.len() / ENTRY_LEN);
        for chunk in body.chunks_exact(ENTRY_LEN) {
            entries.push(Entry {
                family: u16::from_be_bytes([chunk[0], chunk[1]]),
                tag: u16::from_be_bytes([chunk[2], chunk[3]]),
                addr: Ipv4Addr::new(chunk[4], chunk[5], chunk[6], chunk[7]),
                mask: Ipv4Addr::new(chunk[8], chunk[9], chunk[10], chunk[11]),
                next_hop: Ipv4Addr::new(chunk[12], chunk[13], chunk[14], chunk[15]),
                metric: u32::from_be_bytes([chunk[16], chunk[17], chunk[18], chunk[19]]),
            });
        }
        Ok(Self {
            command,
            version,
            entries,
        })
    }
}

/// Convert a contiguous IPv4 netmask to its prefix length. Returns `None` for a
/// non-contiguous mask (e.g. `255.0.255.0`), which is not a valid netmask.
pub fn netmask_to_len(mask: Ipv4Addr) -> Option<u8> {
    let bits = u32::from(mask);
    let ones = bits.leading_ones();
    // A valid netmask is `ones` set bits followed by all zeros.
    let expected = if ones == 0 { 0 } else { u32::MAX << (32 - ones) };
    if bits == expected {
        Some(ones as u8)
    } else {
        None
    }
}

/// Convert a prefix length to an IPv4 netmask.
pub fn len_to_netmask(len: u8) -> Ipv4Addr {
    let bits = if len == 0 {
        0
    } else {
        u32::MAX << (32 - len as u32)
    };
    Ipv4Addr::from(bits)
}

// ===========================================================================
// The RIP routing table — distance-vector logic (RFC 2453 §3.9 / §3.10)
// ===========================================================================

/// What RIP wants reflected in the global RIB when its best route to a prefix
/// changes. RIP resolves its own neighbours internally and presents exactly one
/// route per prefix to [`wren_core::Rib`].
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum RipEvent {
    /// RIP's best route to this prefix — announce/replace it in the RIB.
    Learned(Route),
    /// RIP no longer has a usable route to this prefix — withdraw it.
    Lost(Prefix),
}

/// One route as RIP would advertise it (after split horizon): the destination
/// and the metric to reach it through us. The distance-vector engine is address-
/// family-neutral, so each variant's codec formats this into its own wire RTE —
/// a RIPv2 [`Entry`] (IPv4) or a RIPng RTE (IPv6).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Advert {
    /// The destination network.
    pub prefix: Prefix,
    /// The advertised metric (`METRIC_INFINITY` when poisoned by split horizon).
    pub metric: u32,
}

/// One entry in RIP's own routing table.
#[derive(Clone, Debug)]
struct RipRoute {
    /// Current metric (1..=16; 16 = unreachable, pending garbage collection).
    metric: u32,
    /// The gateway we forward through (the neighbour, or its advertised next hop).
    next_hop: IpAddr,
    /// The interface the route was learned on — drives split horizon.
    ifindex: u32,
    /// Logical-seconds deadline for the route timeout (RFC 2453 §3.8).
    expire_at: u64,
    /// Set once the route entered garbage collection; the deletion deadline.
    delete_at: Option<u64>,
    /// The route-change flag, for triggered updates (RFC 2453 §3.10.1).
    changed: bool,
    /// True for a directly-connected network: it never times out and no RIP
    /// advertisement from a neighbour can replace it.
    connected: bool,
    /// True for a route redistributed from another protocol (via the RIB). Like a
    /// connected route it is "ours" — immune to a neighbour's advertisement — but
    /// unlike connected it does not auto-expire, and it can be explicitly withdrawn
    /// (poisoned, then garbage-collected) when its source goes away.
    redistributed: bool,
}

/// RIP's distance-vector routing table.
///
/// All of the protocol's decision logic lives here and is **pure**: time is
/// supplied by the caller (`now`, in seconds) rather than read from a clock, so
/// the metric arithmetic, the timeout/garbage state machine and split horizon
/// are fully unit-testable. The async runner feeds it real time and real packets
/// and forwards the resulting [`RipEvent`]s to the RIB.
#[derive(Default)]
pub struct RipTable {
    routes: BTreeMap<Prefix, RipRoute>,
}

impl RipTable {
    /// An empty table.
    pub fn new() -> Self {
        Self::default()
    }

    /// Process one received RIPv2 route entry from neighbour `from` on interface
    /// `ifindex` at time `now` (RFC 2453 §3.9.2). A thin wrapper over the address-
    /// neutral [`process_route`](Self::process_route); RIPng calls that directly.
    pub fn process(
        &mut self,
        entry: &Entry,
        from: Ipv4Addr,
        ifindex: u32,
        now: u64,
    ) -> Option<RipEvent> {
        if entry.family != AF_INET {
            return None;
        }
        let prefix = entry.prefix()?; // ignore an invalid netmask
        let next_hop = if entry.next_hop.is_unspecified() {
            None
        } else {
            Some(IpAddr::V4(entry.next_hop))
        };
        self.process_route(prefix, entry.metric, next_hop, IpAddr::V4(from), ifindex, now)
    }

    /// Process a received distance-vector route, independent of wire format
    /// (RFC 2453 §3.9.2 / RFC 2080 §2.4.2): `recv_metric` is the metric as
    /// advertised (we add 1), `next_hop` is the advertised gateway or `None` to
    /// use `from` (the neighbour that sent the datagram). Returns a [`RipEvent`]
    /// when the best route to `prefix` changed.
    pub fn process_route(
        &mut self,
        prefix: Prefix,
        recv_metric: u32,
        next_hop: Option<IpAddr>,
        from: IpAddr,
        ifindex: u32,
        now: u64,
    ) -> Option<RipEvent> {
        // metric = min(received + 1, infinity) — the cost to reach it through us.
        let metric = (recv_metric + 1).min(METRIC_INFINITY);
        let nh = next_hop.unwrap_or(from);

        match self.routes.get_mut(&prefix) {
            None => {
                if metric >= METRIC_INFINITY {
                    return None; // never add an unreachable route
                }
                self.routes.insert(
                    prefix,
                    RipRoute {
                        metric,
                        next_hop: nh,
                        ifindex,
                        expire_at: now + TIMEOUT_SECS,
                        delete_at: None,
                        changed: true,
                        connected: false,
                        redistributed: false,
                    },
                );
                Some(RipEvent::Learned(rip_to_core(prefix, metric, nh)))
            }
            Some(r) => {
                // A connected or redistributed network is ours; no neighbour's
                // advertisement can replace it.
                if r.connected || r.redistributed {
                    return None;
                }
                let same_source = r.next_hop == nh && r.ifindex == ifindex;
                if same_source {
                    // The current best source re-advertised: always trust it.
                    if metric < METRIC_INFINITY {
                        r.expire_at = now + TIMEOUT_SECS;
                        r.delete_at = None;
                    }
                    if metric == r.metric {
                        return None;
                    }
                    r.metric = metric;
                    r.changed = true;
                    if metric >= METRIC_INFINITY {
                        r.delete_at = Some(now + GARBAGE_SECS);
                        Some(RipEvent::Lost(prefix))
                    } else {
                        Some(RipEvent::Learned(rip_to_core(prefix, metric, nh)))
                    }
                } else if metric < r.metric {
                    // A different neighbour offers a strictly better path: adopt it.
                    r.metric = metric;
                    r.next_hop = nh;
                    r.ifindex = ifindex;
                    r.expire_at = now + TIMEOUT_SECS;
                    r.delete_at = None;
                    r.changed = true;
                    Some(RipEvent::Learned(rip_to_core(prefix, metric, nh)))
                } else {
                    None
                }
            }
        }
    }

    /// Inject a directly-connected network on interface `ifindex` (e.g. an
    /// interface's own subnet) so RIP advertises it to neighbours. It is held at
    /// the interface cost (metric 1), never expires, and is immune to being
    /// replaced by a learned route. Re-injecting the same prefix refreshes it.
    pub fn add_connected(&mut self, prefix: Prefix, ifindex: u32) {
        // "via me": an unspecified next hop of the prefix's own family. It is only
        // a sentinel — connected routes are always advertised with next-hop self
        // and are immune in `process_route`, so its exact value never matters.
        let next_hop = if prefix.is_ipv4() {
            IpAddr::V4(Ipv4Addr::UNSPECIFIED)
        } else {
            IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED)
        };
        self.routes.insert(
            prefix,
            RipRoute {
                metric: 1,
                next_hop,
                ifindex,
                expire_at: u64::MAX,
                delete_at: None,
                changed: true,
                connected: true,
                redistributed: false,
            },
        );
    }

    /// Inject a route redistributed from another protocol (via the RIB) so RIP
    /// advertises it to neighbours at `metric` (clamped to 1..=15). Like a
    /// connected route it is "ours" — immune to a neighbour's advertisement and it
    /// never times out on its own — but it can be withdrawn via
    /// [`withdraw_redistributed`](Self::withdraw_redistributed). Re-injecting the
    /// same prefix refreshes it. A connected network already advertised as ours is
    /// left untouched (it takes precedence).
    pub fn add_redistributed(&mut self, prefix: Prefix, metric: u32) {
        if self.routes.get(&prefix).is_some_and(|r| r.connected) {
            return;
        }
        let metric = metric.clamp(1, METRIC_INFINITY - 1);
        // "via me": an unspecified next hop of the prefix's own family — only a
        // sentinel, since redistributed routes are advertised with next-hop self.
        let next_hop = if prefix.is_ipv4() {
            IpAddr::V4(Ipv4Addr::UNSPECIFIED)
        } else {
            IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED)
        };
        self.routes.insert(
            prefix,
            RipRoute {
                metric,
                next_hop,
                ifindex: 0, // not tied to an interface → never split-horizon-poisoned
                expire_at: u64::MAX, // never times out on its own
                delete_at: None,
                changed: true,
                connected: false,
                redistributed: true,
            },
        );
    }

    /// Withdraw a route previously added with
    /// [`add_redistributed`](Self::add_redistributed): poison it (metric 16) and
    /// start the garbage timer, so neighbours are told it is gone on the next
    /// (triggered) update and it is removed after `GARBAGE_SECS`. A no-op unless
    /// `prefix` is a redistributed route still reachable.
    pub fn withdraw_redistributed(&mut self, prefix: &Prefix, now: u64) {
        if let Some(r) = self.routes.get_mut(prefix) {
            if r.redistributed && r.metric < METRIC_INFINITY {
                r.metric = METRIC_INFINITY;
                r.delete_at = Some(now + GARBAGE_SECS);
                r.changed = true;
            }
        }
    }

    /// Advance the timers to `now`: a route past its timeout becomes unreachable
    /// (metric 16, garbage timer started); a route past its garbage deadline is
    /// removed. Returns the RIB events for the changes.
    pub fn tick(&mut self, now: u64) -> Vec<RipEvent> {
        let mut events = Vec::new();
        let mut remove = Vec::new();
        for (prefix, r) in self.routes.iter_mut() {
            if r.connected {
                continue; // connected routes never expire
            }
            match r.delete_at {
                Some(del) if now >= del => remove.push(*prefix),
                None if now >= r.expire_at => {
                    r.metric = METRIC_INFINITY;
                    r.delete_at = Some(now + GARBAGE_SECS);
                    r.changed = true;
                    events.push(RipEvent::Lost(*prefix));
                }
                _ => {}
            }
        }
        for p in remove {
            self.routes.remove(&p);
            events.push(RipEvent::Lost(p));
        }
        events
    }

    /// The routes to advertise out interface `out_ifindex`, applying **split
    /// horizon with poisoned reverse** (RFC 2453 §3.9 / RFC 2080 §2.6): a route
    /// learned on that interface is advertised back with metric = infinity. The
    /// address-neutral form used by both RIPv2 and RIPng.
    pub fn adverts(&self, out_ifindex: u32) -> Vec<Advert> {
        self.routes
            .iter()
            .map(|(prefix, r)| advert_for(prefix, r, out_ifindex))
            .collect()
    }

    /// The changed routes for a triggered update (RFC 2453 §3.10.1), with the same
    /// split horizon as [`adverts`](Self::adverts). Does not clear the change
    /// flags — call [`clear_changed`](Self::clear_changed) once after sending on
    /// every interface.
    pub fn triggered_adverts(&self, out_ifindex: u32) -> Vec<Advert> {
        self.routes
            .iter()
            .filter(|(_, r)| r.changed)
            .map(|(prefix, r)| advert_for(prefix, r, out_ifindex))
            .collect()
    }

    /// [`adverts`](Self::adverts) formatted as RIPv2 wire entries (IPv4 only).
    pub fn advertise(&self, out_ifindex: u32) -> Vec<Entry> {
        self.adverts(out_ifindex).iter().filter_map(entry_for).collect()
    }

    /// [`triggered_adverts`](Self::triggered_adverts) as RIPv2 wire entries.
    pub fn triggered(&self, out_ifindex: u32) -> Vec<Entry> {
        self.triggered_adverts(out_ifindex)
            .iter()
            .filter_map(entry_for)
            .collect()
    }

    /// Whether any route is flagged changed (a triggered update is pending).
    pub fn has_changes(&self) -> bool {
        self.routes.values().any(|r| r.changed)
    }

    /// Clear every route-change flag (after an update has been sent everywhere).
    pub fn clear_changed(&mut self) {
        for r in self.routes.values_mut() {
            r.changed = false;
        }
    }

    /// Number of routes (including those in garbage collection).
    pub fn len(&self) -> usize {
        self.routes.len()
    }

    /// Whether the table is empty.
    pub fn is_empty(&self) -> bool {
        self.routes.is_empty()
    }
}

/// Build the core [`Route`] RIP presents to the RIB for a prefix.
fn rip_to_core(prefix: Prefix, metric: u32, nh: IpAddr) -> Route {
    Route::new(prefix, Protocol::Rip, vec![NextHop::via(nh)], metric)
}

/// Build the advertisement for a route out of `out_ifindex`, applying poisoned
/// reverse (a route learned on the egress interface is advertised unreachable).
fn advert_for(prefix: &Prefix, r: &RipRoute, out_ifindex: u32) -> Advert {
    let metric = if r.ifindex == out_ifindex {
        METRIC_INFINITY
    } else {
        r.metric
    };
    Advert {
        prefix: *prefix,
        metric,
    }
}

/// Format an [`Advert`] as a RIPv2 wire entry. Returns `None` for a non-IPv4
/// prefix (RIPv2 carries IPv4 only; IPv6 prefixes belong to RIPng).
fn entry_for(advert: &Advert) -> Option<Entry> {
    let IpAddr::V4(addr) = advert.prefix.addr() else {
        return None;
    };
    Some(Entry {
        family: AF_INET,
        tag: 0,
        addr,
        mask: len_to_netmask(advert.prefix.len()),
        next_hop: Ipv4Addr::UNSPECIFIED,
        metric: advert.metric,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn netmask_roundtrips_and_rejects_noncontiguous() {
        assert_eq!(netmask_to_len(Ipv4Addr::new(255, 255, 255, 0)), Some(24));
        assert_eq!(netmask_to_len(Ipv4Addr::new(0, 0, 0, 0)), Some(0));
        assert_eq!(netmask_to_len(Ipv4Addr::new(255, 255, 255, 255)), Some(32));
        assert_eq!(netmask_to_len(Ipv4Addr::new(255, 0, 255, 0)), None);
        assert_eq!(len_to_netmask(24), Ipv4Addr::new(255, 255, 255, 0));
        assert_eq!(len_to_netmask(0), Ipv4Addr::UNSPECIFIED);
    }

    #[test]
    fn response_round_trips_on_the_wire() {
        let msg = Message::response(vec![
            Entry::route(Ipv4Addr::new(10, 0, 0, 0), Ipv4Addr::new(255, 255, 255, 0), 1),
            Entry::route(Ipv4Addr::new(192, 168, 1, 0), Ipv4Addr::new(255, 255, 255, 0), 5),
        ]);
        let bytes = msg.encode();
        assert_eq!(bytes.len(), HEADER_LEN + 2 * ENTRY_LEN);
        assert_eq!(&bytes[0..4], &[2, 2, 0, 0]); // response, v2, zero
        let back = Message::decode(&bytes).unwrap();
        assert_eq!(back, msg);
    }

    #[test]
    fn full_table_request_is_well_formed() {
        let req = Message::request_full_table();
        assert!(req.is_full_table_request());
        let bytes = req.encode();
        assert_eq!(bytes.len(), HEADER_LEN + ENTRY_LEN);
        assert_eq!(bytes[0], 1); // request
        // family 0, metric 16 at the end of the single RTE.
        assert_eq!(&bytes[4..6], &[0, 0]);
        assert_eq!(&bytes[20..24], &16u32.to_be_bytes());
        assert!(Message::decode(&bytes).unwrap().is_full_table_request());
    }

    #[test]
    fn decode_rejects_short_and_misaligned_and_bad_command() {
        assert_eq!(Message::decode(&[2, 2, 0]), Err(RipError::TooShort));
        assert_eq!(Message::decode(&[2, 2, 0, 0, 1, 2, 3]), Err(RipError::BadLength(3)));
        assert_eq!(Message::decode(&[9, 2, 0, 0]), Err(RipError::UnknownCommand(9)));
    }

    #[test]
    fn entry_converts_to_a_core_route() {
        let e = Entry::route(Ipv4Addr::new(10, 0, 0, 0), Ipv4Addr::new(255, 255, 0, 0), 3);
        let r = e.to_route(Ipv4Addr::new(192, 0, 2, 1), 7).unwrap();
        assert_eq!(r.prefix.to_string(), "10.0.0.0/16");
        assert_eq!(r.protocol, Protocol::Rip);
        assert_eq!(r.metric, 3);
        assert_eq!(r.source, 7);
        // Unspecified next hop falls back to the datagram's originator.
        assert_eq!(r.nexthops[0].gateway, Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))));
    }

    // --- RIP table (distance-vector) tests ---

    fn net(addr: [u8; 4], len: u8, metric: u32) -> Entry {
        Entry::route(Ipv4Addr::from(addr), len_to_netmask(len), metric)
    }

    fn metric_of(entries: &[Entry], addr: [u8; 4]) -> Option<u32> {
        entries
            .iter()
            .find(|e| e.addr == Ipv4Addr::from(addr))
            .map(|e| e.metric)
    }

    #[test]
    fn learning_increments_metric_and_split_horizon_poisons() {
        let mut t = RipTable::new();
        let from = Ipv4Addr::new(192, 0, 2, 1);
        let ev = t.process(&net([10, 0, 0, 0], 24, 1), from, 2, 0).unwrap();
        match ev {
            RipEvent::Learned(r) => {
                assert_eq!(r.metric, 2); // received 1 + 1
                assert_eq!(r.prefix.to_string(), "10.0.0.0/24");
            }
            other => panic!("expected Learned, got {other:?}"),
        }
        // Out the learning interface (2): poisoned reverse → metric 16.
        assert_eq!(metric_of(&t.advertise(2), [10, 0, 0, 0]), Some(16));
        // Out a different interface (3): the real metric.
        assert_eq!(metric_of(&t.advertise(3), [10, 0, 0, 0]), Some(2));
    }

    #[test]
    fn unreachable_is_not_learned_fresh() {
        let mut t = RipTable::new();
        // metric 16 received → 17 capped to 16 → never installed.
        assert!(t.process(&net([10, 0, 0, 0], 24, 16), Ipv4Addr::new(192, 0, 2, 1), 2, 0).is_none());
        assert!(t.is_empty());
    }

    #[test]
    fn same_source_is_trusted_even_when_worse() {
        let mut t = RipTable::new();
        let a = Ipv4Addr::new(192, 0, 2, 1);
        t.process(&net([10, 0, 0, 0], 24, 1), a, 2, 0); // metric 2
        // The same neighbour now advertises a worse metric — trust it.
        let ev = t.process(&net([10, 0, 0, 0], 24, 4), a, 2, 10).unwrap();
        assert!(matches!(ev, RipEvent::Learned(ref r) if r.metric == 5));
    }

    #[test]
    fn better_neighbour_replaces_worse() {
        let mut t = RipTable::new();
        let a = Ipv4Addr::new(192, 0, 2, 1);
        let b = Ipv4Addr::new(192, 0, 2, 2);
        t.process(&net([10, 0, 0, 0], 24, 5), a, 2, 0); // metric 6 via A
        let ev = t.process(&net([10, 0, 0, 0], 24, 2), b, 2, 0).unwrap(); // metric 3 via B
        assert!(matches!(ev, RipEvent::Learned(ref r)
            if r.metric == 3 && r.nexthops[0].gateway == Some(IpAddr::V4(b))));
        // A worse offer from a third source is ignored.
        let c = Ipv4Addr::new(192, 0, 2, 3);
        assert!(t.process(&net([10, 0, 0, 0], 24, 9), c, 2, 0).is_none());
    }

    #[test]
    fn timeout_then_garbage_collection() {
        let mut t = RipTable::new();
        t.process(&net([10, 0, 0, 0], 24, 1), Ipv4Addr::new(192, 0, 2, 1), 2, 0);
        // Before the timeout: nothing happens.
        assert!(t.tick(TIMEOUT_SECS - 1).is_empty());
        // At the timeout: the route goes unreachable (Lost) and is poisoned.
        let ev = t.tick(TIMEOUT_SECS);
        assert_eq!(ev, vec![RipEvent::Lost("10.0.0.0/24".parse().unwrap())]);
        assert_eq!(metric_of(&t.advertise(3), [10, 0, 0, 0]), Some(16));
        // At the garbage deadline: it is removed.
        let _ = t.tick(TIMEOUT_SECS + GARBAGE_SECS);
        assert!(t.is_empty());
    }

    #[test]
    fn connected_network_is_advertised_with_split_horizon() {
        let mut t = RipTable::new();
        t.add_connected("10.0.0.0/24".parse().unwrap(), 2);
        // Advertised at the interface cost (1) everywhere except back out its own
        // interface, where poisoned reverse makes it unreachable (16).
        assert_eq!(metric_of(&t.advertise(3), [10, 0, 0, 0]), Some(1));
        assert_eq!(metric_of(&t.advertise(2), [10, 0, 0, 0]), Some(16));
        // It is offered to the RIB as a triggered change immediately.
        assert!(t.has_changes());
    }

    #[test]
    fn connected_network_is_immune_to_neighbours_and_timers() {
        let mut t = RipTable::new();
        t.add_connected("10.0.0.0/24".parse().unwrap(), 2);
        // A neighbour advertising the same prefix cannot displace it.
        let nbr = Ipv4Addr::new(10, 0, 0, 2);
        assert!(t.process(&net([10, 0, 0, 0], 24, 1), nbr, 2, 0).is_none());
        // And it never expires, however far time advances.
        assert!(t.tick(u64::MAX - 1).is_empty());
        assert_eq!(metric_of(&t.advertise(3), [10, 0, 0, 0]), Some(1));
    }

    #[test]
    fn redistributed_route_is_advertised_at_its_metric_and_is_immune() {
        let mut t = RipTable::new();
        t.add_redistributed("192.0.2.0/24".parse().unwrap(), 5);
        // Not tied to an interface (ifindex 0) → advertised at metric 5 on every
        // interface, with no split-horizon poisoning.
        assert_eq!(metric_of(&t.advertise(2), [192, 0, 2, 0]), Some(5));
        assert_eq!(metric_of(&t.advertise(7), [192, 0, 2, 0]), Some(5));
        assert!(t.has_changes()); // offered as a triggered change immediately
        // A neighbour cannot displace it, and it never times out on its own.
        let nbr = Ipv4Addr::new(10, 0, 0, 2);
        assert!(t.process(&net([192, 0, 2, 0], 24, 1), nbr, 2, 0).is_none());
        assert!(t.tick(u64::MAX - 1).is_empty());
    }

    #[test]
    fn withdrawing_a_redistributed_route_poisons_then_garbage_collects() {
        let mut t = RipTable::new();
        let p = "192.0.2.0/24".parse().unwrap();
        t.add_redistributed(p, 2);
        t.clear_changed();

        // Withdraw at t=10: poisoned to metric 16 and flagged changed.
        t.withdraw_redistributed(&p, 10);
        assert!(t.has_changes());
        assert_eq!(metric_of(&t.advertise(2), [192, 0, 2, 0]), Some(16));

        // Still present (advertising the poison) until the garbage deadline, then
        // removed.
        assert!(t.tick(10 + GARBAGE_SECS - 1).is_empty());
        let ev = t.tick(10 + GARBAGE_SECS);
        assert_eq!(ev, vec![RipEvent::Lost(p)]);
        assert!(t.advertise(2).is_empty());
    }

    #[test]
    fn redistributing_a_connected_network_does_not_clobber_it() {
        let mut t = RipTable::new();
        let p = "10.0.0.0/24".parse().unwrap();
        t.add_connected(p, 2);
        // A redistributed announcement for the same prefix is ignored: connected
        // takes precedence (still split-horizoned on its own interface).
        t.add_redistributed(p, 9);
        assert_eq!(metric_of(&t.advertise(3), [10, 0, 0, 0]), Some(1));
        assert_eq!(metric_of(&t.advertise(2), [10, 0, 0, 0]), Some(16));
    }

    #[test]
    fn triggered_carries_only_changed_routes_until_cleared() {
        let mut t = RipTable::new();
        t.process(&net([10, 0, 0, 0], 24, 1), Ipv4Addr::new(192, 0, 2, 1), 2, 0);
        assert!(t.has_changes());
        assert_eq!(t.triggered(3).len(), 1);
        t.clear_changed();
        assert!(!t.has_changes());
        assert!(t.triggered(3).is_empty());
    }
}
