//! # The BGP-4 TCP session runner (RFC 4271)
//!
//! The async transport that turns the pure `wren-bgp` library (the message and
//! path-attribute wire codec, the §9 decision process, the §3.2 RIBs and the §8
//! session FSM) into a live BGP speaker. Every protocol *decision* lives in the
//! library; this module does the I/O and sequencing the library cannot:
//!
//! * one TCP connection per peer — actively dialled (port 179) for normal peers,
//!   or accepted from a listener for `passive` peers — with length-prefixed
//!   message framing (a 19-byte header carries the length, then the body);
//! * the OPEN negotiation (AS check, Hold Time = `min(ours, theirs)`), the
//!   Keepalive (Hold/3) and Hold timers, all driving the per-peer [`BgpFsm`];
//! * executing the FSM's [`Action`]s — send OPEN/KEEPALIVE/NOTIFICATION, arm the
//!   timers, signal the session up/down;
//! * advertising this speaker's originated networks on reaching Established, and
//!   feeding received UPDATEs into the shared [`BgpRib`], whose best-path changes
//!   are announced to the central router (RIB).
//!
//! Per-peer session tasks own their socket and FSM; a single central task owns the
//! [`BgpRib`] and serialises every Loc-RIB change into a [`RouteUpdate`]. Binding
//! the listener on port 179 needs `CAP_NET_BIND_SERVICE` (the `unshare -Urn` netns
//! used to smoke-test the other runners grants it); active-connect works without.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt::Write as _;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, oneshot};
use tokio::time::{sleep, sleep_until, timeout, Instant};
use tracing::{debug, info, warn};

use wren_bgp::attr::{reconstruct_as_path, AsPathSegment, Origin, PathAttribute};
use wren_bgp::community::format_community;
use wren_bgp::decision::{Path, DEFAULT_LOCAL_PREF};
use wren_bgp::ext_community::format_ext_community;
use wren_bgp::fsm::{Action, BgpFsm, Event, State, CODE_CEASE};
use wren_bgp::large_community::format_large_community;
use wren_bgp::message::{Message, Notification, Open, Update};
use wren_bgp::rib::{BgpRib, RibEvent};
use wren_bgp::{
    AFI_IPV4, AFI_IPV6, AS_TRANS, HEADER_LEN, MARKER, MAX_MESSAGE_LEN, PORT, SAFI_UNICAST, VERSION,
};

use wren_core::{Prefix, Protocol, Route};
use wren_filter::Filter;

use crate::router::{Redistribution, RouteUpdate};

/// How long to wait for an outgoing TCP connection before retrying.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// How long the connector backs off between connection attempts (a simple
/// stand-in for the §8 ConnectRetryTimer, which the connector owns here).
const CONNECT_RETRY: Duration = Duration::from_secs(5);
/// A far-future deadline used to mean "this timer is disabled".
const FAR: Duration = Duration::from_secs(86_400);
/// Cease NOTIFICATION subcode 7, "Connection Collision Resolution" (RFC 4486 §4) —
/// sent to the connection that loses §6.8 collision detection.
const CEASE_COLLISION: u8 = 7;
/// Cease NOTIFICATION subcode 1, "Maximum Number of Prefixes Reached" (RFC 4486 §4) —
/// sent when a peer advertises more prefixes than its configured `max-prefix` limit.
const CEASE_MAXPREFIX: u8 = 1;

/// A process-wide monotonic source of per-connection ids. Two connections to the
/// same peer (a simultaneous open) share a peer address but get distinct ids, so
/// the central task can tell the surviving session's events from a stale loser's.
static NEXT_CONN_ID: AtomicU64 = AtomicU64::new(1);
/// Bound on the central task's inbound event queue.
const PEER_QUEUE: usize = 256;
/// Bound on the central→session origination command queue.
const CMD_QUEUE: usize = 256;

/// The resolved BGP configuration for a run.
pub struct BgpConfig {
    /// This speaker's Autonomous System number (4-octet, RFC 6793).
    pub local_as: u32,
    /// This speaker's BGP Identifier (router id).
    pub router_id: Ipv4Addr,
    /// The Hold Time proposed in our OPEN, in seconds.
    pub hold_time: u16,
    /// The configured peers.
    pub peers: Vec<BgpPeerCfg>,
    /// Networks this speaker originates into BGP (IPv4 and/or IPv6).
    pub originate: Vec<Prefix>,
    /// The IPv6 next hop advertised (next-hop-self) for the IPv6 unicast NLRI this
    /// speaker originates or redistributes (RFC 4760 MP_REACH_NLRI). Required to
    /// advertise any IPv6 route; without it IPv6 prefixes are held but not sent.
    pub next_hop6: Option<Ipv6Addr>,
    /// This route reflector's CLUSTER_ID (RFC 4456), used when reflecting between
    /// clients and other iBGP peers. Defaults to the router id.
    pub cluster_id: Ipv4Addr,
    /// COMMUNITIES (RFC 1997) attached to every originated route.
    pub communities: Vec<u32>,
    /// LARGE_COMMUNITY (RFC 8092) tags attached to every originated route.
    pub large_communities: Vec<(u32, u32, u32)>,
    /// EXTENDED_COMMUNITIES (RFC 4360) attached to every originated route.
    pub ext_communities: Vec<[u8; 8]>,
    /// The Confederation Identifier (RFC 5065): the AS this confederation presents
    /// to true external peers. `None` means no confederation (`local_as` is the
    /// externally visible AS).
    pub confederation_id: Option<u32>,
    /// The Member-AS numbers of the other sub-ASes in this confederation
    /// (RFC 5065); a peer whose `remote_as` is here is a confed-eBGP peer.
    pub confederation_members: Vec<u32>,
    /// The maximum number of equal-cost paths to install per destination as ECMP
    /// (BGP multipath). 1 (the default) is classic single-best-path forwarding.
    pub max_paths: usize,
    /// Address aggregates (RFC 4271 §9.2.2.2): a covering prefix advertised whenever
    /// a more-specific, locally-originated/redistributed route contributes to it.
    pub aggregates: Vec<Aggregate>,
}

/// A configured address aggregate (RFC 4271 §9.2.2.2). The `prefix` is advertised
/// as a single route — carrying ATOMIC_AGGREGATE and AGGREGATOR — whenever at least
/// one strictly-more-specific route in this speaker's origination set (configured
/// `network`s and redistributed prefixes) falls inside it. With `summary_only` the
/// contributing more-specifics are suppressed from advertisement, leaving only the
/// aggregate. The aggregate is advertise-only: it is never installed in the local
/// FIB, and it does not aggregate routes learned from other BGP peers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Aggregate {
    /// The covering prefix to advertise.
    pub prefix: Prefix,
    /// Suppress the contributing more-specifics, advertising only the aggregate.
    pub summary_only: bool,
}

/// How a peer relates to this speaker, which drives the AS_PATH manipulation and
/// the OPEN's My-AS (RFC 4271 + RFC 5065).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum PeerType {
    /// Same AS — or, in a confederation, same Member-AS. Interior BGP.
    Ibgp,
    /// A different Member-AS in the same confederation (RFC 5065): confed-eBGP.
    /// Treated as interior for the decision and LOCAL_PREF/next-hop, but the
    /// Member-AS is prepended to an AS_CONFED_SEQUENCE on egress.
    Confed,
    /// A true external AS, outside any confederation: eBGP.
    Ebgp,
}

/// Classify a peer from its `remote_as` against this speaker's Member-AS and the
/// confederation membership (RFC 5065 §4): same AS → iBGP, a configured member →
/// confed-eBGP, anything else → true eBGP.
fn classify(local_as: u32, members: &[u32], remote_as: u32) -> PeerType {
    if remote_as == local_as {
        PeerType::Ibgp
    } else if members.contains(&remote_as) {
        PeerType::Confed
    } else {
        PeerType::Ebgp
    }
}

/// One configured BGP peer.
pub struct BgpPeerCfg {
    /// The peer's address.
    pub addr: Ipv4Addr,
    /// The peer's AS (eBGP if it differs from [`BgpConfig::local_as`]).
    pub remote_as: u32,
    /// Whether to wait for the peer to connect rather than dialling it.
    pub passive: bool,
    /// Whether this iBGP peer is a route-reflector client (RFC 4456).
    pub rr_client: bool,
    /// GTSM (RFC 5082) maximum hop count to this peer, if enabled (1 = directly
    /// connected). When set the session sends with TTL 255 and rejects received
    /// packets whose TTL is below `255 − (hops − 1)`.
    pub ttl_security: Option<u8>,
    /// TCP-MD5 signature password (RFC 2385) for this peer, if authentication is
    /// enabled. Installed on the socket before the handshake so the kernel signs and
    /// verifies every segment; the peer must share the same key.
    pub password: Option<String>,
    /// TCP-AO (RFC 5925) master key for this peer, if AO authentication is enabled.
    /// Mutually exclusive with [`Self::password`].
    pub ao_key: Option<String>,
    /// The TCP-AO key id (SendID and RecvID), meaningful only with [`Self::ao_key`].
    pub ao_key_id: u8,
    /// The maximum number of prefixes to accept from this peer before tearing the
    /// session down with a Cease (RFC 4486 §4). `None` means no limit.
    pub max_prefix: Option<u32>,
    /// Advertise a default route (`0.0.0.0/0`) to this peer unconditionally, with this
    /// router as the next hop (and without installing it locally).
    pub default_originate: bool,
    /// Inbound route policy (RFC-style import route-map): a filter applied to every
    /// route received from this peer before it enters the RIB. Reject drops the route;
    /// accept admits it, with any set-metric (→MED), set-preference (→LOCAL_PREF) or
    /// set-community modifications applied. `None` accepts everything unchanged.
    pub import: Option<Filter>,
}

impl BgpPeerCfg {
    /// The transport authentication this peer's session uses (at most one scheme).
    fn tcp_auth(&self) -> TcpAuth {
        if let Some(pw) = &self.password {
            TcpAuth::Md5(pw.clone())
        } else if let Some(key) = &self.ao_key {
            TcpAuth::Ao { key: key.clone(), key_id: self.ao_key_id }
        } else {
            TcpAuth::None
        }
    }
}

/// The transport-layer authentication a BGP session installs on its TCP socket before
/// the handshake (so it protects the SYN). At most one scheme is active per peer.
#[derive(Clone)]
enum TcpAuth {
    /// No transport authentication.
    None,
    /// TCP-MD5 signature (RFC 2385) with the given password.
    Md5(String),
    /// TCP-AO (RFC 5925) with the given master key and key id (SendID == RecvID).
    Ao { key: String, key_id: u8 },
}

impl TcpAuth {
    /// Whether any authentication is configured (so the socket must be hand-built).
    fn is_enabled(&self) -> bool {
        !matches!(self, TcpAuth::None)
    }

    /// Install this scheme's key for `peer` on socket `fd`, before the handshake.
    fn install(&self, fd: i32, peer: Ipv4Addr) -> std::io::Result<()> {
        match self {
            TcpAuth::None => Ok(()),
            TcpAuth::Md5(pw) => set_tcp_md5(fd, peer, pw),
            TcpAuth::Ao { key, key_id } => set_tcp_ao(fd, peer, key, *key_id),
        }
    }
}

/// The shared, read-only facts every session task needs.
struct Local {
    local_as: u32,
    router_id: Ipv4Addr,
    hold_time: u16,
    /// The IPv6 next-hop-self for originated IPv6 NLRI (RFC 4760), if configured.
    next_hop6: Option<Ipv6Addr>,
    /// This reflector's CLUSTER_ID (RFC 4456).
    cluster_id: Ipv4Addr,
    /// The Confederation Identifier (RFC 5065): the AS presented to true external
    /// peers. `None` means no confederation (`local_as` is the external AS).
    confed_id: Option<u32>,
    /// peer address → its properties, for matching inbound connections.
    peers: HashMap<Ipv4Addr, PeerProps>,
}

impl Local {
    /// The AS this speaker presents to a true external peer: the Confederation
    /// Identifier if configured, else its (Member-)AS (RFC 5065 §4.2).
    fn external_as(&self) -> u32 {
        self.confed_id.unwrap_or(self.local_as)
    }
}

/// A configured peer's properties, looked up by address for inbound connections.
#[derive(Clone, Copy)]
struct PeerProps {
    remote_as: u32,
    rr_client: bool,
    peer_type: PeerType,
    /// GTSM (RFC 5082) max hop count for this peer, applied to inbound connections.
    ttl_security: Option<u8>,
    /// The peer's `max-prefix` limit (RFC 4486 §4), if any.
    max_prefix: Option<u32>,
}

/// One prefix this speaker originates, with the COMMUNITIES to attach. The central
/// task owns the full origination set and pushes it to each session (via
/// [`SessionCmd`]); the session builds the per-peer UPDATE attributes itself
/// (AS_PATH, next-hop-self), so origination is decided in one place.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OriginRoute {
    /// The originated prefix (IPv4 unicast).
    pub prefix: Prefix,
    /// COMMUNITIES (RFC 1997) to attach.
    pub communities: Vec<u32>,
    /// LARGE_COMMUNITY (RFC 8092) tags to attach.
    pub large_communities: Vec<(u32, u32, u32)>,
    /// EXTENDED_COMMUNITIES (RFC 4360) to attach.
    pub ext_communities: Vec<[u8; 8]>,
    /// This route is an address aggregate (RFC 4271 §9.2.2.2): it is advertised with
    /// ATOMIC_AGGREGATE and AGGREGATOR set.
    pub atomic_aggregate: bool,
}

/// A command from the central task to a per-peer session task: advertise or
/// withdraw originated routes, or propagate learned Loc-RIB routes onward. The
/// session acts on it only once Established.
enum SessionCmd {
    /// Advertise these originated routes (a snapshot on session-up, or an
    /// incremental redistribution change afterwards).
    Advertise(Vec<OriginRoute>),
    /// Withdraw these prefixes (a redistributed source went away).
    Withdraw(Vec<Prefix>),
    /// Re-advertise these learned Loc-RIB best paths to this peer (the Adj-RIB-Out),
    /// applying the eBGP / iBGP propagation rules. The session decides per route
    /// whether and how to send it.
    Propagate(Vec<PropRoute>),
    /// Withdraw these learned prefixes whose best path disappeared.
    WithdrawPropagated(Vec<Prefix>),
    /// Lose §6.8 collision detection: close this connection with a Cease, without
    /// reporting Down — the winning connection owns the peer's slot.
    Shutdown,
    /// The peer exceeded its `max-prefix` limit: close the connection with a Cease
    /// "Maximum Number of Prefixes Reached" (RFC 4486 §4), without reporting Down —
    /// the central task has already withdrawn the peer's routes and damped it.
    CeaseOverLimit,
    /// Send a ROUTE-REFRESH to the peer (RFC 2918), asking it to re-advertise its
    /// routes to us — triggered by the operator's `bgp refresh <peer>`.
    SendRefresh,
    /// Send the End-of-RIB marker(s) (RFC 4724 §2): we have finished the initial
    /// advertisement to this peer, so a graceful-restart helper on the other side
    /// knows the re-advertisement is complete. Pushed by the central task right
    /// after the origination snapshot and Loc-RIB propagation on Established.
    SendEndOfRib,
}

/// One learned Loc-RIB route the central task asks a session to propagate. The
/// session builds the per-peer UPDATE from the carried [`Path`] (its AS_PATH,
/// next hop, communities, and the peer it was learned from).
#[derive(Clone)]
struct PropRoute {
    /// The destination.
    prefix: Prefix,
    /// Its selected best path, as learned.
    path: Path,
}

/// One peer's identity as a session task sees it.
#[derive(Clone, Copy)]
struct PeerInfo {
    addr: Ipv4Addr,
    remote_as: u32,
    /// Whether this iBGP peer is a route-reflector client (RFC 4456).
    rr_client: bool,
    /// How this peer relates to us (RFC 5065): iBGP, confed-eBGP or true eBGP.
    peer_type: PeerType,
    /// GTSM (RFC 5082) max hop count for this peer, if enabled.
    ttl_security: Option<u8>,
}

/// A message from a per-peer session task to the central RIB task.
enum PeerMsg {
    /// The session reached Established, handing the central task the channel on
    /// which to push originated routes to advertise to this peer. Carries the
    /// peer's BGP Identifier and whether this connection was inbound (accepted) or
    /// outbound (dialled), for §6.8 connection-collision detection.
    Established {
        peer: Ipv4Addr,
        peer_id: Ipv4Addr,
        inbound: bool,
        conn_id: u64,
        /// The peer's Graceful Restart Restart Time (RFC 4724), if it advertised GR
        /// with the forwarding state preserved for IPv4 unicast — `Some(secs)` makes
        /// the central task retain this peer's routes for that long when it drops.
        gr_restart_time: Option<u16>,
        cmd_tx: mpsc::Sender<SessionCmd>,
    },
    /// The session left Established / went down — flush the peer's routes, but only
    /// if `conn_id` is still the current connection (a stale loser's Down is
    /// ignored, so it can't evict the surviving session).
    Down { peer: Ipv4Addr, conn_id: u64 },
    /// The peer sent a ROUTE-REFRESH (RFC 2918): re-advertise our Adj-RIB-Out to it.
    /// `conn_id` guards against a stale connection (like [`PeerMsg::Down`]).
    RefreshRequest { peer: Ipv4Addr, conn_id: u64 },
    /// The peer sent an End-of-RIB marker (RFC 4724 §2): it has finished
    /// re-advertising after a graceful restart, so any of its routes we retained as
    /// stale but it did not re-advertise can now be flushed. `conn_id` guards
    /// against a stale connection.
    EndOfRib { peer: Ipv4Addr, conn_id: u64 },
    /// The peer sent an UPDATE.
    Update {
        peer: Ipv4Addr,
        peer_as: u32,
        peer_id: Ipv4Addr,
        from_ebgp: bool,
        /// Whether the sending peer is a confederation-internal (confed-eBGP) peer
        /// (RFC 5065): interior for the decision, externally propagated.
        from_confed: bool,
        /// Whether the sending peer is a route-reflector client (RFC 4456).
        from_client: bool,
        /// The local interface this session rides, for pinning a received IPv6
        /// link-local next hop to it (RFC 2545); `None` if it couldn't be resolved.
        ingress_iface: Option<String>,
        update: Update,
    },
}

/// A `show bgp …` query, answered by the BGP task itself out of the state it owns.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum BgpQuery {
    /// The Loc-RIB best paths, with their path attributes.
    Routes,
    /// The configured neighbours and their session state.
    Neighbors,
    /// Send a ROUTE-REFRESH to this peer (RFC 2918) — `bgp refresh <addr>`. Not a
    /// read-only query, but answered the same way (with a status line).
    Refresh(Ipv4Addr),
}

/// A control-socket query plus the channel to answer it on.
pub struct BgpQueryRequest {
    /// What to report.
    pub query: BgpQuery,
    /// Where to send the rendered answer.
    pub respond: oneshot::Sender<String>,
}

/// One neighbour's tracked state in the BGP task.
struct NeighborState {
    remote_as: u32,
    established: bool,
    /// How many ROUTE-REFRESH requests this peer has sent us (RFC 2918) — a visible
    /// signal in `show bgp neighbors` that a refresh was honoured.
    refreshes_received: u64,
}

/// A neighbour summary handed to the (pure) renderer.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct NeighborSummary {
    /// The peer's address.
    pub addr: Ipv4Addr,
    /// The peer's AS.
    pub remote_as: u32,
    /// Whether the session is currently Established.
    pub established: bool,
    /// How many ROUTE-REFRESH requests this peer has sent us (RFC 2918).
    pub refreshes_received: u64,
}

/// One prefix in the central task's origination set, with the COMMUNITIES to
/// attach and whether it came from `[bgp] network` (configured — never withdrawn
/// by redistribution) or from redistribution (withdrawable when its source goes).
struct OriginEntry {
    communities: Vec<u32>,
    large_communities: Vec<(u32, u32, u32)>,
    ext_communities: Vec<[u8; 8]>,
    configured: bool,
}

/// Whether `aggregate` strictly covers `contributor`: same family, the contributor
/// falls inside the aggregate, and it is strictly more specific (a longer prefix).
/// An aggregate never contributes to itself.
fn covers(aggregate: &Prefix, contributor: &Prefix) -> bool {
    aggregate.is_ipv4() == contributor.is_ipv4()
        && contributor.len() > aggregate.len()
        && aggregate.contains(contributor.addr())
}

/// The effective set of routes to advertise, keyed by prefix: the origination set
/// (configured `network`s and redistributed prefixes) transformed by the configured
/// aggregates (RFC 4271 §9.2.2.2). An aggregate becomes active — added as an
/// ATOMIC_AGGREGATE/AGGREGATOR route — when at least one originated route is strictly
/// more specific and falls inside it; `summary_only` then suppresses those
/// contributors, leaving only the aggregate.
fn effective_origination(
    originated: &BTreeMap<Prefix, OriginEntry>,
    aggregates: &[Aggregate],
) -> BTreeMap<Prefix, OriginRoute> {
    let mut out: BTreeMap<Prefix, OriginRoute> = originated
        .iter()
        .map(|(prefix, e)| {
            (
                *prefix,
                OriginRoute {
                    prefix: *prefix,
                    communities: e.communities.clone(),
                    large_communities: e.large_communities.clone(),
                    ext_communities: e.ext_communities.clone(),
                    atomic_aggregate: false,
                },
            )
        })
        .collect();
    for agg in aggregates {
        let contributors: Vec<Prefix> =
            originated.keys().copied().filter(|c| covers(&agg.prefix, c)).collect();
        if contributors.is_empty() {
            continue; // no more-specific present: the aggregate is not advertised
        }
        if agg.summary_only {
            for c in &contributors {
                out.remove(c);
            }
        }
        // The aggregate itself: empty tag set, ATOMIC_AGGREGATE + AGGREGATOR. It
        // overrides any equal-prefix originated entry (not a contributor anyway).
        out.insert(
            agg.prefix,
            OriginRoute {
                prefix: agg.prefix,
                communities: vec![],
                large_communities: vec![],
                ext_communities: vec![],
                atomic_aggregate: true,
            },
        );
    }
    out
}

fn neighbor_summaries(neighbors: &BTreeMap<Ipv4Addr, NeighborState>) -> Vec<NeighborSummary> {
    neighbors
        .iter()
        .map(|(addr, n)| NeighborSummary {
            addr: *addr,
            remote_as: n.remote_as,
            established: n.established,
            refreshes_received: n.refreshes_received,
        })
        .collect()
}

/// Render the BGP Loc-RIB best paths, one per line (à la `show ip bgp`).
pub fn render_bgp_routes(rib: &BgpRib) -> String {
    if rib.is_empty() {
        return "no bgp routes\n".to_string();
    }
    let mut out = String::new();
    for (prefix, path) in rib.iter_best() {
        let _ = write!(out, "{prefix} via {}", path.next_hop);
        let as_path = format_as_path(&path.as_path);
        if as_path.is_empty() {
            out.push_str(" as-path i"); // empty AS_PATH: locally/iBGP-originated
        } else {
            let _ = write!(out, " as-path {as_path}");
        }
        if !path.communities.is_empty() {
            let comms: Vec<String> = path.communities.iter().map(|c| format_community(*c)).collect();
            let _ = write!(out, " communities {}", comms.join(" "));
        }
        if !path.large_communities.is_empty() {
            let comms: Vec<String> =
                path.large_communities.iter().map(|c| format_large_community(*c)).collect();
            let _ = write!(out, " large-communities {}", comms.join(" "));
        }
        if !path.ext_communities.is_empty() {
            let comms: Vec<String> =
                path.ext_communities.iter().map(|c| format_ext_community(*c)).collect();
            let _ = write!(out, " ext-communities {}", comms.join(" "));
        }
        let _ = write!(out, " localpref {}", path.local_pref);
        if path.med != 0 {
            let _ = write!(out, " med {}", path.med);
        }
        let _ = writeln!(out, " origin {}", origin_str(path.origin));
    }
    out
}

/// Render the configured neighbours and their session state.
pub fn render_bgp_neighbors(neighbors: &[NeighborSummary]) -> String {
    if neighbors.is_empty() {
        return "no bgp neighbors configured\n".to_string();
    }
    let mut out = String::new();
    for n in neighbors {
        let state = if n.established { "Established" } else { "Idle" };
        let _ = write!(out, "{} AS {} {}", n.addr, n.remote_as, state);
        if n.refreshes_received > 0 {
            let _ = write!(out, " refreshes {}", n.refreshes_received);
        }
        out.push('\n');
    }
    out
}

/// Format an AS_PATH as a space-separated list, sets in braces (à la BIRD/FRR).
fn format_as_path(segs: &[AsPathSegment]) -> String {
    let mut parts: Vec<String> = Vec::new();
    for seg in segs {
        match seg {
            AsPathSegment::Sequence(asns) => {
                parts.extend(asns.iter().map(|a| a.to_string()));
            }
            AsPathSegment::Set(asns) => {
                let inner: Vec<String> = asns.iter().map(|a| a.to_string()).collect();
                parts.push(format!("{{{}}}", inner.join(" ")));
            }
            // Confederation segments (RFC 5065) — rendered in parentheses (à la
            // BIRD/FRR), a set inside additionally braced.
            AsPathSegment::ConfedSequence(asns) => {
                let inner: Vec<String> = asns.iter().map(|a| a.to_string()).collect();
                parts.push(format!("({})", inner.join(" ")));
            }
            AsPathSegment::ConfedSet(asns) => {
                let inner: Vec<String> = asns.iter().map(|a| a.to_string()).collect();
                parts.push(format!("({{{}}})", inner.join(" ")));
            }
        }
    }
    parts.join(" ")
}

fn origin_str(o: Origin) -> &'static str {
    match o {
        Origin::Igp => "igp",
        Origin::Egp => "egp",
        Origin::Incomplete => "incomplete",
    }
}

/// Run BGP until the daemon stops: bind the listener, dial the active peers, and
/// fold every session's events into the [`BgpRib`], announcing best-path changes.
///
/// The same task answers `show bgp …` queries off the [`BgpRib`] and the neighbour
/// table it owns, so operational state is read single-threaded with no locking —
/// the same design as the central router loop's `show routes`.
pub async fn run(
    cfg: BgpConfig,
    updates: mpsc::Sender<RouteUpdate>,
    mut queries: mpsc::Receiver<BgpQueryRequest>,
    mut redist: mpsc::Receiver<Redistribution>,
) -> Result<()> {
    // The neighbour table: every configured peer, its AS and whether the session
    // is currently Established. Sorted for stable `show bgp neighbors` output.
    let mut neighbors: BTreeMap<Ipv4Addr, NeighborState> = cfg
        .peers
        .iter()
        .map(|p| {
            (
                p.addr,
                NeighborState { remote_as: p.remote_as, established: false, refreshes_received: 0 },
            )
        })
        .collect();

    // The origination set: the configured `network`s up front (each carrying the
    // configured communities), plus redistributed prefixes added as they arrive.
    let mut originated: BTreeMap<Prefix, OriginEntry> = cfg
        .originate
        .iter()
        .map(|p| {
            (
                *p,
                OriginEntry {
                    communities: cfg.communities.clone(),
                    large_communities: cfg.large_communities.clone(),
                    ext_communities: cfg.ext_communities.clone(),
                    configured: true,
                },
            )
        })
        .collect();
    // Address aggregates (RFC 4271 §9.2.2.2) and the current effective advertised set
    // (the origination set transformed by the aggregates). `advertised` is the source
    // of truth for what we hand a session and the baseline incremental redistribution
    // changes are diffed against.
    let aggregates = cfg.aggregates.clone();
    let mut advertised = effective_origination(&originated, &aggregates);
    // Established sessions we can push origination changes to, keyed by peer.
    let mut sessions: HashMap<Ipv4Addr, mpsc::Sender<SessionCmd>> = HashMap::new();
    // Whether each established session's connection was inbound, for §6.8 collision
    // detection (which of two racing connections to keep).
    let mut est_inbound: HashMap<Ipv4Addr, bool> = HashMap::new();
    // The id of the current connection per peer, so a stale loser connection's Down
    // (e.g. after it was Ceased) can't evict the surviving session.
    let mut current_conn: HashMap<Ipv4Addr, u64> = HashMap::new();
    // Graceful Restart (RFC 4724): peers that negotiated GR with the forwarding
    // state preserved for IPv4 unicast, mapped to their Restart Time — when such a
    // peer drops we retain its routes for that long instead of withdrawing.
    let mut gr_helper: HashMap<Ipv4Addr, u16> = HashMap::new();
    // The routes currently retained as stale per restarting peer, with the deadline
    // by which the peer must return (its Restart Timer).
    let mut stale: HashMap<Ipv4Addr, StalePeer> = HashMap::new();
    // Peers that exceeded their max-prefix limit (RFC 4486 §4): their session is torn
    // down and kept down — any reconnection is shut down again and their UPDATEs are
    // ignored — until the daemon is reconfigured (no auto-restart timer yet).
    let mut damped: HashSet<Ipv4Addr> = HashSet::new();
    // Peers to which we advertise a default route (`0.0.0.0/0`) on Established.
    let default_originate: HashSet<Ipv4Addr> =
        cfg.peers.iter().filter(|p| p.default_originate).map(|p| p.addr).collect();
    // Per-peer inbound import filters (RFC-style import route-maps), applied to every
    // route received from the peer before it enters the RIB.
    let imports: HashMap<Ipv4Addr, Filter> =
        cfg.peers.iter().filter_map(|p| p.import.clone().map(|f| (p.addr, f))).collect();

    let members = cfg.confederation_members.clone();
    let local = Arc::new(Local {
        local_as: cfg.local_as,
        router_id: cfg.router_id,
        hold_time: cfg.hold_time,
        next_hop6: cfg.next_hop6,
        cluster_id: cfg.cluster_id,
        confed_id: cfg.confederation_id,
        peers: cfg
            .peers
            .iter()
            .map(|p| {
                (
                    p.addr,
                    PeerProps {
                        remote_as: p.remote_as,
                        rr_client: p.rr_client,
                        peer_type: classify(cfg.local_as, &members, p.remote_as),
                        ttl_security: p.ttl_security,
                        max_prefix: p.max_prefix,
                    },
                )
            })
            .collect(),
    });

    let (tx, mut rx) = mpsc::channel::<PeerMsg>(PEER_QUEUE);

    // A listener for inbound connections (passive peers, and the peer that wins a
    // simultaneous-open race). Port 179 needs CAP_NET_BIND_SERVICE. When any peer is
    // authenticated (TCP-MD5 or TCP-AO) we build the socket by hand to install each
    // peer's key before listening, so the kernel verifies their inbound SYNs;
    // otherwise the ordinary async bind is used unchanged.
    let bound = if cfg.peers.iter().any(|p| p.tcp_auth().is_enabled()) {
        bind_listener_authed(&cfg.peers)
    } else {
        TcpListener::bind((Ipv4Addr::UNSPECIFIED, PORT)).await
    };
    match bound {
        Ok(listener) => {
            info!(port = PORT, "BGP listening");
            let local = local.clone();
            let tx = tx.clone();
            tokio::spawn(async move { accept_loop(listener, local, tx).await });
        }
        Err(e) => warn!(error = %e, "BGP could not bind listener; active-connect only"),
    }

    // One active connector per non-passive peer.
    for peer in &cfg.peers {
        if peer.passive {
            continue;
        }
        let info = PeerInfo {
            addr: peer.addr,
            remote_as: peer.remote_as,
            rr_client: peer.rr_client,
            peer_type: classify(cfg.local_as, &members, peer.remote_as),
            ttl_security: peer.ttl_security,
        };
        let auth = peer.tcp_auth();
        let local = local.clone();
        let tx = tx.clone();
        tokio::spawn(async move { connector(info, auth, local, tx).await });
    }
    // Drop our own sender; the listener and connectors keep theirs, so `rx` stays
    // open for the life of the daemon.
    drop(tx);

    let mut rib = BgpRib::with_max_paths(cfg.max_paths);
    loop {
        // The nearest Restart Timer deadline across all restarting peers (RFC 4724);
        // the timer future fires when it elapses, or never if none are pending.
        let next_stale = stale.values().map(|s| s.deadline).min();
        let restart_timer = async move {
            match next_stale {
                Some(d) => sleep_until(d).await,
                None => std::future::pending::<()>().await,
            }
        };
        tokio::pin!(restart_timer);

        let msg = tokio::select! {
            msg = rx.recv() => match msg {
                Some(msg) => msg,
                None => break, // all sessions gone — daemon shutting down
            },
            () = &mut restart_timer => {
                // A restarting peer did not return in time: flush its stale routes.
                let now = Instant::now();
                let expired: Vec<Ipv4Addr> =
                    stale.iter().filter(|(_, s)| s.deadline <= now).map(|(p, _)| *p).collect();
                for p in expired {
                    if let Some(s) = stale.remove(&p) {
                        warn!(peer = %p, count = s.prefixes.len(), "BGP graceful restart timer expired; flushing stale routes");
                        flush_stale(p, s.prefixes, &mut rib, &updates, &sessions).await;
                    }
                }
                continue;
            }
            Some(req) = queries.recv() => {
                let resp = match req.query {
                    BgpQuery::Routes => render_bgp_routes(&rib),
                    BgpQuery::Neighbors => render_bgp_neighbors(&neighbor_summaries(&neighbors)),
                    BgpQuery::Refresh(addr) => match sessions.get(&addr) {
                        Some(cmd_tx) => {
                            let _ = cmd_tx.send(SessionCmd::SendRefresh).await;
                            format!("route refresh sent to {addr}\n")
                        }
                        None => format!("no established session to {addr}\n"),
                    },
                };
                let _ = req.respond.send(resp);
                continue;
            }
            Some(r) = redist.recv() => {
                apply_redistribution(r, &mut originated, &aggregates, &mut advertised, &sessions)
                    .await;
                continue;
            }
        };
        match msg {
            PeerMsg::Established { peer: p, peer_id, inbound, conn_id, gr_restart_time, cmd_tx } => {
                // A peer damped for exceeding its max-prefix limit is kept down: shut
                // any reconnection straight back down without advertising to it.
                if damped.contains(&p) {
                    debug!(peer = %p, "BGP peer is max-prefix damped; closing reconnection");
                    let _ = cmd_tx.send(SessionCmd::CeaseOverLimit).await;
                    continue;
                }
                // §6.8 connection-collision detection: if a session already exists
                // for this peer, two connections raced to Established. Keep the one
                // opened by the speaker with the higher BGP Identifier (RFC 4271
                // §6.8) and shut the other down with a Cease, so exactly one
                // survives — without churning the peer's state.
                if sessions.contains_key(&p) {
                    let keep_inbound = collision_keeps_inbound(local.router_id, peer_id);
                    let existing_inbound = est_inbound.get(&p).copied().unwrap_or(false);
                    let new_wins = inbound == keep_inbound && existing_inbound != keep_inbound;
                    if new_wins {
                        debug!(peer = %p, "BGP collision: new connection wins, dropping the old");
                        if let Some(old) = sessions.get(&p) {
                            let _ = old.send(SessionCmd::Shutdown).await;
                        }
                    } else {
                        debug!(peer = %p, "BGP collision: keeping the existing connection");
                        let _ = cmd_tx.send(SessionCmd::Shutdown).await;
                        continue;
                    }
                }
                info!(peer = %p, "BGP session established");
                if let Some(n) = neighbors.get_mut(&p) {
                    n.established = true;
                }
                est_inbound.insert(p, inbound);
                current_conn.insert(p, conn_id);
                // Remember whether this peer can be helped through a restart, and
                // with what Restart Time (RFC 4724). A stale entry from a previous
                // drop is kept: the re-advertisement below refreshes it, and the
                // peer's End-of-RIB (or the Restart Timer) finalises it.
                match gr_restart_time {
                    Some(t) if t > 0 => {
                        gr_helper.insert(p, t);
                    }
                    _ => {
                        gr_helper.remove(&p);
                    }
                }
                // Push the current effective advertised set (origination transformed
                // by the configured aggregates) to the new session.
                let snapshot: Vec<OriginRoute> = advertised.values().cloned().collect();
                if !snapshot.is_empty() {
                    let _ = cmd_tx.send(SessionCmd::Advertise(snapshot)).await;
                }
                // Also push the current Loc-RIB best paths so the new peer learns
                // the routes we already have (the session applies the propagation
                // rules — it drops anything it taught us, and iBGP→iBGP routes).
                let prop: Vec<PropRoute> = rib
                    .iter_best()
                    .map(|(prefix, path)| PropRoute { prefix: *prefix, path: path.clone() })
                    .collect();
                if !prop.is_empty() {
                    let _ = cmd_tx.send(SessionCmd::Propagate(prop)).await;
                }
                // default-originate: advertise 0.0.0.0/0 to this peer unconditionally
                // (next-hop-self), without installing it locally or sending it to any
                // other peer.
                if default_originate.contains(&p) {
                    if let Ok(default) = Prefix::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0) {
                        let route = OriginRoute {
                            prefix: default,
                            communities: vec![],
                            large_communities: vec![],
                            ext_communities: vec![],
                            atomic_aggregate: false,
                        };
                        let _ = cmd_tx.send(SessionCmd::Advertise(vec![route])).await;
                    }
                }
                // Initial advertisement done: send the End-of-RIB marker so a helper
                // on the peer's side knows our re-advertisement is complete (RFC 4724
                // §2). Queued after Advertise/Propagate, so it arrives last.
                let _ = cmd_tx.send(SessionCmd::SendEndOfRib).await;
                sessions.insert(p, cmd_tx);
            }
            PeerMsg::Down { peer: p, conn_id } => {
                // Ignore a Down from a connection that is no longer the current one
                // (a loser of §6.8 collision resolution closing after a Cease) — it
                // must not evict the surviving session or withdraw its routes.
                if current_conn.get(&p) != Some(&conn_id) {
                    debug!(peer = %p, "ignoring Down from a superseded connection");
                    continue;
                }
                info!(peer = %p, "BGP session down");
                if let Some(n) = neighbors.get_mut(&p) {
                    n.established = false;
                }
                sessions.remove(&p);
                est_inbound.remove(&p);
                current_conn.remove(&p);
                // Graceful Restart helper (RFC 4724 §4.1): if the peer advertised GR
                // with the forwarding state preserved, do NOT withdraw its routes —
                // keep them in service (and in the kernel FIB) as stale and start its
                // Restart Timer. Otherwise fall back to an ordinary withdrawal.
                let retained = match gr_helper.get(&p).copied() {
                    Some(time) => {
                        let prefixes: HashSet<Prefix> = rib.prefixes_from(p).into_iter().collect();
                        if prefixes.is_empty() {
                            false
                        } else {
                            let secs = time.max(1) as u64;
                            info!(peer = %p, count = prefixes.len(), seconds = secs, "BGP graceful restart: retaining peer routes (helper)");
                            stale.insert(
                                p,
                                StalePeer {
                                    prefixes,
                                    deadline: Instant::now() + Duration::from_secs(secs),
                                },
                            );
                            true
                        }
                    }
                    None => false,
                };
                if !retained {
                    for ev in rib.withdraw_peer(p) {
                        apply_event(ev, &updates, &sessions).await;
                    }
                }
            }
            PeerMsg::RefreshRequest { peer: p, conn_id } => {
                // Honour a peer's ROUTE-REFRESH (RFC 2918) by re-advertising our
                // Adj-RIB-Out to it — the origination snapshot plus the Loc-RIB best
                // paths (the session re-applies the propagation rules). Ignore a
                // request from a superseded connection, like a stale Down.
                if current_conn.get(&p) != Some(&conn_id) {
                    continue;
                }
                if let Some(n) = neighbors.get_mut(&p) {
                    n.refreshes_received += 1;
                }
                if let Some(cmd_tx) = sessions.get(&p) {
                    info!(peer = %p, "BGP ROUTE-REFRESH: re-advertising Adj-RIB-Out");
                    let snapshot: Vec<OriginRoute> = advertised.values().cloned().collect();
                    if !snapshot.is_empty() {
                        let _ = cmd_tx.send(SessionCmd::Advertise(snapshot)).await;
                    }
                    let prop: Vec<PropRoute> = rib
                        .iter_best()
                        .map(|(prefix, path)| PropRoute { prefix: *prefix, path: path.clone() })
                        .collect();
                    if !prop.is_empty() {
                        let _ = cmd_tx.send(SessionCmd::Propagate(prop)).await;
                    }
                }
            }
            PeerMsg::EndOfRib { peer: p, conn_id } => {
                // The peer finished re-advertising after a graceful restart (RFC 4724
                // §4.2). A restarting peer sends all its routes before any End-of-RIB
                // marker, so by now every route it still has has refreshed its stale
                // entry; whatever remains in the stale set is genuinely gone and is
                // flushed. (Finalised on the first marker — covers both families,
                // which arrive after all re-advertisements on the same ordered stream.)
                if current_conn.get(&p) != Some(&conn_id) {
                    continue;
                }
                if let Some(s) = stale.remove(&p) {
                    if s.prefixes.is_empty() {
                        info!(peer = %p, "BGP graceful restart complete; all routes refreshed");
                    } else {
                        info!(peer = %p, count = s.prefixes.len(), "BGP graceful restart complete; flushing un-refreshed routes");
                    }
                    flush_stale(p, s.prefixes, &mut rib, &updates, &sessions).await;
                }
            }
            PeerMsg::Update {
                peer,
                peer_as,
                peer_id,
                from_ebgp,
                from_confed,
                from_client,
                ingress_iface,
                update,
            } => {
                // A max-prefix-damped peer is kept out of the RIB entirely, so even a
                // reconnection that re-floods its routes installs nothing.
                if damped.contains(&peer) {
                    continue;
                }
                let facts = PeerFacts {
                    addr: peer,
                    as_: peer_as,
                    id: peer_id,
                    from_ebgp,
                    from_confed,
                    from_client,
                };
                // Graceful restart (RFC 4724 §4.2): a prefix the restarting peer
                // re-advertises is no longer stale, so drop it from the retained set
                // (the rib.update below refreshes its path in place).
                if let Some(s) = stale.get_mut(&peer) {
                    for prefix in &update.nlri {
                        s.prefixes.remove(prefix);
                    }
                    if let Some((_, nlri, _)) = mp_reach_v6(&update) {
                        for prefix in nlri {
                            s.prefixes.remove(prefix);
                        }
                    }
                }
                // Withdrawals: base-NLRI IPv4 (the Withdrawn Routes field) and IPv6
                // (MP_UNREACH_NLRI, RFC 4760 §4).
                for w in update.withdrawn.iter().chain(mp_unreach_v6(&update)) {
                    if let Some(ev) = rib.withdraw(peer, *w) {
                        apply_event(ev, &updates, &sessions).await;
                    }
                }
                // Confederation loop avoidance (RFC 5065 §5.4): drop reachability
                // whose AS_CONFED_SEQUENCE / AS_CONFED_SET already names our
                // Member-AS — withdrawals above are still honoured.
                if is_confed_loop(&update, local.local_as) {
                    debug!(peer = %peer, "BGP UPDATE failed confederation loop check; reachability ignored");
                    continue;
                }
                // Route-reflection loop avoidance (RFC 4456 §8): drop reachability
                // whose ORIGINATOR_ID is ours, or whose CLUSTER_LIST already names
                // our cluster — withdrawals above are still honoured.
                if is_reflection_loop(&update, local.router_id, local.cluster_id) {
                    debug!(peer = %peer, "BGP UPDATE failed reflection loop check; reachability ignored");
                    continue;
                }
                // Max-prefix enforcement (RFC 4486 §4), checked BEFORE installing this
                // update's reachability: if accepting it would push the peer over its
                // limit, withdraw whatever it already had, tear the session down with a
                // Cease, and damp it — without ever installing the over-limit routes
                // (installing then immediately deleting the same prefix races the kernel
                // and can leave the route behind).
                if let Some(limit) = local.peers.get(&peer).and_then(|pp| pp.max_prefix) {
                    let mut prospective: HashSet<Prefix> =
                        rib.prefixes_from(peer).into_iter().collect();
                    prospective.extend(update.nlri.iter().copied());
                    if let Some((_, nlri, _)) = mp_reach_v6(&update) {
                        prospective.extend(nlri.iter().copied());
                    }
                    if prospective.len() as u32 > limit {
                        warn!(peer = %peer, count = prospective.len(), limit, "BGP peer exceeded max-prefix; tearing down");
                        for ev in rib.withdraw_peer(peer) {
                            apply_event(ev, &updates, &sessions).await;
                        }
                        if let Some(cmd_tx) = sessions.remove(&peer) {
                            let _ = cmd_tx.send(SessionCmd::CeaseOverLimit).await;
                        }
                        if let Some(n) = neighbors.get_mut(&peer) {
                            n.established = false;
                        }
                        est_inbound.remove(&peer);
                        current_conn.remove(&peer);
                        damped.insert(peer);
                        continue;
                    }
                }
                let import = imports.get(&peer);
                // IPv4 reachability: base NLRI with the IPv4 NEXT_HOP attribute.
                if !update.nlri.is_empty() {
                    match base_next_hop(&update) {
                        Some(nh) => {
                            let path = build_path(&update, IpAddr::V4(nh), None, facts);
                            for p in &update.nlri {
                                import_and_install(import, peer, *p, &path, &mut rib, &updates, &sessions)
                                    .await;
                            }
                        }
                        None => warn!(peer = %peer, "UPDATE with NLRI but no NEXT_HOP — ignored"),
                    }
                }
                // IPv6 reachability: MP_REACH_NLRI carries its own next hop (RFC 4760).
                // A link-local next hop (RFC 2545) is pinned to the ingress interface.
                if let Some((nh6, nlri, is_link_local)) = mp_reach_v6(&update) {
                    let iface = if is_link_local { ingress_iface.clone() } else { None };
                    let path = build_path(&update, IpAddr::V6(nh6), iface, facts);
                    for p in nlri {
                        import_and_install(import, peer, *p, &path, &mut rib, &updates, &sessions)
                            .await;
                    }
                }
            }
        }
    }
    Ok(())
}

/// Fold a redistribution change from the central router into the origination set,
/// recompute the effective advertised set (origination transformed by the configured
/// aggregates), and push the delta to every established session. BGP carries both
/// IPv4 and IPv6 unicast (the IPv6 prefixes ride MP_REACH_NLRI, RFC 4760); a prefix
/// originated by `[bgp] network` (configured) is never overridden or withdrawn by
/// redistribution.
async fn apply_redistribution(
    r: Redistribution,
    originated: &mut BTreeMap<Prefix, OriginEntry>,
    aggregates: &[Aggregate],
    advertised: &mut BTreeMap<Prefix, OriginRoute>,
    sessions: &HashMap<Ipv4Addr, mpsc::Sender<SessionCmd>>,
) {
    // Fold the change into the raw origination set; bail if nothing changed so an
    // idempotent re-announce produces no churn.
    let changed = match r {
        Redistribution::Announce(route) => {
            let prefix = route.prefix;
            // Communities set on the route by the export filter ride along.
            let communities = route.communities.clone();
            let large_communities = route.large_communities.clone();
            let ext_communities = route.ext_communities.clone();
            match originated.get(&prefix) {
                // A configured `network` is authoritative — never overridden.
                Some(e) if e.configured => false,
                // Already redistributed with the same tags: nothing new.
                Some(e)
                    if e.communities == communities
                        && e.large_communities == large_communities
                        && e.ext_communities == ext_communities =>
                {
                    false
                }
                _ => {
                    originated.insert(
                        prefix,
                        OriginEntry {
                            communities,
                            large_communities,
                            ext_communities,
                            configured: false,
                        },
                    );
                    debug!(%prefix, "redistributed into BGP");
                    true
                }
            }
        }
        Redistribution::Withdraw(prefix) => {
            // Only retract redistributed prefixes; configured networks stay.
            if matches!(originated.get(&prefix), Some(e) if !e.configured) {
                originated.remove(&prefix);
                debug!(%prefix, "redistribution withdrawn from BGP");
                true
            } else {
                false
            }
        }
    };
    if !changed {
        return;
    }
    // Recompute the effective advertised set and diff it against the previous one: a
    // single redistribution change can activate or retire an aggregate and (under
    // summary-only) suppress or restore its contributors, so push the whole delta —
    // not just the one prefix — to every established session.
    let next = effective_origination(originated, aggregates);
    let withdrawn: Vec<Prefix> =
        advertised.keys().filter(|p| !next.contains_key(p)).copied().collect();
    let adv: Vec<OriginRoute> =
        next.values().filter(|r| advertised.get(&r.prefix) != Some(r)).cloned().collect();
    *advertised = next;
    for tx in sessions.values() {
        if !adv.is_empty() {
            let _ = tx.send(SessionCmd::Advertise(adv.clone())).await;
        }
        if !withdrawn.is_empty() {
            let _ = tx.send(SessionCmd::Withdraw(withdrawn.clone())).await;
        }
    }
}

/// Apply a Loc-RIB change: propagate it to the other BGP peers (the Adj-RIB-Out)
/// and hand it to the central router (the kernel FIB).
async fn apply_event(
    ev: RibEvent,
    updates: &mpsc::Sender<RouteUpdate>,
    sessions: &HashMap<Ipv4Addr, mpsc::Sender<SessionCmd>>,
) {
    propagate(&ev, sessions).await;
    emit(ev, updates).await;
}

/// A view of a received BGP path as a [`Route`] for the inbound import filter: the
/// prefix, the MED as the metric, the LOCAL_PREF as the (higher-wins) preference, and
/// the path's communities. This is the domain a `[[filter]]` route-map operates on.
fn path_to_route(prefix: Prefix, path: &Path) -> Route {
    let mut route = Route::new(prefix, Protocol::Bgp, vec![], path.med);
    route.preference = path.local_pref;
    route.communities = path.communities.clone();
    route.large_communities = path.large_communities.clone();
    route.ext_communities = path.ext_communities.clone();
    route
}

/// Run a received path through this peer's inbound import filter (if any). Returns the
/// path to install — possibly with set-metric (→MED), set-preference (→LOCAL_PREF) and
/// set-community modifications folded back in — or `None` if the filter rejected it.
fn apply_import(import: Option<&Filter>, prefix: Prefix, path: &Path) -> Option<Path> {
    let Some(filter) = import else {
        return Some(path.clone());
    };
    let modified = filter.apply(&path_to_route(prefix, path)).accepted()?;
    let mut out = path.clone();
    out.med = modified.metric;
    out.local_pref = modified.preference;
    out.communities = modified.communities;
    out.large_communities = modified.large_communities;
    out.ext_communities = modified.ext_communities;
    Some(out)
}

/// Install one received prefix into the RIB after the peer's inbound import filter: a
/// rejected prefix is instead withdrawn (so a route that was accepted before but is now
/// rejected on re-advertisement is removed). Shared by the IPv4 and IPv6 reachability
/// paths.
async fn import_and_install(
    import: Option<&Filter>,
    peer: Ipv4Addr,
    prefix: Prefix,
    path: &Path,
    rib: &mut BgpRib,
    updates: &mpsc::Sender<RouteUpdate>,
    sessions: &HashMap<Ipv4Addr, mpsc::Sender<SessionCmd>>,
) {
    let ev = match apply_import(import, prefix, path) {
        Some(p) => rib.update(peer, prefix, p),
        None => rib.withdraw(peer, prefix),
    };
    if let Some(ev) = ev {
        apply_event(ev, updates, sessions).await;
    }
}

/// Re-advertise a Loc-RIB change to every established session (the Adj-RIB-Out
/// fan-out), IPv4 or IPv6. This broadcasts unconditionally; each session applies
/// the eBGP/iBGP propagation rules (and the IPv6 multiprotocol gating) itself, and
/// the session that taught us the route drops it (split horizon).
async fn propagate(ev: &RibEvent, sessions: &HashMap<Ipv4Addr, mpsc::Sender<SessionCmd>>) {
    match ev {
        RibEvent::Best { prefix, path, .. } => {
            let pr = PropRoute { prefix: *prefix, path: path.clone() };
            for tx in sessions.values() {
                let _ = tx.send(SessionCmd::Propagate(vec![pr.clone()])).await;
            }
        }
        RibEvent::Withdrawn(prefix) => {
            for tx in sessions.values() {
                let _ = tx.send(SessionCmd::WithdrawPropagated(vec![*prefix])).await;
            }
        }
    }
}

/// Turn a Loc-RIB change into a router update.
async fn emit(ev: RibEvent, updates: &mpsc::Sender<RouteUpdate>) {
    let upd = match ev {
        RibEvent::Best { prefix, path, hops } => {
            RouteUpdate::Announce(path.to_route_multipath(prefix, hops))
        }
        RibEvent::Withdrawn(prefix) => RouteUpdate::Withdraw {
            prefix,
            protocol: Protocol::Bgp,
            source: 0,
        },
    };
    let _ = updates.send(upd).await;
}

/// A graceful-restart helper's retained state for one peer (RFC 4724 §4.1): the
/// routes we kept in service (and in the kernel FIB) while the peer is away, and
/// the deadline by which it must return before we flush them.
struct StalePeer {
    /// The peer's prefixes still awaiting re-advertisement — refreshed (removed)
    /// as the peer re-sends them, and the remainder flushed at End-of-RIB.
    prefixes: HashSet<Prefix>,
    /// When the Restart Timer expires and any still-stale routes are flushed.
    deadline: Instant,
}

/// Flush a peer's still-stale routes from the RIB (a graceful restart did not
/// complete in time, or the peer's End-of-RIB showed they are gone): withdraw each,
/// propagating and updating the kernel FIB.
async fn flush_stale(
    peer: Ipv4Addr,
    prefixes: impl IntoIterator<Item = Prefix>,
    rib: &mut BgpRib,
    updates: &mpsc::Sender<RouteUpdate>,
    sessions: &HashMap<Ipv4Addr, mpsc::Sender<SessionCmd>>,
) {
    for prefix in prefixes {
        if let Some(ev) = rib.withdraw(peer, prefix) {
            apply_event(ev, updates, sessions).await;
        }
    }
}

/// The session facts a received UPDATE is tagged with, threaded into every [`Path`]
/// built from it.
#[derive(Clone, Copy)]
struct PeerFacts {
    addr: Ipv4Addr,
    as_: u32,
    id: Ipv4Addr,
    from_ebgp: bool,
    /// Whether the sending peer is a confederation-internal (confed-eBGP) peer.
    from_confed: bool,
    /// Whether the sending peer is a route-reflector client (RFC 4456).
    from_client: bool,
}

/// Build a [`Path`] from a received UPDATE's attributes with the given `next_hop`
/// (the base-NLRI IPv4 NEXT_HOP, or the IPv6 next hop pulled from MP_REACH_NLRI).
fn build_path(
    update: &Update,
    next_hop: IpAddr,
    next_hop_iface: Option<String>,
    peer: PeerFacts,
) -> Path {
    let mut origin = Origin::Incomplete;
    let mut as_path = Vec::new();
    let mut as4_path = None;
    let mut med = 0;
    let mut local_pref = DEFAULT_LOCAL_PREF;
    let mut communities = Vec::new();
    let mut large_communities = Vec::new();
    let mut ext_communities = Vec::new();
    let mut originator_id = None;
    let mut cluster_list = Vec::new();
    for a in &update.attributes {
        match a {
            PathAttribute::Origin(o) => origin = *o,
            PathAttribute::AsPath(segs) => as_path = segs.clone(),
            PathAttribute::As4Path(segs) => as4_path = Some(segs.clone()),
            PathAttribute::MultiExitDisc(m) => med = *m,
            PathAttribute::LocalPref(lp) => local_pref = *lp,
            PathAttribute::Communities(c) => communities = c.clone(),
            PathAttribute::LargeCommunities(c) => large_communities = c.clone(),
            PathAttribute::ExtendedCommunities(c) => ext_communities = c.clone(),
            PathAttribute::OriginatorId(id) => originator_id = Some(*id),
            PathAttribute::ClusterList(ids) => cluster_list = ids.clone(),
            _ => {}
        }
    }
    // If a legacy speaker carried the real 4-octet hops in AS4_PATH, merge them
    // back over the AS_TRANS placeholders in AS_PATH (RFC 6793 §4.2.3).
    if let Some(as4) = as4_path {
        as_path = reconstruct_as_path(&as_path, &as4);
    }
    Path {
        origin,
        as_path,
        next_hop,
        next_hop_iface,
        local_pref,
        med,
        from_ebgp: peer.from_ebgp,
        from_confed: peer.from_confed,
        peer_as: peer.as_,
        igp_metric: 0,
        peer_id: peer.id,
        peer_addr: peer.addr,
        from_client: peer.from_client,
        originator_id,
        cluster_list,
        communities,
        large_communities,
        ext_communities,
    }
}

/// RFC 4271 §6.8: when two connections to a peer race to Established, keep the one
/// opened by the speaker with the higher BGP Identifier. From our side that means
/// keeping the **inbound** (peer-initiated) connection when our identifier is the
/// lower of the two; otherwise we keep our own **outbound** connection. Equal
/// identifiers are a misconfiguration; we then keep the outbound arbitrarily.
fn collision_keeps_inbound(local_id: Ipv4Addr, peer_id: Ipv4Addr) -> bool {
    u32::from(local_id) < u32::from(peer_id)
}

/// Whether a received UPDATE's reachability must be ignored for route-reflection
/// loop avoidance (RFC 4456 §8): its ORIGINATOR_ID is our own router id, or its
/// CLUSTER_LIST already contains our CLUSTER_ID.
fn is_reflection_loop(update: &Update, router_id: Ipv4Addr, cluster_id: Ipv4Addr) -> bool {
    for a in &update.attributes {
        match a {
            PathAttribute::OriginatorId(id) if *id == router_id => return true,
            PathAttribute::ClusterList(ids) if ids.contains(&cluster_id) => return true,
            _ => {}
        }
    }
    false
}

/// Whether a received UPDATE's reachability must be ignored for confederation loop
/// avoidance (RFC 5065 §5.4): one of its AS_CONFED_SEQUENCE / AS_CONFED_SET segments
/// already contains our Member-AS, so the route has looped back into our sub-AS.
fn is_confed_loop(update: &Update, member_as: u32) -> bool {
    update.attributes.iter().any(|a| match a {
        PathAttribute::AsPath(segs) => segs
            .iter()
            .any(|s| s.is_confederation() && s.asns().contains(&member_as)),
        _ => false,
    })
}

/// The base-NLRI IPv4 NEXT_HOP attribute of an UPDATE, if present.
fn base_next_hop(update: &Update) -> Option<Ipv4Addr> {
    update.attributes.iter().find_map(|a| match a {
        PathAttribute::NextHop(nh) => Some(*nh),
        _ => None,
    })
}

/// The MP_REACH_NLRI (IPv6 unicast) of an UPDATE: the next hop to install, the
/// reachable prefixes, and whether the next hop is a link-local (RFC 4760 §3 /
/// RFC 2545 §3). A 32-octet next hop carries the speaker's link-local after the
/// global; we forward over that link-local (pinned to the ingress interface),
/// which is what the peer intended on the shared link. Otherwise the global.
fn mp_reach_v6(update: &Update) -> Option<(Ipv6Addr, &[Prefix], bool)> {
    update.attributes.iter().find_map(|a| match a {
        PathAttribute::MpReachNlri { afi, next_hop, nlri, .. } if *afi == AFI_IPV6 => {
            let (global, link_local) = wren_bgp::decode_v6_next_hop(next_hop)?;
            match link_local {
                Some(ll) => Some((ll, nlri.as_slice(), true)),
                None => Some((global, nlri.as_slice(), false)),
            }
        }
        _ => None,
    })
}

/// The MP_UNREACH_NLRI (IPv6 unicast) withdrawals of an UPDATE (RFC 4760 §4).
fn mp_unreach_v6(update: &Update) -> &[Prefix] {
    update
        .attributes
        .iter()
        .find_map(|a| match a {
            PathAttribute::MpUnreachNlri { afi, withdrawn, .. } if *afi == AFI_IPV6 => {
                Some(withdrawn.as_slice())
            }
            _ => None,
        })
        .unwrap_or(&[])
}

/// Whether a learned `path` should be re-advertised to a peer (the Adj-RIB-Out
/// decision) that is `to_ebgp`, a route-reflector client `to_rr_client`, at address
/// `to_peer`. Never echo a route back to where it came from; honour the well-known
/// communities; and apply the propagation / route-reflection rules (RFC 4456 §3.2):
///
/// - a route learned from an **eBGP** peer goes to every peer;
/// - a route learned from a **client** is reflected to every iBGP and eBGP peer;
/// - a route learned from a **non-client iBGP** peer goes only to clients (and
///   eBGP peers) — the iBGP split-horizon rule, which route reflection relaxes
///   precisely for clients.
///
/// With no clients configured this collapses to plain iBGP split horizon. A
/// confed-eBGP peer counts as non-iBGP here (RFC 5065): an iBGP-learned route may
/// cross into another Member-AS, and a confed-learned route propagates freely.
fn should_propagate(path: &Path, to_type: PeerType, to_rr_client: bool, to_peer: Ipv4Addr) -> bool {
    if path.peer_addr == to_peer {
        return false; // don't echo a route back to where we learned it
    }
    let reachable = if path.from_ebgp || path.from_confed || path.from_client {
        true
    } else {
        // iBGP non-client learned: only to clients or non-iBGP peers (eBGP / confed).
        to_rr_client || to_type != PeerType::Ibgp
    };
    if !reachable {
        return false;
    }
    should_advertise(&path.communities, to_type)
}

/// Prepend `asn` to the front of an AS_PATH (RFC 4271 §5.1.2): grow the leading
/// AS_SEQUENCE, or start a new one if the path is empty or begins with an AS_SET.
fn prepend_as(segs: &mut Vec<AsPathSegment>, asn: u32) {
    match segs.first_mut() {
        Some(AsPathSegment::Sequence(v)) => v.insert(0, asn),
        _ => segs.insert(0, AsPathSegment::Sequence(vec![asn])),
    }
}

/// Prepend a Member-AS to the front of an AS_PATH inside an AS_CONFED_SEQUENCE
/// (RFC 5065 §5.3): grow a leading AS_CONFED_SEQUENCE, or start a new one. Used when
/// a route crosses a confederation sub-AS (confed-eBGP) boundary.
fn prepend_confed(segs: &mut Vec<AsPathSegment>, asn: u32) {
    match segs.first_mut() {
        Some(AsPathSegment::ConfedSequence(v)) => v.insert(0, asn),
        _ => segs.insert(0, AsPathSegment::ConfedSequence(vec![asn])),
    }
}

/// Remove every confederation segment (AS_CONFED_SEQUENCE / AS_CONFED_SET) from an
/// AS_PATH (RFC 5065 §6), done before the route leaves the confederation to a true
/// external peer — the internal Member-AS hops must not be visible outside.
fn strip_confed_segments(segs: &mut Vec<AsPathSegment>) {
    segs.retain(|s| !s.is_confederation());
}

/// Whether a route carrying `communities` may be advertised to a peer of the given
/// class, honouring the RFC 1997 well-known communities with the RFC 5065
/// confederation refinement: `NO_ADVERTISE` blocks every peer; `NO_EXPORT` blocks
/// only true eBGP (the route may still cross confederation sub-AS boundaries); and
/// `NO_EXPORT_SUBCONFED` ("local-AS") blocks both confed-eBGP and true eBGP, keeping
/// the route within the Member-AS.
fn should_advertise(communities: &[u32], to_type: PeerType) -> bool {
    use wren_bgp::community::{NO_ADVERTISE, NO_EXPORT, NO_EXPORT_SUBCONFED};
    if communities.contains(&NO_ADVERTISE) {
        return false;
    }
    match to_type {
        PeerType::Ibgp => true,
        PeerType::Confed => !communities.contains(&NO_EXPORT_SUBCONFED),
        PeerType::Ebgp => {
            !communities.contains(&NO_EXPORT) && !communities.contains(&NO_EXPORT_SUBCONFED)
        }
    }
}

/// Actively dial a peer, run the session, and retry on failure.
async fn connector(
    peer: PeerInfo,
    auth: TcpAuth,
    local: Arc<Local>,
    tx: mpsc::Sender<PeerMsg>,
) {
    loop {
        // An authenticated peer needs its key installed on the socket before the
        // handshake, so it gets a hand-built connect; an ordinary peer uses tokio's.
        let dial = async {
            if auth.is_enabled() {
                connect_authed(peer.addr, &auth).await
            } else {
                TcpStream::connect((peer.addr, PORT)).await
            }
        };
        match timeout(CONNECT_TIMEOUT, dial).await {
            Ok(Ok(stream)) => {
                if let Err(e) = drive_session(stream, peer, &local, &tx, false).await {
                    debug!(peer = %peer.addr, error = %e, "BGP session ended");
                }
            }
            Ok(Err(e)) => debug!(peer = %peer.addr, error = %e, "BGP connect failed"),
            Err(_) => debug!(peer = %peer.addr, "BGP connect timed out"),
        }
        sleep(CONNECT_RETRY).await;
    }
}

/// Accept inbound connections and run a session for each known peer.
async fn accept_loop(listener: TcpListener, local: Arc<Local>, tx: mpsc::Sender<PeerMsg>) {
    loop {
        match listener.accept().await {
            Ok((stream, addr)) => {
                let IpAddr::V4(ip) = addr.ip() else {
                    continue; // IPv4 transport only here
                };
                let Some(&props) = local.peers.get(&ip) else {
                    debug!(peer = %ip, "inbound BGP from unconfigured peer; dropping");
                    continue;
                };
                let peer = PeerInfo {
                    addr: ip,
                    remote_as: props.remote_as,
                    rr_client: props.rr_client,
                    peer_type: props.peer_type,
                    ttl_security: props.ttl_security,
                };
                let local = local.clone();
                let tx = tx.clone();
                tokio::spawn(async move {
                    if let Err(e) = drive_session(stream, peer, &local, &tx, true).await {
                        debug!(peer = %ip, error = %e, "BGP inbound session ended");
                    }
                });
            }
            Err(e) => warn!(error = %e, "BGP accept error"),
        }
    }
}

/// Linux `struct tcp_md5sig` (the argument to the `TCP_MD5SIG` setsockopt). The libc
/// crate exposes the `TCP_MD5SIG` constant but not this struct on glibc, so we mirror
/// `<linux/tcp.h>` here. `tcpm_key` is `TCP_MD5SIG_MAXKEYLEN` (80) bytes; the field
/// after `tcpm_keylen` is zero padding when no flags are set.
#[repr(C)]
struct TcpMd5Sig {
    tcpm_addr: libc::sockaddr_storage,
    tcpm_flags: u8,
    tcpm_prefixlen: u8,
    tcpm_keylen: u16,
    tcpm_ifindex: u32,
    tcpm_key: [u8; 80],
}

/// A `sockaddr_in` for `addr:port` in network byte order.
fn sockaddr_in_v4(addr: Ipv4Addr, port: u16) -> libc::sockaddr_in {
    libc::sockaddr_in {
        sin_family: libc::AF_INET as libc::sa_family_t,
        sin_port: port.to_be(),
        sin_addr: libc::in_addr { s_addr: u32::from(addr).to_be() },
        sin_zero: [0; 8],
    }
}

/// Install a TCP-MD5 signature key (RFC 2385) for `peer` on socket `fd`. Set before
/// the handshake, the kernel then signs every segment to that peer and rejects any
/// inbound segment from it whose signature does not match the shared `password`. The
/// key is at most `TCP_MD5SIG_MAXKEYLEN` (80) bytes.
fn set_tcp_md5(fd: i32, peer: Ipv4Addr, password: &str) -> std::io::Result<()> {
    let key = password.as_bytes();
    if key.len() > 80 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "TCP-MD5 password exceeds 80 bytes",
        ));
    }
    let mut sig: TcpMd5Sig = unsafe { std::mem::zeroed() };
    let sin = sockaddr_in_v4(peer, 0);
    // Copy the sockaddr_in into the (larger) sockaddr_storage field.
    unsafe {
        std::ptr::copy_nonoverlapping(
            std::ptr::addr_of!(sin) as *const u8,
            std::ptr::addr_of_mut!(sig.tcpm_addr) as *mut u8,
            std::mem::size_of::<libc::sockaddr_in>(),
        );
    }
    sig.tcpm_keylen = key.len() as u16;
    sig.tcpm_key[..key.len()].copy_from_slice(key);
    let rc = unsafe {
        libc::setsockopt(
            fd,
            libc::IPPROTO_TCP,
            libc::TCP_MD5SIG,
            std::ptr::addr_of!(sig) as *const libc::c_void,
            std::mem::size_of::<TcpMd5Sig>() as libc::socklen_t,
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// Linux `struct tcp_ao_add` (the argument to the `TCP_AO_ADD_KEY` setsockopt,
/// RFC 5925 / `<linux/tcp.h>`). libc does not expose it, so it is mirrored here; the
/// layout (296 bytes) was verified against the running kernel. `set_flags` packs the
/// `set_current:1, set_rnext:1` bitfield (low two bits).
#[repr(C)]
struct TcpAoAdd {
    addr: libc::sockaddr_storage,
    alg_name: [u8; 64],
    ifindex: i32,
    set_flags: u32,
    reserved2: u16,
    prefix: u8,
    sndid: u8,
    rcvid: u8,
    maclen: u8,
    keyflags: u8,
    keylen: u8,
    reserved3: u32,
    key: [u8; 80],
}

/// The `TCP_AO_ADD_KEY` setsockopt name (`<linux/tcp.h>`; not in libc).
const TCP_AO_ADD_KEY: libc::c_int = 38;
/// The maximum TCP-AO key length, and the HMAC-SHA-1-96 MAC length (RFC 5926).
const TCP_AO_MAXKEYLEN: usize = 80;
const TCP_AO_SHA1_MACLEN: u8 = 12;

/// Install a TCP-AO master key (RFC 5925) for `peer` on socket `fd`, using HMAC-SHA-1
/// (the RFC 5926 mandatory algorithm) with `key_id` as both the SendID and the RecvID.
/// Set before the handshake, the kernel then derives per-connection traffic keys and
/// authenticates every segment to/from that peer; the key becomes the current active
/// key immediately (`set_current` / `set_rnext`).
fn set_tcp_ao(fd: i32, peer: Ipv4Addr, key: &str, key_id: u8) -> std::io::Result<()> {
    let kb = key.as_bytes();
    if kb.is_empty() || kb.len() > TCP_AO_MAXKEYLEN {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "TCP-AO key must be 1..=80 bytes",
        ));
    }
    let mut ao: TcpAoAdd = unsafe { std::mem::zeroed() };
    let sin = sockaddr_in_v4(peer, 0);
    unsafe {
        std::ptr::copy_nonoverlapping(
            std::ptr::addr_of!(sin) as *const u8,
            std::ptr::addr_of_mut!(ao.addr) as *mut u8,
            std::mem::size_of::<libc::sockaddr_in>(),
        );
    }
    let alg = b"hmac(sha1)";
    ao.alg_name[..alg.len()].copy_from_slice(alg);
    ao.set_flags = 0b11; // set_current | set_rnext: use this key right away
    ao.prefix = 32; // a host (/32) match for the peer address
    ao.sndid = key_id;
    ao.rcvid = key_id;
    ao.maclen = TCP_AO_SHA1_MACLEN;
    ao.keylen = kb.len() as u8;
    ao.key[..kb.len()].copy_from_slice(kb);
    let rc = unsafe {
        libc::setsockopt(
            fd,
            libc::IPPROTO_TCP,
            TCP_AO_ADD_KEY,
            std::ptr::addr_of!(ao) as *const libc::c_void,
            std::mem::size_of::<TcpAoAdd>() as libc::socklen_t,
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// Put `fd` into non-blocking mode, so a connect can be driven by tokio's reactor.
fn set_nonblocking(fd: i32) -> std::io::Result<()> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        return Err(std::io::Error::last_os_error());
    }
    if unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// Connect to a peer that requires transport authentication (TCP-MD5 or TCP-AO).
/// tokio's `TcpStream::connect` hands back an already-connected socket — too late to
/// install the key, which must cover the SYN — so we build the socket by hand: install
/// the key, start a non-blocking connect, then drive it to completion through tokio.
/// IPv4 only here.
async fn connect_authed(peer: Ipv4Addr, auth: &TcpAuth) -> std::io::Result<TcpStream> {
    use std::os::fd::FromRawFd;
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // Until the fd is handed to a std stream below, close it ourselves on any error.
    let prepared = (|| -> std::io::Result<()> {
        auth.install(fd, peer)?;
        set_nonblocking(fd)?;
        let sin = sockaddr_in_v4(peer, PORT);
        let rc = unsafe {
            libc::connect(
                fd,
                std::ptr::addr_of!(sin) as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
            )
        };
        if rc != 0 {
            let e = std::io::Error::last_os_error();
            // A non-blocking connect reports "in progress"; anything else is fatal.
            if e.raw_os_error() != Some(libc::EINPROGRESS) {
                return Err(e);
            }
        }
        Ok(())
    })();
    if let Err(e) = prepared {
        unsafe { libc::close(fd) };
        return Err(e);
    }
    // From here the std stream owns the fd and closes it on drop.
    let std_stream = unsafe { std::net::TcpStream::from_raw_fd(fd) };
    let stream = TcpStream::from_std(std_stream)?;
    stream.writable().await?; // resolves when the connect completes (or fails)
    if let Some(e) = stream.take_error()? {
        return Err(e);
    }
    Ok(stream)
}

/// Bind the BGP listener by hand so each authenticated peer's key (TCP-MD5 or TCP-AO)
/// is installed before `listen`, letting the kernel verify that peer's inbound
/// connections. IPv4, port 179 on every address — the same bind tokio's
/// `TcpListener::bind` does, with the keys added.
fn bind_listener_authed(peers: &[BgpPeerCfg]) -> std::io::Result<TcpListener> {
    use std::os::fd::FromRawFd;
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let prepared = (|| -> std::io::Result<()> {
        let one: i32 = 1;
        let rc = unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_REUSEADDR,
                std::ptr::addr_of!(one) as *const libc::c_void,
                std::mem::size_of::<i32>() as libc::socklen_t,
            )
        };
        if rc != 0 {
            return Err(std::io::Error::last_os_error());
        }
        for p in peers {
            p.tcp_auth().install(fd, p.addr)?;
        }
        let sin = sockaddr_in_v4(Ipv4Addr::UNSPECIFIED, PORT);
        if unsafe {
            libc::bind(
                fd,
                std::ptr::addr_of!(sin) as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
            )
        } < 0
        {
            return Err(std::io::Error::last_os_error());
        }
        if unsafe { libc::listen(fd, 1024) } < 0 {
            return Err(std::io::Error::last_os_error());
        }
        set_nonblocking(fd)?;
        Ok(())
    })();
    if let Err(e) = prepared {
        unsafe { libc::close(fd) };
        return Err(e);
    }
    let std_listener = unsafe { std::net::TcpListener::from_raw_fd(fd) };
    TcpListener::from_std(std_listener)
}

/// Apply the Generalized TTL Security Mechanism (GTSM, RFC 5082) to a peer's TCP
/// socket: send with IP TTL 255 (`IP_TTL`) and have the kernel reject any received
/// packet whose TTL is below `255 − (hops − 1)` (`IP_MINTTL`). A directly-connected
/// eBGP neighbour uses `hops = 1`, so the minimum accepted TTL is 255 — a packet from
/// an off-path attacker more than one hop away arrives with a decremented TTL and is
/// dropped by the kernel before it ever reaches the session. Applied to both the
/// dialled and the accepted connection (via [`drive_session`]). IPv4 transport only
/// here; a failure is logged but not fatal — GTSM is defence in depth, and a session
/// without it still works.
fn apply_gtsm(stream: &TcpStream, hops: u8) {
    use std::os::fd::AsRawFd;
    let fd = stream.as_raw_fd();
    let min_ttl = 255 - (hops.max(1) as i32 - 1);
    if let Err(e) = crate::rip::setsockopt_int(fd, libc::IPPROTO_IP, libc::IP_TTL, 255) {
        debug!(error = %e, "GTSM: could not set IP_TTL 255");
    }
    if let Err(e) = crate::rip::setsockopt_int(fd, libc::IPPROTO_IP, libc::IP_MINTTL, min_ttl) {
        debug!(error = %e, "GTSM: could not set IP_MINTTL {min_ttl}");
    }
}

/// The per-peer session: the TCP socket is already connected, so the FSM starts at
/// OpenSent and is driven to Established and back by received messages and timers.
async fn drive_session(
    stream: TcpStream,
    peer: PeerInfo,
    local: &Local,
    tx: &mpsc::Sender<PeerMsg>,
    inbound: bool,
) -> Result<()> {
    stream.set_nodelay(true).ok();
    // GTSM (RFC 5082): if configured for this peer, send with TTL 255 and reject
    // packets that arrive with a too-low TTL. Applied here so both the inbound
    // (accepted) and outbound (dialled) connection get it.
    if let Some(hops) = peer.ttl_security {
        apply_gtsm(&stream, hops);
    }
    let local_ip = match stream.local_addr()?.ip() {
        IpAddr::V4(a) => a,
        IpAddr::V6(_) => local.router_id,
    };
    // Resolve the interface facing this peer for RFC 2545 link-local next hops.
    let link = crate::connected::resolve_link(local_ip);
    let (mut rd, wr) = stream.into_split();

    // The central task pushes origination commands (advertise/withdraw) down this
    // channel once we report Established; we hand it the sender then.
    let (cmd_tx, mut cmd_rx) = mpsc::channel::<SessionCmd>(CMD_QUEUE);

    let mut fsm = BgpFsm::new();
    let mut sess = Session {
        wr,
        local,
        peer,
        tx,
        cmd_tx,
        peer_type: peer.peer_type,
        // "true eBGP": a confederation-internal (confed-eBGP) peer is treated as
        // interior for next-hop-self and LOCAL_PREF (RFC 5065 §5.3).
        from_ebgp: peer.peer_type == PeerType::Ebgp,
        local_ip,
        link,
        inbound,
        conn_id: NEXT_CONN_ID.fetch_add(1, Ordering::Relaxed),
        neg_hold: local.hold_time,
        keepalive_int: (local.hold_time / 3).max(1),
        peer_id: peer.addr,
        four_octet: false,
        mp_ipv6: false,
        peer_route_refresh: false,
        peer_gr: None,
        established: false,
        hold_deadline: Instant::now() + FAR,
        ka_deadline: Instant::now() + FAR,
    };

    // The TCP connection is already up: ManualStart then TcpConnected take the FSM
    // straight to OpenSent (SendOpen, arm the Hold timer).
    let _ = fsm.handle(Event::ManualStart);
    let acts = fsm.handle(Event::TcpConnected);
    if sess.apply(&acts).await? {
        return Ok(());
    }

    loop {
        if fsm.state() == State::Idle {
            break;
        }
        let hold = sleep_until(sess.hold_deadline);
        let ka = sleep_until(sess.ka_deadline);
        tokio::pin!(hold, ka);

        let four = sess.four_octet;
        let step = tokio::select! {
            r = read_message(&mut rd, four) => match r {
                Ok(msg) => match &msg {
                    Message::Open(o) => {
                        let peer_as = o.effective_as();
                        if peer_as != sess.peer.remote_as {
                            warn!(peer = %sess.peer.addr, expected = sess.peer.remote_as, got = peer_as, "BGP OPEN AS mismatch");
                            Step::Event(Event::OpenError)
                        } else {
                            sess.peer_id = o.identifier;
                            // 4-octet AS_PATH only when both speakers advertised the
                            // capability (RFC 6793 §4); we always do.
                            sess.four_octet = o.supports_four_octet_as();
                            // Send IPv6 NLRI only if the peer can receive it (RFC 4760).
                            sess.mp_ipv6 = o.supports_multiprotocol(AFI_IPV6, SAFI_UNICAST);
                            // Send a ROUTE-REFRESH only if the peer can honour it (RFC 2918).
                            sess.peer_route_refresh = o.supports_route_refresh();
                            // Graceful Restart (RFC 4724): help this peer through a
                            // restart only if it preserves IPv4-unicast forwarding;
                            // remember the Restart Time to bound the retention.
                            sess.peer_gr = o
                                .gr_forwarding_preserved(AFI_IPV4, SAFI_UNICAST)
                                .then(|| o.gr_restart_time().unwrap_or(0));
                            sess.neg_hold = sess.local.hold_time.min(o.hold_time);
                            sess.keepalive_int = (sess.neg_hold / 3).max(1);
                            Step::Event(Event::OpenReceived)
                        }
                    }
                    Message::Keepalive => Step::Event(Event::KeepAliveReceived),
                    Message::Update(u) => {
                        if fsm.is_established() {
                            if u.end_of_rib().is_some() {
                                // An End-of-RIB marker (RFC 4724 §2): the peer has
                                // finished re-advertising. Signal the central task so
                                // it can finalise a graceful restart, rather than
                                // feeding an empty UPDATE into the RIB.
                                let _ = sess.tx.send(PeerMsg::EndOfRib {
                                    peer: sess.peer.addr,
                                    conn_id: sess.conn_id,
                                }).await;
                            } else {
                                let _ = sess.tx.send(PeerMsg::Update {
                                    peer: sess.peer.addr,
                                    peer_as: sess.peer.remote_as,
                                    peer_id: sess.peer_id,
                                    from_ebgp: sess.from_ebgp,
                                    from_confed: sess.peer_type == PeerType::Confed,
                                    from_client: sess.peer.rr_client,
                                    ingress_iface: sess.link.as_ref().map(|(n, _)| n.clone()),
                                    update: u.clone(),
                                }).await;
                            }
                        }
                        Step::Event(Event::UpdateReceived)
                    }
                    Message::Notification(n) => {
                        debug!(peer = %sess.peer.addr, code = n.code, subcode = n.subcode, "BGP NOTIFICATION received");
                        Step::Event(Event::NotificationReceived)
                    }
                    // ROUTE-REFRESH (RFC 2918): the peer asks us to re-advertise our
                    // Adj-RIB-Out. Forward the request to the central task, which
                    // re-pushes the origination snapshot and Loc-RIB to this session.
                    // It is not an FSM event (the session stays Established).
                    Message::RouteRefresh { afi, safi } => {
                        if fsm.is_established() {
                            debug!(peer = %sess.peer.addr, afi, safi, "BGP ROUTE-REFRESH received");
                            let _ = sess.tx.send(PeerMsg::RefreshRequest {
                                peer: sess.peer.addr,
                                conn_id: sess.conn_id,
                            }).await;
                        }
                        Step::Handled
                    }
                },
                Err(e) => {
                    debug!(peer = %sess.peer.addr, error = %e, "BGP read error");
                    Step::ReadFailed
                }
            },
            () = &mut hold => Step::Event(Event::HoldTimerExpires),
            () = &mut ka => Step::Event(Event::KeepaliveTimerExpires),
            cmd = cmd_rx.recv() => match cmd {
                Some(c) => Step::Cmd(c),
                None => Step::ReadFailed, // central task gone — tear the session down
            },
        };

        match step {
            Step::Event(event) => {
                let acts = fsm.handle(event);
                if sess.apply(&acts).await? {
                    break;
                }
            }
            // Origination commands only matter once Established; before that the
            // central task has not yet been handed our channel anyway.
            Step::Cmd(SessionCmd::Advertise(routes)) => {
                if sess.established {
                    sess.advertise(&routes).await?;
                }
            }
            Step::Cmd(SessionCmd::Withdraw(prefixes)) => {
                if sess.established {
                    sess.withdraw(&prefixes).await?;
                }
            }
            Step::Cmd(SessionCmd::Propagate(routes)) => {
                if sess.established {
                    sess.propagate_routes(&routes).await?;
                }
            }
            Step::Cmd(SessionCmd::WithdrawPropagated(prefixes)) => {
                if sess.established {
                    sess.withdraw(&prefixes).await?;
                }
            }
            Step::Handled => {}
            // The central task asks us to send a ROUTE-REFRESH to the peer (the
            // operator ran `bgp refresh <peer>`). Send it for IPv4 unicast, and for
            // IPv6 unicast too when that family is negotiated (RFC 2918 §3).
            Step::Cmd(SessionCmd::SendRefresh) => {
                if sess.established && sess.peer_route_refresh {
                    let _ = sess
                        .send(&Message::RouteRefresh { afi: AFI_IPV4, safi: SAFI_UNICAST })
                        .await;
                    if sess.mp_ipv6 {
                        let _ = sess
                            .send(&Message::RouteRefresh { afi: AFI_IPV6, safi: SAFI_UNICAST })
                            .await;
                    }
                }
            }
            // Send the End-of-RIB marker(s) (RFC 4724 §2) now the initial
            // advertisement to this peer is complete: IPv4 unicast always, and IPv6
            // unicast too when that family is negotiated.
            Step::Cmd(SessionCmd::SendEndOfRib) => {
                if sess.established {
                    let _ = sess
                        .send(&Message::Update(Update::end_of_rib_marker(AFI_IPV4, SAFI_UNICAST)))
                        .await;
                    if sess.mp_ipv6 {
                        let _ = sess
                            .send(&Message::Update(Update::end_of_rib_marker(AFI_IPV6, SAFI_UNICAST)))
                            .await;
                    }
                }
            }
            Step::Cmd(SessionCmd::Shutdown) => {
                // Lost §6.8 collision resolution: tell the peer with a Cease
                // (Connection Collision Resolution) and close, but do NOT report
                // Down — the winning connection owns this peer's slot in the
                // central task, and a Down would evict it.
                let _ = sess
                    .send(&Message::Notification(Notification {
                        code: CODE_CEASE,
                        subcode: CEASE_COLLISION,
                        data: vec![],
                    }))
                    .await;
                return Ok(());
            }
            Step::Cmd(SessionCmd::CeaseOverLimit) => {
                // The peer blew its max-prefix limit: send a Cease "Maximum Number of
                // Prefixes Reached" and close. Like Shutdown we do NOT report Down —
                // the central task already withdrew this peer's routes and damped it.
                let _ = sess
                    .send(&Message::Notification(Notification {
                        code: CODE_CEASE,
                        subcode: CEASE_MAXPREFIX,
                        data: vec![],
                    }))
                    .await;
                return Ok(());
            }
            Step::ReadFailed => {
                let acts = fsm.handle(Event::TcpConnectionFails);
                let _ = sess.apply(&acts).await;
                break;
            }
        }
    }
    Ok(())
}

/// What woke a session's select loop: an FSM event, an origination command from
/// the central task, or a fatal read/channel failure that tears the session down.
enum Step {
    Event(Event),
    Cmd(SessionCmd),
    /// A message was handled inline with no FSM transition (e.g. ROUTE-REFRESH).
    Handled,
    ReadFailed,
}

/// The mutable per-session state plus the write half of the socket.
struct Session<'a> {
    wr: OwnedWriteHalf,
    local: &'a Local,
    peer: PeerInfo,
    tx: &'a mpsc::Sender<PeerMsg>,
    /// Handed to the central task on Established so it can push origination
    /// commands (advertise/withdraw) back to this session.
    cmd_tx: mpsc::Sender<SessionCmd>,
    /// How this peer relates to us (RFC 5065): iBGP, confed-eBGP or true eBGP —
    /// drives the AS_PATH manipulation and the OPEN's My-AS.
    peer_type: PeerType,
    /// Whether this peer is a *true* external (eBGP) peer — confed-eBGP is interior
    /// here (next-hop-self, LOCAL_PREF drop, the received-path eBGP flag).
    from_ebgp: bool,
    local_ip: Ipv4Addr,
    /// The local interface this session rides and its IPv6 link-local, resolved
    /// from `local_ip` (RFC 2545): the link-local we advertise as the second
    /// next-hop address toward a directly-connected peer, and the interface we pin
    /// a received link-local next hop to. `None` if it couldn't be resolved.
    link: Option<(String, Ipv6Addr)>,
    /// Whether this connection was accepted (inbound) vs dialled (outbound), for
    /// §6.8 collision detection.
    inbound: bool,
    /// This connection's unique id, so the central task can distinguish the
    /// surviving session's Established/Down from a stale loser's.
    conn_id: u64,
    neg_hold: u16,
    keepalive_int: u16,
    peer_id: Ipv4Addr,
    /// Whether the peer advertised the 4-octet AS capability (RFC 6793) — sets the
    /// AS_PATH wire width for UPDATEs we send and receive.
    four_octet: bool,
    /// Whether the peer advertised the IPv6-unicast Multiprotocol capability
    /// (RFC 4760) — only then do we send it IPv6 NLRI in MP_REACH_NLRI.
    mp_ipv6: bool,
    /// Whether the peer advertised the Route Refresh capability (RFC 2918) — only
    /// then do we send it a ROUTE-REFRESH (it would not honour one otherwise).
    peer_route_refresh: bool,
    /// The peer's Graceful Restart Restart Time (RFC 4724), if it advertised GR with
    /// the forwarding state preserved for IPv4 unicast — handed to the central task
    /// on Established so it retains this peer's routes through a restart.
    peer_gr: Option<u16>,
    established: bool,
    hold_deadline: Instant,
    ka_deadline: Instant,
}

impl Session<'_> {
    /// Carry out the FSM's actions; returns `true` if the TCP connection must be
    /// torn down (the caller then ends the session).
    async fn apply(&mut self, acts: &[Action]) -> Result<bool> {
        let mut drop_tcp = false;
        for a in acts {
            match a {
                Action::SendOpen => {
                    // RFC 5065 §4.2: present the Confederation Identifier to a true
                    // external peer, but the Member-AS to a confederation peer (iBGP
                    // or confed-eBGP). Without a confederation both are `local_as`.
                    let my_as = if self.peer_type == PeerType::Ebgp {
                        self.local.external_as()
                    } else {
                        self.local.local_as
                    };
                    let open = Message::Open(Open::new(
                        VERSION,
                        my_as,
                        self.local.hold_time,
                        self.local.router_id,
                    ));
                    self.send(&open).await?;
                }
                Action::SendKeepalive => {
                    self.send(&Message::Keepalive).await?;
                    self.ka_deadline = self.next_keepalive();
                }
                Action::SendNotification { code, subcode } => {
                    self.send(&Message::Notification(Notification {
                        code: *code,
                        subcode: *subcode,
                        data: vec![],
                    }))
                    .await?;
                }
                Action::StartHoldTimer | Action::RestartHoldTimer => {
                    self.hold_deadline = self.next_hold();
                }
                Action::StartKeepaliveTimer => {
                    self.ka_deadline = self.next_keepalive();
                }
                Action::SessionEstablished => {
                    self.established = true;
                    // Hand the central task our command channel; it replies with the
                    // current origination snapshot, which we advertise on receipt.
                    let _ = self
                        .tx
                        .send(PeerMsg::Established {
                            peer: self.peer.addr,
                            peer_id: self.peer_id,
                            inbound: self.inbound,
                            conn_id: self.conn_id,
                            gr_restart_time: self.peer_gr,
                            cmd_tx: self.cmd_tx.clone(),
                        })
                        .await;
                }
                Action::SessionDown => {
                    if self.established {
                        let _ = self
                            .tx
                            .send(PeerMsg::Down { peer: self.peer.addr, conn_id: self.conn_id })
                            .await;
                        self.established = false;
                    }
                }
                Action::DropTcp => drop_tcp = true,
                // The connector owns connection retries; nothing to do here.
                Action::ConnectTcp
                | Action::StartConnectRetryTimer
                | Action::StopConnectRetryTimer => {}
            }
        }
        Ok(drop_tcp)
    }

    /// The next Hold-timer deadline (disabled when the negotiated Hold Time is 0).
    fn next_hold(&self) -> Instant {
        if self.neg_hold == 0 {
            Instant::now() + FAR
        } else {
            Instant::now() + Duration::from_secs(self.neg_hold as u64)
        }
    }

    /// The next Keepalive-timer deadline (disabled when Hold Time is 0).
    fn next_keepalive(&self) -> Instant {
        if self.neg_hold == 0 {
            Instant::now() + FAR
        } else {
            Instant::now() + Duration::from_secs(self.keepalive_int as u64)
        }
    }

    /// Build the MP_REACH next-hop field for an IPv6 advertisement with global next
    /// hop `global`. When we set next-hop-self (`next_hop_self`) on a directly
    /// connected link — we resolved a link-local for the egress interface — we
    /// append it, a 32-octet next hop per RFC 2545 §3, so a peer on the shared
    /// subnet forwards over our link-local. Otherwise just the 16-octet global.
    fn v6_next_hop_field(&self, global: Ipv6Addr, next_hop_self: bool) -> Vec<u8> {
        let link_local = if next_hop_self {
            self.link.as_ref().map(|(_, ll)| *ll)
        } else {
            None
        };
        wren_bgp::encode_v6_next_hop(global, link_local)
    }

    /// Advertise originated routes to this peer, building the per-peer attributes
    /// (AS_PATH, next-hop-self, COMMUNITIES, LARGE_COMMUNITY). Routes are grouped by
    /// their full tag set so each UPDATE carries a single COMMUNITIES /
    /// LARGE_COMMUNITY attribute, and a route whose well-known communities forbid
    /// this peer (RFC 1997) is skipped.
    async fn advertise(&mut self, routes: &[OriginRoute]) -> Result<()> {
        type TagKey = (Vec<u32>, Vec<(u32, u32, u32)>, Vec<[u8; 8]>);
        let mut groups: BTreeMap<TagKey, Vec<Prefix>> = BTreeMap::new();
        for r in routes {
            // Aggregates carry extra attributes (ATOMIC_AGGREGATE/AGGREGATOR) and are
            // sent individually below, not folded into a tag group.
            if r.atomic_aggregate {
                continue;
            }
            if should_advertise(&r.communities, self.peer_type) {
                groups
                    .entry((
                        r.communities.clone(),
                        r.large_communities.clone(),
                        r.ext_communities.clone(),
                    ))
                    .or_default()
                    .push(r.prefix);
            }
        }
        for ((communities, large_communities, ext_communities), nlri) in groups {
            // The attributes shared by every NLRI in this tag group (everything but
            // the family-specific next hop). For an IPv6 group the next hop rides in
            // MP_REACH_NLRI instead of the base NEXT_HOP attribute.
            let mut base = self.base_path_attrs();
            if !communities.is_empty() {
                base.push(PathAttribute::Communities(communities));
            }
            if !large_communities.is_empty() {
                base.push(PathAttribute::LargeCommunities(large_communities));
            }
            if !ext_communities.is_empty() {
                base.push(PathAttribute::ExtendedCommunities(ext_communities));
            }

            let (v4, v6): (Vec<Prefix>, Vec<Prefix>) = nlri.into_iter().partition(|p| p.is_ipv4());
            self.send_originated_update(base, v4, v6).await?;
        }

        // Address aggregates (RFC 4271 §9.2.2.2): each carries ATOMIC_AGGREGATE and
        // AGGREGATOR (and AS4_AGGREGATOR toward a legacy 2-octet peer, RFC 6793 §3)
        // and is sent in its own UPDATE.
        for r in routes.iter().filter(|r| r.atomic_aggregate) {
            if !should_advertise(&r.communities, self.peer_type) {
                continue;
            }
            let mut base = self.base_path_attrs();
            base.push(PathAttribute::AtomicAggregate);
            let agg_as = self.local.external_as();
            if !self.four_octet && agg_as > u16::MAX as u32 {
                base.push(PathAttribute::Aggregator { asn: AS_TRANS as u32, id: self.local.router_id });
                base.push(PathAttribute::As4Aggregator { asn: agg_as, id: self.local.router_id });
            } else {
                base.push(PathAttribute::Aggregator { asn: agg_as, id: self.local.router_id });
            }
            if !r.communities.is_empty() {
                base.push(PathAttribute::Communities(r.communities.clone()));
            }
            if !r.large_communities.is_empty() {
                base.push(PathAttribute::LargeCommunities(r.large_communities.clone()));
            }
            if !r.ext_communities.is_empty() {
                base.push(PathAttribute::ExtendedCommunities(r.ext_communities.clone()));
            }
            let (v4, v6) = if r.prefix.is_ipv4() {
                (vec![r.prefix], vec![])
            } else {
                (vec![], vec![r.prefix])
            };
            self.send_originated_update(base, v4, v6).await?;
        }
        Ok(())
    }

    /// The path attributes shared by every originated UPDATE to this peer (everything
    /// but the family-specific next hop and any per-route COMMUNITIES): ORIGIN plus
    /// the peer-type AS_PATH / LOCAL_PREF (RFC 4271 + RFC 5065), and AS4_PATH toward a
    /// legacy 2-octet peer (RFC 6793).
    fn base_path_attrs(&self) -> Vec<PathAttribute> {
        let mut base = vec![PathAttribute::Origin(Origin::Igp)];
        match self.peer_type {
            PeerType::Ebgp => {
                // True eBGP: prepend the externally visible AS (the Confederation
                // Identifier if we are in a confederation, else our AS).
                let ext = self.local.external_as();
                base.push(PathAttribute::AsPath(vec![AsPathSegment::Sequence(vec![ext])]));
                // Toward a legacy 2-octet peer our AS would collapse to AS_TRANS on the
                // wire; carry the real 4-octet AS in AS4_PATH (RFC 6793).
                if !self.four_octet && ext > u16::MAX as u32 {
                    base.push(PathAttribute::As4Path(vec![AsPathSegment::Sequence(vec![ext])]));
                }
            }
            PeerType::Confed => {
                // Confed-eBGP (RFC 5065 §5.3): prepend our Member-AS to an
                // AS_CONFED_SEQUENCE — internal to the confederation — and carry
                // LOCAL_PREF, which is honoured across member-AS boundaries.
                base.push(PathAttribute::AsPath(vec![AsPathSegment::ConfedSequence(vec![
                    self.local.local_as,
                ])]));
                base.push(PathAttribute::LocalPref(DEFAULT_LOCAL_PREF));
            }
            PeerType::Ibgp => {
                // iBGP: empty AS_PATH, carry LOCAL_PREF.
                base.push(PathAttribute::AsPath(vec![]));
                base.push(PathAttribute::LocalPref(DEFAULT_LOCAL_PREF));
            }
        }
        base
    }

    /// Send an originated UPDATE carrying `base` attributes: IPv4 NLRI with the IPv4
    /// NEXT_HOP (next-hop-self), and/or IPv6 NLRI via MP_REACH_NLRI (RFC 4760) — the
    /// latter only if the peer negotiated IPv6 and a next-hop6 is configured.
    async fn send_originated_update(
        &mut self,
        base: Vec<PathAttribute>,
        v4: Vec<Prefix>,
        v6: Vec<Prefix>,
    ) -> Result<()> {
        // IPv4 unicast: base NLRI with the IPv4 NEXT_HOP (next-hop-self).
        if !v4.is_empty() {
            let mut attributes = base.clone();
            attributes.push(PathAttribute::NextHop(self.local_ip));
            self.send(&Message::Update(Update { withdrawn: vec![], attributes, nlri: v4 }))
                .await?;
        }

        // IPv6 unicast: MP_REACH_NLRI, only if the peer negotiated it and we have a
        // next-hop-self to advertise.
        if !v6.is_empty() {
            match (self.mp_ipv6, self.local.next_hop6) {
                (true, Some(nh6)) => {
                    let mut attributes = base;
                    attributes.push(PathAttribute::MpReachNlri {
                        afi: AFI_IPV6,
                        safi: SAFI_UNICAST,
                        // We originate, so this is always next-hop-self.
                        next_hop: self.v6_next_hop_field(nh6, true),
                        nlri: v6,
                    });
                    self.send(&Message::Update(Update { withdrawn: vec![], attributes, nlri: vec![] }))
                        .await?;
                }
                (false, _) => debug!(peer = %self.peer.addr, "peer has no IPv6 capability; not advertising IPv6 NLRI"),
                (true, None) => warn!(peer = %self.peer.addr, "IPv6 routes to advertise but no `[bgp] next-hop6` configured"),
            }
        }
        Ok(())
    }

    /// Withdraw originated prefixes from this peer: IPv4 in the base Withdrawn Routes
    /// field, IPv6 in MP_UNREACH_NLRI (RFC 4760 §4).
    async fn withdraw(&mut self, prefixes: &[Prefix]) -> Result<()> {
        if prefixes.is_empty() {
            return Ok(());
        }
        let (v4, v6): (Vec<Prefix>, Vec<Prefix>) =
            prefixes.iter().copied().partition(|p| p.is_ipv4());
        if !v4.is_empty() {
            self.send(&Message::Update(Update {
                withdrawn: v4,
                attributes: vec![],
                nlri: vec![],
            }))
            .await?;
        }
        if !v6.is_empty() && self.mp_ipv6 {
            self.send(&Message::Update(Update {
                withdrawn: vec![],
                attributes: vec![PathAttribute::MpUnreachNlri {
                    afi: AFI_IPV6,
                    safi: SAFI_UNICAST,
                    withdrawn: v6,
                }],
                nlri: vec![],
            }))
            .await?;
        }
        Ok(())
    }

    /// Re-advertise learned Loc-RIB routes to this peer (the Adj-RIB-Out), applying
    /// the propagation rules: never echo a route back to the peer it came from,
    /// never pass an iBGP-learned route to another iBGP peer (split horizon, absent
    /// route reflection), and honour the NO_EXPORT / NO_ADVERTISE communities.
    /// IPv4 unicast only for now.
    async fn propagate_routes(&mut self, routes: &[PropRoute]) -> Result<()> {
        for r in routes {
            if !should_propagate(&r.path, self.peer_type, self.peer.rr_client, self.peer.addr) {
                continue;
            }
            let mut attributes = self.propagated_base_attrs(&r.path);
            if r.prefix.is_ipv4() {
                // IPv4: base NLRI with the IPv4 NEXT_HOP — preserved for iBGP, set
                // to ourselves for eBGP.
                let nh = if self.from_ebgp {
                    self.local_ip
                } else if let IpAddr::V4(v4) = r.path.next_hop {
                    v4
                } else {
                    continue; // a v4 prefix with a non-v4 next hop: malformed, skip
                };
                attributes.push(PathAttribute::NextHop(nh));
                self.send(&Message::Update(Update {
                    withdrawn: vec![],
                    attributes,
                    nlri: vec![r.prefix],
                }))
                .await?;
            } else {
                // IPv6: MP_REACH_NLRI, only if the peer negotiated it. The next hop
                // is preserved for iBGP, or our next-hop-self6 for eBGP.
                if !self.mp_ipv6 {
                    continue;
                }
                let nh6 = if self.from_ebgp {
                    match self.local.next_hop6 {
                        Some(n) => n,
                        None => {
                            warn!(peer = %self.peer.addr, "IPv6 route to propagate but no `[bgp] next-hop6` configured");
                            continue;
                        }
                    }
                } else if let IpAddr::V6(v6) = r.path.next_hop {
                    v6
                } else {
                    continue;
                };
                attributes.push(PathAttribute::MpReachNlri {
                    afi: AFI_IPV6,
                    safi: SAFI_UNICAST,
                    // Toward eBGP we set next-hop-self (so append our link-local on a
                    // shared link); toward iBGP the global next hop is preserved.
                    next_hop: self.v6_next_hop_field(nh6, self.from_ebgp),
                    nlri: vec![r.prefix],
                });
                self.send(&Message::Update(Update {
                    withdrawn: vec![],
                    attributes,
                    nlri: vec![],
                }))
                .await?;
            }
        }
        Ok(())
    }

    /// Build the family-agnostic path attributes for re-advertising a learned
    /// `path` to this peer — everything but the family-specific next hop (the IPv4
    /// NEXT_HOP or the IPv6 MP_REACH_NLRI), which the caller appends.
    fn propagated_base_attrs(&self, path: &Path) -> Vec<PathAttribute> {
        let mut attrs = vec![PathAttribute::Origin(path.origin)];
        let mut as_path = path.as_path.clone();
        match self.peer_type {
            PeerType::Ebgp => {
                // True eBGP egress (RFC 5065 §6): the route leaves the confederation,
                // so strip the internal AS_CONFED_SEQUENCE / AS_CONFED_SET segments
                // and prepend the externally visible AS (the Confederation Identifier
                // when in a confederation, else our AS).
                strip_confed_segments(&mut as_path);
                prepend_as(&mut as_path, self.local.external_as());
                attrs.push(PathAttribute::AsPath(as_path));
            }
            PeerType::Confed => {
                // Confed-eBGP (RFC 5065 §5.3): prepend our Member-AS to the
                // AS_CONFED_SEQUENCE — the confed segments stay internal — and carry
                // LOCAL_PREF / MED across the sub-AS boundary.
                prepend_confed(&mut as_path, self.local.local_as);
                attrs.push(PathAttribute::AsPath(as_path));
                attrs.push(PathAttribute::LocalPref(path.local_pref));
                if path.med != 0 {
                    attrs.push(PathAttribute::MultiExitDisc(path.med));
                }
            }
            PeerType::Ibgp => {
                // iBGP: AS_PATH unchanged, carry LOCAL_PREF / MED.
                attrs.push(PathAttribute::AsPath(as_path));
                attrs.push(PathAttribute::LocalPref(path.local_pref));
                if path.med != 0 {
                    attrs.push(PathAttribute::MultiExitDisc(path.med));
                }
                // Route reflection (RFC 4456 §8): when reflecting an iBGP-learned
                // route to an iBGP peer, stamp ORIGINATOR_ID (the router that
                // introduced it, preserved if already present) and prepend our
                // CLUSTER_ID to the CLUSTER_LIST so a later reflector detects a loop.
                // A route entering this Member-AS from eBGP or confed-eBGP is a fresh
                // introduction, not a reflection, so it gets no reflection attributes.
                if !path.from_ebgp && !path.from_confed {
                    let originator = path.originator_id.unwrap_or(path.peer_id);
                    attrs.push(PathAttribute::OriginatorId(originator));
                    let mut cl = path.cluster_list.clone();
                    cl.insert(0, self.local.cluster_id);
                    attrs.push(PathAttribute::ClusterList(cl));
                }
            }
        }
        if !path.communities.is_empty() {
            attrs.push(PathAttribute::Communities(path.communities.clone()));
        }
        if !path.large_communities.is_empty() {
            attrs.push(PathAttribute::LargeCommunities(path.large_communities.clone()));
        }
        if !path.ext_communities.is_empty() {
            attrs.push(PathAttribute::ExtendedCommunities(path.ext_communities.clone()));
        }
        attrs
    }

    /// Frame and write one BGP message at the session's negotiated AS width.
    async fn send(&mut self, msg: &Message) -> Result<()> {
        self.wr
            .write_all(&msg.encode(self.four_octet))
            .await
            .context("writing BGP message")?;
        Ok(())
    }
}

/// Read one length-prefixed BGP message: the 19-byte header gives the total
/// length, then the remaining body follows. `four_octet` is the session's
/// negotiated AS_PATH width for decoding an UPDATE (RFC 6793).
async fn read_message(rd: &mut OwnedReadHalf, four_octet: bool) -> Result<Message> {
    let mut hdr = [0u8; HEADER_LEN];
    rd.read_exact(&mut hdr)
        .await
        .context("reading BGP header")?;
    if hdr[..16] != MARKER {
        anyhow::bail!("bad BGP marker");
    }
    let len = u16::from_be_bytes([hdr[16], hdr[17]]) as usize;
    if !(HEADER_LEN..=MAX_MESSAGE_LEN).contains(&len) {
        anyhow::bail!("bad BGP length {len}");
    }
    let mut buf = vec![0u8; len];
    buf[..HEADER_LEN].copy_from_slice(&hdr);
    if len > HEADER_LEN {
        rd.read_exact(&mut buf[HEADER_LEN..])
            .await
            .context("reading BGP body")?;
    }
    Message::decode(&buf, four_octet).map_err(|e| anyhow::anyhow!("decoding BGP message: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use wren_bgp::community::{NO_ADVERTISE, NO_EXPORT};
    use wren_bgp::decision::Path;
    use wren_core::Prefix;

    fn ip(o: [u8; 4]) -> Ipv4Addr {
        Ipv4Addr::from(o)
    }

    #[test]
    fn render_routes_shows_attributes_and_communities() {
        let mut rib = BgpRib::new();
        let path = Path {
            origin: Origin::Igp,
            as_path: vec![AsPathSegment::Sequence(vec![65001, 196_618])],
            next_hop: IpAddr::V4(ip([192, 0, 2, 1])),
            next_hop_iface: None,
            local_pref: 100,
            med: 0,
            from_ebgp: true,
            from_confed: false,
            peer_as: 65001,
            igp_metric: 0,
            peer_id: ip([10, 0, 0, 1]),
            peer_addr: ip([10, 0, 0, 1]),
            from_client: false,
            originator_id: None,
            cluster_list: vec![],
            communities: vec![0xFDE9_0064, NO_EXPORT],
            large_communities: vec![(65001, 1, 2)],
            ext_communities: vec![[0x00, 0x02, 0xFD, 0xE9, 0x00, 0x00, 0x00, 0x64]], // rt:65001:100
        };
        rib.update(ip([10, 0, 0, 1]), "10.0.0.0/8".parse::<Prefix>().unwrap(), path);
        let out = render_bgp_routes(&rib);
        assert!(out.contains("10.0.0.0/8 via 192.0.2.1"));
        assert!(out.contains("large-communities 65001:1:2"));
        assert!(out.contains("ext-communities rt:65001:100"));
        assert!(out.contains("as-path 65001 196618"));
        assert!(out.contains("communities 65001:100 no-export"));
        assert!(out.contains("localpref 100"));
        assert!(out.contains("origin igp"));
    }

    #[test]
    fn render_routes_empty_rib() {
        assert_eq!(render_bgp_routes(&BgpRib::new()), "no bgp routes\n");
    }

    #[test]
    fn render_neighbors_lists_state() {
        let n = vec![
            NeighborSummary { addr: ip([10, 0, 0, 2]), remote_as: 65002, established: true, refreshes_received: 2 },
            NeighborSummary { addr: ip([10, 0, 0, 3]), remote_as: 4_200_000_000, established: false, refreshes_received: 0 },
        ];
        let out = render_bgp_neighbors(&n);
        assert!(out.contains("10.0.0.2 AS 65002 Established refreshes 2"));
        assert!(out.contains("10.0.0.3 AS 4200000000 Idle"));
        // A peer with no refreshes does not show the counter.
        assert!(!out.lines().find(|l| l.contains("10.0.0.3")).unwrap().contains("refreshes"));
        assert_eq!(render_bgp_neighbors(&[]), "no bgp neighbors configured\n");
    }

    fn learned_path(from_ebgp: bool, from_peer: [u8; 4]) -> Path {
        Path {
            origin: Origin::Igp,
            as_path: vec![AsPathSegment::Sequence(vec![65001])],
            next_hop: IpAddr::V4(ip(from_peer)),
            next_hop_iface: None,
            local_pref: 100,
            med: 0,
            from_ebgp,
            from_confed: false,
            peer_as: 65001,
            igp_metric: 0,
            peer_id: ip(from_peer),
            peer_addr: ip(from_peer),
            from_client: false,
            originator_id: None,
            cluster_list: vec![],
            communities: vec![],
            large_communities: vec![],
            ext_communities: vec![],
        }
    }

    #[test]
    fn import_filter_rejects_passes_and_modifies() {
        use wren_filter::{Action, Filter, Match, Modify, PrefixList, PrefixPattern, Rule};
        let prefix: Prefix = "10.50.0.0/16".parse().unwrap();
        let path = learned_path(true, [10, 0, 0, 2]);

        // No filter: the path passes through untouched.
        let out = apply_import(None, prefix, &path).expect("no filter accepts");
        assert_eq!(out.local_pref, 100);
        assert!(out.communities.is_empty());

        // reject-all drops the route.
        assert!(apply_import(Some(&Filter::reject_all()), prefix, &path).is_none());

        // A rule that matches the prefix, sets the preference (→LOCAL_PREF) and tags a
        // community; the modifications are folded back into the path.
        let filter = Filter {
            rules: vec![Rule {
                matcher: Match::prefix(PrefixList(vec![PrefixPattern::orlonger(
                    "10.50.0.0/16".parse().unwrap(),
                )])),
                modify: Modify { set_preference: Some(250), add_communities: vec![0xFFFF_FF01], ..Modify::default() },
                action: Action::Accept,
            }],
            default: Action::Reject,
        };
        let out = apply_import(Some(&filter), prefix, &path).expect("rule accepts");
        assert_eq!(out.local_pref, 250);
        assert_eq!(out.communities, vec![0xFFFF_FF01]);

        // A prefix the rule does not match falls to the default (reject).
        let other: Prefix = "192.168.0.0/24".parse().unwrap();
        assert!(apply_import(Some(&filter), other, &path).is_none());
    }

    #[test]
    fn collision_keeps_the_higher_identifier_connection() {
        // We have the lower id -> keep the inbound (peer-initiated) connection.
        assert!(collision_keeps_inbound(ip([10, 0, 0, 1]), ip([10, 0, 0, 2])));
        // We have the higher id -> keep our own outbound connection.
        assert!(!collision_keeps_inbound(ip([10, 0, 0, 2]), ip([10, 0, 0, 1])));
        // Equal ids (a misconfiguration) -> keep the outbound.
        assert!(!collision_keeps_inbound(ip([10, 0, 0, 1]), ip([10, 0, 0, 1])));
    }

    #[test]
    fn prepend_as_grows_or_starts_a_sequence() {
        // Grows an existing leading sequence.
        let mut p = vec![AsPathSegment::Sequence(vec![65001, 65002])];
        prepend_as(&mut p, 65000);
        assert_eq!(p, vec![AsPathSegment::Sequence(vec![65000, 65001, 65002])]);

        // Empty path → a fresh sequence.
        let mut p = vec![];
        prepend_as(&mut p, 65000);
        assert_eq!(p, vec![AsPathSegment::Sequence(vec![65000])]);

        // Leading set → a new sequence is inserted in front of it.
        let mut p = vec![AsPathSegment::Set(vec![10, 11])];
        prepend_as(&mut p, 65000);
        assert_eq!(
            p,
            vec![AsPathSegment::Sequence(vec![65000]), AsPathSegment::Set(vec![10, 11])]
        );
    }

    #[test]
    fn propagation_never_echoes_to_the_origin_peer() {
        let path = learned_path(true, [10, 0, 0, 1]);
        // To the very peer it came from: suppressed.
        assert!(!should_propagate(&path, PeerType::Ebgp, false, ip([10, 0, 0, 1])));
        // To a different eBGP peer: propagated.
        assert!(should_propagate(&path, PeerType::Ebgp, false, ip([10, 0, 0, 2])));
    }

    #[test]
    fn propagation_applies_ibgp_split_horizon() {
        // A route learned from a non-client iBGP peer is not passed to another
        // non-client iBGP peer …
        let ibgp = learned_path(false, [10, 0, 0, 1]);
        assert!(!should_propagate(&ibgp, PeerType::Ibgp, false, ip([10, 0, 0, 2])));
        // … but is passed on to an eBGP peer.
        assert!(should_propagate(&ibgp, PeerType::Ebgp, false, ip([10, 0, 0, 2])));
        // A route learned from eBGP goes to both iBGP and eBGP peers.
        let ebgp = learned_path(true, [10, 0, 0, 1]);
        assert!(should_propagate(&ebgp, PeerType::Ibgp, false, ip([10, 0, 0, 2])));
        assert!(should_propagate(&ebgp, PeerType::Ebgp, false, ip([10, 0, 0, 2])));
    }

    #[test]
    fn confederation_relaxes_the_split_horizon_for_confed_peers() {
        // An iBGP-learned route crosses into another Member-AS (confed-eBGP), like
        // it would to a true eBGP peer — the iBGP split horizon does not apply.
        let ibgp = learned_path(false, [10, 0, 0, 1]);
        assert!(should_propagate(&ibgp, PeerType::Confed, false, ip([10, 0, 0, 2])));

        // A confed-learned route (interior for the decision) still propagates freely
        // to iBGP, other confed and eBGP peers.
        let mut confed = learned_path(false, [10, 0, 0, 1]);
        confed.from_confed = true;
        assert!(should_propagate(&confed, PeerType::Ibgp, false, ip([10, 0, 0, 2])));
        assert!(should_propagate(&confed, PeerType::Confed, false, ip([10, 0, 0, 3])));
        assert!(should_propagate(&confed, PeerType::Ebgp, false, ip([10, 0, 0, 4])));
    }

    #[test]
    fn route_reflection_relaxes_the_split_horizon_for_clients() {
        // A route learned from a non-client iBGP peer IS reflected to a client.
        let from_nonclient = learned_path(false, [10, 0, 0, 1]);
        assert!(should_propagate(&from_nonclient, PeerType::Ibgp, true, ip([10, 0, 0, 2])));

        // A route learned from a client is reflected to every iBGP peer (client or
        // not) and to eBGP peers.
        let mut from_client = learned_path(false, [10, 0, 0, 1]);
        from_client.from_client = true;
        assert!(should_propagate(&from_client, PeerType::Ibgp, false, ip([10, 0, 0, 2]))); // non-client iBGP
        assert!(should_propagate(&from_client, PeerType::Ibgp, true, ip([10, 0, 0, 3]))); // client
        assert!(should_propagate(&from_client, PeerType::Ebgp, false, ip([10, 0, 0, 4]))); // eBGP
    }

    #[test]
    fn reflection_loop_check_drops_own_originator_or_cluster() {
        let upd = |attrs: Vec<PathAttribute>| Update { withdrawn: vec![], attributes: attrs, nlri: vec![] };
        let rid = ip([10, 0, 0, 1]);
        let cid = ip([1, 1, 1, 1]);
        // Our own ORIGINATOR_ID → loop.
        assert!(is_reflection_loop(&upd(vec![PathAttribute::OriginatorId(rid)]), rid, cid));
        // Our CLUSTER_ID in the CLUSTER_LIST → loop.
        assert!(is_reflection_loop(
            &upd(vec![PathAttribute::ClusterList(vec![ip([9, 9, 9, 9]), cid])]),
            rid,
            cid
        ));
        // Neither → fine.
        assert!(!is_reflection_loop(
            &upd(vec![PathAttribute::OriginatorId(ip([7, 7, 7, 7]))]),
            rid,
            cid
        ));
    }

    #[test]
    fn propagation_honours_no_advertise() {
        let mut path = learned_path(true, [10, 0, 0, 1]);
        path.communities = vec![NO_ADVERTISE];
        assert!(!should_propagate(&path, PeerType::Ebgp, false, ip([10, 0, 0, 2])));
    }

    #[test]
    fn no_advertise_blocks_every_peer() {
        assert!(!should_advertise(&[NO_ADVERTISE], PeerType::Ebgp));
        assert!(!should_advertise(&[NO_ADVERTISE], PeerType::Confed));
        assert!(!should_advertise(&[NO_ADVERTISE], PeerType::Ibgp));
    }

    #[test]
    fn no_export_keeps_a_route_inside_the_confederation() {
        use wren_bgp::community::NO_EXPORT_SUBCONFED;
        // NO_EXPORT blocks a true eBGP peer but still crosses confederation
        // (confed-eBGP) and iBGP boundaries (RFC 1997 + RFC 5065).
        assert!(!should_advertise(&[NO_EXPORT], PeerType::Ebgp));
        assert!(should_advertise(&[NO_EXPORT], PeerType::Confed));
        assert!(should_advertise(&[NO_EXPORT], PeerType::Ibgp));
        // NO_EXPORT_SUBCONFED ("local-AS") keeps it within the Member-AS: confed and
        // eBGP both blocked, iBGP still sent.
        assert!(!should_advertise(&[NO_EXPORT_SUBCONFED], PeerType::Ebgp));
        assert!(!should_advertise(&[NO_EXPORT_SUBCONFED], PeerType::Confed));
        assert!(should_advertise(&[NO_EXPORT_SUBCONFED], PeerType::Ibgp));
    }

    #[test]
    fn ordinary_or_absent_communities_advertise_freely() {
        assert!(should_advertise(&[], PeerType::Ebgp));
        assert!(should_advertise(&[0xFDE9_0064], PeerType::Ebgp)); // 65001:100
    }

    #[test]
    fn classify_distinguishes_ibgp_confed_and_ebgp() {
        // Same AS → iBGP; a configured member → confed-eBGP; anything else → eBGP.
        let members = [65002, 65003];
        assert_eq!(classify(65001, &members, 65001), PeerType::Ibgp);
        assert_eq!(classify(65001, &members, 65002), PeerType::Confed);
        assert_eq!(classify(65001, &members, 64500), PeerType::Ebgp);
        // With no members configured, any differing AS is a true external peer.
        assert_eq!(classify(65001, &[], 65002), PeerType::Ebgp);
    }

    #[test]
    fn confed_loop_check_drops_our_member_as() {
        let upd = |attrs: Vec<PathAttribute>| Update { withdrawn: vec![], attributes: attrs, nlri: vec![] };
        // Our Member-AS inside an AS_CONFED_SEQUENCE → a confederation loop.
        let looped = upd(vec![PathAttribute::AsPath(vec![
            AsPathSegment::ConfedSequence(vec![65002, 65001]),
            AsPathSegment::Sequence(vec![64500]),
        ])]);
        assert!(is_confed_loop(&looped, 65001));
        // Our AS only in the *regular* sequence is not a confed loop (it is the
        // ordinary AS-path loop case, handled separately).
        let clean = upd(vec![PathAttribute::AsPath(vec![
            AsPathSegment::ConfedSequence(vec![65002]),
            AsPathSegment::Sequence(vec![65001]),
        ])]);
        assert!(!is_confed_loop(&clean, 65001));
    }

    #[test]
    fn prepend_confed_and_strip_confed_segments_round_trip() {
        // prepend_confed grows a leading AS_CONFED_SEQUENCE …
        let mut segs = vec![AsPathSegment::ConfedSequence(vec![65002])];
        prepend_confed(&mut segs, 65001);
        assert_eq!(segs, vec![AsPathSegment::ConfedSequence(vec![65001, 65002])]);
        // … or starts one in front of a regular sequence.
        let mut segs = vec![AsPathSegment::Sequence(vec![64500])];
        prepend_confed(&mut segs, 65001);
        assert_eq!(
            segs,
            vec![
                AsPathSegment::ConfedSequence(vec![65001]),
                AsPathSegment::Sequence(vec![64500]),
            ]
        );
        // strip_confed_segments removes every confederation segment, keeping the
        // real-AS sequence — the egress-to-true-eBGP transform.
        let mut segs = vec![
            AsPathSegment::ConfedSequence(vec![65001, 65002]),
            AsPathSegment::ConfedSet(vec![65003]),
            AsPathSegment::Sequence(vec![64500]),
        ];
        strip_confed_segments(&mut segs);
        assert_eq!(segs, vec![AsPathSegment::Sequence(vec![64500])]);
    }

    fn static_route(prefix: &str) -> wren_core::Route {
        wren_core::Route::new(prefix.parse().unwrap(), Protocol::Static, vec![], 0)
    }

    #[tokio::test]
    async fn redistribution_adds_then_withdraws_a_prefix() {
        let mut originated: BTreeMap<Prefix, OriginEntry> = BTreeMap::new();
        let (tx, mut rx) = mpsc::channel::<SessionCmd>(16);
        let mut sessions = HashMap::new();
        sessions.insert(ip([10, 0, 0, 2]), tx);
        let p: Prefix = "10.5.0.0/16".parse().unwrap();
        let mut advertised: BTreeMap<Prefix, OriginRoute> = BTreeMap::new();

        apply_redistribution(Redistribution::Announce(static_route("10.5.0.0/16")), &mut originated, &[], &mut advertised, &sessions).await;
        assert!(originated.contains_key(&p));
        match rx.try_recv().unwrap() {
            SessionCmd::Advertise(routes) => assert_eq!(routes[0].prefix, p),
            _ => panic!("expected advertise"),
        }

        // Re-announcing the same prefix is idempotent: no second advertise.
        apply_redistribution(Redistribution::Announce(static_route("10.5.0.0/16")), &mut originated, &[], &mut advertised, &sessions).await;
        assert!(rx.try_recv().is_err());

        apply_redistribution(Redistribution::Withdraw(p), &mut originated, &[], &mut advertised, &sessions).await;
        assert!(!originated.contains_key(&p));
        assert!(matches!(rx.try_recv().unwrap(), SessionCmd::Withdraw(_)));
    }

    #[tokio::test]
    async fn redistribution_never_withdraws_a_configured_network() {
        let p: Prefix = "10.10.0.0/24".parse().unwrap();
        let mut originated: BTreeMap<Prefix, OriginEntry> = BTreeMap::new();
        originated.insert(
            p,
            OriginEntry {
                communities: vec![],
                large_communities: vec![],
                ext_communities: vec![],
                configured: true,
            },
        );
        let (tx, mut rx) = mpsc::channel::<SessionCmd>(16);
        let mut sessions = HashMap::new();
        sessions.insert(ip([10, 0, 0, 2]), tx);
        let mut advertised: BTreeMap<Prefix, OriginRoute> = BTreeMap::new();

        apply_redistribution(Redistribution::Withdraw(p), &mut originated, &[], &mut advertised, &sessions).await;
        assert!(originated.contains_key(&p)); // configured: kept
        assert!(rx.try_recv().is_err()); // nothing pushed
    }

    #[tokio::test]
    async fn ipv6_prefixes_are_redistributed_into_bgp() {
        // MP-BGP (RFC 4760): IPv6 prefixes are now carried, so redistribution
        // accepts them and pushes an advertise to every session.
        let mut originated: BTreeMap<Prefix, OriginEntry> = BTreeMap::new();
        let (tx, mut rx) = mpsc::channel::<SessionCmd>(16);
        let mut sessions = HashMap::new();
        sessions.insert(ip([10, 0, 0, 2]), tx);
        let p: Prefix = "2001:db8:99::/64".parse().unwrap();
        let mut advertised: BTreeMap<Prefix, OriginRoute> = BTreeMap::new();

        apply_redistribution(Redistribution::Announce(static_route("2001:db8:99::/64")), &mut originated, &[], &mut advertised, &sessions).await;
        assert!(originated.contains_key(&p));
        match rx.try_recv().unwrap() {
            SessionCmd::Advertise(routes) => assert_eq!(routes[0].prefix, p),
            _ => panic!("expected advertise"),
        }
    }

    #[test]
    fn advertise_partitions_v4_and_v6_next_hops() {
        // A path with an IPv6 next hop renders with the v6 address (MP_REACH path).
        let mut rib = BgpRib::new();
        let mut path = Path {
            origin: Origin::Igp,
            as_path: vec![AsPathSegment::Sequence(vec![65002])],
            next_hop: IpAddr::V6("2001:db8::2".parse().unwrap()),
            next_hop_iface: None,
            local_pref: 100,
            med: 0,
            from_ebgp: true,
            from_confed: false,
            peer_as: 65002,
            igp_metric: 0,
            peer_id: ip([10, 0, 0, 2]),
            peer_addr: ip([10, 0, 0, 2]),
            from_client: false,
            originator_id: None,
            cluster_list: vec![],
            communities: vec![],
            large_communities: vec![],
            ext_communities: vec![],
        };
        rib.update(ip([10, 0, 0, 2]), "2001:db8:99::/64".parse::<Prefix>().unwrap(), path.clone());
        let out = render_bgp_routes(&rib);
        assert!(out.contains("2001:db8:99::/64 via 2001:db8::2"));
        // And to_route carries the v6 next hop into the kernel route.
        path.next_hop = IpAddr::V6("2001:db8::2".parse().unwrap());
        let route = path.to_route("2001:db8:99::/64".parse().unwrap());
        assert_eq!(route.nexthops[0], wren_core::NextHop::via(path.next_hop));
    }
}
