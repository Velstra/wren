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

use std::collections::{BTreeMap, HashMap};
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
use wren_bgp::{AFI_IPV6, HEADER_LEN, MARKER, MAX_MESSAGE_LEN, PORT, SAFI_UNICAST, VERSION};

use wren_core::{Prefix, Protocol};

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
        cmd_tx: mpsc::Sender<SessionCmd>,
    },
    /// The session left Established / went down — flush the peer's routes, but only
    /// if `conn_id` is still the current connection (a stale loser's Down is
    /// ignored, so it can't evict the surviving session).
    Down { peer: Ipv4Addr, conn_id: u64 },
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

/// A snapshot of the whole origination set as [`OriginRoute`]s, for advertising to
/// a freshly-established session.
fn origination_snapshot(originated: &BTreeMap<Prefix, OriginEntry>) -> Vec<OriginRoute> {
    originated
        .iter()
        .map(|(prefix, e)| OriginRoute {
            prefix: *prefix,
            communities: e.communities.clone(),
            large_communities: e.large_communities.clone(),
            ext_communities: e.ext_communities.clone(),
        })
        .collect()
}

fn neighbor_summaries(neighbors: &BTreeMap<Ipv4Addr, NeighborState>) -> Vec<NeighborSummary> {
    neighbors
        .iter()
        .map(|(addr, n)| NeighborSummary {
            addr: *addr,
            remote_as: n.remote_as,
            established: n.established,
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
        let _ = writeln!(out, "{} AS {} {}", n.addr, n.remote_as, state);
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
        .map(|p| (p.addr, NeighborState { remote_as: p.remote_as, established: false }))
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
    // Established sessions we can push origination changes to, keyed by peer.
    let mut sessions: HashMap<Ipv4Addr, mpsc::Sender<SessionCmd>> = HashMap::new();
    // Whether each established session's connection was inbound, for §6.8 collision
    // detection (which of two racing connections to keep).
    let mut est_inbound: HashMap<Ipv4Addr, bool> = HashMap::new();
    // The id of the current connection per peer, so a stale loser connection's Down
    // (e.g. after it was Ceased) can't evict the surviving session.
    let mut current_conn: HashMap<Ipv4Addr, u64> = HashMap::new();

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
                    },
                )
            })
            .collect(),
    });

    let (tx, mut rx) = mpsc::channel::<PeerMsg>(PEER_QUEUE);

    // A listener for inbound connections (passive peers, and the peer that wins a
    // simultaneous-open race). Port 179 needs CAP_NET_BIND_SERVICE.
    match TcpListener::bind((Ipv4Addr::UNSPECIFIED, PORT)).await {
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
        };
        let local = local.clone();
        let tx = tx.clone();
        tokio::spawn(async move { connector(info, local, tx).await });
    }
    // Drop our own sender; the listener and connectors keep theirs, so `rx` stays
    // open for the life of the daemon.
    drop(tx);

    let mut rib = BgpRib::new();
    loop {
        let msg = tokio::select! {
            msg = rx.recv() => match msg {
                Some(msg) => msg,
                None => break, // all sessions gone — daemon shutting down
            },
            Some(req) = queries.recv() => {
                let resp = match req.query {
                    BgpQuery::Routes => render_bgp_routes(&rib),
                    BgpQuery::Neighbors => render_bgp_neighbors(&neighbor_summaries(&neighbors)),
                };
                let _ = req.respond.send(resp);
                continue;
            }
            Some(r) = redist.recv() => {
                apply_redistribution(r, &mut originated, &sessions).await;
                continue;
            }
        };
        match msg {
            PeerMsg::Established { peer: p, peer_id, inbound, conn_id, cmd_tx } => {
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
                // Push the current origination snapshot to the new session, then
                // remember it for future incremental redistribution changes.
                let snapshot = origination_snapshot(&originated);
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
                for ev in rib.withdraw_peer(p) {
                    apply_event(ev, &updates, &sessions).await;
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
                let facts = PeerFacts {
                    addr: peer,
                    as_: peer_as,
                    id: peer_id,
                    from_ebgp,
                    from_confed,
                    from_client,
                };
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
                // IPv4 reachability: base NLRI with the IPv4 NEXT_HOP attribute.
                if !update.nlri.is_empty() {
                    match base_next_hop(&update) {
                        Some(nh) => {
                            let path = build_path(&update, IpAddr::V4(nh), None, facts);
                            for p in &update.nlri {
                                if let Some(ev) = rib.update(peer, *p, path.clone()) {
                                    apply_event(ev, &updates, &sessions).await;
                                }
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
                        if let Some(ev) = rib.update(peer, *p, path.clone()) {
                            apply_event(ev, &updates, &sessions).await;
                        }
                    }
                }
            }
        }
    }
    Ok(())
}

/// Fold a redistribution change from the central router into the origination set
/// and push it to every established session. BGP carries both IPv4 and IPv6 unicast
/// (the IPv6 prefixes ride MP_REACH_NLRI, RFC 4760); a prefix originated by
/// `[bgp] network` (configured) is never overridden or withdrawn by redistribution.
async fn apply_redistribution(
    r: Redistribution,
    originated: &mut BTreeMap<Prefix, OriginEntry>,
    sessions: &HashMap<Ipv4Addr, mpsc::Sender<SessionCmd>>,
) {
    match r {
        Redistribution::Announce(route) => {
            let prefix = route.prefix;
            // Communities set on the route by the export filter ride along.
            let communities = route.communities.clone();
            let large_communities = route.large_communities.clone();
            let ext_communities = route.ext_communities.clone();
            match originated.get(&prefix) {
                // A configured `network` is authoritative — never overridden.
                Some(e) if e.configured => return,
                // Already redistributed with the same tags: nothing new.
                Some(e) if e.communities == communities
                    && e.large_communities == large_communities
                    && e.ext_communities == ext_communities =>
                {
                    return
                }
                _ => {}
            }
            originated.insert(
                prefix,
                OriginEntry {
                    communities: communities.clone(),
                    large_communities: large_communities.clone(),
                    ext_communities: ext_communities.clone(),
                    configured: false,
                },
            );
            let adv = vec![OriginRoute {
                prefix,
                communities,
                large_communities,
                ext_communities,
            }];
            for tx in sessions.values() {
                let _ = tx.send(SessionCmd::Advertise(adv.clone())).await;
            }
            debug!(%prefix, "redistributed into BGP");
        }
        Redistribution::Withdraw(prefix) => {
            // Only retract redistributed prefixes; configured networks stay.
            if matches!(originated.get(&prefix), Some(e) if !e.configured) {
                originated.remove(&prefix);
                for tx in sessions.values() {
                    let _ = tx.send(SessionCmd::Withdraw(vec![prefix])).await;
                }
                debug!(%prefix, "redistribution withdrawn from BGP");
            }
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

/// Re-advertise a Loc-RIB change to every established session (the Adj-RIB-Out
/// fan-out), IPv4 or IPv6. This broadcasts unconditionally; each session applies
/// the eBGP/iBGP propagation rules (and the IPv6 multiprotocol gating) itself, and
/// the session that taught us the route drops it (split horizon).
async fn propagate(ev: &RibEvent, sessions: &HashMap<Ipv4Addr, mpsc::Sender<SessionCmd>>) {
    match ev {
        RibEvent::Best { prefix, path } => {
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
        RibEvent::Best { prefix, path } => RouteUpdate::Announce(path.to_route(prefix)),
        RibEvent::Withdrawn(prefix) => RouteUpdate::Withdraw {
            prefix,
            protocol: Protocol::Bgp,
            source: 0,
        },
    };
    let _ = updates.send(upd).await;
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
async fn connector(peer: PeerInfo, local: Arc<Local>, tx: mpsc::Sender<PeerMsg>) {
    loop {
        match timeout(CONNECT_TIMEOUT, TcpStream::connect((peer.addr, PORT))).await {
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
                            sess.neg_hold = sess.local.hold_time.min(o.hold_time);
                            sess.keepalive_int = (sess.neg_hold / 3).max(1);
                            Step::Event(Event::OpenReceived)
                        }
                    }
                    Message::Keepalive => Step::Event(Event::KeepAliveReceived),
                    Message::Update(u) => {
                        if fsm.is_established() {
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
                        Step::Event(Event::UpdateReceived)
                    }
                    Message::Notification(n) => {
                        debug!(peer = %sess.peer.addr, code = n.code, subcode = n.subcode, "BGP NOTIFICATION received");
                        Step::Event(Event::NotificationReceived)
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
            let mut base = vec![PathAttribute::Origin(Origin::Igp)];
            match self.peer_type {
                PeerType::Ebgp => {
                    // True eBGP: prepend the externally visible AS (the Confederation
                    // Identifier if we are in a confederation, else our AS).
                    let ext = self.local.external_as();
                    base.push(PathAttribute::AsPath(vec![AsPathSegment::Sequence(vec![ext])]));
                    // Toward a legacy 2-octet peer our AS would collapse to AS_TRANS
                    // on the wire; carry the real 4-octet AS in AS4_PATH (RFC 6793).
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

            // IPv4 unicast: base NLRI with the IPv4 NEXT_HOP (next-hop-self).
            if !v4.is_empty() {
                let mut attributes = base.clone();
                attributes.push(PathAttribute::NextHop(self.local_ip));
                self.send(&Message::Update(Update {
                    withdrawn: vec![],
                    attributes,
                    nlri: v4,
                }))
                .await?;
            }

            // IPv6 unicast: MP_REACH_NLRI, only if the peer negotiated it and we have
            // a next-hop-self to advertise.
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
                        self.send(&Message::Update(Update {
                            withdrawn: vec![],
                            attributes,
                            nlri: vec![],
                        }))
                        .await?;
                    }
                    (false, _) => debug!(peer = %self.peer.addr, "peer has no IPv6 capability; not advertising IPv6 NLRI"),
                    (true, None) => warn!(peer = %self.peer.addr, "IPv6 routes to advertise but no `[bgp] next-hop6` configured"),
                }
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
            NeighborSummary { addr: ip([10, 0, 0, 2]), remote_as: 65002, established: true },
            NeighborSummary { addr: ip([10, 0, 0, 3]), remote_as: 4_200_000_000, established: false },
        ];
        let out = render_bgp_neighbors(&n);
        assert!(out.contains("10.0.0.2 AS 65002 Established"));
        assert!(out.contains("10.0.0.3 AS 4200000000 Idle"));
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

        apply_redistribution(Redistribution::Announce(static_route("10.5.0.0/16")), &mut originated, &sessions).await;
        assert!(originated.contains_key(&p));
        match rx.try_recv().unwrap() {
            SessionCmd::Advertise(routes) => assert_eq!(routes[0].prefix, p),
            _ => panic!("expected advertise"),
        }

        // Re-announcing the same prefix is idempotent: no second advertise.
        apply_redistribution(Redistribution::Announce(static_route("10.5.0.0/16")), &mut originated, &sessions).await;
        assert!(rx.try_recv().is_err());

        apply_redistribution(Redistribution::Withdraw(p), &mut originated, &sessions).await;
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

        apply_redistribution(Redistribution::Withdraw(p), &mut originated, &sessions).await;
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

        apply_redistribution(Redistribution::Announce(static_route("2001:db8:99::/64")), &mut originated, &sessions).await;
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
