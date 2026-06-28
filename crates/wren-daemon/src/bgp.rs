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
use wren_bgp::fsm::{Action, BgpFsm, Event, State};
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
    /// COMMUNITIES (RFC 1997) attached to every originated route.
    pub communities: Vec<u32>,
    /// LARGE_COMMUNITY (RFC 8092) tags attached to every originated route.
    pub large_communities: Vec<(u32, u32, u32)>,
    /// EXTENDED_COMMUNITIES (RFC 4360) attached to every originated route.
    pub ext_communities: Vec<[u8; 8]>,
}

/// One configured BGP peer.
pub struct BgpPeerCfg {
    /// The peer's address.
    pub addr: Ipv4Addr,
    /// The peer's AS (eBGP if it differs from [`BgpConfig::local_as`]).
    pub remote_as: u32,
    /// Whether to wait for the peer to connect rather than dialling it.
    pub passive: bool,
}

/// The shared, read-only facts every session task needs.
struct Local {
    local_as: u32,
    router_id: Ipv4Addr,
    hold_time: u16,
    /// The IPv6 next-hop-self for originated IPv6 NLRI (RFC 4760), if configured.
    next_hop6: Option<Ipv6Addr>,
    /// peer address → its AS, for matching inbound connections.
    peers: HashMap<Ipv4Addr, u32>,
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
/// withdraw originated routes. The session acts on it only once Established.
enum SessionCmd {
    /// Advertise these originated routes (a snapshot on session-up, or an
    /// incremental redistribution change afterwards).
    Advertise(Vec<OriginRoute>),
    /// Withdraw these prefixes (a redistributed source went away).
    Withdraw(Vec<Prefix>),
}

/// One peer's identity as a session task sees it.
#[derive(Clone, Copy)]
struct PeerInfo {
    addr: Ipv4Addr,
    remote_as: u32,
}

/// A message from a per-peer session task to the central RIB task.
enum PeerMsg {
    /// The session reached Established, handing the central task the channel on
    /// which to push originated routes to advertise to this peer.
    Established(Ipv4Addr, mpsc::Sender<SessionCmd>),
    /// The session left Established / went down — flush the peer's routes.
    Down(Ipv4Addr),
    /// The peer sent an UPDATE.
    Update {
        peer: Ipv4Addr,
        peer_as: u32,
        peer_id: Ipv4Addr,
        from_ebgp: bool,
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

    let local = Arc::new(Local {
        local_as: cfg.local_as,
        router_id: cfg.router_id,
        hold_time: cfg.hold_time,
        next_hop6: cfg.next_hop6,
        peers: cfg.peers.iter().map(|p| (p.addr, p.remote_as)).collect(),
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
            PeerMsg::Established(p, cmd_tx) => {
                info!(peer = %p, "BGP session established");
                if let Some(n) = neighbors.get_mut(&p) {
                    n.established = true;
                }
                // Push the current origination snapshot to the new session, then
                // remember it for future incremental redistribution changes.
                let snapshot = origination_snapshot(&originated);
                if !snapshot.is_empty() {
                    let _ = cmd_tx.send(SessionCmd::Advertise(snapshot)).await;
                }
                sessions.insert(p, cmd_tx);
            }
            PeerMsg::Down(p) => {
                info!(peer = %p, "BGP session down");
                if let Some(n) = neighbors.get_mut(&p) {
                    n.established = false;
                }
                sessions.remove(&p);
                for ev in rib.withdraw_peer(p) {
                    emit(ev, &updates).await;
                }
            }
            PeerMsg::Update {
                peer,
                peer_as,
                peer_id,
                from_ebgp,
                update,
            } => {
                let facts = PeerFacts { addr: peer, as_: peer_as, id: peer_id, from_ebgp };
                // Withdrawals: base-NLRI IPv4 (the Withdrawn Routes field) and IPv6
                // (MP_UNREACH_NLRI, RFC 4760 §4).
                for w in update.withdrawn.iter().chain(mp_unreach_v6(&update)) {
                    if let Some(ev) = rib.withdraw(peer, *w) {
                        emit(ev, &updates).await;
                    }
                }
                // IPv4 reachability: base NLRI with the IPv4 NEXT_HOP attribute.
                if !update.nlri.is_empty() {
                    match base_next_hop(&update) {
                        Some(nh) => {
                            let path = build_path(&update, IpAddr::V4(nh), facts);
                            for p in &update.nlri {
                                if let Some(ev) = rib.update(peer, *p, path.clone()) {
                                    emit(ev, &updates).await;
                                }
                            }
                        }
                        None => warn!(peer = %peer, "UPDATE with NLRI but no NEXT_HOP — ignored"),
                    }
                }
                // IPv6 reachability: MP_REACH_NLRI carries its own next hop (RFC 4760).
                if let Some((nh6, nlri)) = mp_reach_v6(&update) {
                    let path = build_path(&update, IpAddr::V6(nh6), facts);
                    for p in nlri {
                        if let Some(ev) = rib.update(peer, *p, path.clone()) {
                            emit(ev, &updates).await;
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
}

/// Build a [`Path`] from a received UPDATE's attributes with the given `next_hop`
/// (the base-NLRI IPv4 NEXT_HOP, or the IPv6 next hop pulled from MP_REACH_NLRI).
fn build_path(update: &Update, next_hop: IpAddr, peer: PeerFacts) -> Path {
    let mut origin = Origin::Incomplete;
    let mut as_path = Vec::new();
    let mut as4_path = None;
    let mut med = 0;
    let mut local_pref = DEFAULT_LOCAL_PREF;
    let mut communities = Vec::new();
    let mut large_communities = Vec::new();
    let mut ext_communities = Vec::new();
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
        local_pref,
        med,
        from_ebgp: peer.from_ebgp,
        peer_as: peer.as_,
        igp_metric: 0,
        peer_id: peer.id,
        peer_addr: peer.addr,
        communities,
        large_communities,
        ext_communities,
    }
}

/// The base-NLRI IPv4 NEXT_HOP attribute of an UPDATE, if present.
fn base_next_hop(update: &Update) -> Option<Ipv4Addr> {
    update.attributes.iter().find_map(|a| match a {
        PathAttribute::NextHop(nh) => Some(*nh),
        _ => None,
    })
}

/// The MP_REACH_NLRI (IPv6 unicast) of an UPDATE: its 16-octet global next hop and
/// reachable prefixes (RFC 4760 §3 / RFC 2545). A 32-octet next hop carries a
/// link-local after the global; we use the global for the kernel route.
fn mp_reach_v6(update: &Update) -> Option<(Ipv6Addr, &[Prefix])> {
    update.attributes.iter().find_map(|a| match a {
        PathAttribute::MpReachNlri { afi, next_hop, nlri, .. }
            if *afi == AFI_IPV6 && next_hop.len() >= 16 =>
        {
            let mut g = [0u8; 16];
            g.copy_from_slice(&next_hop[..16]);
            Some((Ipv6Addr::from(g), nlri.as_slice()))
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

/// Whether a route carrying `communities` may be advertised to a peer, honouring
/// the RFC 1997 well-known communities: `NO_ADVERTISE` blocks every peer, and
/// `NO_EXPORT` / `NO_EXPORT_SUBCONFED` block eBGP peers.
fn should_advertise(communities: &[u32], to_ebgp: bool) -> bool {
    use wren_bgp::community::{NO_ADVERTISE, NO_EXPORT, NO_EXPORT_SUBCONFED};
    if communities.contains(&NO_ADVERTISE) {
        return false;
    }
    if to_ebgp && (communities.contains(&NO_EXPORT) || communities.contains(&NO_EXPORT_SUBCONFED)) {
        return false;
    }
    true
}

/// Actively dial a peer, run the session, and retry on failure.
async fn connector(peer: PeerInfo, local: Arc<Local>, tx: mpsc::Sender<PeerMsg>) {
    loop {
        match timeout(CONNECT_TIMEOUT, TcpStream::connect((peer.addr, PORT))).await {
            Ok(Ok(stream)) => {
                if let Err(e) = drive_session(stream, peer, &local, &tx).await {
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
                let Some(&remote_as) = local.peers.get(&ip) else {
                    debug!(peer = %ip, "inbound BGP from unconfigured peer; dropping");
                    continue;
                };
                let peer = PeerInfo {
                    addr: ip,
                    remote_as,
                };
                let local = local.clone();
                let tx = tx.clone();
                tokio::spawn(async move {
                    if let Err(e) = drive_session(stream, peer, &local, &tx).await {
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
) -> Result<()> {
    stream.set_nodelay(true).ok();
    let local_ip = match stream.local_addr()?.ip() {
        IpAddr::V4(a) => a,
        IpAddr::V6(_) => local.router_id,
    };
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
        from_ebgp: peer.remote_as != local.local_as,
        local_ip,
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
    from_ebgp: bool,
    local_ip: Ipv4Addr,
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
                    let open = Message::Open(Open::new(
                        VERSION,
                        self.local.local_as,
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
                        .send(PeerMsg::Established(self.peer.addr, self.cmd_tx.clone()))
                        .await;
                }
                Action::SessionDown => {
                    if self.established {
                        let _ = self.tx.send(PeerMsg::Down(self.peer.addr)).await;
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

    /// Advertise originated routes to this peer, building the per-peer attributes
    /// (AS_PATH, next-hop-self, COMMUNITIES, LARGE_COMMUNITY). Routes are grouped by
    /// their full tag set so each UPDATE carries a single COMMUNITIES /
    /// LARGE_COMMUNITY attribute, and a route whose well-known communities forbid
    /// this peer (RFC 1997) is skipped.
    async fn advertise(&mut self, routes: &[OriginRoute]) -> Result<()> {
        type TagKey = (Vec<u32>, Vec<(u32, u32, u32)>, Vec<[u8; 8]>);
        let mut groups: BTreeMap<TagKey, Vec<Prefix>> = BTreeMap::new();
        for r in routes {
            if should_advertise(&r.communities, self.from_ebgp) {
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
            if self.from_ebgp {
                base.push(PathAttribute::AsPath(vec![AsPathSegment::Sequence(vec![
                    self.local.local_as,
                ])]));
                // Toward a legacy 2-octet peer our AS would collapse to AS_TRANS on
                // the wire; carry the real 4-octet AS in AS4_PATH (RFC 6793).
                if !self.four_octet && self.local.local_as > u16::MAX as u32 {
                    base.push(PathAttribute::As4Path(vec![AsPathSegment::Sequence(vec![
                        self.local.local_as,
                    ])]));
                }
            } else {
                // iBGP: empty AS_PATH, carry LOCAL_PREF.
                base.push(PathAttribute::AsPath(vec![]));
                base.push(PathAttribute::LocalPref(DEFAULT_LOCAL_PREF));
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
                            next_hop: nh6.octets().to_vec(),
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
            local_pref: 100,
            med: 0,
            from_ebgp: true,
            peer_as: 65001,
            igp_metric: 0,
            peer_id: ip([10, 0, 0, 1]),
            peer_addr: ip([10, 0, 0, 1]),
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

    #[test]
    fn no_advertise_blocks_every_peer() {
        assert!(!should_advertise(&[NO_ADVERTISE], true));
        assert!(!should_advertise(&[NO_ADVERTISE], false));
    }

    #[test]
    fn no_export_blocks_only_ebgp() {
        assert!(!should_advertise(&[NO_EXPORT], true)); // eBGP: suppressed
        assert!(should_advertise(&[NO_EXPORT], false)); // iBGP: still sent
    }

    #[test]
    fn ordinary_or_absent_communities_advertise_freely() {
        assert!(should_advertise(&[], true));
        assert!(should_advertise(&[0xFDE9_0064], true)); // 65001:100
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
            local_pref: 100,
            med: 0,
            from_ebgp: true,
            peer_as: 65002,
            igp_metric: 0,
            peer_id: ip([10, 0, 0, 2]),
            peer_addr: ip([10, 0, 0, 2]),
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
