//! # The Babel socket runner (RFC 8966)
//!
//! The async driver that turns the pure [`wren_babel`] library into a live
//! protocol. Like [`crate::ripng`] it runs over IPv6: one UDP socket per interface
//! bound to `[::]:6696`, joined to the Babel multicast group `ff02::1:6`. It owns a
//! [`NeighbourTable`] (Hello/IHU link-cost) and a [`RouteTable`] (the feasibility
//! condition and route selection), and translates selection changes into
//! [`RouteUpdate`]s for the central router.
//!
//! Each cycle it:
//!
//! * sends a periodic **Hello** (an increasing seqno) plus an **IHU** per neighbour
//!   advertising our receive cost for it, so both directions of the link cost
//!   converge (§3.4);
//! * sends periodic **Update**s advertising our own networks and re-advertising the
//!   routes we have selected (distance-vector, §3.7);
//! * on receipt feeds Hellos/IHUs into the neighbour table and Updates — costed by
//!   the link to the sending neighbour — into the route table (§3.5), forwarding
//!   any selection change to the RIB;
//! * ages neighbours out (a lost neighbour flushes its routes, §3.4.2).
//!
//! Babel identifies a neighbour by its link-local source address and uses the
//! packet's source address as the implicit next hop, so learned routes are pinned
//! to the receiving interface before they go to the kernel (a link-local gateway is
//! only installable with an outgoing interface).

use std::ffi::{CStr, CString};
use std::io;
use std::mem;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6};
use std::os::raw::c_void;
use std::os::unix::io::FromRawFd;
use std::ptr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use std::fmt::Write as _;

use anyhow::{Context, Result};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, oneshot};
use tokio::time::MissedTickBehavior;
use tracing::{debug, info, warn};

use wren_babel::tlv::Tlv;
use wren_babel::{BabelEvent, NeighbourTable, Packet, RouteTable, METRIC_INFINITY, MULTICAST, PORT};
use wren_core::{NextHop, Prefix, Protocol, Route};

use crate::connected;
use crate::sockopt::{setsockopt_int, setsockopt_struct};
use crate::router::{Redistribution, RouteUpdate};

/// Send a Hello (and per-neighbour IHUs) this often (seconds).
const HELLO_SECS: u64 = 4;
/// Send a full Update dump this often (seconds).
const UPDATE_SECS: u64 = 16;
/// Advance neighbour expiry this often (seconds).
const HOUSEKEEPING_SECS: u64 = 1;

/// The advertised Hello interval, in centiseconds (= [`HELLO_SECS`]).
const HELLO_INTERVAL_CS: u16 = (HELLO_SECS * 100) as u16;
/// The advertised IHU interval, in centiseconds (conventionally ~3× Hello).
const IHU_INTERVAL_CS: u16 = 1200;
/// The advertised Update interval, in centiseconds (= [`UPDATE_SECS`]).
const UPDATE_INTERVAL_CS: u16 = (UPDATE_SECS * 100) as u16;

/// Drop a neighbour whose last Hello is older than this (seconds, ~4× Hello).
const HELLO_TIMEOUT: u64 = HELLO_SECS * 4;
/// Treat a neighbour's txcost as infinite if its last IHU is older than this.
const IHU_TIMEOUT: u64 = 12;

/// Receive buffer (one Babel datagram fits in a link MTU).
const RECV_BUF: usize = 1500;
/// The sequence number we originate our own routes with (kept stable for a run;
/// refreshes are byte-identical, so a neighbour treats them as no-ops).
const OUR_SEQNO: u16 = 1;
/// Cap on Update TLVs per packet, to stay well under the IPv6 minimum MTU.
const MAX_UPDATES_PER_PACKET: usize = 40;

/// Resolved Babel configuration for the runner.
pub struct BabelConfig {
    /// Our 8-octet Router-ID (originator of our own routes).
    pub router_id: [u8; 8],
    /// The interfaces Babel runs on.
    pub interfaces: Vec<String>,
    /// Networks to originate beyond the directly-connected ones.
    pub originate: Vec<Prefix>,
    /// The metric advertised for routes redistributed from the RIB (the metric
    /// "at the source"). 0 means "as good as a directly-originated network".
    pub redistribute_metric: u16,
    /// The VRF (kernel routing table) this Babel instance installs into. Every route
    /// it produces — its connected reachability and selected routes, both address
    /// families — is stamped with this table, so a Babel instance bound to a VRF
    /// (`[babel] vrf = "…"`) keeps its routes in the VRF's table instead of the main
    /// table. Defaults to [`wren_core::RT_TABLE_MAIN`] for the default VRF.
    pub vrf_table: u32,
}

/// One Babel-speaking interface.
struct Iface {
    name: String,
    ifindex: u32,
    sock: Arc<UdpSocket>,
    /// Our link-local address on this interface, if known (used to recognise IHUs
    /// addressed to us).
    link_local: Option<Ipv6Addr>,
}

/// A datagram received on one interface.
struct Datagram {
    ifindex: u32,
    src: SocketAddrV6,
    data: Vec<u8>,
}

/// The runner's mutable protocol state.
struct State {
    router_id: [u8; 8],
    neighbours: NeighbourTable,
    table: RouteTable,
    /// Our own networks (connected + configured), advertised with our Router-ID.
    self_prefixes: Vec<Prefix>,
    /// Routes we have selected and re-advertise, with their origin `(router-id,
    /// seqno, metric)`.
    relayed: std::collections::BTreeMap<Prefix, ([u8; 8], u16, u16)>,
    /// Routes redistributed from the RIB (other protocols), originated as ours
    /// (origin = our Router-ID) at the configured metric. Prefix → advertised
    /// metric.
    redistributed: std::collections::BTreeMap<Prefix, u16>,
    /// Prefixes just removed from [`State::redistributed`], to be advertised once
    /// at metric infinity (a retraction, §3.5.5) on the next Update, then dropped.
    retractions: Vec<Prefix>,
    /// The next Hello sequence number to send.
    hello_seqno: u16,
}

/// Run Babel on `cfg.interfaces`, forwarding learned/lost routes to `updates`.
///
/// `redist` carries RIB best-path routes the central router pushes for
/// redistribution; Babel originates each (under our Router-ID, at
/// `cfg.redistribute_metric`) and retracts it (metric infinity) when its best
/// path goes away. Babel is dual-stack, so both IPv4 and IPv6 routes are carried.
/// A `show babel …` query, answered by the Babel task itself out of the state it
/// owns (its neighbour table with the Hello/IHU link costs).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum BabelQuery {
    /// The neighbours and their link costs.
    Neighbors,
    /// The selected routes (the Babel RIB).
    Routes,
}

/// A control-socket query plus the channel to answer it on.
pub struct BabelQueryRequest {
    /// What to report.
    pub query: BabelQuery,
    /// Where to send the rendered answer.
    pub respond: oneshot::Sender<String>,
}

/// One neighbour, snapshotted for the (pure) renderer.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct BabelNeighborInfo {
    /// The neighbour's address (its link-local on the shared link).
    pub addr: IpAddr,
    /// The receive cost the neighbour reported to us (IHU, §3.4.3).
    pub rxcost: u16,
    /// The link cost we use towards the neighbour (§3.4.3).
    pub cost: u16,
}

/// Render the Babel neighbours, one per line (à la `show babel neighbour`).
pub fn render_babel_neighbors(neighbors: &[BabelNeighborInfo]) -> String {
    if neighbors.is_empty() {
        return "no babel neighbours\n".to_string();
    }
    let mut out = String::new();
    for n in neighbors {
        let cost = if n.cost == METRIC_INFINITY {
            "inf".to_string()
        } else {
            n.cost.to_string()
        };
        let _ = writeln!(out, "{} rxcost {} cost {}", n.addr, n.rxcost, cost);
    }
    out
}

/// Render the Babel selected routes, one per line (à la `show babel route`).
pub fn render_babel_routes(routes: &[(Prefix, IpAddr, u16)]) -> String {
    if routes.is_empty() {
        return "no babel routes\n".to_string();
    }
    let mut out = String::new();
    for (prefix, next_hop, metric) in routes {
        let m = if *metric == METRIC_INFINITY {
            "inf".to_string()
        } else {
            metric.to_string()
        };
        let _ = writeln!(out, "{prefix} via {next_hop} metric {m}");
    }
    out
}

/// Snapshot every neighbour and its link costs, for `show babel neighbors`.
fn neighbor_infos(neighbours: &NeighbourTable) -> Vec<BabelNeighborInfo> {
    let mut addrs = neighbours.addresses();
    addrs.sort();
    addrs
        .into_iter()
        .map(|addr| BabelNeighborInfo {
            addr,
            rxcost: neighbours.rxcost(&addr),
            cost: neighbours.cost(&addr),
        })
        .collect()
}

pub async fn run(
    cfg: BabelConfig,
    updates: mpsc::Sender<RouteUpdate>,
    mut redist: mpsc::Receiver<Redistribution>,
    mut queries: mpsc::Receiver<BabelQueryRequest>,
) -> Result<()> {
    let mut ifaces = Vec::with_capacity(cfg.interfaces.len());
    for name in &cfg.interfaces {
        let (ifindex, std_sock) =
            open_babel_socket(name).with_context(|| format!("opening Babel socket on {name:?}"))?;
        let sock =
            Arc::new(UdpSocket::from_std(std_sock).context("registering Babel socket with tokio")?);
        let link_local = link_local_of(name);
        info!(interface = %name, ifindex, ?link_local, "Babel listening on [ff02::1:6]:6696");
        ifaces.push(Iface {
            name: name.clone(),
            ifindex,
            sock,
            link_local,
        });
    }
    if ifaces.is_empty() {
        warn!("Babel is enabled but no interfaces are configured — nothing to do");
        return Ok(());
    }

    let (pkt_tx, mut pkt_rx) = mpsc::channel::<Datagram>(256);
    for iface in &ifaces {
        spawn_receiver(iface.sock.clone(), iface.ifindex, pkt_tx.clone());
    }
    drop(pkt_tx);

    let redistribute_metric = cfg.redistribute_metric;
    let vrf_table = cfg.vrf_table;
    let mut state = State {
        router_id: cfg.router_id,
        neighbours: NeighbourTable::new(),
        table: RouteTable::new(),
        self_prefixes: Vec::new(),
        relayed: std::collections::BTreeMap::new(),
        redistributed: std::collections::BTreeMap::new(),
        retractions: Vec::new(),
        hello_seqno: 0,
    };

    // Originate our directly-connected networks (announced to the RIB as connected,
    // which the router tracks but lets the kernel own) plus any configured ones.
    for net in connected::discover(&cfg.interfaces) {
        if state.self_prefixes.contains(&net.prefix) {
            continue;
        }
        state.self_prefixes.push(net.prefix);
        info!(prefix = %net.prefix, interface = %net.ifname, "Babel originating connected network");
        let route = Route::new(
            net.prefix,
            Protocol::Connected,
            vec![NextHop::dev(net.ifname)],
            0,
        )
        .with_table(vrf_table);
        let _ = updates.send(RouteUpdate::Announce(route)).await;
    }
    for prefix in cfg.originate {
        if !state.self_prefixes.contains(&prefix) {
            info!(%prefix, "Babel originating configured network");
            state.self_prefixes.push(prefix);
        }
    }

    // Solicit each neighbour's whole table at startup (a wildcard Route Request).
    let request = Packet::new(vec![Tlv::RouteRequest { prefix: None }]).encode();
    for iface in &ifaces {
        send_raw(&iface.sock, &request).await;
    }

    let start = Instant::now();
    let mut hello = tokio::time::interval(Duration::from_secs(HELLO_SECS));
    hello.set_missed_tick_behavior(MissedTickBehavior::Delay);
    let mut update = tokio::time::interval(Duration::from_secs(UPDATE_SECS));
    update.set_missed_tick_behavior(MissedTickBehavior::Delay);
    let mut housekeeping = tokio::time::interval(Duration::from_secs(HOUSEKEEPING_SECS));
    housekeeping.tick().await;

    loop {
        tokio::select! {
            received = pkt_rx.recv() => {
                let Some(dg) = received else {
                    warn!("all Babel receivers stopped");
                    break;
                };
                let now = start.elapsed().as_secs();
                let changed = handle_datagram(&mut state, &ifaces, &dg, now, vrf_table, &updates).await;
                if changed {
                    // A selection changed — flush a triggered Update promptly.
                    send_updates(&mut state, &ifaces).await;
                }
            }
            _ = hello.tick() => {
                send_hellos(&mut state, &ifaces).await;
            }
            _ = update.tick() => {
                send_updates(&mut state, &ifaces).await;
            }
            _ = housekeeping.tick() => {
                let now = start.elapsed().as_secs();
                let dead = state.neighbours.expire(now, HELLO_TIMEOUT, IHU_TIMEOUT);
                for addr in dead {
                    info!(neighbour = %addr, "Babel neighbour lost");
                    for ev in state.table.neighbour_lost(addr) {
                        forward_event(&mut state.relayed, ev, vrf_table, &updates).await;
                    }
                }
            }
            Some(r) = redist.recv() => {
                if apply_redistribution(&mut state, r, redistribute_metric) {
                    // A redistributed route changed — flush a triggered Update.
                    send_updates(&mut state, &ifaces).await;
                }
            }
            Some(req) = queries.recv() => {
                let answer = match req.query {
                    BabelQuery::Neighbors => render_babel_neighbors(&neighbor_infos(&state.neighbours)),
                    BabelQuery::Routes => render_babel_routes(&state.table.selected_routes()),
                };
                let _ = req.respond.send(answer);
            }
        }
    }
    Ok(())
}

/// Fold a redistribution change from the central router into our originated
/// routes: an announced route is originated as ours (under our Router-ID, at
/// `metric`); a withdrawal queues a retraction (metric infinity) so neighbours
/// are told it is gone. A network we already originate ourselves (connected or
/// configured) takes precedence and is left untouched. Returns whether anything
/// changed (and so a triggered Update is due).
fn apply_redistribution(state: &mut State, r: Redistribution, metric: u16) -> bool {
    match r {
        Redistribution::Announce(route) => {
            if state.self_prefixes.contains(&route.prefix) {
                return false; // our own connected/configured network wins
            }
            // Idempotent: re-announcing at the same metric is a no-op.
            if state.redistributed.insert(route.prefix, metric) == Some(metric) {
                return false;
            }
            // It is back — cancel any pending retraction for it.
            state.retractions.retain(|p| *p != route.prefix);
            true
        }
        Redistribution::Withdraw(prefix) => {
            if state.redistributed.remove(&prefix).is_some() {
                state.retractions.push(prefix);
                true
            } else {
                false
            }
        }
    }
}

fn spawn_receiver(sock: Arc<UdpSocket>, ifindex: u32, pkt_tx: mpsc::Sender<Datagram>) {
    tokio::spawn(async move {
        let mut buf = vec![0u8; RECV_BUF];
        loop {
            match sock.recv_from(&mut buf).await {
                Ok((n, SocketAddr::V6(src))) => {
                    let dg = Datagram {
                        ifindex,
                        src,
                        data: buf[..n].to_vec(),
                    };
                    if pkt_tx.send(dg).await.is_err() {
                        break;
                    }
                }
                Ok((_, SocketAddr::V4(_))) => {} // an AF_INET6 socket; shouldn't happen
                Err(e) => {
                    warn!(ifindex, error = %e, "Babel receive failed");
                    break;
                }
            }
        }
    });
}

/// Process one received datagram, returning whether any route selection changed.
async fn handle_datagram(
    state: &mut State,
    ifaces: &[Iface],
    dg: &Datagram,
    now: u64,
    vrf_table: u32,
    updates: &mpsc::Sender<RouteUpdate>,
) -> bool {
    let pkt = match Packet::decode(&dg.data) {
        Ok(p) => p,
        Err(e) => {
            debug!(error = %e, src = %dg.src, "ignoring malformed Babel datagram");
            return false;
        }
    };
    let Some(iface) = ifaces.iter().find(|i| i.ifindex == dg.ifindex) else {
        return false;
    };
    let src = IpAddr::V6(*dg.src.ip());

    // TLVs carry running context: the Router-ID and Next Hop apply to the Updates
    // that follow them in the same packet (§4.6.7–§4.6.9).
    let mut cur_router_id: Option<[u8; 8]> = None;
    let mut cur_nexthop: IpAddr = src;
    let mut changed = false;

    for tlv in &pkt.body {
        match tlv {
            Tlv::Hello { seqno, .. } => {
                state.neighbours.on_hello(src, *seqno, now);
            }
            Tlv::Ihu {
                rxcost, address, ..
            } => {
                if ihu_is_for_us(iface, address) {
                    state.neighbours.on_ihu(src, *rxcost, now);
                }
            }
            Tlv::RouterId(id) => cur_router_id = Some(*id),
            Tlv::NextHop(ip) => cur_nexthop = *ip,
            Tlv::Update {
                seqno,
                metric,
                prefix,
                ..
            } => {
                let Some(router_id) = cur_router_id else {
                    // An Update with no Router-ID in scope is malformed; skip it.
                    debug!(src = %dg.src, "Babel Update without a Router-ID; ignoring");
                    continue;
                };
                let cost = state.neighbours.cost(&src);
                if let Some(ev) =
                    state
                        .table
                        .update(*prefix, router_id, src, cur_nexthop, *seqno, *metric, cost)
                {
                    // If this very Update became the selected route, remember its
                    // origin so we can re-advertise it.
                    if let BabelEvent::Select { next_hop, .. } = &ev {
                        if *next_hop == cur_nexthop {
                            state
                                .relayed
                                .insert(*prefix, (router_id, *seqno, route_metric(&ev)));
                        }
                    }
                    forward_event_pinned(&mut state.relayed, ev, &iface.name, vrf_table, updates).await;
                    changed = true;
                }
            }
            Tlv::RouteRequest { .. } | Tlv::SeqnoRequest { .. } => {
                // Answer any request with a fresh full dump (handled below).
                changed = true;
            }
            _ => {}
        }
    }
    changed
}

/// The metric carried by a `Select` event (0 for a `Retract`).
fn route_metric(ev: &BabelEvent) -> u16 {
    match ev {
        BabelEvent::Select { metric, .. } => *metric,
        BabelEvent::Retract(_) => 0,
    }
}

/// Whether an IHU's target address is us (or a wildcard IHU).
fn ihu_is_for_us(iface: &Iface, address: &Option<IpAddr>) -> bool {
    match (address, iface.link_local) {
        (None, _) => true, // wildcard IHU
        (_, None) => true, // we don't know our own address — accept
        (Some(IpAddr::V6(a)), Some(ll)) => *a == ll,
        (Some(_), _) => false,
    }
}

/// Send a Hello on every interface, followed by an IHU per known neighbour
/// advertising our receive cost for it (so the neighbour learns its txcost).
async fn send_hellos(state: &mut State, ifaces: &[Iface]) {
    let seqno = state.hello_seqno;
    state.hello_seqno = state.hello_seqno.wrapping_add(1);

    for iface in ifaces {
        let mut tlvs = vec![Tlv::Hello {
            flags: 0,
            seqno,
            interval: HELLO_INTERVAL_CS,
        }];
        for addr in state.neighbours.addresses() {
            tlvs.push(Tlv::Ihu {
                rxcost: state.neighbours.rxcost(&addr),
                interval: IHU_INTERVAL_CS,
                address: Some(addr),
            });
        }
        send_raw(&iface.sock, &Packet::new(tlvs).encode()).await;
    }
}

/// Send our full route advertisement on every interface: our own networks (origin
/// = us, metric 0) and the routes we have selected (re-advertised with their
/// origin Router-ID and our computed metric). Updates are grouped under their
/// Router-ID and chunked into MTU-safe packets.
async fn send_updates(state: &mut State, ifaces: &[Iface]) {
    let tlvs = build_update_tlvs(state);
    // Retractions are advertised exactly once; build_update_tlvs has captured them.
    state.retractions.clear();
    if tlvs.is_empty() {
        return;
    }
    for iface in ifaces {
        for chunk in chunk_updates(&tlvs) {
            send_raw(&iface.sock, &Packet::new(chunk).encode()).await;
        }
    }
}

/// Build the Update TLV stream: our own networks first (under our Router-ID), then
/// each relayed route under its origin Router-ID. A `RouterId` TLV is emitted only
/// when the originator changes (§4.6.7).
fn build_update_tlvs(state: &State) -> Vec<Tlv> {
    let mut tlvs = Vec::new();
    let mut cur_rid: Option<[u8; 8]> = None;

    let mut push_update =
        |rid: [u8; 8], seqno: u16, metric: u16, prefix: Prefix, out: &mut Vec<Tlv>| {
            if cur_rid != Some(rid) {
                out.push(Tlv::RouterId(rid));
                cur_rid = Some(rid);
            }
            out.push(Tlv::Update {
                flags: 0,
                interval: UPDATE_INTERVAL_CS,
                seqno,
                metric,
                prefix,
            });
        };

    for prefix in &state.self_prefixes {
        push_update(state.router_id, OUR_SEQNO, 0, *prefix, &mut tlvs);
    }
    // Routes redistributed from the RIB, originated as ours at their metric.
    for (prefix, metric) in &state.redistributed {
        push_update(state.router_id, OUR_SEQNO, *metric, *prefix, &mut tlvs);
    }
    // One-shot retractions for redistributed routes that just went away.
    for prefix in &state.retractions {
        push_update(state.router_id, OUR_SEQNO, METRIC_INFINITY, *prefix, &mut tlvs);
    }
    for (prefix, (rid, seqno, metric)) in &state.relayed {
        // Don't re-advertise a route we also originate ourselves.
        if state.self_prefixes.contains(prefix)
            || state.redistributed.contains_key(prefix)
            || *rid == state.router_id
        {
            continue;
        }
        push_update(*rid, *seqno, *metric, *prefix, &mut tlvs);
    }
    tlvs
}

/// Split an Update TLV stream into MTU-safe packets, re-emitting the active
/// `RouterId` at the head of each packet so every Update keeps its originator.
fn chunk_updates(tlvs: &[Tlv]) -> Vec<Vec<Tlv>> {
    let mut packets = Vec::new();
    let mut cur: Vec<Tlv> = Vec::new();
    let mut last_rid: Option<Tlv> = None;
    let mut updates_in_cur = 0;

    for tlv in tlvs {
        if let Tlv::RouterId(_) = tlv {
            last_rid = Some(tlv.clone());
        }
        if updates_in_cur >= MAX_UPDATES_PER_PACKET {
            packets.push(std::mem::take(&mut cur));
            updates_in_cur = 0;
            if let Some(rid) = &last_rid {
                cur.push(rid.clone());
            }
        }
        if let Tlv::Update { .. } = tlv {
            updates_in_cur += 1;
        }
        cur.push(tlv.clone());
    }
    if !cur.is_empty() {
        packets.push(cur);
    }
    packets
}

/// Forward a selection event to the RIB, pinning a link-local next hop to the
/// receiving interface so the kernel can install it. Also keeps `relayed` in sync.
async fn forward_event_pinned(
    relayed: &mut std::collections::BTreeMap<Prefix, ([u8; 8], u16, u16)>,
    ev: BabelEvent,
    ifname: &str,
    vrf_table: u32,
    updates: &mpsc::Sender<RouteUpdate>,
) {
    match ev {
        BabelEvent::Select {
            prefix,
            next_hop,
            metric,
        } => {
            let route = babel_route(prefix, next_hop, metric, ifname).with_table(vrf_table);
            let _ = updates.send(RouteUpdate::Announce(route)).await;
        }
        BabelEvent::Retract(prefix) => {
            relayed.remove(&prefix);
            let _ = updates
                .send(RouteUpdate::Withdraw {
                    table: vrf_table,
                    prefix,
                    protocol: Protocol::Babel,
                    source: 0,
                })
                .await;
        }
    }
}

/// Forward a selection event with no interface to pin (used for neighbour-loss
/// fallbacks, where the surviving route's next hop is already routable or will be
/// refreshed by the next Update).
async fn forward_event(
    relayed: &mut std::collections::BTreeMap<Prefix, ([u8; 8], u16, u16)>,
    ev: BabelEvent,
    vrf_table: u32,
    updates: &mpsc::Sender<RouteUpdate>,
) {
    match ev {
        BabelEvent::Select {
            prefix,
            next_hop,
            metric,
        } => {
            let nh = nexthop_for(next_hop, None);
            let route =
                Route::new(prefix, Protocol::Babel, vec![nh], metric as u32).with_table(vrf_table);
            let _ = updates.send(RouteUpdate::Announce(route)).await;
        }
        BabelEvent::Retract(prefix) => {
            relayed.remove(&prefix);
            let _ = updates
                .send(RouteUpdate::Withdraw {
                    table: vrf_table,
                    prefix,
                    protocol: Protocol::Babel,
                    source: 0,
                })
                .await;
        }
    }
}

/// Build a Babel route, pinning a link-local gateway to `ifname`.
fn babel_route(prefix: Prefix, next_hop: IpAddr, metric: u16, ifname: &str) -> Route {
    Route::new(
        prefix,
        Protocol::Babel,
        vec![nexthop_for(next_hop, Some(ifname))],
        metric as u32,
    )
}

/// A next hop for `gw`: a link-local IPv6 gateway is pinned to `ifname` (it is only
/// installable with an outgoing interface); a global/IPv4 gateway is left bare.
fn nexthop_for(gw: IpAddr, ifname: Option<&str>) -> NextHop {
    let link_local = matches!(gw, IpAddr::V6(a) if (a.segments()[0] & 0xffc0) == 0xfe80);
    match (link_local, ifname) {
        (true, Some(name)) => NextHop::via_dev(gw, name.to_string()),
        _ => NextHop::via(gw),
    }
}

/// Multicast a pre-encoded Babel packet to `ff02::1:6` out of `sock`'s interface.
async fn send_raw(sock: &UdpSocket, data: &[u8]) {
    let dst = SocketAddr::V6(SocketAddrV6::new(MULTICAST, PORT, 0, 0));
    if let Err(e) = sock.send_to(data, dst).await {
        warn!(error = %e, "sending Babel packet");
    }
}

/// Our link-local (`fe80::/10`) IPv6 address on `ifname`, via `getifaddrs(3)`.
fn link_local_of(ifname: &str) -> Option<Ipv6Addr> {
    let mut head: *mut libc::ifaddrs = ptr::null_mut();
    // SAFETY: getifaddrs allocates a list into `head`; checked and freed below.
    if unsafe { libc::getifaddrs(&mut head) } != 0 {
        return None;
    }
    let mut found = None;
    let mut cur = head;
    while !cur.is_null() {
        // SAFETY: `cur` is a non-null node in the kernel-provided list.
        let ifa = unsafe { &*cur };
        cur = ifa.ifa_next;
        if ifa.ifa_addr.is_null() {
            continue;
        }
        // SAFETY: `ifa_name` is a valid NUL-terminated C string.
        let name = unsafe { CStr::from_ptr(ifa.ifa_name) }.to_string_lossy();
        if name != ifname {
            continue;
        }
        // SAFETY: reading sa_family is valid for any sockaddr.
        if unsafe { (*ifa.ifa_addr).sa_family } as i32 != libc::AF_INET6 {
            continue;
        }
        // SAFETY: family is AF_INET6, so the sockaddr is a sockaddr_in6.
        let sin6 = unsafe { &*(ifa.ifa_addr as *const libc::sockaddr_in6) };
        let a = Ipv6Addr::from(sin6.sin6_addr.s6_addr);
        if (a.segments()[0] & 0xffc0) == 0xfe80 {
            found = Some(a);
            break;
        }
    }
    // SAFETY: freeing exactly the list getifaddrs allocated above.
    unsafe { libc::freeifaddrs(head) };
    found
}

/// Open a non-blocking IPv6 UDP socket for Babel on `ifname`: reuse-port +
/// bind-to-device on `[::]:6696`, joined to and sending out via `ff02::1:6` on that
/// interface. Returns its index and the socket. Mirrors [`crate::ripng`]'s socket
/// setup (Babel uses a hop limit of 1, as it is a single-hop-per-link protocol).
fn open_babel_socket(ifname: &str) -> Result<(u32, std::net::UdpSocket)> {
    let cname = CString::new(ifname).context("interface name has an interior NUL")?;
    // SAFETY: `cname` is a valid NUL-terminated string for the call's duration.
    let ifindex = unsafe { libc::if_nametoindex(cname.as_ptr()) };
    if ifindex == 0 {
        anyhow::bail!("interface {ifname:?} not found");
    }

    // SAFETY: a plain socket(2); the fd is checked before use.
    let fd = unsafe {
        libc::socket(
            libc::AF_INET6,
            libc::SOCK_DGRAM | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
            0,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error()).context("socket(AF_INET6, SOCK_DGRAM)");
    }
    // SAFETY: `fd` was just returned by socket() and owned by nobody else; wrapping
    // it ensures it is closed on any early return.
    let sock = unsafe { std::net::UdpSocket::from_raw_fd(fd) };

    setsockopt_int(fd, libc::SOL_SOCKET, libc::SO_REUSEADDR, 1)?;
    setsockopt_int(fd, libc::SOL_SOCKET, libc::SO_REUSEPORT, 1)?;
    setsockopt_int(fd, libc::IPPROTO_IPV6, libc::IPV6_V6ONLY, 1)?;

    // SAFETY: `ifname` bytes + length describe a valid optval buffer.
    let rc = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_BINDTODEVICE,
            ifname.as_ptr() as *const c_void,
            ifname.len() as libc::socklen_t,
        )
    };
    if rc < 0 {
        return Err(io::Error::last_os_error())
            .with_context(|| format!("SO_BINDTODEVICE {ifname:?} (needs CAP_NET_RAW)"));
    }

    // bind [::]:6696
    // SAFETY: a zeroed sockaddr_in6 with family/port set is a valid bind addr
    // (sin6_addr stays :: = in6addr_any).
    let mut sa: libc::sockaddr_in6 = unsafe { mem::zeroed() };
    sa.sin6_family = libc::AF_INET6 as libc::sa_family_t;
    sa.sin6_port = PORT.to_be();
    let rc = unsafe {
        libc::bind(
            fd,
            &sa as *const _ as *const libc::sockaddr,
            mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
        )
    };
    if rc < 0 {
        return Err(io::Error::last_os_error()).context("bind [::]:6696");
    }

    // Join ff02::1:6 on this interface, and send our multicast out of it.
    // SAFETY: ipv6_mreq is a plain POD; we fill both fields.
    let mut mreq: libc::ipv6_mreq = unsafe { mem::zeroed() };
    mreq.ipv6mr_multiaddr.s6_addr = MULTICAST.octets();
    mreq.ipv6mr_interface = ifindex;
    setsockopt_struct(fd, libc::IPPROTO_IPV6, libc::IPV6_ADD_MEMBERSHIP, &mreq)
        .context("IPV6_ADD_MEMBERSHIP ff02::1:6")?;
    setsockopt_int(
        fd,
        libc::IPPROTO_IPV6,
        libc::IPV6_MULTICAST_IF,
        ifindex as i32,
    )?;
    setsockopt_int(fd, libc::IPPROTO_IPV6, libc::IPV6_MULTICAST_LOOP, 0)?;
    setsockopt_int(fd, libc::IPPROTO_IPV6, libc::IPV6_MULTICAST_HOPS, 1)?;

    Ok((ifindex, sock))
}

/// Derive an 8-octet Babel Router-ID from a dotted-quad router id: the IPv4 in the
/// low four octets (high four zero), giving a stable, unique-per-router value.
pub fn router_id_from_ipv4(v4: Ipv4Addr) -> [u8; 8] {
    let o = v4.octets();
    [0, 0, 0, 0, o[0], o[1], o[2], o[3]]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pfx(s: &str) -> Prefix {
        s.parse().unwrap()
    }

    #[test]
    fn router_id_packs_ipv4_into_low_octets() {
        let id = router_id_from_ipv4("10.0.0.1".parse().unwrap());
        assert_eq!(id, [0, 0, 0, 0, 10, 0, 0, 1]);
    }

    #[test]
    fn self_routes_advertise_under_our_router_id_with_metric_zero() {
        let state = State {
            router_id: [0, 0, 0, 0, 10, 0, 0, 1],
            neighbours: NeighbourTable::new(),
            table: RouteTable::new(),
            self_prefixes: vec![pfx("10.0.0.0/24"), pfx("2001:db8::/64")],
            relayed: std::collections::BTreeMap::new(),
            redistributed: std::collections::BTreeMap::new(),
            retractions: Vec::new(),
            hello_seqno: 0,
        };
        let tlvs = build_update_tlvs(&state);
        // One Router-ID followed by the two Updates (same originator).
        assert_eq!(tlvs.len(), 3);
        assert!(matches!(tlvs[0], Tlv::RouterId(id) if id == state.router_id));
        let metrics: Vec<u16> = tlvs
            .iter()
            .filter_map(|t| match t {
                Tlv::Update { metric, .. } => Some(*metric),
                _ => None,
            })
            .collect();
        assert_eq!(metrics, vec![0, 0]);
    }

    fn empty_state() -> State {
        State {
            router_id: [0, 0, 0, 0, 10, 0, 0, 1],
            neighbours: NeighbourTable::new(),
            table: RouteTable::new(),
            self_prefixes: Vec::new(),
            relayed: std::collections::BTreeMap::new(),
            redistributed: std::collections::BTreeMap::new(),
            retractions: Vec::new(),
            hello_seqno: 0,
        }
    }

    fn route(prefix: &str) -> Route {
        Route::new(pfx(prefix), Protocol::Static, vec![NextHop::dev("eth0")], 0)
    }

    #[test]
    fn redistributed_route_is_originated_under_our_router_id_at_its_metric() {
        let mut state = empty_state();
        assert!(apply_redistribution(
            &mut state,
            Redistribution::Announce(route("2001:db8:99::/64")),
            96
        ));
        // Idempotent: the same announce at the same metric changes nothing.
        assert!(!apply_redistribution(
            &mut state,
            Redistribution::Announce(route("2001:db8:99::/64")),
            96
        ));
        let tlvs = build_update_tlvs(&state);
        // Origin is us, metric is the redistribute metric.
        assert!(matches!(tlvs[0], Tlv::RouterId(id) if id == state.router_id));
        assert!(tlvs.iter().any(|t| matches!(
            t,
            Tlv::Update { metric: 96, prefix, .. } if *prefix == pfx("2001:db8:99::/64")
        )));
    }

    #[test]
    fn withdrawing_a_redistributed_route_retracts_it_once_at_infinity() {
        let mut state = empty_state();
        apply_redistribution(
            &mut state,
            Redistribution::Announce(route("2001:db8:99::/64")),
            0,
        );
        assert!(apply_redistribution(
            &mut state,
            Redistribution::Withdraw(pfx("2001:db8:99::/64")),
            0
        ));
        // The route is gone from the originated set and queued as a retraction.
        assert!(!state.redistributed.contains_key(&pfx("2001:db8:99::/64")));
        let tlvs = build_update_tlvs(&state);
        assert!(tlvs.iter().any(|t| matches!(
            t,
            Tlv::Update { metric: METRIC_INFINITY, prefix, .. } if *prefix == pfx("2001:db8:99::/64")
        )));
        // Withdrawing an unknown prefix is a no-op.
        assert!(!apply_redistribution(
            &mut state,
            Redistribution::Withdraw(pfx("2001:db8:99::/64")),
            0
        ));
    }

    #[test]
    fn an_own_network_is_not_clobbered_by_redistribution() {
        let mut state = empty_state();
        state.self_prefixes.push(pfx("2001:db8::/64"));
        assert!(!apply_redistribution(
            &mut state,
            Redistribution::Announce(route("2001:db8::/64")),
            96
        ));
        assert!(!state.redistributed.contains_key(&pfx("2001:db8::/64")));
    }

    #[test]
    fn relayed_route_keeps_its_origin_router_id() {
        let mut relayed = std::collections::BTreeMap::new();
        let rid = [1, 1, 1, 1, 1, 1, 1, 1];
        relayed.insert(pfx("203.0.113.0/24"), (rid, 7u16, 150u16));
        let state = State {
            router_id: [0, 0, 0, 0, 10, 0, 0, 1],
            neighbours: NeighbourTable::new(),
            table: RouteTable::new(),
            self_prefixes: vec![],
            relayed,
            redistributed: std::collections::BTreeMap::new(),
            retractions: Vec::new(),
            hello_seqno: 0,
        };
        let tlvs = build_update_tlvs(&state);
        assert!(matches!(tlvs[0], Tlv::RouterId(id) if id == rid));
        assert!(matches!(
            tlvs[1],
            Tlv::Update {
                seqno: 7,
                metric: 150,
                ..
            }
        ));
    }

    #[test]
    fn link_local_gateway_is_pinned_to_interface() {
        let route = babel_route(pfx("10.0.0.0/24"), "fe80::1".parse().unwrap(), 96, "eth1");
        assert_eq!(route.nexthops.len(), 1);
        assert_eq!(route.nexthops[0].iface.as_deref(), Some("eth1"));
        assert_eq!(route.protocol, Protocol::Babel);
    }

    #[test]
    fn chunking_re_emits_router_id_per_packet() {
        let rid = [0, 0, 0, 0, 10, 0, 0, 1];
        let mut tlvs = vec![Tlv::RouterId(rid)];
        for i in 0..(MAX_UPDATES_PER_PACKET + 5) {
            tlvs.push(Tlv::Update {
                flags: 0,
                interval: UPDATE_INTERVAL_CS,
                seqno: 1,
                metric: 0,
                prefix: pfx(&format!("10.0.{i}.0/24")),
            });
        }
        let packets = chunk_updates(&tlvs);
        assert_eq!(packets.len(), 2);
        // Every packet starts with the Router-ID so each Update keeps its origin.
        assert!(matches!(packets[0][0], Tlv::RouterId(id) if id == rid));
        assert!(matches!(packets[1][0], Tlv::RouterId(id) if id == rid));
    }
}
