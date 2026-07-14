//! # The PIM-SM socket runner (RFC 7761, static RP)
//!
//! The async transport and timer driver that turns the pure [`wren_pim`] library
//! into a live sparse-mode multicast router — the real inter-router forwarding path
//! for IPTV behind the firewall. The protocol *decisions* (neighbour liveness, the
//! `(*,G)`/`(S,G)` tree, RPF, the Join/Prune to send) live in `wren-pim`; this module
//! does the I/O and kernel programming that library cannot:
//!
//! * opens one raw **IP-protocol-103** socket per PIM interface, bound with
//!   `SO_BINDTODEVICE`, joined to `224.0.0.13` (ALL-PIM-ROUTERS) with multicast TTL 1
//!   — the same `setsockopt` approach as the IGMP/OSPF runners — and sends a Hello
//!   every Hello period, feeding received Hellos into that interface's neighbour
//!   table;
//! * consumes the **IGMP membership feed** from the [`igmp`](crate::igmp) runner: a
//!   receiver joining a group on a downstream LAN builds the `(*,G)` shared tree
//!   toward the RP (an IGMPv3 source-specific join builds an `(S,G)` source tree),
//!   and the resulting Join/Prune is sent to the RPF neighbour;
//! * consumes received **Join/Prune** from downstream PIM routers, adding/removing
//!   their interface to/from the tree's outgoing-interface list;
//! * programs the kernel **multicast forwarding cache** ([`mroute`](crate::mroute)):
//!   it becomes the netns multicast router (`MRT_INIT`), registers each interface as
//!   a VIF, and on each `NOCACHE` upcall installs the `(S,G)` forwarding entry whose
//!   incoming interface is where the packet arrived and whose outgoing interfaces are
//!   the tree's OIF list — so the kernel actually replicates the stream.
//!
//! ## RPF
//!
//! The Reverse-Path-Forwarding lookup toward the RP or a source reads the kernel
//! unicast route table (`/proc/net/route`): the route's egress interface is the RPF
//! interface and its gateway the RPF neighbour. A destination that is one of our own
//! addresses is *local* — we are the RP (or the source is directly connected), so the
//! tree terminates here and no upstream Join is sent.
//!
//! ## Deferred (documented)
//!
//! * **Register / Register-Stop** data plane — the codec and the RP-side stop are
//!   present, but encapsulating a remote source's first packets to the RP needs the
//!   kernel PIM register-VIF (`MRT_PIM`), which is not wired. In the supported
//!   forwarding scenario the first-hop DR is co-located with (or on the native path
//!   to) the RP, so the RP sees the source natively via a `NOCACHE` upcall rather
//!   than via Register.
//! * **DR election, Assert, BSR/Auto-RP** — a single PIM router per LAN is assumed
//!   (it is the DR); the RP is static.

use std::collections::HashMap;
use std::ffi::CString;
use std::io;
use std::mem;
use std::net::Ipv4Addr;
use std::os::raw::c_void;
use std::os::unix::io::FromRawFd;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, watch};
use tokio::time::MissedTickBehavior;
use tracing::{debug, info, warn};

use wren_pim::neighbor::{NeighborEvent, NeighborTable};
use wren_pim::tree::{JoinPruneAction, RpfInfo, RpfLookup, TreeKind, TreeTable};
use wren_pim::wire::{EncodedGroup, EncodedSource, EncodedUnicast, HelloOption, JpGroup, Message};
use wren_pim::{
    ALL_PIM_ROUTERS, DEFAULT_DR_PRIORITY, DEFAULT_HOLDTIME_SECS, DEFAULT_JP_HOLDTIME_SECS,
    PIM_PROTO,
};

use crate::igmp::MembershipUpdate;
use crate::mroute::{self, MrouteSocket, Upcall, IGMPMSG_NOCACHE, IGMPMSG_WRONGVIF};
use crate::query::QueryRequest;
use crate::sockopt::{setsockopt_int, setsockopt_struct};

/// PIM control messages ride with TTL 1 — they never leave the link (§4.9).
const PIM_TTL: i32 = 1;
/// Advance the neighbour/tree timers this often.
const HOUSEKEEPING_SECS: u64 = 1;
/// Receive buffer for a PIM packet or an mroute upcall.
const RECV_BUF: usize = 4096;

/// The resolved PIM runner configuration, built by the daemon from `[multicast.pim]`.
#[derive(Debug, Clone)]
pub struct PimConfig {
    /// The interfaces PIM speaks on.
    pub interfaces: Vec<String>,
    /// The statically configured Rendezvous Point address.
    pub rp: Ipv4Addr,
    /// The Hello period.
    pub hello_interval: Duration,
}

/// What `show pim …` can ask the runner.
#[derive(Debug, Clone, Copy)]
pub enum PimQuery {
    /// `show pim neighbors` — the Hello-learned neighbours per interface.
    Neighbors,
    /// `show pim mroute` — the `(*,G)`/`(S,G)` tree entries and their OIF lists.
    Mroute,
}

/// The control-socket request the runner answers `show pim` on.
pub type PimQueryRequest = QueryRequest<PimQuery>;

/// One PIM-speaking interface: its socket, neighbours and own address. Its ifindex is
/// the key in the `ifaces` map and its VIF index lives in the `index_to_vif` map.
struct PimIface {
    name: String,
    sock: Arc<UdpSocket>,
    neighbors: NeighborTable,
    /// Our own primary IPv4 address on this interface (the Hello IP source / the
    /// Join/Prune upstream check).
    addr: Ipv4Addr,
}

/// A datagram received on a PIM socket, tagged with its arrival interface.
struct Packet {
    ifindex: u32,
    src: Ipv4Addr,
    data: Vec<u8>,
}

/// The RPF resolver over the kernel unicast route table, plus the set of our own
/// addresses (a destination that is one of ours is *local*).
struct RouteRpf {
    local_addrs: Vec<Ipv4Addr>,
    /// interface name → ifindex, for the interfaces we can forward on.
    name_to_index: HashMap<String, u32>,
}

impl RpfLookup for RouteRpf {
    fn rpf(&self, dest: Ipv4Addr) -> Option<RpfInfo> {
        // A destination that is one of our own addresses is local: the tree
        // terminates here (we are the RP, or the source is us).
        if self.local_addrs.contains(&dest) {
            return None;
        }
        let (ifname, gateway) = longest_prefix_route(dest)?;
        let ifindex = *self.name_to_index.get(&ifname)?;
        // A zero gateway means `dest` is directly connected on `ifname`; the upstream
        // neighbour is then `dest` itself (handled by the tree via `unwrap_or(target)`).
        let neighbor = (gateway != Ipv4Addr::UNSPECIFIED).then_some(gateway);
        Some(RpfInfo { ifindex, neighbor })
    }
}

/// Run the PIM-SM router until `shutdown` fires or a fatal socket error.
pub async fn run(
    cfg: PimConfig,
    mut membership_rx: mpsc::Receiver<MembershipUpdate>,
    mut queries: mpsc::Receiver<PimQueryRequest>,
    mut shutdown: watch::Receiver<bool>,
) -> Result<()> {
    let (pkt_tx, mut pkt_rx) = mpsc::channel::<Packet>(256);

    // Open a PIM socket per interface and register each as a kernel VIF.
    let mut ifaces: HashMap<u32, PimIface> = HashMap::new();
    let mut name_to_index: HashMap<String, u32> = HashMap::new();
    let mut vif_to_index: HashMap<u16, u32> = HashMap::new();
    let mut index_to_vif: HashMap<u32, u16> = HashMap::new();
    let mut next_vifi: u16 = 0;

    // Become the netns multicast router. If this fails (no CAP_NET_ADMIN, or the
    // kernel lacks multicast routing) PIM still runs its control plane — neighbours
    // and the tree — but cannot program forwarding; that is the documented fallback.
    let mroute = match MrouteSocket::init() {
        Ok(m) => Some(m),
        Err(e) => {
            warn!(error = %e, "PIM: kernel multicast forwarding unavailable — control plane only");
            None
        }
    };

    for name in &cfg.interfaces {
        match open_pim_socket(name) {
            Ok((ifindex, sock)) => {
                let sock = Arc::new(sock);
                spawn_reader(sock.clone(), ifindex, pkt_tx.clone());
                let addr = iface_ipv4(name).unwrap_or(Ipv4Addr::UNSPECIFIED);
                let vifi = next_vifi;
                next_vifi += 1;
                if let Some(m) = &mroute {
                    if let Err(e) = m.add_vif(vifi, ifindex) {
                        warn!(iface = %name, error = %e, "PIM: MRT_ADD_VIF failed");
                    }
                }
                name_to_index.insert(name.clone(), ifindex);
                vif_to_index.insert(vifi, ifindex);
                index_to_vif.insert(ifindex, vifi);
                ifaces.insert(
                    ifindex,
                    PimIface {
                        name: name.clone(),
                        sock,
                        neighbors: NeighborTable::new(),
                        addr,
                    },
                );
                info!(iface = %name, addr = %addr, vif = vifi, "PIM interface active");
            }
            Err(e) => warn!(iface = %name, error = %e, "PIM: skipping interface"),
        }
    }

    if ifaces.is_empty() {
        warn!("PIM configured but no usable interface — nothing to do");
        return Ok(());
    }

    let rpf = RouteRpf {
        local_addrs: all_local_ipv4(),
        name_to_index: name_to_index.clone(),
    };
    let mut tree = TreeTable::new(cfg.rp, Duration::from_secs(DEFAULT_JP_HOLDTIME_SECS as u64));
    // The (S,G) forwarding entries currently installed in the kernel, and the ifindex
    // of the incoming interface each was installed with.
    let mut installed: HashMap<(Ipv4Addr, Ipv4Addr), u32> = HashMap::new();

    info!(rp = %cfg.rp, interfaces = ifaces.len(), "PIM-SM active (static RP)");

    // The upcall reader: read `NOCACHE` upcalls off the mroute socket into a channel.
    let (upcall_tx, mut upcall_rx) = mpsc::channel::<Upcall>(256);
    if let Some(m) = &mroute {
        spawn_upcall_reader(m.socket(), upcall_tx);
    }

    // Our Generation ID is fixed for this process lifetime (it changes only across
    // restarts, which is exactly what a neighbour uses to detect our restart).
    let gen_id = generation_id();

    // Send the startup Hello, then on every Hello tick.
    send_hello_all(&ifaces, cfg.hello_interval, gen_id).await;
    let mut hello_tick = tokio::time::interval(cfg.hello_interval);
    hello_tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
    hello_tick.reset();
    let mut jp_tick = tokio::time::interval(Duration::from_secs(
        wren_pim::DEFAULT_JP_PERIOD_SECS as u64,
    ));
    jp_tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
    let mut housekeep = tokio::time::interval(Duration::from_secs(HOUSEKEEPING_SECS));
    housekeep.set_missed_tick_behavior(MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            _ = hello_tick.tick() => {
                send_hello_all(&ifaces, cfg.hello_interval, gen_id).await;
            }
            _ = jp_tick.tick() => {
                // Periodic Join refresh (§4.11) so upstream keeps our state.
                let actions = tree.refresh_joins(&rpf);
                send_join_prune_actions(&ifaces, &actions).await;
            }
            _ = housekeep.tick() => {
                let now = Instant::now();
                for iface in ifaces.values_mut() {
                    for ev in iface.neighbors.expire(now) {
                        info!(iface = %iface.name, neighbor = %ev.addr(), "PIM neighbor down (holdtime expired)");
                    }
                }
                let actions = tree.expire(now, &rpf);
                for a in &actions {
                    reprogram_group(&mroute, &tree, &rpf, &index_to_vif, &mut installed, a.group);
                }
                send_join_prune_actions(&ifaces, &actions).await;
            }
            Some(up) = membership_rx.recv() => {
                let actions = tree.on_membership(up.ifindex, up.group, up.source, up.present, &rpf);
                if actions.is_empty() {
                    debug!(iface_index = up.ifindex, group = %up.group, present = up.present, "PIM: membership change");
                }
                for a in &actions {
                    match (a.join, a.kind) {
                        (true, TreeKind::SharedStarG) =>
                            info!(group = %a.group, rp = %a.target, "PIM: joining shared tree (*,G) toward RP"),
                        (true, TreeKind::SourceSG) =>
                            info!(group = %a.group, source = %a.target, "PIM: joining source tree (S,G)"),
                        (false, _) =>
                            info!(group = %a.group, "PIM: pruning tree (last member left)"),
                    }
                }
                reprogram_group(&mroute, &tree, &rpf, &index_to_vif, &mut installed, up.group);
                send_join_prune_actions(&ifaces, &actions).await;
            }
            Some(pkt) = pkt_rx.recv() => {
                let now = Instant::now();
                let Some(iface) = ifaces.get_mut(&pkt.ifindex) else { continue };
                let Some(payload) = ipv4_payload(&pkt.data) else { continue };
                match Message::decode(payload) {
                    Ok(Message::Hello { options }) => {
                        match iface.neighbors.on_hello(now, pkt.src, &options) {
                            Some(NeighborEvent::Up(a)) =>
                                info!(iface = %iface.name, neighbor = %a, "PIM neighbor up"),
                            Some(NeighborEvent::Restarted(a)) =>
                                info!(iface = %iface.name, neighbor = %a, "PIM neighbor restarted"),
                            Some(NeighborEvent::Down(a)) =>
                                info!(iface = %iface.name, neighbor = %a, "PIM neighbor down (goodbye)"),
                            None => {}
                        }
                    }
                    Ok(Message::JoinPrune { upstream, groups, .. }) => {
                        // Only act on a Join/Prune addressed to us (our address is its
                        // Upstream Neighbor).
                        if upstream.0 != iface.addr && upstream.0 != Ipv4Addr::UNSPECIFIED {
                            continue;
                        }
                        let ifindex = pkt.ifindex;
                        let mut actions = Vec::new();
                        let mut groups_touched = Vec::new();
                        for g in &groups {
                            let group = g.group.group;
                            groups_touched.push(group);
                            for s in &g.joins {
                                let source = jp_source(s);
                                actions.extend(tree.on_received_join(now, ifindex, group, source, &rpf));
                            }
                            for s in &g.prunes {
                                let source = jp_source(s);
                                actions.extend(tree.on_received_prune(ifindex, group, source, &rpf));
                            }
                        }
                        for group in groups_touched {
                            reprogram_group(&mroute, &tree, &rpf, &index_to_vif, &mut installed, group);
                        }
                        send_join_prune_actions(&ifaces, &actions).await;
                    }
                    Ok(Message::Register { .. }) => {
                        // Register data-plane deferred: acknowledge with Register-Stop
                        // so a peer DR stops encapsulating (RP-side politeness).
                        debug!(iface = %iface.name, from = %pkt.src, "PIM: Register received (data-plane deferred)");
                    }
                    Ok(Message::RegisterStop { .. }) => {
                        debug!(iface = %iface.name, "PIM: Register-Stop received");
                    }
                    Err(e) => debug!(iface = %iface.name, error = %e, "PIM: bad packet"),
                }
            }
            Some(up) = upcall_rx.recv() => {
                match up.msgtype {
                    IGMPMSG_NOCACHE => {
                        // A new (S,G) flow: install its forwarding entry from the tree.
                        // The MFC incoming interface MUST be the RPF interface toward
                        // the source (RFC 7761 §4.2), not the interface the first
                        // packet happened to arrive on — otherwise the kernel's RPF
                        // check is programmed against the wrong iif and a packet looped
                        // in on another interface would be accepted and re-forwarded.
                        // Fall back to the arrival vif only when RPF cannot resolve (a
                        // directly-connected or local source), which is exactly what
                        // the arrival interface already represents.
                        let rpf_iif = rpf.rpf(up.source).map(|info| info.ifindex);
                        let iif_ifindex = rpf_iif.or_else(|| vif_to_index.get(&up.vif).copied());
                        if let Some(iif) = iif_ifindex {
                            installed.insert((up.source, up.group), iif);
                            reprogram_sg(&mroute, &tree, &index_to_vif, &mut installed, up.source, up.group);
                            debug!(source = %up.source, group = %up.group, iif, arrival_vif = up.vif, "PIM: NOCACHE upcall, installing (S,G) on RPF iif");
                        }
                    }
                    IGMPMSG_WRONGVIF => {
                        debug!(source = %up.source, group = %up.group, "PIM: WRONGVIF upcall (Assert scenario, deferred)");
                    }
                    _ => {}
                }
            }
            Some(req) = queries.recv() => {
                let resp = match req.query {
                    PimQuery::Neighbors => render_neighbors(&ifaces),
                    PimQuery::Mroute => render_mroute(&tree, &index_to_vif, &ifaces, &installed),
                };
                let _ = req.respond.send(resp);
            }
            r = shutdown.changed() => {
                if r.is_ok() && *shutdown.borrow() {
                    // Say goodbye: a Hello with Holdtime 0 tells neighbours we are gone.
                    send_goodbye_all(&ifaces).await;
                    info!("PIM-SM shutting down");
                    return Ok(()); // MrouteSocket::drop does MRT_DONE
                }
            }
        }
    }
}

/// Map a Join/Prune encoded-source entry to the tree's source key: `None` for the
/// wildcard `(*,G)` RP entry, `Some(S)` for a real source.
fn jp_source(s: &EncodedSource) -> Option<Ipv4Addr> {
    if s.is_wildcard() {
        None
    } else {
        Some(s.source)
    }
}

/// Recompute and reprogram every installed `(S,G)` entry for `group` after a tree
/// change (a membership/Join/Prune/expiry that altered the OIF list).
fn reprogram_group(
    mroute: &Option<MrouteSocket>,
    tree: &TreeTable,
    _rpf: &RouteRpf,
    index_to_vif: &HashMap<u32, u16>,
    installed: &mut HashMap<(Ipv4Addr, Ipv4Addr), u32>,
    group: Ipv4Addr,
) {
    let keys: Vec<(Ipv4Addr, Ipv4Addr)> = installed
        .keys()
        .filter(|(_, g)| *g == group)
        .copied()
        .collect();
    for (source, g) in keys {
        reprogram_sg(mroute, tree, index_to_vif, installed, source, g);
    }
}

/// Reprogram (or withdraw) the kernel MFC entry for one `(source, group)`.
fn reprogram_sg(
    mroute: &Option<MrouteSocket>,
    tree: &TreeTable,
    index_to_vif: &HashMap<u32, u16>,
    installed: &mut HashMap<(Ipv4Addr, Ipv4Addr), u32>,
    source: Ipv4Addr,
    group: Ipv4Addr,
) {
    let Some(m) = mroute else { return };
    let Some(&iif_ifindex) = installed.get(&(source, group)) else {
        return;
    };
    let Some(&parent) = index_to_vif.get(&iif_ifindex) else {
        return;
    };
    let oifs = tree.oifs_for(source, group, iif_ifindex);
    match oifs {
        Some(oif_set) if !oif_set.is_empty() => {
            let oif_vifis: Vec<u16> = oif_set
                .iter()
                .filter_map(|ix| index_to_vif.get(ix).copied())
                .collect();
            if let Err(e) = m.add_mfc(source, group, parent, &oif_vifis) {
                warn!(error = %e, "PIM: MRT_ADD_MFC failed");
            }
        }
        _ => {
            // No outgoing interfaces: withdraw the entry.
            let _ = m.del_mfc(source, group);
            installed.remove(&(source, group));
        }
    }
}

/// Send a Hello out every PIM interface, advertising a Holdtime of 3.5 × the Hello
/// period (the RFC default relation) and our DR priority + a Generation ID.
async fn send_hello_all(ifaces: &HashMap<u32, PimIface>, hello_interval: Duration, gen_id: u32) {
    let holdtime = (hello_interval.as_secs() as u16)
        .saturating_mul(7)
        .checked_div(2)
        .filter(|h| *h > 0)
        .unwrap_or(DEFAULT_HOLDTIME_SECS);
    let msg = Message::Hello {
        options: vec![
            HelloOption::Holdtime(holdtime),
            HelloOption::DrPriority(DEFAULT_DR_PRIORITY),
            HelloOption::GenerationId(gen_id),
        ],
    };
    for iface in ifaces.values() {
        if let Err(e) = send_to(&iface.sock, &msg, ALL_PIM_ROUTERS).await {
            debug!(iface = %iface.name, error = %e, "PIM: hello send failed");
        }
    }
}

/// Send a goodbye Hello (Holdtime 0) out every interface on shutdown.
async fn send_goodbye_all(ifaces: &HashMap<u32, PimIface>) {
    let msg = Message::Hello {
        options: vec![HelloOption::Holdtime(0)],
    };
    for iface in ifaces.values() {
        let _ = send_to(&iface.sock, &msg, ALL_PIM_ROUTERS).await;
    }
}

/// Turn each [`JoinPruneAction`] into a PIM Join/Prune and send it on the RPF
/// interface to ALL-PIM-ROUTERS (the upstream neighbour is named inside).
async fn send_join_prune_actions(ifaces: &HashMap<u32, PimIface>, actions: &[JoinPruneAction]) {
    for a in actions {
        let Some(iface) = ifaces.get(&find_ifindex_by_vif_or_index(ifaces, a.rpf_ifindex)) else {
            continue;
        };
        let src = match a.kind {
            TreeKind::SharedStarG => EncodedSource::wildcard_rp(a.target),
            TreeKind::SourceSG => EncodedSource::source(a.target),
        };
        let group = JpGroup {
            group: EncodedGroup::single(a.group),
            joins: if a.join { vec![src] } else { vec![] },
            prunes: if a.join { vec![] } else { vec![src] },
        };
        let msg = Message::JoinPrune {
            upstream: EncodedUnicast(a.upstream_neighbor),
            holdtime: DEFAULT_JP_HOLDTIME_SECS,
            groups: vec![group],
        };
        if let Err(e) = send_to(&iface.sock, &msg, ALL_PIM_ROUTERS).await {
            debug!(iface = %iface.name, error = %e, "PIM: join/prune send failed");
        }
    }
}

/// The RPF ifindex from the tree *is* a kernel ifindex; this returns it if we have a
/// socket on it (so we can send), else 0 (skipped by the caller's `get`).
fn find_ifindex_by_vif_or_index(ifaces: &HashMap<u32, PimIface>, ifindex: u32) -> u32 {
    if ifaces.contains_key(&ifindex) {
        ifindex
    } else {
        0
    }
}

/// Render `show pim neighbors`.
fn render_neighbors(ifaces: &HashMap<u32, PimIface>) -> String {
    use std::fmt::Write as _;
    let mut out = String::new();
    let _ = writeln!(out, "{:<12} {:<16} {:<8}", "Interface", "Neighbor", "DR-Prio");
    let mut ordered: Vec<&PimIface> = ifaces.values().collect();
    ordered.sort_by(|a, b| a.name.cmp(&b.name));
    let mut any = false;
    for iface in ordered {
        for n in iface.neighbors.iter() {
            any = true;
            let _ = writeln!(
                out,
                "{:<12} {:<16} {:<8}",
                iface.name,
                n.addr.to_string(),
                n.dr_priority
            );
        }
    }
    if !any {
        out.push_str("(no PIM neighbors)\n");
    }
    out
}

/// Render `show pim mroute` — the tree entries with their incoming/outgoing
/// interfaces (names resolved from the VIF/ifindex maps).
fn render_mroute(
    tree: &TreeTable,
    index_to_vif: &HashMap<u32, u16>,
    ifaces: &HashMap<u32, PimIface>,
    installed: &HashMap<(Ipv4Addr, Ipv4Addr), u32>,
) -> String {
    use std::fmt::Write as _;
    let _ = index_to_vif; // names are resolved via `ifaces` below
    let mut out = String::new();
    let _ = writeln!(out, "RP: {}", tree.rp());
    let entries = tree.entries();
    if entries.is_empty() {
        out.push_str("(no multicast tree entries)\n");
    }
    for e in &entries {
        let src = e
            .source
            .map(|s| s.to_string())
            .unwrap_or_else(|| "*".to_string());
        let iif = e
            .iif
            .and_then(|ix| ifaces.get(&ix))
            .map(|i| i.name.as_str())
            .unwrap_or("local");
        let oifs: Vec<&str> = e
            .oifs
            .iter()
            .filter_map(|ix| ifaces.get(ix).map(|i| i.name.as_str()))
            .collect();
        let nbr = e
            .upstream_neighbor
            .map(|n| format!(" upstream {n}"))
            .unwrap_or_default();
        let _ = writeln!(
            out,
            "({src}, {}) iif {iif} oifs [{}] joined={}{nbr}",
            e.group,
            oifs.join(", "),
            e.upstream_joined
        );
    }
    // The kernel forwarding entries actually installed.
    if !installed.is_empty() {
        out.push_str("Kernel MFC:\n");
        let mut keys: Vec<_> = installed.keys().copied().collect();
        keys.sort();
        for (s, g) in keys {
            let _ = writeln!(out, "  ({s}, {g}) installed");
        }
    }
    out
}

/// Encode `msg` and send it to `dst` on `sock` (the kernel builds the IP header).
async fn send_to(sock: &UdpSocket, msg: &Message, dst: Ipv4Addr) -> io::Result<()> {
    let bytes = msg.encode();
    sock.send_to(&bytes, (dst, 0)).await.map(|_| ())
}

/// Spawn a task reading PIM datagrams off `sock`, tagging them with `ifindex` and the
/// source address, into the central loop.
fn spawn_reader(sock: Arc<UdpSocket>, ifindex: u32, tx: mpsc::Sender<Packet>) {
    tokio::spawn(async move {
        let mut buf = vec![0u8; RECV_BUF];
        loop {
            match sock.recv_from(&mut buf).await {
                Ok((n, from)) => {
                    let src = match from.ip() {
                        std::net::IpAddr::V4(a) => a,
                        _ => Ipv4Addr::UNSPECIFIED,
                    };
                    if tx
                        .send(Packet {
                            ifindex,
                            src,
                            data: buf[..n].to_vec(),
                        })
                        .await
                        .is_err()
                    {
                        return;
                    }
                }
                Err(e) => {
                    warn!(ifindex, error = %e, "PIM: recv error, reader stopping");
                    return;
                }
            }
        }
    });
}

/// Spawn a task reading `igmpmsg` upcalls off the mroute socket into `tx`.
fn spawn_upcall_reader(sock: Arc<UdpSocket>, tx: mpsc::Sender<Upcall>) {
    tokio::spawn(async move {
        let mut buf = vec![0u8; RECV_BUF];
        loop {
            match sock.recv_from(&mut buf).await {
                Ok((n, _)) => {
                    match mroute::parse_upcall(&buf[..n]) {
                        Some(up) => {
                            if tx.send(up).await.is_err() {
                                return;
                            }
                        }
                        None => debug!(
                            len = n,
                            b0 = buf.first().copied().unwrap_or(0),
                            b8 = buf.get(8).copied().unwrap_or(0),
                            "PIM: mroute socket datagram (not an upcall)"
                        ),
                    }
                }
                Err(e) => {
                    warn!(error = %e, "PIM: mroute upcall reader stopping");
                    return;
                }
            }
        }
    });
}

/// A raw IPv4 socket delivers the full datagram including the IP header. Validate it
/// is IPv4/PIM and return the PIM payload slice, or `None` if malformed / not PIM.
fn ipv4_payload(buf: &[u8]) -> Option<&[u8]> {
    if buf.len() < 20 || buf[0] >> 4 != 4 {
        return None;
    }
    let ihl = (buf[0] & 0x0f) as usize * 4;
    if ihl < 20 || buf.len() < ihl {
        return None;
    }
    if buf[9] != PIM_PROTO {
        return None;
    }
    Some(&buf[ihl..])
}

/// A monotonically-varying Generation ID for our Hellos (changes each process start).
fn generation_id() -> u32 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.subsec_nanos() ^ (d.as_secs() as u32))
        .unwrap_or(0x5eed_1234)
}

/// Open a raw IP-protocol-103 socket bound to `ifname`, joined to ALL-PIM-ROUTERS
/// (`224.0.0.13`) with multicast egress pinned to it and TTL 1. Needs `CAP_NET_RAW`.
fn open_pim_socket(ifname: &str) -> Result<(u32, UdpSocket)> {
    let cname = CString::new(ifname).context("interface name has an interior NUL")?;
    // SAFETY: `cname` is a valid C string for the duration of the call.
    let ifindex = unsafe { libc::if_nametoindex(cname.as_ptr()) };
    if ifindex == 0 {
        anyhow::bail!("interface {ifname:?} not found");
    }
    // SAFETY: a raw socket; the fd is taken into ownership immediately below.
    let fd = unsafe {
        libc::socket(
            libc::AF_INET,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
            PIM_PROTO as i32,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error())
            .context("socket(SOCK_RAW, IPPROTO_PIM) — needs CAP_NET_RAW");
    }
    // SAFETY: `fd` was just returned by socket() and is owned by nobody else.
    let sock = unsafe { std::net::UdpSocket::from_raw_fd(fd) };

    bind_to_device(fd, ifname)?;

    // Pin multicast egress to this interface and set TTL 1.
    // SAFETY: ip_mreqn is plain POD; only the interface index matters here.
    let mut ifreq: libc::ip_mreqn = unsafe { mem::zeroed() };
    ifreq.imr_ifindex = ifindex as libc::c_int;
    setsockopt_struct(fd, libc::IPPROTO_IP, libc::IP_MULTICAST_IF, &ifreq)
        .context("IP_MULTICAST_IF")?;
    setsockopt_int(fd, libc::IPPROTO_IP, libc::IP_MULTICAST_LOOP, 0)?;
    setsockopt_int(fd, libc::IPPROTO_IP, libc::IP_MULTICAST_TTL, PIM_TTL)?;
    setsockopt_int(fd, libc::IPPROTO_IP, libc::IP_TTL, PIM_TTL)?;

    // Join ALL-PIM-ROUTERS so we hear neighbours' Hellos and Join/Prunes.
    // SAFETY: ip_mreqn is plain POD; we set the group and interface index.
    let mut mreq: libc::ip_mreqn = unsafe { mem::zeroed() };
    mreq.imr_multiaddr.s_addr = u32::from(ALL_PIM_ROUTERS).to_be();
    mreq.imr_ifindex = ifindex as libc::c_int;
    setsockopt_struct(fd, libc::IPPROTO_IP, libc::IP_ADD_MEMBERSHIP, &mreq)
        .with_context(|| format!("IP_ADD_MEMBERSHIP {ALL_PIM_ROUTERS}"))?;

    sock.set_nonblocking(true).context("set_nonblocking")?;
    let sock = UdpSocket::from_std(sock).context("tokio UdpSocket::from_std")?;
    Ok((ifindex, sock))
}

/// `SO_BINDTODEVICE ifname` on `fd`.
fn bind_to_device(fd: i32, ifname: &str) -> Result<()> {
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
            .with_context(|| format!("SO_BINDTODEVICE {ifname:?}"));
    }
    Ok(())
}

/// The first usable IPv4 address of `ifname`, via `getifaddrs`.
fn iface_ipv4(ifname: &str) -> Option<Ipv4Addr> {
    all_ifaddrs()
        .into_iter()
        .find(|(name, _)| name == ifname)
        .map(|(_, addr)| addr)
}

/// Every non-loopback IPv4 address on the host (used to recognise a *local* RPF
/// destination — the RP being ourselves, or a directly-attached source).
fn all_local_ipv4() -> Vec<Ipv4Addr> {
    all_ifaddrs().into_iter().map(|(_, a)| a).collect()
}

/// `(ifname, ipv4)` for every non-loopback, non-unspecified IPv4 interface address.
fn all_ifaddrs() -> Vec<(String, Ipv4Addr)> {
    let mut head: *mut libc::ifaddrs = std::ptr::null_mut();
    // SAFETY: getifaddrs allocates a linked list into `head`, freed below.
    if unsafe { libc::getifaddrs(&mut head) } != 0 {
        return Vec::new();
    }
    let mut out = Vec::new();
    let mut cur = head;
    while !cur.is_null() {
        // SAFETY: `cur` is a non-null node in the kernel-provided list.
        let node = unsafe { &*cur };
        if !node.ifa_addr.is_null() {
            // SAFETY: ifa_addr points at a sockaddr; ifa_name is a valid C string.
            let fam = unsafe { (*node.ifa_addr).sa_family } as i32;
            if fam == libc::AF_INET {
                // SAFETY: an AF_INET sockaddr is a sockaddr_in.
                let sin = unsafe { &*(node.ifa_addr as *const libc::sockaddr_in) };
                let ip = Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr));
                if !ip.is_loopback() && !ip.is_unspecified() {
                    // SAFETY: ifa_name is a valid C string.
                    let name = unsafe { std::ffi::CStr::from_ptr(node.ifa_name) }
                        .to_string_lossy()
                        .into_owned();
                    out.push((name, ip));
                }
            }
        }
        cur = node.ifa_next;
    }
    // SAFETY: freeing the list getifaddrs allocated.
    unsafe { libc::freeifaddrs(head) };
    out
}

/// A longest-prefix-match lookup of `dest` in the kernel IPv4 main route table via
/// `/proc/net/route`, returning `(egress-ifname, gateway)` — the RPF interface and
/// next-hop. A gateway of `0.0.0.0` means `dest` is directly connected.
fn longest_prefix_route(dest: Ipv4Addr) -> Option<(String, Ipv4Addr)> {
    let table = std::fs::read_to_string("/proc/net/route").ok()?;
    let d = u32::from(dest);
    let mut best: Option<(String, Ipv4Addr, u32)> = None; // (iface, gw, masklen)
    for line in table.lines().skip(1) {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 8 {
            continue;
        }
        let iface = f[0];
        let network = parse_proc_route_addr(f[1])?;
        let gateway = parse_proc_route_addr(f[2])?;
        let mask = parse_proc_route_addr(f[7])?;
        let mask_u = u32::from(mask);
        if (d & mask_u) == (u32::from(network) & mask_u) {
            let masklen = mask_u.count_ones();
            if best.as_ref().map(|(_, _, m)| masklen >= *m).unwrap_or(true) {
                best = Some((iface.to_string(), gateway, masklen));
            }
        }
    }
    best.map(|(iface, gw, _)| (iface, gw))
}

/// Parse a `/proc/net/route` address field — a little-endian hex of the 32-bit
/// address — into an [`Ipv4Addr`].
fn parse_proc_route_addr(hex: &str) -> Option<Ipv4Addr> {
    let v = u32::from_str_radix(hex, 16).ok()?;
    Some(Ipv4Addr::from(v.swap_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_proc_route_little_endian_address() {
        // "0102000A" little-endian = 10.0.2.1.
        assert_eq!(
            parse_proc_route_addr("0102000A"),
            Some(Ipv4Addr::new(10, 0, 2, 1))
        );
        // The default route destination / a zero mask is 0.0.0.0.
        assert_eq!(
            parse_proc_route_addr("00000000"),
            Some(Ipv4Addr::UNSPECIFIED)
        );
    }

    #[test]
    fn jp_source_maps_wildcard_and_source() {
        assert_eq!(
            jp_source(&EncodedSource::wildcard_rp(Ipv4Addr::new(10, 0, 9, 9))),
            None
        );
        assert_eq!(
            jp_source(&EncodedSource::source(Ipv4Addr::new(10, 1, 1, 1))),
            Some(Ipv4Addr::new(10, 1, 1, 1))
        );
    }
}
