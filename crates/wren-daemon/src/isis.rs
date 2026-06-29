//! # The IS-IS socket runner (ISO/IEC 10589, RFC 1195)
//!
//! The async transport that turns the pure `wren-isis` library (PDU/TLV codec,
//! the link-state database, the adjacency FSM, the DIS election and the §7.2 SPF)
//! into a live IS-IS speaker. Every protocol *decision* lives in the library; this
//! module does the I/O and sequencing the library cannot — and it is Wren's
//! **first layer-2 runner**: IS-IS rides directly on the data link, not on IP.
//!
//! * One `AF_PACKET`/`SOCK_DGRAM` socket **per interface**, bound to the interface
//!   and joined to the two IS-IS multicast MACs `AllL1ISs`/`AllL2ISs` via
//!   `PACKET_ADD_MEMBERSHIP`. Frames are IEEE 802.2 LLC (DSAP = SSAP = `0xFE`,
//!   control = `0x03`) carrying the IS-IS PDU; the kernel adds/strips the 802.3 MAC
//!   header for us (`SOCK_DGRAM`), and a received frame's source MAC is the
//!   neighbour's SNPA.
//! * Periodic Hellos drive neighbour discovery through the three-state adjacency
//!   FSM (`Down → Initializing → Up`), and on a LAN the §8.4.5 DIS election.
//! * This router originates its own LSP — area address, supported protocols,
//!   interface addresses, IS reachability (to the LAN pseudonode or the p2p
//!   neighbour) and the connected IP prefixes — and (as DIS) the pseudonode LSP,
//!   flooding both.
//! * CSNP/PSNP reconcile the databases (the library's `evaluate_csnp` decides what
//!   to request and what to send), the §7.2 SPF runs per level, and the resulting
//!   routes are announced to the central router (RIB).
//!
//! `AF_PACKET` needs `CAP_NET_RAW`; the `unshare -Urn` netns used to smoke-test
//! the other runners grants it.
//!
//! **Scope.** This is a working dual-stack single-area speaker (broadcast and
//! point-to-point, L1/L2). Deliberately left for later, all without reshaping this
//! code: the point-to-point three-way-handshake TLV (p2p adjacencies come up
//! classic two-way here), SRM/SSN retransmit lists (flooding is reflood-on-change
//! plus periodic CSNP reconciliation), LSP fragmentation (one fragment per node),
//! and L1↔L2 route leaking beyond the attached-bit default the SPF already emits.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::ffi::{CStr, CString};
use std::fmt::Write as _;
use std::io;
use std::mem;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::fd::{AsRawFd, RawFd};
use std::ptr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use tokio::io::unix::AsyncFd;
use tokio::sync::{mpsc, oneshot};
use tokio::time::MissedTickBehavior;
use tracing::{debug, info, warn};

use wren_core::{NextHop, Prefix, Protocol, Route};
use wren_isis::adjacency::AdjEvent;
use wren_isis::adjacency::{AdjState, Adjacency};
use wren_isis::dis::{elect_dis, DisCandidate};
use wren_isis::lsdb::Lsdb;
use wren_isis::pdu::{Csnp, LanHello, Lsp, P2pHello, Pdu, PduBody, Psnp};
use wren_isis::spf;
use wren_isis::tlv::{ExtIpReach, ExtIsReach, Ipv6Reach, LspEntry, Tlv};
use wren_isis::{
    AreaAddress, IsLevel, LspId, SystemId, ALL_L1_ISS, ALL_L2_ISS, LLC_CONTROL, LLC_SAP,
    NLPID_IPV4, NLPID_IPV6,
};

use crate::connected;
use crate::sockopt::setsockopt_struct;
use crate::router::{Redistribution, RouteUpdate};

/// The lifetime stamped on an originated LSP (seconds). Refreshed before expiry.
const LSP_LIFETIME: u16 = 1200;
/// Re-originate our LSPs once their remaining lifetime drops below this.
const LSP_REFRESH_BELOW: u16 = 300;
/// How often (seconds) the housekeeping timer ages the database and the holding
/// timers, and re-runs the SPF.
const HOUSEKEEPING_SECS: u64 = 1;
/// How often the DIS sends a CSNP describing its database (seconds).
const CSNP_SECS: u64 = 10;
/// Receive buffer; an IS-IS PDU fits comfortably in a link MTU.
const RECV_BUF: usize = 9000;

/// `ETH_P_802_2` — the AF_PACKET protocol selecting 802.2 LLC frames.
const ETH_P_802_2: u16 = 0x0004;

/// An IS-IS interface's link type.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum IfaceType {
    /// A multi-access LAN that elects a Designated IS.
    Broadcast,
    /// A direct link to a single neighbour (no DIS).
    PointToPoint,
}

/// One configured IS-IS interface.
pub struct IsisIfaceCfg {
    /// The interface name.
    pub name: String,
    /// Its link type.
    pub iface_type: IfaceType,
}

/// The resolved IS-IS configuration for a run.
pub struct IsisConfig {
    /// This router's 6-byte System ID.
    pub system_id: SystemId,
    /// The area this router belongs to.
    pub area: AreaAddress,
    /// The level(s) this router runs (L1 intra-area, L2 backbone, or both).
    pub level: IsLevel,
    /// This router's DIS-election priority.
    pub priority: u8,
    /// The metric advertised for each interface's links.
    pub metric: u32,
    /// The metric advertised for routes redistributed from the RIB (their IP/IPv6
    /// reachability TLVs). Defaults to the interface metric when unset upstream.
    pub redistribute_metric: u32,
    /// HelloInterval in seconds.
    pub hello_interval: u64,
    /// The holding-time multiplier (HoldingTime = hello_interval × this).
    pub holding_multiplier: u16,
    /// The interfaces IS-IS runs on.
    pub interfaces: Vec<IsisIfaceCfg>,
    /// Run BFD (RFC 5880) to each neighbour with an up adjacency and tear the
    /// adjacency down at once when BFD reports the path failed (RFC 5882).
    pub bfd: bool,
}

/// Map a single level to its database / per-neighbour-array index.
fn lidx(level: IsLevel) -> usize {
    if matches!(level, IsLevel::L2) {
        1
    } else {
        0
    }
}

/// The multicast MAC a PDU of `level` is sent to.
fn level_mac(level: IsLevel) -> [u8; 6] {
    if level.has_l2() && !level.has_l1() {
        ALL_L2_ISS
    } else {
        ALL_L1_ISS
    }
}

/// Build the 7-byte node ID (System ID + pseudonode number) used in TLV 22.
fn node_id(sys: SystemId, pseudonode: u8) -> [u8; 7] {
    let mut n = [0u8; 7];
    n[..6].copy_from_slice(&sys.0);
    n[6] = pseudonode;
    n
}

/// A neighbour on one interface: its per-level adjacency FSMs plus runtime facts.
struct Nbr {
    snpa: [u8; 6],
    priority: u8,
    last_seen: u64,
    holding: u16,
    /// The adjacency FSM per level (`[L1, L2]`), present once a Hello is seen.
    adj: [Option<Adjacency>; 2],
    /// The LAN ID (DIS System ID + pseudonode) the neighbour advertised, per level.
    lan_id: [Option<(SystemId, u8)>; 2],
    /// The neighbour's IP address for BFD, learned from the IP Interface Address TLV
    /// in its Hellos (TLV 132 for IPv4, 232 for IPv6), and the interface scope for an
    /// IPv6 link-local one. `None` until a usable address is heard. IS-IS adjacencies
    /// are over SNPA/MAC, so this is the only place a neighbour IP appears.
    bfd_addr: Option<(IpAddr, u32)>,
}

impl Nbr {
    fn new(snpa: [u8; 6], holding: u16) -> Self {
        Nbr {
            snpa,
            priority: 0,
            last_seen: 0,
            holding,
            adj: [None, None],
            lan_id: [None, None],
            bfd_addr: None,
        }
    }

    fn up(&self, lidx: usize) -> bool {
        self.adj[lidx].as_ref().is_some_and(|a| a.is_up())
    }

    /// Whether this neighbour has an up adjacency at any level.
    fn up_any(&self) -> bool {
        self.up(0) || self.up(1)
    }
}

/// One IS-IS-speaking interface and its per-interface state.
struct Iface {
    name: String,
    ifindex: u32,
    snpa: [u8; 6],
    iface_type: IfaceType,
    /// This circuit's local ID, used as the pseudonode number when we are the DIS.
    local_circuit_id: u8,
    sock: Arc<PacketSock>,
    v4: Vec<Ipv4Addr>,
    v6: Vec<Ipv6Addr>,
    neighbors: HashMap<SystemId, Nbr>,
    /// The elected LAN ID (DIS System ID + pseudonode) per level.
    dis: [Option<(SystemId, u8)>; 2],
    /// Whether we are the DIS per level.
    is_dis: [bool; 2],
    /// The pseudonode LSP sequence number we have originated, per level.
    pn_seq: [u32; 2],
}

/// The central IS-IS state, owned by one task.
struct Isis {
    cfg: IsisConfig,
    ifaces: Vec<Iface>,
    /// The link-state database per level (`[L1, L2]`).
    dbs: [Lsdb; 2],
    /// The sequence number of our own (non-pseudonode) LSP, per level.
    own_seq: [u32; 2],
    /// Our connected IPv4/IPv6 prefixes (advertised as IP reachability; also
    /// announced to the RIB as `Connected`, so they are filtered from SPF output).
    v4_reach: Vec<Prefix>,
    v6_reach: Vec<Prefix>,
    /// Routes redistributed from the RIB (other protocols), advertised as IP/IPv6
    /// reachability in our own LSP at their stored metric. Prefix → metric.
    ext_v4: BTreeMap<Prefix, u32>,
    ext_v6: BTreeMap<Prefix, u32>,
    /// The prefixes currently announced to the router, for withdraw reconciliation.
    announced: HashSet<Prefix>,
    updates: mpsc::Sender<RouteUpdate>,
    /// BFD (RFC 5880): the channel to the BFD engine to register/deregister
    /// per-neighbour sessions, the notify sender included in each registration (the
    /// engine reports a session going down on it), and the set of `(address, scope)`
    /// pairs currently registered (the neighbours with an up adjacency that advertise
    /// an IP). Unused when `cfg.bfd` is false.
    bfd_register: mpsc::Sender<crate::bfd::BfdCommand>,
    bfd_notify: mpsc::Sender<IpAddr>,
    bfd_registered: HashSet<(IpAddr, u32)>,
}

/// A frame received on one interface, handed to the central task.
struct RxFrame {
    idx: usize,
    src: [u8; 6],
    data: Vec<u8>,
}

/// A `show isis …` query, answered by the IS-IS task itself out of the state it
/// owns (its interfaces, their per-level adjacencies and the DIS election).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum IsisQuery {
    /// The adjacencies on every interface, per level, with their state.
    Neighbors,
    /// The IS-IS interfaces, with their type, level and elected DIS.
    Interfaces,
    /// The link-state database — every LSP held, per level.
    Database,
}

/// A control-socket query plus the channel to answer it on.
pub struct IsisQueryRequest {
    /// What to report.
    pub query: IsisQuery,
    /// Where to send the rendered answer.
    pub respond: oneshot::Sender<String>,
}

/// One adjacency (a neighbour at one level), snapshotted for the (pure) renderer.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct IsisNeighborInfo {
    /// The neighbour's System ID.
    pub system_id: SystemId,
    /// The neighbour's SNPA (its MAC on a LAN).
    pub snpa: [u8; 6],
    /// The local interface the neighbour is on.
    pub iface: String,
    /// The level this adjacency runs at (1 or 2).
    pub level: u8,
    /// The adjacency state.
    pub state: AdjState,
}

/// One IS-IS interface, snapshotted for the (pure) renderer.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct IsisIfaceInfo {
    /// The interface name.
    pub name: String,
    /// Whether the circuit is a LAN or a point-to-point link.
    pub iface_type: IfaceType,
    /// The level(s) the circuit runs.
    pub level: IsLevel,
    /// The elected DIS LAN ID per level (`[L1, L2]`), and whether it is us.
    pub dis: [Option<(SystemId, u8)>; 2],
    /// Whether this router is the DIS, per level (`[L1, L2]`).
    pub is_dis: [bool; 2],
}

/// One LSP held in the link-state database, snapshotted for the (pure) renderer.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct IsisLspInfo {
    /// The level whose database holds this LSP (1 or 2).
    pub level: u8,
    /// The LSP's identifier (system-id.pseudonode-fragment).
    pub lsp_id: LspId,
    /// The LSP's sequence number (higher is newer).
    pub seq: u32,
    /// The LSP's Fletcher checksum.
    pub checksum: u16,
    /// Remaining lifetime in seconds (0 == purged/expired).
    pub lifetime: u16,
    /// The 4-bit ATT (attached) flags — non-zero on an L1L2 router drawing a
    /// default route towards the backbone.
    pub attached: u8,
    /// The Partition-Repair bit.
    pub partition: bool,
    /// The LSP Database Overload bit.
    pub overload: bool,
}

/// The short name of an adjacency state, as shown by `show isis neighbors`.
fn adj_state_name(s: AdjState) -> &'static str {
    match s {
        AdjState::Down => "Down",
        AdjState::Initializing => "Init",
        AdjState::Up => "Up",
    }
}

/// The short name of a level set, as shown by `show isis interfaces`.
fn level_name(l: IsLevel) -> &'static str {
    match l {
        IsLevel::L1 => "l1",
        IsLevel::L2 => "l2",
        IsLevel::L1L2 => "l1l2",
    }
}

/// Render the IS-IS adjacencies, one per line (à la `show isis neighbor`).
pub fn render_isis_neighbors(neighbors: &[IsisNeighborInfo]) -> String {
    if neighbors.is_empty() {
        return "no isis adjacencies\n".to_string();
    }
    let mut out = String::new();
    for n in neighbors {
        let _ = writeln!(
            out,
            "{} via {} dev {} level {} state {}",
            n.system_id,
            mac_str(&n.snpa),
            n.iface,
            n.level,
            adj_state_name(n.state),
        );
    }
    out
}

/// Render the IS-IS interfaces, one per line (à la `show isis interface`).
pub fn render_isis_interfaces(ifaces: &[IsisIfaceInfo]) -> String {
    if ifaces.is_empty() {
        return "no isis interfaces\n".to_string();
    }
    let kind = |t: IfaceType| match t {
        IfaceType::Broadcast => "broadcast",
        IfaceType::PointToPoint => "point-to-point",
    };
    let mut out = String::new();
    for i in ifaces {
        let _ = write!(
            out,
            "{} type {} level {}",
            i.name,
            kind(i.iface_type),
            level_name(i.level),
        );
        // The DIS only exists on a broadcast circuit; show it per active level.
        for (lidx, level_no) in [(0usize, 1u8), (1usize, 2u8)] {
            if let Some((sys, pn)) = i.dis[lidx] {
                let me = if i.is_dis[lidx] { " (self)" } else { "" };
                let _ = write!(out, " dis-l{level_no} {sys}.{pn:02}{me}");
            }
        }
        out.push('\n');
    }
    out
}

/// Render the link-state database, one LSP per line (à la `show isis database`).
/// The `att/p/ol` column mirrors FRR/Cisco: the Attached, Partition and Overload
/// bits. The ATT field shows `1` when any of the four attached-metric flags is set.
pub fn render_isis_database(lsps: &[IsisLspInfo]) -> String {
    if lsps.is_empty() {
        return "no isis lsps\n".to_string();
    }
    let mut out = String::new();
    for l in lsps {
        let att = u8::from(l.attached != 0);
        let p = u8::from(l.partition);
        let ol = u8::from(l.overload);
        let _ = writeln!(
            out,
            "level {} lsp {} seq {:#010x} chksum {:#06x} lifetime {} att/p/ol {}/{}/{}",
            l.level, l.lsp_id, l.seq, l.checksum, l.lifetime, att, p, ol,
        );
    }
    out
}

/// Run IS-IS with `cfg`, forwarding learned routes to `updates`. Returns when a
/// socket error tears the runner down; otherwise runs until cancelled.
///
/// `redist` carries RIB best-path routes the central router pushes for
/// redistribution; IS-IS advertises each (as Extended-IP / IPv6 reachability in
/// its own LSP, at `cfg.redistribute_metric`) and removes it again when its best
/// path goes away, re-originating and flooding the LSP on each change. `queries`
/// carries the operator's `show isis …` requests, answered out of the live state.
pub async fn run(
    cfg: IsisConfig,
    updates: mpsc::Sender<RouteUpdate>,
    mut redist: mpsc::Receiver<Redistribution>,
    mut queries: mpsc::Receiver<IsisQueryRequest>,
    bfd_register: mpsc::Sender<crate::bfd::BfdCommand>,
    bfd_notify: mpsc::Sender<IpAddr>,
    mut bfd_down: mpsc::Receiver<IpAddr>,
) -> Result<()> {
    let mut ifaces = Vec::with_capacity(cfg.interfaces.len());
    for (i, ic) in cfg.interfaces.iter().enumerate() {
        let (ifindex, snpa, sock) = open_isis_socket(&ic.name)
            .with_context(|| format!("opening IS-IS socket on {:?}", ic.name))?;
        let (v4, v6) = iface_ips(&ic.name);
        info!(interface = %ic.name, ifindex, snpa = %mac_str(&snpa), "IS-IS listening (802.2 LLC)");
        ifaces.push(Iface {
            name: ic.name.clone(),
            ifindex,
            snpa,
            iface_type: ic.iface_type,
            local_circuit_id: (i as u8) + 1,
            sock: Arc::new(sock),
            v4,
            v6,
            neighbors: HashMap::new(),
            dis: [None, None],
            is_dis: [false, false],
            pn_seq: [0, 0],
        });
    }
    if ifaces.is_empty() {
        warn!("IS-IS is enabled but no interfaces are configured — nothing to do");
        return Ok(());
    }

    // One receiver task per interface funnels frames into a single channel so the
    // central task below is the sole owner of the databases.
    let (tx, mut rx) = mpsc::channel::<RxFrame>(256);
    for (idx, iface) in ifaces.iter().enumerate() {
        spawn_receiver(idx, iface.sock.clone(), tx.clone());
    }
    drop(tx);

    // Discover our connected networks: advertise them as IP reachability and
    // register them in the RIB as Connected (the kernel already owns them).
    let names: Vec<String> = cfg.interfaces.iter().map(|i| i.name.clone()).collect();
    let mut v4_reach = Vec::new();
    let mut v6_reach = Vec::new();
    for net in connected::discover(&names) {
        info!(prefix = %net.prefix, interface = %net.ifname, "IS-IS advertising connected network");
        let route = Route::new(
            net.prefix,
            Protocol::Connected,
            vec![NextHop::dev(net.ifname)],
            0,
        );
        let _ = updates.send(RouteUpdate::Announce(route)).await;
        if net.prefix.is_ipv4() {
            v4_reach.push(net.prefix);
        } else {
            v6_reach.push(net.prefix);
        }
    }

    let mut isis = Isis {
        cfg,
        ifaces,
        dbs: [Lsdb::new(), Lsdb::new()],
        own_seq: [0, 0],
        v4_reach,
        v6_reach,
        ext_v4: BTreeMap::new(),
        ext_v6: BTreeMap::new(),
        announced: HashSet::new(),
        updates,
        bfd_register,
        bfd_notify,
        bfd_registered: HashSet::new(),
    };

    // Originate our initial LSP(s) and send the first Hellos.
    for level in isis.active_levels() {
        isis.reoriginate(level).await;
    }
    isis.send_hellos().await;

    let start = Instant::now();
    let mut hello = tokio::time::interval(Duration::from_secs(isis.cfg.hello_interval));
    hello.set_missed_tick_behavior(MissedTickBehavior::Delay);
    let mut csnp = tokio::time::interval(Duration::from_secs(CSNP_SECS));
    csnp.set_missed_tick_behavior(MissedTickBehavior::Delay);
    let mut house = tokio::time::interval(Duration::from_secs(HOUSEKEEPING_SECS));
    house.set_missed_tick_behavior(MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            frame = rx.recv() => {
                let Some(frame) = frame else { return Ok(()) };
                isis.handle_frame(frame, start.elapsed().as_secs()).await;
            }
            _ = hello.tick() => isis.send_hellos().await,
            _ = csnp.tick() => isis.send_csnps().await,
            _ = house.tick() => {
                isis.housekeeping(start.elapsed().as_secs()).await;
                isis.run_spf_and_announce().await;
            }
            Some(r) = redist.recv() => isis.apply_redistribution(r).await,
            Some(req) = queries.recv() => {
                let answer = match req.query {
                    IsisQuery::Neighbors => render_isis_neighbors(&isis.neighbor_infos()),
                    IsisQuery::Interfaces => render_isis_interfaces(&isis.iface_infos()),
                    IsisQuery::Database => render_isis_database(&isis.lsp_infos()),
                };
                let _ = req.respond.send(answer);
            }
            // BFD (RFC 5880) reported a neighbour's forwarding path down: tear that
            // adjacency down at once (RFC 5882 §4.4), exactly as a holding-time
            // expiry would, instead of waiting for the holding time.
            Some(peer) = bfd_down.recv() => isis.force_neighbor_down(peer).await,
        }
        // Keep the set of registered BFD sessions in step with the up adjacencies
        // (a no-op when `[isis] bfd` is off).
        isis.reconcile_bfd().await;
    }
}

impl Isis {
    /// Snapshot every adjacency (neighbour × active level), for `show isis
    /// neighbors`. Sorted by (interface, System ID, level) for a stable listing.
    fn neighbor_infos(&self) -> Vec<IsisNeighborInfo> {
        let mut out = Vec::new();
        for iface in &self.ifaces {
            let mut ids: Vec<&SystemId> = iface.neighbors.keys().collect();
            ids.sort_by_key(|id| id.0);
            for id in ids {
                let n = &iface.neighbors[id];
                for (lidx, level_no) in [(0usize, 1u8), (1usize, 2u8)] {
                    if let Some(adj) = &n.adj[lidx] {
                        out.push(IsisNeighborInfo {
                            system_id: *id,
                            snpa: n.snpa,
                            iface: iface.name.clone(),
                            level: level_no,
                            state: adj.state,
                        });
                    }
                }
            }
        }
        out
    }

    /// Snapshot every IS-IS interface, for `show isis interfaces`.
    fn iface_infos(&self) -> Vec<IsisIfaceInfo> {
        self.ifaces
            .iter()
            .map(|iface| IsisIfaceInfo {
                name: iface.name.clone(),
                iface_type: iface.iface_type,
                level: self.cfg.level,
                dis: iface.dis,
                is_dis: iface.is_dis,
            })
            .collect()
    }

    /// Snapshot every LSP in every active level's database, for `show isis
    /// database`. Ordered by (level, LSP ID) for a stable listing.
    fn lsp_infos(&self) -> Vec<IsisLspInfo> {
        let mut out = Vec::new();
        for level in self.active_levels() {
            let lidx = match level {
                IsLevel::L1 => 0,
                IsLevel::L2 => 1,
                IsLevel::L1L2 => continue, // active_levels() never yields L1L2
            };
            let level_no = lidx as u8 + 1;
            let mut lsps: Vec<&Lsp> = self.dbs[lidx].iter().collect();
            lsps.sort_by_key(|lsp| lsp.lsp_id);
            for lsp in lsps {
                out.push(IsisLspInfo {
                    level: level_no,
                    lsp_id: lsp.lsp_id,
                    seq: lsp.sequence_number,
                    checksum: lsp.checksum,
                    lifetime: lsp.remaining_lifetime,
                    attached: lsp.attached,
                    partition: lsp.partition,
                    overload: lsp.overload,
                });
            }
        }
        out
    }

    /// The levels this router runs.
    fn active_levels(&self) -> Vec<IsLevel> {
        match self.cfg.level {
            IsLevel::L1 => vec![IsLevel::L1],
            IsLevel::L2 => vec![IsLevel::L2],
            IsLevel::L1L2 => vec![IsLevel::L1, IsLevel::L2],
        }
    }

    /// Whether we have at least one Up Level-2 adjacency (drives the ATT bit).
    fn have_l2_adjacency(&self) -> bool {
        self.ifaces
            .iter()
            .any(|f| f.neighbors.values().any(|n| n.up(1)))
    }

    // --- frame dispatch ----------------------------------------------------

    async fn handle_frame(&mut self, frame: RxFrame, now: u64) {
        // Ignore our own looped-back transmissions (AF_PACKET delivers them too).
        if frame.src == self.ifaces[frame.idx].snpa {
            return;
        }
        let Some(pdu_bytes) = strip_llc(&frame.data) else {
            return;
        };
        let pdu = match Pdu::decode(pdu_bytes) {
            Ok(p) => p,
            Err(e) => {
                debug!(error = %e, "dropping malformed IS-IS PDU");
                return;
            }
        };
        match pdu.body {
            PduBody::LanHello(h) => self.process_lan_hello(frame.idx, h, frame.src, now).await,
            PduBody::P2pHello(h) => self.process_p2p_hello(frame.idx, h, frame.src, now).await,
            PduBody::Lsp(l) => self.process_lsp(frame.idx, l, pdu_bytes).await,
            PduBody::Csnp(c) => self.process_csnp(frame.idx, c).await,
            PduBody::Psnp(p) => self.process_psnp(frame.idx, p).await,
        }
    }

    async fn process_lan_hello(&mut self, idx: usize, h: LanHello, src: [u8; 6], now: u64) {
        let level = h.level;
        if !self.cfg.level_active(level) {
            return;
        }
        // Level-1 adjacencies require a matching area address.
        if level == IsLevel::L1 && !area_addresses(&h.tlvs).contains(&self.cfg.area) {
            return;
        }
        let li = lidx(level);
        let our_snpa = self.ifaces[idx].snpa;
        let lists_us = lan_neighbors(&h.tlvs).contains(&our_snpa);
        let event = if lists_us {
            AdjEvent::HelloTwoWay
        } else {
            AdjEvent::HelloOneWay
        };

        let holding = h.holding_time;
        let bfd_addr = neighbor_bfd_addr(&h.tlvs, self.ifaces[idx].ifindex);
        let changed = {
            let iface = &mut self.ifaces[idx];
            let nbr = iface
                .neighbors
                .entry(h.source_id)
                .or_insert_with(|| Nbr::new(src, holding));
            nbr.snpa = src;
            nbr.priority = h.priority;
            nbr.last_seen = now;
            nbr.holding = holding;
            if bfd_addr.is_some() {
                nbr.bfd_addr = bfd_addr;
            }
            nbr.lan_id[li] = Some((h.lan_id.0, h.lan_id.1));
            let adj = nbr.adj[li].get_or_insert_with(|| Adjacency::new(h.source_id, level));
            let was_up = adj.is_up();
            adj.handle(event);
            was_up != adj.is_up()
        };

        if changed {
            self.run_dis(idx, level).await;
            self.reoriginate(level).await;
        }
    }

    async fn process_p2p_hello(&mut self, idx: usize, h: P2pHello, src: [u8; 6], now: u64) {
        let holding = h.holding_time;
        let bfd_addr = neighbor_bfd_addr(&h.tlvs, self.ifaces[idx].ifindex);
        let mut changed_levels = Vec::new();
        for level in self.active_levels() {
            if !h.circuit_type.level_active(level) {
                continue;
            }
            if level == IsLevel::L1 && !area_addresses(&h.tlvs).contains(&self.cfg.area) {
                continue;
            }
            let li = lidx(level);
            let iface = &mut self.ifaces[idx];
            let nbr = iface
                .neighbors
                .entry(h.source_id)
                .or_insert_with(|| Nbr::new(src, holding));
            nbr.snpa = src;
            nbr.last_seen = now;
            nbr.holding = holding;
            if bfd_addr.is_some() {
                nbr.bfd_addr = bfd_addr;
            }
            // A point-to-point link comes up classic two-way (the RFC 5303 three-way
            // TLV is a later refinement).
            let adj = nbr.adj[li].get_or_insert_with(|| Adjacency::new(h.source_id, level));
            let was_up = adj.is_up();
            adj.handle(AdjEvent::HelloTwoWay);
            if was_up != adj.is_up() {
                changed_levels.push(level);
            }
        }
        for level in changed_levels {
            self.reoriginate(level).await;
        }
    }

    async fn process_lsp(&mut self, idx: usize, lsp: Lsp, raw: &[u8]) {
        let level = lsp.level;
        if !self.cfg.level_active(level) {
            return;
        }
        let li = lidx(level);
        if self.dbs[li].install(lsp).changed() {
            // Flood the new LSP out of every other interface running this level.
            self.flood(level, raw, Some(idx)).await;
        }
    }

    async fn process_csnp(&mut self, idx: usize, csnp: Csnp) {
        let level = csnp.level;
        if !self.cfg.level_active(level) {
            return;
        }
        let li = lidx(level);
        let entries = lsp_entries(&csnp.tlvs);
        let sync = self.dbs[li].evaluate_csnp(&entries, csnp.start_lsp_id, csnp.end_lsp_id);
        // Send any LSP the sender lacks or holds an older copy of.
        for id in &sync.send {
            if let Some(lsp) = self.dbs[li].get(id) {
                let bytes = Pdu {
                    max_area_addresses: 0,
                    body: PduBody::Lsp(lsp.clone()),
                }
                .encode();
                self.send_on(idx, level, &bytes).await;
            }
        }
        // Request the LSPs we are missing or hold an older copy of, via a PSNP.
        if !sync.request.is_empty() {
            let psnp = self.build_psnp(level, &sync.request);
            self.send_on(idx, level, &psnp).await;
        }
    }

    async fn process_psnp(&mut self, idx: usize, psnp: Psnp) {
        let level = psnp.level;
        if !self.cfg.level_active(level) {
            return;
        }
        let li = lidx(level);
        // Treat every listed entry as a request: send the LSP if we hold it.
        for entry in lsp_entries(&psnp.tlvs) {
            if let Some(lsp) = self.dbs[li].get(&entry.lsp_id) {
                let bytes = Pdu {
                    max_area_addresses: 0,
                    body: PduBody::Lsp(lsp.clone()),
                }
                .encode();
                self.send_on(idx, level, &bytes).await;
            }
        }
    }

    // --- DIS election ------------------------------------------------------

    /// Run the LAN DIS election for `(idx, level)` and re-originate the pseudonode
    /// LSP if our role changed (point-to-point interfaces have no DIS).
    async fn run_dis(&mut self, idx: usize, level: IsLevel) {
        if self.ifaces[idx].iface_type != IfaceType::Broadcast {
            return;
        }
        let li = lidx(level);
        let mut cands = vec![DisCandidate::new(
            self.cfg.system_id,
            self.ifaces[idx].snpa,
            self.cfg.priority,
        )];
        let mut any_up = false;
        for (sys, nbr) in &self.ifaces[idx].neighbors {
            if nbr.up(li) {
                any_up = true;
                cands.push(DisCandidate::new(*sys, nbr.snpa, nbr.priority));
            }
        }
        let winner = if any_up { elect_dis(&cands) } else { None };
        let is_dis = winner
            .as_ref()
            .is_some_and(|w| w.system_id == self.cfg.system_id);
        let lan_id = match &winner {
            None => None,
            Some(w) if w.system_id == self.cfg.system_id => {
                Some((self.cfg.system_id, self.ifaces[idx].local_circuit_id))
            }
            Some(w) => self.ifaces[idx]
                .neighbors
                .get(&w.system_id)
                .and_then(|n| n.lan_id[li])
                .or(Some((w.system_id, 0))),
        };

        let changed = self.ifaces[idx].dis[li] != lan_id || self.ifaces[idx].is_dis[li] != is_dis;
        self.ifaces[idx].dis[li] = lan_id;
        self.ifaces[idx].is_dis[li] = is_dis;
        if changed {
            self.reoriginate_pseudonode(idx, level).await;
        }
    }

    // --- redistribution ---------------------------------------------------

    /// Fold a redistribution change from the central router into our originated
    /// reachability: an announced route is advertised in our LSP (Extended-IP for
    /// IPv4, IPv6-Reachability with the external bit for IPv6) at
    /// `cfg.redistribute_metric`; a withdrawal removes it. On any change we
    /// re-originate and flood our LSP for every active level. A prefix we already
    /// advertise as a connected network takes precedence and is left untouched.
    async fn apply_redistribution(&mut self, r: Redistribution) {
        let metric = self.cfg.redistribute_metric;
        let changed = match r {
            Redistribution::Announce(route) => {
                let p = route.prefix;
                if self.v4_reach.contains(&p) || self.v6_reach.contains(&p) {
                    false // our own connected network wins
                } else if p.is_ipv4() {
                    self.ext_v4.insert(p, metric) != Some(metric)
                } else {
                    self.ext_v6.insert(p, metric) != Some(metric)
                }
            }
            Redistribution::Withdraw(prefix) => {
                if prefix.is_ipv4() {
                    self.ext_v4.remove(&prefix).is_some()
                } else {
                    self.ext_v6.remove(&prefix).is_some()
                }
            }
        };
        if changed {
            for level in self.active_levels() {
                self.reoriginate(level).await;
            }
        }
    }

    // --- origination & flooding -------------------------------------------

    /// Re-originate this router's own LSP for `level` and flood it.
    async fn reoriginate(&mut self, level: IsLevel) {
        let li = lidx(level);
        self.own_seq[li] += 1;
        let lsp = self.build_our_lsp(level, self.own_seq[li]);
        self.store_and_flood(level, lsp).await;
    }

    /// As the DIS, re-originate the pseudonode LSP for `(idx, level)`; if we are no
    /// longer the DIS, flush any pseudonode LSP we had originated.
    async fn reoriginate_pseudonode(&mut self, idx: usize, level: IsLevel) {
        let li = lidx(level);
        let pn = self.ifaces[idx].local_circuit_id;
        let pn_id = LspId::new(self.cfg.system_id, pn, 0);
        if self.ifaces[idx].is_dis[li] {
            let mut reach = vec![ExtIsReach {
                neighbor_id: node_id(self.cfg.system_id, 0),
                metric: 0,
                sub_tlvs: vec![],
            }];
            for (sys, nbr) in &self.ifaces[idx].neighbors {
                if nbr.up(li) {
                    reach.push(ExtIsReach {
                        neighbor_id: node_id(*sys, 0),
                        metric: 0,
                        sub_tlvs: vec![],
                    });
                }
            }
            self.ifaces[idx].pn_seq[li] += 1;
            let lsp = Lsp {
                level,
                remaining_lifetime: LSP_LIFETIME,
                lsp_id: pn_id,
                sequence_number: self.ifaces[idx].pn_seq[li],
                checksum: 0,
                partition: false,
                attached: 0,
                overload: false,
                is_type: self.cfg.level,
                tlvs: vec![Tlv::ExtendedIsReachability(reach)],
            };
            self.store_and_flood(level, lsp).await;
        } else if self.dbs[li].contains(&pn_id) {
            self.flush_lsp(level, pn_id).await;
        }
    }

    /// Build this router's own LSP for `level` with sequence number `seq`.
    fn build_our_lsp(&self, level: IsLevel, seq: u32) -> Lsp {
        let li = lidx(level);
        let mut tlvs = vec![
            Tlv::AreaAddresses(vec![self.cfg.area.clone()]),
            Tlv::ProtocolsSupported(vec![NLPID_IPV4, NLPID_IPV6]),
        ];

        let v4: Vec<Ipv4Addr> = self.ifaces.iter().flat_map(|f| f.v4.clone()).collect();
        let v6: Vec<Ipv6Addr> = self.ifaces.iter().flat_map(|f| f.v6.clone()).collect();
        if !v4.is_empty() {
            tlvs.push(Tlv::Ipv4InterfaceAddresses(v4));
        }
        if !v6.is_empty() {
            tlvs.push(Tlv::Ipv6InterfaceAddresses(v6));
        }

        // IS reachability: on a LAN point at the pseudonode; on p2p at the neighbour.
        let mut reach = Vec::new();
        for iface in &self.ifaces {
            match iface.iface_type {
                IfaceType::Broadcast => {
                    if let Some((dis_sys, dis_pn)) = iface.dis[li] {
                        reach.push(ExtIsReach {
                            neighbor_id: node_id(dis_sys, dis_pn),
                            metric: self.cfg.metric,
                            sub_tlvs: vec![],
                        });
                    }
                }
                IfaceType::PointToPoint => {
                    for (sys, nbr) in &iface.neighbors {
                        if nbr.up(li) {
                            reach.push(ExtIsReach {
                                neighbor_id: node_id(*sys, 0),
                                metric: self.cfg.metric,
                                sub_tlvs: vec![],
                            });
                        }
                    }
                }
            }
        }
        if !reach.is_empty() {
            tlvs.push(Tlv::ExtendedIsReachability(reach));
        }

        // IP reachability: our connected prefixes, then any redistributed (external)
        // ones. Redistributed IPv6 prefixes set the external bit (RFC 5308).
        let mut v4r: Vec<ExtIpReach> = self
            .v4_reach
            .iter()
            .map(|p| ExtIpReach {
                metric: self.cfg.metric,
                up_down: false,
                prefix_len: p.len(),
                prefix: as_v4(p.addr()),
                sub_tlvs: None,
            })
            .collect();
        v4r.extend(self.ext_v4.iter().map(|(p, metric)| ExtIpReach {
            metric: *metric,
            up_down: false,
            prefix_len: p.len(),
            prefix: as_v4(p.addr()),
            sub_tlvs: None,
        }));
        if !v4r.is_empty() {
            tlvs.push(Tlv::ExtendedIpReachability(v4r));
        }
        let mut v6r: Vec<Ipv6Reach> = self
            .v6_reach
            .iter()
            .map(|p| Ipv6Reach {
                metric: self.cfg.metric,
                up_down: false,
                external: false,
                prefix_len: p.len(),
                prefix: as_v6(p.addr()),
                sub_tlvs: None,
            })
            .collect();
        v6r.extend(self.ext_v6.iter().map(|(p, metric)| Ipv6Reach {
            metric: *metric,
            up_down: false,
            external: true,
            prefix_len: p.len(),
            prefix: as_v6(p.addr()),
            sub_tlvs: None,
        }));
        if !v6r.is_empty() {
            tlvs.push(Tlv::Ipv6Reachability(v6r));
        }

        // An L1L2 router with backbone reach sets the attached bit in its L1 LSP.
        let attached =
            if level == IsLevel::L1 && self.cfg.level.has_l2() && self.have_l2_adjacency() {
                0b0001
            } else {
                0
            };

        Lsp {
            level,
            remaining_lifetime: LSP_LIFETIME,
            lsp_id: LspId::new(self.cfg.system_id, 0, 0),
            sequence_number: seq,
            checksum: 0,
            partition: false,
            attached,
            overload: false,
            is_type: self.cfg.level,
            tlvs,
        }
    }

    /// Encode an LSP (filling its checksum), store the verified copy and flood it.
    async fn store_and_flood(&mut self, level: IsLevel, lsp: Lsp) {
        let li = lidx(level);
        let bytes = Pdu {
            max_area_addresses: 0,
            body: PduBody::Lsp(lsp),
        }
        .encode();
        // Re-decode so the stored copy carries the computed Fletcher checksum (so a
        // reflooded copy of our own LSP never looks "more recent" than ours).
        if let Ok(Pdu {
            body: PduBody::Lsp(stored),
            ..
        }) = Pdu::decode(&bytes)
        {
            self.dbs[li].install(stored);
        }
        self.flood(level, &bytes, None).await;
    }

    /// Purge an LSP from the domain: re-flood it at zero remaining lifetime and
    /// drop it from our database.
    async fn flush_lsp(&mut self, level: IsLevel, id: LspId) {
        let li = lidx(level);
        let Some(mut lsp) = self.dbs[li].remove(&id) else {
            return;
        };
        lsp.remaining_lifetime = 0;
        lsp.sequence_number += 1;
        let bytes = Pdu {
            max_area_addresses: 0,
            body: PduBody::Lsp(lsp),
        }
        .encode();
        self.flood(level, &bytes, None).await;
    }

    /// Flood `bytes` (an encoded LSP PDU) out of every interface running `level`,
    /// optionally skipping the interface it arrived on.
    async fn flood(&self, level: IsLevel, bytes: &[u8], except: Option<usize>) {
        let mac = level_mac(level);
        let targets: Vec<(Arc<PacketSock>, u32)> = self
            .ifaces
            .iter()
            .enumerate()
            .filter(|(i, _)| Some(*i) != except)
            .map(|(_, f)| (f.sock.clone(), f.ifindex))
            .collect();
        for (sock, ifindex) in targets {
            if let Err(e) = sock.send(bytes, mac, ifindex).await {
                warn!(error = %e, "flooding IS-IS LSP");
            }
        }
    }

    /// Send an encoded PDU out of one interface to the `level` multicast.
    async fn send_on(&self, idx: usize, level: IsLevel, bytes: &[u8]) {
        let sock = self.ifaces[idx].sock.clone();
        let ifindex = self.ifaces[idx].ifindex;
        if let Err(e) = sock.send(bytes, level_mac(level), ifindex).await {
            warn!(error = %e, "sending IS-IS PDU");
        }
    }

    // --- Hellos & sequence-number PDUs ------------------------------------

    async fn send_hellos(&mut self) {
        let holding = (self.cfg.hello_interval as u16) * self.cfg.holding_multiplier;
        // Build then send, so we don't hold a borrow across the await.
        let mut to_send: Vec<(usize, [u8; 6], Vec<u8>)> = Vec::new();
        for (idx, iface) in self.ifaces.iter().enumerate() {
            match iface.iface_type {
                IfaceType::Broadcast => {
                    for level in self.active_levels() {
                        let li = lidx(level);
                        let mut tlvs = self.hello_tlvs(iface);
                        let snpas: Vec<[u8; 6]> = iface
                            .neighbors
                            .values()
                            .filter(|n| n.adj[li].is_some())
                            .map(|n| n.snpa)
                            .collect();
                        if !snpas.is_empty() {
                            tlvs.push(Tlv::LanNeighbors(snpas));
                        }
                        let lan_id = iface.dis[li].unwrap_or((SystemId::ZERO, 0));
                        let pdu = Pdu {
                            max_area_addresses: 0,
                            body: PduBody::LanHello(LanHello {
                                level,
                                circuit_type: self.cfg.level,
                                source_id: self.cfg.system_id,
                                holding_time: holding,
                                priority: self.cfg.priority,
                                lan_id,
                                tlvs,
                            }),
                        };
                        to_send.push((idx, level_mac(level), pdu.encode()));
                    }
                }
                IfaceType::PointToPoint => {
                    let pdu = Pdu {
                        max_area_addresses: 0,
                        body: PduBody::P2pHello(P2pHello {
                            circuit_type: self.cfg.level,
                            source_id: self.cfg.system_id,
                            holding_time: holding,
                            local_circuit_id: iface.local_circuit_id,
                            tlvs: self.hello_tlvs(iface),
                        }),
                    };
                    to_send.push((idx, ALL_L1_ISS, pdu.encode()));
                }
            }
        }
        for (idx, mac, bytes) in to_send {
            let sock = self.ifaces[idx].sock.clone();
            let ifindex = self.ifaces[idx].ifindex;
            if let Err(e) = sock.send(&bytes, mac, ifindex).await {
                warn!(interface = %self.ifaces[idx].name, error = %e, "sending IS-IS Hello");
            }
        }
    }

    /// The common TLVs every Hello carries (area, protocols, interface addresses).
    fn hello_tlvs(&self, iface: &Iface) -> Vec<Tlv> {
        let mut tlvs = vec![
            Tlv::AreaAddresses(vec![self.cfg.area.clone()]),
            Tlv::ProtocolsSupported(vec![NLPID_IPV4, NLPID_IPV6]),
        ];
        if !iface.v4.is_empty() {
            tlvs.push(Tlv::Ipv4InterfaceAddresses(iface.v4.clone()));
        }
        if !iface.v6.is_empty() {
            tlvs.push(Tlv::Ipv6InterfaceAddresses(iface.v6.clone()));
        }
        tlvs
    }

    async fn send_csnps(&mut self) {
        let mut to_send: Vec<(usize, [u8; 6], Vec<u8>)> = Vec::new();
        for (idx, iface) in self.ifaces.iter().enumerate() {
            for level in self.active_levels() {
                let li = lidx(level);
                // On a LAN only the DIS sends CSNPs; on point-to-point both ends do.
                let send = match iface.iface_type {
                    IfaceType::Broadcast => iface.is_dis[li],
                    IfaceType::PointToPoint => true,
                };
                if !send {
                    continue;
                }
                let pdu = Pdu {
                    max_area_addresses: 0,
                    body: PduBody::Csnp(Csnp {
                        level,
                        source_id: (self.cfg.system_id, iface.local_circuit_id),
                        start_lsp_id: LspId::new(SystemId::ZERO, 0, 0),
                        end_lsp_id: LspId::new(SystemId::new([0xff; 6]), 0xff, 0xff),
                        tlvs: vec![Tlv::LspEntries(self.dbs[li].summary())],
                    }),
                };
                to_send.push((idx, level_mac(level), pdu.encode()));
            }
        }
        for (idx, mac, bytes) in to_send {
            let sock = self.ifaces[idx].sock.clone();
            let ifindex = self.ifaces[idx].ifindex;
            if let Err(e) = sock.send(&bytes, mac, ifindex).await {
                warn!(error = %e, "sending IS-IS CSNP");
            }
        }
    }

    /// Build a PSNP requesting `ids` (the fields we don't know are left zero).
    fn build_psnp(&self, level: IsLevel, ids: &[LspId]) -> Vec<u8> {
        let entries = ids
            .iter()
            .map(|id| LspEntry {
                remaining_lifetime: 0,
                lsp_id: *id,
                sequence_number: 0,
                checksum: 0,
            })
            .collect();
        Pdu {
            max_area_addresses: 0,
            body: PduBody::Psnp(Psnp {
                level,
                source_id: (self.cfg.system_id, 0),
                tlvs: vec![Tlv::LspEntries(entries)],
            }),
        }
        .encode()
    }

    // --- timers ------------------------------------------------------------

    async fn housekeeping(&mut self, now: u64) {
        // Expire neighbours whose holding time has elapsed.
        let mut dead_levels: Vec<IsLevel> = Vec::new();
        let mut redo_dis: Vec<(usize, IsLevel)> = Vec::new();
        for idx in 0..self.ifaces.len() {
            let dead: Vec<SystemId> = self.ifaces[idx]
                .neighbors
                .iter()
                .filter(|(_, n)| now.saturating_sub(n.last_seen) >= n.holding as u64)
                .map(|(s, _)| *s)
                .collect();
            for sys in dead {
                if let Some(nbr) = self.ifaces[idx].neighbors.remove(&sys) {
                    for level in self.active_levels() {
                        if nbr.up(lidx(level)) {
                            if !dead_levels.contains(&level) {
                                dead_levels.push(level);
                            }
                            redo_dis.push((idx, level));
                        }
                    }
                    info!(neighbor = %sys, interface = %self.ifaces[idx].name, "IS-IS adjacency down (holding time expired)");
                }
            }
        }
        for (idx, level) in redo_dis {
            self.run_dis(idx, level).await;
        }
        for level in dead_levels {
            self.reoriginate(level).await;
        }

        // Age the databases and refresh our own LSPs before they expire.
        let mut refresh: Vec<IsLevel> = Vec::new();
        for level in self.active_levels() {
            let li = lidx(level);
            self.dbs[li].age(HOUSEKEEPING_SECS as u16);
            let low = self.dbs[li]
                .get(&LspId::new(self.cfg.system_id, 0, 0))
                .is_some_and(|l| l.remaining_lifetime < LSP_REFRESH_BELOW);
            if low {
                refresh.push(level);
            }
        }
        for level in refresh {
            self.reoriginate(level).await;
        }
    }

    /// Keep the BFD (RFC 5880) registrations in step with the set of neighbours that
    /// have an up adjacency *and* advertise an IP: register a session as such a
    /// neighbour appears, deregister it as the neighbour goes down or disappears. A
    /// no-op unless `[isis] bfd` is set. The BFD engine reports a session going down
    /// on [`Self::bfd_notify`], which the run loop turns into
    /// [`Self::force_neighbor_down`].
    async fn reconcile_bfd(&mut self) {
        if !self.cfg.bfd {
            return;
        }
        let mut want: HashSet<(IpAddr, u32)> = HashSet::new();
        for iface in &self.ifaces {
            for n in iface.neighbors.values() {
                if n.up_any() {
                    if let Some(addr) = n.bfd_addr {
                        want.insert(addr);
                    }
                }
            }
        }
        let added: Vec<(IpAddr, u32)> = want.difference(&self.bfd_registered).copied().collect();
        for (addr, scope) in added {
            let _ = self
                .bfd_register
                .send(crate::bfd::BfdCommand::Register {
                    peer: addr,
                    scope_id: scope,
                    consumer: crate::bfd::BfdConsumer::Isis,
                    notify: self.bfd_notify.clone(),
                    auth: None, // IS-IS uses the global [bfd] key
                })
                .await;
        }
        let removed: Vec<(IpAddr, u32)> = self.bfd_registered.difference(&want).copied().collect();
        for (addr, scope) in removed {
            let _ = self
                .bfd_register
                .send(crate::bfd::BfdCommand::Deregister {
                    peer: addr,
                    scope_id: scope,
                    consumer: crate::bfd::BfdConsumer::Isis,
                })
                .await;
        }
        self.bfd_registered = want;
    }

    /// Tear down the adjacency to the neighbour at `peer` (a BFD-reported path
    /// failure), mirroring the holding-time expiry in [`Self::housekeeping`]: remove
    /// the neighbour, re-run any affected DIS election, re-originate the LSP and
    /// re-run SPF. The BFD reconcile then drops the stale session.
    async fn force_neighbor_down(&mut self, peer: IpAddr) {
        let mut dead_levels: Vec<IsLevel> = Vec::new();
        let mut redo_dis: Vec<(usize, IsLevel)> = Vec::new();
        for idx in 0..self.ifaces.len() {
            let sys = self.ifaces[idx]
                .neighbors
                .iter()
                .find(|(_, n)| n.bfd_addr.map(|(a, _)| a) == Some(peer))
                .map(|(s, _)| *s);
            let Some(sys) = sys else { continue };
            if let Some(nbr) = self.ifaces[idx].neighbors.remove(&sys) {
                for level in self.active_levels() {
                    if nbr.up(lidx(level)) {
                        if !dead_levels.contains(&level) {
                            dead_levels.push(level);
                        }
                        redo_dis.push((idx, level));
                    }
                }
                info!(neighbor = %sys, interface = %self.ifaces[idx].name, %peer, "IS-IS adjacency down (BFD)");
            }
        }
        for (idx, level) in redo_dis {
            self.run_dis(idx, level).await;
        }
        let any_dead = !dead_levels.is_empty();
        for level in dead_levels {
            self.reoriginate(level).await;
        }
        if any_dead {
            self.run_spf_and_announce().await;
        }
    }

    // --- SPF → RIB ---------------------------------------------------------

    async fn run_spf_and_announce(&mut self) {
        let mut chosen: BTreeMap<Prefix, Route> = BTreeMap::new();
        for level in self.active_levels() {
            let li = lidx(level);
            for r in spf::routes(&self.dbs[li], self.cfg.system_id, level) {
                // Our own connected prefixes are announced as Connected already.
                if self.v4_reach.contains(&r.prefix) || self.v6_reach.contains(&r.prefix) {
                    continue;
                }
                // An on-link route with no resolvable interface can't be installed.
                if r.nexthops
                    .iter()
                    .all(|nh| nh.gateway.is_none() && nh.iface.is_none())
                {
                    continue;
                }
                match chosen.get(&r.prefix) {
                    Some(existing) if existing.metric <= r.metric => {}
                    _ => {
                        chosen.insert(r.prefix, r);
                    }
                }
            }
        }

        let current: HashSet<Prefix> = chosen.keys().copied().collect();
        for route in chosen.into_values() {
            let _ = self.updates.send(RouteUpdate::Announce(route)).await;
        }
        let gone: Vec<Prefix> = self
            .announced
            .iter()
            .filter(|p| !current.contains(p))
            .copied()
            .collect();
        for prefix in gone {
            let _ = self
                .updates
                .send(RouteUpdate::Withdraw {
                    prefix,
                    protocol: Protocol::Isis,
                    source: 0,
                })
                .await;
        }
        self.announced = current;
    }
}

impl IsisConfig {
    /// Whether this router runs `level` (a single L1 or L2).
    fn level_active(&self, level: IsLevel) -> bool {
        self.level.level_active(level)
    }
}

/// Helper extension: whether a level set includes a single level.
trait LevelSet {
    fn level_active(self, level: IsLevel) -> bool;
}
impl LevelSet for IsLevel {
    fn level_active(self, level: IsLevel) -> bool {
        match level {
            IsLevel::L1 => self.has_l1(),
            IsLevel::L2 => self.has_l2(),
            IsLevel::L1L2 => self.has_l1() || self.has_l2(),
        }
    }
}

// ---------------------------------------------------------------------------
// TLV extraction helpers
// ---------------------------------------------------------------------------

fn area_addresses(tlvs: &[Tlv]) -> Vec<AreaAddress> {
    tlvs.iter()
        .find_map(|t| match t {
            Tlv::AreaAddresses(a) => Some(a.clone()),
            _ => None,
        })
        .unwrap_or_default()
}

fn lan_neighbors(tlvs: &[Tlv]) -> Vec<[u8; 6]> {
    tlvs.iter()
        .find_map(|t| match t {
            Tlv::LanNeighbors(m) => Some(m.clone()),
            _ => None,
        })
        .unwrap_or_default()
}

/// The neighbour's IP address for a BFD session, from the IP Interface Address TLVs
/// of its Hello: prefer an IPv4 address (TLV 132, unscoped); otherwise an IPv6 one
/// (TLV 232) — a link-local needs the interface scope, a global is unscoped. IS-IS
/// runs over SNPA/MAC, so these TLVs are the only place a neighbour IP appears.
fn neighbor_bfd_addr(tlvs: &[Tlv], ifindex: u32) -> Option<(IpAddr, u32)> {
    for t in tlvs {
        if let Tlv::Ipv4InterfaceAddresses(addrs) = t {
            if let Some(a) = addrs.first() {
                return Some((IpAddr::V4(*a), 0));
            }
        }
    }
    for t in tlvs {
        if let Tlv::Ipv6InterfaceAddresses(addrs) = t {
            if let Some(a) = addrs.first() {
                let o = a.octets();
                let link_local = o[0] == 0xfe && (o[1] & 0xc0) == 0x80;
                return Some((IpAddr::V6(*a), if link_local { ifindex } else { 0 }));
            }
        }
    }
    None
}

fn lsp_entries(tlvs: &[Tlv]) -> Vec<LspEntry> {
    let mut out = Vec::new();
    for t in tlvs {
        if let Tlv::LspEntries(e) = t {
            out.extend_from_slice(e);
        }
    }
    out
}

fn as_v4(addr: IpAddr) -> Ipv4Addr {
    match addr {
        IpAddr::V4(a) => a,
        IpAddr::V6(_) => Ipv4Addr::UNSPECIFIED,
    }
}

fn as_v6(addr: IpAddr) -> Ipv6Addr {
    match addr {
        IpAddr::V6(a) => a,
        IpAddr::V4(_) => Ipv6Addr::UNSPECIFIED,
    }
}

// ---------------------------------------------------------------------------
// Config parsing (used by the daemon's `build_isis_config`)
// ---------------------------------------------------------------------------

/// Parse a System ID written as three dotted 16-bit groups, e.g. `1921.6800.1001`.
pub fn parse_system_id(s: &str) -> Result<SystemId> {
    let hex: String = s.chars().filter(|c| *c != '.').collect();
    if hex.len() != 12 || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
        anyhow::bail!("system-id {s:?} must be 12 hex digits, e.g. \"1921.6800.1001\"");
    }
    let mut b = [0u8; 6];
    for (i, byte) in b.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).expect("hex checked");
    }
    Ok(SystemId(b))
}

/// Parse an area address written as hex (dots ignored), e.g. `49.0001` → `49 00 01`.
pub fn parse_area(s: &str) -> Result<AreaAddress> {
    let hex: String = s.chars().filter(|c| *c != '.').collect();
    if hex.is_empty() || hex.len() % 2 != 0 || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
        anyhow::bail!("area {s:?} must be an even number of hex digits, e.g. \"49.0001\"");
    }
    let bytes = (0..hex.len() / 2)
        .map(|i| u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).expect("hex checked"))
        .collect();
    Ok(AreaAddress(bytes))
}

/// Derive a System ID from an IPv4 Router ID (the four octets in the low bytes).
pub fn system_id_from_router_id(rid: Ipv4Addr) -> SystemId {
    let o = rid.octets();
    SystemId([0, 0, o[0], o[1], o[2], o[3]])
}

// ---------------------------------------------------------------------------
// AF_PACKET socket plumbing
// ---------------------------------------------------------------------------

/// An owned raw fd that closes itself on drop (wrapped by [`AsyncFd`]).
struct RawSock(RawFd);
impl AsRawFd for RawSock {
    fn as_raw_fd(&self) -> RawFd {
        self.0
    }
}
impl Drop for RawSock {
    fn drop(&mut self) {
        // SAFETY: we own this fd exclusively; closing it once is correct.
        unsafe { libc::close(self.0) };
    }
}

/// A non-blocking AF_PACKET socket registered with tokio's reactor.
struct PacketSock {
    fd: AsyncFd<RawSock>,
}

impl PacketSock {
    /// Receive one LLC frame, returning its payload (LLC header onward) and the
    /// source MAC (the neighbour's SNPA).
    async fn recv(&self) -> io::Result<(Vec<u8>, [u8; 6])> {
        loop {
            let mut guard = self.fd.readable().await?;
            match guard.try_io(|inner| recvfrom_ll(inner.get_ref().as_raw_fd())) {
                Ok(result) => return result,
                Err(_would_block) => continue,
            }
        }
    }

    /// Send one IS-IS PDU to `dst` out of `ifindex`, framed in an 802.2 LLC header
    /// (DSAP = SSAP = `0xFE`, control = `0x03` UI). The kernel prepends the 802.3
    /// MAC header; the receiver strips this LLC header with [`strip_llc`].
    async fn send(&self, pdu: &[u8], dst: [u8; 6], ifindex: u32) -> io::Result<()> {
        let mut frame = Vec::with_capacity(3 + pdu.len());
        frame.extend_from_slice(&[LLC_SAP, LLC_SAP, LLC_CONTROL]);
        frame.extend_from_slice(pdu);
        loop {
            let mut guard = self.fd.writable().await?;
            match guard.try_io(|inner| sendto_ll(inner.get_ref().as_raw_fd(), &frame, dst, ifindex))
            {
                Ok(result) => return result,
                Err(_would_block) => continue,
            }
        }
    }
}

/// Spawn a receiver task funnelling frames from one interface into `tx`.
fn spawn_receiver(idx: usize, sock: Arc<PacketSock>, tx: mpsc::Sender<RxFrame>) {
    tokio::spawn(async move {
        loop {
            match sock.recv().await {
                Ok((data, src)) => {
                    if tx.send(RxFrame { idx, src, data }).await.is_err() {
                        break; // central task gone
                    }
                }
                Err(e) => {
                    warn!(error = %e, "IS-IS receive failed");
                    break;
                }
            }
        }
    });
}

/// Open an AF_PACKET/SOCK_DGRAM socket for IS-IS on `ifname`: 802.2 LLC, bound to
/// the interface and joined to both IS-IS multicast MACs. Returns its kernel
/// index, its MAC (our SNPA) and the registered socket.
fn open_isis_socket(ifname: &str) -> Result<(u32, [u8; 6], PacketSock)> {
    let cname = CString::new(ifname).context("interface name has an interior NUL")?;
    // SAFETY: `cname` is a valid NUL-terminated string for the call's duration.
    let ifindex = unsafe { libc::if_nametoindex(cname.as_ptr()) };
    if ifindex == 0 {
        anyhow::bail!("interface {ifname:?} not found");
    }

    let proto = (ETH_P_802_2.to_be()) as libc::c_int;
    // SAFETY: a plain socket(2); the fd is checked and owned immediately below.
    let fd = unsafe {
        libc::socket(
            libc::AF_PACKET,
            libc::SOCK_DGRAM | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
            proto,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error())
            .context("socket(AF_PACKET, SOCK_DGRAM) — needs CAP_NET_RAW");
    }
    let guard = RawSock(fd);

    // Bind to the interface so we only see (and send on) its frames.
    // SAFETY: a zeroed sockaddr_ll with family/protocol/ifindex set is a valid addr.
    let mut sa: libc::sockaddr_ll = unsafe { mem::zeroed() };
    sa.sll_family = libc::AF_PACKET as libc::c_ushort;
    sa.sll_protocol = ETH_P_802_2.to_be();
    sa.sll_ifindex = ifindex as libc::c_int;
    let rc = unsafe {
        libc::bind(
            fd,
            &sa as *const _ as *const libc::sockaddr,
            mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
        )
    };
    if rc < 0 {
        return Err(io::Error::last_os_error())
            .with_context(|| format!("bind AF_PACKET to {ifname:?} (needs CAP_NET_RAW)"));
    }

    // Join the two IS-IS multicast groups so the NIC delivers their frames.
    add_membership(fd, ifindex, ALL_L1_ISS).context("joining AllL1ISs")?;
    add_membership(fd, ifindex, ALL_L2_ISS).context("joining AllL2ISs")?;

    let snpa = read_mac(ifname).with_context(|| format!("reading MAC of {ifname:?}"))?;
    let sock = PacketSock {
        fd: AsyncFd::new(guard).context("registering AF_PACKET socket with tokio")?,
    };
    Ok((ifindex, snpa, sock))
}

/// Join a layer-2 multicast group on `ifindex` (`PACKET_ADD_MEMBERSHIP`).
fn add_membership(fd: RawFd, ifindex: u32, mac: [u8; 6]) -> Result<()> {
    // SAFETY: packet_mreq is plain POD; we fill all the relevant fields.
    let mut mreq: libc::packet_mreq = unsafe { mem::zeroed() };
    mreq.mr_ifindex = ifindex as libc::c_int;
    mreq.mr_type = libc::PACKET_MR_MULTICAST as libc::c_ushort;
    mreq.mr_alen = 6;
    mreq.mr_address[..6].copy_from_slice(&mac);
    setsockopt_struct(fd, libc::SOL_PACKET, libc::PACKET_ADD_MEMBERSHIP, &mreq)
}

/// `recvfrom` an 802.2 frame, returning its payload and source MAC.
fn recvfrom_ll(fd: RawFd) -> io::Result<(Vec<u8>, [u8; 6])> {
    let mut buf = vec![0u8; RECV_BUF];
    // SAFETY: zeroed sockaddr_ll is a valid receive address buffer.
    let mut sa: libc::sockaddr_ll = unsafe { mem::zeroed() };
    let mut salen = mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t;
    // SAFETY: buf and sa are valid, sized buffers for the duration of the call.
    let n = unsafe {
        libc::recvfrom(
            fd,
            buf.as_mut_ptr() as *mut libc::c_void,
            buf.len(),
            0,
            &mut sa as *mut _ as *mut libc::sockaddr,
            &mut salen,
        )
    };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    buf.truncate(n as usize);
    let mut mac = [0u8; 6];
    mac.copy_from_slice(&sa.sll_addr[..6]);
    Ok((buf, mac))
}

/// `sendto` an 802.2 frame `frame` to `dst` out of `ifindex`. The 802.3 length
/// field is the frame length, carried in `sll_protocol`.
fn sendto_ll(fd: RawFd, frame: &[u8], dst: [u8; 6], ifindex: u32) -> io::Result<()> {
    // SAFETY: zeroed sockaddr_ll with the link-layer fields set is a valid dest.
    let mut sa: libc::sockaddr_ll = unsafe { mem::zeroed() };
    sa.sll_family = libc::AF_PACKET as libc::c_ushort;
    sa.sll_protocol = (frame.len() as u16).to_be();
    sa.sll_ifindex = ifindex as libc::c_int;
    sa.sll_halen = 6;
    sa.sll_addr[..6].copy_from_slice(&dst);
    // SAFETY: frame and sa are valid for the call; sizes match.
    let n = unsafe {
        libc::sendto(
            fd,
            frame.as_ptr() as *const libc::c_void,
            frame.len(),
            0,
            &sa as *const _ as *const libc::sockaddr,
            mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
        )
    };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Read an interface's MAC address from `/sys/class/net/<ifname>/address`.
fn read_mac(ifname: &str) -> Result<[u8; 6]> {
    const SIOCGIFHWADDR: libc::c_ulong = 0x8927;
    let name = ifname.as_bytes();
    if name.len() >= libc::IF_NAMESIZE {
        anyhow::bail!("interface name {ifname:?} too long");
    }
    // A throwaway datagram socket to carry the ioctl. Unlike `/sys/class/net`, the
    // `SIOCGIFHWADDR` ioctl is network-namespace-aware, so it works inside an
    // `unshare -Urn` namespace (where sysfs still reflects the initial namespace).
    // SAFETY: a plain socket(2); `guard` owns the fd and closes it on return.
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error()).context("socket(AF_INET) for SIOCGIFHWADDR");
    }
    let guard = RawSock(fd);
    // `struct ifreq`: a 16-byte name, then `ifr_hwaddr` (a `sockaddr` whose 2-byte
    // family is followed by 14 bytes of data — the MAC is its first six octets).
    let mut ifr = [0u8; 40];
    ifr[..name.len()].copy_from_slice(name);
    // SAFETY: `ifr` is a 40-byte `ifreq` buffer; SIOCGIFHWADDR fills it in place.
    let rc = unsafe { libc::ioctl(guard.0, SIOCGIFHWADDR, ifr.as_mut_ptr()) };
    if rc < 0 {
        return Err(io::Error::last_os_error()).with_context(|| format!("SIOCGIFHWADDR {ifname:?}"));
    }
    let mut mac = [0u8; 6];
    mac.copy_from_slice(&ifr[18..24]); // 16 (name) + 2 (sa_family) → sa_data
    Ok(mac)
}

/// Render a MAC address for logging.
fn mac_str(mac: &[u8; 6]) -> String {
    mac.iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

/// Read an interface's host IPv4 and IPv6 addresses (both used as IS-IS interface
/// addresses, the SPF's next-hop source). IPv6 link-locals are kept.
fn iface_ips(ifname: &str) -> (Vec<Ipv4Addr>, Vec<Ipv6Addr>) {
    let mut v4 = Vec::new();
    let mut v6 = Vec::new();
    let mut head: *mut libc::ifaddrs = ptr::null_mut();
    // SAFETY: getifaddrs allocates a list into `head`; checked and freed below.
    if unsafe { libc::getifaddrs(&mut head) } != 0 {
        return (v4, v6);
    }
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
        // SAFETY: reading sa_family from a non-null sockaddr is always valid.
        let family = unsafe { (*ifa.ifa_addr).sa_family } as libc::c_int;
        if family == libc::AF_INET {
            // SAFETY: family is AF_INET, so this is a sockaddr_in.
            let sin = unsafe { &*(ifa.ifa_addr as *const libc::sockaddr_in) };
            let a = Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr));
            if !a.is_loopback() && !a.is_unspecified() {
                v4.push(a);
            }
        } else if family == libc::AF_INET6 {
            // SAFETY: family is AF_INET6, so this is a sockaddr_in6.
            let sin6 = unsafe { &*(ifa.ifa_addr as *const libc::sockaddr_in6) };
            let a = Ipv6Addr::from(sin6.sin6_addr.s6_addr);
            if !a.is_loopback() && !a.is_unspecified() {
                v6.push(a);
            }
        }
    }
    // SAFETY: freeing exactly the list getifaddrs allocated above.
    unsafe { libc::freeifaddrs(head) };
    (v4, v6)
}

/// Strip the IS-IS 802.2 LLC header (DSAP = SSAP = `0xFE`, control = `0x03`),
/// returning the IS-IS PDU bytes, or `None` if it is not an IS-IS LLC frame.
fn strip_llc(payload: &[u8]) -> Option<&[u8]> {
    if payload.len() < 3
        || payload[0] != LLC_SAP
        || payload[1] != LLC_SAP
        || payload[2] != LLC_CONTROL
    {
        return None;
    }
    Some(&payload[3..])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_system_id() {
        let id = parse_system_id("1921.6800.1001").unwrap();
        assert_eq!(id, SystemId::new([0x19, 0x21, 0x68, 0x00, 0x10, 0x01]));
        assert!(parse_system_id("19.21").is_err());
        assert!(parse_system_id("zzzz.6800.1001").is_err());
    }

    #[test]
    fn parses_area() {
        assert_eq!(
            parse_area("49.0001").unwrap(),
            AreaAddress(vec![0x49, 0, 1])
        );
        assert_eq!(parse_area("490000").unwrap(), AreaAddress(vec![0x49, 0, 0]));
        assert!(parse_area("49.001").is_err()); // odd digit count
        assert!(parse_area("").is_err());
    }

    #[test]
    fn derives_system_id_from_router_id() {
        let id = system_id_from_router_id(Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(id, SystemId::new([0, 0, 10, 0, 0, 1]));
    }

    #[test]
    fn strips_llc_header() {
        // A minimal IS-IS LLC frame: DSAP/SSAP/control then a PDU starting 0x83.
        let frame = [0xFE, 0xFE, 0x03, 0x83, 0x14, 0x01];
        assert_eq!(strip_llc(&frame), Some(&[0x83, 0x14, 0x01][..]));
        // Not an IS-IS LLC frame (wrong SAP).
        assert_eq!(strip_llc(&[0xAA, 0xAA, 0x03, 0x83]), None);
        assert_eq!(strip_llc(&[0xFE, 0xFE]), None);
    }

    #[test]
    fn node_id_packs_system_and_pseudonode() {
        let n = node_id(SystemId::new([1, 2, 3, 4, 5, 6]), 7);
        assert_eq!(n, [1, 2, 3, 4, 5, 6, 7]);
    }

    #[test]
    fn level_mac_selects_by_level() {
        assert_eq!(level_mac(IsLevel::L1), ALL_L1_ISS);
        assert_eq!(level_mac(IsLevel::L2), ALL_L2_ISS);
        assert_eq!(level_mac(IsLevel::L1L2), ALL_L1_ISS);
    }

    #[test]
    fn render_isis_database_lists_lsps_with_flags() {
        assert_eq!(render_isis_database(&[]), "no isis lsps\n");
        let lsp = IsisLspInfo {
            level: 2,
            lsp_id: LspId::new(SystemId::new([0, 0, 10, 0, 0, 1]), 0, 0),
            seq: 3,
            checksum: 0x1234,
            lifetime: 1198,
            attached: 0b0001,
            partition: false,
            overload: false,
        };
        let out = render_isis_database(&[lsp]);
        assert_eq!(
            out,
            "level 2 lsp 0000.0a00.0001.00-00 seq 0x00000003 chksum 0x1234 \
             lifetime 1198 att/p/ol 1/0/0\n"
        );
    }
}
