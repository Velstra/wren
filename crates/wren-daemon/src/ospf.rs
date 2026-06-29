//! # The OSPFv2 socket runner (RFC 2328)
//!
//! The async transport that turns the pure `wren-ospf` library (packet codec,
//! the §9/§10 state machines, the §9.4 DR election, the §13 flooding decision,
//! the §16 SPF) into a live OSPF speaker. Every protocol *decision* lives in the
//! library; this module does the I/O and sequencing the library cannot:
//!
//! * one raw `IPPROTO_OSPF` (89) socket **per interface**, joined to
//!   `AllSPFRouters`/`AllDRouters` and pinned to the interface (`SO_BINDTODEVICE`,
//!   TTL 1, no loopback);
//! * periodic Hellos and Hello-driven neighbour discovery to 2-Way + DR election;
//! * the Database Exchange (§10.6–§10.8) through Link State Request / Update to
//!   reaching Full;
//! * originating this router's Router-LSA and (as DR) Network-LSA, flooding them;
//! * **multi-area**: one link-state database per area, an SPF per area, and — for
//!   an area border router — Summary-LSA (type 3) origination plus the §16.2
//!   inter-area route calculation;
//! * announcing the resulting routes to the central router (RIB).
//!
//! Raw sockets need `CAP_NET_RAW`; the `unshare -Urn` netns used to smoke-test
//! the other runners grants it.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt::Write as _;
use std::io;
use std::mem;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::os::raw::c_void;
use std::os::unix::io::FromRawFd;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, oneshot};
use tokio::time::MissedTickBehavior;
use tracing::{debug, info, warn};

use wren_core::Prefix;
use wren_ospf::flood::{decide_flood, FloodDecision, FloodInput};
use wren_ospf::interface::{Candidate, Interface, InterfaceEvent, InterfaceState, InterfaceType};
use wren_ospf::lsa::{
    AsExternalLsa, LsType, Lsa, LsaBody, LsaHeader, NetworkLsa, RouterLink, RouterLinkType,
    RouterLsa, SummaryLsa, RTR_FLAG_B, RTR_FLAG_E,
};
use wren_ospf::lsdb::{LsaKey, Lsdb};
use wren_ospf::neighbor::{
    Neighbor, NeighborAction, NeighborContext, NeighborEvent, NeighborState,
};
use wren_ospf::packet::{
    Auth, Body, DatabaseDescription, Header, Hello, LinkStateAck, LinkStateRequest,
    LinkStateUpdate, LsRequest, Packet, DD_FLAG_INIT, DD_FLAG_MASTER, DD_FLAG_MORE,
};
use wren_ospf::spf::{self, SpfRoute};
use wren_ospf::{
    ALL_D_ROUTERS, ALL_SPF_ROUTERS, INITIAL_SEQUENCE_NUMBER, IP_PROTOCOL, MAX_AGE, OPT_E, OPT_NP,
};

use crate::sockopt::{setsockopt_int, setsockopt_struct};
use crate::router::{Redistribution, RouteUpdate};

/// How often (seconds) the housekeeping timer advances dead/wait timers.
const HOUSEKEEPING_SECS: u64 = 1;
/// Receive buffer: the raw socket delivers the IP header too, and an LSU can be
/// link-MTU sized.
const RECV_BUF: usize = 9000;
/// The OSPF backbone area (0.0.0.0), to which inter-area summaries condense.
const BACKBONE: Ipv4Addr = Ipv4Addr::UNSPECIFIED;
/// A pseudo-area key for AS-wide (type-5) LSA sequence numbers — these are not
/// area-scoped, so they need a sequence namespace distinct from any real area.
const AS_SCOPE: Ipv4Addr = Ipv4Addr::new(255, 255, 255, 255);

/// The resolved OSPF configuration for a run.
pub struct OspfConfig {
    /// This router's Router ID.
    pub router_id: Ipv4Addr,
    /// The network type of the interfaces.
    pub iface_type: InterfaceType,
    /// This router's DR-election priority.
    pub priority: u8,
    /// Interface output cost (the metric advertised for each link).
    pub cost: u16,
    /// HelloInterval in seconds.
    pub hello_interval: u16,
    /// RouterDeadInterval in seconds.
    pub dead_interval: u32,
    /// Interfaces OSPF runs on, each with the area it belongs to.
    pub interfaces: Vec<OspfIfaceCfg>,
    /// External destinations to redistribute into OSPF as AS-external (type-5)
    /// LSAs at startup (from `redistribute-static`). RIB-based redistribution
    /// (`[ospf] redistribute`) adds to this set dynamically over the run.
    pub redistribute: Vec<RedistRoute>,
    /// The external (type-2) metric advertised for RIB-redistributed routes.
    pub redistribute_metric: u32,
    /// Areas configured as stubs (RFC 2328 §3.6): they receive no AS-external
    /// (type-5) LSAs, and an area border router injects a default route into them.
    pub stub_areas: HashSet<Ipv4Addr>,
    /// The metric an ABR advertises for the default route (`0.0.0.0/0`) it injects
    /// into each stub area.
    pub stub_default_cost: u32,
    /// Areas configured as not-so-stubby (NSSA, RFC 3101): like a stub they carry
    /// no AS-external (type-5) LSAs, but an ASBR inside may originate type-7 LSAs,
    /// which the area border router translates to type-5 for the rest of the AS.
    pub nssa_areas: HashSet<Ipv4Addr>,
    /// Totally-stubby areas (RFC 2328 §3.6 "no-summary" stubs): a stub area into
    /// which the ABR also suppresses inter-area (type-3) summaries, leaving only the
    /// injected default. Every area here is also in [`Self::stub_areas`].
    pub totally_stubby_areas: HashSet<Ipv4Addr>,
    /// Totally-NSSA areas (NSSA "no-summary"): an NSSA into which the ABR suppresses
    /// inter-area (type-3) summaries and instead injects a type-7 default route.
    /// Every area here is also in [`Self::nssa_areas`].
    pub totally_nssa_areas: HashSet<Ipv4Addr>,
    /// Plain NSSAs into which the ABR additionally injects a type-7 default route
    /// (RFC 3101 §2.3) while still carrying the inter-area (type-3) summaries — unlike
    /// a totally-NSSA, which suppresses those summaries. Every area here is also in
    /// [`Self::nssa_areas`]; a totally-NSSA already injects the default, so it need not
    /// be listed here as well.
    pub nssa_default_areas: HashSet<Ipv4Addr>,
    /// The packet authentication scheme (RFC 2328 §D) applied to every interface. For
    /// MD5 the carried sequence number is a template (0); the runner stamps an
    /// increasing value on each sent packet via [`Ospf::send_auth`].
    pub auth: Auth,
    /// Run a BFD (RFC 5880) session to each neighbour for fast failure detection:
    /// when a neighbour reaches Full a session is registered, and a BFD-down tears
    /// the adjacency down at once instead of waiting for the dead interval.
    pub bfd: bool,
}

/// One configured OSPF interface and the area it is in.
pub struct OspfIfaceCfg {
    /// The interface name.
    pub name: String,
    /// The area the interface belongs to.
    pub area: Ipv4Addr,
}

/// An external destination this ASBR redistributes into OSPF (type-2 metric).
pub struct RedistRoute {
    /// The external network.
    pub prefix: Prefix,
    /// The advertised (type-2) external metric.
    pub metric: u32,
}

/// A neighbour on one interface: its FSM plus the runtime exchange state.
struct OspfNeighbor {
    fsm: Neighbor,
    addr: Ipv4Addr,
    last_seen: u64,
    /// The current DD sequence number for this adjacency.
    dd_seq: u32,
    /// Whether we are the master of the DD exchange.
    master: bool,
    /// Whether we have put our database summary on the wire yet.
    summary_sent: bool,
    /// The LSAs we still need from this neighbour (§10.9 request list).
    request_list: Vec<LsaKey>,
}

impl OspfNeighbor {
    fn new(router_id: Ipv4Addr, addr: Ipv4Addr, now: u64) -> Self {
        OspfNeighbor {
            fsm: Neighbor::new(router_id),
            addr,
            last_seen: now,
            dd_seq: 0,
            master: false,
            summary_sent: false,
            request_list: Vec::new(),
        }
    }
}

/// One OSPF-speaking interface.
struct Iface {
    name: String,
    ifindex: u32,
    addr: Ipv4Addr,
    mask_len: u8,
    /// The area this interface belongs to.
    area: Ipv4Addr,
    sock: Arc<UdpSocket>,
    fsm: Interface,
    neighbors: HashMap<Ipv4Addr, OspfNeighbor>,
    wait_deadline: Option<u64>,
}

impl Iface {
    /// This interface's network number (address with host bits cleared).
    fn network(&self) -> Ipv4Addr {
        let mask = u32::from(len_to_mask(self.mask_len));
        Ipv4Addr::from(u32::from(self.addr) & mask)
    }
}

/// Per-area link-state state. Types 1–4 are area-scoped, so each area has its own
/// database and bookkeeping of the LSAs this router originates into it.
struct Area {
    lsdb: Lsdb,
    /// The Network-LSAs we currently originate into this area (as DR).
    originated_networks: HashSet<LsaKey>,
    /// The Summary-LSAs we currently originate into this area (as an ABR).
    originated_summaries: HashSet<LsaKey>,
    /// The NSSA type-7 LSAs we currently originate into this area (as an ASBR in an
    /// NSSA, RFC 3101).
    originated_nssa: HashSet<LsaKey>,
}

impl Area {
    fn new() -> Self {
        Area {
            lsdb: Lsdb::new(),
            originated_networks: HashSet::new(),
            originated_summaries: HashSet::new(),
            originated_nssa: HashSet::new(),
        }
    }
}

/// A raw OSPF datagram (still carrying its IP header).
struct RawPacket {
    ifindex: u32,
    src: Ipv4Addr,
    data: Vec<u8>,
}

/// The whole OSPF speaker: interfaces, the per-area databases, our LSA sequence
/// numbers and the channel to the router.
struct Ospf {
    cfg: OspfConfig,
    ifaces: Vec<Iface>,
    /// One link-state database per area.
    areas: BTreeMap<Ipv4Addr, Area>,
    /// The AS-wide database of AS-external (type-5) LSAs (not area-scoped).
    external_lsdb: Lsdb,
    /// The external destinations this ASBR currently originates, prefix → type-2
    /// metric. Seeded from `redistribute-static` and updated by RIB-based
    /// redistribution (`[ospf] redistribute`).
    externals: BTreeMap<Prefix, u32>,
    /// The AS-external LSAs we currently originate (for flush bookkeeping).
    originated_externals: HashSet<LsaKey>,
    /// The AS-external (type-5) LSAs we currently originate by translating NSSA
    /// type-7 LSAs as an ABR (RFC 3101 §3.2) — tracked apart from
    /// `originated_externals` so the two flush independently.
    originated_translated: HashSet<LsaKey>,
    /// The next sequence number to use for each LSA we originate, keyed by
    /// `(area, LSA identity)` — the same LSA key recurs across areas.
    lsa_seqs: HashMap<(Ipv4Addr, LsaKey), i32>,
    /// A counter handing out fresh DD sequence numbers per adjacency.
    next_dd_seq: u32,
    /// The prefixes we currently have announced to the RIB (for reconciliation).
    announced: HashSet<Prefix>,
    updates: mpsc::Sender<RouteUpdate>,
    /// BFD (RFC 5880): the channel to the BFD engine to register/deregister
    /// per-neighbour sessions, the notify sender included in each registration (the
    /// engine reports a session going down on it), and the set of neighbour
    /// addresses currently registered (the Full neighbours). Unused when
    /// `cfg.bfd` is false.
    bfd_register: mpsc::Sender<crate::bfd::BfdCommand>,
    bfd_notify: mpsc::Sender<std::net::IpAddr>,
    bfd_registered: HashSet<Ipv4Addr>,
}

/// A `show ospf …` query, answered by the OSPF task itself out of the state it
/// owns (its interfaces, their neighbours and the DR election) — no shared access.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum OspfQuery {
    /// The neighbours on every interface, with their adjacency state.
    Neighbors,
    /// The OSPF-speaking interfaces, with their area, state and elected DR/BDR.
    Interfaces,
    /// The link-state database: every LSA in every area, plus the AS-external LSAs.
    Database,
}

/// A control-socket query plus the channel to answer it on.
pub struct OspfQueryRequest {
    /// What to report.
    pub query: OspfQuery,
    /// Where to send the rendered answer.
    pub respond: oneshot::Sender<String>,
}

/// One neighbour, snapshotted for the (pure) renderer.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct OspfNeighborInfo {
    /// The neighbour's Router ID.
    pub router_id: Ipv4Addr,
    /// The neighbour's interface address.
    pub addr: Ipv4Addr,
    /// The adjacency state.
    pub state: NeighborState,
    /// The local interface the neighbour is on.
    pub iface: String,
}

/// One OSPF interface, snapshotted for the (pure) renderer.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct OspfIfaceInfo {
    /// The interface name.
    pub name: String,
    /// The area it belongs to.
    pub area: Ipv4Addr,
    /// Its IPv4 address.
    pub addr: Ipv4Addr,
    /// The interface state.
    pub state: InterfaceState,
    /// The elected Designated Router (`0.0.0.0` = none).
    pub dr: Ipv4Addr,
    /// The elected Backup Designated Router (`0.0.0.0` = none).
    pub bdr: Ipv4Addr,
    /// This router's priority on the interface.
    pub priority: u8,
}

/// The short name of a neighbour state, as shown by `show ospf neighbors`.
fn neighbor_state_name(s: NeighborState) -> &'static str {
    match s {
        NeighborState::Down => "Down",
        NeighborState::Attempt => "Attempt",
        NeighborState::Init => "Init",
        NeighborState::TwoWay => "2-Way",
        NeighborState::ExStart => "ExStart",
        NeighborState::Exchange => "Exchange",
        NeighborState::Loading => "Loading",
        NeighborState::Full => "Full",
    }
}

/// The short name of an interface state, as shown by `show ospf interfaces`.
fn iface_state_name(s: InterfaceState) -> &'static str {
    match s {
        InterfaceState::Down => "Down",
        InterfaceState::Loopback => "Loopback",
        InterfaceState::Waiting => "Waiting",
        InterfaceState::PointToPoint => "PtP",
        InterfaceState::DrOther => "DROther",
        InterfaceState::Backup => "Backup",
        InterfaceState::Dr => "DR",
    }
}

/// Render the OSPF neighbours, one per line (à la `show ip ospf neighbor`).
pub fn render_ospf_neighbors(neighbors: &[OspfNeighborInfo]) -> String {
    if neighbors.is_empty() {
        return "no ospf neighbors\n".to_string();
    }
    let mut out = String::new();
    for n in neighbors {
        let _ = writeln!(
            out,
            "{} via {} dev {} state {}",
            n.router_id,
            n.addr,
            n.iface,
            neighbor_state_name(n.state),
        );
    }
    out
}

/// Render the OSPF interfaces, one per line (à la `show ip ospf interface`).
pub fn render_ospf_interfaces(ifaces: &[OspfIfaceInfo]) -> String {
    if ifaces.is_empty() {
        return "no ospf interfaces\n".to_string();
    }
    let mut out = String::new();
    for i in ifaces {
        let _ = write!(
            out,
            "{} area {} {} state {} pri {}",
            i.name,
            i.area,
            i.addr,
            iface_state_name(i.state),
            i.priority,
        );
        if !i.dr.is_unspecified() {
            let _ = write!(out, " dr {}", i.dr);
        }
        if !i.bdr.is_unspecified() {
            let _ = write!(out, " bdr {}", i.bdr);
        }
        out.push('\n');
    }
    out
}

/// One LSA, snapshotted for `show ospf database`. `area` is `None` for the
/// AS-scoped AS-external (type-5) LSAs, which do not belong to any single area.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct OspfLsaInfo {
    /// The area the LSA belongs to, or `None` for AS-external LSAs.
    pub area: Option<Ipv4Addr>,
    /// The LSA type.
    pub ls_type: LsType,
    /// The Link State ID (meaning depends on the type).
    pub link_state_id: Ipv4Addr,
    /// The originating router's id.
    pub advertising_router: Ipv4Addr,
    /// The instance's sequence number (signed, increasing).
    pub seq: i32,
    /// The LSA's age in seconds.
    pub age: u16,
}

/// The short name of an LSA type, as shown by `show ospf database`.
fn ls_type_name(t: LsType) -> &'static str {
    match t {
        LsType::Router => "router",
        LsType::Network => "network",
        LsType::SummaryNetwork => "summary",
        LsType::SummaryAsbr => "asbr-summary",
        LsType::AsExternal => "external",
        LsType::Nssa => "nssa-external",
    }
}

/// Render the OSPF link-state database, one LSA per line, grouped area by area with
/// the AS-external LSAs last (à la `show ip ospf database`).
pub fn render_ospf_database(lsas: &[OspfLsaInfo]) -> String {
    if lsas.is_empty() {
        return "no ospf lsas\n".to_string();
    }
    let mut out = String::new();
    for l in lsas {
        match l.area {
            Some(area) => {
                let _ = write!(out, "area {area} {}", ls_type_name(l.ls_type));
            }
            None => {
                let _ = write!(out, "as-external {}", ls_type_name(l.ls_type));
            }
        }
        let _ = writeln!(
            out,
            " id {} adv-router {} seq {:#010x} age {}",
            l.link_state_id, l.advertising_router, l.seq as u32, l.age,
        );
    }
    out
}

/// Run OSPF on the configured interfaces, announcing SPF routes to `updates`.
///
/// `redist` carries RIB best-path routes the central router pushes for
/// redistribution; OSPF originates each as an AS-external (type-5) LSA and
/// withdraws it again when its best path goes away. `queries` carries the
/// operator's `show ospf …` requests, answered out of the live state.
pub async fn run(
    cfg: OspfConfig,
    updates: mpsc::Sender<RouteUpdate>,
    mut redist: mpsc::Receiver<Redistribution>,
    mut queries: mpsc::Receiver<OspfQueryRequest>,
    bfd_register: mpsc::Sender<crate::bfd::BfdCommand>,
    bfd_notify: mpsc::Sender<std::net::IpAddr>,
    mut bfd_down: mpsc::Receiver<std::net::IpAddr>,
) -> Result<()> {
    let mut ifaces = Vec::new();
    let mut areas: BTreeMap<Ipv4Addr, Area> = BTreeMap::new();
    for ic in &cfg.interfaces {
        let name = &ic.name;
        let (ifindex, std_sock) =
            open_ospf_socket(name).with_context(|| format!("opening OSPF socket on {name:?}"))?;
        let Some((addr, mask_len)) = iface_ipv4(name) else {
            warn!(interface = %name, "no IPv4 address — skipping OSPF on this interface");
            continue;
        };
        let sock =
            Arc::new(UdpSocket::from_std(std_sock).context("registering OSPF socket with tokio")?);
        let mut fsm = Interface::new(cfg.router_id, cfg.priority, cfg.iface_type);
        for act in fsm.handle(InterfaceEvent::InterfaceUp, &[]) {
            debug!(interface = %name, ?act, "interface up");
        }
        info!(interface = %name, ifindex, %addr, area = %ic.area, kind = ?cfg.iface_type, "OSPF up (proto 89)");
        areas.entry(ic.area).or_insert_with(Area::new);
        ifaces.push(Iface {
            name: name.clone(),
            ifindex,
            addr,
            mask_len,
            area: ic.area,
            sock,
            fsm,
            neighbors: HashMap::new(),
            wait_deadline: Some(cfg.dead_interval as u64),
        });
    }
    if ifaces.is_empty() {
        warn!("OSPF is enabled but no usable interfaces — nothing to do");
        return Ok(());
    }

    let (pkt_tx, mut pkt_rx) = mpsc::channel::<RawPacket>(256);
    for iface in &ifaces {
        spawn_receiver(iface.sock.clone(), iface.ifindex, pkt_tx.clone());
    }
    drop(pkt_tx);

    // Seed the external set from the from-config statics (`redistribute-static`);
    // RIB-based redistribution then adds to it over the run.
    let externals: BTreeMap<Prefix, u32> =
        cfg.redistribute.iter().map(|r| (r.prefix, r.metric)).collect();
    let mut ospf = Ospf {
        cfg,
        ifaces,
        areas,
        external_lsdb: Lsdb::new(),
        externals,
        originated_externals: HashSet::new(),
        originated_translated: HashSet::new(),
        lsa_seqs: HashMap::new(),
        next_dd_seq: 0x0100_0000,
        announced: HashSet::new(),
        updates,
        bfd_register,
        bfd_notify,
        bfd_registered: HashSet::new(),
    };
    ospf.originate_externals().await;
    ospf.reoriginate_and_flood().await;
    ospf.run_spf_and_announce().await;

    let start = Instant::now();
    let mut hello = tokio::time::interval(Duration::from_secs(ospf.cfg.hello_interval as u64));
    hello.set_missed_tick_behavior(MissedTickBehavior::Delay);
    let mut housekeeping = tokio::time::interval(Duration::from_secs(HOUSEKEEPING_SECS));
    housekeeping.tick().await;

    loop {
        tokio::select! {
            received = pkt_rx.recv() => {
                let Some(pkt) = received else {
                    warn!("all OSPF receivers stopped");
                    break;
                };
                let now = start.elapsed().as_secs();
                ospf.handle_packet(&pkt, now).await;
            }
            _ = hello.tick() => {
                ospf.send_hellos().await;
            }
            _ = housekeeping.tick() => {
                let now = start.elapsed().as_secs();
                ospf.age_neighbors(now).await;
                ospf.fire_wait_timers(now).await;
                ospf.retransmit_init_dds().await;
            }
            Some(r) = redist.recv() => {
                ospf.apply_redistribution(r).await;
            }
            Some(req) = queries.recv() => {
                let answer = match req.query {
                    OspfQuery::Neighbors => render_ospf_neighbors(&ospf.neighbor_infos()),
                    OspfQuery::Interfaces => render_ospf_interfaces(&ospf.iface_infos()),
                    OspfQuery::Database => render_ospf_database(&ospf.lsa_infos()),
                };
                let _ = req.respond.send(answer);
            }
            // BFD (RFC 5880) reported a neighbour's forwarding path down: tear that
            // adjacency down at once (RFC 5882 §4.4), exactly as an inactivity
            // timeout would, instead of waiting for the dead interval.
            Some(peer) = bfd_down.recv() => {
                if let std::net::IpAddr::V4(v4) = peer {
                    ospf.force_neighbor_down(v4).await;
                }
            }
        }
        // Keep the set of registered BFD sessions in step with the Full neighbours
        // (a no-op when `[ospf] bfd` is off). Cheap: a few neighbours per interface.
        ospf.reconcile_bfd().await;
    }
    Ok(())
}

impl Ospf {
    /// Snapshot every neighbour on every interface, for `show ospf neighbors`.
    /// Sorted by (interface, neighbour Router ID) for a stable listing.
    fn neighbor_infos(&self) -> Vec<OspfNeighborInfo> {
        let mut out = Vec::new();
        for iface in &self.ifaces {
            let mut ids: Vec<&Ipv4Addr> = iface.neighbors.keys().collect();
            ids.sort_by_key(|id| u32::from(**id));
            for id in ids {
                let n = &iface.neighbors[id];
                out.push(OspfNeighborInfo {
                    router_id: *id,
                    addr: n.addr,
                    state: n.fsm.state,
                    iface: iface.name.clone(),
                });
            }
        }
        out
    }

    /// Snapshot every OSPF interface, for `show ospf interfaces`.
    fn iface_infos(&self) -> Vec<OspfIfaceInfo> {
        self.ifaces
            .iter()
            .map(|iface| OspfIfaceInfo {
                name: iface.name.clone(),
                area: iface.area,
                addr: iface.addr,
                state: iface.fsm.state,
                dr: iface.fsm.dr,
                bdr: iface.fsm.bdr,
                priority: iface.fsm.priority,
            })
            .collect()
    }

    /// Snapshot the whole link-state database, for `show ospf database`: every LSA in
    /// every area (areas in id order), then the AS-external LSAs. Within each database
    /// LSAs are ordered by (type, link-state-id, advertising-router) for a stable list.
    fn lsa_infos(&self) -> Vec<OspfLsaInfo> {
        fn sort_key(l: &OspfLsaInfo) -> (u8, u32, u32) {
            (l.ls_type.as_u8(), u32::from(l.link_state_id), u32::from(l.advertising_router))
        }
        let mut out = Vec::new();
        for (area_id, area) in &self.areas {
            let mut area_lsas: Vec<OspfLsaInfo> = area
                .lsdb
                .iter()
                .map(|lsa| OspfLsaInfo {
                    area: Some(*area_id),
                    ls_type: lsa.header.ls_type,
                    link_state_id: lsa.header.link_state_id,
                    advertising_router: lsa.header.advertising_router,
                    seq: lsa.header.ls_seq,
                    age: lsa.header.ls_age,
                })
                .collect();
            area_lsas.sort_by_key(sort_key);
            out.extend(area_lsas);
        }
        let mut ext: Vec<OspfLsaInfo> = self
            .external_lsdb
            .iter()
            .map(|lsa| OspfLsaInfo {
                area: None,
                ls_type: lsa.header.ls_type,
                link_state_id: lsa.header.link_state_id,
                advertising_router: lsa.header.advertising_router,
                seq: lsa.header.ls_seq,
                age: lsa.header.ls_age,
            })
            .collect();
        ext.sort_by_key(sort_key);
        out.extend(ext);
        out
    }

    /// Strip the IP header, decode the packet and dispatch it.
    async fn handle_packet(&mut self, pkt: &RawPacket, now: u64) {
        let Some(ospf) = strip_ip_header(&pkt.data) else {
            return;
        };
        let packet = match Packet::decode_auth(ospf, &self.cfg.auth) {
            Ok(p) => p,
            Err(e) => {
                debug!(src = %pkt.src, error = %e, "ignoring malformed OSPF packet");
                return;
            }
        };
        let Some(idx) = self.iface_index(pkt.ifindex) else {
            return;
        };
        // Drop our own reflections and packets for the wrong area on this link.
        if packet.header.router_id == self.cfg.router_id
            || packet.header.area_id != self.ifaces[idx].area
        {
            return;
        }
        let nbr_id = packet.header.router_id;
        match packet.body {
            Body::Hello(h) => self.handle_hello(idx, nbr_id, pkt.src, &h, now).await,
            Body::DatabaseDescription(dd) => self.handle_dd(idx, nbr_id, &dd).await,
            Body::LinkStateRequest(req) => self.handle_lsr(idx, nbr_id, &req).await,
            Body::LinkStateUpdate(upd) => self.handle_lsu(idx, nbr_id, upd).await,
            Body::LinkStateAck(_) => debug!(src = %pkt.src, "OSPF LSAck received"),
        }
    }

    // --- Hello / neighbour discovery --------------------------------------

    async fn handle_hello(
        &mut self,
        idx: usize,
        nbr_id: Ipv4Addr,
        src: Ipv4Addr,
        hello: &Hello,
        now: u64,
    ) {
        let cfg_hi = self.cfg.hello_interval;
        let cfg_di = self.cfg.dead_interval;
        let self_id = self.cfg.router_id;
        {
            let iface = &self.ifaces[idx];
            // The neighbour's E-bit (AS-external) and N-bit (NSSA) must match this
            // area's type, or no adjacency forms (RFC 2328 §10.5, RFC 3101): a stub
            // expects both cleared, an NSSA expects the N-bit, a normal area the E-bit.
            let want_opts = self.area_options(iface.area) & (OPT_E | OPT_NP);
            let got_opts = hello.options & (OPT_E | OPT_NP);
            if hello.hello_interval != cfg_hi
                || hello.dead_interval != cfg_di
                || hello.network_mask != len_to_mask(iface.mask_len)
                || got_opts != want_opts
            {
                debug!(neighbor = %nbr_id, options = hello.options, "Hello parameters/options mismatch — ignored");
                return;
            }
        }
        let declared_dr = self.addr_to_router_id(idx, hello.designated_router);
        let declared_bdr = self.addr_to_router_id(idx, hello.backup_designated_router);

        let adjacency_ok = self.adjacency_ok(idx, nbr_id);
        let iface = &mut self.ifaces[idx];
        let entry = iface
            .neighbors
            .entry(nbr_id)
            .or_insert_with(|| OspfNeighbor::new(nbr_id, src, now));
        let was_bidir = entry.fsm.is_bidirectional();
        entry.addr = src;
        entry.last_seen = now;
        entry.fsm.priority = hello.router_priority;
        entry.fsm.declared_dr = declared_dr;
        entry.fsm.declared_bdr = declared_bdr;

        let ctx = NeighborContext {
            adjacency_ok,
            request_list_empty: entry.request_list.is_empty(),
        };
        let prev_state = entry.fsm.state;
        let mut acts = entry.fsm.handle(NeighborEvent::HelloReceived, ctx);
        let two_way = hello.neighbors.contains(&self_id);
        let ev = if two_way {
            NeighborEvent::TwoWayReceived
        } else {
            NeighborEvent::OneWayReceived
        };
        acts.extend(entry.fsm.handle(ev, ctx));
        let new_state = entry.fsm.state;
        let now_bidir = entry.fsm.is_bidirectional();
        if new_state != prev_state {
            info!(interface = %iface.name, neighbor = %nbr_id, from = ?prev_state, to = ?new_state, "OSPF neighbour state change");
        }

        let reveals_dr = !hello.designated_router.is_unspecified()
            || !hello.backup_designated_router.is_unspecified();
        let waiting = iface.fsm.state == InterfaceState::Waiting;
        let election_changed = if waiting && reveals_dr {
            self.run_interface_event(idx, InterfaceEvent::BackupSeen)
        } else if was_bidir != now_bidir {
            self.run_interface_event(idx, InterfaceEvent::NeighborChange)
        } else {
            false
        };

        self.act_on_neighbor(idx, nbr_id, acts).await;
        if election_changed {
            self.reeval_adjacencies(idx).await;
        }
    }

    fn adjacency_ok(&self, idx: usize, nbr_id: Ipv4Addr) -> bool {
        let iface = &self.ifaces[idx];
        if !iface.fsm.iface_type.elects_dr() {
            return true;
        }
        iface.fsm.is_dr_or_bdr() || iface.fsm.dr == nbr_id || iface.fsm.bdr == nbr_id
    }

    /// Drive an interface FSM event and return whether the DR/BDR changed.
    fn run_interface_event(&mut self, idx: usize, ev: InterfaceEvent) -> bool {
        let cands = candidates(&self.ifaces[idx]);
        let iface = &mut self.ifaces[idx];
        let (before_dr, before_bdr) = (iface.fsm.dr, iface.fsm.bdr);
        let _ = iface.fsm.handle(ev, &cands);
        let changed = iface.fsm.dr != before_dr || iface.fsm.bdr != before_bdr;
        if changed {
            info!(interface = %iface.name, state = ?iface.fsm.state, dr = %iface.fsm.dr, bdr = %iface.fsm.bdr, "OSPF DR election");
        }
        changed
    }

    /// After an election, re-evaluate whether each neighbour should now be
    /// adjacent (§10.4 "AdjOK?").
    async fn reeval_adjacencies(&mut self, idx: usize) {
        let nbr_ids: Vec<Ipv4Addr> = self.ifaces[idx]
            .neighbors
            .values()
            .filter(|n| n.fsm.is_bidirectional())
            .map(|n| n.fsm.router_id)
            .collect();
        for nbr_id in nbr_ids {
            let ok = self.adjacency_ok(idx, nbr_id);
            let (acts, prev, new) = {
                let iface = &mut self.ifaces[idx];
                let n = iface.neighbors.get_mut(&nbr_id).unwrap();
                let ctx = NeighborContext {
                    adjacency_ok: ok,
                    request_list_empty: n.request_list.is_empty(),
                };
                let prev = n.fsm.state;
                let acts = n.fsm.handle(NeighborEvent::AdjOk, ctx);
                (acts, prev, n.fsm.state)
            };
            if new != prev {
                info!(interface = %self.ifaces[idx].name, neighbor = %nbr_id, from = ?prev, to = ?new, "OSPF neighbour state change");
            }
            self.act_on_neighbor(idx, nbr_id, acts).await;
        }
    }

    // --- Acting on neighbour FSM actions ----------------------------------

    async fn act_on_neighbor(&mut self, idx: usize, nbr_id: Ipv4Addr, acts: Vec<NeighborAction>) {
        for act in acts {
            match act {
                NeighborAction::StartDdExchange => self.start_dd_exchange(idx, nbr_id).await,
                NeighborAction::AdjacencyUp => self.on_adjacency_full(idx, nbr_id).await,
                NeighborAction::ClearAdjacency => {
                    if let Some(n) = self.ifaces[idx].neighbors.get_mut(&nbr_id) {
                        n.request_list.clear();
                        n.summary_sent = false;
                    }
                }
                _ => {}
            }
        }
    }

    // --- Database Description exchange (§10.8) -----------------------------

    /// Enter ExStart: pick a DD sequence and send the initial (I/M/MS, empty) DD.
    async fn start_dd_exchange(&mut self, idx: usize, nbr_id: Ipv4Addr) {
        let seq = self.alloc_dd_seq();
        let area = self.ifaces[idx].area;
        let options = self.area_options(area);
        let (sock, dst, bytes) = {
            let iface = &mut self.ifaces[idx];
            let Some(n) = iface.neighbors.get_mut(&nbr_id) else {
                return;
            };
            n.dd_seq = seq;
            n.master = true; // tentatively, until negotiation
            n.summary_sent = false;
            n.request_list.clear();
            let dd = DatabaseDescription {
                interface_mtu: 1500,
                options,
                flags: DD_FLAG_INIT | DD_FLAG_MORE | DD_FLAG_MASTER,
                dd_sequence: seq,
                lsa_headers: vec![],
            };
            (iface.sock.clone(), n.addr, self.dd_packet(area, dd))
        };
        info!(neighbor = %nbr_id, seq, "OSPF starting Database Exchange");
        send(&sock, dst, &bytes).await;
    }

    async fn handle_dd(&mut self, idx: usize, nbr_id: Ipv4Addr, dd: &DatabaseDescription) {
        let self_id = self.cfg.router_id;
        let state = match self.ifaces[idx].neighbors.get(&nbr_id) {
            Some(n) => n.fsm.state,
            None => return,
        };
        let is_init = dd.flags & DD_FLAG_INIT != 0
            && dd.flags & DD_FLAG_MORE != 0
            && dd.flags & DD_FLAG_MASTER != 0
            && dd.lsa_headers.is_empty();
        let recv_more = dd.flags & DD_FLAG_MORE != 0;

        match state {
            NeighborState::ExStart => {
                if is_init && u32::from(nbr_id) > u32::from(self_id) {
                    self.negotiation_done(idx, nbr_id, false, dd.dd_sequence)
                        .await;
                } else if dd.flags & DD_FLAG_INIT == 0
                    && dd.flags & DD_FLAG_MASTER == 0
                    && u32::from(nbr_id) < u32::from(self_id)
                {
                    let our_seq = self.ifaces[idx].neighbors[&nbr_id].dd_seq;
                    if dd.dd_sequence == our_seq {
                        self.process_dd_headers(idx, nbr_id, &dd.lsa_headers);
                        self.negotiation_done(idx, nbr_id, true, our_seq + 1).await;
                    }
                }
            }
            NeighborState::Exchange | NeighborState::Loading | NeighborState::Full => {
                self.exchange_dd(idx, nbr_id, dd, recv_more).await;
            }
            _ => {}
        }
    }

    /// Finish negotiation and send our first Exchange DD with the database summary.
    async fn negotiation_done(&mut self, idx: usize, nbr_id: Ipv4Addr, master: bool, seq: u32) {
        {
            let n = self.ifaces[idx].neighbors.get_mut(&nbr_id).unwrap();
            n.master = master;
            n.dd_seq = seq;
            n.fsm
                .handle(NeighborEvent::NegotiationDone, NeighborContext::default());
        }
        self.send_exchange_dd(idx, nbr_id).await;
    }

    /// Handle a DD packet while in Exchange and drive the lockstep to completion.
    async fn exchange_dd(
        &mut self,
        idx: usize,
        nbr_id: Ipv4Addr,
        dd: &DatabaseDescription,
        recv_more: bool,
    ) {
        let (master, our_seq, summary_sent) = {
            let n = &self.ifaces[idx].neighbors[&nbr_id];
            (n.master, n.dd_seq, n.summary_sent)
        };
        if master {
            if dd.dd_sequence != our_seq {
                return;
            }
            self.process_dd_headers(idx, nbr_id, &dd.lsa_headers);
            if summary_sent && !recv_more {
                self.exchange_done(idx, nbr_id).await;
            } else {
                self.ifaces[idx].neighbors.get_mut(&nbr_id).unwrap().dd_seq = our_seq + 1;
                self.send_exchange_dd(idx, nbr_id).await;
            }
        } else {
            if dd.dd_sequence == our_seq {
                self.send_exchange_dd(idx, nbr_id).await;
                return;
            }
            self.ifaces[idx].neighbors.get_mut(&nbr_id).unwrap().dd_seq = dd.dd_sequence;
            self.process_dd_headers(idx, nbr_id, &dd.lsa_headers);
            self.send_exchange_dd(idx, nbr_id).await;
            if !recv_more {
                self.exchange_done(idx, nbr_id).await;
            }
        }
    }

    /// Send an Exchange DD: our (area) database summary the first time, empty after.
    async fn send_exchange_dd(&mut self, idx: usize, nbr_id: Ipv4Addr) {
        let area = self.ifaces[idx].area;
        let options = self.area_options(area);
        let headers = self.db_headers(area);
        let (sock, dst, bytes) = {
            let iface = &mut self.ifaces[idx];
            let n = iface.neighbors.get_mut(&nbr_id).unwrap();
            let send_headers = if n.summary_sent { vec![] } else { headers };
            n.summary_sent = true;
            let mut flags = 0u8;
            if n.master {
                flags |= DD_FLAG_MASTER;
            }
            let dd = DatabaseDescription {
                interface_mtu: 1500,
                options,
                flags,
                dd_sequence: n.dd_seq,
                lsa_headers: send_headers,
            };
            (iface.sock.clone(), n.addr, self.dd_packet(area, dd))
        };
        send(&sock, dst, &bytes).await;
    }

    /// Note which of the neighbour's advertised LSAs we need (§10.6 / §10.9).
    fn process_dd_headers(&mut self, idx: usize, nbr_id: Ipv4Addr, headers: &[LsaHeader]) {
        let area = self.ifaces[idx].area;
        let needed: Vec<LsaKey> = headers
            .iter()
            .filter(|h| self.need_lsa(area, h))
            .map(|h| h.key())
            .collect();
        let n = self.ifaces[idx].neighbors.get_mut(&nbr_id).unwrap();
        for key in needed {
            if !n.request_list.contains(&key) {
                n.request_list.push(key);
            }
        }
    }

    /// Exchange finished: go to Full (request list empty) or Loading (send LSRs).
    async fn exchange_done(&mut self, idx: usize, nbr_id: Ipv4Addr) {
        let acts = {
            let n = self.ifaces[idx].neighbors.get_mut(&nbr_id).unwrap();
            let ctx = NeighborContext {
                adjacency_ok: true,
                request_list_empty: n.request_list.is_empty(),
            };
            n.fsm.handle(NeighborEvent::ExchangeDone, ctx)
        };
        let loading = self.ifaces[idx].neighbors[&nbr_id].fsm.state == NeighborState::Loading;
        if loading {
            self.send_lsr(idx, nbr_id).await;
        }
        self.act_on_neighbor(idx, nbr_id, acts).await;
    }

    // --- Link State Request / Update (§10.9, §13) -------------------------

    async fn send_lsr(&mut self, idx: usize, nbr_id: Ipv4Addr) {
        let area = self.ifaces[idx].area;
        let (sock, dst, bytes) = {
            let iface = &self.ifaces[idx];
            let n = &iface.neighbors[&nbr_id];
            if n.request_list.is_empty() {
                return;
            }
            let entries = n
                .request_list
                .iter()
                .map(|(ls_type, lsid, advr)| LsRequest {
                    ls_type: *ls_type,
                    link_state_id: *lsid,
                    advertising_router: *advr,
                })
                .collect();
            let pkt = self.packet(area, Body::LinkStateRequest(LinkStateRequest { entries }));
            (iface.sock.clone(), n.addr, pkt)
        };
        send(&sock, dst, &bytes).await;
    }

    /// Answer a neighbour's Link State Request with the requested LSAs (§10.9).
    async fn handle_lsr(&mut self, idx: usize, nbr_id: Ipv4Addr, req: &LinkStateRequest) {
        let area = self.ifaces[idx].area;
        let lsas: Vec<Lsa> = req
            .entries
            .iter()
            .filter_map(|e| {
                self.lsdb_for(area, e.ls_type).get(&(
                    e.ls_type,
                    e.link_state_id,
                    e.advertising_router,
                ))
            })
            .cloned()
            .collect();
        if lsas.is_empty() {
            return;
        }
        let dst = match self.ifaces[idx].neighbors.get(&nbr_id) {
            Some(n) => n.addr,
            None => return,
        };
        let sock = self.ifaces[idx].sock.clone();
        let bytes = self.packet(area, Body::LinkStateUpdate(LinkStateUpdate { lsas }));
        send(&sock, dst, &bytes).await;
    }

    /// Process a Link State Update (§13): install newer LSAs into the area
    /// database, acknowledge, pull the request list down, re-flood and re-run SPF.
    async fn handle_lsu(&mut self, idx: usize, nbr_id: Ipv4Addr, upd: LinkStateUpdate) {
        let self_id = self.cfg.router_id;
        let area = self.ifaces[idx].area;
        let src_addr = match self.ifaces[idx].neighbors.get(&nbr_id) {
            Some(n) => n.addr,
            None => return,
        };
        let mut installed = false;
        let mut ack_headers = Vec::new();
        let mut reflood_area = Vec::new();
        let mut reflood_ext = Vec::new();
        for lsa in upd.lsas {
            let is_ext = lsa.header.ls_type == LsType::AsExternal;
            // Stub and NSSA areas carry no AS-external (type-5) LSAs; drop any that
            // arrive on such an interface rather than installing or acking it.
            if is_ext && self.no_externals(area) {
                continue;
            }
            let on_request_list = self.ifaces[idx]
                .neighbors
                .get(&nbr_id)
                .map(|n| n.request_list.contains(&lsa.key()))
                .unwrap_or(false);
            let decision = {
                let input = FloodInput {
                    lsdb: self.lsdb_for(area, lsa.header.ls_type),
                    received: &lsa,
                    self_router_id: self_id,
                    db_copy_age_since_install: None,
                    on_request_list,
                    on_retransmit_list: false,
                    any_neighbor_exchanging: self.any_neighbor_exchanging(),
                };
                decide_flood(&input)
            };
            match decision {
                FloodDecision::Install { .. } => {
                    ack_headers.push(lsa.header);
                    let key = lsa.key();
                    let third_party = lsa.header.advertising_router != self_id;
                    if is_ext {
                        if third_party {
                            reflood_ext.push(lsa.clone());
                        }
                        self.external_lsdb.install(lsa);
                    } else {
                        if third_party {
                            reflood_area.push(lsa.clone());
                        }
                        self.areas.get_mut(&area).unwrap().lsdb.install(lsa);
                    }
                    self.drop_from_request_lists(&key);
                    installed = true;
                }
                FloodDecision::DirectAck => ack_headers.push(lsa.header),
                _ => {}
            }
        }

        if !ack_headers.is_empty() {
            let sock = self.ifaces[idx].sock.clone();
            let bytes = self.packet(
                area,
                Body::LinkStateAck(LinkStateAck {
                    lsa_headers: ack_headers,
                }),
            );
            send(&sock, src_addr, &bytes).await;
        }
        for lsa in &reflood_area {
            self.flood_lsa_except(area, lsa, src_addr).await;
        }
        for lsa in &reflood_ext {
            self.flood_external_except(lsa, src_addr).await;
        }

        let loading_done = {
            let n = self.ifaces[idx].neighbors.get(&nbr_id);
            n.map(|n| n.fsm.state == NeighborState::Loading && n.request_list.is_empty())
                .unwrap_or(false)
        };
        if loading_done {
            let acts = {
                let n = self.ifaces[idx].neighbors.get_mut(&nbr_id).unwrap();
                n.fsm
                    .handle(NeighborEvent::LoadingDone, NeighborContext::default())
            };
            self.act_on_neighbor(idx, nbr_id, acts).await;
        }

        if installed {
            // A changed area database can change the inter-area summaries an ABR
            // injects into the other areas, so recompute them too.
            self.originate_summaries().await;
            self.run_spf_and_announce().await;
        }
    }

    // --- LSA origination + flooding ---------------------------------------

    /// Build this router's Router-LSA for `area` from the interfaces in that area
    /// (sequence filled by [`Ospf::install_originated`]). The B-bit is set when we
    /// are an area border router.
    fn build_router_lsa(&self, area: Ipv4Addr) -> Lsa {
        let cost = self.cfg.cost;
        let stub = |iface: &Iface| RouterLink {
            link_id: iface.network(),
            link_data: len_to_mask(iface.mask_len),
            link_type: RouterLinkType::Stub,
            metric: cost,
        };
        let mut links = Vec::new();
        for iface in self.ifaces.iter().filter(|i| i.area == area) {
            if self.cfg.iface_type == InterfaceType::PointToPoint {
                for n in iface
                    .neighbors
                    .values()
                    .filter(|n| n.fsm.state == NeighborState::Full)
                {
                    links.push(RouterLink {
                        link_id: n.fsm.router_id,
                        link_data: iface.addr,
                        link_type: RouterLinkType::PointToPoint,
                        metric: cost,
                    });
                }
                links.push(stub(iface));
            } else if self.cfg.iface_type.elects_dr() {
                match self.transit_dr_addr(iface) {
                    Some(dr_addr) => links.push(RouterLink {
                        link_id: dr_addr,
                        link_data: iface.addr,
                        link_type: RouterLinkType::Transit,
                        metric: cost,
                    }),
                    None => links.push(stub(iface)),
                }
            } else {
                links.push(stub(iface));
            }
        }
        let mut flags = 0u8;
        if self.is_abr() {
            flags |= RTR_FLAG_B;
        }
        if self.is_asbr() {
            flags |= RTR_FLAG_E;
        }
        Lsa {
            header: self.self_header(LsType::Router, self.cfg.router_id),
            body: LsaBody::Router(RouterLsa { flags, links }),
        }
    }

    /// Whether this router redistributes external routes (an AS boundary router).
    fn is_asbr(&self) -> bool {
        !self.externals.is_empty()
    }

    /// (Re)originate this ASBR's AS-external (type-5) LSAs from [`Ospf::externals`]
    /// into the AS-wide database, flush those no longer present (MAX_AGE), and
    /// flood every change. Called at startup (no neighbours yet → the flood is a
    /// no-op and the LSAs propagate via Database Exchange) and on every
    /// redistribution change.
    async fn originate_externals(&mut self) {
        let mut to_flood = Vec::new();
        let mut want = HashSet::new();
        let externals: Vec<(Prefix, u32)> =
            self.externals.iter().map(|(p, m)| (*p, *m)).collect();
        for (prefix, metric) in externals {
            let net = match prefix.addr() {
                IpAddr::V4(a) => a,
                IpAddr::V6(_) => continue, // OSPFv2 is IPv4-only
            };
            let mut lsa = Lsa {
                header: self.self_header(LsType::AsExternal, net),
                body: LsaBody::AsExternal(AsExternalLsa {
                    network_mask: len_to_mask(prefix.len()),
                    external_type2: true,
                    metric,
                    forwarding_address: Ipv4Addr::UNSPECIFIED,
                    route_tag: 0,
                }),
            };
            let key = lsa.key();
            lsa.header.ls_seq = self.next_seq(AS_SCOPE, key);
            self.external_lsdb.install(lsa.clone());
            want.insert(key);
            to_flood.push(lsa);
        }
        // Flush externals we no longer originate (age them out AS-wide).
        let prev = self.originated_externals.clone();
        for key in prev.difference(&want) {
            if let Some(mut lsa) = self.external_lsdb.get(key).cloned() {
                lsa.header.ls_age = MAX_AGE;
                lsa.header.ls_seq = self.next_seq(AS_SCOPE, *key);
                self.external_lsdb.install(lsa.clone());
                to_flood.push(lsa);
            }
        }
        self.originated_externals = want;
        for lsa in &to_flood {
            self.flood_external_except(lsa, Ipv4Addr::UNSPECIFIED).await;
        }
        // The same destinations are also originated as NSSA type-7 LSAs into any
        // NSSA area we are attached to (RFC 3101 §2).
        self.originate_nssa().await;
    }

    /// Originate this ASBR's external destinations as NSSA type-7 LSAs into each
    /// not-so-stubby area it is attached to (RFC 3101 §2). The body is identical to
    /// a type-5; the area border router translates it to type-5 for the rest of the
    /// AS. The forwarding address is left `0.0.0.0` (forward via the originator),
    /// matching what the SPF resolves.
    async fn originate_nssa(&mut self) {
        let nssa_areas: Vec<Ipv4Addr> =
            self.areas.keys().copied().filter(|a| self.is_nssa(*a)).collect();
        for area in nssa_areas {
            let mut to_flood = Vec::new();
            let mut want = HashSet::new();
            let externals: Vec<(Prefix, u32)> =
                self.externals.iter().map(|(p, m)| (*p, *m)).collect();
            for (prefix, metric) in externals {
                let net = match prefix.addr() {
                    IpAddr::V4(a) => a,
                    IpAddr::V6(_) => continue,
                };
                let mut lsa = Lsa {
                    header: {
                        let mut h = self.self_header(LsType::Nssa, net);
                        h.options = OPT_NP; // the N/P-bit marks a type-7 (RFC 3101)
                        h
                    },
                    body: LsaBody::AsExternal(AsExternalLsa {
                        network_mask: len_to_mask(prefix.len()),
                        external_type2: true,
                        metric,
                        forwarding_address: Ipv4Addr::UNSPECIFIED,
                        route_tag: 0,
                    }),
                };
                let key = lsa.key();
                lsa.header.ls_seq = self.next_seq(area, key);
                self.areas.get_mut(&area).unwrap().lsdb.install(lsa.clone());
                want.insert(key);
                to_flood.push(lsa);
            }
            // Flush type-7 LSAs we no longer originate (age them out in the area).
            let prev = self.areas[&area].originated_nssa.clone();
            for key in prev.difference(&want) {
                if let Some(mut lsa) = self.areas[&area].lsdb.get(key).cloned() {
                    lsa.header.ls_age = MAX_AGE;
                    lsa.header.ls_seq = self.next_seq(area, *key);
                    self.areas.get_mut(&area).unwrap().lsdb.install(lsa.clone());
                    to_flood.push(lsa);
                }
            }
            self.areas.get_mut(&area).unwrap().originated_nssa = want;
            for lsa in &to_flood {
                self.flood_lsa(area, lsa).await;
            }
        }
    }

    /// Fold a redistribution change from the central router into the external set
    /// and re-originate. OSPFv2 is IPv4-only, so non-IPv4 routes are ignored. When
    /// the ASBR status flips (first external added / last removed) the Router-LSA's
    /// E-bit changes, so it (and the summaries) are re-originated too.
    async fn apply_redistribution(&mut self, r: Redistribution) {
        let was_asbr = self.is_asbr();
        match r {
            Redistribution::Announce(route) => {
                if !route.prefix.is_ipv4() {
                    return;
                }
                let metric = self.cfg.redistribute_metric;
                if self.externals.insert(route.prefix, metric) == Some(metric) {
                    return; // already redistributed at this metric — nothing to do
                }
                info!(prefix = %route.prefix, metric, "OSPF redistributing external route (type-5)");
            }
            Redistribution::Withdraw(prefix) => {
                if self.externals.remove(&prefix).is_none() {
                    return; // not one of ours
                }
                info!(%prefix, "OSPF withdrawing redistributed external route");
            }
        }
        if self.is_asbr() != was_asbr {
            // The E-bit on our Router-LSA just changed; re-flood it.
            self.reoriginate_and_flood().await;
        }
        self.originate_externals().await;
        self.run_spf_and_announce().await;
    }

    /// The DR's interface address on `iface` if we are fully adjacent to it.
    fn transit_dr_addr(&self, iface: &Iface) -> Option<Ipv4Addr> {
        let dr = iface.fsm.dr;
        if dr.is_unspecified() {
            return None;
        }
        let adjacent = if dr == self.cfg.router_id {
            iface
                .neighbors
                .values()
                .any(|n| n.fsm.state == NeighborState::Full)
        } else {
            iface
                .neighbors
                .get(&dr)
                .map(|n| n.fsm.state == NeighborState::Full)
                .unwrap_or(false)
        };
        adjacent.then(|| self.router_id_to_addr(iface, dr))
    }

    /// The Network-LSA we should originate for `idx` as its DR, or `None`.
    fn build_network_lsa(&self, idx: usize) -> Option<Lsa> {
        let iface = &self.ifaces[idx];
        if !iface.fsm.iface_type.elects_dr() || iface.fsm.dr != self.cfg.router_id {
            return None;
        }
        let mut attached = vec![self.cfg.router_id];
        for n in iface
            .neighbors
            .values()
            .filter(|n| n.fsm.state == NeighborState::Full)
        {
            attached.push(n.fsm.router_id);
        }
        if attached.len() < 2 {
            return None;
        }
        Some(Lsa {
            header: self.self_header(LsType::Network, iface.addr),
            body: LsaBody::Network(NetworkLsa {
                network_mask: len_to_mask(iface.mask_len),
                attached_routers: attached,
            }),
        })
    }

    /// A type-3 Summary-LSA describing `prefix` at `cost`.
    fn build_summary_lsa(&self, prefix: Prefix, cost: u32) -> Lsa {
        let net = match prefix.addr() {
            IpAddr::V4(a) => a,
            IpAddr::V6(_) => Ipv4Addr::UNSPECIFIED, // OSPFv2 is IPv4-only
        };
        Lsa {
            header: self.self_header(LsType::SummaryNetwork, net),
            body: LsaBody::Summary(SummaryLsa {
                network_mask: len_to_mask(prefix.len()),
                metric: cost,
            }),
        }
    }

    /// A header for an LSA we originate (sequence/checksum/length filled later).
    fn self_header(&self, ls_type: LsType, link_state_id: Ipv4Addr) -> LsaHeader {
        LsaHeader {
            ls_age: 0,
            options: OPT_E,
            ls_type,
            link_state_id,
            advertising_router: self.cfg.router_id,
            ls_seq: 0,
            ls_checksum: 0,
            length: 0,
        }
    }

    /// Set the next sequence number for `lsa` in `area`, install it and return it.
    fn install_originated(&mut self, area: Ipv4Addr, mut lsa: Lsa) -> Lsa {
        let key = lsa.key();
        lsa.header.ls_seq = self.next_seq(area, key);
        self.areas.get_mut(&area).unwrap().lsdb.install(lsa.clone());
        lsa
    }

    /// Re-originate all of this router's LSAs into every area (Router-LSA, the
    /// Network-LSAs it is DR for, and — as an ABR — the inter-area Summary-LSAs),
    /// flushing those it should no longer originate, and flood each.
    async fn reoriginate_and_flood(&mut self) {
        let areas: Vec<Ipv4Addr> = self.areas.keys().copied().collect();
        for area in areas {
            let mut to_flood = Vec::new();
            let rl = self.build_router_lsa(area);
            to_flood.push(self.install_originated(area, rl));

            let mut want = HashSet::new();
            for idx in 0..self.ifaces.len() {
                if self.ifaces[idx].area != area {
                    continue;
                }
                if let Some(lsa) = self.build_network_lsa(idx) {
                    want.insert(lsa.key());
                    to_flood.push(self.install_originated(area, lsa));
                }
            }
            let prev = self.areas[&area].originated_networks.clone();
            for key in prev.difference(&want) {
                if let Some(mut lsa) = self.areas[&area].lsdb.get(key).cloned() {
                    lsa.header.ls_age = MAX_AGE;
                    to_flood.push(self.install_originated(area, lsa));
                }
            }
            self.areas.get_mut(&area).unwrap().originated_networks = want;

            for lsa in &to_flood {
                self.flood_lsa(area, lsa).await;
            }
        }
        self.originate_summaries().await;
    }

    /// Originate the inter-area Summary-LSAs (§12.4.3) an area border router
    /// injects: into the backbone, every non-backbone area's intra-area routes;
    /// into each non-backbone area, the backbone's — the §16 condensation that
    /// keeps inter-area routing loop-free.
    async fn originate_summaries(&mut self) {
        if !self.is_abr() {
            return;
        }
        let areas: Vec<Ipv4Addr> = self.areas.keys().copied().collect();
        let mut intra: BTreeMap<Ipv4Addr, Vec<SpfRoute>> = BTreeMap::new();
        for a in &areas {
            intra.insert(
                *a,
                spf::compute(&self.areas[a].lsdb, self.cfg.router_id).routes,
            );
        }

        for &dest in &areas {
            let sources: Vec<Ipv4Addr> = if dest == BACKBONE {
                areas.iter().copied().filter(|a| *a != BACKBONE).collect()
            } else {
                areas.iter().copied().filter(|a| *a == BACKBONE).collect()
            };
            // The lowest cost to each destination network from the source areas.
            let mut want_routes: BTreeMap<Prefix, u32> = BTreeMap::new();
            for src in &sources {
                for r in &intra[src] {
                    let slot = want_routes.entry(r.prefix).or_insert(r.cost);
                    *slot = (*slot).min(r.cost);
                }
            }
            // Into a totally-stubby / totally-NSSA ("no-summary") area the ABR
            // suppresses the inter-area type-3 summaries entirely — the injected
            // default below (a type-3 default for a stub, a type-7 default for an
            // NSSA) stands in for every destination outside the area.
            if self.no_summary(dest) {
                want_routes.clear();
            }
            // Into a stub area (RFC 2328 §3.6) the ABR injects a default route in
            // place of the AS-external LSAs the area never sees — a type-3 summary
            // for 0.0.0.0/0 at the configured cost. For a plain stub the ordinary
            // inter-area summaries are still sent too; a totally-stubby area cleared
            // them just above, so only this default remains.
            if self.is_stub(dest) {
                if let Ok(default) = Prefix::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0) {
                    want_routes.insert(default, self.cfg.stub_default_cost);
                }
            }

            let mut to_flood = Vec::new();
            let mut want_keys = HashSet::new();
            for (prefix, cost) in &want_routes {
                let lsa = self.build_summary_lsa(*prefix, *cost);
                want_keys.insert(lsa.key());
                to_flood.push(self.install_originated(dest, lsa));
            }
            let prev = self.areas[&dest].originated_summaries.clone();
            for key in prev.difference(&want_keys) {
                if let Some(mut lsa) = self.areas[&dest].lsdb.get(key).cloned() {
                    lsa.header.ls_age = MAX_AGE;
                    to_flood.push(self.install_originated(dest, lsa));
                }
            }
            self.areas.get_mut(&dest).unwrap().originated_summaries = want_keys;

            for lsa in &to_flood {
                self.flood_lsa(dest, lsa).await;
            }
        }
        // As an ABR, inject the type-7 default into any totally-NSSA area, and
        // translate any NSSA type-7 LSAs to type-5 for the rest of the AS.
        self.originate_nssa_default().await;
        self.translate_nssa().await;
    }

    /// Inject a type-7 default route (`0.0.0.0/0`) into each NSSA that wants one, as
    /// its area border router. Two kinds want it (see [`Ospf::wants_nssa_default`]): a
    /// **totally-NSSA**, which carries neither AS-external (type-5) nor inter-area
    /// (type-3) summaries, so its internal routers reach every destination outside the
    /// area through this default; and a **plain NSSA** listed in `nssa-default-areas`
    /// (RFC 3101 §2.3), which keeps its summaries but still needs a path to the
    /// AS-external destinations an NSSA never carries. The injected LSA is identical in
    /// both cases — the P-bit is left clear (`options = 0`) so the ABR does **not**
    /// translate the default into a type-5 for the rest of the AS. Reached only after
    /// the `is_abr` guard in [`Ospf::originate_summaries`], so only an ABR injects it;
    /// the cost is the same `stub_default_cost` a stub default uses.
    async fn originate_nssa_default(&mut self) {
        let areas: Vec<Ipv4Addr> =
            self.areas.keys().copied().filter(|a| self.wants_nssa_default(*a)).collect();
        for area in areas {
            let lsa = Lsa {
                header: {
                    let mut h = self.self_header(LsType::Nssa, Ipv4Addr::UNSPECIFIED);
                    h.options = 0; // P-bit clear: never translate the default AS-wide
                    h
                },
                body: LsaBody::AsExternal(AsExternalLsa {
                    network_mask: len_to_mask(0),
                    external_type2: true,
                    metric: self.cfg.stub_default_cost,
                    forwarding_address: Ipv4Addr::UNSPECIFIED,
                    route_tag: 0,
                }),
            };
            let lsa = self.install_originated(area, lsa);
            self.flood_lsa(area, &lsa).await;
        }
    }

    /// Translate the NSSA type-7 LSAs held in each not-so-stubby area into AS-external
    /// type-5 LSAs and flood them into the rest of the AS (RFC 3101 §3.2). Only an
    /// ABR translates (this is reached only after the `is_abr` guard in
    /// [`Ospf::originate_summaries`]). The single-ABR case here translates every
    /// reachable, non-self type-7 — the §3.2 translator election (highest Router ID,
    /// P-bit gating) is a refinement left for later. The forwarding address is
    /// carried through unchanged (`0.0.0.0` ⇒ forward via us, the translator).
    async fn translate_nssa(&mut self) {
        let nssa_areas: Vec<Ipv4Addr> =
            self.areas.keys().copied().filter(|a| self.is_nssa(*a)).collect();
        let mut to_flood = Vec::new();
        let mut want = HashSet::new();
        for area in &nssa_areas {
            let sevens: Vec<Lsa> = self.areas[area]
                .lsdb
                .iter_type(LsType::Nssa)
                .filter(|l| {
                    l.header.advertising_router != self.cfg.router_id
                        && l.header.ls_age < MAX_AGE
                })
                .cloned()
                .collect();
            for seven in sevens {
                let LsaBody::AsExternal(ext) = seven.body else {
                    continue;
                };
                let mut lsa = Lsa {
                    header: self.self_header(LsType::AsExternal, seven.header.link_state_id),
                    body: LsaBody::AsExternal(ext),
                };
                let key = lsa.key();
                lsa.header.ls_seq = self.next_seq(AS_SCOPE, key);
                self.external_lsdb.install(lsa.clone());
                want.insert(key);
                to_flood.push(lsa);
            }
        }
        // Flush translations we no longer originate (age them out AS-wide).
        let prev = self.originated_translated.clone();
        for key in prev.difference(&want) {
            if let Some(mut lsa) = self.external_lsdb.get(key).cloned() {
                lsa.header.ls_age = MAX_AGE;
                lsa.header.ls_seq = self.next_seq(AS_SCOPE, *key);
                self.external_lsdb.install(lsa.clone());
                to_flood.push(lsa);
            }
        }
        self.originated_translated = want;
        for lsa in &to_flood {
            self.flood_external_except(lsa, Ipv4Addr::UNSPECIFIED).await;
        }
    }

    /// On reaching Full: re-originate our LSAs, flood them and re-run SPF.
    async fn on_adjacency_full(&mut self, idx: usize, nbr_id: Ipv4Addr) {
        info!(interface = %self.ifaces[idx].name, neighbor = %nbr_id, "OSPF adjacency Full");
        self.reoriginate_and_flood().await;
        self.run_spf_and_announce().await;
    }

    /// Flood one LSA to every Full neighbour on an interface in `area`.
    async fn flood_lsa(&self, area: Ipv4Addr, lsa: &Lsa) {
        self.flood_lsa_except(area, lsa, Ipv4Addr::UNSPECIFIED)
            .await;
    }

    /// Flood one LSA to every Full neighbour in `area` except the one at `except`.
    async fn flood_lsa_except(&self, area: Ipv4Addr, lsa: &Lsa, except: Ipv4Addr) {
        let bytes = self.packet(
            area,
            Body::LinkStateUpdate(LinkStateUpdate {
                lsas: vec![lsa.clone()],
            }),
        );
        for iface in self.ifaces.iter().filter(|i| i.area == area) {
            for n in iface.neighbors.values() {
                if n.fsm.state == NeighborState::Full && n.addr != except {
                    send(&iface.sock, n.addr, &bytes).await;
                }
            }
        }
    }

    /// Flood an AS-external (type-5) LSA AS-wide: to every Full neighbour in every
    /// area except the one at `except`.
    async fn flood_external_except(&self, lsa: &Lsa, except: Ipv4Addr) {
        for iface in &self.ifaces {
            // Stub and NSSA areas never receive AS-external (type-5) LSAs.
            if self.no_externals(iface.area) {
                continue;
            }
            let bytes = self.packet(
                iface.area,
                Body::LinkStateUpdate(LinkStateUpdate {
                    lsas: vec![lsa.clone()],
                }),
            );
            for n in iface.neighbors.values() {
                if n.fsm.state == NeighborState::Full && n.addr != except {
                    send(&iface.sock, n.addr, &bytes).await;
                }
            }
        }
    }

    // --- SPF → RIB --------------------------------------------------------

    /// Run an SPF per area, fold in the inter-area routes (§16.2) and reconcile
    /// the announced routes with the router. Intra-area routes win over inter-area
    /// (§16): a prefix reachable intra-area is never overridden by a summary.
    async fn run_spf_and_announce(&mut self) {
        let areas: Vec<Ipv4Addr> = self.areas.keys().copied().collect();
        let mut chosen: BTreeMap<Prefix, SpfRoute> = BTreeMap::new();
        // The best reachability to each router across areas (for the external calc).
        let mut merged = spf::SpfResult::default();

        // Intra-area routes (best by cost across areas).
        for area in &areas {
            let res = spf::compute(&self.areas[area].lsdb, self.cfg.router_id);
            for (rid, cost) in &res.routers {
                match merged.routers.get(rid) {
                    Some(c) if *c <= *cost => {}
                    _ => {
                        merged.routers.insert(*rid, *cost);
                        merged.router_nexthops.insert(
                            *rid,
                            res.router_nexthops.get(rid).cloned().unwrap_or_default(),
                        );
                    }
                }
            }
            for r in res.routes {
                match chosen.get(&r.prefix) {
                    Some(e) if e.cost <= r.cost => {}
                    _ => {
                        chosen.insert(r.prefix, r);
                    }
                }
            }
        }
        let intra_prefixes: HashSet<Prefix> = chosen.keys().copied().collect();

        // Inter-area routes: an ABR examines only the backbone; a non-ABR its area.
        let inter_src = if self.is_abr() {
            self.areas.contains_key(&BACKBONE).then_some(BACKBONE)
        } else {
            areas.first().copied()
        };
        if let Some(area) = inter_src {
            let res = spf::compute(&self.areas[&area].lsdb, self.cfg.router_id);
            for r in spf::inter_area_routes(&self.areas[&area].lsdb, &res, self.cfg.router_id) {
                if intra_prefixes.contains(&r.prefix) {
                    continue; // intra-area wins
                }
                match chosen.get(&r.prefix) {
                    Some(e) if e.cost <= r.cost => {}
                    _ => {
                        chosen.insert(r.prefix, r);
                    }
                }
            }
        }

        // AS-external routes (§16.4) — least preferred: only for prefixes not
        // already covered by an intra- or inter-area route.
        for r in spf::external_routes(&self.external_lsdb, &merged, self.cfg.router_id) {
            chosen.entry(r.prefix).or_insert(r);
        }
        // NSSA type-7 externals (RFC 3101): the type-7 LSAs in each NSSA area's own
        // database, computed like AS-externals. A router inside an NSSA reaches its
        // externals this way without the type-5s the area never receives.
        for area in &areas {
            if self.is_nssa(*area) {
                for r in spf::nssa_routes(&self.areas[area].lsdb, &merged, self.cfg.router_id) {
                    chosen.entry(r.prefix).or_insert(r);
                }
            }
        }

        let new_prefixes: HashSet<Prefix> = chosen.keys().copied().collect();
        for r in chosen.values() {
            let _ = self.updates.send(RouteUpdate::Announce(r.to_route())).await;
        }
        let gone: Vec<Prefix> = self.announced.difference(&new_prefixes).copied().collect();
        for prefix in gone {
            let _ = self
                .updates
                .send(RouteUpdate::Withdraw {
                    prefix,
                    protocol: wren_core::Protocol::Ospf,
                    source: 0,
                })
                .await;
        }
        self.announced = new_prefixes;
    }

    // --- Timers -----------------------------------------------------------

    async fn age_neighbors(&mut self, now: u64) {
        let dead_interval = self.cfg.dead_interval as u64;
        let mut changed = false;
        for idx in 0..self.ifaces.len() {
            let dead: Vec<Ipv4Addr> = self.ifaces[idx]
                .neighbors
                .iter()
                .filter(|(_, n)| now.saturating_sub(n.last_seen) >= dead_interval)
                .map(|(id, _)| *id)
                .collect();
            for id in dead {
                if let Some(mut n) = self.ifaces[idx].neighbors.remove(&id) {
                    n.fsm
                        .handle(NeighborEvent::InactivityTimer, NeighborContext::default());
                    info!(interface = %self.ifaces[idx].name, neighbor = %id, "OSPF neighbour dead (inactivity)");
                    changed = true;
                }
                if self.run_interface_event(idx, InterfaceEvent::NeighborChange) {
                    self.reeval_adjacencies(idx).await;
                }
            }
        }
        if changed {
            self.reoriginate_and_flood().await;
            self.run_spf_and_announce().await;
        }
    }

    /// Keep the BFD (RFC 5880) registrations in step with the set of **Full**
    /// neighbours: register a session as a neighbour reaches Full, deregister it as
    /// the neighbour leaves Full or disappears. A no-op unless `[ospf] bfd` is set.
    /// The BFD engine reports a session going down on [`Self::bfd_notify`], which the
    /// run loop turns into [`Self::force_neighbor_down`].
    async fn reconcile_bfd(&mut self) {
        if !self.cfg.bfd {
            return;
        }
        let mut full: HashSet<Ipv4Addr> = HashSet::new();
        for iface in &self.ifaces {
            for n in iface.neighbors.values() {
                if n.fsm.state == NeighborState::Full {
                    full.insert(n.addr);
                }
            }
        }
        let added: Vec<Ipv4Addr> = full.difference(&self.bfd_registered).copied().collect();
        for peer in added {
            let _ = self
                .bfd_register
                .send(crate::bfd::BfdCommand::Register {
                    peer,
                    consumer: crate::bfd::BfdConsumer::Ospf,
                    notify: self.bfd_notify.clone(),
                })
                .await;
        }
        let removed: Vec<Ipv4Addr> = self.bfd_registered.difference(&full).copied().collect();
        for peer in removed {
            let _ = self
                .bfd_register
                .send(crate::bfd::BfdCommand::Deregister {
                    peer,
                    consumer: crate::bfd::BfdConsumer::Ospf,
                })
                .await;
        }
        self.bfd_registered = full;
    }

    /// Tear down the adjacency to the neighbour at `peer` (a BFD-reported path
    /// failure), mirroring [`Self::age_neighbors`]: remove the neighbour, drive its
    /// FSM down, re-run the interface's DR election and adjacency evaluation, and
    /// re-originate / re-run SPF. The BFD reconcile then drops the stale session.
    async fn force_neighbor_down(&mut self, peer: Ipv4Addr) {
        let mut changed = false;
        for idx in 0..self.ifaces.len() {
            let id = self.ifaces[idx]
                .neighbors
                .iter()
                .find(|(_, n)| n.addr == peer)
                .map(|(id, _)| *id);
            let Some(id) = id else { continue };
            if let Some(mut n) = self.ifaces[idx].neighbors.remove(&id) {
                n.fsm.handle(NeighborEvent::InactivityTimer, NeighborContext::default());
                info!(interface = %self.ifaces[idx].name, neighbor = %id, %peer, "OSPF neighbour down (BFD)");
                changed = true;
            }
            if self.run_interface_event(idx, InterfaceEvent::NeighborChange) {
                self.reeval_adjacencies(idx).await;
            }
        }
        if changed {
            self.reoriginate_and_flood().await;
            self.run_spf_and_announce().await;
        }
    }

    /// Resend the initial (I/M/MS) Database Description to any neighbour still in
    /// ExStart, so a lost or crossed init does not deadlock the negotiation.
    async fn retransmit_init_dds(&mut self) {
        let mut out = Vec::new();
        for iface in &self.ifaces {
            for n in iface.neighbors.values() {
                if n.fsm.state == NeighborState::ExStart {
                    let dd = DatabaseDescription {
                        interface_mtu: 1500,
                        options: self.area_options(iface.area),
                        flags: DD_FLAG_INIT | DD_FLAG_MORE | DD_FLAG_MASTER,
                        dd_sequence: n.dd_seq,
                        lsa_headers: vec![],
                    };
                    out.push((iface.sock.clone(), n.addr, self.dd_packet(iface.area, dd)));
                }
            }
        }
        for (sock, dst, bytes) in out {
            send(&sock, dst, &bytes).await;
        }
    }

    async fn fire_wait_timers(&mut self, now: u64) {
        for idx in 0..self.ifaces.len() {
            if let Some(deadline) = self.ifaces[idx].wait_deadline {
                if now >= deadline && self.ifaces[idx].fsm.state == InterfaceState::Waiting {
                    self.ifaces[idx].wait_deadline = None;
                    if self.run_interface_event(idx, InterfaceEvent::WaitTimer) {
                        self.reeval_adjacencies(idx).await;
                    }
                }
            }
        }
    }

    async fn send_hellos(&self) {
        for iface in &self.ifaces {
            let hello = Hello {
                network_mask: len_to_mask(iface.mask_len),
                hello_interval: self.cfg.hello_interval,
                // The E-bit advertises AS-external capability; it is cleared in a
                // stub area so two stub routers agree (RFC 2328 §3.6, §9.5).
                options: self.area_options(iface.area),
                router_priority: iface.fsm.priority,
                dead_interval: self.cfg.dead_interval,
                designated_router: self.router_id_to_addr(iface, iface.fsm.dr),
                backup_designated_router: self.router_id_to_addr(iface, iface.fsm.bdr),
                neighbors: iface
                    .neighbors
                    .values()
                    .filter(|n| n.fsm.state >= NeighborState::Init)
                    .map(|n| n.fsm.router_id)
                    .collect(),
            };
            let header = Header {
                router_id: self.cfg.router_id,
                area_id: iface.area,
            };
            let bytes = Packet::hello(header, hello).encode_auth(&self.send_auth());
            send(&iface.sock, ALL_SPF_ROUTERS, &bytes).await;
        }
    }

    // --- Helpers ----------------------------------------------------------

    fn iface_index(&self, ifindex: u32) -> Option<usize> {
        self.ifaces.iter().position(|i| i.ifindex == ifindex)
    }

    /// Whether `area` is configured as a stub area (RFC 2328 §3.6): no AS-external
    /// LSAs, the E-bit cleared in Hellos, an ABR-injected default route.
    fn is_stub(&self, area: Ipv4Addr) -> bool {
        self.cfg.stub_areas.contains(&area)
    }

    /// Whether `area` is configured as a not-so-stubby area (NSSA, RFC 3101).
    fn is_nssa(&self, area: Ipv4Addr) -> bool {
        self.cfg.nssa_areas.contains(&area)
    }

    /// Whether `area` is a totally-stubby area (a "no-summary" stub).
    fn is_totally_stubby(&self, area: Ipv4Addr) -> bool {
        self.cfg.totally_stubby_areas.contains(&area)
    }

    /// Whether `area` is a totally-NSSA area (a "no-summary" NSSA).
    fn is_totally_nssa(&self, area: Ipv4Addr) -> bool {
        self.cfg.totally_nssa_areas.contains(&area)
    }

    /// Whether an ABR should inject a type-7 default route (`0.0.0.0/0`) into `area` —
    /// true both for a totally-NSSA (where the default stands in for the suppressed
    /// summaries and externals) and for a plain NSSA explicitly listed in
    /// `nssa-default-areas` (RFC 3101 §2.3), which keeps its summaries but still needs
    /// a path to the AS-external destinations an NSSA never carries.
    fn wants_nssa_default(&self, area: Ipv4Addr) -> bool {
        self.is_totally_nssa(area) || self.cfg.nssa_default_areas.contains(&area)
    }

    /// Whether an ABR should suppress inter-area (type-3) summaries into `area` —
    /// true for both totally-stubby and totally-NSSA "no-summary" areas, whose
    /// internal routers reach everything outside the area through an injected
    /// default instead.
    fn no_summary(&self, area: Ipv4Addr) -> bool {
        self.is_totally_stubby(area) || self.is_totally_nssa(area)
    }

    /// Whether `area` carries no AS-external (type-5) LSAs — true for both stub and
    /// NSSA areas, which differ only in that an NSSA also carries type-7.
    fn no_externals(&self, area: Ipv4Addr) -> bool {
        self.is_stub(area) || self.is_nssa(area)
    }

    /// The OSPF Options for packets exchanged in `area`: the E-bit (AS-external
    /// capable) is set only in a normal area, and the N-bit (NSSA-capable) only in
    /// an NSSA. The relevant bits must match across Hellos *and* Database
    /// Description packets for an adjacency to form (RFC 2328 §3.6, RFC 3101).
    fn area_options(&self, area: Ipv4Addr) -> u8 {
        if self.is_nssa(area) {
            OPT_NP
        } else if self.is_stub(area) {
            0
        } else {
            OPT_E
        }
    }

    /// Whether this router has interfaces in more than one area.
    fn is_abr(&self) -> bool {
        let mut seen: Option<Ipv4Addr> = None;
        for i in &self.ifaces {
            match seen {
                None => seen = Some(i.area),
                Some(a) if a != i.area => return true,
                _ => {}
            }
        }
        false
    }

    fn alloc_dd_seq(&mut self) -> u32 {
        self.next_dd_seq = self.next_dd_seq.wrapping_add(1);
        self.next_dd_seq
    }

    /// The next LS sequence number for the LSA `key` in `area`.
    fn next_seq(&mut self, area: Ipv4Addr, key: LsaKey) -> i32 {
        let slot = self
            .lsa_seqs
            .entry((area, key))
            .or_insert(INITIAL_SEQUENCE_NUMBER);
        let v = *slot;
        *slot = slot.wrapping_add(1);
        v
    }

    /// The database that holds `ls_type`: the AS-wide external database for
    /// type-5, otherwise the area's database.
    fn lsdb_for(&self, area: Ipv4Addr, ls_type: LsType) -> &Lsdb {
        if ls_type == LsType::AsExternal {
            &self.external_lsdb
        } else {
            &self.areas[&area].lsdb
        }
    }

    /// Whether the relevant database lacks an instance of `h` at least as recent.
    fn need_lsa(&self, area: Ipv4Addr, h: &LsaHeader) -> bool {
        match self.lsdb_for(area, h.ls_type).header(&h.key()) {
            None => true,
            Some(cur) => h.compare_recency(cur) == std::cmp::Ordering::Greater,
        }
    }

    fn any_neighbor_exchanging(&self) -> bool {
        self.ifaces.iter().any(|i| {
            i.neighbors.values().any(|n| {
                matches!(
                    n.fsm.state,
                    NeighborState::Exchange | NeighborState::Loading
                )
            })
        })
    }

    /// Every LSA header to describe on an adjacency in `area`: the area's own
    /// database plus the AS-wide external (type-5) LSAs.
    fn db_headers(&self, area: Ipv4Addr) -> Vec<LsaHeader> {
        let mut headers: Vec<LsaHeader> =
            self.areas[&area].lsdb.iter().map(|l| l.header).collect();
        // Stub and NSSA areas carry no AS-external (type-5) LSAs, so they are left
        // out of the Database Description too — otherwise a neighbour would request
        // a type-5 we will never flood into the area and stall in Loading. (A type-7
        // LSA lives in the area lsdb above, so an NSSA still summarises those.)
        if !self.no_externals(area) {
            headers.extend(self.external_lsdb.iter().map(|l| l.header));
        }
        headers
    }

    fn drop_from_request_lists(&mut self, key: &LsaKey) {
        for iface in &mut self.ifaces {
            for n in iface.neighbors.values_mut() {
                n.request_list.retain(|k| k != key);
            }
        }
    }

    fn packet(&self, area: Ipv4Addr, body: Body) -> Vec<u8> {
        let header = Header {
            router_id: self.cfg.router_id,
            area_id: area,
        };
        Packet { header, body }.encode_auth(&self.send_auth())
    }

    /// The authentication to stamp on an outgoing packet. Null and simple-password
    /// auth are used verbatim; for MD5 the configured key is reused but the sequence
    /// number is set to the current wall-clock seconds, which is non-decreasing across
    /// the session (RFC 2328 §D.3 requires a monotonic sequence per packet).
    fn send_auth(&self) -> Auth {
        match &self.cfg.auth {
            Auth::Md5 { key_id, key, .. } => Auth::Md5 {
                key_id: *key_id,
                key: key.clone(),
                seq: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs() as u32)
                    .unwrap_or(0),
            },
            other => other.clone(),
        }
    }

    fn dd_packet(&self, area: Ipv4Addr, dd: DatabaseDescription) -> Vec<u8> {
        self.packet(area, Body::DatabaseDescription(dd))
    }

    fn addr_to_router_id(&self, idx: usize, addr: Ipv4Addr) -> Ipv4Addr {
        let iface = &self.ifaces[idx];
        if addr.is_unspecified() {
            Ipv4Addr::UNSPECIFIED
        } else if addr == iface.addr {
            self.cfg.router_id
        } else {
            iface
                .neighbors
                .values()
                .find(|n| n.addr == addr)
                .map(|n| n.fsm.router_id)
                .unwrap_or(Ipv4Addr::UNSPECIFIED)
        }
    }

    fn router_id_to_addr(&self, iface: &Iface, rid: Ipv4Addr) -> Ipv4Addr {
        if rid.is_unspecified() {
            Ipv4Addr::UNSPECIFIED
        } else if rid == self.cfg.router_id {
            iface.addr
        } else {
            iface
                .neighbors
                .get(&rid)
                .map(|n| n.addr)
                .unwrap_or(Ipv4Addr::UNSPECIFIED)
        }
    }
}

/// The 2-Way-or-better neighbours as election candidates (§9.4).
fn candidates(iface: &Iface) -> Vec<Candidate> {
    iface
        .neighbors
        .values()
        .filter(|n| n.fsm.is_bidirectional())
        .map(|n| Candidate {
            router_id: n.fsm.router_id,
            priority: n.fsm.priority,
            declared_dr: n.fsm.declared_dr,
            declared_bdr: n.fsm.declared_bdr,
        })
        .collect()
}

/// Send `bytes` to `dst` (port-less raw IP), warning on error.
async fn send(sock: &UdpSocket, dst: Ipv4Addr, bytes: &[u8]) {
    if let Err(e) = sock.send_to(bytes, (dst, 0)).await {
        warn!(%dst, error = %e, "sending OSPF packet");
    }
}

/// Spawn a task reading raw OSPF datagrams from one interface into `pkt_tx`.
fn spawn_receiver(sock: Arc<UdpSocket>, ifindex: u32, pkt_tx: mpsc::Sender<RawPacket>) {
    tokio::spawn(async move {
        let mut buf = vec![0u8; RECV_BUF];
        loop {
            match sock.recv_from(&mut buf).await {
                Ok((n, SocketAddr::V4(src))) => {
                    let pkt = RawPacket {
                        ifindex,
                        src: *src.ip(),
                        data: buf[..n].to_vec(),
                    };
                    if pkt_tx.send(pkt).await.is_err() {
                        break;
                    }
                }
                Ok((_, SocketAddr::V6(_))) => {}
                Err(e) => {
                    warn!(ifindex, error = %e, "OSPF receive failed");
                    break;
                }
            }
        }
    });
}

/// The OSPF payload of a received raw IPv4 datagram (skip the IP header by IHL).
fn strip_ip_header(data: &[u8]) -> Option<&[u8]> {
    if data.len() < 20 || (data[0] >> 4) != 4 {
        return None;
    }
    let ihl = (data[0] & 0x0f) as usize * 4;
    if ihl < 20 || data.len() < ihl {
        return None;
    }
    Some(&data[ihl..])
}

/// The contiguous IPv4 netmask for a prefix length.
fn len_to_mask(len: u8) -> Ipv4Addr {
    let bits = if len == 0 {
        0
    } else {
        u32::MAX << (32 - len as u32)
    };
    Ipv4Addr::from(bits)
}

// ---------------------------------------------------------------------------
// Socket + interface-address setup (libc, like the RIP runner).
// ---------------------------------------------------------------------------

fn open_ospf_socket(ifname: &str) -> Result<(u32, std::net::UdpSocket)> {
    let cname = std::ffi::CString::new(ifname).context("interface name has an interior NUL")?;
    // SAFETY: `cname` is a valid NUL-terminated string for the call's duration.
    let ifindex = unsafe { libc::if_nametoindex(cname.as_ptr()) };
    if ifindex == 0 {
        anyhow::bail!("interface {ifname:?} not found");
    }

    // SAFETY: a raw socket; the fd is taken into ownership immediately below.
    let fd = unsafe {
        libc::socket(
            libc::AF_INET,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
            IP_PROTOCOL as libc::c_int,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error())
            .context("socket(AF_INET, SOCK_RAW, 89) — needs CAP_NET_RAW");
    }
    // SAFETY: `fd` was just returned by socket() and is owned by nobody else.
    let sock = unsafe { std::net::UdpSocket::from_raw_fd(fd) };

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

    join_group(fd, ALL_SPF_ROUTERS, ifindex).context("IP_ADD_MEMBERSHIP 224.0.0.5")?;
    join_group(fd, ALL_D_ROUTERS, ifindex).context("IP_ADD_MEMBERSHIP 224.0.0.6")?;
    // SAFETY: ip_mreqn is plain POD; all fields are filled.
    let mut mreq: libc::ip_mreqn = unsafe { mem::zeroed() };
    mreq.imr_ifindex = ifindex as libc::c_int;
    setsockopt_struct(fd, libc::IPPROTO_IP, libc::IP_MULTICAST_IF, &mreq)
        .context("IP_MULTICAST_IF")?;
    setsockopt_int(fd, libc::IPPROTO_IP, libc::IP_MULTICAST_LOOP, 0)?;
    setsockopt_int(fd, libc::IPPROTO_IP, libc::IP_MULTICAST_TTL, 1)?;

    Ok((ifindex, sock))
}

fn join_group(fd: i32, group: Ipv4Addr, ifindex: u32) -> Result<()> {
    // SAFETY: ip_mreqn is plain POD; we set the group and interface index.
    let mut mreq: libc::ip_mreqn = unsafe { mem::zeroed() };
    mreq.imr_multiaddr.s_addr = u32::from(group).to_be();
    mreq.imr_ifindex = ifindex as libc::c_int;
    setsockopt_struct(fd, libc::IPPROTO_IP, libc::IP_ADD_MEMBERSHIP, &mreq)
}

/// The primary IPv4 address and prefix length of `ifname`, via `getifaddrs`.
fn iface_ipv4(ifname: &str) -> Option<(Ipv4Addr, u8)> {
    let mut head: *mut libc::ifaddrs = std::ptr::null_mut();
    // SAFETY: getifaddrs allocates a list into `head`; freed below.
    if unsafe { libc::getifaddrs(&mut head) } != 0 {
        return None;
    }
    let mut result = None;
    let mut cur = head;
    while !cur.is_null() {
        // SAFETY: `cur` is a non-null node in the kernel-provided list.
        let ifa = unsafe { &*cur };
        cur = ifa.ifa_next;
        if ifa.ifa_addr.is_null() || ifa.ifa_netmask.is_null() {
            continue;
        }
        // SAFETY: `ifa_name` is a valid NUL-terminated C string.
        let name = unsafe { std::ffi::CStr::from_ptr(ifa.ifa_name) }.to_string_lossy();
        // SAFETY: reading sa_family is valid for any sockaddr.
        if name != ifname || unsafe { (*ifa.ifa_addr).sa_family } as i32 != libc::AF_INET {
            continue;
        }
        // SAFETY: family is AF_INET, so both sockaddrs are really sockaddr_in.
        let addr = unsafe { &*(ifa.ifa_addr as *const libc::sockaddr_in) };
        let mask = unsafe { &*(ifa.ifa_netmask as *const libc::sockaddr_in) };
        let a = Ipv4Addr::from(u32::from_be(addr.sin_addr.s_addr));
        let m = u32::from_be(mask.sin_addr.s_addr);
        result = Some((a, m.count_ones() as u8));
        break;
    }
    // SAFETY: freeing exactly the list getifaddrs allocated.
    unsafe { libc::freeifaddrs(head) };
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_ospf_database_groups_areas_then_externals() {
        let lsa = |area, t, id: [u8; 4], adv: [u8; 4]| OspfLsaInfo {
            area,
            ls_type: t,
            link_state_id: Ipv4Addr::from(id),
            advertising_router: Ipv4Addr::from(adv),
            seq: -2_147_483_647, // first sequence number (0x80000001)
            age: 42,
        };
        assert_eq!(render_ospf_database(&[]), "no ospf lsas\n");
        let out = render_ospf_database(&[
            lsa(Some(Ipv4Addr::new(0, 0, 0, 0)), LsType::Router, [1, 1, 1, 1], [1, 1, 1, 1]),
            lsa(None, LsType::AsExternal, [10, 9, 0, 0], [2, 2, 2, 2]),
        ]);
        assert!(out.contains("area 0.0.0.0 router id 1.1.1.1 adv-router 1.1.1.1 seq 0x80000001 age 42"));
        assert!(out.contains("as-external external id 10.9.0.0 adv-router 2.2.2.2 seq 0x80000001"));
    }

    #[test]
    fn len_to_mask_is_contiguous() {
        assert_eq!(len_to_mask(24), Ipv4Addr::new(255, 255, 255, 0));
        assert_eq!(len_to_mask(0), Ipv4Addr::new(0, 0, 0, 0));
        assert_eq!(len_to_mask(32), Ipv4Addr::new(255, 255, 255, 255));
    }

    #[test]
    fn strip_ip_header_skips_by_ihl() {
        let mut pkt = vec![0x45u8; 20];
        pkt[0] = 0x45;
        pkt.extend_from_slice(&[0xaa, 0xbb]);
        assert_eq!(strip_ip_header(&pkt), Some(&[0xaa, 0xbb][..]));
        assert_eq!(strip_ip_header(&[0x60; 20]), None);
        assert_eq!(strip_ip_header(&[0x45; 10]), None);
    }
}
