//! # The OSPFv3 socket runner (RFC 5340)
//!
//! The async transport that turns the pure `wren-ospfv3` library (packet codec,
//! the §9/§10 state machines, the §9.4 DR election, the §13 flooding decision,
//! the §4.8 SPF) into a live OSPF-for-IPv6 speaker. Every protocol *decision*
//! lives in the library; this module does the I/O and sequencing the library
//! cannot, mirroring the OSPFv2 runner with the OSPFv3 differences (RFC 5340 §2–3):
//!
//! * one raw `IPPROTO_OSPFIGP` (89) **IPv6** socket per interface, joined to
//!   `ff02::5`/`ff02::6` and pinned to the interface (`SO_BINDTODEVICE`, hop
//!   limit 1, no loopback). Packets are sourced from the interface's *link-local*
//!   address, and the checksum is the IPv6 upper-layer checksum over a
//!   pseudo-header — so encode/decode carry the source and destination addresses;
//! * periodic Hellos (carrying an Interface ID, the DR/BDR by **Router ID**) to
//!   2-Way + DR election; the Database Exchange to Full;
//! * originating this router's **address-free** Router-LSA, its Network-LSA as DR,
//!   the **Intra-Area-Prefix-LSAs** carrying the actual IPv6 prefixes, and a
//!   per-link **Link-LSA** advertising our link-local next-hop address and the
//!   on-link prefixes — flooding each within its scope (link-local / area / AS);
//! * **multi-area**: one database per area, an SPF per area, and — as an ABR —
//!   Inter-Area-Prefix-LSA origination plus the inter-area route calculation;
//! * announcing the resulting routes (link-local next hops) to the router (RIB).
//!
//! Raw sockets need `CAP_NET_RAW`; the `unshare -Urn` netns used to smoke-test the
//! other runners grants it.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::io;
use std::mem;
use std::fmt::Write as _;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6};
use std::os::raw::c_void;
use std::os::unix::io::FromRawFd;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::time::MissedTickBehavior;
use tracing::{debug, info, warn};

use wren_core::Prefix;
use wren_ospfv3::flood::{decide_flood, FloodDecision, FloodInput};
use wren_ospfv3::interface::{Candidate, Interface, InterfaceEvent, InterfaceState, InterfaceType};
use wren_ospfv3::lsa::{
    AsExternalLsa, InterAreaPrefixLsa, IntraAreaPrefixLsa, IntraPrefix, LinkLsa, LsType, Lsa,
    LsaBody, LsaHeader, NetworkLsa, Prefix as V3Prefix, RouterLink, RouterLinkType, RouterLsa,
    RTR_FLAG_B, RTR_FLAG_E,
};
use wren_ospfv3::lsdb::{LsaKey, Lsdb};
use wren_ospfv3::neighbor::{
    Neighbor, NeighborAction, NeighborContext, NeighborEvent, NeighborState,
};
use wren_ospfv3::packet::{
    Body, DatabaseDescription, Header, Hello, LinkStateAck, LinkStateRequest, LinkStateUpdate,
    LsRequest, Packet, DD_FLAG_INIT, DD_FLAG_MASTER, DD_FLAG_MORE,
};
use wren_ospfv3::spf::{self, SpfRoute};
use wren_ospfv3::{
    ALL_D_ROUTERS, ALL_SPF_ROUTERS, INITIAL_SEQUENCE_NUMBER, IP_PROTOCOL, MAX_AGE, OPT_E, OPT_R,
    OPT_V6,
};

use crate::sockopt::{setsockopt_int, setsockopt_struct};
use crate::router::RouteUpdate;

/// How often (seconds) the housekeeping timer advances dead/wait timers.
const HOUSEKEEPING_SECS: u64 = 1;
/// Receive buffer: an LSU can be link-MTU sized.
const RECV_BUF: usize = 9000;
/// The OSPF backbone area (0.0.0.0), to which inter-area summaries condense.
const BACKBONE: Ipv4Addr = Ipv4Addr::UNSPECIFIED;
/// A pseudo-scope key for AS-wide (AS-external) LSA sequence numbers.
const AS_SCOPE: Ipv4Addr = Ipv4Addr::new(255, 255, 255, 255);
/// A pseudo-scope key for link-local (Link-LSA) sequence numbers — Link-LSA keys
/// are already unique per interface (by Interface ID), so one namespace suffices.
const LINK_SCOPE: Ipv4Addr = Ipv4Addr::new(255, 255, 255, 254);
/// The options every LSA/packet we originate advertises: IPv6 unicast, an active
/// router, AS-external capable (not a stub).
const SELF_OPTIONS: u32 = OPT_V6 | OPT_E | OPT_R;
/// The interface MTU advertised in Database Description packets.
const IFACE_MTU: u16 = 1500;

/// The resolved OSPFv3 configuration for a run.
pub struct Ospf3Config {
    /// This router's Router ID (a 32-bit id, even over IPv6).
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
    pub dead_interval: u16,
    /// The Instance ID carried in every packet (§2.11).
    pub instance_id: u8,
    /// Interfaces OSPFv3 runs on, each with the area it belongs to.
    pub interfaces: Vec<Ospf3IfaceCfg>,
    /// External destinations to redistribute as AS-external LSAs. A non-empty list
    /// makes this router an AS boundary router (ASBR).
    pub redistribute: Vec<RedistRoute>,
    /// Run BFD (RFC 5880) to each Full neighbour and tear the adjacency down at once
    /// when BFD reports the path failed (RFC 5882), instead of waiting for the dead
    /// interval. `[ospf3] bfd = true`.
    pub bfd: bool,
}

/// One configured OSPFv3 interface and the area it is in.
pub struct Ospf3IfaceCfg {
    /// The interface name.
    pub name: String,
    /// The area the interface belongs to.
    pub area: Ipv4Addr,
}

/// An external destination this ASBR redistributes (type-2 metric).
pub struct RedistRoute {
    /// The external IPv6 network.
    pub prefix: Prefix,
    /// The advertised (type-2) external metric.
    pub metric: u32,
}

/// A neighbour on one interface: its FSM plus the runtime exchange state.
struct Ospf3Neighbor {
    fsm: Neighbor,
    /// The neighbour's link-local source address, for unicast replies and floods.
    addr: Ipv6Addr,
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

impl Ospf3Neighbor {
    fn new(router_id: Ipv4Addr, addr: Ipv6Addr, now: u64) -> Self {
        Ospf3Neighbor {
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

/// One OSPFv3-speaking interface.
struct Iface {
    name: String,
    ifindex: u32,
    /// This interface's Interface ID (locally unique 32-bit; we use the ifindex).
    interface_id: u32,
    /// Our link-local address on this link — the next hop neighbours route through.
    link_local: Ipv6Addr,
    /// The global IPv6 prefixes configured on this interface (network + length).
    prefixes: Vec<(Ipv6Addr, u8)>,
    /// The area this interface belongs to.
    area: Ipv4Addr,
    sock: Arc<UdpSocket>,
    fsm: Interface,
    neighbors: HashMap<Ipv4Addr, Ospf3Neighbor>,
    wait_deadline: Option<u64>,
    /// The link-local-scoped database: this link's Link-LSAs (ours + neighbours').
    link_lsdb: Lsdb,
}

/// Per-area link-state state. Area-scoped types live here; each area has its own
/// database and a record of the LSAs this router originates into it.
struct Area {
    lsdb: Lsdb,
    /// The Network-LSAs we currently originate into this area (as DR).
    originated_networks: HashSet<LsaKey>,
    /// The Intra-Area-Prefix-LSAs we currently originate (for flush bookkeeping).
    originated_prefixes: HashSet<LsaKey>,
    /// The Inter-Area-Prefix-LSAs we currently originate (as an ABR).
    originated_summaries: HashSet<LsaKey>,
}

impl Area {
    fn new() -> Self {
        Area {
            lsdb: Lsdb::new(),
            originated_networks: HashSet::new(),
            originated_prefixes: HashSet::new(),
            originated_summaries: HashSet::new(),
        }
    }
}

/// A raw OSPFv3 datagram (the IPv6 header is not delivered on a v6 raw socket).
struct RawPacket {
    ifindex: u32,
    src: Ipv6Addr,
    data: Vec<u8>,
}

/// The whole OSPFv3 speaker.
struct Ospf {
    cfg: Ospf3Config,
    ifaces: Vec<Iface>,
    /// One link-state database per area.
    areas: BTreeMap<Ipv4Addr, Area>,
    /// The AS-wide database of AS-external LSAs (not area-scoped).
    external_lsdb: Lsdb,
    /// The AS-external LSAs we currently originate (for flush bookkeeping).
    originated_externals: HashSet<LsaKey>,
    /// The next sequence number to use for each LSA we originate, keyed by
    /// `(scope, LSA identity)` — the same key recurs across areas.
    lsa_seqs: HashMap<(Ipv4Addr, LsaKey), i32>,
    /// Stable Link State IDs for the Inter-Area-Prefix-LSAs we originate per area.
    summary_ids: HashMap<(Ipv4Addr, Prefix), Ipv4Addr>,
    /// Stable Link State IDs for the AS-external LSAs we originate.
    external_ids: HashMap<Prefix, Ipv4Addr>,
    /// A counter handing out the above Link State IDs.
    next_lsid: u32,
    /// A counter handing out fresh DD sequence numbers per adjacency.
    next_dd_seq: u32,
    /// The prefixes we currently have announced to the RIB (for reconciliation).
    announced: HashSet<Prefix>,
    updates: mpsc::Sender<RouteUpdate>,
    /// BFD (RFC 5880): the channel to the BFD engine to register/deregister
    /// per-neighbour sessions, the notify sender included in each registration (the
    /// engine reports a session going down on it), and the set of `(link-local
    /// address, interface index)` pairs currently registered (the Full neighbours).
    /// Unused when `cfg.bfd` is false. The scope is the interface index — OSPFv3
    /// neighbours are link-local, so the scope is what keeps two links' sessions
    /// distinct.
    bfd_register: mpsc::Sender<crate::bfd::BfdCommand>,
    bfd_notify: mpsc::Sender<IpAddr>,
    bfd_registered: HashSet<(Ipv6Addr, u32)>,
}

/// Run OSPFv3 on the configured interfaces, announcing SPF routes to `updates`.
/// A `show ospf3 …` query, answered by the OSPFv3 task itself out of the state it
/// owns (its interfaces, their neighbours and the DR election) — no shared access,
/// the IPv6 sibling of `show ospf`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Ospf3Query {
    /// The neighbours on every interface, with their adjacency state.
    Neighbors,
    /// The OSPFv3 interfaces, with their area, state and elected DR/BDR.
    Interfaces,
}

/// A control-socket query plus the channel to answer it on.
pub type Ospf3QueryRequest = crate::query::QueryRequest<Ospf3Query>;

/// One neighbour, snapshotted for the (pure) renderer. The neighbour address is an
/// IPv6 link-local (the next hop neighbours route through), unlike OSPFv2.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Ospf3NeighborInfo {
    /// The neighbour's Router ID (still a 32-bit dotted quad in OSPFv3).
    pub router_id: Ipv4Addr,
    /// The neighbour's link-local interface address.
    pub addr: Ipv6Addr,
    /// The adjacency state.
    pub state: NeighborState,
    /// The local interface the neighbour is on.
    pub iface: String,
}

/// One OSPFv3 interface, snapshotted for the (pure) renderer.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Ospf3IfaceInfo {
    /// The interface name.
    pub name: String,
    /// The area it belongs to.
    pub area: Ipv4Addr,
    /// Our link-local address on the link.
    pub link_local: Ipv6Addr,
    /// The interface state.
    pub state: InterfaceState,
    /// The elected Designated Router, by Router ID (`0.0.0.0` = none).
    pub dr: Ipv4Addr,
    /// The elected Backup Designated Router, by Router ID (`0.0.0.0` = none).
    pub bdr: Ipv4Addr,
    /// This router's priority on the interface.
    pub priority: u8,
}

/// The short name of a neighbour state, as shown by `show ospf3 neighbors`.
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

/// The short name of an interface state, as shown by `show ospf3 interfaces`.
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

/// Render the OSPFv3 neighbours, one per line (à la `show ipv6 ospf6 neighbor`).
pub fn render_ospf3_neighbors(neighbors: &[Ospf3NeighborInfo]) -> String {
    if neighbors.is_empty() {
        return "no ospf3 neighbors\n".to_string();
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

/// Render the OSPFv3 interfaces, one per line (à la `show ipv6 ospf6 interface`).
pub fn render_ospf3_interfaces(ifaces: &[Ospf3IfaceInfo]) -> String {
    if ifaces.is_empty() {
        return "no ospf3 interfaces\n".to_string();
    }
    let mut out = String::new();
    for i in ifaces {
        let _ = write!(
            out,
            "{} area {} {} state {} pri {}",
            i.name,
            i.area,
            i.link_local,
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

pub async fn run(
    cfg: Ospf3Config,
    updates: mpsc::Sender<RouteUpdate>,
    mut queries: mpsc::Receiver<Ospf3QueryRequest>,
    bfd_register: mpsc::Sender<crate::bfd::BfdCommand>,
    bfd_notify: mpsc::Sender<IpAddr>,
    mut bfd_down: mpsc::Receiver<IpAddr>,
) -> Result<()> {
    let mut ifaces = Vec::new();
    let mut areas: BTreeMap<Ipv4Addr, Area> = BTreeMap::new();
    for ic in &cfg.interfaces {
        let name = &ic.name;
        let (ifindex, std_sock) = open_ospf3_socket(name)
            .with_context(|| format!("opening OSPFv3 socket on {name:?}"))?;
        let (link_local, prefixes) = iface_ipv6(name);
        let Some(link_local) = link_local else {
            warn!(interface = %name, "no link-local IPv6 address — skipping OSPFv3 on this interface");
            continue;
        };
        let sock = Arc::new(
            UdpSocket::from_std(std_sock).context("registering OSPFv3 socket with tokio")?,
        );
        let mut fsm = Interface::new(cfg.router_id, cfg.priority, cfg.iface_type);
        for act in fsm.handle(InterfaceEvent::InterfaceUp, &[]) {
            debug!(interface = %name, ?act, "interface up");
        }
        info!(interface = %name, ifindex, %link_local, area = %ic.area, kind = ?cfg.iface_type, "OSPFv3 up (proto 89)");
        areas.entry(ic.area).or_insert_with(Area::new);
        ifaces.push(Iface {
            name: name.clone(),
            ifindex,
            interface_id: ifindex,
            link_local,
            prefixes,
            area: ic.area,
            sock,
            fsm,
            neighbors: HashMap::new(),
            wait_deadline: Some(cfg.dead_interval as u64),
            link_lsdb: Lsdb::new(),
        });
    }
    if ifaces.is_empty() {
        warn!("OSPFv3 is enabled but no usable interfaces — nothing to do");
        return Ok(());
    }

    let (pkt_tx, mut pkt_rx) = mpsc::channel::<RawPacket>(256);
    for iface in &ifaces {
        spawn_receiver(iface.sock.clone(), iface.ifindex, pkt_tx.clone());
    }
    drop(pkt_tx);

    let mut ospf = Ospf {
        cfg,
        ifaces,
        areas,
        external_lsdb: Lsdb::new(),
        originated_externals: HashSet::new(),
        lsa_seqs: HashMap::new(),
        summary_ids: HashMap::new(),
        external_ids: HashMap::new(),
        next_lsid: 1,
        next_dd_seq: 0x0100_0000,
        announced: HashSet::new(),
        updates,
        bfd_register,
        bfd_notify,
        bfd_registered: HashSet::new(),
    };
    ospf.originate_externals();
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
                    warn!("all OSPFv3 receivers stopped");
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
            Some(req) = queries.recv() => {
                let resp = match req.query {
                    Ospf3Query::Neighbors => render_ospf3_neighbors(&ospf.neighbor_infos()),
                    Ospf3Query::Interfaces => render_ospf3_interfaces(&ospf.iface_infos()),
                };
                let _ = req.respond.send(resp);
            }
            // BFD (RFC 5880) reported a neighbour's forwarding path down: tear that
            // adjacency down at once (RFC 5882 §4.4), exactly as an inactivity
            // timeout would, instead of waiting for the dead interval.
            Some(peer) = bfd_down.recv() => {
                if let IpAddr::V6(v6) = peer {
                    ospf.force_neighbor_down(v6).await;
                }
            }
        }
        // Keep the set of registered BFD sessions in step with the Full neighbours
        // (a no-op when `[ospf3] bfd` is off).
        ospf.reconcile_bfd().await;
    }
    Ok(())
}

impl Ospf {
    /// Snapshot every interface's neighbours for `show ospf3 neighbors`.
    fn neighbor_infos(&self) -> Vec<Ospf3NeighborInfo> {
        let mut out = Vec::new();
        for iface in &self.ifaces {
            for nbr in iface.neighbors.values() {
                out.push(Ospf3NeighborInfo {
                    router_id: nbr.fsm.router_id,
                    addr: nbr.addr,
                    state: nbr.fsm.state,
                    iface: iface.name.clone(),
                });
            }
        }
        out
    }

    /// Snapshot every interface for `show ospf3 interfaces`.
    fn iface_infos(&self) -> Vec<Ospf3IfaceInfo> {
        self.ifaces
            .iter()
            .map(|iface| Ospf3IfaceInfo {
                name: iface.name.clone(),
                area: iface.area,
                link_local: iface.link_local,
                state: iface.fsm.state,
                dr: iface.fsm.dr,
                bdr: iface.fsm.bdr,
                priority: iface.fsm.priority,
            })
            .collect()
    }
}

impl Ospf {
    /// Decode the packet (resolving the destination for the pseudo-header) and
    /// dispatch it.
    async fn handle_packet(&mut self, pkt: &RawPacket, now: u64) {
        let Some(idx) = self.iface_index(pkt.ifindex) else {
            return;
        };
        // The IPv6 destination feeds the upper-layer (pseudo-header) checksum the
        // library verifies. The kernel does not check it for a raw protocol, so we
        // try the three addresses a packet could have been sent to — our own
        // link-local (unicast) or either multicast group — and accept the one whose
        // checksum verifies. A genuinely corrupt packet matches none and is dropped.
        let dsts = [self.ifaces[idx].link_local, ALL_SPF_ROUTERS, ALL_D_ROUTERS];
        let packet = dsts
            .iter()
            .find_map(|dst| Packet::decode(&pkt.data, pkt.src, *dst).ok());
        let Some(packet) = packet else {
            debug!(src = %pkt.src, "ignoring malformed/unverifiable OSPFv3 packet");
            return;
        };
        // Drop our own reflections, the wrong area, or a foreign Instance ID.
        if packet.header.router_id == self.cfg.router_id
            || packet.header.area_id != self.ifaces[idx].area
            || packet.header.instance_id != self.cfg.instance_id
        {
            return;
        }
        let nbr_id = packet.header.router_id;
        match packet.body {
            Body::Hello(h) => self.handle_hello(idx, nbr_id, pkt.src, &h, now).await,
            Body::DatabaseDescription(dd) => self.handle_dd(idx, nbr_id, &dd).await,
            Body::LinkStateRequest(req) => self.handle_lsr(idx, nbr_id, &req).await,
            Body::LinkStateUpdate(upd) => self.handle_lsu(idx, nbr_id, upd).await,
            Body::LinkStateAck(_) => debug!(src = %pkt.src, "OSPFv3 LSAck received"),
        }
    }

    // --- Hello / neighbour discovery --------------------------------------

    async fn handle_hello(
        &mut self,
        idx: usize,
        nbr_id: Ipv4Addr,
        src: Ipv6Addr,
        hello: &Hello,
        now: u64,
    ) {
        let cfg_hi = self.cfg.hello_interval;
        let cfg_di = self.cfg.dead_interval;
        let self_id = self.cfg.router_id;
        if hello.hello_interval != cfg_hi || hello.dead_interval != cfg_di {
            debug!(neighbor = %nbr_id, "Hello timers mismatch — ignored");
            return;
        }
        // OSPFv3 carries the DR/BDR directly as Router IDs — no address mapping.
        let declared_dr = hello.designated_router;
        let declared_bdr = hello.backup_designated_router;

        let adjacency_ok = self.adjacency_ok(idx, nbr_id);
        let iface = &mut self.ifaces[idx];
        let entry = iface
            .neighbors
            .entry(nbr_id)
            .or_insert_with(|| Ospf3Neighbor::new(nbr_id, src, now));
        let was_bidir = entry.fsm.is_bidirectional();
        entry.addr = src;
        entry.last_seen = now;
        entry.fsm.priority = hello.router_priority;
        entry.fsm.interface_id = hello.interface_id;
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
            info!(interface = %iface.name, neighbor = %nbr_id, from = ?prev_state, to = ?new_state, "OSPFv3 neighbour state change");
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
            info!(interface = %iface.name, state = ?iface.fsm.state, dr = %iface.fsm.dr, bdr = %iface.fsm.bdr, "OSPFv3 DR election");
        }
        changed
    }

    /// After an election, re-evaluate whether each neighbour should be adjacent.
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
                info!(interface = %self.ifaces[idx].name, neighbor = %nbr_id, from = ?prev, to = ?new, "OSPFv3 neighbour state change");
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
        let dst = {
            let Some(n) = self.ifaces[idx].neighbors.get_mut(&nbr_id) else {
                return;
            };
            n.dd_seq = seq;
            n.master = true; // tentatively, until negotiation
            n.summary_sent = false;
            n.request_list.clear();
            n.addr
        };
        let dd = DatabaseDescription {
            options: SELF_OPTIONS,
            interface_mtu: IFACE_MTU,
            flags: DD_FLAG_INIT | DD_FLAG_MORE | DD_FLAG_MASTER,
            dd_sequence: seq,
            lsa_headers: vec![],
        };
        let iface = &self.ifaces[idx];
        let bytes = self.dd_bytes(iface, dst, dd);
        let (sock, ifindex) = (iface.sock.clone(), iface.ifindex);
        info!(neighbor = %nbr_id, seq, "OSPFv3 starting Database Exchange");
        send(&sock, dst, ifindex, &bytes).await;
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

    /// Send an Exchange DD: our database summary the first time, empty after.
    async fn send_exchange_dd(&mut self, idx: usize, nbr_id: Ipv4Addr) {
        let headers = self.db_headers(idx);
        let (dst, flags, dd_seq, send_headers) = {
            let n = self.ifaces[idx].neighbors.get_mut(&nbr_id).unwrap();
            let send_headers = if n.summary_sent { vec![] } else { headers };
            n.summary_sent = true;
            let mut flags = 0u8;
            if n.master {
                flags |= DD_FLAG_MASTER;
            }
            (n.addr, flags, n.dd_seq, send_headers)
        };
        let dd = DatabaseDescription {
            options: SELF_OPTIONS,
            interface_mtu: IFACE_MTU,
            flags,
            dd_sequence: dd_seq,
            lsa_headers: send_headers,
        };
        let iface = &self.ifaces[idx];
        let bytes = self.dd_bytes(iface, dst, dd);
        let (sock, ifindex) = (iface.sock.clone(), iface.ifindex);
        send(&sock, dst, ifindex, &bytes).await;
    }

    /// Note which of the neighbour's advertised LSAs we need (§10.6 / §10.9).
    fn process_dd_headers(&mut self, idx: usize, nbr_id: Ipv4Addr, headers: &[LsaHeader]) {
        let needed: Vec<LsaKey> = headers
            .iter()
            .filter(|h| self.need_lsa(idx, h))
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
        let (sock, dst, ifindex, bytes) = {
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
            let bytes = self.encode(
                iface,
                Body::LinkStateRequest(LinkStateRequest { entries }),
                n.addr,
            );
            (iface.sock.clone(), n.addr, iface.ifindex, bytes)
        };
        send(&sock, dst, ifindex, &bytes).await;
    }

    /// Answer a neighbour's Link State Request with the requested LSAs (§10.9).
    async fn handle_lsr(&mut self, idx: usize, nbr_id: Ipv4Addr, req: &LinkStateRequest) {
        let lsas: Vec<Lsa> = req
            .entries
            .iter()
            .filter_map(|e| {
                self.lsdb_for(idx, e.ls_type)
                    .get(&(e.ls_type, e.link_state_id, e.advertising_router))
                    .cloned()
            })
            .collect();
        if lsas.is_empty() {
            return;
        }
        let (sock, dst, ifindex, bytes) = {
            let iface = &self.ifaces[idx];
            let Some(n) = iface.neighbors.get(&nbr_id) else {
                return;
            };
            let bytes = self.encode(
                iface,
                Body::LinkStateUpdate(LinkStateUpdate { lsas }),
                n.addr,
            );
            (iface.sock.clone(), n.addr, iface.ifindex, bytes)
        };
        send(&sock, dst, ifindex, &bytes).await;
    }

    /// Process a Link State Update (§13): install newer LSAs into the scoped
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
            let scope = lsa.header.ls_type.scope();
            let on_request_list = self.ifaces[idx]
                .neighbors
                .get(&nbr_id)
                .map(|n| n.request_list.contains(&lsa.key()))
                .unwrap_or(false);
            let decision = {
                let input = FloodInput {
                    lsdb: self.lsdb_for(idx, lsa.header.ls_type),
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
                    match scope {
                        wren_ospfv3::lsa::Scope::LinkLocal => {
                            // Link-LSAs are single-hop: install, ack, never reflood.
                            self.ifaces[idx].link_lsdb.install(lsa);
                        }
                        wren_ospfv3::lsa::Scope::As => {
                            if third_party {
                                reflood_ext.push(lsa.clone());
                            }
                            self.external_lsdb.install(lsa);
                        }
                        _ => {
                            if third_party {
                                reflood_area.push(lsa.clone());
                            }
                            self.areas.get_mut(&area).unwrap().lsdb.install(lsa);
                        }
                    }
                    self.drop_from_request_lists(&key);
                    installed = true;
                }
                FloodDecision::DirectAck => ack_headers.push(lsa.header),
                _ => {}
            }
        }

        if !ack_headers.is_empty() {
            let (sock, ifindex, bytes) = {
                let iface = &self.ifaces[idx];
                let bytes = self.encode(
                    iface,
                    Body::LinkStateAck(LinkStateAck {
                        lsa_headers: ack_headers,
                    }),
                    src_addr,
                );
                (iface.sock.clone(), iface.ifindex, bytes)
            };
            send(&sock, src_addr, ifindex, &bytes).await;
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
            self.originate_summaries().await;
            self.run_spf_and_announce().await;
        }
    }

    // --- LSA origination + flooding ---------------------------------------

    /// Build this router's address-free Router-LSA for `area` (§A.4.3): one link
    /// per Full adjacency, by interface and router ID. The B/E bits flag an ABR/ASBR.
    fn build_router_lsa(&self, area: Ipv4Addr) -> Lsa {
        let cost = self.cfg.cost;
        let mut links = Vec::new();
        for iface in self.ifaces.iter().filter(|i| i.area == area) {
            if self.cfg.iface_type == InterfaceType::PointToPoint {
                for n in iface
                    .neighbors
                    .values()
                    .filter(|n| n.fsm.state == NeighborState::Full)
                {
                    links.push(RouterLink {
                        link_type: RouterLinkType::PointToPoint,
                        metric: cost,
                        interface_id: iface.interface_id,
                        neighbor_interface_id: n.fsm.interface_id,
                        neighbor_router_id: n.fsm.router_id,
                    });
                }
            } else if self.cfg.iface_type.elects_dr() {
                if let Some((dr_rid, dr_if)) = self.transit_dr(iface) {
                    links.push(RouterLink {
                        link_type: RouterLinkType::Transit,
                        metric: cost,
                        interface_id: iface.interface_id,
                        neighbor_interface_id: dr_if,
                        neighbor_router_id: dr_rid,
                    });
                }
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
            header: self.self_header(LsType::Router, Ipv4Addr::UNSPECIFIED),
            body: LsaBody::Router(RouterLsa {
                flags,
                options: SELF_OPTIONS,
                links,
            }),
        }
    }

    /// The transit network's `(DR router id, DR interface id)` on `iface`, if we
    /// are fully adjacent to its DR. `None` for a stub-like or unconverged link.
    fn transit_dr(&self, iface: &Iface) -> Option<(Ipv4Addr, u32)> {
        let dr = iface.fsm.dr;
        if dr.is_unspecified() {
            return None;
        }
        if dr == self.cfg.router_id {
            iface
                .neighbors
                .values()
                .any(|n| n.fsm.state == NeighborState::Full)
                .then_some((dr, iface.interface_id))
        } else {
            iface
                .neighbors
                .get(&dr)
                .filter(|n| n.fsm.state == NeighborState::Full)
                .map(|n| (dr, n.fsm.interface_id))
        }
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
            header: self.self_header(LsType::Network, Ipv4Addr::from(iface.interface_id)),
            body: LsaBody::Network(NetworkLsa {
                options: SELF_OPTIONS,
                attached_routers: attached,
            }),
        })
    }

    /// The Intra-Area-Prefix-LSA referencing our own Router-LSA (§A.4.9): the
    /// prefixes of interfaces in `area` that are *not* attached to a transit
    /// network (point-to-point links and stub-like broadcast links). The transit
    /// prefixes are carried by the DR's Network-referencing LSA instead.
    fn build_router_prefix_lsa(&self, area: Ipv4Addr) -> Lsa {
        let cost = self.cfg.cost;
        let mut prefixes = Vec::new();
        for iface in self.ifaces.iter().filter(|i| i.area == area) {
            if self.transit_dr(iface).is_some() {
                continue; // the DR advertises this link's prefix
            }
            for (net, len) in &iface.prefixes {
                prefixes.push(IntraPrefix {
                    metric: cost,
                    prefix: V3Prefix::from_ipv6(*net, *len, 0),
                });
            }
        }
        Lsa {
            header: self.self_header(LsType::IntraAreaPrefix, Ipv4Addr::UNSPECIFIED),
            body: LsaBody::IntraAreaPrefix(IntraAreaPrefixLsa {
                referenced_ls_type: LsType::Router.as_u16(),
                referenced_link_state_id: Ipv4Addr::UNSPECIFIED,
                referenced_advertising_router: self.cfg.router_id,
                prefixes,
            }),
        }
    }

    /// The Intra-Area-Prefix-LSA referencing the Network-LSA we originate as DR for
    /// `idx` — the transit link's prefix(es), at metric 0. `None` if not the DR.
    fn build_network_prefix_lsa(&self, idx: usize) -> Option<Lsa> {
        let iface = &self.ifaces[idx];
        self.build_network_lsa(idx)?;
        let prefixes = iface
            .prefixes
            .iter()
            .map(|(net, len)| IntraPrefix {
                metric: 0,
                prefix: V3Prefix::from_ipv6(*net, *len, 0),
            })
            .collect();
        Some(Lsa {
            header: self.self_header(LsType::IntraAreaPrefix, Ipv4Addr::from(iface.interface_id)),
            body: LsaBody::IntraAreaPrefix(IntraAreaPrefixLsa {
                referenced_ls_type: LsType::Network.as_u16(),
                referenced_link_state_id: Ipv4Addr::from(iface.interface_id),
                referenced_advertising_router: self.cfg.router_id,
                prefixes,
            }),
        })
    }

    /// Our Link-LSA for `idx` (§A.4.8, link-local scope): our link-local next-hop
    /// address and the IPv6 prefixes on the link, keyed by our Interface ID.
    fn build_link_lsa(&self, idx: usize) -> Lsa {
        let iface = &self.ifaces[idx];
        let prefixes = iface
            .prefixes
            .iter()
            .map(|(net, len)| V3Prefix::from_ipv6(*net, *len, 0))
            .collect();
        Lsa {
            header: self.self_header(LsType::Link, Ipv4Addr::from(iface.interface_id)),
            body: LsaBody::Link(LinkLsa {
                router_priority: iface.fsm.priority,
                options: SELF_OPTIONS,
                link_local_address: iface.link_local,
                prefixes,
            }),
        }
    }

    /// An Inter-Area-Prefix-LSA describing `prefix` at `cost`, with a stable LSID.
    fn build_summary_lsa(&mut self, area: Ipv4Addr, prefix: Prefix, cost: u32) -> Option<Lsa> {
        let v3 = to_v3_prefix(prefix)?;
        let lsid = self.alloc_summary_id(area, prefix);
        Some(Lsa {
            header: self.self_header(LsType::InterAreaPrefix, lsid),
            body: LsaBody::InterAreaPrefix(InterAreaPrefixLsa {
                metric: cost,
                prefix: v3,
            }),
        })
    }

    /// Whether this router redistributes external routes (an AS boundary router).
    fn is_asbr(&self) -> bool {
        !self.cfg.redistribute.is_empty()
    }

    /// Build and install this ASBR's AS-external LSAs into the AS-wide database.
    fn originate_externals(&mut self) {
        if self.cfg.redistribute.is_empty() {
            return;
        }
        let mut want = HashSet::new();
        for r in 0..self.cfg.redistribute.len() {
            let prefix = self.cfg.redistribute[r].prefix;
            let metric = self.cfg.redistribute[r].metric;
            let Some(v3) = to_v3_prefix(prefix) else {
                continue; // OSPFv3 carries IPv6 prefixes only
            };
            let lsid = self.alloc_external_id(prefix);
            let mut lsa = Lsa {
                header: self.self_header(LsType::AsExternal, lsid),
                body: LsaBody::AsExternal(AsExternalLsa {
                    external_type2: true,
                    metric,
                    prefix: v3,
                    forwarding_address: None,
                    route_tag: None,
                    referenced_ls_type: 0,
                    referenced_link_state_id: None,
                }),
            };
            let key = lsa.key();
            lsa.header.ls_seq = self.next_seq(AS_SCOPE, key);
            self.external_lsdb.install(lsa);
            want.insert(key);
            info!(prefix = %prefix, metric, "OSPFv3 redistributing external route");
        }
        self.originated_externals = want;
    }

    /// A header for an LSA we originate (sequence/checksum/length filled later).
    fn self_header(&self, ls_type: LsType, link_state_id: Ipv4Addr) -> LsaHeader {
        LsaHeader {
            ls_age: 0,
            ls_type,
            link_state_id,
            advertising_router: self.cfg.router_id,
            ls_seq: 0,
            ls_checksum: 0,
            length: 0,
        }
    }

    /// Set the next sequence number for `lsa` in the area scope, install it into
    /// the area database and return it.
    fn install_area(&mut self, area: Ipv4Addr, mut lsa: Lsa) -> Lsa {
        let key = lsa.key();
        lsa.header.ls_seq = self.next_seq(area, key);
        self.areas.get_mut(&area).unwrap().lsdb.install(lsa.clone());
        lsa
    }

    /// Re-originate all of this router's LSAs into every area and onto every link
    /// (Router-LSA, the Network-LSAs and their prefixes, the router prefixes, and
    /// the per-link Link-LSAs), flushing those it should no longer originate, and
    /// flood each within its scope.
    async fn reoriginate_and_flood(&mut self) {
        // Per-link: the Link-LSA (link-local scope).
        for idx in 0..self.ifaces.len() {
            let mut lsa = self.build_link_lsa(idx);
            let key = lsa.key();
            lsa.header.ls_seq = self.next_seq(LINK_SCOPE, key);
            self.ifaces[idx].link_lsdb.install(lsa.clone());
            self.flood_link_lsa(idx, &lsa).await;
        }

        let areas: Vec<Ipv4Addr> = self.areas.keys().copied().collect();
        for area in areas {
            let mut to_flood = Vec::new();
            let rl = self.build_router_lsa(area);
            to_flood.push(self.install_area(area, rl));
            let rp = self.build_router_prefix_lsa(area);
            to_flood.push(self.install_area(area, rp));

            let mut want_net = HashSet::new();
            let mut want_pfx = HashSet::new();
            // The router-prefix LSA is always originated; track it so it is never
            // flushed while the area exists.
            want_pfx.insert((
                LsType::IntraAreaPrefix,
                Ipv4Addr::UNSPECIFIED,
                self.cfg.router_id,
            ));
            for idx in 0..self.ifaces.len() {
                if self.ifaces[idx].area != area {
                    continue;
                }
                if let Some(lsa) = self.build_network_lsa(idx) {
                    want_net.insert(lsa.key());
                    to_flood.push(self.install_area(area, lsa));
                }
                if let Some(lsa) = self.build_network_prefix_lsa(idx) {
                    want_pfx.insert(lsa.key());
                    to_flood.push(self.install_area(area, lsa));
                }
            }
            self.flush_stale(area, &mut to_flood, want_net, |a| {
                &mut a.originated_networks
            });
            self.flush_stale(area, &mut to_flood, want_pfx, |a| {
                &mut a.originated_prefixes
            });

            for lsa in &to_flood {
                self.flood_lsa(area, lsa).await;
            }
        }
        self.originate_summaries().await;
    }

    /// MaxAge-flush the LSAs in `slot` no longer in `want`, recording `want` as the
    /// new set; queue each flushed LSA for flooding.
    fn flush_stale(
        &mut self,
        area: Ipv4Addr,
        to_flood: &mut Vec<Lsa>,
        want: HashSet<LsaKey>,
        slot: impl Fn(&mut Area) -> &mut HashSet<LsaKey>,
    ) {
        let prev = slot(self.areas.get_mut(&area).unwrap()).clone();
        for key in prev.difference(&want) {
            if let Some(mut lsa) = self.areas[&area].lsdb.get(key).cloned() {
                lsa.header.ls_age = MAX_AGE;
                to_flood.push(self.install_area(area, lsa));
            }
        }
        *slot(self.areas.get_mut(&area).unwrap()) = want;
    }

    /// Originate the inter-area Inter-Area-Prefix-LSAs (§A.4.5) an ABR injects:
    /// into the backbone, every non-backbone area's intra-area routes; into each
    /// non-backbone area, the backbone's — the §4.8.4 condensation.
    async fn originate_summaries(&mut self) {
        if !self.is_abr() {
            return;
        }
        let areas: Vec<Ipv4Addr> = self.areas.keys().copied().collect();
        let mut intra: BTreeMap<Ipv4Addr, Vec<SpfRoute>> = BTreeMap::new();
        let links = self.link_union();
        for a in &areas {
            intra.insert(
                *a,
                spf::compute(&self.areas[a].lsdb, &links, self.cfg.router_id).routes,
            );
        }

        for &dest in &areas {
            let sources: Vec<Ipv4Addr> = if dest == BACKBONE {
                areas.iter().copied().filter(|a| *a != BACKBONE).collect()
            } else {
                areas.iter().copied().filter(|a| *a == BACKBONE).collect()
            };
            let mut want_routes: BTreeMap<Prefix, u32> = BTreeMap::new();
            for src in &sources {
                for r in &intra[src] {
                    let slot = want_routes.entry(r.prefix).or_insert(r.cost);
                    *slot = (*slot).min(r.cost);
                }
            }

            let mut to_flood = Vec::new();
            let mut want_keys = HashSet::new();
            for (prefix, cost) in &want_routes {
                if let Some(lsa) = self.build_summary_lsa(dest, *prefix, *cost) {
                    want_keys.insert(lsa.key());
                    to_flood.push(self.install_area(dest, lsa));
                }
            }
            self.flush_stale(dest, &mut to_flood, want_keys, |a| {
                &mut a.originated_summaries
            });

            for lsa in &to_flood {
                self.flood_lsa(dest, lsa).await;
            }
        }
    }

    /// On reaching Full: re-originate our LSAs, flood them and re-run SPF.
    async fn on_adjacency_full(&mut self, idx: usize, nbr_id: Ipv4Addr) {
        info!(interface = %self.ifaces[idx].name, neighbor = %nbr_id, "OSPFv3 adjacency Full");
        self.reoriginate_and_flood().await;
        self.run_spf_and_announce().await;
    }

    /// Flood one area LSA to every Full neighbour on an interface in `area`.
    async fn flood_lsa(&self, area: Ipv4Addr, lsa: &Lsa) {
        self.flood_lsa_except(area, lsa, Ipv6Addr::UNSPECIFIED)
            .await;
    }

    /// Flood one area LSA to every Full neighbour in `area` except the one at `except`.
    async fn flood_lsa_except(&self, area: Ipv4Addr, lsa: &Lsa, except: Ipv6Addr) {
        for iface in self.ifaces.iter().filter(|i| i.area == area) {
            for n in iface.neighbors.values() {
                if n.fsm.state == NeighborState::Full && n.addr != except {
                    let bytes = self.encode(
                        iface,
                        Body::LinkStateUpdate(LinkStateUpdate {
                            lsas: vec![lsa.clone()],
                        }),
                        n.addr,
                    );
                    send(&iface.sock, n.addr, iface.ifindex, &bytes).await;
                }
            }
        }
    }

    /// Flood a Link-LSA on its own interface only (link-local scope).
    async fn flood_link_lsa(&self, idx: usize, lsa: &Lsa) {
        let iface = &self.ifaces[idx];
        for n in iface.neighbors.values() {
            if n.fsm.state >= NeighborState::Exchange {
                let bytes = self.encode(
                    iface,
                    Body::LinkStateUpdate(LinkStateUpdate {
                        lsas: vec![lsa.clone()],
                    }),
                    n.addr,
                );
                send(&iface.sock, n.addr, iface.ifindex, &bytes).await;
            }
        }
    }

    /// Flood an AS-external LSA AS-wide: every Full neighbour in every area except
    /// the one at `except`.
    async fn flood_external_except(&self, lsa: &Lsa, except: Ipv6Addr) {
        for iface in &self.ifaces {
            for n in iface.neighbors.values() {
                if n.fsm.state == NeighborState::Full && n.addr != except {
                    let bytes = self.encode(
                        iface,
                        Body::LinkStateUpdate(LinkStateUpdate {
                            lsas: vec![lsa.clone()],
                        }),
                        n.addr,
                    );
                    send(&iface.sock, n.addr, iface.ifindex, &bytes).await;
                }
            }
        }
    }

    // --- SPF → RIB --------------------------------------------------------

    /// Run an SPF per area, fold in the inter-area and AS-external routes, and
    /// reconcile the announced routes with the router. Intra-area beats inter-area
    /// beats external (§4.8 preference).
    async fn run_spf_and_announce(&mut self) {
        let areas: Vec<Ipv4Addr> = self.areas.keys().copied().collect();
        let links = self.link_union();
        let mut chosen: BTreeMap<Prefix, SpfRoute> = BTreeMap::new();
        let mut merged = spf::SpfResult::default();

        // Intra-area routes (best by cost across areas).
        for area in &areas {
            let res = spf::compute(&self.areas[area].lsdb, &links, self.cfg.router_id);
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
            let res = spf::compute(&self.areas[&area].lsdb, &links, self.cfg.router_id);
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

        // AS-external routes — least preferred.
        for r in spf::external_routes(&self.external_lsdb, &merged, self.cfg.router_id) {
            chosen.entry(r.prefix).or_insert(r);
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
                    table: wren_core::RT_TABLE_MAIN,
                    prefix,
                    protocol: wren_core::Protocol::Ospf,
                    source: 0,
                })
                .await;
        }
        self.announced = new_prefixes;
    }

    /// A single database unioning every link's Link-LSAs, for the SPF next-hop
    /// resolution (each Link-LSA key is unique by Interface ID + Router ID).
    fn link_union(&self) -> Lsdb {
        let mut db = Lsdb::new();
        for iface in &self.ifaces {
            for lsa in iface.link_lsdb.iter() {
                db.install(lsa.clone());
            }
        }
        db
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
                    info!(interface = %self.ifaces[idx].name, neighbor = %id, "OSPFv3 neighbour dead (inactivity)");
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
    /// the neighbour leaves Full or disappears. A no-op unless `[ospf3] bfd` is set.
    /// OSPFv3 neighbours are IPv6 link-local, so each session is keyed by the
    /// neighbour's address *and* the interface index (its BFD scope). The BFD engine
    /// reports a session going down on [`Self::bfd_notify`], which the run loop turns
    /// into [`Self::force_neighbor_down`].
    async fn reconcile_bfd(&mut self) {
        if !self.cfg.bfd {
            return;
        }
        let mut full: HashSet<(Ipv6Addr, u32)> = HashSet::new();
        for iface in &self.ifaces {
            for n in iface.neighbors.values() {
                if n.fsm.state == NeighborState::Full {
                    full.insert((n.addr, iface.ifindex));
                }
            }
        }
        let added: Vec<(Ipv6Addr, u32)> =
            full.difference(&self.bfd_registered).copied().collect();
        for (addr, scope) in added {
            let _ = self
                .bfd_register
                .send(crate::bfd::BfdCommand::Register {
                    peer: IpAddr::V6(addr),
                    scope_id: scope,
                    consumer: crate::bfd::BfdConsumer::Ospf3,
                    notify: self.bfd_notify.clone(),
                    auth: None, // OSPFv3 uses the global [bfd] key
                })
                .await;
        }
        let removed: Vec<(Ipv6Addr, u32)> =
            self.bfd_registered.difference(&full).copied().collect();
        for (addr, scope) in removed {
            let _ = self
                .bfd_register
                .send(crate::bfd::BfdCommand::Deregister {
                    peer: IpAddr::V6(addr),
                    scope_id: scope,
                    consumer: crate::bfd::BfdConsumer::Ospf3,
                })
                .await;
        }
        self.bfd_registered = full;
    }

    /// Tear down the adjacency to the neighbour at `peer` (a BFD-reported path
    /// failure), mirroring [`Self::age_neighbors`]: remove the neighbour, drive its
    /// FSM down, re-run the interface's DR election and adjacency evaluation, and
    /// re-originate / re-run SPF. The BFD reconcile then drops the stale session.
    async fn force_neighbor_down(&mut self, peer: Ipv6Addr) {
        let mut changed = false;
        for idx in 0..self.ifaces.len() {
            let id = self.ifaces[idx]
                .neighbors
                .iter()
                .find(|(_, n)| n.addr == peer)
                .map(|(id, _)| *id);
            let Some(id) = id else { continue };
            if let Some(mut n) = self.ifaces[idx].neighbors.remove(&id) {
                n.fsm
                    .handle(NeighborEvent::InactivityTimer, NeighborContext::default());
                info!(interface = %self.ifaces[idx].name, neighbor = %id, %peer, "OSPFv3 neighbour down (BFD)");
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

    /// Resend the initial (I/M/MS) DD to any neighbour still in ExStart, so a lost
    /// or crossed init does not deadlock the negotiation.
    async fn retransmit_init_dds(&mut self) {
        let mut out = Vec::new();
        for iface in &self.ifaces {
            for n in iface.neighbors.values() {
                if n.fsm.state == NeighborState::ExStart {
                    let dd = DatabaseDescription {
                        options: SELF_OPTIONS,
                        interface_mtu: IFACE_MTU,
                        flags: DD_FLAG_INIT | DD_FLAG_MORE | DD_FLAG_MASTER,
                        dd_sequence: n.dd_seq,
                        lsa_headers: vec![],
                    };
                    out.push((
                        iface.sock.clone(),
                        n.addr,
                        iface.ifindex,
                        self.dd_bytes(iface, n.addr, dd),
                    ));
                }
            }
        }
        for (sock, dst, ifindex, bytes) in out {
            send(&sock, dst, ifindex, &bytes).await;
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
                interface_id: iface.interface_id,
                router_priority: iface.fsm.priority,
                options: SELF_OPTIONS,
                hello_interval: self.cfg.hello_interval,
                dead_interval: self.cfg.dead_interval,
                designated_router: iface.fsm.dr,
                backup_designated_router: iface.fsm.bdr,
                neighbors: iface
                    .neighbors
                    .values()
                    .filter(|n| n.fsm.state >= NeighborState::Init)
                    .map(|n| n.fsm.router_id)
                    .collect(),
            };
            let bytes = self.encode(iface, Body::Hello(hello), ALL_SPF_ROUTERS);
            send(&iface.sock, ALL_SPF_ROUTERS, iface.ifindex, &bytes).await;
        }
    }

    // --- Helpers ----------------------------------------------------------

    fn iface_index(&self, ifindex: u32) -> Option<usize> {
        self.ifaces.iter().position(|i| i.ifindex == ifindex)
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

    /// A fresh 32-bit Link State ID for an originated summary/external LSA.
    fn alloc_lsid(&mut self) -> Ipv4Addr {
        let id = self.next_lsid;
        self.next_lsid = self.next_lsid.wrapping_add(1);
        Ipv4Addr::from(id)
    }

    fn alloc_summary_id(&mut self, area: Ipv4Addr, prefix: Prefix) -> Ipv4Addr {
        if let Some(id) = self.summary_ids.get(&(area, prefix)) {
            return *id;
        }
        let id = self.alloc_lsid();
        self.summary_ids.insert((area, prefix), id);
        id
    }

    fn alloc_external_id(&mut self, prefix: Prefix) -> Ipv4Addr {
        if let Some(id) = self.external_ids.get(&prefix) {
            return *id;
        }
        let id = self.alloc_lsid();
        self.external_ids.insert(prefix, id);
        id
    }

    /// The next LS sequence number for the LSA `key` in `scope`.
    fn next_seq(&mut self, scope: Ipv4Addr, key: LsaKey) -> i32 {
        let slot = self
            .lsa_seqs
            .entry((scope, key))
            .or_insert(INITIAL_SEQUENCE_NUMBER);
        let v = *slot;
        *slot = slot.wrapping_add(1);
        v
    }

    /// The database that holds `ls_type` arriving on interface `idx`: the
    /// interface's link-local database for a Link-LSA, the AS-wide database for an
    /// AS-external LSA, otherwise the interface's area database.
    fn lsdb_for(&self, idx: usize, ls_type: LsType) -> &Lsdb {
        match ls_type.scope() {
            wren_ospfv3::lsa::Scope::LinkLocal => &self.ifaces[idx].link_lsdb,
            wren_ospfv3::lsa::Scope::As => &self.external_lsdb,
            _ => &self.areas[&self.ifaces[idx].area].lsdb,
        }
    }

    /// Whether the relevant database lacks an instance of `h` at least as recent.
    fn need_lsa(&self, idx: usize, h: &LsaHeader) -> bool {
        match self.lsdb_for(idx, h.ls_type).header(&h.key()) {
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

    /// Every LSA header to describe on an adjacency on interface `idx`: that link's
    /// Link-LSAs, the area's database, and the AS-wide external LSAs.
    fn db_headers(&self, idx: usize) -> Vec<LsaHeader> {
        let iface = &self.ifaces[idx];
        iface
            .link_lsdb
            .iter()
            .chain(self.areas[&iface.area].lsdb.iter())
            .chain(self.external_lsdb.iter())
            .map(|l| l.header)
            .collect()
    }

    fn drop_from_request_lists(&mut self, key: &LsaKey) {
        for iface in &mut self.ifaces {
            for n in iface.neighbors.values_mut() {
                n.request_list.retain(|k| k != key);
            }
        }
    }

    fn dd_bytes(&self, iface: &Iface, dst: Ipv6Addr, dd: DatabaseDescription) -> Vec<u8> {
        self.encode(iface, Body::DatabaseDescription(dd), dst)
    }

    /// Encode a packet from `iface` with its link-local source and the given IPv6
    /// destination (multicast for Hellos/floods to the group, the neighbour's
    /// link-local for unicast) — the destination feeds the pseudo-header checksum.
    fn encode(&self, iface: &Iface, body: Body, dst: Ipv6Addr) -> Vec<u8> {
        let header = Header {
            router_id: self.cfg.router_id,
            area_id: iface.area,
            instance_id: self.cfg.instance_id,
        };
        Packet { header, body }.encode(iface.link_local, dst)
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

/// An OSPFv3 wire prefix from a [`wren_core::Prefix`], or `None` for an IPv4 one.
fn to_v3_prefix(prefix: Prefix) -> Option<V3Prefix> {
    match prefix.addr() {
        IpAddr::V6(a) => Some(V3Prefix::from_ipv6(a, prefix.len(), 0)),
        IpAddr::V4(_) => None,
    }
}

/// Send `bytes` to `dst` out `ifindex` (link-local needs the scope), warning on
/// error.
async fn send(sock: &UdpSocket, dst: Ipv6Addr, ifindex: u32, bytes: &[u8]) {
    let target = SocketAddrV6::new(dst, 0, 0, ifindex);
    if let Err(e) = sock.send_to(bytes, SocketAddr::V6(target)).await {
        warn!(%dst, error = %e, "sending OSPFv3 packet");
    }
}

/// Spawn a task reading raw OSPFv3 datagrams from one interface into `pkt_tx`.
fn spawn_receiver(sock: Arc<UdpSocket>, ifindex: u32, pkt_tx: mpsc::Sender<RawPacket>) {
    tokio::spawn(async move {
        let mut buf = vec![0u8; RECV_BUF];
        loop {
            match sock.recv_from(&mut buf).await {
                Ok((n, SocketAddr::V6(src))) => {
                    let pkt = RawPacket {
                        ifindex,
                        src: *src.ip(),
                        data: buf[..n].to_vec(),
                    };
                    if pkt_tx.send(pkt).await.is_err() {
                        break;
                    }
                }
                Ok((_, SocketAddr::V4(_))) => {} // an AF_INET6 socket; shouldn't happen
                Err(e) => {
                    warn!(ifindex, error = %e, "OSPFv3 receive failed");
                    break;
                }
            }
        }
    });
}

// ---------------------------------------------------------------------------
// Socket + interface-address setup (libc, like the RIPng runner).
// ---------------------------------------------------------------------------

fn open_ospf3_socket(ifname: &str) -> Result<(u32, std::net::UdpSocket)> {
    let cname = std::ffi::CString::new(ifname).context("interface name has an interior NUL")?;
    // SAFETY: `cname` is a valid NUL-terminated string for the call's duration.
    let ifindex = unsafe { libc::if_nametoindex(cname.as_ptr()) };
    if ifindex == 0 {
        anyhow::bail!("interface {ifname:?} not found");
    }

    // SAFETY: a raw socket; the fd is taken into ownership immediately below.
    let fd = unsafe {
        libc::socket(
            libc::AF_INET6,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
            IP_PROTOCOL as libc::c_int,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error())
            .context("socket(AF_INET6, SOCK_RAW, 89) — needs CAP_NET_RAW");
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

    join_group(fd, ALL_SPF_ROUTERS, ifindex).context("IPV6_ADD_MEMBERSHIP ff02::5")?;
    join_group(fd, ALL_D_ROUTERS, ifindex).context("IPV6_ADD_MEMBERSHIP ff02::6")?;
    setsockopt_int(
        fd,
        libc::IPPROTO_IPV6,
        libc::IPV6_MULTICAST_IF,
        ifindex as i32,
    )?;
    setsockopt_int(fd, libc::IPPROTO_IPV6, libc::IPV6_MULTICAST_LOOP, 0)?;
    // OSPF packets are single-hop: hop limit 1 on multicast and unicast alike.
    setsockopt_int(fd, libc::IPPROTO_IPV6, libc::IPV6_MULTICAST_HOPS, 1)?;
    setsockopt_int(fd, libc::IPPROTO_IPV6, libc::IPV6_UNICAST_HOPS, 1)?;

    Ok((ifindex, sock))
}

fn join_group(fd: i32, group: Ipv6Addr, ifindex: u32) -> Result<()> {
    // SAFETY: ipv6_mreq is plain POD; we set the group and interface index.
    let mut mreq: libc::ipv6_mreq = unsafe { mem::zeroed() };
    mreq.ipv6mr_multiaddr.s6_addr = group.octets();
    mreq.ipv6mr_interface = ifindex;
    setsockopt_struct(fd, libc::IPPROTO_IPV6, libc::IPV6_ADD_MEMBERSHIP, &mreq)
}

/// The interface's link-local address and its global IPv6 prefixes (network +
/// length), via `getifaddrs`.
fn iface_ipv6(ifname: &str) -> (Option<Ipv6Addr>, Vec<(Ipv6Addr, u8)>) {
    let mut head: *mut libc::ifaddrs = std::ptr::null_mut();
    // SAFETY: getifaddrs allocates a list into `head`; freed below.
    if unsafe { libc::getifaddrs(&mut head) } != 0 {
        return (None, Vec::new());
    }
    let mut link_local = None;
    let mut prefixes = Vec::new();
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
        if name != ifname || unsafe { (*ifa.ifa_addr).sa_family } as i32 != libc::AF_INET6 {
            continue;
        }
        // SAFETY: family is AF_INET6, so both sockaddrs are really sockaddr_in6.
        let addr = unsafe { &*(ifa.ifa_addr as *const libc::sockaddr_in6) };
        let mask = unsafe { &*(ifa.ifa_netmask as *const libc::sockaddr_in6) };
        let a = Ipv6Addr::from(addr.sin6_addr.s6_addr);
        if a.octets()[0] == 0xfe && (a.octets()[1] & 0xc0) == 0x80 {
            link_local.get_or_insert(a);
            continue;
        }
        let len = mask
            .sin6_addr
            .s6_addr
            .iter()
            .map(|b| b.count_ones())
            .sum::<u32>() as u8;
        prefixes.push((network_v6(a, len), len));
    }
    // SAFETY: freeing exactly the list getifaddrs allocated.
    unsafe { libc::freeifaddrs(head) };
    (link_local, prefixes)
}

/// An IPv6 address with its host bits cleared to `len` bits.
fn network_v6(addr: Ipv6Addr, len: u8) -> Ipv6Addr {
    let bits = u128::from(addr);
    let mask = if len == 0 {
        0
    } else if len >= 128 {
        u128::MAX
    } else {
        u128::MAX << (128 - len as u32)
    };
    Ipv6Addr::from(bits & mask)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn network_v6_clears_host_bits() {
        let a = Ipv6Addr::new(0x2001, 0xdb8, 0xabcd, 0x1234, 0xdead, 0xbeef, 0, 1);
        assert_eq!(
            network_v6(a, 64),
            Ipv6Addr::new(0x2001, 0xdb8, 0xabcd, 0x1234, 0, 0, 0, 0)
        );
        assert_eq!(network_v6(a, 0), Ipv6Addr::UNSPECIFIED);
        assert_eq!(network_v6(a, 128), a);
    }

    #[test]
    fn to_v3_prefix_rejects_ipv4() {
        let v6: Prefix = "2001:db8::/32".parse().unwrap();
        assert!(to_v3_prefix(v6).is_some());
        let v4: Prefix = "10.0.0.0/8".parse().unwrap();
        assert!(to_v3_prefix(v4).is_none());
    }
}
