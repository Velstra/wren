//! # The IGMP querier / proxy socket runner (RFC 3376, RFC 4605)
//!
//! The async transport and timer driver that turns the pure [`wren_igmp`] library
//! into a live IGMP speaker — the IPTV / multicast-behind-the-firewall path. The
//! protocol *decisions* (membership state, timers, proxy aggregation) all live in
//! `wren-igmp`; this module only does the I/O that library can't:
//!
//! * opens one raw `IPPROTO_IGMP` socket **per interface**, bound to it with
//!   `SO_BINDTODEVICE`, joined to `224.0.0.22` (so it hears every IGMPv3 report,
//!   which are all sent there) and `224.0.0.2`, with multicast TTL pinned to 1 —
//!   the same `libc`/`setsockopt` approach as the RIP and VRRP runners;
//! * on each **querier** and **downstream** interface it acts as the IGMP querier:
//!   sends a General Query at startup and every Query Interval, and feeds received
//!   membership reports into that interface's [`MembershipTable`], logging the
//!   groups joined/left;
//! * when a `[multicast] upstream` interface is configured it runs the RFC 4605
//!   proxy: downstream membership is aggregated by [`IgmpProxy`] and the router
//!   joins/leaves each group upstream (acting as a host on the upstream link) as
//!   the first/last downstream member appears/goes. Programming the kernel
//!   multicast forwarding cache (MFC) for the computed [`ForwardingEntry`]s is a
//!   documented hook ([`program_mfc`]), not yet wired.
//!
//! IGMP has no IPv6 twin here — that is MLDv2 (RFC 3810), deferred (see the
//! `wren-igmp` crate docs).

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

use wren_igmp::election::{ElectionEvent, QuerierState};
use wren_igmp::membership::{FilterMode, MembershipEvent, MembershipTable, TimerConfig};
use wren_igmp::proxy::{ForwardingEntry, IgmpProxy, ProxyAction};
use wren_igmp::wire::{encode_float, GroupRecord, Message, Query, RecordType};
use wren_igmp::{is_link_local_control, ALL_HOSTS, IGMPV3_ALL_ROUTERS, IGMP_PROTO};

use crate::sockopt::{setsockopt_int, setsockopt_struct};

/// IGMP messages ride with TTL 1 — they never leave the link (§4).
const IGMP_TTL: i32 = 1;
/// Advance the membership timers (and flush any due expiry) this often.
const HOUSEKEEPING_SECS: u64 = 1;
/// Receive buffer: an IP header + a v3 report; groups are small, 2 KiB is ample.
const RECV_BUF: usize = 2048;

/// The floating-point codes carried in the queries this querier sends: the General
/// Query's Max Resp Code, the Group-Specific (Last-Member) query's shorter Max Resp
/// Code, the robustness/QQIC fields and the version flag.
#[derive(Debug, Clone, Copy)]
struct QueryParams {
    max_resp: u8,
    lmq: u8,
    qrv: u8,
    qqic: u8,
    v3: bool,
}

/// A membership change fed from the IGMP querier to the PIM-SM runner (when PIM is
/// enabled): a receiver joined or left group `G` on interface `ifindex`. `source` is
/// `None` for an ASM `(*,G)` membership (build the shared tree) or `Some(S)` for an
/// IGMPv3 source-specific membership (build the `(S,G)` source tree). PIM turns this
/// into the corresponding Join/Prune toward the RP or source.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MembershipUpdate {
    /// The interface index the membership is on (a PIM outgoing interface).
    pub ifindex: u32,
    /// The multicast group.
    pub group: Ipv4Addr,
    /// The source for an IGMPv3 source-specific membership, else `None` (ASM).
    pub source: Option<Ipv4Addr>,
    /// Whether the group is now present (joined) or gone (left).
    pub present: bool,
}

/// The resolved runner configuration, built by the daemon from `[multicast]`.
#[derive(Debug, Clone)]
pub struct QuerierConfig {
    /// Interfaces to act as the plain IGMP querier on (no proxying).
    pub querier_interfaces: Vec<String>,
    /// The RFC 4605 proxy upstream interface, if proxying is configured.
    pub upstream: Option<String>,
    /// The RFC 4605 proxy downstream interfaces (each also acts as a querier).
    pub downstream: Vec<String>,
    /// Robustness Variable (QRV).
    pub robustness: u8,
    /// Query Interval (how often a General Query is sent).
    pub query_interval: Duration,
    /// Query Response Interval (the Max Response Time advertised in queries).
    pub query_response_interval: Duration,
    /// IGMP version to speak (2 or 3). 3 is the default.
    pub igmp_version: u8,
    /// When PIM-SM is enabled, the channel membership changes are fed to the PIM
    /// runner over (so it can build the multicast trees). `None` disables the feed.
    pub pim_feed: Option<mpsc::Sender<MembershipUpdate>>,
}

/// One IGMP-speaking interface: its socket, membership table and role.
struct Iface {
    name: String,
    ifindex: u32,
    sock: Arc<UdpSocket>,
    table: MembershipTable<Ipv4Addr>,
    /// Querier-election state (RFC 3376 §6): whether we currently send queries here.
    querier: QuerierState<Ipv4Addr>,
    /// True if this interface feeds the RFC 4605 proxy (a downstream interface).
    proxy_downstream: bool,
}

/// A datagram received on one interface, tagged with its arrival interface.
struct Packet {
    ifindex: u32,
    data: Vec<u8>,
}

/// Run the IGMP querier/proxy until `shutdown` fires or a fatal socket error.
pub async fn run(cfg: QuerierConfig, mut shutdown: watch::Receiver<bool>) -> Result<()> {
    let timers = TimerConfig {
        robustness: cfg.robustness.max(1),
        query_interval: cfg.query_interval,
        query_response_interval: cfg.query_response_interval,
        last_member_query_count: cfg.robustness.max(1),
        ..TimerConfig::default()
    };
    let pim_feed = cfg.pim_feed.clone();

    // Every querier and every proxy-downstream interface tracks membership and
    // queries its LAN. Downstream interfaces additionally feed the proxy.
    let mut ifaces: HashMap<u32, Iface> = HashMap::new();
    let (pkt_tx, mut pkt_rx) = mpsc::channel::<Packet>(256);

    let mut member_specs: Vec<(String, bool)> = Vec::new();
    for name in &cfg.querier_interfaces {
        member_specs.push((name.clone(), false));
    }
    for name in &cfg.downstream {
        member_specs.push((name.clone(), true));
    }

    for (name, is_downstream) in member_specs {
        match open_igmp_socket(&name, /* join_reports = */ true) {
            Ok((ifindex, sock)) => {
                let sock = Arc::new(sock);
                spawn_reader(sock.clone(), ifindex, pkt_tx.clone());
                // Our own source address on the link is what querier election
                // compares; unknown → unspecified (the minimum), so we keep querying.
                let own = iface_ipv4(&name).unwrap_or(Ipv4Addr::UNSPECIFIED);
                ifaces.insert(
                    ifindex,
                    Iface {
                        name: name.clone(),
                        ifindex,
                        sock,
                        table: MembershipTable::new(timers),
                        querier: QuerierState::new(own, &timers),
                        proxy_downstream: is_downstream,
                    },
                );
                info!(iface = %name, addr = %own, downstream = is_downstream, "IGMP querier active");
            }
            Err(e) => warn!(iface = %name, error = %e, "IGMP: skipping interface"),
        }
    }

    // The proxy upstream: a send-only IGMP socket we act as a host on.
    let mut proxy: Option<(Arc<UdpSocket>, IgmpProxy)> = match &cfg.upstream {
        Some(up) => match open_igmp_socket(up, /* join_reports = */ false) {
            Ok((_ifindex, sock)) => {
                info!(iface = %up, "IGMP proxy upstream active (RFC 4605)");
                Some((Arc::new(sock), IgmpProxy::new()))
            }
            Err(e) => {
                warn!(iface = %up, error = %e, "IGMP proxy upstream not started");
                None
            }
        },
        None => None,
    };

    if ifaces.is_empty() && proxy.is_none() {
        warn!("IGMP configured but no usable interface — nothing to do");
        return Ok(());
    }

    // The floating-point query codes. Max Resp Code = Query Response Interval in
    // 1/10 s; QQIC = Query Interval in seconds; the Last-Member (group-specific)
    // query uses the shorter Last Member Query Interval (§4.1.1 / §8.8).
    let qp = QueryParams {
        max_resp: encode_float((cfg.query_response_interval.as_millis() / 100) as u32),
        lmq: encode_float((timers.last_member_query_interval.as_millis() / 100) as u32),
        qrv: cfg.robustness & 0x07,
        qqic: encode_float(cfg.query_interval.as_secs() as u32),
        v3: cfg.igmp_version != 2,
    };

    // Send the startup General Query on every interface we are the querier for, then
    // on the periodic tick.
    send_general_query_all(&ifaces, &qp).await;

    let mut query_tick = tokio::time::interval(cfg.query_interval);
    query_tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
    query_tick.reset(); // the immediate first tick is the startup query above
    let mut housekeep = tokio::time::interval(Duration::from_secs(HOUSEKEEPING_SECS));
    housekeep.set_missed_tick_behavior(MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            _ = query_tick.tick() => {
                send_general_query_all(&ifaces, &qp).await;
            }
            _ = housekeep.tick() => {
                let now = Instant::now();
                for iface in ifaces.values_mut() {
                    // Resume querying if the elected querier has gone silent.
                    if let Some(ElectionEvent::BecameQuerier) = iface.querier.tick(now) {
                        info!(iface = %iface.name, "IGMP: resuming querier role (other querier gone)");
                    }
                    let events = iface.table.expire(now);
                    handle_events(iface, &events, &mut proxy, &qp, &pim_feed).await;
                }
            }
            Some(pkt) = pkt_rx.recv() => {
                let now = Instant::now();
                let Some(iface) = ifaces.get_mut(&pkt.ifindex) else { continue };
                let Some((src, payload)) = ipv4_parse(&pkt.data) else { continue };
                match Message::decode(payload) {
                    Ok(msg @ (Message::V3Report { .. }
                        | Message::V2Report(_)
                        | Message::V1Report(_)
                        | Message::V2Leave(_))) => {
                        let events = iface.table.apply(now, &msg);
                        handle_events(iface, &events, &mut proxy, &qp, &pim_feed).await;
                    }
                    // Another querier on the link: run querier election (lowest source
                    // IP wins). If it is lower than ours we step down and stop querying.
                    Ok(Message::Query(_)) => {
                        if let Some(ElectionEvent::BecameNonQuerier) = iface.querier.on_query(now, src) {
                            info!(iface = %iface.name, other = %src, "IGMP: yielding querier role to lower address");
                        }
                    }
                    Err(e) => debug!(iface = %iface.name, error = %e, "IGMP: bad packet"),
                }
            }
            r = shutdown.changed() => {
                if r.is_ok() && *shutdown.borrow() {
                    // Leave every upstream group as a well-behaved host on the way out.
                    if let Some((sock, proxy)) = proxy.as_mut() {
                        let groups: Vec<Ipv4Addr> = proxy.joined_groups().copied().collect();
                        for g in groups {
                            let _ = send_to(sock, &upstream_report(g, false), IGMPV3_ALL_ROUTERS).await;
                        }
                    }
                    info!("IGMP querier shutting down");
                    return Ok(());
                }
            }
        }
    }
}

/// Turn a batch of membership events into log lines and, for a proxy-downstream
/// interface, an upstream re-sync (join/leave the aggregated groups).
async fn handle_events(
    iface: &mut Iface,
    events: &[MembershipEvent<Ipv4Addr>],
    proxy: &mut Option<(Arc<UdpSocket>, IgmpProxy)>,
    qp: &QueryParams,
    pim_feed: &Option<mpsc::Sender<MembershipUpdate>>,
) {
    if events.is_empty() {
        return;
    }
    for ev in events {
        match ev {
            // The smoke asserts on this exact line: "IGMP membership joined".
            MembershipEvent::Joined(g) => {
                info!(iface = %iface.name, group = %g, "IGMP membership joined")
            }
            MembershipEvent::Left(g) => {
                info!(iface = %iface.name, group = %g, "IGMP membership left")
            }
            // Last-Member-Query: a leave was heard — send a Group-Specific Query so
            // any remaining member re-reports before the shortened timer drops it.
            MembershipEvent::Querying(g) => {
                debug!(iface = %iface.name, group = %g, "IGMP: last-member query");
                if iface.querier.is_querier() {
                    let mut q = Query::group_specific(*g, qp.lmq, qp.qrv, qp.qqic);
                    q.v3 = qp.v3;
                    let _ = send_to(&iface.sock, &Message::Query(q), *g).await;
                }
            }
            MembershipEvent::Updated(_) => {}
        }
    }

    // Feed membership changes to the PIM-SM runner (when enabled), so it builds the
    // multicast trees. `try_send` keeps IGMP from ever back-pressuring on PIM. This
    // runs for every interface (a plain querier LAN is a PIM outgoing interface too),
    // before the RFC 4605 proxy early-return below.
    if let Some(feed) = pim_feed {
        for ev in events {
            let g = ev.group();
            match ev {
                MembershipEvent::Joined(_) | MembershipEvent::Updated(_) => {
                    // An IGMPv3 INCLUDE-mode group with sources is a source-specific
                    // (SSM) membership → one `(S,G)` per source; anything else is an
                    // ASM `(*,G)` membership.
                    match iface.table.get(g) {
                        Some(m) if m.mode == FilterMode::Include && !m.sources.is_empty() => {
                            for s in &m.sources {
                                let _ = feed.try_send(MembershipUpdate {
                                    ifindex: iface.ifindex,
                                    group: g,
                                    source: Some(*s),
                                    present: true,
                                });
                            }
                        }
                        _ => {
                            let _ = feed.try_send(MembershipUpdate {
                                ifindex: iface.ifindex,
                                group: g,
                                source: None,
                                present: true,
                            });
                        }
                    }
                }
                MembershipEvent::Left(_) => {
                    let _ = feed.try_send(MembershipUpdate {
                        ifindex: iface.ifindex,
                        group: g,
                        source: None,
                        present: false,
                    });
                }
                MembershipEvent::Querying(_) => {}
            }
        }
    }

    // RFC 4605: aggregate this downstream's membership upstream. Link-local control
    // groups (224.0.0.0/24) are never proxied.
    if !iface.proxy_downstream {
        return;
    }
    let Some((up_sock, agg)) = proxy.as_mut() else {
        return;
    };
    let wanted = iface
        .table
        .active_groups()
        .into_iter()
        .filter(|g| !is_link_local_control(*g))
        .collect();
    for action in agg.sync_downstream(iface.ifindex, &wanted) {
        match action {
            ProxyAction::JoinUpstream(g) => {
                info!(group = %g, "IGMP proxy: joining group upstream");
                let _ = send_to(up_sock, &upstream_report(g, true), IGMPV3_ALL_ROUTERS).await;
            }
            ProxyAction::LeaveUpstream(g) => {
                info!(group = %g, "IGMP proxy: leaving group upstream");
                let _ = send_to(up_sock, &upstream_report(g, false), IGMPV3_ALL_ROUTERS).await;
            }
        }
    }
    program_mfc(&agg.forwarding());
}

/// The kernel multicast-forwarding-cache hook (documented, not yet wired). On Linux
/// this is a routing socket with `MRT_INIT` + `MRT_ADD_VIF` + one `MRT_ADD_MFC` per
/// entry (iif = upstream vif, oifs = the entry's downstream vifs). Until that lands,
/// the upstream join above still pulls each stream to the router; we log the picture
/// the MFC would program so it is observable.
fn program_mfc(entries: &[ForwardingEntry<Ipv4Addr>]) {
    for e in entries {
        debug!(group = %e.group, oifs = ?e.downstreams, "IGMP proxy: forwarding-cache entry (MFC hook)");
    }
}

/// A v3 report acting as a host: `TO_EXCLUDE {}` to join a group `*,G`,
/// `TO_INCLUDE {}` to leave it (§4.2 / RFC 4605 §3.2).
fn upstream_report(group: Ipv4Addr, join: bool) -> Message {
    let rt = if join {
        RecordType::ToExclude
    } else {
        RecordType::ToInclude
    };
    Message::V3Report {
        records: vec![GroupRecord::any_source(rt, group)],
    }
}

/// Send a General Query out every interface we are the elected querier for (a
/// non-querier stays silent, RFC 3376 §6).
async fn send_general_query_all(ifaces: &HashMap<u32, Iface>, qp: &QueryParams) {
    let mut query = Query::general(qp.max_resp, qp.qrv, qp.qqic);
    query.v3 = qp.v3;
    let msg = Message::Query(query);
    for iface in ifaces.values() {
        if !iface.querier.is_querier() {
            continue;
        }
        if let Err(e) = send_to(&iface.sock, &msg, ALL_HOSTS).await {
            debug!(iface = %iface.name, error = %e, "IGMP: general query send failed");
        }
    }
}

/// Encode `msg` and send it to `dst` on `sock` (the kernel builds the IP header).
async fn send_to(sock: &UdpSocket, msg: &Message, dst: Ipv4Addr) -> io::Result<()> {
    let bytes = msg.encode();
    sock.send_to(&bytes, (dst, 0)).await.map(|_| ())
}

/// Spawn a task that reads datagrams off `sock` and forwards them tagged with
/// `ifindex` to the central loop.
fn spawn_reader(sock: Arc<UdpSocket>, ifindex: u32, tx: mpsc::Sender<Packet>) {
    tokio::spawn(async move {
        let mut buf = vec![0u8; RECV_BUF];
        loop {
            match sock.recv_from(&mut buf).await {
                Ok((n, _from)) => {
                    if tx
                        .send(Packet {
                            ifindex,
                            data: buf[..n].to_vec(),
                        })
                        .await
                        .is_err()
                    {
                        return; // central loop gone
                    }
                }
                Err(e) => {
                    warn!(ifindex, error = %e, "IGMP: recv error, reader stopping");
                    return;
                }
            }
        }
    });
}

/// A raw IPv4 socket delivers the full datagram including the IP header. Validate
/// it is IPv4/IGMP and return the source address (for querier election) and the IGMP
/// payload slice, or `None` if it is malformed or not IGMP.
fn ipv4_parse(buf: &[u8]) -> Option<(Ipv4Addr, &[u8])> {
    if buf.len() < 20 {
        return None;
    }
    if buf[0] >> 4 != 4 {
        return None; // not IPv4
    }
    let ihl = (buf[0] & 0x0f) as usize * 4;
    if ihl < 20 || buf.len() < ihl {
        return None;
    }
    if buf[9] != IGMP_PROTO {
        return None; // not IGMP
    }
    let src = Ipv4Addr::new(buf[12], buf[13], buf[14], buf[15]);
    Some((src, &buf[ihl..]))
}

/// The first usable IPv4 address of `ifname` (the source querier election compares),
/// via `getifaddrs`. `None` if the interface has no IPv4 address yet.
fn iface_ipv4(ifname: &str) -> Option<Ipv4Addr> {
    let mut head: *mut libc::ifaddrs = std::ptr::null_mut();
    // SAFETY: getifaddrs allocates a linked list into `head`, freed below.
    if unsafe { libc::getifaddrs(&mut head) } != 0 {
        return None;
    }
    let mut result = None;
    let mut cur = head;
    while !cur.is_null() {
        // SAFETY: `cur` is a non-null node in the kernel-provided list.
        let node = unsafe { &*cur };
        if !node.ifa_addr.is_null() {
            // SAFETY: ifa_name is a valid C string; ifa_addr points at a sockaddr.
            let name = unsafe { std::ffi::CStr::from_ptr(node.ifa_name) };
            let fam = unsafe { (*node.ifa_addr).sa_family } as i32;
            if name.to_bytes() == ifname.as_bytes() && fam == libc::AF_INET {
                // SAFETY: an AF_INET sockaddr is a sockaddr_in.
                let sin = unsafe { &*(node.ifa_addr as *const libc::sockaddr_in) };
                let ip = Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr));
                if !ip.is_loopback() && !ip.is_unspecified() {
                    result = Some(ip);
                    break;
                }
            }
        }
        cur = node.ifa_next;
    }
    // SAFETY: freeing the list getifaddrs allocated.
    unsafe { libc::freeifaddrs(head) };
    result
}

/// Open a raw `IPPROTO_IGMP` socket bound to `ifname`, with multicast egress pinned
/// to it and TTL 1. When `join_reports` is set it also joins `224.0.0.22`,
/// `224.0.0.2` and `224.0.0.1` so it *receives* the reports hosts send and the
/// General Queries other queriers send (for election). Needs `CAP_NET_RAW`.
fn open_igmp_socket(ifname: &str, join_reports: bool) -> Result<(u32, UdpSocket)> {
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
            IGMP_PROTO as i32,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error())
            .context("socket(SOCK_RAW, IPPROTO_IGMP) — needs CAP_NET_RAW");
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
    setsockopt_int(fd, libc::IPPROTO_IP, libc::IP_MULTICAST_TTL, IGMP_TTL)?;
    setsockopt_int(fd, libc::IPPROTO_IP, libc::IP_TTL, IGMP_TTL)?;

    if join_reports {
        for group in [IGMPV3_ALL_ROUTERS, ALL_HOSTS_ROUTERS, ALL_HOSTS] {
            // SAFETY: ip_mreqn is plain POD; we set the group and interface index.
            let mut mreq: libc::ip_mreqn = unsafe { mem::zeroed() };
            mreq.imr_multiaddr.s_addr = u32::from(group).to_be();
            mreq.imr_ifindex = ifindex as libc::c_int;
            setsockopt_struct(fd, libc::IPPROTO_IP, libc::IP_ADD_MEMBERSHIP, &mreq)
                .with_context(|| format!("IP_ADD_MEMBERSHIP {group}"))?;
        }
    }

    sock.set_nonblocking(true).context("set_nonblocking")?;
    let sock = UdpSocket::from_std(sock).context("tokio UdpSocket::from_std")?;
    Ok((ifindex, sock))
}

/// `224.0.0.2` all-routers — joined alongside `224.0.0.22` so a querier also hears
/// legacy v2 leaves (sent there).
const ALL_HOSTS_ROUTERS: Ipv4Addr = wren_igmp::ALL_ROUTERS;

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

/// Join multicast `group` on `iface` and park until killed, so the OS kernel keeps
/// us a member of the group — which makes it emit genuine IGMP (IPv4) or MLD (IPv6)
/// membership reports. The `wren mcast-join` diagnostic / test helper (used by the
/// querier smokes to simulate a host without a second daemon). Needs no special
/// privilege beyond the interface being multicast-capable.
pub fn mcast_join_blocking(group: std::net::IpAddr, iface: &str) -> Result<()> {
    let cname = CString::new(iface).context("interface name has an interior NUL")?;
    // SAFETY: `cname` is valid for the call.
    let ifindex = unsafe { libc::if_nametoindex(cname.as_ptr()) };
    if ifindex == 0 {
        anyhow::bail!("interface {iface:?} not found");
    }
    match group {
        std::net::IpAddr::V4(g) => {
            // SAFETY: a plain datagram socket to carry the membership; closed on exit.
            let fd =
                unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
            if fd < 0 {
                return Err(io::Error::last_os_error()).context("socket(AF_INET, DGRAM)");
            }
            // SAFETY: ip_mreqn is plain POD; we set the group and interface index.
            let mut mreq: libc::ip_mreqn = unsafe { mem::zeroed() };
            mreq.imr_multiaddr.s_addr = u32::from(g).to_be();
            mreq.imr_ifindex = ifindex as libc::c_int;
            setsockopt_struct(fd, libc::IPPROTO_IP, libc::IP_ADD_MEMBERSHIP, &mreq)
                .with_context(|| format!("IP_ADD_MEMBERSHIP {g} on {iface}"))?;
        }
        std::net::IpAddr::V6(g) => {
            // SAFETY: a plain datagram socket to carry the membership; closed on exit.
            let fd =
                unsafe { libc::socket(libc::AF_INET6, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
            if fd < 0 {
                return Err(io::Error::last_os_error()).context("socket(AF_INET6, DGRAM)");
            }
            // SAFETY: ipv6_mreq is plain POD; we set the group and interface index.
            let mut mreq: libc::ipv6_mreq = unsafe { mem::zeroed() };
            mreq.ipv6mr_multiaddr.s6_addr = g.octets();
            mreq.ipv6mr_interface = ifindex;
            setsockopt_struct(fd, libc::IPPROTO_IPV6, libc::IPV6_ADD_MEMBERSHIP, &mreq)
                .with_context(|| format!("IPV6_ADD_MEMBERSHIP {g} on {iface}"))?;
        }
    }
    info!(group = %group, iface, "joined multicast group; parking (Ctrl-C to leave)");
    // Park: the kernel holds the membership (and answers queries) as long as we live.
    loop {
        std::thread::sleep(Duration::from_secs(3600));
    }
}
