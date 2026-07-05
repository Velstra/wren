//! # The MLD querier / proxy socket runner (RFC 3810, RFC 4605)
//!
//! The IPv6 twin of [`crate::igmp`]: the async transport and timer driver that turns
//! the pure [`wren_igmp::mld`] codec + the shared membership state machine into a
//! live MLDv2 speaker. MLD rides in ICMPv6 rather than a bare IP protocol, so this
//! module opens a raw `IPPROTO_ICMPV6` socket per interface; everything else mirrors
//! the IGMP runner:
//!
//! * bound to the interface with `SO_BINDTODEVICE`, joined to `ff02::16` (every
//!   MLDv2 report is sent there) and `ff02::2`, with an `ICMP6_FILTER` that passes
//!   only MLD types (130/131/132/143) and the multicast hop limit pinned to 1;
//! * on each querier / downstream interface it sends a General Query at startup and
//!   every Query Interval and feeds received reports into that interface's
//!   [`MembershipTable`]`<Ipv6Addr>`, logging the groups joined/left;
//! * when an upstream interface is configured it runs the RFC 4605 proxy for IPv6
//!   groups (the [`MldProxy`]), joining/leaving each group upstream. The kernel
//!   IPv6 multicast forwarding cache is the same documented hook as IGMP.
//!
//! Unlike an IPv4 raw socket, a raw ICMPv6 socket delivers the payload *without* the
//! IPv6 header and the kernel computes/verifies the ICMPv6 checksum, so decode reads
//! the MLD message directly and encode leaves the checksum field zero.

use std::collections::HashMap;
use std::ffi::CString;
use std::io;
use std::mem;
use std::net::Ipv6Addr;
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
use wren_igmp::membership::{MembershipEvent, MembershipTable, TimerConfig};
use wren_igmp::mld::{encode_float16, Message, MldQuery, MldRecord};
use wren_igmp::proxy::{ForwardingEntry, MldProxy, ProxyAction};
use wren_igmp::wire::{encode_float, RecordType};
use wren_igmp::{
    membership::MulticastAddr, ALL_NODES_V6, ALL_ROUTERS_V6, ICMPV6_PROTO, MLDV2_ALL_ROUTERS,
    MLD_QUERY, MLD_V1_DONE, MLD_V1_REPORT, MLD_V2_REPORT,
};

use crate::igmp::QuerierConfig;
use crate::sockopt::{setsockopt_int, setsockopt_struct};

/// MLD messages ride with hop limit 1 — they never leave the link (§5).
const MLD_HOPS: i32 = 1;
/// Advance the membership timers (and flush any due expiry) this often.
const HOUSEKEEPING_SECS: u64 = 1;
/// Receive buffer: an MLDv2 report; groups are small, 2 KiB is ample.
const RECV_BUF: usize = 2048;
/// `setsockopt` name for the ICMPv6 type filter (`ICMP6_FILTER`).
const ICMP6_FILTER: i32 = 1;

/// The floating-point query codes this querier sends: the General Query's 16-bit
/// Max Resp Code, the Group-Specific (Last-Member) query's shorter code, and the
/// robustness/QQIC fields (§5.1).
#[derive(Debug, Clone, Copy)]
struct QueryParams {
    max_resp: u16,
    lmq: u16,
    qrv: u8,
    qqic: u8,
}

/// One MLD-speaking interface: its socket, membership table and role.
struct Iface {
    name: String,
    ifindex: u32,
    sock: Arc<UdpSocket>,
    table: MembershipTable<Ipv6Addr>,
    /// Querier-election state (RFC 3810 §7): whether we currently send queries here.
    querier: QuerierState<Ipv6Addr>,
    proxy_downstream: bool,
}

/// A datagram received on one interface, tagged with its arrival interface and the
/// IPv6 source (for querier election).
struct Packet {
    ifindex: u32,
    src: Ipv6Addr,
    data: Vec<u8>,
}

/// Run the MLD querier/proxy until `shutdown` fires or a fatal socket error. Shares
/// [`QuerierConfig`] with IGMP — the same interface roles, over IPv6.
pub async fn run(cfg: QuerierConfig, mut shutdown: watch::Receiver<bool>) -> Result<()> {
    let timers = TimerConfig {
        robustness: cfg.robustness.max(1),
        query_interval: cfg.query_interval,
        query_response_interval: cfg.query_response_interval,
        last_member_query_count: cfg.robustness.max(1),
        ..TimerConfig::default()
    };

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
        match open_mld_socket(&name, /* join_reports = */ true) {
            Ok((ifindex, sock)) => {
                let sock = Arc::new(sock);
                spawn_reader(sock.clone(), ifindex, pkt_tx.clone());
                // Election compares our link-local source on the link; unknown → the
                // unspecified address (the minimum), so we keep querying.
                let own = iface_linklocal_v6(&name).unwrap_or(Ipv6Addr::UNSPECIFIED);
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
                info!(iface = %name, addr = %own, downstream = is_downstream, "MLD querier active");
            }
            Err(e) => warn!(iface = %name, error = %e, "MLD: skipping interface"),
        }
    }

    let mut proxy: Option<(Arc<UdpSocket>, MldProxy)> = match &cfg.upstream {
        Some(up) => match open_mld_socket(up, /* join_reports = */ false) {
            Ok((_ifindex, sock)) => {
                info!(iface = %up, "MLD proxy upstream active (RFC 4605)");
                Some((Arc::new(sock), MldProxy::new()))
            }
            Err(e) => {
                warn!(iface = %up, error = %e, "MLD proxy upstream not started");
                None
            }
        },
        None => None,
    };

    if ifaces.is_empty() && proxy.is_none() {
        warn!("MLD configured but no usable interface — nothing to do");
        return Ok(());
    }

    // The query codes. Max Resp Code = Query Response Interval in ms (16-bit float);
    // QQIC = Query Interval in seconds (8-bit float); the Last-Member (group-specific)
    // query uses the shorter Last Member Query Interval (§5.1 / §9).
    let qp = QueryParams {
        max_resp: encode_float16(cfg.query_response_interval.as_millis() as u32),
        lmq: encode_float16(timers.last_member_query_interval.as_millis() as u32),
        qrv: cfg.robustness & 0x07,
        qqic: encode_float(cfg.query_interval.as_secs() as u32),
    };

    send_general_query_all(&ifaces, &qp).await;

    let mut query_tick = tokio::time::interval(cfg.query_interval);
    query_tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
    query_tick.reset();
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
                    if let Some(ElectionEvent::BecameQuerier) = iface.querier.tick(now) {
                        info!(iface = %iface.name, "MLD: resuming querier role (other querier gone)");
                    }
                    let events = iface.table.expire(now);
                    handle_events(iface, &events, &mut proxy, &qp).await;
                }
            }
            Some(pkt) = pkt_rx.recv() => {
                let now = Instant::now();
                let Some(iface) = ifaces.get_mut(&pkt.ifindex) else { continue };
                match Message::decode(&pkt.data) {
                    Ok(msg @ (Message::V2Report { .. }
                        | Message::V1Report(_)
                        | Message::V1Done(_))) => {
                        let events = iface.table.apply(now, &msg);
                        handle_events(iface, &events, &mut proxy, &qp).await;
                    }
                    // Querier election (RFC 3810 §7): the lowest link-local source wins.
                    Ok(Message::Query(_)) => {
                        if let Some(ElectionEvent::BecameNonQuerier) = iface.querier.on_query(now, pkt.src) {
                            info!(iface = %iface.name, other = %pkt.src, "MLD: yielding querier role to lower address");
                        }
                    }
                    Err(e) => debug!(iface = %iface.name, error = %e, "MLD: bad packet"),
                }
            }
            r = shutdown.changed() => {
                if r.is_ok() && *shutdown.borrow() {
                    if let Some((sock, proxy)) = proxy.as_mut() {
                        let groups: Vec<Ipv6Addr> = proxy.joined_groups().copied().collect();
                        for g in groups {
                            let _ = send_to(sock, &upstream_report(g, false), MLDV2_ALL_ROUTERS).await;
                        }
                    }
                    info!("MLD querier shutting down");
                    return Ok(());
                }
            }
        }
    }
}

/// Turn a batch of membership events into log lines and, for a proxy-downstream
/// interface, an upstream re-sync (join/leave the aggregated IPv6 groups).
async fn handle_events(
    iface: &mut Iface,
    events: &[MembershipEvent<Ipv6Addr>],
    proxy: &mut Option<(Arc<UdpSocket>, MldProxy)>,
    qp: &QueryParams,
) {
    if events.is_empty() {
        return;
    }
    for ev in events {
        match ev {
            // The smoke asserts on this exact line: "MLD membership joined".
            MembershipEvent::Joined(g) => {
                info!(iface = %iface.name, group = %g, "MLD membership joined")
            }
            MembershipEvent::Left(g) => {
                info!(iface = %iface.name, group = %g, "MLD membership left")
            }
            // Last-Member-Query: a Done was heard — send a Multicast-Address-Specific
            // Query so any remaining listener re-reports before the timer drops it.
            MembershipEvent::Querying(g) => {
                debug!(iface = %iface.name, group = %g, "MLD: last-member query");
                if iface.querier.is_querier() {
                    let q = MldQuery::group_specific(*g, qp.lmq, qp.qrv, qp.qqic);
                    let _ = send_to(&iface.sock, &Message::Query(q), *g).await;
                }
            }
            MembershipEvent::Updated(_) => {}
        }
    }

    if !iface.proxy_downstream {
        return;
    }
    let Some((up_sock, agg)) = proxy.as_mut() else {
        return;
    };
    // Link-scoped groups are already filtered by the membership table's is_control.
    let wanted = iface
        .table
        .active_groups()
        .into_iter()
        .filter(|g| !g.is_control())
        .collect();
    for action in agg.sync_downstream(iface.ifindex, &wanted) {
        match action {
            ProxyAction::JoinUpstream(g) => {
                info!(group = %g, "MLD proxy: joining group upstream");
                let _ = send_to(up_sock, &upstream_report(g, true), MLDV2_ALL_ROUTERS).await;
            }
            ProxyAction::LeaveUpstream(g) => {
                info!(group = %g, "MLD proxy: leaving group upstream");
                let _ = send_to(up_sock, &upstream_report(g, false), MLDV2_ALL_ROUTERS).await;
            }
        }
    }
    program_mfc(&agg.forwarding());
}

/// The IPv6 multicast-forwarding-cache hook (documented, not yet wired — the same
/// `MRT6_*` routing-socket story as IGMP's IPv4 MFC). We compute the entries; the
/// upstream join above already pulls each stream to the router.
fn program_mfc(entries: &[ForwardingEntry<Ipv6Addr>]) {
    for e in entries {
        debug!(group = %e.group, oifs = ?e.downstreams, "MLD proxy: forwarding-cache entry (MFC hook)");
    }
}

/// An MLDv2 report acting as a host: `TO_EXCLUDE {}` to join `*,G`,
/// `TO_INCLUDE {}` to leave it (RFC 4605 §3.2).
fn upstream_report(group: Ipv6Addr, join: bool) -> Message {
    let rt = if join {
        RecordType::ToExclude
    } else {
        RecordType::ToInclude
    };
    Message::V2Report {
        records: vec![MldRecord::any_source(rt, group)],
    }
}

/// Send a General Query out every interface we are the elected querier for (a
/// non-querier stays silent, RFC 3810 §7).
async fn send_general_query_all(ifaces: &HashMap<u32, Iface>, qp: &QueryParams) {
    let msg = Message::Query(MldQuery::general(qp.max_resp, qp.qrv, qp.qqic));
    for iface in ifaces.values() {
        if !iface.querier.is_querier() {
            continue;
        }
        if let Err(e) = send_to(&iface.sock, &msg, ALL_NODES_V6).await {
            debug!(iface = %iface.name, error = %e, "MLD: general query send failed");
        }
    }
}

/// Encode `msg` and send it to `dst` (the kernel builds the IPv6 header and fills
/// the ICMPv6 checksum).
async fn send_to(sock: &UdpSocket, msg: &Message, dst: Ipv6Addr) -> io::Result<()> {
    let bytes = msg.encode();
    sock.send_to(&bytes, (dst, 0)).await.map(|_| ())
}

/// Spawn a task reading datagrams off `sock`, tagging them with `ifindex` and the
/// IPv6 source address (a raw ICMPv6 socket delivers the payload without the IPv6
/// header, so the source comes from `recv_from`).
fn spawn_reader(sock: Arc<UdpSocket>, ifindex: u32, tx: mpsc::Sender<Packet>) {
    tokio::spawn(async move {
        let mut buf = vec![0u8; RECV_BUF];
        loop {
            match sock.recv_from(&mut buf).await {
                Ok((n, from)) => {
                    let src = match from {
                        std::net::SocketAddr::V6(a) => *a.ip(),
                        _ => Ipv6Addr::UNSPECIFIED,
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
                    warn!(ifindex, error = %e, "MLD: recv error, reader stopping");
                    return;
                }
            }
        }
    });
}

/// The interface's link-local (`fe80::/10`) IPv6 address — the source querier
/// election compares — via `getifaddrs`. `None` if none is assigned yet.
fn iface_linklocal_v6(ifname: &str) -> Option<Ipv6Addr> {
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
            if name.to_bytes() == ifname.as_bytes() && fam == libc::AF_INET6 {
                // SAFETY: an AF_INET6 sockaddr is a sockaddr_in6.
                let sin6 = unsafe { &*(node.ifa_addr as *const libc::sockaddr_in6) };
                let ip = Ipv6Addr::from(sin6.sin6_addr.s6_addr);
                let o = ip.octets();
                if o[0] == 0xfe && (o[1] & 0xc0) == 0x80 {
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

/// Open a raw `IPPROTO_ICMPV6` socket bound to `ifname`, hop limit 1, filtered to MLD
/// types. When `join_reports` is set it also joins `ff02::16`, `ff02::2` and `ff02::1`
/// so it *receives* the reports hosts send and the General Queries other queriers
/// send (for election). Needs `CAP_NET_RAW`.
fn open_mld_socket(ifname: &str, join_reports: bool) -> Result<(u32, UdpSocket)> {
    let cname = CString::new(ifname).context("interface name has an interior NUL")?;
    // SAFETY: `cname` is a valid C string for the duration of the call.
    let ifindex = unsafe { libc::if_nametoindex(cname.as_ptr()) };
    if ifindex == 0 {
        anyhow::bail!("interface {ifname:?} not found");
    }
    // SAFETY: a raw socket; the fd is taken into ownership immediately below.
    let fd = unsafe {
        libc::socket(
            libc::AF_INET6,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
            ICMPV6_PROTO as i32,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error())
            .context("socket(SOCK_RAW, IPPROTO_ICMPV6) — needs CAP_NET_RAW");
    }
    // SAFETY: `fd` was just returned by socket() and is owned by nobody else.
    let sock = unsafe { std::net::UdpSocket::from_raw_fd(fd) };

    bind_to_device(fd, ifname)?;

    // Pass only MLD ICMPv6 types (130/131/132/143); block everything else so NDP and
    // echo traffic never reaches us. `icmp6_filter` is 8×u32; 1 = block, 0 = pass.
    let mut filt = [0xffff_ffffu32; 8];
    for t in [MLD_QUERY, MLD_V1_REPORT, MLD_V1_DONE, MLD_V2_REPORT] {
        filt[(t >> 5) as usize] &= !(1u32 << (t & 31));
    }
    setsockopt_struct(fd, libc::IPPROTO_ICMPV6, ICMP6_FILTER, &filt).context("ICMP6_FILTER")?;

    setsockopt_int(
        fd,
        libc::IPPROTO_IPV6,
        libc::IPV6_MULTICAST_IF,
        ifindex as i32,
    )
    .context("IPV6_MULTICAST_IF")?;
    setsockopt_int(fd, libc::IPPROTO_IPV6, libc::IPV6_MULTICAST_LOOP, 0)?;
    setsockopt_int(fd, libc::IPPROTO_IPV6, libc::IPV6_MULTICAST_HOPS, MLD_HOPS)?;
    setsockopt_int(fd, libc::IPPROTO_IPV6, libc::IPV6_UNICAST_HOPS, MLD_HOPS)?;

    if join_reports {
        for group in [MLDV2_ALL_ROUTERS, ALL_ROUTERS_V6, ALL_NODES_V6] {
            // SAFETY: ipv6_mreq is plain POD; we set the group and interface index.
            let mut mreq: libc::ipv6_mreq = unsafe { mem::zeroed() };
            mreq.ipv6mr_multiaddr.s6_addr = group.octets();
            mreq.ipv6mr_interface = ifindex;
            setsockopt_struct(fd, libc::IPPROTO_IPV6, libc::IPV6_ADD_MEMBERSHIP, &mreq)
                .with_context(|| format!("IPV6_ADD_MEMBERSHIP {group}"))?;
        }
    }

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
