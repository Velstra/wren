//! # The RIPng socket runner (RFC 2080)
//!
//! The IPv6 sibling of [`crate::rip`]. It drives the same address-neutral
//! [`wren_rip::RipTable`] distance-vector engine, but over IPv6: one UDP socket
//! per interface bound to `[::]:521`, joined to the RIPng multicast group
//! `FF02::9`, with the RIPng (RFC 2080) wire codec from [`wren_rip::ng`]. The
//! socket-option plumbing is the IPv6 analogue of the RIP runner and reuses its
//! `setsockopt` helpers.

use std::ffi::CString;
use std::io;
use std::mem;
use std::net::{IpAddr, SocketAddr, SocketAddrV6};
use std::os::raw::c_void;
use std::os::unix::io::FromRawFd;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::time::MissedTickBehavior;
use tracing::{debug, info, warn};

use wren_core::{NextHop, Protocol, Route};
use wren_rip::{ng, Advert, Command, RipEvent, RipTable, UPDATE_SECS};

use crate::connected;
use crate::rip::{render_rip_routes, RipQuery, RipQueryRequest};
use crate::sockopt::{setsockopt_int, setsockopt_struct};
use crate::router::{Redistribution, RouteUpdate};

/// Advance timers / flush triggered updates this often (seconds).
const HOUSEKEEPING_SECS: u64 = 1;
/// Receive buffer (an IPv6 minimum-MTU RIPng datagram fits easily).
const RECV_BUF: usize = 1500;

/// One RIPng-speaking interface.
struct Iface {
    name: String,
    ifindex: u32,
    sock: Arc<UdpSocket>,
}

/// A datagram received on one interface.
struct Packet {
    ifindex: u32,
    src: SocketAddrV6,
    data: Vec<u8>,
}

/// Run RIPng on `interfaces`, forwarding learned/lost routes to `updates`.
///
/// `redist` carries RIB best-path routes the central router pushes for
/// redistribution; RIPng advertises each IPv6 route to its neighbours (at
/// `redistribute_metric`, 1..=15) and poisons it again when its best path goes
/// away. This is the IPv6 sibling of [`crate::rip::run`]'s redistribution, over
/// the same address-neutral [`wren_rip::RipTable`].
pub async fn run(
    interfaces: Vec<String>,
    updates: mpsc::Sender<RouteUpdate>,
    mut redist: mpsc::Receiver<Redistribution>,
    redistribute_metric: u32,
    mut queries: mpsc::Receiver<RipQueryRequest>,
) -> Result<()> {
    let mut ifaces = Vec::with_capacity(interfaces.len());
    for name in &interfaces {
        let (ifindex, std_sock) =
            open_ripng_socket(name).with_context(|| format!("opening RIPng socket on {name:?}"))?;
        let sock =
            Arc::new(UdpSocket::from_std(std_sock).context("registering RIPng socket with tokio")?);
        info!(interface = %name, ifindex, "RIPng listening on [ff02::9]:521");
        ifaces.push(Iface {
            name: name.clone(),
            ifindex,
            sock,
        });
    }
    if ifaces.is_empty() {
        warn!("RIPng is enabled but no interfaces are configured — nothing to do");
        return Ok(());
    }

    let (pkt_tx, mut pkt_rx) = mpsc::channel::<Packet>(256);
    for iface in &ifaces {
        spawn_receiver(iface.sock.clone(), iface.ifindex, pkt_tx.clone());
    }
    drop(pkt_tx);

    // Solicit each neighbour's whole table at startup (RFC 2080 §2.4.1).
    let request = ng::Message::request_full_table().encode();
    for iface in &ifaces {
        if let Err(e) = iface
            .sock
            .send_to(&request, (ng::ALL_RIP_ROUTERS, ng::PORT))
            .await
        {
            warn!(interface = %iface.name, error = %e, "sending startup RIPng request");
        }
    }

    let mut table = RipTable::new();

    // Redistribute our directly-connected IPv6 networks (see crate::rip for the
    // IPv4 equivalent and the kernel-ownership rationale).
    for net in connected::discover(&interfaces) {
        if net.prefix.is_ipv4() {
            continue; // IPv4 connected networks belong to RIP
        }
        if let Some(iface) = ifaces.iter().find(|i| i.name == net.ifname) {
            table.add_connected(net.prefix, iface.ifindex);
        }
        info!(prefix = %net.prefix, interface = %net.ifname, "RIPng advertising connected network");
        let route = Route::new(
            net.prefix,
            Protocol::Connected,
            vec![NextHop::dev(net.ifname)],
            0,
        );
        let _ = updates.send(RouteUpdate::Announce(route)).await;
    }

    let start = Instant::now();
    let mut periodic = tokio::time::interval(Duration::from_secs(UPDATE_SECS));
    periodic.set_missed_tick_behavior(MissedTickBehavior::Delay);
    periodic.tick().await;
    let mut housekeeping = tokio::time::interval(Duration::from_secs(HOUSEKEEPING_SECS));
    housekeeping.tick().await;

    loop {
        tokio::select! {
            received = pkt_rx.recv() => {
                let Some(pkt) = received else {
                    warn!("all RIPng receivers stopped");
                    break;
                };
                let now = start.elapsed().as_secs();
                handle_packet(&mut table, &ifaces, &pkt, now, &updates).await;
                flush_triggered(&mut table, &ifaces).await;
            }
            _ = periodic.tick() => {
                let now = start.elapsed().as_secs();
                for ev in table.tick(now) {
                    forward_event(ev, &updates).await;
                }
                send_full_update(&table, &ifaces).await;
                table.clear_changed();
            }
            _ = housekeeping.tick() => {
                let now = start.elapsed().as_secs();
                for ev in table.tick(now) {
                    forward_event(ev, &updates).await;
                }
                flush_triggered(&mut table, &ifaces).await;
            }
            Some(r) = redist.recv() => {
                let now = start.elapsed().as_secs();
                apply_redistribution(&mut table, r, redistribute_metric, now);
                flush_triggered(&mut table, &ifaces).await;
            }
            Some(req) = queries.recv() => {
                let resp = match req.query {
                    RipQuery::Routes => render_rip_routes(&table.routes(), |idx| {
                        iface_by_index(&ifaces, idx).map(|i| i.name.clone())
                    }),
                };
                let _ = req.respond.send(resp);
            }
        }
    }
    Ok(())
}

/// Fold a redistribution change from the central router into the RIPng table: an
/// IPv6 route is injected as one of ours (advertised at `metric`); a withdrawal
/// poisons it (metric 16) so neighbours are told it is gone. Non-IPv6 routes are
/// ignored (those belong to RIP).
fn apply_redistribution(table: &mut RipTable, r: Redistribution, metric: u32, now: u64) {
    match r {
        Redistribution::Announce(route) => {
            if !route.prefix.is_ipv4() {
                table.add_redistributed(route.prefix, metric);
            }
        }
        Redistribution::Withdraw(prefix) => {
            table.withdraw_redistributed(&prefix, now);
        }
    }
}

fn spawn_receiver(sock: Arc<UdpSocket>, ifindex: u32, pkt_tx: mpsc::Sender<Packet>) {
    tokio::spawn(async move {
        let mut buf = vec![0u8; RECV_BUF];
        loop {
            match sock.recv_from(&mut buf).await {
                Ok((n, SocketAddr::V6(src))) => {
                    let pkt = Packet {
                        ifindex,
                        src,
                        data: buf[..n].to_vec(),
                    };
                    if pkt_tx.send(pkt).await.is_err() {
                        break;
                    }
                }
                Ok((_, SocketAddr::V4(_))) => {} // an AF_INET6 socket; shouldn't happen
                Err(e) => {
                    warn!(ifindex, error = %e, "RIPng receive failed");
                    break;
                }
            }
        }
    });
}

async fn handle_packet(
    table: &mut RipTable,
    ifaces: &[Iface],
    pkt: &Packet,
    now: u64,
    updates: &mpsc::Sender<RouteUpdate>,
) {
    let msg = match ng::Message::decode(&pkt.data) {
        Ok(m) => m,
        Err(e) => {
            debug!(error = %e, src = %pkt.src, "ignoring malformed RIPng datagram");
            return;
        }
    };
    let from = IpAddr::V6(*pkt.src.ip());

    match msg.command {
        Command::Request => {
            if msg.is_full_table_request() {
                if let Some(iface) = iface_by_index(ifaces, pkt.ifindex) {
                    let adverts = table.adverts(pkt.ifindex);
                    send_response(&iface.sock, SocketAddr::V6(pkt.src), &adverts).await;
                }
            }
        }
        Command::Response => {
            let ifname = iface_by_index(ifaces, pkt.ifindex).map(|i| i.name.as_str());
            for rte in &msg.entries {
                let next_hop = rte.next_hop.map(IpAddr::V6);
                if let Some(ev) = table.process_route(
                    rte.prefix,
                    rte.metric as u32,
                    next_hop,
                    from,
                    pkt.ifindex,
                    now,
                ) {
                    let ev = match ifname {
                        Some(name) => pin_linklocal_nexthop(ev, name),
                        None => ev,
                    };
                    forward_event(ev, updates).await;
                }
            }
        }
    }
}

/// A route via a link-local IPv6 gateway can only be installed in the kernel if
/// the outgoing interface is pinned, so attach the receiving interface to such a
/// next hop. Global/ULA next hops are routable on their own and left untouched.
fn pin_linklocal_nexthop(ev: RipEvent, ifname: &str) -> RipEvent {
    let RipEvent::Learned(mut route) = ev else {
        return ev;
    };
    for nh in &mut route.nexthops {
        if let Some(IpAddr::V6(a)) = nh.gateway {
            if (a.segments()[0] & 0xffc0) == 0xfe80 {
                nh.iface = Some(ifname.to_string());
            }
        }
    }
    RipEvent::Learned(route)
}

async fn flush_triggered(table: &mut RipTable, ifaces: &[Iface]) {
    if !table.has_changes() {
        return;
    }
    for iface in ifaces {
        let adverts = table.triggered_adverts(iface.ifindex);
        send_response(
            &iface.sock,
            SocketAddr::from((ng::ALL_RIP_ROUTERS, ng::PORT)),
            &adverts,
        )
        .await;
    }
    table.clear_changed();
}

async fn send_full_update(table: &RipTable, ifaces: &[Iface]) {
    for iface in ifaces {
        let adverts = table.adverts(iface.ifindex);
        send_response(
            &iface.sock,
            SocketAddr::from((ng::ALL_RIP_ROUTERS, ng::PORT)),
            &adverts,
        )
        .await;
    }
}

/// Send `adverts` as one or more RIPng Response datagrams to `dst`.
async fn send_response(sock: &UdpSocket, dst: SocketAddr, adverts: &[Advert]) {
    for chunk in adverts.chunks(ng::MAX_ENTRIES) {
        let msg = ng::Message::from_adverts(chunk);
        if msg.entries.is_empty() {
            continue;
        }
        if let Err(e) = sock.send_to(&msg.encode(), dst).await {
            warn!(error = %e, %dst, "sending RIPng response");
        }
    }
}

async fn forward_event(ev: RipEvent, updates: &mpsc::Sender<RouteUpdate>) {
    let update = match ev {
        RipEvent::Learned(route) => RouteUpdate::Announce(route),
        RipEvent::Lost(prefix) => RouteUpdate::Withdraw {
            table: wren_core::RT_TABLE_MAIN,
            prefix,
            protocol: Protocol::Rip,
            source: 0,
        },
    };
    let _ = updates.send(update).await;
}

fn iface_by_index(ifaces: &[Iface], ifindex: u32) -> Option<&Iface> {
    ifaces.iter().find(|i| i.ifindex == ifindex)
}

/// Open a non-blocking IPv6 UDP socket for RIPng on `ifname`: reuse-port +
/// bind-to-device on `[::]:521`, joined to and sending out via `FF02::9` on that
/// interface (hop limit 255, no loopback). Returns its index and the socket.
fn open_ripng_socket(ifname: &str) -> Result<(u32, std::net::UdpSocket)> {
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
    // SAFETY: `fd` was just returned by socket() and is owned by nobody else;
    // wrapping it ensures it is closed on any early return.
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

    // bind [::]:521
    // SAFETY: a zeroed sockaddr_in6 with family/port set is a valid bind addr
    // (sin6_addr stays :: = in6addr_any).
    let mut sa: libc::sockaddr_in6 = unsafe { mem::zeroed() };
    sa.sin6_family = libc::AF_INET6 as libc::sa_family_t;
    sa.sin6_port = ng::PORT.to_be();
    let rc = unsafe {
        libc::bind(
            fd,
            &sa as *const _ as *const libc::sockaddr,
            mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
        )
    };
    if rc < 0 {
        return Err(io::Error::last_os_error()).context("bind [::]:521");
    }

    // Join ff02::9 on this interface, and send our multicast out of it.
    // SAFETY: ipv6_mreq is a plain POD; we fill both fields.
    let mut mreq: libc::ipv6_mreq = unsafe { mem::zeroed() };
    mreq.ipv6mr_multiaddr.s6_addr = ng::ALL_RIP_ROUTERS.octets();
    mreq.ipv6mr_interface = ifindex;
    setsockopt_struct(fd, libc::IPPROTO_IPV6, libc::IPV6_ADD_MEMBERSHIP, &mreq)
        .context("IPV6_ADD_MEMBERSHIP ff02::9")?;
    setsockopt_int(
        fd,
        libc::IPPROTO_IPV6,
        libc::IPV6_MULTICAST_IF,
        ifindex as i32,
    )?;
    setsockopt_int(fd, libc::IPPROTO_IPV6, libc::IPV6_MULTICAST_LOOP, 0)?;
    // RIPng is exchanged with hop limit 255 (as RIPng/OSPFv3 implementations do).
    setsockopt_int(fd, libc::IPPROTO_IPV6, libc::IPV6_MULTICAST_HOPS, 255)?;

    Ok((ifindex, sock))
}
