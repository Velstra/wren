//! # The RIPv2 socket runner (RFC 2453)
//!
//! This is the async transport and timer driver that turns the pure
//! [`wren_rip::RipTable`] into a live RIP speaker. The protocol *decisions* all
//! live in `wren-rip` (metric arithmetic, split horizon, the timeout/garbage
//! state machine); this module only does the I/O the table can't:
//!
//! * opens one UDP socket **per interface**, bound to `0.0.0.0:520`, joined to
//!   the RIP multicast group `224.0.0.9` and pinned to that interface
//!   (`SO_BINDTODEVICE` + `IP_MULTICAST_IF`), so a datagram's arrival interface is
//!   implicit and split horizon needs no per-packet `IP_PKTINFO` decode;
//! * sends the startup whole-table request (RFC 2453 §3.9.1) out every interface;
//! * feeds received Responses into the table, answers whole-table Requests, and
//!   drives the periodic (30 s) and triggered updates plus the timeout/garbage
//!   ticks;
//! * forwards the table's [`RipEvent`]s to the central router as [`RouteUpdate`]s.
//!
//! The socket options that `tokio`/`std` don't expose are set with `libc`
//! `setsockopt` on the raw fd before the socket is handed to `tokio` — the same
//! minimal-dependency approach as `wren-netlink`.

use std::ffi::CString;
use std::fmt::Write as _;
use std::io;
use std::mem;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::os::raw::c_void;
use std::os::unix::io::FromRawFd;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};

use crate::sockopt::{setsockopt_int, setsockopt_struct};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, oneshot};
use tokio::time::MissedTickBehavior;
use tracing::{debug, info, warn};

use wren_core::{NextHop, Protocol, Route};
use wren_rip::{
    Command, Entry, Message, RipEvent, RipTable, RouteInfo, MAX_ENTRIES, PORT, UPDATE_SECS,
};

use crate::connected;
use crate::router::{Redistribution, RouteUpdate};

/// The RIPv2 multicast group (RFC 2453 §3.1): all-RIP-routers.
const RIP_MCAST: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 9);
/// How often the timeout/garbage timers are advanced and any pending triggered
/// update is flushed. One second is fine: the table's deadlines are in seconds.
const HOUSEKEEPING_SECS: u64 = 1;
/// Receive buffer; a RIP datagram is at most 4 + 25·20 = 504 octets.
const RECV_BUF: usize = 1500;

/// One RIP-speaking interface: its kernel index and the socket bound to it.
struct Iface {
    name: String,
    ifindex: u32,
    sock: Arc<UdpSocket>,
}

/// A datagram received on one interface, handed to the central task.
struct Packet {
    ifindex: u32,
    src: SocketAddrV4,
    data: Vec<u8>,
}

/// A `show rip` / `show ripng` query, answered by the RIP task itself out of the
/// [`RipTable`] it owns (no shared access, like the other protocols' `show`).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RipQuery {
    /// RIP's own routing table (destination, metric, gateway, interface).
    Routes,
}

/// A control-socket query plus the channel to answer it on. Shared by RIPv2 and
/// RIPng — both run the same address-neutral [`RipTable`].
pub struct RipQueryRequest {
    /// What to report.
    pub query: RipQuery,
    /// Where to send the rendered answer.
    pub respond: oneshot::Sender<String>,
}

/// Render RIP's routing table (à la `show ip rip`), one route per line, resolving
/// each route's interface index to a name via `iface_name`. Shared by RIPv2 and
/// RIPng, so it formats from the address-neutral [`RouteInfo`].
pub fn render_rip_routes(
    routes: &[RouteInfo],
    iface_name: impl Fn(u32) -> Option<String>,
) -> String {
    if routes.is_empty() {
        return "no rip routes\n".to_string();
    }
    let mut out = String::new();
    for r in routes {
        let _ = write!(out, "{}", r.prefix);
        if !r.next_hop.is_unspecified() {
            let _ = write!(out, " via {}", r.next_hop);
        }
        if let Some(name) = iface_name(r.ifindex) {
            let _ = write!(out, " dev {name}");
        }
        if r.metric >= wren_rip::METRIC_INFINITY {
            out.push_str(" metric unreachable");
        } else {
            let _ = write!(out, " metric {}", r.metric);
        }
        if r.connected {
            out.push_str(" (connected)");
        } else if r.redistributed {
            out.push_str(" (redistributed)");
        }
        out.push('\n');
    }
    out
}

/// Run RIP on `interfaces`, forwarding learned/lost routes to `updates`. Returns
/// when a socket error tears the runner down; otherwise runs until cancelled.
///
/// `redist` carries RIB best-path routes the central router pushes for
/// redistribution; RIP advertises each to its neighbours (at `redistribute_metric`,
/// 1..=15) and poisons it again when its best path goes away.
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
            open_rip_socket(name).with_context(|| format!("opening RIP socket on {name:?}"))?;
        let sock =
            Arc::new(UdpSocket::from_std(std_sock).context("registering RIP socket with tokio")?);
        info!(interface = %name, ifindex, "RIP listening on 224.0.0.9:520");
        ifaces.push(Iface {
            name: name.clone(),
            ifindex,
            sock,
        });
    }
    if ifaces.is_empty() {
        warn!("RIP is enabled but no interfaces are configured — nothing to do");
        return Ok(());
    }

    // One receiver task per interface funnels datagrams into a single channel so
    // the central task below is the sole owner of the RipTable.
    let (pkt_tx, mut pkt_rx) = mpsc::channel::<Packet>(256);
    for iface in &ifaces {
        spawn_receiver(iface.sock.clone(), iface.ifindex, pkt_tx.clone());
    }
    drop(pkt_tx); // only the receiver tasks keep the channel open

    // Solicit each neighbour's whole table at startup (RFC 2453 §3.9.1).
    let request = Message::request_full_table().encode();
    for iface in &ifaces {
        if let Err(e) = iface.sock.send_to(&request, (RIP_MCAST, PORT)).await {
            warn!(interface = %iface.name, error = %e, "sending startup RIP request");
        }
    }

    let mut table = RipTable::new();

    // Redistribute our directly-connected networks: advertise them over RIP and
    // register them in the RIB (where Protocol::Connected outranks everything; the
    // kernel already owns the matching forwarding entry, so the router won't
    // reinstall it).
    for net in connected::discover(&interfaces) {
        if !net.prefix.is_ipv4() {
            continue; // IPv6 connected networks belong to RIPng
        }
        if let Some(iface) = ifaces.iter().find(|i| i.name == net.ifname) {
            table.add_connected(net.prefix, iface.ifindex);
        }
        info!(prefix = %net.prefix, interface = %net.ifname, "RIP advertising connected network");
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
    periodic.tick().await; // consume the immediate first tick
    let mut housekeeping = tokio::time::interval(Duration::from_secs(HOUSEKEEPING_SECS));
    housekeeping.tick().await;

    loop {
        tokio::select! {
            received = pkt_rx.recv() => {
                let Some(pkt) = received else {
                    warn!("all RIP receivers stopped");
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

/// Fold a redistribution change from the central router into the RIP table: an
/// IPv4 route is injected as one of ours (advertised at `metric`); a withdrawal
/// poisons it (metric 16) so neighbours are told it is gone. Non-IPv4 routes are
/// ignored (those belong to RIPng).
fn apply_redistribution(table: &mut RipTable, r: Redistribution, metric: u32, now: u64) {
    match r {
        Redistribution::Announce(route) => {
            if route.prefix.is_ipv4() {
                table.add_redistributed(route.prefix, metric);
            }
        }
        Redistribution::Withdraw(prefix) => {
            table.withdraw_redistributed(&prefix, now);
        }
    }
}

/// Spawn a task that reads datagrams from one interface socket into `pkt_tx`.
fn spawn_receiver(sock: Arc<UdpSocket>, ifindex: u32, pkt_tx: mpsc::Sender<Packet>) {
    tokio::spawn(async move {
        let mut buf = vec![0u8; RECV_BUF];
        loop {
            match sock.recv_from(&mut buf).await {
                Ok((n, SocketAddr::V4(src))) => {
                    let pkt = Packet {
                        ifindex,
                        src,
                        data: buf[..n].to_vec(),
                    };
                    if pkt_tx.send(pkt).await.is_err() {
                        break; // central task gone
                    }
                }
                Ok((_, SocketAddr::V6(_))) => {} // RIPv2 is IPv4-only; ignore
                Err(e) => {
                    warn!(ifindex, error = %e, "RIP receive failed");
                    break;
                }
            }
        }
    });
}

/// Process one received datagram: learn from Responses, answer whole-table
/// Requests, forwarding any resulting RIB events.
async fn handle_packet(
    table: &mut RipTable,
    ifaces: &[Iface],
    pkt: &Packet,
    now: u64,
    updates: &mpsc::Sender<RouteUpdate>,
) {
    let msg = match Message::decode(&pkt.data) {
        Ok(m) => m,
        Err(e) => {
            debug!(error = %e, src = %pkt.src, "ignoring malformed RIP datagram");
            return;
        }
    };
    let from = *pkt.src.ip();

    match msg.command {
        Command::Request => {
            // Answer the standard "send me your whole table" request (§3.9.1) on
            // the same interface, applying split horizon. Specific-entry queries
            // are not answered yet.
            if msg.is_full_table_request() {
                if let Some(iface) = iface_by_index(ifaces, pkt.ifindex) {
                    let entries = table.advertise(pkt.ifindex);
                    send_response(&iface.sock, SocketAddr::V4(pkt.src), &entries).await;
                }
            }
        }
        Command::Response => {
            for entry in &msg.entries {
                if let Some(ev) = table.process(entry, from, pkt.ifindex, now) {
                    forward_event(ev, updates).await;
                }
            }
        }
    }
}

/// Send a triggered update (only changed routes, RFC 2453 §3.10.1) out every
/// interface, then clear the change flags. A no-op when nothing changed.
///
/// This collapses the RFC's randomized 1–5 s triggered-update timer into the
/// 1 s housekeeping cadence (and an immediate flush after each received packet),
/// which is simpler and still rate-limits the bursts.
async fn flush_triggered(table: &mut RipTable, ifaces: &[Iface]) {
    if !table.has_changes() {
        return;
    }
    for iface in ifaces {
        let entries = table.triggered(iface.ifindex);
        send_response(&iface.sock, SocketAddr::from((RIP_MCAST, PORT)), &entries).await;
    }
    table.clear_changed();
}

/// Send the whole table (periodic update, RFC 2453 §3.8) out every interface.
async fn send_full_update(table: &RipTable, ifaces: &[Iface]) {
    for iface in ifaces {
        let entries = table.advertise(iface.ifindex);
        send_response(&iface.sock, SocketAddr::from((RIP_MCAST, PORT)), &entries).await;
    }
}

/// Send `entries` as one or more Response datagrams to `dst`, splitting at the
/// 25-RTE-per-datagram limit (RFC 2453 §4). A no-op for an empty entry set.
async fn send_response(sock: &UdpSocket, dst: SocketAddr, entries: &[Entry]) {
    for chunk in entries.chunks(MAX_ENTRIES) {
        let msg = Message::response(chunk.to_vec()).encode();
        if let Err(e) = sock.send_to(&msg, dst).await {
            warn!(error = %e, %dst, "sending RIP response");
        }
    }
}

/// Translate a table event into the router's protocol-agnostic update. RIP
/// presents exactly one route per prefix, so its RIB source is a constant.
async fn forward_event(ev: RipEvent, updates: &mpsc::Sender<RouteUpdate>) {
    let update = match ev {
        RipEvent::Learned(route) => RouteUpdate::Announce(route),
        RipEvent::Lost(prefix) => RouteUpdate::Withdraw {
            prefix,
            protocol: Protocol::Rip,
            source: 0,
        },
    };
    let _ = updates.send(update).await; // router gone → daemon is shutting down
}

fn iface_by_index(ifaces: &[Iface], ifindex: u32) -> Option<&Iface> {
    ifaces.iter().find(|i| i.ifindex == ifindex)
}

// ---------------------------------------------------------------------------
// Socket setup — the bits std/tokio don't expose, set via libc setsockopt.
// ---------------------------------------------------------------------------

/// Open a non-blocking UDP socket for RIP on `ifname`: reuse-port + bind-to-
/// device on `0.0.0.0:520`, joined to and sending out via `224.0.0.9` on that
/// interface. Returns its kernel index and the configured `std` socket.
fn open_rip_socket(ifname: &str) -> Result<(u32, std::net::UdpSocket)> {
    let cname = CString::new(ifname).context("interface name has an interior NUL")?;
    // SAFETY: `cname` is a valid NUL-terminated string for the call's duration.
    let ifindex = unsafe { libc::if_nametoindex(cname.as_ptr()) };
    if ifindex == 0 {
        anyhow::bail!("interface {ifname:?} not found");
    }

    // SAFETY: a plain socket(2); the fd is checked before use.
    let fd = unsafe {
        libc::socket(
            libc::AF_INET,
            libc::SOCK_DGRAM | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
            0,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error()).context("socket(AF_INET, SOCK_DGRAM)");
    }
    // Take ownership immediately so any early return closes the fd exactly once.
    // SAFETY: `fd` was just returned by socket() and is owned by nobody else.
    let sock = unsafe { std::net::UdpSocket::from_raw_fd(fd) };

    // Several RIP sockets share port 520 (one per interface).
    setsockopt_int(fd, libc::SOL_SOCKET, libc::SO_REUSEADDR, 1)?;
    setsockopt_int(fd, libc::SOL_SOCKET, libc::SO_REUSEPORT, 1)?;

    // Pin every send/receive on this socket to `ifname`.
    // SAFETY: `ifname` bytes + their length describe a valid optval buffer.
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

    // bind 0.0.0.0:520
    // SAFETY: a zeroed sockaddr_in with family/port/addr set is a valid bind addr.
    let mut sa: libc::sockaddr_in = unsafe { mem::zeroed() };
    sa.sin_family = libc::AF_INET as libc::sa_family_t;
    sa.sin_port = PORT.to_be();
    sa.sin_addr.s_addr = 0; // INADDR_ANY
    let rc = unsafe {
        libc::bind(
            fd,
            &sa as *const _ as *const libc::sockaddr,
            mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
        )
    };
    if rc < 0 {
        return Err(io::Error::last_os_error()).context("bind 0.0.0.0:520");
    }

    // Join 224.0.0.9 on this interface, and send our multicast out of it.
    // SAFETY: ip_mreqn is a plain POD; we fill all three fields.
    let mut mreq: libc::ip_mreqn = unsafe { mem::zeroed() };
    mreq.imr_multiaddr.s_addr = u32::from(RIP_MCAST).to_be();
    mreq.imr_address.s_addr = 0;
    mreq.imr_ifindex = ifindex as libc::c_int;
    setsockopt_struct(fd, libc::IPPROTO_IP, libc::IP_ADD_MEMBERSHIP, &mreq)
        .context("IP_ADD_MEMBERSHIP 224.0.0.9")?;
    setsockopt_struct(fd, libc::IPPROTO_IP, libc::IP_MULTICAST_IF, &mreq)
        .context("IP_MULTICAST_IF")?;
    // Don't loop our own multicast back; keep it on the local link (TTL 1).
    setsockopt_int(fd, libc::IPPROTO_IP, libc::IP_MULTICAST_LOOP, 0)?;
    setsockopt_int(fd, libc::IPPROTO_IP, libc::IP_MULTICAST_TTL, 1)?;

    Ok((ifindex, sock))
}

// The `setsockopt_int` / `setsockopt_struct` helpers now live in `crate::sockopt`
// (shared by every protocol runner) and are imported at the top of this module.
