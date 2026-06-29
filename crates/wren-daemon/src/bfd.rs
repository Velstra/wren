//! # The BFD socket runner (RFC 5880 / RFC 5881)
//!
//! The async transport and timer driver that turns the pure [`wren_bfd::Session`]
//! state machines into live BFD speakers. The protocol *decisions* live in
//! `wren-bfd` (the Control-packet codec and the §6.8.6 FSM); this module does only
//! the I/O and timekeeping the FSM can't:
//!
//! * binds the shared receive sockets on the BFD Control port **3784** — one for
//!   IPv4 (`0.0.0.0`) and one for IPv6 (`[::]`, `IPV6_V6ONLY` so the two coexist) —
//!   and, per peer, a connected transmit socket sending with TTL / hop limit 255
//!   (the GTSM check single-hop BFD uses, RFC 5881 §5);
//! * demultiplexes received packets to a session by `(source address, scope)`
//!   — the scope (the receiving interface index) distinguishes IPv6 link-local
//!   peers, which is exactly how OSPFv3 identifies its neighbours;
//! * drives each session's transmit timer (jittered, sub-second once Up) and its
//!   detection timer (Detect Mult × the negotiated receive interval);
//! * reports a session going **down** (after it had come up) to the protocols that
//!   subscribed to it, so they tear their adjacency to that peer down at once
//!   rather than waiting for a hold / dead timer.
//!
//! Sessions are **dynamic and multi-consumer**: a protocol [registers](BfdCommand)
//! a peer (BGP statically at startup, the OSPF IGPs as a neighbour reaches Full and
//! leaves it), and the runner creates the session on first registration and tears
//! it down when the last subscriber deregisters. A peer shared by two protocols has
//! one session; both are notified when it fails.
//!
//! Scope: single-hop asynchronous mode, **IPv4 and IPv6**, no authentication, no
//! Echo — the configuration that drives routing-protocol failover.

use std::collections::HashMap;
use std::fmt::Write as _;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6};
use std::os::unix::io::{AsRawFd, FromRawFd};
use std::{io, mem};

use anyhow::{Context, Result};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, oneshot};
use tokio::time::{sleep_until, Duration, Instant};
use tracing::{debug, info, warn};

use wren_bfd::{ControlPacket, Session, SessionConfig, State};

use crate::sockopt::setsockopt_int;

/// The well-known UDP port for single-hop BFD Control packets (RFC 5881 §4).
const CONTROL_PORT: u16 = 3784;

/// The IP TTL / IPv6 hop limit single-hop BFD transmits with, so the receiver can
/// apply the GTSM check that the neighbour is exactly one hop away (RFC 5881 §5).
const SINGLE_HOP_TTL: u32 = 255;

/// How a session is keyed and demultiplexed: the peer's address plus a scope. The
/// scope is the interface index for an IPv6 **link-local** peer (two links can reuse
/// the same `fe80::` address — the scope keeps their sessions distinct) and `0`
/// otherwise. This is exactly the identity OSPFv3 hands us for a neighbour.
type PeerKey = (IpAddr, u32);

/// The resolved BFD configuration handed to the runner: just the shared session
/// timing, since sessions are created dynamically by registration.
pub struct BfdConfig {
    /// The shared session timing parameters from `[bfd]`.
    pub session: SessionConfig,
}

/// Which protocol a BFD subscription belongs to, so one peer can be tracked by
/// several protocols at once and deregistered independently.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum BfdConsumer {
    /// A BGP neighbour (`[[bgp.neighbor]] bfd = true`).
    Bgp,
    /// An OSPFv2 neighbour (`[ospf] bfd = true`). Only constructed when the OSPFv2
    /// engine is compiled in.
    #[cfg_attr(not(feature = "ospf"), allow(dead_code))]
    Ospf,
    /// An OSPFv3 neighbour (`[ospf3] bfd = true`). Only constructed when the OSPFv3
    /// engine is compiled in.
    #[cfg_attr(not(feature = "ospf3"), allow(dead_code))]
    Ospf3,
}

/// A registration command from a protocol to the BFD engine.
pub enum BfdCommand {
    /// Track `peer` for `consumer`, notifying `notify` with the peer's address when
    /// the session goes down (after having come up). Creates the session if new;
    /// adds the subscriber if the session already exists.
    Register {
        /// The peer's address (the session's transmit target and demux key).
        peer: IpAddr,
        /// The interface index for an IPv6 link-local peer, `0` otherwise.
        scope_id: u32,
        /// Which protocol is subscribing.
        consumer: BfdConsumer,
        /// Where to report this peer going down.
        notify: mpsc::Sender<IpAddr>,
    },
    /// Stop tracking `peer` for `consumer`. The session is torn down once no
    /// protocol subscribes to it any more. Only used by the OSPF consumers (BGP
    /// registrations are static), so unconstructed when both IGPs are compiled out.
    #[cfg_attr(
        not(any(feature = "ospf", feature = "ospf3")),
        allow(dead_code)
    )]
    Deregister {
        /// The peer's address.
        peer: IpAddr,
        /// The interface index for an IPv6 link-local peer, `0` otherwise.
        scope_id: u32,
        /// Which protocol is unsubscribing.
        consumer: BfdConsumer,
    },
}

/// A `show bfd` query, answered by the BFD task out of the sessions it owns.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum BfdQuery {
    /// The live sessions and their current state.
    Sessions,
}

/// A control-socket query plus the channel to answer it on.
pub struct BfdQueryRequest {
    /// What to report.
    pub query: BfdQuery,
    /// Where to send the rendered answer.
    pub respond: oneshot::Sender<String>,
}

/// One peer's live session: the FSM, its transmit socket, the timer deadlines the
/// runner maintains, and the protocols subscribed to its down notifications.
struct PeerSession {
    peer: IpAddr,
    sess: Session,
    tx: UdpSocket,
    /// When to transmit the next Control packet.
    next_tx: Instant,
    /// When the session fails if no packet arrives; `None` until the neighbour is
    /// first heard (detection is not armed before then).
    detect_deadline: Option<Instant>,
    /// The protocols to notify when this session goes down, by consumer.
    subscribers: HashMap<BfdConsumer, mpsc::Sender<IpAddr>>,
}

/// A flat snapshot of one session for the (pure) `show bfd` renderer.
struct SessionInfo {
    peer: IpAddr,
    state: State,
    local_discr: u32,
    remote_discr: u32,
    tx_ms: u64,
    detect_ms: u64,
}

/// Run the BFD engine until the daemon shuts down: create a session per registered
/// peer, drive them, and notify subscribers when a session that had come up fails.
pub async fn run(
    cfg: BfdConfig,
    mut register: mpsc::Receiver<BfdCommand>,
    mut queries: mpsc::Receiver<BfdQueryRequest>,
) -> Result<()> {
    // The shared receive sockets: every peer sends its Control packets to our 3784.
    // Bind both families so one engine serves IPv4 (BGP) and IPv6 (OSPFv3) peers; a
    // family whose bind fails (e.g. IPv6 disabled) is simply not listened on.
    let rx4 = match UdpSocket::bind((Ipv4Addr::UNSPECIFIED, CONTROL_PORT)).await {
        Ok(s) => Some(s),
        Err(e) => {
            warn!(error = %e, "BFD could not bind 0.0.0.0:{CONTROL_PORT}");
            None
        }
    };
    let rx6 = match bind_rx_v6() {
        Ok(s) => Some(s),
        Err(e) => {
            warn!(error = %e, "BFD could not bind [::]:{CONTROL_PORT}");
            None
        }
    };
    if rx4.is_none() && rx6.is_none() {
        anyhow::bail!("BFD could not bind any control socket on port {CONTROL_PORT}");
    }
    info!(port = CONTROL_PORT, ipv4 = rx4.is_some(), ipv6 = rx6.is_some(), "BFD listening");

    // Sessions are created on registration. Discriminators come from a per-process
    // counter — unique on this system, which is all the single-hop demux (by source
    // address and scope) needs.
    let mut sessions: HashMap<PeerKey, PeerSession> = HashMap::new();
    let mut next_discr: u32 = 1;

    let mut buf4 = [0u8; 128];
    let mut buf6 = [0u8; 128];
    loop {
        // Wake at the nearest of every session's transmit and detection deadlines.
        let wake = next_wakeup(&sessions);
        let timer = async move {
            match wake {
                Some(w) => sleep_until(w).await,
                None => std::future::pending::<()>().await,
            }
        };
        tokio::pin!(timer);

        tokio::select! {
            r = recv_from_opt(&rx4, &mut buf4) => {
                if let Some((n, src)) = r {
                    on_receive(&mut sessions, &buf4[..n], key_of(src));
                }
            }
            r = recv_from_opt(&rx6, &mut buf6) => {
                if let Some((n, src)) = r {
                    on_receive(&mut sessions, &buf6[..n], key_of(src));
                }
            }
            () = &mut timer => {}
            Some(cmd) = register.recv() => {
                handle_command(&mut sessions, &mut next_discr, cfg.session, cmd).await;
            }
            Some(req) = queries.recv() => {
                let resp = match req.query {
                    BfdQuery::Sessions => render_bfd_sessions(&snapshot(&sessions)),
                };
                let _ = req.respond.send(resp);
            }
        }

        // Service every session: fire detection timeouts, then due transmits.
        service(&mut sessions);
    }
}

/// Receive on an optional socket, or block forever if it is not bound — so a missing
/// address family simply never fires its `select!` branch.
async fn recv_from_opt(sock: &Option<UdpSocket>, buf: &mut [u8]) -> Option<(usize, SocketAddr)> {
    match sock {
        Some(s) => s.recv_from(buf).await.ok(),
        None => std::future::pending().await,
    }
}

/// The session key for a received datagram: its source address, plus the receiving
/// interface index as the scope for an IPv6 link-local source (the kernel fills
/// `sin6_scope_id`), `0` otherwise.
fn key_of(src: SocketAddr) -> PeerKey {
    match src {
        SocketAddr::V4(a) => (IpAddr::V4(*a.ip()), 0),
        SocketAddr::V6(a) => {
            // `fe80::/10` is link-local: only then does the scope (interface index)
            // distinguish it. `Ipv6Addr::is_unicast_link_local` is still unstable, so
            // test the prefix by hand.
            let o = a.ip().octets();
            let link_local = o[0] == 0xfe && (o[1] & 0xc0) == 0x80;
            let scope = if link_local { a.scope_id() } else { 0 };
            (IpAddr::V6(*a.ip()), scope)
        }
    }
}

/// Apply a registration command: create or extend a session on Register, shrink or
/// remove it on Deregister.
async fn handle_command(
    sessions: &mut HashMap<PeerKey, PeerSession>,
    next_discr: &mut u32,
    session_cfg: SessionConfig,
    cmd: BfdCommand,
) {
    match cmd {
        BfdCommand::Register { peer, scope_id, consumer, notify } => {
            let key = (peer, scope_id);
            if let Some(s) = sessions.get_mut(&key) {
                s.subscribers.insert(consumer, notify);
                debug!(%peer, ?consumer, "BFD subscription added to existing session");
                return;
            }
            let tx = match build_tx_socket(peer, scope_id).await {
                Ok(s) => s,
                Err(e) => {
                    warn!(%peer, error = %e, "BFD could not open transmit socket; not tracking");
                    return;
                }
            };
            let discr = *next_discr;
            *next_discr += 1;
            let mut subscribers = HashMap::new();
            subscribers.insert(consumer, notify);
            info!(%peer, ?consumer, "BFD session started");
            sessions.insert(
                key,
                PeerSession {
                    peer,
                    sess: Session::new(discr, session_cfg),
                    tx,
                    next_tx: Instant::now(), // begin the handshake immediately
                    detect_deadline: None,
                    subscribers,
                },
            );
        }
        BfdCommand::Deregister { peer, scope_id, consumer } => {
            let key = (peer, scope_id);
            if let Some(s) = sessions.get_mut(&key) {
                s.subscribers.remove(&consumer);
                if s.subscribers.is_empty() {
                    sessions.remove(&key);
                    info!(%peer, "BFD session torn down (no subscribers)");
                }
            }
        }
    }
}

/// Bind the shared IPv6 receive socket on `[::]:3784` with `IPV6_V6ONLY`, so it can
/// coexist with the IPv4 socket already bound to the same port. Hand-built because
/// the option must be set before `bind`.
fn bind_rx_v6() -> Result<UdpSocket> {
    // SAFETY: a UDP socket; the fd is taken into ownership immediately below.
    let fd = unsafe {
        libc::socket(
            libc::AF_INET6,
            libc::SOCK_DGRAM | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
            0,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error()).context("socket(AF_INET6, DGRAM)");
    }
    // SAFETY: `fd` was just returned by socket() and is owned by nobody else.
    let std_sock = unsafe { std::net::UdpSocket::from_raw_fd(fd) };
    setsockopt_int(fd, libc::IPPROTO_IPV6, libc::IPV6_V6ONLY, 1).context("IPV6_V6ONLY")?;
    // SAFETY: a zeroed sockaddr_in6 is a valid "any address" once family/port are set.
    let mut sa: libc::sockaddr_in6 = unsafe { mem::zeroed() };
    sa.sin6_family = libc::AF_INET6 as libc::sa_family_t;
    sa.sin6_port = CONTROL_PORT.to_be();
    // SAFETY: `sa` is a valid sockaddr_in6 of the declared length for the call.
    let rc = unsafe {
        libc::bind(
            fd,
            &sa as *const _ as *const libc::sockaddr,
            mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
        )
    };
    if rc < 0 {
        return Err(io::Error::last_os_error()).context("bind [::]:3784");
    }
    UdpSocket::from_std(std_sock).context("registering v6 control socket with tokio")
}

/// Open a connected transmit socket for `peer`: an ephemeral local port (RFC 5881
/// §4 requires the source port be ephemeral) connected to the peer's 3784, sending
/// with TTL / hop limit 255. For an IPv6 link-local peer the `scope_id` (interface
/// index) pins the source interface.
async fn build_tx_socket(peer: IpAddr, scope_id: u32) -> Result<UdpSocket> {
    match peer {
        IpAddr::V4(v4) => {
            let sock = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).await.context("binding tx socket")?;
            sock.set_ttl(SINGLE_HOP_TTL).context("setting TTL 255")?;
            sock.connect((v4, CONTROL_PORT)).await.context("connecting tx socket")?;
            Ok(sock)
        }
        IpAddr::V6(v6) => {
            let sock = UdpSocket::bind((Ipv6Addr::UNSPECIFIED, 0)).await.context("binding v6 tx socket")?;
            setsockopt_int(
                sock.as_raw_fd(),
                libc::IPPROTO_IPV6,
                libc::IPV6_UNICAST_HOPS,
                SINGLE_HOP_TTL as i32,
            )
            .context("setting IPV6_UNICAST_HOPS 255")?;
            let dst = SocketAddrV6::new(v6, CONTROL_PORT, 0, scope_id);
            sock.connect(dst).await.context("connecting v6 tx socket")?;
            Ok(sock)
        }
    }
}

/// Notify every subscriber that `peer`'s session has gone down.
fn notify_down(s: &PeerSession) {
    for tx in s.subscribers.values() {
        let _ = tx.try_send(s.peer);
    }
}

/// Handle a received datagram: decode it, demultiplex by `(source, scope)` to the
/// matching session, fold it into the FSM, and (re)arm that session's detection
/// timer. A transition out of Up to Down notifies the subscribers.
fn on_receive(sessions: &mut HashMap<PeerKey, PeerSession>, buf: &[u8], key: PeerKey) {
    let Some(pkt) = ControlPacket::decode(buf) else { return };
    let Some(s) = sessions.get_mut(&key) else { return };
    if let Some(t) = s.sess.on_packet(&pkt) {
        info!(peer = %s.peer, from = t.from.label(), to = t.to.label(), "BFD session state change");
        if t.from == State::Up && t.to == State::Down {
            notify_down(s);
        }
        // A state change must be advertised to the neighbour as soon as practical.
        s.next_tx = Instant::now();
    }
    // We have heard the neighbour: (re)arm the detection timer from the freshly
    // negotiated receive interval.
    let dt = s.sess.detection_time_us();
    s.detect_deadline = Some(Instant::now() + Duration::from_micros(dt));
}

/// Fire any elapsed detection timeout, then send any due Control packet, for every
/// session. A detection timeout on a session that had been up notifies subscribers.
fn service(sessions: &mut HashMap<PeerKey, PeerSession>) {
    let now = Instant::now();
    for s in sessions.values_mut() {
        if let Some(d) = s.detect_deadline {
            if now >= d {
                if let Some(t) = s.sess.on_detect_timeout() {
                    warn!(peer = %s.peer, "BFD detection time expired; session down");
                    s.detect_deadline = None; // disarm until the neighbour is heard again
                    s.next_tx = now; // announce the Down state immediately
                    if t.from == State::Up {
                        notify_down(s);
                    }
                }
            }
        }
        if now >= s.next_tx {
            let pkt = s.sess.build_control();
            let _ = s.tx.try_send(&pkt.encode());
            let iv = s.sess.transmit_interval_us();
            s.next_tx = now + Duration::from_micros(iv);
        }
    }
}

/// The earliest deadline across all sessions (transmit or detection), or `None`
/// when there are no sessions (the runner then idles until a registration).
fn next_wakeup(sessions: &HashMap<PeerKey, PeerSession>) -> Option<Instant> {
    let mut wake: Option<Instant> = None;
    for s in sessions.values() {
        wake = Some(wake.map_or(s.next_tx, |w: Instant| w.min(s.next_tx)));
        if let Some(d) = s.detect_deadline {
            wake = Some(wake.map_or(d, |w: Instant| w.min(d)));
        }
    }
    wake
}

/// Snapshot the sessions for the renderer (so rendering touches no live state),
/// sorted by peer for a stable listing.
fn snapshot(sessions: &HashMap<PeerKey, PeerSession>) -> Vec<SessionInfo> {
    let mut out: Vec<SessionInfo> = sessions
        .values()
        .map(|s| SessionInfo {
            peer: s.peer,
            state: s.sess.state(),
            local_discr: s.sess.local_discr(),
            remote_discr: s.sess.remote_discr(),
            tx_ms: s.sess.transmit_interval_us() / 1000,
            detect_ms: s.sess.detection_time_us() / 1000,
        })
        .collect();
    out.sort_by_key(|a| a.peer);
    out
}

/// Render the BFD sessions, one per line — `show bfd`.
fn render_bfd_sessions(rows: &[SessionInfo]) -> String {
    if rows.is_empty() {
        return "no bfd sessions\n".to_string();
    }
    let mut out = String::new();
    let _ = writeln!(
        out,
        "{:<28} {:<10} {:>11} {:>12} {:>8} {:>8}",
        "peer", "state", "local-discr", "remote-discr", "tx", "detect"
    );
    for r in rows {
        let _ = writeln!(
            out,
            "{:<28} {:<10} {:>11} {:>12} {:>6}ms {:>6}ms",
            r.peer.to_string(),
            r.state.label(),
            r.local_discr,
            r.remote_discr,
            r.tx_ms,
            r.detect_ms,
        );
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_an_empty_and_a_populated_table() {
        assert_eq!(render_bfd_sessions(&[]), "no bfd sessions\n");
        let rows = vec![SessionInfo {
            peer: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            state: State::Up,
            local_discr: 1,
            remote_discr: 2,
            tx_ms: 270,
            detect_ms: 900,
        }];
        let out = render_bfd_sessions(&rows);
        assert!(out.contains("10.0.0.2"));
        assert!(out.contains("Up"));
        assert!(out.contains("900ms"));
    }

    #[test]
    fn renders_an_ipv6_link_local_peer() {
        let rows = vec![SessionInfo {
            peer: "fe80::1".parse().unwrap(),
            state: State::Up,
            local_discr: 3,
            remote_discr: 4,
            tx_ms: 180,
            detect_ms: 600,
        }];
        let out = render_bfd_sessions(&rows);
        assert!(out.contains("fe80::1"));
        assert!(out.contains("600ms"));
    }

    #[test]
    fn keys_distinguish_family_and_scope() {
        let v4: SocketAddr = "10.0.0.2:3784".parse().unwrap();
        assert_eq!(key_of(v4), (IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 0));
        // A link-local source carries its receiving interface as the scope.
        let v6 = SocketAddr::V6(SocketAddrV6::new("fe80::1".parse().unwrap(), 3784, 0, 7));
        assert_eq!(key_of(v6), (IpAddr::V6("fe80::1".parse().unwrap()), 7));
        // A global IPv6 source is unscoped.
        let g = SocketAddr::V6(SocketAddrV6::new("2001:db8::1".parse().unwrap(), 3784, 0, 7));
        assert_eq!(key_of(g), (IpAddr::V6("2001:db8::1".parse().unwrap()), 0));
    }
}
