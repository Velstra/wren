//! # The BFD socket runner (RFC 5880 / RFC 5881)
//!
//! The async transport and timer driver that turns the pure [`wren_bfd::Session`]
//! state machines into live BFD speakers. The protocol *decisions* live in
//! `wren-bfd` (the Control-packet codec and the §6.8.6 FSM); this module does only
//! the I/O and timekeeping the FSM can't:
//!
//! * binds one shared receive socket to `0.0.0.0:3784` (the BFD Control port) and,
//!   per peer, a connected transmit socket sending with IP TTL 255 (the GTSM check
//!   single-hop BFD uses, RFC 5881 §5);
//! * demultiplexes received packets by source address to the matching session
//!   (single-hop, one session per peer);
//! * drives each session's transmit timer (jittered, sub-second once Up) and its
//!   detection timer (Detect Mult × the negotiated receive interval);
//! * reports a session going **down** (after it had come up) to the protocols that
//!   subscribed to it, so they tear their adjacency to that peer down at once
//!   rather than waiting for a hold / dead timer.
//!
//! Sessions are **dynamic and multi-consumer**: a protocol [registers](BfdCommand)
//! a peer (BGP statically at startup, OSPF as neighbours reach Full and leave it),
//! and the runner creates the session on first registration and tears it down when
//! the last subscriber deregisters. A peer shared by two protocols has one session;
//! both are notified when it fails.
//!
//! Scope: single-hop asynchronous mode, IPv4, no authentication, no Echo — the
//! configuration that drives routing-protocol failover.

use std::collections::HashMap;
use std::fmt::Write as _;
use std::net::{IpAddr, Ipv4Addr};

use anyhow::{Context, Result};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, oneshot};
use tokio::time::{sleep_until, Duration, Instant};
use tracing::{debug, info, warn};

use wren_bfd::{ControlPacket, Session, SessionConfig, State};

/// The well-known UDP port for single-hop BFD Control packets (RFC 5881 §4).
const CONTROL_PORT: u16 = 3784;

/// The IP TTL single-hop BFD transmits with, so the receiver can apply the GTSM
/// check that the neighbour is exactly one hop away (RFC 5881 §5).
const SINGLE_HOP_TTL: u32 = 255;

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
    /// An OSPF neighbour (`[ospf] bfd = true`). Only constructed when the OSPF engine
    /// is compiled in.
    #[cfg_attr(not(feature = "ospf"), allow(dead_code))]
    Ospf,
}

/// A registration command from a protocol to the BFD engine.
pub enum BfdCommand {
    /// Track `peer` for `consumer`, notifying `notify` with the peer's address when
    /// the session goes down (after having come up). Creates the session if new;
    /// adds the subscriber if the session already exists.
    Register {
        /// The peer's address (the session's transmit/demux key).
        peer: Ipv4Addr,
        /// Which protocol is subscribing.
        consumer: BfdConsumer,
        /// Where to report this peer going down.
        notify: mpsc::Sender<IpAddr>,
    },
    /// Stop tracking `peer` for `consumer`. The session is torn down once no
    /// protocol subscribes to it any more. Only used by the OSPF consumer (BGP
    /// registrations are static), so unconstructed when OSPF is compiled out.
    #[cfg_attr(not(feature = "ospf"), allow(dead_code))]
    Deregister {
        /// The peer's address.
        peer: Ipv4Addr,
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
    peer: Ipv4Addr,
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
    peer: Ipv4Addr,
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
    // The shared receive socket: every peer sends its Control packets to our 3784.
    let rx = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, CONTROL_PORT))
        .await
        .with_context(|| format!("binding BFD control socket 0.0.0.0:{CONTROL_PORT}"))?;
    info!(port = CONTROL_PORT, "BFD listening");

    // Sessions are created on registration. Discriminators come from a per-process
    // counter — unique on this system, which is all the single-hop demux (by source
    // address) needs.
    let mut sessions: HashMap<Ipv4Addr, PeerSession> = HashMap::new();
    let mut next_discr: u32 = 1;

    let mut buf = [0u8; 128];
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
            r = rx.recv_from(&mut buf) => {
                match r {
                    Ok((n, src)) => on_receive(&mut sessions, &buf[..n], src.ip()),
                    Err(e) => debug!(error = %e, "BFD recv error"),
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

/// Apply a registration command: create or extend a session on Register, shrink or
/// remove it on Deregister.
async fn handle_command(
    sessions: &mut HashMap<Ipv4Addr, PeerSession>,
    next_discr: &mut u32,
    session_cfg: SessionConfig,
    cmd: BfdCommand,
) {
    match cmd {
        BfdCommand::Register { peer, consumer, notify } => {
            if let Some(s) = sessions.get_mut(&peer) {
                s.subscribers.insert(consumer, notify);
                debug!(%peer, ?consumer, "BFD subscription added to existing session");
                return;
            }
            let tx = match build_tx_socket(peer).await {
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
                peer,
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
        BfdCommand::Deregister { peer, consumer } => {
            if let Some(s) = sessions.get_mut(&peer) {
                s.subscribers.remove(&consumer);
                if s.subscribers.is_empty() {
                    sessions.remove(&peer);
                    info!(%peer, "BFD session torn down (no subscribers)");
                }
            }
        }
    }
}

/// Open a connected transmit socket for `peer`: an ephemeral local port (RFC 5881
/// §4 requires the source port be ephemeral) connected to the peer's 3784, sending
/// with TTL 255.
async fn build_tx_socket(peer: Ipv4Addr) -> Result<UdpSocket> {
    let sock = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).await.context("binding tx socket")?;
    sock.set_ttl(SINGLE_HOP_TTL).context("setting TTL 255")?;
    sock.connect((peer, CONTROL_PORT)).await.context("connecting tx socket")?;
    Ok(sock)
}

/// Notify every subscriber that `peer`'s session has gone down.
fn notify_down(s: &PeerSession) {
    for tx in s.subscribers.values() {
        let _ = tx.try_send(IpAddr::V4(s.peer));
    }
}

/// Handle a received datagram: decode it, demultiplex by source address to the
/// matching session, fold it into the FSM, and (re)arm that session's detection
/// timer. A transition out of Up to Down notifies the subscribers.
fn on_receive(sessions: &mut HashMap<Ipv4Addr, PeerSession>, buf: &[u8], src: IpAddr) {
    let IpAddr::V4(sip) = src else { return }; // IPv4 single-hop only for now
    let Some(pkt) = ControlPacket::decode(buf) else { return };
    let Some(s) = sessions.get_mut(&sip) else { return };
    if let Some(t) = s.sess.on_packet(&pkt) {
        info!(peer = %sip, from = t.from.label(), to = t.to.label(), "BFD session state change");
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
fn service(sessions: &mut HashMap<Ipv4Addr, PeerSession>) {
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
fn next_wakeup(sessions: &HashMap<Ipv4Addr, PeerSession>) -> Option<Instant> {
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
fn snapshot(sessions: &HashMap<Ipv4Addr, PeerSession>) -> Vec<SessionInfo> {
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
    out.sort_by_key(|i| u32::from(i.peer));
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
        "{:<18} {:<10} {:>11} {:>12} {:>8} {:>8}",
        "peer", "state", "local-discr", "remote-discr", "tx", "detect"
    );
    for r in rows {
        let _ = writeln!(
            out,
            "{:<18} {:<10} {:>11} {:>12} {:>6}ms {:>6}ms",
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
            peer: Ipv4Addr::new(10, 0, 0, 2),
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
}
