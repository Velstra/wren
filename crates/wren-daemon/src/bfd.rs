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
//! * reports a session going **down** (after it had come up) to the BGP engine on
//!   `down_tx`, so the BGP session to that peer is torn down at once rather than
//!   waiting for the Hold Timer.
//!
//! Scope: single-hop asynchronous mode, IPv4, no authentication, no Echo — the
//! configuration that drives BGP failover. Sessions are started for the BGP
//! neighbours configured with `bfd = true`.

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

/// The resolved BFD configuration handed to the runner.
pub struct BfdConfig {
    /// The peers to run a session to (the BGP neighbours with `bfd = true`).
    pub peers: Vec<Ipv4Addr>,
    /// The shared session timing parameters from `[bfd]`.
    pub session: SessionConfig,
}

/// A `show bfd` query, answered by the BFD task out of the sessions it owns.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum BfdQuery {
    /// The configured sessions and their current state.
    Sessions,
}

/// A control-socket query plus the channel to answer it on.
pub struct BfdQueryRequest {
    /// What to report.
    pub query: BfdQuery,
    /// Where to send the rendered answer.
    pub respond: oneshot::Sender<String>,
}

/// One peer's live session: the FSM, its transmit socket, and the two timer
/// deadlines the runner maintains.
struct PeerSession {
    peer: Ipv4Addr,
    sess: Session,
    tx: UdpSocket,
    /// When to transmit the next Control packet.
    next_tx: Instant,
    /// When the session fails if no packet arrives; `None` until the neighbour is
    /// first heard (detection is not armed before then).
    detect_deadline: Option<Instant>,
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

/// Run the BFD engine: bring up a session to every configured peer and drive them
/// until the daemon shuts down. `down_tx` carries the address of a peer whose
/// session has just gone down (after being up) to the BGP engine.
pub async fn run(
    cfg: BfdConfig,
    down_tx: mpsc::Sender<IpAddr>,
    mut queries: mpsc::Receiver<BfdQueryRequest>,
) -> Result<()> {
    // The shared receive socket: every peer sends its Control packets to our 3784.
    let rx = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, CONTROL_PORT))
        .await
        .with_context(|| format!("binding BFD control socket 0.0.0.0:{CONTROL_PORT}"))?;
    info!(port = CONTROL_PORT, sessions = cfg.peers.len(), "BFD listening");

    // One session (and connected transmit socket) per peer. Discriminators are
    // assigned from a per-process counter — unique on this system, which is all the
    // single-hop demux (by source address) needs.
    let now = Instant::now();
    let mut sessions: Vec<PeerSession> = Vec::with_capacity(cfg.peers.len());
    let mut next_discr: u32 = 1;
    for peer in cfg.peers {
        let tx = match build_tx_socket(peer).await {
            Ok(s) => s,
            Err(e) => {
                warn!(%peer, error = %e, "BFD could not open transmit socket; skipping session");
                continue;
            }
        };
        let discr = next_discr;
        next_discr += 1;
        sessions.push(PeerSession {
            peer,
            sess: Session::new(discr, cfg.session),
            tx,
            next_tx: now, // begin the handshake immediately
            detect_deadline: None,
        });
    }

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
                    Ok((n, src)) => on_receive(&mut sessions, &buf[..n], src.ip(), &down_tx).await,
                    Err(e) => debug!(error = %e, "BFD recv error"),
                }
            }
            () = &mut timer => {}
            Some(req) = queries.recv() => {
                let resp = match req.query {
                    BfdQuery::Sessions => render_bfd_sessions(&snapshot(&sessions)),
                };
                let _ = req.respond.send(resp);
            }
        }

        // Service every session: fire detection timeouts, then due transmits.
        service(&mut sessions, &down_tx).await;
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

/// Handle a received datagram: decode it, demultiplex by source address to the
/// matching session, fold it into the FSM, and (re)arm that session's detection
/// timer. A transition out of Up to Down is reported to BGP.
async fn on_receive(
    sessions: &mut [PeerSession],
    buf: &[u8],
    src: IpAddr,
    down_tx: &mpsc::Sender<IpAddr>,
) {
    let IpAddr::V4(sip) = src else { return }; // IPv4 single-hop only for now
    let Some(pkt) = ControlPacket::decode(buf) else { return };
    let Some(s) = sessions.iter_mut().find(|s| s.peer == sip) else { return };
    if let Some(t) = s.sess.on_packet(&pkt) {
        info!(peer = %sip, from = t.from.label(), to = t.to.label(), "BFD session state change");
        if t.from == State::Up && t.to == State::Down {
            let _ = down_tx.try_send(IpAddr::V4(sip));
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
/// session. A detection timeout on a session that had been up is reported to BGP.
async fn service(sessions: &mut [PeerSession], down_tx: &mpsc::Sender<IpAddr>) {
    let now = Instant::now();
    for s in sessions.iter_mut() {
        if let Some(d) = s.detect_deadline {
            if now >= d {
                if let Some(t) = s.sess.on_detect_timeout() {
                    warn!(peer = %s.peer, "BFD detection time expired; session down");
                    s.detect_deadline = None; // disarm until the neighbour is heard again
                    s.next_tx = now; // announce the Down state immediately
                    if t.from == State::Up {
                        let _ = down_tx.try_send(IpAddr::V4(s.peer));
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
/// when there are no sessions (the runner then idles).
fn next_wakeup(sessions: &[PeerSession]) -> Option<Instant> {
    let mut wake: Option<Instant> = None;
    for s in sessions {
        wake = Some(wake.map_or(s.next_tx, |w: Instant| w.min(s.next_tx)));
        if let Some(d) = s.detect_deadline {
            wake = Some(wake.map_or(d, |w: Instant| w.min(d)));
        }
    }
    wake
}

/// Snapshot the sessions for the renderer (so rendering touches no live state).
fn snapshot(sessions: &[PeerSession]) -> Vec<SessionInfo> {
    sessions
        .iter()
        .map(|s| SessionInfo {
            peer: s.peer,
            state: s.sess.state(),
            local_discr: s.sess.local_discr(),
            remote_discr: s.sess.remote_discr(),
            tx_ms: s.sess.transmit_interval_us() / 1000,
            detect_ms: s.sess.detection_time_us() / 1000,
        })
        .collect()
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
