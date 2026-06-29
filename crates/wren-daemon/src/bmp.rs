//! The BGP Monitoring Protocol (BMP, RFC 7854) client: stream this speaker's BGP
//! state to a monitoring station.
//!
//! One async task. It connects out to the configured station, sends an Initiation
//! message, then forwards the observations the central BGP task hands it over a
//! channel — a Peer Up when a session establishes, a Route Monitoring message
//! wrapping each UPDATE a peer sends, and a Peer Down when a session drops. On a
//! write failure it reconnects (re-sending Initiation) with a fixed backoff. The
//! wire codec lives in [`wren_bgp::bmp`]; this module is only the session and I/O.
//!
//! BMP is best-effort monitoring: the central task offers events with `try_send`, so
//! a slow or absent station never back-pressures the routing path — events that
//! don't fit the channel (e.g. while the station is down) are dropped. State is not
//! replayed on reconnect: the station sees observations from connect time forward.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::time::{sleep, timeout};
use tracing::{debug, info};

use wren_bgp::bmp::{self, PerPeerHeader};

/// How long to wait for the TCP connection to the station before retrying.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// How long to wait after a session ends before reconnecting.
const RECONNECT_BACKOFF: Duration = Duration::from_secs(10);

/// The configured BMP monitoring station.
pub struct BmpConfig {
    /// The station's address (host:port; the BMP port is conventionally 11019/tcp).
    pub station: SocketAddr,
    /// The sysName reported in the Initiation message.
    pub sys_name: String,
    /// The sysDescr reported in the Initiation message.
    pub sys_descr: String,
}

/// An observation the central BGP task hands the BMP client to forward. Each carries
/// the peer identity needed to build the Per-Peer Header, plus the message-specific
/// payload (the OPENs for Peer Up, the encoded UPDATE PDU for Route Monitoring).
pub enum BmpEvent {
    /// A session reached Established → a Peer Up Notification (RFC 7854 §4.10).
    PeerUp {
        /// The peer's transport address.
        peer: IpAddr,
        /// The peer's AS.
        asn: u32,
        /// The peer's BGP Identifier.
        bgp_id: Ipv4Addr,
        /// Our local address on the session.
        local_addr: IpAddr,
        /// Our local TCP port.
        local_port: u16,
        /// The peer's TCP port.
        remote_port: u16,
        /// The OPEN we sent, a full BGP PDU.
        sent_open: Vec<u8>,
        /// The OPEN we received, a full BGP PDU.
        received_open: Vec<u8>,
    },
    /// A session left Established → a Peer Down Notification (§4.9).
    PeerDown {
        /// The peer's transport address.
        peer: IpAddr,
        /// The peer's AS.
        asn: u32,
        /// The peer's BGP Identifier.
        bgp_id: Ipv4Addr,
    },
    /// A peer sent an UPDATE → a Route Monitoring message (§4.6).
    RouteMonitor {
        /// The peer's transport address.
        peer: IpAddr,
        /// The peer's AS.
        asn: u32,
        /// The peer's BGP Identifier.
        bgp_id: Ipv4Addr,
        /// The UPDATE re-encoded as a full BGP PDU.
        update: Vec<u8>,
    },
}

/// The current time as (seconds, microseconds) since the Unix epoch, for the
/// Per-Peer Header timestamp. A clock before the epoch reports zero.
fn now() -> (u32, u32) {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(d) => (d.as_secs() as u32, d.subsec_micros()),
        Err(_) => (0, 0),
    }
}

/// Encode one event into its BMP message, stamping it with the current time.
fn encode_event(ev: &BmpEvent) -> Vec<u8> {
    let (secs, micros) = now();
    match ev {
        BmpEvent::PeerUp {
            peer,
            asn,
            bgp_id,
            local_addr,
            local_port,
            remote_port,
            sent_open,
            received_open,
        } => {
            let pph = PerPeerHeader::global(*peer, *asn, *bgp_id, secs, micros);
            bmp::peer_up(&pph, *local_addr, *local_port, *remote_port, sent_open, received_open)
        }
        BmpEvent::PeerDown { peer, asn, bgp_id } => {
            let pph = PerPeerHeader::global(*peer, *asn, *bgp_id, secs, micros);
            bmp::peer_down(&pph, bmp::peer_down_reason::REMOTE_NO_NOTIFICATION, &[])
        }
        BmpEvent::RouteMonitor { peer, asn, bgp_id, update } => {
            let pph = PerPeerHeader::global(*peer, *asn, *bgp_id, secs, micros);
            bmp::route_monitoring(&pph, update)
        }
    }
}

/// Run the BMP client until the daemon stops: connect, send Initiation, forward
/// events, and reconnect on failure.
pub async fn run(cfg: BmpConfig, mut rx: mpsc::Receiver<BmpEvent>) {
    loop {
        match session(&cfg, &mut rx).await {
            Ok(()) => return, // the channel closed — the BGP task is gone
            Err(e) => debug!(station = %cfg.station, error = %e, "BMP session ended; reconnecting"),
        }
        sleep(RECONNECT_BACKOFF).await;
    }
}

/// One connection to the station: Initiation, then forward events until a write fails
/// or the channel closes. Returns `Ok(())` only when the sender (the BGP task) is gone.
async fn session(cfg: &BmpConfig, rx: &mut mpsc::Receiver<BmpEvent>) -> std::io::Result<()> {
    let mut stream = timeout(CONNECT_TIMEOUT, TcpStream::connect(cfg.station))
        .await
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "BMP connect timed out"))??;
    info!(station = %cfg.station, "BMP connected to monitoring station");
    stream.write_all(&bmp::initiation(&cfg.sys_name, &cfg.sys_descr)).await?;

    while let Some(ev) = rx.recv().await {
        stream.write_all(&encode_event(&ev)).await?;
    }
    // The channel closed (daemon shutting down): say goodbye cleanly.
    let _ = stream.write_all(&bmp::termination(0)).await;
    Ok(())
}
