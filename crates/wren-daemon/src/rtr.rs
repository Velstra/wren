//! The RPKI-to-Router (RTR) client (RFC 8210): fetch ROAs live from a validating
//! cache and feed them to the BGP engine, instead of configuring them statically.
//!
//! One async task per configured cache. It connects over TCP, sends a Reset Query to
//! pull the full set, accumulates the streamed Prefix PDUs into a ROA set, and on each
//! End of Data pushes a fresh snapshot to the BGP task (which merges it with any static
//! `[[bgp.roa]]` and revalidates). It then refreshes incrementally with Serial Query
//! (on the refresh timer or a Serial Notify), handles a Cache Reset by re-syncing, and
//! reconnects with a fixed backoff on any error. The wire codec lives in
//! [`wren_bgp::rtr`]; this module is only the session and I/O.

use std::collections::BTreeSet;
use std::net::SocketAddr;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::OwnedReadHalf;
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::time::{sleep, timeout};
use tracing::{debug, info, warn};

use wren_bgp::rpki::Roa;
use wren_bgp::rtr::{pdu_length, Pdu, HEADER_LEN};

/// How long to wait for the TCP connection to the cache before retrying.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// How long to wait after a session ends before reconnecting.
const RECONNECT_BACKOFF: Duration = Duration::from_secs(10);
/// The default refresh interval (Serial Query period) when the cache advertises none.
const DEFAULT_REFRESH_SECS: u64 = 3600;
/// A sane upper bound on a single PDU, to reject a corrupt/hostile length field.
const MAX_PDU_LEN: usize = 65535;

/// One configured RTR cache to fetch ROAs from.
pub struct RtrConfig {
    /// The cache's address (host:port; the RTR port is conventionally 3323/tcp).
    pub server: SocketAddr,
    /// The refresh interval in seconds; `None` uses the cache's advertised value (or
    /// [`DEFAULT_REFRESH_SECS`]).
    pub refresh: Option<u32>,
}

/// Run the RTR client until the daemon stops: connect, sync, refresh, and reconnect on
/// failure. Each completed sync (End of Data) sends the full ROA set down `roas_tx`.
pub async fn run(cfg: RtrConfig, roas_tx: mpsc::Sender<Vec<Roa>>) {
    loop {
        match session(&cfg, &roas_tx).await {
            Ok(()) => return, // the BGP task is gone; nothing to feed
            Err(e) => debug!(server = %cfg.server, error = %e, "RTR session ended; reconnecting"),
        }
        sleep(RECONNECT_BACKOFF).await;
    }
}

/// One connection to the cache: Reset Query, then process PDUs until the socket fails.
/// Returns `Ok(())` only when the receiver (the BGP task) has gone away.
async fn session(cfg: &RtrConfig, roas_tx: &mpsc::Sender<Vec<Roa>>) -> std::io::Result<()> {
    let stream = timeout(CONNECT_TIMEOUT, TcpStream::connect(cfg.server))
        .await
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "RTR connect timed out"))??;
    info!(server = %cfg.server, "RTR connected to validating cache");
    let (mut rd, mut wr) = stream.into_split();

    let mut roas: BTreeSet<Roa> = BTreeSet::new();
    let mut session_id: u16 = 0;
    let mut serial: u32 = 0;
    let mut refresh = cfg.refresh.map(u64::from).unwrap_or(DEFAULT_REFRESH_SECS).max(1);

    // Pull the entire current ROA set to start.
    wr.write_all(&Pdu::ResetQuery.encode()).await?;

    loop {
        // Read the next PDU, or — after `refresh` seconds of quiet — ask for the delta.
        let pdu = tokio::select! {
            r = read_pdu(&mut rd) => r?,
            () = sleep(Duration::from_secs(refresh)) => {
                wr.write_all(&Pdu::SerialQuery { session_id, serial }.encode()).await?;
                continue;
            }
        };
        match pdu {
            Pdu::CacheResponse { session_id: sid } => session_id = sid,
            Pdu::IPv4Prefix { .. } | Pdu::IPv6Prefix { .. } => {
                if let Some((roa, announce)) = pdu.to_roa() {
                    if announce {
                        roas.insert(roa);
                    } else {
                        roas.remove(&roa);
                    }
                }
            }
            Pdu::EndOfData { session_id: sid, serial: s, refresh: rf, .. } => {
                session_id = sid;
                serial = s;
                if rf > 0 {
                    refresh = u64::from(rf);
                }
                let snapshot: Vec<Roa> = roas.iter().copied().collect();
                info!(server = %cfg.server, count = snapshot.len(), serial, "RTR ROA set updated");
                if roas_tx.send(snapshot).await.is_err() {
                    return Ok(()); // BGP task gone — stop the client
                }
            }
            // The cache lost our state: forget ours and re-sync from scratch.
            Pdu::CacheReset => {
                roas.clear();
                wr.write_all(&Pdu::ResetQuery.encode()).await?;
            }
            // A new serial is available: ask for the delta now.
            Pdu::SerialNotify { .. } => {
                wr.write_all(&Pdu::SerialQuery { session_id, serial }.encode()).await?;
            }
            Pdu::ErrorReport { code } => {
                warn!(server = %cfg.server, code, "RTR cache reported an error");
            }
            // PDUs a cache should not send us, and recognised-but-unhandled ones.
            Pdu::Unsupported { .. } | Pdu::SerialQuery { .. } | Pdu::ResetQuery => {}
        }
    }
}

/// Read one length-framed RTR PDU: the 8-byte header gives the total length, then the
/// remaining body follows.
async fn read_pdu(rd: &mut OwnedReadHalf) -> std::io::Result<Pdu> {
    let mut hdr = [0u8; HEADER_LEN];
    rd.read_exact(&mut hdr).await?;
    let len = pdu_length(&hdr).expect("8-byte header has a length") as usize;
    if !(HEADER_LEN..=MAX_PDU_LEN).contains(&len) {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "bad RTR PDU length"));
    }
    let mut buf = vec![0u8; len];
    buf[..HEADER_LEN].copy_from_slice(&hdr);
    if len > HEADER_LEN {
        rd.read_exact(&mut buf[HEADER_LEN..]).await?;
    }
    Pdu::decode(&buf).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))
}
