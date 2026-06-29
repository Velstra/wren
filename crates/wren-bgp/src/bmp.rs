//! BGP Monitoring Protocol (BMP, RFC 7854) — the wire encoding.
//!
//! BMP lets a router stream its BGP state to a monitoring station over a plain TCP
//! connection the *router* initiates: an Initiation message, then a Peer Up per
//! session that comes up, a Route Monitoring message wrapping each UPDATE the peer
//! sends (so the station sees the router's Adj-RIB-In), and a Peer Down when a
//! session drops. It is one-directional — the station only listens.
//!
//! This module is the pure codec (no sockets): the 6-byte Common Header (§4.1), the
//! 42-byte Per-Peer Header (§4.2) and builders for the message types Wren emits —
//! Initiation (§4.3), Peer Up (§4.10), Peer Down (§4.9), Route Monitoring (§4.6) and
//! Termination (§4.5). The async client that connects to the station and feeds it
//! these bytes lives in `wren-daemon` (`bmp.rs`), exactly as the RTR client does.
//!
//! A Route Monitoring / Peer Up body embeds a *complete* BGP PDU (an UPDATE or an
//! OPEN, header included) — produced by [`crate::message::Message::encode`] — so
//! this module never re-implements BGP message encoding.

use std::net::{IpAddr, Ipv4Addr};

/// The BMP version this crate speaks (§4.1). Version 3 is the published RFC 7854.
pub const VERSION: u8 = 3;

/// The Common Header length: version(1) · length(4) · type(1).
pub const COMMON_HEADER_LEN: usize = 6;

/// The Per-Peer Header length (§4.2): a fixed 42 octets.
pub const PER_PEER_HEADER_LEN: usize = 42;

/// BMP message types (§4.1).
pub mod msg_type {
    /// Route Monitoring — an UPDATE the peer sent (§4.6).
    pub const ROUTE_MONITORING: u8 = 0;
    /// Statistics Report (§4.8).
    pub const STATISTICS_REPORT: u8 = 1;
    /// Peer Down Notification (§4.9).
    pub const PEER_DOWN: u8 = 2;
    /// Peer Up Notification (§4.10).
    pub const PEER_UP: u8 = 3;
    /// Initiation (§4.3).
    pub const INITIATION: u8 = 4;
    /// Termination (§4.5).
    pub const TERMINATION: u8 = 5;
    /// Route Mirroring (§4.7).
    pub const ROUTE_MIRRORING: u8 = 6;
}

/// Information TLV types carried in Initiation / Peer Up (§4.4).
pub mod info_type {
    /// A free-form UTF-8 string.
    pub const STRING: u16 = 0;
    /// sysDescr (the routing daemon's description).
    pub const SYS_DESCR: u16 = 1;
    /// sysName (the router's name).
    pub const SYS_NAME: u16 = 2;
}

/// Peer Type values for the Per-Peer Header (§4.2).
pub mod peer_type {
    /// A Global Instance Peer — an ordinary BGP peer (no RD, no VRF).
    pub const GLOBAL_INSTANCE: u8 = 0;
}

/// Peer Flags (§4.2): the V bit — set when the peer address is IPv6.
pub const PEER_FLAG_V_IPV6: u8 = 0x80;

/// Peer Down reason codes (§4.9).
pub mod peer_down_reason {
    /// The local system closed the session; a BGP NOTIFICATION follows.
    pub const LOCAL_NOTIFICATION: u8 = 1;
    /// The local system closed the session for an FSM event; a 2-byte code follows.
    pub const LOCAL_FSM: u8 = 2;
    /// The remote system closed the session with a NOTIFICATION (which follows).
    pub const REMOTE_NOTIFICATION: u8 = 3;
    /// The remote system closed the session without a NOTIFICATION.
    pub const REMOTE_NO_NOTIFICATION: u8 = 4;
    /// The peer was de-configured.
    pub const PEER_DECONFIGURED: u8 = 5;
}

/// The Per-Peer Header (§4.2): which peer a Route Monitoring / Peer Up / Peer Down
/// message is about, and when it was observed.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct PerPeerHeader {
    /// Peer Type (§4.2) — [`peer_type::GLOBAL_INSTANCE`] for an ordinary peer.
    pub peer_type: u8,
    /// Peer Flags (§4.2) — only the V bit ([`PEER_FLAG_V_IPV6`]) is used here.
    pub flags: u8,
    /// Peer Distinguisher (§4.2) — zero for a Global Instance Peer.
    pub distinguisher: [u8; 8],
    /// The peer's address.
    pub address: IpAddr,
    /// The peer's Autonomous System number (4-octet).
    pub asn: u32,
    /// The peer's BGP Identifier.
    pub bgp_id: Ipv4Addr,
    /// Observation time, whole seconds since the Unix epoch.
    pub timestamp_secs: u32,
    /// Observation time, the microseconds part.
    pub timestamp_micros: u32,
}

impl PerPeerHeader {
    /// A Global Instance Peer header — the common case (no route distinguisher). The
    /// V flag is derived from the address family.
    pub fn global(
        address: IpAddr,
        asn: u32,
        bgp_id: Ipv4Addr,
        timestamp_secs: u32,
        timestamp_micros: u32,
    ) -> Self {
        let flags = if address.is_ipv6() { PEER_FLAG_V_IPV6 } else { 0 };
        PerPeerHeader {
            peer_type: peer_type::GLOBAL_INSTANCE,
            flags,
            distinguisher: [0; 8],
            address,
            asn,
            bgp_id,
            timestamp_secs,
            timestamp_micros,
        }
    }

    /// Append the 42-octet Per-Peer Header to `out`.
    fn encode(&self, out: &mut Vec<u8>) {
        out.push(self.peer_type);
        out.push(self.flags);
        out.extend_from_slice(&self.distinguisher);
        encode_addr16(out, self.address);
        out.extend_from_slice(&self.asn.to_be_bytes());
        out.extend_from_slice(&self.bgp_id.octets());
        out.extend_from_slice(&self.timestamp_secs.to_be_bytes());
        out.extend_from_slice(&self.timestamp_micros.to_be_bytes());
    }
}

/// Append an address as a 16-octet field (§4.2): a full IPv6, or an IPv4 in the last
/// four octets with the leading twelve zeroed.
fn encode_addr16(out: &mut Vec<u8>, addr: IpAddr) {
    match addr {
        IpAddr::V4(a) => {
            out.extend_from_slice(&[0u8; 12]);
            out.extend_from_slice(&a.octets());
        }
        IpAddr::V6(a) => out.extend_from_slice(&a.octets()),
    }
}

/// Wrap a message `body` in the 6-byte Common Header for `msg_type`, patching the
/// total length (§4.1).
fn with_header(msg_type: u8, body: &[u8]) -> Vec<u8> {
    let total = (COMMON_HEADER_LEN + body.len()) as u32;
    let mut out = Vec::with_capacity(total as usize);
    out.push(VERSION);
    out.extend_from_slice(&total.to_be_bytes());
    out.push(msg_type);
    out.extend_from_slice(body);
    out
}

/// Append one Information TLV — `type(2) · length(2) · value` (§4.4).
fn info_tlv(out: &mut Vec<u8>, tlv_type: u16, value: &[u8]) {
    out.extend_from_slice(&tlv_type.to_be_bytes());
    out.extend_from_slice(&(value.len() as u16).to_be_bytes());
    out.extend_from_slice(value);
}

/// Build an Initiation message (§4.3): the first message on the connection, carrying
/// the router's sysName and sysDescr.
pub fn initiation(sys_name: &str, sys_descr: &str) -> Vec<u8> {
    let mut body = Vec::new();
    info_tlv(&mut body, info_type::SYS_DESCR, sys_descr.as_bytes());
    info_tlv(&mut body, info_type::SYS_NAME, sys_name.as_bytes());
    with_header(msg_type::INITIATION, &body)
}

/// Build a Termination message (§4.5) with a single Reason TLV (type 1, a 2-octet
/// reason code) — sent before the router closes the connection cleanly.
pub fn termination(reason: u16) -> Vec<u8> {
    let mut body = Vec::new();
    info_tlv(&mut body, 1, &reason.to_be_bytes());
    with_header(msg_type::TERMINATION, &body)
}

/// Build a Peer Up Notification (§4.10): the per-peer header, the local end's
/// address and ports, and the two OPEN messages exchanged (each a full BGP PDU).
pub fn peer_up(
    pph: &PerPeerHeader,
    local_addr: IpAddr,
    local_port: u16,
    remote_port: u16,
    sent_open: &[u8],
    received_open: &[u8],
) -> Vec<u8> {
    let mut body = Vec::new();
    pph.encode(&mut body);
    encode_addr16(&mut body, local_addr);
    body.extend_from_slice(&local_port.to_be_bytes());
    body.extend_from_slice(&remote_port.to_be_bytes());
    body.extend_from_slice(sent_open);
    body.extend_from_slice(received_open);
    with_header(msg_type::PEER_UP, &body)
}

/// Build a Peer Down Notification (§4.9): the per-peer header, a reason code and any
/// reason-specific data (a BGP NOTIFICATION for the *notification* reasons, a 2-octet
/// FSM code for [`peer_down_reason::LOCAL_FSM`], nothing otherwise).
pub fn peer_down(pph: &PerPeerHeader, reason: u8, data: &[u8]) -> Vec<u8> {
    let mut body = Vec::new();
    pph.encode(&mut body);
    body.push(reason);
    body.extend_from_slice(data);
    with_header(msg_type::PEER_DOWN, &body)
}

/// Build a Route Monitoring message (§4.6): the per-peer header followed by one
/// complete BGP UPDATE PDU (header included) as received from the peer.
pub fn route_monitoring(pph: &PerPeerHeader, bgp_update: &[u8]) -> Vec<u8> {
    let mut body = Vec::new();
    pph.encode(&mut body);
    body.extend_from_slice(bgp_update);
    with_header(msg_type::ROUTE_MONITORING, &body)
}

/// Parse a BMP Common Header from the front of `buf`, returning the message type and
/// the total message length (header included), or `None` if the buffer is short or
/// the version is not [`VERSION`]. A station uses this to frame the stream.
pub fn parse_common_header(buf: &[u8]) -> Option<(u8, usize)> {
    if buf.len() < COMMON_HEADER_LEN || buf[0] != VERSION {
        return None;
    }
    let len = u32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]) as usize;
    if len < COMMON_HEADER_LEN {
        return None;
    }
    Some((buf[5], len))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pph() -> PerPeerHeader {
        PerPeerHeader::global(
            "10.0.0.2".parse().unwrap(),
            65002,
            "10.0.0.2".parse().unwrap(),
            0x1122_3344,
            0x5566_7788,
        )
    }

    #[test]
    fn common_header_frames_every_message() {
        for msg in [
            initiation("r1", "wren"),
            termination(0),
            peer_up(&pph(), "10.0.0.1".parse().unwrap(), 179, 50000, &[1, 2, 3], &[4, 5]),
            peer_down(&pph(), peer_down_reason::REMOTE_NO_NOTIFICATION, &[]),
            route_monitoring(&pph(), &[9; 23]),
        ] {
            let (_, len) = parse_common_header(&msg).expect("header");
            assert_eq!(len, msg.len(), "Common Header length must match the buffer");
            assert_eq!(msg[0], VERSION);
        }
    }

    #[test]
    fn per_peer_header_is_42_octets_with_ipv4_in_the_low_four() {
        let mut out = Vec::new();
        pph().encode(&mut out);
        assert_eq!(out.len(), PER_PEER_HEADER_LEN);
        // Peer type 0, flags 0 (IPv4), distinguisher zeroed.
        assert_eq!(out[0], peer_type::GLOBAL_INSTANCE);
        assert_eq!(out[1], 0);
        assert_eq!(&out[2..10], &[0u8; 8]);
        // Address: 12 zero octets then 10.0.0.2.
        assert_eq!(&out[10..22], &[0u8; 12]);
        assert_eq!(&out[22..26], &[10, 0, 0, 2]);
        // AS 65002, then the BGP id 10.0.0.2.
        assert_eq!(&out[26..30], &65002u32.to_be_bytes());
        assert_eq!(&out[30..34], &[10, 0, 0, 2]);
    }

    #[test]
    fn ipv6_peer_sets_the_v_flag_and_full_address() {
        let h = PerPeerHeader::global("2001:db8::2".parse().unwrap(), 65002, "10.0.0.2".parse().unwrap(), 0, 0);
        assert_eq!(h.flags, PEER_FLAG_V_IPV6);
        let mut out = Vec::new();
        h.encode(&mut out);
        let addr: std::net::Ipv6Addr = "2001:db8::2".parse().unwrap();
        assert_eq!(&out[10..26], &addr.octets());
    }

    #[test]
    fn initiation_carries_sysname_and_sysdescr() {
        let msg = initiation("router-a", "wren 0.1");
        let (ty, _) = parse_common_header(&msg).unwrap();
        assert_eq!(ty, msg_type::INITIATION);
        // The body is sysDescr TLV then sysName TLV; both strings appear verbatim.
        let body = &msg[COMMON_HEADER_LEN..];
        assert!(body.windows(8).any(|w| w == b"wren 0.1"));
        assert!(body.windows(8).any(|w| w == b"router-a"));
    }

    #[test]
    fn peer_up_embeds_both_opens_and_the_ports() {
        let msg = peer_up(&pph(), "10.0.0.1".parse().unwrap(), 179, 50000, &[0xAA; 29], &[0xBB; 29]);
        let (ty, len) = parse_common_header(&msg).unwrap();
        assert_eq!(ty, msg_type::PEER_UP);
        assert_eq!(len, msg.len());
        // After the common + per-peer header: local addr(16) + ports(4) + two OPENs.
        let off = COMMON_HEADER_LEN + PER_PEER_HEADER_LEN;
        assert_eq!(&msg[off + 16..off + 18], &179u16.to_be_bytes());
        assert_eq!(&msg[off + 18..off + 20], &50000u16.to_be_bytes());
        assert!(msg[off + 20..].starts_with(&[0xAA; 29]));
        assert!(msg.ends_with(&[0xBB; 29]));
    }

    #[test]
    fn route_monitoring_appends_the_update_pdu() {
        let update = [7u8; 30];
        let msg = route_monitoring(&pph(), &update);
        let (ty, _) = parse_common_header(&msg).unwrap();
        assert_eq!(ty, msg_type::ROUTE_MONITORING);
        assert!(msg.ends_with(&update));
        assert_eq!(msg.len(), COMMON_HEADER_LEN + PER_PEER_HEADER_LEN + update.len());
    }

    #[test]
    fn parse_common_header_rejects_short_or_wrong_version() {
        assert!(parse_common_header(&[VERSION, 0, 0, 0, 6]).is_none()); // too short
        assert!(parse_common_header(&[2, 0, 0, 0, 6, 0]).is_none()); // wrong version
        assert!(parse_common_header(&[VERSION, 0, 0, 0, 3, 0]).is_none()); // len < header
    }
}
