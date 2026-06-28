//! # wren-bgp — BGP-4 (RFC 4271)
//!
//! The Border Gateway Protocol, built like [`wren_ospf`]: a dependency-free
//! (`std`-only) library holding the protocol's *pure* parts — the message and
//! path-attribute wire codec, and (later) the decision process / best-path
//! selection — so they are fully unit-testable with no sockets. The async TCP
//! session runner (port 179) that drives it lives in `wren-daemon`, behind tokio,
//! exactly as the RIP/OSPF runners do.
//!
//! What is in place so far:
//!
//! * [`message`] — the 19-byte message header (§4.1) and the four message types
//!   OPEN (§4.2), UPDATE (§4.3), NOTIFICATION (§4.5) and KEEPALIVE (§4.4), plus
//!   the NLRI / withdrawn-route prefix encoding (§4.3).
//! * [`attr`] — the UPDATE path attributes (§5): ORIGIN, AS_PATH, NEXT_HOP,
//!   MULTI_EXIT_DISC, LOCAL_PREF, ATOMIC_AGGREGATE and AGGREGATOR.
//! * [`decision`] — the decision process / best-path (§9.1.2.2).
//! * [`rib`] — the Adj-RIB-In / Loc-RIB with per-prefix path selection (§3.2).
//! * [`fsm`] — the per-peer session state machine (§8).
//!
//! The async TCP (port 179) session runner that drives all of this lives in
//! `wren-daemon` (`bgp.rs`), as the RIP/OSPF runners do. Still to come: MP-BGP
//! (RFC 4760) and route reflection.
//!
//! Autonomous System numbers are **4-octet** throughout the library (RFC 6793):
//! ASNs are kept as `u32`, the 4-octet AS Number capability (`code 65`) is
//! negotiated in the OPEN, and AS_PATH is encoded 4-octet-wide between two
//! 4-octet-capable speakers. Toward a legacy 2-octet speaker the wire AS_PATH is
//! 2-octet (with [`AS_TRANS`] standing in for any AS that does not fit), and the
//! 4-octet values ride through transitively in AS4_PATH / AS4_AGGREGATOR. See
//! [`capability`] and [`attr::reconstruct_as_path`].

#![forbid(unsafe_code)]

use std::net::{IpAddr, Ipv4Addr};

use wren_core::Prefix;

pub mod attr;
pub mod capability;
pub mod community;
pub mod decision;
pub mod ext_community;
pub mod fsm;
pub mod large_community;
pub mod message;
pub mod rib;

// ===========================================================================
// Protocol constants (RFC 4271)
// ===========================================================================

/// The BGP version this crate speaks (§4.2).
pub const VERSION: u8 = 4;

/// The well-known TCP port BGP listens on (§4).
pub const PORT: u16 = 179;

/// The 19-byte message header length: 16-byte marker + 2-byte length + 1 type.
pub const HEADER_LEN: usize = 19;

/// The message Marker (§4.1): all ones (historically the authentication field).
pub const MARKER: [u8; 16] = [0xff; 16];

/// The largest a BGP message may be, header included (§4.1).
pub const MAX_MESSAGE_LEN: usize = 4096;

/// The smallest a BGP message may be — a header-only KEEPALIVE (§4.1).
pub const MIN_MESSAGE_LEN: usize = HEADER_LEN;

/// A conventional default Hold Time, in seconds (§4.2 suggests 90; many use 180).
pub const DEFAULT_HOLD_TIME: u16 = 180;

/// The reserved 2-octet AS number that stands in for a 4-octet AS in any field a
/// legacy (2-octet) speaker reads — the OPEN `my_as` and a 2-octet AS_PATH /
/// AGGREGATOR (RFC 6793 §4 / RFC 4893).
pub const AS_TRANS: u16 = 23456;

/// Fit a 4-octet AS into a 2-octet field: itself when it fits, [`AS_TRANS`]
/// otherwise (RFC 6793 §4).
pub(crate) fn as_trans_fit(as_num: u32) -> u16 {
    if as_num > u16::MAX as u32 {
        AS_TRANS
    } else {
        as_num as u16
    }
}

/// The message types carried in the header's Type field (§4.1).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum MessageType {
    /// Open a session and negotiate parameters (§4.2).
    Open,
    /// Advertise/withdraw routes (§4.3).
    Update,
    /// Report an error and close the session (§4.5).
    Notification,
    /// Keep the session alive (§4.4).
    Keepalive,
}

impl MessageType {
    /// Decode the on-wire Type byte.
    pub fn from_u8(v: u8) -> Option<Self> {
        Some(match v {
            1 => MessageType::Open,
            2 => MessageType::Update,
            3 => MessageType::Notification,
            4 => MessageType::Keepalive,
            _ => return None,
        })
    }

    /// The on-wire Type byte.
    pub fn as_u8(self) -> u8 {
        match self {
            MessageType::Open => 1,
            MessageType::Update => 2,
            MessageType::Notification => 3,
            MessageType::Keepalive => 4,
        }
    }
}

// ===========================================================================
// NLRI prefix encoding (§4.3) — shared by NLRI and withdrawn routes.
// ===========================================================================
//
// A prefix is one length octet (the prefix length in bits) followed by the
// minimum number of whole octets needed to hold those bits (`ceil(len/8)`), most
// significant first. Base RFC 4271 NLRI is IPv4; IPv6 NLRI rides in MP-BGP.

/// Append `prefix` in BGP NLRI form (IPv4 only).
pub(crate) fn encode_prefix(out: &mut Vec<u8>, prefix: &Prefix) {
    let len = prefix.len();
    out.push(len);
    let octets = match prefix.addr() {
        IpAddr::V4(a) => a.octets(),
        IpAddr::V6(_) => return, // IPv4-only here
    };
    let n = len.div_ceil(8) as usize;
    out.extend_from_slice(&octets[..n]);
}

/// Decode a BGP NLRI prefix (IPv4) from the front of `buf`, returning the prefix
/// and the number of bytes consumed.
pub(crate) fn decode_prefix(buf: &[u8]) -> Option<(Prefix, usize)> {
    let len = *buf.first()?;
    if len > 32 {
        return None;
    }
    let n = (len as usize).div_ceil(8);
    if buf.len() < 1 + n {
        return None;
    }
    let mut octets = [0u8; 4];
    octets[..n].copy_from_slice(&buf[1..1 + n]);
    let prefix = Prefix::new(IpAddr::V4(Ipv4Addr::from(octets)), len).ok()?;
    Some((prefix, 1 + n))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(s: &str) -> Prefix {
        s.parse().unwrap()
    }

    #[test]
    fn message_type_roundtrips() {
        for t in [
            MessageType::Open,
            MessageType::Update,
            MessageType::Notification,
            MessageType::Keepalive,
        ] {
            assert_eq!(MessageType::from_u8(t.as_u8()), Some(t));
        }
        assert_eq!(MessageType::from_u8(0), None);
        assert_eq!(MessageType::from_u8(5), None);
    }

    #[test]
    fn prefix_roundtrips_at_byte_boundaries() {
        for s in ["0.0.0.0/0", "10.0.0.0/8", "192.168.0.0/16", "203.0.113.0/24", "198.51.100.7/32"] {
            let mut buf = Vec::new();
            encode_prefix(&mut buf, &p(s));
            let (decoded, used) = decode_prefix(&buf).expect("decodes");
            assert_eq!(decoded, p(s));
            assert_eq!(used, buf.len());
        }
    }

    #[test]
    fn prefix_uses_minimum_octets() {
        // /24 takes 3 address octets, /17 takes 3 too, /0 takes none.
        let mut buf = Vec::new();
        encode_prefix(&mut buf, &p("203.0.113.0/24"));
        assert_eq!(buf, vec![24, 203, 0, 113]);

        let mut buf = Vec::new();
        encode_prefix(&mut buf, &p("0.0.0.0/0"));
        assert_eq!(buf, vec![0]);

        let mut buf = Vec::new();
        encode_prefix(&mut buf, &p("10.128.0.0/9"));
        assert_eq!(buf, vec![9, 10, 128]);
    }

    #[test]
    fn decode_rejects_overlong_and_truncated() {
        assert!(decode_prefix(&[33, 1, 2, 3, 4, 5]).is_none()); // len > 32
        assert!(decode_prefix(&[24, 203, 0]).is_none()); // needs 3 octets, has 2
        assert!(decode_prefix(&[]).is_none());
    }
}
