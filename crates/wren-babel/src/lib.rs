//! # wren-babel — Babel (RFC 8966)
//!
//! Babel is a loop-avoiding distance-vector routing protocol that works well on
//! both wired and wireless links and carries IPv4 and IPv6 routes over a single
//! IPv6 transport. Like [`wren_ospf`] and [`wren_bgp`], this crate is a
//! dependency-free (`std`-only) library holding the protocol's *pure* parts so
//! they are fully unit-testable with no sockets; the async UDP runner that drives
//! it lives in `wren-daemon`.
//!
//! What is in place so far:
//!
//! * the packet framing (§4.2) — the 4-byte header (Magic 42, Version 2, body
//!   length) and the body as a sequence of TLVs (§4.3), with `Pad1`/`PadN`;
//! * the [`tlv`] codec — Hello, IHU, Router-ID, Next Hop, Update, Route Request,
//!   Seqno Request, Acknowledgment Request/Acknowledgment, and the address
//!   encodings (AE 0 wildcard / 1 IPv4 / 2 IPv6 / 3 link-local IPv6), including
//!   prefix de-compression of `Update`s on receive (the §4.5 "default prefix").
//!
//! Still to come: the route table with the feasibility condition (§3.5), the
//! neighbour table and link-cost (Hello/IHU) computation, and the UDP runner.
//!
//! Babel runs over UDP port [`PORT`] (6696), sending to the link-local multicast
//! group [`MULTICAST`] (`ff02::1:6`) and to unicast neighbours.

#![forbid(unsafe_code)]

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use wren_core::Prefix;

pub mod neighbor;
pub mod table;
pub mod tlv;

pub use neighbor::NeighbourTable;
pub use table::{BabelEvent, RouteTable};
pub use tlv::Tlv;

// ===========================================================================
// Protocol constants (RFC 8966)
// ===========================================================================

/// The first byte of every Babel packet (§4.2).
pub const MAGIC: u8 = 42;

/// The Babel version this crate speaks (§4.2).
pub const VERSION: u8 = 2;

/// The well-known UDP port Babel uses (§4).
pub const PORT: u16 = 6696;

/// The link-local multicast group Babel floods to: `ff02::1:6` (§4).
pub const MULTICAST: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 1, 6);

/// The 4-byte packet header length (§4.2).
pub const HEADER_LEN: usize = 4;

/// The metric value meaning "unreachable" — a retraction (§3.2.5).
pub const METRIC_INFINITY: u16 = 0xFFFF;

/// A conventional default Hello interval, in centiseconds (4 s).
pub const DEFAULT_HELLO_INTERVAL: u16 = 400;

// Address Encodings (§4.1.1).
/// AE 0 — wildcard (no address; used by a full-table Route Request).
pub const AE_WILDCARD: u8 = 0;
/// AE 1 — IPv4.
pub const AE_IPV4: u8 = 1;
/// AE 2 — IPv6.
pub const AE_IPV6: u8 = 2;
/// AE 3 — link-local IPv6 (the `fe80::/64` prefix is implied; 8 octets on wire).
pub const AE_IPV6_LL: u8 = 3;

// ===========================================================================
// Packet
// ===========================================================================

/// A decoded Babel packet: its header is validated and stripped, leaving the body
/// TLVs (the optional packet trailer, used only for authentication, is ignored).
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct Packet {
    /// The TLVs carried in the packet body, in order.
    pub body: Vec<Tlv>,
}

/// Why a Babel packet or TLV could not be decoded.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum DecodeError {
    /// Fewer bytes than the header (or a field) requires.
    TooShort,
    /// The Magic byte was not [`MAGIC`].
    BadMagic(u8),
    /// The Version byte was not [`VERSION`].
    BadVersion(u8),
    /// The stated body length ran past the buffer.
    BadBodyLength,
    /// A TLV body was malformed.
    Malformed,
}

impl std::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DecodeError::TooShort => write!(f, "packet shorter than required"),
            DecodeError::BadMagic(m) => write!(f, "bad magic {m} (expected 42)"),
            DecodeError::BadVersion(v) => write!(f, "unsupported version {v}"),
            DecodeError::BadBodyLength => write!(f, "body length runs past the buffer"),
            DecodeError::Malformed => write!(f, "malformed TLV body"),
        }
    }
}

impl std::error::Error for DecodeError {}

impl Packet {
    /// A packet carrying `body`.
    pub fn new(body: Vec<Tlv>) -> Self {
        Packet { body }
    }

    /// Serialise the packet (header + body TLVs). `Update`s are written
    /// uncompressed (no omitted octets), which is always valid.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HEADER_LEN + 64);
        out.push(MAGIC);
        out.push(VERSION);
        out.extend_from_slice(&[0, 0]); // body length, patched below
        for tlv in &self.body {
            tlv.encode(&mut out);
        }
        let body_len = (out.len() - HEADER_LEN) as u16;
        out[2..4].copy_from_slice(&body_len.to_be_bytes());
        out
    }

    /// Parse and validate a Babel packet, reconstructing compressed `Update`
    /// prefixes against the §4.5 default-prefix register.
    pub fn decode(buf: &[u8]) -> Result<Packet, DecodeError> {
        if buf.len() < HEADER_LEN {
            return Err(DecodeError::TooShort);
        }
        if buf[0] != MAGIC {
            return Err(DecodeError::BadMagic(buf[0]));
        }
        if buf[1] != VERSION {
            return Err(DecodeError::BadVersion(buf[1]));
        }
        let body_len = u16::from_be_bytes([buf[2], buf[3]]) as usize;
        if HEADER_LEN + body_len > buf.len() {
            return Err(DecodeError::BadBodyLength);
        }
        let body = &buf[HEADER_LEN..HEADER_LEN + body_len];

        let mut ctx = Compress::default();
        let mut tlvs = Vec::new();
        let mut i = 0;
        while i < body.len() {
            let t = body[i];
            if t == tlv::TYPE_PAD1 {
                tlvs.push(Tlv::Pad1);
                i += 1;
                continue;
            }
            if i + 2 > body.len() {
                return Err(DecodeError::Malformed);
            }
            let len = body[i + 1] as usize;
            let start = i + 2;
            let end = start + len;
            if end > body.len() {
                return Err(DecodeError::Malformed);
            }
            match Tlv::decode(t, &body[start..end], &mut ctx) {
                Some(tlv) => tlvs.push(tlv),
                // Unknown / unparseable TLVs are preserved verbatim (Babel ignores
                // types it does not understand, §4.3).
                None => tlvs.push(Tlv::Unknown {
                    tlv_type: t,
                    body: body[start..end].to_vec(),
                }),
            }
            i = end;
        }
        Ok(Packet { body: tlvs })
    }
}

// ===========================================================================
// Compression state (§4.5) and address/prefix helpers
// ===========================================================================

/// The per-packet parser state used to de-compress `Update` prefixes: the most
/// recent "default prefix" per address family (§4.5). Only the receive path needs
/// it; we always transmit uncompressed.
#[derive(Default)]
pub(crate) struct Compress {
    default_v4: [u8; 4],
    default_v6: [u8; 16],
}

impl Compress {
    /// Record `prefix` as the default for its address family (Update flag 0x80).
    pub(crate) fn set_default(&mut self, prefix: &Prefix) {
        match prefix.addr() {
            IpAddr::V4(a) => self.default_v4 = a.octets(),
            IpAddr::V6(a) => self.default_v6 = a.octets(),
        }
    }

    fn default_for(&self, ae: u8) -> &[u8] {
        match ae {
            AE_IPV4 => &self.default_v4,
            _ => &self.default_v6,
        }
    }
}

/// Whether an IPv6 address is in `fe80::/10` (link-local), so it can be written
/// with AE 3.
fn is_link_local(a: &Ipv6Addr) -> bool {
    a.segments()[0] & 0xffc0 == 0xfe80
}

/// Append a full address and return the address encoding (AE) used. Link-local
/// IPv6 is compressed to its low 8 octets (AE 3).
pub(crate) fn write_address(out: &mut Vec<u8>, ip: IpAddr) -> u8 {
    match ip {
        IpAddr::V4(a) => {
            out.extend_from_slice(&a.octets());
            AE_IPV4
        }
        IpAddr::V6(a) if is_link_local(&a) => {
            out.extend_from_slice(&a.octets()[8..]);
            AE_IPV6_LL
        }
        IpAddr::V6(a) => {
            out.extend_from_slice(&a.octets());
            AE_IPV6
        }
    }
}

/// Read an address of encoding `ae` from the front of `buf`, returning it and the
/// number of bytes consumed.
pub(crate) fn read_address(ae: u8, buf: &[u8]) -> Option<(IpAddr, usize)> {
    match ae {
        AE_IPV4 => {
            let b: [u8; 4] = buf.get(..4)?.try_into().ok()?;
            Some((IpAddr::V4(Ipv4Addr::from(b)), 4))
        }
        AE_IPV6 => {
            let b: [u8; 16] = buf.get(..16)?.try_into().ok()?;
            Some((IpAddr::V6(Ipv6Addr::from(b)), 16))
        }
        AE_IPV6_LL => {
            let low: [u8; 8] = buf.get(..8)?.try_into().ok()?;
            let mut full = [0u8; 16];
            full[0] = 0xfe;
            full[1] = 0x80;
            full[8..].copy_from_slice(&low);
            Some((IpAddr::V6(Ipv6Addr::from(full)), 8))
        }
        _ => None,
    }
}

/// Append `prefix` uncompressed and return `(ae, plen)`. Only the significant
/// octets (`ceil(plen/8)`) are written.
pub(crate) fn write_prefix(out: &mut Vec<u8>, prefix: &Prefix) -> (u8, u8) {
    let plen = prefix.len();
    let nbytes = (plen as usize).div_ceil(8);
    match prefix.addr() {
        IpAddr::V4(a) => {
            out.extend_from_slice(&a.octets()[..nbytes.min(4)]);
            (AE_IPV4, plen)
        }
        IpAddr::V6(a) => {
            out.extend_from_slice(&a.octets()[..nbytes.min(16)]);
            (AE_IPV6, plen)
        }
    }
}

/// Reconstruct a prefix of encoding `ae`, length `plen`, with `omitted` leading
/// octets taken from the default prefix in `ctx`. Returns the prefix and the
/// number of address bytes consumed from `buf`.
pub(crate) fn read_prefix(
    ae: u8,
    plen: u8,
    omitted: u8,
    buf: &[u8],
    ctx: &Compress,
) -> Option<(Prefix, usize)> {
    let total = (plen as usize).div_ceil(8);
    let omitted = omitted as usize;
    if omitted > total {
        return None;
    }
    let present = total - omitted;
    if buf.len() < present {
        return None;
    }
    let mut addr = [0u8; 16];
    let deflt = ctx.default_for(ae);
    for (k, slot) in addr.iter_mut().take(omitted).enumerate() {
        *slot = *deflt.get(k)?;
    }
    addr[omitted..omitted + present].copy_from_slice(&buf[..present]);
    let ip = match ae {
        AE_IPV4 => IpAddr::V4(Ipv4Addr::new(addr[0], addr[1], addr[2], addr[3])),
        AE_IPV6 => {
            let b: [u8; 16] = addr;
            IpAddr::V6(Ipv6Addr::from(b))
        }
        _ => return None,
    };
    let prefix = Prefix::new(ip, plen).ok()?;
    Some((prefix, present))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tlv::Tlv;

    #[test]
    fn empty_packet_roundtrips() {
        let bytes = Packet::new(vec![]).encode();
        assert_eq!(bytes, vec![MAGIC, VERSION, 0, 0]);
        assert_eq!(Packet::decode(&bytes).unwrap(), Packet::new(vec![]));
    }

    #[test]
    fn rejects_bad_magic_and_version() {
        assert_eq!(Packet::decode(&[0, 2, 0, 0]), Err(DecodeError::BadMagic(0)));
        assert_eq!(Packet::decode(&[42, 9, 0, 0]), Err(DecodeError::BadVersion(9)));
        assert_eq!(Packet::decode(&[42]), Err(DecodeError::TooShort));
        assert_eq!(Packet::decode(&[42, 2, 0, 5]), Err(DecodeError::BadBodyLength));
    }

    #[test]
    fn pad1_and_padn_are_carried() {
        let pkt = Packet::new(vec![Tlv::Pad1, Tlv::PadN(3), Tlv::Pad1]);
        let bytes = pkt.encode();
        assert_eq!(Packet::decode(&bytes).unwrap(), pkt);
    }

    #[test]
    fn unknown_tlv_is_preserved() {
        let pkt = Packet::new(vec![Tlv::Unknown {
            tlv_type: 200,
            body: vec![1, 2, 3],
        }]);
        let bytes = pkt.encode();
        assert_eq!(Packet::decode(&bytes).unwrap(), pkt);
    }
}
