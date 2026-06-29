//! The RPKI-to-Router (RTR) protocol wire codec (RFC 8210).
//!
//! RTR is how a router fetches Validated ROA Payloads from a validating cache instead
//! of configuring them statically: the router opens a TCP session, asks for the full
//! set (Reset Query) or the delta since a serial (Serial Query), and the cache streams
//! back Prefix PDUs — each an announce/withdraw of one ROA — bracketed by a Cache
//! Response and an End of Data. This module is the pure PDU [`Pdu`] codec: every PDU
//! encodes to and decodes from bytes, so the session logic in the daemon's runner is
//! testable in isolation and the codec is testable without a socket.
//!
//! Only the IPv4/IPv6 unicast ROA PDUs carry routing data; BGPsec Router Key PDUs
//! (type 9) are recognised and skipped ([`Pdu::Unsupported`]).

use std::net::{Ipv4Addr, Ipv6Addr};

use wren_core::Prefix;

use crate::rpki::Roa;

/// The protocol version Wren speaks (RFC 8210). Version 0 is the older RFC 6810.
pub const VERSION: u8 = 1;

/// The fixed 8-byte PDU header (version, type, a u16 field, and the total length).
pub const HEADER_LEN: usize = 8;

/// PDU type codes (RFC 8210 §5).
pub mod pdu_type {
    pub const SERIAL_NOTIFY: u8 = 0;
    pub const SERIAL_QUERY: u8 = 1;
    pub const RESET_QUERY: u8 = 2;
    pub const CACHE_RESPONSE: u8 = 3;
    pub const IPV4_PREFIX: u8 = 4;
    pub const IPV6_PREFIX: u8 = 6;
    pub const END_OF_DATA: u8 = 7;
    pub const CACHE_RESET: u8 = 8;
    pub const ROUTER_KEY: u8 = 9;
    pub const ERROR_REPORT: u8 = 10;
}

/// The Prefix PDU flag bit meaning "announce" (vs. withdraw when clear), RFC 8210 §5.
const FLAG_ANNOUNCE: u8 = 1;

/// A decoded (or to-be-encoded) RTR PDU.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Pdu {
    /// Cache → router: a new serial is available; the router should Serial Query.
    SerialNotify { session_id: u16, serial: u32 },
    /// Router → cache: send the delta since `serial` for `session_id`.
    SerialQuery { session_id: u16, serial: u32 },
    /// Router → cache: send the entire current ROA set.
    ResetQuery,
    /// Cache → router: the start of a response, naming the session.
    CacheResponse { session_id: u16 },
    /// Cache → router: one IPv4 ROA (announce or withdraw).
    IPv4Prefix { announce: bool, prefix_len: u8, max_len: u8, addr: Ipv4Addr, asn: u32 },
    /// Cache → router: one IPv6 ROA (announce or withdraw).
    IPv6Prefix { announce: bool, prefix_len: u8, max_len: u8, addr: Ipv6Addr, asn: u32 },
    /// Cache → router: the end of a response, with the new serial and timers.
    EndOfData { session_id: u16, serial: u32, refresh: u32, retry: u32, expire: u32 },
    /// Cache → router: drop your cached state and Reset Query afresh.
    CacheReset,
    /// Cache → router: an error, with the protocol error code (RFC 8210 §12).
    ErrorReport { code: u16 },
    /// A recognised but unhandled PDU type (e.g. BGPsec Router Key) — skipped.
    Unsupported { pdu_type: u8 },
}

/// A PDU decode failure.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum RtrError {
    /// The buffer is shorter than the PDU claims (need to read more).
    Truncated,
    /// The length field is invalid for the PDU type.
    BadLength,
    /// The PDU type code is not known.
    UnknownType(u8),
}

impl std::fmt::Display for RtrError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RtrError::Truncated => write!(f, "truncated RTR PDU"),
            RtrError::BadLength => write!(f, "bad RTR PDU length"),
            RtrError::UnknownType(t) => write!(f, "unknown RTR PDU type {t}"),
        }
    }
}

impl std::error::Error for RtrError {}

/// The total length an RTR PDU declares, read from the 4-byte length field of an
/// 8-byte header. `None` if `buf` is shorter than a header. The async runner uses this
/// to frame the stream: read the header, then the rest of the PDU.
pub fn pdu_length(buf: &[u8]) -> Option<u32> {
    if buf.len() < HEADER_LEN {
        return None;
    }
    Some(u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]))
}

impl Pdu {
    /// Encode this PDU to bytes (header + body).
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HEADER_LEN);
        match self {
            Pdu::SerialNotify { session_id, serial } => {
                header(&mut out, pdu_type::SERIAL_NOTIFY, *session_id, 12);
                out.extend_from_slice(&serial.to_be_bytes());
            }
            Pdu::SerialQuery { session_id, serial } => {
                header(&mut out, pdu_type::SERIAL_QUERY, *session_id, 12);
                out.extend_from_slice(&serial.to_be_bytes());
            }
            Pdu::ResetQuery => header(&mut out, pdu_type::RESET_QUERY, 0, 8),
            Pdu::CacheResponse { session_id } => {
                header(&mut out, pdu_type::CACHE_RESPONSE, *session_id, 8)
            }
            Pdu::IPv4Prefix { announce, prefix_len, max_len, addr, asn } => {
                header(&mut out, pdu_type::IPV4_PREFIX, 0, 20);
                out.push(if *announce { FLAG_ANNOUNCE } else { 0 });
                out.push(*prefix_len);
                out.push(*max_len);
                out.push(0);
                out.extend_from_slice(&addr.octets());
                out.extend_from_slice(&asn.to_be_bytes());
            }
            Pdu::IPv6Prefix { announce, prefix_len, max_len, addr, asn } => {
                header(&mut out, pdu_type::IPV6_PREFIX, 0, 32);
                out.push(if *announce { FLAG_ANNOUNCE } else { 0 });
                out.push(*prefix_len);
                out.push(*max_len);
                out.push(0);
                out.extend_from_slice(&addr.octets());
                out.extend_from_slice(&asn.to_be_bytes());
            }
            Pdu::EndOfData { session_id, serial, refresh, retry, expire } => {
                header(&mut out, pdu_type::END_OF_DATA, *session_id, 24);
                out.extend_from_slice(&serial.to_be_bytes());
                out.extend_from_slice(&refresh.to_be_bytes());
                out.extend_from_slice(&retry.to_be_bytes());
                out.extend_from_slice(&expire.to_be_bytes());
            }
            Pdu::CacheReset => header(&mut out, pdu_type::CACHE_RESET, 0, 8),
            Pdu::ErrorReport { code } => {
                // Minimal Error Report: no encapsulated PDU, no text (both length 0).
                header(&mut out, pdu_type::ERROR_REPORT, *code, 16);
                out.extend_from_slice(&0u32.to_be_bytes()); // encapsulated PDU length
                out.extend_from_slice(&0u32.to_be_bytes()); // error text length
            }
            Pdu::Unsupported { pdu_type } => header(&mut out, *pdu_type, 0, 8),
        }
        out
    }

    /// Decode one PDU from the front of `buf`. The slice must hold at least the whole
    /// PDU (use [`pdu_length`] to frame the stream first); returns [`RtrError::Truncated`]
    /// otherwise.
    pub fn decode(buf: &[u8]) -> Result<Pdu, RtrError> {
        if buf.len() < HEADER_LEN {
            return Err(RtrError::Truncated);
        }
        let pdu_type = buf[1];
        let u16_field = u16::from_be_bytes([buf[2], buf[3]]);
        let length = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]) as usize;
        if length < HEADER_LEN {
            return Err(RtrError::BadLength);
        }
        if buf.len() < length {
            return Err(RtrError::Truncated);
        }
        let body = &buf[HEADER_LEN..length];
        match pdu_type {
            pdu_type::SERIAL_NOTIFY => {
                let serial = be_u32(body, 0)?;
                Ok(Pdu::SerialNotify { session_id: u16_field, serial })
            }
            pdu_type::SERIAL_QUERY => {
                let serial = be_u32(body, 0)?;
                Ok(Pdu::SerialQuery { session_id: u16_field, serial })
            }
            pdu_type::RESET_QUERY => Ok(Pdu::ResetQuery),
            pdu_type::CACHE_RESPONSE => Ok(Pdu::CacheResponse { session_id: u16_field }),
            pdu_type::IPV4_PREFIX => {
                if body.len() < 12 {
                    return Err(RtrError::BadLength);
                }
                Ok(Pdu::IPv4Prefix {
                    announce: body[0] & FLAG_ANNOUNCE != 0,
                    prefix_len: body[1],
                    max_len: body[2],
                    addr: Ipv4Addr::new(body[4], body[5], body[6], body[7]),
                    asn: be_u32(body, 8)?,
                })
            }
            pdu_type::IPV6_PREFIX => {
                if body.len() < 24 {
                    return Err(RtrError::BadLength);
                }
                let mut o = [0u8; 16];
                o.copy_from_slice(&body[4..20]);
                Ok(Pdu::IPv6Prefix {
                    announce: body[0] & FLAG_ANNOUNCE != 0,
                    prefix_len: body[1],
                    max_len: body[2],
                    addr: Ipv6Addr::from(o),
                    asn: be_u32(body, 20)?,
                })
            }
            pdu_type::END_OF_DATA => Ok(Pdu::EndOfData {
                session_id: u16_field,
                serial: be_u32(body, 0)?,
                refresh: be_u32(body, 4)?,
                retry: be_u32(body, 8)?,
                expire: be_u32(body, 12)?,
            }),
            pdu_type::CACHE_RESET => Ok(Pdu::CacheReset),
            pdu_type::ERROR_REPORT => Ok(Pdu::ErrorReport { code: u16_field }),
            pdu_type::ROUTER_KEY => Ok(Pdu::Unsupported { pdu_type }),
            other => Err(RtrError::UnknownType(other)),
        }
    }

    /// If this is a Prefix PDU, the ROA it carries and whether it is an announce
    /// (`true`) or a withdraw (`false`). `None` for every non-prefix PDU.
    pub fn to_roa(&self) -> Option<(Roa, bool)> {
        let (prefix, max_len, asn, announce) = match self {
            Pdu::IPv4Prefix { announce, prefix_len, max_len, addr, asn } => {
                (Prefix::new((*addr).into(), *prefix_len).ok()?, *max_len, *asn, *announce)
            }
            Pdu::IPv6Prefix { announce, prefix_len, max_len, addr, asn } => {
                (Prefix::new((*addr).into(), *prefix_len).ok()?, *max_len, *asn, *announce)
            }
            _ => return None,
        };
        Some((Roa { prefix, max_length: max_len, origin_as: asn }, announce))
    }
}

/// Write the 8-byte RTR header for `pdu_type` with the given u16 field and total length.
fn header(out: &mut Vec<u8>, pdu_type: u8, u16_field: u16, length: u32) {
    out.push(VERSION);
    out.push(pdu_type);
    out.extend_from_slice(&u16_field.to_be_bytes());
    out.extend_from_slice(&length.to_be_bytes());
}

/// Read a big-endian u32 at `offset` in `body`, or [`RtrError::BadLength`] if short.
fn be_u32(body: &[u8], offset: usize) -> Result<u32, RtrError> {
    body.get(offset..offset + 4)
        .map(|s| u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
        .ok_or(RtrError::BadLength)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(pdu: Pdu) {
        let bytes = pdu.encode();
        // The encoded length matches the header's declared length.
        assert_eq!(pdu_length(&bytes), Some(bytes.len() as u32));
        assert_eq!(Pdu::decode(&bytes), Ok(pdu));
    }

    #[test]
    fn round_trips_every_pdu() {
        roundtrip(Pdu::SerialNotify { session_id: 7, serial: 42 });
        roundtrip(Pdu::SerialQuery { session_id: 7, serial: 42 });
        roundtrip(Pdu::ResetQuery);
        roundtrip(Pdu::CacheResponse { session_id: 7 });
        roundtrip(Pdu::IPv4Prefix {
            announce: true,
            prefix_len: 24,
            max_len: 24,
            addr: Ipv4Addr::new(10, 99, 0, 0),
            asn: 65002,
        });
        roundtrip(Pdu::IPv6Prefix {
            announce: false,
            prefix_len: 32,
            max_len: 48,
            addr: "2001:db8::".parse().unwrap(),
            asn: 65001,
        });
        roundtrip(Pdu::EndOfData { session_id: 7, serial: 42, refresh: 3600, retry: 600, expire: 7200 });
        roundtrip(Pdu::CacheReset);
        roundtrip(Pdu::ErrorReport { code: 2 });
    }

    #[test]
    fn prefix_pdu_becomes_a_roa() {
        let (roa, announce) = Pdu::IPv4Prefix {
            announce: true,
            prefix_len: 24,
            max_len: 24,
            addr: Ipv4Addr::new(10, 99, 0, 0),
            asn: 65002,
        }
        .to_roa()
        .expect("a prefix PDU yields a ROA");
        assert!(announce);
        assert_eq!(roa.prefix, "10.99.0.0/24".parse().unwrap());
        assert_eq!(roa.max_length, 24);
        assert_eq!(roa.origin_as, 65002);
        // A non-prefix PDU has no ROA.
        assert_eq!(Pdu::CacheReset.to_roa(), None);
    }

    #[test]
    fn decode_rejects_truncation_and_unknown_types() {
        // A header that claims more than the buffer holds.
        let mut bytes = Pdu::CacheResponse { session_id: 1 }.encode();
        bytes[7] = 99; // length far beyond the buffer
        assert_eq!(Pdu::decode(&bytes), Err(RtrError::Truncated));
        // A short buffer (less than a header).
        assert_eq!(Pdu::decode(&[1, 3, 0]), Err(RtrError::Truncated));
        // An unknown PDU type.
        let mut unknown = Pdu::CacheReset.encode();
        unknown[1] = 200;
        assert_eq!(Pdu::decode(&unknown), Err(RtrError::UnknownType(200)));
    }

    #[test]
    fn router_key_is_recognised_but_unsupported() {
        let pdu = Pdu::Unsupported { pdu_type: pdu_type::ROUTER_KEY };
        let bytes = pdu.encode();
        assert_eq!(Pdu::decode(&bytes), Ok(Pdu::Unsupported { pdu_type: pdu_type::ROUTER_KEY }));
    }
}
