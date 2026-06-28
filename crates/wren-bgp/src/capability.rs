//! BGP capabilities (RFC 5492) carried in the OPEN message's Optional Parameters,
//! and the 4-octet AS Number capability (RFC 6793 §4, code 65).
//!
//! An OPEN's Optional Parameters area is a sequence of
//! `param_type(1) · param_len(1) · value`. The Capabilities parameter (type 2)
//! wraps a sequence of capabilities, each `cap_code(1) · cap_len(1) · cap_value`.
//! This module models that nesting just enough to advertise and detect the
//! 4-octet AS capability; any other capability is preserved opaquely so a
//! round-trip is loss-free.

/// The Optional Parameter type that carries capabilities (RFC 5492 §4).
pub const OPT_PARAM_CAPABILITIES: u8 = 2;

/// The Multiprotocol Extensions capability code (RFC 4760 §8).
pub const CAP_MULTIPROTOCOL: u8 = 1;

/// The Route Refresh capability code (RFC 2918 §3).
pub const CAP_ROUTE_REFRESH: u8 = 2;

/// The 4-octet AS Number capability code (RFC 6793 §4).
pub const CAP_FOUR_OCTET_AS: u8 = 65;

/// One advertised BGP capability (RFC 5492).
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Capability {
    /// The Multiprotocol Extensions capability (code 1, RFC 4760 §8): the speaker
    /// can carry the named `(AFI, SAFI)` address family (e.g. IPv6 unicast).
    Multiprotocol {
        /// The Address Family Identifier (e.g. [`crate::AFI_IPV6`]).
        afi: u16,
        /// The Subsequent Address Family Identifier (e.g. [`crate::SAFI_UNICAST`]).
        safi: u8,
    },
    /// The Route Refresh capability (code 2, RFC 2918): the speaker can receive a
    /// ROUTE-REFRESH message and will re-advertise its Adj-RIB-Out. No value.
    RouteRefresh,
    /// The 4-octet AS Number capability (code 65): the speaker's real AS.
    FourOctetAs(u32),
    /// A capability this implementation does not model, kept verbatim.
    Unknown {
        /// The capability code.
        code: u8,
        /// The capability value.
        value: Vec<u8>,
    },
}

impl Capability {
    /// The on-wire capability code.
    pub fn code(&self) -> u8 {
        match self {
            Capability::Multiprotocol { .. } => CAP_MULTIPROTOCOL,
            Capability::RouteRefresh => CAP_ROUTE_REFRESH,
            Capability::FourOctetAs(_) => CAP_FOUR_OCTET_AS,
            Capability::Unknown { code, .. } => *code,
        }
    }

    /// Append this capability (`code · len · value`) to `out`.
    fn encode(&self, out: &mut Vec<u8>) {
        out.push(self.code());
        match self {
            Capability::Multiprotocol { afi, safi } => {
                // AFI(2) · Reserved(1) · SAFI(1).
                out.push(4);
                out.extend_from_slice(&afi.to_be_bytes());
                out.push(0);
                out.push(*safi);
            }
            Capability::RouteRefresh => {
                out.push(0); // no value
            }
            Capability::FourOctetAs(asn) => {
                out.push(4);
                out.extend_from_slice(&asn.to_be_bytes());
            }
            Capability::Unknown { value, .. } => {
                out.push(value.len() as u8);
                out.extend_from_slice(value);
            }
        }
    }

    /// Decode one capability from the front of `buf`, returning it and the bytes
    /// consumed, or `None` if the buffer is short.
    fn decode_one(buf: &[u8]) -> Option<(Capability, usize)> {
        if buf.len() < 2 {
            return None;
        }
        let code = buf[0];
        let len = buf[1] as usize;
        let end = 2 + len;
        if buf.len() < end {
            return None;
        }
        let value = &buf[2..end];
        let cap = match code {
            CAP_MULTIPROTOCOL if value.len() == 4 => Capability::Multiprotocol {
                afi: u16::from_be_bytes([value[0], value[1]]),
                // value[2] is Reserved.
                safi: value[3],
            },
            CAP_ROUTE_REFRESH if value.is_empty() => Capability::RouteRefresh,
            CAP_FOUR_OCTET_AS if value.len() == 4 => {
                Capability::FourOctetAs(u32::from_be_bytes([value[0], value[1], value[2], value[3]]))
            }
            _ => Capability::Unknown {
                code,
                value: value.to_vec(),
            },
        };
        Some((cap, end))
    }
}

/// Build the OPEN Optional Parameters bytes advertising `caps`: a single
/// Capabilities (type 2) parameter wrapping them all (or empty when there are
/// none).
pub fn encode_optional_parameters(caps: &[Capability]) -> Vec<u8> {
    if caps.is_empty() {
        return Vec::new();
    }
    let mut blob = Vec::new();
    for c in caps {
        c.encode(&mut blob);
    }
    let mut out = Vec::with_capacity(2 + blob.len());
    out.push(OPT_PARAM_CAPABILITIES);
    out.push(blob.len() as u8);
    out.extend_from_slice(&blob);
    out
}

/// Parse an OPEN's Optional Parameters bytes, returning every capability found in
/// its Capabilities (type 2) parameters. Non-capability parameters are skipped.
pub fn parse_optional_parameters(opt: &[u8]) -> Vec<Capability> {
    let mut caps = Vec::new();
    let mut off = 0;
    while off + 2 <= opt.len() {
        let ptype = opt[off];
        let plen = opt[off + 1] as usize;
        off += 2;
        if off + plen > opt.len() {
            break; // truncated parameter
        }
        let value = &opt[off..off + plen];
        off += plen;
        if ptype != OPT_PARAM_CAPABILITIES {
            continue;
        }
        let mut o = 0;
        while o < value.len() {
            let Some((cap, used)) = Capability::decode_one(&value[o..]) else {
                break;
            };
            caps.push(cap);
            o += used;
        }
    }
    caps
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn four_octet_as_capability_roundtrips() {
        let caps = vec![Capability::FourOctetAs(196_618)];
        let opt = encode_optional_parameters(&caps);
        // type 2, len 6, [cap 65, len 4, 4-octet AS].
        assert_eq!(opt[0], OPT_PARAM_CAPABILITIES);
        assert_eq!(opt[2], CAP_FOUR_OCTET_AS);
        assert_eq!(opt[3], 4);
        assert_eq!(parse_optional_parameters(&opt), caps);
    }

    #[test]
    fn empty_capabilities_encode_to_nothing() {
        assert!(encode_optional_parameters(&[]).is_empty());
        assert_eq!(parse_optional_parameters(&[]), vec![]);
    }

    #[test]
    fn multiprotocol_capability_roundtrips() {
        use crate::{AFI_IPV6, SAFI_UNICAST};
        let caps = vec![Capability::Multiprotocol { afi: AFI_IPV6, safi: SAFI_UNICAST }];
        let opt = encode_optional_parameters(&caps);
        // type 2, then [cap 1, len 4, AFI hi/lo, reserved 0, SAFI].
        assert_eq!(opt[0], OPT_PARAM_CAPABILITIES);
        assert_eq!(opt[2], CAP_MULTIPROTOCOL);
        assert_eq!(opt[3], 4);
        assert_eq!(&opt[4..8], &[0x00, 0x02, 0x00, 0x01]);
        assert_eq!(parse_optional_parameters(&opt), caps);
    }

    #[test]
    fn route_refresh_capability_roundtrips() {
        let caps = vec![Capability::RouteRefresh];
        let opt = encode_optional_parameters(&caps);
        // type 2 (capabilities param), then [cap 2 (route-refresh), len 0].
        assert_eq!(opt[0], OPT_PARAM_CAPABILITIES);
        assert_eq!(opt[2], CAP_ROUTE_REFRESH);
        assert_eq!(opt[3], 0);
        assert_eq!(parse_optional_parameters(&opt), caps);
    }

    #[test]
    fn unknown_capabilities_are_preserved_alongside_known() {
        let caps = vec![
            Capability::Unknown {
                code: 70, // route-refresh-cisco, say — unmodelled
                value: vec![0, 1, 0, 1],
            },
            Capability::FourOctetAs(65_536),
        ];
        let opt = encode_optional_parameters(&caps);
        assert_eq!(parse_optional_parameters(&opt), caps);
    }

    #[test]
    fn truncated_optional_parameters_stop_cleanly() {
        // A Capabilities param claiming more bytes than present yields nothing,
        // not a panic.
        let opt = [OPT_PARAM_CAPABILITIES, 10, CAP_FOUR_OCTET_AS, 4, 0, 0];
        assert_eq!(parse_optional_parameters(&opt), vec![]);
    }
}
