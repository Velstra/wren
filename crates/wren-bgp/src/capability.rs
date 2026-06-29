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

/// The Graceful Restart capability code (RFC 4724 §3).
pub const CAP_GRACEFUL_RESTART: u8 = 64;

/// The 4-octet AS Number capability code (RFC 6793 §4).
pub const CAP_FOUR_OCTET_AS: u8 = 65;

/// The Extended Next Hop Encoding capability code (RFC 5549 / RFC 8950 §3): the
/// speaker can receive a next hop of a different address family from the NLRI — an
/// IPv4 prefix with an IPv6 next hop.
pub const CAP_EXTENDED_NEXT_HOP: u8 = 5;

/// The ADD-PATH capability code (RFC 7911 §4).
pub const CAP_ADD_PATH: u8 = 69;

/// ADD-PATH Send/Receive: able to **receive** multiple paths (RFC 7911 §4).
pub const ADD_PATH_RECEIVE: u8 = 1;
/// ADD-PATH Send/Receive: able to **send** multiple paths (RFC 7911 §4).
pub const ADD_PATH_SEND: u8 = 2;
/// ADD-PATH Send/Receive: able to both send and receive (RFC 7911 §4).
pub const ADD_PATH_BOTH: u8 = 3;

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
    /// The Graceful Restart capability (code 64, RFC 4724 §3): the speaker can be
    /// helped through a restart (and help others). Carries the Restart State (R)
    /// flag — set in the first OPEN after a restart — the Restart Time a helper
    /// should wait, and the address families whose forwarding state survives a
    /// restart (each `(AFI, SAFI, F-flag)`, F set ⇒ forwarding preserved).
    GracefulRestart {
        /// The Restart State (R) flag (RFC 4724 §3): set while recovering.
        restart_state: bool,
        /// The Restart Time in seconds (12-bit; how long a helper retains routes).
        restart_time: u16,
        /// The advertised families and their per-family Forwarding State (F) flag.
        families: Vec<(u16, u8, bool)>,
    },
    /// The 4-octet AS Number capability (code 65): the speaker's real AS.
    FourOctetAs(u32),
    /// The ADD-PATH capability (code 69, RFC 7911 §4): the speaker can send and/or
    /// receive multiple paths for the same destination. Carries one
    /// `(AFI, SAFI, Send/Receive)` tuple per family, where the Send/Receive byte is
    /// [`ADD_PATH_RECEIVE`] / [`ADD_PATH_SEND`] / [`ADD_PATH_BOTH`].
    AddPath(Vec<(u16, u8, u8)>),
    /// The Extended Next Hop Encoding capability (code 5, RFC 5549 / RFC 8950 §3):
    /// the speaker can receive, for each listed `(NLRI AFI, NLRI SAFI, Nexthop AFI)`
    /// tuple, NLRI of one family with a next hop of another — e.g. IPv4 unicast
    /// (AFI 1, SAFI 1) reachable through an IPv6 next hop (Nexthop AFI 2). Note SAFI
    /// is a 2-octet field here (unlike the 1-octet SAFI elsewhere).
    ExtendedNextHop(Vec<(u16, u16, u16)>),
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
            Capability::GracefulRestart { .. } => CAP_GRACEFUL_RESTART,
            Capability::FourOctetAs(_) => CAP_FOUR_OCTET_AS,
            Capability::AddPath(_) => CAP_ADD_PATH,
            Capability::ExtendedNextHop(_) => CAP_EXTENDED_NEXT_HOP,
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
            Capability::GracefulRestart { restart_state, restart_time, families } => {
                // Value: Restart Flags(4 bits) · Restart Time(12 bits), then a
                // 4-octet (AFI(2) · SAFI(1) · Flags(1)) tuple per family.
                out.push(2 + 4 * families.len() as u8);
                let hdr: u16 =
                    ((*restart_state as u16) << 15) | (restart_time & 0x0FFF);
                out.extend_from_slice(&hdr.to_be_bytes());
                for (afi, safi, preserved) in families {
                    out.extend_from_slice(&afi.to_be_bytes());
                    out.push(*safi);
                    out.push(if *preserved { 0x80 } else { 0x00 });
                }
            }
            Capability::FourOctetAs(asn) => {
                out.push(4);
                out.extend_from_slice(&asn.to_be_bytes());
            }
            Capability::AddPath(families) => {
                // One 4-octet (AFI(2) · SAFI(1) · Send/Receive(1)) tuple per family.
                out.push(4 * families.len() as u8);
                for (afi, safi, sr) in families {
                    out.extend_from_slice(&afi.to_be_bytes());
                    out.push(*safi);
                    out.push(*sr);
                }
            }
            Capability::ExtendedNextHop(tuples) => {
                // One 6-octet (NLRI AFI(2) · NLRI SAFI(2) · Nexthop AFI(2)) tuple each.
                out.push(6 * tuples.len() as u8);
                for (afi, safi, nh_afi) in tuples {
                    out.extend_from_slice(&afi.to_be_bytes());
                    out.extend_from_slice(&safi.to_be_bytes());
                    out.extend_from_slice(&nh_afi.to_be_bytes());
                }
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
            CAP_GRACEFUL_RESTART if value.len() >= 2 && (value.len() - 2) % 4 == 0 => {
                let hdr = u16::from_be_bytes([value[0], value[1]]);
                let restart_state = hdr & 0x8000 != 0;
                let restart_time = hdr & 0x0FFF;
                let mut families = Vec::new();
                let mut o = 2;
                while o + 4 <= value.len() {
                    families.push((
                        u16::from_be_bytes([value[o], value[o + 1]]),
                        value[o + 2],
                        value[o + 3] & 0x80 != 0,
                    ));
                    o += 4;
                }
                Capability::GracefulRestart { restart_state, restart_time, families }
            }
            CAP_FOUR_OCTET_AS if value.len() == 4 => {
                Capability::FourOctetAs(u32::from_be_bytes([value[0], value[1], value[2], value[3]]))
            }
            CAP_ADD_PATH if value.len() % 4 == 0 => {
                let mut families = Vec::new();
                let mut o = 0;
                while o + 4 <= value.len() {
                    families.push((
                        u16::from_be_bytes([value[o], value[o + 1]]),
                        value[o + 2],
                        value[o + 3],
                    ));
                    o += 4;
                }
                Capability::AddPath(families)
            }
            CAP_EXTENDED_NEXT_HOP if value.len() % 6 == 0 => {
                let mut tuples = Vec::new();
                let mut o = 0;
                while o + 6 <= value.len() {
                    tuples.push((
                        u16::from_be_bytes([value[o], value[o + 1]]),
                        u16::from_be_bytes([value[o + 2], value[o + 3]]),
                        u16::from_be_bytes([value[o + 4], value[o + 5]]),
                    ));
                    o += 6;
                }
                Capability::ExtendedNextHop(tuples)
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
    fn graceful_restart_capability_roundtrips() {
        use crate::{AFI_IPV4, AFI_IPV6, SAFI_UNICAST};
        let caps = vec![Capability::GracefulRestart {
            restart_state: true,
            restart_time: 120,
            families: vec![(AFI_IPV4, SAFI_UNICAST, true), (AFI_IPV6, SAFI_UNICAST, false)],
        }];
        let opt = encode_optional_parameters(&caps);
        // type 2 (capabilities param), then [cap 64, len 2 + 2*4 = 10].
        assert_eq!(opt[0], OPT_PARAM_CAPABILITIES);
        assert_eq!(opt[2], CAP_GRACEFUL_RESTART);
        assert_eq!(opt[3], 10);
        // The R flag is the top bit of the 16-bit flags+time word.
        assert_eq!(u16::from_be_bytes([opt[4], opt[5]]), 0x8000 | 120);
        assert_eq!(parse_optional_parameters(&opt), caps);
    }

    #[test]
    fn add_path_capability_roundtrips() {
        use crate::{AFI_IPV4, AFI_IPV6, SAFI_UNICAST};
        let caps = vec![Capability::AddPath(vec![
            (AFI_IPV4, SAFI_UNICAST, ADD_PATH_BOTH),
            (AFI_IPV6, SAFI_UNICAST, ADD_PATH_SEND),
        ])];
        let opt = encode_optional_parameters(&caps);
        // type 2 (capabilities param), then [cap 69, len 2*4 = 8].
        assert_eq!(opt[0], OPT_PARAM_CAPABILITIES);
        assert_eq!(opt[2], CAP_ADD_PATH);
        assert_eq!(opt[3], 8);
        // First family: AFI 1, SAFI 1, Send/Receive 3 (both).
        assert_eq!(&opt[4..8], &[0x00, 0x01, 0x01, ADD_PATH_BOTH]);
        assert_eq!(parse_optional_parameters(&opt), caps);
    }

    #[test]
    fn extended_next_hop_capability_roundtrips() {
        use crate::{AFI_IPV4, AFI_IPV6, SAFI_UNICAST};
        let caps = vec![Capability::ExtendedNextHop(vec![(
            AFI_IPV4,
            SAFI_UNICAST as u16,
            AFI_IPV6,
        )])];
        let opt = encode_optional_parameters(&caps);
        // type 2 (capabilities param), then [cap 5, len 6, AFI 1, SAFI 1, NH-AFI 2].
        assert_eq!(opt[0], OPT_PARAM_CAPABILITIES);
        assert_eq!(opt[2], CAP_EXTENDED_NEXT_HOP);
        assert_eq!(opt[3], 6);
        assert_eq!(&opt[4..10], &[0x00, 0x01, 0x00, 0x01, 0x00, 0x02]);
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
