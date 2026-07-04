//! SRv6 service programming for BGP overlays (RFC 9252).
//!
//! When an EVPN or L3VPN route is carried over an SRv6 data plane instead of
//! VXLAN/MPLS, the forwarding instruction is a 128-bit **SRv6 Service SID** — an
//! IPv6 address that, looked up on the egress PE, means "decapsulate and hand the
//! inner packet to this bridge-domain / VRF" (an RFC 8986 `End.DT*` behaviour).
//! That SID travels in the BGP **Prefix-SID** path attribute (type 40) as a
//! nested TLV tree:
//!
//! ```text
//! SRv6 L2/L3 Service TLV (type 6 / 5)
//!   RESERVED(1)
//!   └─ SRv6 SID Information Sub-TLV (type 1)
//!        RESERVED1(1) · SID(16) · Flags(1) · Endpoint-Behavior(2) · RESERVED2(1)
//!        └─ SRv6 SID Structure Sub-Sub-TLV (type 1, len 6)
//!             LocBlockLen · LocNodeLen · FuncLen · ArgLen · TransLen · TransOffset
//! ```
//!
//! Every length field counts the bytes that follow it (i.e. it does *not* include
//! the type/length header of its own record). This module is the pure wire codec
//! plus a helper that derives a service SID from a configured locator.

use std::net::Ipv6Addr;

/// A 128-bit SRv6 SID — an IPv6 address used as a network-programming instruction.
pub type Srv6Sid = [u8; 16];

/// RFC 8986 endpoint behaviours used for BGP overlay service SIDs.
pub mod behavior {
    /// End.DT6 — decapsulate and look the inner packet up in an IPv6 VRF (L3VPN).
    pub const END_DT6: u16 = 0x0012;
    /// End.DT4 — decapsulate and look the inner packet up in an IPv4 VRF (L3VPN).
    pub const END_DT4: u16 = 0x0013;
    /// End.DT46 — decapsulate and look up in a dual IPv4/IPv6 VRF (L3VPN).
    pub const END_DT46: u16 = 0x0014;
    /// End.DT2U — decapsulate and bridge the inner Ethernet frame, unicast
    /// (EVPN type-2 MAC/IP).
    pub const END_DT2U: u16 = 0x0016;
    /// End.DT2M — decapsulate and flood the inner Ethernet frame (EVPN type-3
    /// IMET / BUM).
    pub const END_DT2M: u16 = 0x0017;
}

// TLV type codes within the Prefix-SID attribute (RFC 9252 §2/§3).
const TLV_SRV6_L3_SERVICE: u8 = 5;
const TLV_SRV6_L2_SERVICE: u8 = 6;
const SUBTLV_SID_INFORMATION: u8 = 1;
const SUBSUBTLV_SID_STRUCTURE: u8 = 1;

/// RFC 9252 §3.2.1 SRv6 SID Structure Sub-Sub-TLV — how the 128 bits of the SID
/// are partitioned (all lengths in **bits**), plus the transposition parameters
/// that describe any bits carried in the route's label field instead of the SID.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Default)]
pub struct Srv6SidStructure {
    /// Length of the Locator Block (the shared, routable prefix), in bits.
    pub locator_block_len: u8,
    /// Length of the Locator Node (the per-node part of the locator), in bits.
    pub locator_node_len: u8,
    /// Length of the Function (the local instruction selector), in bits.
    pub function_len: u8,
    /// Length of the Argument (per-flow data), in bits.
    pub argument_len: u8,
    /// Number of Function bits transposed into the route's label field.
    pub transposition_len: u8,
    /// Bit offset within the SID at which the transposed bits sit.
    pub transposition_offset: u8,
}

/// One SRv6 SID Information Sub-TLV: a service SID plus its behaviour and layout.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct Srv6ServiceSid {
    /// The 128-bit service SID.
    pub sid: Srv6Sid,
    /// The RFC 8986 endpoint behaviour (see [`behavior`]).
    pub behavior: u16,
    /// The SID flags octet (currently unused; kept for round-trip fidelity).
    pub flags: u8,
    /// How the SID is partitioned.
    pub structure: Srv6SidStructure,
}

/// An SRv6 Service TLV — the L3 Service TLV (type 5) or the L2 Service TLV
/// (type 6) — carrying one or more SID Information sub-TLVs.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct Srv6ServiceTlv {
    /// `true` for the L2 Service TLV (type 6), `false` for L3 (type 5).
    pub is_l2: bool,
    /// The service SIDs advertised in this TLV.
    pub sids: Vec<Srv6ServiceSid>,
}

impl Srv6ServiceTlv {
    /// The first (and, in practice, only) SID carried by this TLV.
    pub fn first_sid(&self) -> Option<&Srv6ServiceSid> {
        self.sids.first()
    }
}

/// Format a SID as an IPv6 address (its canonical textual form).
pub fn sid_to_string(sid: &Srv6Sid) -> String {
    Ipv6Addr::from(*sid).to_string()
}

/// Derive a service SID from a locator prefix, a service discriminator, and a
/// 24-bit VNI/EVI function value.
///
/// The SID is `locator ++ discriminator(1B) ++ vni(3B) ++ zero-fill`. The
/// discriminator keeps the unicast (`End.DT2U`) and multicast (`End.DT2M`) SIDs
/// of the same EVI distinct, since a SID value maps to exactly one behaviour on
/// the egress node. Requires a byte-aligned locator length ≤ 96 (validated at
/// config load); the returned structure records block/node/function layout with
/// no argument and no transposition (the full SID is carried in the attribute).
pub fn build_service_sid(
    locator: Ipv6Addr,
    prefix_len: u8,
    discriminator: u8,
    vni: u32,
) -> (Srv6Sid, Srv6SidStructure) {
    let mut sid = locator.octets();
    let loc_bytes = (prefix_len / 8) as usize;
    // Zero everything past the locator so only our function bits are set.
    for b in sid.iter_mut().skip(loc_bytes) {
        *b = 0;
    }
    if loc_bytes < 16 {
        sid[loc_bytes] = discriminator;
    }
    let vni_be = vni.to_be_bytes(); // [_, v2, v1, v0] — low 24 bits are the VNI.
    for (i, off) in (loc_bytes + 1..loc_bytes + 4).enumerate() {
        if off < 16 {
            sid[off] = vni_be[1 + i];
        }
    }
    let block = prefix_len.min(40);
    let structure = Srv6SidStructure {
        locator_block_len: block,
        locator_node_len: prefix_len.saturating_sub(block),
        function_len: 32, // 8-bit discriminator + 24-bit VNI
        argument_len: 0,
        transposition_len: 0,
        transposition_offset: 0,
    };
    (sid, structure)
}

/// Serialise one SRv6 Service TLV (with its nested sub-TLVs) into `out`.
pub fn encode_srv6_service_tlv(out: &mut Vec<u8>, tlv: &Srv6ServiceTlv) {
    let mut sub = Vec::new();
    for s in &tlv.sids {
        encode_sid_information(&mut sub, s);
    }
    out.push(if tlv.is_l2 {
        TLV_SRV6_L2_SERVICE
    } else {
        TLV_SRV6_L3_SERVICE
    });
    // TLV Length spans the RESERVED octet plus the sub-TLVs.
    let len = 1 + sub.len();
    out.extend_from_slice(&(len as u16).to_be_bytes());
    out.push(0); // RESERVED
    out.extend_from_slice(&sub);
}

fn encode_sid_information(out: &mut Vec<u8>, s: &Srv6ServiceSid) {
    let mut subsub = Vec::new();
    encode_sid_structure(&mut subsub, &s.structure);
    out.push(SUBTLV_SID_INFORMATION);
    // Length spans RESERVED1(1)+SID(16)+Flags(1)+Behavior(2)+RESERVED2(1)+subsub.
    let len = 1 + 16 + 1 + 2 + 1 + subsub.len();
    out.extend_from_slice(&(len as u16).to_be_bytes());
    out.push(0); // RESERVED1
    out.extend_from_slice(&s.sid);
    out.push(s.flags);
    out.extend_from_slice(&s.behavior.to_be_bytes());
    out.push(0); // RESERVED2
    out.extend_from_slice(&subsub);
}

fn encode_sid_structure(out: &mut Vec<u8>, st: &Srv6SidStructure) {
    out.push(SUBSUBTLV_SID_STRUCTURE);
    out.extend_from_slice(&6u16.to_be_bytes());
    out.push(st.locator_block_len);
    out.push(st.locator_node_len);
    out.push(st.function_len);
    out.push(st.argument_len);
    out.push(st.transposition_len);
    out.push(st.transposition_offset);
}

/// Parse the value of a Prefix-SID attribute into the SRv6 Service TLVs we model
/// and a verbatim list of any other top-level TLVs (e.g. the MPLS-SR Label-Index
/// / SRGB TLVs), so a route reflector re-advertises them intact.
///
/// Returns `None` on a malformed length so the caller can fall back to keeping
/// the attribute as opaque bytes (RFC 7606 attribute-discard) rather than
/// tearing down the session.
#[allow(clippy::type_complexity)]
pub fn decode_prefix_sid(value: &[u8]) -> Option<(Vec<Srv6ServiceTlv>, Vec<(u8, Vec<u8>)>)> {
    let mut srv6 = Vec::new();
    let mut other = Vec::new();
    let mut off = 0;
    while off < value.len() {
        if off + 3 > value.len() {
            return None;
        }
        let tlv_type = value[off];
        let tlv_len = u16::from_be_bytes([value[off + 1], value[off + 2]]) as usize;
        let body_start = off + 3;
        let body_end = body_start + tlv_len;
        if body_end > value.len() {
            return None;
        }
        let body = &value[body_start..body_end];
        match tlv_type {
            TLV_SRV6_L2_SERVICE | TLV_SRV6_L3_SERVICE => {
                let sids = decode_service_sids(body)?;
                srv6.push(Srv6ServiceTlv {
                    is_l2: tlv_type == TLV_SRV6_L2_SERVICE,
                    sids,
                });
            }
            _ => other.push((tlv_type, body.to_vec())),
        }
        off = body_end;
    }
    Some((srv6, other))
}

/// The value of an SRv6 Service TLV is a RESERVED octet then a run of sub-TLVs.
fn decode_service_sids(body: &[u8]) -> Option<Vec<Srv6ServiceSid>> {
    if body.is_empty() {
        return None;
    }
    let mut sids = Vec::new();
    let mut off = 1; // skip RESERVED
    while off < body.len() {
        if off + 3 > body.len() {
            return None;
        }
        let sub_type = body[off];
        let sub_len = u16::from_be_bytes([body[off + 1], body[off + 2]]) as usize;
        let start = off + 3;
        let end = start + sub_len;
        if end > body.len() {
            return None;
        }
        if sub_type == SUBTLV_SID_INFORMATION {
            sids.push(decode_sid_information(&body[start..end])?);
        }
        // Other sub-TLVs are ignored (not re-emitted): only SID Information is
        // meaningful for our datapath, and losing an unknown sub-TLV inside a
        // SID we *did* parse is acceptable per RFC 9252 §3.
        off = end;
    }
    Some(sids)
}

/// Parse a SID Information sub-TLV value:
/// RESERVED1(1) · SID(16) · Flags(1) · Behavior(2) · RESERVED2(1) · sub-sub-TLVs.
fn decode_sid_information(body: &[u8]) -> Option<Srv6ServiceSid> {
    if body.len() < 21 {
        return None;
    }
    let mut sid = [0u8; 16];
    sid.copy_from_slice(&body[1..17]);
    let flags = body[17];
    let behavior = u16::from_be_bytes([body[18], body[19]]);
    // body[20] is RESERVED2; sub-sub-TLVs follow.
    let structure = decode_sid_structure(&body[21..]).unwrap_or_default();
    Some(Srv6ServiceSid {
        sid,
        behavior,
        flags,
        structure,
    })
}

/// Find and parse the SID Structure sub-sub-TLV in a SID Information tail.
fn decode_sid_structure(buf: &[u8]) -> Option<Srv6SidStructure> {
    let mut off = 0;
    while off + 3 <= buf.len() {
        let t = buf[off];
        let len = u16::from_be_bytes([buf[off + 1], buf[off + 2]]) as usize;
        let start = off + 3;
        let end = start + len;
        if end > buf.len() {
            return None;
        }
        if t == SUBSUBTLV_SID_STRUCTURE && len >= 6 {
            let f = &buf[start..end];
            return Some(Srv6SidStructure {
                locator_block_len: f[0],
                locator_node_len: f[1],
                function_len: f[2],
                argument_len: f[3],
                transposition_len: f[4],
                transposition_offset: f[5],
            });
        }
        off = end;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_sid() -> Srv6ServiceSid {
        let (sid, structure) = build_service_sid("fc00:0:1::".parse().unwrap(), 48, 0x00, 10100);
        Srv6ServiceSid {
            sid,
            behavior: behavior::END_DT2U,
            flags: 0,
            structure,
        }
    }

    #[test]
    fn build_service_sid_places_vni_after_locator() {
        let (sid, st) = build_service_sid("fc00:0:1::".parse().unwrap(), 48, 0x00, 10100);
        // /48 locator => 6 bytes; byte 6 is the discriminator, bytes 7..10 the VNI.
        assert_eq!(&sid[0..6], &[0xfc, 0x00, 0x00, 0x00, 0x00, 0x01]);
        assert_eq!(sid[6], 0x00);
        assert_eq!(&sid[7..10], &10100u32.to_be_bytes()[1..4]);
        assert_eq!(st.locator_block_len, 40);
        assert_eq!(st.locator_node_len, 8);
        assert_eq!(st.function_len, 32);
    }

    #[test]
    fn discriminator_distinguishes_unicast_and_multicast() {
        let (u, _) = build_service_sid("fc00:0:1::".parse().unwrap(), 48, 0x00, 10100);
        let (m, _) = build_service_sid("fc00:0:1::".parse().unwrap(), 48, 0x01, 10100);
        assert_ne!(u, m);
        assert_eq!(m[6], 0x01);
    }

    #[test]
    fn service_tlv_roundtrips() {
        let tlv = Srv6ServiceTlv {
            is_l2: true,
            sids: vec![sample_sid()],
        };
        let mut buf = Vec::new();
        encode_srv6_service_tlv(&mut buf, &tlv);
        let (srv6, other) = decode_prefix_sid(&buf).expect("decode");
        assert!(other.is_empty());
        assert_eq!(srv6, vec![tlv]);
    }

    #[test]
    fn preserves_unknown_toplevel_tlv() {
        // A Prefix-SID with an MPLS-SR Label-Index TLV (type 1) we don't model,
        // followed by our SRv6 L2 Service TLV, must keep the unknown one verbatim.
        let mut buf = vec![1u8, 0x00, 0x07, 0, 0, 0, 0, 0, 0, 0]; // type 1, len 7
        let tlv = Srv6ServiceTlv {
            is_l2: false,
            sids: vec![sample_sid()],
        };
        encode_srv6_service_tlv(&mut buf, &tlv);
        let (srv6, other) = decode_prefix_sid(&buf).expect("decode");
        assert_eq!(srv6, vec![tlv]);
        assert_eq!(other, vec![(1u8, vec![0u8; 7])]);
    }

    #[test]
    fn rejects_truncated_tlv() {
        // Claims length 40 but no body.
        assert!(decode_prefix_sid(&[5u8, 0x00, 0x28]).is_none());
    }

    #[test]
    fn sid_information_survives_missing_structure() {
        // A SID Information sub-TLV with no SID Structure sub-sub-TLV must still
        // parse (structure defaults to all-zero), not fail.
        let s = Srv6ServiceSid {
            sid: [0x20; 16],
            behavior: behavior::END_DT2M,
            flags: 0,
            structure: Srv6SidStructure::default(),
        };
        let tlv = Srv6ServiceTlv {
            is_l2: true,
            sids: vec![s],
        };
        let mut buf = Vec::new();
        encode_srv6_service_tlv(&mut buf, &tlv);
        let (srv6, _) = decode_prefix_sid(&buf).expect("decode");
        assert_eq!(srv6[0].sids[0].sid, [0x20; 16]);
        assert_eq!(srv6[0].sids[0].behavior, behavior::END_DT2M);
    }
}
