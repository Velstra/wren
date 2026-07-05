//! BGP SR Policy (SAFI 73) — the signalling of Segment Routing Policies over BGP
//! (RFC 9256 for the SR Policy model, plus the BGP encoding from
//! draft-ietf-idr-segment-routing-te-policy / RFC 9012 Tunnel Encapsulation).
//!
//! An SR Policy is identified by the tuple `(headend, colour, endpoint)`. It is
//! advertised as one BGP route per **candidate path**: the SR Policy NLRI
//! `(distinguisher, colour, endpoint)` names the candidate, and the route's
//! **Tunnel Encapsulation** attribute (type 23, RFC 9012) with Tunnel-Type
//! `SR Policy` (15) carries the candidate's contents — its preference, binding
//! SID, priority, name and one or more weighted **segment lists** of SRv6 SIDs
//! (reusing [`crate::srv6`]) or SR-MPLS labels.
//!
//! This module is the pure wire codec plus the in-memory model; the RIB that
//! stores received policies and selects the best candidate per `(colour,
//! endpoint)` lives in [`crate::sr_policy_rib`], and the BGP session plumbing
//! (SAFI-73 negotiation, MP_REACH/UNREACH) is in the daemon.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::srv6::{Srv6Sid, Srv6SidStructure};

/// The SR Policy SAFI (draft-ietf-idr-segment-routing-te-policy §2.1).
pub const SAFI_SR_POLICY: u8 = 73;

/// The SR Policy Tunnel-Type in the Tunnel Encapsulation attribute (RFC 9012 /
/// IANA "BGP Tunnel Encapsulation Attribute Tunnel Types").
pub const TUNNEL_TYPE_SR_POLICY: u16 = 15;

// SR Policy sub-TLV type codes (draft-ietf-idr-segment-routing-te-policy §2.4).
// Per RFC 9012 §2 a sub-TLV whose type is ≥ 128 has a 2-octet length field; a
// type < 128 has a 1-octet length field.
const SUBTLV_PREFERENCE: u8 = 12;
const SUBTLV_BINDING_SID: u8 = 13;
const SUBTLV_PRIORITY: u8 = 15;
const SUBTLV_SEGMENT_LIST: u8 = 128;
const SUBTLV_POLICY_NAME: u8 = 129;
// Sub-TLVs nested inside a Segment List sub-TLV.
const SUBTLV_WEIGHT: u8 = 9;
const SEG_TYPE_MPLS: u8 = 1; // Segment Type A: SID as an MPLS label.
const SEG_TYPE_SRV6: u8 = 13; // Segment Type B: SRv6 SID (128-bit).

/// One segment of an SR Policy segment list — an SRv6 SID (the locked stack) or,
/// for SR-MPLS interop, an MPLS label.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Segment {
    /// Segment Type A: a 20-bit MPLS label (SR-MPLS).
    MplsLabel(u32),
    /// Segment Type B: a 128-bit SRv6 SID, optionally with its RFC 8986 endpoint
    /// behaviour and RFC 9252 SID structure.
    Srv6Sid {
        /// The 128-bit SRv6 SID.
        sid: Srv6Sid,
        /// The RFC 8986 endpoint behaviour, if the optional trailer was present.
        behavior: Option<u16>,
        /// The SID structure (locator/function/argument layout), if present.
        structure: Option<Srv6SidStructure>,
    },
}

/// One weighted segment list of an SR Policy candidate path (RFC 9256 §2.2).
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct SegmentList {
    /// The load-balancing weight across this candidate's segment lists, if set.
    pub weight: Option<u32>,
    /// The ordered segments (the SID list pushed onto steered packets).
    pub segments: Vec<Segment>,
}

/// The Binding SID of an SR Policy candidate path (RFC 9256 §6.1).
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub enum BindingSid {
    /// No binding SID requested.
    #[default]
    None,
    /// An SR-MPLS binding label (20-bit).
    MplsLabel(u32),
    /// An SRv6 binding SID (128-bit).
    Srv6Sid(Srv6Sid),
}

/// The contents of one SR Policy candidate path, as carried in the SR Policy
/// Tunnel-Type TLV of the Tunnel Encapsulation attribute.
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct SrPolicyEncoding {
    /// The candidate path preference — higher wins (RFC 9256 §2.9). `None` is
    /// treated as the default preference (100) for selection.
    pub preference: Option<u32>,
    /// The candidate path's binding SID.
    pub binding_sid: BindingSid,
    /// The candidate path priority (used on topology changes), if advertised.
    pub priority: Option<u8>,
    /// The symbolic policy name, if advertised.
    pub policy_name: Option<String>,
    /// The candidate path's weighted segment lists.
    pub segment_lists: Vec<SegmentList>,
}

impl SrPolicyEncoding {
    /// The effective preference used for best-candidate selection (RFC 9256 §2.9):
    /// the advertised value, or the default of 100.
    pub fn effective_preference(&self) -> u32 {
        self.preference.unwrap_or(100)
    }
}

/// An SR Policy NLRI (draft-ietf-idr-segment-routing-te-policy §2.1): the
/// candidate-path key `(distinguisher, colour, endpoint)`. Ordered `(colour,
/// endpoint, distinguisher)` so the RIB groups a policy's candidates together.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct SrPolicyNlri {
    /// The policy colour — the intent/SLA the steering route's Color extended
    /// community (RFC 9012 §4.3) matches against. (Ordered first so a policy's
    /// candidate paths sort together.)
    pub color: u32,
    /// The policy endpoint (the tail-end node the SID list steers toward).
    pub endpoint: IpAddr,
    /// Distinguishes several candidate paths of the same `(colour, endpoint)`
    /// SR Policy advertised by the same originator.
    pub distinguisher: u32,
}

impl SrPolicyNlri {
    /// Serialise this NLRI (RFC-style: NLRI-length in bits, then distinguisher,
    /// colour and endpoint). The endpoint width follows its address family.
    pub fn encode(&self, out: &mut Vec<u8>) {
        // Length is in bits: 32 (distinguisher) + 32 (colour) + endpoint bits.
        let endpoint_bits = match self.endpoint {
            IpAddr::V4(_) => 32u16,
            IpAddr::V6(_) => 128u16,
        };
        let total_bits = 64 + endpoint_bits;
        out.push((total_bits / 8) as u8 * 8); // length in bits, byte-aligned
        out.extend_from_slice(&self.distinguisher.to_be_bytes());
        out.extend_from_slice(&self.color.to_be_bytes());
        match self.endpoint {
            IpAddr::V4(a) => out.extend_from_slice(&a.octets()),
            IpAddr::V6(a) => out.extend_from_slice(&a.octets()),
        }
    }

    /// Decode one SR Policy NLRI from the front of `buf` for the given `afi`
    /// (which fixes the endpoint width), returning it and the bytes consumed.
    pub fn decode(buf: &[u8], afi: u16) -> Option<(SrPolicyNlri, usize)> {
        if buf.is_empty() {
            return None;
        }
        let len_bits = buf[0] as usize;
        let len_bytes = len_bits / 8;
        let end = 1 + len_bytes;
        if buf.len() < end {
            return None;
        }
        let body = &buf[1..end];
        // distinguisher(4) + colour(4) + endpoint(4 or 16).
        let endpoint_len = if afi == crate::AFI_IPV6 { 16 } else { 4 };
        if body.len() != 8 + endpoint_len {
            return None;
        }
        let distinguisher = u32::from_be_bytes([body[0], body[1], body[2], body[3]]);
        let color = u32::from_be_bytes([body[4], body[5], body[6], body[7]]);
        let endpoint = if afi == crate::AFI_IPV6 {
            let mut o = [0u8; 16];
            o.copy_from_slice(&body[8..24]);
            IpAddr::V6(Ipv6Addr::from(o))
        } else {
            IpAddr::V4(Ipv4Addr::new(body[8], body[9], body[10], body[11]))
        };
        Some((
            SrPolicyNlri {
                distinguisher,
                color,
                endpoint,
            },
            end,
        ))
    }
}

/// Decode a run of SR Policy NLRI for the given AFI (used by MP_REACH/UNREACH).
pub fn decode_nlris(buf: &[u8], afi: u16) -> Option<Vec<SrPolicyNlri>> {
    let mut out = Vec::new();
    let mut off = 0;
    while off < buf.len() {
        let (nlri, used) = SrPolicyNlri::decode(&buf[off..], afi)?;
        out.push(nlri);
        off += used;
    }
    Some(out)
}

// --- Tunnel Encapsulation attribute (type 23) SR Policy encoding --------------

/// One TLV of a Tunnel Encapsulation attribute (RFC 9012 §2). The SR Policy
/// Tunnel-Type (15) is decoded into an [`SrPolicyEncoding`]; any other tunnel type
/// is kept verbatim so the attribute round-trips (e.g. a route reflector).
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum TunnelTlv {
    /// The SR Policy tunnel (Tunnel-Type 15) with its decoded contents.
    SrPolicy(SrPolicyEncoding),
    /// A tunnel type this speaker does not model, kept as raw sub-TLV bytes.
    Other {
        /// The tunnel type code.
        tunnel_type: u16,
        /// The raw sub-TLV bytes (the tunnel TLV value).
        value: Vec<u8>,
    },
}

/// Serialise a whole Tunnel Encapsulation attribute value: a sequence of tunnel
/// TLVs (`Tunnel-Type(2) · Length(2) · Value`).
pub fn encode_tunnel_encap(tlvs: &[TunnelTlv]) -> Vec<u8> {
    let mut out = Vec::new();
    for tlv in tlvs {
        match tlv {
            TunnelTlv::SrPolicy(enc) => encode_tunnel_tlv(&mut out, enc),
            TunnelTlv::Other { tunnel_type, value } => {
                out.extend_from_slice(&tunnel_type.to_be_bytes());
                out.extend_from_slice(&(value.len() as u16).to_be_bytes());
                out.extend_from_slice(value);
            }
        }
    }
    out
}

/// Parse a whole Tunnel Encapsulation attribute value into its tunnel TLVs.
/// Returns `None` on a malformed length so the caller can keep the attribute
/// opaque rather than resetting the session (RFC 7606).
pub fn decode_tunnel_encap(value: &[u8]) -> Option<Vec<TunnelTlv>> {
    let mut out = Vec::new();
    let mut off = 0;
    while off < value.len() {
        if off + 4 > value.len() {
            return None;
        }
        let tunnel_type = u16::from_be_bytes([value[off], value[off + 1]]);
        let len = u16::from_be_bytes([value[off + 2], value[off + 3]]) as usize;
        let start = off + 4;
        let end = start + len;
        if end > value.len() {
            return None;
        }
        let body = &value[start..end];
        if tunnel_type == TUNNEL_TYPE_SR_POLICY {
            out.push(TunnelTlv::SrPolicy(decode_tunnel_value(body)?));
        } else {
            out.push(TunnelTlv::Other {
                tunnel_type,
                value: body.to_vec(),
            });
        }
        off = end;
    }
    Some(out)
}

/// The SR Policy contents carried by a Tunnel Encapsulation attribute's tunnel
/// TLVs, if one is the SR Policy type.
pub fn sr_policy_of(tlvs: &[TunnelTlv]) -> Option<&SrPolicyEncoding> {
    tlvs.iter().find_map(|t| match t {
        TunnelTlv::SrPolicy(enc) => Some(enc),
        _ => None,
    })
}

/// Encode the SR Policy Tunnel-Type TLV (RFC 9012 §2) for the Tunnel
/// Encapsulation attribute value: `Tunnel-Type(2) · Length(2) · sub-TLVs`.
pub fn encode_tunnel_tlv(out: &mut Vec<u8>, enc: &SrPolicyEncoding) {
    let mut sub = Vec::new();
    if let Some(pref) = enc.preference {
        // Preference sub-TLV (12): Flags(1) · RESERVED(1) · Preference(4).
        push_sub_header(&mut sub, SUBTLV_PREFERENCE, 6);
        sub.push(0);
        sub.push(0);
        sub.extend_from_slice(&pref.to_be_bytes());
    }
    match enc.binding_sid {
        BindingSid::None => {}
        BindingSid::MplsLabel(label) => {
            // Binding SID sub-TLV (13): Flags(1) · RESERVED(1) · label(4).
            push_sub_header(&mut sub, SUBTLV_BINDING_SID, 6);
            sub.push(0);
            sub.push(0);
            sub.extend_from_slice(&(label << 12).to_be_bytes());
        }
        BindingSid::Srv6Sid(sid) => {
            // Binding SID sub-TLV (13): Flags(1) · RESERVED(1) · SRv6 SID(16).
            push_sub_header(&mut sub, SUBTLV_BINDING_SID, 18);
            sub.push(0);
            sub.push(0);
            sub.extend_from_slice(&sid);
        }
    }
    if let Some(prio) = enc.priority {
        // Priority sub-TLV (15): Priority(1) · RESERVED(1).
        push_sub_header(&mut sub, SUBTLV_PRIORITY, 2);
        sub.push(prio);
        sub.push(0);
    }
    for sl in &enc.segment_lists {
        encode_segment_list(&mut sub, sl);
    }
    if let Some(name) = &enc.policy_name {
        // Policy Name sub-TLV (129, 2-octet length): RESERVED(1) · name (UTF-8).
        let bytes = name.as_bytes();
        push_sub_header(&mut sub, SUBTLV_POLICY_NAME, 1 + bytes.len());
        sub.push(0);
        sub.extend_from_slice(bytes);
    }

    out.extend_from_slice(&TUNNEL_TYPE_SR_POLICY.to_be_bytes());
    out.extend_from_slice(&(sub.len() as u16).to_be_bytes());
    out.extend_from_slice(&sub);
}

/// Encode a Segment List sub-TLV (128, 2-octet length): RESERVED(1), an optional
/// Weight sub-TLV, then the segment sub-TLVs.
fn encode_segment_list(out: &mut Vec<u8>, sl: &SegmentList) {
    let mut body = Vec::new();
    body.push(0); // RESERVED
    if let Some(w) = sl.weight {
        // Weight sub-TLV (9): Flags(1) · RESERVED(1) · Weight(4).
        push_sub_header(&mut body, SUBTLV_WEIGHT, 6);
        body.push(0);
        body.push(0);
        body.extend_from_slice(&w.to_be_bytes());
    }
    for seg in &sl.segments {
        encode_segment(&mut body, seg);
    }
    push_sub_header(out, SUBTLV_SEGMENT_LIST, body.len());
    out.extend_from_slice(&body);
}

/// Encode one segment sub-TLV: Type A (MPLS) or Type B (SRv6 SID).
fn encode_segment(out: &mut Vec<u8>, seg: &Segment) {
    match seg {
        Segment::MplsLabel(label) => {
            // Type A (1): Flags(1) · RESERVED(1) · label in the top 20 bits(4).
            push_sub_header(out, SEG_TYPE_MPLS, 6);
            out.push(0);
            out.push(0);
            out.extend_from_slice(&(label << 12).to_be_bytes());
        }
        Segment::Srv6Sid {
            sid,
            behavior,
            structure,
        } => {
            // Type B (13): Flags(1) · RESERVED(1) · SRv6 SID(16) · optional
            // Endpoint Behavior(2) · RESERVED(1) · SID Structure(6).
            let has_trailer = behavior.is_some() || structure.is_some();
            let len = if has_trailer { 18 + 9 } else { 18 };
            push_sub_header(out, SEG_TYPE_SRV6, len);
            out.push(0);
            out.push(0);
            out.extend_from_slice(sid);
            if has_trailer {
                out.extend_from_slice(&behavior.unwrap_or(0).to_be_bytes());
                out.push(0); // RESERVED
                let st = structure.unwrap_or_default();
                out.push(st.locator_block_len);
                out.push(st.locator_node_len);
                out.push(st.function_len);
                out.push(st.argument_len);
                out.push(st.transposition_len);
                out.push(st.transposition_offset);
            }
        }
    }
}

/// Push a sub-TLV header: `Type(1) · Length(1 or 2)`. RFC 9012 §2: a sub-TLV type
/// ≥ 128 uses a 2-octet length, otherwise 1 octet.
fn push_sub_header(out: &mut Vec<u8>, sub_type: u8, len: usize) {
    out.push(sub_type);
    if sub_type >= 128 {
        out.extend_from_slice(&(len as u16).to_be_bytes());
    } else {
        out.push(len as u8);
    }
}

/// Decode an SR Policy Tunnel-Type TLV value (the sub-TLVs) into an
/// [`SrPolicyEncoding`]. Returns `None` on a malformed length so the caller can
/// keep the attribute opaque rather than resetting the session (RFC 7606).
pub fn decode_tunnel_value(mut buf: &[u8]) -> Option<SrPolicyEncoding> {
    let mut enc = SrPolicyEncoding::default();
    while !buf.is_empty() {
        let (sub_type, value, rest) = take_sub_tlv(buf)?;
        buf = rest;
        match sub_type {
            SUBTLV_PREFERENCE if value.len() >= 6 => {
                enc.preference = Some(u32::from_be_bytes([value[2], value[3], value[4], value[5]]));
            }
            SUBTLV_BINDING_SID => {
                // Flags(1) RESERVED(1) then a 0/4/16-octet SID.
                enc.binding_sid = match value.len() {
                    6 => {
                        let label = u32::from_be_bytes([value[2], value[3], value[4], value[5]]);
                        BindingSid::MplsLabel(label >> 12)
                    }
                    18 => {
                        let mut sid = [0u8; 16];
                        sid.copy_from_slice(&value[2..18]);
                        BindingSid::Srv6Sid(sid)
                    }
                    _ => BindingSid::None,
                };
            }
            SUBTLV_PRIORITY if !value.is_empty() => enc.priority = Some(value[0]),
            SUBTLV_SEGMENT_LIST => {
                if let Some(sl) = decode_segment_list(value) {
                    enc.segment_lists.push(sl);
                }
            }
            SUBTLV_POLICY_NAME if !value.is_empty() => {
                // RESERVED(1) then the UTF-8 name.
                enc.policy_name = Some(String::from_utf8_lossy(&value[1..]).into_owned());
            }
            _ => {} // unmodelled sub-TLV: ignored
        }
    }
    Some(enc)
}

/// Decode a Segment List sub-TLV value: RESERVED(1), then Weight / Segment
/// sub-TLVs.
fn decode_segment_list(value: &[u8]) -> Option<SegmentList> {
    if value.is_empty() {
        return None;
    }
    let mut sl = SegmentList::default();
    let mut buf = &value[1..]; // skip RESERVED
    while !buf.is_empty() {
        let (sub_type, v, rest) = take_sub_tlv(buf)?;
        buf = rest;
        match sub_type {
            SUBTLV_WEIGHT if v.len() >= 6 => {
                sl.weight = Some(u32::from_be_bytes([v[2], v[3], v[4], v[5]]));
            }
            SEG_TYPE_MPLS if v.len() >= 6 => {
                let label = u32::from_be_bytes([v[2], v[3], v[4], v[5]]);
                sl.segments.push(Segment::MplsLabel(label >> 12));
            }
            SEG_TYPE_SRV6 if v.len() >= 18 => {
                let mut sid = [0u8; 16];
                sid.copy_from_slice(&v[2..18]);
                let (behavior, structure) = if v.len() >= 18 + 9 {
                    let beh = u16::from_be_bytes([v[18], v[19]]);
                    // v[20] RESERVED, then the 6-octet structure.
                    let st = Srv6SidStructure {
                        locator_block_len: v[21],
                        locator_node_len: v[22],
                        function_len: v[23],
                        argument_len: v[24],
                        transposition_len: v[25],
                        transposition_offset: v[26],
                    };
                    (Some(beh), Some(st))
                } else {
                    (None, None)
                };
                sl.segments.push(Segment::Srv6Sid {
                    sid,
                    behavior,
                    structure,
                });
            }
            _ => {}
        }
    }
    Some(sl)
}

/// Split one sub-TLV off the front of `buf`, returning `(type, value, rest)`.
/// The length field is 2 octets when the type is ≥ 128, else 1 (RFC 9012 §2).
fn take_sub_tlv(buf: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    if buf.len() < 2 {
        return None;
    }
    let sub_type = buf[0];
    let (len, header) = if sub_type >= 128 {
        if buf.len() < 3 {
            return None;
        }
        (u16::from_be_bytes([buf[1], buf[2]]) as usize, 3)
    } else {
        (buf[1] as usize, 2)
    };
    let end = header + len;
    if buf.len() < end {
        return None;
    }
    Some((sub_type, &buf[header..end], &buf[end..]))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v6(s: &str) -> Srv6Sid {
        s.parse::<Ipv6Addr>().unwrap().octets()
    }

    #[test]
    fn nlri_roundtrips_v4_and_v6() {
        let n4 = SrPolicyNlri {
            distinguisher: 1,
            color: 100,
            endpoint: "10.0.0.9".parse().unwrap(),
        };
        let mut buf = Vec::new();
        n4.encode(&mut buf);
        let (dec, used) = SrPolicyNlri::decode(&buf, crate::AFI_IPV4).unwrap();
        assert_eq!(dec, n4);
        assert_eq!(used, buf.len());

        let n6 = SrPolicyNlri {
            distinguisher: 7,
            color: 200,
            endpoint: "2001:db8::1".parse().unwrap(),
        };
        let mut buf = Vec::new();
        n6.encode(&mut buf);
        let (dec, used) = SrPolicyNlri::decode(&buf, crate::AFI_IPV6).unwrap();
        assert_eq!(dec, n6);
        assert_eq!(used, buf.len());
    }

    #[test]
    fn multiple_nlris_decode() {
        let a = SrPolicyNlri {
            distinguisher: 1,
            color: 100,
            endpoint: "10.0.0.1".parse().unwrap(),
        };
        let b = SrPolicyNlri {
            distinguisher: 2,
            color: 100,
            endpoint: "10.0.0.2".parse().unwrap(),
        };
        let mut buf = Vec::new();
        a.encode(&mut buf);
        b.encode(&mut buf);
        assert_eq!(decode_nlris(&buf, crate::AFI_IPV4), Some(vec![a, b]));
    }

    #[test]
    fn tunnel_tlv_roundtrips_full_srv6_candidate() {
        let enc = SrPolicyEncoding {
            preference: Some(200),
            binding_sid: BindingSid::Srv6Sid(v6("2001:db8:b::1")),
            priority: Some(10),
            policy_name: Some("blue-te".to_string()),
            segment_lists: vec![SegmentList {
                weight: Some(1),
                segments: vec![
                    Segment::Srv6Sid {
                        sid: v6("2001:db8:1::1"),
                        behavior: None,
                        structure: None,
                    },
                    Segment::Srv6Sid {
                        sid: v6("2001:db8:2::1"),
                        behavior: Some(0x0040),
                        structure: Some(Srv6SidStructure {
                            locator_block_len: 40,
                            locator_node_len: 24,
                            function_len: 16,
                            argument_len: 0,
                            transposition_len: 0,
                            transposition_offset: 0,
                        }),
                    },
                ],
            }],
        };
        // Wrap/unwrap through the Tunnel-Type TLV envelope.
        let mut buf = Vec::new();
        encode_tunnel_tlv(&mut buf, &enc);
        assert_eq!(u16::from_be_bytes([buf[0], buf[1]]), TUNNEL_TYPE_SR_POLICY);
        let len = u16::from_be_bytes([buf[2], buf[3]]) as usize;
        let value = &buf[4..4 + len];
        let dec = decode_tunnel_value(value).expect("decode");
        assert_eq!(dec, enc);
    }

    #[test]
    fn tunnel_tlv_roundtrips_mpls_candidate() {
        let enc = SrPolicyEncoding {
            preference: Some(100),
            binding_sid: BindingSid::MplsLabel(24000),
            priority: None,
            policy_name: None,
            segment_lists: vec![SegmentList {
                weight: None,
                segments: vec![Segment::MplsLabel(16001), Segment::MplsLabel(16002)],
            }],
        };
        let mut buf = Vec::new();
        encode_tunnel_tlv(&mut buf, &enc);
        let len = u16::from_be_bytes([buf[2], buf[3]]) as usize;
        let dec = decode_tunnel_value(&buf[4..4 + len]).expect("decode");
        assert_eq!(dec, enc);
    }

    #[test]
    fn default_preference_is_100() {
        let enc = SrPolicyEncoding::default();
        assert_eq!(enc.effective_preference(), 100);
        let enc = SrPolicyEncoding {
            preference: Some(250),
            ..Default::default()
        };
        assert_eq!(enc.effective_preference(), 250);
    }

    #[test]
    fn tunnel_encap_attr_roundtrips_with_opaque_neighbour_tlv() {
        let enc = SrPolicyEncoding {
            preference: Some(150),
            binding_sid: BindingSid::None,
            priority: None,
            policy_name: Some("p1".to_string()),
            segment_lists: vec![SegmentList {
                weight: Some(2),
                segments: vec![Segment::Srv6Sid {
                    sid: v6("2001:db8:1::1"),
                    behavior: None,
                    structure: None,
                }],
            }],
        };
        let tlvs = vec![
            TunnelTlv::Other {
                tunnel_type: 2, // some other tunnel type, kept opaque
                value: vec![0xaa, 0xbb, 0xcc],
            },
            TunnelTlv::SrPolicy(enc.clone()),
        ];
        let bytes = encode_tunnel_encap(&tlvs);
        let dec = decode_tunnel_encap(&bytes).expect("decode");
        assert_eq!(dec, tlvs);
        assert_eq!(sr_policy_of(&dec), Some(&enc));
    }

    #[test]
    fn malformed_sub_tlv_length_is_rejected() {
        // A segment-list sub-TLV (128) claiming more than is present.
        let buf = [SUBTLV_SEGMENT_LIST, 0x00, 0x40, 0x00];
        assert!(decode_tunnel_value(&buf).is_none());
    }
}
