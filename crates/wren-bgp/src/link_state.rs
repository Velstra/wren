//! BGP-LS (RFC 7752 / RFC 9552) — the Link-State address family (AFI 16388 /
//! SAFI 71) a BGP speaker uses to export a link-state topology (OSPF / IS-IS) to a
//! controller, which consumes it to compute paths (e.g. the SR segment lists of
//! [`crate::sr_policy`]).
//!
//! A Link-State route is a **Link-State NLRI** (carried in MP_REACH/UNREACH,
//! RFC 4760) describing one Node, Link or IP Prefix, plus an optional **BGP-LS
//! Attribute** (path attribute type 29) carrying that object's attributes (node
//! name, IGP metric, admin group, SRLGs, and the SR TLVs — SID/Label, SR
//! Capabilities).
//!
//! The descriptor and attribute spaces are large and evolving, so this codec models
//! the NLRI *shape* (type, protocol, identifier, and the descriptor TLV tree) and
//! keeps every descriptor / attribute TLV as a generic [`LsTlv`] `(type, value)`.
//! That is a faithful, loss-free round-trip; typed accessors ([`node_descriptor`],
//! [`igp_router_id`], [`prefix`], and the BGP-LS attribute helpers) pull out the
//! fields `show bgp link-state` renders. Only the codec and RIB live wren-side; a
//! controller consumes the topology.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use wren_core::Prefix;

/// The BGP-LS Address Family Identifier (RFC 7752 §3.2).
pub const AFI_LINK_STATE: u16 = 16388;
/// The BGP-LS Subsequent Address Family Identifier (RFC 7752 §3.2).
pub const SAFI_LINK_STATE: u8 = 71;

/// The BGP-LS path attribute type code (RFC 7752 §3.3).
pub const BGP_LS_ATTR: u8 = 29;

// Link-State NLRI types (RFC 7752 §3.2).
const NLRI_NODE: u16 = 1;
const NLRI_LINK: u16 = 2;
const NLRI_IPV4_PREFIX: u16 = 3;
const NLRI_IPV6_PREFIX: u16 = 4;

// Descriptor TLV types (RFC 7752 §3.2.1).
/// Local Node Descriptors TLV.
pub const TLV_LOCAL_NODE_DESCRIPTORS: u16 = 256;
/// Remote Node Descriptors TLV.
pub const TLV_REMOTE_NODE_DESCRIPTORS: u16 = 257;
/// IP Reachability Information TLV (the prefix of a Prefix NLRI).
pub const TLV_IP_REACHABILITY: u16 = 265;

// Node-descriptor sub-TLV types (RFC 7752 §3.2.1.4).
/// Autonomous System sub-TLV.
pub const SUBTLV_AUTONOMOUS_SYSTEM: u16 = 512;
/// IGP Router-ID sub-TLV.
pub const SUBTLV_IGP_ROUTER_ID: u16 = 515;

// BGP-LS Attribute TLV types (RFC 7752 §3.3 / IANA).
/// Node Name attribute TLV (§3.3.1.3).
pub const ATTR_NODE_NAME: u16 = 1026;
/// Administrative Group (colour) attribute TLV (§3.3.2.2).
pub const ATTR_ADMIN_GROUP: u16 = 1088;
/// IGP Metric attribute TLV (§3.3.2.3).
pub const ATTR_IGP_METRIC: u16 = 1095;
/// Shared Risk Link Group attribute TLV (§3.3.2.5).
pub const ATTR_SRLG: u16 = 1096;
/// SR Capabilities attribute TLV (RFC 9085 §2.1.2) — the node's SRGB.
pub const ATTR_SR_CAPABILITIES: u16 = 1034;
/// Adjacency SID attribute TLV (RFC 9085 §2.2.1) — a link's SR adjacency segment.
pub const ATTR_ADJ_SID: u16 = 1099;
/// Prefix SID attribute TLV (RFC 9085 §2.3.1) — a prefix's SR segment.
pub const ATTR_PREFIX_SID: u16 = 1158;

/// One BGP-LS TLV: a 2-octet type and its raw value. Used for every descriptor and
/// every BGP-LS attribute, so the codec is loss-free across the whole (large) TLV
/// space; typed accessors pull out the modelled fields.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct LsTlv {
    /// The TLV type code.
    pub typ: u16,
    /// The raw TLV value.
    pub value: Vec<u8>,
}

impl LsTlv {
    /// Serialise this TLV (`Type(2) · Length(2) · Value`) into `out`.
    pub fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.typ.to_be_bytes());
        out.extend_from_slice(&(self.value.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.value);
    }
}

/// Decode a run of TLVs (`Type(2) · Length(2) · Value`) from `buf`. Returns `None`
/// on a truncated TLV so the caller can keep the object opaque (RFC 7606).
pub fn decode_tlvs(buf: &[u8]) -> Option<Vec<LsTlv>> {
    let mut out = Vec::new();
    let mut off = 0;
    while off < buf.len() {
        if off + 4 > buf.len() {
            return None;
        }
        let typ = u16::from_be_bytes([buf[off], buf[off + 1]]);
        let len = u16::from_be_bytes([buf[off + 2], buf[off + 3]]) as usize;
        let start = off + 4;
        let end = start + len;
        if end > buf.len() {
            return None;
        }
        out.push(LsTlv {
            typ,
            value: buf[start..end].to_vec(),
        });
        off = end;
    }
    Some(out)
}

/// Serialise a run of TLVs into `out`.
pub fn encode_tlvs(out: &mut Vec<u8>, tlvs: &[LsTlv]) {
    for t in tlvs {
        t.encode(out);
    }
}

/// The kind of a Link-State object, for display and grouping.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub enum LsObjectKind {
    /// A Node NLRI (type 1).
    Node,
    /// A Link NLRI (type 2).
    Link,
    /// An IPv4 Topology Prefix NLRI (type 3).
    Ipv4Prefix,
    /// An IPv6 Topology Prefix NLRI (type 4).
    Ipv6Prefix,
}

impl fmt::Display for LsObjectKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            LsObjectKind::Node => "node",
            LsObjectKind::Link => "link",
            LsObjectKind::Ipv4Prefix => "ipv4-prefix",
            LsObjectKind::Ipv6Prefix => "ipv6-prefix",
        };
        f.write_str(s)
    }
}

/// A Link-State NLRI (RFC 7752 §3.2): one Node, Link or IP Prefix, identified by the
/// IGP `protocol`, the routing-universe `identifier`, and its descriptor TLVs.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct LinkStateNlri {
    /// Which object this NLRI describes.
    pub kind: LsObjectKind,
    /// The Protocol-ID (RFC 7752 §3.2): the IGP the object was learned from
    /// (1 IS-IS L1, 2 IS-IS L2, 3 OSPFv2, 4 Direct, 5 Static, 6 OSPFv3, 7 BGP).
    pub protocol: u8,
    /// The Identifier (RFC 7752 §3.2): the routing universe (0 = L3 topology).
    pub identifier: u64,
    /// The descriptor TLVs: Local Node Descriptors (256), plus — for a Link —
    /// Remote Node Descriptors (257) and link descriptors, or — for a Prefix —
    /// the prefix descriptors including IP Reachability (265).
    pub descriptors: Vec<LsTlv>,
}

impl LinkStateNlri {
    /// Serialise this NLRI (`NLRI-Type(2) · Total-Length(2) · Protocol(1) ·
    /// Identifier(8) · Descriptors`) into `out`.
    pub fn encode(&self, out: &mut Vec<u8>) {
        let nlri_type = match self.kind {
            LsObjectKind::Node => NLRI_NODE,
            LsObjectKind::Link => NLRI_LINK,
            LsObjectKind::Ipv4Prefix => NLRI_IPV4_PREFIX,
            LsObjectKind::Ipv6Prefix => NLRI_IPV6_PREFIX,
        };
        let mut body = Vec::new();
        body.push(self.protocol);
        body.extend_from_slice(&self.identifier.to_be_bytes());
        encode_tlvs(&mut body, &self.descriptors);
        out.extend_from_slice(&nlri_type.to_be_bytes());
        out.extend_from_slice(&(body.len() as u16).to_be_bytes());
        out.extend_from_slice(&body);
    }

    /// Decode one Link-State NLRI from the front of `buf`, returning it and the
    /// bytes consumed.
    pub fn decode(buf: &[u8]) -> Option<(LinkStateNlri, usize)> {
        if buf.len() < 4 {
            return None;
        }
        let nlri_type = u16::from_be_bytes([buf[0], buf[1]]);
        let len = u16::from_be_bytes([buf[2], buf[3]]) as usize;
        let end = 4 + len;
        if buf.len() < end || len < 9 {
            return None;
        }
        let body = &buf[4..end];
        let kind = match nlri_type {
            NLRI_NODE => LsObjectKind::Node,
            NLRI_LINK => LsObjectKind::Link,
            NLRI_IPV4_PREFIX => LsObjectKind::Ipv4Prefix,
            NLRI_IPV6_PREFIX => LsObjectKind::Ipv6Prefix,
            _ => return None,
        };
        let protocol = body[0];
        let identifier = u64::from_be_bytes([
            body[1], body[2], body[3], body[4], body[5], body[6], body[7], body[8],
        ]);
        let descriptors = decode_tlvs(&body[9..])?;
        Some((
            LinkStateNlri {
                kind,
                protocol,
                identifier,
                descriptors,
            },
            end,
        ))
    }

    /// The Local (256) or Remote (257) Node Descriptors sub-TLVs, if present.
    pub fn node_descriptor(&self, which: u16) -> Option<Vec<LsTlv>> {
        self.descriptors
            .iter()
            .find(|t| t.typ == which)
            .and_then(|t| decode_tlvs(&t.value))
    }

    /// The IGP Router-ID (sub-TLV 515) of the Local (256) or Remote (257) node, as
    /// raw octets (4/6 for OSPF/IS-IS-system-id, 7/8 for IS-IS pseudonode).
    pub fn igp_router_id(&self, which: u16) -> Option<Vec<u8>> {
        self.node_descriptor(which)?
            .into_iter()
            .find(|t| t.typ == SUBTLV_IGP_ROUTER_ID)
            .map(|t| t.value)
    }

    /// The Autonomous System (sub-TLV 512) of the Local node, if present.
    pub fn local_as(&self) -> Option<u32> {
        let subs = self.node_descriptor(TLV_LOCAL_NODE_DESCRIPTORS)?;
        subs.iter()
            .find(|t| t.typ == SUBTLV_AUTONOMOUS_SYSTEM && t.value.len() == 4)
            .map(|t| u32::from_be_bytes([t.value[0], t.value[1], t.value[2], t.value[3]]))
    }

    /// The prefix carried in the IP Reachability Information TLV (265) of a Prefix
    /// NLRI: `Prefix-Length(1) · Prefix (length rounded up to octets)`.
    pub fn prefix(&self) -> Option<Prefix> {
        let tlv = self
            .descriptors
            .iter()
            .find(|t| t.typ == TLV_IP_REACHABILITY)?;
        if tlv.value.is_empty() {
            return None;
        }
        let plen = tlv.value[0];
        let bytes = &tlv.value[1..];
        let is_v6 = self.kind == LsObjectKind::Ipv6Prefix;
        let addr = if is_v6 {
            let mut o = [0u8; 16];
            let n = bytes.len().min(16);
            o[..n].copy_from_slice(&bytes[..n]);
            IpAddr::V6(Ipv6Addr::from(o))
        } else {
            let mut o = [0u8; 4];
            let n = bytes.len().min(4);
            o[..n].copy_from_slice(&bytes[..n]);
            IpAddr::V4(Ipv4Addr::from(o))
        };
        Prefix::new(addr, plen).ok()
    }
}

/// Decode a run of Link-State NLRI (used by MP_REACH/UNREACH).
pub fn decode_nlris(buf: &[u8]) -> Option<Vec<LinkStateNlri>> {
    let mut out = Vec::new();
    let mut off = 0;
    while off < buf.len() {
        let (nlri, used) = LinkStateNlri::decode(&buf[off..])?;
        out.push(nlri);
        off += used;
    }
    Some(out)
}

/// The BGP-LS Attribute (RFC 7752 §3.3): the attribute TLVs of one Link-State
/// object (node / link / prefix attributes), kept generic with typed accessors.
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct BgpLsAttribute {
    /// The attribute TLVs, in wire order.
    pub tlvs: Vec<LsTlv>,
}

impl BgpLsAttribute {
    /// Build from decoded TLVs.
    pub fn new(tlvs: Vec<LsTlv>) -> Self {
        Self { tlvs }
    }

    /// The value of the first attribute TLV of the given type, if present.
    pub fn tlv(&self, typ: u16) -> Option<&[u8]> {
        self.tlvs
            .iter()
            .find(|t| t.typ == typ)
            .map(|t| t.value.as_slice())
    }

    /// The Node Name (TLV 1026), if present.
    pub fn node_name(&self) -> Option<String> {
        self.tlv(ATTR_NODE_NAME)
            .map(|v| String::from_utf8_lossy(v).into_owned())
    }

    /// The IGP Metric (TLV 1095): 1, 2 or 3 octets wide (RFC 7752 §3.3.2.3).
    pub fn igp_metric(&self) -> Option<u32> {
        let v = self.tlv(ATTR_IGP_METRIC)?;
        let mut m = 0u32;
        for b in v.iter().take(3) {
            m = (m << 8) | *b as u32;
        }
        Some(m)
    }

    /// The Administrative Group / colour bitmask (TLV 1088), if present.
    pub fn admin_group(&self) -> Option<u32> {
        let v = self.tlv(ATTR_ADMIN_GROUP)?;
        if v.len() < 4 {
            return None;
        }
        Some(u32::from_be_bytes([v[0], v[1], v[2], v[3]]))
    }

    /// The Shared Risk Link Groups (TLV 1096): a list of 32-bit SRLG values.
    pub fn srlgs(&self) -> Vec<u32> {
        self.tlv(ATTR_SRLG)
            .map(|v| {
                v.chunks_exact(4)
                    .map(|c| u32::from_be_bytes([c[0], c[1], c[2], c[3]]))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Whether an SR SID/Label attribute is present — an SR Capabilities SRGB
    /// (1034), an Adjacency SID (1099) or a Prefix SID (1158). These feed a
    /// controller computing SR segment lists ([`crate::sr_policy`]).
    pub fn has_sr(&self) -> bool {
        self.tlvs
            .iter()
            .any(|t| matches!(t.typ, ATTR_SR_CAPABILITIES | ATTR_ADJ_SID | ATTR_PREFIX_SID))
    }

    /// Serialise the attribute value (its TLVs) into `out`.
    pub fn encode(&self, out: &mut Vec<u8>) {
        encode_tlvs(out, &self.tlvs);
    }

    /// Decode a BGP-LS Attribute value into its TLVs.
    pub fn decode(value: &[u8]) -> Option<BgpLsAttribute> {
        Some(BgpLsAttribute::new(decode_tlvs(value)?))
    }
}

/// Format an IGP Router-ID for display: an IPv4 dotted quad for a 4-octet OSPF
/// router-id, else IS-IS system-id colon-hex (`aaaa.bbbb.cccc[.dd]`).
pub fn format_router_id(id: &[u8]) -> String {
    if id.len() == 4 {
        return Ipv4Addr::new(id[0], id[1], id[2], id[3]).to_string();
    }
    // IS-IS system id (6 octets, `aaaa.bbbb.cccc`) or pseudonode (7,
    // `aaaa.bbbb.cccc.dd`): a separator before every even-indexed octet.
    let mut s = String::new();
    for (i, b) in id.iter().enumerate() {
        if i > 0 && i % 2 == 0 {
            s.push('.');
        }
        s.push_str(&format!("{b:02x}"));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A Local Node Descriptors TLV (256) with an AS (512) and IGP Router-ID (515).
    fn local_node(as_num: u32, router_id: [u8; 4]) -> LsTlv {
        let mut sub = Vec::new();
        LsTlv {
            typ: SUBTLV_AUTONOMOUS_SYSTEM,
            value: as_num.to_be_bytes().to_vec(),
        }
        .encode(&mut sub);
        LsTlv {
            typ: SUBTLV_IGP_ROUTER_ID,
            value: router_id.to_vec(),
        }
        .encode(&mut sub);
        LsTlv {
            typ: TLV_LOCAL_NODE_DESCRIPTORS,
            value: sub,
        }
    }

    #[test]
    fn node_nlri_roundtrips_and_extracts_descriptors() {
        let nlri = LinkStateNlri {
            kind: LsObjectKind::Node,
            protocol: 3, // OSPFv2
            identifier: 0,
            descriptors: vec![local_node(65000, [10, 0, 0, 1])],
        };
        let mut buf = Vec::new();
        nlri.encode(&mut buf);
        let (dec, used) = LinkStateNlri::decode(&buf).unwrap();
        assert_eq!(dec, nlri);
        assert_eq!(used, buf.len());
        assert_eq!(dec.local_as(), Some(65000));
        assert_eq!(
            dec.igp_router_id(TLV_LOCAL_NODE_DESCRIPTORS),
            Some(vec![10, 0, 0, 1])
        );
        assert_eq!(
            format_router_id(&dec.igp_router_id(256).unwrap()),
            "10.0.0.1"
        );
    }

    #[test]
    fn link_nlri_roundtrips_with_remote_node_and_link_descriptors() {
        // Link descriptor: IPv4 interface address (259) + neighbor address (260).
        let nlri = LinkStateNlri {
            kind: LsObjectKind::Link,
            protocol: 3,
            identifier: 0,
            descriptors: vec![
                local_node(65000, [10, 0, 0, 1]),
                LsTlv {
                    typ: TLV_REMOTE_NODE_DESCRIPTORS,
                    value: {
                        let mut sub = Vec::new();
                        LsTlv {
                            typ: SUBTLV_IGP_ROUTER_ID,
                            value: vec![10, 0, 0, 2],
                        }
                        .encode(&mut sub);
                        sub
                    },
                },
                LsTlv {
                    typ: 259,
                    value: vec![192, 0, 2, 1],
                },
                LsTlv {
                    typ: 260,
                    value: vec![192, 0, 2, 2],
                },
            ],
        };
        let mut buf = Vec::new();
        nlri.encode(&mut buf);
        let (dec, _) = LinkStateNlri::decode(&buf).unwrap();
        assert_eq!(dec, nlri);
        assert_eq!(
            dec.igp_router_id(TLV_REMOTE_NODE_DESCRIPTORS),
            Some(vec![10, 0, 0, 2])
        );
    }

    #[test]
    fn prefix_nlri_roundtrips_and_extracts_prefix() {
        // IP Reachability (265): prefix-length 24, then 3 octets of 10.20.30.0/24.
        let nlri = LinkStateNlri {
            kind: LsObjectKind::Ipv4Prefix,
            protocol: 3,
            identifier: 0,
            descriptors: vec![
                local_node(65000, [10, 0, 0, 1]),
                LsTlv {
                    typ: TLV_IP_REACHABILITY,
                    value: vec![24, 10, 20, 30],
                },
            ],
        };
        let mut buf = Vec::new();
        nlri.encode(&mut buf);
        let (dec, _) = LinkStateNlri::decode(&buf).unwrap();
        assert_eq!(dec, nlri);
        assert_eq!(dec.prefix(), Some("10.20.30.0/24".parse().unwrap()));
    }

    #[test]
    fn multiple_nlris_decode() {
        let a = LinkStateNlri {
            kind: LsObjectKind::Node,
            protocol: 3,
            identifier: 0,
            descriptors: vec![local_node(65000, [10, 0, 0, 1])],
        };
        let b = LinkStateNlri {
            kind: LsObjectKind::Node,
            protocol: 3,
            identifier: 0,
            descriptors: vec![local_node(65000, [10, 0, 0, 2])],
        };
        let mut buf = Vec::new();
        a.encode(&mut buf);
        b.encode(&mut buf);
        assert_eq!(decode_nlris(&buf), Some(vec![a, b]));
    }

    #[test]
    fn bgp_ls_attribute_roundtrips_and_extracts_fields() {
        let mut tlvs = vec![
            LsTlv {
                typ: ATTR_NODE_NAME,
                value: b"r1".to_vec(),
            },
            LsTlv {
                typ: ATTR_IGP_METRIC,
                value: vec![0x00, 0x0a], // 10, 2-octet
            },
            LsTlv {
                typ: ATTR_ADMIN_GROUP,
                value: vec![0x00, 0x00, 0x00, 0x05],
            },
            LsTlv {
                typ: ATTR_SRLG,
                value: vec![0, 0, 0, 100, 0, 0, 0, 200],
            },
        ];
        tlvs.push(LsTlv {
            typ: ATTR_ADJ_SID,
            value: vec![0, 0, 0, 0, 0x3e, 0x80], // flags+weight+reserved+label 16000
        });
        let attr = BgpLsAttribute::new(tlvs);
        let mut buf = Vec::new();
        attr.encode(&mut buf);
        let dec = BgpLsAttribute::decode(&buf).unwrap();
        assert_eq!(dec, attr);
        assert_eq!(dec.node_name().as_deref(), Some("r1"));
        assert_eq!(dec.igp_metric(), Some(10));
        assert_eq!(dec.admin_group(), Some(5));
        assert_eq!(dec.srlgs(), vec![100, 200]);
        assert!(dec.has_sr());
    }

    #[test]
    fn truncated_tlv_is_rejected() {
        // Claims length 40 but no body.
        assert!(decode_tlvs(&[0x01, 0x00, 0x00, 0x28]).is_none());
        // A Node NLRI whose total length overruns the buffer.
        assert!(LinkStateNlri::decode(&[0x00, 0x01, 0x00, 0x40, 0x03]).is_none());
    }

    #[test]
    fn isis_system_id_router_id_formats() {
        assert_eq!(
            format_router_id(&[0x19, 0x21, 0x68, 0x00, 0x10, 0x05]),
            "1921.6800.1005"
        );
    }
}
