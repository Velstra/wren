//! IS-IS TLVs — the type-length-value tuples that make up the body of every PDU
//! (ISO/IEC 10589 §9, with the IP and wide-metric extensions of RFC 1195 / RFC
//! 5305 / RFC 5308).
//!
//! Each TLV is a 1-byte type, a 1-byte length and that many value bytes, so a
//! single TLV value never exceeds 255 bytes — a router that has more to say (more
//! reachabilities, more neighbours) emits several TLVs of the same type, or
//! several LSP fragments. This module models the TLVs IS-IS needs for modern dual
//! IPv4/IPv6 operation; any type it does not interpret is preserved verbatim as
//! [`Tlv::Unknown`] so a PDU still round-trips.

use std::net::{Ipv4Addr, Ipv6Addr};

use crate::{AreaAddress, LspId};

// TLV type codes.
const T_AREA_ADDRESSES: u8 = 1;
const T_LAN_NEIGHBORS: u8 = 6;
const T_PADDING: u8 = 8;
const T_LSP_ENTRIES: u8 = 9;
const T_AUTHENTICATION: u8 = 10;
const T_EXTENDED_IS_REACH: u8 = 22;
const T_PROTOCOLS_SUPPORTED: u8 = 129;
const T_IPV4_IFACE_ADDRS: u8 = 132;
const T_EXTENDED_IP_REACH: u8 = 135;
const T_IPV6_IFACE_ADDRS: u8 = 232;
const T_IPV6_REACH: u8 = 236;

/// One entry of an LSP Entries TLV (type 9, ISO 10589 §9.10): the summary of a
/// single LSP a router holds, as carried in a CSNP/PSNP. 16 bytes on the wire.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct LspEntry {
    /// The LSP's remaining lifetime in seconds.
    pub remaining_lifetime: u16,
    /// The LSP's identifier.
    pub lsp_id: LspId,
    /// The LSP's sequence number.
    pub sequence_number: u32,
    /// The LSP's checksum.
    pub checksum: u16,
}

/// One neighbour of an Extended IS Reachability TLV (type 22, RFC 5305): a link to
/// another IS (or a pseudonode) with a 24-bit wide metric and optional sub-TLVs
/// (carrying interface addresses, link identifiers, traffic-engineering data …).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ExtIsReach {
    /// The neighbour's 7-byte ID (System ID + pseudonode number).
    pub neighbor_id: [u8; 7],
    /// The 24-bit metric to the neighbour.
    pub metric: u32,
    /// The opaque sub-TLV block (preserved verbatim; ≤255 bytes).
    pub sub_tlvs: Vec<u8>,
}

/// One destination of an Extended IP Reachability TLV (type 135, RFC 5305): an
/// IPv4 prefix with a 32-bit metric, the up/down bit (set when a prefix is leaked
/// down from L2 into L1) and optional sub-TLVs.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ExtIpReach {
    /// The 32-bit metric to the prefix.
    pub metric: u32,
    /// The up/down bit — set on a prefix leaked from Level 2 down into Level 1.
    pub up_down: bool,
    /// The prefix length in bits (0–32).
    pub prefix_len: u8,
    /// The prefix's base IPv4 address (host bits are zero).
    pub prefix: Ipv4Addr,
    /// Optional sub-TLVs (`Some` sets the S bit; ≤255 bytes).
    pub sub_tlvs: Option<Vec<u8>>,
}

/// One destination of an IPv6 Reachability TLV (type 236, RFC 5308): an IPv6
/// prefix with a 32-bit metric, the up/down and external bits and optional
/// sub-TLVs.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Ipv6Reach {
    /// The 32-bit metric to the prefix.
    pub metric: u32,
    /// The up/down bit — set on a prefix leaked from Level 2 down into Level 1.
    pub up_down: bool,
    /// The external bit — set on a prefix redistributed from another protocol.
    pub external: bool,
    /// The prefix length in bits (0–128).
    pub prefix_len: u8,
    /// The prefix's base IPv6 address (host bits are zero).
    pub prefix: Ipv6Addr,
    /// Optional sub-TLVs (`Some` sets the S bit; ≤255 bytes).
    pub sub_tlvs: Option<Vec<u8>>,
}

/// An IS-IS TLV. Unknown types keep their raw value so a PDU round-trips and an
/// implementation can pass through what it does not understand.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Tlv {
    /// Area Addresses (type 1): the area address(es) the originator belongs to.
    AreaAddresses(Vec<AreaAddress>),
    /// IS Neighbours (type 6): the SNPA (MAC) addresses of neighbours seen on a
    /// LAN, used in a Hello to prove two-way reachability.
    LanNeighbors(Vec<[u8; 6]>),
    /// Padding (type 8): zero bytes used to pad a Hello to the interface MTU.
    Padding(usize),
    /// LSP Entries (type 9): LSP summaries advertised in a CSNP/PSNP.
    LspEntries(Vec<LspEntry>),
    /// Authentication (type 10): the authentication type byte and its data.
    Authentication { auth_type: u8, data: Vec<u8> },
    /// Extended IS Reachability (type 22): wide-metric links to neighbours.
    ExtendedIsReachability(Vec<ExtIsReach>),
    /// Protocols Supported (type 129): the NLPIDs (IPv4 `0xCC`, IPv6 `0x8E`).
    ProtocolsSupported(Vec<u8>),
    /// IP Interface Addresses (type 132): the originator's IPv4 interface addresses.
    Ipv4InterfaceAddresses(Vec<Ipv4Addr>),
    /// Extended IP Reachability (type 135): wide-metric IPv4 prefixes.
    ExtendedIpReachability(Vec<ExtIpReach>),
    /// IPv6 Interface Addresses (type 232): the originator's IPv6 interface addresses.
    Ipv6InterfaceAddresses(Vec<Ipv6Addr>),
    /// IPv6 Reachability (type 236): wide-metric IPv6 prefixes.
    Ipv6Reachability(Vec<Ipv6Reach>),
    /// Any TLV type this implementation does not interpret, kept verbatim.
    Unknown { typ: u8, value: Vec<u8> },
}

impl Tlv {
    /// The TLV type code.
    pub fn type_code(&self) -> u8 {
        match self {
            Tlv::AreaAddresses(_) => T_AREA_ADDRESSES,
            Tlv::LanNeighbors(_) => T_LAN_NEIGHBORS,
            Tlv::Padding(_) => T_PADDING,
            Tlv::LspEntries(_) => T_LSP_ENTRIES,
            Tlv::Authentication { .. } => T_AUTHENTICATION,
            Tlv::ExtendedIsReachability(_) => T_EXTENDED_IS_REACH,
            Tlv::ProtocolsSupported(_) => T_PROTOCOLS_SUPPORTED,
            Tlv::Ipv4InterfaceAddresses(_) => T_IPV4_IFACE_ADDRS,
            Tlv::ExtendedIpReachability(_) => T_EXTENDED_IP_REACH,
            Tlv::Ipv6InterfaceAddresses(_) => T_IPV6_IFACE_ADDRS,
            Tlv::Ipv6Reachability(_) => T_IPV6_REACH,
            Tlv::Unknown { typ, .. } => *typ,
        }
    }

    /// Serialize the TLV (type, length, value) onto `out`. The value is built into
    /// a scratch buffer first so the 1-byte length is exact; a value longer than
    /// 255 bytes is truncated to the length byte's range (callers split instead).
    pub fn encode(&self, out: &mut Vec<u8>) {
        let mut value = Vec::new();
        self.encode_value(&mut value);
        let len = value.len().min(u8::MAX as usize);
        out.push(self.type_code());
        out.push(len as u8);
        out.extend_from_slice(&value[..len]);
    }

    fn encode_value(&self, v: &mut Vec<u8>) {
        match self {
            Tlv::AreaAddresses(areas) => {
                for a in areas {
                    v.push(a.0.len() as u8);
                    v.extend_from_slice(&a.0);
                }
            }
            Tlv::LanNeighbors(macs) => {
                for m in macs {
                    v.extend_from_slice(m);
                }
            }
            Tlv::Padding(n) => v.extend(std::iter::repeat(0u8).take(*n)),
            Tlv::LspEntries(entries) => {
                for e in entries {
                    v.extend_from_slice(&e.remaining_lifetime.to_be_bytes());
                    e.lsp_id.encode(v);
                    v.extend_from_slice(&e.sequence_number.to_be_bytes());
                    v.extend_from_slice(&e.checksum.to_be_bytes());
                }
            }
            Tlv::Authentication { auth_type, data } => {
                v.push(*auth_type);
                v.extend_from_slice(data);
            }
            Tlv::ExtendedIsReachability(reaches) => {
                for r in reaches {
                    v.extend_from_slice(&r.neighbor_id);
                    put_u24(v, r.metric);
                    v.push(r.sub_tlvs.len().min(u8::MAX as usize) as u8);
                    v.extend_from_slice(&r.sub_tlvs);
                }
            }
            Tlv::ProtocolsSupported(nlpids) => v.extend_from_slice(nlpids),
            Tlv::Ipv4InterfaceAddresses(addrs) => {
                for a in addrs {
                    v.extend_from_slice(&a.octets());
                }
            }
            Tlv::ExtendedIpReachability(reaches) => {
                for r in reaches {
                    v.extend_from_slice(&r.metric.to_be_bytes());
                    let mut control = r.prefix_len & 0x3f;
                    if r.up_down {
                        control |= 0x80;
                    }
                    if r.sub_tlvs.is_some() {
                        control |= 0x40;
                    }
                    v.push(control);
                    let n = pfx_bytes(r.prefix_len);
                    v.extend_from_slice(&r.prefix.octets()[..n]);
                    if let Some(sub) = &r.sub_tlvs {
                        v.push(sub.len().min(u8::MAX as usize) as u8);
                        v.extend_from_slice(sub);
                    }
                }
            }
            Tlv::Ipv6InterfaceAddresses(addrs) => {
                for a in addrs {
                    v.extend_from_slice(&a.octets());
                }
            }
            Tlv::Ipv6Reachability(reaches) => {
                for r in reaches {
                    v.extend_from_slice(&r.metric.to_be_bytes());
                    let mut flags = 0u8;
                    if r.up_down {
                        flags |= 0x80;
                    }
                    if r.external {
                        flags |= 0x40;
                    }
                    if r.sub_tlvs.is_some() {
                        flags |= 0x20;
                    }
                    v.push(flags);
                    v.push(r.prefix_len);
                    let n = pfx_bytes(r.prefix_len);
                    v.extend_from_slice(&r.prefix.octets()[..n]);
                    if let Some(sub) = &r.sub_tlvs {
                        v.push(sub.len().min(u8::MAX as usize) as u8);
                        v.extend_from_slice(sub);
                    }
                }
            }
            Tlv::Unknown { value, .. } => v.extend_from_slice(value),
        }
    }

    /// Parse one TLV value `v` of type `typ` into the typed form, or `None` if the
    /// value is malformed for that type.
    fn decode_one(typ: u8, v: &[u8]) -> Option<Tlv> {
        Some(match typ {
            T_AREA_ADDRESSES => {
                let mut areas = Vec::new();
                let mut p = 0;
                while p < v.len() {
                    let n = v[p] as usize;
                    p += 1;
                    if p + n > v.len() {
                        return None;
                    }
                    areas.push(AreaAddress(v[p..p + n].to_vec()));
                    p += n;
                }
                Tlv::AreaAddresses(areas)
            }
            T_LAN_NEIGHBORS => {
                if v.len() % 6 != 0 {
                    return None;
                }
                let macs = v
                    .chunks_exact(6)
                    .map(|c| {
                        let mut m = [0u8; 6];
                        m.copy_from_slice(c);
                        m
                    })
                    .collect();
                Tlv::LanNeighbors(macs)
            }
            T_PADDING => Tlv::Padding(v.len()),
            T_LSP_ENTRIES => {
                if v.len() % 16 != 0 {
                    return None;
                }
                let mut entries = Vec::new();
                for c in v.chunks_exact(16) {
                    entries.push(LspEntry {
                        remaining_lifetime: u16::from_be_bytes([c[0], c[1]]),
                        lsp_id: LspId::decode(&c[2..10])?,
                        sequence_number: u32::from_be_bytes([c[10], c[11], c[12], c[13]]),
                        checksum: u16::from_be_bytes([c[14], c[15]]),
                    });
                }
                Tlv::LspEntries(entries)
            }
            T_AUTHENTICATION => {
                if v.is_empty() {
                    return None;
                }
                Tlv::Authentication {
                    auth_type: v[0],
                    data: v[1..].to_vec(),
                }
            }
            T_EXTENDED_IS_REACH => {
                let mut reaches = Vec::new();
                let mut p = 0;
                while p < v.len() {
                    if p + 11 > v.len() {
                        return None;
                    }
                    let mut nid = [0u8; 7];
                    nid.copy_from_slice(&v[p..p + 7]);
                    let metric = get_u24(&v[p + 7..p + 10]);
                    let sub_len = v[p + 10] as usize;
                    p += 11;
                    if p + sub_len > v.len() {
                        return None;
                    }
                    reaches.push(ExtIsReach {
                        neighbor_id: nid,
                        metric,
                        sub_tlvs: v[p..p + sub_len].to_vec(),
                    });
                    p += sub_len;
                }
                Tlv::ExtendedIsReachability(reaches)
            }
            T_PROTOCOLS_SUPPORTED => Tlv::ProtocolsSupported(v.to_vec()),
            T_IPV4_IFACE_ADDRS => {
                if v.len() % 4 != 0 {
                    return None;
                }
                let addrs = v
                    .chunks_exact(4)
                    .map(|c| Ipv4Addr::new(c[0], c[1], c[2], c[3]))
                    .collect();
                Tlv::Ipv4InterfaceAddresses(addrs)
            }
            T_EXTENDED_IP_REACH => {
                let mut reaches = Vec::new();
                let mut p = 0;
                while p < v.len() {
                    if p + 5 > v.len() {
                        return None;
                    }
                    let metric = u32::from_be_bytes([v[p], v[p + 1], v[p + 2], v[p + 3]]);
                    let control = v[p + 4];
                    let up_down = control & 0x80 != 0;
                    let has_sub = control & 0x40 != 0;
                    let prefix_len = control & 0x3f;
                    if prefix_len > 32 {
                        return None;
                    }
                    let n = pfx_bytes(prefix_len);
                    p += 5;
                    if p + n > v.len() {
                        return None;
                    }
                    let mut octets = [0u8; 4];
                    octets[..n].copy_from_slice(&v[p..p + n]);
                    p += n;
                    let sub_tlvs = if has_sub {
                        if p >= v.len() {
                            return None;
                        }
                        let sl = v[p] as usize;
                        p += 1;
                        if p + sl > v.len() {
                            return None;
                        }
                        let sub = v[p..p + sl].to_vec();
                        p += sl;
                        Some(sub)
                    } else {
                        None
                    };
                    reaches.push(ExtIpReach {
                        metric,
                        up_down,
                        prefix_len,
                        prefix: Ipv4Addr::from(octets),
                        sub_tlvs,
                    });
                }
                Tlv::ExtendedIpReachability(reaches)
            }
            T_IPV6_IFACE_ADDRS => {
                if v.len() % 16 != 0 {
                    return None;
                }
                let mut addrs = Vec::new();
                for c in v.chunks_exact(16) {
                    let mut o = [0u8; 16];
                    o.copy_from_slice(c);
                    addrs.push(Ipv6Addr::from(o));
                }
                Tlv::Ipv6InterfaceAddresses(addrs)
            }
            T_IPV6_REACH => {
                let mut reaches = Vec::new();
                let mut p = 0;
                while p < v.len() {
                    if p + 6 > v.len() {
                        return None;
                    }
                    let metric = u32::from_be_bytes([v[p], v[p + 1], v[p + 2], v[p + 3]]);
                    let flags = v[p + 4];
                    let up_down = flags & 0x80 != 0;
                    let external = flags & 0x40 != 0;
                    let has_sub = flags & 0x20 != 0;
                    let prefix_len = v[p + 5];
                    if prefix_len > 128 {
                        return None;
                    }
                    let n = pfx_bytes(prefix_len);
                    p += 6;
                    if p + n > v.len() {
                        return None;
                    }
                    let mut octets = [0u8; 16];
                    octets[..n].copy_from_slice(&v[p..p + n]);
                    p += n;
                    let sub_tlvs = if has_sub {
                        if p >= v.len() {
                            return None;
                        }
                        let sl = v[p] as usize;
                        p += 1;
                        if p + sl > v.len() {
                            return None;
                        }
                        let sub = v[p..p + sl].to_vec();
                        p += sl;
                        Some(sub)
                    } else {
                        None
                    };
                    reaches.push(Ipv6Reach {
                        metric,
                        up_down,
                        external,
                        prefix_len,
                        prefix: Ipv6Addr::from(octets),
                        sub_tlvs,
                    });
                }
                Tlv::Ipv6Reachability(reaches)
            }
            other => Tlv::Unknown {
                typ: other,
                value: v.to_vec(),
            },
        })
    }
}

/// Serialize a list of TLVs onto `out`.
pub fn encode_all(tlvs: &[Tlv], out: &mut Vec<u8>) {
    for t in tlvs {
        t.encode(out);
    }
}

/// Parse a back-to-back stream of TLVs (the body of a PDU). Returns `None` if a
/// TLV's length runs past the buffer or a known TLV is internally malformed.
pub fn decode_all(buf: &[u8]) -> Option<Vec<Tlv>> {
    let mut tlvs = Vec::new();
    let mut p = 0;
    while p < buf.len() {
        if p + 2 > buf.len() {
            return None;
        }
        let typ = buf[p];
        let len = buf[p + 1] as usize;
        p += 2;
        if p + len > buf.len() {
            return None;
        }
        tlvs.push(Tlv::decode_one(typ, &buf[p..p + len])?);
        p += len;
    }
    Some(tlvs)
}

// --- helpers ---------------------------------------------------------------

/// The number of significant prefix bytes for a prefix of `len` bits.
fn pfx_bytes(len: u8) -> usize {
    (len as usize).div_ceil(8)
}

fn put_u24(out: &mut Vec<u8>, v: u32) {
    out.push((v >> 16) as u8);
    out.push((v >> 8) as u8);
    out.push(v as u8);
}

fn get_u24(b: &[u8]) -> u32 {
    ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{SystemId, NLPID_IPV4, NLPID_IPV6};

    fn roundtrip(tlv: &Tlv) -> Tlv {
        let mut buf = Vec::new();
        tlv.encode(&mut buf);
        let mut got = decode_all(&buf).expect("decodes");
        assert_eq!(got.len(), 1);
        got.pop().unwrap()
    }

    #[test]
    fn area_addresses_roundtrip() {
        let t = Tlv::AreaAddresses(vec![
            AreaAddress(vec![0x49, 0x00, 0x01]),
            AreaAddress(vec![0x49, 0x00, 0x02]),
        ]);
        assert_eq!(roundtrip(&t), t);
    }

    #[test]
    fn protocols_and_iface_addresses_roundtrip() {
        let p = Tlv::ProtocolsSupported(vec![NLPID_IPV4, NLPID_IPV6]);
        assert_eq!(roundtrip(&p), p);
        let v4 = Tlv::Ipv4InterfaceAddresses(vec![Ipv4Addr::new(10, 0, 0, 1)]);
        assert_eq!(roundtrip(&v4), v4);
        let v6 = Tlv::Ipv6InterfaceAddresses(vec![Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1)]);
        assert_eq!(roundtrip(&v6), v6);
    }

    #[test]
    fn extended_is_reach_roundtrips_with_subtlvs() {
        let t = Tlv::ExtendedIsReachability(vec![
            ExtIsReach {
                neighbor_id: [1, 2, 3, 4, 5, 6, 0],
                metric: 10,
                sub_tlvs: vec![],
            },
            ExtIsReach {
                neighbor_id: [9, 9, 9, 9, 9, 9, 1],
                metric: 0x00ab_cdef & 0x00ff_ffff,
                sub_tlvs: vec![0x04, 0x04, 10, 0, 0, 1],
            },
        ]);
        assert_eq!(roundtrip(&t), t);
    }

    #[test]
    fn extended_ip_reach_roundtrips_both_paths() {
        // No sub-TLVs, a /24 → 3 significant bytes.
        let bare = Tlv::ExtendedIpReachability(vec![ExtIpReach {
            metric: 20,
            up_down: false,
            prefix_len: 24,
            prefix: Ipv4Addr::new(192, 168, 1, 0),
            sub_tlvs: None,
        }]);
        assert_eq!(roundtrip(&bare), bare);
        // Up/down set and sub-TLVs present (the S bit), a /32.
        let full = Tlv::ExtendedIpReachability(vec![ExtIpReach {
            metric: 0xdead_beef,
            up_down: true,
            prefix_len: 32,
            prefix: Ipv4Addr::new(10, 1, 2, 3),
            sub_tlvs: Some(vec![1, 2, 3]),
        }]);
        assert_eq!(roundtrip(&full), full);
    }

    #[test]
    fn ipv6_reach_roundtrips_with_flags() {
        let t = Tlv::Ipv6Reachability(vec![Ipv6Reach {
            metric: 100,
            up_down: true,
            external: true,
            prefix_len: 64,
            prefix: Ipv6Addr::new(0x2001, 0xdb8, 1, 0, 0, 0, 0, 0),
            sub_tlvs: None,
        }]);
        assert_eq!(roundtrip(&t), t);
        // A default route (/0) carries no prefix bytes.
        let def = Tlv::Ipv6Reachability(vec![Ipv6Reach {
            metric: 1,
            up_down: false,
            external: false,
            prefix_len: 0,
            prefix: Ipv6Addr::UNSPECIFIED,
            sub_tlvs: None,
        }]);
        assert_eq!(roundtrip(&def), def);
    }

    #[test]
    fn lsp_entries_roundtrip() {
        let t = Tlv::LspEntries(vec![LspEntry {
            remaining_lifetime: 1199,
            lsp_id: LspId::new(SystemId::new([1, 1, 1, 1, 1, 1]), 0, 0),
            sequence_number: 42,
            checksum: 0xbeef,
        }]);
        assert_eq!(roundtrip(&t), t);
    }

    #[test]
    fn unknown_tlv_is_preserved() {
        let raw = Tlv::Unknown {
            typ: 222,
            value: vec![1, 2, 3, 4],
        };
        assert_eq!(roundtrip(&raw), raw);
    }

    #[test]
    fn padding_and_lan_neighbors() {
        let pad = Tlv::Padding(17);
        assert_eq!(roundtrip(&pad), pad);
        let nbrs = Tlv::LanNeighbors(vec![[0, 1, 2, 3, 4, 5], [10, 11, 12, 13, 14, 15]]);
        assert_eq!(roundtrip(&nbrs), nbrs);
    }

    #[test]
    fn truncated_tlv_stream_is_rejected() {
        // type=1, len=5, but only 2 value bytes present.
        assert_eq!(decode_all(&[1, 5, 0, 0]), None);
    }

    #[test]
    fn several_tlvs_decode_in_order() {
        let mut buf = Vec::new();
        encode_all(
            &[
                Tlv::ProtocolsSupported(vec![NLPID_IPV4]),
                Tlv::Padding(2),
                Tlv::Ipv4InterfaceAddresses(vec![Ipv4Addr::new(1, 1, 1, 1)]),
            ],
            &mut buf,
        );
        let tlvs = decode_all(&buf).unwrap();
        assert_eq!(tlvs.len(), 3);
        assert_eq!(tlvs[0].type_code(), 129);
        assert_eq!(tlvs[1].type_code(), 8);
        assert_eq!(tlvs[2].type_code(), 132);
    }
}
