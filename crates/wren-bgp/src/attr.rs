//! BGP path attributes (RFC 4271 §4.3 / §5): the typed values an UPDATE carries
//! to describe a set of routes.
//!
//! Each attribute is `flags(1) · type(1) · length(1 or 2) · value`. The flags
//! mark an attribute Optional / Transitive / Partial / Extended-Length; for the
//! well-known attributes [`PathAttribute::encode`] writes the canonical flags, so
//! callers just build the typed value.
//!
//! ASNs are held as `u32` (RFC 6793). The width of AS_PATH / AGGREGATOR *on the
//! wire* is a per-session property: [`PathAttribute::encode`] and
//! [`PathAttribute::decode`] take a `four_octet` flag — `true` between two
//! 4-octet-capable speakers, `false` toward a legacy peer (where each AS is
//! 2-octet and [`crate::AS_TRANS`] stands in for any AS that does not fit). The
//! AS4_PATH / AS4_AGGREGATOR attributes carry the true 4-octet values through
//! legacy speakers and are always 4-octet on the wire; [`reconstruct_as_path`]
//! merges them back into AS_PATH on receipt (RFC 6793 §4.2.3).

use std::net::Ipv4Addr;

use wren_core::Prefix;

use crate::{as_trans_fit, decode_prefix, decode_prefix_v6, encode_prefix_any, AFI_IPV6};

/// Attribute flag: the attribute is optional (vs. well-known).
pub const FLAG_OPTIONAL: u8 = 0x80;
/// Attribute flag: the attribute is transitive (passed to other ASes).
pub const FLAG_TRANSITIVE: u8 = 0x40;
/// Attribute flag: an optional transitive attribute was only partially processed.
pub const FLAG_PARTIAL: u8 = 0x20;
/// Attribute flag: the length field is two octets, not one.
pub const FLAG_EXTENDED_LEN: u8 = 0x10;

/// The ORIGIN of a route (§5.1.1) — how it entered BGP.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Origin {
    /// Interior to the originating AS (e.g. an IGP).
    Igp,
    /// Learned via EGP (historical).
    Egp,
    /// Learned some other way (e.g. redistribution).
    Incomplete,
}

impl Origin {
    /// Decode the on-wire ORIGIN byte.
    pub fn from_u8(v: u8) -> Option<Self> {
        Some(match v {
            0 => Origin::Igp,
            1 => Origin::Egp,
            2 => Origin::Incomplete,
            _ => return None,
        })
    }

    /// The on-wire ORIGIN byte.
    pub fn as_u8(self) -> u8 {
        match self {
            Origin::Igp => 0,
            Origin::Egp => 1,
            Origin::Incomplete => 2,
        }
    }
}

/// One segment of an AS_PATH (§5.1.2). ASes are held 4-octet-wide (RFC 6793); the
/// `four_octet` flag chooses the on-wire width.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum AsPathSegment {
    /// An unordered set of ASes (from aggregation).
    Set(Vec<u32>),
    /// An ordered sequence of ASes the route has traversed.
    Sequence(Vec<u32>),
}

impl AsPathSegment {
    const SET: u8 = 1;
    const SEQUENCE: u8 = 2;

    /// The ASes this segment carries (in order).
    pub fn asns(&self) -> &[u32] {
        match self {
            AsPathSegment::Set(a) | AsPathSegment::Sequence(a) => a,
        }
    }

    fn encode(&self, out: &mut Vec<u8>, four_octet: bool) {
        let (kind, asns) = match self {
            AsPathSegment::Set(a) => (Self::SET, a),
            AsPathSegment::Sequence(a) => (Self::SEQUENCE, a),
        };
        out.push(kind);
        out.push(asns.len() as u8);
        for &asn in asns {
            if four_octet {
                out.extend_from_slice(&asn.to_be_bytes());
            } else {
                out.extend_from_slice(&as_trans_fit(asn).to_be_bytes());
            }
        }
    }

    fn decode(buf: &[u8], four_octet: bool) -> Option<(AsPathSegment, usize)> {
        if buf.len() < 2 {
            return None;
        }
        let kind = buf[0];
        let count = buf[1] as usize;
        let width = if four_octet { 4 } else { 2 };
        let end = 2 + count * width;
        if buf.len() < end {
            return None;
        }
        let asns: Vec<u32> = buf[2..end]
            .chunks_exact(width)
            .map(|c| {
                if four_octet {
                    u32::from_be_bytes([c[0], c[1], c[2], c[3]])
                } else {
                    u16::from_be_bytes([c[0], c[1]]) as u32
                }
            })
            .collect();
        let seg = match kind {
            Self::SET => AsPathSegment::Set(asns),
            Self::SEQUENCE => AsPathSegment::Sequence(asns),
            _ => return None,
        };
        Some((seg, end))
    }
}

/// A BGP path attribute (§5).
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum PathAttribute {
    /// ORIGIN (type 1, well-known mandatory).
    Origin(Origin),
    /// AS_PATH (type 2, well-known mandatory).
    AsPath(Vec<AsPathSegment>),
    /// NEXT_HOP (type 3, well-known mandatory).
    NextHop(Ipv4Addr),
    /// MULTI_EXIT_DISC (type 4, optional non-transitive).
    MultiExitDisc(u32),
    /// LOCAL_PREF (type 5, well-known discretionary).
    LocalPref(u32),
    /// ATOMIC_AGGREGATE (type 6, well-known discretionary).
    AtomicAggregate,
    /// COMMUNITIES (type 8, optional transitive) — the RFC 1997 32-bit tags.
    Communities(Vec<u32>),
    /// LARGE_COMMUNITY (type 32, optional transitive) — the RFC 8092 12-octet
    /// `(global, local1, local2)` tags.
    LargeCommunities(Vec<(u32, u32, u32)>),
    /// EXTENDED_COMMUNITIES (type 16, optional transitive) — the RFC 4360 8-octet
    /// tags (Route Target / Route Origin and friends), kept as raw octets.
    ExtendedCommunities(Vec<[u8; 8]>),
    /// MP_REACH_NLRI (type 14, optional non-transitive) — multiprotocol
    /// reachability (RFC 4760 §3): the destinations of one `(AFI, SAFI)` family
    /// together with the next hop to reach them. Used here to carry IPv6 unicast.
    MpReachNlri {
        /// The Address Family Identifier (e.g. [`crate::AFI_IPV6`]).
        afi: u16,
        /// The Subsequent Address Family Identifier (e.g. [`crate::SAFI_UNICAST`]).
        safi: u8,
        /// The next hop, raw (16 octets for an IPv6 global, 32 for global +
        /// link-local per RFC 2545) — kept opaque so the codec is family-agnostic.
        next_hop: Vec<u8>,
        /// The reachable prefixes (NLRI) in this family.
        nlri: Vec<Prefix>,
    },
    /// MP_UNREACH_NLRI (type 15, optional non-transitive) — multiprotocol
    /// withdrawal (RFC 4760 §4): prefixes of one `(AFI, SAFI)` being withdrawn.
    MpUnreachNlri {
        /// The Address Family Identifier.
        afi: u16,
        /// The Subsequent Address Family Identifier.
        safi: u8,
        /// The prefixes being withdrawn.
        withdrawn: Vec<Prefix>,
    },
    /// ORIGINATOR_ID (type 9, optional non-transitive) — the BGP identifier of the
    /// router that first introduced the route into the local AS (RFC 4456), set by
    /// a route reflector for loop avoidance.
    OriginatorId(Ipv4Addr),
    /// CLUSTER_LIST (type 10, optional non-transitive) — the sequence of cluster
    /// ids the route has been reflected through (RFC 4456); each reflector prepends
    /// its own, and a reflector that finds its id here drops the route.
    ClusterList(Vec<Ipv4Addr>),
    /// AGGREGATOR (type 7, optional transitive).
    Aggregator {
        /// The AS that formed the aggregate.
        asn: u32,
        /// The BGP identifier of the aggregating router.
        id: Ipv4Addr,
    },
    /// AS4_PATH (type 17, optional transitive) — the 4-octet AS_PATH carried
    /// intact through legacy 2-octet speakers (RFC 6793 §3).
    As4Path(Vec<AsPathSegment>),
    /// AS4_AGGREGATOR (type 18, optional transitive) — the 4-octet AGGREGATOR
    /// carried through legacy speakers (RFC 6793 §3).
    As4Aggregator {
        /// The 4-octet AS that formed the aggregate.
        asn: u32,
        /// The BGP identifier of the aggregating router.
        id: Ipv4Addr,
    },
    /// An attribute type this implementation does not model, kept verbatim.
    Unknown {
        /// The original attribute flags.
        flags: u8,
        /// The attribute type code.
        type_code: u8,
        /// The raw attribute value.
        value: Vec<u8>,
    },
}

impl PathAttribute {
    const ORIGIN: u8 = 1;
    const AS_PATH: u8 = 2;
    const NEXT_HOP: u8 = 3;
    const MED: u8 = 4;
    const LOCAL_PREF: u8 = 5;
    const ATOMIC_AGGREGATE: u8 = 6;
    const AGGREGATOR: u8 = 7;
    const COMMUNITIES: u8 = 8;
    const ORIGINATOR_ID: u8 = 9;
    const CLUSTER_LIST: u8 = 10;
    const MP_REACH_NLRI: u8 = 14;
    const MP_UNREACH_NLRI: u8 = 15;
    const EXTENDED_COMMUNITIES: u8 = 16;
    const AS4_PATH: u8 = 17;
    const AS4_AGGREGATOR: u8 = 18;
    const LARGE_COMMUNITIES: u8 = 32;

    /// The attribute type code.
    pub fn type_code(&self) -> u8 {
        match self {
            PathAttribute::Origin(_) => Self::ORIGIN,
            PathAttribute::AsPath(_) => Self::AS_PATH,
            PathAttribute::NextHop(_) => Self::NEXT_HOP,
            PathAttribute::MultiExitDisc(_) => Self::MED,
            PathAttribute::LocalPref(_) => Self::LOCAL_PREF,
            PathAttribute::AtomicAggregate => Self::ATOMIC_AGGREGATE,
            PathAttribute::Aggregator { .. } => Self::AGGREGATOR,
            PathAttribute::Communities(_) => Self::COMMUNITIES,
            PathAttribute::ExtendedCommunities(_) => Self::EXTENDED_COMMUNITIES,
            PathAttribute::MpReachNlri { .. } => Self::MP_REACH_NLRI,
            PathAttribute::MpUnreachNlri { .. } => Self::MP_UNREACH_NLRI,
            PathAttribute::OriginatorId(_) => Self::ORIGINATOR_ID,
            PathAttribute::ClusterList(_) => Self::CLUSTER_LIST,
            PathAttribute::LargeCommunities(_) => Self::LARGE_COMMUNITIES,
            PathAttribute::As4Path(_) => Self::AS4_PATH,
            PathAttribute::As4Aggregator { .. } => Self::AS4_AGGREGATOR,
            PathAttribute::Unknown { type_code, .. } => *type_code,
        }
    }

    /// The canonical flags for this attribute (the well-known ones are transitive;
    /// MED is optional non-transitive; AGGREGATOR / AS4_* are optional transitive).
    fn canonical_flags(&self) -> u8 {
        match self {
            PathAttribute::MultiExitDisc(_)
            | PathAttribute::MpReachNlri { .. }
            | PathAttribute::MpUnreachNlri { .. }
            | PathAttribute::OriginatorId(_)
            | PathAttribute::ClusterList(_) => FLAG_OPTIONAL,
            PathAttribute::Aggregator { .. }
            | PathAttribute::Communities(_)
            | PathAttribute::ExtendedCommunities(_)
            | PathAttribute::LargeCommunities(_)
            | PathAttribute::As4Path(_)
            | PathAttribute::As4Aggregator { .. } => FLAG_OPTIONAL | FLAG_TRANSITIVE,
            PathAttribute::Unknown { flags, .. } => *flags,
            _ => FLAG_TRANSITIVE,
        }
    }

    /// Serialise just this attribute's value into `out`. `four_octet` chooses the
    /// AS_PATH / AGGREGATOR width; AS4_PATH / AS4_AGGREGATOR are always 4-octet.
    fn encode_value(&self, out: &mut Vec<u8>, four_octet: bool) {
        match self {
            PathAttribute::Origin(o) => out.push(o.as_u8()),
            PathAttribute::AsPath(segs) => {
                for s in segs {
                    s.encode(out, four_octet);
                }
            }
            PathAttribute::NextHop(ip) => out.extend_from_slice(&ip.octets()),
            PathAttribute::MultiExitDisc(m) => out.extend_from_slice(&m.to_be_bytes()),
            PathAttribute::LocalPref(p) => out.extend_from_slice(&p.to_be_bytes()),
            PathAttribute::AtomicAggregate => {}
            PathAttribute::Communities(comms) => {
                for c in comms {
                    out.extend_from_slice(&c.to_be_bytes());
                }
            }
            PathAttribute::LargeCommunities(comms) => {
                for (g, l1, l2) in comms {
                    out.extend_from_slice(&g.to_be_bytes());
                    out.extend_from_slice(&l1.to_be_bytes());
                    out.extend_from_slice(&l2.to_be_bytes());
                }
            }
            PathAttribute::ExtendedCommunities(comms) => {
                for c in comms {
                    out.extend_from_slice(c);
                }
            }
            PathAttribute::MpReachNlri { afi, safi, next_hop, nlri } => {
                out.extend_from_slice(&afi.to_be_bytes());
                out.push(*safi);
                out.push(next_hop.len() as u8);
                out.extend_from_slice(next_hop);
                out.push(0); // Reserved (SNPA count, unused)
                for p in nlri {
                    encode_prefix_any(out, p);
                }
            }
            PathAttribute::MpUnreachNlri { afi, safi, withdrawn } => {
                out.extend_from_slice(&afi.to_be_bytes());
                out.push(*safi);
                for p in withdrawn {
                    encode_prefix_any(out, p);
                }
            }
            PathAttribute::OriginatorId(id) => out.extend_from_slice(&id.octets()),
            PathAttribute::ClusterList(ids) => {
                for id in ids {
                    out.extend_from_slice(&id.octets());
                }
            }
            PathAttribute::Aggregator { asn, id } => {
                if four_octet {
                    out.extend_from_slice(&asn.to_be_bytes());
                } else {
                    out.extend_from_slice(&as_trans_fit(*asn).to_be_bytes());
                }
                out.extend_from_slice(&id.octets());
            }
            PathAttribute::As4Path(segs) => {
                for s in segs {
                    s.encode(out, true);
                }
            }
            PathAttribute::As4Aggregator { asn, id } => {
                out.extend_from_slice(&asn.to_be_bytes());
                out.extend_from_slice(&id.octets());
            }
            PathAttribute::Unknown { value, .. } => out.extend_from_slice(value),
        }
    }

    /// Serialise the whole attribute (flags · type · length · value) into `out`.
    /// `four_octet` chooses the AS_PATH / AGGREGATOR width (RFC 6793).
    pub fn encode(&self, out: &mut Vec<u8>, four_octet: bool) {
        let mut value = Vec::new();
        self.encode_value(&mut value, four_octet);
        let extended = value.len() > 0xff;
        let mut flags = self.canonical_flags();
        if extended {
            flags |= FLAG_EXTENDED_LEN;
        } else {
            flags &= !FLAG_EXTENDED_LEN;
        }
        out.push(flags);
        out.push(self.type_code());
        if extended {
            out.extend_from_slice(&(value.len() as u16).to_be_bytes());
        } else {
            out.push(value.len() as u8);
        }
        out.extend_from_slice(&value);
    }

    /// Decode one attribute from the front of `buf`, returning it and the number
    /// of bytes consumed. `four_octet` chooses the AS_PATH / AGGREGATOR width.
    pub fn decode(buf: &[u8], four_octet: bool) -> Option<(PathAttribute, usize)> {
        if buf.len() < 3 {
            return None;
        }
        let flags = buf[0];
        let type_code = buf[1];
        let (len, header) = if flags & FLAG_EXTENDED_LEN != 0 {
            if buf.len() < 4 {
                return None;
            }
            (u16::from_be_bytes([buf[2], buf[3]]) as usize, 4)
        } else {
            (buf[2] as usize, 3)
        };
        let end = header + len;
        if buf.len() < end {
            return None;
        }
        let value = &buf[header..end];
        let attr = match type_code {
            Self::ORIGIN => {
                let o = Origin::from_u8(*value.first()?)?;
                PathAttribute::Origin(o)
            }
            Self::AS_PATH => PathAttribute::AsPath(decode_as_segments(value, four_octet)?),
            Self::AS4_PATH => PathAttribute::As4Path(decode_as_segments(value, true)?),
            Self::NEXT_HOP => {
                if value.len() < 4 {
                    return None;
                }
                PathAttribute::NextHop(Ipv4Addr::new(value[0], value[1], value[2], value[3]))
            }
            Self::MED => PathAttribute::MultiExitDisc(read_u32(value)?),
            Self::LOCAL_PREF => PathAttribute::LocalPref(read_u32(value)?),
            Self::ATOMIC_AGGREGATE => PathAttribute::AtomicAggregate,
            Self::COMMUNITIES => {
                if value.len() % 4 != 0 {
                    return None;
                }
                let comms = value
                    .chunks_exact(4)
                    .map(|c| u32::from_be_bytes([c[0], c[1], c[2], c[3]]))
                    .collect();
                PathAttribute::Communities(comms)
            }
            Self::EXTENDED_COMMUNITIES => {
                if value.len() % 8 != 0 {
                    return None;
                }
                let comms = value
                    .chunks_exact(8)
                    .map(|c| {
                        let mut a = [0u8; 8];
                        a.copy_from_slice(c);
                        a
                    })
                    .collect();
                PathAttribute::ExtendedCommunities(comms)
            }
            Self::LARGE_COMMUNITIES => {
                if value.len() % 12 != 0 {
                    return None;
                }
                let comms = value
                    .chunks_exact(12)
                    .map(|c| {
                        (
                            u32::from_be_bytes([c[0], c[1], c[2], c[3]]),
                            u32::from_be_bytes([c[4], c[5], c[6], c[7]]),
                            u32::from_be_bytes([c[8], c[9], c[10], c[11]]),
                        )
                    })
                    .collect();
                PathAttribute::LargeCommunities(comms)
            }
            Self::MP_REACH_NLRI => {
                // AFI(2) · SAFI(1) · NHLen(1) · NextHop(NHLen) · Reserved(1) · NLRI.
                if value.len() < 5 {
                    return None;
                }
                let afi = u16::from_be_bytes([value[0], value[1]]);
                let safi = value[2];
                let nh_len = value[3] as usize;
                let nh_end = 4 + nh_len;
                if value.len() < nh_end + 1 {
                    return None;
                }
                let next_hop = value[4..nh_end].to_vec();
                // value[nh_end] is the Reserved octet.
                let nlri = decode_mp_prefixes(&value[nh_end + 1..], afi)?;
                PathAttribute::MpReachNlri { afi, safi, next_hop, nlri }
            }
            Self::MP_UNREACH_NLRI => {
                if value.len() < 3 {
                    return None;
                }
                let afi = u16::from_be_bytes([value[0], value[1]]);
                let safi = value[2];
                let withdrawn = decode_mp_prefixes(&value[3..], afi)?;
                PathAttribute::MpUnreachNlri { afi, safi, withdrawn }
            }
            Self::ORIGINATOR_ID => {
                if value.len() < 4 {
                    return None;
                }
                PathAttribute::OriginatorId(Ipv4Addr::new(value[0], value[1], value[2], value[3]))
            }
            Self::CLUSTER_LIST => {
                if value.len() % 4 != 0 {
                    return None;
                }
                let ids = value
                    .chunks_exact(4)
                    .map(|c| Ipv4Addr::new(c[0], c[1], c[2], c[3]))
                    .collect();
                PathAttribute::ClusterList(ids)
            }
            Self::AGGREGATOR => {
                let (asn, id) = decode_aggregator(value, four_octet)?;
                PathAttribute::Aggregator { asn, id }
            }
            Self::AS4_AGGREGATOR => {
                let (asn, id) = decode_aggregator(value, true)?;
                PathAttribute::As4Aggregator { asn, id }
            }
            _ => PathAttribute::Unknown {
                flags,
                type_code,
                value: value.to_vec(),
            },
        };
        Some((attr, end))
    }
}

fn read_u32(b: &[u8]) -> Option<u32> {
    if b.len() < 4 {
        return None;
    }
    Some(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
}

/// Decode a run of MP-BGP NLRI prefixes for the given address family (RFC 4760):
/// IPv6 for [`AFI_IPV6`], IPv4 otherwise.
fn decode_mp_prefixes(buf: &[u8], afi: u16) -> Option<Vec<Prefix>> {
    let mut out = Vec::new();
    let mut off = 0;
    while off < buf.len() {
        let (p, used) = if afi == AFI_IPV6 {
            decode_prefix_v6(&buf[off..])?
        } else {
            decode_prefix(&buf[off..])?
        };
        out.push(p);
        off += used;
    }
    Some(out)
}

/// Decode a whole AS_PATH / AS4_PATH value (a run of segments) at the given width.
fn decode_as_segments(value: &[u8], four_octet: bool) -> Option<Vec<AsPathSegment>> {
    let mut segs = Vec::new();
    let mut off = 0;
    while off < value.len() {
        let (seg, used) = AsPathSegment::decode(&value[off..], four_octet)?;
        segs.push(seg);
        off += used;
    }
    Some(segs)
}

/// Decode an AGGREGATOR / AS4_AGGREGATOR value: a 2- or 4-octet AS followed by the
/// 4-octet BGP identifier.
fn decode_aggregator(value: &[u8], four_octet: bool) -> Option<(u32, Ipv4Addr)> {
    let asn_len = if four_octet { 4 } else { 2 };
    if value.len() < asn_len + 4 {
        return None;
    }
    let asn = if four_octet {
        u32::from_be_bytes([value[0], value[1], value[2], value[3]])
    } else {
        u16::from_be_bytes([value[0], value[1]]) as u32
    };
    let id = Ipv4Addr::new(
        value[asn_len],
        value[asn_len + 1],
        value[asn_len + 2],
        value[asn_len + 3],
    );
    Some((asn, id))
}

/// Reconstruct the true AS_PATH from the 2-octet `as_path` and an `as4_path`
/// received from a legacy speaker (RFC 6793 §4.2.3).
///
/// The 2-octet `as_path` may carry [`crate::AS_TRANS`] placeholders for any AS
/// that did not fit; the optional transitive `as4_path` carries those real
/// 4-octet ASes. When `as4_path` is at least as long as `as_path` would have it,
/// the trailing AS4_PATH replaces the equivalent tail of AS_PATH; if AS4_PATH is
/// *longer* than AS_PATH (it cannot describe more hops than were traversed) it is
/// ignored and `as_path` is returned unchanged.
pub fn reconstruct_as_path(
    as_path: &[AsPathSegment],
    as4_path: &[AsPathSegment],
) -> Vec<AsPathSegment> {
    // Flatten each path to a list of "elements": one per AS in a sequence, one per
    // whole set (a set is atomic and counts as a single AS per §9.1.2.2).
    let flat = |segs: &[AsPathSegment]| -> Vec<Element> {
        let mut els = Vec::new();
        for seg in segs {
            match seg {
                AsPathSegment::Sequence(asns) => els.extend(asns.iter().map(|&a| Element::As(a))),
                AsPathSegment::Set(asns) => els.push(Element::Set(asns.clone())),
            }
        }
        els
    };

    if as4_path.is_empty() {
        return as_path.to_vec();
    }
    let path = flat(as_path);
    let path4 = flat(as4_path);
    if path4.len() > path.len() {
        return as_path.to_vec();
    }
    let keep = path.len() - path4.len();
    let mut merged: Vec<Element> = path[..keep].to_vec();
    merged.extend(path4);
    coalesce(&merged)
}

/// An AS_PATH element used while merging: a single AS or a whole (atomic) set.
#[derive(Clone)]
enum Element {
    As(u32),
    Set(Vec<u32>),
}

/// Rebuild segments from a flat element list, coalescing runs of single ASes into
/// one Sequence segment.
fn coalesce(els: &[Element]) -> Vec<AsPathSegment> {
    let mut out = Vec::new();
    let mut run: Vec<u32> = Vec::new();
    for el in els {
        match el {
            Element::As(a) => run.push(*a),
            Element::Set(s) => {
                if !run.is_empty() {
                    out.push(AsPathSegment::Sequence(std::mem::take(&mut run)));
                }
                out.push(AsPathSegment::Set(s.clone()));
            }
        }
    }
    if !run.is_empty() {
        out.push(AsPathSegment::Sequence(run));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(o: [u8; 4]) -> Ipv4Addr {
        Ipv4Addr::from(o)
    }

    /// Round-trip an attribute at the given on-wire AS width.
    fn roundtrip_w(attr: PathAttribute, four_octet: bool) {
        let mut buf = Vec::new();
        attr.encode(&mut buf, four_octet);
        let (decoded, used) = PathAttribute::decode(&buf, four_octet).expect("decodes");
        assert_eq!(decoded, attr);
        assert_eq!(used, buf.len());
    }

    /// Round-trip an attribute whose width does not matter, at both widths.
    fn roundtrip(attr: PathAttribute) {
        roundtrip_w(attr.clone(), true);
        roundtrip_w(attr, false);
    }

    #[test]
    fn origin_roundtrips() {
        for o in [Origin::Igp, Origin::Egp, Origin::Incomplete] {
            assert_eq!(Origin::from_u8(o.as_u8()), Some(o));
            roundtrip(PathAttribute::Origin(o));
        }
        assert_eq!(Origin::from_u8(3), None);
    }

    #[test]
    fn as_path_roundtrips_sets_and_sequences() {
        // Two-octet-range ASes survive both widths intact.
        roundtrip(PathAttribute::AsPath(vec![
            AsPathSegment::Sequence(vec![65001, 65002, 65003]),
            AsPathSegment::Set(vec![65010, 65011]),
        ]));
        roundtrip(PathAttribute::AsPath(vec![])); // empty path (iBGP-originated)
    }

    #[test]
    fn four_octet_as_path_roundtrips_at_full_width() {
        // ASes beyond 65535 only survive the 4-octet encoding.
        roundtrip_w(
            PathAttribute::AsPath(vec![AsPathSegment::Sequence(vec![196_618, 65001, 4_200_000_000])]),
            true,
        );
    }

    #[test]
    fn two_octet_encoding_substitutes_as_trans() {
        // Toward a legacy peer a 4-octet AS becomes AS_TRANS on the wire.
        let attr = PathAttribute::AsPath(vec![AsPathSegment::Sequence(vec![196_618, 65001])]);
        let mut buf = Vec::new();
        attr.encode(&mut buf, false);
        let (decoded, _) = PathAttribute::decode(&buf, false).unwrap();
        assert_eq!(
            decoded,
            PathAttribute::AsPath(vec![AsPathSegment::Sequence(vec![
                crate::AS_TRANS as u32,
                65001
            ])])
        );
    }

    #[test]
    fn as4_path_and_as4_aggregator_are_always_four_octet() {
        // AS4_* ignore the session width — encode/decode them at both, identically.
        let p = PathAttribute::As4Path(vec![AsPathSegment::Sequence(vec![196_618, 4_200_000_000])]);
        roundtrip_w(p.clone(), false);
        roundtrip_w(p, true);
        let agg = PathAttribute::As4Aggregator { asn: 196_618, id: ip([10, 0, 0, 1]) };
        roundtrip_w(agg.clone(), false);
        roundtrip_w(agg, true);
    }

    #[test]
    fn well_known_attributes_roundtrip() {
        roundtrip(PathAttribute::NextHop(ip([192, 0, 2, 1])));
        roundtrip(PathAttribute::MultiExitDisc(100));
        roundtrip(PathAttribute::LocalPref(150));
        roundtrip(PathAttribute::AtomicAggregate);
        // A 2-octet-range aggregator AS survives both widths.
        roundtrip(PathAttribute::Aggregator { asn: 65001, id: ip([10, 0, 0, 1]) });
        // A 4-octet aggregator AS only survives the 4-octet width.
        roundtrip_w(PathAttribute::Aggregator { asn: 196_618, id: ip([10, 0, 0, 1]) }, true);
    }

    #[test]
    fn flags_are_canonical() {
        let mut buf = Vec::new();
        PathAttribute::Origin(Origin::Igp).encode(&mut buf, true);
        assert_eq!(buf[0], FLAG_TRANSITIVE); // well-known transitive
        assert_eq!(buf[1], 1); // ORIGIN

        let mut buf = Vec::new();
        PathAttribute::MultiExitDisc(5).encode(&mut buf, true);
        assert_eq!(buf[0], FLAG_OPTIONAL); // optional non-transitive
        assert_eq!(buf[1], 4);

        let mut buf = Vec::new();
        PathAttribute::Aggregator { asn: 1, id: ip([1, 2, 3, 4]) }.encode(&mut buf, true);
        assert_eq!(buf[0], FLAG_OPTIONAL | FLAG_TRANSITIVE);

        let mut buf = Vec::new();
        PathAttribute::As4Path(vec![]).encode(&mut buf, true);
        assert_eq!(buf[0], FLAG_OPTIONAL | FLAG_TRANSITIVE);
        assert_eq!(buf[1], 17); // AS4_PATH
    }

    #[test]
    fn communities_roundtrip() {
        use crate::community::{NO_EXPORT, NO_ADVERTISE};
        roundtrip(PathAttribute::Communities(vec![0xFDE9_0064, NO_EXPORT, NO_ADVERTISE]));
        roundtrip(PathAttribute::Communities(vec![])); // empty list is legal
    }

    #[test]
    fn large_communities_roundtrip() {
        roundtrip(PathAttribute::LargeCommunities(vec![
            (65536, 1, 2),
            (4_200_000_000, 4_294_967_295, 0),
        ]));
        roundtrip(PathAttribute::LargeCommunities(vec![])); // empty list is legal
    }

    #[test]
    fn extended_communities_roundtrip() {
        roundtrip(PathAttribute::ExtendedCommunities(vec![
            [0x00, 0x02, 0xFD, 0xE9, 0x00, 0x00, 0x00, 0x64], // rt:65001:100
            [0x02, 0x03, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01], // ro:65536:1
        ]));
        roundtrip(PathAttribute::ExtendedCommunities(vec![])); // empty list is legal
        // Flags are optional-transitive, type 8.
        let mut buf = Vec::new();
        PathAttribute::Communities(vec![1]).encode(&mut buf, true);
        assert_eq!(buf[0], FLAG_OPTIONAL | FLAG_TRANSITIVE);
        assert_eq!(buf[1], 8);
    }

    fn p(s: &str) -> Prefix {
        s.parse().unwrap()
    }

    #[test]
    fn mp_reach_nlri_roundtrips_ipv6_unicast() {
        use crate::{AFI_IPV6, SAFI_UNICAST};
        // A 16-octet IPv6 global next hop and two IPv6 prefixes.
        let attr = PathAttribute::MpReachNlri {
            afi: AFI_IPV6,
            safi: SAFI_UNICAST,
            next_hop: std::net::Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1).octets().to_vec(),
            nlri: vec![p("2001:db8:99::/64"), p("2001:db8:a::/48")],
        };
        roundtrip(attr.clone());
        // Optional non-transitive, type 14.
        let mut buf = Vec::new();
        attr.encode(&mut buf, true);
        assert_eq!(buf[0], FLAG_OPTIONAL);
        assert_eq!(buf[1], 14);
    }

    #[test]
    fn mp_reach_nlri_carries_a_linklocal_next_hop() {
        use crate::{AFI_IPV6, SAFI_UNICAST};
        // RFC 2545: a 32-octet next hop is global + link-local.
        let mut nh = std::net::Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1).octets().to_vec();
        nh.extend_from_slice(&std::net::Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1).octets());
        roundtrip(PathAttribute::MpReachNlri {
            afi: AFI_IPV6,
            safi: SAFI_UNICAST,
            next_hop: nh,
            nlri: vec![p("2001:db8::/32")],
        });
    }

    #[test]
    fn mp_unreach_nlri_roundtrips_ipv6_withdrawals() {
        use crate::{AFI_IPV6, SAFI_UNICAST};
        let attr = PathAttribute::MpUnreachNlri {
            afi: AFI_IPV6,
            safi: SAFI_UNICAST,
            withdrawn: vec![p("2001:db8:99::/64"), p("2001:db8::1/128")],
        };
        roundtrip(attr.clone());
        let mut buf = Vec::new();
        attr.encode(&mut buf, true);
        assert_eq!(buf[0], FLAG_OPTIONAL);
        assert_eq!(buf[1], 15);
        // An empty withdrawal (end-of-RIB-ish) is legal too.
        roundtrip(PathAttribute::MpUnreachNlri {
            afi: AFI_IPV6,
            safi: SAFI_UNICAST,
            withdrawn: vec![],
        });
    }

    #[test]
    fn originator_id_and_cluster_list_roundtrip() {
        let oid = PathAttribute::OriginatorId(ip([10, 0, 0, 1]));
        roundtrip(oid.clone());
        let mut buf = Vec::new();
        oid.encode(&mut buf, true);
        assert_eq!(buf[0], FLAG_OPTIONAL); // optional non-transitive
        assert_eq!(buf[1], 9);

        let cl = PathAttribute::ClusterList(vec![ip([1, 1, 1, 1]), ip([2, 2, 2, 2])]);
        roundtrip(cl.clone());
        let mut buf = Vec::new();
        cl.encode(&mut buf, true);
        assert_eq!(buf[0], FLAG_OPTIONAL);
        assert_eq!(buf[1], 10);
        // An empty cluster list is legal; a non-multiple-of-4 value is rejected.
        roundtrip(PathAttribute::ClusterList(vec![]));
        assert!(PathAttribute::decode(&[0x80, 10, 3, 1, 2, 3], true).is_none());
    }

    #[test]
    fn communities_reject_non_multiple_of_four() {
        // 8,len=3,[..] — a COMMUNITIES value not a multiple of 4 octets.
        assert!(PathAttribute::decode(&[0xC0, 8, 3, 1, 2, 3], true).is_none());
    }

    #[test]
    fn unknown_attribute_is_preserved() {
        let raw = PathAttribute::Unknown {
            flags: FLAG_OPTIONAL | FLAG_TRANSITIVE,
            type_code: 99,
            value: vec![1, 2, 3, 4, 5],
        };
        roundtrip(raw);
    }

    #[test]
    fn extended_length_used_for_long_values() {
        // A long AS_PATH forces the extended-length encoding (>255 value bytes).
        let big: Vec<u32> = (0..200).collect();
        let attr = PathAttribute::AsPath(vec![AsPathSegment::Sequence(big)]);
        let mut buf = Vec::new();
        attr.encode(&mut buf, true);
        assert_ne!(buf[0] & FLAG_EXTENDED_LEN, 0, "extended-length flag set");
        let (decoded, used) = PathAttribute::decode(&buf, true).unwrap();
        assert_eq!(decoded, attr);
        assert_eq!(used, buf.len());
    }

    #[test]
    fn reconstruct_replaces_as_trans_tail_with_as4_path() {
        // AS_PATH from a legacy peer: real ASes then AS_TRANS for the 4-octet hops.
        let as_path = vec![AsPathSegment::Sequence(vec![
            100,
            200,
            crate::AS_TRANS as u32,
            crate::AS_TRANS as u32,
        ])];
        let as4_path = vec![AsPathSegment::Sequence(vec![70_000, 80_000])];
        assert_eq!(
            reconstruct_as_path(&as_path, &as4_path),
            vec![AsPathSegment::Sequence(vec![100, 200, 70_000, 80_000])]
        );
    }

    #[test]
    fn reconstruct_ignores_as4_path_longer_than_as_path() {
        let as_path = vec![AsPathSegment::Sequence(vec![100, 200])];
        let as4_path = vec![AsPathSegment::Sequence(vec![70_000, 80_000, 90_000])];
        // AS4_PATH cannot describe more hops than AS_PATH → ignored.
        assert_eq!(reconstruct_as_path(&as_path, &as4_path), as_path);
        // No AS4_PATH at all → AS_PATH unchanged.
        assert_eq!(reconstruct_as_path(&as_path, &[]), as_path);
    }

    #[test]
    fn reconstruct_preserves_a_leading_set() {
        // A set counts as one element and stays atomic across the merge.
        let as_path = vec![
            AsPathSegment::Set(vec![500, 501]),
            AsPathSegment::Sequence(vec![100, crate::AS_TRANS as u32]),
        ];
        let as4_path = vec![AsPathSegment::Sequence(vec![70_000])];
        // N = 3 (set + 2), M = 1 → keep first 2 elements (set, 100), append 70000.
        assert_eq!(
            reconstruct_as_path(&as_path, &as4_path),
            vec![
                AsPathSegment::Set(vec![500, 501]),
                AsPathSegment::Sequence(vec![100, 70_000]),
            ]
        );
    }
}
