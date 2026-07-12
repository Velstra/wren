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

use crate::evpn::{decode_evpn_nlris, encode_evpn_nlri, EvpnNlri, AFI_L2VPN, SAFI_EVPN};
use crate::flowspec::{decode_nlris as decode_flowspec_nlris, FlowSpec, SAFI_FLOWSPEC};
use crate::link_state::{
    decode_nlris as decode_ls_nlris, BgpLsAttribute, LinkStateNlri, AFI_LINK_STATE, SAFI_LINK_STATE,
};
use crate::sr_policy::{
    decode_nlris as decode_sr_policy_nlris, decode_tunnel_encap, encode_tunnel_encap, SrPolicyNlri,
    TunnelTlv, SAFI_SR_POLICY,
};
use crate::srv6::{decode_prefix_sid, encode_srv6_service_tlv, Srv6ServiceTlv};
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
    /// An ordered sequence of Member-AS numbers a route has traversed *within* a
    /// confederation (RFC 5065 §3, AS_CONFED_SEQUENCE). Stripped before the route
    /// leaves the confederation, and not counted in AS_PATH length.
    ConfedSequence(Vec<u32>),
    /// An unordered set of Member-AS numbers within a confederation (RFC 5065 §3,
    /// AS_CONFED_SET). Like [`AsPathSegment::ConfedSequence`] but unordered.
    ConfedSet(Vec<u32>),
}

impl AsPathSegment {
    const SET: u8 = 1;
    const SEQUENCE: u8 = 2;
    const CONFED_SEQUENCE: u8 = 3;
    const CONFED_SET: u8 = 4;

    /// The ASes this segment carries (in order).
    pub fn asns(&self) -> &[u32] {
        match self {
            AsPathSegment::Set(a)
            | AsPathSegment::Sequence(a)
            | AsPathSegment::ConfedSequence(a)
            | AsPathSegment::ConfedSet(a) => a,
        }
    }

    /// Whether this is a confederation segment (AS_CONFED_SEQUENCE / AS_CONFED_SET),
    /// which is internal to a confederation: stripped on egress to a true eBGP peer
    /// and excluded from AS_PATH length.
    pub fn is_confederation(&self) -> bool {
        matches!(
            self,
            AsPathSegment::ConfedSequence(_) | AsPathSegment::ConfedSet(_)
        )
    }

    fn encode(&self, out: &mut Vec<u8>, four_octet: bool) {
        let (kind, asns) = match self {
            AsPathSegment::Set(a) => (Self::SET, a),
            AsPathSegment::Sequence(a) => (Self::SEQUENCE, a),
            AsPathSegment::ConfedSequence(a) => (Self::CONFED_SEQUENCE, a),
            AsPathSegment::ConfedSet(a) => (Self::CONFED_SET, a),
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
            Self::CONFED_SEQUENCE => AsPathSegment::ConfedSequence(asns),
            Self::CONFED_SET => AsPathSegment::ConfedSet(asns),
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
    /// MP_REACH_NLRI carrying EVPN routes (AFI 25 / SAFI 70, RFC 7432 §7) — a
    /// separate variant because EVPN NLRI are not IP prefixes.
    MpReachEvpn {
        /// The next hop: the advertising VTEP's address, 4 (IPv4) or 16 (IPv6)
        /// raw octets.
        next_hop: Vec<u8>,
        /// The EVPN routes being advertised.
        nlri: Vec<EvpnNlri>,
    },
    /// MP_UNREACH_NLRI carrying EVPN withdrawals (AFI 25 / SAFI 70).
    MpUnreachEvpn {
        /// The EVPN routes being withdrawn.
        withdrawn: Vec<EvpnNlri>,
    },
    /// MP_REACH_NLRI carrying FlowSpec rules (AFI 1/2 · SAFI 133, RFC 8955 §4) — a
    /// separate variant because FlowSpec NLRI are flow specifications, not IP
    /// prefixes. The traffic-filtering action rides as an extended community on the
    /// same UPDATE (§7), so it is not part of the NLRI.
    MpReachFlowSpec {
        /// The Address Family Identifier: [`crate::AFI_IPV4`] or [`crate::AFI_IPV6`].
        afi: u16,
        /// The next hop, raw octets. FlowSpec does not route to a next hop
        /// (RFC 8955 §4 says it is ignored); originators send it empty.
        next_hop: Vec<u8>,
        /// The flow rules being advertised.
        nlri: Vec<FlowSpec>,
    },
    /// MP_UNREACH_NLRI carrying FlowSpec withdrawals (AFI 1/2 · SAFI 133).
    MpUnreachFlowSpec {
        /// The Address Family Identifier the rules belong to.
        afi: u16,
        /// The flow rules being withdrawn.
        withdrawn: Vec<FlowSpec>,
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
    /// BGP Prefix-SID (type 40, optional transitive) — carries Segment Routing
    /// SIDs for a route (RFC 8669 / RFC 9252). We model the SRv6 L2/L3 Service
    /// TLVs (the overlay service SIDs) and keep any other top-level TLV verbatim
    /// so a route reflector re-advertises it intact.
    PrefixSid {
        /// The SRv6 Service TLVs (L2 = type 6, L3 = type 5).
        srv6: Vec<Srv6ServiceTlv>,
        /// Top-level TLVs we don't model (e.g. MPLS-SR Label-Index / SRGB),
        /// preserved as `(type, value)` for faithful re-advertisement.
        other: Vec<(u8, Vec<u8>)>,
    },
    /// MP_REACH_NLRI carrying SR Policy candidate paths (SAFI 73,
    /// draft-ietf-idr-segment-routing-te-policy) — a separate variant because SR
    /// Policy NLRI are `(distinguisher, colour, endpoint)` tuples, not IP prefixes.
    /// The candidate contents ride in the Tunnel Encapsulation attribute (type 23)
    /// on the same UPDATE.
    MpReachSrPolicy {
        /// The Address Family Identifier of the endpoint: IPv4 or IPv6.
        afi: u16,
        /// The next hop, raw octets (4 or 16) — ignored for SR Policy but carried.
        next_hop: Vec<u8>,
        /// The SR Policy candidate-path NLRI being advertised.
        nlri: Vec<SrPolicyNlri>,
    },
    /// MP_UNREACH_NLRI carrying SR Policy withdrawals (SAFI 73).
    MpUnreachSrPolicy {
        /// The Address Family Identifier of the endpoint: IPv4 or IPv6.
        afi: u16,
        /// The SR Policy candidate-path NLRI being withdrawn.
        withdrawn: Vec<SrPolicyNlri>,
    },
    /// Tunnel Encapsulation (type 23, optional transitive, RFC 9012) — a set of
    /// tunnel TLVs. Used here to carry the SR Policy (Tunnel-Type 15) contents of
    /// an SR Policy route; other tunnel types are kept opaque.
    TunnelEncap(Vec<TunnelTlv>),
    /// Only-To-Customer (OTC, type 35, optional transitive) — the RFC 9234 §4.1
    /// route-leak-prevention marker, carrying the AS number that first set it. A
    /// route bearing OTC must not be advertised to a Provider, Peer or RS (§5).
    OnlyToCustomer(u32),
    /// MP_REACH_NLRI carrying BGP-LS Link-State NLRI (AFI 16388 / SAFI 71,
    /// RFC 7752) — a separate variant because Link-State NLRI are node/link/prefix
    /// objects, not IP prefixes. Each object's attributes ride in the BGP-LS
    /// Attribute (type 29) on the same UPDATE.
    MpReachLinkState {
        /// The next hop, raw octets (4 or 16).
        next_hop: Vec<u8>,
        /// The Link-State objects being advertised.
        nlri: Vec<LinkStateNlri>,
    },
    /// MP_UNREACH_NLRI carrying BGP-LS withdrawals (AFI 16388 / SAFI 71).
    MpUnreachLinkState {
        /// The Link-State objects being withdrawn.
        withdrawn: Vec<LinkStateNlri>,
    },
    /// BGP-LS Attribute (type 29, optional non-transitive, RFC 7752 §3.3) — the
    /// node / link / prefix attribute TLVs of a Link-State object.
    BgpLs(BgpLsAttribute),
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
    const BGP_LS: u8 = 29;
    const LARGE_COMMUNITIES: u8 = 32;
    const TUNNEL_ENCAP: u8 = 23;
    const ONLY_TO_CUSTOMER: u8 = 35;
    const PREFIX_SID: u8 = 40;

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
            PathAttribute::MpReachNlri { .. }
            | PathAttribute::MpReachEvpn { .. }
            | PathAttribute::MpReachFlowSpec { .. }
            | PathAttribute::MpReachSrPolicy { .. }
            | PathAttribute::MpReachLinkState { .. } => Self::MP_REACH_NLRI,
            PathAttribute::MpUnreachNlri { .. }
            | PathAttribute::MpUnreachEvpn { .. }
            | PathAttribute::MpUnreachFlowSpec { .. }
            | PathAttribute::MpUnreachSrPolicy { .. }
            | PathAttribute::MpUnreachLinkState { .. } => Self::MP_UNREACH_NLRI,
            PathAttribute::OriginatorId(_) => Self::ORIGINATOR_ID,
            PathAttribute::ClusterList(_) => Self::CLUSTER_LIST,
            PathAttribute::LargeCommunities(_) => Self::LARGE_COMMUNITIES,
            PathAttribute::As4Path(_) => Self::AS4_PATH,
            PathAttribute::As4Aggregator { .. } => Self::AS4_AGGREGATOR,
            PathAttribute::PrefixSid { .. } => Self::PREFIX_SID,
            PathAttribute::TunnelEncap(_) => Self::TUNNEL_ENCAP,
            PathAttribute::OnlyToCustomer(_) => Self::ONLY_TO_CUSTOMER,
            PathAttribute::BgpLs(_) => Self::BGP_LS,
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
            | PathAttribute::MpReachEvpn { .. }
            | PathAttribute::MpUnreachEvpn { .. }
            | PathAttribute::MpReachFlowSpec { .. }
            | PathAttribute::MpUnreachFlowSpec { .. }
            | PathAttribute::MpReachSrPolicy { .. }
            | PathAttribute::MpUnreachSrPolicy { .. }
            | PathAttribute::MpReachLinkState { .. }
            | PathAttribute::MpUnreachLinkState { .. }
            | PathAttribute::BgpLs(_)
            | PathAttribute::OriginatorId(_)
            | PathAttribute::ClusterList(_) => FLAG_OPTIONAL,
            PathAttribute::Aggregator { .. }
            | PathAttribute::Communities(_)
            | PathAttribute::ExtendedCommunities(_)
            | PathAttribute::LargeCommunities(_)
            | PathAttribute::As4Path(_)
            | PathAttribute::As4Aggregator { .. }
            | PathAttribute::PrefixSid { .. }
            | PathAttribute::TunnelEncap(_)
            | PathAttribute::OnlyToCustomer(_) => FLAG_OPTIONAL | FLAG_TRANSITIVE,
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
            PathAttribute::MpReachEvpn { next_hop, nlri } => {
                out.extend_from_slice(&AFI_L2VPN.to_be_bytes());
                out.push(SAFI_EVPN);
                out.push(next_hop.len() as u8);
                out.extend_from_slice(next_hop);
                out.push(0); // Reserved (SNPA count, unused)
                for n in nlri {
                    encode_evpn_nlri(out, n);
                }
            }
            PathAttribute::MpUnreachEvpn { withdrawn } => {
                out.extend_from_slice(&AFI_L2VPN.to_be_bytes());
                out.push(SAFI_EVPN);
                for n in withdrawn {
                    encode_evpn_nlri(out, n);
                }
            }
            PathAttribute::MpReachFlowSpec { afi, next_hop, nlri } => {
                out.extend_from_slice(&afi.to_be_bytes());
                out.push(SAFI_FLOWSPEC);
                out.push(next_hop.len() as u8);
                out.extend_from_slice(next_hop);
                out.push(0); // Reserved (SNPA count, unused)
                for n in nlri {
                    n.encode(out);
                }
            }
            PathAttribute::MpUnreachFlowSpec { afi, withdrawn } => {
                out.extend_from_slice(&afi.to_be_bytes());
                out.push(SAFI_FLOWSPEC);
                for n in withdrawn {
                    n.encode(out);
                }
            }
            PathAttribute::MpReachSrPolicy { afi, next_hop, nlri } => {
                out.extend_from_slice(&afi.to_be_bytes());
                out.push(SAFI_SR_POLICY);
                out.push(next_hop.len() as u8);
                out.extend_from_slice(next_hop);
                out.push(0); // Reserved (SNPA count, unused)
                for n in nlri {
                    n.encode(out);
                }
            }
            PathAttribute::MpUnreachSrPolicy { afi, withdrawn } => {
                out.extend_from_slice(&afi.to_be_bytes());
                out.push(SAFI_SR_POLICY);
                for n in withdrawn {
                    n.encode(out);
                }
            }
            PathAttribute::TunnelEncap(tlvs) => out.extend_from_slice(&encode_tunnel_encap(tlvs)),
            PathAttribute::MpReachLinkState { next_hop, nlri } => {
                out.extend_from_slice(&AFI_LINK_STATE.to_be_bytes());
                out.push(SAFI_LINK_STATE);
                out.push(next_hop.len() as u8);
                out.extend_from_slice(next_hop);
                out.push(0); // Reserved (SNPA count, unused)
                for n in nlri {
                    n.encode(out);
                }
            }
            PathAttribute::MpUnreachLinkState { withdrawn } => {
                out.extend_from_slice(&AFI_LINK_STATE.to_be_bytes());
                out.push(SAFI_LINK_STATE);
                for n in withdrawn {
                    n.encode(out);
                }
            }
            PathAttribute::BgpLs(attr) => attr.encode(out),
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
            PathAttribute::PrefixSid { srv6, other } => {
                for tlv in srv6 {
                    encode_srv6_service_tlv(out, tlv);
                }
                for (t, v) in other {
                    out.push(*t);
                    out.extend_from_slice(&(v.len() as u16).to_be_bytes());
                    out.extend_from_slice(v);
                }
            }
            PathAttribute::OnlyToCustomer(asn) => out.extend_from_slice(&asn.to_be_bytes()),
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
                // RFC 4271 §4.3 / RFC 7606 §5: ORIGIN is a fixed 1-octet attribute.
                if value.len() != 1 {
                    return None;
                }
                let o = Origin::from_u8(value[0])?;
                PathAttribute::Origin(o)
            }
            Self::AS_PATH => PathAttribute::AsPath(decode_as_segments(value, four_octet)?),
            Self::AS4_PATH => PathAttribute::As4Path(decode_as_segments(value, true)?),
            Self::NEXT_HOP => {
                // RFC 7606 §5: NEXT_HOP is exactly 4 octets — an over-long value is
                // malformed, not silently truncated to its first four bytes.
                if value.len() != 4 {
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
                if afi == AFI_L2VPN && safi == SAFI_EVPN {
                    let nlri = decode_evpn_nlris(&value[nh_end + 1..])?;
                    PathAttribute::MpReachEvpn { next_hop, nlri }
                } else if safi == SAFI_FLOWSPEC {
                    let nlri = decode_flowspec_nlris(&value[nh_end + 1..])?;
                    PathAttribute::MpReachFlowSpec { afi, next_hop, nlri }
                } else if safi == SAFI_SR_POLICY {
                    let nlri = decode_sr_policy_nlris(&value[nh_end + 1..], afi)?;
                    PathAttribute::MpReachSrPolicy { afi, next_hop, nlri }
                } else if afi == AFI_LINK_STATE && safi == SAFI_LINK_STATE {
                    let nlri = decode_ls_nlris(&value[nh_end + 1..])?;
                    PathAttribute::MpReachLinkState { next_hop, nlri }
                } else {
                    let nlri = decode_mp_prefixes(&value[nh_end + 1..], afi)?;
                    PathAttribute::MpReachNlri { afi, safi, next_hop, nlri }
                }
            }
            Self::MP_UNREACH_NLRI => {
                if value.len() < 3 {
                    return None;
                }
                let afi = u16::from_be_bytes([value[0], value[1]]);
                let safi = value[2];
                if afi == AFI_L2VPN && safi == SAFI_EVPN {
                    let withdrawn = decode_evpn_nlris(&value[3..])?;
                    PathAttribute::MpUnreachEvpn { withdrawn }
                } else if safi == SAFI_FLOWSPEC {
                    let withdrawn = decode_flowspec_nlris(&value[3..])?;
                    PathAttribute::MpUnreachFlowSpec { afi, withdrawn }
                } else if safi == SAFI_SR_POLICY {
                    let withdrawn = decode_sr_policy_nlris(&value[3..], afi)?;
                    PathAttribute::MpUnreachSrPolicy { afi, withdrawn }
                } else if afi == AFI_LINK_STATE && safi == SAFI_LINK_STATE {
                    let withdrawn = decode_ls_nlris(&value[3..])?;
                    PathAttribute::MpUnreachLinkState { withdrawn }
                } else {
                    let withdrawn = decode_mp_prefixes(&value[3..], afi)?;
                    PathAttribute::MpUnreachNlri { afi, safi, withdrawn }
                }
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
            Self::ONLY_TO_CUSTOMER => PathAttribute::OnlyToCustomer(read_u32(value)?),
            Self::TUNNEL_ENCAP => match decode_tunnel_encap(value) {
                Some(tlvs) => PathAttribute::TunnelEncap(tlvs),
                // A malformed Tunnel Encapsulation attribute is optional-transitive:
                // keep it opaque (RFC 7606) rather than failing the UPDATE.
                None => PathAttribute::Unknown {
                    flags,
                    type_code,
                    value: value.to_vec(),
                },
            },
            Self::BGP_LS => match BgpLsAttribute::decode(value) {
                Some(attr) => PathAttribute::BgpLs(attr),
                // A malformed BGP-LS attribute is optional non-transitive: keep it
                // opaque (RFC 7606) rather than failing the UPDATE.
                None => PathAttribute::Unknown {
                    flags,
                    type_code,
                    value: value.to_vec(),
                },
            },
            Self::PREFIX_SID => match decode_prefix_sid(value) {
                Some((srv6, other)) => PathAttribute::PrefixSid { srv6, other },
                // A malformed Prefix-SID is optional-transitive: keep it opaque
                // (RFC 7606 attribute-discard) rather than failing the UPDATE.
                None => PathAttribute::Unknown {
                    flags,
                    type_code,
                    value: value.to_vec(),
                },
            },
            _ => PathAttribute::Unknown {
                flags,
                type_code,
                value: value.to_vec(),
            },
        };
        // RFC 7606 §4: validate the attribute flags against the canonical value
        // for this (known) attribute. The Optional and Transitive bits must match
        // exactly, and the Partial bit must be clear unless the attribute is
        // optional-transitive; the Extended-Length bit is free. Reject a mismatch
        // (e.g. an ORIGIN marked Optional, or a well-known attribute with the
        // Partial bit) instead of silently installing it. Unknown attributes carry
        // their received flags as their canonical value, so they always pass.
        let canonical = attr.canonical_flags();
        let defining = FLAG_OPTIONAL | FLAG_TRANSITIVE;
        if flags & defining != canonical & defining {
            return None;
        }
        let optional_transitive = canonical & defining == FLAG_OPTIONAL | FLAG_TRANSITIVE;
        if !optional_transitive && flags & FLAG_PARTIAL != 0 {
            return None;
        }
        Some((attr, end))
    }
}

fn read_u32(b: &[u8]) -> Option<u32> {
    // MED / LOCAL_PREF / OTC are all fixed 4-octet attributes (RFC 4271 §5, RFC
    // 9234); a value of any other length is malformed (RFC 7606 §5), not a u32
    // read from the first four bytes of an over-long field.
    if b.len() != 4 {
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
        // RFC 7607: AS 0 is reserved and must never appear in an AS_PATH /
        // AS4_PATH; reject the attribute (→ the UPDATE is treated as malformed)
        // rather than propagate a path routed through the reserved AS.
        if seg.asns().contains(&0) {
            return None;
        }
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
                // Confederation segments are internal and never appear in AS4_PATH;
                // carry them through verbatim so reconstruction preserves them.
                AsPathSegment::ConfedSequence(_) | AsPathSegment::ConfedSet(_) => {
                    els.push(Element::Confed(seg.clone()))
                }
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
    /// A whole confederation segment, carried through reconstruction verbatim.
    Confed(AsPathSegment),
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
            Element::Confed(seg) => {
                if !run.is_empty() {
                    out.push(AsPathSegment::Sequence(std::mem::take(&mut run)));
                }
                out.push(seg.clone());
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
    fn prefix_sid_srv6_roundtrips() {
        use crate::srv6::{behavior, build_service_sid, Srv6ServiceSid, Srv6ServiceTlv};
        let (sid, structure) = build_service_sid("fc00:0:1::".parse().unwrap(), 48, 0, 10100);
        let attr = PathAttribute::PrefixSid {
            srv6: vec![Srv6ServiceTlv {
                is_l2: true,
                sids: vec![Srv6ServiceSid {
                    sid,
                    behavior: behavior::END_DT2U,
                    flags: 0,
                    structure,
                }],
            }],
            other: vec![(3u8, vec![0u8; 5])],
        };
        roundtrip(attr);
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
    fn as_path_roundtrips_confederation_segments() {
        // AS_CONFED_SEQUENCE / AS_CONFED_SET (RFC 5065) survive the codec, mixed
        // with ordinary segments, at both widths.
        roundtrip(PathAttribute::AsPath(vec![
            AsPathSegment::ConfedSequence(vec![65001, 65002]),
            AsPathSegment::ConfedSet(vec![65003, 65004]),
            AsPathSegment::Sequence(vec![64500]),
        ]));
    }

    #[test]
    fn reconstruct_preserves_leading_confederation_segments() {
        // A confed segment at the front is carried through AS4_PATH reconstruction
        // verbatim while the real-AS tail is merged from AS4_PATH.
        let as_path = vec![
            AsPathSegment::ConfedSequence(vec![65001]),
            AsPathSegment::Sequence(vec![crate::AS_TRANS as u32, 64500]),
        ];
        let as4 = vec![AsPathSegment::Sequence(vec![196_618, 64500])];
        assert_eq!(
            reconstruct_as_path(&as_path, &as4),
            vec![
                AsPathSegment::ConfedSequence(vec![65001]),
                AsPathSegment::Sequence(vec![196_618, 64500]),
            ]
        );
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
    fn only_to_customer_roundtrips() {
        // RFC 9234 OTC: a 4-octet AS, optional transitive.
        roundtrip(PathAttribute::OnlyToCustomer(65001));
        roundtrip(PathAttribute::OnlyToCustomer(4_200_000_000));
        let mut buf = Vec::new();
        PathAttribute::OnlyToCustomer(65001).encode(&mut buf, true);
        assert_eq!(buf[0], FLAG_OPTIONAL | FLAG_TRANSITIVE);
        assert_eq!(buf[1], 35); // OTC type code
        assert_eq!(buf[2], 4); // length
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
    fn mp_reach_evpn_roundtrips() {
        use crate::evpn::{Esi, EvpnNlri, Rd};
        let attr = PathAttribute::MpReachEvpn {
            next_hop: std::net::Ipv4Addr::new(192, 0, 2, 1).octets().to_vec(),
            nlri: vec![
                EvpnNlri::MacIp {
                    rd: Rd::from_ip(std::net::Ipv4Addr::new(192, 0, 2, 1), 100),
                    esi: Esi::ZERO,
                    eth_tag: 0,
                    mac: [0x02, 0, 0x5e, 0x10, 0, 0x01],
                    ip: Some("10.0.0.5".parse().unwrap()),
                    label1: 10100,
                    label2: None,
                },
                EvpnNlri::Imet {
                    rd: Rd::from_ip(std::net::Ipv4Addr::new(192, 0, 2, 1), 100),
                    eth_tag: 0,
                    orig_ip: "192.0.2.1".parse().unwrap(),
                },
            ],
        };
        roundtrip(attr.clone());
        // Same wire type code (14) and flags as any other MP_REACH.
        let mut buf = Vec::new();
        attr.encode(&mut buf, true);
        assert_eq!(buf[0], FLAG_OPTIONAL);
        assert_eq!(buf[1], 14);
    }

    #[test]
    fn mp_unreach_evpn_roundtrips_including_empty() {
        use crate::evpn::{EvpnNlri, Rd};
        roundtrip(PathAttribute::MpUnreachEvpn {
            withdrawn: vec![EvpnNlri::Imet {
                rd: Rd::from_ip(std::net::Ipv4Addr::new(192, 0, 2, 1), 100),
                eth_tag: 0,
                orig_ip: "192.0.2.1".parse().unwrap(),
            }],
        });
        // The empty form is the EVPN End-of-RIB body.
        roundtrip(PathAttribute::MpUnreachEvpn { withdrawn: vec![] });
    }

    #[test]
    fn mp_reach_flowspec_roundtrips() {
        use crate::flowspec::{Component, FlowSpec, NumOp};
        use crate::AFI_IPV4;
        let spec = FlowSpec {
            components: vec![
                Component::DestPrefix("10.50.0.0/24".parse().unwrap()),
                Component::IpProto(vec![NumOp::eq(6)]),
                Component::DestPort(vec![NumOp::eq(22)]),
            ],
        };
        let attr = PathAttribute::MpReachFlowSpec {
            afi: AFI_IPV4,
            next_hop: vec![], // FlowSpec has no meaningful next hop (RFC 8955 §4)
            nlri: vec![spec],
        };
        roundtrip(attr.clone());
        // Same wire type code (14) and flags as any other MP_REACH.
        let mut buf = Vec::new();
        attr.encode(&mut buf, true);
        assert_eq!(buf[0], FLAG_OPTIONAL);
        assert_eq!(buf[1], 14);
    }

    #[test]
    fn mp_unreach_flowspec_roundtrips_including_empty() {
        use crate::flowspec::{Component, FlowSpec};
        use crate::AFI_IPV4;
        roundtrip(PathAttribute::MpUnreachFlowSpec {
            afi: AFI_IPV4,
            withdrawn: vec![FlowSpec {
                components: vec![Component::DestPrefix("10.50.0.0/24".parse().unwrap())],
            }],
        });
        roundtrip(PathAttribute::MpUnreachFlowSpec { afi: AFI_IPV4, withdrawn: vec![] });
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
    fn attribute_flags_are_validated_rfc7606() {
        // A canonical ORIGIN (well-known transitive) decodes; the same value with
        // the Optional bit set, or with the Partial bit set on a well-known
        // attribute, is rejected (RFC 7606 §4) instead of silently accepted.
        assert!(PathAttribute::decode(&[FLAG_TRANSITIVE, 1, 1, 0], true).is_some());
        assert!(PathAttribute::decode(&[FLAG_OPTIONAL | FLAG_TRANSITIVE, 1, 1, 0], true).is_none());
        assert!(PathAttribute::decode(&[FLAG_TRANSITIVE | FLAG_PARTIAL, 1, 1, 0], true).is_none());
        // NEXT_HOP (type 3) is well-known transitive: the Partial bit is illegal.
        assert!(PathAttribute::decode(&[FLAG_TRANSITIVE, 3, 4, 192, 0, 2, 1], true).is_some());
        assert!(
            PathAttribute::decode(&[FLAG_TRANSITIVE | FLAG_PARTIAL, 3, 4, 192, 0, 2, 1], true)
                .is_none()
        );
        // MED (type 4) is optional non-transitive: the Transitive bit is illegal.
        assert!(PathAttribute::decode(&[FLAG_OPTIONAL, 4, 4, 0, 0, 0, 5], true).is_some());
        assert!(
            PathAttribute::decode(&[FLAG_OPTIONAL | FLAG_TRANSITIVE, 4, 4, 0, 0, 0, 5], true)
                .is_none()
        );
    }

    #[test]
    fn as_path_with_as_zero_is_rejected_rfc7607() {
        // AS 0 is reserved and must not appear in an AS_PATH.
        let mut zero = Vec::new();
        PathAttribute::AsPath(vec![AsPathSegment::Sequence(vec![0])]).encode(&mut zero, true);
        assert!(PathAttribute::decode(&zero, true).is_none());
        // A normal AS_PATH still decodes.
        let mut ok = Vec::new();
        PathAttribute::AsPath(vec![AsPathSegment::Sequence(vec![65001])]).encode(&mut ok, true);
        assert!(PathAttribute::decode(&ok, true).is_some());
    }

    #[test]
    fn fixed_length_attributes_reject_wrong_length_rfc7606() {
        // ORIGIN is exactly 1 octet, NEXT_HOP exactly 4, MED/LOCAL_PREF exactly 4
        // (RFC 7606 §5). A longer value is malformed, not silently truncated.
        assert!(PathAttribute::decode(&[FLAG_TRANSITIVE, 1, 2, 0, 0], true).is_none()); // ORIGIN len 2
        assert!(
            PathAttribute::decode(&[FLAG_TRANSITIVE, 3, 5, 192, 0, 2, 1, 9], true).is_none()
        ); // NEXT_HOP len 5
        assert!(
            PathAttribute::decode(&[FLAG_OPTIONAL, 4, 5, 0, 0, 0, 5, 0], true).is_none()
        ); // MED len 5
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
        // ASes start at 1 — AS 0 is reserved and rejected by decode (RFC 7607).
        let big: Vec<u32> = (1..201).collect();
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
