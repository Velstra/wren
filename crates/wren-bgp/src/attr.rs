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
use crate::{
    as_trans_fit, decode_prefix, decode_prefix_v6, encode_prefix_any, AFI_IPV4, AFI_IPV6,
    SAFI_UNICAST,
};

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

/// What a decoded path attribute means for the UPDATE that carries it — the
/// error-handling categories of RFC 7606 §2, minus the two that never reach here.
///
/// [`PathAttribute::decode`] returns `None` for the third category,
/// "treat-as-withdraw": either the attribute is malformed in a way that could
/// affect route selection, or the attribute block itself is unparseable (§4). The
/// remaining two categories, "session reset" and "AFI/SAFI disable", are decided
/// at the message level and never by an individual attribute.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AttrOutcome {
    /// The attribute decoded cleanly and takes part in the UPDATE.
    Keep(PathAttribute),
    /// The attribute is malformed, but RFC 7606 confines the damage to the
    /// attribute itself: drop it and process the rest of the UPDATE normally.
    /// Reserved for attributes that cannot affect route selection or installation
    /// (§2) — in practice ATOMIC_AGGREGATE (§7.6) and AGGREGATOR (§7.7).
    Discard {
        /// The discarded attribute's type code, so the caller can still enforce
        /// the once-per-UPDATE rule of §3(g) against it.
        type_code: u8,
    },
}

/// Classify a malformed-but-discardable attribute. RFC 7606 §3(c) escalates
/// contradictory Optional/Transitive bits to treat-as-withdraw *whatever* the
/// attribute is, and §7.6/§7.7 prescribe discard only for a bad length — so an
/// attribute qualifies for discard solely when its flags are canonical and it is
/// the length that is wrong. `canonical` is the attribute's canonical flag byte.
fn discard_or_withdraw(
    flags: u8,
    canonical: u8,
    type_code: u8,
    end: usize,
) -> Option<(AttrOutcome, usize)> {
    // Mirrors the flag validation applied to well-formed attributes below.
    let defining = FLAG_OPTIONAL | FLAG_TRANSITIVE;
    if flags & defining != canonical & defining {
        return None;
    }
    if canonical & defining != FLAG_OPTIONAL | FLAG_TRANSITIVE && flags & FLAG_PARTIAL != 0 {
        return None;
    }
    Some((AttrOutcome::Discard { type_code }, end))
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
    pub fn decode(buf: &[u8], four_octet: bool) -> Option<(AttrOutcome, usize)> {
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
            Self::ATOMIC_AGGREGATE => {
                // RFC 7606 §7.6: ATOMIC_AGGREGATE is a fixed 0-length attribute — a
                // value-bearing one is malformed, and because the attribute cannot
                // affect route selection the prescribed handling is attribute
                // discard rather than withdrawing the UPDATE's routes.
                if !value.is_empty() {
                    return discard_or_withdraw(flags, FLAG_TRANSITIVE, type_code, end);
                }
                PathAttribute::AtomicAggregate
            }
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
                    // Only the families this speaker actually understands reach
                    // the prefix decoder. `decode_mp_prefixes` treats every AFI
                    // that is not IPv6 as IPv4, so an unrecognised pair used to
                    // fall through and be *misparsed*: AFI 1234 / SAFI 77 came
                    // back as a list of IPv4 prefixes, tagged with the AFI it
                    // was not. Bytes that mean nothing to us must not become
                    // routes that mean something.
                    if !known_family(afi, safi) {
                        return None;
                    }
                    // The Next Hop is not free-form here. RFC 4760 §3 fixes its
                    // length by family, RFC 2545 §3 gives IPv6 either 16 octets
                    // or 32 (a global address followed by a link-local one), and
                    // RFC 8950 §3 lets an IPv6 next hop carry IPv4 routes at
                    // those same two lengths. Nothing checked it, so `nh_len` of
                    // 0 decoded happily and every route in the attribute arrived
                    // pointing at an empty vector.
                    //
                    // Checked *here* rather than beside the AFI/SAFI, and that
                    // placement is the whole subtlety: FlowSpec has no
                    // meaningful next hop at all (RFC 8955 §4) and this crate's
                    // own encoder emits length 0 for it, so a blanket rule in
                    // the preamble refuses wren's own valid FlowSpec attribute —
                    // the existing round-trip test says so. The families with
                    // their own next-hop conventions keep them; this arm is
                    // plain unicast, where the two RFCs above are the whole
                    // contract.
                    if !unicast_next_hop_len(afi, nh_len) {
                        return None;
                    }
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
                    // The same gate on the withdraw side. A withdraw for a
                    // family we never advertised support for cannot name a route
                    // we hold, and misparsing it would manufacture IPv4
                    // withdrawals out of somebody else's address format.
                    if !known_family(afi, safi) {
                        return None;
                    }
                    let withdrawn = decode_mp_prefixes(&value[3..], afi)?;
                    PathAttribute::MpUnreachNlri { afi, safi, withdrawn }
                }
            }
            Self::ORIGINATOR_ID => {
                // RFC 7606 §5: ORIGINATOR_ID (RFC 4456) is exactly 4 octets — an
                // over-long value is malformed, not truncated to its first four.
                if value.len() != 4 {
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
            Self::AGGREGATOR => match decode_aggregator(value, four_octet) {
                Some((asn, id)) => PathAttribute::Aggregator { asn, id },
                // RFC 7606 §7.7: a wrong-length AGGREGATOR is attribute discard —
                // like ATOMIC_AGGREGATE it is purely informational. (AS4_AGGREGATOR
                // below is deliberately left at treat-as-withdraw: RFC 7606 §7 hands
                // it to §8 rather than prescribing discard.)
                None => {
                    let canonical = FLAG_OPTIONAL | FLAG_TRANSITIVE;
                    return discard_or_withdraw(flags, canonical, type_code, end);
                }
            },
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
        Some((AttrOutcome::Keep(attr), end))
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
/// Whether a Next Hop of `nh_len` octets is a length **unicast** defines.
///
/// * **IPv4** — 4 (RFC 4760 §3), or 16/32 when the peer negotiated RFC 8950 and
///   carries IPv4 routes over an IPv6 next hop.
/// * **IPv6** — 16, or 32 for a global address followed by a link-local one
///   (RFC 2545 §3).
///
/// Zero is valid for neither: a unicast route needs a next hop to resolve, and
/// "no next hop" is what MP_UNREACH is for. Families that genuinely have no next
/// hop do not come through here — see the call site.
fn unicast_next_hop_len(afi: u16, nh_len: usize) -> bool {
    match afi {
        AFI_IPV4 => matches!(nh_len, 4 | 16 | 32),
        AFI_IPV6 => matches!(nh_len, 16 | 32),
        // Unreachable: `known_family` has already gated this to the two above.
        _ => false,
    }
}

/// Whether this speaker understands an (AFI, SAFI) pair well enough to parse its
/// NLRI. The families with their own decoders are matched before this is
/// reached; what is left is the plain prefix encoding, which only IPv4 and IPv6
/// unicast use here.
fn known_family(afi: u16, safi: u8) -> bool {
    matches!((afi, safi), (AFI_IPV4, SAFI_UNICAST) | (AFI_IPV6, SAFI_UNICAST))
}

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
    // RFC 7606 §5/§7.7: AGGREGATOR is exactly `asn_len + 4` octets (the AS plus the
    // 4-octet BGP identifier) — a length mismatch is malformed, not truncated.
    if value.len() != asn_len + 4 {
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

    /// Decode one attribute that is expected to survive: `None` for a
    /// treat-as-withdraw verdict, and a panic if RFC 7606 discarded it instead.
    fn decode_kept(buf: &[u8], four_octet: bool) -> Option<(PathAttribute, usize)> {
        match PathAttribute::decode(buf, four_octet)? {
            (AttrOutcome::Keep(a), used) => Some((a, used)),
            (AttrOutcome::Discard { type_code }, _) => {
                panic!("attribute type {type_code} was discarded, expected it to be kept")
            }
        }
    }

    /// Round-trip an attribute at the given on-wire AS width.
    fn roundtrip_w(attr: PathAttribute, four_octet: bool) {
        let mut buf = Vec::new();
        attr.encode(&mut buf, four_octet);
        let (decoded, used) = decode_kept(&buf, four_octet).expect("decodes");
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
        let (decoded, _) = decode_kept(&buf, false).unwrap();
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

        /// Build a raw MP_REACH value: AFI(2) · SAFI · NHLen · NextHop · Reserved ·
    /// NLRI, with one 2001:db8::/64 in it.
    fn mp_reach_value(afi: u16, safi: u8, nh: &[u8]) -> Vec<u8> {
        let mut v = afi.to_be_bytes().to_vec();
        v.push(safi);
        v.push(nh.len() as u8);
        v.extend_from_slice(nh);
        v.push(0); // Reserved
        // The NLRI has to match the family, or an IPv4 decode of an IPv6 /64
        // fails on the prefix length rather than on the next hop this is about.
        if afi == AFI_IPV6 {
            v.extend_from_slice(&[64, 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0]);
        } else {
            v.extend_from_slice(&[24, 10, 0, 0]);
        }
        v
    }

    fn decode_mp_reach(value: &[u8]) -> Option<PathAttribute> {
        let mut raw = vec![FLAG_OPTIONAL, 14, value.len() as u8];
        raw.extend_from_slice(value);
        PathAttribute::decode(&raw, true).map(|(o, _)| match o {
            AttrOutcome::Keep(a) => a,
            AttrOutcome::Discard { .. } => panic!("unexpected discard"),
        })
    }

    #[test]
    fn a_next_hop_of_a_length_no_family_defines_is_refused() {
        // RFC 4760 §3 fixes the Next Hop length by family; RFC 2545 §3 gives
        // IPv6 16 or 32 octets; RFC 8950 §3 reuses those two for IPv4 routes
        // over an IPv6 next hop. Nothing checked it, so length 0 decoded happily
        // and every route in the attribute arrived pointing at an empty vector —
        // a route this speaker cannot resolve and will never install, silently.
        for bad in [0usize, 1, 3, 5, 15, 17, 31, 33] {
            let nh = vec![0x22; bad];
            assert!(
                decode_mp_reach(&mp_reach_value(AFI_IPV6, SAFI_UNICAST, &nh)).is_none(),
                "an IPv6 next hop of {bad} octets was accepted"
            );
        }
        // The lengths the RFCs do define.
        for good in [16usize, 32] {
            let nh = vec![0x22; good];
            assert!(
                decode_mp_reach(&mp_reach_value(AFI_IPV6, SAFI_UNICAST, &nh)).is_some(),
                "an IPv6 next hop of {good} octets was refused"
            );
        }
        // RFC 8950: IPv4 unicast may take an IPv6-shaped next hop, and its own.
        for good in [4usize, 16, 32] {
            let nh = vec![0x22; good];
            let v = mp_reach_value(AFI_IPV4, SAFI_UNICAST, &nh);
            assert!(
                decode_mp_reach(&v).is_some(),
                "an IPv4 next hop of {good} octets was refused"
            );
        }
    }

    #[test]
    fn a_family_this_speaker_does_not_know_is_refused_not_misparsed() {
        // `decode_mp_prefixes` reads every AFI that is not IPv6 as IPv4, so an
        // unrecognised pair used to fall through and be *misparsed*: the NLRI
        // came back as a list of IPv4 prefixes, tagged with an AFI it was not.
        // Bytes that mean nothing to us must not become routes that mean
        // something.
        for (afi, safi) in [(1234u16, 77u8), (AFI_IPV4, 99), (AFI_IPV6, 4), (0, 0)] {
            let v = mp_reach_value(afi, safi, &[10, 0, 0, 1]);
            assert!(
                decode_mp_reach(&v).is_none(),
                "MP_REACH for the unknown family ({afi}, {safi}) was decoded"
            );
        }
        // MP_UNREACH takes the same gate: a withdraw for a family we never
        // advertised cannot name a route we hold.
        for (afi, safi) in [(1234u16, 77u8), (AFI_IPV4, 99)] {
            let mut v = afi.to_be_bytes().to_vec();
            v.push(safi);
            v.extend_from_slice(&[24, 10, 0, 0]);
            let mut raw = vec![FLAG_OPTIONAL, 15, v.len() as u8];
            raw.extend_from_slice(&v);
            assert!(
                PathAttribute::decode(&raw, true).is_none(),
                "MP_UNREACH for the unknown family ({afi}, {safi}) was decoded"
            );
        }
    }

    #[test]
    fn flowspec_keeps_its_absent_next_hop() {
        // The placement of the next-hop rule is load-bearing, not incidental.
        // FlowSpec has no meaningful next hop (RFC 8955 §4) and this crate's own
        // encoder emits length 0 for it — so a blanket length check in the
        // MP_REACH preamble refuses wren's own valid attribute. It did, and the
        // existing round-trip test caught it.
        use crate::flowspec::{Component, FlowSpec};
        let attr = PathAttribute::MpReachFlowSpec {
            afi: AFI_IPV4,
            next_hop: vec![],
            nlri: vec![FlowSpec {
                components: vec![Component::DestPrefix("10.50.0.0/24".parse().unwrap())],
            }],
        };
        let mut buf = Vec::new();
        attr.encode(&mut buf, true);
        assert!(
            PathAttribute::decode(&buf, true).is_some(),
            "a zero-length FlowSpec next hop was refused"
        );
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
    fn variable_length_attributes_reject_wrong_length_rfc7606() {
        // ATOMIC_AGGREGATE (type 6) is exactly 0 octets; the empty canonical form
        // decodes, a value-bearing one is malformed and discarded (RFC 7606 §7.6).
        assert!(decode_kept(&[FLAG_TRANSITIVE, 6, 0], true).is_some());
        assert_eq!(
            PathAttribute::decode(&[FLAG_TRANSITIVE, 6, 1, 0], true),
            Some((AttrOutcome::Discard { type_code: 6 }, 4))
        );
        // AGGREGATOR (type 7) is exactly asn_len + 4 (8 octets with a 4-octet AS);
        // the exact form decodes, a padded one is discarded (RFC 7606 §7.7).
        assert!(
            decode_kept(&[FLAG_OPTIONAL | FLAG_TRANSITIVE, 7, 8, 0, 0, 0, 1, 10, 0, 0, 1], true)
                .is_some()
        );
        assert_eq!(
            PathAttribute::decode(
                &[FLAG_OPTIONAL | FLAG_TRANSITIVE, 7, 10, 0, 0, 0, 1, 10, 0, 0, 1, 9, 9],
                true
            ),
            Some((AttrOutcome::Discard { type_code: 7 }, 13))
        );
        // ORIGINATOR_ID (type 9, RFC 4456) is exactly 4 octets. RFC 7606 §7.9 keeps
        // a wrong-length one at treat-as-withdraw — discard applies there only to an
        // ORIGINATOR_ID arriving from an external neighbour, which is a policy
        // decision above the decoder.
        assert!(decode_kept(&[FLAG_OPTIONAL, 9, 4, 10, 0, 0, 1], true).is_some());
        assert!(PathAttribute::decode(&[FLAG_OPTIONAL, 9, 5, 10, 0, 0, 1, 0], true).is_none());
    }

    #[test]
    fn attribute_discard_requires_canonical_flags_rfc7606() {
        // RFC 7606 §3(c): contradictory Optional/Transitive bits are treat-as-withdraw
        // whatever the attribute, so the §7.6/§7.7 discard must not swallow them. Each
        // pair below is the same wrong-length value, once with canonical flags
        // (discard) and once with broken flags (withdraw).
        let bad_len = |flags: u8| PathAttribute::decode(&[flags, 6, 1, 0], true);
        assert!(matches!(bad_len(FLAG_TRANSITIVE), Some((AttrOutcome::Discard { .. }, _))));
        // ATOMIC_AGGREGATE is well-known transitive: Optional or Partial is a conflict.
        assert!(bad_len(FLAG_OPTIONAL | FLAG_TRANSITIVE).is_none());
        assert!(bad_len(FLAG_TRANSITIVE | FLAG_PARTIAL).is_none());

        // AGGREGATOR is optional transitive, so Partial is legal but dropping either
        // defining bit is not.
        let agg = |flags: u8| PathAttribute::decode(&[flags, 7, 10, 0, 0, 0, 1, 10, 0, 0, 1, 9, 9], true);
        let canonical = FLAG_OPTIONAL | FLAG_TRANSITIVE;
        assert!(matches!(agg(canonical), Some((AttrOutcome::Discard { .. }, _))));
        assert!(matches!(agg(canonical | FLAG_PARTIAL), Some((AttrOutcome::Discard { .. }, _))));
        assert!(agg(FLAG_TRANSITIVE).is_none());
        assert!(agg(FLAG_OPTIONAL).is_none());
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
        let (decoded, used) = decode_kept(&buf, true).unwrap();
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

    // =======================================================================
    // Byte-offset assertions (RFC 4271 §4.3, RFC 4760 §3)
    //
    // The `roundtrip` helper above encodes and decodes with wren alone, so a
    // field at the wrong offset is invisible to it. The tests below assert the
    // offsets and code points the RFCs name — the only kind of test that can
    // see the class of bug that made every wren router invisible to FRR.
    // =======================================================================

    /// RFC 4271 §4.3 lays every path attribute out as Attribute Flags 0,
    /// Attribute Type Code 1, then a 1-octet length at 2 — or, when the
    /// Extended Length bit (0x10) is set, a 2-octet big-endian length at 2..4.
    ///
    /// The Extended Length rule is the interesting half: get the threshold or
    /// the width wrong and the peer reads the first octet of the value as part
    /// of the length. It then treats the whole UPDATE as malformed (§6.3) and
    /// resets the session — a repeating flap for as long as the route is
    /// advertised.
    #[test]
    fn an_attribute_header_uses_a_two_octet_length_exactly_above_255_octets() {
        // An unrecognised attribute lets the value be any length, so the
        // boundary can be straddled exactly: 255 is the largest that still fits
        // one octet, 256 the smallest that does not.
        let unknown = |n: usize| PathAttribute::Unknown {
            flags: FLAG_OPTIONAL | FLAG_TRANSITIVE,
            type_code: 200,
            value: vec![0xab; n],
        };
        let mut b = Vec::new();
        unknown(255).encode(&mut b, true);
        assert_eq!(b[0] & 0x10, 0, "255 octets is the largest one-octet length");
        assert_eq!(b[1], 200, "the type code is byte 1");
        assert_eq!(b[2], 255, "the length is a single octet at byte 2");
        assert_eq!(b.len(), 3 + 255, "3 octets of header");

        let mut b = Vec::new();
        unknown(256).encode(&mut b, true);
        assert_eq!(b[0] & 0x10, 0x10, "256 octets sets the Extended Length bit");
        assert_eq!(&b[2..4], &[0x01, 0x00], "the length is 2 octets at 2..4, big-endian");
        assert_eq!(b.len(), 4 + 256, "4 octets of header");

        // And both come back intact through the decoder. (An `Unknown` keeps the
        // flags exactly as received, Extended Length bit included, so compare
        // the type and value rather than the whole attribute.)
        for n in [255usize, 256] {
            let mut b = Vec::new();
            unknown(n).encode(&mut b, true);
            let (got, used) = decode_kept(&b, true).expect("decodes");
            assert_eq!(used, b.len(), "the header width is read back correctly");
            match got {
                PathAttribute::Unknown { type_code, value, .. } => {
                    assert_eq!(type_code, 200);
                    assert_eq!(value.len(), n, "a {n}-octet value survives");
                    assert!(value.iter().all(|&x| x == 0xab));
                }
                other => panic!("expected an unknown attribute, got {other:?}"),
            }
        }
    }

    /// RFC 4271 §5 and RFC 4760 §3 assign the type codes an implementation
    /// switches on. A wrong code makes a well-known attribute unrecognised
    /// (§6.3 *Unrecognized Well-known Attribute*, session reset) or turns
    /// MP_REACH into MP_UNREACH, which withdraws exactly the routes it meant to
    /// advertise.
    #[test]
    fn the_attribute_type_codes_are_the_ones_the_rfcs_assign() {
        let code = |a: PathAttribute| {
            let mut b = Vec::new();
            a.encode(&mut b, true);
            (b[0], b[1])
        };
        // (flags, type code). Well-known transitive is 0x40, optional
        // non-transitive 0x80, optional transitive 0xc0 (RFC 4271 §4.3).
        assert_eq!(code(PathAttribute::Origin(Origin::Igp)), (0x40, 1));
        assert_eq!(code(PathAttribute::AsPath(vec![])), (0x40, 2));
        assert_eq!(code(PathAttribute::NextHop(ip([10, 0, 0, 1]))), (0x40, 3));
        assert_eq!(code(PathAttribute::MultiExitDisc(0)), (0x80, 4));
        assert_eq!(code(PathAttribute::LocalPref(0)), (0x40, 5));
        assert_eq!(code(PathAttribute::AtomicAggregate), (0x40, 6));
        assert_eq!(code(PathAttribute::Aggregator { asn: 1, id: ip([1, 2, 3, 4]) }), (0xc0, 7));
        assert_eq!(code(PathAttribute::Communities(vec![])), (0xc0, 8));
        assert_eq!(code(PathAttribute::OriginatorId(ip([1, 2, 3, 4]))), (0x80, 9));
        assert_eq!(code(PathAttribute::ClusterList(vec![])), (0x80, 10));
        assert_eq!(
            code(PathAttribute::MpReachNlri {
                afi: 2,
                safi: 1,
                next_hop: vec![0u8; 16],
                nlri: vec![],
            }),
            (0x80, 14),
            "MP_REACH_NLRI is optional non-transitive, type 14"
        );
        assert_eq!(
            code(PathAttribute::MpUnreachNlri { afi: 2, safi: 1, withdrawn: vec![] }),
            (0x80, 15),
            "MP_UNREACH_NLRI is optional non-transitive, type 15"
        );
        assert_eq!(code(PathAttribute::ExtendedCommunities(vec![])), (0xc0, 16));
        assert_eq!(code(PathAttribute::LargeCommunities(vec![])), (0xc0, 32));
        assert_eq!(code(PathAttribute::OnlyToCustomer(1)), (0xc0, 35));
    }

    /// RFC 4271 §5.1.1 numbers ORIGIN: 0 IGP, 1 EGP, 2 INCOMPLETE. It is the
    /// second-to-last tie-break in §9.1.2's decision process, so getting the
    /// numbering wrong silently inverts route preference between two otherwise
    /// equal paths — and `origin_roundtrips` above only checks the enum against
    /// itself.
    #[test]
    fn the_origin_codes_are_the_ones_the_rfc_assigns() {
        for (o, code) in [(Origin::Igp, 0u8), (Origin::Egp, 1), (Origin::Incomplete, 2)] {
            assert_eq!(o.as_u8(), code, "{o:?} is ORIGIN {code}");
            assert_eq!(Origin::from_u8(code), Some(o));
            let mut b = Vec::new();
            PathAttribute::Origin(o).encode(&mut b, true);
            assert_eq!(b[2], 1, "an ORIGIN value is one octet");
            assert_eq!(b[3], code, "the value is the code itself");
        }
        assert_eq!(Origin::from_u8(3), None);
    }

    /// RFC 4271 §4.3 and RFC 5065 §3 number the AS_PATH segment types:
    /// 1 AS_SET, 2 AS_SEQUENCE, 3 AS_CONFED_SEQUENCE, 4 AS_CONFED_SET. Each
    /// segment is `[type][count of ASes][ASes]`, where the count is a number of
    /// *AS numbers*, not octets.
    ///
    /// AS_SET and AS_SEQUENCE transposed changes how §9.1.2 measures path
    /// length (a set counts as 1 regardless of size) and, worse, makes a
    /// confederation segment look like a public one — so the AS-path a route
    /// carries out of the confederation is wrong and remote loop detection
    /// stops working.
    #[test]
    fn the_as_path_segment_types_are_the_ones_the_rfcs_assign() {
        let seg = |s: AsPathSegment| {
            let mut b = Vec::new();
            PathAttribute::AsPath(vec![s]).encode(&mut b, true);
            b
        };
        for (s, kind) in [
            (AsPathSegment::Set(vec![65001, 65002]), 1u8),
            (AsPathSegment::Sequence(vec![65001, 65002]), 2),
            (AsPathSegment::ConfedSequence(vec![65001, 65002]), 3),
            (AsPathSegment::ConfedSet(vec![65001, 65002]), 4),
        ] {
            let b = seg(s);
            assert_eq!(b[3], kind, "the segment type is the first value octet");
            assert_eq!(b[4], 2, "the count is a number of ASes, not octets");
            assert_eq!(
                &b[5..13],
                &[0, 0, 0xfd, 0xe9, 0, 0, 0xfd, 0xea],
                "the ASes follow, 4 octets each at the 4-octet width"
            );
            assert_eq!(b[2] as usize, b.len() - 3, "the attribute length covers the segment");
        }
        // At the 2-octet width the same ASes are half as wide (RFC 6793 §4).
        let b = {
            let mut v = Vec::new();
            PathAttribute::AsPath(vec![AsPathSegment::Sequence(vec![65001, 65002])])
                .encode(&mut v, false);
            v
        };
        assert_eq!(b[4], 2, "still two ASes");
        assert_eq!(&b[5..9], &[0xfd, 0xe9, 0xfd, 0xea], "2 octets each");
    }

    /// RFC 4760 §3 fixes the MP_REACH_NLRI value: AFI 0..2, SAFI 2, Length of
    /// Next Hop Network Address 3, the next hop, then a *Reserved* octet that
    /// must be sent as zero, then the NLRI. MP_UNREACH_NLRI (§4) is AFI 0..2,
    /// SAFI 2, then the withdrawn NLRI — with no next hop and no reserved octet.
    ///
    /// The reserved octet is the trap: it sits between the next hop and the
    /// NLRI, and omitting it (or putting it before the next hop) makes the peer
    /// read the first NLRI length octet as the reserved field and every prefix
    /// after that as garbage. §7 then treats the attribute as malformed and the
    /// whole family is withdrawn.
    #[test]
    fn an_mp_reach_value_has_a_reserved_octet_between_the_next_hop_and_the_nlri() {
        let nh: Vec<u8> = (0x20..0x30).collect(); // 16 octets, a v6 next hop
        let mut b = Vec::new();
        PathAttribute::MpReachNlri {
            afi: crate::AFI_IPV6,
            safi: crate::SAFI_UNICAST,
            next_hop: nh.clone(),
            nlri: vec![p("2001:db8::/32")],
        }
        .encode(&mut b, true);
        let v = &b[3..]; // flags, type, 1-octet length
        assert_eq!(&v[0..2], &[0, 2], "AFI is bytes 0..2 of the value; IPv6 is 2");
        assert_eq!(v[2], 1, "SAFI is byte 2; unicast is 1");
        assert_eq!(v[3], 16, "the Next Hop *length* is byte 3");
        assert_eq!(&v[4..20], &nh[..], "the next hop itself is bytes 4..20");
        assert_eq!(v[20], 0, "byte 20 is the Reserved octet and must be zero");
        assert_eq!(&v[21..], &[32, 0x20, 0x01, 0x0d, 0xb8], "the NLRI starts at byte 21");

        // MP_UNREACH has no next hop and no reserved octet at all.
        let mut b = Vec::new();
        PathAttribute::MpUnreachNlri {
            afi: crate::AFI_IPV6,
            safi: crate::SAFI_UNICAST,
            withdrawn: vec![p("2001:db8::/32")],
        }
        .encode(&mut b, true);
        let v = &b[3..];
        assert_eq!(&v[0..2], &[0, 2], "AFI is bytes 0..2");
        assert_eq!(v[2], 1, "SAFI is byte 2");
        assert_eq!(
            &v[3..],
            &[32, 0x20, 0x01, 0x0d, 0xb8],
            "the withdrawn NLRI follows the SAFI directly"
        );
    }

    /// The (AFI, SAFI) pairs IANA assigns to the families wren carries. These
    /// are the numbers a peer's capability negotiation and MP_REACH demuxing
    /// switch on: get one wrong and the family is either never negotiated or
    /// the NLRI is handed to the wrong parser.
    ///
    /// Asserted on the encoder's own output for the variants that hard-code the
    /// pair, since nothing else in the crate pins them.
    #[test]
    fn the_hard_coded_address_families_use_the_iana_assigned_numbers() {
        let value = |a: PathAttribute| {
            let mut b = Vec::new();
            a.encode(&mut b, true);
            // Skip flags, type, and the 1- or 2-octet length.
            let hdr = if b[0] & 0x10 != 0 { 4 } else { 3 };
            b[hdr..].to_vec()
        };
        let evpn = value(PathAttribute::MpReachEvpn { next_hop: vec![10, 0, 0, 1], nlri: vec![] });
        assert_eq!(&evpn[0..3], &[0, 25, 70], "EVPN is AFI 25 (L2VPN), SAFI 70");

        let ls = value(PathAttribute::MpReachLinkState { next_hop: vec![10, 0, 0, 1], nlri: vec![] });
        assert_eq!(
            &ls[0..3],
            &[0x40, 0x04, 71],
            "BGP-LS is AFI 16388 (0x4004), SAFI 71"
        );
        let ls_u = value(PathAttribute::MpUnreachLinkState { withdrawn: vec![] });
        assert_eq!(&ls_u[0..3], &[0x40, 0x04, 71]);

        let srp = value(PathAttribute::MpReachSrPolicy {
            afi: crate::AFI_IPV4,
            next_hop: vec![10, 0, 0, 1],
            nlri: vec![],
        });
        assert_eq!(&srp[0..3], &[0, 1, 73], "SR Policy is SAFI 73 under the endpoint's AFI");
        let srp6 = value(PathAttribute::MpUnreachSrPolicy {
            afi: crate::AFI_IPV6,
            withdrawn: vec![],
        });
        assert_eq!(&srp6[0..3], &[0, 2, 73]);

        let fs = value(PathAttribute::MpUnreachFlowSpec {
            afi: crate::AFI_IPV4,
            withdrawn: vec![],
        });
        assert_eq!(&fs[0..3], &[0, 1, 133], "FlowSpec is SAFI 133");
    }

    /// `MpReachSrPolicy`, `MpUnreachSrPolicy`, `MpReachLinkState`,
    /// `MpUnreachLinkState`, `BgpLs` and `TunnelEncap` are all built and sent by
    /// the daemon (`wren-daemon/src/bgp.rs`) and, until this test, not one of
    /// them was exercised anywhere — an encoder change to any of them would
    /// have compiled, passed the whole suite, and gone out on the wire.
    ///
    /// RFC 7752 §3.2 gives the Link-State NLRI its shape (NLRI-Type 0..2, Total
    /// NLRI Length 2..4, Protocol-ID 4, Identifier 5..13, then descriptor
    /// TLVs); draft-ietf-idr-segment-routing-te-policy gives the SR Policy NLRI
    /// its length-in-*bits* leading octet; RFC 9012 §3 gives the Tunnel
    /// Encapsulation attribute its `Tunnel-Type(2) · Length(2) · Value` TLVs.
    #[test]
    fn the_sr_policy_and_link_state_attributes_round_trip_and_keep_their_wire_shape() {
        use crate::link_state::{BgpLsAttribute, LinkStateNlri, LsObjectKind, LsTlv};
        use crate::sr_policy::{SrPolicyNlri, TunnelTlv};

        // --- SR Policy NLRI: the leading octet is a length in BITS. ---------
        let v4 = SrPolicyNlri {
            distinguisher: 1,
            color: 100,
            endpoint: "10.0.0.9".parse().unwrap(),
        };
        let attr = PathAttribute::MpReachSrPolicy {
            afi: crate::AFI_IPV4,
            next_hop: vec![10, 0, 0, 1],
            nlri: vec![v4],
        };
        let mut b = Vec::new();
        attr.encode(&mut b, true);
        let n = &b[3 + 2 + 1 + 1 + 4 + 1..]; // AFI(2) SAFI(1) nhlen(1) nh(4) reserved(1)
        assert_eq!(n[0], 96, "an IPv4 SR Policy NLRI is 96 bits (12 octets) long");
        assert_eq!(&n[1..5], &[0, 0, 0, 1], "the distinguisher is 4 octets");
        assert_eq!(&n[5..9], &[0, 0, 0, 100], "the colour is 4 octets");
        assert_eq!(&n[9..13], &[10, 0, 0, 9], "the endpoint follows its AFI's width");
        let (decoded, used) = decode_kept(&b, true).expect("decodes");
        assert_eq!(decoded, attr);
        assert_eq!(used, b.len());

        let v6 = SrPolicyNlri {
            distinguisher: 2,
            color: 200,
            endpoint: "2001:db8::9".parse().unwrap(),
        };
        let attr = PathAttribute::MpUnreachSrPolicy {
            afi: crate::AFI_IPV6,
            withdrawn: vec![v6],
        };
        let mut b = Vec::new();
        attr.encode(&mut b, true);
        assert_eq!(b[3 + 3], 192, "an IPv6 SR Policy NLRI is 192 bits (24 octets) long");
        assert_eq!(decode_kept(&b, true).expect("decodes").0, attr);

        // --- Tunnel Encapsulation (RFC 9012 §3): Type(2) Length(2) Value ----
        let attr = PathAttribute::TunnelEncap(vec![TunnelTlv::Other {
            tunnel_type: 3, // IP-in-IP: a type wren does not model, kept verbatim
            value: vec![0xde, 0xad, 0xbe, 0xef],
        }]);
        let mut b = Vec::new();
        attr.encode(&mut b, true);
        assert_eq!(b[1], 23, "TUNNEL ENCAPSULATION is attribute type 23");
        assert_eq!(&b[3..5], &[0, 3], "Tunnel-Type is a 2-octet field");
        assert_eq!(&b[5..7], &[0, 4], "then a 2-octet Length");
        assert_eq!(&b[7..11], &[0xde, 0xad, 0xbe, 0xef], "then the value");
        assert_eq!(decode_kept(&b, true).expect("decodes").0, attr);

        // --- Link-State NLRI (RFC 7752 §3.2) --------------------------------
        let nlri = LinkStateNlri {
            kind: LsObjectKind::Node,
            protocol: 2, // IS-IS Level 2
            identifier: 0,
            descriptors: vec![LsTlv { typ: 512, value: vec![0, 0, 0xfd, 0xe8] }],
        };
        let attr = PathAttribute::MpReachLinkState {
            next_hop: vec![10, 0, 0, 1],
            nlri: vec![nlri.clone()],
        };
        let mut b = Vec::new();
        attr.encode(&mut b, true);
        let n = &b[3 + 2 + 1 + 1 + 4 + 1..]; // AFI(2) SAFI(1) nhlen(1) nh(4) reserved(1)
        assert_eq!(&n[0..2], &[0, 1], "NLRI-Type is 2 octets; a Node NLRI is 1");
        assert_eq!(
            u16::from_be_bytes([n[2], n[3]]) as usize,
            n.len() - 4,
            "Total NLRI Length is bytes 2..4 and covers everything after it"
        );
        assert_eq!(n[4], 2, "Protocol-ID is byte 4");
        assert_eq!(&n[5..13], &[0u8; 8], "the Identifier is an 8-octet field at 5..13");
        assert_eq!(&n[13..17], &[0x02, 0x00, 0, 4], "then the descriptor TLVs (type 512, len 4)");
        assert_eq!(decode_kept(&b, true).expect("decodes").0, attr);

        let attr = PathAttribute::MpUnreachLinkState { withdrawn: vec![nlri] };
        let mut b = Vec::new();
        attr.encode(&mut b, true);
        assert_eq!(decode_kept(&b, true).expect("decodes").0, attr);

        // --- The BGP-LS attribute itself (type 29) ---------------------------
        let attr = PathAttribute::BgpLs(BgpLsAttribute::new(vec![
            LsTlv { typ: 1026, value: b"wren".to_vec() },
        ]));
        let mut b = Vec::new();
        attr.encode(&mut b, true);
        assert_eq!(b[0], 0x80, "BGP-LS_ATTRIBUTE is optional non-transitive");
        assert_eq!(b[1], 29, "BGP-LS_ATTRIBUTE is type code 29");
        assert_eq!(&b[3..5], &[0x04, 0x02], "the node-name TLV type is 1026");
        assert_eq!(&b[5..7], &[0, 4], "then its 2-octet length");
        assert_eq!(&b[7..11], b"wren");
        assert_eq!(decode_kept(&b, true).expect("decodes").0, attr);
    }
}
