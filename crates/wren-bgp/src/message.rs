//! BGP messages (RFC 4271 §4): the 19-byte common header and the four message
//! types OPEN, UPDATE, NOTIFICATION and KEEPALIVE.
//!
//! Every message is `marker(16) · length(2) · type(1) · body`. [`Message::encode`]
//! frames the body with the header (filling the all-ones marker and the length);
//! [`Message::decode`] validates the marker, length and type before parsing the
//! body. The session runner reads a 19-byte header first to learn the length,
//! then the remaining bytes — but [`Message::decode`] also accepts a whole
//! message buffer, which is what the tests use.

use std::net::Ipv4Addr;

use wren_core::Prefix;

use crate::attr::{AttrOutcome, PathAttribute};
use crate::capability::{encode_optional_parameters, parse_optional_parameters, Capability};
use crate::{
    as_trans_fit, decode_prefix, encode_prefix, MessageType, AFI_IPV4, HEADER_LEN, MARKER,
    MAX_MESSAGE_LEN,
    SAFI_UNICAST, VERSION,
};

/// An OPEN message body (§4.2): the parameters two speakers agree on to start a
/// session.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Open {
    /// The protocol version (always [`VERSION`]).
    pub version: u8,
    /// The sender's AS in the 2-octet `My Autonomous System` field. For a 4-octet
    /// AS this is [`crate::AS_TRANS`] and the real AS rides in a
    /// [`Capability::FourOctetAs`] (RFC 6793 §4); use [`Open::effective_as`].
    pub my_as: u16,
    /// The proposed Hold Time, in seconds.
    pub hold_time: u16,
    /// The sender's BGP Identifier (a 32-bit id, written as an IPv4 address).
    pub identifier: Ipv4Addr,
    /// The advertised capabilities (RFC 5492), parsed from the Optional Parameters.
    pub capabilities: Vec<Capability>,
}

impl Open {
    /// Build an OPEN advertising `local_as` as a 4-octet AS (RFC 6793): the
    /// 2-octet `my_as` field carries the AS directly when it fits or
    /// [`crate::AS_TRANS`] otherwise, and the real AS is advertised in the
    /// 4-octet AS capability.
    pub fn new(version: u8, local_as: u32, hold_time: u16, identifier: Ipv4Addr) -> Open {
        Open {
            version,
            my_as: as_trans_fit(local_as),
            hold_time,
            identifier,
            // Always offer the 4-octet AS capability, and the Multiprotocol
            // capability for **both** unicast families (RFC 4760).
            //
            // IPv4 unicast has to be named explicitly even though RFC 4760 §8
            // says a speaker advertising no MP capability at all is assumed to
            // support it. That default only applies when the OPEN carries no MP
            // capability whatsoever — and this one always carries the IPv6 entry.
            // A peer then computes the negotiated families as the intersection of
            // what was advertised, finds no IPv4 in it, and refuses the family:
            // FRR answers such an OPEN with "Configured AFI/SAFIs do not overlap
            // with received MP capabilities" and, once IPv6 is activated to get
            // the session up, reports IPv4 unicast as never negotiated. Omitting
            // it therefore made every IPv4 prefix unadvertisable to a third-party
            // speaker while wren-to-wren kept working, because both ends shared
            // the same assumption.
            capabilities: vec![
                Capability::FourOctetAs(local_as),
                Capability::Multiprotocol {
                    afi: crate::AFI_IPV4,
                    safi: crate::SAFI_UNICAST,
                },
                Capability::Multiprotocol {
                    afi: crate::AFI_IPV6,
                    safi: crate::SAFI_UNICAST,
                },
                // We honour a received ROUTE-REFRESH by re-advertising (RFC 2918).
                Capability::RouteRefresh,
                // Graceful Restart (RFC 4724): a fresh OPEN (not mid-restart, R=0).
                // wren preserves forwarding across a restart — the kernel FIB
                // outlives the process — so the F flag is set for both unicast
                // families, and we ask helpers to wait DEFAULT_RESTART_TIME.
                Capability::GracefulRestart {
                    restart_state: false,
                    restart_time: crate::DEFAULT_RESTART_TIME,
                    families: vec![
                        (crate::AFI_IPV4, crate::SAFI_UNICAST, true),
                        (crate::AFI_IPV6, crate::SAFI_UNICAST, true),
                    ],
                },
            ],
        }
    }

    /// The peer's real 4-octet AS: the value of its 4-octet AS capability if
    /// present, else the 2-octet `my_as` field (RFC 6793 §4).
    pub fn effective_as(&self) -> u32 {
        self.four_octet_as().unwrap_or(self.my_as as u32)
    }

    /// The advertised 4-octet AS, if the capability is present.
    pub fn four_octet_as(&self) -> Option<u32> {
        self.capabilities.iter().find_map(|c| match c {
            Capability::FourOctetAs(asn) => Some(*asn),
            _ => None,
        })
    }

    /// Whether this OPEN advertised the 4-octet AS Number capability.
    pub fn supports_four_octet_as(&self) -> bool {
        self.four_octet_as().is_some()
    }

    /// Whether this OPEN advertised the Multiprotocol capability for the given
    /// `(AFI, SAFI)` address family (RFC 4760 §8).
    pub fn supports_multiprotocol(&self, afi: u16, safi: u8) -> bool {
        self.capabilities.iter().any(|c| {
            matches!(c, Capability::Multiprotocol { afi: a, safi: s } if *a == afi && *s == safi)
        })
    }

    /// Whether this OPEN advertised the Route Refresh capability (RFC 2918 §3) —
    /// i.e. the peer will honour a ROUTE-REFRESH we send by re-advertising.
    pub fn supports_route_refresh(&self) -> bool {
        self.capabilities.iter().any(|c| matches!(c, Capability::RouteRefresh))
    }

    /// The peer's ADD-PATH Send/Receive flags for the given `(AFI, SAFI)` family
    /// (RFC 7911 §4), if it advertised ADD-PATH for it — [`ADD_PATH_RECEIVE`],
    /// [`ADD_PATH_SEND`] or [`ADD_PATH_BOTH`] (from [`crate::capability`]). `None`
    /// means the peer offered no ADD-PATH for that family.
    pub fn supports_add_path(&self, afi: u16, safi: u8) -> Option<u8> {
        self.capabilities.iter().find_map(|c| match c {
            Capability::AddPath(families) => families
                .iter()
                .find(|(a, s, _)| *a == afi && *s == safi)
                .map(|(_, _, sr)| *sr),
            _ => None,
        })
    }

    /// Whether this OPEN advertised the Extended Next Hop Encoding capability
    /// (RFC 5549 / RFC 8950 §3) for the given `(NLRI AFI, NLRI SAFI, Nexthop AFI)` —
    /// i.e. the peer can receive that NLRI family with the named next-hop family
    /// (e.g. IPv4 unicast reachable through an IPv6 next hop).
    pub fn supports_extended_next_hop(&self, afi: u16, safi: u8, nh_afi: u16) -> bool {
        self.capabilities.iter().any(|c| {
            matches!(c, Capability::ExtendedNextHop(ts)
                if ts.iter().any(|(a, s, n)| *a == afi && *s == safi as u16 && *n == nh_afi))
        })
    }

    /// Whether this OPEN advertised the Graceful Restart capability (RFC 4724 §3).
    pub fn supports_graceful_restart(&self) -> bool {
        self.gr_restart_time().is_some()
    }

    /// The Restart Time the peer asks helpers to wait (RFC 4724 §3), if it
    /// advertised Graceful Restart — how long to retain its routes after the
    /// session drops.
    pub fn gr_restart_time(&self) -> Option<u16> {
        self.capabilities.iter().find_map(|c| match c {
            Capability::GracefulRestart { restart_time, .. } => Some(*restart_time),
            _ => None,
        })
    }

    /// Whether the peer's Graceful Restart capability marks the `(AFI, SAFI)`
    /// family's forwarding state as preserved across its restart (the F flag,
    /// RFC 4724 §3) — only then may a helper retain that family's routes.
    pub fn gr_forwarding_preserved(&self, afi: u16, safi: u8) -> bool {
        self.capabilities.iter().any(|c| {
            matches!(c, Capability::GracefulRestart { families, .. }
                if families.iter().any(|(a, s, f)| *a == afi && *s == safi && *f))
        })
    }

    /// The BGP Role the peer advertised (RFC 9234 §4.1), if any — its own role in
    /// the relationship, which must be the complement of ours.
    pub fn role(&self) -> Option<crate::capability::BgpRole> {
        self.capabilities.iter().find_map(|c| match c {
            Capability::BgpRole(r) => Some(*r),
            _ => None,
        })
    }
}

/// Which address families have ADD-PATH (RFC 7911) in effect on a session, in the
/// direction a message is being encoded or decoded. When a family's flag is set,
/// every NLRI/withdrawn entry of that family on the wire is preceded by a 4-octet
/// Path Identifier. ADD-PATH presence is **not** self-describing on the wire — it
/// must be supplied from the negotiated session state, which is why the codec takes
/// this alongside `four_octet`.
///
/// Only IPv4 unicast (base NLRI) is modelled here; ADD-PATH for MP families (IPv6)
/// is a future extension and is simply never negotiated, so it stays off-wire.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct AddPath {
    /// ADD-PATH is in effect for IPv4 unicast in this direction.
    pub ipv4_unicast: bool,
}

impl AddPath {
    /// No family has ADD-PATH — the classic single-path encoding.
    pub const NONE: AddPath = AddPath { ipv4_unicast: false };

    /// ADD-PATH for IPv4 unicast only.
    pub const fn ipv4(on: bool) -> AddPath {
        AddPath { ipv4_unicast: on }
    }
}

/// An UPDATE message body (§4.3): withdrawn routes, path attributes and the NLRI
/// they describe.
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct Update {
    /// Routes being withdrawn from service.
    pub withdrawn: Vec<Prefix>,
    /// The path attributes describing the advertised routes.
    pub attributes: Vec<PathAttribute>,
    /// The destinations (NLRI) the attributes apply to.
    pub nlri: Vec<Prefix>,
    /// RFC 7911 ADD-PATH Path Identifiers parallel to [`Update::nlri`]: either empty
    /// (ADD-PATH off for IPv4 unicast on the session) or aligned 1:1 with `nlri`.
    /// The codec writes/reads these only when [`AddPath::ipv4_unicast`] is set; all
    /// existing consumers that read `nlri` as bare prefixes stay correct.
    pub nlri_path_ids: Vec<u32>,
    /// RFC 7911 ADD-PATH Path Identifiers parallel to [`Update::withdrawn`] — same
    /// alignment rule as [`Update::nlri_path_ids`].
    pub withdrawn_path_ids: Vec<u32>,
}

impl Update {
    /// Build the End-of-RIB marker for an address family (RFC 4724 §2): for IPv4
    /// unicast a completely empty UPDATE; for any other family an UPDATE whose only
    /// content is an empty MP_UNREACH_NLRI naming that family. Sent once the initial
    /// routing update toward a peer is complete, so a graceful-restart helper knows
    /// the re-advertisement has finished.
    pub fn end_of_rib_marker(afi: u16, safi: u8) -> Update {
        if afi == AFI_IPV4 && safi == SAFI_UNICAST {
            Update::default()
        } else {
            Update {
                withdrawn: vec![],
                attributes: vec![PathAttribute::MpUnreachNlri { afi, safi, withdrawn: vec![] }],
                nlri: vec![],
                ..Default::default()
            }
        }
    }

    /// Whether this UPDATE is an End-of-RIB marker (RFC 4724 §2), and for which
    /// `(AFI, SAFI)`: a completely empty UPDATE marks IPv4 unicast; an UPDATE whose
    /// sole attribute is an empty MP_UNREACH_NLRI marks that attribute's family.
    pub fn end_of_rib(&self) -> Option<(u16, u8)> {
        if !self.withdrawn.is_empty() || !self.nlri.is_empty() {
            return None;
        }
        match self.attributes.as_slice() {
            [] => Some((AFI_IPV4, SAFI_UNICAST)),
            [PathAttribute::MpUnreachNlri { afi, safi, withdrawn }] if withdrawn.is_empty() => {
                Some((*afi, *safi))
            }
            // An empty EVPN MP_UNREACH decodes into the EVPN-specific variant.
            [PathAttribute::MpUnreachEvpn { withdrawn }] if withdrawn.is_empty() => {
                Some((crate::AFI_L2VPN, crate::SAFI_EVPN))
            }
            // Likewise an empty FlowSpec MP_UNREACH marks that AFI's FlowSpec family.
            [PathAttribute::MpUnreachFlowSpec { afi, withdrawn }] if withdrawn.is_empty() => {
                Some((*afi, crate::SAFI_FLOWSPEC))
            }
            _ => None,
        }
    }
}

/// A NOTIFICATION message body (§4.5): an error that closes the session.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Notification {
    /// The error code.
    pub code: u8,
    /// The error subcode.
    pub subcode: u8,
    /// Diagnostic data.
    pub data: Vec<u8>,
}

/// A decoded BGP message.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Message {
    /// An OPEN message (§4.2).
    Open(Open),
    /// An UPDATE message (§4.3).
    Update(Update),
    /// A NOTIFICATION message (§4.5).
    Notification(Notification),
    /// A KEEPALIVE message (§4.4) — header only.
    Keepalive,
    /// A ROUTE-REFRESH message (RFC 2918): ask the peer to re-advertise its
    /// Adj-RIB-Out for one `(AFI, SAFI)` address family.
    RouteRefresh {
        /// The Address Family Identifier (e.g. [`crate::AFI_IPV4`]).
        afi: u16,
        /// The Subsequent Address Family Identifier (e.g. [`crate::SAFI_UNICAST`]).
        safi: u8,
    },
}

/// Why a BGP message could not be decoded.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum DecodeError {
    /// Fewer bytes than the header (or a body) requires.
    TooShort,
    /// The 16-byte marker was not all ones.
    BadMarker,
    /// The length field disagreed with the buffer, or is out of range.
    BadLength { stated: u16, actual: usize },
    /// The Type field held a value outside 1–5.
    BadType(u8),
    /// The OPEN version was not [`VERSION`].
    BadVersion(u8),
    /// A body field was malformed (bad prefix, attribute, or length).
    Malformed,
}

impl std::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DecodeError::TooShort => write!(f, "message shorter than required"),
            DecodeError::BadMarker => write!(f, "bad marker (not all ones)"),
            DecodeError::BadLength { stated, actual } => {
                write!(f, "stated length {stated} != actual {actual}")
            }
            DecodeError::BadType(t) => write!(f, "unknown message type {t}"),
            DecodeError::BadVersion(v) => write!(f, "unsupported BGP version {v}"),
            DecodeError::Malformed => write!(f, "malformed message body"),
        }
    }
}

impl std::error::Error for DecodeError {}

impl Message {
    /// The type of this message.
    pub fn message_type(&self) -> MessageType {
        match self {
            Message::Open(_) => MessageType::Open,
            Message::Update(_) => MessageType::Update,
            Message::Notification(_) => MessageType::Notification,
            Message::Keepalive => MessageType::Keepalive,
            Message::RouteRefresh { .. } => MessageType::RouteRefresh,
        }
    }

    /// Serialise the message, framed with the 19-byte header. `four_octet` chooses
    /// the AS_PATH / AGGREGATOR width in an UPDATE (RFC 6793); other messages
    /// ignore it.
    pub fn encode(&self, four_octet: bool, add_path: AddPath) -> Vec<u8> {
        let mut out = Vec::with_capacity(HEADER_LEN + 32);
        out.extend_from_slice(&MARKER);
        out.extend_from_slice(&[0, 0]); // length, patched below
        out.push(self.message_type().as_u8());
        match self {
            Message::Open(o) => encode_open(o, &mut out),
            Message::Update(u) => encode_update(u, &mut out, four_octet, add_path),
            Message::Notification(n) => encode_notification(n, &mut out),
            Message::Keepalive => {}
            // ROUTE-REFRESH body: AFI(2) · Reserved(1) · SAFI(1) (RFC 2918 §3).
            Message::RouteRefresh { afi, safi } => {
                out.extend_from_slice(&afi.to_be_bytes());
                out.push(0);
                out.push(*safi);
            }
        }
        let len = out.len() as u16;
        out[16..18].copy_from_slice(&len.to_be_bytes());
        out
    }

    /// Parse and validate a whole BGP message from `buf`. `four_octet` chooses the
    /// AS_PATH / AGGREGATOR width when the message is an UPDATE (RFC 6793);
    /// `add_path` says which families carry RFC 7911 Path Identifiers in their NLRI.
    pub fn decode(buf: &[u8], four_octet: bool, add_path: AddPath) -> Result<Message, DecodeError> {
        if buf.len() < HEADER_LEN {
            return Err(DecodeError::TooShort);
        }
        if buf[..16] != MARKER {
            return Err(DecodeError::BadMarker);
        }
        let stated = u16::from_be_bytes([buf[16], buf[17]]);
        // RFC 4271 §4.1 fixes the message length between 19 and 4096 octets.
        // The lower bound was here; the upper was not, so this primitive would
        // decode a 60000-octet "BGP message" that no conformant speaker may
        // send. `wren-daemon` bounds it while framing, which is why nothing has
        // gone wrong in the daemon — but this is a public library entry point,
        // it is what the fuzz target drives, and a second caller would not
        // inherit the daemon's check.
        //
        // No RFC 8654 extended-message support exists in this crate (no
        // capability, no negotiation), so 4096 is the whole of the contract and
        // not merely the un-negotiated default.
        if stated as usize != buf.len()
            || (stated as usize) < HEADER_LEN
            || stated as usize > MAX_MESSAGE_LEN
        {
            return Err(DecodeError::BadLength {
                stated,
                actual: buf.len(),
            });
        }
        let mtype = MessageType::from_u8(buf[18]).ok_or(DecodeError::BadType(buf[18]))?;
        let body = &buf[HEADER_LEN..];
        Ok(match mtype {
            MessageType::Open => Message::Open(decode_open(body)?),
            MessageType::Update => Message::Update(decode_update(body, four_octet, add_path)?),
            MessageType::Notification => Message::Notification(decode_notification(body)?),
            MessageType::Keepalive => {
                if !body.is_empty() {
                    return Err(DecodeError::Malformed);
                }
                Message::Keepalive
            }
            MessageType::RouteRefresh => {
                if body.len() != 4 {
                    return Err(DecodeError::Malformed);
                }
                Message::RouteRefresh {
                    afi: u16::from_be_bytes([body[0], body[1]]),
                    // body[2] is Reserved.
                    safi: body[3],
                }
            }
        })
    }
}

// --- OPEN ------------------------------------------------------------------

fn encode_open(o: &Open, out: &mut Vec<u8>) {
    out.push(o.version);
    out.extend_from_slice(&o.my_as.to_be_bytes());
    out.extend_from_slice(&o.hold_time.to_be_bytes());
    out.extend_from_slice(&o.identifier.octets());
    let opt = encode_optional_parameters(&o.capabilities);
    out.push(opt.len() as u8);
    out.extend_from_slice(&opt);
}

fn decode_open(body: &[u8]) -> Result<Open, DecodeError> {
    if body.len() < 10 {
        return Err(DecodeError::TooShort);
    }
    let version = body[0];
    if version != VERSION {
        return Err(DecodeError::BadVersion(version));
    }
    let opt_len = body[9] as usize;
    if body.len() < 10 + opt_len {
        return Err(DecodeError::TooShort);
    }
    let my_as = u16::from_be_bytes([body[1], body[2]]);
    // RFC 7607 §2: AS 0 is reserved, and an OPEN carrying it in My Autonomous
    // System must be refused. A peer that got in with AS 0 would then be
    // compared against, and matched by, every AS-0 test in the decision
    // process — and `decode_as_segments` already refuses AS 0 inside an
    // AS_PATH, so accepting it in the OPEN was the one door left open.
    //
    // AS_TRANS (23456) is *not* this case: a four-octet speaker puts it here on
    // purpose and carries its real ASN in a capability (RFC 6793 §4.1).
    if my_as == 0 {
        return Err(DecodeError::Malformed);
    }
    let identifier = Ipv4Addr::new(body[5], body[6], body[7], body[8]);
    // RFC 6286 §2.2: "a BGP Identifier is valid if and only if it is a non-zero
    // four-octet unsigned integer" — it relaxed RFC 4271's "must be an IP
    // address of this speaker" to exactly this, so zero is the whole test and
    // nothing here may reject an address merely for looking unusual.
    //
    // It matters beyond tidiness: the identifier is a tie-breaker in the
    // decision process and one half of the collision-detection comparison, so a
    // peer offering zero wins or loses those by a value the RFC says cannot
    // occur.
    if identifier.is_unspecified() {
        return Err(DecodeError::Malformed);
    }
    Ok(Open {
        version,
        my_as,
        hold_time: u16::from_be_bytes([body[3], body[4]]),
        identifier,
        capabilities: parse_optional_parameters(&body[10..10 + opt_len]),
    })
}

// --- UPDATE ----------------------------------------------------------------

fn encode_update(u: &Update, out: &mut Vec<u8>, four_octet: bool, add_path: AddPath) {
    let ap = add_path.ipv4_unicast;

    // Withdrawn Routes, length-prefixed. With ADD-PATH each route is preceded by
    // its 4-octet Path Identifier (RFC 7911 §3).
    let mut withdrawn = Vec::new();
    for (i, p) in u.withdrawn.iter().enumerate() {
        if ap {
            let id = u.withdrawn_path_ids.get(i).copied().unwrap_or(0);
            withdrawn.extend_from_slice(&id.to_be_bytes());
        }
        encode_prefix(&mut withdrawn, p);
    }
    out.extend_from_slice(&(withdrawn.len() as u16).to_be_bytes());
    out.extend_from_slice(&withdrawn);

    // Path attributes, length-prefixed.
    let mut attrs = Vec::new();
    for a in &u.attributes {
        a.encode(&mut attrs, four_octet);
    }
    out.extend_from_slice(&(attrs.len() as u16).to_be_bytes());
    out.extend_from_slice(&attrs);

    // NLRI fills the rest (no length prefix), each preceded by its Path Identifier
    // under ADD-PATH.
    for (i, p) in u.nlri.iter().enumerate() {
        if ap {
            let id = u.nlri_path_ids.get(i).copied().unwrap_or(0);
            out.extend_from_slice(&id.to_be_bytes());
        }
        encode_prefix(out, p);
    }
}

fn decode_update(body: &[u8], four_octet: bool, add_path: AddPath) -> Result<Update, DecodeError> {
    if body.len() < 4 {
        return Err(DecodeError::TooShort);
    }
    let ap = add_path.ipv4_unicast;
    let wlen = u16::from_be_bytes([body[0], body[1]]) as usize;
    let mut off = 2;
    // A Withdrawn-Routes-Length that overruns the message is a framing error that
    // leaves the NLRI boundary undeterminable — RFC 7606 §4 keeps this session-fatal.
    if body.len() < off + wlen {
        return Err(DecodeError::Malformed);
    }
    let (mut withdrawn, mut withdrawn_path_ids) = decode_prefixes(&body[off..off + wlen], ap)?;
    off += wlen;

    if body.len() < off + 2 {
        return Err(DecodeError::TooShort);
    }
    let alen = u16::from_be_bytes([body[off], body[off + 1]]) as usize;
    off += 2;
    // Likewise, a Total-Path-Attribute-Length that overruns the message is framing-
    // fatal (RFC 7606 §4): without it we cannot find where the NLRI begins.
    if body.len() < off + alen {
        return Err(DecodeError::Malformed);
    }
    let attr_bytes = &body[off..off + alen];
    off += alen;
    // The NLRI boundary is fixed by `alen` regardless of any error *inside* the
    // attribute block, so the NLRI is always decodable here. A malformed NLRI field
    // itself, however, is framing-fatal (we cannot tell what to withdraw).
    let (nlri, nlri_path_ids) = decode_prefixes(&body[off..], ap)?;

    // RFC 7606 "treat-as-withdraw": rather than reset the session, a semantically
    // broken UPDATE has its advertised NLRI withdrawn. This applies when a path
    // attribute fails to decode (a single malformed optional attribute must not tear
    // the session down) or when a mandatory well-known attribute is missing from an
    // UPDATE that carries NLRI (RFC 4271 §5 mandates ORIGIN, AS_PATH and NEXT_HOP).
    let attributes = match decode_attributes(attr_bytes, four_octet) {
        Ok(attrs) if mandatory_attributes_present(&attrs, !nlri.is_empty()) => attrs,
        _ => {
            // Fold the NLRI into the withdrawn set and drop the attributes.
            withdrawn.extend(nlri);
            withdrawn_path_ids.extend(nlri_path_ids);
            return Ok(Update {
                withdrawn,
                attributes: Vec::new(),
                nlri: Vec::new(),
                nlri_path_ids: Vec::new(),
                withdrawn_path_ids,
            });
        }
    };

    Ok(Update {
        withdrawn,
        attributes,
        nlri,
        nlri_path_ids,
        withdrawn_path_ids,
    })
}

/// Whether an UPDATE carries any MP_REACH_NLRI — that is, whether it advertises
/// anything through the multiprotocol attribute rather than the IPv4 NLRI field.
fn advertises_multiprotocol(attrs: &[PathAttribute]) -> bool {
    attrs.iter().any(|a| {
        matches!(
            a,
            PathAttribute::MpReachNlri { .. }
                | PathAttribute::MpReachEvpn { .. }
                | PathAttribute::MpReachFlowSpec { .. }
                | PathAttribute::MpReachSrPolicy { .. }
                | PathAttribute::MpReachLinkState { .. }
        )
    })
}

/// Whether the well-known mandatory attributes this UPDATE needs are present.
/// Their absence triggers RFC 7606 treat-as-withdraw rather than a session reset.
///
/// Two advertising shapes, and they require different sets:
///
/// * **IPv4 NLRI** (RFC 4271 §5) — ORIGIN, AS_PATH *and* NEXT_HOP.
/// * **MP_REACH_NLRI** (RFC 4760 §3) — ORIGIN and AS_PATH. Not NEXT_HOP: the
///   next hop for those routes is carried *inside* MP_REACH, and §3 says such an
///   UPDATE "should not" carry the NEXT_HOP attribute at all, so requiring it
///   would reject every conformant IPv6 advertisement in existence.
///
/// The MP case was not checked. The test was `nlri.is_empty()`, and an MP-only
/// UPDATE has an empty IPv4 NLRI field — so the whole check was skipped and a
/// peer could advertise IPv6, EVPN, FlowSpec, SR-Policy or Link-State routes
/// with no ORIGIN and no AS_PATH at all. An AS_PATH nobody sent is an AS_PATH
/// with no loop to detect and no length to compare.
///
/// LOCAL_PREF is deliberately not checked here even though §3 requires it on an
/// IBGP MP UPDATE: whether a session is internal is not something the wire
/// format knows, and this function has only the bytes.
fn mandatory_attributes_present(attrs: &[PathAttribute], has_ipv4_nlri: bool) -> bool {
    let mp = advertises_multiprotocol(attrs);
    if !has_ipv4_nlri && !mp {
        // Advertises nothing: a pure withdraw, or an End-of-RIB marker. There is
        // no route for an attribute to describe.
        return true;
    }
    let mut origin = false;
    let mut as_path = false;
    let mut next_hop = false;
    for a in attrs {
        match a {
            PathAttribute::Origin(_) => origin = true,
            PathAttribute::AsPath(_) => as_path = true,
            PathAttribute::NextHop(_) => next_hop = true,
            _ => {}
        }
    }
    origin && as_path && (!has_ipv4_nlri || next_hop)
}

/// Decode a run of NLRI prefixes (IPv4 base NLRI). With `add_path`, each prefix is
/// preceded by a 4-octet Path Identifier (RFC 7911 §3); the returned id vector is
/// then aligned 1:1 with the prefixes (and empty otherwise).
fn decode_prefixes(mut buf: &[u8], add_path: bool) -> Result<(Vec<Prefix>, Vec<u32>), DecodeError> {
    let mut out = Vec::new();
    let mut ids = Vec::new();
    while !buf.is_empty() {
        if add_path {
            if buf.len() < 4 {
                return Err(DecodeError::Malformed);
            }
            ids.push(u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]));
            buf = &buf[4..];
        }
        let (p, used) = decode_prefix(buf).ok_or(DecodeError::Malformed)?;
        out.push(p);
        buf = &buf[used..];
    }
    Ok((out, ids))
}

fn decode_attributes(mut buf: &[u8], four_octet: bool) -> Result<Vec<PathAttribute>, DecodeError> {
    let mut out = Vec::new();
    // RFC 7606 §3(g): a path attribute (any type) that appears more than once in
    // one UPDATE makes the UPDATE malformed — reject it rather than silently
    // keeping the first or last copy.
    let mut seen = [false; 256];
    while !buf.is_empty() {
        let (outcome, used) =
            PathAttribute::decode(buf, four_octet).ok_or(DecodeError::Malformed)?;
        // §3(g) counts an attribute that *appeared*, so a discarded one still
        // occupies its type code.
        let tc = match &outcome {
            AttrOutcome::Keep(a) => a.type_code(),
            AttrOutcome::Discard { type_code } => *type_code,
        } as usize;
        if seen[tc] {
            return Err(DecodeError::Malformed);
        }
        seen[tc] = true;
        // RFC 7606 §2 "attribute discard": drop this attribute alone and keep
        // processing — the UPDATE's routes are unaffected.
        if let AttrOutcome::Keep(a) = outcome {
            out.push(a);
        }
        buf = &buf[used..];
    }
    Ok(out)
}

// --- NOTIFICATION ----------------------------------------------------------

fn encode_notification(n: &Notification, out: &mut Vec<u8>) {
    out.push(n.code);
    out.push(n.subcode);
    out.extend_from_slice(&n.data);
}

fn decode_notification(body: &[u8]) -> Result<Notification, DecodeError> {
    if body.len() < 2 {
        return Err(DecodeError::TooShort);
    }
    Ok(Notification {
        code: body[0],
        subcode: body[1],
        data: body[2..].to_vec(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attr::{AsPathSegment, Origin, PathAttribute};
    use crate::DEFAULT_HOLD_TIME;

    #[test]
    fn duplicate_attribute_is_rejected_rfc7606() {
        // A single ORIGIN decodes; two ORIGINs in one attribute list make the
        // UPDATE malformed (RFC 7606 §3(g)) rather than silently first/last-wins.
        assert!(decode_attributes(&[0x40, 1, 1, 0], false).is_ok());
        assert!(decode_attributes(&[0x40, 1, 1, 0, 0x40, 1, 1, 0], false).is_err());
    }

    fn ip(o: [u8; 4]) -> Ipv4Addr {
        Ipv4Addr::from(o)
    }
    fn p(s: &str) -> Prefix {
        s.parse().unwrap()
    }

    fn roundtrip(msg: Message) {
        // Default to the 4-octet wire width; messages without AS_PATH are width-
        // agnostic anyway.
        roundtrip_w(msg, true);
    }

    fn roundtrip_w(msg: Message, four_octet: bool) {
        let bytes = msg.encode(four_octet, AddPath::NONE);
        assert_eq!(&bytes[..16], &MARKER);
        assert_eq!(u16::from_be_bytes([bytes[16], bytes[17]]) as usize, bytes.len());
        assert_eq!(Message::decode(&bytes, four_octet, AddPath::NONE).expect("decodes"), msg);
    }

    #[test]
    fn keepalive_is_header_only() {
        let bytes = Message::Keepalive.encode(true, AddPath::NONE);
        assert_eq!(bytes.len(), HEADER_LEN);
        roundtrip(Message::Keepalive);
    }

    /// Frame an UPDATE `body` (everything after the message type octet) into a full
    /// BGP message: marker + total-length + type(2) + body.
    fn frame_update(body: &[u8]) -> Vec<u8> {
        let mut m = Vec::with_capacity(HEADER_LEN + body.len());
        m.extend_from_slice(&MARKER);
        m.extend_from_slice(&((HEADER_LEN + body.len()) as u16).to_be_bytes());
        m.push(2); // UPDATE
        m.extend_from_slice(body);
        m
    }

    /// Assemble an UPDATE body from an attribute block and one IPv4 NLRI prefix
    /// (10.0.0.0/24), with no withdrawn routes.
    fn update_body(attrs: &[u8]) -> Vec<u8> {
        let mut body = vec![0, 0]; // Withdrawn Routes Length = 0
        body.extend_from_slice(&(attrs.len() as u16).to_be_bytes());
        body.extend_from_slice(attrs);
        body.extend_from_slice(&[24, 10, 0, 0]); // NLRI 10.0.0.0/24
        body
    }

    #[test]
    fn malformed_optional_attribute_treats_update_as_withdraw() {
        // A syntactically-valid path (ORIGIN, AS_PATH, NEXT_HOP) plus a *malformed*
        // optional MED (length 3, but MED must be 4 octets). RFC 7606: this must not
        // reset the session — the UPDATE's NLRI is withdrawn instead.
        let mut attrs = Vec::new();
        PathAttribute::Origin(Origin::Igp).encode(&mut attrs, true);
        PathAttribute::AsPath(vec![AsPathSegment::Sequence(vec![65001])]).encode(&mut attrs, true);
        PathAttribute::NextHop(ip([10, 0, 0, 1])).encode(&mut attrs, true);
        attrs.extend_from_slice(&[0x80, 4, 3, 0, 0, 0]); // MED: optional, type 4, len 3

        let msg = frame_update(&update_body(&attrs));
        let decoded = Message::decode(&msg, true, AddPath::NONE).expect("decodes, not a reset");
        let Message::Update(u) = decoded else { panic!("expected UPDATE") };
        assert_eq!(u.withdrawn, vec![p("10.0.0.0/24")], "NLRI must be withdrawn");
        assert!(u.nlri.is_empty(), "no NLRI is advertised");
        assert!(u.attributes.is_empty(), "attributes are dropped on treat-as-withdraw");
    }

    #[test]
    fn missing_mandatory_attribute_treats_update_as_withdraw() {
        // ORIGIN + NEXT_HOP present but AS_PATH missing, with NLRI: a well-known
        // mandatory attribute is absent, so RFC 7606 treat-as-withdraw applies rather
        // than a NOTIFICATION/reset.
        let mut attrs = Vec::new();
        PathAttribute::Origin(Origin::Igp).encode(&mut attrs, true);
        PathAttribute::NextHop(ip([10, 0, 0, 1])).encode(&mut attrs, true);

        let msg = frame_update(&update_body(&attrs));
        let decoded = Message::decode(&msg, true, AddPath::NONE).expect("decodes, not a reset");
        let Message::Update(u) = decoded else { panic!("expected UPDATE") };
        assert_eq!(u.withdrawn, vec![p("10.0.0.0/24")], "NLRI must be withdrawn");
        assert!(u.nlri.is_empty());
        assert!(u.attributes.is_empty());
    }

    /// An UPDATE body carrying only an attribute block — no IPv4 NLRI at all,
    /// which is the shape every IPv6/EVPN/FlowSpec advertisement has.
    fn mp_only_body(attrs: &[u8]) -> Vec<u8> {
        let mut body = vec![0, 0]; // Withdrawn Routes Length = 0
        body.extend_from_slice(&(attrs.len() as u16).to_be_bytes());
        body.extend_from_slice(attrs);
        body
    }

    /// A well-formed MP_REACH for one IPv6 unicast prefix, as raw attribute
    /// bytes: flags · type 14 · len · AFI(2) · SAFI · NHLen · NextHop · Reserved
    /// · NLRI.
    fn mp_reach_ipv6(nh: &[u8]) -> Vec<u8> {
        let mut value = vec![0, 2, 1, nh.len() as u8];
        value.extend_from_slice(nh);
        value.push(0); // Reserved
        value.extend_from_slice(&[64, 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0]); // 2001:db8::/64
        let mut out = vec![0x80, 14, value.len() as u8];
        out.extend_from_slice(&value);
        out
    }

    #[test]
    fn an_mp_only_update_still_needs_origin_and_as_path_rfc4760() {
        // The hole: the mandatory-attribute check was gated on the *IPv4* NLRI
        // field being non-empty, and an MP-only UPDATE leaves that field empty —
        // so the check never ran and a peer could advertise IPv6 (or EVPN, or
        // FlowSpec) with no ORIGIN and no AS_PATH whatsoever. An AS_PATH nobody
        // sent is an AS_PATH with no loop to detect and no length to compare.
        //
        // RFC 4760 §3 requires both on any UPDATE carrying MP_REACH_NLRI.
        let bare = mp_reach_ipv6(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        let decoded = Message::decode(&frame_update(&mp_only_body(&bare)), true, AddPath::NONE)
            .expect("treat-as-withdraw, not a session reset");
        let Message::Update(u) = decoded else { panic!("expected UPDATE") };
        assert!(
            u.attributes.is_empty(),
            "an MP_REACH with no ORIGIN or AS_PATH was accepted: {:?}",
            u.attributes
        );

        // And with them present it is accepted, so the check is about the
        // attributes and not about MP_REACH itself.
        let mut ok = Vec::new();
        PathAttribute::Origin(Origin::Igp).encode(&mut ok, true);
        PathAttribute::AsPath(vec![AsPathSegment::Sequence(vec![65001])]).encode(&mut ok, true);
        ok.extend_from_slice(&bare);
        let decoded = Message::decode(&frame_update(&mp_only_body(&ok)), true, AddPath::NONE)
            .expect("decodes");
        let Message::Update(u) = decoded else { panic!("expected UPDATE") };
        assert!(
            u.attributes.iter().any(|a| matches!(a, PathAttribute::MpReachNlri { .. })),
            "a complete MP UPDATE was rejected: {:?}",
            u.attributes
        );
    }

    #[test]
    fn an_mp_only_update_does_not_need_a_next_hop_attribute_rfc4760() {
        // The other half of RFC 4760 §3, and the reason the mandatory set had to
        // be split rather than simply applied: the next hop for MP routes is
        // carried *inside* MP_REACH, and §3 says such an UPDATE "should not"
        // carry the NEXT_HOP attribute at all. Requiring it would reject every
        // conformant IPv6 advertisement in existence.
        let mut attrs = Vec::new();
        PathAttribute::Origin(Origin::Igp).encode(&mut attrs, true);
        PathAttribute::AsPath(vec![AsPathSegment::Sequence(vec![65001])]).encode(&mut attrs, true);
        attrs.extend_from_slice(&mp_reach_ipv6(&[
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
        ]));
        let decoded = Message::decode(&frame_update(&mp_only_body(&attrs)), true, AddPath::NONE)
            .expect("decodes");
        let Message::Update(u) = decoded else { panic!("expected UPDATE") };
        assert!(
            u.attributes.iter().any(|a| matches!(a, PathAttribute::MpReachNlri { .. })),
            "an MP UPDATE was rejected for lacking a NEXT_HOP it must not carry"
        );
    }

    #[test]
    fn a_message_longer_than_the_contract_allows_is_refused_rfc4271() {
        // RFC 4271 §4.1 bounds a BGP message at 4096 octets, and this crate
        // negotiates no RFC 8654 extended-message capability, so 4096 is the
        // whole of it. The lower bound was checked here and the upper was not;
        // `wren-daemon` bounds it while framing, so the daemon was never
        // exposed — but this is the public entry point and what the fuzz target
        // drives.
        let body = vec![0u8; MAX_MESSAGE_LEN + 1 - HEADER_LEN];
        let mut m = Vec::new();
        m.extend_from_slice(&MARKER);
        m.extend_from_slice(&((HEADER_LEN + body.len()) as u16).to_be_bytes());
        m.push(4); // KEEPALIVE, so only the length can be what is wrong
        m.extend_from_slice(&body);
        assert_eq!(m.len(), MAX_MESSAGE_LEN + 1);
        assert!(
            matches!(Message::decode(&m, true, AddPath::NONE), Err(DecodeError::BadLength { .. })),
            "a {}-octet message was accepted",
            m.len()
        );

        // Exactly 4096 is still legal — the bound is inclusive.
        let body = vec![0u8; MAX_MESSAGE_LEN - HEADER_LEN];
        let mut m = Vec::new();
        m.extend_from_slice(&MARKER);
        m.extend_from_slice(&(MAX_MESSAGE_LEN as u16).to_be_bytes());
        m.push(2); // UPDATE — a KEEPALIVE must have an empty body
        m.extend_from_slice(&body);
        assert!(
            !matches!(
                Message::decode(&m, true, AddPath::NONE),
                Err(DecodeError::BadLength { .. })
            ),
            "the largest legal message was refused for its length"
        );
    }

    #[test]
    fn an_open_with_a_reserved_as_or_a_zero_identifier_is_refused() {
        // RFC 7607 §2: AS 0 is reserved and an OPEN carrying it must be refused.
        // RFC 6286 §2.2: a BGP Identifier is valid iff it is a non-zero 4-octet
        // integer. Neither was checked, and both feed comparisons that assume
        // the value cannot occur — AS 0 every AS-0 test in the decision process,
        // the identifier the tie-break and collision detection.
        let open = |my_as: u16, id: [u8; 4]| {
            let mut body = vec![VERSION];
            body.extend_from_slice(&my_as.to_be_bytes());
            body.extend_from_slice(&180u16.to_be_bytes());
            body.extend_from_slice(&id);
            body.push(0); // no optional parameters
            let mut m = Vec::new();
            m.extend_from_slice(&MARKER);
            m.extend_from_slice(&((HEADER_LEN + body.len()) as u16).to_be_bytes());
            m.push(1); // OPEN
            m.extend_from_slice(&body);
            Message::decode(&m, true, AddPath::NONE)
        };
        assert!(open(0, [10, 0, 0, 1]).is_err(), "AS 0 was accepted in an OPEN");
        assert!(open(65001, [0, 0, 0, 0]).is_err(), "a zero BGP Identifier was accepted");
        // AS_TRANS is not this case: a four-octet speaker puts it here on purpose.
        assert!(open(23456, [10, 0, 0, 1]).is_ok(), "AS_TRANS was refused");
        assert!(open(65001, [10, 0, 0, 1]).is_ok(), "a valid OPEN was refused");
    }

    #[test]
    fn atomic_aggregate_wrong_length_is_discard_not_withdraw_rfc7606() {
        // RFC 7606 §7.6/§7.7: ATOMIC_AGGREGATE and AGGREGATOR cannot influence route
        // selection, so a malformed one is discarded on its own — the UPDATE's NLRI
        // stays *advertised* rather than being withdrawn as a malformed MED would be.
        // type 6 len 1 (must be 0); type 7 len 10 (must be 8 at a 4-octet AS width).
        for broken in [vec![0x40, 6, 1, 0], vec![0xC0, 7, 10, 0, 0, 0, 1, 10, 0, 0, 1, 9, 9]] {
            let type_code = broken[1];
            let mut attrs = Vec::new();
            PathAttribute::Origin(Origin::Igp).encode(&mut attrs, true);
            PathAttribute::AsPath(vec![AsPathSegment::Sequence(vec![65001])])
                .encode(&mut attrs, true);
            PathAttribute::NextHop(ip([10, 0, 0, 1])).encode(&mut attrs, true);
            attrs.extend_from_slice(&broken);

            let msg = frame_update(&update_body(&attrs));
            let Message::Update(u) = Message::decode(&msg, true, AddPath::NONE).expect("decodes")
            else {
                panic!("expected UPDATE")
            };
            assert_eq!(u.nlri, vec![p("10.0.0.0/24")], "type {type_code}: NLRI is kept");
            assert!(u.withdrawn.is_empty(), "type {type_code}: nothing withdrawn");
            assert_eq!(u.attributes.len(), 3, "type {type_code}: only the good three");
            assert!(
                !u.attributes.iter().any(|a| a.type_code() == type_code),
                "type {type_code}: the malformed attribute itself is gone"
            );
        }
    }

    #[test]
    fn a_discarded_attribute_still_counts_as_a_duplicate_rfc7606() {
        // RFC 7606 §3(g) is about an attribute *appearing* twice, so discarding the
        // second copy must not hide the duplicate. Two malformed ATOMIC_AGGREGATEs
        // make the UPDATE malformed even though neither would be kept.
        assert!(decode_attributes(&[0x40, 6, 1, 0], false).is_ok());
        assert!(decode_attributes(&[0x40, 6, 1, 0, 0x40, 6, 1, 0], false).is_err());
    }

    #[test]
    fn malformed_mp_attributes_are_treated_as_withdraw() {
        // RFC 7606 §7.12 hands MP_UNREACH_NLRI (type 15) to the general rules of
        // §3/§4, so a malformed one is treat-as-withdraw and must never reset the
        // session.
        //
        // MP_REACH_NLRI (type 14) is a DELIBERATE DEVIATION: because the Next Hop
        // precedes the NLRI, §7.11 requires "session reset" or "AFI/SAFI disable".
        // wren is intentionally more lenient and withdraws instead, so a peer emitting
        // a broken MP_REACH cannot tear the session down; AFI/SAFI disable would be
        // the conforming replacement. This test pins that choice so it stays explicit.
        //
        // Both attributes are truncated below their fixed preamble (MP_REACH needs
        // AFI/SAFI/NextHop-Length plus the Reserved octet, MP_UNREACH needs AFI/SAFI),
        // so it is the length that makes them malformed and not their flags, which are
        // the canonical 0x80.
        let mut base = Vec::new();
        PathAttribute::Origin(Origin::Igp).encode(&mut base, true);
        PathAttribute::AsPath(vec![AsPathSegment::Sequence(vec![65001])]).encode(&mut base, true);
        PathAttribute::NextHop(ip([10, 0, 0, 1])).encode(&mut base, true);

        for type_code in [14u8, 15] {
            let broken = [0x80, type_code, 2, 0, 2];

            // (a) An MP-only UPDATE carries nothing outside the broken attribute, so
            // the requirement is simply that decoding succeeds and drops it.
            let mut body = vec![0, 0]; // Withdrawn Routes Length = 0
            body.extend_from_slice(&(broken.len() as u16).to_be_bytes());
            body.extend_from_slice(&broken);
            let msg = frame_update(&body);
            let decoded = Message::decode(&msg, true, AddPath::NONE).expect("decodes, not a reset");
            let Message::Update(u) = decoded else { panic!("expected UPDATE") };
            assert!(u.attributes.is_empty(), "the malformed MP attribute is dropped");
            assert!(u.nlri.is_empty());
            assert!(u.withdrawn.is_empty());

            // (b) The same attribute beside a well-formed IPv4 path: that NLRI is
            // withdrawn rather than advertised, and the session still survives.
            let mut attrs = base.clone();
            attrs.extend_from_slice(&broken);
            let msg = frame_update(&update_body(&attrs));
            let decoded = Message::decode(&msg, true, AddPath::NONE).expect("decodes, not a reset");
            let Message::Update(u) = decoded else { panic!("expected UPDATE") };
            assert_eq!(u.withdrawn, vec![p("10.0.0.0/24")], "NLRI must be withdrawn");
            assert!(u.nlri.is_empty());
        }
    }

    #[test]
    fn well_formed_update_still_decodes_normally() {
        // The treat-as-withdraw path must not disturb a valid UPDATE: all mandatory
        // attributes present and well-formed → the NLRI is advertised as usual.
        let mut attrs = Vec::new();
        PathAttribute::Origin(Origin::Igp).encode(&mut attrs, true);
        PathAttribute::AsPath(vec![AsPathSegment::Sequence(vec![65001])]).encode(&mut attrs, true);
        PathAttribute::NextHop(ip([10, 0, 0, 1])).encode(&mut attrs, true);

        let msg = frame_update(&update_body(&attrs));
        let Message::Update(u) = Message::decode(&msg, true, AddPath::NONE).expect("decodes") else {
            panic!("expected UPDATE")
        };
        assert_eq!(u.nlri, vec![p("10.0.0.0/24")], "NLRI is advertised");
        assert!(u.withdrawn.is_empty(), "nothing withdrawn");
        assert_eq!(u.attributes.len(), 3);
    }

    #[test]
    fn route_refresh_roundtrips() {
        use crate::{AFI_IPV4, AFI_IPV6, SAFI_UNICAST};
        // Header (19) + AFI(2) + Reserved(1) + SAFI(1) = 23 octets, type 5.
        let bytes = Message::RouteRefresh { afi: AFI_IPV4, safi: SAFI_UNICAST }.encode(true, AddPath::NONE);
        assert_eq!(bytes.len(), HEADER_LEN + 4);
        assert_eq!(bytes[18], 5); // ROUTE-REFRESH type code
        roundtrip(Message::RouteRefresh { afi: AFI_IPV4, safi: SAFI_UNICAST });
        roundtrip(Message::RouteRefresh { afi: AFI_IPV6, safi: SAFI_UNICAST });
        // A wrong-length body is rejected.
        let mut short = Message::RouteRefresh { afi: AFI_IPV4, safi: SAFI_UNICAST }.encode(true, AddPath::NONE);
        short.truncate(HEADER_LEN + 3);
        short[17] = (HEADER_LEN + 3) as u8;
        assert!(matches!(Message::decode(&short, true, AddPath::NONE), Err(DecodeError::Malformed)));
    }

    #[test]
    fn open_advertises_route_refresh_capability() {
        let open = Open::new(VERSION, 65001, DEFAULT_HOLD_TIME, ip([10, 0, 0, 1]));
        assert!(open.supports_route_refresh());
    }

    #[test]
    fn open_advertises_graceful_restart_capability() {
        use crate::{AFI_IPV4, AFI_IPV6, DEFAULT_RESTART_TIME, SAFI_UNICAST};
        let open = Open::new(VERSION, 65001, DEFAULT_HOLD_TIME, ip([10, 0, 0, 1]));
        assert!(open.supports_graceful_restart());
        assert_eq!(open.gr_restart_time(), Some(DEFAULT_RESTART_TIME));
        // Forwarding is preserved for both unicast families …
        assert!(open.gr_forwarding_preserved(AFI_IPV4, SAFI_UNICAST));
        assert!(open.gr_forwarding_preserved(AFI_IPV6, SAFI_UNICAST));
        // … but not for an unadvertised family.
        assert!(!open.gr_forwarding_preserved(AFI_IPV6, 2));
        roundtrip(Message::Open(open));
    }

    #[test]
    fn end_of_rib_markers_are_recognised() {
        use crate::{AFI_IPV4, AFI_IPV6, SAFI_UNICAST};
        // IPv4-unicast marker: a completely empty UPDATE.
        let v4 = Update::end_of_rib_marker(AFI_IPV4, SAFI_UNICAST);
        assert_eq!(v4, Update::default());
        assert_eq!(v4.end_of_rib(), Some((AFI_IPV4, SAFI_UNICAST)));
        roundtrip(Message::Update(v4));
        // IPv6-unicast marker: an empty MP_UNREACH_NLRI, and it round-trips.
        let v6 = Update::end_of_rib_marker(AFI_IPV6, SAFI_UNICAST);
        assert_eq!(v6.end_of_rib(), Some((AFI_IPV6, SAFI_UNICAST)));
        roundtrip(Message::Update(v6));
        // A real withdrawal is not an End-of-RIB marker.
        let real = Update { withdrawn: vec![p("10.0.0.0/8")], ..Update::default() };
        assert_eq!(real.end_of_rib(), None);
    }

    #[test]
    fn open_roundtrips_with_four_octet_as_capability() {
        let open = Open::new(VERSION, 196_618, DEFAULT_HOLD_TIME, ip([10, 0, 0, 1]));
        // A 4-octet AS is signalled as AS_TRANS on the wire, real AS in the cap.
        assert_eq!(open.my_as, crate::AS_TRANS);
        assert_eq!(open.effective_as(), 196_618);
        assert!(open.supports_four_octet_as());
        roundtrip(Message::Open(open));

        // A 2-octet AS sits directly in my_as and still advertises the capability.
        let open = Open::new(VERSION, 65001, DEFAULT_HOLD_TIME, ip([10, 0, 0, 1]));
        assert_eq!(open.my_as, 65001);
        assert_eq!(open.effective_as(), 65001);
        roundtrip(Message::Open(open));
    }

    #[test]
    fn open_advertises_and_detects_multiprotocol() {
        use crate::{AFI_IPV4, AFI_IPV6, SAFI_UNICAST};
        // Open::new advertises both unicast families out of the box. IPv4 is
        // named rather than left to RFC 4760 §8's "no MP capability at all"
        // default, which this OPEN forfeits the moment it carries the IPv6 entry
        // — a peer intersecting the advertised families would otherwise find no
        // IPv4 in the set and refuse the family outright.
        let open = Open::new(VERSION, 65001, DEFAULT_HOLD_TIME, ip([10, 0, 0, 1]));
        assert!(open.supports_multiprotocol(AFI_IPV4, SAFI_UNICAST));
        assert!(open.supports_multiprotocol(AFI_IPV6, SAFI_UNICAST));
        // A family nobody offered is still absent.
        assert!(!open.supports_multiprotocol(AFI_IPV6, crate::SAFI_FLOWSPEC));
        roundtrip(Message::Open(open));
    }

    #[test]
    fn update_roundtrips_with_attributes_and_nlri() {
        roundtrip(Message::Update(Update {
            withdrawn: vec![p("198.51.100.0/24")],
            attributes: vec![
                PathAttribute::Origin(Origin::Igp),
                PathAttribute::AsPath(vec![AsPathSegment::Sequence(vec![65001, 65002])]),
                PathAttribute::NextHop(ip([192, 0, 2, 1])),
                PathAttribute::LocalPref(100),
            ],
            nlri: vec![p("10.0.0.0/8"), p("203.0.113.0/24")],
            ..Default::default()
        }));
    }

    #[test]
    fn empty_update_is_a_keepalive_of_routes() {
        // A withdrawn-only / empty UPDATE is legal.
        roundtrip(Message::Update(Update::default()));
    }

    #[test]
    fn update_roundtrips_with_add_path_identifiers() {
        // With ADD-PATH (RFC 7911) every NLRI / withdrawn route on the wire carries
        // a 4-octet Path Identifier; the codec must round-trip them aligned 1:1.
        let ap = AddPath::ipv4(true);
        let update = Update {
            withdrawn: vec![p("198.51.100.0/24")],
            withdrawn_path_ids: vec![7],
            attributes: vec![
                PathAttribute::Origin(Origin::Igp),
                PathAttribute::AsPath(vec![AsPathSegment::Sequence(vec![65001])]),
                PathAttribute::NextHop(ip([192, 0, 2, 1])),
            ],
            nlri: vec![p("10.0.0.0/8"), p("10.0.0.0/8")],
            nlri_path_ids: vec![1, 2],
        };
        let bytes = Message::Update(update.clone()).encode(false, ap);
        let Message::Update(decoded) = Message::decode(&bytes, false, ap).unwrap() else {
            panic!("not an update");
        };
        assert_eq!(decoded.nlri, update.nlri);
        assert_eq!(decoded.nlri_path_ids, vec![1, 2]);
        assert_eq!(decoded.withdrawn_path_ids, vec![7]);
        // The same two prefixes with DIFFERENT path-ids are two distinct paths —
        // exactly what ADD-PATH exists to carry.
        assert_eq!(decoded.nlri.len(), 2);

        // Decoded WITHOUT add-path the 4-octet ids would be misread as prefixes —
        // proving the flag is required out-of-band (not self-describing).
        assert!(Message::decode(&bytes, false, AddPath::NONE)
            .map(|m| matches!(m, Message::Update(u) if u.nlri != update.nlri))
            .unwrap_or(true));
    }

    #[test]
    fn four_octet_speaker_interops_with_a_legacy_peer() {
        use crate::attr::reconstruct_as_path;

        // A 4-octet speaker (AS 196618) advertises toward a legacy 2-octet peer:
        // the AS_PATH is sent 2-octet (AS_TRANS in place of the big AS) and the
        // real value rides in AS4_PATH (RFC 6793).
        let update = Update {
            withdrawn: vec![],
            attributes: vec![
                PathAttribute::Origin(Origin::Igp),
                PathAttribute::AsPath(vec![AsPathSegment::Sequence(vec![196_618, 65001])]),
                PathAttribute::As4Path(vec![AsPathSegment::Sequence(vec![196_618, 65001])]),
                PathAttribute::NextHop(ip([192, 0, 2, 1])),
            ],
            nlri: vec![p("10.0.0.0/8")],
            ..Default::default()
        };
        // Encode toward the legacy peer (four_octet = false).
        let bytes = Message::Update(update).encode(false, AddPath::NONE);
        let Message::Update(decoded) = Message::decode(&bytes, false, AddPath::NONE).unwrap() else {
            panic!("not an update");
        };

        // On the wire AS_PATH collapsed the 4-octet AS to AS_TRANS …
        let as_path = decoded.attributes.iter().find_map(|a| match a {
            PathAttribute::AsPath(s) => Some(s.clone()),
            _ => None,
        });
        assert_eq!(
            as_path,
            Some(vec![AsPathSegment::Sequence(vec![crate::AS_TRANS as u32, 65001])])
        );
        // … but AS4_PATH preserved the real value, and reconstruction restores it.
        let as4 = decoded.attributes.iter().find_map(|a| match a {
            PathAttribute::As4Path(s) => Some(s.clone()),
            _ => None,
        });
        assert_eq!(
            reconstruct_as_path(&as_path.unwrap(), &as4.unwrap()),
            vec![AsPathSegment::Sequence(vec![196_618, 65001])]
        );
    }

    #[test]
    fn notification_roundtrips() {
        roundtrip(Message::Notification(Notification {
            code: 6,
            subcode: 2,
            data: vec![0xde, 0xad],
        }));
    }

    #[test]
    fn decode_rejects_bad_marker_length_type_version() {
        let mut bytes = Message::Keepalive.encode(true, AddPath::NONE);
        bytes[0] ^= 0x01;
        assert_eq!(Message::decode(&bytes, true, AddPath::NONE), Err(DecodeError::BadMarker));

        let mut bytes = Message::Keepalive.encode(true, AddPath::NONE);
        bytes.push(0); // length field no longer matches
        assert!(matches!(Message::decode(&bytes, true, AddPath::NONE), Err(DecodeError::BadLength { .. })));

        let mut bytes = Message::Keepalive.encode(true, AddPath::NONE);
        bytes[18] = 9; // bad type
        assert_eq!(Message::decode(&bytes, true, AddPath::NONE), Err(DecodeError::BadType(9)));

        let mut bytes = Message::Open(Open::new(VERSION, 1, 90, ip([1, 1, 1, 1]))).encode(true, AddPath::NONE);
        bytes[HEADER_LEN] = 3; // version 3
        assert_eq!(Message::decode(&bytes, true, AddPath::NONE), Err(DecodeError::BadVersion(3)));
    }

    // =======================================================================
    // Byte-offset assertions (RFC 4271 §4)
    //
    // The `roundtrip` helper above encodes with wren and decodes with wren; it
    // checks the marker and the length field and nothing else. A field written
    // at the wrong offset is invisible to it, because the decoder reads it back
    // from the same wrong offset. The tests below name the offset the RFC names.
    // =======================================================================

    /// RFC 4271 §4.1: every message opens with a 16-octet all-ones Marker, a
    /// 2-octet Length at 16..18 covering the whole message, and a 1-octet Type
    /// at 18. §4.1 assigns OPEN 1, UPDATE 2, NOTIFICATION 3, KEEPALIVE 4, and
    /// RFC 2918 adds ROUTE-REFRESH 5.
    #[test]
    fn the_message_header_and_type_codes_are_the_ones_the_rfc_assigns() {
        for (t, code) in [
            (MessageType::Open, 1u8),
            (MessageType::Update, 2),
            (MessageType::Notification, 3),
            (MessageType::Keepalive, 4),
            (MessageType::RouteRefresh, 5),
        ] {
            assert_eq!(t.as_u8(), code, "{t:?} is message type {code}");
            assert_eq!(MessageType::from_u8(code), Some(t));
        }
        assert_eq!(MessageType::from_u8(0), None);
        assert_eq!(MessageType::from_u8(6), None);

        let b = Message::Keepalive.encode(true, AddPath::NONE);
        assert_eq!(&b[0..16], &[0xffu8; 16], "the Marker is 16 octets of 0xff");
        assert_eq!(&b[16..18], &[0, 19], "Length is bytes 16..18; a KEEPALIVE is 19");
        assert_eq!(b[18], 4, "Type is byte 18");
        assert_eq!(b.len(), 19, "a KEEPALIVE is header-only");
    }

    /// RFC 4271 §4.2: the OPEN body is Version 19, My Autonomous System 20..22,
    /// Hold Time 22..24, BGP Identifier 24..28, Optional Parameters Length 28,
    /// then the parameters.
    ///
    /// My AS and Hold Time transposed round-trips perfectly and is fatal: the
    /// peer reads the AS number as a hold time (and vice versa), so §6.2's
    /// "Bad Peer AS" check fires and the session never opens. Note also that
    /// `my_as` is the *2-octet* field even for a 4-octet speaker — the real AS
    /// travels in the capability — so `AS_TRANS` (23456) is what a 4-octet AS
    /// must put here.
    #[test]
    fn an_open_body_is_encoded_in_the_rfc_field_order() {
        let msg = Message::Open(Open {
            version: 4,
            my_as: 0xfde8,     // 65000
            hold_time: 0x005a, // 90
            identifier: ip([10, 0, 0, 1]),
            capabilities: vec![],
        });
        let b = msg.encode(true, AddPath::NONE);
        assert_eq!(b[18], 1, "an OPEN is Type 1");
        assert_eq!(b[19], 4, "Version is byte 19");
        assert_eq!(&b[20..22], &[0xfd, 0xe8], "My Autonomous System is bytes 20..22");
        assert_eq!(&b[22..24], &[0x00, 0x5a], "Hold Time is bytes 22..24");
        assert_eq!(&b[24..28], &[10, 0, 0, 1], "BGP Identifier is bytes 24..28");
        assert_eq!(b[28], 0, "Optional Parameters Length is byte 28");
        assert_eq!(b.len(), 29, "an OPEN with no parameters is 29 octets");
    }

    /// RFC 4271 §4.3: the UPDATE body is Withdrawn Routes Length 19..21, the
    /// withdrawn routes, Total Path Attribute Length, the attributes, then the
    /// NLRI to the end of the message — the NLRI carries no length of its own
    /// and is derived from the header Length.
    ///
    /// Swap the two length fields and a peer reads the attribute block as
    /// withdrawn routes: it withdraws prefixes nobody advertised and installs
    /// nothing. Wren's own decoder, reading them back in the same order, sees a
    /// perfectly good UPDATE.
    #[test]
    fn an_update_body_is_encoded_in_the_rfc_field_order() {
        let msg = Message::Update(Update {
            withdrawn: vec![p("192.0.2.0/24")],
            attributes: vec![PathAttribute::Origin(Origin::Igp)],
            nlri: vec![p("10.0.0.0/24")],
            nlri_path_ids: vec![],
            withdrawn_path_ids: vec![],
        });
        let b = msg.encode(true, AddPath::NONE);
        assert_eq!(b[18], 2, "an UPDATE is Type 2");
        // One withdrawn /24 is 4 octets: a length byte plus three prefix octets.
        assert_eq!(&b[19..21], &[0, 4], "Withdrawn Routes Length is bytes 19..21");
        assert_eq!(&b[21..25], &[24, 192, 0, 2], "the withdrawn prefix follows it");
        // ORIGIN is 4 octets on the wire: flags, type, length, value.
        assert_eq!(&b[25..27], &[0, 4], "Total Path Attribute Length follows the withdrawals");
        assert_eq!(&b[27..31], &[0x40, 1, 1, 0], "the ORIGIN attribute");
        assert_eq!(&b[31..], &[24, 10, 0, 0], "the NLRI runs to the end of the message");
        assert_eq!(
            u16::from_be_bytes([b[16], b[17]]) as usize,
            b.len(),
            "only the header Length bounds the NLRI"
        );

        // An UPDATE with nothing in it is the 19-octet header plus two zero
        // length fields — the shape of an End-of-RIB marker (RFC 4724 §2).
        let eor = Message::Update(Update {
            withdrawn: vec![],
            attributes: vec![],
            nlri: vec![],
            nlri_path_ids: vec![],
            withdrawn_path_ids: vec![],
        })
        .encode(true, AddPath::NONE);
        assert_eq!(eor.len(), 23);
        assert_eq!(&eor[19..23], &[0, 0, 0, 0]);
    }

    /// RFC 4271 §4.5: a NOTIFICATION is Error code 19, Error subcode 20, then
    /// the data. This is the last thing a peer hears before the session is torn
    /// down, and the pair is what an operator reads to find out why; transposed,
    /// every diagnosis on the far side is wrong.
    #[test]
    fn a_notification_body_is_the_code_then_the_subcode_then_data() {
        let msg = Message::Notification(Notification {
            code: 6,    // Cease
            subcode: 2, // Administrative Shutdown
            data: b"bye".to_vec(),
        });
        let b = msg.encode(true, AddPath::NONE);
        assert_eq!(b[18], 3, "a NOTIFICATION is Type 3");
        assert_eq!(b[19], 6, "Error code is byte 19");
        assert_eq!(b[20], 2, "Error subcode is byte 20");
        assert_eq!(&b[21..], b"bye", "the data follows from byte 21");
        assert_eq!(b.len(), 24);
    }

    /// RFC 2918 §3: a ROUTE-REFRESH body is AFI 19..21, a Reserved octet 21,
    /// and SAFI 22 — a fixed 23-octet message. The reserved octet between the
    /// two is easy to omit, which shifts the SAFI into it and makes the peer
    /// refresh the wrong address family (or none).
    #[test]
    fn a_route_refresh_body_has_a_reserved_octet_between_afi_and_safi() {
        let b = Message::RouteRefresh { afi: crate::AFI_IPV6, safi: crate::SAFI_UNICAST }
            .encode(true, AddPath::NONE);
        assert_eq!(b[18], 5, "a ROUTE-REFRESH is Type 5");
        assert_eq!(&b[19..21], &[0, 2], "AFI is bytes 19..21; IPv6 is 2");
        assert_eq!(b[21], 0, "byte 21 is Reserved and must be zero");
        assert_eq!(b[22], 1, "SAFI is byte 22; unicast is 1");
        assert_eq!(b.len(), 23);
    }

    /// The decode side, from bytes laid out by hand rather than by wren's own
    /// encoder — the half a round trip cannot check.
    #[test]
    fn a_hand_built_open_decodes_each_field_from_its_rfc_offset() {
        let mut w = vec![0xffu8; 16];
        w.extend_from_slice(&[0, 29]); // length
        w.push(1); // OPEN
        w.push(4); // version
        w.extend_from_slice(&[0x5b, 0xa0]); // my AS = 23456 (AS_TRANS)
        w.extend_from_slice(&[0x00, 0xb4]); // hold time = 180
        w.extend_from_slice(&[192, 0, 2, 1]); // identifier
        w.push(0); // no optional parameters
        assert_eq!(w.len(), 29);
        match Message::decode(&w, true, AddPath::NONE).expect("a well-formed OPEN decodes") {
            Message::Open(o) => {
                assert_eq!(o.version, 4);
                assert_eq!(o.my_as, 23456);
                assert_eq!(o.hold_time, 180);
                assert_eq!(o.identifier, ip([192, 0, 2, 1]));
                assert!(o.capabilities.is_empty());
            }
            other => panic!("expected an OPEN, got {other:?}"),
        }
    }
}
