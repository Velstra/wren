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

use crate::attr::PathAttribute;
use crate::capability::{encode_optional_parameters, parse_optional_parameters, Capability};
use crate::{
    as_trans_fit, decode_prefix, encode_prefix, MessageType, AFI_IPV4, HEADER_LEN, MARKER,
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
            // capability for IPv6 unicast (RFC 4760) — wren can carry IPv6 NLRI,
            // and a peer that cannot will simply not advertise it back.
            capabilities: vec![
                Capability::FourOctetAs(local_as),
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
        if stated as usize != buf.len() || (stated as usize) < HEADER_LEN {
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
    Ok(Open {
        version,
        my_as: u16::from_be_bytes([body[1], body[2]]),
        hold_time: u16::from_be_bytes([body[3], body[4]]),
        identifier: Ipv4Addr::new(body[5], body[6], body[7], body[8]),
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
    if body.len() < off + wlen {
        return Err(DecodeError::Malformed);
    }
    let (withdrawn, withdrawn_path_ids) = decode_prefixes(&body[off..off + wlen], ap)?;
    off += wlen;

    if body.len() < off + 2 {
        return Err(DecodeError::TooShort);
    }
    let alen = u16::from_be_bytes([body[off], body[off + 1]]) as usize;
    off += 2;
    if body.len() < off + alen {
        return Err(DecodeError::Malformed);
    }
    let attributes = decode_attributes(&body[off..off + alen], four_octet)?;
    off += alen;

    let (nlri, nlri_path_ids) = decode_prefixes(&body[off..], ap)?;
    Ok(Update {
        withdrawn,
        attributes,
        nlri,
        nlri_path_ids,
        withdrawn_path_ids,
    })
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
    while !buf.is_empty() {
        let (a, used) = PathAttribute::decode(buf, four_octet).ok_or(DecodeError::Malformed)?;
        out.push(a);
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
        use crate::{AFI_IPV6, SAFI_UNICAST};
        // Open::new advertises IPv6-unicast multiprotocol support out of the box.
        let open = Open::new(VERSION, 65001, DEFAULT_HOLD_TIME, ip([10, 0, 0, 1]));
        assert!(open.supports_multiprotocol(AFI_IPV6, SAFI_UNICAST));
        assert!(!open.supports_multiprotocol(crate::AFI_IPV4, SAFI_UNICAST));
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
}
