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
    pub fn encode(&self, four_octet: bool) -> Vec<u8> {
        let mut out = Vec::with_capacity(HEADER_LEN + 32);
        out.extend_from_slice(&MARKER);
        out.extend_from_slice(&[0, 0]); // length, patched below
        out.push(self.message_type().as_u8());
        match self {
            Message::Open(o) => encode_open(o, &mut out),
            Message::Update(u) => encode_update(u, &mut out, four_octet),
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
    /// AS_PATH / AGGREGATOR width when the message is an UPDATE (RFC 6793).
    pub fn decode(buf: &[u8], four_octet: bool) -> Result<Message, DecodeError> {
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
            MessageType::Update => Message::Update(decode_update(body, four_octet)?),
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

fn encode_update(u: &Update, out: &mut Vec<u8>, four_octet: bool) {
    // Withdrawn Routes, length-prefixed.
    let mut withdrawn = Vec::new();
    for p in &u.withdrawn {
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

    // NLRI fills the rest (no length prefix).
    for p in &u.nlri {
        encode_prefix(out, p);
    }
}

fn decode_update(body: &[u8], four_octet: bool) -> Result<Update, DecodeError> {
    if body.len() < 4 {
        return Err(DecodeError::TooShort);
    }
    let wlen = u16::from_be_bytes([body[0], body[1]]) as usize;
    let mut off = 2;
    if body.len() < off + wlen {
        return Err(DecodeError::Malformed);
    }
    let withdrawn = decode_prefixes(&body[off..off + wlen])?;
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

    let nlri = decode_prefixes(&body[off..])?;
    Ok(Update {
        withdrawn,
        attributes,
        nlri,
    })
}

fn decode_prefixes(mut buf: &[u8]) -> Result<Vec<Prefix>, DecodeError> {
    let mut out = Vec::new();
    while !buf.is_empty() {
        let (p, used) = decode_prefix(buf).ok_or(DecodeError::Malformed)?;
        out.push(p);
        buf = &buf[used..];
    }
    Ok(out)
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
        let bytes = msg.encode(four_octet);
        assert_eq!(&bytes[..16], &MARKER);
        assert_eq!(u16::from_be_bytes([bytes[16], bytes[17]]) as usize, bytes.len());
        assert_eq!(Message::decode(&bytes, four_octet).expect("decodes"), msg);
    }

    #[test]
    fn keepalive_is_header_only() {
        let bytes = Message::Keepalive.encode(true);
        assert_eq!(bytes.len(), HEADER_LEN);
        roundtrip(Message::Keepalive);
    }

    #[test]
    fn route_refresh_roundtrips() {
        use crate::{AFI_IPV4, AFI_IPV6, SAFI_UNICAST};
        // Header (19) + AFI(2) + Reserved(1) + SAFI(1) = 23 octets, type 5.
        let bytes = Message::RouteRefresh { afi: AFI_IPV4, safi: SAFI_UNICAST }.encode(true);
        assert_eq!(bytes.len(), HEADER_LEN + 4);
        assert_eq!(bytes[18], 5); // ROUTE-REFRESH type code
        roundtrip(Message::RouteRefresh { afi: AFI_IPV4, safi: SAFI_UNICAST });
        roundtrip(Message::RouteRefresh { afi: AFI_IPV6, safi: SAFI_UNICAST });
        // A wrong-length body is rejected.
        let mut short = Message::RouteRefresh { afi: AFI_IPV4, safi: SAFI_UNICAST }.encode(true);
        short.truncate(HEADER_LEN + 3);
        short[17] = (HEADER_LEN + 3) as u8;
        assert!(matches!(Message::decode(&short, true), Err(DecodeError::Malformed)));
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
        }));
    }

    #[test]
    fn empty_update_is_a_keepalive_of_routes() {
        // A withdrawn-only / empty UPDATE is legal.
        roundtrip(Message::Update(Update::default()));
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
        };
        // Encode toward the legacy peer (four_octet = false).
        let bytes = Message::Update(update).encode(false);
        let Message::Update(decoded) = Message::decode(&bytes, false).unwrap() else {
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
        let mut bytes = Message::Keepalive.encode(true);
        bytes[0] ^= 0x01;
        assert_eq!(Message::decode(&bytes, true), Err(DecodeError::BadMarker));

        let mut bytes = Message::Keepalive.encode(true);
        bytes.push(0); // length field no longer matches
        assert!(matches!(Message::decode(&bytes, true), Err(DecodeError::BadLength { .. })));

        let mut bytes = Message::Keepalive.encode(true);
        bytes[18] = 9; // bad type
        assert_eq!(Message::decode(&bytes, true), Err(DecodeError::BadType(9)));

        let mut bytes = Message::Open(Open::new(VERSION, 1, 90, ip([1, 1, 1, 1]))).encode(true);
        bytes[HEADER_LEN] = 3; // version 3
        assert_eq!(Message::decode(&bytes, true), Err(DecodeError::BadVersion(3)));
    }
}
