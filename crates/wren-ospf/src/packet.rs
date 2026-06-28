//! OSPFv2 packets — the 24-byte common header (RFC 2328 §A.3.1) and all five
//! packet bodies, with the standard IP packet checksum:
//!
//! * Hello (§A.3.2) — discover and maintain neighbours.
//! * Database Description (§A.3.3) — the I/M/MS exchange that synchronises two
//!   databases, carrying LSA *headers*.
//! * Link State Request (§A.3.4) — ask for the LSAs found missing or stale.
//! * Link State Update (§A.3.5) — flood full LSAs.
//! * Link State Acknowledgment (§A.3.6) — acknowledge flooded LSAs by header.
//!
//! Every body round-trips through [`Packet::encode`] / [`Packet::decode`], which
//! fill and verify the version, length, checksum and a Null authentication
//! trailer. An unknown Type byte is [`DecodeError::UnknownType`]; a malformed LSA
//! inside an update is [`DecodeError::BadLsa`].

use std::net::Ipv4Addr;

use crate::lsa::{Lsa, LsType, LsaHeader, LSA_HEADER_LEN};
use crate::{ip_checksum, VERSION};

/// The five OSPF packet types (§A.3.1, the Type field).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PacketType {
    /// Discover and maintain neighbour relationships (§10.5).
    Hello,
    /// Describe the contents of the link-state database (§10.6).
    DatabaseDescription,
    /// Request specific LSAs from a neighbour (§10.7).
    LinkStateRequest,
    /// Flood LSAs (§13).
    LinkStateUpdate,
    /// Acknowledge flooded LSAs (§13.5).
    LinkStateAck,
}

impl PacketType {
    /// Decode the on-wire Type byte.
    pub fn from_u8(v: u8) -> Option<Self> {
        Some(match v {
            1 => PacketType::Hello,
            2 => PacketType::DatabaseDescription,
            3 => PacketType::LinkStateRequest,
            4 => PacketType::LinkStateUpdate,
            5 => PacketType::LinkStateAck,
            _ => return None,
        })
    }

    /// The on-wire Type byte.
    pub fn as_u8(self) -> u8 {
        match self {
            PacketType::Hello => 1,
            PacketType::DatabaseDescription => 2,
            PacketType::LinkStateRequest => 3,
            PacketType::LinkStateUpdate => 4,
            PacketType::LinkStateAck => 5,
        }
    }
}

/// The serialized size of the OSPF common header.
pub const HEADER_LEN: usize = 24;

/// The fields of the OSPF common header that the caller supplies; the version
/// (always [`VERSION`]), the type (from the body), the length and the checksum
/// are filled in by [`Packet::encode`]. Authentication is always Null (AuType 0,
/// the 8 auth bytes zero) — cryptographic auth is a later concern.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Header {
    /// The originating router's Router ID.
    pub router_id: Ipv4Addr,
    /// The area this packet belongs to.
    pub area_id: Ipv4Addr,
}

/// A Hello packet body (§A.3.2): the parameters two routers must agree on to
/// become neighbours, plus the sender's current view of the link's neighbours
/// and its elected DR/BDR.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Hello {
    /// The network mask of the originating interface.
    pub network_mask: Ipv4Addr,
    /// Seconds between this router's Hellos (must match the neighbour's).
    pub hello_interval: u16,
    /// The originator's optional capabilities (the [`crate`] `OPT_*` bits).
    pub options: u8,
    /// The originator's Router Priority for DR election (0 = never DR).
    pub router_priority: u8,
    /// Seconds of silence after which the neighbour is declared down (must match).
    pub dead_interval: u32,
    /// The originator's view of the Designated Router (its interface address,
    /// `0.0.0.0` for none).
    pub designated_router: Ipv4Addr,
    /// The originator's view of the Backup Designated Router (`0.0.0.0` none).
    pub backup_designated_router: Ipv4Addr,
    /// Router IDs of every neighbour from which a valid Hello was recently seen.
    pub neighbors: Vec<Ipv4Addr>,
}

/// The minimum Hello body length (everything but the neighbour list).
const HELLO_FIXED_LEN: usize = 20;

// ---------------------------------------------------------------------------
// Database Description (§A.3.3)
// ---------------------------------------------------------------------------

/// `MS`-bit — the sender is the master of the DD exchange (§10.6).
pub const DD_FLAG_MASTER: u8 = 0x01;
/// `M`-bit ("more") — further DD packets follow this one.
pub const DD_FLAG_MORE: u8 = 0x02;
/// `I`-bit ("init") — this is the first DD packet (empty, negotiating master).
pub const DD_FLAG_INIT: u8 = 0x04;

/// A Database Description body (§A.3.3): during adjacency bring-up two routers
/// exchange these to describe their databases. The first few (the `I`-bit set)
/// negotiate master/slave and the DD sequence; the rest carry LSA *headers* only
/// (the receiver requests the full LSAs it needs via [`LinkStateRequest`]).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct DatabaseDescription {
    /// The sender interface's IP MTU (mismatches abort the adjacency, §10.6).
    pub interface_mtu: u16,
    /// The sender's optional capabilities (the [`crate`] `OPT_*` bits).
    pub options: u8,
    /// The I/M/MS flags ([`DD_FLAG_INIT`] / [`DD_FLAG_MORE`] / [`DD_FLAG_MASTER`]).
    pub flags: u8,
    /// The DD sequence number, owned by the master and echoed by the slave.
    pub dd_sequence: u32,
    /// The LSA headers describing the sender's database (empty on an `I` packet).
    pub lsa_headers: Vec<LsaHeader>,
}

/// The fixed part of a DD body (MTU, options, flags, sequence) before the headers.
const DD_FIXED_LEN: usize = 8;

// ---------------------------------------------------------------------------
// Link State Request (§A.3.4)
// ---------------------------------------------------------------------------

/// One entry of a Link State Request: the identity of an LSA the sender wants
/// the full copy of (§10.7). The recency (sequence/age) is deliberately absent —
/// a request names the LSA, the answer carries whatever instance is current.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct LsRequest {
    /// Which kind of LSA is wanted.
    pub ls_type: LsType,
    /// The wanted LSA's Link State ID.
    pub link_state_id: Ipv4Addr,
    /// The wanted LSA's advertising router.
    pub advertising_router: Ipv4Addr,
}

/// The on-wire size of one Link State Request entry (a 32-bit type + two ids).
const LS_REQUEST_LEN: usize = 12;

/// A Link State Request body (§A.3.4): the LSAs a router asks a neighbour to send
/// in full, having seen newer headers during the DD exchange.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct LinkStateRequest {
    /// The requested LSAs, by identity.
    pub entries: Vec<LsRequest>,
}

// ---------------------------------------------------------------------------
// Link State Update (§A.3.5)
// ---------------------------------------------------------------------------

/// A Link State Update body (§A.3.5): the flooding workhorse — one or more full
/// LSAs. The on-wire count is derived from `lsas` on encode and validated against
/// the buffer on decode.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct LinkStateUpdate {
    /// The flooded LSAs.
    pub lsas: Vec<Lsa>,
}

// ---------------------------------------------------------------------------
// Link State Acknowledgment (§A.3.6)
// ---------------------------------------------------------------------------

/// A Link State Acknowledgment body (§A.3.6): LSA *headers* acknowledging LSAs
/// received in a Link State Update, so the sender can clear its retransmit list.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct LinkStateAck {
    /// The acknowledged LSAs, by header.
    pub lsa_headers: Vec<LsaHeader>,
}

/// A decoded OSPF packet: the common header plus a recognised body.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Packet {
    /// The common header fields.
    pub header: Header,
    /// The packet body.
    pub body: Body,
}

/// The body of an OSPF packet — one variant per [`PacketType`].
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Body {
    /// A Hello packet (§A.3.2).
    Hello(Hello),
    /// A Database Description packet (§A.3.3).
    DatabaseDescription(DatabaseDescription),
    /// A Link State Request packet (§A.3.4).
    LinkStateRequest(LinkStateRequest),
    /// A Link State Update packet (§A.3.5).
    LinkStateUpdate(LinkStateUpdate),
    /// A Link State Acknowledgment packet (§A.3.6).
    LinkStateAck(LinkStateAck),
}

impl Body {
    fn packet_type(&self) -> PacketType {
        match self {
            Body::Hello(_) => PacketType::Hello,
            Body::DatabaseDescription(_) => PacketType::DatabaseDescription,
            Body::LinkStateRequest(_) => PacketType::LinkStateRequest,
            Body::LinkStateUpdate(_) => PacketType::LinkStateUpdate,
            Body::LinkStateAck(_) => PacketType::LinkStateAck,
        }
    }
}

/// Why an OSPF packet could not be decoded.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum DecodeError {
    /// Fewer bytes than the common header (or a body) requires.
    TooShort,
    /// The version field was not [`VERSION`].
    BadVersion(u8),
    /// The Type field held a value outside 1–5.
    UnknownType(u8),
    /// The length field disagreed with the buffer.
    BadLength { stated: u16, actual: usize },
    /// The IP checksum did not verify.
    BadChecksum,
    /// A Link State Update carried an LSA that would not parse (bad length,
    /// truncated, or fewer LSAs than its count claimed).
    BadLsa,
}

impl std::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DecodeError::TooShort => write!(f, "packet shorter than required"),
            DecodeError::BadVersion(v) => write!(f, "unsupported OSPF version {v}"),
            DecodeError::UnknownType(t) => write!(f, "unknown packet type {t}"),
            DecodeError::BadLength { stated, actual } => {
                write!(f, "stated length {stated} != actual {actual}")
            }
            DecodeError::BadChecksum => write!(f, "checksum mismatch"),
            DecodeError::BadLsa => write!(f, "malformed LSA in update"),
        }
    }
}

impl std::error::Error for DecodeError {}

/// Compute the OSPF packet checksum over `pkt` (§A.3.1): the standard IP
/// checksum over the whole packet, with the 16-bit checksum field (bytes 12–13)
/// and the 64-bit authentication field (bytes 16–23) treated as zero. `pkt` must
/// already have those bytes zeroed; the auth field is *skipped*, not summed.
fn packet_checksum(pkt: &[u8]) -> u16 {
    // Sum [0..16] and [24..] — i.e. everything except the authentication field.
    let mut scratch = Vec::with_capacity(pkt.len() - 8);
    scratch.extend_from_slice(&pkt[..16]);
    scratch.extend_from_slice(&pkt[HEADER_LEN..]);
    ip_checksum(&scratch)
}

impl Packet {
    /// A Hello packet with the given header.
    pub fn hello(header: Header, hello: Hello) -> Self {
        Packet {
            header,
            body: Body::Hello(hello),
        }
    }

    /// A Database Description packet.
    pub fn database_description(header: Header, dd: DatabaseDescription) -> Self {
        Packet {
            header,
            body: Body::DatabaseDescription(dd),
        }
    }

    /// A Link State Request packet.
    pub fn link_state_request(header: Header, req: LinkStateRequest) -> Self {
        Packet {
            header,
            body: Body::LinkStateRequest(req),
        }
    }

    /// A Link State Update packet.
    pub fn link_state_update(header: Header, upd: LinkStateUpdate) -> Self {
        Packet {
            header,
            body: Body::LinkStateUpdate(upd),
        }
    }

    /// A Link State Acknowledgment packet.
    pub fn link_state_ack(header: Header, ack: LinkStateAck) -> Self {
        Packet {
            header,
            body: Body::LinkStateAck(ack),
        }
    }

    /// Serialize the packet, filling in version, type, length, checksum and a
    /// Null authentication trailer.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HEADER_LEN + HELLO_FIXED_LEN);
        // Common header, checksum + auth left zero for now.
        out.push(VERSION);
        out.push(self.body.packet_type().as_u8());
        out.extend_from_slice(&[0, 0]); // length, patched below
        out.extend_from_slice(&self.header.router_id.octets());
        out.extend_from_slice(&self.header.area_id.octets());
        out.extend_from_slice(&[0, 0]); // checksum, patched below
        out.extend_from_slice(&[0, 0]); // AuType = 0 (Null)
        out.extend_from_slice(&[0; 8]); // authentication

        match &self.body {
            Body::Hello(h) => encode_hello(h, &mut out),
            Body::DatabaseDescription(d) => encode_dd(d, &mut out),
            Body::LinkStateRequest(r) => encode_lsr(r, &mut out),
            Body::LinkStateUpdate(u) => encode_lsu(u, &mut out),
            Body::LinkStateAck(a) => encode_lsack(a, &mut out),
        }

        let len = out.len() as u16;
        out[2..4].copy_from_slice(&len.to_be_bytes());
        let csum = packet_checksum(&out);
        out[12..14].copy_from_slice(&csum.to_be_bytes());
        out
    }

    /// Parse and validate an OSPF packet from `buf`. Verifies the version, the
    /// length field and the checksum before dispatching on the type.
    pub fn decode(buf: &[u8]) -> Result<Packet, DecodeError> {
        if buf.len() < HEADER_LEN {
            return Err(DecodeError::TooShort);
        }
        if buf[0] != VERSION {
            return Err(DecodeError::BadVersion(buf[0]));
        }
        let ptype = PacketType::from_u8(buf[1]).ok_or(DecodeError::UnknownType(buf[1]))?;
        let stated = u16::from_be_bytes([buf[2], buf[3]]);
        if stated as usize != buf.len() {
            return Err(DecodeError::BadLength {
                stated,
                actual: buf.len(),
            });
        }
        // Verify the checksum: rebuild with checksum + auth zeroed and compare.
        let mut scratch = buf.to_vec();
        scratch[12] = 0;
        scratch[13] = 0;
        for b in &mut scratch[16..HEADER_LEN] {
            *b = 0;
        }
        if packet_checksum(&scratch) != u16::from_be_bytes([buf[12], buf[13]]) {
            return Err(DecodeError::BadChecksum);
        }

        let header = Header {
            router_id: Ipv4Addr::new(buf[4], buf[5], buf[6], buf[7]),
            area_id: Ipv4Addr::new(buf[8], buf[9], buf[10], buf[11]),
        };
        let body = &buf[HEADER_LEN..];
        let body = match ptype {
            PacketType::Hello => Body::Hello(decode_hello(body)?),
            PacketType::DatabaseDescription => Body::DatabaseDescription(decode_dd(body)?),
            PacketType::LinkStateRequest => Body::LinkStateRequest(decode_lsr(body)?),
            PacketType::LinkStateUpdate => Body::LinkStateUpdate(decode_lsu(body)?),
            PacketType::LinkStateAck => Body::LinkStateAck(decode_lsack(body)?),
        };
        Ok(Packet { header, body })
    }

    /// Borrow the Hello body, if this is a Hello packet.
    pub fn as_hello(&self) -> Option<&Hello> {
        match &self.body {
            Body::Hello(h) => Some(h),
            _ => None,
        }
    }

    /// Borrow the Database Description body, if this is a DD packet.
    pub fn as_database_description(&self) -> Option<&DatabaseDescription> {
        match &self.body {
            Body::DatabaseDescription(d) => Some(d),
            _ => None,
        }
    }

    /// Borrow the Link State Request body, if this is an LSR packet.
    pub fn as_link_state_request(&self) -> Option<&LinkStateRequest> {
        match &self.body {
            Body::LinkStateRequest(r) => Some(r),
            _ => None,
        }
    }

    /// Borrow the Link State Update body, if this is an LSU packet.
    pub fn as_link_state_update(&self) -> Option<&LinkStateUpdate> {
        match &self.body {
            Body::LinkStateUpdate(u) => Some(u),
            _ => None,
        }
    }

    /// Borrow the Link State Acknowledgment body, if this is an LSAck packet.
    pub fn as_link_state_ack(&self) -> Option<&LinkStateAck> {
        match &self.body {
            Body::LinkStateAck(a) => Some(a),
            _ => None,
        }
    }
}

fn encode_hello(h: &Hello, out: &mut Vec<u8>) {
    out.extend_from_slice(&h.network_mask.octets());
    out.extend_from_slice(&h.hello_interval.to_be_bytes());
    out.push(h.options);
    out.push(h.router_priority);
    out.extend_from_slice(&h.dead_interval.to_be_bytes());
    out.extend_from_slice(&h.designated_router.octets());
    out.extend_from_slice(&h.backup_designated_router.octets());
    for n in &h.neighbors {
        out.extend_from_slice(&n.octets());
    }
}

fn decode_hello(body: &[u8]) -> Result<Hello, DecodeError> {
    if body.len() < HELLO_FIXED_LEN {
        return Err(DecodeError::TooShort);
    }
    // The neighbour list must be a whole number of 4-byte router ids.
    let rest = &body[HELLO_FIXED_LEN..];
    if rest.len() % 4 != 0 {
        return Err(DecodeError::TooShort);
    }
    let neighbors = rest
        .chunks_exact(4)
        .map(|c| Ipv4Addr::new(c[0], c[1], c[2], c[3]))
        .collect();
    Ok(Hello {
        network_mask: Ipv4Addr::new(body[0], body[1], body[2], body[3]),
        hello_interval: u16::from_be_bytes([body[4], body[5]]),
        options: body[6],
        router_priority: body[7],
        dead_interval: u32::from_be_bytes([body[8], body[9], body[10], body[11]]),
        designated_router: Ipv4Addr::new(body[12], body[13], body[14], body[15]),
        backup_designated_router: Ipv4Addr::new(body[16], body[17], body[18], body[19]),
        neighbors,
    })
}

// --- Database Description --------------------------------------------------

fn encode_dd(d: &DatabaseDescription, out: &mut Vec<u8>) {
    out.extend_from_slice(&d.interface_mtu.to_be_bytes());
    out.push(d.options);
    out.push(d.flags);
    out.extend_from_slice(&d.dd_sequence.to_be_bytes());
    for h in &d.lsa_headers {
        h.encode(out);
    }
}

fn decode_dd(body: &[u8]) -> Result<DatabaseDescription, DecodeError> {
    if body.len() < DD_FIXED_LEN {
        return Err(DecodeError::TooShort);
    }
    let rest = &body[DD_FIXED_LEN..];
    if rest.len() % LSA_HEADER_LEN != 0 {
        return Err(DecodeError::TooShort);
    }
    let mut lsa_headers = Vec::with_capacity(rest.len() / LSA_HEADER_LEN);
    for chunk in rest.chunks_exact(LSA_HEADER_LEN) {
        lsa_headers.push(LsaHeader::decode(chunk).ok_or(DecodeError::BadLsa)?);
    }
    Ok(DatabaseDescription {
        interface_mtu: u16::from_be_bytes([body[0], body[1]]),
        options: body[2],
        flags: body[3],
        dd_sequence: u32::from_be_bytes([body[4], body[5], body[6], body[7]]),
        lsa_headers,
    })
}

// --- Link State Request ----------------------------------------------------

fn encode_lsr(r: &LinkStateRequest, out: &mut Vec<u8>) {
    for e in &r.entries {
        // The LS Type is a 32-bit field; only the low byte is used in OSPFv2.
        out.extend_from_slice(&[0, 0, 0, e.ls_type.as_u8()]);
        out.extend_from_slice(&e.link_state_id.octets());
        out.extend_from_slice(&e.advertising_router.octets());
    }
}

fn decode_lsr(body: &[u8]) -> Result<LinkStateRequest, DecodeError> {
    if body.len() % LS_REQUEST_LEN != 0 {
        return Err(DecodeError::TooShort);
    }
    let mut entries = Vec::with_capacity(body.len() / LS_REQUEST_LEN);
    for c in body.chunks_exact(LS_REQUEST_LEN) {
        let ls_type = LsType::from_u8(c[3]).ok_or(DecodeError::UnknownType(c[3]))?;
        entries.push(LsRequest {
            ls_type,
            link_state_id: Ipv4Addr::new(c[4], c[5], c[6], c[7]),
            advertising_router: Ipv4Addr::new(c[8], c[9], c[10], c[11]),
        });
    }
    Ok(LinkStateRequest { entries })
}

// --- Link State Update -----------------------------------------------------

fn encode_lsu(u: &LinkStateUpdate, out: &mut Vec<u8>) {
    out.extend_from_slice(&(u.lsas.len() as u32).to_be_bytes());
    for lsa in &u.lsas {
        out.extend_from_slice(&lsa.encode());
    }
}

fn decode_lsu(body: &[u8]) -> Result<LinkStateUpdate, DecodeError> {
    if body.len() < 4 {
        return Err(DecodeError::TooShort);
    }
    let count = u32::from_be_bytes([body[0], body[1], body[2], body[3]]) as usize;
    let mut lsas = Vec::with_capacity(count);
    let mut off = 4;
    for _ in 0..count {
        let (lsa, used) = Lsa::decode(&body[off..]).ok_or(DecodeError::BadLsa)?;
        lsas.push(lsa);
        off += used;
    }
    // Every advertised LSA must be accounted for, with nothing dangling.
    if off != body.len() {
        return Err(DecodeError::BadLsa);
    }
    Ok(LinkStateUpdate { lsas })
}

// --- Link State Acknowledgment --------------------------------------------

fn encode_lsack(a: &LinkStateAck, out: &mut Vec<u8>) {
    for h in &a.lsa_headers {
        h.encode(out);
    }
}

fn decode_lsack(body: &[u8]) -> Result<LinkStateAck, DecodeError> {
    if body.len() % LSA_HEADER_LEN != 0 {
        return Err(DecodeError::TooShort);
    }
    let mut lsa_headers = Vec::with_capacity(body.len() / LSA_HEADER_LEN);
    for chunk in body.chunks_exact(LSA_HEADER_LEN) {
        lsa_headers.push(LsaHeader::decode(chunk).ok_or(DecodeError::BadLsa)?);
    }
    Ok(LinkStateAck { lsa_headers })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lsa::{LsaBody, RouterLink, RouterLinkType, RouterLsa};
    use crate::{DEFAULT_DEAD_INTERVAL, DEFAULT_HELLO_INTERVAL, INITIAL_SEQUENCE_NUMBER, OPT_E};

    fn sample_header() -> Header {
        Header {
            router_id: Ipv4Addr::new(10, 0, 0, 1),
            area_id: Ipv4Addr::new(0, 0, 0, 0),
        }
    }

    fn sample_lsa_header(lsid: [u8; 4]) -> LsaHeader {
        LsaHeader {
            ls_age: 1,
            options: OPT_E,
            ls_type: LsType::Router,
            link_state_id: Ipv4Addr::from(lsid),
            advertising_router: Ipv4Addr::new(10, 0, 0, 1),
            ls_seq: INITIAL_SEQUENCE_NUMBER,
            ls_checksum: 0xbeef,
            length: 36,
        }
    }

    fn sample_hello() -> Packet {
        Packet::hello(
            Header {
                router_id: Ipv4Addr::new(10, 0, 0, 1),
                area_id: Ipv4Addr::new(0, 0, 0, 0),
            },
            Hello {
                network_mask: Ipv4Addr::new(255, 255, 255, 0),
                hello_interval: DEFAULT_HELLO_INTERVAL,
                options: OPT_E,
                router_priority: 1,
                dead_interval: DEFAULT_DEAD_INTERVAL,
                designated_router: Ipv4Addr::new(10, 0, 0, 1),
                backup_designated_router: Ipv4Addr::new(10, 0, 0, 2),
                neighbors: vec![Ipv4Addr::new(10, 0, 0, 2), Ipv4Addr::new(10, 0, 0, 3)],
            },
        )
    }

    #[test]
    fn packet_type_roundtrips() {
        for t in [
            PacketType::Hello,
            PacketType::DatabaseDescription,
            PacketType::LinkStateRequest,
            PacketType::LinkStateUpdate,
            PacketType::LinkStateAck,
        ] {
            assert_eq!(PacketType::from_u8(t.as_u8()), Some(t));
        }
        assert_eq!(PacketType::from_u8(0), None);
        assert_eq!(PacketType::from_u8(6), None);
    }

    #[test]
    fn hello_roundtrips_through_the_wire() {
        let pkt = sample_hello();
        let bytes = pkt.encode();
        // 24 header + 20 fixed + 2 neighbours * 4.
        assert_eq!(bytes.len(), HEADER_LEN + HELLO_FIXED_LEN + 8);
        assert_eq!(bytes[0], VERSION);
        assert_eq!(bytes[1], PacketType::Hello.as_u8());
        let decoded = Packet::decode(&bytes).expect("valid hello decodes");
        assert_eq!(decoded, pkt);
    }

    #[test]
    fn checksum_is_verified() {
        let mut bytes = sample_hello().encode();
        // Corrupt a body byte; checksum must now fail.
        let last = bytes.len() - 1;
        bytes[last] ^= 0xff;
        assert_eq!(Packet::decode(&bytes), Err(DecodeError::BadChecksum));
    }

    #[test]
    fn rejects_bad_version_and_length() {
        let mut bytes = sample_hello().encode();
        bytes[0] = 3;
        assert_eq!(Packet::decode(&bytes), Err(DecodeError::BadVersion(3)));

        let mut bytes = sample_hello().encode();
        bytes.push(0); // length field no longer matches
        assert!(matches!(
            Packet::decode(&bytes),
            Err(DecodeError::BadLength { .. })
        ));
    }

    #[test]
    fn hello_with_no_neighbors() {
        let mut pkt = sample_hello();
        if let Body::Hello(h) = &mut pkt.body {
            h.neighbors.clear();
        }
        let bytes = pkt.encode();
        assert_eq!(bytes.len(), HEADER_LEN + HELLO_FIXED_LEN);
        assert_eq!(Packet::decode(&bytes).unwrap(), pkt);
    }

    #[test]
    fn database_description_roundtrips_with_headers_and_flags() {
        let pkt = Packet::database_description(
            sample_header(),
            DatabaseDescription {
                interface_mtu: 1500,
                options: OPT_E,
                flags: DD_FLAG_INIT | DD_FLAG_MORE | DD_FLAG_MASTER,
                dd_sequence: 0x1234_5678,
                lsa_headers: vec![sample_lsa_header([10, 0, 0, 1]), sample_lsa_header([10, 0, 0, 2])],
            },
        );
        let bytes = pkt.encode();
        assert_eq!(bytes.len(), HEADER_LEN + DD_FIXED_LEN + 2 * LSA_HEADER_LEN);
        assert_eq!(bytes[1], PacketType::DatabaseDescription.as_u8());
        assert_eq!(Packet::decode(&bytes).unwrap(), pkt);
    }

    #[test]
    fn empty_init_dd_roundtrips() {
        // The first DD packet of an exchange: I/M/MS set, no headers yet.
        let pkt = Packet::database_description(
            sample_header(),
            DatabaseDescription {
                interface_mtu: 1500,
                options: OPT_E,
                flags: DD_FLAG_INIT | DD_FLAG_MORE | DD_FLAG_MASTER,
                dd_sequence: 42,
                lsa_headers: vec![],
            },
        );
        let bytes = pkt.encode();
        assert_eq!(bytes.len(), HEADER_LEN + DD_FIXED_LEN);
        let decoded = Packet::decode(&bytes).unwrap();
        assert_eq!(decoded.as_database_description().unwrap().dd_sequence, 42);
        assert_eq!(decoded, pkt);
    }

    #[test]
    fn link_state_request_roundtrips() {
        let pkt = Packet::link_state_request(
            sample_header(),
            LinkStateRequest {
                entries: vec![
                    LsRequest {
                        ls_type: LsType::Router,
                        link_state_id: Ipv4Addr::new(10, 0, 0, 2),
                        advertising_router: Ipv4Addr::new(10, 0, 0, 2),
                    },
                    LsRequest {
                        ls_type: LsType::AsExternal,
                        link_state_id: Ipv4Addr::new(0, 0, 0, 0),
                        advertising_router: Ipv4Addr::new(10, 0, 0, 9),
                    },
                ],
            },
        );
        let bytes = pkt.encode();
        assert_eq!(bytes.len(), HEADER_LEN + 2 * LS_REQUEST_LEN);
        assert_eq!(Packet::decode(&bytes).unwrap(), pkt);
    }

    #[test]
    fn link_state_update_roundtrips_full_lsas() {
        let lsa = Lsa {
            header: sample_lsa_header([10, 0, 0, 1]),
            body: LsaBody::Router(RouterLsa {
                flags: 0,
                links: vec![RouterLink {
                    link_id: Ipv4Addr::new(10, 1, 0, 0),
                    link_data: Ipv4Addr::new(255, 255, 0, 0),
                    link_type: RouterLinkType::Stub,
                    metric: 5,
                }],
            }),
        };
        let pkt = Packet::link_state_update(
            sample_header(),
            LinkStateUpdate {
                lsas: vec![lsa.clone(), lsa],
            },
        );
        let bytes = pkt.encode();
        let decoded = Packet::decode(&bytes).expect("valid LSU decodes");
        let upd = decoded.as_link_state_update().unwrap();
        assert_eq!(upd.lsas.len(), 2);
        // Lsa::encode recomputes length+checksum, so compare bodies + identities.
        assert_eq!(upd.lsas[0].body, pkt.as_link_state_update().unwrap().lsas[0].body);
        assert_eq!(upd.lsas[0].key(), pkt.as_link_state_update().unwrap().lsas[0].key());
    }

    #[test]
    fn truncated_lsu_is_bad_lsa_not_panic() {
        let lsa = Lsa {
            header: sample_lsa_header([10, 0, 0, 1]),
            body: LsaBody::Router(RouterLsa { flags: 0, links: vec![] }),
        };
        let pkt = Packet::link_state_update(sample_header(), LinkStateUpdate { lsas: vec![lsa] });
        let mut bytes = pkt.encode();
        // Claim two LSAs while only one is present.
        bytes[HEADER_LEN..HEADER_LEN + 4].copy_from_slice(&2u32.to_be_bytes());
        // Length field still has to match so we reach the LSU parser.
        let len = bytes.len() as u16;
        bytes[2..4].copy_from_slice(&len.to_be_bytes());
        bytes[12] = 0;
        bytes[13] = 0;
        let csum = packet_checksum(&bytes);
        bytes[12..14].copy_from_slice(&csum.to_be_bytes());
        assert_eq!(Packet::decode(&bytes), Err(DecodeError::BadLsa));
    }

    #[test]
    fn link_state_ack_roundtrips() {
        let pkt = Packet::link_state_ack(
            sample_header(),
            LinkStateAck {
                lsa_headers: vec![sample_lsa_header([10, 0, 0, 1]), sample_lsa_header([192, 168, 0, 0])],
            },
        );
        let bytes = pkt.encode();
        assert_eq!(bytes.len(), HEADER_LEN + 2 * LSA_HEADER_LEN);
        assert_eq!(Packet::decode(&bytes).unwrap(), pkt);
    }

    #[test]
    fn wrong_accessor_returns_none() {
        let hello = sample_hello();
        assert!(hello.as_database_description().is_none());
        assert!(hello.as_link_state_update().is_none());
        assert!(hello.as_hello().is_some());
    }
}
