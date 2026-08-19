//! OSPFv3 packets — the 16-byte common header (RFC 5340 §A.3.1) and all five
//! packet bodies, with the IPv6 pseudo-header checksum:
//!
//! * Hello (§A.3.2) — discover and maintain neighbours. No network mask (OSPFv3
//!   neighbours need not share a subnet); it carries the originator's Interface
//!   ID and a 24-bit Options field instead.
//! * Database Description (§A.3.3) — the I/M/MS exchange synchronising two
//!   databases, carrying LSA *headers*.
//! * Link State Request (§A.3.4) — ask for the LSAs found missing or stale.
//! * Link State Update (§A.3.5) — flood full LSAs.
//! * Link State Acknowledgment (§A.3.6) — acknowledge flooded LSAs by header.
//!
//! The checksum is the standard IPv6 upper-layer checksum, computed over a
//! pseudo-header built from the packet's IPv6 source and destination, so
//! [`Packet::encode`] and [`Packet::decode`] take those two addresses.
//!
//! OSPFv3 originally delegated authentication to IPv6's own AH/ESP, but RFC 7166
//! adds a native **Authentication Trailer** appended after the packet.
//! [`Packet::encode_auth`] / [`Packet::decode_auth`] carry an HMAC-SHA-256 digest
//! ([`Auth`]) that authenticates each packet against a shared key.

use std::net::{Ipv4Addr, Ipv6Addr};

use crate::hmac;
use crate::lsa::{checksum_valid, Lsa, LsType, LsaHeader, LSA_HEADER_LEN};
use crate::{packet_checksum, VERSION};

/// The five OSPF packet types (§A.3.1, the Type field) — the same five as OSPFv2.
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

/// The serialized size of the OSPFv3 common header (8 bytes shorter than v2: no
/// authentication, and a 1-byte Instance ID in place of the 2-byte AuType).
pub const HEADER_LEN: usize = 16;

/// RFC 7166 Authentication Type 1 — HMAC Cryptographic Authentication.
const AUTH_TYPE_HMAC: u16 = 1;
/// The fixed part of the Authentication Trailer before the digest (§4.1): Auth
/// Type (2) + Auth Data Len (2) + Reserved (2) + Security Association ID (2) +
/// the 64-bit Cryptographic Sequence Number (8).
const AT_FIXED_LEN: usize = 16;

/// The AT-bit in the 24-bit Options field (RFC 7166 §2.1): a Hello / Database
/// Description sets it to announce that every packet on this link carries an
/// Authentication Trailer.
pub const OPTION_AT_BIT: u32 = 0x0000_0400;

/// OSPFv3 cryptographic authentication for a packet (RFC 7166). `None` sends and
/// expects a plain checksummed packet; `Hmac` appends and verifies an
/// HMAC-SHA-256 Authentication Trailer keyed by a shared secret.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Auth {
    /// No authentication — the standard checksummed packet (RFC 5340).
    None,
    /// HMAC-SHA-256 cryptographic authentication (RFC 7166), keyed by `key` and
    /// identified by the Security Association id `sa_id`, with a 64-bit
    /// monotonically increasing anti-replay `seq`.
    Hmac {
        /// Security Association id (maps to the algorithm and key on the peer).
        sa_id: u16,
        /// The shared authentication key.
        key: Vec<u8>,
        /// The cryptographic sequence number stamped into the trailer on send.
        seq: u64,
    },
}

/// Build the 32-byte Apad for HMAC-SHA-256 (RFC 7166 §4.5): the 16-octet IPv6
/// source address followed by `0x878FE1F3` repeated `(L-16)/4 = 4` times. The
/// Authentication Data field is pre-set to this before the digest is computed.
fn apad(src: Ipv6Addr) -> [u8; hmac::DIGEST_LEN] {
    let mut a = [0u8; hmac::DIGEST_LEN];
    a[..16].copy_from_slice(&src.octets());
    for chunk in a[16..].chunks_exact_mut(4) {
        chunk.copy_from_slice(&0x878F_E1F3u32.to_be_bytes());
    }
    a
}

/// Constant-time byte-slice equality, so a wrong digest cannot be probed by
/// timing the compare.
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b) {
        diff |= x ^ y;
    }
    diff == 0
}

/// The fields of the OSPFv3 common header the caller supplies; the version
/// (always [`VERSION`]), the type, the length and the checksum are filled in by
/// [`Packet::encode`].
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Header {
    /// The originating router's Router ID (still a 32-bit id, even over IPv6).
    pub router_id: Ipv4Addr,
    /// The area this packet belongs to.
    pub area_id: Ipv4Addr,
    /// The Instance ID — lets several OSPFv3 instances share one link (§2.11).
    pub instance_id: u8,
}

/// A Hello packet body (§A.3.2). Compared with OSPFv2: no network mask, an extra
/// Interface ID, a 24-bit Options field and the DR/BDR are now *Router IDs*.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Hello {
    /// The originating interface's Interface ID (unique on the originating router).
    pub interface_id: u32,
    /// The originator's Router Priority for DR election (0 = never DR).
    pub router_priority: u8,
    /// The originator's optional capabilities (24-bit, the [`crate`] `OPT_*` bits).
    pub options: u32,
    /// Seconds between this router's Hellos (must match the neighbour's).
    pub hello_interval: u16,
    /// Seconds of silence after which the neighbour is declared down (must match).
    pub dead_interval: u16,
    /// The originator's view of the Designated Router, by Router ID (`0` = none).
    pub designated_router: Ipv4Addr,
    /// The originator's view of the Backup Designated Router (`0` = none).
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

/// A Database Description body (§A.3.3). Same exchange as OSPFv2, but the Options
/// field is 24-bit and precedes the MTU.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct DatabaseDescription {
    /// The sender's optional capabilities (24-bit, the [`crate`] `OPT_*` bits).
    pub options: u32,
    /// The sender interface's IP MTU (mismatches abort the adjacency, §10.6).
    pub interface_mtu: u16,
    /// The I/M/MS flags ([`DD_FLAG_INIT`] / [`DD_FLAG_MORE`] / [`DD_FLAG_MASTER`]).
    pub flags: u8,
    /// The DD sequence number, owned by the master and echoed by the slave.
    pub dd_sequence: u32,
    /// The LSA headers describing the sender's database (empty on an `I` packet).
    pub lsa_headers: Vec<LsaHeader>,
}

/// The fixed part of a DD body before the headers (0 + options + MTU + 0 + flags
/// + sequence).
const DD_FIXED_LEN: usize = 12;

// ---------------------------------------------------------------------------
// Link State Request (§A.3.4)
// ---------------------------------------------------------------------------

/// One entry of a Link State Request: the identity of an LSA the sender wants the
/// full copy of (§10.7). The LS Type is the full 16-bit OSPFv3 type.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct LsRequest {
    /// Which kind of LSA is wanted.
    pub ls_type: LsType,
    /// The wanted LSA's Link State ID.
    pub link_state_id: Ipv4Addr,
    /// The wanted LSA's advertising router.
    pub advertising_router: Ipv4Addr,
}

/// The on-wire size of one Link State Request entry (2 reserved + 2 type + 2 ids).
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

/// A Link State Update body (§A.3.5): one or more full LSAs.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct LinkStateUpdate {
    /// The flooded LSAs.
    pub lsas: Vec<Lsa>,
}

// ---------------------------------------------------------------------------
// Link State Acknowledgment (§A.3.6)
// ---------------------------------------------------------------------------

/// A Link State Acknowledgment body (§A.3.6): LSA *headers* acknowledging LSAs.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct LinkStateAck {
    /// The acknowledged LSAs, by header.
    pub lsa_headers: Vec<LsaHeader>,
}

/// A decoded OSPFv3 packet: the common header plus a recognised body.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Packet {
    /// The common header fields.
    pub header: Header,
    /// The packet body.
    pub body: Body,
}

/// The body of an OSPFv3 packet — one variant per [`PacketType`].
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

/// Why an OSPFv3 packet could not be decoded.
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
    /// The IPv6 upper-layer checksum did not verify.
    BadChecksum,
    /// A Link State Update carried an LSA that would not parse.
    BadLsa,
    /// The RFC 7166 Authentication Trailer was missing, malformed, or its HMAC
    /// did not verify against the configured key.
    BadAuth,
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
            DecodeError::BadAuth => write!(f, "authentication trailer missing or invalid"),
        }
    }
}

impl std::error::Error for DecodeError {}

// --- 24-bit helpers --------------------------------------------------------

fn put_u24(out: &mut Vec<u8>, v: u32) {
    out.push((v >> 16) as u8);
    out.push((v >> 8) as u8);
    out.push(v as u8);
}

fn get_u24(b: &[u8]) -> u32 {
    ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32
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

    /// Serialize the packet, filling in version, type, length and the IPv6
    /// upper-layer checksum over the pseudo-header built from `src`/`dst`.
    pub fn encode(&self, src: Ipv6Addr, dst: Ipv6Addr) -> Vec<u8> {
        let mut out = Vec::with_capacity(HEADER_LEN + HELLO_FIXED_LEN);
        out.push(VERSION);
        out.push(self.body.packet_type().as_u8());
        out.extend_from_slice(&[0, 0]); // length, patched below
        out.extend_from_slice(&self.header.router_id.octets());
        out.extend_from_slice(&self.header.area_id.octets());
        out.extend_from_slice(&[0, 0]); // checksum, patched below
        out.push(self.header.instance_id);
        out.push(0); // reserved

        match &self.body {
            Body::Hello(h) => encode_hello(h, &mut out),
            Body::DatabaseDescription(d) => encode_dd(d, &mut out),
            Body::LinkStateRequest(r) => encode_lsr(r, &mut out),
            Body::LinkStateUpdate(u) => encode_lsu(u, &mut out),
            Body::LinkStateAck(a) => encode_lsack(a, &mut out),
        }

        let len = out.len() as u16;
        out[2..4].copy_from_slice(&len.to_be_bytes());
        let csum = packet_checksum(src, dst, &out);
        out[12..14].copy_from_slice(&csum.to_be_bytes());
        out
    }

    /// Parse and validate an OSPFv3 packet from `buf`, using `src`/`dst` to verify
    /// the IPv6 upper-layer checksum.
    pub fn decode(buf: &[u8], src: Ipv6Addr, dst: Ipv6Addr) -> Result<Packet, DecodeError> {
        if buf.len() < HEADER_LEN {
            return Err(DecodeError::TooShort);
        }
        if buf[0] != VERSION {
            return Err(DecodeError::BadVersion(buf[0]));
        }
        // Validate the type (for error precedence) before the checksum.
        PacketType::from_u8(buf[1]).ok_or(DecodeError::UnknownType(buf[1]))?;
        let stated = u16::from_be_bytes([buf[2], buf[3]]);
        if stated as usize != buf.len() {
            return Err(DecodeError::BadLength {
                stated,
                actual: buf.len(),
            });
        }
        // Verify the checksum: rebuild with the checksum field zeroed and compare.
        let mut scratch = buf.to_vec();
        scratch[12] = 0;
        scratch[13] = 0;
        if packet_checksum(src, dst, &scratch) != u16::from_be_bytes([buf[12], buf[13]]) {
            return Err(DecodeError::BadChecksum);
        }
        Self::parse_unchecked(buf)
    }

    /// Parse the header and body of an OSPFv3 packet **without** verifying the
    /// checksum (an RFC 7166 authenticated packet leaves the checksum zero, §4.2).
    /// Validates version, type and the stated length against `buf`. Shared by
    /// [`decode`] (after its checksum step) and [`decode_auth`] (after the HMAC).
    ///
    /// [`decode`]: Packet::decode
    /// [`decode_auth`]: Packet::decode_auth
    fn parse_unchecked(buf: &[u8]) -> Result<Packet, DecodeError> {
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
        let header = Header {
            router_id: Ipv4Addr::new(buf[4], buf[5], buf[6], buf[7]),
            area_id: Ipv4Addr::new(buf[8], buf[9], buf[10], buf[11]),
            instance_id: buf[14],
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

    /// Serialize the packet with an RFC 7166 Authentication Trailer when `auth`
    /// is [`Auth::Hmac`] — otherwise the plain checksummed [`encode`].
    ///
    /// Per RFC 7166 the OSPFv3 checksum is left zero (§4.2 — the HMAC supersedes
    /// it), the trailer is appended *after* the packet, and the packet's own
    /// Length field is **not** extended (only the IPv6 payload grows, §2). The
    /// digest is HMAC-SHA-256 over the checksum-zeroed packet, the trailer's
    /// 16-byte fixed header, and the Apad placeholder for the Auth Data (§4.5).
    ///
    /// [`encode`]: Packet::encode
    pub fn encode_auth(&self, src: Ipv6Addr, dst: Ipv6Addr, auth: &Auth) -> Vec<u8> {
        let Auth::Hmac { sa_id, key, seq } = auth else {
            return self.encode(src, dst);
        };
        let mut out = self.encode(src, dst);
        // §4.2: the checksum is not used alongside the trailer.
        out[12] = 0;
        out[13] = 0;
        // Trailer fixed header; Auth Data Len covers the whole trailer (§4.1).
        let auth_data_len = (AT_FIXED_LEN + hmac::DIGEST_LEN) as u16;
        out.extend_from_slice(&AUTH_TYPE_HMAC.to_be_bytes());
        out.extend_from_slice(&auth_data_len.to_be_bytes());
        out.extend_from_slice(&[0, 0]); // reserved
        out.extend_from_slice(&sa_id.to_be_bytes());
        out.extend_from_slice(&seq.to_be_bytes());
        // Compute the digest with the Auth Data field pre-set to Apad, then let it
        // replace that placeholder.
        let digest_at = out.len();
        out.extend_from_slice(&apad(src));
        let digest = hmac::hmac_sha256(key, &out);
        out[digest_at..].copy_from_slice(&digest);
        out
    }

    /// Parse a packet carrying an RFC 7166 Authentication Trailer, verifying its
    /// HMAC against `auth`. With [`Auth::None`] this is the plain [`decode`].
    ///
    /// The trailer follows the OSPFv3 packet, whose Length field does not count
    /// it, so the packet is `buf[..stated]` and the trailer `buf[stated..]`. The
    /// checksum is not verified (it is zero, §4.2); integrity rests on the HMAC,
    /// compared in constant time.
    ///
    /// [`decode`]: Packet::decode
    pub fn decode_auth(
        buf: &[u8],
        src: Ipv6Addr,
        dst: Ipv6Addr,
        auth: &Auth,
    ) -> Result<Packet, DecodeError> {
        let Auth::Hmac { sa_id, key, .. } = auth else {
            return Packet::decode(buf, src, dst);
        };
        if buf.len() < HEADER_LEN {
            return Err(DecodeError::TooShort);
        }
        let stated = u16::from_be_bytes([buf[2], buf[3]]) as usize;
        if stated < HEADER_LEN || buf.len() != stated + AT_FIXED_LEN + hmac::DIGEST_LEN {
            return Err(DecodeError::BadAuth);
        }
        let trailer = &buf[stated..];
        if u16::from_be_bytes([trailer[0], trailer[1]]) != AUTH_TYPE_HMAC
            || u16::from_be_bytes([trailer[2], trailer[3]]) as usize != trailer.len()
            || u16::from_be_bytes([trailer[6], trailer[7]]) != *sa_id
        {
            return Err(DecodeError::BadAuth);
        }
        // Recompute the digest over the checksum-zeroed packet + trailer fixed
        // header + Apad, then compare it against the received digest.
        let mut scratch = Vec::with_capacity(stated + AT_FIXED_LEN + hmac::DIGEST_LEN);
        scratch.extend_from_slice(&buf[..stated]);
        scratch[12] = 0;
        scratch[13] = 0;
        scratch.extend_from_slice(&trailer[..AT_FIXED_LEN]);
        scratch.extend_from_slice(&apad(src));
        let expected = hmac::hmac_sha256(key, &scratch);
        if !ct_eq(&expected, &trailer[AT_FIXED_LEN..]) {
            return Err(DecodeError::BadAuth);
        }
        Self::parse_unchecked(&buf[..stated])
    }

    /// The 64-bit RFC 7166 cryptographic sequence number of an authenticated
    /// packet, or `None` when `buf` has no well-formed HMAC trailer. Used by the
    /// daemon for anti-replay (a sequence that fails to advance is a replay).
    pub fn crypto_seq(buf: &[u8]) -> Option<u64> {
        if buf.len() < HEADER_LEN {
            return None;
        }
        let stated = u16::from_be_bytes([buf[2], buf[3]]) as usize;
        if stated < HEADER_LEN || buf.len() < stated + AT_FIXED_LEN {
            return None;
        }
        let t = &buf[stated..];
        if u16::from_be_bytes([t[0], t[1]]) != AUTH_TYPE_HMAC {
            return None;
        }
        Some(u64::from_be_bytes([
            t[8], t[9], t[10], t[11], t[12], t[13], t[14], t[15],
        ]))
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
    out.extend_from_slice(&h.interface_id.to_be_bytes());
    out.push(h.router_priority);
    put_u24(out, h.options);
    out.extend_from_slice(&h.hello_interval.to_be_bytes());
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
    let rest = &body[HELLO_FIXED_LEN..];
    if rest.len() % 4 != 0 {
        return Err(DecodeError::TooShort);
    }
    let neighbors = rest
        .chunks_exact(4)
        .map(|c| Ipv4Addr::new(c[0], c[1], c[2], c[3]))
        .collect();
    Ok(Hello {
        interface_id: u32::from_be_bytes([body[0], body[1], body[2], body[3]]),
        router_priority: body[4],
        options: get_u24(&body[5..8]),
        hello_interval: u16::from_be_bytes([body[8], body[9]]),
        dead_interval: u16::from_be_bytes([body[10], body[11]]),
        designated_router: Ipv4Addr::new(body[12], body[13], body[14], body[15]),
        backup_designated_router: Ipv4Addr::new(body[16], body[17], body[18], body[19]),
        neighbors,
    })
}

// --- Database Description ---------------------------------------------------

fn encode_dd(d: &DatabaseDescription, out: &mut Vec<u8>) {
    out.push(0); // reserved
    put_u24(out, d.options);
    out.extend_from_slice(&d.interface_mtu.to_be_bytes());
    out.push(0); // reserved
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
        options: get_u24(&body[1..4]),
        interface_mtu: u16::from_be_bytes([body[4], body[5]]),
        flags: body[7],
        dd_sequence: u32::from_be_bytes([body[8], body[9], body[10], body[11]]),
        lsa_headers,
    })
}

// --- Link State Request ----------------------------------------------------

fn encode_lsr(r: &LinkStateRequest, out: &mut Vec<u8>) {
    for e in &r.entries {
        out.extend_from_slice(&[0, 0]); // reserved
        out.extend_from_slice(&e.ls_type.as_u16().to_be_bytes());
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
        entries.push(LsRequest {
            ls_type: LsType::from_u16(u16::from_be_bytes([c[2], c[3]])),
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
    // Never size the allocation from the wire count directly: each LSA occupies
    // at least an LSA header, so the remaining body can hold at most this many.
    // Otherwise a crafted count (up to 2^32) drives a multi-GB pre-allocation
    // (abort/OOM) before a single LSA is validated.
    let mut lsas = Vec::with_capacity(count.min((body.len() - 4) / LSA_HEADER_LEN));
    let mut off = 4;
    for _ in 0..count {
        let (lsa, used) = Lsa::decode(&body[off..]).ok_or(DecodeError::BadLsa)?;
        // RFC 2328 §13 step 1 (RFC 5340): an LSA whose Fletcher LS checksum is
        // wrong is discarded (and the next one processed), never installed or
        // flooded. The bytes are still consumed so the packet stays framed.
        if checksum_valid(&body[off..off + used]) {
            lsas.push(lsa);
        }
        off += used;
    }
    if off != body.len() {
        return Err(DecodeError::BadLsa);
    }
    Ok(LinkStateUpdate { lsas })
}

// --- Link State Acknowledgment ---------------------------------------------

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
    use crate::{
        ALL_SPF_ROUTERS, DEFAULT_DEAD_INTERVAL, DEFAULT_HELLO_INTERVAL, INITIAL_SEQUENCE_NUMBER,
        OPT_E, OPT_R, OPT_V6,
    };

    const SRC: Ipv6Addr = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);

    fn sample_header() -> Header {
        Header {
            router_id: Ipv4Addr::new(10, 0, 0, 1),
            area_id: Ipv4Addr::new(0, 0, 0, 0),
            instance_id: 0,
        }
    }

    fn sample_lsa_header(lsid: [u8; 4]) -> LsaHeader {
        LsaHeader {
            ls_age: 1,
            ls_type: LsType::Router,
            link_state_id: Ipv4Addr::from(lsid),
            advertising_router: Ipv4Addr::new(10, 0, 0, 1),
            ls_seq: INITIAL_SEQUENCE_NUMBER,
            ls_checksum: 0xbeef,
            length: 24,
        }
    }

    fn sample_hello() -> Packet {
        Packet::hello(
            sample_header(),
            Hello {
                interface_id: 5,
                router_priority: 1,
                options: OPT_V6 | OPT_R | OPT_E,
                hello_interval: DEFAULT_HELLO_INTERVAL,
                dead_interval: DEFAULT_DEAD_INTERVAL,
                designated_router: Ipv4Addr::new(10, 0, 0, 1),
                backup_designated_router: Ipv4Addr::new(10, 0, 0, 2),
                neighbors: vec![Ipv4Addr::new(10, 0, 0, 2), Ipv4Addr::new(10, 0, 0, 3)],
            },
        )
    }

    fn roundtrip(pkt: &Packet) -> Packet {
        let bytes = pkt.encode(SRC, ALL_SPF_ROUTERS);
        Packet::decode(&bytes, SRC, ALL_SPF_ROUTERS).expect("decodes")
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
        let bytes = pkt.encode(SRC, ALL_SPF_ROUTERS);
        // 16 header + 20 fixed + 2 neighbours * 4.
        assert_eq!(bytes.len(), HEADER_LEN + HELLO_FIXED_LEN + 8);
        assert_eq!(bytes[0], VERSION);
        assert_eq!(bytes[1], PacketType::Hello.as_u8());
        assert_eq!(roundtrip(&pkt), pkt);
    }

    #[test]
    fn checksum_is_verified_and_address_bound() {
        let bytes = sample_hello().encode(SRC, ALL_SPF_ROUTERS);
        // Corrupt a body byte; the checksum must now fail.
        let mut corrupt = bytes.clone();
        let last = corrupt.len() - 1;
        corrupt[last] ^= 0xff;
        assert_eq!(
            Packet::decode(&corrupt, SRC, ALL_SPF_ROUTERS),
            Err(DecodeError::BadChecksum)
        );
        // The checksum binds the source/destination; the wrong source rejects it.
        let other = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 2);
        assert_eq!(
            Packet::decode(&bytes, other, ALL_SPF_ROUTERS),
            Err(DecodeError::BadChecksum)
        );
    }

    #[test]
    fn hmac_auth_trailer_roundtrips_and_rejects_tampering() {
        let pkt = sample_hello();
        let auth = Auth::Hmac {
            sa_id: 7,
            key: b"a-shared-secret".to_vec(),
            seq: 42,
        };
        let bytes = pkt.encode_auth(SRC, ALL_SPF_ROUTERS, &auth);

        // The trailer is appended beyond the packet's own Length field (16-byte
        // fixed header + 32-byte HMAC-SHA-256 digest) and the checksum is zeroed.
        let stated = u16::from_be_bytes([bytes[2], bytes[3]]) as usize;
        assert_eq!(bytes.len(), stated + AT_FIXED_LEN + hmac::DIGEST_LEN);
        assert_eq!(&bytes[12..14], &[0, 0]);
        assert_eq!(Packet::crypto_seq(&bytes), Some(42));

        // It round-trips and verifies against the same key.
        assert_eq!(
            Packet::decode_auth(&bytes, SRC, ALL_SPF_ROUTERS, &auth).expect("verifies"),
            pkt
        );

        // A flipped digest byte is rejected.
        let mut tampered = bytes.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 0xff;
        assert_eq!(
            Packet::decode_auth(&tampered, SRC, ALL_SPF_ROUTERS, &auth),
            Err(DecodeError::BadAuth)
        );

        // A flipped body byte is rejected — the HMAC covers the whole packet.
        let mut body_flip = bytes.clone();
        body_flip[HEADER_LEN] ^= 0xff;
        assert_eq!(
            Packet::decode_auth(&body_flip, SRC, ALL_SPF_ROUTERS, &auth),
            Err(DecodeError::BadAuth)
        );

        // The wrong key is rejected.
        let wrong = Auth::Hmac {
            sa_id: 7,
            key: b"different-secret".to_vec(),
            seq: 42,
        };
        assert_eq!(
            Packet::decode_auth(&bytes, SRC, ALL_SPF_ROUTERS, &wrong),
            Err(DecodeError::BadAuth)
        );

        // A different source changes Apad (§4.5), so the digest no longer matches.
        let other = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 2);
        assert_eq!(
            Packet::decode_auth(&bytes, other, ALL_SPF_ROUTERS, &auth),
            Err(DecodeError::BadAuth)
        );
    }

    #[test]
    fn rejects_bad_version_and_length() {
        let mut bytes = sample_hello().encode(SRC, ALL_SPF_ROUTERS);
        bytes[0] = 2;
        assert_eq!(
            Packet::decode(&bytes, SRC, ALL_SPF_ROUTERS),
            Err(DecodeError::BadVersion(2))
        );

        let mut bytes = sample_hello().encode(SRC, ALL_SPF_ROUTERS);
        bytes.push(0);
        assert!(matches!(
            Packet::decode(&bytes, SRC, ALL_SPF_ROUTERS),
            Err(DecodeError::BadLength { .. })
        ));
    }

    #[test]
    fn hello_with_no_neighbors() {
        let mut pkt = sample_hello();
        if let Body::Hello(h) = &mut pkt.body {
            h.neighbors.clear();
        }
        let bytes = pkt.encode(SRC, ALL_SPF_ROUTERS);
        assert_eq!(bytes.len(), HEADER_LEN + HELLO_FIXED_LEN);
        assert_eq!(roundtrip(&pkt), pkt);
    }

    #[test]
    fn instance_id_survives() {
        let mut pkt = sample_hello();
        pkt.header.instance_id = 42;
        assert_eq!(roundtrip(&pkt).header.instance_id, 42);
    }

    #[test]
    fn database_description_roundtrips_with_headers_and_flags() {
        let pkt = Packet::database_description(
            sample_header(),
            DatabaseDescription {
                options: OPT_V6 | OPT_E,
                interface_mtu: 1500,
                flags: DD_FLAG_INIT | DD_FLAG_MORE | DD_FLAG_MASTER,
                dd_sequence: 0x1234_5678,
                lsa_headers: vec![sample_lsa_header([0, 0, 0, 1]), sample_lsa_header([0, 0, 0, 2])],
            },
        );
        let bytes = pkt.encode(SRC, ALL_SPF_ROUTERS);
        assert_eq!(bytes.len(), HEADER_LEN + DD_FIXED_LEN + 2 * LSA_HEADER_LEN);
        assert_eq!(bytes[1], PacketType::DatabaseDescription.as_u8());
        assert_eq!(roundtrip(&pkt), pkt);
    }

    #[test]
    fn empty_init_dd_roundtrips() {
        let pkt = Packet::database_description(
            sample_header(),
            DatabaseDescription {
                options: OPT_V6 | OPT_E,
                interface_mtu: 1500,
                flags: DD_FLAG_INIT | DD_FLAG_MORE | DD_FLAG_MASTER,
                dd_sequence: 42,
                lsa_headers: vec![],
            },
        );
        let bytes = pkt.encode(SRC, ALL_SPF_ROUTERS);
        assert_eq!(bytes.len(), HEADER_LEN + DD_FIXED_LEN);
        let decoded = roundtrip(&pkt);
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
                        link_state_id: Ipv4Addr::new(0, 0, 0, 0),
                        advertising_router: Ipv4Addr::new(10, 0, 0, 2),
                    },
                    LsRequest {
                        ls_type: LsType::AsExternal,
                        link_state_id: Ipv4Addr::new(0, 0, 0, 9),
                        advertising_router: Ipv4Addr::new(10, 0, 0, 9),
                    },
                ],
            },
        );
        let bytes = pkt.encode(SRC, ALL_SPF_ROUTERS);
        assert_eq!(bytes.len(), HEADER_LEN + 2 * LS_REQUEST_LEN);
        assert_eq!(roundtrip(&pkt), pkt);
    }

    #[test]
    fn link_state_update_roundtrips_full_lsas() {
        let lsa = Lsa {
            header: sample_lsa_header([0, 0, 0, 0]),
            body: LsaBody::Router(RouterLsa {
                flags: 0,
                options: OPT_V6 | OPT_R,
                links: vec![RouterLink {
                    link_type: RouterLinkType::PointToPoint,
                    metric: 5,
                    interface_id: 1,
                    neighbor_interface_id: 2,
                    neighbor_router_id: Ipv4Addr::new(10, 0, 0, 2),
                }],
            }),
        };
        let pkt = Packet::link_state_update(
            sample_header(),
            LinkStateUpdate {
                lsas: vec![lsa.clone(), lsa],
            },
        );
        let bytes = pkt.encode(SRC, ALL_SPF_ROUTERS);
        let decoded = Packet::decode(&bytes, SRC, ALL_SPF_ROUTERS).expect("valid LSU decodes");
        let upd = decoded.as_link_state_update().unwrap();
        assert_eq!(upd.lsas.len(), 2);
        let orig = pkt.as_link_state_update().unwrap();
        assert_eq!(upd.lsas[0].body, orig.lsas[0].body);
        assert_eq!(upd.lsas[0].key(), orig.lsas[0].key());
    }

    #[test]
    fn lsu_discards_an_lsa_with_a_bad_checksum() {
        let lsa = |lsid: [u8; 4]| Lsa {
            header: sample_lsa_header(lsid),
            body: LsaBody::Router(RouterLsa { flags: 0, options: OPT_V6, links: vec![] }),
        };
        // A two-LSA update; encode stamps each with a valid Fletcher checksum.
        let mut body = Vec::new();
        encode_lsu(
            &LinkStateUpdate { lsas: vec![lsa([1, 1, 1, 1]), lsa([2, 2, 2, 2])] },
            &mut body,
        );
        // Flip a byte of the second LSA's stored ls_checksum field so decoding still
        // succeeds (the field is not structural) but the checksum no longer matches.
        // Layout: 4-byte count + LSA1 (20-byte header + 4-byte router body = 24)
        // then LSA2, whose ls_checksum sits 16 bytes into its header.
        let lsa2_checksum = 4 + 24 + 16;
        body[lsa2_checksum] ^= 0xff;
        let decoded = decode_lsu(&body).expect("packet still frames");
        // The corrupt LSA is discarded; the intact one survives.
        assert_eq!(decoded.lsas.len(), 1);
        assert_eq!(decoded.lsas[0].header.link_state_id, Ipv4Addr::new(1, 1, 1, 1));
    }

    #[test]
    fn truncated_lsu_is_bad_lsa_not_panic() {
        let lsa = Lsa {
            header: sample_lsa_header([0, 0, 0, 0]),
            body: LsaBody::Router(RouterLsa {
                flags: 0,
                options: OPT_V6,
                links: vec![],
            }),
        };
        let pkt = Packet::link_state_update(sample_header(), LinkStateUpdate { lsas: vec![lsa] });
        let mut bytes = pkt.encode(SRC, ALL_SPF_ROUTERS);
        // Claim two LSAs while only one is present, then re-stamp length+checksum.
        bytes[HEADER_LEN..HEADER_LEN + 4].copy_from_slice(&2u32.to_be_bytes());
        let len = bytes.len() as u16;
        bytes[2..4].copy_from_slice(&len.to_be_bytes());
        bytes[12] = 0;
        bytes[13] = 0;
        let csum = packet_checksum(SRC, ALL_SPF_ROUTERS, &bytes);
        bytes[12..14].copy_from_slice(&csum.to_be_bytes());
        assert_eq!(
            Packet::decode(&bytes, SRC, ALL_SPF_ROUTERS),
            Err(DecodeError::BadLsa)
        );
    }

    #[test]
    fn link_state_ack_roundtrips() {
        let pkt = Packet::link_state_ack(
            sample_header(),
            LinkStateAck {
                lsa_headers: vec![sample_lsa_header([0, 0, 0, 1]), sample_lsa_header([0, 0, 0, 9])],
            },
        );
        let bytes = pkt.encode(SRC, ALL_SPF_ROUTERS);
        assert_eq!(bytes.len(), HEADER_LEN + 2 * LSA_HEADER_LEN);
        assert_eq!(roundtrip(&pkt), pkt);
    }

    #[test]
    fn wrong_accessor_returns_none() {
        let hello = sample_hello();
        assert!(hello.as_database_description().is_none());
        assert!(hello.as_link_state_update().is_none());
        assert!(hello.as_hello().is_some());
    }

    #[test]
    fn lsu_with_huge_count_errors_without_oom() {
        // A crafted LSA count (here u32::MAX) must never size the allocation: with
        // no LSA bytes following, decode returns an error immediately instead of
        // attempting a multi-GB pre-allocation (which would abort the process).
        let body = [0xff, 0xff, 0xff, 0xff]; // count = 4_294_967_295, no LSA data
        assert_eq!(decode_lsu(&body), Err(DecodeError::BadLsa));
    }

    // =======================================================================
    // Byte-offset assertions (RFC 5340 Appendix A.3)
    // =======================================================================

    /// RFC 5340 §A.3.1 fixes the 16-byte common header: Version 0, Type 1,
    /// Packet Length 2..4, Router ID 4..8, Area ID 8..12, Checksum 12..14,
    /// **Instance ID 14**, and a reserved zero at 15. OSPFv3 has no
    /// authentication field, which is why the header is 16 octets and not
    /// OSPFv2's 24.
    ///
    /// Instance ID is what lets several OSPFv3 instances share one link
    /// (§4.2.1): a packet whose Instance ID does not match the receiving
    /// interface's is dropped. Put it at byte 15 and it always reads as the
    /// reserved zero, so every non-zero-instance deployment silently forms no
    /// adjacencies — while `instance_id_survives` above passes, because wren
    /// reads back the same byte it wrote.
    #[test]
    fn the_common_header_writes_each_field_at_the_offset_the_rfc_names() {
        let mut pkt = sample_hello();
        pkt.header.router_id = Ipv4Addr::new(1, 2, 3, 4);
        pkt.header.area_id = Ipv4Addr::new(0, 0, 0, 42);
        pkt.header.instance_id = 42;
        let b = pkt.encode(SRC, ALL_SPF_ROUTERS);
        assert_eq!(b[0], 3, "Version is byte 0 and OSPFv3 is 3");
        assert_eq!(b[1], 1, "Type is byte 1 and a Hello is 1");
        assert_eq!(
            u16::from_be_bytes([b[2], b[3]]) as usize,
            b.len(),
            "Packet Length is bytes 2..4"
        );
        assert_eq!(&b[4..8], &[1, 2, 3, 4], "Router ID is bytes 4..8");
        assert_eq!(&b[8..12], &[0, 0, 0, 42], "Area ID is bytes 8..12");
        assert_ne!(&b[12..14], &[0, 0], "Checksum is bytes 12..14 and is filled in");
        assert_eq!(b[14], 42, "Instance ID is byte 14");
        assert_eq!(b[15], 0, "byte 15 is reserved and must be zero");
    }

    /// RFC 5340 §A.3.1 assigns the packet type codes, and they are the numbers
    /// every other OSPFv3 speaker switches on. `packet_type_roundtrips` above
    /// only checks the enum against itself.
    #[test]
    fn the_packet_type_codes_are_the_ones_the_rfc_assigns() {
        for (t, code) in [
            (PacketType::Hello, 1u8),
            (PacketType::DatabaseDescription, 2),
            (PacketType::LinkStateRequest, 3),
            (PacketType::LinkStateUpdate, 4),
            (PacketType::LinkStateAck, 5),
        ] {
            assert_eq!(t.as_u8(), code, "{t:?} is packet type {code}");
            assert_eq!(PacketType::from_u8(code), Some(t));
        }
        assert_eq!(PacketType::from_u8(0), None);
        assert_eq!(PacketType::from_u8(6), None);
    }

    /// RFC 5340 §A.3.2: a Hello body is Interface ID 16..20, Rtr Pri 20, a
    /// 24-bit Options field 21..24, HelloInterval 24..26, RouterDeadInterval
    /// 26..28, Designated Router ID 28..32, Backup DR ID 32..36, then the
    /// neighbour list.
    ///
    /// Note the two differences from OSPFv2 that a round trip cannot police:
    /// Options is three octets, not one, and the dead interval is 16 bits, not
    /// 32. Encode either at OSPFv2's width and every field after it shifts,
    /// so the peer reads a hello/dead pair that never matches its own and
    /// §4.2.1 rejects the Hello outright.
    #[test]
    fn a_hello_body_is_encoded_in_the_rfc_field_order() {
        let pkt = Packet::hello(
            sample_header(),
            Hello {
                interface_id: 0x1112_1314,
                router_priority: 7,
                options: OPT_V6 | OPT_R | OPT_E,
                hello_interval: 0x000a,
                dead_interval: 0x0028,
                designated_router: Ipv4Addr::new(10, 0, 0, 1),
                backup_designated_router: Ipv4Addr::new(10, 0, 0, 2),
                neighbors: vec![Ipv4Addr::new(10, 0, 0, 3)],
            },
        );
        let b = pkt.encode(SRC, ALL_SPF_ROUTERS);
        assert_eq!(&b[16..20], &[0x11, 0x12, 0x13, 0x14], "Interface ID is bytes 16..20");
        assert_eq!(b[20], 7, "Rtr Pri is byte 20");
        assert_eq!(
            u32::from_be_bytes([0, b[21], b[22], b[23]]),
            OPT_V6 | OPT_R | OPT_E,
            "Options is a 24-bit field at bytes 21..24"
        );
        assert_eq!(&b[24..26], &[0x00, 0x0a], "HelloInterval is bytes 24..26");
        assert_eq!(&b[26..28], &[0x00, 0x28], "RouterDeadInterval is bytes 26..28");
        assert_eq!(&b[28..32], &[10, 0, 0, 1], "Designated Router ID is bytes 28..32");
        assert_eq!(&b[32..36], &[10, 0, 0, 2], "Backup DR ID is bytes 32..36");
        assert_eq!(&b[36..40], &[10, 0, 0, 3], "the neighbour list starts at byte 36");
        assert_eq!(b.len(), 40);
    }

    /// RFC 5340 §A.3.3: a Database Description body is a reserved octet 16, a
    /// 24-bit Options field 17..20, Interface MTU 20..22, a second reserved
    /// octet 22, the I/M/MS flag byte 23, and the DD sequence number 24..28.
    /// §A.3.3 also fixes the flag bits: MS = 0x01, M = 0x02, I = 0x04.
    ///
    /// Note the reserved octet *before* the flags: OSPFv2 has no such gap, so
    /// copying its layout puts the flags one byte early. Both ends then believe
    /// they are master (or both slave) and §10.8's exchange deadlocks in
    /// ExStart forever — with no error anywhere, because wren reads back
    /// exactly what it wrote.
    #[test]
    fn a_database_description_body_and_its_flag_bits_match_the_rfc() {
        assert_eq!(DD_FLAG_MASTER, 0x01, "MS is the low bit of the flag byte");
        assert_eq!(DD_FLAG_MORE, 0x02, "M is 0x02");
        assert_eq!(DD_FLAG_INIT, 0x04, "I is 0x04");

        let pkt = Packet::database_description(
            sample_header(),
            DatabaseDescription {
                options: OPT_V6 | OPT_E,
                interface_mtu: 1500,
                flags: DD_FLAG_INIT | DD_FLAG_MORE | DD_FLAG_MASTER,
                dd_sequence: 0x1234_5678,
                lsa_headers: vec![],
            },
        );
        let b = pkt.encode(SRC, ALL_SPF_ROUTERS);
        assert_eq!(b[1], 2, "a DD packet is Type 2");
        assert_eq!(b[16], 0, "byte 16 is reserved and must be zero");
        assert_eq!(
            u32::from_be_bytes([0, b[17], b[18], b[19]]),
            OPT_V6 | OPT_E,
            "Options is a 24-bit field at bytes 17..20"
        );
        assert_eq!(&b[20..22], &[0x05, 0xdc], "Interface MTU 1500 is bytes 20..22");
        assert_eq!(b[22], 0, "byte 22 is reserved and must be zero");
        assert_eq!(b[23], 0x07, "the I|M|MS flag byte is byte 23");
        assert_eq!(&b[24..28], &[0x12, 0x34, 0x56, 0x78], "DD sequence is bytes 24..28");
        assert_eq!(b.len(), 28);
    }

    /// RFC 5340 §A.3.4: each Link State Request entry is 12 octets — two
    /// reserved zero octets, then the *16-bit* LS Type at 2..4, Link State ID
    /// 4..8, Advertising Router 8..12.
    ///
    /// The reserved pair is easy to omit (OSPFv2 has a 32-bit type field with
    /// three leading zeros instead), which shifts both identifiers and makes
    /// every request name an LSA nobody has — the adjacency then never leaves
    /// Loading.
    #[test]
    fn a_link_state_request_entry_has_two_reserved_octets_before_a_16_bit_type() {
        let pkt = Packet::link_state_request(
            sample_header(),
            LinkStateRequest {
                entries: vec![LsRequest {
                    ls_type: LsType::AsExternal, // 0x4005
                    link_state_id: Ipv4Addr::new(10, 1, 0, 0),
                    advertising_router: Ipv4Addr::new(10, 0, 0, 9),
                }],
            },
        );
        let b = pkt.encode(SRC, ALL_SPF_ROUTERS);
        let e = &b[16..28];
        assert_eq!(&e[0..2], &[0, 0], "bytes 0..2 of the entry are reserved zeros");
        assert_eq!(&e[2..4], &[0x40, 0x05], "the 16-bit LS Type is bytes 2..4");
        assert_eq!(&e[4..8], &[10, 1, 0, 0], "Link State ID is bytes 4..8");
        assert_eq!(&e[8..12], &[10, 0, 0, 9], "Advertising Router is bytes 8..12");
        assert_eq!(b.len(), 16 + 12);
    }
}
