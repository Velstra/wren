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

use crate::lsa::{checksum_valid, Lsa, LsType, LsaHeader, LSA_HEADER_LEN};
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

/// AuType 0 — Null authentication (RFC 2328 §D.3): the 8 auth bytes are zero.
pub const AU_NULL: u16 = 0;
/// AuType 1 — simple (cleartext) password authentication.
pub const AU_SIMPLE: u16 = 1;
/// AuType 2 — cryptographic (MD5) authentication.
pub const AU_CRYPTO: u16 = 2;
/// The length of an MD5 message digest, and of the OSPF cryptographic key field.
const MD5_LEN: usize = 16;

/// How an OSPF packet is authenticated (RFC 2328 §D). The interface's configured
/// scheme is supplied to [`Packet::encode_auth`] when sending and to
/// [`Packet::decode_auth`] when receiving; a packet whose AuType or authentication
/// data does not match the configured scheme is rejected ([`DecodeError::BadAuth`]).
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Auth {
    /// No authentication (the default): any packet is accepted, the auth field is 0.
    Null,
    /// Simple password (AuType 1): a cleartext key (≤ 8 bytes) carried verbatim in the
    /// 64-bit authentication field. Trivially sniffable — it only stops a router that
    /// is merely misconfigured, not an attacker.
    Simple(Vec<u8>),
    /// Cryptographic MD5 (AuType 2): a keyed MD5 digest of the packet is appended after
    /// the body, and the auth field carries the key id, the digest length and a
    /// non-decreasing sequence number. An attacker without the key cannot forge a
    /// packet the digest will accept.
    Md5 {
        /// The key identifier (lets a router roll keys without a flag day).
        key_id: u8,
        /// The shared secret; padded with zeros (or truncated) to 16 bytes for MD5.
        key: Vec<u8>,
        /// The cryptographic sequence number written into the auth field when sending
        /// (ignored when verifying — anti-replay sequencing is left to the caller).
        seq: u32,
    },
}

impl Auth {
    /// The on-wire AuType value for this scheme.
    pub fn au_type(&self) -> u16 {
        match self {
            Auth::Null => AU_NULL,
            Auth::Simple(_) => AU_SIMPLE,
            Auth::Md5 { .. } => AU_CRYPTO,
        }
    }

    /// The 8-byte authentication field to place in the header for this scheme.
    fn auth_field(&self) -> [u8; 8] {
        let mut f = [0u8; 8];
        match self {
            Auth::Null => {}
            Auth::Simple(pw) => {
                let n = pw.len().min(8);
                f[..n].copy_from_slice(&pw[..n]);
            }
            Auth::Md5 { key_id, seq, .. } => {
                // [0,1] reserved (0); [2] key id; [3] auth-data length; [4..8] seq.
                f[2] = *key_id;
                f[3] = MD5_LEN as u8;
                f[4..8].copy_from_slice(&seq.to_be_bytes());
            }
        }
        f
    }
}

/// The OSPF cryptographic key padded with zeros (or truncated) to the 16 bytes MD5
/// uses (RFC 2328 §D.4.3).
fn md5_key16(key: &[u8]) -> [u8; 16] {
    let mut k = [0u8; 16];
    let n = key.len().min(16);
    k[..n].copy_from_slice(&key[..n]);
    k
}

/// The cryptographic sequence number carried in the header of a received MD5
/// (AuType 2) packet (RFC 2328 §D.3): bytes 4–7 of the 8-byte authentication field.
/// Returns `None` if `buf` is too short or is not a cryptographically-authenticated
/// packet. [`Packet::decode_auth`] validates the keyed digest but deliberately does
/// not track this sequence; the caller enforces the non-decreasing (anti-replay)
/// property across the packets it receives from each neighbour.
pub fn crypto_seq(buf: &[u8]) -> Option<u32> {
    if buf.len() < HEADER_LEN {
        return None;
    }
    if u16::from_be_bytes([buf[14], buf[15]]) != AU_CRYPTO {
        return None;
    }
    Some(u32::from_be_bytes([buf[20], buf[21], buf[22], buf[23]]))
}

/// The MD5 authentication digest over an OSPF packet (RFC 2328 §D.4.3): MD5 of the
/// packet (header through body, with the auth field already filled and the checksum
/// left zero) concatenated with the 16-byte key.
fn md5_auth_digest(packet: &[u8], key: &[u8]) -> [u8; 16] {
    let mut buf = Vec::with_capacity(packet.len() + 16);
    buf.extend_from_slice(packet);
    buf.extend_from_slice(&md5_key16(key));
    crate::md5::md5(&buf)
}

/// Constant-time equality for two byte slices — the MD5 authentication digest is
/// compared this way so a wrong digest leaks no timing signal about how many of
/// its leading bytes were correct.
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
    /// Authentication failed: the AuType did not match the configured scheme, the
    /// simple password differed, or the MD5 key id / digest did not verify.
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
            DecodeError::BadAuth => write!(f, "authentication mismatch"),
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

/// Verify the OSPF checksum of `buf` (the auth field is excluded from the sum, so this
/// is independent of the authentication scheme — used for Null and simple-password
/// auth, where the checksum, not a digest, protects the body).
fn verify_checksum(buf: &[u8]) -> Result<(), DecodeError> {
    let mut scratch = buf.to_vec();
    scratch[12] = 0;
    scratch[13] = 0;
    if packet_checksum(&scratch) != u16::from_be_bytes([buf[12], buf[13]]) {
        return Err(DecodeError::BadChecksum);
    }
    Ok(())
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

    /// Serialize the packet with Null authentication. Convenience wrapper over
    /// [`Packet::encode_auth`].
    pub fn encode(&self) -> Vec<u8> {
        self.encode_auth(&Auth::Null)
    }

    /// Serialize the packet, filling in version, type, length, checksum and the
    /// authentication per `auth` (RFC 2328 §D). For Null and simple-password auth the
    /// IP checksum is computed (the auth field is excluded from it) and the password,
    /// if any, written into the auth field. For MD5 the checksum is left zero and a
    /// keyed digest is appended after the body, with the length field covering only
    /// the OSPF packet (not the trailing digest).
    pub fn encode_auth(&self, auth: &Auth) -> Vec<u8> {
        let mut out = Vec::with_capacity(HEADER_LEN + HELLO_FIXED_LEN);
        // Common header; length + checksum patched below, auth field filled now.
        out.push(VERSION);
        out.push(self.body.packet_type().as_u8());
        out.extend_from_slice(&[0, 0]); // length, patched below
        out.extend_from_slice(&self.header.router_id.octets());
        out.extend_from_slice(&self.header.area_id.octets());
        out.extend_from_slice(&[0, 0]); // checksum, patched (or left zero for MD5)
        out.extend_from_slice(&auth.au_type().to_be_bytes());
        out.extend_from_slice(&auth.auth_field());

        match &self.body {
            Body::Hello(h) => encode_hello(h, &mut out),
            Body::DatabaseDescription(d) => encode_dd(d, &mut out),
            Body::LinkStateRequest(r) => encode_lsr(r, &mut out),
            Body::LinkStateUpdate(u) => encode_lsu(u, &mut out),
            Body::LinkStateAck(a) => encode_lsack(a, &mut out),
        }

        // The length field covers the OSPF packet only (the MD5 digest, if any, is
        // appended after and counted only in the IP length).
        let len = out.len() as u16;
        out[2..4].copy_from_slice(&len.to_be_bytes());
        match auth {
            Auth::Md5 { key, .. } => {
                // Checksum stays zero with cryptographic auth; append the digest.
                let digest = md5_auth_digest(&out, key);
                out.extend_from_slice(&digest);
            }
            Auth::Null | Auth::Simple(_) => {
                let csum = packet_checksum(&out);
                out[12..14].copy_from_slice(&csum.to_be_bytes());
            }
        }
        out
    }

    /// Parse and validate an OSPF packet expecting Null authentication. Convenience
    /// wrapper over [`Packet::decode_auth`].
    pub fn decode(buf: &[u8]) -> Result<Packet, DecodeError> {
        Packet::decode_auth(buf, &Auth::Null)
    }

    /// Parse and validate an OSPF packet from `buf`, authenticating it against `auth`
    /// (RFC 2328 §D). Verifies the version and length, that the packet's AuType matches
    /// the configured scheme, and the scheme-specific authentication: the checksum and
    /// the password for Null/simple, or the appended keyed digest for MD5. Any mismatch
    /// is rejected.
    pub fn decode_auth(buf: &[u8], auth: &Auth) -> Result<Packet, DecodeError> {
        if buf.len() < HEADER_LEN {
            return Err(DecodeError::TooShort);
        }
        if buf[0] != VERSION {
            return Err(DecodeError::BadVersion(buf[0]));
        }
        let ptype = PacketType::from_u8(buf[1]).ok_or(DecodeError::UnknownType(buf[1]))?;
        let stated = u16::from_be_bytes([buf[2], buf[3]]) as usize;
        // The packet's AuType must match the configured scheme (RFC 2328 §D.3).
        if u16::from_be_bytes([buf[14], buf[15]]) != auth.au_type() {
            return Err(DecodeError::BadAuth);
        }

        // The OSPF packet occupies `stated` bytes; with MD5 a 16-byte digest follows.
        let body_end = match auth {
            Auth::Md5 { .. } => {
                if stated + MD5_LEN != buf.len() || stated < HEADER_LEN {
                    return Err(DecodeError::BadLength { stated: stated as u16, actual: buf.len() });
                }
                stated
            }
            Auth::Null | Auth::Simple(_) => {
                if stated != buf.len() {
                    return Err(DecodeError::BadLength { stated: stated as u16, actual: buf.len() });
                }
                stated
            }
        };

        match auth {
            Auth::Null => verify_checksum(buf)?,
            Auth::Simple(pw) => {
                verify_checksum(buf)?;
                let mut want = [0u8; 8];
                let n = pw.len().min(8);
                want[..n].copy_from_slice(&pw[..n]);
                if buf[16..24] != want {
                    return Err(DecodeError::BadAuth);
                }
            }
            Auth::Md5 { key_id, key, .. } => {
                // The key id must match, and the appended digest must verify over the
                // packet (with its in-place auth field) concatenated with the key.
                if buf[18] != *key_id {
                    return Err(DecodeError::BadAuth);
                }
                let digest = md5_auth_digest(&buf[..body_end], key);
                if !ct_eq(&buf[body_end..body_end + MD5_LEN], &digest) {
                    return Err(DecodeError::BadAuth);
                }
            }
        }

        let header = Header {
            router_id: Ipv4Addr::new(buf[4], buf[5], buf[6], buf[7]),
            area_id: Ipv4Addr::new(buf[8], buf[9], buf[10], buf[11]),
        };
        let body = &buf[HEADER_LEN..body_end];
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
    // Never size the allocation from the wire count directly: each LSA occupies
    // at least an LSA header, so the remaining body can hold at most this many.
    // Otherwise a crafted count (up to 2^32) drives a multi-GB pre-allocation
    // (abort/OOM) before a single LSA is validated.
    let mut lsas = Vec::with_capacity(count.min((body.len() - 4) / LSA_HEADER_LEN));
    let mut off = 4;
    for _ in 0..count {
        let (lsa, used) = Lsa::decode(&body[off..]).ok_or(DecodeError::BadLsa)?;
        // RFC 2328 §13 step 1: an LSA whose Fletcher LS checksum is wrong is
        // discarded (and the next one processed), never installed or flooded. The
        // bytes are still consumed so the packet stays framed.
        if checksum_valid(&body[off..off + used]) {
            lsas.push(lsa);
        }
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
    fn lsu_discards_an_lsa_with_a_bad_checksum() {
        let lsa = |lsid: [u8; 4]| Lsa {
            header: sample_lsa_header(lsid),
            body: LsaBody::Router(RouterLsa { flags: 0, links: vec![] }),
        };
        // A two-LSA update; encode stamps each with a valid Fletcher checksum.
        let mut body = Vec::new();
        encode_lsu(
            &LinkStateUpdate { lsas: vec![lsa([1, 1, 1, 1]), lsa([2, 2, 2, 2])] },
            &mut body,
        );
        // Flip a byte of the second LSA's stored ls_checksum field so decoding
        // still succeeds (the field is not structural) but the checksum no longer
        // matches. Layout: 4-byte count + LSA1 (20-byte header + 4-byte router body
        // = 24) then LSA2, whose ls_checksum sits 16 bytes into its header.
        let lsa2_checksum = 4 + 24 + 16;
        body[lsa2_checksum] ^= 0xff;
        let decoded = decode_lsu(&body).expect("packet still frames");
        // The corrupt LSA is discarded; the intact one survives.
        assert_eq!(decoded.lsas.len(), 1);
        assert_eq!(decoded.lsas[0].header.link_state_id, Ipv4Addr::new(1, 1, 1, 1));
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
    fn simple_password_auth_roundtrips_and_rejects_a_wrong_key() {
        let auth = Auth::Simple(b"opensesame".to_vec()); // > 8 bytes: truncated to 8
        let bytes = sample_hello().encode_auth(&auth);
        assert_eq!(u16::from_be_bytes([bytes[14], bytes[15]]), AU_SIMPLE);
        // Correct key decodes; the auth field carries the (truncated) password.
        assert_eq!(Packet::decode_auth(&bytes, &auth).unwrap(), sample_hello());
        // A different key is rejected, and so is Null against a type-1 packet.
        assert_eq!(
            Packet::decode_auth(&bytes, &Auth::Simple(b"other".to_vec())),
            Err(DecodeError::BadAuth)
        );
        assert_eq!(Packet::decode_auth(&bytes, &Auth::Null), Err(DecodeError::BadAuth));
    }

    #[test]
    fn md5_auth_appends_a_digest_and_rejects_tampering() {
        let auth = Auth::Md5 { key_id: 7, key: b"sharedsecret".to_vec(), seq: 0x0102_0304 };
        let mut bytes = sample_hello().encode_auth(&auth);
        assert_eq!(u16::from_be_bytes([bytes[14], bytes[15]]), AU_CRYPTO);
        // The 16-byte digest is appended beyond the OSPF length field.
        let stated = u16::from_be_bytes([bytes[2], bytes[3]]) as usize;
        assert_eq!(bytes.len(), stated + 16);
        assert_eq!(bytes[18], 7); // key id in the auth field
        // The right key verifies.
        assert_eq!(Packet::decode_auth(&bytes, &auth).unwrap(), sample_hello());
        // A wrong key id, a wrong key, and a flipped body byte are all rejected.
        let wrong_id = Auth::Md5 { key_id: 8, key: b"sharedsecret".to_vec(), seq: 0 };
        assert_eq!(Packet::decode_auth(&bytes, &wrong_id), Err(DecodeError::BadAuth));
        let wrong_key = Auth::Md5 { key_id: 7, key: b"different".to_vec(), seq: 0 };
        assert_eq!(Packet::decode_auth(&bytes, &wrong_key), Err(DecodeError::BadAuth));
        bytes[HEADER_LEN] ^= 0xff;
        assert_eq!(Packet::decode_auth(&bytes, &auth), Err(DecodeError::BadAuth));
    }

    #[test]
    fn crypto_seq_reads_the_md5_sequence_and_ignores_other_schemes() {
        // A crypto (AuType 2) packet exposes its sequence for anti-replay tracking.
        let auth = Auth::Md5 { key_id: 3, key: b"k".to_vec(), seq: 0xdead_beef };
        let bytes = sample_hello().encode_auth(&auth);
        assert_eq!(super::crypto_seq(&bytes), Some(0xdead_beef));
        // Null and simple-password packets carry no cryptographic sequence.
        assert_eq!(super::crypto_seq(&sample_hello().encode_auth(&Auth::Null)), None);
        let simple = sample_hello().encode_auth(&Auth::Simple(b"pw".to_vec()));
        assert_eq!(super::crypto_seq(&simple), None);
        // A truncated buffer yields None rather than panicking.
        assert_eq!(super::crypto_seq(&bytes[..10]), None);
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
    // Byte-offset assertions (RFC 2328 Appendix A.3)
    //
    // The tests above encode with wren and decode with wren. That cannot see a
    // field written at the wrong offset, because the decoder reads it back from
    // the same wrong offset — the shape of the Router-LSA flag bug, which only
    // FRR could see. The tests below name the offset the RFC names.
    // =======================================================================

    /// RFC 2328 §A.3.1 fixes the 24-byte common header: Version 0, Type 1,
    /// Packet length 2..4, Router ID 4..8, Area ID 8..12, Checksum 12..14,
    /// AuType 14..16, Authentication 16..24.
    ///
    /// Router ID and Area ID transposed is the dangerous one: it round-trips
    /// perfectly and puts wren in the wrong area on every neighbour, so §10.5
    /// rejects the Hello (area mismatch) and the adjacency never forms at all.
    #[test]
    fn the_common_header_writes_each_field_at_the_offset_the_rfc_names() {
        let pkt = Packet::hello(
            Header {
                router_id: Ipv4Addr::new(1, 2, 3, 4),
                area_id: Ipv4Addr::new(0, 0, 0, 42),
            },
            Hello {
                network_mask: Ipv4Addr::new(255, 255, 255, 0),
                hello_interval: 10,
                options: OPT_E,
                router_priority: 1,
                dead_interval: 40,
                designated_router: Ipv4Addr::UNSPECIFIED,
                backup_designated_router: Ipv4Addr::UNSPECIFIED,
                neighbors: vec![],
            },
        );
        let b = pkt.encode();
        assert_eq!(b[0], 2, "Version is byte 0 and OSPFv2 is 2");
        assert_eq!(b[1], 1, "Type is byte 1 and a Hello is 1");
        assert_eq!(
            u16::from_be_bytes([b[2], b[3]]) as usize,
            b.len(),
            "Packet length is bytes 2..4 and covers the whole OSPF packet"
        );
        assert_eq!(&b[4..8], &[1, 2, 3, 4], "Router ID is bytes 4..8");
        assert_eq!(&b[8..12], &[0, 0, 0, 42], "Area ID is bytes 8..12");
        assert_ne!(&b[12..14], &[0, 0], "Checksum is bytes 12..14 and is filled in");
        assert_eq!(&b[14..16], &[0, 0], "AuType is bytes 14..16, 0 for Null auth");
        assert_eq!(&b[16..24], &[0u8; 8], "the 8 Authentication bytes are 16..24");
    }

    /// The decode side, against bytes laid out by hand — the half a round trip
    /// cannot check. This is a minimal Hello with its checksum computed
    /// externally by the standard 16-bit ones-complement sum.
    #[test]
    fn a_hand_built_hello_decodes_with_every_field_from_its_rfc_offset() {
        let mut w = vec![
            2, 1, 0, 44, // version, type, length = 24 + 20
            10, 0, 0, 9, // Router ID
            0, 0, 0, 1, // Area ID
            0, 0, // checksum (filled below)
            0, 0, // AuType = Null
            0, 0, 0, 0, 0, 0, 0, 0, // Authentication
            255, 255, 255, 0, // Network Mask
            0, 10, // HelloInterval = 10
            0x02, // Options = E-bit
            5,    // Rtr Pri = 5
            0, 0, 0, 40, // RouterDeadInterval = 40
            10, 0, 0, 9, // Designated Router
            10, 0, 0, 8, // Backup Designated Router
        ];
        assert_eq!(w.len(), 44);
        let csum = packet_checksum(&w);
        w[12..14].copy_from_slice(&csum.to_be_bytes());

        let p = Packet::decode(&w).expect("a well-formed Hello decodes");
        assert_eq!(p.header.router_id, Ipv4Addr::new(10, 0, 0, 9));
        assert_eq!(p.header.area_id, Ipv4Addr::new(0, 0, 0, 1));
        let h = p.as_hello().expect("it is a Hello");
        assert_eq!(h.network_mask, Ipv4Addr::new(255, 255, 255, 0));
        assert_eq!(h.hello_interval, 10);
        assert_eq!(h.options, OPT_E);
        assert_eq!(h.router_priority, 5);
        assert_eq!(h.dead_interval, 40);
        assert_eq!(h.designated_router, Ipv4Addr::new(10, 0, 0, 9));
        assert_eq!(h.backup_designated_router, Ipv4Addr::new(10, 0, 0, 8));
        assert!(h.neighbors.is_empty());
    }

    /// RFC 2328 §A.3.2: a Hello body is Network Mask 0..4, HelloInterval 4..6,
    /// Options 6, Rtr Pri 7, RouterDeadInterval 8..12, Designated Router 12..16,
    /// Backup Designated Router 16..20, then the neighbour list.
    ///
    /// Options and Rtr Pri transposed round-trips but tells peers a priority of
    /// 2 and an options byte of 1 — the E-bit is then clear, so §10.5 refuses
    /// the Hello over an external-routing-capability mismatch and the adjacency
    /// never forms. Swapping DR and BDR silently re-runs §9.4's election wrong.
    #[test]
    fn a_hello_body_is_encoded_in_the_rfc_field_order() {
        let pkt = Packet::hello(
            sample_header(),
            Hello {
                network_mask: Ipv4Addr::new(255, 255, 0, 0),
                hello_interval: 0x000a,
                options: OPT_E,
                router_priority: 7,
                dead_interval: 0x0000_0028,
                designated_router: Ipv4Addr::new(10, 0, 0, 1),
                backup_designated_router: Ipv4Addr::new(10, 0, 0, 2),
                neighbors: vec![Ipv4Addr::new(10, 0, 0, 3)],
            },
        );
        let b = pkt.encode();
        let body = &b[HEADER_LEN..];
        assert_eq!(&body[0..4], &[255, 255, 0, 0], "Network Mask is bytes 0..4");
        assert_eq!(&body[4..6], &[0x00, 0x0a], "HelloInterval is bytes 4..6");
        assert_eq!(body[6], OPT_E, "Options is byte 6");
        assert_eq!(body[7], 7, "Rtr Pri is byte 7");
        assert_eq!(&body[8..12], &[0, 0, 0, 0x28], "RouterDeadInterval is bytes 8..12");
        assert_eq!(&body[12..16], &[10, 0, 0, 1], "Designated Router is bytes 12..16");
        assert_eq!(&body[16..20], &[10, 0, 0, 2], "Backup DR is bytes 16..20");
        assert_eq!(&body[20..24], &[10, 0, 0, 3], "the neighbour list starts at byte 20");
        assert_eq!(body.len(), 24);
    }

    /// RFC 2328 §A.3.3: a Database Description body is Interface MTU 0..2,
    /// Options 2, the I/M/MS flag byte 3, DD sequence number 4..8, then LSA
    /// headers. §A.3.3 also fixes the flag *bits*: MS is 0x01, M is 0x02 and I
    /// is 0x04 — not their declaration order.
    ///
    /// Get the bit values wrong and both routers believe they are master (or
    /// both slave); §10.8 then deadlocks the exchange and the adjacency sticks
    /// in ExStart forever. A round trip through wren's own constants cannot see
    /// it, because both sides use the same constants.
    #[test]
    fn a_database_description_body_and_its_flag_bits_match_the_rfc() {
        assert_eq!(DD_FLAG_MASTER, 0x01, "MS is the low bit of the flag byte");
        assert_eq!(DD_FLAG_MORE, 0x02, "M is 0x02");
        assert_eq!(DD_FLAG_INIT, 0x04, "I is 0x04");

        let pkt = Packet::database_description(
            sample_header(),
            DatabaseDescription {
                interface_mtu: 1500,
                options: OPT_E,
                flags: DD_FLAG_INIT | DD_FLAG_MORE | DD_FLAG_MASTER,
                dd_sequence: 0x1234_5678,
                lsa_headers: vec![],
            },
        );
        let b = pkt.encode();
        assert_eq!(b[1], 2, "a DD packet is Type 2");
        let body = &b[HEADER_LEN..];
        assert_eq!(&body[0..2], &[0x05, 0xdc], "Interface MTU 1500 is bytes 0..2");
        assert_eq!(body[2], OPT_E, "Options is byte 2");
        assert_eq!(body[3], 0x07, "the I|M|MS flag byte is byte 3");
        assert_eq!(&body[4..8], &[0x12, 0x34, 0x56, 0x78], "DD sequence is bytes 4..8");
        assert_eq!(body.len(), DD_FIXED_LEN);
    }

    /// RFC 2328 §A.3.4: each Link State Request entry is a *32-bit* LS type
    /// (bytes 0..4, the value in the low octet), Link State ID 4..8, Advertising
    /// Router 8..12. Encoding the type as a single byte would shift both ids by
    /// three and make every request name an LSA nobody has.
    #[test]
    fn a_link_state_request_entry_uses_a_32_bit_ls_type_field() {
        let pkt = Packet::link_state_request(
            sample_header(),
            LinkStateRequest {
                entries: vec![LsRequest {
                    ls_type: LsType::AsExternal, // 5
                    link_state_id: Ipv4Addr::new(10, 1, 0, 0),
                    advertising_router: Ipv4Addr::new(10, 0, 0, 9),
                }],
            },
        );
        let body = &pkt.encode()[HEADER_LEN..];
        assert_eq!(&body[0..4], &[0, 0, 0, 5], "LS type is a 32-bit field at 0..4");
        assert_eq!(&body[4..8], &[10, 1, 0, 0], "Link State ID is bytes 4..8");
        assert_eq!(&body[8..12], &[10, 0, 0, 9], "Advertising Router is bytes 8..12");
        assert_eq!(body.len(), LS_REQUEST_LEN);
    }

    /// RFC 2328 §A.3.5: a Link State Update body opens with a 32-bit count of
    /// the LSAs that follow, then the LSAs back to back.
    #[test]
    fn a_link_state_update_body_opens_with_a_32_bit_lsa_count() {
        let one = Lsa {
            header: sample_lsa_header([10, 0, 0, 1]),
            body: LsaBody::Router(RouterLsa { flags: 0, links: vec![] }),
        };
        let pkt = Packet::link_state_update(
            sample_header(),
            LinkStateUpdate { lsas: vec![one.clone(), one] },
        );
        let b = pkt.encode();
        let body = &b[HEADER_LEN..];
        assert_eq!(&body[0..4], &[0, 0, 0, 2], "# LSAs is a 32-bit field at 0..4");
        // Each LSA declares its own length in bytes 18..20 of its header, and the
        // two must exactly fill the body.
        let first_len = u16::from_be_bytes([body[4 + 18], body[4 + 19]]) as usize;
        assert_eq!(body.len(), 4 + 2 * first_len, "the LSAs are packed back to back");
    }

    /// RFC 2328 §A.3.1: the checksum is the standard IP checksum over the whole
    /// packet with the 64-bit authentication field (bytes 16..24) **excluded**
    /// from the sum, not merely zeroed.
    ///
    /// Include it and a simple-password packet's checksum changes with the
    /// password, so the peer — which excludes it, per the RFC — rejects every
    /// packet as corrupt. A round trip cannot see this because wren computes
    /// and verifies with the same routine.
    #[test]
    fn the_checksum_excludes_the_authentication_field() {
        let null = sample_hello().encode_auth(&Auth::Null);
        let pw = sample_hello().encode_auth(&Auth::Simple(b"secret12".to_vec()));
        // The two packets differ only in the AuType and the auth field.
        assert_ne!(&null[14..24], &pw[14..24]);
        // AuType (14..16) *is* summed, so the checksums are allowed to differ
        // there; force the AuTypes equal and the checksums must then match.
        let mut probe = pw.clone();
        probe[14..16].copy_from_slice(&null[14..16]);
        probe[12] = 0;
        probe[13] = 0;
        let recomputed = packet_checksum(&probe);
        assert_eq!(
            recomputed,
            u16::from_be_bytes([null[12], null[13]]),
            "changing only the 8 authentication bytes must not change the checksum"
        );
    }
}
