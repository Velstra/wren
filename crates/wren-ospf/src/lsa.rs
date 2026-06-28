//! Link-State Advertisements — the LSA header (RFC 2328 §A.4.1), the LS
//! checksum stamping/verification (§12.1.7) and the "which instance is more
//! recent" comparison (§13.1).
//!
//! Only the 20-byte header lives here for now; the bodies (router, network,
//! summary and AS-external LSAs, §A.4.2–§A.4.5) and the LSDB are the next
//! milestone. The header alone already carries everything flooding needs to
//! decide *which* copy of an LSA to keep, which is why it comes first.

use std::cmp::Ordering;
use std::net::Ipv4Addr;

use crate::{fletcher16, fletcher16_valid, MAX_AGE, MAX_AGE_DIFF};

/// The kind of a link-state advertisement (§4.3 / the LS Type field, §A.4.1).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash, PartialOrd, Ord)]
pub enum LsType {
    /// Type 1 — a router's own links within an area.
    Router,
    /// Type 2 — originated by the DR, lists the routers on a transit network.
    Network,
    /// Type 3 — an inter-area route to a network, originated by an ABR.
    SummaryNetwork,
    /// Type 4 — an inter-area route to an ASBR, originated by an ABR.
    SummaryAsbr,
    /// Type 5 — a route external to the AS, originated by an ASBR.
    AsExternal,
    /// Type 7 — an external route within a not-so-stubby area (RFC 3101). Same body
    /// as a type-5, but area-scoped; an ABR translates it to type-5 for the AS.
    Nssa,
}

impl LsType {
    /// Decode the on-wire LS Type byte.
    pub fn from_u8(v: u8) -> Option<Self> {
        Some(match v {
            1 => LsType::Router,
            2 => LsType::Network,
            3 => LsType::SummaryNetwork,
            4 => LsType::SummaryAsbr,
            5 => LsType::AsExternal,
            7 => LsType::Nssa,
            _ => return None,
        })
    }

    /// The on-wire LS Type byte.
    pub fn as_u8(self) -> u8 {
        match self {
            LsType::Router => 1,
            LsType::Network => 2,
            LsType::SummaryNetwork => 3,
            LsType::SummaryAsbr => 4,
            LsType::AsExternal => 5,
            LsType::Nssa => 7,
        }
    }
}

/// The 20-byte LSA header (§A.4.1), common to every LSA. Together with the
/// originator (`advertising_router`), `ls_type` and `link_state_id` form an
/// LSA's identity; `ls_seq`/`ls_checksum`/`ls_age` distinguish its instances.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct LsaHeader {
    /// Time in seconds since the LSA was originated, capped at [`MAX_AGE`].
    pub ls_age: u16,
    /// The LSA's optional capabilities (the [`crate`] `OPT_*` bits).
    pub options: u8,
    /// What this LSA describes.
    pub ls_type: LsType,
    /// The LSA's identifier within its type — meaning depends on the type
    /// (a router id, a DR interface address, a network number, …).
    pub link_state_id: Ipv4Addr,
    /// The router id of the LSA's originator.
    pub advertising_router: Ipv4Addr,
    /// The instance's sequence number — *signed*, increasing (§12.1.6).
    pub ls_seq: i32,
    /// The Fletcher checksum over the LSA from the Options field onward.
    pub ls_checksum: u16,
    /// The full LSA length in bytes, header included.
    pub length: u16,
}

/// The serialized size of an LSA header.
pub const LSA_HEADER_LEN: usize = 20;

/// Offset of the LS checksum field within the *checksummed region* (the LSA
/// from the Options field onward): the checksum sits 16 bytes into the LSA, of
/// which the first 2 (the LS age) are excluded — see [`fletcher16`].
pub(crate) const LSA_CSUM_OFFSET: usize = 14;

impl LsaHeader {
    /// The identity triple `(type, link-state-id, advertising-router)` that
    /// names this LSA across all of its instances (§12.1).
    pub fn key(&self) -> (LsType, Ipv4Addr, Ipv4Addr) {
        (self.ls_type, self.link_state_id, self.advertising_router)
    }

    /// Compare two instances of *the same* LSA and decide which is more recent
    /// (RFC 2328 §13.1). [`Ordering::Greater`] means `self` is newer,
    /// [`Ordering::Less`] means `other` is, [`Ordering::Equal`] means the two
    /// are to be treated as the same instance. Callers must already have
    /// matched [`LsaHeader::key`]; this only weighs the instance fields.
    pub fn compare_recency(&self, other: &LsaHeader) -> Ordering {
        // 1. Higher (signed) sequence number wins.
        match self.ls_seq.cmp(&other.ls_seq) {
            Ordering::Equal => {}
            ord => return ord,
        }
        // 2. Higher checksum (unsigned) wins.
        match self.ls_checksum.cmp(&other.ls_checksum) {
            Ordering::Equal => {}
            ord => return ord,
        }
        // 3. MaxAge wins over any non-MaxAge instance.
        let self_max = self.ls_age >= MAX_AGE;
        let other_max = other.ls_age >= MAX_AGE;
        match (self_max, other_max) {
            (true, false) => return Ordering::Greater,
            (false, true) => return Ordering::Less,
            _ => {}
        }
        // 4. Ages differing by more than MaxAgeDiff: the *younger* wins.
        let diff = self.ls_age.abs_diff(other.ls_age);
        if diff > MAX_AGE_DIFF {
            return other.ls_age.cmp(&self.ls_age);
        }
        // 5. Otherwise the same instance.
        Ordering::Equal
    }

    /// Serialize the 20-byte header into `out`.
    pub fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.ls_age.to_be_bytes());
        out.push(self.options);
        out.push(self.ls_type.as_u8());
        out.extend_from_slice(&self.link_state_id.octets());
        out.extend_from_slice(&self.advertising_router.octets());
        out.extend_from_slice(&self.ls_seq.to_be_bytes());
        out.extend_from_slice(&self.ls_checksum.to_be_bytes());
        out.extend_from_slice(&self.length.to_be_bytes());
    }

    /// Parse a 20-byte header from the front of `buf`.
    pub fn decode(buf: &[u8]) -> Option<LsaHeader> {
        if buf.len() < LSA_HEADER_LEN {
            return None;
        }
        Some(LsaHeader {
            ls_age: u16::from_be_bytes([buf[0], buf[1]]),
            options: buf[2],
            ls_type: LsType::from_u8(buf[3])?,
            link_state_id: Ipv4Addr::new(buf[4], buf[5], buf[6], buf[7]),
            advertising_router: Ipv4Addr::new(buf[8], buf[9], buf[10], buf[11]),
            ls_seq: i32::from_be_bytes([buf[12], buf[13], buf[14], buf[15]]),
            ls_checksum: u16::from_be_bytes([buf[16], buf[17]]),
            length: u16::from_be_bytes([buf[18], buf[19]]),
        })
    }
}

/// Compute and write the Fletcher LS checksum into a fully-built LSA byte buffer
/// (header + body, with `length` and `ls_seq` already set, `ls_age` arbitrary).
/// Returns the checksum. The checksum is taken from the Options field onward, so
/// the first two bytes (the age) are skipped — meaning the age can later change
/// without invalidating the checksum, exactly as the protocol requires.
pub fn stamp_checksum(lsa: &mut [u8]) -> u16 {
    debug_assert!(lsa.len() >= LSA_HEADER_LEN);
    fletcher16(&mut lsa[2..], LSA_CSUM_OFFSET)
}

/// Verify the Fletcher LS checksum embedded in a full LSA byte buffer.
pub fn checksum_valid(lsa: &[u8]) -> bool {
    lsa.len() >= LSA_HEADER_LEN && fletcher16_valid(&lsa[2..])
}

// ===========================================================================
// LSA bodies (§A.4.2 – §A.4.5)
// ===========================================================================
//
// TOS-specific metrics (the optional extra entries each body may carry) are
// historical: RFC 2328 deprecated type-of-service routing. We therefore decode
// and *skip* any TOS entries present and always originate with TOS 0 only —
// exactly what every modern OSPF speaker does.

/// `B`-bit of a Router-LSA: the originator is an area border router.
pub const RTR_FLAG_B: u8 = 0x01;
/// `E`-bit of a Router-LSA: the originator is an AS boundary router.
pub const RTR_FLAG_E: u8 = 0x02;
/// `V`-bit of a Router-LSA: the originator is a virtual-link endpoint.
pub const RTR_FLAG_V: u8 = 0x04;

/// The kind of a link within a Router-LSA (§A.4.2, the link Type field). The
/// meaning of a link's *Link ID* and *Link Data* depends on this.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RouterLinkType {
    /// Type 1 — point-to-point to another router. Link ID = neighbour Router ID,
    /// Link Data = this router's interface address (or `0.0.0.x` ifindex).
    PointToPoint,
    /// Type 2 — connection to a transit network. Link ID = the DR's interface
    /// address, Link Data = this router's interface address.
    Transit,
    /// Type 3 — connection to a stub network. Link ID = the IP network number,
    /// Link Data = the network mask.
    Stub,
    /// Type 4 — a virtual link. Link ID = neighbour Router ID, Link Data = the
    /// interface address.
    Virtual,
}

impl RouterLinkType {
    fn from_u8(v: u8) -> Option<Self> {
        Some(match v {
            1 => RouterLinkType::PointToPoint,
            2 => RouterLinkType::Transit,
            3 => RouterLinkType::Stub,
            4 => RouterLinkType::Virtual,
            _ => return None,
        })
    }

    fn as_u8(self) -> u8 {
        match self {
            RouterLinkType::PointToPoint => 1,
            RouterLinkType::Transit => 2,
            RouterLinkType::Stub => 3,
            RouterLinkType::Virtual => 4,
        }
    }
}

/// One link (description of a single attachment) within a Router-LSA.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct RouterLink {
    /// Identifies the object this link connects to (meaning per `link_type`).
    pub link_id: Ipv4Addr,
    /// Further data about the link (meaning per `link_type`).
    pub link_data: Ipv4Addr,
    /// What this link attaches to.
    pub link_type: RouterLinkType,
    /// The cost of using this link (TOS 0 metric).
    pub metric: u16,
}

/// A Router-LSA body (Type 1, §A.4.2): one router's own links within an area.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct RouterLsa {
    /// The V/E/B capability bits ([`RTR_FLAG_V`] / [`RTR_FLAG_E`] / [`RTR_FLAG_B`]).
    pub flags: u8,
    /// The router's links.
    pub links: Vec<RouterLink>,
}

/// A Network-LSA body (Type 2, §A.4.3): originated by a transit network's DR,
/// listing every router attached to it (the DR included).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct NetworkLsa {
    /// The network's mask.
    pub network_mask: Ipv4Addr,
    /// The Router IDs attached to the network.
    pub attached_routers: Vec<Ipv4Addr>,
}

/// A Summary-LSA body (Type 3 or 4, §A.4.4): an inter-area route, originated by
/// an ABR. Type 3 describes a network (`network_mask` is its mask); type 4
/// describes an ASBR (`network_mask` is `0.0.0.0`). Which one is carried in the
/// LSA header's `ls_type`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct SummaryLsa {
    /// The destination network's mask (`0.0.0.0` for a type-4 ASBR summary).
    pub network_mask: Ipv4Addr,
    /// The cost to the destination (24-bit TOS 0 metric).
    pub metric: u32,
}

/// An AS-external-LSA body (Type 5, §A.4.5): a route to a destination outside
/// the OSPF AS, originated by an ASBR.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct AsExternalLsa {
    /// The destination network's mask.
    pub network_mask: Ipv4Addr,
    /// The `E`-bit: `false` = a type-1 external metric (comparable to internal
    /// cost), `true` = a type-2 metric (always greater than any internal cost).
    pub external_type2: bool,
    /// The external cost (24-bit metric).
    pub metric: u32,
    /// Where to forward traffic for this destination (`0.0.0.0` = via the ASBR).
    pub forwarding_address: Ipv4Addr,
    /// An opaque tag for external route management (e.g. BGP communities).
    pub route_tag: u32,
}

/// A typed LSA body, selected by the header's [`LsType`].
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum LsaBody {
    /// A Router-LSA (Type 1).
    Router(RouterLsa),
    /// A Network-LSA (Type 2).
    Network(NetworkLsa),
    /// A Summary-LSA (Type 3 or 4 — disambiguated by the header).
    Summary(SummaryLsa),
    /// An AS-external-LSA (Type 5).
    AsExternal(AsExternalLsa),
}

impl LsaBody {
    /// The LS type that must appear in the header for this body. For a summary
    /// body the header decides between type 3 and 4, so this returns type 3 as
    /// the representative; [`Lsa::encode`] preserves the header's own type.
    pub fn ls_type(&self) -> LsType {
        match self {
            LsaBody::Router(_) => LsType::Router,
            LsaBody::Network(_) => LsType::Network,
            LsaBody::Summary(_) => LsType::SummaryNetwork,
            LsaBody::AsExternal(_) => LsType::AsExternal,
        }
    }
}

/// A complete LSA: its 20-byte header and its typed body.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Lsa {
    /// The LSA header. Its `ls_type` is authoritative (it distinguishes the two
    /// summary types); `length` and `ls_checksum` are recomputed on [`encode`].
    ///
    /// [`encode`]: Lsa::encode
    pub header: LsaHeader,
    /// The typed body.
    pub body: LsaBody,
}

impl Lsa {
    /// The LSA's identity (delegates to the header).
    pub fn key(&self) -> (LsType, Ipv4Addr, Ipv4Addr) {
        self.header.key()
    }

    /// Serialize the LSA, filling in the header `length` and the Fletcher
    /// `ls_checksum` from the encoded bytes. `ls_age`, `ls_seq` and the
    /// `link_state_id`/`advertising_router` are taken from `self.header` as-is.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(LSA_HEADER_LEN + 24);
        self.header.encode(&mut out);
        match &self.body {
            LsaBody::Router(r) => encode_router(r, &mut out),
            LsaBody::Network(n) => encode_network(n, &mut out),
            LsaBody::Summary(s) => encode_summary(s, &mut out),
            LsaBody::AsExternal(e) => encode_external(e, &mut out),
        }
        let len = out.len() as u16;
        out[18..20].copy_from_slice(&len.to_be_bytes());
        stamp_checksum(&mut out);
        out
    }

    /// Parse a full LSA from the front of `buf`, using the header's `length`
    /// field to bound the body. Returns the LSA and the number of bytes it
    /// occupied (so a Link State Update can walk a packed list of them).
    pub fn decode(buf: &[u8]) -> Option<(Lsa, usize)> {
        let header = LsaHeader::decode(buf)?;
        let len = header.length as usize;
        if len < LSA_HEADER_LEN || buf.len() < len {
            return None;
        }
        let body_bytes = &buf[LSA_HEADER_LEN..len];
        let body = match header.ls_type {
            LsType::Router => LsaBody::Router(decode_router(body_bytes)?),
            LsType::Network => LsaBody::Network(decode_network(body_bytes)?),
            LsType::SummaryNetwork | LsType::SummaryAsbr => {
                LsaBody::Summary(decode_summary(body_bytes)?)
            }
            // A type-7 NSSA-external uses the very same body as a type-5 (RFC 3101).
            LsType::AsExternal | LsType::Nssa => {
                LsaBody::AsExternal(decode_external(body_bytes)?)
            }
        };
        Some((Lsa { header, body }, len))
    }
}

// --- 24-bit metric helpers (summary / external) ---------------------------

fn put_u24(out: &mut Vec<u8>, v: u32) {
    out.push((v >> 16) as u8);
    out.push((v >> 8) as u8);
    out.push(v as u8);
}

fn get_u24(b: &[u8]) -> u32 {
    ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32
}

// --- Router-LSA -----------------------------------------------------------

fn encode_router(r: &RouterLsa, out: &mut Vec<u8>) {
    out.push(0); // reserved
    out.push(r.flags);
    out.extend_from_slice(&(r.links.len() as u16).to_be_bytes());
    for l in &r.links {
        out.extend_from_slice(&l.link_id.octets());
        out.extend_from_slice(&l.link_data.octets());
        out.push(l.link_type.as_u8());
        out.push(0); // # TOS
        out.extend_from_slice(&l.metric.to_be_bytes());
    }
}

fn decode_router(b: &[u8]) -> Option<RouterLsa> {
    if b.len() < 4 {
        return None;
    }
    let flags = b[1];
    let count = u16::from_be_bytes([b[2], b[3]]) as usize;
    let mut links = Vec::with_capacity(count);
    let mut p = 4;
    for _ in 0..count {
        if b.len() < p + 12 {
            return None;
        }
        let link_id = Ipv4Addr::new(b[p], b[p + 1], b[p + 2], b[p + 3]);
        let link_data = Ipv4Addr::new(b[p + 4], b[p + 5], b[p + 6], b[p + 7]);
        let link_type = RouterLinkType::from_u8(b[p + 8])?;
        let n_tos = b[p + 9] as usize;
        let metric = u16::from_be_bytes([b[p + 10], b[p + 11]]);
        links.push(RouterLink {
            link_id,
            link_data,
            link_type,
            metric,
        });
        // Skip any TOS-specific metrics (4 bytes each).
        p += 12 + n_tos * 4;
        if b.len() < p {
            return None;
        }
    }
    Some(RouterLsa { flags, links })
}

// --- Network-LSA ----------------------------------------------------------

fn encode_network(n: &NetworkLsa, out: &mut Vec<u8>) {
    out.extend_from_slice(&n.network_mask.octets());
    for r in &n.attached_routers {
        out.extend_from_slice(&r.octets());
    }
}

fn decode_network(b: &[u8]) -> Option<NetworkLsa> {
    if b.len() < 4 || (b.len() - 4) % 4 != 0 {
        return None;
    }
    let network_mask = Ipv4Addr::new(b[0], b[1], b[2], b[3]);
    let attached_routers = b[4..]
        .chunks_exact(4)
        .map(|c| Ipv4Addr::new(c[0], c[1], c[2], c[3]))
        .collect();
    Some(NetworkLsa {
        network_mask,
        attached_routers,
    })
}

// --- Summary-LSA ----------------------------------------------------------

fn encode_summary(s: &SummaryLsa, out: &mut Vec<u8>) {
    out.extend_from_slice(&s.network_mask.octets());
    out.push(0); // reserved
    put_u24(out, s.metric);
}

fn decode_summary(b: &[u8]) -> Option<SummaryLsa> {
    if b.len() < 8 {
        return None;
    }
    Some(SummaryLsa {
        network_mask: Ipv4Addr::new(b[0], b[1], b[2], b[3]),
        metric: get_u24(&b[5..8]),
    })
}

// --- AS-external-LSA ------------------------------------------------------

fn encode_external(e: &AsExternalLsa, out: &mut Vec<u8>) {
    out.extend_from_slice(&e.network_mask.octets());
    out.push(if e.external_type2 { 0x80 } else { 0 });
    put_u24(out, e.metric);
    out.extend_from_slice(&e.forwarding_address.octets());
    out.extend_from_slice(&e.route_tag.to_be_bytes());
}

fn decode_external(b: &[u8]) -> Option<AsExternalLsa> {
    if b.len() < 16 {
        return None;
    }
    Some(AsExternalLsa {
        network_mask: Ipv4Addr::new(b[0], b[1], b[2], b[3]),
        external_type2: b[4] & 0x80 != 0,
        metric: get_u24(&b[5..8]),
        forwarding_address: Ipv4Addr::new(b[8], b[9], b[10], b[11]),
        route_tag: u32::from_be_bytes([b[12], b[13], b[14], b[15]]),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::INITIAL_SEQUENCE_NUMBER;

    fn hdr(seq: i32, csum: u16, age: u16) -> LsaHeader {
        LsaHeader {
            ls_age: age,
            options: crate::OPT_E,
            ls_type: LsType::Router,
            link_state_id: Ipv4Addr::new(10, 0, 0, 1),
            advertising_router: Ipv4Addr::new(10, 0, 0, 1),
            ls_seq: seq,
            ls_checksum: csum,
            length: 36,
        }
    }

    #[test]
    fn ls_type_roundtrips() {
        for t in [
            LsType::Router,
            LsType::Network,
            LsType::SummaryNetwork,
            LsType::SummaryAsbr,
            LsType::AsExternal,
        ] {
            assert_eq!(LsType::from_u8(t.as_u8()), Some(t));
        }
        assert_eq!(LsType::from_u8(0), None);
        assert_eq!(LsType::from_u8(11), None);
    }

    #[test]
    fn header_roundtrips() {
        let h = hdr(INITIAL_SEQUENCE_NUMBER, 0xabcd, 1);
        let mut buf = Vec::new();
        h.encode(&mut buf);
        assert_eq!(buf.len(), LSA_HEADER_LEN);
        assert_eq!(LsaHeader::decode(&buf), Some(h));
        assert_eq!(LsaHeader::decode(&buf[..19]), None);
    }

    #[test]
    fn recency_prefers_higher_sequence() {
        let a = hdr(5, 0x1000, 1);
        let b = hdr(4, 0xffff, 1);
        assert_eq!(a.compare_recency(&b), Ordering::Greater);
        assert_eq!(b.compare_recency(&a), Ordering::Less);
    }

    #[test]
    fn recency_initial_sequence_is_oldest() {
        // The signed wrap matters: INITIAL (0x80000001) must read as *less*
        // than the next value, not as a huge unsigned number.
        let first = hdr(INITIAL_SEQUENCE_NUMBER, 0x1, 1);
        let second = hdr(INITIAL_SEQUENCE_NUMBER + 1, 0x1, 1);
        assert_eq!(second.compare_recency(&first), Ordering::Greater);
    }

    #[test]
    fn recency_then_checksum_then_age() {
        // Equal seq -> higher checksum wins.
        assert_eq!(hdr(7, 0x20, 1).compare_recency(&hdr(7, 0x10, 1)), Ordering::Greater);
        // Equal seq+checksum -> MaxAge wins.
        assert_eq!(
            hdr(7, 0x10, MAX_AGE).compare_recency(&hdr(7, 0x10, 1)),
            Ordering::Greater
        );
        // Equal seq+checksum, big age gap -> younger wins.
        assert_eq!(
            hdr(7, 0x10, 100).compare_recency(&hdr(7, 0x10, 100 + MAX_AGE_DIFF + 1)),
            Ordering::Greater
        );
        // Small age gap -> same instance.
        assert_eq!(hdr(7, 0x10, 100).compare_recency(&hdr(7, 0x10, 120)), Ordering::Equal);
    }

    #[test]
    fn full_lsa_checksum_stamps_and_validates() {
        // Build a fake 24-byte LSA: 20-byte header + 4 bytes of body.
        let h = hdr(INITIAL_SEQUENCE_NUMBER, 0, 9);
        let mut lsa = Vec::new();
        h.encode(&mut lsa);
        lsa.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
        let c = stamp_checksum(&mut lsa);
        assert_ne!(c, 0);
        assert!(checksum_valid(&lsa));
        // The decoded header reflects the stamped checksum.
        assert_eq!(LsaHeader::decode(&lsa).unwrap().ls_checksum, c);
        // Age changes must NOT break the checksum (it skips the age field).
        lsa[0] = 0x0f;
        lsa[1] = 0xff;
        assert!(checksum_valid(&lsa));
        // A body change must break it.
        lsa[20] ^= 0xff;
        assert!(!checksum_valid(&lsa));
    }

    fn lsa(ls_type: LsType, lsid: [u8; 4], body: LsaBody) -> Lsa {
        Lsa {
            header: LsaHeader {
                ls_age: 1,
                options: crate::OPT_E,
                ls_type,
                link_state_id: Ipv4Addr::from(lsid),
                advertising_router: Ipv4Addr::new(10, 0, 0, 1),
                ls_seq: INITIAL_SEQUENCE_NUMBER,
                ls_checksum: 0,
                length: 0,
            },
            body,
        }
    }

    fn assert_lsa_roundtrips(l: &Lsa) {
        let bytes = l.encode();
        // Encode must fix up length and a valid checksum.
        assert_eq!(bytes.len() as u16, u16::from_be_bytes([bytes[18], bytes[19]]));
        assert!(checksum_valid(&bytes));
        let (decoded, consumed) = Lsa::decode(&bytes).expect("decodes");
        assert_eq!(consumed, bytes.len());
        // The header length/checksum are recomputed, so compare the rest + body.
        assert_eq!(decoded.body, l.body);
        assert_eq!(decoded.header.key(), l.header.key());
        assert_eq!(decoded.header.ls_seq, l.header.ls_seq);
    }

    #[test]
    fn router_lsa_roundtrips() {
        let l = lsa(
            LsType::Router,
            [10, 0, 0, 1],
            LsaBody::Router(RouterLsa {
                flags: RTR_FLAG_B | RTR_FLAG_E,
                links: vec![
                    RouterLink {
                        link_id: Ipv4Addr::new(10, 0, 0, 2),
                        link_data: Ipv4Addr::new(192, 168, 1, 1),
                        link_type: RouterLinkType::PointToPoint,
                        metric: 10,
                    },
                    RouterLink {
                        link_id: Ipv4Addr::new(10, 1, 0, 0),
                        link_data: Ipv4Addr::new(255, 255, 0, 0),
                        link_type: RouterLinkType::Stub,
                        metric: 1,
                    },
                ],
            }),
        );
        assert_lsa_roundtrips(&l);
    }

    #[test]
    fn router_lsa_skips_tos_metrics() {
        // Hand-build a Router-LSA whose single link carries one TOS entry; the
        // decoder must skip it and still land on the right byte boundary.
        let mut body = vec![0u8, RTR_FLAG_V, 0, 1]; // reserved, flags, #links=1
        body.extend_from_slice(&Ipv4Addr::new(10, 0, 0, 9).octets()); // link id
        body.extend_from_slice(&Ipv4Addr::new(10, 0, 0, 5).octets()); // link data
        body.push(RouterLinkType::Transit.as_u8());
        body.push(1); // # TOS = 1
        body.extend_from_slice(&7u16.to_be_bytes()); // metric
        body.extend_from_slice(&[2, 0, 0, 33]); // one TOS entry (skipped)
        let r = decode_router(&body).expect("decodes with a TOS entry");
        assert_eq!(r.links.len(), 1);
        assert_eq!(r.links[0].metric, 7);
        assert_eq!(r.links[0].link_type, RouterLinkType::Transit);
    }

    #[test]
    fn network_lsa_roundtrips() {
        let l = lsa(
            LsType::Network,
            [192, 168, 1, 1],
            LsaBody::Network(NetworkLsa {
                network_mask: Ipv4Addr::new(255, 255, 255, 0),
                attached_routers: vec![Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(10, 0, 0, 2)],
            }),
        );
        assert_lsa_roundtrips(&l);
    }

    #[test]
    fn summary_lsa_roundtrips_with_24bit_metric() {
        let l = lsa(
            LsType::SummaryNetwork,
            [10, 2, 0, 0],
            LsaBody::Summary(SummaryLsa {
                network_mask: Ipv4Addr::new(255, 255, 0, 0),
                metric: 0x00ab_cdef & crate::LS_INFINITY, // 24-bit
            }),
        );
        assert_lsa_roundtrips(&l);
        if let LsaBody::Summary(s) = &Lsa::decode(&l.encode()).unwrap().0.body {
            assert_eq!(s.metric, 0x00ab_cdef & crate::LS_INFINITY);
        } else {
            panic!("expected summary");
        }
    }

    #[test]
    fn as_external_lsa_roundtrips() {
        let l = lsa(
            LsType::AsExternal,
            [0, 0, 0, 0],
            LsaBody::AsExternal(AsExternalLsa {
                network_mask: Ipv4Addr::new(255, 255, 255, 0),
                external_type2: true,
                metric: 20,
                forwarding_address: Ipv4Addr::new(192, 168, 1, 254),
                route_tag: 0xdead_beef,
            }),
        );
        assert_lsa_roundtrips(&l);
    }

    #[test]
    fn nssa_type7_lsa_roundtrips_with_the_external_body() {
        // A type-7 NSSA-external carries the same body as a type-5, but its header
        // LS type is 7 — the decoder must preserve that (RFC 3101).
        let l = lsa(
            LsType::Nssa,
            [10, 99, 0, 0],
            LsaBody::AsExternal(AsExternalLsa {
                network_mask: Ipv4Addr::new(255, 255, 255, 0),
                external_type2: true,
                metric: 20,
                forwarding_address: Ipv4Addr::UNSPECIFIED,
                route_tag: 0,
            }),
        );
        assert_lsa_roundtrips(&l);
        let (decoded, _) = Lsa::decode(&l.encode()).unwrap();
        assert_eq!(decoded.header.ls_type, LsType::Nssa);
        assert_eq!(decoded.header.ls_type.as_u8(), 7);
        assert!(matches!(decoded.body, LsaBody::AsExternal(_)));
    }
}
