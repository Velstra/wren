//! Link-State Advertisements for OSPFv3 (RFC 5340 §A.4): the 20-byte LSA header
//! (§A.4.2) with its scoped 16-bit LS Type, the compact IPv6 address-prefix
//! encoding (§A.4.1), the seven LSA bodies (§A.4.3–§A.4.9), the Fletcher LS
//! checksum (§4.4.3) and the §13.1 "which instance is more recent" comparison.
//!
//! The big shape change from OSPFv2 is that **topology and addressing are
//! separated**. Router- and Network-LSAs describe the graph using interface IDs
//! and router IDs only; the IPv6 prefixes that hang off the graph travel in
//! Link-LSAs (per link) and Intra-Area-Prefix-LSAs (per area). The LSA header
//! also loses its Options byte — Options move into the Router/Network/Link bodies.

use std::cmp::Ordering;
use std::net::{Ipv4Addr, Ipv6Addr};

use crate::{fletcher16, fletcher16_valid, MAX_AGE, MAX_AGE_DIFF};

// ===========================================================================
// LS Type — a scoped 16-bit field (§A.4.2.1)
// ===========================================================================

/// The flooding scope of an LSA, taken from the two scope bits (S2,S1) of the
/// LS Type (§3.3 / §A.4.2.1).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash, PartialOrd, Ord)]
pub enum Scope {
    /// `00` — flooded only on the originating link (e.g. Link-LSAs).
    LinkLocal,
    /// `01` — flooded throughout a single area (most LSAs).
    Area,
    /// `10` — flooded throughout the AS (AS-external LSAs).
    As,
    /// `11` — reserved.
    Reserved,
}

/// The kind of a link-state advertisement (§A.4.2.1, the 16-bit LS Type field).
/// The top three bits are the U (handle-if-unknown) flag and the two scope bits;
/// the low 13 bits are the function code. Unknown function codes are preserved
/// verbatim as [`LsType::Unknown`] so they can still be flooded (the whole point
/// of the scoped type), carried with a raw [`LsaBody::Unknown`] body.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash, PartialOrd, Ord)]
pub enum LsType {
    /// `0x2001` — a router's own links within an area (interface/router IDs only).
    Router,
    /// `0x2002` — originated by the DR, lists the routers on a transit network.
    Network,
    /// `0x2003` — an inter-area route to an IPv6 prefix, originated by an ABR.
    InterAreaPrefix,
    /// `0x2004` — an inter-area route to an ASBR, originated by an ABR.
    InterAreaRouter,
    /// `0x4005` — a route external to the AS, originated by an ASBR.
    AsExternal,
    /// `0x0008` — a router's link-local address and the prefixes on one link.
    Link,
    /// `0x2009` — the IPv6 prefixes associated with a Router- or Network-LSA.
    IntraAreaPrefix,
    /// Any LS Type this implementation does not interpret. The raw 16-bit value
    /// is kept so the LSA round-trips and floods within its [`Scope`].
    Unknown(u16),
}

impl LsType {
    /// Decode the on-wire 16-bit LS Type.
    pub fn from_u16(v: u16) -> Self {
        match v {
            0x2001 => LsType::Router,
            0x2002 => LsType::Network,
            0x2003 => LsType::InterAreaPrefix,
            0x2004 => LsType::InterAreaRouter,
            0x4005 => LsType::AsExternal,
            0x0008 => LsType::Link,
            0x2009 => LsType::IntraAreaPrefix,
            other => LsType::Unknown(other),
        }
    }

    /// The on-wire 16-bit LS Type.
    pub fn as_u16(self) -> u16 {
        match self {
            LsType::Router => 0x2001,
            LsType::Network => 0x2002,
            LsType::InterAreaPrefix => 0x2003,
            LsType::InterAreaRouter => 0x2004,
            LsType::AsExternal => 0x4005,
            LsType::Link => 0x0008,
            LsType::IntraAreaPrefix => 0x2009,
            LsType::Unknown(v) => v,
        }
    }

    /// The flooding scope encoded in the type's scope bits (§3.3).
    pub fn scope(self) -> Scope {
        match (self.as_u16() >> 13) & 0b11 {
            0 => Scope::LinkLocal,
            1 => Scope::Area,
            2 => Scope::As,
            _ => Scope::Reserved,
        }
    }
}

// ===========================================================================
// LSA header (§A.4.2)
// ===========================================================================

/// The 20-byte OSPFv3 LSA header (§A.4.2), common to every LSA. Unlike OSPFv2 it
/// carries no Options byte (Options moved into the bodies); the Link State ID is
/// an opaque 32-bit number whose meaning depends on the type, *not* an address.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct LsaHeader {
    /// Time in seconds since the LSA was originated, capped at [`MAX_AGE`].
    pub ls_age: u16,
    /// What this LSA describes, with its flooding scope (§A.4.2.1).
    pub ls_type: LsType,
    /// The LSA's identifier within its type — an opaque number (§4.4.3), e.g. the
    /// originator's interface ID for a Link- or Network-LSA, or 0 for a Router-LSA.
    pub link_state_id: Ipv4Addr,
    /// The router id of the LSA's originator.
    pub advertising_router: Ipv4Addr,
    /// The instance's sequence number — *signed*, increasing (§12.1.6 of RFC 2328).
    pub ls_seq: i32,
    /// The Fletcher checksum over the LSA from the LS Type field onward.
    pub ls_checksum: u16,
    /// The full LSA length in bytes, header included.
    pub length: u16,
}

/// The serialized size of an LSA header.
pub const LSA_HEADER_LEN: usize = 20;

/// Offset of the LS checksum field within the *checksummed region* (the LSA from
/// the LS Type field onward): the checksum sits 16 bytes into the LSA, of which
/// the first 2 (the LS age) are excluded — see [`fletcher16`].
pub(crate) const LSA_CSUM_OFFSET: usize = 14;

impl LsaHeader {
    /// The identity triple `(type, link-state-id, advertising-router)` that names
    /// this LSA across all of its instances.
    pub fn key(&self) -> (LsType, Ipv4Addr, Ipv4Addr) {
        (self.ls_type, self.link_state_id, self.advertising_router)
    }

    /// Compare two instances of *the same* LSA and decide which is more recent
    /// (RFC 2328 §13.1, unchanged in OSPFv3). [`Ordering::Greater`] means `self`
    /// is newer. Callers must already have matched [`LsaHeader::key`].
    pub fn compare_recency(&self, other: &LsaHeader) -> Ordering {
        match self.ls_seq.cmp(&other.ls_seq) {
            Ordering::Equal => {}
            ord => return ord,
        }
        match self.ls_checksum.cmp(&other.ls_checksum) {
            Ordering::Equal => {}
            ord => return ord,
        }
        let self_max = self.ls_age >= MAX_AGE;
        let other_max = other.ls_age >= MAX_AGE;
        match (self_max, other_max) {
            (true, false) => return Ordering::Greater,
            (false, true) => return Ordering::Less,
            _ => {}
        }
        let diff = self.ls_age.abs_diff(other.ls_age);
        if diff > MAX_AGE_DIFF {
            return other.ls_age.cmp(&self.ls_age);
        }
        Ordering::Equal
    }

    /// Serialize the 20-byte header into `out`.
    pub fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.ls_age.to_be_bytes());
        out.extend_from_slice(&self.ls_type.as_u16().to_be_bytes());
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
            ls_type: LsType::from_u16(u16::from_be_bytes([buf[2], buf[3]])),
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
/// The checksum is taken from the LS Type field onward, so the first two bytes
/// (the age) are skipped and the age can later change without invalidating it.
pub fn stamp_checksum(lsa: &mut [u8]) -> u16 {
    debug_assert!(lsa.len() >= LSA_HEADER_LEN);
    fletcher16(&mut lsa[2..], LSA_CSUM_OFFSET)
}

/// Verify the Fletcher LS checksum embedded in a full LSA byte buffer.
pub fn checksum_valid(lsa: &[u8]) -> bool {
    lsa.len() >= LSA_HEADER_LEN && fletcher16_valid(&lsa[2..])
}

// ===========================================================================
// IPv6 address prefix (§A.4.1)
// ===========================================================================

// PrefixOptions bits (§A.4.1.1).
/// `NU`-bit — the prefix is excluded from IPv6 unicast calculations.
pub const PREFIX_NU: u8 = 0x01;
/// `LA`-bit — the prefix is an interface's own (local) address, a /128 host.
pub const PREFIX_LA: u8 = 0x02;
/// `P`-bit — propagate: an NSSA prefix to be re-advertised across the area border.
pub const PREFIX_P: u8 = 0x08;
/// `DN`-bit — set on prefixes learnt down a VPN to prevent loops (RFC 4576-style).
pub const PREFIX_DN: u8 = 0x10;

/// An OSPFv3 address prefix (§A.4.1): a prefix length and prefix-options byte,
/// then the *significant* high-order address bytes only, padded up to a 32-bit
/// boundary. A `/0` carries no address bytes; a `/64` carries 8; a `/128`, 16.
/// The two bytes between the options and the address vary by LSA (a metric, a
/// referenced LS type, or reserved) and are handled by each body, not here.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Prefix {
    /// The prefix length in bits (0–128).
    pub length: u8,
    /// The [`PREFIX_NU`]/[`PREFIX_LA`]/… option bits.
    pub options: u8,
    /// The high-order address bytes, `ceil(length/32)*4` of them.
    pub address: Vec<u8>,
}

/// The number of address bytes an OSPFv3 prefix of the given length occupies:
/// the significant bits rounded up to whole 32-bit words (§A.4.1).
pub fn prefix_addr_bytes(length: u8) -> usize {
    (length as usize).div_ceil(32) * 4
}

impl Prefix {
    /// Build a prefix from a full IPv6 address and a length, keeping only the
    /// significant 32-bit words.
    pub fn from_ipv6(addr: Ipv6Addr, length: u8, options: u8) -> Prefix {
        let n = prefix_addr_bytes(length);
        Prefix {
            length,
            options,
            address: addr.octets()[..n].to_vec(),
        }
    }

    /// The prefix's base address, zero-padded back out to a full 16 bytes.
    pub fn ipv6(&self) -> Ipv6Addr {
        let mut octets = [0u8; 16];
        let n = self.address.len().min(16);
        octets[..n].copy_from_slice(&self.address[..n]);
        Ipv6Addr::from(octets)
    }

    /// Encode the prefix, with `mid` as the 2-byte field between the options and
    /// the address (a metric, a referenced LS type, or 0 — caller's choice).
    fn encode(&self, mid: u16, out: &mut Vec<u8>) {
        out.push(self.length);
        out.push(self.options);
        out.extend_from_slice(&mid.to_be_bytes());
        out.extend_from_slice(&self.address);
    }

    /// Decode a prefix from the front of `b`. Returns the prefix, the 2-byte
    /// `mid` field and the number of bytes consumed.
    fn decode(b: &[u8]) -> Option<(Prefix, u16, usize)> {
        if b.len() < 4 {
            return None;
        }
        let length = b[0];
        let n = prefix_addr_bytes(length);
        if n > 16 || b.len() < 4 + n {
            return None;
        }
        let mid = u16::from_be_bytes([b[2], b[3]]);
        let prefix = Prefix {
            length,
            options: b[1],
            address: b[4..4 + n].to_vec(),
        };
        Some((prefix, mid, 4 + n))
    }
}

// ===========================================================================
// LSA bodies (§A.4.3 – §A.4.9)
// ===========================================================================

// Router-LSA flag bits (§A.4.3). Note these differ from OSPFv2's V/E/B layout.
/// `B`-bit — the originator is an area border router.
pub const RTR_FLAG_B: u8 = 0x01;
/// `E`-bit — the originator is an AS boundary router.
pub const RTR_FLAG_E: u8 = 0x02;
/// `V`-bit — the originator is a virtual-link endpoint.
pub const RTR_FLAG_V: u8 = 0x04;
/// `Nt`-bit — the originator is an NSSA border router that translates type-7.
pub const RTR_FLAG_NT: u8 = 0x10;

/// The kind of a link within an OSPFv3 Router-LSA (§A.4.3). Unlike OSPFv2 there
/// is no stub type — stub addressing is carried by Intra-Area-Prefix-LSAs.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RouterLinkType {
    /// Type 1 — point-to-point to another router.
    PointToPoint,
    /// Type 2 — connection to a transit network (via its DR).
    Transit,
    /// Type 4 — a virtual link.
    Virtual,
}

impl RouterLinkType {
    fn from_u8(v: u8) -> Option<Self> {
        Some(match v {
            1 => RouterLinkType::PointToPoint,
            2 => RouterLinkType::Transit,
            4 => RouterLinkType::Virtual,
            _ => return None,
        })
    }

    fn as_u8(self) -> u8 {
        match self {
            RouterLinkType::PointToPoint => 1,
            RouterLinkType::Transit => 2,
            RouterLinkType::Virtual => 4,
        }
    }
}

/// One link description within a Router-LSA (§A.4.3): topology only — interface
/// IDs and the neighbour's router ID, no addresses.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct RouterLink {
    /// What this link attaches to.
    pub link_type: RouterLinkType,
    /// The cost of using this link.
    pub metric: u16,
    /// This router's Interface ID for the link.
    pub interface_id: u32,
    /// The neighbour's Interface ID (for a transit link, the DR's).
    pub neighbor_interface_id: u32,
    /// The neighbour's Router ID (for a transit link, the DR's).
    pub neighbor_router_id: Ipv4Addr,
}

/// A Router-LSA body (function 1, §A.4.3): one router's own links within an area.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct RouterLsa {
    /// The W/V/E/B/Nt capability bits ([`RTR_FLAG_B`] etc.).
    pub flags: u8,
    /// The router's Options (24-bit, the [`crate`] `OPT_*` bits).
    pub options: u32,
    /// The router's links.
    pub links: Vec<RouterLink>,
}

/// A Network-LSA body (function 2, §A.4.4): originated by a transit network's DR,
/// listing every router attached to it (the DR included). No address — the prefix
/// is in the DR's Intra-Area-Prefix-LSA.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct NetworkLsa {
    /// The network's Options (24-bit), the OR of the attached routers' options.
    pub options: u32,
    /// The Router IDs attached to the network.
    pub attached_routers: Vec<Ipv4Addr>,
}

/// An Inter-Area-Prefix-LSA body (function 3, §A.4.5): the OSPFv3 equivalent of a
/// type-3 summary — an inter-area route to an IPv6 prefix, originated by an ABR.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct InterAreaPrefixLsa {
    /// The cost to the destination (24-bit metric).
    pub metric: u32,
    /// The destination IPv6 prefix.
    pub prefix: Prefix,
}

/// An Inter-Area-Router-LSA body (function 4, §A.4.6): the OSPFv3 equivalent of a
/// type-4 summary — an inter-area route to an ASBR, originated by an ABR.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct InterAreaRouterLsa {
    /// The destination router's Options (24-bit).
    pub options: u32,
    /// The cost to the destination ASBR (24-bit metric).
    pub metric: u32,
    /// The Router ID of the ASBR being described.
    pub destination_router_id: Ipv4Addr,
}

/// An AS-External-LSA body (function 5, §A.4.7): a route to a destination outside
/// the OSPF AS, originated by an ASBR. The forwarding address, route tag and
/// referenced LSA are optional, signalled by the F/T/non-zero-type flags.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct AsExternalLsa {
    /// The `E`-bit: `false` = a type-1 external metric (comparable to internal
    /// cost), `true` = a type-2 metric (always greater than any internal cost).
    pub external_type2: bool,
    /// The external cost (24-bit metric).
    pub metric: u32,
    /// The destination IPv6 prefix.
    pub prefix: Prefix,
    /// Where to forward traffic, if an explicit address is given (the `F`-bit).
    pub forwarding_address: Option<Ipv6Addr>,
    /// An opaque tag for external route management, if present (the `T`-bit).
    pub route_tag: Option<u32>,
    /// The LS Type referenced for additional information (0 = none).
    pub referenced_ls_type: u16,
    /// The referenced LSA's Link State ID, present iff `referenced_ls_type != 0`.
    pub referenced_link_state_id: Option<Ipv4Addr>,
}

// AS-External flag bits (§A.4.7), in the first body byte.
const EXT_FLAG_E: u8 = 0x04;
const EXT_FLAG_F: u8 = 0x02;
const EXT_FLAG_T: u8 = 0x01;

/// A Link-LSA body (function 8, link-local scope, §A.4.8): a router tells the
/// other routers on one link its link-local address (for next hops) and the IPv6
/// prefixes configured on that link.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct LinkLsa {
    /// The originator's Router Priority on this link (for DR election).
    pub router_priority: u8,
    /// The originator's Options (24-bit) for this link.
    pub options: u32,
    /// The originator's link-local address on this link (the next hop others use).
    pub link_local_address: Ipv6Addr,
    /// The IPv6 prefixes configured on this link.
    pub prefixes: Vec<Prefix>,
}

/// One prefix entry of an Intra-Area-Prefix-LSA: a prefix and its metric.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct IntraPrefix {
    /// The cost of the prefix from the referenced LSA's router/network.
    pub metric: u16,
    /// The IPv6 prefix.
    pub prefix: Prefix,
}

/// An Intra-Area-Prefix-LSA body (function 9, §A.4.9): the IPv6 prefixes that
/// belong to a Router-LSA (the router's own stub/loopback prefixes) or a
/// Network-LSA (a transit link's prefix), kept out of the topology LSAs.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct IntraAreaPrefixLsa {
    /// The LS Type of the referenced LSA (Router `0x2001` or Network `0x2002`).
    pub referenced_ls_type: u16,
    /// The referenced LSA's Link State ID (0 for a Router-LSA).
    pub referenced_link_state_id: Ipv4Addr,
    /// The referenced LSA's Advertising Router.
    pub referenced_advertising_router: Ipv4Addr,
    /// The prefixes, each with its metric.
    pub prefixes: Vec<IntraPrefix>,
}

/// A typed LSA body, selected by the header's [`LsType`].
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum LsaBody {
    /// A Router-LSA (function 1).
    Router(RouterLsa),
    /// A Network-LSA (function 2).
    Network(NetworkLsa),
    /// An Inter-Area-Prefix-LSA (function 3).
    InterAreaPrefix(InterAreaPrefixLsa),
    /// An Inter-Area-Router-LSA (function 4).
    InterAreaRouter(InterAreaRouterLsa),
    /// An AS-External-LSA (function 5).
    AsExternal(AsExternalLsa),
    /// A Link-LSA (function 8).
    Link(LinkLsa),
    /// An Intra-Area-Prefix-LSA (function 9).
    IntraAreaPrefix(IntraAreaPrefixLsa),
    /// An LSA whose function code this implementation does not interpret; its
    /// body bytes are preserved verbatim so it still floods within its scope.
    Unknown(Vec<u8>),
}

impl LsaBody {
    /// The LS type that must appear in the header for this body. For an
    /// [`LsaBody::Unknown`] this is unknowable, so [`Lsa::encode`] takes the type
    /// from the header; this returns a placeholder there.
    pub fn ls_type(&self) -> LsType {
        match self {
            LsaBody::Router(_) => LsType::Router,
            LsaBody::Network(_) => LsType::Network,
            LsaBody::InterAreaPrefix(_) => LsType::InterAreaPrefix,
            LsaBody::InterAreaRouter(_) => LsType::InterAreaRouter,
            LsaBody::AsExternal(_) => LsType::AsExternal,
            LsaBody::Link(_) => LsType::Link,
            LsaBody::IntraAreaPrefix(_) => LsType::IntraAreaPrefix,
            LsaBody::Unknown(_) => LsType::Unknown(0),
        }
    }
}

/// A complete LSA: its 20-byte header and its typed body.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Lsa {
    /// The LSA header. Its `ls_type` is authoritative; `length` and `ls_checksum`
    /// are recomputed on [`Lsa::encode`].
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
    /// `ls_checksum` from the encoded bytes.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(LSA_HEADER_LEN + 24);
        self.header.encode(&mut out);
        match &self.body {
            LsaBody::Router(r) => encode_router(r, &mut out),
            LsaBody::Network(n) => encode_network(n, &mut out),
            LsaBody::InterAreaPrefix(p) => encode_inter_area_prefix(p, &mut out),
            LsaBody::InterAreaRouter(r) => encode_inter_area_router(r, &mut out),
            LsaBody::AsExternal(e) => encode_as_external(e, &mut out),
            LsaBody::Link(l) => encode_link(l, &mut out),
            LsaBody::IntraAreaPrefix(p) => encode_intra_area_prefix(p, &mut out),
            LsaBody::Unknown(raw) => out.extend_from_slice(raw),
        }
        let len = out.len() as u16;
        out[18..20].copy_from_slice(&len.to_be_bytes());
        stamp_checksum(&mut out);
        out
    }

    /// Parse a full LSA from the front of `buf`, using the header's `length` field
    /// to bound the body. Returns the LSA and the number of bytes it occupied (so
    /// a Link State Update can walk a packed list of them).
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
            LsType::InterAreaPrefix => {
                LsaBody::InterAreaPrefix(decode_inter_area_prefix(body_bytes)?)
            }
            LsType::InterAreaRouter => {
                LsaBody::InterAreaRouter(decode_inter_area_router(body_bytes)?)
            }
            LsType::AsExternal => LsaBody::AsExternal(decode_as_external(body_bytes)?),
            LsType::Link => LsaBody::Link(decode_link(body_bytes)?),
            LsType::IntraAreaPrefix => {
                LsaBody::IntraAreaPrefix(decode_intra_area_prefix(body_bytes)?)
            }
            LsType::Unknown(_) => LsaBody::Unknown(body_bytes.to_vec()),
        };
        Some((Lsa { header, body }, len))
    }
}

// --- 24-bit helpers --------------------------------------------------------

fn put_u24(out: &mut Vec<u8>, v: u32) {
    out.push((v >> 16) as u8);
    out.push((v >> 8) as u8);
    out.push(v as u8);
}

fn get_u24(b: &[u8]) -> u32 {
    ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32
}

// --- Router-LSA ------------------------------------------------------------

fn encode_router(r: &RouterLsa, out: &mut Vec<u8>) {
    out.push(r.flags);
    put_u24(out, r.options);
    for l in &r.links {
        out.push(l.link_type.as_u8());
        out.push(0); // reserved
        out.extend_from_slice(&l.metric.to_be_bytes());
        out.extend_from_slice(&l.interface_id.to_be_bytes());
        out.extend_from_slice(&l.neighbor_interface_id.to_be_bytes());
        out.extend_from_slice(&l.neighbor_router_id.octets());
    }
}

fn decode_router(b: &[u8]) -> Option<RouterLsa> {
    if b.len() < 4 {
        return None;
    }
    let flags = b[0];
    let options = get_u24(&b[1..4]);
    let mut links = Vec::new();
    let mut p = 4;
    while p < b.len() {
        if b.len() < p + 16 {
            return None;
        }
        links.push(RouterLink {
            link_type: RouterLinkType::from_u8(b[p])?,
            metric: u16::from_be_bytes([b[p + 2], b[p + 3]]),
            interface_id: u32::from_be_bytes([b[p + 4], b[p + 5], b[p + 6], b[p + 7]]),
            neighbor_interface_id: u32::from_be_bytes([b[p + 8], b[p + 9], b[p + 10], b[p + 11]]),
            neighbor_router_id: Ipv4Addr::new(b[p + 12], b[p + 13], b[p + 14], b[p + 15]),
        });
        p += 16;
    }
    Some(RouterLsa {
        flags,
        options,
        links,
    })
}

// --- Network-LSA -----------------------------------------------------------

fn encode_network(n: &NetworkLsa, out: &mut Vec<u8>) {
    out.push(0); // reserved
    put_u24(out, n.options);
    for r in &n.attached_routers {
        out.extend_from_slice(&r.octets());
    }
}

fn decode_network(b: &[u8]) -> Option<NetworkLsa> {
    if b.len() < 4 || (b.len() - 4) % 4 != 0 {
        return None;
    }
    let options = get_u24(&b[1..4]);
    let attached_routers = b[4..]
        .chunks_exact(4)
        .map(|c| Ipv4Addr::new(c[0], c[1], c[2], c[3]))
        .collect();
    Some(NetworkLsa {
        options,
        attached_routers,
    })
}

// --- Inter-Area-Prefix-LSA -------------------------------------------------

fn encode_inter_area_prefix(p: &InterAreaPrefixLsa, out: &mut Vec<u8>) {
    out.push(0); // reserved
    put_u24(out, p.metric);
    p.prefix.encode(0, out);
}

fn decode_inter_area_prefix(b: &[u8]) -> Option<InterAreaPrefixLsa> {
    if b.len() < 4 {
        return None;
    }
    let metric = get_u24(&b[1..4]);
    let (prefix, _mid, _used) = Prefix::decode(&b[4..])?;
    Some(InterAreaPrefixLsa { metric, prefix })
}

// --- Inter-Area-Router-LSA -------------------------------------------------

fn encode_inter_area_router(r: &InterAreaRouterLsa, out: &mut Vec<u8>) {
    out.push(0); // reserved
    put_u24(out, r.options);
    out.push(0); // reserved
    put_u24(out, r.metric);
    out.extend_from_slice(&r.destination_router_id.octets());
}

fn decode_inter_area_router(b: &[u8]) -> Option<InterAreaRouterLsa> {
    if b.len() < 12 {
        return None;
    }
    Some(InterAreaRouterLsa {
        options: get_u24(&b[1..4]),
        metric: get_u24(&b[5..8]),
        destination_router_id: Ipv4Addr::new(b[8], b[9], b[10], b[11]),
    })
}

// --- AS-External-LSA -------------------------------------------------------

fn encode_as_external(e: &AsExternalLsa, out: &mut Vec<u8>) {
    let mut flags = 0u8;
    if e.external_type2 {
        flags |= EXT_FLAG_E;
    }
    if e.forwarding_address.is_some() {
        flags |= EXT_FLAG_F;
    }
    if e.route_tag.is_some() {
        flags |= EXT_FLAG_T;
    }
    out.push(flags);
    put_u24(out, e.metric);
    e.prefix.encode(e.referenced_ls_type, out);
    if let Some(fa) = e.forwarding_address {
        out.extend_from_slice(&fa.octets());
    }
    if let Some(tag) = e.route_tag {
        out.extend_from_slice(&tag.to_be_bytes());
    }
    if e.referenced_ls_type != 0 {
        let id = e.referenced_link_state_id.unwrap_or(Ipv4Addr::UNSPECIFIED);
        out.extend_from_slice(&id.octets());
    }
}

fn decode_as_external(b: &[u8]) -> Option<AsExternalLsa> {
    if b.len() < 4 {
        return None;
    }
    let flags = b[0];
    let metric = get_u24(&b[1..4]);
    let (prefix, referenced_ls_type, used) = Prefix::decode(&b[4..])?;
    let mut p = 4 + used;
    let forwarding_address = if flags & EXT_FLAG_F != 0 {
        if b.len() < p + 16 {
            return None;
        }
        let mut o = [0u8; 16];
        o.copy_from_slice(&b[p..p + 16]);
        p += 16;
        Some(Ipv6Addr::from(o))
    } else {
        None
    };
    let route_tag = if flags & EXT_FLAG_T != 0 {
        if b.len() < p + 4 {
            return None;
        }
        let t = u32::from_be_bytes([b[p], b[p + 1], b[p + 2], b[p + 3]]);
        p += 4;
        Some(t)
    } else {
        None
    };
    let referenced_link_state_id = if referenced_ls_type != 0 {
        if b.len() < p + 4 {
            return None;
        }
        Some(Ipv4Addr::new(b[p], b[p + 1], b[p + 2], b[p + 3]))
    } else {
        None
    };
    Some(AsExternalLsa {
        external_type2: flags & EXT_FLAG_E != 0,
        metric,
        prefix,
        forwarding_address,
        route_tag,
        referenced_ls_type,
        referenced_link_state_id,
    })
}

// --- Link-LSA --------------------------------------------------------------

fn encode_link(l: &LinkLsa, out: &mut Vec<u8>) {
    out.push(l.router_priority);
    put_u24(out, l.options);
    out.extend_from_slice(&l.link_local_address.octets());
    out.extend_from_slice(&(l.prefixes.len() as u32).to_be_bytes());
    for prefix in &l.prefixes {
        prefix.encode(0, out);
    }
}

fn decode_link(b: &[u8]) -> Option<LinkLsa> {
    if b.len() < 24 {
        return None;
    }
    let router_priority = b[0];
    let options = get_u24(&b[1..4]);
    let mut lla = [0u8; 16];
    lla.copy_from_slice(&b[4..20]);
    let count = u32::from_be_bytes([b[20], b[21], b[22], b[23]]) as usize;
    let mut prefixes = Vec::with_capacity(count);
    let mut p = 24;
    for _ in 0..count {
        let (prefix, _mid, used) = Prefix::decode(&b[p..])?;
        prefixes.push(prefix);
        p += used;
    }
    Some(LinkLsa {
        router_priority,
        options,
        link_local_address: Ipv6Addr::from(lla),
        prefixes,
    })
}

// --- Intra-Area-Prefix-LSA -------------------------------------------------

fn encode_intra_area_prefix(p: &IntraAreaPrefixLsa, out: &mut Vec<u8>) {
    out.extend_from_slice(&(p.prefixes.len() as u16).to_be_bytes());
    out.extend_from_slice(&p.referenced_ls_type.to_be_bytes());
    out.extend_from_slice(&p.referenced_link_state_id.octets());
    out.extend_from_slice(&p.referenced_advertising_router.octets());
    for entry in &p.prefixes {
        entry.prefix.encode(entry.metric, out);
    }
}

fn decode_intra_area_prefix(b: &[u8]) -> Option<IntraAreaPrefixLsa> {
    if b.len() < 12 {
        return None;
    }
    let count = u16::from_be_bytes([b[0], b[1]]) as usize;
    let referenced_ls_type = u16::from_be_bytes([b[2], b[3]]);
    let referenced_link_state_id = Ipv4Addr::new(b[4], b[5], b[6], b[7]);
    let referenced_advertising_router = Ipv4Addr::new(b[8], b[9], b[10], b[11]);
    let mut prefixes = Vec::with_capacity(count);
    let mut p = 12;
    for _ in 0..count {
        let (prefix, metric, used) = Prefix::decode(&b[p..])?;
        prefixes.push(IntraPrefix { metric, prefix });
        p += used;
    }
    Some(IntraAreaPrefixLsa {
        referenced_ls_type,
        referenced_link_state_id,
        referenced_advertising_router,
        prefixes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{INITIAL_SEQUENCE_NUMBER, OPT_E, OPT_R, OPT_V6};

    fn hdr(ls_type: LsType, lsid: [u8; 4]) -> LsaHeader {
        LsaHeader {
            ls_age: 1,
            ls_type,
            link_state_id: Ipv4Addr::from(lsid),
            advertising_router: Ipv4Addr::new(10, 0, 0, 1),
            ls_seq: INITIAL_SEQUENCE_NUMBER,
            ls_checksum: 0,
            length: 0,
        }
    }

    fn lsa(ls_type: LsType, lsid: [u8; 4], body: LsaBody) -> Lsa {
        Lsa {
            header: hdr(ls_type, lsid),
            body,
        }
    }

    fn assert_lsa_roundtrips(l: &Lsa) {
        let bytes = l.encode();
        assert_eq!(bytes.len() as u16, u16::from_be_bytes([bytes[18], bytes[19]]));
        assert!(checksum_valid(&bytes));
        let (decoded, consumed) = Lsa::decode(&bytes).expect("decodes");
        assert_eq!(consumed, bytes.len());
        assert_eq!(decoded.body, l.body);
        assert_eq!(decoded.header.key(), l.header.key());
        assert_eq!(decoded.header.ls_seq, l.header.ls_seq);
    }

    #[test]
    fn ls_type_roundtrips_and_scopes() {
        for (t, scope) in [
            (LsType::Router, Scope::Area),
            (LsType::Network, Scope::Area),
            (LsType::InterAreaPrefix, Scope::Area),
            (LsType::InterAreaRouter, Scope::Area),
            (LsType::AsExternal, Scope::As),
            (LsType::Link, Scope::LinkLocal),
            (LsType::IntraAreaPrefix, Scope::Area),
        ] {
            assert_eq!(LsType::from_u16(t.as_u16()), t);
            assert_eq!(t.scope(), scope);
        }
        // An unrecognised function code is preserved and keeps its scope bits.
        let u = LsType::from_u16(0x600a);
        assert_eq!(u, LsType::Unknown(0x600a));
        assert_eq!(u.scope(), Scope::Reserved);
        assert_eq!(u.as_u16(), 0x600a);
    }

    #[test]
    fn header_roundtrips() {
        let h = hdr(LsType::Router, [0, 0, 0, 0]);
        let mut buf = Vec::new();
        h.encode(&mut buf);
        assert_eq!(buf.len(), LSA_HEADER_LEN);
        assert_eq!(LsaHeader::decode(&buf), Some(h));
        assert_eq!(LsaHeader::decode(&buf[..19]), None);
    }

    #[test]
    fn recency_unchanged_from_v2() {
        let a = hdr(LsType::Router, [0, 0, 0, 0]);
        let mut b = a;
        b.ls_seq = a.ls_seq + 1;
        assert_eq!(b.compare_recency(&a), Ordering::Greater);
        assert_eq!(a.compare_recency(&b), Ordering::Less);
    }

    #[test]
    fn prefix_word_packing() {
        assert_eq!(prefix_addr_bytes(0), 0);
        assert_eq!(prefix_addr_bytes(1), 4);
        assert_eq!(prefix_addr_bytes(64), 8);
        assert_eq!(prefix_addr_bytes(65), 12);
        assert_eq!(prefix_addr_bytes(128), 16);
        let p = Prefix::from_ipv6(
            Ipv6Addr::new(0x2001, 0xdb8, 0xabcd, 0, 0, 0, 0, 0),
            48,
            PREFIX_LA,
        );
        assert_eq!(p.address.len(), 8); // /48 -> 2 words
        assert_eq!(p.ipv6(), Ipv6Addr::new(0x2001, 0xdb8, 0xabcd, 0, 0, 0, 0, 0));
        // A round-trip through encode/decode with a metric mid-field.
        let mut buf = Vec::new();
        p.encode(7, &mut buf);
        let (got, mid, used) = Prefix::decode(&buf).unwrap();
        assert_eq!(used, buf.len());
        assert_eq!(mid, 7);
        assert_eq!(got, p);
    }

    #[test]
    fn router_lsa_roundtrips() {
        let l = lsa(
            LsType::Router,
            [0, 0, 0, 0],
            LsaBody::Router(RouterLsa {
                flags: RTR_FLAG_B | RTR_FLAG_E,
                options: OPT_V6 | OPT_R | OPT_E,
                links: vec![
                    RouterLink {
                        link_type: RouterLinkType::PointToPoint,
                        metric: 10,
                        interface_id: 5,
                        neighbor_interface_id: 7,
                        neighbor_router_id: Ipv4Addr::new(10, 0, 0, 2),
                    },
                    RouterLink {
                        link_type: RouterLinkType::Transit,
                        metric: 1,
                        interface_id: 6,
                        neighbor_interface_id: 1,
                        neighbor_router_id: Ipv4Addr::new(10, 0, 0, 9),
                    },
                ],
            }),
        );
        assert_lsa_roundtrips(&l);
    }

    #[test]
    fn network_lsa_roundtrips() {
        let l = lsa(
            LsType::Network,
            [0, 0, 0, 6],
            LsaBody::Network(NetworkLsa {
                options: OPT_V6 | OPT_R | OPT_E,
                attached_routers: vec![Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(10, 0, 0, 2)],
            }),
        );
        assert_lsa_roundtrips(&l);
    }

    #[test]
    fn inter_area_prefix_lsa_roundtrips() {
        let l = lsa(
            LsType::InterAreaPrefix,
            [0, 0, 0, 1],
            LsaBody::InterAreaPrefix(InterAreaPrefixLsa {
                metric: 30,
                prefix: Prefix::from_ipv6(Ipv6Addr::new(0x2001, 0xdb8, 0xb, 0, 0, 0, 0, 0), 64, 0),
            }),
        );
        assert_lsa_roundtrips(&l);
    }

    #[test]
    fn inter_area_router_lsa_roundtrips() {
        let l = lsa(
            LsType::InterAreaRouter,
            [0, 0, 0, 2],
            LsaBody::InterAreaRouter(InterAreaRouterLsa {
                options: OPT_V6 | OPT_E,
                metric: 12,
                destination_router_id: Ipv4Addr::new(10, 9, 9, 9),
            }),
        );
        assert_lsa_roundtrips(&l);
    }

    #[test]
    fn as_external_lsa_roundtrips_minimal_and_full() {
        // Minimal: type-1 metric, no forwarding address / tag / reference.
        let minimal = lsa(
            LsType::AsExternal,
            [0, 0, 0, 1],
            LsaBody::AsExternal(AsExternalLsa {
                external_type2: false,
                metric: 20,
                prefix: Prefix::from_ipv6(Ipv6Addr::new(0x2001, 0xdb8, 0xc, 0, 0, 0, 0, 0), 48, 0),
                forwarding_address: None,
                route_tag: None,
                referenced_ls_type: 0,
                referenced_link_state_id: None,
            }),
        );
        assert_lsa_roundtrips(&minimal);

        // Full: type-2 metric with forwarding address, tag and a reference.
        let full = lsa(
            LsType::AsExternal,
            [0, 0, 0, 2],
            LsaBody::AsExternal(AsExternalLsa {
                external_type2: true,
                metric: 100,
                prefix: Prefix::from_ipv6(Ipv6Addr::new(0x2001, 0xdb8, 0xd, 0, 0, 0, 0, 0), 64, 0),
                forwarding_address: Some(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0xabcd)),
                route_tag: Some(0xdead_beef),
                referenced_ls_type: 0x2009,
                referenced_link_state_id: Some(Ipv4Addr::new(0, 0, 0, 3)),
            }),
        );
        assert_lsa_roundtrips(&full);
    }

    #[test]
    fn link_lsa_roundtrips() {
        let l = lsa(
            LsType::Link,
            [0, 0, 0, 5],
            LsaBody::Link(LinkLsa {
                router_priority: 1,
                options: OPT_V6 | OPT_R | OPT_E,
                link_local_address: Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1),
                prefixes: vec![
                    Prefix::from_ipv6(Ipv6Addr::new(0x2001, 0xdb8, 1, 0, 0, 0, 0, 0), 64, 0),
                    Prefix::from_ipv6(Ipv6Addr::new(0x2001, 0xdb8, 2, 0, 0, 0, 0, 0), 64, 0),
                ],
            }),
        );
        assert_lsa_roundtrips(&l);
    }

    #[test]
    fn intra_area_prefix_lsa_roundtrips() {
        let l = lsa(
            LsType::IntraAreaPrefix,
            [0, 0, 0, 1],
            LsaBody::IntraAreaPrefix(IntraAreaPrefixLsa {
                referenced_ls_type: LsType::Router.as_u16(),
                referenced_link_state_id: Ipv4Addr::UNSPECIFIED,
                referenced_advertising_router: Ipv4Addr::new(10, 0, 0, 1),
                prefixes: vec![
                    IntraPrefix {
                        metric: 10,
                        prefix: Prefix::from_ipv6(
                            Ipv6Addr::new(0x2001, 0xdb8, 0xa, 0, 0, 0, 0, 0),
                            64,
                            0,
                        ),
                    },
                    IntraPrefix {
                        metric: 0,
                        prefix: Prefix::from_ipv6(
                            Ipv6Addr::new(0x2001, 0xdb8, 0xa, 1, 0, 0, 0, 1),
                            128,
                            PREFIX_LA,
                        ),
                    },
                ],
            }),
        );
        assert_lsa_roundtrips(&l);
    }

    #[test]
    fn unknown_lsa_floods_verbatim() {
        // A link-local-scoped unknown type: body bytes must survive a round-trip.
        let raw = vec![0xde, 0xad, 0xbe, 0xef, 0x01, 0x02];
        let l = lsa(LsType::Unknown(0x000b), [0, 0, 0, 1], LsaBody::Unknown(raw.clone()));
        let bytes = l.encode();
        assert!(checksum_valid(&bytes));
        let (decoded, _) = Lsa::decode(&bytes).unwrap();
        assert_eq!(decoded.body, LsaBody::Unknown(raw));
        assert_eq!(decoded.header.ls_type, LsType::Unknown(0x000b));
    }

    #[test]
    fn truncated_router_link_is_rejected() {
        let l = lsa(
            LsType::Router,
            [0, 0, 0, 0],
            LsaBody::Router(RouterLsa {
                flags: 0,
                options: OPT_V6,
                links: vec![RouterLink {
                    link_type: RouterLinkType::PointToPoint,
                    metric: 1,
                    interface_id: 1,
                    neighbor_interface_id: 1,
                    neighbor_router_id: Ipv4Addr::new(10, 0, 0, 2),
                }],
            }),
        );
        let mut bytes = l.encode();
        // Lie about the length so the body is one byte short of a full link.
        let short = (bytes.len() - 1) as u16;
        bytes[18..20].copy_from_slice(&short.to_be_bytes());
        assert_eq!(Lsa::decode(&bytes[..bytes.len() - 1]), None);
    }
}
