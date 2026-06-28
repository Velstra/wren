//! # wren-isis — IS-IS (ISO/IEC 10589, with IP from RFC 1195)
//!
//! The Intermediate System to Intermediate System routing protocol: the other
//! major link-state IGP. Like the OSPF crates this is a dependency-free
//! (`std`-only) library holding the protocol's *pure* parts so they are fully
//! unit-testable with no sockets or clock; the async runner that drives it will
//! live in `wren-daemon`.
//!
//! IS-IS differs from OSPF in shape, which the wire codec has to reflect:
//!
//! * **It runs directly over the data link, not over IP.** PDUs are carried in
//!   IEEE 802.2 LLC frames (DSAP = SSAP = `0xFE`) to the multicast MAC addresses
//!   [`ALL_L1_ISS`] / [`ALL_L2_ISS`], so the runner uses an `AF_PACKET` socket
//!   rather than an IP socket. Addresses inside the protocol are OSI NSAPs: a
//!   variable-length **area address** plus a fixed 6-byte **System ID**.
//! * **Two levels.** Level 1 routes within an area, Level 2 between areas; a
//!   router can be L1, L2 or both. Each level has its own Hello, its own link-state
//!   database of **LSPs** (the IS-IS analogue of OSPF's per-router LSAs) and its own
//!   sequence-number PDUs (CSNP/PSNP) for database synchronisation.
//! * **Everything is TLVs.** A PDU is a small fixed header followed by a stream of
//!   type-length-value tuples ([`tlv`]); IP reachability, the supported protocols,
//!   interface addresses and neighbours are all TLVs, which is how the same PDUs
//!   carry both IPv4 (RFC 1195) and IPv6 (RFC 5308) with wide metrics (RFC 5305).
//!
//! What is in place so far is the **PDU/TLV wire codec** — the common header and
//! all nine PDU types ([`pdu`]) and the core TLVs ([`tlv`]), including the ISO 8473
//! Fletcher checksum over an LSP — and the **link-state database** ([`lsdb`]): the
//! LSP store with the §7.3.16 recency rules, lifetime ageing, and the CSNP/PSNP
//! sequence-number synchronisation of §7.3.15. The **adjacency state machine**
//! ([`adjacency`], §8.2 with the RFC 5303 three-way handshake) and the **DIS
//! election** ([`dis`], §8.4.5) are in place too, as is the **SPF** ([`spf`],
//! §7.2): a Dijkstra over one level's database with the L1/L2 hierarchy and the
//! attached-bit default route. The `AF_PACKET` runner follows, RFC-section by
//! RFC-section, as it did for OSPF.

#![forbid(unsafe_code)]

use std::fmt;

pub mod adjacency;
pub mod dis;
pub mod lsdb;
pub mod pdu;
pub mod spf;
pub mod tlv;

// ===========================================================================
// Protocol constants (ISO/IEC 10589 §9, RFC 1195)
// ===========================================================================

/// The Intradomain Routeing Protocol Discriminator — the first byte of every
/// IS-IS PDU (ISO 9577 allocation for IS-IS).
pub const INTRADOMAIN_DISCRIMINATOR: u8 = 0x83;

/// The Version/Protocol ID Extension byte (always 1).
pub const PROTOCOL_ID_EXTENSION: u8 = 1;

/// The PDU Version byte (always 1).
pub const VERSION: u8 = 1;

/// The length of a System ID in bytes — fixed at 6 (an ID Length field of 0 on the
/// wire denotes this default).
pub const SYSTEM_ID_LEN: usize = 6;

/// The length of an LSP ID: a System ID, a pseudonode byte and an LSP-number byte.
pub const LSP_ID_LEN: usize = SYSTEM_ID_LEN + 2;

/// The default Maximum Area Addresses (an encoded value of 0 denotes this).
pub const DEFAULT_MAX_AREA_ADDRESSES: u8 = 3;

/// `AllL1ISs` — the multicast MAC every Level-1 IS listens on.
pub const ALL_L1_ISS: [u8; 6] = [0x01, 0x80, 0xc2, 0x00, 0x00, 0x14];

/// `AllL2ISs` — the multicast MAC every Level-2 IS listens on.
pub const ALL_L2_ISS: [u8; 6] = [0x01, 0x80, 0xc2, 0x00, 0x00, 0x15];

/// The LLC DSAP/SSAP value identifying IS-IS within an 802.2 frame.
pub const LLC_SAP: u8 = 0xFE;

/// The LLC control byte for IS-IS (Unnumbered Information).
pub const LLC_CONTROL: u8 = 0x03;

/// NLPID for IPv4 (RFC 1195) — advertised in the Protocols Supported TLV.
pub const NLPID_IPV4: u8 = 0xCC;

/// NLPID for IPv6 (RFC 5308) — advertised in the Protocols Supported TLV.
pub const NLPID_IPV6: u8 = 0x8E;

/// The metric meaning "do not use this for the SPF" in the wide-metric encoding
/// (RFC 5305 reserves `2^24 - 1` for extended IS reachability).
pub const MAX_WIDE_METRIC: u32 = 0x00ff_ffff;

// ===========================================================================
// Core identifiers
// ===========================================================================

/// An IS-IS System ID: the fixed 6-byte node identity at the centre of an NSAP.
/// Conventionally written as three 16-bit groups, e.g. `1921.6800.1001`.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SystemId(pub [u8; SYSTEM_ID_LEN]);

impl SystemId {
    /// The all-zero System ID (a useful sentinel; never a real node).
    pub const ZERO: SystemId = SystemId([0; SYSTEM_ID_LEN]);

    /// Build a System ID from its six bytes.
    pub fn new(bytes: [u8; SYSTEM_ID_LEN]) -> Self {
        SystemId(bytes)
    }

    /// The underlying bytes.
    pub fn bytes(&self) -> [u8; SYSTEM_ID_LEN] {
        self.0
    }
}

impl fmt::Display for SystemId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let b = self.0;
        write!(
            f,
            "{:02x}{:02x}.{:02x}{:02x}.{:02x}{:02x}",
            b[0], b[1], b[2], b[3], b[4], b[5]
        )
    }
}

impl fmt::Debug for SystemId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SystemId({self})")
    }
}

/// An LSP identifier (ISO 10589 §9.8): the originating System ID, the pseudonode
/// number (0 on a real router's own LSP, non-zero for a LAN's pseudonode) and the
/// LSP fragment number (LSPs are fragmented when their TLVs overflow one PDU).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct LspId {
    /// The originating System ID (or the DIS's, for a pseudonode LSP).
    pub system_id: SystemId,
    /// The pseudonode number — 0 for a router's own (non-pseudonode) LSP.
    pub pseudonode: u8,
    /// The LSP fragment number.
    pub fragment: u8,
}

impl LspId {
    /// Build an LSP ID.
    pub fn new(system_id: SystemId, pseudonode: u8, fragment: u8) -> Self {
        LspId {
            system_id,
            pseudonode,
            fragment,
        }
    }

    /// Serialize the 8-byte LSP ID.
    pub fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.system_id.0);
        out.push(self.pseudonode);
        out.push(self.fragment);
    }

    /// Parse an 8-byte LSP ID from the front of `b`.
    pub fn decode(b: &[u8]) -> Option<LspId> {
        if b.len() < LSP_ID_LEN {
            return None;
        }
        let mut sid = [0u8; SYSTEM_ID_LEN];
        sid.copy_from_slice(&b[..SYSTEM_ID_LEN]);
        Some(LspId {
            system_id: SystemId(sid),
            pseudonode: b[SYSTEM_ID_LEN],
            fragment: b[SYSTEM_ID_LEN + 1],
        })
    }
}

impl fmt::Display for LspId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}.{:02x}-{:02x}",
            self.system_id, self.pseudonode, self.fragment
        )
    }
}

/// An OSI area address — a variable-length prefix (1–20 bytes) shared by every
/// router in an area.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct AreaAddress(pub Vec<u8>);

/// Which IS-IS level(s) something applies to — the Circuit Type in a Hello, and
/// the IS Type in an LSP (ISO 10589 §9.5/§9.8).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
pub enum IsLevel {
    /// Level 1 only (intra-area).
    L1,
    /// Level 2 only (inter-area / the backbone).
    L2,
    /// Both levels.
    L1L2,
}

impl IsLevel {
    /// Decode the low two bits of a Circuit Type / IS Type field. `0` (reserved /
    /// "no level") is treated as [`IsLevel::L1L2`] for robustness.
    pub fn from_bits(v: u8) -> IsLevel {
        match v & 0b11 {
            0b01 => IsLevel::L1,
            0b10 => IsLevel::L2,
            _ => IsLevel::L1L2,
        }
    }

    /// The two-bit encoding.
    pub fn bits(self) -> u8 {
        match self {
            IsLevel::L1 => 0b01,
            IsLevel::L2 => 0b10,
            IsLevel::L1L2 => 0b11,
        }
    }

    /// Whether this level set includes Level 1.
    pub fn has_l1(self) -> bool {
        matches!(self, IsLevel::L1 | IsLevel::L1L2)
    }

    /// Whether this level set includes Level 2.
    pub fn has_l2(self) -> bool {
        matches!(self, IsLevel::L2 | IsLevel::L1L2)
    }
}

// ===========================================================================
// The ISO 8473 Fletcher checksum (used for LSPs, ISO 10589 §7.3.11)
// ===========================================================================

/// The number of bytes summed before each modulo reduction (RFC 1008 / ISO 8473).
const MODX: usize = 4102;

/// Compute and write the ISO 8473 Fletcher checksum into `region` — the LSP bytes
/// **from the LSP ID field onward** (ISO 10589 §7.3.11). `csum_off` is the offset
/// of the 2-byte checksum field within `region` (12: the 8-byte LSP ID plus the
/// 4-byte sequence number). The two checksum bytes are zeroed, the check bytes are
/// computed and written back, and the 16-bit checksum is returned.
pub fn fletcher16(region: &mut [u8], csum_off: usize) -> u16 {
    region[csum_off] = 0;
    region[csum_off + 1] = 0;
    let (mut c0, mut c1) = (0i32, 0i32);
    let len = region.len();
    let mut left = len;
    let mut p = 0usize;
    while left > 0 {
        let partial = left.min(MODX);
        for _ in 0..partial {
            c0 += region[p] as i32;
            c1 += c0;
            p += 1;
        }
        c0 %= 255;
        c1 %= 255;
        left -= partial;
    }
    // The check octets are placed so the running sums come out zero on receipt.
    let mut x = ((len as i32 - csum_off as i32 - 1) * c0 - c1) % 255;
    if x <= 0 {
        x += 255;
    }
    let mut y = 510 - c0 - x;
    if y > 255 {
        y -= 255;
    }
    region[csum_off] = x as u8;
    region[csum_off + 1] = y as u8;
    ((x << 8) | (y & 0xff)) as u16
}

/// Verify an ISO 8473 Fletcher checksum: fold the whole `region` (the checksum
/// bytes included) and accept iff both running sums come out zero.
pub fn fletcher16_valid(region: &[u8]) -> bool {
    let (mut c0, mut c1) = (0i32, 0i32);
    let mut left = region.len();
    let mut p = 0usize;
    while left > 0 {
        let partial = left.min(MODX);
        for _ in 0..partial {
            c0 += region[p] as i32;
            c1 += c0;
            p += 1;
        }
        c0 %= 255;
        c1 %= 255;
        left -= partial;
    }
    c0 == 0 && c1 == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn system_id_displays_cisco_style() {
        let id = SystemId::new([0x19, 0x21, 0x68, 0x00, 0x10, 0x01]);
        assert_eq!(id.to_string(), "1921.6800.1001");
    }

    #[test]
    fn lsp_id_roundtrips() {
        let id = LspId::new(SystemId::new([1, 2, 3, 4, 5, 6]), 0, 3);
        let mut buf = Vec::new();
        id.encode(&mut buf);
        assert_eq!(buf.len(), LSP_ID_LEN);
        assert_eq!(LspId::decode(&buf), Some(id));
        assert_eq!(LspId::decode(&buf[..7]), None);
        assert_eq!(id.to_string(), "0102.0304.0506.00-03");
    }

    #[test]
    fn is_level_bits_roundtrip() {
        for lvl in [IsLevel::L1, IsLevel::L2, IsLevel::L1L2] {
            assert_eq!(IsLevel::from_bits(lvl.bits()), lvl);
        }
        assert!(IsLevel::L1.has_l1());
        assert!(!IsLevel::L1.has_l2());
        assert!(IsLevel::L1L2.has_l1() && IsLevel::L1L2.has_l2());
    }

    #[test]
    fn fletcher_roundtrips_and_validates() {
        // A stand-in LSP region: LSP ID (8) + seq (4) + checksum (2) + a little body.
        let mut region: Vec<u8> = (0u8..24).collect();
        let csum = fletcher16(&mut region, 12);
        assert_ne!(csum, 0);
        assert!(fletcher16_valid(&region));
        region[20] ^= 0xff;
        assert!(!fletcher16_valid(&region));
    }
}
