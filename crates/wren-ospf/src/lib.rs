//! # wren-ospf — OSPFv2 (RFC 2328)
//!
//! The OSPF Version 2 link-state routing protocol, built like [`wren_rip`]: a
//! dependency-free (`std`-only) library holding the protocol's *pure* parts —
//! the wire codec, the link-state database, the neighbour/interface state
//! machines and the SPF (shortest-path-first) calculation — so they are fully
//! unit-testable with no sockets or clock. The async runner that drives it over
//! a raw IP (protocol 89) socket lives in `wren-daemon`, behind tokio/libc,
//! exactly as the RIP runner does.
//!
//! This crate is being grown RFC-section by RFC-section. What is in place so far:
//!
//! * [`packet`] — the 24-byte OSPF common header (§A.3.1) and the Hello packet
//!   (§A.3.2), with the standard IP packet checksum.
//! * [`lsa`] — the 20-byte LSA header (§A.4.1), the four LSA bodies
//!   (router/network/summary/external, §A.4.2–§A.4.5), the Fletcher LS checksum
//!   (§12.1.7) and the "which LSA instance is newer" comparison (§13.1).
//! * [`lsdb`] — the link-state database (§12.2): keyed storage with the §13.1
//!   recency test deciding what replaces what, plus LSA aging.
//! * [`spf`] — the intra-area Dijkstra shortest-path-first (§16.1) reading the
//!   [`lsdb`] and producing [`wren_core::Route`]s, with §16.1.1 next-hop and stub
//!   handling.
//! * [`neighbor`] — the neighbour state machine (§10): the per-neighbour
//!   conversation from first Hello to a Full adjacency.
//! * [`interface`] — the interface state machine (§9) and the DR/BDR election
//!   (§9.4).
//! * [`flood`] — the flooding procedure (§13): the decision for a received LSA
//!   (install/ack/send-back/discard) and the §13.3 out-interface multicast scope.
//!
//! Still to come: the daemon runner (raw IP proto 89, multicast, Hello/dead
//! timers) wiring the packets, LSDB, FSMs and flooding together; and the inter-
//! area (summary) and AS-external route calculations (§16.2–§16.4).

#![forbid(unsafe_code)]

use std::net::Ipv4Addr;

pub mod flood;
pub mod interface;
pub mod lsa;
pub mod lsdb;
pub mod md5;
pub mod neighbor;
pub mod packet;
pub mod spf;

// ===========================================================================
// Protocol constants (RFC 2328)
// ===========================================================================

/// The OSPF version this crate speaks. Always 2.
pub const VERSION: u8 = 2;

/// IP protocol number carried in the IPv4 header for OSPF packets (§A.1).
pub const IP_PROTOCOL: u8 = 89;

/// `AllSPFRouters` — multicast group every OSPF router joins (§A.1).
pub const ALL_SPF_ROUTERS: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 5);

/// `AllDRouters` — multicast group the DR and BDR additionally join (§A.1).
pub const ALL_D_ROUTERS: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 6);

/// Default `HelloInterval` on broadcast/point-to-point links, in seconds (§C.3).
pub const DEFAULT_HELLO_INTERVAL: u16 = 10;

/// Default `RouterDeadInterval`, in seconds — conventionally 4× the hello (§C.3).
pub const DEFAULT_DEAD_INTERVAL: u32 = 40;

/// `LSRefreshTime` — a router re-originates its self-originated LSAs this often,
/// in seconds (§F / Appendix B).
pub const LS_REFRESH_TIME: u16 = 1800;

/// `MaxAge` — an LSA reaching this age (seconds) is flushed from the domain.
pub const MAX_AGE: u16 = 3600;

/// `MaxAgeDiff` — two instances whose ages differ by more than this (seconds)
/// are treated as different for the §13.1 "which is newer" test.
pub const MAX_AGE_DIFF: u16 = 900;

/// `CheckAge` — LSA checksums are re-verified on this cadence (seconds).
pub const CHECK_AGE: u16 = 300;

/// `MinLSArrival` — the shortest interval (seconds) at which a router will accept
/// a new instance of any one LSA during flooding (§13, rate-limits churn).
pub const MIN_LS_ARRIVAL: u16 = 1;

/// `MinLSInterval` — the shortest interval (seconds) between successive
/// originations of any one self-originated LSA (§12.4).
pub const MIN_LS_INTERVAL: u16 = 5;

/// `InitialSequenceNumber` — the first LS sequence number a router uses (§12.1.6).
/// Sequence numbers are *signed* and increase towards [`MAX_SEQUENCE_NUMBER`].
pub const INITIAL_SEQUENCE_NUMBER: i32 = -0x7fff_ffff; // 0x80000001

/// `MaxSequenceNumber` — the largest LS sequence number (§12.1.6).
pub const MAX_SEQUENCE_NUMBER: i32 = 0x7fff_ffff;

/// `LSInfinity` — the metric meaning "unreachable" in summary/external LSAs.
pub const LS_INFINITY: u32 = 0x00ff_ffff;

// ---------------------------------------------------------------------------
// The Options field (§A.2): | * | * | DC | EA | N/P | MC | E | * |
// ---------------------------------------------------------------------------

/// `E`-bit — the area supports AS-external LSAs (i.e. is *not* a stub). Must
/// match between neighbours on a Hello for an adjacency to form (§10.5).
pub const OPT_E: u8 = 0x02;
/// `MC`-bit — multicast-capable (MOSPF).
pub const OPT_MC: u8 = 0x04;
/// `N/P`-bit — NSSA support / propagate.
pub const OPT_NP: u8 = 0x08;
/// `DC`-bit — demand-circuit support.
pub const OPT_DC: u8 = 0x20;

// ===========================================================================
// Checksums
// ===========================================================================

/// The standard 16-bit one's-complement (IP) checksum over `data`, used for the
/// OSPF packet header checksum field (§A.3.1). The caller zeroes the checksum
/// (and authentication) bytes first; this just folds the bytes.
pub(crate) fn ip_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut chunks = data.chunks_exact(2);
    for c in &mut chunks {
        sum += u16::from_be_bytes([c[0], c[1]]) as u32;
    }
    if let [last] = chunks.remainder() {
        sum += (*last as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// The number of bytes summed before each modulo reduction in the Fletcher
/// loop; the largest value that cannot overflow the running sums (RFC 1008).
const MODX: usize = 4102;

/// The Fletcher-16 LS checksum (ISO/IEC 8473, RFC 2328 §12.1.7), computed over
/// an LSA *from the Options field onward* — i.e. the LS age is excluded, so
/// `region` must be the LSA with its first two bytes already stripped.
///
/// `csum_off` is the byte offset of the 16-bit checksum field within `region`
/// (14 for a standard LSA: the checksum sits 16 bytes into the LSA, the first 2
/// of which are the excluded age). The two checksum bytes are zeroed, the check
/// bytes are computed and written back, and the resulting checksum is returned.
pub(crate) fn fletcher16(region: &mut [u8], csum_off: usize) -> u16 {
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

/// Verify a Fletcher LS checksum: fold the whole `region` (checksum bytes
/// included) and accept iff both running sums come out zero (RFC 1008). `region`
/// is the LSA from the Options field onward, exactly as for [`fletcher16`].
pub(crate) fn fletcher16_valid(region: &[u8]) -> bool {
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
mod checksum_tests {
    use super::*;

    #[test]
    fn ip_checksum_detects_corruption() {
        let mut buf = vec![0x45, 0x00, 0x00, 0x3c, 0x1c, 0x46, 0x40, 0x00, 0x40, 0x06];
        let c = ip_checksum(&buf);
        // Splicing the checksum back in must make the whole thing fold to 0.
        buf.extend_from_slice(&c.to_be_bytes());
        assert_eq!(ip_checksum(&buf), 0);
        // Flip a bit -> no longer valid.
        buf[0] ^= 0x01;
        assert_ne!(ip_checksum(&buf), 0);
    }

    #[test]
    fn fletcher_roundtrips_and_validates() {
        // A 20-byte stand-in LSA region (options-onward) with checksum at off 14.
        let mut region: Vec<u8> = (0u8..24).collect();
        let csum = fletcher16(&mut region, 14);
        assert_ne!(csum, 0, "a non-trivial body yields a non-zero checksum");
        assert!(fletcher16_valid(&region), "freshly stamped region validates");
        // Corrupt a byte -> validation fails.
        region[3] ^= 0xff;
        assert!(!fletcher16_valid(&region));
    }
}
