//! # wren-ospfv3 — OSPFv3 (RFC 5340)
//!
//! OSPF for IPv6, built like [`wren_ospf`] (OSPFv2): a dependency-free
//! (`std`-only) library holding the protocol's *pure* parts so they are fully
//! unit-testable with no sockets or clock. The async runner that drives it over
//! a raw IPv6 (protocol 89) socket will live in `wren-daemon`.
//!
//! OSPFv3 keeps OSPFv2's algorithms (the flooding, the LSDB recency test, the
//! SPF) but rebuilds the wire format around three changes (RFC 5340 §2–§3):
//!
//! * **It runs over IPv6.** Packets are sourced from a link-local address and
//!   sent to `ff02::5` (`AllSPFRouters`) / `ff02::6` (`AllDRouters`); the common
//!   header shrinks from 24 to 16 bytes (no authentication — that is delegated to
//!   IPv6's own AH/ESP) and gains an *Instance ID*. The packet checksum is the
//!   standard IPv6 upper-layer checksum *with the pseudo-header*, so encoding and
//!   decoding need the source and destination addresses (see [`packet`]).
//! * **Topology is separated from addressing.** Router- and Network-LSAs no
//!   longer carry IP prefixes — they describe the graph using *interface IDs* and
//!   *router IDs* only. Addresses are advertised separately, in Link-LSAs
//!   (link-local scope) and Intra-Area-Prefix-LSAs. Inter-area, AS-external and
//!   router-to-router reachability move to their own LSA types.
//! * **LSAs are scoped explicitly.** The LS Type is now a 16-bit field whose top
//!   bits encode the flooding scope (link-local / area / AS) and how an unknown
//!   type is to be handled, so a router can flood LSA types it does not
//!   understand (see [`lsa::LsType`]).
//!
//! This crate is grown RFC-section by RFC-section. What is in place so far:
//!
//! * [`packet`] — the 16-byte OSPFv3 common header (§A.3.1) and all five packet
//!   bodies (Hello/DD/LSR/LSU/LSAck, §A.3.2–§A.3.6), with the IPv6 pseudo-header
//!   checksum.
//! * [`lsa`] — the 20-byte LSA header (§A.4.2) with the scoped 16-bit LS Type,
//!   the compact IPv6 prefix encoding (§A.4.1), the seven LSA bodies
//!   (§A.4.3–§A.4.9), the Fletcher LS checksum and the §13.1 recency comparison.
//! * [`lsdb`] — the link-state database (§12.2): a keyed store with the §13.1
//!   recency test deciding what replaces what, plus aging, one per flooding scope.
//! * [`neighbor`] — the neighbour state machine (§10), unchanged from OSPFv2 but
//!   tracking the neighbour's Interface ID for Router-LSA links.
//! * [`interface`] — the interface state machine (§9) and the DR/BDR election
//!   (§9.4), with DR/BDR identified directly by Router ID.
//! * [`flood`] — the §13 flooding decision (RFC 5340 §4.5, unchanged from v2):
//!   what to do with a received LSA and where to send LSAs onward.
//! * [`spf`] — the intra-area shortest-path-first calculation (§4.8): a Dijkstra
//!   over the address-free Router/Network graph, prefixes attached afterwards
//!   from the Intra-Area-Prefix-LSAs and next hops resolved from the Link-LSAs,
//!   plus the inter-area and AS-external stages.
//!
//! Still to come: the daemon runner (a raw IPv6 protocol-89 socket).
//!
//! [`wren_ospf`]: https://docs.rs/wren-ospf

#![forbid(unsafe_code)]

use std::net::Ipv6Addr;

pub mod flood;
pub mod interface;
pub mod lsa;
pub mod lsdb;
pub mod neighbor;
pub mod packet;
pub mod spf;

// ===========================================================================
// Protocol constants (RFC 5340)
// ===========================================================================

/// The OSPF version this crate speaks. Always 3.
pub const VERSION: u8 = 3;

/// IP protocol number carried in the IPv6 header for OSPF packets (§A.1).
pub const IP_PROTOCOL: u8 = 89;

/// `AllSPFRouters` — link-local multicast group every OSPFv3 router joins (§A.1).
pub const ALL_SPF_ROUTERS: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 5);

/// `AllDRouters` — link-local multicast the DR and BDR additionally join (§A.1).
pub const ALL_D_ROUTERS: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 6);

/// Default `HelloInterval` on broadcast/point-to-point links, in seconds.
pub const DEFAULT_HELLO_INTERVAL: u16 = 10;

/// Default `RouterDeadInterval`, in seconds — conventionally 4× the hello.
pub const DEFAULT_DEAD_INTERVAL: u16 = 40;

/// `LSRefreshTime` — a router re-originates its self-originated LSAs this often.
pub const LS_REFRESH_TIME: u16 = 1800;

/// `MaxAge` — an LSA reaching this age (seconds) is flushed from the domain.
pub const MAX_AGE: u16 = 3600;

/// `MaxAgeDiff` — two instances whose ages differ by more than this (seconds)
/// are treated as different for the §13.1 "which is newer" test.
pub const MAX_AGE_DIFF: u16 = 900;

/// `MinLSArrival` — the shortest interval (seconds) at which a router accepts a
/// new instance of any one LSA during flooding.
pub const MIN_LS_ARRIVAL: u16 = 1;

/// `MinLSInterval` — the shortest interval (seconds) between successive
/// originations of any one self-originated LSA.
pub const MIN_LS_INTERVAL: u16 = 5;

/// `InitialSequenceNumber` — the first LS sequence number a router uses. Sequence
/// numbers are *signed* and increase towards [`MAX_SEQUENCE_NUMBER`].
pub const INITIAL_SEQUENCE_NUMBER: i32 = -0x7fff_ffff; // 0x80000001

/// `MaxSequenceNumber` — the largest LS sequence number.
pub const MAX_SEQUENCE_NUMBER: i32 = 0x7fff_ffff;

/// `LSInfinity` — the metric meaning "unreachable" in inter-area/external LSAs.
pub const LS_INFINITY: u32 = 0x00ff_ffff;

// ---------------------------------------------------------------------------
// The Options field (§A.2) — 24 bits, carried in Hellos, DD packets and the
// Router/Network/Link LSAs (it left the LSA *header* in OSPFv3).
// ---------------------------------------------------------------------------

/// `V6`-bit — the router/link should be included in IPv6 routing calculations.
pub const OPT_V6: u32 = 0x01;
/// `E`-bit — the area supports AS-external LSAs (i.e. is *not* a stub).
pub const OPT_E: u32 = 0x02;
/// `MC`-bit — multicast-capable (MOSPF).
pub const OPT_MC: u32 = 0x04;
/// `N`-bit — the router is attached to an NSSA.
pub const OPT_N: u32 = 0x08;
/// `R`-bit — the originator is an active router; if clear, its transit links are
/// not used. A host that only originates prefixes clears it.
pub const OPT_R: u32 = 0x10;
/// `DC`-bit — demand-circuit support.
pub const OPT_DC: u32 = 0x20;
/// `AF`-bit — the router supports OSPFv3 address families (RFC 5838).
pub const OPT_AF: u32 = 0x0100;

// ===========================================================================
// Checksums
// ===========================================================================

/// Fold a one's-complement running sum to 16 bits.
fn fold(mut sum: u32) -> u16 {
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    sum as u16
}

/// The OSPFv3 packet checksum (§2.6, the standard IPv6 upper-layer checksum): the
/// one's-complement sum over the IPv6 pseudo-header (source, destination, the
/// upper-layer length and the Next Header value 89) followed by the OSPF packet
/// itself, complemented. The packet's own 16-bit checksum field must be zeroed in
/// `pkt` first. Returns the value to store (or, when `pkt` already carries the
/// checksum, `0` if it verifies).
pub(crate) fn packet_checksum(src: Ipv6Addr, dst: Ipv6Addr, pkt: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    for addr in [src, dst] {
        for chunk in addr.octets().chunks_exact(2) {
            sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
        }
    }
    // Upper-layer packet length (32-bit) and the Next Header byte (89). The three
    // zero bytes preceding Next Header contribute nothing.
    let len = pkt.len() as u32;
    sum += len >> 16;
    sum += len & 0xffff;
    sum += IP_PROTOCOL as u32;
    // The OSPF packet body.
    let mut chunks = pkt.chunks_exact(2);
    for c in &mut chunks {
        sum += u16::from_be_bytes([c[0], c[1]]) as u32;
    }
    if let [last] = chunks.remainder() {
        sum += (*last as u32) << 8;
    }
    !fold(sum)
}

/// The number of bytes summed before each modulo reduction in the Fletcher loop;
/// the largest value that cannot overflow the running sums (RFC 1008).
const MODX: usize = 4102;

/// The Fletcher-16 LS checksum (ISO/IEC 8473), computed over an LSA *from the LS
/// Type field onward* — i.e. the LS age is excluded, so `region` must be the LSA
/// with its first two bytes already stripped. Identical in form to OSPFv2; only
/// the excluded prefix (the 2-byte age) differs, and that is the same 2 bytes.
///
/// `csum_off` is the byte offset of the 16-bit checksum field within `region`
/// (14 for a standard LSA). The two checksum bytes are zeroed, the check bytes
/// are computed and written back, and the resulting checksum is returned.
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
/// included) and accept iff both running sums come out zero (RFC 1008).
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
    fn packet_checksum_roundtrips_and_detects_corruption() {
        let src = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
        let dst = ALL_SPF_ROUTERS;
        // A 16-byte stand-in packet with the checksum field (bytes 12..14) zero.
        let mut pkt: Vec<u8> = (0u8..16).collect();
        pkt[12] = 0;
        pkt[13] = 0;
        let c = packet_checksum(src, dst, &pkt);
        // Splice it in; the receiver re-zeroes and recomputes to the same value.
        pkt[12..14].copy_from_slice(&c.to_be_bytes());
        let mut scratch = pkt.clone();
        scratch[12] = 0;
        scratch[13] = 0;
        assert_eq!(packet_checksum(src, dst, &scratch), c);
        // A different destination (pseudo-header) changes the checksum.
        assert_ne!(packet_checksum(src, ALL_D_ROUTERS, &scratch), c);
    }

    #[test]
    fn fletcher_roundtrips_and_validates() {
        let mut region: Vec<u8> = (0u8..24).collect();
        let csum = fletcher16(&mut region, 14);
        assert_ne!(csum, 0);
        assert!(fletcher16_valid(&region));
        region[3] ^= 0xff;
        assert!(!fletcher16_valid(&region));
    }
}
