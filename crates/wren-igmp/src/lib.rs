//! # wren-igmp — IGMP (RFC 3376) and MLD (RFC 3810) querier / proxy (RFC 4605)
//!
//! IPTV and other multicast behind the firewall is the driver here: a LAN host
//! signals "I want group G" with an IGMP (IPv4) or MLD (IPv6) membership report, and
//! the router has to (a) learn that membership and (b) pull the stream down from
//! upstream. This crate is the dependency-free (`std`-only) library holding the
//! *pure* parts — the wire codecs and the membership/aggregation state machines — so
//! they are fully unit-testable with no sockets. The async raw-socket runners that
//! drive them (the actual queriers) live in `wren-daemon` (`igmp.rs` / `mld.rs`), the
//! same split as [`wren_ospf`]/[`wren_babel`].
//!
//! Despite the crate name, it speaks **both** address families: IGMP over IPv4 and
//! MLD over IPv6 are the same protocol logic, so the [`membership`] state machine and
//! the [`proxy`] aggregation are written once, generic over the group address family
//! ([`MulticastAddr`] / [`GroupAddr`]).
//!
//! What is in place:
//!
//! * the [`wire`] codec (IPv4/IGMP) — the IGMPv3 Membership Query and Version 3
//!   Membership Report (with group records and source lists), plus legacy IGMPv1/v2
//!   Report and v2 Leave, the Max-Resp-Code/QQIC floating-point encoding (§4.1.1) and
//!   the Internet checksum;
//! * the [`mld`] codec (IPv6/MLD, RFC 3810) — the MLDv2 Multicast Listener Query and
//!   Version 2 Report over ICMPv6 (types 130/143), plus legacy MLDv1 Report/Done
//!   (131/132), the 16-bit Max-Resp-Code float and the ICMPv6 checksum (with IPv6
//!   pseudo-header);
//! * both codecs face hostile input off the wire, so they validate lengths (and, for
//!   IGMP, the checksum) and are heavily unit-tested including a no-panic-on-arbitrary
//!   -input sweep;
//! * the [`membership`] querier state machine — a per-interface group table (§6) that
//!   a querier feeds received reports into: it tracks each group's filter mode
//!   (INCLUDE/EXCLUDE) and source list, refreshes the group timer, and ages a group
//!   out when the Group Membership Interval elapses. Generic over IPv4/IPv6;
//! * the [`proxy`] aggregation (RFC 4605) — merges the membership of several
//!   *downstream* interfaces into a single *upstream* subscription (also generic over
//!   the family), emitting the join/leave the proxy forwards upstream and the
//!   multicast-forwarding-cache (MFC) entries the kernel needs (group → oif list).
//!
//! ## Deferred (documented, not built)
//!
//! * **PIM** — inter-router multicast routing (RFC 7761). The proxy ([RFC 4605])
//!   covers the single-upstream firewall case without it.
//! * The full §6.4 EXCLUDE-mode source-timer bookkeeping and the Last-Member-Query
//!   retransmission on leaves are simplified to immediate state changes; the common
//!   IPTV cases (join `*,G`, SSM `S,G`, leave) are modelled exactly. See
//!   [`membership`] for the precise contract.

#![forbid(unsafe_code)]

use std::net::{Ipv4Addr, Ipv6Addr};

pub mod election;
pub mod membership;
pub mod mld;
pub mod proxy;
pub mod wire;

pub use election::{ElectionEvent, QuerierState};
pub use membership::{
    FilterMode, GroupMembership, MembershipEvent, MembershipTable, MulticastAddr, TimerConfig,
};
pub use proxy::{ForwardingEntry, GroupAddr, IgmpProxy, MldProxy, MulticastProxy, ProxyAction};
pub use wire::{DecodeError, GroupRecord, Message, Query, RecordType};

// ===========================================================================
// Protocol constants (RFC 3376)
// ===========================================================================

/// The IP protocol number IGMP rides in (§4).
pub const IGMP_PROTO: u8 = 2;

/// `224.0.0.1` — the all-hosts group a General Query is sent to (§4.1.12).
pub const ALL_HOSTS: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 1);

/// `224.0.0.2` — the all-routers group.
pub const ALL_ROUTERS: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 2);

/// `224.0.0.22` — the destination every IGMPv3 Membership Report is sent to, and
/// hence the group a querier joins to hear them (§4.2.14).
pub const IGMPV3_ALL_ROUTERS: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 22);

/// IGMP message type: Membership Query (§4.1).
pub const TYPE_QUERY: u8 = 0x11;
/// IGMP message type: Version 1 Membership Report (RFC 1112).
pub const TYPE_V1_REPORT: u8 = 0x12;
/// IGMP message type: Version 2 Membership Report (RFC 2236).
pub const TYPE_V2_REPORT: u8 = 0x16;
/// IGMP message type: Version 2 Leave Group (RFC 2236).
pub const TYPE_V2_LEAVE: u8 = 0x17;
/// IGMP message type: Version 3 Membership Report (RFC 3376 §4.2).
pub const TYPE_V3_REPORT: u8 = 0x22;

/// Whether `addr` is a multicast group address (`224.0.0.0/4`).
#[inline]
pub fn is_multicast(addr: Ipv4Addr) -> bool {
    addr.is_multicast()
}

/// Whether `addr` is a link-local multicast control group (`224.0.0.0/24`) — these
/// (`224.0.0.1`, `224.0.0.22`, …) are never proxied or forwarded off-link.
#[inline]
pub fn is_link_local_control(addr: Ipv4Addr) -> bool {
    let o = addr.octets();
    o[0] == 224 && o[1] == 0 && o[2] == 0
}

// ===========================================================================
// MLD constants (IPv6 — RFC 3810 / RFC 2710)
// ===========================================================================

/// The IPv6 next-header value MLD rides in — ICMPv6 (RFC 4443).
pub const ICMPV6_PROTO: u8 = 58;

/// `ff02::1` — the all-nodes link-local group an MLD General Query is sent to.
pub const ALL_NODES_V6: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1);

/// `ff02::2` — the all-routers link-local group.
pub const ALL_ROUTERS_V6: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 2);

/// `ff02::16` — the destination every MLDv2 Report is sent to, and hence the group a
/// querier joins to hear them (RFC 3810 §5.2.14).
pub const MLDV2_ALL_ROUTERS: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0x16);

/// ICMPv6 type: Multicast Listener Query (RFC 2710 / RFC 3810 §5.1).
pub const MLD_QUERY: u8 = 130;
/// ICMPv6 type: MLDv1 Multicast Listener Report (RFC 2710).
pub const MLD_V1_REPORT: u8 = 131;
/// ICMPv6 type: MLDv1 Multicast Listener Done (RFC 2710).
pub const MLD_V1_DONE: u8 = 132;
/// ICMPv6 type: MLDv2 Multicast Listener Report (RFC 3810 §5.2).
pub const MLD_V2_REPORT: u8 = 143;
