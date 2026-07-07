//! # wren-pim — PIM-SM (RFC 7761) sparse-mode multicast routing
//!
//! IPTV and other multicast *between routers* is the driver here. Where
//! [`wren_igmp`](../wren_igmp/index.html) learns which hosts on a LAN want a group,
//! PIM-SM is the protocol that actually pulls that group across the router network:
//! it builds the shared tree `(*,G)` rooted at a Rendezvous Point (RP) and the
//! per-source tree `(S,G)`, and tells the kernel's multicast forwarding cache which
//! interface a group arrives on and which interfaces to replicate it onto.
//!
//! This crate is the dependency-free (`std`-only) library — the *pure* parts, fully
//! unit-testable with no sockets:
//!
//! * the [`wire`] codec — the RFC 7761 §4.9 PIM packet formats this subset uses:
//!   Hello, Join/Prune, Register and Register-Stop, plus the encoded-address forms
//!   and the Internet checksum. It faces hostile input off a raw socket, so it
//!   validates every length and is swept with a no-panic-on-arbitrary-input test;
//! * the [`neighbor`] table — Hello-based neighbour discovery and liveness (§4.3):
//!   a neighbour is learned from its Hello, refreshed on each Hello, and aged out
//!   when its advertised Holdtime elapses;
//! * the [`tree`] state machine — the `(*,G)` / `(S,G)` Tree Information Base: it
//!   consumes IGMP membership (from `wren-igmp`) and received Join/Prune, tracks the
//!   RPF interface/neighbour toward the RP or source and the downstream outgoing-
//!   interface (OIF) list, and emits the upstream Join/Prune the runner sends and the
//!   forwarding-cache entries the kernel MFC needs.
//!
//! The async raw-socket runner that drives all of this (raw IP protocol 103, the
//! Hello/Join-Prune I/O, the IGMP membership feed and the `MRT_*` multicast-
//! forwarding-cache writer) lives in `wren-daemon` (`pim.rs` / `mroute.rs`), the same
//! library/runner split as [`wren_igmp`] and the routing IGPs.
//!
//! ## Scope — the bounded subset that landed
//!
//! * **PIM-SM with a *statically configured* RP.** The dynamic RP-discovery
//!   machinery (BSR, RFC 5059; Auto-RP) is **deferred**: the RP address is given in
//!   the config. This removes the most complex bootstrap while keeping real routing.
//! * `(*,G)` shared-tree join toward the RP, driven by IGMP membership.
//! * `(S,G)` source-tree join toward the source (the SPT), driven by an IGMPv3
//!   source-specific (SSM-style) membership or by SPT switchover, and by a received
//!   Join(S,G).
//! * Register / Register-Stop encapsulation at the RP boundary (the codec and the
//!   first-hop/RP state; see [`tree`] for exactly which transitions are modelled).
//!
//! ## Deferred (documented, not built)
//!
//! * **BSR / Auto-RP** dynamic RP discovery — static RP only.
//! * **PIM-DM**, **MSDP**, **Anycast-RP**, the **Assert** election beyond the codec,
//!   and the **BiDir** trees.
//! * **IPv6 PIM (PIM6)** — IPv4 first, mirroring the IGMP-before-MLD order.

#![forbid(unsafe_code)]

use std::net::Ipv4Addr;

pub mod neighbor;
pub mod tree;
pub mod wire;

pub use neighbor::{Neighbor, NeighborEvent, NeighborTable};
pub use tree::{JoinPruneAction, MrouteEntry, RpfInfo, RpfLookup, TreeKind, TreeTable};
pub use wire::{
    DecodeError, EncodedGroup, EncodedSource, EncodedUnicast, HelloOption, Message, PimError,
};

// ===========================================================================
// Protocol constants (RFC 7761)
// ===========================================================================

/// The IP protocol number PIM rides directly on top of (§4.9). Not UDP — raw IP.
pub const PIM_PROTO: u8 = 103;

/// The PIM version this speaks — PIMv2 (§4.9).
pub const PIM_VERSION: u8 = 2;

/// `224.0.0.13` — the ALL-PIM-ROUTERS link-local group every multicast Hello and
/// Join/Prune is sent to (§4.9). Register / Register-Stop are unicast instead.
pub const ALL_PIM_ROUTERS: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 13);

/// PIM message type: Hello (§4.9.2).
pub const TYPE_HELLO: u8 = 0;
/// PIM message type: Register (§4.9.1) — unicast, first-hop DR → RP.
pub const TYPE_REGISTER: u8 = 1;
/// PIM message type: Register-Stop (§4.9.4) — unicast, RP → first-hop DR.
pub const TYPE_REGISTER_STOP: u8 = 2;
/// PIM message type: Join/Prune (§4.9.5).
pub const TYPE_JOIN_PRUNE: u8 = 3;
/// PIM message type: Assert (§4.9.6). Codec only in this subset.
pub const TYPE_ASSERT: u8 = 5;

/// Hello Option type: Holdtime (§4.9.2) — how long to keep the neighbour without a
/// further Hello. A Holdtime of `0xFFFF` means "never time out"; `0` means the
/// neighbour is going away immediately.
pub const OPT_HOLDTIME: u16 = 1;
/// Hello Option type: LAN Prune Delay (§4.9.2).
pub const OPT_LAN_PRUNE_DELAY: u16 = 2;
/// Hello Option type: DR Priority (§4.9.2) — used in DR election on a LAN.
pub const OPT_DR_PRIORITY: u16 = 19;
/// Hello Option type: Generation ID (§4.9.2) — changes when a neighbour restarts.
pub const OPT_GENERATION_ID: u16 = 20;

/// The default Hello period (§4.11, `Hello_Period`) — 30 s.
pub const DEFAULT_HELLO_PERIOD_SECS: u16 = 30;
/// The default Hello Holdtime (§4.11, `Default_Hello_Holdtime`) — 3.5 × Hello, 105 s.
pub const DEFAULT_HOLDTIME_SECS: u16 = 105;
/// The default Join/Prune Holdtime (§4.11, `J/P_Holdtime`) — 3.5 × the 60 s
/// `t_periodic`, i.e. 210 s.
pub const DEFAULT_JP_HOLDTIME_SECS: u16 = 210;
/// The default periodic Join/Prune interval (§4.11, `t_periodic`) — 60 s.
pub const DEFAULT_JP_PERIOD_SECS: u16 = 60;
/// The default DR priority advertised in Hello (§4.3.2).
pub const DEFAULT_DR_PRIORITY: u32 = 1;

/// Whether `addr` is a multicast group address (`224.0.0.0/4`).
#[inline]
pub fn is_multicast(addr: Ipv4Addr) -> bool {
    addr.is_multicast()
}

/// Whether `addr` is a link-local control group (`224.0.0.0/24`) — never routed
/// off-link by PIM (the ALL-PIM-ROUTERS group, the IGMP control groups, …).
#[inline]
pub fn is_link_local_control(addr: Ipv4Addr) -> bool {
    let o = addr.octets();
    o[0] == 224 && o[1] == 0 && o[2] == 0
}
