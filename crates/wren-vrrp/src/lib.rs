//! # wren-vrrp — VRRP version 3 (RFC 5798)
//!
//! The Virtual Router Redundancy Protocol gives a LAN a highly-available default
//! gateway (or any shared service IP): two or more routers back a single *virtual*
//! IP address, electing one **Master** that owns it while the others stand by as
//! **Backup**s. If the master fails, a backup takes the virtual IP over within a
//! few advertisement intervals — the first-hop-redundancy half of a firewall HA
//! pair. This crate is Wren's equivalent of FRR's `vrrpd` / keepalived's VRRP.
//!
//! Like [`wren-bfd`](../wren_bfd/index.html) this crate is **dependency-free**: it
//! holds only the wire codec ([`packet`]) and the pure virtual-router state
//! machine ([`fsm`]). The async raw-socket runner (raw IP protocol 112, multicast
//! 224.0.0.18 / ff02::12, virtual-IP assignment, gratuitous ARP / unsolicited
//! neighbor advertisement) lives in the daemon (`vrrp.rs`), where tokio and the
//! kernel live.
//!
//! VRRP version 3 (RFC 5798) is dual-stack: the same advertisement carries either
//! IPv4 or IPv6 virtual addresses, distinguished by the IP header's family. Older
//! VRRPv2 (RFC 3768, IPv4-only, with a simpler checksum and authentication fields)
//! is intentionally not implemented — v3 supersedes it.

pub mod fsm;
pub mod packet;

pub use fsm::{Action, State, Vrrp, VrrpConfig};
pub use packet::{Advertisement, DecodeError, MCAST_V4, MCAST_V6, VERSION, VRRP_PROTO};
