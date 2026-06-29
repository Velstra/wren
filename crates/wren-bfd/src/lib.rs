//! # wren-bfd — Bidirectional Forwarding Detection (RFC 5880)
//!
//! BFD is a lightweight, protocol-independent hello mechanism for **fast**
//! detection of a forwarding-path failure between two systems — far faster than a
//! routing protocol's own hold timer. Two systems exchange small UDP Control
//! packets at a sub-second rate; when a system stops hearing its neighbour for
//! `detect-mult` intervals it declares the session **Down**, and the routing
//! protocols riding that path (here BGP) tear their adjacency down at once instead
//! of waiting tens of seconds for a hold timer.
//!
//! This crate is the **protocol core**, dependency-free `std`: the Control-packet
//! [wire codec](packet) (RFC 5880 §4.1) and the per-session
//! [state machine](session) (§6.8.6), with no I/O and no timekeeping — both are
//! the daemon runner's job (`wren-daemon`'s `bfd.rs`), which owns the UDP sockets
//! and the transmit / detection timers and feeds packets and timeouts into a
//! [`Session`]. Keeping it pure makes the FSM and the codec unit-testable with no
//! network, the same split every other Wren protocol crate uses.
//!
//! Scope: single-hop asynchronous mode (RFC 5881), with **authentication** (RFC 5880
//! §6.7 — Simple Password and Keyed/Meticulous MD5 & SHA1, in [`auth`]); no Echo
//! function — the common case that drives routing-protocol failover. The Demand and
//! Echo modes are future extensions.

#![forbid(unsafe_code)]

pub mod auth;
pub mod packet;
pub mod session;

pub use auth::{AuthConfig, AuthState, AuthType};
pub use packet::{ControlPacket, Diag, State, MANDATORY_LEN, VERSION};
pub use session::{Session, SessionConfig, Transition};
