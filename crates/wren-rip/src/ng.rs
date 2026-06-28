//! # RIPng (RFC 2080) — the IPv6 RIP wire codec
//!
//! RIPng is RIP for IPv6. The distance-vector logic is identical to RIPv2 and is
//! shared via the address-neutral [`RipTable`](crate::RipTable); only the wire
//! format, transport (UDP port 521, multicast `FF02::9`) and version (1) differ,
//! and that is what this module handles.
//!
//! ## Message format (RFC 2080 §2.1)
//!
//! The 4-octet header (command, version = 1, two zero octets) is the same as
//! RIPv2; each route table entry (RTE) is 20 octets and carries **no** address
//! family identifier:
//!
//! ```text
//! +---------------------------------------------------------------+
//! |                    IPv6 prefix (16 octets)                    |
//! +-------------------------------+---------------+---------------+
//! |        route tag (2)          | prefix len (1)|   metric (1)  |
//! +-------------------------------+---------------+---------------+
//! ```
//!
//! A **next-hop RTE** (RFC 2080 §2.1.1) has `metric == 0xFF`; its 16-octet field
//! is an IPv6 next-hop address that applies to the route RTEs that follow it (an
//! address of `::` means "use the originator of the datagram").

use std::fmt;
use std::net::{IpAddr, Ipv6Addr};

use wren_core::Prefix;

use crate::{Advert, Command, RipError, METRIC_INFINITY};

/// The well-known UDP port RIPng listens on (RFC 2080 §2.1).
pub const PORT: u16 = 521;
/// The RIPng version number.
pub const VERSION: u8 = 1;
/// The link-local "all-RIP-routers" multicast group (RFC 2080 §2.1).
pub const ALL_RIP_ROUTERS: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 9);
/// The metric value that marks an RTE as a next-hop RTE (RFC 2080 §2.1.1).
pub const NEXT_HOP_METRIC: u8 = 0xff;
/// One RTE's length, octets.
pub const RTE_LEN: usize = 20;
/// Fixed message header length, octets.
pub const HEADER_LEN: usize = 4;
/// A conservative cap on RTEs per datagram that fits the IPv6 minimum MTU
/// (1280): `(1280 - 40 IPv6 - 8 UDP - 4 RIPng) / 20`.
pub const MAX_ENTRIES: usize = 61;

/// One RIPng route table entry, with any preceding next-hop RTE already resolved.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Rte {
    /// Destination IPv6 prefix.
    pub prefix: Prefix,
    /// Route tag (carries an attribute across the RIP domain).
    pub tag: u16,
    /// Next hop, or `None` to use the datagram's originator (RFC 2080 §2.1.1).
    pub next_hop: Option<Ipv6Addr>,
    /// Metric, 1..=16 (16 = infinity / unreachable).
    pub metric: u8,
}

impl Rte {
    /// A route RTE with next-hop "self" and no tag.
    pub fn route(prefix: Prefix, metric: u8) -> Self {
        Self {
            prefix,
            tag: 0,
            next_hop: None,
            metric,
        }
    }

    /// Whether this entry advertises an unreachable route (metric ≥ 16).
    pub fn is_infinity(&self) -> bool {
        self.metric as u32 >= METRIC_INFINITY
    }
}

/// A full RIPng message: a header plus its (resolved) route entries.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Message {
    /// Request or Response.
    pub command: Command,
    /// The route table entries, with next hops resolved.
    pub entries: Vec<Rte>,
}

impl Message {
    /// A Response carrying `entries`.
    pub fn response(entries: Vec<Rte>) -> Self {
        Self {
            command: Command::Response,
            entries,
        }
    }

    /// A Response advertising `adverts` (all with next-hop self), e.g. from
    /// [`RipTable::adverts`](crate::RipTable::adverts).
    pub fn from_adverts(adverts: &[Advert]) -> Self {
        let entries = adverts
            .iter()
            .filter(|a| a.prefix.addr().is_ipv6())
            .map(|a| Rte::route(a.prefix, a.metric.min(METRIC_INFINITY) as u8))
            .collect();
        Self::response(entries)
    }

    /// The "send me your whole table" request (RFC 2080 §2.4.1): a single RTE for
    /// `::/0` with metric = infinity.
    pub fn request_full_table() -> Self {
        Self {
            command: Command::Request,
            entries: vec![Rte {
                prefix: Prefix::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0).unwrap(),
                tag: 0,
                next_hop: None,
                metric: METRIC_INFINITY as u8,
            }],
        }
    }

    /// Whether this is the whole-table request above.
    pub fn is_full_table_request(&self) -> bool {
        self.command == Command::Request
            && self.entries.len() == 1
            && self.entries[0].prefix.is_default()
            && self.entries[0].is_infinity()
    }

    /// Encode to the on-the-wire octets, inserting a next-hop RTE whenever the
    /// next hop changes (RFC 2080 §2.1.1).
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HEADER_LEN + self.entries.len() * RTE_LEN);
        out.push(self.command.as_u8());
        out.push(VERSION);
        out.extend_from_slice(&[0, 0]); // must be zero

        let mut current_nh: Option<Ipv6Addr> = None;
        for e in &self.entries {
            let IpAddr::V6(addr) = e.prefix.addr() else {
                continue; // RIPng carries IPv6 only
            };
            if e.next_hop != current_nh {
                let nh = e.next_hop.unwrap_or(Ipv6Addr::UNSPECIFIED);
                push_rte(&mut out, &nh, 0, 0, NEXT_HOP_METRIC);
                current_nh = e.next_hop;
            }
            push_rte(&mut out, &addr, e.tag, e.prefix.len(), e.metric);
        }
        out
    }

    /// Decode from on-the-wire octets, resolving next-hop RTEs into each route's
    /// `next_hop`. Route entries with an invalid prefix length are skipped (per
    /// RFC 2080 §2.4.2, a bad RTE is ignored, not the whole datagram).
    pub fn decode(buf: &[u8]) -> Result<Self, RipError> {
        if buf.len() < HEADER_LEN {
            return Err(RipError::TooShort);
        }
        let command = Command::from_u8(buf[0]).ok_or(RipError::UnknownCommand(buf[0]))?;
        let body = &buf[HEADER_LEN..];
        if body.len() % RTE_LEN != 0 {
            return Err(RipError::BadLength(body.len()));
        }

        let mut entries = Vec::new();
        let mut current_nh: Option<Ipv6Addr> = None;
        for chunk in body.chunks_exact(RTE_LEN) {
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&chunk[0..16]);
            let addr = Ipv6Addr::from(octets);
            let tag = u16::from_be_bytes([chunk[16], chunk[17]]);
            let prefix_len = chunk[18];
            let metric = chunk[19];

            if metric == NEXT_HOP_METRIC {
                // A next-hop RTE: `::` resets to "use the originator".
                current_nh = (!addr.is_unspecified()).then_some(addr);
                continue;
            }
            let Ok(prefix) = Prefix::new(IpAddr::V6(addr), prefix_len) else {
                continue; // ignore an out-of-range prefix length
            };
            entries.push(Rte {
                prefix,
                tag,
                next_hop: current_nh,
                metric,
            });
        }
        Ok(Self { command, entries })
    }
}

/// Append one 20-octet RTE.
fn push_rte(buf: &mut Vec<u8>, addr: &Ipv6Addr, tag: u16, prefix_len: u8, metric: u8) {
    buf.extend_from_slice(&addr.octets());
    buf.extend_from_slice(&tag.to_be_bytes());
    buf.push(prefix_len);
    buf.push(metric);
}

impl fmt::Display for Message {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RIPng {:?} ({} entries)", self.command, self.entries.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(s: &str) -> Prefix {
        s.parse().unwrap()
    }

    #[test]
    fn response_round_trips_on_the_wire() {
        let msg = Message::response(vec![
            Rte::route(p("2001:db8::/32"), 1),
            Rte::route(p("fd00:1234::/48"), 5),
        ]);
        let bytes = msg.encode();
        assert_eq!(bytes.len(), HEADER_LEN + 2 * RTE_LEN);
        assert_eq!(&bytes[0..4], &[2, 1, 0, 0]); // response, v1, zero
        let back = Message::decode(&bytes).unwrap();
        assert_eq!(back, msg);
    }

    #[test]
    fn next_hop_rte_is_emitted_and_resolved() {
        let nh: Ipv6Addr = "fe80::1".parse().unwrap();
        let msg = Message::response(vec![Rte {
            prefix: p("2001:db8::/32"),
            tag: 0,
            next_hop: Some(nh),
            metric: 2,
        }]);
        let bytes = msg.encode();
        // A next-hop RTE (metric 0xFF) precedes the one route RTE.
        assert_eq!(bytes.len(), HEADER_LEN + 2 * RTE_LEN);
        assert_eq!(bytes[HEADER_LEN + 19], NEXT_HOP_METRIC);
        let back = Message::decode(&bytes).unwrap();
        assert_eq!(back.entries.len(), 1);
        assert_eq!(back.entries[0].next_hop, Some(nh));
        assert_eq!(back.entries[0].metric, 2);
    }

    #[test]
    fn full_table_request_is_well_formed() {
        let req = Message::request_full_table();
        assert!(req.is_full_table_request());
        let bytes = req.encode();
        assert_eq!(bytes.len(), HEADER_LEN + RTE_LEN);
        assert_eq!(bytes[0], 1); // request
        assert_eq!(bytes[HEADER_LEN + 18], 0); // prefix len 0
        assert_eq!(bytes[HEADER_LEN + 19], METRIC_INFINITY as u8);
        assert!(Message::decode(&bytes).unwrap().is_full_table_request());
    }

    #[test]
    fn from_adverts_skips_ipv4_and_caps_metric() {
        let adverts = vec![
            Advert { prefix: p("2001:db8::/32"), metric: 3 },
            Advert { prefix: p("10.0.0.0/24"), metric: 1 }, // IPv4 → skipped
            Advert { prefix: p("fd00::/8"), metric: 99 },   // capped to 16
        ];
        let msg = Message::from_adverts(&adverts);
        assert_eq!(msg.entries.len(), 2);
        assert_eq!(msg.entries[0].prefix, p("2001:db8::/32"));
        assert_eq!(msg.entries[1].metric, METRIC_INFINITY as u8);
    }

    #[test]
    fn decode_rejects_short_and_misaligned_and_bad_command() {
        assert_eq!(Message::decode(&[2, 1, 0]), Err(RipError::TooShort));
        assert_eq!(Message::decode(&[2, 1, 0, 0, 1, 2, 3]), Err(RipError::BadLength(3)));
        assert_eq!(Message::decode(&[9, 1, 0, 0]), Err(RipError::UnknownCommand(9)));
    }
}
