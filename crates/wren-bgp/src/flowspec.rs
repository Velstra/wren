//! BGP FlowSpec (RFC 8955) — the flow-specification NLRI carried under AFI 1 /
//! **SAFI 133**, and the traffic-filtering-action extended communities (§7).
//!
//! A flow specification is an ordered set of **match components** (destination /
//! source prefix, IP protocol, ports, ICMP type/code, TCP flags, packet length,
//! DSCP, fragment). Each numeric component carries a list of `{operator, value}`
//! pairs joined by AND/OR with `<`/`>`/`=` comparisons; the TCP-flags and fragment
//! components use a bitmask operator instead (§4.2.1.1–4.2.1.2). The whole set is
//! length-prefixed (1 octet under 240 bytes, else a 2-octet extended length) and the
//! components MUST appear in increasing type order.
//!
//! The matching traffic actions (rate-limit / discard, marking, …) ride as extended
//! communities on the same UPDATE (§7). This module is the dependency-free codec;
//! it is IPv4 (AFI 1) only.

use std::fmt;

use wren_core::Prefix;

use crate::{decode_prefix, encode_prefix};

/// SAFI for "Dissemination of Flow Specification rules" (RFC 8955 §3.1).
pub const SAFI_FLOWSPEC: u8 = 133;

/// FlowSpec component type codes (RFC 8955 §4.2).
pub mod component_type {
    pub const DEST_PREFIX: u8 = 1;
    pub const SRC_PREFIX: u8 = 2;
    pub const IP_PROTO: u8 = 3;
    pub const PORT: u8 = 4;
    pub const DEST_PORT: u8 = 5;
    pub const SRC_PORT: u8 = 6;
    pub const ICMP_TYPE: u8 = 7;
    pub const ICMP_CODE: u8 = 8;
    pub const TCP_FLAGS: u8 = 9;
    pub const PKT_LEN: u8 = 10;
    pub const DSCP: u8 = 11;
    pub const FRAGMENT: u8 = 12;
}

/// One numeric `{operator, value}` pair (RFC 8955 §4.2.1.1). The operator joins this
/// term to the previous with AND (`and`) or OR, and compares the field with `value`
/// by any combination of less-than / greater-than / equal.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct NumOp {
    /// AND this term with the previous (otherwise OR).
    pub and: bool,
    /// Less-than comparison.
    pub lt: bool,
    /// Greater-than comparison.
    pub gt: bool,
    /// Equal comparison.
    pub eq: bool,
    /// The value compared against.
    pub value: u64,
}

impl NumOp {
    /// An `= value` term (the common case), OR-joined to any previous term.
    pub fn eq(value: u64) -> NumOp {
        NumOp { and: false, lt: false, gt: false, eq: true, value }
    }
}

/// One bitmask `{operator, value}` pair (RFC 8955 §4.2.1.2), used by the TCP-flags
/// and fragment components: the field is masked with `value` and tested for "any bit
/// set" or (with `match_`) "exactly these bits", optionally negated (`not`).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct BitOp {
    /// AND this term with the previous (otherwise OR).
    pub and: bool,
    /// Negate the result of the match.
    pub not: bool,
    /// Match the bits exactly (otherwise "any of these bits set").
    pub match_: bool,
    /// The bitmask.
    pub value: u64,
}

/// A single FlowSpec match component.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Component {
    /// Type 1 — destination prefix.
    DestPrefix(Prefix),
    /// Type 2 — source prefix.
    SrcPrefix(Prefix),
    /// Type 3 — IP protocol.
    IpProto(Vec<NumOp>),
    /// Type 4 — port (source or destination).
    Port(Vec<NumOp>),
    /// Type 5 — destination port.
    DestPort(Vec<NumOp>),
    /// Type 6 — source port.
    SrcPort(Vec<NumOp>),
    /// Type 7 — ICMP type.
    IcmpType(Vec<NumOp>),
    /// Type 8 — ICMP code.
    IcmpCode(Vec<NumOp>),
    /// Type 9 — TCP flags (bitmask).
    TcpFlags(Vec<BitOp>),
    /// Type 10 — packet length.
    PktLen(Vec<NumOp>),
    /// Type 11 — DSCP.
    Dscp(Vec<NumOp>),
    /// Type 12 — fragment (bitmask).
    Fragment(Vec<BitOp>),
}

impl Component {
    /// This component's RFC 8955 type code (also its ordering key).
    pub fn type_code(&self) -> u8 {
        use component_type::*;
        match self {
            Component::DestPrefix(_) => DEST_PREFIX,
            Component::SrcPrefix(_) => SRC_PREFIX,
            Component::IpProto(_) => IP_PROTO,
            Component::Port(_) => PORT,
            Component::DestPort(_) => DEST_PORT,
            Component::SrcPort(_) => SRC_PORT,
            Component::IcmpType(_) => ICMP_TYPE,
            Component::IcmpCode(_) => ICMP_CODE,
            Component::TcpFlags(_) => TCP_FLAGS,
            Component::PktLen(_) => PKT_LEN,
            Component::Dscp(_) => DSCP,
            Component::Fragment(_) => FRAGMENT,
        }
    }
}

/// A flow specification: an ordered set of match components (the FlowSpec NLRI).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct FlowSpec {
    /// The match components. Kept sorted by type code on encode.
    pub components: Vec<Component>,
}

impl FlowSpec {
    /// Encode the whole NLRI: the length prefix (1 or 2 octets, RFC 8955 §4) followed
    /// by the components in increasing type order.
    pub fn encode(&self, out: &mut Vec<u8>) {
        let mut comps = self.components.clone();
        comps.sort_by_key(|c| c.type_code());
        let mut body = Vec::new();
        for c in &comps {
            encode_component(c, &mut body);
        }
        // Length: a single octet when < 240, else 0xf-prefixed 12-bit extended length.
        if body.len() < 240 {
            out.push(body.len() as u8);
        } else {
            let len = body.len() as u16;
            out.push(0xf0 | ((len >> 8) as u8));
            out.push((len & 0xff) as u8);
        }
        out.extend_from_slice(&body);
    }

    /// Decode one FlowSpec NLRI from the front of `buf`, returning it and the number
    /// of bytes consumed.
    pub fn decode(buf: &[u8]) -> Option<(FlowSpec, usize)> {
        let first = *buf.first()?;
        let (len, hdr) = if first & 0xf0 == 0xf0 {
            let lo = *buf.get(1)? as usize;
            ((((first & 0x0f) as usize) << 8) | lo, 2)
        } else {
            (first as usize, 1)
        };
        let body = buf.get(hdr..hdr + len)?;
        let mut components = Vec::new();
        let mut off = 0;
        while off < body.len() {
            let (c, used) = decode_component(&body[off..])?;
            components.push(c);
            off += used;
        }
        Some((FlowSpec { components }, hdr + len))
    }
}

fn encode_component(c: &Component, out: &mut Vec<u8>) {
    out.push(c.type_code());
    match c {
        Component::DestPrefix(p) | Component::SrcPrefix(p) => encode_prefix(out, p),
        Component::IpProto(ops)
        | Component::Port(ops)
        | Component::DestPort(ops)
        | Component::SrcPort(ops)
        | Component::IcmpType(ops)
        | Component::IcmpCode(ops)
        | Component::PktLen(ops)
        | Component::Dscp(ops) => encode_num_ops(ops, out),
        Component::TcpFlags(ops) | Component::Fragment(ops) => encode_bit_ops(ops, out),
    }
}

fn decode_component(buf: &[u8]) -> Option<(Component, usize)> {
    use component_type::*;
    let ty = *buf.first()?;
    let rest = &buf[1..];
    let (comp, used) = match ty {
        DEST_PREFIX => {
            let (p, n) = decode_prefix(rest)?;
            (Component::DestPrefix(p), n)
        }
        SRC_PREFIX => {
            let (p, n) = decode_prefix(rest)?;
            (Component::SrcPrefix(p), n)
        }
        TCP_FLAGS => {
            let (ops, n) = decode_bit_ops(rest)?;
            (Component::TcpFlags(ops), n)
        }
        FRAGMENT => {
            let (ops, n) = decode_bit_ops(rest)?;
            (Component::Fragment(ops), n)
        }
        IP_PROTO | PORT | DEST_PORT | SRC_PORT | ICMP_TYPE | ICMP_CODE | PKT_LEN | DSCP => {
            let (ops, n) = decode_num_ops(rest)?;
            let comp = match ty {
                IP_PROTO => Component::IpProto(ops),
                PORT => Component::Port(ops),
                DEST_PORT => Component::DestPort(ops),
                SRC_PORT => Component::SrcPort(ops),
                ICMP_TYPE => Component::IcmpType(ops),
                ICMP_CODE => Component::IcmpCode(ops),
                PKT_LEN => Component::PktLen(ops),
                _ => Component::Dscp(ops),
            };
            (comp, n)
        }
        _ => return None, // unknown component type
    };
    Some((comp, 1 + used))
}

/// The length encoding bits (0..3 → 1/2/4/8 octets) and octet count for a value.
fn len_for(value: u64) -> (u8, usize) {
    if value <= 0xff {
        (0, 1)
    } else if value <= 0xffff {
        (1, 2)
    } else if value <= 0xffff_ffff {
        (2, 4)
    } else {
        (3, 8)
    }
}

fn push_value(out: &mut Vec<u8>, value: u64, nbytes: usize) {
    let b = value.to_be_bytes();
    out.extend_from_slice(&b[8 - nbytes..]);
}

fn read_value(buf: &[u8], nbytes: usize) -> Option<u64> {
    let bytes = buf.get(..nbytes)?;
    let mut v = 0u64;
    for &b in bytes {
        v = (v << 8) | b as u64;
    }
    Some(v)
}

fn encode_num_ops(ops: &[NumOp], out: &mut Vec<u8>) {
    for (i, op) in ops.iter().enumerate() {
        let (lenbits, nbytes) = len_for(op.value);
        let mut b = lenbits << 4;
        if i == ops.len() - 1 {
            b |= 0x80; // end-of-list
        }
        if op.and {
            b |= 0x40;
        }
        if op.lt {
            b |= 0x04;
        }
        if op.gt {
            b |= 0x02;
        }
        if op.eq {
            b |= 0x01;
        }
        out.push(b);
        push_value(out, op.value, nbytes);
    }
}

fn decode_num_ops(buf: &[u8]) -> Option<(Vec<NumOp>, usize)> {
    let mut ops = Vec::new();
    let mut off = 0;
    loop {
        let b = *buf.get(off)?;
        off += 1;
        let nbytes = 1usize << ((b >> 4) & 0x03);
        let value = read_value(&buf[off..], nbytes)?;
        off += nbytes;
        ops.push(NumOp {
            and: b & 0x40 != 0,
            lt: b & 0x04 != 0,
            gt: b & 0x02 != 0,
            eq: b & 0x01 != 0,
            value,
        });
        if b & 0x80 != 0 {
            break;
        }
    }
    Some((ops, off))
}

fn encode_bit_ops(ops: &[BitOp], out: &mut Vec<u8>) {
    for (i, op) in ops.iter().enumerate() {
        let (lenbits, nbytes) = len_for(op.value);
        let mut b = lenbits << 4;
        if i == ops.len() - 1 {
            b |= 0x80;
        }
        if op.and {
            b |= 0x40;
        }
        if op.not {
            b |= 0x02;
        }
        if op.match_ {
            b |= 0x01;
        }
        out.push(b);
        push_value(out, op.value, nbytes);
    }
}

fn decode_bit_ops(buf: &[u8]) -> Option<(Vec<BitOp>, usize)> {
    let mut ops = Vec::new();
    let mut off = 0;
    loop {
        let b = *buf.get(off)?;
        off += 1;
        let nbytes = 1usize << ((b >> 4) & 0x03);
        let value = read_value(&buf[off..], nbytes)?;
        off += nbytes;
        ops.push(BitOp {
            and: b & 0x40 != 0,
            not: b & 0x02 != 0,
            match_: b & 0x01 != 0,
            value,
        });
        if b & 0x80 != 0 {
            break;
        }
    }
    Some((ops, off))
}

// ---- Traffic-filtering actions (RFC 8955 §7) -------------------------------------

/// A FlowSpec traffic-filtering action, carried as an extended community (§7).
#[derive(Clone, Copy, PartialEq, Debug)]
pub enum Action {
    /// `traffic-rate-bytes` (type 0x8006): rate-limit to this many bytes per second.
    /// A rate of `0.0` means **discard** all matching traffic.
    RateLimit(f32),
    /// `traffic-marking` (type 0x8009): rewrite the DSCP of matching packets.
    Marking(u8),
}

impl Action {
    /// The conventional "drop everything" action: rate-limit to zero.
    pub const DISCARD: Action = Action::RateLimit(0.0);

    /// Encode this action as its 8-octet extended community (RFC 8955 §7).
    pub fn encode(self) -> [u8; 8] {
        let mut ec = [0u8; 8];
        match self {
            Action::RateLimit(rate) => {
                ec[0] = 0x80;
                ec[1] = 0x06;
                // octets 2-3: a 2-octet AS (informational, left zero);
                // octets 4-7: the rate as an IEEE-754 single-precision float.
                ec[4..8].copy_from_slice(&rate.to_be_bytes());
            }
            Action::Marking(dscp) => {
                ec[0] = 0x80;
                ec[1] = 0x09;
                ec[7] = dscp & 0x3f;
            }
        }
        ec
    }

    /// Decode a traffic-filtering action from an extended community, or `None` if it
    /// is not a recognised FlowSpec action.
    pub fn decode(ec: &[u8; 8]) -> Option<Action> {
        match (ec[0], ec[1]) {
            (0x80, 0x06) => {
                let rate = f32::from_be_bytes([ec[4], ec[5], ec[6], ec[7]]);
                Some(Action::RateLimit(rate))
            }
            (0x80, 0x09) => Some(Action::Marking(ec[7] & 0x3f)),
            _ => None,
        }
    }
}

impl fmt::Display for Action {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Action::RateLimit(r) if *r == 0.0 => write!(f, "discard"),
            Action::RateLimit(r) => write!(f, "rate-limit {r} bytes/s"),
            Action::Marking(d) => write!(f, "mark dscp {d}"),
        }
    }
}

// ---- Display ---------------------------------------------------------------------

fn fmt_num_ops(ops: &[NumOp]) -> String {
    let mut s = String::new();
    for (i, op) in ops.iter().enumerate() {
        if i > 0 {
            s.push_str(if op.and { "&" } else { "|" });
        }
        if op.lt {
            s.push('<');
        }
        if op.gt {
            s.push('>');
        }
        if op.eq {
            s.push('=');
        }
        s.push_str(&op.value.to_string());
    }
    s
}

fn fmt_bit_ops(ops: &[BitOp]) -> String {
    let mut s = String::new();
    for (i, op) in ops.iter().enumerate() {
        if i > 0 {
            s.push_str(if op.and { "&" } else { "|" });
        }
        if op.not {
            s.push('!');
        }
        if op.match_ {
            s.push('=');
        }
        s.push_str(&format!("0x{:x}", op.value));
    }
    s
}

impl fmt::Display for FlowSpec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut comps = self.components.clone();
        comps.sort_by_key(|c| c.type_code());
        let mut parts = Vec::new();
        for c in &comps {
            let p = match c {
                Component::DestPrefix(p) => format!("dst {p}"),
                Component::SrcPrefix(p) => format!("src {p}"),
                Component::IpProto(o) => format!("proto {}", fmt_num_ops(o)),
                Component::Port(o) => format!("port {}", fmt_num_ops(o)),
                Component::DestPort(o) => format!("dport {}", fmt_num_ops(o)),
                Component::SrcPort(o) => format!("sport {}", fmt_num_ops(o)),
                Component::IcmpType(o) => format!("icmp-type {}", fmt_num_ops(o)),
                Component::IcmpCode(o) => format!("icmp-code {}", fmt_num_ops(o)),
                Component::TcpFlags(o) => format!("tcp-flags {}", fmt_bit_ops(o)),
                Component::PktLen(o) => format!("len {}", fmt_num_ops(o)),
                Component::Dscp(o) => format!("dscp {}", fmt_num_ops(o)),
                Component::Fragment(o) => format!("fragment {}", fmt_bit_ops(o)),
            };
            parts.push(p);
        }
        write!(f, "{}", parts.join(" "))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    fn v4(a: [u8; 4], len: u8) -> Prefix {
        Prefix::new(IpAddr::V4(a.into()), len).expect("valid prefix")
    }

    #[test]
    fn nlri_roundtrips_prefix_proto_and_port() {
        let fs = FlowSpec {
            components: vec![
                Component::DestPrefix(v4([10, 5, 5, 0], 24)),
                Component::IpProto(vec![NumOp::eq(6)]), // TCP
                Component::DestPort(vec![NumOp::eq(80)]),
            ],
        };
        let mut buf = Vec::new();
        fs.encode(&mut buf);
        let (back, used) = FlowSpec::decode(&buf).expect("decode");
        assert_eq!(used, buf.len());
        assert_eq!(back, fs);
        assert_eq!(back.to_string(), "dst 10.5.5.0/24 proto =6 dport =80");
    }

    #[test]
    fn components_are_sorted_by_type_on_encode() {
        // Supplied out of order; the wire must be type-ordered.
        let fs = FlowSpec {
            components: vec![
                Component::DestPort(vec![NumOp::eq(443)]),
                Component::DestPrefix(v4([192, 0, 2, 0], 24)),
            ],
        };
        let mut buf = Vec::new();
        fs.encode(&mut buf);
        // First component on the wire is type 1 (dest prefix).
        assert_eq!(buf[1], component_type::DEST_PREFIX);
    }

    #[test]
    fn numeric_op_range_roundtrips() {
        // dport >= 1024 AND <= 2048 : two AND-joined terms.
        let ops = vec![
            NumOp { and: false, lt: false, gt: true, eq: true, value: 1024 },
            NumOp { and: true, lt: true, gt: false, eq: true, value: 2048 },
        ];
        let fs = FlowSpec { components: vec![Component::DestPort(ops.clone())] };
        let mut buf = Vec::new();
        fs.encode(&mut buf);
        let (back, _) = FlowSpec::decode(&buf).unwrap();
        assert_eq!(back.components, vec![Component::DestPort(ops)]);
        assert_eq!(back.to_string(), "dport >=1024&<=2048");
    }

    #[test]
    fn tcp_flags_bitmask_roundtrips() {
        // SYN (0x02) set.
        let fs = FlowSpec {
            components: vec![Component::TcpFlags(vec![BitOp {
                and: false,
                not: false,
                match_: false,
                value: 0x02,
            }])],
        };
        let mut buf = Vec::new();
        fs.encode(&mut buf);
        let (back, _) = FlowSpec::decode(&buf).unwrap();
        assert_eq!(back, fs);
    }

    #[test]
    fn two_octet_value_uses_two_byte_length() {
        let fs = FlowSpec { components: vec![Component::DestPort(vec![NumOp::eq(8080)])] };
        let mut buf = Vec::new();
        fs.encode(&mut buf);
        // body: type(1) + op(1) + value(2) = 4 ; length prefix 1 ; total 5
        assert_eq!(buf.len(), 5);
        let (back, _) = FlowSpec::decode(&buf).unwrap();
        assert_eq!(back, fs);
    }

    #[test]
    fn rate_limit_action_roundtrips_and_zero_is_discard() {
        let ec = Action::DISCARD.encode();
        assert_eq!(ec[0], 0x80);
        assert_eq!(ec[1], 0x06);
        assert_eq!(Action::decode(&ec), Some(Action::RateLimit(0.0)));
        assert_eq!(Action::DISCARD.to_string(), "discard");

        let rl = Action::RateLimit(1000.0);
        assert_eq!(Action::decode(&rl.encode()), Some(rl));
    }

    #[test]
    fn marking_action_roundtrips() {
        let m = Action::Marking(46); // EF
        let ec = m.encode();
        assert_eq!((ec[0], ec[1]), (0x80, 0x09));
        assert_eq!(Action::decode(&ec), Some(m));
        assert_eq!(m.to_string(), "mark dscp 46");
    }

    #[test]
    fn decode_rejects_unknown_action() {
        assert_eq!(Action::decode(&[0x00, 0x02, 0, 0, 0, 0, 0, 1]), None);
    }
}
