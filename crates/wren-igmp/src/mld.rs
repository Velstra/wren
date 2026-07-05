//! # The MLD wire codec (IPv6 — RFC 3810 / RFC 2710)
//!
//! Multicast Listener Discovery is IGMP's IPv6 twin: same membership semantics,
//! carried in ICMPv6 instead of a bare IP protocol. This module encodes/decodes the
//! MLD *payload* after the IPv6 header (the raw ICMPv6 socket runner in `wren-daemon`
//! deals with the IPv6 layer and, on Linux, the ICMPv6 checksum). Like the IGMP
//! codec every decoder is defensive — it validates lengths before trusting a byte,
//! because a report arrives unauthenticated from any host on the link.
//!
//! Messages handled:
//!
//! | ICMPv6 type | Name | Struct |
//! |-------------|------|--------|
//! | `130` | Multicast Listener Query (v1 24-byte / v2 ≥28-byte) | [`Message::Query`] |
//! | `143` | Version 2 Multicast Listener Report | [`Message::V2Report`] |
//! | `131` | MLDv1 Multicast Listener Report | [`Message::V1Report`] |
//! | `132` | MLDv1 Multicast Listener Done | [`Message::V1Done`] |
//!
//! The membership state machine is shared with IGMP: this module provides the
//! IPv6 translation ([`MembershipTable::apply`] on `MembershipTable<Ipv6Addr>`).
//!
//! ## Checksum
//!
//! The ICMPv6 checksum covers an IPv6 pseudo-header (source, destination, length,
//! next-header 58). For a raw `IPPROTO_ICMPV6` socket the *kernel* computes and
//! inserts it on send and verifies it on receive, so [`Message::encode`] leaves the
//! field zero and [`Message::decode`] does not re-verify. [`checksum`] and
//! [`Message::encode_checksummed`] are provided for tests and completeness.

use std::net::Ipv6Addr;
use std::time::Instant;

use crate::membership::{MembershipEvent, MembershipTable};
use crate::wire::{DecodeError, RecordType};
use crate::{MLD_QUERY, MLD_V1_DONE, MLD_V1_REPORT, MLD_V2_REPORT};

/// The fixed part of an MLDv1 message / MLDv2 query header up to and including the
/// multicast address (type+code+checksum+maxresp+reserved+group = 24 bytes).
const V1_LEN: usize = 24;
/// The fixed part of an MLDv2 query: the 24-byte header + S/QRV/QQIC/N (§5.1).
const V2_QUERY_MIN: usize = 28;
/// The fixed part of an MLDv2 report before the records: type+reserved+checksum+
/// reserved+M = 8 bytes (§5.2).
const V2_REPORT_MIN: usize = 8;
/// The fixed part of a multicast address record before its sources: type+aux-len+
/// N + 16-byte group (§5.2.4).
const RECORD_MIN: usize = 20;

// ===========================================================================
// Multicast address records (RFC 3810 §5.2.4)
// ===========================================================================

/// One Multicast Address Record in an MLDv2 report: the IPv6 twin of
/// [`crate::wire::GroupRecord`]. Reuses the shared [`RecordType`] semantics.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MldRecord {
    /// The record type (an unknown-on-the-wire value is stored as the raw byte).
    pub record_type: u8,
    /// The multicast group this record is about.
    pub multicast: Ipv6Addr,
    /// The source addresses (SSM). Empty for a plain `*,G` join/leave.
    pub sources: Vec<Ipv6Addr>,
    /// Auxiliary data, preserved verbatim (whole 32-bit words).
    pub aux: Vec<u8>,
}

impl MldRecord {
    /// A `*,G` record (no sources, no aux) of the given type.
    pub fn any_source(record_type: RecordType, multicast: Ipv6Addr) -> MldRecord {
        MldRecord {
            record_type: record_type as u8,
            multicast,
            sources: Vec::new(),
            aux: Vec::new(),
        }
    }

    /// This record's typed [`RecordType`], if it is one of the six defined values.
    pub fn typed(&self) -> Option<RecordType> {
        RecordType::from_u8(self.record_type)
    }

    fn encode_into(&self, out: &mut Vec<u8>) {
        debug_assert!(
            self.aux.len() % 4 == 0,
            "aux data must be whole 32-bit words"
        );
        out.push(self.record_type);
        out.push((self.aux.len() / 4) as u8);
        out.extend_from_slice(&(self.sources.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.multicast.octets());
        for s in &self.sources {
            out.extend_from_slice(&s.octets());
        }
        out.extend_from_slice(&self.aux);
    }

    fn decode(buf: &[u8]) -> Result<(MldRecord, usize), DecodeError> {
        if buf.len() < RECORD_MIN {
            return Err(DecodeError::Truncated);
        }
        let record_type = buf[0];
        let aux_words = buf[1] as usize;
        let nsrc = u16::from_be_bytes([buf[2], buf[3]]) as usize;
        let multicast = ipv6_at(buf, 4);
        let aux_len = aux_words * 4;
        let total = RECORD_MIN
            .checked_add(nsrc * 16)
            .and_then(|n| n.checked_add(aux_len))
            .ok_or(DecodeError::BadLength)?;
        if buf.len() < total {
            return Err(DecodeError::BadLength);
        }
        let mut sources = Vec::with_capacity(nsrc);
        let mut off = RECORD_MIN;
        for _ in 0..nsrc {
            sources.push(ipv6_at(buf, off));
            off += 16;
        }
        let aux = buf[off..off + aux_len].to_vec();
        Ok((
            MldRecord {
                record_type,
                multicast,
                sources,
                aux,
            },
            total,
        ))
    }
}

// ===========================================================================
// Query (RFC 3810 §5.1)
// ===========================================================================

/// An MLD Multicast Listener Query. A General Query has `group == ::` and no
/// sources; otherwise it is multicast-address(-and-source)-specific.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MldQuery {
    /// The Maximum Response Code (§5.1.3) — a 16-bit floating-point value in
    /// milliseconds. Use [`MldQuery::max_resp_delay_ms`] for the decoded value.
    pub max_resp_code: u16,
    /// The group being queried; `::` for a General Query.
    pub group: Ipv6Addr,
    /// The S flag — "Suppress Router-Side Processing" (§5.1.7). v1 queries: false.
    pub suppress: bool,
    /// Querier's Robustness Variable (§5.1.8). v1 queries: 0.
    pub qrv: u8,
    /// Querier's Query Interval Code (§5.1.9), floating-point seconds. v1: 0.
    pub qqic: u8,
    /// Source addresses (source-specific query). Empty otherwise.
    pub sources: Vec<Ipv6Addr>,
    /// True if this is an MLDv2 query (carries S/QRV/QQIC/sources); false = MLDv1.
    pub v2: bool,
}

impl MldQuery {
    /// An MLDv2 General Query with the given Max Resp Code, robustness and QQIC.
    pub fn general(max_resp_code: u16, qrv: u8, qqic: u8) -> MldQuery {
        MldQuery {
            max_resp_code,
            group: Ipv6Addr::UNSPECIFIED,
            suppress: false,
            qrv,
            qqic,
            sources: Vec::new(),
            v2: true,
        }
    }

    /// An MLDv2 Multicast-Address-Specific Query for `group`.
    pub fn group_specific(group: Ipv6Addr, max_resp_code: u16, qrv: u8, qqic: u8) -> MldQuery {
        MldQuery {
            max_resp_code,
            group,
            suppress: false,
            qrv,
            qqic,
            sources: Vec::new(),
            v2: true,
        }
    }

    /// The decoded Maximum Response Delay, in milliseconds (§5.1.3).
    pub fn max_resp_delay_ms(&self) -> u32 {
        decode_float16(self.max_resp_code)
    }

    /// True for a General Query (`::`, no sources).
    pub fn is_general(&self) -> bool {
        self.group.is_unspecified() && self.sources.is_empty()
    }
}

// ===========================================================================
// Message
// ===========================================================================

/// A decoded MLD message (the ICMPv6 payload after the IPv6 header).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Message {
    /// Multicast Listener Query (ICMPv6 type 130).
    Query(MldQuery),
    /// Version 2 Multicast Listener Report (type 143) with its records.
    V2Report { records: Vec<MldRecord> },
    /// MLDv1 Multicast Listener Report (type 131) — a bare `*,G` join.
    V1Report(Ipv6Addr),
    /// MLDv1 Multicast Listener Done (type 132) — a bare `*,G` leave.
    V1Done(Ipv6Addr),
}

impl Message {
    /// Encode the message with the ICMPv6 checksum field left zero (the kernel fills
    /// it on a raw `IPPROTO_ICMPV6` socket). Use [`Message::encode_checksummed`] when
    /// a correct checksum is needed without kernel help (e.g. tests).
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(28);
        match self {
            Message::Query(q) => {
                out.push(MLD_QUERY);
                out.push(0); // code
                out.extend_from_slice(&[0, 0]); // checksum placeholder
                out.extend_from_slice(&q.max_resp_code.to_be_bytes());
                out.extend_from_slice(&[0, 0]); // reserved
                out.extend_from_slice(&q.group.octets());
                if q.v2 {
                    let resv_s_qrv = (if q.suppress { 0x08 } else { 0 }) | (q.qrv & 0x07);
                    out.push(resv_s_qrv);
                    out.push(q.qqic);
                    out.extend_from_slice(&(q.sources.len() as u16).to_be_bytes());
                    for s in &q.sources {
                        out.extend_from_slice(&s.octets());
                    }
                }
            }
            Message::V2Report { records } => {
                out.push(MLD_V2_REPORT);
                out.push(0); // reserved
                out.extend_from_slice(&[0, 0]); // checksum placeholder
                out.extend_from_slice(&[0, 0]); // reserved
                out.extend_from_slice(&(records.len() as u16).to_be_bytes());
                for r in records {
                    r.encode_into(&mut out);
                }
            }
            Message::V1Report(g) | Message::V1Done(g) => {
                out.push(match self {
                    Message::V1Report(_) => MLD_V1_REPORT,
                    _ => MLD_V1_DONE,
                });
                out.push(0); // code
                out.extend_from_slice(&[0, 0]); // checksum placeholder
                out.extend_from_slice(&[0, 0]); // max resp delay (0 in report/done)
                out.extend_from_slice(&[0, 0]); // reserved
                out.extend_from_slice(&g.octets());
            }
        }
        out
    }

    /// Encode with a correct ICMPv6 checksum computed over the pseudo-header for
    /// `src`/`dst`. For tests and any path that does not rely on the kernel.
    pub fn encode_checksummed(&self, src: Ipv6Addr, dst: Ipv6Addr) -> Vec<u8> {
        let mut out = self.encode();
        let sum = checksum(src, dst, &out);
        out[2..4].copy_from_slice(&sum.to_be_bytes());
        out
    }

    /// Decode an MLD message from the ICMPv6 payload `buf`. The ICMPv6 checksum is
    /// not re-verified here (the kernel does it on a raw ICMPv6 socket); lengths are.
    pub fn decode(buf: &[u8]) -> Result<Message, DecodeError> {
        if buf.is_empty() {
            return Err(DecodeError::Truncated);
        }
        match buf[0] {
            MLD_QUERY => Ok(Message::Query(decode_query(buf)?)),
            MLD_V2_REPORT => Ok(Message::V2Report {
                records: decode_v2_report(buf)?,
            }),
            MLD_V1_REPORT => Ok(Message::V1Report(decode_v1_group(buf)?)),
            MLD_V1_DONE => Ok(Message::V1Done(decode_v1_group(buf)?)),
            other => Err(DecodeError::UnknownType(other)),
        }
    }
}

fn ipv6_at(buf: &[u8], off: usize) -> Ipv6Addr {
    let mut o = [0u8; 16];
    o.copy_from_slice(&buf[off..off + 16]);
    Ipv6Addr::from(o)
}

fn decode_v1_group(buf: &[u8]) -> Result<Ipv6Addr, DecodeError> {
    if buf.len() < V1_LEN {
        return Err(DecodeError::Truncated);
    }
    Ok(ipv6_at(buf, 8))
}

fn decode_query(buf: &[u8]) -> Result<MldQuery, DecodeError> {
    if buf.len() < V1_LEN {
        return Err(DecodeError::Truncated);
    }
    let max_resp_code = u16::from_be_bytes([buf[4], buf[5]]);
    let group = ipv6_at(buf, 8);
    // An MLDv1 query is 24 bytes; an MLDv2 query carries S/QRV/QQIC/N and sources.
    if buf.len() < V2_QUERY_MIN {
        return Ok(MldQuery {
            max_resp_code,
            group,
            suppress: false,
            qrv: 0,
            qqic: 0,
            sources: Vec::new(),
            v2: false,
        });
    }
    let suppress = buf[24] & 0x08 != 0;
    let qrv = buf[24] & 0x07;
    let qqic = buf[25];
    let nsrc = u16::from_be_bytes([buf[26], buf[27]]) as usize;
    let need = V2_QUERY_MIN
        .checked_add(nsrc * 16)
        .ok_or(DecodeError::BadLength)?;
    if buf.len() < need {
        return Err(DecodeError::BadLength);
    }
    let mut sources = Vec::with_capacity(nsrc);
    let mut off = V2_QUERY_MIN;
    for _ in 0..nsrc {
        sources.push(ipv6_at(buf, off));
        off += 16;
    }
    Ok(MldQuery {
        max_resp_code,
        group,
        suppress,
        qrv,
        qqic,
        sources,
        v2: true,
    })
}

fn decode_v2_report(buf: &[u8]) -> Result<Vec<MldRecord>, DecodeError> {
    if buf.len() < V2_REPORT_MIN {
        return Err(DecodeError::Truncated);
    }
    let m = u16::from_be_bytes([buf[6], buf[7]]) as usize;
    let mut records = Vec::with_capacity(m);
    let mut off = V2_REPORT_MIN;
    for _ in 0..m {
        let (rec, used) = MldRecord::decode(&buf[off..])?;
        off += used;
        records.push(rec);
    }
    Ok(records)
}

// ===========================================================================
// Max-Resp-Code 16-bit floating point (RFC 3810 §5.1.3)
// ===========================================================================

/// Decode a 16-bit code to its value (milliseconds for Max Resp Code). Below 32768
/// the code *is* the value; from 32768 up it is `1 EEE MMMM MMMM MMMM` →
/// `(0x1000 | mant) << (exp + 3)`.
pub fn decode_float16(code: u16) -> u32 {
    if code < 0x8000 {
        code as u32
    } else {
        let mant = (code & 0x0fff) as u32;
        let exp = ((code >> 12) & 0x07) as u32;
        (mant | 0x1000) << (exp + 3)
    }
}

/// Encode a value to its 16-bit code, the inverse of [`decode_float16`]. Values
/// ≤ 32767 encode exactly; larger values use the floating-point form and floor to
/// the representable value below. Beyond the maximum they saturate at `0xFFFF`.
pub fn encode_float16(value: u32) -> u16 {
    if value < 0x8000 {
        return value as u16;
    }
    for exp in 0u32..=7 {
        if (value >> (exp + 3)) <= 0x1fff {
            let mant = ((value >> (exp + 3)) & 0x0fff) as u16; // drop the implicit 0x1000
            return 0x8000 | ((exp as u16) << 12) | mant;
        }
    }
    0xFFFF
}

// ===========================================================================
// ICMPv6 checksum (RFC 4443 §2.3 — with the IPv6 pseudo-header)
// ===========================================================================

/// The ICMPv6 checksum over `payload` for the given source/destination, including
/// the IPv6 pseudo-header (RFC 8200 §8.1: src, dst, upper-layer length, next-header
/// 58). Over a whole valid message (checksum field included) this returns 0.
pub fn checksum(src: Ipv6Addr, dst: Ipv6Addr, payload: &[u8]) -> u16 {
    let mut sum = 0u32;
    let add = |sum: &mut u32, bytes: &[u8]| {
        let mut chunks = bytes.chunks_exact(2);
        for c in &mut chunks {
            *sum += u16::from_be_bytes([c[0], c[1]]) as u32;
        }
        if let [last] = chunks.remainder() {
            *sum += (*last as u32) << 8;
        }
    };
    add(&mut sum, &src.octets());
    add(&mut sum, &dst.octets());
    // Upper-layer packet length (32-bit) then 3 zero bytes and the next header (58).
    sum += payload.len() as u32; // fits in the low 16 bits for any real MLD message
    sum += crate::ICMPV6_PROTO as u32;
    add(&mut sum, payload);
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

// ===========================================================================
// MLD (IPv6) specialisation of the shared membership state machine
// ===========================================================================

impl MembershipTable<Ipv6Addr> {
    /// Apply a received MLD report/done `msg` at time `now`, returning the resulting
    /// membership events. A query yields no events. The IPv4/IGMP twin is
    /// [`MembershipTable::apply`](crate::membership::MembershipTable) on the
    /// `Ipv4Addr` table.
    pub fn apply(&mut self, now: Instant, msg: &Message) -> Vec<MembershipEvent<Ipv6Addr>> {
        match msg {
            Message::V2Report { records } => {
                let mut events = Vec::new();
                for rec in records {
                    if let Some(ev) =
                        self.apply_record(now, rec.multicast, rec.typed(), &rec.sources)
                    {
                        events.push(ev);
                    }
                }
                events
            }
            // An MLDv1 report is a bare any-source join of the group.
            Message::V1Report(g) => self.join_any_source(now, *g).into_iter().collect(),
            // An MLDv1 Done triggers Last-Member-Query fast-leave (§6.4 / §7).
            Message::V1Done(g) => self.leave_group(now, *g).into_iter().collect(),
            Message::Query(_) => Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::membership::{FilterMode, TimerConfig};

    fn ip(s: &str) -> Ipv6Addr {
        s.parse().unwrap()
    }

    // ---- checksum -----------------------------------------------------------

    #[test]
    fn checksum_of_encoded_message_verifies() {
        let src = ip("fe80::1");
        let dst = crate::MLDV2_ALL_ROUTERS;
        let bytes = Message::V1Report(ip("ff15::1234")).encode_checksummed(src, dst);
        assert_eq!(checksum(src, dst, &bytes), 0);
    }

    // ---- float16 codec ------------------------------------------------------

    #[test]
    fn float16_small_values_are_identity() {
        for v in [0u32, 1, 100, 1000, 0x7fff] {
            assert_eq!(encode_float16(v), v as u16);
            assert_eq!(decode_float16(v as u16), v);
        }
    }

    #[test]
    fn float16_32768_round_trips_exactly() {
        // 32768 = 0x1000 << 3 → exp 0, mant 0 → code 0x8000.
        assert_eq!(encode_float16(32_768), 0x8000);
        assert_eq!(decode_float16(0x8000), 32_768);
    }

    #[test]
    fn float16_decode_matches_formula() {
        // 0xFFFF = 1 111 1111_11111111 → (0x1000|0xfff) << (7+3) = 0x1fff << 10.
        assert_eq!(decode_float16(0xFFFF), 0x1fff << 10);
    }

    #[test]
    fn float16_encode_floors_and_saturates() {
        for &v in &[32_768u32, 50_000, 100_000, 0x1fff << 10] {
            assert!(decode_float16(encode_float16(v)) <= v);
        }
        assert_eq!(encode_float16(u32::MAX), 0xFFFF);
    }

    // ---- query --------------------------------------------------------------

    #[test]
    fn general_query_round_trips() {
        let q = MldQuery::general(10_000, 2, 125);
        let bytes = Message::Query(q.clone()).encode();
        assert_eq!(bytes.len(), 28);
        assert_eq!(Message::decode(&bytes), Ok(Message::Query(q)));
    }

    #[test]
    fn source_specific_query_round_trips() {
        let mut q = MldQuery::group_specific(ip("ff15::abcd"), 5000, 2, 100);
        q.sources = vec![ip("2001:db8::1"), ip("2001:db8::2")];
        let bytes = Message::Query(q.clone()).encode();
        assert_eq!(bytes.len(), 28 + 32);
        assert_eq!(Message::decode(&bytes), Ok(Message::Query(q)));
    }

    #[test]
    fn v1_query_is_24_bytes_and_not_v2() {
        let bytes = vec![0u8; V1_LEN];
        let mut b = bytes;
        b[0] = MLD_QUERY;
        match Message::decode(&b).unwrap() {
            Message::Query(q) => {
                assert!(!q.v2);
                assert!(q.is_general());
                assert_eq!(q.qrv, 0);
            }
            other => panic!("expected query, got {other:?}"),
        }
    }

    #[test]
    fn query_decodes_max_resp_delay() {
        let q = MldQuery::general(0x8000, 2, 10); // floating point → 32768 ms
        assert_eq!(q.max_resp_delay_ms(), 32_768);
    }

    // ---- v2 report ----------------------------------------------------------

    #[test]
    fn v2_report_join_star_g_round_trips() {
        let m = Message::V2Report {
            records: vec![MldRecord::any_source(RecordType::ToExclude, ip("ff15::1"))],
        };
        let bytes = m.encode();
        assert_eq!(Message::decode(&bytes), Ok(m));
    }

    #[test]
    fn v2_report_with_sources_round_trips() {
        let m = Message::V2Report {
            records: vec![
                MldRecord {
                    record_type: RecordType::IsInclude as u8,
                    multicast: ip("ff3e::8000:1"),
                    sources: vec![ip("2001:db8::a"), ip("2001:db8::b")],
                    aux: Vec::new(),
                },
                MldRecord::any_source(RecordType::IsExclude, ip("ff15::5")),
            ],
        };
        let bytes = m.encode();
        assert_eq!(Message::decode(&bytes), Ok(m));
    }

    #[test]
    fn v2_report_preserves_aux() {
        let m = Message::V2Report {
            records: vec![MldRecord {
                record_type: RecordType::IsExclude as u8,
                multicast: ip("ff15::7"),
                sources: vec![],
                aux: vec![1, 2, 3, 4],
            }],
        };
        let bytes = m.encode();
        assert_eq!(Message::decode(&bytes), Ok(m));
    }

    #[test]
    fn v1_report_and_done_round_trip() {
        for m in [
            Message::V1Report(ip("ff15::2")),
            Message::V1Done(ip("ff15::3")),
        ] {
            let bytes = m.encode();
            assert_eq!(bytes.len(), V1_LEN);
            assert_eq!(Message::decode(&bytes), Ok(m));
        }
    }

    // ---- hostile input ------------------------------------------------------

    #[test]
    fn empty_and_short_buffers_are_truncated() {
        assert_eq!(Message::decode(&[]), Err(DecodeError::Truncated));
        assert_eq!(
            Message::decode(&[MLD_QUERY, 0, 0]),
            Err(DecodeError::Truncated)
        );
    }

    #[test]
    fn unknown_type_rejected() {
        assert_eq!(
            Message::decode(&[200u8, 0, 0, 0]),
            Err(DecodeError::UnknownType(200))
        );
    }

    #[test]
    fn lying_source_count_in_query_is_rejected() {
        let mut b = vec![0u8; V2_QUERY_MIN];
        b[0] = MLD_QUERY;
        b[26] = 0;
        b[27] = 100; // claims 100 sources, carries none
        assert_eq!(Message::decode(&b), Err(DecodeError::BadLength));
    }

    #[test]
    fn lying_record_count_in_report_is_error() {
        let mut b = vec![0u8; V2_REPORT_MIN];
        b[0] = MLD_V2_REPORT;
        b[6] = 0;
        b[7] = 9; // claims 9 records, carries none
        assert!(matches!(
            Message::decode(&b),
            Err(DecodeError::Truncated | DecodeError::BadLength)
        ));
    }

    #[test]
    fn decode_never_panics_on_arbitrary_input() {
        for len in 0..64usize {
            for seed in 0u8..48 {
                let buf: Vec<u8> = (0..len).map(|i| seed.wrapping_add(i as u8)).collect();
                let _ = Message::decode(&buf);
            }
        }
    }

    // ---- membership integration --------------------------------------------

    #[test]
    fn v1_report_joins_ipv6_group() {
        let mut t: MembershipTable<Ipv6Addr> = MembershipTable::new(TimerConfig::default());
        let ev = t.apply(Instant::now(), &Message::V1Report(ip("ff15::1234")));
        assert_eq!(ev, vec![MembershipEvent::Joined(ip("ff15::1234"))]);
        let m = t.get(ip("ff15::1234")).unwrap();
        assert_eq!(m.mode, FilterMode::Exclude);
    }

    #[test]
    fn link_local_scope_groups_are_ignored() {
        let mut t: MembershipTable<Ipv6Addr> = MembershipTable::new(TimerConfig::default());
        // ff02:: is link-local scope — a control group, never tracked.
        assert!(t
            .apply(Instant::now(), &Message::V1Report(ip("ff02::16")))
            .is_empty());
        assert!(t.is_empty());
        // A global (ff0e::) / site (ff05::) scope group is tracked.
        assert_eq!(
            t.apply(Instant::now(), &Message::V1Report(ip("ff0e::9"))),
            vec![MembershipEvent::Joined(ip("ff0e::9"))]
        );
    }

    #[test]
    fn v2_report_ssm_and_done() {
        let mut t: MembershipTable<Ipv6Addr> = MembershipTable::new(TimerConfig::default());
        let now = Instant::now();
        let report = Message::V2Report {
            records: vec![MldRecord {
                record_type: RecordType::ToInclude as u8,
                multicast: ip("ff3e::1"),
                sources: vec![ip("2001:db8::1")],
                aux: vec![],
            }],
        };
        assert_eq!(
            t.apply(now, &report),
            vec![MembershipEvent::Joined(ip("ff3e::1"))]
        );
        assert_eq!(t.get(ip("ff3e::1")).unwrap().mode, FilterMode::Include);
        // Done triggers fast-leave (Querying), dropped after the last-member window.
        assert_eq!(
            t.apply(now, &Message::V1Done(ip("ff3e::1"))),
            vec![MembershipEvent::Querying(ip("ff3e::1"))]
        );
        assert_eq!(
            t.expire(now + std::time::Duration::from_secs(2)),
            vec![MembershipEvent::Left(ip("ff3e::1"))]
        );
    }
}
