//! # The IGMP wire codec (RFC 3376 §4)
//!
//! Encode/decode of the on-wire IGMP messages — the *payload* after the IPv4
//! header (the raw-socket runner in `wren-daemon` deals with the IP layer). Every
//! decoder is defensive: it validates lengths and the Internet checksum before
//! trusting a byte, because this is the crate's attack surface (a report arrives
//! unauthenticated from any host on the LAN).
//!
//! Messages handled:
//!
//! | Type | Name | Struct |
//! |------|------|--------|
//! | `0x11` | Membership Query (v2 8-byte / v3 ≥12-byte) | [`Message::Query`] |
//! | `0x22` | Version 3 Membership Report | [`Message::V3Report`] |
//! | `0x16` | Version 2 Membership Report | [`Message::V2Report`] |
//! | `0x12` | Version 1 Membership Report | [`Message::V1Report`] |
//! | `0x17` | Version 2 Leave Group | [`Message::V2Leave`] |

use std::fmt;
use std::net::Ipv4Addr;

use crate::{TYPE_QUERY, TYPE_V1_REPORT, TYPE_V2_LEAVE, TYPE_V2_REPORT, TYPE_V3_REPORT};

/// The minimum IGMP message length: type + code + 2-byte checksum + 4-byte group,
/// which is the fixed part of a v2 query/report/leave (§4).
const MIN_LEN: usize = 8;
/// The fixed part of an IGMPv3 query: the 8-byte v2 header + S/QRV/QQIC/N (§4.1).
const V3_QUERY_MIN: usize = 12;
/// The fixed part of an IGMPv3 report before the group records: type + reserved +
/// checksum + reserved + M (§4.2).
const V3_REPORT_MIN: usize = 8;
/// The fixed part of a group record before its sources: type + aux-len + N +
/// 4-byte group (§4.2.4).
const RECORD_MIN: usize = 8;

// ===========================================================================
// Errors
// ===========================================================================

/// Why a buffer failed to decode. Hand-rolled (no `thiserror`) to keep the crate
/// dependency-free.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodeError {
    /// The buffer is shorter than the message it claims to be.
    Truncated,
    /// The Internet checksum did not verify.
    BadChecksum,
    /// The type byte is not an IGMP message this codec knows.
    UnknownType(u8),
    /// A length field (source count / aux-data words) overruns the buffer.
    BadLength,
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DecodeError::Truncated => write!(f, "igmp message truncated"),
            DecodeError::BadChecksum => write!(f, "igmp checksum mismatch"),
            DecodeError::UnknownType(t) => write!(f, "unknown igmp type {t:#04x}"),
            DecodeError::BadLength => write!(f, "igmp length field overruns buffer"),
        }
    }
}

impl std::error::Error for DecodeError {}

// ===========================================================================
// Group records (RFC 3376 §4.2.4)
// ===========================================================================

/// The record types carried in a Version 3 Membership Report (§4.2.12). The
/// numeric value is the on-wire Record Type byte.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum RecordType {
    /// `MODE_IS_INCLUDE` — the interface has an INCLUDE filter for the listed sources.
    IsInclude = 1,
    /// `MODE_IS_EXCLUDE` — EXCLUDE filter; an empty source list means "all sources".
    IsExclude = 2,
    /// `CHANGE_TO_INCLUDE_MODE` — filter changed to INCLUDE the listed sources.
    ToInclude = 3,
    /// `CHANGE_TO_EXCLUDE_MODE` — filter changed to EXCLUDE the listed sources.
    ToExclude = 4,
    /// `ALLOW_NEW_SOURCES` — additional sources the interface now wants.
    AllowNew = 5,
    /// `BLOCK_OLD_SOURCES` — sources the interface no longer wants.
    BlockOld = 6,
}

impl RecordType {
    /// Parse a Record Type byte; `None` for a value outside 1..=6.
    pub fn from_u8(v: u8) -> Option<RecordType> {
        Some(match v {
            1 => RecordType::IsInclude,
            2 => RecordType::IsExclude,
            3 => RecordType::ToInclude,
            4 => RecordType::ToExclude,
            5 => RecordType::AllowNew,
            6 => RecordType::BlockOld,
            _ => return None,
        })
    }
}

/// One Group Record in a v3 report: a multicast group, its record type, and the
/// associated source list (§4.2.4). Auxiliary data (§4.2.10) is preserved verbatim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupRecord {
    /// The record type (an unknown-on-the-wire value is stored as the raw byte).
    pub record_type: u8,
    /// The multicast group this record is about.
    pub multicast: Ipv4Addr,
    /// The source addresses (SSM). Empty for a plain `*,G` join/leave.
    pub sources: Vec<Ipv4Addr>,
    /// Auxiliary data — RFC 3376 defines none, but it is length-delimited so we
    /// carry it through. Always a multiple of 4 bytes (whole 32-bit words).
    pub aux: Vec<u8>,
}

impl GroupRecord {
    /// A `*,G` record (no sources, no aux) of the given type.
    pub fn any_source(record_type: RecordType, multicast: Ipv4Addr) -> GroupRecord {
        GroupRecord {
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

    /// Decode one record from `buf`, returning it and the number of bytes consumed.
    fn decode(buf: &[u8]) -> Result<(GroupRecord, usize), DecodeError> {
        if buf.len() < RECORD_MIN {
            return Err(DecodeError::Truncated);
        }
        let record_type = buf[0];
        let aux_words = buf[1] as usize;
        let nsrc = u16::from_be_bytes([buf[2], buf[3]]) as usize;
        let multicast = Ipv4Addr::new(buf[4], buf[5], buf[6], buf[7]);
        let aux_len = aux_words * 4;
        let total = RECORD_MIN
            .checked_add(nsrc * 4)
            .and_then(|n| n.checked_add(aux_len))
            .ok_or(DecodeError::BadLength)?;
        if buf.len() < total {
            return Err(DecodeError::BadLength);
        }
        let mut sources = Vec::with_capacity(nsrc);
        let mut off = RECORD_MIN;
        for _ in 0..nsrc {
            sources.push(Ipv4Addr::new(
                buf[off],
                buf[off + 1],
                buf[off + 2],
                buf[off + 3],
            ));
            off += 4;
        }
        let aux = buf[off..off + aux_len].to_vec();
        Ok((
            GroupRecord {
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
// Query (RFC 3376 §4.1)
// ===========================================================================

/// An IGMP Membership Query. A General Query has `group == 0.0.0.0` and no
/// sources; a Group-Specific Query names the group; a Group-and-Source-Specific
/// Query also lists sources (§4.1.9-4.1.11).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Query {
    /// The Max Resp Code byte (§4.1.1) — floating-point 1/10-second units. Use
    /// [`Query::max_resp_time_ds`] for the decoded value.
    pub max_resp_code: u8,
    /// The group being queried; `0.0.0.0` for a General Query.
    pub group: Ipv4Addr,
    /// The S flag — "Suppress Router-Side Processing" (§4.1.5). v2 queries: false.
    pub suppress: bool,
    /// Querier's Robustness Variable (§4.1.6). v2 queries: 0 (absent).
    pub qrv: u8,
    /// Querier's Query Interval Code (§4.1.7), floating-point seconds. v2: 0.
    pub qqic: u8,
    /// Source addresses (Group-and-Source-Specific Query). Empty otherwise.
    pub sources: Vec<Ipv4Addr>,
    /// True if this was decoded as (or should encode as) an IGMPv3 query. A v2
    /// query is the 8-byte short form with no S/QRV/QQIC/sources.
    pub v3: bool,
}

impl Query {
    /// A v3 General Query with the given Max Resp Code, robustness and QQIC.
    pub fn general(max_resp_code: u8, qrv: u8, qqic: u8) -> Query {
        Query {
            max_resp_code,
            group: Ipv4Addr::UNSPECIFIED,
            suppress: false,
            qrv,
            qqic,
            sources: Vec::new(),
            v3: true,
        }
    }

    /// A v3 Group-Specific Query for `group`.
    pub fn group_specific(group: Ipv4Addr, max_resp_code: u8, qrv: u8, qqic: u8) -> Query {
        Query {
            max_resp_code,
            group,
            suppress: false,
            qrv,
            qqic,
            sources: Vec::new(),
            v3: true,
        }
    }

    /// The decoded Max Response Time, in 1/10-second units (§4.1.1).
    pub fn max_resp_time_ds(&self) -> u32 {
        decode_float(self.max_resp_code)
    }

    /// The decoded Querier's Query Interval, in seconds (§4.1.7).
    pub fn qqi_secs(&self) -> u32 {
        decode_float(self.qqic)
    }

    /// True for a General Query (`0.0.0.0`, no sources).
    pub fn is_general(&self) -> bool {
        self.group.is_unspecified() && self.sources.is_empty()
    }
}

// ===========================================================================
// Message
// ===========================================================================

/// A decoded IGMP message (the payload after the IPv4 header).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Message {
    /// Membership Query (`0x11`).
    Query(Query),
    /// Version 3 Membership Report (`0x22`) with its group records.
    V3Report { records: Vec<GroupRecord> },
    /// Version 2 Membership Report (`0x16`) — a bare `*,G` join.
    V2Report(Ipv4Addr),
    /// Version 1 Membership Report (`0x12`) — a bare `*,G` join.
    V1Report(Ipv4Addr),
    /// Version 2 Leave Group (`0x17`).
    V2Leave(Ipv4Addr),
}

impl Message {
    /// Encode the message (including a correct Internet checksum) into a fresh
    /// buffer ready to hand to a raw IGMP socket.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(16);
        match self {
            Message::Query(q) => {
                out.push(TYPE_QUERY);
                out.push(q.max_resp_code);
                out.extend_from_slice(&[0, 0]); // checksum placeholder
                out.extend_from_slice(&q.group.octets());
                if q.v3 {
                    let resv_s_qrv = (if q.suppress { 0x08 } else { 0 }) | (q.qrv & 0x07);
                    out.push(resv_s_qrv);
                    out.push(q.qqic);
                    out.extend_from_slice(&(q.sources.len() as u16).to_be_bytes());
                    for s in &q.sources {
                        out.extend_from_slice(&s.octets());
                    }
                }
            }
            Message::V3Report { records } => {
                out.push(TYPE_V3_REPORT);
                out.push(0); // reserved
                out.extend_from_slice(&[0, 0]); // checksum placeholder
                out.extend_from_slice(&[0, 0]); // reserved
                out.extend_from_slice(&(records.len() as u16).to_be_bytes());
                for r in records {
                    r.encode_into(&mut out);
                }
            }
            Message::V2Report(g) | Message::V1Report(g) | Message::V2Leave(g) => {
                out.push(match self {
                    Message::V2Report(_) => TYPE_V2_REPORT,
                    Message::V1Report(_) => TYPE_V1_REPORT,
                    _ => TYPE_V2_LEAVE,
                });
                out.push(0); // max resp code (0 in reports/leaves)
                out.extend_from_slice(&[0, 0]); // checksum placeholder
                out.extend_from_slice(&g.octets());
            }
        }
        let sum = checksum(&out);
        out[2..4].copy_from_slice(&sum.to_be_bytes());
        out
    }

    /// Decode an IGMP message from `buf`, verifying the checksum first.
    pub fn decode(buf: &[u8]) -> Result<Message, DecodeError> {
        if buf.len() < MIN_LEN {
            return Err(DecodeError::Truncated);
        }
        if checksum(buf) != 0 {
            return Err(DecodeError::BadChecksum);
        }
        match buf[0] {
            TYPE_QUERY => Ok(Message::Query(decode_query(buf)?)),
            TYPE_V3_REPORT => Ok(Message::V3Report {
                records: decode_v3_report(buf)?,
            }),
            TYPE_V2_REPORT => Ok(Message::V2Report(group_field(buf))),
            TYPE_V1_REPORT => Ok(Message::V1Report(group_field(buf))),
            TYPE_V2_LEAVE => Ok(Message::V2Leave(group_field(buf))),
            other => Err(DecodeError::UnknownType(other)),
        }
    }
}

/// The 4-byte group address at offset 4 of a v1/v2 message.
fn group_field(buf: &[u8]) -> Ipv4Addr {
    Ipv4Addr::new(buf[4], buf[5], buf[6], buf[7])
}

fn decode_query(buf: &[u8]) -> Result<Query, DecodeError> {
    let max_resp_code = buf[1];
    let group = group_field(buf);
    // A v2 query is exactly 8 bytes; a v3 query carries S/QRV/QQIC/N and sources.
    if buf.len() < V3_QUERY_MIN {
        return Ok(Query {
            max_resp_code,
            group,
            suppress: false,
            qrv: 0,
            qqic: 0,
            sources: Vec::new(),
            v3: false,
        });
    }
    let suppress = buf[8] & 0x08 != 0;
    let qrv = buf[8] & 0x07;
    let qqic = buf[9];
    let nsrc = u16::from_be_bytes([buf[10], buf[11]]) as usize;
    let need = V3_QUERY_MIN
        .checked_add(nsrc * 4)
        .ok_or(DecodeError::BadLength)?;
    if buf.len() < need {
        return Err(DecodeError::BadLength);
    }
    let mut sources = Vec::with_capacity(nsrc);
    let mut off = V3_QUERY_MIN;
    for _ in 0..nsrc {
        sources.push(Ipv4Addr::new(
            buf[off],
            buf[off + 1],
            buf[off + 2],
            buf[off + 3],
        ));
        off += 4;
    }
    Ok(Query {
        max_resp_code,
        group,
        suppress,
        qrv,
        qqic,
        sources,
        v3: true,
    })
}

fn decode_v3_report(buf: &[u8]) -> Result<Vec<GroupRecord>, DecodeError> {
    if buf.len() < V3_REPORT_MIN {
        return Err(DecodeError::Truncated);
    }
    let m = u16::from_be_bytes([buf[6], buf[7]]) as usize;
    // Never size the allocation from the wire count alone: each group record is at
    // least 8 bytes (type + aux-len + num-sources + group address), so the body can
    // hold at most this many. Otherwise a crafted count (up to 65535) drives a
    // multi-MB pre-allocation from an 8-byte packet.
    let mut records = Vec::with_capacity(m.min(buf.len().saturating_sub(V3_REPORT_MIN) / 8));
    let mut off = V3_REPORT_MIN;
    for _ in 0..m {
        let (rec, used) = GroupRecord::decode(&buf[off..])?;
        off += used;
        records.push(rec);
    }
    Ok(records)
}

// ===========================================================================
// Max-Resp-Code / QQIC floating point (RFC 3376 §4.1.1)
// ===========================================================================

/// Decode a code byte to its value. Below 128 the code *is* the value; from 128 up
/// it is the floating-point form `1 EEE MMMM` → `(0x10 | mant) << (exp + 3)`. The
/// unit (1/10 s for Max Resp Code, seconds for QQIC) is the caller's to interpret.
pub fn decode_float(code: u8) -> u32 {
    if code < 128 {
        code as u32
    } else {
        let mant = (code & 0x0f) as u32;
        let exp = ((code >> 4) & 0x07) as u32;
        (mant | 0x10) << (exp + 3)
    }
}

/// Encode a value to its code byte, the inverse of [`decode_float`]. Values ≤ 127
/// encode exactly; larger values use the floating-point form and lose the low bits
/// (the encoding's granularity), so `decode_float(encode_float(v)) <= v` for those.
/// Values beyond the representable maximum saturate at `0xFF`.
pub fn encode_float(value: u32) -> u8 {
    if value < 128 {
        return value as u8;
    }
    // Pick the smallest exponent whose 5-bit mantissa (`0x10..=0x1f`) can hold the
    // shifted value; the `& 0x0f` then floors it to the representable value below.
    for exp in 0u32..=7 {
        if (value >> (exp + 3)) <= 0x1f {
            let mant = ((value >> (exp + 3)) & 0x0f) as u8; // drop the implicit 0x10 bit
            return 0x80 | ((exp as u8) << 4) | mant;
        }
    }
    0xFF
}

// ===========================================================================
// Internet checksum (RFC 1071)
// ===========================================================================

/// The 16-bit one's-complement Internet checksum over `data`. Over a whole valid
/// message (checksum field included) this returns 0.
pub fn checksum(data: &[u8]) -> u16 {
    let mut sum = 0u32;
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

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> Ipv4Addr {
        s.parse().unwrap()
    }

    // ---- checksum -----------------------------------------------------------

    #[test]
    fn checksum_of_encoded_message_verifies() {
        let m = Message::Query(Query::general(100, 2, 125));
        let bytes = m.encode();
        // Over the full message (checksum embedded) the checksum is 0.
        assert_eq!(checksum(&bytes), 0);
    }

    #[test]
    fn corrupt_byte_fails_checksum() {
        let mut bytes = Message::V2Report(ip("239.1.2.3")).encode();
        bytes[5] ^= 0xff;
        assert_eq!(Message::decode(&bytes), Err(DecodeError::BadChecksum));
    }

    // ---- float codec --------------------------------------------------------

    #[test]
    fn float_small_values_are_identity() {
        for v in 0u32..128 {
            assert_eq!(encode_float(v), v as u8);
            assert_eq!(decode_float(v as u8), v);
        }
    }

    #[test]
    fn float_128_round_trips_exactly() {
        // 128 = (0x10) << 3, i.e. exp=0 mant=0 → code 0x80.
        assert_eq!(encode_float(128), 0x80);
        assert_eq!(decode_float(0x80), 128);
    }

    #[test]
    fn float_decode_matches_formula() {
        // code 0xFF = 1 111 1111 → (0x10|0xf) << (7+3) = 0x1f << 10 = 31744.
        assert_eq!(decode_float(0xFF), 31_744);
    }

    #[test]
    fn float_encode_never_exceeds_value_and_round_trips_representable() {
        for &v in &[128u32, 200, 255, 1000, 4000, 12500, 31_744] {
            let code = encode_float(v);
            let back = decode_float(code);
            assert!(back <= v, "encode({v}) decoded to {back} which is > {v}");
        }
        // A value at an exact band boundary is exact.
        assert_eq!(decode_float(encode_float(31_744)), 31_744);
    }

    #[test]
    fn float_saturates() {
        assert_eq!(encode_float(u32::MAX), 0xFF);
    }

    // ---- query --------------------------------------------------------------

    #[test]
    fn general_query_round_trips() {
        let q = Query::general(100, 2, 125);
        let bytes = Message::Query(q.clone()).encode();
        assert_eq!(bytes.len(), 12);
        assert_eq!(Message::decode(&bytes), Ok(Message::Query(q)));
    }

    #[test]
    fn group_source_query_round_trips() {
        let mut q = Query::group_specific(ip("239.9.9.9"), 50, 2, 100);
        q.sources = vec![ip("10.0.0.1"), ip("10.0.0.2")];
        let bytes = Message::Query(q.clone()).encode();
        assert_eq!(bytes.len(), 12 + 8);
        assert_eq!(Message::decode(&bytes), Ok(Message::Query(q)));
    }

    #[test]
    fn v2_query_is_eight_bytes_and_decodes_as_not_v3() {
        // Hand-build a v2 query: type, max-resp, checksum, group.
        let mut bytes = vec![TYPE_QUERY, 100, 0, 0, 0, 0, 0, 0];
        let sum = checksum(&bytes);
        bytes[2..4].copy_from_slice(&sum.to_be_bytes());
        match Message::decode(&bytes).unwrap() {
            Message::Query(q) => {
                assert!(!q.v3);
                assert!(q.is_general());
                assert_eq!(q.qrv, 0);
            }
            other => panic!("expected query, got {other:?}"),
        }
    }

    #[test]
    fn query_decodes_max_resp_and_qqi() {
        let q = Query::general(0x80, 2, 0x80); // both floating point → 128
        assert_eq!(q.max_resp_time_ds(), 128);
        assert_eq!(q.qqi_secs(), 128);
    }

    // ---- v3 report ----------------------------------------------------------

    #[test]
    fn v3_report_join_star_g_round_trips() {
        let m = Message::V3Report {
            records: vec![GroupRecord::any_source(
                RecordType::ToExclude,
                ip("239.1.1.1"),
            )],
        };
        let bytes = m.encode();
        assert_eq!(Message::decode(&bytes), Ok(m));
    }

    #[test]
    fn v3_report_with_sources_round_trips() {
        let m = Message::V3Report {
            records: vec![
                GroupRecord {
                    record_type: RecordType::IsInclude as u8,
                    multicast: ip("232.1.2.3"),
                    sources: vec![ip("198.51.100.1"), ip("198.51.100.2")],
                    aux: Vec::new(),
                },
                GroupRecord::any_source(RecordType::IsExclude, ip("239.5.5.5")),
            ],
        };
        let bytes = m.encode();
        assert_eq!(Message::decode(&bytes), Ok(m));
    }

    #[test]
    fn v3_report_preserves_aux_data() {
        let m = Message::V3Report {
            records: vec![GroupRecord {
                record_type: RecordType::IsExclude as u8,
                multicast: ip("239.7.7.7"),
                sources: vec![],
                aux: vec![0xde, 0xad, 0xbe, 0xef],
            }],
        };
        let bytes = m.encode();
        assert_eq!(Message::decode(&bytes), Ok(m));
    }

    // ---- v1/v2 --------------------------------------------------------------

    #[test]
    fn v2_report_and_leave_round_trip() {
        for m in [
            Message::V2Report(ip("239.2.2.2")),
            Message::V1Report(ip("239.3.3.3")),
            Message::V2Leave(ip("239.4.4.4")),
        ] {
            let bytes = m.encode();
            assert_eq!(bytes.len(), 8);
            assert_eq!(Message::decode(&bytes), Ok(m));
        }
    }

    // ---- hostile input ------------------------------------------------------

    #[test]
    fn empty_and_short_buffers_are_truncated() {
        assert_eq!(Message::decode(&[]), Err(DecodeError::Truncated));
        assert_eq!(Message::decode(&[0x11, 0, 0]), Err(DecodeError::Truncated));
    }

    #[test]
    fn unknown_type_rejected() {
        let mut bytes = vec![0x99, 0, 0, 0, 0, 0, 0, 0];
        let sum = checksum(&bytes);
        bytes[2..4].copy_from_slice(&sum.to_be_bytes());
        assert_eq!(Message::decode(&bytes), Err(DecodeError::UnknownType(0x99)));
    }

    #[test]
    fn lying_source_count_in_query_is_rejected() {
        // v3 query claiming 100 sources but carrying none.
        let mut bytes = vec![TYPE_QUERY, 100, 0, 0, 0, 0, 0, 0, 0x02, 125, 0, 100];
        let sum = checksum(&bytes);
        bytes[2..4].copy_from_slice(&sum.to_be_bytes());
        assert_eq!(Message::decode(&bytes), Err(DecodeError::BadLength));
    }

    #[test]
    fn lying_record_count_in_report_is_truncated() {
        // v3 report header claiming 5 records but carrying none.
        let mut bytes = vec![TYPE_V3_REPORT, 0, 0, 0, 0, 0, 0, 5];
        let sum = checksum(&bytes);
        bytes[2..4].copy_from_slice(&sum.to_be_bytes());
        assert!(matches!(
            Message::decode(&bytes),
            Err(DecodeError::Truncated | DecodeError::BadLength)
        ));
    }

    #[test]
    fn lying_source_count_in_record_is_bad_length() {
        // v3 report, 1 record, record claims 200 sources but carries none.
        let mut bytes = vec![TYPE_V3_REPORT, 0, 0, 0, 0, 0, 0, 1];
        bytes.extend_from_slice(&[RecordType::IsExclude as u8, 0, 0, 200, 239, 1, 1, 1]);
        let sum = checksum(&bytes);
        bytes[2..4].copy_from_slice(&sum.to_be_bytes());
        assert_eq!(Message::decode(&bytes), Err(DecodeError::BadLength));
    }

    #[test]
    fn decode_never_panics_on_arbitrary_input() {
        // Walk a range of byte patterns of every length up to a record; the decoder
        // must always terminate with Ok or a typed error, never panic/overflow.
        for len in 0..40usize {
            for seed in 0u8..64 {
                let buf: Vec<u8> = (0..len).map(|i| seed.wrapping_add(i as u8)).collect();
                let _ = Message::decode(&buf);
            }
        }
    }
}
