//! # The PIM-SM packet codec (RFC 7761 §4.9)
//!
//! Encode and decode the PIMv2 messages this sparse-mode subset uses — Hello,
//! Join/Prune, Register and Register-Stop — plus the encoded-address forms (§4.9.1)
//! they carry and the Internet checksum (§4.9). Everything here is IPv4; PIM6 is
//! deferred (see the crate docs).
//!
//! The decoder is defensive: it is fed raw bytes off a `SOCK_RAW` socket, so it
//! validates every length before indexing and returns a [`DecodeError`] rather than
//! panicking on a short or malformed packet. The `decode_never_panics` test sweeps
//! arbitrary input to prove it.

use std::fmt;
use std::net::Ipv4Addr;

use crate::{
    OPT_DR_PRIORITY, OPT_GENERATION_ID, OPT_HOLDTIME, OPT_LAN_PRUNE_DELAY, PIM_VERSION, TYPE_HELLO,
    TYPE_JOIN_PRUNE, TYPE_REGISTER, TYPE_REGISTER_STOP,
};

/// Address Family Number for IPv4 (IANA), the first octet of every encoded address.
const AF_IPV4: u8 = 1;
/// Encoding Type 0 — the native (non-tunnelled) encoding, the second octet.
const ENC_NATIVE: u8 = 0;
/// A full `/32` host mask, the mask length every encoded group/source here uses.
const HOST_MASK: u8 = 32;

/// Encoded-Unicast IPv4 length: Addr-Family + Encoding-Type + 4 address bytes.
const ENC_UNICAST_LEN: usize = 6;
/// Encoded-Group / Encoded-Source IPv4 length: the unicast prefix + a flags octet +
/// a mask-length octet, i.e. 8 bytes.
const ENC_GROUP_LEN: usize = 8;
const ENC_SOURCE_LEN: usize = 8;

/// The fixed 4-byte PIM header (version/type, reserved, 16-bit checksum).
const HEADER_LEN: usize = 4;
/// The number of leading octets a PIM **Register** checksum covers: the 4-octet
/// header plus the 32-bit flags field (RFC 7761 §4.9) — deliberately NOT the
/// encapsulated multicast datagram that follows.
const REGISTER_CSUM_LEN: usize = 8;

/// Source-flags bit (§4.9.5.1): S — the sparse-mode bit, set on every entry here.
const SRC_FLAG_SPARSE: u8 = 0x04;
/// Source-flags bit: W — WildCard, set on the RP entry of a `(*,G)` Join/Prune.
const SRC_FLAG_WILDCARD: u8 = 0x02;
/// Source-flags bit: R — RPT, set on the RP entry of a `(*,G)` Join/Prune.
const SRC_FLAG_RPT: u8 = 0x01;

/// Register-flags bit (§4.9.1): B — the Border bit.
const REG_FLAG_BORDER: u32 = 0x8000_0000;
/// Register-flags bit: N — the Null-Register bit (a probe carrying no data).
const REG_FLAG_NULL: u32 = 0x4000_0000;

/// Why decoding a PIM message off the wire failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecodeError {
    /// The buffer is shorter than the field being read.
    Truncated,
    /// The PIM version nibble was not 2.
    BadVersion(u8),
    /// A message type this subset does not decode (BSR, Assert, Graft, …).
    UnknownType(u8),
    /// The Internet checksum did not verify.
    BadChecksum,
    /// An encoded address used an address family / encoding this subset rejects.
    BadAddress,
    /// A length field (option length, source count) overran the buffer.
    BadLength,
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DecodeError::Truncated => write!(f, "pim message truncated"),
            DecodeError::BadVersion(v) => write!(f, "pim: unsupported version {v}"),
            DecodeError::UnknownType(t) => write!(f, "pim: unhandled message type {t}"),
            DecodeError::BadChecksum => write!(f, "pim: checksum mismatch"),
            DecodeError::BadAddress => write!(f, "pim: unsupported encoded address"),
            DecodeError::BadLength => write!(f, "pim: bad length field"),
        }
    }
}

impl std::error::Error for DecodeError {}

/// Alias kept for the crate's public surface — encoding is infallible, so the only
/// error type callers see is [`DecodeError`].
pub type PimError = DecodeError;

// ===========================================================================
// Encoded addresses (§4.9.1)
// ===========================================================================

/// An Encoded-Unicast IPv4 address (§4.9.1) — the Register-Stop source and the
/// Join/Prune "Upstream Neighbor" field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EncodedUnicast(pub Ipv4Addr);

impl EncodedUnicast {
    fn encode_into(&self, out: &mut Vec<u8>) {
        out.push(AF_IPV4);
        out.push(ENC_NATIVE);
        out.extend_from_slice(&self.0.octets());
    }

    fn decode(buf: &[u8]) -> Result<(EncodedUnicast, usize), DecodeError> {
        if buf.len() < ENC_UNICAST_LEN {
            return Err(DecodeError::Truncated);
        }
        if buf[0] != AF_IPV4 || buf[1] != ENC_NATIVE {
            return Err(DecodeError::BadAddress);
        }
        let addr = Ipv4Addr::new(buf[2], buf[3], buf[4], buf[5]);
        Ok((EncodedUnicast(addr), ENC_UNICAST_LEN))
    }
}

/// An Encoded-Group IPv4 address (§4.9.1). The `bidir`/`admin_scope` flag bits are
/// carried for round-trip fidelity but are always false in this subset.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EncodedGroup {
    /// The multicast group.
    pub group: Ipv4Addr,
    /// The prefix length — `32` for a single group `G`.
    pub mask_len: u8,
    /// The B (bidirectional) flag — always false here.
    pub bidir: bool,
    /// The Z (admin-scope) flag — always false here.
    pub admin_scope: bool,
}

impl EncodedGroup {
    /// A single group `G` (`/32`, no flags).
    pub fn single(group: Ipv4Addr) -> EncodedGroup {
        EncodedGroup {
            group,
            mask_len: HOST_MASK,
            bidir: false,
            admin_scope: false,
        }
    }

    fn encode_into(&self, out: &mut Vec<u8>) {
        out.push(AF_IPV4);
        out.push(ENC_NATIVE);
        let flags = (if self.bidir { 0x80 } else { 0 }) | (if self.admin_scope { 0x01 } else { 0 });
        out.push(flags);
        out.push(self.mask_len);
        out.extend_from_slice(&self.group.octets());
    }

    fn decode(buf: &[u8]) -> Result<(EncodedGroup, usize), DecodeError> {
        if buf.len() < ENC_GROUP_LEN {
            return Err(DecodeError::Truncated);
        }
        if buf[0] != AF_IPV4 || buf[1] != ENC_NATIVE {
            return Err(DecodeError::BadAddress);
        }
        Ok((
            EncodedGroup {
                bidir: buf[2] & 0x80 != 0,
                admin_scope: buf[2] & 0x01 != 0,
                mask_len: buf[3],
                group: Ipv4Addr::new(buf[4], buf[5], buf[6], buf[7]),
            },
            ENC_GROUP_LEN,
        ))
    }
}

/// An Encoded-Source IPv4 address with its S/W/R flags (§4.9.1, §4.9.5.1). In a
/// `(*,G)` Join/Prune the single source entry is the RP with `wildcard`+`rpt` set;
/// in an `(S,G)` Join/Prune it is the source `S` with only `sparse` set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EncodedSource {
    /// The source address — the RP for a `(*,G)` entry, else the source `S`.
    pub source: Ipv4Addr,
    /// The prefix length — `32` for a host source.
    pub mask_len: u8,
    /// S — the sparse-mode bit (always set here).
    pub sparse: bool,
    /// W — the WildCard bit: set on the `(*,G)` RP entry.
    pub wildcard: bool,
    /// R — the RPT bit: set on the `(*,G)` RP entry (join is toward the RP tree).
    pub rpt: bool,
}

impl EncodedSource {
    /// The `(*,G)` RP entry: the RP address with S/W/R all set.
    pub fn wildcard_rp(rp: Ipv4Addr) -> EncodedSource {
        EncodedSource {
            source: rp,
            mask_len: HOST_MASK,
            sparse: true,
            wildcard: true,
            rpt: true,
        }
    }

    /// The `(S,G)` source-tree entry: the source `S` with only S set.
    pub fn source(s: Ipv4Addr) -> EncodedSource {
        EncodedSource {
            source: s,
            mask_len: HOST_MASK,
            sparse: true,
            wildcard: false,
            rpt: false,
        }
    }

    /// Whether this entry is the wildcard `(*,G)` RP entry (W and R set).
    pub fn is_wildcard(&self) -> bool {
        self.wildcard && self.rpt
    }

    fn encode_into(&self, out: &mut Vec<u8>) {
        out.push(AF_IPV4);
        out.push(ENC_NATIVE);
        let mut flags = 0u8;
        if self.sparse {
            flags |= SRC_FLAG_SPARSE;
        }
        if self.wildcard {
            flags |= SRC_FLAG_WILDCARD;
        }
        if self.rpt {
            flags |= SRC_FLAG_RPT;
        }
        out.push(flags);
        out.push(self.mask_len);
        out.extend_from_slice(&self.source.octets());
    }

    fn decode(buf: &[u8]) -> Result<(EncodedSource, usize), DecodeError> {
        if buf.len() < ENC_SOURCE_LEN {
            return Err(DecodeError::Truncated);
        }
        if buf[0] != AF_IPV4 || buf[1] != ENC_NATIVE {
            return Err(DecodeError::BadAddress);
        }
        Ok((
            EncodedSource {
                sparse: buf[2] & SRC_FLAG_SPARSE != 0,
                wildcard: buf[2] & SRC_FLAG_WILDCARD != 0,
                rpt: buf[2] & SRC_FLAG_RPT != 0,
                mask_len: buf[3],
                source: Ipv4Addr::new(buf[4], buf[5], buf[6], buf[7]),
            },
            ENC_SOURCE_LEN,
        ))
    }
}

// ===========================================================================
// Hello options (§4.9.2)
// ===========================================================================

/// One TLV option in a Hello message (§4.9.2). The variants this subset originates
/// and interprets are explicit; anything else round-trips as [`HelloOption::Unknown`]
/// so forwarding an unknown option and re-encoding it is lossless.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HelloOption {
    /// Holdtime in seconds — keep the neighbour this long without a further Hello.
    Holdtime(u16),
    /// DR Priority — higher wins the Designated-Router election on the LAN.
    DrPriority(u32),
    /// Generation ID — a random value that changes when the neighbour restarts.
    GenerationId(u32),
    /// LAN Prune Delay (Propagation_Delay, Override_Interval, T bit) — carried but
    /// not acted on in this subset.
    LanPruneDelay { value: u16, override_interval: u16 },
    /// Any other option type, preserved verbatim.
    Unknown { typ: u16, data: Vec<u8> },
}

impl HelloOption {
    fn encode_into(&self, out: &mut Vec<u8>) {
        let (typ, mut data): (u16, Vec<u8>) = match self {
            HelloOption::Holdtime(h) => (OPT_HOLDTIME, h.to_be_bytes().to_vec()),
            HelloOption::DrPriority(p) => (OPT_DR_PRIORITY, p.to_be_bytes().to_vec()),
            HelloOption::GenerationId(g) => (OPT_GENERATION_ID, g.to_be_bytes().to_vec()),
            HelloOption::LanPruneDelay {
                value,
                override_interval,
            } => {
                let mut v = Vec::with_capacity(4);
                v.extend_from_slice(&value.to_be_bytes());
                v.extend_from_slice(&override_interval.to_be_bytes());
                (OPT_LAN_PRUNE_DELAY, v)
            }
            HelloOption::Unknown { typ, data } => (*typ, data.clone()),
        };
        out.extend_from_slice(&typ.to_be_bytes());
        out.extend_from_slice(&(data.len() as u16).to_be_bytes());
        out.append(&mut data);
    }

    fn decode(typ: u16, data: &[u8]) -> HelloOption {
        match typ {
            OPT_HOLDTIME if data.len() == 2 => {
                HelloOption::Holdtime(u16::from_be_bytes([data[0], data[1]]))
            }
            OPT_DR_PRIORITY if data.len() == 4 => {
                HelloOption::DrPriority(u32::from_be_bytes([data[0], data[1], data[2], data[3]]))
            }
            OPT_GENERATION_ID if data.len() == 4 => {
                HelloOption::GenerationId(u32::from_be_bytes([data[0], data[1], data[2], data[3]]))
            }
            OPT_LAN_PRUNE_DELAY if data.len() == 4 => HelloOption::LanPruneDelay {
                value: u16::from_be_bytes([data[0], data[1]]),
                override_interval: u16::from_be_bytes([data[2], data[3]]),
            },
            _ => HelloOption::Unknown {
                typ,
                data: data.to_vec(),
            },
        }
    }
}

// ===========================================================================
// Join/Prune group entries (§4.9.5)
// ===========================================================================

/// One group block of a Join/Prune message: a group and the sources joined and
/// pruned for it (§4.9.5). A `(*,G)` join is a single joined [`EncodedSource`] with
/// the wildcard bits set; an `(S,G)` join is the source `S`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JpGroup {
    /// The multicast group this block concerns.
    pub group: EncodedGroup,
    /// The sources being joined (added to the OIF list upstream).
    pub joins: Vec<EncodedSource>,
    /// The sources being pruned (removed upstream).
    pub prunes: Vec<EncodedSource>,
}

impl JpGroup {
    fn encode_into(&self, out: &mut Vec<u8>) {
        self.group.encode_into(out);
        out.extend_from_slice(&(self.joins.len() as u16).to_be_bytes());
        out.extend_from_slice(&(self.prunes.len() as u16).to_be_bytes());
        for s in &self.joins {
            s.encode_into(out);
        }
        for s in &self.prunes {
            s.encode_into(out);
        }
    }

    fn decode(buf: &[u8]) -> Result<(JpGroup, usize), DecodeError> {
        let (group, mut off) = EncodedGroup::decode(buf)?;
        if buf.len() < off + 4 {
            return Err(DecodeError::Truncated);
        }
        let njoin = u16::from_be_bytes([buf[off], buf[off + 1]]) as usize;
        let nprune = u16::from_be_bytes([buf[off + 2], buf[off + 3]]) as usize;
        off += 4;
        let mut joins = Vec::with_capacity(njoin.min(64));
        for _ in 0..njoin {
            let (s, used) = EncodedSource::decode(&buf[off..])?;
            off += used;
            joins.push(s);
        }
        let mut prunes = Vec::with_capacity(nprune.min(64));
        for _ in 0..nprune {
            let (s, used) = EncodedSource::decode(&buf[off..])?;
            off += used;
            prunes.push(s);
        }
        Ok((
            JpGroup {
                group,
                joins,
                prunes,
            },
            off,
        ))
    }
}

// ===========================================================================
// The message
// ===========================================================================

/// A decoded (or to-be-encoded) PIMv2 message — the subset this crate speaks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Message {
    /// Hello (§4.9.2) — neighbour discovery/liveness, sent to ALL-PIM-ROUTERS.
    Hello { options: Vec<HelloOption> },
    /// Join/Prune (§4.9.5) — sent to ALL-PIM-ROUTERS on the RPF interface, naming
    /// the upstream neighbour it is addressed to.
    JoinPrune {
        /// The RPF neighbour this Join/Prune is addressed to (only it acts on it).
        upstream: EncodedUnicast,
        /// The Join/Prune Holdtime in seconds (how long the upstream keeps the state).
        holdtime: u16,
        /// The per-group join/prune blocks.
        groups: Vec<JpGroup>,
    },
    /// Register (§4.9.1) — unicast first-hop DR → RP, encapsulating a data packet
    /// (or, when `null`, a header-only probe).
    Register {
        /// B — the Border bit.
        border: bool,
        /// N — the Null-Register bit (probe, no encapsulated data).
        null: bool,
        /// The encapsulated multicast IP datagram (empty for a Null-Register).
        data: Vec<u8>,
    },
    /// Register-Stop (§4.9.4) — unicast RP → first-hop DR, telling it to stop
    /// registering `(source, group)`. A `(*,G)` stop uses an unspecified source.
    RegisterStop {
        /// The group to stop registering.
        group: EncodedGroup,
        /// The source to stop registering (`0.0.0.0` for all sources of the group).
        source: EncodedUnicast,
    },
}

impl Message {
    /// Encode the message with a correct header and Internet checksum, ready to hand
    /// to a raw IP-protocol-103 socket (the kernel adds the IP header).
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(32);
        out.push((PIM_VERSION << 4) | self.type_code());
        out.push(0); // reserved
        out.extend_from_slice(&[0, 0]); // checksum placeholder
        match self {
            Message::Hello { options } => {
                for o in options {
                    o.encode_into(&mut out);
                }
            }
            Message::JoinPrune {
                upstream,
                holdtime,
                groups,
            } => {
                upstream.encode_into(&mut out);
                out.push(0); // reserved
                out.push(groups.len() as u8);
                out.extend_from_slice(&holdtime.to_be_bytes());
                for g in groups {
                    g.encode_into(&mut out);
                }
            }
            Message::Register {
                border,
                null,
                data,
            } => {
                let mut flags = 0u32;
                if *border {
                    flags |= REG_FLAG_BORDER;
                }
                if *null {
                    flags |= REG_FLAG_NULL;
                }
                out.extend_from_slice(&flags.to_be_bytes());
                out.extend_from_slice(data);
            }
            Message::RegisterStop { group, source } => {
                group.encode_into(&mut out);
                source.encode_into(&mut out);
            }
        }
        // RFC 7761 §4.9: a Register's checksum covers only the first 8 octets
        // (header + flags), NOT the encapsulated data; every other message type
        // checksums the whole PIM message.
        let csum_end = if matches!(self, Message::Register { .. }) {
            REGISTER_CSUM_LEN.min(out.len())
        } else {
            out.len()
        };
        let sum = super::wire::checksum(&out[..csum_end]);
        out[2..4].copy_from_slice(&sum.to_be_bytes());
        out
    }

    /// Decode a PIM message from `buf`, verifying the version and checksum first.
    pub fn decode(buf: &[u8]) -> Result<Message, DecodeError> {
        if buf.len() < HEADER_LEN {
            return Err(DecodeError::Truncated);
        }
        let version = buf[0] >> 4;
        if version != PIM_VERSION {
            return Err(DecodeError::BadVersion(version));
        }
        // RFC 7761 §4.9: verify a Register's checksum over only the first 8 octets
        // (header + flags); every other type covers the whole message. A compliant
        // DR/RP computes the header-only Register checksum, so covering the whole
        // buffer here would reject every real Register as BadChecksum.
        let csum_end = if buf[0] & 0x0f == TYPE_REGISTER {
            REGISTER_CSUM_LEN.min(buf.len())
        } else {
            buf.len()
        };
        if checksum(&buf[..csum_end]) != 0 {
            return Err(DecodeError::BadChecksum);
        }
        let body = &buf[HEADER_LEN..];
        match buf[0] & 0x0f {
            TYPE_HELLO => Ok(Message::Hello {
                options: decode_hello_options(body)?,
            }),
            TYPE_JOIN_PRUNE => decode_join_prune(body),
            TYPE_REGISTER => decode_register(body),
            TYPE_REGISTER_STOP => decode_register_stop(body),
            other => Err(DecodeError::UnknownType(other)),
        }
    }

    /// The 4-bit type code for this message.
    fn type_code(&self) -> u8 {
        match self {
            Message::Hello { .. } => TYPE_HELLO,
            Message::JoinPrune { .. } => TYPE_JOIN_PRUNE,
            Message::Register { .. } => TYPE_REGISTER,
            Message::RegisterStop { .. } => TYPE_REGISTER_STOP,
        }
    }
}

/// Decode the TLV option list of a Hello body.
fn decode_hello_options(mut buf: &[u8]) -> Result<Vec<HelloOption>, DecodeError> {
    let mut options = Vec::new();
    while !buf.is_empty() {
        if buf.len() < 4 {
            return Err(DecodeError::Truncated);
        }
        let typ = u16::from_be_bytes([buf[0], buf[1]]);
        let len = u16::from_be_bytes([buf[2], buf[3]]) as usize;
        let end = 4usize.checked_add(len).ok_or(DecodeError::BadLength)?;
        if buf.len() < end {
            return Err(DecodeError::BadLength);
        }
        options.push(HelloOption::decode(typ, &buf[4..end]));
        buf = &buf[end..];
    }
    Ok(options)
}

/// Decode a Join/Prune body (§4.9.5).
fn decode_join_prune(buf: &[u8]) -> Result<Message, DecodeError> {
    let (upstream, mut off) = EncodedUnicast::decode(buf)?;
    if buf.len() < off + 4 {
        return Err(DecodeError::Truncated);
    }
    // buf[off] is reserved.
    let ngroups = buf[off + 1] as usize;
    let holdtime = u16::from_be_bytes([buf[off + 2], buf[off + 3]]);
    off += 4;
    let mut groups = Vec::with_capacity(ngroups.min(64));
    for _ in 0..ngroups {
        let (g, used) = JpGroup::decode(&buf[off..])?;
        off += used;
        groups.push(g);
    }
    Ok(Message::JoinPrune {
        upstream,
        holdtime,
        groups,
    })
}

/// Decode a Register body (§4.9.1): a 4-byte flags word then the encapsulated packet.
fn decode_register(buf: &[u8]) -> Result<Message, DecodeError> {
    if buf.len() < 4 {
        return Err(DecodeError::Truncated);
    }
    let flags = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
    Ok(Message::Register {
        border: flags & REG_FLAG_BORDER != 0,
        null: flags & REG_FLAG_NULL != 0,
        data: buf[4..].to_vec(),
    })
}

/// Decode a Register-Stop body (§4.9.4): an encoded group then an encoded-unicast
/// source.
fn decode_register_stop(buf: &[u8]) -> Result<Message, DecodeError> {
    let (group, off) = EncodedGroup::decode(buf)?;
    let (source, _) = EncodedUnicast::decode(&buf[off..])?;
    Ok(Message::RegisterStop { group, source })
}

// ===========================================================================
// Internet checksum (RFC 1071)
// ===========================================================================

/// The 16-bit one's-complement Internet checksum over `data`. Over a whole valid
/// message (checksum field included) this returns 0. For IPv4 PIM the checksum
/// covers the entire PIM message (§4.9).
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

    #[test]
    fn hello_round_trips() {
        let msg = Message::Hello {
            options: vec![
                HelloOption::Holdtime(105),
                HelloOption::DrPriority(1),
                HelloOption::GenerationId(0xdead_beef),
            ],
        };
        let bytes = msg.encode();
        // Header: version 2, type 0 (Hello).
        assert_eq!(bytes[0], 0x20);
        assert_eq!(checksum(&bytes), 0);
        assert_eq!(Message::decode(&bytes).unwrap(), msg);
    }

    #[test]
    fn hello_preserves_unknown_option() {
        let msg = Message::Hello {
            options: vec![HelloOption::Unknown {
                typ: 65000,
                data: vec![1, 2, 3, 4, 5],
            }],
        };
        let bytes = msg.encode();
        assert_eq!(Message::decode(&bytes).unwrap(), msg);
    }

    #[test]
    fn star_g_join_round_trips() {
        // (*,G) join toward the RP: one joined source entry with W+R set = the RP.
        let msg = Message::JoinPrune {
            upstream: EncodedUnicast(ip("10.0.2.1")),
            holdtime: 210,
            groups: vec![JpGroup {
                group: EncodedGroup::single(ip("239.1.1.1")),
                joins: vec![EncodedSource::wildcard_rp(ip("10.0.9.9"))],
                prunes: vec![],
            }],
        };
        let bytes = msg.encode();
        assert_eq!(bytes[0], 0x23); // version 2, type 3
        assert_eq!(checksum(&bytes), 0);
        let decoded = Message::decode(&bytes).unwrap();
        assert_eq!(decoded, msg);
        // The joined entry is the wildcard RP entry.
        if let Message::JoinPrune { groups, .. } = decoded {
            assert!(groups[0].joins[0].is_wildcard());
        } else {
            panic!("not a join/prune");
        }
    }

    #[test]
    fn s_g_join_and_prune_round_trips() {
        let msg = Message::JoinPrune {
            upstream: EncodedUnicast(ip("10.0.2.1")),
            holdtime: 210,
            groups: vec![JpGroup {
                group: EncodedGroup::single(ip("232.1.1.1")),
                joins: vec![EncodedSource::source(ip("198.51.100.7"))],
                prunes: vec![EncodedSource::source(ip("198.51.100.8"))],
            }],
        };
        let bytes = msg.encode();
        let decoded = Message::decode(&bytes).unwrap();
        assert_eq!(decoded, msg);
        if let Message::JoinPrune { groups, .. } = decoded {
            assert!(!groups[0].joins[0].is_wildcard());
            assert!(groups[0].joins[0].sparse);
            assert_eq!(groups[0].prunes.len(), 1);
        } else {
            panic!("not a join/prune");
        }
    }

    #[test]
    fn multiple_groups_in_one_join_prune() {
        let msg = Message::JoinPrune {
            upstream: EncodedUnicast(ip("10.0.2.1")),
            holdtime: 210,
            groups: vec![
                JpGroup {
                    group: EncodedGroup::single(ip("239.1.0.1")),
                    joins: vec![EncodedSource::wildcard_rp(ip("10.0.9.9"))],
                    prunes: vec![],
                },
                JpGroup {
                    group: EncodedGroup::single(ip("239.1.0.2")),
                    joins: vec![EncodedSource::source(ip("10.1.1.1"))],
                    prunes: vec![],
                },
            ],
        };
        let bytes = msg.encode();
        assert_eq!(Message::decode(&bytes).unwrap(), msg);
    }

    #[test]
    fn register_round_trips() {
        // A Register encapsulating a tiny fake IP packet.
        let payload = vec![0x45, 0x00, 0x00, 0x1c, 0xde, 0xad];
        let msg = Message::Register {
            border: false,
            null: false,
            data: payload.clone(),
        };
        let bytes = msg.encode();
        assert_eq!(bytes[0], 0x21); // version 2, type 1
        // RFC 7761 §4.9: the Register checksum covers only the first 8 octets
        // (header + flags), so *that* prefix sums to zero (not the whole message,
        // which includes the encapsulated data).
        assert_eq!(checksum(&bytes[..8]), 0);
        assert_eq!(Message::decode(&bytes).unwrap(), msg);
    }

    #[test]
    fn null_register_round_trips() {
        let msg = Message::Register {
            border: false,
            null: true,
            data: vec![],
        };
        let bytes = msg.encode();
        let decoded = Message::decode(&bytes).unwrap();
        assert_eq!(decoded, msg);
        if let Message::Register { null, .. } = decoded {
            assert!(null);
        } else {
            panic!("not a register");
        }
    }

    #[test]
    fn register_stop_round_trips() {
        let msg = Message::RegisterStop {
            group: EncodedGroup::single(ip("239.1.1.1")),
            source: EncodedUnicast(ip("198.51.100.7")),
        };
        let bytes = msg.encode();
        assert_eq!(bytes[0], 0x22); // version 2, type 2
        assert_eq!(Message::decode(&bytes).unwrap(), msg);
    }

    #[test]
    fn rejects_bad_version() {
        let mut bytes = Message::Hello { options: vec![] }.encode();
        bytes[0] = 0x10; // version 1
        // Re-fix the checksum so the version check (not the checksum) is what fires.
        bytes[2..4].copy_from_slice(&[0, 0]);
        let sum = checksum(&bytes);
        bytes[2..4].copy_from_slice(&sum.to_be_bytes());
        assert_eq!(Message::decode(&bytes), Err(DecodeError::BadVersion(1)));
    }

    #[test]
    fn rejects_corrupt_checksum() {
        let mut bytes = Message::Hello {
            options: vec![HelloOption::Holdtime(105)],
        }
        .encode();
        let last = bytes.len() - 1;
        bytes[last] ^= 0xff;
        assert_eq!(Message::decode(&bytes), Err(DecodeError::BadChecksum));
    }

    #[test]
    fn rejects_unknown_type() {
        // Type 4 (Bootstrap) is not in this subset.
        let mut bytes = vec![(PIM_VERSION << 4) | 4, 0, 0, 0];
        let sum = checksum(&bytes);
        bytes[2..4].copy_from_slice(&sum.to_be_bytes());
        assert_eq!(Message::decode(&bytes), Err(DecodeError::UnknownType(4)));
    }

    #[test]
    fn decode_never_panics_on_arbitrary_input() {
        // Sweep short and structured-but-hostile inputs; decode must return Err, not
        // panic, on any of them (the codec faces raw socket bytes).
        for len in 0..64usize {
            let buf = vec![0xffu8; len];
            let _ = Message::decode(&buf);
        }
        // Valid header + a truncated Join/Prune / Register / Register-Stop body.
        for typ in [TYPE_JOIN_PRUNE, TYPE_REGISTER, TYPE_REGISTER_STOP, TYPE_HELLO] {
            for len in 0..40usize {
                let mut buf = vec![0u8; 4 + len];
                buf[0] = (PIM_VERSION << 4) | typ;
                let sum = checksum(&buf);
                buf[2..4].copy_from_slice(&sum.to_be_bytes());
                let _ = Message::decode(&buf);
            }
        }
        // A Join/Prune claiming many groups/sources but with no room for them.
        let mut buf = vec![
            (PIM_VERSION << 4) | TYPE_JOIN_PRUNE,
            0,
            0,
            0,
            AF_IPV4,
            ENC_NATIVE,
            10,
            0,
            0,
            1, // upstream 10.0.0.1
            0,
            0xff, // reserved, num-groups = 255
            0,
            210, // holdtime
        ];
        let sum = checksum(&buf);
        buf[2..4].copy_from_slice(&sum.to_be_bytes());
        assert!(Message::decode(&buf).is_err());
    }

    #[test]
    fn encoded_source_flags_pack_correctly() {
        // The (*,G) RP entry sets S(4)|W(2)|R(1) = 7 in the flags octet.
        let mut out = Vec::new();
        EncodedSource::wildcard_rp(ip("10.0.0.1")).encode_into(&mut out);
        assert_eq!(out[2], 0x07);
        // The (S,G) entry sets only S = 4.
        let mut out = Vec::new();
        EncodedSource::source(ip("10.0.0.1")).encode_into(&mut out);
        assert_eq!(out[2], 0x04);
    }
}
