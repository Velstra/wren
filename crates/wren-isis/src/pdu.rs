//! IS-IS PDUs — the common header (ISO/IEC 10589 §9.5) and the nine PDU types:
//! the LAN and point-to-point Hellos (IIH), the Level-1/Level-2 Link State PDUs
//! (LSP), and the Complete and Partial Sequence Number PDUs (CSNP/PSNP).
//!
//! Every PDU starts with the same 8-byte common header (discriminator, lengths,
//! version, Maximum Area Addresses, PDU type) and continues with a small set of
//! type-specific fixed fields and then a stream of [`Tlv`](crate::tlv::Tlv)s. The
//! `PDU Length` field (total length) is filled in on encode, and an LSP's ISO 8473
//! Fletcher checksum is computed over its body — so a built LSP is ready to send
//! and a decoded one is checksum-verified.

use crate::tlv::{self, Tlv};
use crate::{
    fletcher16, fletcher16_valid, IsLevel, LspId, SystemId, INTRADOMAIN_DISCRIMINATOR,
    PROTOCOL_ID_EXTENSION, SYSTEM_ID_LEN, VERSION,
};

/// The serialized size of the common header shared by every PDU.
pub const COMMON_HEADER_LEN: usize = 8;

/// The nine IS-IS PDU types (ISO 10589 §9.5, the low 5 bits of the type octet).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PduType {
    /// Level-1 LAN IS-to-IS Hello (15).
    L1LanHello,
    /// Level-2 LAN IS-to-IS Hello (16).
    L2LanHello,
    /// Point-to-Point IS-to-IS Hello (17).
    P2pHello,
    /// Level-1 Link State PDU (18).
    L1Lsp,
    /// Level-2 Link State PDU (20).
    L2Lsp,
    /// Level-1 Complete Sequence Numbers PDU (24).
    L1Csnp,
    /// Level-2 Complete Sequence Numbers PDU (25).
    L2Csnp,
    /// Level-1 Partial Sequence Numbers PDU (26).
    L1Psnp,
    /// Level-2 Partial Sequence Numbers PDU (27).
    L2Psnp,
}

impl PduType {
    /// Decode the 5-bit PDU type code.
    pub fn from_u8(v: u8) -> Option<PduType> {
        Some(match v {
            15 => PduType::L1LanHello,
            16 => PduType::L2LanHello,
            17 => PduType::P2pHello,
            18 => PduType::L1Lsp,
            20 => PduType::L2Lsp,
            24 => PduType::L1Csnp,
            25 => PduType::L2Csnp,
            26 => PduType::L1Psnp,
            27 => PduType::L2Psnp,
            _ => return None,
        })
    }

    /// The on-wire 5-bit PDU type code.
    pub fn as_u8(self) -> u8 {
        match self {
            PduType::L1LanHello => 15,
            PduType::L2LanHello => 16,
            PduType::P2pHello => 17,
            PduType::L1Lsp => 18,
            PduType::L2Lsp => 20,
            PduType::L1Csnp => 24,
            PduType::L2Csnp => 25,
            PduType::L1Psnp => 26,
            PduType::L2Psnp => 27,
        }
    }

    /// The length of the fixed header (common + type-specific) for this PDU type —
    /// where its TLVs begin.
    pub fn fixed_header_len(self) -> usize {
        match self {
            PduType::L1LanHello | PduType::L2LanHello => 27,
            PduType::P2pHello => 20,
            PduType::L1Lsp | PduType::L2Lsp => 27,
            PduType::L1Csnp | PduType::L2Csnp => 33,
            PduType::L1Psnp | PduType::L2Psnp => 17,
        }
    }
}

/// A LAN Hello (IIH) body (ISO 10589 §9.5) — type 15 (L1) or 16 (L2).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct LanHello {
    /// Which level this Hello is (L1 → type 15, L2 → type 16).
    pub level: IsLevel,
    /// The level(s) the originator runs on this circuit (the Circuit Type field).
    pub circuit_type: IsLevel,
    /// The originator's System ID.
    pub source_id: SystemId,
    /// The Holding Time — declare the neighbour down after this many seconds.
    pub holding_time: u16,
    /// The originator's DIS-election priority (7 bits; higher wins).
    pub priority: u8,
    /// The LAN ID: the current Designated IS's System ID and its pseudonode number.
    pub lan_id: (SystemId, u8),
    /// The Hello's TLVs (Area Addresses, Protocols Supported, IS Neighbours, …).
    pub tlvs: Vec<Tlv>,
}

/// A point-to-point Hello (IIH) body (ISO 10589 §9.7) — type 17.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct P2pHello {
    /// The level(s) the originator runs on this circuit.
    pub circuit_type: IsLevel,
    /// The originator's System ID.
    pub source_id: SystemId,
    /// The Holding Time in seconds.
    pub holding_time: u16,
    /// The originator's Local Circuit ID for this link.
    pub local_circuit_id: u8,
    /// The Hello's TLVs.
    pub tlvs: Vec<Tlv>,
}

/// A Link State PDU body (ISO 10589 §9.8) — type 18 (L1) or 20 (L2). The checksum
/// is computed by [`Pdu::encode`] and verified by [`Pdu::decode`].
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Lsp {
    /// Which level this LSP belongs to (L1 → type 18, L2 → type 20).
    pub level: IsLevel,
    /// Remaining lifetime in seconds; 0 flushes the LSP from the database.
    pub remaining_lifetime: u16,
    /// The LSP's identifier.
    pub lsp_id: LspId,
    /// The LSP's sequence number (higher is newer).
    pub sequence_number: u32,
    /// The Fletcher checksum (filled on encode, verified on decode).
    pub checksum: u16,
    /// The Partition Repair bit.
    pub partition: bool,
    /// The 4-bit ATT (attached) metric flags — set by an L1L2 router to draw a
    /// default route towards the backbone.
    pub attached: u8,
    /// The LSP Database Overload bit.
    pub overload: bool,
    /// The originator's IS type (the low two bits of the flags byte).
    pub is_type: IsLevel,
    /// The LSP's TLVs (the reachability and capability advertisements).
    pub tlvs: Vec<Tlv>,
}

/// A Complete Sequence Numbers PDU body (ISO 10589 §9.10) — type 24 (L1) or 25
/// (L2). Describes the sender's whole database over an LSP-ID range, as LSP
/// Entries TLVs.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Csnp {
    /// Which level this CSNP belongs to.
    pub level: IsLevel,
    /// The sender's System ID and a trailing octet (the circuit id, usually 0).
    pub source_id: (SystemId, u8),
    /// The first LSP ID the range covers.
    pub start_lsp_id: LspId,
    /// The last LSP ID the range covers.
    pub end_lsp_id: LspId,
    /// The TLVs — the LSP Entries describing the sender's database.
    pub tlvs: Vec<Tlv>,
}

/// A Partial Sequence Numbers PDU body (ISO 10589 §9.11) — type 26 (L1) or 27
/// (L2). Acknowledges or requests specific LSPs, as LSP Entries TLVs.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Psnp {
    /// Which level this PSNP belongs to.
    pub level: IsLevel,
    /// The sender's System ID and a trailing octet (the circuit id, usually 0).
    pub source_id: (SystemId, u8),
    /// The TLVs — the LSP Entries being acknowledged or requested.
    pub tlvs: Vec<Tlv>,
}

/// A complete IS-IS PDU: its Maximum Area Addresses setting and its typed body.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum PduBody {
    /// A LAN Hello.
    LanHello(LanHello),
    /// A point-to-point Hello.
    P2pHello(P2pHello),
    /// A Link State PDU.
    Lsp(Lsp),
    /// A Complete Sequence Numbers PDU.
    Csnp(Csnp),
    /// A Partial Sequence Numbers PDU.
    Psnp(Psnp),
}

/// A decoded IS-IS PDU.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Pdu {
    /// The Maximum Area Addresses field (0 on the wire means the default of 3).
    pub max_area_addresses: u8,
    /// The typed body.
    pub body: PduBody,
}

/// Why an IS-IS PDU could not be decoded.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum DecodeError {
    /// Fewer bytes than the header (or a field) requires.
    TooShort,
    /// The first byte was not the IS-IS routeing protocol discriminator.
    BadDiscriminator(u8),
    /// The Version/Protocol-ID-Extension or Version byte was wrong.
    BadVersion(u8),
    /// An unsupported ID Length (only the default 6-byte System ID is supported).
    BadIdLength(u8),
    /// The PDU type code was outside the nine known values.
    UnknownType(u8),
    /// The stated PDU Length disagreed with the buffer.
    BadLength { stated: usize, actual: usize },
    /// An LSP's Fletcher checksum did not verify.
    BadChecksum,
    /// The TLV stream was malformed.
    BadTlv,
}

impl std::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DecodeError::TooShort => write!(f, "PDU shorter than required"),
            DecodeError::BadDiscriminator(d) => {
                write!(f, "not an IS-IS PDU (discriminator {d:#x})")
            }
            DecodeError::BadVersion(v) => write!(f, "unsupported version byte {v}"),
            DecodeError::BadIdLength(l) => write!(f, "unsupported ID length {l}"),
            DecodeError::UnknownType(t) => write!(f, "unknown PDU type {t}"),
            DecodeError::BadLength { stated, actual } => {
                write!(f, "stated length {stated} != actual {actual}")
            }
            DecodeError::BadChecksum => write!(f, "LSP checksum mismatch"),
            DecodeError::BadTlv => write!(f, "malformed TLV stream"),
        }
    }
}

impl std::error::Error for DecodeError {}

impl Pdu {
    /// The PDU type of this PDU.
    pub fn pdu_type(&self) -> PduType {
        match &self.body {
            PduBody::LanHello(h) => {
                if h.level.has_l2() && !h.level.has_l1() {
                    PduType::L2LanHello
                } else {
                    PduType::L1LanHello
                }
            }
            PduBody::P2pHello(_) => PduType::P2pHello,
            PduBody::Lsp(l) => level_type(l.level, PduType::L1Lsp, PduType::L2Lsp),
            PduBody::Csnp(c) => level_type(c.level, PduType::L1Csnp, PduType::L2Csnp),
            PduBody::Psnp(p) => level_type(p.level, PduType::L1Psnp, PduType::L2Psnp),
        }
    }

    /// Serialize the PDU, filling in the PDU Length field and (for an LSP) the
    /// Fletcher checksum.
    pub fn encode(&self) -> Vec<u8> {
        let pt = self.pdu_type();
        let mut out = Vec::with_capacity(pt.fixed_header_len() + 32);
        // Common header.
        out.push(INTRADOMAIN_DISCRIMINATOR);
        out.push(pt.fixed_header_len() as u8);
        out.push(PROTOCOL_ID_EXTENSION);
        out.push(0); // ID Length 0 = the default 6-byte System ID
        out.push(pt.as_u8());
        out.push(VERSION);
        out.push(0); // reserved
        out.push(self.max_area_addresses);

        // PDU-specific fixed fields; `len_off` marks the 2-byte PDU Length field.
        let len_off;
        match &self.body {
            PduBody::LanHello(h) => {
                out.push(h.circuit_type.bits());
                out.extend_from_slice(&h.source_id.0);
                out.extend_from_slice(&h.holding_time.to_be_bytes());
                len_off = out.len();
                out.extend_from_slice(&[0, 0]); // PDU length, patched below
                out.push(h.priority & 0x7f);
                out.extend_from_slice(&h.lan_id.0 .0);
                out.push(h.lan_id.1);
                tlv::encode_all(&h.tlvs, &mut out);
            }
            PduBody::P2pHello(h) => {
                out.push(h.circuit_type.bits());
                out.extend_from_slice(&h.source_id.0);
                out.extend_from_slice(&h.holding_time.to_be_bytes());
                len_off = out.len();
                out.extend_from_slice(&[0, 0]);
                out.push(h.local_circuit_id);
                tlv::encode_all(&h.tlvs, &mut out);
            }
            PduBody::Lsp(l) => {
                len_off = out.len();
                out.extend_from_slice(&[0, 0]); // PDU length
                out.extend_from_slice(&l.remaining_lifetime.to_be_bytes());
                l.lsp_id.encode(&mut out);
                out.extend_from_slice(&l.sequence_number.to_be_bytes());
                out.extend_from_slice(&[0, 0]); // checksum, patched below
                out.push(lsp_flags(l));
                tlv::encode_all(&l.tlvs, &mut out);
            }
            PduBody::Csnp(c) => {
                len_off = out.len();
                out.extend_from_slice(&[0, 0]);
                out.extend_from_slice(&c.source_id.0 .0);
                out.push(c.source_id.1);
                c.start_lsp_id.encode(&mut out);
                c.end_lsp_id.encode(&mut out);
                tlv::encode_all(&c.tlvs, &mut out);
            }
            PduBody::Psnp(p) => {
                len_off = out.len();
                out.extend_from_slice(&[0, 0]);
                out.extend_from_slice(&p.source_id.0 .0);
                out.push(p.source_id.1);
                tlv::encode_all(&p.tlvs, &mut out);
            }
        }

        let total = out.len() as u16;
        out[len_off..len_off + 2].copy_from_slice(&total.to_be_bytes());
        // An LSP's checksum covers the bytes from the LSP ID field to the end.
        if matches!(self.body, PduBody::Lsp(_)) {
            let region_start = COMMON_HEADER_LEN + 2 + 2; // common + PDU len + lifetime
            fletcher16(&mut out[region_start..], 12);
        }
        out
    }

    /// Parse and validate an IS-IS PDU from `buf`.
    pub fn decode(buf: &[u8]) -> Result<Pdu, DecodeError> {
        if buf.len() < COMMON_HEADER_LEN {
            return Err(DecodeError::TooShort);
        }
        if buf[0] != INTRADOMAIN_DISCRIMINATOR {
            return Err(DecodeError::BadDiscriminator(buf[0]));
        }
        if buf[2] != PROTOCOL_ID_EXTENSION {
            return Err(DecodeError::BadVersion(buf[2]));
        }
        if buf[3] != 0 && buf[3] as usize != SYSTEM_ID_LEN {
            return Err(DecodeError::BadIdLength(buf[3]));
        }
        let pt = PduType::from_u8(buf[4] & 0x1f).ok_or(DecodeError::UnknownType(buf[4] & 0x1f))?;
        if buf[5] != VERSION {
            return Err(DecodeError::BadVersion(buf[5]));
        }
        let max_area_addresses = buf[7];
        let fixed = pt.fixed_header_len();
        if buf.len() < fixed {
            return Err(DecodeError::TooShort);
        }

        // The PDU Length field bounds the PDU; the TLVs run from `fixed` to there.
        let len_off = match pt {
            PduType::L1LanHello | PduType::L2LanHello | PduType::P2pHello => 17,
            _ => COMMON_HEADER_LEN,
        };
        let stated = u16::from_be_bytes([buf[len_off], buf[len_off + 1]]) as usize;
        if stated < fixed || stated > buf.len() {
            return Err(DecodeError::BadLength {
                stated,
                actual: buf.len(),
            });
        }
        let tlv_bytes = &buf[fixed..stated];
        let tlvs = tlv::decode_all(tlv_bytes).ok_or(DecodeError::BadTlv)?;

        let body = match pt {
            PduType::L1LanHello | PduType::L2LanHello => {
                let level = if pt == PduType::L1LanHello {
                    IsLevel::L1
                } else {
                    IsLevel::L2
                };
                PduBody::LanHello(LanHello {
                    level,
                    circuit_type: IsLevel::from_bits(buf[8]),
                    source_id: sys_id(&buf[9..15]),
                    holding_time: u16::from_be_bytes([buf[15], buf[16]]),
                    priority: buf[19] & 0x7f,
                    lan_id: (sys_id(&buf[20..26]), buf[26]),
                    tlvs,
                })
            }
            PduType::P2pHello => PduBody::P2pHello(P2pHello {
                circuit_type: IsLevel::from_bits(buf[8]),
                source_id: sys_id(&buf[9..15]),
                holding_time: u16::from_be_bytes([buf[15], buf[16]]),
                local_circuit_id: buf[19],
                tlvs,
            }),
            PduType::L1Lsp | PduType::L2Lsp => {
                let remaining_lifetime = u16::from_be_bytes([buf[10], buf[11]]);
                // A purge (Remaining Lifetime 0) is flooded with a zeroed body and
                // checksum to withdraw an LSP from the domain (ISO 10589 §7.3.16.4),
                // so its checksum must NOT be verified — real routers (FRR, IOS)
                // zero the checksum field on a purge. Verifying it unconditionally
                // rejected every standard neighbour's purge as BadChecksum, leaving
                // the dead LSP in the database indefinitely (a domain-wide blackhole).
                if remaining_lifetime != 0 && !fletcher16_valid(&buf[12..stated]) {
                    return Err(DecodeError::BadChecksum);
                }
                let level = if pt == PduType::L1Lsp {
                    IsLevel::L1
                } else {
                    IsLevel::L2
                };
                let flags = buf[26];
                PduBody::Lsp(Lsp {
                    level,
                    remaining_lifetime,
                    lsp_id: LspId::decode(&buf[12..20]).ok_or(DecodeError::TooShort)?,
                    sequence_number: u32::from_be_bytes([buf[20], buf[21], buf[22], buf[23]]),
                    checksum: u16::from_be_bytes([buf[24], buf[25]]),
                    partition: flags & 0x80 != 0,
                    attached: (flags >> 3) & 0x0f,
                    overload: flags & 0x04 != 0,
                    is_type: IsLevel::is_type_from_bits(flags),
                    tlvs,
                })
            }
            PduType::L1Csnp | PduType::L2Csnp => {
                let level = if pt == PduType::L1Csnp {
                    IsLevel::L1
                } else {
                    IsLevel::L2
                };
                PduBody::Csnp(Csnp {
                    level,
                    source_id: (sys_id(&buf[10..16]), buf[16]),
                    start_lsp_id: LspId::decode(&buf[17..25]).ok_or(DecodeError::TooShort)?,
                    end_lsp_id: LspId::decode(&buf[25..33]).ok_or(DecodeError::TooShort)?,
                    tlvs,
                })
            }
            PduType::L1Psnp | PduType::L2Psnp => {
                let level = if pt == PduType::L1Psnp {
                    IsLevel::L1
                } else {
                    IsLevel::L2
                };
                PduBody::Psnp(Psnp {
                    level,
                    source_id: (sys_id(&buf[10..16]), buf[16]),
                    tlvs,
                })
            }
        };
        Ok(Pdu {
            max_area_addresses,
            body,
        })
    }
}

/// Map a level (L1/L2) to one of two PDU types; L1L2 (invalid for a levelled PDU)
/// falls back to the L1 code.
fn level_type(level: IsLevel, l1: PduType, l2: PduType) -> PduType {
    if level.has_l2() && !level.has_l1() {
        l2
    } else {
        l1
    }
}

/// Assemble the LSP flags byte (P / ATT / OL / IS-type).
fn lsp_flags(l: &Lsp) -> u8 {
    let mut b = 0u8;
    if l.partition {
        b |= 0x80;
    }
    b |= (l.attached & 0x0f) << 3;
    if l.overload {
        b |= 0x04;
    }
    b |= l.is_type.is_type_bits();
    b
}

/// Read a 6-byte System ID from `b` (which must be at least 6 bytes).
fn sys_id(b: &[u8]) -> SystemId {
    let mut s = [0u8; SYSTEM_ID_LEN];
    s.copy_from_slice(&b[..SYSTEM_ID_LEN]);
    SystemId(s)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tlv::{ExtIpReach, Tlv};
    use crate::{AreaAddress, NLPID_IPV4};
    use std::net::Ipv4Addr;

    fn sid(o: [u8; 6]) -> SystemId {
        SystemId::new(o)
    }

    fn sample_tlvs() -> Vec<Tlv> {
        vec![
            Tlv::AreaAddresses(vec![AreaAddress(vec![0x49, 0, 1])]),
            Tlv::ProtocolsSupported(vec![NLPID_IPV4]),
        ]
    }

    fn roundtrip(pdu: &Pdu) -> Pdu {
        let bytes = pdu.encode();
        assert_eq!(bytes[0], INTRADOMAIN_DISCRIMINATOR);
        let decoded = Pdu::decode(&bytes).expect("decodes");
        // An LSP's checksum is filled in by encode, so the input (built with a zero
        // placeholder) only matches once that computed value is carried across.
        let mut expected = pdu.clone();
        if let (PduBody::Lsp(e), PduBody::Lsp(d)) = (&mut expected.body, &decoded.body) {
            e.checksum = d.checksum;
        }
        assert_eq!(decoded, expected);
        decoded
    }

    #[test]
    fn lan_hello_l1_and_l2_roundtrip() {
        for (level, pt) in [
            (IsLevel::L1, PduType::L1LanHello),
            (IsLevel::L2, PduType::L2LanHello),
        ] {
            let pdu = Pdu {
                max_area_addresses: 0,
                body: PduBody::LanHello(LanHello {
                    level,
                    circuit_type: IsLevel::L1L2,
                    source_id: sid([1, 1, 1, 1, 1, 1]),
                    holding_time: 30,
                    priority: 64,
                    lan_id: (sid([1, 1, 1, 1, 1, 1]), 1),
                    tlvs: sample_tlvs(),
                }),
            };
            assert_eq!(pdu.pdu_type(), pt);
            roundtrip(&pdu);
        }
    }

    #[test]
    fn p2p_hello_roundtrips() {
        let pdu = Pdu {
            max_area_addresses: 3,
            body: PduBody::P2pHello(P2pHello {
                circuit_type: IsLevel::L1L2,
                source_id: sid([2, 2, 2, 2, 2, 2]),
                holding_time: 27,
                local_circuit_id: 1,
                tlvs: sample_tlvs(),
            }),
        };
        assert_eq!(pdu.pdu_type(), PduType::P2pHello);
        roundtrip(&pdu);
    }

    #[test]
    fn lsp_roundtrips_and_checksum_verifies() {
        let pdu = Pdu {
            max_area_addresses: 0,
            body: PduBody::Lsp(Lsp {
                level: IsLevel::L2,
                remaining_lifetime: 1199,
                lsp_id: LspId::new(sid([1, 1, 1, 1, 1, 1]), 0, 0),
                sequence_number: 0x10,
                checksum: 0,
                partition: false,
                attached: 0,
                overload: false,
                // A Level-2 LSP's IS Type is L2 (§9.8 value 3). L1L2 is not a
                // value this field has, so it cannot round-trip through it.
                is_type: IsLevel::L2,
                tlvs: vec![Tlv::ExtendedIpReachability(vec![ExtIpReach {
                    metric: 10,
                    up_down: false,
                    prefix_len: 24,
                    prefix: Ipv4Addr::new(192, 168, 1, 0),
                    sub_tlvs: None,
                }])],
            }),
        };
        let decoded = roundtrip(&pdu);
        // The checksum field is filled on encode and survives the round-trip.
        if let PduBody::Lsp(l) = &decoded.body {
            assert_ne!(l.checksum, 0);
        } else {
            panic!("not an LSP");
        }
    }

    #[test]
    fn corrupt_lsp_checksum_is_rejected() {
        let pdu = Pdu {
            max_area_addresses: 0,
            body: PduBody::Lsp(Lsp {
                level: IsLevel::L1,
                remaining_lifetime: 1000,
                lsp_id: LspId::new(sid([3, 3, 3, 3, 3, 3]), 0, 0),
                sequence_number: 1,
                checksum: 0,
                partition: false,
                attached: 0,
                overload: false,
                is_type: IsLevel::L1,
                tlvs: sample_tlvs(),
            }),
        };
        let mut bytes = pdu.encode();
        let last = bytes.len() - 1;
        bytes[last] ^= 0xff;
        assert_eq!(Pdu::decode(&bytes), Err(DecodeError::BadChecksum));
    }

    #[test]
    fn purge_lsp_zero_lifetime_skips_checksum() {
        // A purge (Remaining Lifetime 0) withdraws an LSP and is flooded with a
        // zeroed checksum (ISO 10589 §7.3.16.4) — FRR/IOS do this. It must decode
        // without a checksum error, or every neighbour's purge is dropped and the
        // dead LSP lingers in the database forever (a domain-wide blackhole).
        let pdu = Pdu {
            max_area_addresses: 0,
            body: PduBody::Lsp(Lsp {
                level: IsLevel::L2,
                remaining_lifetime: 0,
                lsp_id: LspId::new(sid([4, 4, 4, 4, 4, 4]), 0, 0),
                sequence_number: 7,
                checksum: 0,
                partition: false,
                attached: 0,
                overload: false,
                is_type: IsLevel::L1L2,
                tlvs: sample_tlvs(),
            }),
        };
        let mut bytes = pdu.encode();
        // Zero the checksum field (buf[24..26]) so a checksum verification would
        // fail — the zero lifetime must make decode skip that verification.
        bytes[24] = 0;
        bytes[25] = 0;
        match Pdu::decode(&bytes).expect("purge decodes despite zero checksum").body {
            PduBody::Lsp(l) => assert_eq!(l.remaining_lifetime, 0),
            _ => panic!("not an LSP"),
        }
    }

    #[test]
    fn lsp_flags_roundtrip() {
        let pdu = Pdu {
            max_area_addresses: 0,
            body: PduBody::Lsp(Lsp {
                level: IsLevel::L1,
                remaining_lifetime: 500,
                lsp_id: LspId::new(sid([4, 4, 4, 4, 4, 4]), 1, 2),
                sequence_number: 7,
                checksum: 0,
                partition: true,
                attached: 0b1010,
                overload: true,
                // L2, not L1L2: an LSP IS Type is L1 or L2 (§9.8), and L2 is the
                // half the old shared codec encoded as the unused value 0b10.
                is_type: IsLevel::L2,
                tlvs: vec![],
            }),
        };
        let decoded = roundtrip(&pdu);
        if let PduBody::Lsp(l) = &decoded.body {
            assert!(l.partition && l.overload);
            assert_eq!(l.attached, 0b1010);
            assert_eq!(l.is_type, IsLevel::L2);
        }
    }

    #[test]
    fn csnp_and_psnp_roundtrip() {
        let entries = Tlv::LspEntries(vec![crate::tlv::LspEntry {
            remaining_lifetime: 900,
            lsp_id: LspId::new(sid([5, 5, 5, 5, 5, 5]), 0, 0),
            sequence_number: 3,
            checksum: 0x1234,
        }]);
        let csnp = Pdu {
            max_area_addresses: 0,
            body: PduBody::Csnp(Csnp {
                level: IsLevel::L1,
                source_id: (sid([6, 6, 6, 6, 6, 6]), 0),
                start_lsp_id: LspId::new(SystemId::ZERO, 0, 0),
                end_lsp_id: LspId::new(sid([0xff; 6]), 0xff, 0xff),
                tlvs: vec![entries.clone()],
            }),
        };
        assert_eq!(csnp.pdu_type(), PduType::L1Csnp);
        roundtrip(&csnp);

        let psnp = Pdu {
            max_area_addresses: 0,
            body: PduBody::Psnp(Psnp {
                level: IsLevel::L2,
                source_id: (sid([7, 7, 7, 7, 7, 7]), 0),
                tlvs: vec![entries],
            }),
        };
        assert_eq!(psnp.pdu_type(), PduType::L2Psnp);
        roundtrip(&psnp);
    }

    #[test]
    fn rejects_bad_discriminator_and_type() {
        let good = Pdu {
            max_area_addresses: 0,
            body: PduBody::P2pHello(P2pHello {
                circuit_type: IsLevel::L1,
                source_id: sid([1, 1, 1, 1, 1, 1]),
                holding_time: 10,
                local_circuit_id: 1,
                tlvs: vec![],
            }),
        }
        .encode();
        let mut bytes = good.clone();
        bytes[0] = 0x00;
        assert_eq!(Pdu::decode(&bytes), Err(DecodeError::BadDiscriminator(0)));
        let mut bad_type = good.clone();
        bad_type[4] = 19; // not a known PDU type
        assert_eq!(Pdu::decode(&bad_type), Err(DecodeError::UnknownType(19)));
    }

    // =======================================================================
    // Byte-offset assertions (ISO/IEC 10589 §9, RFC 1195)
    //
    // Everything above encodes with wren and decodes with wren, which cannot
    // see a field written at the wrong offset or a flag in the wrong bit: the
    // decoder reads it back from the same wrong place. That is how the OSPFv2
    // Router-LSA V/E/B bug survived every round-trip test in this repository
    // and was only found on hardware, against FRR. The tests below name the
    // offset and the bit the standard names.
    // =======================================================================

    /// ISO 10589 §9.8 fixes the LSP flags octet (the last byte of the LSP
    /// fixed header):
    ///
    /// ```text
    ///   bit  8   7  6  5  4   3    2 1
    ///       [P] [   ATT   ] [OL] [IStype]
    /// ```
    ///
    /// i.e. `P` = 0x80, the four ATT bits = 0x78 (default-metric ATT is the
    /// *lowest* of the four, 0x08), `OL` = 0x04, IS-type = 0x03.
    ///
    /// The ATT bits are the dangerous ones: a Level-1 router installs its
    /// default route towards the nearest LSP with ATT set (§7.2.9.2). Shift the
    /// field by one and every L1-only router in the area either loses its
    /// default route entirely or points it at a router that is not attached to
    /// the backbone. A round trip cannot see it — `lsp_flags_roundtrip` above
    /// passes with any permutation of these bits.
    #[test]
    fn the_lsp_flags_octet_puts_each_bit_where_iso_10589_names_it() {
        let lsp = |partition, attached, overload, is_type| Pdu {
            max_area_addresses: 0,
            body: PduBody::Lsp(Lsp {
                level: IsLevel::L1,
                remaining_lifetime: 500,
                lsp_id: LspId::new(sid([4, 4, 4, 4, 4, 4]), 0, 0),
                sequence_number: 1,
                checksum: 0,
                partition,
                attached,
                overload,
                is_type,
                tlvs: vec![],
            }),
        };
        // The flags octet is the last byte of the 27-byte LSP fixed header.
        let flags_off = PduType::L1Lsp.fixed_header_len() - 1;
        assert_eq!(flags_off, 26, "the LSP fixed header is 27 octets (§9.8)");

        let f = |p, a, o, t| lsp(p, a, o, t).encode()[flags_off];
        assert_eq!(f(true, 0, false, IsLevel::L1) & 0x80, 0x80, "P is bit 8 (0x80)");
        assert_eq!(f(false, 0, true, IsLevel::L1) & 0x04, 0x04, "OL is bit 3 (0x04)");
        assert_eq!(
            f(false, 0b0001, false, IsLevel::L1) & 0x78,
            0x08,
            "the default-metric ATT bit is bit 4 (0x08), the lowest of the four"
        );
        assert_eq!(
            f(false, 0b1111, false, IsLevel::L1) & 0x78,
            0x78,
            "all four ATT bits occupy 0x78"
        );
        assert_eq!(
            f(false, 0b1000, false, IsLevel::L1) & 0x78,
            0x40,
            "the error-metric ATT bit is bit 7 (0x40), the highest of the four"
        );
        assert_eq!(f(false, 0, false, IsLevel::L1) & 0x03, 0b01, "IS-type is bits 2..1");
        assert_eq!(f(false, 0, false, IsLevel::L1L2) & 0x03, 0b11);
        // Nothing bleeds outside its own field.
        assert_eq!(f(true, 0b1111, true, IsLevel::L1L2), 0xff, "all bits set = 0xff");
        assert_eq!(f(false, 0, false, IsLevel::L1), 0b01, "only IS-type set");
        // The half the old test never checked, and the bug it hid: a Level-2 LSP
        // must carry IS Type 3 (§9.8), not the unused value 2 that the Circuit
        // Type's `L2 = 0b10` produced here.
        assert_eq!(
            f(false, 0, false, IsLevel::L2) & 0x03,
            0b11,
            "a Level-2 LSP's IS Type is 3, not the unused 2"
        );
    }

    /// The IS Type codec is the LSP field (§9.8), which is not the Circuit Type
    /// (§9.5) even though both are two bits of the same enum.
    ///
    /// `L2` differs between them — `0b10` as a Circuit Type, `0b11` as an IS
    /// Type — and one codec serving both wrote the Circuit Type value into every
    /// Level-2 LSP (an *unused* IS Type) and read a standard neighbour's `3` back
    /// as `L1L2`. That misread was invisible because nothing in the tree branches
    /// on `is_type`; it is fixed here so it stays fixed.
    #[test]
    fn the_lsp_is_type_is_encoded_and_decoded_per_iso_10589_9_8() {
        // Encode: L1 -> 1, L2 -> 3, and L1L2 (an L2-capable IS) -> 3.
        assert_eq!(IsLevel::L1.is_type_bits(), 0b01);
        assert_eq!(IsLevel::L2.is_type_bits(), 0b11);
        assert_eq!(IsLevel::L1L2.is_type_bits(), 0b11);

        // Decode: 1 -> L1, 3 -> L2. The `3 -> L2` is the FRR-interop half — FRR
        // emits 3 for a Level-2 LSP, and the Circuit Type decoder read that as
        // L1L2.
        assert_eq!(IsLevel::is_type_from_bits(0b01), IsLevel::L1);
        assert_eq!(IsLevel::is_type_from_bits(0b11), IsLevel::L2);

        // The Circuit Type is untouched and still numbers L2 as 0b10, which is
        // the whole reason the two need separate codecs.
        assert_eq!(IsLevel::L2.bits(), 0b10);
        assert_ne!(IsLevel::L2.bits(), IsLevel::L2.is_type_bits());
    }

    /// ISO 10589 §9.1 fixes the 8-octet common header shared by every PDU:
    /// byte 0 the Intradomain Routeing Protocol Discriminator 0x83, byte 1 the
    /// Length Indicator (the fixed header length), byte 2 the Version/Protocol
    /// ID Extension 1, byte 3 the ID Length (0 = the default 6), byte 4 the PDU
    /// Type in its low five bits, byte 5 the Version 1, byte 6 reserved, byte 7
    /// Maximum Area Addresses.
    ///
    /// A wrong Length Indicator makes a conformant peer start reading TLVs in
    /// the middle of the fixed header and discard the PDU; a wrong discriminator
    /// means the frame is not recognised as IS-IS at all.
    #[test]
    fn the_common_header_writes_each_field_at_the_offset_iso_10589_names() {
        let pdu = Pdu {
            max_area_addresses: 3,
            body: PduBody::Lsp(Lsp {
                level: IsLevel::L2,
                remaining_lifetime: 1199,
                lsp_id: LspId::new(sid([9, 9, 9, 9, 9, 9]), 0, 0),
                sequence_number: 1,
                checksum: 0,
                partition: false,
                attached: 0,
                overload: false,
                is_type: IsLevel::L1L2,
                tlvs: vec![],
            }),
        };
        let b = pdu.encode();
        assert_eq!(b[0], 0x83, "byte 0 is the intradomain routeing discriminator");
        assert_eq!(b[1], 27, "byte 1 is the fixed header length — 27 for an LSP");
        assert_eq!(b[2], 1, "byte 2 is the Version/Protocol ID Extension");
        assert_eq!(b[3], 0, "byte 3 is the ID Length, 0 meaning the default 6");
        assert_eq!(b[4], 20, "byte 4 is the PDU type — an L2 LSP is 20");
        assert_eq!(b[5], 1, "byte 5 is the Version");
        assert_eq!(b[6], 0, "byte 6 is reserved and must be zero");
        assert_eq!(b[7], 3, "byte 7 is Maximum Area Addresses");
    }

    /// ISO 10589 §9.5–§9.13 assign the PDU type codes. These are the numbers
    /// every other IS-IS speaker switches on; renumbering one makes wren's
    /// Hellos or LSPs unrecognisable, and `PduType` round-tripping through
    /// itself proves nothing about them.
    #[test]
    fn the_pdu_type_codes_are_the_ones_iso_10589_assigns() {
        for (t, code, hdr) in [
            (PduType::L1LanHello, 15u8, 27usize),
            (PduType::L2LanHello, 16, 27),
            (PduType::P2pHello, 17, 20),
            (PduType::L1Lsp, 18, 27),
            (PduType::L2Lsp, 20, 27),
            (PduType::L1Csnp, 24, 33),
            (PduType::L2Csnp, 25, 33),
            (PduType::L1Psnp, 26, 17),
            (PduType::L2Psnp, 27, 17),
        ] {
            assert_eq!(t.as_u8(), code, "{t:?} is PDU type {code}");
            assert_eq!(PduType::from_u8(code), Some(t));
            assert_eq!(t.fixed_header_len(), hdr, "{t:?} has a {hdr}-octet fixed header");
        }
        // 19, 21, 22 and 23 are unassigned between the LSP and CSNP blocks.
        for bad in [0u8, 14, 19, 21, 22, 23, 28] {
            assert_eq!(PduType::from_u8(bad), None, "{bad} is not an IS-IS PDU type");
        }
    }

    /// ISO 10589 §9.8: an LSP's fixed header is PDU Length 8..10, Remaining
    /// Lifetime 10..12, LSP ID 12..20 (System ID 12..18, pseudonode 18,
    /// fragment 19), Sequence Number 20..24, Checksum 24..26, flags 26.
    ///
    /// The checksum is computed from the LSP ID onward (§7.3.11), i.e. it
    /// deliberately excludes the Remaining Lifetime so the lifetime can be
    /// decremented hop by hop without recomputing it. Move the region start and
    /// wren still verifies its own LSPs while every peer rejects them.
    #[test]
    fn an_lsp_fixed_header_matches_the_iso_10589_field_order() {
        let pdu = Pdu {
            max_area_addresses: 0,
            body: PduBody::Lsp(Lsp {
                level: IsLevel::L1,
                remaining_lifetime: 0x04b0, // 1200
                lsp_id: LspId::new(sid([0x19, 0x21, 0x68, 0x00, 0x10, 0x01]), 0x02, 0x03),
                sequence_number: 0x1122_3344,
                checksum: 0,
                partition: false,
                attached: 0,
                overload: false,
                is_type: IsLevel::L1,
                tlvs: vec![],
            }),
        };
        let b = pdu.encode();
        assert_eq!(
            u16::from_be_bytes([b[8], b[9]]) as usize,
            b.len(),
            "PDU Length is bytes 8..10 and covers the whole PDU"
        );
        assert_eq!(&b[10..12], &[0x04, 0xb0], "Remaining Lifetime is bytes 10..12");
        assert_eq!(
            &b[12..18],
            &[0x19, 0x21, 0x68, 0x00, 0x10, 0x01],
            "the LSP ID's System ID is bytes 12..18"
        );
        assert_eq!(b[18], 0x02, "the pseudonode octet is byte 18");
        assert_eq!(b[19], 0x03, "the LSP number (fragment) is byte 19");
        assert_eq!(&b[20..24], &[0x11, 0x22, 0x33, 0x44], "Sequence Number is 20..24");
        assert_ne!(&b[24..26], &[0, 0], "the Checksum at 24..26 is filled in");

        // The checksum covers bytes 12.. (LSP ID onward) and not the lifetime:
        // rewriting the lifetime must leave it valid, rewriting the LSP ID must not.
        let mut aged = b.clone();
        aged[10..12].copy_from_slice(&1u16.to_be_bytes());
        assert!(
            crate::fletcher16_valid(&aged[12..]),
            "decrementing Remaining Lifetime must not invalidate the checksum"
        );
        let mut tampered = b.clone();
        tampered[12] ^= 0xff;
        assert!(!crate::fletcher16_valid(&tampered[12..]));
    }

    /// ISO 10589 §9.5: a LAN Hello is Circuit Type 8, Source ID 9..15, Holding
    /// Time 15..17, PDU Length 17..19, Priority 19 (low 7 bits, bit 8
    /// reserved), LAN ID 20..27 (System ID 20..26, pseudonode 26).
    ///
    /// Priority drives the §8.4.5 DIS election. Slip it a byte and two routers
    /// each read the other's LAN-ID octet as a priority, both claim the DIS
    /// role, and the pseudonode LSP flaps.
    #[test]
    fn a_lan_hello_matches_the_iso_10589_field_order() {
        let pdu = Pdu {
            max_area_addresses: 0,
            body: PduBody::LanHello(LanHello {
                level: IsLevel::L1,
                circuit_type: IsLevel::L1L2,
                source_id: sid([1, 2, 3, 4, 5, 6]),
                holding_time: 0x001e, // 30
                priority: 64,
                lan_id: (sid([7, 8, 9, 10, 11, 12]), 1),
                tlvs: vec![],
            }),
        };
        let b = pdu.encode();
        assert_eq!(b[8], 0b11, "Circuit Type is byte 8; L1L2 is 0b11");
        assert_eq!(&b[9..15], &[1, 2, 3, 4, 5, 6], "Source ID is bytes 9..15");
        assert_eq!(&b[15..17], &[0x00, 0x1e], "Holding Time is bytes 15..17");
        assert_eq!(
            u16::from_be_bytes([b[17], b[18]]) as usize,
            b.len(),
            "PDU Length is bytes 17..19"
        );
        assert_eq!(b[19], 64, "Priority is byte 19");
        assert_eq!(&b[20..26], &[7, 8, 9, 10, 11, 12], "the LAN ID System ID is 20..26");
        assert_eq!(b[26], 1, "the LAN ID pseudonode octet is byte 26");
        assert_eq!(b.len(), 27, "an empty LAN Hello is exactly its 27-octet header");

        // Bit 8 of the priority octet is reserved and must never be set.
        let mut hi = pdu.clone();
        if let PduBody::LanHello(h) = &mut hi.body {
            h.priority = 0xff;
        }
        assert_eq!(hi.encode()[19] & 0x80, 0, "the priority octet's top bit is reserved");
    }

    /// ISO 10589 §9.10: a CSNP is PDU Length 8..10, Source ID 10..16, source
    /// circuit octet 16, Start LSP ID 17..25, End LSP ID 25..33.
    ///
    /// The start/end pair bounds the range the CSNP describes; overlap them by
    /// a byte and a peer concludes its own LSPs fall outside the advertised
    /// range, never requests the ones it is missing, and the two databases stay
    /// permanently out of sync without any visible error.
    #[test]
    fn a_csnp_matches_the_iso_10589_field_order() {
        let pdu = Pdu {
            max_area_addresses: 0,
            body: PduBody::Csnp(Csnp {
                level: IsLevel::L1,
                source_id: (sid([1, 1, 1, 1, 1, 1]), 0),
                start_lsp_id: LspId::new(sid([0, 0, 0, 0, 0, 0]), 0, 0),
                end_lsp_id: LspId::new(sid([0xff; 6]), 0xff, 0xff),
                tlvs: vec![],
            }),
        };
        let b = pdu.encode();
        assert_eq!(
            u16::from_be_bytes([b[8], b[9]]) as usize,
            b.len(),
            "PDU Length is bytes 8..10"
        );
        assert_eq!(&b[10..16], &[1, 1, 1, 1, 1, 1], "Source ID is bytes 10..16");
        assert_eq!(b[16], 0, "the source circuit octet is byte 16");
        assert_eq!(&b[17..25], &[0u8; 8], "Start LSP ID is bytes 17..25");
        assert_eq!(&b[25..33], &[0xffu8; 8], "End LSP ID is bytes 25..33");
        assert_eq!(b.len(), 33, "an empty CSNP is exactly its 33-octet header");
    }
}
