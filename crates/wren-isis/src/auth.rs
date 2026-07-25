//! IS-IS PDU authentication — the cleartext password of ISO 10589 §9.8 and the
//! Generic Cryptographic Authentication of RFC 5310.
//!
//! Cleartext authentication is a TLV comparison and needs nothing from this
//! module beyond [`IsisAuth::placeholder`]. Cryptographic authentication is
//! different in kind: the digest covers the *encoded* PDU, so it can only be
//! applied once the PDU has been serialized, and it has to be undone in exactly
//! the same way on receipt. Everything here therefore works on PDU bytes.
//!
//! Three details of RFC 5310 are easy to get wrong, and getting them wrong
//! produces an implementation that authenticates happily against itself and fails
//! against every other vendor:
//!
//! 1. Before hashing, the Authentication Data field is filled with **Apad**
//!    (`0x878FE1F3` repeated), not with zeros (§3.3).
//! 2. An LSP's Remaining Lifetime and Checksum are zeroed before hashing (§4),
//!    because both are rewritten by transit routers.
//! 3. An LSP's Fletcher checksum covers the Authentication TLV, so writing the
//!    digest invalidates it — the checksum has to be recomputed *afterwards*.
//!    [`IsisAuth::seal`] does this; a caller that patches the digest by hand will
//!    emit LSPs every neighbour discards.

use crate::fletcher16;
use wren_core::hmac::{hmac_sha256, DIGEST_LEN};

/// Authentication TLV (ISO 10589 §9.8).
const T_AUTHENTICATION: u8 = 10;
/// Cleartext password authentication (ISO 10589 §9.8).
pub const AUTH_TYPE_CLEARTEXT: u8 = 1;
/// Generic Cryptographic Authentication (RFC 5310 §3).
pub const AUTH_TYPE_CRYPTO: u8 = 3;
/// Key ID width in a Generic Cryptographic Authentication TLV (RFC 5310 §3.1).
const KEY_ID_LEN: usize = 2;
/// Value length of an HMAC-SHA-256 Authentication TLV: type + Key ID + digest.
const CRYPTO_VALUE_LEN: usize = 1 + KEY_ID_LEN + DIGEST_LEN;

/// Offset of an LSP's Remaining Lifetime (ISO 10589 §9.6) — rewritten in transit,
/// so RFC 5310 §4 excludes it from the digest.
const LSP_LIFETIME: std::ops::Range<usize> = 10..12;
/// Offset of an LSP's Checksum — likewise excluded.
const LSP_CHECKSUM: std::ops::Range<usize> = 24..26;
/// An LSP's Fletcher checksum covers everything from the LSP ID on, and sits 12
/// octets into that region.
const LSP_CSUM_REGION: usize = 12;

/// How an IS-IS instance authenticates the PDUs it sends and accepts.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum IsisAuth {
    /// The shared password travels in the clear (ISO 10589 §9.8). Offers no
    /// protection against anyone who can observe the link.
    Cleartext(Vec<u8>),
    /// HMAC-SHA-256 over the whole PDU (RFC 5310), keyed by a shared secret.
    HmacSha256 {
        /// The shared secret. Any length — HMAC folds it to the block size.
        key: Vec<u8>,
        /// The advertised Key ID, letting keys be rolled without an outage.
        key_id: u16,
    },
}

impl IsisAuth {
    /// The `auth_type` byte for this scheme.
    pub fn auth_type(&self) -> u8 {
        match self {
            Self::Cleartext(_) => AUTH_TYPE_CLEARTEXT,
            Self::HmacSha256 { .. } => AUTH_TYPE_CRYPTO,
        }
    }

    /// The Authentication TLV's value *after* the type byte, as it goes on the
    /// wire before sealing: the password itself, or the Key ID followed by an
    /// Apad-filled digest field that [`Self::seal`] overwrites.
    pub fn placeholder(&self) -> Vec<u8> {
        match self {
            Self::Cleartext(pw) => pw.clone(),
            Self::HmacSha256 { key_id, .. } => {
                let mut v = Vec::with_capacity(KEY_ID_LEN + DIGEST_LEN);
                v.extend_from_slice(&key_id.to_be_bytes());
                v.extend_from_slice(&apad());
                v
            }
        }
    }

    /// Write the digest into an encoded PDU and repair the checksum it disturbs.
    /// A no-op for cleartext, whose TLV is already final at encode time.
    pub fn seal(&self, pdu: &mut [u8]) {
        let Self::HmacSha256 { key_id, .. } = self else {
            return;
        };
        let Some(value) = crypto_value_range(pdu) else {
            return;
        };
        // The Key ID rides in the clear ahead of the digest.
        let key_at = value.start + 1;
        pdu[key_at..key_at + KEY_ID_LEN].copy_from_slice(&key_id.to_be_bytes());
        let Some(digest) = self.digest(pdu, value.start) else {
            return;
        };
        let at = key_at + KEY_ID_LEN;
        pdu[at..at + DIGEST_LEN].copy_from_slice(&digest);
        // Gotcha 3: the digest just changed bytes the Fletcher checksum covers.
        if is_lsp(pdu) {
            fletcher16(&mut pdu[LSP_CSUM_REGION..], LSP_CSUM_REGION);
        }
    }

    /// Whether `pdu` carries authentication matching this configuration.
    pub fn verify(&self, pdu: &[u8]) -> bool {
        match self {
            Self::Cleartext(expected) => match auth_tlv_range(pdu) {
                Some(v) if pdu[v.start] == AUTH_TYPE_CLEARTEXT => {
                    &pdu[v.start + 1..v.end] == expected.as_slice()
                }
                _ => false,
            },
            Self::HmacSha256 { .. } => {
                let Some(value) = crypto_value_range(pdu) else {
                    return false;
                };
                let Some(expected) = self.digest(pdu, value.start) else {
                    return false;
                };
                let at = value.start + 1 + KEY_ID_LEN;
                ct_eq(&pdu[at..at + DIGEST_LEN], &expected)
            }
        }
    }

    /// The HMAC over `pdu` as RFC 5310 defines the input: the Authentication Data
    /// field replaced by Apad, and — for an LSP — the two transit-mutable header
    /// fields zeroed. Computed on a scratch copy, so the caller's bytes are safe
    /// and the same routine serves both sealing and verification.
    fn digest(&self, pdu: &[u8], value_start: usize) -> Option<[u8; DIGEST_LEN]> {
        let Self::HmacSha256 { key, .. } = self else {
            return None;
        };
        let mut scratch = pdu.to_vec();
        let at = value_start + 1 + KEY_ID_LEN;
        scratch[at..at + DIGEST_LEN].copy_from_slice(&apad());
        if is_lsp(&scratch) {
            scratch[LSP_LIFETIME].fill(0);
            scratch[LSP_CHECKSUM].fill(0);
        }
        Some(hmac_sha256(key, &scratch))
    }
}

/// Apad (RFC 5310 §3.3): `0x878FE1F3` repeated to the digest length. Unlike the
/// OSPFv3 variant of the same idea (RFC 7166 §4.5) it carries no address prefix.
fn apad() -> [u8; DIGEST_LEN] {
    let mut a = [0u8; DIGEST_LEN];
    for chunk in a.chunks_exact_mut(4) {
        chunk.copy_from_slice(&0x878F_E1F3u32.to_be_bytes());
    }
    a
}

/// Whether the encoded PDU is an LSP (types 18 and 20 — ISO 10589 §9.6).
fn is_lsp(pdu: &[u8]) -> bool {
    matches!(pdu.get(4), Some(18) | Some(20))
}

/// Locate the Authentication TLV's value inside an encoded PDU. The second octet
/// of the common header is the fixed-header length, i.e. where the TLVs begin, so
/// this works for every PDU type without reparsing the body.
fn auth_tlv_range(pdu: &[u8]) -> Option<std::ops::Range<usize>> {
    let mut off = *pdu.get(1)? as usize;
    while off + 2 <= pdu.len() {
        let (t, len) = (pdu[off], pdu[off + 1] as usize);
        let value = off + 2;
        if value + len > pdu.len() {
            return None;
        }
        if t == T_AUTHENTICATION && len >= 1 {
            return Some(value..value + len);
        }
        off = value + len;
    }
    None
}

/// The Authentication TLV's value, but only if it is a well-formed HMAC-SHA-256
/// one — so neither sealing nor verification can index past a short TLV.
fn crypto_value_range(pdu: &[u8]) -> Option<std::ops::Range<usize>> {
    let v = auth_tlv_range(pdu)?;
    (v.len() == CRYPTO_VALUE_LEN && pdu[v.start] == AUTH_TYPE_CRYPTO).then_some(v)
}

/// Constant-time byte-slice equality, so a wrong digest cannot be probed by
/// timing the compare.
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pdu::{Lsp, P2pHello, Pdu, PduBody};
    use crate::tlv::Tlv;
    use crate::{IsLevel, LspId, SystemId};

    fn auth() -> IsisAuth {
        IsisAuth::HmacSha256 {
            key: b"s3cret".to_vec(),
            key_id: 7,
        }
    }

    fn auth_tlv(a: &IsisAuth) -> Vec<Tlv> {
        vec![Tlv::Authentication {
            auth_type: a.auth_type(),
            data: a.placeholder(),
        }]
    }

    fn encode(body: PduBody) -> Vec<u8> {
        Pdu {
            max_area_addresses: 3,
            body,
        }
        .encode()
    }

    /// A P2P Hello whose first TLV is the auth placeholder, encoded.
    fn hello_bytes(tlvs: Vec<Tlv>) -> Vec<u8> {
        encode(PduBody::P2pHello(P2pHello {
            circuit_type: IsLevel::L2,
            source_id: SystemId::new([1; 6]),
            holding_time: 30,
            local_circuit_id: 1,
            tlvs,
        }))
    }

    /// An LSP whose first TLV is the auth placeholder, encoded.
    fn lsp_bytes(a: &IsisAuth, lifetime: u16, seq: u32) -> Vec<u8> {
        encode(PduBody::Lsp(Lsp {
            level: IsLevel::L2,
            remaining_lifetime: lifetime,
            lsp_id: LspId::new(SystemId::new([2; 6]), 0, 0),
            sequence_number: seq,
            checksum: 0,
            partition: false,
            attached: 0,
            overload: false,
            is_type: IsLevel::L2,
            tlvs: auth_tlv(a),
        }))
    }

    #[test]
    fn a_sealed_pdu_verifies_and_a_tampered_one_does_not() {
        let a = auth();
        let mut pdu = hello_bytes(auth_tlv(&a));
        assert!(!a.verify(&pdu), "the Apad placeholder is not a valid digest");
        a.seal(&mut pdu);
        assert!(a.verify(&pdu), "sealing makes it verify");

        // A different key rejects it.
        let other = IsisAuth::HmacSha256 {
            key: b"other".to_vec(),
            key_id: 7,
        };
        assert!(!other.verify(&pdu));

        // Flipping any covered byte breaks the digest.
        let mut tampered = pdu.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 0x01;
        assert!(!a.verify(&tampered));
    }

    #[test]
    fn the_key_id_is_advertised_in_the_clear() {
        let a = auth();
        let mut pdu = hello_bytes(auth_tlv(&a));
        a.seal(&mut pdu);
        let v = crypto_value_range(&pdu).expect("a crypto auth TLV");
        assert_eq!(pdu[v.start], AUTH_TYPE_CRYPTO);
        assert_eq!(&pdu[v.start + 1..v.start + 3], &7u16.to_be_bytes());
    }

    #[test]
    fn an_lsp_digest_ignores_lifetime_and_checksum_rfc5310() {
        // The point of zeroing those two fields: a transit router may age an LSP and
        // recompute its checksum, and the digest must still verify afterwards.
        let a = auth();
        let mut pdu = lsp_bytes(&a, 1200, 5);
        a.seal(&mut pdu);
        assert!(a.verify(&pdu));

        // Ageing rewrites the lifetime. (The Fletcher checksum starts after that
        // field precisely so ageing needs no recomputation — but the digest would
        // cover it were RFC 5310 §4 not excluding it explicitly.)
        let mut aged = pdu.clone();
        aged[LSP_LIFETIME].copy_from_slice(&600u16.to_be_bytes());
        assert_ne!(aged[LSP_LIFETIME], pdu[LSP_LIFETIME], "the lifetime did change");
        assert!(a.verify(&aged), "ageing an LSP must not invalidate its digest");

        // Same for a rewritten checksum field.
        let mut rechecked = pdu.clone();
        rechecked[LSP_CHECKSUM].copy_from_slice(&0x1234u16.to_be_bytes());
        assert!(a.verify(&rechecked), "a rewritten checksum must not invalidate it");

        // A field that is *not* excluded still breaks it.
        let mut forged = pdu.clone();
        forged[20..24].copy_from_slice(&6u32.to_be_bytes()); // sequence number
        assert!(!a.verify(&forged), "a forged sequence number is caught");
    }

    #[test]
    fn sealing_an_lsp_leaves_its_checksum_valid() {
        // Gotcha 3: encode() checksummed the Apad placeholder, so seal() must
        // recompute it or every neighbour drops the LSP before ever authenticating.
        let a = auth();
        let mut pdu = lsp_bytes(&a, 1200, 5);
        a.seal(&mut pdu);
        assert!(
            crate::fletcher16_valid(&pdu[LSP_CSUM_REGION..]),
            "the checksum survives the digest write"
        );
        assert!(Pdu::decode(&pdu).is_ok(), "and the PDU still decodes");
    }

    #[test]
    fn a_missing_or_short_auth_tlv_is_rejected_not_panicked() {
        let a = auth();
        // No Authentication TLV at all: nothing to verify, and sealing is a no-op
        // rather than a panic.
        let mut bare = hello_bytes(vec![]);
        assert!(!a.verify(&bare));
        a.seal(&mut bare);

        // The two schemes do not satisfy each other.
        let clear = IsisAuth::Cleartext(b"s3cret".to_vec());
        let clear_pdu = hello_bytes(auth_tlv(&clear));
        assert!(clear.verify(&clear_pdu));
        assert!(!a.verify(&clear_pdu), "cleartext does not satisfy HMAC");
        let mut crypto_pdu = hello_bytes(auth_tlv(&a));
        a.seal(&mut crypto_pdu);
        assert!(!clear.verify(&crypto_pdu), "HMAC does not satisfy cleartext");

        // Truncated input of every length must be rejected, never indexed past.
        for n in 0..crypto_pdu.len() {
            assert!(!a.verify(&crypto_pdu[..n]));
            a.seal(&mut crypto_pdu.clone()[..n]);
        }
    }
}
