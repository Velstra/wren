//! IS-IS PDU authentication — the cleartext password of ISO 10589 §9.8, the
//! HMAC-MD5 of RFC 5304, and the Generic Cryptographic Authentication of RFC 5310.
//!
//! Cleartext authentication is a TLV comparison and needs nothing from this
//! module beyond [`IsisAuth::placeholder`]. Cryptographic authentication is
//! different in kind: the digest covers the *encoded* PDU, so it can only be
//! applied once the PDU has been serialized, and it has to be undone in exactly
//! the same way on receipt. Everything here therefore works on PDU bytes.
//!
//! Four details are easy to get wrong, and getting any of them wrong produces an
//! implementation that authenticates happily against itself and fails against every
//! other vendor:
//!
//! 1. **The two schemes fill the digest field differently before hashing.** RFC 5304
//!    §3 authenticates "the IS-IS PDU … with the Authentication Value field … set to
//!    zero"; RFC 5310 §3.3 instead fills it with **Apad** (`0x878FE1F3` repeated).
//!    They are otherwise near-identical, which is exactly why this is easy to miss.
//! 2. RFC 5310 carries a 2-octet **Key ID** ahead of the digest; RFC 5304 has none,
//!    so the digest sits directly after the type byte.
//! 3. An LSP's Remaining Lifetime and Checksum are zeroed before hashing (both
//!    RFCs), because transit routers rewrite them.
//! 4. An LSP's Fletcher checksum covers the Authentication TLV, so writing the
//!    digest invalidates it — the checksum has to be recomputed *afterwards*.
//!    [`IsisAuth::seal`] does this; a caller that patches the digest by hand will
//!    emit LSPs every neighbour discards.

use crate::fletcher16;
use wren_core::hmac::{hmac_md5, hmac_sha256, DIGEST_LEN, MD5_DIGEST_LEN};

/// Authentication TLV (ISO 10589 §9.8).
const T_AUTHENTICATION: u8 = 10;
/// Cleartext password authentication (ISO 10589 §9.8).
pub const AUTH_TYPE_CLEARTEXT: u8 = 1;
/// Generic Cryptographic Authentication (RFC 5310 §3).
pub const AUTH_TYPE_CRYPTO: u8 = 3;
/// HMAC-MD5 authentication (RFC 5304 §2). The older scheme, and the one most
/// vendors default to.
pub const AUTH_TYPE_HMAC_MD5: u8 = 54;
/// Key ID width in a Generic Cryptographic Authentication TLV (RFC 5310 §3.1).
const KEY_ID_LEN: usize = 2;

/// How a cryptographic Authentication TLV is laid out and hashed. The two schemes
/// differ in exactly these ways; everything else about them is shared.
struct Layout {
    /// Octets of Key ID between the type byte and the digest (RFC 5310 has 2,
    /// RFC 5304 none).
    key_id_len: usize,
    /// Digest width.
    digest_len: usize,
    /// Whether the digest field is filled with Apad before hashing (RFC 5310) as
    /// opposed to zeros (RFC 5304). See gotcha 1 above.
    apad: bool,
}

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
    /// HMAC-MD5 over the whole PDU (RFC 5304), keyed by a shared secret. Weaker
    /// than [`Self::HmacSha256`] but the scheme most deployed routers default to.
    HmacMd5 {
        /// The shared secret. Any length — HMAC folds it to the block size.
        key: Vec<u8>,
    },
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
            Self::HmacMd5 { .. } => AUTH_TYPE_HMAC_MD5,
            Self::HmacSha256 { .. } => AUTH_TYPE_CRYPTO,
        }
    }

    /// The TLV layout and hashing rules of a cryptographic scheme; `None` for the
    /// cleartext password, which has neither.
    fn layout(&self) -> Option<Layout> {
        match self {
            Self::Cleartext(_) => None,
            Self::HmacMd5 { .. } => Some(Layout {
                key_id_len: 0,
                digest_len: MD5_DIGEST_LEN,
                apad: false,
            }),
            Self::HmacSha256 { .. } => Some(Layout {
                key_id_len: KEY_ID_LEN,
                digest_len: DIGEST_LEN,
                apad: true,
            }),
        }
    }

    /// The Authentication TLV's value *after* the type byte, as it goes on the
    /// wire before sealing: the password itself, or (for a keyed scheme) any Key ID
    /// followed by a filled digest field that [`Self::seal`] overwrites.
    pub fn placeholder(&self) -> Vec<u8> {
        match self {
            Self::Cleartext(pw) => pw.clone(),
            Self::HmacMd5 { .. } => digest_placeholder(MD5_DIGEST_LEN, false),
            Self::HmacSha256 { key_id, .. } => {
                let mut v = Vec::with_capacity(KEY_ID_LEN + DIGEST_LEN);
                v.extend_from_slice(&key_id.to_be_bytes());
                v.extend_from_slice(&digest_placeholder(DIGEST_LEN, true));
                v
            }
        }
    }

    /// Write the digest into an encoded PDU and repair the checksum it disturbs.
    /// A no-op for cleartext, whose TLV is already final at encode time.
    pub fn seal(&self, pdu: &mut [u8]) {
        let Some(l) = self.layout() else {
            return;
        };
        let Some(value) = self.crypto_value_range(pdu) else {
            return;
        };
        // The Key ID, where the scheme has one, rides in the clear ahead of the digest.
        if let Self::HmacSha256 { key_id, .. } = self {
            let at = value.start + 1;
            pdu[at..at + l.key_id_len].copy_from_slice(&key_id.to_be_bytes());
        }
        let Some(digest) = self.digest(pdu, value.start) else {
            return;
        };
        let at = value.start + 1 + l.key_id_len;
        pdu[at..at + l.digest_len].copy_from_slice(&digest);
        // Gotcha 4: the digest just changed bytes the Fletcher checksum covers.
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
            Self::HmacMd5 { .. } | Self::HmacSha256 { .. } => {
                let (Some(l), Some(value)) = (self.layout(), self.crypto_value_range(pdu)) else {
                    return false;
                };
                let Some(expected) = self.digest(pdu, value.start) else {
                    return false;
                };
                let at = value.start + 1 + l.key_id_len;
                ct_eq(&pdu[at..at + l.digest_len], &expected)
            }
        }
    }

    /// The HMAC over `pdu` as the RFCs define the input: the Authentication Data
    /// field refilled with the scheme's placeholder, and — for an LSP — the two
    /// transit-mutable header fields zeroed. Computed on a scratch copy, so the
    /// caller's bytes are safe and the same routine serves sealing and verification.
    fn digest(&self, pdu: &[u8], value_start: usize) -> Option<Vec<u8>> {
        let l = self.layout()?;
        let mut scratch = pdu.to_vec();
        let at = value_start + 1 + l.key_id_len;
        scratch[at..at + l.digest_len].copy_from_slice(&digest_placeholder(l.digest_len, l.apad));
        if is_lsp(&scratch) {
            scratch[LSP_LIFETIME].fill(0);
            scratch[LSP_CHECKSUM].fill(0);
        }
        Some(match self {
            Self::Cleartext(_) => return None,
            Self::HmacMd5 { key } => hmac_md5(key, &scratch).to_vec(),
            Self::HmacSha256 { key, .. } => hmac_sha256(key, &scratch).to_vec(),
        })
    }

    /// The Authentication TLV's value, but only if it is a well-formed one for
    /// *this* scheme — so neither sealing nor verification can index past a short
    /// TLV, and a PDU authenticated under the other scheme is rejected outright.
    fn crypto_value_range(&self, pdu: &[u8]) -> Option<std::ops::Range<usize>> {
        let l = self.layout()?;
        let v = auth_tlv_range(pdu)?;
        (v.len() == 1 + l.key_id_len + l.digest_len && pdu[v.start] == self.auth_type())
            .then_some(v)
    }
}

/// The digest field as it stands before sealing and, identically, as it is refilled
/// before hashing: RFC 5304 §3 wants zeros, RFC 5310 §3.3 wants Apad — `0x878FE1F3`
/// repeated to the digest length. Unlike the OSPFv3 variant of the same idea
/// (RFC 7166 §4.5), the IS-IS Apad carries no address prefix.
fn digest_placeholder(len: usize, apad: bool) -> Vec<u8> {
    let mut v = vec![0u8; len];
    if apad {
        for chunk in v.chunks_exact_mut(4) {
            chunk.copy_from_slice(&0x878F_E1F3u32.to_be_bytes());
        }
    }
    v
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

    /// The same secret under the older scheme, so tests can prove the two do not
    /// authenticate each other.
    fn hmac_md5_auth() -> IsisAuth {
        IsisAuth::HmacMd5 {
            key: b"s3cret".to_vec(),
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
        let v = a.crypto_value_range(&pdu).expect("a crypto auth TLV");
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
        // Gotcha 4: encode() checksummed the placeholder, so seal() must recompute it
        // or every neighbour drops the LSP before ever authenticating.
        for a in [auth(), hmac_md5_auth()] {
            let mut pdu = lsp_bytes(&a, 1200, 5);
            a.seal(&mut pdu);
            assert!(
                crate::fletcher16_valid(&pdu[LSP_CSUM_REGION..]),
                "the checksum survives the digest write"
            );
            assert!(Pdu::decode(&pdu).is_ok(), "and the PDU still decodes");
            assert!(a.verify(&pdu));
        }
    }

    #[test]
    fn hmac_md5_zeroes_the_digest_field_where_sha256_apads_it_rfc5304() {
        // Gotcha 1, the one a copy-paste between the two schemes silently gets wrong.
        // RFC 5304 §3 hashes the PDU "with the Authentication Value field ... set to
        // zero"; RFC 5310 §3.3 fills the same field with Apad instead.
        let md5 = hmac_md5_auth();
        assert_eq!(md5.placeholder(), vec![0u8; MD5_DIGEST_LEN]);

        let sha = auth();
        let ph = sha.placeholder();
        assert_eq!(&ph[..KEY_ID_LEN], &7u16.to_be_bytes(), "the Key ID leads");
        assert!(ph[KEY_ID_LEN..]
            .chunks_exact(4)
            .all(|c| c == 0x878F_E1F3u32.to_be_bytes()));

        // And the digest really is taken over a zero-filled field: rebuild the hash
        // input here, independently of `digest()`, and compare.
        let mut pdu = hello_bytes(auth_tlv(&md5));
        md5.seal(&mut pdu);
        let v = md5.crypto_value_range(&pdu).expect("an hmac-md5 auth TLV");
        let mut input = pdu.clone();
        input[v.start + 1..v.end].fill(0);
        assert_eq!(
            &pdu[v.start + 1..v.end],
            &hmac_md5(b"s3cret", &input)[..],
            "RFC 5304 hashes a zeroed Authentication Value"
        );
    }

    #[test]
    fn the_two_crypto_schemes_do_not_satisfy_each_other() {
        // Same secret, different scheme: a router configured for one must reject the
        // other outright rather than fall back to it.
        let md5 = hmac_md5_auth();
        let sha = auth();
        let mut m = hello_bytes(auth_tlv(&md5));
        md5.seal(&mut m);
        let mut s = hello_bytes(auth_tlv(&sha));
        sha.seal(&mut s);

        assert!(md5.verify(&m) && sha.verify(&s), "each verifies its own");
        assert!(!sha.verify(&m), "an HMAC-MD5 PDU does not satisfy HMAC-SHA-256");
        assert!(!md5.verify(&s), "nor the other way round");

        // Truncated input of every length must be rejected, never indexed past.
        for n in 0..m.len() {
            assert!(!md5.verify(&m[..n]));
            md5.seal(&mut m.clone()[..n]);
        }
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
