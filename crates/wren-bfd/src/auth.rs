//! BFD authentication (RFC 5880 §4.2–4.4, §6.7).
//!
//! When a session is authenticated, the `A` bit in the Control packet is set and an
//! **Authentication Section** is appended after the 24-octet mandatory section. Wren
//! implements all five RFC 5880 types:
//!
//! * **Simple Password** (type 1, §4.2) — a cleartext key id + password.
//! * **Keyed MD5 / Meticulous Keyed MD5** (types 2/3, §4.3) — a 16-octet MD5 digest
//!   over the whole packet with a shared key, plus a sequence number.
//! * **Keyed SHA1 / Meticulous Keyed SHA1** (types 4/5, §4.4) — the same with a
//!   20-octet SHA-1 hash.
//!
//! The *meticulous* variants bump the sequence number on every packet; the plain
//! keyed variants may repeat it. On receive the sequence number must advance within
//! a window of `3 × Detect Mult` to resist replay (§6.7.3/§6.7.4).
//!
//! MD5 and SHA-1 are implemented here from scratch so the crate stays dependency
//! free; both carry test vectors. They are used only for BFD's keyed-digest
//! authentication, never for confidentiality.

/// Which authentication a session uses (RFC 5880 §4.2–4.4).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AuthType {
    /// Simple Password (type 1).
    SimplePassword,
    /// Keyed MD5 (type 2).
    KeyedMd5,
    /// Meticulous Keyed MD5 (type 3).
    MeticulousKeyedMd5,
    /// Keyed SHA1 (type 4).
    KeyedSha1,
    /// Meticulous Keyed SHA1 (type 5).
    MeticulousKeyedSha1,
}

impl AuthType {
    /// The on-the-wire Auth Type code.
    fn code(self) -> u8 {
        match self {
            AuthType::SimplePassword => 1,
            AuthType::KeyedMd5 => 2,
            AuthType::MeticulousKeyedMd5 => 3,
            AuthType::KeyedSha1 => 4,
            AuthType::MeticulousKeyedSha1 => 5,
        }
    }

    /// The digest length in octets for a keyed type (16 for MD5, 20 for SHA1).
    fn digest_len(self) -> usize {
        match self {
            AuthType::KeyedMd5 | AuthType::MeticulousKeyedMd5 => 16,
            AuthType::KeyedSha1 | AuthType::MeticulousKeyedSha1 => 20,
            AuthType::SimplePassword => 0,
        }
    }

    /// Whether the sequence number must strictly advance every packet (§6.7).
    fn meticulous(self) -> bool {
        matches!(self, AuthType::MeticulousKeyedMd5 | AuthType::MeticulousKeyedSha1)
    }
}

/// A session's authentication configuration: the type, the key id sent on the wire,
/// and the shared secret. Cloned into an [`AuthState`] per session.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct AuthConfig {
    /// The authentication type.
    pub auth_type: AuthType,
    /// The key id advertised in the auth section.
    pub key_id: u8,
    /// The shared secret (a password for Simple, the keying material for the digest
    /// types — right-padded with zeros or truncated to the digest length).
    pub secret: Vec<u8>,
}

impl AuthConfig {
    /// Build the per-session mutable auth state. `detect_mult` is this system's local
    /// Detect Mult, used to size the receive replay window.
    pub fn new_state(&self, detect_mult: u8) -> AuthState {
        AuthState {
            cfg: self.clone(),
            detect_mult: detect_mult.max(1),
            // RFC 5880 §6.8.1: the transmit sequence number starts at a random value;
            // any non-zero start works, and we never depend on unpredictability here.
            xmit_seq: 1,
            rx_seq: None,
        }
    }
}

/// The mutable per-session authentication state: the configuration plus the transmit
/// sequence number and the last accepted receive sequence number.
#[derive(Clone, Debug)]
pub struct AuthState {
    cfg: AuthConfig,
    detect_mult: u8,
    xmit_seq: u32,
    rx_seq: Option<u32>,
}

impl AuthState {
    /// Append the Authentication Section to a 24-octet mandatory packet, setting the
    /// `A` bit and the Length field, and (for the digest types) bumping the transmit
    /// sequence number and computing the digest. Returns the full datagram.
    pub fn append(&mut self, mand: &[u8; 24]) -> Vec<u8> {
        let mut out = mand.to_vec();
        out[1] |= 1 << 2; // the A (Authentication Present) bit
        match self.cfg.auth_type {
            AuthType::SimplePassword => {
                let auth_len = 3 + self.cfg.secret.len();
                out[3] = (24 + auth_len) as u8;
                out.push(AuthType::SimplePassword.code());
                out.push(auth_len as u8);
                out.push(self.cfg.key_id);
                out.extend_from_slice(&self.cfg.secret);
            }
            ty => {
                let dlen = ty.digest_len();
                let auth_len = 8 + dlen; // type+len+keyid+reserved+seq(4) = 8
                out[3] = (24 + auth_len) as u8;
                self.xmit_seq = self.xmit_seq.wrapping_add(1);
                out.push(ty.code());
                out.push(auth_len as u8);
                out.push(self.cfg.key_id);
                out.push(0); // Reserved
                out.extend_from_slice(&self.xmit_seq.to_be_bytes());
                let digest_off = out.len();
                // The digest is computed with the shared key in the digest field.
                let mut key = self.cfg.secret.clone();
                key.resize(dlen, 0);
                out.extend_from_slice(&key);
                let digest = digest_for(ty, &out);
                out[digest_off..digest_off + dlen].copy_from_slice(&digest);
            }
        }
        out
    }

    /// Verify the Authentication Section of a received datagram against this session's
    /// configuration, advancing the replay window on success (§6.7.3/§6.7.4). Returns
    /// `false` for a missing, malformed, wrong-type, wrong-key, bad-digest or
    /// out-of-window auth section — the caller then silently discards the packet.
    pub fn verify(&mut self, buf: &[u8]) -> bool {
        // The Length field bounds the auth section after the 24-octet mandatory part.
        if buf.len() < 25 {
            return false;
        }
        let total = buf[3] as usize;
        if total < 26 || total > buf.len() {
            return false;
        }
        let sec = &buf[24..total];
        if sec.len() < 2 || sec[1] as usize != sec.len() {
            return false;
        }
        if sec[0] != self.cfg.auth_type.code() {
            return false;
        }
        match self.cfg.auth_type {
            AuthType::SimplePassword => {
                if sec.len() != 3 + self.cfg.secret.len() {
                    return false;
                }
                sec[2] == self.cfg.key_id && constant_eq(&sec[3..], &self.cfg.secret)
            }
            ty => {
                let dlen = ty.digest_len();
                if sec.len() != 8 + dlen || sec[2] != self.cfg.key_id {
                    return false;
                }
                let seq = u32::from_be_bytes([sec[4], sec[5], sec[6], sec[7]]);
                // Recompute the digest with the shared key in the digest field.
                let mut tmp = buf[..total].to_vec();
                let digest_off = 24 + 8;
                let recv = tmp[digest_off..digest_off + dlen].to_vec();
                let mut key = self.cfg.secret.clone();
                key.resize(dlen, 0);
                tmp[digest_off..digest_off + dlen].copy_from_slice(&key);
                let calc = digest_for(ty, &tmp);
                if !constant_eq(&calc, &recv) {
                    return false;
                }
                // Replay window (§6.7.3): the sequence number must advance within
                // 3 × Detect Mult of the last accepted one (strictly, for meticulous).
                let ok = match self.rx_seq {
                    None => true, // first authenticated packet seeds the window
                    Some(last) => {
                        let advanced = if self.cfg.auth_type.meticulous() {
                            seq > last
                        } else {
                            seq >= last
                        };
                        advanced && seq <= last.saturating_add(3 * self.detect_mult as u32)
                    }
                };
                if ok {
                    self.rx_seq = Some(seq);
                }
                ok
            }
        }
    }
}

/// Compute the digest of a keyed-auth packet under the given type.
fn digest_for(ty: AuthType, data: &[u8]) -> Vec<u8> {
    match ty {
        AuthType::KeyedMd5 | AuthType::MeticulousKeyedMd5 => md5(data).to_vec(),
        AuthType::KeyedSha1 | AuthType::MeticulousKeyedSha1 => sha1(data).to_vec(),
        AuthType::SimplePassword => Vec::new(),
    }
}

/// A length-checked, branch-on-every-byte equality, so a digest/password compare does
/// not leak where it first differs.
fn constant_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

// --- MD5 (RFC 1321) -------------------------------------------------------------

/// The MD5 digest of `msg` (RFC 1321). Used only for BFD keyed authentication.
pub fn md5(msg: &[u8]) -> [u8; 16] {
    const S: [u32; 64] = [
        7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5,
        9, 14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10,
        15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
    ];
    const K: [u32; 64] = [
        0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613,
        0xfd469501, 0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193,
        0xa679438e, 0x49b40821, 0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d,
        0x02441453, 0xd8a1e681, 0xe7d3fbc8, 0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
        0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a, 0xfffa3942, 0x8771f681, 0x6d9d6122,
        0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70, 0x289b7ec6, 0xeaa127fa,
        0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665, 0xf4292244,
        0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
        0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb,
        0xeb86d391,
    ];
    let (mut a0, mut b0, mut c0, mut d0) =
        (0x67452301u32, 0xefcdab89u32, 0x98badcfeu32, 0x10325476u32);

    let mut m = msg.to_vec();
    let bitlen = (msg.len() as u64).wrapping_mul(8);
    m.push(0x80);
    while m.len() % 64 != 56 {
        m.push(0);
    }
    m.extend_from_slice(&bitlen.to_le_bytes());

    for chunk in m.chunks(64) {
        let mut w = [0u32; 16];
        for (i, word) in w.iter_mut().enumerate() {
            *word = u32::from_le_bytes([
                chunk[i * 4],
                chunk[i * 4 + 1],
                chunk[i * 4 + 2],
                chunk[i * 4 + 3],
            ]);
        }
        let (mut a, mut b, mut c, mut d) = (a0, b0, c0, d0);
        for i in 0..64 {
            let (f, g) = if i < 16 {
                ((b & c) | (!b & d), i)
            } else if i < 32 {
                ((d & b) | (!d & c), (5 * i + 1) % 16)
            } else if i < 48 {
                (b ^ c ^ d, (3 * i + 5) % 16)
            } else {
                (c ^ (b | !d), (7 * i) % 16)
            };
            let f = f
                .wrapping_add(a)
                .wrapping_add(K[i])
                .wrapping_add(w[g]);
            a = d;
            d = c;
            c = b;
            b = b.wrapping_add(f.rotate_left(S[i]));
        }
        a0 = a0.wrapping_add(a);
        b0 = b0.wrapping_add(b);
        c0 = c0.wrapping_add(c);
        d0 = d0.wrapping_add(d);
    }
    let mut out = [0u8; 16];
    out[0..4].copy_from_slice(&a0.to_le_bytes());
    out[4..8].copy_from_slice(&b0.to_le_bytes());
    out[8..12].copy_from_slice(&c0.to_le_bytes());
    out[12..16].copy_from_slice(&d0.to_le_bytes());
    out
}

// --- SHA-1 (RFC 3174) -----------------------------------------------------------

/// The SHA-1 hash of `msg` (RFC 3174). Used only for BFD keyed authentication.
pub fn sha1(msg: &[u8]) -> [u8; 20] {
    let mut h: [u32; 5] = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0];
    let mut m = msg.to_vec();
    let bitlen = (msg.len() as u64).wrapping_mul(8);
    m.push(0x80);
    while m.len() % 64 != 56 {
        m.push(0);
    }
    m.extend_from_slice(&bitlen.to_be_bytes());

    for chunk in m.chunks(64) {
        let mut w = [0u32; 80];
        for (i, word) in w.iter_mut().take(16).enumerate() {
            *word = u32::from_be_bytes([
                chunk[i * 4],
                chunk[i * 4 + 1],
                chunk[i * 4 + 2],
                chunk[i * 4 + 3],
            ]);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }
        let (mut a, mut b, mut c, mut d, mut e) = (h[0], h[1], h[2], h[3], h[4]);
        for (i, &wi) in w.iter().enumerate() {
            let (f, k) = if i < 20 {
                ((b & c) | (!b & d), 0x5A827999u32)
            } else if i < 40 {
                (b ^ c ^ d, 0x6ED9EBA1)
            } else if i < 60 {
                ((b & c) | (b & d) | (c & d), 0x8F1BBCDC)
            } else {
                (b ^ c ^ d, 0xCA62C1D6)
            };
            let tmp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(wi);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = tmp;
        }
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
    }
    let mut out = [0u8; 20];
    for (i, word) in h.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    #[test]
    fn md5_known_vectors() {
        assert_eq!(hex(&md5(b"")), "d41d8cd98f00b204e9800998ecf8427e");
        assert_eq!(hex(&md5(b"abc")), "900150983cd24fb0d6963f7d28e17f72");
        assert_eq!(
            hex(&md5(b"The quick brown fox jumps over the lazy dog")),
            "9e107d9d372bb6826bd81d3542a419d6"
        );
    }

    #[test]
    fn sha1_known_vectors() {
        assert_eq!(hex(&sha1(b"")), "da39a3ee5e6b4b0d3255bfef95601890afd80709");
        assert_eq!(hex(&sha1(b"abc")), "a9993e364706816aba3e25717850c26c9cd0d89d");
        assert_eq!(
            hex(&sha1(b"The quick brown fox jumps over the lazy dog")),
            "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12"
        );
    }

    fn mand() -> [u8; 24] {
        // A plausible mandatory section (the exact contents do not matter here).
        let mut b = [0u8; 24];
        b[0] = 0x20; // version 1
        b[1] = 0xc0; // state Up
        b[2] = 3; // detect mult
        b[3] = 24;
        b[4] = 0;
        b[5] = 0;
        b[6] = 0;
        b[7] = 1; // my discr
        b
    }

    fn cfg(ty: AuthType, secret: &[u8]) -> AuthConfig {
        AuthConfig { auth_type: ty, key_id: 7, secret: secret.to_vec() }
    }

    #[test]
    fn simple_password_round_trips_and_rejects_wrong_key() {
        let mut tx = cfg(AuthType::SimplePassword, b"hunter2").new_state(3);
        let bytes = tx.append(&mand());
        // The A bit is set and the Length covers the appended section.
        assert_ne!(bytes[1] & (1 << 2), 0);
        assert_eq!(bytes[3] as usize, bytes.len());
        let mut rx = cfg(AuthType::SimplePassword, b"hunter2").new_state(3);
        assert!(rx.verify(&bytes));
        let mut bad = cfg(AuthType::SimplePassword, b"nope").new_state(3);
        assert!(!bad.verify(&bytes));
    }

    #[test]
    fn keyed_digests_round_trip_and_reject_tampering() {
        for ty in [
            AuthType::KeyedMd5,
            AuthType::MeticulousKeyedMd5,
            AuthType::KeyedSha1,
            AuthType::MeticulousKeyedSha1,
        ] {
            let mut tx = cfg(ty, b"sharedsecret").new_state(3);
            let mut rx = cfg(ty, b"sharedsecret").new_state(3);
            let p1 = tx.append(&mand());
            assert!(rx.verify(&p1), "{ty:?} first packet verifies");
            let p2 = tx.append(&mand());
            assert!(rx.verify(&p2), "{ty:?} second packet verifies (seq advanced)");
            // A flipped digest byte must fail.
            let mut tampered = p2.clone();
            let last = tampered.len() - 1;
            tampered[last] ^= 0x01;
            let mut rx2 = cfg(ty, b"sharedsecret").new_state(3);
            assert!(!rx2.verify(&tampered), "{ty:?} tampered digest rejected");
            // The wrong shared key must fail.
            let mut rxbad = cfg(ty, b"othersecret").new_state(3);
            assert!(!rxbad.verify(&p1), "{ty:?} wrong key rejected");
        }
    }

    #[test]
    fn meticulous_rejects_a_replayed_sequence_number() {
        let mut tx = cfg(AuthType::MeticulousKeyedSha1, b"k").new_state(3);
        let mut rx = cfg(AuthType::MeticulousKeyedSha1, b"k").new_state(3);
        let p1 = tx.append(&mand());
        let p2 = tx.append(&mand());
        assert!(rx.verify(&p1));
        assert!(rx.verify(&p2));
        // Replaying p1 (an older sequence number) is rejected by a meticulous session.
        assert!(!rx.verify(&p1));
    }

    #[test]
    fn wrong_auth_type_is_rejected() {
        let mut tx = cfg(AuthType::KeyedMd5, b"k").new_state(3);
        let bytes = tx.append(&mand());
        let mut rx = cfg(AuthType::KeyedSha1, b"k").new_state(3);
        assert!(!rx.verify(&bytes));
    }
}
