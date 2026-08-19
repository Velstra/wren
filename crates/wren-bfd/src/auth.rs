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
                // Replay window (§6.7.3/§6.7.4): the sequence number must lie
                // within 3 × Detect Mult of the last accepted one — from it
                // inclusive for keyed, from one past it for meticulous.
                let ok = match self.rx_seq {
                    None => true, // first authenticated packet seeds the window
                    Some(last) => within_replay_window(
                        last,
                        seq,
                        self.detect_mult,
                        self.cfg.auth_type.meticulous(),
                    ),
                };
                if ok {
                    self.rx_seq = Some(seq);
                }
                ok
            }
        }
    }
}

/// Whether `seq` is inside the replay window that opens at `last`.
///
/// **Serial-number arithmetic, because the sequence space is circular.** RFC 5880
/// §6.7.3 has the sender increment the sequence number "occasionally", and
/// §6.7.4 on every packet — so a long-lived meticulous session at 3 packets a
/// second wraps 2³² in about forty-five years, and one at the 10 ms floor in
/// under a year and a half. What was here compared the numbers directly and
/// bounded the window with `last.saturating_add(..)`, so both halves broke at
/// the wrap: `seq > last` is false for every sequence number after the wrap, and
/// the saturating bound pins the window's top at `u32::MAX` for ever. The
/// session then rejects every authenticated packet its peer sends, permanently,
/// and BFD tears the link down — from one legitimate increment.
///
/// Taking the difference modulo 2³² instead is the standard reading of a
/// circular sequence space (the same arithmetic RFC 1982 describes): a packet
/// one past a wrapped `last` has a delta of 1 whatever the absolute values are,
/// and a replay from far behind has a delta close to 2³², which is outside any
/// window this can produce.
fn within_replay_window(last: u32, seq: u32, detect_mult: u8, meticulous: bool) -> bool {
    // At most 3 × 255 = 765, so the multiply cannot overflow a u32.
    let window = 3 * detect_mult as u32;
    let delta = seq.wrapping_sub(last);
    // Meticulous requires a strict advance; keyed permits the same number again.
    let floor = if meticulous { 1 } else { 0 };
    delta >= floor && delta <= window
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

    /// A keyed-auth packet at a chosen sequence number, with a digest that
    /// verifies. Mirrors `append`, but takes the sequence rather than
    /// incrementing a counter — which is the only way to reach the far end of a
    /// 2³² space in a test.
    fn forge(cfg: &AuthConfig, seq: u32) -> Vec<u8> {
        let ty = cfg.auth_type;
        let dlen = ty.digest_len();
        let mut out = mand().to_vec();
        out[1] |= 1 << 2; // the A bit
        let auth_len = 8 + dlen;
        out[3] = (24 + auth_len) as u8;
        out.push(ty.code());
        out.push(auth_len as u8);
        out.push(cfg.key_id);
        out.push(0); // Reserved
        out.extend_from_slice(&seq.to_be_bytes());
        let digest_off = out.len();
        let mut key = cfg.secret.clone();
        key.resize(dlen, 0);
        out.extend_from_slice(&key);
        let digest = digest_for(ty, &out);
        out[digest_off..digest_off + dlen].copy_from_slice(&digest);
        out
    }

    #[test]
    fn the_replay_window_survives_the_sequence_wrapping_to_zero() {
        // The sequence space is circular, and the window did not know it. The
        // comparison was `seq > last` with a `saturating_add` ceiling, so at the
        // wrap both halves failed at once: every sequence number after the wrap
        // is numerically *below* `last`, and the ceiling had already pinned
        // itself at u32::MAX. The session then rejected every authenticated
        // packet its peer sent, for ever, and BFD tore the link down — from one
        // legitimate increment.
        for ty in [AuthType::MeticulousKeyedSha1, AuthType::KeyedMd5] {
            let c = cfg(ty, b"k");
            let mut rx = c.new_state(3);
            assert!(rx.verify(&forge(&c, u32::MAX)), "{ty:?} seeds at u32::MAX");
            assert!(
                rx.verify(&forge(&c, 0)),
                "{ty:?} refused the packet after the sequence wrapped to 0"
            );
            assert!(rx.verify(&forge(&c, 1)), "{ty:?} refused the one after that");
        }
    }

    /// The window itself, at the edges and across the wrap.
    #[test]
    fn the_replay_window_is_a_circular_range() {
        // 3 × Detect Mult = 9 either side of the wrap.
        for meticulous in [false, true] {
            let floor = u32::from(meticulous);
            assert!(within_replay_window(u32::MAX, u32::MAX.wrapping_add(1), 3, meticulous));
            assert!(within_replay_window(u32::MAX, 8, 3, meticulous), "the far edge, wrapped");
            assert!(!within_replay_window(u32::MAX, 9, 3, meticulous), "one past the far edge");
            // A replay from behind is a huge forward delta, so it is outside.
            assert!(!within_replay_window(0, u32::MAX, 3, meticulous), "a replay was admitted");
            assert!(!within_replay_window(100, 99, 3, meticulous), "an older number was admitted");
            // The same number again: keyed permits it, meticulous does not.
            assert_eq!(within_replay_window(100, 100, 3, meticulous), floor == 0);
        }
    }

    #[test]
    fn wrong_auth_type_is_rejected() {
        let mut tx = cfg(AuthType::KeyedMd5, b"k").new_state(3);
        let bytes = tx.append(&mand());
        let mut rx = cfg(AuthType::KeyedSha1, b"k").new_state(3);
        assert!(!rx.verify(&bytes));
    }

    /// RFC 5880 §4.4 fixes the Simple Password Authentication Section, which
    /// begins immediately after the 24-octet mandatory section: Auth Type 24,
    /// Auth Len 25, Auth Key ID 26, Password 27 onward. Auth Len counts the
    /// whole section including its own three header octets.
    ///
    /// Asserted on the bytes rather than through `verify`, because `append` and
    /// `verify` share this layout: move a field and wren still authenticates
    /// against itself while every other implementation reads the key ID as part
    /// of the password and drops the session.
    #[test]
    fn the_simple_password_section_matches_the_rfc_field_order() {
        let mut tx = cfg(AuthType::SimplePassword, b"hunter2").new_state(3);
        let b = tx.append(&mand());
        assert_eq!(b[1] & 0x04, 0x04, "the A bit is set in byte 1 of the header");
        assert_eq!(b[3] as usize, b.len(), "the header Length now covers the section");
        assert_eq!(b[24], 1, "Auth Type is byte 24; Simple Password is 1");
        assert_eq!(b[25], 3 + 7, "Auth Len is byte 26 and counts its own 3 octets");
        assert_eq!(b[26], 7, "Auth Key ID is byte 26");
        assert_eq!(&b[27..], b"hunter2", "the password starts at byte 27");
        assert_eq!(b.len(), 24 + 3 + 7);
    }

    /// RFC 5880 §4.3/§4.4 fix the Keyed MD5 and SHA1 sections: Auth Type 24,
    /// Auth Len 25, Auth Key ID 26, Reserved 27 (must be zero), Sequence Number
    /// 28..32 big-endian, then the digest from byte 32. Auth Len is
    /// 8 + digest length — 24 for MD5, 28 for SHA1.
    ///
    /// The sequence number is the replay defence (§6.7.3). Land it at the wrong
    /// offset and a peer reads four bytes of the digest as the sequence: every
    /// packet looks like a wild jump, the receiver's window rejects the lot, and
    /// the authenticated session never comes up at all.
    #[test]
    fn a_keyed_digest_section_matches_the_rfc_field_order() {
        for (ty, code, dlen) in [
            (AuthType::KeyedMd5, 2u8, 16usize),
            (AuthType::MeticulousKeyedMd5, 3, 16),
            (AuthType::KeyedSha1, 4, 20),
            (AuthType::MeticulousKeyedSha1, 5, 20),
        ] {
            let mut tx = cfg(ty, b"sharedsecret").new_state(3);
            tx.xmit_seq = 0x0102_0303; // append bumps it to ...04
            let b = tx.append(&mand());
            assert_eq!(ty.code(), code, "{ty:?} is auth type code {code}");
            assert_eq!(b[1] & 0x04, 0x04, "the A bit is set");
            assert_eq!(b[3] as usize, b.len(), "the header Length covers the section");
            assert_eq!(b[24], code, "Auth Type is byte 24");
            assert_eq!(b[25] as usize, 8 + dlen, "Auth Len is byte 25 = 8 + digest len");
            assert_eq!(b[26], 7, "Auth Key ID is byte 26");
            assert_eq!(b[27], 0, "byte 27 is Reserved and must be zero");
            assert_eq!(
                &b[28..32],
                &[0x01, 0x02, 0x03, 0x04],
                "the Sequence Number is bytes 28..32, big-endian, incremented on send"
            );
            assert_eq!(b.len(), 24 + 8 + dlen, "the digest occupies the last {dlen} octets");
            // The digest field is not the raw key: the key is only the seed
            // written into that field before hashing (§4.3).
            let mut key = b"sharedsecret".to_vec();
            key.resize(dlen, 0);
            assert_ne!(&b[32..], &key[..], "byte 32 onward is the digest, not the key");
        }
    }

    /// RFC 5880 §4.3: the digest is computed over the whole datagram *with the
    /// shared key sitting in the digest field*, zero-padded or truncated to the
    /// digest length. That is unusual enough that a self-consistent
    /// implementation is easy to get wrong and impossible to notice — both ends
    /// of a wren-to-wren session would agree on any other construction.
    ///
    /// Rebuilt here independently of `append`, so a change to the construction
    /// shows up as a mismatch rather than as silent non-interoperability.
    #[test]
    fn the_keyed_md5_digest_is_taken_over_the_packet_with_the_key_in_its_own_field() {
        let mut tx = cfg(AuthType::KeyedMd5, b"sharedsecret").new_state(3);
        let b = tx.append(&mand());
        // Rebuild the pre-digest image: everything as sent, but with the key
        // (padded to 16) in place of the digest.
        let mut image = b[..32].to_vec();
        let mut key = b"sharedsecret".to_vec();
        key.resize(16, 0);
        image.extend_from_slice(&key);
        assert_eq!(image.len(), b.len());
        assert_eq!(&b[32..], &md5(&image)[..], "the digest must match §4.3's construction");
        // And it really covers the mandatory section: flipping My Discriminator
        // changes the digest.
        let mut other = image.clone();
        other[7] ^= 0xff;
        assert_ne!(md5(&other), md5(&image));
    }
}
