//! VRRP version 3 advertisement wire codec (RFC 5798 §5.1).
//!
//! ```text
//!  0                   1                   2                   3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |Version| Type  | Virtual Rtr ID|   Priority    |Count IPvX Addr|
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |(rsvd) |     Max Adver Int     |          Checksum             |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                       IPvX Address(es)                        |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! ```
//!
//! The 16-bit checksum is the standard internet checksum over the VRRP message
//! **prepended with the IPv4 or IPv6 pseudo-header** (RFC 5798 §5.2.8) — unlike the
//! older VRRPv2, where it covered the message alone.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// IANA protocol number for VRRP (carried in the IP header's protocol field).
pub const VRRP_PROTO: u8 = 112;
/// The only protocol version this crate speaks (RFC 5798).
pub const VERSION: u8 = 3;
/// The only message type defined: an advertisement.
pub const TYPE_ADVERTISEMENT: u8 = 1;
/// The IPv4 VRRP multicast group (`224.0.0.18`).
pub const MCAST_V4: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 18);
/// The IPv6 VRRP multicast group (`ff02::12`).
pub const MCAST_V6: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0x12);

/// The fixed part of an advertisement, before the address list.
const HEADER_LEN: usize = 8;

/// Why an advertisement failed to decode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodeError {
    /// Buffer shorter than the 8-byte header (or the declared address list).
    Short,
    /// Protocol version is not 3.
    Version(u8),
    /// Message type is not Advertisement (1).
    Type(u8),
}

impl std::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DecodeError::Short => write!(f, "advertisement truncated"),
            DecodeError::Version(v) => write!(f, "unsupported VRRP version {v}"),
            DecodeError::Type(t) => write!(f, "unsupported VRRP message type {t}"),
        }
    }
}

impl std::error::Error for DecodeError {}

/// A decoded (or to-be-encoded) VRRP advertisement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Advertisement {
    /// Virtual Router ID (1–255) — identifies the virtual router on the link.
    pub vrid: u8,
    /// Sender's priority for the virtual router. 255 = the address owner; 0 is sent
    /// once by a master that is releasing the address; 1–254 otherwise.
    pub priority: u8,
    /// The master's advertisement interval, in **centiseconds** (12-bit).
    pub max_adver_int_cs: u16,
    /// The virtual IP address(es), all of one family.
    pub addresses: Vec<IpAddr>,
}

impl Advertisement {
    /// Encode the advertisement, computing the checksum from the IP `src`/`dst` the
    /// datagram will carry (`dst` is the VRRP multicast group). `src` and `dst` must
    /// share the family of `addresses`.
    pub fn encode(&self, src: IpAddr, dst: IpAddr) -> Vec<u8> {
        let mut b = Vec::with_capacity(HEADER_LEN + self.addresses.len() * 16);
        b.push((VERSION << 4) | TYPE_ADVERTISEMENT);
        b.push(self.vrid);
        b.push(self.priority);
        b.push(self.addresses.len() as u8);
        // rsvd (4 bits, zero) + max adver int (12 bits).
        b.extend_from_slice(&(self.max_adver_int_cs & 0x0fff).to_be_bytes());
        b.extend_from_slice(&[0, 0]); // checksum placeholder
        for a in &self.addresses {
            match a {
                IpAddr::V4(v4) => b.extend_from_slice(&v4.octets()),
                IpAddr::V6(v6) => b.extend_from_slice(&v6.octets()),
            }
        }
        let ck = checksum(src, dst, &b);
        b[6..8].copy_from_slice(&ck.to_be_bytes());
        b
    }

    /// Decode an advertisement. `ipv6` selects the address-family of the address
    /// list (the runner knows it from the receiving socket / IP header — the wire
    /// format alone is ambiguous between four 4-byte and 16-byte addresses).
    pub fn decode(buf: &[u8], ipv6: bool) -> Result<Advertisement, DecodeError> {
        if buf.len() < HEADER_LEN {
            return Err(DecodeError::Short);
        }
        let version = buf[0] >> 4;
        if version != VERSION {
            return Err(DecodeError::Version(version));
        }
        let typ = buf[0] & 0x0f;
        if typ != TYPE_ADVERTISEMENT {
            return Err(DecodeError::Type(typ));
        }
        let vrid = buf[1];
        let priority = buf[2];
        let count = buf[3] as usize;
        let max_adver_int_cs = u16::from_be_bytes([buf[4], buf[5]]) & 0x0fff;
        let addr_len = if ipv6 { 16 } else { 4 };
        let need = HEADER_LEN + count * addr_len;
        if buf.len() < need {
            return Err(DecodeError::Short);
        }
        let mut addresses = Vec::with_capacity(count);
        let mut off = HEADER_LEN;
        for _ in 0..count {
            let slice = &buf[off..off + addr_len];
            let addr = if ipv6 {
                let mut o = [0u8; 16];
                o.copy_from_slice(slice);
                IpAddr::V6(Ipv6Addr::from(o))
            } else {
                let mut o = [0u8; 4];
                o.copy_from_slice(slice);
                IpAddr::V4(Ipv4Addr::from(o))
            };
            addresses.push(addr);
            off += addr_len;
        }
        Ok(Advertisement {
            vrid,
            priority,
            max_adver_int_cs,
            addresses,
        })
    }

    /// Verify the on-the-wire checksum of a received message against the IP
    /// `src`/`dst` it arrived with.
    pub fn verify_checksum(buf: &[u8], src: IpAddr, dst: IpAddr) -> bool {
        // A correct checksum makes the full ones-complement sum (pseudo-header +
        // message, checksum field included) fold to zero.
        fold_to_zero(src, dst, buf)
    }
}

/// Compute the VRRP checksum over the pseudo-header + `msg` (whose checksum field
/// must be zero).
fn checksum(src: IpAddr, dst: IpAddr, msg: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    accumulate_pseudo(&mut sum, src, dst, msg.len());
    sum16(msg, &mut sum);
    fold(sum)
}

/// Whether pseudo-header + `buf` (checksum field intact) sum to the all-ones word,
/// i.e. the checksum is valid.
fn fold_to_zero(src: IpAddr, dst: IpAddr, buf: &[u8]) -> bool {
    let mut sum: u32 = 0;
    accumulate_pseudo(&mut sum, src, dst, buf.len());
    sum16(buf, &mut sum);
    fold(sum) == 0
}

/// Add the IPv4/IPv6 pseudo-header words for an `vrrp_len`-byte VRRP message to
/// `sum`. A mismatched src/dst family contributes nothing (the caller guarantees a
/// matched pair in practice).
fn accumulate_pseudo(sum: &mut u32, src: IpAddr, dst: IpAddr, vrrp_len: usize) {
    match (src, dst) {
        (IpAddr::V4(s), IpAddr::V4(d)) => {
            sum16(&s.octets(), sum);
            sum16(&d.octets(), sum);
            // zero(1) || protocol(1) || length(2)
            *sum += u16::from_be_bytes([0, VRRP_PROTO]) as u32;
            *sum += vrrp_len as u32;
        }
        (IpAddr::V6(s), IpAddr::V6(d)) => {
            sum16(&s.octets(), sum);
            sum16(&d.octets(), sum);
            // upper-layer packet length (4 octets) || zero(3) || next-header(1)
            *sum += vrrp_len as u32;
            *sum += VRRP_PROTO as u32;
        }
        _ => {}
    }
}

/// Add `buf` as 16-bit big-endian words to `sum` (odd final byte is the high byte).
fn sum16(buf: &[u8], sum: &mut u32) {
    let mut i = 0;
    while i + 1 < buf.len() {
        *sum += u16::from_be_bytes([buf[i], buf[i + 1]]) as u32;
        i += 2;
    }
    if i < buf.len() {
        *sum += (buf[i] as u32) << 8;
    }
}

/// Fold the 32-bit accumulator to a 16-bit ones-complement checksum.
fn fold(mut sum: u32) -> u16 {
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v4(s: &str) -> IpAddr {
        IpAddr::V4(s.parse().unwrap())
    }
    fn v6(s: &str) -> IpAddr {
        IpAddr::V6(s.parse().unwrap())
    }

    #[test]
    fn ipv4_advertisement_roundtrips_and_checksum_verifies() {
        let adv = Advertisement {
            vrid: 51,
            priority: 200,
            max_adver_int_cs: 100,
            addresses: vec![v4("10.0.0.254")],
        };
        let src = v4("10.0.0.1");
        let dst = IpAddr::V4(MCAST_V4);
        let bytes = adv.encode(src, dst);
        assert_eq!(bytes.len(), HEADER_LEN + 4);
        assert_eq!(bytes[0], (VERSION << 4) | TYPE_ADVERTISEMENT);
        assert!(Advertisement::verify_checksum(&bytes, src, dst));
        // A flipped byte breaks verification.
        let mut bad = bytes.clone();
        bad[2] ^= 0xff;
        assert!(!Advertisement::verify_checksum(&bad, src, dst));

        let back = Advertisement::decode(&bytes, false).unwrap();
        assert_eq!(back, adv);
    }

    #[test]
    fn ipv6_advertisement_roundtrips_and_checksum_verifies() {
        let adv = Advertisement {
            vrid: 7,
            priority: 100,
            max_adver_int_cs: 100,
            addresses: vec![v6("2001:db8::1"), v6("fe80::1")],
        };
        let src = v6("fe80::abcd");
        let dst = IpAddr::V6(MCAST_V6);
        let bytes = adv.encode(src, dst);
        assert_eq!(bytes.len(), HEADER_LEN + 32);
        assert!(Advertisement::verify_checksum(&bytes, src, dst));
        let back = Advertisement::decode(&bytes, true).unwrap();
        assert_eq!(back, adv);
    }

    #[test]
    fn decode_rejects_bad_version_type_and_truncation() {
        let adv = Advertisement {
            vrid: 1,
            priority: 100,
            max_adver_int_cs: 100,
            addresses: vec![v4("10.0.0.1")],
        };
        let bytes = adv.encode(v4("10.0.0.2"), IpAddr::V4(MCAST_V4));
        // Wrong version.
        let mut wrong = bytes.clone();
        wrong[0] = (2 << 4) | TYPE_ADVERTISEMENT;
        assert_eq!(Advertisement::decode(&wrong, false), Err(DecodeError::Version(2)));
        // Wrong type.
        let mut wt = bytes.clone();
        wt[0] = (VERSION << 4) | 2;
        assert_eq!(Advertisement::decode(&wt, false), Err(DecodeError::Type(2)));
        // Truncated header.
        assert_eq!(Advertisement::decode(&bytes[..5], false), Err(DecodeError::Short));
        // Count says one address but the list is missing.
        assert_eq!(Advertisement::decode(&bytes[..HEADER_LEN], false), Err(DecodeError::Short));
    }

    #[test]
    fn max_adver_int_is_masked_to_twelve_bits() {
        let adv = Advertisement {
            vrid: 1,
            priority: 100,
            max_adver_int_cs: 0x0fff,
            addresses: vec![v4("10.0.0.1")],
        };
        let bytes = adv.encode(v4("10.0.0.2"), IpAddr::V4(MCAST_V4));
        // Top nibble of the rsvd/interval field stays zero.
        assert_eq!(bytes[4] & 0xf0, 0);
        assert_eq!(Advertisement::decode(&bytes, false).unwrap().max_adver_int_cs, 0x0fff);
    }
}
