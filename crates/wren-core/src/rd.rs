//! Route Distinguishers (RFC 4364 §4.2).
//!
//! An 8-octet value that makes a VRF's routes globally unique so the same IP prefix
//! can appear in several VRFs without colliding. Three encodings, distinguished by a
//! 2-octet Type field:
//!
//! * **Type 0** — `<2-octet AS> : <4-octet number>`, e.g. `65000:1`.
//! * **Type 1** — `<4-octet IPv4> : <2-octet number>`, e.g. `192.0.2.1:1`.
//! * **Type 2** — `<4-octet AS> : <2-octet number>`, e.g. `4200000000:1`.
//!
//! Wren uses the RD as a VRF's identity (shown by `show vrf`); it is the same wire
//! shape as a BGP Route Target extended community but a distinct field.

use std::fmt;
use std::net::Ipv4Addr;

/// A Route Distinguisher: the raw 8 octets, with the Type field in the first two.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct RouteDistinguisher(pub [u8; 8]);

impl RouteDistinguisher {
    /// Parse the `admin:assigned` text form (RFC 4364 §4.2). The administrator part
    /// selects the type: a dotted-quad is Type 1; a number ≤ 65535 is Type 0; a
    /// larger number is Type 2. Returns `None` for anything that does not fit.
    pub fn parse(s: &str) -> Option<RouteDistinguisher> {
        let (admin, assigned) = s.split_once(':')?;
        let mut out = [0u8; 8];
        if let Ok(ip) = admin.parse::<Ipv4Addr>() {
            // Type 1: 4-octet IPv4 admin, 2-octet assigned.
            let num: u16 = assigned.parse().ok()?;
            out[0..2].copy_from_slice(&1u16.to_be_bytes());
            out[2..6].copy_from_slice(&ip.octets());
            out[6..8].copy_from_slice(&num.to_be_bytes());
            return Some(RouteDistinguisher(out));
        }
        let asn: u32 = admin.parse().ok()?;
        if asn <= u16::MAX as u32 {
            // Type 0: 2-octet AS admin, 4-octet assigned.
            let num: u32 = assigned.parse().ok()?;
            out[0..2].copy_from_slice(&0u16.to_be_bytes());
            out[2..4].copy_from_slice(&(asn as u16).to_be_bytes());
            out[4..8].copy_from_slice(&num.to_be_bytes());
        } else {
            // Type 2: 4-octet AS admin, 2-octet assigned.
            let num: u16 = assigned.parse().ok()?;
            out[0..2].copy_from_slice(&2u16.to_be_bytes());
            out[2..6].copy_from_slice(&asn.to_be_bytes());
            out[6..8].copy_from_slice(&num.to_be_bytes());
        }
        Some(RouteDistinguisher(out))
    }

    /// The raw 8 octets.
    pub fn to_bytes(self) -> [u8; 8] {
        self.0
    }
}

impl fmt::Display for RouteDistinguisher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let b = self.0;
        let ty = u16::from_be_bytes([b[0], b[1]]);
        match ty {
            0 => {
                let asn = u16::from_be_bytes([b[2], b[3]]);
                let num = u32::from_be_bytes([b[4], b[5], b[6], b[7]]);
                write!(f, "{asn}:{num}")
            }
            1 => {
                let ip = Ipv4Addr::new(b[2], b[3], b[4], b[5]);
                let num = u16::from_be_bytes([b[6], b[7]]);
                write!(f, "{ip}:{num}")
            }
            2 => {
                let asn = u32::from_be_bytes([b[2], b[3], b[4], b[5]]);
                let num = u16::from_be_bytes([b[6], b[7]]);
                write!(f, "{asn}:{num}")
            }
            // Unknown type: print the raw octets rather than guess.
            _ => write!(f, "0x{}", b.iter().map(|x| format!("{x:02x}")).collect::<String>()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn round(s: &str) -> String {
        RouteDistinguisher::parse(s).expect("parses").to_string()
    }

    #[test]
    fn type0_two_octet_as() {
        let rd = RouteDistinguisher::parse("65000:1").unwrap();
        // Type 0, AS 65000 (0xFDE8), assigned 1.
        assert_eq!(rd.to_bytes(), [0, 0, 0xfd, 0xe8, 0, 0, 0, 1]);
        assert_eq!(rd.to_string(), "65000:1");
    }

    #[test]
    fn type1_ipv4() {
        let rd = RouteDistinguisher::parse("192.0.2.1:100").unwrap();
        assert_eq!(rd.to_bytes(), [0, 1, 192, 0, 2, 1, 0, 100]);
        assert_eq!(rd.to_string(), "192.0.2.1:100");
    }

    #[test]
    fn type2_four_octet_as() {
        let rd = RouteDistinguisher::parse("4200000000:7").unwrap();
        // 4200000000 = 0xFA56_EA00.
        assert_eq!(rd.to_bytes(), [0, 2, 0xfa, 0x56, 0xea, 0x00, 0, 7]);
        assert_eq!(rd.to_string(), "4200000000:7");
    }

    #[test]
    fn round_trips() {
        for s in ["0:0", "65535:4294967295", "10.0.0.1:65535", "65536:1"] {
            assert_eq!(round(s), s);
        }
    }

    #[test]
    fn rejects_malformed() {
        assert!(RouteDistinguisher::parse("nope").is_none());
        assert!(RouteDistinguisher::parse("65000").is_none());
        assert!(RouteDistinguisher::parse("65000:notanumber").is_none());
        // Type 0 assigned overflows u32.
        assert!(RouteDistinguisher::parse("65000:4294967296").is_none());
        // Type 2 (4-octet AS) assigned must fit u16.
        assert!(RouteDistinguisher::parse("65536:70000").is_none());
    }
}
