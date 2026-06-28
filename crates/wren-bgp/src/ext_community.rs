//! BGP extended communities (RFC 4360, with the 4-octet AS form of RFC 5668) —
//! the 8-octet tags carried in the EXTENDED_COMMUNITIES path attribute, and their
//! textual `rt:`/`ro:` form.
//!
//! An extended community is 8 bytes: a 1-byte **type**, usually a 1-byte
//! **sub-type**, then a 6-byte value. The two sub-types that matter in practice
//! are **Route Target** (`rt`) and **Route Origin** (`ro`), carried in one of
//! three structured forms depending on the administrator field:
//!
//! | Form | Type | Admin | Value | Text |
//! |---|---|---|---|---|
//! | Two-octet AS specific | `0x00` | 2-byte AS | 4-byte | `rt:65001:100` |
//! | IPv4 address specific | `0x01` | 4-byte IPv4 | 2-byte | `rt:192.0.2.1:100` |
//! | Four-octet AS specific (RFC 5668) | `0x02` | 4-byte AS | 2-byte | `rt:65536:100` |
//!
//! We keep the raw 8 bytes so *any* extended community round-trips on the wire;
//! the parser/formatter understand the three RT/RO forms above and fall back to a
//! plain `0x…` hex form for everything else.

use std::net::Ipv4Addr;

/// One extended community: the raw 8 octets, exactly as on the wire.
pub type ExtCommunity = [u8; 8];

/// Sub-type for a Route Target.
pub const SUBTYPE_ROUTE_TARGET: u8 = 0x02;
/// Sub-type for a Route Origin (a.k.a. Site of Origin).
pub const SUBTYPE_ROUTE_ORIGIN: u8 = 0x03;

const TYPE_TWO_OCTET_AS: u8 = 0x00;
const TYPE_IPV4: u8 = 0x01;
const TYPE_FOUR_OCTET_AS: u8 = 0x02;

/// Parse an extended community from text. Understands `rt:<admin>:<value>` and
/// `ro:<admin>:<value>` where `<admin>` is a 2- or 4-octet AS or an IPv4 address
/// (selecting the encoding per RFC 4360 / RFC 5668), plus a raw `0x<16 hex>` form.
/// Returns `None` if it is malformed.
pub fn parse_ext_community(s: &str) -> Option<ExtCommunity> {
    let s = s.trim();
    // Raw hex form: 0x + 16 hex digits.
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        if hex.len() != 16 {
            return None;
        }
        let mut out = [0u8; 8];
        for (i, b) in out.iter_mut().enumerate() {
            *b = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).ok()?;
        }
        return Some(out);
    }

    let (kind, rest) = s.split_once(':')?;
    let subtype = match kind.to_ascii_lowercase().as_str() {
        "rt" => SUBTYPE_ROUTE_TARGET,
        "ro" | "soo" => SUBTYPE_ROUTE_ORIGIN,
        _ => return None,
    };
    let (admin, value) = rest.split_once(':')?;

    if let Ok(ip) = admin.parse::<Ipv4Addr>() {
        // IPv4 address specific: 4-byte IPv4 + 2-byte value.
        let v: u16 = value.parse().ok()?;
        let mut out = [0u8; 8];
        out[0] = TYPE_IPV4;
        out[1] = subtype;
        out[2..6].copy_from_slice(&ip.octets());
        out[6..8].copy_from_slice(&v.to_be_bytes());
        return Some(out);
    }

    let asn: u32 = admin.parse().ok()?;
    let mut out = [0u8; 8];
    out[1] = subtype;
    if asn <= u16::MAX as u32 {
        // Two-octet AS specific: 2-byte AS + 4-byte value.
        let v: u32 = value.parse().ok()?;
        out[0] = TYPE_TWO_OCTET_AS;
        out[2..4].copy_from_slice(&(asn as u16).to_be_bytes());
        out[4..8].copy_from_slice(&v.to_be_bytes());
    } else {
        // Four-octet AS specific (RFC 5668): 4-byte AS + 2-byte value.
        let v: u16 = value.parse().ok()?;
        out[0] = TYPE_FOUR_OCTET_AS;
        out[2..6].copy_from_slice(&asn.to_be_bytes());
        out[6..8].copy_from_slice(&v.to_be_bytes());
    }
    Some(out)
}

/// Format an extended community as text: a `rt:`/`ro:` form for the recognised
/// Route Target / Route Origin encodings, else a plain `0x<16 hex>`.
pub fn format_ext_community(c: ExtCommunity) -> String {
    let prefix = match c[1] {
        SUBTYPE_ROUTE_TARGET => "rt",
        SUBTYPE_ROUTE_ORIGIN => "ro",
        _ => return hex(c),
    };
    match c[0] {
        TYPE_TWO_OCTET_AS => {
            let asn = u16::from_be_bytes([c[2], c[3]]);
            let v = u32::from_be_bytes([c[4], c[5], c[6], c[7]]);
            format!("{prefix}:{asn}:{v}")
        }
        TYPE_IPV4 => {
            let ip = Ipv4Addr::new(c[2], c[3], c[4], c[5]);
            let v = u16::from_be_bytes([c[6], c[7]]);
            format!("{prefix}:{ip}:{v}")
        }
        TYPE_FOUR_OCTET_AS => {
            let asn = u32::from_be_bytes([c[2], c[3], c[4], c[5]]);
            let v = u16::from_be_bytes([c[6], c[7]]);
            format!("{prefix}:{asn}:{v}")
        }
        _ => hex(c),
    }
}

fn hex(c: ExtCommunity) -> String {
    let mut s = String::from("0x");
    for b in c {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn two_octet_as_route_target() {
        let c = parse_ext_community("rt:65001:100").unwrap();
        assert_eq!(c, [0x00, 0x02, 0xFD, 0xE9, 0x00, 0x00, 0x00, 0x64]);
        assert_eq!(format_ext_community(c), "rt:65001:100");
    }

    #[test]
    fn four_octet_as_route_target() {
        // AS > 65535 selects the four-octet form (RFC 5668), 2-byte value.
        let c = parse_ext_community("rt:65536:100").unwrap();
        assert_eq!(c, [0x02, 0x02, 0x00, 0x01, 0x00, 0x00, 0x00, 0x64]);
        assert_eq!(format_ext_community(c), "rt:65536:100");
    }

    #[test]
    fn ipv4_route_origin() {
        let c = parse_ext_community("ro:192.0.2.1:100").unwrap();
        assert_eq!(c, [0x01, 0x03, 192, 0, 2, 1, 0x00, 0x64]);
        assert_eq!(format_ext_community(c), "ro:192.0.2.1:100");
    }

    #[test]
    fn raw_hex_round_trips_unknown_types() {
        let c = parse_ext_community("0x4300000000000001").unwrap();
        assert_eq!(format_ext_community(c), "0x4300000000000001");
    }

    #[test]
    fn rejects_garbage_and_overflow() {
        assert_eq!(parse_ext_community("rt:65001"), None); // missing value
        assert_eq!(parse_ext_community("xx:1:2"), None); // bad kind
        assert_eq!(parse_ext_community("rt:65536:99999"), None); // 4-octet form, value > u16
        assert_eq!(parse_ext_community("rt:192.0.2.1:99999"), None); // IPv4 form, value > u16
        assert_eq!(parse_ext_community("0x1234"), None); // wrong hex length
    }

    #[test]
    fn formats_round_trip() {
        for s in ["rt:65001:100", "ro:65001:0", "rt:65536:1", "ro:192.0.2.1:42"] {
            let c = parse_ext_community(s).unwrap();
            assert_eq!(parse_ext_community(&format_ext_community(c)), Some(c));
        }
    }
}
