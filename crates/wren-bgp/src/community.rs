//! BGP communities (RFC 1997) — the 32-bit tags carried in the COMMUNITIES path
//! attribute, their well-known values, and the textual `asn:value` form.
//!
//! A community is a 32-bit value, conventionally written `ASN:value` (the high
//! and low 16 bits). The reserved `0xFFFFFFxx` range holds the well-known
//! communities that change a route's propagation.

/// `NO_EXPORT` — do not advertise this route outside the local AS (to eBGP
/// peers / confederation boundary).
pub const NO_EXPORT: u32 = 0xFFFF_FF01;
/// `NO_ADVERTISE` — do not advertise this route to any peer.
pub const NO_ADVERTISE: u32 = 0xFFFF_FF02;
/// `NO_EXPORT_SUBCONFED` — do not advertise outside the local sub-confederation
/// (i.e. not to any eBGP peer, including confederation peers).
pub const NO_EXPORT_SUBCONFED: u32 = 0xFFFF_FF03;

/// Parse a community from text: a well-known name (`no-export`, `no-advertise`,
/// `no-export-subconfed`), the plain 32-bit integer, or the conventional
/// `asn:value` (two 16-bit halves). Returns `None` if it is malformed.
pub fn parse_community(s: &str) -> Option<u32> {
    match s.trim().to_ascii_lowercase().as_str() {
        "no-export" => return Some(NO_EXPORT),
        "no-advertise" => return Some(NO_ADVERTISE),
        "no-export-subconfed" => return Some(NO_EXPORT_SUBCONFED),
        _ => {}
    }
    let s = s.trim();
    if let Some((hi, lo)) = s.split_once(':') {
        let hi: u16 = hi.parse().ok()?;
        let lo: u16 = lo.parse().ok()?;
        Some((hi as u32) << 16 | lo as u32)
    } else {
        // A bare 32-bit value (decimal).
        s.parse::<u32>().ok()
    }
}

/// Format a community as text: a well-known name where one applies, else the
/// conventional `asn:value`.
pub fn format_community(c: u32) -> String {
    match c {
        NO_EXPORT => "no-export".to_string(),
        NO_ADVERTISE => "no-advertise".to_string(),
        NO_EXPORT_SUBCONFED => "no-export-subconfed".to_string(),
        _ => format!("{}:{}", c >> 16, c & 0xFFFF),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_asn_value_form() {
        assert_eq!(parse_community("65001:100"), Some(0xFDE9_0064));
        assert_eq!(parse_community("0:0"), Some(0));
        assert_eq!(parse_community("65535:65535"), Some(0xFFFF_FFFF));
    }

    #[test]
    fn parses_well_known_names_case_insensitively() {
        assert_eq!(parse_community("no-export"), Some(NO_EXPORT));
        assert_eq!(parse_community("NO-ADVERTISE"), Some(NO_ADVERTISE));
        assert_eq!(parse_community("No-Export-Subconfed"), Some(NO_EXPORT_SUBCONFED));
    }

    #[test]
    fn parses_a_bare_integer() {
        assert_eq!(parse_community("4294967041"), Some(NO_EXPORT));
    }

    #[test]
    fn rejects_garbage() {
        assert_eq!(parse_community("65001:"), None);
        assert_eq!(parse_community("foo"), None);
        assert_eq!(parse_community("65001:99999"), None); // low half overflows u16
        assert_eq!(parse_community("1:2:3"), None);
    }

    #[test]
    fn formats_round_trip() {
        for s in ["65001:100", "no-export", "no-advertise", "no-export-subconfed", "0:42"] {
            let c = parse_community(s).unwrap();
            assert_eq!(parse_community(&format_community(c)), Some(c));
        }
        assert_eq!(format_community(0xFDE9_0064), "65001:100");
    }
}
