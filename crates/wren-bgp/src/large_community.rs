//! BGP large communities (RFC 8092) — the 12-octet tags carried in the
//! LARGE_COMMUNITY path attribute, and their textual `global:local1:local2` form.
//!
//! A large community is three 32-bit values: a **Global Administrator** (usually
//! the 4-octet ASN that assigned it) and two **Local Data** parts whose meaning is
//! up to that AS. It exists because RFC 1997's 16:16 community cannot hold a
//! 4-octet ASN; the large community gives a 4-octet AS a natural `ASN:function:
//! parameter` tag. Unlike RFC 1997 there are no well-known large communities.

/// One large community: `(global, local1, local2)`.
pub type LargeCommunity = (u32, u32, u32);

/// Parse a large community from its `global:local1:local2` text (three unsigned
/// 32-bit decimals). Returns `None` if it is malformed.
pub fn parse_large_community(s: &str) -> Option<LargeCommunity> {
    let mut parts = s.trim().split(':');
    let global: u32 = parts.next()?.parse().ok()?;
    let local1: u32 = parts.next()?.parse().ok()?;
    let local2: u32 = parts.next()?.parse().ok()?;
    if parts.next().is_some() {
        return None; // more than three parts
    }
    Some((global, local1, local2))
}

/// Format a large community as `global:local1:local2`.
pub fn format_large_community((global, local1, local2): LargeCommunity) -> String {
    format!("{global}:{local1}:{local2}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_the_three_part_form() {
        assert_eq!(parse_large_community("65536:1:2"), Some((65536, 1, 2)));
        assert_eq!(parse_large_community("0:0:0"), Some((0, 0, 0)));
        assert_eq!(
            parse_large_community("4200000000:4294967295:0"),
            Some((4_200_000_000, 4_294_967_295, 0))
        );
    }

    #[test]
    fn rejects_wrong_arity_and_garbage() {
        assert_eq!(parse_large_community("65001:100"), None); // only two parts
        assert_eq!(parse_large_community("1:2:3:4"), None); // four parts
        assert_eq!(parse_large_community("foo:1:2"), None);
        assert_eq!(parse_large_community("65001:100:99999999999"), None); // overflows u32
        assert_eq!(parse_large_community(""), None);
    }

    #[test]
    fn formats_round_trip() {
        for s in ["65536:1:2", "0:0:0", "4200000000:1:4294967295"] {
            let c = parse_large_community(s).unwrap();
            assert_eq!(parse_large_community(&format_large_community(c)), Some(c));
        }
        assert_eq!(format_large_community((65536, 1, 2)), "65536:1:2");
    }
}
