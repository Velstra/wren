//! RPKI route-origin validation (RFC 6811).
//!
//! A [`RoaTable`] holds Validated ROA Payloads (VRPs) — each a [`Roa`] of
//! `{ prefix, max_length, origin_as }` — and classifies a received BGP route
//! `{ prefix, origin AS }` as [`Validity::Valid`], [`Validity::Invalid`] or
//! [`Validity::NotFound`] per the §2 algorithm:
//!
//! * a VRP **covers** a route when its prefix is equal to or less specific than the
//!   route's prefix and contains it (ignoring `max_length` and the AS);
//! * a VRP **matches** a route when it covers it *and* the route's prefix length is
//!   `≤ max_length` *and* the origin AS is equal;
//! * the route is **Valid** if any VRP matches, **Invalid** if some VRP covers but
//!   none matches, and **NotFound** if no VRP covers it.
//!
//! This is the pure validation kernel: ROAs are plain values and validation takes a
//! prefix and an AS, so it is fully unit-testable without sockets or an RTR feed. The
//! ROAs are configured statically here; fetching them live over the RTR protocol
//! (RFC 8210) is a separate transport concern layered on top.

use wren_core::Prefix;

/// One Validated ROA Payload (RFC 6811): an authorisation that `origin_as` may
/// originate `prefix` and any more-specific within it up to `max_length`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Roa {
    /// The authorised prefix.
    pub prefix: Prefix,
    /// The longest prefix length the origin may announce within `prefix`
    /// (`prefix.len() ≤ max_length ≤ 32` for IPv4 / `128` for IPv6).
    pub max_length: u8,
    /// The Autonomous System authorised to originate it (4-octet, RFC 6793). AS 0 is
    /// a valid value that authorises no origin (RFC 6483), so it never `matches` a
    /// real route's origin.
    pub origin_as: u32,
}

/// The origin-validation outcome for a route (RFC 6811 §2).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Validity {
    /// At least one VRP matches the route (covers it, within `max_length`, AS equal).
    Valid,
    /// At least one VRP covers the route's prefix, but none matches (wrong origin AS,
    /// or the prefix is longer than every covering VRP's `max_length`).
    Invalid,
    /// No VRP covers the route's prefix — the prefix is outside RPKI's knowledge.
    NotFound,
}

impl Validity {
    /// The lower-case operator-facing label (`valid` / `invalid` / `notfound`).
    pub fn as_str(self) -> &'static str {
        match self {
            Validity::Valid => "valid",
            Validity::Invalid => "invalid",
            Validity::NotFound => "notfound",
        }
    }
}

/// A set of Validated ROA Payloads to validate routes against (RFC 6811).
#[derive(Clone, Default)]
pub struct RoaTable {
    roas: Vec<Roa>,
}

impl RoaTable {
    /// A table over the given ROAs.
    pub fn new(roas: Vec<Roa>) -> Self {
        Self { roas }
    }

    /// Whether the table holds no ROAs (validation then always returns `NotFound`, so
    /// callers can skip tagging routes when RPKI is effectively unconfigured).
    pub fn is_empty(&self) -> bool {
        self.roas.is_empty()
    }

    /// The number of ROAs in the table.
    pub fn len(&self) -> usize {
        self.roas.len()
    }

    /// Every ROA, in insertion order — for `show bgp roa`.
    pub fn iter(&self) -> impl Iterator<Item = &Roa> {
        self.roas.iter()
    }

    /// Validate a route's `prefix` and `origin_as` against the table (RFC 6811 §2).
    pub fn validate(&self, prefix: &Prefix, origin_as: u32) -> Validity {
        let mut covered = false;
        for roa in &self.roas {
            // "covers": same family, the ROA prefix is equal-or-less-specific, and it
            // contains the route prefix's network address.
            if roa.prefix.is_ipv4() != prefix.is_ipv4()
                || roa.prefix.len() > prefix.len()
                || !roa.prefix.contains(prefix.addr())
            {
                continue;
            }
            covered = true;
            // "matches": additionally within max_length and with the authorised AS.
            if prefix.len() <= roa.max_length && roa.origin_as == origin_as {
                return Validity::Valid;
            }
        }
        if covered {
            Validity::Invalid
        } else {
            Validity::NotFound
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pfx(s: &str) -> Prefix {
        s.parse().unwrap()
    }
    fn roa(prefix: &str, max_length: u8, origin_as: u32) -> Roa {
        Roa { prefix: pfx(prefix), max_length, origin_as }
    }

    #[test]
    fn not_found_when_no_roa_covers() {
        let t = RoaTable::new(vec![roa("10.0.0.0/8", 24, 65001)]);
        // A prefix outside any ROA's range.
        assert_eq!(t.validate(&pfx("192.0.2.0/24"), 65001), Validity::NotFound);
        // The empty table never covers anything.
        assert_eq!(RoaTable::default().validate(&pfx("10.0.0.0/24"), 65001), Validity::NotFound);
    }

    #[test]
    fn valid_when_a_roa_matches() {
        let t = RoaTable::new(vec![roa("10.0.0.0/8", 24, 65001)]);
        // Exact ROA prefix, right AS.
        assert_eq!(t.validate(&pfx("10.0.0.0/8"), 65001), Validity::Valid);
        // A more-specific within max_length, right AS.
        assert_eq!(t.validate(&pfx("10.1.2.0/24"), 65001), Validity::Valid);
    }

    #[test]
    fn invalid_on_wrong_origin_or_too_specific() {
        let t = RoaTable::new(vec![roa("10.0.0.0/8", 24, 65001)]);
        // Covered, within max_length, but the wrong origin AS.
        assert_eq!(t.validate(&pfx("10.1.2.0/24"), 65002), Validity::Invalid);
        // Right AS but more specific than max_length (/25 > /24).
        assert_eq!(t.validate(&pfx("10.1.2.0/25"), 65001), Validity::Invalid);
    }

    #[test]
    fn a_matching_roa_outweighs_a_covering_non_matching_one() {
        // Two ROAs cover 10.1.2.0/24: one wrong-AS, one right. A single match → Valid.
        let t = RoaTable::new(vec![roa("10.0.0.0/8", 16, 65002), roa("10.1.0.0/16", 24, 65001)]);
        assert_eq!(t.validate(&pfx("10.1.2.0/24"), 65001), Validity::Valid);
        // For 10.1.2.0/24 with AS 65003: 10.1.0.0/16 covers (within /24) but wrong AS,
        // 10.0.0.0/8 covers but /24 > its /16 max_length → no match → Invalid.
        assert_eq!(t.validate(&pfx("10.1.2.0/24"), 65003), Validity::Invalid);
    }

    #[test]
    fn families_do_not_cross() {
        let t = RoaTable::new(vec![roa("2001:db8::/32", 48, 65001)]);
        assert_eq!(t.validate(&pfx("2001:db8:1::/48"), 65001), Validity::Valid);
        assert_eq!(t.validate(&pfx("2001:db8:1::/48"), 65002), Validity::Invalid);
        // An IPv4 route is never covered by an IPv6 ROA.
        assert_eq!(t.validate(&pfx("10.0.0.0/24"), 65001), Validity::NotFound);
    }

    #[test]
    fn as0_authorises_no_origin() {
        // An AS0 ROA (RFC 6483) covers the prefix but matches no real origin → Invalid.
        let t = RoaTable::new(vec![roa("10.0.0.0/8", 24, 0)]);
        assert_eq!(t.validate(&pfx("10.1.2.0/24"), 65001), Validity::Invalid);
    }
}
