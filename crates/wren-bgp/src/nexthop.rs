//! MP-BGP IPv6 next-hop encoding for MP_REACH_NLRI (RFC 4760 §3, RFC 2545 §3).
//!
//! The Network Address of Next Hop field in an IPv6-unicast MP_REACH_NLRI is
//! either 16 octets — just the global next hop — or 32 octets, the global next
//! hop followed by the speaker's link-local address. RFC 2545 §3 says the
//! link-local is included if and only if the speaker shares a subnet with the
//! peer the route is advertised to (the directly-connected case): the receiver
//! then forwards over that link-local, which only makes sense pinned to the
//! interface the route arrived on.

use std::net::Ipv6Addr;

/// Whether `a` is an IPv6 link-local unicast address (`fe80::/10`).
fn is_link_local(a: &Ipv6Addr) -> bool {
    (a.segments()[0] & 0xffc0) == 0xfe80
}

/// Encode the MP_REACH_NLRI IPv6 next-hop field (RFC 2545 §3): the 16-octet
/// `global` address, optionally followed by a 16-octet `link_local` — a 32-octet
/// field — when the speaker shares the next hop's subnet with the peer.
pub fn encode_v6_next_hop(global: Ipv6Addr, link_local: Option<Ipv6Addr>) -> Vec<u8> {
    let mut out = Vec::with_capacity(32);
    out.extend_from_slice(&global.octets());
    if let Some(ll) = link_local {
        out.extend_from_slice(&ll.octets());
    }
    out
}

/// Decode an MP_REACH_NLRI IPv6 next-hop `field` into its global address and, when
/// the field is 32 octets and the trailing 16 are a link-local (`fe80::/10`), that
/// link-local (RFC 2545 §3). A field shorter than 16 octets is rejected; a 32-octet
/// field whose second address is *not* link-local is read as global-only (the
/// trailing octets ignored, per the robustness principle).
pub fn decode_v6_next_hop(field: &[u8]) -> Option<(Ipv6Addr, Option<Ipv6Addr>)> {
    if field.len() < 16 {
        return None;
    }
    let mut g = [0u8; 16];
    g.copy_from_slice(&field[..16]);
    let global = Ipv6Addr::from(g);

    let link_local = if field.len() >= 32 {
        let mut l = [0u8; 16];
        l.copy_from_slice(&field[16..32]);
        let ll = Ipv6Addr::from(l);
        is_link_local(&ll).then_some(ll)
    } else {
        None
    };
    Some((global, link_local))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v6(s: &str) -> Ipv6Addr {
        s.parse().unwrap()
    }

    #[test]
    fn global_only_next_hop_is_sixteen_octets() {
        let bytes = encode_v6_next_hop(v6("2001:db8::1"), None);
        assert_eq!(bytes.len(), 16);
        assert_eq!(decode_v6_next_hop(&bytes), Some((v6("2001:db8::1"), None)));
    }

    #[test]
    fn global_plus_link_local_round_trips_to_thirty_two_octets() {
        let bytes = encode_v6_next_hop(v6("2001:db8::1"), Some(v6("fe80::1")));
        assert_eq!(bytes.len(), 32);
        assert_eq!(
            decode_v6_next_hop(&bytes),
            Some((v6("2001:db8::1"), Some(v6("fe80::1"))))
        );
    }

    #[test]
    fn a_non_link_local_trailing_address_is_ignored() {
        // A 32-octet field whose second half is global is treated as global-only.
        let mut bytes = v6("2001:db8::1").octets().to_vec();
        bytes.extend_from_slice(&v6("2001:db8::2").octets());
        assert_eq!(decode_v6_next_hop(&bytes), Some((v6("2001:db8::1"), None)));
    }

    #[test]
    fn a_too_short_field_is_rejected() {
        assert_eq!(decode_v6_next_hop(&[0u8; 8]), None);
    }
}
