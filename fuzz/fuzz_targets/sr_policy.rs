#![no_main]
//! Fuzz `wren_bgp::sr_policy` — the SR Policy SAFI-73 NLRI decoder and the
//! Tunnel Encapsulation attribute's SR-Policy sub-TLV decoder (RFC 9012 /
//! draft-ietf-idr-segment-routing-te-policy). Both arrive from a peer, so
//! neither path may panic or loop on a malformed input. The NLRI decode is run
//! for both AFI widths since the AFI fixes the endpoint length.
use libfuzzer_sys::fuzz_target;
use wren_bgp::sr_policy::{decode_nlris, decode_tunnel_encap, decode_tunnel_value, SrPolicyNlri};

const AFI_IPV4: u16 = 1;
const AFI_IPV6: u16 = 2;

fuzz_target!(|data: &[u8]| {
    for afi in [AFI_IPV4, AFI_IPV6] {
        let _ = SrPolicyNlri::decode(data, afi);
        let _ = decode_nlris(data, afi);
    }
    let _ = decode_tunnel_encap(data);
    let _ = decode_tunnel_value(data);
});
