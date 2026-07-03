#![no_main]
//! Fuzz `wren_bgp::evpn` — the EVPN NLRI decoder (RFC 7432 route types 2/3/5
//! plus unknown-type skip). Exercises both the single-NLRI and the
//! run-of-NLRIs entry points, and re-encodes whatever decodes so the encoder
//! is fuzzed against decoder-accepted shapes too.
use libfuzzer_sys::fuzz_target;
use wren_bgp::evpn::{decode_evpn_nlri, decode_evpn_nlris, encode_evpn_nlri};

fuzz_target!(|data: &[u8]| {
    // Decode must never panic or loop on any input.
    if let Some((nlri, _used)) = decode_evpn_nlri(data) {
        let mut buf = Vec::new();
        encode_evpn_nlri(&mut buf, &nlri);
    }
    let _ = decode_evpn_nlris(data);
});
