#![no_main]
//! Fuzz `wren_bgp::flowspec` — the FlowSpec NLRI decoder (RFC 8955 component
//! types, the 1/2-byte length header, and the numeric/bitmask op lists it
//! walks). A FlowSpec NLRI arrives in an MP_REACH attribute from a peer, so the
//! decoder must never panic or loop on a malformed component stream.
use libfuzzer_sys::fuzz_target;
use wren_bgp::flowspec::{decode_nlris, FlowSpec};

fuzz_target!(|data: &[u8]| {
    // Single-NLRI and run-of-NLRIs entry points must never panic on any input.
    let _ = FlowSpec::decode(data);
    let _ = decode_nlris(data);
});
