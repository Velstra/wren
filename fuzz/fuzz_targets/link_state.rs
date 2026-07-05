#![no_main]
//! Fuzz `wren_bgp::link_state` — the BGP-LS NLRI decoder (SAFI 71, node/link/
//! prefix descriptors) and the BGP-LS Attribute TLV decoder (RFC 7752). Both
//! arrive from a peer inside MP_REACH / the LS attribute, so neither the
//! run-of-NLRIs walk nor the attribute TLV walk may panic on malformed input.
use libfuzzer_sys::fuzz_target;
use wren_bgp::link_state::{decode_nlris, BgpLsAttribute, LinkStateNlri};

fuzz_target!(|data: &[u8]| {
    let _ = LinkStateNlri::decode(data);
    let _ = decode_nlris(data);
    let _ = BgpLsAttribute::decode(data);
});
