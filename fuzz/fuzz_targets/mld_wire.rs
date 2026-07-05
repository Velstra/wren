#![no_main]
//! Fuzz `wren_igmp::mld::Message::decode` — the MLDv2 query / report decoder
//! (RFC 3810, the multicast-address-record list it walks). MLD is received on
//! the link from any adjacent IPv6 host, so the decoder must never panic on a
//! malformed message — only return `DecodeError`.
use libfuzzer_sys::fuzz_target;
use wren_igmp::mld::Message;

fuzz_target!(|data: &[u8]| {
    let _ = Message::decode(data);
});
