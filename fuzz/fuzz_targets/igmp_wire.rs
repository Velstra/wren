#![no_main]
//! Fuzz `wren_igmp::wire::Message::decode` — the IGMPv3 membership query /
//! report decoder (RFC 3376, the group-record list it walks). IGMP is received
//! on the LAN from any adjacent host, so the decoder must never panic on a
//! malformed packet — only return `DecodeError`.
use libfuzzer_sys::fuzz_target;
use wren_igmp::wire::Message;

fuzz_target!(|data: &[u8]| {
    let _ = Message::decode(data);
});
