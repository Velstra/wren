#![no_main]
//! Fuzz `wren_babel::Packet::decode` — the Babel packet decoder (the TLV stream
//! it walks). A previously-fixed remote panic lived on this path, so it is a
//! priority target — seed it with that regression input (see README).
use libfuzzer_sys::fuzz_target;
use wren_babel::Packet;

fuzz_target!(|data: &[u8]| {
    let _ = Packet::decode(data);
});
