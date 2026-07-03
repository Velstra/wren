#![no_main]
//! Fuzz `wren_bfd::ControlPacket::decode` — the BFD control-packet decoder.
//! BFD packets arrive at high rate from the peer; the decoder returns `None` for
//! anything malformed and must never panic.
use libfuzzer_sys::fuzz_target;
use wren_bfd::ControlPacket;

fuzz_target!(|data: &[u8]| {
    let _ = ControlPacket::decode(data);
});
