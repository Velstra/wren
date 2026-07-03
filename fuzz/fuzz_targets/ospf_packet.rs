#![no_main]
//! Fuzz `wren_ospf::packet::Packet::decode` — the OSPFv2 packet decoder
//! (Hello/DD/LSR/LSU/LSAck, including the LSA bodies it walks).
use libfuzzer_sys::fuzz_target;
use wren_ospf::packet::Packet;

fuzz_target!(|data: &[u8]| {
    let _ = Packet::decode(data);
});
