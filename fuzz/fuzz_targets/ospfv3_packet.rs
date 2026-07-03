#![no_main]
//! Fuzz `wren_ospfv3::packet::Packet::decode` — the OSPFv3 (IPv6) packet decoder.
//! It takes the source/destination IPv6 addresses (used for pseudo-header
//! checksum context); fixed link-local-ish constants are fine for fuzzing the
//! parser surface.
use libfuzzer_sys::fuzz_target;
use std::net::Ipv6Addr;
use wren_ospfv3::packet::Packet;

const SRC: Ipv6Addr = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
const DST: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 5);

fuzz_target!(|data: &[u8]| {
    let _ = Packet::decode(data, SRC, DST);
});
