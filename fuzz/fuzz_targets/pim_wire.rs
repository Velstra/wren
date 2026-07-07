#![no_main]
//! Fuzz `wren_pim::wire::Message::decode` — the PIM-SM (RFC 7761 §4.9) packet
//! decoder (Hello, Join/Prune, Register, Register-Stop, and the encoded-address
//! forms it walks). PIM is received on a raw IP-protocol-103 socket from any adjacent
//! router, so the decoder must never panic on a malformed packet — only return
//! `DecodeError`.
use libfuzzer_sys::fuzz_target;
use wren_pim::wire::Message;

fuzz_target!(|data: &[u8]| {
    let _ = Message::decode(data);
});
