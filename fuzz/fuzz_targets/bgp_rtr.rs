#![no_main]
//! Fuzz `wren_bgp::rtr::Pdu::decode` — the RPKI-to-Router (RTR) PDU decoder that
//! feeds ROA/prefix validation. Attacker-adjacent: an RTR cache can be
//! compromised or spoofed, so the decoder must reject any malformed PDU without
//! panicking.
use libfuzzer_sys::fuzz_target;
use wren_bgp::rtr::Pdu;

fuzz_target!(|data: &[u8]| {
    let _ = Pdu::decode(data);
});
