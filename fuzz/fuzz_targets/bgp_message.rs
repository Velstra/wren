#![no_main]
//! Fuzz `wren_bgp::message::Message::decode` — the BGP wire-message decoder
//! (OPEN/UPDATE/NOTIFICATION/KEEPALIVE/ROUTE-REFRESH). The first input byte
//! selects the `four_octet` ASN mode so both codec paths are exercised; the rest
//! is the message buffer. Seed with the C1 regression input (see README).
use libfuzzer_sys::fuzz_target;
use wren_bgp::message::{AddPath, Message};

fuzz_target!(|data: &[u8]| {
    let Some((&flags, buf)) = data.split_first() else {
        return;
    };
    let four_octet = flags & 1 != 0;
    // Decode must never panic or loop on any input; the result is discarded.
    let _ = Message::decode(buf, four_octet, AddPath::NONE);
});
