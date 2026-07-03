#![no_main]
//! Fuzz `wren_vrrp::Advertisement::decode` — the VRRP advertisement decoder.
//! The first input byte picks the IPv4/IPv6 form; the rest is the packet buffer.
use libfuzzer_sys::fuzz_target;
use wren_vrrp::Advertisement;

fuzz_target!(|data: &[u8]| {
    let Some((&flags, buf)) = data.split_first() else {
        return;
    };
    let ipv6 = flags & 1 != 0;
    let _ = Advertisement::decode(buf, ipv6);
});
