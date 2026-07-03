#![no_main]
//! Fuzz `wren_isis::pdu::Pdu::decode` — the IS-IS PDU decoder (IIH/LSP/xSNP and
//! the TLVs it walks). IS-IS runs directly over L2, so any adjacent host can
//! inject frames; the decoder must never panic on a malformed PDU.
use libfuzzer_sys::fuzz_target;
use wren_isis::pdu::Pdu;

fuzz_target!(|data: &[u8]| {
    let _ = Pdu::decode(data);
});
