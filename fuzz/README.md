# Wren wire-decoder fuzzing (code-review Architektur-6)

Continuous fuzzing for every attacker-reachable **wire decoder** in Wren. These
decoders parse bytes that arrive from BGP/OSPF/IS-IS/BFD/VRRP/Babel peers (and an
RPKI-to-Router cache), so a panic or infinite loop in any of them is a remote
denial-of-service. The review asked for this harness to exist *before* EVPN/SRv6
widen the parser surface.

This is a **standalone [cargo-fuzz] workspace** (its own `[workspace]` table), so
the stable-Rust root build and `cargo test` never touch it. It needs nightly +
libFuzzer.

## One-time setup

```sh
cargo install cargo-fuzz
```

## Run

From the repo root (or this `fuzz/` dir):

```sh
cargo +nightly fuzz list                    # the targets below
cargo +nightly fuzz run bgp_message         # fuzz until a crash / Ctrl-C
cargo +nightly fuzz run bgp_message -- -max_total_time=60
```

A quick "does everything still build" check without the fuzzer runtime:

```sh
cd fuzz && cargo +nightly check
```

## Targets

| Target | Decoder | Notes |
|---|---|---|
| `bgp_message` | `wren_bgp::message::Message::decode` | first input byte selects `four_octet` ASN mode |
| `bgp_rtr` | `wren_bgp::rtr::Pdu::decode` | RPKI-to-Router PDUs (spoofable cache) |
| `ospf_packet` | `wren_ospf::packet::Packet::decode` | OSPFv2 packets + LSA bodies |
| `ospfv3_packet` | `wren_ospfv3::packet::Packet::decode` | OSPFv3/IPv6 |
| `isis_pdu` | `wren_isis::pdu::Pdu::decode` | IS-IS over raw L2 |
| `bfd_control` | `wren_bfd::ControlPacket::decode` | high-rate control packets |
| `vrrp_advertisement` | `wren_vrrp::Advertisement::decode` | first input byte selects IPv4/IPv6 |
| `babel_packet` | `wren_babel::Packet::decode` | prior remote-panic path |

Targets that take an out-of-band flag (BGP `four_octet`, VRRP `ipv6`) consume the
**first input byte** for it and decode the remainder, so libFuzzer explores both
modes from one corpus.

## Seed corpus

`corpus/<target>/` holds starter inputs. Shipped seeds:

- `bgp_message/c1_overlong_length` — the **C1 regression seed**: a header whose
  length field claims `0xFFFF` bytes against a truncated buffer, the
  length-vs-buffer DoS the C1 one-line clamp fixed. Keep this so C1 can never
  silently regress.
- `bgp_message/keepalive`, `bgp_message/truncated`, `babel_packet/truncated_tlv`,
  `vrrp_advertisement/v2_min` — minimal valid / edge inputs to prime coverage.

Grow a corpus cheaply from the crates' own unit tests: many encode a message and
assert the round-trip (e.g. `wren-bgp/src/lib.rs::decode_rejects_overlong_and_truncated`,
`wren-bgp/src/message.rs` codec tests). Dump those byte vectors into
`corpus/<target>/` as new seeds. A crash reproducer that libFuzzer writes to
`artifacts/<target>/` should be committed as a seed too, then fixed.

[cargo-fuzz]: https://github.com/rust-fuzz/cargo-fuzz
