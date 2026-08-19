//! Babel TLVs (RFC 8966 §4.6): the typed records a packet body carries.
//!
//! Each TLV is `type(1) · length(1) · body` — except [`Tlv::Pad1`], a lone zero
//! byte with no length. [`Tlv::encode`] writes the whole TLV (patching the length);
//! [`Tlv::decode`] parses one body. Compressed `Update` prefixes are reconstructed
//! against the packet's [`Compress`](crate::Compress) register, so decoding happens
//! in packet context (see [`crate::Packet::decode`]).

use std::net::IpAddr;

use wren_core::Prefix;

use crate::{read_address, read_prefix, write_address, write_prefix, Compress, AE_WILDCARD};

/// Pad1 (§4.6.1) — a single padding byte.
pub const TYPE_PAD1: u8 = 0;
/// PadN (§4.6.1) — N padding bytes.
pub const TYPE_PADN: u8 = 1;
/// Acknowledgment Request (§4.6.2).
pub const TYPE_ACK_REQ: u8 = 2;
/// Acknowledgment (§4.6.3).
pub const TYPE_ACK: u8 = 3;
/// Hello (§4.6.4).
pub const TYPE_HELLO: u8 = 4;
/// IHU — I Heard You (§4.6.6).
pub const TYPE_IHU: u8 = 5;
/// Router-ID (§4.6.7).
pub const TYPE_ROUTER_ID: u8 = 6;
/// Next Hop (§4.6.8).
pub const TYPE_NEXT_HOP: u8 = 7;
/// Update (§4.6.9).
pub const TYPE_UPDATE: u8 = 8;
/// Route Request (§4.6.10).
pub const TYPE_ROUTE_REQUEST: u8 = 9;
/// Seqno Request (§4.6.11).
pub const TYPE_SEQNO_REQUEST: u8 = 10;

/// The Update flag (§4.6.9) marking the advertised prefix as the new default
/// prefix for subsequent compressed Updates in the packet.
pub const UPDATE_FLAG_DEFAULT_PREFIX: u8 = 0x80;

/// One Babel TLV.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Tlv {
    /// A single padding byte.
    Pad1,
    /// `n` padding bytes.
    PadN(u8),
    /// Request that the receiver acknowledge with a matching nonce (§4.6.2).
    AckReq {
        /// The nonce to be echoed.
        nonce: u16,
        /// How long (centiseconds) the sender will wait for the Ack.
        interval: u16,
    },
    /// Acknowledge an Acknowledgment Request (§4.6.3).
    Ack {
        /// The echoed nonce.
        nonce: u16,
    },
    /// A periodic Hello establishing/maintaining a neighbour (§4.6.4).
    Hello {
        /// Flags (e.g. unicast Hello).
        flags: u16,
        /// This Hello's sequence number.
        seqno: u16,
        /// The Hello interval, in centiseconds (0 = unscheduled).
        interval: u16,
    },
    /// I Heard You — reports the cost back to a neighbour (§4.6.6).
    Ihu {
        /// The receive cost from the addressed neighbour.
        rxcost: u16,
        /// The IHU interval, in centiseconds.
        interval: u16,
        /// The neighbour's address (`None` for a wildcard IHU).
        address: Option<IpAddr>,
    },
    /// The Router-ID for subsequent Updates in the packet (§4.6.7).
    RouterId([u8; 8]),
    /// The next hop for subsequent Updates of this address family (§4.6.8).
    NextHop(IpAddr),
    /// Advertise (or retract, with metric 0xFFFF) a route to a prefix (§4.6.9).
    Update {
        /// Update flags (§4.6.9).
        flags: u8,
        /// The advertised interval, in centiseconds.
        interval: u16,
        /// The originator's sequence number for this route.
        seqno: u16,
        /// The advertised metric (`0xFFFF` retracts the route).
        metric: u16,
        /// The destination prefix.
        prefix: Prefix,
    },
    /// Request the current Update for a prefix, or the whole table (§4.6.10).
    RouteRequest {
        /// The requested prefix, or `None` for the whole table (AE 0 wildcard).
        prefix: Option<Prefix>,
    },
    /// Request a fresher sequence number for a route from its originator (§4.6.11).
    SeqnoRequest {
        /// The sequence number being requested.
        seqno: u16,
        /// The remaining hop count (decremented on forward).
        hop_count: u8,
        /// The originating Router-ID the request targets.
        router_id: [u8; 8],
        /// The prefix in question.
        prefix: Prefix,
    },
    /// A TLV type this implementation does not model, kept verbatim.
    Unknown {
        /// The TLV type code.
        tlv_type: u8,
        /// The raw TLV body.
        body: Vec<u8>,
    },
}

impl Tlv {
    /// The TLV type code.
    pub fn tlv_type(&self) -> u8 {
        match self {
            Tlv::Pad1 => TYPE_PAD1,
            Tlv::PadN(_) => TYPE_PADN,
            Tlv::AckReq { .. } => TYPE_ACK_REQ,
            Tlv::Ack { .. } => TYPE_ACK,
            Tlv::Hello { .. } => TYPE_HELLO,
            Tlv::Ihu { .. } => TYPE_IHU,
            Tlv::RouterId(_) => TYPE_ROUTER_ID,
            Tlv::NextHop(_) => TYPE_NEXT_HOP,
            Tlv::Update { .. } => TYPE_UPDATE,
            Tlv::RouteRequest { .. } => TYPE_ROUTE_REQUEST,
            Tlv::SeqnoRequest { .. } => TYPE_SEQNO_REQUEST,
            Tlv::Unknown { tlv_type, .. } => *tlv_type,
        }
    }

    /// Serialise the whole TLV (type · length · body), patching the length.
    pub fn encode(&self, out: &mut Vec<u8>) {
        if let Tlv::Pad1 = self {
            out.push(TYPE_PAD1);
            return;
        }
        out.push(self.tlv_type());
        let len_pos = out.len();
        out.push(0); // length, patched below
        self.encode_body(out);
        let body_len = out.len() - len_pos - 1;
        out[len_pos] = body_len as u8;
    }

    fn encode_body(&self, out: &mut Vec<u8>) {
        match self {
            Tlv::Pad1 => {}
            Tlv::PadN(n) => out.resize(out.len() + *n as usize, 0),
            Tlv::AckReq { nonce, interval } => {
                out.extend_from_slice(&[0, 0]); // reserved
                out.extend_from_slice(&nonce.to_be_bytes());
                out.extend_from_slice(&interval.to_be_bytes());
            }
            Tlv::Ack { nonce } => out.extend_from_slice(&nonce.to_be_bytes()),
            Tlv::Hello {
                flags,
                seqno,
                interval,
            } => {
                out.extend_from_slice(&flags.to_be_bytes());
                out.extend_from_slice(&seqno.to_be_bytes());
                out.extend_from_slice(&interval.to_be_bytes());
            }
            Tlv::Ihu {
                rxcost,
                interval,
                address,
            } => {
                let ae_pos = out.len();
                out.push(AE_WILDCARD); // AE, patched if an address follows
                out.push(0); // reserved
                out.extend_from_slice(&rxcost.to_be_bytes());
                out.extend_from_slice(&interval.to_be_bytes());
                if let Some(ip) = address {
                    let ae = write_address(out, *ip);
                    out[ae_pos] = ae;
                }
            }
            Tlv::RouterId(id) => {
                out.extend_from_slice(&[0, 0]); // reserved
                out.extend_from_slice(id);
            }
            Tlv::NextHop(ip) => {
                let ae_pos = out.len();
                out.push(AE_WILDCARD);
                out.push(0); // reserved
                let ae = write_address(out, *ip);
                out[ae_pos] = ae;
            }
            Tlv::Update {
                flags,
                interval,
                seqno,
                metric,
                prefix,
            } => {
                let ae_pos = out.len();
                out.push(AE_WILDCARD); // AE, patched below
                out.push(*flags);
                let plen_pos = out.len();
                out.push(0); // plen, patched below
                out.push(0); // omitted (we never compress on send)
                out.extend_from_slice(&interval.to_be_bytes());
                out.extend_from_slice(&seqno.to_be_bytes());
                out.extend_from_slice(&metric.to_be_bytes());
                let (ae, plen) = write_prefix(out, prefix);
                out[ae_pos] = ae;
                out[plen_pos] = plen;
            }
            Tlv::RouteRequest { prefix } => match prefix {
                None => {
                    out.push(AE_WILDCARD);
                    out.push(0); // plen 0
                }
                Some(p) => {
                    let ae_pos = out.len();
                    out.push(AE_WILDCARD);
                    let plen_pos = out.len();
                    out.push(0);
                    let (ae, plen) = write_prefix(out, p);
                    out[ae_pos] = ae;
                    out[plen_pos] = plen;
                }
            },
            Tlv::SeqnoRequest {
                seqno,
                hop_count,
                router_id,
                prefix,
            } => {
                let ae_pos = out.len();
                out.push(AE_WILDCARD);
                let plen_pos = out.len();
                out.push(0);
                out.extend_from_slice(&seqno.to_be_bytes());
                out.push(*hop_count);
                out.push(0); // reserved
                out.extend_from_slice(router_id);
                let (ae, plen) = write_prefix(out, prefix);
                out[ae_pos] = ae;
                out[plen_pos] = plen;
            }
            Tlv::Unknown { body, .. } => out.extend_from_slice(body),
        }
    }

    /// Decode one TLV of `tlv_type` from its `body`, using `ctx` to de-compress an
    /// `Update` prefix. Returns `None` for an unknown type or a malformed body
    /// (the caller preserves it as [`Tlv::Unknown`]).
    pub(crate) fn decode(tlv_type: u8, body: &[u8], ctx: &mut Compress) -> Option<Tlv> {
        match tlv_type {
            TYPE_PADN => Some(Tlv::PadN(body.len() as u8)),
            TYPE_ACK_REQ => {
                let nonce = be16(body, 2)?;
                let interval = be16(body, 4)?;
                Some(Tlv::AckReq { nonce, interval })
            }
            TYPE_ACK => Some(Tlv::Ack {
                nonce: be16(body, 0)?,
            }),
            TYPE_HELLO => Some(Tlv::Hello {
                flags: be16(body, 0)?,
                seqno: be16(body, 2)?,
                interval: be16(body, 4)?,
            }),
            TYPE_IHU => {
                let ae = *body.first()?;
                let rxcost = be16(body, 2)?;
                let interval = be16(body, 4)?;
                let address = if ae == AE_WILDCARD {
                    None
                } else {
                    Some(read_address(ae, body.get(6..)?)?.0)
                };
                Some(Tlv::Ihu {
                    rxcost,
                    interval,
                    address,
                })
            }
            TYPE_ROUTER_ID => {
                let id: [u8; 8] = body.get(2..10)?.try_into().ok()?;
                Some(Tlv::RouterId(id))
            }
            TYPE_NEXT_HOP => {
                let ae = *body.first()?;
                let (ip, _) = read_address(ae, body.get(2..)?)?;
                Some(Tlv::NextHop(ip))
            }
            TYPE_UPDATE => {
                let ae = *body.first()?;
                let flags = *body.get(1)?;
                let plen = *body.get(2)?;
                let omitted = *body.get(3)?;
                let interval = be16(body, 4)?;
                let seqno = be16(body, 6)?;
                let metric = be16(body, 8)?;
                let (prefix, _) = read_prefix(ae, plen, omitted, body.get(10..)?, ctx)?;
                if flags & UPDATE_FLAG_DEFAULT_PREFIX != 0 {
                    ctx.set_default(&prefix);
                }
                Some(Tlv::Update {
                    flags,
                    interval,
                    seqno,
                    metric,
                    prefix,
                })
            }
            TYPE_ROUTE_REQUEST => {
                let ae = *body.first()?;
                let plen = *body.get(1)?;
                if ae == AE_WILDCARD {
                    return Some(Tlv::RouteRequest { prefix: None });
                }
                let (prefix, _) = read_prefix(ae, plen, 0, body.get(2..)?, ctx)?;
                Some(Tlv::RouteRequest {
                    prefix: Some(prefix),
                })
            }
            TYPE_SEQNO_REQUEST => {
                let ae = *body.first()?;
                let plen = *body.get(1)?;
                let seqno = be16(body, 2)?;
                let hop_count = *body.get(4)?;
                let router_id: [u8; 8] = body.get(6..14)?.try_into().ok()?;
                let (prefix, _) = read_prefix(ae, plen, 0, body.get(14..)?, ctx)?;
                Some(Tlv::SeqnoRequest {
                    seqno,
                    hop_count,
                    router_id,
                    prefix,
                })
            }
            _ => None,
        }
    }
}

/// Read a big-endian `u16` at `off` in `buf`.
fn be16(buf: &[u8], off: usize) -> Option<u16> {
    let b: [u8; 2] = buf.get(off..off + 2)?.try_into().ok()?;
    Some(u16::from_be_bytes(b))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Packet, MAGIC, METRIC_INFINITY, VERSION};

    fn p(s: &str) -> Prefix {
        s.parse().unwrap()
    }

    /// Round-trip a TLV through a whole packet (the decoder needs packet context).
    fn roundtrip(tlv: Tlv) {
        let pkt = Packet::new(vec![tlv.clone()]);
        let decoded = Packet::decode(&pkt.encode()).expect("decodes");
        assert_eq!(decoded.body, vec![tlv]);
    }

    #[test]
    fn control_tlvs_roundtrip() {
        roundtrip(Tlv::AckReq {
            nonce: 0x1234,
            interval: 150,
        });
        roundtrip(Tlv::Ack { nonce: 0x1234 });
        roundtrip(Tlv::Hello {
            flags: 0,
            seqno: 42,
            interval: 400,
        });
        roundtrip(Tlv::RouterId([1, 2, 3, 4, 5, 6, 7, 8]));
    }

    #[test]
    fn ihu_with_and_without_address() {
        roundtrip(Tlv::Ihu {
            rxcost: 96,
            interval: 600,
            address: Some("fe80::1".parse().unwrap()),
        });
        roundtrip(Tlv::Ihu {
            rxcost: 256,
            interval: 600,
            address: None,
        });
    }

    #[test]
    fn next_hop_roundtrips_v4_and_linklocal() {
        roundtrip(Tlv::NextHop("192.0.2.1".parse().unwrap()));
        roundtrip(Tlv::NextHop("fe80::abcd".parse().unwrap()));
    }

    #[test]
    fn update_roundtrips_v4_and_v6() {
        roundtrip(Tlv::Update {
            flags: 0,
            interval: 400,
            seqno: 7,
            metric: 256,
            prefix: p("10.0.0.0/8"),
        });
        roundtrip(Tlv::Update {
            flags: 0,
            interval: 400,
            seqno: 7,
            metric: METRIC_INFINITY,
            prefix: p("2001:db8::/32"),
        });
        // The default route encodes with zero prefix octets.
        roundtrip(Tlv::Update {
            flags: 0,
            interval: 400,
            seqno: 1,
            metric: 0,
            prefix: p("0.0.0.0/0"),
        });
    }

    #[test]
    fn requests_roundtrip() {
        roundtrip(Tlv::RouteRequest { prefix: None });
        roundtrip(Tlv::RouteRequest {
            prefix: Some(p("203.0.113.0/24")),
        });
        roundtrip(Tlv::SeqnoRequest {
            seqno: 9,
            hop_count: 16,
            router_id: [8, 7, 6, 5, 4, 3, 2, 1],
            prefix: p("10.1.2.0/24"),
        });
    }

    #[test]
    fn update_prefix_compression_is_decoded() {
        // Two Updates: the first sets the default prefix (flag 0x80), the second
        // omits its leading octets. We hand-encode the compressed second Update and
        // check the decoder reconstructs the full prefix from the default.
        let mut body = Vec::new();
        Tlv::Update {
            flags: UPDATE_FLAG_DEFAULT_PREFIX,
            interval: 400,
            seqno: 1,
            metric: 100,
            prefix: p("10.1.0.0/16"),
        }
        .encode(&mut body);
        // Update 2 (hand-built): AE 1, flags 0, plen 24, omitted 2, then 1 octet (7)
        // → 10.1.7.0/24 reusing the default's first two octets.
        body.push(TYPE_UPDATE);
        let len_pos = body.len();
        body.push(0);
        body.extend_from_slice(&[1, 0, 24, 2]); // ae, flags, plen, omitted
        body.extend_from_slice(&400u16.to_be_bytes());
        body.extend_from_slice(&2u16.to_be_bytes());
        body.extend_from_slice(&110u16.to_be_bytes());
        body.push(7); // the one present octet
        body[len_pos] = (body.len() - len_pos - 1) as u8;

        let mut pkt = vec![MAGIC, VERSION, 0, 0];
        pkt.extend_from_slice(&body);
        let blen = (pkt.len() - 4) as u16;
        pkt[2..4].copy_from_slice(&blen.to_be_bytes());

        let decoded = Packet::decode(&pkt).unwrap();
        match &decoded.body[1] {
            Tlv::Update { prefix, .. } => assert_eq!(*prefix, p("10.1.7.0/24")),
            other => panic!("expected Update, got {other:?}"),
        }
    }

    // =======================================================================
    // Byte-offset assertions (RFC 8966 §4.6)
    //
    // Every test above round-trips a TLV through this crate's own encoder and
    // decoder. That cannot see a field at the wrong offset — the decoder reads
    // it back from the same wrong place — which is exactly how the OSPFv2
    // Router-LSA flag bug survived until another implementation was put on the
    // wire. The tests below name the offset the RFC names.
    // =======================================================================

    /// RFC 8966 §4.2 fixes the packet header: Magic 42, Version 2, then a
    /// 2-octet Body Length that counts the TLVs *only* — not the four header
    /// octets. §4.3 makes every TLV `[Type][Length][Body]`, where Length also
    /// excludes its own two octets.
    ///
    /// Count the header into the body length and a peer reads four octets past
    /// the end of the TLV stream, so the last TLV in every packet is discarded
    /// as malformed — including the Update that carries the route.
    #[test]
    fn the_packet_body_length_counts_the_tlvs_only() {
        let pkt = Packet::new(vec![Tlv::Ack { nonce: 0x1234 }]);
        let b = pkt.encode();
        assert_eq!(b[0], MAGIC, "byte 0 is the magic, 42");
        assert_eq!(b[1], VERSION, "byte 1 is the version, 2");
        assert_eq!(
            u16::from_be_bytes([b[2], b[3]]) as usize,
            b.len() - 4,
            "Body Length is bytes 2..4 and excludes the 4-octet header"
        );
        assert_eq!(b[4], 3, "the Ack TLV type is 3");
        assert_eq!(b[5], 2, "the TLV Length excludes its own 2 octets");
        assert_eq!(&b[6..8], &[0x12, 0x34], "then the 2-octet nonce");
        assert_eq!(b.len(), 8);
    }

    /// RFC 8966 §4.6 assigns the TLV type codes, and §4.6.1 makes Pad1 the one
    /// TLV with **no length octet at all** — a bare zero byte. Give Pad1 a
    /// length octet and every TLV after it in the packet is misframed.
    #[test]
    fn the_tlv_type_codes_are_the_ones_the_rfc_assigns_and_pad1_has_no_length() {
        let first_two = |t: Tlv| {
            let b = Packet::new(vec![t]).encode();
            (b[4], b.len())
        };
        assert_eq!(first_two(Tlv::Pad1), (0, 5), "Pad1 is type 0 and one octet total");
        assert_eq!(first_two(Tlv::PadN(3)).0, 1, "PadN is type 1");
        assert_eq!(first_two(Tlv::AckReq { nonce: 0, interval: 0 }).0, 2, "AckReq is 2");
        assert_eq!(first_two(Tlv::Ack { nonce: 0 }).0, 3, "Ack is 3");
        assert_eq!(
            first_two(Tlv::Hello { flags: 0, seqno: 0, interval: 0 }).0,
            4,
            "Hello is 4"
        );
        assert_eq!(
            first_two(Tlv::Ihu { rxcost: 0, interval: 0, address: None }).0,
            5,
            "IHU is 5"
        );
        assert_eq!(first_two(Tlv::RouterId([0; 8])).0, 6, "Router-Id is 6");
        assert_eq!(first_two(Tlv::RouteRequest { prefix: None }).0, 9, "Route Req is 9");
        // Pad1 really is a single octet: two of them plus an Ack frame correctly.
        let b = Packet::new(vec![Tlv::Pad1, Tlv::Pad1, Tlv::Ack { nonce: 7 }]).encode();
        assert_eq!(&b[4..6], &[0, 0], "two bare Pad1 octets");
        assert_eq!(b[6], 3, "then the Ack TLV type");
        assert_eq!(b.len(), 4 + 1 + 1 + 4);
    }

    /// RFC 8966 §4.6.9 fixes the Update TLV body: AE 0, Flags 1, Plen 2,
    /// Omitted 3, Interval 4..6, Seqno 6..8, Metric 8..10, then the
    /// `ceil((plen - omitted)/8)` prefix octets.
    ///
    /// Seqno and Metric transposed is the dangerous one, and it round-trips
    /// perfectly. Babel's loop-freedom rests on the feasibility condition
    /// (§3.5.1), which compares `(seqno, metric)` pairs: read them the wrong way
    /// round and a peer either accepts routes it must not (a routing loop that
    /// the protocol is specifically designed to make impossible) or rejects
    /// every update as unfeasible and never installs a route at all.
    #[test]
    fn an_update_tlv_is_encoded_in_the_rfc_field_order() {
        let pkt = Packet::new(vec![Tlv::Update {
            flags: 0,
            interval: 0x0064,
            seqno: 0x1122,
            metric: 0x3344,
            prefix: p("10.9.8.0/24"),
        }]);
        let b = pkt.encode();
        assert_eq!(b[4], 8, "the Update TLV type is 8");
        let v = &b[6..]; // past the TLV type and length octets
        assert_eq!(v[0], 1, "AE is byte 0 of the body; IPv4 is 1");
        assert_eq!(v[1], 0, "Flags is byte 1");
        assert_eq!(v[2], 24, "Plen is byte 2");
        assert_eq!(v[3], 0, "Omitted is byte 3 — wren never compresses on send");
        assert_eq!(&v[4..6], &[0x00, 0x64], "Interval is bytes 4..6");
        assert_eq!(&v[6..8], &[0x11, 0x22], "Seqno is bytes 6..8");
        assert_eq!(&v[8..10], &[0x33, 0x44], "Metric is bytes 8..10");
        assert_eq!(&v[10..13], &[10, 9, 8], "the prefix is ceil(24/8) = 3 octets");
        assert_eq!(b[5] as usize, 13, "the TLV Length covers exactly the body");
        assert_eq!(b.len(), 4 + 2 + 13);

        // An IPv6 update uses AE 2 and carries ceil(plen/8) octets, not 16.
        let b = Packet::new(vec![Tlv::Update {
            flags: 0,
            interval: 100,
            seqno: 1,
            metric: METRIC_INFINITY,
            prefix: p("2001:db8::/32"),
        }])
        .encode();
        let v = &b[6..];
        assert_eq!(v[0], 2, "AE 2 is IPv6");
        assert_eq!(v[2], 32, "Plen 32");
        assert_eq!(&v[8..10], &[0xff, 0xff], "an infinity metric retracts the route");
        assert_eq!(&v[10..14], &[0x20, 0x01, 0x0d, 0xb8], "four prefix octets for a /32");
        assert_eq!(b[5] as usize, 14);
    }

    /// RFC 8966 §4.6.6 fixes the IHU body: AE 0, Reserved 1, Rxcost 2..4,
    /// Interval 4..6, then the optional address. Rxcost and Interval transposed
    /// feeds the neighbour's cost computation (§3.4.3) an interval in place of a
    /// cost, so link costs bear no relation to link quality and the metric that
    /// Babel's whole route selection rests on is noise.
    #[test]
    fn an_ihu_tlv_is_encoded_in_the_rfc_field_order() {
        let b = Packet::new(vec![Tlv::Ihu {
            rxcost: 0x0100,
            interval: 0x012c,
            address: Some("10.0.0.2".parse().unwrap()),
        }])
        .encode();
        assert_eq!(b[4], 5, "the IHU TLV type is 5");
        let v = &b[6..];
        assert_eq!(v[0], 1, "AE is byte 0; IPv4 is 1");
        assert_eq!(v[1], 0, "byte 1 is Reserved and must be zero");
        assert_eq!(&v[2..4], &[0x01, 0x00], "Rxcost is bytes 2..4");
        assert_eq!(&v[4..6], &[0x01, 0x2c], "Interval is bytes 4..6");
        assert_eq!(&v[6..10], &[10, 0, 0, 2], "the address follows at byte 6");

        // With no address the AE is 0 (wildcard) and the body stops at 6 octets.
        let b = Packet::new(vec![Tlv::Ihu { rxcost: 1, interval: 2, address: None }]).encode();
        assert_eq!(b[6], 0, "AE 0 means no address is present");
        assert_eq!(b[5], 6, "the body is just the six fixed octets");
    }
}
