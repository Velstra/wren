//! BGP EVPN NLRI codec (RFC 7432, updated by RFC 9136 for IP-prefix routes).
//!
//! EVPN routes ride in MP_REACH_NLRI / MP_UNREACH_NLRI under AFI 25 (L2VPN) /
//! SAFI 70 (EVPN). Each NLRI is a `(route type, length, body)` triple; the body
//! layout depends on the route type. This module implements the route types the
//! daemon speaks —
//!
//! - **Type 2** MAC/IP Advertisement (§7.2) — a MAC (optionally with an IP)
//!   learned in an EVPN instance,
//! - **Type 3** Inclusive Multicast Ethernet Tag (§7.3) — "I participate in
//!   this EVI; send me BUM traffic",
//! - **Type 5** IP Prefix (RFC 9136 §3.1) — inter-subnet forwarding,
//!
//! plus decode-and-skip for every other type (§7: unknown route types MUST be
//! ignored using the length octet, not treated as an error).
//!
//! With the VXLAN encapsulation of RFC 8365 (§5.1.3), the 3-octet "MPLS label"
//! fields carry the 24-bit VNI directly; we store the raw 24-bit value.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use wren_core::Prefix;

/// Address Family Identifier: L2VPN (IANA).
pub const AFI_L2VPN: u16 = 25;
/// Subsequent Address Family Identifier: EVPN (RFC 7432).
pub const SAFI_EVPN: u8 = 70;

/// EVPN route type: Ethernet Auto-Discovery (RFC 7432 §7.1).
pub const ROUTE_TYPE_ETH_AUTO_DISCOVERY: u8 = 1;
/// EVPN route type: MAC/IP Advertisement (RFC 7432 §7.2).
pub const ROUTE_TYPE_MAC_IP: u8 = 2;
/// EVPN route type: Inclusive Multicast Ethernet Tag (RFC 7432 §7.3).
pub const ROUTE_TYPE_IMET: u8 = 3;
/// EVPN route type: Ethernet Segment (RFC 7432 §7.4).
pub const ROUTE_TYPE_ETH_SEGMENT: u8 = 4;
/// EVPN route type: IP Prefix (RFC 9136 §3.1).
pub const ROUTE_TYPE_IP_PREFIX: u8 = 5;

/// The BGP Encapsulation extended community (RFC 9012 §4.1): transitive opaque
/// (0x03), sub-type 0x0c, tunnel type in the last two octets.
pub const ENCAP_EXT_COMMUNITY_TYPE: u8 = 0x03;
/// Sub-type of the Encapsulation extended community.
pub const ENCAP_EXT_COMMUNITY_SUBTYPE: u8 = 0x0c;
/// BGP tunnel encapsulation type: VXLAN (IANA, RFC 8365).
pub const TUNNEL_TYPE_VXLAN: u16 = 8;

/// Build the Encapsulation extended community for a tunnel type (RFC 9012 §4.1),
/// e.g. [`TUNNEL_TYPE_VXLAN`] on every EVPN route of a VXLAN fabric (RFC 8365 §6).
pub fn encap_ext_community(tunnel_type: u16) -> [u8; 8] {
    let t = tunnel_type.to_be_bytes();
    [
        ENCAP_EXT_COMMUNITY_TYPE,
        ENCAP_EXT_COMMUNITY_SUBTYPE,
        0,
        0,
        0,
        0,
        t[0],
        t[1],
    ]
}

// ---------------------------------------------------------------------------
// Route Distinguisher (RFC 4364 §4.2)
// ---------------------------------------------------------------------------

/// A Route Distinguisher: 2-octet type + 6-octet value, kept as raw wire octets.
/// Type 0 is `2-octet-AS : 4-octet-value`, type 1 is `IPv4 : 2-octet-value`,
/// type 2 is `4-octet-AS : 2-octet-value`.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct Rd(pub [u8; 8]);

impl Rd {
    /// A type-1 RD `router-id : value` — the conventional per-PE, per-EVI form.
    pub fn from_ip(ip: Ipv4Addr, value: u16) -> Self {
        let mut b = [0u8; 8];
        b[0] = 0;
        b[1] = 1;
        b[2..6].copy_from_slice(&ip.octets());
        b[6..8].copy_from_slice(&value.to_be_bytes());
        Rd(b)
    }

    /// A type-0 RD `2-octet-AS : value`.
    pub fn from_as2(as_num: u16, value: u32) -> Self {
        let mut b = [0u8; 8];
        b[0] = 0;
        b[1] = 0;
        b[2..4].copy_from_slice(&as_num.to_be_bytes());
        b[4..8].copy_from_slice(&value.to_be_bytes());
        Rd(b)
    }
}

impl fmt::Display for Rd {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let b = &self.0;
        let rd_type = u16::from_be_bytes([b[0], b[1]]);
        match rd_type {
            0 => {
                let asn = u16::from_be_bytes([b[2], b[3]]);
                let val = u32::from_be_bytes([b[4], b[5], b[6], b[7]]);
                write!(f, "{asn}:{val}")
            }
            1 => {
                let ip = Ipv4Addr::new(b[2], b[3], b[4], b[5]);
                let val = u16::from_be_bytes([b[6], b[7]]);
                write!(f, "{ip}:{val}")
            }
            2 => {
                let asn = u32::from_be_bytes([b[2], b[3], b[4], b[5]]);
                let val = u16::from_be_bytes([b[6], b[7]]);
                write!(f, "{asn}:{val}")
            }
            _ => write!(
                f,
                "raw:{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
                b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]
            ),
        }
    }
}

// ---------------------------------------------------------------------------
// Ethernet Segment Identifier (RFC 7432 §5)
// ---------------------------------------------------------------------------

/// A 10-octet Ethernet Segment Identifier. All-zero means "single-homed"
/// (RFC 7432 §5), which is what a non-multihomed VTEP always sends.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Default)]
pub struct Esi(pub [u8; 10]);

impl Esi {
    /// The reserved all-zero ESI of a single-homed segment.
    pub const ZERO: Esi = Esi([0; 10]);
}

impl fmt::Display for Esi {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let b = &self.0;
        write!(
            f,
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7], b[8], b[9]
        )
    }
}

// ---------------------------------------------------------------------------
// The NLRI itself
// ---------------------------------------------------------------------------

/// One decoded EVPN NLRI. The variants mirror the wire route types; `Unknown`
/// preserves anything we don't interpret so it can be ignored per §7 (and
/// withdrawn by exact octets if the peer withdraws it).
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub enum EvpnNlri {
    /// Type 2 — MAC/IP Advertisement (§7.2).
    MacIp {
        rd: Rd,
        esi: Esi,
        eth_tag: u32,
        mac: [u8; 6],
        /// The optional IP bound to the MAC (ARP/ND suppression, IRB).
        ip: Option<IpAddr>,
        /// Label1: the L2 VNI under VXLAN encapsulation (RFC 8365 §5.1.3).
        label1: u32,
        /// Label2: the L3 VNI for symmetric IRB, when present.
        label2: Option<u32>,
    },
    /// Type 3 — Inclusive Multicast Ethernet Tag (§7.3): EVI membership + BUM.
    Imet {
        rd: Rd,
        eth_tag: u32,
        /// The originating router's IP (the local VTEP).
        orig_ip: IpAddr,
    },
    /// Type 5 — IP Prefix (RFC 9136 §3.1): inter-subnet forwarding.
    IpPrefix {
        rd: Rd,
        esi: Esi,
        eth_tag: u32,
        prefix: Prefix,
        /// The gateway address; unspecified (all-zero) when the label/next-hop
        /// fully identifies the egress (RFC 9136 §3.2).
        gw: IpAddr,
        /// The L3 VNI under VXLAN encapsulation.
        label: u32,
    },
    /// Any route type we don't interpret (types 1, 4, and future ones): kept as
    /// raw octets so it round-trips and can be skipped per §7.
    Unknown { route_type: u8, body: Vec<u8> },
}

impl EvpnNlri {
    /// The wire route type of this NLRI.
    pub fn route_type(&self) -> u8 {
        match self {
            EvpnNlri::MacIp { .. } => ROUTE_TYPE_MAC_IP,
            EvpnNlri::Imet { .. } => ROUTE_TYPE_IMET,
            EvpnNlri::IpPrefix { .. } => ROUTE_TYPE_IP_PREFIX,
            EvpnNlri::Unknown { route_type, .. } => *route_type,
        }
    }

    /// The Route Distinguisher, when the variant carries one we interpret.
    pub fn rd(&self) -> Option<Rd> {
        match self {
            EvpnNlri::MacIp { rd, .. }
            | EvpnNlri::Imet { rd, .. }
            | EvpnNlri::IpPrefix { rd, .. } => Some(*rd),
            EvpnNlri::Unknown { .. } => None,
        }
    }
}

/// Push a 3-octet label/VNI field (the low 24 bits of `v`).
fn push_u24(out: &mut Vec<u8>, v: u32) {
    let b = v.to_be_bytes();
    out.extend_from_slice(&b[1..4]);
}

fn read_u24(buf: &[u8]) -> Option<u32> {
    let b = buf.get(..3)?;
    Some(u32::from_be_bytes([0, b[0], b[1], b[2]]))
}

fn read_u32(buf: &[u8]) -> Option<u32> {
    let b = buf.get(..4)?;
    Some(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
}

fn read_rd(buf: &[u8]) -> Option<Rd> {
    let b = buf.get(..8)?;
    let mut rd = [0u8; 8];
    rd.copy_from_slice(b);
    Some(Rd(rd))
}

fn read_esi(buf: &[u8]) -> Option<Esi> {
    let b = buf.get(..10)?;
    let mut esi = [0u8; 10];
    esi.copy_from_slice(b);
    Some(Esi(esi))
}

/// Read an IP address whose length is given in **bits** (32 or 128), as the
/// MAC/IP and IMET route bodies encode it. 0 bits means "absent".
fn read_ip(buf: &[u8], bits: u8) -> Option<(Option<IpAddr>, usize)> {
    match bits {
        0 => Some((None, 0)),
        32 => {
            let b = buf.get(..4)?;
            Some((
                Some(IpAddr::V4(Ipv4Addr::new(b[0], b[1], b[2], b[3]))),
                4,
            ))
        }
        128 => {
            let b = buf.get(..16)?;
            let mut o = [0u8; 16];
            o.copy_from_slice(b);
            Some((Some(IpAddr::V6(Ipv6Addr::from(o))), 16))
        }
        _ => None,
    }
}

/// Append one EVPN NLRI in wire form: route type, length, body.
pub fn encode_evpn_nlri(out: &mut Vec<u8>, nlri: &EvpnNlri) {
    let mut body = Vec::new();
    match nlri {
        EvpnNlri::MacIp {
            rd,
            esi,
            eth_tag,
            mac,
            ip,
            label1,
            label2,
        } => {
            body.extend_from_slice(&rd.0);
            body.extend_from_slice(&esi.0);
            body.extend_from_slice(&eth_tag.to_be_bytes());
            body.push(48); // MAC address length in bits — always 48 (§7.2)
            body.extend_from_slice(mac);
            match ip {
                None => body.push(0),
                Some(IpAddr::V4(a)) => {
                    body.push(32);
                    body.extend_from_slice(&a.octets());
                }
                Some(IpAddr::V6(a)) => {
                    body.push(128);
                    body.extend_from_slice(&a.octets());
                }
            }
            push_u24(&mut body, *label1);
            if let Some(l2) = label2 {
                push_u24(&mut body, *l2);
            }
        }
        EvpnNlri::Imet {
            rd,
            eth_tag,
            orig_ip,
        } => {
            body.extend_from_slice(&rd.0);
            body.extend_from_slice(&eth_tag.to_be_bytes());
            match orig_ip {
                IpAddr::V4(a) => {
                    body.push(32);
                    body.extend_from_slice(&a.octets());
                }
                IpAddr::V6(a) => {
                    body.push(128);
                    body.extend_from_slice(&a.octets());
                }
            }
        }
        EvpnNlri::IpPrefix {
            rd,
            esi,
            eth_tag,
            prefix,
            gw,
            label,
        } => {
            body.extend_from_slice(&rd.0);
            body.extend_from_slice(&esi.0);
            body.extend_from_slice(&eth_tag.to_be_bytes());
            body.push(prefix.len());
            // RFC 9136 §3.1: prefix and gateway are fixed-width (4 or 16
            // octets), the total length disambiguates v4 (34) vs v6 (58).
            match (prefix.addr(), gw) {
                (IpAddr::V4(p), IpAddr::V4(g)) => {
                    body.extend_from_slice(&p.octets());
                    body.extend_from_slice(&g.octets());
                }
                (IpAddr::V6(p), IpAddr::V6(g)) => {
                    body.extend_from_slice(&p.octets());
                    body.extend_from_slice(&g.octets());
                }
                // Mixed families cannot be encoded; emit an unspecified
                // gateway of the prefix's family instead of corrupt NLRI.
                (IpAddr::V4(p), _) => {
                    body.extend_from_slice(&p.octets());
                    body.extend_from_slice(&Ipv4Addr::UNSPECIFIED.octets());
                }
                (IpAddr::V6(p), _) => {
                    body.extend_from_slice(&p.octets());
                    body.extend_from_slice(&Ipv6Addr::UNSPECIFIED.octets());
                }
            }
            push_u24(&mut body, *label);
        }
        EvpnNlri::Unknown { body: raw, .. } => body.extend_from_slice(raw),
    }
    out.push(nlri.route_type());
    out.push(body.len() as u8);
    out.extend_from_slice(&body);
}

/// Decode one EVPN NLRI from the front of `buf`, returning it and the bytes
/// consumed. `None` means malformed framing (truncated); a well-framed body we
/// cannot interpret becomes [`EvpnNlri::Unknown`] per §7.
pub fn decode_evpn_nlri(buf: &[u8]) -> Option<(EvpnNlri, usize)> {
    let route_type = *buf.first()?;
    let len = *buf.get(1)? as usize;
    let body = buf.get(2..2 + len)?;
    let consumed = 2 + len;
    let nlri = decode_body(route_type, body).unwrap_or(EvpnNlri::Unknown {
        route_type,
        body: body.to_vec(),
    });
    Some((nlri, consumed))
}

/// Decode a route-type body; `None` falls back to `Unknown` in the caller (a
/// body that doesn't parse is ignored, not a session error — RFC 7606 spirit).
fn decode_body(route_type: u8, body: &[u8]) -> Option<EvpnNlri> {
    match route_type {
        ROUTE_TYPE_MAC_IP => {
            let rd = read_rd(body)?;
            let esi = read_esi(body.get(8..)?)?;
            let eth_tag = read_u32(body.get(18..)?)?;
            let mac_len = *body.get(22)?;
            if mac_len != 48 {
                return None; // §7.2: MAC length is always 48
            }
            let mac_b = body.get(23..29)?;
            let mut mac = [0u8; 6];
            mac.copy_from_slice(mac_b);
            let ip_bits = *body.get(29)?;
            let (ip, ip_len) = read_ip(body.get(30..)?, ip_bits)?;
            let after_ip = 30 + ip_len;
            let label1 = read_u24(body.get(after_ip..)?)?;
            let rest = body.len() - (after_ip + 3);
            let label2 = if rest >= 3 {
                Some(read_u24(body.get(after_ip + 3..)?)?)
            } else {
                None
            };
            Some(EvpnNlri::MacIp {
                rd,
                esi,
                eth_tag,
                mac,
                ip,
                label1,
                label2,
            })
        }
        ROUTE_TYPE_IMET => {
            let rd = read_rd(body)?;
            let eth_tag = read_u32(body.get(8..)?)?;
            let ip_bits = *body.get(12)?;
            let (ip, _) = read_ip(body.get(13..)?, ip_bits)?;
            Some(EvpnNlri::Imet {
                rd,
                eth_tag,
                orig_ip: ip?, // §7.3: the originating IP is mandatory
            })
        }
        ROUTE_TYPE_IP_PREFIX => {
            let rd = read_rd(body)?;
            let esi = read_esi(body.get(8..)?)?;
            let eth_tag = read_u32(body.get(18..)?)?;
            let plen = *body.get(22)?;
            // Fixed-width prefix + gateway; total body length picks the family.
            let (prefix_addr, gw, after) = match body.len() {
                34 => {
                    let p = body.get(23..27)?;
                    let g = body.get(27..31)?;
                    (
                        IpAddr::V4(Ipv4Addr::new(p[0], p[1], p[2], p[3])),
                        IpAddr::V4(Ipv4Addr::new(g[0], g[1], g[2], g[3])),
                        31,
                    )
                }
                58 => {
                    let mut p = [0u8; 16];
                    p.copy_from_slice(body.get(23..39)?);
                    let mut g = [0u8; 16];
                    g.copy_from_slice(body.get(39..55)?);
                    (
                        IpAddr::V6(Ipv6Addr::from(p)),
                        IpAddr::V6(Ipv6Addr::from(g)),
                        55,
                    )
                }
                _ => return None,
            };
            let label = read_u24(body.get(after..)?)?;
            let prefix = Prefix::new(prefix_addr, plen).ok()?;
            Some(EvpnNlri::IpPrefix {
                rd,
                esi,
                eth_tag,
                prefix,
                gw,
                label,
            })
        }
        _ => None,
    }
}

/// Decode a run of EVPN NLRI filling an MP_REACH/MP_UNREACH body. Trailing
/// garbage that doesn't frame as `(type, len, body)` fails the whole run —
/// the attribute is then treated per RFC 7606 by the caller.
pub fn decode_evpn_nlris(mut buf: &[u8]) -> Option<Vec<EvpnNlri>> {
    let mut out = Vec::new();
    while !buf.is_empty() {
        let (nlri, used) = decode_evpn_nlri(buf)?;
        out.push(nlri);
        buf = &buf[used..];
    }
    Some(out)
}

impl fmt::Display for EvpnNlri {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EvpnNlri::MacIp {
                rd, mac, ip, label1, ..
            } => {
                write!(
                    f,
                    "[2]:{rd}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                    mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
                )?;
                if let Some(ip) = ip {
                    write!(f, ":{ip}")?;
                }
                write!(f, " vni {label1}")
            }
            EvpnNlri::Imet { rd, orig_ip, .. } => write!(f, "[3]:{rd}:{orig_ip}"),
            EvpnNlri::IpPrefix {
                rd, prefix, label, ..
            } => write!(f, "[5]:{rd}:{prefix} vni {label}"),
            EvpnNlri::Unknown { route_type, body } => {
                write!(f, "[{route_type}]:len {}", body.len())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rd() -> Rd {
        Rd::from_ip(Ipv4Addr::new(192, 0, 2, 1), 100)
    }

    fn roundtrip(nlri: &EvpnNlri) {
        let mut buf = Vec::new();
        encode_evpn_nlri(&mut buf, nlri);
        let (decoded, used) = decode_evpn_nlri(&buf).expect("decodes");
        assert_eq!(used, buf.len());
        assert_eq!(&decoded, nlri);
    }

    #[test]
    fn mac_ip_roundtrips_without_ip() {
        roundtrip(&EvpnNlri::MacIp {
            rd: rd(),
            esi: Esi::ZERO,
            eth_tag: 0,
            mac: [0x02, 0x00, 0x5e, 0x10, 0x00, 0x01],
            ip: None,
            label1: 10100,
            label2: None,
        });
    }

    #[test]
    fn mac_ip_roundtrips_with_v4_and_l3_label() {
        roundtrip(&EvpnNlri::MacIp {
            rd: rd(),
            esi: Esi::ZERO,
            eth_tag: 0,
            mac: [0x02, 0x00, 0x5e, 0x10, 0x00, 0x01],
            ip: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5))),
            label1: 10100,
            label2: Some(4001),
        });
    }

    #[test]
    fn mac_ip_roundtrips_with_v6() {
        roundtrip(&EvpnNlri::MacIp {
            rd: rd(),
            esi: Esi::ZERO,
            eth_tag: 0,
            mac: [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
            ip: Some(IpAddr::V6("2001:db8::5".parse().unwrap())),
            label1: 10100,
            label2: None,
        });
    }

    #[test]
    fn imet_roundtrips_v4_and_v6() {
        roundtrip(&EvpnNlri::Imet {
            rd: rd(),
            eth_tag: 0,
            orig_ip: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
        });
        roundtrip(&EvpnNlri::Imet {
            rd: rd(),
            eth_tag: 0,
            orig_ip: IpAddr::V6("2001:db8::1".parse().unwrap()),
        });
    }

    #[test]
    fn ip_prefix_roundtrips_v4_and_v6() {
        roundtrip(&EvpnNlri::IpPrefix {
            rd: rd(),
            esi: Esi::ZERO,
            eth_tag: 0,
            prefix: Prefix::new(IpAddr::V4(Ipv4Addr::new(10, 1, 0, 0)), 24).unwrap(),
            gw: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            label: 4001,
        });
        roundtrip(&EvpnNlri::IpPrefix {
            rd: rd(),
            esi: Esi::ZERO,
            eth_tag: 0,
            prefix: Prefix::new("2001:db8:1::".parse().unwrap(), 64).unwrap(),
            gw: IpAddr::V6(Ipv6Addr::UNSPECIFIED),
            label: 4001,
        });
    }

    #[test]
    fn unknown_route_type_is_skipped_not_rejected() {
        // A type-4 (Ethernet Segment) route we don't interpret: framing is
        // fine, so it decodes as Unknown and consumes exactly its length.
        let mut buf = vec![ROUTE_TYPE_ETH_SEGMENT, 3, 0xaa, 0xbb, 0xcc];
        buf.extend_from_slice(&[ROUTE_TYPE_IMET, 0]); // second, garbage-bodied
        let (first, used) = decode_evpn_nlri(&buf).unwrap();
        assert_eq!(
            first,
            EvpnNlri::Unknown {
                route_type: ROUTE_TYPE_ETH_SEGMENT,
                body: vec![0xaa, 0xbb, 0xcc],
            }
        );
        assert_eq!(used, 5);
    }

    #[test]
    fn malformed_body_becomes_unknown_but_truncated_framing_fails() {
        // Well-framed but nonsense MAC/IP body → Unknown (ignored), not error.
        let buf = [ROUTE_TYPE_MAC_IP, 2, 0x01, 0x02];
        let (nlri, used) = decode_evpn_nlri(&buf).unwrap();
        assert!(matches!(nlri, EvpnNlri::Unknown { .. }));
        assert_eq!(used, 4);
        // Truncated framing (length octet promises more than the buffer has).
        assert!(decode_evpn_nlri(&[ROUTE_TYPE_MAC_IP, 40, 0x00]).is_none());
        assert!(decode_evpn_nlri(&[]).is_none());
    }

    #[test]
    fn mac_len_other_than_48_is_ignored() {
        let mut buf = Vec::new();
        encode_evpn_nlri(
            &mut buf,
            &EvpnNlri::MacIp {
                rd: rd(),
                esi: Esi::ZERO,
                eth_tag: 0,
                mac: [0; 6],
                ip: None,
                label1: 1,
                label2: None,
            },
        );
        buf[2 + 22] = 24; // corrupt the MAC length field
        let (nlri, _) = decode_evpn_nlri(&buf).unwrap();
        assert!(matches!(nlri, EvpnNlri::Unknown { .. }));
    }

    #[test]
    fn nlri_run_decodes_all_or_nothing() {
        let mut buf = Vec::new();
        encode_evpn_nlri(
            &mut buf,
            &EvpnNlri::Imet {
                rd: rd(),
                eth_tag: 0,
                orig_ip: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            },
        );
        let one = decode_evpn_nlris(&buf).unwrap();
        assert_eq!(one.len(), 1);
        buf.push(0x07); // trailing garbage that can't frame
        assert!(decode_evpn_nlris(&buf).is_none());
    }

    #[test]
    fn rd_formats_by_type() {
        assert_eq!(rd().to_string(), "192.0.2.1:100");
        assert_eq!(Rd::from_as2(65001, 10100).to_string(), "65001:10100");
    }

    #[test]
    fn encap_community_is_vxlan_shaped() {
        let c = encap_ext_community(TUNNEL_TYPE_VXLAN);
        assert_eq!(c, [0x03, 0x0c, 0, 0, 0, 0, 0, 8]);
    }
}
