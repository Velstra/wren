//! Grace-LSA (RFC 3623 §2) — the payload a router floods to ask its neighbours to act
//! as graceful-restart helpers while it restarts its OSPF software without disrupting
//! forwarding.
//!
//! A Grace-LSA is a **link-local opaque LSA** ([`crate::lsa::LsType::OpaqueLink`], type
//! 9) with Opaque Type [`OPAQUE_TYPE_GRACE`] (3) and Opaque ID 0, flooded on each of the
//! restarting router's interfaces just before (and during) the restart. Its body is a
//! sequence of TLVs (RFC 2370 §2.1 encoding: 2-byte type, 2-byte length, value padded to
//! a 4-byte boundary) carrying the grace period, the restart reason and — on multi-access
//! links — the interface address. This module is the pure codec for that body; the
//! opaque-LSA envelope is built in [`crate::lsa`].

use std::net::Ipv4Addr;

/// The Opaque Type of a Grace-LSA within its Link State ID (RFC 3623 §2).
pub const OPAQUE_TYPE_GRACE: u8 = 3;

/// TLV type 1 — the grace period, in seconds (RFC 3623 §2.1).
const TLV_GRACE_PERIOD: u16 = 1;
/// TLV type 2 — the graceful-restart reason (RFC 3623 §2.2).
const TLV_RESTART_REASON: u16 = 2;
/// TLV type 3 — the interface's IP address (RFC 3623 §2.3), for multi-access links.
const TLV_IP_INTERFACE_ADDRESS: u16 = 3;

/// Why a router is performing a graceful restart (RFC 3623 §2.2, the reason TLV value).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RestartReason {
    /// 0 — unknown.
    Unknown,
    /// 1 — a software restart.
    SoftwareRestart,
    /// 2 — a software reload or upgrade.
    SoftwareReload,
    /// 3 — a switch to a redundant control processor.
    SwitchToRedundant,
}

impl RestartReason {
    /// The on-wire reason byte.
    pub fn as_u8(self) -> u8 {
        match self {
            RestartReason::Unknown => 0,
            RestartReason::SoftwareRestart => 1,
            RestartReason::SoftwareReload => 2,
            RestartReason::SwitchToRedundant => 3,
        }
    }

    /// Decode the reason byte; unknown values map to [`RestartReason::Unknown`] so a
    /// future reason never fails the parse (RFC 3623 is permissive here).
    pub fn from_u8(v: u8) -> RestartReason {
        match v {
            1 => RestartReason::SoftwareRestart,
            2 => RestartReason::SoftwareReload,
            3 => RestartReason::SwitchToRedundant,
            _ => RestartReason::Unknown,
        }
    }
}

/// A decoded Grace-LSA body (RFC 3623 §2).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct GraceLsa {
    /// The grace period in seconds: how long the restarting router asks its neighbours to
    /// keep helping (retain the adjacency and its LSAs) before giving up.
    pub grace_period: u32,
    /// Why the router is restarting.
    pub reason: RestartReason,
    /// The restarting interface's IP address (`0.0.0.0` when omitted — it is optional on
    /// point-to-point links, where the neighbour is unambiguous).
    pub interface_address: Ipv4Addr,
}

/// Append a TLV (type, length, value) with the value zero-padded to a 4-byte boundary
/// (RFC 2370 §2.1).
fn put_tlv(out: &mut Vec<u8>, tlv_type: u16, value: &[u8]) {
    out.extend_from_slice(&tlv_type.to_be_bytes());
    out.extend_from_slice(&(value.len() as u16).to_be_bytes());
    out.extend_from_slice(value);
    while out.len() % 4 != 0 {
        out.push(0);
    }
}

impl GraceLsa {
    /// Encode the Grace-LSA body (the opaque payload placed after the 20-byte LSA
    /// header). The grace-period and reason TLVs are always present; the interface
    /// address is included only when non-zero.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(24);
        put_tlv(&mut out, TLV_GRACE_PERIOD, &self.grace_period.to_be_bytes());
        put_tlv(&mut out, TLV_RESTART_REASON, &[self.reason.as_u8()]);
        if !self.interface_address.is_unspecified() {
            put_tlv(
                &mut out,
                TLV_IP_INTERFACE_ADDRESS,
                &self.interface_address.octets(),
            );
        }
        out
    }

    /// Parse a Grace-LSA body from the opaque payload. Requires the mandatory
    /// grace-period and reason TLVs; unknown TLVs are skipped (RFC 2370 forward
    /// compatibility). Returns `None` on a malformed or incomplete body.
    pub fn decode(data: &[u8]) -> Option<GraceLsa> {
        let mut grace_period: Option<u32> = None;
        let mut reason: Option<RestartReason> = None;
        let mut interface_address = Ipv4Addr::UNSPECIFIED;

        let mut off = 0;
        while off + 4 <= data.len() {
            let tlv_type = u16::from_be_bytes([data[off], data[off + 1]]);
            let len = u16::from_be_bytes([data[off + 2], data[off + 3]]) as usize;
            let val_start = off + 4;
            let val_end = val_start.checked_add(len)?;
            if val_end > data.len() {
                return None;
            }
            let value = &data[val_start..val_end];
            match tlv_type {
                TLV_GRACE_PERIOD if len == 4 => {
                    grace_period = Some(u32::from_be_bytes(value.try_into().ok()?));
                }
                TLV_RESTART_REASON if len == 1 => {
                    reason = Some(RestartReason::from_u8(value[0]));
                }
                TLV_IP_INTERFACE_ADDRESS if len == 4 => {
                    interface_address = Ipv4Addr::new(value[0], value[1], value[2], value[3]);
                }
                _ => {} // unknown or wrong-length TLV — skip
            }
            // Advance past the value, padded to the next 4-byte boundary.
            off = val_end + ((4 - (len % 4)) % 4);
        }

        Some(GraceLsa {
            grace_period: grace_period?,
            reason: reason?,
            interface_address,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reason_roundtrips_and_defaults_unknown() {
        for r in [
            RestartReason::Unknown,
            RestartReason::SoftwareRestart,
            RestartReason::SoftwareReload,
            RestartReason::SwitchToRedundant,
        ] {
            assert_eq!(RestartReason::from_u8(r.as_u8()), r);
        }
        assert_eq!(RestartReason::from_u8(99), RestartReason::Unknown);
    }

    #[test]
    fn grace_lsa_roundtrips_with_interface_address() {
        let g = GraceLsa {
            grace_period: 120,
            reason: RestartReason::SoftwareRestart,
            interface_address: Ipv4Addr::new(10, 0, 0, 1),
        };
        let bytes = g.encode();
        // Every TLV is 4-byte aligned: grace(4+4) + reason(4+pad to 4) + ifaddr(4+4).
        assert_eq!(bytes.len() % 4, 0);
        assert_eq!(GraceLsa::decode(&bytes), Some(g));
    }

    #[test]
    fn grace_lsa_roundtrips_without_interface_address() {
        // On a point-to-point link the interface address is omitted; decode yields 0.0.0.0.
        let g = GraceLsa {
            grace_period: 60,
            reason: RestartReason::SoftwareReload,
            interface_address: Ipv4Addr::UNSPECIFIED,
        };
        let bytes = g.encode();
        assert!(!bytes
            .windows(2)
            .any(|w| w == TLV_IP_INTERFACE_ADDRESS.to_be_bytes()));
        assert_eq!(GraceLsa::decode(&bytes), Some(g));
    }

    #[test]
    fn decode_skips_unknown_tlv_and_needs_mandatory_ones() {
        // A body carrying only the reason TLV is incomplete (no grace period).
        let mut only_reason = Vec::new();
        put_tlv(&mut only_reason, TLV_RESTART_REASON, &[1]);
        assert_eq!(GraceLsa::decode(&only_reason), None);

        // A well-formed body with an extra unknown TLV still decodes.
        let mut body = Vec::new();
        put_tlv(&mut body, 99, &[1, 2, 3, 4, 5]); // unknown, odd length → padded
        put_tlv(&mut body, TLV_GRACE_PERIOD, &200u32.to_be_bytes());
        put_tlv(&mut body, TLV_RESTART_REASON, &[3]);
        let g = GraceLsa::decode(&body).expect("decodes past the unknown TLV");
        assert_eq!(g.grace_period, 200);
        assert_eq!(g.reason, RestartReason::SwitchToRedundant);
    }

    #[test]
    fn decode_rejects_a_truncated_tlv() {
        // A TLV claiming 4 bytes of value but with only 2 present.
        let bad = vec![0x00, TLV_GRACE_PERIOD as u8, 0x00, 0x04, 0x00, 0x01];
        assert_eq!(GraceLsa::decode(&bad), None);
    }
}
