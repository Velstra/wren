//! Designated Intermediate System election (ISO/IEC 10589 §8.4.5) — the LAN-only,
//! per-level election of the router that originates the LAN's pseudonode LSP.
//!
//! Two things make the DIS election simpler than OSPF's Designated Router
//! election (RFC 2328 §9.4):
//!
//! * **It is preemptive.** A higher-priority router that appears on the LAN takes
//!   over the DIS role *at once* — there is no "the established DR keeps the role"
//!   rule, and so no two-step §9.4 dance. The election is a plain maximum.
//! * **There is no backup.** OSPF elects a DR *and* a BDR for fast failover; IS-IS
//!   elects only the DIS and relies on its frequent (every ~3⅓ s) CSNPs to keep
//!   the database tight, so a lost DIS is simply re-elected.
//!
//! The winner is the highest **priority** (a 7-bit value, default 64); ties break
//! on the highest **SNPA** — the LAN MAC address, *not* the System ID, because the
//! SNPA is the identifier that is meaningful at the link layer. Every router is
//! eligible: unlike OSPF there is no priority-0 "ineligible" case, so a lone
//! priority-0 router still becomes its own DIS.

use std::cmp::Ordering;

use crate::SystemId;

/// One participant in the DIS election (ISO 10589 §8.4.5): a router on the LAN
/// with its System ID, its SNPA (LAN MAC) and its advertised priority.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct DisCandidate {
    /// The router's System ID.
    pub system_id: SystemId,
    /// The router's SNPA (its LAN MAC) — the election's tie-break.
    pub snpa: [u8; 6],
    /// The router's advertised DIS priority (7 bits; higher wins).
    pub priority: u8,
}

impl DisCandidate {
    /// Build a candidate.
    pub fn new(system_id: SystemId, snpa: [u8; 6], priority: u8) -> Self {
        DisCandidate {
            system_id,
            snpa,
            priority,
        }
    }
}

/// Order two candidates for "more eligible to be DIS": higher priority wins, ties
/// broken by the higher SNPA (ISO 10589 §8.4.5).
fn more_eligible(a: &DisCandidate, b: &DisCandidate) -> Ordering {
    a.priority
        .cmp(&b.priority)
        .then_with(|| a.snpa.cmp(&b.snpa))
}

/// Elect the DIS from `candidates` — which must include the calculating router —
/// returning the winner, or `None` if the set is empty. Highest priority wins,
/// ties broken on the highest SNPA. Because the election is a plain maximum it is
/// inherently preemptive: re-running it the moment the candidate set changes
/// always yields the currently-best router.
pub fn elect_dis(candidates: &[DisCandidate]) -> Option<DisCandidate> {
    candidates.iter().copied().max_by(more_eligible)
}

/// Whether `me` wins the DIS election over `candidates` (which must include `me`).
/// A convenience over [`elect_dis`] for the common "am I the DIS?" question.
pub fn is_dis(candidates: &[DisCandidate], me: SystemId) -> bool {
    elect_dis(candidates).is_some_and(|w| w.system_id == me)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sid(n: u8) -> SystemId {
        SystemId::new([n, n, n, n, n, n])
    }

    fn mac(n: u8) -> [u8; 6] {
        [0x00, 0x00, 0x00, 0x00, 0x00, n]
    }

    fn cand(id: u8, m: u8, prio: u8) -> DisCandidate {
        DisCandidate::new(sid(id), mac(m), prio)
    }

    #[test]
    fn highest_priority_wins() {
        let r1 = cand(1, 1, 64);
        let r2 = cand(2, 2, 100);
        let r3 = cand(3, 3, 10);
        let dis = elect_dis(&[r1, r2, r3]).unwrap();
        assert_eq!(dis.system_id, sid(2));
        assert!(is_dis(&[r1, r2, r3], sid(2)));
        assert!(!is_dis(&[r1, r2, r3], sid(1)));
    }

    #[test]
    fn ties_break_on_higher_snpa_not_system_id() {
        // Equal priority. R1 has the lower System ID but the *higher* SNPA, so it
        // wins — proving the tie-break is the MAC, not the System ID.
        let r1 = cand(1, 0xff, 64);
        let r2 = cand(2, 0x01, 64);
        let dis = elect_dis(&[r1, r2]).unwrap();
        assert_eq!(dis.system_id, sid(1));
        assert_eq!(dis.snpa, mac(0xff));
    }

    #[test]
    fn election_is_preemptive() {
        // R1 is the lone router and DIS.
        let r1 = cand(1, 1, 64);
        assert_eq!(elect_dis(&[r1]).unwrap().system_id, sid(1));
        // A higher-priority R9 appears and immediately takes over — no "established
        // DIS keeps the role" rule (the OSPF contrast).
        let r9 = cand(9, 9, 100);
        assert_eq!(elect_dis(&[r1, r9]).unwrap().system_id, sid(9));
    }

    #[test]
    fn lone_priority_zero_router_still_wins() {
        // No priority-0 "ineligible" case as in OSPF.
        let r1 = cand(1, 1, 0);
        assert_eq!(elect_dis(&[r1]).unwrap().system_id, sid(1));
        assert!(is_dis(&[r1], sid(1)));
    }

    #[test]
    fn empty_candidate_set_has_no_dis() {
        assert_eq!(elect_dis(&[]), None);
        assert!(!is_dis(&[], sid(1)));
    }
}
