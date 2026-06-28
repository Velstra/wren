//! The flooding procedure (RFC 2328 §13) — what to do with an LSA that arrived
//! in a Link State Update, and where to send LSAs onward (§13.3).
//!
//! This is the decision kernel, kept pure: [`decide_flood`] takes the link-state
//! database, the received LSA and the few facts the runner knows about the
//! receiving adjacency (whether the LSA is on the neighbour's request or our
//! retransmission list, whether any neighbour is mid-exchange, how long our copy
//! has been installed) and returns a [`FloodDecision`] — install and reflood,
//! acknowledge, send our newer copy back, or discard. It does *not* mutate the
//! database: the runner installs on [`FloodDecision::Install`] (it owns the clock
//! and the sockets). [`flood_scope`] is the companion §13.3 rule deciding the
//! multicast destination for sending an LSA out a given interface — the part that
//! makes a DROther flood only to the DR/BDR.
//!
//! Steps 1–3 of §13 (checksum, known LS type, stub-area filtering) happen earlier
//! — the LSA reached here already decoded and checksum-verified by
//! [`crate::packet`]/[`crate::lsa`]; this module is §13 steps 4 onward.

use std::net::Ipv4Addr;

use crate::interface::{InterfaceState, InterfaceType};
use crate::lsa::Lsa;
use crate::lsdb::Lsdb;
use crate::{MAX_AGE, MAX_SEQUENCE_NUMBER, MIN_LS_ARRIVAL};

/// The facts the runner supplies about a received LSA and its adjacency.
pub struct FloodInput<'a> {
    /// The link-state database for the LSA's scope (area, or AS for type 5).
    pub lsdb: &'a Lsdb,
    /// The LSA just received (already checksum-validated).
    pub received: &'a Lsa,
    /// This router's own Router ID, to detect a self-originated LSA (§13.4).
    pub self_router_id: Ipv4Addr,
    /// Seconds since our database copy was installed, or `None` if we hold none.
    /// Drives the MinLSArrival rate limit (§13 step 5a).
    pub db_copy_age_since_install: Option<u16>,
    /// Whether the received LSA is on the sending neighbour's Link State Request
    /// list (§13 step 6 — a Database Exchange error).
    pub on_request_list: bool,
    /// Whether the received LSA is on our Link State retransmission list to this
    /// neighbour (§13 step 7a — an implied acknowledgment).
    pub on_retransmit_list: bool,
    /// Whether any neighbour is in Exchange or Loading — governs the MaxAge-flush
    /// shortcut (§13 step 4).
    pub any_neighbor_exchanging: bool,
}

/// Why an LSA was dropped without further action.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum DiscardReason {
    /// A new instance arrived less than MinLSArrival after the last (§13 step 5a).
    MinLsArrival,
    /// Our copy is at MaxAge with MaxSequenceNumber — a sequence-space wrap in
    /// progress; the received older copy is ignored (§13 step 8).
    MaxSeqWrap,
}

/// What the runner must do with the received LSA (§13 steps 4–8).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum FloodDecision {
    /// Install into the database and flood onward (§13 step 5). `self_originated`
    /// flags that the LSA claims to come from us yet is newer than our copy — the
    /// runner must fight back per §13.4 (re-originate a higher instance, or flush).
    Install { self_originated: bool },
    /// Duplicate that was on our retransmission list — an implied acknowledgment;
    /// drop it from the retransmission list, send no ack (§13 step 7a).
    ImpliedAck,
    /// Duplicate not awaiting retransmission, or a MaxAge flush for an unknown
    /// LSA — send a direct Link State Acknowledgment (§13 step 7b / step 4).
    DirectAck,
    /// Our database copy is more recent — send it back to the neighbour, no ack
    /// (§13 step 8).
    SendBack,
    /// The LSA is on the neighbour's request list though not newer — a Database
    /// Exchange error; raise BadLSReq (§13 step 6).
    BadLsReq,
    /// Drop the LSA silently.
    Discard(DiscardReason),
}

/// Decide the fate of a received LSA (§13 steps 4–8).
pub fn decide_flood(input: &FloodInput) -> FloodDecision {
    let recv = input.received;
    let key = recv.key();
    let db = input.lsdb.header(&key);
    let recv_maxage = recv.header.ls_age >= MAX_AGE;

    // Step 4: a MaxAge LSA we do not hold, with nobody mid-exchange, is just
    // acknowledged and dropped — there is nothing to flush.
    if recv_maxage && db.is_none() && !input.any_neighbor_exchanging {
        return FloodDecision::DirectAck;
    }

    let self_originated = recv.header.advertising_router == input.self_router_id;

    let Some(db_hdr) = db else {
        // No database copy: the received LSA is, by definition, the newest.
        return FloodDecision::Install { self_originated };
    };

    match recv.header.compare_recency(db_hdr) {
        // Step 5: received is strictly more recent → install (rate-limited).
        std::cmp::Ordering::Greater => {
            if let Some(since) = input.db_copy_age_since_install {
                if since < MIN_LS_ARRIVAL {
                    return FloodDecision::Discard(DiscardReason::MinLsArrival);
                }
            }
            FloodDecision::Install { self_originated }
        }
        // Not more recent. Step 6 first: on the request list is a protocol error.
        _ if input.on_request_list => FloodDecision::BadLsReq,
        // Step 7: the same instance — acknowledge (implied or direct).
        std::cmp::Ordering::Equal => {
            if input.on_retransmit_list {
                FloodDecision::ImpliedAck
            } else {
                FloodDecision::DirectAck
            }
        }
        // Step 8: our copy is more recent. Guard the sequence-wrap corner, else
        // send our copy back to the neighbour.
        std::cmp::Ordering::Less => {
            if db_hdr.ls_age >= MAX_AGE && db_hdr.ls_seq == MAX_SEQUENCE_NUMBER {
                FloodDecision::Discard(DiscardReason::MaxSeqWrap)
            } else {
                FloodDecision::SendBack
            }
        }
    }
}

/// The multicast destination for flooding an LSA out one interface (§13.3).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum FloodScope {
    /// `AllSPFRouters` (224.0.0.5) — every router on the link.
    AllSpfRouters,
    /// `AllDRouters` (224.0.0.6) — only the DR and BDR.
    AllDRouters,
}

/// Decide whether (and to whom) to flood an LSA out an interface (§13.3). Returns
/// `None` when this interface should be skipped, otherwise the multicast scope.
///
/// `received_on_iface` is whether the LSA arrived on *this* interface, and
/// `from_dr_or_bdr` whether its sender was that interface's DR or BDR.
pub fn flood_scope(
    iface_type: InterfaceType,
    state: InterfaceState,
    received_on_iface: bool,
    from_dr_or_bdr: bool,
) -> Option<FloodScope> {
    if iface_type.elects_dr() {
        // §13.3(1d): arrived from the DR/BDR — everyone on the link already has it.
        if received_on_iface && from_dr_or_bdr {
            return None;
        }
        // §13.3(1e): we are the Backup and it arrived here — let the DR flood it.
        if received_on_iface && state == InterfaceState::Backup {
            return None;
        }
        // §13.3(4): the DR/BDR speak to everyone; a DROther only to the DR/BDR.
        if matches!(state, InterfaceState::Dr | InterfaceState::Backup) {
            Some(FloodScope::AllSpfRouters)
        } else {
            Some(FloodScope::AllDRouters)
        }
    } else {
        // Point-to-point / point-to-multipoint / virtual: reach every router. The
        // per-neighbour retransmission list (the runner's job) keeps the LSA from
        // bouncing straight back to the sender.
        Some(FloodScope::AllSpfRouters)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lsa::{Lsa, LsaBody, LsaHeader, LsType, RouterLsa};
    use crate::{INITIAL_SEQUENCE_NUMBER, OPT_E};

    fn ip(o: [u8; 4]) -> Ipv4Addr {
        Ipv4Addr::from(o)
    }

    fn router_lsa(advr: [u8; 4], seq: i32, age: u16) -> Lsa {
        Lsa {
            header: LsaHeader {
                ls_age: age,
                options: OPT_E,
                ls_type: LsType::Router,
                link_state_id: ip(advr),
                advertising_router: ip(advr),
                ls_seq: seq,
                ls_checksum: 0,
                length: 0,
            },
            body: LsaBody::Router(RouterLsa { flags: 0, links: vec![] }),
        }
    }

    /// A baseline input: someone else's LSA, no list membership, nobody exchanging.
    fn input<'a>(lsdb: &'a Lsdb, received: &'a Lsa) -> FloodInput<'a> {
        FloodInput {
            lsdb,
            received,
            self_router_id: ip([9, 9, 9, 9]),
            db_copy_age_since_install: None,
            on_request_list: false,
            on_retransmit_list: false,
            any_neighbor_exchanging: false,
        }
    }

    #[test]
    fn brand_new_lsa_is_installed() {
        let db = Lsdb::new();
        let lsa = router_lsa([1, 1, 1, 1], 5, 1);
        assert_eq!(
            decide_flood(&input(&db, &lsa)),
            FloodDecision::Install { self_originated: false }
        );
    }

    #[test]
    fn newer_installs_older_sends_back() {
        let mut db = Lsdb::new();
        db.install(router_lsa([1, 1, 1, 1], 5, 10));

        let newer = router_lsa([1, 1, 1, 1], 6, 1);
        let mut inp = input(&db, &newer);
        inp.db_copy_age_since_install = Some(10); // well past MinLSArrival
        assert_eq!(decide_flood(&inp), FloodDecision::Install { self_originated: false });

        let older = router_lsa([1, 1, 1, 1], 4, 1);
        assert_eq!(decide_flood(&input(&db, &older)), FloodDecision::SendBack);
    }

    #[test]
    fn min_ls_arrival_rate_limits_a_fresh_install() {
        let mut db = Lsdb::new();
        db.install(router_lsa([1, 1, 1, 1], 5, 10));
        let newer = router_lsa([1, 1, 1, 1], 6, 1);
        let mut inp = input(&db, &newer);
        inp.db_copy_age_since_install = Some(0); // installed just now
        assert_eq!(
            decide_flood(&inp),
            FloodDecision::Discard(DiscardReason::MinLsArrival)
        );
    }

    #[test]
    fn duplicate_acks_implied_or_direct() {
        let mut db = Lsdb::new();
        db.install(router_lsa([1, 1, 1, 1], 5, 10));
        let dup = router_lsa([1, 1, 1, 1], 5, 10);

        let mut on_retx = input(&db, &dup);
        on_retx.on_retransmit_list = true;
        assert_eq!(decide_flood(&on_retx), FloodDecision::ImpliedAck);

        assert_eq!(decide_flood(&input(&db, &dup)), FloodDecision::DirectAck);
    }

    #[test]
    fn on_request_list_but_not_newer_is_bad_ls_req() {
        let mut db = Lsdb::new();
        db.install(router_lsa([1, 1, 1, 1], 5, 10));
        let dup = router_lsa([1, 1, 1, 1], 5, 10);
        let mut inp = input(&db, &dup);
        inp.on_request_list = true;
        assert_eq!(decide_flood(&inp), FloodDecision::BadLsReq);
    }

    #[test]
    fn maxage_flush_for_unknown_lsa_is_acked_and_dropped() {
        let db = Lsdb::new();
        let flush = router_lsa([1, 1, 1, 1], 5, MAX_AGE);
        // Nobody exchanging → ack and drop.
        assert_eq!(decide_flood(&input(&db, &flush)), FloodDecision::DirectAck);

        // But if a neighbour is mid-exchange, install it so it floods through.
        let mut inp = input(&db, &flush);
        inp.any_neighbor_exchanging = true;
        assert_eq!(decide_flood(&inp), FloodDecision::Install { self_originated: false });
    }

    #[test]
    fn sequence_wrap_corner_discards_older() {
        let mut db = Lsdb::new();
        db.install(router_lsa([1, 1, 1, 1], MAX_SEQUENCE_NUMBER, MAX_AGE));
        let older = router_lsa([1, 1, 1, 1], INITIAL_SEQUENCE_NUMBER, 1);
        assert_eq!(
            decide_flood(&input(&db, &older)),
            FloodDecision::Discard(DiscardReason::MaxSeqWrap)
        );
    }

    #[test]
    fn self_originated_newer_copy_is_flagged() {
        let db = Lsdb::new();
        let mine = router_lsa([9, 9, 9, 9], 7, 1); // advertising_router == self
        assert_eq!(
            decide_flood(&input(&db, &mine)),
            FloodDecision::Install { self_originated: true }
        );
    }

    #[test]
    fn flood_scope_dr_other_only_reaches_the_d_routers() {
        // A DROther floods to AllDRouters; the DR/Backup flood to AllSPFRouters.
        assert_eq!(
            flood_scope(InterfaceType::Broadcast, InterfaceState::DrOther, false, false),
            Some(FloodScope::AllDRouters)
        );
        assert_eq!(
            flood_scope(InterfaceType::Broadcast, InterfaceState::Dr, false, false),
            Some(FloodScope::AllSpfRouters)
        );
    }

    #[test]
    fn flood_scope_skips_when_received_from_dr_or_as_backup() {
        // Arrived from the DR on this interface → no reflood (1d).
        assert_eq!(
            flood_scope(InterfaceType::Broadcast, InterfaceState::DrOther, true, true),
            None
        );
        // We are the Backup and it arrived here → leave it to the DR (1e).
        assert_eq!(
            flood_scope(InterfaceType::Broadcast, InterfaceState::Backup, true, false),
            None
        );
    }

    #[test]
    fn flood_scope_point_to_point_always_all_spf() {
        assert_eq!(
            flood_scope(InterfaceType::PointToPoint, InterfaceState::PointToPoint, true, false),
            Some(FloodScope::AllSpfRouters)
        );
    }
}
