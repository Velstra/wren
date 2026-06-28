//! The interface state machine (RFC 5340 §4.2.5, inheriting RFC 2328 §9) and the
//! Designated Router election (§9.4) — the per-interface logic that decides this
//! router's role on a network and, on multi-access links, who the DR and BDR are.
//!
//! OSPFv3's interface FSM and DR election are **unchanged** from OSPFv2, with one
//! simplification: the DR/BDR fields of an OSPFv3 Hello hold **Router IDs**
//! directly (OSPFv2 carried interface addresses that the runner had to map to
//! router IDs before electing). So the candidate set here is already in terms of
//! Router IDs with no mapping step.
//!
//! Both pieces are pure. [`elect_dr_bdr`] is the §9.4 algorithm as a free function
//! over a candidate set (each router's priority and its currently advertised
//! DR/BDR), including the §9.4(5) recomputation when the calculating router's own
//! role flips. [`Interface::handle`] is the §9.3 transition table; on the events
//! that trigger an election it folds the result back into the interface state.

use std::cmp::Ordering;
use std::net::Ipv4Addr;

/// How an interface attaches to its network (§9.1, the interface type) — it
/// decides whether a DR is elected at all and the post-`InterfaceUp` state.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum InterfaceType {
    /// A link to exactly one other router (no DR).
    PointToPoint,
    /// A multi-access network with multicast (Ethernet) — elects a DR/BDR.
    Broadcast,
    /// A non-broadcast multi-access network — elects a DR/BDR, Hellos unicast.
    Nbma,
    /// Point-to-multipoint: treated as a collection of point-to-point links.
    PointToMultipoint,
    /// A virtual link through the transit area (no DR).
    Virtual,
}

impl InterfaceType {
    /// Whether this interface type elects a Designated Router (§9.4).
    pub fn elects_dr(self) -> bool {
        matches!(self, InterfaceType::Broadcast | InterfaceType::Nbma)
    }
}

/// The interface states (§9.1).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum InterfaceState {
    /// The interface is unusable.
    Down,
    /// A looped-back interface — advertised but carries no traffic.
    Loopback,
    /// Waiting to learn the DR/BDR before electing (broadcast/NBMA only).
    Waiting,
    /// Operational point-to-point (also point-to-multipoint / virtual).
    PointToPoint,
    /// On a multi-access network, this router is neither DR nor BDR.
    DrOther,
    /// This router is the Backup Designated Router.
    Backup,
    /// This router is the Designated Router.
    Dr,
}

/// The events that drive the interface machine (§9.2).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum InterfaceEvent {
    /// The interface became operational.
    InterfaceUp,
    /// The wait timer expired without learning the DR — elect now.
    WaitTimer,
    /// A Hello revealed an existing BDR — the wait can end early.
    BackupSeen,
    /// A neighbour's state crossed a threshold relevant to the election.
    NeighborChange,
    /// The interface was looped back.
    LoopInd,
    /// The loopback was removed.
    UnloopInd,
    /// The interface went down administratively or physically.
    InterfaceDown,
}

/// A side effect the runner must perform after a transition.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum InterfaceAction {
    /// Begin sending periodic Hellos on this interface.
    StartHellos,
    /// Arm the wait timer (RouterDeadInterval) to bound DR discovery.
    StartWaitTimer,
    /// Cancel the wait timer (the election ran).
    StopWaitTimer,
    /// Clear neighbours and elected state (interface went Down/Loopback).
    ResetInterface,
    /// The elected DR/BDR changed — (re)build adjacencies and Network-LSAs.
    ElectionChanged,
}

/// One participant in the DR election (§9.4): a router on the network with its
/// priority and the DR/BDR it currently advertises (Router IDs, `0.0.0.0` none).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Candidate {
    /// The router's identity.
    pub router_id: Ipv4Addr,
    /// Its Router Priority (0 = ineligible to be DR/BDR).
    pub priority: u8,
    /// The DR it advertises.
    pub declared_dr: Ipv4Addr,
    /// The BDR it advertises.
    pub declared_bdr: Ipv4Addr,
}

/// Order two candidates for "more eligible": higher priority wins, ties broken by
/// the higher Router ID (§9.4).
fn more_eligible(a: &Candidate, b: &Candidate) -> Ordering {
    a.priority
        .cmp(&b.priority)
        .then_with(|| u32::from(a.router_id).cmp(&u32::from(b.router_id)))
}

/// The best candidate from `pool`, or `0.0.0.0` if it is empty.
fn best(pool: impl Iterator<Item = Candidate>) -> Ipv4Addr {
    pool.max_by(more_eligible)
        .map(|c| c.router_id)
        .unwrap_or(Ipv4Addr::UNSPECIFIED)
}

/// Calculate the Backup Designated Router (§9.4 step 3).
fn calc_bdr(cands: &[Candidate]) -> Ipv4Addr {
    // Eligible routers that do not declare *themselves* DR.
    let not_dr = || {
        cands
            .iter()
            .copied()
            .filter(|c| c.priority > 0 && c.declared_dr != c.router_id)
    };
    // Prefer those that declared themselves BDR; otherwise all of `not_dr`.
    let declaring_self_bdr: Vec<Candidate> =
        not_dr().filter(|c| c.declared_bdr == c.router_id).collect();
    if declaring_self_bdr.is_empty() {
        best(not_dr())
    } else {
        best(declaring_self_bdr.into_iter())
    }
}

/// Calculate the Designated Router (§9.4 step 4), given the elected `bdr`.
fn calc_dr(cands: &[Candidate], bdr: Ipv4Addr) -> Ipv4Addr {
    let declaring_self_dr = cands
        .iter()
        .copied()
        .filter(|c| c.priority > 0 && c.declared_dr == c.router_id);
    let dr = best(declaring_self_dr);
    if dr.is_unspecified() {
        // No one claims to be DR → the BDR is promoted.
        bdr
    } else {
        dr
    }
}

/// Run the §9.4 Designated Router election over `candidates` (which must include
/// the calculating router `self_id`). Returns `(dr, bdr)` as Router IDs, with
/// `0.0.0.0` meaning "none". Implements the step-5 single recomputation that runs
/// when the calculating router's own DR/BDR status changes as a result.
pub fn elect_dr_bdr(candidates: &[Candidate], self_id: Ipv4Addr) -> (Ipv4Addr, Ipv4Addr) {
    let bdr = calc_bdr(candidates);
    let dr = calc_dr(candidates, bdr);

    if let Some(me) = candidates.iter().find(|c| c.router_id == self_id) {
        let was_dr = me.declared_dr == self_id;
        let was_bdr = me.declared_bdr == self_id;
        let now_dr = dr == self_id;
        let now_bdr = bdr == self_id;
        // §9.4(5): if our own role flipped, redo 3–4 with our updated view.
        if was_dr != now_dr || was_bdr != now_bdr {
            let mut updated = candidates.to_vec();
            if let Some(slot) = updated.iter_mut().find(|c| c.router_id == self_id) {
                slot.declared_dr = dr;
                slot.declared_bdr = bdr;
            }
            let bdr2 = calc_bdr(&updated);
            let dr2 = calc_dr(&updated, bdr2);
            return (dr2, bdr2);
        }
    }
    (dr, bdr)
}

/// One router's view of an interface (§9.1): its identity and priority, the
/// interface type, the current state and the elected DR/BDR.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Interface {
    /// This router's Router ID.
    pub router_id: Ipv4Addr,
    /// This router's Router Priority on this interface.
    pub priority: u8,
    /// How the interface attaches to its network.
    pub iface_type: InterfaceType,
    /// The current interface state.
    pub state: InterfaceState,
    /// The currently elected Designated Router (`0.0.0.0` = none).
    pub dr: Ipv4Addr,
    /// The currently elected Backup Designated Router (`0.0.0.0` = none).
    pub bdr: Ipv4Addr,
}

impl Interface {
    /// A new interface in [`InterfaceState::Down`] with no DR/BDR.
    pub fn new(router_id: Ipv4Addr, priority: u8, iface_type: InterfaceType) -> Self {
        Interface {
            router_id,
            priority,
            iface_type,
            state: InterfaceState::Down,
            dr: Ipv4Addr::UNSPECIFIED,
            bdr: Ipv4Addr::UNSPECIFIED,
        }
    }

    /// Whether this router is the DR or BDR on this interface — the §10.4 test for
    /// whether to form full adjacencies with DROther neighbours.
    pub fn is_dr_or_bdr(&self) -> bool {
        self.dr == self.router_id || self.bdr == self.router_id
    }

    /// Drive the interface machine with `ev` (§9.3). `neighbors` are the
    /// interface's neighbours in 2-Way or better, as election candidates; it is
    /// consulted only for the events that run an election.
    pub fn handle(&mut self, ev: InterfaceEvent, neighbors: &[Candidate]) -> Vec<InterfaceAction> {
        use InterfaceAction::*;
        use InterfaceEvent::*;
        use InterfaceState::*;

        match ev {
            InterfaceDown => {
                self.reset();
                self.state = Down;
                vec![ResetInterface]
            }
            LoopInd => {
                self.reset();
                self.state = Loopback;
                vec![ResetInterface]
            }
            UnloopInd => {
                if self.state == Loopback {
                    self.state = Down;
                }
                vec![]
            }
            InterfaceUp => {
                if self.state != Down {
                    return vec![];
                }
                if self.iface_type.elects_dr() {
                    // Multi-access: wait to discover an existing DR before electing.
                    self.state = Waiting;
                    vec![StartHellos, StartWaitTimer]
                } else {
                    self.state = PointToPoint;
                    vec![StartHellos]
                }
            }
            WaitTimer | BackupSeen => {
                if self.state == Waiting {
                    let changed = self.run_election(neighbors);
                    let mut acts = vec![StopWaitTimer];
                    if changed {
                        acts.push(ElectionChanged);
                    }
                    acts
                } else {
                    vec![]
                }
            }
            NeighborChange => {
                if matches!(self.state, DrOther | Backup | Dr) {
                    if self.run_election(neighbors) {
                        vec![ElectionChanged]
                    } else {
                        vec![]
                    }
                } else {
                    vec![]
                }
            }
        }
    }

    /// Run the election including this router and fold the outcome into the
    /// interface state. Returns whether the DR or BDR changed.
    fn run_election(&mut self, neighbors: &[Candidate]) -> bool {
        let mut cands: Vec<Candidate> = neighbors.to_vec();
        cands.push(Candidate {
            router_id: self.router_id,
            priority: self.priority,
            declared_dr: self.dr,
            declared_bdr: self.bdr,
        });
        let (dr, bdr) = elect_dr_bdr(&cands, self.router_id);
        let changed = dr != self.dr || bdr != self.bdr;
        self.dr = dr;
        self.bdr = bdr;
        self.state = if dr == self.router_id {
            InterfaceState::Dr
        } else if bdr == self.router_id {
            InterfaceState::Backup
        } else {
            InterfaceState::DrOther
        };
        changed
    }

    fn reset(&mut self) {
        self.dr = Ipv4Addr::UNSPECIFIED;
        self.bdr = Ipv4Addr::UNSPECIFIED;
    }
}

#[cfg(test)]
mod tests {
    use super::InterfaceAction::*;
    use super::InterfaceEvent::*;
    use super::InterfaceState::*;
    use super::*;

    fn ip(o: [u8; 4]) -> Ipv4Addr {
        Ipv4Addr::from(o)
    }

    fn cand(id: [u8; 4], prio: u8, dr: [u8; 4], bdr: [u8; 4]) -> Candidate {
        Candidate {
            router_id: ip(id),
            priority: prio,
            declared_dr: ip(dr),
            declared_bdr: ip(bdr),
        }
    }

    const NONE: [u8; 4] = [0, 0, 0, 0];

    #[test]
    fn lone_router_becomes_dr_with_no_backup() {
        let me = cand([1, 1, 1, 1], 1, NONE, NONE);
        assert_eq!(elect_dr_bdr(&[me], ip([1, 1, 1, 1])), (ip([1, 1, 1, 1]), ip(NONE)));
    }

    #[test]
    fn steady_state_two_routers() {
        let r1 = cand([1, 1, 1, 1], 1, [2, 2, 2, 2], [1, 1, 1, 1]);
        let r2 = cand([2, 2, 2, 2], 1, [2, 2, 2, 2], [1, 1, 1, 1]);
        let (dr, bdr) = elect_dr_bdr(&[r1, r2], ip([1, 1, 1, 1]));
        assert_eq!(dr, ip([2, 2, 2, 2]));
        assert_eq!(bdr, ip([1, 1, 1, 1]));
    }

    #[test]
    fn priority_beats_router_id() {
        let r1 = cand([1, 1, 1, 1], 2, [1, 1, 1, 1], NONE);
        let r2 = cand([2, 2, 2, 2], 1, NONE, [2, 2, 2, 2]);
        let (dr, bdr) = elect_dr_bdr(&[r1, r2], ip([2, 2, 2, 2]));
        assert_eq!(dr, ip([1, 1, 1, 1]));
        assert_eq!(bdr, ip([2, 2, 2, 2]));
    }

    #[test]
    fn priority_zero_router_is_never_dr_or_bdr() {
        let r1 = cand([1, 1, 1, 1], 0, NONE, NONE);
        let r2 = cand([2, 2, 2, 2], 1, NONE, NONE);
        let (dr, bdr) = elect_dr_bdr(&[r1, r2], ip([2, 2, 2, 2]));
        assert_eq!(dr, ip([2, 2, 2, 2]));
        assert_eq!(bdr, ip(NONE));
    }

    #[test]
    fn existing_dr_is_not_preempted_by_a_higher_priority_newcomer() {
        // §9.4(4) keeps the established DR (it declares itself); the newcomer (even
        // at priority 100) only takes Backup.
        let r2 = cand([2, 2, 2, 2], 1, [2, 2, 2, 2], NONE);
        let r9 = cand([9, 9, 9, 9], 100, NONE, NONE);
        let (dr, bdr) = elect_dr_bdr(&[r2, r9], ip([9, 9, 9, 9]));
        assert_eq!(dr, ip([2, 2, 2, 2]), "established DR keeps the role");
        assert_eq!(bdr, ip([9, 9, 9, 9]), "the newcomer takes Backup");
    }

    #[test]
    fn broadcast_interface_up_waits_then_elects_dr() {
        let mut iface = Interface::new(ip([1, 1, 1, 1]), 1, InterfaceType::Broadcast);
        let acts = iface.handle(InterfaceUp, &[]);
        assert_eq!(iface.state, Waiting);
        assert!(acts.contains(&StartWaitTimer) && acts.contains(&StartHellos));

        let acts = iface.handle(WaitTimer, &[]);
        assert_eq!(iface.state, Dr);
        assert_eq!(iface.dr, ip([1, 1, 1, 1]));
        assert_eq!(iface.bdr, ip(NONE));
        assert!(acts.contains(&StopWaitTimer) && acts.contains(&ElectionChanged));
        assert!(iface.is_dr_or_bdr());
    }

    #[test]
    fn point_to_point_interface_up_skips_election() {
        let mut iface = Interface::new(ip([1, 1, 1, 1]), 1, InterfaceType::PointToPoint);
        let acts = iface.handle(InterfaceUp, &[]);
        assert_eq!(iface.state, PointToPoint);
        assert_eq!(acts, vec![StartHellos]);
        assert!(!iface.is_dr_or_bdr());
    }

    #[test]
    fn neighbor_change_demotes_to_backup_when_a_higher_router_appears() {
        let mut iface = Interface::new(ip([1, 1, 1, 1]), 1, InterfaceType::Broadcast);
        iface.handle(InterfaceUp, &[]);
        iface.handle(WaitTimer, &[]);
        assert_eq!(iface.state, Dr);

        let r2 = cand([2, 2, 2, 2], 1, [2, 2, 2, 2], NONE);
        let acts = iface.handle(NeighborChange, &[r2]);
        assert_eq!(iface.dr, ip([2, 2, 2, 2]));
        assert_eq!(iface.state, Backup);
        assert_eq!(acts, vec![ElectionChanged]);
    }

    #[test]
    fn interface_down_clears_election_state() {
        let mut iface = Interface::new(ip([1, 1, 1, 1]), 1, InterfaceType::Broadcast);
        iface.handle(InterfaceUp, &[]);
        iface.handle(WaitTimer, &[]);
        assert_eq!(iface.state, Dr);
        let acts = iface.handle(InterfaceDown, &[]);
        assert_eq!(iface.state, Down);
        assert_eq!(iface.dr, ip(NONE));
        assert_eq!(iface.bdr, ip(NONE));
        assert_eq!(acts, vec![ResetInterface]);
    }

    #[test]
    fn idempotent_neighbor_change_reports_no_change() {
        let mut iface = Interface::new(ip([1, 1, 1, 1]), 1, InterfaceType::Broadcast);
        iface.handle(InterfaceUp, &[]);
        iface.handle(WaitTimer, &[]);
        let acts = iface.handle(NeighborChange, &[]);
        assert!(acts.is_empty());
        assert_eq!(iface.state, Dr);
    }
}
