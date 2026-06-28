//! The neighbour state machine (RFC 5340 §4.2.6, inheriting RFC 2328 §10) — the
//! per-neighbour conversation that takes a router from "just heard a Hello" all
//! the way to a fully synchronised adjacency.
//!
//! OSPFv3's neighbour FSM is **unchanged** from OSPFv2: the eight states, the
//! events and the §10.3 transition table are identical. Two data-structure
//! differences matter for the layers above:
//!
//! * the DR/BDR a neighbour advertises are **Router IDs** in the OSPFv3 Hello, so
//!   no interface-address→router-id mapping is needed (it was the runner's job in
//!   OSPFv2); and
//! * the neighbour data structure additionally records the neighbour's
//!   **Interface ID** ([`Neighbor::interface_id`]), which the Router-LSA needs as
//!   the *Neighbor Interface ID* of a point-to-point or transit link.
//!
//! This is the pure event-driven core: [`Neighbor::handle`] consumes a
//! [`NeighborEvent`] (plus a small [`NeighborContext`] for the two decisions the
//! interface layer owns — whether an adjacency *should* form, §10.4, and whether
//! the Link State Request list has drained) and returns the [`NeighborAction`]s
//! the runner must carry out. No sockets, no clock.

use std::net::Ipv4Addr;

/// The eight neighbour states (§10.1), in increasing order of adjacency progress.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum NeighborState {
    /// No recent Hellos — the initial and torn-down state.
    Down,
    /// (NBMA only) a Hello has been sent but none heard back yet.
    Attempt,
    /// A Hello was heard, but the neighbour did not yet list us (one-way).
    Init,
    /// Bidirectional communication confirmed; no adjacency formed (or needed).
    TwoWay,
    /// Negotiating the master/slave roles and the DD sequence number.
    ExStart,
    /// Exchanging Database Description packets describing each database.
    Exchange,
    /// Sending Link State Requests for the LSAs still missing.
    Loading,
    /// Databases synchronised — a full adjacency.
    Full,
}

/// The inputs that drive the neighbour machine (§10.2).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum NeighborEvent {
    /// (NBMA) begin sending Hellos to this neighbour.
    Start,
    /// A valid Hello was received from the neighbour.
    HelloReceived,
    /// A Hello listing *us* arrived — communication is bidirectional.
    TwoWayReceived,
    /// The master/slave + DD sequence negotiation completed (§10.8).
    NegotiationDone,
    /// The Database Description exchange finished (both set the M-bit to 0).
    ExchangeDone,
    /// The Link State Request list emptied while in Loading.
    LoadingDone,
    /// Re-evaluate whether the adjacency should still exist (§10.4 "AdjOK?").
    AdjOk,
    /// A DD packet arrived with an unexpected sequence/flags — resynchronise.
    SeqNumberMismatch,
    /// A neighbour requested an LSA we do not hold — resynchronise.
    BadLsReq,
    /// A Hello arrived that no longer lists us — communication is one-way.
    OneWayReceived,
    /// The inactivity timer fired — the neighbour went silent.
    InactivityTimer,
    /// The neighbour is being destroyed (administrative).
    KillNbr,
    /// The link to the neighbour went down.
    LinkDown,
}

/// What the runner must do as a result of a transition.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum NeighborAction {
    /// Arm the inactivity timer (RouterDeadInterval).
    StartInactivityTimer,
    /// Restart the inactivity timer (a Hello refreshed liveness).
    ResetInactivityTimer,
    /// Cancel the inactivity timer.
    StopInactivityTimer,
    /// Entering ExStart: become master tentatively, bump the DD sequence and
    /// start sending the initial (empty, I/M/MS-set) Database Description.
    StartDdExchange,
    /// Negotiation done: start sending the database summary DD packets and,
    /// once requests are known, the Link State Requests.
    StartDatabaseExchange,
    /// The adjacency reached Full — (re)originate LSAs / run the routing table.
    AdjacencyUp,
    /// Tear down the adjacency's Link State lists (left Full, resynchronising,
    /// or dropped below ExStart).
    ClearAdjacency,
}

/// The two decisions the interface layer owns, supplied with each event.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct NeighborContext {
    /// Whether an adjacency *should* exist with this neighbour (§10.4): always on
    /// point-to-point/virtual links; on broadcast/NBMA only if this router or the
    /// neighbour is the DR or BDR.
    pub adjacency_ok: bool,
    /// Whether the Link State Request list is empty (decides Exchange→Full vs
    /// Exchange→Loading on [`NeighborEvent::ExchangeDone`]).
    pub request_list_empty: bool,
}

/// A neighbour as tracked by one interface (§10.1): its identity, the state of the
/// conversation, the priority/DR/BDR its Hellos advertise (cached for the
/// interface's DR election in [`crate::interface`]) and its Interface ID.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Neighbor {
    /// The neighbour's Router ID.
    pub router_id: Ipv4Addr,
    /// The conversation state.
    pub state: NeighborState,
    /// The neighbour's advertised Router Priority (0 = ineligible to be DR).
    pub priority: u8,
    /// The neighbour's Interface ID for this link (from its Hello) — used as the
    /// *Neighbor Interface ID* when building Router-LSA links (§4.4.3 / §A.4.3).
    pub interface_id: u32,
    /// The DR the neighbour last advertised (a Router ID; `0.0.0.0` = none).
    pub declared_dr: Ipv4Addr,
    /// The BDR the neighbour last advertised (`0.0.0.0` = none).
    pub declared_bdr: Ipv4Addr,
}

impl Neighbor {
    /// A freshly-discovered neighbour in [`NeighborState::Down`].
    pub fn new(router_id: Ipv4Addr) -> Self {
        Neighbor {
            router_id,
            state: NeighborState::Down,
            priority: 0,
            interface_id: 0,
            declared_dr: Ipv4Addr::UNSPECIFIED,
            declared_bdr: Ipv4Addr::UNSPECIFIED,
        }
    }

    /// Whether the neighbour is at least bidirectional (§9.4 election eligibility
    /// and §13 flooding both consider only neighbours in 2-Way or higher).
    pub fn is_bidirectional(&self) -> bool {
        self.state >= NeighborState::TwoWay
    }

    /// Drive the machine with `ev` under `ctx`, mutating [`Neighbor::state`] and
    /// returning the actions the runner must perform (§10.3).
    pub fn handle(&mut self, ev: NeighborEvent, ctx: NeighborContext) -> Vec<NeighborAction> {
        use NeighborAction::*;
        use NeighborEvent::*;
        use NeighborState::*;

        // Events that fire from (almost) any state and end the conversation.
        match ev {
            KillNbr | LinkDown => {
                let was_forming = self.state >= ExStart;
                self.state = Down;
                let mut acts = vec![StopInactivityTimer];
                if was_forming {
                    acts.push(ClearAdjacency);
                }
                return acts;
            }
            InactivityTimer => {
                let was_forming = self.state >= ExStart;
                self.state = Down;
                return if was_forming {
                    vec![ClearAdjacency]
                } else {
                    vec![]
                };
            }
            _ => {}
        }

        match (self.state, ev) {
            // --- Down / Attempt -------------------------------------------
            (Down, Start) => {
                self.state = Attempt;
                vec![StartInactivityTimer]
            }
            (Down, HelloReceived) => {
                self.state = Init;
                vec![StartInactivityTimer]
            }
            (Attempt, HelloReceived) => {
                self.state = Init;
                vec![ResetInactivityTimer]
            }

            // --- Init -----------------------------------------------------
            (Init, HelloReceived) => vec![ResetInactivityTimer],
            (Init, TwoWayReceived) => {
                if ctx.adjacency_ok {
                    self.state = ExStart;
                    vec![StartDdExchange]
                } else {
                    self.state = TwoWay;
                    vec![]
                }
            }
            (Init, OneWayReceived) => vec![],

            // --- TwoWay ---------------------------------------------------
            (TwoWay, HelloReceived) => vec![ResetInactivityTimer],
            (TwoWay, AdjOk) => {
                if ctx.adjacency_ok {
                    self.state = ExStart;
                    vec![StartDdExchange]
                } else {
                    vec![]
                }
            }
            (TwoWay, OneWayReceived) => {
                self.state = Init;
                vec![]
            }

            // --- ExStart --------------------------------------------------
            (ExStart, NegotiationDone) => {
                self.state = Exchange;
                vec![StartDatabaseExchange]
            }
            (ExStart, AdjOk) if !ctx.adjacency_ok => {
                self.state = TwoWay;
                vec![ClearAdjacency]
            }

            // --- Exchange -------------------------------------------------
            (Exchange, ExchangeDone) => {
                if ctx.request_list_empty {
                    self.state = Full;
                    vec![AdjacencyUp]
                } else {
                    self.state = Loading;
                    vec![]
                }
            }
            (Exchange, AdjOk) if !ctx.adjacency_ok => {
                self.state = TwoWay;
                vec![ClearAdjacency]
            }

            // --- Loading --------------------------------------------------
            (Loading, LoadingDone) => {
                self.state = Full;
                vec![AdjacencyUp]
            }
            (Loading, AdjOk) if !ctx.adjacency_ok => {
                self.state = TwoWay;
                vec![ClearAdjacency]
            }

            // --- Full -----------------------------------------------------
            (Full, AdjOk) if !ctx.adjacency_ok => {
                self.state = TwoWay;
                vec![ClearAdjacency]
            }

            // --- Resynchronise (any adjacency-forming state) --------------
            (Exchange | Loading | Full, SeqNumberMismatch | BadLsReq) => {
                self.state = ExStart;
                vec![ClearAdjacency, StartDdExchange]
            }

            // A Hello refreshing liveness in any adjacency state.
            (Exchange | Loading | Full | ExStart, HelloReceived) => vec![ResetInactivityTimer],

            // Lost bidirectionality at or above ExStart: back to Init.
            (ExStart | Exchange | Loading | Full, OneWayReceived) => {
                self.state = Init;
                vec![ClearAdjacency]
            }

            // Everything else is a no-op in the current state.
            _ => vec![],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::NeighborAction::*;
    use super::NeighborEvent::*;
    use super::NeighborState::*;
    use super::*;

    fn ip(o: [u8; 4]) -> Ipv4Addr {
        Ipv4Addr::from(o)
    }

    /// Adjacency wanted, request list ends up empty.
    fn adj() -> NeighborContext {
        NeighborContext {
            adjacency_ok: true,
            request_list_empty: true,
        }
    }

    #[test]
    fn full_adjacency_bringup_path() {
        let mut n = Neighbor::new(ip([2, 2, 2, 2]));
        assert_eq!(n.handle(HelloReceived, adj()), vec![StartInactivityTimer]);
        assert_eq!(n.state, Init);
        assert_eq!(n.handle(TwoWayReceived, adj()), vec![StartDdExchange]);
        assert_eq!(n.state, ExStart);
        assert_eq!(n.handle(NegotiationDone, adj()), vec![StartDatabaseExchange]);
        assert_eq!(n.state, Exchange);
        assert_eq!(n.handle(ExchangeDone, adj()), vec![AdjacencyUp]);
        assert_eq!(n.state, Full);
    }

    #[test]
    fn exchange_with_outstanding_requests_goes_through_loading() {
        let mut n = Neighbor::new(ip([2, 2, 2, 2]));
        n.state = Exchange;
        let ctx = NeighborContext {
            adjacency_ok: true,
            request_list_empty: false,
        };
        assert!(n.handle(ExchangeDone, ctx).is_empty());
        assert_eq!(n.state, Loading);
        assert_eq!(n.handle(LoadingDone, adj()), vec![AdjacencyUp]);
        assert_eq!(n.state, Full);
    }

    #[test]
    fn two_way_without_adjacency_stays_two_way() {
        let mut n = Neighbor::new(ip([2, 2, 2, 2]));
        n.handle(HelloReceived, adj());
        let ctx = NeighborContext {
            adjacency_ok: false,
            request_list_empty: true,
        };
        assert!(n.handle(TwoWayReceived, ctx).is_empty());
        assert_eq!(n.state, TwoWay);
        assert_eq!(n.handle(AdjOk, adj()), vec![StartDdExchange]);
        assert_eq!(n.state, ExStart);
    }

    #[test]
    fn seqnumber_mismatch_restarts_exchange() {
        let mut n = Neighbor::new(ip([2, 2, 2, 2]));
        n.state = Full;
        let acts = n.handle(SeqNumberMismatch, adj());
        assert_eq!(acts, vec![ClearAdjacency, StartDdExchange]);
        assert_eq!(n.state, ExStart);
    }

    #[test]
    fn one_way_drops_back_to_init() {
        let mut n = Neighbor::new(ip([2, 2, 2, 2]));
        n.state = Full;
        assert_eq!(n.handle(OneWayReceived, adj()), vec![ClearAdjacency]);
        assert_eq!(n.state, Init);

        let mut m = Neighbor::new(ip([3, 3, 3, 3]));
        m.state = TwoWay;
        assert!(m.handle(OneWayReceived, adj()).is_empty());
        assert_eq!(m.state, Init);
    }

    #[test]
    fn adjok_tears_down_when_no_longer_needed() {
        let mut n = Neighbor::new(ip([2, 2, 2, 2]));
        n.state = Full;
        let ctx = NeighborContext {
            adjacency_ok: false,
            request_list_empty: true,
        };
        assert_eq!(n.handle(AdjOk, ctx), vec![ClearAdjacency]);
        assert_eq!(n.state, TwoWay);
    }

    #[test]
    fn inactivity_and_kill_return_to_down() {
        let mut n = Neighbor::new(ip([2, 2, 2, 2]));
        n.state = Full;
        assert_eq!(n.handle(InactivityTimer, adj()), vec![ClearAdjacency]);
        assert_eq!(n.state, Down);

        let mut m = Neighbor::new(ip([3, 3, 3, 3]));
        m.state = TwoWay;
        assert_eq!(m.handle(KillNbr, adj()), vec![StopInactivityTimer]);
        assert_eq!(m.state, Down);
    }

    #[test]
    fn bidirectional_predicate_tracks_two_way_threshold() {
        let mut n = Neighbor::new(ip([2, 2, 2, 2]));
        assert!(!n.is_bidirectional());
        n.state = Init;
        assert!(!n.is_bidirectional());
        n.state = TwoWay;
        assert!(n.is_bidirectional());
        n.state = Full;
        assert!(n.is_bidirectional());
    }

    #[test]
    fn interface_id_is_recorded_for_router_lsa_links() {
        // OSPFv3 quirk: the neighbour's Interface ID (learned from its Hello) is
        // kept so a transit/p2p Router-LSA link can name it.
        let mut n = Neighbor::new(ip([2, 2, 2, 2]));
        assert_eq!(n.interface_id, 0);
        n.interface_id = 7;
        assert_eq!(n.interface_id, 7);
    }
}
