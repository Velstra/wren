//! The IS-IS adjacency state machine (ISO/IEC 10589 §8.2, with the point-to-point
//! three-way handshake of [RFC 5303](https://www.rfc-editor.org/rfc/rfc5303)).
//!
//! IS-IS adjacencies are much simpler than OSPF's. There is no master/slave
//! Database Description exchange — database synchronisation is the job of the
//! CSNP/PSNP sequence-number PDUs ([`crate::lsdb`]) — so the whole conversation is
//! a three-state machine: **Down → Initializing → Up**. The pivot is *two-way
//! reachability*: a router proves it hears a neighbour by listing that neighbour
//! back, on a LAN in the IS Neighbours TLV (the neighbour's SNPA) and on a
//! point-to-point link in the RFC 5303 three-way TLV. So the only distinction the
//! pure machine needs from a received Hello is whether it **lists us** — exactly
//! the IS-IS analogue of OSPF's one-way/two-way split.
//!
//! Like the OSPF neighbour FSM this is the pure event-driven core:
//! [`Adjacency::handle`] consumes an [`AdjEvent`] and returns the [`AdjAction`]s
//! the runner must perform (arm the holding timer, (re)originate LSPs and re-run
//! SPF, re-run the DIS election). No sockets, no clock; and Hello *acceptance* —
//! the area match for an L1 adjacency, the level and Maximum-Area-Addresses
//! checks — is the runner's gate before it ever feeds an event here.

use crate::{IsLevel, SystemId};

/// The three adjacency states (ISO 10589 §8.2.4 / RFC 5303 §3).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum AdjState {
    /// No usable Hello — the initial and torn-down state.
    Down,
    /// A Hello was heard, but it does not yet list us (one-way).
    Initializing,
    /// Two-way reachability confirmed — a usable adjacency.
    Up,
}

/// The inputs that drive the adjacency machine.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AdjEvent {
    /// A Hello arrived but it does **not** list us — the neighbour is present, but
    /// two-way reachability is unconfirmed (we are absent from its IS Neighbours
    /// TLV, or its three-way TLV does not acknowledge our circuit).
    HelloOneWay,
    /// A Hello arrived that **lists us** — two-way reachability is confirmed.
    HelloTwoWay,
    /// The holding timer expired — the neighbour went silent.
    HoldingTimerExpired,
    /// The circuit went down, or the adjacency is being removed administratively.
    CircuitDown,
}

/// What the runner must do as a result of a transition.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AdjAction {
    /// Arm the holding timer (the neighbour's advertised Holding Time).
    StartHoldingTimer,
    /// Restart the holding timer (a Hello refreshed liveness).
    ResetHoldingTimer,
    /// Cancel the holding timer.
    StopHoldingTimer,
    /// The adjacency reached Up: (re)originate this system's LSPs, re-run SPF, and
    /// — on a LAN — re-run the DIS election (the adjacency set changed).
    AdjacencyUp,
    /// The adjacency left Up (lost two-way, timed out, or the circuit dropped):
    /// (re)originate LSPs, re-run SPF, and re-run the DIS election.
    AdjacencyDown,
}

/// One IS-IS adjacency over a circuit, at one level (ISO 10589 §8.2). L1 and L2
/// adjacencies over the same circuit are tracked separately. The neighbour's
/// advertised DIS priority, SNPA and LAN ID are cached here — exactly what the
/// LAN's [`crate::dis`] election consumes.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Adjacency {
    /// The neighbour's System ID.
    pub neighbor_id: SystemId,
    /// Which level this adjacency is at.
    pub level: IsLevel,
    /// The conversation state.
    pub state: AdjState,
    /// The neighbour's advertised DIS priority (7 bits; higher wins, LAN only).
    pub priority: u8,
    /// The neighbour's SNPA (its LAN MAC) — the DIS election's tie-break.
    pub snpa: [u8; 6],
    /// The LAN ID (the DIS's System ID and pseudonode number) the neighbour last
    /// advertised in its Hello.
    pub lan_id: (SystemId, u8),
}

impl Adjacency {
    /// A freshly-discovered adjacency in [`AdjState::Down`].
    pub fn new(neighbor_id: SystemId, level: IsLevel) -> Self {
        Adjacency {
            neighbor_id,
            level,
            state: AdjState::Down,
            priority: 0,
            snpa: [0; 6],
            lan_id: (SystemId::ZERO, 0),
        }
    }

    /// Whether the adjacency is usable (Up) — the test for whether it counts in
    /// SPF and in the DIS election.
    pub fn is_up(&self) -> bool {
        self.state == AdjState::Up
    }

    /// Drive the machine with `ev`, mutating [`Adjacency::state`] and returning the
    /// actions the runner must perform.
    pub fn handle(&mut self, ev: AdjEvent) -> Vec<AdjAction> {
        use AdjAction::*;
        use AdjEvent::*;
        use AdjState::*;

        match (self.state, ev) {
            // --- Teardown from any state -------------------------------------
            (_, CircuitDown) => {
                let was_up = self.state == Up;
                self.state = Down;
                let mut acts = vec![StopHoldingTimer];
                if was_up {
                    acts.push(AdjacencyDown);
                }
                acts
            }
            (_, HoldingTimerExpired) => {
                let was_up = self.state == Up;
                self.state = Down;
                // The timer already fired, so there is nothing to stop.
                if was_up {
                    vec![AdjacencyDown]
                } else {
                    vec![]
                }
            }

            // --- Down --------------------------------------------------------
            (Down, HelloOneWay) => {
                self.state = Initializing;
                vec![StartHoldingTimer]
            }
            // A first Hello that already lists us takes us straight to Up.
            (Down, HelloTwoWay) => {
                self.state = Up;
                vec![StartHoldingTimer, AdjacencyUp]
            }

            // --- Initializing ------------------------------------------------
            (Initializing, HelloOneWay) => vec![ResetHoldingTimer],
            (Initializing, HelloTwoWay) => {
                self.state = Up;
                vec![ResetHoldingTimer, AdjacencyUp]
            }

            // --- Up ----------------------------------------------------------
            (Up, HelloTwoWay) => vec![ResetHoldingTimer],
            // Lost two-way: the neighbour no longer lists us — back to Initializing.
            (Up, HelloOneWay) => {
                self.state = Initializing;
                vec![ResetHoldingTimer, AdjacencyDown]
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::AdjAction::*;
    use super::AdjEvent::*;
    use super::AdjState::*;
    use super::*;

    fn sid(n: u8) -> SystemId {
        SystemId::new([n, n, n, n, n, n])
    }

    fn adj() -> Adjacency {
        Adjacency::new(sid(2), IsLevel::L1)
    }

    #[test]
    fn bringup_via_initializing() {
        let mut a = adj();
        // First Hello does not list us yet.
        assert_eq!(a.handle(HelloOneWay), vec![StartHoldingTimer]);
        assert_eq!(a.state, Initializing);
        assert!(!a.is_up());
        // Next Hello lists us → Up.
        assert_eq!(a.handle(HelloTwoWay), vec![ResetHoldingTimer, AdjacencyUp]);
        assert_eq!(a.state, Up);
        assert!(a.is_up());
        // Steady-state Hellos just refresh the timer.
        assert_eq!(a.handle(HelloTwoWay), vec![ResetHoldingTimer]);
        assert_eq!(a.state, Up);
    }

    #[test]
    fn first_hello_listing_us_goes_straight_to_up() {
        let mut a = adj();
        assert_eq!(a.handle(HelloTwoWay), vec![StartHoldingTimer, AdjacencyUp]);
        assert_eq!(a.state, Up);
    }

    #[test]
    fn lost_two_way_drops_to_initializing() {
        let mut a = adj();
        a.handle(HelloTwoWay);
        assert_eq!(a.state, Up);
        // A Hello that no longer lists us tears the adjacency down to Init.
        assert_eq!(
            a.handle(HelloOneWay),
            vec![ResetHoldingTimer, AdjacencyDown]
        );
        assert_eq!(a.state, Initializing);
    }

    #[test]
    fn holding_timer_expiry_from_up_signals_down() {
        let mut a = adj();
        a.handle(HelloTwoWay);
        assert_eq!(a.handle(HoldingTimerExpired), vec![AdjacencyDown]);
        assert_eq!(a.state, Down);
    }

    #[test]
    fn holding_timer_expiry_from_init_is_silent() {
        let mut a = adj();
        a.handle(HelloOneWay);
        assert_eq!(a.state, Initializing);
        // Never reached Up, so nothing to signal down.
        assert!(a.handle(HoldingTimerExpired).is_empty());
        assert_eq!(a.state, Down);
    }

    #[test]
    fn circuit_down_stops_timer_and_signals_when_up() {
        let mut a = adj();
        a.handle(HelloTwoWay);
        assert_eq!(a.handle(CircuitDown), vec![StopHoldingTimer, AdjacencyDown]);
        assert_eq!(a.state, Down);

        // From Initializing it only stops the timer — no adjacency was up.
        let mut b = adj();
        b.handle(HelloOneWay);
        assert_eq!(b.handle(CircuitDown), vec![StopHoldingTimer]);
        assert_eq!(b.state, Down);
    }
}
