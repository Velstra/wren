//! The per-session BFD state machine (RFC 5880 §6.8.6), pure and timekeeping-free.
//!
//! A [`Session`] holds one peering's local and learned-remote parameters and the
//! current [`State`]. The daemon runner drives it with three pure operations and
//! does all the I/O and timing itself:
//!
//! * [`Session::on_packet`] — fold a received Control packet into the FSM, returning
//!   the [`Transition`] if the state changed;
//! * [`Session::on_detect_timeout`] — the runner's detection timer fired (no packet
//!   heard for the Detection Time), so the session fails;
//! * [`Session::build_control`] — produce the next Control packet to transmit.
//!
//! The runner asks [`Session::transmit_interval_us`] how long to wait before the
//! next transmit and [`Session::detection_time_us`] how long to wait before
//! declaring the neighbour gone.

use crate::packet::{ControlPacket, Diag, State};

/// The minimum Desired Min TX Interval (microseconds) a session advertises while
/// it is not Up (RFC 5880 §6.8.3): at least one second, so forming or failed
/// sessions transmit slowly and cheaply until the path actually comes up.
pub const SLOW_TX_FLOOR_US: u32 = 1_000_000;

/// A session's static timing parameters (from `[bfd]` config).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SessionConfig {
    /// Our Desired Min TX Interval (microseconds) — how fast we want to transmit
    /// once the session is Up.
    pub desired_min_tx_us: u32,
    /// Our Required Min RX Interval (microseconds) — the fastest we are willing to
    /// receive; the neighbour will not transmit faster than this.
    pub required_min_rx_us: u32,
    /// Our Detect Mult — the neighbour multiplies its receive interval by this to
    /// get the Detection Time after which it declares us down.
    pub detect_mult: u8,
}

/// A change of session state, returned by the FSM operations when the state moved.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Transition {
    /// The state before the event.
    pub from: State,
    /// The state after the event.
    pub to: State,
}

/// One BFD session's state (RFC 5880 §6.8.1 state variables, the subset Wren uses
/// for single-hop asynchronous mode without authentication or Echo).
#[derive(Clone, Debug)]
pub struct Session {
    local_discr: u32,
    cfg: SessionConfig,
    state: State,
    local_diag: Diag,
    remote_discr: u32,
    remote_state: State,
    remote_min_rx_us: u32,
    remote_desired_tx_us: u32,
    remote_detect_mult: u8,
    /// Whether our next transmitted packet must set the Final (`F`) bit because we
    /// received a Poll (`P`) (RFC 5880 §6.8.7).
    send_final: bool,
}

impl Session {
    /// Create a fresh session in the Down state. `local_discr` must be a non-zero
    /// discriminator unique on this system (the runner assigns it).
    pub fn new(local_discr: u32, cfg: SessionConfig) -> Session {
        Session {
            local_discr,
            cfg,
            state: State::Down,
            local_diag: Diag::None,
            remote_discr: 0,
            remote_state: State::Down,
            // Until we hear the neighbour, assume the minimum so any pre-receive
            // detection computation is harmless (the runner never arms detection
            // before the first packet anyway).
            remote_min_rx_us: 1,
            remote_desired_tx_us: 1,
            remote_detect_mult: 1,
            send_final: false,
        }
    }

    /// The current session state.
    pub fn state(&self) -> State {
        self.state
    }

    /// Our local discriminator.
    pub fn local_discr(&self) -> u32 {
        self.local_discr
    }

    /// The neighbour's discriminator as last learned (0 if not yet heard / down).
    pub fn remote_discr(&self) -> u32 {
        self.remote_discr
    }

    /// Fold a received Control packet into the FSM (RFC 5880 §6.8.6). The
    /// packet-level reception checks (version, discriminators, …) are done by
    /// [`ControlPacket::decode`]; this applies the state transitions. Returns the
    /// [`Transition`] when the state changed, else `None`.
    pub fn on_packet(&mut self, pkt: &ControlPacket) -> Option<Transition> {
        // Learn the neighbour's parameters from every accepted packet.
        self.remote_discr = pkt.my_discr;
        self.remote_state = pkt.state;
        self.remote_min_rx_us = pkt.required_min_rx;
        self.remote_desired_tx_us = pkt.desired_min_tx;
        self.remote_detect_mult = pkt.detect_mult;
        // A received Poll obliges us to answer with the Final bit set, promptly.
        if pkt.poll {
            self.send_final = true;
        }

        // An administratively-down session ignores incoming packets for transitions.
        if self.state == State::AdminDown {
            return None;
        }

        // The §6.8.6 reception state machine.
        let next = if pkt.state == State::AdminDown {
            if self.state != State::Down {
                self.local_diag = Diag::NeighborSignaledDown;
                Some(State::Down)
            } else {
                None
            }
        } else {
            match self.state {
                State::Down => match pkt.state {
                    State::Down => Some(State::Init),
                    State::Init => Some(State::Up),
                    _ => None,
                },
                State::Init => match pkt.state {
                    State::Init | State::Up => Some(State::Up),
                    _ => None,
                },
                State::Up => match pkt.state {
                    State::Down => {
                        self.local_diag = Diag::NeighborSignaledDown;
                        Some(State::Down)
                    }
                    _ => None,
                },
                State::AdminDown => None,
            }
        };

        match next {
            Some(to) => {
                let from = self.state;
                if to == State::Up {
                    self.local_diag = Diag::None;
                }
                if to == State::Down {
                    // The neighbour is gone for forwarding purposes; forget its id.
                    self.remote_discr = 0;
                }
                self.state = to;
                Some(Transition { from, to })
            }
            None => None,
        }
    }

    /// The runner's detection timer expired — no valid packet was received within
    /// the Detection Time (RFC 5880 §6.8.4). A session that was Up or Init fails
    /// with diagnostic Control Detection Time Expired; an already-Down session is
    /// unaffected. Returns the [`Transition`] when the state changed.
    pub fn on_detect_timeout(&mut self) -> Option<Transition> {
        if matches!(self.state, State::Up | State::Init) {
            let from = self.state;
            self.local_diag = Diag::ControlDetectionTimeExpired;
            self.state = State::Down;
            self.remote_state = State::Down;
            self.remote_discr = 0;
            Some(Transition { from, to: State::Down })
        } else {
            None
        }
    }

    /// Build the next Control packet to transmit, reflecting the current state and
    /// our (possibly floored) Desired Min TX Interval. Consumes any pending Final
    /// obligation from a received Poll.
    pub fn build_control(&mut self) -> ControlPacket {
        let final_ = self.send_final;
        self.send_final = false;
        ControlPacket {
            diag: self.local_diag,
            state: self.state,
            poll: false,
            final_,
            cpi: false,
            demand: false,
            detect_mult: self.cfg.detect_mult,
            my_discr: self.local_discr,
            your_discr: self.remote_discr,
            desired_min_tx: self.effective_desired_tx_us(),
            required_min_rx: self.cfg.required_min_rx_us,
            required_min_echo_rx: 0,
        }
    }

    /// Our effective Desired Min TX Interval: the configured value once Up, floored
    /// to one second while the session is not Up (RFC 5880 §6.8.3).
    fn effective_desired_tx_us(&self) -> u32 {
        if self.state == State::Up {
            self.cfg.desired_min_tx_us
        } else {
            self.cfg.desired_min_tx_us.max(SLOW_TX_FLOOR_US)
        }
    }

    /// The interval (microseconds) the runner should wait before the next transmit
    /// (RFC 5880 §6.8.2): the greater of our effective Desired Min TX and the
    /// neighbour's Required Min RX, reduced by a per-session jitter of 10–25%
    /// (§6.8.7, here a deterministic value in the allowed 75–90% window, varied by
    /// the discriminator so sessions do not transmit in lockstep).
    pub fn transmit_interval_us(&self) -> u64 {
        let base = (self.effective_desired_tx_us() as u64).max(self.remote_min_rx_us as u64);
        let pct = 75 + (self.local_discr % 16) as u64; // 75..=90
        base * pct / 100
    }

    /// The Detection Time (microseconds) after which, hearing nothing, the session
    /// fails (RFC 5880 §6.8.4): the neighbour's Detect Mult times the negotiated
    /// receive interval (the greater of our Required Min RX and the neighbour's
    /// Desired Min TX).
    pub fn detection_time_us(&self) -> u64 {
        let interval =
            (self.cfg.required_min_rx_us as u64).max(self.remote_desired_tx_us as u64);
        self.remote_detect_mult as u64 * interval
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> SessionConfig {
        SessionConfig { desired_min_tx_us: 300_000, required_min_rx_us: 300_000, detect_mult: 3 }
    }

    /// Run `rounds` of a full bidirectional exchange between two sessions, feeding
    /// each the other's built packet, and return them.
    fn exchange(rounds: usize) -> (Session, Session) {
        let mut a = Session::new(1, cfg());
        let mut b = Session::new(2, cfg());
        for _ in 0..rounds {
            let pa = a.build_control();
            b.on_packet(&pa);
            let pb = b.build_control();
            a.on_packet(&pb);
        }
        (a, b)
    }

    #[test]
    fn three_way_handshake_reaches_up() {
        let (a, b) = exchange(3);
        assert_eq!(a.state(), State::Up);
        assert_eq!(b.state(), State::Up);
        // Each learned the other's discriminator.
        assert_eq!(a.remote_discr(), 2);
        assert_eq!(b.remote_discr(), 1);
    }

    #[test]
    fn detect_timeout_from_up_goes_down_with_the_right_diag() {
        let (mut a, _b) = exchange(3);
        assert_eq!(a.state(), State::Up);
        let t = a.on_detect_timeout().expect("transition");
        assert_eq!(t, Transition { from: State::Up, to: State::Down });
        assert_eq!(a.state(), State::Down);
        assert_eq!(a.remote_discr(), 0);
        // The packet we now build carries the detection-expired diagnostic.
        let p = a.build_control();
        assert_eq!(p.diag, Diag::ControlDetectionTimeExpired);
        assert_eq!(p.state, State::Down);
        // A second timeout on an already-Down session is a no-op.
        assert!(a.on_detect_timeout().is_none());
    }

    #[test]
    fn neighbor_signaling_down_tears_an_up_session_down() {
        let (mut a, _b) = exchange(3);
        assert_eq!(a.state(), State::Up);
        let down = ControlPacket {
            diag: Diag::AdministrativelyDown,
            state: State::Down,
            poll: false,
            final_: false,
            cpi: false,
            demand: false,
            detect_mult: 3,
            my_discr: 2,
            your_discr: 1,
            desired_min_tx: 300_000,
            required_min_rx: 300_000,
            required_min_echo_rx: 0,
        };
        let t = a.on_packet(&down).expect("transition");
        assert_eq!(t, Transition { from: State::Up, to: State::Down });
        assert_eq!(a.build_control().diag, Diag::NeighborSignaledDown);
    }

    #[test]
    fn transmits_slowly_until_up_then_at_the_configured_rate() {
        let mut a = Session::new(3, cfg());
        // Down: floored to at least ~1s (minus jitter, so well above 700ms).
        assert!(a.transmit_interval_us() >= 700_000);
        // Drive it Up via a matching exchange.
        let mut b = Session::new(4, cfg());
        for _ in 0..3 {
            let pa = a.build_control();
            b.on_packet(&pa);
            let pb = b.build_control();
            a.on_packet(&pb);
        }
        assert_eq!(a.state(), State::Up);
        // Up: at the 300 ms configured rate (minus jitter), far below the floor.
        assert!(a.transmit_interval_us() <= 300_000);
    }

    #[test]
    fn answers_a_poll_with_the_final_bit_once() {
        let mut a = Session::new(5, cfg());
        let mut poll = a.build_control();
        poll.poll = true;
        poll.my_discr = 9;
        poll.state = State::Down;
        a.on_packet(&poll);
        assert!(a.build_control().final_, "first packet after a poll sets Final");
        assert!(!a.build_control().final_, "and only that one packet");
    }

    #[test]
    fn detection_time_follows_the_negotiated_receive_interval() {
        let (a, _b) = exchange(3);
        // remote detect_mult 3 × max(our min_rx 300ms, remote desired_tx 300ms).
        assert_eq!(a.detection_time_us(), 3 * 300_000);
    }
}
