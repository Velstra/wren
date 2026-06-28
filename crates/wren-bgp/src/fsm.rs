//! The BGP finite state machine (RFC 4271 §8) — the per-peer session lifecycle
//! from Idle to Established and back.
//!
//! [`BgpFsm::handle`] consumes an [`Event`] (an administrative command, a timer
//! expiry, a TCP connection change, or a received message) and returns the
//! [`Action`]s the session runner must carry out — open/close the TCP connection,
//! send an OPEN/KEEPALIVE/NOTIFICATION, arm or restart a timer, or signal the
//! session up/down. No sockets, no clock: the runner supplies events and executes
//! actions, so every transition is unit-testable.
//!
//! A pragmatic subset of the §8.1 event set is modelled — enough to bring a
//! session up, keep it alive and tear it down cleanly. Collision detection
//! (§6.8) and the delay-open/passive options are left to the runner/future work.

/// The six session states (§8.2.2).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum State {
    /// Refusing connections; the start state.
    Idle,
    /// Trying to complete the outgoing TCP connection.
    Connect,
    /// The outgoing connect failed; listening/retrying.
    Active,
    /// TCP is up and our OPEN was sent; awaiting the peer's OPEN.
    OpenSent,
    /// OPENs exchanged; awaiting the peer's first KEEPALIVE.
    OpenConfirm,
    /// The session is up; UPDATEs may flow.
    Established,
}

/// The inputs that drive the session machine (a subset of §8.1).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Event {
    /// Administratively start the peer.
    ManualStart,
    /// Administratively stop the peer.
    ManualStop,
    /// The ConnectRetry timer fired.
    ConnectRetryTimerExpires,
    /// The Hold timer fired — the peer went silent.
    HoldTimerExpires,
    /// The Keepalive timer fired — time to send a KEEPALIVE.
    KeepaliveTimerExpires,
    /// The TCP connection completed.
    TcpConnected,
    /// The TCP connection failed or was reset.
    TcpConnectionFails,
    /// A valid OPEN was received.
    OpenReceived,
    /// A KEEPALIVE was received.
    KeepAliveReceived,
    /// An UPDATE was received.
    UpdateReceived,
    /// A NOTIFICATION was received.
    NotificationReceived,
    /// The received OPEN was unacceptable/malformed.
    OpenError,
}

/// A NOTIFICATION error code (§4.5 / §6).
pub const CODE_MESSAGE_HEADER: u8 = 1;
/// OPEN Message Error.
pub const CODE_OPEN_MESSAGE: u8 = 2;
/// UPDATE Message Error.
pub const CODE_UPDATE_MESSAGE: u8 = 3;
/// Hold Timer Expired.
pub const CODE_HOLD_TIMER_EXPIRED: u8 = 4;
/// Finite State Machine Error.
pub const CODE_FSM_ERROR: u8 = 5;
/// Cease (administrative shutdown).
pub const CODE_CEASE: u8 = 6;

/// What the runner must do as a result of a transition.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Action {
    /// Initiate the outgoing TCP connection to the peer (port 179).
    ConnectTcp,
    /// Tear down the TCP connection.
    DropTcp,
    /// Send an OPEN message.
    SendOpen,
    /// Send a KEEPALIVE message.
    SendKeepalive,
    /// Send a NOTIFICATION with this error code/subcode, then close.
    SendNotification {
        /// The NOTIFICATION error code.
        code: u8,
        /// The NOTIFICATION error subcode.
        subcode: u8,
    },
    /// (Re)arm the ConnectRetry timer.
    StartConnectRetryTimer,
    /// Cancel the ConnectRetry timer.
    StopConnectRetryTimer,
    /// Arm the Hold timer (RouterDeadInterval-equivalent).
    StartHoldTimer,
    /// Restart the Hold timer (a message refreshed liveness).
    RestartHoldTimer,
    /// Arm the Keepalive timer (typically Hold/3).
    StartKeepaliveTimer,
    /// The session reached Established — start advertising / accept UPDATEs.
    SessionEstablished,
    /// The session left Established (or failed) — flush this peer's routes.
    SessionDown,
}

/// One peer's session state machine.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct BgpFsm {
    state: State,
}

impl Default for BgpFsm {
    fn default() -> Self {
        BgpFsm { state: State::Idle }
    }
}

impl BgpFsm {
    /// A new session in [`State::Idle`].
    pub fn new() -> Self {
        Self::default()
    }

    /// The current state.
    pub fn state(&self) -> State {
        self.state
    }

    /// Whether the session is Established (UPDATEs may be processed).
    pub fn is_established(&self) -> bool {
        self.state == State::Established
    }

    /// Drive the machine with `ev`, mutating the state and returning the actions
    /// the runner must perform (§8.2.2).
    pub fn handle(&mut self, ev: Event) -> Vec<Action> {
        use Action::*;
        use Event::*;
        use State::*;

        let was_established = self.state == Established;

        // Events that end the session from (almost) any state.
        match ev {
            ManualStop => {
                let mut acts = Vec::new();
                if self.state != Idle {
                    acts.push(SendNotification {
                        code: CODE_CEASE,
                        subcode: 0,
                    });
                    acts.push(DropTcp);
                }
                if was_established {
                    acts.push(SessionDown);
                }
                self.state = Idle;
                return acts;
            }
            NotificationReceived => {
                self.state = Idle;
                let mut acts = vec![DropTcp];
                if was_established {
                    acts.push(SessionDown);
                }
                return acts;
            }
            _ => {}
        }

        match (self.state, ev) {
            // --- Idle -----------------------------------------------------
            (Idle, ManualStart) => {
                self.state = Connect;
                vec![StartConnectRetryTimer, ConnectTcp]
            }

            // --- Connect --------------------------------------------------
            (Connect, TcpConnected) => {
                self.state = OpenSent;
                vec![StopConnectRetryTimer, SendOpen, StartHoldTimer]
            }
            (Connect, ConnectRetryTimerExpires) => vec![StartConnectRetryTimer, ConnectTcp],
            (Connect, TcpConnectionFails) => {
                self.state = Active;
                vec![StartConnectRetryTimer]
            }

            // --- Active ---------------------------------------------------
            (Active, TcpConnected) => {
                self.state = OpenSent;
                vec![StopConnectRetryTimer, SendOpen, StartHoldTimer]
            }
            (Active, ConnectRetryTimerExpires) => {
                self.state = Connect;
                vec![StartConnectRetryTimer, ConnectTcp]
            }

            // --- OpenSent -------------------------------------------------
            (OpenSent, OpenReceived) => {
                self.state = OpenConfirm;
                vec![SendKeepalive, StartKeepaliveTimer, RestartHoldTimer]
            }
            (OpenSent, HoldTimerExpires) => {
                self.state = Idle;
                vec![
                    SendNotification { code: CODE_HOLD_TIMER_EXPIRED, subcode: 0 },
                    DropTcp,
                ]
            }
            (OpenSent, OpenError) => {
                self.state = Idle;
                vec![
                    SendNotification { code: CODE_OPEN_MESSAGE, subcode: 0 },
                    DropTcp,
                ]
            }
            (OpenSent, TcpConnectionFails) => {
                self.state = Active;
                vec![DropTcp, StartConnectRetryTimer]
            }

            // --- OpenConfirm ----------------------------------------------
            (OpenConfirm, KeepAliveReceived) => {
                self.state = Established;
                vec![RestartHoldTimer, SessionEstablished]
            }
            (OpenConfirm, KeepaliveTimerExpires) => vec![SendKeepalive],
            (OpenConfirm, HoldTimerExpires) => {
                self.state = Idle;
                vec![
                    SendNotification { code: CODE_HOLD_TIMER_EXPIRED, subcode: 0 },
                    DropTcp,
                ]
            }
            (OpenConfirm, TcpConnectionFails) => {
                self.state = Idle;
                vec![DropTcp]
            }

            // --- Established ----------------------------------------------
            (Established, KeepAliveReceived) => vec![RestartHoldTimer],
            (Established, UpdateReceived) => vec![RestartHoldTimer],
            (Established, KeepaliveTimerExpires) => vec![SendKeepalive],
            (Established, HoldTimerExpires) => {
                self.state = Idle;
                vec![
                    SendNotification { code: CODE_HOLD_TIMER_EXPIRED, subcode: 0 },
                    DropTcp,
                    SessionDown,
                ]
            }
            (Established, TcpConnectionFails) => {
                self.state = Idle;
                vec![DropTcp, SessionDown]
            }

            // Anything else is a no-op in the current state.
            _ => vec![],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Action::*;
    use super::Event::*;
    use super::State::*;
    use super::*;

    #[test]
    fn full_session_bringup() {
        let mut fsm = BgpFsm::new();
        assert_eq!(fsm.handle(ManualStart), vec![StartConnectRetryTimer, ConnectTcp]);
        assert_eq!(fsm.state(), Connect);
        assert_eq!(
            fsm.handle(TcpConnected),
            vec![StopConnectRetryTimer, SendOpen, StartHoldTimer]
        );
        assert_eq!(fsm.state(), OpenSent);
        assert_eq!(
            fsm.handle(OpenReceived),
            vec![SendKeepalive, StartKeepaliveTimer, RestartHoldTimer]
        );
        assert_eq!(fsm.state(), OpenConfirm);
        assert_eq!(fsm.handle(KeepAliveReceived), vec![RestartHoldTimer, SessionEstablished]);
        assert_eq!(fsm.state(), Established);
        assert!(fsm.is_established());
    }

    #[test]
    fn keepalive_and_update_keep_the_session() {
        let mut fsm = BgpFsm { state: Established };
        assert_eq!(fsm.handle(KeepAliveReceived), vec![RestartHoldTimer]);
        assert_eq!(fsm.handle(UpdateReceived), vec![RestartHoldTimer]);
        assert_eq!(fsm.handle(KeepaliveTimerExpires), vec![SendKeepalive]);
        assert_eq!(fsm.state(), Established);
    }

    #[test]
    fn hold_timer_expiry_tears_down_with_notification() {
        let mut fsm = BgpFsm { state: Established };
        let acts = fsm.handle(HoldTimerExpires);
        assert_eq!(
            acts,
            vec![
                SendNotification { code: CODE_HOLD_TIMER_EXPIRED, subcode: 0 },
                DropTcp,
                SessionDown,
            ]
        );
        assert_eq!(fsm.state(), Idle);
    }

    #[test]
    fn manual_stop_sends_cease_and_flushes_when_established() {
        let mut fsm = BgpFsm { state: Established };
        let acts = fsm.handle(ManualStop);
        assert_eq!(
            acts,
            vec![SendNotification { code: CODE_CEASE, subcode: 0 }, DropTcp, SessionDown]
        );
        assert_eq!(fsm.state(), Idle);

        // From OpenSent (not yet up) there is no SessionDown to flush.
        let mut fsm = BgpFsm { state: OpenSent };
        let acts = fsm.handle(ManualStop);
        assert_eq!(acts, vec![SendNotification { code: CODE_CEASE, subcode: 0 }, DropTcp]);
    }

    #[test]
    fn notification_received_drops_and_flushes() {
        let mut fsm = BgpFsm { state: Established };
        assert_eq!(fsm.handle(NotificationReceived), vec![DropTcp, SessionDown]);
        assert_eq!(fsm.state(), Idle);
    }

    #[test]
    fn connect_failure_goes_active_then_retries() {
        let mut fsm = BgpFsm::new();
        fsm.handle(ManualStart);
        assert_eq!(fsm.handle(TcpConnectionFails), vec![StartConnectRetryTimer]);
        assert_eq!(fsm.state(), Active);
        assert_eq!(
            fsm.handle(ConnectRetryTimerExpires),
            vec![StartConnectRetryTimer, ConnectTcp]
        );
        assert_eq!(fsm.state(), Connect);
    }

    #[test]
    fn bad_open_in_opensent_notifies_and_idles() {
        let mut fsm = BgpFsm { state: OpenSent };
        assert_eq!(
            fsm.handle(OpenError),
            vec![SendNotification { code: CODE_OPEN_MESSAGE, subcode: 0 }, DropTcp]
        );
        assert_eq!(fsm.state(), Idle);
    }
}
