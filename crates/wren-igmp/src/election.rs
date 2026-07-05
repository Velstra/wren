//! # Querier election (RFC 3376 §6 / RFC 3810 §7)
//!
//! A link may have more than one multicast router willing to be the querier. To
//! avoid every one of them flooding queries, they elect a single **Querier**: the
//! router with the *lowest* source address on the link wins. A router that hears a
//! query from a lower address than its own steps down to **Non-Querier** and stops
//! sending General Queries, arming an *Other-Querier-Present* timer; if that timer
//! elapses with no further query from a lower address (the elected querier went
//! away), it resumes as Querier.
//!
//! This is the same algorithm for IGMP (compare IPv4 source addresses) and MLD
//! (compare IPv6 link-local source addresses), so it is written once here, generic
//! over any ordered address type. The address compared is the router's own
//! *unicast* source on the interface (not a group address), so this is a plain
//! `Ord + Copy` bound rather than the multicast-address trait.

use std::time::{Duration, Instant};

use crate::membership::TimerConfig;

/// A state transition produced by the election, for the runner to log/act on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ElectionEvent {
    /// This router stepped down: a query from a lower address was heard.
    BecameNonQuerier,
    /// This router resumed as querier: the Other-Querier-Present timer elapsed.
    BecameQuerier,
}

/// A querier's election state on one interface, generic over the (unicast) source
/// address family `A`.
#[derive(Debug, Clone)]
pub struct QuerierState<A: Ord + Copy> {
    /// This router's own source address on the interface. A router only steps down
    /// for an address *strictly lower* than this; the unspecified/zero address (used
    /// when the interface's address is unknown) is the minimum, so such a router
    /// never yields — it simply keeps querying.
    own: A,
    /// Whether this router is currently the elected querier.
    is_querier: bool,
    /// When to resume as querier if no lower query is heard (Non-Querier only).
    other_deadline: Option<Instant>,
    /// The Other-Querier-Present interval (RFC 3376 §8.5): `QRV·QI + QRI/2`.
    other_present: Duration,
}

impl<A: Ord + Copy> QuerierState<A> {
    /// A router that starts up as the querier (per the RFC startup behaviour) with
    /// its own source address `own` and timers derived from `cfg`.
    pub fn new(own: A, cfg: &TimerConfig) -> Self {
        QuerierState {
            own,
            is_querier: true,
            other_deadline: None,
            other_present: cfg.other_querier_present_interval(),
        }
    }

    /// Whether this router should currently send General Queries.
    pub fn is_querier(&self) -> bool {
        self.is_querier
    }

    /// This router's own source address.
    pub fn own(&self) -> A {
        self.own
    }

    /// Process a query received from source address `src`. If `src` is lower than our
    /// own address we (re)start the Other-Querier-Present timer and, if we were the
    /// querier, step down. Returns a transition event only when the querier/non-
    /// querier state actually flips.
    pub fn on_query(&mut self, now: Instant, src: A) -> Option<ElectionEvent> {
        if src < self.own {
            // A lower-addressed querier is present: (re)arm the timer.
            self.other_deadline = Some(now + self.other_present);
            if self.is_querier {
                self.is_querier = false;
                return Some(ElectionEvent::BecameNonQuerier);
            }
        }
        None
    }

    /// Advance time. If we are a non-querier whose Other-Querier-Present timer has
    /// elapsed, resume as querier. Returns the transition event when it flips.
    pub fn tick(&mut self, now: Instant) -> Option<ElectionEvent> {
        if !self.is_querier {
            if let Some(deadline) = self.other_deadline {
                if now >= deadline {
                    self.is_querier = true;
                    self.other_deadline = None;
                    return Some(ElectionEvent::BecameQuerier);
                }
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn ip(s: &str) -> Ipv4Addr {
        s.parse().unwrap()
    }

    fn cfg() -> TimerConfig {
        TimerConfig::default()
    }

    #[test]
    fn starts_as_querier() {
        let q = QuerierState::new(ip("10.0.0.5"), &cfg());
        assert!(q.is_querier());
    }

    #[test]
    fn lower_address_query_makes_us_step_down() {
        let mut q = QuerierState::new(ip("10.0.0.5"), &cfg());
        let now = Instant::now();
        // A query from a lower address: we yield.
        assert_eq!(
            q.on_query(now, ip("10.0.0.1")),
            Some(ElectionEvent::BecameNonQuerier)
        );
        assert!(!q.is_querier());
        // A second lower query only refreshes the timer, no new transition.
        assert_eq!(q.on_query(now, ip("10.0.0.1")), None);
        assert!(!q.is_querier());
    }

    #[test]
    fn higher_or_equal_address_query_is_ignored() {
        let mut q = QuerierState::new(ip("10.0.0.5"), &cfg());
        let now = Instant::now();
        // Higher address: they will step down, not us.
        assert_eq!(q.on_query(now, ip("10.0.0.9")), None);
        assert!(q.is_querier());
        // Our own looped-back query: equal, ignored.
        assert_eq!(q.on_query(now, ip("10.0.0.5")), None);
        assert!(q.is_querier());
    }

    #[test]
    fn lowest_address_wins_between_two_queriers() {
        // Model both routers seeing each other's queries.
        let mut low = QuerierState::new(ip("10.0.0.1"), &cfg());
        let mut high = QuerierState::new(ip("10.0.0.2"), &cfg());
        let now = Instant::now();
        // low hears high (higher) → stays querier; high hears low (lower) → steps down.
        assert_eq!(low.on_query(now, ip("10.0.0.2")), None);
        assert_eq!(
            high.on_query(now, ip("10.0.0.1")),
            Some(ElectionEvent::BecameNonQuerier)
        );
        assert!(low.is_querier());
        assert!(!high.is_querier());
    }

    #[test]
    fn resumes_querier_after_other_present_timer() {
        let c = cfg();
        let mut q = QuerierState::new(ip("10.0.0.5"), &c);
        let t0 = Instant::now();
        q.on_query(t0, ip("10.0.0.1"));
        assert!(!q.is_querier());
        // Before the OQPI (255 s for the defaults) → still non-querier.
        let oqpi = c.other_querier_present_interval();
        assert_eq!(q.tick(t0 + oqpi - Duration::from_secs(1)), None);
        assert!(!q.is_querier());
        // After the OQPI with no further lower query → resume querier.
        assert_eq!(q.tick(t0 + oqpi), Some(ElectionEvent::BecameQuerier));
        assert!(q.is_querier());
    }

    #[test]
    fn unspecified_own_never_yields() {
        // A router with an unknown (zero) address is the minimum: nobody is lower,
        // so it keeps querying regardless of who else is present.
        let mut q = QuerierState::new(Ipv4Addr::UNSPECIFIED, &cfg());
        assert_eq!(q.on_query(Instant::now(), ip("10.0.0.1")), None);
        assert!(q.is_querier());
    }

    #[test]
    fn other_querier_present_interval_matches_rfc() {
        // QRV 2, QI 125 s, QRI 10 s → 2·125 + 5 = 255 s.
        assert_eq!(
            TimerConfig::default().other_querier_present_interval(),
            Duration::from_secs(255)
        );
    }
}
