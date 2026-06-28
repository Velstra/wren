//! The Babel neighbour table and link-cost computation (RFC 8966 §3.4).
//!
//! For each neighbour we track a **Hello history** — which of the Hellos we
//! expected actually arrived — and the **txcost** the neighbour reports about us in
//! its IHUs. From those two we derive:
//!
//! * **rxcost** — how well *we* hear the neighbour, computed from the Hello history
//!   and advertised back to it in our own IHUs;
//! * the **link cost** — what it costs to send *to* the neighbour, used by the
//!   [route table](crate::table) when composing route metrics.
//!
//! The strategy implemented is the classic wired **"2-out-of-3"** rule
//! (Appendix A.2.1): the link is usable when at least two of the last three
//! expected Hellos arrived, in which case the cost is the neighbour's reported
//! txcost; otherwise it is infinite. (The ETX rule for lossy/wireless links is a
//! later refinement.)
//!
//! Like the rest of the crate this is pure: time is passed in as a logical second
//! count, so the whole table is unit-testable with no clock.

use std::collections::BTreeMap;
use std::net::IpAddr;

use crate::METRIC_INFINITY;

/// The nominal cost of one perfect wired hop (§3.4.3 / Appendix A.2.1).
pub const NOMINAL_RXCOST: u16 = 256;

/// One neighbour on a shared link.
#[derive(Clone, Copy, Debug)]
struct Neighbour {
    /// Hello reception history; bit 0 is the most recent expected Hello.
    history: u16,
    /// The next Hello sequence number expected from this neighbour.
    expected_seqno: u16,
    /// Whether at least one Hello has been seen (so the history is meaningful).
    have_hello: bool,
    /// `txcost`: the rxcost the neighbour last reported about us via IHU
    /// (infinite until the first IHU).
    txcost: u16,
    /// When (logical seconds) the last Hello arrived.
    last_hello: u64,
    /// When (logical seconds) the last IHU arrived.
    last_ihu: u64,
}

impl Neighbour {
    fn new() -> Self {
        Neighbour {
            history: 0,
            expected_seqno: 0,
            have_hello: false,
            txcost: METRIC_INFINITY,
            last_hello: 0,
            last_ihu: 0,
        }
    }

    /// Fold a received Hello (`seqno`) into the history (Appendix A.1).
    fn on_hello(&mut self, seqno: u16, now: u64) {
        if !self.have_hello {
            self.history = 1;
            self.have_hello = true;
        } else {
            let gap = seqno.wrapping_sub(self.expected_seqno);
            if gap < 0x8000 {
                // `gap` Hellos were missed before this one; shift them in as zeros,
                // then mark this one received.
                let shift = gap as u32 + 1;
                self.history = if shift >= 16 { 1 } else { (self.history << shift) | 1 };
            } else {
                // The seqno went backwards (reordering or a restart) — resync.
                self.history = 1;
            }
        }
        self.expected_seqno = seqno.wrapping_add(1);
        self.last_hello = now;
    }

    /// Record an IHU: the neighbour's rxcost for us becomes our txcost to it.
    fn on_ihu(&mut self, txcost: u16, now: u64) {
        self.txcost = txcost;
        self.last_ihu = now;
    }

    /// Our receive cost from this neighbour: nominal if at least two of the last
    /// three expected Hellos arrived, else infinite (§A.2.1).
    fn rxcost(&self) -> u16 {
        if !self.have_hello {
            return METRIC_INFINITY;
        }
        if (self.history & 0b111).count_ones() >= 2 {
            NOMINAL_RXCOST
        } else {
            METRIC_INFINITY
        }
    }

    /// The cost of sending to this neighbour: its reported txcost when the link is
    /// usable in our direction, else infinite.
    fn cost(&self) -> u16 {
        if self.rxcost() == METRIC_INFINITY || self.txcost == METRIC_INFINITY {
            METRIC_INFINITY
        } else {
            self.txcost
        }
    }
}

/// The neighbour table: every known neighbour, keyed by its (link-local) address.
#[derive(Default)]
pub struct NeighbourTable {
    neighbours: BTreeMap<IpAddr, Neighbour>,
}

impl NeighbourTable {
    /// An empty table.
    pub fn new() -> Self {
        Self::default()
    }

    /// Process a Hello from `addr` with sequence number `seqno` at time `now`.
    pub fn on_hello(&mut self, addr: IpAddr, seqno: u16, now: u64) {
        self.neighbours
            .entry(addr)
            .or_insert_with(Neighbour::new)
            .on_hello(seqno, now);
    }

    /// Process an IHU from `addr` reporting `rxcost` (its receive cost for us).
    pub fn on_ihu(&mut self, addr: IpAddr, rxcost: u16, now: u64) {
        self.neighbours
            .entry(addr)
            .or_insert_with(Neighbour::new)
            .on_ihu(rxcost, now);
    }

    /// Our receive cost from `addr` — the value to advertise in an IHU to it
    /// (infinite if unknown).
    pub fn rxcost(&self, addr: &IpAddr) -> u16 {
        self.neighbours
            .get(addr)
            .map_or(METRIC_INFINITY, Neighbour::rxcost)
    }

    /// The cost of sending to `addr` (infinite if unknown or the link is down).
    pub fn cost(&self, addr: &IpAddr) -> u16 {
        self.neighbours
            .get(addr)
            .map_or(METRIC_INFINITY, Neighbour::cost)
    }

    /// Whether `addr` is a known neighbour.
    pub fn contains(&self, addr: &IpAddr) -> bool {
        self.neighbours.contains_key(addr)
    }

    /// Every known neighbour's address (e.g. to address an IHU to each of them).
    pub fn addresses(&self) -> Vec<IpAddr> {
        self.neighbours.keys().copied().collect()
    }

    /// The number of known neighbours.
    pub fn len(&self) -> usize {
        self.neighbours.len()
    }

    /// Whether no neighbours are known.
    pub fn is_empty(&self) -> bool {
        self.neighbours.is_empty()
    }

    /// Age the table at time `now`: drop neighbours whose last Hello is older than
    /// `hello_timeout` (returned, so the caller can flush their routes), and clear
    /// the txcost of neighbours whose last IHU is older than `ihu_timeout` (so the
    /// link to them goes infinite until a fresh IHU).
    pub fn expire(&mut self, now: u64, hello_timeout: u64, ihu_timeout: u64) -> Vec<IpAddr> {
        for n in self.neighbours.values_mut() {
            if now.saturating_sub(n.last_ihu) > ihu_timeout {
                n.txcost = METRIC_INFINITY;
            }
        }
        let dead: Vec<IpAddr> = self
            .neighbours
            .iter()
            .filter(|(_, n)| now.saturating_sub(n.last_hello) > hello_timeout)
            .map(|(a, _)| *a)
            .collect();
        for a in &dead {
            self.neighbours.remove(a);
        }
        dead
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn two_of_three_hellos_bring_rxcost_finite() {
        let mut t = NeighbourTable::new();
        let n = ip("fe80::1");
        // One Hello is not enough (need 2 of the last 3).
        t.on_hello(n, 1, 0);
        assert_eq!(t.rxcost(&n), METRIC_INFINITY);
        // A second consecutive Hello → rxcost becomes nominal.
        t.on_hello(n, 2, 1);
        assert_eq!(t.rxcost(&n), NOMINAL_RXCOST);
    }

    #[test]
    fn cost_needs_an_ihu_for_txcost() {
        let mut t = NeighbourTable::new();
        let n = ip("fe80::1");
        t.on_hello(n, 1, 0);
        t.on_hello(n, 2, 1);
        // We hear the neighbour (rxcost finite) but have no txcost yet → cost infinite.
        assert_eq!(t.cost(&n), METRIC_INFINITY);
        // After an IHU, our cost to the neighbour is the reported txcost.
        t.on_ihu(n, 96, 2);
        assert_eq!(t.cost(&n), 96);
    }

    #[test]
    fn a_missed_hello_drops_the_link() {
        let mut t = NeighbourTable::new();
        let n = ip("fe80::1");
        t.on_hello(n, 1, 0);
        t.on_hello(n, 2, 1);
        assert_eq!(t.rxcost(&n), NOMINAL_RXCOST);
        // Skip seqnos 3 and 4, arrive at 5: history shifts in two misses, leaving
        // only 1 of the last 3 → rxcost infinite again.
        t.on_hello(n, 5, 2);
        assert_eq!(t.rxcost(&n), METRIC_INFINITY);
    }

    #[test]
    fn reordered_seqno_resyncs() {
        let mut t = NeighbourTable::new();
        let n = ip("fe80::1");
        t.on_hello(n, 10, 0);
        t.on_hello(n, 11, 1);
        assert_eq!(t.rxcost(&n), NOMINAL_RXCOST);
        // A much older seqno (restart) resyncs the history to a single Hello.
        t.on_hello(n, 1, 2);
        assert_eq!(t.rxcost(&n), METRIC_INFINITY);
    }

    #[test]
    fn stale_ihu_makes_cost_infinite_then_hello_timeout_drops_neighbour() {
        let mut t = NeighbourTable::new();
        let n = ip("fe80::1");
        t.on_hello(n, 1, 0);
        t.on_hello(n, 2, 1);
        t.on_ihu(n, 96, 1);
        assert_eq!(t.cost(&n), 96);

        // At t=10 the IHU (last at t=1) is stale (timeout 5) → txcost cleared, cost
        // infinite, but the neighbour is still alive (Hello timeout 20).
        let dead = t.expire(10, 20, 5);
        assert!(dead.is_empty());
        assert!(t.contains(&n));
        assert_eq!(t.cost(&n), METRIC_INFINITY);

        // At t=30 the Hello (last at t=1) is stale → the neighbour is removed.
        let dead = t.expire(30, 20, 5);
        assert_eq!(dead, vec![n]);
        assert!(t.is_empty());
    }
}
