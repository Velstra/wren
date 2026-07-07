//! # The PIM neighbour table (RFC 7761 §4.3)
//!
//! A PIM router learns its neighbours from the Hello messages they multicast to
//! ALL-PIM-ROUTERS (`224.0.0.13`) on each PIM interface, and keeps each neighbour
//! only as long as the Holdtime that neighbour advertised. This module is that
//! per-interface table: feed it a decoded Hello with [`NeighborTable::on_hello`],
//! age it with [`NeighborTable::expire`], and it tells you when a neighbour appeared
//! or went away — which the runner turns into log lines and (for a Join/Prune) the
//! set of valid RPF-neighbour candidates on an interface.
//!
//! The clock is injected (`Instant` passed in), so the table is fully unit-testable
//! with no sockets or real time.

use std::collections::BTreeMap;
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use crate::wire::HelloOption;
use crate::DEFAULT_HOLDTIME_SECS;

/// A Holdtime of `0xFFFF` seconds means "never time out" (§4.9.2).
const HOLDTIME_INFINITY: u16 = 0xFFFF;

/// One learned PIM neighbour on an interface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Neighbor {
    /// The neighbour's primary address (the Hello's IP source).
    pub addr: Ipv4Addr,
    /// The DR priority it advertised (default 1 if it sent no DR-Priority option).
    pub dr_priority: u32,
    /// The Generation ID it last advertised, if any — a change means it restarted.
    pub generation_id: Option<u32>,
    /// When this neighbour expires unless a further Hello refreshes it. `None` for a
    /// neighbour that advertised the infinite Holdtime.
    pub deadline: Option<Instant>,
}

/// What changed when a Hello or expiry was applied.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NeighborEvent {
    /// A neighbour was heard for the first time.
    Up(Ipv4Addr),
    /// An existing neighbour restarted — its Generation ID changed. The runner
    /// re-sends its Join/Prune state so the neighbour relearns it promptly.
    Restarted(Ipv4Addr),
    /// A neighbour timed out (or sent a Holdtime-0 goodbye).
    Down(Ipv4Addr),
}

impl NeighborEvent {
    /// The neighbour address this event concerns.
    pub fn addr(&self) -> Ipv4Addr {
        match *self {
            NeighborEvent::Up(a) | NeighborEvent::Restarted(a) | NeighborEvent::Down(a) => a,
        }
    }
}

/// The PIM neighbours seen on one interface, keyed by address.
#[derive(Debug, Clone, Default)]
pub struct NeighborTable {
    neighbors: BTreeMap<Ipv4Addr, Neighbor>,
}

impl NeighborTable {
    /// A fresh, empty table.
    pub fn new() -> Self {
        NeighborTable::default()
    }

    /// The number of live neighbours.
    pub fn len(&self) -> usize {
        self.neighbors.len()
    }

    /// Whether there are no neighbours.
    pub fn is_empty(&self) -> bool {
        self.neighbors.is_empty()
    }

    /// Whether `addr` is a known neighbour on this interface — the check that
    /// validates an RPF neighbour before a Join/Prune is addressed to it.
    pub fn contains(&self, addr: Ipv4Addr) -> bool {
        self.neighbors.contains_key(&addr)
    }

    /// Iterate the neighbours in address order.
    pub fn iter(&self) -> impl Iterator<Item = &Neighbor> {
        self.neighbors.values()
    }

    /// Apply a Hello received from `src` at `now`, returning the resulting event (or
    /// `None` if a known neighbour was merely refreshed). The Holdtime, DR priority
    /// and Generation ID are read from the Hello's options; a missing Holdtime falls
    /// back to the default (105 s).
    pub fn on_hello(
        &mut self,
        now: Instant,
        src: Ipv4Addr,
        options: &[HelloOption],
    ) -> Option<NeighborEvent> {
        let mut holdtime = DEFAULT_HOLDTIME_SECS;
        let mut dr_priority = crate::DEFAULT_DR_PRIORITY;
        let mut generation_id = None;
        for o in options {
            match o {
                HelloOption::Holdtime(h) => holdtime = *h,
                HelloOption::DrPriority(p) => dr_priority = *p,
                HelloOption::GenerationId(g) => generation_id = Some(*g),
                _ => {}
            }
        }

        // A Holdtime of 0 is a goodbye — drop the neighbour immediately.
        if holdtime == 0 {
            return self
                .neighbors
                .remove(&src)
                .map(|_| NeighborEvent::Down(src));
        }

        let deadline = if holdtime == HOLDTIME_INFINITY {
            None
        } else {
            Some(now + Duration::from_secs(holdtime as u64))
        };

        match self.neighbors.get_mut(&src) {
            Some(existing) => {
                // A changed Generation ID means the neighbour restarted (§4.3.4).
                let restarted = match (existing.generation_id, generation_id) {
                    (Some(old), Some(new)) => old != new,
                    _ => false,
                };
                existing.dr_priority = dr_priority;
                existing.generation_id = generation_id;
                existing.deadline = deadline;
                restarted.then_some(NeighborEvent::Restarted(src))
            }
            None => {
                self.neighbors.insert(
                    src,
                    Neighbor {
                        addr: src,
                        dr_priority,
                        generation_id,
                        deadline,
                    },
                );
                Some(NeighborEvent::Up(src))
            }
        }
    }

    /// Age out every neighbour whose Holdtime elapsed by `now`, returning a `Down`
    /// event per removed neighbour.
    pub fn expire(&mut self, now: Instant) -> Vec<NeighborEvent> {
        let gone: Vec<Ipv4Addr> = self
            .neighbors
            .iter()
            .filter(|(_, n)| matches!(n.deadline, Some(d) if d <= now))
            .map(|(a, _)| *a)
            .collect();
        gone.into_iter()
            .map(|a| {
                self.neighbors.remove(&a);
                NeighborEvent::Down(a)
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> Ipv4Addr {
        s.parse().unwrap()
    }

    fn hello(holdtime: u16, dr: u32, gen: Option<u32>) -> Vec<HelloOption> {
        let mut o = vec![HelloOption::Holdtime(holdtime), HelloOption::DrPriority(dr)];
        if let Some(g) = gen {
            o.push(HelloOption::GenerationId(g));
        }
        o
    }

    #[test]
    fn first_hello_brings_neighbour_up() {
        let mut t = NeighborTable::new();
        let ev = t.on_hello(Instant::now(), ip("10.0.2.1"), &hello(105, 1, Some(7)));
        assert_eq!(ev, Some(NeighborEvent::Up(ip("10.0.2.1"))));
        assert_eq!(t.len(), 1);
        assert!(t.contains(ip("10.0.2.1")));
    }

    #[test]
    fn refreshing_hello_is_not_a_new_event() {
        let mut t = NeighborTable::new();
        let t0 = Instant::now();
        t.on_hello(t0, ip("10.0.2.1"), &hello(105, 1, Some(7)));
        let ev = t.on_hello(t0 + Duration::from_secs(30), ip("10.0.2.1"), &hello(105, 1, Some(7)));
        assert_eq!(ev, None);
        assert_eq!(t.len(), 1);
    }

    #[test]
    fn changed_generation_id_signals_restart() {
        let mut t = NeighborTable::new();
        let t0 = Instant::now();
        t.on_hello(t0, ip("10.0.2.1"), &hello(105, 1, Some(7)));
        let ev = t.on_hello(t0, ip("10.0.2.1"), &hello(105, 1, Some(99)));
        assert_eq!(ev, Some(NeighborEvent::Restarted(ip("10.0.2.1"))));
    }

    #[test]
    fn holdtime_zero_is_a_goodbye() {
        let mut t = NeighborTable::new();
        let t0 = Instant::now();
        t.on_hello(t0, ip("10.0.2.1"), &hello(105, 1, Some(7)));
        let ev = t.on_hello(t0, ip("10.0.2.1"), &hello(0, 1, None));
        assert_eq!(ev, Some(NeighborEvent::Down(ip("10.0.2.1"))));
        assert!(t.is_empty());
    }

    #[test]
    fn neighbour_expires_after_holdtime() {
        let mut t = NeighborTable::new();
        let t0 = Instant::now();
        t.on_hello(t0, ip("10.0.2.1"), &hello(105, 1, Some(7)));
        // Just before the holdtime: still present.
        assert!(t.expire(t0 + Duration::from_secs(104)).is_empty());
        assert!(t.contains(ip("10.0.2.1")));
        // After it: down.
        assert_eq!(
            t.expire(t0 + Duration::from_secs(105)),
            vec![NeighborEvent::Down(ip("10.0.2.1"))]
        );
        assert!(t.is_empty());
    }

    #[test]
    fn infinite_holdtime_never_expires() {
        let mut t = NeighborTable::new();
        let t0 = Instant::now();
        t.on_hello(t0, ip("10.0.2.1"), &hello(0xFFFF, 1, Some(7)));
        assert!(t.expire(t0 + Duration::from_secs(100_000)).is_empty());
        assert!(t.contains(ip("10.0.2.1")));
    }

    #[test]
    fn missing_holdtime_option_uses_default() {
        let mut t = NeighborTable::new();
        let t0 = Instant::now();
        // A Hello with only a DR-Priority option: Holdtime defaults to 105 s.
        t.on_hello(t0, ip("10.0.2.1"), &[HelloOption::DrPriority(1)]);
        assert!(t.expire(t0 + Duration::from_secs(104)).is_empty());
        assert_eq!(
            t.expire(t0 + Duration::from_secs(105)),
            vec![NeighborEvent::Down(ip("10.0.2.1"))]
        );
    }
}
