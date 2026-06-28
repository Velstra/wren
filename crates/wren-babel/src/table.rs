//! The Babel route table and the feasibility condition (RFC 8966 §3.5–§3.6).
//!
//! This is the pure routing kernel: it takes received Updates as plain values and
//! decides which route to each prefix is selected, with no sockets and no clock.
//!
//! Two tables cooperate:
//!
//! * the **source table** ([`SourceTable`]) keeps, per source `(prefix,
//!   router-id)`, the *feasibility distance* — the best `(seqno, metric)` we have
//!   committed to. The **feasibility condition** (§3.5.1) uses it to reject routes
//!   that could form a loop: a received `(seqno, metric)` is feasible only if it is
//!   strictly better than the feasibility distance (a more recent seqno, or the
//!   same seqno with a strictly smaller metric), or the source is new, or it is a
//!   retraction.
//! * the **route table** ([`RouteTable`]) keeps every neighbour's offered route per
//!   source and selects, for each prefix, the feasible route of smallest metric
//!   (advertised metric plus the link cost to the neighbour). Selection changes are
//!   reported as [`BabelEvent`]s for the central RIB.

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

use wren_core::Prefix;

use crate::METRIC_INFINITY;

/// Whether sequence number `a` is strictly more recent than `b`, compared modulo
/// 2¹⁶ (§3.2.1): `a` is newer when `(a - b) mod 65536` lies in `1..=32767`.
pub fn seqno_newer(a: u16, b: u16) -> bool {
    a != b && a.wrapping_sub(b) < 0x8000
}

/// Add a link `cost` to an advertised `metric`, saturating at infinity (§3.5.2):
/// an infinite operand, or any sum that reaches `0xFFFF`, is infinity.
pub fn add_metric(metric: u16, cost: u16) -> u16 {
    if metric == METRIC_INFINITY || cost == METRIC_INFINITY {
        METRIC_INFINITY
    } else {
        metric.saturating_add(cost)
    }
}

/// A feasibility distance: the best `(seqno, metric)` committed for a source.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
struct Fd {
    seqno: u16,
    metric: u16,
}

/// Whether `(seqno, metric)` is strictly better than the feasibility distance
/// `fd` (§3.5.1): a more recent seqno, or the same seqno with a smaller metric.
fn strictly_better(seqno: u16, metric: u16, fd: Fd) -> bool {
    seqno_newer(seqno, fd.seqno) || (seqno == fd.seqno && metric < fd.metric)
}

/// The source table: the feasibility distance per `(prefix, router-id)`.
#[derive(Default)]
pub struct SourceTable {
    fds: BTreeMap<(Prefix, [u8; 8]), Fd>,
}

impl SourceTable {
    /// Whether an Update with `(seqno, metric)` for `(prefix, router_id)` satisfies
    /// the feasibility condition (§3.5.1). Retractions (`metric == infinity`) and
    /// updates for an unknown source are always feasible.
    pub fn is_feasible(&self, prefix: Prefix, router_id: [u8; 8], seqno: u16, metric: u16) -> bool {
        if metric == METRIC_INFINITY {
            return true;
        }
        match self.fds.get(&(prefix, router_id)) {
            None => true,
            Some(fd) => strictly_better(seqno, metric, *fd),
        }
    }

    /// Lower the feasibility distance for a selected route, if it improves on the
    /// current one (§3.5.3). Never raises it for the same seqno.
    fn update(&mut self, prefix: Prefix, router_id: [u8; 8], seqno: u16, metric: u16) {
        if metric == METRIC_INFINITY {
            return;
        }
        let key = (prefix, router_id);
        let better = match self.fds.get(&key) {
            None => true,
            Some(fd) => strictly_better(seqno, metric, *fd),
        };
        if better {
            self.fds.insert(key, Fd { seqno, metric });
        }
    }

    /// The number of sources tracked.
    pub fn len(&self) -> usize {
        self.fds.len()
    }

    /// Whether no sources are tracked.
    pub fn is_empty(&self) -> bool {
        self.fds.is_empty()
    }
}

/// The index of one offered route: a source reached through a particular neighbour.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
struct RouteKey {
    prefix: Prefix,
    router_id: [u8; 8],
    neighbour: IpAddr,
}

/// One neighbour's offered route to a source.
#[derive(Clone, Copy, Debug)]
struct RouteEntry {
    seqno: u16,
    /// The metric as advertised by the neighbour (used for feasibility).
    advertised: u16,
    /// The link cost to that neighbour.
    cost: u16,
    /// The next hop to install if this route is selected.
    next_hop: IpAddr,
    /// Whether this route passed the feasibility condition.
    feasible: bool,
}

impl RouteEntry {
    /// The route's own metric: advertised metric plus the link cost (§3.5.2).
    fn metric(&self) -> u16 {
        add_metric(self.advertised, self.cost)
    }
}

/// A change to the selected route for a prefix, for the central RIB to apply.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum BabelEvent {
    /// `prefix`'s best route appeared or changed — install it.
    Select {
        /// The destination.
        prefix: Prefix,
        /// The next hop to forward via.
        next_hop: IpAddr,
        /// The selected route's metric.
        metric: u16,
    },
    /// `prefix` has no feasible route any more — withdraw it.
    Retract(Prefix),
}

/// The Babel route table: every neighbour's offered route, and the selected best
/// per prefix.
#[derive(Default)]
pub struct RouteTable {
    sources: SourceTable,
    routes: BTreeMap<RouteKey, RouteEntry>,
    /// The currently selected route per prefix, as last emitted: `(key, next_hop,
    /// metric)`, for change detection.
    selected: BTreeMap<Prefix, (RouteKey, IpAddr, u16)>,
}

impl RouteTable {
    /// An empty table.
    pub fn new() -> Self {
        Self::default()
    }

    /// Process a received Update for `(prefix, router_id)` from `neighbour`, with
    /// the advertised `seqno`/`metric` and the `cost` of the link to that
    /// neighbour. `next_hop` is what to install if the route is selected. Returns a
    /// selection change for this prefix, if any.
    #[allow(clippy::too_many_arguments)]
    pub fn update(
        &mut self,
        prefix: Prefix,
        router_id: [u8; 8],
        neighbour: IpAddr,
        next_hop: IpAddr,
        seqno: u16,
        advertised: u16,
        cost: u16,
    ) -> Option<BabelEvent> {
        let key = RouteKey {
            prefix,
            router_id,
            neighbour,
        };
        if advertised == METRIC_INFINITY {
            // A retraction withdraws this neighbour's route to the source.
            self.routes.remove(&key);
        } else {
            // The currently selected route to a source is feasible by definition —
            // it is the one that set the feasibility distance, so a refresh of it
            // (which is never "strictly better" than itself) must not be rejected.
            // Feasibility otherwise gates only the selection of *other* routes.
            let feasible = self.is_selected_route(&key)
                || self.sources.is_feasible(prefix, router_id, seqno, advertised);
            self.routes.insert(
                key,
                RouteEntry {
                    seqno,
                    advertised,
                    cost,
                    next_hop,
                    feasible,
                },
            );
        }
        self.reselect(prefix)
    }

    /// Drop every route through `neighbour` (its session went down), returning the
    /// selection change for each affected prefix.
    pub fn neighbour_lost(&mut self, neighbour: IpAddr) -> Vec<BabelEvent> {
        let affected: BTreeSet<Prefix> = self
            .routes
            .keys()
            .filter(|k| k.neighbour == neighbour)
            .map(|k| k.prefix)
            .collect();
        self.routes.retain(|k, _| k.neighbour != neighbour);
        affected
            .into_iter()
            .filter_map(|p| self.reselect(p))
            .collect()
    }

    /// Whether `key` indexes the route currently selected for its prefix.
    fn is_selected_route(&self, key: &RouteKey) -> bool {
        self.selected
            .get(&key.prefix)
            .is_some_and(|(k, _, _)| k == key)
    }

    /// The selected next hop and metric for `prefix`, if any.
    pub fn selected(&self, prefix: &Prefix) -> Option<(IpAddr, u16)> {
        self.selected.get(prefix).map(|(_, nh, m)| (*nh, *m))
    }

    /// Every prefix with a selected route, as `(prefix, next_hop, metric)`, sorted
    /// by prefix — for the operational `show babel routes` view.
    pub fn selected_routes(&self) -> Vec<(Prefix, IpAddr, u16)> {
        self.selected
            .iter()
            .map(|(p, (_, nh, m))| (*p, *nh, *m))
            .collect()
    }

    /// The number of prefixes with a selected route.
    pub fn len(&self) -> usize {
        self.selected.len()
    }

    /// Whether no prefix has a selected route.
    pub fn is_empty(&self) -> bool {
        self.selected.is_empty()
    }

    /// Re-run selection for one prefix: pick the feasible, finite-metric route of
    /// smallest metric (ties broken deterministically by route key), update the
    /// source's feasibility distance, and emit a change versus what was selected.
    fn reselect(&mut self, prefix: Prefix) -> Option<BabelEvent> {
        let best = self
            .routes
            .iter()
            .filter(|(k, e)| k.prefix == prefix && e.feasible && e.metric() < METRIC_INFINITY)
            .min_by_key(|(k, e)| (e.metric(), **k))
            .map(|(k, e)| (*k, *e));

        match best {
            Some((key, entry)) => {
                let metric = entry.metric();
                self.sources
                    .update(prefix, key.router_id, entry.seqno, entry.advertised);
                let now = (key, entry.next_hop, metric);
                if self.selected.get(&prefix) == Some(&now) {
                    None // unchanged
                } else {
                    self.selected.insert(prefix, now);
                    Some(BabelEvent::Select {
                        prefix,
                        next_hop: entry.next_hop,
                        metric,
                    })
                }
            }
            None => self
                .selected
                .remove(&prefix)
                .map(|_| BabelEvent::Retract(prefix)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pfx(s: &str) -> Prefix {
        s.parse().unwrap()
    }
    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }
    const RID: [u8; 8] = [1, 1, 1, 1, 1, 1, 1, 1];

    #[test]
    fn seqno_comparison_wraps() {
        assert!(seqno_newer(5, 4));
        assert!(!seqno_newer(4, 5));
        assert!(!seqno_newer(4, 4));
        // Wraparound: 0 is newer than 65535.
        assert!(seqno_newer(0, 65535));
        assert!(!seqno_newer(65535, 0));
    }

    #[test]
    fn metric_addition_saturates() {
        assert_eq!(add_metric(100, 50), 150);
        assert_eq!(add_metric(METRIC_INFINITY, 1), METRIC_INFINITY);
        assert_eq!(add_metric(60000, 60000), METRIC_INFINITY);
    }

    #[test]
    fn first_route_is_selected_and_sets_feasibility_distance() {
        let mut t = RouteTable::new();
        let ev = t.update(pfx("10.0.0.0/8"), RID, ip("fe80::1"), ip("fe80::1"), 1, 100, 10);
        assert_eq!(
            ev,
            Some(BabelEvent::Select {
                prefix: pfx("10.0.0.0/8"),
                next_hop: ip("fe80::1"),
                metric: 110,
            })
        );
        assert_eq!(t.selected(&pfx("10.0.0.0/8")), Some((ip("fe80::1"), 110)));
    }

    #[test]
    fn worse_metric_same_seqno_is_infeasible() {
        let mut t = RouteTable::new();
        let dst = pfx("10.0.0.0/8");
        // Select advertised metric 100 → feasibility distance (1, 100).
        t.update(dst, RID, ip("fe80::1"), ip("fe80::1"), 1, 100, 0);
        // A second neighbour advertises the same source with a *higher* metric and
        // the same seqno: infeasible, so it is not selectable even if its computed
        // metric were lower.
        let ev = t.update(dst, RID, ip("fe80::2"), ip("fe80::2"), 1, 150, 0);
        assert_eq!(ev, None);
        // The original route stays selected.
        assert_eq!(t.selected(&dst), Some((ip("fe80::1"), 100)));
    }

    #[test]
    fn newer_seqno_is_feasible_even_with_higher_metric() {
        let mut t = RouteTable::new();
        let dst = pfx("10.0.0.0/8");
        t.update(dst, RID, ip("fe80::1"), ip("fe80::1"), 1, 100, 0);
        // The same route refreshed with a newer seqno but a *higher* metric is
        // still feasible (the seqno rule keeps it loop-free), so the selected route
        // tracks the new, higher metric rather than being retracted.
        let ev = t.update(dst, RID, ip("fe80::1"), ip("fe80::1"), 2, 150, 0);
        assert_eq!(
            ev,
            Some(BabelEvent::Select {
                prefix: dst,
                next_hop: ip("fe80::1"),
                metric: 150,
            })
        );
    }

    #[test]
    fn lower_metric_neighbour_wins_then_loss_falls_back() {
        let mut t = RouteTable::new();
        let dst = pfx("203.0.113.0/24");
        // Two feasible routes (different seqnos keep both feasible); the lower
        // computed metric wins.
        t.update(dst, RID, ip("fe80::1"), ip("fe80::1"), 1, 100, 50); // metric 150
        let ev = t.update(dst, RID, ip("fe80::2"), ip("fe80::2"), 2, 100, 10); // metric 110
        assert!(matches!(ev, Some(BabelEvent::Select { next_hop, .. }) if next_hop == ip("fe80::2")));

        // Losing the best neighbour falls back to the other.
        let evs = t.neighbour_lost(ip("fe80::2"));
        assert!(evs
            .iter()
            .any(|e| matches!(e, BabelEvent::Select { next_hop, .. } if *next_hop == ip("fe80::1"))));
    }

    #[test]
    fn retraction_withdraws_the_prefix() {
        let mut t = RouteTable::new();
        let dst = pfx("10.0.0.0/8");
        t.update(dst, RID, ip("fe80::1"), ip("fe80::1"), 1, 100, 0);
        // A retraction (infinite metric) from the only neighbour withdraws it.
        let ev = t.update(dst, RID, ip("fe80::1"), ip("fe80::1"), 1, METRIC_INFINITY, 0);
        assert_eq!(ev, Some(BabelEvent::Retract(dst)));
        assert!(t.is_empty());
    }

    #[test]
    fn re_announcing_the_same_route_is_a_no_op() {
        let mut t = RouteTable::new();
        let dst = pfx("10.0.0.0/8");
        assert!(t
            .update(dst, RID, ip("fe80::1"), ip("fe80::1"), 1, 100, 10)
            .is_some());
        assert!(t
            .update(dst, RID, ip("fe80::1"), ip("fe80::1"), 1, 100, 10)
            .is_none());
    }
}
