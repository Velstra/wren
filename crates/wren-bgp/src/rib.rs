//! The BGP routing information bases (RFC 4271 §3.2) and per-prefix path
//! selection.
//!
//! [`BgpRib`] keeps, for each destination, the path each peer offered (the
//! Adj-RIB-In) and selects the single best among them (the Loc-RIB) with the
//! [`crate::decision`] preference order. Mutating it returns a [`RibEvent`] when
//! a prefix's best path appears, changes or disappears — which the session runner
//! turns into RIB announcements/withdrawals and (after export policy) into the
//! Adj-RIB-Out it re-advertises.
//!
//! This is the pure data structure: peers and paths are plain values, so the
//! whole select-and-diff cycle is unit-testable without sockets.

use std::collections::BTreeMap;
use std::net::Ipv4Addr;

use wren_core::Prefix;

use crate::decision::{is_better, Path};

/// What changed in the Loc-RIB when a path was offered or withdrawn.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum RibEvent {
    /// `prefix`'s best path appeared or changed — install/replace it.
    Best {
        /// The destination.
        prefix: Prefix,
        /// Its new best path.
        path: Path,
    },
    /// `prefix` has no path left — withdraw it.
    Withdrawn(Prefix),
}

/// The BGP RIBs: the per-peer Adj-RIB-In and the selected Loc-RIB.
#[derive(Clone, Default)]
pub struct BgpRib {
    /// Adj-RIB-In: every peer's offered path per destination.
    entries: BTreeMap<Prefix, BTreeMap<Ipv4Addr, Path>>,
    /// Loc-RIB: the selected best path per destination (for change detection).
    best: BTreeMap<Prefix, Path>,
}

impl BgpRib {
    /// An empty RIB.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record (or replace) the path `peer` offers for `prefix`, re-select the
    /// best, and return the resulting change, if any.
    pub fn update(&mut self, peer: Ipv4Addr, prefix: Prefix, path: Path) -> Option<RibEvent> {
        self.entries.entry(prefix).or_default().insert(peer, path);
        self.reselect(prefix)
    }

    /// Withdraw the path `peer` offered for `prefix`, re-select the best, and
    /// return the resulting change, if any.
    pub fn withdraw(&mut self, peer: Ipv4Addr, prefix: Prefix) -> Option<RibEvent> {
        if let Some(peers) = self.entries.get_mut(&prefix) {
            peers.remove(&peer);
            if peers.is_empty() {
                self.entries.remove(&prefix);
            }
        }
        self.reselect(prefix)
    }

    /// Drop every path learned from `peer` (a session went down), returning the
    /// changes for each affected prefix.
    pub fn withdraw_peer(&mut self, peer: Ipv4Addr) -> Vec<RibEvent> {
        let affected: Vec<Prefix> = self
            .entries
            .iter()
            .filter(|(_, peers)| peers.contains_key(&peer))
            .map(|(p, _)| *p)
            .collect();
        let mut events = Vec::new();
        for prefix in affected {
            if let Some(peers) = self.entries.get_mut(&prefix) {
                peers.remove(&peer);
                if peers.is_empty() {
                    self.entries.remove(&prefix);
                }
            }
            if let Some(ev) = self.reselect(prefix) {
                events.push(ev);
            }
        }
        events
    }

    /// The current best path for `prefix`, if any.
    pub fn best(&self, prefix: &Prefix) -> Option<&Path> {
        self.best.get(prefix)
    }

    /// Iterate every prefix's best path, in prefix order.
    pub fn iter_best(&self) -> impl Iterator<Item = (&Prefix, &Path)> {
        self.best.iter()
    }

    /// Number of prefixes with a selected best path.
    pub fn len(&self) -> usize {
        self.best.len()
    }

    /// Whether the Loc-RIB holds no routes.
    pub fn is_empty(&self) -> bool {
        self.best.is_empty()
    }

    /// Re-run path selection for one prefix and emit the change vs. the previously
    /// selected best.
    fn reselect(&mut self, prefix: Prefix) -> Option<RibEvent> {
        let new_best = self
            .entries
            .get(&prefix)
            .and_then(|peers| select_best(peers.values()).cloned());
        match new_best {
            Some(path) => {
                if self.best.get(&prefix) == Some(&path) {
                    None // unchanged
                } else {
                    self.best.insert(prefix, path.clone());
                    Some(RibEvent::Best { prefix, path })
                }
            }
            None => self
                .best
                .remove(&prefix)
                .map(|_| RibEvent::Withdrawn(prefix)),
        }
    }
}

/// The best path among `paths` per the decision order, or `None` if empty.
fn select_best<'a>(paths: impl Iterator<Item = &'a Path>) -> Option<&'a Path> {
    let mut best: Option<&Path> = None;
    for p in paths {
        match best {
            Some(b) if !is_better(p, b) => {}
            _ => best = Some(p),
        }
    }
    best
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attr::{AsPathSegment, Origin};
    use crate::decision::DEFAULT_LOCAL_PREF;

    fn ip(o: [u8; 4]) -> Ipv4Addr {
        Ipv4Addr::from(o)
    }
    fn pfx(s: &str) -> Prefix {
        s.parse().unwrap()
    }

    fn path(local_pref: u32, peer: [u8; 4]) -> Path {
        Path {
            origin: Origin::Igp,
            as_path: vec![AsPathSegment::Sequence(vec![65001])],
            next_hop: std::net::IpAddr::V4(ip(peer)),
            local_pref,
            med: 0,
            from_ebgp: true,
            peer_as: 65001,
            igp_metric: 10,
            peer_id: ip(peer),
            peer_addr: ip(peer),
            communities: vec![],
            large_communities: vec![],
            ext_communities: vec![],
        }
    }

    #[test]
    fn first_path_is_selected_best() {
        let mut rib = BgpRib::new();
        let dst = pfx("10.0.0.0/8");
        let ev = rib.update(ip([10, 0, 0, 1]), dst, path(DEFAULT_LOCAL_PREF, [10, 0, 0, 1]));
        assert!(matches!(ev, Some(RibEvent::Best { prefix, .. }) if prefix == dst));
        assert!(rib.best(&dst).is_some());
        assert_eq!(rib.len(), 1);
    }

    #[test]
    fn better_path_supersedes_and_withdraw_falls_back() {
        let mut rib = BgpRib::new();
        let dst = pfx("203.0.113.0/24");
        let p1 = ip([10, 0, 0, 1]);
        let p2 = ip([10, 0, 0, 2]);

        rib.update(p1, dst, path(100, [10, 0, 0, 1]));
        // A higher-LOCAL_PREF path from another peer wins.
        let ev = rib.update(p2, dst, path(200, [10, 0, 0, 2]));
        assert!(matches!(ev, Some(RibEvent::Best { ref path, .. }) if path.peer_addr == p2));

        // A worse path from a third peer changes nothing.
        assert!(rib.update(ip([10, 0, 0, 3]), dst, path(50, [10, 0, 0, 3])).is_none());

        // Withdraw the winner → fall back to the next best (peer 1).
        let ev = rib.withdraw(p2, dst).unwrap();
        assert!(matches!(ev, RibEvent::Best { ref path, .. } if path.peer_addr == p1));
    }

    #[test]
    fn last_withdraw_removes_the_prefix() {
        let mut rib = BgpRib::new();
        let dst = pfx("10.0.0.0/8");
        let peer = ip([10, 0, 0, 1]);
        rib.update(peer, dst, path(100, [10, 0, 0, 1]));
        assert_eq!(rib.withdraw(peer, dst), Some(RibEvent::Withdrawn(dst)));
        assert!(rib.is_empty());
        // Withdrawing again is a no-op.
        assert_eq!(rib.withdraw(peer, dst), None);
    }

    #[test]
    fn re_announcing_the_same_path_is_a_no_op() {
        let mut rib = BgpRib::new();
        let dst = pfx("10.0.0.0/8");
        let peer = ip([10, 0, 0, 1]);
        assert!(rib.update(peer, dst, path(100, [10, 0, 0, 1])).is_some());
        assert!(rib.update(peer, dst, path(100, [10, 0, 0, 1])).is_none());
    }

    #[test]
    fn withdraw_peer_clears_all_its_prefixes() {
        let mut rib = BgpRib::new();
        let peer = ip([10, 0, 0, 1]);
        let other = ip([10, 0, 0, 2]);
        rib.update(peer, pfx("10.0.0.0/8"), path(200, [10, 0, 0, 1]));
        rib.update(peer, pfx("172.16.0.0/12"), path(200, [10, 0, 0, 1]));
        // A second prefix also held by `other` should fall back, not vanish.
        rib.update(other, pfx("172.16.0.0/12"), path(100, [10, 0, 0, 2]));

        let events = rib.withdraw_peer(peer);
        // 10.0.0.0/8 is withdrawn; 172.16.0.0/12 falls back to `other`.
        assert!(events.contains(&RibEvent::Withdrawn(pfx("10.0.0.0/8"))));
        assert!(events
            .iter()
            .any(|e| matches!(e, RibEvent::Best { prefix, path } if *prefix == pfx("172.16.0.0/12") && path.peer_addr == other)));
        assert_eq!(rib.len(), 1);
    }
}
