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
use std::net::IpAddr;

use wren_core::{NextHop, Prefix};

use crate::decision::{is_better, multipath_eligible, Path};

/// What changed in the Loc-RIB when a path was offered or withdrawn.
///
/// `Best` is much larger than `Withdrawn` (it carries the whole winning [`Path`]),
/// but a `RibEvent` is a transient by-value notification consumed immediately by the
/// runner — never stored in bulk — so the size disparity does not matter here.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum RibEvent {
    /// `prefix`'s best path appeared or changed — install/replace it.
    Best {
        /// The destination.
        prefix: Prefix,
        /// Its new best path (the winner whose attributes are re-advertised).
        path: Path,
        /// The equal-cost forwarding next hops to install for it. With multipath
        /// disabled this is just the winner's own next hop; with multipath enabled
        /// it also holds every equal-cost path's next hop (RFC 4271 §9.1.2.2 tie),
        /// capped at the configured maximum. See [`super::decision::multipath_eligible`].
        hops: Vec<NextHop>,
    },
    /// `prefix` has no path left — withdraw it.
    Withdrawn(Prefix),
}

/// The BGP RIBs: the per-peer Adj-RIB-In and the selected Loc-RIB.
#[derive(Clone)]
pub struct BgpRib {
    /// Adj-RIB-In: every offered path per destination, keyed by `(peer, path_id)`.
    /// Without ADD-PATH a peer offers one path per destination (`path_id` 0); with
    /// ADD-PATH (RFC 7911) it can offer several, each under a distinct received Path
    /// Identifier, and all of them coexist here as candidates for selection.
    entries: BTreeMap<Prefix, BTreeMap<(IpAddr, u32), Path>>,
    /// Loc-RIB: the selected best path per destination (for change detection).
    best: BTreeMap<Prefix, Path>,
    /// The equal-cost next-hop set last emitted per destination — tracked so a
    /// change in the multipath set (a second equal path appearing/leaving) is
    /// detected even when the winning best path itself is unchanged.
    hops: BTreeMap<Prefix, Vec<NextHop>>,
    /// The maximum number of equal-cost paths to install per destination (BGP
    /// multipath / ECMP). 1 means classic single-best-path selection.
    max_paths: usize,
}

impl Default for BgpRib {
    fn default() -> Self {
        Self::new()
    }
}

impl BgpRib {
    /// An empty RIB with single-best-path selection (no multipath).
    pub fn new() -> Self {
        Self {
            entries: BTreeMap::new(),
            best: BTreeMap::new(),
            hops: BTreeMap::new(),
            max_paths: 1,
        }
    }

    /// An empty RIB that installs up to `max_paths` equal-cost paths per
    /// destination as ECMP (BGP multipath). `max_paths` is clamped to at least 1.
    pub fn with_max_paths(max_paths: usize) -> Self {
        Self { max_paths: max_paths.max(1), ..Self::new() }
    }

    /// Record (or replace) the path `peer` offers for `prefix` (with no ADD-PATH
    /// Path Identifier), re-select the best, and return the resulting change.
    pub fn update(&mut self, peer: IpAddr, prefix: Prefix, path: Path) -> Option<RibEvent> {
        self.update_with_id(peer, 0, prefix, path)
    }

    /// Record (or replace) the path `peer` offers for `prefix` under the received
    /// ADD-PATH Path Identifier `path_id` (RFC 7911) — distinct ids from the same
    /// peer coexist as separate candidates — re-select the best, and return the
    /// resulting change.
    pub fn update_with_id(
        &mut self,
        peer: IpAddr,
        path_id: u32,
        prefix: Prefix,
        path: Path,
    ) -> Option<RibEvent> {
        self.entries.entry(prefix).or_default().insert((peer, path_id), path);
        self.reselect(prefix)
    }

    /// Withdraw the path `peer` offered for `prefix` (Path Identifier 0), re-select
    /// the best, and return the resulting change, if any.
    pub fn withdraw(&mut self, peer: IpAddr, prefix: Prefix) -> Option<RibEvent> {
        self.withdraw_with_id(peer, 0, prefix)
    }

    /// Withdraw the path `peer` offered for `prefix` under ADD-PATH Path Identifier
    /// `path_id` (RFC 7911), re-select the best, and return the resulting change.
    pub fn withdraw_with_id(
        &mut self,
        peer: IpAddr,
        path_id: u32,
        prefix: Prefix,
    ) -> Option<RibEvent> {
        if let Some(peers) = self.entries.get_mut(&prefix) {
            peers.remove(&(peer, path_id));
            if peers.is_empty() {
                self.entries.remove(&prefix);
            }
        }
        self.reselect(prefix)
    }

    /// Drop every path learned from `peer` (a session went down), returning the
    /// changes for each affected prefix.
    pub fn withdraw_peer(&mut self, peer: IpAddr) -> Vec<RibEvent> {
        let affected: Vec<Prefix> = self
            .entries
            .iter()
            .filter(|(_, peers)| peers.keys().any(|(p, _)| *p == peer))
            .map(|(p, _)| *p)
            .collect();
        let mut events = Vec::new();
        for prefix in affected {
            if let Some(peers) = self.entries.get_mut(&prefix) {
                peers.retain(|(p, _), _| *p != peer);
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

    /// Every destination for which `peer` currently offers a path (its Adj-RIB-In
    /// entries). Used by a graceful-restart helper to mark a peer's routes stale
    /// when its session drops, without removing them (RFC 4724).
    pub fn prefixes_from(&self, peer: IpAddr) -> Vec<Prefix> {
        self.entries
            .iter()
            .filter(|(_, peers)| peers.keys().any(|(p, _)| *p == peer))
            .map(|(p, _)| *p)
            .collect()
    }

    /// Every candidate path for `prefix` (the whole Adj-RIB-In set, not just the
    /// selected best), in deterministic `(peer, path_id)` order. The ADD-PATH send
    /// side advertises all of these — each under a Path Identifier it assigns — so a
    /// peer learns more than the single best path (RFC 7911).
    pub fn paths(&self, prefix: &Prefix) -> Vec<((IpAddr, u32), &Path)> {
        self.entries
            .get(prefix)
            .map(|peers| peers.iter().map(|(k, v)| (*k, v)).collect())
            .unwrap_or_default()
    }

    /// The current best path for `prefix`, if any.
    pub fn best(&self, prefix: &Prefix) -> Option<&Path> {
        self.best.get(prefix)
    }

    /// Every candidate path across the whole Adj-RIB-In, as
    /// `(prefix, peer, received-path-id, path)`, in `(prefix, peer, path-id)` order.
    /// With ADD-PATH (RFC 7911) a destination can have several — used by
    /// `show bgp paths` to list them.
    pub fn iter_paths(&self) -> impl Iterator<Item = (&Prefix, IpAddr, u32, &Path)> {
        self.entries
            .iter()
            .flat_map(|(pfx, peers)| peers.iter().map(move |(&(peer, id), path)| (pfx, peer, id, path)))
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
    /// selected best — including any change to the equal-cost multipath next-hop set.
    fn reselect(&mut self, prefix: Prefix) -> Option<RibEvent> {
        let selection = self.entries.get(&prefix).and_then(|peers| {
            let best = select_best(peers.values())?;
            // The winner's next hop always leads. With multipath enabled, append the
            // next hop of every other path that ties with it on the forwarding
            // attributes, in deterministic peer order, deduped and capped.
            let mut hops = vec![best.next_hop_entry()];
            if self.max_paths > 1 {
                for p in peers.values() {
                    if std::ptr::eq(p, best) || !multipath_eligible(best, p) {
                        continue;
                    }
                    let hop = p.next_hop_entry();
                    if !hops.contains(&hop) {
                        hops.push(hop);
                    }
                    if hops.len() >= self.max_paths {
                        break;
                    }
                }
            }
            Some((best.clone(), hops))
        });
        match selection {
            Some((path, hops)) => {
                if self.best.get(&prefix) == Some(&path) && self.hops.get(&prefix) == Some(&hops) {
                    None // best path and its multipath set both unchanged
                } else {
                    self.best.insert(prefix, path.clone());
                    self.hops.insert(prefix, hops.clone());
                    Some(RibEvent::Best { prefix, path, hops })
                }
            }
            None => {
                self.hops.remove(&prefix);
                self.best.remove(&prefix).map(|_| RibEvent::Withdrawn(prefix))
            }
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
    use std::net::Ipv4Addr;

    /// A transport peer address (IPv4, but typed as `IpAddr` for the RIB keys).
    fn ip(o: [u8; 4]) -> IpAddr {
        IpAddr::V4(Ipv4Addr::from(o))
    }
    /// A 32-bit BGP identifier (router id).
    fn id(o: [u8; 4]) -> Ipv4Addr {
        Ipv4Addr::from(o)
    }
    fn pfx(s: &str) -> Prefix {
        s.parse().unwrap()
    }

    fn path(local_pref: u32, peer: [u8; 4]) -> Path {
        Path {
            origin: Origin::Igp,
            as_path: vec![AsPathSegment::Sequence(vec![65001])],
            next_hop: ip(peer),
            next_hop_iface: None,
            local_pref,
            med: 0,
            from_ebgp: true,
            from_confed: false,
            peer_as: 65001,
            igp_metric: 10,
            peer_id: id(peer),
            peer_addr: ip(peer),
            from_client: false,
            originator_id: None,
            cluster_list: vec![],
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
    fn prefixes_from_lists_a_peers_destinations() {
        let mut rib = BgpRib::new();
        let peer = ip([10, 0, 0, 1]);
        let other = ip([10, 0, 0, 2]);
        rib.update(peer, pfx("10.0.0.0/8"), path(100, [10, 0, 0, 1]));
        rib.update(peer, pfx("172.16.0.0/12"), path(100, [10, 0, 0, 1]));
        rib.update(other, pfx("192.168.0.0/16"), path(100, [10, 0, 0, 2]));
        let mut from_peer = rib.prefixes_from(peer);
        from_peer.sort();
        assert_eq!(from_peer, vec![pfx("10.0.0.0/8"), pfx("172.16.0.0/12")]);
        assert_eq!(rib.prefixes_from(other), vec![pfx("192.168.0.0/16")]);
        assert!(rib.prefixes_from(ip([9, 9, 9, 9])).is_empty());
    }

    fn hop(o: [u8; 4]) -> NextHop {
        NextHop::via(ip(o))
    }

    #[test]
    fn multipath_installs_equal_cost_next_hops() {
        let mut rib = BgpRib::with_max_paths(2);
        let dst = pfx("10.99.0.0/24");
        let p1 = ip([10, 0, 0, 1]);
        let p2 = ip([10, 1, 0, 1]);

        // The first path installs a single next hop.
        let ev = rib.update(p1, dst, path(100, [10, 0, 0, 1])).unwrap();
        assert!(matches!(ev, RibEvent::Best { ref hops, .. } if hops.len() == 1));

        // A second equal-cost path widens the installed set to two next hops — a
        // fresh Best even though the winning path is unchanged by the decision.
        let ev = rib.update(p2, dst, path(100, [10, 1, 0, 1])).unwrap();
        match ev {
            RibEvent::Best { hops, .. } => {
                assert_eq!(hops.len(), 2);
                assert!(hops.contains(&hop([10, 0, 0, 1])));
                assert!(hops.contains(&hop([10, 1, 0, 1])));
            }
            _ => panic!("expected Best"),
        }

        // Withdrawing one path narrows back to a single next hop (still a change).
        let ev = rib.withdraw(p2, dst).unwrap();
        assert!(matches!(ev, RibEvent::Best { ref hops, .. } if hops.len() == 1));
    }

    #[test]
    fn multipath_is_off_by_default() {
        let mut rib = BgpRib::new();
        let dst = pfx("10.99.0.0/24");
        let ev = rib.update(ip([10, 0, 0, 1]), dst, path(100, [10, 0, 0, 1])).unwrap();
        assert!(matches!(ev, RibEvent::Best { ref hops, .. } if hops.len() == 1));
        // A second equal-cost path changes nothing without multipath.
        assert!(rib.update(ip([10, 1, 0, 1]), dst, path(100, [10, 1, 0, 1])).is_none());
    }

    #[test]
    fn multipath_caps_at_max_paths() {
        let mut rib = BgpRib::with_max_paths(2);
        let dst = pfx("10.99.0.0/24");
        rib.update(ip([10, 0, 0, 1]), dst, path(100, [10, 0, 0, 1]));
        rib.update(ip([10, 1, 0, 1]), dst, path(100, [10, 1, 0, 1]));
        // A third equal path exceeds the cap of 2 → the installed set is unchanged.
        assert!(rib.update(ip([10, 2, 0, 1]), dst, path(100, [10, 2, 0, 1])).is_none());
        assert_eq!(rib.hops.get(&dst).map(|h| h.len()), Some(2));
    }

    #[test]
    fn add_path_keeps_two_paths_from_one_peer() {
        // RFC 7911: with ADD-PATH a single peer can offer several paths for the same
        // destination under distinct Path Identifiers; both must coexist as
        // candidates rather than the second overwriting the first.
        let mut rib = BgpRib::new();
        let dst = pfx("10.50.0.0/24");
        let peer = ip([10, 0, 0, 1]);
        rib.update_with_id(peer, 1, dst, path(100, [10, 0, 0, 1]));
        rib.update_with_id(peer, 2, dst, path(200, [10, 0, 0, 2]));
        // Both paths are retained (id 1 and id 2), not collapsed to one.
        assert_eq!(rib.paths(&dst).len(), 2);
        // The higher-LOCAL_PREF path (id 2) is selected best.
        assert_eq!(rib.best(&dst).unwrap().local_pref, 200);
        // Withdrawing id 2 falls back to id 1 — the other path is still there.
        let ev = rib.withdraw_with_id(peer, 2, dst).unwrap();
        assert!(matches!(ev, RibEvent::Best { ref path, .. } if path.local_pref == 100));
        assert_eq!(rib.paths(&dst).len(), 1);
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
            .any(|e| matches!(e, RibEvent::Best { prefix, path, .. } if *prefix == pfx("172.16.0.0/12") && path.peer_addr == other)));
        assert_eq!(rib.len(), 1);
    }
}
