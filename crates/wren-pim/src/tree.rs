//! # The PIM-SM Tree Information Base (RFC 7761 §4.1, §4.5, §4.6)
//!
//! The forwarding state a sparse-mode router keeps: the shared tree `(*,G)` rooted
//! at the Rendezvous Point and the per-source tree `(S,G)`. Each entry has an
//! **incoming interface** (the RPF interface toward the RP or the source) and a set
//! of **outgoing interfaces** (the OIF list — where the group's traffic is
//! replicated). This module is that database and its transitions; it is pure, so it
//! is driven entirely by four inputs and produces two outputs:
//!
//! **Inputs**
//! * local IGMP/MLD membership ([`TreeTable::on_membership`]) — a receiver on a
//!   downstream interface wants group `G` (a `(*,G)` shared-tree join) or a specific
//!   source `(S,G)` (an IGMPv3 source-specific / SSM-style join);
//! * a Join/Prune received from a downstream PIM neighbour
//!   ([`TreeTable::on_received_join`] / [`TreeTable::on_received_prune`]) — that
//!   neighbour adds/removes the interface it arrived on to/from the OIF list;
//! * the passage of time ([`TreeTable::expire`]) — a downstream Join/Prune carries a
//!   Holdtime; an OIF learned from a neighbour that is not refreshed within it is
//!   pruned;
//! * the RPF resolver ([`RpfLookup`]) — supplied by the caller (the runner reads the
//!   unicast route table); it maps the RP or a source to the interface and next-hop
//!   neighbour to reach it.
//!
//! **Outputs**
//! * the upstream Join/Prune the router must send ([`JoinPruneAction`]) — emitted when
//!   an entry gains its first OIF (Join toward the RP/source) or loses its last
//!   (Prune). If the RP/source is *local* (we are the RP, or the source is us) no
//!   upstream action is emitted — the tree terminates here;
//! * the forwarding OIF list for a data packet ([`TreeTable::oifs_for`]) — the union
//!   of the `(S,G)` and `(*,G)` OIF lists, which the runner programs into the kernel
//!   multicast forwarding cache when the first packet of an `(S,G)` flow arrives.
//!
//! ## Modelled
//!
//! The IPTV cases that matter: a `(*,G)` shared tree built from ASM membership /
//! received wildcard Joins, and an `(S,G)` source tree built from SSM membership /
//! received `(S,G)` Joins. The RPF interface is never itself an OIF (split horizon).
//!
//! ## Deferred (documented)
//!
//! ASM **SPT switchover** by data-rate threshold (§4.2.1) — an ASM `(*,G)` receiver
//! stays on the shared tree here; source-specific `(S,G)` trees are built only from
//! an explicit SSM membership or a received `(S,G)` Join, not by auto-switchover.
//! The Assert election (§4.6) and the full downstream/upstream per-interface Join/
//! Prune state machines (§4.5.2/§4.5.3) beyond OIF add/remove are not modelled.

use std::collections::{BTreeMap, BTreeSet};
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

/// The RPF resolution the caller supplies: given a destination (the RP for a `(*,G)`
/// entry, or a source `S` for an `(S,G)` entry), return the interface and next-hop to
/// reach it, or `None` if the destination is *local* (we are the RP / the source is a
/// directly-connected first hop is signalled by a `neighbor` of `None`, see below).
pub trait RpfLookup {
    /// Resolve the RPF toward `dest`. `None` means `dest` is one of *our* addresses
    /// (we are the RP, or the source is local) — the tree terminates here and no
    /// upstream Join/Prune is sent.
    fn rpf(&self, dest: Ipv4Addr) -> Option<RpfInfo>;
}

/// The RPF toward a destination: which interface to reach it on and the next-hop.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RpfInfo {
    /// The RPF interface index (the incoming interface of the entry, never an OIF).
    pub ifindex: u32,
    /// The next-hop PIM neighbour toward the destination. `None` when the destination
    /// is directly connected — then the destination address itself is the upstream.
    pub neighbor: Option<Ipv4Addr>,
}

/// Whether an entry is a shared `(*,G)` tree or a source `(S,G)` tree.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TreeKind {
    /// The shared tree `(*,G)`, joined toward the RP.
    SharedStarG,
    /// A source tree `(S,G)`, joined toward the source.
    SourceSG,
}

/// An upstream Join or Prune the router must send as a result of a TIB transition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JoinPruneAction {
    /// `true` for a Join (first OIF appeared), `false` for a Prune (last OIF gone).
    pub join: bool,
    /// Whether this is a shared `(*,G)` or source `(S,G)` action.
    pub kind: TreeKind,
    /// The group.
    pub group: Ipv4Addr,
    /// The RP (for `SharedStarG`) or the source `S` (for `SourceSG`) — the address
    /// that goes in the encoded-source entry of the Join/Prune.
    pub target: Ipv4Addr,
    /// The RPF interface to send the Join/Prune out of.
    pub rpf_ifindex: u32,
    /// The upstream neighbour the Join/Prune is addressed to (its "Upstream Neighbor"
    /// field). The RPF next-hop, or the target itself when directly connected.
    pub upstream_neighbor: Ipv4Addr,
}

/// A read-only view of one TIB entry, for `show pim mroute`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MrouteEntry {
    /// `None` for a `(*,G)` shared-tree entry, `Some(S)` for a source tree.
    pub source: Option<Ipv4Addr>,
    /// The group.
    pub group: Ipv4Addr,
    /// The RPF interface (incoming interface), if the target is not local.
    pub iif: Option<u32>,
    /// The upstream neighbour we joined toward, if any.
    pub upstream_neighbor: Option<Ipv4Addr>,
    /// The outgoing interface list, in index order.
    pub oifs: Vec<u32>,
    /// Whether we currently hold an upstream Join for this entry.
    pub upstream_joined: bool,
}

/// One `(*,G)` or `(S,G)` entry's mutable state.
#[derive(Debug, Clone)]
struct Entry {
    /// OIFs contributed by *local* IGMP/MLD membership (aged by the IGMP layer, which
    /// calls `on_membership(present=false)` on leave — not time-expired here).
    local_oifs: BTreeSet<u32>,
    /// OIFs contributed by a *received* downstream Join, each with the deadline its
    /// Join Holdtime implies. Refreshed by the next Join, pruned by `expire`.
    join_oifs: BTreeMap<u32, Instant>,
    /// The RPF interface toward the target (RP or S), recomputed on each transition.
    /// `None` when the target is local (we are the RP / the source is us).
    iif: Option<u32>,
    /// The upstream neighbour we last resolved, for `show`.
    upstream_neighbor: Option<Ipv4Addr>,
    /// Whether we currently hold an upstream Join (the OIF list is non-empty and the
    /// target is not local).
    upstream_joined: bool,
}

impl Entry {
    fn new() -> Self {
        Entry {
            local_oifs: BTreeSet::new(),
            join_oifs: BTreeMap::new(),
            iif: None,
            upstream_neighbor: None,
            upstream_joined: false,
        }
    }

    /// The full OIF set (local ∪ join-learned), excluding the RPF interface.
    fn oifs(&self) -> BTreeSet<u32> {
        let mut oifs: BTreeSet<u32> = self.local_oifs.iter().copied().collect();
        oifs.extend(self.join_oifs.keys().copied());
        if let Some(iif) = self.iif {
            oifs.remove(&iif);
        }
        oifs
    }

    fn is_empty(&self) -> bool {
        self.local_oifs.is_empty() && self.join_oifs.is_empty()
    }
}

/// The Tree Information Base: the `(*,G)` and `(S,G)` entries, keyed by
/// `(Option<source>, group)`.
#[derive(Debug, Clone)]
pub struct TreeTable {
    /// The statically configured Rendezvous Point address (static-RP subset).
    rp: Ipv4Addr,
    /// The Join/Prune Holdtime applied to a received downstream Join.
    join_holdtime: Duration,
    entries: BTreeMap<(Option<Ipv4Addr>, Ipv4Addr), Entry>,
}

impl TreeTable {
    /// A fresh TIB with the given static RP and downstream-Join Holdtime.
    pub fn new(rp: Ipv4Addr, join_holdtime: Duration) -> Self {
        TreeTable {
            rp,
            join_holdtime,
            entries: BTreeMap::new(),
        }
    }

    /// The configured RP address.
    pub fn rp(&self) -> Ipv4Addr {
        self.rp
    }

    /// The number of TIB entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the TIB is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Apply a local membership change on `ifindex`: a receiver joined (`present`) or
    /// left group `G`. `source` is `None` for an ASM `(*,G)` join (build the shared
    /// tree toward the RP) or `Some(S)` for an IGMPv3 source-specific `(S,G)` join
    /// (build the source tree toward `S`). Returns any upstream Join/Prune the change
    /// triggers.
    pub fn on_membership<R: RpfLookup>(
        &mut self,
        ifindex: u32,
        group: Ipv4Addr,
        source: Option<Ipv4Addr>,
        present: bool,
        rpf: &R,
    ) -> Vec<JoinPruneAction> {
        let key = (source, group);
        if present {
            self.ensure_entry(key, rpf);
            if let Some(e) = self.entries.get_mut(&key) {
                e.local_oifs.insert(ifindex);
            }
        } else if let Some(e) = self.entries.get_mut(&key) {
            e.local_oifs.remove(&ifindex);
        }
        self.reconcile(key, rpf)
    }

    /// Apply a received downstream Join for `(source, group)` that arrived on
    /// `recv_ifindex` at `now` (its Holdtime starts the OIF timer). `source` is `None`
    /// for a wildcard `(*,G)` Join. Returns any upstream Join the change triggers.
    pub fn on_received_join<R: RpfLookup>(
        &mut self,
        now: Instant,
        recv_ifindex: u32,
        group: Ipv4Addr,
        source: Option<Ipv4Addr>,
        rpf: &R,
    ) -> Vec<JoinPruneAction> {
        let key = (source, group);
        self.ensure_entry(key, rpf);
        // Never add the RPF (incoming) interface as an OIF — split horizon.
        if let Some(e) = self.entries.get_mut(&key) {
            if e.iif != Some(recv_ifindex) {
                e.join_oifs.insert(recv_ifindex, now + self.join_holdtime);
            }
        }
        self.reconcile(key, rpf)
    }

    /// Apply a received downstream Prune for `(source, group)` on `recv_ifindex`:
    /// remove that interface from the join-learned OIF list. Returns any upstream
    /// Prune the change triggers (if this emptied the entry).
    pub fn on_received_prune<R: RpfLookup>(
        &mut self,
        recv_ifindex: u32,
        group: Ipv4Addr,
        source: Option<Ipv4Addr>,
        rpf: &R,
    ) -> Vec<JoinPruneAction> {
        let key = (source, group);
        if let Some(e) = self.entries.get_mut(&key) {
            e.join_oifs.remove(&recv_ifindex);
        }
        self.reconcile(key, rpf)
    }

    /// Age out join-learned OIFs whose Holdtime elapsed by `now`, emitting an upstream
    /// Prune for any entry that empties as a result.
    pub fn expire<R: RpfLookup>(&mut self, now: Instant, rpf: &R) -> Vec<JoinPruneAction> {
        let keys: Vec<_> = self.entries.keys().copied().collect();
        let mut actions = Vec::new();
        for key in keys {
            if let Some(e) = self.entries.get_mut(&key) {
                e.join_oifs.retain(|_, &mut deadline| deadline > now);
            }
            actions.extend(self.reconcile(key, rpf));
        }
        actions
    }

    /// Re-emit the upstream Join for every currently-joined entry — the periodic
    /// refresh (§4.11 `t_periodic`) and the response to a neighbour restart. Only
    /// entries that still have an OIF and a non-local RPF produce an action.
    pub fn refresh_joins<R: RpfLookup>(&mut self, rpf: &R) -> Vec<JoinPruneAction> {
        let keys: Vec<_> = self.entries.keys().copied().collect();
        let mut actions = Vec::new();
        for (source, group) in keys {
            let target = source.unwrap_or(self.rp);
            let kind = if source.is_some() {
                TreeKind::SourceSG
            } else {
                TreeKind::SharedStarG
            };
            let has_oif = self
                .entries
                .get(&(source, group))
                .map(|e| !e.oifs().is_empty())
                .unwrap_or(false);
            if !has_oif {
                continue;
            }
            if let Some(info) = rpf.rpf(target) {
                actions.push(JoinPruneAction {
                    join: true,
                    kind,
                    group,
                    target,
                    rpf_ifindex: info.ifindex,
                    upstream_neighbor: info.neighbor.unwrap_or(target),
                });
            }
        }
        actions
    }

    /// The OIF list to forward an `(S,G)` data packet on: the union of the `(S,G)`
    /// entry's OIFs and the `(*,G)` shared-tree entry's OIFs. `None` if neither entry
    /// exists (nothing wants the group — the packet is not forwarded). The returned
    /// set never contains `arrived_on` (never reflect a packet back where it came).
    pub fn oifs_for(
        &self,
        source: Ipv4Addr,
        group: Ipv4Addr,
        arrived_on: u32,
    ) -> Option<BTreeSet<u32>> {
        let sg = self.entries.get(&(Some(source), group));
        let star = self.entries.get(&(None, group));
        if sg.is_none() && star.is_none() {
            return None;
        }
        let mut oifs = BTreeSet::new();
        if let Some(e) = sg {
            oifs.extend(e.oifs());
        }
        if let Some(e) = star {
            oifs.extend(e.oifs());
        }
        oifs.remove(&arrived_on);
        Some(oifs)
    }

    /// Whether the group is known to the TIB at all (has a `(*,G)` or any `(S,G)`
    /// entry) — used by the runner to decide whether an arriving flow is wanted.
    pub fn wants_group(&self, group: Ipv4Addr) -> bool {
        self.entries.keys().any(|(_, g)| *g == group)
    }

    /// A snapshot of the TIB for `show pim mroute`, in `(source, group)` order.
    pub fn entries(&self) -> Vec<MrouteEntry> {
        self.entries
            .iter()
            .map(|((source, group), e)| MrouteEntry {
                source: *source,
                group: *group,
                iif: e.iif,
                upstream_neighbor: e.upstream_neighbor,
                oifs: e.oifs().into_iter().collect(),
                upstream_joined: e.upstream_joined,
            })
            .collect()
    }

    /// Create the entry for `key` if absent, resolving its RPF interface.
    fn ensure_entry<R: RpfLookup>(&mut self, key: (Option<Ipv4Addr>, Ipv4Addr), rpf: &R) {
        if self.entries.contains_key(&key) {
            return;
        }
        let target = key.0.unwrap_or(self.rp);
        let info = rpf.rpf(target);
        let mut e = Entry::new();
        e.iif = info.as_ref().map(|i| i.ifindex);
        e.upstream_neighbor = info.and_then(|i| i.neighbor);
        self.entries.insert(key, e);
    }

    /// Recompute an entry's upstream state after an OIF change and emit the Join or
    /// Prune (if any) the transition implies. Removes an entry that has become empty.
    fn reconcile<R: RpfLookup>(
        &mut self,
        key: (Option<Ipv4Addr>, Ipv4Addr),
        rpf: &R,
    ) -> Vec<JoinPruneAction> {
        let (source, group) = key;
        let target = source.unwrap_or(self.rp);
        let kind = if source.is_some() {
            TreeKind::SourceSG
        } else {
            TreeKind::SharedStarG
        };
        let Some(e) = self.entries.get_mut(&key) else {
            return Vec::new();
        };

        // Refresh the RPF each time (the route may have changed) and drop the RPF
        // interface from the join-learned OIFs if it is now the incoming interface.
        let info = rpf.rpf(target);
        e.iif = info.as_ref().map(|i| i.ifindex);
        e.upstream_neighbor = info.as_ref().and_then(|i| i.neighbor);
        if let Some(iif) = e.iif {
            e.join_oifs.remove(&iif);
            e.local_oifs.remove(&iif);
        }

        let want_join = !e.oifs().is_empty();
        let empty = e.is_empty();
        let was_joined = e.upstream_joined;

        let mut actions = Vec::new();
        // An upstream action is only meaningful when the target is not local.
        if let Some(info) = info {
            let upstream_neighbor = info.neighbor.unwrap_or(target);
            if want_join && !was_joined {
                e.upstream_joined = true;
                actions.push(JoinPruneAction {
                    join: true,
                    kind,
                    group,
                    target,
                    rpf_ifindex: info.ifindex,
                    upstream_neighbor,
                });
            } else if !want_join && was_joined {
                e.upstream_joined = false;
                actions.push(JoinPruneAction {
                    join: false,
                    kind,
                    group,
                    target,
                    rpf_ifindex: info.ifindex,
                    upstream_neighbor,
                });
            }
        } else {
            // Local target (we are the RP / the source is us): never hold an upstream.
            e.upstream_joined = false;
        }

        if empty {
            self.entries.remove(&key);
        }
        actions
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> Ipv4Addr {
        s.parse().unwrap()
    }

    /// A mock RPF resolver: a map of destination → (ifindex, next-hop). A destination
    /// absent from the map is *local* (returns `None`).
    struct MockRpf {
        routes: BTreeMap<Ipv4Addr, RpfInfo>,
    }

    impl MockRpf {
        fn new() -> Self {
            MockRpf {
                routes: BTreeMap::new(),
            }
        }
        fn via(mut self, dest: &str, ifindex: u32, nbr: Option<&str>) -> Self {
            self.routes.insert(
                ip(dest),
                RpfInfo {
                    ifindex,
                    neighbor: nbr.map(ip),
                },
            );
            self
        }
    }

    impl RpfLookup for MockRpf {
        fn rpf(&self, dest: Ipv4Addr) -> Option<RpfInfo> {
            self.routes.get(&dest).cloned()
        }
    }

    fn table(rp: &str) -> TreeTable {
        TreeTable::new(ip(rp), Duration::from_secs(210))
    }

    #[test]
    fn membership_builds_shared_tree_and_joins_rp() {
        // RP reachable via ifindex 2, next-hop 10.0.2.1.
        let rpf = MockRpf::new().via("10.0.9.9", 2, Some("10.0.2.1"));
        let mut t = table("10.0.9.9");
        // A receiver on ifindex 5 joins 239.1.1.1 (ASM → (*,G)).
        let actions = t.on_membership(5, ip("239.1.1.1"), None, true, &rpf);
        assert_eq!(actions.len(), 1);
        let a = &actions[0];
        assert!(a.join);
        assert_eq!(a.kind, TreeKind::SharedStarG);
        assert_eq!(a.target, ip("10.0.9.9")); // the RP
        assert_eq!(a.rpf_ifindex, 2);
        assert_eq!(a.upstream_neighbor, ip("10.0.2.1"));
        // The forwarding OIF list contains the receiver interface, not the RPF iface.
        let oifs = t.oifs_for(ip("198.51.100.1"), ip("239.1.1.1"), 2).unwrap();
        assert!(oifs.contains(&5));
        assert!(!oifs.contains(&2));
    }

    #[test]
    fn last_member_leaving_prunes_toward_rp() {
        let rpf = MockRpf::new().via("10.0.9.9", 2, Some("10.0.2.1"));
        let mut t = table("10.0.9.9");
        t.on_membership(5, ip("239.1.1.1"), None, true, &rpf);
        // The only receiver leaves: prune toward the RP, entry removed.
        let actions = t.on_membership(5, ip("239.1.1.1"), None, false, &rpf);
        assert_eq!(actions.len(), 1);
        assert!(!actions[0].join);
        assert_eq!(actions[0].kind, TreeKind::SharedStarG);
        assert!(t.is_empty());
    }

    #[test]
    fn rp_is_local_so_no_upstream_join() {
        // At the RP itself the RP address is local → RPF returns None.
        let rpf = MockRpf::new(); // empty = everything local
        let mut t = table("10.0.9.9");
        let actions = t.on_membership(5, ip("239.1.1.1"), None, true, &rpf);
        // No upstream Join (we are the RP), but the entry + OIF still exists for
        // forwarding.
        assert!(actions.is_empty());
        let oifs = t.oifs_for(ip("198.51.100.1"), ip("239.1.1.1"), 2).unwrap();
        assert!(oifs.contains(&5));
    }

    #[test]
    fn received_wildcard_join_adds_oif_and_joins_rp() {
        // A downstream router sends Join(*,G) on ifindex 3; RP is upstream on 2.
        let rpf = MockRpf::new().via("10.0.9.9", 2, Some("10.0.2.1"));
        let mut t = table("10.0.9.9");
        let now = Instant::now();
        let actions = t.on_received_join(now, 3, ip("239.1.1.1"), None, &rpf);
        assert_eq!(actions.len(), 1);
        assert!(actions[0].join);
        let oifs = t.oifs_for(ip("198.51.100.1"), ip("239.1.1.1"), 2).unwrap();
        assert!(oifs.contains(&3));
    }

    #[test]
    fn join_on_rpf_interface_is_not_an_oif() {
        // Split horizon: a Join arriving on the RPF interface (2) must not become an
        // OIF (would reflect traffic back toward the RP).
        let rpf = MockRpf::new().via("10.0.9.9", 2, Some("10.0.2.1"));
        let mut t = table("10.0.9.9");
        let now = Instant::now();
        let actions = t.on_received_join(now, 2, ip("239.1.1.1"), None, &rpf);
        // No OIF ⇒ no upstream Join, and the entry is dropped as empty.
        assert!(actions.is_empty());
        assert!(t.is_empty());
    }

    #[test]
    fn ssm_membership_builds_source_tree() {
        // An IGMPv3 INCLUDE(S,G) membership joins the source tree toward S directly.
        let rpf = MockRpf::new().via("10.1.1.1", 4, Some("10.0.2.1"));
        let mut t = table("10.0.9.9");
        let actions = t.on_membership(5, ip("232.1.1.1"), Some(ip("10.1.1.1")), true, &rpf);
        assert_eq!(actions.len(), 1);
        assert!(actions[0].join);
        assert_eq!(actions[0].kind, TreeKind::SourceSG);
        assert_eq!(actions[0].target, ip("10.1.1.1")); // the source
        assert_eq!(actions[0].rpf_ifindex, 4);
    }

    #[test]
    fn sg_and_star_g_oifs_union_for_forwarding() {
        let rpf = MockRpf::new()
            .via("10.0.9.9", 2, Some("10.0.2.1"))
            .via("10.1.1.1", 2, Some("10.0.2.1"));
        let mut t = table("10.0.9.9");
        // A (*,G) receiver on 5 and an (S,G) receiver on 6.
        t.on_membership(5, ip("239.1.1.1"), None, true, &rpf);
        t.on_membership(6, ip("239.1.1.1"), Some(ip("10.1.1.1")), true, &rpf);
        let oifs = t.oifs_for(ip("10.1.1.1"), ip("239.1.1.1"), 2).unwrap();
        assert!(oifs.contains(&5)); // from (*,G)
        assert!(oifs.contains(&6)); // from (S,G)
    }

    #[test]
    fn second_receiver_does_not_rejoin() {
        let rpf = MockRpf::new().via("10.0.9.9", 2, Some("10.0.2.1"));
        let mut t = table("10.0.9.9");
        assert_eq!(t.on_membership(5, ip("239.1.1.1"), None, true, &rpf).len(), 1);
        // A second receiver for the same group: OIF grows, but no new upstream Join.
        assert!(t.on_membership(6, ip("239.1.1.1"), None, true, &rpf).is_empty());
        // The first leaving still leaves one OIF ⇒ no prune yet.
        assert!(t.on_membership(5, ip("239.1.1.1"), None, false, &rpf).is_empty());
        // The last leaving prunes.
        assert_eq!(
            t.on_membership(6, ip("239.1.1.1"), None, false, &rpf).len(),
            1
        );
    }

    #[test]
    fn received_join_expires_and_prunes() {
        let rpf = MockRpf::new().via("10.0.9.9", 2, Some("10.0.2.1"));
        let mut t = table("10.0.9.9");
        let now = Instant::now();
        t.on_received_join(now, 3, ip("239.1.1.1"), None, &rpf);
        // Before the 210 s Holdtime: still present.
        assert!(t.expire(now + Duration::from_secs(209), &rpf).is_empty());
        assert!(!t.is_empty());
        // After it: the OIF ages out and the entry prunes upstream.
        let actions = t.expire(now + Duration::from_secs(210), &rpf);
        assert_eq!(actions.len(), 1);
        assert!(!actions[0].join);
        assert!(t.is_empty());
    }

    #[test]
    fn refresh_join_replays_active_entries() {
        let rpf = MockRpf::new().via("10.0.9.9", 2, Some("10.0.2.1"));
        let mut t = table("10.0.9.9");
        t.on_membership(5, ip("239.1.1.1"), None, true, &rpf);
        let refresh = t.refresh_joins(&rpf);
        assert_eq!(refresh.len(), 1);
        assert!(refresh[0].join);
        assert_eq!(refresh[0].group, ip("239.1.1.1"));
    }

    #[test]
    fn unknown_group_has_no_forwarding() {
        let t = table("10.0.9.9");
        assert!(t.oifs_for(ip("10.1.1.1"), ip("239.9.9.9"), 2).is_none());
        assert!(!t.wants_group(ip("239.9.9.9")));
    }

    #[test]
    fn mroute_snapshot_reports_entries() {
        let rpf = MockRpf::new().via("10.0.9.9", 2, Some("10.0.2.1"));
        let mut t = table("10.0.9.9");
        t.on_membership(5, ip("239.1.1.1"), None, true, &rpf);
        let entries = t.entries();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].source, None);
        assert_eq!(entries[0].group, ip("239.1.1.1"));
        assert_eq!(entries[0].iif, Some(2));
        assert_eq!(entries[0].oifs, vec![5]);
        assert!(entries[0].upstream_joined);
    }
}
