//! # IGMP/multicast proxy aggregation (RFC 4605)
//!
//! The firewall case: one *upstream* interface faces the network the multicast
//! streams come from (the ISP / IPTV head-end), and one or more *downstream*
//! interfaces face the LANs whose hosts join groups. The proxy's job (RFC 4605
//! §3.2) is to merge the membership databases of all downstream interfaces and act
//! as a *host* on the upstream: join a group upstream as soon as **any** downstream
//! has a member, and leave it upstream when the **last** downstream member goes.
//!
//! This module is the pure aggregation logic:
//!
//! * [`IgmpProxy::sync_downstream`] is called whenever a downstream interface's
//!   membership changes (the runner passes the fresh set of groups wanted on that
//!   interface). It returns the [`ProxyAction`]s the runner must carry out
//!   upstream — send an unsolicited report (join) or a leave;
//! * [`IgmpProxy::forwarding`] returns the multicast-forwarding-cache picture:
//!   for each active group, the list of downstream interfaces (oifs) that want it.
//!   This is the input to the kernel MFC.
//!
//! ## The kernel FIB hook
//!
//! Programming the forwarding itself (so packets are actually replicated
//! downstream) is the runner's job and is a documented hook, not done here: on
//! Linux it is a routing socket with `MRT_INIT` + `MRT_ADD_VIF` per interface +
//! `MRT_ADD_MFC` per [`ForwardingEntry`] (iif = the upstream vif, oifs = the
//! entry's downstream vifs). We compute the *what*; the runner applies the *how*.
//! Until that is wired, the proxy still drives correct upstream joins/leaves so the
//! stream is at least pulled to the router.

use std::collections::{BTreeMap, BTreeSet};
use std::net::{Ipv4Addr, Ipv6Addr};

/// A group address the proxy can aggregate — IPv4 (IGMP) or IPv6 (MLD). The proxy
/// logic is pure set arithmetic, so it needs only ordering and copy.
pub trait GroupAddr: Copy + Ord + Eq {}
impl GroupAddr for Ipv4Addr {}
impl GroupAddr for Ipv6Addr {}

/// What the proxy must do upstream as a result of a downstream membership change.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProxyAction<A: GroupAddr> {
    /// Become a member of `group` upstream (send an unsolicited report upstream):
    /// the first downstream member just appeared.
    JoinUpstream(A),
    /// Leave `group` upstream (send a Leave upstream): the last downstream member
    /// just went.
    LeaveUpstream(A),
}

impl<A: GroupAddr> ProxyAction<A> {
    /// The group this action concerns.
    pub fn group(&self) -> A {
        match *self {
            ProxyAction::JoinUpstream(g) | ProxyAction::LeaveUpstream(g) => g,
        }
    }
}

/// One multicast forwarding entry: a group and the downstream interfaces that want
/// it. The upstream interface is the implicit incoming interface (iif).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForwardingEntry<A: GroupAddr> {
    /// The multicast group.
    pub group: A,
    /// The downstream interface indexes to replicate the stream onto (the oif list).
    pub downstreams: Vec<u32>,
}

/// The proxy's aggregated state: for each group, the set of downstream interface
/// indexes that currently want it. Generic over the group address family.
#[derive(Debug, Clone)]
pub struct MulticastProxy<A: GroupAddr> {
    groups: BTreeMap<A, BTreeSet<u32>>,
}

/// The IGMP (IPv4) proxy — RFC 4605 aggregation over IPv4 groups.
pub type IgmpProxy = MulticastProxy<Ipv4Addr>;
/// The MLD (IPv6) proxy — RFC 4605 aggregation over IPv6 groups.
pub type MldProxy = MulticastProxy<Ipv6Addr>;

impl<A: GroupAddr> Default for MulticastProxy<A> {
    fn default() -> Self {
        MulticastProxy {
            groups: BTreeMap::new(),
        }
    }
}

impl<A: GroupAddr> MulticastProxy<A> {
    /// A fresh proxy with no memberships.
    pub fn new() -> Self {
        MulticastProxy::default()
    }

    /// Reconcile the membership on downstream interface `ifindex` to `wanted` (the
    /// full set of groups with a member on that interface right now), returning the
    /// upstream join/leave actions the change implies.
    ///
    /// This is idempotent and diff-based: only a group crossing the "no downstream
    /// wants it ↔ some downstream wants it" boundary produces an action, so calling
    /// it repeatedly with a stable membership yields no actions.
    pub fn sync_downstream(&mut self, ifindex: u32, wanted: &BTreeSet<A>) -> Vec<ProxyAction<A>> {
        let mut actions = Vec::new();

        // Groups this interface previously contributed to.
        let previously: BTreeSet<A> = self
            .groups
            .iter()
            .filter(|(_, oifs)| oifs.contains(&ifindex))
            .map(|(g, _)| *g)
            .collect();

        // Additions: groups now wanted that this interface did not previously want.
        for &g in wanted.difference(&previously) {
            let oifs = self.groups.entry(g).or_default();
            let was_empty = oifs.is_empty();
            oifs.insert(ifindex);
            if was_empty {
                actions.push(ProxyAction::JoinUpstream(g));
            }
        }

        // Removals: groups previously wanted on this interface but no longer.
        for &g in previously.difference(wanted) {
            if let Some(oifs) = self.groups.get_mut(&g) {
                oifs.remove(&ifindex);
                if oifs.is_empty() {
                    self.groups.remove(&g);
                    actions.push(ProxyAction::LeaveUpstream(g));
                }
            }
        }

        actions
    }

    /// Drop every membership contributed by `ifindex` (the interface went down),
    /// returning any upstream leaves that result.
    pub fn drop_interface(&mut self, ifindex: u32) -> Vec<ProxyAction<A>> {
        self.sync_downstream(ifindex, &BTreeSet::new())
    }

    /// Whether the proxy is (aggregate) a member of `group` upstream.
    pub fn is_joined(&self, group: A) -> bool {
        self.groups.contains_key(&group)
    }

    /// The groups the proxy is currently subscribed to upstream.
    pub fn joined_groups(&self) -> impl Iterator<Item = &A> {
        self.groups.keys()
    }

    /// The current multicast forwarding cache: one entry per active group with its
    /// downstream oif list. Feed to the kernel MFC (see the module docs).
    pub fn forwarding(&self) -> Vec<ForwardingEntry<A>> {
        self.groups
            .iter()
            .map(|(g, oifs)| ForwardingEntry {
                group: *g,
                downstreams: oifs.iter().copied().collect(),
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

    fn set(addrs: &[&str]) -> BTreeSet<Ipv4Addr> {
        addrs.iter().map(|s| ip(s)).collect()
    }

    #[test]
    fn first_downstream_member_joins_upstream() {
        let mut p = IgmpProxy::new();
        let actions = p.sync_downstream(2, &set(&["239.1.1.1"]));
        assert_eq!(actions, vec![ProxyAction::JoinUpstream(ip("239.1.1.1"))]);
        assert!(p.is_joined(ip("239.1.1.1")));
    }

    #[test]
    fn second_downstream_for_same_group_does_not_rejoin() {
        let mut p = IgmpProxy::new();
        p.sync_downstream(2, &set(&["239.1.1.1"]));
        // A different downstream interface wants the same group: no new upstream join.
        let actions = p.sync_downstream(3, &set(&["239.1.1.1"]));
        assert!(actions.is_empty());
        // Both interfaces are oifs for the group.
        let fwd = p.forwarding();
        assert_eq!(fwd.len(), 1);
        assert_eq!(fwd[0].downstreams, vec![2, 3]);
    }

    #[test]
    fn last_member_leaving_leaves_upstream() {
        let mut p = IgmpProxy::new();
        p.sync_downstream(2, &set(&["239.1.1.1"]));
        p.sync_downstream(3, &set(&["239.1.1.1"]));
        // Interface 2 drops it — still wanted by 3, so no upstream leave.
        assert!(p.sync_downstream(2, &BTreeSet::new()).is_empty());
        assert!(p.is_joined(ip("239.1.1.1")));
        // Interface 3 drops it — now the last member is gone.
        let actions = p.sync_downstream(3, &BTreeSet::new());
        assert_eq!(actions, vec![ProxyAction::LeaveUpstream(ip("239.1.1.1"))]);
        assert!(!p.is_joined(ip("239.1.1.1")));
    }

    #[test]
    fn stable_membership_is_idempotent() {
        let mut p = IgmpProxy::new();
        p.sync_downstream(2, &set(&["239.1.1.1", "239.2.2.2"]));
        // Re-syncing the identical set yields no actions.
        assert!(p
            .sync_downstream(2, &set(&["239.1.1.1", "239.2.2.2"]))
            .is_empty());
    }

    #[test]
    fn simultaneous_add_and_remove_on_one_interface() {
        let mut p = IgmpProxy::new();
        p.sync_downstream(2, &set(&["239.1.1.1"]));
        // Interface swaps its group in one sync: one leave + one join.
        let mut actions = p.sync_downstream(2, &set(&["239.9.9.9"]));
        actions.sort_by_key(|a| a.group());
        // Sorted by group address: 239.1.1.1 (leave) precedes 239.9.9.9 (join).
        assert_eq!(
            actions,
            vec![
                ProxyAction::LeaveUpstream(ip("239.1.1.1")),
                ProxyAction::JoinUpstream(ip("239.9.9.9")),
            ]
        );
    }

    #[test]
    fn drop_interface_leaves_its_exclusive_groups() {
        let mut p = IgmpProxy::new();
        p.sync_downstream(2, &set(&["239.1.1.1"]));
        p.sync_downstream(3, &set(&["239.2.2.2"]));
        let mut actions = p.drop_interface(2);
        actions.sort_by_key(|a| a.group());
        assert_eq!(actions, vec![ProxyAction::LeaveUpstream(ip("239.1.1.1"))]);
        // 3's group is untouched.
        assert!(p.is_joined(ip("239.2.2.2")));
    }

    #[test]
    fn forwarding_entries_track_oifs() {
        let mut p = IgmpProxy::new();
        p.sync_downstream(2, &set(&["239.1.1.1"]));
        p.sync_downstream(3, &set(&["239.1.1.1", "239.2.2.2"]));
        let fwd = p.forwarding();
        assert_eq!(fwd.len(), 2);
        let g1 = fwd.iter().find(|e| e.group == ip("239.1.1.1")).unwrap();
        assert_eq!(g1.downstreams, vec![2, 3]);
        let g2 = fwd.iter().find(|e| e.group == ip("239.2.2.2")).unwrap();
        assert_eq!(g2.downstreams, vec![3]);
    }
}
