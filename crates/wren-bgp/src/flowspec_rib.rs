//! The BGP FlowSpec routing information base (RFC 8955 §5) — the per-peer store
//! of received flow rules with single-best selection per NLRI.
//!
//! FlowSpec NLRI are not IP prefixes, so — like [`crate::evpn_rib::EvpnRib`] —
//! they get their own table instead of being retrofitted into
//! [`crate::rib::BgpRib`]: only the BGP [`Path`] (attributes + decision order) is
//! shared. A received rule's traffic-filtering **action** (rate-limit / discard /
//! marking) rides as an extended community on the same UPDATE (RFC 8955 §7), so it
//! is recovered from the best path's `ext_communities` at read time
//! ([`FlowSpec`]'s [`Action`] decoder), not stored separately.
//!
//! Scope: this is the wren-side RIB and inspection surface (`show bgp flowspec`).
//! Installing the selected rules into a forwarding datapath — the Velstra fabric
//! eBPF flow classifier — is a separate, privileged step and is **not** done here.

use std::collections::BTreeMap;
use std::fmt;
use std::net::IpAddr;

use crate::decision::{is_better, Path};
use crate::flowspec::{Action, FlowSpec};

/// A FlowSpec NLRI: the address family it belongs to (AFI 1 IPv4 / AFI 2 IPv6)
/// paired with the flow specification itself — the RIB key.
///
/// [`FlowSpec`] carries a [`wren_core::Prefix`], which is not itself `Ord`, so the
/// ordering is defined over `(afi, canonical NLRI encoding)`: the same total order
/// the routes would take on the wire, and stable because [`FlowSpec::encode`] sorts
/// the components by type.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct FlowSpecNlri {
    /// The Address Family Identifier: [`crate::AFI_IPV4`] or [`crate::AFI_IPV6`].
    pub afi: u16,
    /// The flow specification (its match components).
    pub spec: FlowSpec,
}

impl FlowSpecNlri {
    /// An IPv4 (AFI 1) FlowSpec NLRI.
    pub fn v4(spec: FlowSpec) -> FlowSpecNlri {
        FlowSpecNlri {
            afi: crate::AFI_IPV4,
            spec,
        }
    }

    /// The `(afi, canonical encoding)` ordering key.
    fn sort_key(&self) -> (u16, Vec<u8>) {
        let mut b = Vec::new();
        self.spec.encode(&mut b);
        (self.afi, b)
    }
}

impl PartialOrd for FlowSpecNlri {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for FlowSpecNlri {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.sort_key().cmp(&other.sort_key())
    }
}

impl fmt::Display for FlowSpecNlri {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // AFI 1 is the common case and reads cleanly unadorned; tag IPv6 so a mixed
        // table stays unambiguous.
        if self.afi == crate::AFI_IPV6 {
            write!(f, "[ipv6] {}", self.spec)
        } else {
            write!(f, "{}", self.spec)
        }
    }
}

/// The traffic-filtering actions carried on a path's extended communities
/// (RFC 8955 §7) — whatever a matching rule should do (discard / rate-limit /
/// mark). Empty when the UPDATE carried no recognised FlowSpec action community.
pub fn actions_of(path: &Path) -> Vec<Action> {
    path.ext_communities
        .iter()
        .filter_map(Action::decode)
        .collect()
}

/// What changed in the FlowSpec Loc-RIB when a rule was offered or withdrawn.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum FlowSpecRibEvent {
    /// `nlri`'s best path appeared or changed.
    Best {
        /// The flow rule whose best path changed.
        nlri: FlowSpecNlri,
        /// Its new best path.
        path: Path,
    },
    /// `nlri` has no path left.
    Withdrawn(FlowSpecNlri),
}

/// The FlowSpec BGP table: per-peer Adj-RIB-In plus a selected best per NLRI
/// (RFC 8955 §5). A direct parallel of [`crate::evpn_rib::EvpnRib`].
#[derive(Clone, Default)]
pub struct FlowSpecRib {
    /// Every offered path per NLRI, keyed by `(peer, path_id)` like the IP RIB.
    entries: BTreeMap<FlowSpecNlri, BTreeMap<(IpAddr, u32), Path>>,
    /// The selected best path per NLRI (for change detection).
    best: BTreeMap<FlowSpecNlri, Path>,
}

impl FlowSpecRib {
    /// An empty FlowSpec table.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record (or replace) the path `peer` offers for `nlri`, re-select, and return
    /// the resulting change.
    pub fn update(
        &mut self,
        peer: IpAddr,
        nlri: FlowSpecNlri,
        path: Path,
    ) -> Option<FlowSpecRibEvent> {
        self.entries
            .entry(nlri.clone())
            .or_default()
            .insert((peer, 0), path);
        self.reselect(nlri)
    }

    /// Withdraw the path `peer` offered for `nlri`, re-select, and return the
    /// resulting change, if any.
    pub fn withdraw(&mut self, peer: IpAddr, nlri: FlowSpecNlri) -> Option<FlowSpecRibEvent> {
        if let Some(peers) = self.entries.get_mut(&nlri) {
            peers.retain(|(p, _), _| *p != peer);
            if peers.is_empty() {
                self.entries.remove(&nlri);
            }
        }
        self.reselect(nlri)
    }

    /// Drop every FlowSpec rule learned from `peer` (its session went down),
    /// returning the change for each affected NLRI.
    pub fn withdraw_peer(&mut self, peer: IpAddr) -> Vec<FlowSpecRibEvent> {
        let affected: Vec<FlowSpecNlri> = self
            .entries
            .iter()
            .filter(|(_, peers)| peers.keys().any(|(p, _)| *p == peer))
            .map(|(n, _)| n.clone())
            .collect();
        let mut events = Vec::new();
        for nlri in affected {
            if let Some(peers) = self.entries.get_mut(&nlri) {
                peers.retain(|(p, _), _| *p != peer);
                if peers.is_empty() {
                    self.entries.remove(&nlri);
                }
            }
            if let Some(ev) = self.reselect(nlri) {
                events.push(ev);
            }
        }
        events
    }

    /// The current best path for `nlri`, if any.
    pub fn best(&self, nlri: &FlowSpecNlri) -> Option<&Path> {
        self.best.get(nlri)
    }

    /// Iterate every NLRI's best path, in NLRI order (`show bgp flowspec`).
    pub fn iter_best(&self) -> impl Iterator<Item = (&FlowSpecNlri, &Path)> {
        self.best.iter()
    }

    /// Number of NLRI with a selected best path.
    pub fn len(&self) -> usize {
        self.best.len()
    }

    /// Whether the table holds no rules.
    pub fn is_empty(&self) -> bool {
        self.best.is_empty()
    }

    fn reselect(&mut self, nlri: FlowSpecNlri) -> Option<FlowSpecRibEvent> {
        let best = self
            .entries
            .get(&nlri)
            .and_then(|peers| select_best(peers.values()))
            .cloned();
        match best {
            Some(path) => {
                if self.best.get(&nlri) == Some(&path) {
                    None
                } else {
                    self.best.insert(nlri.clone(), path.clone());
                    Some(FlowSpecRibEvent::Best { nlri, path })
                }
            }
            None => self
                .best
                .remove(&nlri)
                .map(|_| FlowSpecRibEvent::Withdrawn(nlri)),
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
    use crate::flowspec::{Component, NumOp};
    use std::net::{IpAddr, Ipv4Addr};
    use wren_core::Prefix;

    fn ip(o: [u8; 4]) -> IpAddr {
        IpAddr::V4(Ipv4Addr::from(o))
    }

    fn v4(a: [u8; 4], len: u8) -> Prefix {
        Prefix::new(IpAddr::V4(a.into()), len).expect("valid prefix")
    }

    // A rule: match dst a.b.c.d/len tcp dport 22.
    fn rule(dst: [u8; 4], len: u8) -> FlowSpecNlri {
        FlowSpecNlri::v4(FlowSpec {
            components: vec![
                Component::DestPrefix(v4(dst, len)),
                Component::IpProto(vec![NumOp::eq(6)]),
                Component::DestPort(vec![NumOp::eq(22)]),
            ],
        })
    }

    fn path(local_pref: u32, peer: [u8; 4], ext: Vec<[u8; 8]>) -> Path {
        Path {
            origin: Origin::Igp,
            as_path: vec![AsPathSegment::Sequence(vec![65001])],
            next_hop: ip(peer),
            next_hop_iface: None,
            local_pref,
            med: 0,
            from_ebgp: false,
            from_confed: false,
            peer_as: 65001,
            igp_metric: 10,
            peer_id: Ipv4Addr::from(peer),
            peer_addr: ip(peer),
            from_client: false,
            originator_id: None,
            cluster_list: vec![],
            communities: vec![],
            large_communities: vec![],
            ext_communities: ext,
            srv6_sid: None,
        }
    }

    #[test]
    fn best_path_selection_and_fallback() {
        let mut rib = FlowSpecRib::new();
        let nlri = rule([10, 50, 0, 0], 24);
        let p1 = ip([10, 0, 0, 1]);
        let p2 = ip([10, 0, 0, 2]);
        assert!(matches!(
            rib.update(p1, nlri.clone(), path(100, [10, 0, 0, 1], vec![])),
            Some(FlowSpecRibEvent::Best { .. })
        ));
        // Higher LOCAL_PREF from another peer wins.
        let ev = rib.update(p2, nlri.clone(), path(200, [10, 0, 0, 2], vec![]));
        assert!(
            matches!(ev, Some(FlowSpecRibEvent::Best { ref path, .. }) if path.peer_addr == p2)
        );
        // Withdraw the winner → fall back to the other peer.
        let ev = rib.withdraw(p2, nlri.clone()).unwrap();
        assert!(matches!(ev, FlowSpecRibEvent::Best { ref path, .. } if path.peer_addr == p1));
        // Last withdrawal removes the NLRI.
        assert_eq!(
            rib.withdraw(p1, nlri.clone()),
            Some(FlowSpecRibEvent::Withdrawn(nlri))
        );
        assert!(rib.is_empty());
    }

    #[test]
    fn withdraw_peer_clears_only_its_rules() {
        let mut rib = FlowSpecRib::new();
        let p1 = ip([10, 0, 0, 1]);
        let p2 = ip([10, 0, 0, 2]);
        rib.update(
            p1,
            rule([10, 50, 0, 0], 24),
            path(100, [10, 0, 0, 1], vec![]),
        );
        rib.update(
            p2,
            rule([10, 60, 0, 0], 24),
            path(100, [10, 0, 0, 2], vec![]),
        );
        let evs = rib.withdraw_peer(p1);
        assert_eq!(evs.len(), 1);
        assert_eq!(rib.len(), 1);
    }

    #[test]
    fn actions_recovered_from_ext_communities() {
        // The discard action (traffic-rate 0) rides as an ext-community; the RIB
        // recovers it from the best path.
        let mut rib = FlowSpecRib::new();
        let nlri = rule([10, 50, 0, 0], 24);
        let peer = ip([10, 0, 0, 1]);
        rib.update(
            peer,
            nlri.clone(),
            path(100, [10, 0, 0, 1], vec![Action::DISCARD.encode()]),
        );
        let best = rib.best(&nlri).unwrap();
        assert_eq!(actions_of(best), vec![Action::DISCARD]);
    }

    #[test]
    fn nlri_ordering_is_by_canonical_encoding() {
        // Two distinct rules compare consistently regardless of insertion order.
        let a = rule([10, 50, 0, 0], 24);
        let b = rule([10, 60, 0, 0], 24);
        assert_ne!(a.cmp(&b), std::cmp::Ordering::Equal);
        // Component order in the source vec does not affect identity (encode sorts).
        let unsorted = FlowSpecNlri::v4(FlowSpec {
            components: vec![
                Component::DestPort(vec![NumOp::eq(22)]),
                Component::IpProto(vec![NumOp::eq(6)]),
                Component::DestPrefix(v4([10, 50, 0, 0], 24)),
            ],
        });
        assert_eq!(a.cmp(&unsorted), std::cmp::Ordering::Equal);
    }
}
