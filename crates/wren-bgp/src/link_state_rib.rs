//! The BGP-LS routing information base (AFI 16388 / SAFI 71, RFC 7752) — the
//! per-peer store of received Link-State objects (nodes, links, prefixes) with
//! single-best selection per NLRI.
//!
//! Link-State NLRI are not IP prefixes, so — like [`crate::evpn_rib::EvpnRib`] and
//! [`crate::flowspec_rib::FlowSpecRib`] — they get their own table. Each entry pairs
//! the BGP [`Path`] (the decision order when several peers advertise the same
//! object) with the decoded [`BgpLsAttribute`] recovered from the route's BGP-LS
//! Attribute (type 29).
//!
//! Scope: this is the wren-side RIB and inspection surface (`show bgp link-state`) —
//! a controller consuming the topology. Exporting the local OSPF/IS-IS topology
//! *into* BGP-LS is a separate, larger step and is not done here.

use std::collections::BTreeMap;
use std::net::IpAddr;

use crate::decision::{is_better, Path};
use crate::link_state::{BgpLsAttribute, LinkStateNlri};

/// One stored Link-State object: the BGP path plus its decoded BGP-LS attribute.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct LinkStateEntry {
    /// The BGP path (attributes + decision inputs) the object arrived on.
    pub path: Path,
    /// The object's BGP-LS attribute (node/link/prefix attribute TLVs).
    pub attr: BgpLsAttribute,
}

/// What changed in the BGP-LS Loc-RIB when an object was offered or withdrawn.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum LinkStateRibEvent {
    /// `nlri`'s best path appeared or changed.
    Best {
        /// The Link-State object whose best path changed.
        nlri: LinkStateNlri,
        /// Its new best entry.
        entry: LinkStateEntry,
    },
    /// `nlri` has no path left.
    Withdrawn(LinkStateNlri),
}

/// The BGP-LS table: per-peer Adj-RIB-In plus a selected best per NLRI (RFC 7752).
/// A direct parallel of [`crate::flowspec_rib::FlowSpecRib`].
#[derive(Clone, Default)]
pub struct LinkStateRib {
    /// Every offered path per NLRI, keyed by `(peer, path_id)`.
    entries: BTreeMap<LinkStateNlri, BTreeMap<(IpAddr, u32), LinkStateEntry>>,
    /// The selected best path per NLRI (for change detection).
    best: BTreeMap<LinkStateNlri, LinkStateEntry>,
}

impl LinkStateRib {
    /// An empty BGP-LS table.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record (or replace) the object `peer` offers for `nlri`, re-select, and
    /// return the resulting change.
    pub fn update(
        &mut self,
        peer: IpAddr,
        nlri: LinkStateNlri,
        entry: LinkStateEntry,
    ) -> Option<LinkStateRibEvent> {
        self.entries
            .entry(nlri.clone())
            .or_default()
            .insert((peer, 0), entry);
        self.reselect(nlri)
    }

    /// Withdraw the object `peer` offered for `nlri`, re-select, and return the
    /// resulting change, if any.
    pub fn withdraw(&mut self, peer: IpAddr, nlri: LinkStateNlri) -> Option<LinkStateRibEvent> {
        if let Some(peers) = self.entries.get_mut(&nlri) {
            peers.retain(|(p, _), _| *p != peer);
            if peers.is_empty() {
                self.entries.remove(&nlri);
            }
        }
        self.reselect(nlri)
    }

    /// Drop every object learned from `peer` (its session went down), returning the
    /// change for each affected NLRI.
    pub fn withdraw_peer(&mut self, peer: IpAddr) -> Vec<LinkStateRibEvent> {
        let affected: Vec<LinkStateNlri> = self
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

    /// The current best entry for `nlri`, if any.
    pub fn best(&self, nlri: &LinkStateNlri) -> Option<&LinkStateEntry> {
        self.best.get(nlri)
    }

    /// Iterate every NLRI's best entry, in NLRI order (`show bgp link-state`).
    pub fn iter_best(&self) -> impl Iterator<Item = (&LinkStateNlri, &LinkStateEntry)> {
        self.best.iter()
    }

    /// Number of NLRI with a selected best path.
    pub fn len(&self) -> usize {
        self.best.len()
    }

    /// Whether the table holds no objects.
    pub fn is_empty(&self) -> bool {
        self.best.is_empty()
    }

    fn reselect(&mut self, nlri: LinkStateNlri) -> Option<LinkStateRibEvent> {
        let best = self
            .entries
            .get(&nlri)
            .and_then(|peers| select_best(peers.values()))
            .cloned();
        match best {
            Some(entry) => {
                if self.best.get(&nlri) == Some(&entry) {
                    None
                } else {
                    self.best.insert(nlri.clone(), entry.clone());
                    Some(LinkStateRibEvent::Best { nlri, entry })
                }
            }
            None => self
                .best
                .remove(&nlri)
                .map(|_| LinkStateRibEvent::Withdrawn(nlri)),
        }
    }
}

/// The best entry among `entries` per the BGP decision order over their paths.
fn select_best<'a>(
    entries: impl Iterator<Item = &'a LinkStateEntry>,
) -> Option<&'a LinkStateEntry> {
    let mut best: Option<&LinkStateEntry> = None;
    for e in entries {
        match best {
            Some(b) if !is_better(&e.path, &b.path) => {}
            _ => best = Some(e),
        }
    }
    best
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attr::{AsPathSegment, Origin};
    use crate::link_state::{
        LsObjectKind, LsTlv, ATTR_NODE_NAME, SUBTLV_IGP_ROUTER_ID, TLV_LOCAL_NODE_DESCRIPTORS,
    };
    use std::net::Ipv4Addr;

    fn ip(o: [u8; 4]) -> IpAddr {
        IpAddr::V4(Ipv4Addr::from(o))
    }

    fn path(local_pref: u32, peer: [u8; 4]) -> Path {
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
            igp_metric: 0,
            peer_id: Ipv4Addr::from(peer),
            peer_addr: ip(peer),
            from_client: false,
            originator_id: None,
            cluster_list: vec![],
            communities: vec![],
            large_communities: vec![],
            ext_communities: vec![],
            srv6_sid: None,
            otc: None,
            pass_through: vec![],
        }
    }

    fn node_nlri(router_id: [u8; 4]) -> LinkStateNlri {
        let mut sub = Vec::new();
        LsTlv {
            typ: SUBTLV_IGP_ROUTER_ID,
            value: router_id.to_vec(),
        }
        .encode(&mut sub);
        LinkStateNlri {
            kind: LsObjectKind::Node,
            protocol: 3,
            identifier: 0,
            descriptors: vec![LsTlv {
                typ: TLV_LOCAL_NODE_DESCRIPTORS,
                value: sub,
            }],
        }
    }

    fn entry(name: &str, peer: [u8; 4]) -> LinkStateEntry {
        LinkStateEntry {
            path: path(100, peer),
            attr: BgpLsAttribute::new(vec![LsTlv {
                typ: ATTR_NODE_NAME,
                value: name.as_bytes().to_vec(),
            }]),
        }
    }

    #[test]
    fn first_object_is_best() {
        let mut rib = LinkStateRib::new();
        let n = node_nlri([10, 0, 0, 1]);
        let ev = rib.update(ip([10, 0, 0, 1]), n.clone(), entry("r1", [10, 0, 0, 1]));
        assert!(matches!(ev, Some(LinkStateRibEvent::Best { .. })));
        assert_eq!(rib.len(), 1);
        assert_eq!(
            rib.best(&n).unwrap().attr.node_name().as_deref(),
            Some("r1")
        );
    }

    #[test]
    fn reannouncing_same_object_is_noop() {
        let mut rib = LinkStateRib::new();
        let n = node_nlri([10, 0, 0, 1]);
        rib.update(ip([10, 0, 0, 1]), n.clone(), entry("r1", [10, 0, 0, 1]));
        let ev = rib.update(ip([10, 0, 0, 1]), n, entry("r1", [10, 0, 0, 1]));
        assert_eq!(ev, None);
    }

    #[test]
    fn withdraw_removes_the_object() {
        let mut rib = LinkStateRib::new();
        let n = node_nlri([10, 0, 0, 1]);
        rib.update(ip([10, 0, 0, 1]), n.clone(), entry("r1", [10, 0, 0, 1]));
        let ev = rib.withdraw(ip([10, 0, 0, 1]), n.clone());
        assert_eq!(ev, Some(LinkStateRibEvent::Withdrawn(n)));
        assert!(rib.is_empty());
    }

    #[test]
    fn withdraw_peer_drops_all_its_objects() {
        let mut rib = LinkStateRib::new();
        rib.update(
            ip([10, 0, 0, 1]),
            node_nlri([10, 0, 0, 1]),
            entry("r1", [10, 0, 0, 1]),
        );
        rib.update(
            ip([10, 0, 0, 1]),
            node_nlri([10, 0, 0, 2]),
            entry("r2", [10, 0, 0, 1]),
        );
        let events = rib.withdraw_peer(ip([10, 0, 0, 1]));
        assert_eq!(events.len(), 2);
        assert!(rib.is_empty());
    }
}
