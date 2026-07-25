//! The BGP SR Policy routing information base (SAFI 73) — the per-peer store of
//! received SR Policy candidate paths, with BGP best-path selection per NLRI and
//! RFC 9256 §2.9 best-candidate selection per `(colour, endpoint)` policy.
//!
//! SR Policy NLRI are not IP prefixes, so — like [`crate::evpn_rib::EvpnRib`] and
//! [`crate::flowspec_rib::FlowSpecRib`] — they get their own table. Each entry
//! pairs the BGP [`Path`] (used for the standard decision order when several peers
//! advertise the *same* candidate NLRI) with the decoded [`SrPolicyEncoding`] (the
//! candidate's preference, binding SID and segment lists) recovered from the
//! route's Tunnel Encapsulation attribute.
//!
//! Two selection stages, mirroring RFC 9256:
//!   1. **Per NLRI** — of the paths several peers offer for one candidate, the BGP
//!      decision process ([`is_better`]) picks one, exactly like the other RIBs.
//!   2. **Per policy** — of the candidate paths for one `(colour, endpoint)`, the
//!      highest preference is the active path ([`SrPolicyRib::installed`]).
//!
//! Scope: this is the wren-side RIB and inspection surface (`show bgp sr-policy` /
//! `show sr-policy`). Programming the selected SID lists into a forwarding
//! datapath — the Velstra fabric eBPF steering — is a separate, privileged step
//! and is **not** done here.

use std::collections::BTreeMap;
use std::net::IpAddr;

use crate::decision::{is_better, Path};
use crate::sr_policy::{SrPolicyEncoding, SrPolicyNlri};

/// One stored candidate path: the BGP path plus its decoded SR Policy contents.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct SrPolicyEntry {
    /// The BGP path (attributes + decision inputs) the candidate arrived on.
    pub path: Path,
    /// The candidate's SR Policy contents (preference, binding SID, segments).
    pub encoding: SrPolicyEncoding,
}

/// What changed in the SR Policy Loc-RIB when a candidate was offered or withdrawn.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum SrPolicyRibEvent {
    /// `nlri`'s best path appeared or changed.
    Best {
        /// The candidate NLRI whose best path changed.
        nlri: SrPolicyNlri,
        /// Its new best entry.
        entry: SrPolicyEntry,
    },
    /// `nlri` has no path left.
    Withdrawn(SrPolicyNlri),
}

/// One selected SR Policy: the active candidate for a `(colour, endpoint)` pair.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct InstalledPolicy {
    /// The policy colour.
    pub color: u32,
    /// The policy endpoint.
    pub endpoint: IpAddr,
    /// The winning candidate's distinguisher.
    pub distinguisher: u32,
    /// The winning candidate's contents.
    pub encoding: SrPolicyEncoding,
}

/// The SR Policy BGP table: per-peer Adj-RIB-In plus a selected best per NLRI.
#[derive(Clone, Default)]
pub struct SrPolicyRib {
    /// Every offered candidate per NLRI, keyed by `(peer, path_id)`.
    entries: BTreeMap<SrPolicyNlri, BTreeMap<(IpAddr, u32), SrPolicyEntry>>,
    /// The selected best candidate per NLRI (for change detection).
    best: BTreeMap<SrPolicyNlri, SrPolicyEntry>,
}

impl SrPolicyRib {
    /// An empty SR Policy table.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record (or replace) the candidate `peer` offers for `nlri`, re-select, and
    /// return the resulting change.
    pub fn update(
        &mut self,
        peer: IpAddr,
        nlri: SrPolicyNlri,
        entry: SrPolicyEntry,
    ) -> Option<SrPolicyRibEvent> {
        self.entries
            .entry(nlri)
            .or_default()
            .insert((peer, 0), entry);
        self.reselect(nlri)
    }

    /// Withdraw the candidate `peer` offered for `nlri`, re-select, and return the
    /// resulting change, if any.
    pub fn withdraw(&mut self, peer: IpAddr, nlri: SrPolicyNlri) -> Option<SrPolicyRibEvent> {
        if let Some(peers) = self.entries.get_mut(&nlri) {
            peers.retain(|(p, _), _| *p != peer);
            if peers.is_empty() {
                self.entries.remove(&nlri);
            }
        }
        self.reselect(nlri)
    }

    /// Drop every candidate learned from `peer` (its session went down), returning
    /// the change for each affected NLRI.
    pub fn withdraw_peer(&mut self, peer: IpAddr) -> Vec<SrPolicyRibEvent> {
        let affected: Vec<SrPolicyNlri> = self
            .entries
            .iter()
            .filter(|(_, peers)| peers.keys().any(|(p, _)| *p == peer))
            .map(|(n, _)| *n)
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
    pub fn best(&self, nlri: &SrPolicyNlri) -> Option<&SrPolicyEntry> {
        self.best.get(nlri)
    }

    /// Iterate every candidate NLRI's best entry, in NLRI order.
    pub fn iter_best(&self) -> impl Iterator<Item = (&SrPolicyNlri, &SrPolicyEntry)> {
        self.best.iter()
    }

    /// Number of candidate NLRI with a selected best path.
    pub fn len(&self) -> usize {
        self.best.len()
    }

    /// Whether the table holds no candidates.
    pub fn is_empty(&self) -> bool {
        self.best.is_empty()
    }

    /// The selected SR Policies (RFC 9256 §2.9): for each distinct `(colour,
    /// endpoint)`, the candidate with the highest preference wins (ties broken by
    /// the higher distinguisher). One entry per active policy, in `(colour,
    /// endpoint)` order.
    pub fn installed(&self) -> Vec<InstalledPolicy> {
        let mut out: Vec<InstalledPolicy> = Vec::new();
        for (nlri, entry) in &self.best {
            let pref = entry.encoding.effective_preference();
            match out.last_mut() {
                // `best` is ordered (colour, endpoint, distinguisher), so all
                // candidates of one policy are contiguous — fold them here.
                Some(p) if p.color == nlri.color && p.endpoint == nlri.endpoint => {
                    let cur = p.encoding.effective_preference();
                    if pref > cur || (pref == cur && nlri.distinguisher > p.distinguisher) {
                        p.distinguisher = nlri.distinguisher;
                        p.encoding = entry.encoding.clone();
                    }
                }
                _ => out.push(InstalledPolicy {
                    color: nlri.color,
                    endpoint: nlri.endpoint,
                    distinguisher: nlri.distinguisher,
                    encoding: entry.encoding.clone(),
                }),
            }
        }
        out
    }

    fn reselect(&mut self, nlri: SrPolicyNlri) -> Option<SrPolicyRibEvent> {
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
                    self.best.insert(nlri, entry.clone());
                    Some(SrPolicyRibEvent::Best { nlri, entry })
                }
            }
            None => self
                .best
                .remove(&nlri)
                .map(|_| SrPolicyRibEvent::Withdrawn(nlri)),
        }
    }
}

/// The best entry among `entries` per the BGP decision order over their paths.
fn select_best<'a>(entries: impl Iterator<Item = &'a SrPolicyEntry>) -> Option<&'a SrPolicyEntry> {
    let mut best: Option<&SrPolicyEntry> = None;
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
    use crate::sr_policy::{BindingSid, Segment, SegmentList};
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

    fn nlri(color: u32, endpoint: [u8; 4], disc: u32) -> SrPolicyNlri {
        SrPolicyNlri {
            color,
            endpoint: ip(endpoint),
            distinguisher: disc,
        }
    }

    fn enc(pref: u32, seg: u8) -> SrPolicyEncoding {
        SrPolicyEncoding {
            preference: Some(pref),
            binding_sid: BindingSid::None,
            priority: None,
            policy_name: None,
            segment_lists: vec![SegmentList {
                weight: None,
                segments: vec![Segment::MplsLabel(16000 + seg as u32)],
            }],
        }
    }

    fn entry(pref: u32, seg: u8, peer: [u8; 4]) -> SrPolicyEntry {
        SrPolicyEntry {
            path: path(100, peer),
            encoding: enc(pref, seg),
        }
    }

    #[test]
    fn first_candidate_is_best_and_installed() {
        let mut rib = SrPolicyRib::new();
        let n = nlri(100, [10, 0, 0, 9], 1);
        let ev = rib.update(ip([10, 0, 0, 1]), n, entry(100, 1, [10, 0, 0, 1]));
        assert!(matches!(ev, Some(SrPolicyRibEvent::Best { .. })));
        assert_eq!(rib.len(), 1);
        let installed = rib.installed();
        assert_eq!(installed.len(), 1);
        assert_eq!(installed[0].color, 100);
        assert_eq!(installed[0].distinguisher, 1);
    }

    #[test]
    fn higher_preference_candidate_wins_the_policy() {
        let mut rib = SrPolicyRib::new();
        let ep = [10, 0, 0, 9];
        rib.update(
            ip([10, 0, 0, 1]),
            nlri(100, ep, 1),
            entry(100, 1, [10, 0, 0, 1]),
        );
        rib.update(
            ip([10, 0, 0, 2]),
            nlri(100, ep, 2),
            entry(200, 2, [10, 0, 0, 2]),
        );
        // Two candidate NLRI in the RIB, one selected policy (the pref-200 one).
        assert_eq!(rib.len(), 2);
        let installed = rib.installed();
        assert_eq!(installed.len(), 1);
        assert_eq!(installed[0].distinguisher, 2);
        assert_eq!(installed[0].encoding.effective_preference(), 200);
    }

    #[test]
    fn distinct_colours_are_distinct_policies() {
        let mut rib = SrPolicyRib::new();
        let ep = [10, 0, 0, 9];
        rib.update(
            ip([10, 0, 0, 1]),
            nlri(100, ep, 1),
            entry(100, 1, [10, 0, 0, 1]),
        );
        rib.update(
            ip([10, 0, 0, 1]),
            nlri(200, ep, 1),
            entry(100, 2, [10, 0, 0, 1]),
        );
        assert_eq!(rib.installed().len(), 2);
    }

    #[test]
    fn withdraw_removes_the_candidate_and_policy() {
        let mut rib = SrPolicyRib::new();
        let n = nlri(100, [10, 0, 0, 9], 1);
        rib.update(ip([10, 0, 0, 1]), n, entry(100, 1, [10, 0, 0, 1]));
        let ev = rib.withdraw(ip([10, 0, 0, 1]), n);
        assert_eq!(ev, Some(SrPolicyRibEvent::Withdrawn(n)));
        assert!(rib.is_empty());
        assert!(rib.installed().is_empty());
    }

    #[test]
    fn withdraw_peer_drops_all_its_candidates() {
        let mut rib = SrPolicyRib::new();
        let ep = [10, 0, 0, 9];
        rib.update(
            ip([10, 0, 0, 1]),
            nlri(100, ep, 1),
            entry(100, 1, [10, 0, 0, 1]),
        );
        rib.update(
            ip([10, 0, 0, 1]),
            nlri(200, ep, 1),
            entry(100, 2, [10, 0, 0, 1]),
        );
        let events = rib.withdraw_peer(ip([10, 0, 0, 1]));
        assert_eq!(events.len(), 2);
        assert!(rib.is_empty());
    }
}
