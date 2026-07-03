//! The EVPN routing information base and the per-EVI (MAC-VRF) import view
//! (RFC 7432 §9).
//!
//! EVPN NLRI are not IP prefixes, so they get their own table instead of being
//! retrofitted into [`crate::rib::BgpRib`] — a deliberate parallel-RIB split:
//! only the BGP [`Path`] (attributes + decision order) is shared.
//!
//! Two layers:
//!
//! - [`EvpnRib`] — the raw BGP table (`show bgp evpn`): every EVPN route each
//!   peer offered, keyed by the full NLRI (RD included), with single-best
//!   selection per NLRI using the standard decision order.
//! - [`EviTable`] — one EVPN instance's (MAC-VRF's) imported view: routes whose
//!   Route Targets match the EVI's import set, collapsed across RDs into a
//!   remote-MAC table (type 2) and a remote-VTEP flood set (type 3). This is
//!   what a forwarding plane consumes (kernel bridge FDB, or fabric's overlay
//!   maps via the EVPN↔fabric bridge).

use std::collections::BTreeMap;
use std::net::IpAddr;

use crate::decision::{is_better, Path};
use crate::evpn::EvpnNlri;

/// Build the auto-derived Route Target of an EVI (RFC 7432 §7.10.1, adapted to
/// the common AS:VNI convention): a two-octet-AS Route Target extended
/// community whose value is the VNI.
pub fn auto_route_target(as2: u16, vni: u32) -> [u8; 8] {
    let a = as2.to_be_bytes();
    let v = vni.to_be_bytes();
    [0x00, 0x02, a[0], a[1], v[0], v[1], v[2], v[3]]
}

/// What changed in the EVPN Loc-RIB when a route was offered or withdrawn.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum EvpnRibEvent {
    /// `nlri`'s best path appeared or changed.
    Best { nlri: EvpnNlri, path: Path },
    /// `nlri` has no path left.
    Withdrawn(EvpnNlri),
}

/// The EVPN BGP table: per-peer Adj-RIB-In plus a selected best per NLRI.
/// Keys are the **full** NLRI (RD included) — distinct PEs advertise the same
/// MAC under distinct RDs and both stay in the table; collapsing across RDs is
/// the import layer's job ([`EviTable`]).
#[derive(Clone, Default)]
pub struct EvpnRib {
    /// Every offered path per NLRI, keyed by `(peer, path_id)` like the IP RIB.
    entries: BTreeMap<EvpnNlri, BTreeMap<(IpAddr, u32), Path>>,
    /// The selected best path per NLRI (for change detection).
    best: BTreeMap<EvpnNlri, Path>,
}

impl EvpnRib {
    /// An empty EVPN table.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record (or replace) the path `peer` offers for `nlri`, re-select, and
    /// return the resulting change.
    pub fn update(&mut self, peer: IpAddr, nlri: EvpnNlri, path: Path) -> Option<EvpnRibEvent> {
        self.entries.entry(nlri.clone()).or_default().insert((peer, 0), path);
        self.reselect(nlri)
    }

    /// Withdraw the path `peer` offered for `nlri`, re-select, and return the
    /// resulting change, if any.
    pub fn withdraw(&mut self, peer: IpAddr, nlri: EvpnNlri) -> Option<EvpnRibEvent> {
        if let Some(peers) = self.entries.get_mut(&nlri) {
            peers.retain(|(p, _), _| *p != peer);
            if peers.is_empty() {
                self.entries.remove(&nlri);
            }
        }
        self.reselect(nlri)
    }

    /// Drop every EVPN route learned from `peer` (its session went down),
    /// returning the change for each affected NLRI.
    pub fn withdraw_peer(&mut self, peer: IpAddr) -> Vec<EvpnRibEvent> {
        let affected: Vec<EvpnNlri> = self
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
    pub fn best(&self, nlri: &EvpnNlri) -> Option<&Path> {
        self.best.get(nlri)
    }

    /// Iterate every NLRI's best path, in NLRI order (`show bgp evpn`).
    pub fn iter_best(&self) -> impl Iterator<Item = (&EvpnNlri, &Path)> {
        self.best.iter()
    }

    /// Number of NLRI with a selected best path.
    pub fn len(&self) -> usize {
        self.best.len()
    }

    /// Whether the table holds no routes.
    pub fn is_empty(&self) -> bool {
        self.best.is_empty()
    }

    fn reselect(&mut self, nlri: EvpnNlri) -> Option<EvpnRibEvent> {
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
                    Some(EvpnRibEvent::Best { nlri, path })
                }
            }
            None => self.best.remove(&nlri).map(|_| EvpnRibEvent::Withdrawn(nlri)),
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

// ---------------------------------------------------------------------------
// Per-EVI import view (the MAC-VRF)
// ---------------------------------------------------------------------------

/// A remote MAC learned via a type-2 route: where to tunnel frames for it.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct RemoteMac {
    /// The advertising VTEP (the route's BGP next hop).
    pub vtep: IpAddr,
    /// The L2 VNI to encapsulate with (the route's Label1).
    pub vni: u32,
    /// The IP bound to the MAC, if advertised (feeds ARP/ND suppression).
    pub ip: Option<IpAddr>,
}

/// A change to one EVI's imported forwarding state, returned by
/// [`EviTable::apply`]. This is exactly what a forwarding plane must mirror: the
/// kernel bridge FDB, or — via the EVPN↔fabric bridge (`monitor evpn`) — the
/// fabric overlay maps (MAC-FDB, ARP/ND table, BUM flood set). A single `apply`
/// touches at most one entry, so it yields at most one change.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum EviChange {
    /// A remote MAC appeared or changed: tunnel frames for `mac` (on `eth_tag`)
    /// per `entry` (its VTEP, VNI and optional bound IP).
    MacLearned {
        /// The EVPN Ethernet Tag the MAC lives on (0 for VLAN-based service).
        eth_tag: u32,
        /// The learned MAC address.
        mac: [u8; 6],
        /// Where to tunnel to, and the IP bound to the MAC (for ARP/ND suppression).
        entry: RemoteMac,
    },
    /// A remote MAC was withdrawn: stop tunnelling frames for it.
    MacForgotten {
        /// The EVPN Ethernet Tag the MAC lived on.
        eth_tag: u32,
        /// The MAC that is gone.
        mac: [u8; 6],
    },
    /// A remote VTEP joined this EVI's BUM flood set (from a type-3 IMET route).
    VtepAdded {
        /// The originating VTEP to flood BUM traffic toward.
        vtep: IpAddr,
    },
    /// A remote VTEP left this EVI's BUM flood set.
    VtepRemoved {
        /// The VTEP that is gone.
        vtep: IpAddr,
    },
}

/// One EVPN instance's imported view: the remote-MAC table and the remote-VTEP
/// flood set, maintained incrementally from [`EvpnRibEvent`]s whose Route
/// Targets match the EVI's import set (RFC 7432 §9.2).
#[derive(Clone, Debug)]
pub struct EviTable {
    /// Route Targets this EVI imports.
    pub import_rts: Vec<[u8; 8]>,
    /// Remote MACs, keyed by `(eth_tag, mac)` — collapsed across RDs: whichever
    /// route is currently best for its NLRI wins, and among NLRI that differ
    /// only in RD the map keeps the last applied (they should agree on VTEP).
    macs: BTreeMap<(u32, [u8; 6]), RemoteMac>,
    /// Which NLRI currently backs each `(eth_tag, mac)` map entry, so a
    /// withdrawal of a *different* RD's route for the same MAC does not tear
    /// down a mapping it doesn't own.
    owners: BTreeMap<(u32, [u8; 6]), EvpnNlri>,
    /// Remote VTEPs participating in this EVI (from type-3 IMET routes), with
    /// the VNI each advertised — the BUM flood set.
    vteps: BTreeMap<IpAddr, u32>,
    /// Which NLRI backs each VTEP entry.
    vtep_owners: BTreeMap<IpAddr, EvpnNlri>,
}

impl EviTable {
    /// An empty EVI view importing `import_rts`.
    pub fn new(import_rts: Vec<[u8; 8]>) -> Self {
        Self {
            import_rts,
            macs: BTreeMap::new(),
            owners: BTreeMap::new(),
            vteps: BTreeMap::new(),
            vtep_owners: BTreeMap::new(),
        }
    }

    /// Whether a path's Route Targets intersect this EVI's import set.
    pub fn imports(&self, path: &Path) -> bool {
        path.ext_communities.iter().any(|c| self.import_rts.contains(c))
    }

    /// Apply one EVPN table change to this EVI's view. Returns `Some(change)`
    /// when the view changed (a consumer should re-sync its forwarding state to
    /// match), or `None` when nothing this EVI forwards was affected. `Some`
    /// stands in for the old boolean "changed" — `apply(..).is_some()` is the
    /// same predicate.
    pub fn apply(&mut self, ev: &EvpnRibEvent) -> Option<EviChange> {
        match ev {
            EvpnRibEvent::Best { nlri, path } => {
                if !self.imports(path) {
                    // An RT change can move a route out of our import set: treat
                    // a non-matching Best like a withdrawal of what it backed.
                    return self.remove_if_owner(nlri);
                }
                match nlri {
                    EvpnNlri::MacIp {
                        eth_tag, mac, ip, label1, ..
                    } => {
                        let entry = RemoteMac {
                            vtep: path.next_hop,
                            vni: *label1,
                            ip: *ip,
                        };
                        let key = (*eth_tag, *mac);
                        let changed = self.macs.get(&key) != Some(&entry);
                        self.macs.insert(key, entry.clone());
                        self.owners.insert(key, nlri.clone());
                        changed.then_some(EviChange::MacLearned {
                            eth_tag: *eth_tag,
                            mac: *mac,
                            entry,
                        })
                    }
                    EvpnNlri::Imet { orig_ip, .. } => {
                        // Flood toward the advertised originating VTEP. The VNI
                        // rides in the PMSI tunnel attribute in full RFC 7432;
                        // VXLAN fabrics put it in the route's label — absent
                        // here, so consumers use the EVI's own VNI. Track by
                        // originator IP.
                        let changed = !self.vteps.contains_key(orig_ip);
                        self.vteps.insert(*orig_ip, 0);
                        self.vtep_owners.insert(*orig_ip, nlri.clone());
                        changed.then_some(EviChange::VtepAdded { vtep: *orig_ip })
                    }
                    // Type 5 (IP prefix) feeds L3 (IRB) — handled by the RIB
                    // consumer, not the L2 view. Unknown types carry nothing.
                    _ => None,
                }
            }
            EvpnRibEvent::Withdrawn(nlri) => self.remove_if_owner(nlri),
        }
    }

    /// Remove whatever `nlri` currently backs in this view, if anything, and
    /// report the resulting forwarding change.
    fn remove_if_owner(&mut self, nlri: &EvpnNlri) -> Option<EviChange> {
        match nlri {
            EvpnNlri::MacIp { eth_tag, mac, .. } => {
                let key = (*eth_tag, *mac);
                if self.owners.get(&key) == Some(nlri) {
                    self.owners.remove(&key);
                    self.macs
                        .remove(&key)
                        .map(|_| EviChange::MacForgotten { eth_tag: *eth_tag, mac: *mac })
                } else {
                    None
                }
            }
            EvpnNlri::Imet { orig_ip, .. } if self.vtep_owners.get(orig_ip) == Some(nlri) => {
                self.vtep_owners.remove(orig_ip);
                self.vteps.remove(orig_ip).map(|_| EviChange::VtepRemoved { vtep: *orig_ip })
            }
            _ => None,
        }
    }

    /// The remote-MAC table, in `(eth_tag, mac)` order.
    pub fn iter_macs(&self) -> impl Iterator<Item = (&(u32, [u8; 6]), &RemoteMac)> {
        self.macs.iter()
    }

    /// The remote-VTEP flood set.
    pub fn iter_vteps(&self) -> impl Iterator<Item = &IpAddr> {
        self.vteps.keys()
    }

    /// Where to tunnel frames for `mac` on `eth_tag`, if known.
    pub fn lookup_mac(&self, eth_tag: u32, mac: [u8; 6]) -> Option<&RemoteMac> {
        self.macs.get(&(eth_tag, mac))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attr::{AsPathSegment, Origin};
    use crate::evpn::{Esi, Rd};
    use std::net::Ipv4Addr;

    fn ip(o: [u8; 4]) -> IpAddr {
        IpAddr::V4(Ipv4Addr::from(o))
    }

    fn path(local_pref: u32, peer: [u8; 4], rts: Vec<[u8; 8]>) -> Path {
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
            peer_id: Ipv4Addr::from(peer),
            peer_addr: ip(peer),
            from_client: false,
            originator_id: None,
            cluster_list: vec![],
            communities: vec![],
            large_communities: vec![],
            ext_communities: rts,
        }
    }

    fn mac_route(rd_val: u16, mac_last: u8, vni: u32) -> EvpnNlri {
        EvpnNlri::MacIp {
            rd: Rd::from_ip(Ipv4Addr::new(192, 0, 2, rd_val as u8), rd_val),
            esi: Esi::ZERO,
            eth_tag: 0,
            mac: [0x02, 0, 0, 0, 0, mac_last],
            ip: None,
            label1: vni,
            label2: None,
        }
    }

    fn imet(rd_val: u16, orig: [u8; 4]) -> EvpnNlri {
        EvpnNlri::Imet {
            rd: Rd::from_ip(Ipv4Addr::new(192, 0, 2, rd_val as u8), rd_val),
            eth_tag: 0,
            orig_ip: ip(orig),
        }
    }

    const RT: [u8; 8] = [0x00, 0x02, 0xfd, 0xe9, 0, 0, 0x27, 0x74]; // 65001:10100

    #[test]
    fn auto_route_target_matches_as_vni() {
        assert_eq!(auto_route_target(65001, 10100), RT);
    }

    #[test]
    fn best_path_selection_and_fallback() {
        let mut rib = EvpnRib::new();
        let nlri = mac_route(1, 0x01, 10100);
        let p1 = ip([10, 0, 0, 1]);
        let p2 = ip([10, 0, 0, 2]);
        assert!(matches!(
            rib.update(p1, nlri.clone(), path(100, [10, 0, 0, 1], vec![RT])),
            Some(EvpnRibEvent::Best { .. })
        ));
        // Higher LOCAL_PREF from another peer wins.
        let ev = rib.update(p2, nlri.clone(), path(200, [10, 0, 0, 2], vec![RT]));
        assert!(matches!(ev, Some(EvpnRibEvent::Best { ref path, .. }) if path.peer_addr == p2));
        // Withdraw the winner → fall back.
        let ev = rib.withdraw(p2, nlri.clone()).unwrap();
        assert!(matches!(ev, EvpnRibEvent::Best { ref path, .. } if path.peer_addr == p1));
        // Last withdrawal removes the NLRI.
        assert_eq!(rib.withdraw(p1, nlri.clone()), Some(EvpnRibEvent::Withdrawn(nlri)));
        assert!(rib.is_empty());
    }

    #[test]
    fn withdraw_peer_clears_only_its_routes() {
        let mut rib = EvpnRib::new();
        let p1 = ip([10, 0, 0, 1]);
        let p2 = ip([10, 0, 0, 2]);
        rib.update(p1, mac_route(1, 0x01, 10100), path(100, [10, 0, 0, 1], vec![RT]));
        rib.update(p2, mac_route(2, 0x02, 10100), path(100, [10, 0, 0, 2], vec![RT]));
        let evs = rib.withdraw_peer(p1);
        assert_eq!(evs.len(), 1);
        assert_eq!(rib.len(), 1);
    }

    #[test]
    fn evi_imports_only_matching_rt() {
        let mut rib = EvpnRib::new();
        let mut evi = EviTable::new(vec![RT]);
        let peer = ip([10, 0, 0, 1]);

        // Matching RT → imported into the MAC table.
        let ev = rib
            .update(peer, mac_route(1, 0x01, 10100), path(100, [10, 0, 0, 1], vec![RT]))
            .unwrap();
        assert!(evi.apply(&ev).is_some());
        assert_eq!(
            evi.lookup_mac(0, [0x02, 0, 0, 0, 0, 0x01]),
            Some(&RemoteMac { vtep: peer, vni: 10100, ip: None })
        );

        // Foreign RT → not imported.
        let other_rt = auto_route_target(65001, 99);
        let ev = rib
            .update(peer, mac_route(1, 0x02, 99), path(100, [10, 0, 0, 1], vec![other_rt]))
            .unwrap();
        assert!(evi.apply(&ev).is_none());
        assert!(evi.lookup_mac(0, [0x02, 0, 0, 0, 0, 0x02]).is_none());
    }

    #[test]
    fn evi_tracks_vtep_flood_set_from_imet() {
        let mut rib = EvpnRib::new();
        let mut evi = EviTable::new(vec![RT]);
        let peer = ip([10, 0, 0, 1]);
        let nlri = imet(1, [192, 0, 2, 1]);

        let ev = rib.update(peer, nlri.clone(), path(100, [10, 0, 0, 1], vec![RT])).unwrap();
        assert!(evi.apply(&ev).is_some());
        assert_eq!(evi.iter_vteps().collect::<Vec<_>>(), vec![&ip([192, 0, 2, 1])]);

        // Withdrawal empties the flood set.
        let ev = rib.withdraw(peer, nlri).unwrap();
        assert!(evi.apply(&ev).is_some());
        assert_eq!(evi.iter_vteps().count(), 0);
    }

    #[test]
    fn withdrawal_of_other_rd_does_not_steal_mac() {
        // Two PEs advertise the same MAC under different RDs; the map entry is
        // backed by whichever applied last. Withdrawing the non-owner NLRI must
        // not remove the entry.
        let mut evi = EviTable::new(vec![RT]);
        let a = mac_route(1, 0x01, 10100);
        let b = EvpnNlri::MacIp {
            rd: Rd::from_ip(Ipv4Addr::new(192, 0, 2, 2), 2),
            esi: Esi::ZERO,
            eth_tag: 0,
            mac: [0x02, 0, 0, 0, 0, 0x01],
            ip: None,
            label1: 10100,
            label2: None,
        };
        let _ = evi.apply(&EvpnRibEvent::Best { nlri: a.clone(), path: path(100, [10, 0, 0, 1], vec![RT]) });
        let _ = evi.apply(&EvpnRibEvent::Best { nlri: b.clone(), path: path(100, [10, 0, 0, 2], vec![RT]) });
        // b owns the entry now; withdrawing a changes nothing.
        assert!(evi.apply(&EvpnRibEvent::Withdrawn(a)).is_none());
        assert!(evi.lookup_mac(0, [0x02, 0, 0, 0, 0, 0x01]).is_some());
        // Withdrawing b removes it.
        assert!(evi.apply(&EvpnRibEvent::Withdrawn(b)).is_some());
        assert!(evi.lookup_mac(0, [0x02, 0, 0, 0, 0, 0x01]).is_none());
    }

    #[test]
    fn rt_change_out_of_import_set_acts_as_withdraw() {
        let mut evi = EviTable::new(vec![RT]);
        let nlri = mac_route(1, 0x01, 10100);
        let _ = evi.apply(&EvpnRibEvent::Best { nlri: nlri.clone(), path: path(100, [10, 0, 0, 1], vec![RT]) });
        assert!(evi.lookup_mac(0, [0x02, 0, 0, 0, 0, 0x01]).is_some());
        // The same NLRI re-advertised without our RT drops out of the view.
        let foreign = auto_route_target(65001, 99);
        let changed = evi.apply(&EvpnRibEvent::Best { nlri, path: path(100, [10, 0, 0, 1], vec![foreign]) });
        assert!(changed.is_some());
        assert!(evi.lookup_mac(0, [0x02, 0, 0, 0, 0, 0x01]).is_none());
    }

    #[test]
    fn apply_reports_precise_forwarding_deltas() {
        // The delta an EVI yields is exactly what the EVPN↔fabric bridge mirrors:
        // MAC learn/forget and VTEP add/remove, each carrying its identifying keys.
        let mut evi = EviTable::new(vec![RT]);
        let peer = ip([10, 0, 0, 1]);

        // type-2 → MacLearned with the VTEP and VNI.
        let mac = [0x02, 0, 0, 0, 0, 0x01];
        let ev = EvpnRibEvent::Best {
            nlri: mac_route(1, 0x01, 10100),
            path: path(100, [10, 0, 0, 1], vec![RT]),
        };
        assert_eq!(
            evi.apply(&ev),
            Some(EviChange::MacLearned {
                eth_tag: 0,
                mac,
                entry: RemoteMac { vtep: peer, vni: 10100, ip: None },
            })
        );
        // Re-applying the identical route is a no-op (no spurious churn downstream).
        assert_eq!(evi.apply(&ev), None);
        // Withdrawing it → MacForgotten with the same key.
        assert_eq!(
            evi.apply(&EvpnRibEvent::Withdrawn(mac_route(1, 0x01, 10100))),
            Some(EviChange::MacForgotten { eth_tag: 0, mac })
        );

        // type-3 IMET → VtepAdded / VtepRemoved for the flood set.
        let imet_nlri = imet(1, [192, 0, 2, 1]);
        assert_eq!(
            evi.apply(&EvpnRibEvent::Best { nlri: imet_nlri.clone(), path: path(100, [10, 0, 0, 1], vec![RT]) }),
            Some(EviChange::VtepAdded { vtep: ip([192, 0, 2, 1]) })
        );
        assert_eq!(
            evi.apply(&EvpnRibEvent::Withdrawn(imet_nlri)),
            Some(EviChange::VtepRemoved { vtep: ip([192, 0, 2, 1]) })
        );
    }
}
