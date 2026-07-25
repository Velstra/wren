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

use wren_core::Prefix;

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
    /// The SRv6 service SID from the route's Prefix-SID attribute (RFC 9252), if
    /// the advertising PE carries this MAC over SRv6 (End.DT2U) instead of VXLAN.
    pub srv6_sid: Option<crate::srv6::Srv6Sid>,
    /// The advertising PE's own MAC, from the Router's MAC extended community
    /// (RFC 9135 §4). Only **symmetric** IRB needs it: the ingress PE routes into
    /// the L3 VNI and must address the inner Ethernet frame to the egress PE, so
    /// this is the inner MAC DA. Asymmetric IRB bridges to the destination host's
    /// own MAC and the community is absent — hence `Option`, not a default.
    pub router_mac: Option<[u8; 6]>,
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

/// The MAC Mobility extended community's carried state (RFC 7432 §7.7): the move
/// sequence number and the sticky (static) flag.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
struct MacMobility {
    seq: u32,
    sticky: bool,
}

/// The EVPN MAC Mobility extended community: type 0x06, sub-type 0x00, flags byte
/// (bit 0 = Sticky/Static), then a 4-octet sequence number (RFC 7432 §7.7).
const EC_TYPE_EVPN: u8 = 0x06;
const EC_SUBTYPE_MAC_MOBILITY: u8 = 0x00;
const MAC_MOBILITY_STICKY: u8 = 0x01;
/// The Router's MAC extended community (RFC 9135 §4): same EVPN type 0x06, sub-type
/// 0x03, and the remaining six octets are the advertising PE's MAC address.
const EC_SUBTYPE_ROUTER_MAC: u8 = 0x03;

/// Build the Router's MAC extended community for `mac`, to attach to the routes a
/// PE originates for symmetric IRB (RFC 9135 §4 sends it with RT-2; RFC 9136 does
/// the same for the RT-5 IP Prefix route).
pub fn build_router_mac(mac: [u8; 6]) -> [u8; 8] {
    [
        EC_TYPE_EVPN,
        EC_SUBTYPE_ROUTER_MAC,
        mac[0],
        mac[1],
        mac[2],
        mac[3],
        mac[4],
        mac[5],
    ]
}

/// The advertising PE's MAC from a route's Router's MAC extended community, or
/// `None` when it carries none — which is the normal case for asymmetric IRB, where
/// forwarding uses the destination host's own MAC instead.
fn router_mac(path: &Path) -> Option<[u8; 6]> {
    path.ext_communities
        .iter()
        .find(|ec| ec[0] == EC_TYPE_EVPN && ec[1] == EC_SUBTYPE_ROUTER_MAC)
        .map(|ec| [ec[2], ec[3], ec[4], ec[5], ec[6], ec[7]])
}

/// Extract a route's MAC Mobility state from its extended communities, or `None`
/// when the community is absent (an initial, never-moved advertisement, or a peer
/// that does not emit it — the two are indistinguishable, so absence is treated as
/// "no mobility information" rather than an explicit sequence 0).
fn mac_mobility(path: &Path) -> Option<MacMobility> {
    path.ext_communities
        .iter()
        .find(|ec| ec[0] == EC_TYPE_EVPN && ec[1] == EC_SUBTYPE_MAC_MOBILITY)
        .map(|ec| MacMobility {
            seq: u32::from_be_bytes([ec[4], ec[5], ec[6], ec[7]]),
            sticky: ec[2] & MAC_MOBILITY_STICKY != 0,
        })
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
    /// The MAC Mobility state currently in force for each `(eth_tag, mac)` (RFC
    /// 7432 §7.7), or `None` when the backing route carried no MAC Mobility
    /// community. A competing route from a different advertiser only displaces the
    /// incumbent if its sequence is not lower, and a sticky MAC is never displaced
    /// by a non-sticky one; equal-sequence duplicate detection applies only when
    /// *both* routes carry the community (otherwise a mover that does not set it —
    /// common on VXLAN fabrics — must still win, so we fall back to last-writer).
    mac_mobility: BTreeMap<(u32, [u8; 6]), Option<MacMobility>>,
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
            mac_mobility: BTreeMap::new(),
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
                        let key = (*eth_tag, *mac);
                        let mob = mac_mobility(path);
                        // MAC Mobility (RFC 7432 §7.7): decide whether this route may
                        // take over the MAC from whatever currently backs it. Our own
                        // owner re-advertising always wins (it is the incumbent); a
                        // *different* advertiser wins only if its sequence number is
                        // not lower — otherwise a stale pre-move route, applied after
                        // the post-move one, would re-pin the MAC to its old VTEP
                        // (blackhole/loop). A sticky (static) MAC is never displaced
                        // by a non-sticky one, and an equal-sequence route from a
                        // different VTEP is a duplicate (keep the incumbent rather
                        // than flap between the two).
                        let same_owner = self.owners.get(&key) == Some(nlri);
                        if !same_owner {
                            if let Some(cur) = self.mac_mobility.get(&key).copied() {
                                let cur_seq = cur.map_or(0, |m| m.seq);
                                let cur_sticky = cur.is_some_and(|m| m.sticky);
                                let new_seq = mob.map_or(0, |m| m.seq);
                                let new_sticky = mob.is_some_and(|m| m.sticky);
                                let stale = new_seq < cur_seq;
                                let sticky_block = cur_sticky && !new_sticky;
                                // A true duplicate (same MAC, equal sequence, two
                                // VTEPs) is only meaningful when both routes carry an
                                // explicit sequence; without it a mover that omits the
                                // community must still win (last-writer), or a
                                // legitimate move would blackhole to the old VTEP.
                                let duplicate = cur.is_some()
                                    && mob.is_some()
                                    && new_seq == cur_seq
                                    && self.macs.get(&key).map(|m| m.vtep) != Some(path.next_hop);
                                if stale || sticky_block || duplicate {
                                    return None;
                                }
                            }
                        }
                        let entry = RemoteMac {
                            vtep: path.next_hop,
                            vni: *label1,
                            ip: *ip,
                            srv6_sid: path.srv6_sid.map(|s| s.sid),
                            router_mac: router_mac(path),
                        };
                        let changed = self.macs.get(&key) != Some(&entry);
                        self.macs.insert(key, entry.clone());
                        self.owners.insert(key, nlri.clone());
                        self.mac_mobility.insert(key, mob);
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
                    self.mac_mobility.remove(&key);
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

// ---------------------------------------------------------------------------
// Per-IP-VRF import view (inter-subnet forwarding, RFC 9136)
// ---------------------------------------------------------------------------

/// A remote IP prefix learned via a type-5 route: how to reach a subnet that lives
/// behind another PE.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct RemotePrefix {
    /// The advertising PE (the route's BGP next hop) — the tunnel destination.
    pub vtep: IpAddr,
    /// The **L3** VNI to encapsulate with (the route's label). Distinct from an
    /// [`EviTable`] entry's L2 VNI: symmetric IRB routes into a per-tenant L3 VNI
    /// rather than bridging into the destination's L2 domain.
    pub vni: u32,
    /// The overlay next hop inside the tenant's IP-VRF, when the advertising PE
    /// supplies one. RFC 9136 §3.2 lets it be unspecified (all-zero) whenever the
    /// label and next hop already identify the egress, which is the common case —
    /// so an all-zero gateway is normalised to `None` rather than kept as `0.0.0.0`.
    pub gw: Option<IpAddr>,
    /// The egress PE's own MAC (RFC 9135 §4). Symmetric IRB needs it as the inner
    /// MAC DA; without it a forwarding plane cannot build the inner frame, so an
    /// entry lacking it is only usable for SRv6 or an already-known egress MAC.
    pub router_mac: Option<[u8; 6]>,
    /// The SRv6 service SID (RFC 9252 End.DT4/DT6), when the advertising PE carries
    /// this prefix over SRv6 instead of VXLAN.
    pub srv6_sid: Option<crate::srv6::Srv6Sid>,
}

/// A change to one IP-VRF's imported routing state, returned by
/// [`IpVrfTable::apply`] — the L3 counterpart of [`EviChange`].
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum IpVrfChange {
    /// A remote prefix appeared or changed.
    PrefixLearned {
        /// The destination subnet.
        prefix: Prefix,
        /// Where and how to reach it.
        entry: RemotePrefix,
    },
    /// A remote prefix is gone; stop routing to it.
    PrefixForgotten {
        /// The destination subnet that was withdrawn.
        prefix: Prefix,
    },
}

/// One tenant IP-VRF's imported view: the type-5 routes whose Route Targets match
/// its import set, collapsed across RDs into a prefix table. This is what a
/// forwarding plane consumes for **inter-subnet** traffic — the fabric `ROUTES`
/// trie, or a kernel VRF's routing table.
///
/// Deliberately simpler than [`EviTable`] in two ways. There is no MAC Mobility
/// analogue: RFC 9136 defines no mobility sequence for prefixes, and two PEs
/// advertising the same prefix is normal rather than a conflict (anycast, or a
/// multihomed subnet), so [`EvpnRib`]'s best-path selection already picks one. And
/// there is no flood set: a routed prefix has no BUM traffic.
#[derive(Clone, Debug)]
pub struct IpVrfTable {
    /// Route Targets this IP-VRF imports.
    pub import_rts: Vec<[u8; 8]>,
    /// Remote prefixes, collapsed across RDs.
    prefixes: BTreeMap<Prefix, RemotePrefix>,
    /// Which NLRI backs each prefix, so a withdrawal of a *different* RD's route
    /// for the same prefix does not tear down a route it does not own — the same
    /// hazard [`EviTable::owners`] guards against.
    owners: BTreeMap<Prefix, EvpnNlri>,
}

impl IpVrfTable {
    /// An empty IP-VRF view importing `import_rts`.
    pub fn new(import_rts: Vec<[u8; 8]>) -> Self {
        Self {
            import_rts,
            prefixes: BTreeMap::new(),
            owners: BTreeMap::new(),
        }
    }

    /// Whether a path's Route Targets intersect this IP-VRF's import set.
    pub fn imports(&self, path: &Path) -> bool {
        path.ext_communities.iter().any(|c| self.import_rts.contains(c))
    }

    /// Apply one EVPN table change to this IP-VRF's view, returning `Some(change)`
    /// when the routing state changed. Route types other than 5 are ignored — they
    /// belong to the MAC-VRF ([`EviTable`]).
    pub fn apply(&mut self, ev: &EvpnRibEvent) -> Option<IpVrfChange> {
        match ev {
            EvpnRibEvent::Best { nlri, path } => {
                if !self.imports(path) {
                    // An RT change can move a route out of our import set; treat a
                    // non-matching Best as a withdrawal of whatever it backed.
                    return self.remove_if_owner(nlri);
                }
                let EvpnNlri::IpPrefix {
                    prefix, gw, label, ..
                } = nlri
                else {
                    return None;
                };
                let entry = RemotePrefix {
                    vtep: path.next_hop,
                    vni: *label,
                    gw: specified_gw(*gw),
                    router_mac: router_mac(path),
                    srv6_sid: path.srv6_sid.map(|s| s.sid),
                };
                let changed = self.prefixes.get(prefix) != Some(&entry);
                self.prefixes.insert(*prefix, entry.clone());
                self.owners.insert(*prefix, nlri.clone());
                changed.then_some(IpVrfChange::PrefixLearned {
                    prefix: *prefix,
                    entry,
                })
            }
            EvpnRibEvent::Withdrawn(nlri) => self.remove_if_owner(nlri),
        }
    }

    fn remove_if_owner(&mut self, nlri: &EvpnNlri) -> Option<IpVrfChange> {
        let EvpnNlri::IpPrefix { prefix, .. } = nlri else {
            return None;
        };
        if self.owners.get(prefix) != Some(nlri) {
            return None;
        }
        self.owners.remove(prefix);
        self.prefixes
            .remove(prefix)
            .map(|_| IpVrfChange::PrefixForgotten { prefix: *prefix })
    }

    /// The remote-prefix table, in prefix order.
    pub fn iter_prefixes(&self) -> impl Iterator<Item = (&Prefix, &RemotePrefix)> {
        self.prefixes.iter()
    }

    /// How to reach `prefix`, if it is known.
    pub fn lookup(&self, prefix: &Prefix) -> Option<&RemotePrefix> {
        self.prefixes.get(prefix)
    }
}

/// A type-5 gateway address, or `None` when it is the RFC 9136 §3.2 "unspecified"
/// all-zero value meaning "the label and next hop identify the egress".
fn specified_gw(gw: IpAddr) -> Option<IpAddr> {
    match gw {
        IpAddr::V4(a) if a.is_unspecified() => None,
        IpAddr::V6(a) if a.is_unspecified() => None,
        other => Some(other),
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
            srv6_sid: None,
            otc: None,
            pass_through: vec![],
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

    /// A type-5 IP Prefix route for `prefix` under RD `rd_val`, carrying L3 VNI
    /// `vni` and the given gateway.
    fn prefix_route(rd_val: u16, prefix: &str, vni: u32, gw: IpAddr) -> EvpnNlri {
        EvpnNlri::IpPrefix {
            rd: Rd::from_ip(Ipv4Addr::new(192, 0, 2, rd_val as u8), rd_val),
            esi: Esi::ZERO,
            eth_tag: 0,
            prefix: prefix.parse().expect("a prefix"),
            gw,
            label: vni,
        }
    }

    /// A path carrying the import RT and a Router's MAC community.
    fn irb_path(peer: [u8; 4], pe_mac: [u8; 6]) -> Path {
        let mut p = path(100, peer, vec![RT]);
        p.ext_communities.push(build_router_mac(pe_mac));
        p
    }

    #[test]
    fn ip_vrf_imports_type5_prefixes_and_normalises_the_gateway() {
        let mut vrf = IpVrfTable::new(vec![RT]);
        let pe_mac = [0x02, 0xAA, 0, 0, 0, 0x01];
        let unspecified: IpAddr = Ipv4Addr::UNSPECIFIED.into();

        // RFC 9136 §3.2: an all-zero gateway means "the label and next hop identify
        // the egress". Keeping it as 0.0.0.0 would let a forwarding plane install a
        // route via a bogus next hop, so it must arrive as None.
        let nlri = prefix_route(1, "10.20.0.0/24", 50100, unspecified);
        let change = vrf.apply(&EvpnRibEvent::Best {
            nlri: nlri.clone(),
            path: irb_path([10, 0, 0, 1], pe_mac),
        });
        let entry = match change {
            Some(IpVrfChange::PrefixLearned { ref entry, .. }) => entry.clone(),
            other => panic!("expected the prefix to be learned, got {other:?}"),
        };
        assert_eq!(entry.vtep, ip([10, 0, 0, 1]));
        assert_eq!(entry.vni, 50100, "the L3 VNI, not an L2 one");
        assert_eq!(entry.gw, None, "an unspecified gateway is not a next hop");
        assert_eq!(entry.router_mac, Some(pe_mac));

        // A real gateway survives.
        let with_gw = prefix_route(1, "10.30.0.0/24", 50100, ip([10, 20, 0, 254]));
        vrf.apply(&EvpnRibEvent::Best {
            nlri: with_gw,
            path: irb_path([10, 0, 0, 1], pe_mac),
        });
        let e = vrf.lookup(&"10.30.0.0/24".parse().unwrap()).expect("known");
        assert_eq!(e.gw, Some(ip([10, 20, 0, 254])));

        // A route whose RTs we do not import is not ours to route.
        let mut other = IpVrfTable::new(vec![[0x00, 0x02, 0, 1, 0, 0, 0, 9]]);
        assert_eq!(
            other.apply(&EvpnRibEvent::Best {
                nlri: nlri.clone(),
                path: irb_path([10, 0, 0, 1], pe_mac)
            }),
            None
        );

        // Type-2 belongs to the MAC-VRF and must not land here.
        assert_eq!(
            vrf.apply(&EvpnRibEvent::Best {
                nlri: mac_route(1, 0x01, 10100),
                path: irb_path([10, 0, 0, 1], pe_mac)
            }),
            None
        );
    }

    #[test]
    fn a_foreign_rds_withdrawal_does_not_tear_down_the_prefix() {
        // Two PEs advertise the same subnet under different RDs — normal for an
        // anycast or multihomed subnet. Whichever route currently backs the entry
        // owns it; the other one's withdrawal must not remove a route it never
        // installed, or the surviving PE's path would silently disappear.
        let mut vrf = IpVrfTable::new(vec![RT]);
        let pe_mac = [0x02, 0xAA, 0, 0, 0, 0x01];
        let mine = prefix_route(1, "10.20.0.0/24", 50100, Ipv4Addr::UNSPECIFIED.into());
        let theirs = prefix_route(2, "10.20.0.0/24", 50100, Ipv4Addr::UNSPECIFIED.into());

        vrf.apply(&EvpnRibEvent::Best {
            nlri: mine.clone(),
            path: irb_path([10, 0, 0, 1], pe_mac),
        });
        assert_eq!(vrf.apply(&EvpnRibEvent::Withdrawn(theirs)), None);
        assert!(vrf.lookup(&"10.20.0.0/24".parse().unwrap()).is_some());

        // The owner's own withdrawal does remove it.
        assert_eq!(
            vrf.apply(&EvpnRibEvent::Withdrawn(mine)),
            Some(IpVrfChange::PrefixForgotten {
                prefix: "10.20.0.0/24".parse().unwrap()
            })
        );
        assert!(vrf.lookup(&"10.20.0.0/24".parse().unwrap()).is_none());
    }

    /// A MAC Mobility extended community with `seq` and the sticky flag.
    fn mm_ec(seq: u32, sticky: bool) -> [u8; 8] {
        let s = seq.to_be_bytes();
        [0x06, 0x00, if sticky { 0x01 } else { 0 }, 0, s[0], s[1], s[2], s[3]]
    }

    /// A path carrying the import RT and a MAC Mobility community.
    fn mob_path(peer: [u8; 4], seq: u32, sticky: bool) -> Path {
        let mut p = path(100, peer, vec![RT]);
        p.ext_communities.push(mm_ec(seq, sticky));
        p
    }

    #[test]
    fn routers_mac_community_round_trips_and_reaches_the_imported_entry() {
        // RFC 9135 §4: type 0x06, sub-type 0x03, the remaining six octets are the
        // advertising PE's MAC. Pin the wire bytes — a wrong sub-type would still
        // round-trip through our own builder and parser while interoperating with
        // nobody, so the literal encoding is the assertion that matters.
        let pe_mac = [0x02, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE];
        let ec = build_router_mac(pe_mac);
        assert_eq!(ec, [0x06, 0x03, 0x02, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE]);

        let mut p = path(100, [10, 0, 0, 1], vec![RT]);
        p.ext_communities.push(ec);
        assert_eq!(router_mac(&p), Some(pe_mac));

        // It travels all the way into the EVI's imported entry, which is where a
        // forwarding plane doing symmetric IRB reads it as the inner MAC DA.
        let mut evi = EviTable::new(vec![RT]);
        evi.apply(&EvpnRibEvent::Best {
            nlri: mac_route(1, 0x01, 10100),
            path: p,
        });
        let entry = evi.macs.get(&(0, [0x02, 0, 0, 0, 0, 0x01])).expect("imported");
        assert_eq!(entry.router_mac, Some(pe_mac));
    }

    #[test]
    fn a_route_without_the_routers_mac_community_carries_none() {
        // Asymmetric IRB omits it, and so does a MAC Mobility community that shares
        // the same 0x06 type — neither may be mistaken for a router MAC.
        assert_eq!(router_mac(&path(100, [10, 0, 0, 1], vec![RT])), None);
        assert_eq!(router_mac(&mob_path([10, 0, 0, 1], 7, false)), None);
    }

    #[test]
    fn mac_mobility_higher_sequence_wins_and_stale_is_ignored() {
        let mut evi = EviTable::new(vec![RT]);
        let mac = [0x02, 0, 0, 0, 0, 0x01];
        let a = mac_route(1, 0x01, 10100); // MAC behind PE-A (RD 1)
        let b = mac_route(2, 0x01, 10100); // same MAC behind PE-B (RD 2)

        // The MAC is first at VTEP .1 (seq 0).
        let _ = evi.apply(&EvpnRibEvent::Best { nlri: a.clone(), path: mob_path([10, 0, 0, 1], 0, false) });
        assert_eq!(evi.lookup_mac(0, mac).unwrap().vtep, ip([10, 0, 0, 1]));

        // It moves to VTEP .2, announced with a higher sequence — the move wins.
        assert!(evi
            .apply(&EvpnRibEvent::Best { nlri: b, path: mob_path([10, 0, 0, 2], 1, false) })
            .is_some());
        assert_eq!(evi.lookup_mac(0, mac).unwrap().vtep, ip([10, 0, 0, 2]));

        // A stale re-advertisement of the pre-move route (lower sequence) is ignored
        // rather than re-pinning the MAC to the old VTEP.
        assert!(evi
            .apply(&EvpnRibEvent::Best { nlri: a, path: mob_path([10, 0, 0, 1], 0, false) })
            .is_none());
        assert_eq!(evi.lookup_mac(0, mac).unwrap().vtep, ip([10, 0, 0, 2]));
    }

    #[test]
    fn mac_mobility_sticky_mac_is_not_hijacked() {
        let mut evi = EviTable::new(vec![RT]);
        let mac = [0x02, 0, 0, 0, 0, 0x01];
        // A sticky (static) MAC at VTEP .1.
        let _ = evi.apply(&EvpnRibEvent::Best {
            nlri: mac_route(1, 0x01, 10100),
            path: mob_path([10, 0, 0, 1], 0, true),
        });
        // A dynamic route with a higher sequence from another VTEP must NOT take it.
        assert!(evi
            .apply(&EvpnRibEvent::Best {
                nlri: mac_route(2, 0x01, 10100),
                path: mob_path([10, 0, 0, 2], 5, false),
            })
            .is_none());
        assert_eq!(evi.lookup_mac(0, mac).unwrap().vtep, ip([10, 0, 0, 1]));
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
            Some(&RemoteMac { vtep: peer, vni: 10100, ip: None, srv6_sid: None, router_mac: None })
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
                entry: RemoteMac { vtep: peer, vni: 10100, ip: None, srv6_sid: None, router_mac: None },
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
