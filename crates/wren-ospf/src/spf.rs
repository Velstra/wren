//! The intra-area shortest-path-first calculation (RFC 2328 §16.1) — a pure
//! Dijkstra over a single area's [`Lsdb`].
//!
//! The algorithm builds the shortest-path *tree* rooted at the calculating
//! router: vertices are routers (from Router-LSAs) and transit networks (from
//! Network-LSAs). Each accepted edge is checked for a matching link *back*
//! (§16.1, step 2b: "if the LSA does not have a link back ... examine the next
//! link") and MaxAge LSAs are ignored, so a half-converged database never poisons
//! the tree. Once the tree is built, two families of routes drop out:
//!
//! * **transit networks** — one per Network-LSA in the tree (§16.1, the network
//!   vertices); the prefix is the network number, the cost the vertex's distance.
//! * **stub networks** — the §16.1.1 second stage: every Router-LSA in the tree
//!   contributes its stub links at `router_distance + stub_metric`.
//!
//! Next hops are computed exactly as §16.1.1 prescribes: a destination one hop
//! from the root takes a freshly-resolved gateway (the neighbour's interface
//! address, read out of *its* LSA), and anything deeper inherits the parent
//! vertex's next hops. A directly-attached network or an unnumbered point-to-
//! point link yields an empty gateway set, i.e. an on-link (connected) route —
//! the runner pins the outgoing interface, which the LSDB alone cannot name.
//!
//! Inter-area (summary) and AS-external routes are *not* computed here yet; for
//! their benefit [`SpfResult`] also exposes the cost to reach every router
//! vertex (an ABR/ASBR lookup table), which those stages will read.
//!
//! This is the pure core: it reads an [`Lsdb`] and returns [`wren_core::Route`]s,
//! with no sockets and no clock, so it is fully unit-testable from a hand-built
//! database.

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr};

use wren_core::{NextHop, Prefix, Protocol, Route};

use crate::lsa::{LsType, LsaBody, NetworkLsa, RouterLinkType, RouterLsa};
use crate::lsdb::Lsdb;
use crate::{LS_INFINITY, MAX_AGE};

/// A vertex of the shortest-path tree: a router (by Router ID) or a transit
/// network (by the DR's interface address, which is the Network-LSA's Link State
/// ID).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
enum Vertex {
    Router(Ipv4Addr),
    Network(Ipv4Addr),
}

/// What is known about a settled (or candidate) vertex: its distance from the
/// root and the next-hop gateways to reach it. An empty gateway set means the
/// vertex is directly attached to the root (a connected/on-link next hop).
#[derive(Clone, Debug)]
struct VertexInfo {
    dist: u32,
    gateways: Vec<Ipv4Addr>,
}

/// One destination produced by the SPF: an intra-area network route.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct SpfRoute {
    /// The destination network.
    pub prefix: Prefix,
    /// The total OSPF cost from the root.
    pub cost: u32,
    /// The next-hop gateway addresses. Empty means the destination is directly
    /// attached to the root (a connected/on-link route whose outgoing interface
    /// the runner resolves).
    pub gateways: Vec<Ipv4Addr>,
}

impl SpfRoute {
    /// Convert into a [`wren_core::Route`] tagged [`Protocol::Ospf`], with the
    /// cost as the metric. An empty gateway set becomes a single on-link next hop
    /// (gateway and interface unset — the runner fills the interface in).
    pub fn to_route(&self) -> Route {
        let nexthops: Vec<NextHop> = if self.gateways.is_empty() {
            vec![NextHop {
                gateway: None,
                iface: None,
                weight: 1,
            }]
        } else {
            self.gateways
                .iter()
                .map(|g| NextHop::via(IpAddr::V4(*g)))
                .collect()
        };
        Route::new(self.prefix, Protocol::Ospf, nexthops, self.cost)
    }
}

/// The result of an intra-area SPF run.
#[derive(Clone, Default, Debug)]
pub struct SpfResult {
    /// The intra-area network routes, in prefix order.
    pub routes: Vec<SpfRoute>,
    /// The cost to reach every router vertex on the tree (the root included, at
    /// cost 0). Inter-area and AS-external route calculation reads this to find
    /// the distance to an ABR/ASBR.
    pub routers: BTreeMap<Ipv4Addr, u32>,
    /// The next-hop gateways to reach each router vertex (empty for the root and
    /// for directly-attached routers). Inter-area routes inherit these to reach
    /// the destination via the originating ABR.
    pub router_nexthops: BTreeMap<Ipv4Addr, Vec<Ipv4Addr>>,
}

/// Run the intra-area SPF over `db` rooted at `root`, returning the network
/// routes and the per-router distances.
pub fn compute(db: &Lsdb, root: Ipv4Addr) -> SpfResult {
    Spf { db, root }.run()
}

/// Convenience: run the SPF and hand back ready-to-announce [`wren_core::Route`]s.
pub fn routes(db: &Lsdb, root: Ipv4Addr) -> Vec<Route> {
    compute(db, root)
        .routes
        .iter()
        .map(SpfRoute::to_route)
        .collect()
}

/// The inter-area routes for one area (RFC 2328 §16.2): examine the Summary-LSAs
/// (type 3) in `lsdb` and, for each, add the cost the originating ABR advertised
/// to the intra-area cost of reaching that ABR (from `intra`, the SPF result for
/// the *same* area). The next hops are inherited from the path to the ABR.
///
/// Summaries this router originated itself (`self_id`) and unreachable ones
/// (LSInfinity, or an ABR not on the SPF tree) are skipped. The caller is
/// responsible for letting an intra-area route to the same prefix win (§16, the
/// intra-area > inter-area preference) — these routes carry the inter-area cost
/// only.
pub fn inter_area_routes(lsdb: &Lsdb, intra: &SpfResult, self_id: Ipv4Addr) -> Vec<SpfRoute> {
    let mut by_prefix: BTreeMap<Prefix, SpfRoute> = BTreeMap::new();
    for lsa in lsdb.iter_type(LsType::SummaryNetwork) {
        let LsaBody::Summary(summary) = &lsa.body else {
            continue;
        };
        let abr = lsa.header.advertising_router;
        if abr == self_id || summary.metric >= LS_INFINITY || lsa.header.ls_age >= MAX_AGE {
            continue;
        }
        // The ABR must be reachable within this area.
        let Some(&cost_to_abr) = intra.routers.get(&abr) else {
            continue;
        };
        let total = cost_to_abr.saturating_add(summary.metric);
        let plen = mask_len(summary.network_mask);
        // A type-3 Summary-LSA's Link State ID is the destination network number.
        let Ok(prefix) = Prefix::new(IpAddr::V4(lsa.header.link_state_id), plen) else {
            continue;
        };
        let gateways = intra.router_nexthops.get(&abr).cloned().unwrap_or_default();
        add_route(&mut by_prefix, prefix, total, &gateways);
    }
    by_prefix.into_values().collect()
}

/// The AS-external routes (RFC 2328 §16.4): examine the AS-external-LSAs (type 5)
/// in `lsdb` (the AS-wide external database) and, for each, compute the route to
/// the destination. With a type-1 (E1) external metric the cost is the intra-area
/// cost of reaching the originating ASBR plus the advertised metric; with type-2
/// (E2) the cost is the advertised metric alone (E2 always outranks any internal
/// cost). The next hops are inherited from the path to the ASBR.
///
/// Only a forwarding address of `0.0.0.0` (forward via the ASBR) is handled here;
/// an explicit forwarding address (resolved against the routing table) is a
/// refinement. Self-originated, unreachable, MaxAge and LSInfinity LSAs are
/// skipped. As with [`inter_area_routes`], the caller lets more-preferred
/// (intra/inter-area) routes win.
pub fn external_routes(lsdb: &Lsdb, intra: &SpfResult, self_id: Ipv4Addr) -> Vec<SpfRoute> {
    external_routes_of_type(lsdb, intra, self_id, LsType::AsExternal)
}

/// The NSSA-external routes (RFC 3101): exactly like [`external_routes`], but
/// reading the area-scoped type-7 LSAs from an NSSA area's own database. A router
/// inside an NSSA reaches the area's external destinations this way; the area
/// border router additionally translates the type-7s to type-5 for the rest of the
/// AS (done in the runner).
pub fn nssa_routes(lsdb: &Lsdb, intra: &SpfResult, self_id: Ipv4Addr) -> Vec<SpfRoute> {
    external_routes_of_type(lsdb, intra, self_id, LsType::Nssa)
}

/// Shared body of [`external_routes`] / [`nssa_routes`]: type-5 and type-7 carry
/// the same external body and use the same cost rules, differing only in the LS
/// type read and (for type-7) the database scope.
fn external_routes_of_type(
    lsdb: &Lsdb,
    intra: &SpfResult,
    self_id: Ipv4Addr,
    ls_type: LsType,
) -> Vec<SpfRoute> {
    let mut by_prefix: BTreeMap<Prefix, SpfRoute> = BTreeMap::new();
    for lsa in lsdb.iter_type(ls_type) {
        let LsaBody::AsExternal(ext) = &lsa.body else {
            continue;
        };
        let asbr = lsa.header.advertising_router;
        if asbr == self_id || ext.metric >= LS_INFINITY || lsa.header.ls_age >= MAX_AGE {
            continue;
        }
        // Only "forward via the ASBR" (forwarding address 0.0.0.0) is handled.
        if !ext.forwarding_address.is_unspecified() {
            continue;
        }
        let Some(&cost_to_asbr) = intra.routers.get(&asbr) else {
            continue;
        };
        let total = if ext.external_type2 {
            ext.metric
        } else {
            cost_to_asbr.saturating_add(ext.metric)
        };
        let plen = mask_len(ext.network_mask);
        let Ok(prefix) = Prefix::new(IpAddr::V4(lsa.header.link_state_id), plen) else {
            continue;
        };
        let gateways = intra.router_nexthops.get(&asbr).cloned().unwrap_or_default();
        add_route(&mut by_prefix, prefix, total, &gateways);
    }
    by_prefix.into_values().collect()
}

struct Spf<'a> {
    db: &'a Lsdb,
    root: Ipv4Addr,
}

impl Spf<'_> {
    fn run(&self) -> SpfResult {
        // The shortest-path tree (settled vertices) and the candidate list.
        let mut tree: BTreeMap<Vertex, VertexInfo> = BTreeMap::new();
        let mut cand: BTreeMap<Vertex, VertexInfo> = BTreeMap::new();

        tree.insert(
            Vertex::Router(self.root),
            VertexInfo {
                dist: 0,
                gateways: vec![],
            },
        );
        let mut current = Vertex::Router(self.root);

        loop {
            let cur = tree.get(&current).cloned().expect("current is settled");
            for (w, cost) in self.neighbors(current) {
                if tree.contains_key(&w) {
                    continue;
                }
                let dist = cur.dist + cost;
                let gateways = self.initial_gateways(current, &cur.gateways, w);
                match cand.get_mut(&w) {
                    None => {
                        cand.insert(w, VertexInfo { dist, gateways });
                    }
                    Some(existing) => {
                        if dist < existing.dist {
                            *existing = VertexInfo { dist, gateways };
                        } else if dist == existing.dist {
                            merge_gateways(&mut existing.gateways, &gateways);
                        }
                    }
                }
            }

            // Settle the nearest candidate (ties broken by vertex order, so the
            // result is deterministic).
            let next = cand
                .iter()
                .min_by(|a, b| a.1.dist.cmp(&b.1.dist).then_with(|| a.0.cmp(b.0)))
                .map(|(v, _)| *v);
            let Some(w) = next else { break };
            let info = cand.remove(&w).expect("just selected");
            tree.insert(w, info);
            current = w;
        }

        self.harvest(&tree)
    }

    /// The neighbours of `v` that exist, are not MaxAge and have a link back
    /// (§16.1, step 2). Each is returned with the cost of the edge from `v`.
    fn neighbors(&self, v: Vertex) -> Vec<(Vertex, u32)> {
        let mut out = Vec::new();
        match v {
            Vertex::Router(rid) => {
                let Some(rl) = self.router_lsa(rid) else {
                    return out;
                };
                for l in &rl.links {
                    match l.link_type {
                        RouterLinkType::PointToPoint | RouterLinkType::Virtual => {
                            let w = l.link_id;
                            if self.router_alive(w) && self.router_links_to_router(w, rid) {
                                out.push((Vertex::Router(w), l.metric as u32));
                            }
                        }
                        RouterLinkType::Transit => {
                            let dr = l.link_id;
                            if self.network_alive(dr) && self.network_lists_router(dr, rid) {
                                out.push((Vertex::Network(dr), l.metric as u32));
                            }
                        }
                        RouterLinkType::Stub => {} // §16.1.1 second stage
                    }
                }
            }
            Vertex::Network(dr) => {
                let Some(nl) = self.network_lsa(dr) else {
                    return out;
                };
                for &w in &nl.attached_routers {
                    if self.router_alive(w) && self.router_links_to_network(w, dr) {
                        out.push((Vertex::Router(w), 0));
                    }
                }
            }
        }
        out
    }

    /// The next-hop gateways for child `w` reached from parent `v` (§16.1.1).
    /// A parent with gateways already set passes them down unchanged; a parent
    /// that is the root or a directly-attached network resolves a fresh gateway
    /// (the neighbour's own interface address, from its LSA).
    fn initial_gateways(
        &self,
        v: Vertex,
        v_gateways: &[Ipv4Addr],
        w: Vertex,
    ) -> Vec<Ipv4Addr> {
        if !v_gateways.is_empty() {
            return v_gateways.to_vec();
        }
        match (v, w) {
            // Root reaches a point-to-point neighbour: its gateway is the far end
            // of the link, read from the neighbour's reverse link.
            (Vertex::Router(rid), Vertex::Router(w_id)) if rid == self.root => {
                self.reverse_p2p_address(w_id, rid)
                    .map(|a| vec![a])
                    .unwrap_or_default()
            }
            // A network one hop from the root: connected (no gateway).
            (Vertex::Router(rid), Vertex::Network(_)) if rid == self.root => vec![],
            // A router across a directly-attached network: its gateway is its own
            // interface address on that network.
            (Vertex::Network(dr), Vertex::Router(w_id)) => self
                .router_iface_on_network(w_id, dr)
                .map(|a| vec![a])
                .unwrap_or_default(),
            _ => vec![],
        }
    }

    /// Build the route set from the settled tree: transit networks (§16.1) then
    /// stub networks (§16.1.1), de-duplicated keeping the lowest cost and merging
    /// equal-cost next hops.
    fn harvest(&self, tree: &BTreeMap<Vertex, VertexInfo>) -> SpfResult {
        let mut by_prefix: BTreeMap<Prefix, SpfRoute> = BTreeMap::new();
        let mut routers: BTreeMap<Ipv4Addr, u32> = BTreeMap::new();
        let mut router_nexthops: BTreeMap<Ipv4Addr, Vec<Ipv4Addr>> = BTreeMap::new();

        for (vertex, info) in tree {
            match vertex {
                Vertex::Router(rid) => {
                    routers.insert(*rid, info.dist);
                    router_nexthops.insert(*rid, info.gateways.clone());
                    if let Some(rl) = self.router_lsa(*rid) {
                        for l in &rl.links {
                            if l.link_type == RouterLinkType::Stub {
                                // Link ID = network number, Link Data = mask.
                                let plen = mask_len(l.link_data);
                                if let Ok(prefix) = Prefix::new(IpAddr::V4(l.link_id), plen) {
                                    add_route(
                                        &mut by_prefix,
                                        prefix,
                                        info.dist + l.metric as u32,
                                        &info.gateways,
                                    );
                                }
                            }
                        }
                    }
                }
                Vertex::Network(dr) => {
                    if let Some(nl) = self.network_lsa(*dr) {
                        let plen = mask_len(nl.network_mask);
                        if let Ok(prefix) = Prefix::new(IpAddr::V4(*dr), plen) {
                            add_route(&mut by_prefix, prefix, info.dist, &info.gateways);
                        }
                    }
                }
            }
        }

        SpfResult {
            routes: by_prefix.into_values().collect(),
            routers,
            router_nexthops,
        }
    }

    // --- LSDB lookups ------------------------------------------------------

    /// A router's Router-LSA body, regardless of age.
    fn router_lsa(&self, rid: Ipv4Addr) -> Option<&RouterLsa> {
        match self.db.get(&(LsType::Router, rid, rid))?.body {
            crate::lsa::LsaBody::Router(ref r) => Some(r),
            _ => None,
        }
    }

    /// A transit network's Network-LSA body (searched by Link State ID = the DR's
    /// interface address), if present and not MaxAge.
    fn network_lsa(&self, dr: Ipv4Addr) -> Option<&NetworkLsa> {
        self.db.iter_type(LsType::Network).find_map(|lsa| {
            if lsa.header.link_state_id == dr && lsa.header.ls_age < MAX_AGE {
                if let crate::lsa::LsaBody::Network(ref n) = lsa.body {
                    return Some(n);
                }
            }
            None
        })
    }

    /// Whether a router's Router-LSA is present and not MaxAge.
    fn router_alive(&self, rid: Ipv4Addr) -> bool {
        self.db
            .get(&(LsType::Router, rid, rid))
            .is_some_and(|l| l.header.ls_age < MAX_AGE)
    }

    /// Whether a transit network's Network-LSA is present and not MaxAge.
    fn network_alive(&self, dr: Ipv4Addr) -> bool {
        self.network_lsa(dr).is_some()
    }

    /// Whether router `w` advertises a point-to-point/virtual link back to `v`.
    fn router_links_to_router(&self, w: Ipv4Addr, v: Ipv4Addr) -> bool {
        self.router_lsa(w).is_some_and(|rl| {
            rl.links.iter().any(|l| {
                matches!(
                    l.link_type,
                    RouterLinkType::PointToPoint | RouterLinkType::Virtual
                ) && l.link_id == v
            })
        })
    }

    /// Whether router `w` advertises a transit link onto network `dr`.
    fn router_links_to_network(&self, w: Ipv4Addr, dr: Ipv4Addr) -> bool {
        self.router_lsa(w).is_some_and(|rl| {
            rl.links
                .iter()
                .any(|l| l.link_type == RouterLinkType::Transit && l.link_id == dr)
        })
    }

    /// Whether network `dr` lists router `rid` among its attached routers.
    fn network_lists_router(&self, dr: Ipv4Addr, rid: Ipv4Addr) -> bool {
        self.network_lsa(dr)
            .is_some_and(|nl| nl.attached_routers.contains(&rid))
    }

    /// The far-end interface address of the point-to-point link from `peer` back
    /// to `to` — the gateway to reach `peer`. `None` for an unnumbered link.
    fn reverse_p2p_address(&self, peer: Ipv4Addr, to: Ipv4Addr) -> Option<Ipv4Addr> {
        let rl = self.router_lsa(peer)?;
        rl.links
            .iter()
            .find(|l| {
                matches!(
                    l.link_type,
                    RouterLinkType::PointToPoint | RouterLinkType::Virtual
                ) && l.link_id == to
            })
            .map(|l| l.link_data)
            .filter(|a| !a.is_unspecified())
    }

    /// Router `w`'s own interface address on network `dr` — the gateway to reach
    /// `w` across that network.
    fn router_iface_on_network(&self, w: Ipv4Addr, dr: Ipv4Addr) -> Option<Ipv4Addr> {
        let rl = self.router_lsa(w)?;
        rl.links
            .iter()
            .find(|l| l.link_type == RouterLinkType::Transit && l.link_id == dr)
            .map(|l| l.link_data)
            .filter(|a| !a.is_unspecified())
    }
}

/// Insert or fold a route into the by-prefix table: a strictly lower cost
/// replaces, an equal cost merges next hops (ECMP), a higher cost is dropped.
fn add_route(map: &mut BTreeMap<Prefix, SpfRoute>, prefix: Prefix, cost: u32, gateways: &[Ipv4Addr]) {
    match map.get_mut(&prefix) {
        None => {
            map.insert(
                prefix,
                SpfRoute {
                    prefix,
                    cost,
                    gateways: gateways.to_vec(),
                },
            );
        }
        Some(existing) => {
            if cost < existing.cost {
                existing.cost = cost;
                existing.gateways = gateways.to_vec();
            } else if cost == existing.cost {
                merge_gateways(&mut existing.gateways, gateways);
            }
        }
    }
}

/// Union `extra` into `into`, preserving order and dropping duplicates.
fn merge_gateways(into: &mut Vec<Ipv4Addr>, extra: &[Ipv4Addr]) {
    for g in extra {
        if !into.contains(g) {
            into.push(*g);
        }
    }
}

/// The CIDR prefix length of a contiguous IPv4 netmask.
fn mask_len(mask: Ipv4Addr) -> u8 {
    u32::from(mask).count_ones() as u8
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lsa::{
        AsExternalLsa, Lsa, LsaBody, LsaHeader, NetworkLsa, RouterLink, RouterLinkType, RouterLsa,
        SummaryLsa,
    };
    use crate::INITIAL_SEQUENCE_NUMBER;

    fn external_lsa(asbr: [u8; 4], net: [u8; 4], mask: [u8; 4], metric: u32, e2: bool) -> Lsa {
        Lsa {
            header: LsaHeader {
                ls_age: 1,
                options: crate::OPT_E,
                ls_type: LsType::AsExternal,
                link_state_id: ip(net),
                advertising_router: ip(asbr),
                ls_seq: INITIAL_SEQUENCE_NUMBER,
                ls_checksum: 0,
                length: 0,
            },
            body: LsaBody::AsExternal(AsExternalLsa {
                network_mask: ip(mask),
                external_type2: e2,
                metric,
                forwarding_address: Ipv4Addr::UNSPECIFIED,
                route_tag: 0,
            }),
        }
    }

    fn nssa_lsa(asbr: [u8; 4], net: [u8; 4], mask: [u8; 4], metric: u32) -> Lsa {
        Lsa {
            header: LsaHeader {
                ls_age: 1,
                options: crate::OPT_NP,
                ls_type: LsType::Nssa,
                link_state_id: ip(net),
                advertising_router: ip(asbr),
                ls_seq: INITIAL_SEQUENCE_NUMBER,
                ls_checksum: 0,
                length: 0,
            },
            body: LsaBody::AsExternal(AsExternalLsa {
                network_mask: ip(mask),
                external_type2: true,
                metric,
                forwarding_address: Ipv4Addr::UNSPECIFIED,
                route_tag: 0,
            }),
        }
    }

    fn summary_lsa(abr: [u8; 4], net: [u8; 4], mask: [u8; 4], metric: u32) -> Lsa {
        Lsa {
            header: LsaHeader {
                ls_age: 1,
                options: crate::OPT_E,
                ls_type: LsType::SummaryNetwork,
                link_state_id: ip(net),
                advertising_router: ip(abr),
                ls_seq: INITIAL_SEQUENCE_NUMBER,
                ls_checksum: 0,
                length: 0,
            },
            body: LsaBody::Summary(SummaryLsa {
                network_mask: ip(mask),
                metric,
            }),
        }
    }

    fn ip(o: [u8; 4]) -> Ipv4Addr {
        Ipv4Addr::from(o)
    }

    fn router_lsa(rid: [u8; 4], flags: u8, links: Vec<RouterLink>, age: u16) -> Lsa {
        Lsa {
            header: LsaHeader {
                ls_age: age,
                options: crate::OPT_E,
                ls_type: LsType::Router,
                link_state_id: ip(rid),
                advertising_router: ip(rid),
                ls_seq: INITIAL_SEQUENCE_NUMBER,
                ls_checksum: 0,
                length: 0,
            },
            body: LsaBody::Router(RouterLsa { flags, links }),
        }
    }

    fn network_lsa(dr: [u8; 4], adv: [u8; 4], mask: [u8; 4], routers: Vec<[u8; 4]>) -> Lsa {
        Lsa {
            header: LsaHeader {
                ls_age: 0,
                options: crate::OPT_E,
                ls_type: LsType::Network,
                link_state_id: ip(dr),
                advertising_router: ip(adv),
                ls_seq: INITIAL_SEQUENCE_NUMBER,
                ls_checksum: 0,
                length: 0,
            },
            body: LsaBody::Network(NetworkLsa {
                network_mask: ip(mask),
                attached_routers: routers.into_iter().map(ip).collect(),
            }),
        }
    }

    fn p2p(nbr: [u8; 4], local_if: [u8; 4], metric: u16) -> RouterLink {
        RouterLink {
            link_id: ip(nbr),
            link_data: ip(local_if),
            link_type: RouterLinkType::PointToPoint,
            metric,
        }
    }

    fn transit(dr: [u8; 4], local_if: [u8; 4], metric: u16) -> RouterLink {
        RouterLink {
            link_id: ip(dr),
            link_data: ip(local_if),
            link_type: RouterLinkType::Transit,
            metric,
        }
    }

    fn stub(net: [u8; 4], mask: [u8; 4], metric: u16) -> RouterLink {
        RouterLink {
            link_id: ip(net),
            link_data: ip(mask),
            link_type: RouterLinkType::Stub,
            metric,
        }
    }

    fn find<'a>(res: &'a SpfResult, prefix: &str) -> &'a SpfRoute {
        let p: Prefix = prefix.parse().unwrap();
        res.routes
            .iter()
            .find(|r| r.prefix == p)
            .unwrap_or_else(|| panic!("no route for {prefix}"))
    }

    #[test]
    fn point_to_point_reaches_neighbour_stub_via_gateway() {
        let mut db = Lsdb::new();
        // R1 <--cost10--> R2, each with a stub LAN.
        db.install(router_lsa(
            [1, 1, 1, 1],
            0,
            vec![
                p2p([2, 2, 2, 2], [10, 0, 12, 1], 10),
                stub([192, 168, 1, 0], [255, 255, 255, 0], 1),
            ],
            1,
        ));
        db.install(router_lsa(
            [2, 2, 2, 2],
            0,
            vec![
                p2p([1, 1, 1, 1], [10, 0, 12, 2], 10),
                stub([192, 168, 2, 0], [255, 255, 255, 0], 1),
            ],
            1,
        ));

        let res = compute(&db, ip([1, 1, 1, 1]));

        // Root's own stub is connected (cost 1, no gateway).
        let local = find(&res, "192.168.1.0/24");
        assert_eq!(local.cost, 1);
        assert!(local.gateways.is_empty());

        // The far stub: cost 10 (the link) + 1 (the stub), via R2's near end.
        let far = find(&res, "192.168.2.0/24");
        assert_eq!(far.cost, 11);
        assert_eq!(far.gateways, vec![ip([10, 0, 12, 2])]);

        // R2 is reachable at cost 10.
        assert_eq!(res.routers.get(&ip([2, 2, 2, 2])), Some(&10));
        assert_eq!(res.routers.get(&ip([1, 1, 1, 1])), Some(&0));
    }

    #[test]
    fn transit_network_is_connected_and_relays_to_other_router() {
        let mut db = Lsdb::new();
        // R1 (the DR, 10.0.0.1) and R2 (10.0.0.2) share a broadcast LAN.
        db.install(router_lsa(
            [1, 1, 1, 1],
            0,
            vec![transit([10, 0, 0, 1], [10, 0, 0, 1], 1)],
            1,
        ));
        db.install(router_lsa(
            [2, 2, 2, 2],
            0,
            vec![
                transit([10, 0, 0, 1], [10, 0, 0, 2], 1),
                stub([192, 168, 2, 0], [255, 255, 255, 0], 5),
            ],
            1,
        ));
        db.install(network_lsa(
            [10, 0, 0, 1],
            [1, 1, 1, 1],
            [255, 255, 255, 0],
            vec![[1, 1, 1, 1], [2, 2, 2, 2]],
        ));

        let res = compute(&db, ip([1, 1, 1, 1]));

        // The transit LAN itself is a connected route at the link cost.
        let lan = find(&res, "10.0.0.0/24");
        assert_eq!(lan.cost, 1);
        assert!(lan.gateways.is_empty());

        // R2's stub: 1 (root->net) + 0 (net->R2) + 5 (stub), via R2's LAN address.
        let far = find(&res, "192.168.2.0/24");
        assert_eq!(far.cost, 6);
        assert_eq!(far.gateways, vec![ip([10, 0, 0, 2])]);
        assert_eq!(res.routers.get(&ip([2, 2, 2, 2])), Some(&1));
    }

    #[test]
    fn one_way_link_is_ignored() {
        let mut db = Lsdb::new();
        // R1 claims a link to R2, but R2 never claims one back.
        db.install(router_lsa(
            [1, 1, 1, 1],
            0,
            vec![p2p([2, 2, 2, 2], [10, 0, 12, 1], 10)],
            1,
        ));
        db.install(router_lsa(
            [2, 2, 2, 2],
            0,
            vec![stub([192, 168, 2, 0], [255, 255, 255, 0], 1)],
            1,
        ));

        let res = compute(&db, ip([1, 1, 1, 1]));
        // R2 is unreachable: no bidirectional link.
        assert_eq!(res.routers.get(&ip([2, 2, 2, 2])), None);
        assert!(res.routes.iter().all(|r| r.gateways.is_empty()));
    }

    #[test]
    fn maxage_router_is_excluded() {
        let mut db = Lsdb::new();
        db.install(router_lsa(
            [1, 1, 1, 1],
            0,
            vec![p2p([2, 2, 2, 2], [10, 0, 12, 1], 10)],
            1,
        ));
        // R2's LSA has aged out.
        db.install(router_lsa(
            [2, 2, 2, 2],
            0,
            vec![
                p2p([1, 1, 1, 1], [10, 0, 12, 2], 10),
                stub([192, 168, 2, 0], [255, 255, 255, 0], 1),
            ],
            MAX_AGE,
        ));

        let res = compute(&db, ip([1, 1, 1, 1]));
        assert_eq!(res.routers.get(&ip([2, 2, 2, 2])), None);
        assert!(res.routes.iter().all(|r| r.prefix.to_string() != "192.168.2.0/24"));
    }

    #[test]
    fn equal_cost_paths_merge_into_ecmp() {
        let mut db = Lsdb::new();
        // R1 reaches R3 two ways at equal cost: via R2 and via R4.
        db.install(router_lsa(
            [1, 1, 1, 1],
            0,
            vec![
                p2p([2, 2, 2, 2], [10, 0, 12, 1], 10),
                p2p([4, 4, 4, 4], [10, 0, 14, 1], 10),
            ],
            1,
        ));
        db.install(router_lsa(
            [2, 2, 2, 2],
            0,
            vec![
                p2p([1, 1, 1, 1], [10, 0, 12, 2], 10),
                p2p([3, 3, 3, 3], [10, 0, 23, 2], 5),
            ],
            1,
        ));
        db.install(router_lsa(
            [4, 4, 4, 4],
            0,
            vec![
                p2p([1, 1, 1, 1], [10, 0, 14, 4], 10),
                p2p([3, 3, 3, 3], [10, 0, 43, 4], 5),
            ],
            1,
        ));
        db.install(router_lsa(
            [3, 3, 3, 3],
            0,
            vec![
                p2p([2, 2, 2, 2], [10, 0, 23, 3], 5),
                p2p([4, 4, 4, 4], [10, 0, 43, 3], 5),
                stub([192, 168, 3, 0], [255, 255, 255, 0], 1),
            ],
            1,
        ));

        let res = compute(&db, ip([1, 1, 1, 1]));
        assert_eq!(res.routers.get(&ip([3, 3, 3, 3])), Some(&15));

        // R3's stub is reachable via both R2's and R4's near ends.
        let far = find(&res, "192.168.3.0/24");
        assert_eq!(far.cost, 16);
        assert_eq!(far.gateways.len(), 2);
        assert!(far.gateways.contains(&ip([10, 0, 12, 2])));
        assert!(far.gateways.contains(&ip([10, 0, 14, 4])));
    }

    #[test]
    fn to_route_maps_protocol_and_nexthops() {
        let mut db = Lsdb::new();
        db.install(router_lsa(
            [1, 1, 1, 1],
            0,
            vec![
                p2p([2, 2, 2, 2], [10, 0, 12, 1], 10),
                stub([192, 168, 1, 0], [255, 255, 255, 0], 1),
            ],
            1,
        ));
        db.install(router_lsa(
            [2, 2, 2, 2],
            0,
            vec![
                p2p([1, 1, 1, 1], [10, 0, 12, 2], 10),
                stub([192, 168, 2, 0], [255, 255, 255, 0], 1),
            ],
            1,
        ));

        let routes = routes(&db, ip([1, 1, 1, 1]));
        let far = routes
            .iter()
            .find(|r| r.prefix.to_string() == "192.168.2.0/24")
            .unwrap();
        assert_eq!(far.protocol, Protocol::Ospf);
        assert_eq!(far.metric, 11);
        assert_eq!(far.preference, Protocol::Ospf.default_preference());
        assert_eq!(far.nexthops, vec![NextHop::via(IpAddr::V4(ip([10, 0, 12, 2])))]);

        // The connected stub maps to a single on-link next hop.
        let local = routes
            .iter()
            .find(|r| r.prefix.to_string() == "192.168.1.0/24")
            .unwrap();
        assert_eq!(local.nexthops, vec![NextHop { gateway: None, iface: None, weight: 1 }]);
    }

    /// A two-router area where R2 is an ABR injecting a summary for a far network.
    fn area_with_abr() -> Lsdb {
        let mut db = Lsdb::new();
        // R1 (root) ── p2p cost 10 ── R2 (the ABR).
        db.install(router_lsa(
            [1, 1, 1, 1],
            0,
            vec![p2p([2, 2, 2, 2], [10, 0, 12, 1], 10)],
            1,
        ));
        db.install(router_lsa(
            [2, 2, 2, 2],
            crate::lsa::RTR_FLAG_B,
            vec![p2p([1, 1, 1, 1], [10, 0, 12, 2], 10)],
            1,
        ));
        // The ABR summarises 192.168.99.0/24 (in another area) at cost 5.
        db.install(summary_lsa([2, 2, 2, 2], [192, 168, 99, 0], [255, 255, 255, 0], 5));
        db
    }

    #[test]
    fn inter_area_route_is_cost_to_abr_plus_summary() {
        let db = area_with_abr();
        let intra = compute(&db, ip([1, 1, 1, 1]));
        let inter = inter_area_routes(&db, &intra, ip([1, 1, 1, 1]));
        let r = inter
            .iter()
            .find(|r| r.prefix.to_string() == "192.168.99.0/24")
            .expect("inter-area route present");
        // 10 (to the ABR) + 5 (summary metric).
        assert_eq!(r.cost, 15);
        // Reached via the same next hop as the ABR (the p2p far end).
        assert_eq!(r.gateways, vec![ip([10, 0, 12, 2])]);
    }

    #[test]
    fn default_summary_yields_a_default_route() {
        // The stub-area mechanism (RFC 2328 §3.6): the ABR injects a 0.0.0.0/0
        // type-3 summary, which a stub router resolves into a default route via it.
        let mut db = area_with_abr();
        db.install(summary_lsa([2, 2, 2, 2], [0, 0, 0, 0], [0, 0, 0, 0], 5));
        let intra = compute(&db, ip([1, 1, 1, 1]));
        let inter = inter_area_routes(&db, &intra, ip([1, 1, 1, 1]));
        let def = inter
            .iter()
            .find(|r| r.prefix.to_string() == "0.0.0.0/0")
            .expect("default route present");
        assert_eq!(def.cost, 15); // 10 to the ABR + 5 default-cost
        assert_eq!(def.gateways, vec![ip([10, 0, 12, 2])]);
    }

    #[test]
    fn inter_area_skips_unreachable_infinity_and_self() {
        let mut db = area_with_abr();
        // A summary from an ABR not on the SPF tree → unreachable, skipped.
        db.install(summary_lsa([9, 9, 9, 9], [203, 0, 113, 0], [255, 255, 255, 0], 1));
        // A summary at LSInfinity → skipped.
        db.install(summary_lsa([2, 2, 2, 2], [198, 51, 100, 0], [255, 255, 255, 0], crate::LS_INFINITY));
        let intra = compute(&db, ip([1, 1, 1, 1]));
        let inter = inter_area_routes(&db, &intra, ip([1, 1, 1, 1]));
        let dests: Vec<String> = inter.iter().map(|r| r.prefix.to_string()).collect();
        assert!(dests.contains(&"192.168.99.0/24".to_string()));
        assert!(!dests.contains(&"203.0.113.0/24".to_string()), "unreachable ABR skipped");
        assert!(!dests.contains(&"198.51.100.0/24".to_string()), "LSInfinity skipped");

        // A summary we originated ourselves is skipped (self_id = the ABR).
        let self_inter = inter_area_routes(&db, &compute(&db, ip([2, 2, 2, 2])), ip([2, 2, 2, 2]));
        assert!(self_inter.iter().all(|r| r.prefix.to_string() != "192.168.99.0/24"));
    }

    /// A two-router area where R2 is an ASBR injecting an external destination.
    fn area_with_asbr() -> Lsdb {
        let mut db = Lsdb::new();
        db.install(router_lsa([1, 1, 1, 1], 0, vec![p2p([2, 2, 2, 2], [10, 0, 12, 1], 10)], 1));
        db.install(router_lsa(
            [2, 2, 2, 2],
            crate::lsa::RTR_FLAG_E,
            vec![p2p([1, 1, 1, 1], [10, 0, 12, 2], 10)],
            1,
        ));
        db
    }

    #[test]
    fn external_type2_cost_is_the_metric_alone() {
        let area = area_with_asbr();
        let intra = compute(&area, ip([1, 1, 1, 1]));
        // The type-5 LSAs live in their own AS-wide database.
        let mut ext = Lsdb::new();
        ext.install(external_lsa([2, 2, 2, 2], [203, 0, 113, 0], [255, 255, 255, 0], 20, true));
        let routes = external_routes(&ext, &intra, ip([1, 1, 1, 1]));
        let r = routes
            .iter()
            .find(|r| r.prefix.to_string() == "203.0.113.0/24")
            .expect("external route present");
        // E2: cost is the advertised metric, independent of the cost to the ASBR.
        assert_eq!(r.cost, 20);
        assert_eq!(r.gateways, vec![ip([10, 0, 12, 2])]);
    }

    #[test]
    fn nssa_type7_route_is_computed_like_an_external() {
        // R2 is the in-area NSSA ASBR; its type-7 lives in the AREA database.
        let mut db = area_with_asbr();
        db.install(nssa_lsa([2, 2, 2, 2], [10, 99, 0, 0], [255, 255, 255, 0], 20));
        let intra = compute(&db, ip([1, 1, 1, 1]));
        let routes = nssa_routes(&db, &intra, ip([1, 1, 1, 1]));
        let r = routes
            .iter()
            .find(|r| r.prefix.to_string() == "10.99.0.0/24")
            .expect("nssa route present");
        assert_eq!(r.cost, 20); // E2 metric alone
        assert_eq!(r.gateways, vec![ip([10, 0, 12, 2])]); // via the ASBR
        // The originating ASBR derives no route from its own type-7.
        let self_routes = nssa_routes(&db, &compute(&db, ip([2, 2, 2, 2])), ip([2, 2, 2, 2]));
        assert!(self_routes.iter().all(|r| r.prefix.to_string() != "10.99.0.0/24"));
    }

    #[test]
    fn external_type1_adds_cost_to_the_asbr() {
        let area = area_with_asbr();
        let intra = compute(&area, ip([1, 1, 1, 1]));
        let mut ext = Lsdb::new();
        ext.install(external_lsa([2, 2, 2, 2], [203, 0, 113, 0], [255, 255, 255, 0], 20, false));
        let routes = external_routes(&ext, &intra, ip([1, 1, 1, 1]));
        let r = routes.iter().find(|r| r.prefix.to_string() == "203.0.113.0/24").unwrap();
        // E1: 10 (to the ASBR) + 20 (metric).
        assert_eq!(r.cost, 30);
    }

    #[test]
    fn external_skips_unreachable_and_self() {
        let area = area_with_asbr();
        let mut ext = Lsdb::new();
        ext.install(external_lsa([9, 9, 9, 9], [198, 51, 100, 0], [255, 255, 255, 0], 20, true));
        // ASBR 9.9.9.9 is not on the tree → skipped.
        let intra = compute(&area, ip([1, 1, 1, 1]));
        assert!(external_routes(&ext, &intra, ip([1, 1, 1, 1])).is_empty());
        // From the ASBR's own perspective its self-originated LSA is skipped.
        let mut ours = Lsdb::new();
        ours.install(external_lsa([2, 2, 2, 2], [203, 0, 113, 0], [255, 255, 255, 0], 20, true));
        let intra2 = compute(&area, ip([2, 2, 2, 2]));
        assert!(external_routes(&ours, &intra2, ip([2, 2, 2, 2])).is_empty());
    }
}
