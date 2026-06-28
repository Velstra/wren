//! The intra-area shortest-path-first calculation (RFC 5340 §4.8) — a pure
//! Dijkstra over a single area's [`Lsdb`], plus the inter-area and AS-external
//! stages.
//!
//! OSPFv3 keeps OSPFv2's Dijkstra (RFC 2328 §16.1) but splits it in two, because
//! topology and addressing now live in different LSAs:
//!
//! * **The tree is built over the address-free graph.** Vertices are routers
//!   (from Router-LSAs) and transit networks (from Network-LSAs), exactly as in
//!   OSPFv2, but the edges carry *interface IDs* and *router IDs* — no addresses.
//!   A transit network is identified by `(DR router ID, DR interface ID)` (the
//!   Network-LSA's advertising router and Link State ID), not by an interface
//!   address. Each edge is checked for a matching link *back* (§16.1 step 2b) and
//!   MaxAge LSAs are ignored, so a half-converged database never poisons the tree.
//! * **Prefixes are attached afterwards** from the [`Intra-Area-Prefix-LSAs`]: each
//!   one references a Router- or Network-LSA on the tree, and contributes its
//!   prefixes at `vertex_distance + prefix_metric`. There are no stub links and no
//!   network masks to harvest as in OSPFv2 — *every* intra-area prefix arrives this
//!   way. Prefixes flagged `NU` (no-unicast) are skipped.
//!
//! Next hops are link-local IPv6 addresses (§4.8.2): a destination one hop from
//! the root takes the first-hop router's link-local address, read out of *its*
//! Link-LSA (`(Link, that router's interface ID, that router)` in the link-local
//! database), and anything deeper inherits the parent vertex's next hops. A
//! directly-attached network or a router whose Link-LSA we have not yet seen
//! yields an empty gateway set, i.e. an on-link (connected) route — the runner
//! pins the outgoing interface, which the LSDB alone cannot name.
//!
//! [`SpfResult`] also exposes the cost and next hops to reach every router vertex
//! (an ABR/ASBR lookup table) so the inter-area ([`inter_area_routes`]) and
//! AS-external ([`external_routes`]) stages can read them.
//!
//! This is the pure core: it reads two [`Lsdb`]s (the area database and the
//! link-local Link-LSA database) and returns [`wren_core::Route`]s, with no
//! sockets and no clock, so it is fully unit-testable from a hand-built database.

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use wren_core::{NextHop, Prefix, Protocol, Route};

use crate::lsa::{
    LsType, LsaBody, NetworkLsa, RouterLink, RouterLinkType, PREFIX_NU,
};
use crate::lsdb::Lsdb;
use crate::{LS_INFINITY, MAX_AGE};

/// A vertex of the shortest-path tree: a router (by Router ID) or a transit
/// network (by its DR's Router ID and Interface ID — the Network-LSA's
/// advertising router and Link State ID).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
enum Vertex {
    Router(Ipv4Addr),
    Network(Ipv4Addr, u32),
}

/// What is known about a settled (or candidate) vertex: its distance from the
/// root and the link-local next-hop gateways to reach it. An empty gateway set
/// means the vertex is directly attached to the root (a connected/on-link next
/// hop).
#[derive(Clone, Debug)]
struct VertexInfo {
    dist: u32,
    gateways: Vec<Ipv6Addr>,
}

/// One destination produced by the SPF: an intra-area (or, via the helper
/// functions, inter-area / external) IPv6 network route.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct SpfRoute {
    /// The destination network.
    pub prefix: Prefix,
    /// The total OSPF cost from the root.
    pub cost: u32,
    /// The link-local next-hop gateway addresses. Empty means the destination is
    /// directly attached to the root (a connected/on-link route whose outgoing
    /// interface the runner resolves).
    pub gateways: Vec<Ipv6Addr>,
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
                .map(|g| NextHop::via(IpAddr::V6(*g)))
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
    pub router_nexthops: BTreeMap<Ipv4Addr, Vec<Ipv6Addr>>,
}

/// Run the intra-area SPF over the area database `area`, using `links` (the
/// link-local Link-LSA database) to resolve next-hop addresses, rooted at `root`.
pub fn compute(area: &Lsdb, links: &Lsdb, root: Ipv4Addr) -> SpfResult {
    Spf { area, links, root }.run()
}

/// Convenience: run the SPF and hand back ready-to-announce [`wren_core::Route`]s.
pub fn routes(area: &Lsdb, links: &Lsdb, root: Ipv4Addr) -> Vec<Route> {
    compute(area, links, root)
        .routes
        .iter()
        .map(SpfRoute::to_route)
        .collect()
}

/// The inter-area routes for one area (RFC 5340 §4.8.4): examine the
/// Inter-Area-Prefix-LSAs (the OSPFv3 type-3 summaries) in `area` and, for each,
/// add the cost the originating ABR advertised to the intra-area cost of reaching
/// that ABR (from `intra`, the SPF result for the *same* area). The next hops are
/// inherited from the path to the ABR.
///
/// Summaries this router originated itself (`self_id`), unreachable ones (an ABR
/// not on the SPF tree), LSInfinity, MaxAge and `NU` prefixes are skipped. The
/// caller lets a more-preferred (intra-area) route to the same prefix win — these
/// routes carry the inter-area cost only.
pub fn inter_area_routes(area: &Lsdb, intra: &SpfResult, self_id: Ipv4Addr) -> Vec<SpfRoute> {
    let mut by_prefix: BTreeMap<Prefix, SpfRoute> = BTreeMap::new();
    for lsa in area.iter_type(LsType::InterAreaPrefix) {
        let LsaBody::InterAreaPrefix(summary) = &lsa.body else {
            continue;
        };
        let abr = lsa.header.advertising_router;
        if abr == self_id || summary.metric >= LS_INFINITY || lsa.header.ls_age >= MAX_AGE {
            continue;
        }
        if summary.prefix.options & PREFIX_NU != 0 {
            continue;
        }
        // The ABR must be reachable within this area.
        let Some(&cost_to_abr) = intra.routers.get(&abr) else {
            continue;
        };
        let total = cost_to_abr.saturating_add(summary.metric);
        let Some(prefix) = to_core_prefix(&summary.prefix) else {
            continue;
        };
        let gateways = intra.router_nexthops.get(&abr).cloned().unwrap_or_default();
        add_route(&mut by_prefix, prefix, total, &gateways);
    }
    by_prefix.into_values().collect()
}

/// The AS-external routes (RFC 5340 §4.8.5): examine the AS-External-LSAs in
/// `area` (the AS-wide external database) and, for each, compute the route. With a
/// type-1 (E1) external metric the cost is the intra-area cost of reaching the
/// originating ASBR plus the advertised metric; with type-2 (E2) the cost is the
/// advertised metric alone (E2 always outranks any internal cost). The next hops
/// are inherited from the path to the ASBR.
///
/// Only an absent forwarding address (forward via the ASBR) is handled here; an
/// explicit forwarding address (resolved against the routing table) is a
/// refinement. Self-originated, unreachable, MaxAge, LSInfinity and `NU` LSAs are
/// skipped. As with [`inter_area_routes`], the caller lets more-preferred routes
/// win.
pub fn external_routes(area: &Lsdb, intra: &SpfResult, self_id: Ipv4Addr) -> Vec<SpfRoute> {
    let mut by_prefix: BTreeMap<Prefix, SpfRoute> = BTreeMap::new();
    for lsa in area.iter_type(LsType::AsExternal) {
        let LsaBody::AsExternal(ext) = &lsa.body else {
            continue;
        };
        let asbr = lsa.header.advertising_router;
        if asbr == self_id || ext.metric >= LS_INFINITY || lsa.header.ls_age >= MAX_AGE {
            continue;
        }
        // Only "forward via the ASBR" (no explicit forwarding address) is handled.
        if ext.forwarding_address.is_some() {
            continue;
        }
        if ext.prefix.options & PREFIX_NU != 0 {
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
        let Some(prefix) = to_core_prefix(&ext.prefix) else {
            continue;
        };
        let gateways = intra.router_nexthops.get(&asbr).cloned().unwrap_or_default();
        add_route(&mut by_prefix, prefix, total, &gateways);
    }
    by_prefix.into_values().collect()
}

struct Spf<'a> {
    area: &'a Lsdb,
    links: &'a Lsdb,
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
    /// (§16.1 step 2). Each is returned with the cost of the edge from `v`.
    fn neighbors(&self, v: Vertex) -> Vec<(Vertex, u32)> {
        let mut out = Vec::new();
        match v {
            Vertex::Router(rid) => {
                for l in self.router_links(rid) {
                    match l.link_type {
                        RouterLinkType::PointToPoint | RouterLinkType::Virtual => {
                            let w = l.neighbor_router_id;
                            if self.router_alive(w) && self.router_links_to_router(w, rid) {
                                out.push((Vertex::Router(w), l.metric as u32));
                            }
                        }
                        RouterLinkType::Transit => {
                            let dr_rid = l.neighbor_router_id;
                            let dr_if = l.neighbor_interface_id;
                            if self.network_alive(dr_rid, dr_if)
                                && self.network_lists_router(dr_rid, dr_if, rid)
                            {
                                out.push((Vertex::Network(dr_rid, dr_if), l.metric as u32));
                            }
                        }
                    }
                }
            }
            Vertex::Network(dr_rid, dr_if) => {
                if let Some(nl) = self.network_lsa(dr_rid, dr_if) {
                    for &w in &nl.attached_routers {
                        if self.router_alive(w) && self.router_links_to_network(w, dr_rid, dr_if) {
                            out.push((Vertex::Router(w), 0));
                        }
                    }
                }
            }
        }
        out
    }

    /// The next-hop gateways for child `w` reached from parent `v` (§4.8.2).
    /// A parent with gateways already set passes them down unchanged; a parent
    /// that is the root or a directly-attached network resolves a fresh gateway —
    /// the neighbour's own link-local address, read from its Link-LSA.
    fn initial_gateways(&self, v: Vertex, v_gateways: &[Ipv6Addr], w: Vertex) -> Vec<Ipv6Addr> {
        if !v_gateways.is_empty() {
            return v_gateways.to_vec();
        }
        match (v, w) {
            // Root reaches a point-to-point neighbour: its gateway is that
            // neighbour's link-local address on the shared link. The link is named
            // by the neighbour's Interface ID, which the root's own link records.
            (Vertex::Router(rid), Vertex::Router(w_id)) if rid == self.root => self
                .root_neighbor_interface_id(w_id)
                .and_then(|if_id| self.link_local_of(w_id, if_id))
                .map(|a| vec![a])
                .unwrap_or_default(),
            // A network one hop from the root: connected (no gateway).
            (Vertex::Router(rid), Vertex::Network(..)) if rid == self.root => vec![],
            // A router across a directly-attached network: its gateway is its own
            // link-local address on that network (from its Link-LSA, keyed by the
            // interface ID it uses on the network).
            (Vertex::Network(dr_rid, dr_if), Vertex::Router(w_id)) => self
                .router_interface_on_network(w_id, dr_rid, dr_if)
                .and_then(|if_id| self.link_local_of(w_id, if_id))
                .map(|a| vec![a])
                .unwrap_or_default(),
            _ => vec![],
        }
    }

    /// Build the route set from the settled tree: every Intra-Area-Prefix-LSA that
    /// references a vertex on the tree contributes its prefixes at the vertex's
    /// distance plus the prefix metric, de-duplicated keeping the lowest cost and
    /// merging equal-cost next hops.
    fn harvest(&self, tree: &BTreeMap<Vertex, VertexInfo>) -> SpfResult {
        let mut by_prefix: BTreeMap<Prefix, SpfRoute> = BTreeMap::new();
        let mut routers: BTreeMap<Ipv4Addr, u32> = BTreeMap::new();
        let mut router_nexthops: BTreeMap<Ipv4Addr, Vec<Ipv6Addr>> = BTreeMap::new();

        for (vertex, info) in tree {
            if let Vertex::Router(rid) = vertex {
                routers.insert(*rid, info.dist);
                router_nexthops.insert(*rid, info.gateways.clone());
            }
            for prefixes in self.intra_prefixes_for(*vertex) {
                for entry in prefixes {
                    if entry.prefix.options & PREFIX_NU != 0 {
                        continue;
                    }
                    let Some(prefix) = to_core_prefix(&entry.prefix) else {
                        continue;
                    };
                    add_route(
                        &mut by_prefix,
                        prefix,
                        info.dist + entry.metric as u32,
                        &info.gateways,
                    );
                }
            }
        }

        SpfResult {
            routes: by_prefix.into_values().collect(),
            routers,
            router_nexthops,
        }
    }

    /// Every Intra-Area-Prefix-LSA prefix list that references `vertex` — a
    /// Router-LSA (referenced Link State ID 0, advertising router = the router) or
    /// a Network-LSA (referenced Link State ID = the DR's interface ID,
    /// advertising router = the DR).
    fn intra_prefixes_for(&self, vertex: Vertex) -> Vec<&[crate::lsa::IntraPrefix]> {
        let (want_type, want_lsid, want_adv) = match vertex {
            Vertex::Router(rid) => (LsType::Router.as_u16(), Ipv4Addr::UNSPECIFIED, rid),
            Vertex::Network(dr_rid, dr_if) => {
                (LsType::Network.as_u16(), Ipv4Addr::from(dr_if), dr_rid)
            }
        };
        self.area
            .iter_type(LsType::IntraAreaPrefix)
            .filter_map(move |lsa| {
                if lsa.header.ls_age >= MAX_AGE {
                    return None;
                }
                let LsaBody::IntraAreaPrefix(p) = &lsa.body else {
                    return None;
                };
                if p.referenced_ls_type == want_type
                    && p.referenced_link_state_id == want_lsid
                    && p.referenced_advertising_router == want_adv
                {
                    Some(p.prefixes.as_slice())
                } else {
                    None
                }
            })
            .collect()
    }

    // --- LSDB lookups ------------------------------------------------------

    /// Every link a router advertises, aggregated across all of its (non-MaxAge)
    /// Router-LSAs — OSPFv3 lets a router split its links over several Router-LSAs
    /// distinguished by Link State ID (§3.4.3.1).
    fn router_links(&self, rid: Ipv4Addr) -> Vec<RouterLink> {
        let mut out = Vec::new();
        for lsa in self.area.iter_type(LsType::Router) {
            if lsa.header.advertising_router == rid && lsa.header.ls_age < MAX_AGE {
                if let LsaBody::Router(r) = &lsa.body {
                    out.extend_from_slice(&r.links);
                }
            }
        }
        out
    }

    /// A transit network's Network-LSA body, keyed by the DR's `(interface ID,
    /// router ID)`, if present and not MaxAge.
    fn network_lsa(&self, dr_rid: Ipv4Addr, dr_if: u32) -> Option<&NetworkLsa> {
        let lsa = self
            .area
            .get(&(LsType::Network, Ipv4Addr::from(dr_if), dr_rid))?;
        if lsa.header.ls_age >= MAX_AGE {
            return None;
        }
        match &lsa.body {
            LsaBody::Network(n) => Some(n),
            _ => None,
        }
    }

    /// Whether a router has any present, non-MaxAge Router-LSA.
    fn router_alive(&self, rid: Ipv4Addr) -> bool {
        self.area.iter_type(LsType::Router).any(|lsa| {
            lsa.header.advertising_router == rid && lsa.header.ls_age < MAX_AGE
        })
    }

    /// Whether a transit network's Network-LSA is present and not MaxAge.
    fn network_alive(&self, dr_rid: Ipv4Addr, dr_if: u32) -> bool {
        self.network_lsa(dr_rid, dr_if).is_some()
    }

    /// Whether router `w` advertises a point-to-point/virtual link back to `v`.
    fn router_links_to_router(&self, w: Ipv4Addr, v: Ipv4Addr) -> bool {
        self.router_links(w).iter().any(|l| {
            matches!(
                l.link_type,
                RouterLinkType::PointToPoint | RouterLinkType::Virtual
            ) && l.neighbor_router_id == v
        })
    }

    /// Whether router `w` advertises a transit link onto the network whose DR is
    /// `(dr_rid, dr_if)`.
    fn router_links_to_network(&self, w: Ipv4Addr, dr_rid: Ipv4Addr, dr_if: u32) -> bool {
        self.router_links(w).iter().any(|l| {
            l.link_type == RouterLinkType::Transit
                && l.neighbor_router_id == dr_rid
                && l.neighbor_interface_id == dr_if
        })
    }

    /// Whether the network `(dr_rid, dr_if)` lists router `rid` among its attached
    /// routers.
    fn network_lists_router(&self, dr_rid: Ipv4Addr, dr_if: u32, rid: Ipv4Addr) -> bool {
        self.network_lsa(dr_rid, dr_if)
            .is_some_and(|nl| nl.attached_routers.contains(&rid))
    }

    /// The neighbour's Interface ID on the point-to-point link from the root to
    /// `w` — the Interface ID that names `w`'s Link-LSA on the shared link.
    fn root_neighbor_interface_id(&self, w: Ipv4Addr) -> Option<u32> {
        self.router_links(self.root)
            .iter()
            .find(|l| {
                matches!(
                    l.link_type,
                    RouterLinkType::PointToPoint | RouterLinkType::Virtual
                ) && l.neighbor_router_id == w
            })
            .map(|l| l.neighbor_interface_id)
    }

    /// Router `w`'s own Interface ID on the transit network whose DR is
    /// `(dr_rid, dr_if)` — the Interface ID that names `w`'s Link-LSA there.
    fn router_interface_on_network(
        &self,
        w: Ipv4Addr,
        dr_rid: Ipv4Addr,
        dr_if: u32,
    ) -> Option<u32> {
        self.router_links(w)
            .iter()
            .find(|l| {
                l.link_type == RouterLinkType::Transit
                    && l.neighbor_router_id == dr_rid
                    && l.neighbor_interface_id == dr_if
            })
            .map(|l| l.interface_id)
    }

    /// Router `router`'s link-local address on the link whose Interface ID (on
    /// that router) is `interface_id`, read from its Link-LSA. `None` if the
    /// Link-LSA has not been received (then the route falls back to on-link).
    fn link_local_of(&self, router: Ipv4Addr, interface_id: u32) -> Option<Ipv6Addr> {
        let lsa = self
            .links
            .get(&(LsType::Link, Ipv4Addr::from(interface_id), router))?;
        if lsa.header.ls_age >= MAX_AGE {
            return None;
        }
        match &lsa.body {
            LsaBody::Link(l) => Some(l.link_local_address),
            _ => None,
        }
    }
}

/// Convert an OSPFv3 wire prefix into a [`wren_core::Prefix`].
fn to_core_prefix(p: &crate::lsa::Prefix) -> Option<Prefix> {
    Prefix::new(IpAddr::V6(p.ipv6()), p.length).ok()
}

/// Insert or fold a route into the by-prefix table: a strictly lower cost
/// replaces, an equal cost merges next hops (ECMP), a higher cost is dropped.
fn add_route(map: &mut BTreeMap<Prefix, SpfRoute>, prefix: Prefix, cost: u32, gateways: &[Ipv6Addr]) {
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
fn merge_gateways(into: &mut Vec<Ipv6Addr>, extra: &[Ipv6Addr]) {
    for g in extra {
        if !into.contains(g) {
            into.push(*g);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lsa::{
        AsExternalLsa, InterAreaPrefixLsa, IntraAreaPrefixLsa, IntraPrefix, LinkLsa, Lsa, LsaBody,
        LsaHeader, NetworkLsa, RouterLsa,
    };
    use crate::{INITIAL_SEQUENCE_NUMBER, OPT_R, OPT_V6};

    fn rid(o: [u8; 4]) -> Ipv4Addr {
        Ipv4Addr::from(o)
    }

    fn hdr(ls_type: LsType, lsid: Ipv4Addr, adv: Ipv4Addr, age: u16) -> LsaHeader {
        LsaHeader {
            ls_age: age,
            ls_type,
            link_state_id: lsid,
            advertising_router: adv,
            ls_seq: INITIAL_SEQUENCE_NUMBER,
            ls_checksum: 0,
            length: 0,
        }
    }

    fn router_lsa(r: [u8; 4], flags: u8, links: Vec<RouterLink>, age: u16) -> Lsa {
        Lsa {
            header: hdr(LsType::Router, Ipv4Addr::UNSPECIFIED, rid(r), age),
            body: LsaBody::Router(RouterLsa {
                flags,
                options: OPT_V6 | OPT_R,
                links,
            }),
        }
    }

    fn network_lsa(dr: [u8; 4], dr_if: u32, routers: Vec<[u8; 4]>) -> Lsa {
        Lsa {
            header: hdr(LsType::Network, Ipv4Addr::from(dr_if), rid(dr), 0),
            body: LsaBody::Network(NetworkLsa {
                options: OPT_V6 | OPT_R,
                attached_routers: routers.into_iter().map(rid).collect(),
            }),
        }
    }

    fn link_lsa(router: [u8; 4], if_id: u32, lla: Ipv6Addr) -> Lsa {
        Lsa {
            header: hdr(LsType::Link, Ipv4Addr::from(if_id), rid(router), 0),
            body: LsaBody::Link(LinkLsa {
                router_priority: 1,
                options: OPT_V6 | OPT_R,
                link_local_address: lla,
                prefixes: vec![],
            }),
        }
    }

    fn intra_router(router: [u8; 4], prefixes: Vec<IntraPrefix>) -> Lsa {
        Lsa {
            header: hdr(LsType::IntraAreaPrefix, rid([0, 0, 0, 1]), rid(router), 0),
            body: LsaBody::IntraAreaPrefix(IntraAreaPrefixLsa {
                referenced_ls_type: LsType::Router.as_u16(),
                referenced_link_state_id: Ipv4Addr::UNSPECIFIED,
                referenced_advertising_router: rid(router),
                prefixes,
            }),
        }
    }

    fn intra_network(dr: [u8; 4], dr_if: u32, prefixes: Vec<IntraPrefix>) -> Lsa {
        Lsa {
            header: hdr(LsType::IntraAreaPrefix, rid([0, 0, 0, 9]), rid(dr), 0),
            body: LsaBody::IntraAreaPrefix(IntraAreaPrefixLsa {
                referenced_ls_type: LsType::Network.as_u16(),
                referenced_link_state_id: Ipv4Addr::from(dr_if),
                referenced_advertising_router: rid(dr),
                prefixes,
            }),
        }
    }

    fn p2p(nbr: [u8; 4], my_if: u32, nbr_if: u32, metric: u16) -> RouterLink {
        RouterLink {
            link_type: RouterLinkType::PointToPoint,
            metric,
            interface_id: my_if,
            neighbor_interface_id: nbr_if,
            neighbor_router_id: rid(nbr),
        }
    }

    fn transit(dr: [u8; 4], dr_if: u32, my_if: u32, metric: u16) -> RouterLink {
        RouterLink {
            link_type: RouterLinkType::Transit,
            metric,
            interface_id: my_if,
            neighbor_interface_id: dr_if,
            neighbor_router_id: rid(dr),
        }
    }

    fn prefix(addr: Ipv6Addr, len: u8, metric: u16) -> IntraPrefix {
        IntraPrefix {
            metric,
            prefix: crate::lsa::Prefix::from_ipv6(addr, len, 0),
        }
    }

    fn p(s: &str) -> Prefix {
        s.parse().unwrap()
    }

    fn find<'a>(res: &'a SpfResult, s: &str) -> &'a SpfRoute {
        let want = p(s);
        res.routes
            .iter()
            .find(|r| r.prefix == want)
            .unwrap_or_else(|| panic!("no route for {s}"))
    }

    /// fe80::<n>
    fn ll(n: u16) -> Ipv6Addr {
        Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, n)
    }

    #[test]
    fn point_to_point_reaches_neighbour_prefix_via_link_local() {
        let mut area = Lsdb::new();
        let mut links = Lsdb::new();
        // R1 <--cost10--> R2 (R1 if 1, R2 if 2), each with its own /64.
        area.install(router_lsa([1, 1, 1, 1], 0, vec![p2p([2, 2, 2, 2], 1, 2, 10)], 1));
        area.install(router_lsa([2, 2, 2, 2], 0, vec![p2p([1, 1, 1, 1], 2, 1, 10)], 1));
        area.install(intra_router(
            [1, 1, 1, 1],
            vec![prefix(Ipv6Addr::new(0x2001, 0xdb8, 1, 0, 0, 0, 0, 0), 64, 0)],
        ));
        area.install(intra_router(
            [2, 2, 2, 2],
            vec![prefix(Ipv6Addr::new(0x2001, 0xdb8, 2, 0, 0, 0, 0, 0), 64, 0)],
        ));
        // R2's link-local address on its interface 2 (the shared link).
        links.install(link_lsa([2, 2, 2, 2], 2, ll(2)));

        let res = compute(&area, &links, rid([1, 1, 1, 1]));

        // Root's own prefix is connected (no gateway).
        let local = find(&res, "2001:db8:1::/64");
        assert_eq!(local.cost, 0);
        assert!(local.gateways.is_empty());

        // The far prefix: cost 10, via R2's link-local address.
        let far = find(&res, "2001:db8:2::/64");
        assert_eq!(far.cost, 10);
        assert_eq!(far.gateways, vec![ll(2)]);

        assert_eq!(res.routers.get(&rid([2, 2, 2, 2])), Some(&10));
        assert_eq!(res.routers.get(&rid([1, 1, 1, 1])), Some(&0));
    }

    #[test]
    fn transit_network_is_connected_and_relays_to_other_router() {
        let mut area = Lsdb::new();
        let mut links = Lsdb::new();
        // R1 (DR, interface id 1) and R2 (interface id 2) share a broadcast LAN.
        area.install(router_lsa(
            [1, 1, 1, 1],
            0,
            vec![transit([1, 1, 1, 1], 1, 1, 1)],
            1,
        ));
        area.install(router_lsa(
            [2, 2, 2, 2],
            0,
            vec![transit([1, 1, 1, 1], 1, 2, 1)],
            1,
        ));
        area.install(network_lsa([1, 1, 1, 1], 1, vec![[1, 1, 1, 1], [2, 2, 2, 2]]));
        // The LAN's prefix hangs off the DR's Network-LSA (metric 0).
        area.install(intra_network(
            [1, 1, 1, 1],
            1,
            vec![prefix(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0), 64, 0)],
        ));
        // R2's own /64 behind it.
        area.install(intra_router(
            [2, 2, 2, 2],
            vec![prefix(Ipv6Addr::new(0x2001, 0xdb8, 2, 0, 0, 0, 0, 0), 64, 5)],
        ));
        // R2's link-local address on its interface 2.
        links.install(link_lsa([2, 2, 2, 2], 2, ll(2)));

        let res = compute(&area, &links, rid([1, 1, 1, 1]));

        // The transit LAN itself is a connected route at the link cost.
        let lan = find(&res, "2001:db8::/64");
        assert_eq!(lan.cost, 1);
        assert!(lan.gateways.is_empty());

        // R2's prefix: 1 (root->net) + 0 (net->R2) + 5, via R2's link-local addr.
        let far = find(&res, "2001:db8:2::/64");
        assert_eq!(far.cost, 6);
        assert_eq!(far.gateways, vec![ll(2)]);
        assert_eq!(res.routers.get(&rid([2, 2, 2, 2])), Some(&1));
    }

    #[test]
    fn one_way_link_is_ignored() {
        let mut area = Lsdb::new();
        let links = Lsdb::new();
        // R1 claims a link to R2, but R2 never claims one back.
        area.install(router_lsa([1, 1, 1, 1], 0, vec![p2p([2, 2, 2, 2], 1, 2, 10)], 1));
        area.install(router_lsa([2, 2, 2, 2], 0, vec![], 1));
        area.install(intra_router(
            [2, 2, 2, 2],
            vec![prefix(Ipv6Addr::new(0x2001, 0xdb8, 2, 0, 0, 0, 0, 0), 64, 0)],
        ));

        let res = compute(&area, &links, rid([1, 1, 1, 1]));
        assert_eq!(res.routers.get(&rid([2, 2, 2, 2])), None);
        assert!(res.routes.iter().all(|r| r.prefix != p("2001:db8:2::/64")));
    }

    #[test]
    fn maxage_router_is_excluded() {
        let mut area = Lsdb::new();
        let links = Lsdb::new();
        area.install(router_lsa([1, 1, 1, 1], 0, vec![p2p([2, 2, 2, 2], 1, 2, 10)], 1));
        // R2's Router-LSA has aged out.
        area.install(router_lsa(
            [2, 2, 2, 2],
            0,
            vec![p2p([1, 1, 1, 1], 2, 1, 10)],
            MAX_AGE,
        ));
        area.install(intra_router(
            [2, 2, 2, 2],
            vec![prefix(Ipv6Addr::new(0x2001, 0xdb8, 2, 0, 0, 0, 0, 0), 64, 0)],
        ));

        let res = compute(&area, &links, rid([1, 1, 1, 1]));
        assert_eq!(res.routers.get(&rid([2, 2, 2, 2])), None);
        assert!(res.routes.iter().all(|r| r.prefix != p("2001:db8:2::/64")));
    }

    #[test]
    fn nu_prefix_is_skipped() {
        let mut area = Lsdb::new();
        let links = Lsdb::new();
        area.install(router_lsa([1, 1, 1, 1], 0, vec![], 1));
        area.install(intra_router(
            [1, 1, 1, 1],
            vec![IntraPrefix {
                metric: 0,
                prefix: crate::lsa::Prefix::from_ipv6(
                    Ipv6Addr::new(0x2001, 0xdb8, 0xbad, 0, 0, 0, 0, 0),
                    64,
                    crate::lsa::PREFIX_NU,
                ),
            }],
        ));
        let res = compute(&area, &links, rid([1, 1, 1, 1]));
        assert!(res.routes.is_empty(), "NU prefix must not become a route");
    }

    #[test]
    fn equal_cost_paths_merge_into_ecmp() {
        let mut area = Lsdb::new();
        let mut links = Lsdb::new();
        // R1 reaches R3 two ways at equal cost: via R2 and via R4.
        area.install(router_lsa(
            [1, 1, 1, 1],
            0,
            vec![p2p([2, 2, 2, 2], 12, 21, 10), p2p([4, 4, 4, 4], 14, 41, 10)],
            1,
        ));
        area.install(router_lsa(
            [2, 2, 2, 2],
            0,
            vec![p2p([1, 1, 1, 1], 21, 12, 10), p2p([3, 3, 3, 3], 23, 32, 5)],
            1,
        ));
        area.install(router_lsa(
            [4, 4, 4, 4],
            0,
            vec![p2p([1, 1, 1, 1], 41, 14, 10), p2p([3, 3, 3, 3], 43, 34, 5)],
            1,
        ));
        area.install(router_lsa(
            [3, 3, 3, 3],
            0,
            vec![p2p([2, 2, 2, 2], 32, 23, 5), p2p([4, 4, 4, 4], 34, 43, 5)],
            1,
        ));
        area.install(intra_router(
            [3, 3, 3, 3],
            vec![prefix(Ipv6Addr::new(0x2001, 0xdb8, 3, 0, 0, 0, 0, 0), 64, 1)],
        ));
        // R2's and R4's link-local addresses on their interfaces facing R1.
        links.install(link_lsa([2, 2, 2, 2], 21, ll(2)));
        links.install(link_lsa([4, 4, 4, 4], 41, ll(4)));

        let res = compute(&area, &links, rid([1, 1, 1, 1]));
        assert_eq!(res.routers.get(&rid([3, 3, 3, 3])), Some(&15));

        let far = find(&res, "2001:db8:3::/64");
        assert_eq!(far.cost, 16);
        assert_eq!(far.gateways.len(), 2);
        assert!(far.gateways.contains(&ll(2)));
        assert!(far.gateways.contains(&ll(4)));
    }

    #[test]
    fn to_route_maps_protocol_and_nexthops() {
        let mut area = Lsdb::new();
        let mut links = Lsdb::new();
        area.install(router_lsa([1, 1, 1, 1], 0, vec![p2p([2, 2, 2, 2], 1, 2, 10)], 1));
        area.install(router_lsa([2, 2, 2, 2], 0, vec![p2p([1, 1, 1, 1], 2, 1, 10)], 1));
        area.install(intra_router(
            [1, 1, 1, 1],
            vec![prefix(Ipv6Addr::new(0x2001, 0xdb8, 1, 0, 0, 0, 0, 0), 64, 0)],
        ));
        area.install(intra_router(
            [2, 2, 2, 2],
            vec![prefix(Ipv6Addr::new(0x2001, 0xdb8, 2, 0, 0, 0, 0, 0), 64, 0)],
        ));
        links.install(link_lsa([2, 2, 2, 2], 2, ll(2)));

        let rts = routes(&area, &links, rid([1, 1, 1, 1]));
        let far = rts
            .iter()
            .find(|r| r.prefix == p("2001:db8:2::/64"))
            .unwrap();
        assert_eq!(far.protocol, Protocol::Ospf);
        assert_eq!(far.metric, 10);
        assert_eq!(far.preference, Protocol::Ospf.default_preference());
        assert_eq!(far.nexthops, vec![NextHop::via(IpAddr::V6(ll(2)))]);

        // The connected prefix maps to a single on-link next hop.
        let local = rts
            .iter()
            .find(|r| r.prefix == p("2001:db8:1::/64"))
            .unwrap();
        assert_eq!(
            local.nexthops,
            vec![NextHop {
                gateway: None,
                iface: None,
                weight: 1
            }]
        );
    }

    /// A two-router area where R2 is an ABR injecting an inter-area prefix.
    fn area_with_abr() -> Lsdb {
        let mut area = Lsdb::new();
        area.install(router_lsa([1, 1, 1, 1], 0, vec![p2p([2, 2, 2, 2], 1, 2, 10)], 1));
        area.install(router_lsa(
            [2, 2, 2, 2],
            crate::lsa::RTR_FLAG_B,
            vec![p2p([1, 1, 1, 1], 2, 1, 10)],
            1,
        ));
        // The ABR summarises 2001:db8:99::/64 (another area) at cost 5.
        area.install(Lsa {
            header: hdr(LsType::InterAreaPrefix, rid([0, 0, 0, 1]), rid([2, 2, 2, 2]), 1),
            body: LsaBody::InterAreaPrefix(InterAreaPrefixLsa {
                metric: 5,
                prefix: crate::lsa::Prefix::from_ipv6(
                    Ipv6Addr::new(0x2001, 0xdb8, 0x99, 0, 0, 0, 0, 0),
                    64,
                    0,
                ),
            }),
        });
        area
    }

    #[test]
    fn inter_area_route_is_cost_to_abr_plus_summary() {
        let area = area_with_abr();
        let mut links = Lsdb::new();
        links.install(link_lsa([2, 2, 2, 2], 2, ll(2)));
        let intra = compute(&area, &links, rid([1, 1, 1, 1]));
        let inter = inter_area_routes(&area, &intra, rid([1, 1, 1, 1]));
        let r = inter
            .iter()
            .find(|r| r.prefix == p("2001:db8:99::/64"))
            .expect("inter-area route present");
        assert_eq!(r.cost, 15); // 10 (to ABR) + 5 (summary)
        assert_eq!(r.gateways, vec![ll(2)]);
    }

    #[test]
    fn inter_area_skips_unreachable_infinity_and_self() {
        let mut area = area_with_abr();
        // A summary from an ABR not on the SPF tree → unreachable, skipped.
        area.install(Lsa {
            header: hdr(LsType::InterAreaPrefix, rid([0, 0, 0, 2]), rid([9, 9, 9, 9]), 1),
            body: LsaBody::InterAreaPrefix(InterAreaPrefixLsa {
                metric: 1,
                prefix: crate::lsa::Prefix::from_ipv6(
                    Ipv6Addr::new(0x2001, 0xdb8, 0x77, 0, 0, 0, 0, 0),
                    64,
                    0,
                ),
            }),
        });
        // A summary at LSInfinity → skipped.
        area.install(Lsa {
            header: hdr(LsType::InterAreaPrefix, rid([0, 0, 0, 3]), rid([2, 2, 2, 2]), 1),
            body: LsaBody::InterAreaPrefix(InterAreaPrefixLsa {
                metric: LS_INFINITY,
                prefix: crate::lsa::Prefix::from_ipv6(
                    Ipv6Addr::new(0x2001, 0xdb8, 0x66, 0, 0, 0, 0, 0),
                    64,
                    0,
                ),
            }),
        });
        let links = Lsdb::new();
        let intra = compute(&area, &links, rid([1, 1, 1, 1]));
        let inter = inter_area_routes(&area, &intra, rid([1, 1, 1, 1]));
        let dests: Vec<Prefix> = inter.iter().map(|r| r.prefix).collect();
        assert!(dests.contains(&p("2001:db8:99::/64")));
        assert!(!dests.contains(&p("2001:db8:77::/64")), "unreachable ABR skipped");
        assert!(!dests.contains(&p("2001:db8:66::/64")), "LSInfinity skipped");

        // A summary we originated ourselves is skipped (self_id = the ABR).
        let self_intra = compute(&area, &links, rid([2, 2, 2, 2]));
        let self_inter = inter_area_routes(&area, &self_intra, rid([2, 2, 2, 2]));
        assert!(self_inter.iter().all(|r| r.prefix != p("2001:db8:99::/64")));
    }

    /// A two-router area where R2 is an ASBR.
    fn area_with_asbr() -> Lsdb {
        let mut area = Lsdb::new();
        area.install(router_lsa([1, 1, 1, 1], 0, vec![p2p([2, 2, 2, 2], 1, 2, 10)], 1));
        area.install(router_lsa(
            [2, 2, 2, 2],
            crate::lsa::RTR_FLAG_E,
            vec![p2p([1, 1, 1, 1], 2, 1, 10)],
            1,
        ));
        area
    }

    fn external_lsa(asbr: [u8; 4], net: Ipv6Addr, len: u8, metric: u32, e2: bool) -> Lsa {
        Lsa {
            header: hdr(LsType::AsExternal, rid([0, 0, 0, 1]), rid(asbr), 1),
            body: LsaBody::AsExternal(AsExternalLsa {
                external_type2: e2,
                metric,
                prefix: crate::lsa::Prefix::from_ipv6(net, len, 0),
                forwarding_address: None,
                route_tag: None,
                referenced_ls_type: 0,
                referenced_link_state_id: None,
            }),
        }
    }

    #[test]
    fn external_type2_cost_is_the_metric_alone() {
        let area = area_with_asbr();
        let mut links = Lsdb::new();
        links.install(link_lsa([2, 2, 2, 2], 2, ll(2)));
        let intra = compute(&area, &links, rid([1, 1, 1, 1]));
        // The AS-external LSAs live in the AS-wide database (here, the area db).
        let mut ext = Lsdb::new();
        ext.install(external_lsa(
            [2, 2, 2, 2],
            Ipv6Addr::new(0x2001, 0xdb8, 0xaa, 0, 0, 0, 0, 0),
            64,
            20,
            true,
        ));
        let rts = external_routes(&ext, &intra, rid([1, 1, 1, 1]));
        let r = rts
            .iter()
            .find(|r| r.prefix == p("2001:db8:aa::/64"))
            .expect("external route present");
        assert_eq!(r.cost, 20); // E2: the metric alone
        assert_eq!(r.gateways, vec![ll(2)]);
    }

    #[test]
    fn external_type1_adds_cost_to_the_asbr() {
        let area = area_with_asbr();
        let mut links = Lsdb::new();
        links.install(link_lsa([2, 2, 2, 2], 2, ll(2)));
        let intra = compute(&area, &links, rid([1, 1, 1, 1]));
        let mut ext = Lsdb::new();
        ext.install(external_lsa(
            [2, 2, 2, 2],
            Ipv6Addr::new(0x2001, 0xdb8, 0xaa, 0, 0, 0, 0, 0),
            64,
            20,
            false,
        ));
        let rts = external_routes(&ext, &intra, rid([1, 1, 1, 1]));
        let r = rts.iter().find(|r| r.prefix == p("2001:db8:aa::/64")).unwrap();
        assert_eq!(r.cost, 30); // E1: 10 (to ASBR) + 20
    }

    #[test]
    fn external_skips_unreachable_and_self() {
        let area = area_with_asbr();
        let links = Lsdb::new();
        let mut ext = Lsdb::new();
        ext.install(external_lsa(
            [9, 9, 9, 9],
            Ipv6Addr::new(0x2001, 0xdb8, 0xbb, 0, 0, 0, 0, 0),
            64,
            20,
            true,
        ));
        // ASBR 9.9.9.9 is not on the tree → skipped.
        let intra = compute(&area, &links, rid([1, 1, 1, 1]));
        assert!(external_routes(&ext, &intra, rid([1, 1, 1, 1])).is_empty());
        // From the ASBR's own perspective its self-originated LSA is skipped.
        let mut ours = Lsdb::new();
        ours.install(external_lsa(
            [2, 2, 2, 2],
            Ipv6Addr::new(0x2001, 0xdb8, 0xaa, 0, 0, 0, 0, 0),
            64,
            20,
            true,
        ));
        let intra2 = compute(&area, &links, rid([2, 2, 2, 2]));
        assert!(external_routes(&ours, &intra2, rid([2, 2, 2, 2])).is_empty());
    }
}
