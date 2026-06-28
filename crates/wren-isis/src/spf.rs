//! The IS-IS shortest-path-first calculation (ISO/IEC 10589 §7.2, the Decision
//! Process) — a pure Dijkstra over one level's [`Lsdb`].
//!
//! IS-IS, like OSPFv3, runs its SPF over an **address-free graph**: the vertices
//! are *nodes* named by a 7-byte ID (a 6-byte System ID plus a one-byte pseudonode
//! number), and addressing is attached afterwards from TLVs. The shape mirrors the
//! OSPF crates, with the IS-IS specifics folded in:
//!
//! * **Vertices are nodes, edges come from Extended IS Reachability** (TLV 22). A
//!   real router has pseudonode 0; a LAN is represented by a **pseudonode** (the
//!   DIS's pseudonode LSP), exactly the role OSPF's transit-network vertex plays —
//!   members point at the pseudonode at the interface metric, and the pseudonode
//!   points back at every member at metric 0. Each edge is kept only if the
//!   neighbour advertises a link *back* (the IS-IS two-way check), so a
//!   half-converged database never poisons the tree. An LSP whose Remaining
//!   Lifetime has reached zero (a purge) is treated as absent.
//! * **The overload bit means "do not transit me."** A node that sets the LSP
//!   Database Overload bit still has its own prefixes reached, but the SPF never
//!   routes *through* it — its IS-reachability edges are dropped (ISO 10589 §7.2,
//!   the overload condition).
//! * **Prefixes are attached afterwards**, dual-stack: every settled node
//!   contributes its Extended IP Reachability (TLV 135, IPv4) and IPv6 Reachability
//!   (TLV 236) prefixes at `node_distance + prefix_metric`.
//! * **The attached bit draws a default route** (RFC 1195 §3.2 / RFC 5308). When
//!   the SPF is run for **Level 1**, every reachable L1L2 router that set the ATT
//!   bit in its LSP yields a default route (`0.0.0.0/0` and/or `::/0`, per the
//!   address families it supports) towards the backbone. An L1L2 router computing
//!   its own L1 SPF ignores these in favour of its real L2 routes.
//!
//! Next hops are resolved best-effort from the LSDB alone: a node one hop from the
//! root takes the first-hop router's interface addresses (TLV 132 for IPv4, 232 for
//! IPv6, read out of *its* LSP), and anything deeper inherits the parent's. A
//! directly-attached LAN or an unnumbered link yields an empty next-hop set — an
//! on-link (connected) route whose outgoing interface the runner pins (IS-IS binds
//! the next hop to the SNPA of the adjacency, which the database cannot name; the
//! runner refines these with the addresses it learned in the Hello exchange).
//!
//! This is the pure core: it reads an [`Lsdb`] and returns [`wren_core::Route`]s,
//! with no sockets and no clock, so it is fully unit-testable from a hand-built
//! database.

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use wren_core::{NextHop, Prefix, Protocol, Route};

use crate::lsdb::Lsdb;
use crate::pdu::Lsp;
use crate::tlv::Tlv;
use crate::{IsLevel, SystemId, NLPID_IPV4, NLPID_IPV6};

/// A node of the shortest-path graph: a 6-byte System ID plus a one-byte
/// pseudonode number (0 for a real router, non-zero for a LAN's pseudonode).
pub type NodeId = [u8; 7];

/// Build the 7-byte node ID of a router or pseudonode.
fn node_of(sys: SystemId, pseudonode: u8) -> NodeId {
    let mut n = [0u8; 7];
    n[..6].copy_from_slice(&sys.0);
    n[6] = pseudonode;
    n
}

/// The System ID part of a node ID.
fn sys_of(node: NodeId) -> SystemId {
    let mut s = [0u8; 6];
    s.copy_from_slice(&node[..6]);
    SystemId(s)
}

/// Whether a node ID names a pseudonode (a LAN) rather than a real router.
fn is_pseudonode(node: NodeId) -> bool {
    node[6] != 0
}

/// What is known about a settled (or candidate) vertex: its distance from the
/// root and the per-family next-hop gateways to reach it. An empty gateway set
/// means the vertex is directly attached to the root (a connected/on-link hop).
#[derive(Clone, Debug, Default)]
struct VertexInfo {
    dist: u32,
    v4: Vec<Ipv4Addr>,
    v6: Vec<Ipv6Addr>,
}

/// One destination produced by the SPF.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct SpfRoute {
    /// The destination prefix.
    pub prefix: Prefix,
    /// The total IS-IS metric from the root.
    pub cost: u32,
    /// The next-hop gateway addresses (matching the prefix's family). Empty means
    /// the destination is directly attached (a connected/on-link route whose
    /// outgoing interface the runner resolves).
    pub gateways: Vec<IpAddr>,
}

impl SpfRoute {
    /// Convert into a [`wren_core::Route`] tagged [`Protocol::Isis`], with the cost
    /// as the metric. An empty gateway set becomes a single on-link next hop
    /// (gateway and interface unset — the runner fills the interface in).
    pub fn to_route(&self) -> Route {
        let nexthops: Vec<NextHop> = if self.gateways.is_empty() {
            vec![NextHop {
                gateway: None,
                iface: None,
                weight: 1,
            }]
        } else {
            self.gateways.iter().map(|g| NextHop::via(*g)).collect()
        };
        Route::new(self.prefix, Protocol::Isis, nexthops, self.cost)
    }
}

/// The result of an SPF run over one level's database.
#[derive(Clone, Default, Debug)]
pub struct SpfResult {
    /// The routes, in prefix order.
    pub routes: Vec<SpfRoute>,
    /// The distance to every reachable node (the root included, at cost 0). The
    /// inter-level (L1↔L2) leaking stage reads this to find the cost to a node.
    pub nodes: BTreeMap<NodeId, u32>,
    /// The IPv4 next hops to reach each node (empty for the root and directly-
    /// attached nodes). Leaked routes inherit these to reach the advertising node.
    pub node_v4_nexthops: BTreeMap<NodeId, Vec<Ipv4Addr>>,
    /// The IPv6 next hops to reach each node.
    pub node_v6_nexthops: BTreeMap<NodeId, Vec<Ipv6Addr>>,
}

/// Run the SPF over `db` (one level's database) rooted at `root`, for `level`
/// (which decides whether the attached-bit default route is generated — Level 1
/// only). Returns the routes and the per-node distances.
pub fn compute(db: &Lsdb, root: SystemId, level: IsLevel) -> SpfResult {
    Spf {
        db,
        root: node_of(root, 0),
        level,
    }
    .run()
}

/// Convenience: run the SPF and hand back ready-to-announce [`wren_core::Route`]s.
pub fn routes(db: &Lsdb, root: SystemId, level: IsLevel) -> Vec<Route> {
    compute(db, root, level)
        .routes
        .iter()
        .map(SpfRoute::to_route)
        .collect()
}

struct Spf<'a> {
    db: &'a Lsdb,
    root: NodeId,
    level: IsLevel,
}

impl Spf<'_> {
    fn run(&self) -> SpfResult {
        let mut tree: BTreeMap<NodeId, VertexInfo> = BTreeMap::new();
        let mut cand: BTreeMap<NodeId, VertexInfo> = BTreeMap::new();

        tree.insert(self.root, VertexInfo::default());
        let mut current = self.root;

        loop {
            let cur = tree.get(&current).cloned().expect("current is settled");
            for (w, cost) in self.neighbors(current) {
                if tree.contains_key(&w) {
                    continue;
                }
                let dist = cur.dist.saturating_add(cost);
                let (v4, v6) = self.initial_nexthops(&cur, w);
                match cand.get_mut(&w) {
                    None => {
                        cand.insert(w, VertexInfo { dist, v4, v6 });
                    }
                    Some(existing) => {
                        if dist < existing.dist {
                            *existing = VertexInfo { dist, v4, v6 };
                        } else if dist == existing.dist {
                            merge(&mut existing.v4, &v4);
                            merge(&mut existing.v6, &v6);
                        }
                    }
                }
            }

            // Settle the nearest candidate; ties broken by node ID for determinism.
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

    /// The neighbours of `node`: its Extended IS Reachability entries whose target
    /// is alive and advertises a link back (the two-way check). A non-root node
    /// that has the overload bit set is not transited, so it contributes no edges.
    fn neighbors(&self, node: NodeId) -> Vec<(NodeId, u32)> {
        if node != self.root && self.overloaded(node) {
            return Vec::new();
        }
        let mut out = Vec::new();
        for (w, metric) in self.is_reach(node) {
            if self.node_alive(w) && self.has_reach_to(w, node) {
                out.push((w, metric));
            }
        }
        out
    }

    /// The next hops for child `w` reached from parent `cur` (§7.2.5 next-hop
    /// resolution). A parent that already has next hops passes them down; a parent
    /// at the root edge (no gateways) resolves fresh — a pseudonode child is an
    /// on-link LAN (no gateway), a router child takes its own interface addresses.
    fn initial_nexthops(&self, cur: &VertexInfo, w: NodeId) -> (Vec<Ipv4Addr>, Vec<Ipv6Addr>) {
        if !cur.v4.is_empty() || !cur.v6.is_empty() {
            return (cur.v4.clone(), cur.v6.clone());
        }
        if is_pseudonode(w) {
            return (Vec::new(), Vec::new());
        }
        (self.iface_v4(w), self.iface_v6(w))
    }

    /// Build the route set from the settled tree: every node's dual-stack IP
    /// reachability, plus (for Level 1) the attached-bit default route.
    fn harvest(&self, tree: &BTreeMap<NodeId, VertexInfo>) -> SpfResult {
        let mut by_prefix: BTreeMap<Prefix, SpfRoute> = BTreeMap::new();
        let mut nodes = BTreeMap::new();
        let mut node_v4 = BTreeMap::new();
        let mut node_v6 = BTreeMap::new();

        for (node, info) in tree {
            nodes.insert(*node, info.dist);
            node_v4.insert(*node, info.v4.clone());
            node_v6.insert(*node, info.v6.clone());

            for frag in self.fragments(*node) {
                for tlv in &frag.tlvs {
                    match tlv {
                        Tlv::ExtendedIpReachability(reaches) => {
                            for r in reaches {
                                if let Ok(prefix) = Prefix::new(IpAddr::V4(r.prefix), r.prefix_len)
                                {
                                    add_route(
                                        &mut by_prefix,
                                        prefix,
                                        info.dist.saturating_add(r.metric),
                                        &v4_hops(&info.v4),
                                    );
                                }
                            }
                        }
                        Tlv::Ipv6Reachability(reaches) => {
                            for r in reaches {
                                if let Ok(prefix) = Prefix::new(IpAddr::V6(r.prefix), r.prefix_len)
                                {
                                    add_route(
                                        &mut by_prefix,
                                        prefix,
                                        info.dist.saturating_add(r.metric),
                                        &v6_hops(&info.v6),
                                    );
                                }
                            }
                        }
                        _ => {}
                    }
                }
            }

            // The attached-bit default route (Level 1 only).
            if self.level == IsLevel::L1 && *node != self.root && self.attached(*node) {
                if self.supports(*node, NLPID_IPV4) {
                    add_route(&mut by_prefix, default_v4(), info.dist, &v4_hops(&info.v4));
                }
                if self.supports(*node, NLPID_IPV6) {
                    add_route(&mut by_prefix, default_v6(), info.dist, &v6_hops(&info.v6));
                }
            }
        }

        SpfResult {
            routes: by_prefix.into_values().collect(),
            nodes,
            node_v4_nexthops: node_v4,
            node_v6_nexthops: node_v6,
        }
    }

    // --- LSDB lookups ------------------------------------------------------

    /// The alive (non-purged) LSP fragments that make up `node`'s link state.
    fn fragments(&self, node: NodeId) -> impl Iterator<Item = &Lsp> {
        let sys = sys_of(node);
        let pn = node[6];
        self.db.iter().filter(move |l| {
            l.lsp_id.system_id == sys && l.lsp_id.pseudonode == pn && l.remaining_lifetime > 0
        })
    }

    /// Whether `node` has any alive LSP fragment.
    fn node_alive(&self, node: NodeId) -> bool {
        self.fragments(node).next().is_some()
    }

    /// `node`'s Extended IS Reachability edges: `(neighbour node ID, metric)`.
    fn is_reach(&self, node: NodeId) -> Vec<(NodeId, u32)> {
        let mut out = Vec::new();
        for frag in self.fragments(node) {
            for tlv in &frag.tlvs {
                if let Tlv::ExtendedIsReachability(reaches) = tlv {
                    for r in reaches {
                        out.push((r.neighbor_id, r.metric));
                    }
                }
            }
        }
        out
    }

    /// Whether `from` advertises an IS-reachability edge back to `to`.
    fn has_reach_to(&self, from: NodeId, to: NodeId) -> bool {
        self.is_reach(from).iter().any(|(w, _)| *w == to)
    }

    /// The fragment-0 LSP of a node, where the overload and attached flags live.
    fn fragment_zero(&self, node: NodeId) -> Option<&Lsp> {
        self.fragments(node).find(|l| l.lsp_id.fragment == 0)
    }

    /// Whether `node` has the LSP Database Overload bit set (do not transit it).
    fn overloaded(&self, node: NodeId) -> bool {
        self.fragment_zero(node).is_some_and(|l| l.overload)
    }

    /// Whether `node` set the attached bit (it can reach the L2 backbone).
    fn attached(&self, node: NodeId) -> bool {
        self.fragment_zero(node).is_some_and(|l| l.attached != 0)
    }

    /// Whether `node` advertises support for an NLPID (IPv4 `0xCC` / IPv6 `0x8E`).
    fn supports(&self, node: NodeId, nlpid: u8) -> bool {
        self.fragments(node).any(|frag| {
            frag.tlvs
                .iter()
                .any(|tlv| matches!(tlv, Tlv::ProtocolsSupported(ids) if ids.contains(&nlpid)))
        })
    }

    /// `node`'s advertised IPv4 interface addresses (TLV 132).
    fn iface_v4(&self, node: NodeId) -> Vec<Ipv4Addr> {
        let mut out = Vec::new();
        for frag in self.fragments(node) {
            for tlv in &frag.tlvs {
                if let Tlv::Ipv4InterfaceAddresses(addrs) = tlv {
                    out.extend_from_slice(addrs);
                }
            }
        }
        out
    }

    /// `node`'s advertised IPv6 interface addresses (TLV 232).
    fn iface_v6(&self, node: NodeId) -> Vec<Ipv6Addr> {
        let mut out = Vec::new();
        for frag in self.fragments(node) {
            for tlv in &frag.tlvs {
                if let Tlv::Ipv6InterfaceAddresses(addrs) = tlv {
                    out.extend_from_slice(addrs);
                }
            }
        }
        out
    }
}

/// The IPv4 default prefix `0.0.0.0/0`.
fn default_v4() -> Prefix {
    Prefix::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0).expect("valid default")
}

/// The IPv6 default prefix `::/0`.
fn default_v6() -> Prefix {
    Prefix::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0).expect("valid default")
}

/// Widen an IPv4 next-hop list to the generic [`IpAddr`] form.
fn v4_hops(v4: &[Ipv4Addr]) -> Vec<IpAddr> {
    v4.iter().map(|a| IpAddr::V4(*a)).collect()
}

/// Widen an IPv6 next-hop list to the generic [`IpAddr`] form, preferring global
/// addresses. A neighbour usually advertises both a link-local and a global
/// interface address; only the global is installable in the kernel FIB without
/// pinning the outgoing interface, so when any global is present the link-locals
/// are dropped (this also avoids a broken global+link-local ECMP route). When
/// only link-locals exist they are kept as-is.
fn v6_hops(v6: &[Ipv6Addr]) -> Vec<IpAddr> {
    let has_global = v6.iter().any(|a| !is_link_local(a));
    v6.iter()
        .filter(|a| !has_global || !is_link_local(a))
        .map(|a| IpAddr::V6(*a))
        .collect()
}

/// Whether an IPv6 address is in the link-local range `fe80::/10`.
fn is_link_local(a: &Ipv6Addr) -> bool {
    (a.segments()[0] & 0xffc0) == 0xfe80
}

/// Insert or fold a route into the by-prefix table: a strictly lower cost
/// replaces, an equal cost merges next hops (ECMP), a higher cost is dropped.
fn add_route(map: &mut BTreeMap<Prefix, SpfRoute>, prefix: Prefix, cost: u32, gateways: &[IpAddr]) {
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
                merge(&mut existing.gateways, gateways);
            }
        }
    }
}

/// Union `extra` into `into`, preserving order and dropping duplicates.
fn merge<T: Copy + PartialEq>(into: &mut Vec<T>, extra: &[T]) {
    for g in extra {
        if !into.contains(g) {
            into.push(*g);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pdu::Lsp;
    use crate::tlv::{ExtIpReach, ExtIsReach, Ipv6Reach, Tlv};
    use crate::{IsLevel, LspId, SystemId};

    fn sid(n: u8) -> SystemId {
        SystemId::new([n, n, n, n, n, n])
    }

    fn nid(n: u8, pn: u8) -> NodeId {
        node_of(sid(n), pn)
    }

    /// Build one LSP fragment.
    fn lsp(sys: SystemId, pn: u8, frag: u8, tlvs: Vec<Tlv>) -> Lsp {
        Lsp {
            level: IsLevel::L1,
            remaining_lifetime: 1000,
            lsp_id: LspId::new(sys, pn, frag),
            sequence_number: 1,
            checksum: 0,
            partition: false,
            attached: 0,
            overload: false,
            is_type: IsLevel::L1,
            tlvs,
        }
    }

    fn is_reach(neighbor: NodeId, metric: u32) -> ExtIsReach {
        ExtIsReach {
            neighbor_id: neighbor,
            metric,
            sub_tlvs: vec![],
        }
    }

    fn ip4(net: [u8; 4], len: u8, metric: u32) -> Tlv {
        Tlv::ExtendedIpReachability(vec![ExtIpReach {
            metric,
            up_down: false,
            prefix_len: len,
            prefix: Ipv4Addr::from(net),
            sub_tlvs: None,
        }])
    }

    fn iface4(a: [u8; 4]) -> Tlv {
        Tlv::Ipv4InterfaceAddresses(vec![Ipv4Addr::from(a)])
    }

    fn find<'a>(res: &'a SpfResult, prefix: &str) -> &'a SpfRoute {
        let p: Prefix = prefix.parse().unwrap();
        res.routes
            .iter()
            .find(|r| r.prefix == p)
            .unwrap_or_else(|| panic!("no route for {prefix}"))
    }

    #[test]
    fn point_to_point_local_is_connected_and_far_via_gateway() {
        let mut db = Lsdb::new();
        // R1 <--10--> R2; each advertises a connected /24 and one interface address.
        db.install(lsp(
            sid(1),
            0,
            0,
            vec![
                Tlv::ExtendedIsReachability(vec![is_reach(nid(2, 0), 10)]),
                ip4([192, 168, 1, 0], 24, 1),
                iface4([10, 0, 12, 1]),
            ],
        ));
        db.install(lsp(
            sid(2),
            0,
            0,
            vec![
                Tlv::ExtendedIsReachability(vec![is_reach(nid(1, 0), 10)]),
                ip4([192, 168, 2, 0], 24, 1),
                iface4([10, 0, 12, 2]),
            ],
        ));

        let res = compute(&db, sid(1), IsLevel::L1);

        // The root's own prefix is connected (no gateway), at its own metric.
        let local = find(&res, "192.168.1.0/24");
        assert_eq!(local.cost, 1);
        assert!(local.gateways.is_empty());

        // R2's prefix: 10 (link) + 1 (prefix metric), via R2's interface address.
        let far = find(&res, "192.168.2.0/24");
        assert_eq!(far.cost, 11);
        assert_eq!(far.gateways, vec![IpAddr::V4(Ipv4Addr::new(10, 0, 12, 2))]);

        assert_eq!(res.nodes.get(&nid(2, 0)), Some(&10));
        assert_eq!(res.nodes.get(&nid(1, 0)), Some(&0));
    }

    #[test]
    fn lan_pseudonode_relays_to_other_member() {
        let mut db = Lsdb::new();
        // R1 and R2 share a LAN whose DIS is R1, pseudonode 1.
        let pn = node_of(sid(1), 1);
        db.install(lsp(
            sid(1),
            0,
            0,
            vec![
                Tlv::ExtendedIsReachability(vec![is_reach(pn, 10)]),
                iface4([10, 0, 0, 1]),
            ],
        ));
        db.install(lsp(
            sid(2),
            0,
            0,
            vec![
                Tlv::ExtendedIsReachability(vec![is_reach(pn, 10)]),
                ip4([192, 168, 2, 0], 24, 5),
                iface4([10, 0, 0, 2]),
            ],
        ));
        // The pseudonode LSP: metric-0 edges back to both members.
        db.install(lsp(
            sid(1),
            1,
            0,
            vec![Tlv::ExtendedIsReachability(vec![
                is_reach(nid(1, 0), 0),
                is_reach(nid(2, 0), 0),
            ])],
        ));

        let res = compute(&db, sid(1), IsLevel::L1);

        // R2's prefix: 10 (root->pseudonode) + 0 (pseudonode->R2) + 5 (prefix).
        let far = find(&res, "192.168.2.0/24");
        assert_eq!(far.cost, 15);
        assert_eq!(far.gateways, vec![IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))]);
        assert_eq!(res.nodes.get(&nid(2, 0)), Some(&10));
        // The pseudonode is on the tree at the link cost, reached on-link.
        assert_eq!(res.nodes.get(&pn), Some(&10));
        assert!(res.node_v4_nexthops.get(&pn).unwrap().is_empty());
    }

    #[test]
    fn one_way_link_is_ignored() {
        let mut db = Lsdb::new();
        // R1 claims a link to R2, R2 never claims one back.
        db.install(lsp(
            sid(1),
            0,
            0,
            vec![Tlv::ExtendedIsReachability(vec![is_reach(nid(2, 0), 10)])],
        ));
        db.install(lsp(sid(2), 0, 0, vec![ip4([192, 168, 2, 0], 24, 1)]));

        let res = compute(&db, sid(1), IsLevel::L1);
        assert_eq!(res.nodes.get(&nid(2, 0)), None);
        assert!(res
            .routes
            .iter()
            .all(|r| r.prefix.to_string() != "192.168.2.0/24"));
    }

    #[test]
    fn purged_lsp_is_excluded() {
        let mut db = Lsdb::new();
        db.install(lsp(
            sid(1),
            0,
            0,
            vec![Tlv::ExtendedIsReachability(vec![is_reach(nid(2, 0), 10)])],
        ));
        let mut dead = lsp(
            sid(2),
            0,
            0,
            vec![
                Tlv::ExtendedIsReachability(vec![is_reach(nid(1, 0), 10)]),
                ip4([192, 168, 2, 0], 24, 1),
            ],
        );
        dead.remaining_lifetime = 0; // a purge
        db.install(dead);

        let res = compute(&db, sid(1), IsLevel::L1);
        assert_eq!(res.nodes.get(&nid(2, 0)), None);
    }

    #[test]
    fn overloaded_node_is_not_transited_but_its_prefix_is_reached() {
        let mut db = Lsdb::new();
        // R1 -- R2(overloaded) -- R3. R2's own prefix is still reachable; R3 is not
        // reachable *through* R2.
        db.install(lsp(
            sid(1),
            0,
            0,
            vec![
                Tlv::ExtendedIsReachability(vec![is_reach(nid(2, 0), 10)]),
                iface4([10, 0, 12, 1]),
            ],
        ));
        let mut r2 = lsp(
            sid(2),
            0,
            0,
            vec![
                Tlv::ExtendedIsReachability(vec![is_reach(nid(1, 0), 10), is_reach(nid(3, 0), 10)]),
                ip4([192, 168, 2, 0], 24, 1),
                iface4([10, 0, 12, 2]),
            ],
        );
        r2.overload = true;
        db.install(r2);
        db.install(lsp(
            sid(3),
            0,
            0,
            vec![
                Tlv::ExtendedIsReachability(vec![is_reach(nid(2, 0), 10)]),
                ip4([192, 168, 3, 0], 24, 1),
            ],
        ));

        let res = compute(&db, sid(1), IsLevel::L1);
        // R2 itself and its prefix are reached.
        assert_eq!(res.nodes.get(&nid(2, 0)), Some(&10));
        assert_eq!(find(&res, "192.168.2.0/24").cost, 11);
        // R3, only reachable through the overloaded R2, is not.
        assert_eq!(res.nodes.get(&nid(3, 0)), None);
        assert!(res
            .routes
            .iter()
            .all(|r| r.prefix.to_string() != "192.168.3.0/24"));
    }

    #[test]
    fn attached_bit_yields_a_default_route_in_l1_only() {
        let mut db = Lsdb::new();
        db.install(lsp(
            sid(1),
            0,
            0,
            vec![
                Tlv::ExtendedIsReachability(vec![is_reach(nid(2, 0), 10)]),
                iface4([10, 0, 12, 1]),
            ],
        ));
        // R2 is an L1L2 router attached to the backbone, supporting IPv4.
        let mut r2 = lsp(
            sid(2),
            0,
            0,
            vec![
                Tlv::ExtendedIsReachability(vec![is_reach(nid(1, 0), 10)]),
                Tlv::ProtocolsSupported(vec![NLPID_IPV4]),
                iface4([10, 0, 12, 2]),
            ],
        );
        r2.attached = 0b0001;
        db.install(r2);

        // In L1, the attached bit draws a default route towards R2.
        let l1 = compute(&db, sid(1), IsLevel::L1);
        let def = find(&l1, "0.0.0.0/0");
        assert_eq!(def.cost, 10);
        assert_eq!(def.gateways, vec![IpAddr::V4(Ipv4Addr::new(10, 0, 12, 2))]);
        // No IPv6 default — R2 did not advertise IPv6 support.
        assert!(l1.routes.iter().all(|r| r.prefix.to_string() != "::/0"));

        // In L2, the attached bit is meaningless: no default route.
        let l2 = compute(&db, sid(1), IsLevel::L2);
        assert!(l2
            .routes
            .iter()
            .all(|r| r.prefix.to_string() != "0.0.0.0/0"));
    }

    #[test]
    fn dual_stack_ipv6_reachability() {
        let mut db = Lsdb::new();
        db.install(lsp(
            sid(1),
            0,
            0,
            vec![
                Tlv::ExtendedIsReachability(vec![is_reach(nid(2, 0), 10)]),
                Tlv::Ipv6InterfaceAddresses(vec![Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1)]),
            ],
        ));
        db.install(lsp(
            sid(2),
            0,
            0,
            vec![
                Tlv::ExtendedIsReachability(vec![is_reach(nid(1, 0), 10)]),
                Tlv::Ipv6Reachability(vec![Ipv6Reach {
                    metric: 5,
                    up_down: false,
                    external: false,
                    prefix_len: 64,
                    prefix: Ipv6Addr::new(0x2001, 0xdb8, 2, 0, 0, 0, 0, 0),
                    sub_tlvs: None,
                }]),
                Tlv::Ipv6InterfaceAddresses(vec![Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 2)]),
            ],
        ));

        let res = compute(&db, sid(1), IsLevel::L2);
        let far = find(&res, "2001:db8:2::/64");
        assert_eq!(far.cost, 15);
        assert_eq!(
            far.gateways,
            vec![IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 2))]
        );
    }

    #[test]
    fn equal_cost_paths_merge_into_ecmp() {
        let mut db = Lsdb::new();
        // R1 reaches R3 two ways at equal cost: via R2 and via R4.
        db.install(lsp(
            sid(1),
            0,
            0,
            vec![
                Tlv::ExtendedIsReachability(vec![is_reach(nid(2, 0), 10), is_reach(nid(4, 0), 10)]),
                iface4([10, 0, 1, 1]),
            ],
        ));
        db.install(lsp(
            sid(2),
            0,
            0,
            vec![
                Tlv::ExtendedIsReachability(vec![is_reach(nid(1, 0), 10), is_reach(nid(3, 0), 5)]),
                iface4([10, 0, 12, 2]),
            ],
        ));
        db.install(lsp(
            sid(4),
            0,
            0,
            vec![
                Tlv::ExtendedIsReachability(vec![is_reach(nid(1, 0), 10), is_reach(nid(3, 0), 5)]),
                iface4([10, 0, 14, 4]),
            ],
        ));
        db.install(lsp(
            sid(3),
            0,
            0,
            vec![
                Tlv::ExtendedIsReachability(vec![is_reach(nid(2, 0), 5), is_reach(nid(4, 0), 5)]),
                ip4([192, 168, 3, 0], 24, 1),
            ],
        ));

        let res = compute(&db, sid(1), IsLevel::L1);
        assert_eq!(res.nodes.get(&nid(3, 0)), Some(&15));
        let far = find(&res, "192.168.3.0/24");
        assert_eq!(far.cost, 16);
        assert_eq!(far.gateways.len(), 2);
        assert!(far
            .gateways
            .contains(&IpAddr::V4(Ipv4Addr::new(10, 0, 12, 2))));
        assert!(far
            .gateways
            .contains(&IpAddr::V4(Ipv4Addr::new(10, 0, 14, 4))));
    }

    #[test]
    fn to_route_maps_protocol_metric_and_nexthops() {
        let mut db = Lsdb::new();
        db.install(lsp(
            sid(1),
            0,
            0,
            vec![
                Tlv::ExtendedIsReachability(vec![is_reach(nid(2, 0), 10)]),
                ip4([192, 168, 1, 0], 24, 1),
                iface4([10, 0, 12, 1]),
            ],
        ));
        db.install(lsp(
            sid(2),
            0,
            0,
            vec![
                Tlv::ExtendedIsReachability(vec![is_reach(nid(1, 0), 10)]),
                ip4([192, 168, 2, 0], 24, 1),
                iface4([10, 0, 12, 2]),
            ],
        ));

        let routes = routes(&db, sid(1), IsLevel::L1);
        let far = routes
            .iter()
            .find(|r| r.prefix.to_string() == "192.168.2.0/24")
            .unwrap();
        assert_eq!(far.protocol, Protocol::Isis);
        assert_eq!(far.metric, 11);
        assert_eq!(far.preference, Protocol::Isis.default_preference());
        assert_eq!(
            far.nexthops,
            vec![NextHop::via(IpAddr::V4(Ipv4Addr::new(10, 0, 12, 2)))]
        );

        // The connected prefix maps to a single on-link next hop.
        let local = routes
            .iter()
            .find(|r| r.prefix.to_string() == "192.168.1.0/24")
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
}
