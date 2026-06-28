//! The BGP decision process (RFC 4271 §9.1.2.2) — picking the best path to a
//! destination from the candidate paths learned for it.
//!
//! A [`Path`] bundles the attributes the decision compares plus the session
//! facts the receiving router supplies (whether the peer is eBGP or iBGP, the
//! IGP cost to the NEXT_HOP, the peer's identity for the final tie-breaks).
//! [`best_path`] applies the standard preference order — LOCAL_PREF, AS_PATH
//! length, ORIGIN, MED, eBGP-over-iBGP, IGP metric, then peer id/address — and
//! [`Path::to_route`] turns the winner into a [`wren_core::Route`] for the RIB.
//!
//! This is the pure decision kernel: it takes plain values and returns a choice,
//! so the whole tree is unit-testable without sockets or a RIB.

use std::net::{IpAddr, Ipv4Addr};

use wren_core::{NextHop, Prefix, Protocol, Route};

use crate::attr::{AsPathSegment, Origin};

/// The default LOCAL_PREF assigned to a path that carries none (i.e. learned from
/// an eBGP peer, where LOCAL_PREF is not sent across the AS boundary).
pub const DEFAULT_LOCAL_PREF: u32 = 100;

/// A candidate path to one destination, with everything the decision needs.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Path {
    /// The ORIGIN attribute.
    pub origin: Origin,
    /// The AS_PATH segments (its length is the §9.1.2.2 comparison input).
    pub as_path: Vec<AsPathSegment>,
    /// The NEXT_HOP to reach the destination — IPv4 (the base-NLRI NEXT_HOP
    /// attribute) or IPv6 (the MP_REACH_NLRI next hop, RFC 4760).
    pub next_hop: IpAddr,
    /// The interface the next hop must be reached over, when it is an IPv6
    /// link-local carried in a 32-octet MP_REACH next hop (RFC 2545 §3). A
    /// link-local is not globally unique, so the kernel route must pin it to the
    /// interface the route arrived on; `None` for ordinary global next hops.
    pub next_hop_iface: Option<String>,
    /// The (assigned) LOCAL_PREF — higher is preferred.
    pub local_pref: u32,
    /// The MULTI_EXIT_DISC — lower is preferred, compared only within one peer AS.
    pub med: u32,
    /// Whether this path was learned from a true external (eBGP) peer (vs iBGP or
    /// confed-eBGP). A confed-eBGP peer is interior for the decision (RFC 5065
    /// §5.3), so this stays `false` for it.
    pub from_ebgp: bool,
    /// Whether this path was learned from a confederation-internal (confed-eBGP)
    /// peer (RFC 5065): interior for the decision, but — like an eBGP-learned route
    /// — propagated onward without the iBGP split-horizon restriction. Not part of
    /// the §9.1.2.2 comparison.
    pub from_confed: bool,
    /// The neighbouring AS the path came from (for the same-AS MED comparison).
    pub peer_as: u32,
    /// The IGP cost to reach [`Path::next_hop`] — lower is preferred.
    pub igp_metric: u32,
    /// The peer's BGP identifier (router id), a tie-break.
    pub peer_id: Ipv4Addr,
    /// The peer's address, the final tie-break.
    pub peer_addr: Ipv4Addr,
    /// Whether this path was learned from a route-reflector client (RFC 4456). Set
    /// by the reflector to decide reflection; not part of the comparison.
    pub from_client: bool,
    /// ORIGINATOR_ID (RFC 4456) if the route was reflected — the BGP id of the
    /// router that introduced it into the AS. Used for loop avoidance.
    pub originator_id: Option<Ipv4Addr>,
    /// CLUSTER_LIST (RFC 4456) the route carries — the clusters it has passed
    /// through. Its length is a tie-break (§9); a reflector finding its own id here
    /// drops the route.
    pub cluster_list: Vec<Ipv4Addr>,
    /// The COMMUNITIES (RFC 1997) attached to this path — retained for
    /// re-advertisement and policy; not part of the §9.1.2.2 comparison.
    pub communities: Vec<u32>,
    /// The LARGE_COMMUNITY (RFC 8092) tags attached to this path — likewise
    /// retained for re-advertisement and policy, not part of the comparison.
    pub large_communities: Vec<(u32, u32, u32)>,
    /// The EXTENDED_COMMUNITIES (RFC 4360) attached to this path — likewise
    /// retained for re-advertisement and policy, not part of the comparison.
    pub ext_communities: Vec<[u8; 8]>,
}

impl Path {
    /// The AS_PATH length per §9.1.2.2: each AS in a sequence counts once, each
    /// set counts as one regardless of size, and confederation segments
    /// (AS_CONFED_SEQUENCE / AS_CONFED_SET) are not counted at all (RFC 5065 §5.3).
    pub fn as_path_len(&self) -> usize {
        self.as_path
            .iter()
            .map(|s| match s {
                AsPathSegment::Sequence(a) => a.len(),
                AsPathSegment::Set(_) => 1,
                AsPathSegment::ConfedSequence(_) | AsPathSegment::ConfedSet(_) => 0,
            })
            .sum()
    }

    /// Turn this path into a RIB route for `prefix`. The metric carries the
    /// AS_PATH length, so the RIB's own tie-break stays sensible if it ever sees
    /// more than one BGP candidate for a prefix.
    pub fn to_route(&self, prefix: Prefix) -> Route {
        // A link-local next hop (RFC 2545) must be pinned to its interface; an
        // ordinary global/IPv4 next hop is reached by the usual recursive lookup.
        let nexthop = match &self.next_hop_iface {
            Some(dev) => NextHop::via_dev(self.next_hop, dev.clone()),
            None => NextHop::via(self.next_hop),
        };
        Route::new(prefix, Protocol::Bgp, vec![nexthop], self.as_path_len() as u32)
    }
}

/// Whether path `a` is strictly preferred over path `b` (RFC 4271 §9.1.2.2 plus
/// the usual implementation tie-breaks).
pub fn is_better(a: &Path, b: &Path) -> bool {
    // 1. Highest LOCAL_PREF.
    if a.local_pref != b.local_pref {
        return a.local_pref > b.local_pref;
    }
    // 2. Shortest AS_PATH.
    let (la, lb) = (a.as_path_len(), b.as_path_len());
    if la != lb {
        return la < lb;
    }
    // 3. Lowest ORIGIN (IGP < EGP < INCOMPLETE).
    if a.origin != b.origin {
        return a.origin.as_u8() < b.origin.as_u8();
    }
    // 4. Lowest MED — only between paths from the same neighbouring AS.
    if a.peer_as == b.peer_as && a.med != b.med {
        return a.med < b.med;
    }
    // 5. Prefer eBGP over iBGP.
    if a.from_ebgp != b.from_ebgp {
        return a.from_ebgp;
    }
    // 6. Lowest IGP metric to the NEXT_HOP.
    if a.igp_metric != b.igp_metric {
        return a.igp_metric < b.igp_metric;
    }
    // 7. Shortest CLUSTER_LIST (RFC 4456 §9) — fewer reflection hops.
    if a.cluster_list.len() != b.cluster_list.len() {
        return a.cluster_list.len() < b.cluster_list.len();
    }
    // 8. Lowest peer BGP identifier.
    if a.peer_id != b.peer_id {
        return u32::from(a.peer_id) < u32::from(b.peer_id);
    }
    // 9. Lowest peer address.
    u32::from(a.peer_addr) < u32::from(b.peer_addr)
}

/// The index of the best path in `paths`, or `None` if it is empty.
pub fn best_path(paths: &[Path]) -> Option<usize> {
    if paths.is_empty() {
        return None;
    }
    let mut best = 0;
    for (i, p) in paths.iter().enumerate().skip(1) {
        if is_better(p, &paths[best]) {
            best = i;
        }
    }
    Some(best)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(o: [u8; 4]) -> Ipv4Addr {
        Ipv4Addr::from(o)
    }

    /// A baseline path; tests tweak one field to isolate each decision step.
    fn base() -> Path {
        Path {
            origin: Origin::Igp,
            as_path: vec![AsPathSegment::Sequence(vec![65001, 65002])],
            next_hop: IpAddr::V4(ip([192, 0, 2, 1])),
            next_hop_iface: None,
            local_pref: DEFAULT_LOCAL_PREF,
            med: 0,
            from_ebgp: true,
            from_confed: false,
            peer_as: 65001,
            igp_metric: 10,
            peer_id: ip([10, 0, 0, 1]),
            peer_addr: ip([10, 0, 0, 1]),
            from_client: false,
            originator_id: None,
            cluster_list: vec![],
            communities: vec![],
            large_communities: vec![],
            ext_communities: vec![],
        }
    }

    #[test]
    fn as_path_length_counts_sequences_and_sets() {
        let p = Path {
            as_path: vec![
                AsPathSegment::Sequence(vec![1, 2, 3]),
                AsPathSegment::Set(vec![10, 11, 12]),
            ],
            ..base()
        };
        assert_eq!(p.as_path_len(), 4); // 3 + 1
    }

    #[test]
    fn as_path_length_excludes_confederation_segments() {
        // Confed segments (RFC 5065 §5.3) do not count toward AS_PATH length.
        let p = Path {
            as_path: vec![
                AsPathSegment::ConfedSequence(vec![65001, 65002]),
                AsPathSegment::ConfedSet(vec![65003]),
                AsPathSegment::Sequence(vec![64500, 64501]),
            ],
            ..base()
        };
        assert_eq!(p.as_path_len(), 2); // only the real-AS sequence counts
    }

    #[test]
    fn local_pref_wins_first() {
        let hi = Path { local_pref: 200, ..base() };
        // Even with a longer AS_PATH and worse origin, higher LOCAL_PREF wins.
        let lo = Path {
            local_pref: 100,
            as_path: vec![AsPathSegment::Sequence(vec![65001])],
            origin: Origin::Igp,
            ..base()
        };
        assert!(is_better(&hi, &lo));
        assert!(!is_better(&lo, &hi));
    }

    #[test]
    fn shorter_as_path_then_origin() {
        let short = Path { as_path: vec![AsPathSegment::Sequence(vec![65001])], ..base() };
        let long = Path { as_path: vec![AsPathSegment::Sequence(vec![65001, 65002, 65003])], ..base() };
        assert!(is_better(&short, &long));

        // Equal length → lower ORIGIN wins.
        let igp = Path { origin: Origin::Igp, ..base() };
        let inc = Path { origin: Origin::Incomplete, ..base() };
        assert!(is_better(&igp, &inc));
    }

    #[test]
    fn med_compared_only_within_same_peer_as() {
        let lo_med = Path { med: 50, peer_as: 65001, ..base() };
        let hi_med = Path { med: 100, peer_as: 65001, ..base() };
        assert!(is_better(&lo_med, &hi_med));

        // Different peer ASes → MED is not compared; the two are otherwise equal,
        // so neither dominates on MED alone (the tie falls through to peer id).
        let a = Path { med: 100, peer_as: 65001, ..base() };
        let b = Path { med: 50, peer_as: 65002, ..base() };
        assert!(!(is_better(&a, &b) && is_better(&b, &a)));
    }

    #[test]
    fn ebgp_preferred_over_ibgp() {
        let ebgp = Path { from_ebgp: true, ..base() };
        let ibgp = Path { from_ebgp: false, ..base() };
        assert!(is_better(&ebgp, &ibgp));
    }

    #[test]
    fn igp_metric_then_router_id_tie_breaks() {
        let near = Path { igp_metric: 5, ..base() };
        let far = Path { igp_metric: 50, ..base() };
        assert!(is_better(&near, &far));

        // Everything equal → lowest peer id.
        let lo = Path { peer_id: ip([10, 0, 0, 1]), ..base() };
        let hi = Path { peer_id: ip([10, 0, 0, 9]), ..base() };
        assert!(is_better(&lo, &hi));
    }

    #[test]
    fn shorter_cluster_list_breaks_the_tie_before_router_id() {
        // Everything equal but the CLUSTER_LIST length → fewer reflection hops wins,
        // even though the longer-list path has the lower peer id.
        let short = Path { cluster_list: vec![ip([1, 1, 1, 1])], peer_id: ip([10, 0, 0, 9]), ..base() };
        let long = Path {
            cluster_list: vec![ip([1, 1, 1, 1]), ip([2, 2, 2, 2])],
            peer_id: ip([10, 0, 0, 1]),
            ..base()
        };
        assert!(is_better(&short, &long));
        assert!(!is_better(&long, &short));
    }

    #[test]
    fn best_path_picks_the_winner() {
        let paths = vec![
            Path { local_pref: 100, ..base() },
            Path { local_pref: 300, peer_id: ip([10, 0, 0, 5]), ..base() }, // best
            Path { local_pref: 200, ..base() },
        ];
        assert_eq!(best_path(&paths), Some(1));
        assert_eq!(best_path(&[]), None);
    }

    #[test]
    fn to_route_is_bgp_with_next_hop() {
        let p = base();
        let route = p.to_route("203.0.113.0/24".parse().unwrap());
        assert_eq!(route.protocol, Protocol::Bgp);
        assert_eq!(route.metric, 2); // AS_PATH length
        assert_eq!(route.nexthops, vec![NextHop::via(IpAddr::V4(ip([192, 0, 2, 1])))]);
    }

    #[test]
    fn to_route_pins_a_link_local_next_hop_to_its_interface() {
        // RFC 2545: a link-local next hop is installed via that address pinned to
        // the interface the route arrived on.
        let p = Path {
            next_hop: IpAddr::V6("fe80::1".parse().unwrap()),
            next_hop_iface: Some("eth0".into()),
            ..base()
        };
        let route = p.to_route("2001:db8:99::/64".parse().unwrap());
        assert_eq!(
            route.nexthops,
            vec![NextHop::via_dev(IpAddr::V6("fe80::1".parse().unwrap()), "eth0")]
        );
    }
}
