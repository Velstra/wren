//! # wren-filter — BIRD-style route filters (policy)
//!
//! A **filter** decides, for each route a protocol offers (on *import*, into the
//! RIB) or the RIB offers (on *export*, to a protocol or the FIB), whether to
//! **accept** or **reject** it — and, when accepting, optionally **modifies** its
//! attributes (metric, preference). This is the dependency-free policy core, in
//! the spirit of BIRD's filters but expressed as data rather than a scripting
//! language, so it is fully unit-testable and embeddable alongside [`wren_core`].
//!
//! A [`Filter`] is an ordered list of [`Rule`]s plus a default [`Action`]. The
//! first rule whose [`Match`] holds decides the outcome (first-match-wins), after
//! applying that rule's [`Modify`]; if no rule matches, the default action applies.
//!
//! Matching a route's prefix uses **prefix patterns** (`PrefixPattern`), the same
//! idea as BIRD's prefix lists:
//!
//! | Written | Meaning |
//! |---|---|
//! | `10.0.0.0/8` | exactly `10.0.0.0/8` |
//! | `10.0.0.0/8+` | `10.0.0.0/8` or any more-specific (length 8…max) |
//! | `10.0.0.0/8{16,24}` | within `10.0.0.0/8`, length 16…24 |
//!
//! ```
//! use wren_filter::{Filter, Rule, Match, Action, Modify, Decision, PrefixList};
//! use wren_core::{Protocol, Prefix, Route, NextHop};
//! use std::net::IpAddr;
//!
//! // Reject the RFC 1918 ranges; accept everything else, bumping the metric.
//! let filter = Filter {
//!     rules: vec![Rule {
//!         matcher: Match::prefix("10.0.0.0/8+".parse::<PrefixList>().unwrap()),
//!         modify: Modify::default(),
//!         action: Action::Reject,
//!     }],
//!     default: Action::Accept,
//! };
//!
//! let r = Route::new("10.1.2.0/24".parse().unwrap(), Protocol::Bgp, vec![], 0);
//! assert!(matches!(filter.apply(&r), Decision::Reject));
//! ```

#![forbid(unsafe_code)]

use std::fmt;
use std::str::FromStr;

use wren_core::{Prefix, Protocol, Route};

/// One prefix pattern: a base network plus an inclusive length window. A prefix
/// matches when it falls inside the base network *and* its length is in the window.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct PrefixPattern {
    /// The base network the candidate must fall within.
    pub network: Prefix,
    /// The minimum (inclusive) prefix length that matches.
    pub min_len: u8,
    /// The maximum (inclusive) prefix length that matches.
    pub max_len: u8,
}

impl PrefixPattern {
    /// A pattern matching a window `[min_len, max_len]` within `network`. The
    /// window is clamped to `[network.len(), network.max_len()]` and ordered.
    pub fn new(network: Prefix, min_len: u8, max_len: u8) -> Self {
        let floor = network.len();
        let ceil = network.max_len();
        let lo = min_len.clamp(floor, ceil);
        let hi = max_len.clamp(floor, ceil);
        PrefixPattern {
            network,
            min_len: lo.min(hi),
            max_len: lo.max(hi),
        }
    }

    /// A pattern matching exactly `network` (BIRD `prefix`).
    pub fn exact(network: Prefix) -> Self {
        let len = network.len();
        PrefixPattern::new(network, len, len)
    }

    /// A pattern matching `network` or any more-specific prefix (BIRD `prefix+`).
    pub fn orlonger(network: Prefix) -> Self {
        let max = network.max_len();
        PrefixPattern::new(network, network.len(), max)
    }

    /// Whether `prefix` matches this pattern.
    pub fn matches(&self, prefix: &Prefix) -> bool {
        self.network.is_ipv4() == prefix.is_ipv4()
            && prefix.len() >= self.network.len()
            && self.network.contains(prefix.addr())
            && prefix.len() >= self.min_len
            && prefix.len() <= self.max_len
    }
}

impl FromStr for PrefixPattern {
    type Err = ParseError;

    /// Parse `addr/len`, `addr/len+`, or `addr/len{min,max}`.
    fn from_str(s: &str) -> Result<Self, ParseError> {
        let s = s.trim();
        if let Some(base) = s.strip_suffix('+') {
            let network = parse_prefix(base)?;
            return Ok(PrefixPattern::orlonger(network));
        }
        if let Some(open) = s.find('{') {
            let base = &s[..open];
            let window = s[open + 1..]
                .strip_suffix('}')
                .ok_or_else(|| ParseError(format!("unterminated length window in {s:?}")))?;
            let (lo, hi) = window
                .split_once(',')
                .ok_or_else(|| ParseError(format!("length window {window:?} needs `min,max`")))?;
            let network = parse_prefix(base)?;
            let min_len = parse_len(lo)?;
            let max_len = parse_len(hi)?;
            return Ok(PrefixPattern::new(network, min_len, max_len));
        }
        Ok(PrefixPattern::exact(parse_prefix(s)?))
    }
}

/// An ordered set of prefix patterns; a prefix matches if **any** pattern does.
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct PrefixList(pub Vec<PrefixPattern>);

impl PrefixList {
    /// Whether `prefix` matches any pattern in the list.
    pub fn matches(&self, prefix: &Prefix) -> bool {
        self.0.iter().any(|p| p.matches(prefix))
    }
}

impl FromStr for PrefixList {
    type Err = ParseError;

    /// Parse a comma- or whitespace-separated list of patterns.
    fn from_str(s: &str) -> Result<Self, ParseError> {
        let mut out = Vec::new();
        for tok in s.split([',', ' ', '\t']).filter(|t| !t.trim().is_empty()) {
            out.push(tok.parse()?);
        }
        Ok(PrefixList(out))
    }
}

/// The conditions a route is tested against. All present conditions must hold
/// (logical AND); an absent condition is "don't care", so an empty `Match` accepts
/// every route.
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct Match {
    /// The route's prefix must match one of these patterns.
    pub prefix: Option<PrefixList>,
    /// The route's protocol must equal this.
    pub protocol: Option<Protocol>,
    /// The route's metric must be ≤ this.
    pub metric_le: Option<u32>,
    /// The route's metric must be ≥ this.
    pub metric_ge: Option<u32>,
}

impl Match {
    /// A match that holds for every route.
    pub fn any() -> Self {
        Match::default()
    }

    /// A match on the prefix only.
    pub fn prefix(list: PrefixList) -> Self {
        Match {
            prefix: Some(list),
            ..Match::default()
        }
    }

    /// A match on the protocol only.
    pub fn protocol(protocol: Protocol) -> Self {
        Match {
            protocol: Some(protocol),
            ..Match::default()
        }
    }

    /// Whether `route` satisfies all present conditions.
    pub fn test(&self, route: &Route) -> bool {
        self.prefix
            .as_ref()
            .map_or(true, |pl| pl.matches(&route.prefix))
            && self.protocol.map_or(true, |p| route.protocol == p)
            && self.metric_le.map_or(true, |m| route.metric <= m)
            && self.metric_ge.map_or(true, |m| route.metric >= m)
    }
}

/// Attribute changes applied to a route when a rule matches (before its action).
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct Modify {
    /// Set the metric to this value.
    pub set_metric: Option<u32>,
    /// Add this signed delta to the metric (saturating at the `u32` bounds).
    pub add_metric: Option<i64>,
    /// Set the administrative preference to this value.
    pub set_preference: Option<u32>,
    /// Replace the route's communities with this set (RFC 1997 32-bit values).
    pub set_communities: Option<Vec<u32>>,
    /// Append these communities (deduplicated, order-preserving) after any
    /// `set_communities` has been applied.
    pub add_communities: Vec<u32>,
    /// Replace the route's large communities with this set (RFC 8092 triples).
    pub set_large_communities: Option<Vec<(u32, u32, u32)>>,
    /// Append these large communities (deduplicated, order-preserving) after any
    /// `set_large_communities` has been applied.
    pub add_large_communities: Vec<(u32, u32, u32)>,
    /// Replace the route's extended communities with this set (RFC 4360, raw 8
    /// octets each).
    pub set_ext_communities: Option<Vec<[u8; 8]>>,
    /// Append these extended communities (deduplicated, order-preserving) after
    /// any `set_ext_communities` has been applied.
    pub add_ext_communities: Vec<[u8; 8]>,
}

impl Modify {
    /// Whether this modify is a no-op.
    pub fn is_noop(&self) -> bool {
        self.set_metric.is_none()
            && self.add_metric.is_none()
            && self.set_preference.is_none()
            && self.set_communities.is_none()
            && self.add_communities.is_empty()
            && self.set_large_communities.is_none()
            && self.add_large_communities.is_empty()
            && self.set_ext_communities.is_none()
            && self.add_ext_communities.is_empty()
    }

    /// Apply the changes to `route` in place. `set_metric` is applied before
    /// `add_metric`, so the two compose (set a base, then adjust); likewise
    /// `set_communities` (replace) is applied before `add_communities` (append).
    pub fn apply(&self, route: &mut Route) {
        if let Some(m) = self.set_metric {
            route.metric = m;
        }
        if let Some(d) = self.add_metric {
            route.metric = (route.metric as i64 + d).clamp(0, u32::MAX as i64) as u32;
        }
        if let Some(p) = self.set_preference {
            route.preference = p;
        }
        if let Some(set) = &self.set_communities {
            route.communities = set.clone();
        }
        for c in &self.add_communities {
            if !route.communities.contains(c) {
                route.communities.push(*c);
            }
        }
        if let Some(set) = &self.set_large_communities {
            route.large_communities = set.clone();
        }
        for c in &self.add_large_communities {
            if !route.large_communities.contains(c) {
                route.large_communities.push(*c);
            }
        }
        if let Some(set) = &self.set_ext_communities {
            route.ext_communities = set.clone();
        }
        for c in &self.add_ext_communities {
            if !route.ext_communities.contains(c) {
                route.ext_communities.push(*c);
            }
        }
    }
}

/// What a filter decides for a route.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Action {
    /// Let the route through (possibly modified).
    Accept,
    /// Drop the route.
    Reject,
}

/// One filter rule: when `matcher` holds, apply `modify` and take `action`.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Rule {
    /// The conditions that select this rule.
    pub matcher: Match,
    /// Attribute changes applied when the rule matches.
    pub modify: Modify,
    /// Whether a matching route is accepted or rejected.
    pub action: Action,
}

/// The outcome of running a filter over a route.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Decision {
    /// The route is permitted, in its (possibly modified) form.
    Accept(Route),
    /// The route is dropped.
    Reject,
}

impl Decision {
    /// The accepted route, if any.
    pub fn accepted(self) -> Option<Route> {
        match self {
            Decision::Accept(r) => Some(r),
            Decision::Reject => None,
        }
    }
}

/// A named, ordered list of rules with a fall-through default action.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Filter {
    /// The rules, evaluated in order; the first whose match holds decides.
    pub rules: Vec<Rule>,
    /// The action taken when no rule matches.
    pub default: Action,
}

impl Filter {
    /// A filter that accepts every route unchanged.
    pub fn accept_all() -> Self {
        Filter {
            rules: Vec::new(),
            default: Action::Accept,
        }
    }

    /// A filter that rejects every route.
    pub fn reject_all() -> Self {
        Filter {
            rules: Vec::new(),
            default: Action::Reject,
        }
    }

    /// Run the filter over `route` (first-match-wins): the first rule whose match
    /// holds applies its modify and decides; otherwise the default action applies.
    pub fn apply(&self, route: &Route) -> Decision {
        let mut candidate = route.clone();
        for rule in &self.rules {
            if rule.matcher.test(&candidate) {
                rule.modify.apply(&mut candidate);
                return match rule.action {
                    Action::Accept => Decision::Accept(candidate),
                    Action::Reject => Decision::Reject,
                };
            }
        }
        match self.default {
            Action::Accept => Decision::Accept(candidate),
            Action::Reject => Decision::Reject,
        }
    }
}

/// Parse an [`Action`] from `"accept"` / `"reject"`.
pub fn parse_action(s: &str) -> Result<Action, ParseError> {
    match s.trim().to_ascii_lowercase().as_str() {
        "accept" | "permit" => Ok(Action::Accept),
        "reject" | "deny" | "drop" => Ok(Action::Reject),
        other => Err(ParseError(format!(
            "action {other:?} (expected \"accept\" or \"reject\")"
        ))),
    }
}

// --- parsing helpers -------------------------------------------------------

fn parse_prefix(s: &str) -> Result<Prefix, ParseError> {
    s.trim()
        .parse::<Prefix>()
        .map_err(|_| ParseError(format!("invalid prefix {:?}", s.trim())))
}

fn parse_len(s: &str) -> Result<u8, ParseError> {
    s.trim()
        .parse::<u8>()
        .map_err(|_| ParseError(format!("invalid prefix length {:?}", s.trim())))
}

/// Why a filter pattern or action could not be parsed.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ParseError(pub String);

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for ParseError {}

#[cfg(test)]
mod tests {
    use super::*;
    use wren_core::Protocol;

    fn route(prefix: &str, protocol: Protocol, metric: u32) -> Route {
        Route::new(prefix.parse().unwrap(), protocol, vec![], metric)
    }

    fn pfx(s: &str) -> Prefix {
        s.parse().unwrap()
    }

    #[test]
    fn exact_pattern_matches_only_the_exact_prefix() {
        let p = PrefixPattern::exact(pfx("10.0.0.0/8"));
        assert!(p.matches(&pfx("10.0.0.0/8")));
        assert!(!p.matches(&pfx("10.1.0.0/16")));
        assert!(!p.matches(&pfx("11.0.0.0/8")));
    }

    #[test]
    fn orlonger_matches_more_specifics() {
        let p = PrefixPattern::orlonger(pfx("10.0.0.0/8"));
        assert!(p.matches(&pfx("10.0.0.0/8")));
        assert!(p.matches(&pfx("10.1.2.0/24")));
        assert!(p.matches(&pfx("10.255.255.255/32")));
        assert!(!p.matches(&pfx("11.0.0.0/8")));
        // A less-specific prefix never matches an or-longer pattern.
        assert!(!p.matches(&pfx("0.0.0.0/0")));
    }

    #[test]
    fn range_pattern_respects_the_window() {
        let p: PrefixPattern = "192.168.0.0/16{24,28}".parse().unwrap();
        assert!(!p.matches(&pfx("192.168.0.0/16")));
        assert!(!p.matches(&pfx("192.168.1.0/20")));
        assert!(p.matches(&pfx("192.168.1.0/24")));
        assert!(p.matches(&pfx("192.168.1.16/28")));
        assert!(!p.matches(&pfx("192.168.1.16/30")));
    }

    #[test]
    fn pattern_parsing_round_trips_the_forms() {
        assert_eq!(
            "10.0.0.0/8".parse::<PrefixPattern>().unwrap(),
            PrefixPattern::exact(pfx("10.0.0.0/8"))
        );
        assert_eq!(
            "10.0.0.0/8+".parse::<PrefixPattern>().unwrap(),
            PrefixPattern::orlonger(pfx("10.0.0.0/8"))
        );
        assert!("not-a-prefix".parse::<PrefixPattern>().is_err());
        assert!("10.0.0.0/8{24".parse::<PrefixPattern>().is_err());
    }

    #[test]
    fn ipv4_and_ipv6_do_not_cross_match() {
        let p = PrefixPattern::orlonger(pfx("10.0.0.0/8"));
        assert!(!p.matches(&pfx("2001:db8::/32")));
        let v6 = PrefixPattern::orlonger(pfx("2001:db8::/32"));
        assert!(v6.matches(&pfx("2001:db8:1::/48")));
        assert!(!v6.matches(&pfx("10.0.0.0/8")));
    }

    #[test]
    fn prefix_list_matches_any() {
        let list: PrefixList = "10.0.0.0/8+, 192.168.0.0/16+".parse().unwrap();
        assert!(list.matches(&pfx("10.1.0.0/16")));
        assert!(list.matches(&pfx("192.168.5.0/24")));
        assert!(!list.matches(&pfx("172.16.0.0/12")));
    }

    #[test]
    fn match_ands_its_conditions() {
        let m = Match {
            prefix: Some("10.0.0.0/8+".parse().unwrap()),
            protocol: Some(Protocol::Bgp),
            metric_ge: Some(100),
            metric_le: None,
        };
        assert!(m.test(&route("10.1.0.0/16", Protocol::Bgp, 150)));
        // Wrong protocol.
        assert!(!m.test(&route("10.1.0.0/16", Protocol::Rip, 150)));
        // Metric below the floor.
        assert!(!m.test(&route("10.1.0.0/16", Protocol::Bgp, 50)));
        // Prefix outside the list.
        assert!(!m.test(&route("172.16.0.0/12", Protocol::Bgp, 150)));
    }

    #[test]
    fn empty_match_accepts_everything() {
        assert!(Match::any().test(&route("8.8.8.0/24", Protocol::Bgp, 0)));
    }

    #[test]
    fn modify_sets_and_adds_metric_and_preference() {
        let mut r = route("10.0.0.0/24", Protocol::Rip, 5);
        Modify {
            set_metric: Some(10),
            add_metric: Some(3),
            set_preference: Some(250),
            ..Modify::default()
        }
        .apply(&mut r);
        assert_eq!(r.metric, 13); // 10 then +3
        assert_eq!(r.preference, 250);
        // Saturation: a large negative delta floors at 0.
        Modify {
            add_metric: Some(-100),
            ..Modify::default()
        }
        .apply(&mut r);
        assert_eq!(r.metric, 0);
    }

    #[test]
    fn modify_sets_and_appends_communities() {
        let mut r = route("10.0.0.0/24", Protocol::Bgp, 0);
        r.communities = vec![1, 2];
        // set replaces, then add appends (deduplicated against the new set).
        Modify {
            set_communities: Some(vec![10, 20]),
            add_communities: vec![20, 30],
            ..Modify::default()
        }
        .apply(&mut r);
        assert_eq!(r.communities, vec![10, 20, 30]);
        // add alone appends without touching existing, skipping duplicates.
        Modify {
            add_communities: vec![30, 40],
            ..Modify::default()
        }
        .apply(&mut r);
        assert_eq!(r.communities, vec![10, 20, 30, 40]);
    }

    #[test]
    fn modify_sets_and_appends_large_communities() {
        let mut r = route("10.0.0.0/24", Protocol::Bgp, 0);
        r.large_communities = vec![(1, 1, 1)];
        Modify {
            set_large_communities: Some(vec![(65536, 1, 2)]),
            add_large_communities: vec![(65536, 1, 2), (65536, 3, 4)],
            ..Modify::default()
        }
        .apply(&mut r);
        // set replaces, then add appends (deduplicated against the new set).
        assert_eq!(r.large_communities, vec![(65536, 1, 2), (65536, 3, 4)]);
    }

    #[test]
    fn modify_sets_and_appends_ext_communities() {
        let mut r = route("10.0.0.0/24", Protocol::Bgp, 0);
        let rt = [0x00, 0x02, 0xFD, 0xE9, 0x00, 0x00, 0x00, 0x64]; // rt:65001:100
        let ro = [0x00, 0x03, 0xFD, 0xE9, 0x00, 0x00, 0x00, 0x01]; // ro:65001:1
        r.ext_communities = vec![[1; 8]];
        Modify {
            set_ext_communities: Some(vec![rt]),
            add_ext_communities: vec![rt, ro],
            ..Modify::default()
        }
        .apply(&mut r);
        assert_eq!(r.ext_communities, vec![rt, ro]);
    }

    #[test]
    fn filter_is_first_match_wins() {
        let filter = Filter {
            rules: vec![
                // Reject the martians.
                Rule {
                    matcher: Match::prefix("10.0.0.0/8+, 192.168.0.0/16+".parse().unwrap()),
                    modify: Modify::default(),
                    action: Action::Reject,
                },
                // Tag BGP routes with a higher metric, accept.
                Rule {
                    matcher: Match::protocol(Protocol::Bgp),
                    modify: Modify {
                        set_metric: Some(1000),
                        ..Modify::default()
                    },
                    action: Action::Accept,
                },
            ],
            default: Action::Accept,
        };

        // Martian → rejected by the first rule.
        assert_eq!(
            filter.apply(&route("10.1.0.0/16", Protocol::Bgp, 1)),
            Decision::Reject
        );
        // Public BGP → second rule, metric rewritten.
        let d = filter.apply(&route("8.8.8.0/24", Protocol::Bgp, 1));
        match d {
            Decision::Accept(r) => assert_eq!(r.metric, 1000),
            Decision::Reject => panic!("should accept"),
        }
        // Public non-BGP → default accept, unchanged.
        let d = filter.apply(&route("8.8.8.0/24", Protocol::Rip, 7));
        assert_eq!(d.accepted().unwrap().metric, 7);
    }

    #[test]
    fn accept_all_and_reject_all() {
        let r = route("1.2.3.0/24", Protocol::Static, 0);
        assert!(matches!(
            Filter::accept_all().apply(&r),
            Decision::Accept(_)
        ));
        assert_eq!(Filter::reject_all().apply(&r), Decision::Reject);
    }

    #[test]
    fn action_parsing() {
        assert_eq!(parse_action("accept").unwrap(), Action::Accept);
        assert_eq!(parse_action("Reject").unwrap(), Action::Reject);
        assert_eq!(parse_action("deny").unwrap(), Action::Reject);
        assert!(parse_action("maybe").is_err());
    }
}
