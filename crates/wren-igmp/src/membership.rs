//! # The querier membership state machine (RFC 3376 §6)
//!
//! A querier keeps, per interface, a table of the multicast groups that have at
//! least one interested host on the link. This module is that table: it consumes
//! decoded [`Message`](crate::wire::Message) reports (fed by the socket runner),
//! updates each group's filter mode and source list, refreshes the group timer,
//! and ages a group out when no report refreshes it within the Group Membership
//! Interval.
//!
//! ## Modelled exactly
//!
//! The IPTV / firewall cases that matter:
//!
//! * **join `*,G`** — a `MODE_IS_EXCLUDE {}` / `CHANGE_TO_EXCLUDE_MODE {}` report,
//!   or a legacy v1/v2 report: the group is (re)joined in EXCLUDE mode with an empty
//!   exclude set (= "all sources"), timer refreshed;
//! * **SSM join `S,G`** — `MODE_IS_INCLUDE`/`CHANGE_TO_INCLUDE_MODE` with sources:
//!   INCLUDE mode with that source set;
//! * **source add/remove** — `ALLOW_NEW_SOURCES`/`BLOCK_OLD_SOURCES` adjust the
//!   INCLUDE source set;
//! * **leave** — `CHANGE_TO_INCLUDE_MODE {}` (INCLUDE with no sources), a v2 Leave
//!   or an MLDv1 Done: triggers Last-Member-Query fast-leave (see below);
//! * **timeout** — [`MembershipTable::expire`] drops groups whose timer elapsed.
//!
//! ## Last-Member-Query fast-leave (§6.4)
//!
//! A leave (v2 Leave / MLDv1 Done / an INCLUDE→empty change) does **not** drop the
//! group at once: [`MembershipTable::leave_group`] shortens the group timer to the
//! last-member window (`LMQI * LMQC`) and returns [`MembershipEvent::Querying`], and
//! the socket runner sends the corresponding Group-Specific Queries. A report that
//! arrives before the shortened deadline keeps the group; otherwise
//! [`MembershipTable::expire`] drops it. The clock stays injected, so this is fully
//! unit-testable.
//!
//! ## Simplified (documented)
//!
//! The full §6.4 EXCLUDE(X,Y) two-set model — a per-source timer on the *requested*
//! set X distinct from the un-timed *blocked* set Y — is not modelled: EXCLUDE keeps
//! a single blocked-source set and one group timer. This is exact for the any-source
//! IPTV case (EXCLUDE `{}`) that drives this crate; it only loosens per-source
//! precision for the rare mixed EXCLUDE-with-sources report. INCLUDE-mode sources
//! share the group timer rather than each carrying its own.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::{Duration, Instant};

use crate::wire::{Message, RecordType};

/// A multicast group address a membership table can be keyed on. Abstracts over
/// IPv4 (IGMP) and IPv6 (MLD) so the RFC 3376 §6 / RFC 3810 §6 state machine — which
/// is byte-for-byte the same logic — is written once. The only address-family
/// difference is which groups are *link-scoped control* groups a querier never
/// tracks or proxies.
pub trait MulticastAddr: Copy + Ord + Eq + fmt::Debug + fmt::Display {
    /// True for a link-scoped control group (IPv4 `224.0.0.0/24`; IPv6 interface-
    /// or link-local scope, `ffx1::/16` / `ffx2::/16`) — never tracked/proxied.
    fn is_control(&self) -> bool;
}

impl MulticastAddr for Ipv4Addr {
    fn is_control(&self) -> bool {
        crate::is_link_local_control(*self)
    }
}

impl MulticastAddr for Ipv6Addr {
    fn is_control(&self) -> bool {
        // IPv6 multicast scope is the low nibble of the second octet (RFC 4291 §2.7):
        // 1 = interface-local, 2 = link-local. Those never leave the link.
        let o = self.octets();
        o[0] == 0xff && (o[1] & 0x0f) <= 2
    }
}

/// A group's filter mode (RFC 3376 §3.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FilterMode {
    /// Receive traffic *only* from the listed sources (SSM).
    Include,
    /// Receive traffic from all sources *except* the listed ones (the `*,G` /
    /// any-source case has an empty exclude set).
    Exclude,
}

/// The querier's per-group state on one interface. Generic over the group/source
/// address family `A` (IPv4 for IGMP, IPv6 for MLD).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupMembership<A: MulticastAddr> {
    /// Whether the source list is an allow-list (INCLUDE) or a block-list (EXCLUDE).
    pub mode: FilterMode,
    /// The source list — allowed sources in INCLUDE mode, blocked ones in EXCLUDE.
    pub sources: BTreeSet<A>,
    /// When this membership expires unless a further report refreshes it.
    pub deadline: Instant,
}

impl<A: MulticastAddr> GroupMembership<A> {
    /// The set of sources this membership currently wants forwarded, given the
    /// stream's available `available` sources. For EXCLUDE that is everything not
    /// blocked; for INCLUDE it is the intersection with the allow-list.
    pub fn wants_any_source(&self) -> bool {
        // EXCLUDE always wants at least the un-blocked sources; INCLUDE wants a
        // stream only if its allow-list is non-empty.
        matches!(self.mode, FilterMode::Exclude) || !self.sources.is_empty()
    }
}

/// Timers driving group expiry (RFC 3376 §8), all derived from the robustness
/// variable, the query interval and the query-response interval.
#[derive(Debug, Clone, Copy)]
pub struct TimerConfig {
    /// Robustness Variable (QRV), §8.1. Default 2.
    pub robustness: u8,
    /// Query Interval, §8.2. Default 125 s.
    pub query_interval: Duration,
    /// Query Response Interval (max response time), §8.3. Default 10 s.
    pub query_response_interval: Duration,
    /// Last Member Query Interval (§8.8) — the spacing of the group-specific
    /// queries a querier sends on a leave. Default 1 s.
    pub last_member_query_interval: Duration,
    /// Last Member Query Count (§8.9) — how many such queries (and, with the
    /// interval, how long the group survives a leave). Default = robustness.
    pub last_member_query_count: u8,
}

impl Default for TimerConfig {
    fn default() -> Self {
        TimerConfig {
            robustness: 2,
            query_interval: Duration::from_secs(125),
            query_response_interval: Duration::from_secs(10),
            last_member_query_interval: Duration::from_secs(1),
            last_member_query_count: 2,
        }
    }
}

impl TimerConfig {
    /// Group Membership Interval (§8.4): `QRV * QI + QRI`. A group not refreshed
    /// within this window is aged out.
    pub fn group_membership_interval(&self) -> Duration {
        self.query_interval * self.robustness.max(1) as u32 + self.query_response_interval
    }

    /// Other-Querier-Present Interval (§8.5): `QRV * QI + QRI/2`. How long a
    /// non-querier waits, hearing no lower-addressed query, before resuming as querier.
    pub fn other_querier_present_interval(&self) -> Duration {
        self.query_interval * self.robustness.max(1) as u32 + self.query_response_interval / 2
    }

    /// Last-Member window: `LMQI * LMQC`. On a leave the group timer is shortened to
    /// this, so an un-refreshed group is dropped after the group-specific queries.
    pub fn last_member_interval(&self) -> Duration {
        self.last_member_query_interval * self.last_member_query_count.max(1) as u32
    }
}

/// What changed when a report or expiry was applied — the runner turns these into
/// log lines / proxy re-syncs / MFC updates. Generic over the group address family.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MembershipEvent<A: MulticastAddr> {
    /// The group gained its first member (start forwarding it).
    Joined(A),
    /// An existing group's membership was refreshed or its source set changed.
    Updated(A),
    /// The group lost its last member (stop forwarding it).
    Left(A),
    /// A leave was received: the querier should send Group-Specific Queries for the
    /// group (Last-Member-Query, §6.4). The group's timer has been shortened; if no
    /// report refreshes it in time a `Left` follows from [`MembershipTable::expire`].
    Querying(A),
}

impl<A: MulticastAddr> MembershipEvent<A> {
    /// The group this event is about.
    pub fn group(&self) -> A {
        match *self {
            MembershipEvent::Joined(g)
            | MembershipEvent::Updated(g)
            | MembershipEvent::Left(g)
            | MembershipEvent::Querying(g) => g,
        }
    }
}

/// A querier's group table for one interface, generic over the group address family
/// `A` (IPv4 for IGMP, IPv6 for MLD). The state-machine logic is identical for both.
#[derive(Debug, Clone)]
pub struct MembershipTable<A: MulticastAddr> {
    groups: BTreeMap<A, GroupMembership<A>>,
    cfg: TimerConfig,
}

impl<A: MulticastAddr> MembershipTable<A> {
    /// A fresh, empty table with the given timers.
    pub fn new(cfg: TimerConfig) -> Self {
        MembershipTable {
            groups: BTreeMap::new(),
            cfg,
        }
    }

    /// The number of active groups.
    pub fn len(&self) -> usize {
        self.groups.len()
    }

    /// Whether the table has no groups.
    pub fn is_empty(&self) -> bool {
        self.groups.is_empty()
    }

    /// Whether `group` has a member.
    pub fn contains(&self, group: A) -> bool {
        self.groups.contains_key(&group)
    }

    /// The membership state of `group`, if any.
    pub fn get(&self, group: A) -> Option<&GroupMembership<A>> {
        self.groups.get(&group)
    }

    /// Iterate the active groups and their state, in address order.
    pub fn iter(&self) -> impl Iterator<Item = (&A, &GroupMembership<A>)> {
        self.groups.iter()
    }

    /// The set of active group addresses (what the proxy aggregates upstream).
    pub fn active_groups(&self) -> BTreeSet<A> {
        self.groups.keys().copied().collect()
    }

    /// Join `group` in any-source (EXCLUDE `{}`) mode — the plain `*,G` case.
    pub fn join_any_source(&mut self, now: Instant, group: A) -> Option<MembershipEvent<A>> {
        self.apply_record(now, group, Some(RecordType::ToExclude), &[])
    }

    /// Drop `group` outright (an administrative removal / timer expiry): the group
    /// leaves immediately with a `Left` event.
    pub fn drop_group(&mut self, group: A) -> Option<MembershipEvent<A>> {
        self.groups
            .remove(&group)
            .map(|_| MembershipEvent::Left(group))
    }

    /// Process a leave for `group` (a v2 Leave / MLDv1 Done / an INCLUDE→empty
    /// change): rather than dropping it at once, apply Last-Member-Query fast-leave
    /// (§6.4) — shorten the group's timer to the last-member window and signal the
    /// runner to send Group-Specific Queries. If a report refreshes the group before
    /// the shortened deadline it survives; otherwise [`expire`](Self::expire) drops
    /// it. Returns `Querying` (or `None` if the group was not present).
    pub fn leave_group(&mut self, now: Instant, group: A) -> Option<MembershipEvent<A>> {
        let short = now + self.cfg.last_member_interval();
        let m = self.groups.get_mut(&group)?;
        if m.deadline > short {
            m.deadline = short;
        }
        Some(MembershipEvent::Querying(group))
    }

    /// Age out every group whose timer elapsed by `now`, returning a `Left` event
    /// per removed group.
    pub fn expire(&mut self, now: Instant) -> Vec<MembershipEvent<A>> {
        let expired: Vec<A> = self
            .groups
            .iter()
            .filter(|(_, m)| m.deadline <= now)
            .map(|(g, _)| *g)
            .collect();
        expired
            .into_iter()
            .map(|g| {
                self.groups.remove(&g);
                MembershipEvent::Left(g)
            })
            .collect()
    }

    /// Apply one group record's semantics (the shared RFC 3376 §6.4 / RFC 3810 §6.4
    /// state machine). Returns the membership event, if the state changed materially.
    pub fn apply_record(
        &mut self,
        now: Instant,
        group: A,
        rtype: Option<RecordType>,
        sources: &[A],
    ) -> Option<MembershipEvent<A>> {
        // Link-scoped control groups (IPv4 224.0.0.0/24 all-systems/all-routers/the
        // v3 report destination; IPv6 interface/link-local scope) are never
        // *membership* a querier tracks: hosts never report them, and the kernel's
        // own reports for the groups we join to hear reports would otherwise show up
        // as bogus groups.
        if group.is_control() {
            return None;
        }
        let deadline = now + self.cfg.group_membership_interval();
        let existed = self.groups.contains_key(&group);
        match rtype {
            // EXCLUDE — any-source (empty) or exclude-listed. This is the common join.
            Some(RecordType::IsExclude) | Some(RecordType::ToExclude) => {
                let entry = self.groups.entry(group).or_insert_with(|| GroupMembership {
                    mode: FilterMode::Exclude,
                    sources: BTreeSet::new(),
                    deadline,
                });
                entry.mode = FilterMode::Exclude;
                entry.sources = sources.iter().copied().collect();
                entry.deadline = deadline;
                Some(if existed {
                    MembershipEvent::Updated(group)
                } else {
                    MembershipEvent::Joined(group)
                })
            }
            // INCLUDE with sources — SSM join. INCLUDE with no sources — a leave.
            Some(RecordType::IsInclude) | Some(RecordType::ToInclude) => {
                if sources.is_empty() {
                    return self.leave_group(now, group);
                }
                let entry = self.groups.entry(group).or_insert_with(|| GroupMembership {
                    mode: FilterMode::Include,
                    sources: BTreeSet::new(),
                    deadline,
                });
                entry.mode = FilterMode::Include;
                entry.sources = sources.iter().copied().collect();
                entry.deadline = deadline;
                Some(if existed {
                    MembershipEvent::Updated(group)
                } else {
                    MembershipEvent::Joined(group)
                })
            }
            // ALLOW_NEW_SOURCES — add to the INCLUDE allow-list (creating the group).
            Some(RecordType::AllowNew) => {
                let entry = self.groups.entry(group).or_insert_with(|| GroupMembership {
                    mode: FilterMode::Include,
                    sources: BTreeSet::new(),
                    deadline,
                });
                if entry.mode == FilterMode::Include {
                    entry.sources.extend(sources.iter().copied());
                }
                entry.deadline = deadline;
                Some(if existed {
                    MembershipEvent::Updated(group)
                } else {
                    MembershipEvent::Joined(group)
                })
            }
            // BLOCK_OLD_SOURCES — remove from an INCLUDE allow-list; if it empties,
            // the group is left. (In EXCLUDE mode a block adds to the block-list.)
            Some(RecordType::BlockOld) => {
                let entry = self.groups.get_mut(&group)?;
                match entry.mode {
                    FilterMode::Include => {
                        for s in sources {
                            entry.sources.remove(s);
                        }
                        if entry.sources.is_empty() {
                            return self.leave_group(now, group);
                        }
                    }
                    FilterMode::Exclude => {
                        entry.sources.extend(sources.iter().copied());
                    }
                }
                entry.deadline = deadline;
                Some(MembershipEvent::Updated(group))
            }
            // An unrecognised record type is ignored (forward-compatible).
            None => None,
        }
    }
}

/// IGMP (IPv4) specialisation: translate a decoded IGMP [`Message`] into record
/// applications. The MLD (IPv6) equivalent lives in [`crate::mld`].
impl MembershipTable<Ipv4Addr> {
    /// Apply a received IGMP report `msg` at time `now`, returning the resulting
    /// membership events. A non-report message (a query) yields no events.
    pub fn apply(&mut self, now: Instant, msg: &Message) -> Vec<MembershipEvent<Ipv4Addr>> {
        match msg {
            Message::V3Report { records } => {
                let mut events = Vec::new();
                for rec in records {
                    if let Some(ev) =
                        self.apply_record(now, rec.multicast, rec.typed(), &rec.sources)
                    {
                        events.push(ev);
                    }
                }
                events
            }
            // A v1/v2 report is a bare any-source join of the group.
            Message::V2Report(g) | Message::V1Report(g) => {
                self.join_any_source(now, *g).into_iter().collect()
            }
            // A v2 Leave triggers Last-Member-Query fast-leave (§6.4).
            Message::V2Leave(g) => self.leave_group(now, *g).into_iter().collect(),
            Message::Query(_) => Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::GroupRecord;

    fn ip(s: &str) -> Ipv4Addr {
        s.parse().unwrap()
    }

    fn table() -> MembershipTable<Ipv4Addr> {
        MembershipTable::new(TimerConfig::default())
    }

    #[test]
    fn gmi_matches_rfc_defaults() {
        // QRV 2, QI 125 s, QRI 10 s → 260 s.
        assert_eq!(
            TimerConfig::default().group_membership_interval(),
            Duration::from_secs(260)
        );
    }

    #[test]
    fn v2_report_joins_any_source_group() {
        let mut t = table();
        let now = Instant::now();
        let ev = t.apply(now, &Message::V2Report(ip("239.1.1.1")));
        assert_eq!(ev, vec![MembershipEvent::Joined(ip("239.1.1.1"))]);
        let m = t.get(ip("239.1.1.1")).unwrap();
        assert_eq!(m.mode, FilterMode::Exclude);
        assert!(m.sources.is_empty());
        assert!(m.wants_any_source());
    }

    #[test]
    fn repeated_report_refreshes_not_rejoins() {
        let mut t = table();
        let t0 = Instant::now();
        t.apply(t0, &Message::V2Report(ip("239.1.1.1")));
        let ev = t.apply(
            t0 + Duration::from_secs(1),
            &Message::V2Report(ip("239.1.1.1")),
        );
        assert_eq!(ev, vec![MembershipEvent::Updated(ip("239.1.1.1"))]);
        assert_eq!(t.len(), 1);
    }

    #[test]
    fn v3_exclude_report_joins() {
        let mut t = table();
        let msg = Message::V3Report {
            records: vec![GroupRecord::any_source(
                RecordType::ToExclude,
                ip("239.2.2.2"),
            )],
        };
        let ev = t.apply(Instant::now(), &msg);
        assert_eq!(ev, vec![MembershipEvent::Joined(ip("239.2.2.2"))]);
    }

    #[test]
    fn ssm_include_join_records_sources() {
        let mut t = table();
        let msg = Message::V3Report {
            records: vec![GroupRecord {
                record_type: RecordType::ToInclude as u8,
                multicast: ip("232.1.1.1"),
                sources: vec![ip("198.51.100.7")],
                aux: vec![],
            }],
        };
        t.apply(Instant::now(), &msg);
        let m = t.get(ip("232.1.1.1")).unwrap();
        assert_eq!(m.mode, FilterMode::Include);
        assert!(m.sources.contains(&ip("198.51.100.7")));
    }

    #[test]
    fn include_with_no_sources_is_a_leave() {
        let mut t = table();
        let now = Instant::now();
        t.apply(now, &Message::V2Report(ip("239.3.3.3")));
        let msg = Message::V3Report {
            records: vec![GroupRecord::any_source(
                RecordType::ToInclude,
                ip("239.3.3.3"),
            )],
        };
        // Fast-leave: a Querying signal now, dropped after the last-member window.
        let ev = t.apply(now, &msg);
        assert_eq!(ev, vec![MembershipEvent::Querying(ip("239.3.3.3"))]);
        assert!(t.contains(ip("239.3.3.3")));
        assert_eq!(
            t.expire(now + Duration::from_secs(2)),
            vec![MembershipEvent::Left(ip("239.3.3.3"))]
        );
        assert!(!t.contains(ip("239.3.3.3")));
    }

    #[test]
    fn v2_leave_triggers_last_member_query_then_drop() {
        let mut t = table();
        let now = Instant::now();
        t.apply(now, &Message::V2Report(ip("239.4.4.4")));
        // The leave asks for group-specific queries; the group is not dropped yet.
        let ev = t.apply(now, &Message::V2Leave(ip("239.4.4.4")));
        assert_eq!(ev, vec![MembershipEvent::Querying(ip("239.4.4.4"))]);
        assert!(t.contains(ip("239.4.4.4")));
        // LMQI·LMQC = 1s·2 = 2s. Just before → present; after → dropped.
        assert!(t.expire(now + Duration::from_millis(1900)).is_empty());
        assert_eq!(
            t.expire(now + Duration::from_secs(2)),
            vec![MembershipEvent::Left(ip("239.4.4.4"))]
        );
    }

    #[test]
    fn report_during_last_member_window_keeps_group() {
        let mut t = table();
        let t0 = Instant::now();
        t.apply(t0, &Message::V2Report(ip("239.4.4.4")));
        t.apply(t0, &Message::V2Leave(ip("239.4.4.4")));
        // A fresh report inside the window rescues the group (full GMI again).
        let ev = t.apply(
            t0 + Duration::from_secs(1),
            &Message::V2Report(ip("239.4.4.4")),
        );
        assert_eq!(ev, vec![MembershipEvent::Updated(ip("239.4.4.4"))]);
        assert!(t.expire(t0 + Duration::from_secs(5)).is_empty());
        assert!(t.contains(ip("239.4.4.4")));
    }

    #[test]
    fn leave_of_unknown_group_is_noop() {
        let mut t = table();
        let ev = t.apply(Instant::now(), &Message::V2Leave(ip("239.9.9.9")));
        assert!(ev.is_empty());
    }

    #[test]
    fn allow_then_block_sources_adjusts_include_set() {
        let mut t = table();
        let now = Instant::now();
        let allow = Message::V3Report {
            records: vec![GroupRecord {
                record_type: RecordType::AllowNew as u8,
                multicast: ip("232.5.5.5"),
                sources: vec![ip("10.0.0.1"), ip("10.0.0.2")],
                aux: vec![],
            }],
        };
        assert_eq!(
            t.apply(now, &allow),
            vec![MembershipEvent::Joined(ip("232.5.5.5"))]
        );
        assert_eq!(t.get(ip("232.5.5.5")).unwrap().sources.len(), 2);

        let block = Message::V3Report {
            records: vec![GroupRecord {
                record_type: RecordType::BlockOld as u8,
                multicast: ip("232.5.5.5"),
                sources: vec![ip("10.0.0.1")],
                aux: vec![],
            }],
        };
        assert_eq!(
            t.apply(now, &block),
            vec![MembershipEvent::Updated(ip("232.5.5.5"))]
        );
        assert_eq!(t.get(ip("232.5.5.5")).unwrap().sources.len(), 1);

        // Blocking the last source leaves the group (fast-leave → Querying, then
        // dropped once the last-member window elapses).
        let block_last = Message::V3Report {
            records: vec![GroupRecord {
                record_type: RecordType::BlockOld as u8,
                multicast: ip("232.5.5.5"),
                sources: vec![ip("10.0.0.2")],
                aux: vec![],
            }],
        };
        assert_eq!(
            t.apply(now, &block_last),
            vec![MembershipEvent::Querying(ip("232.5.5.5"))]
        );
        assert_eq!(
            t.expire(now + Duration::from_secs(2)),
            vec![MembershipEvent::Left(ip("232.5.5.5"))]
        );
        assert!(!t.contains(ip("232.5.5.5")));
    }

    #[test]
    fn group_expires_after_membership_interval() {
        let mut t = table();
        let t0 = Instant::now();
        t.apply(t0, &Message::V2Report(ip("239.6.6.6")));
        // Just before the deadline: still present.
        assert!(t.expire(t0 + Duration::from_secs(259)).is_empty());
        assert!(t.contains(ip("239.6.6.6")));
        // After the GMI (260 s): aged out.
        let ev = t.expire(t0 + Duration::from_secs(260));
        assert_eq!(ev, vec![MembershipEvent::Left(ip("239.6.6.6"))]);
        assert!(t.is_empty());
    }

    #[test]
    fn refresh_extends_the_deadline() {
        let mut t = table();
        let t0 = Instant::now();
        t.apply(t0, &Message::V2Report(ip("239.7.7.7")));
        // Refresh at t0+200s pushes the deadline out to t0+460s.
        t.apply(
            t0 + Duration::from_secs(200),
            &Message::V2Report(ip("239.7.7.7")),
        );
        assert!(t.expire(t0 + Duration::from_secs(300)).is_empty());
        assert!(t.contains(ip("239.7.7.7")));
    }

    #[test]
    fn multiple_records_in_one_report() {
        let mut t = table();
        let msg = Message::V3Report {
            records: vec![
                GroupRecord::any_source(RecordType::ToExclude, ip("239.1.0.1")),
                GroupRecord::any_source(RecordType::ToExclude, ip("239.1.0.2")),
            ],
        };
        let ev = t.apply(Instant::now(), &msg);
        assert_eq!(ev.len(), 2);
        assert_eq!(t.len(), 2);
    }

    #[test]
    fn link_local_control_groups_are_ignored() {
        let mut t = table();
        let now = Instant::now();
        // A report for a 224.0.0.0/24 control group is not tracked as membership.
        assert!(t.apply(now, &Message::V2Report(ip("224.0.0.2"))).is_empty());
        assert!(t
            .apply(now, &Message::V2Report(ip("224.0.0.22")))
            .is_empty());
        assert!(t.is_empty());
        // A normal group still is.
        assert_eq!(
            t.apply(now, &Message::V2Report(ip("239.1.2.3"))),
            vec![MembershipEvent::Joined(ip("239.1.2.3"))]
        );
    }

    #[test]
    fn query_produces_no_events() {
        let mut t = table();
        let q = Message::Query(crate::wire::Query::general(100, 2, 125));
        assert!(t.apply(Instant::now(), &q).is_empty());
    }
}
