//! The link-state database (RFC 2328 §12.2) and the rules for keeping the most
//! recent instance of each LSA (§13).
//!
//! This is the pure data structure: a keyed store of [`Lsa`]s with the §13.1
//! recency test deciding what replaces what, plus aging so instances that reach
//! [`MAX_AGE`](crate::MAX_AGE) can be flushed. Flooding, retransmission lists and
//! the SPF that reads this database are the next milestones; they all build on
//! `install` / `get` / `iter` / `age` here.
//!
//! Scope: one `Lsdb` holds the LSAs of a single flooding scope. Types 1–4 are
//! area-scoped (one database per area); type 5 (AS-external) is AS-wide. A multi-
//! area router keeps one of these per area plus one for externals; that wiring
//! lives a layer up.

use std::collections::BTreeMap;
use std::net::Ipv4Addr;

use crate::lsa::{Lsa, LsType, LsaHeader};
use crate::MAX_AGE;

/// The identity that names an LSA across its instances: type, Link State ID and
/// advertising router (§12.1).
pub type LsaKey = (LsType, Ipv4Addr, Ipv4Addr);

/// What happened when an LSA was offered to the database (a subset of the §13
/// flooding decision: whether the received copy is now the database copy).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Install {
    /// No instance was held; the offered LSA was stored.
    New,
    /// A strictly older instance was replaced by the offered one.
    Newer,
    /// The offered instance is identical to the one held; nothing changed.
    Same,
    /// The database already holds a strictly newer instance; offer ignored.
    HaveNewer,
}

impl Install {
    /// Whether this outcome changed the database contents (and so should be
    /// flooded onward / trigger an SPF recalculation).
    pub fn changed(self) -> bool {
        matches!(self, Install::New | Install::Newer)
    }
}

/// A link-state database for one flooding scope.
#[derive(Clone, Default)]
pub struct Lsdb {
    entries: BTreeMap<LsaKey, Lsa>,
}

impl Lsdb {
    /// An empty database.
    pub fn new() -> Self {
        Lsdb {
            entries: BTreeMap::new(),
        }
    }

    /// The database copy of an LSA, if held.
    pub fn get(&self, key: &LsaKey) -> Option<&Lsa> {
        self.entries.get(key)
    }

    /// The header of the database copy, if held — what flooding compares against
    /// without needing the whole body.
    pub fn header(&self, key: &LsaKey) -> Option<&LsaHeader> {
        self.entries.get(key).map(|l| &l.header)
    }

    /// The number of LSAs held.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the database is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Iterate over every LSA, in `(type, link-state-id, advertising-router)`
    /// order.
    pub fn iter(&self) -> impl Iterator<Item = &Lsa> {
        self.entries.values()
    }

    /// Iterate over every LSA of one type.
    pub fn iter_type(&self, ls_type: LsType) -> impl Iterator<Item = &Lsa> {
        self.entries
            .iter()
            .filter(move |(k, _)| k.0 == ls_type)
            .map(|(_, v)| v)
    }

    /// Offer an LSA to the database, keeping it only if it is at least as recent
    /// as any instance already held (RFC 2328 §13.1). Returns the [`Install`]
    /// outcome; the caller uses [`Install::changed`] to decide whether to flood
    /// it on and re-run SPF.
    pub fn install(&mut self, lsa: Lsa) -> Install {
        let key = lsa.key();
        match self.entries.get(&key) {
            None => {
                self.entries.insert(key, lsa);
                Install::New
            }
            Some(existing) => match lsa.header.compare_recency(&existing.header) {
                std::cmp::Ordering::Greater => {
                    self.entries.insert(key, lsa);
                    Install::Newer
                }
                std::cmp::Ordering::Equal => Install::Same,
                std::cmp::Ordering::Less => Install::HaveNewer,
            },
        }
    }

    /// Remove an LSA outright (e.g. once a flushed MaxAge LSA has been
    /// acknowledged by all neighbours). Returns the removed LSA if present.
    pub fn remove(&mut self, key: &LsaKey) -> Option<Lsa> {
        self.entries.remove(key)
    }

    /// Advance every LSA's age by `secs` seconds, capping at [`MAX_AGE`].
    /// Returns the keys of LSAs that have *reached* MaxAge and so must be flushed
    /// from the domain (re-flooded at MaxAge, then removed once acknowledged).
    pub fn age(&mut self, secs: u16) -> Vec<LsaKey> {
        let mut maxaged = Vec::new();
        for (key, lsa) in self.entries.iter_mut() {
            let was_max = lsa.header.ls_age >= MAX_AGE;
            lsa.header.ls_age = lsa.header.ls_age.saturating_add(secs).min(MAX_AGE);
            if !was_max && lsa.header.ls_age >= MAX_AGE {
                maxaged.push(*key);
            }
        }
        maxaged
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lsa::{LsaBody, RouterLsa, SummaryLsa};
    use crate::{INITIAL_SEQUENCE_NUMBER, MAX_AGE_DIFF, OPT_E};

    fn router_lsa(advr: [u8; 4], seq: i32, age: u16) -> Lsa {
        Lsa {
            header: LsaHeader {
                ls_age: age,
                options: OPT_E,
                ls_type: LsType::Router,
                link_state_id: Ipv4Addr::from(advr),
                advertising_router: Ipv4Addr::from(advr),
                ls_seq: seq,
                ls_checksum: 0,
                length: 0,
            },
            body: LsaBody::Router(RouterLsa {
                flags: 0,
                links: vec![],
            }),
        }
    }

    fn summary(lsid: [u8; 4], metric: u32) -> Lsa {
        Lsa {
            header: LsaHeader {
                ls_age: 0,
                options: OPT_E,
                ls_type: LsType::SummaryNetwork,
                link_state_id: Ipv4Addr::from(lsid),
                advertising_router: Ipv4Addr::new(10, 0, 0, 1),
                ls_seq: INITIAL_SEQUENCE_NUMBER,
                ls_checksum: 0,
                length: 0,
            },
            body: LsaBody::Summary(SummaryLsa {
                network_mask: Ipv4Addr::new(255, 255, 0, 0),
                metric,
            }),
        }
    }

    #[test]
    fn install_new_then_newer_then_stale() {
        let mut db = Lsdb::new();
        assert_eq!(db.install(router_lsa([10, 0, 0, 1], 5, 1)), Install::New);
        assert_eq!(db.len(), 1);
        // A higher sequence replaces it.
        assert_eq!(db.install(router_lsa([10, 0, 0, 1], 6, 1)), Install::Newer);
        // The same instance is a no-op.
        assert_eq!(db.install(router_lsa([10, 0, 0, 1], 6, 1)), Install::Same);
        // An older instance is rejected, database copy unchanged.
        assert_eq!(db.install(router_lsa([10, 0, 0, 1], 5, 1)), Install::HaveNewer);
        let k = (LsType::Router, [10, 0, 0, 1].into(), [10, 0, 0, 1].into());
        assert_eq!(db.get(&k).unwrap().header.ls_seq, 6);
    }

    #[test]
    fn changed_flags_match_flooding_intent() {
        assert!(Install::New.changed());
        assert!(Install::Newer.changed());
        assert!(!Install::Same.changed());
        assert!(!Install::HaveNewer.changed());
    }

    #[test]
    fn distinct_keys_coexist() {
        let mut db = Lsdb::new();
        db.install(router_lsa([10, 0, 0, 1], 5, 1));
        db.install(router_lsa([10, 0, 0, 2], 5, 1));
        db.install(summary([10, 2, 0, 0], 30));
        assert_eq!(db.len(), 3);
        assert_eq!(db.iter_type(LsType::Router).count(), 2);
        assert_eq!(db.iter_type(LsType::SummaryNetwork).count(), 1);
        assert_eq!(db.iter_type(LsType::Network).count(), 0);
    }

    #[test]
    fn aging_caps_and_reports_maxage() {
        let mut db = Lsdb::new();
        db.install(router_lsa([10, 0, 0, 1], 5, MAX_AGE - 10));
        db.install(router_lsa([10, 0, 0, 2], 5, 0));
        // Age past the cap for the first, not the second.
        let flushed = db.age(20);
        assert_eq!(
            flushed,
            vec![(LsType::Router, [10, 0, 0, 1].into(), [10, 0, 0, 1].into())]
        );
        // Capped, not overflowed.
        let k1 = (
            LsType::Router,
            Ipv4Addr::from([10, 0, 0, 1]),
            Ipv4Addr::from([10, 0, 0, 1]),
        );
        assert_eq!(db.get(&k1).unwrap().header.ls_age, MAX_AGE);
        // Aging again does not re-report an already-MaxAge LSA.
        assert!(db.age(MAX_AGE_DIFF).is_empty());
    }

    #[test]
    fn remove_works() {
        let mut db = Lsdb::new();
        db.install(router_lsa([10, 0, 0, 1], 5, 1));
        let k = (
            LsType::Router,
            Ipv4Addr::from([10, 0, 0, 1]),
            Ipv4Addr::from([10, 0, 0, 1]),
        );
        assert!(db.remove(&k).is_some());
        assert!(db.is_empty());
        assert!(db.remove(&k).is_none());
    }
}
