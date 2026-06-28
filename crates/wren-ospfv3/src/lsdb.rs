//! The link-state database (RFC 5340 §12.2, inheriting RFC 2328 §13) and the
//! rules for keeping the most recent instance of each LSA (§13.1).
//!
//! This is the pure data structure: a keyed store of [`Lsa`]s with the §13.1
//! recency test deciding what replaces what, plus aging so instances that reach
//! [`MAX_AGE`](crate::MAX_AGE) can be flushed. It is identical in shape to the
//! OSPFv2 database — the recency rules did not change — only the LSA types it
//! stores did.
//!
//! Scope: one `Lsdb` holds the LSAs of a single flooding scope ([`Scope`]). In
//! OSPFv3 there are three: **link-local** (Link-LSAs, one database per interface),
//! **area** (Router/Network/Inter-Area-*/Intra-Area-Prefix, one per area) and
//! **AS** (AS-external, one AS-wide). A router keeps one `Lsdb` per active scope;
//! that wiring lives a layer up. Because the [`LsType`] already carries its scope
//! bits, [`Lsdb::scope_is_consistent`] lets the wiring assert it never mixed two.

use std::collections::BTreeMap;
use std::net::Ipv4Addr;

use crate::lsa::{Lsa, LsType, LsaHeader, Scope};
use crate::MAX_AGE;

/// The identity that names an LSA across its instances: type, Link State ID and
/// advertising router (§4.4.3).
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

    /// Whether every LSA held shares the given flooding scope. The wiring keeps
    /// one database per scope, so this should always hold; it is a cheap
    /// invariant check (e.g. in tests) rather than something flooding relies on.
    pub fn scope_is_consistent(&self, scope: Scope) -> bool {
        self.entries.keys().all(|(t, _, _)| t.scope() == scope)
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

    /// Advance every LSA's age by `secs` seconds, capping at [`MAX_AGE`]. Returns
    /// the keys of LSAs that have *reached* MaxAge and so must be flushed from the
    /// domain (re-flooded at MaxAge, then removed once acknowledged).
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
    use crate::lsa::{IntraAreaPrefixLsa, LsaBody, RouterLsa};
    use crate::{INITIAL_SEQUENCE_NUMBER, MAX_AGE_DIFF, OPT_R, OPT_V6};

    fn router_lsa(advr: [u8; 4], seq: i32, age: u16) -> Lsa {
        Lsa {
            header: LsaHeader {
                ls_age: age,
                ls_type: LsType::Router,
                link_state_id: Ipv4Addr::new(0, 0, 0, 0),
                advertising_router: Ipv4Addr::from(advr),
                ls_seq: seq,
                ls_checksum: 0,
                length: 0,
            },
            body: LsaBody::Router(RouterLsa {
                flags: 0,
                options: OPT_V6 | OPT_R,
                links: vec![],
            }),
        }
    }

    fn intra_prefix(advr: [u8; 4], lsid: [u8; 4]) -> Lsa {
        Lsa {
            header: LsaHeader {
                ls_age: 0,
                ls_type: LsType::IntraAreaPrefix,
                link_state_id: Ipv4Addr::from(lsid),
                advertising_router: Ipv4Addr::from(advr),
                ls_seq: INITIAL_SEQUENCE_NUMBER,
                ls_checksum: 0,
                length: 0,
            },
            body: LsaBody::IntraAreaPrefix(IntraAreaPrefixLsa {
                referenced_ls_type: LsType::Router.as_u16(),
                referenced_link_state_id: Ipv4Addr::new(0, 0, 0, 0),
                referenced_advertising_router: Ipv4Addr::from(advr),
                prefixes: vec![],
            }),
        }
    }

    #[test]
    fn install_new_then_newer_then_stale() {
        let mut db = Lsdb::new();
        assert_eq!(db.install(router_lsa([10, 0, 0, 1], 5, 1)), Install::New);
        assert_eq!(db.len(), 1);
        assert_eq!(db.install(router_lsa([10, 0, 0, 1], 6, 1)), Install::Newer);
        assert_eq!(db.install(router_lsa([10, 0, 0, 1], 6, 1)), Install::Same);
        assert_eq!(db.install(router_lsa([10, 0, 0, 1], 5, 1)), Install::HaveNewer);
        let k = (LsType::Router, [0, 0, 0, 0].into(), [10, 0, 0, 1].into());
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
    fn distinct_keys_coexist_and_scope_holds() {
        let mut db = Lsdb::new();
        // Two routers' Router-LSAs share a Link State ID (0) but differ by
        // advertising router — an OSPFv3 quirk the key handles.
        db.install(router_lsa([10, 0, 0, 1], 5, 1));
        db.install(router_lsa([10, 0, 0, 2], 5, 1));
        db.install(intra_prefix([10, 0, 0, 1], [0, 0, 0, 1]));
        assert_eq!(db.len(), 3);
        assert_eq!(db.iter_type(LsType::Router).count(), 2);
        assert_eq!(db.iter_type(LsType::IntraAreaPrefix).count(), 1);
        assert_eq!(db.iter_type(LsType::Network).count(), 0);
        // Router and Intra-Area-Prefix are both area-scoped — one database is fine.
        assert!(db.scope_is_consistent(Scope::Area));
        assert!(!db.scope_is_consistent(Scope::LinkLocal));
    }

    #[test]
    fn aging_caps_and_reports_maxage() {
        let mut db = Lsdb::new();
        db.install(router_lsa([10, 0, 0, 1], 5, MAX_AGE - 10));
        db.install(router_lsa([10, 0, 0, 2], 5, 0));
        let flushed = db.age(20);
        assert_eq!(
            flushed,
            vec![(LsType::Router, [0, 0, 0, 0].into(), [10, 0, 0, 1].into())]
        );
        let k1 = (
            LsType::Router,
            Ipv4Addr::new(0, 0, 0, 0),
            Ipv4Addr::from([10, 0, 0, 1]),
        );
        assert_eq!(db.get(&k1).unwrap().header.ls_age, MAX_AGE);
        assert!(db.age(MAX_AGE_DIFF).is_empty());
    }

    #[test]
    fn remove_works() {
        let mut db = Lsdb::new();
        db.install(router_lsa([10, 0, 0, 1], 5, 1));
        let k = (
            LsType::Router,
            Ipv4Addr::new(0, 0, 0, 0),
            Ipv4Addr::from([10, 0, 0, 1]),
        );
        assert!(db.remove(&k).is_some());
        assert!(db.is_empty());
        assert!(db.remove(&k).is_none());
    }
}
