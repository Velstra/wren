//! The IS-IS link-state database (ISO/IEC 10589 §7.3) and the sequence-number
//! synchronisation that CSNP/PSNP drive (§7.3.15).
//!
//! This is the pure data structure: a store of [`Lsp`]s keyed by their
//! [`LspId`], with the §7.3.16 recency rules deciding what replaces what, plus
//! lifetime ageing so an LSP whose Remaining Lifetime reaches zero is reported
//! for purging. On top of the store sit the two halves of the Update Process:
//!
//! * [`Lsdb::install`] — the receive path (§7.3.15.1): offer a received LSP and
//!   learn whether it became the database copy (so it must be flooded onward and
//!   trigger an SPF), was a duplicate, or was stale.
//! * [`Lsdb::summary`] / [`Lsdb::evaluate_entry`] / [`Lsdb::evaluate_csnp`] — the
//!   sequence-number-PDU path (§7.3.15.2): describe our database as the LSP
//!   Entries of a CSNP, and, from a neighbour's CSNP/PSNP, decide which LSPs to
//!   **request** (we lack them or hold an older copy) and which to **send** (we
//!   hold a newer copy, or one the neighbour never listed).
//!
//! Unlike OSPF's age, which counts *up* to `MaxAge`, an IS-IS Remaining Lifetime
//! counts *down* to zero; and an LSP is keyed by its 8-byte LSP ID alone (the
//! originator is part of that ID), not by a `(type, id, router)` triple. One
//! `Lsdb` holds a single level's database; an L1L2 router keeps one per level a
//! layer up.

use std::cmp::Ordering;
use std::collections::BTreeMap;

use crate::pdu::Lsp;
use crate::tlv::LspEntry;
use crate::LspId;

/// What happened when an LSP was offered to the database (the Update Process,
/// ISO 10589 §7.3.15.1) — a subset of the flooding decision: whether the
/// received copy is now the database copy.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Install {
    /// No instance was held; the offered LSP was stored.
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
    /// flooded onward and trigger an SPF recalculation).
    pub fn changed(self) -> bool {
        matches!(self, Install::New | Install::Newer)
    }
}

/// What a neighbour's single LSP Entry (from a CSNP or PSNP) tells us to do
/// relative to our database (ISO 10589 §7.3.15.2).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SyncAction {
    /// The neighbour advertises an LSP we lack, or a copy newer than ours:
    /// request the full LSP from them with a PSNP (set the SSN flag).
    Request,
    /// We hold a copy newer than the neighbour's: (re)send our LSP to them
    /// (set the SRM flag).
    Send,
    /// Our copy and the neighbour's are identical: nothing to do.
    InSync,
}

/// The result of processing a received CSNP against our database
/// (ISO 10589 §7.3.15.2): the LSPs to request from the sender and the LSPs to
/// send to it.
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct CsnpSync {
    /// LSP IDs to request via a PSNP — we lack them or hold an older copy.
    pub request: Vec<LspId>,
    /// LSP IDs to (re)send — we hold a newer copy, or one the CSNP's range
    /// covered but never listed.
    pub send: Vec<LspId>,
}

/// An IS-IS link-state database for one level.
#[derive(Clone, Default)]
pub struct Lsdb {
    entries: BTreeMap<LspId, Lsp>,
}

impl Lsdb {
    /// An empty database.
    pub fn new() -> Self {
        Lsdb {
            entries: BTreeMap::new(),
        }
    }

    /// The database copy of an LSP, if held.
    pub fn get(&self, id: &LspId) -> Option<&Lsp> {
        self.entries.get(id)
    }

    /// Whether the database holds an LSP with this ID.
    pub fn contains(&self, id: &LspId) -> bool {
        self.entries.contains_key(id)
    }

    /// The number of LSPs held.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the database is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Iterate over every LSP, in ascending LSP-ID order.
    pub fn iter(&self) -> impl Iterator<Item = &Lsp> {
        self.entries.values()
    }

    /// Offer an LSP to the database, keeping it only if it is at least as recent
    /// as any instance already held (ISO 10589 §7.3.16). Returns the [`Install`]
    /// outcome; the caller uses [`Install::changed`] to decide whether to flood
    /// it on and re-run SPF.
    pub fn install(&mut self, lsp: Lsp) -> Install {
        let id = lsp.lsp_id;
        match self.entries.get(&id) {
            None => {
                self.entries.insert(id, lsp);
                Install::New
            }
            Some(existing) => match recency(&lsp, existing) {
                Ordering::Greater => {
                    self.entries.insert(id, lsp);
                    Install::Newer
                }
                Ordering::Equal => Install::Same,
                Ordering::Less => Install::HaveNewer,
            },
        }
    }

    /// Remove an LSP outright (e.g. once a purged zero-lifetime LSP has been
    /// acknowledged). Returns the removed LSP if present.
    pub fn remove(&mut self, id: &LspId) -> Option<Lsp> {
        self.entries.remove(id)
    }

    /// Decrement every LSP's Remaining Lifetime by `secs` seconds, saturating at
    /// zero. Returns the IDs of LSPs that have just *reached* zero lifetime and so
    /// must be purged from the domain (re-flooded at zero lifetime, then removed
    /// once acknowledged). An LSP already at zero is not reported again.
    pub fn age(&mut self, secs: u16) -> Vec<LspId> {
        let mut expired = Vec::new();
        for (id, lsp) in self.entries.iter_mut() {
            if lsp.remaining_lifetime == 0 {
                continue;
            }
            lsp.remaining_lifetime = lsp.remaining_lifetime.saturating_sub(secs);
            if lsp.remaining_lifetime == 0 {
                expired.push(*id);
            }
        }
        expired
    }

    /// Describe the whole database as LSP Entries (lifetime, ID, sequence number,
    /// checksum), in ascending LSP-ID order — the body of a CSNP (§9.10).
    pub fn summary(&self) -> Vec<LspEntry> {
        self.entries.values().map(entry_of).collect()
    }

    /// Describe the database restricted to the inclusive LSP-ID range
    /// `[start, end]` — a CSNP covering one range of the ID space (§9.10).
    pub fn summary_range(&self, start: LspId, end: LspId) -> Vec<LspEntry> {
        self.entries
            .range(start..=end)
            .map(|(_, lsp)| entry_of(lsp))
            .collect()
    }

    /// Compare one LSP Entry from a neighbour's CSNP/PSNP against our database and
    /// decide what to do about it (ISO 10589 §7.3.15.2).
    pub fn evaluate_entry(&self, entry: &LspEntry) -> SyncAction {
        match self.entries.get(&entry.lsp_id) {
            // We hold nothing: the neighbour knows an LSP we do not — request it.
            None => SyncAction::Request,
            Some(ours) => match entry_recency(entry, ours) {
                // Their advertised copy is newer than ours — request it.
                Ordering::Greater => SyncAction::Request,
                // Ours is newer — (re)send it to them.
                Ordering::Less => SyncAction::Send,
                // Identical — synchronised.
                Ordering::Equal => SyncAction::InSync,
            },
        }
    }

    /// Process a received CSNP (its entries plus the `[start, end]` LSP-ID range
    /// it claims to cover completely) against our database (ISO 10589 §7.3.15.2),
    /// yielding the LSPs to request and the LSPs to send.
    ///
    /// Every listed entry is classified by [`evaluate_entry`](Self::evaluate_entry);
    /// in addition, any LSP we hold within `[start, end]` that the CSNP did *not*
    /// list is one the sender lacks, so it is added to `send`.
    pub fn evaluate_csnp(&self, entries: &[LspEntry], start: LspId, end: LspId) -> CsnpSync {
        let mut sync = CsnpSync::default();
        let mut listed = std::collections::BTreeSet::new();
        for entry in entries {
            listed.insert(entry.lsp_id);
            match self.evaluate_entry(entry) {
                SyncAction::Request => sync.request.push(entry.lsp_id),
                SyncAction::Send => sync.send.push(entry.lsp_id),
                SyncAction::InSync => {}
            }
        }
        // LSPs we hold in the covered range but the CSNP never mentioned: the
        // sender is missing them, so offer them.
        for (id, _) in self.entries.range(start..=end) {
            if !listed.contains(id) {
                sync.send.push(*id);
            }
        }
        sync
    }
}

/// Build an LSP Entry (the CSNP/PSNP advertisement) for a stored LSP.
fn entry_of(lsp: &Lsp) -> LspEntry {
    LspEntry {
        remaining_lifetime: lsp.remaining_lifetime,
        lsp_id: lsp.lsp_id,
        sequence_number: lsp.sequence_number,
        checksum: lsp.checksum,
    }
}

/// Order two LSPs with the same LSP ID by recency (ISO 10589 §7.3.16.3/.4):
/// `Greater` means the first argument is the more recent.
fn recency(a: &Lsp, b: &Lsp) -> Ordering {
    cmp_recency(
        (a.sequence_number, a.remaining_lifetime, a.checksum),
        (b.sequence_number, b.remaining_lifetime, b.checksum),
    )
}

/// Order a received LSP Entry against a stored LSP by recency.
fn entry_recency(entry: &LspEntry, ours: &Lsp) -> Ordering {
    cmp_recency(
        (
            entry.sequence_number,
            entry.remaining_lifetime,
            entry.checksum,
        ),
        (ours.sequence_number, ours.remaining_lifetime, ours.checksum),
    )
}

/// The ISO 10589 §7.3.16.4 recency comparison over `(sequence, lifetime,
/// checksum)`. Higher sequence number wins; on a tie, a zero Remaining Lifetime
/// (a purge) is more recent than a non-zero one; on a further tie, the larger
/// checksum is the deterministic tie-break. `Greater` ⇒ `a` is more recent.
fn cmp_recency(a: (u32, u16, u16), b: (u32, u16, u16)) -> Ordering {
    let (a_seq, a_life, a_csum) = a;
    let (b_seq, b_life, b_csum) = b;
    match a_seq.cmp(&b_seq) {
        Ordering::Equal => {}
        other => return other,
    }
    // Equal sequence numbers: an expired (zero-lifetime) LSP is more recent.
    let a_zero = a_life == 0;
    let b_zero = b_life == 0;
    match (a_zero, b_zero) {
        (true, false) => return Ordering::Greater,
        (false, true) => return Ordering::Less,
        _ => {}
    }
    // Still tied: the larger checksum is the deterministic discriminator.
    a_csum.cmp(&b_csum)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pdu::Lsp;
    use crate::tlv::{ExtIpReach, Tlv};
    use crate::{IsLevel, SystemId};
    use std::net::Ipv4Addr;

    fn sid(n: u8) -> SystemId {
        SystemId::new([n, n, n, n, n, n])
    }

    fn lsp(id_byte: u8, seq: u32, life: u16, csum: u16) -> Lsp {
        Lsp {
            level: IsLevel::L1,
            remaining_lifetime: life,
            lsp_id: LspId::new(sid(id_byte), 0, 0),
            sequence_number: seq,
            checksum: csum,
            partition: false,
            attached: 0,
            overload: false,
            is_type: IsLevel::L1,
            tlvs: vec![Tlv::ExtendedIpReachability(vec![ExtIpReach {
                metric: 10,
                up_down: false,
                prefix_len: 24,
                prefix: Ipv4Addr::new(10, 0, id_byte, 0),
                sub_tlvs: None,
            }])],
        }
    }

    fn id(b: u8) -> LspId {
        LspId::new(sid(b), 0, 0)
    }

    #[test]
    fn install_new_then_newer_then_stale() {
        let mut db = Lsdb::new();
        assert_eq!(db.install(lsp(1, 5, 1000, 0xaa)), Install::New);
        assert_eq!(db.len(), 1);
        // A higher sequence number replaces it.
        assert_eq!(db.install(lsp(1, 6, 1000, 0xbb)), Install::Newer);
        // The same sequence and checksum is a no-op.
        assert_eq!(db.install(lsp(1, 6, 1000, 0xbb)), Install::Same);
        // A lower sequence number is rejected.
        assert_eq!(db.install(lsp(1, 5, 1000, 0xcc)), Install::HaveNewer);
        assert_eq!(db.get(&id(1)).unwrap().sequence_number, 6);
    }

    #[test]
    fn changed_flags_match_flooding_intent() {
        assert!(Install::New.changed());
        assert!(Install::Newer.changed());
        assert!(!Install::Same.changed());
        assert!(!Install::HaveNewer.changed());
    }

    #[test]
    fn purge_beats_live_at_equal_sequence() {
        let mut db = Lsdb::new();
        db.install(lsp(1, 7, 1000, 0xaa));
        // Same sequence but a zero Remaining Lifetime (a purge) is more recent.
        assert_eq!(db.install(lsp(1, 7, 0, 0xaa)), Install::Newer);
        assert_eq!(db.get(&id(1)).unwrap().remaining_lifetime, 0);
        // A live copy at the same sequence no longer displaces the purge.
        assert_eq!(db.install(lsp(1, 7, 1000, 0xaa)), Install::HaveNewer);
    }

    #[test]
    fn distinct_ids_coexist() {
        let mut db = Lsdb::new();
        db.install(lsp(1, 1, 1000, 1));
        db.install(lsp(2, 1, 1000, 2));
        db.install(lsp(3, 1, 1000, 3));
        assert_eq!(db.len(), 3);
        assert!(db.contains(&id(2)));
        // Ascending LSP-ID iteration order.
        let ids: Vec<_> = db.iter().map(|l| l.lsp_id).collect();
        assert_eq!(ids, vec![id(1), id(2), id(3)]);
    }

    #[test]
    fn ageing_counts_down_and_reports_expiry() {
        let mut db = Lsdb::new();
        db.install(lsp(1, 1, 30, 1));
        db.install(lsp(2, 1, 1000, 2));
        // The first drops to zero; the second is merely decremented.
        let expired = db.age(30);
        assert_eq!(expired, vec![id(1)]);
        assert_eq!(db.get(&id(1)).unwrap().remaining_lifetime, 0);
        assert_eq!(db.get(&id(2)).unwrap().remaining_lifetime, 970);
        // An already-expired LSP is not reported a second time.
        assert!(db.age(10).is_empty());
    }

    #[test]
    fn remove_works() {
        let mut db = Lsdb::new();
        db.install(lsp(1, 1, 1000, 1));
        assert!(db.remove(&id(1)).is_some());
        assert!(db.is_empty());
        assert!(db.remove(&id(1)).is_none());
    }

    #[test]
    fn summary_describes_database() {
        let mut db = Lsdb::new();
        db.install(lsp(2, 4, 800, 0x1234));
        db.install(lsp(1, 9, 600, 0x5678));
        let sum = db.summary();
        // Sorted by LSP ID, carrying lifetime/seq/checksum.
        assert_eq!(sum.len(), 2);
        assert_eq!(sum[0].lsp_id, id(1));
        assert_eq!(sum[0].sequence_number, 9);
        assert_eq!(sum[0].checksum, 0x5678);
        assert_eq!(sum[1].lsp_id, id(2));
        // A restricted range only covers part of the ID space.
        let ranged = db.summary_range(id(2), id(0xff));
        assert_eq!(ranged.len(), 1);
        assert_eq!(ranged[0].lsp_id, id(2));
    }

    fn entry(b: u8, seq: u32, life: u16, csum: u16) -> LspEntry {
        LspEntry {
            remaining_lifetime: life,
            lsp_id: id(b),
            sequence_number: seq,
            checksum: csum,
        }
    }

    #[test]
    fn evaluate_entry_classifies_each_case() {
        let mut db = Lsdb::new();
        db.install(lsp(1, 5, 1000, 0xaa));
        // Unknown LSP — request it.
        assert_eq!(
            db.evaluate_entry(&entry(9, 1, 1000, 1)),
            SyncAction::Request
        );
        // Newer than ours — request it.
        assert_eq!(
            db.evaluate_entry(&entry(1, 6, 1000, 0xaa)),
            SyncAction::Request
        );
        // Older than ours — send ours.
        assert_eq!(
            db.evaluate_entry(&entry(1, 4, 1000, 0xaa)),
            SyncAction::Send
        );
        // Identical — in sync.
        assert_eq!(
            db.evaluate_entry(&entry(1, 5, 1000, 0xaa)),
            SyncAction::InSync
        );
    }

    #[test]
    fn evaluate_csnp_requests_sends_and_fills_gaps() {
        let mut db = Lsdb::new();
        db.install(lsp(1, 5, 1000, 0xaa)); // same as CSNP -> in sync
        db.install(lsp(2, 9, 1000, 0xbb)); // newer than CSNP -> send
        db.install(lsp(4, 1, 1000, 0xcc)); // not in CSNP, in range -> send
        let csnp = vec![
            entry(1, 5, 1000, 0xaa),
            entry(2, 3, 1000, 0xbb), // older than ours
            entry(3, 7, 1000, 0xdd), // we lack it -> request
        ];
        let sync = db.evaluate_csnp(&csnp, id(0), id(0xff));
        assert_eq!(sync.request, vec![id(3)]);
        // 2 (newer ours) then the unlisted-in-range 4.
        assert_eq!(sync.send, vec![id(2), id(4)]);
    }

    #[test]
    fn evaluate_csnp_respects_the_range() {
        let mut db = Lsdb::new();
        db.install(lsp(1, 1, 1000, 1));
        db.install(lsp(9, 1, 1000, 9)); // outside the CSNP's range
                                        // An empty CSNP over [1,5]: only LSP 1 is "missing at the sender".
        let sync = db.evaluate_csnp(&[], id(1), id(5));
        assert_eq!(sync.send, vec![id(1)]);
        assert!(sync.request.is_empty());
    }
}
