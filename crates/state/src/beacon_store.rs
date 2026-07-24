//! BR1 randomness-beacon PERSISTENCE + REVERT contract (issue #127).
//!
//! The storage/revert boundary for the dormant beacon epoch/round state. It follows
//! the merged **C1 pattern** (`crate::compute_pool_store`) exactly — same digest
//! framing, same single-batch `persist_transition`, same journal-driven
//! `stage_block_revert` composed into the unified reorg batch — but for the beacon
//! keyspace. Because the beacon subsystem is **dormant by default**
//! (`beacon_enabled_from_height == None`), nothing writes a beacon journal during
//! live block execution, so the digest fold and the revert are byte/state-identical
//! no-ops under the production gate; they become live only once the gate opens.
//!
//! ## What is / isn't wired
//!
//! * **Wired (dormant, journal-presence-driven):** [`BeaconStore::state_digest`] is
//!   folded into the block state root **only when the beacon gate is open**
//!   (`crate::executor::compute_block_state_root`); [`BeaconStore::stage_block_revert`]
//!   is composed into the SAME atomic batch as account + contract + C1 revert
//!   (`crate::state::StateManager::revert_block_state_diffs`). Both are no-ops while
//!   no journal exists (always, under the `None` gate), so dormant behavior is
//!   unchanged.
//! * **Not yet wired (documented seam):** materializing the in-memory
//!   `sumchain_beacon_runtime` epoch/round state into the persisted row set during
//!   live block execution (which would WRITE a journal) needs a genesis
//!   `BeaconParams` + membership-snapshot source that does not exist yet. Until then
//!   the store is a complete, isolation-tested adapter — exactly the stance C1 took
//!   before its own live wiring.
//!
//! The row set is a domain-prefixed `key -> value` map; the runtime supplies a
//! materialized snapshot and this module commits/reverts it. Rows are opaque bytes
//! to the store (validated only by their 1-byte domain prefix on revert), so the
//! runtime's serialization can evolve without touching this adapter.

use std::collections::BTreeMap;

use bincode::Options;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sumchain_primitives::{BlockHeight, Hash};
use sumchain_storage::{cf, Database};

use crate::{Result, StateError};

/// Local anti-DoS ceiling on a single decoded beacon journal, in bytes. NOT a
/// consensus/economic cap — it only bounds decoder allocation on a corrupt value.
pub const BEACON_DECODE_BYTE_LIMIT: u64 = 1 << 20;

/// Domain tag for [`BeaconStore::state_digest`]. **Explicitly versioned**
/// (`…state.v1`) — a FROZEN consensus value once the beacon gate can open (it is
/// committed into the block state root), so any change requires a deliberate,
/// activation-coordinated `…state.v2` bump, never an incidental edit. Pinned by the
/// golden test `beacon_state_digest_domain_is_frozen`.
const BEACON_STATE_DIGEST_DOMAIN: &[u8] = b"sumchain.beacon.state.v1";

/// Checked 4-byte little-endian frame prefix (rejects `> u32::MAX`, which would make
/// the digest concatenation ambiguous — a consensus hazard). Byte-identical to a
/// `len as u32` cast for every realistic length.
fn frame_len(n: usize) -> Result<[u8; 4]> {
    let framed = u32::try_from(n).map_err(|_| {
        StateError::InvalidOperation(format!(
            "beacon state digest: field length {n} exceeds u32::MAX; cannot frame unambiguously"
        ))
    })?;
    Ok(framed.to_le_bytes())
}

/// 1-byte domain/type prefixes for the beacon keyspace. Each persisted row key MUST
/// begin with one of these, so no category can alias another and a corrupt journal
/// key is rejected on revert.
pub mod domain {
    /// Registered per-epoch encryption key `EK_j` (+ PoP evidence).
    pub const KEY: u8 = 0x01;
    /// A `(dealer, recipient)` deal record.
    pub const DEAL: u8 = 0x02;
    /// A per-dealer / per-complaint verdict (QUAL disqualification, slash).
    pub const VERDICT: u8 = 0x03;
    /// A finalized round's combined signature.
    pub const ROUND: u8 = 0x04;
    /// A finalized round's beacon output.
    pub const OUTPUT: u8 = 0x05;
}

/// True iff `key`'s first byte is a recognized beacon domain prefix.
fn is_beacon_domain(key: &[u8]) -> bool {
    matches!(
        key.first(),
        Some(&domain::KEY | &domain::DEAL | &domain::VERDICT | &domain::ROUND | &domain::OUTPUT)
    )
}

// --- journal codec (bincode fixint LE + limit + reject-trailing, per C1) ---

fn beacon_codec() -> impl Options {
    bincode::options()
        .with_fixint_encoding()
        .with_little_endian()
        .with_limit(BEACON_DECODE_BYTE_LIMIT)
}

fn beacon_encode<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    beacon_codec()
        .serialize(value)
        .map_err(|e| StateError::SerializationError(e.to_string()))
}

fn beacon_decode<T: DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    beacon_codec()
        .reject_trailing_bytes()
        .deserialize(bytes)
        .map_err(|e| StateError::DeserializationError(e.to_string()))
}

/// One beacon state mutation captured for block-rollback revert.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BeaconMutation {
    /// The domain-prefixed row key.
    pub key: Vec<u8>,
    /// Pre-value (`None` = absent).
    pub old: Option<Vec<u8>>,
    /// Post-value (`None` = deleted).
    pub new: Option<Vec<u8>>,
}

/// Per-block journal of beacon state mutations for block-rollback revert.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct BeaconStateDiff {
    /// The mutations, canonical-key-sorted before persistence.
    pub records: Vec<BeaconMutation>,
}

impl BeaconStateDiff {
    /// Whether the journal is empty.
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }
    fn sort(&mut self) {
        self.records.sort_by(|a, b| a.key.cmp(&b.key));
    }
}

/// Persistence adapter for the dormant BR1 beacon state.
pub struct BeaconStore<'a> {
    db: &'a Database,
}

impl<'a> BeaconStore<'a> {
    /// Wrap a database handle.
    pub fn new(db: &'a Database) -> Self {
        Self { db }
    }

    /// Read the full persisted beacon `key -> value` row set (canonical order).
    pub fn load_state_map(&self) -> Result<BTreeMap<Vec<u8>, Vec<u8>>> {
        let mut map = BTreeMap::new();
        for (k, v) in self.db.iter(cf::BEACON_STATE)? {
            map.insert(k.to_vec(), v.to_vec());
        }
        Ok(map)
    }

    /// Deterministic, domain-separated digest over the FULL persisted beacon state.
    /// `DOMAIN ‖ for each (key, value): key_len(u32 LE) ‖ key ‖ val_len(u32 LE) ‖
    /// value` over `BTreeMap`-ordered rows. The block executor folds this into the
    /// state root **only when the beacon gate is open**; while dormant it is never
    /// folded, so dormant roots are byte-for-byte unchanged.
    pub fn state_digest(&self) -> Result<Hash> {
        let rows = self.load_state_map()?;
        let mut buf: Vec<u8> = Vec::with_capacity(BEACON_STATE_DIGEST_DOMAIN.len());
        buf.extend_from_slice(BEACON_STATE_DIGEST_DOMAIN);
        for (k, v) in &rows {
            buf.extend_from_slice(&frame_len(k.len())?);
            buf.extend_from_slice(k);
            buf.extend_from_slice(&frame_len(v.len())?);
            buf.extend_from_slice(v);
        }
        Ok(Hash::hash(&buf))
    }

    /// Whether a per-block beacon journal exists for `height`.
    pub fn has_journal(&self, height: BlockHeight) -> Result<bool> {
        Ok(self
            .db
            .contains(cf::BEACON_STATE_DIFFS, &height.to_be_bytes())?)
    }

    /// Load + canonically decode the per-height revert journal (`None` if absent —
    /// e.g. always under the dormant gate, which writes no journal).
    pub fn load_journal(&self, height: BlockHeight) -> Result<Option<BeaconStateDiff>> {
        match self.db.get(cf::BEACON_STATE_DIFFS, &height.to_be_bytes())? {
            Some(bytes) => Ok(Some(beacon_decode(&bytes)?)),
            None => Ok(None),
        }
    }

    /// Persist the transition `before -> after` for `height` **atomically** (one
    /// finalized beacon transition per block). Two hard preconditions checked BEFORE
    /// any write: a duplicate-height journal is rejected, and the claimed `before`
    /// row set must byte-for-byte equal the live persisted state (stale-predecessor
    /// rejection). All record writes/deletes + the journal write go into one
    /// [`Database::batch`] committed once. Returns the number of mutated rows.
    pub fn persist_transition(
        &self,
        before: &BTreeMap<Vec<u8>, Vec<u8>>,
        after: &BTreeMap<Vec<u8>, Vec<u8>>,
        height: BlockHeight,
    ) -> Result<usize> {
        if self.has_journal(height)? {
            return Err(StateError::InvalidOperation(format!(
                "beacon transition already finalized at height {height}; refusing to overwrite"
            )));
        }
        // Every row key must carry a recognized beacon domain prefix.
        for k in before.keys().chain(after.keys()) {
            if !is_beacon_domain(k) {
                return Err(StateError::InvalidOperation(
                    "beacon persist_transition: row key has no recognized domain prefix".into(),
                ));
            }
        }
        let live = self.load_state_map()?;
        if *before != live {
            return Err(StateError::InvalidOperation(
                "beacon persist_transition: stale `before` snapshot does not match live state"
                    .into(),
            ));
        }

        let mut keys: BTreeMap<Vec<u8>, ()> = BTreeMap::new();
        for k in before.keys().chain(after.keys()) {
            keys.insert(k.clone(), ());
        }

        let mut diff = BeaconStateDiff::default();
        let mut batch = self.db.batch();
        for key in keys.keys() {
            let new = after.get(key).cloned();
            let old = live.get(key).cloned();
            if old == new {
                continue;
            }
            match &new {
                Some(v) => batch.put(cf::BEACON_STATE, key, v)?,
                None => batch.delete(cf::BEACON_STATE, key)?,
            }
            diff.records.push(BeaconMutation {
                key: key.clone(),
                old,
                new,
            });
        }
        if diff.is_empty() {
            return Ok(0);
        }
        diff.sort();
        let journal = beacon_encode(&diff)?;
        batch.put(cf::BEACON_STATE_DIFFS, &height.to_be_bytes(), &journal)?;
        let mutated = diff.records.len();
        batch.commit()?;
        Ok(mutated)
    }

    /// Stage the reverse-replay of the per-height beacon journal (and the journal's
    /// own deletion) into a caller-provided [`WriteBatch`](sumchain_storage::db::
    /// WriteBatch), returning whether anything was staged (`false` when no journal
    /// exists — ALWAYS under the dormant gate). This composes into the SAME atomic
    /// write as the account + contract + C1 revert, so a crash can never leave a
    /// partially-reverted node. Every key's domain prefix is validated BEFORE it is
    /// staged, so a corrupt journal aborts the whole multi-family revert.
    pub fn stage_block_revert(
        &self,
        batch: &mut sumchain_storage::db::WriteBatch<'_>,
        height: BlockHeight,
    ) -> Result<bool> {
        let hkey = height.to_be_bytes();
        let Some(bytes) = self.db.get(cf::BEACON_STATE_DIFFS, &hkey)? else {
            return Ok(false);
        };
        let diff: BeaconStateDiff = beacon_decode(&bytes)?;
        for record in diff.records.iter().rev() {
            if !is_beacon_domain(&record.key) {
                return Err(StateError::InvalidOperation(format!(
                    "beacon revert: unrecognized key domain at height {height}"
                )));
            }
            match &record.old {
                Some(v) => batch.put(cf::BEACON_STATE, &record.key, v)?,
                None => batch.delete(cf::BEACON_STATE, &record.key)?,
            }
        }
        batch.delete(cf::BEACON_STATE_DIFFS, &hkey)?;
        Ok(true)
    }

    /// Atomically revert the beacon mutations recorded for `height` in isolation
    /// (its own [`Database::batch`]). Thin wrapper over [`stage_block_revert`](Self::
    /// stage_block_revert); retained for the standalone store tests. The LIVE reorg
    /// path drives `stage_block_revert` into the unified batch instead.
    pub fn revert_block(&self, height: BlockHeight) -> Result<()> {
        let mut batch = self.db.batch();
        if self.stage_block_revert(&mut batch, height)? {
            batch.commit()?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sumchain_storage::Database;
    use tempfile::TempDir;

    fn open_db() -> (Database, TempDir) {
        let dir = TempDir::new().unwrap();
        (Database::open_default(dir.path()).unwrap(), dir)
    }

    fn row(prefix: u8, k: &[u8], v: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let mut key = vec![prefix];
        key.extend_from_slice(k);
        (key, v.to_vec())
    }

    #[test]
    fn beacon_state_digest_domain_is_frozen() {
        assert_eq!(BEACON_STATE_DIGEST_DOMAIN, b"sumchain.beacon.state.v1");
        assert!(BEACON_STATE_DIGEST_DOMAIN.ends_with(b".v1"));
    }

    #[test]
    fn empty_digest_is_domain_only() {
        let (db, _d) = open_db();
        assert_eq!(
            BeaconStore::new(&db).state_digest().unwrap(),
            Hash::hash(BEACON_STATE_DIGEST_DOMAIN),
            "empty beacon state hashes to the domain-only digest"
        );
    }

    #[test]
    fn digest_is_insertion_order_independent_and_length_framed() {
        let a = row(domain::KEY, b"aa", b"1");
        let b = row(domain::DEAL, b"bb", b"22");
        let (db1, _dir1) = open_db();
        db1.put(cf::BEACON_STATE, &a.0, &a.1).unwrap();
        db1.put(cf::BEACON_STATE, &b.0, &b.1).unwrap();
        let d1 = BeaconStore::new(&db1).state_digest().unwrap();
        let (db2, _dir2) = open_db();
        db2.put(cf::BEACON_STATE, &b.0, &b.1).unwrap();
        db2.put(cf::BEACON_STATE, &a.0, &a.1).unwrap();
        let d2 = BeaconStore::new(&db2).state_digest().unwrap();
        assert_eq!(d1, d2, "digest is insertion-order independent");

        // Length framing disambiguates equal concatenations.
        let (db3, _dir3) = open_db();
        db3.put(cf::BEACON_STATE, &[domain::KEY, b'a', b'b'], b"c")
            .unwrap();
        let (db4, _dir4) = open_db();
        db4.put(cf::BEACON_STATE, &[domain::KEY, b'a'], b"bc")
            .unwrap();
        assert_ne!(
            BeaconStore::new(&db3).state_digest().unwrap(),
            BeaconStore::new(&db4).state_digest().unwrap()
        );
    }

    #[test]
    fn persist_revert_reapply_roundtrip() {
        let (db, _d) = open_db();
        let store = BeaconStore::new(&db);
        let (k1, v1) = row(domain::KEY, b"v0", b"ek0");
        let (k2, v2) = row(domain::ROUND, b"r0", b"sig0");

        let mut after = BTreeMap::new();
        after.insert(k1.clone(), v1.clone());
        after.insert(k2.clone(), v2.clone());
        let before = BTreeMap::new();

        let n = store.persist_transition(&before, &after, 1).unwrap();
        assert_eq!(n, 2);
        assert_eq!(store.load_state_map().unwrap(), after);
        let committed = store.state_digest().unwrap();

        // Revert restores the empty predecessor.
        store.revert_block(1).unwrap();
        assert!(store.load_state_map().unwrap().is_empty());
        assert_eq!(
            store.state_digest().unwrap(),
            Hash::hash(BEACON_STATE_DIGEST_DOMAIN)
        );
        assert!(!store.has_journal(1).unwrap());

        // Reapply reproduces the identical committed state.
        store.persist_transition(&before, &after, 1).unwrap();
        assert_eq!(store.state_digest().unwrap(), committed);
    }

    #[test]
    fn duplicate_height_and_stale_predecessor_rejected() {
        let (db, _d) = open_db();
        let store = BeaconStore::new(&db);
        let (k1, v1) = row(domain::KEY, b"v0", b"ek0");
        let mut after = BTreeMap::new();
        after.insert(k1, v1);
        let before = BTreeMap::new();
        store.persist_transition(&before, &after, 1).unwrap();

        // Duplicate height rejected.
        assert!(store.persist_transition(&before, &after, 1).is_err());
        // Stale predecessor (claims empty but live is non-empty) rejected at height 2.
        let after2 = after.clone();
        assert!(store
            .persist_transition(&BTreeMap::new(), &after2, 2)
            .is_err());
    }

    #[test]
    fn non_beacon_domain_row_rejected() {
        let (db, _d) = open_db();
        let store = BeaconStore::new(&db);
        let mut after = BTreeMap::new();
        after.insert(vec![0xFF, 0x00], b"x".to_vec()); // 0xFF is not a beacon domain
        assert!(store
            .persist_transition(&BTreeMap::new(), &after, 1)
            .is_err());
    }
}
