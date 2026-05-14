//! Executor for the OmniNode `InferenceAttestation` subprotocol (Phase 2).
//!
//! Persists verifier-signed attestations to the `INFERENCE_ATTESTATIONS`
//! column family and provides the duplicate-lookup primitive the outer
//! dispatch in `executor.rs` uses to enforce one attestation per
//! `(session_id, verifier_address)` pair.
//!
//! This module does NOT decide whether to accept or reject a tx; that's
//! the dispatch's job. It only owns the storage interaction:
//!
//! - [`InferenceAttestationExecutor::exists`] — point-lookup against the
//!   CF, used by the dispatch's dedup check and (in Phase 3) by the
//!   mempool admission hook.
//! - [`InferenceAttestationExecutor::put`] — bincode-serialize the
//!   `InferenceAttestationRecord` and write to the CF under the stable
//!   32-byte key.
//!
//! Fee accounting (`state.deduct`, `state.credit`, `state.increment_nonce`)
//! lives in the dispatcher, not here — matches the pattern other fee-only
//! executors (Agreement, Contract) use.

use std::sync::Arc;

use sumchain_primitives::inference_attestation::{
    session_index_key, session_index_prefix, InferenceAttestationRecord, SESSION_ID_HASH_BYTES,
};
use sumchain_primitives::Address;
use sumchain_storage::{cf, Database};

use crate::{Result, StateError};

/// Storage executor for `InferenceAttestation` rows.
///
/// Wraps the chain's `Database` handle and the
/// `cf::INFERENCE_ATTESTATIONS` column family. Read-only operations are
/// cheap RocksDB point lookups; writes are unconditional `put`s (the
/// dispatcher enforces dedup via [`exists`] before calling [`put`]).
pub struct InferenceAttestationExecutor {
    db: Arc<Database>,
}

impl InferenceAttestationExecutor {
    pub fn new(db: Arc<Database>) -> Self {
        Self { db }
    }

    /// `true` if a record exists at `key` in the
    /// `INFERENCE_ATTESTATIONS` CF.
    ///
    /// Called by the executor dispatch before persisting a new
    /// attestation; the dispatch returns `TxStatus::Failed(51)
    /// DuplicateAttestation` and `fee_paid: 0` when this returns `true`.
    /// In Phase 3 the mempool admission hook calls this same method
    /// against the canonical CF so duplicates are rejected at admission
    /// without ever burning fees on the executor path.
    pub fn exists(&self, key: &[u8; 32]) -> Result<bool> {
        // `?` converts StorageError into StateError::Storage via `#[from]`.
        let maybe = self.db.get(cf::INFERENCE_ATTESTATIONS, key)?;
        Ok(maybe.is_some())
    }

    /// Persist an attestation record. The caller MUST have already
    /// checked [`exists`] and applied fee mutations — `put` does not
    /// dedup, deduct, or charge.
    ///
    /// Fails the tx (propagated to dispatch as a hard error) if the
    /// bincode-serialized record cannot be written.
    /// Persist an attestation record AND its session-id index entry.
    /// The verifier address is taken as an explicit argument (rather
    /// than recovered from `record`, which doesn't carry it) so the
    /// caller — the dispatcher, which knows `tx.sender == verifier` —
    /// passes it directly. This is the only successful-path entry
    /// point; the canonical CF and the session index always move
    /// together.
    /// Persist an attestation record AND its session-id index entry
    /// **atomically** via a single RocksDB write batch. If the batch
    /// commit fails, neither CF is mutated. This is load-bearing for
    /// `sum_listInferenceAttestations` correctness — a partial write
    /// (canonical CF updated, index missing) would make a finalized
    /// attestation invisible to the listing RPC while still findable
    /// via point lookup, which is the kind of silent inconsistency
    /// that's painful to debug.
    pub fn put(
        &self,
        key: &[u8; 32],
        record: &InferenceAttestationRecord,
        verifier_address: &Address,
    ) -> Result<()> {
        let value = bincode::serialize(record)
            .map_err(|e| StateError::SerializationError(e.to_string()))?;
        let index_key = session_index_key(&record.digest.session_id, verifier_address);

        let mut batch = self.db.batch();
        batch.put(cf::INFERENCE_ATTESTATIONS, key, &value)?;
        // Session-id index — empty value, presence is the signal.
        batch.put(cf::INFERENCE_ATTESTATIONS_BY_SESSION, &index_key, &[])?;
        batch.commit()?;
        Ok(())
    }

    /// Enumerate verifier addresses that have attested to `session_id`.
    /// Returns an empty vec for a session with zero attestations.
    /// Backs `sum_listInferenceAttestations`.
    pub fn list_verifiers_by_session(&self, session_id: &str) -> Result<Vec<Address>> {
        let prefix = session_index_prefix(session_id);
        let mut out = Vec::new();
        // prefix_iter may return NotFound on a pre-V2 / pre-Phase-4 DB
        // missing the CF entirely; treat that as zero rows so the RPC
        // returns an empty list rather than failing.
        match self
            .db
            .prefix_iter(cf::INFERENCE_ATTESTATIONS_BY_SESSION, &prefix)
        {
            Ok(it) => {
                for (key, _value) in it {
                    if key.len() != 36 || &key[..SESSION_ID_HASH_BYTES] != prefix.as_slice() {
                        continue;
                    }
                    let mut addr = [0u8; 20];
                    addr.copy_from_slice(&key[SESSION_ID_HASH_BYTES..]);
                    out.push(Address::new(addr));
                }
            }
            Err(sumchain_storage::StorageError::NotFound(_)) => {}
            Err(e) => return Err(e.into()),
        }
        Ok(out)
    }

    /// Fetch a previously persisted record. Phase 4 RPC reads call this;
    /// the Phase 2 dispatcher only uses [`exists`], not this method.
    /// Included here for API completeness — the same module owns all
    /// reads + writes on this CF.
    pub fn get(
        &self,
        key: &[u8; 32],
    ) -> Result<Option<InferenceAttestationRecord>> {
        match self.db.get(cf::INFERENCE_ATTESTATIONS, key)? {
            None => Ok(None),
            Some(bytes) => {
                let record = bincode::deserialize::<InferenceAttestationRecord>(&bytes)
                    .map_err(|e| StateError::SerializationError(e.to_string()))?;
                Ok(Some(record))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sumchain_primitives::inference_attestation::InferenceAttestationDigest;
    use sumchain_primitives::Hash;
    use tempfile::TempDir;

    fn setup() -> (Arc<Database>, TempDir) {
        let dir = TempDir::new().unwrap();
        let db = Arc::new(Database::open_default(dir.path()).unwrap());
        (db, dir)
    }

    fn sample_record() -> InferenceAttestationRecord {
        InferenceAttestationRecord {
            digest: InferenceAttestationDigest {
                session_id: "sample-session".to_string(),
                model_hash: [1u8; 32],
                manifest_root: [2u8; 32],
                response_hash: [3u8; 32],
                proof_root: [4u8; 32],
            },
            verifier_signature: [9u8; 64],
            included_at_height: 42,
            tx_hash: Hash::new([7u8; 32]),
        }
    }

    #[test]
    fn exists_returns_false_for_missing_key() {
        let (db, _dir) = setup();
        let executor = InferenceAttestationExecutor::new(db);
        let key = [0u8; 32];
        assert_eq!(executor.exists(&key).unwrap(), false);
    }

    #[test]
    fn put_then_exists_round_trip() {
        let (db, _dir) = setup();
        let executor = InferenceAttestationExecutor::new(db);
        let key = [11u8; 32];
        executor.put(&key, &sample_record(), &Address::new([42u8; 20])).unwrap();
        assert!(executor.exists(&key).unwrap());
    }

    #[test]
    fn put_then_get_preserves_record_bytes() {
        let (db, _dir) = setup();
        let executor = InferenceAttestationExecutor::new(db);
        let key = [22u8; 32];
        let record = sample_record();
        executor.put(&key, &record, &Address::new([42u8; 20])).unwrap();
        let loaded = executor.get(&key).unwrap().expect("present");
        assert_eq!(loaded, record);
    }

    #[test]
    fn distinct_keys_do_not_collide() {
        let (db, _dir) = setup();
        let executor = InferenceAttestationExecutor::new(db);
        let k1 = [1u8; 32];
        let k2 = [2u8; 32];
        executor.put(&k1, &sample_record(), &Address::new([42u8; 20])).unwrap();
        assert!(executor.exists(&k1).unwrap());
        assert!(!executor.exists(&k2).unwrap());
    }

    #[test]
    fn put_overwrites_silently_at_storage_layer() {
        // The dispatcher enforces dedup via `exists` BEFORE calling `put`,
        // so duplicate puts cannot happen on the success path. This test
        // documents the storage-layer behavior: a bare `put` against an
        // existing key overwrites without complaint. Don't change this
        // without auditing every dispatch caller for a pre-`exists` check.
        let (db, _dir) = setup();
        let executor = InferenceAttestationExecutor::new(db);
        let key = [33u8; 32];
        executor.put(&key, &sample_record(), &Address::new([42u8; 20])).unwrap();

        let mut second = sample_record();
        second.included_at_height = 99;
        executor.put(&key, &second, &Address::new([42u8; 20])).unwrap();
        let loaded = executor.get(&key).unwrap().expect("present");
        assert_eq!(loaded.included_at_height, 99);
    }

    #[test]
    fn list_verifiers_returns_empty_for_unknown_session() {
        let (db, _dir) = setup();
        let executor = InferenceAttestationExecutor::new(db);
        let v = executor.list_verifiers_by_session("never-attested").unwrap();
        assert!(v.is_empty());
    }

    #[test]
    fn list_verifiers_returns_all_attesters_for_session() {
        let (db, _dir) = setup();
        let executor = InferenceAttestationExecutor::new(db);
        let session_id = "multi-verifier-session";

        let v1 = Address::new([0x11u8; 20]);
        let v2 = Address::new([0x22u8; 20]);
        let v3 = Address::new([0x33u8; 20]);

        let mk = |verifier: &Address, key: u8| {
            (
                {
                    let mut k = [0u8; 32];
                    k[0] = key;
                    k
                },
                InferenceAttestationRecord {
                    digest: InferenceAttestationDigest {
                        session_id: session_id.to_string(),
                        model_hash: [1u8; 32],
                        manifest_root: [2u8; 32],
                        response_hash: [3u8; 32],
                        proof_root: [4u8; 32],
                    },
                    verifier_signature: [9u8; 64],
                    included_at_height: 1,
                    tx_hash: Hash::new([7u8; 32]),
                },
                *verifier,
            )
        };

        let (k1, r1, a1) = mk(&v1, 1);
        let (k2, r2, a2) = mk(&v2, 2);
        let (k3, r3, a3) = mk(&v3, 3);
        executor.put(&k1, &r1, &a1).unwrap();
        executor.put(&k2, &r2, &a2).unwrap();
        executor.put(&k3, &r3, &a3).unwrap();

        let mut returned = executor.list_verifiers_by_session(session_id).unwrap();
        returned.sort();
        let mut expected = vec![v1, v2, v3];
        expected.sort();
        assert_eq!(returned, expected);
    }

    #[test]
    fn put_is_atomic_canonical_and_index_together() {
        // The dispatcher and the RPC list path read from two different
        // CFs that `put` must keep in sync. This test exercises the
        // invariant: after every successful `put`, BOTH `exists` (on
        // the canonical CF) AND `list_verifiers_by_session` (on the
        // index CF) reflect the row. Doesn't directly prove batch
        // atomicity at the rocksdb level (kernel crash mid-batch is
        // hard to simulate), but it does prove the two writes are
        // intended to land together — a future regression that drops
        // one of them would fail this test.
        let (db, _dir) = setup();
        let executor = InferenceAttestationExecutor::new(db);
        let key = [77u8; 32];
        let verifier = Address::new([0xabu8; 20]);
        let record = sample_record();
        executor.put(&key, &record, &verifier).unwrap();

        // Canonical CF: point lookup hits.
        assert!(executor.exists(&key).unwrap());
        assert_eq!(executor.get(&key).unwrap().unwrap(), record);

        // Index CF: list returns the verifier.
        let v = executor
            .list_verifiers_by_session(&record.digest.session_id)
            .unwrap();
        assert_eq!(v, vec![verifier]);
    }

    #[test]
    fn list_verifiers_isolates_sessions() {
        // An attester on session A must not appear when listing session B.
        // Proves the BLAKE3 prefix actually separates sessions; a hash
        // collision on the first 16 bytes is statistically impossible but
        // a buggy keying scheme could leak across sessions.
        let (db, _dir) = setup();
        let executor = InferenceAttestationExecutor::new(db);

        let verifier = Address::new([0x55u8; 20]);
        let mk = |session: &str, key: u8| {
            let mut k = [0u8; 32];
            k[0] = key;
            (
                k,
                InferenceAttestationRecord {
                    digest: InferenceAttestationDigest {
                        session_id: session.to_string(),
                        model_hash: [1u8; 32],
                        manifest_root: [2u8; 32],
                        response_hash: [3u8; 32],
                        proof_root: [4u8; 32],
                    },
                    verifier_signature: [9u8; 64],
                    included_at_height: 1,
                    tx_hash: Hash::new([7u8; 32]),
                },
            )
        };

        let (ka, ra) = mk("session-A", 10);
        let (kb, rb) = mk("session-B", 11);
        executor.put(&ka, &ra, &verifier).unwrap();
        executor.put(&kb, &rb, &verifier).unwrap();

        let a_verifiers = executor.list_verifiers_by_session("session-A").unwrap();
        let b_verifiers = executor.list_verifiers_by_session("session-B").unwrap();
        let c_verifiers = executor.list_verifiers_by_session("session-C").unwrap();

        assert_eq!(a_verifiers, vec![verifier]);
        assert_eq!(b_verifiers, vec![verifier]);
        assert!(c_verifiers.is_empty());
    }

    #[test]
    fn omninode_gate_helper_default_disabled() {
        use sumchain_genesis::ChainParams;
        let params = ChainParams::default();
        assert_eq!(params.omninode_enabled_from_height, None);
        // The gate helper itself is private to crate::executor; this test
        // confirms the chain-param default that drives it. Full
        // dispatch-level gate tests live alongside the dispatcher in
        // executor.rs integration tests.
    }

    #[test]
    fn omninode_gate_param_explicit_activation() {
        use sumchain_genesis::ChainParams;
        let mut params = ChainParams::default();
        params.omninode_enabled_from_height = Some(1000);
        // At height 999 the gate is closed; at 1000+ it is open. The
        // closure logic is verified by integration tests that call
        // execute_tx end-to-end; here we just confirm the field round-
        // trips on a constructed ChainParams.
        assert_eq!(params.omninode_enabled_from_height, Some(1000));
    }
}

