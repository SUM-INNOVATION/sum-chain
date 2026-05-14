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

use sumchain_primitives::inference_attestation::InferenceAttestationRecord;
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
    pub fn put(
        &self,
        key: &[u8; 32],
        record: &InferenceAttestationRecord,
    ) -> Result<()> {
        let value = bincode::serialize(record)
            .map_err(|e| StateError::SerializationError(e.to_string()))?;
        self.db.put(cf::INFERENCE_ATTESTATIONS, key, &value)?;
        Ok(())
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
        executor.put(&key, &sample_record()).unwrap();
        assert!(executor.exists(&key).unwrap());
    }

    #[test]
    fn put_then_get_preserves_record_bytes() {
        let (db, _dir) = setup();
        let executor = InferenceAttestationExecutor::new(db);
        let key = [22u8; 32];
        let record = sample_record();
        executor.put(&key, &record).unwrap();
        let loaded = executor.get(&key).unwrap().expect("present");
        assert_eq!(loaded, record);
    }

    #[test]
    fn distinct_keys_do_not_collide() {
        let (db, _dir) = setup();
        let executor = InferenceAttestationExecutor::new(db);
        let k1 = [1u8; 32];
        let k2 = [2u8; 32];
        executor.put(&k1, &sample_record()).unwrap();
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
        executor.put(&key, &sample_record()).unwrap();

        let mut second = sample_record();
        second.included_at_height = 99;
        executor.put(&key, &second).unwrap();
        let loaded = executor.get(&key).unwrap().expect("present");
        assert_eq!(loaded.included_at_height, 99);
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

