//! Transaction mempool for SUM Chain.
//!
//! Stores pending transactions, sorted by fee for block inclusion.
//!
//! ## OmniNode `InferenceAttestation` admission
//!
//! When wired with [`InferenceAttestationAdmission`] (see
//! [`Mempool::with_inference_admission`]), the mempool enforces three
//! checks for any `TxPayload::InferenceAttestation` before insertion:
//!
//! 1. Activation gate: reject if the OmniNode subprotocol isn't enabled
//!    at the current block height.
//! 2. In-flight duplicate: reject if a tx with the same
//!    `(session_id, verifier_address)` pair is already in this mempool.
//! 3. Permanent duplicate: reject if the canonical
//!    `INFERENCE_ATTESTATIONS` CF already contains a finalized
//!    attestation for that pair.
//!
//! This is the load-bearing protection against zero-fee duplicate
//! griefing — the executor returns `Failed(51), fee_paid: 0` on
//! duplicate and does not advance nonce, so the only thing that
//! prevents replay-spam is rejection at admission. The Mempool is
//! intentionally subprotocol-agnostic by default
//! (`InferenceAttestationAdmission` is `Option`-al); production
//! deployments opt in via the builder.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use parking_lot::RwLock;
use sumchain_genesis::ChainParams;
use sumchain_primitives::inference_attestation::inference_attestation_key;
use sumchain_primitives::{
    Address, Balance, Hash, Nonce, SignedTransaction, TxInner, TxPayload,
};
use tracing::{debug, info};

use crate::education_executor::{
    education_in_flight_key, parse_education, EducationExecutor, EduParsed,
};
use crate::inference_attestation_executor::InferenceAttestationExecutor;
use crate::{Result, StateError, StateManager};

/// Mempool configuration
#[derive(Debug, Clone)]
pub struct MempoolConfig {
    /// Maximum number of transactions
    pub max_size: usize,
    /// Maximum transactions per sender
    pub max_per_sender: usize,
    /// Minimum fee for acceptance
    pub min_fee: Balance,
    /// Transaction expiration time in seconds (0 = no expiration)
    pub tx_expiration_secs: u64,
}

impl Default for MempoolConfig {
    fn default() -> Self {
        Self {
            max_size: 10000,
            max_per_sender: 100,
            min_fee: 1,
            tx_expiration_secs: 3600, // 1 hour default
        }
    }
}

/// Transaction entry in mempool
#[derive(Debug, Clone)]
struct TxEntry {
    tx: SignedTransaction,
    fee: Balance,
    #[allow(dead_code)]
    received_at: u64, // Timestamp - reserved for future eviction policy
}

/// Narrow context required for OmniNode `InferenceAttestation` admission.
///
/// Carries only what the admission hook needs: the storage executor that
/// owns the permanent CF, the chain params (for
/// `omninode_enabled_from_height`), and a reference to the current block
/// height. Production nodes construct this once at startup and pass it
/// to [`Mempool::with_inference_admission`]. Tests can construct it
/// directly with handle-grade dependencies (a `TempDir`-backed Database
/// and an `AtomicU64` for height).
///
/// The mempool stores this `Option`-ally so other tx variants admit
/// without any subprotocol coupling.
#[derive(Clone)]
pub struct InferenceAttestationAdmission {
    pub executor: Arc<InferenceAttestationExecutor>,
    pub params: Arc<ChainParams>,
    pub current_height: Arc<AtomicU64>,
}

/// SRC-817/818 Education suite admission context. Same shape and
/// lifecycle as [`InferenceAttestationAdmission`]: owns a read-only
/// `EducationExecutor` (Phase 2 CFs), the chain params (for
/// `education_enabled_from_height`), and the shared live chain-height
/// `Arc<AtomicU64>`. Stored `Option`-ally so non-education txs and
/// no-context paths (tests / consensus internal re-adds) are
/// unaffected. Admission is a narrow filter only — the Phase 2
/// executor remains authoritative (no fee/nonce/dispatch here).
#[derive(Clone)]
pub struct EducationAdmission {
    pub executor: Arc<EducationExecutor>,
    pub params: Arc<ChainParams>,
    pub current_height: Arc<AtomicU64>,
}

/// Transaction mempool
pub struct Mempool {
    /// All transactions by hash
    txs: RwLock<HashMap<Hash, TxEntry>>,
    /// Transactions by sender address
    by_sender: RwLock<HashMap<Address, HashSet<Hash>>>,
    /// Transactions sorted by fee (descending) for selection
    by_fee: RwLock<BTreeMap<(Balance, Hash), Hash>>,
    /// Configuration
    config: MempoolConfig,
    /// In-flight (session_id, verifier_address) keys mapped to tx hash.
    /// Same 32-byte BLAKE3-domain-separated key shape used by the
    /// `INFERENCE_ATTESTATIONS` CF; lets us point-lookup duplicates at
    /// admission and unlink the entry when the tx is removed.
    inference_in_flight: RwLock<HashMap<[u8; 32], Hash>>,
    /// Optional admission context. `None` in tests and in any code path
    /// that adds txs to the mempool without going through user submission
    /// (e.g. consensus re-adding txs from rejected blocks). Production
    /// node-startup wires this via [`Mempool::with_inference_admission`].
    inference_admission: Option<InferenceAttestationAdmission>,
    /// In-flight education dedup keys → tx hash. Same 32-byte
    /// length-safe key the admission path derives via
    /// [`education_in_flight_key`]; re-derived on `remove`/`clear` so
    /// cleanup can't desync from admission.
    education_in_flight: RwLock<HashMap<[u8; 32], Hash>>,
    /// Optional education admission context (parallels
    /// `inference_admission`).
    education_admission: Option<EducationAdmission>,
}

impl Mempool {
    /// Create a new mempool
    pub fn new(config: MempoolConfig) -> Self {
        Self {
            txs: RwLock::new(HashMap::new()),
            by_sender: RwLock::new(HashMap::new()),
            by_fee: RwLock::new(BTreeMap::new()),
            config,
            inference_in_flight: RwLock::new(HashMap::new()),
            inference_admission: None,
            education_in_flight: RwLock::new(HashMap::new()),
            education_admission: None,
        }
    }

    /// Builder: attach the OmniNode `InferenceAttestation` admission
    /// context. Without it, `InferenceAttestation` txs are still
    /// admitted by in-flight dedup but the activation gate and permanent
    /// CF dedup are skipped (which is what you want for tests and for
    /// consensus internal re-adds, but NEVER for production user
    /// submission).
    pub fn with_inference_admission(
        mut self,
        admission: InferenceAttestationAdmission,
    ) -> Self {
        self.inference_admission = Some(admission);
        self
    }

    /// Builder: attach the SRC-817/818 Education admission context.
    /// Without it, education txs are still in-flight-deduped but the
    /// activation gate and committed-CF/structural prechecks are
    /// skipped (tests / consensus internal re-adds), never for
    /// production user submission.
    pub fn with_education_admission(mut self, admission: EducationAdmission) -> Self {
        self.education_admission = Some(admission);
        self
    }

    /// Add a transaction to the mempool
    pub fn add(&self, tx: SignedTransaction) -> Result<Hash> {
        let hash = tx.hash();
        let sender = tx.sender();
        let fee = tx.fee();

        // Check if already exists
        if self.txs.read().contains_key(&hash) {
            return Err(StateError::TxAlreadyExists);
        }

        // OmniNode `InferenceAttestation` subprotocol-specific admission.
        // For any other payload variant this is a no-op. The returned
        // key (if any) is stamped into `inference_in_flight` AFTER all
        // other admission checks pass — see end of this method.
        let inference_key = self.check_inference_admission(&tx)?;
        // SRC-817/818 Education admission. No-op for any other payload
        // variant. Returned key (if any) is stamped into
        // `education_in_flight` AFTER all other admission checks pass.
        let education_key = self.check_education_admission(&tx)?;

        // Check mempool size
        if self.txs.read().len() >= self.config.max_size {
            // Try to evict lowest fee tx
            if !self.try_evict_lowest_fee(fee) {
                return Err(StateError::MempoolFull);
            }
        }

        // Check per-sender limit
        {
            let by_sender = self.by_sender.read();
            if let Some(sender_txs) = by_sender.get(&sender) {
                if sender_txs.len() >= self.config.max_per_sender {
                    return Err(StateError::MempoolFull);
                }
            }
        }

        // Check minimum fee
        if fee < self.config.min_fee {
            return Err(StateError::FeeTooLow {
                minimum: self.config.min_fee,
                got: fee,
            });
        }

        // Add to all indexes
        let entry = TxEntry {
            tx,
            fee,
            received_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis() as u64,
        };

        self.txs.write().insert(hash, entry);
        self.by_sender
            .write()
            .entry(sender)
            .or_insert_with(HashSet::new)
            .insert(hash);

        // Use negative fee for descending order in BTreeMap
        let fee_key = (Balance::MAX - fee, hash);
        self.by_fee.write().insert(fee_key, hash);

        // Stamp the in-flight key only after every other admission check
        // and index insertion has succeeded, so a partial admission path
        // can never leave a dangling in-flight entry behind.
        if let Some(key) = inference_key {
            self.inference_in_flight.write().insert(key, hash);
        }
        if let Some(key) = education_key {
            self.education_in_flight.write().insert(key, hash);
        }

        debug!("Added tx {} to mempool (fee: {})", hash, fee);

        Ok(hash)
    }

    /// Run the three OmniNode `InferenceAttestation` admission checks.
    /// Returns `Ok(None)` for any non-InferenceAttestation payload (skip).
    /// Returns `Ok(Some(key))` if all checks pass and the caller should
    /// register `key` in `inference_in_flight` after final insertion.
    fn check_inference_admission(&self, tx: &SignedTransaction) -> Result<Option<[u8; 32]>> {
        let TxInner::V2(v2_tx) = &tx.inner else {
            return Ok(None);
        };
        let TxPayload::InferenceAttestation(att) = &v2_tx.payload else {
            return Ok(None);
        };

        // (1) Activation gate. Only enforced when an admission context
        // is wired; tests and consensus-internal re-adds construct the
        // mempool without one and skip.
        if let Some(ctx) = &self.inference_admission {
            let height = ctx.current_height.load(Ordering::Relaxed);
            let gate_open = matches!(
                ctx.params.omninode_enabled_from_height,
                Some(h) if height >= h
            );
            if !gate_open {
                return Err(StateError::OmniNodeNotActivated);
            }
        }

        // Same 32-byte BLAKE3-domain-separated key the CF uses, so the
        // in-flight set and the permanent CF are queried under
        // bit-identical keys — no encoding skew possible.
        let key = inference_attestation_key(&att.digest.session_id, &v2_tx.from);

        // (2) In-flight duplicate. Cheap point lookup in our own state.
        if self.inference_in_flight.read().contains_key(&key) {
            return Err(StateError::DuplicateInferenceAttestation);
        }

        // (3) Permanent CF dedup. Only enforced when an admission
        // context is wired (the executor handle lives there).
        if let Some(ctx) = &self.inference_admission {
            if ctx.executor.exists(&key)? {
                return Err(StateError::DuplicateInferenceAttestation);
            }
        }

        Ok(Some(key))
    }

    /// SRC-817/818 Education admission. `Ok(None)` for any
    /// non-education payload (skip — zero behavior change for other
    /// variants). `Ok(Some(key))` if all checks pass and the caller
    /// should register `key` in `education_in_flight` after final
    /// insertion. Admission produces NO receipts and NO state mutation;
    /// the Phase 2 executor remains authoritative. No submission
    /// time-window check here (admission has no canonical block
    /// timestamp — executor + Policy B handle the window).
    fn check_education_admission(
        &self,
        tx: &SignedTransaction,
    ) -> Result<Option<[u8; 32]>> {
        let TxInner::V2(v2_tx) = &tx.inner else {
            return Ok(None);
        };
        let TxPayload::Education(edu) = &v2_tx.payload else {
            return Ok(None);
        };

        // (1) Activation gate (only when an admission ctx is wired).
        if let Some(ctx) = &self.education_admission {
            let height = ctx.current_height.load(Ordering::Relaxed);
            let gate_open = matches!(
                ctx.params.education_enabled_from_height,
                Some(h) if height >= h
            );
            if !gate_open {
                return Err(StateError::EducationNotActivated);
            }
        }

        // (2) Decode/route (size + supported standard/op + bincode).
        let parsed = parse_education(edu).map_err(|code| {
            StateError::InvalidEducationTransaction(format!(
                "undecodable or unsupported education op (code {code})"
            ))
        })?;

        // (3) Derive the length-safe in-flight dedup key.
        let key = education_in_flight_key(&parsed);

        // (4) In-flight duplicate (cheap point lookup in our state).
        if self.education_in_flight.read().contains_key(&key) {
            return Err(StateError::DuplicateEducationRecord);
        }

        // (5) Committed-CF + structural cheap prechecks (only when ctx
        // wired; the executor read handle lives there). No window check.
        if let Some(ctx) = &self.education_admission {
            let ex = &ctx.executor;
            match &parsed {
                EduParsed::CreateCatalog(d) => {
                    if ex.catalog_exists(&d.catalog_id)? {
                        return Err(StateError::DuplicateEducationRecord);
                    }
                }
                EduParsed::CreateOffering(d) => {
                    if ex.offering_exists(&d.offering_id)? {
                        return Err(StateError::DuplicateEducationRecord);
                    }
                    match ex.get_catalog(&d.catalog_id)? {
                        None => {
                            return Err(StateError::InvalidEducationTransaction(
                                "CreateOffering: catalog not found".into(),
                            ))
                        }
                        Some(c) if c.status != 1 /* Active */ => {
                            return Err(StateError::InvalidEducationTransaction(
                                "CreateOffering: catalog not Active".into(),
                            ))
                        }
                        Some(_) => {}
                    }
                }
                EduParsed::PublishContent(d) => {
                    if !ex.offering_exists(&d.offering_id)? {
                        return Err(StateError::InvalidEducationTransaction(
                            "PublishContent: offering not found".into(),
                        ));
                    }
                    if ex.content_exists(&d.offering_id, &d.content_id)? {
                        return Err(StateError::DuplicateEducationRecord);
                    }
                }
                EduParsed::AddAssessment(d) => {
                    if !ex.offering_exists(&d.offering_id)? {
                        return Err(StateError::InvalidEducationTransaction(
                            "AddAssessment: offering not found".into(),
                        ));
                    }
                    if ex.assessment_exists(&d.offering_id, &d.assessment_id)? {
                        return Err(StateError::DuplicateEducationRecord);
                    }
                }
                EduParsed::LinkEnrollment(d) => {
                    match ex.get_offering(&d.offering_id)? {
                        None => {
                            return Err(StateError::InvalidEducationTransaction(
                                "LinkEnrollment: offering not found".into(),
                            ))
                        }
                        Some(o) if o.status != 1 /* Active */ => {
                            return Err(StateError::InvalidEducationTransaction(
                                "LinkEnrollment: offering not Active".into(),
                            ))
                        }
                        Some(_) => {}
                    }
                    if ex
                        .enrollment_link_exists(&d.offering_id, &d.student_commitment)?
                    {
                        return Err(StateError::DuplicateEducationRecord);
                    }
                }
                EduParsed::Submit(d, is_exam) => {
                    let off = match ex.get_offering(&d.offering_id)? {
                        None => {
                            return Err(StateError::InvalidEducationTransaction(
                                "Submit: offering not found".into(),
                            ))
                        }
                        Some(o) => o,
                    };
                    // Active (1) or EnrollmentClosed (2).
                    if off.status != 1 && off.status != 2 {
                        return Err(StateError::InvalidEducationTransaction(
                            "Submit: offering not accepting submissions".into(),
                        ));
                    }
                    let a = match ex
                        .get_assessment(&d.offering_id, &d.assessment_id)?
                    {
                        None => {
                            return Err(StateError::InvalidEducationTransaction(
                                "Submit: assessment not found".into(),
                            ))
                        }
                        Some(a) => a,
                    };
                    let want_kind: u8 = if *is_exam { 1 } else { 0 };
                    if a.kind != want_kind {
                        return Err(StateError::InvalidEducationTransaction(
                            "Submit: assessment kind mismatch".into(),
                        ));
                    }
                    if !ex.enrollment_link_exists(
                        &d.offering_id,
                        &d.student_commitment,
                    )? {
                        return Err(StateError::InvalidEducationTransaction(
                            "Submit: student_commitment not enrolled".into(),
                        ));
                    }
                    if a.max_attempts != 0
                        && ex.committed_attempts(
                            &d.offering_id,
                            &d.assessment_id,
                            &d.student_commitment,
                        )? >= a.max_attempts
                    {
                        return Err(StateError::InvalidEducationTransaction(
                            "Submit: attempts exhausted".into(),
                        ));
                    }
                    if ex.submission_exists(
                        &d.offering_id,
                        &d.assessment_id,
                        &d.student_commitment,
                        d.attempt,
                    )? {
                        return Err(StateError::DuplicateEducationRecord);
                    }
                }
                EduParsed::Grade(d) => {
                    if !ex.offering_exists(&d.offering_id)? {
                        return Err(StateError::InvalidEducationTransaction(
                            "Grade: offering not found".into(),
                        ));
                    }
                    if !ex.assessment_exists(&d.offering_id, &d.assessment_id)? {
                        return Err(StateError::InvalidEducationTransaction(
                            "Grade: assessment not found".into(),
                        ));
                    }
                    if ex.grade_finalized(
                        &d.offering_id,
                        &d.assessment_id,
                        &d.student_commitment,
                    )? {
                        return Err(StateError::DuplicateEducationRecord);
                    }
                }
                EduParsed::FinalizeGrade(d) => {
                    if !ex.offering_exists(&d.offering_id)? {
                        return Err(StateError::InvalidEducationTransaction(
                            "FinalizeGrade: offering not found".into(),
                        ));
                    }
                    if !ex.assessment_exists(&d.offering_id, &d.assessment_id)? {
                        return Err(StateError::InvalidEducationTransaction(
                            "FinalizeGrade: assessment not found".into(),
                        ));
                    }
                    if ex.grade_finalized(
                        &d.offering_id,
                        &d.assessment_id,
                        &d.student_commitment,
                    )? {
                        return Err(StateError::DuplicateEducationRecord);
                    }
                }
                // Mutate/lifecycle ops: cheap existence only (executor
                // remains authoritative for state/auth).
                EduParsed::UpdateCatalog(d) => {
                    if !ex.catalog_exists(&d.catalog_id)? {
                        return Err(StateError::InvalidEducationTransaction(
                            "catalog not found".into(),
                        ));
                    }
                }
                EduParsed::PublishCatalogContent(d) => {
                    if !ex.catalog_exists(&d.catalog_id)? {
                        return Err(StateError::InvalidEducationTransaction(
                            "catalog not found".into(),
                        ));
                    }
                }
                EduParsed::DeprecateCatalog(d) => {
                    if !ex.catalog_exists(&d.catalog_id)? {
                        return Err(StateError::InvalidEducationTransaction(
                            "catalog not found".into(),
                        ));
                    }
                }
                EduParsed::ArchiveCatalog(d) => {
                    if !ex.catalog_exists(&d.catalog_id)? {
                        return Err(StateError::InvalidEducationTransaction(
                            "catalog not found".into(),
                        ));
                    }
                }
                EduParsed::SupersedeCatalog(d) => {
                    if !ex.catalog_exists(&d.old_catalog_id)? {
                        return Err(StateError::InvalidEducationTransaction(
                            "catalog not found".into(),
                        ));
                    }
                }
                EduParsed::UpdateOffering(d) => {
                    if !ex.offering_exists(&d.offering_id)? {
                        return Err(StateError::InvalidEducationTransaction(
                            "offering not found".into(),
                        ));
                    }
                }
                EduParsed::UpdateAssessment(d) => {
                    if !ex.assessment_exists(&d.offering_id, &d.assessment_id)? {
                        return Err(StateError::InvalidEducationTransaction(
                            "assessment not found".into(),
                        ));
                    }
                }
                EduParsed::OpenEnrollment(d) => {
                    if !ex.offering_exists(&d.offering_id)? {
                        return Err(StateError::InvalidEducationTransaction(
                            "offering not found".into(),
                        ));
                    }
                }
                EduParsed::CloseEnrollment(d) => {
                    if !ex.offering_exists(&d.offering_id)? {
                        return Err(StateError::InvalidEducationTransaction(
                            "offering not found".into(),
                        ));
                    }
                }
                EduParsed::FinalizeCourse(d) => {
                    if !ex.offering_exists(&d.offering_id)? {
                        return Err(StateError::InvalidEducationTransaction(
                            "offering not found".into(),
                        ));
                    }
                }
                EduParsed::ArchiveOffering(d) => {
                    if !ex.offering_exists(&d.offering_id)? {
                        return Err(StateError::InvalidEducationTransaction(
                            "offering not found".into(),
                        ));
                    }
                }
                EduParsed::SuspendOrCancel(d) => {
                    if !ex.offering_exists(&d.offering_id)? {
                        return Err(StateError::InvalidEducationTransaction(
                            "offering not found".into(),
                        ));
                    }
                }
            }
        }

        Ok(Some(key))
    }

    /// Remove a transaction from the mempool
    pub fn remove(&self, hash: &Hash) -> Option<SignedTransaction> {
        let entry = self.txs.write().remove(hash)?;
        let sender = entry.tx.sender();

        // Remove from by_sender index
        {
            let mut by_sender = self.by_sender.write();
            if let Some(sender_txs) = by_sender.get_mut(&sender) {
                sender_txs.remove(hash);
                if sender_txs.is_empty() {
                    by_sender.remove(&sender);
                }
            }
        }

        // Remove from by_fee index
        let fee_key = (Balance::MAX - entry.fee, *hash);
        self.by_fee.write().remove(&fee_key);

        // Clear in-flight key for InferenceAttestation txs. Re-derive
        // the key from the stored tx rather than maintaining a reverse
        // index, so the cleanup path can't desync from the admission
        // path. No-op for non-InferenceAttestation variants.
        if let TxInner::V2(v2_tx) = &entry.tx.inner {
            if let TxPayload::InferenceAttestation(att) = &v2_tx.payload {
                let key = inference_attestation_key(
                    &att.digest.session_id,
                    &v2_tx.from,
                );
                self.inference_in_flight.write().remove(&key);
            }
            // Education in-flight unlink. Re-derive the key from the
            // stored tx (no reverse index → cleanup can't desync from
            // admission). No-op for non-education variants and for
            // undecodable payloads (which never got admitted anyway).
            if let TxPayload::Education(edu) = &v2_tx.payload {
                if let Ok(parsed) = parse_education(edu) {
                    let key = education_in_flight_key(&parsed);
                    self.education_in_flight.write().remove(&key);
                }
            }
        }

        debug!("Removed tx {} from mempool", hash);

        Some(entry.tx)
    }

    /// Remove multiple transactions (e.g., after block inclusion)
    pub fn remove_batch(&self, hashes: &[Hash]) {
        for hash in hashes {
            self.remove(hash);
        }
    }

    /// Get a transaction by hash
    pub fn get(&self, hash: &Hash) -> Option<SignedTransaction> {
        self.txs.read().get(hash).map(|e| e.tx.clone())
    }

    /// Check if a transaction exists
    pub fn contains(&self, hash: &Hash) -> bool {
        self.txs.read().contains_key(hash)
    }

    /// Get transactions for a sender
    pub fn get_by_sender(&self, sender: &Address) -> Vec<SignedTransaction> {
        let by_sender = self.by_sender.read();
        let txs = self.txs.read();

        match by_sender.get(sender) {
            Some(hashes) => hashes
                .iter()
                .filter_map(|h| txs.get(h).map(|e| e.tx.clone()))
                .collect(),
            None => Vec::new(),
        }
    }

    /// Get next nonce for a sender (current nonce + pending tx count)
    pub fn pending_nonce(&self, sender: &Address, current_nonce: Nonce) -> Nonce {
        let by_sender = self.by_sender.read();
        match by_sender.get(sender) {
            Some(hashes) => current_nonce + hashes.len() as u64,
            None => current_nonce,
        }
    }

    /// Select transactions for a new block (sorted by fee, highest first)
    pub fn select_for_block(&self, max_count: usize) -> Vec<SignedTransaction> {
        let by_fee = self.by_fee.read();
        let txs = self.txs.read();

        by_fee
            .values()
            .take(max_count)
            .filter_map(|hash| txs.get(hash).map(|e| e.tx.clone()))
            .collect()
    }

    /// Get mempool size
    pub fn len(&self) -> usize {
        self.txs.read().len()
    }

    /// Check if mempool is empty
    pub fn is_empty(&self) -> bool {
        self.txs.read().is_empty()
    }

    /// Get all transactions in the mempool
    pub fn get_all(&self) -> Vec<SignedTransaction> {
        self.txs.read().values().map(|e| e.tx.clone()).collect()
    }

    /// Clear all transactions
    pub fn clear(&self) {
        self.txs.write().clear();
        self.by_sender.write().clear();
        self.by_fee.write().clear();
        self.inference_in_flight.write().clear();
        self.education_in_flight.write().clear();
        info!("Mempool cleared");
    }

    /// Try to evict the lowest fee transaction to make room
    fn try_evict_lowest_fee(&self, new_fee: Balance) -> bool {
        let by_fee = self.by_fee.write();

        // Get lowest fee tx (last in BTreeMap since we use MAX - fee)
        if let Some((fee_key, hash)) = by_fee.iter().next_back().map(|(k, v)| (*k, *v)) {
            let lowest_fee = Balance::MAX - fee_key.0;

            if new_fee > lowest_fee {
                // New tx has higher fee, evict the old one
                drop(by_fee);
                self.remove(&hash);
                debug!("Evicted low-fee tx {} (fee: {})", hash, lowest_fee);
                return true;
            }
        }

        false
    }

    /// Revalidate all transactions against current state
    pub fn revalidate(&self, state: &StateManager, chain_id: u64) {
        let hashes: Vec<Hash> = self.txs.read().keys().cloned().collect();
        let mut to_remove = Vec::new();

        for hash in hashes {
            if let Some(tx) = self.get(&hash) {
                // Check basic validity
                if tx.chain_id() != chain_id {
                    to_remove.push(hash);
                    continue;
                }

                // Check nonce
                let sender = tx.sender();
                if let Ok(current_nonce) = state.get_nonce(&sender) {
                    if tx.nonce() < current_nonce {
                        to_remove.push(hash);
                        continue;
                    }
                }

                // Check balance
                if let Ok(balance) = state.get_balance(&sender) {
                    let total_cost = tx.amount().saturating_add(tx.fee());
                    if balance < total_cost {
                        to_remove.push(hash);
                    }
                }
            }
        }

        if !to_remove.is_empty() {
            info!("Revalidation removing {} stale transactions", to_remove.len());
            self.remove_batch(&to_remove);
        }
    }

    /// Remove expired transactions from the mempool
    /// Returns the number of transactions removed
    pub fn expire_old_transactions(&self) -> usize {
        if self.config.tx_expiration_secs == 0 {
            return 0; // Expiration disabled
        }

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

        let expiration_threshold = now.saturating_sub(self.config.tx_expiration_secs * 1000);

        let mut to_remove = Vec::new();

        {
            let txs = self.txs.read();
            for (hash, entry) in txs.iter() {
                if entry.received_at < expiration_threshold {
                    to_remove.push(*hash);
                }
            }
        }

        let count = to_remove.len();
        if count > 0 {
            info!("Expiring {} old transactions from mempool", count);
            self.remove_batch(&to_remove);
        }

        count
    }

    /// Get mempool statistics
    pub fn stats(&self) -> MempoolStats {
        let txs = self.txs.read();
        let by_sender = self.by_sender.read();

        let mut total_fees = 0u128;
        let mut oldest_tx_age_ms = 0u64;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

        for entry in txs.values() {
            total_fees += entry.fee as u128;
            let age = now.saturating_sub(entry.received_at);
            if age > oldest_tx_age_ms {
                oldest_tx_age_ms = age;
            }
        }

        MempoolStats {
            size: txs.len(),
            unique_senders: by_sender.len(),
            total_fees,
            oldest_tx_age_secs: oldest_tx_age_ms / 1000,
            max_size: self.config.max_size,
        }
    }
}

/// Mempool statistics
#[derive(Debug, Clone)]
pub struct MempoolStats {
    /// Current number of transactions
    pub size: usize,
    /// Number of unique senders
    pub unique_senders: usize,
    /// Total fees of all transactions
    pub total_fees: u128,
    /// Age of the oldest transaction in seconds
    pub oldest_tx_age_secs: u64,
    /// Maximum mempool size
    pub max_size: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use sumchain_crypto::{sign, KeyPair};
    use sumchain_primitives::Transaction;

    fn create_signed_tx(
        kp: &KeyPair,
        to: Address,
        amount: Balance,
        fee: Balance,
        nonce: u64,
    ) -> SignedTransaction {
        let tx = Transaction::new(1, kp.address(), to, amount, fee, nonce);
        let signing_hash = tx.signing_hash();
        let sig = sign(signing_hash.as_bytes(), kp.private_key());
        SignedTransaction::new(tx, *sig.as_bytes(), *kp.public_key().as_bytes())
    }

    #[test]
    fn test_add_and_get() {
        let mempool = Mempool::new(MempoolConfig::default());
        let sender = KeyPair::generate();
        let recipient = KeyPair::generate();

        let tx = create_signed_tx(&sender, recipient.address(), 100, 10, 0);
        let hash = tx.hash();

        mempool.add(tx.clone()).unwrap();

        assert!(mempool.contains(&hash));
        assert_eq!(mempool.get(&hash), Some(tx));
        assert_eq!(mempool.len(), 1);
    }

    #[test]
    fn test_remove() {
        let mempool = Mempool::new(MempoolConfig::default());
        let sender = KeyPair::generate();
        let recipient = KeyPair::generate();

        let tx = create_signed_tx(&sender, recipient.address(), 100, 10, 0);
        let hash = tx.hash();

        mempool.add(tx).unwrap();
        assert!(mempool.contains(&hash));

        mempool.remove(&hash);
        assert!(!mempool.contains(&hash));
        assert_eq!(mempool.len(), 0);
    }

    #[test]
    fn test_duplicate_rejection() {
        let mempool = Mempool::new(MempoolConfig::default());
        let sender = KeyPair::generate();
        let recipient = KeyPair::generate();

        let tx = create_signed_tx(&sender, recipient.address(), 100, 10, 0);

        mempool.add(tx.clone()).unwrap();
        let result = mempool.add(tx);

        assert!(matches!(result, Err(StateError::TxAlreadyExists)));
    }

    #[test]
    fn test_fee_sorting() {
        let mempool = Mempool::new(MempoolConfig::default());
        let sender = KeyPair::generate();
        let recipient = KeyPair::generate();

        let tx1 = create_signed_tx(&sender, recipient.address(), 100, 5, 0);
        let tx2 = create_signed_tx(&sender, recipient.address(), 100, 20, 1);
        let tx3 = create_signed_tx(&sender, recipient.address(), 100, 10, 2);

        mempool.add(tx1).unwrap();
        mempool.add(tx2.clone()).unwrap();
        mempool.add(tx3).unwrap();

        let selected = mempool.select_for_block(1);
        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].fee(), 20); // Highest fee first
    }

    #[test]
    fn test_min_fee() {
        let config = MempoolConfig {
            min_fee: 100,
            ..Default::default()
        };
        let mempool = Mempool::new(config);
        let sender = KeyPair::generate();
        let recipient = KeyPair::generate();

        let tx = create_signed_tx(&sender, recipient.address(), 100, 10, 0); // Fee too low

        let result = mempool.add(tx);
        assert!(matches!(result, Err(StateError::FeeTooLow { .. })));
    }
}
