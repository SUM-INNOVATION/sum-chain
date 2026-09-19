//! SRC-82X tax and compliance, as this block's candidate sees it.
//!
//! The committed twins in `sumchain_storage::tax_store` stay for the RPC
//! server, which answers about the canonical chain.
//!
//! ## Why the reads move with the writes
//!
//! Every operation in this subsystem is a read-then-write: `RegisterClaimType`
//! and `RegisterIssuer` and `CreatePolicy` refuse a duplicate, `UpdateIssuer`
//! and `DeprecateClaimType` and `UpdatePolicy` require the row to exist and
//! rewrite it, `IssueClaim` requires an ACTIVE issuer, `RevokeClaim` requires
//! the proof to be there. All of those were committed reads, correct only
//! because the matching writes committed as they went. Two tax transactions in
//! one block would otherwise both pass the duplicate guard, or the second would
//! fail to find what the first registered.
//!
//! ## Two behaviours reproduced deliberately, not fixed
//!
//! * `v_put_proof` writes the proof AND appends its id to the subject index,
//!   de-duplicating by `contains` -- a read-modify-write on a bincode
//!   `Vec<ProofId>`.
//! * `v_delete_proof` removes ONLY the proof row and leaves the subject index
//!   entry behind, exactly as the committed twin does. That asymmetry is a
//!   pre-existing defect: the index keeps pointing at a proof that is gone.
//!   Changing it here would be a behaviour change smuggled into a migration,
//!   so it is preserved and recorded for separate activation work.

use sumchain_primitives::tax::{
    PolicyId, ProofId, TaxClaimTypeEntry, TaxDisclosureEnvelope, TaxIssuer, TaxPolicy,
    TaxProofEnvelope,
};
use sumchain_primitives::Address;
use sumchain_storage::cf;
use sumchain_storage::exec_view::ExecutionView;
use sumchain_storage::tax_store::{
    claim_type_key, decode_claim_type, decode_issuer, decode_policy, decode_proof,
    decode_proof_ids, disclosure_key, encode_claim_type, encode_disclosure, encode_issuer,
    encode_policy, encode_proof, encode_proof_ids, issuer_key, policy_key, proof_key,
    subject_index_key,
};

use crate::tax_executor::TaxExecutor;
use crate::{Result, StateError};

impl TaxExecutor {
    // ── Claim types ─────────────────────────────────────────────────────────

    pub fn v_get_claim_type(
        view: &ExecutionView<'_, '_>,
        claim_type: &str,
    ) -> Result<Option<TaxClaimTypeEntry>> {
        match view
            .get(cf::TAX_CLAIM_TYPES, claim_type_key(claim_type))
            .map_err(StateError::Storage)?
        {
            Some(bytes) => Ok(Some(
                decode_claim_type(&bytes).map_err(StateError::Storage)?,
            )),
            None => Ok(None),
        }
    }

    pub fn v_put_claim_type(
        view: &mut ExecutionView<'_, '_>,
        entry: &TaxClaimTypeEntry,
    ) -> Result<()> {
        let bytes = encode_claim_type(entry).map_err(StateError::Storage)?;
        view.put(
            cf::TAX_CLAIM_TYPES,
            claim_type_key(&entry.claim_type),
            &bytes,
        )
        .map_err(StateError::Storage)
    }

    // ── Issuers ─────────────────────────────────────────────────────────────

    pub fn v_get_issuer(
        view: &ExecutionView<'_, '_>,
        address: &Address,
    ) -> Result<Option<TaxIssuer>> {
        match view
            .get(cf::TAX_ISSUERS, issuer_key(address))
            .map_err(StateError::Storage)?
        {
            Some(bytes) => Ok(Some(decode_issuer(&bytes).map_err(StateError::Storage)?)),
            None => Ok(None),
        }
    }

    pub fn v_put_issuer(view: &mut ExecutionView<'_, '_>, issuer: &TaxIssuer) -> Result<()> {
        let bytes = encode_issuer(issuer).map_err(StateError::Storage)?;
        view.put(cf::TAX_ISSUERS, issuer_key(&issuer.address), &bytes)
            .map_err(StateError::Storage)
    }

    // ── Policies ────────────────────────────────────────────────────────────

    pub fn v_get_policy(
        view: &ExecutionView<'_, '_>,
        policy_id: &PolicyId,
    ) -> Result<Option<TaxPolicy>> {
        match view
            .get(cf::TAX_POLICIES, policy_key(policy_id))
            .map_err(StateError::Storage)?
        {
            Some(bytes) => Ok(Some(decode_policy(&bytes).map_err(StateError::Storage)?)),
            None => Ok(None),
        }
    }

    pub fn v_put_policy(view: &mut ExecutionView<'_, '_>, policy: &TaxPolicy) -> Result<()> {
        let bytes = encode_policy(policy).map_err(StateError::Storage)?;
        view.put(cf::TAX_POLICIES, policy_key(&policy.policy_id), &bytes)
            .map_err(StateError::Storage)
    }

    // ── Proofs, and the subject index ───────────────────────────────────────

    pub fn v_get_proof(
        view: &ExecutionView<'_, '_>,
        proof_id: &ProofId,
    ) -> Result<Option<TaxProofEnvelope>> {
        match view
            .get(cf::TAX_PROOFS, proof_key(proof_id))
            .map_err(StateError::Storage)?
        {
            Some(bytes) => Ok(Some(decode_proof(&bytes).map_err(StateError::Storage)?)),
            None => Ok(None),
        }
    }

    /// The proof row, and its id appended to the subject index.
    ///
    /// The index value is an accumulating `Vec<ProofId>`, so this is a
    /// read-modify-write: a second proof for the same subject in one block has
    /// to see the first one's id or it would overwrite the list with a
    /// single-element one.
    pub fn v_put_proof(view: &mut ExecutionView<'_, '_>, proof: &TaxProofEnvelope) -> Result<()> {
        let bytes = encode_proof(proof).map_err(StateError::Storage)?;
        view.put(cf::TAX_PROOFS, proof_key(&proof.proof_id), &bytes)
            .map_err(StateError::Storage)?;
        Self::v_add_to_subject_index(view, &proof.subject_nullifier, &proof.proof_id)
    }

    /// ONLY the proof row. The subject index entry stays, as it does on the
    /// committed path -- see this module's header.
    pub fn v_delete_proof(view: &mut ExecutionView<'_, '_>, proof_id: &ProofId) -> Result<()> {
        view.delete(cf::TAX_PROOFS, proof_key(proof_id))
            .map_err(StateError::Storage)
    }

    /// Every proof recorded for `subject_nullifier`, and the index row itself.
    ///
    /// The gated counterpart of [`TaxExecutor::v_delete_proof`], and the whole
    /// of ACTIVATION-AUDIT row OV-3: a deletion that leaves the index behind is
    /// what makes `TAX_SUBJECT_INDEX` grow without bound and point at rows that
    /// are gone. Removing the index row rather than rewriting a shortened list
    /// is deliberate -- the subject has no proofs left, and an empty list row is
    /// a row an absent subject would not have (the asymmetry OV-15 records in
    /// the NFT indexes, not reintroduced here).
    ///
    /// Returns how many proof rows were removed. An id the index names but the
    /// proof family does not hold -- a danger left by a pre-activation deletion
    /// -- is counted as removed and does not fail the call: the index row goes
    /// either way, which is precisely the repair.
    ///
    /// Reachable only through the gate. `v_delete_proof` is untouched, so a node
    /// below the activation height writes exactly what it wrote before.
    pub fn v_delete_subject_proofs(
        view: &mut ExecutionView<'_, '_>,
        subject_nullifier: &[u8; 32],
    ) -> Result<usize> {
        let ids = Self::v_get_subject_proof_ids(view, subject_nullifier)?;
        for id in &ids {
            view.delete(cf::TAX_PROOFS, proof_key(id))
                .map_err(StateError::Storage)?;
        }
        if !ids.is_empty() {
            view.delete(cf::TAX_SUBJECT_INDEX, subject_index_key(subject_nullifier))
                .map_err(StateError::Storage)?;
        }
        Ok(ids.len())
    }

    /// The STORED length of the subject index row, without decoding it.
    ///
    /// ACTIVATION-AUDIT row AL-1. The whole point is that no `Vec<ProofId>` is
    /// built: the caller compares this against
    /// [`crate::MAX_ACCUMULATING_ROW_BYTES`] and refuses, so a row that has
    /// been grown past the limit costs one comparison to reject rather than a
    /// decode, an append and a re-encode. `None` means there is no row, which
    /// is not a refusal -- the first proof for a subject has to be able to
    /// land.
    pub fn v_subject_index_row_len(
        view: &ExecutionView<'_, '_>,
        subject_nullifier: &[u8; 32],
    ) -> Result<Option<usize>> {
        Ok(view
            .get(cf::TAX_SUBJECT_INDEX, subject_index_key(subject_nullifier))
            .map_err(StateError::Storage)?
            .map(|bytes| bytes.len()))
    }

    pub fn v_get_subject_proof_ids(
        view: &ExecutionView<'_, '_>,
        subject_nullifier: &[u8; 32],
    ) -> Result<Vec<ProofId>> {
        match view
            .get(cf::TAX_SUBJECT_INDEX, subject_index_key(subject_nullifier))
            .map_err(StateError::Storage)?
        {
            Some(bytes) => decode_proof_ids(&bytes).map_err(StateError::Storage),
            None => Ok(Vec::new()),
        }
    }

    fn v_add_to_subject_index(
        view: &mut ExecutionView<'_, '_>,
        subject_nullifier: &[u8; 32],
        proof_id: &ProofId,
    ) -> Result<()> {
        let mut ids = Self::v_get_subject_proof_ids(view, subject_nullifier)?;
        // The committed twin skips the write entirely when the id is already
        // there, rather than rewriting an identical list. Same here: a rewrite
        // would cost candidate bytes for no change.
        if ids.contains(proof_id) {
            return Ok(());
        }
        ids.push(*proof_id);
        let bytes = encode_proof_ids(&ids).map_err(StateError::Storage)?;
        view.put(
            cf::TAX_SUBJECT_INDEX,
            subject_index_key(subject_nullifier),
            &bytes,
        )
        .map_err(StateError::Storage)
    }

    // ── Disclosures ─────────────────────────────────────────────────────────

    pub fn v_put_disclosure(
        view: &mut ExecutionView<'_, '_>,
        disclosure: &TaxDisclosureEnvelope,
    ) -> Result<()> {
        let bytes = encode_disclosure(disclosure).map_err(StateError::Storage)?;
        view.put(
            cf::TAX_DISCLOSURES,
            disclosure_key(&disclosure.payload_hash),
            &bytes,
        )
        .map_err(StateError::Storage)
    }

    pub fn v_get_disclosure(
        view: &ExecutionView<'_, '_>,
        payload_hash: &[u8; 32],
    ) -> Result<Option<TaxDisclosureEnvelope>> {
        match view
            .get(cf::TAX_DISCLOSURES, disclosure_key(payload_hash))
            .map_err(StateError::Storage)?
        {
            Some(bytes) => Ok(Some(
                sumchain_storage::tax_store::decode_disclosure(&bytes)
                    .map_err(StateError::Storage)?,
            )),
            None => Ok(None),
        }
    }
}
