//! SRC-84X agreements and IP rights, as this block's candidate sees them.
//!
//! The committed twins in `sumchain_storage::agreement_store` stay for the RPC
//! server, which answers about the canonical chain.
//!
//! ## Why the reads move with the writes
//!
//! This subsystem is a state machine, and every transition is a
//! read-modify-write: `update_status` and `update_state` read the row, change
//! one field plus `updated_at`, and write it back. Eleven of the twenty
//! migrated occurrences are transitions of that shape. Against committed state
//! each one would read the value the block STARTED with, so a second
//! transition in the same block would overwrite the first rather than follow
//! it, and an executor link could go Active -> Paused -> Active while the row
//! records only the last write applied to a stale base.
//!
//! `v_mark_party_signed` is the sharpest case. It flips one party's `signed`
//! flag and then, if every party has now signed, advances the agreement from
//! `PendingSignatures` to `Executed`. That check reads the OTHER parties'
//! flags. Two signatures in one block therefore only reach `Executed` if the
//! second one sees the first; against committed state a two-party agreement
//! signed twice in one block would end the block still pending.
//!
//! ## What these reproduce exactly, from the shared halves
//!
//! * The key layout: six primary families keyed by a bare 32-byte id, the
//!   party index by a 32-byte party-ref HASH, the executor index by a 20-byte
//!   ADDRESS.
//! * The two index VALUES as accumulating `Vec` lists with `contains` dedup --
//!   a read-modify-write in their own right.
//! * The `NotFound` error a transition returns for an absent row. Callers
//!   branch on it, so it is not a detail.

use sumchain_primitives::agreement::{
    AgreementCommitment, AgreementProofEnvelope, AgreementStatus, AttestationId, AttestationPacket,
    AttestationStatus, ExecutorLink, ExecutorLinkId, ExecutorState, IpActionStatus, IpAssetId,
    IpRightsAction, PartySignature, SignatureId,
};
use sumchain_primitives::{Address, Timestamp};
use sumchain_storage::agreement_store::{
    attestation_key, commitment_key, decode_agreement_ids, decode_attestation, decode_commitment,
    decode_executor_link, decode_ip_action, decode_link_ids, decode_signature,
    encode_agreement_ids, encode_attestation, encode_commitment, encode_executor_link,
    encode_ip_action, encode_link_ids, encode_proof, encode_signature, executor_index_key,
    executor_link_key, ip_action_key, party_index_key, proof_key, signature_key, AgreementId,
    ProofId,
};
use sumchain_storage::cf;
use sumchain_storage::exec_view::ExecutionView;

use crate::agreement_executor::AgreementExecutor;
use crate::{Result, StateError};

/// The committed stores return `StorageError::NotFound` when a transition
/// targets a row that is not there, and callers branch on it. Reproduced
/// rather than replaced with a state-level error.
fn not_found(what: &str, id: &[u8]) -> StateError {
    StateError::Storage(sumchain_storage::StorageError::NotFound(format!(
        "{what} not found: {id:?}"
    )))
}

impl AgreementExecutor {
    // ── Commitments, and the party index ────────────────────────────────────

    pub fn v_get_agreement(
        view: &ExecutionView<'_, '_>,
        agreement_id: &AgreementId,
    ) -> Result<Option<AgreementCommitment>> {
        match view
            .get(cf::AGREEMENT_COMMITMENTS, commitment_key(agreement_id))
            .map_err(StateError::Storage)?
        {
            Some(bytes) => Ok(Some(
                decode_commitment(&bytes).map_err(StateError::Storage)?,
            )),
            None => Ok(None),
        }
    }

    pub fn v_agreement_exists(
        view: &ExecutionView<'_, '_>,
        agreement_id: &AgreementId,
    ) -> Result<bool> {
        view.contains(cf::AGREEMENT_COMMITMENTS, commitment_key(agreement_id))
            .map_err(StateError::Storage)
    }

    /// The commitment row AND every party's index entry, as the committed twin
    /// writes them.
    pub fn v_put_agreement(
        view: &mut ExecutionView<'_, '_>,
        agreement: &AgreementCommitment,
    ) -> Result<()> {
        let bytes = encode_commitment(agreement).map_err(StateError::Storage)?;
        view.put(
            cf::AGREEMENT_COMMITMENTS,
            commitment_key(&agreement.agreement_id),
            &bytes,
        )
        .map_err(StateError::Storage)?;
        for party in &agreement.parties {
            Self::v_add_to_party_index(view, &party.party_ref.as_hash(), &agreement.agreement_id)?;
        }
        Ok(())
    }

    pub fn v_get_party_agreement_ids(
        view: &ExecutionView<'_, '_>,
        party_ref_hash: &[u8; 32],
    ) -> Result<Vec<AgreementId>> {
        match view
            .get(cf::AGREEMENT_PARTY_INDEX, party_index_key(party_ref_hash))
            .map_err(StateError::Storage)?
        {
            Some(bytes) => decode_agreement_ids(&bytes).map_err(StateError::Storage),
            None => Ok(Vec::new()),
        }
    }

    fn v_add_to_party_index(
        view: &mut ExecutionView<'_, '_>,
        party_ref_hash: &[u8; 32],
        agreement_id: &AgreementId,
    ) -> Result<()> {
        let mut ids = Self::v_get_party_agreement_ids(view, party_ref_hash)?;
        // The committed twin skips the write entirely when the id is already
        // there rather than rewriting an identical list.
        if ids.contains(agreement_id) {
            return Ok(());
        }
        ids.push(*agreement_id);
        let bytes = encode_agreement_ids(&ids).map_err(StateError::Storage)?;
        view.put(
            cf::AGREEMENT_PARTY_INDEX,
            party_index_key(party_ref_hash),
            &bytes,
        )
        .map_err(StateError::Storage)
    }

    /// Read, set status and `updated_at`, write. `NotFound` for an absent row.
    pub fn v_update_agreement_status(
        view: &mut ExecutionView<'_, '_>,
        agreement_id: &AgreementId,
        status: AgreementStatus,
        timestamp: Timestamp,
    ) -> Result<()> {
        match Self::v_get_agreement(view, agreement_id)? {
            Some(mut agreement) => {
                agreement.status = status;
                agreement.updated_at = timestamp;
                let bytes = encode_commitment(&agreement).map_err(StateError::Storage)?;
                view.put(
                    cf::AGREEMENT_COMMITMENTS,
                    commitment_key(agreement_id),
                    &bytes,
                )
                .map_err(StateError::Storage)
            }
            None => Err(not_found("Agreement", agreement_id)),
        }
    }

    /// Flip one party's signature, then advance the agreement to `Executed` if
    /// that was the last one outstanding.
    ///
    /// The fully-signed check reads the OTHER parties' flags, so this only
    /// reaches `Executed` when it sees the signatures this block already
    /// applied. That is the whole reason this subsystem's reads had to move
    /// with its writes.
    pub fn v_mark_party_signed(
        view: &mut ExecutionView<'_, '_>,
        agreement_id: &AgreementId,
        party_ref_hash: &[u8; 32],
        timestamp: Timestamp,
    ) -> Result<()> {
        match Self::v_get_agreement(view, agreement_id)? {
            Some(mut agreement) => {
                for party in &mut agreement.parties {
                    if party.party_ref.as_hash() == *party_ref_hash {
                        party.signed = true;
                        party.signed_at = Some(timestamp);
                    }
                }
                agreement.updated_at = timestamp;

                if agreement.is_fully_signed()
                    && agreement.status == AgreementStatus::PendingSignatures
                {
                    agreement.status = AgreementStatus::Executed;
                }

                let bytes = encode_commitment(&agreement).map_err(StateError::Storage)?;
                view.put(
                    cf::AGREEMENT_COMMITMENTS,
                    commitment_key(agreement_id),
                    &bytes,
                )
                .map_err(StateError::Storage)
            }
            None => Err(not_found("Agreement", agreement_id)),
        }
    }

    /// The inverse of [`AgreementExecutor::v_mark_party_signed`].
    ///
    /// ACTIVATION-AUDIT row OV-29. Deleting a signature row while the party's
    /// `signed` flag stays set leaves an agreement `Executed` with the signature
    /// that executed it gone, and no path anywhere recomputes the status. This
    /// clears the flag and the timestamp, and walks the status back from
    /// `Executed` to `PendingSignatures` when the agreement is no longer fully
    /// signed -- exactly reversing the promotion `v_mark_party_signed` performs,
    /// and only that one: an agreement moved to `Active`, `Terminated`,
    /// `Superseded` or `Voided` by its own operation is not dragged backwards by
    /// a revocation, because those statuses were not reached by signing.
    ///
    /// Reachable only through the gate; the signing path is untouched, so a node
    /// below the activation height writes exactly what it wrote before.
    pub fn v_unmark_party_signed(
        view: &mut ExecutionView<'_, '_>,
        agreement_id: &AgreementId,
        party_ref_hash: &[u8; 32],
        timestamp: Timestamp,
    ) -> Result<()> {
        match Self::v_get_agreement(view, agreement_id)? {
            Some(mut agreement) => {
                for party in &mut agreement.parties {
                    if party.party_ref.as_hash() == *party_ref_hash {
                        party.signed = false;
                        party.signed_at = None;
                    }
                }
                agreement.updated_at = timestamp;

                if !agreement.is_fully_signed() && agreement.status == AgreementStatus::Executed {
                    agreement.status = AgreementStatus::PendingSignatures;
                }

                let bytes = encode_commitment(&agreement).map_err(StateError::Storage)?;
                view.put(
                    cf::AGREEMENT_COMMITMENTS,
                    commitment_key(agreement_id),
                    &bytes,
                )
                .map_err(StateError::Storage)
            }
            None => Err(not_found("Agreement", agreement_id)),
        }
    }

    // ── Signatures ──────────────────────────────────────────────────────────

    pub fn v_get_signature(
        view: &ExecutionView<'_, '_>,
        signature_id: &SignatureId,
    ) -> Result<Option<PartySignature>> {
        match view
            .get(cf::AGREEMENT_SIGNATURES, signature_key(signature_id))
            .map_err(StateError::Storage)?
        {
            Some(bytes) => Ok(Some(decode_signature(&bytes).map_err(StateError::Storage)?)),
            None => Ok(None),
        }
    }

    pub fn v_signature_exists(
        view: &ExecutionView<'_, '_>,
        signature_id: &SignatureId,
    ) -> Result<bool> {
        view.contains(cf::AGREEMENT_SIGNATURES, signature_key(signature_id))
            .map_err(StateError::Storage)
    }

    pub fn v_put_signature(
        view: &mut ExecutionView<'_, '_>,
        signature: &PartySignature,
    ) -> Result<()> {
        let bytes = encode_signature(signature).map_err(StateError::Storage)?;
        view.put(
            cf::AGREEMENT_SIGNATURES,
            signature_key(&signature.signature_id),
            &bytes,
        )
        .map_err(StateError::Storage)
    }

    pub fn v_delete_signature(
        view: &mut ExecutionView<'_, '_>,
        signature_id: &SignatureId,
    ) -> Result<()> {
        view.delete(cf::AGREEMENT_SIGNATURES, signature_key(signature_id))
            .map_err(StateError::Storage)
    }

    // ── Attestations ────────────────────────────────────────────────────────

    pub fn v_get_attestation(
        view: &ExecutionView<'_, '_>,
        attestation_id: &AttestationId,
    ) -> Result<Option<AttestationPacket>> {
        match view
            .get(cf::AGREEMENT_ATTESTATIONS, attestation_key(attestation_id))
            .map_err(StateError::Storage)?
        {
            Some(bytes) => Ok(Some(
                decode_attestation(&bytes).map_err(StateError::Storage)?,
            )),
            None => Ok(None),
        }
    }

    pub fn v_attestation_exists(
        view: &ExecutionView<'_, '_>,
        attestation_id: &AttestationId,
    ) -> Result<bool> {
        view.contains(cf::AGREEMENT_ATTESTATIONS, attestation_key(attestation_id))
            .map_err(StateError::Storage)
    }

    pub fn v_put_attestation(
        view: &mut ExecutionView<'_, '_>,
        attestation: &AttestationPacket,
    ) -> Result<()> {
        let bytes = encode_attestation(attestation).map_err(StateError::Storage)?;
        view.put(
            cf::AGREEMENT_ATTESTATIONS,
            attestation_key(&attestation.attestation_id),
            &bytes,
        )
        .map_err(StateError::Storage)
    }

    /// Note: no `updated_at` here. The committed twin changes only the status,
    /// which is why this one takes no timestamp.
    pub fn v_update_attestation_status(
        view: &mut ExecutionView<'_, '_>,
        attestation_id: &AttestationId,
        status: AttestationStatus,
    ) -> Result<()> {
        match Self::v_get_attestation(view, attestation_id)? {
            Some(mut att) => {
                att.status = status;
                let bytes = encode_attestation(&att).map_err(StateError::Storage)?;
                view.put(
                    cf::AGREEMENT_ATTESTATIONS,
                    attestation_key(attestation_id),
                    &bytes,
                )
                .map_err(StateError::Storage)
            }
            None => Err(not_found("Attestation", attestation_id)),
        }
    }

    // ── IP actions ──────────────────────────────────────────────────────────

    pub fn v_get_ip_action(
        view: &ExecutionView<'_, '_>,
        action_id: &IpAssetId,
    ) -> Result<Option<IpRightsAction>> {
        match view
            .get(cf::AGREEMENT_IP_ACTIONS, ip_action_key(action_id))
            .map_err(StateError::Storage)?
        {
            Some(bytes) => Ok(Some(decode_ip_action(&bytes).map_err(StateError::Storage)?)),
            None => Ok(None),
        }
    }

    pub fn v_ip_action_exists(view: &ExecutionView<'_, '_>, action_id: &IpAssetId) -> Result<bool> {
        view.contains(cf::AGREEMENT_IP_ACTIONS, ip_action_key(action_id))
            .map_err(StateError::Storage)
    }

    pub fn v_put_ip_action(
        view: &mut ExecutionView<'_, '_>,
        action: &IpRightsAction,
    ) -> Result<()> {
        let bytes = encode_ip_action(action).map_err(StateError::Storage)?;
        view.put(
            cf::AGREEMENT_IP_ACTIONS,
            ip_action_key(&action.action_id),
            &bytes,
        )
        .map_err(StateError::Storage)
    }

    pub fn v_update_ip_action_status(
        view: &mut ExecutionView<'_, '_>,
        action_id: &IpAssetId,
        status: IpActionStatus,
    ) -> Result<()> {
        match Self::v_get_ip_action(view, action_id)? {
            Some(mut action) => {
                action.status = status;
                let bytes = encode_ip_action(&action).map_err(StateError::Storage)?;
                view.put(cf::AGREEMENT_IP_ACTIONS, ip_action_key(action_id), &bytes)
                    .map_err(StateError::Storage)
            }
            None => Err(not_found("IP action", action_id)),
        }
    }

    // ── Executor links, and the executor index ──────────────────────────────

    pub fn v_get_executor_link(
        view: &ExecutionView<'_, '_>,
        link_id: &ExecutorLinkId,
    ) -> Result<Option<ExecutorLink>> {
        match view
            .get(cf::AGREEMENT_EXECUTOR_LINKS, executor_link_key(link_id))
            .map_err(StateError::Storage)?
        {
            Some(bytes) => Ok(Some(
                decode_executor_link(&bytes).map_err(StateError::Storage)?,
            )),
            None => Ok(None),
        }
    }

    pub fn v_executor_link_exists(
        view: &ExecutionView<'_, '_>,
        link_id: &ExecutorLinkId,
    ) -> Result<bool> {
        view.contains(cf::AGREEMENT_EXECUTOR_LINKS, executor_link_key(link_id))
            .map_err(StateError::Storage)
    }

    /// The link row AND its executor-index entry.
    pub fn v_put_executor_link(
        view: &mut ExecutionView<'_, '_>,
        link: &ExecutorLink,
    ) -> Result<()> {
        let bytes = encode_executor_link(link).map_err(StateError::Storage)?;
        view.put(
            cf::AGREEMENT_EXECUTOR_LINKS,
            executor_link_key(&link.link_id),
            &bytes,
        )
        .map_err(StateError::Storage)?;
        Self::v_add_to_executor_index(view, &link.executor_contract, &link.link_id)
    }

    pub fn v_get_executor_link_ids(
        view: &ExecutionView<'_, '_>,
        executor: &Address,
    ) -> Result<Vec<ExecutorLinkId>> {
        match view
            .get(cf::AGREEMENT_EXECUTOR_INDEX, executor_index_key(executor))
            .map_err(StateError::Storage)?
        {
            Some(bytes) => decode_link_ids(&bytes).map_err(StateError::Storage),
            None => Ok(Vec::new()),
        }
    }

    fn v_add_to_executor_index(
        view: &mut ExecutionView<'_, '_>,
        executor: &Address,
        link_id: &ExecutorLinkId,
    ) -> Result<()> {
        let mut ids = Self::v_get_executor_link_ids(view, executor)?;
        if ids.contains(link_id) {
            return Ok(());
        }
        ids.push(*link_id);
        let bytes = encode_link_ids(&ids).map_err(StateError::Storage)?;
        view.put(
            cf::AGREEMENT_EXECUTOR_INDEX,
            executor_index_key(executor),
            &bytes,
        )
        .map_err(StateError::Storage)
    }

    pub fn v_update_executor_state(
        view: &mut ExecutionView<'_, '_>,
        link_id: &ExecutorLinkId,
        state: ExecutorState,
        timestamp: Timestamp,
    ) -> Result<()> {
        match Self::v_get_executor_link(view, link_id)? {
            Some(mut link) => {
                link.state = state;
                link.updated_at = timestamp;
                let bytes = encode_executor_link(&link).map_err(StateError::Storage)?;
                view.put(
                    cf::AGREEMENT_EXECUTOR_LINKS,
                    executor_link_key(link_id),
                    &bytes,
                )
                .map_err(StateError::Storage)
            }
            None => Err(not_found("Executor link", link_id)),
        }
    }

    // ── Proofs ──────────────────────────────────────────────────────────────

    pub fn v_proof_exists(view: &ExecutionView<'_, '_>, proof_id: &ProofId) -> Result<bool> {
        view.contains(cf::AGREEMENT_PROOFS, proof_key(proof_id))
            .map_err(StateError::Storage)
    }

    pub fn v_put_proof(
        view: &mut ExecutionView<'_, '_>,
        proof: &AgreementProofEnvelope,
    ) -> Result<()> {
        let bytes = encode_proof(proof).map_err(StateError::Storage)?;
        view.put(cf::AGREEMENT_PROOFS, proof_key(&proof.proof_id), &bytes)
            .map_err(StateError::Storage)
    }
}
