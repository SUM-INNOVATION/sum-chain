//! SRC-87X healthcare, membership, consent and prescriptions, as this block's
//! candidate sees them.
//!
//! The committed twins in `sumchain_storage::healthcare_store` stay for the RPC
//! server, which answers about the canonical chain.
//!
//! ## Why the reads move with the writes
//!
//! Healthcare is two interlocking state machines -- the consent lifecycle and
//! the prescription lifecycle -- and almost every transition is a
//! read-modify-write: read the row, change one field plus `updated_at`, write
//! it back. Twenty-four of the twenty-nine migrated occurrences have that
//! shape. Against committed state each one would read the value the block
//! STARTED with, so a second transition in the same block would overwrite the
//! first rather than follow it.
//!
//! Two cases are sharper than the rest:
//!
//! * `PartialFillPrescription` writes the SAME row twice inside ONE
//!   transaction: `v_add_fill_history` appends the fill commitment, and then
//!   `v_update_prescription_status` re-reads that row to set
//!   `PartiallyFilled`. If the second read went to committed state it would
//!   read the row without the fill and write it back -- the fill would be
//!   silently discarded by the transaction that recorded it. This is not even a
//!   same-BLOCK hazard; it is a same-TRANSACTION one.
//!   -- `a_partial_fill_records_the_fill_and_the_status_in_one_transaction`
//!
//! * `v_record_fill` decrements `refills_remaining` and derives the status from
//!   what is left. Two fills in one block only reach the right count if the
//!   second sees the first.
//!   -- `two_fills_in_one_block_decrement_refills_twice`
//!
//! ## What these reproduce exactly, from the shared halves
//!
//! * The key layout: five primary families keyed by a bare 32-byte id, and five
//!   INDEX families keyed by the thing they group by -- a PLAN id, a member
//!   nullifier, a subject nullifier, a patient nullifier, and a prescriber
//!   PROVIDER id.
//! * All five index VALUES as accumulating `Vec` lists with `contains` dedup --
//!   a read-modify-write in their own right.
//! * The network index's REMOVE, which writes unconditionally: taking away an
//!   affiliation that was never there still writes a list row.
//! * The `NotFound` error a transition returns for an absent row, and the
//!   `InvalidData` error `v_record_fill` returns. Callers branch on them, so
//!   they are not details.

use sumchain_primitives::healthcare::{
    ConsentEnvelope, ConsentStatus, HealthcareProofEnvelope, MembershipRecord, MembershipStatus,
    Prescription, PrescriptionStatus, ProviderProfile, ProviderStatus,
};
use sumchain_primitives::Timestamp;
use sumchain_storage::cf;
use sumchain_storage::exec_view::ExecutionView;
use sumchain_storage::healthcare_store::{
    consent_key, decode_consent, decode_consent_ids, decode_membership, decode_membership_ids,
    decode_prescription, decode_prescription_ids, decode_provider, decode_provider_ids,
    encode_consent, encode_consent_ids, encode_healthcare_proof, encode_membership,
    encode_membership_ids, encode_prescription, encode_prescription_ids, encode_provider,
    encode_provider_ids, healthcare_proof_key, member_index_key, membership_key,
    patient_rx_index_key, prescriber_rx_index_key, prescription_key, provider_key,
    provider_network_index_key, subject_consent_index_key, ConsentId, MembershipId, PrescriptionId,
    ProofId, ProviderId,
};

use crate::healthcare_executor::HealthcareExecutor;
use crate::{Result, StateError};

/// The committed stores return `StorageError::NotFound` when a transition
/// targets a row that is not there, and callers branch on it. Reproduced
/// rather than replaced with a state-level error.
fn not_found(what: &str, id: &[u8]) -> StateError {
    StateError::Storage(sumchain_storage::StorageError::NotFound(format!(
        "{what} not found: {id:?}"
    )))
}

impl HealthcareExecutor {
    // ── Providers, and the plan-network index ───────────────────────────────

    pub fn v_get_provider(
        view: &ExecutionView<'_, '_>,
        provider_id: &ProviderId,
    ) -> Result<Option<ProviderProfile>> {
        match view
            .get(cf::HEALTHCARE_PROVIDERS, provider_key(provider_id))
            .map_err(StateError::Storage)?
        {
            Some(bytes) => Ok(Some(decode_provider(&bytes).map_err(StateError::Storage)?)),
            None => Ok(None),
        }
    }

    pub fn v_provider_exists(
        view: &ExecutionView<'_, '_>,
        provider_id: &ProviderId,
    ) -> Result<bool> {
        view.contains(cf::HEALTHCARE_PROVIDERS, provider_key(provider_id))
            .map_err(StateError::Storage)
    }

    /// The provider row AND one network-index entry per affiliation it
    /// declares, as the committed twin writes them.
    pub fn v_put_provider(
        view: &mut ExecutionView<'_, '_>,
        provider: &ProviderProfile,
    ) -> Result<()> {
        let bytes = encode_provider(provider).map_err(StateError::Storage)?;
        view.put(
            cf::HEALTHCARE_PROVIDERS,
            provider_key(&provider.provider_id),
            &bytes,
        )
        .map_err(StateError::Storage)?;
        for plan_id in &provider.network_affiliations {
            Self::v_add_to_network_index(view, &provider.provider_id, plan_id)?;
        }
        Ok(())
    }

    pub fn v_get_network_provider_ids(
        view: &ExecutionView<'_, '_>,
        plan_id: &ProviderId,
    ) -> Result<Vec<ProviderId>> {
        match view
            .get(
                cf::HEALTHCARE_PROVIDER_NETWORK_INDEX,
                provider_network_index_key(plan_id),
            )
            .map_err(StateError::Storage)?
        {
            Some(bytes) => decode_provider_ids(&bytes).map_err(StateError::Storage),
            None => Ok(Vec::new()),
        }
    }

    fn v_add_to_network_index(
        view: &mut ExecutionView<'_, '_>,
        provider_id: &ProviderId,
        plan_id: &ProviderId,
    ) -> Result<()> {
        let mut ids = Self::v_get_network_provider_ids(view, plan_id)?;
        // The committed twin skips the write entirely when the id is already
        // there rather than rewriting an identical list.
        if ids.contains(provider_id) {
            return Ok(());
        }
        ids.push(*provider_id);
        let bytes = encode_provider_ids(&ids).map_err(StateError::Storage)?;
        view.put(
            cf::HEALTHCARE_PROVIDER_NETWORK_INDEX,
            provider_network_index_key(plan_id),
            &bytes,
        )
        .map_err(StateError::Storage)
    }

    /// The only index REMOVE in the subsystem, and the only unconditional index
    /// write: the committed twin re-serializes and writes whatever is left even
    /// when nothing was removed, so an id that was never in the list still
    /// leaves an empty list row behind. Reproduced.
    fn v_remove_from_network_index(
        view: &mut ExecutionView<'_, '_>,
        provider_id: &ProviderId,
        plan_id: &ProviderId,
    ) -> Result<()> {
        let mut ids = Self::v_get_network_provider_ids(view, plan_id)?;
        ids.retain(|id| id != provider_id);
        let bytes = encode_provider_ids(&ids).map_err(StateError::Storage)?;
        view.put(
            cf::HEALTHCARE_PROVIDER_NETWORK_INDEX,
            provider_network_index_key(plan_id),
            &bytes,
        )
        .map_err(StateError::Storage)
    }

    /// Read, set status and `updated_at`, write. `NotFound` for an absent row.
    pub fn v_update_provider_status(
        view: &mut ExecutionView<'_, '_>,
        provider_id: &ProviderId,
        status: ProviderStatus,
        timestamp: Timestamp,
    ) -> Result<()> {
        match Self::v_get_provider(view, provider_id)? {
            Some(mut provider) => {
                provider.status = status;
                provider.updated_at = timestamp;
                let bytes = encode_provider(&provider).map_err(StateError::Storage)?;
                view.put(cf::HEALTHCARE_PROVIDERS, provider_key(provider_id), &bytes)
                    .map_err(StateError::Storage)
            }
            None => Err(not_found("Provider", provider_id)),
        }
    }

    /// Append a plan to the provider's affiliation list AND to that plan's
    /// network index -- but only when it is not already there. An affiliation
    /// that already exists writes NOTHING: not the provider row, not the index,
    /// and not even `updated_at`.
    pub fn v_add_network_affiliation(
        view: &mut ExecutionView<'_, '_>,
        provider_id: &ProviderId,
        plan_id: &ProviderId,
        timestamp: Timestamp,
    ) -> Result<()> {
        match Self::v_get_provider(view, provider_id)? {
            Some(mut provider) => {
                if !provider.network_affiliations.contains(plan_id) {
                    provider.network_affiliations.push(*plan_id);
                    provider.updated_at = timestamp;
                    let bytes = encode_provider(&provider).map_err(StateError::Storage)?;
                    view.put(cf::HEALTHCARE_PROVIDERS, provider_key(provider_id), &bytes)
                        .map_err(StateError::Storage)?;
                    Self::v_add_to_network_index(view, provider_id, plan_id)?;
                }
                Ok(())
            }
            None => Err(not_found("Provider", provider_id)),
        }
    }

    /// The mirror of the above, and NOT its symmetric opposite: this one always
    /// writes both the provider row and the index.
    pub fn v_remove_network_affiliation(
        view: &mut ExecutionView<'_, '_>,
        provider_id: &ProviderId,
        plan_id: &ProviderId,
        timestamp: Timestamp,
    ) -> Result<()> {
        match Self::v_get_provider(view, provider_id)? {
            Some(mut provider) => {
                provider.network_affiliations.retain(|p| p != plan_id);
                provider.updated_at = timestamp;
                let bytes = encode_provider(&provider).map_err(StateError::Storage)?;
                view.put(cf::HEALTHCARE_PROVIDERS, provider_key(provider_id), &bytes)
                    .map_err(StateError::Storage)?;
                Self::v_remove_from_network_index(view, provider_id, plan_id)?;
                Ok(())
            }
            None => Err(not_found("Provider", provider_id)),
        }
    }

    // ── Memberships, and the member index ───────────────────────────────────

    pub fn v_get_membership(
        view: &ExecutionView<'_, '_>,
        membership_id: &MembershipId,
    ) -> Result<Option<MembershipRecord>> {
        match view
            .get(cf::HEALTHCARE_MEMBERSHIPS, membership_key(membership_id))
            .map_err(StateError::Storage)?
        {
            Some(bytes) => Ok(Some(
                decode_membership(&bytes).map_err(StateError::Storage)?,
            )),
            None => Ok(None),
        }
    }

    pub fn v_membership_exists(
        view: &ExecutionView<'_, '_>,
        membership_id: &MembershipId,
    ) -> Result<bool> {
        view.contains(cf::HEALTHCARE_MEMBERSHIPS, membership_key(membership_id))
            .map_err(StateError::Storage)
    }

    /// The membership row AND its member-index entry.
    pub fn v_put_membership(
        view: &mut ExecutionView<'_, '_>,
        membership: &MembershipRecord,
    ) -> Result<()> {
        let bytes = encode_membership(membership).map_err(StateError::Storage)?;
        view.put(
            cf::HEALTHCARE_MEMBERSHIPS,
            membership_key(&membership.membership_id),
            &bytes,
        )
        .map_err(StateError::Storage)?;
        Self::v_add_to_member_index(
            view,
            &membership.member_nullifier,
            &membership.membership_id,
        )
    }

    pub fn v_get_member_membership_ids(
        view: &ExecutionView<'_, '_>,
        member_nullifier: &[u8; 32],
    ) -> Result<Vec<MembershipId>> {
        match view
            .get(
                cf::HEALTHCARE_MEMBER_INDEX,
                member_index_key(member_nullifier),
            )
            .map_err(StateError::Storage)?
        {
            Some(bytes) => decode_membership_ids(&bytes).map_err(StateError::Storage),
            None => Ok(Vec::new()),
        }
    }

    fn v_add_to_member_index(
        view: &mut ExecutionView<'_, '_>,
        member_nullifier: &[u8; 32],
        membership_id: &MembershipId,
    ) -> Result<()> {
        let mut ids = Self::v_get_member_membership_ids(view, member_nullifier)?;
        if ids.contains(membership_id) {
            return Ok(());
        }
        ids.push(*membership_id);
        let bytes = encode_membership_ids(&ids).map_err(StateError::Storage)?;
        view.put(
            cf::HEALTHCARE_MEMBER_INDEX,
            member_index_key(member_nullifier),
            &bytes,
        )
        .map_err(StateError::Storage)
    }

    pub fn v_update_membership_status(
        view: &mut ExecutionView<'_, '_>,
        membership_id: &MembershipId,
        status: MembershipStatus,
        timestamp: Timestamp,
    ) -> Result<()> {
        match Self::v_get_membership(view, membership_id)? {
            Some(mut membership) => {
                membership.status = status;
                membership.updated_at = timestamp;
                let bytes = encode_membership(&membership).map_err(StateError::Storage)?;
                view.put(
                    cf::HEALTHCARE_MEMBERSHIPS,
                    membership_key(membership_id),
                    &bytes,
                )
                .map_err(StateError::Storage)
            }
            None => Err(not_found("Membership", membership_id)),
        }
    }

    /// Renewal sets the expiry and forces the status back to `Active`, whatever
    /// it was -- including `Terminated`.
    pub fn v_renew_membership(
        view: &mut ExecutionView<'_, '_>,
        membership_id: &MembershipId,
        new_expiry: Timestamp,
        timestamp: Timestamp,
    ) -> Result<()> {
        match Self::v_get_membership(view, membership_id)? {
            Some(mut membership) => {
                membership.expiry = Some(new_expiry);
                membership.status = MembershipStatus::Active;
                membership.updated_at = timestamp;
                let bytes = encode_membership(&membership).map_err(StateError::Storage)?;
                view.put(
                    cf::HEALTHCARE_MEMBERSHIPS,
                    membership_key(membership_id),
                    &bytes,
                )
                .map_err(StateError::Storage)
            }
            None => Err(not_found("Membership", membership_id)),
        }
    }

    /// An accumulating list INSIDE the membership row rather than in an index
    /// family, with the same `contains` dedup and the same hazard: a second
    /// dependent in one block is only appended if it sees the first.
    pub fn v_add_dependent(
        view: &mut ExecutionView<'_, '_>,
        membership_id: &MembershipId,
        dependent_commitment: [u8; 32],
        timestamp: Timestamp,
    ) -> Result<()> {
        match Self::v_get_membership(view, membership_id)? {
            Some(mut membership) => {
                if !membership.dependents.contains(&dependent_commitment) {
                    membership.dependents.push(dependent_commitment);
                    membership.updated_at = timestamp;
                    let bytes = encode_membership(&membership).map_err(StateError::Storage)?;
                    view.put(
                        cf::HEALTHCARE_MEMBERSHIPS,
                        membership_key(membership_id),
                        &bytes,
                    )
                    .map_err(StateError::Storage)?;
                }
                Ok(())
            }
            None => Err(not_found("Membership", membership_id)),
        }
    }

    /// Unconditional, unlike the add: removing a dependent that was never there
    /// still rewrites the row and bumps `updated_at`.
    pub fn v_remove_dependent(
        view: &mut ExecutionView<'_, '_>,
        membership_id: &MembershipId,
        dependent_commitment: &[u8; 32],
        timestamp: Timestamp,
    ) -> Result<()> {
        match Self::v_get_membership(view, membership_id)? {
            Some(mut membership) => {
                membership.dependents.retain(|d| d != dependent_commitment);
                membership.updated_at = timestamp;
                let bytes = encode_membership(&membership).map_err(StateError::Storage)?;
                view.put(
                    cf::HEALTHCARE_MEMBERSHIPS,
                    membership_key(membership_id),
                    &bytes,
                )
                .map_err(StateError::Storage)
            }
            None => Err(not_found("Membership", membership_id)),
        }
    }

    // ── Consents, and the subject index ─────────────────────────────────────

    pub fn v_get_consent(
        view: &ExecutionView<'_, '_>,
        consent_id: &ConsentId,
    ) -> Result<Option<ConsentEnvelope>> {
        match view
            .get(cf::HEALTHCARE_CONSENTS, consent_key(consent_id))
            .map_err(StateError::Storage)?
        {
            Some(bytes) => Ok(Some(decode_consent(&bytes).map_err(StateError::Storage)?)),
            None => Ok(None),
        }
    }

    pub fn v_consent_exists(view: &ExecutionView<'_, '_>, consent_id: &ConsentId) -> Result<bool> {
        view.contains(cf::HEALTHCARE_CONSENTS, consent_key(consent_id))
            .map_err(StateError::Storage)
    }

    /// The consent row AND its subject-index entry.
    pub fn v_put_consent(
        view: &mut ExecutionView<'_, '_>,
        consent: &ConsentEnvelope,
    ) -> Result<()> {
        let bytes = encode_consent(consent).map_err(StateError::Storage)?;
        view.put(
            cf::HEALTHCARE_CONSENTS,
            consent_key(&consent.consent_id),
            &bytes,
        )
        .map_err(StateError::Storage)?;
        Self::v_add_to_subject_index(view, &consent.subject_nullifier, &consent.consent_id)
    }

    pub fn v_get_subject_consent_ids(
        view: &ExecutionView<'_, '_>,
        subject_nullifier: &[u8; 32],
    ) -> Result<Vec<ConsentId>> {
        match view
            .get(
                cf::HEALTHCARE_SUBJECT_CONSENT_INDEX,
                subject_consent_index_key(subject_nullifier),
            )
            .map_err(StateError::Storage)?
        {
            Some(bytes) => decode_consent_ids(&bytes).map_err(StateError::Storage),
            None => Ok(Vec::new()),
        }
    }

    fn v_add_to_subject_index(
        view: &mut ExecutionView<'_, '_>,
        subject_nullifier: &[u8; 32],
        consent_id: &ConsentId,
    ) -> Result<()> {
        let mut ids = Self::v_get_subject_consent_ids(view, subject_nullifier)?;
        if ids.contains(consent_id) {
            return Ok(());
        }
        ids.push(*consent_id);
        let bytes = encode_consent_ids(&ids).map_err(StateError::Storage)?;
        view.put(
            cf::HEALTHCARE_SUBJECT_CONSENT_INDEX,
            subject_consent_index_key(subject_nullifier),
            &bytes,
        )
        .map_err(StateError::Storage)
    }

    pub fn v_update_consent_status(
        view: &mut ExecutionView<'_, '_>,
        consent_id: &ConsentId,
        status: ConsentStatus,
        timestamp: Timestamp,
    ) -> Result<()> {
        match Self::v_get_consent(view, consent_id)? {
            Some(mut consent) => {
                consent.status = status;
                consent.updated_at = timestamp;
                let bytes = encode_consent(&consent).map_err(StateError::Storage)?;
                view.put(cf::HEALTHCARE_CONSENTS, consent_key(consent_id), &bytes)
                    .map_err(StateError::Storage)
            }
            None => Err(not_found("Consent", consent_id)),
        }
    }

    // ── Prescriptions, and the patient and prescriber indexes ───────────────

    pub fn v_get_prescription(
        view: &ExecutionView<'_, '_>,
        prescription_id: &PrescriptionId,
    ) -> Result<Option<Prescription>> {
        match view
            .get(
                cf::HEALTHCARE_PRESCRIPTIONS,
                prescription_key(prescription_id),
            )
            .map_err(StateError::Storage)?
        {
            Some(bytes) => Ok(Some(
                decode_prescription(&bytes).map_err(StateError::Storage)?,
            )),
            None => Ok(None),
        }
    }

    pub fn v_prescription_exists(
        view: &ExecutionView<'_, '_>,
        prescription_id: &PrescriptionId,
    ) -> Result<bool> {
        view.contains(
            cf::HEALTHCARE_PRESCRIPTIONS,
            prescription_key(prescription_id),
        )
        .map_err(StateError::Storage)
    }

    /// The prescription row AND BOTH of its index entries -- patient first,
    /// then prescriber, which is the committed twin's order and therefore the
    /// order a partial refusal can land between.
    pub fn v_put_prescription(
        view: &mut ExecutionView<'_, '_>,
        prescription: &Prescription,
    ) -> Result<()> {
        let bytes = encode_prescription(prescription).map_err(StateError::Storage)?;
        view.put(
            cf::HEALTHCARE_PRESCRIPTIONS,
            prescription_key(&prescription.prescription_id),
            &bytes,
        )
        .map_err(StateError::Storage)?;
        Self::v_add_to_patient_index(
            view,
            &prescription.patient_nullifier,
            &prescription.prescription_id,
        )?;
        Self::v_add_to_prescriber_index(
            view,
            &prescription.prescriber_provider_id,
            &prescription.prescription_id,
        )
    }

    pub fn v_get_patient_rx_ids(
        view: &ExecutionView<'_, '_>,
        patient_nullifier: &[u8; 32],
    ) -> Result<Vec<PrescriptionId>> {
        match view
            .get(
                cf::HEALTHCARE_PATIENT_RX_INDEX,
                patient_rx_index_key(patient_nullifier),
            )
            .map_err(StateError::Storage)?
        {
            Some(bytes) => decode_prescription_ids(&bytes).map_err(StateError::Storage),
            None => Ok(Vec::new()),
        }
    }

    pub fn v_get_prescriber_rx_ids(
        view: &ExecutionView<'_, '_>,
        prescriber_id: &ProviderId,
    ) -> Result<Vec<PrescriptionId>> {
        match view
            .get(
                cf::HEALTHCARE_PRESCRIBER_RX_INDEX,
                prescriber_rx_index_key(prescriber_id),
            )
            .map_err(StateError::Storage)?
        {
            Some(bytes) => decode_prescription_ids(&bytes).map_err(StateError::Storage),
            None => Ok(Vec::new()),
        }
    }

    fn v_add_to_patient_index(
        view: &mut ExecutionView<'_, '_>,
        patient_nullifier: &[u8; 32],
        prescription_id: &PrescriptionId,
    ) -> Result<()> {
        let mut ids = Self::v_get_patient_rx_ids(view, patient_nullifier)?;
        if ids.contains(prescription_id) {
            return Ok(());
        }
        ids.push(*prescription_id);
        let bytes = encode_prescription_ids(&ids).map_err(StateError::Storage)?;
        view.put(
            cf::HEALTHCARE_PATIENT_RX_INDEX,
            patient_rx_index_key(patient_nullifier),
            &bytes,
        )
        .map_err(StateError::Storage)
    }

    fn v_add_to_prescriber_index(
        view: &mut ExecutionView<'_, '_>,
        prescriber_id: &ProviderId,
        prescription_id: &PrescriptionId,
    ) -> Result<()> {
        let mut ids = Self::v_get_prescriber_rx_ids(view, prescriber_id)?;
        if ids.contains(prescription_id) {
            return Ok(());
        }
        ids.push(*prescription_id);
        let bytes = encode_prescription_ids(&ids).map_err(StateError::Storage)?;
        view.put(
            cf::HEALTHCARE_PRESCRIBER_RX_INDEX,
            prescriber_rx_index_key(prescriber_id),
            &bytes,
        )
        .map_err(StateError::Storage)
    }

    pub fn v_update_prescription_status(
        view: &mut ExecutionView<'_, '_>,
        prescription_id: &PrescriptionId,
        status: PrescriptionStatus,
        timestamp: Timestamp,
    ) -> Result<()> {
        match Self::v_get_prescription(view, prescription_id)? {
            Some(mut prescription) => {
                prescription.status = status;
                prescription.updated_at = timestamp;
                let bytes = encode_prescription(&prescription).map_err(StateError::Storage)?;
                view.put(
                    cf::HEALTHCARE_PRESCRIPTIONS,
                    prescription_key(prescription_id),
                    &bytes,
                )
                .map_err(StateError::Storage)
            }
            None => Err(not_found("Prescription", prescription_id)),
        }
    }

    /// Append a fill, decrement the refill counter, and derive the status from
    /// what is left. The whole point of the migration for this subsystem: the
    /// counter it decrements is the one this block already decremented.
    ///
    /// The committed twin's `InvalidData` guard is reproduced verbatim even
    /// though the executor's own guard reads the same row a moment earlier and
    /// makes this branch unreachable through dispatch -- the store is public
    /// and the candidate surface must not be the laxer of the two.
    pub fn v_record_fill(
        view: &mut ExecutionView<'_, '_>,
        prescription_id: &PrescriptionId,
        fill_commitment: [u8; 32],
        timestamp: Timestamp,
    ) -> Result<()> {
        match Self::v_get_prescription(view, prescription_id)? {
            Some(mut prescription) => {
                if prescription.refills_remaining == 0
                    && prescription.status != PrescriptionStatus::Active
                {
                    return Err(StateError::Storage(
                        sumchain_storage::StorageError::InvalidData(
                            "No refills remaining".to_string(),
                        ),
                    ));
                }
                prescription.fill_history.push(fill_commitment);
                if prescription.refills_remaining > 0 {
                    prescription.refills_remaining =
                        prescription.refills_remaining.saturating_sub(1);
                }
                prescription.status = if prescription.refills_remaining == 0 {
                    PrescriptionStatus::Filled
                } else {
                    PrescriptionStatus::PartiallyFilled
                };
                prescription.updated_at = timestamp;
                let bytes = encode_prescription(&prescription).map_err(StateError::Storage)?;
                view.put(
                    cf::HEALTHCARE_PRESCRIPTIONS,
                    prescription_key(prescription_id),
                    &bytes,
                )
                .map_err(StateError::Storage)
            }
            None => Err(not_found("Prescription", prescription_id)),
        }
    }

    /// Append a fill and nothing else -- no refill decrement, no status change.
    ///
    /// `PartialFillPrescription` calls this and then
    /// `v_update_prescription_status` on the SAME row in the SAME transaction,
    /// so the status write must read what this one staged or the fill is lost.
    pub fn v_add_fill_history(
        view: &mut ExecutionView<'_, '_>,
        prescription_id: &PrescriptionId,
        fill_commitment: [u8; 32],
        timestamp: Timestamp,
    ) -> Result<()> {
        match Self::v_get_prescription(view, prescription_id)? {
            Some(mut prescription) => {
                prescription.fill_history.push(fill_commitment);
                prescription.updated_at = timestamp;
                let bytes = encode_prescription(&prescription).map_err(StateError::Storage)?;
                view.put(
                    cf::HEALTHCARE_PRESCRIPTIONS,
                    prescription_key(prescription_id),
                    &bytes,
                )
                .map_err(StateError::Storage)
            }
            None => Err(not_found("Prescription", prescription_id)),
        }
    }

    // ── Proofs ──────────────────────────────────────────────────────────────

    pub fn v_healthcare_proof_exists(
        view: &ExecutionView<'_, '_>,
        proof_id: &ProofId,
    ) -> Result<bool> {
        view.contains(cf::HEALTHCARE_PROOFS, healthcare_proof_key(proof_id))
            .map_err(StateError::Storage)
    }

    pub fn v_put_healthcare_proof(
        view: &mut ExecutionView<'_, '_>,
        proof: &HealthcareProofEnvelope,
    ) -> Result<()> {
        let bytes = encode_healthcare_proof(proof).map_err(StateError::Storage)?;
        view.put(
            cf::HEALTHCARE_PROOFS,
            healthcare_proof_key(&proof.proof_id),
            &bytes,
        )
        .map_err(StateError::Storage)
    }
}
