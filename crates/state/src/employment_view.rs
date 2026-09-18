//! SRC-88X employment and HR, as this block's candidate sees it.
//!
//! The committed twins in `sumchain_storage::employment_store` stay for
//! anything that answers about the canonical chain.
//!
//! ## Why the reads move with the writes
//!
//! Every employment operation is a read-then-write, and every one of those
//! reads was a COMMITTED read — correct only because the matching writes
//! committed as they went:
//!
//! * `RegisterIssuer`, `CreateEmployment`, `CreateIncomeAttestation` and
//!   `SubmitProof` refuse a duplicate. Against the parent both halves of a
//!   same-block pair pass the guard, and the second silently overwrites the
//!   first.
//! * `UpdateIssuer`, `SuspendIssuer`, `RevokeIssuer` and `ReactivateIssuer`
//!   require the issuer row, and `ReactivateIssuer` requires it to be
//!   SUSPENDED — a status an earlier transaction in the same block may have
//!   just set.
//! * `CreateEmployment` and `CreateIncomeAttestation` require an ACTIVE issuer,
//!   so a registration earlier in the block has to be visible.
//! * `UpdateEmployment`, `SuspendEmployment`, `EndEmployment`,
//!   `RevokeEmployment` and `RevokeIncomeAttestation` read the row to check the
//!   issuer, then rewrite it.
//! * The five index families hold accumulating `Vec<[u8; 32]>` values, so
//!   appending is a read-modify-write. A second credential for one employee in
//!   one block must see the first one's id, or it replaces the list with a
//!   single-element one and the first credential drops out of the index.
//!
//! ## One write site per family
//!
//! Each of the nine families is written in exactly one function here, and each
//! of those takes the key explicitly rather than deriving it from the value.
//! That is not tidiness: the committed twins key `update_status` and `revoke`
//! by the id the CALLER passed, while `put` keys by the id inside the value.
//! Those agree for every row the executor can produce, and deriving the key
//! from the value anyway would be a quiet behaviour change on rows where they
//! do not.
//!
//! ## Behaviours reproduced deliberately, not fixed
//!
//! * `v_issuer_exists`, `v_credential_exists`, `v_attestation_exists` and
//!   `v_proof_exists` test for PRESENCE without decoding, exactly as
//!   `Database::contains` does. A corrupt row therefore reads as present, and
//!   the duplicate guards that use them refuse on it rather than erroring.
//!   The guards that use `v_get_*` do error. Both behaviours are the committed
//!   ones and both are pinned by tests.
//! * `v_update_credential_status` and `v_revoke_credential` rewrite ONLY the
//!   credential row. They do not touch the three indexes, so an index built at
//!   creation keeps pointing at a credential whose status has since changed —
//!   including to `Ended`. The committed twins do the same; changing it here
//!   would be a behaviour change smuggled into a migration.
//! * `v_revoke_attestation` sets `revocation_ref` and `updated_at` and leaves
//!   the rest, including the two income indexes.

use sumchain_primitives::employment::{
    EmployerRef, EmploymentCredential, EmploymentId, EmploymentIssuerProfile,
    EmploymentProofEnvelope, EmploymentStatus, IncomeAttestation, IncomeAttestationId,
    IssuerStatus, ProofId, SubjectRef,
};
use sumchain_primitives::{Address, Timestamp};
use sumchain_storage::cf;
use sumchain_storage::employment_store::{
    credential_key, decode_attestation, decode_credential, decode_id_list, decode_issuer,
    decode_proof, employee_address_index_key, employee_index_key, employer_index_key,
    encode_attestation, encode_credential, encode_id_list, encode_issuer, encode_proof,
    income_attestation_key, income_holder_address_index_key, issuer_key, proof_key,
    subject_income_index_key,
};
use sumchain_storage::exec_view::ExecutionView;
use sumchain_storage::StorageError;

use crate::employment_executor::EmploymentExecutor;
use crate::{Result, StateError};

impl EmploymentExecutor {
    // ── Issuer profiles (SRC-881) ───────────────────────────────────────────

    pub fn v_get_issuer(
        view: &ExecutionView<'_, '_>,
        issuer_address: &Address,
    ) -> Result<Option<EmploymentIssuerProfile>> {
        match view
            .get(cf::EMPLOYMENT_ISSUERS, issuer_key(issuer_address))
            .map_err(StateError::Storage)?
        {
            Some(bytes) => Ok(Some(decode_issuer(&bytes).map_err(StateError::Storage)?)),
            None => Ok(None),
        }
    }

    /// Presence, without decoding — the committed twin is `Database::contains`.
    pub fn v_issuer_exists(view: &ExecutionView<'_, '_>, issuer_address: &Address) -> Result<bool> {
        view.contains(cf::EMPLOYMENT_ISSUERS, issuer_key(issuer_address))
            .map_err(StateError::Storage)
    }

    pub fn v_put_issuer(
        view: &mut ExecutionView<'_, '_>,
        issuer: &EmploymentIssuerProfile,
    ) -> Result<()> {
        Self::v_write_issuer_row(view, &issuer.issuer_address, issuer)
    }

    /// The only write to `EMPLOYMENT_ISSUERS`.
    fn v_write_issuer_row(
        view: &mut ExecutionView<'_, '_>,
        issuer_address: &Address,
        issuer: &EmploymentIssuerProfile,
    ) -> Result<()> {
        let bytes = encode_issuer(issuer).map_err(StateError::Storage)?;
        view.put(cf::EMPLOYMENT_ISSUERS, issuer_key(issuer_address), &bytes)
            .map_err(StateError::Storage)
    }

    /// Read, set status and timestamp, write back. A missing row is an ERROR,
    /// not a no-op: the committed twin returns `NotFound`, and every caller
    /// propagates it.
    pub fn v_update_issuer_status(
        view: &mut ExecutionView<'_, '_>,
        issuer_address: &Address,
        status: IssuerStatus,
        timestamp: Timestamp,
    ) -> Result<()> {
        match Self::v_get_issuer(view, issuer_address)? {
            Some(mut issuer) => {
                issuer.status = status;
                issuer.updated_at = timestamp;
                Self::v_write_issuer_row(view, issuer_address, &issuer)
            }
            None => Err(StateError::Storage(StorageError::NotFound(format!(
                "Issuer not found: {issuer_address:?}"
            )))),
        }
    }

    // ── Employment credentials (SRC-882) ────────────────────────────────────

    pub fn v_get_credential(
        view: &ExecutionView<'_, '_>,
        employment_id: &EmploymentId,
    ) -> Result<Option<EmploymentCredential>> {
        match view
            .get(cf::EMPLOYMENT_CREDENTIALS, credential_key(employment_id))
            .map_err(StateError::Storage)?
        {
            Some(bytes) => Ok(Some(
                decode_credential(&bytes).map_err(StateError::Storage)?,
            )),
            None => Ok(None),
        }
    }

    pub fn v_credential_exists(
        view: &ExecutionView<'_, '_>,
        employment_id: &EmploymentId,
    ) -> Result<bool> {
        view.contains(cf::EMPLOYMENT_CREDENTIALS, credential_key(employment_id))
            .map_err(StateError::Storage)
    }

    /// The credential row, then its three index entries, in that order.
    ///
    /// The order is load-bearing under the write-set ceiling: a refusal between
    /// them leaves the row staged and the indexes not, which is the partial the
    /// committed path would also produce. Reversing it would stage an index
    /// pointing at a credential that does not exist.
    pub fn v_put_credential(
        view: &mut ExecutionView<'_, '_>,
        credential: &EmploymentCredential,
    ) -> Result<()> {
        Self::v_write_credential_row(view, &credential.employment_id, credential)?;
        Self::v_add_to_employee_index(view, &credential.employee_ref, &credential.employment_id)?;
        Self::v_add_to_employee_address_index(
            view,
            &credential.employee_address,
            &credential.employment_id,
        )?;
        Self::v_add_to_employer_index(view, &credential.employer_ref, &credential.employment_id)
    }

    /// The only write to `EMPLOYMENT_CREDENTIALS`.
    fn v_write_credential_row(
        view: &mut ExecutionView<'_, '_>,
        employment_id: &EmploymentId,
        credential: &EmploymentCredential,
    ) -> Result<()> {
        let bytes = encode_credential(credential).map_err(StateError::Storage)?;
        view.put(
            cf::EMPLOYMENT_CREDENTIALS,
            credential_key(employment_id),
            &bytes,
        )
        .map_err(StateError::Storage)
    }

    /// ONLY the credential row. The three indexes are left as creation built
    /// them — see this module's header.
    pub fn v_update_credential_status(
        view: &mut ExecutionView<'_, '_>,
        employment_id: &EmploymentId,
        status: EmploymentStatus,
        timestamp: Timestamp,
    ) -> Result<()> {
        match Self::v_get_credential(view, employment_id)? {
            Some(mut credential) => {
                credential.status = status;
                credential.updated_at = timestamp;
                Self::v_write_credential_row(view, employment_id, &credential)
            }
            None => Err(StateError::Storage(StorageError::NotFound(format!(
                "Employment credential not found: {employment_id:?}"
            )))),
        }
    }

    /// Ends the credential and records the revocation reference. Also only the
    /// row.
    pub fn v_revoke_credential(
        view: &mut ExecutionView<'_, '_>,
        employment_id: &EmploymentId,
        revocation_ref: [u8; 32],
        timestamp: Timestamp,
    ) -> Result<()> {
        match Self::v_get_credential(view, employment_id)? {
            Some(mut credential) => {
                credential.status = EmploymentStatus::Ended;
                credential.revocation_ref = Some(revocation_ref);
                credential.updated_at = timestamp;
                Self::v_write_credential_row(view, employment_id, &credential)
            }
            None => Err(StateError::Storage(StorageError::NotFound(format!(
                "Employment credential not found: {employment_id:?}"
            )))),
        }
    }

    pub fn v_get_employee_credential_ids(
        view: &ExecutionView<'_, '_>,
        employee_ref: &SubjectRef,
    ) -> Result<Vec<EmploymentId>> {
        match view
            .get(
                cf::EMPLOYMENT_EMPLOYEE_INDEX,
                employee_index_key(employee_ref),
            )
            .map_err(StateError::Storage)?
        {
            Some(bytes) => decode_id_list(&bytes).map_err(StateError::Storage),
            None => Ok(Vec::new()),
        }
    }

    fn v_add_to_employee_index(
        view: &mut ExecutionView<'_, '_>,
        employee_ref: &SubjectRef,
        employment_id: &EmploymentId,
    ) -> Result<()> {
        let mut ids = Self::v_get_employee_credential_ids(view, employee_ref)?;
        // The committed twin skips the write entirely when the id is already
        // there rather than rewriting an identical list. Same here: a rewrite
        // would cost candidate bytes for no change.
        if ids.contains(employment_id) {
            return Ok(());
        }
        ids.push(*employment_id);
        let bytes = encode_id_list(&ids).map_err(StateError::Storage)?;
        view.put(
            cf::EMPLOYMENT_EMPLOYEE_INDEX,
            employee_index_key(employee_ref),
            &bytes,
        )
        .map_err(StateError::Storage)
    }

    pub fn v_get_employee_address_credential_ids(
        view: &ExecutionView<'_, '_>,
        employee_address: &Address,
    ) -> Result<Vec<EmploymentId>> {
        match view
            .get(
                cf::EMPLOYMENT_EMPLOYEE_ADDRESS_INDEX,
                employee_address_index_key(employee_address),
            )
            .map_err(StateError::Storage)?
        {
            Some(bytes) => decode_id_list(&bytes).map_err(StateError::Storage),
            None => Ok(Vec::new()),
        }
    }

    fn v_add_to_employee_address_index(
        view: &mut ExecutionView<'_, '_>,
        employee_address: &Address,
        employment_id: &EmploymentId,
    ) -> Result<()> {
        let mut ids = Self::v_get_employee_address_credential_ids(view, employee_address)?;
        if ids.contains(employment_id) {
            return Ok(());
        }
        ids.push(*employment_id);
        let bytes = encode_id_list(&ids).map_err(StateError::Storage)?;
        view.put(
            cf::EMPLOYMENT_EMPLOYEE_ADDRESS_INDEX,
            employee_address_index_key(employee_address),
            &bytes,
        )
        .map_err(StateError::Storage)
    }

    pub fn v_get_employer_credential_ids(
        view: &ExecutionView<'_, '_>,
        employer_ref: &EmployerRef,
    ) -> Result<Vec<EmploymentId>> {
        match view
            .get(
                cf::EMPLOYMENT_EMPLOYER_INDEX,
                employer_index_key(employer_ref),
            )
            .map_err(StateError::Storage)?
        {
            Some(bytes) => decode_id_list(&bytes).map_err(StateError::Storage),
            None => Ok(Vec::new()),
        }
    }

    fn v_add_to_employer_index(
        view: &mut ExecutionView<'_, '_>,
        employer_ref: &EmployerRef,
        employment_id: &EmploymentId,
    ) -> Result<()> {
        let mut ids = Self::v_get_employer_credential_ids(view, employer_ref)?;
        if ids.contains(employment_id) {
            return Ok(());
        }
        ids.push(*employment_id);
        let bytes = encode_id_list(&ids).map_err(StateError::Storage)?;
        view.put(
            cf::EMPLOYMENT_EMPLOYER_INDEX,
            employer_index_key(employer_ref),
            &bytes,
        )
        .map_err(StateError::Storage)
    }

    // ── Income attestations (SRC-883) ───────────────────────────────────────

    pub fn v_get_attestation(
        view: &ExecutionView<'_, '_>,
        attestation_id: &IncomeAttestationId,
    ) -> Result<Option<IncomeAttestation>> {
        match view
            .get(
                cf::EMPLOYMENT_INCOME_ATTESTATIONS,
                income_attestation_key(attestation_id),
            )
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
        attestation_id: &IncomeAttestationId,
    ) -> Result<bool> {
        view.contains(
            cf::EMPLOYMENT_INCOME_ATTESTATIONS,
            income_attestation_key(attestation_id),
        )
        .map_err(StateError::Storage)
    }

    /// The attestation row, then the subject index, then the holder-address
    /// index — the committed order, and the one the ceiling sweep pins.
    pub fn v_put_attestation(
        view: &mut ExecutionView<'_, '_>,
        attestation: &IncomeAttestation,
    ) -> Result<()> {
        Self::v_write_attestation_row(view, &attestation.attestation_id, attestation)?;
        Self::v_add_to_subject_income_index(
            view,
            &attestation.subject_ref,
            &attestation.attestation_id,
        )?;
        Self::v_add_to_holder_address_index(
            view,
            &attestation.holder_address,
            &attestation.attestation_id,
        )
    }

    /// The only write to `EMPLOYMENT_INCOME_ATTESTATIONS`.
    fn v_write_attestation_row(
        view: &mut ExecutionView<'_, '_>,
        attestation_id: &IncomeAttestationId,
        attestation: &IncomeAttestation,
    ) -> Result<()> {
        let bytes = encode_attestation(attestation).map_err(StateError::Storage)?;
        view.put(
            cf::EMPLOYMENT_INCOME_ATTESTATIONS,
            income_attestation_key(attestation_id),
            &bytes,
        )
        .map_err(StateError::Storage)
    }

    /// Records the revocation reference and the timestamp. The two income
    /// indexes are untouched, as on the committed path.
    pub fn v_revoke_attestation(
        view: &mut ExecutionView<'_, '_>,
        attestation_id: &IncomeAttestationId,
        revocation_ref: [u8; 32],
        timestamp: Timestamp,
    ) -> Result<()> {
        match Self::v_get_attestation(view, attestation_id)? {
            Some(mut attestation) => {
                attestation.revocation_ref = Some(revocation_ref);
                attestation.updated_at = timestamp;
                Self::v_write_attestation_row(view, attestation_id, &attestation)
            }
            None => Err(StateError::Storage(StorageError::NotFound(format!(
                "Income attestation not found: {attestation_id:?}"
            )))),
        }
    }

    pub fn v_get_subject_attestation_ids(
        view: &ExecutionView<'_, '_>,
        subject_ref: &SubjectRef,
    ) -> Result<Vec<IncomeAttestationId>> {
        match view
            .get(
                cf::EMPLOYMENT_SUBJECT_INCOME_INDEX,
                subject_income_index_key(subject_ref),
            )
            .map_err(StateError::Storage)?
        {
            Some(bytes) => decode_id_list(&bytes).map_err(StateError::Storage),
            None => Ok(Vec::new()),
        }
    }

    fn v_add_to_subject_income_index(
        view: &mut ExecutionView<'_, '_>,
        subject_ref: &SubjectRef,
        attestation_id: &IncomeAttestationId,
    ) -> Result<()> {
        let mut ids = Self::v_get_subject_attestation_ids(view, subject_ref)?;
        if ids.contains(attestation_id) {
            return Ok(());
        }
        ids.push(*attestation_id);
        let bytes = encode_id_list(&ids).map_err(StateError::Storage)?;
        view.put(
            cf::EMPLOYMENT_SUBJECT_INCOME_INDEX,
            subject_income_index_key(subject_ref),
            &bytes,
        )
        .map_err(StateError::Storage)
    }

    pub fn v_get_holder_address_attestation_ids(
        view: &ExecutionView<'_, '_>,
        holder_address: &Address,
    ) -> Result<Vec<IncomeAttestationId>> {
        match view
            .get(
                cf::EMPLOYMENT_INCOME_HOLDER_ADDRESS_INDEX,
                income_holder_address_index_key(holder_address),
            )
            .map_err(StateError::Storage)?
        {
            Some(bytes) => decode_id_list(&bytes).map_err(StateError::Storage),
            None => Ok(Vec::new()),
        }
    }

    fn v_add_to_holder_address_index(
        view: &mut ExecutionView<'_, '_>,
        holder_address: &Address,
        attestation_id: &IncomeAttestationId,
    ) -> Result<()> {
        let mut ids = Self::v_get_holder_address_attestation_ids(view, holder_address)?;
        if ids.contains(attestation_id) {
            return Ok(());
        }
        ids.push(*attestation_id);
        let bytes = encode_id_list(&ids).map_err(StateError::Storage)?;
        view.put(
            cf::EMPLOYMENT_INCOME_HOLDER_ADDRESS_INDEX,
            income_holder_address_index_key(holder_address),
            &bytes,
        )
        .map_err(StateError::Storage)
    }

    // ── Proof envelopes (SRC-885) ───────────────────────────────────────────

    pub fn v_get_proof(
        view: &ExecutionView<'_, '_>,
        proof_id: &ProofId,
    ) -> Result<Option<EmploymentProofEnvelope>> {
        match view
            .get(cf::EMPLOYMENT_PROOFS, proof_key(proof_id))
            .map_err(StateError::Storage)?
        {
            Some(bytes) => Ok(Some(decode_proof(&bytes).map_err(StateError::Storage)?)),
            None => Ok(None),
        }
    }

    pub fn v_proof_exists(view: &ExecutionView<'_, '_>, proof_id: &ProofId) -> Result<bool> {
        view.contains(cf::EMPLOYMENT_PROOFS, proof_key(proof_id))
            .map_err(StateError::Storage)
    }

    /// The only write to `EMPLOYMENT_PROOFS`. A proof has no index of its own.
    pub fn v_put_proof(
        view: &mut ExecutionView<'_, '_>,
        proof: &EmploymentProofEnvelope,
    ) -> Result<()> {
        let bytes = encode_proof(proof).map_err(StateError::Storage)?;
        view.put(cf::EMPLOYMENT_PROOFS, proof_key(&proof.proof_id), &bytes)
            .map_err(StateError::Storage)
    }
}
