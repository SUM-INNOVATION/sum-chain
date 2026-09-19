//! SRC-89X finance and banking, as this block's candidate sees it.
//!
//! The committed twins in `sumchain_storage::finance_store` stay for the RPC
//! server, which answers about the canonical chain.
//!
//! ## Why the reads move with the writes
//!
//! Every operation in this subsystem is a read-then-write. `RegisterIssuer`,
//! `CreateAddressProof`, `CreateBankStanding`, `CreateKycAttestation` and
//! `SubmitProof` refuse a duplicate; `UpdateIssuer`, `SuspendIssuer`,
//! `RevokeIssuer` and `ReactivateIssuer` require the issuer row and rewrite it;
//! every credential operation requires a REGISTERED, ACTIVE issuer of a class
//! permitted to issue that credential; every revocation requires the credential
//! and checks its issuer. All of those were committed reads, correct only
//! because the matching writes committed as they went. Two finance
//! transactions in one block would otherwise both pass a duplicate guard, or
//! the second would fail to find what the first registered.
//!
//! ## Four accumulating indexes, which is why the reads have to move
//!
//! `FINANCE_JURISDICTION_INDEX` holds a bincode `Vec<Address>`, and
//! `FINANCE_SUBJECT_ADDRESS_INDEX` / `FINANCE_SUBJECT_BANK_INDEX` /
//! `FINANCE_SUBJECT_KYC_INDEX` each hold a bincode `Vec<[u8; 32]>`. None of
//! them is a presence marker. Appending is a read-modify-write, so the read has
//! to see the candidate: two issuers registered into one jurisdiction in a
//! single block, or two credentials for one subject, would otherwise each write
//! a one-element list and the second would erase the first.
//!
//! ## Behaviours reproduced deliberately, not fixed
//!
//! * `v_update_issuer_status` rewrites ONLY the issuer row, leaving the
//!   jurisdiction index alone, exactly as the committed twin does. A revoked
//!   issuer therefore stays listed under its jurisdiction.
//! * `v_*_exists` uses a presence check, not a decode, exactly as
//!   `Database::contains` does. A corrupt row therefore reads as PRESENT rather
//!   than erroring — which is the opposite of the `v_get_*` readers, and is
//!   preserved rather than harmonised.
//! * `v_put_issuer` adds to the jurisdiction index only when the address is not
//!   already listed, so re-registering never duplicates an entry; the committed
//!   twin skips the write in that case too, rather than rewriting an identical
//!   list.
//!
//! Each is a pre-existing defect. Changing any of them here would be a
//! behaviour change smuggled into a migration, so they are preserved and
//! recorded for separate activation-gated work.

use sumchain_primitives::finance::{
    AccountStanding, AddressProof, BankStandingCredential, FinanceIssuerProfile,
    FinanceIssuerStatus, FinanceProofEnvelope, KycAttestation, KycStatus,
};
use sumchain_primitives::{Address, Timestamp};
use sumchain_storage::cf;
use sumchain_storage::exec_view::ExecutionView;
use sumchain_storage::finance_store::{
    address_proof_key, bank_standing_key, decode_address_proof, decode_addresses,
    decode_bank_standing, decode_id_list, decode_issuer, decode_kyc_attestation,
    encode_address_proof, encode_addresses, encode_bank_standing, encode_id_list, encode_issuer,
    encode_kyc_attestation, encode_proof, issuer_key, jurisdiction_index_key, kyc_attestation_key,
    proof_key, subject_address_index_key, subject_bank_index_key, subject_kyc_index_key,
    AddressProofId, BankStandingId, KycAttestationId, ProofId, SubjectRef,
};
use sumchain_storage::StorageError;

use crate::finance_executor::FinanceExecutor;
use crate::{Result, StateError};

impl FinanceExecutor {
    // ── Issuer profiles (SRC-891), and the jurisdiction index ───────────────

    pub fn v_get_issuer(
        view: &ExecutionView<'_, '_>,
        issuer_address: &Address,
    ) -> Result<Option<FinanceIssuerProfile>> {
        let issuer_row = view
            .get(cf::FINANCE_ISSUERS, issuer_key(issuer_address))
            .map_err(StateError::Storage)?;
        match issuer_row {
            Some(bytes) => Ok(Some(decode_issuer(&bytes).map_err(StateError::Storage)?)),
            None => Ok(None),
        }
    }

    /// Presence, NOT a decode -- the committed twin is `Database::contains`.
    /// See this module's header: a corrupt row reads as present here.
    pub fn v_issuer_exists(view: &ExecutionView<'_, '_>, issuer_address: &Address) -> Result<bool> {
        view.contains(cf::FINANCE_ISSUERS, issuer_key(issuer_address))
            .map_err(StateError::Storage)
    }

    /// The issuer row, and its address appended to the jurisdiction index.
    pub fn v_put_issuer(
        view: &mut ExecutionView<'_, '_>,
        issuer: &FinanceIssuerProfile,
    ) -> Result<()> {
        let issuer_bytes = encode_issuer(issuer).map_err(StateError::Storage)?;
        view.put(
            cf::FINANCE_ISSUERS,
            issuer_key(&issuer.issuer_address),
            &issuer_bytes,
        )
        .map_err(StateError::Storage)?;
        Self::v_add_to_jurisdiction_index(view, &issuer.jurisdiction_code, &issuer.issuer_address)
    }

    /// The issuer row ONLY. The jurisdiction index is not touched, exactly as
    /// the committed twin leaves it -- see this module's header.
    pub fn v_update_issuer_status(
        view: &mut ExecutionView<'_, '_>,
        issuer_address: &Address,
        status: FinanceIssuerStatus,
        timestamp: Timestamp,
    ) -> Result<()> {
        match Self::v_get_issuer(view, issuer_address)? {
            Some(mut issuer) => {
                issuer.status = status;
                issuer.updated_at = timestamp;
                let updated_bytes = encode_issuer(&issuer).map_err(StateError::Storage)?;
                view.put(
                    cf::FINANCE_ISSUERS,
                    issuer_key(issuer_address),
                    &updated_bytes,
                )
                .map_err(StateError::Storage)
            }
            None => Err(StateError::Storage(StorageError::NotFound(format!(
                "Issuer not found: {issuer_address:?}"
            )))),
        }
    }

    pub fn v_get_jurisdiction_issuer_addresses(
        view: &ExecutionView<'_, '_>,
        jurisdiction_code: &str,
    ) -> Result<Vec<Address>> {
        let jurisdiction_row = view
            .get(
                cf::FINANCE_JURISDICTION_INDEX,
                jurisdiction_index_key(jurisdiction_code),
            )
            .map_err(StateError::Storage)?;
        match jurisdiction_row {
            Some(bytes) => decode_addresses(&bytes).map_err(StateError::Storage),
            None => Ok(Vec::new()),
        }
    }

    /// The STORED LENGTH of the jurisdiction index row, without decoding it.
    ///
    /// ACTIVATION-AUDIT row AL-4. The bounded readers in
    /// `finance_executor.rs` compare this against
    /// [`crate::MAX_ACCUMULATING_ROW_BYTES`] and refuse, so a row that has
    /// already grown past the bound is never handed to `decode_addresses`. The
    /// same spelling `agreement_view.rs::v_party_index_row_len` uses, because
    /// it is the same rule.
    pub fn v_jurisdiction_index_row_len(
        view: &ExecutionView<'_, '_>,
        jurisdiction_code: &str,
    ) -> Result<Option<usize>> {
        Ok(view
            .get(
                cf::FINANCE_JURISDICTION_INDEX,
                jurisdiction_index_key(jurisdiction_code),
            )
            .map_err(StateError::Storage)?
            .map(|bytes| bytes.len()))
    }

    /// Read-modify-write on an accumulating `Vec<Address>`: a second issuer
    /// registered into the same jurisdiction in one block has to see the first.
    fn v_add_to_jurisdiction_index(
        view: &mut ExecutionView<'_, '_>,
        jurisdiction_code: &str,
        issuer_address: &Address,
    ) -> Result<()> {
        let mut addresses = Self::v_get_jurisdiction_issuer_addresses(view, jurisdiction_code)?;
        // The committed twin skips the write entirely when the address is
        // already listed, rather than rewriting an identical list.
        if addresses.contains(issuer_address) {
            return Ok(());
        }
        addresses.push(*issuer_address);
        let index_bytes = encode_addresses(&addresses).map_err(StateError::Storage)?;
        view.put(
            cf::FINANCE_JURISDICTION_INDEX,
            jurisdiction_index_key(jurisdiction_code),
            &index_bytes,
        )
        .map_err(StateError::Storage)
    }

    // ── Address proofs (SRC-892), and their subject index ───────────────────

    pub fn v_get_address_proof(
        view: &ExecutionView<'_, '_>,
        proof_id: &AddressProofId,
    ) -> Result<Option<AddressProof>> {
        let address_proof_row = view
            .get(cf::FINANCE_ADDRESS_PROOFS, address_proof_key(proof_id))
            .map_err(StateError::Storage)?;
        match address_proof_row {
            Some(bytes) => Ok(Some(
                decode_address_proof(&bytes).map_err(StateError::Storage)?,
            )),
            None => Ok(None),
        }
    }

    pub fn v_address_proof_exists(
        view: &ExecutionView<'_, '_>,
        proof_id: &AddressProofId,
    ) -> Result<bool> {
        view.contains(cf::FINANCE_ADDRESS_PROOFS, address_proof_key(proof_id))
            .map_err(StateError::Storage)
    }

    /// The proof row, and its id appended to the subject index.
    pub fn v_put_address_proof(
        view: &mut ExecutionView<'_, '_>,
        proof: &AddressProof,
    ) -> Result<()> {
        let address_proof_bytes = encode_address_proof(proof).map_err(StateError::Storage)?;
        view.put(
            cf::FINANCE_ADDRESS_PROOFS,
            address_proof_key(&proof.proof_id),
            &address_proof_bytes,
        )
        .map_err(StateError::Storage)?;
        Self::v_add_to_subject_address_index(view, &proof.subject_ref, &proof.proof_id)
    }

    pub fn v_revoke_address_proof(
        view: &mut ExecutionView<'_, '_>,
        proof_id: &AddressProofId,
        revocation_ref: [u8; 32],
        timestamp: Timestamp,
    ) -> Result<()> {
        match Self::v_get_address_proof(view, proof_id)? {
            Some(mut proof) => {
                proof.revocation_ref = Some(revocation_ref);
                proof.updated_at = timestamp;
                let revoked_bytes = encode_address_proof(&proof).map_err(StateError::Storage)?;
                view.put(
                    cf::FINANCE_ADDRESS_PROOFS,
                    address_proof_key(proof_id),
                    &revoked_bytes,
                )
                .map_err(StateError::Storage)
            }
            None => Err(StateError::Storage(StorageError::NotFound(format!(
                "Address proof not found: {proof_id:?}"
            )))),
        }
    }

    pub fn v_get_subject_address_proof_ids(
        view: &ExecutionView<'_, '_>,
        subject_ref: &SubjectRef,
    ) -> Result<Vec<AddressProofId>> {
        let subject_address_row = view
            .get(
                cf::FINANCE_SUBJECT_ADDRESS_INDEX,
                subject_address_index_key(subject_ref),
            )
            .map_err(StateError::Storage)?;
        match subject_address_row {
            Some(bytes) => decode_id_list(&bytes).map_err(StateError::Storage),
            None => Ok(Vec::new()),
        }
    }

    /// The stored length of the subject address-proof index row (AL-4), by the
    /// reasoning [`Self::v_jurisdiction_index_row_len`] gives.
    pub fn v_subject_address_index_row_len(
        view: &ExecutionView<'_, '_>,
        subject_ref: &SubjectRef,
    ) -> Result<Option<usize>> {
        Ok(view
            .get(
                cf::FINANCE_SUBJECT_ADDRESS_INDEX,
                subject_address_index_key(subject_ref),
            )
            .map_err(StateError::Storage)?
            .map(|bytes| bytes.len()))
    }

    fn v_add_to_subject_address_index(
        view: &mut ExecutionView<'_, '_>,
        subject_ref: &SubjectRef,
        proof_id: &AddressProofId,
    ) -> Result<()> {
        let mut ids = Self::v_get_subject_address_proof_ids(view, subject_ref)?;
        if ids.contains(proof_id) {
            return Ok(());
        }
        ids.push(*proof_id);
        let subject_address_bytes = encode_id_list(&ids).map_err(StateError::Storage)?;
        view.put(
            cf::FINANCE_SUBJECT_ADDRESS_INDEX,
            subject_address_index_key(subject_ref),
            &subject_address_bytes,
        )
        .map_err(StateError::Storage)
    }

    // ── Bank standing credentials (SRC-893), and their subject index ────────

    pub fn v_get_bank_standing(
        view: &ExecutionView<'_, '_>,
        credential_id: &BankStandingId,
    ) -> Result<Option<BankStandingCredential>> {
        let bank_standing_row = view
            .get(cf::FINANCE_BANK_STANDINGS, bank_standing_key(credential_id))
            .map_err(StateError::Storage)?;
        match bank_standing_row {
            Some(bytes) => Ok(Some(
                decode_bank_standing(&bytes).map_err(StateError::Storage)?,
            )),
            None => Ok(None),
        }
    }

    pub fn v_bank_standing_exists(
        view: &ExecutionView<'_, '_>,
        credential_id: &BankStandingId,
    ) -> Result<bool> {
        view.contains(cf::FINANCE_BANK_STANDINGS, bank_standing_key(credential_id))
            .map_err(StateError::Storage)
    }

    /// The credential row, and its id appended to the subject index.
    pub fn v_put_bank_standing(
        view: &mut ExecutionView<'_, '_>,
        credential: &BankStandingCredential,
    ) -> Result<()> {
        let bank_standing_bytes = encode_bank_standing(credential).map_err(StateError::Storage)?;
        view.put(
            cf::FINANCE_BANK_STANDINGS,
            bank_standing_key(&credential.credential_id),
            &bank_standing_bytes,
        )
        .map_err(StateError::Storage)?;
        Self::v_add_to_subject_bank_index(view, &credential.subject_ref, &credential.credential_id)
    }

    pub fn v_update_bank_standing(
        view: &mut ExecutionView<'_, '_>,
        credential_id: &BankStandingId,
        standing: AccountStanding,
        timestamp: Timestamp,
    ) -> Result<()> {
        match Self::v_get_bank_standing(view, credential_id)? {
            Some(mut credential) => {
                credential.standing = standing;
                credential.updated_at = timestamp;
                let updated_bytes =
                    encode_bank_standing(&credential).map_err(StateError::Storage)?;
                view.put(
                    cf::FINANCE_BANK_STANDINGS,
                    bank_standing_key(credential_id),
                    &updated_bytes,
                )
                .map_err(StateError::Storage)
            }
            None => Err(StateError::Storage(StorageError::NotFound(format!(
                "Bank standing credential not found: {credential_id:?}"
            )))),
        }
    }

    pub fn v_revoke_bank_standing(
        view: &mut ExecutionView<'_, '_>,
        credential_id: &BankStandingId,
        revocation_ref: [u8; 32],
        timestamp: Timestamp,
    ) -> Result<()> {
        match Self::v_get_bank_standing(view, credential_id)? {
            Some(mut credential) => {
                credential.revocation_ref = Some(revocation_ref);
                credential.updated_at = timestamp;
                let revoked_bytes =
                    encode_bank_standing(&credential).map_err(StateError::Storage)?;
                view.put(
                    cf::FINANCE_BANK_STANDINGS,
                    bank_standing_key(credential_id),
                    &revoked_bytes,
                )
                .map_err(StateError::Storage)
            }
            None => Err(StateError::Storage(StorageError::NotFound(format!(
                "Bank standing credential not found: {credential_id:?}"
            )))),
        }
    }

    pub fn v_get_subject_bank_standing_ids(
        view: &ExecutionView<'_, '_>,
        subject_ref: &SubjectRef,
    ) -> Result<Vec<BankStandingId>> {
        let subject_bank_row = view
            .get(
                cf::FINANCE_SUBJECT_BANK_INDEX,
                subject_bank_index_key(subject_ref),
            )
            .map_err(StateError::Storage)?;
        match subject_bank_row {
            Some(bytes) => decode_id_list(&bytes).map_err(StateError::Storage),
            None => Ok(Vec::new()),
        }
    }

    /// The stored length of the subject bank-standing index row (AL-4), by the
    /// reasoning [`Self::v_jurisdiction_index_row_len`] gives.
    pub fn v_subject_bank_index_row_len(
        view: &ExecutionView<'_, '_>,
        subject_ref: &SubjectRef,
    ) -> Result<Option<usize>> {
        Ok(view
            .get(
                cf::FINANCE_SUBJECT_BANK_INDEX,
                subject_bank_index_key(subject_ref),
            )
            .map_err(StateError::Storage)?
            .map(|bytes| bytes.len()))
    }

    fn v_add_to_subject_bank_index(
        view: &mut ExecutionView<'_, '_>,
        subject_ref: &SubjectRef,
        credential_id: &BankStandingId,
    ) -> Result<()> {
        let mut ids = Self::v_get_subject_bank_standing_ids(view, subject_ref)?;
        if ids.contains(credential_id) {
            return Ok(());
        }
        ids.push(*credential_id);
        let subject_bank_bytes = encode_id_list(&ids).map_err(StateError::Storage)?;
        view.put(
            cf::FINANCE_SUBJECT_BANK_INDEX,
            subject_bank_index_key(subject_ref),
            &subject_bank_bytes,
        )
        .map_err(StateError::Storage)
    }

    // ── KYC attestations (SRC-894), and their subject index ─────────────────

    pub fn v_get_kyc_attestation(
        view: &ExecutionView<'_, '_>,
        attestation_id: &KycAttestationId,
    ) -> Result<Option<KycAttestation>> {
        let kyc_attestation_row = view
            .get(
                cf::FINANCE_KYC_ATTESTATIONS,
                kyc_attestation_key(attestation_id),
            )
            .map_err(StateError::Storage)?;
        match kyc_attestation_row {
            Some(bytes) => Ok(Some(
                decode_kyc_attestation(&bytes).map_err(StateError::Storage)?,
            )),
            None => Ok(None),
        }
    }

    pub fn v_kyc_attestation_exists(
        view: &ExecutionView<'_, '_>,
        attestation_id: &KycAttestationId,
    ) -> Result<bool> {
        view.contains(
            cf::FINANCE_KYC_ATTESTATIONS,
            kyc_attestation_key(attestation_id),
        )
        .map_err(StateError::Storage)
    }

    /// The attestation row, and its id appended to the subject index.
    pub fn v_put_kyc_attestation(
        view: &mut ExecutionView<'_, '_>,
        attestation: &KycAttestation,
    ) -> Result<()> {
        let kyc_attestation_bytes =
            encode_kyc_attestation(attestation).map_err(StateError::Storage)?;
        view.put(
            cf::FINANCE_KYC_ATTESTATIONS,
            kyc_attestation_key(&attestation.attestation_id),
            &kyc_attestation_bytes,
        )
        .map_err(StateError::Storage)?;
        Self::v_add_to_subject_kyc_index(
            view,
            &attestation.subject_ref,
            &attestation.attestation_id,
        )
    }

    pub fn v_update_kyc_status(
        view: &mut ExecutionView<'_, '_>,
        attestation_id: &KycAttestationId,
        status: KycStatus,
        timestamp: Timestamp,
    ) -> Result<()> {
        match Self::v_get_kyc_attestation(view, attestation_id)? {
            Some(mut attestation) => {
                attestation.status = status;
                attestation.updated_at = timestamp;
                let updated_bytes =
                    encode_kyc_attestation(&attestation).map_err(StateError::Storage)?;
                view.put(
                    cf::FINANCE_KYC_ATTESTATIONS,
                    kyc_attestation_key(attestation_id),
                    &updated_bytes,
                )
                .map_err(StateError::Storage)
            }
            None => Err(StateError::Storage(StorageError::NotFound(format!(
                "KYC attestation not found: {attestation_id:?}"
            )))),
        }
    }

    /// Revocation sets BOTH the status and the revocation ref, which is what
    /// makes it different from `v_update_kyc_status`.
    pub fn v_revoke_kyc_attestation(
        view: &mut ExecutionView<'_, '_>,
        attestation_id: &KycAttestationId,
        revocation_ref: [u8; 32],
        timestamp: Timestamp,
    ) -> Result<()> {
        match Self::v_get_kyc_attestation(view, attestation_id)? {
            Some(mut attestation) => {
                attestation.status = KycStatus::Revoked;
                attestation.revocation_ref = Some(revocation_ref);
                attestation.updated_at = timestamp;
                let revoked_bytes =
                    encode_kyc_attestation(&attestation).map_err(StateError::Storage)?;
                view.put(
                    cf::FINANCE_KYC_ATTESTATIONS,
                    kyc_attestation_key(attestation_id),
                    &revoked_bytes,
                )
                .map_err(StateError::Storage)
            }
            None => Err(StateError::Storage(StorageError::NotFound(format!(
                "KYC attestation not found: {attestation_id:?}"
            )))),
        }
    }

    pub fn v_get_subject_kyc_ids(
        view: &ExecutionView<'_, '_>,
        subject_ref: &SubjectRef,
    ) -> Result<Vec<KycAttestationId>> {
        let subject_kyc_row = view
            .get(
                cf::FINANCE_SUBJECT_KYC_INDEX,
                subject_kyc_index_key(subject_ref),
            )
            .map_err(StateError::Storage)?;
        match subject_kyc_row {
            Some(bytes) => decode_id_list(&bytes).map_err(StateError::Storage),
            None => Ok(Vec::new()),
        }
    }

    /// The stored length of the subject KYC index row (AL-4), by the reasoning
    /// [`Self::v_jurisdiction_index_row_len`] gives.
    pub fn v_subject_kyc_index_row_len(
        view: &ExecutionView<'_, '_>,
        subject_ref: &SubjectRef,
    ) -> Result<Option<usize>> {
        Ok(view
            .get(
                cf::FINANCE_SUBJECT_KYC_INDEX,
                subject_kyc_index_key(subject_ref),
            )
            .map_err(StateError::Storage)?
            .map(|bytes| bytes.len()))
    }

    fn v_add_to_subject_kyc_index(
        view: &mut ExecutionView<'_, '_>,
        subject_ref: &SubjectRef,
        attestation_id: &KycAttestationId,
    ) -> Result<()> {
        let mut ids = Self::v_get_subject_kyc_ids(view, subject_ref)?;
        if ids.contains(attestation_id) {
            return Ok(());
        }
        ids.push(*attestation_id);
        let subject_kyc_bytes = encode_id_list(&ids).map_err(StateError::Storage)?;
        view.put(
            cf::FINANCE_SUBJECT_KYC_INDEX,
            subject_kyc_index_key(subject_ref),
            &subject_kyc_bytes,
        )
        .map_err(StateError::Storage)
    }

    // ── Proof envelopes (SRC-895) ───────────────────────────────────────────

    /// Presence, NOT a decode. `SubmitProof` is the only operation that reads
    /// this family and it reads it exactly this way, so nothing on the
    /// execution path ever decodes a `FinanceProofEnvelope`.
    pub fn v_proof_exists(view: &ExecutionView<'_, '_>, proof_id: &ProofId) -> Result<bool> {
        view.contains(cf::FINANCE_PROOFS, proof_key(proof_id))
            .map_err(StateError::Storage)
    }

    pub fn v_put_proof(
        view: &mut ExecutionView<'_, '_>,
        proof: &FinanceProofEnvelope,
    ) -> Result<()> {
        let proof_bytes = encode_proof(proof).map_err(StateError::Storage)?;
        view.put(cf::FINANCE_PROOFS, proof_key(&proof.proof_id), &proof_bytes)
            .map_err(StateError::Storage)
    }
}
