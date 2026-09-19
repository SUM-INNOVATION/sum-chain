//! SRC-88X Employment & HR Storage
//!
//! Storage layer for:
//! - SRC-881: Employer & Payroll Issuer Profile
//! - SRC-882: Employment Relationship Credential
//! - SRC-883: Income / Payroll Attestation
//! - SRC-885: 88X Proof Profiles

use sumchain_primitives::{
    employment::{
        EmploymentCredential, EmploymentEvent, EmploymentIssuerProfile, EmploymentProofEnvelope,
        EmploymentStatus, IncomeAttestation, IssuerStatus,
    },
    Address, BlockHeight, Timestamp,
};

use crate::db::{cf, Database};
use crate::page::{paged_resolve, paged_scan, PageSpec};
use crate::{Result, StorageError};

// Type aliases for clarity
pub type EmploymentId = [u8; 32];
pub type IncomeAttestationId = [u8; 32];
pub type ProofId = [u8; 32];
pub type SubjectRef = [u8; 32];
pub type EmployerRef = [u8; 32];

// =============================================================================
// Shared key layout and codec
// =============================================================================
//
// One builder per row and one codec per value type, called by the committed
// stores below and by the candidate surface in
// `sumchain_state::employment_view`. Nine of the ten families here are
// reachable from block execution; the tenth, the event log, is not -- it shares
// the discipline anyway, so that no row in this file is encoded in two places
// and no key in it is spelled twice.
//
// Every value is bincode. Every key is an identifier's own bytes, unprefixed:
// a 20-byte address for the three address-keyed families, a 32-byte id or
// commitment for the rest. The one exception is the event key, which is
// height||index big-endian so that the height is a usable scan prefix.
//
// Five families share the SAME value type -- a bincode `Vec<[u8; 32]>` -- and
// three share the same key shape. They are deliberately given separate
// builders anyway: same shape is not the same row, and one of them could
// change without the others.

/// Issuer profiles are keyed by the issuer's address.
pub fn issuer_key(issuer_address: &Address) -> &[u8] {
    issuer_address.as_bytes()
}

/// Employment credentials are keyed by employment id.
pub fn credential_key(employment_id: &EmploymentId) -> &[u8] {
    employment_id
}

/// The employee index is keyed by the employee COMMITMENT (`employee_ref`),
/// and its VALUE is an accumulating `Vec<EmploymentId>`, not a presence marker.
pub fn employee_index_key(employee_ref: &SubjectRef) -> &[u8] {
    employee_ref
}

/// The employee-address index is keyed by the employee's WALLET address --
/// the same shape as [`issuer_key`], a different row.
pub fn employee_address_index_key(employee_address: &Address) -> &[u8] {
    employee_address.as_bytes()
}

/// The employer index is keyed by the employer commitment (`employer_ref`).
pub fn employer_index_key(employer_ref: &EmployerRef) -> &[u8] {
    employer_ref
}

/// Income attestations are keyed by attestation id.
pub fn income_attestation_key(attestation_id: &IncomeAttestationId) -> &[u8] {
    attestation_id
}

/// The subject income index is keyed by the subject commitment.
pub fn subject_income_index_key(subject_ref: &SubjectRef) -> &[u8] {
    subject_ref
}

/// The income holder-address index is keyed by the holder's WALLET address.
pub fn income_holder_address_index_key(holder_address: &Address) -> &[u8] {
    holder_address.as_bytes()
}

/// Proof envelopes are keyed by proof id.
pub fn proof_key(proof_id: &ProofId) -> &[u8] {
    proof_id
}

/// Events are keyed by height then index, both big-endian, so that
/// [`event_height_prefix`] selects exactly one block.
pub fn event_key(height: BlockHeight, index: u32) -> [u8; 12] {
    let mut key = [0u8; 12];
    key[..8].copy_from_slice(&height.to_be_bytes());
    key[8..].copy_from_slice(&index.to_be_bytes());
    key
}

/// The prefix every [`event_key`] at `height` begins with.
pub fn event_height_prefix(height: BlockHeight) -> [u8; 8] {
    height.to_be_bytes()
}

pub fn encode_issuer(issuer: &EmploymentIssuerProfile) -> Result<Vec<u8>> {
    bincode::serialize(issuer).map_err(|e| StorageError::Serialization(e.to_string()))
}

pub fn decode_issuer(bytes: &[u8]) -> Result<EmploymentIssuerProfile> {
    bincode::deserialize(bytes).map_err(|e| StorageError::Serialization(e.to_string()))
}

pub fn encode_credential(credential: &EmploymentCredential) -> Result<Vec<u8>> {
    bincode::serialize(credential).map_err(|e| StorageError::Serialization(e.to_string()))
}

pub fn decode_credential(bytes: &[u8]) -> Result<EmploymentCredential> {
    bincode::deserialize(bytes).map_err(|e| StorageError::Serialization(e.to_string()))
}

pub fn encode_attestation(attestation: &IncomeAttestation) -> Result<Vec<u8>> {
    bincode::serialize(attestation).map_err(|e| StorageError::Serialization(e.to_string()))
}

pub fn decode_attestation(bytes: &[u8]) -> Result<IncomeAttestation> {
    bincode::deserialize(bytes).map_err(|e| StorageError::Serialization(e.to_string()))
}

pub fn encode_proof(proof: &EmploymentProofEnvelope) -> Result<Vec<u8>> {
    bincode::serialize(proof).map_err(|e| StorageError::Serialization(e.to_string()))
}

pub fn decode_proof(bytes: &[u8]) -> Result<EmploymentProofEnvelope> {
    bincode::deserialize(bytes).map_err(|e| StorageError::Serialization(e.to_string()))
}

/// The value every one of the five index families holds. `EmploymentId`,
/// `IncomeAttestationId` and `ProofId` are all `[u8; 32]`, so one codec covers
/// them -- which is a fact about the schema, not a convenience: a change to any
/// one of those aliases has to be made here, deliberately.
pub fn encode_id_list(ids: &[EmploymentId]) -> Result<Vec<u8>> {
    bincode::serialize(ids).map_err(|e| StorageError::Serialization(e.to_string()))
}

pub fn decode_id_list(bytes: &[u8]) -> Result<Vec<EmploymentId>> {
    bincode::deserialize(bytes).map_err(|e| StorageError::Serialization(e.to_string()))
}

pub fn encode_event(event: &EmploymentEvent) -> Result<Vec<u8>> {
    bincode::serialize(event).map_err(|e| StorageError::Serialization(e.to_string()))
}

pub fn decode_event(bytes: &[u8]) -> Result<EmploymentEvent> {
    bincode::deserialize(bytes).map_err(|e| StorageError::Serialization(e.to_string()))
}

// =============================================================================
// Issuer Profile Storage (SRC-881)
// =============================================================================

/// Storage for Employment Issuer Profiles (SRC-881)
pub struct EmploymentIssuerStore<'a> {
    db: &'a Database,
}

impl<'a> EmploymentIssuerStore<'a> {
    pub fn new(db: &'a Database) -> Self {
        Self { db }
    }

    /// Store an issuer profile
    pub fn put(&self, issuer: &EmploymentIssuerProfile) -> Result<()> {
        self.db.put(
            cf::EMPLOYMENT_ISSUERS,
            issuer_key(&issuer.issuer_address),
            &encode_issuer(issuer)?,
        )
    }

    /// Get an issuer by address
    pub fn get(&self, issuer_address: &Address) -> Result<Option<EmploymentIssuerProfile>> {
        match self
            .db
            .get(cf::EMPLOYMENT_ISSUERS, issuer_key(issuer_address))?
        {
            Some(bytes) => Ok(Some(decode_issuer(&bytes)?)),
            None => Ok(None),
        }
    }

    /// Check if issuer exists
    pub fn exists(&self, issuer_address: &Address) -> Result<bool> {
        self.db
            .contains(cf::EMPLOYMENT_ISSUERS, issuer_key(issuer_address))
    }

    /// Update issuer status
    pub fn update_status(
        &self,
        issuer_address: &Address,
        status: IssuerStatus,
        timestamp: Timestamp,
    ) -> Result<()> {
        match self.get(issuer_address)? {
            Some(mut issuer) => {
                issuer.status = status;
                issuer.updated_at = timestamp;
                self.db.put(
                    cf::EMPLOYMENT_ISSUERS,
                    issuer_key(issuer_address),
                    &encode_issuer(&issuer)?,
                )
            }
            None => Err(StorageError::NotFound(format!(
                "Issuer not found: {:?}",
                issuer_address
            ))),
        }
    }

    /// One bounded page of active issuers, in key order (SC-2).
    pub fn list_active_paged(&self, page: PageSpec) -> Result<Vec<EmploymentIssuerProfile>> {
        paged_scan(
            self.db,
            cf::EMPLOYMENT_ISSUERS,
            page,
            |v| decode_issuer(v),
            |i: &EmploymentIssuerProfile| i.status.is_active(),
        )
    }

    /// List all active issuers
    pub fn list_active(&self) -> Result<Vec<EmploymentIssuerProfile>> {
        let mut issuers = Vec::new();
        for (_, value) in self.db.iter(cf::EMPLOYMENT_ISSUERS)? {
            let issuer = decode_issuer(&value)?;
            if issuer.status.is_active() {
                issuers.push(issuer);
            }
        }
        Ok(issuers)
    }
}

// =============================================================================
// Employment Credential Storage (SRC-882)
// =============================================================================

/// Counts over an employee's whole credential set, plus one bounded page of
/// the valid credentials. Produced by
/// [`EmploymentCredentialStore::summarize_by_employee`].
#[derive(Debug, Default, Clone)]
pub struct EmploymentEmployeeSummary {
    /// Every credential the employee holds.
    pub total: u32,
    /// Those valid at the time the summary was taken.
    pub active: u32,
    /// Those whose status is `Ended`.
    pub ended: u32,
    /// The requested page of the valid ones — never the whole set.
    pub active_page: Vec<EmploymentCredential>,
}

/// Storage for Employment Credentials (SRC-882)
pub struct EmploymentCredentialStore<'a> {
    db: &'a Database,
}

impl<'a> EmploymentCredentialStore<'a> {
    pub fn new(db: &'a Database) -> Self {
        Self { db }
    }

    /// Store an employment credential
    pub fn put(&self, credential: &EmploymentCredential) -> Result<()> {
        self.db.put(
            cf::EMPLOYMENT_CREDENTIALS,
            credential_key(&credential.employment_id),
            &encode_credential(credential)?,
        )?;

        // Update indexes
        self.add_to_employee_index(&credential.employee_ref, &credential.employment_id)?;
        self.add_to_employee_address_index(&credential.employee_address, &credential.employment_id)?;
        self.add_to_employer_index(&credential.employer_ref, &credential.employment_id)?;

        Ok(())
    }

    /// Get a credential by ID
    pub fn get(&self, employment_id: &EmploymentId) -> Result<Option<EmploymentCredential>> {
        match self
            .db
            .get(cf::EMPLOYMENT_CREDENTIALS, credential_key(employment_id))?
        {
            Some(bytes) => Ok(Some(decode_credential(&bytes)?)),
            None => Ok(None),
        }
    }

    /// Check if credential exists
    pub fn exists(&self, employment_id: &EmploymentId) -> Result<bool> {
        self.db
            .contains(cf::EMPLOYMENT_CREDENTIALS, credential_key(employment_id))
    }

    /// Update employment status
    pub fn update_status(
        &self,
        employment_id: &EmploymentId,
        status: EmploymentStatus,
        timestamp: Timestamp,
    ) -> Result<()> {
        match self.get(employment_id)? {
            Some(mut credential) => {
                credential.status = status;
                credential.updated_at = timestamp;
                self.db.put(
                    cf::EMPLOYMENT_CREDENTIALS,
                    credential_key(employment_id),
                    &encode_credential(&credential)?,
                )
            }
            None => Err(StorageError::NotFound(format!(
                "Employment credential not found: {:?}",
                employment_id
            ))),
        }
    }

    /// Revoke employment credential
    pub fn revoke(
        &self,
        employment_id: &EmploymentId,
        revocation_ref: [u8; 32],
        timestamp: Timestamp,
    ) -> Result<()> {
        match self.get(employment_id)? {
            Some(mut credential) => {
                credential.status = EmploymentStatus::Ended;
                credential.revocation_ref = Some(revocation_ref);
                credential.updated_at = timestamp;
                self.db.put(
                    cf::EMPLOYMENT_CREDENTIALS,
                    credential_key(employment_id),
                    &encode_credential(&credential)?,
                )
            }
            None => Err(StorageError::NotFound(format!(
                "Employment credential not found: {:?}",
                employment_id
            ))),
        }
    }

    /// One bounded page of an employee's credentials, in index order (SC-2).
    pub fn get_by_employee_paged(
        &self,
        employee_ref: &SubjectRef,
        page: PageSpec,
    ) -> Result<Vec<EmploymentCredential>> {
        let ids = self.get_employee_credential_ids(employee_ref)?;
        paged_resolve(&ids, page, |id| self.get(id), |_| true)
    }

    /// One bounded page of an employee's VALID credentials, in index order
    /// (SC-2).
    ///
    /// The filter runs inside the page walk rather than over a fully built
    /// list, so the `active` variant no longer materialises every credential
    /// before discarding most of them — which is the half of the source
    /// message this row quotes.
    pub fn get_active_by_employee_paged(
        &self,
        employee_ref: &SubjectRef,
        current_time: Timestamp,
        page: PageSpec,
    ) -> Result<Vec<EmploymentCredential>> {
        let ids = self.get_employee_credential_ids(employee_ref)?;
        paged_resolve(
            &ids,
            page,
            |id| self.get(id),
            |c: &EmploymentCredential| c.is_valid(current_time),
        )
    }

    /// The first VALID credential binding `employee_ref` to `employer_ref`, or
    /// `None` (SC-2).
    ///
    /// `employment_verifyEmployment` built every active credential the employee
    /// holds and then ran `.find()` over the list. A page cannot replace that —
    /// a bounded list would answer "not employed" for an employee whose
    /// matching credential falls past the page — so the predicate moves into
    /// the walk instead. The walk stops at the first match and retains one
    /// credential, and the ANSWER is unchanged for every input.
    pub fn find_active_by_employee_and_employer(
        &self,
        employee_ref: &SubjectRef,
        employer_ref: &EmployerRef,
        current_time: Timestamp,
    ) -> Result<Option<EmploymentCredential>> {
        for id in self.get_employee_credential_ids(employee_ref)? {
            if let Some(c) = self.get(&id)? {
                if c.is_valid(current_time) && c.employer_ref == *employer_ref {
                    return Ok(Some(c));
                }
            }
        }
        Ok(None)
    }

    /// Exact counts over an employee's credentials, plus one bounded page of
    /// the valid ones (SC-2).
    ///
    /// `employment_getSummary` returns three counts AND a list. The counts have
    /// to see every credential or they are wrong, so they are folded one
    /// credential at a time and nothing is retained for them; only the page is
    /// collected.
    pub fn summarize_by_employee(
        &self,
        employee_ref: &SubjectRef,
        current_time: Timestamp,
        page: PageSpec,
    ) -> Result<EmploymentEmployeeSummary> {
        let mut out = EmploymentEmployeeSummary::default();
        let mut matched = 0usize;
        let horizon = page.offset().saturating_add(page.limit());
        for id in self.get_employee_credential_ids(employee_ref)? {
            let Some(c) = self.get(&id)? else { continue };
            out.total += 1;
            if c.status == sumchain_primitives::employment::EmploymentStatus::Ended {
                out.ended += 1;
            }
            if c.is_valid(current_time) {
                out.active += 1;
                if matched < horizon {
                    if matched >= page.offset() {
                        out.active_page.push(c);
                    }
                    matched += 1;
                }
            }
        }
        Ok(out)
    }

    /// One bounded page of an employer's credentials, in index order (SC-2).
    pub fn get_by_employer_paged(
        &self,
        employer_ref: &EmployerRef,
        page: PageSpec,
    ) -> Result<Vec<EmploymentCredential>> {
        let ids = self.get_employer_credential_ids(employer_ref)?;
        paged_resolve(&ids, page, |id| self.get(id), |_| true)
    }

    /// One bounded page of the credentials held by a wallet address, in index
    /// order (SC-2).
    pub fn get_by_employee_address_paged(
        &self,
        employee_address: &Address,
        page: PageSpec,
    ) -> Result<Vec<EmploymentCredential>> {
        let ids = self.get_employee_address_credential_ids(employee_address)?;
        paged_resolve(&ids, page, |id| self.get(id), |_| true)
    }

    /// One bounded page of the VALID credentials held by a wallet address, in
    /// index order (SC-2).
    pub fn get_active_by_employee_address_paged(
        &self,
        employee_address: &Address,
        current_time: Timestamp,
        page: PageSpec,
    ) -> Result<Vec<EmploymentCredential>> {
        let ids = self.get_employee_address_credential_ids(employee_address)?;
        paged_resolve(
            &ids,
            page,
            |id| self.get(id),
            |c: &EmploymentCredential| c.is_valid(current_time),
        )
    }

    /// Get credentials by employee
    pub fn get_by_employee(&self, employee_ref: &SubjectRef) -> Result<Vec<EmploymentCredential>> {
        let ids = self.get_employee_credential_ids(employee_ref)?;
        let mut credentials = Vec::new();
        for id in ids {
            if let Some(credential) = self.get(&id)? {
                credentials.push(credential);
            }
        }
        Ok(credentials)
    }

    /// Get active credentials by employee
    pub fn get_active_by_employee(
        &self,
        employee_ref: &SubjectRef,
        current_time: Timestamp,
    ) -> Result<Vec<EmploymentCredential>> {
        let all = self.get_by_employee(employee_ref)?;
        Ok(all.into_iter().filter(|c| c.is_valid(current_time)).collect())
    }

    /// Get credentials by employer
    pub fn get_by_employer(&self, employer_ref: &EmployerRef) -> Result<Vec<EmploymentCredential>> {
        let ids = self.get_employer_credential_ids(employer_ref)?;
        let mut credentials = Vec::new();
        for id in ids {
            if let Some(credential) = self.get(&id)? {
                credentials.push(credential);
            }
        }
        Ok(credentials)
    }

    /// Get credentials by employee wallet address
    pub fn get_by_employee_address(&self, employee_address: &Address) -> Result<Vec<EmploymentCredential>> {
        let ids = self.get_employee_address_credential_ids(employee_address)?;
        let mut credentials = Vec::new();
        for id in ids {
            if let Some(credential) = self.get(&id)? {
                credentials.push(credential);
            }
        }
        Ok(credentials)
    }

    /// Get active credentials by employee wallet address
    pub fn get_active_by_employee_address(
        &self,
        employee_address: &Address,
        current_time: Timestamp,
    ) -> Result<Vec<EmploymentCredential>> {
        let all = self.get_by_employee_address(employee_address)?;
        Ok(all.into_iter().filter(|c| c.is_valid(current_time)).collect())
    }

    // Index helpers
    fn add_to_employee_index(&self, employee_ref: &SubjectRef, employment_id: &EmploymentId) -> Result<()> {
        let mut ids = self.get_employee_credential_ids(employee_ref)?;
        if !ids.contains(employment_id) {
            ids.push(*employment_id);
            self.db.put(
                cf::EMPLOYMENT_EMPLOYEE_INDEX,
                employee_index_key(employee_ref),
                &encode_id_list(&ids)?,
            )?;
        }
        Ok(())
    }

    fn add_to_employee_address_index(&self, employee_address: &Address, employment_id: &EmploymentId) -> Result<()> {
        let mut ids = self.get_employee_address_credential_ids(employee_address)?;
        if !ids.contains(employment_id) {
            ids.push(*employment_id);
            self.db.put(
                cf::EMPLOYMENT_EMPLOYEE_ADDRESS_INDEX,
                employee_address_index_key(employee_address),
                &encode_id_list(&ids)?,
            )?;
        }
        Ok(())
    }

    fn add_to_employer_index(&self, employer_ref: &EmployerRef, employment_id: &EmploymentId) -> Result<()> {
        let mut ids = self.get_employer_credential_ids(employer_ref)?;
        if !ids.contains(employment_id) {
            ids.push(*employment_id);
            self.db.put(
                cf::EMPLOYMENT_EMPLOYER_INDEX,
                employer_index_key(employer_ref),
                &encode_id_list(&ids)?,
            )?;
        }
        Ok(())
    }

    fn get_employee_credential_ids(&self, employee_ref: &SubjectRef) -> Result<Vec<EmploymentId>> {
        match self.db.get(
            cf::EMPLOYMENT_EMPLOYEE_INDEX,
            employee_index_key(employee_ref),
        )? {
            Some(bytes) => decode_id_list(&bytes),
            None => Ok(Vec::new()),
        }
    }

    fn get_employee_address_credential_ids(&self, employee_address: &Address) -> Result<Vec<EmploymentId>> {
        match self.db.get(
            cf::EMPLOYMENT_EMPLOYEE_ADDRESS_INDEX,
            employee_address_index_key(employee_address),
        )? {
            Some(bytes) => decode_id_list(&bytes),
            None => Ok(Vec::new()),
        }
    }

    fn get_employer_credential_ids(&self, employer_ref: &EmployerRef) -> Result<Vec<EmploymentId>> {
        match self.db.get(
            cf::EMPLOYMENT_EMPLOYER_INDEX,
            employer_index_key(employer_ref),
        )? {
            Some(bytes) => decode_id_list(&bytes),
            None => Ok(Vec::new()),
        }
    }
}

// =============================================================================
// Income Attestation Storage (SRC-883)
// =============================================================================

/// Storage for Income Attestations (SRC-883)
pub struct IncomeAttestationStore<'a> {
    db: &'a Database,
}

impl<'a> IncomeAttestationStore<'a> {
    pub fn new(db: &'a Database) -> Self {
        Self { db }
    }

    /// Store an income attestation
    pub fn put(&self, attestation: &IncomeAttestation) -> Result<()> {
        self.db.put(
            cf::EMPLOYMENT_INCOME_ATTESTATIONS,
            income_attestation_key(&attestation.attestation_id),
            &encode_attestation(attestation)?,
        )?;

        // Update indexes
        self.add_to_subject_index(&attestation.subject_ref, &attestation.attestation_id)?;
        self.add_to_holder_address_index(&attestation.holder_address, &attestation.attestation_id)?;

        Ok(())
    }

    /// Get an attestation by ID
    pub fn get(&self, attestation_id: &IncomeAttestationId) -> Result<Option<IncomeAttestation>> {
        match self.db.get(
            cf::EMPLOYMENT_INCOME_ATTESTATIONS,
            income_attestation_key(attestation_id),
        )? {
            Some(bytes) => Ok(Some(decode_attestation(&bytes)?)),
            None => Ok(None),
        }
    }

    /// Check if attestation exists
    pub fn exists(&self, attestation_id: &IncomeAttestationId) -> Result<bool> {
        self.db.contains(
            cf::EMPLOYMENT_INCOME_ATTESTATIONS,
            income_attestation_key(attestation_id),
        )
    }

    /// Revoke attestation
    pub fn revoke(
        &self,
        attestation_id: &IncomeAttestationId,
        revocation_ref: [u8; 32],
        timestamp: Timestamp,
    ) -> Result<()> {
        match self.get(attestation_id)? {
            Some(mut attestation) => {
                attestation.revocation_ref = Some(revocation_ref);
                attestation.updated_at = timestamp;
                self.db.put(
                    cf::EMPLOYMENT_INCOME_ATTESTATIONS,
                    income_attestation_key(attestation_id),
                    &encode_attestation(&attestation)?,
                )
            }
            None => Err(StorageError::NotFound(format!(
                "Income attestation not found: {:?}",
                attestation_id
            ))),
        }
    }

    /// One bounded page of a subject's income attestations, in index order
    /// (SC-2).
    pub fn get_by_subject_paged(
        &self,
        subject_ref: &SubjectRef,
        page: PageSpec,
    ) -> Result<Vec<IncomeAttestation>> {
        let ids = self.get_subject_attestation_ids(subject_ref)?;
        paged_resolve(&ids, page, |id| self.get(id), |_| true)
    }

    /// One bounded page of a subject's VALID income attestations, in index
    /// order (SC-2).
    pub fn get_valid_by_subject_paged(
        &self,
        subject_ref: &SubjectRef,
        current_time: Timestamp,
        page: PageSpec,
    ) -> Result<Vec<IncomeAttestation>> {
        let ids = self.get_subject_attestation_ids(subject_ref)?;
        paged_resolve(
            &ids,
            page,
            |id| self.get(id),
            |a: &IncomeAttestation| a.is_valid(current_time),
        )
    }

    /// One bounded page of the income attestations held by a wallet address, in
    /// index order (SC-2).
    pub fn get_by_holder_address_paged(
        &self,
        holder_address: &Address,
        page: PageSpec,
    ) -> Result<Vec<IncomeAttestation>> {
        let ids = self.get_holder_address_attestation_ids(holder_address)?;
        paged_resolve(&ids, page, |id| self.get(id), |_| true)
    }

    /// One bounded page of the VALID income attestations held by a wallet
    /// address, in index order (SC-2).
    pub fn get_valid_by_holder_address_paged(
        &self,
        holder_address: &Address,
        current_time: Timestamp,
        page: PageSpec,
    ) -> Result<Vec<IncomeAttestation>> {
        let ids = self.get_holder_address_attestation_ids(holder_address)?;
        paged_resolve(
            &ids,
            page,
            |id| self.get(id),
            |a: &IncomeAttestation| a.is_valid(current_time),
        )
    }

    /// Get attestations by subject
    pub fn get_by_subject(&self, subject_ref: &SubjectRef) -> Result<Vec<IncomeAttestation>> {
        let ids = self.get_subject_attestation_ids(subject_ref)?;
        let mut attestations = Vec::new();
        for id in ids {
            if let Some(attestation) = self.get(&id)? {
                attestations.push(attestation);
            }
        }
        Ok(attestations)
    }

    /// Get valid attestations by subject
    pub fn get_valid_by_subject(
        &self,
        subject_ref: &SubjectRef,
        current_time: Timestamp,
    ) -> Result<Vec<IncomeAttestation>> {
        let all = self.get_by_subject(subject_ref)?;
        Ok(all.into_iter().filter(|a| a.is_valid(current_time)).collect())
    }

    /// Get attestations by holder wallet address
    pub fn get_by_holder_address(&self, holder_address: &Address) -> Result<Vec<IncomeAttestation>> {
        let ids = self.get_holder_address_attestation_ids(holder_address)?;
        let mut attestations = Vec::new();
        for id in ids {
            if let Some(attestation) = self.get(&id)? {
                attestations.push(attestation);
            }
        }
        Ok(attestations)
    }

    /// Get valid attestations by holder wallet address
    pub fn get_valid_by_holder_address(
        &self,
        holder_address: &Address,
        current_time: Timestamp,
    ) -> Result<Vec<IncomeAttestation>> {
        let all = self.get_by_holder_address(holder_address)?;
        Ok(all.into_iter().filter(|a| a.is_valid(current_time)).collect())
    }

    // Index helpers
    fn add_to_subject_index(&self, subject_ref: &SubjectRef, attestation_id: &IncomeAttestationId) -> Result<()> {
        let mut ids = self.get_subject_attestation_ids(subject_ref)?;
        if !ids.contains(attestation_id) {
            ids.push(*attestation_id);
            self.db.put(
                cf::EMPLOYMENT_SUBJECT_INCOME_INDEX,
                subject_income_index_key(subject_ref),
                &encode_id_list(&ids)?,
            )?;
        }
        Ok(())
    }

    fn add_to_holder_address_index(&self, holder_address: &Address, attestation_id: &IncomeAttestationId) -> Result<()> {
        let mut ids = self.get_holder_address_attestation_ids(holder_address)?;
        if !ids.contains(attestation_id) {
            ids.push(*attestation_id);
            self.db.put(
                cf::EMPLOYMENT_INCOME_HOLDER_ADDRESS_INDEX,
                income_holder_address_index_key(holder_address),
                &encode_id_list(&ids)?,
            )?;
        }
        Ok(())
    }

    fn get_subject_attestation_ids(&self, subject_ref: &SubjectRef) -> Result<Vec<IncomeAttestationId>> {
        match self.db.get(
            cf::EMPLOYMENT_SUBJECT_INCOME_INDEX,
            subject_income_index_key(subject_ref),
        )? {
            Some(bytes) => decode_id_list(&bytes),
            None => Ok(Vec::new()),
        }
    }

    fn get_holder_address_attestation_ids(&self, holder_address: &Address) -> Result<Vec<IncomeAttestationId>> {
        match self.db.get(
            cf::EMPLOYMENT_INCOME_HOLDER_ADDRESS_INDEX,
            income_holder_address_index_key(holder_address),
        )? {
            Some(bytes) => decode_id_list(&bytes),
            None => Ok(Vec::new()),
        }
    }
}

// =============================================================================
// Employment Proof Storage (SRC-885)
// =============================================================================

/// Storage for Employment Proofs (SRC-885)
pub struct EmploymentProofStore<'a> {
    db: &'a Database,
}

impl<'a> EmploymentProofStore<'a> {
    pub fn new(db: &'a Database) -> Self {
        Self { db }
    }

    /// Store an employment proof
    pub fn put(&self, proof: &EmploymentProofEnvelope) -> Result<()> {
        self.db.put(
            cf::EMPLOYMENT_PROOFS,
            proof_key(&proof.proof_id),
            &encode_proof(proof)?,
        )
    }

    /// Get a proof by ID
    pub fn get(&self, proof_id: &ProofId) -> Result<Option<EmploymentProofEnvelope>> {
        match self.db.get(cf::EMPLOYMENT_PROOFS, proof_key(proof_id))? {
            Some(bytes) => Ok(Some(decode_proof(&bytes)?)),
            None => Ok(None),
        }
    }

    /// Check if proof exists
    pub fn exists(&self, proof_id: &ProofId) -> Result<bool> {
        self.db.contains(cf::EMPLOYMENT_PROOFS, proof_key(proof_id))
    }

    /// Check if proof is valid (not expired)
    pub fn is_valid(&self, proof_id: &ProofId, current_time: Timestamp) -> Result<bool> {
        match self.get(proof_id)? {
            Some(proof) => Ok(proof.is_valid(current_time)),
            None => Ok(false),
        }
    }
}

// =============================================================================
// Employment Event Storage
// =============================================================================

/// Storage for Employment Events
pub struct EmploymentEventStore<'a> {
    db: &'a Database,
}

impl<'a> EmploymentEventStore<'a> {
    pub fn new(db: &'a Database) -> Self {
        Self { db }
    }

    /// Store an employment event
    pub fn put(&self, height: BlockHeight, index: u32, event: &EmploymentEvent) -> Result<()> {
        self.db.put(
            cf::EMPLOYMENT_SYSTEM_EVENTS,
            &event_key(height, index),
            &encode_event(event)?,
        )
    }

    /// Get events by block height
    pub fn get_by_height(&self, height: BlockHeight) -> Result<Vec<EmploymentEvent>> {
        let prefix = event_height_prefix(height);
        let mut events = Vec::new();
        for (_, value) in self.db.prefix_iter(cf::EMPLOYMENT_SYSTEM_EVENTS, &prefix)? {
            events.push(decode_event(&value)?);
        }
        Ok(events)
    }
}

// =============================================================================
// Combined Employment Store
// =============================================================================

/// Combined storage interface for all SRC-88X operations
pub struct EmploymentStore<'a> {
    db: &'a Database,
}

impl<'a> EmploymentStore<'a> {
    pub fn new(db: &'a Database) -> Self {
        Self { db }
    }

    /// Get issuer store
    pub fn issuers(&self) -> EmploymentIssuerStore<'_> {
        EmploymentIssuerStore::new(self.db)
    }

    /// Get credential store
    pub fn credentials(&self) -> EmploymentCredentialStore<'_> {
        EmploymentCredentialStore::new(self.db)
    }

    /// Get income attestation store
    pub fn income_attestations(&self) -> IncomeAttestationStore<'_> {
        IncomeAttestationStore::new(self.db)
    }

    /// Get proof store
    pub fn proofs(&self) -> EmploymentProofStore<'_> {
        EmploymentProofStore::new(self.db)
    }

    /// Get event store
    pub fn events(&self) -> EmploymentEventStore<'_> {
        EmploymentEventStore::new(self.db)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sumchain_primitives::employment::{
        EmploymentIssuerClass, EmploymentType, IncomeBracket, IncomePeriod,
    };
    use tempfile::TempDir;

    fn temp_db() -> (Database, TempDir) {
        let dir = TempDir::new().unwrap();
        let db = Database::open_default(dir.path()).unwrap();
        (db, dir)
    }

    fn sample_issuer() -> EmploymentIssuerProfile {
        EmploymentIssuerProfile {
            issuer_address: Address::new([1u8; 20]),
            issuer_class: EmploymentIssuerClass::PayrollProcessor,
            display_name: "Sample Issuer".to_string(),
            issuer_commitment: [2u8; 32],
            jurisdiction_code: "US-CA".to_string(),
            policy_id: [3u8; 32],
            status: IssuerStatus::Active,
            registered_at_height: 100,
            created_at: 1000,
            updated_at: 1000,
        }
    }

    fn sample_credential() -> EmploymentCredential {
        EmploymentCredential {
            employment_id: [4u8; 32],
            employee_address: Address::new([99u8; 20]),
            employee_ref: [5u8; 32],
            employer_ref: [6u8; 32],
            status: EmploymentStatus::Active,
            tenure_commitment: [7u8; 32],
            role_commitment: Some([8u8; 32]),
            employment_type: EmploymentType::FullTime,
            valid_from: 1000,
            expiry: 0,
            policy_id: [9u8; 32],
            revocation_ref: None,
            issuer_address: Address::new([10u8; 20]),
            issuer_name: "Sample Employer".to_string(),
            issuer_class: EmploymentIssuerClass::PayrollProcessor,
            created_at: 1000,
            updated_at: 1000,
        }
    }

    fn sample_attestation() -> IncomeAttestation {
        IncomeAttestation {
            attestation_id: [11u8; 32],
            holder_address: Address::new([98u8; 20]),
            subject_ref: [12u8; 32],
            period_commitment: [13u8; 32],
            period_type: IncomePeriod::Annual,
            income_bracket: IncomeBracket::Bracket4,
            threshold_commitment: None,
            employment_id: Some([4u8; 32]),
            issuer_address: Address::new([14u8; 20]),
            issuer_class: EmploymentIssuerClass::PayrollProcessor,
            valid_from: 1000,
            expiry: 2000,
            policy_id: [15u8; 32],
            revocation_ref: None,
            created_at: 1000,
            updated_at: 1000,
        }
    }

    #[test]
    fn test_issuer_store() {
        let (db, _dir) = temp_db();
        let store = EmploymentIssuerStore::new(&db);

        let issuer = sample_issuer();
        store.put(&issuer).unwrap();

        let retrieved = store.get(&issuer.issuer_address).unwrap().unwrap();
        assert_eq!(retrieved.jurisdiction_code, "US-CA");
        assert!(retrieved.status.is_active());

        // Test status update
        store.update_status(&issuer.issuer_address, IssuerStatus::Suspended, 1100).unwrap();
        let updated = store.get(&issuer.issuer_address).unwrap().unwrap();
        assert!(!updated.status.is_active());
    }

    #[test]
    fn test_credential_store() {
        let (db, _dir) = temp_db();
        let store = EmploymentCredentialStore::new(&db);

        let credential = sample_credential();
        store.put(&credential).unwrap();

        let retrieved = store.get(&credential.employment_id).unwrap().unwrap();
        assert_eq!(retrieved.employment_id, credential.employment_id);
        assert!(retrieved.status.is_currently_employed());

        // Test employee index
        let by_employee = store.get_by_employee(&credential.employee_ref).unwrap();
        assert_eq!(by_employee.len(), 1);

        // Test employer index
        let by_employer = store.get_by_employer(&credential.employer_ref).unwrap();
        assert_eq!(by_employer.len(), 1);

        // Test active filter
        let active = store.get_active_by_employee(&credential.employee_ref, 1500).unwrap();
        assert_eq!(active.len(), 1);
    }

    #[test]
    fn test_income_attestation_store() {
        let (db, _dir) = temp_db();
        let store = IncomeAttestationStore::new(&db);

        let attestation = sample_attestation();
        store.put(&attestation).unwrap();

        let retrieved = store.get(&attestation.attestation_id).unwrap().unwrap();
        assert_eq!(retrieved.attestation_id, attestation.attestation_id);
        assert_eq!(retrieved.income_bracket, IncomeBracket::Bracket4);

        // Test subject index
        let by_subject = store.get_by_subject(&attestation.subject_ref).unwrap();
        assert_eq!(by_subject.len(), 1);

        // Test valid filter
        let valid = store.get_valid_by_subject(&attestation.subject_ref, 1500).unwrap();
        assert_eq!(valid.len(), 1);

        // Revoke and check
        store.revoke(&attestation.attestation_id, [99u8; 32], 1600).unwrap();
        let valid_after_revoke = store.get_valid_by_subject(&attestation.subject_ref, 1700).unwrap();
        assert_eq!(valid_after_revoke.len(), 0);
    }

    #[test]
    fn test_employment_store_combined() {
        let (db, _dir) = temp_db();
        let store = EmploymentStore::new(&db);

        // Store all types
        let issuer = sample_issuer();
        store.issuers().put(&issuer).unwrap();

        let credential = sample_credential();
        store.credentials().put(&credential).unwrap();

        let attestation = sample_attestation();
        store.income_attestations().put(&attestation).unwrap();

        // Verify all stored
        assert!(store.issuers().exists(&issuer.issuer_address).unwrap());
        assert!(store.credentials().exists(&credential.employment_id).unwrap());
        assert!(store.income_attestations().exists(&attestation.attestation_id).unwrap());
    }
}
