//! DocClass Storage Module (SRC-80X/81X)
//!
//! Provides persistent storage for DocClass credentials:
//! - Identity Roots (SRC-800)
//! - Eligibility Attestations (SRC-802)
//! - Academic/Professional Credentials (SRC-810-813)
//! - Revocation Records (SRC-805)
//! - Issuer Registry

use sumchain_primitives::{
    Address, AcademicCredential, BlockHeight, CredentialId, DocClassEvent, DocClassIssuer,
    DocClassIssuerStatus, DocSubcode, EligibilityAttestation, IdentityRoot, IdentityStatus,
    RevocationRecord, RevocationStatus, Timestamp,
};

use crate::db::{cf, Database};
use crate::page::{paged_resolve, paged_scan, PageSpec};
use crate::{Result, StorageError};

// =============================================================================
// Shared key layout and codec
// =============================================================================
//
// One builder per row and one codec per value, called by the committed stores
// below and by the candidate surface in `sumchain_state::docclass_view`.
//
// They are extracted rather than restated on each side because four things here
// are easy to get subtly wrong:
//
//   * Three families are keyed by a bare 32-byte credential id, two by the
//     20-byte address bytes, and two by a COMPOSITE key built by hand:
//     revocations are `credential_id || revoked_at_height` big-endian, and
//     events are `height || tx_index || event_index`, all big-endian. Endianness
//     is the ordering contract for both, because both are read back by prefix
//     scan and the revocation reader additionally sorts on the decoded height.
//   * `DOCCLASS_SUBJECT_INDEX` is written with TWO DIFFERENT value shapes at the
//     SAME key. `IdentityRootStore` writes `Vec<(CredentialId, DocSubcode)>`;
//     `EligibilityStore` and `CredentialStore` write `Vec<CredentialId>`. That is
//     an inherited defect, not a refactoring artefact, and it is reproduced
//     exactly -- which is why there are two encoders for one family rather than
//     one that guesses. See `docs/lane-a/DEPLOYMENT-BLOCKERS.md`.
//   * The three index values are accumulating lists, not presence markers, so an
//     append is a read-modify-write. On the candidate side it has to read the
//     candidate, or a second entry in one block overwrites the first one's list
//     with a single-element one.
//   * `encode_subject_credential_index` and `encode_issuer_credential_index`
//     encode the same Rust type. They are still one function per family rather
//     than one generic helper: a generic `encode<T: Serialize>` cannot pin any
//     individual row's byte layout, a codec test written against it can only
//     restate what serde does, and a mutation to it could not be attributed to
//     one family. Named per family, each is a thing a test can fix bytes for and
//     a mutation can break on its own.

/// A subject commitment: the 32-byte privacy-preserving binding a credential
/// carries instead of the subject's identity.
pub type SubjectCommitment = [u8; 32];

/// Identity roots are keyed by identity id.
pub fn identity_root_key(identity_id: &CredentialId) -> &[u8] {
    identity_id
}

/// Eligibility attestations are keyed by credential id.
pub fn eligibility_key(credential_id: &CredentialId) -> &[u8] {
    credential_id
}

/// Academic/professional credentials are keyed by credential id.
pub fn credential_key(credential_id: &CredentialId) -> &[u8] {
    credential_id
}

/// Issuers are keyed by the raw 20 address bytes, not by a 32-byte id.
pub fn docclass_issuer_key(address: &Address) -> &[u8] {
    address.as_bytes()
}

/// The subject index is keyed by the 32-byte subject commitment. Its VALUE is
/// one of two incompatible shapes; see the module note above.
///
/// This is the LEGACY key, and after the subject-index split activation
/// (ACTIVATION-AUDIT row BD-6) it belongs to the credential-id-list shape
/// alone. The identity-pair shape moves to [`subject_identity_index_key`].
pub fn subject_index_key(subject_commitment: &SubjectCommitment) -> &[u8] {
    subject_commitment
}

/// The one-byte tag that separates the identity-pair key space from the
/// credential-id-list key space.
///
/// A commitment is 32 bytes, so a tagged key is 33 and cannot equal any legacy
/// key. The tag leads rather than trails so the two spaces do not interleave
/// under a prefix scan.
pub const SUBJECT_IDENTITY_INDEX_TAG: u8 = 0x01;

/// The subject index key the IDENTITY shape uses after the split activation.
///
/// `DOCCLASS_SUBJECT_INDEX` held two incompatible value shapes at one key: a
/// `Vec<(CredentialId, DocSubcode)>` written by the identity path and a bare
/// `Vec<CredentialId>` written by the eligibility and credential paths. Because
/// the subject commitment is an arbitrary 32-byte payload value, an attacker
/// picks the colliding key: two cheap transactions arm it, the second silently
/// destroys the first's index, and the next identity operation on that subject
/// fails to decode and ends the block. Separating the key spaces removes both
/// halves -- the silent corruption and the block denial -- by construction.
pub fn subject_identity_index_key(subject_commitment: &SubjectCommitment) -> Vec<u8> {
    let mut key = Vec::with_capacity(33);
    key.push(SUBJECT_IDENTITY_INDEX_TAG);
    key.extend_from_slice(subject_commitment);
    key
}

/// The issuer index is keyed by the raw 20 address bytes of the ISSUER, and its
/// value is a bincode `Vec<CredentialId>`.
pub fn issuer_index_key(issuer: &Address) -> &[u8] {
    issuer.as_bytes()
}

/// Revocation records are keyed by `credential_id || revoked_at_height`, the
/// height big-endian so a prefix scan yields a credential's records in height
/// order. 40 bytes exactly; the reader rejects any other width.
pub fn revocation_key(credential_id: &CredentialId, revoked_at_height: BlockHeight) -> Vec<u8> {
    let mut key = Vec::with_capacity(40);
    key.extend_from_slice(credential_id);
    key.extend_from_slice(&revoked_at_height.to_be_bytes());
    key
}

/// The revocation key a node at or above
/// `docclass_revocation_record_enabled_from_height` writes:
/// `credential_id || revoked_at_height || sequence`, both numbers big-endian.
/// 44 bytes exactly, and no 40-byte legacy key can equal one.
///
/// ACTIVATION-AUDIT row OV-24. The height alone does not distinguish two
/// records for one credential in one block, so the later write replaces the
/// earlier and a revoke followed by a reactivation leaves one record. The
/// sequence does distinguish them, and it orders them: a 40-byte legacy key is
/// a strict prefix of any 44-byte key at the same height, so under a plain key
/// comparison every record written before activation sorts BEFORE every record
/// written after it at that height -- which is the order they happened in.
///
/// `sequence` counts records at THIS height for THIS credential, and is read
/// out of state by the writer rather than taken from the transaction's index;
/// see `DocClassExecutor::v_next_revocation_sequence` for why the transaction
/// index is the wrong source.
pub fn revocation_key_sequenced(
    credential_id: &CredentialId,
    revoked_at_height: BlockHeight,
    sequence: u32,
) -> Vec<u8> {
    let mut key = Vec::with_capacity(44);
    key.extend_from_slice(credential_id);
    key.extend_from_slice(&revoked_at_height.to_be_bytes());
    key.extend_from_slice(&sequence.to_be_bytes());
    key
}

/// Whether `key` is a revocation key of either width belonging to
/// `credential_id`.
///
/// Both widths, because a chain that activates the sequenced key keeps every
/// record it wrote before. Anything else -- a prefix-scan overrun into a
/// neighbouring credential's row, or a hand-written row of some third width --
/// is skipped before it is decoded, which is what
/// `a_revocation_key_of_the_wrong_width_is_skipped_by_the_candidate_reader`
/// pins.
pub fn is_revocation_key_for(key: &[u8], credential_id: &CredentialId) -> bool {
    (key.len() == 40 || key.len() == 44) && &key[..32] == credential_id
}

/// Events are keyed by `block_height || tx_index || event_index`, all
/// big-endian: 8 + 4 + 2 = 14 bytes.
pub fn docclass_event_key(block_height: BlockHeight, tx_index: u32, event_index: u16) -> Vec<u8> {
    let mut key = Vec::with_capacity(14);
    key.extend_from_slice(&block_height.to_be_bytes());
    key.extend_from_slice(&tx_index.to_be_bytes());
    key.extend_from_slice(&event_index.to_be_bytes());
    key
}

pub fn encode_identity_root(identity: &IdentityRoot) -> Result<Vec<u8>> {
    bincode::serialize(identity).map_err(|e| StorageError::Serialization(e.to_string()))
}

pub fn decode_identity_root(bytes: &[u8]) -> Result<IdentityRoot> {
    bincode::deserialize(bytes).map_err(|e| StorageError::Serialization(e.to_string()))
}

/// The subject index AS THE IDENTITY STORE WRITES IT: a list of
/// `(credential id, subcode)` pairs.
pub fn encode_subject_identity_index(index: &[(CredentialId, DocSubcode)]) -> Result<Vec<u8>> {
    bincode::serialize(index).map_err(|e| StorageError::Serialization(e.to_string()))
}

pub fn decode_subject_identity_index(bytes: &[u8]) -> Result<Vec<(CredentialId, DocSubcode)>> {
    bincode::deserialize(bytes).map_err(|e| StorageError::Serialization(e.to_string()))
}

pub fn encode_eligibility(attestation: &EligibilityAttestation) -> Result<Vec<u8>> {
    bincode::serialize(attestation).map_err(|e| StorageError::Serialization(e.to_string()))
}

pub fn decode_eligibility(bytes: &[u8]) -> Result<EligibilityAttestation> {
    bincode::deserialize(bytes).map_err(|e| StorageError::Serialization(e.to_string()))
}

pub fn encode_credential(credential: &AcademicCredential) -> Result<Vec<u8>> {
    bincode::serialize(credential).map_err(|e| StorageError::Serialization(e.to_string()))
}

pub fn decode_credential(bytes: &[u8]) -> Result<AcademicCredential> {
    bincode::deserialize(bytes).map_err(|e| StorageError::Serialization(e.to_string()))
}

/// The subject index AS THE ELIGIBILITY AND CREDENTIAL STORES WRITE IT: a bare
/// list of credential ids, at the same key the identity store uses for pairs.
pub fn encode_subject_credential_index(ids: &[CredentialId]) -> Result<Vec<u8>> {
    bincode::serialize(ids).map_err(|e| StorageError::Serialization(e.to_string()))
}

pub fn decode_subject_credential_index(bytes: &[u8]) -> Result<Vec<CredentialId>> {
    bincode::deserialize(bytes).map_err(|e| StorageError::Serialization(e.to_string()))
}

pub fn encode_issuer_credential_index(ids: &[CredentialId]) -> Result<Vec<u8>> {
    bincode::serialize(ids).map_err(|e| StorageError::Serialization(e.to_string()))
}

pub fn decode_issuer_credential_index(bytes: &[u8]) -> Result<Vec<CredentialId>> {
    bincode::deserialize(bytes).map_err(|e| StorageError::Serialization(e.to_string()))
}

pub fn encode_revocation_record(record: &RevocationRecord) -> Result<Vec<u8>> {
    bincode::serialize(record).map_err(|e| StorageError::Serialization(e.to_string()))
}

pub fn decode_revocation_record(bytes: &[u8]) -> Result<RevocationRecord> {
    bincode::deserialize(bytes).map_err(|e| StorageError::Serialization(e.to_string()))
}

pub fn encode_docclass_issuer(issuer: &DocClassIssuer) -> Result<Vec<u8>> {
    bincode::serialize(issuer).map_err(|e| StorageError::Serialization(e.to_string()))
}

pub fn decode_docclass_issuer(bytes: &[u8]) -> Result<DocClassIssuer> {
    bincode::deserialize(bytes).map_err(|e| StorageError::Serialization(e.to_string()))
}

pub fn encode_docclass_event(event: &DocClassEvent) -> Result<Vec<u8>> {
    bincode::serialize(event).map_err(|e| StorageError::Serialization(e.to_string()))
}

pub fn decode_docclass_event(bytes: &[u8]) -> Result<DocClassEvent> {
    bincode::deserialize(bytes).map_err(|e| StorageError::Serialization(e.to_string()))
}

// =============================================================================
// Identity Root Storage (SRC-800)
// =============================================================================

/// Storage for Identity Root records (SRC-800)
pub struct IdentityRootStore<'a> {
    db: &'a Database,
}

impl<'a> IdentityRootStore<'a> {
    pub fn new(db: &'a Database) -> Self {
        Self { db }
    }

    /// Store an identity root
    pub fn put(&self, identity: &IdentityRoot) -> Result<()> {
        let bytes = encode_identity_root(identity)?;
        self.db.put(
            cf::DOCCLASS_IDENTITY_ROOTS,
            identity_root_key(&identity.identity_id),
            &bytes,
        )?;

        // Index by subject commitment
        self.add_to_subject_index(&identity.subject_commitment, &identity.identity_id, DocSubcode::IdentityRoot)?;

        Ok(())
    }

    /// Get an identity root by ID
    pub fn get(&self, identity_id: &CredentialId) -> Result<Option<IdentityRoot>> {
        match self
            .db
            .get(cf::DOCCLASS_IDENTITY_ROOTS, identity_root_key(identity_id))?
        {
            Some(bytes) => Ok(Some(decode_identity_root(&bytes)?)),
            None => Ok(None),
        }
    }

    /// Check if identity exists
    pub fn exists(&self, identity_id: &CredentialId) -> Result<bool> {
        self.db
            .contains(cf::DOCCLASS_IDENTITY_ROOTS, identity_root_key(identity_id))
    }

    /// One bounded page of the identity roots a controller controls, in key
    /// order (SC-7).
    ///
    /// A full scan with a filter — there is no by-controller index. The page
    /// bounds the response and the decoded roots held at once; `IdentityRoot`
    /// is the largest row in the subsystem (AL-10), so that bound is the
    /// point.
    pub fn get_by_controller_paged(
        &self,
        controller: &Address,
        page: PageSpec,
    ) -> Result<Vec<IdentityRoot>> {
        paged_scan(
            self.db,
            cf::DOCCLASS_IDENTITY_ROOTS,
            page,
            |v| decode_identity_root(v),
            |i: &IdentityRoot| {
                i.controller == *controller || i.additional_controllers.contains(controller)
            },
        )
    }

    /// Get identity by controller address
    pub fn get_by_controller(&self, controller: &Address) -> Result<Vec<IdentityRoot>> {
        let mut identities = Vec::new();

        for (_, value) in self.db.iter(cf::DOCCLASS_IDENTITY_ROOTS)? {
            let identity = decode_identity_root(&value)?;
            if identity.controller == *controller ||
               identity.additional_controllers.contains(controller) {
                identities.push(identity);
            }
        }

        Ok(identities)
    }

    /// Update identity status
    pub fn update_status(&self, identity_id: &CredentialId, status: IdentityStatus, timestamp: Timestamp) -> Result<()> {
        match self.get(identity_id)? {
            Some(mut identity) => {
                identity.status = status;
                identity.updated_at = timestamp;
                self.put(&identity)
            }
            None => Err(StorageError::NotFound(format!("Identity not found: {:?}", identity_id))),
        }
    }

    /// Helper to add to subject index
    fn add_to_subject_index(&self, subject_commitment: &[u8; 32], credential_id: &CredentialId, subcode: DocSubcode) -> Result<()> {
        let mut index = self.get_by_subject(subject_commitment)?;
        let entry = (*credential_id, subcode);
        if !index.iter().any(|(id, _)| id == credential_id) {
            index.push(entry);
            let bytes = encode_subject_identity_index(&index)?;
            self.db.put(
                cf::DOCCLASS_SUBJECT_INDEX,
                subject_index_key(subject_commitment),
                &bytes,
            )?;
        }
        Ok(())
    }

    /// Get all credential IDs for a subject commitment
    /// Read the identity subject index, post-split key first.
    ///
    /// Reads fall back to the legacy bare-commitment key exactly as the undo
    /// journal's re-key does, so a node reading rows written before the
    /// subject-index split activation still finds them. A value at the LEGACY
    /// key that does not decode as identity pairs is still an error, because
    /// before the split that is precisely the collision this reader has always
    /// surfaced.
    pub fn get_by_subject(
        &self,
        subject_commitment: &[u8; 32],
    ) -> Result<Vec<(CredentialId, DocSubcode)>> {
        if let Some(bytes) = self.db.get(
            cf::DOCCLASS_SUBJECT_INDEX,
            &subject_identity_index_key(subject_commitment),
        )? {
            return decode_subject_identity_index(&bytes);
        }
        match self.db.get(
            cf::DOCCLASS_SUBJECT_INDEX,
            subject_index_key(subject_commitment),
        )? {
            Some(bytes) => decode_subject_identity_index(&bytes),
            None => Ok(Vec::new()),
        }
    }
}

// =============================================================================
// Eligibility Attestation Storage (SRC-802)
// =============================================================================

/// Storage for Eligibility Attestations (SRC-802)
pub struct EligibilityStore<'a> {
    db: &'a Database,
}

impl<'a> EligibilityStore<'a> {
    pub fn new(db: &'a Database) -> Self {
        Self { db }
    }

    /// Store an eligibility attestation
    pub fn put(&self, attestation: &EligibilityAttestation) -> Result<()> {
        let bytes = encode_eligibility(attestation)?;
        self.db.put(
            cf::DOCCLASS_ELIGIBILITY,
            eligibility_key(&attestation.credential_id),
            &bytes,
        )?;

        // Index by subject commitment
        self.add_to_subject_index(&attestation.subject_commitment, &attestation.credential_id)?;

        // Index by issuer
        self.add_to_issuer_index(&attestation.issuer, &attestation.credential_id)?;

        Ok(())
    }

    /// Get an eligibility attestation by ID
    pub fn get(&self, credential_id: &CredentialId) -> Result<Option<EligibilityAttestation>> {
        match self
            .db
            .get(cf::DOCCLASS_ELIGIBILITY, eligibility_key(credential_id))?
        {
            Some(bytes) => Ok(Some(decode_eligibility(&bytes)?)),
            None => Ok(None),
        }
    }

    /// Check if attestation exists
    pub fn exists(&self, credential_id: &CredentialId) -> Result<bool> {
        self.db
            .contains(cf::DOCCLASS_ELIGIBILITY, eligibility_key(credential_id))
    }

    /// One bounded page of an issuer's eligibility attestations, in index
    /// order (SC-7).
    pub fn get_by_issuer_paged(
        &self,
        issuer: &Address,
        page: PageSpec,
    ) -> Result<Vec<EligibilityAttestation>> {
        let ids = self.get_issuer_credentials(issuer)?;
        paged_resolve(&ids, page, |id| self.get(id), |_| true)
    }

    /// One bounded page of a subject's eligibility attestations, in index
    /// order (SC-7).
    pub fn get_by_subject_paged(
        &self,
        subject_commitment: &[u8; 32],
        page: PageSpec,
    ) -> Result<Vec<EligibilityAttestation>> {
        let ids = self.get_subject_credentials(subject_commitment)?;
        paged_resolve(&ids, page, |id| self.get(id), |_| true)
    }

    /// Get attestations by issuer
    pub fn get_by_issuer(&self, issuer: &Address) -> Result<Vec<EligibilityAttestation>> {
        let credential_ids = self.get_issuer_credentials(issuer)?;
        let mut attestations = Vec::new();

        for credential_id in credential_ids {
            if let Some(attestation) = self.get(&credential_id)? {
                attestations.push(attestation);
            }
        }

        Ok(attestations)
    }

    /// Get attestations by subject commitment
    pub fn get_by_subject(&self, subject_commitment: &[u8; 32]) -> Result<Vec<EligibilityAttestation>> {
        let credential_ids = self.get_subject_credentials(subject_commitment)?;
        let mut attestations = Vec::new();

        for credential_id in credential_ids {
            if let Some(attestation) = self.get(&credential_id)? {
                attestations.push(attestation);
            }
        }

        Ok(attestations)
    }

    /// Get valid (non-expired, non-revoked) attestations for a subject
    pub fn get_valid_for_subject(&self, subject_commitment: &[u8; 32], current_time: Timestamp) -> Result<Vec<EligibilityAttestation>> {
        let attestations = self.get_by_subject(subject_commitment)?;
        Ok(attestations.into_iter().filter(|a| {
            a.revocation_status == RevocationStatus::Active &&
            (a.expires_at == 0 || a.expires_at > current_time) &&
            a.valid_from <= current_time
        }).collect())
    }

    /// Update revocation status
    pub fn update_revocation(&self, credential_id: &CredentialId, status: RevocationStatus, superseded_by: Option<CredentialId>) -> Result<()> {
        match self.get(credential_id)? {
            Some(mut attestation) => {
                attestation.revocation_status = status;
                attestation.superseded_by = superseded_by;
                self.put(&attestation)
            }
            None => Err(StorageError::NotFound(format!("Attestation not found: {:?}", credential_id))),
        }
    }

    // Index helpers
    fn add_to_subject_index(&self, subject_commitment: &[u8; 32], credential_id: &CredentialId) -> Result<()> {
        let mut index = self.get_subject_credentials(subject_commitment)?;
        if !index.contains(credential_id) {
            index.push(*credential_id);
            let bytes = encode_subject_credential_index(&index)?;
            self.db.put(
                cf::DOCCLASS_SUBJECT_INDEX,
                subject_index_key(subject_commitment),
                &bytes,
            )?;
        }
        Ok(())
    }

    fn get_subject_credentials(&self, subject_commitment: &[u8; 32]) -> Result<Vec<CredentialId>> {
        match self.db.get(
            cf::DOCCLASS_SUBJECT_INDEX,
            subject_index_key(subject_commitment),
        )? {
            Some(bytes) => decode_subject_credential_index(&bytes),
            None => Ok(Vec::new()),
        }
    }

    fn add_to_issuer_index(&self, issuer: &Address, credential_id: &CredentialId) -> Result<()> {
        let mut index = self.get_issuer_credentials(issuer)?;
        if !index.contains(credential_id) {
            index.push(*credential_id);
            let bytes = encode_issuer_credential_index(&index)?;
            self.db
                .put(cf::DOCCLASS_ISSUER_INDEX, issuer_index_key(issuer), &bytes)?;
        }
        Ok(())
    }

    fn get_issuer_credentials(&self, issuer: &Address) -> Result<Vec<CredentialId>> {
        match self
            .db
            .get(cf::DOCCLASS_ISSUER_INDEX, issuer_index_key(issuer))?
        {
            Some(bytes) => decode_issuer_credential_index(&bytes),
            None => Ok(Vec::new()),
        }
    }
}

// =============================================================================
// Academic/Professional Credential Storage (SRC-810-813)
// =============================================================================

/// Storage for Academic/Professional Credentials (SRC-810-813)
pub struct CredentialStore<'a> {
    db: &'a Database,
}

impl<'a> CredentialStore<'a> {
    pub fn new(db: &'a Database) -> Self {
        Self { db }
    }

    /// Store an academic/professional credential
    pub fn put(&self, credential: &AcademicCredential) -> Result<()> {
        let bytes = encode_credential(credential)?;
        self.db.put(
            cf::DOCCLASS_CREDENTIALS,
            credential_key(&credential.credential_id),
            &bytes,
        )?;

        // Index by subject commitment
        self.add_to_subject_index(&credential.subject_commitment, &credential.credential_id)?;

        // Index by issuer
        self.add_to_issuer_index(&credential.issuer, &credential.credential_id)?;

        Ok(())
    }

    /// Get a credential by ID
    pub fn get(&self, credential_id: &CredentialId) -> Result<Option<AcademicCredential>> {
        match self
            .db
            .get(cf::DOCCLASS_CREDENTIALS, credential_key(credential_id))?
        {
            Some(bytes) => Ok(Some(decode_credential(&bytes)?)),
            None => Ok(None),
        }
    }

    /// Check if credential exists
    pub fn exists(&self, credential_id: &CredentialId) -> Result<bool> {
        self.db
            .contains(cf::DOCCLASS_CREDENTIALS, credential_key(credential_id))
    }

    /// One bounded page of the credentials a holder address holds within
    /// `subcodes`, in key order (SC-7).
    ///
    /// `docclass_getAcademicCredentialsByHolder` did this as three separate
    /// whole-family `get_by_subcode` scans and filtered each result by holder
    /// afterwards — three scans per call, each returning every credential of
    /// its subcode. Both predicates move inside one scan, so the call costs one
    /// walk and retains at most `limit` credentials.
    pub fn get_by_holder_in_subcodes_paged(
        &self,
        holder: &Address,
        subcodes: &[DocSubcode],
        page: PageSpec,
    ) -> Result<Vec<AcademicCredential>> {
        paged_scan(
            self.db,
            cf::DOCCLASS_CREDENTIALS,
            page,
            |v| decode_credential(v),
            |c: &AcademicCredential| c.subject_address == *holder && subcodes.contains(&c.subcode),
        )
    }

    /// One bounded page of the credentials carrying `subcode`, in key order
    /// (SC-7).
    ///
    /// `docclass_getAcademicCredentialsByHolder` calls this once per subcode,
    /// so the per-call bound is per-subcode: three subcode scans become three
    /// bounded pages rather than three whole-family `Vec`s.
    pub fn get_by_subcode_paged(
        &self,
        subcode: DocSubcode,
        page: PageSpec,
    ) -> Result<Vec<AcademicCredential>> {
        paged_scan(
            self.db,
            cf::DOCCLASS_CREDENTIALS,
            page,
            |v| decode_credential(v),
            |c: &AcademicCredential| c.subcode == subcode,
        )
    }

    /// One bounded page of an issuer's academic credentials, in index order
    /// (SC-7).
    pub fn get_by_issuer_paged(
        &self,
        issuer: &Address,
        page: PageSpec,
    ) -> Result<Vec<AcademicCredential>> {
        let ids = self.get_issuer_credentials(issuer)?;
        paged_resolve(&ids, page, |id| self.get(id), |_| true)
    }

    /// One bounded page of a subject's academic credentials, in index order
    /// (SC-7).
    pub fn get_by_subject_paged(
        &self,
        subject_commitment: &[u8; 32],
        page: PageSpec,
    ) -> Result<Vec<AcademicCredential>> {
        let ids = self.get_subject_credentials(subject_commitment)?;
        paged_resolve(&ids, page, |id| self.get(id), |_| true)
    }

    /// Get credentials by subcode
    pub fn get_by_subcode(&self, subcode: DocSubcode) -> Result<Vec<AcademicCredential>> {
        let mut credentials = Vec::new();

        for (_, value) in self.db.iter(cf::DOCCLASS_CREDENTIALS)? {
            let credential = decode_credential(&value)?;
            if credential.subcode == subcode {
                credentials.push(credential);
            }
        }

        Ok(credentials)
    }

    /// Get credentials by issuer
    pub fn get_by_issuer(&self, issuer: &Address) -> Result<Vec<AcademicCredential>> {
        let credential_ids = self.get_issuer_credentials(issuer)?;
        let mut credentials = Vec::new();

        for credential_id in credential_ids {
            if let Some(credential) = self.get(&credential_id)? {
                credentials.push(credential);
            }
        }

        Ok(credentials)
    }

    /// Get credentials by subject commitment
    pub fn get_by_subject(&self, subject_commitment: &[u8; 32]) -> Result<Vec<AcademicCredential>> {
        let credential_ids = self.get_subject_credentials(subject_commitment)?;
        let mut credentials = Vec::new();

        for credential_id in credential_ids {
            if let Some(credential) = self.get(&credential_id)? {
                credentials.push(credential);
            }
        }

        Ok(credentials)
    }

    /// Get valid credentials for a subject
    pub fn get_valid_for_subject(&self, subject_commitment: &[u8; 32], current_time: Timestamp) -> Result<Vec<AcademicCredential>> {
        let credentials = self.get_by_subject(subject_commitment)?;
        Ok(credentials.into_iter().filter(|c| {
            c.revocation_status == RevocationStatus::Active &&
            (c.expires_at == 0 || c.expires_at > current_time) &&
            c.valid_from <= current_time
        }).collect())
    }

    /// Update revocation status
    pub fn update_revocation(&self, credential_id: &CredentialId, status: RevocationStatus, superseded_by: Option<CredentialId>) -> Result<()> {
        match self.get(credential_id)? {
            Some(mut credential) => {
                credential.revocation_status = status;
                credential.superseded_by = superseded_by;
                self.put(&credential)
            }
            None => Err(StorageError::NotFound(format!("Credential not found: {:?}", credential_id))),
        }
    }

    // Index helpers
    fn add_to_subject_index(&self, subject_commitment: &[u8; 32], credential_id: &CredentialId) -> Result<()> {
        let mut index = self.get_subject_credentials(subject_commitment)?;
        if !index.contains(credential_id) {
            index.push(*credential_id);
            let bytes = encode_subject_credential_index(&index)?;
            self.db.put(
                cf::DOCCLASS_SUBJECT_INDEX,
                subject_index_key(subject_commitment),
                &bytes,
            )?;
        }
        Ok(())
    }

    fn get_subject_credentials(&self, subject_commitment: &[u8; 32]) -> Result<Vec<CredentialId>> {
        match self.db.get(
            cf::DOCCLASS_SUBJECT_INDEX,
            subject_index_key(subject_commitment),
        )? {
            Some(bytes) => decode_subject_credential_index(&bytes),
            None => Ok(Vec::new()),
        }
    }

    fn add_to_issuer_index(&self, issuer: &Address, credential_id: &CredentialId) -> Result<()> {
        let mut index = self.get_issuer_credentials(issuer)?;
        if !index.contains(credential_id) {
            index.push(*credential_id);
            let bytes = encode_issuer_credential_index(&index)?;
            self.db
                .put(cf::DOCCLASS_ISSUER_INDEX, issuer_index_key(issuer), &bytes)?;
        }
        Ok(())
    }

    fn get_issuer_credentials(&self, issuer: &Address) -> Result<Vec<CredentialId>> {
        match self
            .db
            .get(cf::DOCCLASS_ISSUER_INDEX, issuer_index_key(issuer))?
        {
            Some(bytes) => decode_issuer_credential_index(&bytes),
            None => Ok(Vec::new()),
        }
    }
}

// =============================================================================
// Revocation Record Storage (SRC-805)
// =============================================================================

/// Storage for Revocation Records (SRC-805)
pub struct RevocationStore<'a> {
    db: &'a Database,
}

impl<'a> RevocationStore<'a> {
    pub fn new(db: &'a Database) -> Self {
        Self { db }
    }

    /// Store a revocation record
    pub fn put(&self, record: &RevocationRecord) -> Result<()> {
        let key = revocation_key(&record.credential_id, record.revoked_at_height);
        let bytes = encode_revocation_record(record)?;
        self.db.put(cf::DOCCLASS_REVOCATIONS, &key, &bytes)
    }

    /// Get revocation records for a credential
    pub fn get_for_credential(&self, credential_id: &CredentialId) -> Result<Vec<RevocationRecord>> {
        let mut records = Vec::new();

        for (key, value) in self.db.prefix_iter(cf::DOCCLASS_REVOCATIONS, credential_id)? {
            if is_revocation_key_for(&key, credential_id) {
                records.push((key, decode_revocation_record(&value)?));
            }
        }

        // Most recent FIRST, ordered by the KEY rather than by the height it
        // contains: the key is `credential_id || height || [tx_index]`, so a
        // descending key comparison is a descending height comparison that also
        // breaks a tie within one block by transaction order. Identical to the
        // height-only sort for as long as every key is 40 bytes wide, which is
        // every chain below `docclass_revocation_record_enabled_from_height`.
        records.sort_by(|a, b| b.0.cmp(&a.0));

        Ok(records.into_iter().map(|(_, r)| r).collect())
    }

    /// Get the latest revocation record for a credential
    pub fn get_latest(&self, credential_id: &CredentialId) -> Result<Option<RevocationRecord>> {
        let records = self.get_for_credential(credential_id)?;
        Ok(records.into_iter().next())
    }

    /// Check if credential is revoked
    pub fn is_revoked(&self, credential_id: &CredentialId) -> Result<bool> {
        match self.get_latest(credential_id)? {
            Some(record) => Ok(record.status == RevocationStatus::Revoked),
            None => Ok(false),
        }
    }

    /// Get current revocation status
    pub fn get_status(&self, credential_id: &CredentialId) -> Result<RevocationStatus> {
        match self.get_latest(credential_id)? {
            Some(record) => Ok(record.status),
            None => Ok(RevocationStatus::Active),
        }
    }

    /// One bounded page of a revoker's revocation records, in key order
    /// (SC-7). No RPC method reaches this today (DE-12); the bound is here so
    /// that a future `#[method]` cannot expose an unbounded one.
    pub fn get_by_revoker_paged(
        &self,
        revoker: &Address,
        page: PageSpec,
    ) -> Result<Vec<RevocationRecord>> {
        paged_scan(
            self.db,
            cf::DOCCLASS_REVOCATIONS,
            page,
            |v| decode_revocation_record(v),
            |r: &RevocationRecord| r.revoker == *revoker,
        )
    }

    /// Get all revocations by revoker
    pub fn get_by_revoker(&self, revoker: &Address) -> Result<Vec<RevocationRecord>> {
        let mut records = Vec::new();

        for (_, value) in self.db.iter(cf::DOCCLASS_REVOCATIONS)? {
            let record = decode_revocation_record(&value)?;
            if record.revoker == *revoker {
                records.push(record);
            }
        }

        Ok(records)
    }
}

// =============================================================================
// DocClass Issuer Registry Storage
// =============================================================================

/// Storage for DocClass Issuer Registry
pub struct DocClassIssuerStore<'a> {
    db: &'a Database,
}

impl<'a> DocClassIssuerStore<'a> {
    pub fn new(db: &'a Database) -> Self {
        Self { db }
    }

    /// Register or update an issuer
    pub fn put(&self, issuer: &DocClassIssuer) -> Result<()> {
        let bytes = encode_docclass_issuer(issuer)?;
        self.db.put(
            cf::DOCCLASS_ISSUERS,
            docclass_issuer_key(&issuer.address),
            &bytes,
        )
    }

    /// Get an issuer by address
    pub fn get(&self, address: &Address) -> Result<Option<DocClassIssuer>> {
        match self
            .db
            .get(cf::DOCCLASS_ISSUERS, docclass_issuer_key(address))?
        {
            Some(bytes) => Ok(Some(decode_docclass_issuer(&bytes)?)),
            None => Ok(None),
        }
    }

    /// Check if issuer is registered
    pub fn is_registered(&self, address: &Address) -> Result<bool> {
        self.db
            .contains(cf::DOCCLASS_ISSUERS, docclass_issuer_key(address))
    }

    /// Check if issuer is active and can issue credentials
    pub fn can_issue(&self, address: &Address) -> Result<bool> {
        match self.get(address)? {
            Some(issuer) => Ok(issuer.status.can_issue()),
            None => Ok(false),
        }
    }

    /// Check if issuer can issue a specific subcode in a jurisdiction
    pub fn can_issue_subcode(&self, address: &Address, subcode: DocSubcode, jurisdiction: &str) -> Result<bool> {
        match self.get(address)? {
            Some(issuer) => {
                if !issuer.status.can_issue() {
                    return Ok(false);
                }
                // Check if subcode is authorized
                if !issuer.authorized_subcodes.contains(&subcode) {
                    return Ok(false);
                }
                // Check if jurisdiction is authorized (empty list = all jurisdictions)
                if !issuer.jurisdictions.is_empty() &&
                   !issuer.jurisdictions.iter().any(|j| j == jurisdiction || j == "*") {
                    return Ok(false);
                }
                // Check issuer type compatibility
                if !issuer.issuer_type.can_issue(subcode) {
                    return Ok(false);
                }
                Ok(true)
            }
            None => Ok(false),
        }
    }

    /// Update issuer status
    pub fn update_status(&self, address: &Address, status: DocClassIssuerStatus, timestamp: Timestamp) -> Result<()> {
        match self.get(address)? {
            Some(mut issuer) => {
                issuer.status = status;
                issuer.updated_at = timestamp;
                self.put(&issuer)
            }
            None => Err(StorageError::NotFound(format!("Issuer not found: {}", address))),
        }
    }

    /// How many issuers the family holds.
    ///
    /// `docclass_getSummary` wanted this number and got it by building a `Vec`
    /// of every issuer and taking `.len()`. A count is not a page: bounding it
    /// to 100 rows would make the answer WRONG rather than short, so the fix is
    /// to retain nothing instead of to return less.
    pub fn count(&self) -> Result<u64> {
        let mut n = 0u64;
        for entry in self.db.iter_checked_from(cf::DOCCLASS_ISSUERS, None)? {
            let _ = entry?;
            n += 1;
        }
        Ok(n)
    }

    /// One bounded page of registered issuers, in key order (SC-7).
    ///
    /// This is the reader `docclass_getIssuers` takes `limit`/`offset` for.
    /// That method already skipped and took — but only AFTER `get_all` had
    /// built a `Vec` holding every issuer in the family, so the bound it
    /// advertised was on the response and never on the read. The skip and the
    /// take now happen inside the scan, which stops at `offset + limit` rows.
    pub fn get_all_paged(&self, page: PageSpec) -> Result<Vec<DocClassIssuer>> {
        paged_scan(
            self.db,
            cf::DOCCLASS_ISSUERS,
            page,
            |v| decode_docclass_issuer(v),
            |_| true,
        )
    }

    /// One bounded page of issuers that may issue, in key order (SC-7). No RPC
    /// method reaches this today (DE-12).
    pub fn get_active_paged(&self, page: PageSpec) -> Result<Vec<DocClassIssuer>> {
        paged_scan(
            self.db,
            cf::DOCCLASS_ISSUERS,
            page,
            |v| decode_docclass_issuer(v),
            |i: &DocClassIssuer| i.status.can_issue(),
        )
    }

    /// One bounded page of the issuers valid in a jurisdiction, in key order
    /// (SC-7). The predicate is the one `get_by_jurisdiction` applies, moved
    /// inside the scan instead of running over a fully built `get_all`.
    pub fn get_by_jurisdiction_paged(
        &self,
        jurisdiction: &str,
        page: PageSpec,
    ) -> Result<Vec<DocClassIssuer>> {
        paged_scan(
            self.db,
            cf::DOCCLASS_ISSUERS,
            page,
            |v| decode_docclass_issuer(v),
            |i: &DocClassIssuer| {
                i.jurisdictions.is_empty()
                    || i.jurisdictions
                        .iter()
                        .any(|j| j == jurisdiction || j == "*")
            },
        )
    }

    /// One bounded page of the issuers authorised for `subcode`, in key order
    /// (SC-7). No RPC method reaches this today (DE-12).
    pub fn get_by_subcode_paged(
        &self,
        subcode: DocSubcode,
        page: PageSpec,
    ) -> Result<Vec<DocClassIssuer>> {
        paged_scan(
            self.db,
            cf::DOCCLASS_ISSUERS,
            page,
            |v| decode_docclass_issuer(v),
            |i: &DocClassIssuer| i.authorized_subcodes.contains(&subcode),
        )
    }

    /// Get all registered issuers
    pub fn get_all(&self) -> Result<Vec<DocClassIssuer>> {
        let mut issuers = Vec::new();

        for (_, value) in self.db.iter(cf::DOCCLASS_ISSUERS)? {
            issuers.push(decode_docclass_issuer(&value)?);
        }

        Ok(issuers)
    }

    /// Get all active issuers
    pub fn get_active(&self) -> Result<Vec<DocClassIssuer>> {
        let all = self.get_all()?;
        Ok(all.into_iter().filter(|i| i.status.can_issue()).collect())
    }

    /// Get issuers by jurisdiction
    pub fn get_by_jurisdiction(&self, jurisdiction: &str) -> Result<Vec<DocClassIssuer>> {
        let all = self.get_all()?;
        Ok(all.into_iter().filter(|i| {
            i.jurisdictions.is_empty() ||
            i.jurisdictions.iter().any(|j| j == jurisdiction || j == "*")
        }).collect())
    }

    /// Get issuers by authorized subcode
    pub fn get_by_subcode(&self, subcode: DocSubcode) -> Result<Vec<DocClassIssuer>> {
        let all = self.get_all()?;
        Ok(all.into_iter().filter(|i| i.authorized_subcodes.contains(&subcode)).collect())
    }

    /// Delete an issuer
    pub fn delete(&self, address: &Address) -> Result<()> {
        self.db
            .delete(cf::DOCCLASS_ISSUERS, docclass_issuer_key(address))
    }
}

// =============================================================================
// DocClass Event Storage
// =============================================================================

/// Storage for DocClass Events (for indexing/querying)
pub struct DocClassEventStore<'a> {
    db: &'a Database,
}

impl<'a> DocClassEventStore<'a> {
    pub fn new(db: &'a Database) -> Self {
        Self { db }
    }

    /// Store an event
    pub fn put(&self, block_height: BlockHeight, tx_index: u32, event_index: u16, event: &DocClassEvent) -> Result<()> {
        let key = docclass_event_key(block_height, tx_index, event_index);
        let bytes = encode_docclass_event(event)?;
        self.db.put(cf::DOCCLASS_EVENTS, &key, &bytes)
    }

    /// Get events in a block range
    pub fn get_events_in_range(&self, start_height: BlockHeight, end_height: BlockHeight) -> Result<Vec<(BlockHeight, DocClassEvent)>> {
        let mut events = Vec::new();
        let start_key = docclass_event_key(start_height, 0, 0);

        for (key, value) in self.db.prefix_iter(cf::DOCCLASS_EVENTS, &start_key[..8])? {
            if key.len() >= 8 {
                let mut height_bytes = [0u8; 8];
                height_bytes.copy_from_slice(&key[..8]);
                let height = BlockHeight::from_be_bytes(height_bytes);

                if height > end_height {
                    break;
                }

                events.push((height, decode_docclass_event(&value)?));
            }
        }

        Ok(events)
    }

    /// Get events for a specific block
    pub fn get_events_at_height(&self, block_height: BlockHeight) -> Result<Vec<DocClassEvent>> {
        let prefix = block_height.to_be_bytes();
        let mut events = Vec::new();

        for (key, value) in self.db.prefix_iter(cf::DOCCLASS_EVENTS, &prefix)? {
            if key.len() >= 8 && &key[..8] == prefix.as_slice() {
                events.push(decode_docclass_event(&value)?);
            }
        }

        Ok(events)
    }
}

// =============================================================================
// Combined DocClass Store
// =============================================================================

/// Unified DocClass store providing access to all credential types
pub struct DocClassStore<'a> {
    db: &'a Database,
}

impl<'a> DocClassStore<'a> {
    pub fn new(db: &'a Database) -> Self {
        Self { db }
    }

    /// Get identity root store
    pub fn identity_roots(&self) -> IdentityRootStore<'_> {
        IdentityRootStore::new(self.db)
    }

    /// Get eligibility store
    pub fn eligibility(&self) -> EligibilityStore<'_> {
        EligibilityStore::new(self.db)
    }

    /// Get academic/professional credential store
    pub fn credentials(&self) -> CredentialStore<'_> {
        CredentialStore::new(self.db)
    }

    /// Get revocation store
    pub fn revocations(&self) -> RevocationStore<'_> {
        RevocationStore::new(self.db)
    }

    /// Get issuer registry store
    pub fn issuers(&self) -> DocClassIssuerStore<'_> {
        DocClassIssuerStore::new(self.db)
    }

    /// Get event store
    pub fn events(&self) -> DocClassEventStore<'_> {
        DocClassEventStore::new(self.db)
    }

    /// Verify a credential is valid at a given time
    /// Checks: exists, not expired, not revoked, issuer is valid
    pub fn verify_credential(&self, credential_id: &CredentialId, current_time: Timestamp) -> Result<bool> {
        // Check eligibility attestations first
        if let Some(attestation) = self.eligibility().get(credential_id)? {
            // Check expiry
            if attestation.expires_at > 0 && attestation.expires_at <= current_time {
                return Ok(false);
            }
            // Check valid from
            if attestation.valid_from > current_time {
                return Ok(false);
            }
            // Check revocation
            if !attestation.revocation_status.is_valid() {
                return Ok(false);
            }
            // Check issuer is still valid
            if !self.issuers().can_issue(&attestation.issuer)? {
                return Ok(false);
            }
            return Ok(true);
        }

        // Check academic credentials
        if let Some(credential) = self.credentials().get(credential_id)? {
            // Check expiry
            if credential.expires_at > 0 && credential.expires_at <= current_time {
                return Ok(false);
            }
            // Check valid from
            if credential.valid_from > current_time {
                return Ok(false);
            }
            // Check revocation
            if !credential.revocation_status.is_valid() {
                return Ok(false);
            }
            // Check issuer is still valid
            if !self.issuers().can_issue(&credential.issuer)? {
                return Ok(false);
            }
            return Ok(true);
        }

        // Credential not found
        Ok(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Database;
    use tempfile::TempDir;
    use sumchain_primitives::{
        DocClassIssuerType, EligibilityType, IssuerKey, KeyType,
    };

    fn temp_db() -> (Database, TempDir) {
        let dir = TempDir::new().unwrap();
        let db = Database::open_default(dir.path()).unwrap();
        (db, dir)
    }

    fn sample_issuer(address: Address) -> DocClassIssuer {
        DocClassIssuer {
            address,
            name: "Test Issuer".to_string(),
            issuer_type: DocClassIssuerType::Government,
            jurisdictions: vec!["US".to_string()],
            authorized_subcodes: vec![DocSubcode::EligibilityAttestation],
            keys: vec![IssuerKey {
                key_id: "key1".to_string(),
                public_key: [1u8; 32],
                key_type: KeyType::Ed25519,
                added_at: 1000,
                expires_at: 0,
                active: true,
                is_primary: true,
            }],
            registered_at: 1000,
            updated_at: 1000,
            status: DocClassIssuerStatus::Active,
            stake_amount: 0,
            metadata: None,
        }
    }

    #[test]
    fn test_issuer_registration() {
        let (db, _dir) = temp_db();
        let store = DocClassIssuerStore::new(&db);

        let addr = Address::new([1u8; 20]);
        let issuer = sample_issuer(addr);

        store.put(&issuer).unwrap();
        assert!(store.is_registered(&addr).unwrap());

        let retrieved = store.get(&addr).unwrap().unwrap();
        assert_eq!(retrieved.name, "Test Issuer");
        assert!(store.can_issue(&addr).unwrap());
    }

    #[test]
    fn test_issuer_subcode_authorization() {
        let (db, _dir) = temp_db();
        let store = DocClassIssuerStore::new(&db);

        let addr = Address::new([1u8; 20]);
        let issuer = sample_issuer(addr);
        store.put(&issuer).unwrap();

        // Can issue authorized subcode in authorized jurisdiction
        assert!(store.can_issue_subcode(&addr, DocSubcode::EligibilityAttestation, "US").unwrap());

        // Cannot issue unauthorized subcode
        assert!(!store.can_issue_subcode(&addr, DocSubcode::Diploma, "US").unwrap());

        // Cannot issue in unauthorized jurisdiction
        assert!(!store.can_issue_subcode(&addr, DocSubcode::EligibilityAttestation, "UK").unwrap());
    }

    #[test]
    fn test_revocation_tracking() {
        let (db, _dir) = temp_db();
        let store = RevocationStore::new(&db);

        let credential_id = [42u8; 32];
        let record = RevocationRecord {
            credential_id,
            status: RevocationStatus::Revoked,
            reason: sumchain_primitives::RevocationReason::KeyCompromise,
            reason_details: Some("Key was leaked".to_string()),
            revoker: Address::new([1u8; 20]),
            revoked_at: 1234567890,
            revoked_at_height: 100,
            superseded_by: None,
            signature: [0u8; 64],
        };

        store.put(&record).unwrap();

        assert!(store.is_revoked(&credential_id).unwrap());
        assert_eq!(store.get_status(&credential_id).unwrap(), RevocationStatus::Revoked);

        let retrieved = store.get_latest(&credential_id).unwrap().unwrap();
        assert_eq!(retrieved.revoked_at_height, 100);
    }

    #[test]
    fn test_eligibility_attestation_storage() {
        let (db, _dir) = temp_db();
        let store = EligibilityStore::new(&db);

        let subject_commitment = [99u8; 32];
        let attestation = EligibilityAttestation {
            credential_id: [1u8; 32],
            subcode: DocSubcode::EligibilityAttestation,
            subject_commitment,
            subject_address: Address::new([0x36; 20]),
            encryption_meta: None,
            issuer: Address::new([2u8; 20]),
            jurisdiction: "US".to_string(),
            eligibility_type: EligibilityType::Citizenship,
            schema_hash: [3u8; 32],
            content_commitment: [4u8; 32],
            issued_at: 1000,
            valid_from: 1000,
            expires_at: 0,
            payload_hash: None,
            payload_hint: None,
            issuer_signature: [0u8; 64],
            issuer_key_id: "key1".to_string(),
            revocation_status: RevocationStatus::Active,
            superseded_by: None,
        };

        store.put(&attestation).unwrap();

        assert!(store.exists(&attestation.credential_id).unwrap());

        let by_subject = store.get_by_subject(&subject_commitment).unwrap();
        assert_eq!(by_subject.len(), 1);
        assert_eq!(by_subject[0].credential_id, attestation.credential_id);

        let valid = store.get_valid_for_subject(&subject_commitment, 2000).unwrap();
        assert_eq!(valid.len(), 1);
    }
}
