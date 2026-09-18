//! SRC-80X/81X identity, credential, revocation and issuer rows, as this
//! block's candidate sees them.
//!
//! The committed twins in `sumchain_storage::docclass_store` stay for the RPC
//! server, admission and the operator paths, which answer about the canonical
//! chain.
//!
//! ## Why the reads move with the writes
//!
//! DocClass is a credential registry whose every interesting operation is a
//! read-modify-write or a guard on a row the same block may have just written.
//! Of the nineteen operations, fifteen read a committed row before deciding
//! what to do, and against committed state each one would read the value the
//! block STARTED with.
//!
//! Three shapes make that sharp rather than cosmetic:
//!
//!   * **Read-modify-write on the primary row.** The seven identity operations
//!     (`AddKey`, `RemoveKey`, `RotateKey`, `AddController`, `RemoveController`,
//!     `UpdateService`, plus the two status transitions) each read the identity,
//!     change one field of it, and write the whole row back. Two key additions
//!     in one block only both survive if the second reads the first. The same
//!     holds for `RotateIssuerKey`, which appends to `DocClassIssuer.keys`.
//!   * **Guards that branch on what they read.** `ReactivateCredential` refuses
//!     unless `RevocationStore::get_status` says `Suspended`, so suspend and
//!     reactivate in one block only works if the reactivation sees the
//!     suspension. `IssueCredential` refuses unless
//!     `DocClassIssuerStore::can_issue_subcode` says the sender may -- so
//!     registering an issuer and issuing its first credential in one block only
//!     works if the issue sees the registration. `check_revoke_auth` reads the
//!     credential itself and compares its issuer to the sender.
//!   * **Duplicate guards.** `CreateIdentityRoot`, `RegisterIssuer` and both
//!     issue paths refuse an id that already exists. Against committed state a
//!     block could create the same identity twice.
//!
//! ## What these reproduce exactly, from the shared halves
//!
//! * The key layout: three families keyed by a bare 32-byte credential id, two
//!   by the raw 20 address bytes, one by the 32-byte subject commitment, and two
//!   COMPOSITE keys built by hand -- revocations as
//!   `credential_id || height` and events as `height || tx_index || event_index`,
//!   both big-endian.
//! * The three index VALUES as accumulating lists with `contains` dedup -- a
//!   read-modify-write in their own right.
//! * `DOCCLASS_SUBJECT_INDEX` carrying TWO INCOMPATIBLE value shapes at one key:
//!   `Vec<(CredentialId, DocSubcode)>` from the identity store and
//!   `Vec<CredentialId>` from the other two. Reproduced, not repaired; see
//!   `docs/lane-a/DEPLOYMENT-BLOCKERS.md`.
//! * The `NotFound` error each transition returns for an absent row, spelled
//!   with the same label and the same formatting the committed twin uses --
//!   `{:?}` for the three id-keyed families, `{}` for the address-keyed issuer.

use sumchain_primitives::{
    AcademicCredential, Address, BlockHeight, CredentialId, DocClassEvent, DocClassIssuer,
    DocClassIssuerStatus, DocSubcode, EligibilityAttestation, IdentityRoot, IdentityStatus,
    RevocationRecord, RevocationStatus, Timestamp,
};
use sumchain_storage::cf;
use sumchain_storage::docclass_store::{
    credential_key, decode_credential, decode_docclass_issuer, decode_eligibility,
    decode_identity_root, decode_issuer_credential_index, decode_revocation_record,
    decode_subject_credential_index, decode_subject_identity_index, docclass_event_key,
    docclass_issuer_key, eligibility_key, encode_credential, encode_docclass_event,
    encode_docclass_issuer, encode_eligibility, encode_identity_root,
    encode_issuer_credential_index, encode_revocation_record, encode_subject_credential_index,
    encode_subject_identity_index, identity_root_key, issuer_index_key, revocation_key,
    subject_identity_index_key, subject_index_key, SubjectCommitment,
};
use sumchain_storage::exec_view::ExecutionView;

use crate::docclass_executor::DocClassExecutor;
use crate::{Result, StateError};

/// The committed stores return `StorageError::NotFound` when a transition
/// targets a row that is not there. Reproduced rather than replaced with a
/// state-level error, because the text reaches the caller.
///
/// Two spellings, because the committed twins use two: the id-keyed families
/// format their key with `{:?}` and the issuer registry formats its `Address`
/// with `{}`.
fn not_found_id(what: &str, id: &CredentialId) -> StateError {
    StateError::Storage(sumchain_storage::StorageError::NotFound(format!(
        "{what} not found: {id:?}"
    )))
}

fn not_found_issuer(address: &Address) -> StateError {
    StateError::Storage(sumchain_storage::StorageError::NotFound(format!(
        "Issuer not found: {address}"
    )))
}

impl DocClassExecutor {
    // ── Identity roots, and the subject index ───────────────────────────────

    pub fn v_get_identity_root(
        view: &ExecutionView<'_, '_>,
        identity_id: &CredentialId,
    ) -> Result<Option<IdentityRoot>> {
        match view
            .get(cf::DOCCLASS_IDENTITY_ROOTS, identity_root_key(identity_id))
            .map_err(StateError::Storage)?
        {
            Some(bytes) => Ok(Some(
                decode_identity_root(&bytes).map_err(StateError::Storage)?,
            )),
            None => Ok(None),
        }
    }

    pub fn v_identity_root_exists(
        view: &ExecutionView<'_, '_>,
        identity_id: &CredentialId,
    ) -> Result<bool> {
        view.contains(cf::DOCCLASS_IDENTITY_ROOTS, identity_root_key(identity_id))
            .map_err(StateError::Storage)
    }

    /// The identity row AND its subject-index entry, in that order, as the
    /// committed twin writes them.
    pub fn v_put_identity_root(
        view: &mut ExecutionView<'_, '_>,
        identity: &IdentityRoot,
        split_subject_index: bool,
    ) -> Result<()> {
        let bytes = encode_identity_root(identity).map_err(StateError::Storage)?;
        view.put(
            cf::DOCCLASS_IDENTITY_ROOTS,
            identity_root_key(&identity.identity_id),
            &bytes,
        )
        .map_err(StateError::Storage)?;
        Self::v_add_to_subject_identity_index(
            view,
            &identity.subject_commitment,
            &identity.identity_id,
            DocSubcode::IdentityRoot,
            split_subject_index,
        )
    }

    /// The subject index as the IDENTITY store reads it: `(id, subcode)` pairs.
    ///
    /// The same key can hold a bare `Vec<CredentialId>` written by the
    /// eligibility or credential store, which this decode does not accept. That
    /// is the inherited collision, and it surfaces here as a decode error rather
    /// than as silence.
    /// Reads the split key first, then falls back to the legacy bare key.
    ///
    /// No gate parameter, deliberately: the reader has to answer correctly on
    /// both sides of the activation and for rows written on either side, and
    /// reading the tagged key first does that without being told which side it
    /// is on. The legacy branch keeps its hard decode error, because below the
    /// activation a value of the wrong shape at that key IS the collision, and
    /// hiding it would change what a pre-activation node does.
    pub fn v_get_subject_identity_entries(
        view: &ExecutionView<'_, '_>,
        subject_commitment: &SubjectCommitment,
    ) -> Result<Vec<(CredentialId, DocSubcode)>> {
        if let Some(bytes) = view
            .get(
                cf::DOCCLASS_SUBJECT_INDEX,
                &subject_identity_index_key(subject_commitment),
            )
            .map_err(StateError::Storage)?
        {
            return decode_subject_identity_index(&bytes).map_err(StateError::Storage);
        }
        match view
            .get(
                cf::DOCCLASS_SUBJECT_INDEX,
                subject_index_key(subject_commitment),
            )
            .map_err(StateError::Storage)?
        {
            Some(bytes) => decode_subject_identity_index(&bytes).map_err(StateError::Storage),
            None => Ok(Vec::new()),
        }
    }

    fn v_add_to_subject_identity_index(
        view: &mut ExecutionView<'_, '_>,
        subject_commitment: &SubjectCommitment,
        credential_id: &CredentialId,
        subcode: DocSubcode,
        split_subject_index: bool,
    ) -> Result<()> {
        let mut index = Self::v_get_subject_identity_entries(view, subject_commitment)?;
        let entry = (*credential_id, subcode);
        // The committed twin skips the write entirely when the id is already
        // there rather than rewriting an identical list.
        if index.iter().any(|(id, _)| id == credential_id) {
            return Ok(());
        }
        index.push(entry);
        let bytes = encode_subject_identity_index(&index).map_err(StateError::Storage)?;
        if split_subject_index {
            view.put(
                cf::DOCCLASS_SUBJECT_INDEX,
                &subject_identity_index_key(subject_commitment),
                &bytes,
            )
            .map_err(StateError::Storage)
        } else {
            view.put(
                cf::DOCCLASS_SUBJECT_INDEX,
                subject_index_key(subject_commitment),
                &bytes,
            )
            .map_err(StateError::Storage)
        }
    }

    /// Read, set status and `updated_at`, write through `v_put_identity_root` --
    /// so the subject-index append runs again, exactly as the committed twin's
    /// `update_status` calls its own `put`.
    pub fn v_update_identity_status(
        view: &mut ExecutionView<'_, '_>,
        identity_id: &CredentialId,
        status: IdentityStatus,
        timestamp: Timestamp,
        split_subject_index: bool,
    ) -> Result<()> {
        match Self::v_get_identity_root(view, identity_id)? {
            Some(mut identity) => {
                identity.status = status;
                identity.updated_at = timestamp;
                Self::v_put_identity_root(view, &identity, split_subject_index)
            }
            None => Err(not_found_id("Identity", identity_id)),
        }
    }

    // ── The two credential-id list indexes ──────────────────────────────────
    //
    // `EligibilityStore` and `CredentialStore` carry a private copy each of
    // these four helpers, character for character identical. One candidate copy
    // serves both, because the bytes and the dedup rule are the same; splitting
    // them would be two names for one row layout.

    pub fn v_get_subject_credential_ids(
        view: &ExecutionView<'_, '_>,
        subject_commitment: &SubjectCommitment,
    ) -> Result<Vec<CredentialId>> {
        match view
            .get(
                cf::DOCCLASS_SUBJECT_INDEX,
                subject_index_key(subject_commitment),
            )
            .map_err(StateError::Storage)?
        {
            Some(bytes) => decode_subject_credential_index(&bytes).map_err(StateError::Storage),
            None => Ok(Vec::new()),
        }
    }

    fn v_add_to_subject_credential_index(
        view: &mut ExecutionView<'_, '_>,
        subject_commitment: &SubjectCommitment,
        credential_id: &CredentialId,
    ) -> Result<()> {
        let mut index = Self::v_get_subject_credential_ids(view, subject_commitment)?;
        if index.contains(credential_id) {
            return Ok(());
        }
        index.push(*credential_id);
        let bytes = encode_subject_credential_index(&index).map_err(StateError::Storage)?;
        view.put(
            cf::DOCCLASS_SUBJECT_INDEX,
            subject_index_key(subject_commitment),
            &bytes,
        )
        .map_err(StateError::Storage)
    }

    pub fn v_get_issuer_credential_ids(
        view: &ExecutionView<'_, '_>,
        issuer: &Address,
    ) -> Result<Vec<CredentialId>> {
        match view
            .get(cf::DOCCLASS_ISSUER_INDEX, issuer_index_key(issuer))
            .map_err(StateError::Storage)?
        {
            Some(bytes) => decode_issuer_credential_index(&bytes).map_err(StateError::Storage),
            None => Ok(Vec::new()),
        }
    }

    fn v_add_to_issuer_credential_index(
        view: &mut ExecutionView<'_, '_>,
        issuer: &Address,
        credential_id: &CredentialId,
    ) -> Result<()> {
        let mut index = Self::v_get_issuer_credential_ids(view, issuer)?;
        if index.contains(credential_id) {
            return Ok(());
        }
        index.push(*credential_id);
        let bytes = encode_issuer_credential_index(&index).map_err(StateError::Storage)?;
        view.put(cf::DOCCLASS_ISSUER_INDEX, issuer_index_key(issuer), &bytes)
            .map_err(StateError::Storage)
    }

    // ── Eligibility attestations ────────────────────────────────────────────

    pub fn v_get_eligibility(
        view: &ExecutionView<'_, '_>,
        credential_id: &CredentialId,
    ) -> Result<Option<EligibilityAttestation>> {
        match view
            .get(cf::DOCCLASS_ELIGIBILITY, eligibility_key(credential_id))
            .map_err(StateError::Storage)?
        {
            Some(bytes) => Ok(Some(
                decode_eligibility(&bytes).map_err(StateError::Storage)?,
            )),
            None => Ok(None),
        }
    }

    pub fn v_eligibility_exists(
        view: &ExecutionView<'_, '_>,
        credential_id: &CredentialId,
    ) -> Result<bool> {
        view.contains(cf::DOCCLASS_ELIGIBILITY, eligibility_key(credential_id))
            .map_err(StateError::Storage)
    }

    /// The attestation row, then its SUBJECT index entry, then its ISSUER index
    /// entry. The order is the committed twin's and is load-bearing: a ceiling
    /// that refuses part way through must refuse them in this sequence.
    pub fn v_put_eligibility(
        view: &mut ExecutionView<'_, '_>,
        attestation: &EligibilityAttestation,
    ) -> Result<()> {
        let bytes = encode_eligibility(attestation).map_err(StateError::Storage)?;
        view.put(
            cf::DOCCLASS_ELIGIBILITY,
            eligibility_key(&attestation.credential_id),
            &bytes,
        )
        .map_err(StateError::Storage)?;
        Self::v_add_to_subject_credential_index(
            view,
            &attestation.subject_commitment,
            &attestation.credential_id,
        )?;
        Self::v_add_to_issuer_credential_index(
            view,
            &attestation.issuer,
            &attestation.credential_id,
        )
    }

    /// Set the revocation status and the supersession pointer, then write the
    /// row back THROUGH `v_put_eligibility` -- both index appends run again,
    /// exactly as the committed twin's `update_revocation` calls its own `put`.
    pub fn v_update_eligibility_revocation(
        view: &mut ExecutionView<'_, '_>,
        credential_id: &CredentialId,
        status: RevocationStatus,
        superseded_by: Option<CredentialId>,
    ) -> Result<()> {
        match Self::v_get_eligibility(view, credential_id)? {
            Some(mut attestation) => {
                attestation.revocation_status = status;
                attestation.superseded_by = superseded_by;
                Self::v_put_eligibility(view, &attestation)
            }
            None => Err(not_found_id("Attestation", credential_id)),
        }
    }

    // ── Academic / professional credentials ─────────────────────────────────

    pub fn v_get_credential(
        view: &ExecutionView<'_, '_>,
        credential_id: &CredentialId,
    ) -> Result<Option<AcademicCredential>> {
        match view
            .get(cf::DOCCLASS_CREDENTIALS, credential_key(credential_id))
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
        credential_id: &CredentialId,
    ) -> Result<bool> {
        view.contains(cf::DOCCLASS_CREDENTIALS, credential_key(credential_id))
            .map_err(StateError::Storage)
    }

    /// The credential row, then its SUBJECT index entry, then its ISSUER index
    /// entry -- the same order the eligibility store uses.
    pub fn v_put_credential(
        view: &mut ExecutionView<'_, '_>,
        credential: &AcademicCredential,
    ) -> Result<()> {
        let bytes = encode_credential(credential).map_err(StateError::Storage)?;
        view.put(
            cf::DOCCLASS_CREDENTIALS,
            credential_key(&credential.credential_id),
            &bytes,
        )
        .map_err(StateError::Storage)?;
        Self::v_add_to_subject_credential_index(
            view,
            &credential.subject_commitment,
            &credential.credential_id,
        )?;
        Self::v_add_to_issuer_credential_index(view, &credential.issuer, &credential.credential_id)
    }

    pub fn v_update_credential_revocation(
        view: &mut ExecutionView<'_, '_>,
        credential_id: &CredentialId,
        status: RevocationStatus,
        superseded_by: Option<CredentialId>,
    ) -> Result<()> {
        match Self::v_get_credential(view, credential_id)? {
            Some(mut credential) => {
                credential.revocation_status = status;
                credential.superseded_by = superseded_by;
                Self::v_put_credential(view, &credential)
            }
            None => Err(not_found_id("Credential", credential_id)),
        }
    }

    // ── Revocation records ──────────────────────────────────────────────────

    /// Keyed by `credential_id || revoked_at_height`. Two records for one
    /// credential at the SAME height are ONE row: the second overwrites the
    /// first. Reproduced, not fixed.
    pub fn v_put_revocation_record(
        view: &mut ExecutionView<'_, '_>,
        record: &RevocationRecord,
    ) -> Result<()> {
        let key = revocation_key(&record.credential_id, record.revoked_at_height);
        let bytes = encode_revocation_record(record).map_err(StateError::Storage)?;
        view.put(cf::DOCCLASS_REVOCATIONS, &key, &bytes)
            .map_err(StateError::Storage)
    }

    /// Every record for a credential, most recent height FIRST.
    ///
    /// A prefix scan on the view is MERGED with committed state, so a record
    /// this block staged and one an earlier block published are both here. The
    /// width and prefix filter is the committed twin's: a key that is not
    /// exactly 40 bytes, or whose first 32 do not match, is skipped rather than
    /// decoded -- which is what keeps RocksDB's prefix overrun from turning a
    /// neighbouring credential's record into this one's.
    pub fn v_get_revocations_for_credential(
        view: &ExecutionView<'_, '_>,
        credential_id: &CredentialId,
    ) -> Result<Vec<RevocationRecord>> {
        let mut records = Vec::new();
        for entry in view
            .prefix_iter(cf::DOCCLASS_REVOCATIONS, credential_id)
            .map_err(StateError::Storage)?
        {
            let (key, value) = entry.map_err(StateError::Storage)?;
            if key.len() == 40 && &key[..32] == credential_id {
                records.push(decode_revocation_record(&value).map_err(StateError::Storage)?);
            }
        }
        records.sort_by(|a, b| b.revoked_at_height.cmp(&a.revoked_at_height));
        Ok(records)
    }

    pub fn v_get_latest_revocation(
        view: &ExecutionView<'_, '_>,
        credential_id: &CredentialId,
    ) -> Result<Option<RevocationRecord>> {
        Ok(Self::v_get_revocations_for_credential(view, credential_id)?
            .into_iter()
            .next())
    }

    /// `Active` when no record exists at all -- absence is a status here, which
    /// is why a decode failure must never be allowed to collapse into it.
    pub fn v_get_revocation_status(
        view: &ExecutionView<'_, '_>,
        credential_id: &CredentialId,
    ) -> Result<RevocationStatus> {
        match Self::v_get_latest_revocation(view, credential_id)? {
            Some(record) => Ok(record.status),
            None => Ok(RevocationStatus::Active),
        }
    }

    // ── Issuer registry ─────────────────────────────────────────────────────

    pub fn v_get_docclass_issuer(
        view: &ExecutionView<'_, '_>,
        address: &Address,
    ) -> Result<Option<DocClassIssuer>> {
        match view
            .get(cf::DOCCLASS_ISSUERS, docclass_issuer_key(address))
            .map_err(StateError::Storage)?
        {
            Some(bytes) => Ok(Some(
                decode_docclass_issuer(&bytes).map_err(StateError::Storage)?,
            )),
            None => Ok(None),
        }
    }

    pub fn v_issuer_is_registered(view: &ExecutionView<'_, '_>, address: &Address) -> Result<bool> {
        view.contains(cf::DOCCLASS_ISSUERS, docclass_issuer_key(address))
            .map_err(StateError::Storage)
    }

    /// The issuer row, and no index: the registry writes one family only.
    pub fn v_put_docclass_issuer(
        view: &mut ExecutionView<'_, '_>,
        issuer: &DocClassIssuer,
    ) -> Result<()> {
        let bytes = encode_docclass_issuer(issuer).map_err(StateError::Storage)?;
        view.put(
            cf::DOCCLASS_ISSUERS,
            docclass_issuer_key(&issuer.address),
            &bytes,
        )
        .map_err(StateError::Storage)
    }

    /// The four-part authorization the issue paths consult, in the committed
    /// twin's order: status, then subcode, then jurisdiction, then issuer type.
    ///
    /// An EMPTY `jurisdictions` list means every jurisdiction, and `"*"` matches
    /// anything -- both reproduced.
    pub fn v_can_issue_subcode(
        view: &ExecutionView<'_, '_>,
        address: &Address,
        subcode: DocSubcode,
        jurisdiction: &str,
    ) -> Result<bool> {
        match Self::v_get_docclass_issuer(view, address)? {
            Some(issuer) => {
                if !issuer.status.can_issue() {
                    return Ok(false);
                }
                if !issuer.authorized_subcodes.contains(&subcode) {
                    return Ok(false);
                }
                if !issuer.jurisdictions.is_empty()
                    && !issuer
                        .jurisdictions
                        .iter()
                        .any(|j| j == jurisdiction || j == "*")
                {
                    return Ok(false);
                }
                if !issuer.issuer_type.can_issue(subcode) {
                    return Ok(false);
                }
                Ok(true)
            }
            None => Ok(false),
        }
    }

    pub fn v_update_docclass_issuer_status(
        view: &mut ExecutionView<'_, '_>,
        address: &Address,
        status: DocClassIssuerStatus,
        timestamp: Timestamp,
    ) -> Result<()> {
        match Self::v_get_docclass_issuer(view, address)? {
            Some(mut issuer) => {
                issuer.status = status;
                issuer.updated_at = timestamp;
                Self::v_put_docclass_issuer(view, &issuer)
            }
            None => Err(not_found_issuer(address)),
        }
    }

    // ── Events ──────────────────────────────────────────────────────────────

    /// Keyed by `height || tx_index || event_index`, all big-endian.
    ///
    /// Both dispatch arms pass a literal `0` for `tx_index`, so every DocClass
    /// event in a block lands at the SAME key and only the last one survives.
    /// That is inherited and is pinned as a deployment blocker, not repaired
    /// here.
    pub fn v_put_docclass_event(
        view: &mut ExecutionView<'_, '_>,
        block_height: BlockHeight,
        tx_index: u32,
        event_index: u16,
        event: &DocClassEvent,
    ) -> Result<()> {
        let key = docclass_event_key(block_height, tx_index, event_index);
        let bytes = encode_docclass_event(event).map_err(StateError::Storage)?;
        view.put(cf::DOCCLASS_EVENTS, &key, &bytes)
            .map_err(StateError::Storage)
    }
}
