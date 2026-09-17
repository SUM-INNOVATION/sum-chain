//! SRC-86X property, title, encumbrance and insurance rows, as this block's
//! candidate sees them.
//!
//! The committed twins in `sumchain_storage::property_store` stay for the RPC
//! server, admission and the operator paths, which answer about the canonical
//! chain.
//!
//! ## Why the reads move with the writes
//!
//! Property is a lifecycle registry, and almost every operation is a
//! read-modify-write. Twenty-two of the thirty-one migrated occurrences are
//! transitions that read a row, change its status plus a timestamp, and write
//! it back; against committed state each one would read the value the block
//! STARTED with, so a second transition in the same block would overwrite the
//! first rather than follow it.
//!
//! Three of those transitions are also GUARDED on the state they read, and
//! those are the sharp cases -- they do not merely write a stale row, they take
//! a different branch:
//!
//!   * `ReinstateCoverage` refuses unless the coverage is `Suspended`. Suspend
//!     and reinstate in one block only works if the reinstate sees the suspend.
//!   * `PayClaim` refuses unless the claim is `Approved` or
//!     `PartiallyApproved`. Approve and pay in one block only works if the pay
//!     sees the approval.
//!   * `ReopenClaim` refuses unless the claim is `Closed` or `Denied`.
//!
//! The existence guards are the other half. `RecordTitleEvent`,
//! `RecordEncumbrance` and `IssueCoverage` each refuse unless the asset is
//! there, and `FileClaim` unless the coverage is; anchoring an asset and
//! recording its first title event in one block only works if the second
//! transaction sees the first.
//!
//! ## What these reproduce exactly, from the shared halves
//!
//! * The key layout: ten families keyed by a bare 32-byte id, and the
//!   jurisdiction index keyed by the UTF-8 bytes of a free-form jurisdiction
//!   string.
//! * All five index VALUES as accumulating `Vec<[u8; 32]>` lists with
//!   `contains` dedup -- a read-modify-write in their own right, which is why
//!   two assets in one jurisdiction in one block need the candidate to end up
//!   with both.
//! * The `NotFound` error a transition returns for an absent row, spelled with
//!   the same label and the same `{:?}` formatting the committed twin uses.

use sumchain_primitives::property::{
    AssetAnchor, AssetStatus, ClaimStatus, CoverageStatus, Encumbrance, EncumbranceStatus,
    InsuranceClaim, InsuranceCoverage, PropertyProofEnvelope, TitleEvent, TitleEventStatus,
};
use sumchain_primitives::Timestamp;
use sumchain_storage::cf;
use sumchain_storage::exec_view::ExecutionView;
use sumchain_storage::property_store::{
    asset_coverage_index_key, asset_encumbrance_index_key, asset_key, asset_title_index_key,
    claim_key, coverage_claim_index_key, coverage_key, decode_asset, decode_asset_coverage_ids,
    decode_asset_encumbrance_ids, decode_asset_title_event_ids, decode_claim, decode_coverage,
    decode_coverage_claim_ids, decode_encumbrance, decode_jurisdiction_asset_ids,
    decode_title_event, encode_asset, encode_asset_coverage_ids, encode_asset_encumbrance_ids,
    encode_asset_title_event_ids, encode_claim, encode_coverage, encode_coverage_claim_ids,
    encode_encumbrance, encode_jurisdiction_asset_ids, encode_property_proof, encode_title_event,
    encumbrance_key, jurisdiction_index_key, property_proof_key, title_event_key, AssetId, ClaimId,
    CoverageId, EncumbranceId, ProofId, TitleEventId,
};

use crate::property_executor::PropertyExecutor;
use crate::{Result, StateError};

/// The committed stores return `StorageError::NotFound` when a transition
/// targets a row that is not there. Reproduced rather than replaced with a
/// state-level error, because the text reaches the caller.
fn not_found(what: &str, id: &[u8]) -> StateError {
    StateError::Storage(sumchain_storage::StorageError::NotFound(format!(
        "{what} not found: {id:?}"
    )))
}

impl PropertyExecutor {
    // ── Asset anchors, and the jurisdiction index ───────────────────────────

    pub fn v_get_asset(
        view: &ExecutionView<'_, '_>,
        asset_id: &AssetId,
    ) -> Result<Option<AssetAnchor>> {
        match view
            .get(cf::PROPERTY_ASSETS, asset_key(asset_id))
            .map_err(StateError::Storage)?
        {
            Some(bytes) => Ok(Some(decode_asset(&bytes).map_err(StateError::Storage)?)),
            None => Ok(None),
        }
    }

    pub fn v_asset_exists(view: &ExecutionView<'_, '_>, asset_id: &AssetId) -> Result<bool> {
        view.contains(cf::PROPERTY_ASSETS, asset_key(asset_id))
            .map_err(StateError::Storage)
    }

    /// The asset row AND its jurisdiction-index entry, in that order, as the
    /// committed twin writes them.
    pub fn v_put_asset(view: &mut ExecutionView<'_, '_>, asset: &AssetAnchor) -> Result<()> {
        let bytes = encode_asset(asset).map_err(StateError::Storage)?;
        view.put(cf::PROPERTY_ASSETS, asset_key(&asset.asset_id), &bytes)
            .map_err(StateError::Storage)?;
        Self::v_add_to_jurisdiction_index(view, &asset.jurisdiction_code, &asset.asset_id)
    }

    pub fn v_get_jurisdiction_asset_ids(
        view: &ExecutionView<'_, '_>,
        jurisdiction: &str,
    ) -> Result<Vec<AssetId>> {
        match view
            .get(
                cf::PROPERTY_JURISDICTION_INDEX,
                jurisdiction_index_key(jurisdiction),
            )
            .map_err(StateError::Storage)?
        {
            Some(bytes) => decode_jurisdiction_asset_ids(&bytes).map_err(StateError::Storage),
            None => Ok(Vec::new()),
        }
    }

    fn v_add_to_jurisdiction_index(
        view: &mut ExecutionView<'_, '_>,
        jurisdiction: &str,
        asset_id: &AssetId,
    ) -> Result<()> {
        let mut ids = Self::v_get_jurisdiction_asset_ids(view, jurisdiction)?;
        // The committed twin skips the write entirely when the id is already
        // there rather than rewriting an identical list.
        if ids.contains(asset_id) {
            return Ok(());
        }
        ids.push(*asset_id);
        let bytes = encode_jurisdiction_asset_ids(&ids).map_err(StateError::Storage)?;
        view.put(
            cf::PROPERTY_JURISDICTION_INDEX,
            jurisdiction_index_key(jurisdiction),
            &bytes,
        )
        .map_err(StateError::Storage)
    }

    /// Read, set status and `updated_at`, write. `NotFound` for an absent row.
    pub fn v_update_asset_status(
        view: &mut ExecutionView<'_, '_>,
        asset_id: &AssetId,
        status: AssetStatus,
        timestamp: Timestamp,
    ) -> Result<()> {
        match Self::v_get_asset(view, asset_id)? {
            Some(mut asset) => {
                asset.status = status;
                asset.updated_at = timestamp;
                let bytes = encode_asset(&asset).map_err(StateError::Storage)?;
                view.put(cf::PROPERTY_ASSETS, asset_key(asset_id), &bytes)
                    .map_err(StateError::Storage)
            }
            None => Err(not_found("Asset", asset_id)),
        }
    }

    // ── Title events, and the asset title index ─────────────────────────────

    pub fn v_get_title_event(
        view: &ExecutionView<'_, '_>,
        event_id: &TitleEventId,
    ) -> Result<Option<TitleEvent>> {
        match view
            .get(cf::PROPERTY_TITLE_EVENTS, title_event_key(event_id))
            .map_err(StateError::Storage)?
        {
            Some(bytes) => Ok(Some(
                decode_title_event(&bytes).map_err(StateError::Storage)?,
            )),
            None => Ok(None),
        }
    }

    pub fn v_title_event_exists(
        view: &ExecutionView<'_, '_>,
        event_id: &TitleEventId,
    ) -> Result<bool> {
        view.contains(cf::PROPERTY_TITLE_EVENTS, title_event_key(event_id))
            .map_err(StateError::Storage)
    }

    /// The event row AND its asset-index entry.
    pub fn v_put_title_event(view: &mut ExecutionView<'_, '_>, event: &TitleEvent) -> Result<()> {
        let bytes = encode_title_event(event).map_err(StateError::Storage)?;
        view.put(
            cf::PROPERTY_TITLE_EVENTS,
            title_event_key(&event.event_id),
            &bytes,
        )
        .map_err(StateError::Storage)?;
        Self::v_add_to_asset_title_index(view, &event.asset_id, &event.event_id)
    }

    pub fn v_get_asset_title_event_ids(
        view: &ExecutionView<'_, '_>,
        asset_id: &AssetId,
    ) -> Result<Vec<TitleEventId>> {
        match view
            .get(
                cf::PROPERTY_ASSET_TITLE_INDEX,
                asset_title_index_key(asset_id),
            )
            .map_err(StateError::Storage)?
        {
            Some(bytes) => decode_asset_title_event_ids(&bytes).map_err(StateError::Storage),
            None => Ok(Vec::new()),
        }
    }

    fn v_add_to_asset_title_index(
        view: &mut ExecutionView<'_, '_>,
        asset_id: &AssetId,
        event_id: &TitleEventId,
    ) -> Result<()> {
        let mut ids = Self::v_get_asset_title_event_ids(view, asset_id)?;
        if ids.contains(event_id) {
            return Ok(());
        }
        ids.push(*event_id);
        let bytes = encode_asset_title_event_ids(&ids).map_err(StateError::Storage)?;
        view.put(
            cf::PROPERTY_ASSET_TITLE_INDEX,
            asset_title_index_key(asset_id),
            &bytes,
        )
        .map_err(StateError::Storage)
    }

    /// Note: this writes `created_at`, not `updated_at`. `TitleEvent` has no
    /// `updated_at` field, and the committed twin overwrites the creation
    /// timestamp with the transition's -- reproduced, not corrected.
    pub fn v_update_title_event_status(
        view: &mut ExecutionView<'_, '_>,
        event_id: &TitleEventId,
        status: TitleEventStatus,
        timestamp: Timestamp,
    ) -> Result<()> {
        match Self::v_get_title_event(view, event_id)? {
            Some(mut event) => {
                event.status = status;
                event.created_at = timestamp;
                let bytes = encode_title_event(&event).map_err(StateError::Storage)?;
                view.put(cf::PROPERTY_TITLE_EVENTS, title_event_key(event_id), &bytes)
                    .map_err(StateError::Storage)
            }
            None => Err(not_found("Title event", event_id)),
        }
    }

    // ── Encumbrances, and the asset encumbrance index ───────────────────────

    pub fn v_get_encumbrance(
        view: &ExecutionView<'_, '_>,
        encumbrance_id: &EncumbranceId,
    ) -> Result<Option<Encumbrance>> {
        match view
            .get(cf::PROPERTY_ENCUMBRANCES, encumbrance_key(encumbrance_id))
            .map_err(StateError::Storage)?
        {
            Some(bytes) => Ok(Some(
                decode_encumbrance(&bytes).map_err(StateError::Storage)?,
            )),
            None => Ok(None),
        }
    }

    pub fn v_encumbrance_exists(
        view: &ExecutionView<'_, '_>,
        encumbrance_id: &EncumbranceId,
    ) -> Result<bool> {
        view.contains(cf::PROPERTY_ENCUMBRANCES, encumbrance_key(encumbrance_id))
            .map_err(StateError::Storage)
    }

    /// The encumbrance row AND its asset-index entry.
    pub fn v_put_encumbrance(
        view: &mut ExecutionView<'_, '_>,
        encumbrance: &Encumbrance,
    ) -> Result<()> {
        let bytes = encode_encumbrance(encumbrance).map_err(StateError::Storage)?;
        view.put(
            cf::PROPERTY_ENCUMBRANCES,
            encumbrance_key(&encumbrance.encumbrance_id),
            &bytes,
        )
        .map_err(StateError::Storage)?;
        Self::v_add_to_asset_encumbrance_index(
            view,
            &encumbrance.asset_id,
            &encumbrance.encumbrance_id,
        )
    }

    pub fn v_get_asset_encumbrance_ids(
        view: &ExecutionView<'_, '_>,
        asset_id: &AssetId,
    ) -> Result<Vec<EncumbranceId>> {
        match view
            .get(
                cf::PROPERTY_ASSET_ENCUMBRANCE_INDEX,
                asset_encumbrance_index_key(asset_id),
            )
            .map_err(StateError::Storage)?
        {
            Some(bytes) => decode_asset_encumbrance_ids(&bytes).map_err(StateError::Storage),
            None => Ok(Vec::new()),
        }
    }

    fn v_add_to_asset_encumbrance_index(
        view: &mut ExecutionView<'_, '_>,
        asset_id: &AssetId,
        encumbrance_id: &EncumbranceId,
    ) -> Result<()> {
        let mut ids = Self::v_get_asset_encumbrance_ids(view, asset_id)?;
        if ids.contains(encumbrance_id) {
            return Ok(());
        }
        ids.push(*encumbrance_id);
        let bytes = encode_asset_encumbrance_ids(&ids).map_err(StateError::Storage)?;
        view.put(
            cf::PROPERTY_ASSET_ENCUMBRANCE_INDEX,
            asset_encumbrance_index_key(asset_id),
            &bytes,
        )
        .map_err(StateError::Storage)
    }

    pub fn v_update_encumbrance_status(
        view: &mut ExecutionView<'_, '_>,
        encumbrance_id: &EncumbranceId,
        status: EncumbranceStatus,
        timestamp: Timestamp,
    ) -> Result<()> {
        match Self::v_get_encumbrance(view, encumbrance_id)? {
            Some(mut encumbrance) => {
                encumbrance.status = status;
                encumbrance.updated_at = timestamp;
                let bytes = encode_encumbrance(&encumbrance).map_err(StateError::Storage)?;
                view.put(
                    cf::PROPERTY_ENCUMBRANCES,
                    encumbrance_key(encumbrance_id),
                    &bytes,
                )
                .map_err(StateError::Storage)
            }
            None => Err(not_found("Encumbrance", encumbrance_id)),
        }
    }

    // ── Insurance coverage, and the asset coverage index ────────────────────

    pub fn v_get_coverage(
        view: &ExecutionView<'_, '_>,
        coverage_id: &CoverageId,
    ) -> Result<Option<InsuranceCoverage>> {
        match view
            .get(cf::PROPERTY_COVERAGE, coverage_key(coverage_id))
            .map_err(StateError::Storage)?
        {
            Some(bytes) => Ok(Some(decode_coverage(&bytes).map_err(StateError::Storage)?)),
            None => Ok(None),
        }
    }

    pub fn v_coverage_exists(
        view: &ExecutionView<'_, '_>,
        coverage_id: &CoverageId,
    ) -> Result<bool> {
        view.contains(cf::PROPERTY_COVERAGE, coverage_key(coverage_id))
            .map_err(StateError::Storage)
    }

    /// The coverage row AND its asset-index entry.
    pub fn v_put_coverage(
        view: &mut ExecutionView<'_, '_>,
        coverage: &InsuranceCoverage,
    ) -> Result<()> {
        let bytes = encode_coverage(coverage).map_err(StateError::Storage)?;
        view.put(
            cf::PROPERTY_COVERAGE,
            coverage_key(&coverage.coverage_id),
            &bytes,
        )
        .map_err(StateError::Storage)?;
        Self::v_add_to_asset_coverage_index(view, &coverage.asset_id, &coverage.coverage_id)
    }

    pub fn v_get_asset_coverage_ids(
        view: &ExecutionView<'_, '_>,
        asset_id: &AssetId,
    ) -> Result<Vec<CoverageId>> {
        match view
            .get(
                cf::PROPERTY_ASSET_COVERAGE_INDEX,
                asset_coverage_index_key(asset_id),
            )
            .map_err(StateError::Storage)?
        {
            Some(bytes) => decode_asset_coverage_ids(&bytes).map_err(StateError::Storage),
            None => Ok(Vec::new()),
        }
    }

    fn v_add_to_asset_coverage_index(
        view: &mut ExecutionView<'_, '_>,
        asset_id: &AssetId,
        coverage_id: &CoverageId,
    ) -> Result<()> {
        let mut ids = Self::v_get_asset_coverage_ids(view, asset_id)?;
        if ids.contains(coverage_id) {
            return Ok(());
        }
        ids.push(*coverage_id);
        let bytes = encode_asset_coverage_ids(&ids).map_err(StateError::Storage)?;
        view.put(
            cf::PROPERTY_ASSET_COVERAGE_INDEX,
            asset_coverage_index_key(asset_id),
            &bytes,
        )
        .map_err(StateError::Storage)
    }

    pub fn v_update_coverage_status(
        view: &mut ExecutionView<'_, '_>,
        coverage_id: &CoverageId,
        status: CoverageStatus,
        timestamp: Timestamp,
    ) -> Result<()> {
        match Self::v_get_coverage(view, coverage_id)? {
            Some(mut coverage) => {
                coverage.status = status;
                coverage.updated_at = timestamp;
                let bytes = encode_coverage(&coverage).map_err(StateError::Storage)?;
                view.put(cf::PROPERTY_COVERAGE, coverage_key(coverage_id), &bytes)
                    .map_err(StateError::Storage)
            }
            None => Err(not_found("Coverage", coverage_id)),
        }
    }

    /// Renewal sets the new expiry AND forces the status to `Renewed`. The
    /// committed twin does both; a renewal is not a status update with an extra
    /// field.
    pub fn v_renew_coverage(
        view: &mut ExecutionView<'_, '_>,
        coverage_id: &CoverageId,
        new_expiry: Timestamp,
        timestamp: Timestamp,
    ) -> Result<()> {
        match Self::v_get_coverage(view, coverage_id)? {
            Some(mut coverage) => {
                coverage.expiry = new_expiry;
                coverage.status = CoverageStatus::Renewed;
                coverage.updated_at = timestamp;
                let bytes = encode_coverage(&coverage).map_err(StateError::Storage)?;
                view.put(cf::PROPERTY_COVERAGE, coverage_key(coverage_id), &bytes)
                    .map_err(StateError::Storage)
            }
            None => Err(not_found("Coverage", coverage_id)),
        }
    }

    // ── Insurance claims, and the coverage claim index ──────────────────────

    pub fn v_get_claim(
        view: &ExecutionView<'_, '_>,
        claim_id: &ClaimId,
    ) -> Result<Option<InsuranceClaim>> {
        match view
            .get(cf::PROPERTY_CLAIMS, claim_key(claim_id))
            .map_err(StateError::Storage)?
        {
            Some(bytes) => Ok(Some(decode_claim(&bytes).map_err(StateError::Storage)?)),
            None => Ok(None),
        }
    }

    pub fn v_claim_exists(view: &ExecutionView<'_, '_>, claim_id: &ClaimId) -> Result<bool> {
        view.contains(cf::PROPERTY_CLAIMS, claim_key(claim_id))
            .map_err(StateError::Storage)
    }

    /// The claim row AND its coverage-index entry.
    pub fn v_put_claim(view: &mut ExecutionView<'_, '_>, claim: &InsuranceClaim) -> Result<()> {
        let bytes = encode_claim(claim).map_err(StateError::Storage)?;
        view.put(cf::PROPERTY_CLAIMS, claim_key(&claim.claim_id), &bytes)
            .map_err(StateError::Storage)?;
        Self::v_add_to_coverage_claim_index(view, &claim.coverage_id, &claim.claim_id)
    }

    pub fn v_get_coverage_claim_ids(
        view: &ExecutionView<'_, '_>,
        coverage_id: &CoverageId,
    ) -> Result<Vec<ClaimId>> {
        match view
            .get(
                cf::PROPERTY_COVERAGE_CLAIM_INDEX,
                coverage_claim_index_key(coverage_id),
            )
            .map_err(StateError::Storage)?
        {
            Some(bytes) => decode_coverage_claim_ids(&bytes).map_err(StateError::Storage),
            None => Ok(Vec::new()),
        }
    }

    fn v_add_to_coverage_claim_index(
        view: &mut ExecutionView<'_, '_>,
        coverage_id: &CoverageId,
        claim_id: &ClaimId,
    ) -> Result<()> {
        let mut ids = Self::v_get_coverage_claim_ids(view, coverage_id)?;
        if ids.contains(claim_id) {
            return Ok(());
        }
        ids.push(*claim_id);
        let bytes = encode_coverage_claim_ids(&ids).map_err(StateError::Storage)?;
        view.put(
            cf::PROPERTY_COVERAGE_CLAIM_INDEX,
            coverage_claim_index_key(coverage_id),
            &bytes,
        )
        .map_err(StateError::Storage)
    }

    pub fn v_update_claim_status(
        view: &mut ExecutionView<'_, '_>,
        claim_id: &ClaimId,
        status: ClaimStatus,
        timestamp: Timestamp,
    ) -> Result<()> {
        match Self::v_get_claim(view, claim_id)? {
            Some(mut claim) => {
                claim.status = status;
                claim.updated_at = timestamp;
                let bytes = encode_claim(&claim).map_err(StateError::Storage)?;
                view.put(cf::PROPERTY_CLAIMS, claim_key(claim_id), &bytes)
                    .map_err(StateError::Storage)
            }
            None => Err(not_found("Claim", claim_id)),
        }
    }

    /// Approval records the approved-amount commitment AND forces the status to
    /// `Approved`.
    pub fn v_approve_claim(
        view: &mut ExecutionView<'_, '_>,
        claim_id: &ClaimId,
        approved_amount_commitment: [u8; 32],
        timestamp: Timestamp,
    ) -> Result<()> {
        match Self::v_get_claim(view, claim_id)? {
            Some(mut claim) => {
                claim.approved_amount_commitment = Some(approved_amount_commitment);
                claim.status = ClaimStatus::Approved;
                claim.updated_at = timestamp;
                let bytes = encode_claim(&claim).map_err(StateError::Storage)?;
                view.put(cf::PROPERTY_CLAIMS, claim_key(claim_id), &bytes)
                    .map_err(StateError::Storage)
            }
            None => Err(not_found("Claim", claim_id)),
        }
    }

    /// Payment records the paid-amount commitment AND forces the status to
    /// `Paid`. It does NOT clear the approved-amount commitment.
    pub fn v_pay_claim(
        view: &mut ExecutionView<'_, '_>,
        claim_id: &ClaimId,
        paid_amount_commitment: [u8; 32],
        timestamp: Timestamp,
    ) -> Result<()> {
        match Self::v_get_claim(view, claim_id)? {
            Some(mut claim) => {
                claim.paid_amount_commitment = Some(paid_amount_commitment);
                claim.status = ClaimStatus::Paid;
                claim.updated_at = timestamp;
                let bytes = encode_claim(&claim).map_err(StateError::Storage)?;
                view.put(cf::PROPERTY_CLAIMS, claim_key(claim_id), &bytes)
                    .map_err(StateError::Storage)
            }
            None => Err(not_found("Claim", claim_id)),
        }
    }

    // ── Proofs ──────────────────────────────────────────────────────────────
    //
    // No `v_get_property_proof`: `SubmitProof` guards with `contains` and
    // `VerifyProof` reads nothing at all, so a decoding candidate reader here
    // would be `pub` API no execution path can reach.

    pub fn v_property_proof_exists(
        view: &ExecutionView<'_, '_>,
        proof_id: &ProofId,
    ) -> Result<bool> {
        view.contains(cf::PROPERTY_PROOFS, property_proof_key(proof_id))
            .map_err(StateError::Storage)
    }

    pub fn v_put_property_proof(
        view: &mut ExecutionView<'_, '_>,
        proof: &PropertyProofEnvelope,
    ) -> Result<()> {
        let bytes = encode_property_proof(proof).map_err(StateError::Storage)?;
        view.put(
            cf::PROPERTY_PROOFS,
            property_proof_key(&proof.proof_id),
            &bytes,
        )
        .map_err(StateError::Storage)
    }
}
