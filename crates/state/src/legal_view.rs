//! SRC-85X legal and benefits, as this block's candidate sees it.
//!
//! The committed twins in `sumchain_storage::legal_store` stay for the RPC
//! server, which answers about the canonical chain: `legal_get_case`,
//! `legal_get_active_cases` and `legal_get_cases_by_jurisdiction` all read
//! `CaseStore` directly and must keep doing so.
//!
//! ## Why the reads move with the writes
//!
//! Every one of the twenty-four legal operations is a read-then-write, and the
//! subsystem is unusual in how MANY of them are pure status transitions:
//! `UpdateCase`, `CloseCase`, `SealCase`, `UnsealCase`, `TransferCase` and
//! `ConsolidateCase` all reduce to "read the case, check the issuer, write the
//! case back with a new status", and orders and benefits each have five more of
//! the same shape. A status transition that reads committed state reads the
//! PARENT block: a case anchored earlier in this block is invisible, so
//! `UpdateCase` refuses it as "Case not found"; and a second transition applied
//! to a case the block already moved recomputes from the stale row and silently
//! drops the first transition's effect.
//!
//! The duplicate guards -- `AnchorCase`, `RecordEvent`, `IssueOrder`,
//! `DetermineBenefit` and `SubmitProof` all refuse an id that already exists --
//! fail the other way round: read against the parent, two anchors of the same
//! case id in one block both pass.
//!
//! And the three index families are accumulating `Vec<[u8; 32]>` values, not
//! presence markers. A second event for one case, read from committed state,
//! would see an empty list and OVERWRITE the first event's index entry with a
//! single-element one. That is the same read-modify-write the tax subject index
//! has, three times over.
//!
//! ## `exists` does not decode, and that is deliberate
//!
//! The duplicate guards call `contains`, never `get`. A corrupt row therefore
//! reads as PRESENT, not as absent, and the guard refuses -- which is the safe
//! direction and is what the committed twin does. The `v_*_exists` accessors
//! below reproduce it exactly rather than upgrading them to a decode, because
//! upgrading would turn a refusal into a block-level error for rows that exist
//! today.
//!
//! ## Behaviours reproduced deliberately, not fixed
//!
//! * `v_put_case` writes the case AND appends its id to the jurisdiction index
//!   under the key `"{jurisdiction}:case"`, de-duplicating by `contains`.
//!   `v_update_case_status` does NOT touch that index, so a case that becomes
//!   `Sealed` stays listed under its jurisdiction; the RPC layer filters sealed
//!   cases out on read. Preserved.
//! * `v_add_related_case` skips the write entirely when the relation is already
//!   recorded, so a repeated consolidation costs a fee and changes nothing.
//!   Preserved.
//! * Nothing here writes `cf::LEGAL_SYSTEM_EVENTS`. `LegalEventStore` exists and
//!   the executor never calls it, so the legal journal is empty on every chain.
//!   Preserved: giving execution a new write is not a migration.

use sumchain_primitives::legal::{
    BenefitDetermination, BenefitStatus, CaseAnchor, CaseStatus, CourtOrder, LegalProofEnvelope,
    OrderStatus, ProcessEvent, ProcessEventStatus,
};
use sumchain_primitives::Timestamp;
use sumchain_storage::cf;
use sumchain_storage::exec_view::ExecutionView;
use sumchain_storage::legal_store::{
    benefit_key, case_event_index_key, case_key, case_order_index_key, decode_benefit, decode_case,
    decode_id_list, decode_order, decode_process_event, decode_proof, encode_benefit, encode_case,
    encode_id_list, encode_order, encode_process_event, encode_proof, jurisdiction_index_key,
    order_key, process_event_key, proof_key, BenefitId, CaseId, OrderId, ProcessEventId, ProofId,
};
use sumchain_storage::StorageError;

use crate::legal_executor::LegalExecutor;
use crate::{Result, StateError};

impl LegalExecutor {
    // ── Cases (SRC-851) ─────────────────────────────────────────────────────

    pub fn v_get_case(
        view: &ExecutionView<'_, '_>,
        case_id: &CaseId,
    ) -> Result<Option<CaseAnchor>> {
        match view
            .get(cf::LEGAL_CASES, case_key(case_id))
            .map_err(StateError::Storage)?
        {
            Some(bytes) => Ok(Some(decode_case(&bytes).map_err(StateError::Storage)?)),
            None => Ok(None),
        }
    }

    /// Presence only. The committed twin uses `contains`, so a corrupt row
    /// answers `true` here rather than erroring -- see this module's header.
    pub fn v_case_exists(view: &ExecutionView<'_, '_>, case_id: &CaseId) -> Result<bool> {
        view.contains(cf::LEGAL_CASES, case_key(case_id))
            .map_err(StateError::Storage)
    }

    /// The case row, and its id appended to the jurisdiction index.
    ///
    /// Two rows, in that order. The index value is an accumulating
    /// `Vec<CaseId>`, so the append is a read-modify-write: a second case in the
    /// same jurisdiction in one block has to see the first one's id or it would
    /// replace the list with a single-element one.
    pub fn v_put_case(view: &mut ExecutionView<'_, '_>, case: &CaseAnchor) -> Result<()> {
        let bytes = encode_case(case).map_err(StateError::Storage)?;
        view.put(cf::LEGAL_CASES, case_key(&case.case_id), &bytes)
            .map_err(StateError::Storage)?;
        Self::v_add_to_jurisdiction_index(view, &case.jurisdiction_code, &case.case_id, "case")
    }

    /// Read, set status and timestamp, write back. Errors when the case is not
    /// there, as the committed twin does -- the callers all check existence
    /// first, so reaching the error means something else went wrong.
    pub fn v_update_case_status(
        view: &mut ExecutionView<'_, '_>,
        case_id: &CaseId,
        status: CaseStatus,
        timestamp: Timestamp,
    ) -> Result<()> {
        match Self::v_get_case(view, case_id)? {
            Some(mut case) => {
                case.status = status;
                case.updated_at = timestamp;
                let bytes = encode_case(&case).map_err(StateError::Storage)?;
                view.put(cf::LEGAL_CASES, case_key(case_id), &bytes)
                    .map_err(StateError::Storage)
            }
            None => Err(StateError::Storage(StorageError::NotFound(format!(
                "Case not found: {case_id:?}"
            )))),
        }
    }

    /// Append a related case id, skipping the write when it is already there.
    ///
    /// The skip is the committed twin's behaviour: a repeated consolidation
    /// leaves the row byte-identical AND leaves `updated_at` alone, because the
    /// timestamp is only written inside the branch that appends.
    pub fn v_add_related_case(
        view: &mut ExecutionView<'_, '_>,
        case_id: &CaseId,
        related_case_id: &CaseId,
        timestamp: Timestamp,
    ) -> Result<()> {
        match Self::v_get_case(view, case_id)? {
            Some(mut case) => {
                if !case.related_cases.contains(related_case_id) {
                    case.related_cases.push(*related_case_id);
                    case.updated_at = timestamp;
                    let bytes = encode_case(&case).map_err(StateError::Storage)?;
                    view.put(cf::LEGAL_CASES, case_key(case_id), &bytes)
                        .map_err(StateError::Storage)?;
                }
                Ok(())
            }
            None => Err(StateError::Storage(StorageError::NotFound(format!(
                "Case not found: {case_id:?}"
            )))),
        }
    }

    // ── The jurisdiction index, shared by cases and benefits ────────────────

    pub fn v_get_jurisdiction_ids(
        view: &ExecutionView<'_, '_>,
        jurisdiction: &str,
        id_type: &str,
    ) -> Result<Vec<[u8; 32]>> {
        match view
            .get(
                cf::LEGAL_JURISDICTION_INDEX,
                &jurisdiction_index_key(jurisdiction, id_type),
            )
            .map_err(StateError::Storage)?
        {
            Some(bytes) => decode_id_list(&bytes).map_err(StateError::Storage),
            None => Ok(Vec::new()),
        }
    }

    /// The STORED length of a jurisdiction-index row, without decoding it.
    ///
    /// ACTIVATION-AUDIT row AL-3. `v_add_to_jurisdiction_index` decodes the
    /// whole row, pushes one 32-byte id and re-encodes the whole row, and
    /// `view.put` only then accounts for a byte. The caller that wants to
    /// refuse an oversized row therefore has to know its size WITHOUT paying
    /// for the decode, and a length is the only thing it needs: `None` for an
    /// absent row, `Some(n)` for one of `n` bytes. The same shape and the same
    /// reasoning as `AgreementView::v_party_index_row_len`.
    pub fn v_jurisdiction_index_row_len(
        view: &ExecutionView<'_, '_>,
        jurisdiction: &str,
        id_type: &str,
    ) -> Result<Option<usize>> {
        Ok(view
            .get(
                cf::LEGAL_JURISDICTION_INDEX,
                &jurisdiction_index_key(jurisdiction, id_type),
            )
            .map_err(StateError::Storage)?
            .map(|bytes| bytes.len()))
    }

    fn v_add_to_jurisdiction_index(
        view: &mut ExecutionView<'_, '_>,
        jurisdiction: &str,
        id: &[u8; 32],
        id_type: &str,
    ) -> Result<()> {
        let mut ids = Self::v_get_jurisdiction_ids(view, jurisdiction, id_type)?;
        // The committed twin skips the write entirely when the id is already
        // listed, rather than rewriting an identical list. Same here: a rewrite
        // would cost candidate bytes for no change.
        if ids.contains(id) {
            return Ok(());
        }
        ids.push(*id);
        let bytes = encode_id_list(&ids).map_err(StateError::Storage)?;
        view.put(
            cf::LEGAL_JURISDICTION_INDEX,
            &jurisdiction_index_key(jurisdiction, id_type),
            &bytes,
        )
        .map_err(StateError::Storage)
    }

    // ── Process events (SRC-852) ────────────────────────────────────────────

    pub fn v_get_process_event(
        view: &ExecutionView<'_, '_>,
        event_id: &ProcessEventId,
    ) -> Result<Option<ProcessEvent>> {
        match view
            .get(cf::LEGAL_EVENTS, process_event_key(event_id))
            .map_err(StateError::Storage)?
        {
            Some(bytes) => Ok(Some(
                decode_process_event(&bytes).map_err(StateError::Storage)?,
            )),
            None => Ok(None),
        }
    }

    pub fn v_process_event_exists(
        view: &ExecutionView<'_, '_>,
        event_id: &ProcessEventId,
    ) -> Result<bool> {
        view.contains(cf::LEGAL_EVENTS, process_event_key(event_id))
            .map_err(StateError::Storage)
    }

    /// The event row, then its id appended to the case→events index.
    pub fn v_put_process_event(
        view: &mut ExecutionView<'_, '_>,
        event: &ProcessEvent,
    ) -> Result<()> {
        let bytes = encode_process_event(event).map_err(StateError::Storage)?;
        view.put(cf::LEGAL_EVENTS, process_event_key(&event.event_id), &bytes)
            .map_err(StateError::Storage)?;
        Self::v_add_to_case_event_index(view, &event.case_id, &event.event_id)
    }

    /// Events carry no `updated_at`, so unlike cases, orders and benefits this
    /// transition writes only the status.
    pub fn v_update_process_event_status(
        view: &mut ExecutionView<'_, '_>,
        event_id: &ProcessEventId,
        status: ProcessEventStatus,
    ) -> Result<()> {
        match Self::v_get_process_event(view, event_id)? {
            Some(mut event) => {
                event.status = status;
                let bytes = encode_process_event(&event).map_err(StateError::Storage)?;
                view.put(cf::LEGAL_EVENTS, process_event_key(event_id), &bytes)
                    .map_err(StateError::Storage)
            }
            None => Err(StateError::Storage(StorageError::NotFound(format!(
                "Process event not found: {event_id:?}"
            )))),
        }
    }

    pub fn v_get_case_event_ids(
        view: &ExecutionView<'_, '_>,
        case_id: &CaseId,
    ) -> Result<Vec<ProcessEventId>> {
        match view
            .get(cf::LEGAL_CASE_EVENT_INDEX, case_event_index_key(case_id))
            .map_err(StateError::Storage)?
        {
            Some(bytes) => decode_id_list(&bytes).map_err(StateError::Storage),
            None => Ok(Vec::new()),
        }
    }

    /// The STORED length of a case-event-index row, without decoding it.
    /// ACTIVATION-AUDIT row AL-3, the second of its three families; same
    /// reasoning as [`Self::v_jurisdiction_index_row_len`].
    pub fn v_case_event_index_row_len(
        view: &ExecutionView<'_, '_>,
        case_id: &CaseId,
    ) -> Result<Option<usize>> {
        Ok(view
            .get(cf::LEGAL_CASE_EVENT_INDEX, case_event_index_key(case_id))
            .map_err(StateError::Storage)?
            .map(|bytes| bytes.len()))
    }

    fn v_add_to_case_event_index(
        view: &mut ExecutionView<'_, '_>,
        case_id: &CaseId,
        event_id: &ProcessEventId,
    ) -> Result<()> {
        let mut ids = Self::v_get_case_event_ids(view, case_id)?;
        if ids.contains(event_id) {
            return Ok(());
        }
        ids.push(*event_id);
        let bytes = encode_id_list(&ids).map_err(StateError::Storage)?;
        view.put(
            cf::LEGAL_CASE_EVENT_INDEX,
            case_event_index_key(case_id),
            &bytes,
        )
        .map_err(StateError::Storage)
    }

    // ── Court orders (SRC-853) ──────────────────────────────────────────────

    pub fn v_get_order(
        view: &ExecutionView<'_, '_>,
        order_id: &OrderId,
    ) -> Result<Option<CourtOrder>> {
        match view
            .get(cf::LEGAL_ORDERS, order_key(order_id))
            .map_err(StateError::Storage)?
        {
            Some(bytes) => Ok(Some(decode_order(&bytes).map_err(StateError::Storage)?)),
            None => Ok(None),
        }
    }

    pub fn v_order_exists(view: &ExecutionView<'_, '_>, order_id: &OrderId) -> Result<bool> {
        view.contains(cf::LEGAL_ORDERS, order_key(order_id))
            .map_err(StateError::Storage)
    }

    /// The order row, then its id appended to the case→orders index.
    pub fn v_put_order(view: &mut ExecutionView<'_, '_>, order: &CourtOrder) -> Result<()> {
        let bytes = encode_order(order).map_err(StateError::Storage)?;
        view.put(cf::LEGAL_ORDERS, order_key(&order.order_id), &bytes)
            .map_err(StateError::Storage)?;
        Self::v_add_to_case_order_index(view, &order.case_id, &order.order_id)
    }

    pub fn v_update_order_status(
        view: &mut ExecutionView<'_, '_>,
        order_id: &OrderId,
        status: OrderStatus,
        timestamp: Timestamp,
    ) -> Result<()> {
        match Self::v_get_order(view, order_id)? {
            Some(mut order) => {
                order.status = status;
                order.updated_at = timestamp;
                let bytes = encode_order(&order).map_err(StateError::Storage)?;
                view.put(cf::LEGAL_ORDERS, order_key(order_id), &bytes)
                    .map_err(StateError::Storage)
            }
            None => Err(StateError::Storage(StorageError::NotFound(format!(
                "Order not found: {order_id:?}"
            )))),
        }
    }

    pub fn v_get_case_order_ids(
        view: &ExecutionView<'_, '_>,
        case_id: &CaseId,
    ) -> Result<Vec<OrderId>> {
        match view
            .get(cf::LEGAL_CASE_ORDER_INDEX, case_order_index_key(case_id))
            .map_err(StateError::Storage)?
        {
            Some(bytes) => decode_id_list(&bytes).map_err(StateError::Storage),
            None => Ok(Vec::new()),
        }
    }

    /// The STORED length of a case-order-index row, without decoding it.
    /// ACTIVATION-AUDIT row AL-3, the third of its three families; same
    /// reasoning as [`Self::v_jurisdiction_index_row_len`].
    pub fn v_case_order_index_row_len(
        view: &ExecutionView<'_, '_>,
        case_id: &CaseId,
    ) -> Result<Option<usize>> {
        Ok(view
            .get(cf::LEGAL_CASE_ORDER_INDEX, case_order_index_key(case_id))
            .map_err(StateError::Storage)?
            .map(|bytes| bytes.len()))
    }

    fn v_add_to_case_order_index(
        view: &mut ExecutionView<'_, '_>,
        case_id: &CaseId,
        order_id: &OrderId,
    ) -> Result<()> {
        let mut ids = Self::v_get_case_order_ids(view, case_id)?;
        if ids.contains(order_id) {
            return Ok(());
        }
        ids.push(*order_id);
        let bytes = encode_id_list(&ids).map_err(StateError::Storage)?;
        view.put(
            cf::LEGAL_CASE_ORDER_INDEX,
            case_order_index_key(case_id),
            &bytes,
        )
        .map_err(StateError::Storage)
    }

    // ── Benefit determinations (SRC-854) ────────────────────────────────────

    pub fn v_get_benefit(
        view: &ExecutionView<'_, '_>,
        benefit_id: &BenefitId,
    ) -> Result<Option<BenefitDetermination>> {
        match view
            .get(cf::LEGAL_BENEFITS, benefit_key(benefit_id))
            .map_err(StateError::Storage)?
        {
            Some(bytes) => Ok(Some(decode_benefit(&bytes).map_err(StateError::Storage)?)),
            None => Ok(None),
        }
    }

    pub fn v_benefit_exists(view: &ExecutionView<'_, '_>, benefit_id: &BenefitId) -> Result<bool> {
        view.contains(cf::LEGAL_BENEFITS, benefit_key(benefit_id))
            .map_err(StateError::Storage)
    }

    /// The benefit row, then its id appended to the jurisdiction index under
    /// `"{jurisdiction}:benefit"` -- the same family cases use, kept apart only
    /// by that suffix.
    pub fn v_put_benefit(
        view: &mut ExecutionView<'_, '_>,
        benefit: &BenefitDetermination,
    ) -> Result<()> {
        let bytes = encode_benefit(benefit).map_err(StateError::Storage)?;
        view.put(cf::LEGAL_BENEFITS, benefit_key(&benefit.benefit_id), &bytes)
            .map_err(StateError::Storage)?;
        Self::v_add_to_jurisdiction_index(
            view,
            &benefit.jurisdiction_code,
            &benefit.benefit_id,
            "benefit",
        )
    }

    pub fn v_update_benefit_status(
        view: &mut ExecutionView<'_, '_>,
        benefit_id: &BenefitId,
        status: BenefitStatus,
        timestamp: Timestamp,
    ) -> Result<()> {
        match Self::v_get_benefit(view, benefit_id)? {
            Some(mut benefit) => {
                benefit.status = status;
                benefit.updated_at = timestamp;
                let bytes = encode_benefit(&benefit).map_err(StateError::Storage)?;
                view.put(cf::LEGAL_BENEFITS, benefit_key(benefit_id), &bytes)
                    .map_err(StateError::Storage)
            }
            None => Err(StateError::Storage(StorageError::NotFound(format!(
                "Benefit not found: {benefit_id:?}"
            )))),
        }
    }

    // ── Legal proofs (SRC-855) ──────────────────────────────────────────────

    pub fn v_get_proof(
        view: &ExecutionView<'_, '_>,
        proof_id: &ProofId,
    ) -> Result<Option<LegalProofEnvelope>> {
        match view
            .get(cf::LEGAL_PROOFS, proof_key(proof_id))
            .map_err(StateError::Storage)?
        {
            Some(bytes) => Ok(Some(decode_proof(&bytes).map_err(StateError::Storage)?)),
            None => Ok(None),
        }
    }

    pub fn v_proof_exists(view: &ExecutionView<'_, '_>, proof_id: &ProofId) -> Result<bool> {
        view.contains(cf::LEGAL_PROOFS, proof_key(proof_id))
            .map_err(StateError::Storage)
    }

    /// One row. Proofs carry a `subject_nullifier` but there is no subject
    /// index for legal proofs: the RPC finds them by scanning the family. That
    /// is a full scan per query and it is the shape this subsystem already has.
    pub fn v_put_proof(view: &mut ExecutionView<'_, '_>, proof: &LegalProofEnvelope) -> Result<()> {
        let bytes = encode_proof(proof).map_err(StateError::Storage)?;
        view.put(cf::LEGAL_PROOFS, proof_key(&proof.proof_id), &bytes)
            .map_err(StateError::Storage)
    }
}
