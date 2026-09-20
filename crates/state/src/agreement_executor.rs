//! SRC-84X Agreement & IP Executor
//!
//! Transaction executor for:
//! - SRC-841: Agreement Commitments
//! - SRC-842: Party Signatures
//! - SRC-843: Notary & Attestation
//! - SRC-844: IP Rights Actions
//! - SRC-845: Executor Links
//! - SRC-846: Agreement Proofs

use sumchain_storage::exec_view::ExecutionView;

use sumchain_primitives::{
    agreement::{
        AgreementCommitment, AgreementOperation, AgreementProofEnvelope, AgreementStatus,
        AgreementTxData, AttestationPacket, AttestationStatus, ExecutorLink, ExecutorState,
        IpActionStatus, IpRightsAction, PartySignature,
    },
    Address, Balance, BlockHeight, Hash, Timestamp,
};
use tracing::debug;

use sumchain_genesis::ChainParams;

use crate::{Result, StateError, StateManager};

/// Result of Agreement operation execution
#[derive(Debug)]
pub struct AgreementExecutionResult {
    pub success: bool,
    pub agreement_id: Option<[u8; 32]>,
    pub signature_id: Option<[u8; 32]>,
    pub attestation_id: Option<[u8; 32]>,
    pub ip_action_id: Option<[u8; 32]>,
    pub link_id: Option<[u8; 32]>,
    pub proof_id: Option<[u8; 32]>,
    pub error: Option<String>,
}

impl AgreementExecutionResult {
    pub fn success_with_agreement(agreement_id: [u8; 32]) -> Self {
        Self {
            success: true,
            agreement_id: Some(agreement_id),
            signature_id: None,
            attestation_id: None,
            ip_action_id: None,
            link_id: None,
            proof_id: None,
            error: None,
        }
    }

    pub fn success_with_signature(signature_id: [u8; 32]) -> Self {
        Self {
            success: true,
            agreement_id: None,
            signature_id: Some(signature_id),
            attestation_id: None,
            ip_action_id: None,
            link_id: None,
            proof_id: None,
            error: None,
        }
    }

    pub fn success_with_attestation(attestation_id: [u8; 32]) -> Self {
        Self {
            success: true,
            agreement_id: None,
            signature_id: None,
            attestation_id: Some(attestation_id),
            ip_action_id: None,
            link_id: None,
            proof_id: None,
            error: None,
        }
    }

    pub fn success_with_ip_action(ip_action_id: [u8; 32]) -> Self {
        Self {
            success: true,
            agreement_id: None,
            signature_id: None,
            attestation_id: None,
            ip_action_id: Some(ip_action_id),
            link_id: None,
            proof_id: None,
            error: None,
        }
    }

    pub fn success_with_link(link_id: [u8; 32]) -> Self {
        Self {
            success: true,
            agreement_id: None,
            signature_id: None,
            attestation_id: None,
            ip_action_id: None,
            link_id: Some(link_id),
            proof_id: None,
            error: None,
        }
    }

    pub fn success_with_proof(proof_id: [u8; 32]) -> Self {
        Self {
            success: true,
            agreement_id: None,
            signature_id: None,
            attestation_id: None,
            ip_action_id: None,
            link_id: None,
            proof_id: Some(proof_id),
            error: None,
        }
    }

    pub fn success() -> Self {
        Self {
            success: true,
            agreement_id: None,
            signature_id: None,
            attestation_id: None,
            ip_action_id: None,
            link_id: None,
            proof_id: None,
            error: None,
        }
    }

    pub fn failure(error: impl Into<String>) -> Self {
        Self {
            success: false,
            agreement_id: None,
            signature_id: None,
            attestation_id: None,
            ip_action_id: None,
            link_id: None,
            proof_id: None,
            error: Some(error.into()),
        }
    }
}

/// Agreement executor for SRC-84X transactions
/// No database handle, by construction.
///
/// Every operation takes the block's `ExecutionView` and no `self`, so
/// `self.db` is not something this file can name: a committed write here is a
/// compile error rather than a review finding. The committed twins stay in
/// `sumchain_storage::agreement_store` for the RPC server.
pub struct AgreementExecutor;

/// The activation decisions an Agreement transaction executes under.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct AgreementGates {
    /// Executor-written timestamps are the block's, not a literal zero.
    /// ACTIVATION-AUDIT row TS-5.
    pub real_block_timestamp: bool,
    /// Signature rows and the parties' `signed` flags agree.
    /// ACTIVATION-AUDIT rows OV-28 and OV-29.
    pub signature_integrity: bool,
    /// `VerifyProof` refuses as UNSUPPORTED, for every payload.
    /// ACTIVATION-AUDIT AU-12 (= PR-5). Supersedes the retired presence check: no
    /// verifier exists in this tree, so the operation cannot be performed
    /// and must not report success.
    pub proof_unsupported: bool,
    /// An operation that writes nothing reports a failed receipt rather
    /// than a success one. ACTIVATION-AUDIT row OV-30.
    pub no_op_receipt: bool,
    /// An accumulating index row past the limit is refused BEFORE it is
    /// decoded, appended to and re-encoded. ACTIVATION-AUDIT row AL-5.
    pub allocation_bound: bool,
    /// Every arm that needs a party's authority refuses as UNSUPPORTED.
    /// ACTIVATION-AUDIT rows AU-9, AU-10 and AU-11. An agreement records no
    /// party ADDRESS, so there is no sender any of these arms could accept and
    /// no canonical input any stored signature could be checked against.
    pub party_authority_unsupported: bool,
    /// An operation carrying a `policy_id` this chain cannot resolve refuses.
    /// ACTIVATION-AUDIT row AU-8: nothing states whether a `policy_id` names a
    /// policy ACCOUNT or commits to an off-chain policy DOCUMENT, so the claim
    /// is refused rather than guessed at. A zero `policy_id` names no policy
    /// and is unaffected.
    pub policy_id_ambiguous_refused: bool,
}

impl AgreementGates {
    /// Every gate closed -- the release configuration today.
    pub const CLOSED: Self = Self {
        real_block_timestamp: false,
        signature_integrity: false,
        proof_unsupported: false,
        no_op_receipt: false,
        allocation_bound: false,
        policy_id_ambiguous_refused: false,
        party_authority_unsupported: false,
    };

    /// Every gate open. For the gated half of a mixed-version test.
    pub const OPEN: Self = Self {
        real_block_timestamp: true,
        signature_integrity: true,
        proof_unsupported: true,
        no_op_receipt: true,
        allocation_bound: true,
        policy_id_ambiguous_refused: true,
        party_authority_unsupported: true,
    };

    /// Derive the decisions from the chain's parameters at `block_height`.
    pub fn from_params(params: &ChainParams, block_height: BlockHeight) -> Self {
        Self {
            real_block_timestamp: crate::subsystem_block_timestamp_gate_open(params, block_height),
            signature_integrity: AgreementExecutor::signature_integrity_gate_open(
                params,
                block_height,
            ),
            proof_unsupported: crate::subsystem_proof_unsupported_gate_open(params, block_height),
            no_op_receipt: crate::subsystem_no_op_receipt_gate_open(params, block_height),
            allocation_bound: crate::subsystem_allocation_bound_gate_open(params, block_height),
            party_authority_unsupported: AgreementExecutor::party_authority_unsupported_gate_open(
                params,
                block_height,
            ),
            policy_id_ambiguous_refused: crate::subsystem_ambiguous_policy_id_refused_gate_open(
                params,
                block_height,
            ),
        }
    }

    /// The stored-row length limit this gate imposes, or `None` when closed.
    ///
    /// `None` is what the bounded readers in `agreement_view.rs` treat as "no
    /// limit", so a closed gate reads byte-for-byte what the unbounded reader
    /// read. The same spelling `DocClassGates::row_limit` uses, reading the
    /// same constant, because it is the same rule.
    #[inline]
    pub fn row_limit(self) -> Option<usize> {
        self.allocation_bound
            .then_some(crate::MAX_ACCUMULATING_ROW_BYTES)
    }
}

impl AgreementExecutor {
    /// The ACTIVATION-AUDIT row AU-8 refusal, or `None` when the operation
    /// names no policy.
    ///
    /// One helper rather than a copy of the predicate per arm: the arms are
    /// several and the rule is one, and two copies that drifted would refuse
    /// different things under one height.
    #[inline]
    fn ambiguous_policy_refusal(
        gates: AgreementGates,
        policy_id: &[u8; 32],
    ) -> Option<AgreementExecutionResult> {
        if gates.policy_id_ambiguous_refused && policy_id != &crate::UNNAMED_POLICY_ID {
            return Some(AgreementExecutionResult::failure(
                crate::AMBIGUOUS_POLICY_ID_UNRESOLVABLE,
            ));
        }
        None
    }

    /// The activation height for the Agreement signature-integrity rules.
    ///
    /// Reads `params.agreement_signature_integrity_enabled_from_height`, and
    /// nothing else. `None` -- the default, and what a genesis written before
    /// the field existed resolves to -- closes the gate, so a node executes
    /// exactly what it executed before the field was declared.
    ///
    /// Below the gate (ACTIVATION-AUDIT rows OV-28 and OV-29) a signature naming
    /// a party the agreement does not bind is stored anyway and rewrites the
    /// agreement row while flipping no flag, and `RevokeSignature` deletes the
    /// signature row and leaves the party's `signed` flag set. At and above it
    /// the signature must name a bound party, and revoking one clears that
    /// party's flag and walks an `Executed` agreement back to
    /// `PendingSignatures`.
    #[inline]
    fn signature_integrity_activation(params: &ChainParams) -> Option<u64> {
        params.agreement_signature_integrity_enabled_from_height
    }

    /// Whether the Agreement signature-integrity rules are active at
    /// `block_height`.
    #[inline]
    pub fn signature_integrity_gate_open(params: &ChainParams, block_height: BlockHeight) -> bool {
        matches!(Self::signature_integrity_activation(params), Some(h) if block_height >= h)
    }

    /// The activation height for the Agreement party-authority refusal.
    ///
    /// Reads `params.agreement_party_authority_unsupported_enabled_from_height`,
    /// and nothing else. `None` -- the default, and what a genesis written
    /// before the field existed resolves to -- closes the gate, so a node
    /// executes exactly what it executed before the field was declared.
    ///
    /// ACTIVATION-AUDIT rows AU-9, AU-10 and AU-11. Below the gate a signature
    /// names its own party and nothing compares that party to the sender, so
    /// any funded account signs for anybody and carries a two-party agreement
    /// to `Executed` alone; the `signature` bytes it supplies are stored and
    /// checked against nothing; and any funded account terminates, voids or
    /// supersedes any agreement, revokes any IP action, and drives any executor
    /// link through its whole lifecycle. At and above the gate every one of
    /// those arms returns a FAILED receipt carrying
    /// [`crate::AGREEMENT_PARTY_AUTHORITY_UNSUPPORTED`], before the deduct,
    /// where this executor's other refusals already return.
    ///
    /// **Why refusal and not a guard.** `AgreementCommitment` carries no
    /// address, and `PartyRef` is a 32-byte commitment or a 32-byte subject id.
    /// Neither is an `Address` and neither can be mapped to one without
    /// inventing the mapping. Checking the stored `signature` is no better off:
    /// it needs a canonical signing input, and this subsystem defines none.
    /// Both are wire changes to `crates/sumchain-wire/src/agreement.rs`.
    #[inline]
    fn party_authority_unsupported_activation(params: &ChainParams) -> Option<u64> {
        params.agreement_party_authority_unsupported_enabled_from_height
    }

    /// Whether the Agreement party-authority refusal is active at
    /// `block_height`.
    #[inline]
    pub fn party_authority_unsupported_gate_open(
        params: &ChainParams,
        block_height: BlockHeight,
    ) -> bool {
        matches!(Self::party_authority_unsupported_activation(params), Some(h) if block_height >= h)
    }

    /// The refusal every party-authority arm returns at the gate.
    ///
    /// One helper rather than twelve copies of the same `failure(..)`, so the
    /// arms cannot drift into saying different things about one absence.
    #[inline]
    fn party_authority_unsupported() -> AgreementExecutionResult {
        AgreementExecutionResult::failure(crate::AGREEMENT_PARTY_AUTHORITY_UNSUPPORTED)
    }

    /// Execute an Agreement transaction.
    #[allow(clippy::too_many_arguments)]
    pub fn execute(
        view: &mut ExecutionView<'_, '_>,
        params: &ChainParams,
        sender: &Address,
        data: &AgreementTxData,
        proposer: &Address,
        fee: Balance,
        block_height: BlockHeight,
        block_timestamp: Timestamp,
        tx_index: u32,
        tx_hash: Hash,
    ) -> Result<AgreementExecutionResult> {
        Self::execute_with_gates(
            view,
            sender,
            data,
            proposer,
            fee,
            block_height,
            block_timestamp,
            tx_index,
            tx_hash,
            AgreementGates::from_params(params, block_height),
        )
    }

    /// A stored index row longer than the bound, refused without being decoded.
    ///
    /// The DocClass wording verbatim, and for the same reason it gives: one
    /// phrasing across every family so the refusal is greppable, with the
    /// LENGTH in it, because the remedy for a row over the limit is not
    /// "retry".
    fn row_too_large(what: &str, bytes: usize) -> AgreementExecutionResult {
        AgreementExecutionResult::failure(format!(
            "{what} too large to modify: {bytes} bytes, limit {}",
            crate::MAX_ACCUMULATING_ROW_BYTES
        ))
    }

    /// Every party-index row this commitment would append to, checked against
    /// the bound before the first of them is decoded.
    ///
    /// ACTIVATION-AUDIT row AL-5. `v_put_agreement` appends the agreement id to
    /// one accumulating row per party, and each append decodes the whole row,
    /// pushes one 32-byte id and re-encodes the whole row. So one commitment
    /// naming `p` parties does that `p` times, and a row grown below the gate
    /// costs its own size several times over on every later commitment that
    /// names the same party. Checked here, before `v_deduct`, because every
    /// other refusal in this arm is checked there too -- an Agreement refusal
    /// in this subsystem writes nothing at all, and a bound that charged for
    /// the refusal would be the one exception.
    fn party_index_within_bound(
        view: &ExecutionView<'_, '_>,
        agreement: &AgreementCommitment,
        max_bytes: Option<usize>,
    ) -> Result<Option<AgreementExecutionResult>> {
        // No read AT ALL while the gate is closed, not merely no refusal. A
        // read here would move the decode of a corrupt row earlier than the
        // unremediated binary reaches it, and `agreement_routing.rs`'s
        // `corrupt_rows_error_through_dispatch_with_exactly_this_staged` pins
        // exactly which families a corrupt row leaves staged -- which is how
        // that was caught rather than shipped.
        let Some(max) = max_bytes else {
            return Ok(None);
        };
        for party in &agreement.parties {
            if let Some(bytes) = Self::v_party_index_row_len(view, &party.party_ref.as_hash())? {
                if bytes > max {
                    return Ok(Some(Self::row_too_large("Agreement party index", bytes)));
                }
            }
        }
        Ok(None)
    }

    /// The executor-index row this link would append to, checked against the
    /// bound before it is decoded. ACTIVATION-AUDIT row AL-5, executor half.
    fn executor_index_within_bound(
        view: &ExecutionView<'_, '_>,
        executor: &Address,
        max_bytes: Option<usize>,
    ) -> Result<Option<AgreementExecutionResult>> {
        let Some(max) = max_bytes else {
            return Ok(None);
        };
        match Self::v_executor_index_row_len(view, executor)? {
            Some(bytes) if bytes > max => {
                Ok(Some(Self::row_too_large("Agreement executor index", bytes)))
            }
            _ => Ok(None),
        }
    }

    /// Execute an Agreement transaction with the activation decisions supplied
    /// directly. The seam the mixed-version tests use.
    #[allow(clippy::too_many_arguments)]
    pub fn execute_with_gates(
        view: &mut ExecutionView<'_, '_>,
        sender: &Address,
        data: &AgreementTxData,
        proposer: &Address,
        fee: Balance,
        _block_height: BlockHeight,
        block_timestamp: Timestamp,
        _tx_index: u32,
        _tx_hash: Hash,
        gates: AgreementGates,
    ) -> Result<AgreementExecutionResult> {
        let block_timestamp =
            crate::effective_block_timestamp(block_timestamp, gates.real_block_timestamp);

        // ACTIVATION-AUDIT row AL-12, the Agreement third. Every arm below
        // `bincode::deserialize`s `data.data` with no size or shape limit ahead
        // of it, and `CommitAgreement` stores an `AgreementCommitment` whose
        // `parties` list is taken from the payload verbatim -- so one
        // transaction bounded only by `max_block_bytes` decides how many party
        // indexes the next `v_put_agreement` rebuilds, and how large the
        // agreement row every later arm decodes is.
        //
        // This is a refusal, not an error, and the DocClass arm's reasoning
        // applies unchanged: below the gate an undecodable payload is `Err(..)`
        // and takes the whole block with it, and an oversized one that happens
        // to decode is admitted; above the gate an oversized payload is a
        // failed receipt in a valid block whether or not it would have decoded.
        // The refusal charges nothing and does not advance the nonce, because
        // every arm below deducts the fee itself and every pre-existing
        // `failure()` that fires before that deduction is already free.
        if gates.allocation_bound && data.data.len() > crate::MAX_SUBSYSTEM_PAYLOAD_BYTES {
            return Ok(AgreementExecutionResult::failure(format!(
                "Agreement payload too large: {} bytes, limit {}",
                data.data.len(),
                crate::MAX_SUBSYSTEM_PAYLOAD_BYTES
            )));
        }

        // ACTIVATION-AUDIT rows AU-9, AU-10 and AU-11.
        //
        // Every arm named here needs a PARTY's authority and has none to ask
        // for: `AgreementCommitment` carries no address, `PartyRef` is a
        // commitment or a subject id, and the stored `signature` has no
        // canonical input to be checked against. So at and above the gate they
        // refuse as UNSUPPORTED rather than pretend to authorize, and below it
        // they are byte-for-byte the unremediated binary.
        //
        // ONE list, at the top of the dispatch, rather than a branch inside
        // each arm: the claim is that these are one rule, and twelve copies of
        // it would let eleven drift. It is written as an exhaustive `match`
        // with no wildcard so that an operation added to `AgreementOperation`
        // later is a COMPILE ERROR here -- somebody then has to decide which
        // side of this rule it is on, instead of defaulting to reachable.
        //
        // Refused before the payload is even decoded. Every refusal in this
        // executor is free and writes nothing, and this one is the same; it
        // also means an undecodable payload for a gated arm is a failed
        // receipt rather than the `Err(..)` that takes the whole block with it,
        // which is the direction `MAX_SUBSYSTEM_PAYLOAD_BYTES` above already
        // moved this arm.
        //
        // What is deliberately NOT here: `CommitAgreement`, `RecordIpAction`
        // and `LinkExecutor`, which CREATE a row under a fresh id and damage
        // nothing that exists; and the three attestation arms, which already
        // check `issuer_address == sender` and are the reason this defect is
        // specific rather than architectural. The family keeps a way to record
        // an agreement. What it loses is the ability of a stranger to change
        // one.
        //
        // `UpdateAgreement` is here although AU-11 does not name it: it writes
        // an `AgreementStatus` taken straight from the payload over any
        // agreement, so it REACHES `Terminated`, `Voided` and `Superseded` --
        // the three states AU-11 is about -- and a gate that left it open
        // would close nothing. `RevokeSignature` is here for the matching
        // reason on AU-9's side: authorizing the writing of a signature while
        // leaving any sender able to delete one is not an authorization rule.
        if gates.party_authority_unsupported {
            let needs_a_party = match data.operation {
                AgreementOperation::UpdateAgreement
                | AgreementOperation::TerminateAgreement
                | AgreementOperation::VoidAgreement
                | AgreementOperation::SupersedeAgreement
                | AgreementOperation::SignAgreement
                | AgreementOperation::RevokeSignature
                | AgreementOperation::UpdateIpAction
                | AgreementOperation::TerminateIpAction
                | AgreementOperation::RevokeIpAction
                | AgreementOperation::ActivateExecutor
                | AgreementOperation::PauseExecutor
                | AgreementOperation::ResumeExecutor
                | AgreementOperation::TerminateExecutor
                | AgreementOperation::CompleteExecutor => true,
                AgreementOperation::CommitAgreement
                | AgreementOperation::AddParty
                | AgreementOperation::RemoveParty
                | AgreementOperation::CreateAttestation
                | AgreementOperation::RevokeAttestation
                | AgreementOperation::UpdateAttestationStatus
                | AgreementOperation::RecordIpAction
                | AgreementOperation::LinkExecutor
                | AgreementOperation::SubmitProof
                | AgreementOperation::VerifyProof => false,
            };
            if needs_a_party {
                return Ok(Self::party_authority_unsupported());
            }
        }

        match data.operation {
            // SRC-841: Agreement Commitment Operations
            AgreementOperation::CommitAgreement => {
                let agreement: AgreementCommitment = bincode::deserialize(&data.data)
                    .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

                // ACTIVATION-AUDIT row AU-8: a `policy_id` this chain cannot
                // resolve is a claim it cannot back, so it is refused ahead of
                // the deduct rather than stored. Zero names no policy.
                if let Some(refusal) = Self::ambiguous_policy_refusal(gates, &agreement.policy_id) {
                    return Ok(refusal);
                }

                if Self::v_agreement_exists(view, &agreement.agreement_id)? {
                    return Ok(AgreementExecutionResult::failure("Agreement already exists"));
                }

                // ACTIVATION-AUDIT row AL-5, the party-index half.
                if let Some(refusal) =
                    Self::party_index_within_bound(view, &agreement, gates.row_limit())?
                {
                    return Ok(refusal);
                }

                StateManager::v_deduct(view, sender, fee)?;
                StateManager::v_credit(view, proposer, fee)?;
                StateManager::v_increment_nonce(view, sender)?;
                let agreement_id = agreement.agreement_id;
                Self::v_put_agreement(view, &agreement)?;
                debug!("Agreement committed: {:?}", agreement_id);
                Ok(AgreementExecutionResult::success_with_agreement(agreement_id))
            }

            AgreementOperation::UpdateAgreement => {
                #[derive(serde::Deserialize)]
                struct UpdateData {
                    agreement_id: [u8; 32],
                    status: AgreementStatus,
                }
                let update: UpdateData = bincode::deserialize(&data.data)
                    .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

                if Self::v_get_agreement(view, &update.agreement_id)?.is_none() {
                    return Ok(AgreementExecutionResult::failure("Agreement not found"));
                }

                StateManager::v_deduct(view, sender, fee)?;
                StateManager::v_credit(view, proposer, fee)?;
                StateManager::v_increment_nonce(view, sender)?;
                Self::v_update_agreement_status(
                    view,
                    &update.agreement_id,
                    update.status,
                    block_timestamp,
                )?;
                Ok(AgreementExecutionResult::success())
            }

            AgreementOperation::TerminateAgreement | AgreementOperation::VoidAgreement => {
                #[derive(serde::Deserialize)]
                struct TerminateData {
                    agreement_id: [u8; 32],
                }
                let d: TerminateData = bincode::deserialize(&data.data)
                    .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

                if Self::v_get_agreement(view, &d.agreement_id)?.is_none() {
                    return Ok(AgreementExecutionResult::failure("Agreement not found"));
                }

                let new_status = if data.operation == AgreementOperation::TerminateAgreement {
                    AgreementStatus::Terminated
                } else {
                    AgreementStatus::Voided
                };

                StateManager::v_deduct(view, sender, fee)?;
                StateManager::v_credit(view, proposer, fee)?;
                StateManager::v_increment_nonce(view, sender)?;
                Self::v_update_agreement_status(
                    view,
                    &d.agreement_id,
                    new_status,
                    block_timestamp,
                )?;
                Ok(AgreementExecutionResult::success())
            }

            AgreementOperation::SupersedeAgreement => {
                #[derive(serde::Deserialize)]
                struct SupersedeData {
                    old_agreement_id: [u8; 32],
                    new_agreement: AgreementCommitment,
                }
                let d: SupersedeData = bincode::deserialize(&data.data)
                    .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

                // ACTIVATION-AUDIT row AU-8: a `policy_id` this chain cannot
                // resolve is a claim it cannot back, so it is refused ahead of
                // the deduct rather than stored. Zero names no policy.
                if let Some(refusal) =
                    Self::ambiguous_policy_refusal(gates, &d.new_agreement.policy_id)
                {
                    return Ok(refusal);
                }

                if Self::v_get_agreement(view, &d.old_agreement_id)?.is_none() {
                    return Ok(AgreementExecutionResult::failure("Old agreement not found"));
                }

                // ACTIVATION-AUDIT row AL-5. The supersede arm writes a SECOND
                // commitment through the same `v_put_agreement`, so it appends
                // to the same party-index rows and is bounded by the same rule.
                if let Some(refusal) =
                    Self::party_index_within_bound(view, &d.new_agreement, gates.row_limit())?
                {
                    return Ok(refusal);
                }

                StateManager::v_deduct(view, sender, fee)?;
                StateManager::v_credit(view, proposer, fee)?;
                StateManager::v_increment_nonce(view, sender)?;

                // Mark old as superseded
                Self::v_update_agreement_status(
                    view,
                    &d.old_agreement_id,
                    AgreementStatus::Superseded,
                    block_timestamp,
                )?;

                // Store new agreement
                let new_id = d.new_agreement.agreement_id;
                Self::v_put_agreement(view, &d.new_agreement)?;
                debug!("Agreement superseded: {:?} -> {:?}", d.old_agreement_id, new_id);
                Ok(AgreementExecutionResult::success_with_agreement(new_id))
            }

            // SRC-842: Party Signature Operations
            AgreementOperation::SignAgreement => {
                let signature: PartySignature = bincode::deserialize(&data.data)
                    .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

                // Verify agreement exists
                if Self::v_get_agreement(view, &signature.agreement_id)?.is_none() {
                    return Ok(AgreementExecutionResult::failure("Agreement not found"));
                }

                if Self::v_signature_exists(view, &signature.signature_id)? {
                    return Ok(AgreementExecutionResult::failure("Signature already exists"));
                }

                // OV-28: below the gate a signature naming a party the agreement
                // does not bind is stored anyway, and `v_mark_party_signed`
                // rewrites the agreement row -- bumping `updated_at` -- while
                // matching nobody and flipping no flag. The signature family then
                // holds rows for parties the agreement has never heard of.
                if gates.signature_integrity {
                    let party_hash = signature.party_ref.as_hash();
                    let agreement = match Self::v_get_agreement(view, &signature.agreement_id)? {
                        Some(a) => a,
                        None => {
                            return Ok(AgreementExecutionResult::failure("Agreement not found"))
                        }
                    };
                    if !agreement
                        .parties
                        .iter()
                        .any(|p| p.party_ref.as_hash() == party_hash)
                    {
                        return Ok(AgreementExecutionResult::failure(
                            "Signer is not a party to this agreement",
                        ));
                    }
                }

                StateManager::v_deduct(view, sender, fee)?;
                StateManager::v_credit(view, proposer, fee)?;
                StateManager::v_increment_nonce(view, sender)?;

                let sig_id = signature.signature_id;
                let agreement_id = signature.agreement_id;
                let party_hash = signature.party_ref.as_hash();

                Self::v_put_signature(view, &signature)?;
                Self::v_mark_party_signed(view, &agreement_id, &party_hash, block_timestamp)?;

                debug!("Agreement signed: {:?} by party {:?}", agreement_id, party_hash);
                Ok(AgreementExecutionResult::success_with_signature(sig_id))
            }

            AgreementOperation::RevokeSignature => {
                #[derive(serde::Deserialize)]
                struct RevokeData {
                    signature_id: [u8; 32],
                }
                let d: RevokeData = bincode::deserialize(&data.data)
                    .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

                let existing = match Self::v_get_signature(view, &d.signature_id)? {
                    Some(sig) => sig,
                    None => return Ok(AgreementExecutionResult::failure("Signature not found")),
                };

                StateManager::v_deduct(view, sender, fee)?;
                StateManager::v_credit(view, proposer, fee)?;
                StateManager::v_increment_nonce(view, sender)?;
                Self::v_delete_signature(view, &d.signature_id)?;
                // OV-29: below the gate the signature row goes and the party's
                // `signed` flag stays, so an agreement promoted to `Executed` by
                // that very signature stays `Executed` with the signature gone,
                // and nothing anywhere recomputes it.
                if gates.signature_integrity {
                    Self::v_unmark_party_signed(
                        view,
                        &existing.agreement_id,
                        &existing.party_ref.as_hash(),
                        block_timestamp,
                    )?;
                }
                Ok(AgreementExecutionResult::success())
            }

            AgreementOperation::AddParty | AgreementOperation::RemoveParty => {
                // These would require updating agreement parties
                //
                // ACTIVATION-AUDIT row OV-30. That comment is the whole
                // implementation: below the gate this arm charges the fee,
                // advances the nonce and returns SUCCESS, having touched no
                // agreement and no party. At and above the gate it says so.
                //
                // A failed receipt, not an implementation: `AgreementCommitment`
                // defines no add-party or remove-party semantics, and inventing
                // one inside an executor would be a rule nobody set. Refused
                // before the deduct, where this file's other refusals return.
                if gates.no_op_receipt {
                    return Ok(AgreementExecutionResult::failure(
                        "AddParty and RemoveParty are not implemented and change no party",
                    ));
                }
                StateManager::v_deduct(view, sender, fee)?;
                StateManager::v_credit(view, proposer, fee)?;
                StateManager::v_increment_nonce(view, sender)?;
                debug!("Party operation requested by: {}", sender);
                Ok(AgreementExecutionResult::success())
            }

            // SRC-843: Attestation Operations
            AgreementOperation::CreateAttestation => {
                let attestation: AttestationPacket = bincode::deserialize(&data.data)
                    .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

                // ACTIVATION-AUDIT row AU-8: a `policy_id` this chain cannot
                // resolve is a claim it cannot back, so it is refused ahead of
                // the deduct rather than stored. Zero names no policy.
                if let Some(refusal) = Self::ambiguous_policy_refusal(gates, &attestation.policy_id)
                {
                    return Ok(refusal);
                }

                if attestation.issuer_address != *sender {
                    return Ok(AgreementExecutionResult::failure("Issuer must be sender"));
                }

                if Self::v_attestation_exists(view, &attestation.attestation_id)? {
                    return Ok(AgreementExecutionResult::failure("Attestation already exists"));
                }

                StateManager::v_deduct(view, sender, fee)?;
                StateManager::v_credit(view, proposer, fee)?;
                StateManager::v_increment_nonce(view, sender)?;
                let att_id = attestation.attestation_id;
                Self::v_put_attestation(view, &attestation)?;
                debug!("Attestation created: {:?}", att_id);
                Ok(AgreementExecutionResult::success_with_attestation(att_id))
            }

            AgreementOperation::RevokeAttestation => {
                #[derive(serde::Deserialize)]
                struct RevokeData {
                    attestation_id: [u8; 32],
                }
                let d: RevokeData = bincode::deserialize(&data.data)
                    .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

                let att = match Self::v_get_attestation(view, &d.attestation_id)? {
                    Some(a) => a,
                    None => return Ok(AgreementExecutionResult::failure("Attestation not found")),
                };

                if att.issuer_address != *sender {
                    return Ok(AgreementExecutionResult::failure("Only issuer can revoke"));
                }

                StateManager::v_deduct(view, sender, fee)?;
                StateManager::v_credit(view, proposer, fee)?;
                StateManager::v_increment_nonce(view, sender)?;
                Self::v_update_attestation_status(
                    view,
                    &d.attestation_id,
                    AttestationStatus::Revoked,
                )?;
                Ok(AgreementExecutionResult::success())
            }

            AgreementOperation::UpdateAttestationStatus => {
                #[derive(serde::Deserialize)]
                struct UpdateData {
                    attestation_id: [u8; 32],
                    status: AttestationStatus,
                }
                let d: UpdateData = bincode::deserialize(&data.data)
                    .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

                let att = match Self::v_get_attestation(view, &d.attestation_id)? {
                    Some(a) => a,
                    None => return Ok(AgreementExecutionResult::failure("Attestation not found")),
                };

                if att.issuer_address != *sender {
                    return Ok(AgreementExecutionResult::failure("Only issuer can update"));
                }

                StateManager::v_deduct(view, sender, fee)?;
                StateManager::v_credit(view, proposer, fee)?;
                StateManager::v_increment_nonce(view, sender)?;
                Self::v_update_attestation_status(view, &d.attestation_id, d.status)?;
                Ok(AgreementExecutionResult::success())
            }

            // SRC-844: IP Rights Operations
            AgreementOperation::RecordIpAction => {
                let action: IpRightsAction = bincode::deserialize(&data.data)
                    .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

                // ACTIVATION-AUDIT row AU-8: a `policy_id` this chain cannot
                // resolve is a claim it cannot back, so it is refused ahead of
                // the deduct rather than stored. Zero names no policy.
                if let Some(refusal) = Self::ambiguous_policy_refusal(gates, &action.policy_id) {
                    return Ok(refusal);
                }

                if Self::v_ip_action_exists(view, &action.action_id)? {
                    return Ok(AgreementExecutionResult::failure("IP action already exists"));
                }

                StateManager::v_deduct(view, sender, fee)?;
                StateManager::v_credit(view, proposer, fee)?;
                StateManager::v_increment_nonce(view, sender)?;
                let action_id = action.action_id;
                Self::v_put_ip_action(view, &action)?;
                debug!("IP action recorded: {:?}", action_id);
                Ok(AgreementExecutionResult::success_with_ip_action(action_id))
            }

            AgreementOperation::UpdateIpAction | AgreementOperation::TerminateIpAction | AgreementOperation::RevokeIpAction => {
                #[derive(serde::Deserialize)]
                struct UpdateData {
                    action_id: [u8; 32],
                }
                let d: UpdateData = bincode::deserialize(&data.data)
                    .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

                if Self::v_get_ip_action(view, &d.action_id)?.is_none() {
                    return Ok(AgreementExecutionResult::failure("IP action not found"));
                }

                let new_status = match data.operation {
                    AgreementOperation::TerminateIpAction => IpActionStatus::Terminated,
                    AgreementOperation::RevokeIpAction => IpActionStatus::Revoked,
                    _ => IpActionStatus::Active,
                };

                StateManager::v_deduct(view, sender, fee)?;
                StateManager::v_credit(view, proposer, fee)?;
                StateManager::v_increment_nonce(view, sender)?;
                Self::v_update_ip_action_status(view, &d.action_id, new_status)?;
                Ok(AgreementExecutionResult::success())
            }

            // SRC-845: Executor Link Operations
            AgreementOperation::LinkExecutor => {
                let link: ExecutorLink = bincode::deserialize(&data.data)
                    .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

                // ACTIVATION-AUDIT row AU-8: a `policy_id` this chain cannot
                // resolve is a claim it cannot back, so it is refused ahead of
                // the deduct rather than stored. Zero names no policy.
                if let Some(refusal) =
                    Self::ambiguous_policy_refusal(gates, &link.activation_policy_id)
                {
                    return Ok(refusal);
                }

                // Verify agreement exists
                if Self::v_get_agreement(view, &link.agreement_id)?.is_none() {
                    return Ok(AgreementExecutionResult::failure("Agreement not found"));
                }

                if Self::v_executor_link_exists(view, &link.link_id)? {
                    return Ok(AgreementExecutionResult::failure("Executor link already exists"));
                }

                // ACTIVATION-AUDIT row AL-5, the executor-index half.
                if let Some(refusal) = Self::executor_index_within_bound(
                    view,
                    &link.executor_contract,
                    gates.row_limit(),
                )? {
                    return Ok(refusal);
                }

                StateManager::v_deduct(view, sender, fee)?;
                StateManager::v_credit(view, proposer, fee)?;
                StateManager::v_increment_nonce(view, sender)?;
                let link_id = link.link_id;
                Self::v_put_executor_link(view, &link)?;
                debug!("Executor linked: {:?}", link_id);
                Ok(AgreementExecutionResult::success_with_link(link_id))
            }

            AgreementOperation::ActivateExecutor => {
                #[derive(serde::Deserialize)]
                struct ActivateData {
                    link_id: [u8; 32],
                }
                let d: ActivateData = bincode::deserialize(&data.data)
                    .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

                let link = match Self::v_get_executor_link(view, &d.link_id)? {
                    Some(l) => l,
                    None => return Ok(AgreementExecutionResult::failure("Executor link not found")),
                };

                if link.state != ExecutorState::Draft {
                    return Ok(AgreementExecutionResult::failure("Can only activate draft executors"));
                }

                StateManager::v_deduct(view, sender, fee)?;
                StateManager::v_credit(view, proposer, fee)?;
                StateManager::v_increment_nonce(view, sender)?;
                Self::v_update_executor_state(
                    view,
                    &d.link_id,
                    ExecutorState::Active,
                    block_timestamp,
                )?;
                debug!("Executor activated: {:?}", d.link_id);
                Ok(AgreementExecutionResult::success())
            }

            AgreementOperation::PauseExecutor => {
                #[derive(serde::Deserialize)]
                struct PauseData {
                    link_id: [u8; 32],
                }
                let d: PauseData = bincode::deserialize(&data.data)
                    .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

                if Self::v_get_executor_link(view, &d.link_id)?.is_none() {
                    return Ok(AgreementExecutionResult::failure("Executor link not found"));
                }

                StateManager::v_deduct(view, sender, fee)?;
                StateManager::v_credit(view, proposer, fee)?;
                StateManager::v_increment_nonce(view, sender)?;
                Self::v_update_executor_state(
                    view,
                    &d.link_id,
                    ExecutorState::Paused,
                    block_timestamp,
                )?;
                Ok(AgreementExecutionResult::success())
            }

            AgreementOperation::ResumeExecutor => {
                #[derive(serde::Deserialize)]
                struct ResumeData {
                    link_id: [u8; 32],
                }
                let d: ResumeData = bincode::deserialize(&data.data)
                    .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

                let link = match Self::v_get_executor_link(view, &d.link_id)? {
                    Some(l) => l,
                    None => return Ok(AgreementExecutionResult::failure("Executor link not found")),
                };

                if link.state != ExecutorState::Paused {
                    return Ok(AgreementExecutionResult::failure("Can only resume paused executors"));
                }

                StateManager::v_deduct(view, sender, fee)?;
                StateManager::v_credit(view, proposer, fee)?;
                StateManager::v_increment_nonce(view, sender)?;
                Self::v_update_executor_state(
                    view,
                    &d.link_id,
                    ExecutorState::Active,
                    block_timestamp,
                )?;
                Ok(AgreementExecutionResult::success())
            }

            AgreementOperation::TerminateExecutor => {
                #[derive(serde::Deserialize)]
                struct TerminateData {
                    link_id: [u8; 32],
                }
                let d: TerminateData = bincode::deserialize(&data.data)
                    .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

                if Self::v_get_executor_link(view, &d.link_id)?.is_none() {
                    return Ok(AgreementExecutionResult::failure("Executor link not found"));
                }

                StateManager::v_deduct(view, sender, fee)?;
                StateManager::v_credit(view, proposer, fee)?;
                StateManager::v_increment_nonce(view, sender)?;
                Self::v_update_executor_state(
                    view,
                    &d.link_id,
                    ExecutorState::Terminated,
                    block_timestamp,
                )?;
                Ok(AgreementExecutionResult::success())
            }

            AgreementOperation::CompleteExecutor => {
                #[derive(serde::Deserialize)]
                struct CompleteData {
                    link_id: [u8; 32],
                }
                let d: CompleteData = bincode::deserialize(&data.data)
                    .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

                if Self::v_get_executor_link(view, &d.link_id)?.is_none() {
                    return Ok(AgreementExecutionResult::failure("Executor link not found"));
                }

                StateManager::v_deduct(view, sender, fee)?;
                StateManager::v_credit(view, proposer, fee)?;
                StateManager::v_increment_nonce(view, sender)?;
                Self::v_update_executor_state(
                    view,
                    &d.link_id,
                    ExecutorState::Completed,
                    block_timestamp,
                )?;
                Ok(AgreementExecutionResult::success())
            }

            // SRC-846: Proof Operations
            AgreementOperation::SubmitProof => {
                let proof: AgreementProofEnvelope = bincode::deserialize(&data.data)
                    .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

                if Self::v_proof_exists(view, &proof.proof_id)? {
                    return Ok(AgreementExecutionResult::failure("Proof already exists"));
                }

                StateManager::v_deduct(view, sender, fee)?;
                StateManager::v_credit(view, proposer, fee)?;
                StateManager::v_increment_nonce(view, sender)?;
                let proof_id = proof.proof_id;
                Self::v_put_proof(view, &proof)?;
                debug!("Agreement proof submitted: {:?}", proof_id);
                Ok(AgreementExecutionResult::success_with_proof(proof_id))
            }

            AgreementOperation::VerifyProof => {
                // ACTIVATION-AUDIT AU-12 (= PR-5). Below the gate this arm reads no
                // payload and no proof and returns SUCCESS, so the chain reports a
                // verified proof for a proof it has never held, for a payload that
                // is not a proof id, and for proof bytes nothing has ever looked
                // at. At and above the gate it refuses as UNSUPPORTED, for every
                // payload: no verifier for Agreement proofs exists in this tree --
                // nothing checks `proof_data` against `public_inputs`, there is no
                // proof system in the workspace, no verifying key anywhere, and no
                // wire type for a verification request -- and an operation that
                // cannot be performed must say so rather than succeed.
                //
                // The proof family is deliberately NOT consulted. Whether the named
                // proof is present is not a fact about whether it is valid, and
                // branching on it would restore the implication that a present
                // proof was checked. That is why the presence gate this replaces
                // is retired rather than kept beneath this one.
                //
                // Refused BEFORE the deduct, which is where the sibling
                // `SubmitProof` arm's duplicate-id refusal returns, so a refused
                // proof operation costs the same in both.
                if gates.proof_unsupported {
                    return Ok(AgreementExecutionResult::failure(
                        crate::VERIFY_PROOF_UNSUPPORTED,
                    ));
                }
                // Verification is read-only - just record the request
                StateManager::v_deduct(view, sender, fee)?;
                StateManager::v_credit(view, proposer, fee)?;
                StateManager::v_increment_nonce(view, sender)?;
                debug!("Agreement proof verification requested by: {}", sender);
                Ok(AgreementExecutionResult::success())
            }
        }
    }
}

// FIXME: tests reference primitives fields removed during schema migration; gated until updated.
#[cfg(all(test, feature = "legacy_tests"))]
mod tests {
    use super::*;
    // `Arc` is used only by this module's fixtures. Importing it here rather
    // than at file scope keeps the normal build free of an unused import while
    // leaving the gated build exactly as it was.
    use std::sync::Arc;
    use sumchain_primitives::agreement::{
        AgreementRole, PartyBinding, PartyRef,
    };
    use sumchain_storage::Database;
    use tempfile::TempDir;

    fn setup() -> (Arc<Database>, TempDir, Arc<StateManager>) {
        let dir = TempDir::new().unwrap();
        let db = Arc::new(Database::open_default(dir.path()).unwrap());
        let state = Arc::new(StateManager::new(db.clone(), 1));
        (db, dir, state)
    }

    #[test]
    fn test_commit_agreement() {
        let (db, _dir, _state) = setup();
        // A block's candidate, opened here because a `#[test]` function
        // cannot take one as a parameter. An earlier scripted signature
        // rewrite added `view` to the parameter list of every test in this
        // module, which is not valid Rust; only the `cfg` gate kept it
        // out of sight.
        let mut overlay = sumchain_storage::overlay::ApplicationOverlay::new(&db, 1 << 20);
        let view = &mut sumchain_storage::exec_view::ExecutionView::new(&mut overlay);
        let params = ChainParams::default();

        let sender = Address::new([1u8; 20]);
        let proposer = Address::new([99u8; 20]);
        StateManager::v_credit(view, &sender, 1_000_000_000_000).unwrap();

        let party1 = PartyBinding {
            party_ref: PartyRef::Commitment([2u8; 32]),
            role: AgreementRole::Buyer,
            signed: false,
            signed_at: None,
        };

        let agreement = AgreementCommitment {
            agreement_id: [10u8; 32],
            agreement_commitment: [11u8; 32],
            parties: vec![party1],
            jurisdiction_code: "US-DE".to_string(),
            effective_from: Some(1000),
            expiry: Some(2000),
            attachments: vec![],
            policy_id: [12u8; 32],
            status: AgreementStatus::Draft,
            created_at: 1000,
            updated_at: 1000,
            created_at_height: 100,
            supersedes: None,
        };

        let tx_data = AgreementTxData {
            operation: AgreementOperation::CommitAgreement,
            data: bincode::serialize(&agreement).unwrap(),
            recipient: Address::ZERO,
        };

        let result = AgreementExecutor::execute(
            view,
            &params,
            &sender,
            &tx_data,
            &proposer,
            1000,
            100,
            1000000,
            0,
            Hash::default(),
        )
        .unwrap();

        assert!(result.success, "Commit agreement failed: {:?}", result.error);
        assert_eq!(result.agreement_id, Some([10u8; 32]));

        // Read the CANDIDATE: this executor stages now, and a committed read
        // straight after `execute` would be asserting the defect this package
        // removed.
        let retrieved = AgreementExecutor::v_get_agreement(view, &[10u8; 32])
            .unwrap()
            .unwrap();
        assert_eq!(retrieved.jurisdiction_code, "US-DE");
    }
}
