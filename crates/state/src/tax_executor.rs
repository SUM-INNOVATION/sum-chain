//! SRC-82X Tax & Compliance Executor
//!
//! A minimal implementation that handles core tax operations.

use sumchain_storage::exec_view::ExecutionView;

use sumchain_primitives::{
    Address, Balance, BlockHeight, Hash, Timestamp,
    TaxClaimTypeEntry, TaxIssuer, TaxIssuerStatus, TaxOperation,
    TaxPolicy, TaxProofEnvelope, TaxDisclosureEnvelope, TaxTxData,
    ClaimTypeStatus,
};
use tracing::debug;

use sumchain_genesis::ChainParams;

use crate::{Result, StateError, StateManager};

/// Result of Tax operation execution
#[derive(Debug)]
pub struct TaxExecutionResult {
    pub success: bool,
    pub policy_id: Option<[u8; 32]>,
    pub proof_id: Option<[u8; 32]>,
    pub error: Option<String>,
}

impl TaxExecutionResult {
    pub fn success_with_policy(policy_id: [u8; 32]) -> Self {
        Self { success: true, policy_id: Some(policy_id), proof_id: None, error: None }
    }

    pub fn success_with_proof(proof_id: [u8; 32]) -> Self {
        Self { success: true, policy_id: None, proof_id: Some(proof_id), error: None }
    }

    pub fn success() -> Self {
        Self { success: true, policy_id: None, proof_id: None, error: None }
    }

    pub fn failure(error: impl Into<String>) -> Self {
        Self { success: false, policy_id: None, proof_id: None, error: Some(error.into()) }
    }
}

/// Tax executor for SRC-82X transactions.
///
/// No database handle, by construction: every operation takes the block's
/// `ExecutionView` and no `self`, so `self.db` is not something this file can
/// name. The committed twins stay in `sumchain_storage::tax_store` for the RPC
/// server.
pub struct TaxExecutor;

/// The activation decisions a Tax transaction executes under.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TaxGates {
    /// The claim-type registry is writable only by a registered, active issuer.
    /// ACTIVATION-AUDIT row AU-19.
    pub authorization: bool,
    /// Executor-written timestamps are the block's, not a literal zero.
    /// ACTIVATION-AUDIT class 2.
    pub real_block_timestamp: bool,
}

impl TaxGates {
    /// Every gate closed -- the release configuration today.
    pub const CLOSED: Self = Self {
        authorization: false,
        real_block_timestamp: false,
    };

    /// Every gate open. For the gated half of a mixed-version test.
    pub const OPEN: Self = Self {
        authorization: true,
        real_block_timestamp: true,
    };

    /// Derive the decisions from the chain's parameters at `block_height`.
    pub fn from_params(params: &ChainParams, block_height: BlockHeight) -> Self {
        Self {
            authorization: TaxExecutor::authorization_gate_open(params, block_height),
            real_block_timestamp: crate::subsystem_block_timestamp_gate_open(params, block_height),
        }
    }
}

impl TaxExecutor {
    /// The activation height for the Tax claim-type authority check.
    ///
    /// **This is a seam for a `ChainParams` field that does not exist yet.**
    /// `crates/genesis/**` belongs to another track, so the field cannot be
    /// added from here. The field this function must read, once that track adds
    /// it, is:
    ///
    /// ```text
    /// /// SRC-84X Tax claim-type authority. Dormant by default (`None` ->
    /// /// never open). Below the gate claim-type registration, update and
    /// /// deprecation have no authority check at all: all three guard only on
    /// /// row presence or absence, so any funded account writes the chain's
    /// /// claim-type registry. At and above the gate the sender must be a
    /// /// registered tax issuer whose status is still Active. Activation is a
    /// /// consensus change and needs a coordinated validator upgrade.
    /// #[serde(default)]
    /// pub tax_authorization_enabled_from_height: Option<u64>,
    /// ```
    ///
    /// Until it exists this returns `None`, which is exactly what an absent
    /// `#[serde(default)] Option<u64>` resolves to, so production behaviour is
    /// unchanged and every pinning test that records the gap still passes.
    #[inline]
    fn authorization_activation(params: &ChainParams) -> Option<u64> {
        params.tax_authorization_enabled_from_height
    }

    /// Whether the Tax claim-type authority check is active at `block_height`.
    #[inline]
    pub fn authorization_gate_open(params: &ChainParams, block_height: BlockHeight) -> bool {
        matches!(Self::authorization_activation(params), Some(h) if block_height >= h)
    }

    /// Is `sender` a registered tax issuer whose standing is still `Active`?
    fn issuer_in_good_standing(view: &ExecutionView<'_, '_>, sender: &Address) -> Result<bool> {
        Ok(match Self::v_get_issuer(view, sender)? {
            Some(issuer) => issuer.status == TaxIssuerStatus::Active,
            None => false,
        })
    }

    /// Execute a Tax transaction.
    #[allow(clippy::too_many_arguments)]
    pub fn execute(
        view: &mut ExecutionView<'_, '_>,
        params: &ChainParams,
        sender: &Address,
        data: &TaxTxData,
        proposer: &Address,
        fee: Balance,
        block_height: BlockHeight,
        block_timestamp: Timestamp,
        tx_index: u32,
        tx_hash: Hash,
    ) -> Result<TaxExecutionResult> {
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
            TaxGates::from_params(params, block_height),
        )
    }

    /// Execute a Tax transaction with the activation decisions supplied
    /// directly. The seam the mixed-version tests use.
    #[allow(clippy::too_many_arguments)]
    pub fn execute_with_gates(
        view: &mut ExecutionView<'_, '_>,
        sender: &Address,
        data: &TaxTxData,
        proposer: &Address,
        fee: Balance,
        _block_height: BlockHeight,
        block_timestamp: Timestamp,
        _tx_index: u32,
        _tx_hash: Hash,
        gates: TaxGates,
    ) -> Result<TaxExecutionResult> {
        let block_timestamp =
            crate::effective_block_timestamp(block_timestamp, gates.real_block_timestamp);
        // AU-19: claim-type registration, update and deprecation have no
        // authority check at all below the gate -- all three guard only on row
        // presence or absence, so any funded account writes the chain's
        // claim-type registry. One check covers all three because they are the
        // same registry and the same question.
        if gates.authorization
            && matches!(
                data.operation,
                TaxOperation::RegisterClaimType
                    | TaxOperation::UpdateClaimType
                    | TaxOperation::DeprecateClaimType
            )
            && !Self::issuer_in_good_standing(view, sender)?
        {
            return Ok(TaxExecutionResult::failure(
                "Only a registered, active tax issuer can write the claim-type registry",
            ));
        }

        match data.operation {
            TaxOperation::RegisterClaimType => {
                let entry: TaxClaimTypeEntry = bincode::deserialize(&data.data)
                    .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

                if Self::v_get_claim_type(view, &entry.claim_type)?.is_some() {
                    return Ok(TaxExecutionResult::failure("Already exists"));
                }

                StateManager::v_deduct(view, sender, fee)?;
                StateManager::v_credit(view, proposer, fee)?;
                StateManager::v_increment_nonce(view, sender)?;
                Self::v_put_claim_type(view, &entry)?;
                debug!("Claim type registered: {}", entry.claim_type);
                Ok(TaxExecutionResult::success())
            }

            TaxOperation::UpdateClaimType => {
                let entry: TaxClaimTypeEntry = bincode::deserialize(&data.data)
                    .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

                if Self::v_get_claim_type(view, &entry.claim_type)?.is_none() {
                    return Ok(TaxExecutionResult::failure("Not found"));
                }

                StateManager::v_deduct(view, sender, fee)?;
                StateManager::v_credit(view, proposer, fee)?;
                StateManager::v_increment_nonce(view, sender)?;
                Self::v_put_claim_type(view, &entry)?;
                Ok(TaxExecutionResult::success())
            }

            TaxOperation::DeprecateClaimType => {
                #[derive(serde::Deserialize)]
                struct Data { claim_type: String }
                let d: Data = bincode::deserialize(&data.data)
                    .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

                let mut entry = match Self::v_get_claim_type(view, &d.claim_type)? {
                    Some(e) => e,
                    None => return Ok(TaxExecutionResult::failure("Not found")),
                };

                StateManager::v_deduct(view, sender, fee)?;
                StateManager::v_credit(view, proposer, fee)?;
                StateManager::v_increment_nonce(view, sender)?;
                entry.status = ClaimTypeStatus::Deprecated;
                Self::v_put_claim_type(view, &entry)?;
                Ok(TaxExecutionResult::success())
            }

            TaxOperation::RegisterIssuer => {
                let issuer: TaxIssuer = bincode::deserialize(&data.data)
                    .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

                if issuer.address != *sender {
                    return Ok(TaxExecutionResult::failure("Address must be sender"));
                }

                if Self::v_get_issuer(view, sender)?.is_some() {
                    return Ok(TaxExecutionResult::failure("Already registered"));
                }

                StateManager::v_deduct(view, sender, fee)?;
                StateManager::v_credit(view, proposer, fee)?;
                StateManager::v_increment_nonce(view, sender)?;
                Self::v_put_issuer(view, &issuer)?;
                debug!("Tax issuer registered: {}", issuer.address);
                Ok(TaxExecutionResult::success())
            }

            TaxOperation::UpdateIssuer => {
                let issuer: TaxIssuer = bincode::deserialize(&data.data)
                    .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

                if issuer.address != *sender {
                    return Ok(TaxExecutionResult::failure("Can only update own"));
                }

                if Self::v_get_issuer(view, sender)?.is_none() {
                    return Ok(TaxExecutionResult::failure("Not registered"));
                }

                StateManager::v_deduct(view, sender, fee)?;
                StateManager::v_credit(view, proposer, fee)?;
                StateManager::v_increment_nonce(view, sender)?;
                Self::v_put_issuer(view, &issuer)?;
                Ok(TaxExecutionResult::success())
            }

            TaxOperation::SuspendIssuer | TaxOperation::RevokeIssuer => {
                #[derive(serde::Deserialize)]
                struct Data { issuer_address: Address }
                let d: Data = bincode::deserialize(&data.data)
                    .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

                let mut issuer = match Self::v_get_issuer(view, &d.issuer_address)? {
                    Some(i) => i,
                    None => return Ok(TaxExecutionResult::failure("Not found")),
                };

                if d.issuer_address != *sender {
                    return Ok(TaxExecutionResult::failure("Not authorized"));
                }

                StateManager::v_deduct(view, sender, fee)?;
                StateManager::v_credit(view, proposer, fee)?;
                StateManager::v_increment_nonce(view, sender)?;

                issuer.status = if data.operation == TaxOperation::SuspendIssuer {
                    TaxIssuerStatus::Suspended
                } else {
                    TaxIssuerStatus::Revoked
                };
                issuer.updated_at = block_timestamp;
                Self::v_put_issuer(view, &issuer)?;
                Ok(TaxExecutionResult::success())
            }

            TaxOperation::CreatePolicy => {
                let policy: TaxPolicy = bincode::deserialize(&data.data)
                    .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

                if policy.creator != *sender {
                    return Ok(TaxExecutionResult::failure("Creator must be sender"));
                }

                if Self::v_get_policy(view, &policy.policy_id)?.is_some() {
                    return Ok(TaxExecutionResult::failure("Already exists"));
                }

                StateManager::v_deduct(view, sender, fee)?;
                StateManager::v_credit(view, proposer, fee)?;
                StateManager::v_increment_nonce(view, sender)?;
                let policy_id = policy.policy_id;
                Self::v_put_policy(view, &policy)?;
                debug!("Tax policy created: {:?}", policy_id);
                Ok(TaxExecutionResult::success_with_policy(policy_id))
            }

            TaxOperation::UpdatePolicy => {
                let policy: TaxPolicy = bincode::deserialize(&data.data)
                    .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

                let existing = match Self::v_get_policy(view, &policy.policy_id)? {
                    Some(p) => p,
                    None => return Ok(TaxExecutionResult::failure("Not found")),
                };

                if existing.creator != *sender {
                    return Ok(TaxExecutionResult::failure("Only creator can update"));
                }

                StateManager::v_deduct(view, sender, fee)?;
                StateManager::v_credit(view, proposer, fee)?;
                StateManager::v_increment_nonce(view, sender)?;
                let policy_id = policy.policy_id;
                Self::v_put_policy(view, &policy)?;
                Ok(TaxExecutionResult::success_with_policy(policy_id))
            }

            TaxOperation::IssueClaim => {
                let proof: TaxProofEnvelope = bincode::deserialize(&data.data)
                    .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

                let issuer = match Self::v_get_issuer(view, sender)? {
                    Some(i) => i,
                    None => return Ok(TaxExecutionResult::failure("Not registered")),
                };

                if issuer.status != TaxIssuerStatus::Active {
                    return Ok(TaxExecutionResult::failure("Not active"));
                }

                StateManager::v_deduct(view, sender, fee)?;
                StateManager::v_credit(view, proposer, fee)?;
                StateManager::v_increment_nonce(view, sender)?;
                let proof_id = proof.proof_id;
                Self::v_put_proof(view, &proof)?;
                debug!("Tax proof issued: {:?}", proof_id);
                Ok(TaxExecutionResult::success_with_proof(proof_id))
            }

            TaxOperation::RevokeClaim => {
                #[derive(serde::Deserialize)]
                struct Data { subject_nullifier: [u8; 32] }
                let d: Data = bincode::deserialize(&data.data)
                    .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

                let issuer = match Self::v_get_issuer(view, sender)? {
                    Some(i) => i,
                    None => return Ok(TaxExecutionResult::failure("Not registered")),
                };

                if issuer.status != TaxIssuerStatus::Active {
                    return Ok(TaxExecutionResult::failure("Not active"));
                }

                if Self::v_get_proof(view, &d.subject_nullifier)?.is_none() {
                    return Ok(TaxExecutionResult::failure("Not found"));
                }

                StateManager::v_deduct(view, sender, fee)?;
                StateManager::v_credit(view, proposer, fee)?;
                StateManager::v_increment_nonce(view, sender)?;
                Self::v_delete_proof(view, &d.subject_nullifier)?;
                Ok(TaxExecutionResult::success())
            }

            TaxOperation::VerifyProof => {
                // Verify a submitted proof - just record verification request
                StateManager::v_deduct(view, sender, fee)?;
                StateManager::v_credit(view, proposer, fee)?;
                StateManager::v_increment_nonce(view, sender)?;
                debug!("Proof verification requested by: {}", sender);
                Ok(TaxExecutionResult::success())
            }

            TaxOperation::AttachDisclosure => {
                let disclosure: TaxDisclosureEnvelope = bincode::deserialize(&data.data)
                    .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

                StateManager::v_deduct(view, sender, fee)?;
                StateManager::v_credit(view, proposer, fee)?;
                StateManager::v_increment_nonce(view, sender)?;
                Self::v_put_disclosure(view, &disclosure)?;
                debug!("Disclosure attached: {:?}", disclosure.payload_hash);
                Ok(TaxExecutionResult::success())
            }
        }
    }
}

// FIXME: tests reference primitives fields removed during schema migration; gated until updated.
#[cfg(all(test, feature = "legacy_tests"))]
mod tests {
    use super::*;
    use std::sync::Arc;
    use sumchain_primitives::TaxIssuerClass;
    use sumchain_storage::Database;
    use tempfile::TempDir;

    fn setup() -> (Arc<Database>, TempDir, Arc<StateManager>) {
        let dir = TempDir::new().unwrap();
        let db = Arc::new(Database::open_default(dir.path()).unwrap());
        let state = Arc::new(StateManager::new(db.clone(), 1));
        (db, dir, state)
    }

    #[test]
    fn test_register_issuer() {
        let (db, _dir, _state) = setup();
        // A block's candidate, opened here because a `#[test]` function
        // cannot take one as a parameter. An earlier scripted signature
        // rewrite added `view` to the parameter list of every test in this
        // module, which is not valid Rust; only the `cfg` gate kept it
        // out of sight.
        let mut overlay = sumchain_storage::overlay::ApplicationOverlay::new(&db, 1 << 20);
        let view = &mut sumchain_storage::exec_view::ExecutionView::new(&mut overlay);

        let issuer_addr = Address::new([1u8; 20]);
        let proposer = Address::new([99u8; 20]);
        StateManager::v_credit(view, &issuer_addr, 1_000_000_000_000).unwrap();

        let issuer = TaxIssuer {
            address: issuer_addr,
            tax_class: TaxIssuerClass::TaxAuthority,
            jurisdictions: vec!["US".to_string()],
            attributes_hash: [0u8; 32],
            attributes_schema_hash: [0u8; 32],
            registered_at: 1000000,
            updated_at: 1000000,
            status: TaxIssuerStatus::Active,
            expires_at: None,
        };

        let tx_data = TaxTxData {
            operation: TaxOperation::RegisterIssuer,
            data: bincode::serialize(&issuer).unwrap(),
        };

        let result = TaxExecutor::execute(
            view,
            &issuer_addr,
            &tx_data,
            &proposer,
            1000,
            100,
            1000000,
            0,
            Hash::default(),
        )
        .unwrap();

        assert!(result.success, "Register issuer failed: {:?}", result.error);

        // Read the CANDIDATE: this executor stages now.
        let retrieved = TaxExecutor::v_get_issuer(view, &issuer_addr)
            .unwrap()
            .unwrap();
        assert_eq!(retrieved.tax_class, TaxIssuerClass::TaxAuthority);
    }
}
