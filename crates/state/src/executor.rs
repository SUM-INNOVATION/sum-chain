//! Transaction and block execution for SUM Chain.
//!
//! Validates and applies transactions to the state.

use std::sync::Arc;

use sumchain_crypto::verify_bytes;
use sumchain_genesis::ChainParams;
use sumchain_primitives::{
    Address, Balance, Block, BlockHeader, Hash, Receipt, SignedTransaction,
    TransactionV2, TxPayload, TxStatus,
};
use sumchain_storage::schema::StateDiff;
use sumchain_storage::Database;
use tracing::{debug, info, warn};

use crate::agreement_executor::AgreementExecutor;
use crate::contract_executor::ContractExecutorState;
use crate::docclass_executor::DocClassExecutor;
use crate::employment_executor::EmploymentExecutor;
use crate::equity_executor::EquityExecutor;
use crate::finance_executor::FinanceExecutor;
use crate::healthcare_executor::HealthcareExecutor;
use crate::legal_executor::LegalExecutor;
use crate::messaging_executor::MessagingExecutor;
use crate::nft_executor::NftExecutor;
use crate::policy_account_executor::PolicyAccountExecutor;
use crate::property_executor::PropertyExecutor;
use crate::staking_executor::StakingExecutor;
use crate::tax_executor::TaxExecutor;
use crate::token_executor::TokenExecutor;
use crate::{Result, StateError, StateManager};

/// Result of executing a transaction
#[derive(Debug)]
pub struct TxExecutionResult {
    pub tx_hash: Hash,
    pub status: TxStatus,
    pub fee_paid: Balance,
}

/// Block executor
pub struct BlockExecutor {
    state: Arc<StateManager>,
    db: Arc<Database>,
    params: ChainParams,
    nft_executor: NftExecutor,
    token_executor: TokenExecutor,
    contract_executor: ContractExecutorState,
    staking_executor: StakingExecutor,
    messaging_executor: MessagingExecutor,
    docclass_executor: DocClassExecutor,
    tax_executor: TaxExecutor,
    equity_executor: EquityExecutor,
    agreement_executor: AgreementExecutor,
    legal_executor: LegalExecutor,
    property_executor: PropertyExecutor,
    healthcare_executor: HealthcareExecutor,
    employment_executor: EmploymentExecutor,
    finance_executor: FinanceExecutor,
    policy_account_executor: PolicyAccountExecutor,
}

impl BlockExecutor {
    /// Create a new block executor
    pub fn new(state: Arc<StateManager>, db: Arc<Database>, params: ChainParams) -> Self {
        let nft_executor = NftExecutor::new(db.clone(), params.clone());
        let token_executor = TokenExecutor::new(db.clone(), params.clone());
        let contract_executor = ContractExecutorState::new(db.clone(), params.clone());
        let staking_executor = StakingExecutor::new(db.clone(), params.clone());
        let messaging_executor = MessagingExecutor::new(db.clone(), params.clone());
        let docclass_executor = DocClassExecutor::new(db.clone(), params.clone());
        let tax_executor = TaxExecutor::new(db.clone(), params.clone());
        let equity_executor = EquityExecutor::new(db.clone(), params.clone());
        let agreement_executor = AgreementExecutor::new(db.clone(), params.clone());
        let legal_executor = LegalExecutor::new(db.clone(), params.clone());
        let property_executor = PropertyExecutor::new(db.clone(), params.clone());
        let healthcare_executor = HealthcareExecutor::new(db.clone(), params.clone());
        let employment_executor = EmploymentExecutor::new(db.clone(), params.clone());
        let finance_executor = FinanceExecutor::new(db.clone(), params.clone());
        let policy_account_executor = PolicyAccountExecutor::new(db.clone());
        Self {
            state,
            db,
            params,
            nft_executor,
            token_executor,
            contract_executor,
            staking_executor,
            messaging_executor,
            docclass_executor,
            tax_executor,
            equity_executor,
            agreement_executor,
            legal_executor,
            property_executor,
            healthcare_executor,
            employment_executor,
            finance_executor,
            policy_account_executor,
        }
    }

    /// Validate a transaction without executing it
    pub fn validate_tx(&self, tx: &SignedTransaction) -> Result<()> {
        // 1. Verify chain ID
        if tx.chain_id() != self.state.chain_id() {
            return Err(StateError::InvalidChainId {
                expected: self.state.chain_id(),
                got: tx.chain_id(),
            });
        }

        // 2. Verify signer matches from address
        if !tx.verify_signer() {
            return Err(StateError::SignerMismatch {
                from: tx.sender().to_base58(),
                signer: tx.signer_address().to_base58(),
            });
        }

        // 3. Verify signature
        let signing_hash = tx.signing_hash();
        verify_bytes(signing_hash.as_bytes(), &tx.signature, &tx.public_key)
            .map_err(|_| StateError::InvalidSignature)?;

        // 4. Verify nonce
        let expected_nonce = self.state.get_nonce(&tx.sender())?;
        if tx.nonce() != expected_nonce {
            return Err(StateError::InvalidNonce {
                expected: expected_nonce,
                got: tx.nonce(),
            });
        }

        // 5. Verify balance (for legacy transfers, check total_cost; for V2, check fee at minimum)
        let balance = self.state.get_balance(&tx.sender())?;
        let total_cost = tx.amount().saturating_add(tx.fee());
        if balance < total_cost {
            return Err(StateError::InsufficientBalance {
                required: total_cost,
                available: balance,
            });
        }

        // 6. Verify minimum fee
        if tx.fee() < self.params.min_fee {
            return Err(StateError::FeeTooLow {
                minimum: self.params.min_fee,
                got: tx.fee(),
            });
        }

        Ok(())
    }

    /// Execute a single transaction (supports both legacy and V2 formats)
    pub fn execute_tx(
        &self,
        tx: &SignedTransaction,
        proposer: &Address,
        block_timestamp: u64,
    ) -> Result<TxExecutionResult> {
        let tx_hash = tx.hash();

        // Validate first
        if let Err(e) = self.validate_tx(tx) {
            debug!("Transaction {} validation failed: {}", tx_hash, e);

            let status = match &e {
                StateError::InvalidSignature => TxStatus::InvalidSignature,
                StateError::InvalidNonce { .. } => TxStatus::InvalidNonce,
                StateError::InsufficientBalance { .. } => TxStatus::InsufficientBalance,
                StateError::InvalidChainId { .. } => TxStatus::InvalidChainId,
                _ => TxStatus::Failed(0),
            };

            return Ok(TxExecutionResult {
                tx_hash,
                status,
                fee_paid: 0,
            });
        }

        // Handle based on transaction type
        match tx.inner() {
            sumchain_primitives::TxInner::Legacy(legacy_tx) => {
                // Execute legacy transfer
                self.state.transfer(
                    &legacy_tx.from,
                    &legacy_tx.to,
                    legacy_tx.amount,
                    legacy_tx.fee,
                    proposer,
                )?;

                debug!(
                    "Transaction {} executed: {} -> {} amount={}",
                    tx_hash, legacy_tx.from, legacy_tx.to, legacy_tx.amount
                );

                Ok(TxExecutionResult {
                    tx_hash,
                    status: TxStatus::Success,
                    fee_paid: legacy_tx.fee,
                })
            }
            sumchain_primitives::TxInner::V2(v2_tx) => {
                // Execute V2 transaction
                match &v2_tx.payload {
                    TxPayload::Transfer { to, amount } => {
                        self.state.transfer(
                            &v2_tx.from,
                            to,
                            *amount,
                            v2_tx.fee,
                            proposer,
                        )?;

                        debug!(
                            "V2 Transfer {} executed: {} -> {} amount={}",
                            tx_hash, v2_tx.from, to, amount
                        );

                        Ok(TxExecutionResult {
                            tx_hash,
                            status: TxStatus::Success,
                            fee_paid: v2_tx.fee,
                        })
                    }
                    TxPayload::Nft(nft_data) => {
                        // Execute NFT operation
                        let result = self.nft_executor.execute(
                            &v2_tx.from,
                            &nft_data,
                            &self.state,
                            proposer,
                            v2_tx.fee,
                        )?;

                        if result.success {
                            debug!(
                                "V2 NFT {} executed: {:?}",
                                tx_hash,
                                nft_data.operation
                            );

                            Ok(TxExecutionResult {
                                tx_hash,
                                status: TxStatus::Success,
                                fee_paid: v2_tx.fee,
                            })
                        } else {
                            warn!(
                                "V2 NFT {} failed: {}",
                                tx_hash,
                                result.error.as_deref().unwrap_or("Unknown error")
                            );

                            Ok(TxExecutionResult {
                                tx_hash,
                                status: TxStatus::Failed(2), // NFT operation failed
                                fee_paid: 0,
                            })
                        }
                    }
                    TxPayload::Token(token_data) => {
                        // Execute Token (SRC-20) operation
                        // Note: block_height is not available here, use 0 for now
                        // This will be updated when execute_block is called
                        let result = self.token_executor.execute(
                            &v2_tx.from,
                            &token_data,
                            &self.state,
                            proposer,
                            v2_tx.fee,
                            0, // block_height placeholder
                        )?;

                        if result.success {
                            debug!(
                                "V2 Token {} executed: {:?}",
                                tx_hash,
                                token_data.operation
                            );

                            Ok(TxExecutionResult {
                                tx_hash,
                                status: TxStatus::Success,
                                fee_paid: v2_tx.fee,
                            })
                        } else {
                            warn!(
                                "V2 Token {} failed: {}",
                                tx_hash,
                                result.error.as_deref().unwrap_or("Unknown error")
                            );

                            Ok(TxExecutionResult {
                                tx_hash,
                                status: TxStatus::Failed(3), // Token operation failed
                                fee_paid: 0,
                            })
                        }
                    }
                    TxPayload::ContractDeploy(deploy_data) => {
                        // Execute contract deployment
                        let result = self.contract_executor.deploy(
                            &v2_tx.from,
                            &deploy_data,
                            &self.state,
                            proposer,
                            v2_tx.fee,
                            0, // block_height placeholder
                            0, // block_timestamp placeholder
                        )?;

                        if result.success {
                            debug!(
                                "V2 Contract Deploy {} executed: contract at {}",
                                tx_hash, result.contract_address
                            );

                            Ok(TxExecutionResult {
                                tx_hash,
                                status: TxStatus::Success,
                                fee_paid: v2_tx.fee,
                            })
                        } else {
                            warn!(
                                "V2 Contract Deploy {} failed: {}",
                                tx_hash,
                                result.error.as_deref().unwrap_or("Unknown error")
                            );

                            Ok(TxExecutionResult {
                                tx_hash,
                                status: TxStatus::Failed(4), // Contract deploy failed
                                fee_paid: 0,
                            })
                        }
                    }
                    TxPayload::ContractCall(call_data) => {
                        // Execute contract call
                        let result = self.contract_executor.call(
                            &v2_tx.from,
                            &call_data,
                            &self.state,
                            proposer,
                            v2_tx.fee,
                            0, // block_height placeholder
                            0, // block_timestamp placeholder
                        )?;

                        if result.success {
                            debug!(
                                "V2 Contract Call {} executed: {} on {}",
                                tx_hash, call_data.method, call_data.contract
                            );

                            Ok(TxExecutionResult {
                                tx_hash,
                                status: TxStatus::Success,
                                fee_paid: v2_tx.fee,
                            })
                        } else {
                            warn!(
                                "V2 Contract Call {} failed: {}",
                                tx_hash,
                                result.error.as_deref().unwrap_or("Unknown error")
                            );

                            Ok(TxExecutionResult {
                                tx_hash,
                                status: TxStatus::Failed(5), // Contract call failed
                                fee_paid: 0,
                            })
                        }
                    }
                    TxPayload::Staking(staking_data) => {
                        // Execute staking operation
                        let result = self.staking_executor.execute(
                            &v2_tx.from,
                            &staking_data,
                            &self.state,
                            proposer,
                            v2_tx.fee,
                            0, // block_height placeholder
                        )?;

                        if result.success {
                            debug!(
                                "V2 Staking {} executed: {:?}",
                                tx_hash,
                                staking_data.operation
                            );

                            Ok(TxExecutionResult {
                                tx_hash,
                                status: TxStatus::Success,
                                fee_paid: v2_tx.fee,
                            })
                        } else {
                            warn!(
                                "V2 Staking {} failed: {}",
                                tx_hash,
                                result.error.as_deref().unwrap_or("Unknown error")
                            );

                            Ok(TxExecutionResult {
                                tx_hash,
                                status: TxStatus::Failed(6), // Staking operation failed
                                fee_paid: 0,
                            })
                        }
                    }
                    TxPayload::Messaging(messaging_data) => {
                        // Execute messaging operation (SRC-201)
                        let result = self.messaging_executor.execute(
                            &v2_tx.from,
                            &messaging_data,
                            &self.state,
                            proposer,
                            v2_tx.fee,
                            0, // block_height placeholder
                            0, // block_timestamp placeholder
                            0, // tx_index placeholder
                            tx_hash,
                        )?;

                        if result.success {
                            debug!(
                                "V2 Messaging {} executed: {:?}",
                                tx_hash,
                                messaging_data.operation
                            );

                            Ok(TxExecutionResult {
                                tx_hash,
                                status: TxStatus::Success,
                                fee_paid: v2_tx.fee,
                            })
                        } else {
                            warn!(
                                "V2 Messaging {} failed: {}",
                                tx_hash,
                                result.error.as_deref().unwrap_or("Unknown error")
                            );

                            Ok(TxExecutionResult {
                                tx_hash,
                                status: TxStatus::Failed(7), // Messaging operation failed
                                fee_paid: 0,
                            })
                        }
                    }
                    TxPayload::DocClass(docclass_data) => {
                        // Execute DocClass operation (SRC-80X/81X)
                        let result = self.docclass_executor.execute(
                            &v2_tx.from,
                            &docclass_data,
                            &self.state,
                            proposer,
                            v2_tx.fee,
                            0, // block_height placeholder
                            0, // block_timestamp placeholder
                            0, // tx_index placeholder
                            tx_hash,
                        )?;

                        if result.success {
                            debug!(
                                "V2 DocClass {} executed: {:?}",
                                tx_hash,
                                docclass_data.operation
                            );

                            Ok(TxExecutionResult {
                                tx_hash,
                                status: TxStatus::Success,
                                fee_paid: v2_tx.fee,
                            })
                        } else {
                            warn!(
                                "V2 DocClass {} failed: {}",
                                tx_hash,
                                result.error.as_deref().unwrap_or("Unknown error")
                            );

                            Ok(TxExecutionResult {
                                tx_hash,
                                status: TxStatus::Failed(8), // DocClass operation failed
                                fee_paid: 0,
                            })
                        }
                    }
                    TxPayload::Tax(tax_data) => {
                        // Execute Tax operation (SRC-82X)
                        let result = self.tax_executor.execute(
                            &v2_tx.from,
                            &tax_data,
                            &self.state,
                            proposer,
                            v2_tx.fee,
                            0, // block_height placeholder
                            0, // block_timestamp placeholder
                            0, // tx_index placeholder
                            tx_hash,
                        )?;

                        if result.success {
                            debug!(
                                "V2 Tax {} executed: {:?}",
                                tx_hash,
                                tax_data.operation
                            );

                            Ok(TxExecutionResult {
                                tx_hash,
                                status: TxStatus::Success,
                                fee_paid: v2_tx.fee,
                            })
                        } else {
                            warn!(
                                "V2 Tax {} failed: {}",
                                tx_hash,
                                result.error.as_deref().unwrap_or("Unknown error")
                            );

                            Ok(TxExecutionResult {
                                tx_hash,
                                status: TxStatus::Failed(9), // Tax operation failed
                                fee_paid: 0,
                            })
                        }
                    }
                    TxPayload::Equity(equity_data) => {
                        // Execute Equity operation (SRC-83X)
                        let result = self.equity_executor.execute(
                            &v2_tx.from,
                            &equity_data,
                            &self.state,
                            proposer,
                            v2_tx.fee,
                            0, // block_height placeholder
                            0, // block_timestamp placeholder
                            0, // tx_index placeholder
                            tx_hash,
                        )?;

                        if result.success {
                            debug!(
                                "V2 Equity {} executed: {:?}",
                                tx_hash,
                                equity_data.operation
                            );

                            Ok(TxExecutionResult {
                                tx_hash,
                                status: TxStatus::Success,
                                fee_paid: v2_tx.fee,
                            })
                        } else {
                            warn!(
                                "V2 Equity {} failed: {}",
                                tx_hash,
                                result.error.as_deref().unwrap_or("Unknown error")
                            );

                            Ok(TxExecutionResult {
                                tx_hash,
                                status: TxStatus::Failed(10), // Equity operation failed
                                fee_paid: 0,
                            })
                        }
                    }
                    TxPayload::Agreement(agreement_data) => {
                        // Execute Agreement operation (SRC-84X)
                        let result = self.agreement_executor.execute(
                            &v2_tx.from,
                            &agreement_data,
                            &self.state,
                            proposer,
                            v2_tx.fee,
                            0, // block_height placeholder
                            0, // block_timestamp placeholder
                            0, // tx_index placeholder
                            tx_hash,
                        )?;

                        if result.success {
                            debug!(
                                "V2 Agreement {} executed: {:?}",
                                tx_hash,
                                agreement_data.operation
                            );

                            Ok(TxExecutionResult {
                                tx_hash,
                                status: TxStatus::Success,
                                fee_paid: v2_tx.fee,
                            })
                        } else {
                            warn!(
                                "V2 Agreement {} failed: {}",
                                tx_hash,
                                result.error.as_deref().unwrap_or("Unknown error")
                            );

                            Ok(TxExecutionResult {
                                tx_hash,
                                status: TxStatus::Failed(11), // Agreement operation failed
                                fee_paid: 0,
                            })
                        }
                    }
                    TxPayload::Legal(legal_data) => {
                        // Execute Legal operation (SRC-85X)
                        let result = self.legal_executor.execute(
                            &v2_tx.from,
                            &legal_data,
                            &self.state,
                            proposer,
                            v2_tx.fee,
                            0, // block_height placeholder
                            0, // block_timestamp placeholder
                            0, // tx_index placeholder
                            tx_hash,
                        )?;

                        if result.success {
                            debug!(
                                "V2 Legal {} executed: {:?}",
                                tx_hash,
                                legal_data.operation
                            );

                            Ok(TxExecutionResult {
                                tx_hash,
                                status: TxStatus::Success,
                                fee_paid: v2_tx.fee,
                            })
                        } else {
                            warn!(
                                "V2 Legal {} failed: {}",
                                tx_hash,
                                result.error.as_deref().unwrap_or("Unknown error")
                            );

                            Ok(TxExecutionResult {
                                tx_hash,
                                status: TxStatus::Failed(12), // Legal operation failed
                                fee_paid: 0,
                            })
                        }
                    }
                    TxPayload::Property(property_data) => {
                        // Execute Property operation (SRC-86X)
                        let result = self.property_executor.execute(
                            &v2_tx.from,
                            &property_data,
                            &self.state,
                            proposer,
                            v2_tx.fee,
                            0, // block_height placeholder
                            0, // block_timestamp placeholder
                            0, // tx_index placeholder
                            tx_hash,
                        )?;

                        if result.success {
                            debug!(
                                "V2 Property {} executed: {:?}",
                                tx_hash,
                                property_data.operation
                            );

                            Ok(TxExecutionResult {
                                tx_hash,
                                status: TxStatus::Success,
                                fee_paid: v2_tx.fee,
                            })
                        } else {
                            warn!(
                                "V2 Property {} failed: {}",
                                tx_hash,
                                result.error.as_deref().unwrap_or("Unknown error")
                            );

                            Ok(TxExecutionResult {
                                tx_hash,
                                status: TxStatus::Failed(13), // Property operation failed
                                fee_paid: 0,
                            })
                        }
                    }
                    TxPayload::Healthcare(healthcare_data) => {
                        // Execute Healthcare operation (SRC-87X)
                        let result = self.healthcare_executor.execute(
                            &v2_tx.from,
                            &healthcare_data,
                            &self.state,
                            proposer,
                            v2_tx.fee,
                            0, // block_height placeholder
                            0, // block_timestamp placeholder
                            0, // tx_index placeholder
                            tx_hash,
                        )?;

                        if result.success {
                            debug!(
                                "V2 Healthcare {} executed: {:?}",
                                tx_hash,
                                healthcare_data.operation
                            );

                            Ok(TxExecutionResult {
                                tx_hash,
                                status: TxStatus::Success,
                                fee_paid: v2_tx.fee,
                            })
                        } else {
                            warn!(
                                "V2 Healthcare {} failed: {}",
                                tx_hash,
                                result.error.as_deref().unwrap_or("Unknown error")
                            );

                            Ok(TxExecutionResult {
                                tx_hash,
                                status: TxStatus::Failed(14), // Healthcare operation failed
                                fee_paid: 0,
                            })
                        }
                    }
                    TxPayload::Employment(employment_data) => {
                        // Execute Employment operation (SRC-88X)
                        let result = self.employment_executor.execute(
                            &v2_tx.from,
                            &employment_data,
                            &self.state,
                            proposer,
                            v2_tx.fee,
                            0, // block_height placeholder
                            0, // block_timestamp placeholder
                            0, // tx_index placeholder
                            tx_hash,
                        )?;

                        if result.success {
                            debug!(
                                "V2 Employment {} executed: {:?}",
                                tx_hash,
                                employment_data.operation
                            );

                            Ok(TxExecutionResult {
                                tx_hash,
                                status: TxStatus::Success,
                                fee_paid: v2_tx.fee,
                            })
                        } else {
                            warn!(
                                "V2 Employment {} failed: {}",
                                tx_hash,
                                result.error.as_deref().unwrap_or("Unknown error")
                            );

                            Ok(TxExecutionResult {
                                tx_hash,
                                status: TxStatus::Failed(15), // Employment operation failed
                                fee_paid: 0,
                            })
                        }
                    }
                    TxPayload::Finance(finance_data) => {
                        // Execute Finance operation (SRC-89X)
                        let result = self.finance_executor.execute(
                            &v2_tx.from,
                            &finance_data,
                            &self.state,
                            proposer,
                            v2_tx.fee,
                            0, // block_height placeholder
                            0, // block_timestamp placeholder
                            0, // tx_index placeholder
                            tx_hash,
                        )?;

                        if result.success {
                            debug!(
                                "V2 Finance {} executed: {:?}",
                                tx_hash,
                                finance_data.operation
                            );

                            Ok(TxExecutionResult {
                                tx_hash,
                                status: TxStatus::Success,
                                fee_paid: v2_tx.fee,
                            })
                        } else {
                            warn!(
                                "V2 Finance {} failed: {}",
                                tx_hash,
                                result.error.as_deref().unwrap_or("Unknown error")
                            );

                            Ok(TxExecutionResult {
                                tx_hash,
                                status: TxStatus::Failed(16), // Finance operation failed
                                fee_paid: 0,
                            })
                        }
                    }
                    TxPayload::PolicyAccount(policy_data) => {
                        // Execute Policy Account operation
                        let result = self.policy_account_executor.execute(
                            &v2_tx.from,
                            &policy_data,
                            &self.state,
                            proposer,
                            v2_tx.fee,
                            0, // block_height placeholder
                            block_timestamp,
                        )?;

                        if result.success {
                            debug!(
                                "V2 PolicyAccount {} executed: {:?}",
                                tx_hash,
                                policy_data.operation
                            );

                            Ok(TxExecutionResult {
                                tx_hash,
                                status: TxStatus::Success,
                                fee_paid: v2_tx.fee,
                            })
                        } else {
                            warn!(
                                "V2 PolicyAccount {} failed: {}",
                                tx_hash,
                                result.message
                            );

                            Ok(TxExecutionResult {
                                tx_hash,
                                status: TxStatus::Failed(17), // PolicyAccount operation failed
                                fee_paid: 0,
                            })
                        }
                    }
                }
            }
        }
    }

    /// Execute a V2 transaction (supports both transfers and NFT operations)
    pub fn execute_tx_v2(
        &self,
        tx: &TransactionV2,
        signature: &[u8; 64],
        public_key: &[u8; 32],
        proposer: &Address,
    ) -> Result<TxExecutionResult> {
        let tx_hash = tx.signing_hash();

        // 1. Verify chain ID
        if tx.chain_id != self.state.chain_id() {
            return Ok(TxExecutionResult {
                tx_hash,
                status: TxStatus::InvalidChainId,
                fee_paid: 0,
            });
        }

        // 2. Verify signer matches from address
        let signer_address = Address::from_public_key(public_key);
        if signer_address != tx.from {
            return Ok(TxExecutionResult {
                tx_hash,
                status: TxStatus::InvalidSignature,
                fee_paid: 0,
            });
        }

        // 3. Verify signature
        if verify_bytes(tx_hash.as_bytes(), signature, public_key).is_err() {
            return Ok(TxExecutionResult {
                tx_hash,
                status: TxStatus::InvalidSignature,
                fee_paid: 0,
            });
        }

        // 4. Verify nonce
        let expected_nonce = self.state.get_nonce(&tx.from)?;
        if tx.nonce != expected_nonce {
            return Ok(TxExecutionResult {
                tx_hash,
                status: TxStatus::InvalidNonce,
                fee_paid: 0,
            });
        }

        // 5. Verify minimum fee
        if tx.fee < self.params.min_fee {
            return Ok(TxExecutionResult {
                tx_hash,
                status: TxStatus::Failed(1), // Fee too low
                fee_paid: 0,
            });
        }

        // 6. Execute based on payload type
        match &tx.payload {
            TxPayload::Transfer { to, amount } => {
                // Check balance for transfer
                let total_cost = amount.saturating_add(tx.fee);
                let balance = self.state.get_balance(&tx.from)?;
                if balance < total_cost {
                    return Ok(TxExecutionResult {
                        tx_hash,
                        status: TxStatus::InsufficientBalance,
                        fee_paid: 0,
                    });
                }

                // Execute transfer
                self.state.transfer(&tx.from, to, *amount, tx.fee, proposer)?;

                debug!(
                    "V2 Transfer {} executed: {} -> {} amount={}",
                    tx_hash, tx.from, to, amount
                );

                Ok(TxExecutionResult {
                    tx_hash,
                    status: TxStatus::Success,
                    fee_paid: tx.fee,
                })
            }
            TxPayload::Nft(nft_data) => {
                // Check balance for fee
                let balance = self.state.get_balance(&tx.from)?;
                if balance < tx.fee {
                    return Ok(TxExecutionResult {
                        tx_hash,
                        status: TxStatus::InsufficientBalance,
                        fee_paid: 0,
                    });
                }

                // Execute NFT operation
                let result = self.nft_executor.execute(
                    &tx.from,
                    nft_data,
                    &self.state,
                    proposer,
                    tx.fee,
                )?;

                if result.success {
                    debug!(
                        "V2 NFT {} executed: {:?}",
                        tx_hash,
                        nft_data.operation
                    );

                    Ok(TxExecutionResult {
                        tx_hash,
                        status: TxStatus::Success,
                        fee_paid: tx.fee,
                    })
                } else {
                    warn!(
                        "V2 NFT {} failed: {}",
                        tx_hash,
                        result.error.as_deref().unwrap_or("Unknown error")
                    );

                    Ok(TxExecutionResult {
                        tx_hash,
                        status: TxStatus::Failed(2), // NFT operation failed
                        fee_paid: 0,
                    })
                }
            }
            TxPayload::Token(token_data) => {
                // Check balance for fee
                let balance = self.state.get_balance(&tx.from)?;
                if balance < tx.fee {
                    return Ok(TxExecutionResult {
                        tx_hash,
                        status: TxStatus::InsufficientBalance,
                        fee_paid: 0,
                    });
                }

                // Execute Token (SRC-20) operation
                let result = self.token_executor.execute(
                    &tx.from,
                    token_data,
                    &self.state,
                    proposer,
                    tx.fee,
                    0, // block_height placeholder
                )?;

                if result.success {
                    debug!(
                        "V2 Token {} executed: {:?}",
                        tx_hash,
                        token_data.operation
                    );

                    Ok(TxExecutionResult {
                        tx_hash,
                        status: TxStatus::Success,
                        fee_paid: tx.fee,
                    })
                } else {
                    warn!(
                        "V2 Token {} failed: {}",
                        tx_hash,
                        result.error.as_deref().unwrap_or("Unknown error")
                    );

                    Ok(TxExecutionResult {
                        tx_hash,
                        status: TxStatus::Failed(3), // Token operation failed
                        fee_paid: 0,
                    })
                }
            }
            TxPayload::ContractDeploy(deploy_data) => {
                // Check balance for fee + value
                let total_cost = tx.fee.saturating_add(deploy_data.value);
                let balance = self.state.get_balance(&tx.from)?;
                if balance < total_cost {
                    return Ok(TxExecutionResult {
                        tx_hash,
                        status: TxStatus::InsufficientBalance,
                        fee_paid: 0,
                    });
                }

                // Execute contract deployment
                let result = self.contract_executor.deploy(
                    &tx.from,
                    deploy_data,
                    &self.state,
                    proposer,
                    tx.fee,
                    0, // block_height placeholder
                    0, // block_timestamp placeholder
                )?;

                if result.success {
                    debug!(
                        "V2 Contract Deploy {} executed: contract at {}",
                        tx_hash, result.contract_address
                    );

                    Ok(TxExecutionResult {
                        tx_hash,
                        status: TxStatus::Success,
                        fee_paid: tx.fee,
                    })
                } else {
                    warn!(
                        "V2 Contract Deploy {} failed: {}",
                        tx_hash,
                        result.error.as_deref().unwrap_or("Unknown error")
                    );

                    Ok(TxExecutionResult {
                        tx_hash,
                        status: TxStatus::Failed(4), // Contract deploy failed
                        fee_paid: 0,
                    })
                }
            }
            TxPayload::ContractCall(call_data) => {
                // Check balance for fee + value
                let total_cost = tx.fee.saturating_add(call_data.value);
                let balance = self.state.get_balance(&tx.from)?;
                if balance < total_cost {
                    return Ok(TxExecutionResult {
                        tx_hash,
                        status: TxStatus::InsufficientBalance,
                        fee_paid: 0,
                    });
                }

                // Execute contract call
                let result = self.contract_executor.call(
                    &tx.from,
                    call_data,
                    &self.state,
                    proposer,
                    tx.fee,
                    0, // block_height placeholder
                    0, // block_timestamp placeholder
                )?;

                if result.success {
                    debug!(
                        "V2 Contract Call {} executed: {} on {}",
                        tx_hash, call_data.method, call_data.contract
                    );

                    Ok(TxExecutionResult {
                        tx_hash,
                        status: TxStatus::Success,
                        fee_paid: tx.fee,
                    })
                } else {
                    warn!(
                        "V2 Contract Call {} failed: {}",
                        tx_hash,
                        result.error.as_deref().unwrap_or("Unknown error")
                    );

                    Ok(TxExecutionResult {
                        tx_hash,
                        status: TxStatus::Failed(5), // Contract call failed
                        fee_paid: 0,
                    })
                }
            }
            TxPayload::Staking(staking_data) => {
                // Check balance for fee
                let balance = self.state.get_balance(&tx.from)?;
                if balance < tx.fee {
                    return Ok(TxExecutionResult {
                        tx_hash,
                        status: TxStatus::InsufficientBalance,
                        fee_paid: 0,
                    });
                }

                // Execute staking operation
                let result = self.staking_executor.execute(
                    &tx.from,
                    staking_data,
                    &self.state,
                    proposer,
                    tx.fee,
                    0, // block_height placeholder
                )?;

                if result.success {
                    debug!(
                        "V2 Staking {} executed: {:?}",
                        tx_hash,
                        staking_data.operation
                    );

                    Ok(TxExecutionResult {
                        tx_hash,
                        status: TxStatus::Success,
                        fee_paid: tx.fee,
                    })
                } else {
                    warn!(
                        "V2 Staking {} failed: {}",
                        tx_hash,
                        result.error.as_deref().unwrap_or("Unknown error")
                    );

                    Ok(TxExecutionResult {
                        tx_hash,
                        status: TxStatus::Failed(6), // Staking operation failed
                        fee_paid: 0,
                    })
                }
            }
            TxPayload::Messaging(messaging_data) => {
                // Check balance for fee
                let balance = self.state.get_balance(&tx.from)?;
                if balance < tx.fee {
                    return Ok(TxExecutionResult {
                        tx_hash,
                        status: TxStatus::InsufficientBalance,
                        fee_paid: 0,
                    });
                }

                // Execute messaging operation (SRC-201)
                let result = self.messaging_executor.execute(
                    &tx.from,
                    messaging_data,
                    &self.state,
                    proposer,
                    tx.fee,
                    0, // block_height placeholder
                    0, // block_timestamp placeholder
                    0, // tx_index placeholder
                    tx_hash,
                )?;

                if result.success {
                    debug!(
                        "V2 Messaging {} executed: {:?}",
                        tx_hash,
                        messaging_data.operation
                    );

                    Ok(TxExecutionResult {
                        tx_hash,
                        status: TxStatus::Success,
                        fee_paid: tx.fee,
                    })
                } else {
                    warn!(
                        "V2 Messaging {} failed: {}",
                        tx_hash,
                        result.error.as_deref().unwrap_or("Unknown error")
                    );

                    Ok(TxExecutionResult {
                        tx_hash,
                        status: TxStatus::Failed(7), // Messaging operation failed
                        fee_paid: 0,
                    })
                }
            }
            TxPayload::DocClass(docclass_data) => {
                // Check balance for fee
                let balance = self.state.get_balance(&tx.from)?;
                if balance < tx.fee {
                    return Ok(TxExecutionResult {
                        tx_hash,
                        status: TxStatus::InsufficientBalance,
                        fee_paid: 0,
                    });
                }

                // Execute DocClass operation (SRC-80X/81X)
                let result = self.docclass_executor.execute(
                    &tx.from,
                    docclass_data,
                    &self.state,
                    proposer,
                    tx.fee,
                    0, // block_height placeholder
                    0, // block_timestamp placeholder
                    0, // tx_index placeholder
                    tx_hash,
                )?;

                if result.success {
                    debug!(
                        "V2 DocClass {} executed: {:?}",
                        tx_hash,
                        docclass_data.operation
                    );

                    Ok(TxExecutionResult {
                        tx_hash,
                        status: TxStatus::Success,
                        fee_paid: tx.fee,
                    })
                } else {
                    warn!(
                        "V2 DocClass {} failed: {}",
                        tx_hash,
                        result.error.as_deref().unwrap_or("Unknown error")
                    );

                    Ok(TxExecutionResult {
                        tx_hash,
                        status: TxStatus::Failed(8), // DocClass operation failed
                        fee_paid: 0,
                    })
                }
            }
            TxPayload::Tax(tax_data) => {
                // Check balance for fee
                let balance = self.state.get_balance(&tx.from)?;
                if balance < tx.fee {
                    return Ok(TxExecutionResult {
                        tx_hash,
                        status: TxStatus::InsufficientBalance,
                        fee_paid: 0,
                    });
                }

                // Execute Tax operation (SRC-82X)
                let result = self.tax_executor.execute(
                    &tx.from,
                    tax_data,
                    &self.state,
                    proposer,
                    tx.fee,
                    0, // block_height placeholder
                    0, // block_timestamp placeholder
                    0, // tx_index placeholder
                    tx_hash,
                )?;

                if result.success {
                    debug!(
                        "V2 Tax {} executed: {:?}",
                        tx_hash,
                        tax_data.operation
                    );

                    Ok(TxExecutionResult {
                        tx_hash,
                        status: TxStatus::Success,
                        fee_paid: tx.fee,
                    })
                } else {
                    warn!(
                        "V2 Tax {} failed: {}",
                        tx_hash,
                        result.error.as_deref().unwrap_or("Unknown error")
                    );

                    Ok(TxExecutionResult {
                        tx_hash,
                        status: TxStatus::Failed(9), // Tax operation failed
                        fee_paid: 0,
                    })
                }
            }
            TxPayload::Equity(equity_data) => {
                // Check balance for fee
                let balance = self.state.get_balance(&tx.from)?;
                if balance < tx.fee {
                    return Ok(TxExecutionResult {
                        tx_hash,
                        status: TxStatus::InsufficientBalance,
                        fee_paid: 0,
                    });
                }

                // Execute Equity operation (SRC-83X)
                let result = self.equity_executor.execute(
                    &tx.from,
                    equity_data,
                    &self.state,
                    proposer,
                    tx.fee,
                    0, // block_height placeholder
                    0, // block_timestamp placeholder
                    0, // tx_index placeholder
                    tx_hash,
                )?;

                if result.success {
                    debug!(
                        "V2 Equity {} executed: {:?}",
                        tx_hash,
                        equity_data.operation
                    );

                    Ok(TxExecutionResult {
                        tx_hash,
                        status: TxStatus::Success,
                        fee_paid: tx.fee,
                    })
                } else {
                    warn!(
                        "V2 Equity {} failed: {}",
                        tx_hash,
                        result.error.as_deref().unwrap_or("Unknown error")
                    );

                    Ok(TxExecutionResult {
                        tx_hash,
                        status: TxStatus::Failed(10), // Equity operation failed
                        fee_paid: 0,
                    })
                }
            }
            TxPayload::Agreement(agreement_data) => {
                // Check balance for fee
                let balance = self.state.get_balance(&tx.from)?;
                if balance < tx.fee {
                    return Ok(TxExecutionResult {
                        tx_hash,
                        status: TxStatus::InsufficientBalance,
                        fee_paid: 0,
                    });
                }

                // Execute Agreement operation (SRC-84X)
                let result = self.agreement_executor.execute(
                    &tx.from,
                    agreement_data,
                    &self.state,
                    proposer,
                    tx.fee,
                    0, // block_height placeholder
                    0, // block_timestamp placeholder
                    0, // tx_index placeholder
                    tx_hash,
                )?;

                if result.success {
                    debug!(
                        "V2 Agreement {} executed: {:?}",
                        tx_hash,
                        agreement_data.operation
                    );

                    Ok(TxExecutionResult {
                        tx_hash,
                        status: TxStatus::Success,
                        fee_paid: tx.fee,
                    })
                } else {
                    warn!(
                        "V2 Agreement {} failed: {}",
                        tx_hash,
                        result.error.as_deref().unwrap_or("Unknown error")
                    );

                    Ok(TxExecutionResult {
                        tx_hash,
                        status: TxStatus::Failed(11), // Agreement operation failed
                        fee_paid: 0,
                    })
                }
            }
            TxPayload::Legal(legal_data) => {
                // Check balance for fee
                let balance = self.state.get_balance(&tx.from)?;
                if balance < tx.fee {
                    return Ok(TxExecutionResult {
                        tx_hash,
                        status: TxStatus::InsufficientBalance,
                        fee_paid: 0,
                    });
                }

                // Execute Legal operation (SRC-85X)
                let result = self.legal_executor.execute(
                    &tx.from,
                    legal_data,
                    &self.state,
                    proposer,
                    tx.fee,
                    0, // block_height placeholder
                    0, // block_timestamp placeholder
                    0, // tx_index placeholder
                    tx_hash,
                )?;

                if result.success {
                    debug!(
                        "V2 Legal {} executed: {:?}",
                        tx_hash,
                        legal_data.operation
                    );

                    Ok(TxExecutionResult {
                        tx_hash,
                        status: TxStatus::Success,
                        fee_paid: tx.fee,
                    })
                } else {
                    warn!(
                        "V2 Legal {} failed: {}",
                        tx_hash,
                        result.error.as_deref().unwrap_or("Unknown error")
                    );

                    Ok(TxExecutionResult {
                        tx_hash,
                        status: TxStatus::Failed(12), // Legal operation failed
                        fee_paid: 0,
                    })
                }
            }
            TxPayload::Property(property_data) => {
                // Check balance for fee
                let balance = self.state.get_balance(&tx.from)?;
                if balance < tx.fee {
                    return Ok(TxExecutionResult {
                        tx_hash,
                        status: TxStatus::InsufficientBalance,
                        fee_paid: 0,
                    });
                }

                // Execute Property operation (SRC-86X)
                let result = self.property_executor.execute(
                    &tx.from,
                    property_data,
                    &self.state,
                    proposer,
                    tx.fee,
                    0, // block_height placeholder
                    0, // block_timestamp placeholder
                    0, // tx_index placeholder
                    tx_hash,
                )?;

                if result.success {
                    debug!(
                        "V2 Property {} executed: {:?}",
                        tx_hash,
                        property_data.operation
                    );

                    Ok(TxExecutionResult {
                        tx_hash,
                        status: TxStatus::Success,
                        fee_paid: tx.fee,
                    })
                } else {
                    warn!(
                        "V2 Property {} failed: {}",
                        tx_hash,
                        result.error.as_deref().unwrap_or("Unknown error")
                    );

                    Ok(TxExecutionResult {
                        tx_hash,
                        status: TxStatus::Failed(13), // Property operation failed
                        fee_paid: 0,
                    })
                }
            }
            TxPayload::Healthcare(healthcare_data) => {
                // Check balance for fee
                let balance = self.state.get_balance(&tx.from)?;
                if balance < tx.fee {
                    return Ok(TxExecutionResult {
                        tx_hash,
                        status: TxStatus::InsufficientBalance,
                        fee_paid: 0,
                    });
                }

                // Execute Healthcare operation (SRC-87X)
                let result = self.healthcare_executor.execute(
                    &tx.from,
                    healthcare_data,
                    &self.state,
                    proposer,
                    tx.fee,
                    0, // block_height placeholder
                    0, // block_timestamp placeholder
                    0, // tx_index placeholder
                    tx_hash,
                )?;

                if result.success {
                    debug!(
                        "V2 Healthcare {} executed: {:?}",
                        tx_hash,
                        healthcare_data.operation
                    );

                    Ok(TxExecutionResult {
                        tx_hash,
                        status: TxStatus::Success,
                        fee_paid: tx.fee,
                    })
                } else {
                    warn!(
                        "V2 Healthcare {} failed: {}",
                        tx_hash,
                        result.error.as_deref().unwrap_or("Unknown error")
                    );

                    Ok(TxExecutionResult {
                        tx_hash,
                        status: TxStatus::Failed(14), // Healthcare operation failed
                        fee_paid: 0,
                    })
                }
            }
            TxPayload::Employment(employment_data) => {
                // Check balance for fee
                let balance = self.state.get_balance(&tx.from)?;
                if balance < tx.fee {
                    return Ok(TxExecutionResult {
                        tx_hash,
                        status: TxStatus::InsufficientBalance,
                        fee_paid: 0,
                    });
                }

                // Execute Employment operation (SRC-88X)
                let result = self.employment_executor.execute(
                    &tx.from,
                    employment_data,
                    &self.state,
                    proposer,
                    tx.fee,
                    0, // block_height placeholder
                    0, // block_timestamp placeholder
                    0, // tx_index placeholder
                    tx_hash,
                )?;

                if result.success {
                    debug!(
                        "V2 Employment {} executed: {:?}",
                        tx_hash,
                        employment_data.operation
                    );

                    Ok(TxExecutionResult {
                        tx_hash,
                        status: TxStatus::Success,
                        fee_paid: tx.fee,
                    })
                } else {
                    warn!(
                        "V2 Employment {} failed: {}",
                        tx_hash,
                        result.error.as_deref().unwrap_or("Unknown error")
                    );

                    Ok(TxExecutionResult {
                        tx_hash,
                        status: TxStatus::Failed(15), // Employment operation failed
                        fee_paid: 0,
                    })
                }
            }
            TxPayload::Finance(finance_data) => {
                // Check balance for fee
                let balance = self.state.get_balance(&tx.from)?;
                if balance < tx.fee {
                    return Ok(TxExecutionResult {
                        tx_hash,
                        status: TxStatus::InsufficientBalance,
                        fee_paid: 0,
                    });
                }

                // Execute Finance operation (SRC-89X)
                let result = self.finance_executor.execute(
                    &tx.from,
                    finance_data,
                    &self.state,
                    proposer,
                    tx.fee,
                    0, // block_height placeholder
                    0, // block_timestamp placeholder
                    0, // tx_index placeholder
                    tx_hash,
                )?;

                if result.success {
                    debug!(
                        "V2 Finance {} executed: {:?}",
                        tx_hash,
                        finance_data.operation
                    );

                    Ok(TxExecutionResult {
                        tx_hash,
                        status: TxStatus::Success,
                        fee_paid: tx.fee,
                    })
                } else {
                    warn!(
                        "V2 Finance {} failed: {}",
                        tx_hash,
                        result.error.as_deref().unwrap_or("Unknown error")
                    );

                    Ok(TxExecutionResult {
                        tx_hash,
                        status: TxStatus::Failed(16), // Finance operation failed
                        fee_paid: 0,
                    })
                }
            }
            TxPayload::PolicyAccount(policy_data) => {
                // This branch should never be reached - PolicyAccount is V2 only
                return Err(StateError::InvalidOperation(
                    "PolicyAccount is only supported in V2 transactions".to_string(),
                ));
            }
        }
    }

    /// Execute a block and return receipts
    pub fn execute_block(
        &self,
        block: &Block,
        _parent_state_root: Hash,
    ) -> Result<(Vec<Receipt>, Hash, StateDiff)> {
        info!(
            "Executing block {} with {} transactions",
            block.height(),
            block.tx_count()
        );

        let proposer = Address::from_public_key(&block.header.proposer_pubkey);
        let mut receipts = Vec::new();
        let mut state_diff = StateDiff::new();

        for (idx, tx) in block.transactions.iter().enumerate() {
            // Record pre-execution state for diff
            let sender = tx.sender();
            let recipient = tx.recipient();
            let sender_before = self.state.get_account(&sender)?;
            let recipient_before = if let Some(ref r) = recipient {
                Some(self.state.get_account(r)?)
            } else {
                None
            };
            let proposer_before = self.state.get_account(&proposer)?;

            let result = self.execute_tx(tx, &proposer, block.header.timestamp)?;

            // Record post-execution state for diff
            let sender_after = self.state.get_account(&sender)?;
            let recipient_after = if let Some(ref r) = recipient {
                Some(self.state.get_account(r)?)
            } else {
                None
            };
            let proposer_after = self.state.get_account(&proposer)?;

            // Add to state diff
            state_diff.add_change(sender, Some(sender_before), sender_after);
            if let (Some(r), Some(before), Some(after)) = (recipient, recipient_before, recipient_after) {
                state_diff.add_change(r, Some(before), after);
            }
            if !proposer.is_zero() && proposer != sender && recipient.map_or(true, |r| proposer != r) {
                state_diff.add_change(proposer, Some(proposer_before), proposer_after);
            }

            let receipt = Receipt::new(
                result.tx_hash,
                block.height(),
                idx as u32,
                result.status,
                result.fee_paid,
            );

            receipts.push(receipt);
        }

        // Compute new state root (simplified)
        let state_root = self.compute_block_state_root(block, &receipts)?;
        self.state.set_state_root(state_root);

        info!(
            "Block {} executed, new state root: {}",
            block.height(),
            state_root
        );

        Ok((receipts, state_root, state_diff))
    }

    /// Compute state root after block execution
    fn compute_block_state_root(&self, block: &Block, receipts: &[Receipt]) -> Result<Hash> {
        // Simplified state root computation
        // In production, this would be a proper MPT root
        //
        // Note: We deliberately do NOT include block.hash() here because
        // block.hash() depends on the state_root in the header, creating
        // a circular dependency. The state root must be computable before
        // the final block hash is known.

        let mut data = Vec::new();

        // Include block info (but not block hash - that would be circular)
        data.extend_from_slice(&block.height().to_be_bytes());
        data.extend_from_slice(block.header.parent_hash.as_bytes());
        data.extend_from_slice(&block.header.timestamp.to_be_bytes());
        data.extend_from_slice(block.header.tx_root.as_bytes());

        // Include receipt outcomes
        for receipt in receipts {
            data.extend_from_slice(receipt.tx_hash.as_bytes());
            data.push(if receipt.is_success() { 1 } else { 0 });
            data.extend_from_slice(&receipt.fee_paid.to_be_bytes());
        }

        // Mix with previous state root (from before this block's execution)
        data.extend_from_slice(self.state.state_root().as_bytes());

        Ok(Hash::hash(&data))
    }

    /// Validate a block header
    pub fn validate_header(
        &self,
        header: &BlockHeader,
        parent: Option<&Block>,
        validators: &[[u8; 32]],
    ) -> Result<()> {
        // Genesis block validation
        if header.height == 0 {
            if !header.parent_hash.is_zero() {
                return Err(StateError::BlockValidation(
                    "Genesis block must have zero parent hash".to_string(),
                ));
            }
            return Ok(());
        }

        // Non-genesis validation
        let parent = parent.ok_or_else(|| {
            StateError::BlockValidation("Parent block required for non-genesis".to_string())
        })?;

        // Check parent hash
        if header.parent_hash != parent.hash() {
            return Err(StateError::BlockValidation(
                "Parent hash mismatch".to_string(),
            ));
        }

        // Check height
        if header.height != parent.height() + 1 {
            return Err(StateError::BlockValidation(format!(
                "Invalid height: expected {}, got {}",
                parent.height() + 1,
                header.height
            )));
        }

        // Check timestamp
        if header.timestamp <= parent.header.timestamp {
            return Err(StateError::BlockValidation(
                "Timestamp must be greater than parent".to_string(),
            ));
        }

        // Validate proposer is in validator set
        let proposer_idx = (header.height as usize) % validators.len();
        let expected_proposer = validators[proposer_idx];

        if header.proposer_pubkey != expected_proposer {
            return Err(StateError::BlockValidation(format!(
                "Invalid proposer for height {}: expected {:?}",
                header.height, expected_proposer
            )));
        }

        // Verify proposer signature
        let signing_hash = header.signing_hash();
        verify_bytes(
            signing_hash.as_bytes(),
            &header.proposer_sig,
            &header.proposer_pubkey,
        )
        .map_err(|_| StateError::BlockValidation("Invalid proposer signature".to_string()))?;

        Ok(())
    }

    /// Validate entire block (header + transactions)
    pub fn validate_block(
        &self,
        block: &Block,
        parent: Option<&Block>,
        validators: &[[u8; 32]],
    ) -> Result<()> {
        // Validate header
        self.validate_header(&block.header, parent, validators)?;

        // Verify tx_root
        if !block.verify_tx_root() {
            return Err(StateError::BlockValidation(
                "Transaction root mismatch".to_string(),
            ));
        }

        // Validate transaction count
        if block.tx_count() > self.params.max_txs_per_block as usize {
            return Err(StateError::BlockValidation(format!(
                "Too many transactions: {} > {}",
                block.tx_count(),
                self.params.max_txs_per_block
            )));
        }

        // Validate block size
        let block_bytes = block.to_bytes();
        if block_bytes.len() as u64 > self.params.max_block_bytes {
            return Err(StateError::BlockValidation(format!(
                "Block too large: {} > {}",
                block_bytes.len(),
                self.params.max_block_bytes
            )));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sumchain_crypto::{sign, KeyPair};
    use sumchain_primitives::Transaction;
    use sumchain_storage::Database;
    use tempfile::TempDir;

    fn setup() -> (Arc<StateManager>, Arc<Database>, TempDir) {
        let dir = TempDir::new().unwrap();
        let db = Arc::new(Database::open_default(dir.path()).unwrap());
        let state = Arc::new(StateManager::new(db.clone(), 1));
        (state, db, dir)
    }

    fn create_signed_tx(
        kp: &KeyPair,
        to: Address,
        amount: Balance,
        fee: Balance,
        nonce: u64,
    ) -> SignedTransaction {
        let tx = Transaction::new(1, kp.address(), to, amount, fee, nonce);
        let signing_hash = tx.signing_hash();
        let sig = sign(signing_hash.as_bytes(), kp.private_key());

        SignedTransaction::new(tx, *sig.as_bytes(), *kp.public_key().as_bytes())
    }

    #[test]
    fn test_validate_tx_success() {
        let (state, db, _dir) = setup();
        let executor = BlockExecutor::new(state.clone(), db, ChainParams::default());

        let sender = KeyPair::generate();
        let recipient = KeyPair::generate();

        // Fund sender
        state
            .put_account(
                &sender.address(),
                &sumchain_storage::schema::AccountState {
                    balance: 1000,
                    nonce: 0,
                },
            )
            .unwrap();

        let tx = create_signed_tx(&sender, recipient.address(), 100, 10, 0);
        assert!(executor.validate_tx(&tx).is_ok());
    }

    #[test]
    fn test_validate_tx_wrong_nonce() {
        let (state, db, _dir) = setup();
        let executor = BlockExecutor::new(state.clone(), db, ChainParams::default());

        let sender = KeyPair::generate();
        let recipient = KeyPair::generate();

        state
            .put_account(
                &sender.address(),
                &sumchain_storage::schema::AccountState {
                    balance: 1000,
                    nonce: 5, // Nonce is 5
                },
            )
            .unwrap();

        let tx = create_signed_tx(&sender, recipient.address(), 100, 10, 0); // But tx has nonce 0
        let result = executor.validate_tx(&tx);
        assert!(matches!(result, Err(StateError::InvalidNonce { .. })));
    }

    #[test]
    fn test_execute_tx() {
        let (state, db, _dir) = setup();
        let executor = BlockExecutor::new(state.clone(), db, ChainParams::default());

        let sender = KeyPair::generate();
        let recipient = KeyPair::generate();
        let proposer = KeyPair::generate();

        state
            .put_account(
                &sender.address(),
                &sumchain_storage::schema::AccountState {
                    balance: 1000,
                    nonce: 0,
                },
            )
            .unwrap();

        let tx = create_signed_tx(&sender, recipient.address(), 100, 10, 0);
        let result = executor.execute_tx(&tx, &proposer.address(), 1000000000).unwrap();

        assert!(result.status.is_success());
        assert_eq!(state.get_balance(&sender.address()).unwrap(), 890);
        assert_eq!(state.get_balance(&recipient.address()).unwrap(), 100);
        assert_eq!(state.get_balance(&proposer.address()).unwrap(), 10);
    }
}
