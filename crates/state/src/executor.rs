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

use crate::nft_executor::NftExecutor;
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
}

impl BlockExecutor {
    /// Create a new block executor
    pub fn new(state: Arc<StateManager>, db: Arc<Database>, params: ChainParams) -> Self {
        let nft_executor = NftExecutor::new(db.clone());
        Self {
            state,
            db,
            params,
            nft_executor,
        }
    }

    /// Validate a transaction without executing it
    pub fn validate_tx(&self, tx: &SignedTransaction) -> Result<()> {
        // 1. Verify chain ID
        if tx.tx.chain_id != self.state.chain_id() {
            return Err(StateError::InvalidChainId {
                expected: self.state.chain_id(),
                got: tx.tx.chain_id,
            });
        }

        // 2. Verify signer matches from address
        if !tx.verify_signer() {
            return Err(StateError::SignerMismatch {
                from: tx.tx.from.to_base58(),
                signer: tx.signer_address().to_base58(),
            });
        }

        // 3. Verify signature
        let signing_hash = tx.signing_hash();
        verify_bytes(signing_hash.as_bytes(), &tx.signature, &tx.public_key)
            .map_err(|_| StateError::InvalidSignature)?;

        // 4. Verify nonce
        let expected_nonce = self.state.get_nonce(&tx.tx.from)?;
        if tx.tx.nonce != expected_nonce {
            return Err(StateError::InvalidNonce {
                expected: expected_nonce,
                got: tx.tx.nonce,
            });
        }

        // 5. Verify balance
        let balance = self.state.get_balance(&tx.tx.from)?;
        let total_cost = tx.tx.total_cost();
        if balance < total_cost {
            return Err(StateError::InsufficientBalance {
                required: total_cost,
                available: balance,
            });
        }

        // 6. Verify minimum fee
        if tx.tx.fee < self.params.min_fee {
            return Err(StateError::FeeTooLow {
                minimum: self.params.min_fee,
                got: tx.tx.fee,
            });
        }

        Ok(())
    }

    /// Execute a single transaction
    pub fn execute_tx(
        &self,
        tx: &SignedTransaction,
        proposer: &Address,
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

        // Execute the transfer
        self.state.transfer(
            &tx.tx.from,
            &tx.tx.to,
            tx.tx.amount,
            tx.tx.fee,
            proposer,
        )?;

        debug!(
            "Transaction {} executed: {} -> {} amount={}",
            tx_hash, tx.tx.from, tx.tx.to, tx.tx.amount
        );

        Ok(TxExecutionResult {
            tx_hash,
            status: TxStatus::Success,
            fee_paid: tx.tx.fee,
        })
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
            let sender_before = self.state.get_account(&tx.tx.from)?;
            let recipient_before = self.state.get_account(&tx.tx.to)?;
            let proposer_before = self.state.get_account(&proposer)?;

            let result = self.execute_tx(tx, &proposer)?;

            // Record post-execution state for diff
            let sender_after = self.state.get_account(&tx.tx.from)?;
            let recipient_after = self.state.get_account(&tx.tx.to)?;
            let proposer_after = self.state.get_account(&proposer)?;

            // Add to state diff
            state_diff.add_change(tx.tx.from, Some(sender_before), sender_after);
            state_diff.add_change(tx.tx.to, Some(recipient_before), recipient_after);
            if !proposer.is_zero() && proposer != tx.tx.from && proposer != tx.tx.to {
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
        let result = executor.execute_tx(&tx, &proposer.address()).unwrap();

        assert!(result.status.is_success());
        assert_eq!(state.get_balance(&sender.address()).unwrap(), 890);
        assert_eq!(state.get_balance(&recipient.address()).unwrap(), 100);
        assert_eq!(state.get_balance(&proposer.address()).unwrap(), 10);
    }
}
