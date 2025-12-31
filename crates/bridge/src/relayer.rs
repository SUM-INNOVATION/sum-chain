//! Bridge relayer implementation.
//!
//! The relayer monitors both Ethereum and SUM Chain for bridge events,
//! coordinates validator attestations, and submits bridge operations.

use crate::{
    config::BridgeConfig,
    error::BridgeError,
    ethereum::{EthereumClient, EthereumWatcher},
    types::{
        BridgeOperation, BridgeState, DepositEvent, ValidatorAttestation, ValidatorSignature,
        WithdrawalRequest, WithdrawalStatus,
    },
    wrapped_tokens::WrappedTokenRegistry,
    EthAddress, Result,
};
use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::Arc;
use sumchain_crypto::KeyPair;
use sumchain_primitives::Address;
use tokio::sync::mpsc;
use tokio::time::{interval, Duration};
use tracing::{debug, error, info, warn};

/// Pending deposit awaiting validator attestations
#[derive(Debug, Clone)]
pub struct PendingDeposit {
    /// The deposit event from Ethereum
    pub deposit: DepositEvent,
    /// Collected attestations from validators
    pub attestations: Vec<ValidatorAttestation>,
    /// Whether this deposit has been processed
    pub processed: bool,
}

/// Pending withdrawal awaiting Ethereum execution
#[derive(Debug, Clone)]
pub struct PendingWithdrawal {
    /// The withdrawal request
    pub withdrawal: WithdrawalRequest,
    /// Collected attestations from validators
    pub attestations: Vec<ValidatorAttestation>,
    /// Whether this withdrawal has been executed on Ethereum
    pub executed: bool,
    /// Ethereum transaction hash if executed
    pub eth_tx_hash: Option<[u8; 32]>,
}

/// Bridge relayer that coordinates cross-chain operations
pub struct BridgeRelayer {
    /// Configuration
    config: BridgeConfig,
    /// Ethereum client
    eth_client: Arc<EthereumClient>,
    /// Ethereum event watcher
    eth_watcher: Arc<RwLock<EthereumWatcher>>,
    /// Wrapped token registry
    token_registry: Arc<WrappedTokenRegistry>,
    /// Bridge state
    state: Arc<RwLock<BridgeState>>,
    /// Pending deposits awaiting attestations
    pending_deposits: Arc<RwLock<HashMap<[u8; 32], PendingDeposit>>>,
    /// Pending withdrawals awaiting execution
    pending_withdrawals: Arc<RwLock<HashMap<[u8; 32], PendingWithdrawal>>>,
    /// Validator key pair (if this node is a validator)
    validator_keypair: Option<KeyPair>,
    /// Set of validator addresses
    validators: Arc<RwLock<Vec<Address>>>,
    /// Required attestation threshold (e.g., 2/3 of validators)
    attestation_threshold: usize,
}

impl BridgeRelayer {
    /// Create a new bridge relayer
    pub fn new(
        config: BridgeConfig,
        validator_keypair: Option<KeyPair>,
        validators: Vec<Address>,
    ) -> Result<Self> {
        let eth_client = Arc::new(EthereumClient::new(config.clone())?);
        let eth_watcher = Arc::new(RwLock::new(EthereumWatcher::new(
            eth_client.clone(),
            config.start_block,
        )));
        let token_registry = Arc::new(WrappedTokenRegistry::new());

        // Calculate threshold: 2/3 + 1 of validators
        let attestation_threshold = (validators.len() * 2 / 3) + 1;

        Ok(Self {
            config,
            eth_client,
            eth_watcher,
            token_registry,
            state: Arc::new(RwLock::new(BridgeState::default())),
            pending_deposits: Arc::new(RwLock::new(HashMap::new())),
            pending_withdrawals: Arc::new(RwLock::new(HashMap::new())),
            validator_keypair,
            validators: Arc::new(RwLock::new(validators)),
            attestation_threshold,
        })
    }

    /// Get the token registry
    pub fn token_registry(&self) -> &Arc<WrappedTokenRegistry> {
        &self.token_registry
    }

    /// Get the bridge state
    pub fn state(&self) -> BridgeState {
        self.state.read().clone()
    }

    /// Check if the bridge is paused
    pub fn is_paused(&self) -> bool {
        self.state.read().paused
    }

    /// Pause the bridge
    pub fn pause(&self) {
        let mut state = self.state.write();
        state.paused = true;
        info!("Bridge paused");
    }

    /// Resume the bridge
    pub fn resume(&self) {
        let mut state = self.state.write();
        state.paused = false;
        info!("Bridge resumed");
    }

    /// Update the validator set
    pub fn update_validators(&self, validators: Vec<Address>) {
        let new_threshold = (validators.len() * 2 / 3) + 1;
        *self.validators.write() = validators;
        info!(
            "Updated validator set, new threshold: {}/{}",
            new_threshold,
            self.validators.read().len()
        );
    }

    /// Process a deposit event from Ethereum
    pub async fn process_deposit(&self, deposit: DepositEvent) -> Result<()> {
        if self.is_paused() {
            return Err(BridgeError::BridgePaused);
        }

        // Check if token is supported
        if !self.token_registry.is_supported(&deposit.token) {
            return Err(BridgeError::TokenNotSupported(deposit.token.to_hex()));
        }

        let deposit_id = deposit.deposit_id;

        // Check if already processed
        {
            let pending = self.pending_deposits.read();
            if let Some(existing) = pending.get(&deposit_id) {
                if existing.processed {
                    debug!("Deposit {} already processed", hex::encode(deposit_id));
                    return Ok(());
                }
            }
        }

        // Add to pending deposits
        {
            let mut pending = self.pending_deposits.write();
            pending
                .entry(deposit_id)
                .or_insert_with(|| PendingDeposit {
                    deposit: deposit.clone(),
                    attestations: Vec::new(),
                    processed: false,
                });
        }

        // If we're a validator, create and broadcast attestation
        if let Some(ref keypair) = self.validator_keypair {
            let attestation = self.create_deposit_attestation(&deposit, keypair)?;
            self.add_deposit_attestation(deposit_id, attestation)?;
        }

        Ok(())
    }

    /// Create an attestation for a deposit
    fn create_deposit_attestation(
        &self,
        deposit: &DepositEvent,
        keypair: &KeyPair,
    ) -> Result<ValidatorAttestation> {
        // Create message to sign: deposit_id || recipient || token_id || amount
        let mut message = Vec::new();
        message.extend_from_slice(&deposit.deposit_id);
        message.extend_from_slice(deposit.sum_recipient.as_bytes());

        // Get wrapped token info
        let token = self
            .token_registry
            .get_by_eth(&deposit.token)
            .ok_or_else(|| BridgeError::TokenNotSupported(deposit.token.to_hex()))?;

        message.extend_from_slice(&token.sum_token_id);

        // Convert amount to SUM decimals
        let sum_amount = self
            .token_registry
            .convert_to_sum(&deposit.token, deposit.amount)
            .ok_or(BridgeError::InvalidAmount)?;

        message.extend_from_slice(&sum_amount.to_le_bytes());

        // Sign the message
        let signature = sumchain_crypto::sign(&message, keypair.private_key());

        // Convert to byte arrays
        let mut pubkey = [0u8; 32];
        let mut sig_bytes = [0u8; 64];
        pubkey.copy_from_slice(keypair.public_key().as_bytes());
        sig_bytes.copy_from_slice(signature.as_bytes());

        Ok(ValidatorAttestation {
            operation_id: deposit.deposit_id,
            validator_pubkey: pubkey,
            signature: sig_bytes,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        })
    }

    /// Add an attestation for a deposit
    pub fn add_deposit_attestation(
        &self,
        deposit_id: [u8; 32],
        attestation: ValidatorAttestation,
    ) -> Result<()> {
        let validators = self.validators.read();

        // Verify the attestor is a validator (by checking if pubkey corresponds to a known validator)
        let attestor_address = Address::from_public_key(&attestation.validator_pubkey);
        if !validators.contains(&attestor_address) {
            return Err(BridgeError::UnauthorizedValidator);
        }

        let mut pending = self.pending_deposits.write();
        let entry = pending
            .get_mut(&deposit_id)
            .ok_or_else(|| BridgeError::DepositNotFound(hex::encode(deposit_id)))?;

        // Check if this validator already attested
        if entry
            .attestations
            .iter()
            .any(|a| a.validator_pubkey == attestation.validator_pubkey)
        {
            return Ok(()); // Already attested
        }

        entry.attestations.push(attestation);
        debug!(
            "Deposit {} has {}/{} attestations",
            hex::encode(deposit_id),
            entry.attestations.len(),
            self.attestation_threshold
        );

        Ok(())
    }

    /// Check if a deposit has enough attestations and is ready to mint
    pub fn is_deposit_ready(&self, deposit_id: &[u8; 32]) -> bool {
        let pending = self.pending_deposits.read();
        if let Some(entry) = pending.get(deposit_id) {
            !entry.processed && entry.attestations.len() >= self.attestation_threshold
        } else {
            false
        }
    }

    /// Get a deposit that's ready for minting
    pub fn get_ready_deposit(
        &self,
        deposit_id: &[u8; 32],
    ) -> Option<(DepositEvent, Vec<ValidatorSignature>)> {
        let pending = self.pending_deposits.read();
        if let Some(entry) = pending.get(deposit_id) {
            if !entry.processed && entry.attestations.len() >= self.attestation_threshold {
                let signatures: Vec<ValidatorSignature> = entry
                    .attestations
                    .iter()
                    .map(|a| ValidatorSignature {
                        pubkey: a.validator_pubkey,
                        signature: a.signature,
                    })
                    .collect();
                return Some((entry.deposit.clone(), signatures));
            }
        }
        None
    }

    /// Mark a deposit as processed (after minting wrapped tokens)
    pub fn mark_deposit_processed(&self, deposit_id: [u8; 32]) -> Result<()> {
        let mut pending = self.pending_deposits.write();
        let entry = pending
            .get_mut(&deposit_id)
            .ok_or_else(|| BridgeError::DepositNotFound(hex::encode(deposit_id)))?;

        entry.processed = true;

        // Update state
        let mut state = self.state.write();
        state.completed_deposits += 1;

        info!("Deposit {} marked as processed", hex::encode(deposit_id));
        Ok(())
    }

    /// Submit a withdrawal request (burn wrapped tokens for Ethereum withdrawal)
    pub fn submit_withdrawal(&self, withdrawal: WithdrawalRequest) -> Result<[u8; 32]> {
        if self.is_paused() {
            return Err(BridgeError::BridgePaused);
        }

        // Validate the token exists
        let token = self
            .token_registry
            .get_by_eth(&withdrawal.token)
            .ok_or_else(|| BridgeError::TokenNotSupported(withdrawal.token.to_hex()))?;

        // Check withdrawals are enabled
        if !token.withdrawals_enabled {
            return Err(BridgeError::WithdrawalsDisabled);
        }

        let withdrawal_id = withdrawal.withdrawal_id;

        // Add to pending withdrawals
        {
            let mut pending = self.pending_withdrawals.write();
            if pending.contains_key(&withdrawal_id) {
                return Err(BridgeError::WithdrawalAlreadyExists);
            }

            pending.insert(
                withdrawal_id,
                PendingWithdrawal {
                    withdrawal: withdrawal.clone(),
                    attestations: Vec::new(),
                    executed: false,
                    eth_tx_hash: None,
                },
            );
        }

        // If we're a validator, create attestation
        if let Some(ref keypair) = self.validator_keypair {
            let attestation = self.create_withdrawal_attestation(&withdrawal, keypair)?;
            self.add_withdrawal_attestation(withdrawal_id, attestation)?;
        }

        info!(
            "Withdrawal {} submitted: {} {} to {}",
            hex::encode(withdrawal_id),
            withdrawal.amount,
            token.symbol,
            withdrawal.eth_recipient.to_hex()
        );

        Ok(withdrawal_id)
    }

    /// Create an attestation for a withdrawal
    fn create_withdrawal_attestation(
        &self,
        withdrawal: &WithdrawalRequest,
        keypair: &KeyPair,
    ) -> Result<ValidatorAttestation> {
        // Create message to sign: withdrawal fields
        let mut message = Vec::new();
        message.extend_from_slice(&withdrawal.withdrawal_id);
        message.extend_from_slice(withdrawal.sum_sender.as_bytes());
        message.extend_from_slice(withdrawal.token.as_bytes());
        message.extend_from_slice(&withdrawal.amount.to_le_bytes());
        message.extend_from_slice(withdrawal.eth_recipient.as_bytes());

        let signature = sumchain_crypto::sign(&message, keypair.private_key());

        // Convert to byte arrays
        let mut pubkey = [0u8; 32];
        let mut sig_bytes = [0u8; 64];
        pubkey.copy_from_slice(keypair.public_key().as_bytes());
        sig_bytes.copy_from_slice(signature.as_bytes());

        Ok(ValidatorAttestation {
            operation_id: withdrawal.withdrawal_id,
            validator_pubkey: pubkey,
            signature: sig_bytes,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        })
    }

    /// Add an attestation for a withdrawal
    pub fn add_withdrawal_attestation(
        &self,
        withdrawal_id: [u8; 32],
        attestation: ValidatorAttestation,
    ) -> Result<()> {
        let validators = self.validators.read();

        let attestor_address = Address::from_public_key(&attestation.validator_pubkey);
        if !validators.contains(&attestor_address) {
            return Err(BridgeError::UnauthorizedValidator);
        }

        let mut pending = self.pending_withdrawals.write();
        let entry = pending
            .get_mut(&withdrawal_id)
            .ok_or_else(|| BridgeError::WithdrawalNotFound(hex::encode(withdrawal_id)))?;

        if entry
            .attestations
            .iter()
            .any(|a| a.validator_pubkey == attestation.validator_pubkey)
        {
            return Ok(());
        }

        entry.attestations.push(attestation);
        debug!(
            "Withdrawal {} has {}/{} attestations",
            hex::encode(withdrawal_id),
            entry.attestations.len(),
            self.attestation_threshold
        );

        Ok(())
    }

    /// Check if a withdrawal is ready for Ethereum execution
    pub fn is_withdrawal_ready(&self, withdrawal_id: &[u8; 32]) -> bool {
        let pending = self.pending_withdrawals.read();
        if let Some(entry) = pending.get(withdrawal_id) {
            !entry.executed && entry.attestations.len() >= self.attestation_threshold
        } else {
            false
        }
    }

    /// Get withdrawals ready for execution
    pub fn get_ready_withdrawals(
        &self,
    ) -> Vec<([u8; 32], WithdrawalRequest, Vec<ValidatorSignature>)> {
        let pending = self.pending_withdrawals.read();
        pending
            .iter()
            .filter(|(_, entry)| {
                !entry.executed && entry.attestations.len() >= self.attestation_threshold
            })
            .map(|(id, entry)| {
                let signatures: Vec<ValidatorSignature> = entry
                    .attestations
                    .iter()
                    .map(|a| ValidatorSignature {
                        pubkey: a.validator_pubkey,
                        signature: a.signature,
                    })
                    .collect();
                (*id, entry.withdrawal.clone(), signatures)
            })
            .collect()
    }

    /// Mark a withdrawal as executed on Ethereum
    pub fn mark_withdrawal_executed(
        &self,
        withdrawal_id: [u8; 32],
        eth_tx_hash: [u8; 32],
    ) -> Result<()> {
        let mut pending = self.pending_withdrawals.write();
        let entry = pending
            .get_mut(&withdrawal_id)
            .ok_or_else(|| BridgeError::WithdrawalNotFound(hex::encode(withdrawal_id)))?;

        entry.executed = true;
        entry.eth_tx_hash = Some(eth_tx_hash);

        // Update state
        let mut state = self.state.write();
        state.completed_withdrawals += 1;

        info!(
            "Withdrawal {} executed, eth tx: {}",
            hex::encode(withdrawal_id),
            hex::encode(eth_tx_hash)
        );

        Ok(())
    }

    /// Run the relayer main loop
    pub async fn run(&self, mut shutdown: mpsc::Receiver<()>) -> Result<()> {
        info!("Starting bridge relayer");

        let mut poll_interval = interval(Duration::from_secs(self.config.poll_interval_secs));

        loop {
            tokio::select! {
                _ = shutdown.recv() => {
                    info!("Bridge relayer shutting down");
                    break;
                }
                _ = poll_interval.tick() => {
                    if !self.is_paused() {
                        if let Err(e) = self.poll_ethereum_events().await {
                            error!("Error polling Ethereum: {}", e);
                        }

                        if let Err(e) = self.process_ready_deposits().await {
                            error!("Error processing deposits: {}", e);
                        }

                        if let Err(e) = self.process_ready_withdrawals().await {
                            error!("Error processing withdrawals: {}", e);
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /// Poll Ethereum for new deposit events
    async fn poll_ethereum_events(&self) -> Result<()> {
        let deposits = {
            let mut watcher = self.eth_watcher.write();
            watcher.poll_deposits().await?
        };

        for deposit in deposits {
            info!(
                "Found deposit: {} {} from {} to {}",
                deposit.amount,
                deposit.token.to_hex(),
                deposit.eth_sender.to_hex(),
                deposit.sum_recipient.to_base58()
            );

            if let Err(e) = self.process_deposit(deposit).await {
                warn!("Failed to process deposit: {}", e);
            }
        }

        Ok(())
    }

    /// Process deposits that have enough attestations
    async fn process_ready_deposits(&self) -> Result<()> {
        let ready_deposits: Vec<[u8; 32]> = {
            let pending = self.pending_deposits.read();
            pending
                .iter()
                .filter(|(_, entry)| {
                    !entry.processed && entry.attestations.len() >= self.attestation_threshold
                })
                .map(|(id, _)| *id)
                .collect()
        };

        for deposit_id in ready_deposits {
            if let Some((deposit, signatures)) = self.get_ready_deposit(&deposit_id) {
                // Create mint operation
                let token = self
                    .token_registry
                    .get_by_eth(&deposit.token)
                    .ok_or_else(|| BridgeError::TokenNotSupported(deposit.token.to_hex()))?;

                let sum_amount = self
                    .token_registry
                    .convert_to_sum(&deposit.token, deposit.amount)
                    .ok_or(BridgeError::InvalidAmount)?;

                let _operation = BridgeOperation::MintWrapped {
                    deposit_id,
                    recipient: deposit.sum_recipient,
                    token_id: token.sum_token_id,
                    amount: sum_amount,
                    signatures,
                };

                // TODO: Submit operation to SUM Chain transaction pool
                // For now, just log and mark as processed
                info!(
                    "Ready to mint {} {} for {}",
                    sum_amount,
                    token.symbol,
                    deposit.sum_recipient.to_base58()
                );

                self.mark_deposit_processed(deposit_id)?;
            }
        }

        Ok(())
    }

    /// Process withdrawals that are ready for Ethereum execution
    async fn process_ready_withdrawals(&self) -> Result<()> {
        let ready_withdrawals = self.get_ready_withdrawals();

        for (withdrawal_id, withdrawal, _signatures) in ready_withdrawals {
            let token = self
                .token_registry
                .get_by_eth(&withdrawal.token)
                .ok_or_else(|| BridgeError::TokenNotSupported(withdrawal.token.to_hex()))?;

            // For now, just log
            info!(
                "Ready to release {} {} to {} on Ethereum",
                withdrawal.amount, token.symbol, withdrawal.eth_recipient.to_hex()
            );

            // Simulate execution for now
            let fake_tx_hash = [0u8; 32]; // Would be real tx hash
            self.mark_withdrawal_executed(withdrawal_id, fake_tx_hash)?;
        }

        Ok(())
    }

    /// Get pending deposit count
    pub fn pending_deposit_count(&self) -> usize {
        self.pending_deposits
            .read()
            .values()
            .filter(|d| !d.processed)
            .count()
    }

    /// Get pending withdrawal count
    pub fn pending_withdrawal_count(&self) -> usize {
        self.pending_withdrawals
            .read()
            .values()
            .filter(|w| !w.executed)
            .count()
    }

    /// Get statistics
    pub fn stats(&self) -> BridgeStats {
        let state = self.state.read();
        BridgeStats {
            completed_deposits: state.completed_deposits,
            completed_withdrawals: state.completed_withdrawals,
            pending_deposits: self.pending_deposit_count(),
            pending_withdrawals: self.pending_withdrawal_count(),
            paused: state.paused,
            validator_count: self.validators.read().len(),
            attestation_threshold: self.attestation_threshold,
        }
    }
}

/// Bridge statistics
#[derive(Debug, Clone)]
pub struct BridgeStats {
    pub completed_deposits: u64,
    pub completed_withdrawals: u64,
    pub pending_deposits: usize,
    pub pending_withdrawals: usize,
    pub paused: bool,
    pub validator_count: usize,
    pub attestation_threshold: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> BridgeConfig {
        BridgeConfig::local()
    }

    #[test]
    fn test_relayer_creation() {
        let keypair = KeyPair::generate();
        let validators = vec![keypair.address()];

        let relayer = BridgeRelayer::new(test_config(), Some(keypair), validators).unwrap();

        assert!(!relayer.is_paused());
        assert_eq!(relayer.pending_deposit_count(), 0);
        assert_eq!(relayer.pending_withdrawal_count(), 0);
    }

    #[test]
    fn test_pause_resume() {
        let relayer =
            BridgeRelayer::new(test_config(), None, vec![KeyPair::generate().address()]).unwrap();

        assert!(!relayer.is_paused());

        relayer.pause();
        assert!(relayer.is_paused());

        relayer.resume();
        assert!(!relayer.is_paused());
    }

    #[test]
    fn test_threshold_calculation() {
        // 3 validators -> threshold = 2 + 1 = 3
        let validators: Vec<Address> = (0..3).map(|_| KeyPair::generate().address()).collect();
        let relayer = BridgeRelayer::new(test_config(), None, validators).unwrap();
        assert_eq!(relayer.attestation_threshold, 3);

        // 4 validators -> threshold = 2 + 1 = 3
        let validators: Vec<Address> = (0..4).map(|_| KeyPair::generate().address()).collect();
        let relayer = BridgeRelayer::new(test_config(), None, validators).unwrap();
        assert_eq!(relayer.attestation_threshold, 3);

        // 5 validators -> threshold = 3 + 1 = 4
        let validators: Vec<Address> = (0..5).map(|_| KeyPair::generate().address()).collect();
        let relayer = BridgeRelayer::new(test_config(), None, validators).unwrap();
        assert_eq!(relayer.attestation_threshold, 4);
    }
}
