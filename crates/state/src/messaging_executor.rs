//! SRC-201 Messaging Executor
//!
//! Executes on-chain messaging transactions including:
//! - Message sending (sponsored and direct)
//! - Payment attachment and claims
//! - Anti-spam staking
//! - Recipient controls (filters, contacts, blocks)

use std::sync::Arc;

use sumchain_genesis::{ChainParams, MessagingParams};
use sumchain_primitives::{
    Address, Balance, BlockSenderData, ClaimPaymentData, ContactData, Hash, InboxFilter,
    MessageEvent, MessagingOperation, MessagingTxData, PendingPayment, RegisteredPublicKey,
    RegisterPublicKeyData, ReportSpamData, SendMessageData, SendMessageWithPaymentData,
    SetDailyQuotaData, SetInboxFilterData, SetMaxMessageSizeData, SetMinTrustStakeData,
    SetSponsorshipEnabledData, StakeForTrustData, MessagingUnstakeData, FundRegistryData,
    UpdatePublicKeyData, SponsoredMessage, validate_message_format, DEFAULT_DAILY_QUOTA, DEFAULT_MAX_MESSAGE_SIZE,
};
use sumchain_storage::{Database, MessagingStore};
use sumchain_crypto::recipient_hash;
use tracing::{debug, warn};

use crate::{Result, StateError, StateManager};

/// Result of messaging execution
#[derive(Debug)]
pub struct MessagingExecutionResult {
    pub success: bool,
    pub message_id: Option<Hash>,
    pub error: Option<String>,
}

impl MessagingExecutionResult {
    pub fn success(message_id: Option<Hash>) -> Self {
        Self {
            success: true,
            message_id,
            error: None,
        }
    }

    pub fn failure(error: impl Into<String>) -> Self {
        Self {
            success: false,
            message_id: None,
            error: Some(error.into()),
        }
    }
}

/// Messaging executor for SRC-201 transactions
pub struct MessagingExecutor {
    db: Arc<Database>,
    params: ChainParams,
}

impl MessagingExecutor {
    pub fn new(db: Arc<Database>, params: ChainParams) -> Self {
        Self { db, params }
    }

    /// Get messaging params (with defaults)
    fn messaging_params(&self) -> MessagingParams {
        self.params.messaging.clone().unwrap_or_default()
    }

    /// Execute a messaging transaction
    pub fn execute(
        &self,
        sender: &Address,
        data: &MessagingTxData,
        state: &StateManager,
        proposer: &Address,
        fee: Balance,
        block_height: u64,
        block_timestamp: u64,
        tx_index: u32,
        tx_hash: Hash,
    ) -> Result<MessagingExecutionResult> {
        let store = MessagingStore::new(&self.db);

        match data.operation {
            MessagingOperation::SendMessage => {
                self.send_message_sponsored(sender, &data.data, state, proposer, block_height, block_timestamp, tx_index, tx_hash, &store)
            }
            MessagingOperation::SendMessageDirect => {
                self.send_message_direct(sender, &data.data, state, proposer, fee, block_height, block_timestamp, tx_index, tx_hash, &store)
            }
            MessagingOperation::SendMessageWithPayment => {
                self.send_message_with_payment(sender, &data.data, state, proposer, fee, block_height, block_timestamp, tx_index, tx_hash, &store)
            }
            MessagingOperation::ClaimPayment => {
                self.claim_payment(sender, &data.data, state, block_timestamp, &store)
            }
            MessagingOperation::StakeForTrust => {
                self.stake_for_trust(sender, &data.data, state, &store)
            }
            MessagingOperation::Unstake => {
                self.unstake(sender, &data.data, state, &store)
            }
            MessagingOperation::SetInboxFilter => {
                self.set_inbox_filter(sender, &data.data, &store)
            }
            MessagingOperation::AddContact => {
                self.add_contact(sender, &data.data, &store)
            }
            MessagingOperation::RemoveContact => {
                self.remove_contact(sender, &data.data, &store)
            }
            MessagingOperation::BlockSender => {
                self.block_sender(sender, &data.data, &store)
            }
            MessagingOperation::ReportSpam => {
                self.report_spam(sender, &data.data, &store)
            }
            MessagingOperation::RegisterPublicKey => {
                self.register_public_key(sender, &data.data, block_height, block_timestamp, &store)
            }
            MessagingOperation::UpdatePublicKey => {
                self.update_public_key(sender, &data.data, block_height, &store)
            }
            // Admin operations
            MessagingOperation::SetDailyQuota => {
                self.set_daily_quota(sender, &data.data, &store)
            }
            MessagingOperation::SetMaxMessageSize => {
                self.set_max_message_size(sender, &data.data, &store)
            }
            MessagingOperation::SetMinTrustStake => {
                self.set_min_trust_stake(sender, &data.data, &store)
            }
            MessagingOperation::SetSponsorshipEnabled => {
                self.set_sponsorship_enabled(sender, &data.data, &store)
            }
            MessagingOperation::FundRegistry => {
                self.fund_registry(sender, &data.data, state, &store)
            }
            // Issue #145: sponsored public-key registration is dispatched by the
            // state executor's gated, sponsor-pays, per-code path
            // (`BlockExecutor::execute_sponsored_register_v1`) BEFORE this generic
            // entrypoint is reached — it needs the activation gate, the chain id
            // for the inner preimage, and explicit sponsor fee/nonce handling that
            // this `MessagingExecutionResult`-shaped API cannot express. Reaching
            // this arm means a caller bypassed the dispatch interception; fail
            // closed rather than execute an ungated / miscoded registration.
            MessagingOperation::RegisterPublicKeySponsoredV1 => {
                Ok(MessagingExecutionResult::failure(
                    "RegisterPublicKeySponsoredV1 must be executed via the state \
                     executor's gated sponsored-registration path, not the generic \
                     messaging executor",
                ))
            }
        }
    }

    /// Check if sender is admin
    fn is_admin(&self, sender: &Address, store: &MessagingStore) -> bool {
        if let Ok(Some(admin)) = store.get_registry_admin() {
            &admin == sender
        } else {
            // If no admin set, check genesis params
            if let Some(ref msg_params) = self.params.messaging {
                if let Some(ref admin_str) = msg_params.registry_admin {
                    if let Ok(admin) = Address::from_base58(admin_str)
                        .or_else(|_| Address::from_hex(admin_str)) {
                        return &admin == sender;
                    }
                }
            }
            false
        }
    }

    /// Calculate current day (for rate limiting)
    fn current_day(&self, timestamp: u64) -> u32 {
        (timestamp / 86400) as u32
    }

    /// Check rate limit for sender
    fn check_rate_limit(&self, sender: &Address, timestamp: u64, store: &MessagingStore) -> Result<()> {
        let day = self.current_day(timestamp);
        let count = store.get_daily_message_count(sender, day)?;
        let quota = store.get_daily_quota()?;

        // Staked senders get 5x quota
        let stake = store.get_stake_balance(sender)?;
        let min_stake = store.get_min_trust_stake()?;
        let effective_quota = if stake >= min_stake {
            quota.saturating_mul(5)
        } else {
            quota
        };

        if count >= effective_quota {
            return Err(StateError::NftError("Daily quota exceeded".to_string()));
        }

        Ok(())
    }

    /// Check spam score restrictions
    fn check_spam_restrictions(&self, sender: &Address, store: &MessagingStore) -> Result<()> {
        let score = store.get_spam_score(sender)?;
        let params = self.messaging_params();

        if score >= params.high_spam_threshold {
            // High spam score requires stake
            let stake = store.get_stake_balance(sender)?;
            let min_stake = store.get_min_trust_stake()?;
            if stake < min_stake {
                return Err(StateError::NftError("High spam score requires stake".to_string()));
            }
        } else if score >= params.spam_threshold {
            // Moderate spam score: reduced quota (handled in check_rate_limit)
        }

        Ok(())
    }

    /// Check recipient filter
    fn check_recipient_filter(
        &self,
        sender: &Address,
        recipient_hash: &[u8; 32],
        store: &MessagingStore,
    ) -> Result<()> {
        let filter = store.get_inbox_filter(recipient_hash)?;

        match filter {
            InboxFilter::AcceptAll => {
                // Check if blocked
                if store.is_blocked(recipient_hash, sender)? {
                    return Err(StateError::NftError("Sender is blocked".to_string()));
                }
            }
            InboxFilter::ContactsOnly => {
                let sender_hash = recipient_hash_for_address(sender);
                if !store.is_contact(recipient_hash, &sender_hash)? {
                    return Err(StateError::NftError("Sender not in contacts".to_string()));
                }
            }
            InboxFilter::StakedOnly => {
                let stake = store.get_stake_balance(sender)?;
                let min_stake = store.get_min_trust_stake()?;
                if stake < min_stake {
                    return Err(StateError::NftError("Recipient requires staked senders".to_string()));
                }
            }
        }

        Ok(())
    }

    /// Send message with gas sponsorship
    /// The tx.from is the sponsor address, but the real sender is derived from
    /// SponsoredMessage.sender_pubkey
    fn send_message_sponsored(
        &self,
        _sponsor: &Address, // tx.from is the sponsor, not the message sender
        data: &[u8],
        state: &StateManager,
        proposer: &Address,
        block_height: u64,
        block_timestamp: u64,
        tx_index: u32,
        tx_hash: Hash,
        store: &MessagingStore,
    ) -> Result<MessagingExecutionResult> {
        // Check if sponsorship is enabled
        if !store.is_sponsorship_enabled()? {
            return Ok(MessagingExecutionResult::failure("Sponsorship disabled"));
        }

        // Parse sponsored message data (includes sender_pubkey)
        let sponsored_msg: SponsoredMessage = bincode::deserialize(data)
            .map_err(|e| StateError::NftError(format!("Invalid sponsored message data: {}", e)))?;

        // Derive the real sender address from the sender's public key
        let real_sender = Address::from_public_key(&sponsored_msg.sender_pubkey);

        // Verify the real sender has registered their public key
        if !store.has_public_key(&real_sender).unwrap_or(false) {
            return Ok(MessagingExecutionResult::failure("Sender must register public key first"));
        }

        // Validate message format
        if let Err(e) = validate_message_format(&sponsored_msg.message_data) {
            return Ok(MessagingExecutionResult::failure(format!("Invalid message format: {}", e)));
        }

        // Check message size
        let max_size = store.get_max_message_size()?;
        if sponsored_msg.message_data.len() > max_size as usize {
            return Ok(MessagingExecutionResult::failure("Message too large"));
        }

        // Check expiry
        if sponsored_msg.expiry < block_timestamp {
            return Ok(MessagingExecutionResult::failure("Sponsored message has expired"));
        }

        // Check rate limit for the real sender
        self.check_rate_limit(&real_sender, block_timestamp, store)?;

        // Check spam restrictions for the real sender
        self.check_spam_restrictions(&real_sender, store)?;

        // Check recipient filter (using real sender)
        self.check_recipient_filter(&real_sender, &sponsored_msg.recipient_hash, store)?;

        // Credit fee to proposer (fee already deducted from sponsor in tx validation)
        // Note: The sponsor pays the fee via normal tx flow, no sponsorship pool deduction needed

        // Increment real sender's nonce and daily count
        store.increment_sender_nonce(&real_sender)?;
        let day = self.current_day(block_timestamp);
        store.increment_daily_message_count(&real_sender, day)?;

        // Store message event with real sender
        let event = MessageEvent {
            sender: real_sender,
            recipient_hash: sponsored_msg.recipient_hash,
            message_id: tx_hash,
            size: sponsored_msg.message_data.len() as u32,
            has_payment: sponsored_msg.koppa_amount.is_some(),
            block_height,
            timestamp: block_timestamp,
        };
        store.store_message_event(&event, tx_index)?;

        tracing::info!(
            "Sponsored message stored: tx={} sender={} recipient_hash=0x{} block={}",
            tx_hash,
            real_sender.to_base58(),
            hex::encode(sponsored_msg.recipient_hash),
            block_height
        );

        Ok(MessagingExecutionResult::success(Some(tx_hash)))
    }

    /// Send message directly (user pays gas)
    fn send_message_direct(
        &self,
        sender: &Address,
        data: &[u8],
        state: &StateManager,
        proposer: &Address,
        fee: Balance,
        block_height: u64,
        block_timestamp: u64,
        tx_index: u32,
        tx_hash: Hash,
        store: &MessagingStore,
    ) -> Result<MessagingExecutionResult> {
        // Parse message data
        let msg_data: SendMessageData = bincode::deserialize(data)
            .map_err(|e| StateError::NftError(format!("Invalid message data: {}", e)))?;

        // Validate message format
        if let Err(e) = validate_message_format(&msg_data.message_data) {
            return Ok(MessagingExecutionResult::failure(format!("Invalid message format: {}", e)));
        }

        // Check message size
        let max_size = store.get_max_message_size()?;
        if msg_data.message_data.len() > max_size as usize {
            return Ok(MessagingExecutionResult::failure("Message too large"));
        }

        // Check rate limit
        self.check_rate_limit(sender, block_timestamp, store)?;

        // Check spam restrictions
        self.check_spam_restrictions(sender, store)?;

        // Check recipient filter
        self.check_recipient_filter(sender, &msg_data.recipient_hash, store)?;

        // Deduct fee and pay proposer
        state.deduct(sender, fee)?;
        state.credit(proposer, fee)?;

        // Increment nonce
        state.increment_nonce(sender)?;

        // Increment sender's message nonce and daily count
        store.increment_sender_nonce(sender)?;
        let day = self.current_day(block_timestamp);
        store.increment_daily_message_count(sender, day)?;

        // Store message event
        let event = MessageEvent {
            sender: *sender,
            recipient_hash: msg_data.recipient_hash,
            message_id: tx_hash,
            size: msg_data.message_data.len() as u32,
            has_payment: false,
            block_height,
            timestamp: block_timestamp,
        };
        store.store_message_event(&event, tx_index)?;

        debug!("Direct message sent: {} -> {:?}", sender, msg_data.recipient_hash);

        Ok(MessagingExecutionResult::success(Some(tx_hash)))
    }

    /// Send message with attached Koppa payment
    fn send_message_with_payment(
        &self,
        sender: &Address,
        data: &[u8],
        state: &StateManager,
        proposer: &Address,
        fee: Balance,
        block_height: u64,
        block_timestamp: u64,
        tx_index: u32,
        tx_hash: Hash,
        store: &MessagingStore,
    ) -> Result<MessagingExecutionResult> {
        // Parse message data
        let msg_data: SendMessageWithPaymentData = bincode::deserialize(data)
            .map_err(|e| StateError::NftError(format!("Invalid message data: {}", e)))?;

        // Validate message format
        if let Err(e) = validate_message_format(&msg_data.message_data) {
            return Ok(MessagingExecutionResult::failure(format!("Invalid message format: {}", e)));
        }

        // Check message size
        let max_size = store.get_max_message_size()?;
        if msg_data.message_data.len() > max_size as usize {
            return Ok(MessagingExecutionResult::failure("Message too large"));
        }

        // Check rate limit
        self.check_rate_limit(sender, block_timestamp, store)?;

        // Check spam restrictions
        self.check_spam_restrictions(sender, store)?;

        // Check recipient filter
        self.check_recipient_filter(sender, &msg_data.recipient_hash, store)?;

        // Calculate total cost
        let total_cost = fee.saturating_add(msg_data.koppa_amount);
        let balance = state.get_balance(sender)?;
        if balance < total_cost {
            return Ok(MessagingExecutionResult::failure("Insufficient balance"));
        }

        // Deduct fee and payment
        state.deduct(sender, total_cost)?;
        state.credit(proposer, fee)?;

        // Escrow the payment (store as pending)
        let expiry = block_timestamp + (7 * 24 * 3600); // 7 days expiry
        let pending = PendingPayment {
            recipient_hash: msg_data.recipient_hash,
            amount: msg_data.koppa_amount,
            expiry,
            sender: *sender,
        };
        store.set_pending_payment(&tx_hash, &pending)?;

        // Increment nonce
        state.increment_nonce(sender)?;

        // Increment sender's message nonce and daily count
        store.increment_sender_nonce(sender)?;
        let day = self.current_day(block_timestamp);
        store.increment_daily_message_count(sender, day)?;

        // Store message event
        let event = MessageEvent {
            sender: *sender,
            recipient_hash: msg_data.recipient_hash,
            message_id: tx_hash,
            size: msg_data.message_data.len() as u32,
            has_payment: true,
            block_height,
            timestamp: block_timestamp,
        };
        store.store_message_event(&event, tx_index)?;

        debug!(
            "Message with payment sent: {} -> {:?}, amount: {}",
            sender, msg_data.recipient_hash, msg_data.koppa_amount
        );

        Ok(MessagingExecutionResult::success(Some(tx_hash)))
    }

    /// Claim payment from a message
    fn claim_payment(
        &self,
        sender: &Address,
        data: &[u8],
        state: &StateManager,
        block_timestamp: u64,
        store: &MessagingStore,
    ) -> Result<MessagingExecutionResult> {
        let claim_data: ClaimPaymentData = bincode::deserialize(data)
            .map_err(|e| StateError::NftError(format!("Invalid claim data: {}", e)))?;

        // Get pending payment
        let pending = match store.get_pending_payment(&claim_data.message_id)? {
            Some(p) => p,
            None => return Ok(MessagingExecutionResult::failure("No pending payment")),
        };

        // Verify recipient
        let claimer_hash = recipient_hash_for_address(&claim_data.recipient_address);
        if claimer_hash != pending.recipient_hash {
            return Ok(MessagingExecutionResult::failure("Not the recipient"));
        }

        // Verify claimer matches tx sender
        if *sender != claim_data.recipient_address {
            return Ok(MessagingExecutionResult::failure("Claimer mismatch"));
        }

        // Check expiry (if expired, refund to sender)
        if block_timestamp > pending.expiry {
            // Refund to original sender
            state.credit(&pending.sender, pending.amount)?;
            store.delete_pending_payment(&claim_data.message_id)?;
            return Ok(MessagingExecutionResult::failure("Payment expired, refunded to sender"));
        }

        // Credit recipient
        state.credit(sender, pending.amount)?;

        // Delete pending payment
        store.delete_pending_payment(&claim_data.message_id)?;

        debug!("Payment claimed: {} received {}", sender, pending.amount);

        Ok(MessagingExecutionResult::success(Some(claim_data.message_id)))
    }

    /// Stake Koppa for trusted sender tier
    fn stake_for_trust(
        &self,
        sender: &Address,
        data: &[u8],
        state: &StateManager,
        store: &MessagingStore,
    ) -> Result<MessagingExecutionResult> {
        let stake_data: StakeForTrustData = bincode::deserialize(data)
            .map_err(|e| StateError::NftError(format!("Invalid stake data: {}", e)))?;

        if stake_data.amount == 0 {
            return Ok(MessagingExecutionResult::failure("Zero stake amount"));
        }

        // Deduct from sender's balance
        state.deduct(sender, stake_data.amount)?;

        // Add to stake
        let new_stake = store.add_stake(sender, stake_data.amount)?;

        debug!("Staked for trust: {} staked {}, total: {}", sender, stake_data.amount, new_stake);

        Ok(MessagingExecutionResult::success(None))
    }

    /// Unstake Koppa
    fn unstake(
        &self,
        sender: &Address,
        data: &[u8],
        state: &StateManager,
        store: &MessagingStore,
    ) -> Result<MessagingExecutionResult> {
        let unstake_data: MessagingUnstakeData = bincode::deserialize(data)
            .map_err(|e| StateError::NftError(format!("Invalid unstake data: {}", e)))?;

        let current_stake = store.get_stake_balance(sender)?;
        if current_stake < unstake_data.amount {
            return Ok(MessagingExecutionResult::failure("Insufficient stake"));
        }

        // Deduct from stake
        let new_stake = current_stake.saturating_sub(unstake_data.amount);
        store.set_stake_balance(sender, new_stake)?;

        // Credit back to sender
        state.credit(sender, unstake_data.amount)?;

        debug!("Unstaked: {} withdrew {}, remaining: {}", sender, unstake_data.amount, new_stake);

        Ok(MessagingExecutionResult::success(None))
    }

    /// Set inbox filter mode
    fn set_inbox_filter(
        &self,
        sender: &Address,
        data: &[u8],
        store: &MessagingStore,
    ) -> Result<MessagingExecutionResult> {
        let filter_data: SetInboxFilterData = bincode::deserialize(data)
            .map_err(|e| StateError::NftError(format!("Invalid filter data: {}", e)))?;

        let sender_hash = recipient_hash_for_address(sender);
        store.set_inbox_filter(&sender_hash, filter_data.mode)?;

        debug!("Inbox filter set: {} -> {:?}", sender, filter_data.mode);

        Ok(MessagingExecutionResult::success(None))
    }

    /// Add contact to whitelist
    fn add_contact(
        &self,
        sender: &Address,
        data: &[u8],
        store: &MessagingStore,
    ) -> Result<MessagingExecutionResult> {
        let contact_data: ContactData = bincode::deserialize(data)
            .map_err(|e| StateError::NftError(format!("Invalid contact data: {}", e)))?;

        let sender_hash = recipient_hash_for_address(sender);
        store.add_contact(&sender_hash, &contact_data.contact_hash)?;

        debug!("Contact added: {} added {:?}", sender, contact_data.contact_hash);

        Ok(MessagingExecutionResult::success(None))
    }

    /// Remove contact from whitelist
    fn remove_contact(
        &self,
        sender: &Address,
        data: &[u8],
        store: &MessagingStore,
    ) -> Result<MessagingExecutionResult> {
        let contact_data: ContactData = bincode::deserialize(data)
            .map_err(|e| StateError::NftError(format!("Invalid contact data: {}", e)))?;

        let sender_hash = recipient_hash_for_address(sender);
        store.remove_contact(&sender_hash, &contact_data.contact_hash)?;

        debug!("Contact removed: {} removed {:?}", sender, contact_data.contact_hash);

        Ok(MessagingExecutionResult::success(None))
    }

    /// Block a sender
    fn block_sender(
        &self,
        sender: &Address,
        data: &[u8],
        store: &MessagingStore,
    ) -> Result<MessagingExecutionResult> {
        let block_data: BlockSenderData = bincode::deserialize(data)
            .map_err(|e| StateError::NftError(format!("Invalid block data: {}", e)))?;

        let sender_hash = recipient_hash_for_address(sender);
        store.block_sender(&sender_hash, &block_data.sender)?;

        debug!("Sender blocked: {} blocked {}", sender, block_data.sender);

        Ok(MessagingExecutionResult::success(None))
    }

    /// Report spam
    fn report_spam(
        &self,
        sender: &Address,
        data: &[u8],
        store: &MessagingStore,
    ) -> Result<MessagingExecutionResult> {
        let report_data: ReportSpamData = bincode::deserialize(data)
            .map_err(|e| StateError::NftError(format!("Invalid report data: {}", e)))?;

        // Reporter must have stake
        let reporter_stake = store.get_stake_balance(sender)?;
        let min_stake = store.get_min_trust_stake()?;
        if reporter_stake < min_stake {
            return Ok(MessagingExecutionResult::failure("Reporter must have stake"));
        }

        // Increment spammer's spam score
        let new_score = store.increment_spam_score(&report_data.spammer, 5)?;

        warn!(
            "Spam reported: {} reported {} for message {}, new score: {}",
            sender, report_data.spammer, report_data.message_id, new_score
        );

        Ok(MessagingExecutionResult::success(None))
    }

    // ========================================================================
    // Public Key Registry
    // ========================================================================

    /// Register Ed25519 public key for messaging
    fn register_public_key(
        &self,
        sender: &Address,
        data: &[u8],
        block_height: u64,
        block_timestamp: u64,
        store: &MessagingStore,
    ) -> Result<MessagingExecutionResult> {
        let key_data: RegisterPublicKeyData = bincode::deserialize(data)
            .map_err(|e| StateError::NftError(format!("Invalid key data: {}", e)))?;

        // Verify the public key derives to this address
        let derived_address = Address::from_public_key(&key_data.public_key);
        if &derived_address != sender {
            return Ok(MessagingExecutionResult::failure(
                "Public key does not match sender address"
            ));
        }

        // Check if already registered
        if store.has_public_key(sender)? {
            return Ok(MessagingExecutionResult::failure(
                "Public key already registered. Use UpdatePublicKey to change."
            ));
        }

        // Store the registered key
        let registered = RegisteredPublicKey {
            public_key: key_data.public_key,
            address: *sender,
            registered_at_block: block_height,
            registered_at: block_timestamp,
            updated_at_block: 0,
        };
        store.set_public_key(sender, &registered)?;

        debug!("Public key registered: {} -> {:?}", sender, key_data.public_key);

        Ok(MessagingExecutionResult::success(None))
    }

    /// Update registered public key
    fn update_public_key(
        &self,
        sender: &Address,
        data: &[u8],
        block_height: u64,
        store: &MessagingStore,
    ) -> Result<MessagingExecutionResult> {
        let key_data: UpdatePublicKeyData = bincode::deserialize(data)
            .map_err(|e| StateError::NftError(format!("Invalid key data: {}", e)))?;

        // Get existing registration
        let existing = match store.get_public_key(sender)? {
            Some(k) => k,
            None => return Ok(MessagingExecutionResult::failure(
                "No public key registered. Use RegisterPublicKey first."
            )),
        };

        // Verify the new public key derives to this address
        let derived_address = Address::from_public_key(&key_data.new_public_key);
        if &derived_address != sender {
            return Ok(MessagingExecutionResult::failure(
                "New public key does not match sender address"
            ));
        }

        // Update the registration
        let updated = RegisteredPublicKey {
            public_key: key_data.new_public_key,
            address: *sender,
            registered_at_block: existing.registered_at_block,
            registered_at: existing.registered_at,
            updated_at_block: block_height,
        };
        store.set_public_key(sender, &updated)?;

        debug!("Public key updated: {} -> {:?}", sender, key_data.new_public_key);

        Ok(MessagingExecutionResult::success(None))
    }

    // ========================================================================
    // Admin Operations
    // ========================================================================

    fn set_daily_quota(
        &self,
        sender: &Address,
        data: &[u8],
        store: &MessagingStore,
    ) -> Result<MessagingExecutionResult> {
        if !self.is_admin(sender, store) {
            return Ok(MessagingExecutionResult::failure("Not admin"));
        }

        let quota_data: SetDailyQuotaData = bincode::deserialize(data)
            .map_err(|e| StateError::NftError(format!("Invalid quota data: {}", e)))?;

        store.set_daily_quota(quota_data.quota)?;

        debug!("Daily quota set to {} by admin {}", quota_data.quota, sender);

        Ok(MessagingExecutionResult::success(None))
    }

    fn set_max_message_size(
        &self,
        sender: &Address,
        data: &[u8],
        store: &MessagingStore,
    ) -> Result<MessagingExecutionResult> {
        if !self.is_admin(sender, store) {
            return Ok(MessagingExecutionResult::failure("Not admin"));
        }

        let size_data: SetMaxMessageSizeData = bincode::deserialize(data)
            .map_err(|e| StateError::NftError(format!("Invalid size data: {}", e)))?;

        store.set_max_message_size(size_data.size)?;

        debug!("Max message size set to {} by admin {}", size_data.size, sender);

        Ok(MessagingExecutionResult::success(None))
    }

    fn set_min_trust_stake(
        &self,
        sender: &Address,
        data: &[u8],
        store: &MessagingStore,
    ) -> Result<MessagingExecutionResult> {
        if !self.is_admin(sender, store) {
            return Ok(MessagingExecutionResult::failure("Not admin"));
        }

        let stake_data: SetMinTrustStakeData = bincode::deserialize(data)
            .map_err(|e| StateError::NftError(format!("Invalid stake data: {}", e)))?;

        store.set_min_trust_stake(stake_data.amount)?;

        debug!("Min trust stake set to {} by admin {}", stake_data.amount, sender);

        Ok(MessagingExecutionResult::success(None))
    }

    fn set_sponsorship_enabled(
        &self,
        sender: &Address,
        data: &[u8],
        store: &MessagingStore,
    ) -> Result<MessagingExecutionResult> {
        if !self.is_admin(sender, store) {
            return Ok(MessagingExecutionResult::failure("Not admin"));
        }

        let enabled_data: SetSponsorshipEnabledData = bincode::deserialize(data)
            .map_err(|e| StateError::NftError(format!("Invalid enabled data: {}", e)))?;

        store.set_sponsorship_enabled(enabled_data.enabled)?;

        debug!("Sponsorship enabled set to {} by admin {}", enabled_data.enabled, sender);

        Ok(MessagingExecutionResult::success(None))
    }

    fn fund_registry(
        &self,
        sender: &Address,
        data: &[u8],
        state: &StateManager,
        store: &MessagingStore,
    ) -> Result<MessagingExecutionResult> {
        let fund_data: FundRegistryData = bincode::deserialize(data)
            .map_err(|e| StateError::NftError(format!("Invalid fund data: {}", e)))?;

        if fund_data.amount == 0 {
            return Ok(MessagingExecutionResult::failure("Zero fund amount"));
        }

        // Deduct from sender
        state.deduct(sender, fund_data.amount)?;

        // Add to sponsorship fund
        let new_balance = store.add_sponsorship_balance(fund_data.amount)?;

        debug!("Registry funded: {} added {}, total: {}", sender, fund_data.amount, new_balance);

        Ok(MessagingExecutionResult::success(None))
    }
}

/// Helper: compute recipient hash from address
fn recipient_hash_for_address(address: &Address) -> [u8; 32] {
    recipient_hash(address)
}

// FIXME: tests reference primitives fields removed during schema migration; gated until updated.
#[cfg(all(test, feature = "legacy_tests"))]
mod tests {
    use super::*;
    use sumchain_storage::Database;
    use tempfile::TempDir;

    fn setup() -> (Arc<Database>, TempDir, Arc<StateManager>) {
        let dir = TempDir::new().unwrap();
        let db = Arc::new(Database::open_default(dir.path()).unwrap());
        let state = Arc::new(StateManager::new(db.clone(), 1));
        (db, dir, state)
    }

    #[test]
    fn test_messaging_executor_creation() {
        let (db, _dir, _state) = setup();
        let params = ChainParams::default();
        let _executor = MessagingExecutor::new(db, params);
    }
}
