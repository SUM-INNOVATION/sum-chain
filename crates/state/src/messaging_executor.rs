//! SRC-201 Messaging Executor
//!
//! Executes on-chain messaging transactions including:
//! - Message sending (sponsored and direct)
//! - Payment attachment and claims
//! - Anti-spam staking
//! - Recipient controls (filters, contacts, blocks)

use sumchain_storage::exec_view::ExecutionView;

use sumchain_genesis::{ChainParams, MessagingParams};
use sumchain_primitives::{
    Address, Balance, BlockSenderData, ClaimPaymentData, ContactData, Hash, InboxFilter,
    MessageEvent, MessagingOperation, MessagingTxData, PendingPayment, RegisteredPublicKey,
    RegisterPublicKeyData, ReportSpamData, SendMessageData, SendMessageWithPaymentData,
    SetDailyQuotaData, SetInboxFilterData, SetMaxMessageSizeData, SetMinTrustStakeData,
    SetSponsorshipEnabledData, StakeForTrustData, MessagingUnstakeData, FundRegistryData,
    UpdatePublicKeyData, SponsoredMessage, validate_message_format, DEFAULT_DAILY_QUOTA, DEFAULT_MAX_MESSAGE_SIZE,
};
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
/// No database handle, by construction.
///
/// Every operation takes the block's `ExecutionView` and no `self`, so
/// `self.db` is not something this file can name: a committed write here is a
/// compile error rather than a review finding. The committed twins stay in
/// `sumchain_storage::messaging_store` for the RPC server and for the one-time
/// index backfill, both of which are asking about canonical state.
pub struct MessagingExecutor;

impl MessagingExecutor {
    /// Get messaging params (with defaults)
    fn messaging_params(params: &ChainParams) -> MessagingParams {
        params.messaging.clone().unwrap_or_default()
    }

    /// Execute a messaging transaction
    ///
    /// `block_timestamp` arrives real from both dispatch arms and is reduced to
    /// the literal `0` they used to pass while
    /// `subsystem_block_timestamp_enabled_from_height` is closed — the same
    /// substitution, through the same function, that the other eight subsystems
    /// make (TS-11). It is not cosmetic here: `current_day` buckets the daily
    /// send quota by timestamp, so at time zero every message a chain ever sends
    /// counts against day zero and the quota is exhausted permanently; and
    /// `claim_payment` compares a pending payment's expiry against it. Both
    /// decide whether a transaction succeeds, so the substitution is gated.
    ///
    /// `tx_index` is already reduced by the dispatch arm — see
    /// [`crate::effective_tx_index`] — because it is the arm that knows the
    /// index. It reaches the event-row keys unchanged from here.
    #[allow(clippy::too_many_arguments)]
    pub fn execute(
        view: &mut ExecutionView<'_, '_>,
        params: &ChainParams,
        sender: &Address,
        data: &MessagingTxData,
        proposer: &Address,
        fee: Balance,
        block_height: u64,
        block_timestamp: u64,
        tx_index: u32,
        tx_hash: Hash,
    ) -> Result<MessagingExecutionResult> {
        let block_timestamp = crate::effective_block_timestamp(
            block_timestamp,
            crate::subsystem_block_timestamp_gate_open(params, block_height),
        );
        match data.operation {
            MessagingOperation::SendMessage => Self::send_message_sponsored(
                view,
                params,
                sender,
                &data.data,
                proposer,
                block_height,
                block_timestamp,
                tx_index,
                tx_hash,
            ),
            MessagingOperation::SendMessageDirect => Self::send_message_direct(
                view,
                params,
                sender,
                &data.data,
                proposer,
                fee,
                block_height,
                block_timestamp,
                tx_index,
                tx_hash,
            ),
            MessagingOperation::SendMessageWithPayment => Self::send_message_with_payment(
                view,
                params,
                sender,
                &data.data,
                proposer,
                fee,
                block_height,
                block_timestamp,
                tx_index,
                tx_hash,
            ),
            MessagingOperation::ClaimPayment => {
                Self::claim_payment(view, sender, &data.data, block_timestamp)
            }
            MessagingOperation::StakeForTrust => Self::stake_for_trust(view, sender, &data.data),
            MessagingOperation::Unstake => Self::unstake(view, sender, &data.data),
            MessagingOperation::SetInboxFilter => Self::set_inbox_filter(view, sender, &data.data),
            MessagingOperation::AddContact => Self::add_contact(view, sender, &data.data),
            MessagingOperation::RemoveContact => Self::remove_contact(view, sender, &data.data),
            MessagingOperation::BlockSender => Self::block_sender(view, sender, &data.data),
            MessagingOperation::ReportSpam => Self::report_spam(view, sender, &data.data),
            MessagingOperation::RegisterPublicKey => {
                Self::register_public_key(view, sender, &data.data, block_height, block_timestamp)
            }
            MessagingOperation::UpdatePublicKey => {
                Self::update_public_key(view, sender, &data.data, block_height)
            }
            // Admin operations
            MessagingOperation::SetDailyQuota => {
                Self::set_daily_quota(view, params, sender, &data.data)
            }
            MessagingOperation::SetMaxMessageSize => {
                Self::set_max_message_size(view, params, sender, &data.data)
            }
            MessagingOperation::SetMinTrustStake => {
                Self::set_min_trust_stake(view, params, sender, &data.data)
            }
            MessagingOperation::SetSponsorshipEnabled => {
                Self::set_sponsorship_enabled(view, params, sender, &data.data)
            }
            MessagingOperation::FundRegistry => Self::fund_registry(view, sender, &data.data),
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

    /// Whether `sender` is the registry admin, as the CANDIDATE sees it.
    ///
    /// Fallible on purpose. The previous shape was `-> bool` around
    /// `if let Ok(Some(admin))`, which put three different situations in one
    /// bucket: no admin row, an admin row that failed to decode, and a storage
    /// error. A malformed row therefore fell through to the GENESIS admin --
    /// a corrupt twenty-first byte silently moved authority back to the
    /// configured address, and the caller could not tell.
    ///
    /// Now: a decode or storage failure propagates, an admin row present
    /// decides the answer, and the genesis fallback applies only when there is
    /// genuinely no row.
    fn v_is_admin(
        view: &ExecutionView<'_, '_>,
        params: &ChainParams,
        sender: &Address,
    ) -> Result<bool> {
        if let Some(admin) = Self::v_get_registry_admin(view)? {
            return Ok(&admin == sender);
        }
        // No row at all: fall back to the genesis-configured admin.
        if let Some(ref msg_params) = params.messaging {
            if let Some(ref admin_str) = msg_params.registry_admin {
                if let Ok(admin) =
                    Address::from_base58(admin_str).or_else(|_| Address::from_hex(admin_str))
                {
                    return Ok(&admin == sender);
                }
            }
        }
        Ok(false)
    }

    /// Calculate current day (for rate limiting)
    fn current_day(timestamp: u64) -> u32 {
        (timestamp / 86400) as u32
    }

    /// Check rate limit for sender
    fn check_rate_limit(
        view: &ExecutionView<'_, '_>,
        sender: &Address,
        timestamp: u64,
    ) -> Result<()> {
        let day = Self::current_day(timestamp);
        let count = Self::v_get_daily_message_count(view, sender, day)?;
        let quota = Self::v_get_daily_quota(view)?;

        // Staked senders get 5x quota
        let stake = Self::v_get_stake_balance(view, sender)?;
        let min_stake = Self::v_get_min_trust_stake(view)?;
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
    fn check_spam_restrictions(
        view: &ExecutionView<'_, '_>,
        params: &ChainParams,
        sender: &Address,
    ) -> Result<()> {
        let score = Self::v_get_spam_score(view, sender)?;
        let params = Self::messaging_params(params);

        if score >= params.high_spam_threshold {
            // High spam score requires stake
            let stake = Self::v_get_stake_balance(view, sender)?;
            let min_stake = Self::v_get_min_trust_stake(view)?;
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
        view: &ExecutionView<'_, '_>,
        sender: &Address,
        recipient_hash: &[u8; 32],
    ) -> Result<()> {
        let filter = Self::v_get_inbox_filter(view, recipient_hash)?;

        match filter {
            InboxFilter::AcceptAll => {
                // Check if blocked
                if Self::v_is_blocked(view, recipient_hash, sender)? {
                    return Err(StateError::NftError("Sender is blocked".to_string()));
                }
            }
            InboxFilter::ContactsOnly => {
                let sender_hash = recipient_hash_for_address(sender);
                if !Self::v_is_contact(view, recipient_hash, &sender_hash)? {
                    return Err(StateError::NftError("Sender not in contacts".to_string()));
                }
            }
            InboxFilter::StakedOnly => {
                let stake = Self::v_get_stake_balance(view, sender)?;
                let min_stake = Self::v_get_min_trust_stake(view)?;
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
    #[allow(clippy::too_many_arguments)]
    fn send_message_sponsored(
        view: &mut ExecutionView<'_, '_>,
        params: &ChainParams,
        _sponsor: &Address, // tx.from is the sponsor, not the message sender
        data: &[u8],
        proposer: &Address,
        block_height: u64,
        block_timestamp: u64,
        tx_index: u32,
        tx_hash: Hash,
    ) -> Result<MessagingExecutionResult> {
        // Check if sponsorship is enabled
        if !Self::v_is_sponsorship_enabled(view)? {
            return Ok(MessagingExecutionResult::failure("Sponsorship disabled"));
        }

        // Parse sponsored message data (includes sender_pubkey)
        let sponsored_msg: SponsoredMessage = bincode::deserialize(data)
            .map_err(|e| StateError::NftError(format!("Invalid sponsored message data: {}", e)))?;

        // Derive the real sender address from the sender's public key
        let real_sender = Address::from_public_key(&sponsored_msg.sender_pubkey);

        // Verify the real sender has registered their public key.
        //
        // issue #145: this predicate is a CONSENSUS branch — every validator must
        // evaluate it identically or their state roots diverge. A DB read error is
        // a node-local I/O fault, NOT the fact "sender is unregistered". Swallowing
        // it with `unwrap_or(false)` would silently push the faulting node down the
        // failure branch while a healthy node takes the success branch → fork.
        // Propagate the error with `?` so the faulting node halts loudly (and can be
        // recovered) instead of committing a divergent block.
        if !Self::v_has_public_key(view, &real_sender)? {
            return Ok(MessagingExecutionResult::failure("Sender must register public key first"));
        }

        // Validate message format
        if let Err(e) = validate_message_format(&sponsored_msg.message_data) {
            return Ok(MessagingExecutionResult::failure(format!("Invalid message format: {}", e)));
        }

        // Check message size
        let max_size = Self::v_get_max_message_size(view)?;
        if sponsored_msg.message_data.len() > max_size as usize {
            return Ok(MessagingExecutionResult::failure("Message too large"));
        }

        // Check expiry
        if sponsored_msg.expiry < block_timestamp {
            return Ok(MessagingExecutionResult::failure("Sponsored message has expired"));
        }

        // Check rate limit for the real sender
        Self::check_rate_limit(view, &real_sender, block_timestamp)?;

        // Check spam restrictions for the real sender
        Self::check_spam_restrictions(view, params, &real_sender)?;

        // Check recipient filter (using real sender)
        Self::check_recipient_filter(view, &real_sender, &sponsored_msg.recipient_hash)?;

        // Credit fee to proposer (fee already deducted from sponsor in tx validation)
        // Note: The sponsor pays the fee via normal tx flow, no sponsorship pool deduction needed

        // Increment real sender's nonce and daily count
        Self::v_increment_sender_nonce(view, &real_sender)?;
        let day = Self::current_day(block_timestamp);
        Self::v_increment_daily_message_count(view, &real_sender, day)?;

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
        Self::v_store_message_event(view, &event, tx_index)?;

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
    #[allow(clippy::too_many_arguments)]
    fn send_message_direct(
        view: &mut ExecutionView<'_, '_>,
        params: &ChainParams,
        sender: &Address,
        data: &[u8],
        proposer: &Address,
        fee: Balance,
        block_height: u64,
        block_timestamp: u64,
        tx_index: u32,
        tx_hash: Hash,
    ) -> Result<MessagingExecutionResult> {
        // Parse message data
        let msg_data: SendMessageData = bincode::deserialize(data)
            .map_err(|e| StateError::NftError(format!("Invalid message data: {}", e)))?;

        // Validate message format
        if let Err(e) = validate_message_format(&msg_data.message_data) {
            return Ok(MessagingExecutionResult::failure(format!("Invalid message format: {}", e)));
        }

        // Check message size
        let max_size = Self::v_get_max_message_size(view)?;
        if msg_data.message_data.len() > max_size as usize {
            return Ok(MessagingExecutionResult::failure("Message too large"));
        }

        // Check rate limit
        Self::check_rate_limit(view, sender, block_timestamp)?;

        // Check spam restrictions
        Self::check_spam_restrictions(view, params, sender)?;

        // Check recipient filter
        Self::check_recipient_filter(view, sender, &msg_data.recipient_hash)?;

        // Deduct fee and pay proposer
        StateManager::v_deduct(view, sender, fee)?;
        StateManager::v_credit(view, proposer, fee)?;

        // Increment nonce
        StateManager::v_increment_nonce(view, sender)?;

        // Increment sender's message nonce and daily count
        Self::v_increment_sender_nonce(view, sender)?;
        let day = Self::current_day(block_timestamp);
        Self::v_increment_daily_message_count(view, sender, day)?;

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
        Self::v_store_message_event(view, &event, tx_index)?;

        debug!("Direct message sent: {} -> {:?}", sender, msg_data.recipient_hash);

        Ok(MessagingExecutionResult::success(Some(tx_hash)))
    }

    /// Send message with attached Koppa payment
    #[allow(clippy::too_many_arguments)]
    fn send_message_with_payment(
        view: &mut ExecutionView<'_, '_>,
        params: &ChainParams,
        sender: &Address,
        data: &[u8],
        proposer: &Address,
        fee: Balance,
        block_height: u64,
        block_timestamp: u64,
        tx_index: u32,
        tx_hash: Hash,
    ) -> Result<MessagingExecutionResult> {
        // Parse message data
        let msg_data: SendMessageWithPaymentData = bincode::deserialize(data)
            .map_err(|e| StateError::NftError(format!("Invalid message data: {}", e)))?;

        // Validate message format
        if let Err(e) = validate_message_format(&msg_data.message_data) {
            return Ok(MessagingExecutionResult::failure(format!("Invalid message format: {}", e)));
        }

        // Check message size
        let max_size = Self::v_get_max_message_size(view)?;
        if msg_data.message_data.len() > max_size as usize {
            return Ok(MessagingExecutionResult::failure("Message too large"));
        }

        // Check rate limit
        Self::check_rate_limit(view, sender, block_timestamp)?;

        // Check spam restrictions
        Self::check_spam_restrictions(view, params, sender)?;

        // Check recipient filter
        Self::check_recipient_filter(view, sender, &msg_data.recipient_hash)?;

        // Calculate total cost
        let total_cost = fee.saturating_add(msg_data.koppa_amount);
        let balance = StateManager::v_get_balance(view, sender)?;
        if balance < total_cost {
            return Ok(MessagingExecutionResult::failure("Insufficient balance"));
        }

        // Deduct fee and payment
        StateManager::v_deduct(view, sender, total_cost)?;
        StateManager::v_credit(view, proposer, fee)?;

        // Escrow the payment (store as pending)
        let expiry = block_timestamp + (7 * 24 * 3600); // 7 days expiry
        let pending = PendingPayment {
            recipient_hash: msg_data.recipient_hash,
            amount: msg_data.koppa_amount,
            expiry,
            sender: *sender,
        };
        Self::v_set_pending_payment(view, &tx_hash, &pending)?;

        // Increment nonce
        StateManager::v_increment_nonce(view, sender)?;

        // Increment sender's message nonce and daily count
        Self::v_increment_sender_nonce(view, sender)?;
        let day = Self::current_day(block_timestamp);
        Self::v_increment_daily_message_count(view, sender, day)?;

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
        Self::v_store_message_event(view, &event, tx_index)?;

        debug!(
            "Message with payment sent: {} -> {:?}, amount: {}",
            sender, msg_data.recipient_hash, msg_data.koppa_amount
        );

        Ok(MessagingExecutionResult::success(Some(tx_hash)))
    }

    /// Claim payment from a message
    fn claim_payment(
        view: &mut ExecutionView<'_, '_>,
        sender: &Address,
        data: &[u8],
        block_timestamp: u64,
    ) -> Result<MessagingExecutionResult> {
        let claim_data: ClaimPaymentData = bincode::deserialize(data)
            .map_err(|e| StateError::NftError(format!("Invalid claim data: {}", e)))?;

        // Get pending payment
        let pending = match Self::v_get_pending_payment(view, &claim_data.message_id)? {
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
            StateManager::v_credit(view, &pending.sender, pending.amount)?;
            Self::v_delete_pending_payment(view, &claim_data.message_id)?;
            return Ok(MessagingExecutionResult::failure("Payment expired, refunded to sender"));
        }

        // Credit recipient
        StateManager::v_credit(view, sender, pending.amount)?;

        // Delete pending payment
        Self::v_delete_pending_payment(view, &claim_data.message_id)?;

        debug!("Payment claimed: {} received {}", sender, pending.amount);

        Ok(MessagingExecutionResult::success(Some(claim_data.message_id)))
    }

    /// Stake Koppa for trusted sender tier
    fn stake_for_trust(
        view: &mut ExecutionView<'_, '_>,
        sender: &Address,
        data: &[u8],
    ) -> Result<MessagingExecutionResult> {
        let stake_data: StakeForTrustData = bincode::deserialize(data)
            .map_err(|e| StateError::NftError(format!("Invalid stake data: {}", e)))?;

        if stake_data.amount == 0 {
            return Ok(MessagingExecutionResult::failure("Zero stake amount"));
        }

        // Deduct from sender's balance
        StateManager::v_deduct(view, sender, stake_data.amount)?;

        // Add to stake
        let new_stake = Self::v_add_stake(view, sender, stake_data.amount)?;

        debug!("Staked for trust: {} staked {}, total: {}", sender, stake_data.amount, new_stake);

        Ok(MessagingExecutionResult::success(None))
    }

    /// Unstake Koppa
    fn unstake(
        view: &mut ExecutionView<'_, '_>,
        sender: &Address,
        data: &[u8],
    ) -> Result<MessagingExecutionResult> {
        let unstake_data: MessagingUnstakeData = bincode::deserialize(data)
            .map_err(|e| StateError::NftError(format!("Invalid unstake data: {}", e)))?;

        let current_stake = Self::v_get_stake_balance(view, sender)?;
        if current_stake < unstake_data.amount {
            return Ok(MessagingExecutionResult::failure("Insufficient stake"));
        }

        // Deduct from stake
        let new_stake = current_stake.saturating_sub(unstake_data.amount);
        Self::v_set_stake_balance(view, sender, new_stake)?;

        // Credit back to sender
        StateManager::v_credit(view, sender, unstake_data.amount)?;

        debug!("Unstaked: {} withdrew {}, remaining: {}", sender, unstake_data.amount, new_stake);

        Ok(MessagingExecutionResult::success(None))
    }

    /// Set inbox filter mode
    fn set_inbox_filter(
        view: &mut ExecutionView<'_, '_>,
        sender: &Address,
        data: &[u8],
    ) -> Result<MessagingExecutionResult> {
        let filter_data: SetInboxFilterData = bincode::deserialize(data)
            .map_err(|e| StateError::NftError(format!("Invalid filter data: {}", e)))?;

        let sender_hash = recipient_hash_for_address(sender);
        Self::v_set_inbox_filter(view, &sender_hash, filter_data.mode)?;

        debug!("Inbox filter set: {} -> {:?}", sender, filter_data.mode);

        Ok(MessagingExecutionResult::success(None))
    }

    /// Add contact to whitelist
    fn add_contact(
        view: &mut ExecutionView<'_, '_>,
        sender: &Address,
        data: &[u8],
    ) -> Result<MessagingExecutionResult> {
        let contact_data: ContactData = bincode::deserialize(data)
            .map_err(|e| StateError::NftError(format!("Invalid contact data: {}", e)))?;

        let sender_hash = recipient_hash_for_address(sender);
        Self::v_add_contact(view, &sender_hash, &contact_data.contact_hash)?;

        debug!("Contact added: {} added {:?}", sender, contact_data.contact_hash);

        Ok(MessagingExecutionResult::success(None))
    }

    /// Remove contact from whitelist
    fn remove_contact(
        view: &mut ExecutionView<'_, '_>,
        sender: &Address,
        data: &[u8],
    ) -> Result<MessagingExecutionResult> {
        let contact_data: ContactData = bincode::deserialize(data)
            .map_err(|e| StateError::NftError(format!("Invalid contact data: {}", e)))?;

        let sender_hash = recipient_hash_for_address(sender);
        Self::v_remove_contact(view, &sender_hash, &contact_data.contact_hash)?;

        debug!("Contact removed: {} removed {:?}", sender, contact_data.contact_hash);

        Ok(MessagingExecutionResult::success(None))
    }

    /// Block a sender
    fn block_sender(
        view: &mut ExecutionView<'_, '_>,
        sender: &Address,
        data: &[u8],
    ) -> Result<MessagingExecutionResult> {
        let block_data: BlockSenderData = bincode::deserialize(data)
            .map_err(|e| StateError::NftError(format!("Invalid block data: {}", e)))?;

        let sender_hash = recipient_hash_for_address(sender);
        Self::v_block_sender(view, &sender_hash, &block_data.sender)?;

        debug!("Sender blocked: {} blocked {}", sender, block_data.sender);

        Ok(MessagingExecutionResult::success(None))
    }

    /// Report spam
    fn report_spam(
        view: &mut ExecutionView<'_, '_>,
        sender: &Address,
        data: &[u8],
    ) -> Result<MessagingExecutionResult> {
        let report_data: ReportSpamData = bincode::deserialize(data)
            .map_err(|e| StateError::NftError(format!("Invalid report data: {}", e)))?;

        // Reporter must have stake
        let reporter_stake = Self::v_get_stake_balance(view, sender)?;
        let min_stake = Self::v_get_min_trust_stake(view)?;
        if reporter_stake < min_stake {
            return Ok(MessagingExecutionResult::failure("Reporter must have stake"));
        }

        // Increment spammer's spam score
        let new_score = Self::v_increment_spam_score(view, &report_data.spammer, 5)?;

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
        view: &mut ExecutionView<'_, '_>,
        sender: &Address,
        data: &[u8],
        block_height: u64,
        block_timestamp: u64,
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
        if Self::v_has_public_key(view, sender)? {
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
        Self::v_set_public_key(view, sender, &registered)?;

        debug!("Public key registered: {} -> {:?}", sender, key_data.public_key);

        Ok(MessagingExecutionResult::success(None))
    }

    /// Update registered public key
    fn update_public_key(
        view: &mut ExecutionView<'_, '_>,
        sender: &Address,
        data: &[u8],
        block_height: u64,
    ) -> Result<MessagingExecutionResult> {
        let key_data: UpdatePublicKeyData = bincode::deserialize(data)
            .map_err(|e| StateError::NftError(format!("Invalid key data: {}", e)))?;

        // Get existing registration
        let existing = match Self::v_get_public_key(view, sender)? {
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
        Self::v_set_public_key(view, sender, &updated)?;

        debug!("Public key updated: {} -> {:?}", sender, key_data.new_public_key);

        Ok(MessagingExecutionResult::success(None))
    }

    // ========================================================================
    // Admin Operations
    // ========================================================================

    fn set_daily_quota(
        view: &mut ExecutionView<'_, '_>,
        params: &ChainParams,
        sender: &Address,
        data: &[u8],
    ) -> Result<MessagingExecutionResult> {
        if !Self::v_is_admin(view, params, sender)? {
            return Ok(MessagingExecutionResult::failure("Not admin"));
        }

        let quota_data: SetDailyQuotaData = bincode::deserialize(data)
            .map_err(|e| StateError::NftError(format!("Invalid quota data: {}", e)))?;

        Self::v_set_daily_quota(view, quota_data.quota)?;

        debug!("Daily quota set to {} by admin {}", quota_data.quota, sender);

        Ok(MessagingExecutionResult::success(None))
    }

    fn set_max_message_size(
        view: &mut ExecutionView<'_, '_>,
        params: &ChainParams,
        sender: &Address,
        data: &[u8],
    ) -> Result<MessagingExecutionResult> {
        if !Self::v_is_admin(view, params, sender)? {
            return Ok(MessagingExecutionResult::failure("Not admin"));
        }

        let size_data: SetMaxMessageSizeData = bincode::deserialize(data)
            .map_err(|e| StateError::NftError(format!("Invalid size data: {}", e)))?;

        Self::v_set_max_message_size(view, size_data.size)?;

        debug!("Max message size set to {} by admin {}", size_data.size, sender);

        Ok(MessagingExecutionResult::success(None))
    }

    fn set_min_trust_stake(
        view: &mut ExecutionView<'_, '_>,
        params: &ChainParams,
        sender: &Address,
        data: &[u8],
    ) -> Result<MessagingExecutionResult> {
        if !Self::v_is_admin(view, params, sender)? {
            return Ok(MessagingExecutionResult::failure("Not admin"));
        }

        let stake_data: SetMinTrustStakeData = bincode::deserialize(data)
            .map_err(|e| StateError::NftError(format!("Invalid stake data: {}", e)))?;

        Self::v_set_min_trust_stake(view, stake_data.amount)?;

        debug!("Min trust stake set to {} by admin {}", stake_data.amount, sender);

        Ok(MessagingExecutionResult::success(None))
    }

    fn set_sponsorship_enabled(
        view: &mut ExecutionView<'_, '_>,
        params: &ChainParams,
        sender: &Address,
        data: &[u8],
    ) -> Result<MessagingExecutionResult> {
        if !Self::v_is_admin(view, params, sender)? {
            return Ok(MessagingExecutionResult::failure("Not admin"));
        }

        let enabled_data: SetSponsorshipEnabledData = bincode::deserialize(data)
            .map_err(|e| StateError::NftError(format!("Invalid enabled data: {}", e)))?;

        Self::v_set_sponsorship_enabled(view, enabled_data.enabled)?;

        debug!("Sponsorship enabled set to {} by admin {}", enabled_data.enabled, sender);

        Ok(MessagingExecutionResult::success(None))
    }

    fn fund_registry(
        view: &mut ExecutionView<'_, '_>,
        sender: &Address,
        data: &[u8],
    ) -> Result<MessagingExecutionResult> {
        let fund_data: FundRegistryData = bincode::deserialize(data)
            .map_err(|e| StateError::NftError(format!("Invalid fund data: {}", e)))?;

        if fund_data.amount == 0 {
            return Ok(MessagingExecutionResult::failure("Zero fund amount"));
        }

        // Deduct from sender
        StateManager::v_deduct(view, sender, fund_data.amount)?;

        // Add to sponsorship fund
        let new_balance = Self::v_add_sponsorship_balance(view, fund_data.amount)?;

        debug!("Registry funded: {} added {}, total: {}", sender, fund_data.amount, new_balance);

        Ok(MessagingExecutionResult::success(None))
    }
}

/// Helper: compute recipient hash from address
fn recipient_hash_for_address(address: &Address) -> [u8; 32] {
    recipient_hash(address)
}

#[cfg(all(test, feature = "legacy_tests"))]
mod tests {
    use super::*;
    // Scoped to this module: the production code above holds no
    // `Arc<Database>` any more, so a file-level import would be unused.
    use std::sync::Arc;
    use sumchain_storage::Database;
    use tempfile::TempDir;

    fn setup() -> (Arc<Database>, TempDir) {
        let dir = TempDir::new().unwrap();
        let db = Arc::new(Database::open_default(dir.path()).unwrap());
        (db, dir)
    }

    /// Replaces `test_messaging_executor_creation`, which asserted that
    /// `MessagingExecutor::new(db, params)` returned a value. That constructor
    /// no longer exists: `MessagingExecutor` is a unit struct and every entry
    /// point is an associated function over an `ExecutionView`, so "can it be
    /// constructed" is not a question about the type any more. What the old
    /// test was standing in for — that the executor's dispatch reaches a real
    /// operation and stages it on the candidate — is asserted directly here.
    #[test]
    fn register_public_key_stages_on_the_candidate() {
        let (db, _dir) = setup();
        let mut overlay = sumchain_storage::overlay::ApplicationOverlay::new(&db, 1 << 20);
        let view = &mut sumchain_storage::exec_view::ExecutionView::new(&mut overlay);
        let params = ChainParams::default();

        // The registration path requires the key to derive to the sender, so
        // the sender address is derived rather than chosen.
        let public_key = [7u8; 32];
        let sender = Address::from_public_key(&public_key);
        let proposer = Address::new([99u8; 20]);

        assert!(
            !MessagingExecutor::v_has_public_key(view, &sender).unwrap(),
            "no key is registered before the transaction runs"
        );

        let tx_data = MessagingTxData {
            operation: MessagingOperation::RegisterPublicKey,
            data: bincode::serialize(&RegisterPublicKeyData { public_key }).unwrap(),
        };

        let result = MessagingExecutor::execute(
            view,
            &params,
            &sender,
            &tx_data,
            &proposer,
            1000,
            100,
            1_000_000,
            0,
            Hash::default(),
        )
        .unwrap();
        assert!(
            result.success,
            "RegisterPublicKey failed: {:?}",
            result.error
        );

        // Read the CANDIDATE: this executor stages, it does not commit.
        let registered = MessagingExecutor::v_get_public_key(view, &sender)
            .unwrap()
            .expect("the key is on the candidate");
        assert_eq!(registered.public_key, public_key);
        assert_eq!(registered.address, sender);
    }

    /// The same entry point must refuse a key that does not derive to the
    /// sender, and refuse it as a failed result rather than an error.
    #[test]
    fn register_public_key_refuses_a_key_that_is_not_the_senders() {
        let (db, _dir) = setup();
        let mut overlay = sumchain_storage::overlay::ApplicationOverlay::new(&db, 1 << 20);
        let view = &mut sumchain_storage::exec_view::ExecutionView::new(&mut overlay);
        let params = ChainParams::default();

        let public_key = [7u8; 32];
        let not_the_sender = Address::new([1u8; 20]);
        assert_ne!(Address::from_public_key(&public_key), not_the_sender);
        let proposer = Address::new([99u8; 20]);

        let tx_data = MessagingTxData {
            operation: MessagingOperation::RegisterPublicKey,
            data: bincode::serialize(&RegisterPublicKeyData { public_key }).unwrap(),
        };

        let result = MessagingExecutor::execute(
            view,
            &params,
            &not_the_sender,
            &tx_data,
            &proposer,
            1000,
            100,
            1_000_000,
            0,
            Hash::default(),
        )
        .unwrap();
        assert!(!result.success);
        assert!(
            !MessagingExecutor::v_has_public_key(view, &not_the_sender).unwrap(),
            "a refused registration stages nothing"
        );
    }
}
