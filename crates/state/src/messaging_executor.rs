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
use sumchain_primitives::{verify_sponsored_send_v2, SponsoredEnvelopeError};
use sumchain_crypto::recipient_hash;
use tracing::{debug, warn};

use crate::{Result, StateError, StateManager};

/// Width of the daily-quota bucket, applied to the block timestamp.
/// Named so the consensus configuration (#268) commits to it.
pub const MESSAGING_DAY_SECONDS: u64 = 86400;
/// Quota multiplier for a sender whose stake meets the trust minimum.
pub const STAKED_SENDER_QUOTA_MULTIPLIER: u32 = 5;
/// Added to the block timestamp to set a pending payment's expiry.
pub const PENDING_PAYMENT_EXPIRY: u64 = 7 * 24 * 3600;
/// Spam-score increment applied by one accepted report.
pub const SPAM_REPORT_SCORE_INCREMENT: u32 = 5;
/// Divisor taking the block timestamp, in milliseconds since the Unix epoch,
/// to the seconds every messaging time rule is written in (#278). Applied only
/// at and above `messaging_timestamp_units_enabled_from_height`.
pub const MESSAGING_TIMESTAMP_MS_PER_SECOND: u64 = 1000;

/// Result of messaging execution
#[derive(Debug)]
pub struct MessagingExecutionResult {
    pub success: bool,
    pub message_id: Option<Hash>,
    pub error: Option<String>,
    /// For a refused sponsored send whose envelope was authenticated (it
    /// decoded, its version-2 signature verified strictly and its nonce was
    /// the named sender's current one): that sender and nonce. From
    /// `messaging_fee_nonce_accounting_enabled_from_height` the block loop
    /// spends the nonce when it settles the refusal. `None` for every other
    /// result.
    pub consumes: Option<(Address, u64)>,
}

impl MessagingExecutionResult {
    pub fn success(message_id: Option<Hash>) -> Self {
        Self {
            success: true,
            message_id,
            error: None,
            consumes: None,
        }
    }

    pub fn failure(error: impl Into<String>) -> Self {
        Self {
            success: false,
            message_id: None,
            error: Some(error.into()),
            consumes: None,
        }
    }

    /// A refusal of an authenticated sponsored envelope: `sender`'s envelope
    /// at `nonce`.
    pub fn refused_authenticated(error: impl Into<String>, sender: Address, nonce: u64) -> Self {
        Self {
            consumes: Some((sender, nonce)),
            ..Self::failure(error)
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

    /// The activation height for reading the block timestamp in seconds.
    ///
    /// Reads `params.messaging_timestamp_units_enabled_from_height`.
    ///
    /// Issue #278. The block timestamp is milliseconds since the Unix epoch;
    /// the three messaging time rules are written in seconds: the daily-quota
    /// bucket ([`MESSAGING_DAY_SECONDS`]), a pending payment's expiry
    /// ([`PENDING_PAYMENT_EXPIRY`]), and a sponsored message's client-signed
    /// `expiry`, which `messaging_submitSponsored` checks against
    /// `as_secs()`. Below this height they are applied to the millisecond value
    /// exactly as before; at and above it to the value divided by
    /// [`MESSAGING_TIMESTAMP_MS_PER_SECOND`].
    ///
    /// Its own field, not `subsystem_block_timestamp_enabled_from_height`: that
    /// gate decides WHETHER the executor sees the block's time, this one what
    /// UNIT it reads it in. While the timestamp gate is closed the executor sees
    /// zero, and zero is zero in either unit, so this gate is inert until that
    /// one opens. Opening the timestamp gate without this one gives an 86.4 s
    /// quota window, a ten-minute payment expiry and a sponsored message that is
    /// always expired.
    #[inline]
    fn timestamp_units_activation(params: &ChainParams) -> Option<u64> {
        params.messaging_timestamp_units_enabled_from_height
    }

    /// The time messaging's rules compare against, at `block_height`.
    ///
    /// `block_timestamp` is the already-gated value from
    /// [`crate::effective_block_timestamp`]. Below the units gate it is
    /// returned unchanged; at and above it, in whole seconds.
    fn rule_clock(params: &ChainParams, block_height: u64, block_timestamp: u64) -> u64 {
        match Self::timestamp_units_activation(params) {
            Some(h) if block_height >= h => block_timestamp / MESSAGING_TIMESTAMP_MS_PER_SECOND,
            _ => block_timestamp,
        }
    }

    /// `ChainParams::messaging_sponsored_envelope_verification_enabled_from_height`.
    ///
    /// Reads `params.messaging_sponsored_envelope_verification_enabled_from_height`.
    fn sponsored_envelope_verification_activation(params: &ChainParams) -> Option<u64> {
        params.messaging_sponsored_envelope_verification_enabled_from_height
    }

    /// Whether a sponsored `SendMessage` in a block at `block_height` is
    /// accepted only with a version-2 sender envelope that verifies: a strict
    /// signature by the named sender over
    /// [`sumchain_primitives::sponsored_send_v2_signing_preimage`] and the
    /// sender's current messaging nonce; a positive amount is then paid by the
    /// named sender into the pending-payment escrow. Below the gate, or while
    /// it is unset, the envelope is executed under the earlier rule, as
    /// before.
    pub fn sponsored_envelope_verification_gate_open(
        params: &ChainParams,
        block_height: u64,
    ) -> bool {
        matches!(
            Self::sponsored_envelope_verification_activation(params),
            Some(h) if block_height >= h
        )
    }

    /// `ChainParams::messaging_fee_nonce_accounting_enabled_from_height`.
    ///
    /// Reads `params.messaging_fee_nonce_accounting_enabled_from_height`.
    fn fee_nonce_accounting_activation(params: &ChainParams) -> Option<u64> {
        params.messaging_fee_nonce_accounting_enabled_from_height
    }

    /// Whether every messaging operation in a block at `block_height` is
    /// charged its fee and advances the sender's account nonce, once, before
    /// it is dispatched, succeeding or refused. Below the gate, or while it is
    /// unset, the operations charge as before.
    pub fn fee_nonce_accounting_gate_open(params: &ChainParams, block_height: u64) -> bool {
        matches!(
            Self::fee_nonce_accounting_activation(params),
            Some(h) if block_height >= h
        )
    }

    /// Execute a messaging transaction
    ///
    /// `chain_id` is the chain the block belongs to, which `validate_tx` has
    /// already required the outer transaction to name; a sponsored envelope's
    /// version-2 preimage binds it.
    ///
    /// From `messaging_fee_nonce_accounting_enabled_from_height` on, the fee is
    /// charged here, once, before the operation is dispatched: `fee` leaves
    /// `sender`, `proposer` is credited and `sender`'s account nonce advances,
    /// whether the operation then succeeds or is refused, as the other V2 arms
    /// charge. The dispatch arm reports that fee on a refused operation's
    /// receipt. The two operations that charged for themselves before the gate
    /// (`SendMessageDirect`, `SendMessageWithPayment`) are told the fee is
    /// charged and charge nothing more. `validate_tx` has already required the
    /// sender's balance to cover `fee`.
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
    /// The value those rules compare against is then [`Self::rule_clock`]:
    /// the same milliseconds below `messaging_timestamp_units_enabled_from_height`,
    /// whole seconds at and above it (#278).
    ///
    /// `tx_index` is already reduced by the dispatch arm — see
    /// [`crate::effective_tx_index`] — because it is the arm that knows the
    /// index. It reaches the event-row keys unchanged from here.
    #[allow(clippy::too_many_arguments)]
    pub fn execute(
        view: &mut ExecutionView<'_, '_>,
        params: &ChainParams,
        chain_id: u64,
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
        // What the quota bucket and both expiries compare against. The stored
        // rows that RECORD a time (`MessageEvent::timestamp`,
        // `RegisteredPublicKey::registered_at`) keep `block_timestamp`.
        let clock = Self::rule_clock(params, block_height, block_timestamp);
        // Exactly once, on every path from here: nothing below charges again.
        // A refusal from here on is settled by the block loop, which rolls
        // this transaction back and charges the fee once in a scope of its
        // own (`crate::executor::RefusalCharge`). The same flag turns the
        // business checks that used to make the block inapplicable into
        // refusals (`Self::refuse`).
        let fee_charged = Self::fee_nonce_accounting_gate_open(params, block_height);
        if fee_charged {
            StateManager::v_deduct(view, sender, fee)?;
            StateManager::v_credit(view, proposer, fee)?;
            StateManager::v_increment_nonce(view, sender)?;
        }
        #[cfg(test)]
        if let Some(outcome) = test_operation::run(view) {
            return outcome;
        }
        match data.operation {
            MessagingOperation::SendMessage => Self::send_message_sponsored(
                view,
                params,
                chain_id,
                sender,
                &data.data,
                proposer,
                block_height,
                block_timestamp,
                clock,
                tx_index,
                tx_hash,
                fee_charged,
            ),
            MessagingOperation::SendMessageDirect => Self::send_message_direct(
                view,
                params,
                sender,
                &data.data,
                proposer,
                fee,
                fee_charged,
                block_height,
                block_timestamp,
                clock,
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
                fee_charged,
                block_height,
                block_timestamp,
                clock,
                tx_index,
                tx_hash,
            ),
            MessagingOperation::ClaimPayment => {
                Self::claim_payment(view, sender, &data.data, clock, fee_charged)
            }
            MessagingOperation::StakeForTrust => {
                Self::stake_for_trust(view, sender, &data.data, fee_charged)
            }
            MessagingOperation::Unstake => Self::unstake(view, sender, &data.data, fee_charged),
            MessagingOperation::SetInboxFilter => {
                Self::set_inbox_filter(view, sender, &data.data, fee_charged)
            }
            MessagingOperation::AddContact => {
                Self::add_contact(view, sender, &data.data, fee_charged)
            }
            MessagingOperation::RemoveContact => {
                Self::remove_contact(view, sender, &data.data, fee_charged)
            }
            MessagingOperation::BlockSender => {
                Self::block_sender(view, sender, &data.data, fee_charged)
            }
            MessagingOperation::ReportSpam => {
                Self::report_spam(view, sender, &data.data, fee_charged)
            }
            MessagingOperation::RegisterPublicKey => Self::register_public_key(
                view,
                sender,
                &data.data,
                block_height,
                block_timestamp,
                fee_charged,
            ),
            MessagingOperation::UpdatePublicKey => {
                Self::update_public_key(view, sender, &data.data, block_height, fee_charged)
            }
            // Admin operations
            MessagingOperation::SetDailyQuota => {
                Self::set_daily_quota(view, params, sender, &data.data, fee_charged)
            }
            MessagingOperation::SetMaxMessageSize => {
                Self::set_max_message_size(view, params, sender, &data.data, fee_charged)
            }
            MessagingOperation::SetMinTrustStake => {
                Self::set_min_trust_stake(view, params, sender, &data.data, fee_charged)
            }
            MessagingOperation::SetSponsorshipEnabled => {
                Self::set_sponsorship_enabled(view, params, sender, &data.data, fee_charged)
            }
            MessagingOperation::FundRegistry => {
                Self::fund_registry(view, sender, &data.data, fee_charged)
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
        (timestamp / MESSAGING_DAY_SECONDS) as u32
    }

    /// A business check that failed, with its reason.
    ///
    /// From `messaging_fee_nonce_accounting_enabled_from_height` (`accounted`)
    /// it is a refusal: an ordinary failed operation, which the block loop
    /// rolls back and charges once. Below the gate it is the error it always
    /// was, `StateError::NftError` with the same text, and the block that
    /// carries it is not applicable, as before.
    fn refuse(reason: String, accounted: bool) -> Result<MessagingExecutionResult> {
        if accounted {
            Ok(MessagingExecutionResult::failure(reason))
        } else {
            Err(StateError::NftError(reason))
        }
    }

    /// Decode an operation's payload. A payload that does not decode is the
    /// signer's own bytes, so no state changes the answer: from the
    /// accounting gate it is a refusal (`Err` inside), below it the error it
    /// always was, with the same text (`Err` outside).
    fn decode<T: serde::de::DeserializeOwned>(
        data: &[u8],
        what: &str,
        accounted: bool,
    ) -> Result<std::result::Result<T, MessagingExecutionResult>> {
        match bincode::deserialize(data) {
            Ok(value) => Ok(Ok(value)),
            Err(e) => Self::refuse(format!("{what}: {e}"), accounted).map(Err),
        }
    }

    /// The quota bucket a send in a block at `block_height`, with header
    /// timestamp `block_timestamp`, counts against: the day `check_rate_limit`
    /// reads, through the same timestamp gate, the same units gate and the same
    /// division. Zero for every block while the timestamp gate is closed.
    ///
    /// For readers OUTSIDE execution — the pool judges a sponsored envelope
    /// against its sender's quota at admission. Execution does not call it, and
    /// it reads and writes no state.
    pub fn quota_day(params: &ChainParams, block_height: u64, block_timestamp: u64) -> u32 {
        let block_timestamp = crate::effective_block_timestamp(
            block_timestamp,
            crate::subsystem_block_timestamp_gate_open(params, block_height),
        );
        Self::current_day(Self::rule_clock(params, block_height, block_timestamp))
    }

    /// Check rate limit for sender. `Some(reason)` when the sender is over
    /// its quota; an `Err` is a storage failure.
    fn check_rate_limit(
        view: &ExecutionView<'_, '_>,
        sender: &Address,
        timestamp: u64,
    ) -> Result<Option<String>> {
        let day = Self::current_day(timestamp);
        let count = Self::v_get_daily_message_count(view, sender, day)?;
        let quota = Self::v_get_daily_quota(view)?;

        // Staked senders get 5x quota
        let stake = Self::v_get_stake_balance(view, sender)?;
        let min_stake = Self::v_get_min_trust_stake(view)?;
        let effective_quota = if stake >= min_stake {
            quota.saturating_mul(STAKED_SENDER_QUOTA_MULTIPLIER)
        } else {
            quota
        };

        if count >= effective_quota {
            return Ok(Some("Daily quota exceeded".to_string()));
        }

        Ok(None)
    }

    /// Check spam score restrictions. `Some(reason)` when they refuse the
    /// sender; an `Err` is a storage failure.
    fn check_spam_restrictions(
        view: &ExecutionView<'_, '_>,
        params: &ChainParams,
        sender: &Address,
    ) -> Result<Option<String>> {
        let score = Self::v_get_spam_score(view, sender)?;
        let params = Self::messaging_params(params);

        if score >= params.high_spam_threshold {
            // High spam score requires stake
            let stake = Self::v_get_stake_balance(view, sender)?;
            let min_stake = Self::v_get_min_trust_stake(view)?;
            if stake < min_stake {
                return Ok(Some("High spam score requires stake".to_string()));
            }
        } else if score >= params.spam_threshold {
            // Moderate spam score: reduced quota (handled in check_rate_limit)
        }

        Ok(None)
    }

    /// Check recipient filter. `Some(reason)` when the recipient's filter
    /// refuses the sender; an `Err` is a storage failure.
    fn check_recipient_filter(
        view: &ExecutionView<'_, '_>,
        sender: &Address,
        recipient_hash: &[u8; 32],
    ) -> Result<Option<String>> {
        let filter = Self::v_get_inbox_filter(view, recipient_hash)?;

        match filter {
            InboxFilter::AcceptAll => {
                // Check if blocked
                if Self::v_is_blocked(view, recipient_hash, sender)? {
                    return Ok(Some("Sender is blocked".to_string()));
                }
            }
            InboxFilter::ContactsOnly => {
                let sender_hash = recipient_hash_for_address(sender);
                if !Self::v_is_contact(view, recipient_hash, &sender_hash)? {
                    return Ok(Some("Sender not in contacts".to_string()));
                }
            }
            InboxFilter::StakedOnly => {
                let stake = Self::v_get_stake_balance(view, sender)?;
                let min_stake = Self::v_get_min_trust_stake(view)?;
                if stake < min_stake {
                    return Ok(Some("Recipient requires staked senders".to_string()));
                }
            }
        }

        Ok(None)
    }

    /// The quota, spam and recipient-filter checks a send passes, in that
    /// order. `Some(reason)` for the first that refuses; an `Err` is a
    /// storage failure.
    fn check_send_limits(
        view: &ExecutionView<'_, '_>,
        params: &ChainParams,
        sender: &Address,
        recipient_hash: &[u8; 32],
        clock: u64,
    ) -> Result<Option<String>> {
        if let Some(reason) = Self::check_rate_limit(view, sender, clock)? {
            return Ok(Some(reason));
        }
        if let Some(reason) = Self::check_spam_restrictions(view, params, sender)? {
            return Ok(Some(reason));
        }
        Self::check_recipient_filter(view, sender, recipient_hash)
    }

    /// Send message with gas sponsorship
    /// The tx.from is the sponsor address, but the real sender is derived from
    /// SponsoredMessage.sender_pubkey
    ///
    /// From `messaging_sponsored_envelope_verification_enabled_from_height` on,
    /// the envelope is executed by [`Self::send_message_enveloped`]. Below the
    /// gate it is executed under the earlier rule, as before.
    #[allow(clippy::too_many_arguments)]
    fn send_message_sponsored(
        view: &mut ExecutionView<'_, '_>,
        params: &ChainParams,
        chain_id: u64,
        _sponsor: &Address, // tx.from is the sponsor, not the message sender
        data: &[u8],
        proposer: &Address,
        block_height: u64,
        block_timestamp: u64,
        clock: u64,
        tx_index: u32,
        tx_hash: Hash,
        accounted: bool,
    ) -> Result<MessagingExecutionResult> {
        if Self::sponsored_envelope_verification_gate_open(params, block_height) {
            return Self::send_message_enveloped(
                view,
                params,
                chain_id,
                data,
                proposer,
                block_height,
                block_timestamp,
                clock,
                tx_index,
                tx_hash,
                accounted,
            );
        }

        // Check if sponsorship is enabled
        if !Self::v_is_sponsorship_enabled(view)? {
            return Ok(MessagingExecutionResult::failure("Sponsorship disabled"));
        }

        // Parse sponsored message data (includes sender_pubkey)
        let sponsored_msg: SponsoredMessage =
            match Self::decode(data, "Invalid sponsored message data", accounted)? {
                Ok(decoded) => decoded,
                Err(refused) => return Ok(refused),
            };

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
        if sponsored_msg.expiry < clock {
            return Ok(MessagingExecutionResult::failure("Sponsored message has expired"));
        }

        // The quota, spam and recipient-filter checks, for the real sender:
        // refusals from the accounting gate, errors below it, as before.
        if let Some(reason) = Self::check_send_limits(
            view,
            params,
            &real_sender,
            &sponsored_msg.recipient_hash,
            clock,
        )? {
            return Self::refuse(reason, accounted);
        }

        // Credit fee to proposer (fee already deducted from sponsor in tx validation)
        // Note: The sponsor pays the fee via normal tx flow, no sponsorship pool deduction needed

        // Increment real sender's nonce and daily count
        Self::v_increment_sender_nonce(view, &real_sender)?;
        let day = Self::current_day(clock);
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

    /// A sponsored send from `messaging_sponsored_envelope_verification_enabled_from_height`.
    ///
    /// The envelope is **authenticated** when it decodes, its signature
    /// verifies strictly, by the key it names, over the version-2 preimage for
    /// `chain_id`, and its nonce is the named sender's current messaging
    /// nonce, read from the candidate so that a second envelope from the same
    /// sender in this block sees the first. A refusal before that point names
    /// no authorization, and nothing of the sender's is spent. A refusal after
    /// it carries the sender and nonce (`MessagingExecutionResult::consumes`):
    /// from `messaging_fee_nonce_accounting_enabled_from_height` the block loop
    /// spends that nonce when it settles the refusal, so an authorization
    /// included once is never valid again, whatever the outcome.
    ///
    /// The checks, in order:
    /// 1. the payload decodes;
    /// 2. the signature, then the nonce (authentication);
    /// 3. sponsorship enabled, the sender registered;
    /// 4. format, size, expiry against the rule clock;
    /// 5. quota, spam, recipient filters;
    /// 6. for a positive amount, the named sender's balance covers it.
    ///
    /// **The amount.** `amount = koppa_amount.unwrap_or(0)`: `Some(0)` and
    /// `None` both mean no payment (they sign the same preimage). A positive
    /// amount is a payment by the named sender, who signed it: it is debited
    /// from the sender and written to the existing pending-payment escrow,
    /// keyed by this transaction's hash, with the expiry and the claim rules of
    /// a paid send. The relayer (`tx.from`) pays only the fee; no path here
    /// moves value out of its balance unless it is itself the named sender.
    /// Affordability is read from the candidate after the fee: from the
    /// accounting gate the fee left the relayer before dispatch, so a sender
    /// that relays its own envelope is checked after paying it, and charged
    /// the fee once and the amount once.
    ///
    /// Then the amount moves, the sender's messaging nonce and daily count
    /// advance, the envelope's outcome row records this transaction (receipt
    /// code 0 and the amount escrowed), and the event is stored; it reports a
    /// payment exactly when the escrow was written.
    #[allow(clippy::too_many_arguments)]
    fn send_message_enveloped(
        view: &mut ExecutionView<'_, '_>,
        params: &ChainParams,
        chain_id: u64,
        data: &[u8],
        _proposer: &Address,
        block_height: u64,
        block_timestamp: u64,
        clock: u64,
        tx_index: u32,
        tx_hash: Hash,
        accounted: bool,
    ) -> Result<MessagingExecutionResult> {
        // ── before authentication: a refusal spends nothing of the sender's ──
        let sponsored_msg: SponsoredMessage =
            match Self::decode(data, "Invalid sponsored message data", accounted)? {
                Ok(decoded) => decoded,
                Err(refused) => return Ok(refused),
            };

        let amount = sponsored_msg.koppa_amount.unwrap_or(0);

        // The named sender's strict signature over the version-2 preimage,
        // which binds this chain, the sender key, the recipient, the message
        // bytes, the nonce, the expiry and the amount.
        match verify_sponsored_send_v2(&sponsored_msg, chain_id) {
            Ok(()) => {}
            Err(SponsoredEnvelopeError::InvalidPublicKey) => {
                return Ok(MessagingExecutionResult::failure(
                    "Invalid sponsored message sender key",
                ));
            }
            Err(SponsoredEnvelopeError::InvalidSignature) => {
                return Ok(MessagingExecutionResult::failure(
                    "Invalid sponsored message signature",
                ));
            }
        }
        let real_sender = Address::from_public_key(&sponsored_msg.sender_pubkey);
        let nonce = sponsored_msg.nonce;
        let expected = Self::v_get_sender_nonce(view, &real_sender)?;
        if nonce != expected {
            return Ok(MessagingExecutionResult::failure(format!(
                "Sponsored message nonce {nonce} is not the sender's current nonce {expected}"
            )));
        }

        // ── authenticated: a refusal from here spends the nonce ─────────────
        let refused = |reason: String| {
            Ok(MessagingExecutionResult::refused_authenticated(
                reason,
                real_sender,
                nonce,
            ))
        };

        if !Self::v_is_sponsorship_enabled(view)? {
            return refused("Sponsorship disabled".to_string());
        }
        // A DB read error is a node-local fault, not "unregistered": it
        // propagates (issue #145), as on the path below the gate.
        if !Self::v_has_public_key(view, &real_sender)? {
            return refused("Sender must register public key first".to_string());
        }
        if let Err(e) = validate_message_format(&sponsored_msg.message_data) {
            return refused(format!("Invalid message format: {e}"));
        }
        let max_size = Self::v_get_max_message_size(view)?;
        if sponsored_msg.message_data.len() > max_size as usize {
            return refused("Message too large".to_string());
        }
        if sponsored_msg.expiry < clock {
            return refused("Sponsored message has expired".to_string());
        }
        // Refusals from the accounting gate, errors below it, as before.
        if let Some(reason) = Self::check_send_limits(
            view,
            params,
            &real_sender,
            &sponsored_msg.recipient_hash,
            clock,
        )? {
            if !accounted {
                return Err(StateError::NftError(reason));
            }
            return refused(reason);
        }
        if amount > 0 && StateManager::v_get_balance(view, &real_sender)? < amount {
            return refused("Insufficient balance for payment".to_string());
        }

        // ── apply ───────────────────────────────────────────────────────────
        if amount > 0 {
            StateManager::v_deduct(view, &real_sender, amount)?;
            Self::v_set_pending_payment(
                view,
                &tx_hash,
                &PendingPayment {
                    recipient_hash: sponsored_msg.recipient_hash,
                    amount,
                    expiry: clock + PENDING_PAYMENT_EXPIRY,
                    sender: real_sender,
                },
            )?;
        }
        Self::v_increment_sender_nonce(view, &real_sender)?;
        Self::v_set_envelope_outcome(
            view,
            &real_sender,
            nonce,
            &sumchain_storage::messaging_store::EnvelopeOutcome {
                tx_hash,
                outcome_code: 0,
                escrowed_amount: amount,
            },
        )?;
        let day = Self::current_day(clock);
        Self::v_increment_daily_message_count(view, &real_sender, day)?;

        let event = MessageEvent {
            sender: real_sender,
            recipient_hash: sponsored_msg.recipient_hash,
            message_id: tx_hash,
            size: sponsored_msg.message_data.len() as u32,
            // Exactly when the escrow above was written.
            has_payment: amount > 0,
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
    ///
    /// `fee_charged`: the fee, the proposer's credit and the nonce were
    /// already accounted by [`Self::execute`] (from the fee-accounting gate
    /// on), so this operation charges nothing more. Below the gate it is
    /// `false` and the operation charges on success, as before.
    #[allow(clippy::too_many_arguments)]
    fn send_message_direct(
        view: &mut ExecutionView<'_, '_>,
        params: &ChainParams,
        sender: &Address,
        data: &[u8],
        proposer: &Address,
        fee: Balance,
        fee_charged: bool,
        block_height: u64,
        block_timestamp: u64,
        clock: u64,
        tx_index: u32,
        tx_hash: Hash,
    ) -> Result<MessagingExecutionResult> {
        // Parse message data
        let msg_data: SendMessageData =
            match Self::decode(data, "Invalid message data", fee_charged)? {
                Ok(decoded) => decoded,
                Err(refused) => return Ok(refused),
            };

        // Validate message format
        if let Err(e) = validate_message_format(&msg_data.message_data) {
            return Ok(MessagingExecutionResult::failure(format!("Invalid message format: {}", e)));
        }

        // Check message size
        let max_size = Self::v_get_max_message_size(view)?;
        if msg_data.message_data.len() > max_size as usize {
            return Ok(MessagingExecutionResult::failure("Message too large"));
        }

        // The quota, spam and recipient-filter checks: refusals from the
        // accounting gate, errors below it, as before.
        if let Some(reason) =
            Self::check_send_limits(view, params, sender, &msg_data.recipient_hash, clock)?
        {
            return Self::refuse(reason, fee_charged);
        }

        if !fee_charged {
            // Deduct fee and pay proposer
            StateManager::v_deduct(view, sender, fee)?;
            StateManager::v_credit(view, proposer, fee)?;

            // Increment nonce
            StateManager::v_increment_nonce(view, sender)?;
        }

        // Increment sender's message nonce and daily count
        Self::v_increment_sender_nonce(view, sender)?;
        let day = Self::current_day(clock);
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
    ///
    /// `fee_charged` as in [`Self::send_message_direct`]: with the fee already
    /// accounted, only the payment is taken here, and the balance check is
    /// against the payment alone. The fee has already left the balance, so
    /// this is the earlier `fee + amount` condition, with one exception: when
    /// the sender is the block's proposer the fee comes straight back, so the
    /// check is `amount` alone, and such a sender holding less than
    /// `fee + amount` (but at least `amount`, and the fee validation requires)
    /// now succeeds, paying the fee to itself.
    #[allow(clippy::too_many_arguments)]
    fn send_message_with_payment(
        view: &mut ExecutionView<'_, '_>,
        params: &ChainParams,
        sender: &Address,
        data: &[u8],
        proposer: &Address,
        fee: Balance,
        fee_charged: bool,
        block_height: u64,
        block_timestamp: u64,
        clock: u64,
        tx_index: u32,
        tx_hash: Hash,
    ) -> Result<MessagingExecutionResult> {
        // Parse message data
        let msg_data: SendMessageWithPaymentData =
            match Self::decode(data, "Invalid message data", fee_charged)? {
                Ok(decoded) => decoded,
                Err(refused) => return Ok(refused),
            };

        // Validate message format
        if let Err(e) = validate_message_format(&msg_data.message_data) {
            return Ok(MessagingExecutionResult::failure(format!("Invalid message format: {}", e)));
        }

        // Check message size
        let max_size = Self::v_get_max_message_size(view)?;
        if msg_data.message_data.len() > max_size as usize {
            return Ok(MessagingExecutionResult::failure("Message too large"));
        }

        // The quota, spam and recipient-filter checks: refusals from the
        // accounting gate, errors below it, as before.
        if let Some(reason) =
            Self::check_send_limits(view, params, sender, &msg_data.recipient_hash, clock)?
        {
            return Self::refuse(reason, fee_charged);
        }

        // Calculate total cost
        let total_cost = if fee_charged {
            msg_data.koppa_amount
        } else {
            fee.saturating_add(msg_data.koppa_amount)
        };
        let balance = StateManager::v_get_balance(view, sender)?;
        if balance < total_cost {
            return Ok(MessagingExecutionResult::failure("Insufficient balance"));
        }

        // Deduct fee and payment
        StateManager::v_deduct(view, sender, total_cost)?;
        if !fee_charged {
            StateManager::v_credit(view, proposer, fee)?;
        }

        // Escrow the payment (store as pending)
        let expiry = clock + PENDING_PAYMENT_EXPIRY; // 7 days expiry
        let pending = PendingPayment {
            recipient_hash: msg_data.recipient_hash,
            amount: msg_data.koppa_amount,
            expiry,
            sender: *sender,
        };
        Self::v_set_pending_payment(view, &tx_hash, &pending)?;

        // Increment nonce
        if !fee_charged {
            StateManager::v_increment_nonce(view, sender)?;
        }

        // Increment sender's message nonce and daily count
        Self::v_increment_sender_nonce(view, sender)?;
        let day = Self::current_day(clock);
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
        clock: u64,
        accounted: bool,
    ) -> Result<MessagingExecutionResult> {
        let claim_data: ClaimPaymentData =
            match Self::decode(data, "Invalid claim data", accounted)? {
                Ok(decoded) => decoded,
                Err(refused) => return Ok(refused),
            };

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

        // Check expiry (if expired, refund to sender). From the accounting
        // gate the refund is the operation's outcome, a success: a refusal
        // there is rolled back and leaves no value effect. Below the gate, as
        // before: the refund is staged and the receipt reports a failure.
        // Inert while the clock gates are closed (the clock reads zero).
        if clock > pending.expiry {
            // Refund to original sender
            StateManager::v_credit(view, &pending.sender, pending.amount)?;
            Self::v_delete_pending_payment(view, &claim_data.message_id)?;
            if accounted {
                return Ok(MessagingExecutionResult::success(Some(
                    claim_data.message_id,
                )));
            }
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
        accounted: bool,
    ) -> Result<MessagingExecutionResult> {
        let stake_data: StakeForTrustData =
            match Self::decode(data, "Invalid stake data", accounted)? {
                Ok(decoded) => decoded,
                Err(refused) => return Ok(refused),
            };

        if stake_data.amount == 0 {
            return Ok(MessagingExecutionResult::failure("Zero stake amount"));
        }

        // From the accounting gate a stake the sender cannot afford is a
        // refusal, checked before anything moves. Below it the debit refuses
        // the block, as before.
        if accounted && StateManager::v_get_balance(view, sender)? < stake_data.amount {
            return Ok(MessagingExecutionResult::failure(
                "Insufficient balance for stake",
            ));
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
        accounted: bool,
    ) -> Result<MessagingExecutionResult> {
        let unstake_data: MessagingUnstakeData =
            match Self::decode(data, "Invalid unstake data", accounted)? {
                Ok(decoded) => decoded,
                Err(refused) => return Ok(refused),
            };

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
        accounted: bool,
    ) -> Result<MessagingExecutionResult> {
        let filter_data: SetInboxFilterData =
            match Self::decode(data, "Invalid filter data", accounted)? {
                Ok(decoded) => decoded,
                Err(refused) => return Ok(refused),
            };

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
        accounted: bool,
    ) -> Result<MessagingExecutionResult> {
        let contact_data: ContactData = match Self::decode(data, "Invalid contact data", accounted)?
        {
            Ok(decoded) => decoded,
            Err(refused) => return Ok(refused),
        };

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
        accounted: bool,
    ) -> Result<MessagingExecutionResult> {
        let contact_data: ContactData = match Self::decode(data, "Invalid contact data", accounted)?
        {
            Ok(decoded) => decoded,
            Err(refused) => return Ok(refused),
        };

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
        accounted: bool,
    ) -> Result<MessagingExecutionResult> {
        let block_data: BlockSenderData = match Self::decode(data, "Invalid block data", accounted)?
        {
            Ok(decoded) => decoded,
            Err(refused) => return Ok(refused),
        };

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
        accounted: bool,
    ) -> Result<MessagingExecutionResult> {
        let report_data: ReportSpamData =
            match Self::decode(data, "Invalid report data", accounted)? {
                Ok(decoded) => decoded,
                Err(refused) => return Ok(refused),
            };

        // Reporter must have stake
        let reporter_stake = Self::v_get_stake_balance(view, sender)?;
        let min_stake = Self::v_get_min_trust_stake(view)?;
        if reporter_stake < min_stake {
            return Ok(MessagingExecutionResult::failure("Reporter must have stake"));
        }

        // Increment spammer's spam score
        let new_score = Self::v_increment_spam_score(view, &report_data.spammer, SPAM_REPORT_SCORE_INCREMENT)?;

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
        accounted: bool,
    ) -> Result<MessagingExecutionResult> {
        let key_data: RegisterPublicKeyData =
            match Self::decode(data, "Invalid key data", accounted)? {
                Ok(decoded) => decoded,
                Err(refused) => return Ok(refused),
            };

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
        accounted: bool,
    ) -> Result<MessagingExecutionResult> {
        let key_data: UpdatePublicKeyData = match Self::decode(data, "Invalid key data", accounted)?
        {
            Ok(decoded) => decoded,
            Err(refused) => return Ok(refused),
        };

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
        accounted: bool,
    ) -> Result<MessagingExecutionResult> {
        if !Self::v_is_admin(view, params, sender)? {
            return Ok(MessagingExecutionResult::failure("Not admin"));
        }

        let quota_data: SetDailyQuotaData =
            match Self::decode(data, "Invalid quota data", accounted)? {
                Ok(decoded) => decoded,
                Err(refused) => return Ok(refused),
            };

        Self::v_set_daily_quota(view, quota_data.quota)?;

        debug!("Daily quota set to {} by admin {}", quota_data.quota, sender);

        Ok(MessagingExecutionResult::success(None))
    }

    fn set_max_message_size(
        view: &mut ExecutionView<'_, '_>,
        params: &ChainParams,
        sender: &Address,
        data: &[u8],
        accounted: bool,
    ) -> Result<MessagingExecutionResult> {
        if !Self::v_is_admin(view, params, sender)? {
            return Ok(MessagingExecutionResult::failure("Not admin"));
        }

        let size_data: SetMaxMessageSizeData =
            match Self::decode(data, "Invalid size data", accounted)? {
                Ok(decoded) => decoded,
                Err(refused) => return Ok(refused),
            };

        Self::v_set_max_message_size(view, size_data.size)?;

        debug!("Max message size set to {} by admin {}", size_data.size, sender);

        Ok(MessagingExecutionResult::success(None))
    }

    fn set_min_trust_stake(
        view: &mut ExecutionView<'_, '_>,
        params: &ChainParams,
        sender: &Address,
        data: &[u8],
        accounted: bool,
    ) -> Result<MessagingExecutionResult> {
        if !Self::v_is_admin(view, params, sender)? {
            return Ok(MessagingExecutionResult::failure("Not admin"));
        }

        let stake_data: SetMinTrustStakeData =
            match Self::decode(data, "Invalid stake data", accounted)? {
                Ok(decoded) => decoded,
                Err(refused) => return Ok(refused),
            };

        Self::v_set_min_trust_stake(view, stake_data.amount)?;

        debug!("Min trust stake set to {} by admin {}", stake_data.amount, sender);

        Ok(MessagingExecutionResult::success(None))
    }

    fn set_sponsorship_enabled(
        view: &mut ExecutionView<'_, '_>,
        params: &ChainParams,
        sender: &Address,
        data: &[u8],
        accounted: bool,
    ) -> Result<MessagingExecutionResult> {
        if !Self::v_is_admin(view, params, sender)? {
            return Ok(MessagingExecutionResult::failure("Not admin"));
        }

        let enabled_data: SetSponsorshipEnabledData =
            match Self::decode(data, "Invalid enabled data", accounted)? {
                Ok(decoded) => decoded,
                Err(refused) => return Ok(refused),
            };

        Self::v_set_sponsorship_enabled(view, enabled_data.enabled)?;

        debug!("Sponsorship enabled set to {} by admin {}", enabled_data.enabled, sender);

        Ok(MessagingExecutionResult::success(None))
    }

    fn fund_registry(
        view: &mut ExecutionView<'_, '_>,
        sender: &Address,
        data: &[u8],
        accounted: bool,
    ) -> Result<MessagingExecutionResult> {
        let fund_data: FundRegistryData = match Self::decode(data, "Invalid fund data", accounted)?
        {
            Ok(decoded) => decoded,
            Err(refused) => return Ok(refused),
        };

        if fund_data.amount == 0 {
            return Ok(MessagingExecutionResult::failure("Zero fund amount"));
        }

        // From the accounting gate a deposit the sender cannot afford is a
        // refusal, checked before anything moves. Below it the debit refuses
        // the block, as before.
        if accounted && StateManager::v_get_balance(view, sender)? < fund_data.amount {
            return Ok(MessagingExecutionResult::failure(
                "Insufficient balance for deposit",
            ));
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

/// Unit tests of this crate only: an operation that stands in for whichever
/// one a messaging transaction names, run after the accounting gate's charge,
/// so a test can stage writes and then refuse (or succeed) and see what the
/// block loop leaves. Not compiled outside `cargo test` of this crate.
#[cfg(test)]
pub(crate) mod test_operation {
    use super::{MessagingExecutionResult, Result};
    use std::cell::RefCell;
    use sumchain_storage::exec_view::ExecutionView;

    type Operation = Box<dyn Fn(&mut ExecutionView<'_, '_>) -> Result<MessagingExecutionResult>>;

    thread_local! {
        static OPERATION: RefCell<Option<Operation>> = const { RefCell::new(None) };
    }

    /// Run `op` in place of every messaging operation on this thread until
    /// [`clear`].
    pub(crate) fn set(op: Operation) {
        OPERATION.with(|o| *o.borrow_mut() = Some(op));
    }

    pub(crate) fn clear() {
        OPERATION.with(|o| *o.borrow_mut() = None);
    }

    pub(super) fn run(
        view: &mut ExecutionView<'_, '_>,
    ) -> Option<Result<MessagingExecutionResult>> {
        OPERATION.with(|o| o.borrow().as_ref().map(|op| op(view)))
    }
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
            1,
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
            1,
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
