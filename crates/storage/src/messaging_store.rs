//! SRC-201 Messaging Storage
//!
//! Provides storage operations for on-chain messaging:
//! - Configuration (quotas, limits, sponsorship)
//! - Rate limiting (daily counts, nonces)
//! - Anti-spam (stakes, spam scores)
//! - Recipient controls (filters, contacts, blocks)
//! - Payment escrow
//! - Message event indexing

use sumchain_primitives::{
    Address, Balance, BlockHeight, Hash, InboxFilter, MessageEvent, PendingPayment,
    RegisteredPublicKey, DEFAULT_DAILY_QUOTA, DEFAULT_MAX_MESSAGE_SIZE, DEFAULT_MIN_TRUST_STAKE,
};

use crate::db::{cf, Database};
use crate::{Result, StorageError};

/// Keys for messaging configuration
pub mod config_keys {
    pub const DAILY_QUOTA: &[u8] = b"daily_quota";
    pub const MAX_MESSAGE_SIZE: &[u8] = b"max_message_size";
    pub const MIN_TRUST_STAKE: &[u8] = b"min_trust_stake";
    pub const SPONSORSHIP_ENABLED: &[u8] = b"sponsorship_enabled";
    pub const SPONSORSHIP_BALANCE: &[u8] = b"sponsorship_balance";
    pub const REGISTRY_ADMIN: &[u8] = b"registry_admin";
    pub const SPAM_THRESHOLD: &[u8] = b"spam_threshold";
    pub const STAKE_COOLDOWN_BLOCKS: &[u8] = b"stake_cooldown_blocks";
    /// Idempotency marker for the one-time sender/payment index backfill.
    pub const INDEX_BACKFILL_V1: &[u8] = b"messaging_indexes_backfill_v1";
}

/// Hard cap on rows returned by the indexed listing reads.
pub const MESSAGING_LIST_MAX: usize = 1000;
/// Default page size for `get_messages_by_sender` when unspecified.
pub const MESSAGING_LIST_DEFAULT: usize = 100;

/// Counts produced by a one-time index backfill pass.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct BackfillStats {
    /// Number of sender-event index rows written.
    pub sender_events: u64,
    /// Number of pending-payment-by-recipient index rows written.
    pub pending_payments: u64,
    /// True if the backfill ran; false if it was already complete (gated).
    pub ran: bool,
}

// =============================================================================
// Shared key layout and codec
// =============================================================================
//
// One builder per row and one codec per value, called by the committed store
// below and by the candidate surface in `sumchain_state::messaging_view`. They
// are `pub` so there is exactly one definition to read and one to change; a
// second encoder inside either side would round-trip through itself and
// disagree only about rows the other produced.
//
// Three shapes in here are easy to get wrong, and are the reason these are
// extracted rather than restated:
//
//   * Counters and balances are BARE big-endian integers of a fixed width, not
//     bincode. Nonces and daily counts differ in width (8 and 4).
//   * Stakes and spam scores DELETE the row at zero instead of storing zero.
//     Absence and a row of zeroes are different states.
//   * Contacts, blocks and the payment index are PRESENCE rows. Contacts and
//     blocks carry the single byte `1`; the payment index carries an EMPTY
//     value. Writing `[1]` where the chain writes `[]` is a divergence a
//     round-trip test cannot see.

/// Sender-nonce row key: the address, unprefixed.
pub fn sender_nonce_key(sender: &Address) -> &[u8] {
    sender.as_bytes()
}

/// Daily-count row key: `sender(20) || day(4 BE)`.
pub fn daily_count_key(sender: &Address, day: u32) -> Vec<u8> {
    let mut key = Vec::with_capacity(24);
    key.extend_from_slice(sender.as_bytes());
    key.extend_from_slice(&day.to_be_bytes());
    key
}

/// Stake row key: the address, unprefixed.
pub fn stake_key(address: &Address) -> &[u8] {
    address.as_bytes()
}

/// Spam-score row key: the address, unprefixed.
pub fn spam_score_key(address: &Address) -> &[u8] {
    address.as_bytes()
}

/// Inbox-filter row key: the recipient hash, unprefixed.
pub fn inbox_filter_key(recipient_hash: &[u8; 32]) -> &[u8] {
    recipient_hash
}

/// Contact row key: `recipient_hash(32) || sender_hash(32)`.
pub fn contact_key(recipient_hash: &[u8; 32], sender_hash: &[u8; 32]) -> Vec<u8> {
    let mut key = Vec::with_capacity(64);
    key.extend_from_slice(recipient_hash);
    key.extend_from_slice(sender_hash);
    key
}

/// Block-list row key: `recipient_hash(32) || sender(20)`.
pub fn blocked_key(recipient_hash: &[u8; 32], sender: &Address) -> Vec<u8> {
    let mut key = Vec::with_capacity(52);
    key.extend_from_slice(recipient_hash);
    key.extend_from_slice(sender.as_bytes());
    key
}

/// Pending-payment row key: the message id, unprefixed.
pub fn pending_payment_key(message_id: &Hash) -> &[u8] {
    message_id.as_bytes()
}

/// Recipient-payment index key: `recipient_hash(32) || message_id(32)`.
pub fn payment_index_key(recipient_hash: &[u8; 32], message_id: &Hash) -> Vec<u8> {
    let mut key = Vec::with_capacity(64);
    key.extend_from_slice(recipient_hash);
    key.extend_from_slice(message_id.as_bytes());
    key
}

/// Message-event row key: `recipient_hash(32) || block_height(8 BE) ||
/// tx_index(4 BE)`.
pub fn event_key(recipient_hash: &[u8; 32], block_height: u64, tx_index: u32) -> Vec<u8> {
    let mut key = Vec::with_capacity(44);
    key.extend_from_slice(recipient_hash);
    key.extend_from_slice(&block_height.to_be_bytes());
    key.extend_from_slice(&tx_index.to_be_bytes());
    key
}

/// Sender index key: `sender(20) || block_height(8 BE) || tx_index(4 BE)`.
pub fn sender_index_key(sender: &Address, block_height: u64, tx_index: u32) -> Vec<u8> {
    let mut key = Vec::with_capacity(32);
    key.extend_from_slice(sender.as_bytes());
    key.extend_from_slice(&block_height.to_be_bytes());
    key.extend_from_slice(&tx_index.to_be_bytes());
    key
}

/// Public-key row key: the address, unprefixed.
pub fn public_key_key(address: &Address) -> &[u8] {
    address.as_bytes()
}

/// The value a presence row carries in `MESSAGING_CONTACTS` and
/// `MESSAGING_BLOCKED`.
pub const PRESENT: &[u8] = &[1];

/// The value the recipient-payment index carries: nothing. The key IS the
/// fact.
pub const INDEX_PRESENT: &[u8] = &[];

pub fn encode_u32(v: u32) -> [u8; 4] {
    v.to_be_bytes()
}

pub fn decode_u32(bytes: &[u8], what: &str) -> Result<u32> {
    Ok(u32::from_be_bytes(bytes.try_into().map_err(|_| {
        StorageError::InvalidData(format!("Invalid {what}"))
    })?))
}

pub fn encode_u64(v: u64) -> [u8; 8] {
    v.to_be_bytes()
}

pub fn decode_u64(bytes: &[u8], what: &str) -> Result<u64> {
    Ok(u64::from_be_bytes(bytes.try_into().map_err(|_| {
        StorageError::InvalidData(format!("Invalid {what}"))
    })?))
}

pub fn encode_balance(v: Balance) -> [u8; 16] {
    v.to_be_bytes()
}

pub fn decode_balance(bytes: &[u8], what: &str) -> Result<Balance> {
    Ok(u128::from_be_bytes(bytes.try_into().map_err(|_| {
        StorageError::InvalidData(format!("Invalid {what}"))
    })?))
}

/// A bool is one byte, and anything non-zero reads as true — which is what the
/// committed reader did, so the candidate must not tighten it.
pub fn encode_bool(v: bool) -> [u8; 1] {
    [if v { 1 } else { 0 }]
}

pub fn decode_bool(bytes: &[u8]) -> bool {
    bytes.first().copied().unwrap_or(0) != 0
}

pub fn encode_inbox_filter(mode: InboxFilter) -> [u8; 1] {
    [mode as u8]
}

/// An unknown or empty byte reads as `AcceptAll`, which is what the committed
/// reader did. Shared so a candidate cannot hand-roll the mapping and then
/// disagree the day a variant is added.
pub fn decode_inbox_filter(bytes: &[u8]) -> InboxFilter {
    InboxFilter::from_byte(bytes.first().copied().unwrap_or(0)).unwrap_or(InboxFilter::AcceptAll)
}

/// The registry admin is a bare 20-byte address, and a wrong-length value is an
/// ERROR rather than "no admin" -- silently reading absence there would let a
/// corrupt row disable the admin checks instead of failing the block.
pub fn decode_registry_admin(bytes: &[u8]) -> Result<Address> {
    Address::from_slice(bytes).map_err(|e| StorageError::InvalidData(e.to_string()))
}

pub fn encode_pending_payment(payment: &PendingPayment) -> Result<Vec<u8>> {
    bincode::serialize(payment).map_err(|e| StorageError::Serialization(e.to_string()))
}

pub fn decode_pending_payment(bytes: &[u8]) -> Result<PendingPayment> {
    bincode::deserialize(bytes).map_err(|e| StorageError::Serialization(e.to_string()))
}

pub fn encode_message_event(event: &MessageEvent) -> Result<Vec<u8>> {
    bincode::serialize(event).map_err(|e| StorageError::Serialization(e.to_string()))
}

pub fn decode_message_event(bytes: &[u8]) -> Result<MessageEvent> {
    bincode::deserialize(bytes).map_err(|e| StorageError::Serialization(e.to_string()))
}

pub fn encode_public_key(key: &RegisteredPublicKey) -> Result<Vec<u8>> {
    bincode::serialize(key).map_err(|e| StorageError::Serialization(e.to_string()))
}

pub fn decode_public_key(bytes: &[u8]) -> Result<RegisteredPublicKey> {
    bincode::deserialize(bytes).map_err(|e| StorageError::Serialization(e.to_string()))
}

/// Messaging storage operations
pub struct MessagingStore<'a> {
    db: &'a Database,
}

impl<'a> MessagingStore<'a> {
    pub fn new(db: &'a Database) -> Self {
        Self { db }
    }

    // ========================================================================
    // Configuration
    // ========================================================================

    /// Get daily message quota
    pub fn get_daily_quota(&self) -> Result<u32> {
        match self.db.get(cf::MESSAGING_CONFIG, config_keys::DAILY_QUOTA)? {
            Some(bytes) => Ok(decode_u32(&bytes, "quota")?),
            None => Ok(DEFAULT_DAILY_QUOTA),
        }
    }

    /// Set daily message quota
    pub fn set_daily_quota(&self, quota: u32) -> Result<()> {
        self.db.put(
            cf::MESSAGING_CONFIG,
            config_keys::DAILY_QUOTA,
            &encode_u32(quota),
        )
    }

    /// Get maximum message size
    pub fn get_max_message_size(&self) -> Result<u32> {
        match self.db.get(cf::MESSAGING_CONFIG, config_keys::MAX_MESSAGE_SIZE)? {
            Some(bytes) => Ok(decode_u32(&bytes, "size")?),
            None => Ok(DEFAULT_MAX_MESSAGE_SIZE),
        }
    }

    /// Set maximum message size
    pub fn set_max_message_size(&self, size: u32) -> Result<()> {
        self.db.put(
            cf::MESSAGING_CONFIG,
            config_keys::MAX_MESSAGE_SIZE,
            &encode_u32(size),
        )
    }

    /// Get minimum stake for trusted sender tier
    pub fn get_min_trust_stake(&self) -> Result<Balance> {
        match self.db.get(cf::MESSAGING_CONFIG, config_keys::MIN_TRUST_STAKE)? {
            Some(bytes) => Ok(decode_balance(&bytes, "stake")?),
            None => Ok(DEFAULT_MIN_TRUST_STAKE),
        }
    }

    /// Set minimum stake for trusted sender tier
    pub fn set_min_trust_stake(&self, amount: Balance) -> Result<()> {
        self.db.put(
            cf::MESSAGING_CONFIG,
            config_keys::MIN_TRUST_STAKE,
            &encode_balance(amount),
        )
    }

    /// Check if gas sponsorship is enabled
    pub fn is_sponsorship_enabled(&self) -> Result<bool> {
        match self.db.get(cf::MESSAGING_CONFIG, config_keys::SPONSORSHIP_ENABLED)? {
            Some(bytes) => Ok(bytes.first().copied() == Some(1)),
            None => Ok(true), // Enabled by default
        }
    }

    /// Set sponsorship enabled flag
    pub fn set_sponsorship_enabled(&self, enabled: bool) -> Result<()> {
        self.db.put(
            cf::MESSAGING_CONFIG,
            config_keys::SPONSORSHIP_ENABLED,
            &encode_bool(enabled),
        )
    }

    /// Get sponsorship fund balance
    pub fn get_sponsorship_balance(&self) -> Result<Balance> {
        match self.db.get(cf::MESSAGING_CONFIG, config_keys::SPONSORSHIP_BALANCE)? {
            Some(bytes) => Ok(decode_balance(&bytes, "balance")?),
            None => Ok(0),
        }
    }

    /// Set sponsorship fund balance
    pub fn set_sponsorship_balance(&self, amount: Balance) -> Result<()> {
        self.db.put(
            cf::MESSAGING_CONFIG,
            config_keys::SPONSORSHIP_BALANCE,
            &encode_balance(amount),
        )
    }

    /// Add to sponsorship fund
    pub fn add_sponsorship_balance(&self, amount: Balance) -> Result<Balance> {
        let current = self.get_sponsorship_balance()?;
        let new_balance = current.saturating_add(amount);
        self.set_sponsorship_balance(new_balance)?;
        Ok(new_balance)
    }

    /// Deduct from sponsorship fund
    pub fn deduct_sponsorship_balance(&self, amount: Balance) -> Result<Balance> {
        let current = self.get_sponsorship_balance()?;
        if current < amount {
            return Err(StorageError::InvalidData("Insufficient sponsorship balance".into()));
        }
        let new_balance = current.saturating_sub(amount);
        self.set_sponsorship_balance(new_balance)?;
        Ok(new_balance)
    }

    /// Get registry admin address
    pub fn get_registry_admin(&self) -> Result<Option<Address>> {
        match self.db.get(cf::MESSAGING_CONFIG, config_keys::REGISTRY_ADMIN)? {
            Some(bytes) => Ok(Some(decode_registry_admin(&bytes)?)),
            None => Ok(None),
        }
    }

    /// Set registry admin address
    pub fn set_registry_admin(&self, admin: &Address) -> Result<()> {
        self.db.put(cf::MESSAGING_CONFIG, config_keys::REGISTRY_ADMIN, admin.as_bytes())
    }

    // ========================================================================
    // Rate Limiting
    // ========================================================================

    /// Get sender's message nonce (for replay protection)
    pub fn get_sender_nonce(&self, sender: &Address) -> Result<u64> {
        match self
            .db
            .get(cf::MESSAGING_SENDER_NONCES, sender_nonce_key(sender))?
        {
            Some(bytes) => Ok(decode_u64(&bytes, "nonce")?),
            None => Ok(0),
        }
    }

    /// Set sender's message nonce
    pub fn set_sender_nonce(&self, sender: &Address, nonce: u64) -> Result<()> {
        self.db.put(
            cf::MESSAGING_SENDER_NONCES,
            sender_nonce_key(sender),
            &encode_u64(nonce),
        )
    }

    /// Increment sender's message nonce
    pub fn increment_sender_nonce(&self, sender: &Address) -> Result<u64> {
        let current = self.get_sender_nonce(sender)?;
        let new_nonce = current + 1;
        self.set_sender_nonce(sender, new_nonce)?;
        Ok(new_nonce)
    }

    /// Get daily message count for sender
    /// `day` is days since Unix epoch (timestamp / 86400)
    pub fn get_daily_message_count(&self, sender: &Address, day: u32) -> Result<u32> {
        match self
            .db
            .get(cf::MESSAGING_DAILY_COUNTS, &daily_count_key(sender, day))?
        {
            Some(bytes) => Ok(decode_u32(&bytes, "count")?),
            None => Ok(0),
        }
    }

    /// Increment daily message count for sender
    pub fn increment_daily_message_count(&self, sender: &Address, day: u32) -> Result<u32> {
        let current = self.get_daily_message_count(sender, day)?;
        let new_count = current + 1;

        self.db.put(
            cf::MESSAGING_DAILY_COUNTS,
            &daily_count_key(sender, day),
            &encode_u32(new_count),
        )?;
        Ok(new_count)
    }

    // ========================================================================
    // Anti-Spam
    // ========================================================================

    /// Get stake balance for anti-spam
    pub fn get_stake_balance(&self, address: &Address) -> Result<Balance> {
        match self.db.get(cf::MESSAGING_STAKES, stake_key(address))? {
            Some(bytes) => Ok(decode_balance(&bytes, "stake")?),
            None => Ok(0),
        }
    }

    /// Set stake balance
    pub fn set_stake_balance(&self, address: &Address, amount: Balance) -> Result<()> {
        if amount == 0 {
            self.db.delete(cf::MESSAGING_STAKES, stake_key(address))
        } else {
            self.db.put(
                cf::MESSAGING_STAKES,
                stake_key(address),
                &encode_balance(amount),
            )
        }
    }

    /// Add to stake balance
    pub fn add_stake(&self, address: &Address, amount: Balance) -> Result<Balance> {
        let current = self.get_stake_balance(address)?;
        let new_balance = current.saturating_add(amount);
        self.set_stake_balance(address, new_balance)?;
        Ok(new_balance)
    }

    /// Get spam score for an address
    pub fn get_spam_score(&self, address: &Address) -> Result<u32> {
        match self
            .db
            .get(cf::MESSAGING_SPAM_SCORES, spam_score_key(address))?
        {
            Some(bytes) => Ok(decode_u32(&bytes, "score")?),
            None => Ok(0),
        }
    }

    /// Set spam score for an address
    pub fn set_spam_score(&self, address: &Address, score: u32) -> Result<()> {
        if score == 0 {
            self.db
                .delete(cf::MESSAGING_SPAM_SCORES, spam_score_key(address))
        } else {
            self.db.put(
                cf::MESSAGING_SPAM_SCORES,
                spam_score_key(address),
                &encode_u32(score),
            )
        }
    }

    /// Increment spam score
    pub fn increment_spam_score(&self, address: &Address, delta: u32) -> Result<u32> {
        let current = self.get_spam_score(address)?;
        let new_score = current.saturating_add(delta);
        self.set_spam_score(address, new_score)?;
        Ok(new_score)
    }

    // ========================================================================
    // Recipient Controls
    // ========================================================================

    /// Get inbox filter mode
    pub fn get_inbox_filter(&self, recipient_hash: &[u8; 32]) -> Result<InboxFilter> {
        match self.db.get(
            cf::MESSAGING_INBOX_FILTERS,
            inbox_filter_key(recipient_hash),
        )? {
            Some(bytes) => Ok(decode_inbox_filter(&bytes)),
            None => Ok(InboxFilter::AcceptAll),
        }
    }

    /// Set inbox filter mode
    pub fn set_inbox_filter(&self, recipient_hash: &[u8; 32], mode: InboxFilter) -> Result<()> {
        self.db.put(
            cf::MESSAGING_INBOX_FILTERS,
            inbox_filter_key(recipient_hash),
            &encode_inbox_filter(mode),
        )
    }

    /// Check if sender is in recipient's contacts
    pub fn is_contact(&self, recipient_hash: &[u8; 32], sender_hash: &[u8; 32]) -> Result<bool> {
        self.db.contains(
            cf::MESSAGING_CONTACTS,
            &contact_key(recipient_hash, sender_hash),
        )
    }

    /// Add sender to recipient's contacts
    pub fn add_contact(&self, recipient_hash: &[u8; 32], sender_hash: &[u8; 32]) -> Result<()> {
        self.db.put(
            cf::MESSAGING_CONTACTS,
            &contact_key(recipient_hash, sender_hash),
            PRESENT,
        )
    }

    /// Remove sender from recipient's contacts
    pub fn remove_contact(&self, recipient_hash: &[u8; 32], sender_hash: &[u8; 32]) -> Result<()> {
        self.db.delete(
            cf::MESSAGING_CONTACTS,
            &contact_key(recipient_hash, sender_hash),
        )
    }

    /// Check if sender is blocked by recipient
    pub fn is_blocked(&self, recipient_hash: &[u8; 32], sender: &Address) -> Result<bool> {
        self.db
            .contains(cf::MESSAGING_BLOCKED, &blocked_key(recipient_hash, sender))
    }

    /// Block a sender
    pub fn block_sender(&self, recipient_hash: &[u8; 32], sender: &Address) -> Result<()> {
        self.db.put(
            cf::MESSAGING_BLOCKED,
            &blocked_key(recipient_hash, sender),
            PRESENT,
        )
    }

    /// Unblock a sender
    pub fn unblock_sender(&self, recipient_hash: &[u8; 32], sender: &Address) -> Result<()> {
        self.db
            .delete(cf::MESSAGING_BLOCKED, &blocked_key(recipient_hash, sender))
    }

    // ========================================================================
    // Payment Escrow
    // ========================================================================

    /// Get pending payment by message ID
    pub fn get_pending_payment(&self, message_id: &Hash) -> Result<Option<PendingPayment>> {
        match self.db.get(
            cf::MESSAGING_PENDING_PAYMENTS,
            pending_payment_key(message_id),
        )? {
            Some(bytes) => Ok(Some(decode_pending_payment(&bytes)?)),
            None => Ok(None),
        }
    }

    /// Store pending payment, plus the recipient -> payment secondary index,
    /// in one atomic batch so primary and index cannot diverge.
    pub fn set_pending_payment(&self, message_id: &Hash, payment: &PendingPayment) -> Result<()> {
        let bytes = encode_pending_payment(payment)?;
        let mut batch = self.db.batch();
        batch.put(
            cf::MESSAGING_PENDING_PAYMENTS,
            pending_payment_key(message_id),
            &bytes,
        )?;
        batch.put(
            cf::MESSAGING_PAYMENTS_BY_RECIPIENT,
            &payment_index_key(&payment.recipient_hash, message_id),
            INDEX_PRESENT,
        )?;
        batch.commit()
    }

    /// Delete pending payment (after claim or expiry) and its recipient index
    /// entry. The index key needs `recipient_hash`, which a `message_id` alone
    /// cannot reconstruct, so the payment is read first. A missing primary is a
    /// no-op (idempotent).
    pub fn delete_pending_payment(&self, message_id: &Hash) -> Result<()> {
        let mut batch = self.db.batch();
        if let Some(payment) = self.get_pending_payment(message_id)? {
            batch.delete(
                cf::MESSAGING_PAYMENTS_BY_RECIPIENT,
                &payment_index_key(&payment.recipient_hash, message_id),
            )?;
        }
        batch.delete(
            cf::MESSAGING_PENDING_PAYMENTS,
            pending_payment_key(message_id),
        )?;
        batch.commit()
    }

    // ========================================================================
    // Message Event Indexing
    // ========================================================================

    /// Store a message event for indexing
    /// Key format: recipient_hash (32) + block_height (8) + tx_index (4)
    pub fn store_message_event(&self, event: &MessageEvent, tx_index: u32) -> Result<()> {
        let key = event_key(&event.recipient_hash, event.block_height, tx_index);
        let bytes = encode_message_event(event)?;

        tracing::info!(
            "MessagingStore: storing message event with key prefix 0x{} (block={}, tx_index={})",
            hex::encode(&event.recipient_hash),
            event.block_height,
            tx_index
        );

        // Primary event + sender index (powers messaging_getSentMessages) in
        // one atomic batch so they cannot diverge if one write fails.
        let mut batch = self.db.batch();
        batch.put(cf::MESSAGING_EVENTS, &key, &bytes)?;
        batch.put(
            cf::MESSAGING_SENDER_EVENTS,
            &sender_index_key(&event.sender, event.block_height, tx_index),
            &bytes,
        )?;
        batch.commit()
    }

    /// List messages sent by `sender` via the sender index, ordered ascending
    /// by `(block_height, tx_index)`. `offset`/`limit` paginate; `limit` is
    /// clamped to [`MESSAGING_LIST_MAX`].
    pub fn get_messages_by_sender(
        &self,
        sender: &Address,
        limit: usize,
        offset: usize,
    ) -> Result<Vec<MessageEvent>> {
        let prefix = sender.as_bytes();
        let cap = limit.min(MESSAGING_LIST_MAX);
        let mut out = Vec::new();
        let mut skipped = 0usize;
        for (key, value) in self.db.prefix_iter(cf::MESSAGING_SENDER_EVENTS, prefix)? {
            // `prefix_iterator` can over-return; stop at the prefix boundary.
            if !key.starts_with(prefix) {
                break;
            }
            if skipped < offset {
                skipped += 1;
                continue;
            }
            if out.len() >= cap {
                break;
            }
            if let Ok(event) = decode_message_event(&value) {
                out.push(event);
            }
        }
        Ok(out)
    }

    /// List pending payments addressed to `recipient_hash` via the recipient
    /// index, returning `(message_id, payment)` pairs. Capped at
    /// [`MESSAGING_LIST_MAX`].
    pub fn get_pending_payments_by_recipient(
        &self,
        recipient_hash: &[u8; 32],
    ) -> Result<Vec<(Hash, PendingPayment)>> {
        let mut out = Vec::new();
        for (key, _) in self.db.prefix_iter(cf::MESSAGING_PAYMENTS_BY_RECIPIENT, recipient_hash)? {
            if !key.starts_with(recipient_hash) {
                break;
            }
            if out.len() >= MESSAGING_LIST_MAX {
                break;
            }
            // Key = recipient_hash(32) || message_id(32).
            if key.len() != 64 {
                continue;
            }
            let mut id = [0u8; 32];
            id.copy_from_slice(&key[32..64]);
            let message_id = Hash::new(id);
            if let Some(payment) = self.get_pending_payment(&message_id)? {
                out.push((message_id, payment));
            }
        }
        Ok(out)
    }

    /// One-time, idempotent backfill of the sender and recipient-payment
    /// indexes from the primary CFs. Gated by a marker in `MESSAGING_CONFIG`,
    /// so subsequent calls are a single point-read. Index writes are
    /// overwrites, so an ungated rerun would also be safe.
    pub fn backfill_indexes(&self) -> Result<BackfillStats> {
        if self
            .db
            .get(cf::MESSAGING_CONFIG, config_keys::INDEX_BACKFILL_V1)?
            .is_some()
        {
            return Ok(BackfillStats::default());
        }
        let mut stats = BackfillStats { ran: true, ..Default::default() };

        // Sender index from MESSAGING_EVENTS (recipient_hash(32)||block(8)||tx_index(4)).
        // Fail fast on any malformed row: a partial index must not be marked
        // complete. A failed run leaves the marker unset, so the next boot
        // retries (index writes are overwrites, so the retry is idempotent).
        for (key, value) in self.db.full_iter(cf::MESSAGING_EVENTS)? {
            if key.len() < 44 {
                return Err(StorageError::InvalidData(format!(
                    "backfill: MESSAGING_EVENTS key too short ({} bytes)",
                    key.len()
                )));
            }
            // The shared decoder, with the backfill's own context added to the
            // message rather than around the error. Formatting the error itself
            // would nest its Display inside a second `Serialization`, so the
            // text read "Serialization error: backfill: ...: Serialization
            // error: ..." -- two prefixes where the parent produced one. Any
            // other variant propagates untouched: only a decode failure is
            // something this loop has context to add to.
            let event = decode_message_event(&value).map_err(|e| match e {
                StorageError::Serialization(msg) => {
                    StorageError::Serialization(format!("backfill: bad MessageEvent: {msg}"))
                }
                other => other,
            })?;
            let tx_index = u32::from_be_bytes(key[40..44].try_into().unwrap());
            self.db.put(
                cf::MESSAGING_SENDER_EVENTS,
                &sender_index_key(&event.sender, event.block_height, tx_index),
                &value,
            )?;
            stats.sender_events += 1;
        }

        // Recipient-payment index from MESSAGING_PENDING_PAYMENTS (message_id(32)).
        for (key, value) in self.db.full_iter(cf::MESSAGING_PENDING_PAYMENTS)? {
            if key.len() != 32 {
                return Err(StorageError::InvalidData(format!(
                    "backfill: MESSAGING_PENDING_PAYMENTS key not 32 bytes ({} bytes)",
                    key.len()
                )));
            }
            let payment = decode_pending_payment(&value).map_err(|e| match e {
                StorageError::Serialization(msg) => {
                    StorageError::Serialization(format!("backfill: bad PendingPayment: {msg}"))
                }
                other => other,
            })?;
            let mut id = [0u8; 32];
            id.copy_from_slice(&key);
            let message_id = Hash::new(id);
            self.db.put(
                cf::MESSAGING_PAYMENTS_BY_RECIPIENT,
                &payment_index_key(&payment.recipient_hash, &message_id),
                &[],
            )?;
            stats.pending_payments += 1;
        }

        // Mark complete only after a fully successful pass.
        self.db.put(cf::MESSAGING_CONFIG, config_keys::INDEX_BACKFILL_V1, &[1])?;
        Ok(stats)
    }

    /// Get messages for a recipient within a block range
    pub fn get_messages_by_recipient(
        &self,
        recipient_hash: &[u8; 32],
        from_block: u64,
        to_block: u64,
        limit: usize,
    ) -> Result<Vec<MessageEvent>> {
        let mut events = Vec::new();

        // Use full scan and filter by recipient_hash and block range
        // Note: prefix_iter requires bloom filter configuration which may not be set up
        for (key, value) in self.db.full_iter(cf::MESSAGING_EVENTS)? {
            // Key format: recipient_hash (32) + block_height (8) + tx_index (4)
            if key.len() < 44 {
                continue;
            }

            // Check if recipient_hash matches (first 32 bytes of key)
            if &key[0..32] != recipient_hash {
                continue;
            }

            // Extract and check block height (bytes 32-40)
            let block_height = u64::from_be_bytes(key[32..40].try_into().unwrap_or([0u8; 8]));
            if block_height < from_block || block_height > to_block {
                continue;
            }

            if let Ok(event) = decode_message_event(&value) {
                events.push(event);
                if events.len() >= limit {
                    break;
                }
            }
        }

        Ok(events)
    }

    /// Get total message count for a recipient (within a block range)
    pub fn get_message_count(
        &self,
        recipient_hash: &[u8; 32],
        from_block: u64,
        to_block: u64,
    ) -> Result<u64> {
        let mut count = 0u64;

        // Use full scan and filter by recipient_hash and block range
        for (key, _) in self.db.full_iter(cf::MESSAGING_EVENTS)? {
            if key.len() < 44 {
                continue;
            }

            // Check if recipient_hash matches
            if &key[0..32] != recipient_hash {
                continue;
            }

            // Extract and check block height
            let block_height = u64::from_be_bytes(key[32..40].try_into().unwrap_or([0u8; 8]));
            if block_height < from_block || block_height > to_block {
                continue;
            }

            count += 1;
        }

        Ok(count)
    }

    /// Get a message by its transaction hash (message_id)
    /// This scans all events - use sparingly for debugging
    pub fn get_message_by_tx_hash(&self, tx_hash: &[u8; 32]) -> Result<Option<MessageEvent>> {
        // Scan all events looking for this message_id
        // Note: This is O(n) - consider adding a tx_hash -> event index for production
        for (_key, value) in self.db.full_iter(cf::MESSAGING_EVENTS)? {
            if let Ok(event) = decode_message_event(&value) {
                if event.message_id.as_bytes() == tx_hash {
                    return Ok(Some(event));
                }
            }
        }
        Ok(None)
    }

    /// Get all messages in a specific block
    /// This scans all events looking for the block height
    pub fn get_messages_in_block(&self, block_height: u64, limit: usize) -> Result<Vec<MessageEvent>> {
        let mut events = Vec::new();

        // Scan all events looking for this block height
        for (_key, value) in self.db.full_iter(cf::MESSAGING_EVENTS)? {
            if let Ok(event) = decode_message_event(&value) {
                if event.block_height == block_height {
                    events.push(event);
                    if events.len() >= limit {
                        break;
                    }
                }
            }
        }

        Ok(events)
    }

    // ========================================================================
    // Public Key Registry
    // ========================================================================

    /// Get registered public key for an address
    pub fn get_public_key(&self, address: &Address) -> Result<Option<RegisteredPublicKey>> {
        match self
            .db
            .get(cf::MESSAGING_PUBLIC_KEYS, public_key_key(address))?
        {
            Some(bytes) => Ok(Some(decode_public_key(&bytes)?)),
            None => Ok(None),
        }
    }

    /// Register or update public key for an address
    pub fn set_public_key(&self, address: &Address, registered_key: &RegisteredPublicKey) -> Result<()> {
        let bytes = encode_public_key(registered_key)?;
        self.db
            .put(cf::MESSAGING_PUBLIC_KEYS, public_key_key(address), &bytes)
    }

    /// Check if an address has a registered public key
    pub fn has_public_key(&self, address: &Address) -> Result<bool> {
        self.db
            .contains(cf::MESSAGING_PUBLIC_KEYS, public_key_key(address))
    }

    /// Delete registered public key (for key rotation cleanup if needed)
    pub fn delete_public_key(&self, address: &Address) -> Result<()> {
        self.db
            .delete(cf::MESSAGING_PUBLIC_KEYS, public_key_key(address))
    }

    /// Iterate every registered public key in the CF.
    /// Used by the operator-side export/import recovery tooling.
    pub fn iter_all_pubkeys(&self) -> Result<Vec<(Address, RegisteredPublicKey)>> {
        let mut out = Vec::new();
        for (key, value) in self.db.full_iter(cf::MESSAGING_PUBLIC_KEYS)? {
            if key.len() != 20 {
                continue;
            }
            let mut addr_bytes = [0u8; 20];
            addr_bytes.copy_from_slice(&key);
            let address = Address::new(addr_bytes);

            let registered = decode_public_key(&value)?;

            out.push((address, registered));
        }
        Ok(out)
    }

    // ========================================================================
    // Operator registry seed (OC-2)
    // ========================================================================

    /// Seed the SRC-201 public-key registry from an operator-supplied set, and
    /// record that it happened.
    ///
    /// # Why this exists instead of a loop over [`Self::set_public_key`]
    ///
    /// `cf::MESSAGING_PUBLIC_KEYS` is read by consensus — `SendMessage` requires
    /// the sender to hold a registered key, and both the plain and the sponsored
    /// `RegisterPublicKey` paths refuse a duplicate. A node whose copy of that
    /// family differs from its peers' therefore produces different RECEIPTS for
    /// identical blocks, and receipts are folded into the state root. Writing
    /// the family from an operator command, at any height a block has already
    /// been executed at, is a fork with no consensus event to explain it.
    ///
    /// That is not a hazard a warning closes, because the damage is also
    /// unobservable after the fact: nothing distinguishes an imported row from a
    /// registered one, so an operator who ran the import mid-chain cannot be told
    /// which rows to remove, and the only remedy is a resync.
    ///
    /// So the operation is narrowed to the one shape that is not a mutation of
    /// executed state: an INITIAL CONDITION, applied to a database that has
    /// executed no block above genesis and holds no registration of its own.
    /// Every other shape is refused here, in the library, so that no caller can
    /// reach the write without passing the same three questions.
    ///
    /// # Why a marker, and why it carries a digest
    ///
    /// Seeding at genesis is only sound if EVERY node seeds the same set — it is
    /// a coordinated initial condition, exactly like a genesis edit, and a node
    /// that seeded a different file is forked from block one rather than from
    /// block N. Nothing in the chain data records that, because the rows look
    /// identical either way.
    ///
    /// So the fact is recorded in `cf::META`, in the same batch as the rows, and
    /// it carries [`RegistrySeed::digest`] — a blake3 over the seeded set in
    /// address order, so two operators who seeded the same registrations from
    /// differently-ordered files still get the same value and two who did not
    /// cannot. The row outlives the process that wrote it, is read back by
    /// `sumchain_state::sync_capability`, and is reported in the startup log and
    /// on `chain_getSyncCapability`. "Did we all seed the same thing?" is then a
    /// question a peer can answer before the first messaging transaction, rather
    /// than an inference drawn from a diverged root afterwards.
    ///
    /// # Arguments
    ///
    /// `chain_height` is this database's own tip as
    /// [`crate::schema::BlockStore::get_latest_height`] reports it: `None` for a
    /// database that holds no block at all, `Some(0)` for one holding only
    /// genesis. Anything above that is refused.
    ///
    /// # Errors
    ///
    /// Refuses, WITHOUT WRITING ANYTHING, when the database has executed a block
    /// above genesis, when the registry already holds a row, when a seed has
    /// already been recorded, or when `keys` is empty. The rows and the marker
    /// go in one batch, so no crash can leave a seeded registry that does not
    /// say it was seeded.
    pub fn seed_registry_at_genesis(
        &self,
        chain_height: Option<BlockHeight>,
        keys: &[(Address, RegisteredPublicKey)],
    ) -> Result<RegistrySeed> {
        if let Some(height) = chain_height {
            if height > 0 {
                return Err(StorageError::InvalidData(format!(
                    "refusing to seed the SRC-201 public-key registry: this database is at \
                     height {height}, and that family is read by consensus. A write here \
                     changes the receipts this node produces for blocks it has already \
                     executed, and nothing afterwards can tell a seeded row from a \
                     registered one. Seeding is permitted only on a database that has \
                     executed no block above genesis; to correct a diverged registry, \
                     resync"
                )));
            }
        }
        if let Some(existing) = registry_seed(self.db)? {
            return Err(StorageError::InvalidData(format!(
                "refusing to seed the SRC-201 public-key registry: it was already seeded at \
                 height {} with {} key(s), digest {}. A second seed would leave this node \
                 unable to say what its registry contains",
                existing.seeded_at_height, existing.key_count, existing.digest
            )));
        }
        if self
            .db
            .full_iter(cf::MESSAGING_PUBLIC_KEYS)?
            .next()
            .is_some()
        {
            return Err(StorageError::InvalidData(
                "refusing to seed the SRC-201 public-key registry: it already holds at least \
                 one registration. A seed is an initial condition, not a merge — a partial \
                 overwrite leaves a registry no operator can describe"
                    .to_string(),
            ));
        }
        if keys.is_empty() {
            return Err(StorageError::InvalidData(
                "refusing to seed the SRC-201 public-key registry from an empty set: there is \
                 nothing to seed, and recording a marker for it would make this node claim a \
                 provenance it does not have"
                    .to_string(),
            ));
        }

        // Address order, so the digest is a property of the SET and not of the
        // order the operator's file happened to be in. Two validators seeding
        // the same registrations must agree; two seeding different ones must
        // not.
        let mut ordered: Vec<(Address, Vec<u8>)> = Vec::with_capacity(keys.len());
        for (address, key) in keys {
            ordered.push((*address, encode_public_key(key)?));
        }
        ordered.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));
        if ordered.windows(2).any(|w| w[0].0 == w[1].0) {
            return Err(StorageError::InvalidData(
                "refusing to seed the SRC-201 public-key registry: the set names the same \
                 address twice, so which registration this node would end up holding depends \
                 on input order"
                    .to_string(),
            ));
        }

        let mut hasher = blake3::Hasher::new();
        hasher.update(REGISTRY_SEED_DIGEST_CONTEXT);
        hasher.update(&(ordered.len() as u64).to_be_bytes());
        for (address, encoded) in &ordered {
            hasher.update(address.as_bytes());
            hasher.update(&(encoded.len() as u64).to_be_bytes());
            hasher.update(encoded);
        }
        let seed = RegistrySeed {
            seeded_at_height: chain_height.unwrap_or(0),
            key_count: ordered.len() as u64,
            digest: hasher.finalize().to_hex().to_string(),
        };

        // One batch: the rows and the fact that an operator put them there. The
        // caller does not get to choose the ordering, because the only ordering
        // that closes the crash window is this one.
        let mut batch = self.db.batch();
        for (address, encoded) in &ordered {
            batch.put(cf::MESSAGING_PUBLIC_KEYS, public_key_key(address), encoded)?;
        }
        batch.put(
            cf::META,
            REGISTRY_SEED_META_KEY,
            &encode_registry_seed(&seed)?,
        )?;
        batch.commit()?;
        Ok(seed)
    }
}

/// `META` key holding what an operator seed did to this database's SRC-201
/// public-key registry.
pub const REGISTRY_SEED_META_KEY: &[u8] = b"messaging/registry_seed_v1";

/// Domain separation for [`RegistrySeed::digest`], so the value cannot collide
/// with a hash this repo computes over the same bytes for another purpose.
const REGISTRY_SEED_DIGEST_CONTEXT: &[u8] = b"sumchain/messaging/registry_seed_v1";

/// What an operator seed did to this node's SRC-201 public-key registry.
///
/// Present only on a node whose registry did NOT come from its own execution.
/// A node that built the family by executing blocks has no such row, and that
/// absence is the normal, correct state.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RegistrySeed {
    /// The height the database was at when the seed was applied. Zero by
    /// construction — [`MessagingStore::seed_registry_at_genesis`] refuses above
    /// it — and recorded anyway, so the row states its own precondition rather
    /// than leaving a reader to trust that the refusal was in place.
    pub seeded_at_height: BlockHeight,
    /// How many registrations were written.
    pub key_count: u64,
    /// blake3, in hex, over the seeded set in address order.
    ///
    /// The value two validators compare. Equal digests mean equal registries;
    /// different digests mean they will disagree about the first `SendMessage`
    /// whose sender is in one set and not the other.
    pub digest: String,
}

fn encode_registry_seed(seed: &RegistrySeed) -> Result<Vec<u8>> {
    serde_json::to_vec(seed).map_err(|e| StorageError::Serialization(e.to_string()))
}

/// What an operator seed did to this database, or `None` if none was applied.
///
/// A malformed row is an ERROR rather than a `None`. `None` is a positive claim
/// — "this node's registry came from its own execution" — and a node that cannot
/// read the row is in no position to make it.
pub fn registry_seed(db: &Database) -> Result<Option<RegistrySeed>> {
    match db.get(cf::META, REGISTRY_SEED_META_KEY)? {
        None => Ok(None),
        Some(bytes) => serde_json::from_slice(&bytes).map(Some).map_err(|e| {
            StorageError::InvalidData(format!(
                "the messaging registry-seed row is unreadable ({e}). This node cannot \
                 establish whether its SRC-201 registry came from its own execution and \
                 must not claim that it did"
            ))
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn temp_db() -> (Database, TempDir) {
        let dir = TempDir::new().unwrap();
        let db = Database::open_default(dir.path()).unwrap();
        (db, dir)
    }

    #[test]
    fn test_daily_quota() {
        let (db, _dir) = temp_db();
        let store = MessagingStore::new(&db);

        // Default
        assert_eq!(store.get_daily_quota().unwrap(), DEFAULT_DAILY_QUOTA);

        // Set and get
        store.set_daily_quota(200).unwrap();
        assert_eq!(store.get_daily_quota().unwrap(), 200);
    }

    #[test]
    fn test_sender_nonce() {
        let (db, _dir) = temp_db();
        let store = MessagingStore::new(&db);

        let sender = Address::from_hex("0x0000000000000000000000000000000000000001").unwrap();

        assert_eq!(store.get_sender_nonce(&sender).unwrap(), 0);

        store.set_sender_nonce(&sender, 5).unwrap();
        assert_eq!(store.get_sender_nonce(&sender).unwrap(), 5);

        let new_nonce = store.increment_sender_nonce(&sender).unwrap();
        assert_eq!(new_nonce, 6);
    }

    #[test]
    fn test_daily_message_count() {
        let (db, _dir) = temp_db();
        let store = MessagingStore::new(&db);

        let sender = Address::from_hex("0x0000000000000000000000000000000000000001").unwrap();
        let day = 19724u32; // Some day

        assert_eq!(store.get_daily_message_count(&sender, day).unwrap(), 0);

        store.increment_daily_message_count(&sender, day).unwrap();
        assert_eq!(store.get_daily_message_count(&sender, day).unwrap(), 1);

        store.increment_daily_message_count(&sender, day).unwrap();
        assert_eq!(store.get_daily_message_count(&sender, day).unwrap(), 2);

        // Different day should be separate
        assert_eq!(store.get_daily_message_count(&sender, day + 1).unwrap(), 0);
    }

    #[test]
    fn test_stake_balance() {
        let (db, _dir) = temp_db();
        let store = MessagingStore::new(&db);

        let addr = Address::from_hex("0x0000000000000000000000000000000000000001").unwrap();

        assert_eq!(store.get_stake_balance(&addr).unwrap(), 0);

        store.add_stake(&addr, 1000).unwrap();
        assert_eq!(store.get_stake_balance(&addr).unwrap(), 1000);

        store.add_stake(&addr, 500).unwrap();
        assert_eq!(store.get_stake_balance(&addr).unwrap(), 1500);
    }

    #[test]
    fn test_inbox_filter() {
        let (db, _dir) = temp_db();
        let store = MessagingStore::new(&db);

        let recipient_hash = [1u8; 32];

        assert_eq!(store.get_inbox_filter(&recipient_hash).unwrap(), InboxFilter::AcceptAll);

        store.set_inbox_filter(&recipient_hash, InboxFilter::ContactsOnly).unwrap();
        assert_eq!(store.get_inbox_filter(&recipient_hash).unwrap(), InboxFilter::ContactsOnly);
    }

    #[test]
    fn test_contacts() {
        let (db, _dir) = temp_db();
        let store = MessagingStore::new(&db);

        let recipient_hash = [1u8; 32];
        let sender_hash = [2u8; 32];

        assert!(!store.is_contact(&recipient_hash, &sender_hash).unwrap());

        store.add_contact(&recipient_hash, &sender_hash).unwrap();
        assert!(store.is_contact(&recipient_hash, &sender_hash).unwrap());

        store.remove_contact(&recipient_hash, &sender_hash).unwrap();
        assert!(!store.is_contact(&recipient_hash, &sender_hash).unwrap());
    }

    #[test]
    fn test_blocked_senders() {
        let (db, _dir) = temp_db();
        let store = MessagingStore::new(&db);

        let recipient_hash = [1u8; 32];
        let sender = Address::from_hex("0x0000000000000000000000000000000000000001").unwrap();

        assert!(!store.is_blocked(&recipient_hash, &sender).unwrap());

        store.block_sender(&recipient_hash, &sender).unwrap();
        assert!(store.is_blocked(&recipient_hash, &sender).unwrap());

        store.unblock_sender(&recipient_hash, &sender).unwrap();
        assert!(!store.is_blocked(&recipient_hash, &sender).unwrap());
    }

    #[test]
    fn test_pending_payment() {
        let (db, _dir) = temp_db();
        let store = MessagingStore::new(&db);

        let message_id = Hash::hash(b"test message");
        let payment = PendingPayment {
            recipient_hash: [1u8; 32],
            amount: 1000,
            expiry: 12345678,
            sender: Address::from_hex("0x0000000000000000000000000000000000000001").unwrap(),
        };

        assert!(store.get_pending_payment(&message_id).unwrap().is_none());

        store.set_pending_payment(&message_id, &payment).unwrap();
        let retrieved = store.get_pending_payment(&message_id).unwrap().unwrap();
        assert_eq!(retrieved.amount, 1000);

        store.delete_pending_payment(&message_id).unwrap();
        assert!(store.get_pending_payment(&message_id).unwrap().is_none());
    }
}
