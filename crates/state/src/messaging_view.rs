//! SRC-201 messaging, as this block's candidate sees it.
//!
//! The committed twins in `sumchain_storage::messaging_store` stay: the RPC
//! server answers about the canonical chain, and the one-time index backfill
//! rewrites committed rows outside any block.
//!
//! ## Why the reads had to move with the writes
//!
//! Three of these are read-modify-write guards, and they were only correct
//! because the writes committed as they went:
//!
//!   * `v_increment_sender_nonce` -- replay protection. A second message from
//!     the same sender in one block must see the first one's nonce.
//!   * `v_increment_daily_message_count` -- the quota. Route the write alone and
//!     the count resets to the parent's value for every transaction in the
//!     block, so a sender gets the whole quota per block instead of per day.
//!   * `v_increment_spam_score` -- the same shape, for reports.
//!
//! A migration that moved the writes and left the reads committed would not
//! have failed a test that only checks where rows land; it would have removed
//! the guards. That is the reason this subsystem is one commit.
//!
//! ## What these reproduce exactly, from the shared halves
//!
//! * The key layout, from the twelve builders in `messaging_store`.
//! * The value encodings: bare big-endian integers at three DIFFERENT widths
//!   (nonce 8, count 4, balance 16), a one-byte bool, a one-byte filter, and
//!   bincode for the three structs.
//! * Absence. `v_set_stake_balance(0)` and `v_set_spam_score(0)` DELETE the row
//!   rather than storing zeroes.
//! * Presence bytes. Contacts and blocks carry `PRESENT`; the recipient-payment
//!   index carries `INDEX_PRESENT`, which is empty.
//! * The two-row writes: a pending payment and its recipient index, a message
//!   event and its sender index.
//!
//! All of it comes from the shared builders rather than being restated here.

use sumchain_primitives::{
    Address, Balance, Hash, InboxFilter, MessageEvent, PendingPayment, RegisteredPublicKey,
    DEFAULT_DAILY_QUOTA, DEFAULT_MAX_MESSAGE_SIZE, DEFAULT_MIN_TRUST_STAKE,
};
use sumchain_storage::cf;
use sumchain_storage::exec_view::ExecutionView;
use sumchain_storage::messaging_store::{
    blocked_key, config_keys, contact_key, daily_count_key, decode_balance, decode_bool,
    decode_inbox_filter, decode_message_event, decode_pending_payment, decode_public_key,
    decode_registry_admin, decode_u32, decode_u64, encode_balance, encode_bool,
    encode_inbox_filter, encode_message_event, encode_pending_payment, encode_public_key,
    encode_u32, encode_u64, event_key, inbox_filter_key, payment_index_key, pending_payment_key,
    public_key_key, sender_index_key, sender_nonce_key, spam_score_key, stake_key, INDEX_PRESENT,
    PRESENT,
};

use crate::messaging_executor::MessagingExecutor;
use crate::{Result, StateError};

impl MessagingExecutor {
    // ── Config ──────────────────────────────────────────────────────────────

    pub fn v_get_daily_quota(view: &ExecutionView<'_, '_>) -> Result<u32> {
        match Self::cfg(view, config_keys::DAILY_QUOTA)? {
            Some(bytes) => decode_u32(&bytes, "quota").map_err(StateError::Storage),
            None => Ok(DEFAULT_DAILY_QUOTA),
        }
    }

    pub fn v_set_daily_quota(view: &mut ExecutionView<'_, '_>, quota: u32) -> Result<()> {
        Self::put_cfg(view, config_keys::DAILY_QUOTA, &encode_u32(quota))
    }

    pub fn v_get_max_message_size(view: &ExecutionView<'_, '_>) -> Result<u32> {
        match Self::cfg(view, config_keys::MAX_MESSAGE_SIZE)? {
            Some(bytes) => decode_u32(&bytes, "size").map_err(StateError::Storage),
            None => Ok(DEFAULT_MAX_MESSAGE_SIZE),
        }
    }

    pub fn v_set_max_message_size(view: &mut ExecutionView<'_, '_>, size: u32) -> Result<()> {
        Self::put_cfg(view, config_keys::MAX_MESSAGE_SIZE, &encode_u32(size))
    }

    pub fn v_get_min_trust_stake(view: &ExecutionView<'_, '_>) -> Result<Balance> {
        match Self::cfg(view, config_keys::MIN_TRUST_STAKE)? {
            Some(bytes) => decode_balance(&bytes, "stake").map_err(StateError::Storage),
            None => Ok(DEFAULT_MIN_TRUST_STAKE),
        }
    }

    pub fn v_set_min_trust_stake(view: &mut ExecutionView<'_, '_>, amount: Balance) -> Result<()> {
        Self::put_cfg(view, config_keys::MIN_TRUST_STAKE, &encode_balance(amount))
    }

    /// Anything non-zero is true, which is what the committed reader did.
    pub fn v_is_sponsorship_enabled(view: &ExecutionView<'_, '_>) -> Result<bool> {
        Ok(Self::cfg(view, config_keys::SPONSORSHIP_ENABLED)?
            .map(|b| decode_bool(&b))
            .unwrap_or(false))
    }

    pub fn v_set_sponsorship_enabled(
        view: &mut ExecutionView<'_, '_>,
        enabled: bool,
    ) -> Result<()> {
        Self::put_cfg(
            view,
            config_keys::SPONSORSHIP_ENABLED,
            &encode_bool(enabled),
        )
    }

    pub fn v_get_sponsorship_balance(view: &ExecutionView<'_, '_>) -> Result<Balance> {
        match Self::cfg(view, config_keys::SPONSORSHIP_BALANCE)? {
            Some(bytes) => decode_balance(&bytes, "balance").map_err(StateError::Storage),
            None => Ok(0),
        }
    }

    /// Read, add, write -- the committed twin's three steps, against the
    /// candidate so two funding transactions in one block accumulate.
    pub fn v_add_sponsorship_balance(
        view: &mut ExecutionView<'_, '_>,
        amount: Balance,
    ) -> Result<Balance> {
        let total = Self::v_get_sponsorship_balance(view)?.saturating_add(amount);
        Self::put_cfg(
            view,
            config_keys::SPONSORSHIP_BALANCE,
            &encode_balance(total),
        )?;
        Ok(total)
    }

    /// A wrong-length value is an ERROR, not "no admin". The committed twin
    /// refuses it, and a candidate that answered `None` instead would turn a
    /// corrupt row into an open admin check.
    pub fn v_get_registry_admin(view: &ExecutionView<'_, '_>) -> Result<Option<Address>> {
        match Self::cfg(view, config_keys::REGISTRY_ADMIN)? {
            Some(bytes) => Ok(Some(
                decode_registry_admin(&bytes).map_err(StateError::Storage)?,
            )),
            None => Ok(None),
        }
    }

    fn cfg(view: &ExecutionView<'_, '_>, key: &[u8]) -> Result<Option<Vec<u8>>> {
        view.get(cf::MESSAGING_CONFIG, key)
            .map_err(StateError::Storage)
    }

    fn put_cfg(view: &mut ExecutionView<'_, '_>, key: &[u8], value: &[u8]) -> Result<()> {
        view.put(cf::MESSAGING_CONFIG, key, value)
            .map_err(StateError::Storage)
    }

    // ── Counters: the read-modify-write guards ──────────────────────────────

    pub fn v_get_sender_nonce(view: &ExecutionView<'_, '_>, sender: &Address) -> Result<u64> {
        match view
            .get(cf::MESSAGING_SENDER_NONCES, sender_nonce_key(sender))
            .map_err(StateError::Storage)?
        {
            Some(bytes) => decode_u64(&bytes, "nonce").map_err(StateError::Storage),
            None => Ok(0),
        }
    }

    /// Replay protection. Reading committed state here would hand the same
    /// nonce to every message a sender puts in one block.
    pub fn v_increment_sender_nonce(
        view: &mut ExecutionView<'_, '_>,
        sender: &Address,
    ) -> Result<u64> {
        let next = Self::v_get_sender_nonce(view, sender)? + 1;
        view.put(
            cf::MESSAGING_SENDER_NONCES,
            sender_nonce_key(sender),
            &encode_u64(next),
        )
        .map_err(StateError::Storage)?;
        Ok(next)
    }

    pub fn v_get_daily_message_count(
        view: &ExecutionView<'_, '_>,
        sender: &Address,
        day: u32,
    ) -> Result<u32> {
        match view
            .get(cf::MESSAGING_DAILY_COUNTS, &daily_count_key(sender, day))
            .map_err(StateError::Storage)?
        {
            Some(bytes) => decode_u32(&bytes, "count").map_err(StateError::Storage),
            None => Ok(0),
        }
    }

    /// The daily quota. Against committed state this would reset once per
    /// block, which is a quota per block rather than per day.
    pub fn v_increment_daily_message_count(
        view: &mut ExecutionView<'_, '_>,
        sender: &Address,
        day: u32,
    ) -> Result<u32> {
        let next = Self::v_get_daily_message_count(view, sender, day)? + 1;
        view.put(
            cf::MESSAGING_DAILY_COUNTS,
            &daily_count_key(sender, day),
            &encode_u32(next),
        )
        .map_err(StateError::Storage)?;
        Ok(next)
    }

    // ── Anti-spam: absence is not zero ──────────────────────────────────────

    pub fn v_get_stake_balance(view: &ExecutionView<'_, '_>, address: &Address) -> Result<Balance> {
        match view
            .get(cf::MESSAGING_STAKES, stake_key(address))
            .map_err(StateError::Storage)?
        {
            Some(bytes) => decode_balance(&bytes, "stake").map_err(StateError::Storage),
            None => Ok(0),
        }
    }

    /// Zero DELETES the row. The committed twin did, and a candidate that
    /// stored sixteen zero bytes would leave a row the chain does not have.
    pub fn v_set_stake_balance(
        view: &mut ExecutionView<'_, '_>,
        address: &Address,
        amount: Balance,
    ) -> Result<()> {
        if amount == 0 {
            view.delete(cf::MESSAGING_STAKES, stake_key(address))
        } else {
            view.put(
                cf::MESSAGING_STAKES,
                stake_key(address),
                &encode_balance(amount),
            )
        }
        .map_err(StateError::Storage)
    }

    pub fn v_add_stake(
        view: &mut ExecutionView<'_, '_>,
        address: &Address,
        amount: Balance,
    ) -> Result<Balance> {
        let total = Self::v_get_stake_balance(view, address)?.saturating_add(amount);
        Self::v_set_stake_balance(view, address, total)?;
        Ok(total)
    }

    pub fn v_get_spam_score(view: &ExecutionView<'_, '_>, address: &Address) -> Result<u32> {
        match view
            .get(cf::MESSAGING_SPAM_SCORES, spam_score_key(address))
            .map_err(StateError::Storage)?
        {
            Some(bytes) => decode_u32(&bytes, "score").map_err(StateError::Storage),
            None => Ok(0),
        }
    }

    /// Zero DELETES the row, as above.
    pub fn v_set_spam_score(
        view: &mut ExecutionView<'_, '_>,
        address: &Address,
        score: u32,
    ) -> Result<()> {
        if score == 0 {
            view.delete(cf::MESSAGING_SPAM_SCORES, spam_score_key(address))
        } else {
            view.put(
                cf::MESSAGING_SPAM_SCORES,
                spam_score_key(address),
                &encode_u32(score),
            )
        }
        .map_err(StateError::Storage)
    }

    pub fn v_increment_spam_score(
        view: &mut ExecutionView<'_, '_>,
        address: &Address,
        delta: u32,
    ) -> Result<u32> {
        let next = Self::v_get_spam_score(view, address)?.saturating_add(delta);
        Self::v_set_spam_score(view, address, next)?;
        Ok(next)
    }

    // ── Recipient controls ──────────────────────────────────────────────────

    pub fn v_get_inbox_filter(
        view: &ExecutionView<'_, '_>,
        recipient_hash: &[u8; 32],
    ) -> Result<InboxFilter> {
        let bytes = view
            .get(
                cf::MESSAGING_INBOX_FILTERS,
                inbox_filter_key(recipient_hash),
            )
            .map_err(StateError::Storage)?;
        Ok(bytes
            .as_deref()
            .map(decode_inbox_filter)
            .unwrap_or(InboxFilter::AcceptAll))
    }

    pub fn v_set_inbox_filter(
        view: &mut ExecutionView<'_, '_>,
        recipient_hash: &[u8; 32],
        mode: InboxFilter,
    ) -> Result<()> {
        view.put(
            cf::MESSAGING_INBOX_FILTERS,
            inbox_filter_key(recipient_hash),
            &encode_inbox_filter(mode),
        )
        .map_err(StateError::Storage)
    }

    pub fn v_is_contact(
        view: &ExecutionView<'_, '_>,
        recipient_hash: &[u8; 32],
        sender_hash: &[u8; 32],
    ) -> Result<bool> {
        view.contains(
            cf::MESSAGING_CONTACTS,
            &contact_key(recipient_hash, sender_hash),
        )
        .map_err(StateError::Storage)
    }

    pub fn v_add_contact(
        view: &mut ExecutionView<'_, '_>,
        recipient_hash: &[u8; 32],
        sender_hash: &[u8; 32],
    ) -> Result<()> {
        view.put(
            cf::MESSAGING_CONTACTS,
            &contact_key(recipient_hash, sender_hash),
            PRESENT,
        )
        .map_err(StateError::Storage)
    }

    pub fn v_remove_contact(
        view: &mut ExecutionView<'_, '_>,
        recipient_hash: &[u8; 32],
        sender_hash: &[u8; 32],
    ) -> Result<()> {
        view.delete(
            cf::MESSAGING_CONTACTS,
            &contact_key(recipient_hash, sender_hash),
        )
        .map_err(StateError::Storage)
    }

    pub fn v_is_blocked(
        view: &ExecutionView<'_, '_>,
        recipient_hash: &[u8; 32],
        sender: &Address,
    ) -> Result<bool> {
        view.contains(cf::MESSAGING_BLOCKED, &blocked_key(recipient_hash, sender))
            .map_err(StateError::Storage)
    }

    pub fn v_block_sender(
        view: &mut ExecutionView<'_, '_>,
        recipient_hash: &[u8; 32],
        sender: &Address,
    ) -> Result<()> {
        view.put(
            cf::MESSAGING_BLOCKED,
            &blocked_key(recipient_hash, sender),
            PRESENT,
        )
        .map_err(StateError::Storage)
    }

    // ── Payment escrow: two rows, together ──────────────────────────────────

    pub fn v_get_pending_payment(
        view: &ExecutionView<'_, '_>,
        message_id: &Hash,
    ) -> Result<Option<PendingPayment>> {
        match view
            .get(
                cf::MESSAGING_PENDING_PAYMENTS,
                pending_payment_key(message_id),
            )
            .map_err(StateError::Storage)?
        {
            Some(bytes) => Ok(Some(
                decode_pending_payment(&bytes).map_err(StateError::Storage)?,
            )),
            None => Ok(None),
        }
    }

    /// The primary row AND the recipient index. The committed twin wrote both
    /// in one batch so they could not diverge; in a candidate the whole block
    /// is the batch, and the index row carries an EMPTY value.
    pub fn v_set_pending_payment(
        view: &mut ExecutionView<'_, '_>,
        message_id: &Hash,
        payment: &PendingPayment,
    ) -> Result<()> {
        let bytes = encode_pending_payment(payment).map_err(StateError::Storage)?;
        view.put(
            cf::MESSAGING_PENDING_PAYMENTS,
            pending_payment_key(message_id),
            &bytes,
        )
        .map_err(StateError::Storage)?;
        view.put(
            cf::MESSAGING_PAYMENTS_BY_RECIPIENT,
            &payment_index_key(&payment.recipient_hash, message_id),
            INDEX_PRESENT,
        )
        .map_err(StateError::Storage)
    }

    /// Both rows again. The index key needs `recipient_hash`, which the message
    /// id cannot reconstruct, so the payment is read first; a missing primary
    /// is a no-op, as it was.
    pub fn v_delete_pending_payment(
        view: &mut ExecutionView<'_, '_>,
        message_id: &Hash,
    ) -> Result<()> {
        if let Some(payment) = Self::v_get_pending_payment(view, message_id)? {
            view.delete(
                cf::MESSAGING_PAYMENTS_BY_RECIPIENT,
                &payment_index_key(&payment.recipient_hash, message_id),
            )
            .map_err(StateError::Storage)?;
        }
        view.delete(
            cf::MESSAGING_PENDING_PAYMENTS,
            pending_payment_key(message_id),
        )
        .map_err(StateError::Storage)
    }

    // ── Message events: two rows, same bytes ────────────────────────────────

    /// The primary event and the sender index, both carrying the whole event.
    pub fn v_store_message_event(
        view: &mut ExecutionView<'_, '_>,
        event: &MessageEvent,
        tx_index: u32,
    ) -> Result<()> {
        let bytes = encode_message_event(event).map_err(StateError::Storage)?;
        view.put(
            cf::MESSAGING_EVENTS,
            &event_key(&event.recipient_hash, event.block_height, tx_index),
            &bytes,
        )
        .map_err(StateError::Storage)?;
        view.put(
            cf::MESSAGING_SENDER_EVENTS,
            &sender_index_key(&event.sender, event.block_height, tx_index),
            &bytes,
        )
        .map_err(StateError::Storage)
    }

    /// Read one back, for tests and for the same-block reads the executor does
    /// not currently need but the index parity proof does.
    pub fn v_get_message_event(
        view: &ExecutionView<'_, '_>,
        recipient_hash: &[u8; 32],
        block_height: u64,
        tx_index: u32,
    ) -> Result<Option<MessageEvent>> {
        match view
            .get(
                cf::MESSAGING_EVENTS,
                &event_key(recipient_hash, block_height, tx_index),
            )
            .map_err(StateError::Storage)?
        {
            Some(bytes) => Ok(Some(
                decode_message_event(&bytes).map_err(StateError::Storage)?,
            )),
            None => Ok(None),
        }
    }

    // ── Public keys ─────────────────────────────────────────────────────────

    pub fn v_get_public_key(
        view: &ExecutionView<'_, '_>,
        address: &Address,
    ) -> Result<Option<RegisteredPublicKey>> {
        match view
            .get(cf::MESSAGING_PUBLIC_KEYS, public_key_key(address))
            .map_err(StateError::Storage)?
        {
            Some(bytes) => Ok(Some(
                decode_public_key(&bytes).map_err(StateError::Storage)?,
            )),
            None => Ok(None),
        }
    }

    pub fn v_has_public_key(view: &ExecutionView<'_, '_>, address: &Address) -> Result<bool> {
        view.contains(cf::MESSAGING_PUBLIC_KEYS, public_key_key(address))
            .map_err(StateError::Storage)
    }

    pub fn v_set_public_key(
        view: &mut ExecutionView<'_, '_>,
        address: &Address,
        registered: &RegisteredPublicKey,
    ) -> Result<()> {
        let bytes = encode_public_key(registered).map_err(StateError::Storage)?;
        view.put(cf::MESSAGING_PUBLIC_KEYS, public_key_key(address), &bytes)
            .map_err(StateError::Storage)
    }
}
