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
    Address, Balance, Hash, InboxFilter, MessageEvent, PendingPayment, RegisteredPublicKey,
    DEFAULT_DAILY_QUOTA, DEFAULT_MAX_MESSAGE_SIZE, DEFAULT_MIN_TRUST_STAKE,
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
            Some(bytes) => {
                let quota = u32::from_be_bytes(
                    bytes.try_into().map_err(|_| StorageError::InvalidData("Invalid quota".into()))?
                );
                Ok(quota)
            }
            None => Ok(DEFAULT_DAILY_QUOTA),
        }
    }

    /// Set daily message quota
    pub fn set_daily_quota(&self, quota: u32) -> Result<()> {
        self.db.put(cf::MESSAGING_CONFIG, config_keys::DAILY_QUOTA, &quota.to_be_bytes())
    }

    /// Get maximum message size
    pub fn get_max_message_size(&self) -> Result<u32> {
        match self.db.get(cf::MESSAGING_CONFIG, config_keys::MAX_MESSAGE_SIZE)? {
            Some(bytes) => {
                let size = u32::from_be_bytes(
                    bytes.try_into().map_err(|_| StorageError::InvalidData("Invalid size".into()))?
                );
                Ok(size)
            }
            None => Ok(DEFAULT_MAX_MESSAGE_SIZE),
        }
    }

    /// Set maximum message size
    pub fn set_max_message_size(&self, size: u32) -> Result<()> {
        self.db.put(cf::MESSAGING_CONFIG, config_keys::MAX_MESSAGE_SIZE, &size.to_be_bytes())
    }

    /// Get minimum stake for trusted sender tier
    pub fn get_min_trust_stake(&self) -> Result<Balance> {
        match self.db.get(cf::MESSAGING_CONFIG, config_keys::MIN_TRUST_STAKE)? {
            Some(bytes) => {
                let amount = u128::from_be_bytes(
                    bytes.try_into().map_err(|_| StorageError::InvalidData("Invalid stake".into()))?
                );
                Ok(amount)
            }
            None => Ok(DEFAULT_MIN_TRUST_STAKE),
        }
    }

    /// Set minimum stake for trusted sender tier
    pub fn set_min_trust_stake(&self, amount: Balance) -> Result<()> {
        self.db.put(cf::MESSAGING_CONFIG, config_keys::MIN_TRUST_STAKE, &amount.to_be_bytes())
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
        self.db.put(cf::MESSAGING_CONFIG, config_keys::SPONSORSHIP_ENABLED, &[if enabled { 1 } else { 0 }])
    }

    /// Get sponsorship fund balance
    pub fn get_sponsorship_balance(&self) -> Result<Balance> {
        match self.db.get(cf::MESSAGING_CONFIG, config_keys::SPONSORSHIP_BALANCE)? {
            Some(bytes) => {
                let amount = u128::from_be_bytes(
                    bytes.try_into().map_err(|_| StorageError::InvalidData("Invalid balance".into()))?
                );
                Ok(amount)
            }
            None => Ok(0),
        }
    }

    /// Set sponsorship fund balance
    pub fn set_sponsorship_balance(&self, amount: Balance) -> Result<()> {
        self.db.put(cf::MESSAGING_CONFIG, config_keys::SPONSORSHIP_BALANCE, &amount.to_be_bytes())
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
            Some(bytes) => {
                let addr = Address::from_slice(&bytes)
                    .map_err(|e| StorageError::InvalidData(e.to_string()))?;
                Ok(Some(addr))
            }
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
        match self.db.get(cf::MESSAGING_SENDER_NONCES, sender.as_bytes())? {
            Some(bytes) => {
                let nonce = u64::from_be_bytes(
                    bytes.try_into().map_err(|_| StorageError::InvalidData("Invalid nonce".into()))?
                );
                Ok(nonce)
            }
            None => Ok(0),
        }
    }

    /// Set sender's message nonce
    pub fn set_sender_nonce(&self, sender: &Address, nonce: u64) -> Result<()> {
        self.db.put(cf::MESSAGING_SENDER_NONCES, sender.as_bytes(), &nonce.to_be_bytes())
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
        let mut key = Vec::with_capacity(24);
        key.extend_from_slice(sender.as_bytes());
        key.extend_from_slice(&day.to_be_bytes());

        match self.db.get(cf::MESSAGING_DAILY_COUNTS, &key)? {
            Some(bytes) => {
                let count = u32::from_be_bytes(
                    bytes.try_into().map_err(|_| StorageError::InvalidData("Invalid count".into()))?
                );
                Ok(count)
            }
            None => Ok(0),
        }
    }

    /// Increment daily message count for sender
    pub fn increment_daily_message_count(&self, sender: &Address, day: u32) -> Result<u32> {
        let mut key = Vec::with_capacity(24);
        key.extend_from_slice(sender.as_bytes());
        key.extend_from_slice(&day.to_be_bytes());

        let current = self.get_daily_message_count(sender, day)?;
        let new_count = current + 1;

        self.db.put(cf::MESSAGING_DAILY_COUNTS, &key, &new_count.to_be_bytes())?;
        Ok(new_count)
    }

    // ========================================================================
    // Anti-Spam
    // ========================================================================

    /// Get stake balance for anti-spam
    pub fn get_stake_balance(&self, address: &Address) -> Result<Balance> {
        match self.db.get(cf::MESSAGING_STAKES, address.as_bytes())? {
            Some(bytes) => {
                let amount = u128::from_be_bytes(
                    bytes.try_into().map_err(|_| StorageError::InvalidData("Invalid stake".into()))?
                );
                Ok(amount)
            }
            None => Ok(0),
        }
    }

    /// Set stake balance
    pub fn set_stake_balance(&self, address: &Address, amount: Balance) -> Result<()> {
        if amount == 0 {
            self.db.delete(cf::MESSAGING_STAKES, address.as_bytes())
        } else {
            self.db.put(cf::MESSAGING_STAKES, address.as_bytes(), &amount.to_be_bytes())
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
        match self.db.get(cf::MESSAGING_SPAM_SCORES, address.as_bytes())? {
            Some(bytes) => {
                let score = u32::from_be_bytes(
                    bytes.try_into().map_err(|_| StorageError::InvalidData("Invalid score".into()))?
                );
                Ok(score)
            }
            None => Ok(0),
        }
    }

    /// Set spam score for an address
    pub fn set_spam_score(&self, address: &Address, score: u32) -> Result<()> {
        if score == 0 {
            self.db.delete(cf::MESSAGING_SPAM_SCORES, address.as_bytes())
        } else {
            self.db.put(cf::MESSAGING_SPAM_SCORES, address.as_bytes(), &score.to_be_bytes())
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
        match self.db.get(cf::MESSAGING_INBOX_FILTERS, recipient_hash)? {
            Some(bytes) => {
                let mode = InboxFilter::from_byte(bytes.first().copied().unwrap_or(0))
                    .unwrap_or(InboxFilter::AcceptAll);
                Ok(mode)
            }
            None => Ok(InboxFilter::AcceptAll),
        }
    }

    /// Set inbox filter mode
    pub fn set_inbox_filter(&self, recipient_hash: &[u8; 32], mode: InboxFilter) -> Result<()> {
        self.db.put(cf::MESSAGING_INBOX_FILTERS, recipient_hash, &[mode as u8])
    }

    /// Check if sender is in recipient's contacts
    pub fn is_contact(&self, recipient_hash: &[u8; 32], sender_hash: &[u8; 32]) -> Result<bool> {
        let mut key = Vec::with_capacity(64);
        key.extend_from_slice(recipient_hash);
        key.extend_from_slice(sender_hash);
        self.db.contains(cf::MESSAGING_CONTACTS, &key)
    }

    /// Add sender to recipient's contacts
    pub fn add_contact(&self, recipient_hash: &[u8; 32], sender_hash: &[u8; 32]) -> Result<()> {
        let mut key = Vec::with_capacity(64);
        key.extend_from_slice(recipient_hash);
        key.extend_from_slice(sender_hash);
        self.db.put(cf::MESSAGING_CONTACTS, &key, &[1])
    }

    /// Remove sender from recipient's contacts
    pub fn remove_contact(&self, recipient_hash: &[u8; 32], sender_hash: &[u8; 32]) -> Result<()> {
        let mut key = Vec::with_capacity(64);
        key.extend_from_slice(recipient_hash);
        key.extend_from_slice(sender_hash);
        self.db.delete(cf::MESSAGING_CONTACTS, &key)
    }

    /// Check if sender is blocked by recipient
    pub fn is_blocked(&self, recipient_hash: &[u8; 32], sender: &Address) -> Result<bool> {
        let mut key = Vec::with_capacity(52);
        key.extend_from_slice(recipient_hash);
        key.extend_from_slice(sender.as_bytes());
        self.db.contains(cf::MESSAGING_BLOCKED, &key)
    }

    /// Block a sender
    pub fn block_sender(&self, recipient_hash: &[u8; 32], sender: &Address) -> Result<()> {
        let mut key = Vec::with_capacity(52);
        key.extend_from_slice(recipient_hash);
        key.extend_from_slice(sender.as_bytes());
        self.db.put(cf::MESSAGING_BLOCKED, &key, &[1])
    }

    /// Unblock a sender
    pub fn unblock_sender(&self, recipient_hash: &[u8; 32], sender: &Address) -> Result<()> {
        let mut key = Vec::with_capacity(52);
        key.extend_from_slice(recipient_hash);
        key.extend_from_slice(sender.as_bytes());
        self.db.delete(cf::MESSAGING_BLOCKED, &key)
    }

    // ========================================================================
    // Payment Escrow
    // ========================================================================

    /// Get pending payment by message ID
    pub fn get_pending_payment(&self, message_id: &Hash) -> Result<Option<PendingPayment>> {
        match self.db.get(cf::MESSAGING_PENDING_PAYMENTS, message_id.as_bytes())? {
            Some(bytes) => {
                let payment: PendingPayment = bincode::deserialize(&bytes)
                    .map_err(|e| StorageError::Serialization(e.to_string()))?;
                Ok(Some(payment))
            }
            None => Ok(None),
        }
    }

    /// Store pending payment
    pub fn set_pending_payment(&self, message_id: &Hash, payment: &PendingPayment) -> Result<()> {
        let bytes = bincode::serialize(payment)
            .map_err(|e| StorageError::Serialization(e.to_string()))?;
        self.db.put(cf::MESSAGING_PENDING_PAYMENTS, message_id.as_bytes(), &bytes)
    }

    /// Delete pending payment (after claim or expiry)
    pub fn delete_pending_payment(&self, message_id: &Hash) -> Result<()> {
        self.db.delete(cf::MESSAGING_PENDING_PAYMENTS, message_id.as_bytes())
    }

    // ========================================================================
    // Message Event Indexing
    // ========================================================================

    /// Store a message event for indexing
    /// Key format: recipient_hash (32) + block_height (8) + tx_index (4)
    pub fn store_message_event(&self, event: &MessageEvent, tx_index: u32) -> Result<()> {
        let mut key = Vec::with_capacity(44);
        key.extend_from_slice(&event.recipient_hash);
        key.extend_from_slice(&event.block_height.to_be_bytes());
        key.extend_from_slice(&tx_index.to_be_bytes());

        let bytes = bincode::serialize(event)
            .map_err(|e| StorageError::Serialization(e.to_string()))?;
        self.db.put(cf::MESSAGING_EVENTS, &key, &bytes)
    }

    /// Get messages for a recipient within a block range
    pub fn get_messages_by_recipient(
        &self,
        recipient_hash: &[u8; 32],
        from_block: u64,
        to_block: u64,
        limit: usize,
    ) -> Result<Vec<MessageEvent>> {
        let mut start_key = Vec::with_capacity(44);
        start_key.extend_from_slice(recipient_hash);
        start_key.extend_from_slice(&from_block.to_be_bytes());
        start_key.extend_from_slice(&0u32.to_be_bytes());

        let mut end_key = Vec::with_capacity(44);
        end_key.extend_from_slice(recipient_hash);
        end_key.extend_from_slice(&(to_block + 1).to_be_bytes());
        end_key.extend_from_slice(&0u32.to_be_bytes());

        let mut events = Vec::new();
        for (key, value) in self.db.prefix_iter(cf::MESSAGING_EVENTS, recipient_hash)? {
            // Check if key is within range
            if key.len() < 44 {
                continue;
            }
            if key.as_ref() >= end_key.as_slice() {
                break;
            }
            if key.as_ref() < start_key.as_slice() {
                continue;
            }

            if let Ok(event) = bincode::deserialize::<MessageEvent>(&value) {
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

        let mut start_key = Vec::with_capacity(44);
        start_key.extend_from_slice(recipient_hash);
        start_key.extend_from_slice(&from_block.to_be_bytes());

        let mut end_key = Vec::with_capacity(44);
        end_key.extend_from_slice(recipient_hash);
        end_key.extend_from_slice(&(to_block + 1).to_be_bytes());

        for (key, _) in self.db.prefix_iter(cf::MESSAGING_EVENTS, recipient_hash)? {
            if key.len() < 40 {
                continue;
            }
            if key.as_ref() >= end_key.as_slice() {
                break;
            }
            if key.as_ref() < start_key.as_slice() {
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
            if let Ok(event) = bincode::deserialize::<MessageEvent>(&value) {
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
            if let Ok(event) = bincode::deserialize::<MessageEvent>(&value) {
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
        match self.db.get(cf::MESSAGING_PUBLIC_KEYS, address.as_bytes())? {
            Some(bytes) => {
                let key: RegisteredPublicKey = bincode::deserialize(&bytes)
                    .map_err(|e| StorageError::Serialization(e.to_string()))?;
                Ok(Some(key))
            }
            None => Ok(None),
        }
    }

    /// Register or update public key for an address
    pub fn set_public_key(&self, address: &Address, registered_key: &RegisteredPublicKey) -> Result<()> {
        let bytes = bincode::serialize(registered_key)
            .map_err(|e| StorageError::Serialization(e.to_string()))?;
        self.db.put(cf::MESSAGING_PUBLIC_KEYS, address.as_bytes(), &bytes)
    }

    /// Check if an address has a registered public key
    pub fn has_public_key(&self, address: &Address) -> Result<bool> {
        self.db.contains(cf::MESSAGING_PUBLIC_KEYS, address.as_bytes())
    }

    /// Delete registered public key (for key rotation cleanup if needed)
    pub fn delete_public_key(&self, address: &Address) -> Result<()> {
        self.db.delete(cf::MESSAGING_PUBLIC_KEYS, address.as_bytes())
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
