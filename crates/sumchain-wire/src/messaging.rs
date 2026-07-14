//! SRC-201: On-Chain Messaging Token Standard
//!
//! Defines types for encrypted on-chain messaging with registry-as-recipient
//! pattern for metadata privacy. Messages are stored in transaction calldata.

use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;

use crate::{Address, Balance, Hash};

/// SRC-201 magic bytes: "S201" in ASCII
pub const SRC201_MAGIC: [u8; 4] = [0x53, 0x32, 0x30, 0x31];

/// Current SRC-201 protocol version
pub const SRC201_VERSION: u8 = 1;

/// Fixed header size in bytes
pub const SRC201_HEADER_SIZE: usize = 72;

/// Nonce size for XChaCha20-Poly1305
pub const SRC201_NONCE_SIZE: usize = 24;

/// Auth tag size for Poly1305
pub const SRC201_TAG_SIZE: usize = 16;

/// KDF context for message key derivation
pub const SRC201_KDF_CONTEXT: &str = "SRC-201-v1.1-message-key";

/// KDF context for attachment key derivation
pub const SRC201_ATTACHMENT_KDF_CONTEXT: &str = "SRC-201-v1.1-attachment-key";

/// Default daily message quota per address
pub const DEFAULT_DAILY_QUOTA: u32 = 100;

/// Default maximum message size in bytes
pub const DEFAULT_MAX_MESSAGE_SIZE: u32 = 65535;

/// Default minimum stake for trusted sender tier (100 Koppa in base units)
pub const DEFAULT_MIN_TRUST_STAKE: u128 = 100_000_000_000;

/// Spam score threshold for restrictions
pub const DEFAULT_SPAM_THRESHOLD: u32 = 50;

/// High spam score threshold requiring stake
pub const DEFAULT_HIGH_SPAM_THRESHOLD: u32 = 80;

/// Messaging operation codes
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum MessagingOperation {
    /// Send message with gas sponsorship (meta-transaction)
    SendMessage = 0,
    /// Send message directly (user pays gas)
    SendMessageDirect = 1,
    /// Send message with attached Koppa payment
    SendMessageWithPayment = 2,
    /// Claim payment from a message (called by recipient)
    ClaimPayment = 3,
    /// Stake Koppa for trusted sender tier
    StakeForTrust = 4,
    /// Withdraw stake (with cooldown)
    Unstake = 5,
    /// Set inbox filter mode
    SetInboxFilter = 6,
    /// Add address to contacts whitelist
    AddContact = 7,
    /// Remove address from contacts
    RemoveContact = 8,
    /// Block a sender
    BlockSender = 9,
    /// Report a message as spam
    ReportSpam = 10,
    /// Register Ed25519 public key for messaging
    RegisterPublicKey = 11,
    /// Update registered public key
    UpdatePublicKey = 12,

    // Admin operations (governance controlled, 128+)
    /// Set daily free message quota
    SetDailyQuota = 128,
    /// Set maximum message size
    SetMaxMessageSize = 129,
    /// Set minimum stake for trusted tier
    SetMinTrustStake = 130,
    /// Enable/disable gas sponsorship
    SetSponsorshipEnabled = 131,
    /// Fund the registry with Koppa
    FundRegistry = 132,
}

impl MessagingOperation {
    /// Convert from byte
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            0 => Some(MessagingOperation::SendMessage),
            1 => Some(MessagingOperation::SendMessageDirect),
            2 => Some(MessagingOperation::SendMessageWithPayment),
            3 => Some(MessagingOperation::ClaimPayment),
            4 => Some(MessagingOperation::StakeForTrust),
            5 => Some(MessagingOperation::Unstake),
            6 => Some(MessagingOperation::SetInboxFilter),
            7 => Some(MessagingOperation::AddContact),
            8 => Some(MessagingOperation::RemoveContact),
            9 => Some(MessagingOperation::BlockSender),
            10 => Some(MessagingOperation::ReportSpam),
            11 => Some(MessagingOperation::RegisterPublicKey),
            12 => Some(MessagingOperation::UpdatePublicKey),
            128 => Some(MessagingOperation::SetDailyQuota),
            129 => Some(MessagingOperation::SetMaxMessageSize),
            130 => Some(MessagingOperation::SetMinTrustStake),
            131 => Some(MessagingOperation::SetSponsorshipEnabled),
            132 => Some(MessagingOperation::FundRegistry),
            _ => None,
        }
    }

    /// Check if this is an admin operation
    pub fn is_admin(&self) -> bool {
        (*self as u8) >= 128
    }

    /// Check if this operation sends a message
    pub fn is_send(&self) -> bool {
        matches!(
            self,
            MessagingOperation::SendMessage
                | MessagingOperation::SendMessageDirect
                | MessagingOperation::SendMessageWithPayment
        )
    }
}

/// Messaging transaction data
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MessagingTxData {
    /// Operation code
    pub operation: MessagingOperation,
    /// Operation-specific data (serialized)
    pub data: Vec<u8>,
}

/// Message flags byte
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct MessageFlags(pub u8);

impl MessageFlags {
    pub const ENCRYPTED: u8 = 1 << 0;
    pub const HAS_REPLY_TO: u8 = 1 << 1;
    pub const HAS_TIMESTAMP: u8 = 1 << 2;
    pub const HAS_ATTACHMENTS: u8 = 1 << 3;
    pub const IS_READ_RECEIPT: u8 = 1 << 4;
    pub const IS_PAYMENT_REQUEST: u8 = 1 << 5;
    pub const REQUIRES_STAKE: u8 = 1 << 6;

    pub fn new() -> Self {
        Self(0)
    }

    pub fn encrypted() -> Self {
        Self(Self::ENCRYPTED)
    }

    pub fn is_encrypted(&self) -> bool {
        self.0 & Self::ENCRYPTED != 0
    }

    pub fn has_reply_to(&self) -> bool {
        self.0 & Self::HAS_REPLY_TO != 0
    }

    pub fn has_timestamp(&self) -> bool {
        self.0 & Self::HAS_TIMESTAMP != 0
    }

    pub fn has_attachments(&self) -> bool {
        self.0 & Self::HAS_ATTACHMENTS != 0
    }

    pub fn is_read_receipt(&self) -> bool {
        self.0 & Self::IS_READ_RECEIPT != 0
    }

    pub fn is_payment_request(&self) -> bool {
        self.0 & Self::IS_PAYMENT_REQUEST != 0
    }

    pub fn requires_stake(&self) -> bool {
        self.0 & Self::REQUIRES_STAKE != 0
    }

    pub fn set(&mut self, flag: u8) {
        self.0 |= flag;
    }

    pub fn clear(&mut self, flag: u8) {
        self.0 &= !flag;
    }
}

/// Content type for message payload
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[repr(u8)]
pub enum ContentType {
    // Text types (0x01-0x0F)
    #[default]
    TextPlain = 0x01,
    TextMarkdown = 0x02,
    TextHtml = 0x03,

    // Application types (0x10-0x2F)
    ApplicationJson = 0x10,
    ApplicationPdf = 0x11,

    // Image types (0x30-0x3F)
    ImagePng = 0x30,
    ImageJpeg = 0x31,
    ImageGif = 0x32,
    ImageWebp = 0x33,

    // SUM-specific types (0x80-0x8F)
    PaymentRequest = 0x80,
    ReadReceipt = 0x81,
    ContactCard = 0x82,

    // Custom type (0xFF)
    Custom = 0xFF,
}

impl ContentType {
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            0x01 => Some(ContentType::TextPlain),
            0x02 => Some(ContentType::TextMarkdown),
            0x03 => Some(ContentType::TextHtml),
            0x10 => Some(ContentType::ApplicationJson),
            0x11 => Some(ContentType::ApplicationPdf),
            0x30 => Some(ContentType::ImagePng),
            0x31 => Some(ContentType::ImageJpeg),
            0x32 => Some(ContentType::ImageGif),
            0x33 => Some(ContentType::ImageWebp),
            0x80 => Some(ContentType::PaymentRequest),
            0x81 => Some(ContentType::ReadReceipt),
            0x82 => Some(ContentType::ContactCard),
            0xFF => Some(ContentType::Custom),
            _ => None,
        }
    }

    pub fn is_text(&self) -> bool {
        (*self as u8) >= 0x01 && (*self as u8) <= 0x0F
    }

    pub fn is_image(&self) -> bool {
        (*self as u8) >= 0x30 && (*self as u8) <= 0x3F
    }
}

/// Inbox filter mode
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[repr(u8)]
pub enum InboxFilter {
    /// Accept all messages
    #[default]
    AcceptAll = 0,
    /// Only accept from contacts
    ContactsOnly = 1,
    /// Only accept from staked senders
    StakedOnly = 2,
}

impl InboxFilter {
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            0 => Some(InboxFilter::AcceptAll),
            1 => Some(InboxFilter::ContactsOnly),
            2 => Some(InboxFilter::StakedOnly),
            _ => None,
        }
    }
}

/// Attachment part type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum AttachmentType {
    /// Inline data (encrypted in message)
    Inline = 0x01,
    /// External reference (IPFS, Arweave, etc.)
    External = 0x02,
}

/// External storage protocol
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum ExternalProtocol {
    IPFS = 0x01,
    Arweave = 0x02,
    HTTPS = 0x03,
}

/// Pending payment information
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingPayment {
    /// Hash of recipient address (for verification)
    pub recipient_hash: [u8; 32],
    /// Payment amount in Koppa
    pub amount: Balance,
    /// Expiry timestamp (Unix)
    pub expiry: u64,
    /// Sender address (for refunds)
    pub sender: Address,
}

/// Message event for indexing (emitted by registry)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MessageEvent {
    /// Sender address (visible on-chain)
    pub sender: Address,
    /// BLAKE3 hash of recipient address
    pub recipient_hash: [u8; 32],
    /// Transaction hash (message ID)
    pub message_id: Hash,
    /// Message size in bytes
    pub size: u32,
    /// Whether message has attached payment
    pub has_payment: bool,
    /// Block height when message was included
    pub block_height: u64,
    /// Block timestamp
    pub timestamp: u64,
}

/// Quota information for a sender
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuotaInfo {
    /// Messages used today
    pub used_today: u32,
    /// Remaining messages today
    pub remaining: u32,
    /// Total daily quota
    pub total_quota: u32,
    /// Sender tier (0=basic, 1=staked)
    pub tier: u8,
    /// Stake amount
    pub stake_amount: Balance,
    /// Unix timestamp when quota resets
    pub resets_at: u64,
}

/// Spam report for a message
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpamReport {
    /// Reporter address
    pub reporter: Address,
    /// Timestamp of report
    pub timestamp: u64,
    /// Message ID being reported
    pub message_id: Hash,
}

// ============================================================================
// Operation-specific data structures
// ============================================================================

/// Data for SendMessage operation
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SendMessageData {
    /// Encoded SRC-201 message (encrypted)
    pub message_data: Vec<u8>,
    /// BLAKE3 hash of recipient address (for indexing)
    pub recipient_hash: [u8; 32],
}

/// Data for SendMessageWithPayment operation
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SendMessageWithPaymentData {
    /// Encoded SRC-201 message (encrypted)
    pub message_data: Vec<u8>,
    /// BLAKE3 hash of recipient address
    pub recipient_hash: [u8; 32],
    /// Koppa amount to attach
    pub koppa_amount: Balance,
}

/// Data for ClaimPayment operation
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClaimPaymentData {
    /// Message ID (tx hash) containing the payment
    pub message_id: Hash,
    /// Recipient's address (proves ownership)
    pub recipient_address: Address,
}

/// Data for StakeForTrust operation
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StakeForTrustData {
    /// Amount to stake
    pub amount: Balance,
}

/// Data for Unstake operation
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnstakeData {
    /// Amount to unstake
    pub amount: Balance,
}

/// Data for SetInboxFilter operation
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SetInboxFilterData {
    /// Filter mode
    pub mode: InboxFilter,
}

/// Data for AddContact/RemoveContact operations
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContactData {
    /// BLAKE3 hash of contact's address
    pub contact_hash: [u8; 32],
}

/// Data for BlockSender operation
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockSenderData {
    /// Address to block
    pub sender: Address,
}

/// Data for ReportSpam operation
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReportSpamData {
    /// Message ID being reported
    pub message_id: Hash,
    /// Address of the spammer
    pub spammer: Address,
}

/// Data for SetDailyQuota admin operation
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SetDailyQuotaData {
    pub quota: u32,
}

/// Data for SetMaxMessageSize admin operation
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SetMaxMessageSizeData {
    pub size: u32,
}

/// Data for SetMinTrustStake admin operation
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SetMinTrustStakeData {
    pub amount: Balance,
}

/// Data for SetSponsorshipEnabled admin operation
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SetSponsorshipEnabledData {
    pub enabled: bool,
}

/// Data for FundRegistry admin operation
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FundRegistryData {
    pub amount: Balance,
}

/// Data for RegisterPublicKey operation
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegisterPublicKeyData {
    /// Ed25519 public key (32 bytes)
    pub public_key: [u8; 32],
}

/// Data for UpdatePublicKey operation
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpdatePublicKeyData {
    /// New Ed25519 public key (32 bytes)
    pub new_public_key: [u8; 32],
}

/// Registered public key entry
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegisteredPublicKey {
    /// The Ed25519 public key
    pub public_key: [u8; 32],
    /// Address that registered this key
    pub address: Address,
    /// Block height when registered
    pub registered_at_block: u64,
    /// Timestamp when registered
    pub registered_at: u64,
    /// Block height when last updated (0 if never updated)
    pub updated_at_block: u64,
}

// ============================================================================
// Sponsored message (meta-transaction)
// ============================================================================

/// Sponsored message for gas-free sending
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SponsoredMessage {
    /// Encoded SRC-201 message
    pub message_data: Vec<u8>,
    /// BLAKE3 hash of recipient address
    pub recipient_hash: [u8; 32],
    /// Sender's signature over the message envelope
    #[serde(with = "BigArray")]
    pub signature: [u8; 64],
    /// Sender's public key
    pub sender_pubkey: [u8; 32],
    /// Sender's message nonce (prevents replay)
    pub nonce: u64,
    /// Expiry timestamp (Unix)
    pub expiry: u64,
    /// Optional Koppa amount to attach
    pub koppa_amount: Option<Balance>,
}

impl SponsoredMessage {
    /// Compute the signing hash for this sponsored message
    pub fn signing_hash(&self, chain_id: u64, registry_address: &Address) -> Hash {
        // Domain separator
        let mut domain_data = Vec::new();
        domain_data.extend_from_slice(b"SRC-201-v1.1");
        domain_data.extend_from_slice(&chain_id.to_be_bytes());
        domain_data.extend_from_slice(registry_address.as_bytes());
        let domain_separator = blake3::hash(&domain_data);

        // Message hash
        let message_hash = blake3::hash(&self.message_data);

        let mut data = Vec::new();
        data.extend_from_slice(domain_separator.as_bytes());
        data.extend_from_slice(&self.sender_pubkey);
        data.extend_from_slice(&self.recipient_hash);
        data.extend_from_slice(message_hash.as_bytes());
        data.extend_from_slice(&self.nonce.to_be_bytes());
        data.extend_from_slice(&self.expiry.to_be_bytes());
        if let Some(amount) = self.koppa_amount {
            data.extend_from_slice(&amount.to_be_bytes());
        }

        Hash::hash(&data)
    }
}

// ============================================================================
// Message header structure (for parsing)
// ============================================================================

/// Parsed SRC-201 message header (72 bytes)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageHeader {
    pub magic: [u8; 4],
    pub version: u8,
    pub flags: MessageFlags,
    pub content_type: ContentType,
    pub attachment_count: u8,
    pub recipient_hash: [u8; 32],
    pub ephemeral_pubkey: [u8; 32],
}

impl MessageHeader {
    /// Parse header from bytes
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < SRC201_HEADER_SIZE {
            return None;
        }

        let mut magic = [0u8; 4];
        magic.copy_from_slice(&data[0..4]);

        if magic != SRC201_MAGIC {
            return None;
        }

        let version = data[4];
        let flags = MessageFlags(data[5]);
        let content_type = ContentType::from_byte(data[6])?;
        let attachment_count = data[7];

        let mut recipient_hash = [0u8; 32];
        recipient_hash.copy_from_slice(&data[8..40]);

        let mut ephemeral_pubkey = [0u8; 32];
        ephemeral_pubkey.copy_from_slice(&data[40..72]);

        Some(Self {
            magic,
            version,
            flags,
            content_type,
            attachment_count,
            recipient_hash,
            ephemeral_pubkey,
        })
    }

    /// Serialize header to bytes (used as AAD in AEAD)
    pub fn to_bytes(&self) -> [u8; SRC201_HEADER_SIZE] {
        let mut bytes = [0u8; SRC201_HEADER_SIZE];
        bytes[0..4].copy_from_slice(&self.magic);
        bytes[4] = self.version;
        bytes[5] = self.flags.0;
        bytes[6] = self.content_type as u8;
        bytes[7] = self.attachment_count;
        bytes[8..40].copy_from_slice(&self.recipient_hash);
        bytes[40..72].copy_from_slice(&self.ephemeral_pubkey);
        bytes
    }
}

/// Validate an SRC-201 message format (basic checks)
pub fn validate_message_format(data: &[u8]) -> Result<MessageHeader, &'static str> {
    if data.len() < SRC201_HEADER_SIZE + SRC201_NONCE_SIZE + 2 + SRC201_TAG_SIZE {
        return Err("Message too short");
    }

    let header = MessageHeader::from_bytes(data).ok_or("Invalid header")?;

    if header.version != SRC201_VERSION {
        return Err("Unsupported version");
    }

    // Check payload length field
    let payload_len =
        u16::from_be_bytes([data[SRC201_HEADER_SIZE + 24], data[SRC201_HEADER_SIZE + 25]]) as usize;

    let expected_min_size = SRC201_HEADER_SIZE + SRC201_NONCE_SIZE + 2 + payload_len + SRC201_TAG_SIZE;
    if data.len() < expected_min_size {
        return Err("Payload length mismatch");
    }

    Ok(header)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_message_flags() {
        let mut flags = MessageFlags::new();
        assert!(!flags.is_encrypted());

        flags.set(MessageFlags::ENCRYPTED);
        assert!(flags.is_encrypted());

        flags.set(MessageFlags::HAS_REPLY_TO);
        assert!(flags.has_reply_to());

        flags.clear(MessageFlags::ENCRYPTED);
        assert!(!flags.is_encrypted());
        assert!(flags.has_reply_to());
    }

    #[test]
    fn test_messaging_operation_from_byte() {
        assert_eq!(
            MessagingOperation::from_byte(0),
            Some(MessagingOperation::SendMessage)
        );
        assert_eq!(
            MessagingOperation::from_byte(128),
            Some(MessagingOperation::SetDailyQuota)
        );
        assert!(MessagingOperation::from_byte(200).is_none());
    }

    #[test]
    fn test_content_type() {
        assert!(ContentType::TextPlain.is_text());
        assert!(ContentType::ImagePng.is_image());
        assert!(!ContentType::ApplicationJson.is_text());
    }

    #[test]
    fn test_message_header_roundtrip() {
        let header = MessageHeader {
            magic: SRC201_MAGIC,
            version: SRC201_VERSION,
            flags: MessageFlags::encrypted(),
            content_type: ContentType::TextPlain,
            attachment_count: 0,
            recipient_hash: [1u8; 32],
            ephemeral_pubkey: [2u8; 32],
        };

        let bytes = header.to_bytes();
        let parsed = MessageHeader::from_bytes(&bytes).unwrap();

        assert_eq!(header, parsed);
    }
}
