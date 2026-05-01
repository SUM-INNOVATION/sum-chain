//! Node Registry types for SUM Chain.
//!
//! Defines the on-chain data structures for the node registry,
//! which tracks network nodes beyond validators (e.g. Archive/Storage nodes).

use serde::{Deserialize, Serialize};

use crate::Address;

/// Role a node can play in the network
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum NodeRole {
    /// Block-producing validator
    Validator = 0,
    /// Full archive/storage node
    ArchiveNode = 1,
}

impl NodeRole {
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            0 => Some(NodeRole::Validator),
            1 => Some(NodeRole::ArchiveNode),
            _ => None,
        }
    }
}

/// Status of a registered node
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum NodeStatus {
    /// Node is active and in good standing
    Active = 0,
    /// Node has been slashed for misbehaviour
    Slashed = 1,
}

impl NodeStatus {
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            0 => Some(NodeStatus::Active),
            1 => Some(NodeStatus::Slashed),
            _ => None,
        }
    }
}

/// On-chain record for a registered node
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeRecord {
    /// Node operator address
    pub address: Address,
    /// Role this node fulfils
    pub role: NodeRole,
    /// Staked balance in native Koppa base units
    pub staked_balance: u64,
    /// Current status
    pub status: NodeStatus,
    /// Block height at which the node was registered
    pub registered_at: u64,
}

/// Operations that can be performed on the node registry
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum NodeRegistryOperation {
    /// Register a new node with a role and initial stake
    Register {
        role: NodeRole,
        stake: u64,
    },
    /// Update a node's status (e.g. slash)
    UpdateStatus {
        target: Address,
        new_status: NodeStatus,
    },
}

/// Transaction data for node registry operations
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeRegistryTxData {
    pub operation: NodeRegistryOperation,
}

// ─── V2 Operations ───────────────────────────────────────────────────────────

/// V2 node registry operations. Additive — V1 `NodeRegistryOperation` is unchanged.
///
/// Currently carries account-level X25519 encryption-key registration for
/// SNIP V2 Ask 3. May grow to cover other V2 account-level keying ops over time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum NodeRegistryOperationV2 {
    /// Register (or rotate) the X25519 encryption pubkey for the signer's address.
    ///
    /// One key per account; subsequent calls overwrite. The pubkey is a 32-byte
    /// Montgomery U-coordinate (RFC 7748). Clamping is on the private scalar,
    /// not the public, so no clamping check applies. **The executor does**
    /// reject the seven libsodium-blocklisted low/small-order encodings (and
    /// their high-bit-set variants), via
    /// `sumchain_crypto::is_low_order_x25519_public_key`, with
    /// `TxStatus::Failed(22)` and reason
    /// `"low-order x25519 public key rejected"` — this prevents griefing where
    /// a registered low-order pubkey would force every legitimate sender's
    /// wrap operation to fail.
    ///
    /// Rotation does not retro-revoke previously-issued bundles encrypted under
    /// the prior X25519 pubkey — the old private key still decrypts old bundles.
    /// Reissuing bundles after rotation is the client's (SNIP's) responsibility.
    RegisterEncryptionKey {
        encryption_pubkey: [u8; 32],
    },
}

/// Transaction data for V2 node registry operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeRegistryV2TxData {
    pub operation: NodeRegistryOperationV2,
}
