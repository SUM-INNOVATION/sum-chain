//! Transaction types for SUM Chain.
//!
//! Transactions represent state changes on the blockchain:
//! - Native token transfers (Koppa)
//! - NFT operations (SUM-721)
//!
//! Each transaction must be signed by the sender's private key.

use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;

use crate::docclass::DocClassTxData;
use crate::equity::EquityTxData;
use crate::messaging::MessagingTxData;
use crate::staking::StakingTxData;
use crate::tax::TaxTxData;
use crate::{Address, Balance, ChainId, Hash, Nonce};

/// Transaction type identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum TxType {
    /// Native token transfer
    Transfer = 0,
    /// NFT operation (SUM-721)
    Nft = 1,
    /// Token operation (SRC-20)
    Token = 2,
    /// Smart contract deployment
    ContractDeploy = 3,
    /// Smart contract call
    ContractCall = 4,
    /// Staking operation
    Staking = 5,
    /// Messaging operation (SRC-201)
    Messaging = 6,
    /// DocClass operation (SRC-80X/81X)
    DocClass = 7,
    /// Tax & Compliance operation (SRC-82X)
    Tax = 8,
    /// Business, Governance & Equity operation (SRC-83X)
    Equity = 9,
}

impl TxType {
    /// Convert from byte
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            0 => Some(TxType::Transfer),
            1 => Some(TxType::Nft),
            2 => Some(TxType::Token),
            3 => Some(TxType::ContractDeploy),
            4 => Some(TxType::ContractCall),
            5 => Some(TxType::Staking),
            6 => Some(TxType::Messaging),
            7 => Some(TxType::DocClass),
            8 => Some(TxType::Tax),
            9 => Some(TxType::Equity),
            _ => None,
        }
    }
}

/// Unsigned transaction data (legacy transfer format for backwards compatibility)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Transaction {
    /// Chain ID to prevent replay across networks
    pub chain_id: ChainId,
    /// Sender address
    pub from: Address,
    /// Recipient address
    pub to: Address,
    /// Amount to transfer (in smallest unit)
    pub amount: Balance,
    /// Transaction fee paid to validator
    pub fee: Balance,
    /// Sender's nonce (must match account nonce)
    pub nonce: Nonce,
}

/// NFT-specific transaction data
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NftTxData {
    /// Collection ID (32 bytes)
    pub collection_id: [u8; 32],
    /// Token ID (0 for collection-level operations)
    pub token_id: u64,
    /// NFT operation code
    pub operation: NftOperation,
    /// Operation-specific data (serialized)
    pub data: Vec<u8>,
}

/// NFT operation codes
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum NftOperation {
    /// Create a new collection
    CreateCollection = 0,
    /// Mint a new token
    Mint = 1,
    /// Mint a certified document
    MintDocument = 2,
    /// Batch mint tokens
    BatchMint = 3,
    /// Transfer a token
    Transfer = 4,
    /// Approve an address for a token
    Approve = 5,
    /// Set approval for all tokens
    SetApprovalForAll = 6,
    /// Burn a token
    Burn = 7,
    /// Update token metadata
    UpdateMetadata = 8,
    /// Transfer collection ownership
    TransferCollectionOwnership = 9,
    /// Update collection config
    UpdateCollectionConfig = 10,
    /// Lock a token
    LockToken = 11,
    /// Unlock a token
    UnlockToken = 12,
}

/// SRC-20 Token operation codes
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum TokenOperation {
    /// Create a new token
    Create = 0,
    /// Mint new tokens
    Mint = 1,
    /// Burn tokens
    Burn = 2,
    /// Transfer tokens
    Transfer = 3,
    /// Approve spending allowance
    Approve = 4,
    /// Transfer using allowance
    TransferFrom = 5,
    /// Pause token transfers
    Pause = 6,
    /// Unpause token transfers
    Unpause = 7,
    /// Transfer token ownership
    TransferOwnership = 8,
    /// Add a minter
    AddMinter = 9,
    /// Remove a minter
    RemoveMinter = 10,
}

impl TokenOperation {
    /// Convert from byte
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            0 => Some(TokenOperation::Create),
            1 => Some(TokenOperation::Mint),
            2 => Some(TokenOperation::Burn),
            3 => Some(TokenOperation::Transfer),
            4 => Some(TokenOperation::Approve),
            5 => Some(TokenOperation::TransferFrom),
            6 => Some(TokenOperation::Pause),
            7 => Some(TokenOperation::Unpause),
            8 => Some(TokenOperation::TransferOwnership),
            9 => Some(TokenOperation::AddMinter),
            10 => Some(TokenOperation::RemoveMinter),
            _ => None,
        }
    }

    /// Check if this operation requires token ownership
    pub fn requires_ownership(&self) -> bool {
        matches!(
            self,
            TokenOperation::Pause
                | TokenOperation::Unpause
                | TokenOperation::TransferOwnership
                | TokenOperation::AddMinter
                | TokenOperation::RemoveMinter
        )
    }

    /// Check if this operation requires minter role
    pub fn requires_minter(&self) -> bool {
        matches!(self, TokenOperation::Mint)
    }
}

/// SRC-20 Token-specific transaction data
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenTxData {
    /// Token ID (32 bytes) - zero for Create operation
    pub token_id: [u8; 32],
    /// Token operation code
    pub operation: TokenOperation,
    /// Operation-specific data (serialized)
    pub data: Vec<u8>,
}

/// Smart contract deployment data
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContractDeployData {
    /// WASM bytecode
    pub code: Vec<u8>,
    /// Init method name (usually "new" or "init")
    pub init_method: String,
    /// Init method arguments (serialized)
    pub init_args: Vec<u8>,
    /// Initial Koppa to send to contract
    pub value: Balance,
    /// Gas limit for deployment
    pub gas_limit: u64,
}

/// Smart contract call data
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContractCallData {
    /// Contract address to call
    pub contract: Address,
    /// Method name to call
    pub method: String,
    /// Method arguments (serialized)
    pub args: Vec<u8>,
    /// Koppa to send with call
    pub value: Balance,
    /// Gas limit for call
    pub gas_limit: u64,
}

impl NftOperation {
    /// Convert from byte
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            0 => Some(NftOperation::CreateCollection),
            1 => Some(NftOperation::Mint),
            2 => Some(NftOperation::MintDocument),
            3 => Some(NftOperation::BatchMint),
            4 => Some(NftOperation::Transfer),
            5 => Some(NftOperation::Approve),
            6 => Some(NftOperation::SetApprovalForAll),
            7 => Some(NftOperation::Burn),
            8 => Some(NftOperation::UpdateMetadata),
            9 => Some(NftOperation::TransferCollectionOwnership),
            10 => Some(NftOperation::UpdateCollectionConfig),
            11 => Some(NftOperation::LockToken),
            12 => Some(NftOperation::UnlockToken),
            _ => None,
        }
    }

    /// Check if this operation creates a new collection
    pub fn is_collection_creation(&self) -> bool {
        matches!(self, NftOperation::CreateCollection)
    }

    /// Check if this operation requires token ownership
    pub fn requires_token_ownership(&self) -> bool {
        matches!(
            self,
            NftOperation::Transfer
                | NftOperation::Approve
                | NftOperation::Burn
                | NftOperation::UpdateMetadata
                | NftOperation::LockToken
                | NftOperation::UnlockToken
        )
    }

    /// Check if this operation requires collection ownership
    pub fn requires_collection_ownership(&self) -> bool {
        matches!(
            self,
            NftOperation::Mint
                | NftOperation::MintDocument
                | NftOperation::BatchMint
                | NftOperation::TransferCollectionOwnership
                | NftOperation::UpdateCollectionConfig
        )
    }
}

/// Extended transaction with payload type
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransactionV2 {
    /// Chain ID to prevent replay across networks
    pub chain_id: ChainId,
    /// Sender address
    pub from: Address,
    /// Transaction fee paid to validator
    pub fee: Balance,
    /// Sender's nonce (must match account nonce)
    pub nonce: Nonce,
    /// Transaction payload
    pub payload: TxPayload,
}

/// Transaction payload - transfer, NFT, Token, Contract, Staking, or Messaging operation
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TxPayload {
    /// Native token transfer
    Transfer {
        /// Recipient address
        to: Address,
        /// Amount to transfer
        amount: Balance,
    },
    /// NFT operation (SUM-721)
    Nft(NftTxData),
    /// Token operation (SRC-20)
    Token(TokenTxData),
    /// Smart contract deployment
    ContractDeploy(ContractDeployData),
    /// Smart contract call
    ContractCall(ContractCallData),
    /// Staking operation
    Staking(StakingTxData),
    /// Messaging operation (SRC-201)
    Messaging(MessagingTxData),
    /// DocClass operation (SRC-80X/81X)
    DocClass(DocClassTxData),
    /// Tax & Compliance operation (SRC-82X)
    Tax(TaxTxData),
    /// Business, Governance & Equity operation (SRC-83X)
    Equity(EquityTxData),
}

impl TransactionV2 {
    /// Create a new transfer transaction
    pub fn transfer(
        chain_id: ChainId,
        from: Address,
        to: Address,
        amount: Balance,
        fee: Balance,
        nonce: Nonce,
    ) -> Self {
        Self {
            chain_id,
            from,
            fee,
            nonce,
            payload: TxPayload::Transfer { to, amount },
        }
    }

    /// Create a new NFT transaction
    pub fn nft(
        chain_id: ChainId,
        from: Address,
        fee: Balance,
        nonce: Nonce,
        nft_data: NftTxData,
    ) -> Self {
        Self {
            chain_id,
            from,
            fee,
            nonce,
            payload: TxPayload::Nft(nft_data),
        }
    }

    /// Create a new Token (SRC-20) transaction
    pub fn token(
        chain_id: ChainId,
        from: Address,
        fee: Balance,
        nonce: Nonce,
        token_data: TokenTxData,
    ) -> Self {
        Self {
            chain_id,
            from,
            fee,
            nonce,
            payload: TxPayload::Token(token_data),
        }
    }

    /// Create a new contract deployment transaction
    pub fn contract_deploy(
        chain_id: ChainId,
        from: Address,
        fee: Balance,
        nonce: Nonce,
        deploy_data: ContractDeployData,
    ) -> Self {
        Self {
            chain_id,
            from,
            fee,
            nonce,
            payload: TxPayload::ContractDeploy(deploy_data),
        }
    }

    /// Create a new contract call transaction
    pub fn contract_call(
        chain_id: ChainId,
        from: Address,
        fee: Balance,
        nonce: Nonce,
        call_data: ContractCallData,
    ) -> Self {
        Self {
            chain_id,
            from,
            fee,
            nonce,
            payload: TxPayload::ContractCall(call_data),
        }
    }

    /// Create a new staking transaction
    pub fn staking(
        chain_id: ChainId,
        from: Address,
        fee: Balance,
        nonce: Nonce,
        staking_data: StakingTxData,
    ) -> Self {
        Self {
            chain_id,
            from,
            fee,
            nonce,
            payload: TxPayload::Staking(staking_data),
        }
    }

    /// Create a new messaging transaction
    pub fn messaging(
        chain_id: ChainId,
        from: Address,
        fee: Balance,
        nonce: Nonce,
        messaging_data: MessagingTxData,
    ) -> Self {
        Self {
            chain_id,
            from,
            fee,
            nonce,
            payload: TxPayload::Messaging(messaging_data),
        }
    }

    /// Get the transaction type
    pub fn tx_type(&self) -> TxType {
        match &self.payload {
            TxPayload::Transfer { .. } => TxType::Transfer,
            TxPayload::Nft(_) => TxType::Nft,
            TxPayload::Token(_) => TxType::Token,
            TxPayload::ContractDeploy(_) => TxType::ContractDeploy,
            TxPayload::ContractCall(_) => TxType::ContractCall,
            TxPayload::Staking(_) => TxType::Staking,
            TxPayload::Messaging(_) => TxType::Messaging,
            TxPayload::DocClass(_) => TxType::DocClass,
            TxPayload::Tax(_) => TxType::Tax,
            TxPayload::Equity(_) => TxType::Equity,
        }
    }

    /// Compute the signing hash
    pub fn signing_hash(&self) -> Hash {
        let bytes = bincode::serialize(self).expect("TransactionV2 serialization should not fail");
        Hash::hash(&bytes)
    }

    /// Serialize to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        bincode::serialize(self).expect("TransactionV2 serialization should not fail")
    }

    /// Deserialize from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, bincode::Error> {
        bincode::deserialize(bytes)
    }

    /// Get recipient address (for transfers) or contract address (for calls)
    pub fn recipient(&self) -> Option<Address> {
        match &self.payload {
            TxPayload::Transfer { to, .. } => Some(*to),
            TxPayload::ContractCall(data) => Some(data.contract),
            TxPayload::Nft(_) => None,
            TxPayload::Token(_) => None,
            TxPayload::ContractDeploy(_) => None,
            TxPayload::Staking(_) => None,
            TxPayload::Messaging(_) => None, // Recipient is encrypted in message
            TxPayload::DocClass(_) => None,  // No direct recipient
            TxPayload::Tax(_) => None,       // No direct recipient
            TxPayload::Equity(_) => None,    // No direct recipient
        }
    }

    /// Get transfer amount (for transfers) or value (for contract calls)
    pub fn amount(&self) -> Balance {
        match &self.payload {
            TxPayload::Transfer { amount, .. } => *amount,
            TxPayload::ContractDeploy(data) => data.value,
            TxPayload::ContractCall(data) => data.value,
            TxPayload::Nft(_) => 0,
            TxPayload::Token(_) => 0,
            TxPayload::Staking(_) => 0,
            TxPayload::Messaging(_) => 0, // Koppa attachment is inside message data
            TxPayload::DocClass(_) => 0,  // Stake/fee handled separately
            TxPayload::Tax(_) => 0,       // Fee-only operations
            TxPayload::Equity(_) => 0,    // Fee-only operations
        }
    }

    /// Convert to legacy Transaction format (only for transfers)
    pub fn to_legacy(&self) -> Option<Transaction> {
        match &self.payload {
            TxPayload::Transfer { to, amount } => Some(Transaction {
                chain_id: self.chain_id,
                from: self.from,
                to: *to,
                amount: *amount,
                fee: self.fee,
                nonce: self.nonce,
            }),
            _ => None,
        }
    }

    /// Get contract deploy data if this is a deploy transaction
    pub fn deploy_data(&self) -> Option<&ContractDeployData> {
        match &self.payload {
            TxPayload::ContractDeploy(data) => Some(data),
            _ => None,
        }
    }

    /// Get contract call data if this is a call transaction
    pub fn call_data(&self) -> Option<&ContractCallData> {
        match &self.payload {
            TxPayload::ContractCall(data) => Some(data),
            _ => None,
        }
    }

    /// Check if this is a contract transaction
    pub fn is_contract(&self) -> bool {
        matches!(
            self.payload,
            TxPayload::ContractDeploy(_) | TxPayload::ContractCall(_)
        )
    }

    /// Get token data if this is a Token transaction
    pub fn token_data(&self) -> Option<&TokenTxData> {
        match &self.payload {
            TxPayload::Token(data) => Some(data),
            _ => None,
        }
    }

    /// Get staking data if this is a Staking transaction
    pub fn staking_data(&self) -> Option<&StakingTxData> {
        match &self.payload {
            TxPayload::Staking(data) => Some(data),
            _ => None,
        }
    }

    /// Check if this is a staking transaction
    pub fn is_staking(&self) -> bool {
        matches!(self.payload, TxPayload::Staking(_))
    }

    /// Get messaging data if this is a Messaging transaction
    pub fn messaging_data(&self) -> Option<&MessagingTxData> {
        match &self.payload {
            TxPayload::Messaging(data) => Some(data),
            _ => None,
        }
    }

    /// Check if this is a messaging transaction
    pub fn is_messaging(&self) -> bool {
        matches!(self.payload, TxPayload::Messaging(_))
    }

    /// Get docclass data if this is a DocClass transaction
    pub fn docclass_data(&self) -> Option<&DocClassTxData> {
        match &self.payload {
            TxPayload::DocClass(data) => Some(data),
            _ => None,
        }
    }

    /// Check if this is a docclass transaction
    pub fn is_docclass(&self) -> bool {
        matches!(self.payload, TxPayload::DocClass(_))
    }
}

impl Transaction {
    /// Create a new transaction
    pub fn new(
        chain_id: ChainId,
        from: Address,
        to: Address,
        amount: Balance,
        fee: Balance,
        nonce: Nonce,
    ) -> Self {
        Self {
            chain_id,
            from,
            to,
            amount,
            fee,
            nonce,
        }
    }

    /// Compute the signing hash for this transaction
    /// This is what gets signed by the sender
    pub fn signing_hash(&self) -> Hash {
        // Deterministic serialization using bincode
        let bytes = bincode::serialize(self).expect("Transaction serialization should not fail");
        Hash::hash(&bytes)
    }

    /// Serialize transaction to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        bincode::serialize(self).expect("Transaction serialization should not fail")
    }

    /// Deserialize transaction from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, bincode::Error> {
        bincode::deserialize(bytes)
    }

    /// Total cost to sender (amount + fee)
    pub fn total_cost(&self) -> Balance {
        self.amount.saturating_add(self.fee)
    }
}

/// Transaction inner payload - supports both legacy and V2 formats
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TxInner {
    /// Legacy transfer transaction (backwards compatible)
    Legacy(Transaction),
    /// V2 transaction with extended payload support (NFT, etc.)
    V2(TransactionV2),
}

/// Signed transaction (transaction + signature)
/// Supports both legacy transfers and V2 transactions (NFT operations)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedTransaction {
    /// The unsigned transaction (legacy or V2)
    pub inner: TxInner,
    /// Ed25519 signature (64 bytes)
    #[serde(with = "BigArray")]
    pub signature: [u8; 64],
    /// Signer's public key (for verification)
    pub public_key: [u8; 32],
}

impl SignedTransaction {
    /// Create a new signed legacy transaction (backwards compatible)
    pub fn new(tx: Transaction, signature: [u8; 64], public_key: [u8; 32]) -> Self {
        Self {
            inner: TxInner::Legacy(tx),
            signature,
            public_key,
        }
    }

    /// Create a new signed V2 transaction (for NFT and extended operations)
    pub fn new_v2(tx: TransactionV2, signature: [u8; 64], public_key: [u8; 32]) -> Self {
        Self {
            inner: TxInner::V2(tx),
            signature,
            public_key,
        }
    }

    /// Get the transaction type
    pub fn tx_type(&self) -> TxType {
        match &self.inner {
            TxInner::Legacy(_) => TxType::Transfer,
            TxInner::V2(tx) => tx.tx_type(),
        }
    }

    /// Check if this is an NFT transaction
    pub fn is_nft(&self) -> bool {
        self.tx_type() == TxType::Nft
    }

    /// Check if this is a Token (SRC-20) transaction
    pub fn is_token(&self) -> bool {
        self.tx_type() == TxType::Token
    }

    /// Get NFT data if this is an NFT transaction
    pub fn nft_data(&self) -> Option<&NftTxData> {
        match &self.inner {
            TxInner::V2(tx) => match &tx.payload {
                TxPayload::Nft(data) => Some(data),
                _ => None,
            },
            _ => None,
        }
    }

    /// Get Token data if this is a Token transaction
    pub fn token_data(&self) -> Option<&TokenTxData> {
        match &self.inner {
            TxInner::V2(tx) => match &tx.payload {
                TxPayload::Token(data) => Some(data),
                _ => None,
            },
            _ => None,
        }
    }

    /// Get Staking data if this is a Staking transaction
    pub fn staking_data(&self) -> Option<&StakingTxData> {
        match &self.inner {
            TxInner::V2(tx) => match &tx.payload {
                TxPayload::Staking(data) => Some(data),
                _ => None,
            },
            _ => None,
        }
    }

    /// Check if this is a Staking transaction
    pub fn is_staking(&self) -> bool {
        self.tx_type() == TxType::Staking
    }

    /// Get Messaging data if this is a Messaging transaction
    pub fn messaging_data(&self) -> Option<&MessagingTxData> {
        match &self.inner {
            TxInner::V2(tx) => match &tx.payload {
                TxPayload::Messaging(data) => Some(data),
                _ => None,
            },
            _ => None,
        }
    }

    /// Check if this is a Messaging transaction
    pub fn is_messaging(&self) -> bool {
        self.tx_type() == TxType::Messaging
    }

    /// Compute the transaction hash (unique identifier)
    pub fn hash(&self) -> Hash {
        let bytes =
            bincode::serialize(self).expect("SignedTransaction serialization should not fail");
        Hash::hash(&bytes)
    }

    /// Get the transaction signing hash
    pub fn signing_hash(&self) -> Hash {
        match &self.inner {
            TxInner::Legacy(tx) => tx.signing_hash(),
            TxInner::V2(tx) => tx.signing_hash(),
        }
    }

    /// Serialize to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        bincode::serialize(self).expect("SignedTransaction serialization should not fail")
    }

    /// Deserialize from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, bincode::Error> {
        bincode::deserialize(bytes)
    }

    /// Serialize to hex string
    pub fn to_hex(&self) -> String {
        hex::encode(self.to_bytes())
    }

    /// Deserialize from hex string
    pub fn from_hex(s: &str) -> Result<Self, String> {
        let s = s.strip_prefix("0x").unwrap_or(s);
        let bytes = hex::decode(s).map_err(|e| e.to_string())?;
        Self::from_bytes(&bytes).map_err(|e| e.to_string())
    }

    /// Get sender address
    pub fn sender(&self) -> Address {
        match &self.inner {
            TxInner::Legacy(tx) => tx.from,
            TxInner::V2(tx) => tx.from,
        }
    }

    /// Get chain ID
    pub fn chain_id(&self) -> ChainId {
        match &self.inner {
            TxInner::Legacy(tx) => tx.chain_id,
            TxInner::V2(tx) => tx.chain_id,
        }
    }

    /// Get transaction fee
    pub fn fee(&self) -> Balance {
        match &self.inner {
            TxInner::Legacy(tx) => tx.fee,
            TxInner::V2(tx) => tx.fee,
        }
    }

    /// Get transaction nonce
    pub fn nonce(&self) -> Nonce {
        match &self.inner {
            TxInner::Legacy(tx) => tx.nonce,
            TxInner::V2(tx) => tx.nonce,
        }
    }

    /// Get transfer amount (0 for NFT transactions)
    pub fn amount(&self) -> Balance {
        match &self.inner {
            TxInner::Legacy(tx) => tx.amount,
            TxInner::V2(tx) => tx.amount(),
        }
    }

    /// Get recipient address (None for NFT transactions)
    pub fn recipient(&self) -> Option<Address> {
        match &self.inner {
            TxInner::Legacy(tx) => Some(tx.to),
            TxInner::V2(tx) => tx.recipient(),
        }
    }

    /// Get the expected address from the public key
    pub fn signer_address(&self) -> Address {
        Address::from_public_key(&self.public_key)
    }

    /// Verify that the signer matches the from address
    pub fn verify_signer(&self) -> bool {
        self.signer_address() == self.sender()
    }

    /// Get legacy transaction reference (for backwards compatibility)
    /// Returns None if this is a V2 NFT transaction
    pub fn legacy_tx(&self) -> Option<&Transaction> {
        match &self.inner {
            TxInner::Legacy(tx) => Some(tx),
            TxInner::V2(_) => None,
        }
    }

    /// Access the inner transaction data
    /// Use tx_type() to determine which variant is active
    pub fn inner(&self) -> &TxInner {
        &self.inner
    }
}

// Backwards compatibility: provide access to legacy `tx` field
impl SignedTransaction {
    /// Get legacy transaction (DEPRECATED: use sender(), fee(), nonce() etc. or inner() instead)
    /// Panics if this is a V2 NFT transaction
    #[deprecated(note = "Use sender(), fee(), nonce() etc. or inner() instead")]
    pub fn tx(&self) -> &Transaction {
        match &self.inner {
            TxInner::Legacy(tx) => tx,
            TxInner::V2(_) => panic!("Cannot access legacy tx field on V2 transaction"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_tx() -> Transaction {
        Transaction::new(
            1, // chain_id
            Address::from_hex("0x0000000000000000000000000000000000000001").unwrap(),
            Address::from_hex("0x0000000000000000000000000000000000000002").unwrap(),
            1000,
            10,
            0,
        )
    }

    #[test]
    fn test_signing_hash_deterministic() {
        let tx = sample_tx();
        let h1 = tx.signing_hash();
        let h2 = tx.signing_hash();
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_different_nonce_different_hash() {
        let tx1 = sample_tx();
        let mut tx2 = sample_tx();
        tx2.nonce = 1;
        assert_ne!(tx1.signing_hash(), tx2.signing_hash());
    }

    #[test]
    fn test_total_cost() {
        let tx = sample_tx();
        assert_eq!(tx.total_cost(), 1010);
    }

    #[test]
    fn test_serialization_roundtrip() {
        let tx = sample_tx();
        let bytes = tx.to_bytes();
        let tx2 = Transaction::from_bytes(&bytes).unwrap();
        assert_eq!(tx, tx2);
    }

    #[test]
    fn test_signed_tx_hex_roundtrip() {
        let tx = sample_tx();
        let signed = SignedTransaction::new(tx, [0u8; 64], [0u8; 32]);
        let hex = signed.to_hex();
        let signed2 = SignedTransaction::from_hex(&hex).unwrap();
        assert_eq!(signed, signed2);
    }
}
