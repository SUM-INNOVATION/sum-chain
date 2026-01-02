//! Bridge types for cross-chain operations.

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sumchain_primitives::Address as SumAddress;

/// Validator signature with public key
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatorSignature {
    /// Validator public key (32 bytes)
    pub pubkey: [u8; 32],
    /// Ed25519 signature (64 bytes)
    pub signature: [u8; 64],
}

impl Serialize for ValidatorSignature {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // Serialize as a tuple of hex strings for JSON compatibility
        let pubkey_hex = hex::encode(self.pubkey);
        let sig_hex = hex::encode(self.signature);
        (pubkey_hex, sig_hex).serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for ValidatorSignature {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let (pubkey_hex, sig_hex): (String, String) = Deserialize::deserialize(deserializer)?;

        let pubkey_bytes = hex::decode(&pubkey_hex)
            .map_err(|_| serde::de::Error::custom("Invalid pubkey hex"))?;
        let sig_bytes = hex::decode(&sig_hex)
            .map_err(|_| serde::de::Error::custom("Invalid signature hex"))?;

        if pubkey_bytes.len() != 32 {
            return Err(serde::de::Error::custom("Invalid pubkey length"));
        }
        if sig_bytes.len() != 64 {
            return Err(serde::de::Error::custom("Invalid signature length"));
        }

        let mut pubkey = [0u8; 32];
        let mut signature = [0u8; 64];
        pubkey.copy_from_slice(&pubkey_bytes);
        signature.copy_from_slice(&sig_bytes);

        Ok(ValidatorSignature { pubkey, signature })
    }
}

/// Ethereum address (20 bytes)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EthAddress([u8; 20]);

impl EthAddress {
    /// Zero address
    pub const ZERO: EthAddress = EthAddress([0u8; 20]);

    /// Create from bytes
    pub fn from_bytes(bytes: [u8; 20]) -> Self {
        EthAddress(bytes)
    }

    /// Create from slice
    pub fn from_slice(slice: &[u8]) -> Option<Self> {
        if slice.len() != 20 {
            return None;
        }
        let mut bytes = [0u8; 20];
        bytes.copy_from_slice(slice);
        Some(EthAddress(bytes))
    }

    /// Parse from hex string
    pub fn from_hex(s: &str) -> Option<Self> {
        let s = s.strip_prefix("0x").unwrap_or(s);
        let bytes = hex::decode(s).ok()?;
        Self::from_slice(&bytes)
    }

    /// Get as bytes
    pub fn as_bytes(&self) -> &[u8; 20] {
        &self.0
    }

    /// Convert to hex string
    pub fn to_hex(&self) -> String {
        format!("0x{}", hex::encode(self.0))
    }
}

impl std::fmt::Display for EthAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

impl From<ethers::types::Address> for EthAddress {
    fn from(addr: ethers::types::Address) -> Self {
        EthAddress(addr.0)
    }
}

impl From<EthAddress> for ethers::types::Address {
    fn from(addr: EthAddress) -> Self {
        ethers::types::Address::from(addr.0)
    }
}

/// Wrapped token info
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WrappedToken {
    /// Original Ethereum token address (0x0 for ETH)
    pub eth_address: EthAddress,
    /// SUM Chain token ID (SRC-20)
    pub sum_token_id: [u8; 32],
    /// Token name
    pub name: String,
    /// Token symbol
    pub symbol: String,
    /// Decimals (on Ethereum side)
    pub eth_decimals: u8,
    /// Decimals (on SUM side, usually same)
    pub sum_decimals: u8,
    /// Whether deposits are enabled
    pub deposits_enabled: bool,
    /// Whether withdrawals are enabled
    pub withdrawals_enabled: bool,
    /// Minimum deposit amount
    pub min_deposit: u128,
    /// Maximum deposit amount (0 = no limit)
    pub max_deposit: u128,
}

impl WrappedToken {
    /// Create wrapped ETH token
    pub fn eth() -> Self {
        Self {
            eth_address: EthAddress::ZERO,
            sum_token_id: *blake3::hash(b"wrapped_eth").as_bytes(),
            name: "Wrapped Ether".to_string(),
            symbol: "sETH".to_string(),
            eth_decimals: 18,
            sum_decimals: 9, // Match Koppa decimals
            deposits_enabled: true,
            withdrawals_enabled: true,
            min_deposit: 1_000_000_000_000_000, // 0.001 ETH
            max_deposit: 0,
        }
    }
}

/// Deposit event from Ethereum
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DepositEvent {
    /// Unique deposit ID (Ethereum tx hash + log index)
    pub deposit_id: [u8; 32],
    /// Ethereum transaction hash
    pub eth_tx_hash: [u8; 32],
    /// Block number on Ethereum
    pub eth_block: u64,
    /// Log index in the block
    pub log_index: u64,
    /// Depositor address on Ethereum
    pub eth_sender: EthAddress,
    /// Recipient address on SUM Chain
    pub sum_recipient: SumAddress,
    /// Token being deposited
    pub token: EthAddress,
    /// Amount deposited (in token's decimals)
    pub amount: u128,
    /// Timestamp of deposit
    pub timestamp: u64,
}

impl DepositEvent {
    /// Compute deposit ID from tx hash and log index
    pub fn compute_id(tx_hash: &[u8; 32], log_index: u64) -> [u8; 32] {
        let mut data = Vec::with_capacity(40);
        data.extend_from_slice(tx_hash);
        data.extend_from_slice(&log_index.to_be_bytes());
        *blake3::hash(&data).as_bytes()
    }
}

/// Withdrawal request from SUM Chain
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WithdrawalRequest {
    /// Unique withdrawal ID (SUM tx hash)
    pub withdrawal_id: [u8; 32],
    /// SUM Chain transaction hash
    pub sum_tx_hash: [u8; 32],
    /// Block height on SUM Chain
    pub sum_block: u64,
    /// Sender on SUM Chain (who burned the wrapped tokens)
    pub sum_sender: SumAddress,
    /// Recipient on Ethereum
    pub eth_recipient: EthAddress,
    /// Token to release (Ethereum address)
    pub token: EthAddress,
    /// Amount to release
    pub amount: u128,
    /// Timestamp of withdrawal request
    pub timestamp: u64,
    /// Status of the withdrawal
    pub status: WithdrawalStatus,
}

/// Withdrawal status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum WithdrawalStatus {
    /// Waiting for validator signatures
    Pending,
    /// Has enough signatures, ready to execute
    Ready,
    /// Executed on Ethereum
    Completed,
    /// Failed (will need retry)
    Failed,
    /// Expired (timed out)
    Expired,
}

/// Validator attestation for a deposit/withdrawal
#[derive(Debug, Clone)]
pub struct ValidatorAttestation {
    /// The operation being attested (deposit or withdrawal ID)
    pub operation_id: [u8; 32],
    /// Validator's public key
    pub validator_pubkey: [u8; 32],
    /// Ed25519 signature over the operation data
    pub signature: [u8; 64],
    /// Timestamp of attestation
    pub timestamp: u64,
}

impl Serialize for ValidatorAttestation {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("ValidatorAttestation", 4)?;
        state.serialize_field("operation_id", &hex::encode(self.operation_id))?;
        state.serialize_field("validator_pubkey", &hex::encode(self.validator_pubkey))?;
        state.serialize_field("signature", &hex::encode(self.signature))?;
        state.serialize_field("timestamp", &self.timestamp)?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for ValidatorAttestation {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Helper {
            operation_id: String,
            validator_pubkey: String,
            signature: String,
            timestamp: u64,
        }

        let helper = Helper::deserialize(deserializer)?;

        let op_bytes = hex::decode(&helper.operation_id)
            .map_err(|_| serde::de::Error::custom("Invalid operation_id hex"))?;
        let pk_bytes = hex::decode(&helper.validator_pubkey)
            .map_err(|_| serde::de::Error::custom("Invalid validator_pubkey hex"))?;
        let sig_bytes = hex::decode(&helper.signature)
            .map_err(|_| serde::de::Error::custom("Invalid signature hex"))?;

        if op_bytes.len() != 32 || pk_bytes.len() != 32 || sig_bytes.len() != 64 {
            return Err(serde::de::Error::custom("Invalid field length"));
        }

        let mut operation_id = [0u8; 32];
        let mut validator_pubkey = [0u8; 32];
        let mut signature = [0u8; 64];
        operation_id.copy_from_slice(&op_bytes);
        validator_pubkey.copy_from_slice(&pk_bytes);
        signature.copy_from_slice(&sig_bytes);

        Ok(ValidatorAttestation {
            operation_id,
            validator_pubkey,
            signature,
            timestamp: helper.timestamp,
        })
    }
}

/// Bridge state
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct BridgeState {
    /// Total ETH locked
    pub total_eth_locked: u128,
    /// Total sETH minted
    pub total_seth_minted: u128,
    /// Pending deposits awaiting finalization
    pub pending_deposits: u64,
    /// Pending withdrawals awaiting execution
    pub pending_withdrawals: u64,
    /// Total successful deposits
    pub completed_deposits: u64,
    /// Total successful withdrawals
    pub completed_withdrawals: u64,
    /// Whether bridge is paused
    pub paused: bool,
}

/// Bridge operation for native handling
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum BridgeOperation {
    /// Mint wrapped tokens (from Ethereum deposit)
    MintWrapped {
        /// Deposit ID
        deposit_id: [u8; 32],
        /// Recipient on SUM Chain
        recipient: SumAddress,
        /// Wrapped token ID
        token_id: [u8; 32],
        /// Amount to mint
        amount: u128,
        /// Validator signatures
        signatures: Vec<ValidatorSignature>,
    },
    /// Burn wrapped tokens (for Ethereum withdrawal)
    BurnForWithdraw {
        /// Wrapped token ID
        token_id: [u8; 32],
        /// Amount to burn
        amount: u128,
        /// Recipient Ethereum address
        eth_recipient: EthAddress,
    },
    /// Register a new wrapped token
    RegisterToken {
        /// Ethereum token address
        eth_address: EthAddress,
        /// Token name
        name: String,
        /// Token symbol
        symbol: String,
        /// Decimals
        decimals: u8,
    },
    /// Pause bridge operations
    Pause,
    /// Resume bridge operations
    Resume,
}
