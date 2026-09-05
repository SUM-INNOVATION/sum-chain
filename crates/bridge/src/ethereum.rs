//! Ethereum interaction - watching events and executing transactions.

use crate::{BridgeConfig, BridgeError, DepositEvent, EthAddress, Result, WithdrawalRequest};
use ethabi::ethereum_types::{H160 as Address, H256 as B256, U256};
use std::sync::Arc;
use tracing::{debug, info, warn};

/// Minimal Ethereum JSON-RPC client for the bridge.
///
/// The bridge makes exactly five read-only calls (`eth_chainId`,
/// `eth_blockNumber`, `eth_getBalance`, `eth_getTransactionReceipt`,
/// `eth_gasPrice`) and signs nothing. A full provider stack is not warranted for
/// that, and the two that exist are both unavailable to us (#206):
///
/// * `ethers 2.0.14` is the terminal release of a deprecated crate and drags
///   `jsonwebtoken -> ring 0.16` (RUSTSEC-2025-0009) plus `reqwest 0.11 ->
///   hyper 0.14 -> h2 0.3` (RUSTSEC-2026-0258) and `rustls 0.21 ->
///   rustls-webpki 0.101` (RUSTSEC-2026-0104/0098/0099) into the graph;
/// * the `alloy` umbrella (2.4.x) requires rustc 1.94.1 while this workspace is
///   pinned at 1.88.
///
/// So the transport is `reqwest 0.12` (hyper 1.x) and the types come from
/// `alloy-primitives` / `alloy-sol-types`, whose 1.x line builds at 1.88. ABI
/// encoding is byte-identical to the removed implementation — see
/// `tests/abi_parity.rs`.
pub struct EthereumClient {
    http: reqwest::Client,
    rpc_url: String,
    /// Configuration (public for watcher access)
    pub config: BridgeConfig,
}

impl EthereumClient {
    /// Create a new Ethereum client (connection verified on first use).
    pub fn new(config: BridgeConfig) -> Result<Self> {
        let http = reqwest::Client::builder()
            .build()
            .map_err(|e| BridgeError::EthereumRpc(e.to_string()))?;
        Ok(Self {
            http,
            rpc_url: config.eth_rpc_url.clone(),
            config,
        })
    }

    /// One JSON-RPC round trip. Errors carry the RPC error message so a
    /// misconfigured endpoint is diagnosable rather than a bare failure.
    async fn call(&self, method: &str, params: serde_json::Value) -> Result<serde_json::Value> {
        let body = serde_json::json!({
            "jsonrpc": "2.0", "id": 1, "method": method, "params": params
        });
        let resp: serde_json::Value = self
            .http
            .post(&self.rpc_url)
            .json(&body)
            .send()
            .await
            .map_err(|e| BridgeError::EthereumRpc(format!("{method}: {e}")))?
            .json()
            .await
            .map_err(|e| BridgeError::EthereumRpc(format!("{method}: malformed response: {e}")))?;

        if let Some(err) = resp.get("error") {
            return Err(BridgeError::EthereumRpc(format!("{method}: {err}")));
        }
        Ok(resp.get("result").cloned().unwrap_or(serde_json::Value::Null))
    }

    /// Parse a `0x`-prefixed quantity. Ethereum JSON-RPC returns every numeric
    /// value this way, and a silent 0 on a malformed value would be a correctness
    /// bug in confirmation counting, so this is strict.
    fn hex_u64(v: &serde_json::Value, ctx: &str) -> Result<u64> {
        let s = v
            .as_str()
            .ok_or_else(|| BridgeError::EthereumRpc(format!("{ctx}: expected a hex string")))?;
        u64::from_str_radix(s.trim_start_matches("0x"), 16)
            .map_err(|e| BridgeError::EthereumRpc(format!("{ctx}: bad quantity {s}: {e}")))
    }

    fn hex_u256(v: &serde_json::Value, ctx: &str) -> Result<U256> {
        let s = v
            .as_str()
            .ok_or_else(|| BridgeError::EthereumRpc(format!("{ctx}: expected a hex string")))?;
        U256::from_str_radix(s.trim_start_matches("0x"), 16)
            .map_err(|e| BridgeError::EthereumRpc(format!("{ctx}: bad quantity {s}: {e}")))
    }

    /// Verify connection and chain ID
    pub async fn verify_connection(&self) -> Result<()> {
        let v = self.call("eth_chainId", serde_json::json!([])).await?;
        let chain_id = Self::hex_u64(&v, "eth_chainId")?;

        if chain_id != self.config.eth_chain_id {
            return Err(BridgeError::Config(format!(
                "Chain ID mismatch: expected {}, got {}",
                self.config.eth_chain_id, chain_id
            )));
        }

        info!("Connected to Ethereum chain {}", chain_id);
        Ok(())
    }

    /// Get current block number
    pub async fn block_number(&self) -> Result<u64> {
        let v = self.call("eth_blockNumber", serde_json::json!([])).await?;
        Self::hex_u64(&v, "eth_blockNumber")
    }

    /// Get ETH balance of an address
    pub async fn balance(&self, address: EthAddress) -> Result<U256> {
        let a: Address = address.into();
        let v = self
            .call(
                "eth_getBalance",
                serde_json::json!([format!("{a:?}"), "latest"]),
            )
            .await?;
        Self::hex_u256(&v, "eth_getBalance")
    }

    /// Check if a transaction is confirmed
    pub async fn is_confirmed(&self, tx_hash: [u8; 32]) -> Result<bool> {
        let h = B256::from(tx_hash);
        let receipt = self
            .call(
                "eth_getTransactionReceipt",
                serde_json::json!([format!("{h:?}")]),
            )
            .await?;

        // A pending or unknown transaction returns null — not confirmed, not an
        // error.
        let Some(block_num) = receipt.get("blockNumber").filter(|v| !v.is_null()) else {
            return Ok(false);
        };
        let block_num = Self::hex_u64(block_num, "receipt.blockNumber")?;
        let current_block = self.block_number().await?;
        let confirmations = current_block.saturating_sub(block_num);
        Ok(confirmations >= self.config.eth_confirmations)
    }

    /// Get gas price with multiplier
    pub async fn gas_price(&self) -> Result<U256> {
        let v = self.call("eth_gasPrice", serde_json::json!([])).await?;
        let base_price: u128 = Self::hex_u256(&v, "eth_gasPrice")?
            .try_into()
            .map_err(|_| BridgeError::EthereumRpc("gas price exceeds u128".into()))?;

        let multiplied = base_price as f64 * self.config.gas_price_multiplier;
        let max_price = (self.config.max_gas_price_gwei as u128) * 1_000_000_000;

        Ok(U256::from((multiplied as u128).min(max_price)))
    }
}

/// Ethereum event watcher
pub struct EthereumWatcher {
    client: Arc<EthereumClient>,
    last_processed_block: u64,
}

impl EthereumWatcher {
    /// Create a new watcher
    pub fn new(client: Arc<EthereumClient>, start_block: u64) -> Self {
        Self {
            client,
            last_processed_block: start_block,
        }
    }

    /// Poll for new deposit events
    pub async fn poll_deposits(&mut self) -> Result<Vec<DepositEvent>> {
        let current_block = self.client.block_number().await?;

        // Only process finalized blocks
        let safe_block = current_block.saturating_sub(self.client.config.eth_confirmations);

        if safe_block <= self.last_processed_block {
            return Ok(Vec::new());
        }

        let from_block = self.last_processed_block + 1;
        let to_block = safe_block.min(from_block + 1000); // Max 1000 blocks per query

        debug!(
            "Scanning Ethereum blocks {} to {} for deposits",
            from_block, to_block
        );

        // In production, this would query the bridge contract's Deposit events
        // For now, return empty - actual implementation would use:
        // let filter = Filter::new()
        //     .address(self.client.config.bridge_contract.into())
        //     .event("Deposit(address,address,address,uint256)")
        //     .from_block(from_block)
        //     .to_block(to_block);
        //
        // let logs = self.client.provider.get_logs(&filter).await?;

        self.last_processed_block = to_block;

        Ok(Vec::new())
    }

    /// Get last processed block
    pub fn last_processed_block(&self) -> u64 {
        self.last_processed_block
    }

    /// Set last processed block (for recovery)
    pub fn set_last_processed_block(&mut self, block: u64) {
        self.last_processed_block = block;
    }
}

/// Bridge contract ABI.
///
/// Migrated from ethers `abigen!` to `ethabi` (#206) with the SAME signatures.
/// `ethers::abi` was itself `ethabi`, so selectors, event topics and calldata are
/// byte-identical by construction — pinned against vectors captured from the
/// ethers implementation before it was removed (`tests/abi_parity.rs`).
pub mod abi {
    use ethabi::{Event, EventParam, Function, Param, ParamType, StateMutability};

    fn p(name: &str, kind: ParamType) -> Param {
        Param { name: name.into(), kind, internal_type: None }
    }
    fn ep(name: &str, kind: ParamType, indexed: bool) -> EventParam {
        EventParam { name: name.into(), kind, indexed }
    }

    /// `deposit(address token, uint256 amount, bytes32 sumRecipient)`
    pub fn deposit() -> Function {
        Function {
            name: "deposit".into(),
            inputs: vec![
                p("token", ParamType::Address),
                p("amount", ParamType::Uint(256)),
                p("sumRecipient", ParamType::FixedBytes(32)),
            ],
            outputs: vec![],
            constant: None,
            state_mutability: StateMutability::Payable,
        }
    }

    /// `withdraw(address token, uint256 amount, address recipient, bytes[] signatures)`
    pub fn withdraw() -> Function {
        Function {
            name: "withdraw".into(),
            inputs: vec![
                p("token", ParamType::Address),
                p("amount", ParamType::Uint(256)),
                p("recipient", ParamType::Address),
                p("signatures", ParamType::Array(Box::new(ParamType::Bytes))),
            ],
            outputs: vec![],
            constant: None,
            state_mutability: StateMutability::NonPayable,
        }
    }

    /// `paused() returns (bool)`
    pub fn paused() -> Function {
        Function {
            name: "paused".into(),
            inputs: vec![],
            outputs: vec![p("", ParamType::Bool)],
            constant: None,
            state_mutability: StateMutability::View,
        }
    }

    /// `totalLocked(address token) returns (uint256)`
    pub fn total_locked() -> Function {
        Function {
            name: "totalLocked".into(),
            inputs: vec![p("token", ParamType::Address)],
            outputs: vec![p("", ParamType::Uint(256))],
            constant: None,
            state_mutability: StateMutability::View,
        }
    }

    /// `Deposit(address indexed sender, address indexed token, uint256 amount, bytes32 sumRecipient)`
    pub fn deposit_event() -> Event {
        Event {
            name: "Deposit".into(),
            inputs: vec![
                ep("sender", ParamType::Address, true),
                ep("token", ParamType::Address, true),
                ep("amount", ParamType::Uint(256), false),
                ep("sumRecipient", ParamType::FixedBytes(32), false),
            ],
            anonymous: false,
        }
    }

    /// `Withdrawal(address indexed recipient, address indexed token, uint256 amount)`
    pub fn withdrawal_event() -> Event {
        Event {
            name: "Withdrawal".into(),
            inputs: vec![
                ep("recipient", ParamType::Address, true),
                ep("token", ParamType::Address, true),
                ep("amount", ParamType::Uint(256), false),
            ],
            anonymous: false,
        }
    }
}
