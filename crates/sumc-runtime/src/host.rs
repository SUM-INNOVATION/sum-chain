//! Host functions exposed to WASM contracts.
//!
//! These functions allow contracts to interact with the blockchain state,
//! perform cryptographic operations, and communicate with other contracts.

use crate::{
    ContractAddress, ContractEvent, ContractStorage, GasMeter, LogEntry,
    Result, RuntimeError, MAX_EVENTS, MAX_LOGS,
};
use parking_lot::RwLock;
use std::sync::Arc;
use sumchain_primitives::Address;

/// Execution environment available to contracts
pub struct HostEnv {
    /// Current contract address
    pub self_address: ContractAddress,
    /// Caller address (who called this contract)
    pub caller: Address,
    /// Original transaction sender
    pub origin: Address,
    /// Value (Koppa) attached to this call
    pub attached_value: u128,
    /// Current block height
    pub block_height: u64,
    /// Current block timestamp
    pub block_timestamp: u64,
    /// Chain ID
    pub chain_id: u64,
    /// Gas meter
    pub gas_meter: Arc<GasMeter>,
    /// Contract storage
    pub storage: Arc<ContractStorage>,
    /// Emitted events
    pub events: RwLock<Vec<ContractEvent>>,
    /// Log entries
    pub logs: RwLock<Vec<LogEntry>>,
    /// Call depth (for recursion limiting)
    pub call_depth: u32,
    /// Balance of this contract
    pub balance: RwLock<u128>,
}

impl HostEnv {
    /// Create a new host environment
    pub fn new(
        self_address: ContractAddress,
        caller: Address,
        origin: Address,
        attached_value: u128,
        block_height: u64,
        block_timestamp: u64,
        chain_id: u64,
        gas_meter: Arc<GasMeter>,
        storage: Arc<ContractStorage>,
        balance: u128,
    ) -> Self {
        Self {
            self_address,
            caller,
            origin,
            attached_value,
            block_height,
            block_timestamp,
            chain_id,
            gas_meter,
            storage,
            events: RwLock::new(Vec::new()),
            logs: RwLock::new(Vec::new()),
            call_depth: 0,
            balance: RwLock::new(balance),
        }
    }

    /// Create a sub-environment for cross-contract calls
    pub fn for_call(
        &self,
        target: ContractAddress,
        value: u128,
        gas_limit: u64,
    ) -> Result<Self> {
        let sub_gas = self.gas_meter.sub_meter(gas_limit)?;

        Ok(Self {
            self_address: target,
            caller: self.self_address,
            origin: self.origin,
            attached_value: value,
            block_height: self.block_height,
            block_timestamp: self.block_timestamp,
            chain_id: self.chain_id,
            gas_meter: Arc::new(sub_gas),
            storage: self.storage.clone(),
            events: RwLock::new(Vec::new()),
            logs: RwLock::new(Vec::new()),
            call_depth: self.call_depth + 1,
            balance: RwLock::new(0), // Will be loaded separately
        })
    }

    // === Storage Host Functions ===

    /// Read from contract storage
    pub fn storage_read(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        self.gas_meter.consume_storage_read(key.len())?;
        self.storage.read(&self.self_address, key)
    }

    /// Write to contract storage
    pub fn storage_write(&self, key: &[u8], value: &[u8]) -> Result<()> {
        self.gas_meter.consume_storage_write(key.len() + value.len())?;
        self.storage.write(&self.self_address, key, value)
    }

    /// Delete from contract storage
    pub fn storage_remove(&self, key: &[u8]) -> Result<()> {
        self.gas_meter.consume_storage_delete()?;
        self.storage.delete(&self.self_address, key)
    }

    /// Check if key exists in storage
    pub fn storage_exists(&self, key: &[u8]) -> Result<bool> {
        self.gas_meter.consume_storage_read(key.len())?;
        self.storage.exists(&self.self_address, key)
    }

    // === Crypto Host Functions ===

    /// Blake3 hash
    pub fn blake3(&self, data: &[u8]) -> Result<[u8; 32]> {
        self.gas_meter.consume_blake3(data.len())?;
        Ok(*blake3::hash(data).as_bytes())
    }

    /// Ed25519 signature verification
    pub fn ed25519_verify(
        &self,
        message: &[u8],
        signature: &[u8; 64],
        public_key: &[u8; 32],
    ) -> Result<bool> {
        self.gas_meter.consume_ed25519_verify()?;

        match sumchain_crypto::verify_bytes(message, signature, public_key) {
            Ok(()) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    // === Event Host Functions ===

    /// Emit an event
    pub fn emit_event(&self, topics: Vec<[u8; 32]>, data: Vec<u8>) -> Result<()> {
        let data_len = topics.len() * 32 + data.len();
        self.gas_meter.consume_event(data_len)?;

        let mut events = self.events.write();
        if events.len() >= MAX_EVENTS {
            return Err(RuntimeError::Execution("Too many events".to_string()));
        }

        events.push(ContractEvent {
            contract: self.self_address,
            topics,
            data,
        });

        Ok(())
    }

    /// Write a log entry
    pub fn log(&self, data: Vec<u8>) -> Result<()> {
        self.gas_meter.consume_log(data.len())?;

        let mut logs = self.logs.write();
        if logs.len() >= MAX_LOGS {
            return Err(RuntimeError::Execution("Too many logs".to_string()));
        }

        logs.push(LogEntry {
            contract: self.self_address,
            data,
        });

        Ok(())
    }

    // === Value Transfer ===

    /// Transfer Koppa to another address
    pub fn transfer(&self, to: Address, amount: u128) -> Result<()> {
        self.gas_meter.consume_transfer()?;

        let mut balance = self.balance.write();
        if *balance < amount {
            return Err(RuntimeError::InsufficientBalance {
                required: amount,
                available: *balance,
            });
        }

        *balance -= amount;
        // Note: Actual balance update happens in the executor
        // This just validates and tracks the intention

        Ok(())
    }

    /// Get contract's Koppa balance
    pub fn get_balance(&self) -> u128 {
        *self.balance.read()
    }

    // === Utility ===

    /// Take all emitted events
    pub fn take_events(&self) -> Vec<ContractEvent> {
        std::mem::take(&mut *self.events.write())
    }

    /// Take all log entries
    pub fn take_logs(&self) -> Vec<LogEntry> {
        std::mem::take(&mut *self.logs.write())
    }
}

/// Host function indices for WASM imports
#[repr(u32)]
pub enum HostFunctionIndex {
    // Environment
    Caller = 0,
    SelfAddress = 1,
    Origin = 2,
    AttachedValue = 3,
    BlockHeight = 4,
    BlockTimestamp = 5,
    ChainId = 6,
    Balance = 7,

    // Storage
    StorageRead = 10,
    StorageWrite = 11,
    StorageRemove = 12,
    StorageExists = 13,

    // Crypto
    Blake3 = 20,
    Ed25519Verify = 21,

    // Events/Logs
    EmitEvent = 30,
    Log = 31,

    // Value transfer
    Transfer = 40,

    // Cross-contract calls
    Call = 50,

    // Utilities
    Abort = 60,
    Debug = 61,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::MemoryStorage;

    fn test_env() -> HostEnv {
        let storage = Arc::new(ContractStorage::new(Arc::new(MemoryStorage::new())));
        let gas_meter = Arc::new(GasMeter::new(1_000_000));

        HostEnv::new(
            Address::from_public_key(&[1u8; 32]),
            Address::from_public_key(&[2u8; 32]),
            Address::from_public_key(&[2u8; 32]),
            0,
            100,
            1234567890,
            1337,
            gas_meter,
            storage,
            1000,
        )
    }

    #[test]
    fn test_storage_operations() {
        let env = test_env();

        env.storage_write(b"key1", b"value1").unwrap();
        assert_eq!(
            env.storage_read(b"key1").unwrap(),
            Some(b"value1".to_vec())
        );
        assert!(env.storage_exists(b"key1").unwrap());

        env.storage_remove(b"key1").unwrap();
        assert!(!env.storage_exists(b"key1").unwrap());
    }

    #[test]
    fn test_blake3() {
        let env = test_env();
        let hash = env.blake3(b"hello").unwrap();
        assert_eq!(hash.len(), 32);
    }

    #[test]
    fn test_emit_event() {
        let env = test_env();

        env.emit_event(vec![[1u8; 32]], vec![1, 2, 3]).unwrap();
        env.emit_event(vec![[2u8; 32]], vec![4, 5, 6]).unwrap();

        let events = env.take_events();
        assert_eq!(events.len(), 2);
    }

    #[test]
    fn test_transfer() {
        let env = test_env();

        // Should succeed
        env.transfer(Address::ZERO, 500).unwrap();
        assert_eq!(env.get_balance(), 500);

        // Should fail - insufficient balance
        assert!(env.transfer(Address::ZERO, 600).is_err());
    }
}
