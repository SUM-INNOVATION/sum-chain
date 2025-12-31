//! Contract storage management.

use crate::{ContractAddress, Result, RuntimeError};
use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::Arc;

/// Storage key type
pub type StorageKey = Vec<u8>;

/// Storage value type
pub type StorageValue = Vec<u8>;

/// Contract storage interface
pub trait ContractStorageBackend: Send + Sync {
    /// Read a value from storage
    fn read(&self, contract: &ContractAddress, key: &[u8]) -> Result<Option<Vec<u8>>>;

    /// Write a value to storage
    fn write(&self, contract: &ContractAddress, key: &[u8], value: &[u8]) -> Result<()>;

    /// Delete a value from storage
    fn delete(&self, contract: &ContractAddress, key: &[u8]) -> Result<()>;

    /// Check if a key exists
    fn exists(&self, contract: &ContractAddress, key: &[u8]) -> Result<bool>;

    /// Get contract code by address
    fn get_code(&self, contract: &ContractAddress) -> Result<Option<Vec<u8>>>;

    /// Store contract code
    fn store_code(&self, contract: &ContractAddress, code: &[u8]) -> Result<()>;
}

/// In-memory storage for testing
#[derive(Debug, Default)]
pub struct MemoryStorage {
    /// Contract storage: contract_address -> (key -> value)
    storage: RwLock<HashMap<ContractAddress, HashMap<StorageKey, StorageValue>>>,
    /// Contract code: contract_address -> wasm bytecode
    code: RwLock<HashMap<ContractAddress, Vec<u8>>>,
}

impl MemoryStorage {
    pub fn new() -> Self {
        Self::default()
    }
}

impl ContractStorageBackend for MemoryStorage {
    fn read(&self, contract: &ContractAddress, key: &[u8]) -> Result<Option<Vec<u8>>> {
        let storage = self.storage.read();
        Ok(storage
            .get(contract)
            .and_then(|m| m.get(key))
            .cloned())
    }

    fn write(&self, contract: &ContractAddress, key: &[u8], value: &[u8]) -> Result<()> {
        let mut storage = self.storage.write();
        storage
            .entry(*contract)
            .or_default()
            .insert(key.to_vec(), value.to_vec());
        Ok(())
    }

    fn delete(&self, contract: &ContractAddress, key: &[u8]) -> Result<()> {
        let mut storage = self.storage.write();
        if let Some(m) = storage.get_mut(contract) {
            m.remove(key);
        }
        Ok(())
    }

    fn exists(&self, contract: &ContractAddress, key: &[u8]) -> Result<bool> {
        let storage = self.storage.read();
        Ok(storage
            .get(contract)
            .map(|m| m.contains_key(key))
            .unwrap_or(false))
    }

    fn get_code(&self, contract: &ContractAddress) -> Result<Option<Vec<u8>>> {
        let code = self.code.read();
        Ok(code.get(contract).cloned())
    }

    fn store_code(&self, contract: &ContractAddress, wasm: &[u8]) -> Result<()> {
        let mut code = self.code.write();
        code.insert(*contract, wasm.to_vec());
        Ok(())
    }
}

/// Contract storage wrapper with caching
pub struct ContractStorage {
    /// Underlying storage backend
    backend: Arc<dyn ContractStorageBackend>,
    /// Write cache for pending changes
    write_cache: RwLock<HashMap<(ContractAddress, StorageKey), Option<StorageValue>>>,
    /// Read cache
    read_cache: RwLock<HashMap<(ContractAddress, StorageKey), Option<StorageValue>>>,
}

impl ContractStorage {
    /// Create a new contract storage with the given backend
    pub fn new(backend: Arc<dyn ContractStorageBackend>) -> Self {
        Self {
            backend,
            write_cache: RwLock::new(HashMap::new()),
            read_cache: RwLock::new(HashMap::new()),
        }
    }

    /// Read a value, checking cache first
    pub fn read(&self, contract: &ContractAddress, key: &[u8]) -> Result<Option<Vec<u8>>> {
        let cache_key = (*contract, key.to_vec());

        // Check write cache first (pending changes)
        {
            let write_cache = self.write_cache.read();
            if let Some(value) = write_cache.get(&cache_key) {
                return Ok(value.clone());
            }
        }

        // Check read cache
        {
            let read_cache = self.read_cache.read();
            if let Some(value) = read_cache.get(&cache_key) {
                return Ok(value.clone());
            }
        }

        // Read from backend
        let value = self.backend.read(contract, key)?;

        // Update read cache
        {
            let mut read_cache = self.read_cache.write();
            read_cache.insert(cache_key, value.clone());
        }

        Ok(value)
    }

    /// Write a value (cached until commit)
    pub fn write(&self, contract: &ContractAddress, key: &[u8], value: &[u8]) -> Result<()> {
        let cache_key = (*contract, key.to_vec());
        let mut write_cache = self.write_cache.write();
        write_cache.insert(cache_key, Some(value.to_vec()));
        Ok(())
    }

    /// Delete a value (cached until commit)
    pub fn delete(&self, contract: &ContractAddress, key: &[u8]) -> Result<()> {
        let cache_key = (*contract, key.to_vec());
        let mut write_cache = self.write_cache.write();
        write_cache.insert(cache_key, None); // None = deleted
        Ok(())
    }

    /// Check if a key exists
    pub fn exists(&self, contract: &ContractAddress, key: &[u8]) -> Result<bool> {
        Ok(self.read(contract, key)?.is_some())
    }

    /// Get contract code
    pub fn get_code(&self, contract: &ContractAddress) -> Result<Option<Vec<u8>>> {
        self.backend.get_code(contract)
    }

    /// Store contract code
    pub fn store_code(&self, contract: &ContractAddress, code: &[u8]) -> Result<()> {
        self.backend.store_code(contract, code)
    }

    /// Commit all pending changes to the backend
    pub fn commit(&self) -> Result<()> {
        let mut write_cache = self.write_cache.write();

        for ((contract, key), value) in write_cache.drain() {
            match value {
                Some(v) => self.backend.write(&contract, &key, &v)?,
                None => self.backend.delete(&contract, &key)?,
            }
        }

        // Clear read cache (state has changed)
        self.read_cache.write().clear();

        Ok(())
    }

    /// Rollback all pending changes
    pub fn rollback(&self) {
        self.write_cache.write().clear();
        self.read_cache.write().clear();
    }

    /// Get pending write count (for gas estimation)
    pub fn pending_writes(&self) -> usize {
        self.write_cache.read().len()
    }
}

/// Column family name for contract storage
const CF_CONTRACT_STORAGE: &str = "contract_storage";
/// Column family name for contract code
const CF_CONTRACT_CODE: &str = "contract_code";

/// Storage adapter for RocksDB backend
pub struct RocksDbStorage {
    db: Arc<sumchain_storage::Database>,
}

impl RocksDbStorage {
    /// Create a new RocksDB storage adapter
    pub fn new(db: Arc<sumchain_storage::Database>) -> Self {
        Self { db }
    }

    fn make_key(&self, contract: &ContractAddress, key: &[u8]) -> Vec<u8> {
        let mut full_key = Vec::with_capacity(contract.as_bytes().len() + 1 + key.len());
        full_key.extend_from_slice(contract.as_bytes());
        full_key.push(b':');
        full_key.extend_from_slice(key);
        full_key
    }
}

impl ContractStorageBackend for RocksDbStorage {
    fn read(&self, contract: &ContractAddress, key: &[u8]) -> Result<Option<Vec<u8>>> {
        let full_key = self.make_key(contract, key);
        self.db
            .get(CF_CONTRACT_STORAGE, &full_key)
            .map_err(|e| RuntimeError::Storage(e.to_string()))
    }

    fn write(&self, contract: &ContractAddress, key: &[u8], value: &[u8]) -> Result<()> {
        let full_key = self.make_key(contract, key);
        self.db
            .put(CF_CONTRACT_STORAGE, &full_key, value)
            .map_err(|e| RuntimeError::Storage(e.to_string()))
    }

    fn delete(&self, contract: &ContractAddress, key: &[u8]) -> Result<()> {
        let full_key = self.make_key(contract, key);
        self.db
            .delete(CF_CONTRACT_STORAGE, &full_key)
            .map_err(|e| RuntimeError::Storage(e.to_string()))
    }

    fn exists(&self, contract: &ContractAddress, key: &[u8]) -> Result<bool> {
        Ok(self.read(contract, key)?.is_some())
    }

    fn get_code(&self, contract: &ContractAddress) -> Result<Option<Vec<u8>>> {
        self.db
            .get(CF_CONTRACT_CODE, contract.as_bytes())
            .map_err(|e| RuntimeError::Storage(e.to_string()))
    }

    fn store_code(&self, contract: &ContractAddress, code: &[u8]) -> Result<()> {
        self.db
            .put(CF_CONTRACT_CODE, contract.as_bytes(), code)
            .map_err(|e| RuntimeError::Storage(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sumchain_primitives::Address;

    #[test]
    fn test_memory_storage() {
        let storage = MemoryStorage::new();
        let contract = Address::from_public_key(&[1u8; 32]);

        // Write and read
        storage.write(&contract, b"key1", b"value1").unwrap();
        assert_eq!(
            storage.read(&contract, b"key1").unwrap(),
            Some(b"value1".to_vec())
        );

        // Non-existent key
        assert_eq!(storage.read(&contract, b"key2").unwrap(), None);

        // Delete
        storage.delete(&contract, b"key1").unwrap();
        assert_eq!(storage.read(&contract, b"key1").unwrap(), None);
    }

    #[test]
    fn test_contract_storage_cache() {
        let backend = Arc::new(MemoryStorage::new());
        let storage = ContractStorage::new(backend.clone());
        let contract = Address::from_public_key(&[2u8; 32]);

        // Write (cached)
        storage.write(&contract, b"key1", b"value1").unwrap();

        // Read from cache (not committed yet)
        assert_eq!(
            storage.read(&contract, b"key1").unwrap(),
            Some(b"value1".to_vec())
        );

        // Backend should not have the value yet
        assert_eq!(backend.read(&contract, b"key1").unwrap(), None);

        // Commit
        storage.commit().unwrap();

        // Now backend should have the value
        assert_eq!(
            backend.read(&contract, b"key1").unwrap(),
            Some(b"value1".to_vec())
        );
    }

    #[test]
    fn test_rollback() {
        let backend = Arc::new(MemoryStorage::new());
        let storage = ContractStorage::new(backend.clone());
        let contract = Address::from_public_key(&[3u8; 32]);

        storage.write(&contract, b"key1", b"value1").unwrap();
        storage.rollback();

        // Should not be readable after rollback
        assert_eq!(storage.read(&contract, b"key1").unwrap(), None);
    }
}
