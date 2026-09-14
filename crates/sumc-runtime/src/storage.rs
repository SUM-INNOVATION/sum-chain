//! Contract storage management.

use crate::{ContractAddress, Result, RuntimeError};
use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::Arc;
use sumchain_storage::{contract_cf_kind, ContractMutation};

/// Raw `contract_storage` CF row key: `contract(20) || b':' || key`.
/// Matches `RocksDbStorage::make_key` so journal keys equal on-disk keys.
pub fn storage_cf_key(contract: &ContractAddress, key: &[u8]) -> Vec<u8> {
    let mut k = Vec::with_capacity(contract.as_bytes().len() + 1 + key.len());
    k.extend_from_slice(contract.as_bytes());
    k.push(b':');
    k.extend_from_slice(key);
    k
}

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

    /// Delete contract code (deploy cleanup on failed init).
    fn delete_code(&self, contract: &ContractAddress) -> Result<()>;

    /// Get serialized contract metadata.
    fn get_metadata(&self, contract: &ContractAddress) -> Result<Option<Vec<u8>>>;

    /// Store serialized contract metadata.
    fn store_metadata(&self, contract: &ContractAddress, bytes: &[u8]) -> Result<()>;

    /// Delete contract metadata (deploy cleanup on failed init).
    fn delete_metadata(&self, contract: &ContractAddress) -> Result<()>;

    /// Apply a set of storage writes/deletes atomically. `ops` is
    /// `(contract, key, Some(value) | None)`; `None` deletes. Implementations
    /// MUST apply all-or-nothing.
    fn commit(&self, ops: &[(ContractAddress, StorageKey, Option<StorageValue>)]) -> Result<()>;
}

/// In-memory storage for testing
#[derive(Debug, Default)]
pub struct MemoryStorage {
    /// Contract storage: contract_address -> (key -> value)
    storage: RwLock<HashMap<ContractAddress, HashMap<StorageKey, StorageValue>>>,
    /// Contract code: contract_address -> wasm bytecode
    code: RwLock<HashMap<ContractAddress, Vec<u8>>>,
    /// Contract metadata: contract_address -> serialized bytes
    metadata: RwLock<HashMap<ContractAddress, Vec<u8>>>,
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

    fn delete_code(&self, contract: &ContractAddress) -> Result<()> {
        self.code.write().remove(contract);
        Ok(())
    }

    fn get_metadata(&self, contract: &ContractAddress) -> Result<Option<Vec<u8>>> {
        Ok(self.metadata.read().get(contract).cloned())
    }

    fn store_metadata(&self, contract: &ContractAddress, bytes: &[u8]) -> Result<()> {
        self.metadata.write().insert(*contract, bytes.to_vec());
        Ok(())
    }

    fn delete_metadata(&self, contract: &ContractAddress) -> Result<()> {
        self.metadata.write().remove(contract);
        Ok(())
    }

    fn commit(&self, ops: &[(ContractAddress, StorageKey, Option<StorageValue>)]) -> Result<()> {
        let mut storage = self.storage.write();
        for (contract, key, value) in ops {
            match value {
                Some(v) => {
                    storage.entry(*contract).or_default().insert(key.clone(), v.clone());
                }
                None => {
                    if let Some(m) = storage.get_mut(contract) {
                        m.remove(key);
                    }
                }
            }
        }
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
    /// Per-block journal of COMMITTED contract-CF mutations (old + new), used
    /// for reorg revert + state-root commitment. Only successful commits and
    /// `record_raw` (code/metadata) append here; `rollback` does NOT clear it
    /// (uncommitted writes never reach the journal). Drained per block via
    /// `take_journal`.
    journal: RwLock<Vec<ContractMutation>>,
    /// Writes this BLOCK has committed but that are not durable yet.
    ///
    /// `commit` no longer reaches the database. It hands its operations back to
    /// the caller, which stages them into the block's candidate, and records
    /// them here so the rest of the block can still read them: a later
    /// transaction must see what an earlier one wrote, and the backend — which
    /// is committed storage — cannot show it that.
    ///
    /// This mirrors what `ExecutionView` does one layer up. Read order is
    /// write cache (this transaction), then here (this block), then the backend
    /// (the parent block).
    staged_storage: RwLock<HashMap<(ContractAddress, StorageKey), Option<StorageValue>>>,
    /// The same, for code and metadata, which used to write straight through.
    staged_code: RwLock<HashMap<ContractAddress, Option<Vec<u8>>>>,
    staged_metadata: RwLock<HashMap<ContractAddress, Option<Vec<u8>>>>,
    /// Operations staged but not yet handed to the caller.
    pending: RwLock<Vec<PendingWrite>>,
    /// The candidate these caches belong to.
    ///
    /// `ContractStorage` outlives any one block — it is built once, with the
    /// node — while everything above is scoped to a single candidate. Without
    /// an identity to compare, an abandoned block's rows stayed in
    /// `staged_storage`, which `read` consults BEFORE the backend, and the next
    /// block read state the chain never accepted.
    session: RwLock<Option<u64>>,
}

/// One contract-CF write, waiting to be staged into the block's candidate.
///
/// `ContractStorage` produces these instead of writing; `crates/state` stages
/// them. That keeps `ExecutionView` out of the runtime — this crate never
/// learns what a candidate is — while moving the commit point to the only place
/// that holds one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PendingWrite {
    /// A `cf::CONTRACT_STORAGE` row, keyed `contract || ':' || key`.
    Storage {
        contract: ContractAddress,
        key: StorageKey,
        value: Option<StorageValue>,
    },
    /// A `cf::CONTRACT_CODE` row, keyed by the contract address.
    Code {
        contract: ContractAddress,
        value: Option<Vec<u8>>,
    },
    /// A `cf::CONTRACT_METADATA` row, keyed by the contract address.
    Metadata {
        contract: ContractAddress,
        value: Option<Vec<u8>>,
    },
}

impl ContractStorage {
    /// Create a new contract storage with the given backend
    pub fn new(backend: Arc<dyn ContractStorageBackend>) -> Self {
        Self {
            backend,
            write_cache: RwLock::new(HashMap::new()),
            read_cache: RwLock::new(HashMap::new()),
            journal: RwLock::new(Vec::new()),
            staged_storage: RwLock::new(HashMap::new()),
            staged_code: RwLock::new(HashMap::new()),
            staged_metadata: RwLock::new(HashMap::new()),
            pending: RwLock::new(Vec::new()),
            session: RwLock::new(None),
        }
    }

    /// Record a raw CF mutation directly (used by deploy for code/metadata,
    /// which bypass the storage write-cache).
    pub fn record_raw(&self, mutation: ContractMutation) {
        self.journal.write().push(mutation);
    }

    /// Whether the journal is empty, WITHOUT draining it.
    ///
    /// For assertions that must not disturb what they measure.
    pub fn journal_is_empty(&self) -> bool {
        self.journal.read().is_empty()
    }

    /// Drain the accumulated commit journal.
    pub fn take_journal(&self) -> Vec<ContractMutation> {
        std::mem::take(&mut *self.journal.write())
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

        // Then what this BLOCK has already committed but not made durable. A
        // later transaction must see an earlier one's writes, and the backend
        // is the parent block — it cannot show them.
        {
            let staged = self.staged_storage.read();
            if let Some(value) = staged.get(&cache_key) {
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

        // Read from backend: the parent block's committed state.
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

    /// Get contract code from COMMITTED state, ignoring any candidate.
    ///
    /// For the RPC and diagnostic paths, which must answer about the chain
    /// rather than about whichever block this long-lived executor last touched.
    /// Reading the staged caches there let an abandoned block's contract answer
    /// "yes, I exist" to a question that was not about that block at all.
    pub fn get_code_committed(&self, contract: &ContractAddress) -> Result<Option<Vec<u8>>> {
        self.backend.get_code(contract)
    }

    /// Get contract metadata from COMMITTED state. See
    /// [`Self::get_code_committed`].
    pub fn get_metadata_committed(&self, contract: &ContractAddress) -> Result<Option<Vec<u8>>> {
        self.backend.get_metadata(contract)
    }

    /// Get contract code, as this block sees it.
    pub fn get_code(&self, contract: &ContractAddress) -> Result<Option<Vec<u8>>> {
        if let Some(v) = self.staged_code.read().get(contract) {
            return Ok(v.clone());
        }
        self.backend.get_code(contract)
    }

    /// Store contract code.
    ///
    /// This used to write STRAIGHT THROUGH to the database, unbuffered — a
    /// deploy made its code durable before the block containing it was
    /// accepted, so an abandoned block left the code behind. It is buffered now
    /// and staged with everything else.
    pub fn store_code(&self, contract: &ContractAddress, code: &[u8]) -> Result<()> {
        self.staged_code.write().insert(*contract, Some(code.to_vec()));
        self.pending.write().push(PendingWrite::Code {
            contract: *contract,
            value: Some(code.to_vec()),
        });
        Ok(())
    }

    /// Delete contract code (deploy cleanup on failed init).
    pub fn delete_code(&self, contract: &ContractAddress) -> Result<()> {
        self.staged_code.write().insert(*contract, None);
        self.pending.write().push(PendingWrite::Code {
            contract: *contract,
            value: None,
        });
        Ok(())
    }

    /// Get serialized contract metadata, as this block sees it.
    pub fn get_metadata(&self, contract: &ContractAddress) -> Result<Option<Vec<u8>>> {
        if let Some(v) = self.staged_metadata.read().get(contract) {
            return Ok(v.clone());
        }
        self.backend.get_metadata(contract)
    }

    /// Store serialized contract metadata. Buffered; see [`Self::store_code`].
    pub fn store_metadata(&self, contract: &ContractAddress, bytes: &[u8]) -> Result<()> {
        self.staged_metadata
            .write()
            .insert(*contract, Some(bytes.to_vec()));
        self.pending.write().push(PendingWrite::Metadata {
            contract: *contract,
            value: Some(bytes.to_vec()),
        });
        Ok(())
    }

    /// Delete contract metadata (deploy cleanup on failed init).
    pub fn delete_metadata(&self, contract: &ContractAddress) -> Result<()> {
        self.staged_metadata.write().insert(*contract, None);
        self.pending.write().push(PendingWrite::Metadata {
            contract: *contract,
            value: None,
        });
        Ok(())
    }

    /// Take the writes this block has committed but not yet staged.
    ///
    /// The caller — `crates/state`, which holds the block's `ExecutionView` —
    /// stages these. Draining here and staging there is what keeps the runtime
    /// free of any knowledge of candidates while still ending its ability to
    /// reach the database during execution.
    pub fn take_pending(&self) -> Vec<PendingWrite> {
        std::mem::take(&mut *self.pending.write())
    }

    /// Hand each queued write to `stage`, in order, and clear the queue only if
    /// every one of them succeeded.
    ///
    /// The entries are BORROWED. A `Vec<PendingWrite>` copy would duplicate the
    /// whole contract write set — a deployed contract's code among it — before
    /// the candidate has charged a single byte of it, which is a second copy
    /// the ceiling never sees.
    ///
    /// Clearing only on complete success is the other half. Staging is fallible
    /// (the candidate has a byte ceiling), and draining first would lose
    /// whatever followed a refusal: the queue empty, some of its contents
    /// written nowhere. On a refusal the queue is left exactly as it was.
    ///
    /// `stage` must not call back into this `ContractStorage`: the queue's lock
    /// is held across it.
    pub fn stage_pending<E>(
        &self,
        mut stage: impl FnMut(&PendingWrite) -> std::result::Result<(), E>,
    ) -> std::result::Result<(), E> {
        {
            let pending = self.pending.read();
            for write in pending.iter() {
                stage(write)?;
            }
        }
        self.pending.write().clear();
        Ok(())
    }

    /// The queued writes, WITHOUT draining them. Diagnostics and tests only —
    /// production staging goes through [`Self::stage_pending`], which does not
    /// copy them.
    pub fn queued_writes(&self) -> Vec<PendingWrite> {
        self.pending.read().clone()
    }

    /// How many writes are queued. A length, so asking does not copy them.
    pub fn pending_len(&self) -> usize {
        self.pending.read().len()
    }

    /// Drop the queue, after the caller has staged all of it.
    pub fn clear_pending(&self) {
        self.pending.write().clear();
    }

    /// Bind these caches to `candidate`, discarding anything held for another.
    ///
    /// Called before every contract operation, not at block boundaries. Tying
    /// the lifetime to an identity rather than to a remembered call is what
    /// makes it correct when a block is ABANDONED: nobody signals the end of a
    /// block that is thrown away, so a scheme that depends on being told would
    /// keep holding its rows. The next candidate presents a different identity
    /// and they go.
    ///
    /// Returns true when it cleared, so callers with their own per-candidate
    /// state can drop theirs in step.
    ///
    /// This is the backstop, not the main path: `BlockExecutor` clears at the
    /// end of every block execution, on the normal and the error exit both.
    /// What survives that is a direct `execute_tx` caller, which has no block
    /// boundary to hook, and that is what this covers.
    pub fn begin_candidate(&self, candidate: u64) -> bool {
        let mut session = self.session.write();
        if *session == Some(candidate) {
            return false;
        }
        *session = Some(candidate);
        self.clear_block();
        true
    }

    /// Drop every cache scoped to one candidate.
    ///
    /// The journal goes too. It records what a block committed, for the reorg
    /// diff; a journal surviving into the next block would attribute one
    /// block's mutations to another.
    pub fn clear_block(&self) {
        self.staged_storage.write().clear();
        self.staged_code.write().clear();
        self.staged_metadata.write().clear();
        self.read_cache.write().clear();
        self.write_cache.write().clear();
        self.pending.write().clear();
        self.journal.write().clear();
    }

    /// End the current candidate: drop every cache AND the session binding.
    ///
    /// What `BlockExecutor` calls when a block execution leaves its scope, by
    /// either exit. `clear_block` alone would leave the session bound, so the
    /// next candidate's first operation would still have to notice the change;
    /// unbinding here means nothing is held in the interval at all.
    ///
    /// Not merged into `clear_block`: `begin_candidate` calls that while
    /// holding the session lock, which is not reentrant.
    pub fn end_candidate(&self) {
        *self.session.write() = None;
        self.clear_block();
    }

    /// Accept this transaction's pending changes into the block.
    ///
    /// The write-cache is drained into a vector sorted by `(contract, key)` so
    /// the applied order is deterministic across nodes (required for the reorg
    /// journal and the state-root digest).
    ///
    /// It no longer reaches the database. This used to end in
    /// `backend.commit(&ops)` — a `WriteBatch` against RocksDB, executed while
    /// the block that produced it was still being built, so an abandoned block
    /// left contract storage moved. The operations are queued for the caller to
    /// stage instead, and recorded in `staged_storage` so the rest of the block
    /// can read them.
    ///
    /// The atomicity that batch provided is not lost but widened: the candidate
    /// is atomic across the whole block, not just across these rows.
    pub fn commit(&self) -> Result<()> {
        let mut write_cache = self.write_cache.write();
        let mut ops: Vec<(ContractAddress, StorageKey, Option<StorageValue>)> = write_cache
            .drain()
            .map(|((contract, key), value)| (contract, key, value))
            .collect();
        ops.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()).then_with(|| a.1.cmp(&b.1)));
        drop(write_cache);

        // Pre-images come from what the BLOCK sees, not from the database: an
        // earlier transaction of this block may already have moved the row, and
        // a journal that recorded the parent's value there would revert to the
        // wrong state.
        let mut mutations = Vec::with_capacity(ops.len());
        for (contract, key, new) in &ops {
            let old = self.read_committed_in_block(contract, key)?;
            mutations.push(ContractMutation {
                cf_kind: contract_cf_kind::STORAGE,
                key: storage_cf_key(contract, key),
                old,
                new: new.clone(),
            });
        }

        {
            let mut staged = self.staged_storage.write();
            let mut pending = self.pending.write();
            for (contract, key, value) in ops {
                staged.insert((contract, key.clone()), value.clone());
                pending.push(PendingWrite::Storage {
                    contract,
                    key,
                    value,
                });
            }
        }
        if !mutations.is_empty() {
            self.journal.write().extend(mutations);
        }

        // Clear read cache (state has changed)
        self.read_cache.write().clear();

        Ok(())
    }

    /// The value as of before this transaction, within this block: what the
    /// block has already staged, else what the parent committed.
    fn read_committed_in_block(
        &self,
        contract: &ContractAddress,
        key: &[u8],
    ) -> Result<Option<StorageValue>> {
        if let Some(v) = self.staged_storage.read().get(&(*contract, key.to_vec())) {
            return Ok(v.clone());
        }
        self.backend.read(contract, key)
    }

    /// Rollback uncommitted changes. Does NOT touch the commit journal —
    /// uncommitted writes never reach it, and previously committed mutations
    /// in the same block must survive a later tx's rollback.
    pub fn rollback(&self) {
        self.write_cache.write().clear();
        self.read_cache.write().clear();
    }

    /// Get pending write count (for gas estimation)
    pub fn pending_writes(&self) -> usize {
        self.write_cache.read().len()
    }
}

// Column family names — single source of truth is `sumchain_storage::cf`
// (registered in `ALL_CFS`), so these stay in sync with what the DB opens.
const CF_CONTRACT_STORAGE: &str = sumchain_storage::cf::CONTRACT_STORAGE;
const CF_CONTRACT_CODE: &str = sumchain_storage::cf::CONTRACT_CODE;
const CF_CONTRACT_METADATA: &str = sumchain_storage::cf::CONTRACT_METADATA;

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

    fn delete_code(&self, contract: &ContractAddress) -> Result<()> {
        self.db
            .delete(CF_CONTRACT_CODE, contract.as_bytes())
            .map_err(|e| RuntimeError::Storage(e.to_string()))
    }

    fn get_metadata(&self, contract: &ContractAddress) -> Result<Option<Vec<u8>>> {
        self.db
            .get(CF_CONTRACT_METADATA, contract.as_bytes())
            .map_err(|e| RuntimeError::Storage(e.to_string()))
    }

    fn store_metadata(&self, contract: &ContractAddress, bytes: &[u8]) -> Result<()> {
        self.db
            .put(CF_CONTRACT_METADATA, contract.as_bytes(), bytes)
            .map_err(|e| RuntimeError::Storage(e.to_string()))
    }

    fn delete_metadata(&self, contract: &ContractAddress) -> Result<()> {
        self.db
            .delete(CF_CONTRACT_METADATA, contract.as_bytes())
            .map_err(|e| RuntimeError::Storage(e.to_string()))
    }

    fn commit(&self, ops: &[(ContractAddress, StorageKey, Option<StorageValue>)]) -> Result<()> {
        let mut batch = self.db.batch();
        for (contract, key, value) in ops {
            let full_key = self.make_key(contract, key);
            match value {
                Some(v) => batch
                    .put(CF_CONTRACT_STORAGE, &full_key, v)
                    .map_err(|e| RuntimeError::Storage(e.to_string()))?,
                None => batch
                    .delete(CF_CONTRACT_STORAGE, &full_key)
                    .map_err(|e| RuntimeError::Storage(e.to_string()))?,
            }
        }
        batch.commit().map_err(|e| RuntimeError::Storage(e.to_string()))
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
    fn staging_clears_the_queue_only_when_every_write_lands() {
        let backend = Arc::new(MemoryStorage::new());
        let storage = ContractStorage::new(backend);
        let contract = Address::from_public_key(&[4u8; 32]);

        storage.begin_candidate(1);
        storage.write(&contract, b"a", b"1").unwrap();
        storage.write(&contract, b"b", b"2").unwrap();
        storage.write(&contract, b"c", b"3").unwrap();
        storage.commit().unwrap();
        assert_eq!(storage.pending_len(), 3);

        // A refusal on the second write: the candidate has a byte ceiling and
        // this is what hitting it looks like from here.
        let mut seen = 0usize;
        let refused: std::result::Result<(), &'static str> = storage.stage_pending(|_| {
            seen += 1;
            if seen == 2 {
                Err("ceiling")
            } else {
                Ok(())
            }
        });
        assert_eq!(refused, Err("ceiling"));
        assert_eq!(seen, 2, "staging stops at the refusal");
        assert_eq!(
            storage.pending_len(),
            3,
            "a refusal must leave the WHOLE queue, including the write that \
             landed and the ones after the refusal — draining first lost them"
        );

        // Complete success clears it, and only then.
        let staged = std::cell::RefCell::new(Vec::new());
        let ok: std::result::Result<(), &'static str> = storage.stage_pending(|w| {
            staged.borrow_mut().push(match w {
                PendingWrite::Storage { key, .. } => key.clone(),
                _ => Vec::new(),
            });
            Ok(())
        });
        assert_eq!(ok, Ok(()));
        assert_eq!(
            staged.into_inner(),
            vec![b"a".to_vec(), b"b".to_vec(), b"c".to_vec()],
            "in queue order"
        );
        assert_eq!(storage.pending_len(), 0, "and now the queue is empty");
    }

    #[test]
    fn a_new_candidate_drops_everything_the_last_one_held() {
        let backend = Arc::new(MemoryStorage::new());
        let storage = ContractStorage::new(backend.clone());
        let contract = Address::from_public_key(&[3u8; 32]);

        storage.begin_candidate(1);
        storage.write(&contract, b"k", b"v").unwrap();
        storage.store_code(&contract, b"code").unwrap();
        storage.store_metadata(&contract, b"meta").unwrap();
        storage.commit().unwrap();

        // Candidate 1 can see all of it, and has it queued.
        assert_eq!(storage.read(&contract, b"k").unwrap(), Some(b"v".to_vec()));
        assert_eq!(storage.get_code(&contract).unwrap(), Some(b"code".to_vec()));
        assert_eq!(storage.get_metadata(&contract).unwrap(), Some(b"meta".to_vec()));
        assert!(!storage.queued_writes().is_empty());
        // NOT `take_journal` here: that drains, and the assertion after the
        // candidate change would then be trivially true. An earlier version of
        // this test did exactly that and let a mutation removing the journal
        // clearing pass.
        assert!(!storage.journal_is_empty(), "the commit journalled");

        // Re-binding the SAME candidate changes nothing.
        assert!(!storage.begin_candidate(1), "same candidate must not clear");
        assert_eq!(storage.read(&contract, b"k").unwrap(), Some(b"v".to_vec()));

        // A DIFFERENT candidate drops all of it. Candidate 1 was never
        // published — nothing reached the backend — so none of it may be
        // visible here.
        assert!(storage.begin_candidate(2), "a new candidate must clear");
        assert_eq!(
            storage.read(&contract, b"k").unwrap(),
            None,
            "storage staged by an abandoned candidate must not be readable"
        );
        assert_eq!(
            storage.get_code(&contract).unwrap(),
            None,
            "nor its code"
        );
        assert_eq!(
            storage.get_metadata(&contract).unwrap(),
            None,
            "nor its metadata"
        );
        assert!(
            storage.queued_writes().is_empty(),
            "nor may its queued writes be staged into this candidate"
        );
        assert!(
            storage.take_journal().is_empty(),
            "nor may its journal be attributed to this block"
        );
        assert_eq!(backend.read(&contract, b"k").unwrap(), None, "and nothing was ever durable");
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

        // Commit: this ACCEPTS the write into the block. It no longer reaches
        // the backend — the caller stages the queued operations into the
        // block's candidate, and only publication makes them durable.
        storage.commit().unwrap();

        // The backend is still untouched...
        assert_eq!(
            backend.read(&contract, b"key1").unwrap(),
            None,
            "commit must not write through: that is the defect this replaced"
        );

        // ...the write is queued for the caller to stage...
        let pending = storage.take_pending();
        assert_eq!(pending.len(), 1);
        assert!(matches!(
            &pending[0],
            PendingWrite::Storage { value: Some(v), .. } if v == b"value1"
        ));

        // ...and the rest of the block can still read it, which is what the
        // staged cache is for.
        assert_eq!(
            storage.read(&contract, b"key1").unwrap(),
            Some(b"value1".to_vec())
        );

        // Applying what was queued is what makes it durable.
        backend
            .commit(&[(contract, b"key1".to_vec(), Some(b"value1".to_vec()))])
            .unwrap();
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
