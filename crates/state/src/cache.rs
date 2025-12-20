//! State caching for improved performance.

use lru::LruCache;
use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use sumchain_primitives::{Address, Hash};

/// Cached account data
#[derive(Debug, Clone)]
pub struct CachedAccount {
    /// Account balance
    pub balance: u128,
    /// Account nonce
    pub nonce: u64,
    /// Account state root (for contract storage)
    pub state_root: Hash,
}

/// LRU cache for state data
pub struct StateCache {
    /// Account cache
    accounts: parking_lot::RwLock<LruCache<Address, Arc<CachedAccount>>>,
    /// Storage cache (address -> key -> value)
    storage: parking_lot::RwLock<LruCache<(Address, Hash), Vec<u8>>>,
    /// Cache statistics
    hits: AtomicU64,
    misses: AtomicU64,
}

impl StateCache {
    /// Create a new state cache
    pub fn new(account_capacity: usize, storage_capacity: usize) -> Self {
        Self {
            accounts: parking_lot::RwLock::new(
                LruCache::new(NonZeroUsize::new(account_capacity).unwrap()),
            ),
            storage: parking_lot::RwLock::new(
                LruCache::new(NonZeroUsize::new(storage_capacity).unwrap()),
            ),
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
        }
    }

    /// Get account from cache
    pub fn get_account(&self, address: &Address) -> Option<Arc<CachedAccount>> {
        let result = self.accounts.write().get(address).cloned();

        if result.is_some() {
            self.hits.fetch_add(1, Ordering::Relaxed);
        } else {
            self.misses.fetch_add(1, Ordering::Relaxed);
        }

        result
    }

    /// Put account in cache
    pub fn put_account(&self, address: Address, account: CachedAccount) {
        self.accounts.write().put(address, Arc::new(account));
    }

    /// Get storage value from cache
    pub fn get_storage(&self, address: &Address, key: &Hash) -> Option<Vec<u8>> {
        let result = self.storage.write().get(&(*address, *key)).cloned();

        if result.is_some() {
            self.hits.fetch_add(1, Ordering::Relaxed);
        } else {
            self.misses.fetch_add(1, Ordering::Relaxed);
        }

        result
    }

    /// Put storage value in cache
    pub fn put_storage(&self, address: Address, key: Hash, value: Vec<u8>) {
        self.storage.write().put((address, key), value);
    }

    /// Invalidate account cache
    pub fn invalidate_account(&self, address: &Address) {
        self.accounts.write().pop(address);
    }

    /// Invalidate storage cache
    pub fn invalidate_storage(&self, address: &Address, key: &Hash) {
        self.storage.write().pop(&(*address, *key));
    }

    /// Clear all caches
    pub fn clear(&self) {
        self.accounts.write().clear();
        self.storage.write().clear();
        self.hits.store(0, Ordering::Relaxed);
        self.misses.store(0, Ordering::Relaxed);
    }

    /// Get cache hit rate
    pub fn hit_rate(&self) -> f64 {
        let hits = self.hits.load(Ordering::Relaxed);
        let misses = self.misses.load(Ordering::Relaxed);
        let total = hits + misses;

        if total == 0 {
            0.0
        } else {
            hits as f64 / total as f64
        }
    }

    /// Get cache statistics
    pub fn stats(&self) -> CacheStats {
        CacheStats {
            hits: self.hits.load(Ordering::Relaxed),
            misses: self.misses.load(Ordering::Relaxed),
            account_entries: self.accounts.read().len(),
            storage_entries: self.storage.read().len(),
        }
    }
}

/// Cache statistics
#[derive(Debug, Clone)]
pub struct CacheStats {
    pub hits: u64,
    pub misses: u64,
    pub account_entries: usize,
    pub storage_entries: usize,
}

impl CacheStats {
    pub fn hit_rate(&self) -> f64 {
        let total = self.hits + self.misses;
        if total == 0 {
            0.0
        } else {
            self.hits as f64 / total as f64
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_account_cache() {
        let cache = StateCache::new(100, 1000);
        let addr = Address::from_bytes(&[1; 20]);

        // Cache miss
        assert!(cache.get_account(&addr).is_none());

        // Insert account
        let account = CachedAccount {
            balance: 1000,
            nonce: 5,
            state_root: Hash::from_bytes(&[0; 32]),
        };
        cache.put_account(addr, account.clone());

        // Cache hit
        let cached = cache.get_account(&addr).unwrap();
        assert_eq!(cached.balance, 1000);
        assert_eq!(cached.nonce, 5);

        // Check stats
        let stats = cache.stats();
        assert_eq!(stats.hits, 1);
        assert_eq!(stats.misses, 1);
        assert_eq!(stats.hit_rate(), 0.5);
    }

    #[test]
    fn test_storage_cache() {
        let cache = StateCache::new(100, 1000);
        let addr = Address::from_bytes(&[1; 20]);
        let key = Hash::from_bytes(&[2; 32]);
        let value = vec![3, 4, 5];

        // Cache miss
        assert!(cache.get_storage(&addr, &key).is_none());

        // Insert storage
        cache.put_storage(addr, key, value.clone());

        // Cache hit
        let cached = cache.get_storage(&addr, &key).unwrap();
        assert_eq!(cached, value);
    }

    #[test]
    fn test_cache_invalidation() {
        let cache = StateCache::new(100, 1000);
        let addr = Address::from_bytes(&[1; 20]);

        let account = CachedAccount {
            balance: 1000,
            nonce: 5,
            state_root: Hash::from_bytes(&[0; 32]),
        };
        cache.put_account(addr, account);

        // Verify cached
        assert!(cache.get_account(&addr).is_some());

        // Invalidate
        cache.invalidate_account(&addr);

        // Verify removed
        assert!(cache.get_account(&addr).is_none());
    }

    #[test]
    fn test_lru_eviction() {
        // Small cache that will evict
        let cache = StateCache::new(2, 10);

        // Fill cache beyond capacity
        for i in 0..5 {
            let addr = Address::from_bytes(&[i; 20]);
            let account = CachedAccount {
                balance: i as u128,
                nonce: i as u64,
                state_root: Hash::from_bytes(&[0; 32]),
            };
            cache.put_account(addr, account);
        }

        // Only 2 most recent should be cached
        let stats = cache.stats();
        assert_eq!(stats.account_entries, 2);

        // Oldest entries should be evicted
        let addr_0 = Address::from_bytes(&[0; 20]);
        assert!(cache.get_account(&addr_0).is_none());

        // Most recent should be present
        let addr_4 = Address::from_bytes(&[4; 20]);
        assert!(cache.get_account(&addr_4).is_some());
    }
}
