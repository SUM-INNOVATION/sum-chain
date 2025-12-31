//! Persistent storage collections for contracts.
//!
//! These collections automatically persist to contract storage.

use crate::env;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::marker::PhantomData;

// Re-import std Vec to avoid conflicts
use std::vec::Vec as StdVec;

/// Storage key prefix
fn make_key(prefix: &[u8], key: &[u8]) -> StdVec<u8> {
    let mut full_key = prefix.to_vec();
    full_key.extend_from_slice(key);
    full_key
}

/// Persistent key-value map
#[derive(Debug)]
pub struct Map<K, V> {
    prefix: StdVec<u8>,
    _key: PhantomData<K>,
    _value: PhantomData<V>,
}

impl<K, V> Map<K, V>
where
    K: Serialize + DeserializeOwned,
    V: Serialize + DeserializeOwned,
{
    /// Create a new map with auto-generated prefix
    pub fn new() -> Self {
        // In real implementation, prefix would be derived from storage slot
        Self {
            prefix: StdVec::new(),
            _key: PhantomData,
            _value: PhantomData,
        }
    }

    /// Create a new map with explicit prefix
    pub fn with_prefix(prefix: &[u8]) -> Self {
        Self {
            prefix: prefix.to_vec(),
            _key: PhantomData,
            _value: PhantomData,
        }
    }

    /// Get a value by key
    pub fn get(&self, key: &K) -> Option<V> {
        let key_bytes = bincode::serialize(key).ok()?;
        let full_key = make_key(&self.prefix, &key_bytes);
        let value_bytes = env::storage_read_(&full_key)?;
        bincode::deserialize(&value_bytes).ok()
    }

    /// Insert a key-value pair
    pub fn insert(&mut self, key: K, value: V) {
        if let (Ok(key_bytes), Ok(value_bytes)) =
            (bincode::serialize(&key), bincode::serialize(&value))
        {
            let full_key = make_key(&self.prefix, &key_bytes);
            env::storage_write_(&full_key, &value_bytes);
        }
    }

    /// Remove a key
    pub fn remove(&mut self, key: &K) {
        if let Ok(key_bytes) = bincode::serialize(key) {
            let full_key = make_key(&self.prefix, &key_bytes);
            env::storage_remove_(&full_key);
        }
    }

    /// Check if key exists
    pub fn contains_key(&self, key: &K) -> bool {
        self.get(key).is_some()
    }

    /// Get value or default
    pub fn get_or_default(&self, key: &K) -> V
    where
        V: Default,
    {
        self.get(key).unwrap_or_default()
    }

    /// Update a value with a function
    pub fn update<F>(&mut self, key: &K, f: F)
    where
        F: FnOnce(Option<V>) -> V,
        K: Clone,
    {
        let current = self.get(key);
        let new_value = f(current);
        self.insert(key.clone(), new_value);
    }
}

impl<K, V> Default for Map<K, V>
where
    K: Serialize + DeserializeOwned,
    V: Serialize + DeserializeOwned,
{
    fn default() -> Self {
        Self::new()
    }
}

/// Persistent set
#[derive(Debug)]
pub struct Set<T> {
    prefix: StdVec<u8>,
    _item: PhantomData<T>,
}

impl<T> Set<T>
where
    T: Serialize + DeserializeOwned,
{
    /// Create a new set
    pub fn new() -> Self {
        Self {
            prefix: StdVec::new(),
            _item: PhantomData,
        }
    }

    /// Create with explicit prefix
    pub fn with_prefix(prefix: &[u8]) -> Self {
        Self {
            prefix: prefix.to_vec(),
            _item: PhantomData,
        }
    }

    /// Check if item exists
    pub fn contains(&self, item: &T) -> bool {
        if let Ok(item_bytes) = bincode::serialize(item) {
            let full_key = make_key(&self.prefix, &item_bytes);
            env::storage_read_(&full_key).is_some()
        } else {
            false
        }
    }

    /// Insert an item
    pub fn insert(&mut self, item: T) {
        if let Ok(item_bytes) = bincode::serialize(&item) {
            let full_key = make_key(&self.prefix, &item_bytes);
            env::storage_write_(&full_key, &[1]); // Just store a marker
        }
    }

    /// Remove an item
    pub fn remove(&mut self, item: &T) {
        if let Ok(item_bytes) = bincode::serialize(item) {
            let full_key = make_key(&self.prefix, &item_bytes);
            env::storage_remove_(&full_key);
        }
    }
}

impl<T> Default for Set<T>
where
    T: Serialize + DeserializeOwned,
{
    fn default() -> Self {
        Self::new()
    }
}

/// Persistent vector (append-only for efficiency)
#[derive(Debug)]
pub struct PersistentVec<T> {
    prefix: StdVec<u8>,
    len_key: StdVec<u8>,
    _item: PhantomData<T>,
}

impl<T> PersistentVec<T>
where
    T: Serialize + DeserializeOwned,
{
    /// Create a new vector
    pub fn new() -> Self {
        Self {
            prefix: StdVec::new(),
            len_key: b"__len".to_vec(),
            _item: PhantomData,
        }
    }

    /// Create with explicit prefix
    pub fn with_prefix(prefix: &[u8]) -> Self {
        let mut len_key = prefix.to_vec();
        len_key.extend_from_slice(b"__len");

        Self {
            prefix: prefix.to_vec(),
            len_key,
            _item: PhantomData,
        }
    }

    /// Get the length
    pub fn len(&self) -> u64 {
        env::storage_read_(&self.len_key)
            .and_then(|bytes| bincode::deserialize(&bytes).ok())
            .unwrap_or(0)
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Get item at index
    pub fn get(&self, index: u64) -> Option<T> {
        if index >= self.len() {
            return None;
        }

        let key = make_key(&self.prefix, &index.to_le_bytes());
        let value_bytes = env::storage_read_(&key)?;
        bincode::deserialize(&value_bytes).ok()
    }

    /// Push an item
    pub fn push(&mut self, item: T) {
        let index = self.len();

        if let Ok(item_bytes) = bincode::serialize(&item) {
            let key = make_key(&self.prefix, &index.to_le_bytes());
            env::storage_write_(&key, &item_bytes);
        }

        // Update length
        if let Ok(len_bytes) = bincode::serialize(&(index + 1)) {
            env::storage_write_(&self.len_key, &len_bytes);
        }
    }

    /// Set item at index (must exist)
    pub fn set(&mut self, index: u64, item: T) -> bool {
        if index >= self.len() {
            return false;
        }

        if let Ok(item_bytes) = bincode::serialize(&item) {
            let key = make_key(&self.prefix, &index.to_le_bytes());
            env::storage_write_(&key, &item_bytes);
            true
        } else {
            false
        }
    }
}

impl<T> Default for PersistentVec<T>
where
    T: Serialize + DeserializeOwned,
{
    fn default() -> Self {
        Self::new()
    }
}

/// Single value storage slot
#[derive(Debug)]
pub struct Value<T> {
    key: StdVec<u8>,
    _value: PhantomData<T>,
}

impl<T> Value<T>
where
    T: Serialize + DeserializeOwned,
{
    /// Create a new value with the given key
    pub fn new(key: &[u8]) -> Self {
        Self {
            key: key.to_vec(),
            _value: PhantomData,
        }
    }

    /// Get the value
    pub fn get(&self) -> Option<T> {
        let bytes = env::storage_read_(&self.key)?;
        bincode::deserialize(&bytes).ok()
    }

    /// Set the value
    pub fn set(&self, value: &T) {
        if let Ok(bytes) = bincode::serialize(value) {
            env::storage_write_(&self.key, &bytes);
        }
    }

    /// Get or default
    pub fn get_or_default(&self) -> T
    where
        T: Default,
    {
        self.get().unwrap_or_default()
    }

    /// Update with a function
    pub fn update<F>(&self, f: F)
    where
        F: FnOnce(Option<T>) -> T,
    {
        let current = self.get();
        let new_value = f(current);
        self.set(&new_value);
    }

    /// Remove the value
    pub fn remove(&self) {
        env::storage_remove_(&self.key);
    }
}
