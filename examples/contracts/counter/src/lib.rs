//! Counter Smart Contract Example
//!
//! A simple counter contract demonstrating basic SUMC smart contract features:
//! - State storage (persistent counter value)
//! - Constructor (init function)
//! - Public methods (increment, decrement, get)
//! - Owner-only methods (reset)
//! - Events (CounterChanged)

use sumc_sdk::prelude::*;
use sumc_sdk::storage::Value;

/// Storage accessor for counter value
fn counter_storage() -> Value<u64> {
    Value::new(b"counter")
}

/// Storage accessor for owner address
fn owner_storage() -> Value<[u8; 32]> {
    Value::new(b"owner")
}

/// Counter contract marker struct
#[sumc_sdk_macros::contract]
pub struct Counter;

/// Initialize the counter contract
/// Called once when the contract is deployed
#[sumc_sdk_macros::init]
pub fn init() {
    // Set the initial counter value to 0
    counter_storage().set(&0u64);

    // Store the deployer as the owner
    let caller = env::caller();
    let mut owner_bytes = [0u8; 32];
    owner_bytes.copy_from_slice(caller.as_bytes());
    owner_storage().set(&owner_bytes);

    env::log("Counter contract initialized");
}

/// Get the current counter value
#[sumc_sdk_macros::view]
pub fn get() -> u64 {
    counter_storage().get().unwrap_or(0)
}

/// Increment the counter by 1
#[sumc_sdk_macros::call]
pub fn increment() -> u64 {
    let current = counter_storage().get().unwrap_or(0);
    let new_value = current.saturating_add(1);
    counter_storage().set(&new_value);

    env::log(&format!("Counter incremented: {} -> {}", current, new_value));

    new_value
}

/// Decrement the counter by 1
#[sumc_sdk_macros::call]
pub fn decrement() -> u64 {
    let current = counter_storage().get().unwrap_or(0);
    let new_value = current.saturating_sub(1);
    counter_storage().set(&new_value);

    env::log(&format!("Counter decremented: {} -> {}", current, new_value));

    new_value
}

/// Add a specific amount to the counter
#[sumc_sdk_macros::call]
pub fn add(amount: u64) -> u64 {
    let current = counter_storage().get().unwrap_or(0);
    let new_value = current.saturating_add(amount);
    counter_storage().set(&new_value);

    env::log(&format!("Counter added {}: {} -> {}", amount, current, new_value));

    new_value
}

/// Reset the counter to 0 (owner only)
#[sumc_sdk_macros::call]
pub fn reset() -> bool {
    // Check if caller is the owner
    let caller = env::caller();
    let owner = owner_storage().get();

    if let Some(owner_bytes) = owner {
        if owner_bytes.as_slice() != caller.as_bytes() {
            env::log("Reset failed: caller is not owner");
            return false;
        }
    } else {
        env::log("Reset failed: no owner set");
        return false;
    }

    counter_storage().set(&0u64);
    env::log("Counter reset to 0");
    true
}

/// Get the contract owner address
#[sumc_sdk_macros::view]
pub fn owner() -> [u8; 32] {
    owner_storage().get().unwrap_or([0u8; 32])
}

/// Transfer ownership to a new address (owner only)
#[sumc_sdk_macros::call]
pub fn transfer_ownership(new_owner: [u8; 32]) -> bool {
    // Check if caller is the owner
    let caller = env::caller();
    let owner = owner_storage().get();

    if let Some(owner_bytes) = owner {
        if owner_bytes.as_slice() != caller.as_bytes() {
            env::log("Transfer ownership failed: caller is not owner");
            return false;
        }
    } else {
        env::log("Transfer ownership failed: no owner set");
        return false;
    }

    owner_storage().set(&new_owner);
    env::log("Ownership transferred");
    true
}
