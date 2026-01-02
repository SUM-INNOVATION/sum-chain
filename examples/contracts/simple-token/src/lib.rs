//! Simple Token Smart Contract Example
//!
//! A basic fungible token contract demonstrating:
//! - Token metadata (name, symbol, decimals)
//! - Balance tracking
//! - Transfer functionality
//! - Approval/allowance pattern
//! - Minting (owner only)
//! - Burning

use sumc_sdk::prelude::*;
use sumc_sdk::storage::{Map, Value};

/// Token contract marker struct
#[sumc_sdk_macros::contract]
pub struct SimpleToken;

// Storage accessors
fn name_storage() -> Value<Vec<u8>> {
    Value::new(b"name")
}

fn symbol_storage() -> Value<Vec<u8>> {
    Value::new(b"symbol")
}

fn decimals_storage() -> Value<u8> {
    Value::new(b"decimals")
}

fn total_supply_storage() -> Value<u128> {
    Value::new(b"total_supply")
}

fn owner_storage() -> Value<[u8; 32]> {
    Value::new(b"owner")
}

fn balances() -> Map<[u8; 32], u128> {
    Map::with_prefix(b"bal:")
}

fn allowances() -> Map<([u8; 32], [u8; 32]), u128> {
    Map::with_prefix(b"all:")
}

/// Initialize the token contract
/// Called once when the contract is deployed
#[sumc_sdk_macros::init]
pub fn init() {
    // Set token metadata
    name_storage().set(&b"SimpleToken".to_vec());
    symbol_storage().set(&b"STOK".to_vec());
    decimals_storage().set(&8u8);
    total_supply_storage().set(&0u128);

    // Store the deployer as the owner
    let caller = env::caller();
    let mut owner_bytes = [0u8; 32];
    owner_bytes.copy_from_slice(caller.as_bytes());
    owner_storage().set(&owner_bytes);

    env::log("SimpleToken contract initialized");
}

/// Get token name
#[sumc_sdk_macros::view]
pub fn name() -> Vec<u8> {
    name_storage().get().unwrap_or_default()
}

/// Get token symbol
#[sumc_sdk_macros::view]
pub fn symbol() -> Vec<u8> {
    symbol_storage().get().unwrap_or_default()
}

/// Get token decimals
#[sumc_sdk_macros::view]
pub fn decimals() -> u8 {
    decimals_storage().get().unwrap_or(8)
}

/// Get total supply
#[sumc_sdk_macros::view]
pub fn total_supply() -> u128 {
    total_supply_storage().get().unwrap_or(0)
}

/// Get balance of an address
#[sumc_sdk_macros::view]
pub fn balance_of(account: [u8; 32]) -> u128 {
    balances().get(&account).unwrap_or(0)
}

/// Get allowance for a spender
#[sumc_sdk_macros::view]
pub fn allowance(owner: [u8; 32], spender: [u8; 32]) -> u128 {
    allowances().get(&(owner, spender)).unwrap_or(0)
}

/// Transfer tokens to another address
#[sumc_sdk_macros::call]
pub fn transfer(to: [u8; 32], amount: u128) -> bool {
    let caller = env::caller();
    let mut from = [0u8; 32];
    from.copy_from_slice(caller.as_bytes());

    // Check balance
    let from_balance = balances().get(&from).unwrap_or(0);

    if from_balance < amount {
        env::log("Transfer failed: insufficient balance");
        return false;
    }

    // Update balances
    let to_balance = balances().get(&to).unwrap_or(0);

    balances().insert(from, from_balance - amount);
    balances().insert(to, to_balance + amount);

    env::log(&format!("Transferred {} tokens", amount));
    true
}

/// Approve spender to spend tokens on behalf of caller
#[sumc_sdk_macros::call]
pub fn approve(spender: [u8; 32], amount: u128) -> bool {
    let caller = env::caller();
    let mut owner = [0u8; 32];
    owner.copy_from_slice(caller.as_bytes());

    allowances().insert((owner, spender), amount);

    env::log(&format!("Approved {} tokens", amount));
    true
}

/// Transfer tokens from one address to another (using allowance)
#[sumc_sdk_macros::call]
pub fn transfer_from(from: [u8; 32], to: [u8; 32], amount: u128) -> bool {
    let caller = env::caller();
    let mut spender = [0u8; 32];
    spender.copy_from_slice(caller.as_bytes());

    // Check allowance
    let current_allowance = allowances().get(&(from, spender)).unwrap_or(0);

    if current_allowance < amount {
        env::log("Transfer failed: insufficient allowance");
        return false;
    }

    // Check balance
    let from_balance = balances().get(&from).unwrap_or(0);

    if from_balance < amount {
        env::log("Transfer failed: insufficient balance");
        return false;
    }

    // Update balances and allowance
    let to_balance = balances().get(&to).unwrap_or(0);

    balances().insert(from, from_balance - amount);
    balances().insert(to, to_balance + amount);
    allowances().insert((from, spender), current_allowance - amount);

    env::log(&format!("Transferred {} tokens (from allowance)", amount));
    true
}

/// Mint new tokens (owner only)
#[sumc_sdk_macros::call]
pub fn mint(to: [u8; 32], amount: u128) -> bool {
    // Check if caller is owner
    let caller = env::caller();
    let owner = owner_storage().get();

    if let Some(owner_bytes) = owner {
        if owner_bytes.as_slice() != caller.as_bytes() {
            env::log("Mint failed: caller is not owner");
            return false;
        }
    } else {
        env::log("Mint failed: no owner set");
        return false;
    }

    // Update balance and total supply
    let balance = balances().get(&to).unwrap_or(0);
    let total = total_supply_storage().get().unwrap_or(0);

    balances().insert(to, balance + amount);
    total_supply_storage().set(&(total + amount));

    env::log(&format!("Minted {} tokens", amount));
    true
}

/// Burn tokens
#[sumc_sdk_macros::call]
pub fn burn(amount: u128) -> bool {
    let caller = env::caller();
    let mut from = [0u8; 32];
    from.copy_from_slice(caller.as_bytes());

    // Check balance
    let balance = balances().get(&from).unwrap_or(0);

    if balance < amount {
        env::log("Burn failed: insufficient balance");
        return false;
    }

    // Update balance and total supply
    let total = total_supply_storage().get().unwrap_or(0);

    balances().insert(from, balance - amount);
    total_supply_storage().set(&(total - amount));

    env::log(&format!("Burned {} tokens", amount));
    true
}

/// Get contract owner
#[sumc_sdk_macros::view]
pub fn owner() -> [u8; 32] {
    owner_storage().get().unwrap_or([0u8; 32])
}
