//! Environment functions - access to blockchain state and host functions.
//!
//! These functions are implemented as host function calls in the WASM runtime.

use crate::types::{Address, Balance, BlockHeight, Hash, Timestamp};

// === External host functions (implemented by the runtime) ===

#[link(wasm_import_module = "env")]
extern "C" {
    #[link_name = "caller"]
    fn host_caller() -> i32;
    #[link_name = "self_address"]
    fn host_self_address() -> i32;
    #[link_name = "origin"]
    fn host_origin() -> i32;
    #[link_name = "attached_value"]
    fn host_attached_value() -> i64;
    #[link_name = "block_height"]
    fn host_block_height() -> i64;
    #[link_name = "block_timestamp"]
    fn host_block_timestamp() -> i64;
    #[link_name = "chain_id"]
    fn host_chain_id() -> i64;

    #[link_name = "storage_read"]
    fn host_storage_read(key_ptr: i32, key_len: i32) -> i32;
    #[link_name = "storage_write"]
    fn host_storage_write(key_ptr: i32, key_len: i32, value_ptr: i32, value_len: i32);
    #[link_name = "storage_remove"]
    fn host_storage_remove(key_ptr: i32, key_len: i32);

    #[link_name = "blake3"]
    fn host_blake3(data_ptr: i32, data_len: i32) -> i32;
    #[link_name = "ed25519_verify"]
    fn host_ed25519_verify(msg_ptr: i32, msg_len: i32, sig_ptr: i32, pubkey_ptr: i32) -> i32;

    #[link_name = "emit"]
    fn host_emit(topics_ptr: i32, data_ptr: i32, data_len: i32);
    #[link_name = "log"]
    fn host_log(data_ptr: i32, data_len: i32);

    #[link_name = "transfer"]
    fn host_transfer(to_ptr: i32, amount_lo: i64, amount_hi: i64) -> i32;

    #[link_name = "abort"]
    fn host_abort(msg_ptr: i32, msg_len: i32);
}

// === Safe wrappers ===

/// Get the caller's address (who called this contract)
pub fn caller_address() -> Address {
    // In real implementation, this would read from host
    // For now, return placeholder
    Address::ZERO
}

/// Get this contract's address
pub fn self_address_() -> Address {
    Address::ZERO
}

/// Get the original transaction sender
pub fn origin_address() -> Address {
    Address::ZERO
}

/// Get the value (Koppa) attached to this call
pub fn attached_value_() -> Balance {
    unsafe { host_attached_value() as u128 }
}

/// Get current block height
pub fn block_height_() -> BlockHeight {
    unsafe { host_block_height() as u64 }
}

/// Get current block timestamp
pub fn block_timestamp_() -> Timestamp {
    unsafe { host_block_timestamp() as u64 }
}

/// Get chain ID
pub fn chain_id_() -> u64 {
    unsafe { host_chain_id() as u64 }
}

/// Read from contract storage
pub fn storage_read_(key: &[u8]) -> Option<Vec<u8>> {
    unsafe {
        let result_ptr = host_storage_read(key.as_ptr() as i32, key.len() as i32);
        if result_ptr == 0 {
            None
        } else {
            // Read length and data from result pointer
            // Implementation would read from WASM memory
            Some(Vec::new())
        }
    }
}

/// Write to contract storage
pub fn storage_write_(key: &[u8], value: &[u8]) {
    unsafe {
        host_storage_write(
            key.as_ptr() as i32,
            key.len() as i32,
            value.as_ptr() as i32,
            value.len() as i32,
        );
    }
}

/// Remove from contract storage
pub fn storage_remove_(key: &[u8]) {
    unsafe {
        host_storage_remove(key.as_ptr() as i32, key.len() as i32);
    }
}

/// Compute Blake3 hash
pub fn blake3_(data: &[u8]) -> Hash {
    unsafe {
        let _result_ptr = host_blake3(data.as_ptr() as i32, data.len() as i32);
        // Read 32 bytes from result pointer
        Hash::ZERO
    }
}

/// Verify Ed25519 signature
pub fn ed25519_verify_(message: &[u8], signature: &[u8; 64], public_key: &[u8; 32]) -> bool {
    unsafe {
        host_ed25519_verify(
            message.as_ptr() as i32,
            message.len() as i32,
            signature.as_ptr() as i32,
            public_key.as_ptr() as i32,
        ) != 0
    }
}

/// Emit an event
pub fn emit_event<T: serde::Serialize>(event: &T) {
    if let Ok(data) = bincode::serialize(event) {
        unsafe {
            host_emit(0, data.as_ptr() as i32, data.len() as i32);
        }
    }
}

/// Log a message
pub fn log_(msg: &str) {
    let bytes = msg.as_bytes();
    unsafe {
        host_log(bytes.as_ptr() as i32, bytes.len() as i32);
    }
}

/// Transfer Koppa to an address
pub fn transfer_(to: Address, amount: Balance) -> bool {
    let amount_lo = amount as i64;
    let amount_hi = (amount >> 64) as i64;
    unsafe { host_transfer(to.as_bytes().as_ptr() as i32, amount_lo, amount_hi) != 0 }
}

/// Abort execution with an error message
pub fn abort(msg: &str) -> ! {
    let bytes = msg.as_bytes();
    unsafe {
        host_abort(bytes.as_ptr() as i32, bytes.len() as i32);
    }
    unreachable!()
}

// === Convenience re-exports with simpler names ===

pub use self::attached_value_ as value;
pub use self::block_height_ as height;
pub use self::block_timestamp_ as timestamp;
pub use self::caller_address as caller;
pub use self::chain_id_ as chain;
pub use self::origin_address as origin;
pub use self::self_address_ as self_addr;
pub use self::log_ as log;
pub use self::transfer_ as transfer;
