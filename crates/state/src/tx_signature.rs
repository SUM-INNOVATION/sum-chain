//! Which Ed25519 rule a transaction's signature is checked under.
//!
//! Below `ChainParams::strict_transaction_signatures_enabled_from_height`, or
//! while it is unset, a transaction's signature is checked with
//! [`sumchain_crypto::verify_bytes`], exactly as every block executed before
//! the gate existed was checked. At and above it, the same check uses
//! [`sumchain_crypto::verify_bytes_strict`] (`VerifyingKey::verify_strict`, the
//! verifier the ratified E1 path already uses: canonical encodings, no
//! small-order components), for every transaction.
//!
//! The selection is made here, by height, and nowhere else. The legacy helper
//! itself is unchanged and keeps every other caller, so nothing that replays a
//! block below the gate can read a different verdict.
//!
//! Signatures carried inside a transaction's payload are not the transaction's
//! own signature and are outside this gate.

use sumchain_crypto::{verify_bytes, verify_bytes_strict, Result};
use sumchain_genesis::ChainParams;

/// `ChainParams::strict_transaction_signatures_enabled_from_height`.
fn strict_signatures_activation(params: &ChainParams) -> Option<u64> {
    params.strict_transaction_signatures_enabled_from_height
}

/// Whether a transaction in a block at `block_height` is checked with the
/// strict rule.
pub fn strict_transaction_signatures_gate_open(params: &ChainParams, block_height: u64) -> bool {
    matches!(strict_signatures_activation(params), Some(h) if block_height >= h)
}

/// Check a transaction's signature over `signing_hash` under the rule that
/// applies at `block_height`.
///
/// `block_height` is the height of the block the transaction is executed in.
/// Mempool admission passes the height the transaction would be included at,
/// the next block's.
pub fn verify_transaction_signature(
    params: &ChainParams,
    block_height: u64,
    signing_hash: &[u8],
    signature: &[u8; 64],
    public_key: &[u8; 32],
) -> Result<()> {
    if strict_transaction_signatures_gate_open(params, block_height) {
        verify_bytes_strict(signing_hash, signature, public_key)
    } else {
        verify_bytes(signing_hash, signature, public_key)
    }
}
