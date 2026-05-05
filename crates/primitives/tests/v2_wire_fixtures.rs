//! Wire-format fixture tests for SNIP V2 transaction payloads.
//!
//! Locks the bincode-serialized byte representation of every V2 tx payload
//! that SNIP signs. Any future change to enum variant order, struct field
//! order, struct field add/remove, or bincode config will break these
//! assertions in CI — catching schema drift before it hits validators or
//! SNIP clients.
//!
//! SNIP teams should pin against the same fixed inputs (FIXTURE_* constants
//! below) when generating their own tx-signing payloads. Any expected-bytes
//! change is a wire-format contract break and requires coordinated chain
//! and SNIP deployment.
//!
//! Run with `cargo test -p sumchain-primitives --test v2_wire_fixtures
//! -- --nocapture` to print the actual hex on failure.

use sumchain_primitives::{
    AccessEntryV2, Address, EncryptedKeyBundleV2, Hash, NodeRegistryOperationV2,
    NodeRegistryV2TxData, StorageMetadataOperationV2, StorageMetadataV2TxData,
};
use sumchain_primitives::transaction::TxPayload;

// ─── Fixed inputs (agreed cross-team) ───────────────────────────────────────

const FIXTURE_ENCRYPTION_PUBKEY: [u8; 32] = [0x11; 32];

fn fixture_merkle_root() -> Hash {
    Hash::new([0x42; 32])
}

fn fixture_chunk_indices() -> Vec<u32> {
    vec![1, 2, 3]
}

// ─── Helpers ────────────────────────────────────────────────────────────────

fn assert_bytes(label: &str, actual: &[u8], expected: &[u8]) {
    if actual != expected {
        panic!(
            "{label}: bincode wire bytes drifted\n  expected ({} B): {}\n  actual   ({} B): {}",
            expected.len(),
            hex::encode(expected),
            actual.len(),
            hex::encode(actual),
        );
    }
}

// ─── 1. NodeRegistryOperationV2::RegisterEncryptionKey ──────────────────────

#[test]
fn fixture_register_encryption_key_inner() {
    let op = NodeRegistryOperationV2::RegisterEncryptionKey {
        encryption_pubkey: FIXTURE_ENCRYPTION_PUBKEY,
    };
    let bytes = bincode::serialize(&op).unwrap();
    // Layout:
    //   [variant_tag u32 LE = 0][encryption_pubkey 32 B]
    let mut expected = Vec::with_capacity(4 + 32);
    expected.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
    expected.extend_from_slice(&FIXTURE_ENCRYPTION_PUBKEY);
    assert_bytes("RegisterEncryptionKey (inner)", &bytes, &expected);
}

#[test]
fn fixture_register_encryption_key_tx_payload() {
    let payload = TxPayload::NodeRegistryV2(NodeRegistryV2TxData {
        operation: NodeRegistryOperationV2::RegisterEncryptionKey {
            encryption_pubkey: FIXTURE_ENCRYPTION_PUBKEY,
        },
    });
    let bytes = bincode::serialize(&payload).unwrap();
    // Layout:
    //   [TxPayload tag u32 LE = 19][NodeRegistryV2TxData inner]
    //     inner is the same as `fixture_register_encryption_key_inner`.
    let mut expected = Vec::with_capacity(4 + 4 + 32);
    expected.extend_from_slice(&[0x13, 0x00, 0x00, 0x00]); // TxPayload variant 19
    expected.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // op variant 0
    expected.extend_from_slice(&FIXTURE_ENCRYPTION_PUBKEY);
    assert_bytes(
        "TxPayload::NodeRegistryV2(RegisterEncryptionKey)",
        &bytes,
        &expected,
    );
}

// ─── 2. StorageMetadataOperationV2::RegisterFilePendingV2 ───────────────────
// Fixture: Public file, no recipients, deterministic sizes.

fn fixture_register_file_pending_v2() -> StorageMetadataOperationV2 {
    StorageMetadataOperationV2::RegisterFilePendingV2 {
        merkle_root: fixture_merkle_root(),
        plaintext_size_bytes: 1024,
        stored_size_bytes: 1024,
        chunk_count: 3,
        fee_deposit: 100_000,
        visibility: 0, // Public
        initial_access: Vec::<AccessEntryV2>::new(),
    }
}

#[test]
fn fixture_register_file_pending_v2_inner() {
    let bytes = bincode::serialize(&fixture_register_file_pending_v2()).unwrap();
    // Layout:
    //   [variant_tag u32 LE = 0]
    //   [merkle_root 32 B]
    //   [plaintext_size_bytes u64 LE = 1024]
    //   [stored_size_bytes u64 LE = 1024]
    //   [chunk_count u32 LE = 3]
    //   [fee_deposit u64 LE = 100_000]
    //   [visibility u8 = 0]
    //   [initial_access Vec len u64 LE = 0]
    let mut expected = Vec::new();
    expected.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);          // variant 0
    expected.extend_from_slice(&[0x42; 32]);                         // merkle_root
    expected.extend_from_slice(&1024u64.to_le_bytes());              // plaintext_size_bytes
    expected.extend_from_slice(&1024u64.to_le_bytes());              // stored_size_bytes
    expected.extend_from_slice(&3u32.to_le_bytes());                 // chunk_count
    expected.extend_from_slice(&100_000u64.to_le_bytes());           // fee_deposit
    expected.push(0u8);                                              // visibility = Public
    expected.extend_from_slice(&0u64.to_le_bytes());                 // Vec len = 0
    assert_bytes("RegisterFilePendingV2 (inner)", &bytes, &expected);
}

#[test]
fn fixture_register_file_pending_v2_tx_payload() {
    let payload = TxPayload::StorageMetadataV2(StorageMetadataV2TxData {
        operation: fixture_register_file_pending_v2(),
    });
    let bytes = bincode::serialize(&payload).unwrap();
    // Same as inner with `[TxPayload tag = 20]` (0x14) prepended.
    let mut expected = Vec::new();
    expected.extend_from_slice(&[0x14, 0x00, 0x00, 0x00]); // TxPayload variant 20
    expected.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // op variant 0
    expected.extend_from_slice(&[0x42; 32]);
    expected.extend_from_slice(&1024u64.to_le_bytes());
    expected.extend_from_slice(&1024u64.to_le_bytes());
    expected.extend_from_slice(&3u32.to_le_bytes());
    expected.extend_from_slice(&100_000u64.to_le_bytes());
    expected.push(0u8);
    expected.extend_from_slice(&0u64.to_le_bytes());
    assert_bytes(
        "TxPayload::StorageMetadataV2(RegisterFilePendingV2)",
        &bytes,
        &expected,
    );
}

// ─── 3. StorageMetadataOperationV2::ActivateFileV2 ──────────────────────────

#[test]
fn fixture_activate_file_v2_inner() {
    let op = StorageMetadataOperationV2::ActivateFileV2 {
        merkle_root: fixture_merkle_root(),
    };
    let bytes = bincode::serialize(&op).unwrap();
    // Layout: [variant_tag u32 LE = 1][merkle_root 32 B]
    let mut expected = Vec::with_capacity(4 + 32);
    expected.extend_from_slice(&[0x01, 0x00, 0x00, 0x00]);
    expected.extend_from_slice(&[0x42; 32]);
    assert_bytes("ActivateFileV2 (inner)", &bytes, &expected);
}

#[test]
fn fixture_activate_file_v2_tx_payload() {
    let payload = TxPayload::StorageMetadataV2(StorageMetadataV2TxData {
        operation: StorageMetadataOperationV2::ActivateFileV2 {
            merkle_root: fixture_merkle_root(),
        },
    });
    let bytes = bincode::serialize(&payload).unwrap();
    let mut expected = Vec::with_capacity(4 + 4 + 32);
    expected.extend_from_slice(&[0x14, 0x00, 0x00, 0x00]); // TxPayload variant 20
    expected.extend_from_slice(&[0x01, 0x00, 0x00, 0x00]); // op variant 1
    expected.extend_from_slice(&[0x42; 32]);
    assert_bytes(
        "TxPayload::StorageMetadataV2(ActivateFileV2)",
        &bytes,
        &expected,
    );
}

// ─── 4. StorageMetadataOperationV2::AbandonFileV2 ───────────────────────────

#[test]
fn fixture_abandon_file_v2_inner() {
    let op = StorageMetadataOperationV2::AbandonFileV2 {
        merkle_root: fixture_merkle_root(),
    };
    let bytes = bincode::serialize(&op).unwrap();
    // Layout: [variant_tag u32 LE = 2][merkle_root 32 B]
    let mut expected = Vec::with_capacity(4 + 32);
    expected.extend_from_slice(&[0x02, 0x00, 0x00, 0x00]);
    expected.extend_from_slice(&[0x42; 32]);
    assert_bytes("AbandonFileV2 (inner)", &bytes, &expected);
}

#[test]
fn fixture_abandon_file_v2_tx_payload() {
    let payload = TxPayload::StorageMetadataV2(StorageMetadataV2TxData {
        operation: StorageMetadataOperationV2::AbandonFileV2 {
            merkle_root: fixture_merkle_root(),
        },
    });
    let bytes = bincode::serialize(&payload).unwrap();
    let mut expected = Vec::with_capacity(4 + 4 + 32);
    expected.extend_from_slice(&[0x14, 0x00, 0x00, 0x00]); // TxPayload variant 20
    expected.extend_from_slice(&[0x02, 0x00, 0x00, 0x00]); // op variant 2
    expected.extend_from_slice(&[0x42; 32]);
    assert_bytes(
        "TxPayload::StorageMetadataV2(AbandonFileV2)",
        &bytes,
        &expected,
    );
}

// ─── 5. StorageMetadataOperationV2::AcceptAssignmentV2 ──────────────────────

#[test]
fn fixture_accept_assignment_v2_inner() {
    let op = StorageMetadataOperationV2::AcceptAssignmentV2 {
        merkle_root: fixture_merkle_root(),
        chunk_indices: fixture_chunk_indices(),
    };
    let bytes = bincode::serialize(&op).unwrap();
    // Layout:
    //   [variant_tag u32 LE = 3]
    //   [merkle_root 32 B]
    //   [chunk_indices Vec len u64 LE = 3]
    //   [chunk_indices items: 1u32 LE, 2u32 LE, 3u32 LE]
    let mut expected = Vec::with_capacity(4 + 32 + 8 + 12);
    expected.extend_from_slice(&[0x03, 0x00, 0x00, 0x00]);
    expected.extend_from_slice(&[0x42; 32]);
    expected.extend_from_slice(&3u64.to_le_bytes());
    expected.extend_from_slice(&1u32.to_le_bytes());
    expected.extend_from_slice(&2u32.to_le_bytes());
    expected.extend_from_slice(&3u32.to_le_bytes());
    assert_bytes("AcceptAssignmentV2 (inner)", &bytes, &expected);
}

#[test]
fn fixture_accept_assignment_v2_tx_payload() {
    let payload = TxPayload::StorageMetadataV2(StorageMetadataV2TxData {
        operation: StorageMetadataOperationV2::AcceptAssignmentV2 {
            merkle_root: fixture_merkle_root(),
            chunk_indices: fixture_chunk_indices(),
        },
    });
    let bytes = bincode::serialize(&payload).unwrap();
    let mut expected = Vec::with_capacity(4 + 4 + 32 + 8 + 12);
    expected.extend_from_slice(&[0x14, 0x00, 0x00, 0x00]); // TxPayload variant 20
    expected.extend_from_slice(&[0x03, 0x00, 0x00, 0x00]); // op variant 3
    expected.extend_from_slice(&[0x42; 32]);
    expected.extend_from_slice(&3u64.to_le_bytes());
    expected.extend_from_slice(&1u32.to_le_bytes());
    expected.extend_from_slice(&2u32.to_le_bytes());
    expected.extend_from_slice(&3u32.to_le_bytes());
    assert_bytes(
        "TxPayload::StorageMetadataV2(AcceptAssignmentV2)",
        &bytes,
        &expected,
    );
}

// ─── 6. StorageMetadataOperationV2::AddAccessV2 ─────────────────────────────
// Two fixtures: Public-style (no bundle, no expiry) and Private-style
// (full 80-byte bundle + expiry). Both are wire-valid; executor validity
// rules are independent and live in the state crate.

const FIXTURE_RECIPIENT_ADDR: [u8; 20] = [0x33; 20];
const FIXTURE_BUNDLE: [u8; 80] = [0x55; 80];
const FIXTURE_EXPIRES_AT: u64 = 2_000;

fn fixture_access_entry_public() -> AccessEntryV2 {
    AccessEntryV2 {
        address: Address::new(FIXTURE_RECIPIENT_ADDR),
        encrypted_key_bundle: None,
        expires_at: None,
    }
}

fn fixture_access_entry_private() -> AccessEntryV2 {
    AccessEntryV2 {
        address: Address::new(FIXTURE_RECIPIENT_ADDR),
        encrypted_key_bundle: Some(EncryptedKeyBundleV2(FIXTURE_BUNDLE)),
        expires_at: Some(FIXTURE_EXPIRES_AT),
    }
}

#[test]
fn fixture_add_access_v2_inner_public_entry() {
    let op = StorageMetadataOperationV2::AddAccessV2 {
        merkle_root: fixture_merkle_root(),
        entry: fixture_access_entry_public(),
    };
    let bytes = bincode::serialize(&op).unwrap();
    // Layout:
    //   [variant_tag u32 LE = 4]
    //   [merkle_root 32 B]
    //   [entry.address 20 B]
    //   [entry.encrypted_key_bundle Option tag u8 = 0 (None)]
    //   [entry.expires_at Option tag u8 = 0 (None)]
    let mut expected = Vec::new();
    expected.extend_from_slice(&[0x04, 0x00, 0x00, 0x00]);
    expected.extend_from_slice(&[0x42; 32]);
    expected.extend_from_slice(&FIXTURE_RECIPIENT_ADDR);
    expected.push(0x00);
    expected.push(0x00);
    assert_bytes("AddAccessV2 (inner, public-style entry)", &bytes, &expected);
}

#[test]
fn fixture_add_access_v2_inner_private_entry() {
    let op = StorageMetadataOperationV2::AddAccessV2 {
        merkle_root: fixture_merkle_root(),
        entry: fixture_access_entry_private(),
    };
    let bytes = bincode::serialize(&op).unwrap();
    // Layout:
    //   [variant_tag u32 LE = 4]
    //   [merkle_root 32 B]
    //   [entry.address 20 B]
    //   [entry.encrypted_key_bundle Option tag u8 = 1 (Some)][bundle 80 B]
    //   [entry.expires_at Option tag u8 = 1 (Some)][expires_at u64 LE]
    let mut expected = Vec::new();
    expected.extend_from_slice(&[0x04, 0x00, 0x00, 0x00]);
    expected.extend_from_slice(&[0x42; 32]);
    expected.extend_from_slice(&FIXTURE_RECIPIENT_ADDR);
    expected.push(0x01);
    expected.extend_from_slice(&FIXTURE_BUNDLE);
    expected.push(0x01);
    expected.extend_from_slice(&FIXTURE_EXPIRES_AT.to_le_bytes());
    assert_bytes("AddAccessV2 (inner, private-style entry)", &bytes, &expected);
}

#[test]
fn fixture_add_access_v2_tx_payload_private_entry() {
    let payload = TxPayload::StorageMetadataV2(StorageMetadataV2TxData {
        operation: StorageMetadataOperationV2::AddAccessV2 {
            merkle_root: fixture_merkle_root(),
            entry: fixture_access_entry_private(),
        },
    });
    let bytes = bincode::serialize(&payload).unwrap();
    let mut expected = Vec::new();
    expected.extend_from_slice(&[0x14, 0x00, 0x00, 0x00]); // TxPayload variant 20
    expected.extend_from_slice(&[0x04, 0x00, 0x00, 0x00]); // op variant 4
    expected.extend_from_slice(&[0x42; 32]);
    expected.extend_from_slice(&FIXTURE_RECIPIENT_ADDR);
    expected.push(0x01);
    expected.extend_from_slice(&FIXTURE_BUNDLE);
    expected.push(0x01);
    expected.extend_from_slice(&FIXTURE_EXPIRES_AT.to_le_bytes());
    assert_bytes(
        "TxPayload::StorageMetadataV2(AddAccessV2 private)",
        &bytes,
        &expected,
    );
}

// ─── 7. StorageMetadataOperationV2::RemoveAccessV2 ──────────────────────────

#[test]
fn fixture_remove_access_v2_inner() {
    let op = StorageMetadataOperationV2::RemoveAccessV2 {
        merkle_root: fixture_merkle_root(),
        address: Address::new(FIXTURE_RECIPIENT_ADDR),
    };
    let bytes = bincode::serialize(&op).unwrap();
    // Layout: [variant_tag u32 LE = 5][merkle_root 32 B][address 20 B]
    let mut expected = Vec::with_capacity(4 + 32 + 20);
    expected.extend_from_slice(&[0x05, 0x00, 0x00, 0x00]);
    expected.extend_from_slice(&[0x42; 32]);
    expected.extend_from_slice(&FIXTURE_RECIPIENT_ADDR);
    assert_bytes("RemoveAccessV2 (inner)", &bytes, &expected);
}

#[test]
fn fixture_remove_access_v2_tx_payload() {
    let payload = TxPayload::StorageMetadataV2(StorageMetadataV2TxData {
        operation: StorageMetadataOperationV2::RemoveAccessV2 {
            merkle_root: fixture_merkle_root(),
            address: Address::new(FIXTURE_RECIPIENT_ADDR),
        },
    });
    let bytes = bincode::serialize(&payload).unwrap();
    let mut expected = Vec::with_capacity(4 + 4 + 32 + 20);
    expected.extend_from_slice(&[0x14, 0x00, 0x00, 0x00]);
    expected.extend_from_slice(&[0x05, 0x00, 0x00, 0x00]);
    expected.extend_from_slice(&[0x42; 32]);
    expected.extend_from_slice(&FIXTURE_RECIPIENT_ADDR);
    assert_bytes(
        "TxPayload::StorageMetadataV2(RemoveAccessV2)",
        &bytes,
        &expected,
    );
}

// ─── 8. StorageMetadataOperationV2::UpdateAccessV2 ──────────────────────────

#[test]
fn fixture_update_access_v2_inner() {
    let op = StorageMetadataOperationV2::UpdateAccessV2 {
        merkle_root: fixture_merkle_root(),
        address: Address::new(FIXTURE_RECIPIENT_ADDR),
        new_entry: fixture_access_entry_private(),
    };
    let bytes = bincode::serialize(&op).unwrap();
    // Layout:
    //   [variant_tag u32 LE = 6]
    //   [merkle_root 32 B]
    //   [address 20 B]
    //   [new_entry: AccessEntryV2 — same shape as AddAccessV2's entry]
    let mut expected = Vec::new();
    expected.extend_from_slice(&[0x06, 0x00, 0x00, 0x00]);
    expected.extend_from_slice(&[0x42; 32]);
    expected.extend_from_slice(&FIXTURE_RECIPIENT_ADDR);
    expected.extend_from_slice(&FIXTURE_RECIPIENT_ADDR);
    expected.push(0x01);
    expected.extend_from_slice(&FIXTURE_BUNDLE);
    expected.push(0x01);
    expected.extend_from_slice(&FIXTURE_EXPIRES_AT.to_le_bytes());
    assert_bytes("UpdateAccessV2 (inner)", &bytes, &expected);
}

#[test]
fn fixture_update_access_v2_tx_payload() {
    let payload = TxPayload::StorageMetadataV2(StorageMetadataV2TxData {
        operation: StorageMetadataOperationV2::UpdateAccessV2 {
            merkle_root: fixture_merkle_root(),
            address: Address::new(FIXTURE_RECIPIENT_ADDR),
            new_entry: fixture_access_entry_private(),
        },
    });
    let bytes = bincode::serialize(&payload).unwrap();
    let mut expected = Vec::new();
    expected.extend_from_slice(&[0x14, 0x00, 0x00, 0x00]);
    expected.extend_from_slice(&[0x06, 0x00, 0x00, 0x00]);
    expected.extend_from_slice(&[0x42; 32]);
    expected.extend_from_slice(&FIXTURE_RECIPIENT_ADDR);
    expected.extend_from_slice(&FIXTURE_RECIPIENT_ADDR);
    expected.push(0x01);
    expected.extend_from_slice(&FIXTURE_BUNDLE);
    expected.push(0x01);
    expected.extend_from_slice(&FIXTURE_EXPIRES_AT.to_le_bytes());
    assert_bytes(
        "TxPayload::StorageMetadataV2(UpdateAccessV2)",
        &bytes,
        &expected,
    );
}

// ─── Cross-check: TxPayload variant indices match doc ───────────────────────
// Belt-and-suspenders test that catches a TxPayload reorder even if the
// per-variant fixtures above are accidentally regenerated.

#[test]
fn tx_payload_v2_variant_indices_locked() {
    // NodeRegistryV2 must be variant 19, StorageMetadataV2 must be variant 20.
    let nrv2 = TxPayload::NodeRegistryV2(NodeRegistryV2TxData {
        operation: NodeRegistryOperationV2::RegisterEncryptionKey {
            encryption_pubkey: [0u8; 32],
        },
    });
    let smv2 = TxPayload::StorageMetadataV2(StorageMetadataV2TxData {
        operation: StorageMetadataOperationV2::ActivateFileV2 {
            merkle_root: Hash::new([0u8; 32]),
        },
    });
    let nrv2_bytes = bincode::serialize(&nrv2).unwrap();
    let smv2_bytes = bincode::serialize(&smv2).unwrap();
    assert_eq!(
        &nrv2_bytes[..4],
        &19u32.to_le_bytes(),
        "TxPayload::NodeRegistryV2 must be variant 19"
    );
    assert_eq!(
        &smv2_bytes[..4],
        &20u32.to_le_bytes(),
        "TxPayload::StorageMetadataV2 must be variant 20"
    );
    // Suppress unused warning; Address import lives here for completeness so
    // SNIP can copy this file as-is.
    let _ = Address::new([0u8; 20]);
}
