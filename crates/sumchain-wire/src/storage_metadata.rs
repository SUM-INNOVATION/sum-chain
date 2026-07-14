//! Storage Metadata types for SUM Chain.
//!
//! Defines on-chain data structures for decentralized file storage metadata,
//! including file identity (Blake3 Merkle root), access control lists,
//! fee pools for storage-node payouts, and Proof-of-Retrievability challenges.

use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;

use crate::{Address, Hash};

// ─── PoR Constants ───────────────────────────────────────────────────────────

/// Chunk size for PoR challenges: 1 MB
pub const CHUNK_SIZE: u64 = 1_048_576;

/// How many blocks an ArchiveNode has to respond to a challenge
pub const CHALLENGE_TTL_BLOCKS: u64 = 50;

/// Issue a new challenge every N blocks
pub const CHALLENGE_INTERVAL_BLOCKS: u64 = 100;

/// Reward per valid proof: 10 Koppa (in base units)
pub const CHALLENGE_REWARD: u64 = 10_000_000_000;

/// Percentage of staked balance slashed on expired challenge
pub const SLASH_PERCENTAGE: u64 = 5;

// ─── File Metadata ───────────────────────────────────────────────────────────

/// On-chain metadata for a stored file
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StorageMetadata {
    /// Blake3 Merkle root of the file's content tree
    pub merkle_root: Hash,
    /// Owner/uploader who controls the file
    pub owner: Address,
    /// Total file size in bytes
    pub total_size_bytes: u64,
    /// Native ACL — addresses allowed to retrieve the file
    pub access_list: Vec<Address>,
    /// Locked Koppa (base units) reserved for storage-node payouts
    pub fee_pool: u64,
    /// Block height at which the metadata was created
    pub created_at: u64,
}

// ─── PoR Challenge ───────────────────────────────────────────────────────────

/// An open cryptographic challenge issued by the L1 to an ArchiveNode.
/// The node must submit a valid Merkle proof before `expires_at_height`
/// or face slashing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StorageChallenge {
    /// Deterministic ID: Blake3(merkle_root ++ chunk_index ++ created_at_height)
    pub challenge_id: Hash,
    /// Which file is being challenged
    pub merkle_root: Hash,
    /// Which 1 MB chunk to prove (0-indexed)
    pub chunk_index: u32,
    /// Which ArchiveNode must respond
    pub target_node: Address,
    /// Block height the challenge was issued
    pub created_at_height: u64,
    /// Deadline: must respond before this height
    pub expires_at_height: u64,
}

// ─── Operations ──────────────────────────────────────────────────────────────

/// Operations on storage metadata
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum StorageMetadataOperation {
    /// Register a new file's metadata and lock a fee deposit
    RegisterFile {
        merkle_root: Hash,
        total_size_bytes: u64,
        access_list: Vec<Address>,
        fee_deposit: u64,
    },
    /// Replace the entire access list (owner only)
    UpdateAccessList {
        merkle_root: Hash,
        new_access_list: Vec<Address>,
    },
    /// Append a single address to the access list (owner only)
    AddAccess {
        merkle_root: Hash,
        address: Address,
    },
    /// Remove a single address from the access list (owner only)
    RemoveAccess {
        merkle_root: Hash,
        address: Address,
    },
    /// Top up the fee pool for a file (anyone can do this)
    TopUpFeePool {
        merkle_root: Hash,
        amount: u64,
    },
    /// Submit a Merkle proof for a storage challenge (ArchiveNode only)
    SubmitStorageProof {
        /// The challenge being responded to
        challenge_id: Hash,
        /// File merkle root (must match challenge)
        merkle_root: Hash,
        /// Chunk index (must match challenge)
        chunk_index: u32,
        /// Blake3 hash of the raw chunk data
        chunk_hash: Hash,
        /// Merkle path from chunk leaf to root (sibling hashes, bottom-up)
        merkle_path: Vec<Hash>,
    },
}

/// Transaction data for storage metadata operations
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StorageMetadataTxData {
    pub operation: StorageMetadataOperation,
}

// ─── V2 Schema ───────────────────────────────────────────────────────────────
//
// Plan v3.1 §3.1–3.5. Additive over V1: new enum variants, new row shape,
// new storage CF, new TxPayload variant. V1 stays untouched.
//
// Phase 1 checkpoint 1a defines the full V2 enum and implements
// `RegisterFilePendingV2` + `AbandonFileV2`. Other variants are present in
// the enum but their executor branches are stubbed in checkpoint 1a and will
// be implemented in 1b/1c.

/// Encrypted-key-bundle wrapper. Newtype so that `Option<EncryptedKeyBundleV2>`
/// can derive serde — serde won't auto-derive `Serialize`/`Deserialize` for
/// `Option<[u8; N]>` when `N > 32`. Wire layout is identical to a bare 80-byte
/// array (BigArray serializes as a flat byte sequence).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedKeyBundleV2(#[serde(with = "BigArray")] pub [u8; 80]);

/// Per-recipient access entry for a Private V2 file (or a public ACL entry
/// when bundles are absent). Plan §3.1.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccessEntryV2 {
    pub address: Address,
    /// Encrypted file-key bundle for this recipient. `Some(80 bytes)` for
    /// Private files; `None` for Public files.
    pub encrypted_key_bundle: Option<EncryptedKeyBundleV2>,
    /// Optional access expiry (block height). `None` = never expires.
    pub expires_at: Option<u64>,
}

/// File lifecycle state. `Rotated = 3` is reserved for Ask 10 (file rotation)
/// future work and intentionally not present in v1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum FileLifecycleV2 {
    Pending = 0,
    Active = 1,
    Abandoned = 2,
}

impl FileLifecycleV2 {
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            0 => Some(Self::Pending),
            1 => Some(Self::Active),
            2 => Some(Self::Abandoned),
            _ => None,
        }
    }
}

/// File visibility. Determines whether `access_list` entries must carry
/// encrypted bundles (Private) or must not (Public). Plan §3.5.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum FileVisibilityV2 {
    Public = 0,
    Private = 1,
}

impl FileVisibilityV2 {
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            0 => Some(Self::Public),
            1 => Some(Self::Private),
            _ => None,
        }
    }
}

/// V2 storage operations. Additive — V1 `StorageMetadataOperation` unchanged.
/// Plan §3.1, §3.6 (AcceptAssignmentV2 added at v3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum StorageMetadataOperationV2 {
    /// Register a file in the Pending state. Locks `fee_deposit` into
    /// `fee_pool`, captures the active-archive snapshot at this block height,
    /// and stages the file for owner-driven push fanout.
    /// Plan §3.5 RegisterFilePendingV2.
    RegisterFilePendingV2 {
        merkle_root: Hash,
        plaintext_size_bytes: u64,
        stored_size_bytes: u64,
        chunk_count: u32,
        fee_deposit: u64,
        /// 0 = Public, 1 = Private. Validation in the executor decodes via
        /// `FileVisibilityV2::from_byte` and rejects other values.
        visibility: u8,
        initial_access: Vec<AccessEntryV2>,
    },
    /// Transition a file from Pending → Active. Validity precondition lives
    /// in checkpoint 1b (every chunk index must have an `AcceptAssignmentV2`).
    ActivateFileV2 {
        merkle_root: Hash,
    },
    /// Refund deposit (minus `abandonment_fee_percent`) for a Pending file
    /// that the owner can't activate. Anti-grief: only valid after
    /// `created_at + activation_grace_blocks`. Plan §3.5 AbandonFileV2.
    AbandonFileV2 {
        merkle_root: Hash,
    },
    /// Per-archive attestation that this archive has received and stored the
    /// listed chunks. Required before `ActivateFileV2`. Implemented in 1b.
    AcceptAssignmentV2 {
        merkle_root: Hash,
        chunk_indices: Vec<u32>,
    },
    /// Add one access entry to an Active file's access list. Implemented in 1c.
    AddAccessV2 {
        merkle_root: Hash,
        entry: AccessEntryV2,
    },
    /// Remove one access entry from an Active file's access list. Implemented in 1c.
    RemoveAccessV2 {
        merkle_root: Hash,
        address: Address,
    },
    /// Replace one access entry's bundle/expiry on an Active file (rotation).
    /// Implemented in 1c.
    UpdateAccessV2 {
        merkle_root: Hash,
        address: Address,
        new_entry: AccessEntryV2,
    },
    /// Archive-node chunk reassignment (issue #62). Owner-triggered: advance the
    /// file's assignment epoch to the current block's active-archive snapshot so
    /// replacement archives can be assigned and attest, when an
    /// originally-assigned archive has left the active set (exit/slash/unbond).
    ///
    /// Appended after `UpdateAccessV2` so existing bincode variant indices are
    /// unchanged. The whole file advances one epoch (per-file, not per-chunk);
    /// the executor stamps the current block height. Gated by
    /// `ChainParams::archive_reassignment_enabled_from_height`. See
    /// [docs/specs/SNIP-V2-CHAIN-PLAN.md](../../../docs/specs/SNIP-V2-CHAIN-PLAN.md) §5.4.
    ReassignChunksV2 {
        merkle_root: Hash,
    },
}

/// Transaction data wrapper for V2 storage operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StorageMetadataV2TxData {
    pub operation: StorageMetadataOperationV2,
}

// ─── V2 Assignment Function (Plan v3.2 §3.6) ─────────────────────────────────

/// Domain-separation context for the V2 chunk-assignment KDF.
/// Exact 37-byte ASCII string; do NOT change without bumping the protocol
/// version, since SNIP clients reproduce this byte-for-byte.
pub const SNIP_V2_ASSIGNMENT_CONTEXT: &str = "sumchain SNIP-V2 chunk-assignment v1";

/// Compute the rendezvous-hash assignment for a single chunk.
///
/// Returns the `min(R, snapshot.len())` archive addresses with the smallest
/// BLAKE3-derived score for `(merkle_root, chunk_index)`. Output is sorted
/// ascending by `(score, address)`.
///
/// The snapshot is sorted-and-deduped by ascending byte-order address before
/// scoring, so callers may pass any order. This function is the single source
/// of truth shared by the executor (`AcceptAssignmentV2` validity check),
/// the `storage_getAssignmentCoverageV2` RPC, and SNIP client push logic;
/// all three must agree byte-for-byte.
///
/// Conformance vectors are defined in plan v3.2 Appendix C and locked by
/// tests in this module.
pub fn assigned_archives(
    merkle_root: &Hash,
    snapshot_addresses: &[Address],
    chunk_index: u32,
    replication_factor: u32,
) -> Vec<Address> {
    // Sort + dedup by ascending byte order. Spec mandates this so any caller
    // (executor, RPC, SNIP client) producing the same input snapshot computes
    // the same output regardless of input ordering.
    let mut addrs: Vec<Address> = snapshot_addresses.to_vec();
    addrs.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
    addrs.dedup_by(|a, b| a.as_bytes() == b.as_bytes());

    let r_eff = (replication_factor as usize).min(addrs.len());
    if r_eff == 0 {
        return Vec::new();
    }

    // Score each archive. Build the 56-byte input (32 root + 4 chunk_index_be + 20 addr)
    // exactly as specified in §3.6 — order matters for SNIP client conformance.
    let mut scored: Vec<(u64, Address)> = Vec::with_capacity(addrs.len());
    let chunk_be = chunk_index.to_be_bytes();
    for a in &addrs {
        let mut input = [0u8; 56];
        input[..32].copy_from_slice(merkle_root.as_bytes());
        input[32..36].copy_from_slice(&chunk_be);
        input[36..56].copy_from_slice(a.as_bytes());
        let derived = blake3::derive_key(SNIP_V2_ASSIGNMENT_CONTEXT, &input);
        let score = u64::from_be_bytes(derived[..8].try_into().expect("8-byte slice"));
        scored.push((score, *a));
    }

    // Sort ascending by (score, address). The address tie-break makes the
    // ordering total even in the (negligible) event of a 1-in-2^64 score collision.
    scored.sort_by(|x, y| {
        x.0.cmp(&y.0)
            .then_with(|| x.1.as_bytes().cmp(y.1.as_bytes()))
    });

    scored.into_iter().take(r_eff).map(|(_, a)| a).collect()
}

/// Like [`assigned_archives`] but takes a snapshot that the caller has
/// already sorted and deduped (ascending byte order). Used by the coverage
/// RPC and other batch callers that iterate the assignment over many chunks
/// — calling [`assigned_archives`] in a loop re-sorts the snapshot every
/// iteration, which dominates runtime for large `chunk_count`. This variant
/// shifts that cost out of the hot loop.
///
/// Output is byte-identical to [`assigned_archives`] for the same input
/// snapshot, regardless of how the caller obtained the sort. **Caller
/// responsibility:** pass an already-sorted+deduped slice; this function
/// does NOT re-sort, so an out-of-order input produces wrong assignments.
pub fn assigned_archives_presorted(
    merkle_root: &Hash,
    sorted_addresses: &[Address],
    chunk_index: u32,
    replication_factor: u32,
) -> Vec<Address> {
    let r_eff = (replication_factor as usize).min(sorted_addresses.len());
    if r_eff == 0 {
        return Vec::new();
    }
    let mut scored: Vec<(u64, Address)> = Vec::with_capacity(sorted_addresses.len());
    let chunk_be = chunk_index.to_be_bytes();
    for a in sorted_addresses {
        let mut input = [0u8; 56];
        input[..32].copy_from_slice(merkle_root.as_bytes());
        input[32..36].copy_from_slice(&chunk_be);
        input[36..56].copy_from_slice(a.as_bytes());
        let derived = blake3::derive_key(SNIP_V2_ASSIGNMENT_CONTEXT, &input);
        let score = u64::from_be_bytes(derived[..8].try_into().expect("8-byte slice"));
        scored.push((score, *a));
    }
    scored.sort_by(|x, y| {
        x.0.cmp(&y.0)
            .then_with(|| x.1.as_bytes().cmp(y.1.as_bytes()))
    });
    scored.into_iter().take(r_eff).map(|(_, a)| a).collect()
}

/// Convenience: is `archive` in the assigned set for `(merkle_root, chunk_index)`?
/// Equivalent to `assigned_archives(...).contains(&archive)` but documents intent.
pub fn is_archive_assigned_to_chunk(
    merkle_root: &Hash,
    snapshot_addresses: &[Address],
    chunk_index: u32,
    replication_factor: u32,
    archive: &Address,
) -> bool {
    assigned_archives(merkle_root, snapshot_addresses, chunk_index, replication_factor)
        .iter()
        .any(|a| a.as_bytes() == archive.as_bytes())
}

// ─── V2 Assignment Function — Appendix C conformance tests ───────────────────
#[cfg(test)]
mod assignment_tests {
    use super::*;

    /// Construct the Appendix C archive set deterministically.
    /// archive[j] = blake3::hash("snip-v2-archive-{j+1}").as_bytes()[..20]
    fn fixture_archives() -> [Address; 5] {
        let mut out = [Address::new([0u8; 20]); 5];
        for (j, slot) in out.iter_mut().enumerate() {
            let label = format!("snip-v2-archive-{}", j + 1);
            let h = blake3::hash(label.as_bytes());
            *slot = Address::from_slice(&h.as_bytes()[..20]).expect("20 bytes");
        }
        out
    }

    /// Construct the Appendix C merkle-root set deterministically.
    /// merkle_root[i] = blake3::hash("snip-v2-test-file-{i+1}").as_bytes()
    fn fixture_root(i: usize) -> Hash {
        let label = format!("snip-v2-test-file-{}", i + 1);
        let h = blake3::hash(label.as_bytes());
        Hash::from_slice(h.as_bytes()).expect("32 bytes")
    }

    /// Lock fixture-derivation against drift — if blake3 hashing of the
    /// construction strings ever produces different bytes, every Appendix C
    /// entry below shifts. Catches that early with a single assertion.
    #[test]
    fn appendix_c_fixture_construction_matches() {
        let roots = [fixture_root(0), fixture_root(1), fixture_root(2)];
        let archives = fixture_archives();

        let expected_roots = [
            "a5e2668f5022b62b5e4a1342aa0cfbfcbde2af2e3626b2fd57d6cf44e8f615a4",
            "eed453d08260268bbd3675997f407174d901d842711f3addb6a2e05f776bccce",
            "81137f39ea2a36bae5333d021052c44c0fc4763769c9988241e6669af16dfa74",
        ];
        for (i, h) in expected_roots.iter().enumerate() {
            assert_eq!(hex::encode(roots[i].as_bytes()), *h, "merkle_root[{}]", i);
        }
        let expected_archives = [
            "37c4401960bd5a26d8ed7b676b1ef47c78fac5bb",
            "f1a469857483cc381865df996b2cccd254878a16",
            "8c6a62e786d02ae255a6f481580b95fe05bafffc",
            "f8967230e6a6d6b5b4ce6816d43f406f24d3cdad",
            "7e65c99f5b3994f2014187f24ee9230a027526bd",
        ];
        for (j, h) in expected_archives.iter().enumerate() {
            assert_eq!(hex::encode(archives[j].as_bytes()), *h, "archive[{}]", j);
        }
    }

    /// Plan v3.2 Appendix C — per-archive scores for (merkle_root[0], chunk_index=0).
    /// Catches drift in the BLAKE3 derive_key call shape (context string, byte
    /// order, the keyed_hash-vs-derive_key mistake the plan warns about).
    #[test]
    fn appendix_c_scores_for_root0_chunk0() {
        let root = fixture_root(0);
        let archives = fixture_archives();
        let chunk_be = 0u32.to_be_bytes();

        // Each entry: (archive, expected score as BE u64).
        let cases: [(Address, u64); 5] = [
            (archives[4], 0x4cd8130d5f5c7f55),
            (archives[2], 0x73e9ad5ef9a6ba04),
            (archives[1], 0xc8859dade38f7649),
            (archives[3], 0xd2823bf6a2d883bb),
            (archives[0], 0xf3c350979cb3f293),
        ];

        for (archive, expected_score) in cases.iter() {
            let mut input = [0u8; 56];
            input[..32].copy_from_slice(root.as_bytes());
            input[32..36].copy_from_slice(&chunk_be);
            input[36..56].copy_from_slice(archive.as_bytes());
            let derived = blake3::derive_key(SNIP_V2_ASSIGNMENT_CONTEXT, &input);
            let score = u64::from_be_bytes(derived[..8].try_into().unwrap());
            assert_eq!(
                score,
                *expected_score,
                "score mismatch for archive {} — most likely cause: wrong context string \
                 (\"{}\" expected) or keyed_hash-vs-derive_key drift",
                hex::encode(archive.as_bytes()),
                SNIP_V2_ASSIGNMENT_CONTEXT,
            );
        }
    }

    /// Plan v3.2 Appendix C — assignment outputs for the seven listed cases.
    /// Each row exercises a different aspect of the function.
    #[test]
    fn appendix_c_assignment_outputs() {
        let snapshot = fixture_archives().to_vec();
        let r0 = fixture_root(0);
        let r1 = fixture_root(1);
        let r2 = fixture_root(2);

        // (merkle_root, chunk_index, R, expected output)
        struct Case<'a> {
            root: &'a Hash,
            chunk_index: u32,
            r: u32,
            expected_hex: &'a [&'a str],
        }
        let cases = [
            Case { root: &r0, chunk_index: 0, r: 1, expected_hex: &[
                "7e65c99f5b3994f2014187f24ee9230a027526bd",
            ]},
            Case { root: &r0, chunk_index: 0, r: 3, expected_hex: &[
                "7e65c99f5b3994f2014187f24ee9230a027526bd",
                "8c6a62e786d02ae255a6f481580b95fe05bafffc",
                "f1a469857483cc381865df996b2cccd254878a16",
            ]},
            Case { root: &r0, chunk_index: 7, r: 3, expected_hex: &[
                "f8967230e6a6d6b5b4ce6816d43f406f24d3cdad",
                "37c4401960bd5a26d8ed7b676b1ef47c78fac5bb",
                "7e65c99f5b3994f2014187f24ee9230a027526bd",
            ]},
            Case { root: &r1, chunk_index: 0, r: 3, expected_hex: &[
                "f1a469857483cc381865df996b2cccd254878a16",
                "8c6a62e786d02ae255a6f481580b95fe05bafffc",
                "37c4401960bd5a26d8ed7b676b1ef47c78fac5bb",
            ]},
            Case { root: &r1, chunk_index: 1, r: 3, expected_hex: &[
                "7e65c99f5b3994f2014187f24ee9230a027526bd",
                "8c6a62e786d02ae255a6f481580b95fe05bafffc",
                "f8967230e6a6d6b5b4ce6816d43f406f24d3cdad",
            ]},
            Case { root: &r2, chunk_index: 42, r: 3, expected_hex: &[
                "f1a469857483cc381865df996b2cccd254878a16",
                "8c6a62e786d02ae255a6f481580b95fe05bafffc",
                "f8967230e6a6d6b5b4ce6816d43f406f24d3cdad",
            ]},
            // R = 5 — full set
            Case { root: &r2, chunk_index: 42, r: 5, expected_hex: &[
                "f1a469857483cc381865df996b2cccd254878a16",
                "8c6a62e786d02ae255a6f481580b95fe05bafffc",
                "f8967230e6a6d6b5b4ce6816d43f406f24d3cdad",
                "37c4401960bd5a26d8ed7b676b1ef47c78fac5bb",
                "7e65c99f5b3994f2014187f24ee9230a027526bd",
            ]},
            // R = 7 — clamps to snapshot.len() = 5
            Case { root: &r2, chunk_index: 42, r: 7, expected_hex: &[
                "f1a469857483cc381865df996b2cccd254878a16",
                "8c6a62e786d02ae255a6f481580b95fe05bafffc",
                "f8967230e6a6d6b5b4ce6816d43f406f24d3cdad",
                "37c4401960bd5a26d8ed7b676b1ef47c78fac5bb",
                "7e65c99f5b3994f2014187f24ee9230a027526bd",
            ]},
        ];

        for c in &cases {
            let got = assigned_archives(c.root, &snapshot, c.chunk_index, c.r);
            let got_hex: Vec<String> =
                got.iter().map(|a| hex::encode(a.as_bytes())).collect();
            let want_hex: Vec<String> = c.expected_hex.iter().map(|s| s.to_string()).collect();
            assert_eq!(
                got_hex, want_hex,
                "case (root={}, chunk_index={}, R={}) — assignment drift",
                hex::encode(c.root.as_bytes()),
                c.chunk_index,
                c.r,
            );
        }
    }

    /// Snapshot order independence — feeding the same archives in any
    /// permutation must produce the same output (the function sort-and-dedups
    /// internally per spec).
    #[test]
    fn assigned_archives_is_snapshot_order_independent() {
        let mut snap_a = fixture_archives().to_vec();
        let mut snap_b = snap_a.clone();
        snap_b.reverse();
        let snap_c = vec![snap_a[2], snap_a[0], snap_a[4], snap_a[1], snap_a[3]];

        let root = fixture_root(2);
        let a = assigned_archives(&root, &snap_a, 42, 3);
        let b = assigned_archives(&root, &snap_b, 42, 3);
        let c = assigned_archives(&root, &snap_c, 42, 3);
        assert_eq!(a, b);
        assert_eq!(a, c);

        // Force a non-canonical input: also exercise dedup.
        snap_a.push(snap_a[0]);
        snap_a.push(snap_a[2]);
        let d = assigned_archives(&root, &snap_a, 42, 3);
        assert_eq!(a, d);
    }

    /// is_archive_assigned_to_chunk agrees with assigned_archives.
    #[test]
    fn is_archive_assigned_matches_assigned_archives() {
        let snap = fixture_archives().to_vec();
        let root = fixture_root(0);
        let assigned = assigned_archives(&root, &snap, 0, 3);
        for a in &snap {
            let in_set = assigned.iter().any(|x| x.as_bytes() == a.as_bytes());
            assert_eq!(
                is_archive_assigned_to_chunk(&root, &snap, 0, 3, a),
                in_set,
                "is_archive_assigned_to_chunk disagrees with assigned_archives for {}",
                hex::encode(a.as_bytes()),
            );
        }
    }

    /// Empty snapshot: function returns empty Vec, no panic.
    #[test]
    fn empty_snapshot_returns_empty() {
        let root = fixture_root(0);
        assert!(assigned_archives(&root, &[], 0, 3).is_empty());
    }
}

/// On-chain V2 file row stored under prefix `[b'F', b'2', merkle_root]` to
/// coexist with V1 `[b'F', merkle_root]`. Plan §3.2.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StorageMetadataV2 {
    pub merkle_root: Hash,
    pub owner: Address,
    pub plaintext_size_bytes: u64,
    pub stored_size_bytes: u64,
    pub chunk_count: u32,
    /// Locked deposit. Settlement semantics (PoR payout / abandonment refund)
    /// are unchanged from V1 fee_pool — only the *path in* changes.
    pub fee_pool: u64,
    /// Block height of `RegisterFilePendingV2`. Depends on Phase 0a fix.
    pub created_at: u64,
    /// Set on `ActivateFileV2`; `None` while Pending or Abandoned.
    pub activated_at_height: Option<u64>,
    /// Set on `AbandonFileV2`; `None` while Pending or Active. Off-chain
    /// indexers (e.g. SNIP `IngestOutcome::AbandonedOnChain`) read this to
    /// learn the exact lifecycle-transition block without scanning receipts.
    pub abandoned_at_height: Option<u64>,
    /// Block height at which the active-archive-node snapshot used for
    /// chunk assignment was captured (Ask 15, Option A).
    pub assignment_height: u64,
    pub visibility: FileVisibilityV2,
    pub lifecycle: FileLifecycleV2,
    pub access_list: Vec<AccessEntryV2>,
    /// Reserved for Ask 10 (file rotation). Always `None` in V2.
    pub predecessor_root: Option<Hash>,
}
