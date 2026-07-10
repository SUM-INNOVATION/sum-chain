# SNIP V2 — Chain-Side Plan

**Status:** Draft v3.2 — AcceptAssignmentV2 reframed as bitmap OR-merge; adds AssignmentCoverageV2 RPC, file/tx attestation caps, dedicated CF, deterministic assignment function (2026-04-29)
**Source brief:** SNIP V2 v6 (with appendix)
**Branch baseline:** `main` @ `2b63634`
**Authors:** chain team
**Date:** 2026-04-29
**Approval:** v2 approved 2026-04-28 with advice; v3 incorporates that advice; v3.1 adds X25519 low-order rejection; v3.2 resolves the cap-vs-replacement contradiction surfaced by SNIP review of v3.1 (2026-04-29, approved with three clarifications now folded in)

---

## 0.1. What changed in v3.2 (post-SNIP-review-of-v3.1)

v3.1 was rejected by SNIP review for an internal contradiction: §3.6 stored each `(file, archive)` attestation as `Vec<u32>` with full-replacement semantics, while a proposed `max_chunk_indices_per_tx` cap created a hidden cumulative cap — once an archive's assigned set exceeded the per-tx cap, no replacement-style submission could ever cover it, blocking activation. v3.2 resolves this by switching to bitmap OR-merge.

| SNIP-review concern (v3.1 → v3.2) | Resolution in v3.2 |
|---|---|
| Per-tx cap + full-replacement semantics is contradictory; activation becomes impossible above the cap | §3.6 reworked to **bitmap OR-merge**. Each `AcceptAssignmentV2` ORs the supplied `chunk_indices` into a per-`(file, archive)` bitmap row of length `ceil(chunk_count/8)`. The per-tx cap is now genuinely per-tx. |
| Worst-case state row size unbounded | New consensus param `max_chunk_count_per_file` (default `1_048_576` = 1 TB at `CHUNK_SIZE = 1 MB`) caps bitmap size at 128 KB/archive. New `max_chunk_indices_per_tx` (default `65_536`) caps per-tx payload. |
| Owner has no clean way to know when `ActivateFileV2` is valid | New RPC `storage_getAssignmentCoverageV2` returns popcount summaries + a paginated window of missing chunk indices; never returns raw `Vec<u32>` per archive. |
| Storage home for the attestation row was unspecified | §3.6 specifies a **dedicated CF** `assignment_attestations_v2`, separate from the V2 file row CF. Reasons: distinct access pattern (per-`(file, archive)` lookup + iterate-by-file for coverage), clean prefix scan via `[b'A', root_32, …]`, and so future attestation GC (post-activation) doesn't touch file rows. |
| `missing_offset` semantics were ambiguous | Specified as a **chunk-index lower bound**, not an offset into the filtered-missing list. Stable under concurrent coverage changes: clients call again with `missing_offset = last_returned_index + 1`. |
| Deterministic assignment function was implicit, but executor + coverage RPC + SNIP push logic must all share it | §3.6 now specifies the exact rendezvous-hash assignment function: domain-separated `blake3::derive_key("sumchain SNIP-V2 chunk-assignment v1", merkle_root ‖ chunk_index_be ‖ archive_address)`, score = first 8 BE bytes, sorted ascending with address tie-break, take top-`R`. BLAKE3 chosen to match the chain's hashing convention (Merkle roots, agreement commitments, etc.). New consensus param `assignment_replication_factor` (default 3, capped at snapshot size). |

Test matrix added to §3.6 (must land before Phase 1b passes review): duplicate indices in one tx, out-of-range index rejection, over-cap rejection, idempotent resubmission, multi-tx OR merge, `ActivateFileV2` valid only when OR-coverage over snapshot-active archives reaches all chunks, behavior when an attesting archive becomes Inactive between accept and activate, behavior when `chunk_indices` contains an index not assigned to the signer.

## 0. What changed in v3 (post-approval advice)

v2 was approved with five pieces of advice to apply before implementation. v3 incorporates them:

| Reviewer advice | Resolution in v3 |
|---|---|
| §5.2 wording: missed/expired proofs do **not** drain `fee_pool`; expiry only slashes the target node and deletes the challenge | §5.2 rewritten with accurate behavior: expiry path is in [executor.rs:1897-1951](../../crates/state/src/executor.rs#L1897-L1951) (slash node 5%, mark Slashed, delete challenge). Fee_pool is never drained on missed proofs — only paid out on successful proofs at [storage_metadata.rs:478-492](../../crates/state/src/storage_metadata.rs#L478-L492). |
| Add `AcceptAssignmentV2` sooner — without it, malicious/premature activation can slash honest archives | **Brought into Phase 1 scope** (§3.6, §6). Owner cannot `ActivateFileV2` until every chunk index has at least one archive-signed `AcceptAssignmentV2`. |
| `#[serde(default)]` for new genesis params | §3.4, §3.7 explicitly specify `#[serde(default = "default_*")]` so existing `genesis.json` files (without the new fields) deserialize cleanly. |
| Make V2 tx dispatch explicit — a standalone `NodeRegistryOperationV2` won't execute without `TxPayload` routing | §3.7 added: routing diagram + explicit new `TxPayload::NodeRegistryV2` and `TxPayload::StorageMetadataV2` variants, plus the new match arms in `execute_tx`. |
| For `active_archive_nodes_history`: write initial snapshot, define reverse-lookup behavior for heights before the first change | §5.3 specifies (a) genesis snapshot at height 0 (empty `Vec` if no archives at genesis), (b) `storage_getActiveNodesAtHeight(h)` returns the most recent snapshot at height `≤ h`; for `h = 0` returns the genesis snapshot. |

**v3.1** adds a separate post-approval advisory addition:

| Reviewer advice (v3.1) | Resolution |
|---|---|
| `RegisterEncryptionKey` MUST reject the seven X25519 low/small-order byte-string encodings (matching libsodium's `crypto_scalarmult` `has_small_order`) before write, so no legitimate sender ever wraps against a small-order point and the registry can't be used for griefing | §3.3 prose updated. New validity rule in §3.5. New receipt code `Failed(22)` → `"low-order x25519 public key rejected"` mapped in [crates/primitives/src/receipt.rs](../../crates/primitives/src/receipt.rs). Helper `sumchain_crypto::is_low_order_x25519_public_key` (constant-time, OR-accumulator over byte XOR) + `LOW_ORDER_X25519_POINTS` table added in [crates/crypto/src/messaging.rs](../../crates/crypto/src/messaging.rs) with tests covering all seven entries, high-bit-set variants, all-zero, and freshly generated `KeyPair`-derived pubkeys. |

## A. What changed in v2 (vs the rejected v1)

The first draft was rejected for proposing chain-level economic changes outside SNIP's scope. v2 is narrower — strictly an **additive privacy/lifecycle layer over the existing V1 storage protocol**, with no economic-model changes and no OmniNode dependency.

| Concern in v1 | Resolution in v2 |
|---|---|
| Introduced per-epoch emissions, minting, 40/30/20/10 split — contradicts [docs/architecture/economic-model.md](../architecture/economic-model.md) (fixed supply, no mining rewards) | **Removed entirely.** PoR payouts stay fee-pool based per V1. Any future emission redesign goes through formal economic-model revision (v3.0 → v4.0), not a SNIP response. |
| OmniNode role records assumed without spec; Phase 0b shipped role snapshots before Phase 3 defined the roles | **Removed.** Plan uses existing single-role `NodeRecord`. OmniNode work is independent and out of scope for SNIP V2. |
| `CHALLENGE_REWARD` redefined as derived from epoch budget; replaced fee_pool semantics without migration | **Reverted.** V2 keeps `CHALLENGE_REWARD = 10 Koppa` and fee_pool settlement at [storage_metadata.rs:478-492](../../crates/state/src/storage_metadata.rs#L478-L492). |
| Ask 15 flipped to Option B (epoch-based) on the strength of three-stream emission accounting | **Re-flipped to Option A (height-based)** with snapshot-on-change. Without the emission argument, Option B's added complexity isn't justified. |
| Claimed "200-entry cap = 16 KB/file row max" — actual bincode encoding makes 200 entries ~22 KB, exceeding `max_metadata_bytes = 16,384` | **Recomputed.** Cap enforced by *byte size*, not entry count. Section 3.4. |
| Phase 0b assumed block heights would work for `assignment_epoch` / `created_at` / `activated_at_height` | **Block-height plumbing fix added as Phase 0a prerequisite.** Confirmed bug at [executor.rs:873,906](../../crates/state/src/executor.rs#L873). |
| Storage protocol semantics (initial replication, archive-node exit, challenge coverage) under-specified | **Section 5 (operational semantics)** documents what V2 does and explicitly what it does NOT promise — Filecoin-grade redesign is out of scope. |
| PoC/AGI governance allocation treated as approvable design | **Removed from SNIP plan entirely.** PoC has no place in a storage-protocol response. |

---

## 1. Context

This plan responds to all 15 asks in SNIP V2 v6, scoped to:
- Privacy (Private files, encrypted bundles, X25519 registry)
- File lifecycle (Pending / Active / Abandoned)
- A few RPC additions for client ergonomics (block height, tx status)

**Strictly out of scope for V2:**
- OmniNode role-combination
- Token emission / mining-style PoR rewards
- Decentralized AGI compute (PoC)
- Filecoin/Arweave-style proof redesign (PoRep, randomized recall)
- Re-assignment of chunks on archive-node exit

These are real concerns and may become future work, but each requires its own track (economic-model revision, separate spec, governance approval) and **none should block SNIP V2.**

V1 schemas and economics stay untouched. V2 additions are additive: new enum variants, new tx ops, new RPCs, V2-prefixed storage keys.

---

## 2. Prerequisites (Phase 0a — must land before V2 schema work)

### 2.1 Fix V2 tx executor block-height plumbing

[crates/state/src/executor.rs:866-931](../../crates/state/src/executor.rs#L866-L931) currently passes `0, // block_height placeholder` to both `NodeRegistry` and `StorageMetadata` executors. As a result:

- V1 `NodeRecord.registered_at` is always 0 ([node_registry.rs:62](../../crates/primitives/src/node_registry.rs#L62))
- V1 `StorageMetadata.created_at` is always 0 ([storage_metadata.rs:44](../../crates/primitives/src/storage_metadata.rs#L44))
- Any V2 lifecycle field that depends on block height (`activated_at_height`, `assignment_height`, expiry windows, abandonment grace periods) would inherit the bug.

**Fix:** thread `block_height` through `execute_tx_v2` into both V2 executor calls. One-line change at each call site; needs a test verifying non-zero heights are persisted. **Hard prerequisite for V2 schema work.**

### 2.2 No other chain-side prereqs

V1 storage protocol is otherwise sufficient as a baseline.

---

## 3. Schema additions (V2)

### 3.1 V2 storage operations (additive to [crates/primitives/src/storage_metadata.rs](../../crates/primitives/src/storage_metadata.rs))

```rust
pub enum StorageMetadataOperationV2 {
    RegisterFilePendingV2 {
        merkle_root:           [u8; 32],
        plaintext_size_bytes:  u64,
        stored_size_bytes:     u64,
        chunk_count:           u32,
        fee_deposit:           u64,
        visibility:            u8,               // 0 = Public, 1 = Private
        initial_access:        Vec<AccessEntryV2>,
    },
    ActivateFileV2     { merkle_root: [u8; 32] },
    AbandonFileV2      { merkle_root: [u8; 32] },
    AcceptAssignmentV2 { merkle_root: [u8; 32], chunk_indices: Vec<u32> },  // bits to OR into the (file, archive) bitmap; see §3.6
    AddAccessV2        { merkle_root: [u8; 32], entry: AccessEntryV2 },
    RemoveAccessV2     { merkle_root: [u8; 32], address: [u8; 20] },
    UpdateAccessV2     { merkle_root: [u8; 32], address: [u8; 20], new_entry: AccessEntryV2 },
}

pub struct AccessEntryV2 {
    pub address:              [u8; 20],
    pub encrypted_key_bundle: Option<[u8; 80]>,
    pub expires_at:           Option<u64>,
}

#[repr(u8)]
pub enum FileLifecycleV2 {
    Pending   = 0,
    Active    = 1,
    Abandoned = 2,
    // Reserved for Ask 10 future work:
    // Rotated = 3,
}

#[repr(u8)]
pub enum FileVisibilityV2 {
    Public  = 0,
    Private = 1,
}
```

### 3.2 V2 file row stored in chain state

```rust
pub struct StorageMetadataV2 {
    pub merkle_root:          [u8; 32],
    pub owner:                [u8; 20],
    pub plaintext_size_bytes: u64,
    pub stored_size_bytes:    u64,
    pub chunk_count:          u32,
    pub fee_pool:             u64,            // unchanged settlement semantics from V1
    pub created_at:           u64,            // height of RegisterFilePendingV2 (depends on §2.1 fix)
    pub activated_at_height:  Option<u64>,    // None until ActivateFileV2 (Ask 12)
    pub abandoned_at_height:  Option<u64>,    // None until AbandonFileV2 (off-chain indexer ergonomics)
    pub assignment_height:    u64,            // height at which active-archive-node set was snapshotted (Ask 15, Option A)
    pub visibility:           FileVisibilityV2,
    pub lifecycle:            FileLifecycleV2,
    pub access_list:          Vec<AccessEntryV2>,
    pub predecessor_root:     Option<[u8; 32]>, // reserved for Ask 10; always None in V2
}
```

Stored under prefix `[b'F', b'2', merkle_root]` to coexist with V1 `[b'F', merkle_root]`.

### 3.3 Encryption key registry (Ask 3)

```rust
// crates/primitives/src/node_registry.rs (additive — separate from existing one-role NodeRegistryOperation)

pub enum NodeRegistryOperationV2 {
    RegisterEncryptionKey {
        encryption_pubkey: [u8; 32],   // X25519 Montgomery U; one per account; overwrite-on-rewrite
    },
}
```

Rotation does not retro-revoke previously-issued bundles — past bundles remain decryptable by the holder of the prior X25519 private key. SNIP handles client-side reissue on rotation.

Stored in a new `account_encryption_keys` column family keyed by address.

**Low-order point rejection at registration.** Validity rule: `encryption_pubkey` MUST NOT match any of the **seven X25519 low/small-order byte-string encodings** (after masking the high bit per RFC 7748 §5). The blocklist matches libsodium's `crypto_scalarmult` validation (see [`x25519_ref10.c`](https://raw.githubusercontent.com/jedisct1/libsodium/master/src/libsodium/crypto_scalarmult/curve25519/ref10/x25519_ref10.c)). Two of the seven entries (`p`, `p+1`) are non-canonical field encodings that RFC 7748 processing nevertheless accepts; they are blocked here as well.

Rejecting at registration time means no legitimate sender ever performs a wrap operation against a small-order point, and shuts down griefing where a registered low-order pubkey would make legitimate senders' wrap calls fail. Implemented as `sumchain_crypto::is_low_order_x25519_public_key` ([crates/crypto/src/messaging.rs](../../crates/crypto/src/messaging.rs)) and called from the V2 `RegisterEncryptionKey` executor. Comparison is constant-time (OR-accumulator over byte XOR) so the registry, which is a public surface, doesn't leak which blocklist entry was hit.

Note for future work: this check is at registration time only. Any future code path that accepts unregistered ephemeral X25519 public keys should additionally enforce the RFC 7748 §6.1 all-zero shared-secret check at the ECDH call site.

### 3.6 AcceptAssignmentV2 (added v3, reworked v3.2 — bitmap OR-merge)

```rust
// crates/primitives/src/storage_metadata.rs (additive)

// Extend StorageMetadataOperationV2 with one more variant:
//
// AcceptAssignmentV2 {
//     merkle_root:   [u8; 32],
//     chunk_indices: Vec<u32>,   // bits to SET in this archive's bitmap; OR-merged into prior state
// }
```

**Storage model:** per-`(file, archive)` bitmap of length `ceil(chunk_count / 8)` bytes, in a **dedicated column family** `assignment_attestations_v2`, keyed `[b'A', merkle_root_32, archive_address_20]` → `Vec<u8>`. Lazily allocated (no row exists until first accept). Each `AcceptAssignmentV2` ORs the bits selected by `chunk_indices` into the existing row (creating it if absent).

Why a dedicated CF (not the V2 file row CF): distinct access pattern (per-`(file, archive)` point lookups during attestation; prefix scan `[b'A', root_32, …]` during coverage RPC), and isolating attestation rows keeps any future post-activation GC of these rows from touching file metadata.

Why bitmap-merge rather than `Vec<u32>`-replace (v3.1 design, rejected by SNIP review): a per-tx cap on `chunk_indices` only works as a real per-tx cap when cumulative state lives outside that vec. Replacement semantics turn the per-tx cap into a hidden cumulative cap, blocking activation for any archive assigned more chunks than the cap.

**Validity:**
- File at `merkle_root` exists, `lifecycle == Pending`. (Pending-only — no post-activation re-attestation surface.)
- Signer is in the file's `assignment_height` snapshot AND currently `Active`.
- `chunk_indices.len() ≤ max_chunk_indices_per_tx` (default 65,536; see §3.4).
- Every `idx ∈ chunk_indices`: `idx < chunk_count` AND `idx` is assigned to the signer per the deterministic assignment function below over the snapshot. Mismatch on any index rejects the entire tx (no partial application).
- Duplicate indices within one tx are accepted (set semantics — duplicates OR to the same bit).
- Resubmitting indices already set in the bitmap is a no-op (idempotent OR), receipts as success.

**Effect on success:** for each `idx ∈ chunk_indices` the bit at byte `idx/8`, mask `1 << (idx % 8)` in the row's bitmap is set to 1.

**Deterministic assignment function** (shared by executor, coverage RPC, and SNIP push logic — must be byte-identical across all three implementations). Uses BLAKE3 to match the rest of the chain (`merkle_root` itself is BLAKE3 per [crates/primitives/src/storage_metadata.rs:34](../../crates/primitives/src/storage_metadata.rs#L34); SHA-256 only appears in the Ed25519/X25519 conversion paths and is not a chain primitive):

```
assigned_archives(merkle_root, snapshot, chunk_index, R) -> Vec<Address>:
    # snapshot: the Vec<NodeRecord> read from active_archive_nodes_history at
    #   the file's assignment_height (§5.3).
    addrs = sorted(snapshot.map(.address))     # 20-byte ascending; tie-break by address
    R'    = min(R, addrs.len())
    scored = []
    for a in addrs:
        # Concrete Rust call, not pseudocode: this exact line is what executor,
        # coverage RPC, and SNIP push logic must each call. blake3::derive_key
        # internally builds a fresh keyed BLAKE3 hasher with the context-derived
        # key and digests the input in one shot — equivalent to calling
        # `blake3::Hasher::new_derive_key(CTX).update(input).finalize()`. Do NOT
        # implement as `blake3::keyed_hash(blake3::hash(CTX).as_bytes(), input)`
        # — that is a different construction.
        let input: [u8; 56] = merkle_root || chunk_index.to_be_bytes() || a;   # 32 + 4 + 20
        let h: [u8; 32] = blake3::derive_key(
            "sumchain SNIP-V2 chunk-assignment v1",   # context string — exact bytes, no trailing newline
            &input,
        );
        score = u64::from_be_bytes(h[0..8])
        scored.push((score, a))
    sort scored ascending by (score, a)         # tie-break by address (handles 1-in-2^64 score collisions)
    return scored[0..R'].map(.a)                # the R' assigned archives for this chunk
```

Where `R = assignment_replication_factor` consensus param (§3.4, default 3). This is rendezvous hashing: each chunk's assigned set is the R archives with the smallest BLAKE3-derived score for that `(merkle_root, chunk_index)`. Snapshot-stable: the snapshot is frozen at `assignment_height`, so this function returns the same answer for the lifetime of the file regardless of live churn.

Implementation note: `blake3::derive_key(context, input)` is the exact API ([crates/crypto/src/messaging.rs:90](../../crates/crypto/src/messaging.rs#L90) wraps it for messaging KDF use). The context string `"sumchain SNIP-V2 chunk-assignment v1"` provides domain separation from `messaging::address_hash` ([messaging.rs:184](../../crates/crypto/src/messaging.rs#L184)) and any other BLAKE3 callers that may hash similar inputs. Conformance test vectors are in **Appendix C**; SNIP client implementations must reproduce all listed `(input → assigned set)` mappings byte-for-byte.

**`ActivateFileV2` validity (revised v3.2):** in addition to v3 rules, for every `i ∈ [0, chunk_count)`:

```
∃ archive A: A ∈ snapshot AND A is currently Active
             AND assignment_attestations_v2[(merkle_root, A)][i] == 1
```

Equivalently: the bitwise-OR of all snapshot-active archives' bitmaps covers `[0, chunk_count)` fully.

**State-row size bound:** `max_chunk_count_per_file = 1_048_576` (§3.4) caps any single bitmap row at 128 KB. Bitmap rows are retained post-activation in v3.2 (no GC); a future `GcAttestationsV2` op can prune them after activation + grace if state-bloat shows up.

**Required tests** (must pass before Phase 1b is mergeable; track in [crates/state/src/storage_metadata.rs:797](../../crates/state/src/storage_metadata.rs#L797) test module):
1. Single-tx accept on a fresh file sets exactly the supplied bits; popcount == `unique(chunk_indices).len()`.
2. Two txs with overlapping `chunk_indices` from the same archive: bitmap == OR of both inputs; second tx receipts as success (idempotent, not "already-set" error).
3. Index ≥ `chunk_count` → reject whole tx; bitmap unchanged.
4. Index not assigned to signer per the assignment fn → reject whole tx.
5. `chunk_indices.len() > max_chunk_indices_per_tx` → reject.
6. Duplicate indices within one tx → accept, single bit set per duplicate.
7. `RegisterFilePendingV2` with `chunk_count > max_chunk_count_per_file` → reject.
8. `ActivateFileV2` rejected while any chunk uncovered; accepted exactly when full coverage is reached.
9. Archive that accepts then becomes `Slashed` (or `Inactive`) before activate: its bitmap stops counting toward coverage; activation succeeds iff remaining snapshot-active accepting archives still cover all chunks.
10. `AcceptAssignmentV2` after `ActivateFileV2` → reject (Pending-only).
11. `storage_getAssignmentCoverageV2` paginated `missing_indices` with `missing_offset` advancing across calls returns each missing index exactly once when no concurrent state changes occur, and remains stable (no skipped or repeated indices below the offset) when a concurrent accept covers indices outside the current window.

### 3.7 V2 tx dispatch routing (added v3 — addresses reviewer advice 4)

V2 ops only run if wired into `TxPayload` and the `execute_tx` match. Concretely:

```rust
// crates/primitives/src/transaction.rs — add two variants
pub enum TxPayload {
    Transfer { to: Address, amount: u128 },
    Nft(NftTxData),
    Token(TokenTxData),
    // ... existing variants ...
    NodeRegistry(NodeRegistryTxData),       // V1 — unchanged
    StorageMetadata(StorageMetadataTxData), // V1 — unchanged
    NodeRegistryV2(NodeRegistryV2TxData),       // NEW
    StorageMetadataV2(StorageMetadataV2TxData), // NEW
}
```

```rust
// crates/state/src/executor.rs — add two new match arms in execute_tx
TxPayload::NodeRegistryV2(data) => {
    let result = self.node_registry_executor.execute_v2(
        &v2_tx.from, &data, &self.state, proposer, v2_tx.fee,
        block_height,        // <- threaded via §2.1 fix
        block_timestamp,
    )?;
    /* ... */
}
TxPayload::StorageMetadataV2(data) => {
    let result = self.storage_metadata_executor.execute_v2(/* ... */)?;
    /* ... */
}
```

Existing V1 `TxPayload::NodeRegistry` and `TxPayload::StorageMetadata` arms stay unchanged. Receipts for V2 dispatch failures use new `TxStatus::Failed` codes:

| Code | Meaning | `description()` string |
|---|---|---|
| 20 | `NodeRegistryV2` op failed (generic) | `"failed"` (specific reasons via op-level errors) |
| 21 | `StorageMetadataV2` op failed (generic) | `"failed"` |
| **22** | `RegisterEncryptionKey` rejected a low/small-order X25519 public key (see §3.3) | `"low-order x25519 public key rejected"` |
| **30** | `RegisterFilePendingV2` validity failure (chunk caps, visibility/bundle/owner rules, recipient X25519 missing, collision, size/chunk-count mismatch) | `"RegisterFilePendingV2 validity check failed"` |
| **31** | `AbandonFileV2` validity failure (state/owner/grace) | `"AbandonFileV2 validity check failed"` |
| **32** | V2 storage op routed but not yet implemented (placeholder for 1c stubs) | `"V2 storage op not yet implemented"` |
| **33** | `AcceptAssignmentV2` validity failure (file state, snapshot membership, per-tx cap, index out of range, index-not-assigned) | `"AcceptAssignmentV2 validity check failed"` |
| **34** | `ActivateFileV2` validity failure (state/owner/incomplete chunk coverage) | `"ActivateFileV2 validity check failed"` |
| **35** | `AddAccessV2` / `RemoveAccessV2` / `UpdateAccessV2` validity failure (file state/owner, visibility/bundle mismatch, recipient X25519 missing, duplicate or missing address, byte-cap re-violated) | `"V2 access op validity check failed"` |

`TxStatus::description()` in [crates/primitives/src/receipt.rs](../../crates/primitives/src/receipt.rs) is the single source of truth for the reason string surfaced by `chain_getTransactionStatus(...).Failed.reason`. Codes 22, 30–34 are mapped explicitly there; codes 20/21 fall through to the generic `"failed"` string until per-op reasons are added in their respective implementations.

### 3.4 Access-list size cap (corrected)

The v1 plan claimed "200 entries = 16 KB"; recomputed bincode:

| Field | Encoded size (Private, all Some) |
|---|---|
| `address: [u8; 20]` | 20 B |
| `encrypted_key_bundle: Option<[u8; 80]>` | 1 + 80 = 81 B |
| `expires_at: Option<u64>` | 1 + 8 = 9 B |
| **Per entry total** | **110 B** |
| `Vec<_>` length prefix | 8 B |

So 200 entries (worst case) = **22,008 B ≈ 21.5 KB** — over `max_metadata_bytes = 16,384`.

**Correct design — byte cap, not entry cap:**

```rust
// New consensus params in crates/genesis/src/lib.rs (note serde defaults — addresses reviewer advice 3)
#[serde(default = "default_max_access_list_bytes")]
pub max_access_list_bytes: u64,                // default 16_384

#[serde(default = "default_activation_grace_blocks")]
pub activation_grace_blocks: u64,              // default 50

#[serde(default = "default_abandonment_fee_percent")]
pub abandonment_fee_percent: u64,              // default 10

// v3.2: bitmap-attestation caps (see §3.6)
#[serde(default = "default_max_chunk_count_per_file")]
pub max_chunk_count_per_file: u32,             // default 1_048_576 (= 1 TB at CHUNK_SIZE = 1 MB)

#[serde(default = "default_max_chunk_indices_per_tx")]
pub max_chunk_indices_per_tx: u32,             // default 65_536

#[serde(default = "default_assignment_replication_factor")]
pub assignment_replication_factor: u32,        // default 3 (capped at snapshot size by the assignment fn)

fn default_max_access_list_bytes()         -> u64 { 16_384    }
fn default_activation_grace_blocks()       -> u64 { 50        }
fn default_abandonment_fee_percent()       -> u64 { 10        }
fn default_max_chunk_count_per_file()      -> u32 { 1_048_576 }
fn default_max_chunk_indices_per_tx()      -> u32 { 65_536    }
fn default_assignment_replication_factor() -> u32 { 3         }
```

`#[serde(default)]` is required so existing `genesis.json` / `local_genesis.json` / `testnet_genesis.json` files (which don't have these fields) deserialize without error.

Validity rule on `RegisterFilePendingV2` and `AddAccessV2` / `UpdateAccessV2`:
```
serialized_size(file.access_list_after_op) <= max_access_list_bytes
```

Practical effect:
- Private (all-Some entries): ~148 recipients per file
- Public (bundles None, no expiry): ~744 recipients per file (each entry = 22 B)

If SNIP needs >148 Private recipients per file, that's a separate scaling design (off-chain bundle layer with on-chain commitment); not v1 work.

### 3.5 Validity rules (consolidated)

- `RegisterFilePendingV2`:
  - `chunk_count > 0`, `stored_size_bytes > 0`, `visibility ∈ {0,1}`
  - `chunk_count ≤ max_chunk_count_per_file` (v3.2; bounds bitmap-row size)
  - `chunk_count == ceil(stored_size_bytes / CHUNK_SIZE)` — the canonical chunk count for the declared size; without this the bitmap row size is decoupled from the actual file size and `AcceptAssignmentV2`'s `idx < chunk_count` bound becomes meaningless. **Implementation must use overflow-safe arithmetic: `stored_size_bytes.div_ceil(CHUNK_SIZE)` (stable Rust), not the manual `(a + b - 1) / b` form** — `stored_size_bytes` is tx-controlled and unbounded before this check, so the manual form panics in debug builds and silently wraps in release when `stored_size_bytes > u64::MAX - (CHUNK_SIZE - 1)`. Consensus validation must not have profile-dependent arithmetic. Already enforced in Phase 1a code at [crates/state/src/storage_metadata.rs:865](../../crates/state/src/storage_metadata.rs#L865).
  - `serialized_size(initial_access) ≤ max_access_list_bytes`
  - **Public:** all `encrypted_key_bundle` MUST be `None`; list MAY be empty
  - **Private:** all `encrypted_key_bundle` MUST be `Some([u8; 80])`; owner MUST be in list with non-`None` bundle; every recipient MUST have a registered X25519 pubkey
  - File enters `Lifecycle::Pending`. `activated_at_height = None`, `abandoned_at_height = None`.
  - `assignment_height = current_block_height` (snapshot of active-archive-node set is captured here — see §5.3).
  - PoR challenge generation continues to filter by `lifecycle == Active && current_height > activated_at_height + activation_grace_blocks` (Ask 12).

- `ActivateFileV2`:
  - `lifecycle == Pending`, signer == owner
  - Sets `lifecycle = Active`, `activated_at_height = current_height`

- `AbandonFileV2`:
  - `lifecycle == Pending`, signer == owner
  - `current_height > created_at + activation_grace_blocks` (anti-grief)
  - Refund: `fee_pool × (1 - abandonment_fee_percent / 100)` to owner. The retained `fee_pool × abandonment_fee_percent / 100` is **burned** — there is no treasury credit, fee-pool transfer to validators, or other destination in v3.2. Implementation: `row.fee_pool = 0` is written after the refund-side `state.put_account` ([crates/state/src/storage_metadata.rs:1059-1068](../../crates/state/src/storage_metadata.rs#L1059-L1068)) with no offsetting credit elsewhere. Net effect on circulating supply: `−retained` (since `fee_deposit` was debited from owner at registration). The `retained={…}` value in the abandonment log line is informational only and does not correspond to any account's balance change.
  - Net economic effect: the chain's fixed-supply invariant is preserved at the registration boundary (no minting), and the abandonment burn is a strictly-deflationary anti-grief penalty — consistent with [docs/architecture/economic-model.md](../architecture/economic-model.md). If a future SNIP version wants the retained portion to flow somewhere (validator pool, a treasury, redistributed to active archives), that's a separate consensus change with its own economic-model approval; do not assume a destination exists today.
  - Sets `lifecycle = Abandoned`, `abandoned_at_height = current_block_height`, `fee_pool = 0`. Row retained for audit; `abandoned_at_height` is the indexer-facing block-of-transition (mirrors `activated_at_height`'s shape on the activation side).

- `AddAccessV2` / `RemoveAccessV2` / `UpdateAccessV2`:
  - signer == owner; `lifecycle == Active`
  - Private files: recipient must have registered X25519 pubkey
  - Resulting `access_list` byte-size cap re-enforced

- `RegisterEncryptionKey` (NodeRegistryV2):
  - `encryption_pubkey` is exactly 32 bytes
  - `!sumchain_crypto::is_low_order_x25519_public_key(&encryption_pubkey)` (see §3.3)
  - Reject with `TxStatus::Failed(22)`; `description() = "low-order x25519 public key rejected"`
  - On valid input: write `encryption_pubkey` into `account_encryption_keys[signer_address]` (overwrite-on-rewrite semantics)

---

## 4. RPC additions (V2)

```rust
// chain_*
chain_getBlockHeight() -> { height: u64, finality: "finalized" | "latest" }

chain_getTransactionStatus(tx_hash: String) -> TxStatusV2

enum TxStatusV2 {
    Unknown,
    Pending,
    Included  { block_height: u64 },
    Finalized { block_height: u64 },                    // depth-aware: depth=3 PoA / depth=0 BFT
    Failed    { block_height: Option<u64>, reason: String },
    Dropped,
}

// account_*
account_getEncryptionPublicKey(address: String) -> Option<Hex32>

// storage_*
storage_getFileInfoV2(
    merkle_root:    String,
    access_offset:  Option<u32>,
    access_limit:   Option<u32>,    // default 256
) -> StorageFileInfoV2

storage_getPushableFilesV2(
    offset: Option<u32>,            // skip count; default 0
    limit:  Option<u32>,            // default 256, hard cap 1024
) -> Vec<PushableFileInfoV2>        // ordered by ascending merkle_root (lex on bytes);
                                    // stable under concurrent appends, eventually-consistent
                                    // under lifecycle transitions (Pending→Active stays in
                                    // the list with new lifecycle; →Abandoned drops out).
                                    // Callers paginate with `offset += returned.len()`.

// Ask 15 (Option A — height-based)
storage_getActiveNodesAtHeight(height: u64) -> Vec<NodeRecordInfo>

// v3.2: surfaces the per-(file) coverage state that AcceptAssignmentV2 builds
// up and that ActivateFileV2 gates on. Owner polls until can_activate_now == true.
storage_getAssignmentCoverageV2(
    merkle_root:    String,
    missing_offset: Option<u32>,    // chunk-index lower bound (NOT an offset into the missing list); default 0
    missing_limit:  Option<u32>,    // default 1024, max 16384
) -> AssignmentCoverageV2

struct AssignmentCoverageV2 {
    chunk_count:      u32,
    covered_count:    u32,                          // popcount over OR of all snapshot-active archive bitmaps
    can_activate_now: bool,                         // covered_count == chunk_count && lifecycle == Pending
    missing_total:    u32,                          // chunk_count - covered_count (for whole file, not just window)
    missing_offset:   u32,                          // echoed back
    missing_indices:  Vec<u32>,                     // ascending list of i >= missing_offset where coverage[i] == 0, capped at missing_limit
    per_archive:      Vec<ArchiveCoverageSummaryV2>,
}

struct ArchiveCoverageSummaryV2 {
    archive:          Address,
    assigned_count:   Option<u32>,                  // # of chunks assigned to this archive by the deterministic assignment fn;
                                                    // `Some(n)` for files with `chunk_count <= MAX_ASSIGNED_COUNT_CHUNK_COUNT` (16,384);
                                                    // `None` (JSON `null`) for larger files — clients must compute locally
                                                    // via `assigned_archives_presorted`. Bounds RPC-call cost.
    attested_count:   u32,                          // popcount of this archive's bitmap row (0 if no row yet)
    currently_active: bool,
}
```

`StorageFileInfoV2` mirrors `StorageMetadataV2` with hex-encoded fields and lifecycle/visibility surfaced as integers.

`storage_getActiveNodesAtHeight` walks back to the most recent snapshot ≤ requested height (snapshot-on-change strategy — see §5.3).

`storage_getAssignmentCoverageV2.missing_offset` semantics (v3.2 clarification): treated as a **chunk-index lower bound**, not an offset into the filtered missing list. The RPC returns up to `missing_limit` indices `i` where `i >= missing_offset` AND chunk `i` is not yet covered, in ascending order. Pagination is therefore **stable under concurrent coverage changes**: the next call uses `missing_offset = last_returned_index + 1`. If a concurrent `AcceptAssignmentV2` covers indices below the new offset, those indices simply drop out — the client never re-pages backwards. `per_archive` is always returned in full (bounded by snapshot size, typically O(10) entries) and contains only popcount summaries; raw bitmap data is never serialized into the RPC response.

`assigned_count` is `Option<u32>` (JSON nullable) by deliberate design. The chain caps the per-archive count work at `MAX_ASSIGNED_COUNT_CHUNK_COUNT = 16_384` chunks (worst-case ~160 ms RPC); above that cap every entry's `assigned_count` is `null` and SNIP clients MUST compute counts locally — the deterministic `assigned_archives_presorted` function is bit-identical to chain validation. Without the cap, an attacker could DoS the RPC by registering a file at the per-file maximum (1,048,576 chunks). The chain's coverage values (`covered_count`, `missing_indices`, `can_activate_now`) are always populated regardless of the cap; only the per-archive *assignment* counts are gated.

---

## 5. Operational semantics (addresses reviewer concerns 4 + 6)

### 5.1 What V2 does NOT change about V1 PoR

- Challenge generation: deterministic random (file, chunk, node) selection at every `CHALLENGE_INTERVAL_BLOCKS = 100` blocks ([state/storage_metadata.rs:514](../../crates/state/src/storage_metadata.rs#L514))
- Settlement: `SubmitStorageProof` pays from `fee_pool` capped by `CHALLENGE_REWARD = 10 Koppa` ([storage_metadata.rs:478-492](../../crates/state/src/storage_metadata.rs#L478))
- Slashing: `SLASH_PERCENTAGE = 5` of staked balance on TTL-expired challenge

V2 doesn't introduce Filecoin-style PoRep, Arweave-style randomized recall packing, or per-chunk continuous proof. Those would be a separate redesign with their own scope. **V2's value is privacy, not stronger storage proofs.**

> **Update (issue #81): shipped and gated.** A deterministic, bounded,
> assignment-aware challenge scheduler that guarantees per-chunk-assignment
> coverage over time without an `O(files × chunks)` sweep is specified in
> [snip-assignment-aware-por-scheduling.md](./snip-assignment-aware-por-scheduling.md).
> Phase 1 (`por_assignment_targeting_enabled_from_height`) and Phase 2
> (`assignment_aware_por_scheduler_enabled_from_height`) are implemented and
> **deployed in runtime genesis, activation-gated at height 9,200,000** (two of
> the seven post-supply gates). Below the gate the v1 probabilistic selector
> above remains the only active path; at height 9,200,000 the extension activates
> automatically. Neither gate is exposed by `chain_getChainParams`, so runtime
> genesis is the source of truth.

### 5.2 Initial replication proof (revised v3 — `AcceptAssignmentV2` brought into Phase 1)

V2 ships **with** an on-chain initial replication attestation, contrary to v2 of this plan. Reviewer pointed out that without it, malicious or premature activation slashes honest archives — unacceptable for testnet third-party archive participation.

**Flow:**
- Owner submits `RegisterFilePendingV2` (locks deposit, creates Pending row, snapshots active-archive set at registration height).
- Owner pushes chunks to assigned archive nodes off-chain.
- **Each assigned archive submits `AcceptAssignmentV2 { merkle_root, chunk_indices }`** attesting to having received and stored those chunks. **Bitmap OR-merge** semantics (v3.2): each tx sets bits in the per-`(file, archive)` bitmap; resubmits OR additional bits in, and already-set bits are a no-op (success receipt, not "already-set" error). Multi-tx submission is the supported way to attest more than `max_chunk_indices_per_tx` (default 65,536) bits — no cumulative cap.
- `ActivateFileV2` is only valid once **every chunk index in `[0, chunk_count)` has at least one accepting archive** that is in the snapshot and currently `Active`.
- `activation_grace_blocks` (default 50, ~100s at 2s blocks) still applies post-activation to absorb in-flight retries.

**What expiry/slashing actually does today (corrected from v2):** [executor.rs:1897-1951](../../crates/state/src/executor.rs#L1897-L1951) handles expired challenges by slashing the target node 5% of staked balance and marking it `Slashed`, then deleting the challenge. **`fee_pool` is never touched on missed proofs.** Successful proofs pay from `fee_pool` at [storage_metadata.rs:478-492](../../crates/state/src/storage_metadata.rs#L478-L492).

So if `AcceptAssignmentV2` were absent and an archive were assigned chunks it never received, expiry would slash the honest archive's stake without recourse — a real attack vector. Adding `AcceptAssignmentV2` removes the vector at the cost of one extra tx per (archive × file) pair pre-activation.

**Failure mode that remains (out of scope for V2):** owner can register a file but never push to any archive. Archives never `AcceptAssignmentV2`, so `ActivateFileV2` never becomes valid. After the grace window, owner can `AbandonFileV2` for a 90% refund (default `abandonment_fee_percent = 10`). Net effect: 10% of `fee_deposit` is **burned** (per §3.5 — no treasury credit), no slashing of any archive. Acceptable: owner pays a small anti-grief penalty, no honest party loses stake.

### 5.3 Archive-node assignment snapshot (Ask 15, revised v3)

**Decision: Option A (height-based) with snapshot-on-change.** Re-flipped from v1 of this plan. Without the three-stream emission argument that justified Option B, height-based is the smaller delta.

Implementation:
- New column family `active_archive_nodes_history` keyed by `[height_be_bytes_8]` → `Vec<NodeRecord>`.
- **Genesis snapshot** (added per reviewer advice): an entry at key `height = 0` written at chain genesis containing whatever archive nodes are present at genesis (empty `Vec` if none). This guarantees `storage_getActiveNodesAtHeight(0)` always returns a defined value.
- After genesis, a snapshot is written **only** when the active-archive-node set changes — i.e. on `RegisterArchiveNode` execution, `UpdateStatus { Slashed }`, expired-challenge slashing, or any future archive-exit op. Steady-state storage cost ~O(churn_events × archives) instead of O(blocks × archives).
- `RegisterFilePendingV2` writes `assignment_height = current_block_height` into the V2 file row (depends on §2.1 plumbing fix).

**Reverse-lookup behavior** (specified per reviewer advice):
- `storage_getActiveNodesAtHeight(h)` finds the largest stored key `k ≤ h` in `active_archive_nodes_history` and returns its value. The current implementation does a forward scan (RocksDB lex-asc = numeric-asc on `[height_be_bytes_8]`, stops once the iterator passes `h`); a reverse-seek migration is queued in [crates/state/src/node_registry.rs](../../crates/state/src/node_registry.rs) `get_active_archive_nodes_at_height` to land before this becomes a public high-traffic RPC. Same observable behavior either way.
- For `h = 0` or `h` < first post-genesis change → returns the genesis snapshot.
- For `h` > head height → returns the **most recent snapshot** (no `Err` and no `None`). Saves a round-trip for clients querying near head; "what does the chain currently know" is the right answer rather than rejecting the query. Implementation and tests both encode this contract.
- Caller behavior for files registered before the bug fix in §2.1 lands: `assignment_height` will be `0`, so the lookup returns the genesis snapshot. Acceptable for V1 → V2 migration (no V2 files exist yet).

**Snapshot stability:** once written, never mutated. A node leaving the active set after a file is registered retains its assignment within that epoch. Issue #62 (§5.4) adds owner-triggered reassignment that **layers a new epoch** pointing at a later (already-immutable) snapshot — it never mutates the original snapshot or `assignment_height`.

### 5.4 Archive-node exit / reassignment

**Update (issue #62): deterministic reassignment is now implemented and deployed.** The original V2 shipped with no reassignment (documented below as historical context). Chunk reassignment exists behind `archive_reassignment_enabled_from_height` (fresh-chain default `None`; on mainnet the gate is **set to height 8,900,000 — active once the chain reaches it (≈2026-07-12)**, height 8,716,604 · 2026-07-06). When active, a file's owner submits `ReassignChunksV2 { merkle_root }` to advance the file's **assignment epoch** to the current active-archive snapshot, so replacement archives are assigned and can attest after an originally-assigned archive leaves the active set.

Design (as implemented):
- **Per-file, snapshot-layered epochs.** Epoch 0 is the file's `assignment_height`; each `ReassignChunksV2` appends the current block height as a new epoch. Reassignment heights are stored in the `file_reassignments` CF (`merkle_root → Vec<u64>`); `StorageMetadataV2` is unchanged. Assignment for each epoch uses the existing deterministic `assigned_archives(...)` over `storage_getActiveNodesAtHeight(epoch_height)`.
- **Owner-triggered only** (no automatic chain-wide sweep); rejected as a no-op (`334`) unless a latest-epoch archive has left the active set; `Abandoned` files rejected (`333`).
- **Epoch-aware attestations.** Epoch-0 bitmaps stay in `assignment_attestations_v2` (untouched); replacement attestations live in `assignment_attestations_v2_epoch` (`[b'R', merkle_root, epoch_height, archive]`). `AcceptAssignmentV2` targets the latest epoch; an **Active** file may be re-attested only while the gate is open and a reassignment epoch exists (else `335`).
- **Aggregate coverage.** `covered_count` / `ActivateFileV2` union across epoch 0 + all reassignment epochs, currently-Active archives only. `storage_getAssignmentCoverageV2` gains `assignment_epochs`, `latest_assignment_epoch`, `reassignment_needed`, and `per_epoch` (top-level `per_archive` stays epoch-0-only).
- **PoR challenge generation is unchanged.** Receipt codes 330–335.

Client-facing summary + coverage fields: [SNIP-V2-RPC-CHEATSHEET.md](../rpc/SNIP-V2-RPC-CHEATSHEET.md) §"Archive-node reassignment". Code: [crates/state/src/storage_metadata.rs](../../crates/state/src/storage_metadata.rs), receipt strings in [crates/primitives/src/receipt.rs](../../crates/primitives/src/receipt.rs).

**Historical context (original V2 behavior, still the default below the gate until the chain crosses 8,900,000):** V2 did not implement reassignment. When a snapshotted node left (exit or slashed-to-inactive), files registered before its exit lost effective replication for any chunks assigned to it; PoR challenges to that node failed and slashed (the V1 economic response), but chunks were not redistributed. Reassignment was deferred because it requires either a `Reassign` tx or chain-driven reassignment — deliberately kept out of the initial V2 scope and delivered separately as #62.

### 5.5 Challenge coverage guarantees

The V1 random selection over `(file, chunk, node)` does not guarantee that any specific chunk is challenged within a bounded window. Expected blocks-until-first-challenge for a specific chunk in a file with `N` chunks: `100 × N × num_funded_files`. For a 1 GB file (1024 chunks) in a registry of 1000 funded files, that's ~10^8 blocks — effectively unbounded in steady state.

**This is a V1 property, not a V2 regression.** Documenting because reviewer asked.

A meaningful coverage guarantee (e.g. "every chunk challenged at least once per epoch") would require per-file or per-chunk challenge scheduling — substantial PoR redesign. Out of scope for V2.

---

## 6. Ask-by-ask response (consolidated)

| Ask | Status | Notes |
|---|---|---|
| **1** V1 deployment + testnet RPC | V1 deployed locally; no public testnet endpoint yet | Hosted testnet ETA ~1 wk after V2 schemas land |
| **2** Tx/block size limits | Documented (Appendix B) | New consensus param: `max_access_list_bytes` (default 16,384) |
| **3** RegisterEncryptionKey + account_getEncryptionPublicKey | Accepted | §3.3 |
| **4** RegisterFilePendingV2 | Accepted | Byte-size cap on `initial_access`, not entry count (§3.4) |
| **5** AddAccess / RemoveAccess / UpdateAccess V2 | Accepted | Active-only |
| **6** StorageFileInfoV2 + storage_getFileInfoV2 | Accepted | Pagination on access list |
| **7** Bundle storage on-chain (~80 B/recipient) | Confirmed; see byte cap | ~148 Private recipients per file under default cap |
| **8** chain_getBlockHeight | Accepted | §4 |
| **9** Push-validation source (lazy + warm cache) | Confirmed | TTL 60s prod / 10s dev fine |
| **10** File rotation roadmap | Reserved schema hooks (`predecessor_root`, `Rotated` lifecycle) | No v1 commit |
| **11** chain_getTransactionStatus | Accepted with `Unknown` + `Dropped` extensions | Finality is consensus-mode-aware (depth=3 PoA / depth=0 BFT) |
| **12** ActivateFileV2 + grace period | Accepted **with on-chain replication attestation via `AcceptAssignmentV2`** (§3.6 reworked v3.2 to bitmap OR-merge in dedicated CF; §5.2) | Default `activation_grace_blocks` = 50 (~100s) — confirm or push for 150 (~5min); `max_chunk_count_per_file = 1_048_576`, `max_chunk_indices_per_tx = 65_536`, `assignment_replication_factor = 3` |
| **13** AbandonFileV2 | Accepted | 10% percentage abandonment fee; reuses grace param for anti-grief min |
| **14** Activation race rule | Confirmed | Archive-node-side concern; chain exposes lifecycle field |
| **15** Assignment-snapshot | **Option A (height-based)** with snapshot-on-change | §5.3 |

---

## 7. Phasing — what SNIP can start when

**Phase 0a (now → ~3 days):**
- Fix block-height plumbing in V2 executor (§2.1)
- Stand up local docker compose for SNIP client work
- Document V1↔V2 differences cheat-sheet for SNIP

**Phase 0b (week 1):**
- Asks 8, 11 (`chain_getBlockHeight`, `chain_getTransactionStatus`)
- Ask 3 (`RegisterEncryptionKey` + `account_getEncryptionPublicKey`)
- Ask 15 (height-based snapshot column family + RPC)

**Phase 1 (weeks 2–3):**
- Asks 4, 5, 6, 12, 13, 14 (full V2 storage schema, lifecycle, bundle storage, activation grace, abandonment)
- **`AcceptAssignmentV2`** (§3.6, §5.2) — brought into Phase 1 per reviewer advice
- All V2 storage RPCs

**Phase 2 (weeks 3–4):**
- Hosted testnet endpoint
- End-to-end integration tests with SNIP client

No Phase 3 in this plan. Anything beyond Phase 2 is a separate track.

---

## 8. Open items — needs decision

1. **`activation_grace_blocks`** (Ask 12): 50 (~100s) or 150 (~5min)?
2. **`max_access_list_bytes`** (Ask 4): default 16,384 OK, or larger (1 MB block can support up to ~9 K Private entries, but storage cost grows linearly)?
3. **`abandonment_fee_percent`** (Ask 13): 10% reasonable or counter-propose?
4. **Snapshot-on-change scope** (Ask 15): trigger snapshots on archive registration/status changes only, or also on validator changes? V2 only needs the former.
5. **Public-testnet RPC URL**: SNIP's preferred host/region for the hosted testnet endpoint?

---

## 9. Out of scope — separate tracks

These are real concerns that will need work eventually, but **none should block SNIP V2.** Each requires its own track:

| Topic | Why deferred | Where it should live |
|---|---|---|
| OmniNode role-combination | Requires `NodeRecord` schema redesign; affects validators, archives, future roles. Independent of SNIP. | Internal chain-team design doc |
| Token emissions / mining-style PoR rewards | Contradicts current economic model ([docs/architecture/economic-model.md](../architecture/economic-model.md) — fixed supply). Requires formal economic-model revision (v3.0 → v4.0) and governance approval. | Future tokenomics-extension proposal |
| Decentralized AGI compute (PoC) | Requires verifiable-compute primitives (zk-ML, challenge-response for compute, oracle/benchmark eval). Independent project. | Separate spec |
| File rotation / true revocation (Ask 10) | Schema hooks reserved (`predecessor_root`, `Rotated` lifecycle); design defers | v2.x SNIP work |
| Reassignment on archive-node exit | **Implemented and active on mainnet** (issue #62; gate set to 8,900,000, reached): owner-triggered `ReassignChunksV2` with per-file snapshot-layered epochs; see §5.4 | Delivered |
| Filecoin-grade challenge coverage | Requires per-file or per-chunk challenge scheduling | v3 storage redesign |

---

## 10. For the reviewer — what changed and what to scrutinize

**What changed from v1:**
- Removed all economic-model proposals (emissions, splits, halving, derived `CHALLENGE_REWARD`)
- Removed OmniNode dependency
- Re-flipped Ask 15 to Option A
- Recomputed access-list cap with bincode encoding; switched to byte-size cap
- Added §2.1 prerequisite (block-height plumbing fix)
- Added §5 operational semantics with explicit acknowledgment of what V2 does NOT promise (initial replication, reassignment, challenge coverage)

**What changed in v3.2 (post-SNIP-review of v3.1):**
- §3.6 reworked from `Vec<u32>`-replacement to **bitmap OR-merge** in a dedicated `assignment_attestations_v2` CF — resolves the cap-vs-replacement contradiction
- §3.4 adds `max_chunk_count_per_file = 1_048_576`, `max_chunk_indices_per_tx = 65_536`, `assignment_replication_factor = 3`
- §3.6 specifies the exact deterministic assignment function (rendezvous-hash over domain-separated `blake3::derive_key("sumchain SNIP-V2 chunk-assignment v1", merkle_root ‖ chunk_index_be ‖ archive_address)`; BLAKE3 to match the chain's hashing convention)
- §4 adds `storage_getAssignmentCoverageV2` with `missing_offset` defined as a chunk-index lower bound (stable pagination), no raw `Vec<u32>` per archive in response
- §3.6 enumerates the test matrix Phase 1b must pass

**What to scrutinize most in v2:**
1. §2.1 block-height fix scope — is one-line change at each call site sufficient, or does it need broader executor refactor?
2. §3.4 byte-cap math — is `max_access_list_bytes = 16_384` the right default, or should it be smaller (privacy: smaller files don't leak as much recipient-set size info) or larger (utility)?
3. §5.2 initial replication failure mode — is the "owner gets fee_pool drained / archives get slashed for missing pushes" outcome acceptable for v2, or do we need `AcceptAssignmentV2` in this plan after all?
4. §5.3 snapshot-on-change — is the implementation overhead (writing on every `Register`/`UpdateStatus`) cheap enough, or should we just do dense per-block snapshots and accept the storage cost?
5. §5.4 / §5.5 "no worse than V1" framing — fair, or are we papering over V1 issues that should block V2?
6. §3.3 low-order X25519 point rejection — small but security-load-bearing. Confirm the seven blocklist entries (matching libsodium `crypto_scalarmult` `has_small_order`) are exhaustive for the `RegisterEncryptionKey` validation surface, and that registration-time rejection (rather than per-call wrap-time rejection) is the right place to enforce.

**What to scrutinize most in v3.2:**
7. §3.6 deterministic assignment function — domain-separated BLAKE3 (`derive_key("sumchain SNIP-V2 chunk-assignment v1", …)`) over `merkle_root ‖ chunk_index_be ‖ archive_address` with rendezvous-hash top-R selection. Is `R = 3` the right default, and is the snapshot-stable + sort-by-address tie-break sufficient for SNIP's push logic to recompute the same assignments client-side?
8. §3.6 dedicated `assignment_attestations_v2` CF + bitmap retention post-activation — accept the small ongoing state cost (worst case 128 KB × N_archives per activated file) until a future `GcAttestationsV2`, or GC at activation time?
9. §4 `storage_getAssignmentCoverageV2.missing_offset` as chunk-index lower bound (not list offset) — confirms stable pagination under concurrent accept; SNIP push loop should be a simple "fetch window, push, attest, advance offset" cycle.

---

## Appendix A — V1 reference (for SNIP)

- V1 storage primitives: [crates/primitives/src/storage_metadata.rs](../../crates/primitives/src/storage_metadata.rs)
- V1 storage executor: [crates/state/src/storage_metadata.rs](../../crates/state/src/storage_metadata.rs)
- V1 node registry: [crates/primitives/src/node_registry.rs](../../crates/primitives/src/node_registry.rs), [crates/state/src/node_registry.rs](../../crates/state/src/node_registry.rs)
- V1 RPC API: [crates/rpc/src/api.rs](../../crates/rpc/src/api.rs)
- Consensus engines: [crates/consensus/src/poa.rs](../../crates/consensus/src/poa.rs), [crates/consensus/src/bft/engine.rs](../../crates/consensus/src/bft/engine.rs)
- Genesis / consensus params: [crates/genesis/src/lib.rs](../../crates/genesis/src/lib.rs)
- Economic model (read this before proposing economic changes): [docs/architecture/economic-model.md](../architecture/economic-model.md)
- Local dev cluster: [docker-compose.yaml](../../docker-compose.yaml), [configs/local/](../../configs/local)
- X25519 cryptography (already in repo, unused by storage today): [crates/crypto/src/messaging.rs](../../crates/crypto/src/messaging.rs)

## Appendix B — Constants reference

| Constant | V1 value | V2 status |
|---|---|---|
| `max_block_bytes` | 1,000,000 (1 MB) | unchanged |
| `max_txs_per_block` | 1,000 | unchanged |
| `max_metadata_bytes` | 16,384 | unchanged |
| `finality_depth` (PoA) | 3 | unchanged |
| `block_time_ms` | 2,000 | unchanged |
| `CHUNK_SIZE` | 1,048,576 (1 MB) | unchanged |
| `CHALLENGE_TTL_BLOCKS` | 50 | unchanged |
| `CHALLENGE_INTERVAL_BLOCKS` | 100 | unchanged |
| `CHALLENGE_REWARD` | 10 Koppa | **unchanged** (reverted from v1 of plan) |
| `SLASH_PERCENTAGE` | 5 | unchanged |
| Mempool per-sender cap | 100 txs | unchanged |
| `max_access_list_bytes` | — | **NEW V2: 16,384** (byte cap, not entry count) |
| `activation_grace_blocks` | — | **NEW V2: 50 (proposed)** |
| `abandonment_fee_percent` | — | **NEW V2: 10 (proposed)** |
| `LOW_ORDER_X25519_POINTS` | — | **NEW V2:** 7-entry blocklist for `RegisterEncryptionKey` validation, [crates/crypto/src/messaging.rs](../../crates/crypto/src/messaging.rs); matches libsodium `crypto_scalarmult` `has_small_order` |
| `max_chunk_count_per_file` | — | **NEW v3.2: 1,048,576** (caps bitmap row at 128 KB; rejects `RegisterFilePendingV2` above this) |
| `max_chunk_indices_per_tx` | — | **NEW v3.2: 65,536** (per-tx cap on `AcceptAssignmentV2.chunk_indices`; real per-tx cap, not cumulative) |
| `assignment_replication_factor` | — | **NEW v3.2: 3** (rendezvous-hash R; assignment fn is `min(R, snapshot.len())`) |
| `assignment_attestations_v2` (CF) | — | **NEW v3.2:** dedicated RocksDB column family keyed `[b'A', root_32, archive_20]` → `Vec<u8>` bitmap; see §3.6 |

## Appendix C — Deterministic assignment test vectors (v3.2)

These are conformance vectors for the assignment function in §3.6. **Executor, `storage_getAssignmentCoverageV2`, and SNIP push logic must each reproduce every output below byte-for-byte.** Phase 1b's test suite must include these as fixtures; SNIP-side client tests should pull from the same fixture file.

**Inputs (constructed deterministically so any implementation can regenerate them):**

| Input | Construction |
|---|---|
| `merkle_root[i]` for `i ∈ {0,1,2}` | `blake3::hash(format!("snip-v2-test-file-{}", i+1).as_bytes()).as_bytes()` |
| `archive[j]` for `j ∈ {0..5}` | `blake3::hash(format!("snip-v2-archive-{}", j+1).as_bytes()).as_bytes()[..20]` |
| `snapshot` | `[archive[0], archive[1], archive[2], archive[3], archive[4]]` (any order — assignment fn sorts internally) |
| Context string | exactly `"sumchain SNIP-V2 chunk-assignment v1"` (37 bytes, no trailing newline) |

```
merkle_root[0] = 0xa5e2668f5022b62b5e4a1342aa0cfbfcbde2af2e3626b2fd57d6cf44e8f615a4
merkle_root[1] = 0xeed453d08260268bbd3675997f407174d901d842711f3addb6a2e05f776bccce
merkle_root[2] = 0x81137f39ea2a36bae5333d021052c44c0fc4763769c9988241e6669af16dfa74

archive[0] = 0x37c4401960bd5a26d8ed7b676b1ef47c78fac5bb
archive[1] = 0xf1a469857483cc381865df996b2cccd254878a16
archive[2] = 0x8c6a62e786d02ae255a6f481580b95fe05bafffc
archive[3] = 0xf8967230e6a6d6b5b4ce6816d43f406f24d3cdad
archive[4] = 0x7e65c99f5b3994f2014187f24ee9230a027526bd
```

**Per-archive scores for `(merkle_root[0], chunk_index=0)`** — verify your implementation produces these exact `u64` scores (`u64::from_be_bytes(blake3::derive_key(CTX, root || idx_be || addr)[..8])`):

| Archive | Score (BE u64, hex) |
|---|---|
| `0x7e65c99f5b3994f2014187f24ee9230a027526bd` (archive[4]) | `0x4cd8130d5f5c7f55` |
| `0x8c6a62e786d02ae255a6f481580b95fe05bafffc` (archive[2]) | `0x73e9ad5ef9a6ba04` |
| `0xf1a469857483cc381865df996b2cccd254878a16` (archive[1]) | `0xc8859dade38f7649` |
| `0xf8967230e6a6d6b5b4ce6816d43f406f24d3cdad` (archive[3]) | `0xd2823bf6a2d883bb` |
| `0x37c4401960bd5a26d8ed7b676b1ef47c78fac5bb` (archive[0]) | `0xf3c350979cb3f293` |

**Assignment outputs** — `assigned_archives(merkle_root[i], snapshot, chunk_index, R)`. Output is the ordered list of selected archives (ascending by `(score, address)`):

| `i` | `chunk_index` | `R` | Expected output |
|---|---|---|---|
| 0 | 0  | 1 | `[0x7e65c99f5b3994f2014187f24ee9230a027526bd]` |
| 0 | 0  | 3 | `[0x7e65c99f5b3994f2014187f24ee9230a027526bd, 0x8c6a62e786d02ae255a6f481580b95fe05bafffc, 0xf1a469857483cc381865df996b2cccd254878a16]` |
| 0 | 7  | 3 | `[0xf8967230e6a6d6b5b4ce6816d43f406f24d3cdad, 0x37c4401960bd5a26d8ed7b676b1ef47c78fac5bb, 0x7e65c99f5b3994f2014187f24ee9230a027526bd]` |
| 1 | 0  | 3 | `[0xf1a469857483cc381865df996b2cccd254878a16, 0x8c6a62e786d02ae255a6f481580b95fe05bafffc, 0x37c4401960bd5a26d8ed7b676b1ef47c78fac5bb]` |
| 1 | 1  | 3 | `[0x7e65c99f5b3994f2014187f24ee9230a027526bd, 0x8c6a62e786d02ae255a6f481580b95fe05bafffc, 0xf8967230e6a6d6b5b4ce6816d43f406f24d3cdad]` |
| 2 | 42 | 3 | `[0xf1a469857483cc381865df996b2cccd254878a16, 0x8c6a62e786d02ae255a6f481580b95fe05bafffc, 0xf8967230e6a6d6b5b4ce6816d43f406f24d3cdad]` |
| 2 | 42 | 5 | `[0xf1a469857483cc381865df996b2cccd254878a16, 0x8c6a62e786d02ae255a6f481580b95fe05bafffc, 0xf8967230e6a6d6b5b4ce6816d43f406f24d3cdad, 0x37c4401960bd5a26d8ed7b676b1ef47c78fac5bb, 0x7e65c99f5b3994f2014187f24ee9230a027526bd]` |
| 2 | 42 | 7 | `[0xf1a469857483cc381865df996b2cccd254878a16, 0x8c6a62e786d02ae255a6f481580b95fe05bafffc, 0xf8967230e6a6d6b5b4ce6816d43f406f24d3cdad, 0x37c4401960bd5a26d8ed7b676b1ef47c78fac5bb, 0x7e65c99f5b3994f2014187f24ee9230a027526bd]` (R=7 clamps to `snapshot.len()=5`) |

The last row is the explicit `R > snapshot.len()` clamp test — output identical to `R=5`. The R=1 row exercises that `R'=1` returns only the lowest-scoring archive. The R=3 rows exercise the common case. The two `chunk_index ≠ 0` rows show that changing `chunk_index` produces a totally different assignment.

If your implementation produces different bytes for any cell above, the most likely causes are: (a) wrong context string (trailing newline, wrong casing, "v2" instead of "v1"), (b) using `blake3::keyed_hash(blake3::hash(CTX), input)` instead of `blake3::derive_key(CTX, input)`, (c) wrong `chunk_index` byte order (must be big-endian), or (d) snapshot deduplication differs from the spec (must be sort-and-dedup by 20-byte address ascending).

---

*End of plan v3.2. SNIP review of v3.1 approved the bitmap-merge direction with three clarifications (storage CF, missing_offset semantics, assignment-fn spec) — all three folded in; assignment fn now uses BLAKE3 to match the chain's hashing convention; v3.2 final adds chunk_count canonical-derivation rule, exact `blake3::derive_key` API in pseudocode, conformance test vectors (Appendix C), and explicit "burn" semantics for the abandonment retain. Phase 1b implements against this v3.2 design, not the v3.1 `Vec<u32>`-replacement wording.*
