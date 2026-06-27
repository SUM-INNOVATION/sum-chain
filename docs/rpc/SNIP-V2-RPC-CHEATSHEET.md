# SNIP V2 — RPC Cheatsheet for Client Developers

**Audience:** SNIP-side engineers integrating against the SUM Chain V2 RPC surface.
**Source of truth:** [crates/rpc/src/api.rs](../../crates/rpc/src/api.rs) (the jsonrpsee trait) and the JSON-shape tests in [crates/rpc/src/server.rs](../../crates/rpc/src/server.rs). Where this doc disagrees with those, those win.
**Locally testable:** spin up `docker-compose -f deploy/snip-local-mirror.yaml up -d` (chain_id 31337) and curl `http://localhost:8545`.

---

## Important behaviors that have bitten people

These three items have caused real bugs during chain-side integration tests. Read first.

### 1. Receipt key is `SignedTransaction::hash()`, NOT `signing_hash()`

When you submit a tx via `send_raw_transaction` and need the receipt:
- The chain stores receipts keyed by **`SignedTransaction::hash()`** — i.e. the BLAKE3 hash of the *signed envelope* including the signature. ([crates/consensus/src/poa.rs:419,460-468](../../crates/consensus/src/poa.rs#L419-L468))
- **Not** by `signing_hash()` (the unsigned-bytes hash, which is what you sign).

```rust
// Wrong — the chain has no receipt under this hash:
let h = tx.signing_hash();  // unsigned hash
let signed = SignedTransaction::new_v2(tx, sig, pubkey);
client.get_receipt(h)?;     // returns None forever

// Right:
let signed = SignedTransaction::new_v2(tx, sig, pubkey);
let tx_hash = signed.hash();  // <-- this is what receipts are keyed by
client.get_receipt(tx_hash)?;
```

`Mempool::add` returns this same `signed.hash()`, so simplest pattern: capture submit's return value.

### 2. `assigned_count` is `Option<u32>`, JSON `null` for large files

`storage_getAssignmentCoverageV2` returns one entry per archive in `per_archive`. The `assigned_count` field is **`Option<u32>`**:

- `Some(n)` when `chunk_count <= 16,384` (the chain computed it server-side).
- **`null` when `chunk_count > 16,384`** — the chain declined to compute, to bound RPC cost.

```jsonc
{
  "per_archive": [
    {
      "archive": "ArchiveAddr1",
      "assigned_count": 142,        // small file: chain computed
      "attested_count": 142,
      "currently_active": true
    },
    {
      "archive": "ArchiveAddr2",
      "assigned_count": null,       // large file: client computes locally
      "attested_count": 0,
      "currently_active": true
    }
  ]
}
```

When you see `null`, compute locally using the **same deterministic function the chain uses**:

```rust
use sumchain_primitives::assigned_archives_presorted;

let mut snapshot: Vec<Address> = response.per_archive.iter().map(|p| p.archive.into()).collect();
snapshot.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
snapshot.dedup_by(|a, b| a.as_bytes() == b.as_bytes());

let r = chain_params.assignment_replication_factor;  // from chain_getChainParams
let mut counts: HashMap<Address, u32> = HashMap::new();
for chunk_idx in 0..response.chunk_count {
    for a in assigned_archives_presorted(&merkle_root, &snapshot, chunk_idx, r) {
        *counts.entry(a).or_insert(0) += 1;
    }
}
```

Conformance vectors for `assigned_archives_presorted` are in [SNIP-V2-CHAIN-PLAN.md Appendix C](../specs/SNIP-V2-CHAIN-PLAN.md). Your implementation MUST reproduce them byte-for-byte.

### 3. Mainnet integration is read-only unless separately approved

V2 schemas + RPCs are **not** live on mainnet today. Hitting a mainnet RPC with a V2 tx will fail. Until V2 is shipped to mainnet via a chain upgrade (a separate, larger initiative — see [SNIP-V2-TESTNET-DEPLOYMENT-PREP.md](../archive/SNIP-V2-TESTNET-DEPLOYMENT-PREP.md) §"Mainnet V2 testing"):

- Read-only against mainnet (`chain_id`, `get_balance`, etc.) is fine.
- Any **V2 tx submission** (`RegisterFilePendingV2`, `AcceptAssignmentV2`, `ActivateFileV2`, etc.) must target the local mirror or a future hosted V2 testnet — never mainnet without explicit approval.

---

## Tx submission shape (V2 envelope)

```rust
let tx = TransactionV2 {
    chain_id: <from chain_getChainParams.chain_id>,
    from: <signer address>,
    fee: <Koppa, >= chain_getChainParams.min_fee>,
    nonce: <from get_nonce(signer)>,
    payload: TxPayload::StorageMetadataV2(...),  // or NodeRegistryV2, etc.
};
let signing_hash = tx.signing_hash();           // sign over THIS
let sig = ed25519_sign(signing_hash, private_key);
let signed = SignedTransaction::new_v2(tx, sig, public_key);
let tx_hash = signed.hash();                    // KEEP — receipts are keyed by this

let bytes = bincode::serialize(&signed)?;
let _ = rpc("send_raw_transaction", [hex::encode(bytes)])?;
```

**Fee economics**: V2 ops carry a per-tx `fee` paid to the block proposer (V1 mechanic), plus operation-specific deposits/refunds documented per op:
- `RegisterFilePendingV2.fee_deposit` — locked into `fee_pool`, repays archive nodes for PoR proofs.
- `AbandonFileV2` — refunds `(100 - abandonment_fee_percent)%` of `fee_pool`; remainder is **burned** (no treasury credit).
- `AcceptAssignmentV2`, `ActivateFileV2`, `Add/Remove/UpdateAccessV2` — fee-only, no extra deposit.

---

## Finality polling pattern

`chain_getTransactionStatus` collapses receipt lookup + finality check into one call:

```rust
loop {
    match rpc("chain_getTransactionStatus", [tx_hash])? {
        TxStatusV2::Pending => sleep(block_time_ms),
        TxStatusV2::Included { block_height } => sleep(block_time_ms),  // wait for finalization
        TxStatusV2::Finalized { block_height } => return Ok(block_height),
        TxStatusV2::Failed { block_height, reason } => return Err((block_height, reason)),
        TxStatusV2::Unknown => sleep(block_time_ms),  // not in mempool yet, or evicted
        TxStatusV2::Dropped => return Err("dropped"),  // reserved; not currently emitted
    }
}
```

**Caveats:**
- Under PoA (`finality_depth = 3`), `Failed { block_height }` in an unfinalized block can in principle reorg out. Treat `Failed` as terminal only once `block_height <= chain_getBlockHeight("finalized").height`.
- `Unknown` ≠ tx never sent. The mempool doesn't track evictions, so an evicted tx also returns `Unknown`. If you see `Unknown` after a successful `send_raw_transaction`, retry-submit after the mempool TTL.

`block_time_ms`, `finality_depth` come from `chain_getChainParams` — don't hardcode.

---

## File lifecycle RPC sequence (the canonical SNIP V2 flow)

```
┌─────────────┐
│ 0. setup    │  - All recipients register X25519 via NodeRegistryV2::RegisterEncryptionKey
└──────┬──────┘    (skip if Public file)
       v
┌─────────────────────────────┐
│ 1. RegisterFilePendingV2    │  Owner locks fee_deposit, snapshots active-archive set
└──────┬──────────────────────┘
       v
┌─────────────────────────────────────┐
│ 2. push chunks off-chain to assigned│  (chain doesn't see this; archives + owner coordinate
│    archives                         │   via SNIP-side push protocol; assignment is
└──────┬──────────────────────────────┘   `assigned_archives_presorted(merkle_root, snapshot, idx, R)`)
       v
┌─────────────────────────────┐
│ 3. AcceptAssignmentV2 from  │  Each archive submits chunk_indices for the chunks it has;
│    each assigned archive    │  ORs into the per-(file, archive) bitmap.
└──────┬──────────────────────┘
       v
┌─────────────────────────────────┐
│ 4. poll storage_getAssignment-  │  Owner waits for can_activate_now == true.
│    CoverageV2 until            │  Use `missing_offset` (chunk-index lower bound) for
│    can_activate_now == true    │  stable pagination through `missing_indices`.
└──────┬──────────────────────────┘
       v
┌─────────────────────────────┐
│ 5. ActivateFileV2           │  Pending → Active. PoR challenges become eligible
│                             │  after activation_grace_blocks past activation height.
└──────┬──────────────────────┘
       v
[Active — file now serveable]

       │ optional any time during Active:
       v
┌─────────────────────────────────────────────┐
│ 6. AddAccessV2 / RemoveAccessV2 /           │  Mutate access list. Active-only.
│    UpdateAccessV2                           │
└─────────────────────────────────────────────┘

       │ alternative if push never completes:
       v
┌──────────────────────────────────────────┐
│ 6'. AbandonFileV2 (after grace window)   │  Refund (100 - abandonment_fee_percent)%
│                                          │  of fee_pool; remainder burned.
└──────────────────────────────────────────┘
```

**Stable polling for missing chunks** (Step 4):

```rust
let mut missing_offset: u32 = 0;
loop {
    let cov = rpc("storage_getAssignmentCoverageV2",
                  [merkle_root, missing_offset, 1024])?;
    if cov.can_activate_now { break; }
    if cov.missing_indices.is_empty() { sleep(block_time_ms); continue; }
    // ... push to archives that should have these chunks ...
    missing_offset = cov.missing_indices.last().unwrap() + 1;
    // Re-pages from the new offset; concurrent attestations don't cause
    // backwards re-pagination since `missing_offset` is a chunk-index lower
    // bound, not a list offset into a server-filtered view.
}
```

---

## RPC reference (V2-relevant subset)

| Method | Purpose |
|---|---|
| `chain_id` | Distinguish mainnet / testnet / local-mirror. Local mirror = 31337. |
| `chain_getChainParams` | Live consensus params — read at startup, don't bake in. |
| `chain_getBlockHeight(finality?)` | `null` or `"latest"` → head; `"finalized"` → safe height. |
| `chain_getTransactionStatus(tx_hash)` | Pending/Included/Finalized/Failed/Dropped/Unknown. |
| `get_nonce(address)` | For tx construction. State nonce, not mempool nonce. |
| `send_raw_transaction(hex_bytes)` | Submit a bincode-serialized SignedTransaction. |
| `account_getEncryptionPublicKey(address)` | X25519 pubkey for a recipient (`null` if unregistered). |
| `storage_getFileInfoV2(merkle_root, offset?, limit?)` | Full V2 file row + paginated access list. |
| `storage_getPushableFilesV2(offset?, limit?)` | Pending+Active files (warm-cache for archive nodes). |
| `storage_getAssignmentCoverageV2(merkle_root, missing_offset?, missing_limit?)` | Coverage progress + missing chunks. |
| `storage_getActiveNodesAtHeight(height)` | Snapshot at `assignment_height` for client-side `assigned_archives_presorted`. |

Defaults: `access_limit = 256` / hard cap 1024; `missing_limit = 1024` / hard cap 16384; `pushable.limit = 256` / hard cap 1024.

---

## `StorageFileInfoV2` fields (returned by `storage_getFileInfoV2`)

| Field | Type | Notes |
|---|---|---|
| `merkle_root` | hex string | File's content merkle root (no `0x` prefix). |
| `owner` | base58 | Address that registered the file. |
| `plaintext_size_bytes` | u64 | Size before encryption (Public files: == stored). |
| `stored_size_bytes` | u64 | Size of bytes archives actually hold. |
| `chunk_count` | u32 | Drives the bitmap and assignment fns. |
| `fee_pool` | u64 | Locked Koppa for PoR / refund settlement. |
| `created_at` | u64 | Block height of `RegisterFilePendingV2`. |
| `activated_at_height` | `u64 \| null` | `null` while Pending or Abandoned; `Some(h)` after `ActivateFileV2`. |
| `abandoned_at_height` | `u64 \| null` | `null` while Pending or Active; `Some(h)` after `AbandonFileV2`. SNIP can drive `IngestOutcome::AbandonedOnChain { abandoned_at_height }` directly off this. |
| `assignment_height` | u64 | Block of the active-archive snapshot used for chunk assignment (input to `assigned_archives_presorted`). |
| `visibility` | `0` Public, `1` Private | |
| `lifecycle` | `0` Pending, `1` Active, `2` Abandoned | |
| `access_list` | array of `AccessEntryRpcV2` | Paginated window `[access_offset .. access_offset + len)`. |
| `access_total` | u32 | Total entries across all pages. |
| `access_offset` | u32 | Echoed back from the request. |
| `predecessor_root` | `hex string \| null` | Reserved for file rotation; always `null` in V2. |

Indexer note: `abandoned_at_height` is the lowest-cost way to learn the exact lifecycle-transition block. It's set by the chain in the same atomic write that flips `lifecycle = 2` and zeroes `fee_pool` — so a single `storage_getFileInfoV2` read is consistent (no need to cross-reference receipts).

---

## Receipt code reference

When `chain_getTransactionStatus` returns `Failed { reason }`, the `reason` string comes from [crates/primitives/src/receipt.rs](../../crates/primitives/src/receipt.rs) `TxStatus::description()`:

| Code | Reason | Most common cause |
|---|---|---|
| `22` | `"low-order x25519 public key rejected"` | `RegisterEncryptionKey` got a libsodium-blocklisted point. Use a freshly-derived X25519 pubkey. |
| `30` | `"RegisterFilePendingV2 validity check failed"` | Visibility/bundle mismatch, recipient X25519 missing, byte-cap exceeded, `chunk_count != ceil(stored_size_bytes / CHUNK_SIZE)`, `chunk_count > max_chunk_count_per_file`, or merkle_root collision. |
| `31` | `"AbandonFileV2 validity check failed"` | Wrong lifecycle (must be Pending), wrong owner, or before `created_at + activation_grace_blocks`. |
| `33` | `"AcceptAssignmentV2 validity check failed"` | Signer not in snapshot/not Active, `chunk_indices` over per-tx cap, index out of range, or index not assigned to signer per the deterministic fn. |
| `34` | `"ActivateFileV2 validity check failed"` | Wrong lifecycle (must be Pending), wrong owner, or coverage incomplete (`covered_count < chunk_count`). |
| `35` | `"V2 access op validity check failed"` | AddAccessV2: duplicate / Public-with-bundle / Private-no-X25519 / byte-cap re-violated. RemoveAccessV2: address absent / removing owner from Private. UpdateAccessV2: `new_entry.address != address` / address absent / visibility-bundle mismatch. |

Codes `20`/`21` (generic NodeRegistryV2 / StorageMetadataV2 fail) currently fall through to `"failed"` — a future change may add specific reasons. SNIP retry logic should **not** assume `"failed"` is permanent.

---

## Quick smoke test against local mirror

```bash
docker-compose -f deploy/snip-local-mirror.yaml up -d --build
# wait ~10 seconds for first block

curl -s -X POST -H 'Content-Type: application/json' \
     --data '{"jsonrpc":"2.0","id":1,"method":"chain_id","params":[]}' \
     http://localhost:8545
# → {"jsonrpc":"2.0","result":31337,"id":1}

curl -s -X POST -H 'Content-Type: application/json' \
     --data '{"jsonrpc":"2.0","id":2,"method":"chain_getChainParams","params":[]}' \
     http://localhost:8545 | python3 -m json.tool
# → flat ChainParamsInfo with V2 fields populated

docker-compose -f deploy/snip-local-mirror.yaml down -v
```

This was the smoke test that verified the preset works end-to-end during Phase 2 close — `chain_id` returned 31337, `chain_getChainParams` returned live V2 params, and block height advanced 1→4 over 6 seconds at the configured 2-second block time.
