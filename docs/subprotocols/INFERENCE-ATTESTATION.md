# OmniNode `InferenceAttestation` v1

**Version:** 1.0.0 (frozen)
**Status:** v1 implemented and merged; **active on mainnet**. Live mainnet parameters verified at height 8,716,604 on 2026-07-06 (deployed commit `21de231d`) report `omninode_enabled_from_height = 6,000,000` (current head > gate). Fresh chains still default to `None` (dormant) until they set the gate.
**Created:** 2026-05-13
**Last Updated:** 2026-07-06
**Authors:** SUM Chain Team
**External spec partner:** OmniNode Protocol (Stage 6 handoff)

---

## Abstract

The OmniNode `InferenceAttestation` subprotocol lets off-chain inference verifiers commit verifier-signed digests of inference outputs to SUM Chain. Each attestation binds a session identifier to a tuple of content hashes (model, manifest, response, proof) signed under OmniNode's Stage 6 signing domain. The chain enforces one attestation per `(session_id, verifier_address)` pair forever, exposes read-only RPC for OmniNode coordinators to enumerate attestations and check status, and uses the existing `sum_sendRawTransaction` submit path so no new submission RPC is introduced.

Wire-format and semantics are frozen for v1. Future changes require either a new `TxPayload` variant (e.g. `InferenceAttestationV2`) or a versioned CF key-domain rotation; the wire-fixture tests in [`crates/primitives/tests/inference_attestation_fixtures.rs`](../../crates/primitives/tests/inference_attestation_fixtures.rs) lock the byte layout against drift.

---

## Table of Contents

1. [Activation](#1-activation)
2. [Submit Path](#2-submit-path)
3. [Digest Wire Format](#3-digest-wire-format)
4. [Address & Signature Encoding](#4-address--signature-encoding)
5. [Executor Dispatch & Failure Codes](#5-executor-dispatch--failure-codes)
6. [Permanent Duplicate Policy](#6-permanent-duplicate-policy)
7. [Mempool Admission](#7-mempool-admission)
8. [Read-only RPC](#8-read-only-rpc)
9. [Status Semantics](#9-status-semantics)
10. [Finality](#10-finality)
11. [V1 Exclusions](#11-v1-exclusions)
12. [Test Vectors & Wire-Fixture Lock](#12-test-vectors--wire-fixture-lock)
13. [References](#13-references)

---

## 1. Activation

The subprotocol is gated by a single chain parameter:

```
omninode_enabled_from_height: Option<u64>
```

defined in [`crates/genesis/src/lib.rs`](../../crates/genesis/src/lib.rs). Production genesis defaults to `None`. Pre-activation, attestation txs are rejected on **two different code paths** with two different surface forms:

- **Mempool admission** rejects with `StateError::OmniNodeNotActivated` returned synchronously from `Mempool::add` (and surfaced through `sum_sendRawTransaction` as an RPC error). The tx never enters the mempool, no receipt is ever produced, and the sender's balance and nonce are unchanged.
- **Executor dispatch** rejects with `TxStatus::Failed(50)` and `fee_paid: 0` in a Receipt. This path is reached only when a tx bypasses mempool admission — e.g. block import from a peer that admitted the tx, or any non-user-submission ingress. Production user submission via `sum_sendRawTransaction` is the mempool-admission path and never produces a `Failed(50)` receipt unless the mempool's admission context is misconfigured.

Upgrading binaries on a running chain does not activate the subprotocol on its own; activation requires:

1. A coordinated chain-params update setting `omninode_enabled_from_height: Some(H)` for some future block height `H`.
2. All validators upgraded to a binary that contains this subprotocol before reaching `H`.

Dev / SNIP local-mirror deployments set `Some(0)` to activate from genesis. The local-mirror Docker preset on the `snip-local-mirror-preset` branch currently sets `v2_enabled_from_height: 0` only; bringing up an OmniNode Stage 5 test against that preset additionally requires adding `omninode_enabled_from_height: 0` to `genesis/snip-mirror-genesis.template.json`. That template change is **not** part of this branch and should land alongside Stage 5 kickoff coordination.

**Gate semantics** ([`crates/state/src/executor.rs`](../../crates/state/src/executor.rs)):

```rust
fn omninode_gate_open(params: &ChainParams, block_height: u64) -> bool {
    matches!(params.omninode_enabled_from_height, Some(h) if block_height >= h)
}
```

---

## 2. Submit Path

The canonical submit path is **the chain's existing** `sum_sendRawTransaction(signed_tx_hex)` RPC method. No new submit method ships in v1.

```
POST /
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "sum_sendRawTransaction",
  "params": ["<hex of bincode(SignedTransaction)>"]
}
```

The `SignedTransaction` carries a `TransactionV2` whose payload is `TxPayload::InferenceAttestation(InferenceAttestationTxData { … })`. Outer signing is unchanged from every other v2 transaction: `BLAKE3(bincode(SignedTransaction))` → Ed25519, no domain prefix. The verifier's chain Address is the outer tx `sender` and is derived from the same Ed25519 public key the outer signature verifies against.

`sender == verifier` is enforced by the executor. The verifier signs (a) the outer tx with the chain's standard signing path AND (b) the inner attestation digest under the OmniNode Stage 6 domain. Both signatures use the same Ed25519 key.

---

## 3. Digest Wire Format

```rust
pub struct InferenceAttestationDigest {
    pub session_id:    String,
    pub model_hash:    [u8; 32],
    pub manifest_root: [u8; 32],
    pub response_hash: [u8; 32],
    pub proof_root:    [u8; 32],
}

pub struct InferenceAttestationTxData {
    pub digest:             InferenceAttestationDigest,
    pub verifier_signature: [u8; 64],
}
```

Defined in [`crates/primitives/src/inference_attestation.rs`](../../crates/primitives/src/inference_attestation.rs). Field order is **frozen** for v1 — bincode serializes structs and enums by declaration order, and historical attestations are bincode-encoded into the `INFERENCE_ATTESTATIONS` CF, so reordering fields silently breaks reads of every persisted record.

### Bincode configuration

**bincode 1.3 default config.** Specifically:

- `String` is length-prefixed with a u64 little-endian length followed by UTF-8 bytes.
- Fixed-size `[u8; N]` arrays serialize as N raw bytes, no length prefix.
- Enum variants carry a u32 little-endian variant tag.

For OmniNode Stage 6 test vector `omninode-stage6-vec-1` the canonical digest bytes begin:

```
15 00 00 00 00 00 00 00                          # u64 LE length = 21
6f 6d 6e 69 6e 6f 64 65 2d 73 74 61 67 65 36 2d  # "omninode-stage6-"
76 65 63 2d 31                                    # "vec-1"
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  # 32 bytes model_hash
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
11 11 11 11 11 11 11 11 11 11 11 11 11 11 11 11  # 32 bytes manifest_root
…
```

See [§12](#12-test-vectors--wire-fixture-lock) for the full vectors.

### Domain tag

The verifier signs `DOMAIN_TAG_BYTES || bincode(digest)`:

```rust
pub const DOMAIN_TAG: &str = "omninode.inference_attestation.v1";
```

Domain bytes are the UTF-8 encoding of that exact string, no length prefix, no null terminator — concatenated directly with the canonical digest bytes.

```
signing_input = b"omninode.inference_attestation.v1" || bincode(digest)
verifier_signature = Ed25519_sign(verifier_secret_seed, signing_input)
```

The chain re-verifies bit-for-bit. Drift in the domain string, the bincode config, or the field order breaks every existing signature; the wire-fixture tests fail loudly on any of those.

### `session_id` cap

```rust
pub const MAX_SESSION_ID_BYTES: usize = 256;
```

Enforced inside `verify_attestation_signature` (called by the executor dispatch). Payloads exceeding this cap fail with `Failed(52)` and `fee_paid: 0` before any crypto work — the cap fires first so an oversized session_id can't be used to inflate signing-input length.

---

## 4. Address & Signature Encoding

### Verifier address

Derived from the verifier's 32-byte Ed25519 public key. The exact derivation is the chain's standard `Address::from_public_key` rule (see [`crates/primitives/src/address.rs`](../../crates/primitives/src/address.rs)):

```
address_bytes = BLAKE3(ed25519_pubkey)[12..32]                   # 20 bytes (last 20)
checksum      = BLAKE3(BLAKE3(address_bytes))[0..4]              # double-BLAKE3
payload       = address_bytes || checksum                        # 24 bytes
verifier_address_base58 = bs58::encode(payload).into_string()    # Bitcoin alphabet, no version byte
```

No leading version byte. No `0x` prefix. Base58 alphabet is the default `bs58` Rust crate (Bitcoin alphabet — omits `0OIl`).

### Signature encoding

- **Inner verifier signature** (the field `verifier_signature: [u8; 64]`): 64 raw bytes inside the bincode payload. On the wire (e.g. in RPC responses) hex-encoded with `0x` prefix → 130 chars total.
- **Outer tx signature**: chain-standard Ed25519 over `BLAKE3(bincode(SignedTransaction))`, stored as `[u8; 64]` on the `SignedTransaction` envelope. Same format as every other v2 tx.

---

## 5. Executor Dispatch & Failure Codes

The dispatch arm for `TxPayload::InferenceAttestation` lives in [`crates/state/src/executor.rs`](../../crates/state/src/executor.rs). Five sequential checks; every pre-success path returns `fee_paid: 0` and applies no state mutation. The success path performs all fee accounting BEFORE the CF write so a deduct/credit/nonce error can't leave an orphan record.

| # | Check | Failure status | Notes |
|---|---|---|---|
| 1 | `omninode_gate_open(params, height)` | `Failed(50)` | Pre-activation; default state on every fresh chain. |
| 2 | `Address::from_public_key(tx.public_key) == v2_tx.from` | `Failed(53)` | Defensive `sender == verifier` check. Outer tx validation at `executor.rs` lines 1064–1072 already enforces this with `TxStatus::InvalidSignature` before reaching the variant arm; the in-arm check is defense-in-depth. |
| 3 | `verify_attestation_signature(tx_data, &tx.public_key)` | `Failed(52)` | Ed25519 verify of the inner attestation signature under `DOMAIN_TAG`. |
| 4 | `inference_attestation_executor.exists(cf_key)` | `Failed(51)` | Permanent duplicate check against the canonical CF. |
| 5a | `state.get_balance(sender) < fee` | `InsufficientBalance` | Pre-deduct balance guard. |
| 5b | `state.deduct(sender, fee)` → `state.credit(proposer, fee)` → `state.increment_nonce(sender)` → CF write | `Success`, `fee_paid: fee` | Success path. CF write last via `Database::batch()` so the canonical CF and session-id index move atomically. |

### Failure code reference (TxStatus::description)

```
Failed(50) → "OmniNode subprotocol not enabled at this block height"
Failed(51) → "duplicate InferenceAttestation for (session_id, verifier)"
Failed(52) → "invalid OmniNode Stage 6 verifier signature"
Failed(53) → "tx sender does not match verifier address (Ed25519 pubkey hash)"
```

These descriptions are returned from `Receipt::status.description()` and surfaced through the `sum_getInferenceAttestationStatus` `reason` field on failure. See [`crates/primitives/src/receipt.rs`](../../crates/primitives/src/receipt.rs).

---

## 6. Permanent Duplicate Policy

**One attestation per `(session_id, verifier_address)` pair, forever.** No expiration, no override, no overwrite. This is enforced at two layers:

- **Mempool admission** (see [§7](#7-mempool-admission)) rejects duplicates before they enter a block.
- **Executor dispatch** rejects duplicates that somehow bypass the mempool (e.g. block import from a peer that admitted them) with `Failed(51), fee_paid: 0`.

The dedup key is a 32-byte BLAKE3-domain-separated hash:

```rust
pub const INFERENCE_ATTESTATION_KEY_DOMAIN: &[u8] = b"InferenceAttestationKeyV1";

fn inference_attestation_key(session_id: &str, verifier: &Address) -> [u8; 32] {
    BLAKE3(domain || bincode((session_id, verifier_address)))
}
```

The `V1` suffix in the domain string lets a future schema rotation use a `V2` keyspace without colliding with historical entries (would require a CF migration). Test vectors for this key against the three OmniNode reference vectors are pinned in `fixture_inference_attestation_storage_key`.

**The executor's duplicate-failure path returns `fee_paid: 0` and does NOT advance the sender's nonce.** This makes duplicate-replay an attractive griefing vector unless mempool admission rejects duplicates before they reach a block — which is exactly why mempool admission is required, not optional. See [§7](#7-mempool-admission).

To fund a new account on an existing session, generate a new verifier key (new `verifier_address`) or use a different `session_id`. There is no "update" or "supersede" semantic in v1; the chain commits to the first attestation it sees.

---

## 7. Mempool Admission

The production mempool is constructed with `InferenceAttestationAdmission` wired in. See [`crates/node/src/node.rs`](../../crates/node/src/node.rs); the admission context carries:

```rust
pub struct InferenceAttestationAdmission {
    pub executor:       Arc<InferenceAttestationExecutor>,   // permanent CF dedup
    pub params:         Arc<ChainParams>,                    // activation threshold
    pub current_height: Arc<AtomicU64>,                      // live block height
}
```

`current_height` is initialized at `Node::new` from `BlockStore::get_latest_height()?.unwrap_or(0)` and bumped on every `ConsensusEvent::BlockProduced` and `ConsensusEvent::BlockImported`.

### Admission checks

When `Mempool::add(tx)` sees a `TxPayload::InferenceAttestation`, three sequential checks fire BEFORE the standard mempool index inserts:

1. **Activation gate.** `omninode_gate_open(params, current_height)` — reject with `StateError::OmniNodeNotActivated`.
2. **In-flight duplicate.** Same `(session_id, verifier)` already in this mempool — reject with `StateError::DuplicateInferenceAttestation`.
3. **Permanent CF duplicate.** Same pair already in the `INFERENCE_ATTESTATIONS` CF — reject with `StateError::DuplicateInferenceAttestation`.

Rejected transactions never enter the mempool and never reach `execute_tx`; the executor's identical duplicate check is defense-in-depth for the case where a tx arrives via a different ingress (block import, P2P relay from a non-admission-gated peer).

The mempool maintains its own in-flight map keyed by the same 32-byte BLAKE3 used by the canonical CF, so admission and the canonical CF share one keying function and can't desync. `Mempool::remove` and `Mempool::clear` clear the in-flight entry. Non-`InferenceAttestation` payloads bypass all three checks at zero cost.

### Tests / non-production callers

`Mempool::new(config)` without `.with_inference_admission(...)` constructs an admission-disabled mempool. In-flight dedup still fires (cheap and content-defined) but the activation gate and permanent CF check are skipped. This is the correct behavior for unit tests, integration tests, and consensus internal re-adds of txs from rejected blocks; it is **not** correct for the user-submit path, which is why `Node::new` always wires admission in.

---

## 8. Read-only RPC

Three read-only methods in [`crates/rpc/src/api.rs`](../../crates/rpc/src/api.rs):

### `sum_getInferenceAttestation`

```
method:  sum_getInferenceAttestation
params:  [session_id: string, verifier_address: base58 string]
returns: InferenceAttestationInfo | null
```

Point lookup against the `INFERENCE_ATTESTATIONS` CF using the canonical 32-byte BLAKE3 key. Returns `null` if no attestation exists for the pair.

```bash
curl -s -X POST -H 'Content-Type: application/json' \
  --data '{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "sum_getInferenceAttestation",
    "params": ["my-session-id", "NFG1W1iuwcHCvdFxvWNTjDgqqYgq7m155"]
  }' \
  http://localhost:8545
```

### `sum_listInferenceAttestations`

```
method:  sum_listInferenceAttestations
params:  [session_id: string]
returns: [InferenceAttestationInfo, …]
```

Prefix scan over the `INFERENCE_ATTESTATIONS_BY_SESSION` index CF using the 16-byte session prefix, then per-verifier point lookup on the canonical CF. Returns every verifier's attestation for the session. Empty array if no attestations exist. Used by OmniNode coordinators to determine quorum.

### `sum_getInferenceAttestationStatus`

```
method:  sum_getInferenceAttestationStatus
params:  [tx_hash: 0x-prefixed 32-byte hex]
returns: InferenceAttestationStatusInfo
```

4-state finality classification with a payload-type guard. See [§9](#9-status-semantics).

### Response shapes

```rust
pub struct InferenceAttestationInfo {
    pub session_id:         String,            // OmniNode-defined UTF-8
    pub verifier_address:   String,            // base58 + checksum
    pub model_hash:         String,            // "0x" + 64 hex chars
    pub manifest_root:      String,            // "0x" + 64 hex chars
    pub response_hash:      String,            // "0x" + 64 hex chars
    pub proof_root:         String,            // "0x" + 64 hex chars
    pub verifier_signature: String,            // "0x" + 128 hex chars
    pub included_at_height: u64,
    pub tx_hash:            String,            // "0x" + 64 hex chars
    pub finalized:          bool,              // see §10
}

pub struct InferenceAttestationStatusInfo {
    pub status:             String,            // "submitted" | "included" | "finalized" | "failed" | "unknown"
    pub included_at_height: Option<u64>,       // None for submitted/unknown
    pub reason:             Option<String>,    // Some(description) when status == "failed"
}
```

`InferenceAttestationStatusInfo` lives in `sumchain-primitives::inference_attestation` and is re-exported from `sumchain-rpc::types` for source compatibility.

---

## 9. Status Semantics

The 4-state finality model (plus `unknown`):

| State | Meaning | `included_at_height` | `reason` |
|---|---|---|---|
| `submitted` | In mempool, not yet in any block | None | None |
| `included` | In a block at height `H` but `current_height < H + finality_depth` | `Some(H)` | None |
| `finalized` | In a block at height `H` and `current_height ≥ H + finality_depth` | `Some(H)` | None |
| `failed` | In a block but executor rejected; `fee_paid: 0` | `Some(H)` | `Some(TxStatus::description())` |
| `unknown` | Tx hash not recognized OR refers to a non-`InferenceAttestation` tx | None | None |

### Receipt-first precedence

If a receipt exists for the tx hash, classification uses the receipt (success+finality, or failure+reason) — even if the tx is also still in the mempool during the prune-lag window. A stale mempool entry must never downgrade a finalized status to `submitted`.

### Payload-type guard

A tx hash whose recorded payload is not `InferenceAttestation` always returns `"unknown"` regardless of receipt state. A foreign hash (transfer, staking, SNIP V2, etc.) must not surface as `included` or `finalized` through an attestation-specific RPC — clients would misinterpret it as an attestation otherwise. The classifier explicitly checks the payload variant; tests cover both the foreign-hash and the receipt-precedence cases.

### Dropped state — not in v1

Mempool eviction is not tracked as its own status. The status a client observes for an evicted tx depends on which intermediate state the tx is in:

- **While the tx is still in the mempool** (TTL not yet expired, not yet replaced, mempool not yet full) → `submitted`.
- **After eviction with no receipt** (TTL expired, replaced by higher-fee tx, mempool flushed, …) → `unknown`. The classifier returns `unknown` because the payload-type guard fails: with no `stored_tx` (the tx never reached a block) and no `mempool_tx` (it's been evicted), the classifier can't confirm the hash refers to an `InferenceAttestation` at all.
- **After block inclusion** → `included` / `finalized` / `failed` per [§9](#9-status-semantics)'s receipt-first precedence.

Recommended client behavior: treat **both** an unexpectedly long-running `submitted` (more than `2 × block_time_ms` without a transition) **and** an unexpected `unknown` (where the client knows it submitted the tx) as a signal to resubmit. Resubmission is safe — the permanent dedup guarantees only one attestation per `(session_id, verifier)` will ever land, regardless of how many times the client tries.

The classifier function is pure and lives in primitives: [`classify_inference_attestation_status`](../../crates/primitives/src/inference_attestation.rs).

---

## 10. Finality

`finalized` is computed against the chain's `finality_depth` chain parameter:

```
finalized = current_height >= included_at_height + finality_depth
```

**Read `finality_depth` from the live chain via `chain_getChainParams`. Don't bake a constant.**

```bash
curl -s -X POST -H 'Content-Type: application/json' \
  --data '{"jsonrpc": "2.0", "id": 1, "method": "chain_getChainParams", "params": []}' \
  http://localhost:8545
```

Default `finality_depth` is `3` in genesis ([`crates/genesis/src/lib.rs`](../../crates/genesis/src/lib.rs)). Production chains may set higher values; don't hardcode `3` or `6` in client code.

---

## 11. V1 Exclusions

Explicitly out of scope for v1. All deferred to future protocol versions:

| Excluded | Why deferred | When |
|---|---|---|
| `sum_submitInferenceAttestation` typed RPC sugar | Existing `sum_sendRawTransaction` is canonical and sufficient. Typed sugar is an ergonomics win, not a correctness requirement. | Optional v1.x |
| `sum-chain-sdk` external crate publication | Internal vendoring suffices for v1. Public crate publication is a separate strategic decision. | Future, no commitment |
| Sponsored submission (`sender ≠ verifier` with explicit `verifier_public_key` field) | v1 enforces `sender == verifier` for the simplest possible recovery model. Sponsored submission would require adding `verifier_public_key: [u8; 32]` to the payload (= `InferenceAttestationV2`) and explicit settlement coordination with OmniNode. | v2 if operationally needed |
| Reward / slash / dispute tx families | Settlement and dispute are a separate protocol surface, referenced by `(session_id, verifier_address)`. v1 commits to attestation immutability; economics come later. **Now specified + implemented (dormant) as the separate [Inference Settlement](inference-settlement.md) subprotocol (issue #61)** — escrow-funded reward denial / claim withholding / escrow refund; **no bond slashing** (that needs a v2 verifier-bond registry). Attestation v1 is untouched. | [inference-settlement.md](inference-settlement.md) (issue #61) |
| `Dropped` / replacement status tracking | Chain doesn't track mempool eviction history in v1. Clients implement client-side timeout + resubmit. | Future |
| CF pruning policy for `INFERENCE_ATTESTATIONS` | CF grows monotonically. Acceptable for expected early-adopter attestation rate; dashboard CF size; revisit if growth becomes a real problem. | Future |
| Aggregated multi-sig (BLS) attestations | v1 is one-tx-per-verifier. BLS aggregation is a scaling optimization for later. | Future if attestation rate demands |
| `InferenceAttestationV2` schema fields (e.g. additional commitments, optional fields) | Wire format is frozen for v1. Any new fields go in a new variant; the bincode tag for `TxPayload::InferenceAttestation` is locked at index 21 by the wire-fixture tests. | New variant, append-only |

---

## 12. Test Vectors & Wire-Fixture Lock

Three reference vectors from OmniNode Stage 6 are vendored at [`crates/primitives/tests/fixtures/chain_attestation_vectors.json`](../../crates/primitives/tests/fixtures/chain_attestation_vectors.json). Each vector contains:

```json
{
  "session_id":             "<UTF-8 string>",
  "model_hash":             "<64 hex chars>",
  "manifest_root":          "<64 hex chars>",
  "response_hash":          "<64 hex chars>",
  "proof_root":             "<64 hex chars>",
  "verifier_ed25519_seed":  "<64 hex chars>",
  "canonical_digest_bytes": "<hex>",
  "signing_input_bytes":    "<hex of DOMAIN_TAG || canonical_digest_bytes>",
  "signature_bytes":        "<128 hex chars of Ed25519 signature>",
  "signer_address_base58":  "<base58 with checksum>",
  "signer_pubkey_hex":      "<64 hex chars>"
}
```

The wire-fixture suite in [`crates/primitives/tests/inference_attestation_fixtures.rs`](../../crates/primitives/tests/inference_attestation_fixtures.rs) asserts bit-for-bit parity for every vector:

- `fixture_canonical_digest_bytes_match` — chain bincode output == OmniNode's recorded canonical bytes.
- `fixture_signing_input_bytes_match` — `DOMAIN_TAG || canonical` matches OmniNode's signing-input bytes.
- `fixture_signer_address_derives_from_pubkey` — `Address::from_public_key().to_base58()` matches OmniNode's expected address.
- `fixture_signature_verifies_against_chain_path` — chain Ed25519 verify accepts OmniNode's signature.
- `fixture_inference_attestation_storage_key` — the 32-byte BLAKE3 CF key matches the pinned hex for each vector.
- `tx_type_inference_attestation_ordinal_locked` — `TxType::InferenceAttestation == 21`.
- `tx_payload_inference_attestation_variant_index_locked` — `TxPayload` bincode tag == 21.

These tests are the contract. Drift in `DOMAIN_TAG`, bincode config, field order, `Address::from_public_key`, or the variant ordinals all surface as red CI. Regenerating fixtures requires re-running OmniNode's Stage 6 generator and re-vendoring `chain_attestation_vectors.json`.

### Regenerating

If OmniNode rotates Stage 6 (e.g., field addition → would become `InferenceAttestationV2`):

1. OmniNode regenerates `chain_attestation_vectors.json` from their reference signer.
2. Re-vendor the file into `crates/primitives/tests/fixtures/`.
3. Update the locked CF keys in `EXPECTED_CF_KEY_HEX` (run the test once, paste the new bytes).
4. Either bump v1 wire-format compatibly (rare; only additive non-overlapping serializations are wire-compatible) OR add a new `InferenceAttestationV2` variant and gate it behind a new chain param.

---

## 13. References

- **OmniNode Stage 6 reference impl:** `OmniNode-Protocol/crates/omni-zkml/src/chain_wire.rs` (external repo)
- **Chain primitives:** [`crates/primitives/src/inference_attestation.rs`](../../crates/primitives/src/inference_attestation.rs)
- **Chain storage:** [`crates/storage/src/db.rs`](../../crates/storage/src/db.rs) — `INFERENCE_ATTESTATIONS`, `INFERENCE_ATTESTATIONS_BY_SESSION`
- **Chain executor dispatch:** [`crates/state/src/executor.rs`](../../crates/state/src/executor.rs)
- **Chain storage executor:** [`crates/state/src/inference_attestation_executor.rs`](../../crates/state/src/inference_attestation_executor.rs)
- **Mempool admission:** [`crates/state/src/mempool.rs`](../../crates/state/src/mempool.rs) — `InferenceAttestationAdmission`
- **Production wiring:** [`crates/node/src/node.rs`](../../crates/node/src/node.rs)
- **RPC:** [`crates/rpc/src/api.rs`](../../crates/rpc/src/api.rs), [`crates/rpc/src/server.rs`](../../crates/rpc/src/server.rs)
- **Status classifier (pure):** [`crates/primitives/src/inference_attestation.rs`](../../crates/primitives/src/inference_attestation.rs) — `classify_inference_attestation_status`
- **Wire-fixture tests:** [`crates/primitives/tests/inference_attestation_fixtures.rs`](../../crates/primitives/tests/inference_attestation_fixtures.rs)
- **Dispatch integration tests:** [`crates/state/tests/inference_attestation_dispatch.rs`](../../crates/state/tests/inference_attestation_dispatch.rs)
- **Mempool admission tests:** [`crates/state/tests/inference_attestation_mempool.rs`](../../crates/state/tests/inference_attestation_mempool.rs)
- **Vendored OmniNode reference vectors:** [`crates/primitives/tests/fixtures/chain_attestation_vectors.json`](../../crates/primitives/tests/fixtures/chain_attestation_vectors.json)
- **README subprotocols summary:** [`../../README.md#subprotocols`](../../README.md#subprotocols)
