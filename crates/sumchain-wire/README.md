# sumchain-wire

Byte-frozen on-chain **wire formats** for SUM Chain: addresses, hashes,
transactions, and every subprotocol payload. This is the single, canonical home
of the encoding/decoding surface — a pure **leaf crate** with no signature
verification, state, storage, consensus, RPC, or networking dependency.

It was extracted verbatim from `sumchain-primitives` (sum-chain #124 / W1a).
`sumchain-primitives` re-exports every type here, so downstream crates continue
to `use sumchain_primitives::…` unchanged.

## What lives here vs. what does not

**Here (encoding only):**
- Scalar wire types: `Hash`, `Address`, and the scalar aliases `ChainId`,
  `BlockHeight`, `Nonce`, `Balance`, `Timestamp`.
- `Transaction`, `TransactionV2`, `SignedTransaction`, `TxInner`, `TxType`, and
  all **27** `TxPayload` variants (ordinals **0–26**).
- Every subprotocol `*TxData` payload and its supporting data types
  (agreement, docclass, education, employment, equity, finance, governance,
  healthcare, legal, messaging, node_registry, policy_account, property,
  staking, storage_metadata, supply, tax, token_ops, validator_authority,
  inference_settlement, inference_attestation wire structs).
- Encode/decode helpers, digest/signing-input construction, and hex/bs58
  string forms.

**NOT here (stays above the leaf, in `sumchain-primitives` and its dependents):**
- **Semantic verification** — Ed25519 attestation checks
  (`verify_attestation_signature`, `verify_attestation_v2_signature`), quorum
  evaluation, receipt-bound status classification.
- `Block`, `BlockHeader`, `Receipt`, `TxStatus`, and state-classifier logic.
- All signature *generation* and cryptographic *policy*.

The leaf deliberately depends on **no** `ed25519` / state / rpc / consensus /
networking / rocksdb / libp2p crate, and **not** on `sumchain-primitives` —
keeping the dependency graph acyclic (`wire ← primitives ← crypto ← …`).

## Cargo features: `std` and the `no_std` subset

- **`std`** (default) is the whole crate. A default build has the same items,
  derives, `Display` strings and encoded bytes as it had before the feature
  existed. It enables `serde`, `serde_json`, `bincode`, `thiserror`,
  `serde-big-array`, and the `std` features of `hex`, `bs58` and `blake3`.
- **Without `std`** (`default-features = false`) the crate is `#![no_std]`,
  needs `alloc` (a global allocator), and contains only:
  - `Address` and `AddressText`, with the base58, `r0` agent, and hex text
    forms, `from_public_key`, `Display` and `Debug`;
  - `Hash`, with `hash`, `hash_many`, `merkle_root`, hex, `Display` and `Debug`;
  - `ChainId`, `BlockHeight`, `Nonce`, `Balance`, `Timestamp`, `Result` and
    `PrimitiveError`;
  - in `inference_attestation`: `DOMAIN_TAG`, `MAX_SESSION_ID_BYTES`,
    `InferenceAttestationDigest`, `AttestationError`, `canonical_digest_bytes`,
    `signing_input_bytes` and `verifier_address`.

  These have no serde derives without `std`, and `PrimitiveError` and
  `AttestationError` implement `Debug` only. Everything else in the crate
  needs `std`.

```toml
[dependencies]
sumchain-wire = { version = "…", default-features = false }
```

`std` is additive: when anything in a build enables it, the subset's items are
the same items with the same bytes, plus the rest of the crate. There is no
`no_std` feature, so feature unification cannot remove items from a crate
that needs them.

## B0-PRE candidate-neutral wire types (`b0`)

The [`b0`](src/b0/) module (added in **0.2.0**) holds the frozen B0-PRE
candidate-neutral wire family, reproduced **byte-for-byte** from the
out-of-workspace `b0-pre-validator` reference (copied here, never linked — the
leaf still depends on none of the `tools/` crates). It has its own length-checked
codec, domain tags, frozen enums, SNIP Merkle, and hashing helpers, plus:

- `ObjectCommitmentV1` (80 B), `OutputManifestV1` / `InputManifestV1`
  (38-byte header + 85-byte slot descriptors), `DerivedInputV1` (350 B),
  `R0ComputationStatementV2` (996 B), `GuestProgramAllowlistV1` /
  `GuestProgramEntryV1` (with `guest_set_hash()`), and
  `VerifierMaterialManifestV1`.
- Two **new** production proof types: `PartialComputeProofV1` (137 B) and
  `ProductionProofEnvelopeV1` (235 B), each with a strict self-domained magic
  (`PCPFv1\0` / `PPEVv1\0`), a `schema_version` of 1, and truncation/trailing
  rejection — plus the pure cross-binding checks `shared_binding_ok` and
  `allowlist_membership` (registry Active/activation-height checks stay a
  caller responsibility).

This addition is **strictly additive**: it introduces **no** transaction ordinal
and changes **no** existing 0.1.1 bytes. Byte-equality against the committed
closure-golden fixtures and the frozen reference encoder is exercised by
`tests/wire_0_2_0_golden.rs`.

## Byte-freeze / compatibility guarantee

The types in this crate are **contract-frozen**. Their serialized bytes are
consensus- and signature-relevant: a transaction's `signing_hash` is
`blake3(bincode(tx))`, so any change to the encoded bytes changes hashes,
invalidates signatures, and forks the chain.

The following are **wire-breaking** and MUST NOT change within a compatible
release:
- enum **variant order / discriminant** (e.g. `TxPayload` ordinals 0–26,
  `TxInner` Legacy=0 / V2=1, `TxType` byte values),
- struct **field order and width**,
- the **bincode configuration** used to (de)serialize,
- fixed-array lengths (`Hash` = 32 bytes, `Address` = 20 bytes,
  `SignedTransaction` signature = 64 bytes, public key = 32 bytes).

Appending a **new** `TxPayload` variant (only ever at the next free ordinal,
**27**) is a **breaking, coordinated wire/protocol change** — see "Versioning &
breaking-change policy" below — not an ordinary additive change. Reordering,
removing, or re-typing an existing variant is never permitted within a
compatible release.

## bincode policy

- **Serializer:** `bincode` 1.3, **default config** (fixed-int encoding, u32
  little-endian enum variant tags, little-endian scalars).
- **Signing hash:** `signing_hash = blake3(bincode(tx))`.
- **Without `std`:** `bincode` is not available, so
  `inference_attestation::canonical_digest_bytes` writes the digest's bytes
  with an encoder written by hand in this crate (`session_id` as a u64-LE byte
  length and its UTF-8 bytes, then the four 32-byte arrays in field order). A
  default build still calls `bincode`. The encoder's tests pin it to bincode's
  bytes (see "Golden fixtures").
- **Decoder tolerance (pinned, not aspirational):**
  - As of **0.2.1**, the canonical `SignedTransaction::from_bytes` /
    `from_hex` path **REJECTS trailing bytes**: the input must be exactly one
    serialized `SignedTransaction`. This uses explicit reject-trailing bincode
    options (fixed-int, little-endian) so the **accepted canonical byte set is
    byte-for-byte identical to 0.2.0** — only silent trailing-byte tolerance was
    removed. The encoder (`to_bytes`/`to_hex`), `signing_hash`, and the tx hash
    are unchanged.
  - As of **0.2.2**, `Transaction::from_bytes` and `TransactionV2::from_bytes`
    **also REJECT trailing bytes**, using the same explicit reject-trailing
    bincode options (fixed-int, little-endian) as the `SignedTransaction` path.
    The accepted canonical byte set for both is byte-for-byte identical to
    0.2.1/0.2.0 — only silent trailing-byte tolerance was removed.
  - `MessageHeader::from_bytes` remains **intentionally permissive**: it parses a
    fixed 72-byte prefix off a larger SRC-201 frame whose encrypted body
    legitimately follows, so rejecting "trailing" bytes would reject every real
    message.
  - In all cases, truncated input, short fixed arrays, out-of-range enum
    ordinals (e.g. `TxPayload` tag 27), and oversized length prefixes decode to
    `Err`.

## Versioning & breaking-change policy

- Current version: **0.3.0**. The 0.2.2 → 0.3.0 bump is a **minor (breaking)**
  release: it appends a new `MessagingOperation` variant,
  `RegisterPublicKeySponsoredV1` (sum-chain issue #145), plus its payload
  (`RegisterPublicKeySponsoredV1Data`), the canonical domain tag
  (`SPONSORED_REGISTER_V1_TAG`), and the signing-preimage builder. The variant
  is declared LAST so its bincode variant index — the on-wire `u32-LE` tag,
  index **18** — is append-only and shifts **no** existing `MessagingOperation`
  index (0–17 are byte-identical, locked by golden tests); every other encoded
  byte, hash, and signature is unchanged. Per the exhaustive-enum rule below,
  appending a variant that expands the set of consensus-valid encodings is
  breaking (a coordinated wire/protocol change gated by
  `messaging_sponsored_registration_enabled_from_height`), hence the minor bump.
- The 0.2.1 → 0.2.2 bump is **patch-level**:
  (a) `Transaction::from_bytes` and `TransactionV2::from_bytes` now reject
  trailing bytes (extending the 0.2.1 `SignedTransaction` hardening;
  `MessageHeader` stays permissive by design), and (b) a single public
  `assignment_score` is exposed and drives both assignment loops (no second
  scorer). It changes **no** encoded bytes — the encoder, every golden fixture,
  all hashes/signatures, assignment outputs, and the accepted canonical byte set
  are byte-for-byte identical to 0.2.1/0.2.0.
- The 0.2.0 → 0.2.1 bump was a **patch-level decoder-hardening**: the canonical
  `SignedTransaction::from_bytes`/`from_hex` path rejects trailing bytes; it
  changes **no** encoded bytes vs 0.2.0.
- The 0.1.1 → 0.2.0 bump was **additive**: it adds the `b0` candidate-neutral
  wire types (see above) and re-exports; it introduces no new transaction
  ordinal and changes no existing 0.1.1 encoded bytes.
- **Every change to an existing wire shape is breaking.** Reordering, removing,
  or re-typing a variant; reordering or re-typing a field; changing the bincode
  config; or changing a fixed-array length alters serialized bytes, changes
  hashes, invalidates signatures, and forks the chain — regardless of whether
  the Rust API stays source-compatible.
- **Appending a `TxPayload` variant is also breaking — a coordinated
  wire/protocol change, not an ordinary additive minor bump.** The public
  `TxPayload` enum is *exhaustive*, so a new variant:
  - breaks downstream exhaustive `match` arms over `TxPayload` (source-breaking
    for every consumer);
  - **expands the set of consensus-valid encodings** (an ordinal that decoders
    previously rejected becomes acceptable);
  - therefore requires coordinated consumer **and** chain activation.
- **SemVer bump rule:** a breaking release (either kind above) increments the
  **minor** version while pre-1.0, and the **major** version at/after 1.0. Only
  encoding-neutral doc / comment / Clippy-style changes that leave every golden
  fixture byte-identical are patch-level.
- **Publication never activates an ordinal.** Publishing this crate alone does
  not make a new `TxPayload` ordinal live: new ordinals require explicit
  chain/client adoption, compatibility tests, and activation gating.
- **Ordinal ownership:** W1a introduces **no** new ordinal (variants 0–26 only).
  Above that (owner allocation, 2026-07): ordinal **27** is owned by **C1 /
  ComputePool (#130)**; the **28/29 band** is owned by **W1b** beacon, split by
  protocol phase (**28** = DKG / epoch-setup: key registration, deal, complaint;
  **29** = signing / output: per-round partials, finalization). All are dormant
  reservations — not yet registered `TxType`/`TxPayload` variants.

## Golden fixtures

Byte-stability is enforced by hardcoded, pre-extraction golden vectors:

- [`crates/primitives/tests/wire_golden_fixtures.rs`](https://github.com/SUM-INNOVATION/sum-chain/blob/50e64489e12c88b61e64744fd47bd13b7da82ba7/crates/primitives/tests/wire_golden_fixtures.rs)
  — all 27 `TxPayload` tags, legacy + V2 `SignedTransaction` full bytes,
  `hash`/`signing_hash`, hex (bare and `0x`-prefixed), `TxInner` discriminants,
  and the malformed-input rejection matrix.

These exercise the types through the `sumchain-primitives` re-exports and MUST
stay byte-identical across any change to this crate. Additional per-module wire
fixtures live alongside them in `crates/primitives/tests/`.

The hand-written digest encoder of the `no_std` subset is pinned by the tests in
`src/inference_attestation.rs`, against golden bytes from `bincode`. Those are the
three OmniNode Stage 6 vectors (canonical bytes and signing input) and one
vector per field shape: empty, one-byte, multi-byte UTF-8 and NUL-bearing
`session_id`s, the length-prefix boundaries 255, 256, 257 and 65537, and
arrays that pin field order and byte position. Every vector is checked
against `bincode` as well, as is a sweep of lengths.

## Safety

`#![forbid(unsafe_code)]`. Pure serialization/deserialization; no I/O, no
network, no unsafe.
