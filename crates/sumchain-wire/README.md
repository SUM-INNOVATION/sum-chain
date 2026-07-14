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
- **Decoder tolerance (pinned, not aspirational):** `bincode::deserialize`
  currently **tolerates trailing bytes** after a fully-decoded value. This is
  the *observed and locked* behavior, captured by the golden fixtures — it is
  documented here so it cannot be changed silently. Truncated input, short
  fixed arrays, out-of-range enum ordinals (e.g. `TxPayload` tag 27), and
  oversized length prefixes all decode to `Err`.

## Versioning & breaking-change policy

- Current version: **0.1.0** (independent of the workspace's 0.2.0 members).
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
- **Ordinal ownership:** W1a introduces **no** new ordinal (variants 0–26 only);
  ordinal **27+** is owned by **W1b**.

## Golden fixtures

Byte-stability is enforced by hardcoded, pre-extraction golden vectors:

- [`crates/primitives/tests/wire_golden_fixtures.rs`](https://github.com/SUM-INNOVATION/sum-chain/blob/50e64489e12c88b61e64744fd47bd13b7da82ba7/crates/primitives/tests/wire_golden_fixtures.rs)
  — all 27 `TxPayload` tags, legacy + V2 `SignedTransaction` full bytes,
  `hash`/`signing_hash`, hex (bare and `0x`-prefixed), `TxInner` discriminants,
  and the malformed-input rejection matrix.

These exercise the types through the `sumchain-primitives` re-exports and MUST
stay byte-identical across any change to this crate. Additional per-module wire
fixtures live alongside them in `crates/primitives/tests/`.

## Safety

`#![forbid(unsafe_code)]`. Pure serialization/deserialization; no I/O, no
network, no unsafe.
