# sumchain-primitives

Core primitive types and on-chain wire formats for [SUM Chain][repo],
a Rust L1 blockchain. This crate is the canonical source of the
**byte-stable types** that get serialized into transactions, blocks,
and receipts on chain. Anything that needs to encode, decode, sign,
or verify SUM Chain wire bytes should depend on this crate rather
than re-implementing.

[repo]: https://github.com/SUM-INNOVATION/sum-chain

## What's in it

- `Address` (`address`) — 20-byte chain address, base58 + checksum
  string form, with `Address::from_public_key` for Ed25519 →
  address derivation.
- `Hash` (`hash`) — 32-byte BLAKE3 hash, `0x`-prefixed hex string form.
- `Block`, `BlockHeader` (`block`) — chain block / header types.
- `Transaction`, `TransactionV2`, `SignedTransaction`, `TxPayload`,
  `TxType`, `TxInner` (`transaction`) — the transaction tag union
  used at the wire level (`TxPayload::*` variants for each
  subprotocol).
- `Receipt`, `TxStatus` (`receipt`) — tx receipt + status codes.
- Subprotocol wire payloads (each is its own module, used as a
  variant of `TxPayload`):
  - `inference_attestation` — OmniNode v1 attestation digest +
    tx-data + the `verify_attestation_signature` helper used by
    chain ingestion. `pub mod inference_attestation;`, **not**
    re-exported at the crate root.
  - `messaging` — SRC-201 sponsored messaging.
  - `staking` — validator / delegation operations.
  - `docclass`, `tax`, `equity`, `agreement`, `legal`, `property`,
    `healthcare`, `employment`, `finance`, `node_registry`,
    `policy_account`, `storage_metadata`, `education` — additional
    subprotocols. See the [SUM Chain repo][repo] for the SRC-*
    specs each one implements.

The exact `pub use` surface lives in `src/lib.rs` in the source
repository.

## Stability

All types in this crate participate in chain consensus. **Field
order, variant order, and `#[serde]`/`#[repr]` choices are
wire-significant** — bincode + the chain's serializer treat them as
the canonical encoding. Breaking changes here imply a chain
upgrade. Treat semver bumps accordingly:

- patch: doc-only, internal refactors, no wire change.
- minor: additive (e.g. a new `TxPayload` variant appended at the
  end) — older nodes can't decode the new variant but existing
  variants stay byte-identical.
- major: anything that changes existing wire bytes. Requires a
  coordinated chain activation.

## Usage

```toml
[dependencies]
sumchain-primitives = "0.1"
```

```rust
use sumchain_primitives::{Address, Hash, SignedTransaction, TxPayload};
use sumchain_primitives::inference_attestation::{
    InferenceAttestationDigest, InferenceAttestationTxData,
};
```

For the **submit path** (build a `SignedTransaction` and serialize
it to hex for `sum_sendRawTransaction`), pair this crate with
[`sumchain-crypto`](https://crates.io/crates/sumchain-crypto) for
the Ed25519 sign step:

```rust
let raw_hex = signed_tx.to_hex();
// POST {"method":"sum_sendRawTransaction","params":[raw_hex]}
```

## Dependencies

`primitives` deliberately pulls `ed25519-dalek` directly (rather
than depending on `sumchain-crypto`) so that
`inference_attestation::verify_attestation_signature` can verify
inner attestation signatures without creating a circular dep.
`primitives` therefore stays at the bottom of the crate graph.

## License

Dual-licensed under `MIT OR Apache-2.0` at your option. The full
license texts (`LICENSE-MIT`, `LICENSE-APACHE`) live at the root of
the source repository.
