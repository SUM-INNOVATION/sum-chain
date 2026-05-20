# sumchain-crypto

Cryptographic operations for [SUM Chain][repo], a Rust L1
blockchain. This crate is the thin, audited-dep-only wrapper that
chain nodes, wallets, and downstream submitters (e.g. the OmniNode
attestation submit path) use to sign and verify SUM Chain
transactions.

[repo]: https://github.com/SUM-INNOVATION/sum-chain

## What's in it

- **Ed25519 signing / verification** (`signature`, `keypair`)
  - `KeyPair`, `PrivateKey`, `PublicKey` — Ed25519 key material with
    zeroize-on-drop on the secret half.
  - `sign(&PrivateKey, &Hash) -> Signature`, `verify(&PublicKey,
    &Hash, &Signature) -> Result<()>`, and `verify_bytes(...)` for
    pre-hashed inputs.
- **BLAKE3 hashing** — used for domain-separated tx digests and the
  derived-key construction in messaging.
- **SRC-201 messaging KEM** (`messaging`)
  - X25519 ECDH (`x25519_ecdh`) with ed25519↔x25519 conversions
    (`ed25519_pk_to_x25519`, `ed25519_sk_to_x25519`),
    low-order-point guard (`is_low_order_x25519_public_key`,
    `LOW_ORDER_X25519_POINTS`).
  - BLAKE3-KDF (`blake3_derive_key`) → ChaCha20-Poly1305 AEAD seal
    / open (`encrypt_message`, `decrypt_message`), with
    `recipient_hash` for inbox routing.

Errors surface via `CryptoError` (in [`src/lib.rs`](src/lib.rs)).

## Underlying crates

All audited, standard Rust ecosystem:

- [`ed25519-dalek`](https://crates.io/crates/ed25519-dalek)
- [`blake3`](https://crates.io/crates/blake3)
- [`x25519-dalek`](https://crates.io/crates/x25519-dalek)
- [`chacha20poly1305`](https://crates.io/crates/chacha20poly1305)
- [`curve25519-dalek`](https://crates.io/crates/curve25519-dalek)
- [`sha2`](https://crates.io/crates/sha2)
- [`zeroize`](https://crates.io/crates/zeroize)

No custom crypto. No hand-rolled primitives.

## Usage

```toml
[dependencies]
sumchain-primitives = "0.1"
sumchain-crypto     = "0.1"
```

```rust
use sumchain_crypto::{KeyPair, sign, verify};
use sumchain_primitives::Hash;

let kp = KeyPair::generate();
let msg_hash = Hash::from_bytes(blake3::hash(b"hello").as_bytes());
let sig = sign(kp.private_key(), &msg_hash);
verify(kp.public_key(), &msg_hash, &sig).expect("valid signature");
```

For the SUM Chain transaction submit path, pair with
[`sumchain-primitives`](https://crates.io/crates/sumchain-primitives):
build a `TransactionV2`, hash it, sign the hash with `sign(...)`,
attach the signature to produce a `SignedTransaction`, then call
`SignedTransaction::to_hex()` and POST it to a SUM Chain RPC's
`sum_sendRawTransaction`.

## Stability

`sumchain-crypto` depends on a specific `sumchain-primitives`
version. The two ship in lockstep — same minor track. Semver intent:

- patch: doc, internal refactor.
- minor: additive helper, no behavior change for existing functions.
- major: signature scheme change, KDF change, or KEM construction
  change — implies a coordinated chain activation, not a normal
  release.

## License

Dual-licensed under [MIT](../../LICENSE-MIT) or
[Apache-2.0](../../LICENSE-APACHE) at your option.
