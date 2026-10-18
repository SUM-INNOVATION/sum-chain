//! Dormant library code for the consensus-foundation rules ratified on
//! 2026-10-16 (group G2; #270 certified finality, #268 upgrade authorization),
//! the encoding conventions of byte group A1 ratified on 2026-10-17, and the
//! finality vote format (group V) ratified on 2026-10-17.
//!
//! # This is NOT certified finality
//!
//! Nothing in this crate makes the chain final. There is no certificate
//! encoding, no consensus core (rounds, timeouts, gossip), no network
//! protocol, no signing of votes, and no activation. The A1 conventions below
//! fix how integers and rounds are encoded and how a certificate's signer
//! count is checked. The vote codec ([`vote`]) is the one frozen object
//! layout: it decodes, verifies (E1) and counts votes, and nothing calls it.
//! No node, consensus, storage or RPC code calls this crate, and
//! `tests/dormant.rs` fails if any workspace crate starts depending on it.
//! The code exists so that the ratified *semantics* are implemented and tested
//! before any bytes are reviewed; wiring it in is a separate, reviewed change.
//!
//! # Ratified rules and where they live
//!
//! | Rule | Ratified semantics (2026-10-16) | Implemented here |
//! |------|----------------------------------|------------------|
//! | G2-a | A block is published as canonical only together with a verified certificate, its post-state and the finalized pointer, in one durable atomic batch. | Not here: the storage half is the dormant `sumchain-storage` certified-commit seam (#292). |
//! | G2-b | Signer state is durable before any signature is released; exclusive ownership; explicit initialization; fail-closed recovery. | [`signer`] |
//! | G2-c | Quorum-signed, sequence-chained bootstrap authorization shipped with the release. Genesis membership authenticates the first bootstrap only; handshake announcements never authorize or halt; conflicting fully verified authorizations halt safely without reverting accepted history; late arrival does not invalidate authentic applied history. | [`bootstrap`] |
//! | G2-d | No dynamic membership before certified finality. | [`containment`], enforced when an authorization is recorded as applied |
//!
//! | Byte rule | Ratified encoding convention (A1, 2026-10-17) | Implemented here |
//! |-----------|-----------------------------------------------|------------------|
//! | D0 | Integers little-endian in new finality and upgrade objects and preimages; big-endian only in database keys. | [`encoding`]: separate [`encoding::LeWriter`]/[`encoding::LeReader`] and [`encoding::KeyWriter`]/[`encoding::KeyReader`] types |
//! | D4 | Every round field is a `u32` with `round ≤ 2^20`. | [`encoding::Round`] |
//! | D2 | The certificate carries no explicit validator count; it is implied by the validator-set commitment. | [`certificate::check_signers`] |
//!
//! | Object | Ratified format (group V, 2026-10-17) | Implemented here |
//! |--------|----------------------------------------|------------------|
//! | `FinalityVoteV1` | 113-byte body (V-1), `D_VOTE ‖ body` 139-byte pure-Ed25519 preimage, 184-byte wire (V-5), `step = vote_type + 1` (V-2), all-zero `block_id` = nil (V-3), validator-set commitment (V-4), canonical non-small-order keys (V-6); verified under E1 (`verify_strict`) | [`vote`] |
//!
//! # Still unratified (deliberately absent)
//!
//! * Every other object layout: authorization manifest, handshake hint,
//!   certificate, signer state, evidence, the validator-set commitment's
//!   preimage, and the composition of every database key (byte groups A2–A5
//!   and the object layouts). Types here are
//!   plain Rust structs;
//!   where a digest or signature is needed it is supplied by the caller or an
//!   injected trait, and the tests use synthetic digests.
//! * Round-aware proposer selection and any header change.
//! * The consensus library (adoption is a separate decision).
//! * Notice values: [`bootstrap::BootstrapState::accept`] takes the notice as
//!   a caller-supplied argument with no default.
//! * Activation of anything.
//!
//! # Old binaries cannot be made to halt
//!
//! The halt-before-activation rule in [`bootstrap`] only exists in a binary
//! that contains this framework. A binary built without it cannot recognise an
//! authorization, so no authorization can stop it: the framework must be
//! deployed in an earlier release than the first authorization it is expected
//! to enforce.
//!
//! # Before wiring
//!
//! When any of this is wired into a node path, add this crate to the
//! consensus-crate and constants-census lists in
//! `crates/consensus/tests/consensus_config_census.rs`, and delete
//! `tests/dormant.rs` in the same reviewed change.

pub mod bootstrap;
pub mod certificate;
pub mod containment;
pub mod encoding;
pub mod signer;
pub mod vote;

/// A 32-byte digest. How it is computed (hash function, domain separation) is
/// decided by the unratified encodings, so this crate only compares digests.
pub type Digest = [u8; 32];
