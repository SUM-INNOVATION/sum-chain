//! Dormant library code for the consensus-foundation rules ratified on
//! 2026-10-16 (group G2; #270 certified finality, #268 upgrade authorization).
//!
//! # This is NOT certified finality
//!
//! Nothing in this crate makes the chain final. There is no vote codec, no
//! certificate encoding, no consensus core (rounds, timeouts, gossip), no
//! network protocol, no frozen byte layout of any kind, and no activation.
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
//! # Still unratified (deliberately absent)
//!
//! * Every byte layout: authorization manifest, handshake hint, vote,
//!   certificate, signer state, evidence. Types here are plain Rust structs;
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
pub mod containment;
pub mod signer;

/// A 32-byte digest. How it is computed (hash function, domain separation) is
/// decided by the unratified encodings, so this crate only compares digests.
pub type Digest = [u8; 32];
