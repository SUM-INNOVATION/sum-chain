//! B0-PRE candidate-neutral wire types, reproduced as PRODUCTION code.
//!
//! These modules are a byte-for-byte copy of the frozen B0-PRE candidate-neutral
//! wire types (reference: the out-of-workspace `b0-pre-validator` tool). Every
//! `encode`/`decode`/`identity` body is preserved exactly, so the serialized
//! bytes are identical to the frozen structures; only module paths were rewritten
//! to live under `crate::b0`. This crate depends on **none** of the `tools/`
//! crates — the frozen sources were copied here, not linked.
//!
//! Additive over the 0.1.1 wire surface: no transaction ordinals and no existing
//! bytes change. Two new production types — [`partial_proof::PartialComputeProofV1`]
//! and [`proof_envelope::ProductionProofEnvelopeV1`] — extend the family with
//! strict, self-domained decoders in the same style.
//!
//! # Canonicality is closed across the whole module (API-surface audit)
//!
//! Every public `b0` type that can *represent* decoder-invalid or noncanonical
//! state exposes its canonical bytes/hash ONLY through a fallible route; its raw
//! `encode` is private. Types that cannot represent invalid state keep an
//! infallible `encode`. The `api_surface_audit` integration test enumerates and
//! exercises this table:
//!
//! | Type | Can hold invalid state? | Canonical route |
//! |------|-------------------------|-----------------|
//! | [`object_commitment::ObjectCommitmentV1`] | **No** — private fields + checked constructors make it unrepresentable | infallible `encode`/`identity` (safe by construction); `validate` for defensive re-check |
//! | [`manifest::OutputManifestV1`] / [`manifest::InputManifestV1`] | Yes — public `slots` (cap, order, uniqueness, slot-kind↔object-kind, embedded commitment) | `try_encode` / `try_commitment` (private `encode`) |
//! | [`statement::R0ComputationStatementV2`] | Yes — public fields may embed a valid-but-wrong-kind commitment | `try_encode` / `try_identity` / `template_bytes` (private `encode`) |
//! | [`allowlist::GuestProgramAllowlistV1`] / [`allowlist::GuestProgramEntryV1`] | Yes — public `Vec`, arch rule, ordering | `try_encode` / `try_guest_set_hash` (private `encode`) |
//! | [`verifier_material::VerifierMaterialManifestV1`] | Yes — public `Vec`, label rule, ordering | `try_encode` / `try_identity` (private `encode`) |
//! | [`derived_input::DerivedInputV1`] | **No** — its decoder constrains only constant-written tags/scalars, never a field | infallible `encode`/`identity` |
//! | [`partial_proof::PartialComputeProofV1`] | **No** — free `[u8; 32]` fields; magic/version written as constants | infallible `encode` |
//! | [`proof_envelope::ProductionProofEnvelopeV1`] | **No** — a `Candidate` enum + free `[u8; 32]`; magic/version constants | infallible `encode` |
//!
//! `merkle` exposes only the checked [`merkle::chunk_count_checked`]; there is no
//! infallible lossy chunk-count API. `enums` are closed sets whose `to_repr` is
//! always valid; `codec`/`tags`/`consts`/`hashing` carry no wire value.

#![forbid(unsafe_code)]

pub mod allowlist;
pub mod codec;
pub mod consts;
pub mod derived_input;
pub mod enums;
pub mod hashing;
pub mod manifest;
pub mod merkle;
pub mod object_commitment;
pub mod partial_proof;
pub mod proof_envelope;
pub mod statement;
pub mod tags;
pub mod verifier_material;
pub mod workload;
