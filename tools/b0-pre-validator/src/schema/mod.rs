//! Byte-exact canonical structures (plan §8).
//!
//! Every structure has an `encode` (deriving its length from the fields it
//! pushes) and a `decode` that rejects truncation, trailing bytes, invalid
//! enums/tags, inconsistent counts, duplicates, non-canonical ordering, and
//! over-long lengths *before* allocating. Documented totals are asserted in
//! tests against literals, never against a shared size constant.

pub mod allowlist;
pub mod bench;
pub mod derived_input;
pub mod envelope;
pub mod manifest;
pub mod object;
pub mod provenance;
pub mod result_set;
pub mod statement;
pub mod verifier_material;
