//! B0-PRE reference validator (sum-chain #123, stage 1).
//!
//! This crate is the authoritative host-side implementation of the B0-PRE
//! preregistration: the byte-exact schema encoders, the strict + canonical JSON
//! layer, the exp-table generator/certifier, the frozen transformer arithmetic,
//! the deterministic official-workload fixture derivation, the zero-hash
//! statement templates, and the `b0_pre_spec_hash` preimage assembler.
//!
//! It is deliberately **outside** the sum-chain cargo workspace (root
//! `exclude = ["tools"]`) and shares no code with production crates. The
//! sibling crate `b0-pre-independent` re-derives the deterministic artifacts by
//! a separate path so CI can require byte-for-byte agreement.
//!
//! Nothing here runs a proving system, downloads a toolchain, or performs any
//! measurement; those are later R0-stage operational steps.

#![forbid(unsafe_code)]

pub mod codec;
pub mod consts;
pub mod enums;
pub mod exp;
pub mod fixed;
pub mod golden;
pub mod harness;
pub mod hashing;
pub mod json;
pub mod merkle;
pub mod protocol;
pub mod schema;
pub mod tags;
pub mod transformer;
pub mod validation;
pub mod workload;

/// The frozen B0-PRE protocol revision this crate implements.
pub const SPEC_VERSION: &str = "b0-pre/v10";

/// Why a protocol-hash preimage could not be built.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProtocolHashError {
    /// The artifact is `not_finalizable`: these implementation-produced fields
    /// are still absent.
    NotFinalizable(Vec<String>),
    /// Cross-field semantic checks failed.
    SemanticViolations(Vec<String>),
    /// Serialization / canonicalization failure.
    Json(String),
}

/// Canonical JSON bytes of the artifact (sorted keys, minimal numbers), via the
/// crate's own strict canonicalizer — not serde's default writer.
pub fn canonical_protocol_json(
    p: &protocol::B0PreProtocolV1,
) -> Result<Vec<u8>, ProtocolHashError> {
    let s = serde_json::to_string(p).map_err(|e| ProtocolHashError::Json(e.to_string()))?;
    json::canonicalize(s.as_bytes()).map_err(|e| ProtocolHashError::Json(format!("{e:?}")))
}

/// The `b0_pre_spec_hash` preimage: `SPEC_PREFIX ‖ canonical_protocol_json`.
///
/// Refuses to build from a `not_finalizable` artifact (any pending input absent)
/// or one with semantic violations, so no placeholder can ever enter a finalized
/// preimage. `SPEC_PREFIX` is the frozen `SUMCHAIN/B0-PRE/SPEC/v1\n`.
pub fn protocol_hash_preimage(p: &protocol::B0PreProtocolV1) -> Result<Vec<u8>, ProtocolHashError> {
    let viol = p.semantic_violations();
    if !viol.is_empty() {
        return Err(ProtocolHashError::SemanticViolations(viol));
    }
    if !p.is_finalizable() {
        return Err(ProtocolHashError::NotFinalizable(p.pending_inputs.absent()));
    }
    let canon = canonical_protocol_json(p)?;
    let mut pre = tags::SPEC_PREFIX.to_vec();
    pre.extend_from_slice(&canon);
    Ok(pre)
}

/// `BLAKE3(protocol_hash_preimage)` — the finalized `b0_pre_spec_hash`. Same
/// refusal semantics as [`protocol_hash_preimage`].
pub fn protocol_hash(p: &protocol::B0PreProtocolV1) -> Result<[u8; 32], ProtocolHashError> {
    let pre = protocol_hash_preimage(p)?;
    Ok(blake3::hash(&pre).into())
}
