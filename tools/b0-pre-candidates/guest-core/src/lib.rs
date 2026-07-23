//! # B0-PRE official guest CORE (candidate-neutral)
//!
//! The single, shared source of the guest-side statement contract for the two
//! frozen official B0-PRE statements — `TransformerLayerGroup` and `SelectToken`.
//! Both the SP1 guest and the RISC Zero guest are thin wrappers that read the one
//! input blob, call [`run`], and commit the returned 32-byte journal. Neither
//! wrapper re-implements any semantics, so the two candidates enforce logically
//! identical statements over identical input bytes.
//!
//! ## What is official here, and what is deliberately absent
//!
//! * This is official guest **SOURCE**: the frozen integer transformer, the
//!   strict witness→statement contract, and the committed output form.
//! * It adopts the FROZEN wire types DIRECTLY from `sumchain-wire::b0` (a path
//!   dependency on the merged production crate) — statement, object commitment,
//!   manifests, and derived input are decoded through those exact types, never a
//!   mirror.
//! * It contains **no** program id, verifier key, image id, receipt, cycle
//!   count, or measured cost, and **no** guest-identity / allowlist / spec-hash
//!   selection. Those are venue-built (or later-stage) artifacts; per the
//!   Stage-1 rule they do not enter here. The guest is spec-hash-agnostic: it
//!   commits `computation_statement_hash` over whatever canonical statement it is
//!   given, so no `b0_pre_spec_hash` is fabricated.
//!
//! ## Public output (journal)
//!
//! The ONLY committed value is `computation_statement_hash` = `BLAKE3` over the
//! re-canonicalized 996-byte statement (§17). No host-only or synthetic field is
//! exposed.

#![forbid(unsafe_code)]

use core::fmt;

use sumchain_wire::b0::codec::DecodeError;

pub mod exp;
mod exp_table;
pub mod fixed;
pub mod input;
pub mod transformer;
pub mod verify;

pub use input::GuestInput;

/// Every way the guest deterministically rejects an input. A guest wrapper turns
/// any `Err` into a zkVM abort, so a malformed or false statement yields NO valid
/// proof — there is no partial/ambiguous acceptance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GuestError {
    /// A frozen wire structure (statement / commitment / manifest / envelope) or
    /// the guest-input envelope failed strict decode.
    Decode(DecodeError),
    /// A semantic check failed: a witness did not authenticate against the
    /// statement, a recomputed output did not match, or a frozen sentinel/bound
    /// was violated.
    Semantic(&'static str),
}

impl From<DecodeError> for GuestError {
    fn from(e: DecodeError) -> Self {
        GuestError::Decode(e)
    }
}

impl fmt::Display for GuestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            GuestError::Decode(e) => write!(f, "decode error: {e}"),
            GuestError::Semantic(r) => write!(f, "semantic rejection: {r}"),
        }
    }
}

impl std::error::Error for GuestError {}

/// The official guest entrypoint: decode the guest-input envelope, verify the
/// witness→statement contract for the statement's `unit_kind`, and return the
/// single committed journal (`computation_statement_hash`, 32 bytes).
///
/// Deterministic: identical bytes → identical result. Any malformed tag,
/// noncanonical encoding, reserved value, wrong statement kind, trailing byte, or
/// failing semantic check returns `Err` (which the wrapper turns into an abort).
pub fn run(input_bytes: &[u8]) -> Result<[u8; 32], GuestError> {
    let input = GuestInput::decode(input_bytes)?;
    verify::verify_and_journal(&input)
}
