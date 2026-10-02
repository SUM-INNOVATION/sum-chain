//! ConsensusConfigV1: one canonical encoding of the consensus rules this node
//! runs, a domain-separated commitment to it, and a local record of both (#268).
//!
//! # What this is
//!
//! Every value that decides block or transaction validity, fork choice,
//! membership or how consensus data is interpreted — the chain's identity, the
//! rule codes of the engine actually running, every genesis parameter that
//! execution reads, every activation height, and every consensus constant
//! compiled into this binary — encoded field by field under permanent ids and
//! committed to with one hash. Two nodes with equal commitments enforce the
//! same rules; a commitment that moves names the fields that moved.
//!
//! # What this is not
//!
//! It is not network agreement. The stored baseline is an
//! [`record::BaselineStatus::UnverifiedLocalBaseline`]: what THIS node
//! computed from its own `genesis.json` and its own binary. Nothing here is
//! signed, exchanged with peers, placed in a block or compared at handshake,
//! and nothing here activates, schedules or authorizes a change. Binding the
//! commitment to an authenticated upgrade is later work (#268) and will be a
//! separate, reviewed change.
//!
//! It is also not [`sumchain_state::protocol_digest`], which it leaves
//! untouched. That digest is what peers declare at handshake today; changing
//! what it covers would change the value every running node compares, which
//! is a network change this release does not make.
//!
//! # The rules encoded are the rules that run
//!
//! Rule codes describe the implemented engine: proof-of-authority production,
//! LOCAL depth finality (a node's own `head - finality_depth`, no votes, no
//! certificates), longest chain with a lower-hash tiebreak that refuses to
//! unwind below the local finalized height, round-robin proposers, static
//! genesis membership, no bound on how far production may run ahead of
//! finality, and a block timestamp that must exceed its parent's with no
//! wall-clock bound. Code points for certified finality and its rules are
//! reserved in [`fields`] and are not used.
//!
//! # Schema evolution
//!
//! Schema 1 is frozen once a release has written it. Its field set, ids, types
//! and meanings never change, and an id is never reused. A field is added,
//! removed or retyped only by a new schema number with its own registry; this
//! binary refuses to start on a stored record whose schema it does not
//! implement, so an older binary can never misread a newer record. Moving a
//! node from one schema to the next is an explicit, acknowledged transition,
//! never an implicit re-encoding.

pub mod codec;
pub mod fields;
pub mod record;

pub use codec::{commitment_of, ConsensusConfig, Field, FieldChange, Value, SCHEMA_V1};
pub use fields::{build, FieldSpec, SCHEMA_V1_FIELDS};
pub use record::{
    acknowledge, check_at_startup, read_record, read_transitions, Acknowledged, BaselineRecord,
    BaselineStatus, StartupOutcome, Transition, TransitionKind,
};

/// Why a configuration could not be built, decoded, compared or recorded.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ConfigError {
    /// Bytes that the encoder would not have produced.
    #[error("malformed consensus configuration: {0}")]
    Malformed(String),
    /// A schema this binary does not implement.
    #[error("consensus configuration schema {0} is not implemented by this binary")]
    UnknownSchema(u16),
    /// The configuration could not be computed from the genesis.
    #[error("cannot compute the consensus configuration: {0}")]
    Build(String),
    /// A stored record exists and cannot be trusted.
    #[error(
        "the recorded consensus configuration is unreadable or inconsistent: {0}; \
             refusing to start rather than recreate it"
    )]
    RecordCorrupt(String),
    /// The database could not be read or written.
    #[error("{0}")]
    Storage(String),
    /// The change is not permitted.
    #[error("refusing: {0}")]
    Refused(String),
}

impl ConfigError {
    pub(crate) fn malformed(why: impl Into<String>) -> Self {
        ConfigError::Malformed(why.into())
    }
}
