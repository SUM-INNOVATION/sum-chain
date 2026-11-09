//! The handshake digest: the one value a node declares to its peers, and
//! compares theirs against, before anything they send is acted on.
//!
//! ```text
//! handshake digest = BLAKE3-256( HANDSHAKE_DIGEST_DOMAIN ‖ protocol digest ‖ running commitment )
//!
//! offset  size  field
//! 0       27    HANDSHAKE_DIGEST_DOMAIN, ASCII "sumchain/protocol-digest/v2", no terminator
//! 27      32    sumchain_state::protocol_digest::protocol_digest(genesis)
//! 59      32    build(genesis).commitment(), in PRODUCTION.writes
//! ```
//!
//! 91 bytes are hashed. Both inputs are fixed-width digests, so the order is
//! fixed and there are no length prefixes, and the preimage holds no integer.
//! The schema number is inside the running commitment's own encoding, in the
//! byte order that frozen format defines.
//!
//! # What it adds to the protocol digest
//!
//! The protocol digest covers the chain identity, every activation height and
//! the compiled `consensus_limits()`. It does not cover the rest of the
//! consensus configuration: the rule codes, every non-gate genesis parameter
//! (`min_fee`, `finality_depth`, the staking, messaging, docclass, governance,
//! beacon and compute-pool groups), the reorg bounds and the other compiled
//! constants. Two nodes that differ only there declare the same protocol
//! digest. They declare different handshake digests.
//!
//! The protocol digest is folded whole, although the running configuration
//! already holds the identity fields, every gate and every limit. So the
//! handshake digest is at least as discriminating as the protocol digest by
//! construction, without relying on that mapping staying complete.
//!
//! # The running commitment, never the recorded one
//!
//! The commitment folded is that of [`build`]: the configuration this binary
//! computes from its `genesis.json`, in the schema it writes. It is a pure
//! function of the genesis and the binary, so a restart with both unchanged
//! reproduces it bit for bit, and it moves only when one of them moves.
//!
//! The commitment recorded in a node's database is not. Its schema is moved by
//! a per-node, stopped-node command and its transitions are recorded at that
//! node's own starts, so two nodes running identical rules can hold different
//! recorded commitments. After a successful start the record describes the
//! same rules as the running configuration (startup refuses or records any
//! difference), so nothing is lost by declaring the running one.
//!
//! # What it is not
//!
//! It is not a consensus value. No block, header, state root, receipt or
//! database row holds it, and no validity rule reads it. A peer that declares
//! a different one is refused at the network boundary; that is detection and
//! exclusion only. A peer can declare this node's value and enforce other
//! rules, and only block validity and the values bound in the state root
//! refuse its blocks. It never substitutes for either.
//!
//! It allocates nothing: no activation gate, no consensus-configuration field
//! and no schema number.
//!
//! # Installing a binary that declares it is the activation
//!
//! [`HANDSHAKE_DIGEST_DOMAIN`] has the length of the protocol digest's domain
//! (`sumchain_state::protocol_digest::PROTOCOL_DIGEST_DOMAIN`) and differs
//! from it, so a handshake digest never equals a protocol digest. A node that
//! declares a handshake digest and one that declares a protocol digest refuse
//! each other at connect, in both phases, whatever their rules: every
//! validator moves to such a binary in the same window. From then on, a change
//! to any input of the running configuration, a non-gate value included, is
//! same-window too.

use sumchain_genesis::Genesis;
use sumchain_primitives::Hash;

use super::codec::ConsensusConfig;
use super::fields::build;
use super::ConfigError;

/// Domain separator of the handshake digest.
///
/// The protocol digest's domain with the version moved from 1 to 2: the same
/// length, never the same bytes, so the two values cannot be confused or
/// compared by accident.
pub const HANDSHAKE_DIGEST_DOMAIN: &[u8] = b"sumchain/protocol-digest/v2";

/// The handshake digest of `protocol_digest` and the running configuration.
///
/// `running` must be this binary's running configuration, [`build`] of the
/// genesis `protocol_digest` was computed from. Never the configuration
/// recorded in a database: see the module documentation.
pub fn handshake_digest(protocol_digest: Hash, running: &ConsensusConfig) -> Hash {
    let mut preimage = Vec::with_capacity(HANDSHAKE_DIGEST_DOMAIN.len() + 2 * Hash::SIZE);
    preimage.extend_from_slice(HANDSHAKE_DIGEST_DOMAIN);
    preimage.extend_from_slice(protocol_digest.as_bytes());
    preimage.extend_from_slice(running.commitment().as_bytes());
    Hash::hash(&preimage)
}

/// This binary's handshake digest for `genesis`.
///
/// Fails exactly where computing the protocol digest or [`build`] fails, the
/// same inputs on which node start already fails.
pub fn handshake_digest_for(genesis: &Genesis) -> Result<Hash, ConfigError> {
    let protocol_digest = sumchain_state::protocol_digest::protocol_digest(genesis)
        .map_err(|e| ConfigError::Build(format!("computing the protocol digest: {e}")))?;
    Ok(handshake_digest(protocol_digest, &build(genesis)?))
}
