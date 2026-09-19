//! The protocol digest: one value naming everything two validators must agree
//! about before a block is produced — the configured heights AND the compiled-in
//! rules.
//!
//! # Why this exists beside `Genesis::activation_digest`
//!
//! [`sumchain_genesis::Genesis::activation_digest`] covers `Option<u64>`
//! activation heights and nothing else. Its own doc comment, and the doc
//! comments on [`crate::MAX_SUBSYSTEM_PAYLOAD_BYTES`],
//! [`crate::MAX_ACCUMULATING_ROW_BYTES`] and
//! [`crate::MAX_NFT_BATCH_MINT_REQUESTS`], make the same argument for keeping
//! those three limits out of `ChainParams`:
//!
//! > the activation digest covers `Option<u64>` gates and nothing else, so a
//! > configurable limit would be a consensus-relevant number two validators
//! > could hold different values of with nothing to compare.
//!
//! That argument is half-complete, and the missing half is the point of this
//! module. Making the limit a `ChainParams` field would indeed create a number
//! validators could differ on with nothing to compare. Leaving it a binary
//! constant does NOT remove that number — it moves it from the config file to
//! the BINARY, where there is still nothing to compare. Two nodes built from
//! different commits, or one operator running a patched build, enforce different
//! validity rules and report the *same* activation digest. The comparison
//! operators are told to make is then a comparison that cannot fail for the one
//! class of difference the binary owns.
//!
//! The fix is not to make the constants configurable. It is to make them
//! *comparable*: fold every consensus-relevant compiled-in value into a digest
//! alongside the heights, so that two binaries enforcing different rules produce
//! different digests even when their `genesis.json` files are byte-identical.
//!
//! # What it covers
//!
//! ```text
//! blake3( DOMAIN
//!         ‖ chain_id:u64 BE
//!         ‖ activation_digest[32]          // every Option<u64> gate, transitively
//!         ‖ limit_count:u64 BE
//!         ‖ for each limit in FIXED declared order:
//!               name_len:u64 BE ‖ name ‖ tag:u8 ‖ value )
//! ```
//!
//! The activation digest is folded whole rather than recomputed, so every gate
//! it covers — and the source-scan exhaustiveness test that keeps it covering
//! them — is inherited here for free. A gate added to `ChainParams` moves this
//! digest without this module being touched.
//!
//! The name is folded beside the value so that RENAMING a limit, or moving a
//! value from one limit to another, changes the digest. The tag byte separates
//! the numeric and byte-string cases so that a number and a byte string with the
//! same encoding cannot collide.
//!
//! # What it is not
//!
//! It is not a consensus value and nothing in block validation reads it. It is a
//! PRE-FLIGHT value: computed before consensus exists, published on the wire at
//! handshake (`sumchain_p2p::SyncRequest::GetProtocolId`) and on the operator
//! RPC surface. A peer that declares a different one is refused; a peer too old
//! to declare one at all is not. See `crates/p2p/src/block_syncer.rs`.
//!
//! Folding it into a block header instead would be the other candidate design,
//! and it is rejected here: a header field that today's validators do not write
//! is a consensus change, and gating it behind a new activation height makes the
//! mechanism depend on the very coordination it exists to verify. A refusal that
//! fires on the current chain is worse than the defect it closes.

use sumchain_genesis::Genesis;
use sumchain_primitives::Hash;

use crate::{Result, StateError};

/// Domain separator for the protocol digest.
///
/// Versioned in the string: a future digest covering a different value set is a
/// different value under a different domain, so two binaries that disagree about
/// WHICH values are consensus-relevant cannot compare digests by accident and
/// conclude they agree.
pub const PROTOCOL_DIGEST_DOMAIN: &[u8] = b"sumchain/protocol-digest/v1";

/// One compiled-in consensus value, as it is folded.
///
/// Two shapes because the constants have two shapes. A limit is a magnitude and
/// a domain separator is a byte string; encoding the second as the first would
/// mean hashing it twice or truncating it, and encoding the first as the second
/// would make `512` and `"512"` the same fold.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LimitValue {
    /// A magnitude: a byte cap, a count cap, a height, a threshold, a version.
    ///
    /// `u128` rather than `u64` because `NATIVE_PASS_THRESHOLD_BPS` is a `u128`
    /// and widening at the fold is lossless for every narrower constant.
    Num(u128),
    /// A frozen byte string: a hash domain separator whose exact bytes are part
    /// of the value every validator must compute identically.
    Bytes(&'static [u8]),
}

impl LimitValue {
    /// The tag byte that separates the two shapes in the preimage.
    fn tag(&self) -> u8 {
        match self {
            LimitValue::Num(_) => 0,
            LimitValue::Bytes(_) => 1,
        }
    }
}

/// Every consensus-relevant compiled-in value this binary enforces, in a FIXED
/// declared order.
///
/// The order is the digest's order and must never be permuted: reordering
/// changes the digest without changing a single value, which would read to an
/// operator as a binary mismatch that is not one.
///
/// # Inclusion rule
///
/// A value belongs here when two validator binaries holding DIFFERENT values for
/// it would disagree about whether a transaction is valid, about what a receipt
/// says, or about what a committed digest commits to. A value does NOT belong
/// here when it only affects what one node logs, caches, prunes, paginates, or
/// answers an RPC query with — those differ between nodes today, deliberately,
/// and folding them in would make the digest report mismatches that are not
/// consensus mismatches.
///
/// The census behind each verdict, including the values deliberately EXCLUDED
/// and why, is `crates/state/tests/protocol_digest_census.rs`, which fails if a
/// new constant appears in `crates/state/src` or `crates/storage/src` matching
/// the shape of a limit and is classified in neither direction.
pub fn consensus_limits() -> Vec<(&'static str, LimitValue)> {
    vec![
        // ── Allocation bounds. Each decides, where its gate is open, whether a
        //    transaction is REFUSED before the value is built. A binary with a
        //    larger bound admits a transaction its peers fail, and the success
        //    bit and fee of that receipt are folded into the block state root.
        (
            "MAX_SUBSYSTEM_PAYLOAD_BYTES",
            LimitValue::Num(crate::MAX_SUBSYSTEM_PAYLOAD_BYTES as u128),
        ),
        (
            "MAX_ACCUMULATING_ROW_BYTES",
            LimitValue::Num(crate::MAX_ACCUMULATING_ROW_BYTES as u128),
        ),
        (
            "MAX_NFT_BATCH_MINT_REQUESTS",
            LimitValue::Num(crate::nft_executor::MAX_NFT_BATCH_MINT_REQUESTS as u128),
        ),
        // Arrived from a different track than the three above, and the census
        // test is how it got here: it refused to pass until this constant was
        // classified in one direction or the other. It decides validity --
        // `index_key_text_within_bound` refuses an oversized jurisdiction code
        // above its gate in Legal, Finance and Property, before the text becomes
        // a raw column-family key -- so it is folded rather than excluded.
        (
            "MAX_INDEX_KEY_TEXT_BYTES",
            LimitValue::Num(crate::MAX_INDEX_KEY_TEXT_BYTES as u128),
        ),
        // ── Block applicability. `CANDIDATE_LIMIT_SCAFFOLD` is the one the
        //    census found that nobody was looking for: a LIVE 1 GiB ceiling on a
        //    block's logical write set, read on the production `execute_block`
        //    path, whose own doc comment says "a limit that can refuse a write
        //    helps decide whether a block is applicable, which makes it
        //    consensus-relevant and not a number a storage or executor module
        //    may invent". It is exactly the hazard this digest exists for, and
        //    it is ungated — two binaries with different scaffolds disagree
        //    about a large block today, not at some future height.
        (
            "CANDIDATE_LIMIT_SCAFFOLD",
            LimitValue::Num(crate::executor::CANDIDATE_LIMIT_SCAFFOLD as u128),
        ),
        // `candidate.rs` calls this "a consensus rule" in as many words: at or
        // below it a root mismatch is force-adopted, above it the same mismatch
        // is refused. Two binaries with different windows disagree about whether
        // a divergent block is a fork or a fault — which is the very absorption
        // that hides the activation-height defect.
        (
            "LEGACY_ROOT_COMPATIBILITY_HEIGHT",
            LimitValue::Num(sumchain_storage::candidate::LEGACY_ROOT_COMPATIBILITY_HEIGHT as u128),
        ),
        // ── Economic and governance outcomes. Each decides what state a
        //    successful transaction writes, not merely whether it succeeds.
        (
            "NATIVE_PASS_THRESHOLD_BPS",
            LimitValue::Num(crate::governance_executor::NATIVE_PASS_THRESHOLD_BPS),
        ),
        (
            "MIN_ARCHIVE_STAKE",
            LimitValue::Num(crate::node_registry::MIN_ARCHIVE_STAKE as u128),
        ),
        // ── Credential field caps. Above the schema-validation gate each is an
        //    accept/reject boundary for a credential-issuing transaction. They
        //    were declared inside the function bodies that read them until this
        //    change, which is the same hazard one level further down: a number
        //    that decides validity and that nothing could name, let alone
        //    compare.
        (
            "MAX_TITLE_LENGTH",
            LimitValue::Num(crate::schema_validator::MAX_TITLE_LENGTH as u128),
        ),
        (
            "MAX_CREDENTIAL_TYPE_LENGTH",
            LimitValue::Num(crate::schema_validator::MAX_CREDENTIAL_TYPE_LENGTH as u128),
        ),
        (
            "MAX_PROGRAM_LENGTH",
            LimitValue::Num(crate::schema_validator::MAX_PROGRAM_LENGTH as u128),
        ),
        (
            "MAX_DATE_LENGTH",
            LimitValue::Num(crate::schema_validator::MAX_DATE_LENGTH as u128),
        ),
        (
            "MAX_ATTRIBUTE_VALUE_LENGTH",
            LimitValue::Num(crate::schema_validator::MAX_ATTRIBUTE_VALUE_LENGTH as u128),
        ),
        (
            "MAX_NAME_LENGTH",
            LimitValue::Num(crate::schema_validator::MAX_NAME_LENGTH as u128),
        ),
        (
            "MAX_HINT_LENGTH",
            LimitValue::Num(crate::schema_validator::MAX_HINT_LENGTH as u128),
        ),
        // ── Stored-record schema versions. Both are stamped into records that
        //    feed a state digest the block state root folds, and both modules
        //    say so: a decoder that rejects a version its peers accept produces
        //    a different digest from the same bytes.
        (
            "C1_SCHEMA_VERSION",
            LimitValue::Num(crate::compute_pool_store::C1_SCHEMA_VERSION as u128),
        ),
        (
            "BEACON_RECORD_VERSION",
            LimitValue::Num(crate::beacon_store::BEACON_RECORD_VERSION as u128),
        ),
        // ── Decode ceilings on stored records. Their own doc comments call them
        //    local anti-DoS bounds rather than consensus caps, and at today's
        //    record sizes that is true. They are folded anyway, because "no
        //    record ever reaches 1 MiB" is a claim about data, not a rule
        //    enforced anywhere: if one ever did, the node with the smaller
        //    ceiling refuses a record its peers decode, inside a digest the root
        //    folds. Folding a value that never moves costs an operator nothing;
        //    omitting one that does costs a fork.
        (
            "C1_DECODE_BYTE_LIMIT",
            LimitValue::Num(crate::compute_pool_store::C1_DECODE_BYTE_LIMIT as u128),
        ),
        (
            "BEACON_DECODE_BYTE_LIMIT",
            LimitValue::Num(crate::beacon_store::BEACON_DECODE_BYTE_LIMIT as u128),
        ),
        // ── Beacon wire widths. Each is a validity check on a fixed-width
        //    field; a binary with a different width accepts or refuses a
        //    different set of deals, carriers and signatures.
        (
            "G1_LEN",
            LimitValue::Num(crate::beacon_store::G1_LEN as u128),
        ),
        (
            "G2_LEN",
            LimitValue::Num(crate::beacon_store::G2_LEN as u128),
        ),
        (
            "CT_LEN",
            LimitValue::Num(crate::beacon_store::CT_LEN as u128),
        ),
        (
            "OUT_LEN",
            LimitValue::Num(crate::beacon_store::OUT_LEN as u128),
        ),
        // ── Frozen hash domains. Not limits, but the same hazard in a purer
        //    form: the bytes go straight into a digest the block state root
        //    folds, so a one-character difference between two binaries is a
        //    silent, total divergence of that commitment with no configuration
        //    difference anywhere to find. `C1_STATE_DIGEST_DOMAIN` says of
        //    itself that changing it "is a consensus-breaking change".
        (
            "ACCOUNT_STATE_DIGEST_DOMAIN",
            LimitValue::Bytes(crate::account_root::ACCOUNT_STATE_DIGEST_DOMAIN),
        ),
        (
            "C1_STATE_DIGEST_DOMAIN",
            LimitValue::Bytes(crate::compute_pool_store::C1_STATE_DIGEST_DOMAIN),
        ),
        (
            "BEACON_STATE_DIGEST_DOMAIN",
            LimitValue::Bytes(crate::beacon_store::BEACON_STATE_DIGEST_DOMAIN),
        ),
        (
            "DOCCLASS_STAKE_ESCROW_DOMAIN",
            LimitValue::Bytes(crate::docclass_executor::DOCCLASS_STAKE_ESCROW_DOMAIN),
        ),
        (
            "ASSIGN_SCORE_CONTEXT",
            LimitValue::Bytes(crate::compute_pool::ASSIGN_SCORE_CONTEXT.as_bytes()),
        ),
        (
            "CONTRACT_STATE_DIFF_DOMAIN",
            LimitValue::Bytes(sumchain_storage::schema::CONTRACT_STATE_DIFF_DOMAIN),
        ),
        (
            "EQUITY_MERKLE_LEAF_DOMAIN",
            LimitValue::Bytes(sumchain_storage::equity_store::EQUITY_MERKLE_LEAF_DOMAIN),
        ),
        (
            "EQUITY_MERKLE_NODE_DOMAIN",
            LimitValue::Bytes(sumchain_storage::equity_store::EQUITY_MERKLE_NODE_DOMAIN),
        ),
        (
            "EQUITY_MERKLE_EMPTY_DOMAIN",
            LimitValue::Bytes(sumchain_storage::equity_store::EQUITY_MERKLE_EMPTY_DOMAIN),
        ),
        // ── Key encodings that select which rows a committed digest scans.
        //    `ACCOUNT_KEY_PREFIX` picks out the account rows inside a shared
        //    column family, so a binary with a different prefix folds a
        //    different (empty) account set into the account-state digest.
        (
            "ACCOUNT_KEY_PREFIX",
            LimitValue::Bytes(sumchain_storage::schema::ACCOUNT_KEY_PREFIX),
        ),
        (
            "SUBJECT_IDENTITY_INDEX_TAG",
            LimitValue::Num(sumchain_storage::docclass_store::SUBJECT_IDENTITY_INDEX_TAG as u128),
        ),
    ]
}

/// This binary's protocol digest for `genesis`.
///
/// The value an operator compares, the RPC publishes and a peer declares at
/// handshake. Two nodes agree here exactly when they agree about every
/// activation height AND every value in [`consensus_limits`].
pub fn protocol_digest(genesis: &Genesis) -> Result<Hash> {
    protocol_digest_with_limits(genesis, &consensus_limits())
}

/// [`protocol_digest`] against an explicitly supplied limit set.
///
/// The digest is a pure function of `(genesis, limits)`, and this is the seam
/// that makes that testable: a test cannot link two binaries, but it can compute
/// the digest the OTHER binary would have computed by passing the limit set that
/// binary was built with. `protocol_digest_mismatched_binaries.rs` uses exactly
/// this to assert that a one-value difference in a compiled-in constant is
/// visible in the comparison, without needing a second compiler invocation.
pub fn protocol_digest_with_limits(
    genesis: &Genesis,
    limits: &[(&str, LimitValue)],
) -> Result<Hash> {
    let activation = genesis.activation_digest().map_err(|e| {
        StateError::Genesis(format!("computing the genesis activation digest: {}", e))
    })?;

    let mut data = Vec::new();
    data.extend_from_slice(PROTOCOL_DIGEST_DOMAIN);
    data.extend_from_slice(&genesis.chain_id.to_be_bytes());
    data.extend_from_slice(activation.as_bytes());

    // The count is folded before the entries so that a shorter list cannot be a
    // prefix of a longer one whose extra entry happens to fold to nothing.
    data.extend_from_slice(&(limits.len() as u64).to_be_bytes());
    for (name, value) in limits {
        data.extend_from_slice(&(name.len() as u64).to_be_bytes());
        data.extend_from_slice(name.as_bytes());
        data.push(value.tag());
        match value {
            LimitValue::Num(n) => data.extend_from_slice(&n.to_be_bytes()),
            LimitValue::Bytes(b) => {
                // Length-prefixed: without it, two adjacent byte-string values
                // could be re-split between the fields and fold identically.
                data.extend_from_slice(&(b.len() as u64).to_be_bytes());
                data.extend_from_slice(b);
            }
        }
    }

    Ok(Hash::hash(&data))
}
