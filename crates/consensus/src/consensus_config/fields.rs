//! The schema-1 field registry, and the builder that fills it from a genesis
//! and this binary.
//!
//! # Ids
//!
//! | range | contents |
//! |---|---|
//! | `0x0001–0x000f` | chain identity |
//! | `0x0010–0x001f` | rule codes of the engine that runs |
//! | `0x0100–0x01ff` | scalar `ChainParams` read by consensus code |
//! | `0x0200–0x02ff` | fork-choice and reorg bounds |
//! | `0x0300–0x07ff` | nested parameter groups, effective values |
//! | `0x1000–0x1fff` | activation heights, by gate name |
//! | `0x2000–0x20ff` | `sumchain_state::protocol_digest::consensus_limits`, by name |
//! | `0x2100–0x2fff` | further compiled consensus constants |
//!
//! Ids are permanent. A field that leaves the configuration retires its id; a
//! field that joins gets a new one, under a new schema: post-schema-1 fields,
//! activation gates included, are registered in [`super::schema`] (schema 2's
//! append-only list), never here.
//!
//! # Inclusion rule
//!
//! A value is committed when two nodes holding different values for it would
//! disagree about whether a block or transaction is valid, what state or
//! receipt it produces, which branch wins, who may propose, or how consensus
//! data is interpreted. A value is excluded when it only changes what one node
//! schedules, logs, caches, serves or how much it may hold.
//!
//! Every genesis parameter is classified here: [`build`] destructures each
//! parameter struct WITHOUT `..`, so a field added to any of them fails to
//! compile until it is placed in one direction or the other. Every exclusion
//! is listed in [`EXCLUDED_PARAMETERS`] with its reason, and
//! `crates/consensus/tests/consensus_config_census.rs` fails if any excluded
//! field gains a reader in consensus code.
//!
//! # Effective values
//!
//! A parameter group that genesis leaves unset is not "no value": execution
//! falls back to compiled defaults, and those defaults are the rule. Each group
//! commits a `*_configured` flag AND the values execution actually uses, so a
//! binary whose fallback changed commits differently even under an identical
//! genesis.

use sumchain_genesis::{ChainParams, Genesis};
use sumchain_primitives::{Address, Hash, StakingParams};
use sumchain_state::protocol_digest::{consensus_limits, LimitValue};

use super::codec::{ConsensusConfig, Field, Value};
use super::schema::{Schema, SchemaPolicy, Source, PRODUCTION};
use super::ConfigError;

/// Wire type of a field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ty {
    U8,
    U16,
    U32,
    U64,
    U128,
    Bool,
    Bytes,
    Digest,
    List,
}

/// How a list field's items are ordered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ListOrder {
    /// As declared, because the order carries meaning. Duplicates refused.
    Declared,
    /// Strictly ascending bytes, because the order carries none.
    SortedUnique,
}

/// One registry entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FieldSpec {
    pub id: u16,
    pub name: &'static str,
    pub ty: Ty,
    /// May carry [`Value::Absent`].
    pub optional: bool,
    /// Exact width of a `Bytes` value or of every `List` item.
    pub item_width: Option<usize>,
    pub list_order: ListOrder,
}

const fn spec(id: u16, name: &'static str, ty: Ty, optional: bool) -> FieldSpec {
    FieldSpec {
        id,
        name,
        ty,
        optional,
        item_width: None,
        list_order: ListOrder::SortedUnique,
    }
}
const fn req(id: u16, name: &'static str, ty: Ty) -> FieldSpec {
    spec(id, name, ty, false)
}
const fn opt(id: u16, name: &'static str, ty: Ty) -> FieldSpec {
    spec(id, name, ty, true)
}
/// A required list whose order is as declared.
const fn list(id: u16, name: &'static str) -> FieldSpec {
    FieldSpec {
        id,
        name,
        ty: Ty::List,
        optional: false,
        item_width: None,
        list_order: ListOrder::Declared,
    }
}
/// An optional 20-byte address.
const fn addr(id: u16, name: &'static str) -> FieldSpec {
    FieldSpec {
        id,
        name,
        ty: Ty::Bytes,
        optional: true,
        item_width: Some(20),
        list_order: ListOrder::SortedUnique,
    }
}

// ── Rule codes ──────────────────────────────────────────────────────────────
//
// Each describes what the running engine does. Values not listed as
// "current" are reserved for rules that do not exist yet and are never
// encoded by this binary.

/// `0x0010` engine. 1 = proof-of-authority block production (current).
/// 2 = reserved: proof-of-authority production with certified finality.
pub const ENGINE_POA: u8 = 1;
/// `0x0011` finality rule. 1 = local depth (current): a node treats height
/// `h` as final once its own head reaches `h + finality_depth`; no votes, no
/// certificates, and two nodes may hold different finalized heights.
/// 2 = reserved: quorum certificates.
pub const FINALITY_LOCAL_DEPTH: u8 = 1;
/// `0x0012` quorum rule. 0 = none (current): nothing is voted on.
/// 1 = reserved: headcount `floor(2n/3) + 1` over the validator set.
pub const QUORUM_NONE: u8 = 0;
/// `0x0013` fork choice. 1 = longest chain, lower block hash wins a tie, a
/// switch may not unwind at or below this node's local finalized height, and
/// the ancestor walk is bounded by `max_reorg_walk` (current).
/// 2 = reserved: the same, bounded by certified finality instead.
pub const FORK_CHOICE_LONGEST_LOCAL_FINALITY: u8 = 1;
/// `0x0014` proposer rule. 1 = round robin, `validators[h mod n]` (current).
pub const PROPOSER_ROUND_ROBIN: u8 = 1;
/// `0x0015` membership rule. 1 = the static genesis validator list in
/// declared order (current). Dynamic membership is refused by protocol v1.
pub const MEMBERSHIP_STATIC_GENESIS: u8 = 1;
/// `0x0016` unfinalized-production rule. 0 = unbounded (current): production
/// never waits for finality, and only the reorg bounds limit how much
/// unfinalized history exists. 1 = reserved: at most a configured distance.
pub const UNFINALIZED_UNBOUNDED: u8 = 0;
/// `0x0017` block timestamp rule. 1 = strictly greater than the parent's,
/// with no bound against local time (current). `max_future_drift_ms` is
/// committed as absent because no such bound exists.
pub const TIMESTAMP_AFTER_PARENT: u8 = 1;

/// `0x0018` protocol version. 1 = protocol v1 (current): the rules
/// `check_protocol_v1` enforces — round-robin proposers over static genesis
/// membership (#267, #272). Each future authenticated upgrade moves it by one.
pub const PROTOCOL_VERSION: u16 = 1;

/// The schema-1 registry, in ascending id order.
pub static SCHEMA_V1_FIELDS: &[FieldSpec] = &[
    // ── identity ──
    req(0x0001, "chain_id", Ty::U64),
    req(0x0002, "genesis_time", Ty::U64),
    FieldSpec {
        id: 0x0003,
        name: "validators",
        ty: Ty::List,
        optional: false,
        item_width: Some(32),
        list_order: ListOrder::Declared,
    },
    req(0x0004, "alloc_digest", Ty::Digest),
    req(0x0005, "genesis_block_hash", Ty::Digest),
    // ── rule codes ──
    req(0x0010, "engine", Ty::U8),
    req(0x0011, "finality_rule", Ty::U8),
    req(0x0012, "quorum_rule", Ty::U8),
    req(0x0013, "fork_choice_rule", Ty::U8),
    req(0x0014, "proposer_rule", Ty::U8),
    req(0x0015, "membership_rule", Ty::U8),
    req(0x0016, "unfinalized_rule", Ty::U8),
    req(0x0017, "timestamp_rule", Ty::U8),
    req(0x0018, "protocol_version", Ty::U16),
    // ── scalar chain parameters ──
    req(0x0100, "max_block_bytes", Ty::U64),
    req(0x0101, "max_txs_per_block", Ty::U32),
    req(0x0102, "min_fee", Ty::U128),
    req(0x0103, "finality_depth", Ty::U64),
    req(0x0104, "max_metadata_bytes", Ty::U64),
    req(0x0105, "min_contract_gas", Ty::U64),
    req(0x0106, "max_contract_gas", Ty::U64),
    req(0x0107, "max_access_list_bytes", Ty::U64),
    req(0x0108, "activation_grace_blocks", Ty::U64),
    req(0x0109, "abandonment_fee_percent", Ty::U64),
    req(0x010a, "max_chunk_count_per_file", Ty::U32),
    req(0x010b, "max_chunk_indices_per_tx", Ty::U32),
    req(0x010c, "assignment_replication_factor", Ty::U32),
    req(0x010d, "archive_unbonding_period_blocks", Ty::U64),
    req(0x010e, "max_assignment_aware_challenges_per_block", Ty::U32),
    req(0x010f, "max_files_sampled_per_interval", Ty::U32),
    req(0x0110, "max_chunks_sampled_per_file", Ty::U32),
    req(
        0x0111,
        "inference_settlement_max_dispute_window_blocks",
        Ty::U64,
    ),
    req(
        0x0112,
        "inference_settlement_max_session_duration_blocks",
        Ty::U64,
    ),
    opt(
        0x0113,
        "inference_settlement_dispute_threshold_bps",
        Ty::U16,
    ),
    req(
        0x0114,
        "inference_verifier_unbonding_period_blocks",
        Ty::U64,
    ),
    // ── fork choice and reorg bounds ──
    req(0x0200, "max_reorg_walk", Ty::U64),
    req(0x0201, "undo_retention_floor", Ty::U64),
    opt(0x0202, "max_future_drift_ms", Ty::U64),
    // ── staking (effective: genesis, or the executor's fallback) ──
    req(0x0300, "staking_configured", Ty::Bool),
    req(0x0301, "staking.min_validator_stake", Ty::U128),
    req(0x0302, "staking.max_validators", Ty::U32),
    req(0x0303, "staking.unbonding_period", Ty::U64),
    req(0x0304, "staking.max_commission_bps", Ty::U16),
    req(0x0305, "staking.double_sign_slash_bps", Ty::U16),
    req(0x0306, "staking.downtime_slash_bps", Ty::U16),
    req(0x0307, "staking.double_sign_jail_duration", Ty::U64),
    req(0x0308, "staking.downtime_jail_duration", Ty::U64),
    req(0x0309, "staking.downtime_threshold", Ty::U64),
    req(0x030a, "staking.epoch_length", Ty::U64),
    req(0x030b, "staking.stake_weighted_selection", Ty::Bool),
    // ── messaging (effective: genesis, or `MessagingParams::default`) ──
    req(0x0400, "messaging_configured", Ty::Bool),
    addr(0x0401, "messaging.registry_admin"),
    req(0x0402, "messaging.spam_threshold", Ty::U32),
    req(0x0403, "messaging.high_spam_threshold", Ty::U32),
    // ── docclass (unset: no stake rule, no admin, no validity bound) ──
    req(0x0500, "docclass_configured", Ty::Bool),
    opt(0x0501, "docclass.min_issuer_stake", Ty::U128),
    addr(0x0502, "docclass.admin"),
    opt(0x0503, "docclass.max_credential_validity", Ty::U64),
    opt(0x0504, "docclass.require_issuer_stake", Ty::Bool),
    // ── governance (unset: governance transactions fail) ──
    req(0x0600, "governance_configured", Ty::Bool),
    opt(
        0x0601,
        "governance.validator_authority_threshold_bps",
        Ty::U16,
    ),
    opt(0x0602, "governance.quorum_bps", Ty::U16),
    opt(0x0603, "governance.pass_threshold_bps", Ty::U16),
    opt(0x0604, "governance.voting_period_blocks", Ty::U64),
    opt(0x0605, "governance.max_snapshot_holders", Ty::U32),
    opt(0x0606, "governance.proposal_bond", Ty::U128),
    addr(0x0607, "governance.treasury"),
    opt(0x0608, "governance.min_koppa_for_eligibility", Ty::U128),
    // ── beacon parameters (as configured) ──
    req(0x0700, "beacon_params_configured", Ty::Bool),
    opt(0x0701, "beacon_params.f", Ty::U32),
    opt(0x0702, "beacon_params.c", Ty::U32),
    opt(0x0703, "beacon_params.t", Ty::U32),
    opt(0x0704, "beacon_params.q_dkg", Ty::U32),
    opt(0x0705, "beacon_params.n", Ty::U32),
    // ── beacon schedule (as configured) ──
    req(0x0710, "beacon_schedule_configured", Ty::Bool),
    opt(0x0711, "beacon_schedule.start_height", Ty::U64),
    opt(0x0712, "beacon_schedule.epoch_length", Ty::U64),
    opt(0x0713, "beacon_schedule.key_cutoff_offset", Ty::U64),
    opt(0x0714, "beacon_schedule.deal_start_offset", Ty::U64),
    opt(0x0715, "beacon_schedule.deal_cutoff_offset", Ty::U64),
    opt(0x0716, "beacon_schedule.complaint_start_offset", Ty::U64),
    opt(0x0717, "beacon_schedule.complaint_deadline_offset", Ty::U64),
    // ── activation heights, `ChainParams::activation_heights` order ──
    opt(0x1000, "v2_enabled_from_height", Ty::U64),
    opt(0x1001, "omninode_enabled_from_height", Ty::U64),
    opt(
        0x1002,
        "omninode_sponsored_attestation_enabled_from_height",
        Ty::U64,
    ),
    opt(0x1003, "education_enabled_from_height", Ty::U64),
    opt(0x1004, "contracts_enabled_from_height", Ty::U64),
    opt(0x1005, "account_root_enabled_from_height", Ty::U64),
    opt(0x1006, "governance_enabled_from_height", Ty::U64),
    opt(0x1007, "archive_unbonding_enabled_from_height", Ty::U64),
    opt(0x1008, "archive_reassignment_enabled_from_height", Ty::U64),
    opt(
        0x1009,
        "por_assignment_targeting_enabled_from_height",
        Ty::U64,
    ),
    opt(0x100a, "service_grants_enabled_from_height", Ty::U64),
    opt(0x100b, "monetary_policy_enabled_from_height", Ty::U64),
    opt(
        0x100c,
        "assignment_aware_por_scheduler_enabled_from_height",
        Ty::U64,
    ),
    opt(0x100d, "inference_settlement_enabled_from_height", Ty::U64),
    opt(
        0x100e,
        "inference_settlement_consistency_enabled_from_height",
        Ty::U64,
    ),
    opt(
        0x100f,
        "inference_verifier_bonding_enabled_from_height",
        Ty::U64,
    ),
    opt(0x1010, "compute_pool_enabled_from_height", Ty::U64),
    opt(0x1011, "application_journal_enabled_from_height", Ty::U64),
    opt(0x1012, "beacon_enabled_from_height", Ty::U64),
    opt(
        0x1013,
        "messaging_sponsored_registration_enabled_from_height",
        Ty::U64,
    ),
    opt(0x1014, "nft_receipt_failure_enabled_from_height", Ty::U64),
    opt(0x1015, "docclass_stake_escrow_enabled_from_height", Ty::U64),
    opt(
        0x1016,
        "docclass_subject_index_split_enabled_from_height",
        Ty::U64,
    ),
    opt(
        0x1017,
        "docclass_revocation_standing_enabled_from_height",
        Ty::U64,
    ),
    opt(
        0x1018,
        "healthcare_authorization_enabled_from_height",
        Ty::U64,
    ),
    opt(0x1019, "legal_authorization_enabled_from_height", Ty::U64),
    opt(0x101a, "finance_authorization_enabled_from_height", Ty::U64),
    opt(
        0x101b,
        "employment_authorization_enabled_from_height",
        Ty::U64,
    ),
    opt(
        0x101c,
        "property_authorization_enabled_from_height",
        Ty::U64,
    ),
    opt(0x101d, "tax_authorization_enabled_from_height", Ty::U64),
    opt(
        0x101e,
        "subsystem_block_timestamp_enabled_from_height",
        Ty::U64,
    ),
    opt(0x101f, "subsystem_tx_index_enabled_from_height", Ty::U64),
    opt(
        0x1020,
        "subsystem_allocation_bound_enabled_from_height",
        Ty::U64,
    ),
    opt(
        0x1021,
        "subsystem_tx_write_set_bound_enabled_from_height",
        Ty::U64,
    ),
    opt(0x1022, "tax_proof_lifecycle_enabled_from_height", Ty::U64),
    opt(0x1023, "nft_token_authority_enabled_from_height", Ty::U64),
    opt(
        0x1024,
        "agreement_signature_integrity_enabled_from_height",
        Ty::U64,
    ),
    opt(
        0x1025,
        "healthcare_state_precondition_enabled_from_height",
        Ty::U64,
    ),
    opt(
        0x1026,
        "subsystem_proof_presence_enabled_from_height",
        Ty::U64,
    ),
    opt(
        0x1027,
        "nft_update_path_parity_enabled_from_height",
        Ty::U64,
    ),
    opt(
        0x1028,
        "subsystem_no_op_receipt_enabled_from_height",
        Ty::U64,
    ),
    opt(
        0x1029,
        "peer_protocol_declaration_required_from_height",
        Ty::U64,
    ),
    opt(
        0x102a,
        "docclass_issuer_authority_enabled_from_height",
        Ty::U64,
    ),
    opt(0x102b, "nft_charged_receipt_enabled_from_height", Ty::U64),
    opt(
        0x102c,
        "docclass_revocation_record_enabled_from_height",
        Ty::U64,
    ),
    opt(
        0x102d,
        "docclass_credential_schema_enabled_from_height",
        Ty::U64,
    ),
    opt(0x102e, "nft_index_symmetry_enabled_from_height", Ty::U64),
    opt(
        0x102f,
        "docclass_identity_binding_enabled_from_height",
        Ty::U64,
    ),
    opt(
        0x1030,
        "docclass_issuer_stake_requirement_enabled_from_height",
        Ty::U64,
    ),
    opt(
        0x1031,
        "nft_collection_id_nonce_enabled_from_height",
        Ty::U64,
    ),
    opt(
        0x1032,
        "subsystem_proof_unsupported_enabled_from_height",
        Ty::U64,
    ),
    opt(
        0x1033,
        "property_state_precondition_enabled_from_height",
        Ty::U64,
    ),
    opt(
        0x1034,
        "property_asset_relationship_enabled_from_height",
        Ty::U64,
    ),
    opt(
        0x1035,
        "agreement_party_authority_unsupported_enabled_from_height",
        Ty::U64,
    ),
    opt(
        0x1036,
        "healthcare_consent_subject_signature_enabled_from_height",
        Ty::U64,
    ),
    opt(
        0x1037,
        "subsystem_issuer_self_registration_unsupported_enabled_from_height",
        Ty::U64,
    ),
    opt(
        0x1038,
        "property_proof_submission_unsupported_enabled_from_height",
        Ty::U64,
    ),
    opt(
        0x1039,
        "nft_unpayable_royalty_refused_enabled_from_height",
        Ty::U64,
    ),
    opt(
        0x103a,
        "docclass_signature_unsupported_enabled_from_height",
        Ty::U64,
    ),
    opt(
        0x103b,
        "docclass_credential_validity_bound_enabled_from_height",
        Ty::U64,
    ),
    opt(
        0x103c,
        "docclass_unknown_attribute_refused_enabled_from_height",
        Ty::U64,
    ),
    opt(
        0x103d,
        "subsystem_ambiguous_policy_id_refused_enabled_from_height",
        Ty::U64,
    ),
    opt(
        0x103e,
        "nft_royalty_operation_unsupported_enabled_from_height",
        Ty::U64,
    ),
    // ── `consensus_limits()`, declared order ──
    req(0x2000, "MAX_SUBSYSTEM_PAYLOAD_BYTES", Ty::U128),
    req(0x2001, "MAX_ACCUMULATING_ROW_BYTES", Ty::U128),
    req(0x2002, "MAX_NFT_BATCH_MINT_REQUESTS", Ty::U128),
    req(0x2003, "MAX_INDEX_KEY_TEXT_BYTES", Ty::U128),
    req(0x2004, "MAX_BLOCK_WRITE_SET_BYTES", Ty::U128),
    req(0x2005, "MAX_TX_WRITE_SET_BYTES", Ty::U128),
    req(0x2006, "LEGACY_ROOT_COMPATIBILITY_HEIGHT", Ty::U128),
    req(0x2007, "NATIVE_PASS_THRESHOLD_BPS", Ty::U128),
    req(0x2008, "MIN_ARCHIVE_STAKE", Ty::U128),
    req(0x2009, "MAX_TITLE_LENGTH", Ty::U128),
    req(0x200a, "MAX_CREDENTIAL_TYPE_LENGTH", Ty::U128),
    req(0x200b, "MAX_PROGRAM_LENGTH", Ty::U128),
    req(0x200c, "MAX_DATE_LENGTH", Ty::U128),
    req(0x200d, "MAX_ATTRIBUTE_VALUE_LENGTH", Ty::U128),
    req(0x200e, "MAX_NAME_LENGTH", Ty::U128),
    req(0x200f, "MAX_HINT_LENGTH", Ty::U128),
    req(0x2010, "C1_SCHEMA_VERSION", Ty::U128),
    req(0x2011, "BEACON_RECORD_VERSION", Ty::U128),
    req(0x2012, "C1_DECODE_BYTE_LIMIT", Ty::U128),
    req(0x2013, "BEACON_DECODE_BYTE_LIMIT", Ty::U128),
    req(0x2014, "G1_LEN", Ty::U128),
    req(0x2015, "G2_LEN", Ty::U128),
    req(0x2016, "CT_LEN", Ty::U128),
    req(0x2017, "OUT_LEN", Ty::U128),
    req(0x2018, "ACCOUNT_STATE_DIGEST_DOMAIN", Ty::Bytes),
    req(0x2019, "C1_STATE_DIGEST_DOMAIN", Ty::Bytes),
    req(0x201a, "BEACON_STATE_DIGEST_DOMAIN", Ty::Bytes),
    req(0x201b, "DOCCLASS_STAKE_ESCROW_DOMAIN", Ty::Bytes),
    req(0x201c, "ASSIGN_SCORE_CONTEXT", Ty::Bytes),
    req(0x201d, "CONTRACT_STATE_DIFF_DOMAIN", Ty::Bytes),
    req(0x201e, "EQUITY_MERKLE_LEAF_DOMAIN", Ty::Bytes),
    req(0x201f, "EQUITY_MERKLE_NODE_DOMAIN", Ty::Bytes),
    req(0x2020, "EQUITY_MERKLE_EMPTY_DOMAIN", Ty::Bytes),
    req(0x2021, "ACCOUNT_KEY_PREFIX", Ty::Bytes),
    req(0x2022, "SUBJECT_IDENTITY_INDEX_TAG", Ty::U128),
    // ── further compiled consensus constants, by crate (see `extra_constants`) ──
    list(
        0x2100,
        "sumchain_crypto::messaging::LOW_ORDER_X25519_POINTS",
    ),
    req(0x2200, "sumchain_wire::address::Address::ZERO", Ty::Bytes),
    req(
        0x2201,
        "sumchain_wire::beacon_wire::W1B_BEACON_DKG_TXTYPE",
        Ty::U128,
    ),
    req(
        0x2202,
        "sumchain_wire::beacon_wire::W1B_BEACON_SIGN_TXTYPE",
        Ty::U128,
    ),
    list(0x2203, "sumchain_wire::beacon_wire::BeaconWireOp::ALL"),
    req(
        0x2204,
        "sumchain_wire::beacon_wire::RegisterBeaconKeyV1::MAGIC",
        Ty::Bytes,
    ),
    req(
        0x2205,
        "sumchain_wire::beacon_wire::RegisterBeaconKeyV1::SCHEMA_VERSION",
        Ty::U128,
    ),
    req(
        0x2206,
        "sumchain_wire::beacon_wire::DkgDealV1::MAGIC",
        Ty::Bytes,
    ),
    req(
        0x2207,
        "sumchain_wire::beacon_wire::DkgDealV1::SCHEMA_VERSION",
        Ty::U128,
    ),
    req(
        0x2208,
        "sumchain_wire::beacon_wire::DkgComplaintV1::MAGIC",
        Ty::Bytes,
    ),
    req(
        0x2209,
        "sumchain_wire::beacon_wire::DkgComplaintV1::SCHEMA_VERSION",
        Ty::U128,
    ),
    req(
        0x220a,
        "sumchain_wire::beacon_wire::BeaconPartialV1::MAGIC",
        Ty::Bytes,
    ),
    req(
        0x220b,
        "sumchain_wire::beacon_wire::BeaconPartialV1::SCHEMA_VERSION",
        Ty::U128,
    ),
    req(
        0x220c,
        "sumchain_wire::beacon_wire::BeaconFinalizeV1::MAGIC",
        Ty::Bytes,
    ),
    req(
        0x220d,
        "sumchain_wire::beacon_wire::BeaconFinalizeV1::SCHEMA_VERSION",
        Ty::U128,
    ),
    req(
        0x220e,
        "sumchain_wire::beacon_wire::BeaconFinalizeV1::WITNESS_ELEM_LEN",
        Ty::U128,
    ),
    req(
        0x220f,
        "sumchain_wire::education::MAX_EDU_OP_DATA_BYTES",
        Ty::U128,
    ),
    req(
        0x2210,
        "sumchain_wire::education::catalog_op::CREATE_CATALOG_ENTRY",
        Ty::U128,
    ),
    req(
        0x2211,
        "sumchain_wire::education::catalog_op::UPDATE_CATALOG_ENTRY",
        Ty::U128,
    ),
    req(
        0x2212,
        "sumchain_wire::education::catalog_op::PUBLISH_CATALOG_CONTENT",
        Ty::U128,
    ),
    req(
        0x2213,
        "sumchain_wire::education::catalog_op::DEPRECATE_CATALOG_ENTRY",
        Ty::U128,
    ),
    req(
        0x2214,
        "sumchain_wire::education::catalog_op::SUPERSEDE_CATALOG_ENTRY",
        Ty::U128,
    ),
    req(
        0x2215,
        "sumchain_wire::education::catalog_op::ARCHIVE_CATALOG_ENTRY",
        Ty::U128,
    ),
    req(
        0x2216,
        "sumchain_wire::education::offering_op::CREATE_OFFERING",
        Ty::U128,
    ),
    req(
        0x2217,
        "sumchain_wire::education::offering_op::UPDATE_OFFERING",
        Ty::U128,
    ),
    req(
        0x2218,
        "sumchain_wire::education::offering_op::PUBLISH_CONTENT",
        Ty::U128,
    ),
    req(
        0x2219,
        "sumchain_wire::education::offering_op::ADD_ASSESSMENT",
        Ty::U128,
    ),
    req(
        0x221a,
        "sumchain_wire::education::offering_op::UPDATE_ASSESSMENT",
        Ty::U128,
    ),
    req(
        0x221b,
        "sumchain_wire::education::offering_op::OPEN_ENROLLMENT",
        Ty::U128,
    ),
    req(
        0x221c,
        "sumchain_wire::education::offering_op::CLOSE_ENROLLMENT",
        Ty::U128,
    ),
    req(
        0x221d,
        "sumchain_wire::education::offering_op::LINK_ENROLLMENT",
        Ty::U128,
    ),
    req(
        0x221e,
        "sumchain_wire::education::offering_op::SUBMIT_ASSIGNMENT",
        Ty::U128,
    ),
    req(
        0x221f,
        "sumchain_wire::education::offering_op::SUBMIT_EXAM",
        Ty::U128,
    ),
    req(
        0x2220,
        "sumchain_wire::education::offering_op::GRADE_SUBMISSION",
        Ty::U128,
    ),
    req(
        0x2221,
        "sumchain_wire::education::offering_op::FINALIZE_GRADE",
        Ty::U128,
    ),
    req(
        0x2222,
        "sumchain_wire::education::offering_op::FINALIZE_COURSE",
        Ty::U128,
    ),
    req(
        0x2223,
        "sumchain_wire::education::offering_op::ARCHIVE_OFFERING",
        Ty::U128,
    ),
    req(
        0x2224,
        "sumchain_wire::education::offering_op::SUSPEND_OR_CANCEL_OFFERING",
        Ty::U128,
    ),
    req(
        0x2225,
        "sumchain_wire::governance::GOV_ESCROW_DOMAIN",
        Ty::Bytes,
    ),
    req(
        0x2226,
        "sumchain_wire::governance::GOV_EQUITY_VOTE_DOMAIN",
        Ty::Bytes,
    ),
    req(
        0x2227,
        "sumchain_wire::governance::GOV_PROPOSAL_DOMAIN",
        Ty::Bytes,
    ),
    req(
        0x2228,
        "sumchain_wire::governance::GOV_ASSET_EQUITY_CLASS_PREFIX",
        Ty::Bytes,
    ),
    req(
        0x2229,
        "sumchain_wire::governance::GOV_ASSET_NATIVE_ELIGIBILITY_PREFIX",
        Ty::Bytes,
    ),
    req(
        0x222a,
        "sumchain_wire::governance::GOV_ASSET_SRC20_PREFIX",
        Ty::Bytes,
    ),
    req(0x222b, "sumchain_wire::hash::Hash::ZERO", Ty::Bytes),
    req(
        0x222c,
        "sumchain_wire::healthcare::CONSENT_GRANT_SIGNING_SEP",
        Ty::Bytes,
    ),
    req(
        0x222d,
        "sumchain_wire::inference_attestation::DOMAIN_TAG",
        Ty::Bytes,
    ),
    req(
        0x222e,
        "sumchain_wire::inference_attestation::MAX_SESSION_ID_BYTES",
        Ty::U128,
    ),
    req(
        0x222f,
        "sumchain_wire::inference_attestation::INFERENCE_ATTESTATION_KEY_DOMAIN",
        Ty::Bytes,
    ),
    req(
        0x2230,
        "sumchain_wire::inference_attestation::INFERENCE_ATTESTATION_SESSION_INDEX_DOMAIN",
        Ty::Bytes,
    ),
    req(
        0x2231,
        "sumchain_wire::inference_attestation::SESSION_ID_HASH_BYTES",
        Ty::U128,
    ),
    req(
        0x2232,
        "sumchain_wire::inference_settlement::SESSION_KEY_DOMAIN",
        Ty::Bytes,
    ),
    req(
        0x2233,
        "sumchain_wire::inference_settlement::SESSION_INDEX_DOMAIN",
        Ty::Bytes,
    ),
    req(
        0x2234,
        "sumchain_wire::inference_settlement::SESSION_PREFIX_BYTES",
        Ty::U128,
    ),
    req(
        0x2235,
        "sumchain_wire::inference_settlement::VERIFIER_KEY_DOMAIN",
        Ty::Bytes,
    ),
    req(0x2236, "sumchain_wire::messaging::SRC201_MAGIC", Ty::Bytes),
    req(0x2237, "sumchain_wire::messaging::SRC201_VERSION", Ty::U128),
    req(
        0x2238,
        "sumchain_wire::messaging::SRC201_HEADER_SIZE",
        Ty::U128,
    ),
    req(
        0x2239,
        "sumchain_wire::messaging::SRC201_NONCE_SIZE",
        Ty::U128,
    ),
    req(
        0x223a,
        "sumchain_wire::messaging::SRC201_TAG_SIZE",
        Ty::U128,
    ),
    req(
        0x223b,
        "sumchain_wire::messaging::DEFAULT_DAILY_QUOTA",
        Ty::U128,
    ),
    req(
        0x223c,
        "sumchain_wire::messaging::DEFAULT_MAX_MESSAGE_SIZE",
        Ty::U128,
    ),
    req(
        0x223d,
        "sumchain_wire::messaging::DEFAULT_MIN_TRUST_STAKE",
        Ty::U128,
    ),
    req(
        0x223e,
        "sumchain_wire::messaging::SPONSORED_REGISTER_V1_TAG",
        Ty::Bytes,
    ),
    req(
        0x223f,
        "sumchain_wire::policy_account::POLICY_ACCOUNT_DOMAIN_SEP",
        Ty::Bytes,
    ),
    req(
        0x2240,
        "sumchain_wire::policy_account::PROPOSAL_DOMAIN_SEP",
        Ty::Bytes,
    ),
    req(
        0x2241,
        "sumchain_wire::policy_account::APPROVAL_SIGNING_DOMAIN_V1",
        Ty::Bytes,
    ),
    req(
        0x2242,
        "sumchain_wire::policy_account::MAX_MEMBERS",
        Ty::U128,
    ),
    req(
        0x2243,
        "sumchain_wire::policy_account::MAX_CUSTOM_RULES",
        Ty::U128,
    ),
    req(
        0x2244,
        "sumchain_wire::policy_account::MAX_APPROVALS",
        Ty::U128,
    ),
    req(
        0x2245,
        "sumchain_wire::policy_account::MAX_PROPOSAL_PAYLOAD_SIZE",
        Ty::U128,
    ),
    req(
        0x2246,
        "sumchain_wire::storage_metadata::CHUNK_SIZE",
        Ty::U128,
    ),
    req(
        0x2247,
        "sumchain_wire::storage_metadata::CHALLENGE_TTL_BLOCKS",
        Ty::U128,
    ),
    req(
        0x2248,
        "sumchain_wire::storage_metadata::CHALLENGE_INTERVAL_BLOCKS",
        Ty::U128,
    ),
    req(
        0x2249,
        "sumchain_wire::storage_metadata::CHALLENGE_REWARD",
        Ty::U128,
    ),
    req(
        0x224a,
        "sumchain_wire::storage_metadata::SLASH_PERCENTAGE",
        Ty::U128,
    ),
    req(
        0x224b,
        "sumchain_wire::storage_metadata::SNIP_V2_ASSIGNMENT_CONTEXT",
        Ty::Bytes,
    ),
    req(0x224c, "sumchain_wire::supply::KOPPA", Ty::U128),
    req(
        0x224d,
        "sumchain_wire::supply::TARGET_CANONICAL_SUPPLY",
        Ty::U128,
    ),
    req(
        0x224e,
        "sumchain_wire::supply::GENESIS_ACCOUNTED_SUPPLY",
        Ty::U128,
    ),
    req(0x224f, "sumchain_wire::supply::MAINNET_CHAIN_ID", Ty::U128),
    req(
        0x2250,
        "sumchain_wire::supply::SUPPLY_CORRECTION_DOMAIN",
        Ty::Bytes,
    ),
    req(0x2251, "sumchain_wire::supply::POOL_VALIDATOR", Ty::U128),
    req(0x2252, "sumchain_wire::supply::POOL_ARCHIVE", Ty::U128),
    req(0x2253, "sumchain_wire::supply::POOL_COMPUTE", Ty::U128),
    req(0x2254, "sumchain_wire::supply::POOL_ECOSYSTEM", Ty::U128),
    req(
        0x2255,
        "sumchain_wire::supply::POOL_GOVERNANCE_RESERVE",
        Ty::U128,
    ),
    req(
        0x2256,
        "sumchain_wire::supply::FIXED_SERVICE_POOLS",
        Ty::U128,
    ),
    list(0x2257, "sumchain_wire::supply::GENESIS_VALIDATOR_ACCOUNTS"),
    list(0x2258, "sumchain_wire::supply::GENESIS_VALIDATOR_PUBKEYS"),
    req(0x2259, "sumchain_wire::supply::GRANT_LIQUID_BPS", Ty::U128),
    req(
        0x225a,
        "sumchain_wire::supply::ARCHIVE_ACTIVE_BLOCKS_MILESTONE",
        Ty::U128,
    ),
    req(
        0x225b,
        "sumchain_wire::supply::ARCHIVE_ACTIVE_GRANT",
        Ty::U128,
    ),
    req(
        0x225c,
        "sumchain_wire::supply::ARCHIVE_PROOFS_MILESTONE_1",
        Ty::U128,
    ),
    req(
        0x225d,
        "sumchain_wire::supply::ARCHIVE_PROOFS_GRANT_1",
        Ty::U128,
    ),
    req(
        0x225e,
        "sumchain_wire::supply::ARCHIVE_PROOFS_MILESTONE_2",
        Ty::U128,
    ),
    req(
        0x225f,
        "sumchain_wire::supply::ARCHIVE_PROOFS_GRANT_2",
        Ty::U128,
    ),
    req(
        0x2260,
        "sumchain_wire::supply::COMPUTE_CLAIMS_MILESTONE_1",
        Ty::U128,
    ),
    req(
        0x2261,
        "sumchain_wire::supply::COMPUTE_CLAIMS_GRANT_1",
        Ty::U128,
    ),
    req(
        0x2262,
        "sumchain_wire::supply::COMPUTE_CLAIMS_MILESTONE_2",
        Ty::U128,
    ),
    req(
        0x2263,
        "sumchain_wire::supply::COMPUTE_CLAIMS_GRANT_2",
        Ty::U128,
    ),
    req(
        0x2264,
        "sumchain_wire::supply::GRANTS_AGGREGATE_DIGEST_DOMAIN",
        Ty::Bytes,
    ),
    req(
        0x2265,
        "sumchain_wire::supply::PROTOCOL_RESERVE_DIGEST_DOMAIN",
        Ty::Bytes,
    ),
    req(
        0x2266,
        "sumchain_wire::supply::SUPPLY_LEDGER_DIGEST_DOMAIN",
        Ty::Bytes,
    ),
    req(
        0x2267,
        "sumchain_wire::supply::VALIDATOR_COHORT_1_GRANT",
        Ty::U128,
    ),
    req(
        0x2268,
        "sumchain_wire::supply::VALIDATOR_COHORT_1_LAST_INDEX",
        Ty::U128,
    ),
    req(
        0x2269,
        "sumchain_wire::supply::VALIDATOR_COHORT_2_GRANT",
        Ty::U128,
    ),
    req(
        0x226a,
        "sumchain_wire::supply::VALIDATOR_COHORT_2_LAST_INDEX",
        Ty::U128,
    ),
    req(
        0x226b,
        "sumchain_wire::supply::VALIDATOR_COHORT_3_GRANT",
        Ty::U128,
    ),
    req(
        0x226c,
        "sumchain_wire::supply::VALIDATOR_COHORT_3_LAST_INDEX",
        Ty::U128,
    ),
    req(
        0x226d,
        "sumchain_wire::supply::VALIDATOR_COHORT_4_GRANT",
        Ty::U128,
    ),
    req(
        0x226e,
        "sumchain_wire::supply::VALIDATOR_COHORT_4_LAST_INDEX",
        Ty::U128,
    ),
    req(
        0x226f,
        "sumchain_wire::validator_authority::GOV_REGISTER_ASSET_DOMAIN",
        Ty::Bytes,
    ),
    req(
        0x2270,
        "sumchain_wire::validator_authority::GOV_CANCEL_PROPOSAL_DOMAIN",
        Ty::Bytes,
    ),
    req(
        0x2271,
        "sumchain_wire::validator_authority::GOV_REGISTER_EQUITY_CLASS_DOMAIN",
        Ty::Bytes,
    ),
    req(
        0x2272,
        "sumchain_wire::validator_authority::INFERENCE_RESOLVE_DISPUTE_DOMAIN",
        Ty::Bytes,
    ),
    req(
        0x2400,
        "sumchain_storage::schema::contract_cf_kind::STORAGE",
        Ty::U128,
    ),
    req(
        0x2401,
        "sumchain_storage::schema::contract_cf_kind::CODE",
        Ty::U128,
    ),
    req(
        0x2402,
        "sumchain_storage::schema::contract_cf_kind::METADATA",
        Ty::U128,
    ),
    req(
        0x2500,
        "sumchain_state::schema_validator::SchemaValidatorConfig::default().activation_height",
        Ty::U128,
    ),
    req(
        0x2501,
        "sumchain_state::schema_validator::SchemaValidatorConfig::default().enabled",
        Ty::Bool,
    ),
    req(
        0x2502,
        "sumchain_state::beacon_store::domain::KEY",
        Ty::U128,
    ),
    req(
        0x2503,
        "sumchain_state::beacon_store::domain::DEAL",
        Ty::U128,
    ),
    req(
        0x2504,
        "sumchain_state::beacon_store::domain::VERDICT",
        Ty::U128,
    ),
    req(
        0x2505,
        "sumchain_state::beacon_store::domain::ROUND",
        Ty::U128,
    ),
    req(
        0x2506,
        "sumchain_state::beacon_store::domain::OUTPUT",
        Ty::U128,
    ),
    req(
        0x2507,
        "sumchain_state::beacon_store::domain::MEMBERSHIP",
        Ty::U128,
    ),
    req(
        0x2508,
        "sumchain_state::beacon_store::domain::FALSE_ACCUSER",
        Ty::U128,
    ),
    req(
        0x2509,
        "sumchain_state::beacon_store::domain::ADJUDICATED",
        Ty::U128,
    ),
    req(
        0x250a,
        "sumchain_state::beacon_store::domain::KEY_EQUIV",
        Ty::U128,
    ),
    req(
        0x250b,
        "sumchain_state::beacon_store::domain::DEAL_EQUIV",
        Ty::U128,
    ),
    req(
        0x250c,
        "sumchain_state::compute_pool_store::domain::JOB",
        Ty::U128,
    ),
    req(
        0x250d,
        "sumchain_state::compute_pool_store::domain::UNIT",
        Ty::U128,
    ),
    req(
        0x250e,
        "sumchain_state::compute_pool_store::domain::OFFER",
        Ty::U128,
    ),
    req(
        0x250f,
        "sumchain_state::compute_pool_store::domain::ACTIVE_OFFER_INDEX",
        Ty::U128,
    ),
    req(
        0x2510,
        "sumchain_state::compute_pool_store::domain::RESERVATION",
        Ty::U128,
    ),
    req(
        0x2511,
        "sumchain_state::compute_pool_store::domain::ACCEPTED_LEAF",
        Ty::U128,
    ),
    req(
        0x2512,
        "sumchain_state::compute_pool_store::domain::ASSIGNMENT",
        Ty::U128,
    ),
    req(
        0x2513,
        "sumchain_state::compute_pool_store::domain::ENTITLEMENT",
        Ty::U128,
    ),
    req(
        0x2514,
        "sumchain_state::education_executor::EDU_ASSESSMENT_ROOT_DOMAIN",
        Ty::Bytes,
    ),
    req(
        0x2515,
        "sumchain_state::education_executor::EDU_CATALOG_BY_CODE_DOMAIN",
        Ty::Bytes,
    ),
    req(
        0x2516,
        "sumchain_state::education_executor::EDU_CONTENT_ROOT_DOMAIN",
        Ty::Bytes,
    ),
    req(
        0x2517,
        "sumchain_state::education_executor::EDU_ENROLLMENT_ROOT_DOMAIN",
        Ty::Bytes,
    ),
    req(0x2518, "sumchain_state::UNNAMED_POLICY_ID", Ty::Bytes),
    req(
        0x2519,
        "sumchain_state::messaging_executor::MESSAGING_DAY_SECONDS",
        Ty::U128,
    ),
    req(
        0x251a,
        "sumchain_state::messaging_executor::PENDING_PAYMENT_EXPIRY",
        Ty::U128,
    ),
    req(
        0x251b,
        "sumchain_state::messaging_executor::SPAM_REPORT_SCORE_INCREMENT",
        Ty::U128,
    ),
    req(
        0x251c,
        "sumchain_state::messaging_executor::STAKED_SENDER_QUOTA_MULTIPLIER",
        Ty::U128,
    ),
    req(
        0x251d,
        "sumchain_state::messaging_view::DEFAULT_SPONSORSHIP_ENABLED",
        Ty::Bool,
    ),
    req(
        0x251e,
        "sumchain_state::schema_validator::PHONE_LIKE_DIGIT_COUNT",
        Ty::U128,
    ),
    list(
        0x251f,
        "sumchain_state::schema_validator::STORAGE_HINT_PII_PATTERNS",
    ),
    req(
        0x2520,
        "sumchain_state::staking_executor::MAX_VALIDATOR_METADATA_BYTES",
        Ty::U128,
    ),
    req(
        0x2521,
        "sumchain_state::storage_metadata::POR_SCHEDULE_CHUNK_TAG",
        Ty::Bytes,
    ),
    req(
        0x2522,
        "sumchain_state::storage_metadata::POR_SCHEDULE_FILE_TAG",
        Ty::Bytes,
    ),
    req(
        0x2523,
        "sumchain_state::storage_metadata::POR_SCHEDULE_PICK_TAG",
        Ty::Bytes,
    ),
    req(
        0x2524,
        "sumchain_state::storage_metadata::POR_SCHEDULE_SEED_DOMAIN",
        Ty::Bytes,
    ),
    req(
        0x2525,
        "sumchain_state::storage_metadata::STORAGE_CHALLENGE_SEED_DOMAIN",
        Ty::Bytes,
    ),
    req(
        0x2526,
        "sumchain_state::supply::SUPPLY_STATE_DIGEST_DOMAIN",
        Ty::Bytes,
    ),
    req(
        0x2527,
        "sumchain_state::token_executor::MAX_TOKEN_DECIMALS",
        Ty::U128,
    ),
    req(
        0x2528,
        "sumchain_state::token_executor::MAX_TOKEN_NAME_BYTES",
        Ty::U128,
    ),
    req(
        0x2529,
        "sumchain_state::token_executor::MAX_TOKEN_SYMBOL_BYTES",
        Ty::U128,
    ),
    req(
        0x2600,
        "sumchain_nft::collection::MAX_ROYALTY_BPS",
        Ty::U128,
    ),
    req(
        0x2700,
        "sumc_runtime::gas::GasCosts::default().call_base",
        Ty::U128,
    ),
    req(
        0x2701,
        "sumc_runtime::gas::GasCosts::default().deploy_base",
        Ty::U128,
    ),
    req(
        0x2702,
        "sumc_runtime::gas::GasCosts::default().wasm_instruction",
        Ty::U128,
    ),
    req(
        0x2703,
        "sumc_runtime::gas::GasCosts::default().memory_page",
        Ty::U128,
    ),
    req(
        0x2704,
        "sumc_runtime::gas::GasCosts::default().storage_read_base",
        Ty::U128,
    ),
    req(
        0x2705,
        "sumc_runtime::gas::GasCosts::default().storage_read_per_byte",
        Ty::U128,
    ),
    req(
        0x2706,
        "sumc_runtime::gas::GasCosts::default().storage_write_base",
        Ty::U128,
    ),
    req(
        0x2707,
        "sumc_runtime::gas::GasCosts::default().storage_write_per_byte",
        Ty::U128,
    ),
    req(
        0x2708,
        "sumc_runtime::gas::GasCosts::default().storage_delete",
        Ty::U128,
    ),
    req(
        0x2709,
        "sumc_runtime::gas::GasCosts::default().blake3_base",
        Ty::U128,
    ),
    req(
        0x270a,
        "sumc_runtime::gas::GasCosts::default().blake3_per_byte",
        Ty::U128,
    ),
    req(
        0x270b,
        "sumc_runtime::gas::GasCosts::default().ed25519_verify",
        Ty::U128,
    ),
    req(
        0x270c,
        "sumc_runtime::gas::GasCosts::default().secp256k1_verify",
        Ty::U128,
    ),
    req(
        0x270d,
        "sumc_runtime::gas::GasCosts::default().cross_call_base",
        Ty::U128,
    ),
    req(
        0x270e,
        "sumc_runtime::gas::GasCosts::default().event_base",
        Ty::U128,
    ),
    req(
        0x270f,
        "sumc_runtime::gas::GasCosts::default().event_per_byte",
        Ty::U128,
    ),
    req(
        0x2710,
        "sumc_runtime::gas::GasCosts::default().log_base",
        Ty::U128,
    ),
    req(
        0x2711,
        "sumc_runtime::gas::GasCosts::default().log_per_byte",
        Ty::U128,
    ),
    req(
        0x2712,
        "sumc_runtime::gas::GasCosts::default().transfer",
        Ty::U128,
    ),
    req(0x2713, "sumc_runtime::ENGINE_IDENTITY", Ty::Bytes),
    req(0x2714, "sumc_runtime::types::MAX_CODE_SIZE", Ty::U128),
    req(0x2715, "sumc_runtime::types::MAX_CALL_DEPTH", Ty::U128),
    req(0x2800, "sumchain_beacon_crypto::bls::THRESHOLD_T", Ty::U128),
    req(0x2801, "sumchain_beacon_crypto::bls::DST_SIG", Ty::Bytes),
    req(0x2802, "sumchain_beacon_crypto::bls::DST_POP", Ty::Bytes),
    req(0x2803, "sumchain_beacon_crypto::bls::DST_DLEQ", Ty::Bytes),
    req(
        0x2804,
        "sumchain_beacon_crypto::ecies::ECIES_CTX_DST",
        Ty::Bytes,
    ),
    req(
        0x2805,
        "sumchain_beacon_crypto::ecies::ECIES_HKDF_SALT",
        Ty::Bytes,
    ),
    req(
        0x2806,
        "sumchain_beacon_crypto::ecies::ECIES_AEAD_KEY_LABEL",
        Ty::Bytes,
    ),
    req(
        0x2807,
        "sumchain_beacon_crypto::ecies::ECIES_AEAD_NONCE_LABEL",
        Ty::Bytes,
    ),
    req(
        0x2880,
        "sumchain_beacon_runtime::wire::BEACON_GENESIS_DST",
        Ty::Bytes,
    ),
    req(
        0x2881,
        "sumchain_beacon_runtime::wire::BEACON_ROUND_DST",
        Ty::Bytes,
    ),
    req(
        0x2882,
        "sumchain_beacon_runtime::wire::BEACON_OUT_DST",
        Ty::Bytes,
    ),
];

/// First and last id of the activation-height range.
const GATE_RANGE: std::ops::RangeInclusive<u16> = 0x1000..=0x1fff;

/// The registry entry for `id` in the newest schema this binary knows
/// ([`PRODUCTION`]`.knows`). A schema-1 id resolves to its schema-1 entry.
pub fn spec_for(id: u16) -> Option<&'static FieldSpec> {
    PRODUCTION.knows.spec(id)
}

/// Whether `id` is an activation height.
pub fn is_gate(id: u16) -> bool {
    GATE_RANGE.contains(&id)
}

/// Whether `id` is chain identity or a rule code: values a local
/// acknowledgement may never move.
pub fn is_identity_or_rule(id: u16) -> bool {
    id < 0x0100
}

/// The activation heights a configuration holds, in the shape the existing
/// gate rule (`ChainParams::activation_changes`) compares against.
pub fn recorded_gates(config: &ConsensusConfig) -> Vec<(String, Option<u64>)> {
    config
        .fields()
        .iter()
        .filter(|f| is_gate(f.id))
        .map(|f| {
            let name = config
                .spec(f.id)
                .map(|s| s.name)
                .unwrap_or_default()
                .to_string();
            let height = match f.value {
                Value::U64(h) => Some(h),
                _ => None,
            };
            (name, height)
        })
        .collect()
}

/// The rule codes of a configuration, by name, for logs and the RPC.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleNames {
    pub engine: String,
    pub finality: String,
    pub finality_depth: Option<u64>,
    pub quorum: String,
    pub fork_choice: String,
    pub proposer: String,
    pub membership: String,
    pub unfinalized_production: String,
    pub block_timestamp: String,
    pub protocol_version: Option<u16>,
}

impl RuleNames {
    /// Name the rule codes `config` holds. A code this binary does not define
    /// is reported as `unknown(<n>)`, never guessed.
    pub fn of(config: Option<&ConsensusConfig>) -> Self {
        let code = |id: u16| match config.and_then(|c| c.get(id)) {
            Some(Value::U8(v)) => Some(*v),
            _ => None,
        };
        let name = |id: u16, table: &[(u8, &str)]| -> String {
            match code(id) {
                None => "unavailable".to_string(),
                Some(v) => table
                    .iter()
                    .find(|(c, _)| *c == v)
                    .map(|(_, n)| n.to_string())
                    .unwrap_or_else(|| format!("unknown({v})")),
            }
        };
        RuleNames {
            engine: name(0x0010, &[(ENGINE_POA, "proof-of-authority")]),
            finality: name(0x0011, &[(FINALITY_LOCAL_DEPTH, "local-depth")]),
            finality_depth: match config.and_then(|c| c.get(0x0103)) {
                Some(Value::U64(d)) => Some(*d),
                _ => None,
            },
            quorum: name(0x0012, &[(QUORUM_NONE, "none")]),
            fork_choice: name(
                0x0013,
                &[(
                    FORK_CHOICE_LONGEST_LOCAL_FINALITY,
                    "longest-chain/lower-hash-tiebreak/no-unwind-below-local-finality",
                )],
            ),
            proposer: name(0x0014, &[(PROPOSER_ROUND_ROBIN, "round-robin")]),
            membership: name(0x0015, &[(MEMBERSHIP_STATIC_GENESIS, "static-genesis")]),
            unfinalized_production: name(0x0016, &[(UNFINALIZED_UNBOUNDED, "unbounded")]),
            block_timestamp: name(
                0x0017,
                &[(TIMESTAMP_AFTER_PARENT, "after-parent/no-wall-clock-bound")],
            ),
            protocol_version: match config.and_then(|c| c.get(0x0018)) {
                Some(Value::U16(v)) => Some(*v),
                _ => None,
            },
        }
    }
}

/// Genesis parameters deliberately NOT committed, each with the reason. The
/// census test fails if any of these gains a reader in consensus code.
pub const EXCLUDED_PARAMETERS: &[(&str, &str)] = &[
    (
        "block_time_ms",
        "producer pacing only (`PoAEngine` block-producer timer); no validity, \
         execution or fork-choice rule reads it",
    ),
    (
        "storage_fee_per_byte",
        "no reader outside genesis and RPC display",
    ),
    (
        "validator_inactivity_window_blocks",
        "dormant design parameter; no reader outside genesis",
    ),
    (
        "validator_inactivity_warn_bps",
        "dormant design parameter; no reader outside genesis",
    ),
    (
        "validator_inactivity_inactive_bps",
        "dormant design parameter; no reader outside genesis",
    ),
    (
        "validator_inactivity_removal_bps",
        "dormant design parameter; no reader outside genesis",
    ),
    (
        "validator_reclaim_delay_blocks",
        "dormant design parameter; no reader outside genesis",
    ),
    (
        "messaging.daily_quota",
        "execution reads the quota from state, falling back to DEFAULT_DAILY_QUOTA \
         (committed), never from genesis",
    ),
    (
        "messaging.max_message_size",
        "execution reads it from state, falling back to DEFAULT_MAX_MESSAGE_SIZE \
         (committed), never from genesis",
    ),
    (
        "messaging.min_trust_stake",
        "execution reads it from state, falling back to DEFAULT_MIN_TRUST_STAKE \
         (committed), never from genesis",
    ),
    (
        "messaging.sponsorship_enabled",
        "execution reads it from state, falling back to DEFAULT_SPONSORSHIP_ENABLED \
         (committed), never from genesis",
    ),
    (
        "messaging.initial_sponsorship_fund",
        "no reader outside genesis",
    ),
    (
        "messaging.stake_cooldown_blocks",
        "no reader outside genesis",
    ),
    (
        "docclass.initial_issuers",
        "no reader outside genesis and RPC display; a listed address is not an issuer",
    ),
];

/// Build the configuration this binary enforces for `genesis`, in the schema
/// it records ([`PRODUCTION`]`.writes`).
///
/// Fails if the genesis itself cannot be interpreted (an unparseable
/// validator key or allocation address) — the same inputs on which node start
/// already fails — or if it sets a field of a draft schema, which this binary
/// can register but never activate.
pub fn build(genesis: &Genesis) -> Result<ConsensusConfig, ConfigError> {
    build_with(genesis, &PRODUCTION)
}

/// [`build`] under `policy`: values computed over `policy.knows`, the
/// configuration in `policy.writes`.
pub fn build_with(
    genesis: &Genesis,
    policy: &SchemaPolicy,
) -> Result<ConsensusConfig, ConfigError> {
    let values = compute(genesis, policy)?;
    ConsensusConfig::project(values, policy.knows, policy.writes).map_err(|e| match e {
        ConfigError::BeyondSchema { schema, fields } => ConfigError::Refused(format!(
            "the genesis sets {fields}: field(s) this binary registers but does not record \
             (it records schema {schema}). They must stay absent until a binary that \
             records their schema runs"
        )),
        other => other,
    })
}

/// Every field value of `policy.knows`, in ascending id order: the schema-1
/// values below plus every field a later known schema adds.
pub(crate) fn compute(genesis: &Genesis, policy: &SchemaPolicy) -> Result<Vec<Field>, ConfigError> {
    policy
        .check()
        .map_err(|e| ConfigError::Build(format!("consensus configuration registry: {e}")))?;
    let knows = policy.knows;
    let build_err =
        |what: &str, e: &dyn std::fmt::Display| ConfigError::Build(format!("{what}: {e}"));

    let Genesis {
        chain_id,
        genesis_time,
        validators: _, // via `validator_pubkeys`, which parses and keeps order
        alloc: _,      // via `parsed_alloc`
        params,
    } = genesis;

    let mut f: Vec<Field> = Vec::with_capacity(SCHEMA_V1_FIELDS.len() + 16);
    let mut put = |id: u16, value: Value| f.push(Field { id, value });

    // ── identity ──
    put(0x0001, Value::U64(*chain_id));
    put(0x0002, Value::U64(*genesis_time));
    let validators = genesis
        .validator_pubkeys()
        .map_err(|e| build_err("parsing the validator set", &e))?;
    put(
        0x0003,
        Value::List(validators.iter().map(|k| k.to_vec()).collect()),
    );
    put(
        0x0004,
        Value::Digest(alloc_digest(genesis).map_err(|e| build_err("parsing the allocations", &e))?),
    );
    let genesis_block = genesis
        .create_genesis_block()
        .map_err(|e| build_err("building the genesis block", &e))?;
    put(0x0005, Value::Digest(*genesis_block.hash().as_bytes()));

    // ── rule codes ──
    put(0x0010, Value::U8(ENGINE_POA));
    put(0x0011, Value::U8(FINALITY_LOCAL_DEPTH));
    put(0x0012, Value::U8(QUORUM_NONE));
    put(0x0013, Value::U8(FORK_CHOICE_LONGEST_LOCAL_FINALITY));
    put(0x0014, Value::U8(PROPOSER_ROUND_ROBIN));
    put(0x0015, Value::U8(MEMBERSHIP_STATIC_GENESIS));
    put(0x0016, Value::U8(UNFINALIZED_UNBOUNDED));
    put(0x0017, Value::U8(TIMESTAMP_AFTER_PARENT));
    put(0x0018, Value::U16(PROTOCOL_VERSION));

    // ── chain parameters ──
    //
    // Destructured without `..`: a field added to `ChainParams` does not compile
    // here until it is committed or excluded.
    let ChainParams {
        block_time_ms: _, // excluded: EXCLUDED_PARAMETERS
        max_block_bytes,
        max_txs_per_block,
        min_fee,
        finality_depth,
        storage_fee_per_byte: _, // excluded
        max_metadata_bytes,
        min_contract_gas,
        max_contract_gas,
        staking,
        messaging,
        docclass,
        max_access_list_bytes,
        activation_grace_blocks,
        abandonment_fee_percent,
        max_chunk_count_per_file,
        max_chunk_indices_per_tx,
        assignment_replication_factor,
        governance,
        archive_unbonding_period_blocks,
        validator_inactivity_window_blocks: _, // excluded
        validator_inactivity_warn_bps: _,      // excluded
        validator_inactivity_inactive_bps: _,  // excluded
        validator_inactivity_removal_bps: _,   // excluded
        validator_reclaim_delay_blocks: _,     // excluded
        max_assignment_aware_challenges_per_block,
        max_files_sampled_per_interval,
        max_chunks_sampled_per_file,
        inference_settlement_max_dispute_window_blocks,
        inference_settlement_max_session_duration_blocks,
        inference_settlement_dispute_threshold_bps,
        inference_verifier_unbonding_period_blocks,
        beacon_params,
        beacon_schedule,
        // Activation heights: committed below through `activation_heights()`,
        // whose completeness the genesis crate's own tests enforce. A gate
        // added after schema 1 is registered in `schema::SCHEMA_2_ADDED`.
        v2_enabled_from_height: _,
        omninode_enabled_from_height: _,
        omninode_sponsored_attestation_enabled_from_height: _,
        education_enabled_from_height: _,
        contracts_enabled_from_height: _,
        account_root_enabled_from_height: _,
        governance_enabled_from_height: _,
        archive_unbonding_enabled_from_height: _,
        archive_reassignment_enabled_from_height: _,
        por_assignment_targeting_enabled_from_height: _,
        service_grants_enabled_from_height: _,
        monetary_policy_enabled_from_height: _,
        assignment_aware_por_scheduler_enabled_from_height: _,
        inference_settlement_enabled_from_height: _,
        inference_settlement_consistency_enabled_from_height: _,
        inference_verifier_bonding_enabled_from_height: _,
        compute_pool_enabled_from_height: _,
        application_journal_enabled_from_height: _,
        beacon_enabled_from_height: _,
        messaging_sponsored_registration_enabled_from_height: _,
        nft_receipt_failure_enabled_from_height: _,
        docclass_stake_escrow_enabled_from_height: _,
        docclass_subject_index_split_enabled_from_height: _,
        docclass_revocation_standing_enabled_from_height: _,
        healthcare_authorization_enabled_from_height: _,
        legal_authorization_enabled_from_height: _,
        finance_authorization_enabled_from_height: _,
        employment_authorization_enabled_from_height: _,
        property_authorization_enabled_from_height: _,
        tax_authorization_enabled_from_height: _,
        subsystem_block_timestamp_enabled_from_height: _,
        subsystem_tx_index_enabled_from_height: _,
        subsystem_allocation_bound_enabled_from_height: _,
        subsystem_tx_write_set_bound_enabled_from_height: _,
        tax_proof_lifecycle_enabled_from_height: _,
        nft_token_authority_enabled_from_height: _,
        agreement_signature_integrity_enabled_from_height: _,
        healthcare_state_precondition_enabled_from_height: _,
        subsystem_proof_presence_enabled_from_height: _,
        nft_update_path_parity_enabled_from_height: _,
        subsystem_no_op_receipt_enabled_from_height: _,
        peer_protocol_declaration_required_from_height: _,
        docclass_issuer_authority_enabled_from_height: _,
        nft_charged_receipt_enabled_from_height: _,
        docclass_revocation_record_enabled_from_height: _,
        docclass_credential_schema_enabled_from_height: _,
        nft_index_symmetry_enabled_from_height: _,
        docclass_identity_binding_enabled_from_height: _,
        docclass_issuer_stake_requirement_enabled_from_height: _,
        nft_collection_id_nonce_enabled_from_height: _,
        subsystem_proof_unsupported_enabled_from_height: _,
        property_state_precondition_enabled_from_height: _,
        property_asset_relationship_enabled_from_height: _,
        agreement_party_authority_unsupported_enabled_from_height: _,
        healthcare_consent_subject_signature_enabled_from_height: _,
        subsystem_issuer_self_registration_unsupported_enabled_from_height: _,
        property_proof_submission_unsupported_enabled_from_height: _,
        nft_unpayable_royalty_refused_enabled_from_height: _,
        docclass_signature_unsupported_enabled_from_height: _,
        docclass_credential_validity_bound_enabled_from_height: _,
        docclass_unknown_attribute_refused_enabled_from_height: _,
        subsystem_ambiguous_policy_id_refused_enabled_from_height: _,
        nft_royalty_operation_unsupported_enabled_from_height: _,
        // Schema 2 (draft), 0x103f: `schema::SCHEMA_2_ADDED`.
        credential_schema_validation_enabled_from_height: _,
        // Schema 2 (draft), 0x1042: `schema::SCHEMA_2_ADDED`.
        contract_error_rollback_enabled_from_height: _,
    } = params;

    put(0x0100, Value::U64(*max_block_bytes));
    put(0x0101, Value::U32(*max_txs_per_block));
    put(0x0102, Value::U128(*min_fee));
    put(0x0103, Value::U64(*finality_depth));
    put(0x0104, Value::U64(*max_metadata_bytes));
    put(0x0105, Value::U64(*min_contract_gas));
    put(0x0106, Value::U64(*max_contract_gas));
    put(0x0107, Value::U64(*max_access_list_bytes));
    put(0x0108, Value::U64(*activation_grace_blocks));
    put(0x0109, Value::U64(*abandonment_fee_percent));
    put(0x010a, Value::U32(*max_chunk_count_per_file));
    put(0x010b, Value::U32(*max_chunk_indices_per_tx));
    put(0x010c, Value::U32(*assignment_replication_factor));
    put(0x010d, Value::U64(*archive_unbonding_period_blocks));
    put(
        0x010e,
        Value::U32(*max_assignment_aware_challenges_per_block),
    );
    put(0x010f, Value::U32(*max_files_sampled_per_interval));
    put(0x0110, Value::U32(*max_chunks_sampled_per_file));
    put(
        0x0111,
        Value::U64(*inference_settlement_max_dispute_window_blocks),
    );
    put(
        0x0112,
        Value::U64(*inference_settlement_max_session_duration_blocks),
    );
    put(
        0x0113,
        inference_settlement_dispute_threshold_bps.map_or(Value::Absent, Value::U16),
    );
    put(
        0x0114,
        Value::U64(*inference_verifier_unbonding_period_blocks),
    );

    // ── fork choice and reorg bounds ──
    put(0x0200, Value::U64(crate::poa::MAX_REORG_WALK));
    put(
        0x0201,
        Value::U64(sumchain_storage::pruner::UNDO_RETENTION_FLOOR),
    );
    put(0x0202, Value::Absent);

    // ── staking ──
    //
    // Unset, the staking executor falls back to literals equal to
    // `StakingParams::default()`; the census test pins each literal to it.
    put(0x0300, Value::Bool(staking.is_some()));
    let StakingParams {
        min_validator_stake,
        max_validators,
        unbonding_period,
        max_commission_bps,
        double_sign_slash_bps,
        downtime_slash_bps,
        double_sign_jail_duration,
        downtime_jail_duration,
        downtime_threshold,
        epoch_length,
        stake_weighted_selection,
    } = staking.clone().unwrap_or_default();
    put(0x0301, Value::U128(min_validator_stake));
    put(0x0302, Value::U32(max_validators));
    put(0x0303, Value::U64(unbonding_period));
    put(0x0304, Value::U16(max_commission_bps));
    put(0x0305, Value::U16(double_sign_slash_bps));
    put(0x0306, Value::U16(downtime_slash_bps));
    put(0x0307, Value::U64(double_sign_jail_duration));
    put(0x0308, Value::U64(downtime_jail_duration));
    put(0x0309, Value::U64(downtime_threshold));
    put(0x030a, Value::U64(epoch_length));
    put(0x030b, Value::Bool(stake_weighted_selection));

    // ── messaging ──
    //
    // Unset, the executor uses `MessagingParams::default()`.
    put(0x0400, Value::Bool(messaging.is_some()));
    let sumchain_genesis::MessagingParams {
        daily_quota: _,              // excluded
        max_message_size: _,         // excluded
        min_trust_stake: _,          // excluded
        sponsorship_enabled: _,      // excluded
        initial_sponsorship_fund: _, // excluded
        registry_admin,
        spam_threshold,
        high_spam_threshold,
        stake_cooldown_blocks: _, // excluded
    } = messaging.clone().unwrap_or_default();
    put(0x0401, effective_address(registry_admin.as_deref()));
    put(0x0402, Value::U32(spam_threshold));
    put(0x0403, Value::U32(high_spam_threshold));

    // ── docclass ──
    //
    // Unset is its own behaviour — no issuer-stake rule, no admin, no validity
    // bound — not `DocClassParams::default()`, so absence is committed as such.
    put(0x0500, Value::Bool(docclass.is_some()));
    match docclass {
        Some(sumchain_genesis::DocClassParams {
            min_issuer_stake,
            admin,
            initial_issuers: _, // excluded
            max_credential_validity,
            require_issuer_stake,
        }) => {
            put(0x0501, Value::U128(*min_issuer_stake));
            put(0x0502, effective_address(admin.as_deref()));
            put(0x0503, Value::U64(*max_credential_validity));
            put(0x0504, Value::Bool(*require_issuer_stake));
        }
        None => {
            for id in 0x0501..=0x0504 {
                put(id, Value::Absent);
            }
        }
    }

    // ── governance ──
    put(0x0600, Value::Bool(governance.is_some()));
    match governance {
        Some(sumchain_primitives::GovernanceParams {
            validator_authority_threshold_bps,
            quorum_bps,
            pass_threshold_bps,
            voting_period_blocks,
            max_snapshot_holders,
            proposal_bond,
            treasury,
            min_koppa_for_eligibility,
        }) => {
            put(0x0601, Value::U16(*validator_authority_threshold_bps));
            put(0x0602, Value::U16(*quorum_bps));
            put(0x0603, Value::U16(*pass_threshold_bps));
            put(0x0604, Value::U64(*voting_period_blocks));
            put(0x0605, Value::U32(*max_snapshot_holders));
            put(0x0606, Value::U128(*proposal_bond));
            put(
                0x0607,
                treasury.map_or(Value::Absent, |a| Value::Bytes(a.as_bytes().to_vec())),
            );
            put(0x0608, Value::U128(*min_koppa_for_eligibility));
        }
        None => {
            for id in 0x0601..=0x0608 {
                put(id, Value::Absent);
            }
        }
    }

    // ── beacon ──
    //
    // As configured. The beacon gate cannot open under the current genesis
    // validation, so the executor's unset fallback is unreachable and is not
    // a rule this chain runs.
    put(0x0700, Value::Bool(beacon_params.is_some()));
    match beacon_params {
        Some(sumchain_genesis::BeaconParamsConfig {
            f: bf,
            c,
            t,
            q_dkg,
            n,
        }) => {
            put(0x0701, Value::U32(*bf));
            put(0x0702, Value::U32(*c));
            put(0x0703, Value::U32(*t));
            put(0x0704, Value::U32(*q_dkg));
            put(0x0705, Value::U32(*n));
        }
        None => {
            for id in 0x0701..=0x0705 {
                put(id, Value::Absent);
            }
        }
    }
    put(0x0710, Value::Bool(beacon_schedule.is_some()));
    match beacon_schedule {
        Some(sumchain_primitives::beacon_schedule::BeaconSchedule {
            start_height,
            epoch_length,
            key_cutoff_offset,
            deal_start_offset,
            deal_cutoff_offset,
            complaint_start_offset,
            complaint_deadline_offset,
        }) => {
            put(0x0711, Value::U64(*start_height));
            put(0x0712, Value::U64(*epoch_length));
            put(0x0713, Value::U64(*key_cutoff_offset));
            put(0x0714, Value::U64(*deal_start_offset));
            put(0x0715, Value::U64(*deal_cutoff_offset));
            put(0x0716, Value::U64(*complaint_start_offset));
            put(0x0717, Value::U64(*complaint_deadline_offset));
        }
        None => {
            for id in 0x0711..=0x0717 {
                put(id, Value::Absent);
            }
        }
    }

    // ── activation heights, by name ──
    for (name, height) in params.activation_heights() {
        let id = gate_id_in(knows, name).ok_or_else(|| {
            ConfigError::Build(format!(
                "activation gate {name} has no consensus configuration field id in \
                 schema {}; this binary cannot commit to a gate it does not know \
                 (register it in schema::SCHEMA_2_ADDED)",
                knows.number
            ))
        })?;
        put(id, height.map_or(Value::Absent, Value::U64));
    }

    // ── consensus_limits(), by name ──
    for (name, value) in consensus_limits() {
        let id = limit_id(name).ok_or_else(|| {
            ConfigError::Build(format!(
                "consensus limit {name} has no ConsensusConfigV1 field id"
            ))
        })?;
        put(
            id,
            match value {
                LimitValue::Num(n) => Value::U128(n),
                LimitValue::Bytes(b) => Value::Bytes(b.to_vec()),
            },
        );
    }

    // ── further compiled constants ──
    for (id, _, value) in extra_constants() {
        put(id, value);
    }

    // ── fields added after schema 1 ──
    //
    // Gates came in through `activation_heights()` above.
    for added in knows.all_added() {
        if let Source::Param(value) = added.source {
            put(added.spec.id, value(genesis));
        }
    }

    f.sort_by_key(|field| field.id);
    if f.windows(2).any(|w| w[0].id == w[1].id) {
        return Err(ConfigError::Build(
            "a consensus configuration field was computed twice".to_string(),
        ));
    }
    Ok(f)
}

/// Field id of an activation gate, in the newest schema this binary knows.
pub fn gate_id(name: &str) -> Option<u16> {
    gate_id_in(PRODUCTION.knows, name)
}

/// Field id of an activation gate in `schema`.
pub fn gate_id_in(schema: &'static Schema, name: &str) -> Option<u16> {
    schema
        .specs()
        .into_iter()
        .find(|s| is_gate(s.id) && s.name == name)
        .map(|s| s.id)
}

/// Field id of a `consensus_limits()` entry.
pub fn limit_id(name: &str) -> Option<u16> {
    SCHEMA_V1_FIELDS
        .iter()
        .find(|s| (0x2000..=0x20ff).contains(&s.id) && s.name == name)
        .map(|s| s.id)
}

/// An address as execution resolves it: base58 or hex parses to the address,
/// anything else is ignored by every reader and is therefore no address.
fn effective_address(raw: Option<&str>) -> Value {
    raw.and_then(|s| {
        Address::from_base58(s)
            .or_else(|_| Address::from_hex(s))
            .ok()
    })
    .map_or(Value::Absent, |a| Value::Bytes(a.as_bytes().to_vec()))
}

/// Domain of [`alloc_digest`].
pub const ALLOC_DIGEST_DOMAIN: &[u8] = b"SUMCHAIN/CONSENSUS-CONFIG/ALLOC/v1\0";

/// Digest of the genesis allocations: `count:u64 ‖ (address[20] ‖ balance:u128)*`,
/// little-endian, sorted by address then balance.
///
/// Sorting on both keys makes the digest independent of `HashMap` order even
/// when two spellings of one address appear — a case genesis validation does
/// not refuse today. Such an entry is committed as it stands rather than
/// silently merged.
pub fn alloc_digest(genesis: &Genesis) -> Result<[u8; 32], sumchain_genesis::GenesisError> {
    let mut alloc = genesis.parsed_alloc()?;
    alloc.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()).then(a.1.cmp(&b.1)));
    let mut data = Vec::with_capacity(ALLOC_DIGEST_DOMAIN.len() + 8 + alloc.len() * 36);
    data.extend_from_slice(ALLOC_DIGEST_DOMAIN);
    data.extend_from_slice(&(alloc.len() as u64).to_le_bytes());
    for (addr, balance) in &alloc {
        data.extend_from_slice(addr.as_bytes());
        data.extend_from_slice(&balance.to_le_bytes());
    }
    Ok(*Hash::hash(&data).as_bytes())
}

/// Compiled consensus constants beyond `consensus_limits()`: `(id, name, value)`.
///
/// Every entry names the constant it reads, so the value committed is the value
/// this binary was compiled with. Struct defaults are destructured without `..`:
/// a field added to `GasCosts` or `SchemaValidatorConfig` does not compile here
/// until it is committed. The classification of every constant declaration in
/// the consensus crates — committed here, committed elsewhere, or excluded with
/// a reason — is `crates/consensus/tests/data/consensus_constants_census.tsv`,
/// enforced by `consensus_config_census.rs`.
pub fn extra_constants() -> Vec<(u16, &'static str, Value)> {
    let gas = sumc_runtime::gas::GasCosts::default();
    let sumc_runtime::gas::GasCosts {
        call_base: _,
        deploy_base: _,
        wasm_instruction: _,
        memory_page: _,
        storage_read_base: _,
        storage_read_per_byte: _,
        storage_write_base: _,
        storage_write_per_byte: _,
        storage_delete: _,
        blake3_base: _,
        blake3_per_byte: _,
        ed25519_verify: _,
        secp256k1_verify: _,
        cross_call_base: _,
        event_base: _,
        event_per_byte: _,
        log_base: _,
        log_per_byte: _,
        transfer: _,
    } = gas;
    let schema = sumchain_state::schema_validator::SchemaValidatorConfig::default();
    let sumchain_state::schema_validator::SchemaValidatorConfig {
        activation_height: _,
        enabled: _,
    } = schema;
    vec![
        (
            0x2100,
            "sumchain_crypto::messaging::LOW_ORDER_X25519_POINTS",
            Value::List(
                sumchain_crypto::messaging::LOW_ORDER_X25519_POINTS
                    .iter()
                    .map(|p| p.to_vec())
                    .collect(),
            ),
        ),
        (
            0x2200,
            "sumchain_wire::address::Address::ZERO",
            Value::Bytes(sumchain_wire::address::Address::ZERO.as_bytes().to_vec()),
        ),
        (
            0x2201,
            "sumchain_wire::beacon_wire::W1B_BEACON_DKG_TXTYPE",
            Value::U128(sumchain_wire::beacon_wire::W1B_BEACON_DKG_TXTYPE as u128),
        ),
        (
            0x2202,
            "sumchain_wire::beacon_wire::W1B_BEACON_SIGN_TXTYPE",
            Value::U128(sumchain_wire::beacon_wire::W1B_BEACON_SIGN_TXTYPE as u128),
        ),
        (
            0x2203,
            "sumchain_wire::beacon_wire::BeaconWireOp::ALL",
            Value::List(
                sumchain_wire::beacon_wire::BeaconWireOp::ALL
                    .iter()
                    .map(|o| format!("{o:?}").into_bytes())
                    .collect(),
            ),
        ),
        (
            0x2204,
            "sumchain_wire::beacon_wire::RegisterBeaconKeyV1::MAGIC",
            Value::Bytes(sumchain_wire::beacon_wire::RegisterBeaconKeyV1::MAGIC.to_vec()),
        ),
        (
            0x2205,
            "sumchain_wire::beacon_wire::RegisterBeaconKeyV1::SCHEMA_VERSION",
            Value::U128(sumchain_wire::beacon_wire::RegisterBeaconKeyV1::SCHEMA_VERSION as u128),
        ),
        (
            0x2206,
            "sumchain_wire::beacon_wire::DkgDealV1::MAGIC",
            Value::Bytes(sumchain_wire::beacon_wire::DkgDealV1::MAGIC.to_vec()),
        ),
        (
            0x2207,
            "sumchain_wire::beacon_wire::DkgDealV1::SCHEMA_VERSION",
            Value::U128(sumchain_wire::beacon_wire::DkgDealV1::SCHEMA_VERSION as u128),
        ),
        (
            0x2208,
            "sumchain_wire::beacon_wire::DkgComplaintV1::MAGIC",
            Value::Bytes(sumchain_wire::beacon_wire::DkgComplaintV1::MAGIC.to_vec()),
        ),
        (
            0x2209,
            "sumchain_wire::beacon_wire::DkgComplaintV1::SCHEMA_VERSION",
            Value::U128(sumchain_wire::beacon_wire::DkgComplaintV1::SCHEMA_VERSION as u128),
        ),
        (
            0x220a,
            "sumchain_wire::beacon_wire::BeaconPartialV1::MAGIC",
            Value::Bytes(sumchain_wire::beacon_wire::BeaconPartialV1::MAGIC.to_vec()),
        ),
        (
            0x220b,
            "sumchain_wire::beacon_wire::BeaconPartialV1::SCHEMA_VERSION",
            Value::U128(sumchain_wire::beacon_wire::BeaconPartialV1::SCHEMA_VERSION as u128),
        ),
        (
            0x220c,
            "sumchain_wire::beacon_wire::BeaconFinalizeV1::MAGIC",
            Value::Bytes(sumchain_wire::beacon_wire::BeaconFinalizeV1::MAGIC.to_vec()),
        ),
        (
            0x220d,
            "sumchain_wire::beacon_wire::BeaconFinalizeV1::SCHEMA_VERSION",
            Value::U128(sumchain_wire::beacon_wire::BeaconFinalizeV1::SCHEMA_VERSION as u128),
        ),
        (
            0x220e,
            "sumchain_wire::beacon_wire::BeaconFinalizeV1::WITNESS_ELEM_LEN",
            Value::U128(sumchain_wire::beacon_wire::BeaconFinalizeV1::WITNESS_ELEM_LEN as u128),
        ),
        (
            0x220f,
            "sumchain_wire::education::MAX_EDU_OP_DATA_BYTES",
            Value::U128(sumchain_wire::education::MAX_EDU_OP_DATA_BYTES as u128),
        ),
        (
            0x2210,
            "sumchain_wire::education::catalog_op::CREATE_CATALOG_ENTRY",
            Value::U128(sumchain_wire::education::catalog_op::CREATE_CATALOG_ENTRY as u128),
        ),
        (
            0x2211,
            "sumchain_wire::education::catalog_op::UPDATE_CATALOG_ENTRY",
            Value::U128(sumchain_wire::education::catalog_op::UPDATE_CATALOG_ENTRY as u128),
        ),
        (
            0x2212,
            "sumchain_wire::education::catalog_op::PUBLISH_CATALOG_CONTENT",
            Value::U128(sumchain_wire::education::catalog_op::PUBLISH_CATALOG_CONTENT as u128),
        ),
        (
            0x2213,
            "sumchain_wire::education::catalog_op::DEPRECATE_CATALOG_ENTRY",
            Value::U128(sumchain_wire::education::catalog_op::DEPRECATE_CATALOG_ENTRY as u128),
        ),
        (
            0x2214,
            "sumchain_wire::education::catalog_op::SUPERSEDE_CATALOG_ENTRY",
            Value::U128(sumchain_wire::education::catalog_op::SUPERSEDE_CATALOG_ENTRY as u128),
        ),
        (
            0x2215,
            "sumchain_wire::education::catalog_op::ARCHIVE_CATALOG_ENTRY",
            Value::U128(sumchain_wire::education::catalog_op::ARCHIVE_CATALOG_ENTRY as u128),
        ),
        (
            0x2216,
            "sumchain_wire::education::offering_op::CREATE_OFFERING",
            Value::U128(sumchain_wire::education::offering_op::CREATE_OFFERING as u128),
        ),
        (
            0x2217,
            "sumchain_wire::education::offering_op::UPDATE_OFFERING",
            Value::U128(sumchain_wire::education::offering_op::UPDATE_OFFERING as u128),
        ),
        (
            0x2218,
            "sumchain_wire::education::offering_op::PUBLISH_CONTENT",
            Value::U128(sumchain_wire::education::offering_op::PUBLISH_CONTENT as u128),
        ),
        (
            0x2219,
            "sumchain_wire::education::offering_op::ADD_ASSESSMENT",
            Value::U128(sumchain_wire::education::offering_op::ADD_ASSESSMENT as u128),
        ),
        (
            0x221a,
            "sumchain_wire::education::offering_op::UPDATE_ASSESSMENT",
            Value::U128(sumchain_wire::education::offering_op::UPDATE_ASSESSMENT as u128),
        ),
        (
            0x221b,
            "sumchain_wire::education::offering_op::OPEN_ENROLLMENT",
            Value::U128(sumchain_wire::education::offering_op::OPEN_ENROLLMENT as u128),
        ),
        (
            0x221c,
            "sumchain_wire::education::offering_op::CLOSE_ENROLLMENT",
            Value::U128(sumchain_wire::education::offering_op::CLOSE_ENROLLMENT as u128),
        ),
        (
            0x221d,
            "sumchain_wire::education::offering_op::LINK_ENROLLMENT",
            Value::U128(sumchain_wire::education::offering_op::LINK_ENROLLMENT as u128),
        ),
        (
            0x221e,
            "sumchain_wire::education::offering_op::SUBMIT_ASSIGNMENT",
            Value::U128(sumchain_wire::education::offering_op::SUBMIT_ASSIGNMENT as u128),
        ),
        (
            0x221f,
            "sumchain_wire::education::offering_op::SUBMIT_EXAM",
            Value::U128(sumchain_wire::education::offering_op::SUBMIT_EXAM as u128),
        ),
        (
            0x2220,
            "sumchain_wire::education::offering_op::GRADE_SUBMISSION",
            Value::U128(sumchain_wire::education::offering_op::GRADE_SUBMISSION as u128),
        ),
        (
            0x2221,
            "sumchain_wire::education::offering_op::FINALIZE_GRADE",
            Value::U128(sumchain_wire::education::offering_op::FINALIZE_GRADE as u128),
        ),
        (
            0x2222,
            "sumchain_wire::education::offering_op::FINALIZE_COURSE",
            Value::U128(sumchain_wire::education::offering_op::FINALIZE_COURSE as u128),
        ),
        (
            0x2223,
            "sumchain_wire::education::offering_op::ARCHIVE_OFFERING",
            Value::U128(sumchain_wire::education::offering_op::ARCHIVE_OFFERING as u128),
        ),
        (
            0x2224,
            "sumchain_wire::education::offering_op::SUSPEND_OR_CANCEL_OFFERING",
            Value::U128(sumchain_wire::education::offering_op::SUSPEND_OR_CANCEL_OFFERING as u128),
        ),
        (
            0x2225,
            "sumchain_wire::governance::GOV_ESCROW_DOMAIN",
            Value::Bytes(sumchain_wire::governance::GOV_ESCROW_DOMAIN.to_vec()),
        ),
        (
            0x2226,
            "sumchain_wire::governance::GOV_EQUITY_VOTE_DOMAIN",
            Value::Bytes(sumchain_wire::governance::GOV_EQUITY_VOTE_DOMAIN.to_vec()),
        ),
        (
            0x2227,
            "sumchain_wire::governance::GOV_PROPOSAL_DOMAIN",
            Value::Bytes(sumchain_wire::governance::GOV_PROPOSAL_DOMAIN.to_vec()),
        ),
        (
            0x2228,
            "sumchain_wire::governance::GOV_ASSET_EQUITY_CLASS_PREFIX",
            Value::Bytes(sumchain_wire::governance::GOV_ASSET_EQUITY_CLASS_PREFIX.to_vec()),
        ),
        (
            0x2229,
            "sumchain_wire::governance::GOV_ASSET_NATIVE_ELIGIBILITY_PREFIX",
            Value::Bytes(sumchain_wire::governance::GOV_ASSET_NATIVE_ELIGIBILITY_PREFIX.to_vec()),
        ),
        (
            0x222a,
            "sumchain_wire::governance::GOV_ASSET_SRC20_PREFIX",
            Value::Bytes(sumchain_wire::governance::GOV_ASSET_SRC20_PREFIX.to_vec()),
        ),
        (
            0x222b,
            "sumchain_wire::hash::Hash::ZERO",
            Value::Bytes(sumchain_wire::hash::Hash::ZERO.as_bytes().to_vec()),
        ),
        (
            0x222c,
            "sumchain_wire::healthcare::CONSENT_GRANT_SIGNING_SEP",
            Value::Bytes(sumchain_wire::healthcare::CONSENT_GRANT_SIGNING_SEP.to_vec()),
        ),
        (
            0x222d,
            "sumchain_wire::inference_attestation::DOMAIN_TAG",
            Value::Bytes(
                sumchain_wire::inference_attestation::DOMAIN_TAG
                    .as_bytes()
                    .to_vec(),
            ),
        ),
        (
            0x222e,
            "sumchain_wire::inference_attestation::MAX_SESSION_ID_BYTES",
            Value::U128(sumchain_wire::inference_attestation::MAX_SESSION_ID_BYTES as u128),
        ),
        (
            0x222f,
            "sumchain_wire::inference_attestation::INFERENCE_ATTESTATION_KEY_DOMAIN",
            Value::Bytes(
                sumchain_wire::inference_attestation::INFERENCE_ATTESTATION_KEY_DOMAIN.to_vec(),
            ),
        ),
        (
            0x2230,
            "sumchain_wire::inference_attestation::INFERENCE_ATTESTATION_SESSION_INDEX_DOMAIN",
            Value::Bytes(
                sumchain_wire::inference_attestation::INFERENCE_ATTESTATION_SESSION_INDEX_DOMAIN
                    .to_vec(),
            ),
        ),
        (
            0x2231,
            "sumchain_wire::inference_attestation::SESSION_ID_HASH_BYTES",
            Value::U128(sumchain_wire::inference_attestation::SESSION_ID_HASH_BYTES as u128),
        ),
        (
            0x2232,
            "sumchain_wire::inference_settlement::SESSION_KEY_DOMAIN",
            Value::Bytes(sumchain_wire::inference_settlement::SESSION_KEY_DOMAIN.to_vec()),
        ),
        (
            0x2233,
            "sumchain_wire::inference_settlement::SESSION_INDEX_DOMAIN",
            Value::Bytes(sumchain_wire::inference_settlement::SESSION_INDEX_DOMAIN.to_vec()),
        ),
        (
            0x2234,
            "sumchain_wire::inference_settlement::SESSION_PREFIX_BYTES",
            Value::U128(sumchain_wire::inference_settlement::SESSION_PREFIX_BYTES as u128),
        ),
        (
            0x2235,
            "sumchain_wire::inference_settlement::VERIFIER_KEY_DOMAIN",
            Value::Bytes(sumchain_wire::inference_settlement::VERIFIER_KEY_DOMAIN.to_vec()),
        ),
        (
            0x2236,
            "sumchain_wire::messaging::SRC201_MAGIC",
            Value::Bytes(sumchain_wire::messaging::SRC201_MAGIC.to_vec()),
        ),
        (
            0x2237,
            "sumchain_wire::messaging::SRC201_VERSION",
            Value::U128(sumchain_wire::messaging::SRC201_VERSION as u128),
        ),
        (
            0x2238,
            "sumchain_wire::messaging::SRC201_HEADER_SIZE",
            Value::U128(sumchain_wire::messaging::SRC201_HEADER_SIZE as u128),
        ),
        (
            0x2239,
            "sumchain_wire::messaging::SRC201_NONCE_SIZE",
            Value::U128(sumchain_wire::messaging::SRC201_NONCE_SIZE as u128),
        ),
        (
            0x223a,
            "sumchain_wire::messaging::SRC201_TAG_SIZE",
            Value::U128(sumchain_wire::messaging::SRC201_TAG_SIZE as u128),
        ),
        (
            0x223b,
            "sumchain_wire::messaging::DEFAULT_DAILY_QUOTA",
            Value::U128(sumchain_wire::messaging::DEFAULT_DAILY_QUOTA as u128),
        ),
        (
            0x223c,
            "sumchain_wire::messaging::DEFAULT_MAX_MESSAGE_SIZE",
            Value::U128(sumchain_wire::messaging::DEFAULT_MAX_MESSAGE_SIZE as u128),
        ),
        (
            0x223d,
            "sumchain_wire::messaging::DEFAULT_MIN_TRUST_STAKE",
            Value::U128(sumchain_wire::messaging::DEFAULT_MIN_TRUST_STAKE),
        ),
        (
            0x223e,
            "sumchain_wire::messaging::SPONSORED_REGISTER_V1_TAG",
            Value::Bytes(sumchain_wire::messaging::SPONSORED_REGISTER_V1_TAG.to_vec()),
        ),
        (
            0x223f,
            "sumchain_wire::policy_account::POLICY_ACCOUNT_DOMAIN_SEP",
            Value::Bytes(sumchain_wire::policy_account::POLICY_ACCOUNT_DOMAIN_SEP.to_vec()),
        ),
        (
            0x2240,
            "sumchain_wire::policy_account::PROPOSAL_DOMAIN_SEP",
            Value::Bytes(sumchain_wire::policy_account::PROPOSAL_DOMAIN_SEP.to_vec()),
        ),
        (
            0x2241,
            "sumchain_wire::policy_account::APPROVAL_SIGNING_DOMAIN_V1",
            Value::Bytes(sumchain_wire::policy_account::APPROVAL_SIGNING_DOMAIN_V1.to_vec()),
        ),
        (
            0x2242,
            "sumchain_wire::policy_account::MAX_MEMBERS",
            Value::U128(sumchain_wire::policy_account::MAX_MEMBERS as u128),
        ),
        (
            0x2243,
            "sumchain_wire::policy_account::MAX_CUSTOM_RULES",
            Value::U128(sumchain_wire::policy_account::MAX_CUSTOM_RULES as u128),
        ),
        (
            0x2244,
            "sumchain_wire::policy_account::MAX_APPROVALS",
            Value::U128(sumchain_wire::policy_account::MAX_APPROVALS as u128),
        ),
        (
            0x2245,
            "sumchain_wire::policy_account::MAX_PROPOSAL_PAYLOAD_SIZE",
            Value::U128(sumchain_wire::policy_account::MAX_PROPOSAL_PAYLOAD_SIZE as u128),
        ),
        (
            0x2246,
            "sumchain_wire::storage_metadata::CHUNK_SIZE",
            Value::U128(sumchain_wire::storage_metadata::CHUNK_SIZE as u128),
        ),
        (
            0x2247,
            "sumchain_wire::storage_metadata::CHALLENGE_TTL_BLOCKS",
            Value::U128(sumchain_wire::storage_metadata::CHALLENGE_TTL_BLOCKS as u128),
        ),
        (
            0x2248,
            "sumchain_wire::storage_metadata::CHALLENGE_INTERVAL_BLOCKS",
            Value::U128(sumchain_wire::storage_metadata::CHALLENGE_INTERVAL_BLOCKS as u128),
        ),
        (
            0x2249,
            "sumchain_wire::storage_metadata::CHALLENGE_REWARD",
            Value::U128(sumchain_wire::storage_metadata::CHALLENGE_REWARD as u128),
        ),
        (
            0x224a,
            "sumchain_wire::storage_metadata::SLASH_PERCENTAGE",
            Value::U128(sumchain_wire::storage_metadata::SLASH_PERCENTAGE as u128),
        ),
        (
            0x224b,
            "sumchain_wire::storage_metadata::SNIP_V2_ASSIGNMENT_CONTEXT",
            Value::Bytes(
                sumchain_wire::storage_metadata::SNIP_V2_ASSIGNMENT_CONTEXT
                    .as_bytes()
                    .to_vec(),
            ),
        ),
        (
            0x224c,
            "sumchain_wire::supply::KOPPA",
            Value::U128(sumchain_wire::supply::KOPPA),
        ),
        (
            0x224d,
            "sumchain_wire::supply::TARGET_CANONICAL_SUPPLY",
            Value::U128(sumchain_wire::supply::TARGET_CANONICAL_SUPPLY),
        ),
        (
            0x224e,
            "sumchain_wire::supply::GENESIS_ACCOUNTED_SUPPLY",
            Value::U128(sumchain_wire::supply::GENESIS_ACCOUNTED_SUPPLY),
        ),
        (
            0x224f,
            "sumchain_wire::supply::MAINNET_CHAIN_ID",
            Value::U128(sumchain_wire::supply::MAINNET_CHAIN_ID as u128),
        ),
        (
            0x2250,
            "sumchain_wire::supply::SUPPLY_CORRECTION_DOMAIN",
            Value::Bytes(sumchain_wire::supply::SUPPLY_CORRECTION_DOMAIN.to_vec()),
        ),
        (
            0x2251,
            "sumchain_wire::supply::POOL_VALIDATOR",
            Value::U128(sumchain_wire::supply::POOL_VALIDATOR),
        ),
        (
            0x2252,
            "sumchain_wire::supply::POOL_ARCHIVE",
            Value::U128(sumchain_wire::supply::POOL_ARCHIVE),
        ),
        (
            0x2253,
            "sumchain_wire::supply::POOL_COMPUTE",
            Value::U128(sumchain_wire::supply::POOL_COMPUTE),
        ),
        (
            0x2254,
            "sumchain_wire::supply::POOL_ECOSYSTEM",
            Value::U128(sumchain_wire::supply::POOL_ECOSYSTEM),
        ),
        (
            0x2255,
            "sumchain_wire::supply::POOL_GOVERNANCE_RESERVE",
            Value::U128(sumchain_wire::supply::POOL_GOVERNANCE_RESERVE),
        ),
        (
            0x2256,
            "sumchain_wire::supply::FIXED_SERVICE_POOLS",
            Value::U128(sumchain_wire::supply::FIXED_SERVICE_POOLS),
        ),
        (
            0x2257,
            "sumchain_wire::supply::GENESIS_VALIDATOR_ACCOUNTS",
            Value::List(
                sumchain_wire::supply::GENESIS_VALIDATOR_ACCOUNTS
                    .iter()
                    .map(|s| s.as_bytes().to_vec())
                    .collect(),
            ),
        ),
        (
            0x2258,
            "sumchain_wire::supply::GENESIS_VALIDATOR_PUBKEYS",
            Value::List(
                sumchain_wire::supply::GENESIS_VALIDATOR_PUBKEYS
                    .iter()
                    .map(|s| s.as_bytes().to_vec())
                    .collect(),
            ),
        ),
        (
            0x2259,
            "sumchain_wire::supply::GRANT_LIQUID_BPS",
            Value::U128(sumchain_wire::supply::GRANT_LIQUID_BPS),
        ),
        (
            0x225a,
            "sumchain_wire::supply::ARCHIVE_ACTIVE_BLOCKS_MILESTONE",
            Value::U128(sumchain_wire::supply::ARCHIVE_ACTIVE_BLOCKS_MILESTONE as u128),
        ),
        (
            0x225b,
            "sumchain_wire::supply::ARCHIVE_ACTIVE_GRANT",
            Value::U128(sumchain_wire::supply::ARCHIVE_ACTIVE_GRANT),
        ),
        (
            0x225c,
            "sumchain_wire::supply::ARCHIVE_PROOFS_MILESTONE_1",
            Value::U128(sumchain_wire::supply::ARCHIVE_PROOFS_MILESTONE_1 as u128),
        ),
        (
            0x225d,
            "sumchain_wire::supply::ARCHIVE_PROOFS_GRANT_1",
            Value::U128(sumchain_wire::supply::ARCHIVE_PROOFS_GRANT_1),
        ),
        (
            0x225e,
            "sumchain_wire::supply::ARCHIVE_PROOFS_MILESTONE_2",
            Value::U128(sumchain_wire::supply::ARCHIVE_PROOFS_MILESTONE_2 as u128),
        ),
        (
            0x225f,
            "sumchain_wire::supply::ARCHIVE_PROOFS_GRANT_2",
            Value::U128(sumchain_wire::supply::ARCHIVE_PROOFS_GRANT_2),
        ),
        (
            0x2260,
            "sumchain_wire::supply::COMPUTE_CLAIMS_MILESTONE_1",
            Value::U128(sumchain_wire::supply::COMPUTE_CLAIMS_MILESTONE_1 as u128),
        ),
        (
            0x2261,
            "sumchain_wire::supply::COMPUTE_CLAIMS_GRANT_1",
            Value::U128(sumchain_wire::supply::COMPUTE_CLAIMS_GRANT_1),
        ),
        (
            0x2262,
            "sumchain_wire::supply::COMPUTE_CLAIMS_MILESTONE_2",
            Value::U128(sumchain_wire::supply::COMPUTE_CLAIMS_MILESTONE_2 as u128),
        ),
        (
            0x2263,
            "sumchain_wire::supply::COMPUTE_CLAIMS_GRANT_2",
            Value::U128(sumchain_wire::supply::COMPUTE_CLAIMS_GRANT_2),
        ),
        (
            0x2264,
            "sumchain_wire::supply::GRANTS_AGGREGATE_DIGEST_DOMAIN",
            Value::Bytes(sumchain_wire::supply::GRANTS_AGGREGATE_DIGEST_DOMAIN.to_vec()),
        ),
        (
            0x2265,
            "sumchain_wire::supply::PROTOCOL_RESERVE_DIGEST_DOMAIN",
            Value::Bytes(sumchain_wire::supply::PROTOCOL_RESERVE_DIGEST_DOMAIN.to_vec()),
        ),
        (
            0x2266,
            "sumchain_wire::supply::SUPPLY_LEDGER_DIGEST_DOMAIN",
            Value::Bytes(sumchain_wire::supply::SUPPLY_LEDGER_DIGEST_DOMAIN.to_vec()),
        ),
        (
            0x2267,
            "sumchain_wire::supply::VALIDATOR_COHORT_1_GRANT",
            Value::U128(sumchain_wire::supply::VALIDATOR_COHORT_1_GRANT),
        ),
        (
            0x2268,
            "sumchain_wire::supply::VALIDATOR_COHORT_1_LAST_INDEX",
            Value::U128(sumchain_wire::supply::VALIDATOR_COHORT_1_LAST_INDEX as u128),
        ),
        (
            0x2269,
            "sumchain_wire::supply::VALIDATOR_COHORT_2_GRANT",
            Value::U128(sumchain_wire::supply::VALIDATOR_COHORT_2_GRANT),
        ),
        (
            0x226a,
            "sumchain_wire::supply::VALIDATOR_COHORT_2_LAST_INDEX",
            Value::U128(sumchain_wire::supply::VALIDATOR_COHORT_2_LAST_INDEX as u128),
        ),
        (
            0x226b,
            "sumchain_wire::supply::VALIDATOR_COHORT_3_GRANT",
            Value::U128(sumchain_wire::supply::VALIDATOR_COHORT_3_GRANT),
        ),
        (
            0x226c,
            "sumchain_wire::supply::VALIDATOR_COHORT_3_LAST_INDEX",
            Value::U128(sumchain_wire::supply::VALIDATOR_COHORT_3_LAST_INDEX as u128),
        ),
        (
            0x226d,
            "sumchain_wire::supply::VALIDATOR_COHORT_4_GRANT",
            Value::U128(sumchain_wire::supply::VALIDATOR_COHORT_4_GRANT),
        ),
        (
            0x226e,
            "sumchain_wire::supply::VALIDATOR_COHORT_4_LAST_INDEX",
            Value::U128(sumchain_wire::supply::VALIDATOR_COHORT_4_LAST_INDEX as u128),
        ),
        (
            0x226f,
            "sumchain_wire::validator_authority::GOV_REGISTER_ASSET_DOMAIN",
            Value::Bytes(sumchain_wire::validator_authority::GOV_REGISTER_ASSET_DOMAIN.to_vec()),
        ),
        (
            0x2270,
            "sumchain_wire::validator_authority::GOV_CANCEL_PROPOSAL_DOMAIN",
            Value::Bytes(sumchain_wire::validator_authority::GOV_CANCEL_PROPOSAL_DOMAIN.to_vec()),
        ),
        (
            0x2271,
            "sumchain_wire::validator_authority::GOV_REGISTER_EQUITY_CLASS_DOMAIN",
            Value::Bytes(
                sumchain_wire::validator_authority::GOV_REGISTER_EQUITY_CLASS_DOMAIN.to_vec(),
            ),
        ),
        (
            0x2272,
            "sumchain_wire::validator_authority::INFERENCE_RESOLVE_DISPUTE_DOMAIN",
            Value::Bytes(
                sumchain_wire::validator_authority::INFERENCE_RESOLVE_DISPUTE_DOMAIN.to_vec(),
            ),
        ),
        (
            0x2400,
            "sumchain_storage::schema::contract_cf_kind::STORAGE",
            Value::U128(sumchain_storage::schema::contract_cf_kind::STORAGE as u128),
        ),
        (
            0x2401,
            "sumchain_storage::schema::contract_cf_kind::CODE",
            Value::U128(sumchain_storage::schema::contract_cf_kind::CODE as u128),
        ),
        (
            0x2402,
            "sumchain_storage::schema::contract_cf_kind::METADATA",
            Value::U128(sumchain_storage::schema::contract_cf_kind::METADATA as u128),
        ),
        (
            0x2500,
            "sumchain_state::schema_validator::SchemaValidatorConfig::default().activation_height",
            Value::U128(schema.activation_height as u128),
        ),
        (
            0x2501,
            "sumchain_state::schema_validator::SchemaValidatorConfig::default().enabled",
            Value::Bool(schema.enabled),
        ),
        (
            0x2502,
            "sumchain_state::beacon_store::domain::KEY",
            Value::U128(sumchain_state::beacon_store::domain::KEY as u128),
        ),
        (
            0x2503,
            "sumchain_state::beacon_store::domain::DEAL",
            Value::U128(sumchain_state::beacon_store::domain::DEAL as u128),
        ),
        (
            0x2504,
            "sumchain_state::beacon_store::domain::VERDICT",
            Value::U128(sumchain_state::beacon_store::domain::VERDICT as u128),
        ),
        (
            0x2505,
            "sumchain_state::beacon_store::domain::ROUND",
            Value::U128(sumchain_state::beacon_store::domain::ROUND as u128),
        ),
        (
            0x2506,
            "sumchain_state::beacon_store::domain::OUTPUT",
            Value::U128(sumchain_state::beacon_store::domain::OUTPUT as u128),
        ),
        (
            0x2507,
            "sumchain_state::beacon_store::domain::MEMBERSHIP",
            Value::U128(sumchain_state::beacon_store::domain::MEMBERSHIP as u128),
        ),
        (
            0x2508,
            "sumchain_state::beacon_store::domain::FALSE_ACCUSER",
            Value::U128(sumchain_state::beacon_store::domain::FALSE_ACCUSER as u128),
        ),
        (
            0x2509,
            "sumchain_state::beacon_store::domain::ADJUDICATED",
            Value::U128(sumchain_state::beacon_store::domain::ADJUDICATED as u128),
        ),
        (
            0x250a,
            "sumchain_state::beacon_store::domain::KEY_EQUIV",
            Value::U128(sumchain_state::beacon_store::domain::KEY_EQUIV as u128),
        ),
        (
            0x250b,
            "sumchain_state::beacon_store::domain::DEAL_EQUIV",
            Value::U128(sumchain_state::beacon_store::domain::DEAL_EQUIV as u128),
        ),
        (
            0x250c,
            "sumchain_state::compute_pool_store::domain::JOB",
            Value::U128(sumchain_state::compute_pool_store::domain::JOB as u128),
        ),
        (
            0x250d,
            "sumchain_state::compute_pool_store::domain::UNIT",
            Value::U128(sumchain_state::compute_pool_store::domain::UNIT as u128),
        ),
        (
            0x250e,
            "sumchain_state::compute_pool_store::domain::OFFER",
            Value::U128(sumchain_state::compute_pool_store::domain::OFFER as u128),
        ),
        (
            0x250f,
            "sumchain_state::compute_pool_store::domain::ACTIVE_OFFER_INDEX",
            Value::U128(sumchain_state::compute_pool_store::domain::ACTIVE_OFFER_INDEX as u128),
        ),
        (
            0x2510,
            "sumchain_state::compute_pool_store::domain::RESERVATION",
            Value::U128(sumchain_state::compute_pool_store::domain::RESERVATION as u128),
        ),
        (
            0x2511,
            "sumchain_state::compute_pool_store::domain::ACCEPTED_LEAF",
            Value::U128(sumchain_state::compute_pool_store::domain::ACCEPTED_LEAF as u128),
        ),
        (
            0x2512,
            "sumchain_state::compute_pool_store::domain::ASSIGNMENT",
            Value::U128(sumchain_state::compute_pool_store::domain::ASSIGNMENT as u128),
        ),
        (
            0x2513,
            "sumchain_state::compute_pool_store::domain::ENTITLEMENT",
            Value::U128(sumchain_state::compute_pool_store::domain::ENTITLEMENT as u128),
        ),
        (
            0x2514,
            "sumchain_state::education_executor::EDU_ASSESSMENT_ROOT_DOMAIN",
            Value::Bytes(sumchain_state::education_executor::EDU_ASSESSMENT_ROOT_DOMAIN.to_vec()),
        ),
        (
            0x2515,
            "sumchain_state::education_executor::EDU_CATALOG_BY_CODE_DOMAIN",
            Value::Bytes(sumchain_state::education_executor::EDU_CATALOG_BY_CODE_DOMAIN.to_vec()),
        ),
        (
            0x2516,
            "sumchain_state::education_executor::EDU_CONTENT_ROOT_DOMAIN",
            Value::Bytes(sumchain_state::education_executor::EDU_CONTENT_ROOT_DOMAIN.to_vec()),
        ),
        (
            0x2517,
            "sumchain_state::education_executor::EDU_ENROLLMENT_ROOT_DOMAIN",
            Value::Bytes(sumchain_state::education_executor::EDU_ENROLLMENT_ROOT_DOMAIN.to_vec()),
        ),
        (
            0x2518,
            "sumchain_state::UNNAMED_POLICY_ID",
            Value::Bytes(sumchain_state::UNNAMED_POLICY_ID.to_vec()),
        ),
        (
            0x2519,
            "sumchain_state::messaging_executor::MESSAGING_DAY_SECONDS",
            Value::U128(sumchain_state::messaging_executor::MESSAGING_DAY_SECONDS as u128),
        ),
        (
            0x251a,
            "sumchain_state::messaging_executor::PENDING_PAYMENT_EXPIRY",
            Value::U128(sumchain_state::messaging_executor::PENDING_PAYMENT_EXPIRY as u128),
        ),
        (
            0x251b,
            "sumchain_state::messaging_executor::SPAM_REPORT_SCORE_INCREMENT",
            Value::U128(sumchain_state::messaging_executor::SPAM_REPORT_SCORE_INCREMENT as u128),
        ),
        (
            0x251c,
            "sumchain_state::messaging_executor::STAKED_SENDER_QUOTA_MULTIPLIER",
            Value::U128(sumchain_state::messaging_executor::STAKED_SENDER_QUOTA_MULTIPLIER as u128),
        ),
        (
            0x251d,
            "sumchain_state::messaging_view::DEFAULT_SPONSORSHIP_ENABLED",
            Value::Bool(sumchain_state::messaging_view::DEFAULT_SPONSORSHIP_ENABLED),
        ),
        (
            0x251e,
            "sumchain_state::schema_validator::PHONE_LIKE_DIGIT_COUNT",
            Value::U128(sumchain_state::schema_validator::PHONE_LIKE_DIGIT_COUNT as u128),
        ),
        (
            0x251f,
            "sumchain_state::schema_validator::STORAGE_HINT_PII_PATTERNS",
            Value::List(
                sumchain_state::schema_validator::STORAGE_HINT_PII_PATTERNS
                    .iter()
                    .map(|s| s.as_bytes().to_vec())
                    .collect(),
            ),
        ),
        (
            0x2520,
            "sumchain_state::staking_executor::MAX_VALIDATOR_METADATA_BYTES",
            Value::U128(sumchain_state::staking_executor::MAX_VALIDATOR_METADATA_BYTES as u128),
        ),
        (
            0x2521,
            "sumchain_state::storage_metadata::POR_SCHEDULE_CHUNK_TAG",
            Value::Bytes(sumchain_state::storage_metadata::POR_SCHEDULE_CHUNK_TAG.to_vec()),
        ),
        (
            0x2522,
            "sumchain_state::storage_metadata::POR_SCHEDULE_FILE_TAG",
            Value::Bytes(sumchain_state::storage_metadata::POR_SCHEDULE_FILE_TAG.to_vec()),
        ),
        (
            0x2523,
            "sumchain_state::storage_metadata::POR_SCHEDULE_PICK_TAG",
            Value::Bytes(sumchain_state::storage_metadata::POR_SCHEDULE_PICK_TAG.to_vec()),
        ),
        (
            0x2524,
            "sumchain_state::storage_metadata::POR_SCHEDULE_SEED_DOMAIN",
            Value::Bytes(sumchain_state::storage_metadata::POR_SCHEDULE_SEED_DOMAIN.to_vec()),
        ),
        (
            0x2525,
            "sumchain_state::storage_metadata::STORAGE_CHALLENGE_SEED_DOMAIN",
            Value::Bytes(sumchain_state::storage_metadata::STORAGE_CHALLENGE_SEED_DOMAIN.to_vec()),
        ),
        (
            0x2526,
            "sumchain_state::supply::SUPPLY_STATE_DIGEST_DOMAIN",
            Value::Bytes(sumchain_state::supply::SUPPLY_STATE_DIGEST_DOMAIN.to_vec()),
        ),
        (
            0x2527,
            "sumchain_state::token_executor::MAX_TOKEN_DECIMALS",
            Value::U128(sumchain_state::token_executor::MAX_TOKEN_DECIMALS as u128),
        ),
        (
            0x2528,
            "sumchain_state::token_executor::MAX_TOKEN_NAME_BYTES",
            Value::U128(sumchain_state::token_executor::MAX_TOKEN_NAME_BYTES as u128),
        ),
        (
            0x2529,
            "sumchain_state::token_executor::MAX_TOKEN_SYMBOL_BYTES",
            Value::U128(sumchain_state::token_executor::MAX_TOKEN_SYMBOL_BYTES as u128),
        ),
        (
            0x2600,
            "sumchain_nft::collection::MAX_ROYALTY_BPS",
            Value::U128(sumchain_nft::collection::MAX_ROYALTY_BPS as u128),
        ),
        (
            0x2700,
            "sumc_runtime::gas::GasCosts::default().call_base",
            Value::U128(gas.call_base as u128),
        ),
        (
            0x2701,
            "sumc_runtime::gas::GasCosts::default().deploy_base",
            Value::U128(gas.deploy_base as u128),
        ),
        (
            0x2702,
            "sumc_runtime::gas::GasCosts::default().wasm_instruction",
            Value::U128(gas.wasm_instruction as u128),
        ),
        (
            0x2703,
            "sumc_runtime::gas::GasCosts::default().memory_page",
            Value::U128(gas.memory_page as u128),
        ),
        (
            0x2704,
            "sumc_runtime::gas::GasCosts::default().storage_read_base",
            Value::U128(gas.storage_read_base as u128),
        ),
        (
            0x2705,
            "sumc_runtime::gas::GasCosts::default().storage_read_per_byte",
            Value::U128(gas.storage_read_per_byte as u128),
        ),
        (
            0x2706,
            "sumc_runtime::gas::GasCosts::default().storage_write_base",
            Value::U128(gas.storage_write_base as u128),
        ),
        (
            0x2707,
            "sumc_runtime::gas::GasCosts::default().storage_write_per_byte",
            Value::U128(gas.storage_write_per_byte as u128),
        ),
        (
            0x2708,
            "sumc_runtime::gas::GasCosts::default().storage_delete",
            Value::U128(gas.storage_delete as u128),
        ),
        (
            0x2709,
            "sumc_runtime::gas::GasCosts::default().blake3_base",
            Value::U128(gas.blake3_base as u128),
        ),
        (
            0x270a,
            "sumc_runtime::gas::GasCosts::default().blake3_per_byte",
            Value::U128(gas.blake3_per_byte as u128),
        ),
        (
            0x270b,
            "sumc_runtime::gas::GasCosts::default().ed25519_verify",
            Value::U128(gas.ed25519_verify as u128),
        ),
        (
            0x270c,
            "sumc_runtime::gas::GasCosts::default().secp256k1_verify",
            Value::U128(gas.secp256k1_verify as u128),
        ),
        (
            0x270d,
            "sumc_runtime::gas::GasCosts::default().cross_call_base",
            Value::U128(gas.cross_call_base as u128),
        ),
        (
            0x270e,
            "sumc_runtime::gas::GasCosts::default().event_base",
            Value::U128(gas.event_base as u128),
        ),
        (
            0x270f,
            "sumc_runtime::gas::GasCosts::default().event_per_byte",
            Value::U128(gas.event_per_byte as u128),
        ),
        (
            0x2710,
            "sumc_runtime::gas::GasCosts::default().log_base",
            Value::U128(gas.log_base as u128),
        ),
        (
            0x2711,
            "sumc_runtime::gas::GasCosts::default().log_per_byte",
            Value::U128(gas.log_per_byte as u128),
        ),
        (
            0x2712,
            "sumc_runtime::gas::GasCosts::default().transfer",
            Value::U128(gas.transfer as u128),
        ),
        (
            0x2713,
            "sumc_runtime::ENGINE_IDENTITY",
            Value::Bytes(sumc_runtime::ENGINE_IDENTITY.as_bytes().to_vec()),
        ),
        (
            0x2714,
            "sumc_runtime::types::MAX_CODE_SIZE",
            Value::U128(sumc_runtime::types::MAX_CODE_SIZE as u128),
        ),
        (
            0x2715,
            "sumc_runtime::types::MAX_CALL_DEPTH",
            Value::U128(sumc_runtime::types::MAX_CALL_DEPTH as u128),
        ),
        (
            0x2800,
            "sumchain_beacon_crypto::bls::THRESHOLD_T",
            Value::U128(sumchain_beacon_crypto::bls::THRESHOLD_T as u128),
        ),
        (
            0x2801,
            "sumchain_beacon_crypto::bls::DST_SIG",
            Value::Bytes(sumchain_beacon_crypto::bls::DST_SIG.to_vec()),
        ),
        (
            0x2802,
            "sumchain_beacon_crypto::bls::DST_POP",
            Value::Bytes(sumchain_beacon_crypto::bls::DST_POP.to_vec()),
        ),
        (
            0x2803,
            "sumchain_beacon_crypto::bls::DST_DLEQ",
            Value::Bytes(sumchain_beacon_crypto::bls::DST_DLEQ.to_vec()),
        ),
        (
            0x2804,
            "sumchain_beacon_crypto::ecies::ECIES_CTX_DST",
            Value::Bytes(sumchain_beacon_crypto::ecies::ECIES_CTX_DST.to_vec()),
        ),
        (
            0x2805,
            "sumchain_beacon_crypto::ecies::ECIES_HKDF_SALT",
            Value::Bytes(sumchain_beacon_crypto::ecies::ECIES_HKDF_SALT.to_vec()),
        ),
        (
            0x2806,
            "sumchain_beacon_crypto::ecies::ECIES_AEAD_KEY_LABEL",
            Value::Bytes(sumchain_beacon_crypto::ecies::ECIES_AEAD_KEY_LABEL.to_vec()),
        ),
        (
            0x2807,
            "sumchain_beacon_crypto::ecies::ECIES_AEAD_NONCE_LABEL",
            Value::Bytes(sumchain_beacon_crypto::ecies::ECIES_AEAD_NONCE_LABEL.to_vec()),
        ),
        (
            0x2880,
            "sumchain_beacon_runtime::wire::BEACON_GENESIS_DST",
            Value::Bytes(sumchain_beacon_runtime::wire::BEACON_GENESIS_DST.to_vec()),
        ),
        (
            0x2881,
            "sumchain_beacon_runtime::wire::BEACON_ROUND_DST",
            Value::Bytes(sumchain_beacon_runtime::wire::BEACON_ROUND_DST.to_vec()),
        ),
        (
            0x2882,
            "sumchain_beacon_runtime::wire::BEACON_OUT_DST",
            Value::Bytes(sumchain_beacon_runtime::wire::BEACON_OUT_DST.to_vec()),
        ),
    ]
}
