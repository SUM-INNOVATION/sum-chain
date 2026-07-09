//! # SUM Chain Genesis
//!
//! Genesis configuration for initializing a new SUM Chain network.
//! Includes chain parameters, initial validators, and prefunded accounts.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::Path;

use sumchain_crypto::PublicKey;
use sumchain_primitives::{
    Address, Balance, Block, ChainId, GovernanceParams, Hash, StakingParams, Timestamp,
    DEFAULT_DAILY_QUOTA, DEFAULT_MAX_MESSAGE_SIZE, DEFAULT_MIN_TRUST_STAKE,
};
use thiserror::Error;

/// Genesis configuration errors
#[derive(Debug, Error)]
pub enum GenesisError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON parse error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("Invalid validator public key: {0}")]
    InvalidValidator(String),

    #[error("Invalid address: {0}")]
    InvalidAddress(String),

    #[error("No validators specified")]
    NoValidators,

    #[error("Genesis already initialized")]
    AlreadyInitialized,
}

pub type Result<T> = std::result::Result<T, GenesisError>;

/// Genesis JSON adapter for the one remaining human-edited address in the
/// activation params — `governance.treasury`. It is written as a **base58**
/// string (consistent with `validators` and `alloc` keys), not a raw byte array.
///
/// This is JSON-only and does not change `Address`'s global serde or any
/// bincode/wire/storage encoding; the runtime `GovernanceParams` keeps using
/// [`Address`]. A legacy `[u8; 20]` array is still accepted on input for
/// backward compatibility; serialization always emits base58.
mod addr_json {
    use super::{Address, GovernanceParams};
    use serde::de::{self, SeqAccess, Visitor};
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use std::fmt;

    /// (De)serializes an [`Address`] as a base58 string; accepts a legacy 20-byte
    /// array on input.
    pub(super) struct Base58Address(pub Address);

    impl Serialize for Base58Address {
        fn serialize<S: Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
            s.serialize_str(&self.0.to_base58())
        }
    }

    impl<'de> Deserialize<'de> for Base58Address {
        fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
            struct V;
            impl<'de> Visitor<'de> for V {
                type Value = Address;
                fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                    f.write_str("a base58 address string or a 20-byte array")
                }
                fn visit_str<E: de::Error>(self, v: &str) -> std::result::Result<Address, E> {
                    Address::from_base58(v)
                        .map_err(|e| de::Error::custom(format!("invalid base58 address: {e}")))
                }
                fn visit_seq<A: SeqAccess<'de>>(
                    self,
                    mut seq: A,
                ) -> std::result::Result<Address, A::Error> {
                    let mut bytes = [0u8; 20];
                    for (i, b) in bytes.iter_mut().enumerate() {
                        *b = seq
                            .next_element()?
                            .ok_or_else(|| de::Error::invalid_length(i, &"20 bytes"))?;
                    }
                    if seq.next_element::<u8>()?.is_some() {
                        return Err(de::Error::invalid_length(21, &"exactly 20 bytes"));
                    }
                    Ok(Address::new(bytes))
                }
            }
            d.deserialize_any(V).map(Base58Address)
        }
    }

    /// JSON proxy for [`GovernanceParams`]: base58 `treasury`, plain numeric
    /// threshold/tally params.
    #[derive(Serialize, Deserialize)]
    struct GovernanceParamsJson {
        validator_authority_threshold_bps: u16,
        quorum_bps: u16,
        pass_threshold_bps: u16,
        voting_period_blocks: u64,
        max_snapshot_holders: u32,
        #[serde(default)]
        proposal_bond: u128,
        #[serde(default)]
        treasury: Option<Base58Address>,
        #[serde(default)]
        min_koppa_for_eligibility: u128,
    }

    impl From<&GovernanceParams> for GovernanceParamsJson {
        fn from(g: &GovernanceParams) -> Self {
            Self {
                validator_authority_threshold_bps: g.validator_authority_threshold_bps,
                quorum_bps: g.quorum_bps,
                pass_threshold_bps: g.pass_threshold_bps,
                voting_period_blocks: g.voting_period_blocks,
                max_snapshot_holders: g.max_snapshot_holders,
                proposal_bond: g.proposal_bond,
                treasury: g.treasury.map(Base58Address),
                min_koppa_for_eligibility: g.min_koppa_for_eligibility,
            }
        }
    }

    impl From<GovernanceParamsJson> for GovernanceParams {
        fn from(j: GovernanceParamsJson) -> Self {
            GovernanceParams {
                validator_authority_threshold_bps: j.validator_authority_threshold_bps,
                quorum_bps: j.quorum_bps,
                pass_threshold_bps: j.pass_threshold_bps,
                voting_period_blocks: j.voting_period_blocks,
                max_snapshot_holders: j.max_snapshot_holders,
                proposal_bond: j.proposal_bond,
                treasury: j.treasury.map(|b| b.0),
                min_koppa_for_eligibility: j.min_koppa_for_eligibility,
            }
        }
    }

    /// `#[serde(with = "addr_json::opt_governance")]` for `Option<GovernanceParams>`.
    pub(super) mod opt_governance {
        use super::{Deserialize, Deserializer, GovernanceParams, GovernanceParamsJson, Serializer};
        pub fn serialize<S: Serializer>(
            v: &Option<GovernanceParams>,
            s: S,
        ) -> std::result::Result<S::Ok, S::Error> {
            match v {
                Some(g) => s.serialize_some(&GovernanceParamsJson::from(g)),
                None => s.serialize_none(),
            }
        }
        pub fn deserialize<'de, D: Deserializer<'de>>(
            d: D,
        ) -> std::result::Result<Option<GovernanceParams>, D::Error> {
            Ok(Option::<GovernanceParamsJson>::deserialize(d)?.map(Into::into))
        }
    }
}

/// Chain parameters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainParams {
    /// Target block time in milliseconds
    pub block_time_ms: u64,
    /// Maximum block size in bytes
    pub max_block_bytes: u64,
    /// Maximum transactions per block
    pub max_txs_per_block: u32,
    /// Minimum transaction fee
    pub min_fee: Balance,
    /// Finality depth - blocks are considered final after this many confirmations
    /// For PoA, this should be at least 2/3 of validator count
    #[serde(default = "default_finality_depth")]
    pub finality_depth: u64,
    /// Storage fee per byte for NFT metadata (prevents state bloat attacks)
    #[serde(default = "default_storage_fee_per_byte")]
    pub storage_fee_per_byte: Balance,
    /// Maximum metadata size in bytes for NFT tokens
    #[serde(default = "default_max_metadata_bytes")]
    pub max_metadata_bytes: u64,
    /// Minimum gas limit for contract transactions
    #[serde(default = "default_min_contract_gas")]
    pub min_contract_gas: u64,
    /// Maximum gas limit for contract transactions
    #[serde(default = "default_max_contract_gas")]
    pub max_contract_gas: u64,
    /// Staking parameters (optional - uses defaults if not specified)
    #[serde(default)]
    pub staking: Option<StakingParams>,
    /// SRC-201 Messaging parameters (optional - uses defaults if not specified)
    #[serde(default)]
    pub messaging: Option<MessagingParams>,
    /// SRC-80X/81X DocClass parameters (optional - uses defaults if not specified)
    #[serde(default)]
    pub docclass: Option<DocClassParams>,
    // ─── SNIP V2 (Phase 1) parameters ──────────────────────────────────────
    /// Maximum bincode-serialized size of a V2 file's `access_list` (bytes).
    /// Plan v3.1 §3.4 — 200 Private entries = ~22 KB, so the cap drives the
    /// effective recipient limit (~148 Private at default).
    #[serde(default = "default_max_access_list_bytes")]
    pub max_access_list_bytes: u64,
    /// Grace period after `ActivateFileV2` (in blocks) during which PoR
    /// challenges are suppressed for that file. Plan §3.5, Ask 12.
    #[serde(default = "default_activation_grace_blocks")]
    pub activation_grace_blocks: u64,
    /// Percentage (0–100) of `fee_pool` retained on `AbandonFileV2`. The
    /// remainder is refunded to the owner. Plan §3.5, Ask 13.
    #[serde(default = "default_abandonment_fee_percent")]
    pub abandonment_fee_percent: u64,
    /// Cap on `chunk_count` per V2 file. Bounds the per-`(file, archive)`
    /// `AcceptAssignmentV2` bitmap row size at `ceil(N/8)` bytes — at the
    /// default of 1,048,576 chunks that's 128 KB worst-case per archive.
    /// Plan v3.2 §3.4.
    #[serde(default = "default_max_chunk_count_per_file")]
    pub max_chunk_count_per_file: u32,
    /// Cap on `chunk_indices.len()` in a single `AcceptAssignmentV2` tx.
    /// Bounds tx size; archives with larger assignments split across multiple
    /// txs (the bitmap OR-merge means partial submissions accumulate cleanly).
    /// Plan v3.2 §3.4.
    #[serde(default = "default_max_chunk_indices_per_tx")]
    pub max_chunk_indices_per_tx: u32,
    /// Number of archive nodes assigned to each chunk by the deterministic
    /// rendezvous-hash assignment function. The actual replication factor
    /// is `min(assignment_replication_factor, snapshot.len())`, so genesis
    /// chains with fewer archives still produce coherent assignments.
    /// Plan v3.2 §3.6.
    #[serde(default = "default_assignment_replication_factor")]
    pub assignment_replication_factor: u32,
    /// Block height at which V2 storage operations (`NodeRegistryV2`,
    /// `StorageMetadataV2`) become valid. `None` (the default) means V2 is
    /// disabled entirely — every V2 tx receipts as `TxStatus::Failed(40)`
    /// without consuming the sender's fee.
    ///
    /// Production safety: `#[serde(default)]` resolves a missing field to
    /// `None`, so an existing mainnet `genesis.json` upgraded to a V2-aware
    /// binary stays V2-disabled until the operator explicitly sets a
    /// future activation height.
    ///
    /// To enable V2 from genesis (dev / SNIP local-mirror): set to `Some(0)`.
    /// To activate at a future block on a live chain: set to `Some(target_height)`.
    #[serde(default)]
    pub v2_enabled_from_height: Option<u64>,

    /// Block height at which the OmniNode `InferenceAttestation` subprotocol
    /// activates. `None` = disabled forever; `Some(h)` = ops from block `h`
    /// onward. Mirrors the SNIP V2 activation pattern above.
    ///
    /// Production safety: `#[serde(default)]` resolves a missing field to
    /// `None`, so an existing mainnet `genesis.json` upgraded to an
    /// OmniNode-aware binary stays disabled until the operator explicitly
    /// sets a future activation height.
    ///
    /// Dev / OmniNode Stage 5: set to `Some(0)` to activate from genesis.
    #[serde(default)]
    pub omninode_enabled_from_height: Option<u64>,

    /// Sponsored inference attestation (v2 envelope) activation gate (issue #79).
    /// `None` (default) = the sponsored/relayed submission path is dormant: a
    /// `TxPayload::InferenceAttestationV2` is rejected free (`Failed(54)`, no fee).
    /// v1 attestation (`sender == verifier`) is unaffected — it is governed only by
    /// `omninode_enabled_from_height`. Sponsored attestation changes who *pays* to
    /// submit, not who made the attestation. `#[serde(default)]` keeps existing
    /// `genesis.json` dormant.
    #[serde(default)]
    pub omninode_sponsored_attestation_enabled_from_height: Option<u64>,

    /// Block height at which the SRC-817/818 Education-LMS suite
    /// activates. `None` = disabled forever; `Some(h)` = education txs
    /// executable from block `h` onward. Mirrors the OmniNode/SNIP V2
    /// activation pattern.
    ///
    /// Production safety: `#[serde(default)]` resolves a missing field
    /// to `None`, so an existing mainnet `genesis.json` upgraded to an
    /// Education-aware binary stays disabled until the operator
    /// explicitly sets a future activation height.
    ///
    /// Dev: set to `Some(0)` to activate from genesis.
    #[serde(default)]
    pub education_enabled_from_height: Option<u64>,

    /// Block height at which production-capable smart contracts activate
    /// (persistent storage, reorg-reversible contract state, root-committed).
    /// `None` = disabled forever; `Some(h)` = `ContractDeploy`/`ContractCall`
    /// execute from block `h` onward. Below the gate they are rejected free
    /// (no fee, no state). Mirrors the V2/OmniNode/Education activation pattern.
    ///
    /// Production safety: `#[serde(default)]` resolves a missing field to
    /// `None`, so an existing mainnet `genesis.json` upgraded to a
    /// contract-aware binary stays disabled until operators coordinate an
    /// explicit activation height. Activation changes the block state-root
    /// formula, so it is a consensus-breaking, validator-coordinated upgrade.
    ///
    /// Dev: set to `Some(0)` to activate from genesis.
    #[serde(default)]
    pub contracts_enabled_from_height: Option<u64>,

    /// Block height at which on-chain governance v1 activates. `None` =
    /// disabled forever; `Some(h)` = `TxPayload::Governance` operations
    /// execute from block `h` onward. Below the gate they are rejected free
    /// (no fee, no state). Mirrors the V2/OmniNode/Education/Contracts
    /// activation pattern.
    ///
    /// Production safety: `#[serde(default)]` resolves a missing field to
    /// `None`, so an existing mainnet `genesis.json` upgraded to a
    /// governance-aware binary stays dormant until operators coordinate an
    /// explicit activation height (a consensus-relevant, validator-coordinated
    /// upgrade). See docs/specs/GOVERNANCE-V1.md.
    ///
    /// Dev: set to `Some(0)` to activate from genesis.
    #[serde(default)]
    pub governance_enabled_from_height: Option<u64>,

    /// On-chain governance v1 network parameters (validator-quorum authority +
    /// tally params + snapshot bound). `None` = not configured (governance
    /// operations are rejected even above the height gate). No mainnet defaults;
    /// set only for a coordinated activation or in tests. See
    /// docs/specs/GOVERNANCE-V1.md.
    ///
    /// `treasury` is a base58 address string in `genesis.json` (see
    /// [`addr_json`]); the runtime struct keeps using [`Address`]. There is no
    /// council address — validator-gated actions use validator-quorum approvals.
    #[serde(default, with = "addr_json::opt_governance")]
    pub governance: Option<GovernanceParams>,

    /// Block height at which archive-node stake withdrawal (issue #20) activates.
    /// `None` = disabled forever; `Some(h)` = `BeginUnstake` / `WithdrawUnbonded`
    /// execute from block `h` onward. Below the gate they are rejected free (no
    /// fee, no state). Mirrors the V2/OmniNode/Education/Contracts/Governance
    /// activation pattern; SNIP V2 is already active on mainnet, so archive
    /// withdrawal ships behind its own coordinated gate.
    ///
    /// Production safety: `#[serde(default)]` resolves a missing field to `None`,
    /// so an existing mainnet `genesis.json` stays dormant until operators
    /// coordinate an explicit activation height.
    #[serde(default)]
    pub archive_unbonding_enabled_from_height: Option<u64>,

    /// Number of blocks an archive node's stake stays locked after `BeginUnstake`
    /// before `WithdrawUnbonded` is allowed (issue #20). Only consulted once
    /// `archive_unbonding_enabled_from_height` is set. Distinct from validator
    /// staking's `unbonding_period`.
    #[serde(default = "default_archive_unbonding_period_blocks")]
    pub archive_unbonding_period_blocks: u64,

    /// Archive-node chunk reassignment activation gate (issue #62). `None` = the
    /// reassignment subprotocol is dormant: `ReassignChunksV2` and post-activation
    /// (Active-file) `AcceptAssignmentV2` re-attestation are rejected. Set to a
    /// height via a coordinated validator upgrade to activate. `#[serde(default)]`
    /// keeps existing mainnet `genesis.json` dormant.
    #[serde(default)]
    pub archive_reassignment_enabled_from_height: Option<u64>,

    /// Assignment-aware PoR challenge targeting activation gate (issue #97,
    /// Phase 1). `None` (default) = legacy targeting: a storage challenge's
    /// `target_node` is drawn from *all* globally-active archives, which can
    /// challenge/slash a bystander not assigned to the challenged `(file,
    /// chunk)`. When `Some(h)` and `block_height >= h`, the same file/chunk
    /// candidate is selected as before, but the target is drawn only from the
    /// archives assigned to that chunk (under the file's latest assignment
    /// epoch) that are currently Active; if none, the challenge is skipped for
    /// that interval. Distinct from
    /// `archive_reassignment_enabled_from_height` (#62) and from the Phase 2
    /// bounded scheduler gate (#100). `#[serde(default)]` keeps existing
    /// `genesis.json` on legacy behavior.
    #[serde(default)]
    pub por_assignment_targeting_enabled_from_height: Option<u64>,

    /// Service-grant claiming gate (800B supply correction). `None` (default) =
    /// all `Supply` transactions (grant claim / unlock) are rejected free
    /// (`Failed(380)`, no fee, no state). The one-time supply correction and
    /// earned-credit/milestone ACCRUAL are independent of this gate (they key
    /// off the persisted correction marker); only CLAIMING is gated. Set via a
    /// coordinated upgrade once final pool/cohort numbers are ratified.
    #[serde(default)]
    pub service_grants_enabled_from_height: Option<u64>,

    /// Monetary-policy governance gate. `None` (default) = `ReserveRelease*`
    /// and `MonetaryPolicyMint` governance proposals cannot be created or
    /// executed (fail-closed). When set, those classes remain executable ONLY
    /// through NativeEligibility (native Koppa consensus) governance at the
    /// hardcoded 6667 bps threshold — never validator-quorum, never SRC-20/
    /// equity governance.
    #[serde(default)]
    pub monetary_policy_enabled_from_height: Option<u64>,

    /// Validator inactivity lifecycle parameters (DORMANT — documented design).
    /// Automatic missed-block tracking is NOT persisted by consensus today
    /// (`record_missed_block` has no callers), so automatic jailing/forfeiture
    /// CANNOT be implemented honestly yet and remains fail-closed. These
    /// parameters ship so the schedule is chain-visible and a future PR that
    /// adds real signing-info tracking can activate enforcement without a
    /// params change. Window ~7 days at 3s blocks.
    #[serde(default = "default_validator_inactivity_window_blocks")]
    pub validator_inactivity_window_blocks: u64,
    /// Missed-block warning threshold (bps of the window). Dormant; see above.
    #[serde(default = "default_validator_inactivity_warn_bps")]
    pub validator_inactivity_warn_bps: u16,
    /// Missed-block inactive threshold (bps). Dormant; see above.
    #[serde(default = "default_validator_inactivity_inactive_bps")]
    pub validator_inactivity_inactive_bps: u16,
    /// Missed-block removal/jail threshold (bps). Dormant; see above.
    #[serde(default = "default_validator_inactivity_removal_bps")]
    pub validator_inactivity_removal_bps: u16,
    /// Unbond/reclaim delay after removal (blocks). Dormant; see above.
    #[serde(default = "default_validator_reclaim_delay_blocks")]
    pub validator_reclaim_delay_blocks: u64,

    /// Bounded assignment-aware PoR *scheduler* activation gate (issue #100,
    /// Phase 2). `None` (default) = the scheduler is dormant and challenge
    /// generation is exactly the post-#101 single-challenge path. When `Some(h)`
    /// and `block_height >= h`, each challenge interval emits a bounded,
    /// deterministic *set* of assignment-aware challenges instead of one.
    /// Distinct from `por_assignment_targeting_enabled_from_height` (#97, Phase
    /// 1) — the two gates are never shared. `#[serde(default)]` keeps existing
    /// `genesis.json` on the pre-scheduler path.
    #[serde(default)]
    pub assignment_aware_por_scheduler_enabled_from_height: Option<u64>,

    /// Hard cap on challenges emitted per interval by the #100 scheduler — the
    /// primary per-block cost bound. Only consulted when the scheduler gate is
    /// open.
    #[serde(default = "default_max_assignment_aware_challenges_per_block")]
    pub max_assignment_aware_challenges_per_block: u32,

    /// Cap on distinct files sampled per interval by the #100 scheduler. Only
    /// consulted when the scheduler gate is open.
    #[serde(default = "default_max_files_sampled_per_interval")]
    pub max_files_sampled_per_interval: u32,

    /// Cap on chunk indices sampled per file per interval by the #100 scheduler.
    /// Only consulted when the scheduler gate is open.
    #[serde(default = "default_max_chunks_sampled_per_file")]
    pub max_chunks_sampled_per_file: u32,

    /// OmniNode Inference Settlement activation gate (issue #61). `None` = the
    /// settlement subprotocol is dormant; all settlement ops are rejected free
    /// (`Failed(350)`, no fee). Separate from `omninode_enabled_from_height` —
    /// attestation recording is unaffected either way. `#[serde(default)]` keeps
    /// existing mainnet `genesis.json` dormant.
    #[serde(default)]
    pub inference_settlement_enabled_from_height: Option<u64>,

    /// Upper bound on a session's per-session `dispute_window_blocks` (issue #61).
    /// Only consulted once settlement is enabled.
    #[serde(default = "default_inference_settlement_max_dispute_window_blocks")]
    pub inference_settlement_max_dispute_window_blocks: u64,

    /// Upper bound on a session's lifetime (`expires_at_height - created_at`) so
    /// escrow can't be locked indefinitely (issue #61). Only consulted once
    /// settlement is enabled.
    #[serde(default = "default_inference_settlement_max_session_duration_blocks")]
    pub inference_settlement_max_session_duration_blocks: u64,

    /// Validator-quorum threshold (basis points of the active PoA validator set)
    /// for inference-settlement dispute resolution (issue #61). `None` (default)
    /// means disputes are unavailable — `OpenDispute`/`ResolveDispute` are
    /// rejected. When `Some(bps)`, `ResolveDispute` requires validator approvals
    /// reaching `ceil(active_count * bps / 10000)` of the active validator set;
    /// there is no personal resolver address. `bps` must be `1..=10000`.
    #[serde(default)]
    pub inference_settlement_dispute_threshold_bps: Option<u16>,

    /// Consistency/plurality settlement mode activation gate (issue #77). `None`
    /// (default) = consistency mode is dormant: an `OpenSession` that requests a
    /// consistency config is rejected `Failed(361)`, and existing single-verifier
    /// v1 claims are unaffected. When `Some(h)` and `block_height >= h`, sessions
    /// may opt into a consistency rule and matured claims are evaluated against it.
    /// Independent of `inference_settlement_enabled_from_height` — consistency is a
    /// stricter claim rule layered on top of enabled settlement. `#[serde(default)]`
    /// keeps existing `genesis.json` dormant.
    #[serde(default)]
    pub inference_settlement_consistency_enabled_from_height: Option<u64>,

    /// Verifier bonding + slashing activation gate (issue #78). `None` (default) =
    /// bonding is dormant: bond-registry operations are rejected free (`Failed(364)`,
    /// no fee) and a session that requests a `bond_requirement` fails `Failed(364)`.
    /// Sessions without a bond requirement are unaffected. When `Some(h)` and
    /// `block_height >= h`, verifiers may register bonds and bond-required sessions
    /// enforce/slash. Independent of `inference_settlement_enabled_from_height`
    /// (bonding layers on enabled settlement). `#[serde(default)]` keeps existing
    /// `genesis.json` dormant.
    #[serde(default)]
    pub inference_verifier_bonding_enabled_from_height: Option<u64>,

    /// Unbonding delay (blocks) between `BeginVerifierUnbond` and a permitted
    /// `WithdrawVerifierBond` (issue #78). Only consulted once bonding is enabled.
    #[serde(default = "default_inference_verifier_unbonding_period_blocks")]
    pub inference_verifier_unbonding_period_blocks: u64,
}

fn default_inference_verifier_unbonding_period_blocks() -> u64 {
    201_600 // ~7 days at 3s blocks — matches the archive-node unbonding default.
}

fn default_inference_settlement_max_dispute_window_blocks() -> u64 {
    201_600 // ~7 days at 3s blocks — a generous ceiling; sessions pick smaller.
}

fn default_inference_settlement_max_session_duration_blocks() -> u64 {
    2_592_000 // ~90 days at 3s blocks — ceiling on escrow lock-up.
}

fn default_archive_unbonding_period_blocks() -> u64 {
    201_600 // ~7 days at 3s blocks; a safe non-trivial unbonding delay
}

fn default_finality_depth() -> u64 {
    3 // Default: 3 blocks for finality
}

fn default_storage_fee_per_byte() -> Balance {
    100 // 100 base units per byte (~0.0000001 Koppa per byte)
}

fn default_max_metadata_bytes() -> u64 {
    16384 // 16 KB max metadata size
}

fn default_min_contract_gas() -> u64 {
    21000 // Similar to Ethereum's base gas
}

fn default_max_contract_gas() -> u64 {
    10_000_000 // 10M gas limit per transaction
}

fn default_max_access_list_bytes() -> u64 {
    16_384 // matches max_metadata_bytes; ~148 Private recipients per file
}

fn default_activation_grace_blocks() -> u64 {
    50 // ~100s at 2s blocks; SNIP can request 150 if 5min wall-clock is needed
}

fn default_abandonment_fee_percent() -> u64 {
    10 // 10% of fee_pool retained on abandonment
}

fn default_max_chunk_count_per_file() -> u32 {
    1_048_576 // 1 TB at CHUNK_SIZE = 1 MB; 128 KB bitmap row max
}

fn default_max_chunk_indices_per_tx() -> u32 {
    65_536 // bounds AcceptAssignmentV2 tx size; multi-tx OR-merge handles larger sets
}

fn default_assignment_replication_factor() -> u32 {
    3 // baseline R=3; effective R is min(this, active_snapshot_size)
}

fn default_max_assignment_aware_challenges_per_block() -> u32 {
    16 // issue #100: bounded per-interval challenge budget
}

fn default_max_files_sampled_per_interval() -> u32 {
    8 // issue #100: files inspected per interval
}

fn default_max_chunks_sampled_per_file() -> u32 {
    4 // issue #100: chunks sampled per file per interval
}

fn default_validator_inactivity_window_blocks() -> u64 {
    20_160 // ~7 days of proposer slots at target cadence (dormant design param)
}
fn default_validator_inactivity_warn_bps() -> u16 {
    1_000 // 10% missed (dormant)
}
fn default_validator_inactivity_inactive_bps() -> u16 {
    3_300 // 33% missed (dormant)
}
fn default_validator_inactivity_removal_bps() -> u16 {
    5_000 // 50% missed (dormant)
}
fn default_validator_reclaim_delay_blocks() -> u64 {
    201_600 // ~7 days at 3s blocks (dormant)
}

/// SRC-201 Messaging Parameters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessagingParams {
    /// Daily free message quota per address
    #[serde(default = "default_msg_daily_quota")]
    pub daily_quota: u32,
    /// Maximum message size in bytes
    #[serde(default = "default_msg_max_size")]
    pub max_message_size: u32,
    /// Minimum stake for trusted sender tier
    #[serde(default = "default_msg_min_stake")]
    pub min_trust_stake: Balance,
    /// Enable gas sponsorship for messages
    #[serde(default = "default_sponsorship_enabled")]
    pub sponsorship_enabled: bool,
    /// Initial sponsorship fund (Koppa)
    #[serde(default)]
    pub initial_sponsorship_fund: Balance,
    /// Registry admin address (optional)
    #[serde(default)]
    pub registry_admin: Option<String>,
    /// Spam score threshold for restrictions
    #[serde(default = "default_spam_threshold")]
    pub spam_threshold: u32,
    /// High spam score requiring stake
    #[serde(default = "default_high_spam_threshold")]
    pub high_spam_threshold: u32,
    /// Cooldown blocks before stake withdrawal
    #[serde(default = "default_stake_cooldown")]
    pub stake_cooldown_blocks: u64,
}

fn default_msg_daily_quota() -> u32 {
    DEFAULT_DAILY_QUOTA
}

fn default_msg_max_size() -> u32 {
    DEFAULT_MAX_MESSAGE_SIZE
}

fn default_msg_min_stake() -> Balance {
    DEFAULT_MIN_TRUST_STAKE
}

fn default_sponsorship_enabled() -> bool {
    true
}

fn default_spam_threshold() -> u32 {
    50
}

fn default_high_spam_threshold() -> u32 {
    80
}

fn default_stake_cooldown() -> u64 {
    50400 // ~7 days at 12s blocks
}

impl Default for MessagingParams {
    fn default() -> Self {
        Self {
            daily_quota: default_msg_daily_quota(),
            max_message_size: default_msg_max_size(),
            min_trust_stake: default_msg_min_stake(),
            sponsorship_enabled: default_sponsorship_enabled(),
            initial_sponsorship_fund: 0,
            registry_admin: None,
            spam_threshold: default_spam_threshold(),
            high_spam_threshold: default_high_spam_threshold(),
            stake_cooldown_blocks: default_stake_cooldown(),
        }
    }
}

/// SRC-80X/81X DocClass Parameters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DocClassParams {
    /// Minimum stake required for issuer registration
    #[serde(default = "default_docclass_min_issuer_stake")]
    pub min_issuer_stake: Balance,
    /// DocClass admin address (optional)
    #[serde(default)]
    pub admin: Option<String>,
    /// Initial registered issuers (for bootstrapping)
    #[serde(default)]
    pub initial_issuers: Vec<String>,
    /// Credential validity period limits (in seconds, 0 = no limit)
    #[serde(default)]
    pub max_credential_validity: u64,
    /// Whether to require issuer stake for registration
    #[serde(default = "default_require_issuer_stake")]
    pub require_issuer_stake: bool,
}

fn default_docclass_min_issuer_stake() -> Balance {
    1_000_000_000_000 // 1000 Koppa (10^12 base units)
}

fn default_require_issuer_stake() -> bool {
    true
}

impl Default for DocClassParams {
    fn default() -> Self {
        Self {
            min_issuer_stake: default_docclass_min_issuer_stake(),
            admin: None,
            initial_issuers: Vec::new(),
            max_credential_validity: 0, // No limit
            require_issuer_stake: default_require_issuer_stake(),
        }
    }
}

impl Default for ChainParams {
    fn default() -> Self {
        Self {
            block_time_ms: 2000,           // 2 seconds
            max_block_bytes: 1_000_000,    // 1 MB
            max_txs_per_block: 1000,
            min_fee: 1,
            finality_depth: default_finality_depth(),
            storage_fee_per_byte: default_storage_fee_per_byte(),
            max_metadata_bytes: default_max_metadata_bytes(),
            min_contract_gas: default_min_contract_gas(),
            max_contract_gas: default_max_contract_gas(),
            staking: Some(StakingParams::default()),
            messaging: Some(MessagingParams::default()),
            docclass: Some(DocClassParams::default()),
            max_access_list_bytes: default_max_access_list_bytes(),
            activation_grace_blocks: default_activation_grace_blocks(),
            abandonment_fee_percent: default_abandonment_fee_percent(),
            max_chunk_count_per_file: default_max_chunk_count_per_file(),
            max_chunk_indices_per_tx: default_max_chunk_indices_per_tx(),
            assignment_replication_factor: default_assignment_replication_factor(),
            // Production-safe default: V2 disabled. Tests and dev genesis
            // (snip-mirror, local) opt in via `with_v2_enabled()` or by
            // setting the field explicitly in their genesis JSON.
            v2_enabled_from_height: None,
            // Production-safe default: OmniNode subprotocol disabled.
            // Activation is coordinated separately, after the chain has
            // shipped Phase 2-4 of the InferenceAttestation work.
            omninode_enabled_from_height: None,
            omninode_sponsored_attestation_enabled_from_height: None,
            // Production-safe default: Education-LMS suite disabled.
            // Activation is coordinated separately, post Phase 2-6.
            education_enabled_from_height: None,
            // Production-safe default: smart contracts dormant. Activation is a
            // coordinated, consensus-breaking validator upgrade (changes the
            // state-root formula); never set in default/mainnet config.
            contracts_enabled_from_height: None,
            // Production-safe default: on-chain governance dormant. Activation
            // is a coordinated validator upgrade; never set in default/mainnet
            // config. See docs/specs/GOVERNANCE-V1.md.
            governance_enabled_from_height: None,
            // No governance parameters configured by default.
            governance: None,
            // Production-safe default: archive-node withdrawal dormant (issue
            // #20). Activation is a coordinated validator upgrade.
            archive_unbonding_enabled_from_height: None,
            archive_unbonding_period_blocks: default_archive_unbonding_period_blocks(),
            // Production-safe default: archive-node chunk reassignment dormant
            // (issue #62). Activation is a coordinated validator upgrade.
            archive_reassignment_enabled_from_height: None,
            // Production-safe default: legacy PoR challenge targeting (issue
            // #97). Activation is a coordinated validator upgrade.
            por_assignment_targeting_enabled_from_height: None,
            // Production-safe defaults: service-grant claiming and monetary-
            // policy governance dormant; validator-inactivity schedule is a
            // dormant design parameterization (no auto-tracking exists yet).
            service_grants_enabled_from_height: None,
            monetary_policy_enabled_from_height: None,
            validator_inactivity_window_blocks: default_validator_inactivity_window_blocks(),
            validator_inactivity_warn_bps: default_validator_inactivity_warn_bps(),
            validator_inactivity_inactive_bps: default_validator_inactivity_inactive_bps(),
            validator_inactivity_removal_bps: default_validator_inactivity_removal_bps(),
            validator_reclaim_delay_blocks: default_validator_reclaim_delay_blocks(),
            // Production-safe default: bounded PoR scheduler dormant (issue
            // #100). Activation is a coordinated validator upgrade.
            assignment_aware_por_scheduler_enabled_from_height: None,
            max_assignment_aware_challenges_per_block:
                default_max_assignment_aware_challenges_per_block(),
            max_files_sampled_per_interval: default_max_files_sampled_per_interval(),
            max_chunks_sampled_per_file: default_max_chunks_sampled_per_file(),
            // Production-safe default: OmniNode inference settlement dormant
            // (issue #61). Activation is a coordinated validator upgrade.
            inference_settlement_enabled_from_height: None,
            inference_settlement_max_dispute_window_blocks:
                default_inference_settlement_max_dispute_window_blocks(),
            inference_settlement_max_session_duration_blocks:
                default_inference_settlement_max_session_duration_blocks(),
            inference_settlement_dispute_threshold_bps: None,
            inference_settlement_consistency_enabled_from_height: None,
            inference_verifier_bonding_enabled_from_height: None,
            inference_verifier_unbonding_period_blocks:
                default_inference_verifier_unbonding_period_blocks(),
        }
    }
}

impl ChainParams {
    /// Convenience for tests + dev genesis JSONs where V2 should be enabled
    /// from genesis. Production chains MUST NOT use this — they should set
    /// `v2_enabled_from_height` explicitly to a chosen activation height
    /// (or leave it `None`) in their `genesis.json`.
    pub fn with_v2_enabled() -> Self {
        Self {
            v2_enabled_from_height: Some(0),
            ..Self::default()
        }
    }

    /// Convenience for tests + dev genesis where smart contracts should be
    /// enabled from genesis (also enables V2, since contract txs are V2).
    /// Production chains MUST NOT use this — set `contracts_enabled_from_height`
    /// explicitly to a coordinated activation height.
    pub fn with_contracts_enabled() -> Self {
        Self {
            v2_enabled_from_height: Some(0),
            contracts_enabled_from_height: Some(0),
            ..Self::default()
        }
    }
}

impl ChainParams {
    /// Calculate required fee for storing NFT metadata
    /// Returns base_fee + (metadata_bytes * storage_fee_per_byte)
    pub fn calculate_nft_storage_fee(&self, metadata_bytes: usize) -> Balance {
        let storage_fee = (metadata_bytes as u128).saturating_mul(self.storage_fee_per_byte);
        self.min_fee.saturating_add(storage_fee)
    }

    /// Validate metadata size against limits
    pub fn validate_metadata_size(&self, metadata_bytes: usize) -> bool {
        metadata_bytes as u64 <= self.max_metadata_bytes
    }
}

/// Genesis configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Genesis {
    /// Chain identifier
    pub chain_id: ChainId,
    /// Genesis timestamp (milliseconds since epoch)
    pub genesis_time: Timestamp,
    /// Validator public keys (base58 encoded)
    pub validators: Vec<String>,
    /// Initial account allocations (address -> balance)
    pub alloc: HashMap<String, Balance>,
    /// Chain parameters
    pub params: ChainParams,
}

impl Genesis {
    /// Create a new genesis configuration
    pub fn new(
        chain_id: ChainId,
        genesis_time: Timestamp,
        validators: Vec<String>,
        alloc: HashMap<String, Balance>,
        params: ChainParams,
    ) -> Self {
        Self {
            chain_id,
            genesis_time,
            validators,
            alloc,
            params,
        }
    }

    /// Load genesis from a JSON file
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let contents = fs::read_to_string(path)?;
        let genesis: Genesis = serde_json::from_str(&contents)?;
        genesis.validate()?;
        Ok(genesis)
    }

    /// Save genesis to a JSON file
    pub fn to_file<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let contents = serde_json::to_string_pretty(self)?;
        fs::write(path, contents)?;
        Ok(())
    }

    /// Parse from JSON string
    pub fn from_json(json: &str) -> Result<Self> {
        let genesis: Genesis = serde_json::from_str(json)?;
        genesis.validate()?;
        Ok(genesis)
    }

    /// Serialize to JSON string
    pub fn to_json(&self) -> Result<String> {
        Ok(serde_json::to_string_pretty(self)?)
    }

    /// Validate the genesis configuration
    pub fn validate(&self) -> Result<()> {
        if self.validators.is_empty() {
            return Err(GenesisError::NoValidators);
        }

        // Validate all validator public keys
        for (i, v) in self.validators.iter().enumerate() {
            PublicKey::from_base58(v)
                .map_err(|_| GenesisError::InvalidValidator(format!("validator[{}]: {}", i, v)))?;
        }

        // Validate all addresses in alloc
        for addr in self.alloc.keys() {
            Address::from_base58(addr)
                .or_else(|_| Address::from_hex(addr))
                .map_err(|_| GenesisError::InvalidAddress(addr.clone()))?;
        }

        Ok(())
    }

    /// Get validator public keys as bytes
    pub fn validator_pubkeys(&self) -> Result<Vec<[u8; 32]>> {
        self.validators
            .iter()
            .map(|v| {
                PublicKey::from_base58(v)
                    .map(|pk| *pk.as_bytes())
                    .map_err(|_| GenesisError::InvalidValidator(v.clone()))
            })
            .collect()
    }

    /// Get the first validator (proposer of genesis block)
    pub fn genesis_proposer(&self) -> Result<[u8; 32]> {
        let pubkeys = self.validator_pubkeys()?;
        Ok(pubkeys[0])
    }

    /// Parse allocations into addresses and balances
    pub fn parsed_alloc(&self) -> Result<Vec<(Address, Balance)>> {
        self.alloc
            .iter()
            .map(|(addr_str, balance)| {
                let addr = Address::from_base58(addr_str)
                    .or_else(|_| Address::from_hex(addr_str))
                    .map_err(|_| GenesisError::InvalidAddress(addr_str.clone()))?;
                Ok((addr, *balance))
            })
            .collect()
    }

    /// Compute the initial state root from allocations
    pub fn compute_state_root(&self) -> Result<Hash> {
        let alloc = self.parsed_alloc()?;

        // Simple state root: hash of sorted (address, balance) pairs
        // In production, this would be a proper merkle patricia trie
        let mut sorted_alloc = alloc.clone();
        sorted_alloc.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));

        let mut data = Vec::new();
        for (addr, balance) in sorted_alloc {
            data.extend_from_slice(addr.as_bytes());
            data.extend_from_slice(&balance.to_be_bytes());
        }

        Ok(Hash::hash(&data))
    }

    /// Create the genesis block
    pub fn create_genesis_block(&self) -> Result<Block> {
        let state_root = self.compute_state_root()?;
        let proposer = self.genesis_proposer()?;

        let block = Block::genesis(state_root, proposer, self.genesis_time);

        // Genesis block doesn't need a real signature in PoA
        // (it's trusted as the starting point)

        Ok(block)
    }

    /// Create a default local development genesis
    pub fn local_dev(validator_pubkeys: &[&str], prefund_addresses: &[(&str, Balance)]) -> Self {
        let validators: Vec<String> = validator_pubkeys.iter().map(|s| s.to_string()).collect();

        let alloc: HashMap<String, Balance> = prefund_addresses
            .iter()
            .map(|(addr, bal)| (addr.to_string(), *bal))
            .collect();

        Self {
            chain_id: 1337, // Local dev chain ID
            genesis_time: 0,
            validators,
            alloc,
            params: ChainParams::default(),
        }
    }
}

/// Node configuration for connecting to a network
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeConfig {
    /// Node name/identifier
    pub name: String,
    /// Path to node data directory
    pub data_dir: String,
    /// Listen address for P2P
    pub listen_addr: String,
    /// Bootstrap nodes to connect to
    pub bootnodes: Vec<String>,
    /// Path to node private key (for P2P identity)
    pub node_key_path: Option<String>,
    /// Whether this node is a validator
    pub is_validator: bool,
    /// Path to validator key (if is_validator)
    pub validator_key_path: Option<String>,
    /// RPC listen address
    pub rpc_addr: String,
    /// Enable RPC
    pub rpc_enabled: bool,
    /// Log level
    pub log_level: String,
}

impl Default for NodeConfig {
    fn default() -> Self {
        Self {
            name: "sumchain-node".to_string(),
            data_dir: "data".to_string(),
            listen_addr: "/ip4/0.0.0.0/tcp/30303".to_string(),
            bootnodes: Vec::new(),
            node_key_path: None,
            is_validator: false,
            validator_key_path: None,
            rpc_addr: "127.0.0.1:8545".to_string(),
            rpc_enabled: true,
            log_level: "info".to_string(),
        }
    }
}

impl NodeConfig {
    /// Load from TOML file
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let contents = fs::read_to_string(path)?;
        // Using serde_json for simplicity; in production use toml crate
        let config: NodeConfig = serde_json::from_str(&contents)
            .map_err(|e| GenesisError::Json(e))?;
        Ok(config)
    }

    /// Save to file
    pub fn to_file<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let contents = serde_json::to_string_pretty(self)?;
        fs::write(path, contents)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sumchain_crypto::KeyPair;

    /// Plan v3.2 — existing `genesis.json` files (without the new V2 fields)
    /// must still deserialize cleanly. Any of the SNIP V2 params landing
    /// without `#[serde(default)]` would break old-genesis loads — this test
    /// catches that by deserializing a minimal-shape genesis and asserting the
    /// V2 fields fall back to their declared defaults.
    #[test]
    fn test_genesis_deserializes_without_v2_fields() {
        let json = r#"{
            "chain_id": 1337,
            "genesis_time": 0,
            "validators": [],
            "alloc": {},
            "params": {
                "block_time_ms": 2000,
                "max_block_bytes": 1000000,
                "max_txs_per_block": 1000,
                "min_fee": 1
            }
        }"#;
        let g: Genesis = serde_json::from_str(json).expect("old-shape genesis must deserialize");
        // Phase 1 v3.0 params.
        assert_eq!(g.params.max_access_list_bytes, default_max_access_list_bytes());
        assert_eq!(g.params.activation_grace_blocks, default_activation_grace_blocks());
        assert_eq!(
            g.params.abandonment_fee_percent,
            default_abandonment_fee_percent()
        );
        // v3.2 bitmap-attestation params.
        assert_eq!(
            g.params.max_chunk_count_per_file,
            default_max_chunk_count_per_file()
        );
        assert_eq!(
            g.params.max_chunk_indices_per_tx,
            default_max_chunk_indices_per_tx()
        );
        assert_eq!(
            g.params.assignment_replication_factor,
            default_assignment_replication_factor()
        );
        // v3.3 V2 activation gate: production-safe default is `None`
        // (V2 disabled). An old mainnet genesis upgraded to a V2-aware binary
        // must NOT auto-enable V2 — operator must set the field explicitly.
        assert_eq!(g.params.v2_enabled_from_height, None);
    }

    #[test]
    fn test_genesis_validation() {
        let kp = KeyPair::generate();
        let validator = kp.public_key().to_base58();
        let addr = kp.address().to_base58();

        let genesis = Genesis::new(
            1,
            0,
            vec![validator],
            HashMap::from([(addr, 1_000_000)]),
            ChainParams::default(),
        );

        assert!(genesis.validate().is_ok());
    }

    #[test]
    fn test_no_validators() {
        let genesis = Genesis::new(
            1,
            0,
            vec![],
            HashMap::new(),
            ChainParams::default(),
        );

        assert!(matches!(genesis.validate(), Err(GenesisError::NoValidators)));
    }

    #[test]
    fn test_invalid_validator() {
        let genesis = Genesis::new(
            1,
            0,
            vec!["not-a-valid-pubkey".to_string()],
            HashMap::new(),
            ChainParams::default(),
        );

        assert!(matches!(genesis.validate(), Err(GenesisError::InvalidValidator(_))));
    }

    #[test]
    fn test_genesis_json_roundtrip() {
        let kp = KeyPair::generate();
        let validator = kp.public_key().to_base58();

        let genesis = Genesis::new(
            1337,
            12345,
            vec![validator],
            HashMap::new(),
            ChainParams::default(),
        );

        let json = genesis.to_json().unwrap();
        let parsed = Genesis::from_json(&json).unwrap();

        assert_eq!(genesis.chain_id, parsed.chain_id);
        assert_eq!(genesis.genesis_time, parsed.genesis_time);
        assert_eq!(genesis.validators, parsed.validators);
    }

    #[test]
    fn test_create_genesis_block() {
        let kp = KeyPair::generate();
        let validator = kp.public_key().to_base58();
        let addr = kp.address().to_base58();

        let genesis = Genesis::new(
            1,
            1000,
            vec![validator],
            HashMap::from([(addr, 1_000_000)]),
            ChainParams::default(),
        );

        let block = genesis.create_genesis_block().unwrap();

        assert_eq!(block.height(), 0);
        assert!(block.header.parent_hash.is_zero());
        assert!(block.transactions.is_empty());
    }

    #[test]
    fn test_state_root_deterministic() {
        let kp = KeyPair::generate();
        let validator = kp.public_key().to_base58();
        let addr = kp.address().to_base58();

        let genesis = Genesis::new(
            1,
            0,
            vec![validator],
            HashMap::from([(addr, 1_000_000)]),
            ChainParams::default(),
        );

        let root1 = genesis.compute_state_root().unwrap();
        let root2 = genesis.compute_state_root().unwrap();

        assert_eq!(root1, root2);
    }

    // ── Validator-quorum activation params (base58, no council/resolver) ──────

    fn gov_params_with_treasury(treasury: Option<Address>) -> GovernanceParams {
        GovernanceParams {
            validator_authority_threshold_bps: 6667,
            quorum_bps: 2000,
            pass_threshold_bps: 5000,
            voting_period_blocks: 7200,
            max_snapshot_holders: 10000,
            proposal_bond: 0,
            treasury,
            min_koppa_for_eligibility: 0,
        }
    }

    #[test]
    fn governance_treasury_round_trips_as_base58() {
        let treasury = Address::new([0x11; 20]);
        let mut p = ChainParams::default();
        p.governance = Some(gov_params_with_treasury(Some(treasury)));
        let json = serde_json::to_string(&p).unwrap();
        // treasury emitted as a base58 string, not a byte array.
        assert!(
            json.contains(&format!("\"treasury\":\"{}\"", treasury.to_base58())),
            "treasury not base58: {json}"
        );
        assert!(!json.contains("\"council\""), "no council field: {json}");
        assert!(!json.contains("dispute_resolver"), "no resolver field: {json}");
        // round-trips.
        let p2: ChainParams = serde_json::from_str(&json).unwrap();
        let gp = p2.governance.unwrap();
        assert_eq!(gp.validator_authority_threshold_bps, 6667);
        assert_eq!(gp.treasury, Some(treasury));
    }

    #[test]
    fn dispute_threshold_bps_round_trips() {
        let mut p = ChainParams::default();
        p.inference_settlement_dispute_threshold_bps = Some(6667);
        let json = serde_json::to_string(&p).unwrap();
        assert!(json.contains("\"inference_settlement_dispute_threshold_bps\":6667"));
        let p2: ChainParams = serde_json::from_str(&json).unwrap();
        assert_eq!(p2.inference_settlement_dispute_threshold_bps, Some(6667));
    }

    #[test]
    fn consistency_gate_defaults_none_and_round_trips() {
        // Issue #77: dormant by default; absent from a pre-#77 genesis.json decodes
        // to None (serde default); an explicit height round-trips.
        let p = ChainParams::default();
        assert_eq!(p.inference_settlement_consistency_enabled_from_height, None);
        // Older genesis without the key still loads (serde default).
        let mut value = serde_json::to_value(&p).unwrap();
        value
            .as_object_mut()
            .unwrap()
            .remove("inference_settlement_consistency_enabled_from_height");
        let back: ChainParams = serde_json::from_value(value).unwrap();
        assert_eq!(back.inference_settlement_consistency_enabled_from_height, None);
        // Explicit activation height round-trips.
        let mut p2 = ChainParams::default();
        p2.inference_settlement_consistency_enabled_from_height = Some(8_900_000);
        let json = serde_json::to_string(&p2).unwrap();
        let p3: ChainParams = serde_json::from_str(&json).unwrap();
        assert_eq!(p3.inference_settlement_consistency_enabled_from_height, Some(8_900_000));
    }

    #[test]
    fn sponsored_attestation_gate_default_and_round_trip() {
        // Issue #79: dormant by default; absent-from-genesis decodes to None;
        // explicit height round-trips. v1 attestation is unaffected.
        let p = ChainParams::default();
        assert_eq!(p.omninode_sponsored_attestation_enabled_from_height, None);
        let mut value = serde_json::to_value(&p).unwrap();
        value
            .as_object_mut()
            .unwrap()
            .remove("omninode_sponsored_attestation_enabled_from_height");
        let back: ChainParams = serde_json::from_value(value).unwrap();
        assert_eq!(back.omninode_sponsored_attestation_enabled_from_height, None);
        let mut p2 = ChainParams::default();
        p2.omninode_sponsored_attestation_enabled_from_height = Some(9_100_000);
        let json = serde_json::to_string(&p2).unwrap();
        let p3: ChainParams = serde_json::from_str(&json).unwrap();
        assert_eq!(p3.omninode_sponsored_attestation_enabled_from_height, Some(9_100_000));
    }

    #[test]
    fn verifier_bonding_params_default_and_round_trip() {
        // Issue #78: dormant by default; unbonding period has a non-zero default;
        // absent-from-genesis decodes cleanly; explicit height round-trips.
        let p = ChainParams::default();
        assert_eq!(p.inference_verifier_bonding_enabled_from_height, None);
        assert!(p.inference_verifier_unbonding_period_blocks > 0);
        // Older genesis without the keys still loads (serde defaults).
        let mut value = serde_json::to_value(&p).unwrap();
        let obj = value.as_object_mut().unwrap();
        obj.remove("inference_verifier_bonding_enabled_from_height");
        obj.remove("inference_verifier_unbonding_period_blocks");
        let back: ChainParams = serde_json::from_value(value).unwrap();
        assert_eq!(back.inference_verifier_bonding_enabled_from_height, None);
        assert_eq!(
            back.inference_verifier_unbonding_period_blocks,
            p.inference_verifier_unbonding_period_blocks
        );
        // Explicit activation height round-trips.
        let mut p2 = ChainParams::default();
        p2.inference_verifier_bonding_enabled_from_height = Some(9_000_000);
        let json = serde_json::to_string(&p2).unwrap();
        let p3: ChainParams = serde_json::from_str(&json).unwrap();
        assert_eq!(p3.inference_verifier_bonding_enabled_from_height, Some(9_000_000));
    }

    #[test]
    fn defaults_need_no_council_or_resolver() {
        let p = ChainParams::default();
        assert!(p.governance.is_none());
        assert_eq!(p.inference_settlement_dispute_threshold_bps, None);
        let json = serde_json::to_string(&p).unwrap();
        assert!(!json.contains("council"));
        assert!(!json.contains("dispute_resolver"));
        assert!(json.contains("inference_settlement_dispute_threshold_bps"));
    }

    #[test]
    fn invalid_base58_treasury_rejected() {
        let treasury = Address::new([0x11; 20]);
        let mut p = ChainParams::default();
        p.governance = Some(gov_params_with_treasury(Some(treasury)));
        let json = serde_json::to_string(&p).unwrap();
        let bad = json.replace(&treasury.to_base58(), "not-valid-base58-0OIl");
        assert!(serde_json::from_str::<ChainParams>(&bad).is_err(), "invalid base58 must reject");
    }

    #[test]
    fn legacy_array_treasury_still_accepted() {
        // Backward compat: a legacy [u8;20] array still deserializes to the same address.
        let treasury = Address::new([0x11; 20]);
        let mut p = ChainParams::default();
        p.governance = Some(gov_params_with_treasury(Some(treasury)));
        let json = serde_json::to_string(&p).unwrap();
        let arr = serde_json::to_string(&vec![0x11u8; 20]).unwrap();
        let legacy = json.replace(&format!("\"{}\"", treasury.to_base58()), &arr);
        let p2: ChainParams = serde_json::from_str(&legacy).expect("legacy array treasury parses");
        assert_eq!(p2.governance.unwrap().treasury, Some(treasury));
    }
}
