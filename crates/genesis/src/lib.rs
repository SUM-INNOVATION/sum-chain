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

    /// A subsystem activation gate was set (`Some(_)`) before the typed
    /// parameter structure it requires exists. Fail-closed: the gate cannot be
    /// opened until its parameters are defined and validated. `gate` is the
    /// stable field name (issue references belong in source comments / PR text,
    /// never in this runtime string).
    #[error(
        "subsystem activation gate '{gate}' cannot be enabled: its required \
         parameter structure does not exist yet"
    )]
    IncompleteSubsystemActivation { gate: &'static str },

    /// A `beacon_params` config (issue #127) violates the ratified §7.4 threshold /
    /// fault inequalities and is rejected at genesis load. The params surface may be
    /// declared ahead of activation, but only if internally consistent.
    #[error("invalid beacon_params: {reason}")]
    InvalidBeaconParams { reason: &'static str },

    /// `account_root_enabled_from_height` is `Some(_)` while
    /// `application_journal_enabled_from_height` is `None`.
    ///
    /// `None` on the journal gate is not "off" — it means OBSERVED FROM CHAIN,
    /// and what each node observes is its own first journalled height. That is a
    /// node-local answer, which is harmless while the journal is node-local undo
    /// metadata and fatal once the account commitment depends on it: two
    /// validators would hold different boundaries, and discover the difference
    /// at a reorg rather than at boot.
    #[error(
        "account_root_enabled_from_height is Some({account_root}) while \
         application_journal_enabled_from_height is None. The account commitment folds \
         account state into the block state root, so a reorg reaching a height where the \
         root covers account rows must be able to restore those rows from a generic \
         journal. `None` on the journal gate does not mean 'always required' — it means \
         each node OBSERVES its own boundary from its own journal history, which is a \
         node-local value two validators can disagree about. Pin \
         application_journal_enabled_from_height to a height at or below {account_root}"
    )]
    AccountRootWithoutJournalGate { account_root: u64 },

    /// The journal gate activates LATER than the account-root gate, leaving a
    /// band of heights whose state root covers account rows that no generic
    /// journal can restore.
    #[error(
        "application_journal_enabled_from_height is Some({journal}), later than \
         account_root_enabled_from_height Some({account_root}). Heights \
         {account_root}..{journal} would commit account state to the block state root \
         while their undo record is only the four legacy per-subsystem journals, which do \
         not cover every family a block writes. A reorg into that band could neither \
         revert nor agree. The journal gate must be at or below the account-root gate"
    )]
    JournalGateAfterAccountRoot { journal: u64, account_root: u64 },

    /// A `beacon_schedule` config (issue #127) is internally inconsistent and is
    /// rejected at genesis load (not an activation height — declared dormant).
    #[error("invalid beacon_schedule: {reason}")]
    InvalidBeaconSchedule { reason: &'static str },
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
        use super::{
            Deserialize, Deserializer, GovernanceParams, GovernanceParamsJson, Serializer,
        };
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

    /// Block height at which the ACCOUNT-STATE COMMITMENT enters the block
    /// state root (balances and nonces). `None` (the default) = the account
    /// digest is not folded at any height and the root formula is byte-for-byte
    /// the one an un-upgraded node computes; `Some(h)` = every block at height
    /// `h` or above folds it.
    ///
    /// This closes a consensus hole rather than enabling a subprotocol. Below
    /// the gate the authoritative commitment does not cover account state at
    /// all: `compute_block_state_root` never reads the account rows, so two
    /// nodes can disagree about every balance on the chain and still publish
    /// identical block hashes. Any state-root-based verification — light
    /// client, fast-sync check, fraud proof — is blind to account state until
    /// this is set.
    ///
    /// Production safety: `#[serde(default)]` resolves a missing field to
    /// `None`, so an existing mainnet `genesis.json` upgraded to a
    /// commitment-aware binary keeps producing byte-identical roots until
    /// operators coordinate an explicit activation height. Adding a field to
    /// the root is consensus-breaking: above the activation height an
    /// un-upgraded node computes a different root for the same block and
    /// rejects it, which is the intended, detectable, coordinated split.
    /// Mirrors the V2/OmniNode/Education/Contracts activation pattern.
    ///
    /// Dev: set to `Some(0)` to commit to account state from genesis.
    ///
    /// # Ordered against the journal gate, and validated
    ///
    /// [`ChainParams::validate`] enforces
    /// `application_journal_enabled_from_height <= account_root_enabled_from_height`,
    /// and rejects `Some(_)` here while the journal gate is `None`. Once the
    /// root covers account state, a reorg into that range must be able to
    /// RESTORE account rows, and only the generic application journal restores
    /// every family a block wrote. `None` on the journal gate means "each node
    /// observes its own boundary", which is a node-local value and therefore not
    /// something a consensus commitment may rest on.
    #[serde(default)]
    pub account_root_enabled_from_height: Option<u64>,

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

    // ─── Dormant compute-pool / beacon activation gates ────────────────────
    // Minimal typed foundation for the ecosystem-devnet genesis (issue #118).
    // Both gates mirror the existing `*_enabled_from_height` idiom and stay
    // dormant (`None`). They are FAIL-CLOSED: they must remain `None` until
    // their required typed parameter structures exist — `ComputePoolParams`
    // (blocked on B0 #123 + C1 #130) and `BeaconParams` (blocked on BR1 #127).
    // No parameter struct, economic value, `Some(0)`, or `Some(h)` is
    // introduced here; enforcement lives in `ChainParams::validate()`.
    /// Compute-pool subprotocol activation gate. `None` (default) = dormant.
    /// Fail-closed: a `ChainParams` deserialized in isolation *may* hold
    /// `Some(h)`, but every genesis loaded through the authoritative
    /// `Genesis::validate()` path rejects any `Some(_)` until the
    /// `ComputePoolParams` surface + its validation exist.
    #[serde(default)]
    pub compute_pool_enabled_from_height: Option<u64>,

    /// Generic application-journal activation gate.
    ///
    /// **This journal's OWN gate.** It is deliberately not
    /// [`Self::compute_pool_enabled_from_height`] or
    /// [`Self::beacon_enabled_from_height`]: those two gate dormant consensus
    /// subsystems, they stay closed, and `Genesis::validate` rejects any
    /// `Some(_)` for them. Reusing one of those to switch on undo-journal
    /// enforcement would have tied a node-local storage decision to a consensus
    /// activation that changes which state a block commits.
    ///
    /// # What it gates, and what it does NOT
    ///
    /// It does **not** gate WRITING. `AcceptedCandidate::publish` writes a
    /// record for every block it publishes, with no gate to leave unset — that
    /// ungatedness is the specific defect this journal exists not to repeat, and
    /// it is pinned by
    /// `producer/the_write_side_is_ungated_so_no_configuration_can_leave_it_unwritten`.
    ///
    /// It gates the height from and above which a REVERT must find a record,
    /// and above which the generic journal — not the four legacy per-subsystem
    /// diffs — is the authoritative undo record for a block.
    ///
    /// * `None` (the default and the production rule) — **observed from the
    ///   chain**: the boundary is the lowest height for which this database
    ///   holds a record. A node that upgrades at height H publishes records from
    ///   H upward, so the lowest stored height IS where its journal history
    ///   begins, and the rule is right across an upgrade without anyone choosing
    ///   a number. A hardcoded height cannot be: too low demands records for
    ///   blocks an older binary published, too high leaves a window in which
    ///   nothing is required. `None` here is therefore NOT "off"; there is no
    ///   off.
    /// * `Some(h)` — **pinned**: every node answers "from when is a record
    ///   required" with `h` rather than with its own upgrade height. For a
    ///   deployment that wants a uniform, operator-visible boundary.
    ///
    /// # Not consensus
    ///
    /// The records are node-local: never hashed into a block, never folded into
    /// a state root, never sent over the wire. Two nodes disagreeing about this
    /// value cannot fork on the difference — one of them simply refuses a reorg
    /// the other would perform. That is why `Genesis::validate` admits `Some(_)`
    /// here, unlike the two dormant subsystem gates beside it.
    ///
    /// # Except once the account commitment depends on it
    ///
    /// [`Self::account_root_enabled_from_height`] folds account state into the
    /// authoritative block state root. From that height on, a node that cannot
    /// restore account rows during a reorg cannot agree about the root either.
    /// [`ChainParams::validate`] therefore enforces
    /// `application_journal_enabled_from_height <= account_root_enabled_from_height`
    /// and rejects `None` here whenever the account gate is open — a
    /// node-local, observed boundary is not a foundation a consensus commitment
    /// may stand on. Both `None` remains legal and is the production default.
    #[serde(default)]
    pub application_journal_enabled_from_height: Option<u64>,

    /// Threshold-BLS beacon activation gate. `None` (default) = dormant.
    /// Fail-closed: a `ChainParams` deserialized in isolation *may* hold
    /// `Some(h)`, but every genesis loaded through the authoritative
    /// `Genesis::validate()` path rejects any `Some(_)` until the
    /// `BeaconParams` surface + its validation exist.
    #[serde(default)]
    pub beacon_enabled_from_height: Option<u64>,

    /// BR1 randomness-beacon threshold/fault parameters (issue #127). `None`
    /// (default) = the typed surface is absent. When `Some`, it is VALIDATED at
    /// genesis load ([`BeaconParamsConfig::validate`], the draft §7.4 inequalities),
    /// so an inconsistent config is rejected. **The params surface existing does NOT
    /// activate the beacon:** [`Self::beacon_enabled_from_height`] stays `None` and
    /// `validate()` still rejects any `Some(_)` gate. This lets an operator declare
    /// the (audited, ratified) parameters ahead of a future coordinated activation
    /// without opening the gate. No economic magnitude or activation height here.
    #[serde(default)]
    pub beacon_params: Option<BeaconParamsConfig>,

    /// BR1 randomness-beacon height→epoch **schedule** (issue #127). `None` (default)
    /// = absent. When `Some`, it is VALIDATED at genesis load
    /// (`BeaconSchedule::validate`: `epoch_length ≥ 1`, strictly-ordered phase offsets
    /// inside the epoch). It is the authoritative, deterministic map from block height
    /// to `(epoch, phase, cutoffs)` the executor uses for membership selection, tx
    /// validation, persistence keys, and replay domains. **It is NOT an activation
    /// height:** the gate ([`Self::beacon_enabled_from_height`]) stays `None` and
    /// `validate()` still rejects any `Some(_)` gate; the schedule is frozen config
    /// that may be declared ahead of a future coordinated activation.
    #[serde(default)]
    pub beacon_schedule: Option<sumchain_primitives::beacon_schedule::BeaconSchedule>,

    /// SRC-201 sponsored public-key registration activation gate (issue #145).
    ///
    /// This is a fully-implemented ACTIVATION gate, NOT a dormant-until-built
    /// gate: `None` (default) means the `RegisterPublicKeySponsoredV1` operation
    /// is unavailable and rejects free (`Failed(390)`, no fee, no state) at the
    /// state executor; `Some(h)` permits execution only when
    /// `block_height >= h`. Because it enables real block-ordered execution, it
    /// is deliberately NOT part of the reject-all [`ChainParams::validate`]
    /// (which only guards subsystems whose typed parameter surface does not yet
    /// exist — compute-pool / beacon). Enforcement lives in the state executor's
    /// gate check, mirroring `omninode_sponsored_attestation_enabled_from_height`
    /// and the other `*_enabled_from_height` activation idioms.
    ///
    /// Production-safe default `None`. Activation is a coordinated,
    /// mixed-version-forbidden validator upgrade: every validator must run the
    /// identical reviewed binary and observe the same chosen height BEFORE it is
    /// reached. Never set to `Some(_)` in a committed genesis in this branch.
    /// `#[serde(default)]` keeps every existing genesis file parse-compatible.
    #[serde(default)]
    pub messaging_sponsored_registration_enabled_from_height: Option<u64>,

    /// NFT block denial becomes a charged failure.
    ///
    /// Below the gate, an NFT operation that violates a block-level rule — a bad
    /// royalty, draining the sender inside the block — returns
    /// `StateError::BlockValidation` and makes the whole block unexecutable. At
    /// and above it the same conditions produce a `Failed` receipt that charges
    /// the sender and leaves the block valid.
    ///
    /// Two nodes that disagree about this height disagree about whether a block
    /// EXISTS, not merely about its root: the ungated node produces no block at
    /// all where the gated one produces a block carrying a failed receipt.
    ///
    /// Production-safe default `None`, which is what an absent field resolves
    /// to and what every genesis written before this gate existed carries.
    /// `None` closes the gate, and a closed gate means a node executes exactly
    /// what it executed before this field was declared.
    ///
    /// Activation is a consensus change and a coordinated validator upgrade:
    /// every validator must run the identical reviewed binary and observe the
    /// same height BEFORE it is reached. Never `Some(_)` in a committed genesis
    /// in this branch.
    #[serde(default)]
    pub nft_receipt_failure_enabled_from_height: Option<u64>,

    /// Registration stake is held instead of destroyed.
    ///
    /// Below the gate the stake debited at registration is credited to nobody and
    /// leaves the money supply. At and above it the stake is held by a keyless
    /// escrow address and refunded exactly once on deactivation.
    ///
    /// Production-safe default `None`, which is what an absent field resolves
    /// to and what every genesis written before this gate existed carries.
    /// `None` closes the gate, and a closed gate means a node executes exactly
    /// what it executed before this field was declared.
    ///
    /// Activation is a consensus change and a coordinated validator upgrade:
    /// every validator must run the identical reviewed binary and observe the
    /// same height BEFORE it is reached. Never `Some(_)` in a committed genesis
    /// in this branch.
    #[serde(default)]
    pub docclass_stake_escrow_enabled_from_height: Option<u64>,

    /// The DocClass identity index gets a key of its own.
    ///
    /// Below the gate the identity index shares a 32-byte key space in which two
    /// different subjects can collide. At and above it writes use a tagged
    /// 33-byte key no legacy key can equal; reads still fall back to the legacy
    /// key, so a collision committed BEFORE activation stays.
    ///
    /// Production-safe default `None`, which is what an absent field resolves
    /// to and what every genesis written before this gate existed carries.
    /// `None` closes the gate, and a closed gate means a node executes exactly
    /// what it executed before this field was declared.
    ///
    /// Activation is a consensus change and a coordinated validator upgrade:
    /// every validator must run the identical reviewed binary and observe the
    /// same height BEFORE it is reached. Never `Some(_)` in a committed genesis
    /// in this branch.
    #[serde(default)]
    pub docclass_subject_index_split_enabled_from_height: Option<u64>,

    /// Only the issuer may revoke a DocClass credential.
    ///
    /// Below the gate revocation standing is unchecked.
    ///
    /// Production-safe default `None`, which is what an absent field resolves
    /// to and what every genesis written before this gate existed carries.
    /// `None` closes the gate, and a closed gate means a node executes exactly
    /// what it executed before this field was declared.
    ///
    /// Activation is a consensus change and a coordinated validator upgrade:
    /// every validator must run the identical reviewed binary and observe the
    /// same height BEFORE it is reached. Never `Some(_)` in a committed genesis
    /// in this branch.
    #[serde(default)]
    pub docclass_revocation_standing_enabled_from_height: Option<u64>,

    /// Healthcare operations check the authority they were specified with.
    ///
    /// Below the gate the authorization rules in the subsystem's own specification
    /// are not enforced, so an operation can be performed by a party with no
    /// standing to perform it.
    ///
    /// Production-safe default `None`, which is what an absent field resolves
    /// to and what every genesis written before this gate existed carries.
    /// `None` closes the gate, and a closed gate means a node executes exactly
    /// what it executed before this field was declared.
    ///
    /// Activation is a consensus change and a coordinated validator upgrade:
    /// every validator must run the identical reviewed binary and observe the
    /// same height BEFORE it is reached. Never `Some(_)` in a committed genesis
    /// in this branch.
    #[serde(default)]
    pub healthcare_authorization_enabled_from_height: Option<u64>,

    /// Legal consolidate, transfer and supersession check authority.
    ///
    /// Below the gate these four operations accept any sender. Supersession in
    /// particular is three conditions and not one: the sender must hold the old
    /// record, the replacement must be issued by the sender, and it must concern
    /// the same subject — otherwise supersession is a way to overwrite someone
    /// else's record.
    ///
    /// Production-safe default `None`, which is what an absent field resolves
    /// to and what every genesis written before this gate existed carries.
    /// `None` closes the gate, and a closed gate means a node executes exactly
    /// what it executed before this field was declared.
    ///
    /// Activation is a consensus change and a coordinated validator upgrade:
    /// every validator must run the identical reviewed binary and observe the
    /// same height BEFORE it is reached. Never `Some(_)` in a committed genesis
    /// in this branch.
    #[serde(default)]
    pub legal_authorization_enabled_from_height: Option<u64>,

    /// A revoked finance issuer stops being an issuer.
    ///
    /// Below the gate revocation is recorded and then ignored by the operations
    /// that should consult it.
    ///
    /// Production-safe default `None`, which is what an absent field resolves
    /// to and what every genesis written before this gate existed carries.
    /// `None` closes the gate, and a closed gate means a node executes exactly
    /// what it executed before this field was declared.
    ///
    /// Activation is a consensus change and a coordinated validator upgrade:
    /// every validator must run the identical reviewed binary and observe the
    /// same height BEFORE it is reached. Never `Some(_)` in a committed genesis
    /// in this branch.
    #[serde(default)]
    pub finance_authorization_enabled_from_height: Option<u64>,

    /// A revoked employment issuer stops being an issuer.
    ///
    /// Below the gate revocation is recorded and then ignored by the operations
    /// that should consult it.
    ///
    /// Production-safe default `None`, which is what an absent field resolves
    /// to and what every genesis written before this gate existed carries.
    /// `None` closes the gate, and a closed gate means a node executes exactly
    /// what it executed before this field was declared.
    ///
    /// Activation is a consensus change and a coordinated validator upgrade:
    /// every validator must run the identical reviewed binary and observe the
    /// same height BEFORE it is reached. Never `Some(_)` in a committed genesis
    /// in this branch.
    #[serde(default)]
    pub employment_authorization_enabled_from_height: Option<u64>,

    /// Property operations bind to the row and the registry.
    ///
    /// Below the gate an operation need not be performed by a party the row or the
    /// registry gives standing to.
    ///
    /// Production-safe default `None`, which is what an absent field resolves
    /// to and what every genesis written before this gate existed carries.
    /// `None` closes the gate, and a closed gate means a node executes exactly
    /// what it executed before this field was declared.
    ///
    /// Activation is a consensus change and a coordinated validator upgrade:
    /// every validator must run the identical reviewed binary and observe the
    /// same height BEFORE it is reached. Never `Some(_)` in a committed genesis
    /// in this branch.
    #[serde(default)]
    pub property_authorization_enabled_from_height: Option<u64>,

    /// Tax operations bind to the row and the registry.
    ///
    /// Below the gate an operation need not be performed by a party the row or the
    /// registry gives standing to.
    ///
    /// Production-safe default `None`, which is what an absent field resolves
    /// to and what every genesis written before this gate existed carries.
    /// `None` closes the gate, and a closed gate means a node executes exactly
    /// what it executed before this field was declared.
    ///
    /// Activation is a consensus change and a coordinated validator upgrade:
    /// every validator must run the identical reviewed binary and observe the
    /// same height BEFORE it is reached. Never `Some(_)` in a committed genesis
    /// in this branch.
    #[serde(default)]
    pub tax_authorization_enabled_from_height: Option<u64>,

    /// Eight subsystems see the block's timestamp instead of a literal zero.
    ///
    /// Below the gate eight subsystems are handed `0` where the block's timestamp
    /// belongs, so every time-dependent rule in them evaluates at the epoch —
    /// a prescription validity window, for instance, is checked at time zero.
    /// At and above it they receive the real block timestamp.
    ///
    /// Production-safe default `None`, which is what an absent field resolves
    /// to and what every genesis written before this gate existed carries.
    /// `None` closes the gate, and a closed gate means a node executes exactly
    /// what it executed before this field was declared.
    ///
    /// Activation is a consensus change and a coordinated validator upgrade:
    /// every validator must run the identical reviewed binary and observe the
    /// same height BEFORE it is reached. Never `Some(_)` in a committed genesis
    /// in this branch.
    #[serde(default)]
    pub subsystem_block_timestamp_enabled_from_height: Option<u64>,

    /// Subsystem event rows are keyed by the transaction that produced them.
    ///
    /// Below the gate every dispatch arm hands the subsystem executors a literal
    /// `0` where the transaction's index within its block belongs. DocClass
    /// events are keyed `height || tx_index || event_index` and messaging events
    /// `recipient || height || tx_index`, so every event a block produces lands
    /// at one key and only the LAST survives: the family holds one row per block
    /// and every earlier event is silently overwritten. At and above the gate
    /// each arm passes the transaction's real index and the rows stop colliding.
    ///
    /// Distinct from `subsystem_block_timestamp_enabled_from_height` on purpose.
    /// That gate changes the CONTENTS of rows across eight subsystems and moves
    /// time-dependent validity with it; this one changes the KEYS and the COUNT
    /// of rows in two families, and therefore the size of a block's write set,
    /// which the candidate ceiling can refuse. They are different defects with
    /// different blast radii, and an operator must be able to sequence them.
    ///
    /// Production-safe default `None`, which is what an absent field resolves
    /// to and what every genesis written before this gate existed carries.
    /// `None` closes the gate, and a closed gate means a node executes exactly
    /// what it executed before this field was declared.
    ///
    /// Activation is a consensus change and a coordinated validator upgrade:
    /// every validator must run the identical reviewed binary and observe the
    /// same height BEFORE it is reached. Never `Some(_)` in a committed genesis
    /// in this branch.
    #[serde(default)]
    pub subsystem_tx_index_enabled_from_height: Option<u64>,

    /// A transaction's sizing inputs are bounded BEFORE the value they size is
    /// built.
    ///
    /// Below the gate an accumulating structure is decoded, appended to and
    /// re-encoded in full before `view.put` charges one byte against the
    /// candidate ceiling, and the payload that drives it is `bincode`-decoded
    /// with no length check ahead of it. So the ceiling bounds what a block may
    /// COMMIT; it bounds nothing about what one refused transaction may
    /// ALLOCATE. Measured at the release configuration -- a 1 GiB ceiling and
    /// 2,000,000-byte blocks -- one `AddKey` against a committed DocClass
    /// identity row peaks at 4.00x the row's size and churns 5.00x, and one
    /// such transaction grows that row by 1,899,873 bytes for one `min_fee`,
    /// so the row reaches the largest size a single write can still commit in
    /// a few hundred blocks and the transaction after that peaks above two
    /// gibibytes on its way to being refused.
    ///
    /// At and above the gate three checks fire before the allocation: a
    /// subsystem payload longer than `MAX_SUBSYSTEM_PAYLOAD_BYTES` is refused
    /// before it is decoded; a stored row whose encoding is longer than
    /// `MAX_ACCUMULATING_ROW_BYTES` is refused before it is decoded, which
    /// stops the row growing any further; and an NFT `BatchMint` naming more
    /// than `MAX_NFT_BATCH_MINT_REQUESTS` tokens is refused before the loop
    /// that rebuilds the owner index once per request.
    ///
    /// The limits themselves are binary constants, NOT fields here. An
    /// activation height is a number validators must agree on and this digest
    /// covers it; a size limit is a number validators must agree on and this
    /// digest does NOT cover anything that is not an `Option<u64>` gate. Two
    /// validators holding different limits would split at the first transaction
    /// between them, with nothing to compare. So the limit lives where the rest
    /// of the reviewed binary lives and only the height is configured.
    ///
    /// One field for both subsystems because it is one rule at one seam, and
    /// because a partial activation leaves the cheapest vector open -- an
    /// attacker refused by the DocClass bound simply moves to the NFT one.
    /// There is no configuration in which an operator wants one and not the
    /// other.
    /// The Tax proof store and its subject index stop disagreeing.
    ///
    /// Three defects that share one invariant, and therefore one height
    /// (ACTIVATION-AUDIT rows OV-1, OV-2 and OV-3):
    ///
    ///   * `IssueClaim` is a blind overwrite. The proof id is chosen by the
    ///     sender, so any active issuer replaces any existing proof, and the
    ///     replaced proof's subject-index entry is left pointing at a row whose
    ///     subject is now somebody else's.
    ///   * `RevokeClaim` reads its 32-byte payload field as a PROOF ID while
    ///     calling it a subject nullifier, so a revocation naming a subject
    ///     finds nothing and a revocation naming a proof id succeeds.
    ///   * deleting a proof removes the proof row and leaves the subject-index
    ///     entry, so the index grows without bound and points at rows that are
    ///     gone.
    ///
    /// At and above the gate `IssueClaim` refuses a proof id already present,
    /// `RevokeClaim` resolves its payload through the subject index and revokes
    /// every proof recorded for that subject, and each deletion removes the
    /// matching index entry. Separating them would leave the subsystem
    /// inconsistent in a new way rather than an old one: index cleanup without
    /// the keying fix cleans the wrong subject, and the keying fix without index
    /// cleanup makes the dangling entries accumulate faster.
    ///
    /// Production-safe default `None`, which is what an absent field resolves
    /// to and what every genesis written before this gate existed carries.
    /// `None` closes the gate, and a closed gate means a node executes exactly
    /// what it executed before this field was declared.
    ///
    /// Activation is a consensus change and a coordinated validator upgrade:
    /// every validator must run the identical reviewed binary and observe the
    /// same height BEFORE it is reached. Never `Some(_)` in a committed genesis
    /// in this branch.
    #[serde(default)]
    pub subsystem_allocation_bound_enabled_from_height: Option<u64>,

    /// The Tax proof store and `TAX_SUBJECT_INDEX` stop disagreeing.
    ///
    /// ACTIVATION-AUDIT rows OV-1, OV-2 and OV-3; the full statement of the
    /// rule is on `TaxExecutor::proof_lifecycle_activation`, which is the one
    /// accessor that reads this field.
    ///
    /// This declaration carried neither a doc comment nor its `#[serde(default)]`
    /// when it was found, alone among the gates: the merge that added it landed
    /// the field line and lost the block above it. `Option<u64>` is defaulted by
    /// serde whether the attribute is present or not — which is why
    /// `state/a_genesis_written_before_these_fields_still_parses_dormant` passed
    /// over it and why nothing had caught this — so the loss was documentation
    /// and consistency and not behaviour. Restored rather than left, because
    /// the next reader has no way to tell a deliberate omission from a scar.
    ///
    /// Production-safe default `None`, which is what an absent field resolves
    /// to and what every genesis written before this gate existed carries.
    /// `None` closes the gate, and a closed gate means a node executes exactly
    /// what it executed before this field was declared.
    ///
    /// Activation is a consensus change and a coordinated validator upgrade:
    /// every validator must run the identical reviewed binary and observe the
    /// same height BEFORE it is reached. Never `Some(_)` in a committed genesis
    /// in this branch.
    #[serde(default)]
    pub tax_proof_lifecycle_enabled_from_height: Option<u64>,

    /// An NFT approval or metadata rewrite answers to the same authority a
    /// transfer does.
    ///
    /// Three defects that are one question — which state does a token-mutating
    /// arm consult before it writes — and therefore one height
    /// (ACTIVATION-AUDIT rows OV-12, OV-13 and OV-14):
    ///
    ///   * `UpdateMetadata` accepts the token's CREATOR, which never changes, so
    ///     the minter rewrites the metadata of a token it sold, for the life of
    ///     the token.
    ///   * the `locked` flag is read by transfer and burn only, so a locked
    ///     token is still approvable and its metadata still rewritable.
    ///   * `Approve` never reads the collection, so an approval is recorded on a
    ///     token in a collection that forbids transfers.
    ///
    /// At and above the gate `UpdateMetadata` requires the current owner, and
    /// both `Approve` and `UpdateMetadata` refuse a locked token, and `Approve`
    /// refuses a non-transferable collection. Activating a subset leaves the
    /// hole the other two describe: an owner-only metadata rule still lets a
    /// locked token be rewritten, and a lock check on approval is worth nothing
    /// while the collection that forbids transfers is never read.
    ///
    /// Production-safe default `None`, which is what an absent field resolves
    /// to and what every genesis written before this gate existed carries.
    /// `None` closes the gate, and a closed gate means a node executes exactly
    /// what it executed before this field was declared.
    ///
    /// Activation is a consensus change and a coordinated validator upgrade:
    /// every validator must run the identical reviewed binary and observe the
    /// same height BEFORE it is reached. Never `Some(_)` in a committed genesis
    /// in this branch.
    #[serde(default)]
    pub nft_token_authority_enabled_from_height: Option<u64>,

    /// Agreement signature rows and the parties' `signed` flags agree.
    ///
    /// Two halves of one invariant, and therefore one height (ACTIVATION-AUDIT
    /// rows OV-28 and OV-29):
    ///
    ///   * a signature naming a party the agreement does not bind is stored
    ///     anyway, and rewrites the agreement row while flipping no flag;
    ///   * `RevokeSignature` deletes the signature row and leaves the party's
    ///     `signed` flag set, so an agreement stays `Executed` with the
    ///     signature that executed it gone.
    ///
    /// At and above the gate a signature must name a bound party, and revoking
    /// one clears that party's flag and returns an agreement that was `Executed`
    /// only because it was fully signed to `PendingSignatures`. Activating
    /// either alone leaves the two records disagreeing: flag-clearing without
    /// the party check can clear a flag some other signature set, and the party
    /// check without flag-clearing still lets a revocation strand an `Executed`
    /// status.
    ///
    /// Production-safe default `None`, which is what an absent field resolves
    /// to and what every genesis written before this gate existed carries.
    /// `None` closes the gate, and a closed gate means a node executes exactly
    /// what it executed before this field was declared.
    ///
    /// Activation is a consensus change and a coordinated validator upgrade:
    /// every validator must run the identical reviewed binary and observe the
    /// same height BEFORE it is reached. Never `Some(_)` in a committed genesis
    /// in this branch.
    #[serde(default)]
    pub agreement_signature_integrity_enabled_from_height: Option<u64>,

    /// A Healthcare write consults the row it is about to change.
    ///
    /// Two arms that write unconditionally, and therefore one height
    /// (ACTIVATION-AUDIT rows OV-17 and OV-20):
    ///
    ///   * `RenewMembership` sets `status = Active` whatever the status was, so
    ///     a membership terminated a transaction earlier is active again by the
    ///     end of the block;
    ///   * `RemoveNetworkAffiliation` and `RemoveDependent` write the row and
    ///     the index whether or not the thing being removed was ever there, so
    ///     removing an affiliation a provider never had CREATES an empty index
    ///     row and bumps `updated_at` on a row nothing changed.
    ///
    /// At and above the gate renewal refuses a membership that is `Cancelled`,
    /// `Terminated` or `Expired` — the statuses a renewal must not silently
    /// undo — and both removals are no-ops when there is nothing to remove.
    /// They share a height because they are one rule stated twice: a write arm
    /// must read the row before it decides, and an operator who enabled one
    /// while leaving the other would still be running a subsystem whose writes
    /// do not depend on what is there.
    ///
    /// Production-safe default `None`, which is what an absent field resolves
    /// to and what every genesis written before this gate existed carries.
    /// `None` closes the gate, and a closed gate means a node executes exactly
    /// what it executed before this field was declared.
    ///
    /// Activation is a consensus change and a coordinated validator upgrade:
    /// every validator must run the identical reviewed binary and observe the
    /// same height BEFORE it is reached. Never `Some(_)` in a committed genesis
    /// in this branch.
    #[serde(default)]
    pub healthcare_state_precondition_enabled_from_height: Option<u64>,

    /// A `VerifyProof` transaction stops reporting success for a proof that
    /// does not exist.
    ///
    /// **This gate does not make anything verify a proof.** No proof verifier
    /// exists in this tree: nothing consumes `proof_data` against
    /// `public_inputs`, in any subsystem. What the six arms do below the gate
    /// (ACTIVATION-AUDIT rows AU-6, AU-12, AU-17, AU-20, AU-26 and AU-29, the
    /// same defects as PR-1 to PR-6) is deduct, credit, increment and return
    /// SUCCESS, without reading the payload at all — so a receipt says a proof
    /// verified when the chain holds no such proof, and a relying party reading
    /// receipts cannot tell the two apart. At and above the gate the payload
    /// must be the 32 bytes of a proof id and that proof must be present in the
    /// subsystem's proof family, or the operation is a failed receipt. What
    /// remains true above the gate is that presence is not verification, and
    /// the rows stay open on that half.
    ///
    /// Defining the payload as the proof id is a choice, and it is recorded as
    /// one: `crates/sumchain-wire` declares no request type for a `VerifyProof`
    /// payload, so `data` is free bytes today and the only reading under which
    /// the operation names anything at all is that it names the proof. The same
    /// choice was made, and recorded, for the `RevokeClaim` payload of
    /// `tax_proof_lifecycle_enabled_from_height`.
    ///
    /// ONE field for six subsystems, for the reason
    /// `subsystem_block_timestamp_enabled_from_height` is one field for eight:
    /// it is one rule, the six arms are character-for-character identical, and
    /// the blast radius is identical on both sides — a transaction that was a
    /// success receipt becomes a failed one. There is nothing to sequence, and
    /// an operator who closed five of the six would be shipping a chain in
    /// which the meaning of `VerifyProof` depended on which subsystem was
    /// asked.
    ///
    /// Production-safe default `None`, which is what an absent field resolves
    /// to and what every genesis written before this gate existed carries.
    /// `None` closes the gate, and a closed gate means a node executes exactly
    /// what it executed before this field was declared.
    ///
    /// Activation is a consensus change and a coordinated validator upgrade:
    /// every validator must run the identical reviewed binary and observe the
    /// same height BEFORE it is reached. Never `Some(_)` in a committed genesis
    /// in this branch.
    #[serde(default)]
    pub subsystem_proof_presence_enabled_from_height: Option<u64>,

    /// An NFT arm that writes metadata or a collection config applies the rules
    /// the CREATION arm applies.
    ///
    /// Two defects that are one question — does an update path enforce what the
    /// creation path enforces — and therefore one height (ACTIVATION-AUDIT rows
    /// OV-10 and the first half of RY-2):
    ///
    ///   * `execute_mint` checks `max_metadata_bytes` and charges
    ///     `storage_fee_per_byte`; `UpdateMetadata` takes the payload verbatim
    ///     as the new metadata with neither check, and `BatchMint` clones
    ///     per-request metadata with neither check, for any number of requests.
    ///     Both of those `ChainParams` values are SET in the release
    ///     `genesis.json` — `max_metadata_bytes: 16384`,
    ///     `storage_fee_per_byte: 100` — and bypassed on two of the three arms
    ///     that write metadata, so the chain's own stated limits apply to one
    ///     third of the paths that reach them.
    ///   * collection creation zeroes `royalty_recipient` when `royalty_bps` is
    ///     zero; `UpdateCollectionConfig` has no such rule and sets a recipient
    ///     on a collection that pays no royalty anyway.
    ///
    /// At and above the gate `UpdateMetadata` and `BatchMint` enforce the size
    /// limit and the per-byte storage fee, and `UpdateCollectionConfig` refuses
    /// a recipient for a royalty of zero. One height because they are one
    /// asymmetry: activating the metadata half alone would leave a collection
    /// whose config still accepts a field creation rejects, and activating the
    /// royalty half alone would leave the two metadata arms writing rows the
    /// chain says are too large. Both sides change a success receipt into a
    /// failed one and neither can abort a block, so there is nothing to
    /// sequence.
    ///
    /// **This does not make a royalty payable.** RY-1 — a royalty recorded and
    /// never paid by any transfer — is untouched, and so is the half of RY-2
    /// that observes `NftUpdateCollectionConfigData` carries no
    /// `new_royalty_bps` at all: that is a wire change, not an executor change.
    ///
    /// Production-safe default `None`, which is what an absent field resolves
    /// to and what every genesis written before this gate existed carries.
    /// `None` closes the gate, and a closed gate means a node executes exactly
    /// what it executed before this field was declared.
    ///
    /// Activation is a consensus change and a coordinated validator upgrade:
    /// every validator must run the identical reviewed binary and observe the
    /// same height BEFORE it is reached. Never `Some(_)` in a committed genesis
    /// in this branch.
    #[serde(default)]
    pub nft_update_path_parity_enabled_from_height: Option<u64>,

    /// An operation that writes nothing stops reporting success.
    ///
    /// Three arms in three subsystems that charge the fee, advance the nonce
    /// and return a SUCCESS receipt having changed no row the operation names
    /// (ACTIVATION-AUDIT rows OV-6, OV-25 and OV-30):
    ///
    ///   * Legal `ConsolidateCase` repeated on a pair already consolidated:
    ///     `v_add_related_case` is `contains`-gated, so the append is skipped
    ///     and the primary case's `updated_at` — written only inside that
    ///     branch — is not written either;
    ///   * DocClass `UpdateCredential` writes nothing at all: after its
    ///     authorization check it deducts, credits, increments and returns,
    ///     with no `v_put_*` of any kind and no event;
    ///   * Agreement `AddParty` and `RemoveParty`, whose whole body is the
    ///     deduct, the credit, the increment and `success()`, under a comment
    ///     saying they "would require updating agreement parties".
    ///
    /// At and above the gate each returns a failed receipt instead. ONE height
    /// for the three, on the `subsystem_block_timestamp_enabled_from_height`
    /// argument rather than the per-subsystem one: it is a single rule about
    /// what a receipt MEANS, the blast radius is identical on all three sides
    /// (a success receipt becomes a failed one and no block can abort), and an
    /// operator who activated one of the three would be shipping a chain where
    /// a success receipt means "the operation happened" in Legal and "the fee
    /// was taken" in Agreement.
    ///
    /// **A failed receipt, not an implementation.** This does not make
    /// `AddParty` add a party or `UpdateCredential` update a credential: those
    /// need an operation semantics the subsystems do not define, and inventing
    /// one inside an executor would be a rule nobody set. What it removes is
    /// the receipt that says an absent effect happened.
    ///
    /// Production-safe default `None`, which is what an absent field resolves
    /// to and what every genesis written before this gate existed carries.
    /// `None` closes the gate, and a closed gate means a node executes exactly
    /// what it executed before this field was declared.
    ///
    /// Activation is a consensus change and a coordinated validator upgrade:
    /// every validator must run the identical reviewed binary and observe the
    /// same height BEFORE it is reached. Never `Some(_)` in a committed genesis
    /// in this branch.
    #[serde(default)]
    pub subsystem_no_op_receipt_enabled_from_height: Option<u64>,
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
            block_time_ms: 2000,        // 2 seconds
            max_block_bytes: 1_000_000, // 1 MB
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
            // Production-safe default: the account-state commitment is NOT
            // folded into the block state root. Activation is a coordinated,
            // consensus-breaking validator upgrade (it adds a field to the
            // root); never set in default/mainnet config without one.
            account_root_enabled_from_height: None,
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
            // Production-safe defaults: compute-pool and beacon subsystems
            // dormant. Fail-closed until their typed parameter surfaces exist
            // (issue #118 foundation).
            compute_pool_enabled_from_height: None,
            beacon_enabled_from_height: None,
            // Production default: the application-journal boundary is OBSERVED
            // from this node's own journal history rather than pinned. Not an
            // "off" position — the write side is ungated, so the first block a
            // node publishes establishes the boundary and every block from there
            // up is required to have a record.
            application_journal_enabled_from_height: None,
            // Production-safe default: no beacon parameter surface (typed config
            // absent). The gate above stays dormant regardless.
            beacon_params: None,
            // Production-safe default: no beacon schedule declared.
            beacon_schedule: None,
            // Production-safe default: sponsored public-key registration (issue
            // #145) unavailable. Activation is a coordinated validator upgrade;
            // never set in default/mainnet config.
            messaging_sponsored_registration_enabled_from_height: None,
            // Production-safe default: nft block denial becomes a charged failure — dormant.
            nft_receipt_failure_enabled_from_height: None,
            // Production-safe default: registration stake is held instead of destroyed — dormant.
            docclass_stake_escrow_enabled_from_height: None,
            // Production-safe default: the docclass identity index gets a key of its own — dormant.
            docclass_subject_index_split_enabled_from_height: None,
            // Production-safe default: only the issuer may revoke a docclass credential — dormant.
            docclass_revocation_standing_enabled_from_height: None,
            // Production-safe default: healthcare operations check the authority they were specified with — dormant.
            healthcare_authorization_enabled_from_height: None,
            // Production-safe default: legal consolidate, transfer and supersession check authority — dormant.
            legal_authorization_enabled_from_height: None,
            // Production-safe default: a revoked finance issuer stops being an issuer — dormant.
            finance_authorization_enabled_from_height: None,
            // Production-safe default: a revoked employment issuer stops being an issuer — dormant.
            employment_authorization_enabled_from_height: None,
            // Production-safe default: property operations bind to the row and the registry — dormant.
            property_authorization_enabled_from_height: None,
            // Production-safe default: tax operations bind to the row and the registry — dormant.
            tax_authorization_enabled_from_height: None,
            // Production-safe default: eight subsystems see the block's timestamp instead of a literal zero — dormant.
            subsystem_block_timestamp_enabled_from_height: None,
            subsystem_tx_index_enabled_from_height: None,
            subsystem_allocation_bound_enabled_from_height: None,
            // Production-safe default: the tax proof store and its subject index stop disagreeing — dormant.
            tax_proof_lifecycle_enabled_from_height: None,
            // Production-safe default: an nft approval or metadata rewrite answers to the owner, the lock and the collection — dormant.
            nft_token_authority_enabled_from_height: None,
            // Production-safe default: agreement signature rows and the parties' signed flags agree — dormant.
            agreement_signature_integrity_enabled_from_height: None,
            // Production-safe default: a healthcare write consults the row it is about to change — dormant.
            healthcare_state_precondition_enabled_from_height: None,
            // Production-safe default: VerifyProof stops succeeding for a proof that does not exist — dormant.
            subsystem_proof_presence_enabled_from_height: None,
            // Production-safe default: the nft update arms apply the creation arm's rules — dormant.
            nft_update_path_parity_enabled_from_height: None,
            // Production-safe default: an operation that writes nothing stops reporting success — dormant.
            subsystem_no_op_receipt_enabled_from_height: None,
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

    /// Validate the dormant subsystem activation gates that do not yet have a
    /// typed parameter surface.
    ///
    /// `compute_pool_enabled_from_height` and `beacon_enabled_from_height` are
    /// fail-closed: they must remain `None` until their required parameter
    /// structures exist (`ComputePoolParams`, blocked on B0 #123 + C1 #130;
    /// `BeaconParams`, blocked on BR1 #127). This method does not — and cannot
    /// — prevent constructing a `ChainParams` (in code or by deserializing one
    /// in isolation) that carries `Some(h)`. The guarantee is loader-level:
    /// [`Genesis::validate`] calls this, so every genesis admitted through the
    /// authoritative loader rejects any `Some(_)` for these gates.
    pub fn validate(&self) -> Result<()> {
        if self.compute_pool_enabled_from_height.is_some() {
            return Err(GenesisError::IncompleteSubsystemActivation {
                gate: "compute_pool_enabled_from_height",
            });
        }
        if self.beacon_enabled_from_height.is_some() {
            return Err(GenesisError::IncompleteSubsystemActivation {
                gate: "beacon_enabled_from_height",
            });
        }
        // ── the undo-before-commitment ordering, enforced at load ───────────
        //
        //     application_journal_enabled_from_height <= account_root_enabled_from_height
        //
        // The account-root gate folds account state into the authoritative block
        // state root. Above it, a node that cannot RESTORE account rows during a
        // reorg cannot agree about the root either — it is stuck with a state it
        // can neither revert nor justify. The generic application journal is the
        // only record that restores every family a block wrote, so it must be
        // authoritative from at or before the height the commitment starts.
        //
        // `None` on the journal gate is rejected here rather than treated as
        // "always on". `None` means OBSERVED FROM CHAIN — each node's boundary
        // is its own first journalled height — which is fine for node-local undo
        // metadata and not fine once consensus output depends on it: two
        // validators would hold different boundaries and find out at a reorg.
        // Opening the account commitment therefore forces the journal boundary
        // to be CHAIN-DEFINED, written in the same genesis document, covered by
        // the same genesis identity, and read the same way by every validator.
        //
        // Both `None` is legal and is the production default: no commitment, no
        // requirement.
        //
        // This is a LOAD-time check, so an inconsistent pair is refused before a
        // block executes rather than at the boundary 100,000 blocks later.
        match (
            self.application_journal_enabled_from_height,
            self.account_root_enabled_from_height,
        ) {
            (_, None) => {}
            (None, Some(account_root)) => {
                return Err(GenesisError::AccountRootWithoutJournalGate { account_root })
            }
            (Some(journal), Some(account_root)) if journal > account_root => {
                return Err(GenesisError::JournalGateAfterAccountRoot {
                    journal,
                    account_root,
                })
            }
            (Some(_), Some(_)) => {}
        }

        // The beacon PARAMETER surface (#127) MAY be declared while the gate stays
        // dormant — but only if internally consistent (draft §7.4). This validates
        // the config at load; it does NOT open the gate (still rejected above).
        if let Some(bp) = &self.beacon_params {
            bp.validate()?;
        }
        // The beacon SCHEDULE (#127) MAY likewise be declared dormant, but only if
        // internally consistent (epoch_length ≥ 1, strictly-ordered phase offsets).
        // Not an activation height — the gate stays rejected above.
        if let Some(sched) = &self.beacon_schedule {
            sched
                .validate()
                .map_err(|e| GenesisError::InvalidBeaconSchedule {
                    reason: e_reason(e),
                })?;
        }
        Ok(())
    }
}

/// Map a schedule error to a stable reason string (kept out of `validate` for
/// brevity).
fn e_reason(e: sumchain_primitives::beacon_schedule::BeaconScheduleError) -> &'static str {
    use sumchain_primitives::beacon_schedule::BeaconScheduleError as E;
    match e {
        E::ZeroEpochLength => "epoch_length must be >= 1",
        E::UnorderedOffsets => {
            "phase offsets must satisfy strict separation: key_cutoff < deal_start <= \
             deal_cutoff < complaint_start <= complaint_deadline, with a non-empty \
             signing window (complaint_deadline + 1 < epoch_length)"
        }
        E::Overflow => "beacon epoch derivation overflowed u64",
    }
}

/// BR1 randomness-beacon threshold / fault parameters as an authoritative genesis
/// config surface (issue #127). A plain, self-contained serde struct: it deliberately
/// does NOT depend on `sumchain-beacon-runtime` (which links `blst`), so the genesis
/// crate stays free of the pairing linkage. Its [`validate`](Self::validate) enforces
/// the SAME ratified §7.4 inequalities as `sumchain_beacon_runtime::BeaconParams::
/// validated`; the state producer re-validates through that runtime constructor (the
/// single source of truth for the executable runtime), so the two cannot silently
/// diverge — a mismatch would fail the runtime's own construction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct BeaconParamsConfig {
    /// Byzantine faults tolerated `f`.
    pub f: u32,
    /// Additional crash slack `c`.
    pub c: u32,
    /// Reconstruction threshold `T` (partials to combine; commitment count/deal).
    pub t: u32,
    /// QUAL / qualification size `Q_dkg`.
    pub q_dkg: u32,
    /// Committee size `n` (membership-snapshot cardinality).
    pub n: u32,
}

impl BeaconParamsConfig {
    /// Validate the draft §7.4 inequalities. **Delegates to the single shared
    /// predicate** `sumchain_primitives::beacon_schedule::validate_beacon_params` —
    /// the SAME rule the runtime's `BeaconParams::validated` uses — so genesis and the
    /// runtime accept/reject exactly the same parameter space (no drift).
    pub fn validate(&self) -> Result<()> {
        sumchain_primitives::beacon_schedule::validate_beacon_params(
            self.f, self.c, self.t, self.q_dkg, self.n,
        )
        .map_err(|v| GenesisError::InvalidBeaconParams { reason: v.reason() })
    }
}

/// Domain separator for the genesis activation digest.
///
/// Versioned in the string: a future digest that covers a different field set is
/// a different value under a different domain, so the two can never be compared
/// by accident.
pub const GENESIS_ACTIVATION_DIGEST_DOMAIN: &[u8] = b"sumchain/genesis-activation/v1";

impl ChainParams {
    /// Every activation height this binary knows, in a FIXED declared order.
    ///
    /// The order is the digest's order and must never be permuted: reordering
    /// changes the digest without changing a single height, which would read to
    /// an operator as a genesis mismatch that is not one.
    ///
    /// The list is exhaustive by test, not by discipline —
    /// `genesis_activation_digest.rs::every_activation_height_is_covered_by_the_digest`
    /// reads the field declarations out of this file and fails if one is missing
    /// here. A gate added to `ChainParams` and forgotten here would otherwise be
    /// a height that two validators could silently disagree about.
    pub fn activation_heights(&self) -> Vec<(&'static str, Option<u64>)> {
        vec![
            ("v2_enabled_from_height", self.v2_enabled_from_height),
            (
                "omninode_enabled_from_height",
                self.omninode_enabled_from_height,
            ),
            (
                "omninode_sponsored_attestation_enabled_from_height",
                self.omninode_sponsored_attestation_enabled_from_height,
            ),
            (
                "education_enabled_from_height",
                self.education_enabled_from_height,
            ),
            (
                "contracts_enabled_from_height",
                self.contracts_enabled_from_height,
            ),
            (
                "account_root_enabled_from_height",
                self.account_root_enabled_from_height,
            ),
            (
                "governance_enabled_from_height",
                self.governance_enabled_from_height,
            ),
            (
                "archive_unbonding_enabled_from_height",
                self.archive_unbonding_enabled_from_height,
            ),
            (
                "archive_reassignment_enabled_from_height",
                self.archive_reassignment_enabled_from_height,
            ),
            (
                "por_assignment_targeting_enabled_from_height",
                self.por_assignment_targeting_enabled_from_height,
            ),
            (
                "service_grants_enabled_from_height",
                self.service_grants_enabled_from_height,
            ),
            (
                "monetary_policy_enabled_from_height",
                self.monetary_policy_enabled_from_height,
            ),
            (
                "assignment_aware_por_scheduler_enabled_from_height",
                self.assignment_aware_por_scheduler_enabled_from_height,
            ),
            (
                "inference_settlement_enabled_from_height",
                self.inference_settlement_enabled_from_height,
            ),
            (
                "inference_settlement_consistency_enabled_from_height",
                self.inference_settlement_consistency_enabled_from_height,
            ),
            (
                "inference_verifier_bonding_enabled_from_height",
                self.inference_verifier_bonding_enabled_from_height,
            ),
            (
                "compute_pool_enabled_from_height",
                self.compute_pool_enabled_from_height,
            ),
            (
                "application_journal_enabled_from_height",
                self.application_journal_enabled_from_height,
            ),
            (
                "beacon_enabled_from_height",
                self.beacon_enabled_from_height,
            ),
            (
                "messaging_sponsored_registration_enabled_from_height",
                self.messaging_sponsored_registration_enabled_from_height,
            ),
            (
                "nft_receipt_failure_enabled_from_height",
                self.nft_receipt_failure_enabled_from_height,
            ),
            (
                "docclass_stake_escrow_enabled_from_height",
                self.docclass_stake_escrow_enabled_from_height,
            ),
            (
                "docclass_subject_index_split_enabled_from_height",
                self.docclass_subject_index_split_enabled_from_height,
            ),
            (
                "docclass_revocation_standing_enabled_from_height",
                self.docclass_revocation_standing_enabled_from_height,
            ),
            (
                "healthcare_authorization_enabled_from_height",
                self.healthcare_authorization_enabled_from_height,
            ),
            (
                "legal_authorization_enabled_from_height",
                self.legal_authorization_enabled_from_height,
            ),
            (
                "finance_authorization_enabled_from_height",
                self.finance_authorization_enabled_from_height,
            ),
            (
                "employment_authorization_enabled_from_height",
                self.employment_authorization_enabled_from_height,
            ),
            (
                "property_authorization_enabled_from_height",
                self.property_authorization_enabled_from_height,
            ),
            (
                "tax_authorization_enabled_from_height",
                self.tax_authorization_enabled_from_height,
            ),
            (
                "subsystem_block_timestamp_enabled_from_height",
                self.subsystem_block_timestamp_enabled_from_height,
            ),
            (
                "subsystem_tx_index_enabled_from_height",
                self.subsystem_tx_index_enabled_from_height,
            ),
            (
                "subsystem_allocation_bound_enabled_from_height",
                self.subsystem_allocation_bound_enabled_from_height,
            ),
            (
                "tax_proof_lifecycle_enabled_from_height",
                self.tax_proof_lifecycle_enabled_from_height,
            ),
            (
                "nft_token_authority_enabled_from_height",
                self.nft_token_authority_enabled_from_height,
            ),
            (
                "agreement_signature_integrity_enabled_from_height",
                self.agreement_signature_integrity_enabled_from_height,
            ),
            (
                "healthcare_state_precondition_enabled_from_height",
                self.healthcare_state_precondition_enabled_from_height,
            ),
            (
                "subsystem_proof_presence_enabled_from_height",
                self.subsystem_proof_presence_enabled_from_height,
            ),
            (
                "nft_update_path_parity_enabled_from_height",
                self.nft_update_path_parity_enabled_from_height,
            ),
            (
                "subsystem_no_op_receipt_enabled_from_height",
                self.subsystem_no_op_receipt_enabled_from_height,
            ),
        ]
    }
}

/// What changed between the activation parameters a database was last started
/// under and the ones it is being started under now.
///
/// Three outcomes, and the distinction between them is the whole value: a
/// coordinated activation IS a change to `genesis.json`, so a startup check that
/// refused every change would refuse the thing it exists to protect. What must
/// be refused is a change to a gate the chain has ALREADY PASSED.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ActivationChange {
    /// A gate whose height is still in the future under both the old value and
    /// the new one. This is a coordinated activation being scheduled, rescheduled
    /// or cancelled, and it is legitimate — noisy, and legitimate.
    Retuned {
        gate: String,
        from: Option<u64>,
        to: Option<u64>,
    },
    /// A gate that had ALREADY FIRED under the recorded height and now carries a
    /// different one, or none.
    ///
    /// Blocks were produced under the old rule. Changing the height now does not
    /// change them; it changes what this binary believes about them, which is
    /// how a node computes a different root for a block it already accepted and
    /// discovers it during a reorg.
    AlreadyActive {
        gate: String,
        from: Option<u64>,
        to: Option<u64>,
    },
    /// A gate that was dormant (or scheduled ahead) and is now set to a height
    /// the chain has already passed.
    ///
    /// Every block between that height and the head was produced WITHOUT the
    /// rule. A node starting under this configuration would reject its own
    /// history, or worse, accept it and diverge from the moment it next
    /// recomputed a root.
    RetroactivelyOpened { gate: String, to: u64 },
}

impl ActivationChange {
    /// May a node start under this change?
    ///
    /// Only [`Self::Retuned`]. The other two describe a rule being changed
    /// underneath blocks that already exist, which is not a configuration
    /// change — it is a different chain wearing this one's database.
    pub fn is_permitted(&self) -> bool {
        matches!(self, ActivationChange::Retuned { .. })
    }

    pub fn gate(&self) -> &str {
        match self {
            ActivationChange::Retuned { gate, .. }
            | ActivationChange::AlreadyActive { gate, .. }
            | ActivationChange::RetroactivelyOpened { gate, .. } => gate,
        }
    }
}

impl std::fmt::Display for ActivationChange {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        fn h(v: &Option<u64>) -> String {
            match v {
                Some(n) => n.to_string(),
                None => "dormant".to_string(),
            }
        }
        match self {
            ActivationChange::Retuned { gate, from, to } => write!(
                f,
                "{gate}: {} -> {} (both still ahead of the chain; permitted)",
                h(from),
                h(to)
            ),
            ActivationChange::AlreadyActive { gate, from, to } => write!(
                f,
                "{gate}: {} -> {} — the chain has ALREADY PASSED {}; blocks exist \
                 under the old rule and this changes what they mean",
                h(from),
                h(to),
                h(from)
            ),
            ActivationChange::RetroactivelyOpened { gate, to } => write!(
                f,
                "{gate}: set to {to}, which the chain has already passed; every \
                 block above {to} was produced without this rule"
            ),
        }
    }
}

/// The gates that existed before this binary began recording activation heights.
///
/// # Why this list is closed
///
/// [`ChainParams::activation_changes`] can only compare against a record, and a
/// database written by a binary that never recorded one has nothing to compare
/// against. That is not a hypothetical: `ACTIVATION_META_KEY` does not exist in
/// the deployed binary, so the FIRST start of every node that upgrades to this
/// one has no record — and that start is exactly the one where thirteen gates
/// the operator has never configured before are most likely to carry a wrong
/// height.
///
/// On that start, a gate set at or below the current height means one of two
/// things, and the database cannot tell them apart:
///
///   * the chain genuinely passed that height under a binary that implemented
///     the rule — true for every gate on this list, because they shipped in the
///     binary that produced those blocks; or
///   * the rule is being applied retroactively to blocks produced without it,
///     which is [`ActivationChange::RetroactivelyOpened`] with no record to
///     detect it.
///
/// So this list is the grandfather clause, and it is CLOSED: it names the gates
/// that were already live, which is a historical fact and cannot grow. A gate
/// introduced after it — every one of the thirteen, and every future one —
/// is not on it, and must therefore be dated ahead of the chain on a first
/// start. That default is the safe direction: a new gate someone forgets to
/// think about is REFUSED with a message rather than silently believed.
///
/// Pinned by `every_grandfathered_gate_still_exists` and
/// `a_gate_this_binary_introduced_is_not_grandfathered`.
pub const GATES_PREDATING_ACTIVATION_RECORDING: &[&str] = &[
    "archive_reassignment_enabled_from_height",
    "archive_unbonding_enabled_from_height",
    "assignment_aware_por_scheduler_enabled_from_height",
    "beacon_enabled_from_height",
    "compute_pool_enabled_from_height",
    "contracts_enabled_from_height",
    "education_enabled_from_height",
    "governance_enabled_from_height",
    "inference_settlement_consistency_enabled_from_height",
    "inference_settlement_enabled_from_height",
    "inference_verifier_bonding_enabled_from_height",
    "messaging_sponsored_registration_enabled_from_height",
    "monetary_policy_enabled_from_height",
    "omninode_enabled_from_height",
    "omninode_sponsored_attestation_enabled_from_height",
    "por_assignment_targeting_enabled_from_height",
    "service_grants_enabled_from_height",
    "v2_enabled_from_height",
];

impl ChainParams {
    /// Compare these activation heights against the ones this database was last
    /// started under.
    ///
    /// `recorded` is `(gate name, height)` as persisted. A gate present here and
    /// absent from `recorded` is treated as having been dormant, which is what a
    /// binary that did not know the gate would have believed — so adding a gate
    /// to `ChainParams` and starting an old database is a [`Self::Retuned`] if
    /// the new height is ahead and a refusal if it is not.
    ///
    /// Unchanged gates produce nothing. The result is the change set, and an
    /// empty result means the configuration is identical.
    pub fn activation_changes(
        &self,
        recorded: &[(String, Option<u64>)],
        current_height: u64,
    ) -> Vec<ActivationChange> {
        let mut out = Vec::new();
        for (gate, now) in self.activation_heights() {
            let before = recorded
                .iter()
                .find(|(name, _)| name == gate)
                .map(|(_, h)| *h)
                .unwrap_or(None);
            if before == now {
                continue;
            }
            // Had the old height already fired? If so, nothing about this gate
            // may move: blocks exist that were produced under it.
            if matches!(before, Some(h) if h <= current_height) {
                out.push(ActivationChange::AlreadyActive {
                    gate: gate.to_string(),
                    from: before,
                    to: now,
                });
                continue;
            }
            // The old height had not fired. The new one must not have either.
            if let Some(h) = now {
                if h <= current_height {
                    out.push(ActivationChange::RetroactivelyOpened {
                        gate: gate.to_string(),
                        to: h,
                    });
                    continue;
                }
            }
            out.push(ActivationChange::Retuned {
                gate: gate.to_string(),
                from: before,
                to: now,
            });
        }
        out
    }

    /// Which gates a database with NO activation record must not be started
    /// under.
    ///
    /// [`Self::activation_changes`] needs a record. This is the case where there
    /// is none — the first start of an upgraded node — and it asks the only
    /// question that can still be asked: is this gate claiming to have fired for
    /// blocks this database already holds?
    ///
    /// A gate on [`GATES_PREDATING_ACTIVATION_RECORDING`] may be, and normally
    /// is: it shipped in the binary that produced those blocks, so
    /// `v2_enabled_from_height: Some(0)` on a chain at height 500,000 is the
    /// ordinary configuration and not a fault. Every other gate is one this
    /// binary introduced; no block below the head was produced under it, so a
    /// height at or below the head is retroactive by construction.
    ///
    /// Returns the refusals, empty when the configuration is startable. At
    /// `current_height` 0 the result is always empty: an empty chain has passed
    /// nothing, so no height is retroactive and a genesis may open any gate it
    /// likes at 0.
    pub fn retroactive_gates_on_a_first_start(&self, current_height: u64) -> Vec<ActivationChange> {
        if current_height == 0 {
            return Vec::new();
        }
        self.activation_heights()
            .into_iter()
            .filter(|(gate, _)| !GATES_PREDATING_ACTIVATION_RECORDING.contains(gate))
            .filter_map(|(gate, height)| match height {
                Some(h) if h <= current_height => Some(ActivationChange::RetroactivelyOpened {
                    gate: gate.to_string(),
                    to: h,
                }),
                _ => None,
            })
            .collect()
    }

    /// The activation heights as `(name, height)` pairs that own their strings,
    /// for persisting.
    pub fn recorded_activation_heights(&self) -> Vec<(String, Option<u64>)> {
        self.activation_heights()
            .into_iter()
            .map(|(name, h)| (name.to_string(), h))
            .collect()
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

        // Fail-closed: reject any genesis that opens a subsystem gate whose
        // typed parameter surface does not exist yet (compute-pool / beacon).
        self.params.validate()?;

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

    /// The genesis ACTIVATION DIGEST: one 32-byte value naming the chain and
    /// every height at which its behaviour changes.
    ///
    /// # What this is for
    ///
    /// An activation height is only a coordination mechanism if every validator
    /// holds the same one. Today the heights live in each validator's runtime
    /// `genesis.json`, which is distributed out of band and compared by eye; a
    /// single mistyped digit gives one node a different root formula at a
    /// different height, and nothing reports it until blocks start being
    /// refused. This digest turns that comparison into an equality: two
    /// operators read one hex string to each other, or a monitor scrapes it, and
    /// a difference is visible before the height arrives rather than after.
    ///
    /// It is deliberately NOT a consensus value. Nothing rejects a peer for
    /// disagreeing about it — the chain already rejects the blocks that
    /// disagreement produces, which is the detection the commitment provides.
    /// This is the earlier, cheaper signal.
    ///
    /// # What it covers
    ///
    /// The chain's identity (`chain_id`, `genesis_time`), its validator set in
    /// declared order, its allocations in ascending address order, and every
    /// activation height in [`ChainParams::activation_heights`] — each as a
    /// length-prefixed name, a presence byte and, when present, the height. The
    /// name is folded so that renaming a field, or moving a height from one gate
    /// to another, changes the digest.
    ///
    /// `None` and `Some(0)` are distinguished by the presence byte, which
    /// matters: "dormant forever" and "active from genesis" are opposite
    /// configurations.
    pub fn activation_digest(&self) -> Result<Hash> {
        let mut data = Vec::new();
        data.extend_from_slice(GENESIS_ACTIVATION_DIGEST_DOMAIN);
        data.extend_from_slice(&self.chain_id.to_be_bytes());
        data.extend_from_slice(&self.genesis_time.to_be_bytes());

        // Validators in DECLARED order: the order is the PoA proposer rotation,
        // so two genesis files holding the same set in a different order are
        // different chains and must digest differently.
        data.extend_from_slice(&(self.validators.len() as u64).to_be_bytes());
        for pubkey in self.validator_pubkeys()? {
            data.extend_from_slice(&pubkey);
        }

        // Allocations in ascending address order: a `HashMap` has no order of
        // its own, so without sorting this digest would depend on iteration
        // order and two identical files would disagree.
        let mut alloc: Vec<_> = self.parsed_alloc()?;
        alloc.sort_by_key(|(addr, _)| *addr);
        data.extend_from_slice(&(alloc.len() as u64).to_be_bytes());
        for (addr, balance) in &alloc {
            data.extend_from_slice(addr.as_bytes());
            data.extend_from_slice(&balance.to_be_bytes());
        }

        for (name, height) in self.params.activation_heights() {
            data.extend_from_slice(&(name.len() as u64).to_be_bytes());
            data.extend_from_slice(name.as_bytes());
            match height {
                Some(h) => {
                    data.push(1);
                    data.extend_from_slice(&h.to_be_bytes());
                }
                None => data.push(0),
            }
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
        let config: NodeConfig =
            serde_json::from_str(&contents).map_err(|e| GenesisError::Json(e))?;
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
        assert_eq!(
            g.params.max_access_list_bytes,
            default_max_access_list_bytes()
        );
        assert_eq!(
            g.params.activation_grace_blocks,
            default_activation_grace_blocks()
        );
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
        let genesis = Genesis::new(1, 0, vec![], HashMap::new(), ChainParams::default());

        assert!(matches!(
            genesis.validate(),
            Err(GenesisError::NoValidators)
        ));
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

        assert!(matches!(
            genesis.validate(),
            Err(GenesisError::InvalidValidator(_))
        ));
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
        assert!(
            !json.contains("dispute_resolver"),
            "no resolver field: {json}"
        );
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
        assert_eq!(
            back.inference_settlement_consistency_enabled_from_height,
            None
        );
        // Explicit activation height round-trips.
        let mut p2 = ChainParams::default();
        p2.inference_settlement_consistency_enabled_from_height = Some(8_900_000);
        let json = serde_json::to_string(&p2).unwrap();
        let p3: ChainParams = serde_json::from_str(&json).unwrap();
        assert_eq!(
            p3.inference_settlement_consistency_enabled_from_height,
            Some(8_900_000)
        );
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
        assert_eq!(
            back.omninode_sponsored_attestation_enabled_from_height,
            None
        );
        let mut p2 = ChainParams::default();
        p2.omninode_sponsored_attestation_enabled_from_height = Some(9_100_000);
        let json = serde_json::to_string(&p2).unwrap();
        let p3: ChainParams = serde_json::from_str(&json).unwrap();
        assert_eq!(
            p3.omninode_sponsored_attestation_enabled_from_height,
            Some(9_100_000)
        );
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
        assert_eq!(
            p3.inference_verifier_bonding_enabled_from_height,
            Some(9_000_000)
        );
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
        assert!(
            serde_json::from_str::<ChainParams>(&bad).is_err(),
            "invalid base58 must reject"
        );
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

    // ─── Issue #118: dormant compute-pool / beacon activation-gate foundation ──
    //
    // These tests pin the AUTHORITATIVE-LOADER boundary. A `ChainParams`
    // deserialized in isolation (raw `serde_json::from_str::<ChainParams>`) may
    // still hold `Some(h)` for either gate — that is by design and is NOT what
    // these tests claim. The guarantee under test is that every genesis admitted
    // through `Genesis::from_json` / `Genesis::from_file` (which call
    // `Genesis::validate` → `ChainParams::validate`) rejects any `Some(_)` until
    // the gate's typed parameter surface exists. The real committed
    // `genesis/local_genesis.json` is used as the valid-genesis base so the
    // validator/alloc checks always pass and only the gate behavior is isolated.

    /// The committed local genesis, used as a valid base for gate mutation.
    const LOCAL_GENESIS_JSON: &str = include_str!("../../../genesis/local_genesis.json");

    /// Parse the committed local genesis into a mutable JSON value.
    fn local_genesis_value() -> serde_json::Value {
        serde_json::from_str(LOCAL_GENESIS_JSON).expect("local genesis is valid JSON")
    }

    // Test 1 — missing fields are accepted as `None` by the authoritative loader.
    #[test]
    fn foundation_gates_absent_default_to_none_and_loader_accepts() {
        // The committed local genesis carries neither key.
        assert!(!LOCAL_GENESIS_JSON.contains("compute_pool_enabled_from_height"));
        assert!(!LOCAL_GENESIS_JSON.contains("beacon_enabled_from_height"));
        let g = Genesis::from_json(LOCAL_GENESIS_JSON)
            .expect("committed local genesis must load through the authoritative loader");
        assert_eq!(g.params.compute_pool_enabled_from_height, None);
        assert_eq!(g.params.beacon_enabled_from_height, None);
    }

    // Test 2 — explicit JSON `null` is accepted as `None` by the loader.
    #[test]
    fn foundation_gates_explicit_null_decode_to_none_and_loader_accepts() {
        let mut v = local_genesis_value();
        v["params"]["compute_pool_enabled_from_height"] = serde_json::Value::Null;
        v["params"]["beacon_enabled_from_height"] = serde_json::Value::Null;
        let s = serde_json::to_string(&v).unwrap();
        let g = Genesis::from_json(&s).expect("explicit-null gates must load as None");
        assert_eq!(g.params.compute_pool_enabled_from_height, None);
        assert_eq!(g.params.beacon_enabled_from_height, None);
    }

    // Test 3a — `Some(0)` on compute-pool is rejected INDEPENDENTLY (beacon absent).
    #[test]
    fn foundation_compute_pool_some_zero_rejected_by_loader() {
        let mut v = local_genesis_value();
        v["params"]["compute_pool_enabled_from_height"] = serde_json::json!(0u64);
        let s = serde_json::to_string(&v).unwrap();
        match Genesis::from_json(&s) {
            Err(GenesisError::IncompleteSubsystemActivation { gate }) => {
                assert_eq!(gate, "compute_pool_enabled_from_height");
            }
            other => panic!("expected IncompleteSubsystemActivation, got {other:?}"),
        }
    }

    // Test 3b — `Some(0)` on beacon is rejected INDEPENDENTLY (compute-pool absent).
    #[test]
    fn foundation_beacon_some_zero_rejected_by_loader() {
        let mut v = local_genesis_value();
        v["params"]["beacon_enabled_from_height"] = serde_json::json!(0u64);
        let s = serde_json::to_string(&v).unwrap();
        match Genesis::from_json(&s) {
            Err(GenesisError::IncompleteSubsystemActivation { gate }) => {
                assert_eq!(gate, "beacon_enabled_from_height");
            }
            other => panic!("expected IncompleteSubsystemActivation, got {other:?}"),
        }
    }

    // Issue #127 Item 1a: the beacon PARAMS surface may be declared while the gate
    // stays dormant, but only if internally consistent (§7.4). Default is None.
    #[test]
    fn beacon_params_config_validation() {
        // Default genesis has no beacon params and a dormant gate.
        let g =
            Genesis::from_json(&serde_json::to_string(&local_genesis_value()).unwrap()).unwrap();
        assert_eq!(g.params.beacon_params, None);
        assert_eq!(g.params.beacon_enabled_from_height, None);

        // A VALID params config is accepted at load (gate still None).
        let valid = BeaconParamsConfig {
            f: 1,
            c: 1,
            t: 2,
            q_dkg: 3,
            n: 5,
        };
        assert!(valid.validate().is_ok());
        let mut v = local_genesis_value();
        v["params"]["beacon_params"] = serde_json::to_value(valid).unwrap();
        let g = Genesis::from_json(&serde_json::to_string(&v).unwrap()).unwrap();
        assert_eq!(g.params.beacon_params, Some(valid));
        assert_eq!(
            g.params.beacon_enabled_from_height, None,
            "params surface does NOT open the gate"
        );

        // An INVALID config (T < f+1) is rejected at load.
        let invalid = BeaconParamsConfig {
            f: 1,
            c: 1,
            t: 1,
            q_dkg: 3,
            n: 5,
        };
        assert!(invalid.validate().is_err());
        let mut v = local_genesis_value();
        v["params"]["beacon_params"] = serde_json::to_value(invalid).unwrap();
        assert!(matches!(
            Genesis::from_json(&serde_json::to_string(&v).unwrap()),
            Err(GenesisError::InvalidBeaconParams { .. })
        ));

        // Params present but gate Some ⇒ still rejected (gate cannot open yet).
        let mut v = local_genesis_value();
        v["params"]["beacon_params"] = serde_json::to_value(valid).unwrap();
        v["params"]["beacon_enabled_from_height"] = serde_json::json!(0u64);
        assert!(matches!(
            Genesis::from_json(&serde_json::to_string(&v).unwrap()),
            Err(GenesisError::IncompleteSubsystemActivation {
                gate: "beacon_enabled_from_height"
            })
        ));
    }

    // Test 4 — a future `Some(h)` is rejected too (not just `Some(0)`), per gate.
    #[test]
    fn foundation_gates_future_height_rejected_by_loader() {
        for gate in [
            "compute_pool_enabled_from_height",
            "beacon_enabled_from_height",
        ] {
            let mut v = local_genesis_value();
            v["params"][gate] = serde_json::json!(9_000_000u64);
            let s = serde_json::to_string(&v).unwrap();
            match Genesis::from_json(&s) {
                Err(GenesisError::IncompleteSubsystemActivation { gate: g }) => {
                    assert_eq!(g, gate);
                }
                other => panic!("expected IncompleteSubsystemActivation for {gate}, got {other:?}"),
            }
        }
    }

    // Test 5 — the existing committed genesis fixtures still load: this change
    //          never regresses any of them. Every committed fixture still
    //          deserializes with the two gates dormant (`None`), and NONE fails
    //          the authoritative loader because of the new gates
    //          (`IncompleteSubsystemActivation`). `testnet`/`mainnet` are
    //          placeholder templates whose *validator* keys are not real base58
    //          — they fail `validate()` for that pre-existing, unrelated reason,
    //          exactly as they did before this change — so full `from_file`
    //          admission is asserted only for `local`, which has real keys.
    #[test]
    fn foundation_existing_committed_genesis_fixtures_still_load() {
        for rel in [
            "/../../genesis/local_genesis.json",
            "/../../genesis/testnet_genesis.json",
            "/../../genesis/mainnet_genesis.json",
        ] {
            let path = format!("{}{}", env!("CARGO_MANIFEST_DIR"), rel);
            let contents = std::fs::read_to_string(&path).expect("fixture readable");
            // Still deserializes; the two new gates default to dormant `None`.
            let g: Genesis =
                serde_json::from_str(&contents).unwrap_or_else(|e| panic!("{path}: {e:?}"));
            assert_eq!(g.params.compute_pool_enabled_from_height, None, "{path}");
            assert_eq!(g.params.beacon_enabled_from_height, None, "{path}");
            // The authoritative loader never rejects a committed fixture *for the
            // new gates*. (It may reject placeholder templates for their existing
            // invalid validator keys — that predates and is unrelated to #118.)
            match Genesis::from_file(&path) {
                Ok(_)
                | Err(GenesisError::InvalidValidator(_))
                | Err(GenesisError::InvalidAddress(_)) => {}
                Err(GenesisError::IncompleteSubsystemActivation { gate }) => {
                    panic!("{path}: new gate '{gate}' must not reject a committed fixture")
                }
                Err(e) => panic!("{path}: unexpected pre-existing failure {e:?}"),
            }
        }
        // The real-validator fixture loads fully through the authoritative loader.
        let local = format!(
            "{}/../../genesis/local_genesis.json",
            env!("CARGO_MANIFEST_DIR")
        );
        let g = Genesis::from_file(&local).expect("local genesis must fully load");
        assert_eq!(g.params.compute_pool_enabled_from_height, None);
        assert_eq!(g.params.beacon_enabled_from_height, None);
    }

    // Test 6 — serialization round-trip preserves both `None` gate fields.
    #[test]
    fn foundation_default_serialization_round_trip_preserves_none_gates() {
        let p = ChainParams::default();
        assert_eq!(p.compute_pool_enabled_from_height, None);
        assert_eq!(p.beacon_enabled_from_height, None);
        let json = serde_json::to_string(&p).unwrap();
        // Both keys are emitted (a real round-trip, not a serde-default rescue).
        assert!(json.contains("compute_pool_enabled_from_height"));
        assert!(json.contains("beacon_enabled_from_height"));
        let back: ChainParams = serde_json::from_str(&json).unwrap();
        assert_eq!(back.compute_pool_enabled_from_height, None);
        assert_eq!(back.beacon_enabled_from_height, None);
    }

    // ── Sponsored registration activation gate (issue #145) ──────────────────

    // Default None; a pre-#145 genesis without the key decodes to None; an
    // explicit height round-trips.
    #[test]
    fn sponsored_registration_gate_default_none_absent_and_round_trip() {
        let p = ChainParams::default();
        assert_eq!(p.messaging_sponsored_registration_enabled_from_height, None);
        // Absent from an older genesis → serde default None.
        let mut value = serde_json::to_value(&p).unwrap();
        value
            .as_object_mut()
            .unwrap()
            .remove("messaging_sponsored_registration_enabled_from_height");
        let back: ChainParams = serde_json::from_value(value).unwrap();
        assert_eq!(
            back.messaging_sponsored_registration_enabled_from_height,
            None
        );
        // Explicit height round-trips.
        let p2 = ChainParams {
            messaging_sponsored_registration_enabled_from_height: Some(12_345_678),
            ..Default::default()
        };
        let json = serde_json::to_string(&p2).unwrap();
        let p3: ChainParams = serde_json::from_str(&json).unwrap();
        assert_eq!(
            p3.messaging_sponsored_registration_enabled_from_height,
            Some(12_345_678)
        );
    }

    // Explicit JSON `null` decodes to None (and the loader accepts it).
    #[test]
    fn sponsored_registration_gate_explicit_null_decodes_none() {
        let mut v = local_genesis_value();
        v["params"]["messaging_sponsored_registration_enabled_from_height"] =
            serde_json::Value::Null;
        let s = serde_json::to_string(&v).unwrap();
        let g = Genesis::from_json(&s).expect("explicit-null gate must load as None");
        assert_eq!(
            g.params
                .messaging_sponsored_registration_enabled_from_height,
            None
        );
    }

    // CRITICAL: unlike the dormant compute-pool / beacon gates, this is a
    // fully-implemented ACTIVATION gate — the authoritative loader MUST ACCEPT
    // `Some(h)` (it is deliberately NOT part of the reject-all `validate()`).
    #[test]
    fn sponsored_registration_gate_some_height_accepted_by_loader() {
        for h in [0u64, 9_000_000u64] {
            let mut v = local_genesis_value();
            v["params"]["messaging_sponsored_registration_enabled_from_height"] =
                serde_json::json!(h);
            let s = serde_json::to_string(&v).unwrap();
            let g = Genesis::from_json(&s).unwrap_or_else(|e| {
                panic!("activation gate Some({h}) must be accepted by the loader, got {e:?}")
            });
            assert_eq!(
                g.params
                    .messaging_sponsored_registration_enabled_from_height,
                Some(h)
            );
        }
    }

    // Serialization emits the key and round-trips None (a real round-trip, not a
    // serde-default rescue).
    #[test]
    fn sponsored_registration_gate_default_serialization_round_trip() {
        let p = ChainParams::default();
        let json = serde_json::to_string(&p).unwrap();
        assert!(json.contains("messaging_sponsored_registration_enabled_from_height"));
        let back: ChainParams = serde_json::from_str(&json).unwrap();
        assert_eq!(
            back.messaging_sponsored_registration_enabled_from_height,
            None
        );
    }

    // Every committed genesis fixture still loads AND leaves the gate dormant —
    // no committed genesis activates sponsored registration.
    #[test]
    fn committed_genesis_never_activates_sponsored_registration_gate() {
        for rel in [
            "/../../genesis/local_genesis.json",
            "/../../genesis/testnet_genesis.json",
            "/../../genesis/mainnet_genesis.json",
            "/../../genesis.json",
        ] {
            let path = format!("{}{}", env!("CARGO_MANIFEST_DIR"), rel);
            let contents = match std::fs::read_to_string(&path) {
                Ok(c) => c,
                Err(_) => continue, // not every layout ships every fixture
            };
            assert!(
                !contents.contains("messaging_sponsored_registration_enabled_from_height"),
                "{path}: committed genesis must not carry the sponsored-registration gate"
            );
            let g: Genesis =
                serde_json::from_str(&contents).unwrap_or_else(|e| panic!("{path}: {e:?}"));
            assert_eq!(
                g.params
                    .messaging_sponsored_registration_enabled_from_height,
                None,
                "{path}: gate must be dormant"
            );
        }
    }

    // Test 7 — the foundation adds NO activation / RPC / executor / state /
    //          template behavior: the gates are inert dormant fields validated
    //          fail-closed. `validate` takes `&self` (cannot mutate/activate),
    //          is pure, and accepts the dormant default. Nothing here introduces
    //          a `with_*_enabled` constructor, an activation predicate, a param
    //          struct, an `n_min` floor, a registry, or a `chain_getChainParams`
    //          surface — those remain deferred to their defining issues.
    #[test]
    fn foundation_adds_no_activation_or_runtime_behavior() {
        let p = ChainParams::default();
        // Dormant default is accepted; validation is pure (idempotent, no mutation).
        assert!(p.validate().is_ok());
        assert!(p.validate().is_ok());
        assert_eq!(p.compute_pool_enabled_from_height, None);
        assert_eq!(p.beacon_enabled_from_height, None);
        // A committed genesis loaded through the authoritative loader is admitted
        // with the gates dormant — no activation side effect occurs.
        let g = Genesis::from_json(LOCAL_GENESIS_JSON).unwrap();
        assert_eq!(g.params.compute_pool_enabled_from_height, None);
        assert_eq!(g.params.beacon_enabled_from_height, None);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // The undo-before-commitment ordering:
    //     application_journal_enabled_from_height <= account_root_enabled_from_height
    // ─────────────────────────────────────────────────────────────────────────

    /// Opening the account commitment while the journal gate is `None` is
    /// REFUSED at load.
    ///
    /// `None` is not "off" and it is not "always required": it means each node
    /// observes its own boundary from its own journal history. That is a
    /// node-local number. The account commitment is consensus output. Resting
    /// the second on the first is how two honest validators end up holding
    /// different boundaries and finding out at a reorg, which is precisely the
    /// failure this rejection exists to make unreachable.
    #[test]
    fn the_account_commitment_cannot_open_over_an_observed_journal_boundary() {
        let mut p = ChainParams::default();
        p.account_root_enabled_from_height = Some(1_000);
        p.application_journal_enabled_from_height = None;
        let err = p.validate().expect_err("None journal gate must be refused");
        assert!(
            matches!(
                err,
                GenesisError::AccountRootWithoutJournalGate {
                    account_root: 1_000
                }
            ),
            "{err}"
        );
        // And through the authoritative loader, not only the method.
        let mut g = Genesis::from_json(LOCAL_GENESIS_JSON).unwrap();
        g.params.account_root_enabled_from_height = Some(1_000);
        g.params.application_journal_enabled_from_height = None;
        assert!(
            g.validate().is_err(),
            "Genesis::validate must refuse it too"
        );
    }

    /// A journal gate LATER than the account gate is refused, naming the band.
    ///
    /// Heights in `[account_root, journal)` would commit account state to the
    /// block state root while their only undo record is the four legacy
    /// per-subsystem journals, which do not cover every family a block writes. A
    /// reorg into that band could neither revert nor agree.
    #[test]
    fn a_journal_gate_later_than_the_account_gate_is_refused() {
        let mut p = ChainParams::default();
        p.account_root_enabled_from_height = Some(1_000);
        p.application_journal_enabled_from_height = Some(1_001);
        let err = p
            .validate()
            .expect_err("later journal gate must be refused");
        assert!(
            matches!(
                err,
                GenesisError::JournalGateAfterAccountRoot {
                    journal: 1_001,
                    account_root: 1_000
                }
            ),
            "{err}"
        );
    }

    /// The legal orderings, including both `None` — which is the production
    /// default and must stay loadable.
    #[test]
    fn the_legal_gate_orderings_are_admitted() {
        for (journal, account_root) in [
            (None, None),               // production default: no commitment, no pin
            (Some(0), None),            // journal pinned, commitment still closed
            (Some(1_000), None),        // ditto, at a height
            (Some(1_000), Some(1_000)), // same height: the journal is authoritative
            // from the first block the root covers
            (Some(500), Some(1_000)), // journal strictly earlier
            (Some(0), Some(0)),       // both from genesis
        ] {
            let mut p = ChainParams::default();
            p.application_journal_enabled_from_height = journal;
            p.account_root_enabled_from_height = account_root;
            p.validate()
                .unwrap_or_else(|e| panic!("({journal:?}, {account_root:?}) must be legal: {e}"));
        }
    }

    /// Every committed genesis fixture satisfies the ordering.
    ///
    /// Not a restatement of the rule: it is the check that no shipped chain
    /// document is already inconsistent, which is the only way the rule could be
    /// true in code and false in production.
    #[test]
    fn every_committed_genesis_satisfies_the_gate_ordering() {
        for rel in [
            "/../../genesis/local_genesis.json",
            "/../../genesis/testnet_genesis.json",
            "/../../genesis/mainnet_genesis.json",
            "/../../genesis.json",
        ] {
            let path = format!("{}{}", env!("CARGO_MANIFEST_DIR"), rel);
            let contents = match std::fs::read_to_string(&path) {
                Ok(c) => c,
                Err(_) => continue,
            };
            let g: Genesis =
                serde_json::from_str(&contents).unwrap_or_else(|e| panic!("{path}: {e:?}"));
            // `params.validate()` and not `Genesis::validate()`: the shipped
            // testnet fixture carries placeholder validator keys, which is a
            // separate, deliberate fact about that file and not this rule.
            g.params
                .validate()
                .unwrap_or_else(|e| panic!("{path}: committed chain params must validate: {e}"));
            match (
                g.params.application_journal_enabled_from_height,
                g.params.account_root_enabled_from_height,
            ) {
                (_, None) => {}
                (Some(j), Some(a)) => assert!(j <= a, "{path}: journal gate {j} > account {a}"),
                (None, Some(a)) => panic!("{path}: account gate {a} over an observed journal"),
            }
        }
    }

    /// Both gates are CHAIN-DEFINED: they serialize into the genesis document,
    /// round-trip, and are therefore covered by whatever identity that document
    /// has. An operator cannot set one in genesis and the other somewhere else,
    /// because there is nowhere else to set either.
    #[test]
    fn both_gates_live_in_the_genesis_document_and_round_trip() {
        let mut g = Genesis::from_json(LOCAL_GENESIS_JSON).unwrap();
        g.params.application_journal_enabled_from_height = Some(500);
        g.params.account_root_enabled_from_height = Some(1_000);
        let json = g.to_json().unwrap();
        assert!(json.contains("application_journal_enabled_from_height"));
        assert!(json.contains("account_root_enabled_from_height"));
        let back = Genesis::from_json(&json).expect("a consistent pair round-trips and validates");
        assert_eq!(
            back.params.application_journal_enabled_from_height,
            Some(500)
        );
        assert_eq!(back.params.account_root_enabled_from_height, Some(1_000));

        // The loader is the enforcement point: an inconsistent document does not
        // parse into a usable Genesis at all.
        let bad = json.replace(
            "\"application_journal_enabled_from_height\": 500",
            "\"application_journal_enabled_from_height\": null",
        );
        assert_ne!(bad, json, "the substitution must actually apply");
        assert!(
            Genesis::from_json(&bad).is_err(),
            "an inconsistent genesis must be refused by the loader, not only by validate()"
        );
    }
}
