//! Canonical supply accounting + the one-time mainnet 800B supply correction
//! (protocol-reserve model). See `docs/architecture/economic-model.md`.
//!
//! **Monetary policy invariants**
//! - No automatic emissions (no block reward / inflation / staking mint).
//! - Initial canonical supply after the coordinated correction = 800B Koppa.
//! - The 799B correction delta is **not** credited to any account. It becomes
//!   non-transferable [`ProtocolReserve`] ledger supply, distributed only by
//!   implemented protocol rules (service grants) or released only by native
//!   Koppa consensus governance (6667 bps). It is never a single-controller
//!   treasury, never `Address::ZERO`, never a validator windfall.
//! - Future supply expansion beyond 800B requires a `MonetaryPolicyMint`
//!   governance action (NativeEligibility, 6667 bps) — nothing else can mint.
//!
//! **Canonical supply identity** (maintained, never a scan):
//! ```text
//! canonical_supply = Σ(account balances, incl Address::ZERO)
//!                  + protocol_reserve_remaining (all pools)
//!                  + outstanding_grant_unclaimed (liquid-unclaimed + locked-remaining)
//! ```
//! At migration: accounts = 1B, reserve = 799B, grants = 0 ⇒ canonical = 800B.

use serde::{Deserialize, Serialize};

use crate::Hash;

/// Base units per whole Koppa (9 decimals).
pub const KOPPA: u128 = 1_000_000_000;

/// Target initial canonical supply after the correction: 800B Koppa.
pub const TARGET_CANONICAL_SUPPLY: u128 = 800_000_000_000 * KOPPA; // 8.0e20 base units

/// Live mainnet accounted supply before the correction: exactly 1B Koppa
/// (genesis alloc, held by the two genesis validators). Verified from the
/// deployed genesis.
pub const GENESIS_ACCOUNTED_SUPPLY: u128 = 1_000_000_000 * KOPPA; // 1.0e18 base units

/// The one-time correction delta credited into the ProtocolReserve ledger.
pub const SUPPLY_CORRECTION_DELTA: u128 = TARGET_CANONICAL_SUPPLY - GENESIS_ACCOUNTED_SUPPLY; // 7.99e20

/// Only the mainnet chain (`chain_id == 1`) is eligible for the correction.
pub const MAINNET_CHAIN_ID: u64 = 1;

/// Domain string whose BLAKE3 hash is the deterministic migration id. The id is
/// bound into the persisted marker so an unrelated migration can never satisfy
/// the guard. `migration_id = BLAKE3(SUPPLY_CORRECTION_DOMAIN)`.
pub const SUPPLY_CORRECTION_DOMAIN: &[u8] =
    b"sumchain.mainnet.supply-correction.v1.800b.protocol-reserve";

/// The deterministic 32-byte migration id (`BLAKE3(SUPPLY_CORRECTION_DOMAIN)`):
/// `0x00a88daf2062e610b09b379b74aa6bc5a9557eb145618f46e9571428a4584a8f`.
pub fn supply_correction_migration_id() -> Hash {
    Hash::hash(SUPPLY_CORRECTION_DOMAIN)
}

// ── Pool allocations (base units). Σ MUST equal SUPPLY_CORRECTION_DELTA (799B). ──
/// Validator bootstrap grant pool.
pub const POOL_VALIDATOR: u128 = 80_000_000_000 * KOPPA;
/// Archive/storage service grant pool.
pub const POOL_ARCHIVE: u128 = 120_000_000_000 * KOPPA;
/// Compute/OmniNode service grant pool.
pub const POOL_COMPUTE: u128 = 120_000_000_000 * KOPPA;
/// Ecosystem / public-goods pool (governance-release only).
pub const POOL_ECOSYSTEM: u128 = 160_000_000_000 * KOPPA;
/// Long-term native-governance reserve (governance-release only).
pub const POOL_GOVERNANCE_RESERVE: u128 = 319_000_000_000 * KOPPA;

/// The non-transferable protocol reserve, split into service/governance pools.
/// Counted in canonical supply; only decreased by an implemented protocol rule
/// (service-grant reservation) or a governance release. Never an account.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProtocolReserve {
    pub validator_pool_remaining: u128,
    pub archive_pool_remaining: u128,
    pub compute_pool_remaining: u128,
    pub ecosystem_pool_remaining: u128,
    pub governance_reserve_remaining: u128,
}

impl ProtocolReserve {
    /// The pool split created by the one-time correction (sums to 799B).
    pub const fn initial() -> Self {
        Self {
            validator_pool_remaining: POOL_VALIDATOR,
            archive_pool_remaining: POOL_ARCHIVE,
            compute_pool_remaining: POOL_COMPUTE,
            ecosystem_pool_remaining: POOL_ECOSYSTEM,
            governance_reserve_remaining: POOL_GOVERNANCE_RESERVE,
        }
    }

    /// Total remaining across all pools. Checked add (pools are bounded well
    /// below u128 max, so this cannot overflow in practice).
    pub fn total_remaining(&self) -> u128 {
        self.validator_pool_remaining
            .saturating_add(self.archive_pool_remaining)
            .saturating_add(self.compute_pool_remaining)
            .saturating_add(self.ecosystem_pool_remaining)
            .saturating_add(self.governance_reserve_remaining)
    }

    /// Deterministic digest folded into the block state root so the reserve
    /// ledger is consensus-committed (the account-state root is balance-only and
    /// the reserve is not an account).
    pub fn digest(&self) -> Hash {
        Hash::hash_many(&[
            b"sumchain.protocol-reserve.v1",
            &self.validator_pool_remaining.to_be_bytes(),
            &self.archive_pool_remaining.to_be_bytes(),
            &self.compute_pool_remaining.to_be_bytes(),
            &self.ecosystem_pool_remaining.to_be_bytes(),
            &self.governance_reserve_remaining.to_be_bytes(),
        ])
    }
}

/// Persisted canonical-supply ledger (singleton). Maintained; never a scan.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SupplyLedger {
    /// Initial canonical supply after the correction (800B).
    pub initial_canonical_supply: u128,
    /// Amount minted into the reserve by the one-time correction (799B once done).
    pub total_minted_by_migration: u128,
    /// Amount minted by `MonetaryPolicyMint` governance actions (0 at genesis).
    pub total_minted_by_governance: u128,
    /// Whether the one-time correction has been applied.
    pub migration_applied: bool,
    /// The deterministic migration id bound into the marker.
    pub migration_id: Hash,
    /// Block height at which the correction was applied (0 if not applied).
    pub migration_activation_height: u64,
}

impl SupplyLedger {
    /// Pre-migration ledger (nothing minted yet; canonical == accounted 1B).
    pub fn pre_migration() -> Self {
        Self {
            initial_canonical_supply: GENESIS_ACCOUNTED_SUPPLY,
            total_minted_by_migration: 0,
            total_minted_by_governance: 0,
            migration_applied: false,
            migration_id: supply_correction_migration_id(),
            migration_activation_height: 0,
        }
    }

    /// Current canonical supply = initial + governance mints. (The migration
    /// mint is already folded into `initial_canonical_supply` once applied.)
    pub fn current_canonical_supply(&self) -> u128 {
        self.initial_canonical_supply
            .saturating_add(self.total_minted_by_governance)
    }

    /// Deterministic digest folded into the block state root.
    pub fn digest(&self) -> Hash {
        Hash::hash_many(&[
            b"sumchain.supply-ledger.v1",
            &self.initial_canonical_supply.to_be_bytes(),
            &self.total_minted_by_migration.to_be_bytes(),
            &self.total_minted_by_governance.to_be_bytes(),
            &[self.migration_applied as u8],
            self.migration_id.as_bytes(),
            &self.migration_activation_height.to_be_bytes(),
        ])
    }
}

/// Which protocol service a grant / earned-credit record belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum ServiceKind {
    Validator = 0,
    Archive = 1,
    Compute = 2,
}

impl ServiceKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            ServiceKind::Validator => "Validator",
            ServiceKind::Archive => "Archive",
            ServiceKind::Compute => "Compute",
        }
    }

    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            0 => Some(ServiceKind::Validator),
            1 => Some(ServiceKind::Archive),
            2 => Some(ServiceKind::Compute),
            _ => None,
        }
    }
}

// ── Genesis-validator exclusion (validator bootstrap grants only) ────────────
//
// The first two genesis validators already received 500M Koppa each at genesis;
// they get NO additional automatic validator-bootstrap grant. Both identity
// forms are excluded (account address and consensus pubkey) so there is no
// double-dip via either form. NOTE: this exclusion applies to VALIDATOR grants
// only — pre-existing archive nodes received no equivalent grant and remain
// fully eligible for archive service grants under the same rules as future
// archive nodes.

/// Base58 account addresses of the two genesis validators.
pub const GENESIS_VALIDATOR_ACCOUNTS: [&str; 2] = [
    "8zZ1pfbpUcAmoByWKYgJgiFZWpmhWQKJ4",
    "D7Ls8H7Y2jCqYEEUUxWUcgQkF9cKhHxjV",
];

/// Base58 consensus pubkeys of the two genesis validators.
pub const GENESIS_VALIDATOR_PUBKEYS: [&str; 2] = [
    "GW1pJKzqDmmHczMGz5g7CV51RgDuR6kKw76yZ1cVbEv8",
    "7jUZxm5rJ5PazGYkrtJ4sUJj7ztib2VHEoM2Yc4Liydy",
];

/// All excluded identity forms resolved to chain addresses (accounts, plus the
/// addresses derived from the consensus pubkeys). Infallible on the known
/// constants; unparseable entries are skipped rather than panicking consensus.
pub fn genesis_validator_excluded_addresses() -> Vec<crate::Address> {
    let mut out = Vec::with_capacity(4);
    for s in GENESIS_VALIDATOR_ACCOUNTS {
        if let Ok(a) = crate::Address::from_base58(s) {
            out.push(a);
        }
    }
    for s in GENESIS_VALIDATOR_PUBKEYS {
        if let Ok(bytes) = bs58::decode(s).into_vec() {
            if bytes.len() == 32 {
                let mut pk = [0u8; 32];
                pk.copy_from_slice(&bytes);
                out.push(crate::Address::from_public_key(&pk));
            }
        }
    }
    out
}

// ── Service-grant economics ──────────────────────────────────────────────────

/// Liquid share of every service grant, in basis points (10%). The remaining
/// 90% is locked service stake that unlocks 1:1 only against protocol-earned
/// Koppa ([`ServiceEarnedCredit`]-tracked rewards, never ordinary transfers).
pub const GRANT_LIQUID_BPS: u128 = 1_000;

/// Split a grant amount into (liquid, locked). Locked gets any rounding dust so
/// liquid never exceeds exactly 10%.
pub fn split_grant(total: u128) -> (u128, u128) {
    let liquid = total.saturating_mul(GRANT_LIQUID_BPS) / 10_000;
    (liquid, total.saturating_sub(liquid))
}

/// Declining validator bootstrap cohorts. `index` is the 0-based count of
/// validator grants issued so far (the two genesis validators are excluded
/// before this counter is consulted). Total cost if fully exhausted ≈ 3.42B —
/// far below the 80B validator pool.
pub fn validator_cohort_grant(index: u32) -> Option<u128> {
    match index {
        0..=9 => Some(5_000_000 * KOPPA),      // validators 3-12
        10..=97 => Some(2_500_000 * KOPPA),    // validators 13-100
        98..=997 => Some(1_000_000 * KOPPA),   // validators 101-1,000
        998..=9_997 => Some(250_000 * KOPPA),  // validators 1,001-10,000
        _ => None, // beyond 10,000: no automatic grant unless governance changes the schedule
    }
}

/// Archive service milestones (per archive identity, cumulative). Counting
/// starts at the LATER of registration and the supply-correction height — there
/// is no historical per-archive PoR counter on-chain, so nothing retroactive is
/// fabricated. Pre-existing archive nodes are fully eligible under these same
/// rules.
pub const ARCHIVE_ACTIVE_BLOCKS_MILESTONE: u64 = 201_600; // ~7 days at 3s blocks
pub const ARCHIVE_ACTIVE_GRANT: u128 = 25_000 * KOPPA;
pub const ARCHIVE_PROOFS_MILESTONE_1: u64 = 100;
pub const ARCHIVE_PROOFS_GRANT_1: u128 = 75_000 * KOPPA;
pub const ARCHIVE_PROOFS_MILESTONE_2: u64 = 1_000;
pub const ARCHIVE_PROOFS_GRANT_2: u128 = 250_000 * KOPPA;

/// Compute/OmniNode verifier milestones (per verifier identity, cumulative,
/// counted from the supply-correction height).
pub const COMPUTE_CLAIMS_MILESTONE_1: u64 = 1;
pub const COMPUTE_CLAIMS_GRANT_1: u128 = 10_000 * KOPPA;
pub const COMPUTE_CLAIMS_MILESTONE_2: u64 = 100;
pub const COMPUTE_CLAIMS_GRANT_2: u128 = 90_000 * KOPPA;

/// A per-(address, service) grant ledger record. `total_grant` accumulates the
/// bootstrap/milestone grants awarded; `locked_remaining` is the service-locked
/// portion (forfeitable back to the ProtocolReserve on slashing / service
/// failure); `earned_credit_used_for_unlock` is how much protocol-earned credit
/// has already been consumed by unlocks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceGrant {
    pub recipient: crate::Address,
    pub service_kind: ServiceKind,
    pub total_grant: u128,
    pub liquid_claimed: u128,
    pub locked_remaining: u128,
    pub earned_credit_used_for_unlock: u128,
    pub created_at_height: u64,
    pub status: GrantStatus,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum GrantStatus {
    Active = 0,
    Suspended = 1,
    Forfeited = 2,
    Completed = 3,
}

/// Per-(address, service) verifiable service counters. All fields count only
/// events at/after the supply correction (no retroactive fabrication).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct ServiceMilestones {
    /// Successful PoR proofs (archive) — incremented at the proof-payout site.
    pub por_proofs: u64,
    /// Valid settlement claims (compute) — incremented at the claim-payout site.
    pub settlement_claims: u64,
    /// Denied disputes (compute) — blocks further milestone claims.
    pub denied_disputes: u64,
    /// Milestone amounts already awarded (so each milestone pays exactly once).
    pub awarded: u128,
}

/// Aggregate grant/credit counters (singleton), folded into the supply digest
/// so the canonical-supply identity is consensus-committed without per-address
/// scans. `outstanding_grant_unclaimed` = Σ(liquid unclaimed + locked remaining)
/// across all grants.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct GrantsAggregate {
    pub outstanding_grant_unclaimed: u128,
    pub total_granted: u128,
    pub total_forfeited_to_reserve: u128,
    pub total_earned_validator: u128,
    pub total_earned_archive: u128,
    pub total_earned_compute: u128,
}

impl GrantsAggregate {
    pub fn digest(&self) -> Hash {
        Hash::hash_many(&[
            b"sumchain.grants-aggregate.v1",
            &self.outstanding_grant_unclaimed.to_be_bytes(),
            &self.total_granted.to_be_bytes(),
            &self.total_forfeited_to_reserve.to_be_bytes(),
            &self.total_earned_validator.to_be_bytes(),
            &self.total_earned_archive.to_be_bytes(),
            &self.total_earned_compute.to_be_bytes(),
        ])
    }
}

/// Governance reserve-release audit record (append-only).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReserveReleaseEvent {
    pub proposal_id: [u8; 32],
    pub pool: ReservePool,
    pub recipient: crate::Address,
    pub amount: u128,
    pub reason_hash: Hash,
    pub height: u64,
}

/// Governance monetary-mint audit record (append-only). Only ever produced by a
/// passed `MonetaryPolicyMint` NativeEligibility proposal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MonetaryPolicyEvent {
    pub proposal_id: [u8; 32],
    pub recipient: crate::Address,
    pub amount: u128,
    pub reason_hash: Hash,
    pub height: u64,
}

/// Which reserve pool a governance release draws from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum ReservePool {
    Ecosystem = 0,
    GovernanceReserve = 1,
}

// ── Wire: supply/service-grant transactions (TxType 26, append-only) ─────────

/// Supply subprotocol operations. All are dormant-gated
/// (`service_grants_enabled_from_height`, default `None`) and rejected free
/// (`Failed(380)`, no fee, no state) while the gate is closed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SupplyOperation {
    /// Claim the validator bootstrap grant / any newly-reached archive or
    /// compute milestone grants for the sender. Awards are split 10% liquid
    /// (credited immediately) / 90% locked service stake.
    ClaimServiceGrant { service_kind: ServiceKind },
    /// Unlock locked grant stake 1:1 against protocol-earned credit and credit
    /// it to the sender.
    UnlockServiceGrant { service_kind: ServiceKind },
}

/// Transaction payload wrapper for [`SupplyOperation`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SupplyTxData {
    pub operation: SupplyOperation,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn supply_math_is_exact() {
        assert_eq!(TARGET_CANONICAL_SUPPLY, 800_000_000_000_000_000_000);
        assert_eq!(GENESIS_ACCOUNTED_SUPPLY, 1_000_000_000_000_000_000);
        assert_eq!(SUPPLY_CORRECTION_DELTA, 799_000_000_000_000_000_000);
    }

    #[test]
    fn pools_sum_to_delta() {
        assert_eq!(ProtocolReserve::initial().total_remaining(), SUPPLY_CORRECTION_DELTA);
    }

    #[test]
    fn migration_id_is_domain_blake3() {
        // 0x00a88daf2062e610b09b379b74aa6bc5a9557eb145618f46e9571428a4584a8f
        assert_eq!(
            supply_correction_migration_id().to_hex(),
            "0x00a88daf2062e610b09b379b74aa6bc5a9557eb145618f46e9571428a4584a8f"
        );
    }

    #[test]
    fn canonical_supply_tracks_governance_mint() {
        let mut l = SupplyLedger::pre_migration();
        l.initial_canonical_supply = TARGET_CANONICAL_SUPPLY;
        assert_eq!(l.current_canonical_supply(), TARGET_CANONICAL_SUPPLY);
        l.total_minted_by_governance = 5 * KOPPA;
        assert_eq!(l.current_canonical_supply(), TARGET_CANONICAL_SUPPLY + 5 * KOPPA);
    }
}
