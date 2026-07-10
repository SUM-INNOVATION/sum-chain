//! Canonical-supply accounting + the one-time mainnet 800B supply correction.
//!
//! The correction moves the chain from its live 1B accounted supply to an 800B
//! canonical supply by initializing a non-transferable [`ProtocolReserve`] with
//! the 799B delta. **No account balance changes** — the reserve is a ledger, not
//! an account. It runs at most once, guarded, before the block state root, and
//! its ledger is folded into that root so all nodes agree it happened.
//!
//! See [`sumchain_primitives::supply`] for the invariants and constants.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use sumchain_primitives::supply::{
    genesis_validator_excluded_addresses, split_grant, supply_correction_migration_id,
    validator_cohort_grant, GrantStatus, GrantsAggregate, MigrationWithheldReason,
    MonetaryPolicyEvent, NativeSupplySnapshot, ProtocolReserve, ReservePool, ReserveReleaseEvent,
    ServiceGrant, ServiceKind, ServiceMilestones, SupplyLedger, ARCHIVE_ACTIVE_BLOCKS_MILESTONE,
    ARCHIVE_ACTIVE_GRANT, ARCHIVE_PROOFS_GRANT_1, ARCHIVE_PROOFS_GRANT_2, ARCHIVE_PROOFS_MILESTONE_1,
    ARCHIVE_PROOFS_MILESTONE_2, COMPUTE_CLAIMS_GRANT_1, COMPUTE_CLAIMS_GRANT_2,
    COMPUTE_CLAIMS_MILESTONE_1, COMPUTE_CLAIMS_MILESTONE_2, MAINNET_CHAIN_ID, TARGET_CANONICAL_SUPPLY,
};
use sumchain_primitives::{Address, Hash, NodeRole, NodeStatus};
use sumchain_storage::{cf, Database, DelegationStore, StakingStore, StateStore};

use crate::{Result, StateError};

const LEDGER_KEY: &[u8] = b"ledger";
const RESERVE_KEY: &[u8] = b"reserve";
const AGGREGATE_KEY: &[u8] = b"aggregate";
const COHORT_KEY: &[u8] = b"validator_cohort";

/// Prefixed key: `b'G' || address(20) || kind(1)` — grant record.
fn grant_key(addr: &Address, kind: ServiceKind) -> Vec<u8> {
    let mut k = Vec::with_capacity(22);
    k.push(b'G');
    k.extend_from_slice(addr.as_bytes());
    k.push(kind as u8);
    k
}
/// Prefixed key: `b'E' || address(20) || kind(1)` — cumulative earned credit.
fn credit_key(addr: &Address, kind: ServiceKind) -> Vec<u8> {
    let mut k = Vec::with_capacity(22);
    k.push(b'E');
    k.extend_from_slice(addr.as_bytes());
    k.push(kind as u8);
    k
}
/// Prefixed key: `b'M' || address(20) || kind(1)` — service milestones.
fn milestone_key(addr: &Address, kind: ServiceKind) -> Vec<u8> {
    let mut k = Vec::with_capacity(22);
    k.push(b'M');
    k.extend_from_slice(addr.as_bytes());
    k.push(kind as u8);
    k
}
/// Prefixed key: `b'R' || proposal_id(32)` — reserve-release audit events
/// (unique: a proposal executes exactly once).
fn release_event_key(proposal_id: &[u8; 32]) -> Vec<u8> {
    let mut k = Vec::with_capacity(33);
    k.push(b'R');
    k.extend_from_slice(proposal_id);
    k
}
/// Prefixed key: `b'P' || proposal_id(32)` — monetary-policy audit events.
fn mint_event_key(proposal_id: &[u8; 32]) -> Vec<u8> {
    let mut k = Vec::with_capacity(33);
    k.push(b'P');
    k.extend_from_slice(proposal_id);
    k
}

/// Read/write access to the singleton supply ledger + protocol reserve.
pub struct SupplyStore {
    db: Arc<Database>,
}

impl SupplyStore {
    pub fn new(db: Arc<Database>) -> Self {
        Self { db }
    }

    /// The supply ledger, defaulting to the pre-migration ledger when absent.
    pub fn get_ledger(&self) -> Result<SupplyLedger> {
        match self.db.get(cf::SUPPLY, LEDGER_KEY)? {
            None => Ok(SupplyLedger::pre_migration()),
            Some(bytes) => bincode::deserialize(&bytes)
                .map_err(|e| StateError::DeserializationError(e.to_string())),
        }
    }

    fn put_ledger(&self, ledger: &SupplyLedger) -> Result<()> {
        let bytes =
            bincode::serialize(ledger).map_err(|e| StateError::SerializationError(e.to_string()))?;
        self.db.put(cf::SUPPLY, LEDGER_KEY, &bytes).map_err(StateError::Storage)
    }

    /// The protocol reserve, or `None` before the correction is applied.
    pub fn get_reserve(&self) -> Result<Option<ProtocolReserve>> {
        match self.db.get(cf::SUPPLY, RESERVE_KEY)? {
            None => Ok(None),
            Some(bytes) => bincode::deserialize(&bytes)
                .map(Some)
                .map_err(|e| StateError::DeserializationError(e.to_string())),
        }
    }

    fn put_reserve(&self, reserve: &ProtocolReserve) -> Result<()> {
        let bytes = bincode::serialize(reserve)
            .map_err(|e| StateError::SerializationError(e.to_string()))?;
        self.db.put(cf::SUPPLY, RESERVE_KEY, &bytes).map_err(StateError::Storage)
    }

    pub fn is_migration_applied(&self) -> Result<bool> {
        Ok(self.get_ledger()?.migration_applied)
    }

    /// Deterministic digest of the supply state, folded into the block state
    /// root **once the correction is applied** (the reserve is not an account,
    /// so the balance-only account root would otherwise miss it). Returns `None`
    /// while dormant so pre-correction blocks keep their exact prior root.
    pub fn state_digest(&self) -> Result<Option<Hash>> {
        let ledger = self.get_ledger()?;
        if !ledger.migration_applied {
            return Ok(None);
        }
        let reserve = self.get_reserve()?.unwrap_or_else(ProtocolReserve::initial);
        let aggregate = self.get_aggregate()?;
        Ok(Some(Hash::hash_many(&[
            b"sumchain.supply.v1",
            ledger.digest().as_bytes(),
            reserve.digest().as_bytes(),
            aggregate.digest().as_bytes(),
        ])))
    }

    // ── Grants aggregate (singleton, digest-folded) ──────────────────────────

    pub fn get_aggregate(&self) -> Result<GrantsAggregate> {
        match self.db.get(cf::SUPPLY, AGGREGATE_KEY)? {
            None => Ok(GrantsAggregate::default()),
            Some(bytes) => bincode::deserialize(&bytes)
                .map_err(|e| StateError::DeserializationError(e.to_string())),
        }
    }

    fn put_aggregate(&self, agg: &GrantsAggregate) -> Result<()> {
        let bytes =
            bincode::serialize(agg).map_err(|e| StateError::SerializationError(e.to_string()))?;
        self.db.put(cf::SUPPLY, AGGREGATE_KEY, &bytes).map_err(StateError::Storage)
    }

    // ── Per-address records ──────────────────────────────────────────────────

    pub fn get_grant(&self, addr: &Address, kind: ServiceKind) -> Result<Option<ServiceGrant>> {
        match self.db.get(cf::SUPPLY, &grant_key(addr, kind))? {
            None => Ok(None),
            Some(bytes) => bincode::deserialize(&bytes)
                .map(Some)
                .map_err(|e| StateError::DeserializationError(e.to_string())),
        }
    }

    fn put_grant(&self, grant: &ServiceGrant) -> Result<()> {
        let bytes =
            bincode::serialize(grant).map_err(|e| StateError::SerializationError(e.to_string()))?;
        self.db
            .put(cf::SUPPLY, &grant_key(&grant.recipient, grant.service_kind), &bytes)
            .map_err(StateError::Storage)
    }

    pub fn get_earned_credit(&self, addr: &Address, kind: ServiceKind) -> Result<u128> {
        match self.db.get(cf::SUPPLY, &credit_key(addr, kind))? {
            None => Ok(0),
            Some(bytes) => bincode::deserialize(&bytes)
                .map_err(|e| StateError::DeserializationError(e.to_string())),
        }
    }

    pub fn get_milestones(&self, addr: &Address, kind: ServiceKind) -> Result<ServiceMilestones> {
        match self.db.get(cf::SUPPLY, &milestone_key(addr, kind))? {
            None => Ok(ServiceMilestones::default()),
            Some(bytes) => bincode::deserialize(&bytes)
                .map_err(|e| StateError::DeserializationError(e.to_string())),
        }
    }

    fn put_milestones(&self, addr: &Address, kind: ServiceKind, m: &ServiceMilestones) -> Result<()> {
        let bytes =
            bincode::serialize(m).map_err(|e| StateError::SerializationError(e.to_string()))?;
        self.db.put(cf::SUPPLY, &milestone_key(addr, kind), &bytes).map_err(StateError::Storage)
    }

    pub fn validator_cohort_count(&self) -> Result<u32> {
        match self.db.get(cf::SUPPLY, COHORT_KEY)? {
            None => Ok(0),
            Some(bytes) => bincode::deserialize(&bytes)
                .map_err(|e| StateError::DeserializationError(e.to_string())),
        }
    }

    // ── Earned-credit / milestone accrual (instrumented reward sites only) ───
    //
    // Called ONLY from the three real protocol reward sites (block fees →
    // proposer, PoR payout → archive, settlement claim → verifier), and only
    // once the correction is applied. Ordinary transfers, genesis balances,
    // migration reserve, and governance releases NEVER reach these methods, so
    // "transfers don't count" is structural.

    /// Accrue protocol-earned credit for `addr` under `kind`. No-op while the
    /// correction is dormant (deterministic across the coordinated upgrade).
    pub fn accrue_earned_credit(&self, addr: &Address, kind: ServiceKind, amount: u128) -> Result<()> {
        if amount == 0 || !self.is_migration_applied()? {
            return Ok(());
        }
        let cur = self.get_earned_credit(addr, kind)?;
        let new = cur
            .checked_add(amount)
            .ok_or_else(|| StateError::BlockValidation("earned credit overflow".into()))?;
        let bytes =
            bincode::serialize(&new).map_err(|e| StateError::SerializationError(e.to_string()))?;
        self.db.put(cf::SUPPLY, &credit_key(addr, kind), &bytes).map_err(StateError::Storage)?;

        let mut agg = self.get_aggregate()?;
        match kind {
            ServiceKind::Validator => agg.total_earned_validator = agg.total_earned_validator.saturating_add(amount),
            ServiceKind::Archive => agg.total_earned_archive = agg.total_earned_archive.saturating_add(amount),
            ServiceKind::Compute => agg.total_earned_compute = agg.total_earned_compute.saturating_add(amount),
        }
        self.put_aggregate(&agg)
    }

    /// Record one successful archive PoR proof (milestone counter). No-op while
    /// dormant — counting starts at the correction height, never retroactively.
    pub fn record_por_proof(&self, addr: &Address) -> Result<()> {
        if !self.is_migration_applied()? {
            return Ok(());
        }
        let mut m = self.get_milestones(addr, ServiceKind::Archive)?;
        m.por_proofs = m.por_proofs.saturating_add(1);
        self.put_milestones(addr, ServiceKind::Archive, &m)
    }

    /// Record one valid settlement claim (compute milestone counter).
    pub fn record_settlement_claim(&self, addr: &Address) -> Result<()> {
        if !self.is_migration_applied()? {
            return Ok(());
        }
        let mut m = self.get_milestones(addr, ServiceKind::Compute)?;
        m.settlement_claims = m.settlement_claims.saturating_add(1);
        self.put_milestones(addr, ServiceKind::Compute, &m)
    }

    /// Record a denied dispute against a verifier — blocks further compute
    /// milestone claims.
    pub fn record_denied_dispute(&self, addr: &Address) -> Result<()> {
        if !self.is_migration_applied()? {
            return Ok(());
        }
        let mut m = self.get_milestones(addr, ServiceKind::Compute)?;
        m.denied_disputes = m.denied_disputes.saturating_add(1);
        self.put_milestones(addr, ServiceKind::Compute, &m)
    }

    // ── Grant award / claim / unlock / forfeit ───────────────────────────────

    /// Award `amount` from `kind`'s pool to `addr` as a new/extended grant.
    /// Splits 10% liquid (returned for immediate account credit) / 90% locked.
    /// Checked against the pool: a grant can never exceed the remaining pool.
    fn award_grant(
        &self,
        addr: &Address,
        kind: ServiceKind,
        amount: u128,
        height: u64,
    ) -> Result<u128> {
        // Decrement the pool (checked — fail if insufficient).
        let mut reserve = self
            .get_reserve()?
            .ok_or_else(|| StateError::InvalidOperation("protocol reserve not initialized".into()))?;
        let pool = match kind {
            ServiceKind::Validator => &mut reserve.validator_pool_remaining,
            ServiceKind::Archive => &mut reserve.archive_pool_remaining,
            ServiceKind::Compute => &mut reserve.compute_pool_remaining,
        };
        *pool = pool
            .checked_sub(amount)
            .ok_or_else(|| StateError::InvalidOperation("grant exceeds remaining pool".into()))?;
        self.put_reserve(&reserve)?;

        let (liquid, locked) = split_grant(amount);
        let mut grant = self.get_grant(addr, kind)?.unwrap_or(ServiceGrant {
            recipient: *addr,
            service_kind: kind,
            total_grant: 0,
            liquid_claimed: 0,
            locked_remaining: 0,
            earned_credit_used_for_unlock: 0,
            created_at_height: height,
            status: GrantStatus::Active,
        });
        grant.total_grant = grant.total_grant.saturating_add(amount);
        grant.liquid_claimed = grant.liquid_claimed.saturating_add(liquid);
        grant.locked_remaining = grant.locked_remaining.saturating_add(locked);
        self.put_grant(&grant)?;

        // Aggregate: pool → (liquid leaves reserve+grants entirely: it is
        // credited to the account by the caller; locked stays outstanding).
        let mut agg = self.get_aggregate()?;
        agg.total_granted = agg.total_granted.saturating_add(amount);
        agg.outstanding_grant_unclaimed = agg.outstanding_grant_unclaimed.saturating_add(locked);
        self.put_aggregate(&agg)?;
        Ok(liquid)
    }

    /// Claim the validator bootstrap grant for `addr`. Enforces: registry-based
    /// eligibility (an **Active staking-module validator** whose pubkey-derived
    /// address is the claimer — code reality: the node registry rejects
    /// Validator registrations; validators register through the staking
    /// module), genesis-validator exclusion (both identity forms), one grant
    /// per identity, declining cohorts, pool bound. The lookup iterates the
    /// staking validator set, which is bounded by consensus size — not a
    /// files×anything scan. Returns the liquid amount to credit.
    pub fn claim_validator_grant(
        &self,
        db: &Arc<Database>,
        addr: &Address,
        height: u64,
    ) -> std::result::Result<u128, u32> {
        // Excluded genesis identities (accounts + pubkey-derived) → 382.
        if genesis_validator_excluded_addresses().iter().any(|a| a == addr) {
            return Err(382);
        }
        // Eligibility: an Active staking validator whose pubkey derives to the
        // claimer address (one grant per validator identity — the pubkey and
        // its derived address are the same identity).
        let staking = sumchain_storage::StakingStore::new(db);
        let validators = staking.get_all_validators().map_err(|_| 381u32)?;
        let is_active_validator = validators.iter().any(|v| {
            v.status == sumchain_primitives::ValidatorStatus::Active
                && Address::from_public_key(&v.pubkey) == *addr
        });
        if !is_active_validator {
            return Err(381);
        }
        // One grant per identity → 383.
        if matches!(self.get_grant(addr, ServiceKind::Validator), Ok(Some(_))) {
            return Err(383);
        }
        // Declining cohort schedule; beyond the schedule → 385.
        let index = self.validator_cohort_count().map_err(|_| 385u32)?;
        let amount = validator_cohort_grant(index).ok_or(385u32)?;
        let liquid = self.award_grant(addr, ServiceKind::Validator, amount, height).map_err(|_| 385u32)?;
        let bytes = bincode::serialize(&(index + 1)).map_err(|_| 385u32)?;
        self.db.put(cf::SUPPLY, COHORT_KEY, &bytes).map_err(|_| 385u32)?;
        Ok(liquid)
    }

    /// Claim newly-reached archive/compute milestone grants for `addr`.
    /// Milestones pay exactly once (tracked via `awarded`); a suspended or
    /// forfeited grant cannot claim; compute claims are blocked by any denied
    /// dispute. Returns the liquid amount to credit (0 ⇒ nothing new → 383).
    pub fn claim_milestone_grants(
        &self,
        db: &Arc<Database>,
        addr: &Address,
        kind: ServiceKind,
        height: u64,
    ) -> std::result::Result<u128, u32> {
        if kind == ServiceKind::Validator {
            return Err(381); // validator uses the bootstrap cohort path
        }
        // Grant must not be suspended/forfeited.
        if let Ok(Some(g)) = self.get_grant(addr, kind) {
            if g.status != GrantStatus::Active {
                return Err(386);
            }
        }
        let m = self.get_milestones(addr, kind).map_err(|_| 381u32)?;
        let registry = crate::node_registry::NodeRegistryExecutor::new(db.clone());
        let node = registry.get_node(addr).ok().flatten();

        let mut reached: u128 = 0;
        match kind {
            ServiceKind::Archive => {
                // Must be a currently-active archive node.
                let rec = match &node {
                    Some(r) if r.role == NodeRole::ArchiveNode && r.status == NodeStatus::Active => r,
                    _ => return Err(381),
                };
                // Active-duration milestone counts from the LATER of registration
                // and the correction height — nothing retroactive is fabricated.
                let ledger = self.get_ledger().map_err(|_| 381u32)?;
                let active_since = rec.registered_at.max(ledger.migration_activation_height);
                if height.saturating_sub(active_since) >= ARCHIVE_ACTIVE_BLOCKS_MILESTONE {
                    reached = reached.saturating_add(ARCHIVE_ACTIVE_GRANT);
                }
                if m.por_proofs >= ARCHIVE_PROOFS_MILESTONE_1 {
                    reached = reached.saturating_add(ARCHIVE_PROOFS_GRANT_1);
                }
                if m.por_proofs >= ARCHIVE_PROOFS_MILESTONE_2 {
                    reached = reached.saturating_add(ARCHIVE_PROOFS_GRANT_2);
                }
            }
            ServiceKind::Compute => {
                // Denied disputes block further compute milestone claims.
                if m.denied_disputes > 0 {
                    return Err(386);
                }
                if m.settlement_claims >= COMPUTE_CLAIMS_MILESTONE_1 {
                    reached = reached.saturating_add(COMPUTE_CLAIMS_GRANT_1);
                }
                if m.settlement_claims >= COMPUTE_CLAIMS_MILESTONE_2 {
                    reached = reached.saturating_add(COMPUTE_CLAIMS_GRANT_2);
                }
            }
            ServiceKind::Validator => unreachable!("guarded above"),
        }
        let newly = reached.saturating_sub(m.awarded);
        if newly == 0 {
            return Err(383);
        }
        let liquid = self.award_grant(addr, kind, newly, height).map_err(|_| 385u32)?;
        let mut m2 = m;
        m2.awarded = reached;
        self.put_milestones(addr, kind, &m2).map_err(|_| 385u32)?;
        Ok(liquid)
    }

    /// Unlock locked grant stake 1:1 against protocol-earned credit. Returns
    /// the unlocked amount to credit (Err(384) when nothing is unlockable).
    pub fn unlock_grant(&self, addr: &Address, kind: ServiceKind) -> std::result::Result<u128, u32> {
        let mut grant = match self.get_grant(addr, kind) {
            Ok(Some(g)) => g,
            _ => return Err(383),
        };
        if grant.status != GrantStatus::Active {
            return Err(386);
        }
        let earned = self.get_earned_credit(addr, kind).map_err(|_| 384u32)?;
        let available_credit = earned.saturating_sub(grant.earned_credit_used_for_unlock);
        let unlockable = grant.locked_remaining.min(available_credit);
        if unlockable == 0 {
            return Err(384);
        }
        grant.locked_remaining -= unlockable;
        grant.earned_credit_used_for_unlock =
            grant.earned_credit_used_for_unlock.saturating_add(unlockable);
        if grant.locked_remaining == 0 {
            grant.status = GrantStatus::Completed;
        }
        self.put_grant(&grant).map_err(|_| 384u32)?;
        let mut agg = self.get_aggregate().map_err(|_| 384u32)?;
        agg.outstanding_grant_unclaimed = agg.outstanding_grant_unclaimed.saturating_sub(unlockable);
        self.put_aggregate(&agg).map_err(|_| 384u32)?;
        Ok(unlockable)
    }

    /// Forfeit an address's remaining locked grant back to its service pool
    /// (slashing / service failure). Grant-derived locked stake is public
    /// reserve money — an operator cannot claim it and exit. No-op if no
    /// active grant or nothing locked.
    pub fn forfeit_locked_grant(&self, addr: &Address, kind: ServiceKind) -> Result<()> {
        let mut grant = match self.get_grant(addr, kind)? {
            Some(g) if g.status == GrantStatus::Active && g.locked_remaining > 0 => g,
            _ => return Ok(()),
        };
        let forfeited = grant.locked_remaining;
        grant.locked_remaining = 0;
        grant.status = GrantStatus::Forfeited;
        self.put_grant(&grant)?;

        // Return the locked portion to the originating pool.
        let mut reserve = self
            .get_reserve()?
            .ok_or_else(|| StateError::InvalidOperation("protocol reserve not initialized".into()))?;
        match kind {
            ServiceKind::Validator => {
                reserve.validator_pool_remaining = reserve.validator_pool_remaining.saturating_add(forfeited)
            }
            ServiceKind::Archive => {
                reserve.archive_pool_remaining = reserve.archive_pool_remaining.saturating_add(forfeited)
            }
            ServiceKind::Compute => {
                reserve.compute_pool_remaining = reserve.compute_pool_remaining.saturating_add(forfeited)
            }
        }
        self.put_reserve(&reserve)?;

        let mut agg = self.get_aggregate()?;
        agg.outstanding_grant_unclaimed = agg.outstanding_grant_unclaimed.saturating_sub(forfeited);
        agg.total_forfeited_to_reserve = agg.total_forfeited_to_reserve.saturating_add(forfeited);
        self.put_aggregate(&agg)
    }

    // ── Governance reserve release / monetary mint (executor-called only) ────

    /// Apply a passed NativeEligibility `ReserveRelease` proposal: pool →
    /// recipient account. Canonical supply unchanged. Records an audit event.
    pub fn apply_reserve_release(
        &self,
        pool: ReservePool,
        recipient: &Address,
        amount: u128,
        proposal_id: [u8; 32],
        reason_hash: Hash,
        height: u64,
    ) -> Result<()> {
        let mut reserve = self
            .get_reserve()?
            .ok_or_else(|| StateError::InvalidOperation("protocol reserve not initialized".into()))?;
        let slot = match pool {
            ReservePool::Ecosystem => &mut reserve.ecosystem_pool_remaining,
            ReservePool::GovernanceReserve => &mut reserve.governance_reserve_remaining,
        };
        *slot = slot
            .checked_sub(amount)
            .ok_or_else(|| StateError::InvalidOperation("release exceeds remaining pool".into()))?;
        self.put_reserve(&reserve)?;
        let ev = ReserveReleaseEvent { proposal_id, pool, recipient: *recipient, amount, reason_hash, height };
        let bytes = bincode::serialize(&ev).map_err(|e| StateError::SerializationError(e.to_string()))?;
        self.db.put(cf::SUPPLY, &release_event_key(&proposal_id), &bytes).map_err(StateError::Storage)
    }

    /// Apply a passed NativeEligibility `MonetaryPolicyMint` proposal: canonical
    /// supply grows by `amount`; recipient is credited by the caller. Records an
    /// audit event. The ONLY path that increases canonical supply beyond 800B.
    pub fn apply_monetary_mint(
        &self,
        recipient: &Address,
        amount: u128,
        proposal_id: [u8; 32],
        reason_hash: Hash,
        height: u64,
    ) -> Result<()> {
        let mut ledger = self.get_ledger()?;
        if !ledger.migration_applied {
            return Err(StateError::InvalidOperation("supply correction not applied".into()));
        }
        ledger.total_minted_by_governance = ledger
            .total_minted_by_governance
            .checked_add(amount)
            .ok_or_else(|| StateError::BlockValidation("governance mint overflow".into()))?;
        self.put_ledger(&ledger)?;
        let ev = MonetaryPolicyEvent { proposal_id, recipient: *recipient, amount, reason_hash, height };
        let bytes = bincode::serialize(&ev).map_err(|e| StateError::SerializationError(e.to_string()))?;
        self.db.put(cf::SUPPLY, &mint_event_key(&proposal_id), &bytes).map_err(StateError::Storage)
    }
}

/// Sum of **all** account balances including `Address::ZERO` (a one-time full
/// scan). Used only to validate the pre-migration state; not a hot path.
/// Fail-closed on overflow (impossible for real supply, but never silent).
pub fn accounted_account_supply(db: &Arc<Database>) -> Result<u128> {
    let store = StateStore::new(db);
    let mut sum: u128 = 0;
    for (_addr, acct) in store.iter_all_accounts()? {
        sum = sum
            .checked_add(acct.balance)
            .ok_or_else(|| StateError::BlockValidation("accounted supply overflow".to_string()))?;
    }
    Ok(sum)
}

/// A one-time, whole-ledger census of **every native-Koppa bucket** (see
/// [`NativeSupplySnapshot`]). Deterministic: each bucket sum is an
/// order-independent checked addition over a fixed-order RocksDB scan, so every
/// node at the same height computes an identical result. NOT a hot path — used
/// only by the one-time migration decision and the `chain_getSupplyInfo`
/// diagnostic. Fail-closed on any overflow (never a silent wrap).
///
/// INCLUDE buckets (summed into `economic_supply`): account balances incl.
/// `Address::ZERO`, validator self-stake, active delegations, archive stake,
/// storage V1+V2 fee pools, inference escrow, inference verifier bonds. EXCLUDE
/// buckets (duplicates of a counted bucket, not separate value): unbonding
/// mirrors, governance/policy account balances (already in accounts),
/// `validator.total_delegated`, and pending/unmaterialized rewards.
pub fn native_supply_snapshot(db: &Arc<Database>) -> Result<NativeSupplySnapshot> {
    // Account balances incl. Address::ZERO (INCLUDE); ZERO is also captured as
    // the report-only burn subset in the same single scan.
    let state = StateStore::new(db);
    let mut account_balances_incl_zero: u128 = 0;
    let mut burn_at_zero: u128 = 0;
    for (addr, acct) in state.iter_all_accounts()? {
        account_balances_incl_zero = account_balances_incl_zero
            .checked_add(acct.balance)
            .ok_or_else(|| StateError::BlockValidation("account balance sum overflow".to_string()))?;
        if addr == Address::ZERO {
            burn_at_zero = acct.balance;
        }
    }

    // Validator self-stake + active delegations (INCLUDE).
    let validator_self_stake = StakingStore::new(db).total_validator_self_stake()?;
    let active_delegations = DelegationStore::new(db).total_active_delegations()?;

    // Archive-node stake (INCLUDE).
    let archive_staked_balance =
        crate::node_registry::NodeRegistryExecutor::new(db.clone()).total_archive_staked_balance()?;

    // Storage fee pools V1 + V2 (INCLUDE).
    let (storage_v1_fee_pool, storage_v2_fee_pool) =
        crate::storage_metadata::StorageMetadataExecutor::new(db.clone()).total_fee_pools()?;

    // Inference escrow + verifier bonds (INCLUDE).
    let inference =
        crate::inference_settlement_executor::InferenceSettlementExecutor::new(db.clone());
    let inference_escrow = inference.total_session_remaining_escrow()?;
    let inference_verifier_bonds = inference.total_verifier_bonds()?;

    Ok(NativeSupplySnapshot {
        account_balances_incl_zero,
        burn_at_zero,
        validator_self_stake,
        active_delegations,
        archive_staked_balance,
        storage_v1_fee_pool,
        storage_v2_fee_pool,
        inference_escrow,
        inference_verifier_bonds,
    })
}

/// A pure (write-free) evaluation of the supply correction: the native-supply
/// census plus the decision — apply with a specific reserve delta, or withhold
/// with a precise [`MigrationWithheldReason`]. Shared verbatim by the
/// block-execution apply path and the `chain_getSupplyInfo` diagnostic so both
/// report identically. Infallible by construction: a census scan failure becomes
/// `reason = SnapshotError` (fail-closed) rather than an error, so the RPC can
/// always surface a reason.
#[derive(Debug, Clone, Copy)]
pub struct SupplyCorrectionAssessment {
    pub snapshot: NativeSupplySnapshot,
    /// Live economic supply (Σ INCLUDE buckets); 0 if the census could not be
    /// computed (`SnapshotError`) or overflowed (`ArithmeticOverflow`).
    pub economic_supply: u128,
    /// Reserve delta that would be minted (`TARGET - economic_supply`); non-zero
    /// only when `reason == NotWithheld`.
    pub reserve_delta: u128,
    /// The pool split to persist; `Some` iff `reason == NotWithheld`.
    pub reserve: Option<ProtocolReserve>,
    /// Precise reason the correction is inert this evaluation (`NotWithheld` ⇒ it
    /// applies / would apply now).
    pub reason: MigrationWithheldReason,
}

/// Evaluate the supply correction without writing. `migration_applied` and
/// `ledger_migration_id` come from the persisted ledger; the census is always
/// computed so the RPC diagnostic reflects live ledger sums even post-migration.
pub fn assess_supply_correction(
    db: &Arc<Database>,
    chain_id: u64,
    migration_applied: bool,
    ledger_migration_id: Hash,
) -> SupplyCorrectionAssessment {
    use MigrationWithheldReason as R;

    // The census is the only fallible step; a failure is fail-closed → SnapshotError.
    let snapshot = match native_supply_snapshot(db) {
        Ok(s) => s,
        Err(_) => {
            return SupplyCorrectionAssessment {
                snapshot: NativeSupplySnapshot::zeroed(),
                economic_supply: 0,
                reserve_delta: 0,
                reserve: None,
                reason: R::SnapshotError,
            };
        }
    };
    let econ = snapshot.economic_supply();

    let (economic_supply, reserve_delta, reserve, reason) = if migration_applied {
        (econ.unwrap_or(0), 0, None, R::AlreadyApplied)
    } else if chain_id != MAINNET_CHAIN_ID {
        (econ.unwrap_or(0), 0, None, R::WrongChainId)
    } else if ledger_migration_id != supply_correction_migration_id() {
        (econ.unwrap_or(0), 0, None, R::MigrationIdMismatch)
    } else {
        match econ {
            None => (0, 0, None, R::ArithmeticOverflow),
            Some(0) => (0, 0, None, R::EconomicSupplyZero),
            Some(e) if e > TARGET_CANONICAL_SUPPLY => (e, 0, None, R::EconomicSupplyOverTarget),
            Some(e) => {
                // e ∈ (0, TARGET]. delta ≥ 0.
                let delta = TARGET_CANONICAL_SUPPLY - e;
                if delta == 0 {
                    (e, 0, None, R::ReserveDeltaZero)
                } else {
                    match ProtocolReserve::from_reserve_delta(delta) {
                        // delta < 480B: economic supply too near the target to
                        // fund the fixed service pools — fail closed (never on
                        // real mainnet, where economic ≈ 1B ≪ target).
                        None => (e, 0, None, R::EconomicSupplyOverTarget),
                        Some(reserve) => (e, delta, Some(reserve), R::NotWithheld),
                    }
                }
            }
        }
    };

    SupplyCorrectionAssessment { snapshot, economic_supply, reserve_delta, reserve, reason }
}

// Process-local rate limiter for the withhold-anomaly log. Purely operator-facing
// output — it does NOT touch chain state, so it cannot affect determinism.
// `u64::MAX` means "never logged in this process".
static LAST_WITHHELD_LOG_HEIGHT: AtomicU64 = AtomicU64::new(u64::MAX);
const WITHHELD_LOG_INTERVAL: u64 = 600;

fn log_withheld_anomaly(height: u64, a: &SupplyCorrectionAssessment) {
    let last = LAST_WITHHELD_LOG_HEIGHT.load(Ordering::Relaxed);
    if last == u64::MAX || height >= last.saturating_add(WITHHELD_LOG_INTERVAL) {
        LAST_WITHHELD_LOG_HEIGHT.store(height, Ordering::Relaxed);
        tracing::error!(
            reason = a.reason.as_str(),
            economic_supply = %a.economic_supply,
            target = %TARGET_CANONICAL_SUPPLY,
            height,
            "supply-correction WITHHELD (anomaly) — correction not applied; operator intervention required",
        );
    }
}

/// Apply the one-time mainnet 800B supply correction iff every guard holds.
/// Returns `Ok(true)` if applied this call, `Ok(false)` if not applicable
/// (already applied — replay/restart-safe — or not the mainnet chain — or
/// withheld on a chain-state anomaly).
///
/// The reserve delta is **measured, not hardcoded**: it equals
/// `TARGET_CANONICAL_SUPPLY − economic_supply`, where `economic_supply` is the
/// live census of every native-Koppa bucket ([`native_supply_snapshot`]). The
/// four service/ecosystem pools keep their spec'd sizes; the residual (incl. any
/// Koppa held in non-account ledgers or lost to a sink) lands in the long-term
/// governance reserve. No account is credited.
///
/// **Fails closed** rather than diverging: an in-binary migration-id mismatch is
/// a HARD error (halts the block — it can only be build corruption); every
/// chain-state anomaly (economic supply 0 / over target / delta 0 / overflow /
/// census unreadable) WITHHOLDS deterministically on every upgraded node (the
/// chain keeps producing blocks) and logs once per ~600 blocks. Runs before the
/// block state root; the applied ledger + reserve are folded into that root.
pub fn apply_supply_correction_if_needed(
    db: &Arc<Database>,
    chain_id: u64,
    height: u64,
) -> Result<bool> {
    let store = SupplyStore::new(db.clone());
    let ledger = store.get_ledger()?;

    // Hot-path short-circuits BEFORE any scan: steady state (already applied) or
    // a non-mainnet chain never runs the census.
    if ledger.migration_applied || chain_id != MAINNET_CHAIN_ID {
        return Ok(false);
    }

    let assessment =
        assess_supply_correction(db, chain_id, ledger.migration_applied, ledger.migration_id);

    match assessment.reason {
        MigrationWithheldReason::NotWithheld => {
            let reserve = assessment
                .reserve
                .expect("NotWithheld invariant: reserve split is present");
            // Defensive: the split MUST sum exactly to the measured delta.
            if reserve.total_remaining() != assessment.reserve_delta {
                return Err(StateError::BlockValidation(
                    "supply-correction fail-closed: pool split != reserve delta".to_string(),
                ));
            }
            // Write reserve FIRST, marker (ledger) LAST — so a crash between the
            // two puts leaves the marker unset and the block retries cleanly.
            store.put_reserve(&reserve)?;
            store.put_ledger(&SupplyLedger {
                initial_canonical_supply: TARGET_CANONICAL_SUPPLY,
                total_minted_by_migration: assessment.reserve_delta,
                total_minted_by_governance: 0,
                migration_applied: true,
                migration_id: supply_correction_migration_id(),
                migration_activation_height: height,
            })?;
            tracing::info!(
                economic_supply = %assessment.economic_supply,
                reserve_delta = %assessment.reserve_delta,
                height,
                "supply-correction APPLIED: canonical supply set to 800B; measured delta minted into ProtocolReserve",
            );
            Ok(true)
        }
        // Benign deterministic skips — silent (the hot-path guards above already
        // catch these on the apply path; kept for completeness/RPC symmetry).
        MigrationWithheldReason::AlreadyApplied | MigrationWithheldReason::WrongChainId => Ok(false),
        // In-binary config corruption — HARD fail-closed (halts this block).
        MigrationWithheldReason::MigrationIdMismatch => Err(StateError::BlockValidation(
            "supply-correction fail-closed: migration id mismatch".to_string(),
        )),
        // Chain-state anomalies — WITHHOLD (chain keeps producing), rate-limited log.
        MigrationWithheldReason::EconomicSupplyZero
        | MigrationWithheldReason::EconomicSupplyOverTarget
        | MigrationWithheldReason::ReserveDeltaZero
        | MigrationWithheldReason::ArithmeticOverflow
        | MigrationWithheldReason::SnapshotError => {
            log_withheld_anomaly(height, &assessment);
            Ok(false)
        }
    }
}
