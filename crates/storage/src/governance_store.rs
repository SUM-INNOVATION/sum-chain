//! On-chain governance v1 storage (issue #50, Phase 2 — data model + store).
//!
//! Passive persistence only: registry, proposals, votes, and voting-power
//! snapshots. No executor/lifecycle/snapshot-building logic lives here (those
//! are later phases). Governance behavior stays dormant behind the P1 gate.
//!
//! Deterministic key layouts:
//! - `GOV_REGISTRY`:       asset key (v1: `token_id`, 32 bytes) -> `GovAsset`
//! - `GOV_PROPOSALS`:      `proposal_id` (32) -> `GovProposal`
//! - `GOV_VOTES`:          `proposal_id (32) || voter (20)` -> `GovVote`
//! - `GOV_SNAPSHOTS`:      `proposal_id (32) || holder (20)` -> weight (u128 BE)
//! - `GOV_PROPOSAL_INDEX`: `proposer (20) || proposal_id (32)` -> `` (presence)

use sumchain_primitives::governance::{
    GovAsset, GovAssetKind, GovAssetStatus, GovProposal, GovProposalId, GovProposalStatus, GovVote,
};
use sumchain_primitives::Address;

use crate::db::{cf, Database};
use crate::{Result, StorageError};

fn ser<T: serde::Serialize>(v: &T) -> Result<Vec<u8>> {
    bincode::serialize(v).map_err(|e| StorageError::Serialization(e.to_string()))
}
fn de<T: serde::de::DeserializeOwned>(b: &[u8]) -> Result<T> {
    bincode::deserialize(b).map_err(|e| StorageError::Serialization(e.to_string()))
}

/// Registry key for a governance asset. v1: the SRC-20 `token_id`.
fn asset_key(kind: &GovAssetKind) -> Vec<u8> {
    match kind {
        GovAssetKind::Src20Token(token_id) => token_id.to_vec(),
    }
}

/// `proposal_id (32) || addr (20)` composite key (votes and snapshots).
fn composite_key(proposal_id: &GovProposalId, addr: &Address) -> Vec<u8> {
    let mut k = Vec::with_capacity(52);
    k.extend_from_slice(proposal_id);
    k.extend_from_slice(addr.as_bytes());
    k
}

/// `proposer (20) || proposal_id (32)` index key.
fn proposer_index_key(proposer: &Address, proposal_id: &GovProposalId) -> Vec<u8> {
    let mut k = Vec::with_capacity(52);
    k.extend_from_slice(proposer.as_bytes());
    k.extend_from_slice(proposal_id);
    k
}

fn addr_from_suffix(key: &[u8]) -> Address {
    let mut a = [0u8; 20];
    a.copy_from_slice(&key[32..52]);
    Address::new(a)
}

/// Governance v1 store over the shared `Database`.
pub struct GovStore<'a> {
    db: &'a Database,
}

impl<'a> GovStore<'a> {
    pub fn new(db: &'a Database) -> Self {
        Self { db }
    }

    // ── Registry ─────────────────────────────────────────────────────────────

    pub fn put_asset(&self, asset: &GovAsset) -> Result<()> {
        self.db.put(cf::GOV_REGISTRY, &asset_key(&asset.asset), &ser(asset)?)
    }

    pub fn get_asset(&self, kind: &GovAssetKind) -> Result<Option<GovAsset>> {
        match self.db.get(cf::GOV_REGISTRY, &asset_key(kind))? {
            Some(b) => Ok(Some(de(&b)?)),
            None => Ok(None),
        }
    }

    pub fn list_assets(&self) -> Result<Vec<GovAsset>> {
        let mut out = Vec::new();
        for (_, v) in self.db.iter(cf::GOV_REGISTRY)? {
            out.push(de::<GovAsset>(&v)?);
        }
        Ok(out)
    }

    /// Assets currently enabled (status == Enabled).
    pub fn list_enabled_assets(&self) -> Result<Vec<GovAsset>> {
        Ok(self
            .list_assets()?
            .into_iter()
            .filter(|a| a.status == GovAssetStatus::Enabled)
            .collect())
    }

    /// Assets enabled and effective at `height` (Enabled && effective_height <= height).
    pub fn list_effective_assets(&self, height: u64) -> Result<Vec<GovAsset>> {
        Ok(self
            .list_enabled_assets()?
            .into_iter()
            .filter(|a| a.effective_height <= height)
            .collect())
    }

    // ── Proposals ────────────────────────────────────────────────────────────

    pub fn put_proposal(&self, proposal: &GovProposal) -> Result<()> {
        self.db.put(cf::GOV_PROPOSALS, &proposal.id, &ser(proposal)?)?;
        // Maintain the by-proposer index (presence entry).
        self.db
            .put(cf::GOV_PROPOSAL_INDEX, &proposer_index_key(&proposal.proposer, &proposal.id), &[])
    }

    /// Atomically persist a new proposal together with its proposer index entry
    /// and all frozen snapshot rows. A single `WriteBatch` commit means a
    /// snapshot-bound (or any) failure leaves **no partial rows**.
    pub fn create_proposal_atomic(
        &self,
        proposal: &GovProposal,
        snapshot: &[(Address, u128)],
    ) -> Result<()> {
        let mut batch = self.db.batch();
        batch.put(cf::GOV_PROPOSALS, &proposal.id, &ser(proposal)?)?;
        batch.put(cf::GOV_PROPOSAL_INDEX, &proposer_index_key(&proposal.proposer, &proposal.id), &[])?;
        for (holder, weight) in snapshot {
            batch.put(cf::GOV_SNAPSHOTS, &composite_key(&proposal.id, holder), &weight.to_be_bytes())?;
        }
        batch.commit()
    }

    /// Current holders of `token_id` scanned from `TOKEN_BALANCES` (keyed
    /// `token_id || owner`). Zero balances are skipped. Scanning stops once
    /// `cap + 1` holders are collected, so the caller can detect an over-bound
    /// holder set (`len > cap`) without unbounded work.
    pub fn scan_token_holders(&self, token_id: &[u8; 32], cap: usize) -> Result<Vec<(Address, u128)>> {
        let mut out = Vec::new();
        for (k, v) in self.db.prefix_iter(cf::TOKEN_BALANCES, token_id)? {
            if !k.starts_with(token_id) || k.len() < 52 {
                continue;
            }
            let arr: [u8; 16] = v[..]
                .try_into()
                .map_err(|_| StorageError::Serialization("token balance not 16 bytes".into()))?;
            let bal = u128::from_be_bytes(arr);
            if bal == 0 {
                continue;
            }
            out.push((addr_from_suffix(&k), bal));
            if out.len() > cap {
                break;
            }
        }
        Ok(out)
    }

    pub fn get_proposal(&self, id: &GovProposalId) -> Result<Option<GovProposal>> {
        match self.db.get(cf::GOV_PROPOSALS, id)? {
            Some(b) => Ok(Some(de(&b)?)),
            None => Ok(None),
        }
    }

    pub fn list_proposals(&self) -> Result<Vec<GovProposal>> {
        let mut out = Vec::new();
        for (_, v) in self.db.iter(cf::GOV_PROPOSALS)? {
            out.push(de::<GovProposal>(&v)?);
        }
        Ok(out)
    }

    /// Filter by status on read (status is mutable, so it is not indexed).
    pub fn list_proposals_by_status(&self, status: GovProposalStatus) -> Result<Vec<GovProposal>> {
        Ok(self.list_proposals()?.into_iter().filter(|p| p.status == status).collect())
    }

    /// Proposals created by `proposer`, via the deterministic proposer index.
    pub fn list_proposals_by_proposer(&self, proposer: &Address) -> Result<Vec<GovProposal>> {
        let prefix = proposer.as_bytes();
        let mut out = Vec::new();
        for (k, _) in self.db.prefix_iter(cf::GOV_PROPOSAL_INDEX, prefix)? {
            // `prefix_iter` seeks to the prefix but may continue past it; bound
            // to keys that actually start with `proposer`. key = proposer(20) || id(32).
            if !k.starts_with(prefix) {
                continue;
            }
            let mut id: GovProposalId = [0u8; 32];
            id.copy_from_slice(&k[20..52]);
            if let Some(p) = self.get_proposal(&id)? {
                out.push(p);
            }
        }
        Ok(out)
    }

    // ── Votes (one per proposal+voter, enforced by key) ──────────────────────

    pub fn put_vote(&self, vote: &GovVote) -> Result<()> {
        self.db
            .put(cf::GOV_VOTES, &composite_key(&vote.proposal_id, &vote.voter), &ser(vote)?)
    }

    pub fn get_vote(&self, proposal_id: &GovProposalId, voter: &Address) -> Result<Option<GovVote>> {
        match self.db.get(cf::GOV_VOTES, &composite_key(proposal_id, voter))? {
            Some(b) => Ok(Some(de(&b)?)),
            None => Ok(None),
        }
    }

    pub fn list_votes(&self, proposal_id: &GovProposalId) -> Result<Vec<GovVote>> {
        let mut out = Vec::new();
        for (k, v) in self.db.prefix_iter(cf::GOV_VOTES, proposal_id)? {
            // Bound to the exact proposal prefix (see list_proposals_by_proposer).
            if !k.starts_with(proposal_id) {
                continue;
            }
            out.push(de::<GovVote>(&v)?);
        }
        Ok(out)
    }

    // ── Snapshots (frozen voting power; weight stored u128 big-endian) ────────

    pub fn put_snapshot(&self, proposal_id: &GovProposalId, holder: &Address, weight: u128) -> Result<()> {
        self.db
            .put(cf::GOV_SNAPSHOTS, &composite_key(proposal_id, holder), &weight.to_be_bytes())
    }

    pub fn get_snapshot(&self, proposal_id: &GovProposalId, holder: &Address) -> Result<Option<u128>> {
        match self.db.get(cf::GOV_SNAPSHOTS, &composite_key(proposal_id, holder))? {
            Some(b) => {
                let arr: [u8; 16] = b[..]
                    .try_into()
                    .map_err(|_| StorageError::Serialization("snapshot weight not 16 bytes".into()))?;
                Ok(Some(u128::from_be_bytes(arr)))
            }
            None => Ok(None),
        }
    }

    pub fn list_snapshot(&self, proposal_id: &GovProposalId) -> Result<Vec<(Address, u128)>> {
        let mut out = Vec::new();
        for (k, v) in self.db.prefix_iter(cf::GOV_SNAPSHOTS, proposal_id)? {
            // Bound to the exact proposal prefix (see list_proposals_by_proposer).
            if !k.starts_with(proposal_id) {
                continue;
            }
            let arr: [u8; 16] = v[..]
                .try_into()
                .map_err(|_| StorageError::Serialization("snapshot weight not 16 bytes".into()))?;
            out.push((addr_from_suffix(&k), u128::from_be_bytes(arr)));
        }
        Ok(out)
    }
}
