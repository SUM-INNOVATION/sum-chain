//! SRC-86X Property & Insurance Storage
//!
//! Storage layer for:
//! - SRC-861: Asset Anchors
//! - SRC-862: Title Events
//! - SRC-863: Encumbrances
//! - SRC-864: Insurance Coverage
//! - SRC-865: Insurance Claims
//! - SRC-866: Property Proofs

use sumchain_primitives::{
    property::{
        AssetAnchor, AssetStatus, ClaimStatus, CoverageStatus, Encumbrance, EncumbranceStatus,
        InsuranceClaim, InsuranceCoverage, PropertyEvent, PropertyProofEnvelope, TitleEvent,
        TitleEventStatus,
    },
    BlockHeight, Timestamp,
};

use crate::db::{cf, Database};
use crate::{Result, StorageError};

// Type aliases for clarity
pub type AssetId = [u8; 32];
pub type TitleEventId = [u8; 32];
pub type EncumbranceId = [u8; 32];
pub type CoverageId = [u8; 32];
pub type ClaimId = [u8; 32];
pub type ProofId = [u8; 32];

// =============================================================================
// Asset Anchor Storage (SRC-861)
// =============================================================================

/// Storage for Asset Anchors (SRC-861)
pub struct AssetStore<'a> {
    db: &'a Database,
}

impl<'a> AssetStore<'a> {
    pub fn new(db: &'a Database) -> Self {
        Self { db }
    }

    /// Store an asset anchor
    pub fn put(&self, asset: &AssetAnchor) -> Result<()> {
        let bytes = bincode::serialize(asset)
            .map_err(|e| StorageError::Serialization(e.to_string()))?;
        self.db.put(cf::PROPERTY_ASSETS, &asset.asset_id, &bytes)?;

        // Update jurisdiction index
        self.add_to_jurisdiction_index(&asset.jurisdiction_code, &asset.asset_id)?;

        Ok(())
    }

    /// Get an asset by ID
    pub fn get(&self, asset_id: &AssetId) -> Result<Option<AssetAnchor>> {
        match self.db.get(cf::PROPERTY_ASSETS, asset_id)? {
            Some(bytes) => {
                let asset: AssetAnchor = bincode::deserialize(&bytes)
                    .map_err(|e| StorageError::Serialization(e.to_string()))?;
                Ok(Some(asset))
            }
            None => Ok(None),
        }
    }

    /// Check if asset exists
    pub fn exists(&self, asset_id: &AssetId) -> Result<bool> {
        self.db.contains(cf::PROPERTY_ASSETS, asset_id)
    }

    /// Update asset status
    pub fn update_status(
        &self,
        asset_id: &AssetId,
        status: AssetStatus,
        timestamp: Timestamp,
    ) -> Result<()> {
        match self.get(asset_id)? {
            Some(mut asset) => {
                asset.status = status;
                asset.updated_at = timestamp;
                let bytes = bincode::serialize(&asset)
                    .map_err(|e| StorageError::Serialization(e.to_string()))?;
                self.db.put(cf::PROPERTY_ASSETS, asset_id, &bytes)
            }
            None => Err(StorageError::NotFound(format!(
                "Asset not found: {:?}",
                asset_id
            ))),
        }
    }

    /// Get assets by jurisdiction
    pub fn get_by_jurisdiction(&self, jurisdiction: &str) -> Result<Vec<AssetAnchor>> {
        let ids = self.get_jurisdiction_asset_ids(jurisdiction)?;
        let mut assets = Vec::new();
        for id in ids {
            if let Some(asset) = self.get(&id)? {
                assets.push(asset);
            }
        }
        Ok(assets)
    }

    /// List active assets
    pub fn list_active(&self) -> Result<Vec<AssetAnchor>> {
        let mut assets = Vec::new();
        for (_, value) in self.db.iter(cf::PROPERTY_ASSETS)? {
            let asset: AssetAnchor = bincode::deserialize(&value)
                .map_err(|e| StorageError::Serialization(e.to_string()))?;
            if asset.status == AssetStatus::Active {
                assets.push(asset);
            }
        }
        Ok(assets)
    }

    /// Add related asset
    pub fn add_related_asset(
        &self,
        asset_id: &AssetId,
        related_asset_id: &AssetId,
        timestamp: Timestamp,
    ) -> Result<()> {
        match self.get(asset_id)? {
            Some(mut asset) => {
                if !asset.related_assets.contains(related_asset_id) {
                    asset.related_assets.push(*related_asset_id);
                    asset.updated_at = timestamp;
                    let bytes = bincode::serialize(&asset)
                        .map_err(|e| StorageError::Serialization(e.to_string()))?;
                    self.db.put(cf::PROPERTY_ASSETS, asset_id, &bytes)?;
                }
                Ok(())
            }
            None => Err(StorageError::NotFound(format!(
                "Asset not found: {:?}",
                asset_id
            ))),
        }
    }

    // Index helpers
    fn add_to_jurisdiction_index(&self, jurisdiction: &str, id: &[u8; 32]) -> Result<()> {
        let mut ids = self.get_jurisdiction_asset_ids(jurisdiction)?;
        if !ids.contains(id) {
            ids.push(*id);
            let bytes = bincode::serialize(&ids)
                .map_err(|e| StorageError::Serialization(e.to_string()))?;
            self.db.put(cf::PROPERTY_JURISDICTION_INDEX, jurisdiction.as_bytes(), &bytes)?;
        }
        Ok(())
    }

    fn get_jurisdiction_asset_ids(&self, jurisdiction: &str) -> Result<Vec<AssetId>> {
        match self.db.get(cf::PROPERTY_JURISDICTION_INDEX, jurisdiction.as_bytes())? {
            Some(bytes) => {
                let ids: Vec<AssetId> = bincode::deserialize(&bytes)
                    .map_err(|e| StorageError::Serialization(e.to_string()))?;
                Ok(ids)
            }
            None => Ok(Vec::new()),
        }
    }
}

// =============================================================================
// Title Event Storage (SRC-862)
// =============================================================================

/// Storage for Title Events (SRC-862)
pub struct TitleEventStore<'a> {
    db: &'a Database,
}

impl<'a> TitleEventStore<'a> {
    pub fn new(db: &'a Database) -> Self {
        Self { db }
    }

    /// Store a title event
    pub fn put(&self, event: &TitleEvent) -> Result<()> {
        let bytes = bincode::serialize(event)
            .map_err(|e| StorageError::Serialization(e.to_string()))?;
        self.db.put(cf::PROPERTY_TITLE_EVENTS, &event.event_id, &bytes)?;

        // Update asset title index
        self.add_to_asset_index(&event.asset_id, &event.event_id)?;

        Ok(())
    }

    /// Get a title event by ID
    pub fn get(&self, event_id: &TitleEventId) -> Result<Option<TitleEvent>> {
        match self.db.get(cf::PROPERTY_TITLE_EVENTS, event_id)? {
            Some(bytes) => {
                let event: TitleEvent = bincode::deserialize(&bytes)
                    .map_err(|e| StorageError::Serialization(e.to_string()))?;
                Ok(Some(event))
            }
            None => Ok(None),
        }
    }

    /// Check if title event exists
    pub fn exists(&self, event_id: &TitleEventId) -> Result<bool> {
        self.db.contains(cf::PROPERTY_TITLE_EVENTS, event_id)
    }

    /// Update title event status
    pub fn update_status(
        &self,
        event_id: &TitleEventId,
        status: TitleEventStatus,
        timestamp: Timestamp,
    ) -> Result<()> {
        match self.get(event_id)? {
            Some(mut event) => {
                event.status = status;
                event.created_at = timestamp; // Note: This is recording the status change
                let bytes = bincode::serialize(&event)
                    .map_err(|e| StorageError::Serialization(e.to_string()))?;
                self.db.put(cf::PROPERTY_TITLE_EVENTS, event_id, &bytes)
            }
            None => Err(StorageError::NotFound(format!(
                "Title event not found: {:?}",
                event_id
            ))),
        }
    }

    /// Get title events by asset
    pub fn get_by_asset(&self, asset_id: &AssetId) -> Result<Vec<TitleEvent>> {
        let ids = self.get_asset_event_ids(asset_id)?;
        let mut events = Vec::new();
        for id in ids {
            if let Some(event) = self.get(&id)? {
                events.push(event);
            }
        }
        Ok(events)
    }

    // Index helpers
    fn add_to_asset_index(&self, asset_id: &AssetId, event_id: &TitleEventId) -> Result<()> {
        let mut ids = self.get_asset_event_ids(asset_id)?;
        if !ids.contains(event_id) {
            ids.push(*event_id);
            let bytes = bincode::serialize(&ids)
                .map_err(|e| StorageError::Serialization(e.to_string()))?;
            self.db.put(cf::PROPERTY_ASSET_TITLE_INDEX, asset_id, &bytes)?;
        }
        Ok(())
    }

    fn get_asset_event_ids(&self, asset_id: &AssetId) -> Result<Vec<TitleEventId>> {
        match self.db.get(cf::PROPERTY_ASSET_TITLE_INDEX, asset_id)? {
            Some(bytes) => {
                let ids: Vec<TitleEventId> = bincode::deserialize(&bytes)
                    .map_err(|e| StorageError::Serialization(e.to_string()))?;
                Ok(ids)
            }
            None => Ok(Vec::new()),
        }
    }
}

// =============================================================================
// Encumbrance Storage (SRC-863)
// =============================================================================

/// Storage for Encumbrances (SRC-863)
pub struct EncumbranceStore<'a> {
    db: &'a Database,
}

impl<'a> EncumbranceStore<'a> {
    pub fn new(db: &'a Database) -> Self {
        Self { db }
    }

    /// Store an encumbrance
    pub fn put(&self, encumbrance: &Encumbrance) -> Result<()> {
        let bytes = bincode::serialize(encumbrance)
            .map_err(|e| StorageError::Serialization(e.to_string()))?;
        self.db.put(cf::PROPERTY_ENCUMBRANCES, &encumbrance.encumbrance_id, &bytes)?;

        // Update asset encumbrance index
        self.add_to_asset_index(&encumbrance.asset_id, &encumbrance.encumbrance_id)?;

        Ok(())
    }

    /// Get an encumbrance by ID
    pub fn get(&self, encumbrance_id: &EncumbranceId) -> Result<Option<Encumbrance>> {
        match self.db.get(cf::PROPERTY_ENCUMBRANCES, encumbrance_id)? {
            Some(bytes) => {
                let encumbrance: Encumbrance = bincode::deserialize(&bytes)
                    .map_err(|e| StorageError::Serialization(e.to_string()))?;
                Ok(Some(encumbrance))
            }
            None => Ok(None),
        }
    }

    /// Check if encumbrance exists
    pub fn exists(&self, encumbrance_id: &EncumbranceId) -> Result<bool> {
        self.db.contains(cf::PROPERTY_ENCUMBRANCES, encumbrance_id)
    }

    /// Update encumbrance status
    pub fn update_status(
        &self,
        encumbrance_id: &EncumbranceId,
        status: EncumbranceStatus,
        timestamp: Timestamp,
    ) -> Result<()> {
        match self.get(encumbrance_id)? {
            Some(mut encumbrance) => {
                encumbrance.status = status;
                encumbrance.updated_at = timestamp;
                let bytes = bincode::serialize(&encumbrance)
                    .map_err(|e| StorageError::Serialization(e.to_string()))?;
                self.db.put(cf::PROPERTY_ENCUMBRANCES, encumbrance_id, &bytes)
            }
            None => Err(StorageError::NotFound(format!(
                "Encumbrance not found: {:?}",
                encumbrance_id
            ))),
        }
    }

    /// Get encumbrances by asset
    pub fn get_by_asset(&self, asset_id: &AssetId) -> Result<Vec<Encumbrance>> {
        let ids = self.get_asset_encumbrance_ids(asset_id)?;
        let mut encumbrances = Vec::new();
        for id in ids {
            if let Some(enc) = self.get(&id)? {
                encumbrances.push(enc);
            }
        }
        Ok(encumbrances)
    }

    /// Get active encumbrances by asset
    pub fn get_active_by_asset(&self, asset_id: &AssetId, current_time: Timestamp) -> Result<Vec<Encumbrance>> {
        let all = self.get_by_asset(asset_id)?;
        Ok(all.into_iter().filter(|e| e.is_active(current_time)).collect())
    }

    // Index helpers
    fn add_to_asset_index(&self, asset_id: &AssetId, encumbrance_id: &EncumbranceId) -> Result<()> {
        let mut ids = self.get_asset_encumbrance_ids(asset_id)?;
        if !ids.contains(encumbrance_id) {
            ids.push(*encumbrance_id);
            let bytes = bincode::serialize(&ids)
                .map_err(|e| StorageError::Serialization(e.to_string()))?;
            self.db.put(cf::PROPERTY_ASSET_ENCUMBRANCE_INDEX, asset_id, &bytes)?;
        }
        Ok(())
    }

    fn get_asset_encumbrance_ids(&self, asset_id: &AssetId) -> Result<Vec<EncumbranceId>> {
        match self.db.get(cf::PROPERTY_ASSET_ENCUMBRANCE_INDEX, asset_id)? {
            Some(bytes) => {
                let ids: Vec<EncumbranceId> = bincode::deserialize(&bytes)
                    .map_err(|e| StorageError::Serialization(e.to_string()))?;
                Ok(ids)
            }
            None => Ok(Vec::new()),
        }
    }
}

// =============================================================================
// Insurance Coverage Storage (SRC-864)
// =============================================================================

/// Storage for Insurance Coverage (SRC-864)
pub struct CoverageStore<'a> {
    db: &'a Database,
}

impl<'a> CoverageStore<'a> {
    pub fn new(db: &'a Database) -> Self {
        Self { db }
    }

    /// Store an insurance coverage
    pub fn put(&self, coverage: &InsuranceCoverage) -> Result<()> {
        let bytes = bincode::serialize(coverage)
            .map_err(|e| StorageError::Serialization(e.to_string()))?;
        self.db.put(cf::PROPERTY_COVERAGE, &coverage.coverage_id, &bytes)?;

        // Update asset coverage index
        self.add_to_asset_index(&coverage.asset_id, &coverage.coverage_id)?;

        Ok(())
    }

    /// Get a coverage by ID
    pub fn get(&self, coverage_id: &CoverageId) -> Result<Option<InsuranceCoverage>> {
        match self.db.get(cf::PROPERTY_COVERAGE, coverage_id)? {
            Some(bytes) => {
                let coverage: InsuranceCoverage = bincode::deserialize(&bytes)
                    .map_err(|e| StorageError::Serialization(e.to_string()))?;
                Ok(Some(coverage))
            }
            None => Ok(None),
        }
    }

    /// Check if coverage exists
    pub fn exists(&self, coverage_id: &CoverageId) -> Result<bool> {
        self.db.contains(cf::PROPERTY_COVERAGE, coverage_id)
    }

    /// Update coverage status
    pub fn update_status(
        &self,
        coverage_id: &CoverageId,
        status: CoverageStatus,
        timestamp: Timestamp,
    ) -> Result<()> {
        match self.get(coverage_id)? {
            Some(mut coverage) => {
                coverage.status = status;
                coverage.updated_at = timestamp;
                let bytes = bincode::serialize(&coverage)
                    .map_err(|e| StorageError::Serialization(e.to_string()))?;
                self.db.put(cf::PROPERTY_COVERAGE, coverage_id, &bytes)
            }
            None => Err(StorageError::NotFound(format!(
                "Coverage not found: {:?}",
                coverage_id
            ))),
        }
    }

    /// Renew coverage with new expiry date
    pub fn renew(
        &self,
        coverage_id: &CoverageId,
        new_expiry: Timestamp,
        timestamp: Timestamp,
    ) -> Result<()> {
        match self.get(coverage_id)? {
            Some(mut coverage) => {
                coverage.expiry = new_expiry;
                coverage.status = CoverageStatus::Renewed;
                coverage.updated_at = timestamp;
                let bytes = bincode::serialize(&coverage)
                    .map_err(|e| StorageError::Serialization(e.to_string()))?;
                self.db.put(cf::PROPERTY_COVERAGE, coverage_id, &bytes)
            }
            None => Err(StorageError::NotFound(format!(
                "Coverage not found: {:?}",
                coverage_id
            ))),
        }
    }

    /// Get coverages by asset
    pub fn get_by_asset(&self, asset_id: &AssetId) -> Result<Vec<InsuranceCoverage>> {
        let ids = self.get_asset_coverage_ids(asset_id)?;
        let mut coverages = Vec::new();
        for id in ids {
            if let Some(cov) = self.get(&id)? {
                coverages.push(cov);
            }
        }
        Ok(coverages)
    }

    /// Get active coverages by asset
    pub fn get_active_by_asset(&self, asset_id: &AssetId, current_time: Timestamp) -> Result<Vec<InsuranceCoverage>> {
        let all = self.get_by_asset(asset_id)?;
        Ok(all.into_iter().filter(|c| c.is_in_force(current_time)).collect())
    }

    // Index helpers
    fn add_to_asset_index(&self, asset_id: &AssetId, coverage_id: &CoverageId) -> Result<()> {
        let mut ids = self.get_asset_coverage_ids(asset_id)?;
        if !ids.contains(coverage_id) {
            ids.push(*coverage_id);
            let bytes = bincode::serialize(&ids)
                .map_err(|e| StorageError::Serialization(e.to_string()))?;
            self.db.put(cf::PROPERTY_ASSET_COVERAGE_INDEX, asset_id, &bytes)?;
        }
        Ok(())
    }

    fn get_asset_coverage_ids(&self, asset_id: &AssetId) -> Result<Vec<CoverageId>> {
        match self.db.get(cf::PROPERTY_ASSET_COVERAGE_INDEX, asset_id)? {
            Some(bytes) => {
                let ids: Vec<CoverageId> = bincode::deserialize(&bytes)
                    .map_err(|e| StorageError::Serialization(e.to_string()))?;
                Ok(ids)
            }
            None => Ok(Vec::new()),
        }
    }
}

// =============================================================================
// Insurance Claim Storage (SRC-865)
// =============================================================================

/// Storage for Insurance Claims (SRC-865)
pub struct ClaimStore<'a> {
    db: &'a Database,
}

impl<'a> ClaimStore<'a> {
    pub fn new(db: &'a Database) -> Self {
        Self { db }
    }

    /// Store an insurance claim
    pub fn put(&self, claim: &InsuranceClaim) -> Result<()> {
        let bytes = bincode::serialize(claim)
            .map_err(|e| StorageError::Serialization(e.to_string()))?;
        self.db.put(cf::PROPERTY_CLAIMS, &claim.claim_id, &bytes)?;

        // Update coverage claim index
        self.add_to_coverage_index(&claim.coverage_id, &claim.claim_id)?;

        Ok(())
    }

    /// Get a claim by ID
    pub fn get(&self, claim_id: &ClaimId) -> Result<Option<InsuranceClaim>> {
        match self.db.get(cf::PROPERTY_CLAIMS, claim_id)? {
            Some(bytes) => {
                let claim: InsuranceClaim = bincode::deserialize(&bytes)
                    .map_err(|e| StorageError::Serialization(e.to_string()))?;
                Ok(Some(claim))
            }
            None => Ok(None),
        }
    }

    /// Check if claim exists
    pub fn exists(&self, claim_id: &ClaimId) -> Result<bool> {
        self.db.contains(cf::PROPERTY_CLAIMS, claim_id)
    }

    /// Update claim status
    pub fn update_status(
        &self,
        claim_id: &ClaimId,
        status: ClaimStatus,
        timestamp: Timestamp,
    ) -> Result<()> {
        match self.get(claim_id)? {
            Some(mut claim) => {
                claim.status = status;
                claim.updated_at = timestamp;
                let bytes = bincode::serialize(&claim)
                    .map_err(|e| StorageError::Serialization(e.to_string()))?;
                self.db.put(cf::PROPERTY_CLAIMS, claim_id, &bytes)
            }
            None => Err(StorageError::NotFound(format!(
                "Claim not found: {:?}",
                claim_id
            ))),
        }
    }

    /// Approve a claim with approved amount commitment
    pub fn approve(
        &self,
        claim_id: &ClaimId,
        approved_amount_commitment: [u8; 32],
        timestamp: Timestamp,
    ) -> Result<()> {
        match self.get(claim_id)? {
            Some(mut claim) => {
                claim.approved_amount_commitment = Some(approved_amount_commitment);
                claim.status = ClaimStatus::Approved;
                claim.updated_at = timestamp;
                let bytes = bincode::serialize(&claim)
                    .map_err(|e| StorageError::Serialization(e.to_string()))?;
                self.db.put(cf::PROPERTY_CLAIMS, claim_id, &bytes)
            }
            None => Err(StorageError::NotFound(format!(
                "Claim not found: {:?}",
                claim_id
            ))),
        }
    }

    /// Pay a claim with paid amount commitment
    pub fn pay(
        &self,
        claim_id: &ClaimId,
        paid_amount_commitment: [u8; 32],
        timestamp: Timestamp,
    ) -> Result<()> {
        match self.get(claim_id)? {
            Some(mut claim) => {
                claim.paid_amount_commitment = Some(paid_amount_commitment);
                claim.status = ClaimStatus::Paid;
                claim.updated_at = timestamp;
                let bytes = bincode::serialize(&claim)
                    .map_err(|e| StorageError::Serialization(e.to_string()))?;
                self.db.put(cf::PROPERTY_CLAIMS, claim_id, &bytes)
            }
            None => Err(StorageError::NotFound(format!(
                "Claim not found: {:?}",
                claim_id
            ))),
        }
    }

    /// Get claims by coverage
    pub fn get_by_coverage(&self, coverage_id: &CoverageId) -> Result<Vec<InsuranceClaim>> {
        let ids = self.get_coverage_claim_ids(coverage_id)?;
        let mut claims = Vec::new();
        for id in ids {
            if let Some(claim) = self.get(&id)? {
                claims.push(claim);
            }
        }
        Ok(claims)
    }

    /// Get open claims by coverage
    pub fn get_open_by_coverage(&self, coverage_id: &CoverageId) -> Result<Vec<InsuranceClaim>> {
        let all = self.get_by_coverage(coverage_id)?;
        Ok(all.into_iter().filter(|c| c.is_open()).collect())
    }

    // Index helpers
    fn add_to_coverage_index(&self, coverage_id: &CoverageId, claim_id: &ClaimId) -> Result<()> {
        let mut ids = self.get_coverage_claim_ids(coverage_id)?;
        if !ids.contains(claim_id) {
            ids.push(*claim_id);
            let bytes = bincode::serialize(&ids)
                .map_err(|e| StorageError::Serialization(e.to_string()))?;
            self.db.put(cf::PROPERTY_COVERAGE_CLAIM_INDEX, coverage_id, &bytes)?;
        }
        Ok(())
    }

    fn get_coverage_claim_ids(&self, coverage_id: &CoverageId) -> Result<Vec<ClaimId>> {
        match self.db.get(cf::PROPERTY_COVERAGE_CLAIM_INDEX, coverage_id)? {
            Some(bytes) => {
                let ids: Vec<ClaimId> = bincode::deserialize(&bytes)
                    .map_err(|e| StorageError::Serialization(e.to_string()))?;
                Ok(ids)
            }
            None => Ok(Vec::new()),
        }
    }
}

// =============================================================================
// Property Proof Storage (SRC-866)
// =============================================================================

/// Storage for Property Proofs (SRC-866)
pub struct PropertyProofStore<'a> {
    db: &'a Database,
}

impl<'a> PropertyProofStore<'a> {
    pub fn new(db: &'a Database) -> Self {
        Self { db }
    }

    /// Store a property proof
    pub fn put(&self, proof: &PropertyProofEnvelope) -> Result<()> {
        let bytes = bincode::serialize(proof)
            .map_err(|e| StorageError::Serialization(e.to_string()))?;
        self.db.put(cf::PROPERTY_PROOFS, &proof.proof_id, &bytes)
    }

    /// Get a proof by ID
    pub fn get(&self, proof_id: &ProofId) -> Result<Option<PropertyProofEnvelope>> {
        match self.db.get(cf::PROPERTY_PROOFS, proof_id)? {
            Some(bytes) => {
                let proof: PropertyProofEnvelope = bincode::deserialize(&bytes)
                    .map_err(|e| StorageError::Serialization(e.to_string()))?;
                Ok(Some(proof))
            }
            None => Ok(None),
        }
    }

    /// Check if proof exists
    pub fn exists(&self, proof_id: &ProofId) -> Result<bool> {
        self.db.contains(cf::PROPERTY_PROOFS, proof_id)
    }

    /// Check if proof is valid (not expired)
    pub fn is_valid(&self, proof_id: &ProofId, current_time: Timestamp) -> Result<bool> {
        match self.get(proof_id)? {
            Some(proof) => Ok(current_time < proof.expires_at),
            None => Ok(false),
        }
    }
}

// =============================================================================
// Property Event Storage
// =============================================================================

/// Storage for Property Events
pub struct PropertyEventStore<'a> {
    db: &'a Database,
}

impl<'a> PropertyEventStore<'a> {
    pub fn new(db: &'a Database) -> Self {
        Self { db }
    }

    /// Store a property event
    pub fn put(&self, height: BlockHeight, index: u32, event: &PropertyEvent) -> Result<()> {
        let key = Self::make_key(height, index);
        let bytes = bincode::serialize(event)
            .map_err(|e| StorageError::Serialization(e.to_string()))?;
        self.db.put(cf::PROPERTY_SYSTEM_EVENTS, &key, &bytes)
    }

    /// Get events by block height
    pub fn get_by_height(&self, height: BlockHeight) -> Result<Vec<PropertyEvent>> {
        let prefix = height.to_be_bytes();
        let mut events = Vec::new();
        for (_, value) in self.db.prefix_iter(cf::PROPERTY_SYSTEM_EVENTS, &prefix)? {
            let event: PropertyEvent = bincode::deserialize(&value)
                .map_err(|e| StorageError::Serialization(e.to_string()))?;
            events.push(event);
        }
        Ok(events)
    }

    fn make_key(height: BlockHeight, index: u32) -> [u8; 12] {
        let mut key = [0u8; 12];
        key[..8].copy_from_slice(&height.to_be_bytes());
        key[8..].copy_from_slice(&index.to_be_bytes());
        key
    }
}

// =============================================================================
// Combined Property Store
// =============================================================================

/// Combined storage interface for all SRC-86X operations
pub struct PropertyStore<'a> {
    db: &'a Database,
}

impl<'a> PropertyStore<'a> {
    pub fn new(db: &'a Database) -> Self {
        Self { db }
    }

    /// Get asset store
    pub fn assets(&self) -> AssetStore<'_> {
        AssetStore::new(self.db)
    }

    /// Get title event store
    pub fn title_events(&self) -> TitleEventStore<'_> {
        TitleEventStore::new(self.db)
    }

    /// Get encumbrance store
    pub fn encumbrances(&self) -> EncumbranceStore<'_> {
        EncumbranceStore::new(self.db)
    }

    /// Get coverage store
    pub fn coverage(&self) -> CoverageStore<'_> {
        CoverageStore::new(self.db)
    }

    /// Get claim store
    pub fn claims(&self) -> ClaimStore<'_> {
        ClaimStore::new(self.db)
    }

    /// Get proof store
    pub fn proofs(&self) -> PropertyProofStore<'_> {
        PropertyProofStore::new(self.db)
    }

    /// Get event store
    pub fn events(&self) -> PropertyEventStore<'_> {
        PropertyEventStore::new(self.db)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::DatabaseConfig;
    use sumchain_primitives::{
        property::{
            AssetType, CoverageType, EncumbranceType, ClaimType, PriorityPosition,
            PropertyIssuerClass,
        },
        agreement::PartyRef,
        Address,
    };
    use tempfile::TempDir;

    fn temp_db() -> (Database, TempDir) {
        let dir = TempDir::new().unwrap();
        let db = Database::open_default(dir.path()).unwrap();
        (db, dir)
    }

    fn sample_asset() -> AssetAnchor {
        AssetAnchor {
            asset_id: [1u8; 32],
            asset_commitment: [2u8; 32],
            asset_type: AssetType::SingleFamilyResidence,
            jurisdiction_code: "US-CA-LA".to_string(),
            public_reference: None,
            policy_id: [3u8; 32],
            issuer_class: PropertyIssuerClass::LandRegistry,
            issuer_address: Address::new([4u8; 20]),
            status: AssetStatus::Active,
            created_at: 1000,
            updated_at: 1000,
            anchored_at_height: 100,
            related_assets: vec![],
            attachments: vec![],
        }
    }

    fn sample_encumbrance(asset_id: &AssetId) -> Encumbrance {
        Encumbrance {
            encumbrance_id: [5u8; 32],
            asset_id: *asset_id,
            encumbrance_type: EncumbranceType::FirstMortgage,
            encumbrance_commitment: [6u8; 32],
            holder_ref: PartyRef::Commitment([7u8; 32]),
            obligor_ref: Some(PartyRef::Commitment([8u8; 32])),
            priority: PriorityPosition::First,
            amount_commitment: Some([9u8; 32]),
            effective_from: 1000,
            expiry: Some(2000),
            issuer_address: Address::new([10u8; 20]),
            issuer_class: PropertyIssuerClass::MortgageLender,
            policy_id: [11u8; 32],
            revocation_ref: None,
            status: EncumbranceStatus::Active,
            created_at: 1000,
            updated_at: 1000,
            recorded_at_height: 100,
            agreement_id: None,
            attachments: vec![],
        }
    }

    fn sample_coverage(asset_id: &AssetId) -> InsuranceCoverage {
        InsuranceCoverage {
            coverage_id: [12u8; 32],
            asset_id: *asset_id,
            coverage_type: CoverageType::Homeowners,
            coverage_commitment: [13u8; 32],
            insurer_ref: PartyRef::Commitment([14u8; 32]),
            insured_ref: PartyRef::Commitment([15u8; 32]),
            additional_insureds: vec![],
            limit_commitment: [16u8; 32],
            deductible_commitment: None,
            premium_commitment: None,
            effective_from: 1000,
            expiry: 2000,
            issuer_address: Address::new([17u8; 20]),
            issuer_class: PropertyIssuerClass::InsuranceCompany,
            policy_id: [18u8; 32],
            revocation_ref: None,
            status: CoverageStatus::Active,
            created_at: 1000,
            updated_at: 1000,
            recorded_at_height: 100,
            prior_coverage_id: None,
            attachments: vec![],
        }
    }

    fn sample_claim(coverage_id: &CoverageId, asset_id: &AssetId) -> InsuranceClaim {
        InsuranceClaim {
            claim_id: [19u8; 32],
            coverage_id: *coverage_id,
            asset_id: *asset_id,
            claim_type: ClaimType::WaterDamage,
            claim_commitment: [20u8; 32],
            claimant_ref: PartyRef::Commitment([21u8; 32]),
            date_of_loss: 900,
            date_filed: 1000,
            loss_amount_commitment: Some([22u8; 32]),
            approved_amount_commitment: None,
            paid_amount_commitment: None,
            adjuster_ref: None,
            issuer_address: Address::new([23u8; 20]),
            issuer_class: PropertyIssuerClass::InsuranceCompany,
            policy_id: [24u8; 32],
            revocation_ref: None,
            status: ClaimStatus::Filed,
            created_at: 1000,
            updated_at: 1000,
            recorded_at_height: 100,
            related_claims: vec![],
            attachments: vec![],
        }
    }

    #[test]
    fn test_asset_store() {
        let (db, _dir) = temp_db();
        let store = AssetStore::new(&db);

        let asset = sample_asset();
        store.put(&asset).unwrap();

        let retrieved = store.get(&asset.asset_id).unwrap().unwrap();
        assert_eq!(retrieved.asset_id, asset.asset_id);
        assert_eq!(retrieved.jurisdiction_code, "US-CA-LA");

        // Test jurisdiction index
        let by_jurisdiction = store.get_by_jurisdiction("US-CA-LA").unwrap();
        assert_eq!(by_jurisdiction.len(), 1);
    }

    #[test]
    fn test_encumbrance_store() {
        let (db, _dir) = temp_db();
        let store = EncumbranceStore::new(&db);

        let asset_id = [1u8; 32];
        let enc = sample_encumbrance(&asset_id);
        store.put(&enc).unwrap();

        let retrieved = store.get(&enc.encumbrance_id).unwrap().unwrap();
        assert_eq!(retrieved.encumbrance_id, enc.encumbrance_id);

        // Test asset index
        let by_asset = store.get_by_asset(&asset_id).unwrap();
        assert_eq!(by_asset.len(), 1);

        // Test active filter
        let active = store.get_active_by_asset(&asset_id, 1500).unwrap();
        assert_eq!(active.len(), 1);
    }

    #[test]
    fn test_coverage_store() {
        let (db, _dir) = temp_db();
        let store = CoverageStore::new(&db);

        let asset_id = [1u8; 32];
        let cov = sample_coverage(&asset_id);
        store.put(&cov).unwrap();

        let retrieved = store.get(&cov.coverage_id).unwrap().unwrap();
        assert_eq!(retrieved.coverage_id, cov.coverage_id);

        // Test active filter
        let active = store.get_active_by_asset(&asset_id, 1500).unwrap();
        assert_eq!(active.len(), 1);
    }

    #[test]
    fn test_claim_store() {
        let (db, _dir) = temp_db();
        let store = ClaimStore::new(&db);

        let asset_id = [1u8; 32];
        let coverage_id = [12u8; 32];
        let claim = sample_claim(&coverage_id, &asset_id);
        store.put(&claim).unwrap();

        let retrieved = store.get(&claim.claim_id).unwrap().unwrap();
        assert_eq!(retrieved.claim_id, claim.claim_id);
        assert!(retrieved.is_open());

        // Test coverage index
        let by_coverage = store.get_by_coverage(&coverage_id).unwrap();
        assert_eq!(by_coverage.len(), 1);

        // Test status update
        store.update_status(&claim.claim_id, ClaimStatus::Approved, 1100).unwrap();
        let updated = store.get(&claim.claim_id).unwrap().unwrap();
        assert_eq!(updated.status, ClaimStatus::Approved);
    }

    #[test]
    fn test_property_store_combined() {
        let (db, _dir) = temp_db();
        let store = PropertyStore::new(&db);

        // Store asset
        let asset = sample_asset();
        store.assets().put(&asset).unwrap();

        // Store encumbrance
        let enc = sample_encumbrance(&asset.asset_id);
        store.encumbrances().put(&enc).unwrap();

        // Store coverage
        let cov = sample_coverage(&asset.asset_id);
        store.coverage().put(&cov).unwrap();

        // Store claim
        let claim = sample_claim(&cov.coverage_id, &asset.asset_id);
        store.claims().put(&claim).unwrap();

        // Verify all stored
        assert!(store.assets().exists(&asset.asset_id).unwrap());
        assert!(store.encumbrances().exists(&enc.encumbrance_id).unwrap());
        assert!(store.coverage().exists(&cov.coverage_id).unwrap());
        assert!(store.claims().exists(&claim.claim_id).unwrap());
    }
}
