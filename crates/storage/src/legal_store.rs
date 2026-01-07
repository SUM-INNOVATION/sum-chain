//! SRC-85X Legal & Benefits Storage
//!
//! Storage layer for:
//! - SRC-851: Case/Docket Anchors
//! - SRC-852: Legal Process Events
//! - SRC-853: Court Orders/Judgments
//! - SRC-854: Government Benefit Determinations
//! - SRC-855: Legal Proofs

use sumchain_primitives::{
    legal::{
        BenefitDetermination, BenefitStatus, CaseAnchor, CaseStatus, CourtOrder, LegalEvent,
        LegalProofEnvelope, OrderStatus, ProcessEvent, ProcessEventStatus,
    },
    Address, BlockHeight, Timestamp,
};

use crate::db::{cf, Database};
use crate::{Result, StorageError};

// Type aliases for clarity
pub type CaseId = [u8; 32];
pub type ProcessEventId = [u8; 32];
pub type OrderId = [u8; 32];
pub type BenefitId = [u8; 32];
pub type ProofId = [u8; 32];

// =============================================================================
// Case Anchor Storage (SRC-851)
// =============================================================================

/// Storage for Case Anchors (SRC-851)
pub struct CaseStore<'a> {
    db: &'a Database,
}

impl<'a> CaseStore<'a> {
    pub fn new(db: &'a Database) -> Self {
        Self { db }
    }

    /// Store a case anchor
    pub fn put(&self, case: &CaseAnchor) -> Result<()> {
        let bytes = bincode::serialize(case)
            .map_err(|e| StorageError::Serialization(e.to_string()))?;
        self.db.put(cf::LEGAL_CASES, &case.case_id, &bytes)?;

        // Update jurisdiction index
        self.add_to_jurisdiction_index(&case.jurisdiction_code, &case.case_id, "case")?;

        Ok(())
    }

    /// Get a case by ID
    pub fn get(&self, case_id: &CaseId) -> Result<Option<CaseAnchor>> {
        match self.db.get(cf::LEGAL_CASES, case_id)? {
            Some(bytes) => {
                let case: CaseAnchor = bincode::deserialize(&bytes)
                    .map_err(|e| StorageError::Serialization(e.to_string()))?;
                Ok(Some(case))
            }
            None => Ok(None),
        }
    }

    /// Check if case exists
    pub fn exists(&self, case_id: &CaseId) -> Result<bool> {
        self.db.contains(cf::LEGAL_CASES, case_id)
    }

    /// Update case status
    pub fn update_status(
        &self,
        case_id: &CaseId,
        status: CaseStatus,
        timestamp: Timestamp,
    ) -> Result<()> {
        match self.get(case_id)? {
            Some(mut case) => {
                case.status = status;
                case.updated_at = timestamp;
                let bytes = bincode::serialize(&case)
                    .map_err(|e| StorageError::Serialization(e.to_string()))?;
                self.db.put(cf::LEGAL_CASES, case_id, &bytes)
            }
            None => Err(StorageError::NotFound(format!(
                "Case not found: {:?}",
                case_id
            ))),
        }
    }

    /// Get cases by jurisdiction
    pub fn get_by_jurisdiction(&self, jurisdiction: &str) -> Result<Vec<CaseAnchor>> {
        let ids = self.get_jurisdiction_case_ids(jurisdiction)?;
        let mut cases = Vec::new();
        for id in ids {
            if let Some(case) = self.get(&id)? {
                cases.push(case);
            }
        }
        Ok(cases)
    }

    /// List active cases
    pub fn list_active(&self) -> Result<Vec<CaseAnchor>> {
        let mut cases = Vec::new();
        for (_, value) in self.db.iter(cf::LEGAL_CASES)? {
            let case: CaseAnchor = bincode::deserialize(&value)
                .map_err(|e| StorageError::Serialization(e.to_string()))?;
            if case.status == CaseStatus::Active || case.status == CaseStatus::Filed {
                cases.push(case);
            }
        }
        Ok(cases)
    }

    /// Add related case
    pub fn add_related_case(
        &self,
        case_id: &CaseId,
        related_case_id: &CaseId,
        timestamp: Timestamp,
    ) -> Result<()> {
        match self.get(case_id)? {
            Some(mut case) => {
                if !case.related_cases.contains(related_case_id) {
                    case.related_cases.push(*related_case_id);
                    case.updated_at = timestamp;
                    let bytes = bincode::serialize(&case)
                        .map_err(|e| StorageError::Serialization(e.to_string()))?;
                    self.db.put(cf::LEGAL_CASES, case_id, &bytes)?;
                }
                Ok(())
            }
            None => Err(StorageError::NotFound(format!(
                "Case not found: {:?}",
                case_id
            ))),
        }
    }

    // Index helpers
    fn add_to_jurisdiction_index(
        &self,
        jurisdiction: &str,
        id: &[u8; 32],
        id_type: &str,
    ) -> Result<()> {
        let key = format!("{}:{}", jurisdiction, id_type);
        let mut ids = self.get_jurisdiction_ids(&key)?;
        if !ids.contains(id) {
            ids.push(*id);
            let bytes = bincode::serialize(&ids)
                .map_err(|e| StorageError::Serialization(e.to_string()))?;
            self.db.put(cf::LEGAL_JURISDICTION_INDEX, key.as_bytes(), &bytes)?;
        }
        Ok(())
    }

    fn get_jurisdiction_ids(&self, key: &str) -> Result<Vec<[u8; 32]>> {
        match self.db.get(cf::LEGAL_JURISDICTION_INDEX, key.as_bytes())? {
            Some(bytes) => {
                let ids: Vec<[u8; 32]> = bincode::deserialize(&bytes)
                    .map_err(|e| StorageError::Serialization(e.to_string()))?;
                Ok(ids)
            }
            None => Ok(Vec::new()),
        }
    }

    fn get_jurisdiction_case_ids(&self, jurisdiction: &str) -> Result<Vec<CaseId>> {
        self.get_jurisdiction_ids(&format!("{}:case", jurisdiction))
    }
}

// =============================================================================
// Process Event Storage (SRC-852)
// =============================================================================

/// Storage for Process Events (SRC-852)
pub struct ProcessEventStore<'a> {
    db: &'a Database,
}

impl<'a> ProcessEventStore<'a> {
    pub fn new(db: &'a Database) -> Self {
        Self { db }
    }

    /// Store a process event
    pub fn put(&self, event: &ProcessEvent) -> Result<()> {
        let bytes = bincode::serialize(event)
            .map_err(|e| StorageError::Serialization(e.to_string()))?;
        self.db.put(cf::LEGAL_EVENTS, &event.event_id, &bytes)?;

        // Update case event index
        self.add_to_case_index(&event.case_id, &event.event_id)?;

        Ok(())
    }

    /// Get an event by ID
    pub fn get(&self, event_id: &ProcessEventId) -> Result<Option<ProcessEvent>> {
        match self.db.get(cf::LEGAL_EVENTS, event_id)? {
            Some(bytes) => {
                let event: ProcessEvent = bincode::deserialize(&bytes)
                    .map_err(|e| StorageError::Serialization(e.to_string()))?;
                Ok(Some(event))
            }
            None => Ok(None),
        }
    }

    /// Check if event exists
    pub fn exists(&self, event_id: &ProcessEventId) -> Result<bool> {
        self.db.contains(cf::LEGAL_EVENTS, event_id)
    }

    /// Update event status
    pub fn update_status(
        &self,
        event_id: &ProcessEventId,
        status: ProcessEventStatus,
    ) -> Result<()> {
        match self.get(event_id)? {
            Some(mut event) => {
                event.status = status;
                let bytes = bincode::serialize(&event)
                    .map_err(|e| StorageError::Serialization(e.to_string()))?;
                self.db.put(cf::LEGAL_EVENTS, event_id, &bytes)
            }
            None => Err(StorageError::NotFound(format!(
                "Process event not found: {:?}",
                event_id
            ))),
        }
    }

    /// Get events by case
    pub fn get_by_case(&self, case_id: &CaseId) -> Result<Vec<ProcessEvent>> {
        let event_ids = self.get_case_event_ids(case_id)?;
        let mut events = Vec::new();
        for id in event_ids {
            if let Some(event) = self.get(&id)? {
                events.push(event);
            }
        }
        Ok(events)
    }

    /// Get active events for a case
    pub fn get_active_by_case(&self, case_id: &CaseId) -> Result<Vec<ProcessEvent>> {
        let events = self.get_by_case(case_id)?;
        Ok(events
            .into_iter()
            .filter(|e| e.status == ProcessEventStatus::Recorded)
            .collect())
    }

    // Index helpers
    fn add_to_case_index(&self, case_id: &CaseId, event_id: &ProcessEventId) -> Result<()> {
        let mut ids = self.get_case_event_ids(case_id)?;
        if !ids.contains(event_id) {
            ids.push(*event_id);
            let bytes = bincode::serialize(&ids)
                .map_err(|e| StorageError::Serialization(e.to_string()))?;
            self.db.put(cf::LEGAL_CASE_EVENT_INDEX, case_id, &bytes)?;
        }
        Ok(())
    }

    fn get_case_event_ids(&self, case_id: &CaseId) -> Result<Vec<ProcessEventId>> {
        match self.db.get(cf::LEGAL_CASE_EVENT_INDEX, case_id)? {
            Some(bytes) => {
                let ids: Vec<ProcessEventId> = bincode::deserialize(&bytes)
                    .map_err(|e| StorageError::Serialization(e.to_string()))?;
                Ok(ids)
            }
            None => Ok(Vec::new()),
        }
    }
}

// =============================================================================
// Court Order Storage (SRC-853)
// =============================================================================

/// Storage for Court Orders (SRC-853)
pub struct OrderStore<'a> {
    db: &'a Database,
}

impl<'a> OrderStore<'a> {
    pub fn new(db: &'a Database) -> Self {
        Self { db }
    }

    /// Store an order
    pub fn put(&self, order: &CourtOrder) -> Result<()> {
        let bytes = bincode::serialize(order)
            .map_err(|e| StorageError::Serialization(e.to_string()))?;
        self.db.put(cf::LEGAL_ORDERS, &order.order_id, &bytes)?;

        // Update case order index
        self.add_to_case_index(&order.case_id, &order.order_id)?;

        Ok(())
    }

    /// Get an order by ID
    pub fn get(&self, order_id: &OrderId) -> Result<Option<CourtOrder>> {
        match self.db.get(cf::LEGAL_ORDERS, order_id)? {
            Some(bytes) => {
                let order: CourtOrder = bincode::deserialize(&bytes)
                    .map_err(|e| StorageError::Serialization(e.to_string()))?;
                Ok(Some(order))
            }
            None => Ok(None),
        }
    }

    /// Check if order exists
    pub fn exists(&self, order_id: &OrderId) -> Result<bool> {
        self.db.contains(cf::LEGAL_ORDERS, order_id)
    }

    /// Update order status
    pub fn update_status(
        &self,
        order_id: &OrderId,
        status: OrderStatus,
        timestamp: Timestamp,
    ) -> Result<()> {
        match self.get(order_id)? {
            Some(mut order) => {
                order.status = status;
                order.updated_at = timestamp;
                let bytes = bincode::serialize(&order)
                    .map_err(|e| StorageError::Serialization(e.to_string()))?;
                self.db.put(cf::LEGAL_ORDERS, order_id, &bytes)
            }
            None => Err(StorageError::NotFound(format!(
                "Order not found: {:?}",
                order_id
            ))),
        }
    }

    /// Get orders by case
    pub fn get_by_case(&self, case_id: &CaseId) -> Result<Vec<CourtOrder>> {
        let order_ids = self.get_case_order_ids(case_id)?;
        let mut orders = Vec::new();
        for id in order_ids {
            if let Some(order) = self.get(&id)? {
                orders.push(order);
            }
        }
        Ok(orders)
    }

    /// Get active orders for a case
    pub fn get_active_by_case(&self, case_id: &CaseId, current_time: Timestamp) -> Result<Vec<CourtOrder>> {
        let orders = self.get_by_case(case_id)?;
        Ok(orders
            .into_iter()
            .filter(|o| o.is_in_effect(current_time))
            .collect())
    }

    /// List all active orders
    pub fn list_active(&self, current_time: Timestamp) -> Result<Vec<CourtOrder>> {
        let mut orders = Vec::new();
        for (_, value) in self.db.iter(cf::LEGAL_ORDERS)? {
            let order: CourtOrder = bincode::deserialize(&value)
                .map_err(|e| StorageError::Serialization(e.to_string()))?;
            if order.is_in_effect(current_time) {
                orders.push(order);
            }
        }
        Ok(orders)
    }

    // Index helpers
    fn add_to_case_index(&self, case_id: &CaseId, order_id: &OrderId) -> Result<()> {
        let mut ids = self.get_case_order_ids(case_id)?;
        if !ids.contains(order_id) {
            ids.push(*order_id);
            let bytes = bincode::serialize(&ids)
                .map_err(|e| StorageError::Serialization(e.to_string()))?;
            self.db.put(cf::LEGAL_CASE_ORDER_INDEX, case_id, &bytes)?;
        }
        Ok(())
    }

    fn get_case_order_ids(&self, case_id: &CaseId) -> Result<Vec<OrderId>> {
        match self.db.get(cf::LEGAL_CASE_ORDER_INDEX, case_id)? {
            Some(bytes) => {
                let ids: Vec<OrderId> = bincode::deserialize(&bytes)
                    .map_err(|e| StorageError::Serialization(e.to_string()))?;
                Ok(ids)
            }
            None => Ok(Vec::new()),
        }
    }
}

// =============================================================================
// Benefit Determination Storage (SRC-854)
// =============================================================================

/// Storage for Benefit Determinations (SRC-854)
pub struct BenefitStore<'a> {
    db: &'a Database,
}

impl<'a> BenefitStore<'a> {
    pub fn new(db: &'a Database) -> Self {
        Self { db }
    }

    /// Store a benefit determination
    pub fn put(&self, benefit: &BenefitDetermination) -> Result<()> {
        let bytes = bincode::serialize(benefit)
            .map_err(|e| StorageError::Serialization(e.to_string()))?;
        self.db.put(cf::LEGAL_BENEFITS, &benefit.benefit_id, &bytes)?;

        // Update jurisdiction index
        self.add_to_jurisdiction_index(&benefit.jurisdiction_code, &benefit.benefit_id)?;

        Ok(())
    }

    /// Get a benefit by ID
    pub fn get(&self, benefit_id: &BenefitId) -> Result<Option<BenefitDetermination>> {
        match self.db.get(cf::LEGAL_BENEFITS, benefit_id)? {
            Some(bytes) => {
                let benefit: BenefitDetermination = bincode::deserialize(&bytes)
                    .map_err(|e| StorageError::Serialization(e.to_string()))?;
                Ok(Some(benefit))
            }
            None => Ok(None),
        }
    }

    /// Check if benefit exists
    pub fn exists(&self, benefit_id: &BenefitId) -> Result<bool> {
        self.db.contains(cf::LEGAL_BENEFITS, benefit_id)
    }

    /// Update benefit status
    pub fn update_status(
        &self,
        benefit_id: &BenefitId,
        status: BenefitStatus,
        timestamp: Timestamp,
    ) -> Result<()> {
        match self.get(benefit_id)? {
            Some(mut benefit) => {
                benefit.status = status;
                benefit.updated_at = timestamp;
                let bytes = bincode::serialize(&benefit)
                    .map_err(|e| StorageError::Serialization(e.to_string()))?;
                self.db.put(cf::LEGAL_BENEFITS, benefit_id, &bytes)
            }
            None => Err(StorageError::NotFound(format!(
                "Benefit not found: {:?}",
                benefit_id
            ))),
        }
    }

    /// Get benefits by subject nullifier
    pub fn get_by_subject(&self, subject_nullifier: &[u8; 32]) -> Result<Vec<BenefitDetermination>> {
        let mut benefits = Vec::new();
        for (_, value) in self.db.iter(cf::LEGAL_BENEFITS)? {
            let benefit: BenefitDetermination = bincode::deserialize(&value)
                .map_err(|e| StorageError::Serialization(e.to_string()))?;
            if benefit.subject_nullifier == *subject_nullifier {
                benefits.push(benefit);
            }
        }
        Ok(benefits)
    }

    /// Get valid benefits for subject (not expired)
    pub fn get_valid_for_subject(
        &self,
        subject_nullifier: &[u8; 32],
        current_time: Timestamp,
    ) -> Result<Vec<BenefitDetermination>> {
        let benefits = self.get_by_subject(subject_nullifier)?;
        Ok(benefits
            .into_iter()
            .filter(|b| b.is_valid(current_time))
            .collect())
    }

    /// Get benefits by jurisdiction
    pub fn get_by_jurisdiction(&self, jurisdiction: &str) -> Result<Vec<BenefitDetermination>> {
        let ids = self.get_jurisdiction_benefit_ids(jurisdiction)?;
        let mut benefits = Vec::new();
        for id in ids {
            if let Some(benefit) = self.get(&id)? {
                benefits.push(benefit);
            }
        }
        Ok(benefits)
    }

    /// List approved benefits
    pub fn list_approved(&self, current_time: Timestamp) -> Result<Vec<BenefitDetermination>> {
        let mut benefits = Vec::new();
        for (_, value) in self.db.iter(cf::LEGAL_BENEFITS)? {
            let benefit: BenefitDetermination = bincode::deserialize(&value)
                .map_err(|e| StorageError::Serialization(e.to_string()))?;
            if benefit.is_valid(current_time) {
                benefits.push(benefit);
            }
        }
        Ok(benefits)
    }

    // Index helpers
    fn add_to_jurisdiction_index(&self, jurisdiction: &str, benefit_id: &BenefitId) -> Result<()> {
        let key = format!("{}:benefit", jurisdiction);
        let mut ids = self.get_jurisdiction_ids(&key)?;
        if !ids.contains(benefit_id) {
            ids.push(*benefit_id);
            let bytes = bincode::serialize(&ids)
                .map_err(|e| StorageError::Serialization(e.to_string()))?;
            self.db.put(cf::LEGAL_JURISDICTION_INDEX, key.as_bytes(), &bytes)?;
        }
        Ok(())
    }

    fn get_jurisdiction_ids(&self, key: &str) -> Result<Vec<[u8; 32]>> {
        match self.db.get(cf::LEGAL_JURISDICTION_INDEX, key.as_bytes())? {
            Some(bytes) => {
                let ids: Vec<[u8; 32]> = bincode::deserialize(&bytes)
                    .map_err(|e| StorageError::Serialization(e.to_string()))?;
                Ok(ids)
            }
            None => Ok(Vec::new()),
        }
    }

    fn get_jurisdiction_benefit_ids(&self, jurisdiction: &str) -> Result<Vec<BenefitId>> {
        self.get_jurisdiction_ids(&format!("{}:benefit", jurisdiction))
    }
}

// =============================================================================
// Legal Proof Storage (SRC-855)
// =============================================================================

/// Storage for Legal Proofs (SRC-855)
pub struct LegalProofStore<'a> {
    db: &'a Database,
}

impl<'a> LegalProofStore<'a> {
    pub fn new(db: &'a Database) -> Self {
        Self { db }
    }

    /// Store a proof
    pub fn put(&self, proof: &LegalProofEnvelope) -> Result<()> {
        let bytes = bincode::serialize(proof)
            .map_err(|e| StorageError::Serialization(e.to_string()))?;
        self.db.put(cf::LEGAL_PROOFS, &proof.proof_id, &bytes)
    }

    /// Get a proof by ID
    pub fn get(&self, proof_id: &ProofId) -> Result<Option<LegalProofEnvelope>> {
        match self.db.get(cf::LEGAL_PROOFS, proof_id)? {
            Some(bytes) => {
                let proof: LegalProofEnvelope = bincode::deserialize(&bytes)
                    .map_err(|e| StorageError::Serialization(e.to_string()))?;
                Ok(Some(proof))
            }
            None => Ok(None),
        }
    }

    /// Check if proof exists
    pub fn exists(&self, proof_id: &ProofId) -> Result<bool> {
        self.db.contains(cf::LEGAL_PROOFS, proof_id)
    }

    /// Delete a proof
    pub fn delete(&self, proof_id: &ProofId) -> Result<()> {
        self.db.delete(cf::LEGAL_PROOFS, proof_id)
    }

    /// Get valid proofs for subject (not expired)
    pub fn get_valid_for_subject(
        &self,
        subject_nullifier: &[u8; 32],
        current_time: Timestamp,
    ) -> Result<Vec<LegalProofEnvelope>> {
        let mut proofs = Vec::new();
        for (_, value) in self.db.iter(cf::LEGAL_PROOFS)? {
            let proof: LegalProofEnvelope = bincode::deserialize(&value)
                .map_err(|e| StorageError::Serialization(e.to_string()))?;
            if proof.subject_nullifier == *subject_nullifier
                && (proof.expires_at == 0 || proof.expires_at > current_time)
            {
                proofs.push(proof);
            }
        }
        Ok(proofs)
    }

    /// Get proofs by profile ID
    pub fn get_by_profile(&self, profile_id: &str) -> Result<Vec<LegalProofEnvelope>> {
        let mut proofs = Vec::new();
        for (_, value) in self.db.iter(cf::LEGAL_PROOFS)? {
            let proof: LegalProofEnvelope = bincode::deserialize(&value)
                .map_err(|e| StorageError::Serialization(e.to_string()))?;
            if proof.profile_id == profile_id {
                proofs.push(proof);
            }
        }
        Ok(proofs)
    }
}

// =============================================================================
// Legal Event Storage
// =============================================================================

/// Storage for Legal System Events
pub struct LegalEventStore<'a> {
    db: &'a Database,
}

impl<'a> LegalEventStore<'a> {
    pub fn new(db: &'a Database) -> Self {
        Self { db }
    }

    /// Store an event
    pub fn put(&self, block_height: BlockHeight, tx_index: u32, event: &LegalEvent) -> Result<()> {
        let mut key = [0u8; 12];
        key[..8].copy_from_slice(&block_height.to_be_bytes());
        key[8..12].copy_from_slice(&tx_index.to_be_bytes());

        let bytes = bincode::serialize(event)
            .map_err(|e| StorageError::Serialization(e.to_string()))?;
        self.db.put(cf::LEGAL_SYSTEM_EVENTS, &key, &bytes)
    }

    /// Get events by block height range
    pub fn get_by_height_range(
        &self,
        start_height: BlockHeight,
        end_height: BlockHeight,
    ) -> Result<Vec<(BlockHeight, u32, LegalEvent)>> {
        let mut events = Vec::new();
        for (key, value) in self.db.iter(cf::LEGAL_SYSTEM_EVENTS)? {
            if key.len() < 12 {
                continue;
            }
            let mut height_bytes = [0u8; 8];
            let mut idx_bytes = [0u8; 4];
            height_bytes.copy_from_slice(&key[..8]);
            idx_bytes.copy_from_slice(&key[8..12]);

            let height = u64::from_be_bytes(height_bytes);
            let idx = u32::from_be_bytes(idx_bytes);

            if height >= start_height && height <= end_height {
                let event: LegalEvent = bincode::deserialize(&value)
                    .map_err(|e| StorageError::Serialization(e.to_string()))?;
                events.push((height, idx, event));
            }
        }
        Ok(events)
    }
}

// =============================================================================
// Main Legal Store (Facade)
// =============================================================================

/// Main facade for all SRC-85X storage operations
pub struct LegalStore<'a> {
    db: &'a Database,
}

impl<'a> LegalStore<'a> {
    pub fn new(db: &'a Database) -> Self {
        Self { db }
    }

    /// Get case store
    pub fn cases(&self) -> CaseStore {
        CaseStore::new(self.db)
    }

    /// Get process event store
    pub fn process_events(&self) -> ProcessEventStore {
        ProcessEventStore::new(self.db)
    }

    /// Get order store
    pub fn orders(&self) -> OrderStore {
        OrderStore::new(self.db)
    }

    /// Get benefit store
    pub fn benefits(&self) -> BenefitStore {
        BenefitStore::new(self.db)
    }

    /// Get proof store
    pub fn proofs(&self) -> LegalProofStore {
        LegalProofStore::new(self.db)
    }

    /// Get event store
    pub fn events(&self) -> LegalEventStore {
        LegalEventStore::new(self.db)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sumchain_primitives::legal::{
        BenefitType, CaseType, LegalIssuerClass, LegalProofProfile, LegalProofType, OrderType,
        ProcessEventType,
    };
    use tempfile::TempDir;

    fn temp_db() -> (Database, TempDir) {
        let dir = TempDir::new().unwrap();
        let db = Database::open_default(dir.path()).unwrap();
        (db, dir)
    }

    #[test]
    fn test_case_store() {
        let (db, _dir) = temp_db();
        let store = CaseStore::new(&db);

        let case = CaseAnchor {
            case_id: [10u8; 32],
            case_commitment: [11u8; 32],
            jurisdiction_code: "US-NY-SDNY".to_string(),
            case_type: Some(CaseType::Civil),
            public_reference: None,
            policy_id: [12u8; 32],
            issuer_class: LegalIssuerClass::LawFirm,
            issuer_address: Address::new([1u8; 20]),
            status: CaseStatus::Filed,
            created_at: 1000,
            updated_at: 1000,
            anchored_at_height: 100,
            related_cases: vec![],
        };

        store.put(&case).unwrap();
        let retrieved = store.get(&[10u8; 32]).unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().jurisdiction_code, "US-NY-SDNY");

        // Test jurisdiction index
        let by_jurisdiction = store.get_by_jurisdiction("US-NY-SDNY").unwrap();
        assert_eq!(by_jurisdiction.len(), 1);
    }

    #[test]
    fn test_process_event_store() {
        let (db, _dir) = temp_db();
        let store = ProcessEventStore::new(&db);

        let event = ProcessEvent {
            event_id: [20u8; 32],
            case_id: [10u8; 32],
            event_type: ProcessEventType::Filed,
            event_commitment: [21u8; 32],
            issuer_address: Address::new([1u8; 20]),
            issuer_class: LegalIssuerClass::LawFirm,
            event_time_start: Some(1000),
            event_time_end: None,
            attachments: vec![],
            policy_id: [22u8; 32],
            revocation_ref: None,
            status: ProcessEventStatus::Recorded,
            created_at: 1000,
            recorded_at_height: 100,
            supersedes: None,
        };

        store.put(&event).unwrap();
        let retrieved = store.get(&[20u8; 32]).unwrap();
        assert!(retrieved.is_some());

        // Test case index
        let by_case = store.get_by_case(&[10u8; 32]).unwrap();
        assert_eq!(by_case.len(), 1);
    }

    #[test]
    fn test_order_store() {
        let (db, _dir) = temp_db();
        let store = OrderStore::new(&db);

        let order = CourtOrder {
            order_id: [30u8; 32],
            case_id: [10u8; 32],
            order_type: OrderType::FinalJudgment,
            order_commitment: [31u8; 32],
            issuer_address: Address::new([1u8; 20]),
            issuer_class: LegalIssuerClass::CourtSystem,
            status: OrderStatus::Active,
            effective_from: 1000,
            expiry: Some(2000),
            policy_id: [32u8; 32],
            revocation_ref: None,
            created_at: 1000,
            updated_at: 1000,
            issued_at_height: 100,
            supersedes_order_id: None,
            attachments: vec![],
        };

        store.put(&order).unwrap();
        let retrieved = store.get(&[30u8; 32]).unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().order_type, OrderType::FinalJudgment);

        // Test active orders
        let active = store.get_active_by_case(&[10u8; 32], 1500).unwrap();
        assert_eq!(active.len(), 1);
    }

    #[test]
    fn test_benefit_store() {
        let (db, _dir) = temp_db();
        let store = BenefitStore::new(&db);

        let benefit = BenefitDetermination {
            benefit_id: [40u8; 32],
            benefit_type: BenefitType::Medicare,
            jurisdiction_code: "US".to_string(),
            status: BenefitStatus::Approved,
            determination_commitment: [41u8; 32],
            subject_nullifier: [42u8; 32],
            issuer_address: Address::new([1u8; 20]),
            issuer_class: LegalIssuerClass::GovernmentAgency,
            valid_from: 1000,
            expiry: None,
            policy_id: [43u8; 32],
            revocation_ref: None,
            created_at: 1000,
            updated_at: 1000,
            recorded_at_height: 100,
            supersedes: None,
        };

        store.put(&benefit).unwrap();
        let retrieved = store.get(&[40u8; 32]).unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().benefit_type, BenefitType::Medicare);

        // Test get by subject
        let by_subject = store.get_by_subject(&[42u8; 32]).unwrap();
        assert_eq!(by_subject.len(), 1);

        // Test valid benefits
        let valid = store.get_valid_for_subject(&[42u8; 32], 1500).unwrap();
        assert_eq!(valid.len(), 1);
    }

    #[test]
    fn test_legal_proof_store() {
        let (db, _dir) = temp_db();
        let store = LegalProofStore::new(&db);

        let proof = LegalProofEnvelope {
            proof_id: [50u8; 32],
            profile: LegalProofProfile::BenefitApproved,
            profile_id: "legal.benefit_approved.v1".to_string(),
            policy_ids: vec![[51u8; 32]],
            public_inputs: vec![1, 2, 3],
            proof_data: vec![4, 5, 6],
            proof_type: LegalProofType::Mock,
            subject_nullifier: [52u8; 32],
            generated_at: 1000,
            expires_at: 2000,
        };

        store.put(&proof).unwrap();
        let retrieved = store.get(&[50u8; 32]).unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().profile_id, "legal.benefit_approved.v1");

        // Test valid proofs
        let valid = store.get_valid_for_subject(&[52u8; 32], 1500).unwrap();
        assert_eq!(valid.len(), 1);
    }

    #[test]
    fn test_case_status_update() {
        let (db, _dir) = temp_db();
        let store = CaseStore::new(&db);

        let case = CaseAnchor {
            case_id: [10u8; 32],
            case_commitment: [11u8; 32],
            jurisdiction_code: "US-NY".to_string(),
            case_type: Some(CaseType::Civil),
            public_reference: None,
            policy_id: [12u8; 32],
            issuer_class: LegalIssuerClass::LawFirm,
            issuer_address: Address::new([1u8; 20]),
            status: CaseStatus::Filed,
            created_at: 1000,
            updated_at: 1000,
            anchored_at_height: 100,
            related_cases: vec![],
        };

        store.put(&case).unwrap();

        // Update status
        store.update_status(&[10u8; 32], CaseStatus::Active, 1500).unwrap();
        let updated = store.get(&[10u8; 32]).unwrap().unwrap();
        assert_eq!(updated.status, CaseStatus::Active);
        assert_eq!(updated.updated_at, 1500);
    }

    #[test]
    fn test_order_active_check() {
        let (db, _dir) = temp_db();
        let store = OrderStore::new(&db);

        // Active order with expiry
        let order1 = CourtOrder {
            order_id: [30u8; 32],
            case_id: [10u8; 32],
            order_type: OrderType::Tro,
            order_commitment: [31u8; 32],
            issuer_address: Address::new([1u8; 20]),
            issuer_class: LegalIssuerClass::CourtSystem,
            status: OrderStatus::Active,
            effective_from: 1000,
            expiry: Some(2000),
            policy_id: [32u8; 32],
            revocation_ref: None,
            created_at: 1000,
            updated_at: 1000,
            issued_at_height: 100,
            supersedes_order_id: None,
            attachments: vec![],
        };

        // Stayed order
        let order2 = CourtOrder {
            order_id: [31u8; 32],
            case_id: [10u8; 32],
            order_type: OrderType::PreliminaryInjunction,
            order_commitment: [32u8; 32],
            issuer_address: Address::new([1u8; 20]),
            issuer_class: LegalIssuerClass::CourtSystem,
            status: OrderStatus::Stayed,
            effective_from: 1000,
            expiry: None,
            policy_id: [33u8; 32],
            revocation_ref: None,
            created_at: 1000,
            updated_at: 1000,
            issued_at_height: 100,
            supersedes_order_id: None,
            attachments: vec![],
        };

        store.put(&order1).unwrap();
        store.put(&order2).unwrap();

        // Before expiry - only active order
        let active_1500 = store.get_active_by_case(&[10u8; 32], 1500).unwrap();
        assert_eq!(active_1500.len(), 1);
        assert_eq!(active_1500[0].order_id, [30u8; 32]);

        // After expiry - no active orders
        let active_2500 = store.get_active_by_case(&[10u8; 32], 2500).unwrap();
        assert_eq!(active_2500.len(), 0);
    }
}
