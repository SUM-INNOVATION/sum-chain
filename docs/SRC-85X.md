# SRC-85X: Court & Legal Process, Government Benefits

## Overview

SRC-85X is a privacy-first infrastructure for managing court cases, legal process events, court orders, and government benefit determinations on the SUM Chain. It enables privacy-preserving verification of legal status without exposing sensitive case details.

## Design Principles

1. **Privacy-First**: Case details, party identities, and sensitive information stored as BLAKE3 commitments only.
2. **Dual Issuer Support**: Supports both "lowkey" issuers (notaries, law firms) and "official" issuers (courts, government agencies).
3. **Policy-Driven Trust**: All operations governed by SRC-803 policies.
4. **SRC-805 Revocation Compatible**: All entities support revocation references.

---

## Issuer Classification

SRC-85X supports a two-phase issuer model:

### Phase 1: Lowkey Issuers
Lower barrier to entry, higher verification burden for relying parties.

| Class | Description | Trust Level |
|-------|-------------|-------------|
| `LawFirm` | Licensed law firms | Medium |
| `Notary` | Licensed notaries | Medium |
| `LegalAid` | Legal aid organizations | Medium |
| `ProcessServer` | Licensed process servers | Low |
| `Auditor` | Licensed auditors | Medium |

### Phase 2: Official Issuers
Higher trust, authoritative records.

| Class | Description | Trust Level |
|-------|-------------|-------------|
| `CourtSystem` | State/federal courts | High |
| `GovernmentAgency` | Government agencies | High |
| `Tribunal` | Administrative tribunals | High |

```rust
impl LegalIssuerClass {
    /// Check if this is an official issuer (Phase 2)
    pub fn is_official(&self) -> bool {
        matches!(self, CourtSystem | GovernmentAgency | Tribunal)
    }

    /// Check if this is a lowkey issuer (Phase 1)
    pub fn is_lowkey(&self) -> bool {
        matches!(self, LawFirm | Notary | LegalAid | ProcessServer | Auditor)
    }
}
```

---

## Standards

### SRC-851: Case/Docket Anchor

Privacy-safe case anchoring with jurisdiction support.

#### Data Structures

```rust
/// Case Anchor
struct CaseAnchor {
    case_id: [u8; 32],                 // Unique identifier
    case_commitment: [u8; 32],         // BLAKE3 hash of case details
    jurisdiction_code: String,         // e.g., "US-NY-SDNY", "UK-EW"
    case_type: Option<CaseType>,
    public_reference: Option<String>,  // Optional public docket number
    policy_id: [u8; 32],
    issuer_class: LegalIssuerClass,
    issuer_address: Address,
    status: CaseStatus,
    created_at: Timestamp,
    updated_at: Timestamp,
    anchored_at_height: BlockHeight,
    related_cases: Vec<CaseId>,        // Consolidated/related cases
}

/// Case Types
enum CaseType {
    Civil = 0,
    Criminal = 1,
    Administrative = 2,
    Bankruptcy = 3,
    Family = 4,
    Probate = 5,
    Tax = 6,
    Immigration = 7,
    Intellectual = 8,
    Labor = 9,
    Environmental = 10,
    Securities = 11,
    Antitrust = 12,
    Other = 255,
}

/// Case Status
enum CaseStatus {
    Filed = 0,
    Active = 1,
    Stayed = 2,
    Closed = 3,
    Dismissed = 4,
    Sealed = 5,
    Transferred = 6,
    Consolidated = 7,
    Appealed = 8,
}
```

#### Operations

| Code | Operation | Description |
|------|-----------|-------------|
| 0 | `AnchorCase` | Create a new case anchor |
| 1 | `UpdateCase` | Update case status |
| 2 | `CloseCase` | Close a case |
| 3 | `SealCase` | Seal a case (restrict access) |
| 4 | `UnsealCase` | Unseal a case |
| 5 | `ConsolidateCase` | Link to related case |
| 6 | `TransferCase` | Mark case as transferred |

#### ID Generation

```rust
fn generate_case_id(
    issuer: &Address,
    commitment: &[u8; 32],
    jurisdiction: &str,
    nonce: &[u8; 32],
) -> [u8; 32] {
    blake3::hash(b"SRC851-CASE:v1:" || issuer || commitment || jurisdiction || nonce)
}

fn generate_case_commitment(
    details_hash: &[u8; 32],
    parties_hash: &[u8; 32],
    filing_date: Timestamp,
) -> [u8; 32] {
    blake3::hash(b"SRC851-COMMITMENT:v1:" || details_hash || parties_hash || filing_date)
}
```

---

### SRC-852: Legal Process Event

Records legal process events without exposing case details.

#### Data Structures

```rust
/// Process Event
struct ProcessEvent {
    event_id: [u8; 32],
    case_id: [u8; 32],
    event_type: ProcessEventType,
    event_commitment: [u8; 32],        // Hash of event details
    issuer_address: Address,
    issuer_class: LegalIssuerClass,
    event_time_start: Option<Timestamp>,
    event_time_end: Option<Timestamp>,
    attachments: Vec<AttachmentRef>,
    policy_id: [u8; 32],
    revocation_ref: Option<[u8; 32]>,
    status: ProcessEventStatus,
    created_at: Timestamp,
    recorded_at_height: BlockHeight,
    supersedes: Option<EventId>,
}

/// Process Event Types
enum ProcessEventType {
    Filed = 0,           // Complaint/petition filed
    Served = 1,          // Service of process completed
    Hearing = 2,         // Hearing occurred
    OrderIssued = 3,     // Order/judgment issued
    MotionFiled = 4,     // Motion filed
    ResponseFiled = 5,   // Response/answer filed
    DiscoveryEvent = 6,  // Discovery milestone
    TrialEvent = 7,      // Trial event
    AppealFiled = 8,     // Notice of appeal
    Settlement = 9,      // Settlement reached
    Continuance = 10,    // Case continued
    Dismissal = 11,      // Case dismissed
    Default = 12,        // Default entered
    Other = 255,
}

/// Event Status
enum ProcessEventStatus {
    Recorded = 0,
    Superseded = 1,
    Revoked = 2,
}
```

#### Operations

| Code | Operation | Description |
|------|-----------|-------------|
| 10 | `RecordEvent` | Record a new process event |
| 11 | `UpdateEvent` | Update event status |
| 12 | `SupersedeEvent` | Supersede with corrected event |
| 13 | `RevokeEvent` | Revoke an event |

---

### SRC-853: Court Order/Judgment

Manages court orders with status tracking and enforcement links.

#### Data Structures

```rust
/// Court Order
struct CourtOrder {
    order_id: [u8; 32],
    case_id: [u8; 32],
    order_type: OrderType,
    order_commitment: [u8; 32],        // Hash of order details
    issuer_address: Address,
    issuer_class: LegalIssuerClass,
    status: OrderStatus,
    effective_from: Timestamp,
    expiry: Option<Timestamp>,
    policy_id: [u8; 32],
    revocation_ref: Option<[u8; 32]>,
    created_at: Timestamp,
    updated_at: Timestamp,
    issued_at_height: BlockHeight,
    supersedes_order_id: Option<OrderId>,
    attachments: Vec<AttachmentRef>,
}

/// Order Types
enum OrderType {
    Tro = 0,                    // Temporary Restraining Order
    PreliminaryInjunction = 1,
    PermanentInjunction = 2,
    FinalJudgment = 3,
    ConsentOrder = 4,
    ProtectiveOrder = 5,
    SupportOrder = 6,
    CustodyOrder = 7,
    AssetFreeze = 8,
    Garnishment = 9,
    Subpoena = 10,
    SummonsOrder = 11,
    Warrant = 12,
    Other = 255,
}

/// Order Status
enum OrderStatus {
    Active = 0,
    Stayed = 1,
    Modified = 2,
    Vacated = 3,
    Expired = 4,
    Superseded = 5,
    Appealed = 6,
    Enforced = 7,
}
```

#### Order Effectiveness Check

```rust
impl CourtOrder {
    pub fn is_in_effect(&self, current_time: Timestamp) -> bool {
        if self.status != OrderStatus::Active {
            return false;
        }
        if current_time < self.effective_from {
            return false;
        }
        if let Some(expiry) = self.expiry {
            if current_time > expiry {
                return false;
            }
        }
        true
    }
}
```

#### Operations

| Code | Operation | Description |
|------|-----------|-------------|
| 20 | `IssueOrder` | Issue a new court order |
| 21 | `UpdateOrderStatus` | Update order status |
| 22 | `StayOrder` | Stay an order |
| 23 | `VacateOrder` | Vacate an order |
| 24 | `SupersedeOrder` | Replace with new order |
| 25 | `ModifyOrder` | Modify an existing order |

---

### SRC-854: Government Benefit Determination

Manages government benefit eligibility without exposing personal data.

#### Data Structures

```rust
/// Benefit Determination
struct BenefitDetermination {
    benefit_id: [u8; 32],
    benefit_type: BenefitType,
    jurisdiction_code: String,
    status: BenefitStatus,
    determination_commitment: [u8; 32], // Hash of determination details
    subject_nullifier: [u8; 32],        // Privacy-preserving subject reference
    issuer_address: Address,
    issuer_class: LegalIssuerClass,
    valid_from: Timestamp,
    expiry: Option<Timestamp>,
    policy_id: [u8; 32],
    revocation_ref: Option<[u8; 32]>,
    created_at: Timestamp,
    updated_at: Timestamp,
    recorded_at_height: BlockHeight,
    supersedes: Option<BenefitId>,
}

/// Benefit Types
enum BenefitType {
    Medicare = 0,
    Medicaid = 1,
    SocialSecurity = 2,
    SocialSecurityDisability = 3,
    SupplementalSecurityIncome = 4,
    Snap = 5,                          // Food stamps
    Tanf = 6,                          // Temporary assistance
    Unemployment = 7,
    WorkersComp = 8,
    VeteransBenefits = 9,
    HousingAssistance = 10,
    ChildCareBenefit = 11,
    EarnedIncomeTaxCredit = 12,
    StudentAid = 13,
    Other = 255,
}

/// Benefit Status
enum BenefitStatus {
    Pending = 0,
    Approved = 1,
    Denied = 2,
    Suspended = 3,
    Terminated = 4,
    UnderReview = 5,
    Appealed = 6,
}
```

#### Benefit Validity Check

```rust
impl BenefitDetermination {
    pub fn is_valid(&self, current_time: Timestamp) -> bool {
        if self.status != BenefitStatus::Approved {
            return false;
        }
        if current_time < self.valid_from {
            return false;
        }
        if let Some(expiry) = self.expiry {
            if current_time > expiry {
                return false;
            }
        }
        true
    }
}
```

#### Operations

| Code | Operation | Description |
|------|-----------|-------------|
| 30 | `DetermineBenefit` | Create a new benefit determination |
| 31 | `UpdateBenefitStatus` | Update benefit status |
| 32 | `TerminateBenefit` | Terminate a benefit |
| 33 | `SuspendBenefit` | Suspend a benefit |
| 34 | `ReinstateBenefit` | Reinstate a suspended benefit |

---

### SRC-855: 85X Proof Profiles

ZK proof interfaces for legal status verification.

#### Data Structures

```rust
/// Legal Proof Envelope
struct LegalProofEnvelope {
    proof_id: [u8; 32],
    profile: LegalProofProfile,
    profile_id: String,                // e.g., "legal.case_active.v1"
    policy_ids: Vec<[u8; 32]>,
    public_inputs: Vec<u8>,
    proof_data: Vec<u8>,
    proof_type: LegalProofType,
    subject_nullifier: [u8; 32],
    generated_at: Timestamp,
    expires_at: Timestamp,
}

/// Legal Proof Profiles
enum LegalProofProfile {
    CaseActive = 0,          // Prove case is active
    CaseClosed = 1,          // Prove case is closed
    OrderInEffect = 2,       // Prove order is currently in effect
    BenefitApproved = 3,     // Prove benefit is approved
    NoActiveWarrants = 4,    // Prove no active warrants
    ProcessServed = 5,       // Prove service of process
    JudgmentStatus = 6,      // Prove judgment status
}

/// Proof Types
enum LegalProofType {
    Mock = 0,
    Groth16 = 1,
    Plonk = 2,
    ThresholdSignature = 3,
    MerkleInclusion = 4,
}
```

#### Operations

| Code | Operation | Description |
|------|-----------|-------------|
| 40 | `SubmitProof` | Submit a proof envelope |
| 41 | `VerifyProof` | Request proof verification |

---

## Transaction Format

```rust
/// SRC-85X Transaction Data
struct LegalTxData {
    operation: LegalOperation,
    data: Vec<u8>,  // Bincode-serialized operation data
}
```

### Transaction Type

- **TxType**: `Legal = 11`
- **TxPayload**: `Legal(LegalTxData)`

---

## Storage Schema

### Column Families

| Column Family | Description |
|--------------|-------------|
| `legal_cases` | Case anchor records |
| `legal_events` | Process event records |
| `legal_orders` | Court order records |
| `legal_benefits` | Benefit determination records |
| `legal_proofs` | Proof envelope records |
| `legal_case_event_index` | Case → Events index |
| `legal_case_order_index` | Case → Orders index |
| `legal_jurisdiction_index` | Jurisdiction → Entities index |
| `legal_system_events` | System events |

---

## Events

```rust
enum LegalEvent {
    // SRC-851
    CaseAnchored { case_id, jurisdiction, issuer, timestamp },
    CaseStatusUpdated { case_id, old_status, new_status, timestamp },
    CaseSealed { case_id, timestamp },
    CaseConsolidated { case_id, related_case_id, timestamp },

    // SRC-852
    ProcessEventRecorded { case_id, event_id, event_type, timestamp },
    ProcessEventSuperseded { old_event_id, new_event_id, timestamp },

    // SRC-853
    OrderIssued { case_id, order_id, order_type, issuer, timestamp },
    OrderStatusUpdated { order_id, old_status, new_status, timestamp },
    OrderStayed { order_id, timestamp },
    OrderVacated { order_id, timestamp },

    // SRC-854
    BenefitDetermined { benefit_id, benefit_type, subject_nullifier, status, timestamp },
    BenefitStatusUpdated { benefit_id, old_status, new_status, timestamp },

    // SRC-855
    LegalProofSubmitted { proof_id, profile, timestamp },
    LegalProofVerified { proof_id, valid, timestamp },
}
```

---

## Security Considerations

1. **Issuer Authorization**: Only registered SRC-802 issuers can create records.
2. **Jurisdiction Verification**: Issuers must be authorized for the claimed jurisdiction.
3. **Access Control**: Sealed cases have restricted access.
4. **Revocation Checking**: All queries check SRC-805 revocation status.
5. **Privacy Protection**: No PII stored on-chain; only commitments and nullifiers.

---

## Example Usage

### Anchoring a Case (Law Firm - Phase 1)

```rust
let case = CaseAnchor {
    case_id: CaseAnchor::generate_id(&issuer, &commitment, "US-NY-SDNY", &nonce),
    case_commitment: CaseAnchor::generate_commitment(&details_hash, &parties_hash, filing_date),
    jurisdiction_code: "US-NY-SDNY".to_string(),
    case_type: Some(CaseType::Civil),
    public_reference: Some("1:24-cv-12345".to_string()),
    policy_id: policy_id,
    issuer_class: LegalIssuerClass::LawFirm,  // Phase 1 issuer
    issuer_address: law_firm_address,
    status: CaseStatus::Filed,
    created_at: now,
    updated_at: now,
    anchored_at_height: current_height,
    related_cases: vec![],
};

let tx_data = LegalTxData {
    operation: LegalOperation::AnchorCase,
    data: bincode::serialize(&case).unwrap(),
};
```

### Issuing a Court Order (Court System - Phase 2)

```rust
let order = CourtOrder {
    order_id: CourtOrder::generate_id(&issuer, &commitment, case_id, &nonce),
    case_id,
    order_type: OrderType::Tro,
    order_commitment: CourtOrder::generate_commitment(&order_details, effective_from),
    issuer_address: court_address,
    issuer_class: LegalIssuerClass::CourtSystem,  // Phase 2 issuer
    status: OrderStatus::Active,
    effective_from: now,
    expiry: Some(now + 14_DAYS),  // TROs typically expire
    policy_id: policy_id,
    revocation_ref: None,
    created_at: now,
    updated_at: now,
    issued_at_height: current_height,
    supersedes_order_id: None,
    attachments: vec![],
};

let tx_data = LegalTxData {
    operation: LegalOperation::IssueOrder,
    data: bincode::serialize(&order).unwrap(),
};
```

### Creating a Benefit Determination (Government Agency - Phase 2)

```rust
let benefit = BenefitDetermination {
    benefit_id: BenefitDetermination::generate_id(&issuer, &commitment, &subject_nullifier, &nonce),
    benefit_type: BenefitType::Medicare,
    jurisdiction_code: "US".to_string(),
    status: BenefitStatus::Approved,
    determination_commitment: BenefitDetermination::generate_commitment(&determination_hash, valid_from),
    subject_nullifier: derive_nullifier(&subject_id, &salt),
    issuer_address: ssa_address,
    issuer_class: LegalIssuerClass::GovernmentAgency,  // Phase 2 issuer
    valid_from: now,
    expiry: Some(now + ONE_YEAR),
    policy_id: policy_id,
    revocation_ref: None,
    created_at: now,
    updated_at: now,
    recorded_at_height: current_height,
    supersedes: None,
};

let tx_data = LegalTxData {
    operation: LegalOperation::DetermineBenefit,
    data: bincode::serialize(&benefit).unwrap(),
};
```

### Verifying Benefit Status with ZK Proof

```rust
// Off-chain: Generate proof that benefit is approved
let proof = LegalProofEnvelope {
    proof_id: generate_proof_id(),
    profile: LegalProofProfile::BenefitApproved,
    profile_id: "legal.benefit_approved.v1".to_string(),
    policy_ids: vec![policy_id],
    public_inputs: serialize_public_inputs(&benefit_type, &jurisdiction),
    proof_data: zk_prove_benefit_approved(&benefit, &private_inputs),
    proof_type: LegalProofType::Groth16,
    subject_nullifier: my_nullifier,
    generated_at: now,
    expires_at: now + 24_HOURS,
};

// On-chain: Submit proof
let tx_data = LegalTxData {
    operation: LegalOperation::SubmitProof,
    data: bincode::serialize(&proof).unwrap(),
};
```

---

## Jurisdiction Codes

SRC-85X uses hierarchical jurisdiction codes:

| Format | Example | Description |
|--------|---------|-------------|
| `{country}` | `US`, `UK` | Country-level |
| `{country}-{state}` | `US-NY`, `US-CA` | State/province level |
| `{country}-{state}-{court}` | `US-NY-SDNY` | Court-specific |
| `{country}-{region}` | `UK-EW` | Region (England & Wales) |

---

## Integration with SRC-80X Infrastructure

SRC-85X integrates with:

- **SRC-801**: Subject identifiers (via nullifiers)
- **SRC-802**: Issuer registry (issuer class verification)
- **SRC-803**: Policy framework (authorization)
- **SRC-805**: Revocation (all entities have revocation_ref)
- **SRC-806**: Proof profiles (ZK verification)

---

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.0.0 | 2024-01 | Initial release |
