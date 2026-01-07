# SRC-86X: Property, Real Estate & Insurance Standards

## Overview

The SRC-86X family provides privacy-preserving standards for property records, real estate transactions, and insurance operations on SUM Chain. All standards follow the privacy-first principle with NO plaintext PII on-chain.

## Standards

### SRC-861: Asset Anchor (Property/Asset Identity)

Defines the core asset identity anchor for real estate and personal property.

**Key Features:**
- BLAKE3 commitment of asset details with domain separator
- Support for multiple asset types (residential, commercial, land, vehicles)
- Jurisdiction-coded for cross-regional compliance
- Priority-ordered encumbrance tracking

**Asset Types:**
- `SingleFamilyResidence` - Single-family homes
- `MultiFamily` - Multi-unit residential
- `Condominium` - Condo units
- `Commercial` - Commercial properties
- `Industrial` - Industrial properties
- `Land` - Raw land/lots
- `Vehicle` - Motor vehicles
- `Vessel` - Boats and watercraft
- `Aircraft` - Aviation assets
- `Equipment` - Heavy equipment
- `PersonalProperty` - Other personal property

**Operations:**
- `AnchorAsset` - Register new asset
- `UpdateAsset` - Update asset status
- `TransferAsset` - Initiate ownership transfer
- `MergeAssets` - Combine asset records
- `SubdivideAsset` - Split asset (lot subdivision)
- `DeregisterAsset` - Remove asset registration

### SRC-862: Title/Ownership State Event

Records ownership state changes and title events.

**Event Types:**
- `OwnershipTransfer` - Change of ownership
- `TitleCorrection` - Error correction
- `Subdivision` - Land division
- `Merger` - Combining parcels
- `Condemnation` - Government taking
- `CourtOrder` - Judicial action

**Operations:**
- `RecordTitleEvent` - Create new title event
- `UpdateTitleEvent` - Modify event status
- `SupersedeTitleEvent` - Replace with new event
- `VoidTitleEvent` - Invalidate event

### SRC-863: Encumbrance Standard (Lien/Mortgage/Leasehold)

Manages encumbrances including mortgages, liens, easements, and leases.

**Encumbrance Types:**
- `Mortgage` - Real property mortgages
- `DeedOfTrust` - Deed of trust arrangements
- `Lien` - General liens
- `TaxLien` - Tax obligations
- `MechanicsLien` - Construction liens
- `JudgmentLien` - Court judgments
- `Easement` - Property easements
- `Lease` - Leasehold interests
- `Restriction` - Use restrictions
- `Covenant` - Property covenants

**Priority Positions:**
```rust
pub struct PriorityPosition {
    pub position: u32,          // Priority order
    pub effective_date: Timestamp,
    pub subordinated: bool,     // If priority was subordinated
}
```

**Operations:**
- `RecordEncumbrance` - Create new encumbrance
- `UpdateEncumbrance` - Update status
- `SubordinateEncumbrance` - Lower priority
- `ReleaseEncumbrance` - Mark satisfied/released
- `ForecloseEncumbrance` - Record foreclosure

### SRC-864: Insurance Coverage Standard

Manages insurance coverage for property and casualty.

**Coverage Types:**
- `PropertyOwners` - Property insurance
- `Homeowners` - Homeowner policies
- `Renters` - Tenant coverage
- `Commercial` - Business property
- `Flood` - Flood insurance
- `Earthquake` - Earthquake coverage
- `Title` - Title insurance
- `Liability` - Liability coverage
- `Auto` - Vehicle insurance
- `Umbrella` - Excess liability

**Coverage Status Lifecycle:**
```
Pending → Active → [Renewed/Suspended/Cancelled/Expired/Lapsed]
                 ↓
              Suspended → Reinstated (Active)
```

**Operations:**
- `IssueCoverage` - Create new coverage
- `UpdateCoverage` - Modify status
- `RenewCoverage` - Extend coverage period
- `CancelCoverage` - Cancel policy
- `SuspendCoverage` - Suspend coverage
- `ReinstateCoverage` - Restore suspended coverage

### SRC-865: Insurance Claim Lifecycle

Manages the full lifecycle of insurance claims.

**Claim Types:**
- `Property` - Property damage
- `Liability` - Liability claims
- `Auto` - Vehicle claims
- `Flood` - Flood damage
- `WindStorm` - Wind/storm damage
- `Fire` - Fire damage
- `Theft` - Theft loss
- `Title` - Title claims
- `Other` - Other claims

**Claim Status Lifecycle:**
```
Filed → UnderReview → [Approved/PartiallyApproved/Denied]
                    ↓
                 Approved → Paid → Closed
                    ↓
                 Denied → [Appealed → UnderReview]
                       → [Withdrawn]
                    ↓
                 Closed → Reopened
```

**Operations:**
- `FileClaim` - Submit new claim
- `UpdateClaim` - Modify claim status
- `ApproveClaim` - Approve with amount commitment
- `DenyClaim` - Deny claim
- `PayClaim` - Record payment
- `CloseClaim` - Close claim
- `ReopenClaim` - Reopen closed/denied claim
- `WithdrawClaim` - Withdraw claim

### SRC-866: 86X Proof Profiles

Privacy-preserving proof system for property transactions.

**Proof Types:**
- `OwnershipProof` - Prove ownership without revealing owner identity
- `EncumbranceProof` - Prove no liens or specific encumbrance status
- `CoverageProof` - Prove active coverage without policy details
- `ClaimHistoryProof` - Prove claim history
- `JurisdictionProof` - Prove property jurisdiction

**Issuer Classes (Phase 1 & 2):**

Phase 1 (Lowkey):
- `IndividualOwner` - Property owners
- `AgentBroker` - Real estate agents

Phase 2 (Official):
- `TitleCompany` - Title companies
- `Insurer` - Insurance companies
- `GovernmentRegistry` - Official registries
- `Lender` - Mortgage lenders
- `Appraiser` - Property appraisers
- `Surveyor` - Land surveyors

## Privacy Architecture

### Commitment Generation

All sensitive data uses BLAKE3 commitments with domain separators:

```rust
// Asset commitment
let asset_commitment = blake3::keyed_hash(
    b"SUM:SRC861:ASSET",
    &[parcel_id, address_hash, description_hash].concat()
);

// Owner commitment (using PartyRef)
let owner_ref = PartyRef::Commitment(blake3::keyed_hash(
    b"SUM:SRC861:OWNER",
    &[owner_identity, salt].concat()
));
```

### Nullifier System

Prevents double-spend and linkability attacks:

```rust
let nullifier = blake3::keyed_hash(
    b"SUM:SRC86X:NULLIFIER",
    &[entity_id, secret_key, chain_id].concat()
);
```

## Transaction Types

Property transactions use `TxType::Property (12)`:

```rust
pub enum TxPayload {
    // ... other variants
    Property(PropertyTxData),
}

pub struct PropertyTxData {
    pub operation: PropertyOperation,
    pub data: Vec<u8>,  // Serialized operation data
}
```

## Storage Schema

Column families for SRC-86X:
- `property_assets` - Asset anchors
- `property_title_events` - Title events
- `property_encumbrances` - Encumbrance records
- `property_coverage` - Insurance coverage
- `property_claims` - Insurance claims
- `property_proofs` - Proof envelopes
- `property_asset_title_index` - Asset → Title events index
- `property_asset_encumbrance_index` - Asset → Encumbrances index
- `property_asset_coverage_index` - Asset → Coverage index
- `property_coverage_claim_index` - Coverage → Claims index
- `property_jurisdiction_index` - Jurisdiction-based lookup
- `property_system_events` - System event log

## Compliance Integration

SRC-86X integrates with:
- **SRC-803**: Policy templates for property transactions
- **SRC-805**: Revocation for voided/cancelled records
- **SRC-80X DIT**: Document issuance for deed registration

## Security Considerations

1. **No PII On-Chain**: All personal information stored as commitments
2. **Jurisdiction Isolation**: Records segregated by jurisdiction code
3. **Priority Enforcement**: Encumbrance priorities enforced on-chain
4. **Audit Trail**: Complete event history for compliance
5. **Fraud Prevention**: Nullifiers prevent double-registration
