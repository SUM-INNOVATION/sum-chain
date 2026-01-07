# SRC-87X: Healthcare & Regulated Membership Standards

## Overview

The SRC-87X family provides privacy-preserving standards for healthcare provider registration, membership management, consent handling, and prescription tracking. Critical privacy requirement: **NO plaintext PHI (Protected Health Information) on-chain**.

## Standards

### SRC-871: Provider/Plan Registry Profile

Defines the registry for healthcare providers and insurance plans.

**Provider Types:**
- `Hospital` - Acute care facilities
- `Clinic` - Outpatient clinics
- `Pharmacy` - Licensed pharmacies
- `Laboratory` - Diagnostic labs
- `ImagingCenter` - Radiology facilities
- `Physician` - Individual physicians
- `Dentist` - Dental providers
- `Specialist` - Medical specialists
- `MentalHealth` - Behavioral health
- `HomeHealth` - Home care providers
- `Hospice` - Hospice care
- `Ambulance` - Emergency transport
- `InsurancePlan` - Health plans/payers
- `PBM` - Pharmacy benefit managers
- `TPAdministrator` - Third-party administrators

**Provider Status Lifecycle:**
```
Pending → Active → [Suspended/Inactive/Revoked]
                 ↓
              Suspended → Reactivated (Active)
```

**Network Affiliations:**
Providers can be associated with multiple insurance networks:
```rust
pub struct ProviderProfile {
    // ...
    pub network_affiliations: Vec<[u8; 32]>,  // Plan IDs
}
```

**Operations:**
- `RegisterProvider` - Register new provider
- `UpdateProvider` - Update provider status
- `SuspendProvider` - Suspend registration
- `RevokeProvider` - Revoke permanently
- `ReactivateProvider` - Reactivate suspended provider
- `AddNetworkAffiliation` - Join insurance network
- `RemoveNetworkAffiliation` - Leave network

### SRC-872: Coverage & Membership Status

Manages health plan membership and coverage status.

**Membership Types:**
- `Individual` - Individual coverage
- `Family` - Family plans
- `EmployerGroup` - Employer-sponsored
- `Medicare` - Medicare coverage
- `Medicaid` - Medicaid coverage
- `CHIP` - Children's Health Insurance
- `Exchange` - Marketplace plans
- `ShortTerm` - Short-term coverage
- `Supplemental` - Supplemental policies
- `StudentHealth` - Student plans

**Coverage Tiers:**
- `Bronze` - 60% actuarial value
- `Silver` - 70% actuarial value
- `Gold` - 80% actuarial value
- `Platinum` - 90% actuarial value
- `Catastrophic` - Catastrophic only
- `Custom` - Custom tier

**Network Status:**
- `InNetwork` - Fully in-network
- `OutOfNetwork` - Out-of-network
- `Hybrid` - Partial network access
- `PPO` - PPO network access
- `HMO` - HMO network restrictions
- `EPO` - EPO network type

**Membership Status Lifecycle:**
```
Pending → Active → [Suspended/Terminated/Expired]
                 ↓
              Suspended → Reinstated (Active)
```

**Dependent Management:**
```rust
pub struct MembershipRecord {
    // ...
    pub dependents: Vec<[u8; 32]>,  // Dependent commitments
}
```

**Operations:**
- `IssueMembership` - Create membership
- `UpdateMembership` - Update status
- `RenewMembership` - Renew with new expiry
- `SuspendMembership` - Suspend coverage
- `TerminateMembership` - Terminate
- `ReinstateMembership` - Reinstate suspended
- `AddDependent` - Add dependent
- `RemoveDependent` - Remove dependent

### SRC-874: Consent & Disclosure Envelope

Manages patient consent and data disclosure authorizations.

**Consent Types:**
- `TreatmentConsent` - Consent to treatment
- `InformationDisclosure` - PHI disclosure authorization
- `ResearchParticipation` - Research study consent
- `MarketingOptIn` - Marketing communications
- `DirectoryListing` - Facility directory
- `AdvanceDirective` - End-of-life directives
- `MinorConsent` - Consent for minor
- `ProxyConsent` - Proxy authorization
- `EmergencyWaiver` - Emergency treatment waiver

**Disclosure Scopes:**
- `Full` - Complete record access
- `TreatmentOnly` - Treatment data only
- `Summary` - Summary information
- `Emergency` - Emergency access
- `DateRange` - Specific date range
- `SpecificProvider` - Specific provider only
- `Exclusions` - Access with exclusions

**Consent Status Lifecycle:**
```
Pending → Active → [Revoked/Expired/Superseded]
```

**Operations:**
- `GrantConsent` - Create new consent
- `UpdateConsent` - Modify consent
- `RevokeConsent` - Revoke authorization
- `SupersedeConsent` - Replace with new consent

### SRC-875: 87X Proof Profiles

Privacy-preserving proof system for healthcare transactions.

**Proof Types:**
- `MembershipProof` - Prove active coverage
- `EligibilityProof` - Prove service eligibility
- `ConsentProof` - Prove consent exists
- `ProviderStatusProof` - Prove provider active
- `PrescriptionValidityProof` - Prove valid prescription
- `NetworkProof` - Prove network membership

**Issuer Classes (Phase 1 & 2):**

Phase 1 (Lowkey):
- `IndividualProvider` - Individual healthcare providers
- `SmallPractice` - Small group practices

Phase 2 (Official):
- `HospitalSystem` - Hospital systems
- `HealthPlan` - Insurance companies
- `GovernmentAgency` - CMS, state agencies
- `Accreditor` - JCAHO, NCQA
- `PharmacyChain` - Pharmacy chains
- `PBM` - Pharmacy benefit managers

## SRC-876: Prescription Standard

**CRITICAL**: Prescriptions for controlled substances are **NON-TRANSFERABLE**.

**Prescription Types:**
- `GeneralRx` - Non-controlled medications
- `ScheduleII` - Schedule II controlled (NO TRANSFER)
- `ScheduleIII` - Schedule III controlled (NO TRANSFER)
- `ScheduleIV` - Schedule IV controlled (NO TRANSFER)
- `ScheduleV` - Schedule V controlled (NO TRANSFER)
- `Compounded` - Compounded medications
- `Specialty` - Specialty drugs
- `Biologic` - Biological products

**Prescription Status Lifecycle:**
```
Active → [PartiallyFilled/Filled/Cancelled/Expired/OnHold]
               ↓
          PartiallyFilled → Filled
               ↓
            OnHold → Released (Active)
```

**Controlled Substance Enforcement:**
```rust
impl Prescription {
    pub fn can_transfer(&self) -> bool {
        !self.is_controlled  // FALSE for controlled substances
    }
}
```

**Fill Tracking:**
```rust
pub struct Prescription {
    pub refills_remaining: u8,      // Remaining refills
    pub fill_history: Vec<[u8; 32]>, // Fill commitments
}
```

**Operations:**
- `IssuePrescription` - Create prescription
- `UpdatePrescription` - Modify status
- `FillPrescription` - Record full fill (decrements refills)
- `PartialFillPrescription` - Record partial fill
- `CancelPrescription` - Cancel prescription
- `HoldPrescription` - Place on hold
- `ReleaseHold` - Release from hold

**Transfer Blocked for Controlled Substances:**
```rust
// In healthcare_executor.rs
if prescription.is_controlled && d.status == PrescriptionStatus::TransferRequested {
    return Ok(HealthcareExecutionResult::failure(
        "Controlled substance prescriptions cannot be transferred"
    ));
}
```

## Privacy Architecture

### Commitment Generation

All PHI uses BLAKE3 commitments with domain separators:

```rust
// Patient commitment
let patient_commitment = blake3::keyed_hash(
    b"SUM:SRC872:PATIENT",
    &[patient_id, dob_hash, ssn_hash, salt].concat()
);

// Prescription commitment
let rx_commitment = blake3::keyed_hash(
    b"SUM:SRC876:RX",
    &[ndc_code, quantity, directions_hash, salt].concat()
);
```

### Nullifier System

Prevents duplicate claims and fraud:

```rust
let patient_nullifier = blake3::keyed_hash(
    b"SUM:SRC87X:PATIENT_NULLIFIER",
    &[member_id, policy_id, secret_key].concat()
);
```

## Transaction Types

Healthcare transactions use `TxType::Healthcare (13)`:

```rust
pub enum TxPayload {
    // ... other variants
    Healthcare(HealthcareTxData),
}

pub struct HealthcareTxData {
    pub operation: HealthcareOperation,
    pub data: Vec<u8>,  // Serialized operation data
}
```

## Storage Schema

Column families for SRC-87X:
- `healthcare_providers` - Provider profiles
- `healthcare_memberships` - Membership records
- `healthcare_consents` - Consent envelopes
- `healthcare_prescriptions` - Prescription records
- `healthcare_proofs` - Proof envelopes
- `healthcare_provider_network_index` - Provider → Networks index
- `healthcare_member_index` - Member nullifier → Memberships
- `healthcare_subject_consent_index` - Subject → Consents
- `healthcare_patient_rx_index` - Patient → Prescriptions
- `healthcare_prescriber_rx_index` - Prescriber → Prescriptions
- `healthcare_system_events` - System event log

## Compliance Integration

SRC-87X integrates with:
- **SRC-803**: Policy templates for healthcare operations
- **SRC-805**: Revocation for terminated providers/memberships
- **SRC-80X DIT**: Document issuance for credentials
- **HIPAA**: Privacy Rule alignment (no PHI on-chain)
- **DEA**: Controlled substance tracking requirements

## Security Considerations

1. **No PHI On-Chain**: All health information stored as commitments
2. **Controlled Substance Protection**: Transfer explicitly blocked
3. **Consent Tracking**: Full audit trail for disclosure authorizations
4. **Provider Verification**: Network status verification before claims
5. **Fill Tracking**: Complete prescription fill history
6. **Expiration Enforcement**: Automatic expiration checking

## Regulatory Compliance Notes

### HIPAA Alignment
- All PHI stored off-chain, only commitments on-chain
- Consent tracking supports Authorization requirements
- Audit trail supports Security Rule requirements

### DEA Requirements
- Schedule II-V substances marked as non-transferable
- Complete fill history for controlled substances
- Prescriber verification via provider registry

### State Pharmacy Laws
- Supports state-specific refill limits
- Jurisdiction-coded for multi-state compliance
- Partial fill tracking for compliance
