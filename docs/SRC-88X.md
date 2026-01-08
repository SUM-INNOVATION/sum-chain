# SRC-88X: Employment & HR Standards

## Overview

The SRC-88X family provides privacy-preserving standards for employment verification, payroll attestations, and income proofs on SUM Chain. All standards follow the privacy-first principle with NO plaintext PII on-chain.

## Standards

### SRC-881: Employer & Payroll Issuer Profile

Defines the issuer registry for employment domain entities.

**Issuer Classes (Phase 1 & 2):**

Phase 2 (Official/Lower Risk):
- `GovernmentLabor` - Government labor department
- `PayrollProcessor` - Licensed payroll processor
- `PensionAuthority` - Pension/retirement authority
- `TaxAuthority` - Tax/revenue authority

Phase 1 (Higher Risk):
- `Employer` - Direct employer attestations
- `HrPlatform` - HR/workforce platforms
- `StaffingAgency` - Staffing/temp agencies
- `GigPlatform` - Gig economy platforms
- `BackgroundCheck` - Background verification services

**Operations:**
- `RegisterIssuer` - Register new issuer profile
- `UpdateIssuer` - Update issuer status
- `SuspendIssuer` - Suspend issuer
- `RevokeIssuer` - Revoke issuer
- `ReactivateIssuer` - Reactivate suspended issuer

### SRC-882: Employment Relationship Credential

Records employment relationships with privacy-preserving commitments.

**Employment Types:**
- `FullTime` - Full-time employment
- `PartTime` - Part-time employment
- `Contract` - Contract/1099 work
- `Seasonal` - Seasonal employment
- `Internship` - Intern position
- `Apprenticeship` - Apprenticeship program
- `GigWork` - Gig/freelance work

**Employment Status:**
- `Active` - Currently employed
- `OnLeave` - On leave (parental, medical, etc.)
- `Suspended` - Employment suspended
- `Ended` - Employment terminated

**Key Features:**
- BLAKE3 commitment of employment details with domain separator
- Employee and employer references as commitments (no PII)
- Role commitment for job title/position verification
- Tenure commitment for length of employment proofs

**Operations:**
- `CreateEmployment` - Issue new employment credential
- `UpdateEmployment` - Update employment status
- `SuspendEmployment` - Suspend employment credential
- `EndEmployment` - Mark employment as ended
- `RevokeEmployment` - Revoke with revocation reference

### SRC-883: Income / Payroll Attestation

Range-first income verification using brackets instead of exact amounts.

**Income Brackets:**
```
Bracket0  - Below $15,000
Bracket1  - $15,000 - $30,000
Bracket2  - $30,000 - $50,000
Bracket3  - $50,000 - $75,000
Bracket4  - $75,000 - $100,000
Bracket5  - $100,000 - $150,000
Bracket6  - $150,000 - $200,000
Bracket7  - $200,000 - $300,000
Bracket8  - $300,000 - $500,000
Bracket9  - Above $500,000
Custom    - Custom threshold (use threshold_commitment)
```

**Income Periods:**
- `Monthly` - Monthly income
- `Quarterly` - Quarterly income
- `Annual` - Annual income
- `YTD` - Year-to-date income

**Key Features:**
- Range-based verification instead of exact amounts
- Period commitment for date range verification
- Optional employment_id link for credential correlation
- Custom threshold support via threshold_commitment

**Operations:**
- `CreateIncomeAttestation` - Create new income attestation
- `UpdateIncomeAttestation` - Update attestation (revoke/re-issue)
- `RevokeIncomeAttestation` - Revoke attestation

### SRC-885: 88X Proof Profiles

Privacy-preserving proof system for employment verification.

**Proof Types:**
- `CurrentlyEmployed` - Prove active employment status
- `EmploymentHistory` - Prove employment in date range
- `IncomeThreshold` - Prove income meets minimum bracket
- `TenureAtLeast` - Prove minimum employment tenure
- `Combined` - Multiple conditions combined

**Proof Envelope:**
- Subject nullifier (prevents linkability)
- ZK-ready proof data structure
- Public inputs commitment
- Credential references

## Privacy Architecture

### Commitment Generation

All sensitive data uses BLAKE3 commitments with domain separators:

```rust
// Employee/employer commitment
let employee_ref = blake3::keyed_hash(
    b"SRC882-EMPLOYEE-v1",
    &[identity_data, salt].concat()
);

// Tenure commitment
let tenure_commitment = blake3::keyed_hash(
    b"SRC882-TENURE-v1",
    &[start_date, salt].concat()
);

// Role commitment
let role_commitment = blake3::keyed_hash(
    b"SRC882-ROLE-v1",
    &[job_title, department, salt].concat()
);

// Income period commitment
let period_commitment = blake3::keyed_hash(
    b"SRC883-PERIOD-v1",
    &[period_start, period_end, salt].concat()
);
```

### Nullifier System

Prevents double-use and linkability attacks:

```rust
let nullifier = blake3::keyed_hash(
    b"SRC88X-NULLIFIER-v1",
    &[subject_id, secret_key, chain_id].concat()
);
```

## Transaction Types

Employment transactions use `TxType::Employment (14)`:

```rust
pub enum TxPayload {
    // ... other variants
    Employment(EmploymentTxData),
}

pub struct EmploymentTxData {
    pub operation: EmploymentOperation,
    pub data: Vec<u8>,  // Serialized operation data
}
```

## Storage Schema

Column families for SRC-88X:
- `employment_issuers` - Issuer profiles
- `employment_credentials` - Employment credentials
- `employment_income_attestations` - Income attestations
- `employment_proofs` - Proof envelopes
- `employment_employee_index` - Employee → Credentials index
- `employment_employer_index` - Employer → Credentials index
- `employment_subject_income_index` - Subject → Attestations index
- `employment_system_events` - System event log

## Compliance Integration

SRC-88X integrates with:
- **SRC-803**: Policy templates for employment verification
- **SRC-805**: Revocation for terminated credentials
- **SRC-806**: ZK proof envelopes

## Security Considerations

1. **No PII On-Chain**: All personal information stored as commitments
2. **Range-First Income**: Only brackets revealed, not exact amounts
3. **Employer Privacy**: Employer identity also committed
4. **Audit Trail**: Complete event history for compliance
5. **Fraud Prevention**: Nullifiers prevent double-registration

## Example Use Cases

### Employment Verification for Rental Application
1. Employer issues SRC-882 credential to employee
2. Employee generates proof of active employment
3. Landlord verifies proof without seeing employer details

### Income Verification for Loan
1. Payroll processor issues SRC-883 attestation
2. Employee proves income >= Bracket5 ($100k-$150k)
3. Lender verifies without knowing exact salary

### Background Check
1. Background check service verifies employment history
2. Issues combined proof of tenure and employment type
3. HR platform consumes proof for hiring decision
