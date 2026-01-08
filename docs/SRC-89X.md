# SRC-89X: Utility Address Proof, Banking & Finance Standards

## Overview

The SRC-89X family provides privacy-preserving standards for proof-of-address, bank account standing, KYC attestations, and financial credentials on SUM Chain. All standards follow the privacy-first principle with NO plaintext PII on-chain.

## Standards

### SRC-891: Financial Institution & Utility Issuer Profile

Defines the issuer registry for finance domain entities.

**Issuer Classes (Phase 1 & 2):**

Phase 2 (Official/Lower Risk):
- `GovernmentRevenue` - Government revenue/tax authority
- `CentralBank` - Central bank or treasury
- `RegulatedBank` - Regulated commercial bank
- `CreditUnion` - Licensed credit union
- `RegulatedUtility` - Regulated utility company
- `AddressVerificationService` - Official address verification service

Phase 1 (Higher Risk):
- `Fintech` - Fintech company
- `Neobank` - Neobank / digital-only bank
- `MoneyServiceBusiness` - Money service business
- `Utility` - Utility company (unregulated)
- `Telecom` - Telecom provider
- `PaymentProcessor` - Payment processor

**Issuer Capabilities:**
- `can_issue_address_proof()` - Address proof issuance
- `can_issue_bank_standing()` - Bank standing credentials
- `can_issue_kyc()` - KYC attestations

**Operations:**
- `RegisterIssuer` - Register new issuer profile
- `UpdateIssuer` - Update issuer status
- `SuspendIssuer` - Suspend issuer
- `RevokeIssuer` - Revoke issuer
- `ReactivateIssuer` - Reactivate suspended issuer

### SRC-892: Proof-of-Address Credential

Privacy-preserving address verification using commitments.

**Address Proof Types:**
- `UtilityBill` - Utility bill (electricity, gas, water)
- `BankStatement` - Bank statement
- `TaxDocument` - Tax document
- `GovernmentMail` - Government correspondence
- `TelecomBill` - Telecom bill
- `InsuranceDocument` - Insurance document
- `RentalAgreement` - Rental agreement
- `PropertyOwnership` - Property ownership record
- `VoterRegistration` - Voter registration

**Key Features:**
- Full address committed, only jurisdiction revealed
- Postal code commitment for regional matching
- Document date for recency verification
- SRC-805 compatible revocation

**Commitment Structure:**
```rust
// Address commitment
let address_commitment = blake3::keyed_hash(
    b"SRC892-PHYS-v1",
    &[country, region, city, postal, street, salt].concat()
);

// Postal commitment for regional matching
let postal_commitment = blake3::keyed_hash(
    b"SRC892-POSTAL-v1",
    &[postal_code, salt].concat()
);
```

**Operations:**
- `CreateAddressProof` - Issue new address proof
- `UpdateAddressProof` - Update (revoke/re-issue)
- `RevokeAddressProof` - Revoke address proof

### SRC-893: Bank Account Standing Credential

Bank account verification with range-first balance disclosure.

**Account Types:**
- `Checking` - Checking account
- `Savings` - Savings account
- `MoneyMarket` - Money market account
- `CertificateOfDeposit` - CD account
- `Brokerage` - Brokerage account
- `Retirement` - Retirement account
- `Business` - Business account
- `Joint` - Joint account

**Account Standing:**
- `Good` - Good standing
- `Fair` - Fair standing (minor issues)
- `Poor` - Poor standing (significant issues)
- `Restricted` - Account restricted
- `Closed` - Account closed

**Balance Brackets:**
```
Bracket0  - Below $1,000
Bracket1  - $1,000 - $5,000
Bracket2  - $5,000 - $10,000
Bracket3  - $10,000 - $25,000
Bracket4  - $25,000 - $50,000
Bracket5  - $50,000 - $100,000
Bracket6  - $100,000 - $250,000
Bracket7  - $250,000 - $500,000
Bracket8  - $500,000 - $1,000,000
Bracket9  - Above $1,000,000
Custom    - Custom threshold
```

**Key Features:**
- Account number committed, not revealed
- Range-based balance disclosure
- Tenure commitment for account age verification
- Bank reference as commitment

**Operations:**
- `CreateBankStanding` - Issue new bank standing credential
- `UpdateBankStanding` - Update standing status
- `RevokeBankStanding` - Revoke credential

### SRC-894: KYC / AML Attestation

KYC level and AML risk attestations.

**KYC Levels:**
- `None` - No KYC performed
- `Basic` - Basic KYC (name, email, phone)
- `Enhanced` - Enhanced KYC (ID verification)
- `Full` - Full KYC (ID + proof of address + source of funds)
- `Institutional` - Institutional KYC (for businesses)

**AML Risk Classifications:**
- `Low` - Low risk
- `Medium` - Medium risk
- `High` - High risk
- `Prohibited` - Prohibited (cannot transact)

**KYC Status:**
- `Pending` - KYC pending
- `Active` - KYC active
- `Expired` - KYC expired
- `Revoked` - KYC revoked
- `UnderReview` - Under review

**Key Features:**
- Identity verification commitment
- Methods commitment (verification methods used)
- Subject jurisdiction for compliance
- Tiered KYC level support

**Commitment Structure:**
```rust
// Identity commitment
let identity_commitment = blake3::keyed_hash(
    b"SRC894-ID-v1",
    &[id_type, id_hash, verification_date, salt].concat()
);

// Methods commitment
let methods_commitment = blake3::keyed_hash(
    b"SRC894-METHODS-v1",
    &[methods_list, salt].concat()
);
```

**Operations:**
- `CreateKycAttestation` - Create new KYC attestation
- `UpdateKycAttestation` - Update status
- `RevokeKycAttestation` - Revoke attestation

### SRC-895: 89X Proof Profiles

Privacy-preserving proof system for finance credentials.

**Proof Types:**
- `AddressInJurisdiction` - Prove address in specific jurisdiction
- `AccountInGoodStanding` - Prove bank account standing
- `BalanceAtLeast` - Prove balance meets minimum bracket
- `KycLevelAchieved` - Prove KYC level achieved
- `AmlRiskAcceptable` - Prove AML risk is acceptable
- `Combined` - Multiple conditions combined

**Proof Profile Structure:**
```rust
pub struct FinanceProofProfile {
    pub profile_id: [u8; 32],
    pub proof_type: FinanceProofType,
    pub required_jurisdiction: Option<String>,
    pub min_balance_bracket: Option<BalanceBracket>,
    pub min_kyc_level: Option<KycLevel>,
    pub max_aml_risk: Option<AmlRisk>,
    pub required_issuer_classes: Vec<FinanceIssuerClass>,
    pub max_credential_age_secs: u64,
    pub policy_id: PolicyId,
}
```

## Transaction Types

Finance transactions use `TxType::Finance (15)`:

```rust
pub enum TxPayload {
    // ... other variants
    Finance(FinanceTxData),
}

pub struct FinanceTxData {
    pub operation: FinanceOperation,
    pub data: Vec<u8>,  // Serialized operation data
}
```

## Storage Schema

Column families for SRC-89X:
- `finance_issuers` - Issuer profiles
- `finance_address_proofs` - Address proofs
- `finance_bank_standings` - Bank standing credentials
- `finance_kyc_attestations` - KYC attestations
- `finance_proofs` - Proof envelopes
- `finance_subject_address_index` - Subject → Address proofs index
- `finance_subject_bank_index` - Subject → Bank standings index
- `finance_subject_kyc_index` - Subject → KYC attestations index
- `finance_jurisdiction_index` - Jurisdiction → Issuers/proofs index
- `finance_system_events` - System event log

## Compliance Integration

SRC-89X integrates with:
- **SRC-803**: Policy templates for financial compliance
- **SRC-805**: Revocation for expired/cancelled credentials
- **SRC-806**: ZK proof envelopes
- **SRC-88X**: Employment verification (for income proofs)

## Security Considerations

1. **No PII On-Chain**: All personal information stored as commitments
2. **Range-First Balances**: Only brackets revealed, not exact amounts
3. **Jurisdiction Visibility**: Only jurisdiction code revealed, not full address
4. **AML Integration**: Built-in AML risk classification
5. **Issuer Capability Checks**: Enforced issuer class capabilities
6. **Audit Trail**: Complete event history for compliance

## Example Use Cases

### Address Verification for Account Opening
1. Utility company issues SRC-892 address proof
2. User generates proof of address in required jurisdiction
3. Bank verifies without seeing full address

### Balance Verification for Credit Application
1. Bank issues SRC-893 standing credential
2. User proves balance >= Bracket6 ($100k-$250k)
3. Lender verifies without knowing exact balance

### KYC Portability
1. Regulated bank performs full KYC, issues SRC-894 attestation
2. User proves KYC level to new fintech
3. Fintech accepts without re-doing full KYC

### Combined Proof for Mortgage
1. Generate proof combining:
   - Address in required state (SRC-892)
   - Bank account in good standing (SRC-893)
   - KYC level >= Enhanced (SRC-894)
   - Income >= Bracket5 (SRC-883)
2. Mortgage lender verifies single combined proof

## Risk Level Mapping

| Issuer Class | Default Risk | Can Issue Address | Can Issue Bank | Can Issue KYC |
|--------------|--------------|-------------------|----------------|---------------|
| GovernmentRevenue | Low | Yes | No | Yes |
| CentralBank | Low | No | Yes | Yes |
| RegulatedBank | Low | Yes | Yes | Yes |
| CreditUnion | Low | Yes | Yes | Yes |
| RegulatedUtility | Low | Yes | No | No |
| AddressVerificationService | Medium | Yes | No | No |
| Fintech | Medium | No | Yes | Yes |
| Neobank | Medium | No | Yes | Yes |
| MoneyServiceBusiness | High | No | No | Yes |
| Utility | Medium | Yes | No | No |
| Telecom | Medium | Yes | No | No |
| PaymentProcessor | Medium | No | No | Yes |
