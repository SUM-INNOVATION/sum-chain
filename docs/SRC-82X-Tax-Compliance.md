# SRC-82X: Tax & Compliance Domain Standards

## Abstract

SRC-82X defines a family of standards for tax and compliance-related claims, policies, and proofs on SUM Chain. Built on the SRC-80X trust architecture, these standards enable privacy-preserving tax compliance verification without exposing sensitive financial data.

## Design Principles

1. **No PII On-Chain** — Only commitments and hashes; actual tax data remains encrypted off-chain
2. **Policy-Driven Verification** — All verifications use SRC-803 policies with configurable trust sources
3. **ZK-Ready** — All structures support zero-knowledge proof generation via SRC-806
4. **Jurisdictional Flexibility** — Standards accommodate multi-jurisdiction compliance requirements
5. **Auditability** — Events enable compliance audits without exposing underlying data

## Standard Overview

| Standard | Name | Purpose |
|----------|------|---------|
| SRC-821 | Tax Claim Type Registry | Canonical registry of tax-related claim types |
| SRC-822 | Tax Issuer Classes | Domain-specific issuer class taxonomy |
| SRC-823 | Tax Policy Templates | Reusable verification policies |
| SRC-824 | Tax Proof Profiles | Standardized proof statements |
| SRC-825 | Tax Disclosure Envelope | Encrypted attachment references |

---

# SRC-821: Tax Claim Type Registry

## Purpose

Provides a canonical, on-chain registry of tax-related claim type identifiers under the `tax.*` namespace. Each entry defines the schema, risk level, and verification requirements.

## Claim Type Namespace

All tax claim types use the prefix `tax.` followed by category and specific type:

```
tax.<category>.<type>
```

## V1 Claim Types

### tax.filed.return
- **Description**: Attestation that a tax return was filed for a specific period
- **Schema Hash**: `blake3("SRC821-SCHEMA:tax.filed.return:v1")`
- **Risk Level**: Medium
- **Recommended Validity**: 365 days
- **Required Issuer Classes**: `tax_authority` OR (`auditor_cpa` + `tax_filing_provider`)

### tax.paid.status
- **Description**: Attestation of tax payment status
- **Schema Hash**: `blake3("SRC821-SCHEMA:tax.paid.status:v1")`
- **Risk Level**: Medium
- **Recommended Validity**: 90 days
- **Required Issuer Classes**: `tax_authority` OR `bank_broker`

### tax.balance.status
- **Description**: Attestation of outstanding tax balance (or zero balance)
- **Schema Hash**: `blake3("SRC821-SCHEMA:tax.balance.status:v1")`
- **Risk Level**: High
- **Recommended Validity**: 30 days
- **Required Issuer Classes**: `tax_authority`

### tax.income.bracket
- **Description**: Attestation of income falling within a specific bracket
- **Schema Hash**: `blake3("SRC821-SCHEMA:tax.income.bracket:v1")`
- **Risk Level**: High
- **Recommended Validity**: 365 days
- **Required Issuer Classes**: `tax_authority` OR `auditor_cpa`

### tax.withholding.bracket
- **Description**: Attestation of tax withholding bracket/status
- **Schema Hash**: `blake3("SRC821-SCHEMA:tax.withholding.bracket:v1")`
- **Risk Level**: Medium
- **Recommended Validity**: 365 days
- **Required Issuer Classes**: `employer_payroll` OR `tax_authority`

### tax.notice.open
- **Description**: Attestation of open tax notice/audit status
- **Schema Hash**: `blake3("SRC821-SCHEMA:tax.notice.open:v1")`
- **Risk Level**: High
- **Recommended Validity**: 30 days
- **Required Issuer Classes**: `tax_authority`

### tax.good_standing
- **Description**: Attestation of overall tax good standing
- **Schema Hash**: `blake3("SRC821-SCHEMA:tax.good_standing:v1")`
- **Risk Level**: Medium
- **Recommended Validity**: 90 days
- **Required Issuer Classes**: `tax_authority`

## Data Model

```rust
/// Tax claim type registry entry
pub struct TaxClaimTypeEntry {
    /// Claim type identifier (e.g., "tax.filed.return")
    pub claim_type: String,
    /// Schema hash (BLAKE3)
    pub schema_hash: [u8; 32],
    /// Risk level (0=Low, 1=Medium, 2=High, 3=Critical)
    pub risk_level: u8,
    /// Recommended validity window in seconds
    pub recommended_validity_secs: u64,
    /// Required issuer classes (OR logic between groups, AND within groups)
    pub required_issuer_classes: Vec<Vec<TaxIssuerClass>>,
    /// Entry status
    pub status: ClaimTypeStatus,
    /// Version number
    pub version: u32,
    /// Created at timestamp
    pub created_at: u64,
    /// Updated at timestamp
    pub updated_at: u64,
}

/// Claim type status
pub enum ClaimTypeStatus {
    Active = 0,
    Deprecated = 1,
    Retired = 2,
}
```

## Registry Operations

### Add Claim Type
- Requires governance policy approval (SRC-803 + SRC-806 proof)
- Emits `TaxClaimTypeAdded` event

### Update Claim Type
- Version increment required
- Requires governance policy approval
- Emits `TaxClaimTypeUpdated` event

### Deprecate Claim Type
- Marks as deprecated (still valid but discouraged)
- Requires governance policy approval
- Emits `TaxClaimTypeDeprecated` event

## Events

```rust
pub enum TaxRegistryEvent {
    TaxClaimTypeAdded {
        claim_type: String,
        schema_hash: [u8; 32],
        version: u32,
    },
    TaxClaimTypeUpdated {
        claim_type: String,
        schema_hash: [u8; 32],
        old_version: u32,
        new_version: u32,
    },
    TaxClaimTypeDeprecated {
        claim_type: String,
        version: u32,
    },
}
```

---

# SRC-822: Tax Issuer Classes & Roles

## Purpose

Defines the issuer class taxonomy for the tax domain, extending SRC-802 Issuer Registry with tax-specific classifications.

## Issuer Classes

### tax_authority
- **Description**: Government tax authority (IRS, HMRC, CRA, etc.)
- **Trust Level**: Highest
- **Authorized Claim Types**: All `tax.*` claims
- **Required Attributes**: jurisdiction, authority_id, verification_endpoint

### employer_payroll
- **Description**: Employer payroll systems for withholding attestations
- **Trust Level**: Medium
- **Authorized Claim Types**: `tax.withholding.bracket`, `tax.paid.status`
- **Required Attributes**: employer_id, jurisdiction

### bank_broker
- **Description**: Financial institutions with tax reporting obligations
- **Trust Level**: Medium-High
- **Authorized Claim Types**: `tax.paid.status`, `tax.withholding.bracket`
- **Required Attributes**: institution_id, regulatory_id, jurisdiction

### auditor_cpa
- **Description**: Licensed auditors and CPAs
- **Trust Level**: Medium-High
- **Authorized Claim Types**: `tax.filed.return`, `tax.income.bracket`
- **Required Attributes**: license_id, jurisdiction, license_expiry

### tax_filing_provider
- **Description**: Tax preparation software/services
- **Trust Level**: Low-Medium
- **Authorized Claim Types**: `tax.filed.return` (only with `auditor_cpa` co-signature)
- **Required Attributes**: provider_id, certification_status

## Data Model

```rust
/// Tax-specific issuer class
#[repr(u8)]
pub enum TaxIssuerClass {
    TaxAuthority = 0,
    EmployerPayroll = 1,
    BankBroker = 2,
    AuditorCpa = 3,
    TaxFilingProvider = 4,
}

/// Tax issuer registration
pub struct TaxIssuer {
    /// Base issuer address (links to SRC-802)
    pub address: Address,
    /// Tax-specific issuer class
    pub tax_class: TaxIssuerClass,
    /// Jurisdictions authorized for
    pub jurisdictions: Vec<String>,
    /// Class-specific attributes (serialized)
    pub attributes: Vec<u8>,
    /// Attribute schema hash
    pub attributes_schema_hash: [u8; 32],
    /// Registration timestamp
    pub registered_at: u64,
    /// Status
    pub status: IssuerStatus,
}
```

## Integration with SRC-802

Tax issuers MUST also be registered in the SRC-802 Issuer Registry with:
- `issuer_type`: Extended to include `TaxDomain = 7`
- Cross-reference to tax-specific registration

---

# SRC-823: Tax Policy Templates

## Purpose

Provides reusable policy templates for common tax verification scenarios, implemented as SRC-803 Policy Tokens.

## Policy Templates

### P-Filed: Tax Filing Verification

```rust
/// Policy for verifying tax filing status
pub struct PolicyFiled {
    /// Policy ID
    pub policy_id: PolicyId,
    /// Claim types accepted
    pub claim_types: Vec<String>, // ["tax.filed.return"]
    /// Issuer requirements (OR groups)
    pub issuer_requirements: IssuerRequirements,
    /// Jurisdiction scope (empty = any)
    pub jurisdictions: Vec<String>,
    /// Tax year scope
    pub tax_years: Vec<u32>,
    /// Validity requirements
    pub max_age_secs: u64,
    /// Revocation check required
    pub revocation_check: bool,
}

impl PolicyFiled {
    pub fn issuer_requirements() -> IssuerRequirements {
        IssuerRequirements {
            // Group 1: Tax authority alone
            // Group 2: Auditor CPA + Filing provider together
            groups: vec![
                vec![TaxIssuerClass::TaxAuthority],
                vec![TaxIssuerClass::AuditorCpa, TaxIssuerClass::TaxFilingProvider],
            ],
            quorum: QuorumRule::Any, // Any single group satisfies
        }
    }
}
```

### P-IncomeBracket: Income Bracket Verification

```rust
pub struct PolicyIncomeBracket {
    pub policy_id: PolicyId,
    pub claim_types: Vec<String>, // ["tax.income.bracket"]
    pub issuer_requirements: IssuerRequirements,
    pub bracket_ids: Vec<u32>, // Acceptable bracket IDs
    pub jurisdictions: Vec<String>,
    pub tax_year: u32,
    pub max_age_secs: u64,
    pub revocation_check: bool,
}

impl PolicyIncomeBracket {
    pub fn issuer_requirements() -> IssuerRequirements {
        IssuerRequirements {
            groups: vec![
                vec![TaxIssuerClass::TaxAuthority],
                vec![TaxIssuerClass::AuditorCpa],
            ],
            quorum: QuorumRule::Any,
        }
    }
}
```

### P-NoBalance: Zero Balance Verification

```rust
pub struct PolicyNoBalance {
    pub policy_id: PolicyId,
    pub claim_types: Vec<String>, // ["tax.balance.status"]
    pub issuer_requirements: IssuerRequirements,
    pub jurisdictions: Vec<String>,
    pub max_age_secs: u64, // Recommended: 30 days
    pub revocation_check: bool,
}

impl PolicyNoBalance {
    pub fn issuer_requirements() -> IssuerRequirements {
        IssuerRequirements {
            groups: vec![vec![TaxIssuerClass::TaxAuthority]],
            quorum: QuorumRule::Any,
        }
    }
}
```

### P-GoodStanding: Tax Good Standing

```rust
pub struct PolicyGoodStanding {
    pub policy_id: PolicyId,
    pub claim_types: Vec<String>, // ["tax.good_standing"]
    pub issuer_requirements: IssuerRequirements,
    pub jurisdictions: Vec<String>,
    pub max_age_secs: u64, // Recommended: 90 days
    pub revocation_check: bool,
}
```

## Policy Instantiation

```rust
impl TaxPolicyTemplates {
    /// Create a P-Filed policy instance
    pub fn create_p_filed(
        jurisdictions: Vec<String>,
        tax_years: Vec<u32>,
        max_age_days: u32,
    ) -> PolicyFiled {
        PolicyFiled {
            policy_id: Self::compute_policy_id("P-Filed", &jurisdictions, &tax_years),
            claim_types: vec!["tax.filed.return".to_string()],
            issuer_requirements: PolicyFiled::issuer_requirements(),
            jurisdictions,
            tax_years,
            max_age_secs: max_age_days as u64 * 86400,
            revocation_check: true,
        }
    }
}
```

## Events

```rust
pub enum TaxPolicyEvent {
    PolicyCreated {
        policy_id: PolicyId,
        template_type: String,
        creator: Address,
    },
    PolicyUpdated {
        policy_id: PolicyId,
        updater: Address,
    },
}
```

---

# SRC-824: Tax Proof Profile Standard

## Purpose

Standardizes proof "statements" that verifiers can request and wallets can generate, using SRC-806 Proof Envelopes.

## Proof Profiles

### prove_tax_filed

Proves that a tax return was filed for a specific year and jurisdiction.

```rust
pub struct ProofProfileTaxFiled {
    /// Profile identifier
    pub profile_id: &'static str, // "tax.prove_filed.v1"
    /// Domain separation string
    pub domain_sep: &'static str, // "SRC824-PROOF:tax.prove_filed:v1"
    /// Required policy IDs
    pub required_policies: Vec<PolicyId>,
    /// Public inputs
    pub public_inputs: TaxFiledPublicInputs,
}

pub struct TaxFiledPublicInputs {
    /// Tax year
    pub year: u32,
    /// Jurisdiction code
    pub jurisdiction: String,
    /// Filing status commitment (hides actual status)
    pub status_commitment: [u8; 32],
    /// Timestamp of proof generation
    pub proof_timestamp: u64,
}
```

### prove_income_in_bracket

Proves income falls within a specific bracket without revealing exact amount.

```rust
pub struct ProofProfileIncomeBracket {
    pub profile_id: &'static str, // "tax.prove_income_bracket.v1"
    pub domain_sep: &'static str, // "SRC824-PROOF:tax.prove_income_bracket:v1"
    pub required_policies: Vec<PolicyId>,
    pub public_inputs: IncomeBracketPublicInputs,
}

pub struct IncomeBracketPublicInputs {
    /// Bracket ID being proven
    pub bracket_id: u32,
    /// Tax year
    pub year: u32,
    /// Jurisdiction code
    pub jurisdiction: String,
    /// Proof timestamp
    pub proof_timestamp: u64,
}
```

### prove_no_outstanding_balance

Proves no outstanding tax balance for a period.

```rust
pub struct ProofProfileNoBalance {
    pub profile_id: &'static str, // "tax.prove_no_balance.v1"
    pub domain_sep: &'static str, // "SRC824-PROOF:tax.prove_no_balance:v1"
    pub required_policies: Vec<PolicyId>,
    pub public_inputs: NoBalancePublicInputs,
}

pub struct NoBalancePublicInputs {
    /// Period end date (YYYYMMDD)
    pub period_end: u32,
    /// Jurisdiction code
    pub jurisdiction: String,
    /// Zero balance commitment
    pub balance_commitment: [u8; 32],
    /// Proof timestamp
    pub proof_timestamp: u64,
}
```

### prove_tax_good_standing

Proves overall tax good standing status.

```rust
pub struct ProofProfileGoodStanding {
    pub profile_id: &'static str, // "tax.prove_good_standing.v1"
    pub domain_sep: &'static str, // "SRC824-PROOF:tax.prove_good_standing:v1"
    pub required_policies: Vec<PolicyId>,
    pub public_inputs: GoodStandingPublicInputs,
}

pub struct GoodStandingPublicInputs {
    /// Period being attested
    pub period_start: u32,
    pub period_end: u32,
    /// Jurisdiction code
    pub jurisdiction: String,
    /// Standing commitment
    pub standing_commitment: [u8; 32],
    /// Proof timestamp
    pub proof_timestamp: u64,
}
```

## Verifier Interface

```rust
/// Tax proof verifier interface
pub trait TaxProofVerifier {
    /// Verify a tax proof envelope
    fn verify_proof(
        &self,
        envelope: &ProofEnvelope,
        profile_id: &str,
    ) -> Result<VerificationResult, VerifierError>;

    /// Check policy compliance
    fn check_policy_compliance(
        &self,
        envelope: &ProofEnvelope,
        policy_id: &PolicyId,
    ) -> Result<bool, VerifierError>;

    /// Check revocation status
    fn check_revocation(
        &self,
        envelope: &ProofEnvelope,
    ) -> Result<RevocationCheckResult, VerifierError>;
}

/// Verification result
pub struct VerificationResult {
    pub valid: bool,
    pub profile_id: String,
    pub policy_compliant: bool,
    pub revocation_status: RevocationCheckResult,
    pub verified_at: u64,
}

/// Revocation check result
pub struct RevocationCheckResult {
    pub checked: bool,
    pub revoked: bool,
    pub revocation_reason: Option<RevocationReason>,
}
```

## Mock Verifier (for testing)

```rust
/// Mock verifier for testing when ZK verifier not available
pub struct MockTaxProofVerifier {
    /// Accepted proofs (for testing)
    accepted_proofs: HashSet<[u8; 32]>,
}

impl TaxProofVerifier for MockTaxProofVerifier {
    fn verify_proof(
        &self,
        envelope: &ProofEnvelope,
        profile_id: &str,
    ) -> Result<VerificationResult, VerifierError> {
        // Mock implementation checks:
        // 1. Proof format is valid
        // 2. Profile ID matches
        // 3. Proof is in accepted set (for testing)
        // 4. Policy compliance
        // 5. Revocation status
        Ok(VerificationResult {
            valid: self.accepted_proofs.contains(&envelope.proof_hash),
            profile_id: profile_id.to_string(),
            policy_compliant: true,
            revocation_status: RevocationCheckResult {
                checked: true,
                revoked: false,
                revocation_reason: None,
            },
            verified_at: current_timestamp(),
        })
    }
}
```

---

# SRC-825: Tax Disclosure Envelope

## Purpose

Standardizes encrypted supporting artifact references for tax claims and proofs without storing plaintext on-chain.

## Data Model

```rust
/// Tax disclosure envelope for encrypted attachments
pub struct TaxDisclosureEnvelope {
    /// Payload hash (BLAKE3 of encrypted content)
    pub payload_hash: [u8; 32],
    /// Payload size in bytes
    pub payload_size: u64,
    /// Optional storage hint (IPFS CID, URL, etc.)
    pub hint_uri: Option<String>,
    /// Encryption metadata
    pub encryption_meta: Option<EncryptionMeta>,
    /// Content type hint
    pub content_type: DisclosureContentType,
    /// Associated claim ID (if attached to a claim)
    pub claim_id: Option<ClaimId>,
    /// Associated proof ID (if attached to a proof)
    pub proof_id: Option<ProofId>,
}

/// Encryption metadata (no keys on-chain)
pub struct EncryptionMeta {
    /// Encryption algorithm identifier
    pub algorithm: EncryptionAlgorithm,
    /// Key derivation hint (for recipient)
    pub key_hint: [u8; 32],
    /// Initialization vector (if applicable)
    pub iv: Option<[u8; 12]>,
}

/// Supported encryption algorithms
#[repr(u8)]
pub enum EncryptionAlgorithm {
    /// ChaCha20-Poly1305
    ChaCha20Poly1305 = 0,
    /// AES-256-GCM
    Aes256Gcm = 1,
    /// X25519 + ChaCha20-Poly1305
    X25519ChaCha = 2,
}

/// Content type hints
#[repr(u8)]
pub enum DisclosureContentType {
    /// Tax return document
    TaxReturn = 0,
    /// W-2 or equivalent
    W2Form = 1,
    /// 1099 or equivalent
    Form1099 = 2,
    /// Tax transcript
    Transcript = 3,
    /// Payment receipt
    PaymentReceipt = 4,
    /// Assessment notice
    AssessmentNotice = 5,
    /// Other document
    Other = 255,
}
```

## Commitment Generation

```rust
/// Domain separator for disclosure envelope commitment
const DISCLOSURE_DOMAIN_SEP: &[u8] = b"SRC825-DISCLOSURE-v1";

/// Generate commitment for disclosure envelope
pub fn generate_disclosure_commitment(
    payload_hash: &[u8; 32],
    content_type: DisclosureContentType,
    associated_claim_or_proof: &[u8; 32],
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(DISCLOSURE_DOMAIN_SEP);
    hasher.update(payload_hash);
    hasher.update(&[content_type as u8]);
    hasher.update(associated_claim_or_proof);
    *hasher.finalize().as_bytes()
}
```

## Events

```rust
pub enum TaxDisclosureEvent {
    DisclosureAttached {
        disclosure_commitment: [u8; 32],
        claim_id: Option<ClaimId>,
        proof_id: Option<ProofId>,
        content_type: DisclosureContentType,
    },
}
```

---

# Domain Separation Strings

All SRC-82X operations use domain-separated hashing:

| Context | Domain Separation String |
|---------|-------------------------|
| Schema Hash | `SRC821-SCHEMA:<claim_type>:v<version>` |
| Policy ID | `SRC823-POLICY:<template>:<jurisdiction_hash>:<params_hash>` |
| Proof Profile | `SRC824-PROOF:<profile_id>:v<version>` |
| Disclosure | `SRC825-DISCLOSURE-v1` |
| Claim Commitment | `SRC82X-CLAIM-COMMITMENT-v1` |

---

# Canonical Encoding

SRC-82X uses deterministic JSON for all serializable structures:

1. **Sorted Keys**: Object keys sorted lexicographically
2. **UTF-8**: All strings UTF-8 encoded
3. **No Whitespace**: No spaces, newlines, or tabs
4. **Number Format**: Integers as decimal strings, no leading zeros
5. **Null Handling**: Null values omitted from objects

Example:
```json
{"bracket_id":3,"jurisdiction":"US","proof_timestamp":1704067200,"year":2023}
```

---

# Security Considerations

1. **No PII**: Never store personal tax information on-chain
2. **Commitment Binding**: All commitments use domain-separated BLAKE3
3. **Revocation Checks**: All verifications must include revocation checks
4. **Issuer Verification**: Verify issuer authorization before accepting claims
5. **Temporal Validity**: Enforce recommended validity windows
6. **Jurisdiction Scoping**: Validate jurisdiction matches claim scope

---

# Future Extensions

- Integration with on-chain voting (consuming SRC-806 proofs)
- Cross-jurisdiction verification bridges
- Automated tax compliance oracles
- Integration with DeFi protocols for tax reporting

---

# Copyright

This document is released under CC0 1.0 Universal.
