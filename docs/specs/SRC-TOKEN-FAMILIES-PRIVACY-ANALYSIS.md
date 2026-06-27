# SRC Token Families - Complete Privacy Analysis
## What Data is Public vs Private

**Date:** 2026-02-01
**Version:** 1.0
**Purpose:** Comprehensive catalog of ALL SRC token standards with privacy implications

---

## ⚠️ CRITICAL UNDERSTANDING

**ALL on-chain data is PUBLIC and readable by ANYONE without authentication.**

This includes:
- Token metadata
- Credential commitments (hashes)
- Issuer information
- Subject addresses
- Timestamps and status flags

**Privacy depends on:**
1. Using commitments (hashes) instead of raw data on-chain
2. Storing sensitive data off-chain (IPFS, encrypted)
3. Careful schema design to avoid PII in public fields

---

## Token Family Index

| Range | Family Name | Purpose | Privacy Model |
|-------|-------------|---------|---------------|
| **SRC-20** | Fungible Tokens | Native token standard (like ERC-20) | Public balances |
| **SRC-201** | On-Chain Messaging | Encrypted messaging | Encrypted payloads |
| **SRC-721** | NFTs | Non-fungible tokens | Public ownership |
| **SRC-80X** | Core Trust Infrastructure | Identity, issuers, policies | Commitment-based |
| **SRC-81X** | Academic & Professional | Degrees, transcripts, licenses | Commitment-based |
| **SRC-82X** | Tax & Compliance | Tax forms, compliance docs | Commitment-based |
| **SRC-83X** | Business & Equity | Cap tables, equity, governance | Commitment-based |
| **SRC-84X** | Agreements & IP | Contracts, NDAs, IP | Commitment-based |
| **SRC-85X** | Legal & Benefits | Court records, benefits | Commitment-based |
| **SRC-86X** | Property & Real Estate | Property titles, insurance | Commitment-based |
| **SRC-87X** | Healthcare | Medical credentials, insurance | Commitment-based |
| **SRC-88X** | Employment & HR | Employment, payroll, income | Commitment-based |
| **SRC-89X** | Finance & Banking | Bank accounts, credit, utilities | Commitment-based |

---

## SRC-20: Fungible Token Standard

**Purpose:** Native blockchain token standard for fungible assets (similar to ERC-20)

### On-Chain Public Data
```rust
pub struct Token {
    pub token_id: [u8; 32],
    pub name: String,              // PUBLIC: "Koppa" visible to all
    pub symbol: String,            // PUBLIC: "Ϙ" visible to all
    pub decimals: u8,              // PUBLIC
    pub total_supply: u128,        // PUBLIC
    pub owner: Address,            // PUBLIC: token creator
    pub mintable: bool,            // PUBLIC
    pub burnable: bool,            // PUBLIC
}

// Balance storage - PUBLIC
balances: HashMap<(TokenId, Address), u128>

// Allowances - PUBLIC
allowances: HashMap<(TokenId, Address, Address), u128>
```

### Privacy Implications
- ✅ **All balances are PUBLIC** - anyone can query any address's token balance
- ✅ **All transfers are PUBLIC** - transaction history is fully visible
- ✅ **Total supply is PUBLIC**
- ❌ **No privacy features** - use mixing services or privacy tokens if needed

### What to NEVER put in token name/symbol
- Real names of individuals
- Personally identifiable information
- Confidential business information

---

## SRC-201: On-Chain Encrypted Messaging

**Purpose:** End-to-end encrypted messaging with on-chain delivery guarantees

### On-Chain Public Data
```rust
pub struct Message {
    pub message_id: [u8; 32],           // PUBLIC
    pub sender: Address,                // PUBLIC
    pub recipient: Address,             // PUBLIC
    pub timestamp: Timestamp,           // PUBLIC
    pub encrypted_payload: Vec<u8>,    // PUBLIC but encrypted
    pub nonce: [u8; 24],               // PUBLIC (needed for decryption)
    pub flags: MessageFlags,            // PUBLIC (spam, sponsored, etc.)
}
```

### Privacy Implications
- ✅ **Sender/recipient addresses are PUBLIC** - metadata visible to all
- ✅ **Message timestamps are PUBLIC**
- ✅ **Payload is ENCRYPTED** - only recipient can decrypt with their private key
- ✅ **Content is PRIVATE** - uses X25519-XChaCha20-Poly1305 encryption
- ❌ **Communication graph is PUBLIC** - who messages whom is visible

### Privacy Model
- **Encrypted content**: Only recipient (with private key) can read message
- **Public metadata**: Sender, recipient, timestamp visible to everyone
- **No forward secrecy**: Messages remain encrypted forever (unless key compromised)

---

## SRC-721: Non-Fungible Tokens (NFTs)

**Purpose:** Unique, non-fungible digital assets

### On-Chain Public Data
```rust
pub struct NFT {
    pub token_id: [u8; 32],
    pub collection_id: [u8; 32],
    pub owner: Address,              // PUBLIC
    pub metadata_uri: String,        // PUBLIC: IPFS CID or URL
    pub created_at: Timestamp,       // PUBLIC
}
```

### Privacy Implications
- ✅ **Ownership is PUBLIC** - anyone can see who owns which NFT
- ✅ **Transfer history is PUBLIC** - full provenance visible
- ✅ **Metadata URI is PUBLIC** - link to artwork/data visible
- ❌ **No privacy by default** - consider private collections if needed

---

## SRC-80X: Core Trust Infrastructure

**Family Members:**
- **SRC-800**: Identity Root (legacy, deprecated)
- **SRC-801**: Subject Standard (DID-like identity anchors)
- **SRC-802**: Issuer Registry (who can attest)
- **SRC-803**: Policy Token (verification rules)
- **SRC-804**: Claim Token (verifiable statements)
- **SRC-805**: Revocation Standard (invalidation)
- **SRC-806**: Proof Envelope (ZK proofs)
- **SRC-807**: Eligibility Attestation (citizenship, residency, age)

### SRC-801: Subject Standard

**Purpose:** Cryptographic identity anchor (like a DID) without PII

#### On-Chain Public Data
```rust
pub struct Subject {
    pub subject_id: [u8; 32],           // PUBLIC
    pub controller: Address,            // PUBLIC
    pub recovery_controllers: Vec<Address>,  // PUBLIC
    pub keys: Vec<SubjectKey>,          // PUBLIC (public keys only)
    pub status: SubjectStatus,          // PUBLIC (Active/Deactivated)
    pub created_at: BlockHeight,        // PUBLIC
}
```

#### Privacy Implications
- ✅ **Subject ID is pseudonymous** - hash, not real identity
- ✅ **Public keys are PUBLIC** (as they must be for verification)
- ✅ **Controller addresses are PUBLIC**
- ❌ **NO PII on-chain** - no names, SSN, emails, etc.

#### What NEVER goes on-chain
- Real name
- Email address
- Phone number
- Government ID number
- Physical address
- Date of birth

---

### SRC-802: Issuer Registry

**Purpose:** Register entities authorized to issue credentials

#### On-Chain Public Data
```rust
pub struct IssuerProfile {
    pub issuer_address: Address,        // PUBLIC
    pub issuer_type: IssuerType,       // PUBLIC (Government, Educational, etc.)
    pub display_name: String,           // PUBLIC: "MIT", "California DMV"
    pub jurisdiction: String,           // PUBLIC: "US", "US-CA"
    pub issuer_commitment: [u8; 32],   // PUBLIC: hash of issuer details
    pub status: IssuerStatus,           // PUBLIC (Active/Suspended)
    pub registered_at: Timestamp,       // PUBLIC
}
```

#### Privacy Implications
- ✅ **Institution names are PUBLIC** - "Stanford University" visible to all
- ✅ **Jurisdiction is PUBLIC** - which country/state
- ✅ **Issuer commitment is a hash** - actual details can be private
- ✅ **Anyone can verify issuer registration**

#### What CAN be public (institutional data)
- University name
- Government agency name
- Company name (if issuing employment credentials)
- Country/jurisdiction

#### What should be in commitment (hashed, optional to reveal)
- Physical address
- Contact information
- Accreditation details
- Internal identifiers

---

### SRC-804: Claim Token

**Purpose:** Base structure for all verifiable claims/credentials

#### On-Chain Public Data
```rust
pub struct Claim {
    pub claim_id: [u8; 32],             // PUBLIC
    pub subject_id: [u8; 32],          // PUBLIC: who claim is about
    pub issuer: Address,                // PUBLIC: who issued it
    pub claim_type: ClaimType,          // PUBLIC: Education, Employment, etc.
    pub schema_hash: [u8; 32],         // PUBLIC: defines structure
    pub content_commitment: [u8; 32],  // PUBLIC: hash of claim data
    pub issued_at: Timestamp,           // PUBLIC
    pub expires_at: Timestamp,          // PUBLIC
    pub revocation_status: RevocationStatus,  // PUBLIC
    pub payload_hash: Option<[u8; 32]>,  // PUBLIC: hash of off-chain data
    pub payload_hint: Option<String>,    // PUBLIC: IPFS CID or URL
}
```

#### Privacy Implications
- ✅ **Claim exists PUBLIC** - anyone can see you have *a* credential
- ✅ **Claim type is PUBLIC** - "Education" claim visible
- ✅ **Content commitment is hash** - actual data not revealed
- ✅ **Payload hint PUBLIC but payload can be encrypted**
- ❌ **Sensitive data MUST go in encrypted payload**, not on-chain

---

## SRC-81X: Academic & Professional Credentials

**Family Members:**
- **SRC-810**: Academic Transcript (courses, grades)
- **SRC-811**: Diploma / Degree
- **SRC-812**: Enrollment Verification
- **SRC-813**: Professional License / Certification

### SRC-810: Academic Transcript

**Purpose:** Academic records with courses and grades

#### On-Chain Public Data
```rust
pub struct AcademicCredential {  // Used for 810, 811, 812
    pub credential_id: [u8; 32],        // PUBLIC
    pub subject_address: Address,       // PUBLIC
    pub subcode: u16,                   // PUBLIC: 810
    pub subject_commitment: [u8; 32],  // PUBLIC: hash, not real identity
    pub issuer: Address,                // PUBLIC: university address
    pub institution_id: String,         // PUBLIC: "MIT", "UCLA"
    pub jurisdiction: String,           // PUBLIC: "US"
    pub schema_hash: [u8; 32],         // PUBLIC
    pub content_commitment: [u8; 32],  // PUBLIC: hash of transcript
    pub metadata: CredentialMetadata,   // PUBLIC (see below)
    pub issued_at: Timestamp,           // PUBLIC
    pub valid_from: Timestamp,          // PUBLIC
    pub expires_at: Timestamp,          // PUBLIC
    pub payload_hint: Option<String>,   // PUBLIC: IPFS CID
    pub revocation_status: RevocationStatus,  // PUBLIC
}

pub struct CredentialMetadata {
    pub title: String,                  // PUBLIC: "Bachelor of Science"
    pub credential_type: String,        // PUBLIC: "undergraduate_transcript"
    pub program: Option<String>,        // PUBLIC: "Computer Science"
    pub issue_date: String,             // PUBLIC: "2025-05-15"
    pub completion_date: Option<String>, // PUBLIC: "2025-05-15"
    pub attributes: Vec<CredentialAttribute>,  // PUBLIC
}
```

#### ⚠️ CRITICAL PRIVACY WARNING

**What is PUBLIC in metadata.attributes:**
```json
{
  "attributes": [
    {"name": "degree_level", "value": "undergraduate"},  // PUBLIC
    {"name": "pdf_cid", "value": "QmPDF..."}            // PUBLIC
  ]
}
```

**What MUST be kept OFF-CHAIN (encrypted on IPFS):**
- Student name
- Student ID number
- Detailed course list with grades
- GPA (if not commitment-based)
- Instructor names
- Course descriptions
- Personal notes or recommendations

#### Privacy-Safe On-Chain Example
```json
{
  "credential_id": "0x1234...",
  "subject_address": "EgHb6jcqGdngzrEAcoYo4KUKvbNDkvC3S",
  "institution_id": "Stanford_University",
  "metadata": {
    "title": "Undergraduate Degree",
    "credential_type": "transcript",
    "program": null,  // ← Don't reveal major if private
    "issue_date": "2025-05",
    "attributes": [
      {"name": "credential_level", "value": "undergraduate"},
      {"name": "pdf_cid", "value": "QmEncryptedPDF..."}
    ]
  },
  "content_commitment": "0xblake3hash...",
  "payload_hint": "QmEncryptedFullTranscript..."
}
```

#### Privacy-UNSAFE Example (DO NOT DO THIS)
```json
{
  "metadata": {
    "title": "Bachelor of Science in Computer Science",  // ❌ Reveals major
    "attributes": [
      {"name": "student_name", "value": "John Doe"},     // ❌❌❌ PII!
      {"name": "student_id", "value": "123456789"},      // ❌❌❌ PII!
      {"name": "gpa", "value": "3.85"},                  // ❌ May want private
      {"name": "honors", "value": "Cum Laude"}           // ❌ May want private
    ]
  }
}
```

---

### SRC-811: Diploma / Degree

**Purpose:** Official degree conferral

#### Same Structure as SRC-810

Privacy considerations identical to transcripts. Common mistake:

**WRONG:**
```json
{
  "title": "Doctor of Philosophy in Neuroscience - Jane Smith"  // ❌ Name in title
}
```

**RIGHT:**
```json
{
  "title": "Doctoral Degree",
  "content_commitment": "0xhash...",  // Commitment includes name, major, etc.
  "payload_hint": "QmEncrypted..."    // Full details encrypted on IPFS
}
```

---

### SRC-812: Enrollment Verification

**Purpose:** Verify current enrollment status

#### Privacy Implications
- ✅ **Enrollment status is PUBLIC** (Active/Graduated/Withdrawn)
- ✅ **Program may be PUBLIC** depending on design
- ❌ **Student name NEVER on-chain**

---

## SRC-82X: Tax & Compliance

**Family Members:**
- **SRC-821**: Tax Document Anchor (W-2, 1099, etc.)
- **SRC-822**: Compliance Certificate
- **SRC-823**: Audit Trail Anchor
- **SRC-824**: Regulatory Filing Anchor
- **SRC-825**: Tax Jurisdiction Profile

### Privacy Model: MAXIMUM PRIVACY

Tax documents contain **extremely sensitive** financial PII.

#### On-Chain Public Data
```rust
pub struct TaxDocument {
    pub document_id: [u8; 32],          // PUBLIC
    pub subject_commitment: [u8; 32],   // PUBLIC: hash only
    pub issuer: Address,                // PUBLIC: employer/payer
    pub document_type: TaxDocType,      // PUBLIC: W2, 1099, etc.
    pub tax_year: u16,                  // PUBLIC
    pub jurisdiction: String,           // PUBLIC: "US", "US-CA"
    pub content_commitment: [u8; 32],   // PUBLIC: hash
    pub payload_hash: [u8; 32],        // PUBLIC: hash of encrypted data
    pub issued_at: Timestamp,           // PUBLIC
}
```

#### What NEVER goes on-chain (must be encrypted off-chain)
- SSN / Tax ID
- Exact income amounts
- Bank account numbers
- Home address
- Employer EIN
- Detailed deductions
- Dependent information

#### On-Chain Example (Privacy-Safe)
```json
{
  "document_type": "W2",
  "tax_year": 2025,
  "jurisdiction": "US",
  "content_commitment": "0xblake3hash...",
  "payload_hint": "QmEncryptedW2Data..."  // All PII encrypted
}
```

---

## SRC-83X: Business, Governance & Equity

**Family Members:**
- **SRC-831**: Entity Registry (companies, DAOs)
- **SRC-832**: Equity Position (cap table entries)
- **SRC-833**: Governance Rights
- **SRC-834**: Board/Officer Records
- **SRC-835**: Shareholder Attestation
- **SRC-836**: Equity Event Log

### Privacy Model: MIXED (Public corp structure, private ownership)

#### On-Chain Public Data
```rust
pub struct EntityProfile {
    pub entity_id: [u8; 32],            // PUBLIC
    pub entity_type: EntityType,        // PUBLIC: LLC, Corp, DAO
    pub jurisdiction: String,           // PUBLIC: "US-DE"
    pub name_commitment: [u8; 32],     // PUBLIC: hash of name
    pub registration_date: Timestamp,   // PUBLIC
}

pub struct EquityPosition {
    pub position_id: [u8; 32],          // PUBLIC
    pub entity_id: [u8; 32],           // PUBLIC
    pub holder_commitment: [u8; 32],   // PUBLIC: hash of shareholder
    pub share_class_commitment: [u8; 32],  // PUBLIC: hash
    pub quantity_commitment: [u8; 32], // PUBLIC: hash (not exact shares!)
    pub issued_at: Timestamp,           // PUBLIC
}
```

#### Privacy Strategy
- **Public companies**: More data can be public (required by law)
- **Private companies**: Use commitments for shareholder names, share counts
- **Cap table privacy**: Individual holdings are hashed commitments

---

## SRC-84X: Agreements & IP

**Family Members:**
- **SRC-841**: Agreement Commitments (contracts, NDAs)
- **SRC-842**: IP Registration Anchor (patents, trademarks)
- **SRC-843**: License Agreement
- **SRC-844**: Copyright Claim
- **SRC-845**: Trade Secret Anchor
- **SRC-846**: Open Source License

### Privacy Model: Commitment-based

#### On-Chain Public Data
```rust
pub struct AgreementCommitment {
    pub agreement_id: [u8; 32],         // PUBLIC
    pub parties_commitment: [u8; 32],  // PUBLIC: hash of party list
    pub agreement_type: AgreementType,  // PUBLIC: NDA, License, etc.
    pub content_hash: [u8; 32],        // PUBLIC: hash of agreement text
    pub effective_date: Timestamp,      // PUBLIC
    pub expiration_date: Timestamp,     // PUBLIC
}
```

#### What stays private (off-chain)
- Party names (unless public companies)
- Contract terms
- Financial terms
- Trade secrets
- Confidential clauses

---

## SRC-85X: Legal & Benefits

**Family Members:**
- **SRC-851**: Case/Docket Anchors (court records)
- **SRC-852**: Legal Opinion Anchor
- **SRC-853**: Attorney Credential
- **SRC-854**: Benefits Eligibility
- **SRC-855**: Insurance Policy Anchor

### Privacy Model: HIGH PRIVACY (legal/medical sensitivity)

#### On-Chain Public Data
```rust
pub struct LegalRecord {
    pub record_id: [u8; 32],            // PUBLIC
    pub record_type: LegalRecordType,   // PUBLIC: Case, Opinion, etc.
    pub jurisdiction: String,           // PUBLIC
    pub parties_commitment: [u8; 32],  // PUBLIC: hash
    pub case_number_commitment: [u8; 32],  // PUBLIC: hash
    pub filed_date: Timestamp,          // PUBLIC
}
```

#### What NEVER goes on-chain
- Party names (unless public records)
- Case details
- Settlement terms
- Medical information (for insurance)
- Personal health data

---

## SRC-86X: Property, Real Estate & Insurance

**Family Members:**
- **SRC-861**: Asset Anchor (property identity)
- **SRC-862**: Title Claim
- **SRC-863**: Lien/Encumbrance Record
- **SRC-864**: Appraisal Anchor
- **SRC-865**: Insurance Policy
- **SRC-866**: Claims Record

### Privacy Model: MIXED (public property records, private ownership)

#### On-Chain Public Data
```rust
pub struct AssetAnchor {
    pub asset_id: [u8; 32],             // PUBLIC
    pub asset_type: AssetType,          // PUBLIC: Real Estate, Vehicle
    pub jurisdiction: String,           // PUBLIC
    pub property_commitment: [u8; 32], // PUBLIC: hash of address
    pub owner_commitment: [u8; 32],    // PUBLIC: hash of owner
    pub recording_date: Timestamp,      // PUBLIC
}
```

#### Privacy Considerations
- **Public property records**: Some jurisdictions require public deeds
- **Private ownership**: Can use commitments for owner privacy
- **Property address**: May need to be public for some use cases, hash for others

---

## SRC-87X: Healthcare & Regulated Membership

**Family Members:**
- **SRC-871**: Provider/Plan Registry Profile
- **SRC-872**: Healthcare Credential (medical license)
- **SRC-874**: Insurance Coverage Attestation
- **SRC-875**: Prescription Anchor
- **SRC-876**: Medical Record Anchor

### Privacy Model: MAXIMUM PRIVACY (HIPAA/medical privacy)

#### On-Chain Public Data
```rust
pub struct HealthcareCredential {
    pub credential_id: [u8; 32],        // PUBLIC
    pub subject_commitment: [u8; 32],  // PUBLIC: hash only
    pub provider_id: [u8; 32],         // PUBLIC: hospital/doctor
    pub credential_type: HealthcareType,  // PUBLIC: License, Coverage
    pub content_commitment: [u8; 32],  // PUBLIC: hash
    pub issued_at: Timestamp,           // PUBLIC
}
```

#### What NEVER goes on-chain (HIPAA-protected)
- Patient name
- Medical record number
- Diagnosis
- Treatment details
- Prescription details
- Health insurance member ID
- Any PHI (Protected Health Information)

#### Everything medical MUST be encrypted off-chain

---

## SRC-88X: Employment & HR

**Family Members:**
- **SRC-881**: Employer & Payroll Issuer Profile
- **SRC-882**: Employment Relationship Credential
- **SRC-883**: Income / Payroll Attestation
- **SRC-885**: 88X Proof Profiles

### SRC-882: Employment Credential

#### On-Chain Public Data
```rust
pub struct EmploymentCredential {
    pub employment_id: [u8; 32],        // PUBLIC
    pub employee_address: Address,      // PUBLIC
    pub employer_ref: [u8; 32],        // PUBLIC: hash of employer
    pub employee_ref: [u8; 32],        // PUBLIC: hash of employee details
    pub tenure_commitment: [u8; 32],   // PUBLIC: hash of start date
    pub role_commitment: [u8; 32],     // PUBLIC: hash of role/title
    pub employment_type: EmploymentType,  // PUBLIC: FullTime, PartTime
    pub valid_from: Timestamp,          // PUBLIC
    pub expiry: Timestamp,              // PUBLIC (0 = ongoing)
}
```

#### ⚠️ What is PUBLIC
- Employment exists (you work for this employer)
- Employment type (Full-Time, Part-Time)
- Start date range (via commitment verification)
- Employment status (Active, Terminated)

#### What MUST be OFF-CHAIN (encrypted)
- Employee name
- Employee email
- Job title
- Salary
- Benefits
- Performance reviews
- Manager name
- Internal employee ID

---

### SRC-883: Income / Payroll Attestation

#### On-Chain Public Data
```rust
pub struct IncomeAttestation {
    pub attestation_id: [u8; 32],       // PUBLIC
    pub subject_ref: [u8; 32],         // PUBLIC: hash
    pub issuer: Address,                // PUBLIC: employer/payroll
    pub income_bracket: IncomeBracket,  // PUBLIC: Range, not exact!
    pub period_commitment: [u8; 32],   // PUBLIC: hash of pay period
    pub attestation_type: IncomeType,   // PUBLIC: W2, 1099
    pub issued_at: Timestamp,           // PUBLIC
}

pub enum IncomeBracket {
    Under25K,
    Range25to50K,
    Range50to75K,
    Range75to100K,
    Range100to150K,
    Above150K,
}
```

#### Privacy Model: RANGE-FIRST
- ✅ **Income bracket is PUBLIC** (range, not exact amount)
- ✅ **Exact income is OFF-CHAIN** (encrypted)
- ✅ **ZK proofs can prove "income > $50K"** without revealing exact amount

#### What NEVER goes on-chain
- Exact salary/income
- SSN
- Bank account numbers
- Pay stubs
- Bonus details
- Stock compensation details

---

## SRC-89X: Finance & Banking

**Family Members:**
- **SRC-891**: Financial Institution & Utility Issuer Profile
- **SRC-892**: Account Existence Attestation
- **SRC-893**: Credit Assessment Anchor
- **SRC-894**: Utility Service Verification
- **SRC-895**: Financial Instrument Anchor

### Privacy Model: MAXIMUM PRIVACY (financial data)

#### On-Chain Public Data
```rust
pub struct AccountAttestation {
    pub attestation_id: [u8; 32],       // PUBLIC
    pub subject_commitment: [u8; 32],  // PUBLIC: hash
    pub institution: Address,           // PUBLIC: bank
    pub account_type_commitment: [u8; 32],  // PUBLIC: hash
    pub status_commitment: [u8; 32],   // PUBLIC: hash
    pub issued_at: Timestamp,           // PUBLIC
}
```

#### What NEVER goes on-chain
- Account numbers
- Routing numbers
- Account balances
- Transaction history
- SSN
- Credit scores (exact)
- Personal financial details

---

## Summary: Privacy Best Practices

### ✅ SAFE to put on-chain (PUBLIC)
1. **Commitments (hashes)** of sensitive data
2. **Institutional names** (universities, employers, banks)
3. **Credential types** (Degree, Employment, Account)
4. **Timestamps** (issuance, expiration)
5. **Revocation status**
6. **Pseudonymous addresses** (wallet addresses)
7. **IPFS CIDs** pointing to encrypted data
8. **Ranges/brackets** instead of exact values

### ❌ NEVER put on-chain (MUST ENCRYPT OFF-CHAIN)
1. **Real names** (unless institutional)
2. **SSN / Tax ID / Government IDs**
3. **Email addresses**
4. **Phone numbers**
5. **Physical addresses** (unless public property records)
6. **Account numbers** (bank, credit card, etc.)
7. **Exact income/salary**
8. **Medical information** (HIPAA)
9. **Grades** (detailed academic records)
10. **Any PII** that could identify an individual

### Privacy-Safe Architecture
```
┌─────────────────────────────────────────────┐
│           ON-CHAIN (PUBLIC)                 │
│                                             │
│  - Credential ID                           │
│  - Issuer address                          │
│  - Subject commitment (hash)               │
│  - Content commitment (hash)               │
│  - Timestamps                              │
│  - Revocation status                       │
│  - Payload CID ──────────┐                │
└────────────────────────────│───────────────┘
                             │
                             ▼
           ┌─────────────────────────────────┐
           │   IPFS (ENCRYPTED)              │
           │                                 │
           │  Encrypted with student's       │
           │  public key:                    │
           │                                 │
           │  - Student name                 │
           │  - Detailed grades              │
           │  - Course list                  │
           │  - GPA                          │
           │  - Honors                       │
           │  - All PII                      │
           └─────────────────────────────────┘
                  │
                  │ Only accessible with
                  │ student's private key
                  ▼
           [Student grants access
            to verifiers via
            off-chain mechanism]
```

---

## Verification Without Revealing Data

All SRC-8XX families support **Zero-Knowledge Proofs** via SRC-806:

```
Prover can prove:
  - "I have a degree from Stanford"
  - "My GPA > 3.5"
  - "I am employed full-time"
  - "My income > $75,000"
  - "I am over 21 years old"

WITHOUT revealing:
  - Exact GPA
  - Exact income
  - Exact birthdate
  - Specific courses
  - Employment details
```

---

## FOR SUMAIL GATEWAY TEAM

When implementing academic credentials:

1. **Store on-chain:**
   - Credential ID
   - Institution name ("SUM Hypothesis Institute Technology")
   - Credential type ("diploma")
   - Issue date
   - Content commitment (hash)
   - PDF CID in `metadata.attributes`

2. **Store on IPFS (encrypted):**
   - Student name
   - Student ID
   - Detailed transcript
   - Course grades
   - GPA
   - Honors
   - All PII

3. **NEVER store on-chain:**
   - Student names
   - Detailed grades
   - Personal information
   - Anything that identifies an individual

**Remember:** Anyone with an RPC connection can query ALL on-chain data. Design accordingly.

---

**END OF DOCUMENT**

*Version 1.0 - 2026-02-01*
*Complete privacy analysis of ALL SRC token families*
