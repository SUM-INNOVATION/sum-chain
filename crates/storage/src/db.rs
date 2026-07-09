//! RocksDB wrapper for SUM Chain.
//!
//! Provides a unified interface for persistent storage with
//! multiple column families for different data types.

use rocksdb::{ColumnFamily, ColumnFamilyDescriptor, Options, DB};
use std::path::{Path, PathBuf};
use tracing::{debug, error, info, warn};

use crate::{Result, StorageError};

/// Information about a database backup
#[derive(Debug, Clone)]
pub struct BackupInfo {
    /// Path to the backup directory
    pub path: PathBuf,
    /// Size of the backup in bytes
    pub size_bytes: u64,
    /// Unix timestamp when the backup was created
    pub timestamp: u64,
}

impl BackupInfo {
    /// Format the backup size in human-readable form
    pub fn size_human(&self) -> String {
        const KB: u64 = 1024;
        const MB: u64 = KB * 1024;
        const GB: u64 = MB * 1024;

        if self.size_bytes >= GB {
            format!("{:.2} GB", self.size_bytes as f64 / GB as f64)
        } else if self.size_bytes >= MB {
            format!("{:.2} MB", self.size_bytes as f64 / MB as f64)
        } else if self.size_bytes >= KB {
            format!("{:.2} KB", self.size_bytes as f64 / KB as f64)
        } else {
            format!("{} bytes", self.size_bytes)
        }
    }
}

/// Column family names
pub mod cf {
    /// Blocks indexed by hash
    pub const BLOCKS: &str = "blocks";
    /// Block hash indexed by height
    pub const BLOCK_HEIGHT: &str = "block_height";
    /// Account state (balances, nonces)
    pub const STATE: &str = "state";
    /// Transactions indexed by hash
    pub const TRANSACTIONS: &str = "transactions";
    /// Transaction receipts
    pub const RECEIPTS: &str = "receipts";
    /// Chain metadata (latest block, etc.)
    pub const META: &str = "meta";
    /// State diffs for reorgs
    pub const STATE_DIFFS: &str = "state_diffs";
    /// NFT collections
    pub const NFT_COLLECTIONS: &str = "nft_collections";
    /// NFT tokens (indexed by collection_id + token_id)
    pub const NFT_TOKENS: &str = "nft_tokens";
    /// NFT owner index (owner -> collection_id:token_id list)
    pub const NFT_OWNER_INDEX: &str = "nft_owner_index";
    /// NFT collection index (collection_id -> token_id list)
    pub const NFT_COLLECTION_INDEX: &str = "nft_collection_index";
    /// Issuer registry for certified documents
    pub const ISSUER_REGISTRY: &str = "issuer_registry";
    /// SRC-20 fungible tokens
    pub const TOKENS: &str = "tokens";
    /// SRC-20 token balances (token_id + owner -> balance)
    pub const TOKEN_BALANCES: &str = "token_balances";
    /// SRC-20 token allowances (token_id + owner + spender -> allowance)
    pub const TOKEN_ALLOWANCES: &str = "token_allowances";
    /// SRC-20 token holder index (owner -> token_id list)
    pub const TOKEN_HOLDER_INDEX: &str = "token_holder_index";
    /// Validator staking info (pubkey -> ValidatorInfo)
    pub const VALIDATORS: &str = "validators";
    /// Delegations (delegator + validator_pubkey -> DelegationInfo)
    pub const DELEGATIONS: &str = "delegations";
    /// Unbonding delegations (delegator + completion_height + validator_pubkey -> UnbondingDelegation)
    pub const UNBONDING_DELEGATIONS: &str = "unbonding_delegations";
    /// Delegation index by validator (validator_pubkey -> list of delegator addresses)
    pub const DELEGATION_VALIDATOR_INDEX: &str = "delegation_validator_index";
    /// Slashing records (validator_pubkey + slashed_at -> SlashingRecord)
    pub const SLASHING_RECORDS: &str = "slashing_records";
    /// Validator signing info for liveness tracking (validator_pubkey -> ValidatorSigningInfo)
    pub const VALIDATOR_SIGNING_INFO: &str = "validator_signing_info";
    /// Missed blocks bitmap per validator (validator_pubkey -> bitmap)
    pub const MISSED_BLOCKS: &str = "missed_blocks";
    /// Validator sets by epoch (epoch -> ValidatorSet)
    pub const VALIDATOR_SETS: &str = "validator_sets";

    // Node Registry
    /// Node registry (address -> NodeRecord, role indexes)
    pub const NODE_REGISTRY: &str = "node_registry";
    /// Per-account X25519 encryption pubkey registry (address -> [u8; 32])
    /// SNIP V2 Ask 3 — populated by `NodeRegistryOperationV2::RegisterEncryptionKey`.
    pub const ACCOUNT_ENCRYPTION_KEYS: &str = "account_encryption_keys";
    /// Active-archive-node set snapshots, snapshot-on-change.
    /// Key: `[height_be_bytes_8]`. Value: `bincode(Vec<NodeRecord>)`.
    /// SNIP V2 Ask 15 (Option A, height-based) — see plan v3 §5.3.
    /// Genesis snapshot lives at key `0u64.to_be_bytes()`.
    pub const ACTIVE_ARCHIVE_NODES_HISTORY: &str = "active_archive_nodes_history";

    /// Pending archive-node stake unbonding records (issue #20), keyed by
    /// operator address -> `ArchiveUnbondingRecord`.
    pub const ARCHIVE_UNBONDING: &str = "archive_unbonding";

    // Storage Metadata
    /// Storage file metadata (merkle_root -> StorageMetadata, owner indexes)
    pub const STORAGE_METADATA: &str = "storage_metadata";
    /// V2 storage file metadata (`[b'F', b'2', merkle_root]` -> `StorageMetadataV2`).
    /// Coexists with V1 STORAGE_METADATA — V2 entries live under their own CF
    /// to avoid prefix collisions while keeping V1 reads cheap. SNIP V2 Phase 1.
    pub const STORAGE_METADATA_V2: &str = "storage_metadata_v2";
    /// V2 per-(file, archive) attestation bitmaps for `AcceptAssignmentV2`.
    /// Key: `[b'A', merkle_root_32, archive_address_20]` (53 bytes).
    /// Value: `Vec<u8>` of length `ceil(chunk_count / 8)`.
    /// Plan v3.2 §3.6 — dedicated CF for distinct access pattern (point lookups
    /// during attestation, prefix scan `[b'A', root, ...]` during coverage RPC),
    /// and to keep future post-activation GC isolated from file-row data.
    pub const ASSIGNMENT_ATTESTATIONS_V2: &str = "assignment_attestations_v2";

    /// Per-file archive-reassignment epochs (issue #62). Key: `merkle_root` (raw
    /// 32 bytes). Value: `bincode(Vec<u64>)` of reassignment heights (epoch ≥ 1);
    /// epoch 0 is the file's `StorageMetadataV2.assignment_height` and is not
    /// stored here. No entry ⇒ epoch-0-only (every pre-#62 file).
    pub const FILE_REASSIGNMENTS: &str = "file_reassignments";

    /// Per-(file, epoch, archive) reassignment attestation bitmaps (issue #62).
    /// Key: `[b'R', merkle_root_32, epoch_height_be_8, archive_20]` (61 bytes).
    /// Value: bitmap of length `ceil(chunk_count / 8)`. Kept physically separate
    /// from the epoch-0 `ASSIGNMENT_ATTESTATIONS_V2` CF so epoch-0 attestations
    /// are never conflated with replacement attestations.
    pub const ASSIGNMENT_ATTESTATIONS_V2_EPOCH: &str = "assignment_attestations_v2_epoch";

    /// OmniNode `InferenceAttestation` records (Stage 6 subprotocol).
    /// Key: 32-byte BLAKE3-domain-separated digest of
    /// `(session_id, verifier_address)`, see
    /// `sumchain_primitives::inference_attestation::inference_attestation_key`.
    /// Value: bincode-serialized `InferenceAttestationRecord` containing the
    /// signed digest, verifier signature, included-at block height, and tx
    /// hash. Used by both the executor (dedup on insert) and the future
    /// mempool admission hook (permanent duplicate check) to enforce one
    /// attestation per `(session_id, verifier)` pair across all history.
    pub const INFERENCE_ATTESTATIONS: &str = "inference_attestations";

    /// Session-id index over `INFERENCE_ATTESTATIONS` so RPC
    /// `sum_listInferenceAttestations(session_id)` can enumerate every
    /// verifier that attested to a given session without scanning the
    /// canonical CF. Key shape is `session_id_hash_16 || verifier_address_20`
    /// (36 bytes) — a 16-byte BLAKE3 prefix derived from
    /// `b"InferenceAttestationSessionIndexV1" || session_id` followed by
    /// the 20-byte chain Address. Prefix-iterating with the 16-byte
    /// session prefix returns every verifier for that session.
    /// Value: empty (`&[]`) — presence is the signal; full records live
    /// in the canonical CF and are fetched per-verifier via the
    /// primary key derived from `(session_id, verifier_address)`.
    pub const INFERENCE_ATTESTATIONS_BY_SESSION: &str = "inference_attestations_by_session";

    // ── OmniNode Inference Settlement (issue #61) ──
    /// Per-session settlement records. Key: 32-byte
    /// `BLAKE3("InferenceSettlementSessionV1" || session_id)`. Value:
    /// bincode `InferenceSession` (funder, reward terms, remaining escrow, status).
    pub const INFERENCE_SESSIONS: &str = "inference_sessions";
    /// Per-(session, verifier) paid reward claims. Key: `session_prefix_16 ||
    /// verifier_address_20` (36 bytes). Value: bincode `InferenceClaim`.
    pub const INFERENCE_CLAIMS: &str = "inference_claims";
    /// Per-(session, verifier) dispute records (record-only; no slashing). Key:
    /// `session_prefix_16 || verifier_address_20` (36 bytes). Value: bincode
    /// `InferenceDispute`.
    pub const INFERENCE_DISPUTES: &str = "inference_disputes";
    /// Per-verifier bond records (issue #78). Key: 32-byte
    /// `BLAKE3("InferenceVerifierV1" || verifier_address)`. Value: bincode
    /// `InferenceVerifierRecord` (bond amount, status, unbonding timers).
    /// Bond is accounting-in-record — native Koppa is debited on register/add and
    /// credited back on withdraw, mirroring the escrow pattern. Slashing credits
    /// `Address::ZERO`. Never touched by the attestation CFs.
    pub const INFERENCE_VERIFIERS: &str = "inference_verifiers";

    // ── SRC-817/818 Education-LMS suite (Phase 2) ──
    // Privacy: students appear ONLY as a scoped `student_commitment`
    // [u8;32] — never a raw Address — in any education key or value.
    // Every stored SNIP ref is a `ManagedSnipRef`. Primary records
    // hold counters/roots, not unbounded vectors. Numeric key
    // components are big-endian so bytewise CF order = numeric order.

    /// SRC-817 catalog entries. Key `catalog_id[32]`.
    pub const EDU_CATALOG_ENTRIES: &str = "edu_catalog_entries";
    /// Catalog prerequisite child rows. Key `catalog_id[32] || prereq_catalog_id[32]`.
    pub const EDU_CATALOG_PREREQUISITES: &str = "edu_catalog_prerequisites";
    /// Catalog accreditation child rows. Key `catalog_id[32] || idx_be[4]`.
    pub const EDU_CATALOG_ACCREDITATION: &str = "edu_catalog_accreditation";
    /// Catalog content refs (description / learning-outcomes / syllabus /
    /// assessment-policy). Key `catalog_id[32] || content_kind_u8[1]`.
    /// Value: `ManagedSnipRef` (bounded child rows — no inline vec).
    pub const EDU_CATALOG_CONTENT_ITEMS: &str = "edu_catalog_content_items";
    /// Index: institution -> catalog. Key `institution_id[32] || catalog_id[32]`.
    pub const EDU_CATALOG_BY_INSTITUTION: &str = "edu_catalog_by_institution";
    /// Dedupe/lookup index. Key is length-safe:
    /// `BLAKE3("SRC817-CATALOG-BY-CODE:v1:" || bincode((department,
    /// course_code)))[32] || catalog_id[32]` — no raw string concat.
    pub const EDU_CATALOG_BY_CODE: &str = "edu_catalog_by_code";
    /// Index: status -> catalog. Key `status_u8[1] || catalog_id[32]`.
    pub const EDU_CATALOG_BY_STATUS: &str = "edu_catalog_by_status";

    /// SRC-818 offerings (primary record, counters/roots only).
    /// Key `offering_id[32]`.
    pub const EDU_OFFERINGS: &str = "edu_offerings";
    /// Instructor/TA bindings. Key `offering_id[32] || instructor_addr[20]`.
    /// The address is an institutional/SRC-882 identity — NOT a student.
    pub const EDU_INSTRUCTOR_BINDINGS: &str = "edu_instructor_bindings";
    /// Content items. Key `offering_id[32] || content_id[32]`.
    pub const EDU_CONTENT_ITEMS: &str = "edu_content_items";
    /// Assessments. Key `offering_id[32] || assessment_id[32]`.
    pub const EDU_ASSESSMENTS: &str = "edu_assessments";
    /// Enrollment links. Key `offering_id[32] || student_commitment[32]`.
    pub const EDU_ENROLLMENT_LINKS: &str = "edu_enrollment_links";
    /// Submission receipts (receipt only — never the work).
    /// Key `offering_id[32] || assessment_id[32] || student_commitment[32] || attempt_be[2]`.
    pub const EDU_SUBMISSIONS: &str = "edu_submissions";
    /// Grade records (grade_commitment only — never the raw grade).
    /// Key `offering_id[32] || assessment_id[32] || student_commitment[32]`.
    pub const EDU_GRADES: &str = "edu_grades";
    /// Index: catalog -> offering. Key `catalog_id[32] || offering_id[32]`.
    pub const EDU_OFFERING_BY_CATALOG: &str = "edu_offering_by_catalog";
    /// Index: status -> offering. Key `status_u8[1] || offering_id[32]`.
    pub const EDU_OFFERING_BY_STATUS: &str = "edu_offering_by_status";
    /// Privacy-safe submission index, commitment-keyed (no raw address).
    /// Key `student_commitment[32] || offering_id[32] || assessment_id[32] || attempt_be[2]`.
    pub const EDU_SUBMISSION_BY_STUDENT_COMMITMENT: &str = "edu_submission_by_student_commitment";

    // PoR Challenges
    /// Active storage challenges (challenge_id -> StorageChallenge, node/expiry indexes)
    pub const ACTIVE_CHALLENGES: &str = "active_challenges";
    /// Issue #100 — compact challengeable V2-file index for the bounded PoR
    /// scheduler: `merkle_root(32) -> chunk_count(u32 BE, 4 bytes)`. Present iff
    /// the V2 file is `Active && fee_pool > 0`. Enables O(sample) seeded
    /// sampling without scanning all V2 metadata rows.
    pub const CHALLENGEABLE_FILES_V2: &str = "challengeable_files_v2";
    /// Monetary-policy / supply accounting (800B correction). Singleton records:
    /// `b"ledger"` → bincode `SupplyLedger`, `b"reserve"` → bincode
    /// `ProtocolReserve`. The reserve is non-transferable ledger supply (not an
    /// account); both are folded into the block state root once the correction
    /// is applied.
    pub const SUPPLY: &str = "supply";

    // SRC-80X/81X DocClass column families
    /// Identity roots (SRC-800)
    pub const DOCCLASS_IDENTITY_ROOTS: &str = "docclass_identity_roots";
    /// Eligibility attestations (SRC-802)
    pub const DOCCLASS_ELIGIBILITY: &str = "docclass_eligibility";
    /// Academic/Professional credentials (SRC-810-813)
    pub const DOCCLASS_CREDENTIALS: &str = "docclass_credentials";
    /// Revocation records (SRC-805)
    pub const DOCCLASS_REVOCATIONS: &str = "docclass_revocations";
    /// DocClass issuer registry
    pub const DOCCLASS_ISSUERS: &str = "docclass_issuers";
    /// Subject commitment index (subject_commitment -> credential_ids)
    pub const DOCCLASS_SUBJECT_INDEX: &str = "docclass_subject_index";
    /// Issuer credential index (issuer -> credential_ids)
    pub const DOCCLASS_ISSUER_INDEX: &str = "docclass_issuer_index";
    /// Credential events (for indexing)
    pub const DOCCLASS_EVENTS: &str = "docclass_events";

    // SRC-201 Messaging column families
    /// Messaging configuration
    pub const MESSAGING_CONFIG: &str = "messaging_config";
    /// Message sender nonces (sender -> nonce)
    pub const MESSAGING_SENDER_NONCES: &str = "messaging_sender_nonces";
    /// Daily message counts (sender + day -> count)
    pub const MESSAGING_DAILY_COUNTS: &str = "messaging_daily_counts";
    /// Anti-spam stakes (address -> balance)
    pub const MESSAGING_STAKES: &str = "messaging_stakes";
    /// Spam scores (address -> score)
    pub const MESSAGING_SPAM_SCORES: &str = "messaging_spam_scores";
    /// Inbox filters (recipient_hash -> mode)
    pub const MESSAGING_INBOX_FILTERS: &str = "messaging_inbox_filters";
    /// Contacts (recipient_hash + sender_hash -> bool)
    pub const MESSAGING_CONTACTS: &str = "messaging_contacts";
    /// Blocked senders (recipient_hash + sender -> bool)
    pub const MESSAGING_BLOCKED: &str = "messaging_blocked";
    /// Pending payments (message_id -> PendingPayment)
    pub const MESSAGING_PENDING_PAYMENTS: &str = "messaging_pending_payments";
    /// Message events for indexing (recipient_hash + block_height + idx -> MessageEvent)
    pub const MESSAGING_EVENTS: &str = "messaging_events";
    /// Sent-message index (sender(20) + block_height(8 BE) + tx_index(4 BE) -> MessageEvent)
    pub const MESSAGING_SENDER_EVENTS: &str = "messaging_sender_events";
    /// Pending-payment-by-recipient index (recipient_hash(32) + message_id(32) -> [])
    pub const MESSAGING_PAYMENTS_BY_RECIPIENT: &str = "messaging_payments_by_recipient";
    /// Registered public keys (address -> RegisteredPublicKey)
    pub const MESSAGING_PUBLIC_KEYS: &str = "messaging_public_keys";

    // Smart-contract persistent state (issue #25; dormant until activation).
    /// Contract WASM bytecode (contract_address -> code).
    pub const CONTRACT_CODE: &str = "contract_code";
    /// Contract storage (contract_address + b':' + key -> value).
    pub const CONTRACT_STORAGE: &str = "contract_storage";
    /// Contract metadata (contract_address -> bincode(ContractMetadata)).
    pub const CONTRACT_METADATA: &str = "contract_metadata";
    /// Per-block contract-state diffs for reorg revert (height -> ContractStateDiff).
    pub const CONTRACT_STATE_DIFFS: &str = "contract_state_diffs";

    // SRC-82X Tax & Compliance column families
    /// Tax claim type registry (claim_type -> TaxClaimTypeEntry)
    pub const TAX_CLAIM_TYPES: &str = "tax_claim_types";
    /// Tax issuers (issuer_id -> TaxIssuer)
    pub const TAX_ISSUERS: &str = "tax_issuers";
    /// Tax policies (policy_id -> TaxPolicy)
    pub const TAX_POLICIES: &str = "tax_policies";
    /// Tax proof envelopes (proof_id -> TaxProofEnvelope)
    pub const TAX_PROOFS: &str = "tax_proofs";
    /// Tax disclosure envelopes (disclosure_id -> TaxDisclosureEnvelope)
    pub const TAX_DISCLOSURES: &str = "tax_disclosures";
    /// Tax subject index (subject_commitment -> proof_ids)
    pub const TAX_SUBJECT_INDEX: &str = "tax_subject_index";
    /// Tax issuer index (issuer_id -> proof_ids)
    pub const TAX_ISSUER_INDEX: &str = "tax_issuer_index";
    /// Tax events (block_height + idx -> TaxEvent)
    pub const TAX_EVENTS: &str = "tax_events";

    // SRC-83X Business & Equity column families
    /// Entity profiles (subject_id -> EntityProfile)
    pub const EQUITY_ENTITIES: &str = "equity_entities";
    /// Governance actions (action_id -> GovernanceAction)
    pub const EQUITY_GOVERNANCE: &str = "equity_governance";
    /// Equity tokens (class_id -> EquityToken)
    pub const EQUITY_TOKENS: &str = "equity_tokens";
    /// Equity balances (class_id + holder -> balance)
    pub const EQUITY_BALANCES: &str = "equity_balances";
    /// Equity controller configs (class_id -> EquityControllerConfig)
    pub const EQUITY_CONTROLLERS: &str = "equity_controllers";
    /// Corporate actions (action_id -> CorporateAction)
    pub const EQUITY_CORPORATE_ACTIONS: &str = "equity_corporate_actions";
    /// Ownership snapshots (snapshot_id -> OwnershipSnapshot)
    pub const EQUITY_SNAPSHOTS: &str = "equity_snapshots";
    /// Ownership proofs (proof_id -> OwnershipProofEnvelope)
    pub const EQUITY_PROOFS: &str = "equity_proofs";
    /// Entity index (subject_id -> governance_action_ids, token_class_ids)
    pub const EQUITY_ENTITY_INDEX: &str = "equity_entity_index";
    /// Holder index (holder_commitment -> class_ids with balance)
    pub const EQUITY_HOLDER_INDEX: &str = "equity_holder_index";
    /// Equity events (block_height + idx -> EquityEvent)
    pub const EQUITY_EVENTS: &str = "equity_events";

    // SRC-84X Agreement & IP column families
    /// Agreement commitments (agreement_id -> AgreementCommitment)
    pub const AGREEMENT_COMMITMENTS: &str = "agreement_commitments";
    /// Party signatures (signature_id -> PartySignature)
    pub const AGREEMENT_SIGNATURES: &str = "agreement_signatures";
    /// Attestation packets (attestation_id -> AttestationPacket)
    pub const AGREEMENT_ATTESTATIONS: &str = "agreement_attestations";
    /// IP rights actions (action_id -> IpRightsAction)
    pub const AGREEMENT_IP_ACTIONS: &str = "agreement_ip_actions";
    /// Executor links (link_id -> ExecutorLink)
    pub const AGREEMENT_EXECUTOR_LINKS: &str = "agreement_executor_links";
    /// Agreement proofs (proof_id -> AgreementProofEnvelope)
    pub const AGREEMENT_PROOFS: &str = "agreement_proofs";
    /// Agreement party index (party_ref_hash -> agreement_ids)
    pub const AGREEMENT_PARTY_INDEX: &str = "agreement_party_index";
    /// Agreement executor index (executor_address -> link_ids)
    pub const AGREEMENT_EXECUTOR_INDEX: &str = "agreement_executor_index";
    /// Agreement events (block_height + idx -> AgreementEvent)
    pub const AGREEMENT_EVENTS: &str = "agreement_events";

    // SRC-85X Legal & Benefits column families
    /// Case anchors (case_id -> CaseAnchor)
    pub const LEGAL_CASES: &str = "legal_cases";
    /// Process events (event_id -> ProcessEvent)
    pub const LEGAL_EVENTS: &str = "legal_events";
    /// Court orders (order_id -> CourtOrder)
    pub const LEGAL_ORDERS: &str = "legal_orders";
    /// Benefit determinations (benefit_id -> BenefitDetermination)
    pub const LEGAL_BENEFITS: &str = "legal_benefits";
    /// Legal proofs (proof_id -> LegalProofEnvelope)
    pub const LEGAL_PROOFS: &str = "legal_proofs";
    /// Case event index (case_id -> event_ids)
    pub const LEGAL_CASE_EVENT_INDEX: &str = "legal_case_event_index";
    /// Case order index (case_id -> order_ids)
    pub const LEGAL_CASE_ORDER_INDEX: &str = "legal_case_order_index";
    /// Jurisdiction index (jurisdiction_code -> case_ids, benefit_ids)
    pub const LEGAL_JURISDICTION_INDEX: &str = "legal_jurisdiction_index";
    /// Legal system events (block_height + idx -> LegalEvent)
    pub const LEGAL_SYSTEM_EVENTS: &str = "legal_system_events";

    // SRC-86X Property & Insurance column families
    /// Asset anchors (asset_id -> AssetAnchor)
    pub const PROPERTY_ASSETS: &str = "property_assets";
    /// Title events (event_id -> TitleEvent)
    pub const PROPERTY_TITLE_EVENTS: &str = "property_title_events";
    /// Encumbrances (encumbrance_id -> Encumbrance)
    pub const PROPERTY_ENCUMBRANCES: &str = "property_encumbrances";
    /// Insurance coverage (coverage_id -> InsuranceCoverage)
    pub const PROPERTY_COVERAGE: &str = "property_coverage";
    /// Insurance claims (claim_id -> InsuranceClaim)
    pub const PROPERTY_CLAIMS: &str = "property_claims";
    /// Property proofs (proof_id -> PropertyProofEnvelope)
    pub const PROPERTY_PROOFS: &str = "property_proofs";
    /// Asset title index (asset_id -> title_event_ids)
    pub const PROPERTY_ASSET_TITLE_INDEX: &str = "property_asset_title_index";
    /// Asset encumbrance index (asset_id -> encumbrance_ids)
    pub const PROPERTY_ASSET_ENCUMBRANCE_INDEX: &str = "property_asset_encumbrance_index";
    /// Asset coverage index (asset_id -> coverage_ids)
    pub const PROPERTY_ASSET_COVERAGE_INDEX: &str = "property_asset_coverage_index";
    /// Coverage claim index (coverage_id -> claim_ids)
    pub const PROPERTY_COVERAGE_CLAIM_INDEX: &str = "property_coverage_claim_index";
    /// Jurisdiction index (jurisdiction_code -> asset_ids)
    pub const PROPERTY_JURISDICTION_INDEX: &str = "property_jurisdiction_index";
    /// Property system events (block_height + idx -> PropertyEvent)
    pub const PROPERTY_SYSTEM_EVENTS: &str = "property_system_events";

    // SRC-87X Healthcare & Membership column families
    /// Provider profiles (provider_id -> ProviderProfile)
    pub const HEALTHCARE_PROVIDERS: &str = "healthcare_providers";
    /// Membership records (membership_id -> MembershipRecord)
    pub const HEALTHCARE_MEMBERSHIPS: &str = "healthcare_memberships";
    /// Consent envelopes (consent_id -> ConsentEnvelope)
    pub const HEALTHCARE_CONSENTS: &str = "healthcare_consents";
    /// Prescriptions (prescription_id -> Prescription)
    pub const HEALTHCARE_PRESCRIPTIONS: &str = "healthcare_prescriptions";
    /// Healthcare proofs (proof_id -> HealthcareProofEnvelope)
    pub const HEALTHCARE_PROOFS: &str = "healthcare_proofs";
    /// Provider network index (provider_id -> affiliated_plan_ids)
    pub const HEALTHCARE_PROVIDER_NETWORK_INDEX: &str = "healthcare_provider_network_index";
    /// Member index (member_nullifier -> membership_ids)
    pub const HEALTHCARE_MEMBER_INDEX: &str = "healthcare_member_index";
    /// Subject consent index (subject_nullifier -> consent_ids)
    pub const HEALTHCARE_SUBJECT_CONSENT_INDEX: &str = "healthcare_subject_consent_index";
    /// Patient prescription index (patient_nullifier -> prescription_ids)
    pub const HEALTHCARE_PATIENT_RX_INDEX: &str = "healthcare_patient_rx_index";
    /// Prescriber prescription index (prescriber_provider_id -> prescription_ids)
    pub const HEALTHCARE_PRESCRIBER_RX_INDEX: &str = "healthcare_prescriber_rx_index";
    /// Healthcare system events (block_height + idx -> HealthcareEvent)
    pub const HEALTHCARE_SYSTEM_EVENTS: &str = "healthcare_system_events";

    // SRC-88X Employment & HR column families
    /// Employment issuers (issuer_address -> EmploymentIssuerProfile)
    pub const EMPLOYMENT_ISSUERS: &str = "employment_issuers";
    /// Employment credentials (employment_id -> EmploymentCredential)
    pub const EMPLOYMENT_CREDENTIALS: &str = "employment_credentials";
    /// Income attestations (attestation_id -> IncomeAttestation)
    pub const EMPLOYMENT_INCOME_ATTESTATIONS: &str = "employment_income_attestations";
    /// Employment proofs (proof_id -> EmploymentProofEnvelope)
    pub const EMPLOYMENT_PROOFS: &str = "employment_proofs";
    /// Employee index (employee_ref -> employment_ids)
    pub const EMPLOYMENT_EMPLOYEE_INDEX: &str = "employment_employee_index";
    /// Employee address index (employee_address -> employment_ids)
    pub const EMPLOYMENT_EMPLOYEE_ADDRESS_INDEX: &str = "employment_employee_address_index";
    /// Income attestation holder address index (holder_address -> attestation_ids)
    pub const EMPLOYMENT_INCOME_HOLDER_ADDRESS_INDEX: &str = "employment_income_holder_address_index";
    /// Employer index (employer_ref -> employment_ids)
    pub const EMPLOYMENT_EMPLOYER_INDEX: &str = "employment_employer_index";
    /// Subject income index (subject_ref -> attestation_ids)
    pub const EMPLOYMENT_SUBJECT_INCOME_INDEX: &str = "employment_subject_income_index";
    /// Employment system events (block_height + idx -> EmploymentEvent)
    pub const EMPLOYMENT_SYSTEM_EVENTS: &str = "employment_system_events";

    // Transaction indexing by address
    /// Transactions by sender (sender + height + tx_index -> tx_hash)
    pub const TX_BY_SENDER: &str = "tx_by_sender";
    /// Transactions by recipient (recipient + height + tx_index -> tx_hash)
    pub const TX_BY_RECIPIENT: &str = "tx_by_recipient";

    // SRC-89X Finance & Banking column families
    /// Finance issuers (issuer_address -> FinanceIssuerProfile)
    pub const FINANCE_ISSUERS: &str = "finance_issuers";
    /// Address proofs (proof_id -> AddressProof)
    pub const FINANCE_ADDRESS_PROOFS: &str = "finance_address_proofs";
    /// Bank standing credentials (credential_id -> BankStandingCredential)
    pub const FINANCE_BANK_STANDINGS: &str = "finance_bank_standings";
    /// KYC attestations (attestation_id -> KycAttestation)
    pub const FINANCE_KYC_ATTESTATIONS: &str = "finance_kyc_attestations";
    /// Finance proofs (proof_id -> FinanceProofEnvelope)
    pub const FINANCE_PROOFS: &str = "finance_proofs";
    /// Subject address index (subject_ref -> address_proof_ids)
    pub const FINANCE_SUBJECT_ADDRESS_INDEX: &str = "finance_subject_address_index";
    /// Subject bank standing index (subject_ref -> bank_standing_ids)
    pub const FINANCE_SUBJECT_BANK_INDEX: &str = "finance_subject_bank_index";
    /// Subject KYC index (subject_ref -> kyc_attestation_ids)
    pub const FINANCE_SUBJECT_KYC_INDEX: &str = "finance_subject_kyc_index";
    /// Holder address index for address proofs (holder_address -> proof_ids)
    pub const FINANCE_HOLDER_ADDRESS_PROOF_INDEX: &str = "finance_holder_address_proof_index";
    /// Holder address index for bank standings (holder_address -> credential_ids)
    pub const FINANCE_HOLDER_BANK_INDEX: &str = "finance_holder_bank_index";
    /// Holder address index for KYC attestations (holder_address -> attestation_ids)
    pub const FINANCE_HOLDER_KYC_INDEX: &str = "finance_holder_kyc_index";
    /// Jurisdiction index (jurisdiction_code -> issuer_addresses, proof_ids)
    pub const FINANCE_JURISDICTION_INDEX: &str = "finance_jurisdiction_index";
    /// Finance system events (block_height + idx -> FinanceEvent)
    pub const FINANCE_SYSTEM_EVENTS: &str = "finance_system_events";

    // SRC-87X Healthcare holder address indexes
    /// Member address index for memberships (member_address -> membership_ids)
    pub const HEALTHCARE_MEMBER_ADDRESS_INDEX: &str = "healthcare_member_address_index";
    /// Subject address index for consents (subject_address -> consent_ids)
    pub const HEALTHCARE_SUBJECT_ADDRESS_INDEX: &str = "healthcare_subject_address_index";
    /// Patient address index for prescriptions (patient_address -> prescription_ids)
    pub const HEALTHCARE_PATIENT_ADDRESS_INDEX: &str = "healthcare_patient_address_index";

    // Policy Account column families
    /// Policy accounts (policy_account_id -> PolicyAccount)
    pub const POLICY_ACCOUNTS: &str = "policy_accounts";
    /// Proposals (proposal_id -> Proposal)
    pub const POLICY_PROPOSALS: &str = "policy_proposals";

    // On-chain governance v1 (issue #50; docs/specs/GOVERNANCE-V1.md).
    // Data model only in Phase 2; behavior stays dormant behind the P1 gate.
    /// Governance asset registry (asset key -> GovAsset)
    pub const GOV_REGISTRY: &str = "gov_registry";
    /// Governance proposals (proposal_id -> GovProposal)
    pub const GOV_PROPOSALS: &str = "gov_proposals";
    /// Governance votes (proposal_id || voter -> GovVote)
    pub const GOV_VOTES: &str = "gov_votes";
    /// Governance voting-power snapshots (proposal_id || holder -> weight u128 BE)
    pub const GOV_SNAPSHOTS: &str = "gov_snapshots";
    /// Governance proposal-by-proposer index (proposer || proposal_id -> ())
    pub const GOV_PROPOSAL_INDEX: &str = "gov_proposal_index";

    // Governance v2 (native-Koppa eligibility #91, SRC-833 equity vote #92).
    /// Native-eligibility qualifying SRC-20 registry (#91). Key: `token_id` (32).
    /// Value: bincode `QualifyingAsset { min_balance: u128, effective_height: u64 }`.
    /// Validator-quorum authorized; enumerates the native 1-address-1-vote
    /// electorate at proposal creation.
    pub const GOV_QUALIFYING_ASSETS: &str = "gov_qualifying_assets";
    /// Per-proposal frozen equity-class balances root (#92). Key: `proposal_id`
    /// (32). Value: bincode `EquityClassRoot { class_id, balances_root,
    /// votes_per_share, frozen_height }`. Binds a chain-derived Merkle root to a
    /// single proposal so votes prove membership under exactly the frozen root.
    pub const GOV_EQUITY_CLASS_ROOTS: &str = "gov_equity_class_roots";
    /// Per-(proposal, holder_commitment) equity-vote dedup (#92). Key:
    /// `proposal_id (32) || holder_commitment (32)` (64). Value: `&[]` (presence).
    pub const GOV_EQUITY_USED_COMMITMENTS: &str = "gov_equity_used_commitments";
}

/// All column families used by the database
pub const ALL_CFS: &[&str] = &[
    cf::BLOCKS,
    cf::BLOCK_HEIGHT,
    cf::STATE,
    cf::TRANSACTIONS,
    cf::RECEIPTS,
    cf::META,
    cf::STATE_DIFFS,
    cf::NFT_COLLECTIONS,
    cf::NFT_TOKENS,
    cf::NFT_OWNER_INDEX,
    cf::NFT_COLLECTION_INDEX,
    cf::ISSUER_REGISTRY,
    cf::TOKENS,
    cf::TOKEN_BALANCES,
    cf::TOKEN_ALLOWANCES,
    cf::TOKEN_HOLDER_INDEX,
    cf::VALIDATORS,
    cf::DELEGATIONS,
    cf::UNBONDING_DELEGATIONS,
    cf::DELEGATION_VALIDATOR_INDEX,
    cf::SLASHING_RECORDS,
    cf::VALIDATOR_SIGNING_INFO,
    cf::MISSED_BLOCKS,
    cf::VALIDATOR_SETS,
    cf::ACCOUNT_ENCRYPTION_KEYS,
    cf::ACTIVE_ARCHIVE_NODES_HISTORY,
    cf::ARCHIVE_UNBONDING,
    cf::CHALLENGEABLE_FILES_V2,
    cf::SUPPLY,
    cf::STORAGE_METADATA_V2,
    cf::ASSIGNMENT_ATTESTATIONS_V2,
    cf::FILE_REASSIGNMENTS,
    cf::ASSIGNMENT_ATTESTATIONS_V2_EPOCH,
    cf::INFERENCE_ATTESTATIONS,
    cf::INFERENCE_ATTESTATIONS_BY_SESSION,
    cf::INFERENCE_SESSIONS,
    cf::INFERENCE_CLAIMS,
    cf::INFERENCE_DISPUTES,
    cf::INFERENCE_VERIFIERS,
    // SRC-817/818 Education-LMS suite (Phase 2)
    cf::EDU_CATALOG_ENTRIES,
    cf::EDU_CATALOG_PREREQUISITES,
    cf::EDU_CATALOG_ACCREDITATION,
    cf::EDU_CATALOG_CONTENT_ITEMS,
    cf::EDU_CATALOG_BY_INSTITUTION,
    cf::EDU_CATALOG_BY_CODE,
    cf::EDU_CATALOG_BY_STATUS,
    cf::EDU_OFFERINGS,
    cf::EDU_INSTRUCTOR_BINDINGS,
    cf::EDU_CONTENT_ITEMS,
    cf::EDU_ASSESSMENTS,
    cf::EDU_ENROLLMENT_LINKS,
    cf::EDU_SUBMISSIONS,
    cf::EDU_GRADES,
    cf::EDU_OFFERING_BY_CATALOG,
    cf::EDU_OFFERING_BY_STATUS,
    cf::EDU_SUBMISSION_BY_STUDENT_COMMITMENT,
    // SRC-80X/81X DocClass
    cf::DOCCLASS_IDENTITY_ROOTS,
    cf::DOCCLASS_ELIGIBILITY,
    cf::DOCCLASS_CREDENTIALS,
    cf::DOCCLASS_REVOCATIONS,
    cf::DOCCLASS_ISSUERS,
    cf::DOCCLASS_SUBJECT_INDEX,
    cf::DOCCLASS_ISSUER_INDEX,
    cf::DOCCLASS_EVENTS,
    // SRC-201 Messaging
    cf::MESSAGING_CONFIG,
    cf::MESSAGING_SENDER_NONCES,
    cf::MESSAGING_DAILY_COUNTS,
    cf::MESSAGING_STAKES,
    cf::MESSAGING_SPAM_SCORES,
    cf::MESSAGING_INBOX_FILTERS,
    cf::MESSAGING_CONTACTS,
    cf::MESSAGING_BLOCKED,
    cf::MESSAGING_PENDING_PAYMENTS,
    cf::MESSAGING_EVENTS,
    cf::MESSAGING_SENDER_EVENTS,
    cf::MESSAGING_PAYMENTS_BY_RECIPIENT,
    cf::MESSAGING_PUBLIC_KEYS,
    cf::CONTRACT_CODE,
    cf::CONTRACT_STORAGE,
    cf::CONTRACT_METADATA,
    cf::CONTRACT_STATE_DIFFS,
    // SRC-82X Tax & Compliance
    cf::TAX_CLAIM_TYPES,
    cf::TAX_ISSUERS,
    cf::TAX_POLICIES,
    cf::TAX_PROOFS,
    cf::TAX_DISCLOSURES,
    cf::TAX_SUBJECT_INDEX,
    cf::TAX_ISSUER_INDEX,
    cf::TAX_EVENTS,
    // SRC-83X Business & Equity
    cf::EQUITY_ENTITIES,
    cf::EQUITY_GOVERNANCE,
    cf::EQUITY_TOKENS,
    cf::EQUITY_BALANCES,
    cf::EQUITY_CONTROLLERS,
    cf::EQUITY_CORPORATE_ACTIONS,
    cf::EQUITY_SNAPSHOTS,
    cf::EQUITY_PROOFS,
    cf::EQUITY_ENTITY_INDEX,
    cf::EQUITY_HOLDER_INDEX,
    cf::EQUITY_EVENTS,
    // SRC-84X Agreement & IP
    cf::AGREEMENT_COMMITMENTS,
    cf::AGREEMENT_SIGNATURES,
    cf::AGREEMENT_ATTESTATIONS,
    cf::AGREEMENT_IP_ACTIONS,
    cf::AGREEMENT_EXECUTOR_LINKS,
    cf::AGREEMENT_PROOFS,
    cf::AGREEMENT_PARTY_INDEX,
    cf::AGREEMENT_EXECUTOR_INDEX,
    cf::AGREEMENT_EVENTS,
    // SRC-85X Legal & Benefits
    cf::LEGAL_CASES,
    cf::LEGAL_EVENTS,
    cf::LEGAL_ORDERS,
    cf::LEGAL_BENEFITS,
    cf::LEGAL_PROOFS,
    cf::LEGAL_CASE_EVENT_INDEX,
    cf::LEGAL_CASE_ORDER_INDEX,
    cf::LEGAL_JURISDICTION_INDEX,
    cf::LEGAL_SYSTEM_EVENTS,
    // SRC-86X Property & Insurance
    cf::PROPERTY_ASSETS,
    cf::PROPERTY_TITLE_EVENTS,
    cf::PROPERTY_ENCUMBRANCES,
    cf::PROPERTY_COVERAGE,
    cf::PROPERTY_CLAIMS,
    cf::PROPERTY_PROOFS,
    cf::PROPERTY_ASSET_TITLE_INDEX,
    cf::PROPERTY_ASSET_ENCUMBRANCE_INDEX,
    cf::PROPERTY_ASSET_COVERAGE_INDEX,
    cf::PROPERTY_COVERAGE_CLAIM_INDEX,
    cf::PROPERTY_JURISDICTION_INDEX,
    cf::PROPERTY_SYSTEM_EVENTS,
    // SRC-87X Healthcare & Membership
    cf::HEALTHCARE_PROVIDERS,
    cf::HEALTHCARE_MEMBERSHIPS,
    cf::HEALTHCARE_CONSENTS,
    cf::HEALTHCARE_PRESCRIPTIONS,
    cf::HEALTHCARE_PROOFS,
    cf::HEALTHCARE_PROVIDER_NETWORK_INDEX,
    cf::HEALTHCARE_MEMBER_INDEX,
    cf::HEALTHCARE_SUBJECT_CONSENT_INDEX,
    cf::HEALTHCARE_PATIENT_RX_INDEX,
    cf::HEALTHCARE_PRESCRIBER_RX_INDEX,
    cf::HEALTHCARE_SYSTEM_EVENTS,
    cf::HEALTHCARE_MEMBER_ADDRESS_INDEX,
    cf::HEALTHCARE_SUBJECT_ADDRESS_INDEX,
    cf::HEALTHCARE_PATIENT_ADDRESS_INDEX,
    // SRC-88X Employment & HR
    cf::EMPLOYMENT_ISSUERS,
    cf::EMPLOYMENT_CREDENTIALS,
    cf::EMPLOYMENT_INCOME_ATTESTATIONS,
    cf::EMPLOYMENT_PROOFS,
    cf::EMPLOYMENT_EMPLOYEE_INDEX,
    cf::EMPLOYMENT_EMPLOYEE_ADDRESS_INDEX,
    cf::EMPLOYMENT_INCOME_HOLDER_ADDRESS_INDEX,
    cf::EMPLOYMENT_EMPLOYER_INDEX,
    cf::EMPLOYMENT_SUBJECT_INCOME_INDEX,
    cf::EMPLOYMENT_SYSTEM_EVENTS,
    // SRC-89X Finance & Banking
    cf::FINANCE_ISSUERS,
    cf::FINANCE_ADDRESS_PROOFS,
    cf::FINANCE_BANK_STANDINGS,
    cf::FINANCE_KYC_ATTESTATIONS,
    cf::FINANCE_PROOFS,
    cf::FINANCE_SUBJECT_ADDRESS_INDEX,
    cf::FINANCE_SUBJECT_BANK_INDEX,
    cf::FINANCE_SUBJECT_KYC_INDEX,
    cf::FINANCE_HOLDER_ADDRESS_PROOF_INDEX,
    cf::FINANCE_HOLDER_BANK_INDEX,
    cf::FINANCE_HOLDER_KYC_INDEX,
    cf::FINANCE_JURISDICTION_INDEX,
    cf::FINANCE_SYSTEM_EVENTS,
    // Policy Account
    cf::POLICY_ACCOUNTS,
    cf::POLICY_PROPOSALS,
    // Governance v1 (issue #50)
    cf::GOV_REGISTRY,
    cf::GOV_PROPOSALS,
    cf::GOV_VOTES,
    cf::GOV_SNAPSHOTS,
    cf::GOV_PROPOSAL_INDEX,
    // Governance v2 (issue #91 native eligibility, #92 equity vote)
    cf::GOV_QUALIFYING_ASSETS,
    cf::GOV_EQUITY_CLASS_ROOTS,
    cf::GOV_EQUITY_USED_COMMITMENTS,
    // Node Registry
    cf::NODE_REGISTRY,
    // Storage Metadata
    cf::STORAGE_METADATA,
    // PoR Challenges
    cf::ACTIVE_CHALLENGES,
    // Transaction indexing
    cf::TX_BY_SENDER,
    cf::TX_BY_RECIPIENT,
];

/// Database configuration
#[derive(Debug, Clone)]
pub struct DatabaseConfig {
    /// Path to the database directory
    pub path: String,
    /// Create if missing
    pub create_if_missing: bool,
    /// Maximum open files
    pub max_open_files: i32,
    /// Write buffer size in bytes
    pub write_buffer_size: usize,
    /// Maximum write buffers
    pub max_write_buffer_number: i32,
    /// Try to repair database on corruption
    pub auto_repair: bool,
    /// Enable paranoid checks for data integrity
    pub paranoid_checks: bool,
}

impl Default for DatabaseConfig {
    fn default() -> Self {
        Self {
            path: "data/sumchain".to_string(),
            create_if_missing: true,
            max_open_files: 512,
            write_buffer_size: 64 * 1024 * 1024, // 64MB
            max_write_buffer_number: 3,
            auto_repair: true,
            paranoid_checks: true,
        }
    }
}

/// RocksDB database wrapper
pub struct Database {
    db: DB,
    path: String,
}

impl Database {
    /// Open or create a database at the given path
    pub fn open(config: &DatabaseConfig) -> Result<Self> {
        info!("Opening database at {}", config.path);

        let mut opts = Options::default();
        opts.create_if_missing(config.create_if_missing);
        opts.create_missing_column_families(true);
        opts.set_max_open_files(config.max_open_files);
        opts.set_write_buffer_size(config.write_buffer_size);
        opts.set_max_write_buffer_number(config.max_write_buffer_number);

        // Enable paranoid checks for data integrity
        if config.paranoid_checks {
            opts.set_paranoid_checks(true);
        }

        // Create column family descriptors
        let cf_descriptors: Vec<ColumnFamilyDescriptor> = ALL_CFS
            .iter()
            .map(|name| {
                let mut cf_opts = Options::default();
                cf_opts.set_write_buffer_size(config.write_buffer_size);
                ColumnFamilyDescriptor::new(*name, cf_opts)
            })
            .collect();

        // Try to open the database
        match DB::open_cf_descriptors(&opts, &config.path, cf_descriptors) {
            Ok(db) => {
                debug!("Database opened successfully with {} column families", ALL_CFS.len());
                Ok(Database { db, path: config.path.clone() })
            }
            Err(e) => {
                error!("Failed to open database: {}", e);

                // Attempt repair if enabled and this looks like corruption
                if config.auto_repair && Self::is_corruption_error(&e) {
                    warn!("Database appears corrupted, attempting repair...");

                    if let Err(repair_err) = Self::repair(&config.path) {
                        error!("Database repair failed: {}", repair_err);
                        return Err(StorageError::RocksDb(e));
                    }

                    info!("Database repair completed, retrying open...");

                    // Recreate descriptors after repair
                    let cf_descriptors: Vec<ColumnFamilyDescriptor> = ALL_CFS
                        .iter()
                        .map(|name| {
                            let mut cf_opts = Options::default();
                            cf_opts.set_write_buffer_size(config.write_buffer_size);
                            ColumnFamilyDescriptor::new(*name, cf_opts)
                        })
                        .collect();

                    let db = DB::open_cf_descriptors(&opts, &config.path, cf_descriptors)?;
                    info!("Database opened successfully after repair");
                    Ok(Database { db, path: config.path.clone() })
                } else {
                    Err(StorageError::RocksDb(e))
                }
            }
        }
    }

    /// Open a database with default configuration
    pub fn open_default<P: AsRef<Path>>(path: P) -> Result<Self> {
        let config = DatabaseConfig {
            path: path.as_ref().to_string_lossy().to_string(),
            ..Default::default()
        };
        Self::open(&config)
    }

    /// Open a database in true read-only mode for inspection.
    ///
    /// Guarantees relied on by the SNIP V2 pre-deployment tripwire
    /// (`sumchain inspect-v2-rows`):
    /// - never creates the database (`create_if_missing = false`)
    /// - never creates missing column families
    /// - never attempts repair
    /// - never writes a WAL or LOG entry (RocksDB read-only handle)
    ///
    /// Discovers and opens **every** column family that already exists on
    /// disk via `DB::list_cf`. This avoids two failure modes:
    /// - Some `rocksdb` bindings refuse a partial CF open (they want every
    ///   on-disk CF descriptor passed in). Opening the full set is always
    ///   accepted and costs nothing extra in read-only mode.
    /// - It transparently tolerates pre-V2 databases: V2 CFs that don't
    ///   exist on disk are simply absent from the opened set, and any
    ///   caller that asks for them via `prefix_iter`/`get`/etc. will see
    ///   `StorageError::NotFound("Column family: ...")`. The inspector
    ///   treats that as "this CF doesn't exist on this DB, so it has zero
    ///   rows."
    pub fn open_read_only<P: AsRef<Path>>(path: P) -> Result<Self> {
        let path_str = path.as_ref().to_string_lossy().to_string();

        let mut opts = Options::default();
        opts.create_if_missing(false);

        // Discover every CF on disk. `list_cf` is itself read-only and does
        // not require the DB to be opened first.
        let existing_cfs =
            DB::list_cf(&opts, &path_str).map_err(StorageError::RocksDb)?;

        let cf_descriptors: Vec<ColumnFamilyDescriptor> = existing_cfs
            .iter()
            .map(|n| {
                let cf_opts = Options::default();
                ColumnFamilyDescriptor::new(n, cf_opts)
            })
            .collect();

        // `error_if_log_file_exist = false` so a stopped-but-not-clean node
        // can still be inspected; the read-only handle never writes the WAL.
        let db = DB::open_cf_descriptors_read_only(
            &opts,
            &path_str,
            cf_descriptors,
            false,
        )
        .map_err(StorageError::RocksDb)?;

        Ok(Database { db, path: path_str })
    }

    /// Check if an error indicates database corruption
    fn is_corruption_error(e: &rocksdb::Error) -> bool {
        let msg = e.to_string().to_lowercase();
        msg.contains("corruption")
            || msg.contains("checksum")
            || msg.contains("manifest")
            || msg.contains("current")
            || msg.contains("invalid argument")
    }

    /// Attempt to repair a corrupted database
    pub fn repair<P: AsRef<Path>>(path: P) -> Result<()> {
        let path_str = path.as_ref().to_string_lossy().to_string();
        info!("Attempting to repair database at {}", path_str);

        let mut opts = Options::default();
        opts.create_if_missing(false);

        DB::repair(&opts, &path_str)?;

        info!("Database repair completed for {}", path_str);
        Ok(())
    }

    /// Get the database path
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Perform a consistency check on the database
    pub fn verify_integrity(&self) -> Result<bool> {
        // Try to read from all column families to verify they're accessible
        for cf_name in ALL_CFS {
            if let Err(e) = self.cf(cf_name) {
                error!("Column family {} is not accessible: {}", cf_name, e);
                return Ok(false);
            }
        }

        // Verify we can read the latest block (basic sanity check)
        match self.get(cf::META, b"latest_block_hash") {
            Ok(_) => {}
            Err(StorageError::NotFound(_)) => {} // Ok, might be new database
            Err(e) => {
                error!("Failed to read metadata: {}", e);
                return Ok(false);
            }
        }

        debug!("Database integrity check passed");
        Ok(true)
    }

    /// Compact the entire database to reclaim space and improve performance
    pub fn compact(&self) -> Result<()> {
        info!("Compacting database...");
        for cf_name in ALL_CFS {
            if let Ok(cf) = self.cf(cf_name) {
                self.db.compact_range_cf(cf, None::<&[u8]>, None::<&[u8]>);
            }
        }
        info!("Database compaction completed");
        Ok(())
    }

    /// Get approximate database size in bytes
    pub fn approximate_size(&self) -> u64 {
        let mut total = 0u64;
        if let Ok(Some(size_str)) = self.db.property_value("rocksdb.estimate-live-data-size") {
            if let Ok(size) = size_str.parse::<u64>() {
                total = size;
            }
        }
        total
    }

    /// Create a backup of the database to the specified directory
    ///
    /// This creates a consistent point-in-time backup that can be restored later.
    /// The backup directory must not exist or be empty.
    pub fn create_backup<P: AsRef<Path>>(&self, backup_dir: P) -> Result<BackupInfo> {
        let backup_path = backup_dir.as_ref();
        info!("Creating database backup to {:?}", backup_path);

        // Ensure backup directory exists
        std::fs::create_dir_all(backup_path).map_err(|e| {
            StorageError::InvalidData(format!("Failed to create backup directory: {}", e))
        })?;

        // Flush all pending writes first
        self.flush()?;

        // Create checkpoint (RocksDB's built-in backup mechanism)
        let checkpoint = rocksdb::checkpoint::Checkpoint::new(&self.db)?;
        checkpoint.create_checkpoint(backup_path)?;

        // Get backup metadata
        let size = Self::dir_size(backup_path);
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        info!(
            "Backup created successfully: {:?} ({} bytes)",
            backup_path, size
        );

        Ok(BackupInfo {
            path: backup_path.to_path_buf(),
            size_bytes: size,
            timestamp,
        })
    }

    /// Restore a database from a backup
    ///
    /// This will replace the current database with the backup.
    /// The current database must be closed before calling this.
    pub fn restore_from_backup<P: AsRef<Path>, Q: AsRef<Path>>(
        backup_dir: P,
        target_dir: Q,
    ) -> Result<()> {
        let backup_path = backup_dir.as_ref();
        let target_path = target_dir.as_ref();

        info!(
            "Restoring database from {:?} to {:?}",
            backup_path, target_path
        );

        // Verify backup exists
        if !backup_path.exists() {
            return Err(StorageError::NotFound(format!(
                "Backup directory not found: {:?}",
                backup_path
            )));
        }

        // Remove existing target if it exists
        if target_path.exists() {
            warn!("Removing existing database at {:?}", target_path);
            std::fs::remove_dir_all(target_path).map_err(|e| {
                StorageError::InvalidData(format!("Failed to remove existing database: {}", e))
            })?;
        }

        // Copy backup to target
        Self::copy_dir_recursive(backup_path, target_path)?;

        info!("Database restored successfully to {:?}", target_path);
        Ok(())
    }

    /// List available backups in a directory
    pub fn list_backups<P: AsRef<Path>>(backups_root: P) -> Result<Vec<BackupInfo>> {
        let root = backups_root.as_ref();
        let mut backups = Vec::new();

        if !root.exists() {
            return Ok(backups);
        }

        let entries = std::fs::read_dir(root).map_err(|e| {
            StorageError::InvalidData(format!("Failed to read backups directory: {}", e))
        })?;

        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                // Check if it looks like a RocksDB database
                if path.join("CURRENT").exists() {
                    let metadata = std::fs::metadata(&path).ok();
                    let timestamp = metadata
                        .and_then(|m| m.modified().ok())
                        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                        .map(|d| d.as_secs())
                        .unwrap_or(0);

                    backups.push(BackupInfo {
                        path: path.clone(),
                        size_bytes: Self::dir_size(&path),
                        timestamp,
                    });
                }
            }
        }

        // Sort by timestamp, newest first
        backups.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));

        Ok(backups)
    }

    /// Calculate total size of a directory
    fn dir_size<P: AsRef<Path>>(path: P) -> u64 {
        let mut size = 0u64;
        if let Ok(entries) = std::fs::read_dir(path) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_file() {
                    size += std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
                } else if path.is_dir() {
                    size += Self::dir_size(&path);
                }
            }
        }
        size
    }

    /// Recursively copy a directory
    fn copy_dir_recursive<P: AsRef<Path>, Q: AsRef<Path>>(src: P, dst: Q) -> Result<()> {
        let src = src.as_ref();
        let dst = dst.as_ref();

        std::fs::create_dir_all(dst).map_err(|e| {
            StorageError::InvalidData(format!("Failed to create directory {:?}: {}", dst, e))
        })?;

        for entry in std::fs::read_dir(src)
            .map_err(|e| StorageError::InvalidData(format!("Failed to read {:?}: {}", src, e)))?
        {
            let entry = entry.map_err(|e| {
                StorageError::InvalidData(format!("Failed to read entry: {}", e))
            })?;
            let src_path = entry.path();
            let dst_path = dst.join(entry.file_name());

            if src_path.is_dir() {
                Self::copy_dir_recursive(&src_path, &dst_path)?;
            } else {
                std::fs::copy(&src_path, &dst_path).map_err(|e| {
                    StorageError::InvalidData(format!(
                        "Failed to copy {:?} to {:?}: {}",
                        src_path, dst_path, e
                    ))
                })?;
            }
        }

        Ok(())
    }

    /// Get a column family handle
    fn cf(&self, name: &str) -> Result<&ColumnFamily> {
        self.db
            .cf_handle(name)
            .ok_or_else(|| StorageError::NotFound(format!("Column family: {}", name)))
    }

    /// Put a key-value pair into a column family
    pub fn put(&self, cf_name: &str, key: &[u8], value: &[u8]) -> Result<()> {
        let cf = self.cf(cf_name)?;
        self.db.put_cf(cf, key, value)?;
        Ok(())
    }

    /// Get a value by key from a column family
    pub fn get(&self, cf_name: &str, key: &[u8]) -> Result<Option<Vec<u8>>> {
        let cf = self.cf(cf_name)?;
        Ok(self.db.get_cf(cf, key)?)
    }

    /// Delete a key from a column family
    pub fn delete(&self, cf_name: &str, key: &[u8]) -> Result<()> {
        let cf = self.cf(cf_name)?;
        self.db.delete_cf(cf, key)?;
        Ok(())
    }

    /// Check if a key exists in a column family
    pub fn contains(&self, cf_name: &str, key: &[u8]) -> Result<bool> {
        Ok(self.get(cf_name, key)?.is_some())
    }

    /// Flush all pending writes to disk
    pub fn flush(&self) -> Result<()> {
        self.db.flush()?;
        Ok(())
    }

    /// Get database statistics
    pub fn stats(&self) -> Option<String> {
        self.db.property_value("rocksdb.stats").ok().flatten()
    }

    /// Create a write batch for atomic operations
    pub fn batch(&self) -> WriteBatch<'_> {
        WriteBatch {
            inner: rocksdb::WriteBatch::default(),
            db: &self.db,
        }
    }

    /// Get an iterator over a column family
    pub fn iter(&self, cf_name: &str) -> Result<impl Iterator<Item = (Box<[u8]>, Box<[u8]>)> + '_> {
        let cf = self.cf(cf_name)?;
        Ok(self
            .db
            .iterator_cf(cf, rocksdb::IteratorMode::Start)
            .filter_map(|r| r.ok()))
    }

    /// Get a forward iterator starting at the first key `>= start` (total-order
    /// seek). Used by the bounded PoR scheduler's seeded stride-walk over the
    /// challengeable-file index: `.next()` yields the first entry at or after a
    /// probe key without scanning from the start. Wrap-around is the caller's
    /// job (fall back to [`Self::iter`] when this yields `None`).
    pub fn iter_from<'a>(
        &'a self,
        cf_name: &str,
        start: &[u8],
    ) -> Result<impl Iterator<Item = (Box<[u8]>, Box<[u8]>)> + 'a> {
        let cf = self.cf(cf_name)?;
        Ok(self
            .db
            .iterator_cf(
                cf,
                rocksdb::IteratorMode::From(start, rocksdb::Direction::Forward),
            )
            .filter_map(|r| r.ok()))
    }

    /// Get an iterator with a prefix
    pub fn prefix_iter(
        &self,
        cf_name: &str,
        prefix: &[u8],
    ) -> Result<impl Iterator<Item = (Box<[u8]>, Box<[u8]>)> + '_> {
        let cf = self.cf(cf_name)?;
        Ok(self.db.prefix_iterator_cf(cf, prefix).filter_map(|r| r.ok()))
    }

    /// Get a full iterator over all entries in a column family
    pub fn full_iter(
        &self,
        cf_name: &str,
    ) -> Result<impl Iterator<Item = (Box<[u8]>, Box<[u8]>)> + '_> {
        let cf = self.cf(cf_name)?;
        Ok(self.db.iterator_cf(cf, rocksdb::IteratorMode::Start).filter_map(|r| r.ok()))
    }

    /// Wipe all data from specified column families
    ///
    /// This deletes all key-value pairs from the given column families.
    /// The column families themselves remain, just emptied of data.
    pub fn wipe_column_families(&self, cf_names: &[&str]) -> Result<usize> {
        let mut total_deleted = 0usize;

        for cf_name in cf_names {
            info!("Wiping column family: {}", cf_name);
            let cf = self.cf(cf_name)?;

            // Collect all keys first to avoid iterator invalidation
            let keys: Vec<Box<[u8]>> = self
                .db
                .iterator_cf(cf, rocksdb::IteratorMode::Start)
                .filter_map(|r| r.ok())
                .map(|(k, _)| k)
                .collect();

            let count = keys.len();
            for key in keys {
                self.db.delete_cf(cf, &key)?;
            }

            info!("Deleted {} entries from {}", count, cf_name);
            total_deleted += count;
        }

        // Compact the wiped column families to reclaim space
        for cf_name in cf_names {
            if let Ok(cf) = self.cf(cf_name) {
                self.db.compact_range_cf(cf, None::<&[u8]>, None::<&[u8]>);
            }
        }

        info!("Total deleted: {} entries from {} column families", total_deleted, cf_names.len());
        Ok(total_deleted)
    }
}

/// Atomic write batch
pub struct WriteBatch<'a> {
    inner: rocksdb::WriteBatch,
    db: &'a DB,
}

impl<'a> WriteBatch<'a> {
    /// Put a key-value pair
    pub fn put(&mut self, cf_name: &str, key: &[u8], value: &[u8]) -> Result<()> {
        let cf = self
            .db
            .cf_handle(cf_name)
            .ok_or_else(|| StorageError::NotFound(format!("Column family: {}", cf_name)))?;
        self.inner.put_cf(cf, key, value);
        Ok(())
    }

    /// Delete a key
    pub fn delete(&mut self, cf_name: &str, key: &[u8]) -> Result<()> {
        let cf = self
            .db
            .cf_handle(cf_name)
            .ok_or_else(|| StorageError::NotFound(format!("Column family: {}", cf_name)))?;
        self.inner.delete_cf(cf, key);
        Ok(())
    }

    /// Commit the batch atomically
    pub fn commit(self) -> Result<()> {
        self.db.write(self.inner)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn temp_db() -> (Database, TempDir) {
        let dir = TempDir::new().unwrap();
        let db = Database::open_default(dir.path()).unwrap();
        (db, dir)
    }

    #[test]
    fn test_put_get() {
        let (db, _dir) = temp_db();

        db.put(cf::META, b"key1", b"value1").unwrap();
        let value = db.get(cf::META, b"key1").unwrap();

        assert_eq!(value, Some(b"value1".to_vec()));
    }

    #[test]
    fn test_get_nonexistent() {
        let (db, _dir) = temp_db();

        let value = db.get(cf::META, b"nonexistent").unwrap();
        assert!(value.is_none());
    }

    #[test]
    fn test_delete() {
        let (db, _dir) = temp_db();

        db.put(cf::META, b"key", b"value").unwrap();
        assert!(db.contains(cf::META, b"key").unwrap());

        db.delete(cf::META, b"key").unwrap();
        assert!(!db.contains(cf::META, b"key").unwrap());
    }

    #[test]
    fn test_batch_commit() {
        let (db, _dir) = temp_db();

        let mut batch = db.batch();
        batch.put(cf::META, b"k1", b"v1").unwrap();
        batch.put(cf::META, b"k2", b"v2").unwrap();
        batch.commit().unwrap();

        assert_eq!(db.get(cf::META, b"k1").unwrap(), Some(b"v1".to_vec()));
        assert_eq!(db.get(cf::META, b"k2").unwrap(), Some(b"v2".to_vec()));
    }

    #[test]
    fn test_all_column_families() {
        let (db, _dir) = temp_db();

        // Verify all column families are accessible
        for cf_name in ALL_CFS {
            db.put(cf_name, b"test", b"value").unwrap();
            assert_eq!(db.get(cf_name, b"test").unwrap(), Some(b"value".to_vec()));
        }
    }
}
