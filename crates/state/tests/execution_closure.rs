//! The execution-mutation closure: what block execution can still commit, and
//! through which column families.
//!
//! # Why the other guard is not enough
//!
//! `execution_boundary.rs` counts `db.put(` / `db.delete(` / `db.batch(` inside
//! `crates/state/src`. That is a RAW-SYNTAX check, and it reads 3 — which is
//! true and almost meaningless, because nearly every committed write during
//! block execution goes through a store API rather than a database handle:
//!
//! ```ignore
//! store.identity_roots().put(&identity)?;   // -> IdentityRootStore::put -> db.put
//! store.titles().update_status(&id, st, ts)?;  // -> TitleEventStore::.. -> db.put
//! ```
//!
//! Neither line contains `db.put`, neither is in `crates/state/src`'s syntax
//! budget, and both commit application state in the middle of a block that may
//! never be accepted. A cross-crate audit at `20544f8a` found **317 such sites
//! across 116 application column families**, against a ratchet reading 3.
//!
//! # What this file does instead
//!
//! It computes the CLOSURE: every function that can reach a concrete database
//! mutation, following store constructions, accessor hops, `StateManager`,
//! struct fields, parameters, module-path and `Self::` calls, and the contract
//! flush — then walks FORWARD from `BlockExecutor::execute_block` and records
//! every crossing that block execution can actually reach.
//!
//! Two properties make it a guard rather than a survey:
//!
//! * **Rooted.** A site counts only if an entry point reaches the function it
//!   is in. An earlier version scanned every application function and defaulted
//!   `crates/state/src` to "execution", which counted a `pub fn` nothing calls
//!   the same as one the dispatcher runs every block — and made deleting dead
//!   code look like migration progress. A mutating function no root reaches is
//!   now declared in [`UNREACHED_MUTATORS`], not silently dropped.
//!
//! * **Keyed by identity.** [`MANIFEST`] records `(file, caller, callee,
//!   column families, occurrences)`. A count alone is not a guard: removing one
//!   write and adding another in the same file leaves a per-file total
//!   unchanged, and swapping which family a write targets leaves a family total
//!   unchanged. Both are real changes to what an unaccepted block can commit,
//!   and both used to pass.
//!
//! # What is deliberately NOT counted
//!
//! Four write classes are legitimate and stay out of the execution ledger, but
//! they are CLASSIFIED rather than ignored — [`non_execution_paths_are_classified`]
//! pins each one, so a new writer cannot hide by claiming one of these labels:
//!
//! * GENESIS — no block exists to abandon.
//! * REORG-UNDO — the committed write that unwinds a published block.
//! * CHAIN STORAGE — blocks, transactions, receipts, their indexes, validator
//!   sets. Not application state; the application journal will not cover them.
//! * SNAPSHOT — fast-sync restore, outside consensus.
//!
//! A fifth is not legitimate: OPERATOR TOOLING. See
//! [`operator_tooling_writes_are_declared_deployment_blockers`].
//!
//! The one sanctioned committed write — `ApplicationOverlay::into_batch`,
//! reachable only from `AcceptedCandidate::publish` — is exempt by FUNCTION,
//! not by file. An earlier version exempted three whole files, which hid any
//! other direct write in them.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::path::{Path, PathBuf};

// ═══════════════════════════════════════════════════════════════════════════
// THE LEDGER
// ═══════════════════════════════════════════════════════════════════════════

/// Every committed write block execution can reach, keyed by IDENTITY.
///
/// `(file, caller, callee, column families, occurrences)`.
///
/// A count is not a guard. With per-file totals, removing one write and adding
/// another in the same file passed; swapping which family a write targets, while
/// the family total stayed at 116, passed. Both change what an unaccepted block
/// can commit. Keying the caller function, the library function it actually
/// reaches, and the families that reach the database moves a row for either.
///
/// The caller is a function NAME, not a line: reformatting does not churn this,
/// and moving a write to a different function does.
///
/// ONLY EVER REMOVE ROWS. Recorded at `1687789`, rooted at
/// `BlockExecutor::execute_block`; five `state.rs` rows removed by the account
/// migration, which is the whole of its effect on this list:
///
/// ```text
///   StateManager::credit           -> StateStore::put_account   (STATE)
///   StateManager::deduct           -> StateStore::put_account   (STATE)
///   StateManager::increment_nonce  -> StateStore::put_account   (STATE)
///   StateManager::put_account      -> StateStore::put_account   (STATE)
///   StateManager::transfer         -> StateStore::put_account   (STATE)
/// ```
///
/// 311 occurrences over 235 rows becomes 304 over 230, and `cf::STATE` leaves
/// the execution set entirely — 114 families to 113. Every other row is
/// untouched: accounts were migrated, nothing else moved.
const MANIFEST: &[(&str, &str, &str, &str, usize)] = &[
    ("crates/state/src/agreement_executor.rs", "AgreementExecutor::execute", "AgreementCommitmentStore::mark_party_signed", "AGREEMENT_COMMITMENTS", 1),
    ("crates/state/src/agreement_executor.rs", "AgreementExecutor::execute", "AgreementCommitmentStore::put", "AGREEMENT_COMMITMENTS+AGREEMENT_PARTY_INDEX", 2),
    ("crates/state/src/agreement_executor.rs", "AgreementExecutor::execute", "AgreementCommitmentStore::update_status", "AGREEMENT_COMMITMENTS", 3),
    ("crates/state/src/agreement_executor.rs", "AgreementExecutor::execute", "AgreementProofStore::put", "AGREEMENT_PROOFS", 1),
    ("crates/state/src/agreement_executor.rs", "AgreementExecutor::execute", "AttestationStore::put", "AGREEMENT_ATTESTATIONS", 1),
    ("crates/state/src/agreement_executor.rs", "AgreementExecutor::execute", "AttestationStore::update_status", "AGREEMENT_ATTESTATIONS", 2),
    ("crates/state/src/agreement_executor.rs", "AgreementExecutor::execute", "ExecutorLinkStore::put", "AGREEMENT_EXECUTOR_INDEX+AGREEMENT_EXECUTOR_LINKS", 1),
    ("crates/state/src/agreement_executor.rs", "AgreementExecutor::execute", "ExecutorLinkStore::update_state", "AGREEMENT_EXECUTOR_LINKS", 5),
    ("crates/state/src/agreement_executor.rs", "AgreementExecutor::execute", "IpActionStore::put", "AGREEMENT_IP_ACTIONS", 1),
    ("crates/state/src/agreement_executor.rs", "AgreementExecutor::execute", "IpActionStore::update_status", "AGREEMENT_IP_ACTIONS", 1),
    ("crates/state/src/agreement_executor.rs", "AgreementExecutor::execute", "SignatureStore::delete", "AGREEMENT_SIGNATURES", 1),
    ("crates/state/src/agreement_executor.rs", "AgreementExecutor::execute", "SignatureStore::put", "AGREEMENT_SIGNATURES", 1),
    ("crates/state/src/docclass_executor.rs", "DocClassExecutor::create_identity_root", "DocClassEventStore::put", "DOCCLASS_EVENTS", 1),
    ("crates/state/src/docclass_executor.rs", "DocClassExecutor::create_identity_root", "IdentityRootStore::put", "DOCCLASS_IDENTITY_ROOTS+DOCCLASS_SUBJECT_INDEX", 1),
    ("crates/state/src/docclass_executor.rs", "DocClassExecutor::deactivate_identity", "DocClassEventStore::put", "DOCCLASS_EVENTS", 1),
    ("crates/state/src/docclass_executor.rs", "DocClassExecutor::deactivate_identity", "IdentityRootStore::update_status", "DOCCLASS_IDENTITY_ROOTS+DOCCLASS_SUBJECT_INDEX", 1),
    ("crates/state/src/docclass_executor.rs", "DocClassExecutor::deactivate_issuer", "DocClassEventStore::put", "DOCCLASS_EVENTS", 1),
    ("crates/state/src/docclass_executor.rs", "DocClassExecutor::deactivate_issuer", "DocClassIssuerStore::update_status", "DOCCLASS_ISSUERS", 1),
    ("crates/state/src/docclass_executor.rs", "DocClassExecutor::identity_add_controller", "DocClassEventStore::put", "DOCCLASS_EVENTS", 1),
    ("crates/state/src/docclass_executor.rs", "DocClassExecutor::identity_add_controller", "IdentityRootStore::put", "DOCCLASS_IDENTITY_ROOTS+DOCCLASS_SUBJECT_INDEX", 1),
    ("crates/state/src/docclass_executor.rs", "DocClassExecutor::identity_add_key", "DocClassEventStore::put", "DOCCLASS_EVENTS", 1),
    ("crates/state/src/docclass_executor.rs", "DocClassExecutor::identity_add_key", "IdentityRootStore::put", "DOCCLASS_IDENTITY_ROOTS+DOCCLASS_SUBJECT_INDEX", 1),
    ("crates/state/src/docclass_executor.rs", "DocClassExecutor::identity_remove_controller", "DocClassEventStore::put", "DOCCLASS_EVENTS", 1),
    ("crates/state/src/docclass_executor.rs", "DocClassExecutor::identity_remove_controller", "IdentityRootStore::put", "DOCCLASS_IDENTITY_ROOTS+DOCCLASS_SUBJECT_INDEX", 1),
    ("crates/state/src/docclass_executor.rs", "DocClassExecutor::identity_remove_key", "DocClassEventStore::put", "DOCCLASS_EVENTS", 1),
    ("crates/state/src/docclass_executor.rs", "DocClassExecutor::identity_remove_key", "IdentityRootStore::put", "DOCCLASS_IDENTITY_ROOTS+DOCCLASS_SUBJECT_INDEX", 1),
    ("crates/state/src/docclass_executor.rs", "DocClassExecutor::identity_rotate_key", "DocClassEventStore::put", "DOCCLASS_EVENTS", 1),
    ("crates/state/src/docclass_executor.rs", "DocClassExecutor::identity_rotate_key", "IdentityRootStore::put", "DOCCLASS_IDENTITY_ROOTS+DOCCLASS_SUBJECT_INDEX", 1),
    ("crates/state/src/docclass_executor.rs", "DocClassExecutor::identity_update_service", "DocClassEventStore::put", "DOCCLASS_EVENTS", 1),
    ("crates/state/src/docclass_executor.rs", "DocClassExecutor::identity_update_service", "IdentityRootStore::put", "DOCCLASS_IDENTITY_ROOTS+DOCCLASS_SUBJECT_INDEX", 1),
    ("crates/state/src/docclass_executor.rs", "DocClassExecutor::issue_academic_credential", "CredentialStore::put", "DOCCLASS_CREDENTIALS+DOCCLASS_ISSUER_INDEX+DOCCLASS_SUBJECT_INDEX", 1),
    ("crates/state/src/docclass_executor.rs", "DocClassExecutor::issue_academic_credential", "DocClassEventStore::put", "DOCCLASS_EVENTS", 1),
    ("crates/state/src/docclass_executor.rs", "DocClassExecutor::issue_eligibility", "DocClassEventStore::put", "DOCCLASS_EVENTS", 1),
    ("crates/state/src/docclass_executor.rs", "DocClassExecutor::issue_eligibility", "EligibilityStore::put", "DOCCLASS_ELIGIBILITY+DOCCLASS_ISSUER_INDEX+DOCCLASS_SUBJECT_INDEX", 1),
    ("crates/state/src/docclass_executor.rs", "DocClassExecutor::reactivate_credential", "CredentialStore::update_revocation", "DOCCLASS_CREDENTIALS+DOCCLASS_ISSUER_INDEX+DOCCLASS_SUBJECT_INDEX", 1),
    ("crates/state/src/docclass_executor.rs", "DocClassExecutor::reactivate_credential", "DocClassEventStore::put", "DOCCLASS_EVENTS", 1),
    ("crates/state/src/docclass_executor.rs", "DocClassExecutor::reactivate_credential", "EligibilityStore::update_revocation", "DOCCLASS_ELIGIBILITY+DOCCLASS_ISSUER_INDEX+DOCCLASS_SUBJECT_INDEX", 1),
    ("crates/state/src/docclass_executor.rs", "DocClassExecutor::reactivate_credential", "RevocationStore::put", "DOCCLASS_REVOCATIONS", 1),
    ("crates/state/src/docclass_executor.rs", "DocClassExecutor::reactivate_identity", "DocClassEventStore::put", "DOCCLASS_EVENTS", 1),
    ("crates/state/src/docclass_executor.rs", "DocClassExecutor::reactivate_identity", "IdentityRootStore::update_status", "DOCCLASS_IDENTITY_ROOTS+DOCCLASS_SUBJECT_INDEX", 1),
    ("crates/state/src/docclass_executor.rs", "DocClassExecutor::register_issuer", "DocClassEventStore::put", "DOCCLASS_EVENTS", 1),
    ("crates/state/src/docclass_executor.rs", "DocClassExecutor::register_issuer", "DocClassIssuerStore::put", "DOCCLASS_ISSUERS", 1),
    ("crates/state/src/docclass_executor.rs", "DocClassExecutor::revoke_credential", "CredentialStore::update_revocation", "DOCCLASS_CREDENTIALS+DOCCLASS_ISSUER_INDEX+DOCCLASS_SUBJECT_INDEX", 1),
    ("crates/state/src/docclass_executor.rs", "DocClassExecutor::revoke_credential", "DocClassEventStore::put", "DOCCLASS_EVENTS", 1),
    ("crates/state/src/docclass_executor.rs", "DocClassExecutor::revoke_credential", "EligibilityStore::update_revocation", "DOCCLASS_ELIGIBILITY+DOCCLASS_ISSUER_INDEX+DOCCLASS_SUBJECT_INDEX", 1),
    ("crates/state/src/docclass_executor.rs", "DocClassExecutor::revoke_credential", "RevocationStore::put", "DOCCLASS_REVOCATIONS", 1),
    ("crates/state/src/docclass_executor.rs", "DocClassExecutor::rotate_issuer_key", "DocClassEventStore::put", "DOCCLASS_EVENTS", 1),
    ("crates/state/src/docclass_executor.rs", "DocClassExecutor::rotate_issuer_key", "DocClassIssuerStore::put", "DOCCLASS_ISSUERS", 1),
    ("crates/state/src/docclass_executor.rs", "DocClassExecutor::supersede_credential", "CredentialStore::update_revocation", "DOCCLASS_CREDENTIALS+DOCCLASS_ISSUER_INDEX+DOCCLASS_SUBJECT_INDEX", 1),
    ("crates/state/src/docclass_executor.rs", "DocClassExecutor::supersede_credential", "DocClassEventStore::put", "DOCCLASS_EVENTS", 1),
    ("crates/state/src/docclass_executor.rs", "DocClassExecutor::supersede_credential", "EligibilityStore::update_revocation", "DOCCLASS_ELIGIBILITY+DOCCLASS_ISSUER_INDEX+DOCCLASS_SUBJECT_INDEX", 1),
    ("crates/state/src/docclass_executor.rs", "DocClassExecutor::supersede_credential", "RevocationStore::put", "DOCCLASS_REVOCATIONS", 1),
    ("crates/state/src/docclass_executor.rs", "DocClassExecutor::suspend_credential", "CredentialStore::update_revocation", "DOCCLASS_CREDENTIALS+DOCCLASS_ISSUER_INDEX+DOCCLASS_SUBJECT_INDEX", 1),
    ("crates/state/src/docclass_executor.rs", "DocClassExecutor::suspend_credential", "DocClassEventStore::put", "DOCCLASS_EVENTS", 1),
    ("crates/state/src/docclass_executor.rs", "DocClassExecutor::suspend_credential", "EligibilityStore::update_revocation", "DOCCLASS_ELIGIBILITY+DOCCLASS_ISSUER_INDEX+DOCCLASS_SUBJECT_INDEX", 1),
    ("crates/state/src/docclass_executor.rs", "DocClassExecutor::suspend_credential", "RevocationStore::put", "DOCCLASS_REVOCATIONS", 1),
    ("crates/state/src/docclass_executor.rs", "DocClassExecutor::update_issuer", "DocClassEventStore::put", "DOCCLASS_EVENTS", 1),
    ("crates/state/src/docclass_executor.rs", "DocClassExecutor::update_issuer", "DocClassIssuerStore::put", "DOCCLASS_ISSUERS", 1),
    ("crates/state/src/employment_executor.rs", "EmploymentExecutor::execute", "EmploymentCredentialStore::put", "EMPLOYMENT_CREDENTIALS+EMPLOYMENT_EMPLOYEE_ADDRESS_INDEX+EMPLOYMENT_EMPLOYEE_INDEX+EMPLOYMENT_EMPLOYER_INDEX", 1),
    ("crates/state/src/employment_executor.rs", "EmploymentExecutor::execute", "EmploymentCredentialStore::revoke", "EMPLOYMENT_CREDENTIALS", 1),
    ("crates/state/src/employment_executor.rs", "EmploymentExecutor::execute", "EmploymentCredentialStore::update_status", "EMPLOYMENT_CREDENTIALS", 3),
    ("crates/state/src/employment_executor.rs", "EmploymentExecutor::execute", "EmploymentIssuerStore::put", "EMPLOYMENT_ISSUERS", 1),
    ("crates/state/src/employment_executor.rs", "EmploymentExecutor::execute", "EmploymentIssuerStore::update_status", "EMPLOYMENT_ISSUERS", 4),
    ("crates/state/src/employment_executor.rs", "EmploymentExecutor::execute", "EmploymentProofStore::put", "EMPLOYMENT_PROOFS", 1),
    ("crates/state/src/employment_executor.rs", "EmploymentExecutor::execute", "IncomeAttestationStore::put", "EMPLOYMENT_INCOME_ATTESTATIONS+EMPLOYMENT_INCOME_HOLDER_ADDRESS_INDEX+EMPLOYMENT_SUBJECT_INCOME_INDEX", 1),
    ("crates/state/src/employment_executor.rs", "EmploymentExecutor::execute", "IncomeAttestationStore::revoke", "EMPLOYMENT_INCOME_ATTESTATIONS", 1),
    ("crates/state/src/executor.rs", "BlockExecutor::execute_sponsored_register_v1", "MessagingStore::set_public_key", "MESSAGING_PUBLIC_KEYS", 1),
    ("crates/state/src/finance_executor.rs", "FinanceExecutor::execute", "AddressProofStore::put", "FINANCE_ADDRESS_PROOFS+FINANCE_SUBJECT_ADDRESS_INDEX", 1),
    ("crates/state/src/finance_executor.rs", "FinanceExecutor::execute", "AddressProofStore::revoke", "FINANCE_ADDRESS_PROOFS", 1),
    ("crates/state/src/finance_executor.rs", "FinanceExecutor::execute", "BankStandingStore::put", "FINANCE_BANK_STANDINGS+FINANCE_SUBJECT_BANK_INDEX", 1),
    ("crates/state/src/finance_executor.rs", "FinanceExecutor::execute", "BankStandingStore::revoke", "FINANCE_BANK_STANDINGS", 1),
    ("crates/state/src/finance_executor.rs", "FinanceExecutor::execute", "BankStandingStore::update_standing", "FINANCE_BANK_STANDINGS", 1),
    ("crates/state/src/finance_executor.rs", "FinanceExecutor::execute", "FinanceIssuerStore::put", "FINANCE_ISSUERS+FINANCE_JURISDICTION_INDEX", 1),
    ("crates/state/src/finance_executor.rs", "FinanceExecutor::execute", "FinanceIssuerStore::update_status", "FINANCE_ISSUERS", 4),
    ("crates/state/src/finance_executor.rs", "FinanceExecutor::execute", "FinanceProofStore::put", "FINANCE_PROOFS", 1),
    ("crates/state/src/finance_executor.rs", "FinanceExecutor::execute", "KycAttestationStore::put", "FINANCE_KYC_ATTESTATIONS+FINANCE_SUBJECT_KYC_INDEX", 1),
    ("crates/state/src/finance_executor.rs", "FinanceExecutor::execute", "KycAttestationStore::revoke", "FINANCE_KYC_ATTESTATIONS", 1),
    ("crates/state/src/finance_executor.rs", "FinanceExecutor::execute", "KycAttestationStore::update_status", "FINANCE_KYC_ATTESTATIONS", 1),
    ("crates/state/src/healthcare_executor.rs", "HealthcareExecutor::execute", "ConsentStore::put", "HEALTHCARE_CONSENTS+HEALTHCARE_SUBJECT_CONSENT_INDEX", 2),
    ("crates/state/src/healthcare_executor.rs", "HealthcareExecutor::execute", "ConsentStore::update_status", "HEALTHCARE_CONSENTS", 3),
    ("crates/state/src/healthcare_executor.rs", "HealthcareExecutor::execute", "HealthcareProofStore::put", "HEALTHCARE_PROOFS", 1),
    ("crates/state/src/healthcare_executor.rs", "HealthcareExecutor::execute", "MembershipStore::add_dependent", "HEALTHCARE_MEMBERSHIPS", 1),
    ("crates/state/src/healthcare_executor.rs", "HealthcareExecutor::execute", "MembershipStore::put", "HEALTHCARE_MEMBERSHIPS+HEALTHCARE_MEMBER_INDEX", 1),
    ("crates/state/src/healthcare_executor.rs", "HealthcareExecutor::execute", "MembershipStore::remove_dependent", "HEALTHCARE_MEMBERSHIPS", 1),
    ("crates/state/src/healthcare_executor.rs", "HealthcareExecutor::execute", "MembershipStore::renew", "HEALTHCARE_MEMBERSHIPS", 1),
    ("crates/state/src/healthcare_executor.rs", "HealthcareExecutor::execute", "MembershipStore::update_status", "HEALTHCARE_MEMBERSHIPS", 4),
    ("crates/state/src/healthcare_executor.rs", "HealthcareExecutor::execute", "PrescriptionStore::add_fill_history", "HEALTHCARE_PRESCRIPTIONS", 1),
    ("crates/state/src/healthcare_executor.rs", "HealthcareExecutor::execute", "PrescriptionStore::put", "HEALTHCARE_PATIENT_RX_INDEX+HEALTHCARE_PRESCRIBER_RX_INDEX+HEALTHCARE_PRESCRIPTIONS", 1),
    ("crates/state/src/healthcare_executor.rs", "HealthcareExecutor::execute", "PrescriptionStore::record_fill", "HEALTHCARE_PRESCRIPTIONS", 1),
    ("crates/state/src/healthcare_executor.rs", "HealthcareExecutor::execute", "PrescriptionStore::update_status", "HEALTHCARE_PRESCRIPTIONS", 5),
    ("crates/state/src/healthcare_executor.rs", "HealthcareExecutor::execute", "ProviderStore::add_network_affiliation", "HEALTHCARE_PROVIDERS+HEALTHCARE_PROVIDER_NETWORK_INDEX", 1),
    ("crates/state/src/healthcare_executor.rs", "HealthcareExecutor::execute", "ProviderStore::put", "HEALTHCARE_PROVIDERS+HEALTHCARE_PROVIDER_NETWORK_INDEX", 1),
    ("crates/state/src/healthcare_executor.rs", "HealthcareExecutor::execute", "ProviderStore::remove_network_affiliation", "HEALTHCARE_PROVIDERS+HEALTHCARE_PROVIDER_NETWORK_INDEX", 1),
    ("crates/state/src/healthcare_executor.rs", "HealthcareExecutor::execute", "ProviderStore::update_status", "HEALTHCARE_PROVIDERS", 4),
    ("crates/state/src/legal_executor.rs", "LegalExecutor::execute", "BenefitStore::put", "LEGAL_BENEFITS+LEGAL_JURISDICTION_INDEX", 1),
    ("crates/state/src/legal_executor.rs", "LegalExecutor::execute", "BenefitStore::update_status", "LEGAL_BENEFITS", 4),
    ("crates/state/src/legal_executor.rs", "LegalExecutor::execute", "CaseStore::add_related_case", "LEGAL_CASES", 1),
    ("crates/state/src/legal_executor.rs", "LegalExecutor::execute", "CaseStore::put", "LEGAL_CASES+LEGAL_JURISDICTION_INDEX", 1),
    ("crates/state/src/legal_executor.rs", "LegalExecutor::execute", "CaseStore::update_status", "LEGAL_CASES", 6),
    ("crates/state/src/legal_executor.rs", "LegalExecutor::execute", "LegalProofStore::put", "LEGAL_PROOFS", 1),
    ("crates/state/src/legal_executor.rs", "LegalExecutor::execute", "OrderStore::put", "LEGAL_CASE_ORDER_INDEX+LEGAL_ORDERS", 2),
    ("crates/state/src/legal_executor.rs", "LegalExecutor::execute", "OrderStore::update_status", "LEGAL_ORDERS", 5),
    ("crates/state/src/legal_executor.rs", "LegalExecutor::execute", "ProcessEventStore::put", "LEGAL_CASE_EVENT_INDEX+LEGAL_EVENTS", 2),
    ("crates/state/src/legal_executor.rs", "LegalExecutor::execute", "ProcessEventStore::update_status", "LEGAL_EVENTS", 3),
    ("crates/state/src/messaging_executor.rs", "MessagingExecutor::add_contact", "MessagingStore::add_contact", "MESSAGING_CONTACTS", 1),
    ("crates/state/src/messaging_executor.rs", "MessagingExecutor::block_sender", "MessagingStore::block_sender", "MESSAGING_BLOCKED", 1),
    ("crates/state/src/messaging_executor.rs", "MessagingExecutor::claim_payment", "MessagingStore::delete_pending_payment", "MESSAGING_PAYMENTS_BY_RECIPIENT+MESSAGING_PENDING_PAYMENTS", 2),
    ("crates/state/src/messaging_executor.rs", "MessagingExecutor::fund_registry", "MessagingStore::add_sponsorship_balance", "MESSAGING_CONFIG", 1),
    ("crates/state/src/messaging_executor.rs", "MessagingExecutor::register_public_key", "MessagingStore::set_public_key", "MESSAGING_PUBLIC_KEYS", 1),
    ("crates/state/src/messaging_executor.rs", "MessagingExecutor::remove_contact", "MessagingStore::remove_contact", "MESSAGING_CONTACTS", 1),
    ("crates/state/src/messaging_executor.rs", "MessagingExecutor::report_spam", "MessagingStore::increment_spam_score", "MESSAGING_SPAM_SCORES", 1),
    ("crates/state/src/messaging_executor.rs", "MessagingExecutor::send_message_direct", "MessagingStore::increment_daily_message_count", "MESSAGING_DAILY_COUNTS", 1),
    ("crates/state/src/messaging_executor.rs", "MessagingExecutor::send_message_direct", "MessagingStore::increment_sender_nonce", "MESSAGING_SENDER_NONCES", 1),
    ("crates/state/src/messaging_executor.rs", "MessagingExecutor::send_message_direct", "MessagingStore::store_message_event", "MESSAGING_EVENTS+MESSAGING_SENDER_EVENTS", 1),
    ("crates/state/src/messaging_executor.rs", "MessagingExecutor::send_message_sponsored", "MessagingStore::increment_daily_message_count", "MESSAGING_DAILY_COUNTS", 1),
    ("crates/state/src/messaging_executor.rs", "MessagingExecutor::send_message_sponsored", "MessagingStore::increment_sender_nonce", "MESSAGING_SENDER_NONCES", 1),
    ("crates/state/src/messaging_executor.rs", "MessagingExecutor::send_message_sponsored", "MessagingStore::store_message_event", "MESSAGING_EVENTS+MESSAGING_SENDER_EVENTS", 1),
    ("crates/state/src/messaging_executor.rs", "MessagingExecutor::send_message_with_payment", "MessagingStore::increment_daily_message_count", "MESSAGING_DAILY_COUNTS", 1),
    ("crates/state/src/messaging_executor.rs", "MessagingExecutor::send_message_with_payment", "MessagingStore::increment_sender_nonce", "MESSAGING_SENDER_NONCES", 1),
    ("crates/state/src/messaging_executor.rs", "MessagingExecutor::send_message_with_payment", "MessagingStore::set_pending_payment", "MESSAGING_PAYMENTS_BY_RECIPIENT+MESSAGING_PENDING_PAYMENTS", 1),
    ("crates/state/src/messaging_executor.rs", "MessagingExecutor::send_message_with_payment", "MessagingStore::store_message_event", "MESSAGING_EVENTS+MESSAGING_SENDER_EVENTS", 1),
    ("crates/state/src/messaging_executor.rs", "MessagingExecutor::set_daily_quota", "MessagingStore::set_daily_quota", "MESSAGING_CONFIG", 1),
    ("crates/state/src/messaging_executor.rs", "MessagingExecutor::set_inbox_filter", "MessagingStore::set_inbox_filter", "MESSAGING_INBOX_FILTERS", 1),
    ("crates/state/src/messaging_executor.rs", "MessagingExecutor::set_max_message_size", "MessagingStore::set_max_message_size", "MESSAGING_CONFIG", 1),
    ("crates/state/src/messaging_executor.rs", "MessagingExecutor::set_min_trust_stake", "MessagingStore::set_min_trust_stake", "MESSAGING_CONFIG", 1),
    ("crates/state/src/messaging_executor.rs", "MessagingExecutor::set_sponsorship_enabled", "MessagingStore::set_sponsorship_enabled", "MESSAGING_CONFIG", 1),
    ("crates/state/src/messaging_executor.rs", "MessagingExecutor::stake_for_trust", "MessagingStore::add_stake", "MESSAGING_STAKES", 1),
    ("crates/state/src/messaging_executor.rs", "MessagingExecutor::unstake", "MessagingStore::set_stake_balance", "MESSAGING_STAKES", 1),
    ("crates/state/src/messaging_executor.rs", "MessagingExecutor::update_public_key", "MessagingStore::set_public_key", "MESSAGING_PUBLIC_KEYS", 1),
    ("crates/state/src/nft_executor.rs", "NftExecutor::execute_approve", "NftStore::put_token", "NFT_TOKENS", 1),
    ("crates/state/src/nft_executor.rs", "NftExecutor::execute_batch_mint", "NftStore::add_to_collection_index", "NFT_COLLECTION_INDEX", 1),
    ("crates/state/src/nft_executor.rs", "NftExecutor::execute_batch_mint", "NftStore::add_to_owner_index", "NFT_OWNER_INDEX", 1),
    ("crates/state/src/nft_executor.rs", "NftExecutor::execute_batch_mint", "NftStore::put_collection", "NFT_COLLECTIONS", 1),
    ("crates/state/src/nft_executor.rs", "NftExecutor::execute_batch_mint", "NftStore::put_token", "NFT_TOKENS", 1),
    ("crates/state/src/nft_executor.rs", "NftExecutor::execute_burn", "NftStore::burn_token", "NFT_COLLECTIONS+NFT_COLLECTION_INDEX+NFT_OWNER_INDEX+NFT_TOKENS", 1),
    ("crates/state/src/nft_executor.rs", "NftExecutor::execute_create_collection", "NftStore::put_collection", "NFT_COLLECTIONS", 1),
    ("crates/state/src/nft_executor.rs", "NftExecutor::execute_lock_token", "NftStore::put_token", "NFT_TOKENS", 1),
    ("crates/state/src/nft_executor.rs", "NftExecutor::execute_mint", "NftStore::add_to_collection_index", "NFT_COLLECTION_INDEX", 1),
    ("crates/state/src/nft_executor.rs", "NftExecutor::execute_mint", "NftStore::add_to_owner_index", "NFT_OWNER_INDEX", 1),
    ("crates/state/src/nft_executor.rs", "NftExecutor::execute_mint", "NftStore::put_collection", "NFT_COLLECTIONS", 1),
    ("crates/state/src/nft_executor.rs", "NftExecutor::execute_mint", "NftStore::put_token", "NFT_TOKENS", 1),
    ("crates/state/src/nft_executor.rs", "NftExecutor::execute_transfer", "NftStore::transfer_token", "NFT_OWNER_INDEX+NFT_TOKENS", 1),
    ("crates/state/src/nft_executor.rs", "NftExecutor::execute_transfer_collection", "NftStore::put_collection", "NFT_COLLECTIONS", 1),
    ("crates/state/src/nft_executor.rs", "NftExecutor::execute_unlock_token", "NftStore::put_token", "NFT_TOKENS", 1),
    ("crates/state/src/nft_executor.rs", "NftExecutor::execute_update_collection_config", "NftStore::put_collection", "NFT_COLLECTIONS", 1),
    ("crates/state/src/nft_executor.rs", "NftExecutor::execute_update_metadata", "NftStore::put_token", "NFT_TOKENS", 1),
    ("crates/state/src/property_executor.rs", "PropertyExecutor::execute", "AssetStore::put", "PROPERTY_ASSETS+PROPERTY_JURISDICTION_INDEX", 1),
    ("crates/state/src/property_executor.rs", "PropertyExecutor::execute", "AssetStore::update_status", "PROPERTY_ASSETS", 5),
    ("crates/state/src/property_executor.rs", "PropertyExecutor::execute", "ClaimStore::approve", "PROPERTY_CLAIMS", 1),
    ("crates/state/src/property_executor.rs", "PropertyExecutor::execute", "ClaimStore::pay", "PROPERTY_CLAIMS", 1),
    ("crates/state/src/property_executor.rs", "PropertyExecutor::execute", "ClaimStore::put", "PROPERTY_CLAIMS+PROPERTY_COVERAGE_CLAIM_INDEX", 1),
    ("crates/state/src/property_executor.rs", "PropertyExecutor::execute", "ClaimStore::update_status", "PROPERTY_CLAIMS", 5),
    ("crates/state/src/property_executor.rs", "PropertyExecutor::execute", "CoverageStore::put", "PROPERTY_ASSET_COVERAGE_INDEX+PROPERTY_COVERAGE", 1),
    ("crates/state/src/property_executor.rs", "PropertyExecutor::execute", "CoverageStore::renew", "PROPERTY_COVERAGE", 1),
    ("crates/state/src/property_executor.rs", "PropertyExecutor::execute", "CoverageStore::update_status", "PROPERTY_COVERAGE", 4),
    ("crates/state/src/property_executor.rs", "PropertyExecutor::execute", "EncumbranceStore::put", "PROPERTY_ASSET_ENCUMBRANCE_INDEX+PROPERTY_ENCUMBRANCES", 1),
    ("crates/state/src/property_executor.rs", "PropertyExecutor::execute", "EncumbranceStore::update_status", "PROPERTY_ENCUMBRANCES", 4),
    ("crates/state/src/property_executor.rs", "PropertyExecutor::execute", "PropertyProofStore::put", "PROPERTY_PROOFS", 1),
    ("crates/state/src/property_executor.rs", "PropertyExecutor::execute", "TitleEventStore::put", "PROPERTY_ASSET_TITLE_INDEX+PROPERTY_TITLE_EVENTS", 2),
    ("crates/state/src/property_executor.rs", "PropertyExecutor::execute", "TitleEventStore::update_status", "PROPERTY_TITLE_EVENTS", 3),
    ("crates/state/src/tax_executor.rs", "TaxExecutor::execute", "TaxClaimTypeStore::put", "TAX_CLAIM_TYPES", 3),
    ("crates/state/src/tax_executor.rs", "TaxExecutor::execute", "TaxDisclosureStore::put", "TAX_DISCLOSURES", 1),
    ("crates/state/src/tax_executor.rs", "TaxExecutor::execute", "TaxIssuerStore::put", "TAX_ISSUERS", 3),
    ("crates/state/src/tax_executor.rs", "TaxExecutor::execute", "TaxPolicyStore::put", "TAX_POLICIES", 2),
    ("crates/state/src/tax_executor.rs", "TaxExecutor::execute", "TaxProofStore::delete", "TAX_PROOFS", 1),
    ("crates/state/src/tax_executor.rs", "TaxExecutor::execute", "TaxProofStore::put", "TAX_PROOFS+TAX_SUBJECT_INDEX", 1),
];

/// Occurrences, not rows: a caller reaching the same mutator three times is
/// three places to fix.
const MANIFEST_OCCURRENCES: usize = 234;

/// Application column families a block can still commit to directly.
///
/// ONLY EVER DECREASE. Recorded at `1687789`. Lower than the 116 the unrooted
/// audit reported, for the reason in [`UNREACHED_MUTATORS`].
const LEDGER_CF_COUNT: usize = 86;

/// Functions that commit application state but that no entry point reaches.
///
/// Every one is either dead code or a gap in this file's call resolution, and
/// both need a human. Pinning them is what stops rooting from becoming a way to
/// hide a write: a new unreached mutator fails here rather than quietly
/// dropping out of the manifest.
///
/// Both of these are `pub` with no production caller anywhere in the workspace —
/// verified by grep, not by this resolver — so excluding them is correct.
const UNREACHED_MUTATORS: &[(&str, &str, &str)] = &[
    (
        "crates/state/src/state.rs",
        "StateManager::revert_state_diff",
        "pub, no production caller: the reorg path uses revert_block_state_diffs",
    ),
];


/// Column families declared in `sumchain_storage::cf` that nothing reads or
/// writes anywhere in the workspace.
///
/// Dead schema. They are created at open and never touched again. They must NOT
/// enter the journal allowlist — journalling a family no code uses would make
/// the journal look more complete than it is, and would keep the dead
/// declarations alive by giving them a reader.
const DEAD_COLUMN_FAMILIES: &[&str] = &[
    "EDU_CATALOG_ACCREDITATION",
    "EDU_CATALOG_PREREQUISITES",
    "EDU_INSTRUCTOR_BINDINGS",
    "FINANCE_HOLDER_ADDRESS_PROOF_INDEX",
    "FINANCE_HOLDER_BANK_INDEX",
    "FINANCE_HOLDER_KYC_INDEX",
    "HEALTHCARE_MEMBER_ADDRESS_INDEX",
    "HEALTHCARE_PATIENT_ADDRESS_INDEX",
    "HEALTHCARE_SUBJECT_ADDRESS_INDEX",
    "TAX_ISSUER_INDEX",
];

// ═══════════════════════════════════════════════════════════════════════════
// DISPATCHER ARMS
// ═══════════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ArmKind {
    /// Writes only through `ExecutionView`. Nothing to migrate.
    Overlay,
    /// Commits application state during execution.
    Committed,
    /// Takes an `ExecutionView` AND a committed handle, and uses both.
    Mixed,
}

/// Every `TxPayload` variant the block dispatcher handles, with where it writes.
///
/// The list is closed: [`every_dispatcher_arm_is_declared`] fails if the
/// executor gains or loses an arm, so a new transaction family cannot arrive
/// with an undeclared write surface.
const ARMS: &[(&str, ArmKind, &str)] = &[
    ("Agreement", ArmKind::Committed, "agreement_executor.rs -> AgreementStore sub-stores"),
    ("BeaconSetup", ArmKind::Overlay, "beacon_store.rs (revert stays direct, by design)"),
    ("BeaconSigning", ArmKind::Overlay, "beacon_store.rs (revert stays direct, by design)"),
    ("ComputePool", ArmKind::Overlay, "compute_pool_store.rs (revert stays direct, by design)"),
    ("ContractCall", ArmKind::Overlay, "sumc-runtime queues; contract_executor stages into the candidate"),
    ("ContractDeploy", ArmKind::Overlay, "sumc-runtime queues; contract_executor stages into the candidate"),
    ("DocClass", ArmKind::Committed, "docclass_executor.rs -> DocClassStore sub-stores"),
    ("Education", ArmKind::Overlay, "education_executor.rs"),
    ("Employment", ArmKind::Committed, "employment_executor.rs -> EmploymentStore sub-stores"),
    ("Equity", ArmKind::Overlay, "equity_executor.rs -> EquityExecutor::v_* -> candidate"),
    ("Finance", ArmKind::Committed, "finance_executor.rs -> FinanceStore sub-stores"),
    ("Governance", ArmKind::Overlay, "governance_executor.rs -> governance_view + Token/Equity v_* -> candidate"),
    ("Healthcare", ArmKind::Committed, "healthcare_executor.rs -> HealthcareStore sub-stores"),
    ("InferenceAttestation", ArmKind::Overlay, "inference_attestation_executor.rs"),
    ("InferenceAttestationV2", ArmKind::Overlay, "inference_attestation_executor.rs"),
    ("InferenceSettlement", ArmKind::Overlay, "inference_settlement_executor.rs"),
    ("Legal", ArmKind::Committed, "legal_executor.rs -> LegalStore sub-stores"),
    ("Messaging", ArmKind::Committed, "messaging_executor.rs -> MessagingStore"),
    ("Nft", ArmKind::Committed, "nft_executor.rs -> NftStore"),
    ("NodeRegistry", ArmKind::Overlay, "node_registry.rs"),
    ("NodeRegistryV2", ArmKind::Overlay, "node_registry.rs"),
    ("PolicyAccount", ArmKind::Overlay, "policy_account_executor.rs -> policy_account_view"),
    ("Property", ArmKind::Committed, "property_executor.rs -> PropertyStore sub-stores"),
    ("Staking", ArmKind::Overlay, "staking_executor.rs -> StakingExecutor::v_* -> candidate"),
    ("StorageMetadata", ArmKind::Overlay, "storage_metadata.rs"),
    ("StorageMetadataV2", ArmKind::Overlay, "storage_metadata.rs"),
    ("Supply", ArmKind::Overlay, "supply.rs"),
    ("Tax", ArmKind::Committed, "tax_executor.rs -> TaxStore sub-stores"),
    ("Token", ArmKind::Overlay, "token_executor.rs -> TokenExecutor::v_* -> candidate"),
    ("Transfer", ArmKind::Overlay, "executor.rs fee/transfer -> StateManager::v_transfer -> candidate cf::STATE"),
];

/// What 27 of the 30 arms do with the account row they debit. The fee debit,
/// the proposer credit and the nonce bump now stage into the block's candidate;
/// ComputePool, BeaconSetup and BeaconSigning are `fee_paid: 0` on every path
/// and debit nothing at all. Accounts were the widest single hole, which is why
/// they migrated first.
const ACCOUNT_WRITE_IS_UNIVERSAL: &str =
    "StateManager::v_put_account stages cf::STATE into the block's candidate";

// ═══════════════════════════════════════════════════════════════════════════
// THE SCANNER
// ═══════════════════════════════════════════════════════════════════════════
//
// Source-level, like the raw-syntax guard next door, and with the same honesty
// about what that means: this catches the shapes the codebase actually uses, not
// every shape Rust permits. What makes it worth having is that the shapes it
// follows — store construction, accessor hops, fields, parameters, helper
// indirection — are exactly the ones that made 317 sites invisible to a check
// that only knew `db.put`.
//
// Every resolution rule below is exercised by a synthetic-source test at the
// bottom of this file, and each of those tests was written by breaking the rule
// and watching the count drop.

/// The workspace root: `crates/state/..`.
fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
}

/// Crates whose `src/` is test scaffolding rather than production code.
/// `sumchain-integration-tests` is a library of tests: its modules are plain
/// `mod`s, not `#[cfg(test)]`, so stripping attributes does not reach them.
const TEST_ONLY_CRATES: &[&str] = &["crates/integration-tests/"];

/// The one sanctioned committed write: `(file, owner, fn)`.
///
/// `ApplicationOverlay::into_batch` turns the block's buffered rows into a
/// batch. It is crate-private to `sumchain-storage` and reachable only from
/// `AcceptedCandidate::publish`, which is the whole point of the typestate.
/// Counting it would mark the sanctioned publisher as the violation and every
/// migrated subsystem as unmigrated.
///
/// Exactly one FUNCTION, not a file and not a directory. An earlier version
/// exempted `overlay.rs`, `exec_view.rs` and `candidate.rs` wholesale, which
/// meant a new direct write anywhere in those three files — including one with
/// nothing to do with publication — was invisible.
const SANCTIONED_PUBLISHER: &[(&str, &str, &str)] = &[(
    "crates/storage/src/overlay.rs",
    "ApplicationOverlay",
    "into_batch",
)];

fn is_sanctioned_publisher(f: &Fun) -> bool {
    SANCTIONED_PUBLISHER.iter().any(|(file, owner, name)| {
        f.file == *file && f.owner.as_deref() == Some(*owner) && f.name == *name
    })
}

/// Production `.rs` sources under every crate's `src/`, keyed by workspace-
/// relative path. `#[cfg(test)]` modules and comment lines are removed first:
/// a fixture is not block execution, and a commented-out write is not a write.
fn production_sources() -> BTreeMap<String, String> {
    let root = workspace_root();
    let crates = root.join("crates");
    let mut out = BTreeMap::new();
    let mut dirs: Vec<PathBuf> = std::fs::read_dir(&crates)
        .expect("read crates/")
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.is_dir())
        .map(|p| p.join("src"))
        .filter(|p| p.is_dir())
        .collect();
    dirs.sort();
    for src_dir in dirs {
        walk(&src_dir, &root, &mut out);
    }
    out
}

fn walk(dir: &Path, root: &Path, out: &mut BTreeMap<String, String>) {
    let mut entries: Vec<PathBuf> = std::fs::read_dir(dir)
        .expect("read source directory")
        .filter_map(|e| e.ok().map(|e| e.path()))
        .collect();
    entries.sort();
    for path in entries {
        if path.is_dir() {
            walk(&path, root, out);
        } else if path.extension().and_then(|e| e.to_str()) == Some("rs") {
            let src = std::fs::read_to_string(&path).expect("read source");
            let rel = path
                .strip_prefix(root)
                .expect("path under the workspace root")
                .to_string_lossy()
                .replace('\\', "/");
            if TEST_ONLY_CRATES.iter().any(|c| rel.starts_with(c)) {
                continue;
            }
            out.insert(rel, prepare(&src));
        }
    }
}

/// Drop `#[cfg(test)]` items and comment lines, preserving line numbering so a
/// reported site can be opened at the line the scanner names.
fn prepare(src: &str) -> String {
    let no_comments: String = src
        .lines()
        .map(|l| {
            let t = l.trim_start();
            if t.starts_with("//") {
                ""
            } else {
                l
            }
        })
        .collect::<Vec<_>>()
        .join("\n");
    strip_cfg_test(&no_comments)
}

/// Remove every `#[cfg(test)]` item, blanking it in place so line numbers hold.
fn strip_cfg_test(src: &str) -> String {
    const ATTR: &str = "#[cfg(test)]";
    let mut out = src.to_string();
    let mut from = 0usize;
    while let Some(rel) = out[from..].find(ATTR) {
        let at = from + rel;
        // The item's body is the next balanced `{ .. }`; a `#[cfg(test)] use ..;`
        // or `mod x;` ends at the semicolon instead.
        let after = at + ATTR.len();
        let brace = out[after..].find('{').map(|i| after + i);
        let semi = out[after..].find(';').map(|i| after + i);
        let end = match (brace, semi) {
            (Some(b), Some(s)) if s < b => s + 1,
            (Some(b), _) => match matching(&out, b, b'{', b'}') {
                Some(e) => e + 1,
                None => break,
            },
            (None, Some(s)) => s + 1,
            (None, None) => break,
        };
        // Byte-for-byte, so every offset after this point still addresses the
        // same source position: a multi-byte character becomes that many
        // spaces, and newlines survive so line numbers hold.
        let mut blanked = String::with_capacity(end - at);
        for c in out[at..end].chars() {
            if c == '\n' {
                blanked.push('\n');
            } else {
                for _ in 0..c.len_utf8() {
                    blanked.push(' ');
                }
            }
        }
        out.replace_range(at..end, &blanked);
        from = end;
    }
    out
}

fn matching(s: &str, open: usize, o: u8, c: u8) -> Option<usize> {
    let b = s.as_bytes();
    let mut depth = 0usize;
    let mut i = open;
    while i < b.len() {
        match b[i] {
            x if x == o => depth += 1,
            x if x == c => {
                depth -= 1;
                if depth == 0 {
                    return Some(i);
                }
            }
            b'"' => i = skip_string(b, i)?.saturating_sub(1),
            _ => {}
        }
        i += 1;
    }
    None
}

/// Index just past a double-quoted string starting at `at`.
fn skip_string(b: &[u8], at: usize) -> Option<usize> {
    let mut i = at + 1;
    while i < b.len() {
        match b[i] {
            b'\\' => i += 2,
            b'"' => return Some(i + 1),
            _ => i += 1,
        }
    }
    None
}

#[derive(Debug, Clone)]
struct Fun {
    file: String,
    owner: Option<String>,
    name: String,
    params: String,
    body: String,
}

struct Index {
    funs: Vec<Fun>,
    /// `struct Name { field: Type }`
    fields: HashMap<String, HashMap<String, String>>,
    /// `impl Type { fn acc(&self) -> Ret }`
    accessors: HashMap<(String, String), String>,
    by_owner: HashMap<(String, String), Vec<usize>>,
}

fn ident_start(c: u8) -> bool {
    c.is_ascii_alphabetic() || c == b'_'
}
fn ident_char(c: u8) -> bool {
    c.is_ascii_alphanumeric() || c == b'_'
}

/// The identifier beginning at `i`, if any.
fn ident_at(b: &[u8], i: usize) -> Option<(String, usize)> {
    if i >= b.len() || !ident_start(b[i]) {
        return None;
    }
    let mut j = i;
    while j < b.len() && ident_char(b[j]) {
        j += 1;
    }
    Some((String::from_utf8_lossy(&b[i..j]).to_string(), j))
}

/// Index past whitespace from `i`.
fn skip_ws(b: &[u8], mut i: usize) -> usize {
    while i < b.len() && (b[i] as char).is_whitespace() {
        i += 1;
    }
    i
}

/// The first type-looking identifier in a type expression, e.g. `Arc<Database>`
/// yields `Arc`, `&mut TokenStore<'_>` yields `TokenStore`. `Arc`/`Vec`/`Option`
/// and friends are unwrapped so `Arc<Database>` resolves to `Database`.
fn type_head(s: &str) -> Option<String> {
    const WRAPPERS: &[&str] = &["Arc", "Rc", "Box", "Option", "Vec", "RwLock", "Mutex", "Result"];
    let b = s.as_bytes();
    let mut i = 0;
    while i < b.len() {
        if ident_start(b[i]) {
            let (id, j) = ident_at(b, i)?;
            if WRAPPERS.contains(&id.as_str()) {
                i = j;
                continue;
            }
            if id.chars().next().is_some_and(|c| c.is_ascii_uppercase()) {
                return Some(id);
            }
            i = j;
        } else {
            i += 1;
        }
    }
    None
}

/// Parse one file into functions, struct fields and accessor return types.
fn index_file(file: &str, src: &str, idx: &mut Index) {
    let b = src.as_bytes();

    // `impl [Trait for] Type { .. }` spans, so a fn can be attributed to its type.
    let mut impls: Vec<(usize, usize, String)> = Vec::new();
    let mut i = 0usize;
    while let Some(rel) = src[i..].find("impl") {
        let at = i + rel;
        i = at + 4;
        // Must be the keyword, not part of an identifier.
        if at > 0 && ident_char(b[at - 1]) {
            continue;
        }
        if at + 4 < b.len() && ident_char(b[at + 4]) {
            continue;
        }
        let Some(open) = src[at..].find('{').map(|k| at + k) else {
            continue;
        };
        let head = &src[at + 4..open];
        // `impl<..> Trait for Type` -> Type; `impl<..> Type` -> Type.
        let subject = match head.rfind(" for ") {
            Some(k) => &head[k + 5..],
            None => head,
        };
        let Some(ty) = type_head(subject) else { continue };
        let Some(close) = matching(src, open, b'{', b'}') else {
            continue;
        };
        impls.push((open, close, ty));
    }

    // `struct Name { field: Type, .. }`
    let mut i = 0usize;
    while let Some(rel) = src[i..].find("struct ") {
        let at = i + rel;
        i = at + 7;
        if at > 0 && ident_char(b[at - 1]) {
            continue;
        }
        let Some((name, after)) = ident_at(b, skip_ws(b, at + 7)) else {
            continue;
        };
        let Some(open) = src[after..].find('{').map(|k| after + k) else {
            continue;
        };
        // A tuple struct or a `struct X;` has no brace before the next `;`.
        if let Some(semi) = src[after..].find(';').map(|k| after + k) {
            if semi < open {
                continue;
            }
        }
        let Some(close) = matching(src, open, b'{', b'}') else {
            continue;
        };
        let entry = idx.fields.entry(name).or_default();
        for line in src[open + 1..close].split(',') {
            let line = line.trim();
            let Some(colon) = line.find(':') else { continue };
            let fname = line[..colon].trim();
            let fname = fname.rsplit(' ').next().unwrap_or(fname); // drop `pub`
            if fname.is_empty() || !ident_start(fname.as_bytes()[0]) {
                continue;
            }
            if let Some(ty) = type_head(&line[colon + 1..]) {
                entry.insert(fname.to_string(), ty);
            }
        }
    }

    // Functions.
    let mut i = 0usize;
    while let Some(rel) = src[i..].find("fn ") {
        let at = i + rel;
        i = at + 3;
        if at > 0 && ident_char(b[at - 1]) {
            continue;
        }
        let Some((name, after)) = ident_at(b, skip_ws(b, at + 3)) else {
            continue;
        };
        // Parameter list: first `(` after the name (generics may intervene).
        let Some(popen) = src[after..].find('(').map(|k| after + k) else {
            continue;
        };
        let Some(pclose) = matching(src, popen, b'(', b')') else {
            continue;
        };
        let rest = &src[pclose + 1..];
        let bopen_rel = rest.find('{');
        let semi_rel = rest.find(';');
        let Some(bo) = bopen_rel else { continue };
        if let Some(s) = semi_rel {
            if s < bo {
                continue; // a declaration, not a definition
            }
        }
        let body_at = pclose + 1 + bo;
        let Some(bclose) = matching(src, body_at, b'{', b'}') else {
            continue;
        };
        let owner = impls
            .iter()
            .filter(|(o, c, _)| *o < at && at < *c)
            .map(|(_, _, t)| t.clone())
            .next_back();
        // An accessor: `fn acc(&self) -> Ret`.
        if let Some(ref o) = owner {
            let params = &src[popen + 1..pclose];
            if params.trim_start().starts_with("&self") {
                if let Some(arrow) = rest[..bo].find("->") {
                    if let Some(ret) = type_head(&rest[arrow + 2..bo]) {
                        idx.accessors.insert((o.clone(), name.clone()), ret);
                    }
                }
            }
        }
        let f = Fun {
            file: file.to_string(),
            owner: owner.clone(),
            name: name.clone(),
            params: src[popen + 1..pclose].to_string(),
            body: src[body_at..=bclose].to_string(),
        };
        let k = idx.funs.len();
        idx.by_owner
            .entry((owner.unwrap_or_default(), name))
            .or_default()
            .push(k);
        idx.funs.push(f);
        i = body_at;
    }
}

fn build_index(sources: &BTreeMap<String, String>) -> Index {
    let mut idx = Index {
        funs: Vec::new(),
        fields: HashMap::new(),
        accessors: HashMap::new(),
        by_owner: HashMap::new(),
    };
    for (file, src) in sources {
        index_file(file, src, &mut idx);
    }
    idx
}


// ── Binding resolution ─────────────────────────────────────────────────────
//
// A receiver is resolved by TYPE, never by the name `db`. That is what makes
// renaming a receiver — `db` to `database`, or moving it into a differently
// named field — fail to hide a write.

/// `binding path -> type name` for one function: parameters, `let` bindings,
/// and the fields of the type it is implemented on.
fn bindings(idx: &Index, f: &Fun) -> HashMap<String, String> {
    let mut out = HashMap::new();

    // Parameters: `name: &mut Arc<Type>`.
    for part in split_top_level(&f.params, ',') {
        let part = part.trim();
        let Some(colon) = part.find(':') else { continue };
        let name = part[..colon].trim();
        if name.is_empty() || !ident_start(name.as_bytes()[0]) {
            continue;
        }
        if let Some(ty) = type_head(&part[colon + 1..]) {
            out.insert(name.to_string(), ty);
        }
    }

    // Fields of the implementing type: `self.db`, `self.storage`, ...
    if let Some(owner) = &f.owner {
        if let Some(fs) = idx.fields.get(owner) {
            for (fname, ty) in fs {
                out.insert(format!("self.{fname}"), ty.clone());
            }
        }
    }

    // `let x = Type::new(..)`, `let x: Type = ..`, `let x = <expr>.batch()`.
    let b = f.body.as_bytes();
    let mut i = 0usize;
    while let Some(rel) = f.body[i..].find("let ") {
        let at = i + rel;
        i = at + 4;
        if at > 0 && ident_char(b[at - 1]) {
            continue;
        }
        let mut j = skip_ws(b, at + 4);
        if f.body[j..].starts_with("mut ") {
            j = skip_ws(b, j + 4);
        }
        let Some((name, after)) = ident_at(b, j) else {
            continue;
        };
        let stmt_end = f.body[after..]
            .find(';')
            .map(|k| after + k)
            .unwrap_or(f.body.len());
        let stmt = &f.body[after..stmt_end];
        // An explicit annotation wins.
        if let Some(colon) = stmt.find(':') {
            let eq = stmt.find('=').unwrap_or(stmt.len());
            if colon < eq {
                if let Some(ty) = type_head(&stmt[colon + 1..eq]) {
                    out.insert(name.clone(), ty);
                    continue;
                }
            }
        }
        if stmt.contains(".batch()") {
            out.insert(name.clone(), "WriteBatch".to_string());
            continue;
        }
        if let Some(k) = stmt.find("::new(") {
            if let Some(ty) = type_head_backwards(&stmt[..k]) {
                out.insert(name.clone(), ty);
            }
        }
    }
    out
}

/// The type name immediately preceding a `::new(` — the last capitalised
/// identifier in `s`.
fn type_head_backwards(s: &str) -> Option<String> {
    let b = s.as_bytes();
    let mut end = b.len();
    while end > 0 {
        let mut start = end;
        while start > 0 && ident_char(b[start - 1]) {
            start -= 1;
        }
        if start < end {
            let id = &s[start..end];
            if id.chars().next().is_some_and(|c| c.is_ascii_uppercase()) {
                return Some(id.to_string());
            }
        }
        if start == 0 {
            return None;
        }
        end = start - 1;
    }
    None
}

/// Split on `sep` at paren/bracket/angle depth zero.
fn split_top_level(s: &str, sep: char) -> Vec<String> {
    let mut out = Vec::new();
    let mut depth = 0i32;
    let mut cur = String::new();
    for c in s.chars() {
        match c {
            '(' | '[' | '<' => depth += 1,
            ')' | ']' | '>' => depth -= 1,
            _ => {}
        }
        if c == sep && depth == 0 {
            out.push(std::mem::take(&mut cur));
        } else {
            cur.push(c);
        }
    }
    if !cur.trim().is_empty() {
        out.push(cur);
    }
    out
}

// ── Column families ────────────────────────────────────────────────────────

/// A column family a write lands in.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum Cf {
    Named(String),
    /// The family came from a runtime binding — `db.put(cf, ..)` where `cf` was
    /// chosen by an `if`. `execute_accept_assignment_v2` was exactly this, and no
    /// name-based check could see it.
    Variable,
}

/// Every `cf::NAME` / `CF_NAME` named in a body.
fn named_cfs(body: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let b = body.as_bytes();
    let mut i = 0usize;
    while i < b.len() {
        if let Some((id, j)) = ident_at(b, i) {
            let upper = id.len() > 3
                && id
                    .chars()
                    .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_');
            if upper {
                // Byte-wise, not by slicing: `i - 4` can land inside a
                // multi-byte character in a file that has one anywhere.
                let after_cf_mod = i >= 4 && &b[i - 4..i] == b"cf::";
                if after_cf_mod {
                    out.insert(id);
                } else if let Some(rest) = id.strip_prefix("CF_") {
                    out.insert(rest.to_string());
                }
            }
            i = j;
        } else {
            i += 1;
        }
    }
    out
}

// ── The closure ────────────────────────────────────────────────────────────

/// Method calls that mutate a database handle or a write batch.
const RAW_MUTATORS: &[&str] = &["put", "delete", "commit"];

/// Types whose `put`/`delete`/`commit` IS a committed database write.
const DB_TYPES: &[&str] = &["Database", "WriteBatch"];

/// Functions that write the database directly, with the families they touch.
///
/// The receiver is resolved by type, so this sees `database.put(..)`,
/// `self.backing.put(..)` and a batch bound under any name. The families are
/// those named in the body; a body that writes through a runtime-chosen family
/// and names none is recorded as [`Cf::Variable`] rather than dropped.
fn raw_sinks(idx: &Index) -> HashMap<usize, BTreeSet<Cf>> {
    let mut out: HashMap<usize, BTreeSet<Cf>> = HashMap::new();
    for (k, f) in idx.funs.iter().enumerate() {
        if is_sanctioned_publisher(f) {
            continue;
        }
        let binds = bindings(idx, f);
        let mut writes = false;
        for (path, ty) in &binds {
            if !DB_TYPES.contains(&ty.as_str()) {
                continue;
            }
            for m in RAW_MUTATORS {
                if calls_on(&f.body, path, m) {
                    writes = true;
                }
            }
        }
        if !writes {
            continue;
        }
        let named = named_cfs(&f.body);
        let cfs: BTreeSet<Cf> = if named.is_empty() {
            BTreeSet::from([Cf::Variable])
        } else {
            named.into_iter().map(Cf::Named).collect()
        };
        out.insert(k, cfs);
    }
    out
}

/// Does `body` contain `receiver.method(`, tolerating whitespace and line
/// breaks between the receiver, the dot and the name?
///
/// Tolerating them is the point: `self.db\n    .put(cf, &k, &v)` is the single
/// most common shape in this codebase, and matching within one line is how the
/// first version of the raw-syntax guard missed fourteen writes.
fn calls_on(body: &str, receiver: &str, method: &str) -> bool {
    call_offsets(body, receiver, method).next().is_some()
}

/// Byte offsets of every `receiver.method(` in `body`.
fn call_offsets<'a>(
    body: &'a str,
    receiver: &'a str,
    method: &'a str,
) -> impl Iterator<Item = usize> + 'a {
    let mut from = 0usize;
    std::iter::from_fn(move || {
        let b = body.as_bytes();
        loop {
            let rel = body[from..].find(receiver)?;
            let at = from + rel;
            from = at + receiver.len();
            // A whole-token receiver: `db` must not match inside `adb`.
            if at > 0 && ident_char(b[at - 1]) {
                continue;
            }
            let mut i = skip_ws(b, at + receiver.len());
            if b.get(i) != Some(&b'.') {
                continue;
            }
            i = skip_ws(b, i + 1);
            let Some((id, j)) = ident_at(b, i) else {
                continue;
            };
            if id != method {
                continue;
            }
            if b.get(skip_ws(b, j)) != Some(&b'(') {
                continue;
            }
            return Some(at);
        }
    })
}

/// Transitive closure: every function that can reach a raw sink, with the union
/// of the families reachable from it.
///
/// This is the half the raw-syntax guard cannot do. A write moved behind a
/// helper — `fn persist(&self) { self.db.put(..) }`, called from twenty places —
/// leaves the caller with no `db.put` in its body and no reduction in what a
/// block can commit.
fn mutator_closure(idx: &Index, sinks: &HashMap<usize, BTreeSet<Cf>>) -> HashMap<usize, BTreeSet<Cf>> {
    let mut cfs: HashMap<usize, BTreeSet<Cf>> = sinks.clone();
    // `(owner, name) -> callers` is rebuilt each round from resolved edges.
    let mut changed = true;
    let mut rounds = 0;
    while changed {
        changed = false;
        rounds += 1;
        assert!(rounds < 64, "closure did not converge");
        for (k, f) in idx.funs.iter().enumerate() {
            let mut gained: BTreeSet<Cf> = BTreeSet::new();
            for (target, _) in resolved_calls(idx, f) {
                if let Some(t) = cfs.get(&target) {
                    gained.extend(t.iter().cloned());
                }
            }
            if gained.is_empty() {
                continue;
            }
            let entry = cfs.entry(k).or_default();
            let before = entry.len();
            entry.extend(gained);
            if entry.len() != before {
                changed = true;
            }
        }
    }
    cfs
}

/// Calls from `f` that resolve to a known mutator, as `(callee index, offset)`.
///
/// Five shapes, all of which the codebase uses:
///
/// * `binding.method(..)`            — a store held in a `let`, a parameter or a field
/// * `binding.accessor().method(..)` — `store.identity_roots().put(..)`
/// * `Type::new(..).method(..)`      — a store constructed inline
/// * `Type::new(..).accessor().method(..)`
/// * `Type::method(..)` / `self.method(..)` — associated and inherent calls
fn resolved_calls(idx: &Index, f: &Fun) -> Vec<(usize, usize)> {
    let mut out = Vec::new();
    let binds = bindings(idx, f);
    let b = f.body.as_bytes();

    let push = |ty: &str, method: &str, at: usize, out: &mut Vec<(usize, usize)>| {
        if let Some(ks) = idx.by_owner.get(&(ty.to_string(), method.to_string())) {
            for &k in ks {
                out.push((k, at));
            }
        }
    };

    // binding.method( .. ) and binding.accessor().method( .. )
    for (path, ty) in &binds {
        let mut from = 0usize;
        while let Some(rel) = f.body[from..].find(path.as_str()) {
            let at = from + rel;
            from = at + path.len();
            if at > 0 && ident_char(b[at - 1]) {
                continue;
            }
            let mut i = skip_ws(b, at + path.len());
            if b.get(i) != Some(&b'.') {
                continue;
            }
            i = skip_ws(b, i + 1);
            let Some((m1, j)) = ident_at(b, i) else {
                continue;
            };
            let k = skip_ws(b, j);
            if b.get(k) != Some(&b'(') {
                continue;
            }
            push(ty, &m1, at, &mut out);
            // One accessor hop: `binding.acc().method(`.
            let Some(close) = matching(&f.body, k, b'(', b')') else {
                continue;
            };
            if f.body[k + 1..close].trim().is_empty() {
                if let Some(ret) = idx.accessors.get(&(ty.clone(), m1.clone())) {
                    let mut p = skip_ws(b, close + 1);
                    if b.get(p) == Some(&b'.') {
                        p = skip_ws(b, p + 1);
                        if let Some((m2, q)) = ident_at(b, p) {
                            if b.get(skip_ws(b, q)) == Some(&b'(') {
                                push(ret, &m2, at, &mut out);
                            }
                        }
                    }
                }
            }
        }
    }

    // Type::method( .. ), including `Type::new(..).method(..)` chains.
    let mut i = 0usize;
    while i < b.len() {
        let Some((id, j)) = ident_at(b, i) else {
            i += 1;
            continue;
        };
        i = j;
        if !id.chars().next().is_some_and(|c| c.is_ascii_uppercase()) {
            continue;
        }
        if !f.body[j..].starts_with("::") {
            continue;
        }
        let Some((m, k)) = ident_at(b, j + 2) else {
            continue;
        };
        let popen = skip_ws(b, k);
        if b.get(popen) != Some(&b'(') {
            continue;
        }
        // `Self::helper(..)` is the enclosing type. Every migrated subsystem
        // calls its fee path this way — `Self::deduct_fee(state, ..)` — so
        // without this the account debit is unreachable on fourteen arms.
        let id = if id == "Self" {
            match &f.owner {
                Some(o) => o.clone(),
                None => continue,
            }
        } else {
            id
        };
        push(&id, &m, j, &mut out);
        // `Type::new(..)` then `.method(` or `.acc().method(`.
        if m == "new" {
            if let Some(close) = matching(&f.body, popen, b'(', b')') {
                let mut p = skip_ws(b, close + 1);
                if b.get(p) == Some(&b'.') {
                    p = skip_ws(b, p + 1);
                    if let Some((m1, q)) = ident_at(b, p) {
                        let qq = skip_ws(b, q);
                        if b.get(qq) == Some(&b'(') {
                            push(&id, &m1, j, &mut out);
                            if let Some(c2) = matching(&f.body, qq, b'(', b')') {
                                if f.body[qq + 1..c2].trim().is_empty() {
                                    if let Some(ret) = idx.accessors.get(&(id.clone(), m1.clone())) {
                                        let mut r = skip_ws(b, c2 + 1);
                                        if b.get(r) == Some(&b'.') {
                                            r = skip_ws(b, r + 1);
                                            if let Some((m2, s)) = ident_at(b, r) {
                                                if b.get(skip_ws(b, s)) == Some(&b'(') {
                                                    push(ret, &m2, j, &mut out);
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // `path::to::module::func( .. )` — a free function reached by module path.
    // `executor.rs` dispatches governance as
    // `crate::governance_executor::execute(view, ..)`; without this rule the
    // whole Governance arm is unreachable and its nine committed writes vanish
    // from the inventory.
    {
        let mut i = 0usize;
        while i < b.len() {
            let Some((seg, j)) = ident_at(b, i) else {
                i += 1;
                continue;
            };
            i = j;
            if !f.body[j..].starts_with("::") {
                continue;
            }
            let Some((name, k)) = ident_at(b, j + 2) else {
                continue;
            };
            if b.get(skip_ws(b, k)) != Some(&b'(') {
                continue;
            }
            // A lowercase penultimate segment is a module, not a type.
            if seg.chars().next().is_some_and(|c| c.is_ascii_uppercase()) {
                continue;
            }
            if let Some(ks) = idx.by_owner.get(&(String::new(), name.clone())) {
                for &k2 in ks {
                    let stem = idx.funs[k2]
                        .file
                        .rsplit('/')
                        .next()
                        .and_then(|n| n.strip_suffix(".rs"))
                        .unwrap_or("");
                    if stem == seg {
                        out.push((k2, j));
                    }
                }
            }
        }
    }

    // `name( .. )` — a bare call to a free function in the same module.
    // `governance_executor::apply` is reached only this way, and dropping the
    // rule silently removes nine committed writes from the inventory.
    {
        let mut i = 0usize;
        while i < b.len() {
            let Some((id, j)) = ident_at(b, i) else {
                i += 1;
                continue;
            };
            i = j;
            // Not a method call, not a path segment, and followed by `(`.
            let before = b.get(j - id.len() - 1).copied().filter(|_| j > id.len());
            if before == Some(b'.') || before == Some(b':') {
                continue;
            }
            if f.body[j..].starts_with("::") {
                continue;
            }
            if b.get(skip_ws(b, j)) != Some(&b'(') {
                continue;
            }
            if let Some(ks) = idx.by_owner.get(&(String::new(), id.clone())) {
                for &k in ks {
                    if idx.funs[k].file == f.file {
                        out.push((k, j - id.len()));
                    }
                }
            }
        }
    }

    // `self.method( .. )` — inherent calls, which carry helper indirection.
    if let Some(owner) = &f.owner {
        for at in call_offsets_any(&f.body, "self") {
            let mut p = skip_ws(b, at + 4);
            if b.get(p) != Some(&b'.') {
                continue;
            }
            p = skip_ws(b, p + 1);
            if let Some((m, q)) = ident_at(b, p) {
                if b.get(skip_ws(b, q)) == Some(&b'(') {
                    push(owner, &m, at, &mut out);
                }
            }
        }
    }
    out
}

/// Offsets of every whole-token occurrence of `tok` in `body`.
fn call_offsets_any<'a>(body: &'a str, tok: &'a str) -> impl Iterator<Item = usize> + 'a {
    let mut from = 0usize;
    std::iter::from_fn(move || {
        let b = body.as_bytes();
        loop {
            let rel = body[from..].find(tok)?;
            let at = from + rel;
            from = at + tok.len();
            if at > 0 && ident_char(b[at - 1]) {
                continue;
            }
            if b.get(at + tok.len()).is_some_and(|&c| ident_char(c)) {
                continue;
            }
            return Some(at);
        }
    })
}

// ── Classification ─────────────────────────────────────────────────────────

// ── Reachability ───────────────────────────────────────────────────────────
//
// A source inventory is not an execution surface. The first version of this
// file scanned every application function and defaulted `crates/state/src` to
// "execution", which counted a mutating helper nothing calls exactly the same
// as one the dispatcher reaches on every block. That is a conservative
// inventory, useful for scoping and wrong for a guard: it cannot tell a write
// that matters from one that does not, and it would keep passing while dead
// code was deleted and live code was added.
//
// Sites are now rooted. Each class below names ENTRY POINTS, the call graph is
// walked forward from them, and a write counts only if the function containing
// it is reachable from a root.

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Class {
    /// Reachable from `BlockExecutor::execute_block`. Counted in the ledger.
    Execution,
    /// Reachable only from `StateManager::init_from_genesis` — no block exists
    /// to abandon.
    Genesis,
    /// Reachable only from `StateManager::revert_block_state_diffs` — the
    /// committed write that unwinds an already-published block.
    ReorgUndo,
    /// The node's own storage surface: blocks, transactions, receipts, their
    /// indexes, validator sets, pruning. Not application state.
    ChainStorage,
    /// Fast-sync restore, outside consensus.
    Snapshot,
    /// RPC and mempool: diagnostics and admission, which answer about the
    /// PUBLISHED chain. A committed read here is correct, and a committed write
    /// would not be — there are none.
    RpcAndMempool,
    /// An operator CLI that changes application state outside consensus.
    OperatorTooling,
    /// Inside the storage or runtime library — these ARE the writes, and
    /// counting their internal calls would double-count every one.
    Library,
}

/// `(class, file, owner-or-empty, fn)` entry points. A function is classified
/// by the FIRST class whose roots reach it, in this order, so a helper shared
/// between execution and genesis counts as execution.
const ROOTS: &[(Class, &str, &str, &str)] = &[
    (Class::Execution, "crates/state/src/executor.rs", "BlockExecutor", "execute_block"),
    (Class::Genesis, "crates/state/src/state.rs", "StateManager", "init_from_genesis"),
    (Class::ReorgUndo, "crates/state/src/state.rs", "StateManager", "revert_block_state_diffs"),
    (Class::OperatorTooling, "crates/node/src/main.rs", "", "main"),
];

/// Whole crates that are an entry surface for RPC and mempool admission.
const RPC_FILES: &[(Class, &str)] = &[
    (Class::RpcAndMempool, "crates/rpc/src/"),
    (Class::RpcAndMempool, "crates/state/src/mempool.rs"),
];

/// Whole files that are entry surfaces in their own right: the node's consensus
/// and networking layers, the pruner, and fast-sync restore. Rooting these at a
/// single function would miss the several the binary calls; what matters is
/// that none of them is execution, which the ordering above already decides.
const ROOT_FILES: &[(Class, &str)] = &[
    (Class::ChainStorage, "crates/consensus/src/"),
    (Class::ChainStorage, "crates/p2p/src/"),
    (Class::ChainStorage, "crates/storage/src/pruner.rs"),
    (Class::ChainStorage, "crates/node/src/node.rs"),
    (Class::Snapshot, "crates/state/src/snapshot.rs"),
];

/// Functions reachable from `roots`, following every resolvable call.
fn reachable(idx: &Index, roots: &[usize]) -> HashSet<usize> {
    let mut seen: HashSet<usize> = HashSet::new();
    let mut stack: Vec<usize> = roots.to_vec();
    while let Some(k) = stack.pop() {
        if !seen.insert(k) {
            continue;
        }
        for (c, _) in resolved_calls(idx, &idx.funs[k]) {
            if !seen.contains(&c) {
                stack.push(c);
            }
        }
    }
    seen
}

fn root_indices(idx: &Index, class: Class) -> Vec<usize> {
    let mut out = Vec::new();
    for (c, file, owner, name) in ROOTS {
        if *c != class {
            continue;
        }
        for (k, f) in idx.funs.iter().enumerate() {
            if f.file == *file
                && f.name == *name
                && f.owner.as_deref().unwrap_or("") == *owner
            {
                out.push(k);
            }
        }
    }
    for (c, prefix) in ROOT_FILES.iter().chain(RPC_FILES.iter()) {
        if *c != class {
            continue;
        }
        for (k, f) in idx.funs.iter().enumerate() {
            if f.file.starts_with(prefix) {
                out.push(k);
            }
        }
    }
    out
}

/// Classify every function by which entry surface reaches it.
fn classify_all(idx: &Index) -> Vec<Option<Class>> {
    let mut out = vec![None; idx.funs.len()];
    // Library first, by location: those bodies are the writes themselves.
    for (k, f) in idx.funs.iter().enumerate() {
        if f.file.starts_with("crates/storage/src") || f.file.starts_with("crates/sumc-runtime/src")
        {
            out[k] = Some(Class::Library);
        }
    }
    // Order matters: a helper shared between classes takes the first that
    // reaches it. Execution first because it is what the ledger is about;
    // chain storage before operator tooling because `main` also boots the node,
    // and booting is not tooling.
    for class in [
        Class::Execution,
        Class::Genesis,
        Class::ReorgUndo,
        Class::ChainStorage,
        Class::Snapshot,
        Class::RpcAndMempool,
        Class::OperatorTooling,
    ] {
        let roots = root_indices(idx, class);
        for k in reachable(idx, &roots) {
            if out[k].is_none() {
                out[k] = Some(class);
            }
        }
    }
    out
}

// ── Sites ──────────────────────────────────────────────────────────────────

/// One committed write, keyed by identity rather than by position.
///
/// A count alone is not a guard: removing one write and adding another in the
/// same file leaves the total unchanged, and swapping which column family a
/// write targets leaves the family count unchanged. Both are real changes to
/// what an unaccepted block can commit, and both used to pass. The manifest
/// keys caller, callee and families, so either one moves a row.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct Site {
    file: String,
    /// `Owner::name`, or `name` for a free function. Stable across
    /// reformatting; changes when the write moves to a different function.
    caller: String,
    /// The library function actually reached: `StateStore::put_account`.
    callee: String,
    cfs: BTreeSet<Cf>,
    class: Class,
    /// How many times this caller reaches this callee.
    count: usize,
}

fn qualified(f: &Fun) -> String {
    match &f.owner {
        Some(o) => format!("{o}::{}", f.name),
        None => f.name.clone(),
    }
}

fn cf_list(cfs: &BTreeSet<Cf>) -> String {
    cfs.iter()
        .map(|c| match c {
            Cf::Named(n) => n.clone(),
            Cf::Variable => "<variable>".to_string(),
        })
        .collect::<Vec<_>>()
        .join("+")
}

/// Every call site where application code reaches into the storage or runtime
/// library and commits, with the class of entry surface that can reach it.
///
/// The crossing is what counts, not every hop on the way to it: a write moved
/// behind a private helper is still exactly one site, at the helper's line.
fn all_sites(idx: &Index, closure: &HashMap<usize, BTreeSet<Cf>>) -> Vec<Site> {
    let classes = classify_all(idx);
    type Key = (String, String, String);
    type Val = (Class, BTreeSet<Cf>, usize);
    let mut acc: BTreeMap<Key, Val> = BTreeMap::new();
    for (k, f) in idx.funs.iter().enumerate() {
        let Some(class) = classes[k] else { continue };
        if class == Class::Library {
            continue;
        }
        for (target, _at) in resolved_calls(idx, f) {
            if classes[target] != Some(Class::Library) {
                continue; // application-to-application indirection, not a crossing
            }
            let Some(cfs) = closure.get(&target) else {
                continue;
            };
            let key = (f.file.clone(), qualified(f), qualified(&idx.funs[target]));
            let e = acc
                .entry(key)
                .or_insert((class, BTreeSet::new(), 0));
            e.1.extend(cfs.iter().cloned());
            e.2 += 1;
        }
    }
    acc.into_iter()
        .map(|((file, caller, callee), (class, cfs, count))| Site {
            file,
            caller,
            callee,
            cfs,
            class,
            count,
        })
        .collect()
}

/// Run the whole analysis over an arbitrary source map. Split out so the
/// resolution rules can be exercised against synthetic sources — a probe file
/// written into the real tree would be visible to every other test while it
/// runs, which is a race, not a test.
fn analyse_sources(sources: BTreeMap<String, String>) -> Vec<Site> {
    let prepared: BTreeMap<String, String> =
        sources.into_iter().map(|(k, v)| (k, prepare(&v))).collect();
    let idx = build_index(&prepared);
    let sinks = raw_sinks(&idx);
    let closure = mutator_closure(&idx, &sinks);
    all_sites(&idx, &closure)
}

fn analyse() -> Vec<Site> {
    let idx = build_index(&production_sources());
    let sinks = raw_sinks(&idx);
    let closure = mutator_closure(&idx, &sinks);
    all_sites(&idx, &closure)
}

fn execution_of(sites: &[Site]) -> Vec<&Site> {
    sites.iter().filter(|s| s.class == Class::Execution).collect()
}

/// Total occurrences, not rows: a caller reaching the same mutator twice is two
/// places to fix.
fn execution_total(sites: &[Site]) -> usize {
    execution_of(sites).iter().map(|s| s.count).sum()
}

// ── The dispatch match ─────────────────────────────────────────────────────

/// `(payload variant, arm body)` for every arm of every `match` on a
/// `TxPayload`, in `executor.rs`.
///
/// Arm POSITION, not textual occurrence. The first version collected every
/// `TxPayload::` substring in the file, which meant a mention inside an arm
/// body, a helper, or a type annotation read as a dispatch arm — and a real arm
/// could be added without the count moving if some other mention disappeared in
/// the same commit. Arms are found at brace-depth 1 of a `match` block, which
/// is the only place a pattern can be.
fn dispatch_arms(src: &str) -> Vec<(String, String)> {
    let b = src.as_bytes();
    let mut out = Vec::new();
    let mut i = 0usize;
    while let Some(rel) = src[i..].find("match") {
        let at = i + rel;
        i = at + 5;
        if at > 0 && ident_char(b[at - 1]) {
            continue;
        }
        if b.get(at + 5).is_some_and(|&c| ident_char(c)) {
            continue;
        }
        let Some(open) = src[at..].find('{').map(|k| at + k) else {
            continue;
        };
        let Some(close) = matching(src, open, b'{', b'}') else {
            continue;
        };
        if !src[open..close].contains("TxPayload::") {
            continue;
        }
        // Walk the match body, tracking depth; a pattern sits at depth 1.
        let mut depth = 0i32;
        let mut j = open;
        while j < close {
            match b[j] {
                b'{' | b'(' | b'[' => depth += 1,
                b'}' | b')' | b']' => depth -= 1,
                b'"' => {
                    if let Some(k) = skip_string(b, j) {
                        j = k;
                        continue;
                    }
                }
                _ => {}
            }
            if depth == 1 && src[j..].starts_with("TxPayload::") {
                let after = j + "TxPayload::".len();
                if let Some((name, k)) = ident_at(b, after) {
                    // The arm's body runs from `=>` to the end of the arm.
                    let body = src[k..close]
                        .find("=>")
                        .map(|d| {
                            let from = k + d + 2;
                            let rest = &src[from..close];
                            let end = rest
                                .find('{')
                                .and_then(|o| matching(rest, o, b'{', b'}').map(|e| e + 1))
                                .unwrap_or_else(|| rest.find(',').map(|c| c + 1).unwrap_or(rest.len()));
                            rest[..end].to_string()
                        })
                        .unwrap_or_default();
                    out.push((name, body));
                }
            }
            j += 1;
        }
        // Continue from just inside this match, not past it: the real V2
        // dispatch is an INNER match on `v2_tx.payload`, nested one arm deep
        // inside the outer match on the transaction envelope. Skipping to
        // `close` found only the legacy V1 arms — thirty declared families,
        // and the guard was reading the fail-closed stubs.
        i = open + 1;
    }
    out
}

// ═══════════════════════════════════════════════════════════════════════════
// THE GUARDS
// ═══════════════════════════════════════════════════════════════════════════

#[test]
#[ignore = "reporting aid: run with --ignored to regenerate MANIFEST"]
fn dump_manifest() {
    let sites = analyse();
    for s in execution_of(&sites) {
        println!(
            "    (\"{}\", \"{}\", \"{}\", \"{}\", {}),",
            s.file,
            s.caller,
            s.callee,
            cf_list(&s.cfs),
            s.count
        );
    }
    let mut per_class: BTreeMap<Class, usize> = BTreeMap::new();
    for s in &sites {
        *per_class.entry(s.class).or_default() += s.count;
    }
    eprintln!("rows={} occurrences={}", execution_of(&sites).len(), execution_total(&sites));
    let cfs: BTreeSet<&Cf> = execution_of(&sites).iter().flat_map(|s| s.cfs.iter()).collect();
    eprintln!("cfs={}", cfs.len());
    for (c, n) in &per_class {
        eprintln!("  {c:?}: {n}");
    }
}

/// The manifest is exact: every committed execution write is declared, and
/// nothing declared has silently moved.
///
/// Three ways to fail, each a different mistake:
///
/// * a row the manifest does not have — a new committed write, or one that
///   moved to a different function or a different family;
/// * a row the manifest has and the tree does not — progress, or a rename;
/// * the same row with a different occurrence count.
#[test]
fn the_committed_write_manifest_is_exact() {
    let sites = analyse();
    let found: BTreeMap<(String, String, String), (String, usize)> = execution_of(&sites)
        .into_iter()
        .map(|s| {
            (
                (s.file.clone(), s.caller.clone(), s.callee.clone()),
                (cf_list(&s.cfs), s.count),
            )
        })
        .collect();
    let declared: BTreeMap<(String, String, String), (String, usize)> = MANIFEST
        .iter()
        .map(|(f, caller, callee, cfs, n)| {
            (
                (f.to_string(), caller.to_string(), callee.to_string()),
                (cfs.to_string(), *n),
            )
        })
        .collect();
    assert_eq!(
        declared.len(),
        MANIFEST.len(),
        "the manifest has duplicate (file, caller, callee) keys"
    );

    let mut added = Vec::new();
    let mut moved = Vec::new();
    for (key, (cfs, n)) in &found {
        match declared.get(key) {
            None => added.push(format!(
                "    (\"{}\", \"{}\", \"{}\", \"{cfs}\", {n}),",
                key.0, key.1, key.2
            )),
            Some((dcfs, _)) if dcfs != cfs => moved.push(format!(
                "  {} {} -> {}: families were {dcfs}, are now {cfs}",
                key.0, key.1, key.2
            )),
            Some((_, dn)) if dn != n => moved.push(format!(
                "  {} {} -> {}: {dn} occurrence(s) declared, {n} found",
                key.0, key.1, key.2
            )),
            Some(_) => {}
        }
    }
    let removed: Vec<String> = declared
        .keys()
        .filter(|k| !found.contains_key(*k))
        .map(|k| format!("  {} {} -> {}", k.0, k.1, k.2))
        .collect();

    assert!(
        added.is_empty(),
        "block execution can commit in places the manifest does not declare. \
         Each row below is a write an unaccepted block can make. Route it \
         through `ExecutionView`; do not paste the rows in:\n{}",
        added.join("\n")
    );
    assert!(
        moved.is_empty(),
        "declared writes changed shape. A different callee, or a different \
         column family, is a different write — even when the totals \
         match:\n{}",
        moved.join("\n")
    );
    assert!(
        removed.is_empty(),
        "these declared writes are gone — progress, if they were migrated, or a \
         rename this file has to follow. Remove the rows:\n{}",
        removed.join("\n")
    );

    let total: usize = found.values().map(|(_, n)| *n).sum();
    assert_eq!(total, MANIFEST_OCCURRENCES, "occurrence total changed");
}

/// Every mutating function is either reachable from an entry point or declared
/// unreachable.
///
/// Rooting is what makes this an execution surface rather than a source
/// listing — and it introduces a way to hide: a write the resolver cannot
/// reach simply vanishes. This closes that.
#[test]
fn unreached_mutators_are_declared() {
    let idx = build_index(&production_sources());
    let sinks = raw_sinks(&idx);
    let closure = mutator_closure(&idx, &sinks);
    let classes = classify_all(&idx);

    let mut unreached = BTreeSet::new();
    for (k, f) in idx.funs.iter().enumerate() {
        if classes[k].is_some() {
            continue;
        }
        let crossings = resolved_calls(&idx, f)
            .into_iter()
            .filter(|(t, _)| classes[*t] == Some(Class::Library) && closure.contains_key(t))
            .count();
        if crossings > 0 {
            unreached.insert((f.file.clone(), qualified(f)));
        }
    }
    let declared: BTreeSet<(String, String)> = UNREACHED_MUTATORS
        .iter()
        .map(|(f, n, _)| (f.to_string(), n.to_string()))
        .collect();

    let extra: Vec<_> = unreached.difference(&declared).collect();
    assert!(
        extra.is_empty(),
        "these functions commit application state and no entry point reaches \
         them: {extra:?}. Either they are dead — delete them — or this file \
         cannot resolve the call that reaches them, and the manifest is short \
         by exactly that much. Check which before declaring one."
    );
    let gone: Vec<_> = declared.difference(&unreached).collect();
    assert!(
        gone.is_empty(),
        "these are declared unreachable but are now reached, or are gone: \
         {gone:?}. If they became reachable, their writes belong in the manifest."
    );
}

/// The number of application column families a block can still commit to.
#[test]
fn the_committed_column_family_count_does_not_grow() {
    let sites = analyse();
    let cfs: BTreeSet<&Cf> = sites
        .iter()
        .filter(|s| s.class == Class::Execution)
        .flat_map(|s| s.cfs.iter())
        .collect();
    assert!(
        cfs.len() <= LEDGER_CF_COUNT,
        "block execution can now commit to {} column families, up from {}. The \
         application journal has to cover every one of them.",
        cfs.len(),
        LEDGER_CF_COUNT
    );
    assert_eq!(
        cfs.len(),
        LEDGER_CF_COUNT,
        "fewer families are committed than recorded — lower LEDGER_CF_COUNT"
    );
}

/// Non-execution writes are classified, not ignored.
///
/// Each of these is a legitimate committed write, and each has a reason that
/// does not generalise. Pinning the counts means a new writer cannot arrive
/// wearing one of these labels without the number moving.
#[test]
fn non_execution_paths_are_classified() {
    /// `(class, sites, why it is not execution)`
    const EXPECTED: &[(Class, usize, &str)] = &[
        (Class::Genesis, 2, "no block exists to abandon: account prefunding and the empty archive snapshot"),
        (
            Class::ReorgUndo,
            0,
            "ZERO here on purpose. The revert writes a raw `db.batch()` in \
             state.rs rather than calling a store, so it is one of the three \
             sites the RAW guard next door counts and none that this one does. \
             The two classes are complementary, and this zero says so — it is \
             not an absence of coverage.",
        ),
        (Class::ChainStorage, 18, "blocks, transactions, receipts, their indexes, validator sets, pruning — not application state"),
        (Class::Snapshot, 1, "fast-sync restore, outside consensus"),
        (Class::OperatorTooling, 7, "see operator_tooling_writes_are_declared_deployment_blockers"),
    ];
    let sites = analyse();
    let mut counted: BTreeMap<Class, usize> = BTreeMap::new();
    for s in &sites {
        *counted.entry(s.class).or_default() += s.count;
    }
    for (class, expected, why) in EXPECTED {
        let found = counted.get(class).copied().unwrap_or(0);
        assert_eq!(
            found, *expected,
            "{class:?} now has {found} committed write sites, recorded {expected}.\n  \
             this class is excluded from the execution ledger because: {why}"
        );
    }
    let unexpected: Vec<_> = counted
        .keys()
        .filter(|c| {
            **c != Class::Execution && !EXPECTED.iter().any(|(e, _, _)| e == *c)
        })
        .collect();
    assert!(
        unexpected.is_empty(),
        "these write classes are not declared: {unexpected:?}"
    );
}

/// Every dispatcher arm is declared, with where it writes.
///
/// The executor's `TxPayload` match is the entire transaction surface. A new arm
/// arrives with a new write surface, and this fails until someone says which
/// kind it is.
#[test]
fn every_dispatcher_arm_is_declared() {
    let root = workspace_root();
    let src = prepare(
        &std::fs::read_to_string(root.join("crates/state/src/executor.rs"))
            .expect("read executor.rs"),
    );
    let found: BTreeSet<String> = dispatch_arms(&src).into_iter().map(|(n, _)| n).collect();
    let declared: BTreeSet<String> = ARMS.iter().map(|(n, _, _)| n.to_string()).collect();

    let missing: Vec<_> = found.difference(&declared).collect();
    let stale: Vec<_> = declared.difference(&found).collect();
    assert!(
        missing.is_empty(),
        "the executor dispatches transaction families that are not declared \
         here: {missing:?}. Add each to ARMS saying whether it writes through \
         the overlay, commits, or both — an undeclared arm is an unmeasured \
         write surface."
    );
    assert!(
        stale.is_empty(),
        "ARMS lists families the executor no longer dispatches: {stale:?}"
    );

    let overlay = ARMS.iter().filter(|(_, k, _)| *k == ArmKind::Overlay).count();
    let committed = ARMS.iter().filter(|(_, k, _)| *k == ArmKind::Committed).count();
    let mixed = ARMS.iter().filter(|(_, k, _)| *k == ArmKind::Mixed).count();
    assert_eq!(
        (overlay, committed, mixed),
        (20, 10, 0),
        "the overlay/committed/mixed split changed. Moving an arm from \
         Committed to Overlay is progress — update this and the manifest \
         together; any other movement is not."
    );
    assert_eq!(ARMS.len(), 30, "arm count changed");
}

/// Each arm's declared kind is DERIVED from what that arm can reach.
///
/// The `Transfer` row rotted exactly the way a hand-written label does. The
/// account migration moved its only writes onto the candidate and the label
/// stayed `Committed`, because nothing compared it to the source. The split
/// assertion above did not notice: a stale row keeps the aggregate
/// self-consistent whether or not any individual row is true. Counting is not
/// checking — the same lesson the manifest learned when it went from totals to
/// identities.
///
/// So the kind is computed. An arm is `Committed` when it can reach a function
/// the manifest records as committing during execution, and `Overlay` when it
/// can reach none. `Mixed` says the arm takes BOTH a view and a committed
/// handle — a statement about its signature, not its reach — so it is checked
/// like `Committed`.
///
/// Both dispatch matches are unioned per payload. Each family appears twice,
/// once in the V2 dispatch and once as a V1 fail-closed stub that returns an
/// error and reaches nothing; scoring them separately would call every family
/// Overlay on the strength of its stub.
#[test]
fn each_arms_kind_is_derived_from_what_it_can_reach() {
    /// Arms whose commit the manifest cannot attribute to a state-crate caller.
    ///
    /// Empty now. It held ContractCall and ContractDeploy, whose rows are
    /// written from `sumc-runtime` — which [`classify_all`] marks `Library` by
    /// location, so no `Site` was ever keyed to a function in `crates/state`.
    ///
    /// Their migration is real but this file cannot witness it, in either
    /// direction: the rows were never here to leave, and declaring the arms
    /// `Overlay` would have passed this guard before the migration as readily
    /// as after. The proof lives where the seam does —
    /// `sumc-runtime/tests/contract_commit_point.rs` pins that
    /// `ContractStorage` calls only the READ half of its backend trait, and
    /// `contract_reorg_and_root.rs` pins that an abandoned deploy leaves no
    /// contract row. Emptying this list records that nothing is excused any
    /// more; it does not, by itself, prove anything.
    const COMMITS_OUTSIDE_THE_MANIFEST: &[(&str, &str)] = &[];

    let idx = build_index(&production_sources());

    // Every function that commits during block execution, as the manifest
    // identifies it: `(file, "Owner::name")`.
    let sites = analyse();
    let writers: BTreeSet<(String, String)> = execution_of(&sites)
        .into_iter()
        .map(|s| (s.file.clone(), s.caller.clone()))
        .collect();
    let committing: BTreeSet<usize> = idx
        .funs
        .iter()
        .enumerate()
        .filter(|(_, f)| writers.contains(&(f.file.clone(), qualified(f))))
        .map(|(k, _)| k)
        .collect();
    assert_eq!(
        committing.len(),
        writers.len(),
        "a committed execution writer did not resolve back to an indexed \
         function, so the derivation below would under-report reach"
    );

    let src = prepare(
        &std::fs::read_to_string(workspace_root().join("crates/state/src/executor.rs"))
            .expect("read executor.rs"),
    );
    let dispatch = idx
        .funs
        .iter()
        .find(|f| {
            f.file == "crates/state/src/executor.rs" && f.name == "execute_tx_with_validators"
        })
        .expect("the dispatch function");

    let mut reached: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for (payload, body) in dispatch_arms(&src) {
        let arm = Fun {
            file: dispatch.file.clone(),
            owner: dispatch.owner.clone(),
            name: format!("arm::{payload}"),
            params: dispatch.params.clone(),
            body,
        };
        let roots: Vec<usize> = resolved_calls(&idx, &arm).into_iter().map(|(k, _)| k).collect();
        let seen = reachable(&idx, &roots);
        let entry = reached.entry(payload).or_default();
        for k in seen.iter().filter(|k| committing.contains(k)) {
            entry.insert(qualified(&idx.funs[*k]));
        }
    }
    assert!(
        !reached.is_empty(),
        "no arm bodies were analysed — the derivation proved nothing"
    );

    let excused: BTreeSet<&str> = COMMITS_OUTSIDE_THE_MANIFEST.iter().map(|(a, _)| *a).collect();
    let mut wrong = Vec::new();
    for (payload, kind, _) in ARMS {
        let Some(hits) = reached.get(*payload) else {
            continue; // every_dispatcher_arm_is_declared owns that failure
        };
        let declared_commits = matches!(kind, ArmKind::Committed | ArmKind::Mixed);
        match (declared_commits, hits.is_empty()) {
            (true, true) if excused.contains(payload) => {}
            (true, true) => wrong.push(format!(
                "  {payload}: declared {kind:?} but reaches no committed write. \
                 If it stopped committing, make it Overlay and drop its manifest rows."
            )),
            (false, false) => wrong.push(format!(
                "  {payload}: declared {kind:?} but reaches {hits:?}"
            )),
            _ => {}
        }
    }
    let unneeded: Vec<&str> = COMMITS_OUTSIDE_THE_MANIFEST
        .iter()
        .filter(|(a, _)| reached.get(*a).is_some_and(|h| !h.is_empty()))
        .map(|(a, _)| *a)
        .collect();
    assert!(
        unneeded.is_empty(),
        "these arms no longer need their COMMITS_OUTSIDE_THE_MANIFEST excuse — \
         the manifest attributes their writes now: {unneeded:?}"
    );
    assert!(
        wrong.is_empty(),
        "an arm's declared kind does not match what it can reach:\n{}",
        wrong.join("\n")
    );
}

/// Every arm debits an account, and no arm commits one.
///
/// The claim this replaces was that every arm's fee path writes `cf::STATE`
/// through `StateManager::put_account` — true before the account migration, and
/// the reason accounts went first. The write did not go away; it moved. So the
/// test measures BOTH halves now, which is what makes it a migration proof
/// rather than a restatement:
///
/// * every arm still reaches the account write, now `v_put_account`, which
///   stages into the block's candidate;
/// * NO arm reaches `StateStore::put_account`, which commits.
///
/// Three arms reach neither, and are declared: they are free.
#[test]
fn every_arm_stages_its_account_write_and_none_commits_one() {
    /// Arms that debit no account at all, with why.
    const NO_ACCOUNT_WRITE: &[(&str, &str)] = &[
        (
            "ComputePool",
            "gate-closed seam: Failed(0) with fee_paid 0 and no state mutation, \
             byte-identical to a chain that never saw the tx (#130)",
        ),
        (
            "BeaconSetup",
            "fee_paid 0 on BOTH paths — the dormant fail-closed seam and the \
             gate-open runtime (#127). Beacon ops are never charged.",
        ),
        ("BeaconSigning", "fee_paid 0 on both paths, as BeaconSetup"),
    ];

    let idx = build_index(&production_sources());
    let find = |file: &str, owner: &str, name: &str| -> usize {
        let hits: Vec<usize> = idx
            .funs
            .iter()
            .enumerate()
            .filter(|(_, f)| {
                f.file == file && f.owner.as_deref() == Some(owner) && f.name == name
            })
            .map(|(k, _)| k)
            .collect();
        assert_eq!(hits.len(), 1, "expected exactly one {owner}::{name}");
        hits[0]
    };
    let staged = find("crates/state/src/state.rs", "StateManager", "v_put_account");
    let committed = find("crates/storage/src/schema.rs", "StateStore", "put_account");

    let src = prepare(
        &std::fs::read_to_string(workspace_root().join("crates/state/src/executor.rs"))
            .expect("read executor.rs"),
    );
    let dispatch = idx
        .funs
        .iter()
        .find(|f| {
            f.file == "crates/state/src/executor.rs" && f.name == "execute_tx_with_validators"
        })
        .expect("the dispatch function");

    let mut stages: BTreeSet<String> = BTreeSet::new();
    let mut commits: BTreeSet<String> = BTreeSet::new();
    for (payload, body) in dispatch_arms(&src) {
        if body.trim().is_empty() {
            continue;
        }
        let arm = Fun {
            file: dispatch.file.clone(),
            owner: dispatch.owner.clone(),
            name: format!("arm::{payload}"),
            params: dispatch.params.clone(),
            body,
        };
        let roots: Vec<usize> = resolved_calls(&idx, &arm).into_iter().map(|(k, _)| k).collect();
        let seen = reachable(&idx, &roots);
        if seen.contains(&staged) {
            stages.insert(payload.clone());
        }
        if seen.contains(&committed) {
            commits.insert(payload);
        }
    }

    assert!(
        commits.is_empty(),
        "these arms can still COMMIT an account row during execution: {commits:?}. \
         A block that is never accepted would move those balances."
    );

    let all: BTreeSet<String> = ARMS.iter().map(|(n, _, _)| n.to_string()).collect();
    let declared: BTreeSet<String> =
        NO_ACCOUNT_WRITE.iter().map(|(n, _)| n.to_string()).collect();
    let silent: Vec<_> = all
        .difference(&stages)
        .filter(|n| !declared.contains(*n))
        .collect();
    assert!(
        silent.is_empty(),
        "{ACCOUNT_WRITE_IS_UNIVERSAL}\n  but these arms reach neither the staged \
         account write nor a committed one: {silent:?}. Either they are free — \
         declare each in NO_ACCOUNT_WRITE with the reason — or this file cannot \
         resolve their fee path."
    );
    let wrong: Vec<_> = declared.intersection(&stages).collect();
    assert!(
        wrong.is_empty(),
        "these arms are declared to debit no account, but do: {wrong:?}"
    );
}

/// Dead column families stay out of the ledger and out of the journal.
#[test]
fn dead_column_families_are_written_by_nothing() {
    let sources = production_sources();
    for dead in DEAD_COLUMN_FAMILIES {
        let mut seen_outside_registry = Vec::new();
        for (file, src) in &sources {
            if file == "crates/storage/src/db.rs" {
                continue;
            }
            if named_cfs(src).contains(*dead) {
                seen_outside_registry.push(file.as_str());
            }
        }
        assert!(
            seen_outside_registry.is_empty(),
            "cf::{dead} is recorded as dead schema but is referenced in \
             {seen_outside_registry:?}. Either it is alive — remove it from \
             DEAD_COLUMN_FAMILIES and account for its writes — or the \
             reference is a mistake. It must not enter the journal allowlist \
             while it is dead."
        );
    }
}

/// The operator import that changes application state outside consensus.
///
/// `node/src/main.rs` carries a recovery command that writes messaging public
/// keys straight into the database, with a comment naming the divergence it
/// exists to repair. It is not execution, not genesis, and not chain storage:
/// it is a human changing consensus-relevant state with no block, no candidate
/// and no journal, on one node.
///
/// That makes it a deployment blocker in its own right, independent of the
/// journal work — a node that runs it diverges from every node that did not.
/// This test pins it so it cannot be quietly reclassified as routine tooling.
#[test]
fn operator_tooling_writes_are_declared_deployment_blockers() {
    let sites = analyse();
    let operator: Vec<&Site> = sites
        .iter()
        .filter(|s| s.class == Class::OperatorTooling)
        .collect();
    assert!(
        !operator.is_empty(),
        "the operator-tooling write disappeared. If it was removed, delete this \
         test and the deployment blocker with it."
    );
    let families: BTreeSet<&Cf> = operator.iter().flat_map(|s| s.cfs.iter()).collect();
    let messaging = families
        .iter()
        .any(|c| matches!(c, Cf::Named(n) if n.starts_with("MESSAGING_")));
    assert!(
        messaging,
        "the operator recovery path no longer writes a MESSAGING_* family. \
         Update this test to name what it writes now; do not delete it."
    );
    for s in &operator {
        assert_eq!(
            s.file, "crates/node/src/main.rs",
            "a second operator-tooling writer appeared at {}:{}. Every one of \
             these changes application state outside consensus and blocks \
             deployment.",
            s.file, s.caller
        );
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// ANALYSER SELF-TESTS
// ═══════════════════════════════════════════════════════════════════════════
//
// A ledger is only worth its resolution rules. Each test below was written by
// BREAKING the rule it covers and watching the count fall to zero — the shapes
// here are the ones that would otherwise let a committed write hide, and the
// first four are the shapes that made 317 sites invisible to a check that knew
// only `db.put`.

/// A minimal storage library: one store type whose `put` writes a family.
fn fake_library() -> (String, String) {
    (
        "crates/storage/src/schema.rs".to_string(),
        r#"
pub struct StateStore<'a> { db: &'a Database }
impl<'a> StateStore<'a> {
    pub fn new(db: &'a Database) -> Self { Self { db } }
    pub fn put_account(&self, k: &[u8], v: &[u8]) -> Result<()> {
        self.db.put(cf::STATE, k, v)
    }
}
"#
        .to_string(),
    )
}

/// A root, because the inventory is rooted.
///
/// Every fixture below needs one: without a `BlockExecutor::execute_block` that
/// reaches the probe, nothing is execution and every count is zero — which is
/// exactly the behaviour [`an_unreachable_mutating_helper_is_not_counted`]
/// depends on.
const ROOT_HARNESS: &str = r#"
pub struct BlockExecutor { db: Arc<Database> }
impl BlockExecutor {
    pub fn execute_block(&self, db: &Database) -> Result<()> {
        Probe::execute(db)
    }
}
"#;

fn sources_with(caller: &str) -> BTreeMap<String, String> {
    with_root(BTreeMap::from([
        fake_library(),
        ("crates/state/src/probe_executor.rs".to_string(), caller.to_string()),
    ]))
}

/// Add the root harness to a synthetic source map.
fn with_root(mut sources: BTreeMap<String, String>) -> BTreeMap<String, String> {
    sources.insert(
        "crates/state/src/executor.rs".to_string(),
        ROOT_HARNESS.to_string(),
    );
    sources
}

fn execution_count(caller: &str) -> usize {
    analyse_sources(sources_with(caller))
        .iter()
        .filter(|s| s.class == Class::Execution)
        .count()
}

#[test]
fn the_analyser_sees_a_plain_store_call() {
    assert_eq!(
        execution_count(
            r#"
impl Probe {
    fn execute(&self, db: &Database) -> Result<()> {
        let store = StateStore::new(db);
        store.put_account(b"k", b"v")
    }
}
"#
        ),
        1
    );
}

/// A write moved behind a private helper is still counted.
///
/// This is the shape the raw-syntax guard cannot follow at all. `put_account`
/// below contains no database call: the write lives one level down, in a
/// private helper the caller has never heard of. Without the transitive
/// closure, `put_account` is not a mutator, the caller is not a site, and a
/// subsystem could zero its ledger entry by adding one indirection.
#[test]
fn a_write_behind_a_helper_is_still_counted() {
    let library_with_helper = r#"
pub struct StateStore<'a> { db: &'a Database }
impl<'a> StateStore<'a> {
    pub fn new(db: &'a Database) -> Self { Self { db } }
    pub fn put_account(&self, k: &[u8], v: &[u8]) -> Result<()> {
        self.persist(k, v)
    }
    fn persist(&self, k: &[u8], v: &[u8]) -> Result<()> {
        self.db.put(cf::STATE, k, v)
    }
}
"#;
    let sources = with_root(BTreeMap::from([
        ("crates/storage/src/schema.rs".to_string(), library_with_helper.to_string()),
        (
            "crates/state/src/probe_executor.rs".to_string(),
            r#"
impl Probe {
    fn execute(&self, db: &Database) -> Result<()> {
        let store = StateStore::new(db);
        store.put_account(b"k", b"v")
    }
}
"#
            .to_string(),
        ),
    ]));
    assert_eq!(
        analyse_sources(sources)
            .iter()
            .filter(|s| s.class == Class::Execution)
            .count(),
        1,
        "a write one level down a private helper must still make its caller a site"
    );
}

/// Renaming the receiver does not hide the write.
///
/// The raw-syntax guard next door matches the literal text `db.put(`. Rename the
/// field to `database` and its count silently drops; this resolves the receiver
/// by TYPE, so the rename changes nothing.
#[test]
fn a_renamed_receiver_is_still_counted() {
    let (_, _) = fake_library();
    let renamed_library = r#"
pub struct StateStore<'a> { database: &'a Database }
impl<'a> StateStore<'a> {
    pub fn new(database: &'a Database) -> Self { Self { database } }
    pub fn put_account(&self, k: &[u8], v: &[u8]) -> Result<()> {
        self.database.put(cf::STATE, k, v)
    }
}
"#;
    let sources = with_root(BTreeMap::from([
        ("crates/storage/src/schema.rs".to_string(), renamed_library.to_string()),
        (
            "crates/state/src/probe_executor.rs".to_string(),
            r#"
impl Probe {
    fn execute(&self, db: &Database) -> Result<()> {
        let store = StateStore::new(db);
        store.put_account(b"k", b"v")
    }
}
"#
            .to_string(),
        ),
    ]));
    let n = analyse_sources(sources)
        .iter()
        .filter(|s| s.class == Class::Execution)
        .count();
    assert_eq!(n, 1, "renaming the database receiver must not hide the write");
}

/// A call split across lines is still one call.
///
/// `self.db\n    .put(..)` is the commonest shape in this codebase, and the
/// first version of the raw-syntax guard was blind to it — rustfmt decided
/// whether a write counted.
#[test]
fn a_multiline_call_is_still_counted() {
    let multiline_library = r#"
pub struct StateStore<'a> { db: &'a Database }
impl<'a> StateStore<'a> {
    pub fn new(db: &'a Database) -> Self { Self { db } }
    pub fn put_account(&self, k: &[u8], v: &[u8]) -> Result<()> {
        self.db
            .put(
                cf::STATE,
                k,
                v,
            )
    }
}
"#;
    let sources = with_root(BTreeMap::from([
        ("crates/storage/src/schema.rs".to_string(), multiline_library.to_string()),
        (
            "crates/state/src/probe_executor.rs".to_string(),
            r#"
impl Probe {
    fn execute(&self, db: &Database) -> Result<()> {
        let store = StateStore::new(db);
        store
            .put_account(
                b"k",
                b"v",
            )
    }
}
"#
            .to_string(),
        ),
    ]));
    let sites = analyse_sources(sources);
    assert_eq!(
        sites.iter().filter(|s| s.class == Class::Execution).count(),
        1,
        "a line break between the receiver and the method must not hide the call"
    );
}

/// A write whose column family comes from a runtime binding is counted, and
/// named.
///
/// `execute_accept_assignment_v2` was exactly this: `db.put(cf, ..)` where `cf`
/// was chosen by an `if` between two families. No name-based check could see
/// which family it wrote, and a check that gave up would have dropped the write
/// entirely.
#[test]
fn a_variable_column_family_is_counted_and_attributed() {
    let variable_cf_library = r#"
pub struct BitmapStore<'a> { db: &'a Database }
impl<'a> BitmapStore<'a> {
    pub fn new(db: &'a Database) -> Self { Self { db } }
    pub fn stage(&self, epoch_zero: bool, k: &[u8], v: &[u8]) -> Result<()> {
        let cf = if epoch_zero { cf::ATTESTATIONS } else { cf::ATTESTATIONS_EPOCH };
        self.db.put(cf, k, v)
    }
}
"#;
    let sources = with_root(BTreeMap::from([
        ("crates/storage/src/schema.rs".to_string(), variable_cf_library.to_string()),
        (
            "crates/state/src/probe_executor.rs".to_string(),
            r#"
impl Probe {
    fn execute(&self, db: &Database) -> Result<()> {
        let store = BitmapStore::new(db);
        store.stage(true, b"k", b"v")
    }
}
"#
            .to_string(),
        ),
    ]));
    let sites = analyse_sources(sources);
    let exec: Vec<&Site> = sites.iter().filter(|s| s.class == Class::Execution).collect();
    assert_eq!(exec.len(), 1, "a runtime-chosen family must not drop the write");
    assert_eq!(
        exec[0].cfs,
        BTreeSet::from([
            Cf::Named("ATTESTATIONS".to_string()),
            Cf::Named("ATTESTATIONS_EPOCH".to_string())
        ]),
        "both candidate families must be attributed — over-attribution is the \
         safe direction when the family is not decidable from the source"
    );
}

/// A family named nowhere at all still counts as a write, as [`Cf::Variable`].
#[test]
fn an_unnameable_column_family_is_still_a_write() {
    let opaque_library = r#"
pub struct OpaqueStore<'a> { db: &'a Database }
impl<'a> OpaqueStore<'a> {
    pub fn new(db: &'a Database) -> Self { Self { db } }
    pub fn stage(&self, family: &str, k: &[u8], v: &[u8]) -> Result<()> {
        self.db.put(family, k, v)
    }
}
"#;
    let sources = with_root(BTreeMap::from([
        ("crates/storage/src/schema.rs".to_string(), opaque_library.to_string()),
        (
            "crates/state/src/probe_executor.rs".to_string(),
            r#"
impl Probe {
    fn execute(&self, db: &Database) -> Result<()> {
        OpaqueStore::new(db).stage("anything", b"k", b"v")
    }
}
"#
            .to_string(),
        ),
    ]));
    let sites = analyse_sources(sources);
    let exec: Vec<&Site> = sites.iter().filter(|s| s.class == Class::Execution).collect();
    assert_eq!(exec.len(), 1);
    assert_eq!(exec[0].cfs, BTreeSet::from([Cf::Variable]));
}

/// An accessor hop is followed: `store.identity_roots().put(..)`.
///
/// Eleven of the seventeen ledger files reach their writes this way. A resolver
/// that stopped at the first `.` would report zero for all of them.
#[test]
fn an_accessor_hop_is_followed() {
    let faceted_library = r#"
pub struct IdentityRootStore<'a> { db: &'a Database }
impl<'a> IdentityRootStore<'a> {
    pub fn new(db: &'a Database) -> Self { Self { db } }
    pub fn put(&self, k: &[u8], v: &[u8]) -> Result<()> { self.db.put(cf::IDENTITY, k, v) }
}
pub struct DocClassStore<'a> { db: &'a Database }
impl<'a> DocClassStore<'a> {
    pub fn new(db: &'a Database) -> Self { Self { db } }
    pub fn identity_roots(&self) -> IdentityRootStore<'_> { IdentityRootStore::new(self.db) }
}
"#;
    let sources = with_root(BTreeMap::from([
        ("crates/storage/src/docclass_store.rs".to_string(), faceted_library.to_string()),
        (
            "crates/state/src/probe_executor.rs".to_string(),
            r#"
impl Probe {
    fn execute(&self, db: &Database) -> Result<()> {
        let store = DocClassStore::new(db);
        store.identity_roots().put(b"k", b"v")
    }
}
"#
            .to_string(),
        ),
    ]));
    let sites = analyse_sources(sources);
    let exec: Vec<&Site> = sites.iter().filter(|s| s.class == Class::Execution).collect();
    assert_eq!(exec.len(), 1, "the accessor hop must be followed");
    assert_eq!(exec[0].cfs, BTreeSet::from([Cf::Named("IDENTITY".to_string())]));
}

/// A store reached through a struct field, not a local binding.
#[test]
fn a_store_held_in_a_field_is_counted() {
    assert_eq!(
        analyse_sources(with_root(BTreeMap::from([
            fake_library(),
            (
                "crates/state/src/probe_executor.rs".to_string(),
                r#"
pub struct Probe { db: Arc<Database> }
impl Probe {
    fn execute(&self) -> Result<()> {
        StateStore::new(&self.db).put_account(b"k", b"v")
    }
}
"#
                .to_string()
            ),
        ])))
        .iter()
        .filter(|s| s.class == Class::Execution)
        .count(),
        1
    );
}

/// A write inside a `#[cfg(test)]` module is not block execution.
///
/// Two things keep it out, and the test asserts both: the module never reaches
/// the index, and nothing reachable from a root could call it if it did.
/// Asserting only the count would pass for the second reason alone, and would
/// keep passing if the stripping broke.
#[test]
fn a_cfg_test_module_is_not_counted() {
    const FIXTURE: &str = r#"
impl Probe {
    fn execute(db: &Database) -> Result<()> { Ok(()) }
}
#[cfg(test)]
mod tests {
    fn fixture(db: &Database) -> Result<()> {
        let store = StateStore::new(db);
        store.put_account(b"k", b"v")
    }
}
"#;
    assert!(
        !prepare(FIXTURE).contains("put_account"),
        "the `#[cfg(test)]` module must be removed before indexing"
    );
    assert_eq!(
        execution_count(FIXTURE),
        0,
        "a fixture cannot be reached from a block"
    );
}

/// Publishing a candidate is not an execution violation.
///
/// The overlay does end in a real `WriteBatch` — `into_batch` puts every
/// buffered row and commits — but that batch is reachable only from
/// `AcceptedCandidate::publish`, which is the ONE sanctioned committed write.
/// Counting it here would mark the sanctioned publisher as the violation and
/// every migrated subsystem as unmigrated: the exact inverse of what this
/// ledger measures.
#[test]
fn publishing_a_candidate_is_not_a_committed_execution_write() {
    let overlay = r#"
pub struct ApplicationOverlay<'a> { db: &'a Database }
impl<'a> ApplicationOverlay<'a> {
    pub fn new(db: &'a Database) -> Self { Self { db } }
    pub fn put(&mut self, cf: &str, k: &[u8], v: &[u8]) -> Result<()> { Ok(()) }
    pub fn publish(self, k: &[u8], v: &[u8]) -> Result<()> { self.into_batch(k, v) }
    fn into_batch(self, k: &[u8], v: &[u8]) -> Result<()> {
        let mut batch = self.db.batch();
        batch.put(cf::STATE, k, v)?;
        batch.commit()
    }
}
"#;
    let caller = r#"
impl Probe {
    fn execute(&self, db: &Database) -> Result<()> {
        let mut overlay = ApplicationOverlay::new(db);
        overlay.put(cf::STATE, b"k", b"v")?;
        overlay.publish(b"k", b"v")
    }
}
"#;
    // As it stands: the overlay file is excluded, so neither line is a site.
    let excluded = analyse_sources(with_root(BTreeMap::from([
        ("crates/storage/src/overlay.rs".to_string(), overlay.to_string()),
        ("crates/state/src/probe_executor.rs".to_string(), caller.to_string()),
    ])));
    assert_eq!(
        excluded.iter().filter(|s| s.class == Class::Execution).count(),
        0,
        "staging into the overlay, and publishing it, are the migration target"
    );

    // The same code with the publisher function renamed: the exemption is keyed
    // to `ApplicationOverlay::into_batch` by name, so a DIFFERENT function in
    // the very same file is counted. That is what stops the exemption from
    // covering a whole file, and this half is why it is not inert.
    let not_excluded = analyse_sources(with_root(BTreeMap::from([
        (
            "crates/storage/src/overlay.rs".to_string(),
            overlay.replace("into_batch", "some_other_write"),
        ),
        ("crates/state/src/probe_executor.rs".to_string(), caller.to_string()),
    ])));
    assert_eq!(
        not_excluded.iter().filter(|s| s.class == Class::Execution).count(),
        1,
        "without the exclusion the publish reads as a committed execution write"
    );
}

/// Genesis, reorg-undo and execution are told apart WITHIN one file.
///
/// `state.rs` holds all three: prefunding at genesis, the revert, and the
/// account debit every transaction makes. A file-level rule cannot separate
/// them; rooting can, because each is reached from a different entry point.
#[test]
fn classification_separates_paths_within_one_file() {
    let sources = BTreeMap::from([
        fake_library(),
        (
            // The root reaches only the execution path.
            "crates/state/src/executor.rs".to_string(),
            r#"
pub struct BlockExecutor { db: Arc<Database> }
impl BlockExecutor {
    pub fn execute_block(&self, db: &Database) -> Result<()> {
        StateManager::put_account(db)
    }
}
"#
            .to_string(),
        ),
        (
            "crates/state/src/state.rs".to_string(),
            r#"
impl StateManager {
    pub fn init_from_genesis(&self, db: &Database) -> Result<()> {
        StateStore::new(db).put_account(b"k", b"v")
    }
    pub fn revert_block_state_diffs(&self, db: &Database) -> Result<()> {
        StateStore::new(db).put_account(b"k", b"v")
    }
    pub fn put_account(db: &Database) -> Result<()> {
        StateStore::new(db).put_account(b"k", b"v")
    }
}
"#
            .to_string(),
        ),
    ]);
    let sites = analyse_sources(sources);
    let by_class = |c: Class| sites.iter().filter(|s| s.class == c).count();
    assert_eq!(by_class(Class::Genesis), 1, "genesis prefunding");
    assert_eq!(by_class(Class::ReorgUndo), 1, "the revert");
    assert_eq!(
        by_class(Class::Execution),
        1,
        "three writes in one file, three entry points, three classes"
    );
}

/// A mutating helper nothing reaches is not an execution write.
///
/// This is the difference between an inventory and a guard. The first version
/// of this file defaulted every `crates/state/src` function to "execution", so
/// a `pub fn` with no caller counted exactly as much as one the dispatcher
/// runs on every block — and deleting dead code read as migration progress.
///
/// The real tree has two such functions, both `pub` with no production caller;
/// they are named in [`UNREACHED_MUTATORS`] rather than silently dropped.
#[test]
fn an_unreachable_mutating_helper_is_not_counted() {
    const REACHED: &str = r#"
impl Probe {
    fn execute(db: &Database) -> Result<()> {
        StateStore::new(db).put_account(b"k", b"v")
    }
}
"#;
    const ALSO_AN_ORPHAN: &str = r#"
impl Probe {
    fn execute(db: &Database) -> Result<()> {
        StateStore::new(db).put_account(b"k", b"v")
    }
    pub fn orphan(db: &Database) -> Result<()> {
        StateStore::new(db).put_account(b"orphan", b"v")
    }
}
"#;
    assert_eq!(execution_count(REACHED), 1);
    assert_eq!(
        execution_count(ALSO_AN_ORPHAN),
        1,
        "a second write that no entry point reaches must not enter the ledger"
    );
}

/// Constant-cardinality substitution: the same totals, a different write.
///
/// Both halves below have one site, in one file, touching one column family.
/// Per-file counts and a family total cannot tell them apart, and both passed
/// before the manifest keyed identities. They are different writes: a different
/// caller, a different mutator, a different family.
#[test]
fn substituting_one_write_for_another_is_not_invisible() {
    const BEFORE: &str = r#"
impl Probe {
    fn execute(db: &Database) -> Result<()> {
        StateStore::new(db).put_account(b"k", b"v")
    }
}
"#;
    // Same file, same count, same number of families — different everything else.
    const AFTER: &str = r#"
impl Probe {
    fn execute(db: &Database) -> Result<()> {
        NftStore::new(db).put_token(b"k", b"v")
    }
}
"#;
    let library = r#"
pub struct StateStore<'a> { db: &'a Database }
impl<'a> StateStore<'a> {
    pub fn new(db: &'a Database) -> Self { Self { db } }
    pub fn put_account(&self, k: &[u8], v: &[u8]) -> Result<()> { self.db.put(cf::STATE, k, v) }
}
pub struct NftStore<'a> { db: &'a Database }
impl<'a> NftStore<'a> {
    pub fn new(db: &'a Database) -> Self { Self { db } }
    pub fn put_token(&self, k: &[u8], v: &[u8]) -> Result<()> { self.db.put(cf::NFT_TOKENS, k, v) }
}
"#;
    let run = |probe: &str| {
        analyse_sources(with_root(BTreeMap::from([
            ("crates/storage/src/schema.rs".to_string(), library.to_string()),
            ("crates/state/src/probe_executor.rs".to_string(), probe.to_string()),
        ])))
    };
    let before = run(BEFORE);
    let after = run(AFTER);

    let count = |v: &[Site]| execution_of(v).iter().map(|s| s.count).sum::<usize>();
    let families = |v: &[Site]| {
        execution_of(v)
            .iter()
            .flat_map(|s| s.cfs.iter().cloned())
            .collect::<BTreeSet<Cf>>()
            .len()
    };
    assert_eq!(count(&before), count(&after), "the totals are identical...");
    assert_eq!(families(&before), families(&after), "...and so is the family count");

    let identity = |v: &[Site]| {
        execution_of(v)
            .iter()
            .map(|s| (s.file.clone(), s.caller.clone(), s.callee.clone(), cf_list(&s.cfs)))
            .collect::<Vec<_>>()
    };
    assert_ne!(
        identity(&before),
        identity(&after),
        "...but the manifest keys callee and families, so the substitution moves \
         a row. This is the check a count cannot make."
    );
}

/// A direct write elsewhere in a buffering file is still a write.
///
/// The exemption names one function. A new `db.put` anywhere else in
/// `overlay.rs` — or in `exec_view.rs` or `candidate.rs`, which are no longer
/// exempt at all — is a committed write like any other.
#[test]
fn a_direct_write_elsewhere_in_a_buffering_file_is_counted() {
    let overlay_with_a_second_writer = r#"
pub struct ApplicationOverlay<'a> { db: &'a Database }
impl<'a> ApplicationOverlay<'a> {
    pub fn new(db: &'a Database) -> Self { Self { db } }
    fn into_batch(self, k: &[u8], v: &[u8]) -> Result<()> {
        let mut batch = self.db.batch();
        batch.put(cf::STATE, k, v)?;
        batch.commit()
    }
    pub fn shortcut(&self, k: &[u8], v: &[u8]) -> Result<()> {
        self.db.put(cf::STATE, k, v)
    }
}
"#;
    let sites = analyse_sources(with_root(BTreeMap::from([
        (
            "crates/storage/src/overlay.rs".to_string(),
            overlay_with_a_second_writer.to_string(),
        ),
        (
            "crates/state/src/probe_executor.rs".to_string(),
            r#"
impl Probe {
    fn execute(db: &Database) -> Result<()> {
        ApplicationOverlay::new(db).shortcut(b"k", b"v")
    }
}
"#
            .to_string(),
        ),
    ])));
    assert_eq!(
        execution_of(&sites).len(),
        1,
        "exempting the publisher must not exempt the file it lives in"
    );
}

/// A `TxPayload::` mention outside the dispatch match is not an arm.
///
/// The first version collected every textual occurrence, so a mention in a
/// helper, a type annotation or an arm BODY read as a dispatch arm — and a real
/// arm could be added without the count moving, if some other mention went away
/// in the same commit.
#[test]
fn a_tx_payload_mention_outside_the_dispatch_is_not_an_arm() {
    const SRC: &str = r#"
fn describe(p: &TxPayload) -> &'static str {
    if matches!(p, TxPayload::NotAnArm(_)) { "x" } else { "y" }
}
impl BlockExecutor {
    fn dispatch(&self, p: &TxPayload) -> Result<()> {
        match p {
            TxPayload::Real(d) => {
                // A mention inside an arm BODY, at depth 2.
                let _ = TxPayload::AlsoNotAnArm(d);
                Ok(())
            }
            TxPayload::AlsoReal(_) => Ok(()),
        }
    }
}
"#;
    let arms: BTreeSet<String> = dispatch_arms(&prepare(SRC))
        .into_iter()
        .map(|(n, _)| n)
        .collect();
    assert_eq!(
        arms,
        BTreeSet::from(["Real".to_string(), "AlsoReal".to_string()]),
        "only match-arm patterns are arms"
    );
}
