//! Class 7 (SC-1..SC-8): the registry readers that returned a whole column
//! family in one response, and what they return now.
//!
//! # Why there is no activation height here
//!
//! Every other class in the audit is closed behind a gate, because every other
//! class changes what a transaction does and two nodes that disagree about that
//! disagree about the chain. These are READ paths. No transaction's validity
//! depends on them, no state root folds them, and `crates/state` never calls
//! them. A node that pages and a node that does not still agree about every
//! block, so there is nothing to coordinate and a gate would be ceremony. A
//! previous pass reached the same conclusion and recorded it without acting on
//! it; this file is the acting.
//!
//! # What each test establishes
//!
//! * **Bounded default** — a caller who passes nothing gets 100 rows out of a
//!   family of more than 100. Before, they got the family.
//! * **Pagination** — consecutive offsets are disjoint and, taken together,
//!   reconstruct the whole set. Nothing is skipped at a page boundary and
//!   nothing is served twice.
//! * **Deterministic order** — the same offset asked twice returns the same
//!   rows, so a page boundary is a position and not an accident.
//! * **Refusal, not clamping** — `limit` above the maximum is `-32004`. This is
//!   the point the `-32003` history-floor precedent in
//!   `operator_visible_activation_and_history.rs` already made for a different
//!   question: an answer the node quietly shortened is indistinguishable from a
//!   complete one, so the node must say so instead.
//! * **Compatibility** — the pagination arguments are trailing and optional at
//!   the JSON-RPC layer as well as in Rust, so a client that has never heard of
//!   them keeps working.
//! * **Answers that must not be paged** — `employment_verifyEmployment` and
//!   `employment_getSummary`'s counts are not lists, and bounding them would
//!   have made them WRONG rather than short. Both are pinned against a data set
//!   larger than a page.
//!
//! # Reachability
//!
//! Every RPC method exercised here is registered in `crates/rpc/src/api.rs` and
//! therefore live on the release surface — `crates/rpc/src/server.rs` starts
//! the whole trait in one `into_rpc()` call. The store readers DE-12 records as
//! unreachable are bounded too, and tested through the store rather than
//! through a method, because there is no method to test them through. That
//! difference is stated per row in the audit rather than averaged away.

use std::collections::HashMap;
use std::sync::Arc;

use jsonrpsee::core::client::Error as JsonRpseeError;
use sumchain_consensus::PoAEngine;
use sumchain_crypto::KeyPair;
use sumchain_genesis::{ChainParams, Genesis};
use sumchain_primitives::Address;
use sumchain_rpc::api::SumChainApiServer;
use sumchain_rpc::server::RpcServer;
use sumchain_rpc::{RPC_PAGE_DEFAULT, RPC_PAGE_MAX, RPC_PAGE_OFFSET_MAX};
use sumchain_state::{Mempool, MempoolConfig, StateManager};
use sumchain_storage::Database;
use tempfile::TempDir;
use tokio::sync::mpsc;

/// More rows than one page holds, so "bounded" and "everything" cannot be
/// confused for each other.
const SEEDED: usize = 250;

fn server() -> (RpcServer, Arc<Database>, TempDir) {
    let dir = TempDir::new().unwrap();
    let db = Arc::new(Database::open_default(dir.path()).unwrap());
    let state = Arc::new(StateManager::new(db.clone(), 1));
    let mempool = Arc::new(Mempool::new(MempoolConfig::default()));
    let validator = KeyPair::generate();
    let genesis = Genesis::new(
        1,
        0,
        vec![validator.public_key().to_base58()],
        HashMap::from([(validator.address().to_base58(), 1u128)]),
        ChainParams::default(),
    );
    let engine = Arc::new(
        PoAEngine::new(
            db.clone(),
            state.clone(),
            mempool.clone(),
            &genesis,
            Some(validator),
        )
        .unwrap(),
    );
    let (tx_sender, _rx) = mpsc::channel(8);
    let srv = RpcServer::new(
        db.clone(),
        state,
        mempool,
        engine,
        tx_sender,
        Arc::new(|| 0usize),
    );
    (srv, db, dir)
}

/// A distinct 32-byte id per seeded row.
fn id32(n: usize) -> [u8; 32] {
    let mut k = [0u8; 32];
    k[..8].copy_from_slice(&(n as u64).to_be_bytes());
    k
}

/// A distinct 20-byte address per seeded row.
fn addr(n: usize) -> Address {
    let mut k = [0u8; 20];
    k[..8].copy_from_slice(&(n as u64).to_be_bytes());
    Address::new(k)
}

/// The refusal a page out of bounds must produce: `-32004`, and not a clamped
/// success.
fn assert_refused(err: jsonrpsee::types::ErrorObjectOwned) {
    assert_eq!(
        err.code(),
        -32004,
        "a page out of bounds must be refused with -32004, got: {err:?}"
    );
}

// ===========================================================================
// SC-1 — Tax. REACHABLE: tax_listClaimTypes, tax_getActiveIssuers,
// tax_getIssuersByClass, tax_listPolicies.
// ===========================================================================

fn seed_tax(db: &Arc<Database>) {
    use sumchain_primitives::tax::{
        ClaimTypeStatus, IssuerRequirements, QuorumRule, TaxClaimTypeEntry, TaxIssuer,
        TaxIssuerClass, TaxIssuerStatus, TaxPolicy, TaxPolicyTemplate, TaxRiskLevel,
    };
    use sumchain_storage::{TaxClaimTypeStore, TaxIssuerStore, TaxPolicyStore};

    let cts = TaxClaimTypeStore::new(db);
    let is = TaxIssuerStore::new(db);
    let ps = TaxPolicyStore::new(db);
    for n in 0..SEEDED {
        cts.put(&TaxClaimTypeEntry {
            claim_type: format!("tax.seeded.{n:05}"),
            schema_hash: [1u8; 32],
            risk_level: TaxRiskLevel::Medium,
            recommended_validity_secs: 86_400,
            required_issuer_classes: vec![vec![TaxIssuerClass::TaxAuthority]],
            status: ClaimTypeStatus::Active,
            version: 1,
            created_at: 100,
            updated_at: 100,
        })
        .unwrap();
        is.put(&TaxIssuer {
            address: addr(n),
            tax_class: TaxIssuerClass::TaxAuthority,
            jurisdictions: vec!["US".to_string()],
            attributes_hash: [2u8; 32],
            attributes_schema_hash: [3u8; 32],
            registered_at: 200,
            updated_at: 200,
            status: TaxIssuerStatus::Active,
            expires_at: None,
        })
        .unwrap();
        ps.put(&TaxPolicy {
            policy_id: id32(n),
            template: TaxPolicyTemplate::Filed,
            claim_types: vec!["tax.seeded.00000".to_string()],
            issuer_requirements: IssuerRequirements {
                groups: vec![vec![TaxIssuerClass::AuditorCpa]],
                quorum: QuorumRule::Any,
            },
            jurisdictions: vec!["US".to_string()],
            tax_years: vec![2024],
            max_age_secs: 31_536_000,
            revocation_check: true,
            creator: Address::new([9u8; 20]),
            created_at: 300,
        })
        .unwrap();
    }
}

#[tokio::test]
async fn tax_list_methods_return_one_bounded_page_instead_of_the_family() {
    let (srv, db, _dir) = server();
    seed_tax(&db);

    // The whole point of the row: the caller asks for nothing and the node
    // decides, instead of whoever last wrote to the chain deciding.
    assert_eq!(
        srv.tax_list_claim_types(None, None).await.unwrap().len(),
        RPC_PAGE_DEFAULT as usize
    );
    assert_eq!(
        srv.tax_get_active_issuers(None, None).await.unwrap().len(),
        RPC_PAGE_DEFAULT as usize
    );
    assert_eq!(
        srv.tax_list_policies(None, None).await.unwrap().len(),
        RPC_PAGE_DEFAULT as usize
    );
    assert_eq!(
        srv.tax_get_issuers_by_class("TaxAuthority".to_string(), None, None)
            .await
            .unwrap()
            .len(),
        RPC_PAGE_DEFAULT as usize
    );
}

#[tokio::test]
async fn tax_pages_are_disjoint_deterministic_and_cover_the_family() {
    let (srv, db, _dir) = server();
    seed_tax(&db);

    let mut seen: Vec<String> = Vec::new();
    for offset in (0..SEEDED as u32).step_by(100) {
        let page = srv
            .tax_list_claim_types(Some(100), Some(offset))
            .await
            .unwrap();
        // Same cursor, same page — twice.
        let again = srv
            .tax_list_claim_types(Some(100), Some(offset))
            .await
            .unwrap();
        assert_eq!(
            page.iter().map(|e| &e.claim_type).collect::<Vec<_>>(),
            again.iter().map(|e| &e.claim_type).collect::<Vec<_>>(),
            "the same offset returned two different pages"
        );
        seen.extend(page.into_iter().map(|e| e.claim_type));
    }

    let mut unique = seen.clone();
    unique.sort();
    unique.dedup();
    assert_eq!(unique.len(), seen.len(), "a row was served on two pages");
    assert_eq!(seen.len(), SEEDED, "paging did not cover the family");

    // Deterministic ordering is what makes a boundary well defined: the
    // concatenation of the pages is already sorted.
    let mut sorted = seen.clone();
    sorted.sort();
    assert_eq!(sorted, seen, "pages did not come back in key order");
}

#[tokio::test]
async fn a_tax_page_over_the_maximum_is_refused_and_never_clamped() {
    let (srv, db, _dir) = server();
    seed_tax(&db);

    // The discriminator against a clamp: a clamped node would answer with
    // RPC_PAGE_MAX rows and the caller would never learn it asked too much.
    let err = srv
        .tax_list_claim_types(Some(RPC_PAGE_MAX + 1), None)
        .await
        .expect_err("an over-large limit must be refused");
    assert_refused(err);

    let err = srv
        .tax_get_active_issuers(None, Some(RPC_PAGE_OFFSET_MAX + 1))
        .await
        .expect_err("an over-large offset must be refused");
    assert_refused(err);

    // The bound itself is servable, so the refusal is a boundary and not a ban.
    assert_eq!(
        srv.tax_list_claim_types(Some(RPC_PAGE_MAX), None)
            .await
            .unwrap()
            .len(),
        SEEDED
    );
}

// ===========================================================================
// SC-3 — Finance. REACHABLE: finance_getActiveIssuers,
// finance_getIssuersByJurisdiction.
// ===========================================================================

fn seed_finance(db: &Arc<Database>) {
    use sumchain_primitives::finance::{
        FinanceIssuerClass, FinanceIssuerProfile, FinanceIssuerStatus,
    };
    use sumchain_storage::FinanceIssuerStore;
    let store = FinanceIssuerStore::new(db);
    for n in 0..SEEDED {
        store
            .put(&FinanceIssuerProfile {
                issuer_address: addr(n),
                issuer_class: FinanceIssuerClass::RegulatedBank,
                issuer_commitment: [2u8; 32],
                jurisdiction_code: "US".to_string(),
                policy_id: [3u8; 32],
                status: FinanceIssuerStatus::Active,
                registered_at_height: 5,
                created_at: 1000,
                updated_at: 1100,
            })
            .unwrap();
    }
}

#[tokio::test]
async fn finance_issuer_reads_are_bounded_paged_and_refuse_an_over_large_page() {
    let (srv, db, _dir) = server();
    seed_finance(&db);

    assert_eq!(
        srv.finance_get_active_issuers(None, None)
            .await
            .unwrap()
            .len(),
        RPC_PAGE_DEFAULT as usize
    );
    // The jurisdiction read resolves an index vector: the bound is on how many
    // of its entries are point-read, not on the vector itself.
    assert_eq!(
        srv.finance_get_issuers_by_jurisdiction("US".to_string(), None, None)
            .await
            .unwrap()
            .len(),
        RPC_PAGE_DEFAULT as usize
    );

    let first = srv
        .finance_get_active_issuers(Some(10), Some(0))
        .await
        .unwrap();
    let second = srv
        .finance_get_active_issuers(Some(10), Some(10))
        .await
        .unwrap();
    assert_eq!(first.len(), 10);
    assert_eq!(second.len(), 10);
    for a in &first {
        assert!(
            !second.iter().any(|b| b.issuer_address == a.issuer_address),
            "consecutive pages overlapped"
        );
    }

    assert_refused(
        srv.finance_get_issuers_by_jurisdiction("US".to_string(), Some(RPC_PAGE_MAX + 1), None)
            .await
            .expect_err("over-large limit must be refused"),
    );
}

// ===========================================================================
// SC-4 — Agreement. REACHABLE: agreement_getActiveExecutorLinks,
// agreement_getExecutorLinksByAgreement, agreement_getExecutorLinksByExecutor.
// ===========================================================================

fn seed_agreement(db: &Arc<Database>, exec: Address) {
    use sumchain_primitives::agreement::{ExecutorLink, ExecutorState};
    use sumchain_storage::ExecutorLinkStore;
    let store = ExecutorLinkStore::new(db);
    for n in 0..SEEDED {
        store
            .put(&ExecutorLink {
                link_id: id32(n),
                agreement_id: [0xA1; 32],
                executor_contract: exec,
                executor_interface_id: [1u8; 32],
                terms_commitment: [2u8; 32],
                activation_policy_id: [3u8; 32],
                state: ExecutorState::Active,
                created_at: 100,
                updated_at: 100,
                created_at_height: 5,
                activation_proof_id: None,
            })
            .unwrap();
    }
}

#[tokio::test]
async fn agreement_executor_link_reads_are_bounded_including_the_full_scan_filter() {
    let (srv, db, _dir) = server();
    let exec = Address::new([0xE1; 20]);
    seed_agreement(&db, exec);
    let aid = format!("0x{}", hex::encode([0xA1; 32]));

    assert_eq!(
        srv.agreement_get_active_executor_links(None, None)
            .await
            .unwrap()
            .len(),
        RPC_PAGE_DEFAULT as usize
    );
    // `get_by_agreement` is a full scan plus a filter, not an index read — the
    // audit row says so explicitly. A page still bounds what it returns.
    assert_eq!(
        srv.agreement_get_executor_links_by_agreement(aid.clone(), None, None)
            .await
            .unwrap()
            .len(),
        RPC_PAGE_DEFAULT as usize
    );
    assert_eq!(
        srv.agreement_get_executor_links_by_executor(exec.to_base58(), None, None)
            .await
            .unwrap()
            .len(),
        RPC_PAGE_DEFAULT as usize
    );

    assert_refused(
        srv.agreement_get_active_executor_links(Some(RPC_PAGE_MAX + 1), None)
            .await
            .expect_err("over-large limit must be refused"),
    );
}

// ===========================================================================
// SC-5 — Property. REACHABLE: property_getActiveAssets,
// property_getAssetsByJurisdiction. The remaining get_by_* readers are
// UNREACHABLE (DE-12) and are bounded at the store, below.
// ===========================================================================

fn seed_property(db: &Arc<Database>) {
    use sumchain_primitives::property::{AssetAnchor, AssetStatus, AssetType, PropertyIssuerClass};
    use sumchain_storage::AssetStore;
    let store = AssetStore::new(db);
    for n in 0..SEEDED {
        store
            .put(&AssetAnchor {
                asset_id: id32(n),
                asset_commitment: [2u8; 32],
                asset_type: AssetType::SingleFamilyResidence,
                jurisdiction_code: "US-CA-LA".to_string(),
                public_reference: None,
                policy_id: [3u8; 32],
                issuer_class: PropertyIssuerClass::LandRegistry,
                issuer_address: Address::new([0xE1; 20]),
                status: AssetStatus::Active,
                created_at: 1000,
                updated_at: 1100,
                anchored_at_height: 5,
                related_assets: vec![],
                attachments: vec![],
            })
            .unwrap();
    }
}

#[tokio::test]
async fn property_asset_reads_are_bounded_and_refuse_an_over_large_page() {
    let (srv, db, _dir) = server();
    seed_property(&db);

    assert_eq!(
        srv.property_get_active_assets(None, None)
            .await
            .unwrap()
            .len(),
        RPC_PAGE_DEFAULT as usize
    );
    assert_eq!(
        srv.property_get_assets_by_jurisdiction("US-CA-LA".to_string(), None, None)
            .await
            .unwrap()
            .len(),
        RPC_PAGE_DEFAULT as usize
    );
    assert_refused(
        srv.property_get_active_assets(Some(RPC_PAGE_MAX + 1), None)
            .await
            .expect_err("over-large limit must be refused"),
    );
}

#[tokio::test]
async fn the_unreachable_property_readers_are_bounded_at_the_store() {
    // DE-12: no `#[method(...)]` reaches these, so there is no RPC to call and
    // the claim being made is narrower — a future method cannot expose an
    // unbounded reader, rather than a live vector being closed today.
    use sumchain_primitives::property::{
        PropertyIssuerClass, TitleEvent, TitleEventStatus, TitleEventType,
    };
    use sumchain_storage::{PageSpec, TitleEventStore};

    let dir = TempDir::new().unwrap();
    let db = Database::open_default(dir.path()).unwrap();
    let store = TitleEventStore::new(&db);
    let asset = id32(1);
    for n in 0..SEEDED {
        store
            .put(&TitleEvent {
                event_id: id32(1000 + n),
                asset_id: asset,
                event_type: TitleEventType::InitialRegistration,
                event_commitment: [6u8; 32],
                grantor_ref: None,
                grantee_ref: None,
                issuer_address: Address::new([0xE1; 20]),
                issuer_class: PropertyIssuerClass::LandRegistry,
                effective_date: 1000,
                recording_ref: None,
                policy_id: [3u8; 32],
                revocation_ref: None,
                status: TitleEventStatus::Recorded,
                created_at: 1000,
                recorded_at_height: 7,
                supersedes: None,
                attachments: vec![],
            })
            .unwrap();
    }

    assert_eq!(store.get_by_asset(&asset).unwrap().len(), SEEDED);
    assert_eq!(
        store
            .get_by_asset_paged(&asset, PageSpec::first())
            .unwrap()
            .len(),
        100
    );
    let first = store
        .get_by_asset_paged(&asset, PageSpec::new(0, 10))
        .unwrap();
    let second = store
        .get_by_asset_paged(&asset, PageSpec::new(10, 10))
        .unwrap();
    assert_eq!(first.len(), 10);
    for a in &first {
        assert!(!second.iter().any(|b| b.event_id == a.event_id));
    }
}

// ===========================================================================
// SC-6 — Healthcare. REACHABLE: healthcare_getActiveInstitutionalProviders.
// The five subject- and patient-facing get_by_* readers are UNREACHABLE
// (DE-12) and are bounded at the store, below.
// ===========================================================================

fn seed_healthcare(db: &Arc<Database>) {
    use sumchain_primitives::healthcare::{
        HealthcareIssuerClass, ProviderProfile, ProviderStatus, ProviderType,
    };
    use sumchain_storage::ProviderStore;
    let store = ProviderStore::new(db);
    for n in 0..SEEDED {
        store
            .put(&ProviderProfile {
                provider_id: id32(n),
                provider_commitment: [2u8; 32],
                // Alternating types prove the institutional allowlist still
                // applies once it runs INSIDE the bounded scan.
                provider_type: if n % 2 == 0 {
                    ProviderType::Hospital
                } else {
                    ProviderType::Physician
                },
                jurisdiction_code: "US-CA".to_string(),
                public_reference: None,
                specialties_commitment: None,
                credentials_commitment: None,
                policy_id: [5u8; 32],
                issuer_class: HealthcareIssuerClass::AccreditationBody,
                issuer_address: Address::new([0xE1; 20]),
                status: ProviderStatus::Active,
                created_at: 1000,
                updated_at: 1100,
                registered_at_height: 5,
                network_affiliations: vec![],
                attachments: vec![],
            })
            .unwrap();
    }
}

#[tokio::test]
async fn healthcare_institutional_providers_page_over_rows_the_caller_receives() {
    let (srv, db, _dir) = server();
    seed_healthcare(&db);

    // Half the seeded providers are non-institutional. `limit` counts what the
    // caller gets, not what the scan considered — if the allowlist ran after
    // the page the answer here would be 50.
    let page = srv
        .healthcare_get_active_institutional_providers(None, None)
        .await
        .unwrap();
    assert_eq!(page.len(), RPC_PAGE_DEFAULT as usize);
    // `HealthcareProviderInfo` does not carry the type, so the allowlist is
    // checked through the seeded id: only even `n` were given an institutional
    // type. Every row served must be an even one.
    for p in &page {
        let raw = hex::decode(p.provider_id.trim_start_matches("0x")).unwrap();
        let n = u64::from_be_bytes(raw[..8].try_into().unwrap());
        assert_eq!(
            n % 2,
            0,
            "a filtered-out (non-institutional) row was served"
        );
    }

    assert_refused(
        srv.healthcare_get_active_institutional_providers(Some(RPC_PAGE_MAX + 1), None)
            .await
            .expect_err("over-large limit must be refused"),
    );
}

#[tokio::test]
async fn the_unreachable_healthcare_readers_are_bounded_at_the_store() {
    // DE-12 again, and the place it matters most: these five are the
    // patient- and subject-facing readers, and the RPC surface is narrower
    // than the storage surface here. Bounding them is insurance against a
    // future `#[method]`, not the closing of a live vector.
    use sumchain_primitives::agreement::PartyRef;
    use sumchain_primitives::healthcare::{
        ConsentEnvelope, ConsentStatus, ConsentType, DisclosureScope, HealthcareIssuerClass,
    };
    use sumchain_storage::{ConsentStore, PageSpec};

    let dir = TempDir::new().unwrap();
    let db = Database::open_default(dir.path()).unwrap();
    let store = ConsentStore::new(&db);
    let subject = [0x5Au8; 32];
    for n in 0..SEEDED {
        store
            .put(&ConsentEnvelope {
                consent_id: id32(n),
                subject_address: Address::new([0xEE; 20]),
                consent_type: ConsentType::HipaaAuthorization,
                consent_commitment: [2u8; 32],
                subject_ref: PartyRef::Commitment(subject),
                subject_nullifier: subject,
                recipient_ref: PartyRef::Commitment([0x7Cu8; 32]),
                purpose_commitment: [3u8; 32],
                scope: DisclosureScope::AllRecords,
                scope_commitment: None,
                effective_from: 0,
                expiry: None,
                issuer_address: Address::new([0xE1; 20]),
                issuer_class: HealthcareIssuerClass::AccreditationBody,
                policy_id: [4u8; 32],
                revocation_ref: None,
                status: ConsentStatus::Granted,
                created_at: 10,
                updated_at: 10,
                recorded_at_height: 1,
                supersedes: None,
                attachments: vec![],
            })
            .unwrap();
    }

    assert_eq!(store.get_by_subject(&subject).unwrap().len(), SEEDED);
    assert_eq!(
        store
            .get_by_subject_paged(&subject, PageSpec::first())
            .unwrap()
            .len(),
        100
    );
}

// ===========================================================================
// SC-7 — DocClass. REACHABLE: docclass_getIssuers,
// docclass_getIssuersByJurisdiction, docclass_getIdentityByController,
// docclass_getSummary, docclass_getAcademicCredentialsByHolder.
// ===========================================================================

fn seed_docclass_issuers(db: &Arc<Database>) {
    use sumchain_primitives::docclass::{DocClassIssuer, DocClassIssuerStatus, DocClassIssuerType};
    use sumchain_storage::DocClassIssuerStore;
    let store = DocClassIssuerStore::new(db);
    for n in 0..SEEDED {
        store
            .put(&DocClassIssuer {
                address: addr(n),
                name: format!("issuer-{n:05}"),
                issuer_type: DocClassIssuerType::Educational,
                jurisdictions: vec!["US".to_string()],
                authorized_subcodes: vec![],
                keys: vec![],
                registered_at: 1,
                updated_at: 1,
                status: DocClassIssuerStatus::Active,
                stake_amount: 0,
                metadata: None,
            })
            .unwrap();
    }
}

#[tokio::test]
async fn docclass_get_issuers_bounds_the_read_and_not_only_the_response() {
    let (srv, db, _dir) = server();
    seed_docclass_issuers(&db);

    // This method ALREADY advertised limit/offset. What it did was scan the
    // whole family into a Vec and then skip/take over it, so the bound was on
    // the response and never on the read. The visible half of that change is
    // the refusal: an over-large limit used to be accepted and honoured.
    assert_refused(
        srv.docclass_get_issuers(Some(RPC_PAGE_MAX + 1), None)
            .await
            .expect_err("over-large limit must be refused"),
    );

    assert_eq!(
        srv.docclass_get_issuers(None, None).await.unwrap().len(),
        RPC_PAGE_DEFAULT as usize
    );
    let page = srv.docclass_get_issuers(Some(7), Some(3)).await.unwrap();
    assert_eq!(page.len(), 7);
    let again = srv.docclass_get_issuers(Some(7), Some(3)).await.unwrap();
    assert_eq!(
        page.iter().map(|i| &i.address).collect::<Vec<_>>(),
        again.iter().map(|i| &i.address).collect::<Vec<_>>()
    );

    assert_eq!(
        srv.docclass_get_issuers_by_jurisdiction("US".to_string(), None, None)
            .await
            .unwrap()
            .len(),
        RPC_PAGE_DEFAULT as usize
    );
}

#[tokio::test]
async fn docclass_summary_still_counts_the_whole_family() {
    let (srv, db, _dir) = server();
    seed_docclass_issuers(&db);

    // A COUNT is not a page. `get_all().len()` built a Vec of every issuer to
    // produce one u64; bounding the ANSWER would have made it wrong rather
    // than short, so the reader retains nothing instead of returning less.
    let summary = srv.docclass_get_summary().await.unwrap();
    assert_eq!(
        summary.total_issuers, SEEDED as u64,
        "the count must still be over the whole family"
    );
}

#[tokio::test]
async fn docclass_identity_by_controller_still_answers_from_a_page_of_one() {
    use sumchain_primitives::docclass::{IdentityRoot, IdentityStatus};
    use sumchain_storage::IdentityRootStore;

    let (srv, db, _dir) = server();
    let controller = Address::new([0xC1; 20]);
    let store = IdentityRootStore::new(&db);
    for n in 0..SEEDED {
        store
            .put(&IdentityRoot {
                identity_id: id32(n),
                subject_commitment: id32(n),
                controller,
                additional_controllers: vec![],
                keys: vec![],
                services: vec![],
                created_at: 1,
                updated_at: 1,
                status: IdentityStatus::Active,
                schema_hash: [8u8; 32],
            })
            .unwrap();
    }

    // No parameter was added: the method returns ONE identity and always did,
    // by taking `.next()` off a Vec the reader had filled with every match.
    // The answer is unchanged; only what the node builds to produce it is.
    let got = srv
        .docclass_get_identity_by_controller(controller.to_base58())
        .await
        .unwrap();
    assert!(
        got.is_some(),
        "a controller with 250 roots must still resolve"
    );
    assert!(srv
        .docclass_get_identity_by_controller(Address::new([0xFF; 20]).to_base58())
        .await
        .unwrap()
        .is_none());
}

// ===========================================================================
// SC-2 — Employment. Every method the row names is REACHABLE.
// ===========================================================================

fn seed_employment_issuers(db: &Arc<Database>) {
    use sumchain_primitives::employment::{
        EmploymentIssuerClass, EmploymentIssuerProfile, IssuerStatus,
    };
    use sumchain_storage::EmploymentIssuerStore;
    let store = EmploymentIssuerStore::new(db);
    for n in 0..SEEDED {
        store
            .put(&EmploymentIssuerProfile {
                issuer_address: addr(n),
                issuer_class: EmploymentIssuerClass::Employer,
                display_name: format!("employer-{n:05}"),
                issuer_commitment: [2u8; 32],
                jurisdiction_code: "US".to_string(),
                policy_id: [3u8; 32],
                status: IssuerStatus::Active,
                registered_at_height: 5,
                created_at: 1000,
                updated_at: 1100,
            })
            .unwrap();
    }
}

/// `SEEDED` credentials for one employee. The LAST one names `target_employer`,
/// so anything that stops at a page boundary will miss it.
fn seed_employment_credentials(db: &Arc<Database>, employee: [u8; 32], target_employer: [u8; 32]) {
    use sumchain_primitives::employment::{
        EmploymentCredential, EmploymentIssuerClass, EmploymentStatus, EmploymentType,
    };
    use sumchain_storage::EmploymentCredentialStore;
    let store = EmploymentCredentialStore::new(db);
    for n in 0..SEEDED {
        store
            .put(&EmploymentCredential {
                employment_id: id32(n),
                employee_address: Address::new([0xEE; 20]),
                employee_ref: employee,
                employer_ref: if n == SEEDED - 1 {
                    target_employer
                } else {
                    id32(500_000 + n)
                },
                status: EmploymentStatus::Active,
                tenure_commitment: [7u8; 32],
                role_commitment: None,
                employment_type: EmploymentType::FullTime,
                valid_from: 0,
                expiry: 0,
                policy_id: [3u8; 32],
                revocation_ref: None,
                issuer_address: Address::new([0xE1; 20]),
                issuer_name: "seed".to_string(),
                issuer_class: EmploymentIssuerClass::Employer,
                created_at: 1,
                updated_at: 1,
            })
            .unwrap();
    }
}

#[tokio::test]
async fn employment_list_and_index_reads_are_bounded() {
    let (srv, db, _dir) = server();
    seed_employment_issuers(&db);
    let employee = [0x1Au8; 32];
    seed_employment_credentials(&db, employee, [0x2Bu8; 32]);
    let eref = format!("0x{}", hex::encode(employee));

    assert_eq!(
        srv.employment_list_issuers(None, None).await.unwrap().len(),
        RPC_PAGE_DEFAULT as usize
    );
    assert_eq!(
        srv.employment_get_credentials_by_employee(eref.clone(), None, None)
            .await
            .unwrap()
            .len(),
        RPC_PAGE_DEFAULT as usize
    );
    // The `active` variant used to build the WHOLE list and then filter it.
    assert_eq!(
        srv.employment_get_active_credentials_by_employee(eref.clone(), None, None)
            .await
            .unwrap()
            .len(),
        RPC_PAGE_DEFAULT as usize
    );

    assert_refused(
        srv.employment_list_issuers(Some(RPC_PAGE_MAX + 1), None)
            .await
            .expect_err("over-large limit must be refused"),
    );
}

#[tokio::test]
async fn employment_verification_is_not_paged_and_still_finds_the_last_credential() {
    let (srv, db, _dir) = server();
    let employee = [0x1Au8; 32];
    let employer = [0x2Bu8; 32];
    seed_employment_credentials(&db, employee, employer);

    // THE DISCRIMINATOR for "some answers must not be paged". The matching
    // credential is the 250th of 250. A verification bounded to 100 rows would
    // answer `is_employed: false` — a wrong answer, not a short one. The
    // predicate moved into the walk instead, so the answer is unchanged.
    let got = srv
        .employment_verify_employment(
            format!("0x{}", hex::encode(employee)),
            format!("0x{}", hex::encode(employer)),
        )
        .await
        .unwrap();
    assert!(
        got.is_employed,
        "verification must see past a page boundary"
    );

    let absent = srv
        .employment_verify_employment(
            format!("0x{}", hex::encode(employee)),
            format!("0x{}", hex::encode([0x99u8; 32])),
        )
        .await
        .unwrap();
    assert!(!absent.is_employed);
}

#[tokio::test]
async fn employment_summary_counts_the_whole_set_and_pages_only_its_list() {
    let (srv, db, _dir) = server();
    let employee = [0x1Au8; 32];
    seed_employment_credentials(&db, employee, [0x2Bu8; 32]);

    let summary = srv
        .employment_get_summary(format!("0x{}", hex::encode(employee)), None, None)
        .await
        .unwrap();

    // Counts are exact — they are not lists, and a page would make them wrong.
    assert_eq!(summary.total_credentials, SEEDED as u32);
    assert_eq!(summary.active_credentials, SEEDED as u32);
    // The list is bounded.
    assert_eq!(summary.active_employment.len(), RPC_PAGE_DEFAULT as usize);

    // ...and pages independently of the counts.
    let deep = srv
        .employment_get_summary(format!("0x{}", hex::encode(employee)), Some(10), Some(200))
        .await
        .unwrap();
    assert_eq!(deep.total_credentials, SEEDED as u32);
    assert_eq!(deep.active_employment.len(), 10);
}

// ===========================================================================
// Compatibility — over the wire, not only in Rust.
// ===========================================================================

#[tokio::test]
async fn a_caller_that_sends_no_pagination_argument_still_gets_a_useful_answer() {
    // A Rust caller writes `None, None`; a JSON-RPC client written before these
    // parameters existed sends `[]` or `["US"]` and nothing more. This test
    // goes through `into_rpc()` — the same registration
    // `crates/rpc/src/server.rs` serves production from — so the claim being
    // made is about the wire and not about the trait.
    use jsonrpsee::core::client::ClientT;
    use jsonrpsee::rpc_params;
    use jsonrpsee::server::{RpcModule, Server};
    use sumchain_rpc::types::{FinanceIssuerInfo, TaxClaimTypeInfo};

    let (srv, db, _dir) = server();
    seed_tax(&db);
    seed_finance(&db);

    let module: RpcModule<_> = srv.into_rpc();
    let server = Server::builder().build("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", server.local_addr().unwrap());
    let handle = server.start(module);
    let client = jsonrpsee::http_client::HttpClientBuilder::default()
        .build(&url)
        .unwrap();

    // No pagination argument at all.
    let rows: Vec<TaxClaimTypeInfo> = client
        .request("tax_listClaimTypes", rpc_params![])
        .await
        .expect("an existing caller must still be served");
    assert_eq!(rows.len(), RPC_PAGE_DEFAULT as usize);
    assert!(!rows.is_empty(), "a bounded answer must still be useful");

    // Existing positional arguments, no pagination appended.
    let rows: Vec<FinanceIssuerInfo> = client
        .request("finance_getIssuersByJurisdiction", rpc_params!["US"])
        .await
        .expect("an existing caller must still be served");
    assert_eq!(rows.len(), RPC_PAGE_DEFAULT as usize);

    // And a new caller that DOES page gets `-32004` over the wire, with the
    // code intact rather than flattened into a generic internal error.
    let err = client
        .request::<Vec<TaxClaimTypeInfo>, _>("tax_listClaimTypes", rpc_params![RPC_PAGE_MAX + 1])
        .await
        .expect_err("over-large limit must be refused over the wire");
    match err {
        JsonRpseeError::Call(obj) => assert_eq!(obj.code(), -32004),
        other => panic!("expected a -32004 call error, got {other:?}"),
    }

    handle.stop().unwrap();
    handle.stopped().await;
}
