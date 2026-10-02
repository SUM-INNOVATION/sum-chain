//! `DocClassExecutor::effective_rules` describes what execution does (#280).
//!
//! The function never decides anything; execution keeps its own code. So the
//! only thing that keeps the description true is running execution and
//! comparing: each test below executes real DocClass transactions through
//! `DocClassExecutor::execute` — which derives its gates from `ChainParams` at
//! the block height, exactly as a block does — across unset and configured
//! parameters and on both sides of each gate, and asserts the outcome is the
//! one the reported rules predict.

mod common;

use common::{fund, setup_with_params};
use sumchain_crypto::KeyPair;
use sumchain_genesis::{ChainParams, DocClassParams};
use sumchain_primitives::{
    AcademicCredential, Address, CredentialMetadata, DocClassIssuer, DocClassIssuerStatus,
    DocClassIssuerType, DocClassOperation, DocClassTxData, DocSubcode, Hash, IssuerKey, KeyType,
    RevocationStatus,
};
use sumchain_state::DocClassExecutor;
use sumchain_storage::exec_view::ExecutionView;
use sumchain_storage::overlay::ApplicationOverlay;
use sumchain_storage::DocClassStore;

const GATE: u64 = 10;
const BELOW: u64 = GATE - 1;
const ONE_YEAR_MS: u64 = 365 * 24 * 60 * 60 * 1_000;

fn configs() -> Vec<(&'static str, Option<DocClassParams>)> {
    let with = |min: u128, require: bool, max: u64| DocClassParams {
        min_issuer_stake: min,
        require_issuer_stake: require,
        max_credential_validity: max,
        ..DocClassParams::default()
    };
    vec![
        ("unset", None),
        ("min 1000, required", Some(with(1_000, true, ONE_YEAR_MS))),
        (
            "min 1000, not required",
            Some(with(1_000, false, ONE_YEAR_MS)),
        ),
        ("min 0, required", Some(with(0, true, 0))),
    ]
}

fn chain(docclass: Option<DocClassParams>, gates: Option<u64>) -> ChainParams {
    ChainParams {
        docclass,
        docclass_issuer_stake_requirement_enabled_from_height: gates,
        docclass_credential_validity_bound_enabled_from_height: gates,
        ..ChainParams::with_v2_enabled()
    }
}

fn issuer(address: Address, stake: u128) -> DocClassIssuer {
    DocClassIssuer {
        address,
        name: "Institute of Technology".to_string(),
        issuer_type: DocClassIssuerType::Educational,
        jurisdictions: vec!["US".to_string()],
        authorized_subcodes: vec![DocSubcode::Diploma],
        keys: vec![IssuerKey {
            key_id: "k-1".to_string(),
            public_key: [0x51; 32],
            key_type: KeyType::Ed25519,
            added_at: 1_000,
            expires_at: 0,
            active: true,
            is_primary: true,
        }],
        registered_at: 1_000,
        updated_at: 1_000,
        status: DocClassIssuerStatus::Active,
        stake_amount: stake,
        metadata: None,
    }
}

fn credential(id: u8, issuer: Address, valid_from: u64, expires_at: u64) -> AcademicCredential {
    AcademicCredential {
        credential_id: [id; 32],
        subject_address: Address::ZERO,
        subcode: DocSubcode::Diploma,
        subject_commitment: [id.wrapping_add(0x40); 32],
        issuer,
        institution_id: "IOT".to_string(),
        jurisdiction: "US".to_string(),
        schema_hash: [0x71; 32],
        content_commitment: [0x72; 32],
        metadata: CredentialMetadata {
            title: "Bachelor of Science".to_string(),
            credential_type: "undergraduate_degree".to_string(),
            program: None,
            issue_date: "2024-05-15".to_string(),
            completion_date: None,
            attributes: vec![],
        },
        issued_at: 1_000,
        valid_from,
        expires_at,
        payload_hash: None,
        payload_hint: None,
        encryption_meta: None,
        issuer_signature: [0u8; 64],
        issuer_key_id: String::new(),
        revocation_status: RevocationStatus::Active,
        superseded_by: None,
    }
}

fn execute(
    params: &ChainParams,
    height: u64,
    sender: &KeyPair,
    operation: DocClassOperation,
    subcode: DocSubcode,
    payload: &impl serde::Serialize,
    seed_issuer: bool,
) -> bool {
    let (_state, db, _dir, _executor) = setup_with_params(params.clone());
    fund(&db, sender, 100_000_000);
    if seed_issuer {
        DocClassStore::new(&db)
            .issuers()
            .put(&issuer(sender.address(), 0))
            .unwrap();
    }
    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);
    DocClassExecutor::execute(
        &mut view,
        params,
        &sender.address(),
        &DocClassTxData {
            operation,
            subcode,
            data: bincode::serialize(payload).unwrap(),
            recipient: Address::ZERO,
        },
        &Address::new([9; 20]),
        100,
        height,
        1_000,
        0,
        Hash::ZERO,
    )
    .unwrap()
    .success
}

#[test]
fn the_reported_stake_rule_is_the_one_registration_enforces() {
    let (mut checked, mut refusals) = (0, 0);
    for (name, docclass) in configs() {
        for gates in [None, Some(GATE)] {
            for height in [BELOW, GATE] {
                let params = chain(docclass.clone(), gates);
                let rules = DocClassExecutor::effective_rules(&params, height);
                assert_eq!(rules.configured, docclass.is_some());
                let kp = KeyPair::generate();
                let below_min = execute(
                    &params,
                    height,
                    &kp,
                    DocClassOperation::RegisterIssuer,
                    DocSubcode::IssuerRegistry,
                    &issuer(kp.address(), 999),
                    false,
                );
                let refused = rules.issuer_stake_required && 999 < rules.min_issuer_stake;
                refusals += usize::from(refused);
                assert_eq!(
                    below_min, !refused,
                    "{name}, gate {gates:?}, height {height}: rules {rules:?}"
                );
                if rules.issuer_stake_required {
                    let kp = KeyPair::generate();
                    assert!(execute(
                        &params,
                        height,
                        &kp,
                        DocClassOperation::RegisterIssuer,
                        DocSubcode::IssuerRegistry,
                        &issuer(kp.address(), rules.min_issuer_stake),
                        false,
                    ));
                }
                checked += 1;
            }
        }
    }
    assert_eq!(checked, 16);
    assert!(
        refusals > 0 && refusals < checked,
        "both outcomes exercised"
    );
}

#[test]
fn the_reported_validity_bound_is_the_one_issuance_enforces() {
    let (mut bounded_cases, mut cases) = (0, 0);
    for (name, docclass) in configs() {
        for gates in [None, Some(GATE)] {
            for height in [BELOW, GATE] {
                let params = chain(docclass.clone(), gates);
                let rules = DocClassExecutor::effective_rules(&params, height);
                let kp = KeyPair::generate();
                let two_years = credential(0xC1, kp.address(), 1_000, 1_000 + 2 * ONE_YEAR_MS);
                let accepted = execute(
                    &params,
                    height,
                    &kp,
                    DocClassOperation::IssueCredential,
                    DocSubcode::Diploma,
                    &two_years,
                    true,
                );
                let bounded =
                    matches!(rules.max_credential_validity, Some(max) if 2 * ONE_YEAR_MS > max);
                bounded_cases += usize::from(bounded);
                cases += 1;
                assert_eq!(
                    accepted, !bounded,
                    "{name}, gate {gates:?}, height {height}: rules {rules:?}"
                );
            }
        }
    }
    assert!(
        bounded_cases > 0 && bounded_cases < cases,
        "both outcomes exercised"
    );
}

#[test]
fn an_unset_configuration_reports_no_rules_rather_than_defaults() {
    let rules = DocClassExecutor::effective_rules(&chain(None, Some(0)), 100);
    assert!(!rules.configured);
    assert!(!rules.issuer_stake_required);
    assert_eq!(rules.min_issuer_stake, 0);
    assert_eq!(rules.max_credential_validity, None);
    assert_eq!(rules.admin, None);
    // The defaults the RPC used to report are not what execution applies.
    let defaults = DocClassParams::default();
    assert!(defaults.require_issuer_stake && defaults.min_issuer_stake > 0);
}

#[test]
fn the_reported_admin_is_the_parsed_address_execution_recognises() {
    let admin = KeyPair::generate().address();
    for (raw, expected) in [
        (Some(admin.to_base58()), Some(admin)),
        (Some(hex::encode(admin.as_bytes())), Some(admin)),
        (Some("not-an-address".to_string()), None),
        (None, None),
    ] {
        let params = chain(
            Some(DocClassParams {
                admin: raw.clone(),
                ..DocClassParams::default()
            }),
            None,
        );
        assert_eq!(
            DocClassExecutor::effective_rules(&params, 1).admin,
            expected,
            "{raw:?}"
        );
    }
}
