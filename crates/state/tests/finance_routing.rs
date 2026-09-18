//! SRC-89X finance executes against the block's candidate.
//!
//! Real signed transactions through `BlockExecutor`, in sequence, in one block.
//! Every finance operation is a read-then-write -- a duplicate guard on every
//! registration, an existence check on every update, and a REGISTERED, ACTIVE,
//! correctly-classed issuer required before any credential is issued -- and all
//! of those reads were committed reads, correct only because the matching
//! writes committed as they went.
//!
//! Four of the nine families are ACCUMULATING indexes (`Vec<Address>` for the
//! jurisdiction index, `Vec<[u8; 32]>` for the three subject indexes). Each
//! append is a read-modify-write, so two entries for one subject in a block are
//! the sharpest same-block proof this subsystem has: against committed state
//! the second would read an empty list and erase the first.
//!
//! ## Behaviours this suite PINS rather than fixes
//!
//! * `UpdateIssuer` lets an issuer set its own status to anything, including
//!   `Active` from `Revoked` -- which is the guard `ReactivateIssuer` exists to
//!   enforce, bypassed.
//! * A status change never rewrites the jurisdiction index, so a revoked issuer
//!   stays listed under its jurisdiction.
//! * `SubmitProof` checks nothing at all: no issuer, no credential, no
//!   signature.
//! * `VerifyProof` charges a fee and verifies nothing.
//! * Every `exists` guard is a presence check, not a decode, so a CORRUPT row
//!   reads as present and refuses the transaction as a duplicate.
//!
//! All predate this commit and are reproduced exactly. They are pinned here so
//! that changing any of them is a deliberate act with a failing test attached,
//! not a silent correction inside a migration.

mod common;

use common::{fund, setup_with_params, CHAIN_ID};
use std::sync::Arc;
use sumchain_crypto::{sign, KeyPair};
use sumchain_genesis::ChainParams;
use sumchain_primitives::finance::{
    AccountStanding, AccountType, AddressProof, AddressProofType, AmlRisk, BalanceBracket,
    BankStandingCredential, FinanceIssuerClass, FinanceIssuerProfile, FinanceIssuerStatus,
    FinanceOperation, FinanceProofEnvelope, FinanceProofType, FinanceTxData, KycAttestation,
    KycLevel, KycStatus,
};
use sumchain_primitives::{Address, SignedTransaction, TransactionV2, TxPayload, TxStatus};
use sumchain_state::executor::BlockExecutor;
use sumchain_state::{FinanceExecutor, StateManager};
use sumchain_storage::exec_view::ExecutionView;
use sumchain_storage::overlay::ApplicationOverlay;
use sumchain_storage::{cf, Database, FinanceStore};
use tempfile::TempDir;

/// Every family this unit moved. Nine.
const FINANCE_CFS: &[&str] = &[
    cf::FINANCE_ISSUERS,
    cf::FINANCE_JURISDICTION_INDEX,
    cf::FINANCE_ADDRESS_PROOFS,
    cf::FINANCE_SUBJECT_ADDRESS_INDEX,
    cf::FINANCE_BANK_STANDINGS,
    cf::FINANCE_SUBJECT_BANK_INDEX,
    cf::FINANCE_KYC_ATTESTATIONS,
    cf::FINANCE_SUBJECT_KYC_INDEX,
    cf::FINANCE_PROOFS,
];

/// The dispatcher's finance refusal code. Pinning it is what keeps a negative
/// control honest: any non-success status would also be satisfied by a bad
/// nonce, an insufficient balance or a malformed payload.
const FINANCE_FAILED: TxStatus = TxStatus::Failed(16);

const JURISDICTION: &str = "US-NY";

fn params() -> ChainParams {
    ChainParams::with_v2_enabled()
}

fn tx_data(op: FinanceOperation, payload: &impl serde::Serialize) -> FinanceTxData {
    FinanceTxData {
        operation: op,
        data: bincode::serialize(payload).unwrap(),
        recipient: Address::ZERO,
    }
}

fn signed(
    kp: &KeyPair,
    nonce: u64,
    op: FinanceOperation,
    payload: &impl serde::Serialize,
) -> SignedTransaction {
    let tx = TransactionV2 {
        chain_id: CHAIN_ID,
        from: kp.address(),
        fee: 100,
        nonce,
        payload: TxPayload::Finance(tx_data(op, payload)),
    };
    let h = tx.signing_hash();
    let sig = sign(h.as_bytes(), kp.private_key());
    SignedTransaction::new_v2(tx, *sig.as_bytes(), *kp.public_key().as_bytes())
}

// ── Fixtures ─────────────────────────────────────────────────────────────────

fn issuer_of(kp: &KeyPair, class: FinanceIssuerClass) -> FinanceIssuerProfile {
    FinanceIssuerProfile {
        issuer_address: kp.address(),
        issuer_class: class,
        issuer_commitment: [2u8; 32],
        jurisdiction_code: JURISDICTION.to_string(),
        policy_id: [3u8; 32],
        status: FinanceIssuerStatus::Active,
        registered_at_height: 1,
        created_at: 1_000,
        updated_at: 1_000,
    }
}

fn bank(kp: &KeyPair) -> FinanceIssuerProfile {
    issuer_of(kp, FinanceIssuerClass::RegulatedBank)
}

fn address_proof(kp: &KeyPair, id: u8, subject: [u8; 32]) -> AddressProof {
    AddressProof {
        proof_id: [id; 32],
        subject_ref: subject,
        holder_address: Address::new([0x30; 20]),
        address_commitment: [6u8; 32],
        jurisdiction_code: JURISDICTION.to_string(),
        postal_commitment: [7u8; 32],
        proof_type: AddressProofType::UtilityBill,
        document_date: 900,
        issuer_address: kp.address(),
        issuer_class: FinanceIssuerClass::RegulatedBank,
        valid_from: 1_000,
        expiry: 2_000,
        policy_id: [9u8; 32],
        revocation_ref: None,
        created_at: 1_000,
        updated_at: 1_000,
    }
}

fn bank_standing(kp: &KeyPair, id: u8, subject: [u8; 32]) -> BankStandingCredential {
    BankStandingCredential {
        credential_id: [id; 32],
        subject_ref: subject,
        holder_address: Address::new([0x31; 20]),
        account_commitment: [12u8; 32],
        bank_ref: [13u8; 32],
        account_type: AccountType::Checking,
        standing: AccountStanding::Good,
        tenure_commitment: [14u8; 32],
        balance_bracket: BalanceBracket::Bracket5,
        threshold_commitment: None,
        issuer_address: kp.address(),
        issuer_class: FinanceIssuerClass::RegulatedBank,
        valid_from: 1_000,
        expiry: 2_000,
        policy_id: [16u8; 32],
        revocation_ref: None,
        created_at: 1_000,
        updated_at: 1_000,
    }
}

fn kyc(kp: &KeyPair, id: u8, subject: [u8; 32]) -> KycAttestation {
    KycAttestation {
        attestation_id: [id; 32],
        subject_ref: subject,
        holder_address: Address::new([0x32; 20]),
        kyc_level: KycLevel::Enhanced,
        aml_risk: AmlRisk::Low,
        identity_commitment: [19u8; 32],
        subject_jurisdiction: "US".to_string(),
        methods_commitment: [20u8; 32],
        status: KycStatus::Active,
        issuer_address: kp.address(),
        issuer_class: FinanceIssuerClass::RegulatedBank,
        valid_from: 1_000,
        expiry: 2_000,
        policy_id: [22u8; 32],
        revocation_ref: None,
        created_at: 1_000,
        updated_at: 1_000,
    }
}

fn proof_envelope(id: u8) -> FinanceProofEnvelope {
    FinanceProofEnvelope {
        proof_id: [id; 32],
        profile_id: [24u8; 32],
        proof_type: FinanceProofType::KycLevelAchieved,
        subject_nullifier: [25u8; 32],
        proof_data: vec![9, 9, 9],
        public_inputs_commitment: [26u8; 32],
        credential_refs: vec![],
        source_issuer_class: FinanceIssuerClass::RegulatedBank,
        policy_id: [27u8; 32],
        valid_from: 1_000,
        expiry: 2_000,
        created_at: 1_000,
    }
}

#[derive(serde::Serialize)]
struct UpdateIssuerData {
    status: FinanceIssuerStatus,
}

#[derive(serde::Serialize)]
struct RevokeAddressProofData {
    proof_id: [u8; 32],
    revocation_ref: [u8; 32],
}

#[derive(serde::Serialize)]
struct UpdateBankStandingData {
    credential_id: [u8; 32],
    standing: AccountStanding,
}

#[derive(serde::Serialize)]
struct RevokeBankStandingData {
    credential_id: [u8; 32],
    revocation_ref: [u8; 32],
}

#[derive(serde::Serialize)]
struct UpdateKycData {
    attestation_id: [u8; 32],
    status: KycStatus,
}

#[derive(serde::Serialize)]
struct RevokeKycData {
    attestation_id: [u8; 32],
    revocation_ref: [u8; 32],
}

// ── Canonical / candidate comparison ─────────────────────────────────────────

fn canonical(db: &Database) -> Vec<(String, Vec<u8>, Vec<u8>)> {
    let mut out = Vec::new();
    for f in FINANCE_CFS {
        for (k, v) in db.prefix_iter(f, &[]).unwrap() {
            out.push((f.to_string(), k.to_vec(), v.to_vec()));
        }
    }
    out.sort();
    out
}

/// Families whose CANDIDATE contents differ from the committed ones.
///
/// Not a presence check on the view: `prefix_iter` is MERGED, so a family with
/// a committed row reads as non-empty whether or not this block touched it.
/// Several tests here pre-seed a canonical issuer, which would make a presence
/// check report a change for every ceiling including the ones that staged
/// nothing at all.
fn families_changed(db: &Database, view: &ExecutionView<'_, '_>) -> Vec<&'static str> {
    let mut out = Vec::new();
    for f in FINANCE_CFS {
        let committed: Vec<(Vec<u8>, Vec<u8>)> = db
            .prefix_iter(f, &[])
            .unwrap()
            .map(|(k, v)| (k.to_vec(), v.to_vec()))
            .collect();
        let staged: Vec<(Vec<u8>, Vec<u8>)> = view
            .prefix_iter(f, &[])
            .unwrap()
            .map(|r| {
                let (k, v) = r.unwrap();
                (k.to_vec(), v.to_vec())
            })
            .collect();
        if committed != staged {
            out.push(*f);
        }
    }
    out
}

// ── Same-block visibility ────────────────────────────────────────────────────

/// A KYC attestation issued later in the block finds the issuer registered
/// earlier in it.
///
/// `CreateKycAttestation` requires a REGISTERED, ACTIVE issuer of a class
/// permitted to issue KYC. Against committed state that read answers from the
/// parent block, so the registration would be invisible and the attestation
/// refused.
#[test]
fn an_attestation_finds_an_issuer_registered_earlier_in_the_same_block() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let issuer = KeyPair::generate();
    fund(&db, &issuer, 10_000_000);
    let proposer = Address::new([9; 20]);

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);

    let r0 = executor
        .execute_tx(
            &mut view,
            &signed(&issuer, 0, FinanceOperation::RegisterIssuer, &bank(&issuer)),
            &proposer,
            1,
            1000,
        )
        .unwrap();
    assert!(matches!(r0.status, TxStatus::Success), "{:?}", r0.status);

    let r1 = executor
        .execute_tx(
            &mut view,
            &signed(
                &issuer,
                1,
                FinanceOperation::CreateKycAttestation,
                &kyc(&issuer, 1, [0xAB; 32]),
            ),
            &proposer,
            1,
            1000,
        )
        .unwrap();
    assert!(
        matches!(r1.status, TxStatus::Success),
        "the attestation must find the issuer this block registered: {:?}",
        r1.status
    );
    assert!(
        FinanceExecutor::v_get_kyc_attestation(&view, &[1u8; 32])
            .unwrap()
            .is_some(),
        "and stage the attestation"
    );
}

/// Without the registration, the same attestation is refused.
///
/// The discriminator: the test above would pass on any block in which
/// attestations happen to succeed.
#[test]
fn without_the_registration_the_same_attestation_is_refused() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let issuer = KeyPair::generate();
    fund(&db, &issuer, 10_000_000);
    let proposer = Address::new([9; 20]);

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);
    let r = executor
        .execute_tx(
            &mut view,
            &signed(
                &issuer,
                0,
                FinanceOperation::CreateKycAttestation,
                &kyc(&issuer, 1, [0xAB; 32]),
            ),
            &proposer,
            1,
            1000,
        )
        .unwrap();
    // Failed(16) is "finance operation failed": the transaction REACHED the
    // finance executor and its guard refused it. Accepting any non-success
    // would let an invalid nonce, an insufficient balance or a malformed
    // payload stand in for the guard this test is about.
    assert_eq!(
        r.status, FINANCE_FAILED,
        "an attestation from an unregistered issuer must fail IN the finance \
         executor"
    );
    assert!(
        families_changed(&db, &view).is_empty(),
        "and change nothing at all"
    );
    assert_eq!(
        StateManager::v_get_nonce(&view, &issuer.address()).unwrap(),
        0,
        "a refused finance operation does not advance the account nonce"
    );
}

/// An issuer suspended earlier in the block cannot issue later in it.
///
/// The read has to see the candidate in BOTH directions: a registration made
/// visible, and a suspension made visible.
#[test]
fn a_suspension_earlier_in_the_block_refuses_a_later_attestation() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let issuer = KeyPair::generate();
    fund(&db, &issuer, 10_000_000);
    let proposer = Address::new([9; 20]);
    FinanceStore::new(&db)
        .issuers()
        .put(&bank(&issuer))
        .unwrap();

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);

    let r0 = executor
        .execute_tx(
            &mut view,
            &signed(&issuer, 0, FinanceOperation::SuspendIssuer, &()),
            &proposer,
            1,
            1000,
        )
        .unwrap();
    assert!(matches!(r0.status, TxStatus::Success), "{:?}", r0.status);

    let r1 = executor
        .execute_tx(
            &mut view,
            &signed(
                &issuer,
                1,
                FinanceOperation::CreateKycAttestation,
                &kyc(&issuer, 1, [0xAB; 32]),
            ),
            &proposer,
            1,
            1000,
        )
        .unwrap();
    assert_eq!(
        r1.status, FINANCE_FAILED,
        "a suspension staged earlier in this block must refuse the attestation"
    );
    assert!(
        FinanceExecutor::v_get_kyc_attestation(&view, &[1u8; 32])
            .unwrap()
            .is_none(),
        "and nothing is staged for it"
    );
    assert_eq!(
        StateManager::v_get_nonce(&view, &issuer.address()).unwrap(),
        1,
        "one suspension charged a nonce, the refusal did not"
    );
}

/// The same attestation succeeds when the issuer is left ACTIVE: the
/// discriminating control for the suspension above.
#[test]
fn without_the_suspension_the_same_attestation_succeeds() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let issuer = KeyPair::generate();
    fund(&db, &issuer, 10_000_000);
    let proposer = Address::new([9; 20]);
    FinanceStore::new(&db)
        .issuers()
        .put(&bank(&issuer))
        .unwrap();

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);
    let r = executor
        .execute_tx(
            &mut view,
            &signed(
                &issuer,
                0,
                FinanceOperation::CreateKycAttestation,
                &kyc(&issuer, 1, [0xAB; 32]),
            ),
            &proposer,
            1,
            1000,
        )
        .unwrap();
    assert!(matches!(r.status, TxStatus::Success), "{:?}", r.status);
}

/// A revocation finds the credential created earlier in the same block.
#[test]
fn a_revocation_finds_the_address_proof_created_earlier_in_the_same_block() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let issuer = KeyPair::generate();
    fund(&db, &issuer, 10_000_000);
    let proposer = Address::new([9; 20]);
    FinanceStore::new(&db)
        .issuers()
        .put(&bank(&issuer))
        .unwrap();

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);

    let r0 = executor
        .execute_tx(
            &mut view,
            &signed(
                &issuer,
                0,
                FinanceOperation::CreateAddressProof,
                &address_proof(&issuer, 1, [0xCD; 32]),
            ),
            &proposer,
            1,
            1000,
        )
        .unwrap();
    assert!(matches!(r0.status, TxStatus::Success), "{:?}", r0.status);

    let r1 = executor
        .execute_tx(
            &mut view,
            &signed(
                &issuer,
                1,
                FinanceOperation::RevokeAddressProof,
                &RevokeAddressProofData {
                    proof_id: [1u8; 32],
                    revocation_ref: [0xEE; 32],
                },
            ),
            &proposer,
            1,
            1000,
        )
        .unwrap();
    assert!(
        matches!(r1.status, TxStatus::Success),
        "the revocation must find the proof this block created: {:?}",
        r1.status
    );
    assert_eq!(
        FinanceExecutor::v_get_address_proof(&view, &[1u8; 32])
            .unwrap()
            .unwrap()
            .revocation_ref,
        Some([0xEE; 32]),
        "and the staged proof must carry the revocation ref"
    );
}

/// Without the creation, the same revocation is refused.
#[test]
fn without_the_creation_the_same_revocation_is_refused() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let issuer = KeyPair::generate();
    fund(&db, &issuer, 10_000_000);
    let proposer = Address::new([9; 20]);
    FinanceStore::new(&db)
        .issuers()
        .put(&bank(&issuer))
        .unwrap();

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);
    let r = executor
        .execute_tx(
            &mut view,
            &signed(
                &issuer,
                0,
                FinanceOperation::RevokeAddressProof,
                &RevokeAddressProofData {
                    proof_id: [1u8; 32],
                    revocation_ref: [0xEE; 32],
                },
            ),
            &proposer,
            1,
            1000,
        )
        .unwrap();
    assert_eq!(
        r.status, FINANCE_FAILED,
        "revoking a proof that does not exist must fail in the finance executor"
    );
    assert!(families_changed(&db, &view).is_empty(), "and stage nothing");
    assert_eq!(
        StateManager::v_get_nonce(&view, &issuer.address()).unwrap(),
        0
    );
}

// ── Same-block duplicate refusal ─────────────────────────────────────────────

/// Two registrations of the same issuer in one block: the second is refused by
/// a guard that reads the candidate.
#[test]
fn a_duplicate_issuer_registration_in_the_same_block_is_refused() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let issuer = KeyPair::generate();
    fund(&db, &issuer, 10_000_000);
    let proposer = Address::new([9; 20]);

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);

    for (nonce, expect) in [(0u64, true), (1u64, false)] {
        let r = executor
            .execute_tx(
                &mut view,
                &signed(
                    &issuer,
                    nonce,
                    FinanceOperation::RegisterIssuer,
                    &bank(&issuer),
                ),
                &proposer,
                1,
                1000,
            )
            .unwrap();
        if expect {
            assert!(
                matches!(r.status, TxStatus::Success),
                "the first registration must succeed: {:?}",
                r.status
            );
        } else {
            assert_eq!(
                r.status, FINANCE_FAILED,
                "the duplicate must be refused BY THE FINANCE GUARD, not \
                 rejected earlier for some unrelated reason"
            );
        }
    }
    // The account nonce advanced exactly once: the refused duplicate did not
    // charge one, so a nonce error cannot be what refused it.
    assert_eq!(
        StateManager::v_get_nonce(&view, &issuer.address()).unwrap(),
        1,
        "one successful registration, one refusal"
    );

    let rows: Vec<_> = view
        .prefix_iter(cf::FINANCE_ISSUERS, &[])
        .unwrap()
        .map(|r| r.unwrap())
        .collect();
    assert_eq!(rows.len(), 1, "the duplicate must not leave a second row");
}

/// The same for a credential: two attestations with one id, one block.
#[test]
fn a_duplicate_attestation_id_in_the_same_block_is_refused() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let issuer = KeyPair::generate();
    fund(&db, &issuer, 10_000_000);
    let proposer = Address::new([9; 20]);
    FinanceStore::new(&db)
        .issuers()
        .put(&bank(&issuer))
        .unwrap();

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);

    let r0 = executor
        .execute_tx(
            &mut view,
            &signed(
                &issuer,
                0,
                FinanceOperation::CreateKycAttestation,
                &kyc(&issuer, 1, [0xAB; 32]),
            ),
            &proposer,
            1,
            1000,
        )
        .unwrap();
    assert!(matches!(r0.status, TxStatus::Success), "{:?}", r0.status);

    // Same id, different subject: only the id-duplicate guard can refuse it.
    let r1 = executor
        .execute_tx(
            &mut view,
            &signed(
                &issuer,
                1,
                FinanceOperation::CreateKycAttestation,
                &kyc(&issuer, 1, [0xBC; 32]),
            ),
            &proposer,
            1,
            1000,
        )
        .unwrap();
    assert_eq!(r1.status, FINANCE_FAILED);
    assert_eq!(
        StateManager::v_get_nonce(&view, &issuer.address()).unwrap(),
        1
    );
    assert!(
        FinanceExecutor::v_get_subject_kyc_ids(&view, &[0xBC; 32])
            .unwrap()
            .is_empty(),
        "and the refused duplicate indexed nothing under its own subject"
    );
}

// ── The accumulating indexes ─────────────────────────────────────────────────

/// Two KYC attestations for one subject in the same block: the index holds
/// BOTH ids.
///
/// The subject index value is an accumulating `Vec<[u8; 32]>`. Reading it from
/// committed state would give the second attestation an empty list, and it
/// would overwrite the first one's entry with a single-element one.
#[test]
fn two_attestations_for_one_subject_accumulate_in_the_kyc_index() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let issuer = KeyPair::generate();
    fund(&db, &issuer, 10_000_000);
    let proposer = Address::new([9; 20]);
    let subject = [0xAB; 32];
    FinanceStore::new(&db)
        .issuers()
        .put(&bank(&issuer))
        .unwrap();

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);

    for (nonce, id) in [(0u64, 1u8), (1u64, 2u8)] {
        let r = executor
            .execute_tx(
                &mut view,
                &signed(
                    &issuer,
                    nonce,
                    FinanceOperation::CreateKycAttestation,
                    &kyc(&issuer, id, subject),
                ),
                &proposer,
                1,
                1000,
            )
            .unwrap();
        assert!(matches!(r.status, TxStatus::Success), "{:?}", r.status);
    }

    assert_eq!(
        FinanceExecutor::v_get_subject_kyc_ids(&view, &subject).unwrap(),
        vec![[1u8; 32], [2u8; 32]],
        "both attestation ids, in issue order -- the second must have seen the \
         first"
    );
}

/// The same, for the address-proof subject index.
#[test]
fn two_address_proofs_for_one_subject_accumulate_in_the_address_index() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let issuer = KeyPair::generate();
    fund(&db, &issuer, 10_000_000);
    let proposer = Address::new([9; 20]);
    let subject = [0xCD; 32];
    FinanceStore::new(&db)
        .issuers()
        .put(&bank(&issuer))
        .unwrap();

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);

    for (nonce, id) in [(0u64, 3u8), (1u64, 4u8)] {
        let r = executor
            .execute_tx(
                &mut view,
                &signed(
                    &issuer,
                    nonce,
                    FinanceOperation::CreateAddressProof,
                    &address_proof(&issuer, id, subject),
                ),
                &proposer,
                1,
                1000,
            )
            .unwrap();
        assert!(matches!(r.status, TxStatus::Success), "{:?}", r.status);
    }

    assert_eq!(
        FinanceExecutor::v_get_subject_address_proof_ids(&view, &subject).unwrap(),
        vec![[3u8; 32], [4u8; 32]]
    );
}

/// The same, for the bank-standing subject index.
#[test]
fn two_bank_standings_for_one_subject_accumulate_in_the_bank_index() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let issuer = KeyPair::generate();
    fund(&db, &issuer, 10_000_000);
    let proposer = Address::new([9; 20]);
    let subject = [0xDE; 32];
    FinanceStore::new(&db)
        .issuers()
        .put(&bank(&issuer))
        .unwrap();

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);

    for (nonce, id) in [(0u64, 5u8), (1u64, 6u8)] {
        let r = executor
            .execute_tx(
                &mut view,
                &signed(
                    &issuer,
                    nonce,
                    FinanceOperation::CreateBankStanding,
                    &bank_standing(&issuer, id, subject),
                ),
                &proposer,
                1,
                1000,
            )
            .unwrap();
        assert!(matches!(r.status, TxStatus::Success), "{:?}", r.status);
    }

    assert_eq!(
        FinanceExecutor::v_get_subject_bank_standing_ids(&view, &subject).unwrap(),
        vec![[5u8; 32], [6u8; 32]]
    );
}

/// Two issuers registering into one jurisdiction in the same block: the
/// jurisdiction index holds BOTH addresses.
///
/// This is the fourth accumulating index, and the only one keyed by a string
/// rather than a 32-byte ref.
#[test]
fn two_issuers_in_one_jurisdiction_accumulate_in_the_jurisdiction_index() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let a = KeyPair::generate();
    let b = KeyPair::generate();
    fund(&db, &a, 10_000_000);
    fund(&db, &b, 10_000_000);
    let proposer = Address::new([9; 20]);

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);

    for kp in [&a, &b] {
        let r = executor
            .execute_tx(
                &mut view,
                &signed(kp, 0, FinanceOperation::RegisterIssuer, &bank(kp)),
                &proposer,
                1,
                1000,
            )
            .unwrap();
        assert!(matches!(r.status, TxStatus::Success), "{:?}", r.status);
    }

    assert_eq!(
        FinanceExecutor::v_get_jurisdiction_issuer_addresses(&view, JURISDICTION).unwrap(),
        vec![a.address(), b.address()],
        "both issuer addresses, in registration order -- the second must have \
         seen the first"
    );
}

// ── Abandonment ──────────────────────────────────────────────────────────────

/// A block touching all nine families commits none of it.
#[test]
fn an_abandoned_block_leaves_all_nine_families_untouched() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let issuer = KeyPair::generate();
    fund(&db, &issuer, 100_000_000);
    let proposer = Address::new([9; 20]);
    let before = canonical(&db);

    {
        let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
        let mut view = ExecutionView::new(&mut overlay);

        let steps: Vec<(u64, FinanceOperation, Vec<u8>)> = vec![
            (
                0,
                FinanceOperation::RegisterIssuer,
                bincode::serialize(&bank(&issuer)).unwrap(),
            ),
            (
                1,
                FinanceOperation::CreateAddressProof,
                bincode::serialize(&address_proof(&issuer, 1, [0xC1; 32])).unwrap(),
            ),
            (
                2,
                FinanceOperation::CreateBankStanding,
                bincode::serialize(&bank_standing(&issuer, 2, [0xC2; 32])).unwrap(),
            ),
            (
                3,
                FinanceOperation::CreateKycAttestation,
                bincode::serialize(&kyc(&issuer, 3, [0xC3; 32])).unwrap(),
            ),
            (
                4,
                FinanceOperation::SubmitProof,
                bincode::serialize(&proof_envelope(4)).unwrap(),
            ),
        ];
        for (nonce, op, data) in steps {
            let tx = TransactionV2 {
                chain_id: CHAIN_ID,
                from: issuer.address(),
                fee: 100,
                nonce,
                payload: TxPayload::Finance(FinanceTxData {
                    operation: op,
                    data,
                    recipient: Address::ZERO,
                }),
            };
            let h = tx.signing_hash();
            let sig = sign(h.as_bytes(), issuer.private_key());
            let tx =
                SignedTransaction::new_v2(tx, *sig.as_bytes(), *issuer.public_key().as_bytes());
            let r = executor
                .execute_tx(&mut view, &tx, &proposer, 1, 1000)
                .unwrap();
            assert!(
                matches!(r.status, TxStatus::Success),
                "seeding {op:?} must succeed: {:?}",
                r.status
            );
        }

        // Per family, individually, against a real DIFF -- not a presence
        // check on the merged view.
        let touched = families_changed(&db, &view);
        for f in FINANCE_CFS {
            assert!(
                touched.contains(f),
                "{f} was not staged, so dropping the block proves nothing about it"
            );
        }
        // dropped
    }

    assert_eq!(
        canonical(&db),
        before,
        "an abandoned block must leave every finance row byte-identical"
    );
}

// ── Limit refusal ────────────────────────────────────────────────────────────

/// A refusal leaves canonical storage untouched, and at least one ceiling
/// refuses with the attestation staged and its index entry not.
///
/// The operation has to write more than one row for a genuine partial to be
/// reachable at all: the fee, proposer credit and nonce writes come first, so a
/// ceiling either refuses during the account writes -- nothing finance staged
/// -- or fits the whole transaction. `CreateKycAttestation` writes two, the
/// attestation and its subject-index entry, so a ceiling can land between them.
///
/// The partial is asserted as EXACT state rather than "some family is
/// non-empty": the attestation readable through the view, the index row not,
/// and the canonical rows unchanged. Both families start canonically empty
/// (only the issuer is seeded), so a row readable through the merged view can
/// only have come from the candidate.
///
/// EVERY ceiling below the measured cost is tried, not a stepped sample: the
/// interval between the two writes is a handful of bytes wide, and a stepped
/// sweep can step straight over it.
#[test]
fn a_refusal_leaves_canonical_storage_untouched() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let issuer = KeyPair::generate();
    fund(&db, &issuer, 100_000_000);
    let proposer = Address::new([9; 20]);
    // The issuer is committed, the way an earlier block would have left it, so
    // this transaction's only finance writes are the attestation and its index.
    FinanceStore::new(&db)
        .issuers()
        .put(&bank(&issuer))
        .unwrap();
    let subject = [0x33; 32];
    let before = canonical(&db);

    assert!(
        db.prefix_iter(cf::FINANCE_KYC_ATTESTATIONS, &[])
            .unwrap()
            .next()
            .is_none()
            && db
                .prefix_iter(cf::FINANCE_SUBJECT_KYC_INDEX, &[])
                .unwrap()
                .next()
                .is_none(),
        "attestations and the KYC subject index must start empty for this test \
         to read the candidate through the merged view"
    );

    let tx = signed(
        &issuer,
        0,
        FinanceOperation::CreateKycAttestation,
        &kyc(&issuer, 1, subject),
    );
    let full = {
        let mut scratch = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
        {
            let mut view = ExecutionView::new(&mut scratch);
            executor
                .execute_tx(&mut view, &tx, &proposer, 1, 1000)
                .unwrap();
        }
        scratch.logical_bytes()
    };
    assert!(full > 1, "an attestation must cost something");

    let mut partials = 0usize;
    for ceiling in 1..full {
        let mut overlay = ApplicationOverlay::new(&db, ceiling);
        let mut view = ExecutionView::new(&mut overlay);
        let outcome = executor.execute_tx(&mut view, &tx, &proposer, 1, 1000);
        assert!(outcome.is_err(), "ceiling {ceiling} must refuse");
        assert!(
            outcome.unwrap_err().to_string().contains("limit"),
            "ceiling {ceiling} must fail because a WRITE was refused"
        );

        let attestation_staged = view
            .get(cf::FINANCE_KYC_ATTESTATIONS, &[1u8; 32])
            .unwrap()
            .is_some();
        let index_staged = view
            .get(cf::FINANCE_SUBJECT_KYC_INDEX, &subject)
            .unwrap()
            .is_some();
        if attestation_staged && !index_staged {
            partials += 1;
        }
        assert!(
            !index_staged || attestation_staged,
            "ceiling {ceiling} staged the index without the attestation, which \
             no order of these two writes can produce"
        );
        assert_eq!(
            canonical(&db),
            before,
            "ceiling {ceiling} must leave canonical storage as it was"
        );
    }

    assert!(
        partials > 0,
        "no ceiling refused with the attestation staged and the index not -- \
         either the two writes stopped being separate, or this sweep stopped \
         covering the interval between them"
    );
}

// ── Index parity ─────────────────────────────────────────────────────────────

/// Published rows satisfy every committed point lookup and scan the RPC uses.
#[test]
fn published_rows_satisfy_the_committed_scans() {
    let (state, db, _dir, executor) = setup_with_params(params());
    let issuer = KeyPair::generate();
    fund(&db, &issuer, 100_000_000);
    let subject = [0xEF; 32];

    let receipts = common::publish_block(
        &state,
        &executor,
        1,
        &[3u8; 32],
        vec![
            signed(&issuer, 0, FinanceOperation::RegisterIssuer, &bank(&issuer)),
            signed(
                &issuer,
                1,
                FinanceOperation::CreateAddressProof,
                &address_proof(&issuer, 1, subject),
            ),
            signed(
                &issuer,
                2,
                FinanceOperation::CreateBankStanding,
                &bank_standing(&issuer, 2, subject),
            ),
            signed(
                &issuer,
                3,
                FinanceOperation::CreateKycAttestation,
                &kyc(&issuer, 3, subject),
            ),
            signed(
                &issuer,
                4,
                FinanceOperation::SubmitProof,
                &proof_envelope(4),
            ),
        ],
        &[],
    );
    assert!(
        receipts
            .iter()
            .all(|r| matches!(r.status, TxStatus::Success)),
        "all five must succeed: {:?}",
        receipts.iter().map(|r| r.status).collect::<Vec<_>>()
    );

    let store = FinanceStore::new(&db);

    // Issuers: point lookup, existence, the active scan, the jurisdiction index.
    assert_eq!(
        store
            .issuers()
            .get(&issuer.address())
            .unwrap()
            .map(|i| i.issuer_address),
        Some(issuer.address()),
        "the issuer point lookup"
    );
    assert!(store.issuers().exists(&issuer.address()).unwrap());
    assert_eq!(store.issuers().list_active().unwrap().len(), 1);
    assert_eq!(
        store
            .issuers()
            .get_by_jurisdiction(JURISDICTION)
            .unwrap()
            .into_iter()
            .map(|i| i.issuer_address)
            .collect::<Vec<_>>(),
        vec![issuer.address()],
        "the jurisdiction index, which the candidate wrote"
    );

    // Address proofs: point lookup and both subject scans.
    assert_eq!(
        store
            .address_proofs()
            .get(&[1u8; 32])
            .unwrap()
            .map(|p| p.proof_id),
        Some([1u8; 32])
    );
    assert_eq!(
        store
            .address_proofs()
            .get_by_subject(&subject)
            .unwrap()
            .into_iter()
            .map(|p| p.proof_id)
            .collect::<Vec<_>>(),
        vec![[1u8; 32]]
    );
    assert_eq!(
        store
            .address_proofs()
            .get_valid_by_subject(&subject, 1_500)
            .unwrap()
            .len(),
        1
    );

    // Bank standings.
    assert_eq!(
        store
            .bank_standings()
            .get(&[2u8; 32])
            .unwrap()
            .map(|c| c.credential_id),
        Some([2u8; 32])
    );
    assert_eq!(
        store
            .bank_standings()
            .get_by_subject(&subject)
            .unwrap()
            .into_iter()
            .map(|c| c.credential_id)
            .collect::<Vec<_>>(),
        vec![[2u8; 32]]
    );
    assert_eq!(
        store
            .bank_standings()
            .get_valid_by_subject(&subject, 1_500)
            .unwrap()
            .len(),
        1
    );

    // KYC attestations.
    assert_eq!(
        store
            .kyc_attestations()
            .get(&[3u8; 32])
            .unwrap()
            .map(|a| a.attestation_id),
        Some([3u8; 32])
    );
    assert_eq!(
        store
            .kyc_attestations()
            .get_by_subject(&subject)
            .unwrap()
            .into_iter()
            .map(|a| a.attestation_id)
            .collect::<Vec<_>>(),
        vec![[3u8; 32]]
    );
    assert_eq!(
        store
            .kyc_attestations()
            .get_valid_by_subject(&subject, 1_500)
            .unwrap()
            .len(),
        1
    );

    // Proofs: point lookup, existence, validity.
    assert_eq!(
        store.proofs().get(&[4u8; 32]).unwrap().map(|p| p.proof_id),
        Some([4u8; 32])
    );
    assert!(store.proofs().exists(&[4u8; 32]).unwrap());
    assert!(store.proofs().is_valid(&[4u8; 32], 1_500).unwrap());
}

// ── Malformed committed rows ─────────────────────────────────────────────────

/// A malformed row makes the routed transaction ERROR; it is never read as
/// absence, and nothing is COMMITTED.
///
/// The name says COMMIT and not STAGE deliberately. Three of these cases DO
/// leave a staged row behind -- every `Create*` writes its primary row before
/// it appends to the subject index, so a malformed index row fails after the
/// primary is already in the candidate. Naming this "stage nothing" would
/// claim a guarantee the assertions below do not make; what they make is that
/// the error propagates, that canonical state is untouched, and that the
/// staged residue is confined to a set named per case.
///
/// This is the difference between "no issuer registered" and "the issuer row is
/// corrupt", and the guards branch on exactly that. A candidate reader that
/// swallowed a decode failure into `None` would turn corruption into a
/// duplicate-registration opportunity, or into a credential issued by an issuer
/// whose status could not be read. The `v_get_*` readers propagate, and these
/// prove it through real dispatch rather than by calling the accessor.
///
/// One family is missing from this list on purpose: `FINANCE_PROOFS` is read
/// only by a presence check, so corruption there is not a decode at all. It is
/// pinned separately below.
#[test]
fn malformed_rows_error_through_dispatch_and_commit_nothing() {
    for (family, key, label) in [
        (cf::FINANCE_ISSUERS, Vec::new(), "issuer"),
        (
            cf::FINANCE_JURISDICTION_INDEX,
            JURISDICTION.as_bytes().to_vec(),
            "jurisdiction index",
        ),
        (cf::FINANCE_ADDRESS_PROOFS, vec![1u8; 32], "address proof"),
        (
            cf::FINANCE_SUBJECT_ADDRESS_INDEX,
            vec![0xC1u8; 32],
            "address subject index",
        ),
        (cf::FINANCE_BANK_STANDINGS, vec![2u8; 32], "bank standing"),
        (
            cf::FINANCE_SUBJECT_BANK_INDEX,
            vec![0xC2u8; 32],
            "bank subject index",
        ),
        (
            cf::FINANCE_KYC_ATTESTATIONS,
            vec![3u8; 32],
            "kyc attestation",
        ),
        (
            cf::FINANCE_SUBJECT_KYC_INDEX,
            vec![0xC3u8; 32],
            "kyc subject index",
        ),
    ] {
        let (_state, db, _dir, executor) = setup_with_params(params());
        let actor = KeyPair::generate();
        fund(&db, &actor, 100_000_000);
        let proposer = Address::new([9; 20]);

        // The issuer family is keyed by the actor's address, which is only
        // known here.
        let key = if key.is_empty() {
            actor.address().as_bytes().to_vec()
        } else {
            key
        };

        // Everything except the two issuer-family cases needs a VALID committed
        // issuer, or the transaction would be refused before it reaches the
        // corrupt row.
        if family != cf::FINANCE_ISSUERS && family != cf::FINANCE_JURISDICTION_INDEX {
            FinanceStore::new(&db).issuers().put(&bank(&actor)).unwrap();
        }
        db.put(family, &key, b"not a valid row").unwrap();

        // A transaction whose guard has to READ that family.
        let (op, data): (FinanceOperation, Vec<u8>) = match family {
            f if f == cf::FINANCE_ISSUERS => (
                FinanceOperation::UpdateIssuer,
                bincode::serialize(&UpdateIssuerData {
                    status: FinanceIssuerStatus::Suspended,
                })
                .unwrap(),
            ),
            // The jurisdiction index is read while APPENDING, so the issuer
            // must NOT already exist.
            f if f == cf::FINANCE_JURISDICTION_INDEX => (
                FinanceOperation::RegisterIssuer,
                bincode::serialize(&bank(&actor)).unwrap(),
            ),
            f if f == cf::FINANCE_ADDRESS_PROOFS => (
                FinanceOperation::RevokeAddressProof,
                bincode::serialize(&RevokeAddressProofData {
                    proof_id: [1u8; 32],
                    revocation_ref: [0xEE; 32],
                })
                .unwrap(),
            ),
            f if f == cf::FINANCE_SUBJECT_ADDRESS_INDEX => (
                FinanceOperation::CreateAddressProof,
                bincode::serialize(&address_proof(&actor, 9, [0xC1u8; 32])).unwrap(),
            ),
            f if f == cf::FINANCE_BANK_STANDINGS => (
                FinanceOperation::UpdateBankStanding,
                bincode::serialize(&UpdateBankStandingData {
                    credential_id: [2u8; 32],
                    standing: AccountStanding::Poor,
                })
                .unwrap(),
            ),
            f if f == cf::FINANCE_SUBJECT_BANK_INDEX => (
                FinanceOperation::CreateBankStanding,
                bincode::serialize(&bank_standing(&actor, 9, [0xC2u8; 32])).unwrap(),
            ),
            f if f == cf::FINANCE_KYC_ATTESTATIONS => (
                FinanceOperation::UpdateKycAttestation,
                bincode::serialize(&UpdateKycData {
                    attestation_id: [3u8; 32],
                    status: KycStatus::Expired,
                })
                .unwrap(),
            ),
            _ => (
                FinanceOperation::CreateKycAttestation,
                bincode::serialize(&kyc(&actor, 9, [0xC3u8; 32])).unwrap(),
            ),
        };

        let before = canonical(&db);
        let tx = TransactionV2 {
            chain_id: CHAIN_ID,
            from: actor.address(),
            fee: 100,
            nonce: 0,
            payload: TxPayload::Finance(FinanceTxData {
                operation: op,
                data,
                recipient: Address::ZERO,
            }),
        };
        let sig = *sign(tx.signing_hash().as_bytes(), actor.private_key()).as_bytes();
        let tx = SignedTransaction::new_v2(tx, sig, *actor.public_key().as_bytes());

        let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
        {
            let mut view = ExecutionView::new(&mut overlay);
            let outcome = executor.execute_tx(&mut view, &tx, &proposer, 1, 1000);
            let err = outcome.expect_err(&format!(
                "a malformed {label} row must ERROR, not be read as absence"
            ));
            let text = err.to_string();
            assert!(
                text.contains("Serialization") || text.contains("Storage"),
                "the {label} failure must name the decode, not something else: {text}"
            );
            // What is guaranteed is that the ERROR propagates and canonical
            // state is untouched -- asserted below. Staged residue inside a
            // candidate that is about to be discarded is not a defect, and
            // there IS residue in three cases: every `Create*` stages the
            // primary row BEFORE it appends to the subject index, so a
            // malformed index row fails after the primary has been written.
            // Naming the allowed set rather than asserting an empty one keeps
            // that visible instead of silently tolerated.
            let allowed: Vec<&str> = match family {
                f if f == cf::FINANCE_SUBJECT_ADDRESS_INDEX => {
                    vec![
                        cf::FINANCE_ADDRESS_PROOFS,
                        cf::FINANCE_SUBJECT_ADDRESS_INDEX,
                    ]
                }
                f if f == cf::FINANCE_SUBJECT_BANK_INDEX => {
                    vec![cf::FINANCE_BANK_STANDINGS, cf::FINANCE_SUBJECT_BANK_INDEX]
                }
                f if f == cf::FINANCE_SUBJECT_KYC_INDEX => {
                    vec![cf::FINANCE_KYC_ATTESTATIONS, cf::FINANCE_SUBJECT_KYC_INDEX]
                }
                f if f == cf::FINANCE_JURISDICTION_INDEX => {
                    vec![cf::FINANCE_ISSUERS, cf::FINANCE_JURISDICTION_INDEX]
                }
                other => vec![other],
            };
            for changed in families_changed(&db, &view) {
                assert!(
                    allowed.contains(&changed),
                    "the {label} failure staged {changed}, which is not on the \
                     path this transaction takes before it fails"
                );
            }
        }
        assert_eq!(
            canonical(&db),
            before,
            "and nothing may be committed for {label}"
        );
    }
}

// ── The second dispatch surface ──────────────────────────────────────────────

/// `execute_tx_v2` routes finance through the candidate too.
///
/// Two public transaction surfaces exist. `execute_tx` (wrapping
/// `execute_tx_with_validators`) is the live one every test above drives;
/// `execute_tx_v2` is `pub` with no production caller and has its own finance
/// arm. A migration that moved only the live arm would leave the other writing
/// committed rows.
#[test]
fn the_v2_dispatch_surface_also_stages_finance() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let issuer = KeyPair::generate();
    fund(&db, &issuer, 10_000_000);
    let proposer = Address::new([9; 20]);
    let before = canonical(&db);

    let tx = TransactionV2 {
        chain_id: CHAIN_ID,
        from: issuer.address(),
        fee: 100,
        nonce: 0,
        payload: TxPayload::Finance(tx_data(FinanceOperation::RegisterIssuer, &bank(&issuer))),
    };
    let sig = *sign(tx.signing_hash().as_bytes(), issuer.private_key()).as_bytes();
    let key = *issuer.public_key().as_bytes();

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    {
        let mut view = ExecutionView::new(&mut overlay);
        let r = executor
            .execute_tx_v2(&mut view, &tx, &sig, &key, &proposer, 1, 1000)
            .unwrap();
        assert!(
            matches!(r.status, TxStatus::Success),
            "the v2 surface must execute a finance registration: {:?}",
            r.status
        );
        assert_eq!(
            families_changed(&db, &view),
            vec![cf::FINANCE_ISSUERS, cf::FINANCE_JURISDICTION_INDEX],
            "and stage exactly the issuer family and its jurisdiction index"
        );
        assert_eq!(
            FinanceExecutor::v_get_issuer(&view, &issuer.address())
                .unwrap()
                .map(|i| i.issuer_address),
            Some(issuer.address()),
            "with the issuer readable from the candidate"
        );
    }

    assert_eq!(
        canonical(&db),
        before,
        "and canonical storage still empty of finance rows"
    );
}

/// The v2 surface refuses the same duplicate the live surface refuses, with the
/// same status.
#[test]
fn the_v2_dispatch_surface_refuses_a_duplicate_with_the_finance_status() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let issuer = KeyPair::generate();
    fund(&db, &issuer, 10_000_000);
    let proposer = Address::new([9; 20]);
    FinanceStore::new(&db)
        .issuers()
        .put(&bank(&issuer))
        .unwrap();

    let tx = TransactionV2 {
        chain_id: CHAIN_ID,
        from: issuer.address(),
        fee: 100,
        nonce: 0,
        payload: TxPayload::Finance(tx_data(FinanceOperation::RegisterIssuer, &bank(&issuer))),
    };
    let sig = *sign(tx.signing_hash().as_bytes(), issuer.private_key()).as_bytes();
    let key = *issuer.public_key().as_bytes();

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);
    let r = executor
        .execute_tx_v2(&mut view, &tx, &sig, &key, &proposer, 1, 1000)
        .unwrap();
    assert_eq!(r.status, FINANCE_FAILED);
    assert_eq!(
        StateManager::v_get_nonce(&view, &issuer.address()).unwrap(),
        0,
        "a refused registration does not advance the nonce on this surface \
         either"
    );
}

// ── Preserved defects ────────────────────────────────────────────────────────

/// `UpdateIssuer` lets a REVOKED issuer set itself back to `Active`.
///
/// PRE-EXISTING. `ReactivateIssuer` exists precisely to require the
/// `Suspended` state before reactivation, and `UpdateIssuer` walks around it by
/// accepting any status the sender asks for. Pinned in BOTH directions:
/// `UpdateIssuer` succeeds and `ReactivateIssuer` refuses, from the same state.
#[test]
fn update_issuer_reactivates_a_revoked_issuer_and_reactivate_refuses() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let issuer = KeyPair::generate();
    fund(&db, &issuer, 100_000_000);
    let proposer = Address::new([9; 20]);
    FinanceStore::new(&db)
        .issuers()
        .put(&bank(&issuer))
        .unwrap();

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);

    let r0 = executor
        .execute_tx(
            &mut view,
            &signed(&issuer, 0, FinanceOperation::RevokeIssuer, &()),
            &proposer,
            1,
            1000,
        )
        .unwrap();
    assert!(matches!(r0.status, TxStatus::Success), "{:?}", r0.status);
    assert_eq!(
        FinanceExecutor::v_get_issuer(&view, &issuer.address())
            .unwrap()
            .unwrap()
            .status,
        FinanceIssuerStatus::Revoked
    );

    // The guarded path refuses: reactivation requires Suspended.
    let r1 = executor
        .execute_tx(
            &mut view,
            &signed(&issuer, 1, FinanceOperation::ReactivateIssuer, &()),
            &proposer,
            1,
            1000,
        )
        .unwrap();
    assert_eq!(
        r1.status, FINANCE_FAILED,
        "ReactivateIssuer must refuse a REVOKED issuer"
    );

    // The unguarded path succeeds, from the same state.
    let r2 = executor
        .execute_tx(
            &mut view,
            &signed(
                &issuer,
                1,
                FinanceOperation::UpdateIssuer,
                &UpdateIssuerData {
                    status: FinanceIssuerStatus::Active,
                },
            ),
            &proposer,
            1,
            1000,
        )
        .unwrap();
    assert!(
        matches!(r2.status, TxStatus::Success),
        "PRE-EXISTING: UpdateIssuer sets any status the sender asks for, \
         including Active from Revoked -- preserved here rather than fixed \
         inside a migration: {:?}",
        r2.status
    );
    assert_eq!(
        FinanceExecutor::v_get_issuer(&view, &issuer.address())
            .unwrap()
            .unwrap()
            .status,
        FinanceIssuerStatus::Active
    );
}

/// A status change never rewrites the jurisdiction index.
///
/// PRE-EXISTING: the committed twin's `update_status` writes only the issuer
/// row, so a revoked issuer stays listed under its jurisdiction and
/// `get_by_jurisdiction` keeps returning it.
#[test]
fn a_revoked_issuer_stays_listed_in_the_jurisdiction_index() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let issuer = KeyPair::generate();
    fund(&db, &issuer, 100_000_000);
    let proposer = Address::new([9; 20]);

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);

    executor
        .execute_tx(
            &mut view,
            &signed(&issuer, 0, FinanceOperation::RegisterIssuer, &bank(&issuer)),
            &proposer,
            1,
            1000,
        )
        .unwrap();
    executor
        .execute_tx(
            &mut view,
            &signed(&issuer, 1, FinanceOperation::RevokeIssuer, &()),
            &proposer,
            1,
            1000,
        )
        .unwrap();

    assert_eq!(
        FinanceExecutor::v_get_issuer(&view, &issuer.address())
            .unwrap()
            .unwrap()
            .status,
        FinanceIssuerStatus::Revoked,
        "the issuer row is revoked"
    );
    assert_eq!(
        FinanceExecutor::v_get_jurisdiction_issuer_addresses(&view, JURISDICTION).unwrap(),
        vec![issuer.address()],
        "and it is STILL listed under its jurisdiction -- a dangling listing \
         the committed path has always left, preserved here rather than fixed \
         inside a migration"
    );
}

/// `SubmitProof` checks nothing: no issuer, no credential, no signature.
///
/// PRE-EXISTING. Anyone who can pay the fee can write any proof envelope.
#[test]
fn submit_proof_requires_no_issuer_at_all() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let stranger = KeyPair::generate();
    fund(&db, &stranger, 10_000_000);
    let proposer = Address::new([9; 20]);

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);
    assert!(
        !FinanceExecutor::v_issuer_exists(&view, &stranger.address()).unwrap(),
        "the sender is not an issuer"
    );

    let r = executor
        .execute_tx(
            &mut view,
            &signed(
                &stranger,
                0,
                FinanceOperation::SubmitProof,
                &proof_envelope(7),
            ),
            &proposer,
            1,
            1000,
        )
        .unwrap();
    assert!(
        matches!(r.status, TxStatus::Success),
        "PRE-EXISTING: SubmitProof has no authority check at all: {:?}",
        r.status
    );
    assert!(FinanceExecutor::v_proof_exists(&view, &[7u8; 32]).unwrap());
}

/// `VerifyProof` charges a fee, advances the nonce, and verifies nothing.
///
/// PRE-EXISTING: the arm has no body beyond accounting, and succeeds for a
/// proof id that does not exist.
#[test]
fn verify_proof_charges_a_fee_and_verifies_nothing() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let stranger = KeyPair::generate();
    fund(&db, &stranger, 10_000_000);
    let proposer = Address::new([9; 20]);

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);
    let r = executor
        .execute_tx(
            &mut view,
            &signed(
                &stranger,
                0,
                FinanceOperation::VerifyProof,
                &proof_envelope(0xFE),
            ),
            &proposer,
            1,
            1000,
        )
        .unwrap();
    assert!(
        matches!(r.status, TxStatus::Success),
        "PRE-EXISTING: verification succeeds without a proof to verify: {:?}",
        r.status
    );
    assert!(
        !FinanceExecutor::v_proof_exists(&view, &[0xFEu8; 32]).unwrap(),
        "no such proof exists"
    );
    assert!(
        families_changed(&db, &view).is_empty(),
        "and it writes no finance row"
    );
    assert_eq!(
        StateManager::v_get_nonce(&view, &stranger.address()).unwrap(),
        1,
        "but it does charge the nonce"
    );
}

/// `UpdateAddressProof` is refused, and charges nothing.
///
/// PRE-EXISTING: the arm returns a failure BEFORE the fee and nonce writes, so
/// unlike every other refusal in this subsystem it leaves the account
/// completely untouched.
#[test]
fn update_address_proof_is_refused_without_charging_anything() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let issuer = KeyPair::generate();
    fund(&db, &issuer, 10_000_000);
    let proposer = Address::new([9; 20]);

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);
    let before = StateManager::v_get_balance(&view, &issuer.address()).unwrap();
    let r = executor
        .execute_tx(
            &mut view,
            &signed(
                &issuer,
                0,
                FinanceOperation::UpdateAddressProof,
                &address_proof(&issuer, 1, [0xCD; 32]),
            ),
            &proposer,
            1,
            1000,
        )
        .unwrap();
    assert_eq!(r.status, FINANCE_FAILED);
    assert_eq!(
        StateManager::v_get_balance(&view, &issuer.address()).unwrap(),
        before,
        "the balance is untouched"
    );
    assert_eq!(
        StateManager::v_get_nonce(&view, &issuer.address()).unwrap(),
        0,
        "and so is the nonce"
    );
}

/// A CORRUPT proof row reads as PRESENT, not as an error.
///
/// PRE-EXISTING, and the exact inverse of the `v_get_*` readers: `SubmitProof`
/// is the only operation that reads `FINANCE_PROOFS` and it reads it with a
/// presence check, so corruption there refuses the transaction as a duplicate
/// rather than propagating a decode failure. Pinned in both directions: the
/// corrupt id is refused, a different id succeeds.
#[test]
fn a_corrupt_proof_row_is_read_as_present_and_refuses_the_submission() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let actor = KeyPair::generate();
    fund(&db, &actor, 100_000_000);
    let proposer = Address::new([9; 20]);
    db.put(cf::FINANCE_PROOFS, &[8u8; 32], b"not a valid row")
        .unwrap();
    let before = canonical(&db);

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);

    let r = executor
        .execute_tx(
            &mut view,
            &signed(&actor, 0, FinanceOperation::SubmitProof, &proof_envelope(8)),
            &proposer,
            1,
            1000,
        )
        .unwrap();
    assert_eq!(
        r.status, FINANCE_FAILED,
        "PRE-EXISTING: the corrupt row is read as an existing proof, so the \
         submission is refused as a duplicate rather than erroring"
    );

    // A different id is unaffected, which is what makes the refusal above a
    // statement about the corrupt row rather than about the operation.
    let r2 = executor
        .execute_tx(
            &mut view,
            &signed(&actor, 0, FinanceOperation::SubmitProof, &proof_envelope(9)),
            &proposer,
            1,
            1000,
        )
        .unwrap();
    assert!(matches!(r2.status, TxStatus::Success), "{:?}", r2.status);
    assert_eq!(
        canonical(&db),
        before,
        "and nothing is committed either way"
    );
}

/// An issuer of the wrong CLASS is refused, with the issuer registered and
/// active.
///
/// The class check is the third of the three conditions every credential
/// operation reads out of one issuer row, and the only one the tests above do
/// not exercise.
#[test]
fn an_issuer_of_the_wrong_class_cannot_issue_a_bank_standing() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let utility = KeyPair::generate();
    fund(&db, &utility, 10_000_000);
    let proposer = Address::new([9; 20]);

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);

    let profile = issuer_of(&utility, FinanceIssuerClass::RegulatedUtility);
    executor
        .execute_tx(
            &mut view,
            &signed(&utility, 0, FinanceOperation::RegisterIssuer, &profile),
            &proposer,
            1,
            1000,
        )
        .unwrap();

    // A utility may issue an address proof ...
    let ok = executor
        .execute_tx(
            &mut view,
            &signed(
                &utility,
                1,
                FinanceOperation::CreateAddressProof,
                &address_proof(&utility, 1, [0x77; 32]),
            ),
            &proposer,
            1,
            1000,
        )
        .unwrap();
    assert!(matches!(ok.status, TxStatus::Success), "{:?}", ok.status);

    // ... and may not issue a bank standing credential.
    let refused = executor
        .execute_tx(
            &mut view,
            &signed(
                &utility,
                2,
                FinanceOperation::CreateBankStanding,
                &bank_standing(&utility, 2, [0x77; 32]),
            ),
            &proposer,
            1,
            1000,
        )
        .unwrap();
    assert_eq!(refused.status, FINANCE_FAILED);
    assert!(
        FinanceExecutor::v_get_bank_standing(&view, &[2u8; 32])
            .unwrap()
            .is_none(),
        "and nothing is staged for it"
    );
}

/// A bank standing updated and then revoked later in the block finds the
/// credential created earlier in it.
///
/// Two more read-then-writes on one family: `UpdateBankStanding` rewrites the
/// standing, `RevokeBankStanding` sets the revocation ref. Both read the
/// credential and both check its issuer, so both were committed reads.
#[test]
fn a_bank_standing_update_and_revocation_find_the_same_block_creation() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let issuer = KeyPair::generate();
    fund(&db, &issuer, 100_000_000);
    let proposer = Address::new([9; 20]);
    FinanceStore::new(&db)
        .issuers()
        .put(&bank(&issuer))
        .unwrap();

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);

    for (nonce, op, data) in [
        (
            0u64,
            FinanceOperation::CreateBankStanding,
            bincode::serialize(&bank_standing(&issuer, 5, [0xDE; 32])).unwrap(),
        ),
        (
            1,
            FinanceOperation::UpdateBankStanding,
            bincode::serialize(&UpdateBankStandingData {
                credential_id: [5u8; 32],
                standing: AccountStanding::Poor,
            })
            .unwrap(),
        ),
        (
            2,
            FinanceOperation::RevokeBankStanding,
            bincode::serialize(&RevokeBankStandingData {
                credential_id: [5u8; 32],
                revocation_ref: [0xAA; 32],
            })
            .unwrap(),
        ),
    ] {
        let tx = TransactionV2 {
            chain_id: CHAIN_ID,
            from: issuer.address(),
            fee: 100,
            nonce,
            payload: TxPayload::Finance(FinanceTxData {
                operation: op,
                data,
                recipient: Address::ZERO,
            }),
        };
        let sig = *sign(tx.signing_hash().as_bytes(), issuer.private_key()).as_bytes();
        let tx = SignedTransaction::new_v2(tx, sig, *issuer.public_key().as_bytes());
        let r = executor
            .execute_tx(&mut view, &tx, &proposer, 1, 1000)
            .unwrap();
        assert!(
            matches!(r.status, TxStatus::Success),
            "{op:?} must find what this block staged: {:?}",
            r.status
        );
    }

    let staged = FinanceExecutor::v_get_bank_standing(&view, &[5u8; 32])
        .unwrap()
        .unwrap();
    assert_eq!(
        staged.standing,
        AccountStanding::Poor,
        "the update is visible to the revocation that followed it"
    );
    assert_eq!(staged.revocation_ref, Some([0xAA; 32]));
}

/// A KYC attestation updated and then revoked later in the block finds the
/// attestation created earlier in it.
///
/// Revocation sets BOTH the status and the revocation ref, which is what makes
/// it a different write from the status update before it.
#[test]
fn a_kyc_update_and_revocation_find_the_same_block_creation() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let issuer = KeyPair::generate();
    fund(&db, &issuer, 100_000_000);
    let proposer = Address::new([9; 20]);
    FinanceStore::new(&db)
        .issuers()
        .put(&bank(&issuer))
        .unwrap();

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);

    for (nonce, op, data) in [
        (
            0u64,
            FinanceOperation::CreateKycAttestation,
            bincode::serialize(&kyc(&issuer, 6, [0xEF; 32])).unwrap(),
        ),
        (
            1,
            FinanceOperation::UpdateKycAttestation,
            bincode::serialize(&UpdateKycData {
                attestation_id: [6u8; 32],
                status: KycStatus::UnderReview,
            })
            .unwrap(),
        ),
        (
            2,
            FinanceOperation::RevokeKycAttestation,
            bincode::serialize(&RevokeKycData {
                attestation_id: [6u8; 32],
                revocation_ref: [0xBB; 32],
            })
            .unwrap(),
        ),
    ] {
        let tx = TransactionV2 {
            chain_id: CHAIN_ID,
            from: issuer.address(),
            fee: 100,
            nonce,
            payload: TxPayload::Finance(FinanceTxData {
                operation: op,
                data,
                recipient: Address::ZERO,
            }),
        };
        let sig = *sign(tx.signing_hash().as_bytes(), issuer.private_key()).as_bytes();
        let tx = SignedTransaction::new_v2(tx, sig, *issuer.public_key().as_bytes());
        let r = executor
            .execute_tx(&mut view, &tx, &proposer, 1, 1000)
            .unwrap();
        assert!(
            matches!(r.status, TxStatus::Success),
            "{op:?} must find what this block staged: {:?}",
            r.status
        );
    }

    let staged = FinanceExecutor::v_get_kyc_attestation(&view, &[6u8; 32])
        .unwrap()
        .unwrap();
    assert_eq!(
        staged.status,
        KycStatus::Revoked,
        "revocation overwrote the UnderReview the update staged"
    );
    assert_eq!(staged.revocation_ref, Some([0xBB; 32]));
}

/// A duplicate address-proof id in one block is refused by a guard that reads
/// the candidate.
#[test]
fn a_duplicate_address_proof_id_in_the_same_block_is_refused() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let issuer = KeyPair::generate();
    fund(&db, &issuer, 10_000_000);
    let proposer = Address::new([9; 20]);
    FinanceStore::new(&db)
        .issuers()
        .put(&bank(&issuer))
        .unwrap();

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);

    let r0 = executor
        .execute_tx(
            &mut view,
            &signed(
                &issuer,
                0,
                FinanceOperation::CreateAddressProof,
                &address_proof(&issuer, 1, [0x91; 32]),
            ),
            &proposer,
            1,
            1000,
        )
        .unwrap();
    assert!(matches!(r0.status, TxStatus::Success), "{:?}", r0.status);

    let r1 = executor
        .execute_tx(
            &mut view,
            &signed(
                &issuer,
                1,
                FinanceOperation::CreateAddressProof,
                &address_proof(&issuer, 1, [0x92; 32]),
            ),
            &proposer,
            1,
            1000,
        )
        .unwrap();
    assert_eq!(r1.status, FINANCE_FAILED);
    assert_eq!(
        StateManager::v_get_nonce(&view, &issuer.address()).unwrap(),
        1
    );
    assert!(
        FinanceExecutor::v_get_subject_address_proof_ids(&view, &[0x92; 32])
            .unwrap()
            .is_empty()
    );
}

/// A duplicate bank-standing id in one block is refused by a guard that reads
/// the candidate.
#[test]
fn a_duplicate_bank_standing_id_in_the_same_block_is_refused() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let issuer = KeyPair::generate();
    fund(&db, &issuer, 10_000_000);
    let proposer = Address::new([9; 20]);
    FinanceStore::new(&db)
        .issuers()
        .put(&bank(&issuer))
        .unwrap();

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);

    let r0 = executor
        .execute_tx(
            &mut view,
            &signed(
                &issuer,
                0,
                FinanceOperation::CreateBankStanding,
                &bank_standing(&issuer, 2, [0x93; 32]),
            ),
            &proposer,
            1,
            1000,
        )
        .unwrap();
    assert!(matches!(r0.status, TxStatus::Success), "{:?}", r0.status);

    let r1 = executor
        .execute_tx(
            &mut view,
            &signed(
                &issuer,
                1,
                FinanceOperation::CreateBankStanding,
                &bank_standing(&issuer, 2, [0x94; 32]),
            ),
            &proposer,
            1,
            1000,
        )
        .unwrap();
    assert_eq!(r1.status, FINANCE_FAILED);
    assert!(
        FinanceExecutor::v_get_subject_bank_standing_ids(&view, &[0x94; 32])
            .unwrap()
            .is_empty()
    );
}

/// A duplicate proof id in one block is refused by a guard that reads the
/// candidate.
///
/// `SubmitProof` has no other guard at all, so this presence check is the whole
/// of its admission logic -- and it has to see the candidate.
#[test]
fn a_duplicate_proof_id_in_the_same_block_is_refused() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let actor = KeyPair::generate();
    fund(&db, &actor, 10_000_000);
    let proposer = Address::new([9; 20]);

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);

    let r0 = executor
        .execute_tx(
            &mut view,
            &signed(
                &actor,
                0,
                FinanceOperation::SubmitProof,
                &proof_envelope(0xA1),
            ),
            &proposer,
            1,
            1000,
        )
        .unwrap();
    assert!(matches!(r0.status, TxStatus::Success), "{:?}", r0.status);

    let r1 = executor
        .execute_tx(
            &mut view,
            &signed(
                &actor,
                1,
                FinanceOperation::SubmitProof,
                &proof_envelope(0xA1),
            ),
            &proposer,
            1,
            1000,
        )
        .unwrap();
    assert_eq!(
        r1.status, FINANCE_FAILED,
        "the second submission must see the first one's staged row"
    );
    assert_eq!(
        StateManager::v_get_nonce(&view, &actor.address()).unwrap(),
        1,
        "one submission charged a nonce, the refusal did not"
    );
}

/// Every routed status change stamps `updated_at = 0`.
///
/// PRE-EXISTING, and it lives in the dispatcher rather than in this subsystem:
/// both finance arms in `executor.rs` pass a literal `0` where the block
/// timestamp belongs (`0, // block_timestamp placeholder`). So the only field
/// the executor is supposed to stamp itself is stamped with the epoch, on every
/// update, suspension, revocation and reactivation. The block's real timestamp
/// is passed to `execute_tx` and thrown away.
///
/// Pinned in both directions: the row is rewritten (`status` changed, so the
/// write really happened) and `updated_at` is zero rather than the block time.
#[test]
fn a_routed_status_change_stamps_a_zero_timestamp() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let issuer = KeyPair::generate();
    fund(&db, &issuer, 100_000_000);
    let proposer = Address::new([9; 20]);
    let mut profile = bank(&issuer);
    profile.updated_at = 7_777;
    FinanceStore::new(&db).issuers().put(&profile).unwrap();

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);
    let r = executor
        .execute_tx(
            &mut view,
            &signed(&issuer, 0, FinanceOperation::SuspendIssuer, &()),
            &proposer,
            1,
            1_234_567,
        )
        .unwrap();
    assert!(matches!(r.status, TxStatus::Success), "{:?}", r.status);

    let staged = FinanceExecutor::v_get_issuer(&view, &issuer.address())
        .unwrap()
        .unwrap();
    assert_eq!(
        staged.status,
        FinanceIssuerStatus::Suspended,
        "the row was rewritten"
    );
    assert_eq!(
        staged.updated_at, 0,
        "PRE-EXISTING: the dispatcher passes 0 for the block timestamp, so \
         every routed update stamps the epoch -- preserved here rather than \
         fixed inside a migration"
    );
}

/// The submitted payload's own timestamps and height are stored verbatim.
///
/// PRE-EXISTING: `registered_at_height`, `created_at` and `updated_at` all come
/// out of the transaction data, not out of the block. An issuer can claim any
/// registration height it likes, including one in the future.
#[test]
fn a_registration_stores_the_payloads_own_height_and_timestamps() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let issuer = KeyPair::generate();
    fund(&db, &issuer, 100_000_000);
    let proposer = Address::new([9; 20]);
    let mut profile = bank(&issuer);
    profile.registered_at_height = 999_999;
    profile.created_at = 4_242;
    profile.updated_at = 4_242;

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);
    let r = executor
        .execute_tx(
            &mut view,
            &signed(&issuer, 0, FinanceOperation::RegisterIssuer, &profile),
            &proposer,
            1,
            1_234_567,
        )
        .unwrap();
    assert!(matches!(r.status, TxStatus::Success), "{:?}", r.status);

    let staged = FinanceExecutor::v_get_issuer(&view, &issuer.address())
        .unwrap()
        .unwrap();
    assert_eq!(
        (staged.registered_at_height, staged.created_at),
        (999_999, 4_242),
        "PRE-EXISTING: the executor stores the claimed height and timestamps \
         verbatim, at block height 1 -- it never compares them to the block"
    );
}

// ── Durability across a restart ──────────────────────────────────────────────

/// Published finance rows survive closing and reopening the database.
///
/// Every other parity assertion in this file reads back through the SAME
/// `Database` handle that published. That proves the rows reached the store's
/// read path; it does not prove they reached disk, because a handle can answer
/// from its own memtable. This one publishes, DROPS the handle -- and the
/// `StateManager` and `BlockExecutor` that hold clones of it, or RocksDB would
/// keep the directory locked -- reopens at the same path, and asserts the
/// committed bytes are identical for all NINE durable finance families, then
/// drives the committed readers the RPC uses against the reopened handle.
#[test]
fn published_finance_rows_survive_a_close_and_reopen() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().to_path_buf();
    let issuer = KeyPair::generate();
    let subject = [0xF1; 32];

    // Built by hand rather than through `setup_with_params`, because every
    // handle has to be droppable before the reopen below.
    let before = {
        let db = Arc::new(Database::open_default(&path).unwrap());
        let state = Arc::new(StateManager::new(db.clone(), CHAIN_ID));
        let executor = BlockExecutor::new(state.clone(), db.clone(), params());
        fund(&db, &issuer, 100_000_000);

        let receipts = common::publish_block(
            &state,
            &executor,
            1,
            &[3u8; 32],
            vec![
                signed(&issuer, 0, FinanceOperation::RegisterIssuer, &bank(&issuer)),
                signed(
                    &issuer,
                    1,
                    FinanceOperation::CreateAddressProof,
                    &address_proof(&issuer, 1, subject),
                ),
                signed(
                    &issuer,
                    2,
                    FinanceOperation::CreateBankStanding,
                    &bank_standing(&issuer, 2, subject),
                ),
                signed(
                    &issuer,
                    3,
                    FinanceOperation::CreateKycAttestation,
                    &kyc(&issuer, 3, subject),
                ),
                signed(
                    &issuer,
                    4,
                    FinanceOperation::SubmitProof,
                    &proof_envelope(4),
                ),
            ],
            &[],
        );
        assert!(
            receipts
                .iter()
                .all(|r| matches!(r.status, TxStatus::Success)),
            "all five must succeed: {:?}",
            receipts.iter().map(|r| r.status).collect::<Vec<_>>()
        );
        let snapshot = canonical(&db);
        // Every one of the nine families must actually carry a row, or the
        // reopen below would be comparing emptiness to emptiness.
        for f in FINANCE_CFS {
            assert!(
                snapshot.iter().any(|(fam, _, _)| fam == f),
                "{f} has no published row, so the restart proves nothing about it"
            );
        }
        snapshot
    };

    // Everything holding the handle is out of scope; reopening would fail with
    // a RocksDB LOCK error if any clone had survived, which is what makes this
    // a restart rather than a second handle.
    let reopened = Database::open_default(&path).unwrap();

    assert_eq!(
        canonical(&reopened),
        before,
        "every finance row must come back byte-identical after a restart"
    );

    // And the committed readers still answer, on the reopened handle.
    let store = FinanceStore::new(&reopened);
    assert_eq!(
        store
            .issuers()
            .get(&issuer.address())
            .unwrap()
            .map(|i| i.issuer_address),
        Some(issuer.address())
    );
    assert_eq!(store.issuers().list_active().unwrap().len(), 1);
    assert_eq!(
        store
            .issuers()
            .get_by_jurisdiction(JURISDICTION)
            .unwrap()
            .len(),
        1,
        "the jurisdiction index survived"
    );
    assert_eq!(
        store
            .address_proofs()
            .get_by_subject(&subject)
            .unwrap()
            .into_iter()
            .map(|p| p.proof_id)
            .collect::<Vec<_>>(),
        vec![[1u8; 32]],
        "the address-proof subject index survived"
    );
    assert_eq!(
        store
            .bank_standings()
            .get_by_subject(&subject)
            .unwrap()
            .into_iter()
            .map(|c| c.credential_id)
            .collect::<Vec<_>>(),
        vec![[2u8; 32]],
        "the bank-standing subject index survived"
    );
    assert_eq!(
        store
            .kyc_attestations()
            .get_by_subject(&subject)
            .unwrap()
            .into_iter()
            .map(|a| a.attestation_id)
            .collect::<Vec<_>>(),
        vec![[3u8; 32]],
        "the KYC subject index survived"
    );
    assert!(store.proofs().exists(&[4u8; 32]).unwrap());
    assert!(store.proofs().is_valid(&[4u8; 32], 1_500).unwrap());

    drop(reopened);
    drop(dir);
}

// ── The four accumulating indexes under a measured load ──────────────────────
//
// SCOPE, stated once for all four measurements below, precisely: each measures
// ONE size. Each shows that at 20,000 existing entries the routed path returns
// a limit error after reaching the index replacement, leaves canonical state
// untouched, and -- given room -- appends without disturbing a single existing
// entry. None of them shows that arbitrarily large input can never reach an
// allocator abort, and no test here can: the replacement value is BUILT, in
// full, before the ceiling is charged for it.
//
// The index values are accumulating bincode lists that the committed stores
// have always decoded, linearly searched, appended to and reserialized on every
// write. Routing reproduces that exactly; it neither introduces the growth nor
// bounds it. A bound would make transactions fail that succeed today, which is
// a consensus change and belongs to activation-gated hardening, not to a
// migration -- so no cap is added here.
//
// The candidate holds both the pre-image and the staged replacement, so peak
// memory for one row is higher here than on the committed path. That is a
// property of the candidate model this lane adopted, not of finance.

const MANY: u32 = 20_000;

/// `MANY` distinct 32-byte ids, deterministic and in a known order.
fn many_ids() -> Vec<[u8; 32]> {
    (0..MANY)
        .map(|i| {
            let mut id = [0u8; 32];
            id[..4].copy_from_slice(&i.to_be_bytes());
            id
        })
        .collect()
}

/// `MANY` distinct addresses, deterministic and in a known order.
fn many_addresses() -> Vec<Address> {
    (0..MANY)
        .map(|i| {
            let mut a = [0u8; 20];
            a[..4].copy_from_slice(&i.to_be_bytes());
            a[19] = 1; // keep every address distinct from the zero address
            Address::new(a)
        })
        .collect()
}

/// Builds the transaction payload for one subject-index measurement: the
/// issuer keypair that must own the credential, the byte its id is made of,
/// and the subject the index is keyed by.
type PayloadBuilder = dyn Fn(&KeyPair, u8, [u8; 32]) -> Vec<u8>;

/// The shared body of the three subject-index measurements.
///
/// `primary_cf` is the credential family the operation writes FIRST and
/// `index_cf` the accumulating list it appends to second. That split is what
/// makes the refusal attributable: the primary row staged and the index
/// unchanged puts the failure at the index write and nowhere earlier.
fn measure_subject_index(
    label: &str,
    primary_cf: &str,
    index_cf: &str,
    subject: [u8; 32],
    new_id_byte: u8,
    op: FinanceOperation,
    build: &PayloadBuilder,
) {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let issuer = KeyPair::generate();
    fund(&db, &issuer, 100_000_000);
    let proposer = Address::new([9; 20]);
    FinanceStore::new(&db)
        .issuers()
        .put(&bank(&issuer))
        .unwrap();

    let existing = many_ids();
    let committed_index = bincode::serialize(&existing).unwrap();
    assert_eq!(
        committed_index.len(),
        640_008,
        "{label}: the fixture must actually be the size this test claims"
    );
    db.put(index_cf, &subject, &committed_index).unwrap();
    let before = canonical(&db);

    let new_id = [new_id_byte; 32];
    let tx = {
        let t = TransactionV2 {
            chain_id: CHAIN_ID,
            from: issuer.address(),
            fee: 100,
            nonce: 0,
            payload: TxPayload::Finance(FinanceTxData {
                operation: op,
                data: build(&issuer, new_id_byte, subject),
                recipient: Address::ZERO,
            }),
        };
        let sig = *sign(t.signing_hash().as_bytes(), issuer.private_key()).as_bytes();
        SignedTransaction::new_v2(t, sig, *issuer.public_key().as_bytes())
    };

    // Under a ceiling far below the index's size the replacement is REFUSED --
    // an error, not an abort.
    {
        let mut overlay = ApplicationOverlay::new(&db, 4_096);
        let mut view = ExecutionView::new(&mut overlay);
        let err = executor
            .execute_tx(&mut view, &tx, &proposer, 1, 1000)
            .expect_err("an index far larger than the ceiling must be refused");
        assert!(
            err.to_string().contains("limit"),
            "{label}: refused by the ceiling, not by something else: {err}"
        );
        // Execution REACHED the index replacement: the primary row is staged,
        // so the refusal is not an earlier account or credential write hitting
        // the ceiling first.
        assert!(
            view.get(primary_cf, &new_id).unwrap().is_some(),
            "{label}: the credential must be staged, which is what puts the \
             failure at the index write rather than before it"
        );
        // And the index the candidate can see is still exactly the committed
        // one, byte for byte: the refused write left no partial replacement.
        assert_eq!(
            view.get(index_cf, &subject).unwrap(),
            Some(committed_index.clone()),
            "{label}: the candidate must still see the committed index unchanged"
        );
    }
    assert_eq!(
        canonical(&db),
        before,
        "{label}: and the refusal commits nothing"
    );
    assert_eq!(
        db.get(index_cf, &subject).unwrap(),
        Some(committed_index.clone()),
        "{label}: the canonical index is byte-identical after the refusal"
    );

    // With room, it succeeds and the list grows by exactly one, preserving
    // every existing id -- compared as a whole slice, not by sampling.
    {
        let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
        let mut view = ExecutionView::new(&mut overlay);
        let r = executor
            .execute_tx(&mut view, &tx, &proposer, 1, 1000)
            .unwrap();
        assert!(
            matches!(r.status, TxStatus::Success),
            "{label}: {:?}",
            r.status
        );
        let staged = view.get(index_cf, &subject).unwrap().unwrap();
        let ids: Vec<[u8; 32]> = bincode::deserialize(&staged).unwrap();
        assert_eq!(
            ids.len(),
            MANY as usize + 1,
            "{label}: appended, not replaced"
        );
        assert_eq!(
            &ids[..MANY as usize],
            &existing[..],
            "{label}: every existing id preserved, in order"
        );
        assert_eq!(ids[MANY as usize], new_id, "{label}: and the new one last");
    }
    assert_eq!(canonical(&db), before, "{label}: still nothing committed");
}

/// The KYC subject index at 640,008 bytes: 20,000 existing attestation ids.
///
/// Measures ONE size. See the scope note above this group: it cannot prove that
/// arbitrarily large input never reaches an allocator abort.
#[test]
fn a_640_kb_kyc_subject_index_is_refused_by_the_ceiling_without_canonical_change() {
    measure_subject_index(
        "kyc subject index",
        cf::FINANCE_KYC_ATTESTATIONS,
        cf::FINANCE_SUBJECT_KYC_INDEX,
        [0x81; 32],
        0xFE,
        FinanceOperation::CreateKycAttestation,
        &|kp, id, subject| bincode::serialize(&kyc(kp, id, subject)).unwrap(),
    );
}

/// The address-proof subject index at 640,008 bytes: 20,000 existing proof ids.
///
/// Measures ONE size. See the scope note above this group: it cannot prove that
/// arbitrarily large input never reaches an allocator abort.
#[test]
fn a_640_kb_address_proof_subject_index_is_refused_by_the_ceiling_without_canonical_change() {
    measure_subject_index(
        "address-proof subject index",
        cf::FINANCE_ADDRESS_PROOFS,
        cf::FINANCE_SUBJECT_ADDRESS_INDEX,
        [0x82; 32],
        0xFD,
        FinanceOperation::CreateAddressProof,
        &|kp, id, subject| bincode::serialize(&address_proof(kp, id, subject)).unwrap(),
    );
}

/// The bank-standing subject index at 640,008 bytes: 20,000 existing
/// credential ids.
///
/// Measures ONE size. See the scope note above this group: it cannot prove that
/// arbitrarily large input never reaches an allocator abort.
#[test]
fn a_640_kb_bank_standing_subject_index_is_refused_by_the_ceiling_without_canonical_change() {
    measure_subject_index(
        "bank-standing subject index",
        cf::FINANCE_BANK_STANDINGS,
        cf::FINANCE_SUBJECT_BANK_INDEX,
        [0x83; 32],
        0xFC,
        FinanceOperation::CreateBankStanding,
        &|kp, id, subject| bincode::serialize(&bank_standing(kp, id, subject)).unwrap(),
    );
}

/// The jurisdiction index at 400,008 bytes: 20,000 existing issuer addresses.
///
/// The fourth accumulating index, and the only one keyed by a STRING and
/// holding `Vec<Address>` rather than `Vec<[u8; 32]>` -- so it is measured on
/// its own rather than through the shared body above.
///
/// Measures ONE size. See the scope note above this group: it cannot prove that
/// arbitrarily large input never reaches an allocator abort.
#[test]
fn a_400_kb_jurisdiction_index_is_refused_by_the_ceiling_without_canonical_change() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    // A FRESH key: `RegisterIssuer` refuses a sender that already has a row, so
    // the sender must not be one of the seeded addresses.
    let issuer = KeyPair::generate();
    fund(&db, &issuer, 100_000_000);
    let proposer = Address::new([9; 20]);

    let existing = many_addresses();
    assert!(
        !existing.contains(&issuer.address()),
        "the new issuer must not already be listed"
    );
    let committed_index = bincode::serialize(&existing).unwrap();
    assert_eq!(
        committed_index.len(),
        400_008,
        "the fixture must actually be the size this test claims"
    );
    db.put(
        cf::FINANCE_JURISDICTION_INDEX,
        JURISDICTION.as_bytes(),
        &committed_index,
    )
    .unwrap();
    let before = canonical(&db);

    let tx = signed(&issuer, 0, FinanceOperation::RegisterIssuer, &bank(&issuer));

    {
        let mut overlay = ApplicationOverlay::new(&db, 4_096);
        let mut view = ExecutionView::new(&mut overlay);
        let err = executor
            .execute_tx(&mut view, &tx, &proposer, 1, 1000)
            .expect_err("an index far larger than the ceiling must be refused");
        assert!(
            err.to_string().contains("limit"),
            "refused by the ceiling, not by something else: {err}"
        );
        assert!(
            view.get(cf::FINANCE_ISSUERS, issuer.address().as_bytes())
                .unwrap()
                .is_some(),
            "the issuer row must be staged, which is what puts the failure at \
             the jurisdiction-index write rather than before it"
        );
        assert_eq!(
            view.get(cf::FINANCE_JURISDICTION_INDEX, JURISDICTION.as_bytes())
                .unwrap(),
            Some(committed_index.clone()),
            "the candidate must still see the committed index unchanged"
        );
    }
    assert_eq!(canonical(&db), before, "the refusal commits nothing");
    assert_eq!(
        db.get(cf::FINANCE_JURISDICTION_INDEX, JURISDICTION.as_bytes())
            .unwrap(),
        Some(committed_index.clone()),
        "the canonical index is byte-identical after the refusal"
    );

    {
        let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
        let mut view = ExecutionView::new(&mut overlay);
        let r = executor
            .execute_tx(&mut view, &tx, &proposer, 1, 1000)
            .unwrap();
        assert!(matches!(r.status, TxStatus::Success), "{:?}", r.status);
        let addresses =
            FinanceExecutor::v_get_jurisdiction_issuer_addresses(&view, JURISDICTION).unwrap();
        assert_eq!(addresses.len(), MANY as usize + 1, "appended, not replaced");
        assert_eq!(
            &addresses[..MANY as usize],
            &existing[..],
            "every existing address preserved, in order"
        );
        assert_eq!(
            addresses[MANY as usize],
            issuer.address(),
            "and the new one last"
        );
    }
    assert_eq!(canonical(&db), before, "still nothing committed");
}

// ── Three more preserved defects ─────────────────────────────────────────────

/// Any sender can self-register as any finance issuer class.
///
/// PRE-EXISTING. `RegisterIssuer` checks exactly one thing about authority:
/// that the profile names the SENDER. Nothing else is consulted -- no registry,
/// no licence, no governance approval, no existing issuer's endorsement. A key
/// generated a second ago can register itself as a `CentralBank` and
/// immediately issue credentials of every class that entitles it to.
///
/// Pinned across the classes that matter, and in the positive direction too:
/// the self-registered central bank's KYC attestation succeeds.
#[test]
fn any_sender_can_self_register_as_any_issuer_class() {
    for class in [
        FinanceIssuerClass::CentralBank,
        FinanceIssuerClass::GovernmentRevenue,
        FinanceIssuerClass::RegulatedBank,
    ] {
        let (_state, db, _dir, executor) = setup_with_params(params());
        let stranger = KeyPair::generate();
        fund(&db, &stranger, 100_000_000);
        let proposer = Address::new([9; 20]);

        let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
        let mut view = ExecutionView::new(&mut overlay);
        let r = executor
            .execute_tx(
                &mut view,
                &signed(
                    &stranger,
                    0,
                    FinanceOperation::RegisterIssuer,
                    &issuer_of(&stranger, class),
                ),
                &proposer,
                1,
                1000,
            )
            .unwrap();
        assert!(
            matches!(r.status, TxStatus::Success),
            "PRE-EXISTING: {class:?} is self-assignable: {:?}",
            r.status
        );
        assert_eq!(
            FinanceExecutor::v_get_issuer(&view, &stranger.address())
                .unwrap()
                .unwrap()
                .issuer_class,
            class,
            "and the claimed class is what gets stored"
        );
    }

    // And the privilege is live immediately: a self-declared central bank can
    // attest KYC in the same block it registered in.
    let (_state, db, _dir, executor) = setup_with_params(params());
    let stranger = KeyPair::generate();
    fund(&db, &stranger, 100_000_000);
    let proposer = Address::new([9; 20]);
    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);
    executor
        .execute_tx(
            &mut view,
            &signed(
                &stranger,
                0,
                FinanceOperation::RegisterIssuer,
                &issuer_of(&stranger, FinanceIssuerClass::CentralBank),
            ),
            &proposer,
            1,
            1000,
        )
        .unwrap();
    let mut attestation = kyc(&stranger, 1, [0x71; 32]);
    attestation.issuer_class = FinanceIssuerClass::CentralBank;
    let r = executor
        .execute_tx(
            &mut view,
            &signed(
                &stranger,
                1,
                FinanceOperation::CreateKycAttestation,
                &attestation,
            ),
            &proposer,
            1,
            1000,
        )
        .unwrap();
    assert!(
        matches!(r.status, TxStatus::Success),
        "PRE-EXISTING: the self-declared central bank attests immediately: {:?}",
        r.status
    );
}

/// Update and revoke paths never recheck the issuer.
///
/// PRE-EXISTING, and the asymmetry is the point: every `Create*` operation
/// reads the issuer row and requires REGISTERED + ACTIVE + a permitted CLASS,
/// while every `Update*` and `Revoke*` operation checks only that the
/// credential's stored `issuer_address` equals the sender. So an issuer that
/// has been revoked -- or whose row has been deleted outright -- keeps full
/// control of every credential it ever issued.
///
/// Pinned in both directions: `Create` is refused after the revocation, and
/// `Update`/`Revoke` still succeed from exactly that state.
#[test]
fn update_and_revoke_do_not_recheck_the_issuer_registration_status_or_class() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let issuer = KeyPair::generate();
    fund(&db, &issuer, 100_000_000);
    let proposer = Address::new([9; 20]);
    FinanceStore::new(&db)
        .issuers()
        .put(&bank(&issuer))
        .unwrap();

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);

    // A credential issued while the issuer is in good standing.
    for (nonce, op, data) in [
        (
            0u64,
            FinanceOperation::CreateBankStanding,
            bincode::serialize(&bank_standing(&issuer, 4, [0x72; 32])).unwrap(),
        ),
        (
            1,
            FinanceOperation::CreateKycAttestation,
            bincode::serialize(&kyc(&issuer, 5, [0x72; 32])).unwrap(),
        ),
    ] {
        let t = TransactionV2 {
            chain_id: CHAIN_ID,
            from: issuer.address(),
            fee: 100,
            nonce,
            payload: TxPayload::Finance(FinanceTxData {
                operation: op,
                data,
                recipient: Address::ZERO,
            }),
        };
        let sig = *sign(t.signing_hash().as_bytes(), issuer.private_key()).as_bytes();
        let t = SignedTransaction::new_v2(t, sig, *issuer.public_key().as_bytes());
        let r = executor
            .execute_tx(&mut view, &t, &proposer, 1, 1000)
            .unwrap();
        assert!(matches!(r.status, TxStatus::Success), "{:?}", r.status);
    }

    // Now revoke the issuer.
    let r = executor
        .execute_tx(
            &mut view,
            &signed(&issuer, 2, FinanceOperation::RevokeIssuer, &()),
            &proposer,
            1,
            1000,
        )
        .unwrap();
    assert!(matches!(r.status, TxStatus::Success), "{:?}", r.status);
    assert_eq!(
        FinanceExecutor::v_get_issuer(&view, &issuer.address())
            .unwrap()
            .unwrap()
            .status,
        FinanceIssuerStatus::Revoked
    );

    // Issuing anything NEW is refused, which is the control: the issuer really
    // is out of standing as far as the create path is concerned.
    let refused = executor
        .execute_tx(
            &mut view,
            &signed(
                &issuer,
                3,
                FinanceOperation::CreateKycAttestation,
                &kyc(&issuer, 6, [0x73; 32]),
            ),
            &proposer,
            1,
            1000,
        )
        .unwrap();
    assert_eq!(
        refused.status, FINANCE_FAILED,
        "a revoked issuer must not be able to issue anything new"
    );

    // And yet every update and revoke on what it already issued still passes.
    for (nonce, op, data, what) in [
        (
            3u64,
            FinanceOperation::UpdateBankStanding,
            bincode::serialize(&UpdateBankStandingData {
                credential_id: [4u8; 32],
                standing: AccountStanding::Restricted,
            })
            .unwrap(),
            "update a bank standing",
        ),
        (
            4,
            FinanceOperation::RevokeBankStanding,
            bincode::serialize(&RevokeBankStandingData {
                credential_id: [4u8; 32],
                revocation_ref: [0xC7; 32],
            })
            .unwrap(),
            "revoke a bank standing",
        ),
        (
            5,
            FinanceOperation::UpdateKycAttestation,
            bincode::serialize(&UpdateKycData {
                attestation_id: [5u8; 32],
                status: KycStatus::UnderReview,
            })
            .unwrap(),
            "update a KYC attestation",
        ),
        (
            6,
            FinanceOperation::RevokeKycAttestation,
            bincode::serialize(&RevokeKycData {
                attestation_id: [5u8; 32],
                revocation_ref: [0xC8; 32],
            })
            .unwrap(),
            "revoke a KYC attestation",
        ),
    ] {
        let t = TransactionV2 {
            chain_id: CHAIN_ID,
            from: issuer.address(),
            fee: 100,
            nonce,
            payload: TxPayload::Finance(FinanceTxData {
                operation: op,
                data,
                recipient: Address::ZERO,
            }),
        };
        let sig = *sign(t.signing_hash().as_bytes(), issuer.private_key()).as_bytes();
        let t = SignedTransaction::new_v2(t, sig, *issuer.public_key().as_bytes());
        let r = executor
            .execute_tx(&mut view, &t, &proposer, 1, 1000)
            .unwrap();
        assert!(
            matches!(r.status, TxStatus::Success),
            "PRE-EXISTING: a REVOKED issuer can still {what}: {:?}",
            r.status
        );
    }

    assert_eq!(
        FinanceExecutor::v_get_bank_standing(&view, &[4u8; 32])
            .unwrap()
            .unwrap()
            .revocation_ref,
        Some([0xC7; 32]),
        "and the writes really landed"
    );
    assert_eq!(
        FinanceExecutor::v_get_kyc_attestation(&view, &[5u8; 32])
            .unwrap()
            .unwrap()
            .revocation_ref,
        Some([0xC8; 32])
    );
}

/// The active-issuer and jurisdiction reads are unpaginated and unbounded.
///
/// PRE-EXISTING, on the COMMITTED side the RPC serves: `list_active` scans the
/// whole `FINANCE_ISSUERS` family and returns every match in one `Vec`, and
/// `get_by_jurisdiction` decodes one unbounded `Vec<Address>` and then does a
/// point lookup per entry. Neither takes a limit, an offset or a cursor, so
/// neither has any shape in which a caller could ask for less. Response size
/// and work per call are set by how much the chain has accumulated.
///
/// SCOPE: this measures ONE size -- 2,000 issuers, all active, all in one
/// jurisdiction -- and shows both reads return all 2,000 with no way to ask for
/// fewer. It is not a claim about where the real limit is. No cap is added: a
/// cap changes what these functions return and belongs to the RPC's own
/// activation-gated work.
#[test]
fn a_2000_issuer_registry_is_returned_whole_by_both_unpaginated_reads() {
    let (_state, db, _dir, _executor) = setup_with_params(params());
    let store = FinanceStore::new(&db);

    let addresses = many_addresses();
    for address in addresses.iter().take(2_000) {
        let mut profile = issuer_of(&KeyPair::generate(), FinanceIssuerClass::RegulatedBank);
        profile.issuer_address = *address;
        store.issuers().put(&profile).unwrap();
    }

    let active = store.issuers().list_active().unwrap();
    assert_eq!(
        active.len(),
        2_000,
        "PRE-EXISTING: `list_active` has no limit parameter and returns the \
         whole registry"
    );
    let by_jurisdiction = store.issuers().get_by_jurisdiction(JURISDICTION).unwrap();
    assert_eq!(
        by_jurisdiction.len(),
        2_000,
        "PRE-EXISTING: `get_by_jurisdiction` decodes one unbounded address \
         list and does a point lookup per entry"
    );
    assert_eq!(
        by_jurisdiction
            .iter()
            .map(|i| i.issuer_address)
            .collect::<Vec<_>>(),
        addresses[..2_000].to_vec(),
        "in index order, whole -- there is no cursor to resume from"
    );
}

// ── The publication byte contract ───────────────────────────────────────────

/// The PUBLISHED bytes are the byte contract, and this pins them directly.
///
/// `published_rows_satisfy_the_committed_scans` compares candidate bytes to
/// independent expectations; `published_finance_rows_survive_a_close_and_reopen`
/// compares published rows to THEMSELVES across a restart. Neither pins the
/// step between them: candidate to committed goes through
/// `ApplicationOverlay::into_batch`, and if that reordered a key, dropped a
/// prefix or re-encoded a value, both of those tests would still pass.
///
/// So: publish a real block through the real publisher, then for all NINE
/// families read the RAW committed bytes and compare them against a key written
/// out by hand and a value produced by `bincode::serialize` applied here in the
/// test. Nothing on the expected side calls a key builder or a codec from the
/// crate under test. The key shapes are transcribed from the schema: the issuer
/// row is keyed by the 20-byte wallet address, the jurisdiction index by the
/// RAW UTF-8 of the jurisdiction code, and every other key is a bare 32-byte id
/// or subject commitment.
///
/// The VALUES are deliberately not uniform, and that is the point of building
/// them by hand: the three subject indexes hold bincode `Vec<[u8; 32]>`, while
/// the jurisdiction index holds a bincode `Vec<Address>` -- a different element
/// type in the same shape of row. A publisher that re-encoded one as the other
/// would be invisible to a test that only round-tripped through the crate's own
/// codec. Then close the database, reopen it at the same path, and compare the
/// same nine expectations again.
///
/// Test-only addition: no production source and no existing test body changed.
#[test]
fn published_finance_bytes_match_independently_built_keys_and_values() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().to_path_buf();
    let issuer = KeyPair::generate();
    let subject = [0xF1; 32];

    // Expectations built here, from the schema, with no help from the crate.
    let issuer_v = bank(&issuer);
    let addr_v = address_proof(&issuer, 1, subject);
    let bank_v = bank_standing(&issuer, 2, subject);
    let kyc_v = kyc(&issuer, 3, subject);
    let proof_v = proof_envelope(4);

    let expected: Vec<(&str, Vec<u8>, Vec<u8>)> = vec![
        (
            cf::FINANCE_ISSUERS,
            issuer.address().as_bytes().to_vec(),
            bincode::serialize(&issuer_v).unwrap(),
        ),
        (
            cf::FINANCE_JURISDICTION_INDEX,
            JURISDICTION.as_bytes().to_vec(),
            bincode::serialize(&vec![issuer.address()]).unwrap(),
        ),
        (
            cf::FINANCE_ADDRESS_PROOFS,
            vec![1u8; 32],
            bincode::serialize(&addr_v).unwrap(),
        ),
        (
            cf::FINANCE_SUBJECT_ADDRESS_INDEX,
            subject.to_vec(),
            bincode::serialize(&vec![[1u8; 32]]).unwrap(),
        ),
        (
            cf::FINANCE_BANK_STANDINGS,
            vec![2u8; 32],
            bincode::serialize(&bank_v).unwrap(),
        ),
        (
            cf::FINANCE_SUBJECT_BANK_INDEX,
            subject.to_vec(),
            bincode::serialize(&vec![[2u8; 32]]).unwrap(),
        ),
        (
            cf::FINANCE_KYC_ATTESTATIONS,
            vec![3u8; 32],
            bincode::serialize(&kyc_v).unwrap(),
        ),
        (
            cf::FINANCE_SUBJECT_KYC_INDEX,
            subject.to_vec(),
            bincode::serialize(&vec![[3u8; 32]]).unwrap(),
        ),
        (
            cf::FINANCE_PROOFS,
            vec![4u8; 32],
            bincode::serialize(&proof_v).unwrap(),
        ),
    ];
    assert_eq!(
        expected.len(),
        FINANCE_CFS.len(),
        "one expectation per migrated family, and the list must not drift"
    );

    {
        let db = Arc::new(Database::open_default(&path).unwrap());
        let state = Arc::new(StateManager::new(db.clone(), CHAIN_ID));
        let executor = BlockExecutor::new(state.clone(), db.clone(), params());
        fund(&db, &issuer, 100_000_000);

        let receipts = common::publish_block(
            &state,
            &executor,
            1,
            &[3u8; 32],
            vec![
                signed(&issuer, 0, FinanceOperation::RegisterIssuer, &issuer_v),
                signed(&issuer, 1, FinanceOperation::CreateAddressProof, &addr_v),
                signed(&issuer, 2, FinanceOperation::CreateBankStanding, &bank_v),
                signed(&issuer, 3, FinanceOperation::CreateKycAttestation, &kyc_v),
                signed(&issuer, 4, FinanceOperation::SubmitProof, &proof_v),
            ],
            &[],
        );
        assert!(
            receipts
                .iter()
                .all(|r| matches!(r.status, TxStatus::Success)),
            "all five must succeed: {:?}",
            receipts.iter().map(|r| r.status).collect::<Vec<_>>()
        );

        for (family, key, value) in &expected {
            assert_eq!(
                db.get(family, key).unwrap().as_deref(),
                Some(&value[..]),
                "{family}: the published row does not match the bytes built \
                 independently in this test"
            );
        }
        // And the family holds exactly that one row -- so a publisher that
        // wrote the right bytes at an extra key would still be caught.
        for family in FINANCE_CFS {
            assert_eq!(
                db.prefix_iter(family, &[]).unwrap().count(),
                1,
                "{family} must hold exactly the one published row"
            );
        }

        drop(executor);
        drop(state);
        assert_eq!(
            Arc::strong_count(&db),
            1,
            "nothing else may hold the database, or the drop below does not \
             close it and the reopen proves nothing"
        );
        drop(db);
    }

    let reopened = Database::open_default(&path).unwrap();
    for (family, key, value) in &expected {
        assert_eq!(
            reopened.get(family, key).unwrap().as_deref(),
            Some(&value[..]),
            "{family}: the row changed across a close and reopen"
        );
    }
}

// ── Class 3: the Finance issuer-standing rules, and their activation ─────────
//
// `docs/lane-a/ACTIVATION-AUDIT.md` rows AU-22, AU-23 and AU-25. Every update
// and revoke path checks only the address recorded on the row and never rereads
// the issuer registry, so an issuer that has been suspended or revoked keeps
// full control of everything it ever issued -- and the creation paths DO read
// the registry, so the asymmetry is exact rather than an oversight of shape.
// `UpdateIssuer` applies whatever status the sender asks for, `Active` from
// `Revoked` included, walking around the Suspended-only guard `ReactivateIssuer`
// exists to enforce. `SubmitProof` has no authority check at all.
//
// Gated on `finance_authorization_enabled_from_height`, a `ChainParams` field
// this track cannot add.
//
// AU-21 (anyone self-registers as any issuer class, `CentralBank` included) and
// AU-24 (the `UpdateIssuer` sender check is structurally unable to fire,
// because the row is fetched BY the sender key) are NOT addressed here and are
// not claimed to be. AU-21 needs an authority the subsystem does not have: no
// `ChainParams` field names a finance registrar, and inventing one from inside
// the executor would be a rule nobody set. AU-24 is a dead check rather than a
// hole -- registration forces the equality the comparison later tests -- so
// deleting it would be tidier and would close nothing.

use sumchain_state::FinanceGates;

/// Drive one Finance operation through the gate seam.
fn finance_at(
    view: &mut ExecutionView<'_, '_>,
    sender: &Address,
    op: FinanceOperation,
    payload: &impl serde::Serialize,
    gates: FinanceGates,
) -> sumchain_state::FinanceExecutionResult {
    let proposer = Address::new([9; 20]);
    FinanceExecutor::execute_with_gates(
        view,
        sender,
        &tx_data(op, payload),
        &proposer,
        100,
        1,
        1_000,
        0,
        sumchain_primitives::Hash::ZERO,
        gates,
    )
    .unwrap()
}

/// AU-23: a suspended issuer keeps control of everything it ever issued.
///
/// Create while Active, suspend, then update and revoke. Below the gate both
/// still land; above it neither does, and creation is refused too -- which is
/// the point: the creation path always checked, so at the gate the two halves
/// finally agree.
#[test]
fn a_suspended_finance_issuer_keeps_control_below_the_gate_and_loses_it_above() {
    #[derive(serde::Serialize)]
    struct UpdateIssuer {
        status: FinanceIssuerStatus,
    }
    #[derive(serde::Serialize)]
    struct UpdateKyc {
        attestation_id: [u8; 32],
        status: KycStatus,
    }
    #[derive(serde::Serialize)]
    struct RevokeKyc {
        attestation_id: [u8; 32],
        revocation_ref: [u8; 32],
    }

    for gates in [FinanceGates::CLOSED, FinanceGates::OPEN] {
        let (_state, db, _dir, _executor) = setup_with_params(params());
        let issuer = KeyPair::generate();
        fund(&db, &issuer, 100_000_000);
        let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
        let mut view = ExecutionView::new(&mut overlay);

        assert!(
            finance_at(
                &mut view,
                &issuer.address(),
                FinanceOperation::RegisterIssuer,
                &bank(&issuer),
                gates
            )
            .success
        );
        let att = kyc(&issuer, 0x51, [0x52; 32]);
        assert!(
            finance_at(
                &mut view,
                &issuer.address(),
                FinanceOperation::CreateKycAttestation,
                &att,
                gates
            )
            .success,
            "created while Active under either gate"
        );

        // Suspend, through the arm that is allowed to.
        assert!(
            finance_at(
                &mut view,
                &issuer.address(),
                FinanceOperation::UpdateIssuer,
                &UpdateIssuer {
                    status: FinanceIssuerStatus::Suspended
                },
                gates
            )
            .success
        );

        let updated = finance_at(
            &mut view,
            &issuer.address(),
            FinanceOperation::UpdateKycAttestation,
            &UpdateKyc {
                attestation_id: att.attestation_id,
                status: KycStatus::Expired,
            },
            gates,
        );
        let revoked = finance_at(
            &mut view,
            &issuer.address(),
            FinanceOperation::RevokeKycAttestation,
            &RevokeKyc {
                attestation_id: att.attestation_id,
                revocation_ref: [0x53; 32],
            },
            gates,
        );
        assert_eq!(
            (updated.success, revoked.success),
            (!gates.authorization, !gates.authorization),
            "a suspended issuer keeps update and revoke, until the gate"
        );

        // The creation path refuses on BOTH sides, which is the asymmetry the
        // gate closes.
        let second = kyc(&issuer, 0x54, [0x55; 32]);
        assert!(
            !finance_at(
                &mut view,
                &issuer.address(),
                FinanceOperation::CreateKycAttestation,
                &second,
                gates
            )
            .success,
            "creation has always been refused to a suspended issuer"
        );
    }
}

/// AU-22: `UpdateIssuer` restores `Active` from `Revoked`, until the gate.
#[test]
fn update_issuer_cannot_walk_around_reactivate_at_the_gate() {
    #[derive(serde::Serialize)]
    struct UpdateIssuer {
        status: FinanceIssuerStatus,
    }

    for gates in [FinanceGates::CLOSED, FinanceGates::OPEN] {
        let (_state, db, _dir, _executor) = setup_with_params(params());
        let issuer = KeyPair::generate();
        fund(&db, &issuer, 100_000_000);
        let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
        let mut view = ExecutionView::new(&mut overlay);

        assert!(
            finance_at(
                &mut view,
                &issuer.address(),
                FinanceOperation::RegisterIssuer,
                &bank(&issuer),
                gates
            )
            .success
        );
        assert!(
            finance_at(
                &mut view,
                &issuer.address(),
                FinanceOperation::UpdateIssuer,
                &UpdateIssuer {
                    status: FinanceIssuerStatus::Revoked
                },
                gates
            )
            .success,
            "revoking itself is allowed on both sides"
        );

        let restored = finance_at(
            &mut view,
            &issuer.address(),
            FinanceOperation::UpdateIssuer,
            &UpdateIssuer {
                status: FinanceIssuerStatus::Active,
            },
            gates,
        );
        assert_eq!(
            restored.success,
            !gates.authorization,
            "Active from Revoked, in one transaction, until the gate"
        );
        assert_eq!(
            FinanceExecutor::v_get_issuer(&view, &issuer.address())
                .unwrap()
                .unwrap()
                .status,
            if gates.authorization {
                FinanceIssuerStatus::Revoked
            } else {
                FinanceIssuerStatus::Active
            }
        );
    }
}

/// AU-25: anyone who pays writes any proof envelope, until the gate.
#[test]
fn submit_proof_requires_a_registered_active_issuer_at_the_gate() {
    for gates in [FinanceGates::CLOSED, FinanceGates::OPEN] {
        let (_state, db, _dir, _executor) = setup_with_params(params());
        let stranger = KeyPair::generate();
        fund(&db, &stranger, 100_000_000);
        let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
        let mut view = ExecutionView::new(&mut overlay);

        let env = proof_envelope(0x56);
        let r = finance_at(
            &mut view,
            &stranger.address(),
            FinanceOperation::SubmitProof,
            &env,
            gates,
        );
        assert_eq!(r.success, !gates.authorization);
        assert_eq!(
            FinanceExecutor::v_proof_exists(&view, &env.proof_id).unwrap(),
            !gates.authorization,
            "and nothing reached the proof family at the gate"
        );
    }
}
