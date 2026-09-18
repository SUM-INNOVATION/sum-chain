//! SRC-88X employment executes against the block's candidate.
//!
//! Real signed transactions through `BlockExecutor`, in sequence, in one block.
//! Every employment operation is a read-then-write -- duplicate guards on
//! registration and creation, existence checks before an update, an ACTIVE
//! issuer check before a credential or an attestation, and five accumulating
//! index lists that are read-modified-written. All of those reads were
//! COMMITTED reads, correct only because the matching writes committed as they
//! went.
//!
//! ## Behaviours this suite PINS rather than fixes
//!
//! * `update_status` and `revoke` rewrite only the credential row. The three
//!   indexes built at creation are left pointing at a credential whose status
//!   has since changed, `Ended` included.
//! * `UpdateEmployment`, `SuspendEmployment`, `EndEmployment`,
//!   `RevokeEmployment` and `RevokeIncomeAttestation` check only that the
//!   sender is the recorded issuer. They do NOT re-check that the issuer is
//!   still active, so a suspended or revoked issuer keeps full control of
//!   everything it ever issued.
//! * `UpdateIssuer`'s `issuer.issuer_address != *sender` check can never fire:
//!   the row was fetched BY `sender`, and the store keys it by
//!   `issuer_address`. It is a no-op verification.
//! * `VerifyProof` charges the fee, advances the nonce and verifies nothing --
//!   not even that the proof it is asked about exists.
//! * A CORRUPT proof row reads as PRESENT, because the submission guard is a
//!   `contains` that never decodes. It refuses the submission instead of
//!   erroring. That is not "corruption read as absence", but it is not a decode
//!   either, and it is the committed behaviour.
//! * The five index values are `Vec<[u8; 32]>` lists that grow without bound.
//!
//! All of them predate this commit and are reproduced exactly. They are pinned
//! here so that changing any one of them is a deliberate act with a failing
//! test attached, not a silent correction inside a migration.

mod common;

use common::{fund, setup_with_params, CHAIN_ID};
use sumchain_crypto::{sign, KeyPair};
use sumchain_genesis::ChainParams;
use sumchain_primitives::employment::{
    EmploymentCredential, EmploymentIssuerClass, EmploymentIssuerProfile, EmploymentOperation,
    EmploymentProofEnvelope, EmploymentProofType, EmploymentStatus, EmploymentTxData,
    EmploymentType, IncomeAttestation, IncomeBracket, IncomePeriod, IssuerStatus,
};
use sumchain_primitives::{Address, SignedTransaction, TransactionV2, TxPayload, TxStatus};
use sumchain_state::{EmploymentExecutor, StateManager};
use sumchain_storage::exec_view::ExecutionView;
use sumchain_storage::overlay::ApplicationOverlay;
use sumchain_storage::{cf, Database, EmploymentStore};

/// Every family this unit moved. Nine.
///
/// `EMPLOYMENT_SYSTEM_EVENTS` is deliberately not here: nothing on the
/// execution path writes it, which is why it is not in the ledger either.
const EMPLOYMENT_CFS: &[&str] = &[
    cf::EMPLOYMENT_ISSUERS,
    cf::EMPLOYMENT_CREDENTIALS,
    cf::EMPLOYMENT_EMPLOYEE_INDEX,
    cf::EMPLOYMENT_EMPLOYEE_ADDRESS_INDEX,
    cf::EMPLOYMENT_EMPLOYER_INDEX,
    cf::EMPLOYMENT_INCOME_ATTESTATIONS,
    cf::EMPLOYMENT_SUBJECT_INCOME_INDEX,
    cf::EMPLOYMENT_INCOME_HOLDER_ADDRESS_INDEX,
    cf::EMPLOYMENT_PROOFS,
];

/// "Employment operation failed" — the status the dispatch arm returns when the
/// executor's own guard refuses. Asserting this rather than "not success" is
/// what stops an invalid nonce, an insufficient balance or a malformed payload
/// from standing in for the guard a negative control is about.
const EMPLOYMENT_FAILED: TxStatus = TxStatus::Failed(15);

fn params() -> ChainParams {
    ChainParams::with_v2_enabled()
}

fn payload(op: EmploymentOperation, data: &impl serde::Serialize) -> TxPayload {
    TxPayload::Employment(EmploymentTxData {
        operation: op,
        data: bincode::serialize(data).unwrap(),
        recipient: Address::ZERO,
    })
}

fn signed(
    kp: &KeyPair,
    nonce: u64,
    op: EmploymentOperation,
    data: &impl serde::Serialize,
) -> SignedTransaction {
    let tx = TransactionV2 {
        chain_id: CHAIN_ID,
        from: kp.address(),
        fee: 100,
        nonce,
        payload: payload(op, data),
    };
    let h = tx.signing_hash();
    let sig = sign(h.as_bytes(), kp.private_key());
    SignedTransaction::new_v2(tx, *sig.as_bytes(), *kp.public_key().as_bytes())
}

fn issuer_of(kp: &KeyPair) -> EmploymentIssuerProfile {
    EmploymentIssuerProfile {
        issuer_address: kp.address(),
        issuer_class: EmploymentIssuerClass::PayrollProcessor,
        display_name: "Payroll Co".to_string(),
        issuer_commitment: [0xA1; 32],
        jurisdiction_code: "US-CA".to_string(),
        policy_id: [0xA2; 32],
        status: IssuerStatus::Active,
        registered_at_height: 1,
        created_at: 1_000,
        updated_at: 1_000,
    }
}

/// A credential issued by `kp`, keyed `id`, for one employee/employer pair.
fn credential_of(
    kp: &KeyPair,
    id: u8,
    employee: Address,
    employee_ref: [u8; 32],
    employer_ref: [u8; 32],
) -> EmploymentCredential {
    EmploymentCredential {
        employment_id: [id; 32],
        employee_address: employee,
        employee_ref,
        employer_ref,
        status: EmploymentStatus::Active,
        tenure_commitment: [0xB1; 32],
        role_commitment: Some([0xB2; 32]),
        employment_type: EmploymentType::FullTime,
        valid_from: 100,
        expiry: 0,
        policy_id: [0xB3; 32],
        revocation_ref: None,
        issuer_address: kp.address(),
        issuer_name: "Payroll Co".to_string(),
        issuer_class: EmploymentIssuerClass::PayrollProcessor,
        created_at: 1_000,
        updated_at: 1_000,
    }
}

fn attestation_of(
    kp: &KeyPair,
    id: u8,
    holder: Address,
    subject_ref: [u8; 32],
) -> IncomeAttestation {
    IncomeAttestation {
        attestation_id: [id; 32],
        holder_address: holder,
        subject_ref,
        period_commitment: [0xC1; 32],
        period_type: IncomePeriod::Annual,
        income_bracket: IncomeBracket::Bracket4,
        threshold_commitment: None,
        employment_id: None,
        issuer_address: kp.address(),
        issuer_class: EmploymentIssuerClass::PayrollProcessor,
        valid_from: 100,
        expiry: 1_000_000,
        policy_id: [0xC2; 32],
        revocation_ref: None,
        created_at: 1_000,
        updated_at: 1_000,
    }
}

fn proof_of(id: u8) -> EmploymentProofEnvelope {
    EmploymentProofEnvelope {
        proof_id: [id; 32],
        profile_id: [0xD1; 32],
        proof_type: EmploymentProofType::CurrentlyEmployed,
        subject_nullifier: [0xD2; 32],
        proof_data: vec![7, 7, 7],
        public_inputs_commitment: [0xD3; 32],
        credential_refs: vec![],
        source_issuer_class: EmploymentIssuerClass::PayrollProcessor,
        policy_id: [0xD4; 32],
        valid_from: 100,
        expiry: 1_000_000,
        created_at: 1_000,
    }
}

// ── Payload shapes the executor deserializes ────────────────────────────────

#[derive(serde::Serialize)]
struct UpdateIssuerData {
    status: IssuerStatus,
}

#[derive(serde::Serialize)]
struct UpdateEmploymentData {
    employment_id: [u8; 32],
    status: EmploymentStatus,
}

#[derive(serde::Serialize)]
struct EmploymentIdData {
    employment_id: [u8; 32],
}

#[derive(serde::Serialize)]
struct RevokeEmploymentData {
    employment_id: [u8; 32],
    revocation_ref: [u8; 32],
}

#[derive(serde::Serialize)]
struct RevokeAttestationData {
    attestation_id: [u8; 32],
    revocation_ref: [u8; 32],
}

#[derive(serde::Serialize)]
struct Empty {}

// ── Committed / candidate comparison ────────────────────────────────────────

fn canonical(db: &Database) -> Vec<(String, Vec<u8>, Vec<u8>)> {
    let mut out = Vec::new();
    for f in EMPLOYMENT_CFS {
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
/// Several tests below pre-seed a canonical issuer row, which would make a
/// presence check report that family as staged in every one of them.
fn families_changed(db: &Database, view: &ExecutionView<'_, '_>) -> Vec<&'static str> {
    let mut out = Vec::new();
    for f in EMPLOYMENT_CFS {
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

// ── Same-block visibility: issuers ──────────────────────────────────────────

/// A credential created later in the block finds the issuer registered earlier
/// in it.
///
/// `CreateEmployment` requires a registered, ACTIVE issuer. Against committed
/// state that read answers from the parent block, so the registration would be
/// invisible and the credential refused.
#[test]
fn a_credential_finds_an_issuer_registered_earlier_in_the_same_block() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let issuer = KeyPair::generate();
    fund(&db, &issuer, 10_000_000);
    let proposer = Address::new([9; 20]);

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);

    let r0 = executor
        .execute_tx(
            &mut view,
            &signed(
                &issuer,
                0,
                EmploymentOperation::RegisterIssuer,
                &issuer_of(&issuer),
            ),
            &proposer,
            1,
            1000,
        )
        .unwrap();
    assert!(matches!(r0.status, TxStatus::Success), "{:?}", r0.status);

    let cred = credential_of(&issuer, 1, Address::new([7; 20]), [0x55; 32], [0x66; 32]);
    let r1 = executor
        .execute_tx(
            &mut view,
            &signed(&issuer, 1, EmploymentOperation::CreateEmployment, &cred),
            &proposer,
            1,
            1000,
        )
        .unwrap();
    assert!(
        matches!(r1.status, TxStatus::Success),
        "the credential must find the issuer this block registered: {:?}",
        r1.status
    );
    assert!(
        EmploymentExecutor::v_get_credential(&view, &[1u8; 32])
            .unwrap()
            .is_some(),
        "and stage the credential"
    );
}

/// Without the registration, the same credential is refused.
#[test]
fn without_the_registration_the_same_credential_is_refused() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let issuer = KeyPair::generate();
    fund(&db, &issuer, 10_000_000);
    let proposer = Address::new([9; 20]);

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);
    let cred = credential_of(&issuer, 1, Address::new([7; 20]), [0x55; 32], [0x66; 32]);
    let r = executor
        .execute_tx(
            &mut view,
            &signed(&issuer, 0, EmploymentOperation::CreateEmployment, &cred),
            &proposer,
            1,
            1000,
        )
        .unwrap();
    assert_eq!(
        r.status, EMPLOYMENT_FAILED,
        "a credential from an unregistered issuer must fail IN the employment \
         executor"
    );
    assert!(
        families_changed(&db, &view).is_empty(),
        "and change nothing at all"
    );
    assert_eq!(
        StateManager::v_get_nonce(&view, &issuer.address()).unwrap(),
        0,
        "a refused employment operation does not advance the account nonce"
    );
}

/// A suspension finds the issuer registered earlier in the same block.
///
/// `SuspendIssuer`'s guard is a PRESENCE test, not a read of the profile, so
/// this is the accessor the credential test above does not exercise.
#[test]
fn a_suspension_finds_an_issuer_registered_earlier_in_the_same_block() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let issuer = KeyPair::generate();
    fund(&db, &issuer, 10_000_000);
    let proposer = Address::new([9; 20]);

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);
    executor
        .execute_tx(
            &mut view,
            &signed(
                &issuer,
                0,
                EmploymentOperation::RegisterIssuer,
                &issuer_of(&issuer),
            ),
            &proposer,
            1,
            1000,
        )
        .unwrap();

    let r = executor
        .execute_tx(
            &mut view,
            &signed(&issuer, 1, EmploymentOperation::SuspendIssuer, &Empty {}),
            &proposer,
            1,
            2000,
        )
        .unwrap();
    assert!(
        matches!(r.status, TxStatus::Success),
        "the suspension must find the registration from this block: {:?}",
        r.status
    );
    let staged = EmploymentExecutor::v_get_issuer(&view, &issuer.address())
        .unwrap()
        .unwrap();
    assert_eq!(staged.status, IssuerStatus::Suspended);
    // ZERO, not 2000. Both dispatch arms pass a literal `0` where
    // `block_timestamp` belongs -- see
    // `every_status_update_records_a_zero_timestamp_through_dispatch`.
    assert_eq!(staged.updated_at, 0);
}

/// Without the registration, the same suspension is refused.
#[test]
fn without_the_registration_the_same_suspension_is_refused() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let issuer = KeyPair::generate();
    fund(&db, &issuer, 10_000_000);
    let proposer = Address::new([9; 20]);

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);
    let r = executor
        .execute_tx(
            &mut view,
            &signed(&issuer, 0, EmploymentOperation::SuspendIssuer, &Empty {}),
            &proposer,
            1,
            2000,
        )
        .unwrap();
    assert_eq!(r.status, EMPLOYMENT_FAILED);
    assert!(families_changed(&db, &view).is_empty());
    assert_eq!(
        StateManager::v_get_nonce(&view, &issuer.address()).unwrap(),
        0
    );
}

/// A reactivation sees the SUSPENSION from earlier in the same block.
///
/// `ReactivateIssuer` refuses unless the profile's status is exactly
/// `Suspended`. Against committed state the profile would still read `Active`,
/// so the reactivation would be refused for a suspension the same block had
/// just applied. This is the strongest form of the read-your-own-writes
/// requirement in this subsystem: it depends on a FIELD the candidate wrote,
/// not merely on a row existing.
#[test]
fn a_reactivation_sees_the_suspension_from_the_same_block() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let issuer = KeyPair::generate();
    fund(&db, &issuer, 10_000_000);
    let proposer = Address::new([9; 20]);

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);
    for (nonce, op) in [
        (0u64, EmploymentOperation::RegisterIssuer),
        (1, EmploymentOperation::SuspendIssuer),
    ] {
        let tx = match op {
            EmploymentOperation::RegisterIssuer => signed(&issuer, nonce, op, &issuer_of(&issuer)),
            _ => signed(&issuer, nonce, op, &Empty {}),
        };
        let r = executor
            .execute_tx(&mut view, &tx, &proposer, 1, 1000)
            .unwrap();
        assert!(
            matches!(r.status, TxStatus::Success),
            "{op:?}: {:?}",
            r.status
        );
    }

    let r = executor
        .execute_tx(
            &mut view,
            &signed(&issuer, 2, EmploymentOperation::ReactivateIssuer, &Empty {}),
            &proposer,
            1,
            3000,
        )
        .unwrap();
    assert!(
        matches!(r.status, TxStatus::Success),
        "reactivation must see the status this block set: {:?}",
        r.status
    );
    assert_eq!(
        EmploymentExecutor::v_get_issuer(&view, &issuer.address())
            .unwrap()
            .unwrap()
            .status,
        IssuerStatus::Active
    );
}

/// Without the suspension, the same reactivation is refused.
///
/// The discriminator for the test above: an issuer that is still `Active`
/// cannot be reactivated.
#[test]
fn without_the_suspension_the_same_reactivation_is_refused() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let issuer = KeyPair::generate();
    fund(&db, &issuer, 10_000_000);
    let proposer = Address::new([9; 20]);

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);
    executor
        .execute_tx(
            &mut view,
            &signed(
                &issuer,
                0,
                EmploymentOperation::RegisterIssuer,
                &issuer_of(&issuer),
            ),
            &proposer,
            1,
            1000,
        )
        .unwrap();

    let r = executor
        .execute_tx(
            &mut view,
            &signed(&issuer, 1, EmploymentOperation::ReactivateIssuer, &Empty {}),
            &proposer,
            1,
            3000,
        )
        .unwrap();
    assert_eq!(
        r.status, EMPLOYMENT_FAILED,
        "an issuer that was never suspended cannot be reactivated"
    );
    assert_eq!(
        StateManager::v_get_nonce(&view, &issuer.address()).unwrap(),
        1,
        "one registration, one refusal"
    );
}

// ── Same-block duplicate guards ─────────────────────────────────────────────

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
    for (nonce, expect_success) in [(0u64, true), (1u64, false)] {
        let r = executor
            .execute_tx(
                &mut view,
                &signed(
                    &issuer,
                    nonce,
                    EmploymentOperation::RegisterIssuer,
                    &issuer_of(&issuer),
                ),
                &proposer,
                1,
                1000,
            )
            .unwrap();
        if expect_success {
            assert!(matches!(r.status, TxStatus::Success), "{:?}", r.status);
        } else {
            assert_eq!(
                r.status, EMPLOYMENT_FAILED,
                "the duplicate must be refused BY THE EMPLOYMENT GUARD, not \
                 rejected earlier for some unrelated reason"
            );
        }
    }
    assert_eq!(
        StateManager::v_get_nonce(&view, &issuer.address()).unwrap(),
        1,
        "one successful registration, one refusal"
    );
    let rows: Vec<_> = view
        .prefix_iter(cf::EMPLOYMENT_ISSUERS, &[])
        .unwrap()
        .map(|r| r.unwrap())
        .collect();
    assert_eq!(rows.len(), 1, "the duplicate must not leave a second row");
}

/// Two credentials with the same employment id in one block: the second is
/// refused.
#[test]
fn a_duplicate_employment_id_in_the_same_block_is_refused() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let issuer = KeyPair::generate();
    fund(&db, &issuer, 10_000_000);
    let proposer = Address::new([9; 20]);
    EmploymentStore::new(&db)
        .issuers()
        .put(&issuer_of(&issuer))
        .unwrap();

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);
    let cred = credential_of(&issuer, 1, Address::new([7; 20]), [0x55; 32], [0x66; 32]);

    let r0 = executor
        .execute_tx(
            &mut view,
            &signed(&issuer, 0, EmploymentOperation::CreateEmployment, &cred),
            &proposer,
            1,
            1000,
        )
        .unwrap();
    assert!(matches!(r0.status, TxStatus::Success), "{:?}", r0.status);

    // A different employee, the SAME id: only the duplicate guard can refuse it.
    let clash = credential_of(&issuer, 1, Address::new([8; 20]), [0x57; 32], [0x66; 32]);
    let r1 = executor
        .execute_tx(
            &mut view,
            &signed(&issuer, 1, EmploymentOperation::CreateEmployment, &clash),
            &proposer,
            1,
            1000,
        )
        .unwrap();
    assert_eq!(
        r1.status, EMPLOYMENT_FAILED,
        "the second credential at that id must be refused by the candidate guard"
    );
    assert_eq!(
        StateManager::v_get_nonce(&view, &issuer.address()).unwrap(),
        1
    );
    assert_eq!(
        EmploymentExecutor::v_get_credential(&view, &[1u8; 32])
            .unwrap()
            .unwrap()
            .employee_address,
        Address::new([7; 20]),
        "and the first credential is the one that survives"
    );
    assert!(
        EmploymentExecutor::v_get_employee_credential_ids(&view, &[0x57; 32])
            .unwrap()
            .is_empty(),
        "the refused credential indexed nothing"
    );
}

/// Two attestations with the same id in one block: the second is refused.
#[test]
fn a_duplicate_attestation_id_in_the_same_block_is_refused() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let issuer = KeyPair::generate();
    fund(&db, &issuer, 10_000_000);
    let proposer = Address::new([9; 20]);
    EmploymentStore::new(&db)
        .issuers()
        .put(&issuer_of(&issuer))
        .unwrap();

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);
    let att = attestation_of(&issuer, 2, Address::new([7; 20]), [0x88; 32]);
    let r0 = executor
        .execute_tx(
            &mut view,
            &signed(
                &issuer,
                0,
                EmploymentOperation::CreateIncomeAttestation,
                &att,
            ),
            &proposer,
            1,
            1000,
        )
        .unwrap();
    assert!(matches!(r0.status, TxStatus::Success), "{:?}", r0.status);

    let clash = attestation_of(&issuer, 2, Address::new([8; 20]), [0x89; 32]);
    let r1 = executor
        .execute_tx(
            &mut view,
            &signed(
                &issuer,
                1,
                EmploymentOperation::CreateIncomeAttestation,
                &clash,
            ),
            &proposer,
            1,
            1000,
        )
        .unwrap();
    assert_eq!(r1.status, EMPLOYMENT_FAILED);
    assert_eq!(
        StateManager::v_get_nonce(&view, &issuer.address()).unwrap(),
        1
    );
    assert!(
        EmploymentExecutor::v_get_subject_attestation_ids(&view, &[0x89; 32])
            .unwrap()
            .is_empty(),
        "the refused attestation indexed nothing"
    );
}

/// Two proofs with the same id in one block: the second is refused.
#[test]
fn a_duplicate_proof_in_the_same_block_is_refused() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let submitter = KeyPair::generate();
    fund(&db, &submitter, 10_000_000);
    let proposer = Address::new([9; 20]);

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);
    let r0 = executor
        .execute_tx(
            &mut view,
            &signed(
                &submitter,
                0,
                EmploymentOperation::SubmitProof,
                &proof_of(3),
            ),
            &proposer,
            1,
            1000,
        )
        .unwrap();
    assert!(matches!(r0.status, TxStatus::Success), "{:?}", r0.status);
    assert_eq!(
        EmploymentExecutor::v_get_proof(&view, &[3u8; 32])
            .unwrap()
            .map(|p| p.proof_id),
        Some([3u8; 32]),
        "the proof is readable from the candidate"
    );

    let mut clash = proof_of(3);
    clash.proof_data = vec![9, 9];
    let r1 = executor
        .execute_tx(
            &mut view,
            &signed(&submitter, 1, EmploymentOperation::SubmitProof, &clash),
            &proposer,
            1,
            1000,
        )
        .unwrap();
    assert_eq!(
        r1.status, EMPLOYMENT_FAILED,
        "the second proof at that id must be refused by the candidate guard"
    );
    assert_eq!(
        StateManager::v_get_nonce(&view, &submitter.address()).unwrap(),
        1
    );
    assert_eq!(
        EmploymentExecutor::v_get_proof(&view, &[3u8; 32])
            .unwrap()
            .unwrap()
            .proof_data,
        vec![7, 7, 7],
        "and the first proof is the one that survives"
    );
}

// ── Same-block visibility: credentials and attestations ─────────────────────

/// An update finds the credential created earlier in the same block.
#[test]
fn an_update_finds_the_credential_created_earlier_in_the_same_block() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let issuer = KeyPair::generate();
    fund(&db, &issuer, 10_000_000);
    let proposer = Address::new([9; 20]);
    EmploymentStore::new(&db)
        .issuers()
        .put(&issuer_of(&issuer))
        .unwrap();

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);
    let cred = credential_of(&issuer, 1, Address::new([7; 20]), [0x55; 32], [0x66; 32]);
    executor
        .execute_tx(
            &mut view,
            &signed(&issuer, 0, EmploymentOperation::CreateEmployment, &cred),
            &proposer,
            1,
            1000,
        )
        .unwrap();

    let r = executor
        .execute_tx(
            &mut view,
            &signed(
                &issuer,
                1,
                EmploymentOperation::UpdateEmployment,
                &UpdateEmploymentData {
                    employment_id: [1u8; 32],
                    status: EmploymentStatus::OnLeave,
                },
            ),
            &proposer,
            1,
            4000,
        )
        .unwrap();
    assert!(
        matches!(r.status, TxStatus::Success),
        "the update must find the credential this block created: {:?}",
        r.status
    );
    let staged = EmploymentExecutor::v_get_credential(&view, &[1u8; 32])
        .unwrap()
        .unwrap();
    assert_eq!(staged.status, EmploymentStatus::OnLeave);
    assert_eq!(
        staged.updated_at, 0,
        "the dispatch arm's placeholder timestamp"
    );
}

/// Without the creation, the same update is refused.
#[test]
fn without_the_creation_the_same_employment_update_is_refused() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let issuer = KeyPair::generate();
    fund(&db, &issuer, 10_000_000);
    let proposer = Address::new([9; 20]);
    EmploymentStore::new(&db)
        .issuers()
        .put(&issuer_of(&issuer))
        .unwrap();

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);
    let r = executor
        .execute_tx(
            &mut view,
            &signed(
                &issuer,
                0,
                EmploymentOperation::UpdateEmployment,
                &UpdateEmploymentData {
                    employment_id: [1u8; 32],
                    status: EmploymentStatus::OnLeave,
                },
            ),
            &proposer,
            1,
            4000,
        )
        .unwrap();
    assert_eq!(r.status, EMPLOYMENT_FAILED);
    assert!(families_changed(&db, &view).is_empty(), "and stage nothing");
    assert_eq!(
        StateManager::v_get_nonce(&view, &issuer.address()).unwrap(),
        0
    );
}

/// A revocation finds the attestation created earlier in the same block.
#[test]
fn a_revocation_finds_the_attestation_created_earlier_in_the_same_block() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let issuer = KeyPair::generate();
    fund(&db, &issuer, 10_000_000);
    let proposer = Address::new([9; 20]);
    EmploymentStore::new(&db)
        .issuers()
        .put(&issuer_of(&issuer))
        .unwrap();

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);
    let att = attestation_of(&issuer, 2, Address::new([7; 20]), [0x88; 32]);
    executor
        .execute_tx(
            &mut view,
            &signed(
                &issuer,
                0,
                EmploymentOperation::CreateIncomeAttestation,
                &att,
            ),
            &proposer,
            1,
            1000,
        )
        .unwrap();

    let r = executor
        .execute_tx(
            &mut view,
            &signed(
                &issuer,
                1,
                EmploymentOperation::RevokeIncomeAttestation,
                &RevokeAttestationData {
                    attestation_id: [2u8; 32],
                    revocation_ref: [0xFA; 32],
                },
            ),
            &proposer,
            1,
            5000,
        )
        .unwrap();
    assert!(
        matches!(r.status, TxStatus::Success),
        "the revocation must find the attestation this block created: {:?}",
        r.status
    );
    let staged = EmploymentExecutor::v_get_attestation(&view, &[2u8; 32])
        .unwrap()
        .unwrap();
    assert_eq!(staged.revocation_ref, Some([0xFA; 32]));
    assert_eq!(
        staged.updated_at, 0,
        "the dispatch arm's placeholder timestamp"
    );
}

/// Without the creation, the same revocation is refused.
#[test]
fn without_the_creation_the_same_attestation_revocation_is_refused() {
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
                EmploymentOperation::RevokeIncomeAttestation,
                &RevokeAttestationData {
                    attestation_id: [2u8; 32],
                    revocation_ref: [0xFA; 32],
                },
            ),
            &proposer,
            1,
            5000,
        )
        .unwrap();
    assert_eq!(r.status, EMPLOYMENT_FAILED);
    assert!(families_changed(&db, &view).is_empty());
    assert_eq!(
        StateManager::v_get_nonce(&view, &issuer.address()).unwrap(),
        0
    );
}

// ── The accumulating index lists ────────────────────────────────────────────

/// Two credentials for one employee in one block: all three index lists hold
/// BOTH ids.
///
/// Each index value is an accumulating `Vec<EmploymentId>`. Reading it from
/// committed state would give the second credential an empty list, and it would
/// overwrite the first one's entry with a single-element one.
#[test]
fn two_credentials_for_one_employee_accumulate_in_all_three_indexes() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let issuer = KeyPair::generate();
    fund(&db, &issuer, 10_000_000);
    let proposer = Address::new([9; 20]);
    EmploymentStore::new(&db)
        .issuers()
        .put(&issuer_of(&issuer))
        .unwrap();
    let employee = Address::new([7; 20]);

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);
    for (nonce, id) in [(0u64, 1u8), (1u64, 2u8)] {
        let cred = credential_of(&issuer, id, employee, [0x55; 32], [0x66; 32]);
        let r = executor
            .execute_tx(
                &mut view,
                &signed(&issuer, nonce, EmploymentOperation::CreateEmployment, &cred),
                &proposer,
                1,
                1000,
            )
            .unwrap();
        assert!(matches!(r.status, TxStatus::Success), "{:?}", r.status);
    }

    let both = vec![[1u8; 32], [2u8; 32]];
    assert_eq!(
        EmploymentExecutor::v_get_employee_credential_ids(&view, &[0x55; 32]).unwrap(),
        both,
        "the employee-commitment index: both ids, in creation order"
    );
    assert_eq!(
        EmploymentExecutor::v_get_employee_address_credential_ids(&view, &employee).unwrap(),
        both,
        "the employee-address index"
    );
    assert_eq!(
        EmploymentExecutor::v_get_employer_credential_ids(&view, &[0x66; 32]).unwrap(),
        both,
        "and the employer index -- each one a separate read-modify-write"
    );
}

/// Two attestations for one subject and one holder in one block: both index
/// lists hold BOTH ids.
#[test]
fn two_attestations_for_one_subject_accumulate_in_both_indexes() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let issuer = KeyPair::generate();
    fund(&db, &issuer, 10_000_000);
    let proposer = Address::new([9; 20]);
    EmploymentStore::new(&db)
        .issuers()
        .put(&issuer_of(&issuer))
        .unwrap();
    let holder = Address::new([7; 20]);

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);
    for (nonce, id) in [(0u64, 1u8), (1u64, 2u8)] {
        let att = attestation_of(&issuer, id, holder, [0x88; 32]);
        let r = executor
            .execute_tx(
                &mut view,
                &signed(
                    &issuer,
                    nonce,
                    EmploymentOperation::CreateIncomeAttestation,
                    &att,
                ),
                &proposer,
                1,
                1000,
            )
            .unwrap();
        assert!(matches!(r.status, TxStatus::Success), "{:?}", r.status);
    }

    let both = vec![[1u8; 32], [2u8; 32]];
    assert_eq!(
        EmploymentExecutor::v_get_subject_attestation_ids(&view, &[0x88; 32]).unwrap(),
        both,
        "the subject index: both ids, in creation order"
    );
    assert_eq!(
        EmploymentExecutor::v_get_holder_address_attestation_ids(&view, &holder).unwrap(),
        both,
        "and the holder-address index"
    );
}

// ── Abandonment ─────────────────────────────────────────────────────────────

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

        let cred = credential_of(&issuer, 1, Address::new([7; 20]), [0x55; 32], [0x66; 32]);
        let att = attestation_of(&issuer, 2, Address::new([8; 20]), [0x88; 32]);
        let steps: Vec<(u64, EmploymentOperation, Vec<u8>)> = vec![
            (
                0,
                EmploymentOperation::RegisterIssuer,
                bincode::serialize(&issuer_of(&issuer)).unwrap(),
            ),
            (
                1,
                EmploymentOperation::CreateEmployment,
                bincode::serialize(&cred).unwrap(),
            ),
            (
                2,
                EmploymentOperation::CreateIncomeAttestation,
                bincode::serialize(&att).unwrap(),
            ),
            (
                3,
                EmploymentOperation::SubmitProof,
                bincode::serialize(&proof_of(3)).unwrap(),
            ),
        ];
        for (nonce, op, data) in steps {
            let tx = TransactionV2 {
                chain_id: CHAIN_ID,
                from: issuer.address(),
                fee: 100,
                nonce,
                payload: TxPayload::Employment(EmploymentTxData {
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

        // Per family, a real DIFF against the committed rows. Presence in the
        // merged view would prove nothing.
        let touched = families_changed(&db, &view);
        for f in EMPLOYMENT_CFS {
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
        "an abandoned block must leave every employment row byte-identical"
    );
}

// ── Limit refusal ───────────────────────────────────────────────────────────

/// A refusal leaves canonical storage untouched, and at least one ceiling
/// refuses with the credential staged and its indexes not.
///
/// The operation has to be `CreateEmployment` for that to be reachable at all.
/// Most employment operations write ONE row, and the fee and nonce writes come
/// before it, so a ceiling either refuses during the account writes -- nothing
/// employment staged -- or fits the whole transaction. `CreateEmployment`
/// writes FOUR, the credential and its three index entries, so a ceiling can
/// land between them.
///
/// The partial is asserted as EXACT state rather than "some family is
/// non-empty": the credential readable through the view, the employee index
/// row not, and the canonical rows unchanged. All four families start
/// canonically empty (only the issuer is seeded), so a row readable through the
/// merged view can only have come from the candidate.
///
/// Every ceiling below the measured cost is tried, not a sample: the intervals
/// between the four writes are a handful of bytes wide and a stepped sweep can
/// step straight over one.
#[test]
fn a_refusal_leaves_canonical_storage_untouched() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let issuer = KeyPair::generate();
    fund(&db, &issuer, 100_000_000);
    let proposer = Address::new([9; 20]);
    // The issuer is committed, the way an earlier block would have left it, so
    // this transaction's only employment writes are the credential and its
    // three indexes.
    EmploymentStore::new(&db)
        .issuers()
        .put(&issuer_of(&issuer))
        .unwrap();
    let employee = Address::new([7; 20]);
    let before = canonical(&db);

    for f in [
        cf::EMPLOYMENT_CREDENTIALS,
        cf::EMPLOYMENT_EMPLOYEE_INDEX,
        cf::EMPLOYMENT_EMPLOYEE_ADDRESS_INDEX,
        cf::EMPLOYMENT_EMPLOYER_INDEX,
    ] {
        assert!(
            db.prefix_iter(f, &[]).unwrap().next().is_none(),
            "{f} must start empty for this test to read the candidate through \
             the merged view"
        );
    }

    let cred = credential_of(&issuer, 1, employee, [0x55; 32], [0x66; 32]);
    let tx = signed(&issuer, 0, EmploymentOperation::CreateEmployment, &cred);
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
    assert!(full > 1, "a credential must cost something");

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

        let row_staged = view
            .get(cf::EMPLOYMENT_CREDENTIALS, &[1u8; 32])
            .unwrap()
            .is_some();
        let employee_staged = view
            .get(cf::EMPLOYMENT_EMPLOYEE_INDEX, &[0x55u8; 32])
            .unwrap()
            .is_some();
        let employee_addr_staged = view
            .get(cf::EMPLOYMENT_EMPLOYEE_ADDRESS_INDEX, employee.as_bytes())
            .unwrap()
            .is_some();
        let employer_staged = view
            .get(cf::EMPLOYMENT_EMPLOYER_INDEX, &[0x66u8; 32])
            .unwrap()
            .is_some();

        if row_staged && !employee_staged {
            partials += 1;
        }
        // No index entry can exist without the credential it points at: that
        // is the write order, and reversing it would show up here.
        for (label, staged) in [
            ("employee", employee_staged),
            ("employee-address", employee_addr_staged),
            ("employer", employer_staged),
        ] {
            assert!(
                !staged || row_staged,
                "ceiling {ceiling} staged the {label} index without the \
                 credential, which the committed write order cannot produce"
            );
        }
        // And the three indexes are filled in a fixed order too.
        assert!(
            !employee_addr_staged || employee_staged,
            "ceiling {ceiling}: the employee-address index was staged before \
             the employee index"
        );
        assert!(
            !employer_staged || employee_addr_staged,
            "ceiling {ceiling}: the employer index was staged before the \
             employee-address index"
        );
        assert_eq!(
            canonical(&db),
            before,
            "ceiling {ceiling} must leave canonical storage as it was"
        );
    }

    assert!(
        partials > 0,
        "no ceiling refused with the credential staged and its employee index \
         not -- either those two writes stopped being separate, or this sweep \
         stopped covering the interval between them"
    );
}

// ── Index parity ────────────────────────────────────────────────────────────

/// Published rows satisfy every committed point lookup and scan the RPC uses.
///
/// `employment_get_issuer`, `employment_list_issuers`,
/// `employment_get_credential`, `..._by_employee`, `..._by_employer`,
/// `..._by_employee_address`, their `active` variants,
/// `employment_get_income_attestation`, `..._by_subject` and
/// `..._by_holder_address` all read through these store methods, so each one is
/// exercised here against a block the candidate actually published.
#[test]
fn published_rows_satisfy_the_committed_scans() {
    let (state, db, _dir, executor) = setup_with_params(params());
    let issuer = KeyPair::generate();
    fund(&db, &issuer, 100_000_000);
    let employee = Address::new([7; 20]);
    let holder = Address::new([8; 20]);

    let cred = credential_of(&issuer, 1, employee, [0x55; 32], [0x66; 32]);
    let att = attestation_of(&issuer, 2, holder, [0x88; 32]);
    let receipts = common::publish_block(
        &state,
        &executor,
        1,
        &[3u8; 32],
        vec![
            signed(
                &issuer,
                0,
                EmploymentOperation::RegisterIssuer,
                &issuer_of(&issuer),
            ),
            signed(&issuer, 1, EmploymentOperation::CreateEmployment, &cred),
            signed(
                &issuer,
                2,
                EmploymentOperation::CreateIncomeAttestation,
                &att,
            ),
            signed(&issuer, 3, EmploymentOperation::SubmitProof, &proof_of(3)),
        ],
        &[],
    );
    assert!(
        receipts
            .iter()
            .all(|r| matches!(r.status, TxStatus::Success)),
        "all four must succeed: {:?}",
        receipts.iter().map(|r| r.status).collect::<Vec<_>>()
    );

    let store = EmploymentStore::new(&db);

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
    assert_eq!(
        store.issuers().list_active().unwrap().len(),
        1,
        "the active-issuer scan"
    );

    assert_eq!(
        store
            .credentials()
            .get(&[1u8; 32])
            .unwrap()
            .map(|c| c.employment_id),
        Some([1u8; 32]),
        "the credential point lookup"
    );
    assert!(store.credentials().exists(&[1u8; 32]).unwrap());
    let ids = |v: Vec<EmploymentCredential>| v.iter().map(|c| c.employment_id).collect::<Vec<_>>();
    assert_eq!(
        ids(store.credentials().get_by_employee(&[0x55; 32]).unwrap()),
        vec![[1u8; 32]],
        "the employee-commitment index, which the candidate wrote"
    );
    assert_eq!(
        ids(store
            .credentials()
            .get_active_by_employee(&[0x55; 32], 1_000)
            .unwrap()),
        vec![[1u8; 32]],
        "and its active filter"
    );
    assert_eq!(
        ids(store.credentials().get_by_employer(&[0x66; 32]).unwrap()),
        vec![[1u8; 32]],
        "the employer index"
    );
    assert_eq!(
        ids(store
            .credentials()
            .get_by_employee_address(&employee)
            .unwrap()),
        vec![[1u8; 32]],
        "the employee-address index"
    );
    assert_eq!(
        ids(store
            .credentials()
            .get_active_by_employee_address(&employee, 1_000)
            .unwrap()),
        vec![[1u8; 32]],
        "and its active filter"
    );

    let att_ids =
        |v: Vec<IncomeAttestation>| v.iter().map(|a| a.attestation_id).collect::<Vec<_>>();
    assert_eq!(
        store
            .income_attestations()
            .get(&[2u8; 32])
            .unwrap()
            .map(|a| a.attestation_id),
        Some([2u8; 32]),
        "the attestation point lookup"
    );
    assert!(store.income_attestations().exists(&[2u8; 32]).unwrap());
    assert_eq!(
        att_ids(
            store
                .income_attestations()
                .get_by_subject(&[0x88; 32])
                .unwrap()
        ),
        vec![[2u8; 32]],
        "the subject income index"
    );
    assert_eq!(
        att_ids(
            store
                .income_attestations()
                .get_valid_by_subject(&[0x88; 32], 1_000)
                .unwrap()
        ),
        vec![[2u8; 32]]
    );
    assert_eq!(
        att_ids(
            store
                .income_attestations()
                .get_by_holder_address(&holder)
                .unwrap()
        ),
        vec![[2u8; 32]],
        "the holder-address index"
    );
    assert_eq!(
        att_ids(
            store
                .income_attestations()
                .get_valid_by_holder_address(&holder, 1_000)
                .unwrap()
        ),
        vec![[2u8; 32]]
    );

    assert_eq!(
        store.proofs().get(&[3u8; 32]).unwrap().map(|p| p.proof_id),
        Some([3u8; 32]),
        "the proof point lookup"
    );
    assert!(store.proofs().exists(&[3u8; 32]).unwrap());
    assert!(store.proofs().is_valid(&[3u8; 32], 1_000).unwrap());
}

// ── Malformed committed rows ────────────────────────────────────────────────

/// A malformed row makes the routed transaction ERROR; it is never read as
/// absence.
///
/// This is the difference between "no issuer registered" and "the issuer row is
/// corrupt", and the guards branch on exactly that. A candidate reader that
/// swallowed a decode failure into `None` would turn corruption into a
/// duplicate-registration opportunity, or into a credential issued by an issuer
/// whose status could not be read. The `v_get_*` readers propagate, and these
/// prove it through real dispatch rather than by calling the accessor.
///
/// `EMPLOYMENT_PROOFS` is not here: no execution path decodes it, so there is
/// nothing to swallow. Its own behaviour is pinned separately below.
#[test]
fn malformed_rows_error_through_dispatch_and_stage_nothing() {
    let employee = Address::new([7; 20]);
    let holder = Address::new([8; 20]);

    for (family, label) in [
        (cf::EMPLOYMENT_ISSUERS, "issuer"),
        (cf::EMPLOYMENT_CREDENTIALS, "credential"),
        (cf::EMPLOYMENT_EMPLOYEE_INDEX, "employee index"),
        (
            cf::EMPLOYMENT_EMPLOYEE_ADDRESS_INDEX,
            "employee-address index",
        ),
        (cf::EMPLOYMENT_EMPLOYER_INDEX, "employer index"),
        (cf::EMPLOYMENT_INCOME_ATTESTATIONS, "attestation"),
        (cf::EMPLOYMENT_SUBJECT_INCOME_INDEX, "subject income index"),
        (
            cf::EMPLOYMENT_INCOME_HOLDER_ADDRESS_INDEX,
            "holder-address index",
        ),
    ] {
        let (_state, db, _dir, executor) = setup_with_params(params());
        let actor = KeyPair::generate();
        fund(&db, &actor, 100_000_000);
        let proposer = Address::new([9; 20]);
        let store = EmploymentStore::new(&db);

        // A valid, committed, ACTIVE issuer wherever the guard has to get past
        // one to reach the family under test.
        let needs_issuer = matches!(
            family,
            f if f == cf::EMPLOYMENT_EMPLOYEE_INDEX
                || f == cf::EMPLOYMENT_EMPLOYEE_ADDRESS_INDEX
                || f == cf::EMPLOYMENT_EMPLOYER_INDEX
                || f == cf::EMPLOYMENT_SUBJECT_INCOME_INDEX
                || f == cf::EMPLOYMENT_INCOME_HOLDER_ADDRESS_INDEX
        );
        if needs_issuer {
            store.issuers().put(&issuer_of(&actor)).unwrap();
        }

        let key: Vec<u8> = match family {
            f if f == cf::EMPLOYMENT_ISSUERS => actor.address().as_bytes().to_vec(),
            f if f == cf::EMPLOYMENT_CREDENTIALS => vec![1u8; 32],
            f if f == cf::EMPLOYMENT_EMPLOYEE_INDEX => vec![0x55u8; 32],
            f if f == cf::EMPLOYMENT_EMPLOYEE_ADDRESS_INDEX => employee.as_bytes().to_vec(),
            f if f == cf::EMPLOYMENT_EMPLOYER_INDEX => vec![0x66u8; 32],
            f if f == cf::EMPLOYMENT_INCOME_ATTESTATIONS => vec![2u8; 32],
            f if f == cf::EMPLOYMENT_SUBJECT_INCOME_INDEX => vec![0x88u8; 32],
            _ => holder.as_bytes().to_vec(),
        };
        db.put(family, &key, b"not a valid row").unwrap();

        let cred = credential_of(&actor, 1, employee, [0x55; 32], [0x66; 32]);
        let att = attestation_of(&actor, 2, holder, [0x88; 32]);
        // A transaction whose guard has to READ that family.
        let tx = match family {
            f if f == cf::EMPLOYMENT_ISSUERS => signed(
                &actor,
                0,
                EmploymentOperation::UpdateIssuer,
                &UpdateIssuerData {
                    status: IssuerStatus::Suspended,
                },
            ),
            f if f == cf::EMPLOYMENT_CREDENTIALS => signed(
                &actor,
                0,
                EmploymentOperation::SuspendEmployment,
                &EmploymentIdData {
                    employment_id: [1u8; 32],
                },
            ),
            f if f == cf::EMPLOYMENT_INCOME_ATTESTATIONS => signed(
                &actor,
                0,
                EmploymentOperation::RevokeIncomeAttestation,
                &RevokeAttestationData {
                    attestation_id: [2u8; 32],
                    revocation_ref: [0xFA; 32],
                },
            ),
            f if f == cf::EMPLOYMENT_SUBJECT_INCOME_INDEX
                || f == cf::EMPLOYMENT_INCOME_HOLDER_ADDRESS_INDEX =>
            {
                signed(
                    &actor,
                    0,
                    EmploymentOperation::CreateIncomeAttestation,
                    &att,
                )
            }
            // The three credential indexes are read while APPENDING.
            _ => signed(&actor, 0, EmploymentOperation::CreateEmployment, &cred),
        };

        let before = canonical(&db);
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
            // there IS residue: a creation stages the row, and each earlier
            // index, before it reaches the index that fails. Naming the allowed
            // set rather than asserting an empty one keeps that visible instead
            // of silently tolerated.
            let allowed: Vec<&str> = match family {
                f if f == cf::EMPLOYMENT_EMPLOYEE_INDEX => {
                    vec![cf::EMPLOYMENT_CREDENTIALS, cf::EMPLOYMENT_EMPLOYEE_INDEX]
                }
                f if f == cf::EMPLOYMENT_EMPLOYEE_ADDRESS_INDEX => vec![
                    cf::EMPLOYMENT_CREDENTIALS,
                    cf::EMPLOYMENT_EMPLOYEE_INDEX,
                    cf::EMPLOYMENT_EMPLOYEE_ADDRESS_INDEX,
                ],
                f if f == cf::EMPLOYMENT_EMPLOYER_INDEX => vec![
                    cf::EMPLOYMENT_CREDENTIALS,
                    cf::EMPLOYMENT_EMPLOYEE_INDEX,
                    cf::EMPLOYMENT_EMPLOYEE_ADDRESS_INDEX,
                    cf::EMPLOYMENT_EMPLOYER_INDEX,
                ],
                f if f == cf::EMPLOYMENT_SUBJECT_INCOME_INDEX => vec![
                    cf::EMPLOYMENT_INCOME_ATTESTATIONS,
                    cf::EMPLOYMENT_SUBJECT_INCOME_INDEX,
                ],
                f if f == cf::EMPLOYMENT_INCOME_HOLDER_ADDRESS_INDEX => vec![
                    cf::EMPLOYMENT_INCOME_ATTESTATIONS,
                    cf::EMPLOYMENT_SUBJECT_INCOME_INDEX,
                    cf::EMPLOYMENT_INCOME_HOLDER_ADDRESS_INDEX,
                ],
                f => vec![f],
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

/// A CORRUPT proof row is read as PRESENT, and refuses the submission.
///
/// PRE-EXISTING, and reproduced deliberately. `SubmitProof`'s only read of the
/// proof family is a `contains`, which never decodes, so a corrupt row cannot
/// produce a decode error -- but it is not read as absence either. Pinned in
/// both directions: corrupt refuses, and the same submission against an empty
/// family succeeds.
#[test]
fn a_corrupt_proof_row_refuses_the_submission_rather_than_erroring() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let actor = KeyPair::generate();
    fund(&db, &actor, 100_000_000);
    let proposer = Address::new([9; 20]);
    db.put(cf::EMPLOYMENT_PROOFS, &[3u8; 32], b"not a valid row")
        .unwrap();
    let before = canonical(&db);

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);
    // The accessor itself does propagate, which is why nothing about the
    // refusal below is a swallowed decode: it is simply a read that never
    // decodes. Called directly -- no dispatch path reaches this on the
    // submission route, so there is no transaction that could show it.
    assert!(
        EmploymentExecutor::v_get_proof(&view, &[3u8; 32]).is_err(),
        "v_get_proof must ERROR on a corrupt row rather than report absence"
    );
    let r = executor
        .execute_tx(
            &mut view,
            &signed(&actor, 0, EmploymentOperation::SubmitProof, &proof_of(3)),
            &proposer,
            1,
            1000,
        )
        .unwrap();
    assert_eq!(
        r.status, EMPLOYMENT_FAILED,
        "the corrupt row is seen as an existing proof and the duplicate guard \
         refuses -- no decode happens, so there is no error to propagate"
    );
    assert_eq!(
        StateManager::v_get_nonce(&view, &actor.address()).unwrap(),
        0
    );
    assert_eq!(canonical(&db), before, "and nothing is committed");

    // The other direction: at a different id, with nothing seeded, the same
    // submission succeeds. Without this the assertion above would also pass if
    // `SubmitProof` were simply broken.
    let r2 = executor
        .execute_tx(
            &mut view,
            &signed(&actor, 0, EmploymentOperation::SubmitProof, &proof_of(4)),
            &proposer,
            1,
            1000,
        )
        .unwrap();
    assert!(matches!(r2.status, TxStatus::Success), "{:?}", r2.status);
}

// ── The second dispatch surface ─────────────────────────────────────────────

/// `execute_tx_v2` routes employment through the candidate too.
///
/// Two public transaction surfaces exist. `execute_tx` (wrapping
/// `execute_tx_with_validators`) is the live one every test above drives;
/// `execute_tx_v2` is `pub` with no production caller and has its own
/// employment arm. A migration that moved only the live arm would leave the
/// other writing committed rows.
#[test]
fn the_v2_dispatch_surface_also_stages_employment() {
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
        payload: payload(EmploymentOperation::RegisterIssuer, &issuer_of(&issuer)),
    };
    let sig = *sign(tx.signing_hash().as_bytes(), issuer.private_key()).as_bytes();
    let key = *issuer.public_key().as_bytes();

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    {
        let mut view = ExecutionView::new(&mut overlay);
        let r = executor
            .execute_tx_v2(&mut view, &tx, &sig, &key, &proposer, 1, 1000, 0)
            .unwrap();
        assert!(
            matches!(r.status, TxStatus::Success),
            "the v2 surface must execute an employment registration: {:?}",
            r.status
        );
        assert_eq!(
            families_changed(&db, &view),
            vec![cf::EMPLOYMENT_ISSUERS],
            "and stage exactly the issuer family"
        );
        assert_eq!(
            EmploymentExecutor::v_get_issuer(&view, &issuer.address())
                .unwrap()
                .map(|i| i.issuer_address),
            Some(issuer.address()),
            "with the issuer readable from the candidate"
        );
    }

    assert_eq!(
        canonical(&db),
        before,
        "and canonical storage still empty of employment rows"
    );
}

/// The v2 surface refuses a bad employment operation with the SAME status the
/// live surface uses, and advances no nonce.
///
/// The negative control for that surface: without it, a v2 arm that reported
/// success unconditionally would still pass the test above.
#[test]
fn the_v2_dispatch_surface_refuses_with_the_employment_status() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let issuer = KeyPair::generate();
    fund(&db, &issuer, 10_000_000);
    let proposer = Address::new([9; 20]);

    // An update against an issuer that does not exist.
    let tx = TransactionV2 {
        chain_id: CHAIN_ID,
        from: issuer.address(),
        fee: 100,
        nonce: 0,
        payload: payload(
            EmploymentOperation::UpdateIssuer,
            &UpdateIssuerData {
                status: IssuerStatus::Suspended,
            },
        ),
    };
    let sig = *sign(tx.signing_hash().as_bytes(), issuer.private_key()).as_bytes();
    let key = *issuer.public_key().as_bytes();

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);
    let r = executor
        .execute_tx_v2(&mut view, &tx, &sig, &key, &proposer, 1, 1000, 0)
        .unwrap();
    assert_eq!(
        r.status, EMPLOYMENT_FAILED,
        "the v2 arm must return the employment failure status, not success"
    );
    assert_eq!(
        StateManager::v_get_nonce(&view, &issuer.address()).unwrap(),
        0,
        "and charge no nonce"
    );
    assert!(families_changed(&db, &view).is_empty());
}

// ── The preserved defects ───────────────────────────────────────────────────

/// Updating or revoking a credential leaves all three index entries behind.
///
/// PRE-EXISTING: the committed twins rewrite only the credential row. The
/// indexes keep pointing at a credential whose status has changed, `Ended`
/// included, so an index scan still returns it and callers must filter by
/// status themselves. Pinned in both directions.
#[test]
fn revoking_a_credential_leaves_all_three_index_entries_behind() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let issuer = KeyPair::generate();
    fund(&db, &issuer, 100_000_000);
    let proposer = Address::new([9; 20]);
    EmploymentStore::new(&db)
        .issuers()
        .put(&issuer_of(&issuer))
        .unwrap();
    let employee = Address::new([7; 20]);

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);
    let cred = credential_of(&issuer, 1, employee, [0x55; 32], [0x66; 32]);
    executor
        .execute_tx(
            &mut view,
            &signed(&issuer, 0, EmploymentOperation::CreateEmployment, &cred),
            &proposer,
            1,
            1000,
        )
        .unwrap();

    let r = executor
        .execute_tx(
            &mut view,
            &signed(
                &issuer,
                1,
                EmploymentOperation::RevokeEmployment,
                &RevokeEmploymentData {
                    employment_id: [1u8; 32],
                    revocation_ref: [0xFB; 32],
                },
            ),
            &proposer,
            1,
            6000,
        )
        .unwrap();
    assert!(matches!(r.status, TxStatus::Success), "{:?}", r.status);

    let staged = EmploymentExecutor::v_get_credential(&view, &[1u8; 32])
        .unwrap()
        .unwrap();
    assert_eq!(staged.status, EmploymentStatus::Ended);
    assert_eq!(staged.revocation_ref, Some([0xFB; 32]));

    for (label, ids) in [
        (
            "employee",
            EmploymentExecutor::v_get_employee_credential_ids(&view, &[0x55; 32]).unwrap(),
        ),
        (
            "employee-address",
            EmploymentExecutor::v_get_employee_address_credential_ids(&view, &employee).unwrap(),
        ),
        (
            "employer",
            EmploymentExecutor::v_get_employer_credential_ids(&view, &[0x66; 32]).unwrap(),
        ),
    ] {
        assert_eq!(
            ids,
            vec![[1u8; 32]],
            "the {label} index still points at the revoked credential -- a \
             dangling entry the committed path has always left, preserved here \
             rather than fixed inside a migration"
        );
    }
}

/// A SUSPENDED issuer can still revoke the credentials it issued.
///
/// PRE-EXISTING: only `CreateEmployment` and `CreateIncomeAttestation` check
/// that the issuer is active. Every mutation of an existing credential or
/// attestation checks only that the sender is the recorded issuer. Pinned in
/// both directions: the suspended issuer succeeds at revoking, and is refused
/// at creating.
#[test]
fn a_suspended_issuer_can_still_revoke_but_not_create() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let issuer = KeyPair::generate();
    fund(&db, &issuer, 100_000_000);
    let proposer = Address::new([9; 20]);
    EmploymentStore::new(&db)
        .issuers()
        .put(&issuer_of(&issuer))
        .unwrap();
    let employee = Address::new([7; 20]);

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);
    let cred = credential_of(&issuer, 1, employee, [0x55; 32], [0x66; 32]);
    executor
        .execute_tx(
            &mut view,
            &signed(&issuer, 0, EmploymentOperation::CreateEmployment, &cred),
            &proposer,
            1,
            1000,
        )
        .unwrap();
    let suspend = executor
        .execute_tx(
            &mut view,
            &signed(&issuer, 1, EmploymentOperation::SuspendIssuer, &Empty {}),
            &proposer,
            1,
            2000,
        )
        .unwrap();
    assert!(matches!(suspend.status, TxStatus::Success));

    // Still allowed: revoking what it already issued.
    let revoke = executor
        .execute_tx(
            &mut view,
            &signed(
                &issuer,
                2,
                EmploymentOperation::RevokeEmployment,
                &RevokeEmploymentData {
                    employment_id: [1u8; 32],
                    revocation_ref: [0xFB; 32],
                },
            ),
            &proposer,
            1,
            3000,
        )
        .unwrap();
    assert!(
        matches!(revoke.status, TxStatus::Success),
        "a suspended issuer still controls everything it ever issued: {:?}",
        revoke.status
    );

    // Refused: issuing something new.
    let cred2 = credential_of(&issuer, 2, employee, [0x55; 32], [0x66; 32]);
    let create = executor
        .execute_tx(
            &mut view,
            &signed(&issuer, 3, EmploymentOperation::CreateEmployment, &cred2),
            &proposer,
            1,
            3000,
        )
        .unwrap();
    assert_eq!(
        create.status, EMPLOYMENT_FAILED,
        "but it cannot issue anything new"
    );
}

/// `VerifyProof` charges the fee, advances the nonce, and verifies nothing.
///
/// PRE-EXISTING no-op verification: the arm does not read the proof family at
/// all, so it succeeds for a proof id that was never submitted.
#[test]
fn verify_proof_charges_a_fee_and_verifies_nothing() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let actor = KeyPair::generate();
    fund(&db, &actor, 10_000_000);
    let proposer = Address::new([9; 20]);

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);
    let balance_before = StateManager::v_get_balance(&view, &actor.address()).unwrap();

    let r = executor
        .execute_tx(
            &mut view,
            &signed(&actor, 0, EmploymentOperation::VerifyProof, &proof_of(0xEE)),
            &proposer,
            1,
            1000,
        )
        .unwrap();
    assert!(
        matches!(r.status, TxStatus::Success),
        "verification of a proof that does not exist still succeeds: {:?}",
        r.status
    );
    assert_eq!(
        StateManager::v_get_balance(&view, &actor.address()).unwrap(),
        balance_before - 100,
        "the fee is charged"
    );
    assert_eq!(
        StateManager::v_get_nonce(&view, &actor.address()).unwrap(),
        1
    );
    assert!(
        EmploymentExecutor::v_get_proof(&view, &[0xEE; 32])
            .unwrap()
            .is_none(),
        "and no proof row was ever there"
    );
    assert!(
        families_changed(&db, &view).is_empty(),
        "verification writes no employment row at all"
    );
}

/// `UpdateIncomeAttestation` is refused unconditionally, before any fee.
#[test]
fn update_income_attestation_is_refused_before_any_charge() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let actor = KeyPair::generate();
    fund(&db, &actor, 10_000_000);
    let proposer = Address::new([9; 20]);

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);
    let r = executor
        .execute_tx(
            &mut view,
            &signed(
                &actor,
                0,
                EmploymentOperation::UpdateIncomeAttestation,
                &Empty {},
            ),
            &proposer,
            1,
            1000,
        )
        .unwrap();
    assert_eq!(r.status, EMPLOYMENT_FAILED);
    assert_eq!(
        StateManager::v_get_nonce(&view, &actor.address()).unwrap(),
        0,
        "refused before the nonce is charged"
    );
    assert!(families_changed(&db, &view).is_empty());
}

/// Every status update records `updated_at = 0`, whatever the block timestamp.
///
/// PRE-EXISTING: both employment dispatch arms pass a literal `0` where
/// `block_timestamp` belongs (`0, // block_timestamp placeholder`), so the
/// executor's `block_timestamp` parameter is always zero in production and
/// every `updated_at` it writes is zero. The value is still threaded correctly
/// from the arm to the store, which is why this is a defect in the CALL and not
/// in the routing. Pinned in both directions: zero through dispatch, and the
/// real value when the executor is called with one.
#[test]
fn every_status_update_records_a_zero_timestamp_through_dispatch() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let issuer = KeyPair::generate();
    fund(&db, &issuer, 100_000_000);
    let proposer = Address::new([9; 20]);

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);
    for (nonce, op) in [
        (0u64, EmploymentOperation::RegisterIssuer),
        (1, EmploymentOperation::SuspendIssuer),
    ] {
        let tx = match op {
            EmploymentOperation::RegisterIssuer => signed(&issuer, nonce, op, &issuer_of(&issuer)),
            _ => signed(&issuer, nonce, op, &Empty {}),
        };
        // A block timestamp far from zero, which the arm then discards.
        executor
            .execute_tx(&mut view, &tx, &proposer, 1, 1_700_000_000)
            .unwrap();
    }
    assert_eq!(
        EmploymentExecutor::v_get_issuer(&view, &issuer.address())
            .unwrap()
            .unwrap()
            .updated_at,
        0,
        "the dispatch arm passes 0, so no status update can carry a real time"
    );

    // The discriminator. The zero above has to come from somewhere, and this is
    // where: the same call with the block-timestamp activation OPEN threads the
    // real time through. It used to be enough to call `execute` directly with a
    // timestamp, because the arm was the only thing passing zero; the arm now
    // passes `block.header.timestamp` and the executor substitutes zero while
    // the gate is closed, so the discriminator is the gate rather than the call
    // site. ACTIVATION-AUDIT class 2.
    let direct = EmploymentExecutor::execute_with_gates(
        &mut view,
        &issuer.address(),
        &EmploymentTxData {
            operation: EmploymentOperation::ReactivateIssuer,
            data: bincode::serialize(&Empty {}).unwrap(),
            recipient: Address::ZERO,
        },
        &proposer,
        100,
        1,
        1_700_000_000,
        0,
        sumchain_primitives::Hash::default(),
        sumchain_state::EmploymentGates::OPEN,
    )
    .unwrap();
    assert!(direct.success, "{:?}", direct.error);
    assert_eq!(
        EmploymentExecutor::v_get_issuer(&view, &issuer.address())
            .unwrap()
            .unwrap()
            .updated_at,
        1_700_000_000
    );
}

// ── An index list under load ────────────────────────────────────────────────

/// A 640 KiB employee index is refused by the ceiling with a limit error, and
/// commits nothing.
///
/// SCOPE, precisely: this measures ONE size. It shows that at ~20,000 ids the
/// routed path returns a limit error after reaching the index replacement, and
/// leaves canonical state untouched. It does NOT show that arbitrarily large
/// input can never reach an allocator abort -- no test here can, because the
/// value is built before the ceiling is charged.
///
/// The index value is an accumulating `Vec<EmploymentId>` that the committed
/// store has always decoded, linearly searched, appended to and reserialized on
/// every credential. Routing reproduces that exactly; it neither introduces the
/// growth nor bounds it. A bound would make transactions fail that succeed
/// today, which is a consensus change and belongs to activation-gated
/// hardening, not to a migration.
#[test]
fn a_640_kib_employee_index_is_refused_by_the_ceiling_without_canonical_change() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let issuer = KeyPair::generate();
    fund(&db, &issuer, 100_000_000);
    let proposer = Address::new([9; 20]);
    let employee = Address::new([7; 20]);

    EmploymentStore::new(&db)
        .issuers()
        .put(&issuer_of(&issuer))
        .unwrap();
    let existing: Vec<[u8; 32]> = (0..20_000u32)
        .map(|i| {
            let mut id = [0u8; 32];
            id[..4].copy_from_slice(&i.to_be_bytes());
            id
        })
        .collect();
    let committed_index = bincode::serialize(&existing).unwrap();
    assert!(
        committed_index.len() > 600_000,
        "the fixture must actually be the size this test claims: {} bytes",
        committed_index.len()
    );
    db.put(cf::EMPLOYMENT_EMPLOYEE_INDEX, &[0x55; 32], &committed_index)
        .unwrap();
    let before = canonical(&db);

    let cred = credential_of(&issuer, 0xFE, employee, [0x55; 32], [0x66; 32]);
    let tx = signed(&issuer, 0, EmploymentOperation::CreateEmployment, &cred);

    {
        let mut overlay = ApplicationOverlay::new(&db, 8_192);
        let mut view = ExecutionView::new(&mut overlay);
        let err = executor
            .execute_tx(&mut view, &tx, &proposer, 1, 1000)
            .expect_err("an index far larger than the ceiling must be refused");
        assert!(
            err.to_string().contains("limit"),
            "refused by the ceiling, not by something else: {err}"
        );
        // Execution REACHED the index replacement: the credential row is
        // staged, so the refusal is not an earlier account or credential write
        // hitting the ceiling first.
        assert!(
            view.get(cf::EMPLOYMENT_CREDENTIALS, &[0xFEu8; 32])
                .unwrap()
                .is_some(),
            "the credential must be staged, which is what puts the failure at \
             the employee-index write rather than before it"
        );
        assert_eq!(
            view.get(cf::EMPLOYMENT_EMPLOYEE_INDEX, &[0x55u8; 32])
                .unwrap(),
            Some(committed_index.clone()),
            "the candidate must still see the committed index unchanged"
        );
    }
    assert_eq!(canonical(&db), before, "and nothing is committed");

    // With room, it succeeds and the list grows by exactly one, preserving
    // every existing id -- compared in full, not by sampling.
    {
        let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
        let mut view = ExecutionView::new(&mut overlay);
        let r = executor
            .execute_tx(&mut view, &tx, &proposer, 1, 1000)
            .unwrap();
        assert!(matches!(r.status, TxStatus::Success), "{:?}", r.status);
        let ids = EmploymentExecutor::v_get_employee_credential_ids(&view, &[0x55; 32]).unwrap();
        assert_eq!(ids.len(), 20_001, "appended, not replaced");
        assert_eq!(
            &ids[..20_000],
            &existing[..],
            "every existing id preserved, in order"
        );
        assert_eq!(ids[20_000], [0xFEu8; 32], "and the new one last");
    }
    assert_eq!(canonical(&db), before, "still nothing committed");
}

// ── Durability: the published rows, after the handle is closed ───────────────
//
// The two tests below close a gap this suite was accepted with. Everything
// above reads back through the SAME live `Database` handle the block was
// published through, `published_rows_satisfy_the_committed_scans` included.
// A handle can answer a read from its own memtables, so none of it distinguishes
// "the row reached the store" from "the row reached the disk", and none of it
// pins what `ApplicationOverlay::into_batch` actually writes. Legal and finance
// each carry a restart test; property carries a byte-contract test. Employment
// carried neither. These are test-only additions: no production source and no
// existing test body changed to accommodate them.

/// Published employment rows survive closing and reopening the database.
///
/// This drops every `Arc` on the handle -- asserted, by strong count, to be the
/// last one -- closes RocksDB, reopens at the same path, and compares the bytes
/// of all NINE families. RocksDB holds a LOCK file, so a reopen that raced a
/// surviving clone would fail outright rather than quietly return the same live
/// instance; that is what makes this a restart rather than a second handle.
///
/// Both halves matter. The four primary rows, and the five index rows -- the
/// index rows are the ones the candidate built by read-modify-write, and are
/// the ones a durability gap would most plausibly lose.
#[test]
fn published_employment_rows_survive_a_database_restart() {
    let (state, db, dir, executor) = setup_with_params(params());
    let issuer = KeyPair::generate();
    fund(&db, &issuer, 100_000_000);
    let employee = Address::new([7; 20]);
    let holder = Address::new([8; 20]);

    let cred = credential_of(&issuer, 1, employee, [0x55; 32], [0x66; 32]);
    let att = attestation_of(&issuer, 2, holder, [0x88; 32]);
    let receipts = common::publish_block(
        &state,
        &executor,
        1,
        &[3u8; 32],
        vec![
            signed(
                &issuer,
                0,
                EmploymentOperation::RegisterIssuer,
                &issuer_of(&issuer),
            ),
            signed(&issuer, 1, EmploymentOperation::CreateEmployment, &cred),
            signed(
                &issuer,
                2,
                EmploymentOperation::CreateIncomeAttestation,
                &att,
            ),
            signed(&issuer, 3, EmploymentOperation::SubmitProof, &proof_of(4)),
        ],
        &[],
    );
    assert!(
        receipts
            .iter()
            .all(|r| matches!(r.status, TxStatus::Success)),
        "all four must succeed: {:?}",
        receipts.iter().map(|r| r.status).collect::<Vec<_>>()
    );

    let before = canonical(&db);
    // Every one of the nine families must carry a row, or the comparison below
    // is two empty vectors agreeing with each other.
    for f in EMPLOYMENT_CFS {
        assert!(
            before.iter().any(|(fam, _, _)| fam == f),
            "{f} has no published row, so the restart proves nothing about it"
        );
    }

    let path = dir.path().to_path_buf();
    drop(executor);
    drop(state);
    assert_eq!(
        std::sync::Arc::strong_count(&db),
        1,
        "the executor and the state manager must have released their handles, \
         or the reopen below is not a restart"
    );
    drop(db);

    let reopened = Database::open_default(&path).expect("reopen at the same path");

    assert_eq!(
        canonical(&reopened),
        before,
        "every employment row in all nine families must come back byte-identical"
    );

    // Spelled out per family through the committed readers, on the reopened
    // handle, so that a change which emptied `canonical` could not turn the
    // assertion above into a tautology.
    let store = EmploymentStore::new(&reopened);
    assert_eq!(
        store
            .issuers()
            .get(&issuer.address())
            .unwrap()
            .map(|i| i.issuer_address),
        Some(issuer.address()),
        "EMPLOYMENT_ISSUERS"
    );
    assert_eq!(store.issuers().list_active().unwrap().len(), 1);
    assert_eq!(
        store
            .credentials()
            .get(&[1u8; 32])
            .unwrap()
            .map(|c| c.employment_id),
        Some([1u8; 32]),
        "EMPLOYMENT_CREDENTIALS"
    );
    assert_eq!(
        store
            .income_attestations()
            .get(&[2u8; 32])
            .unwrap()
            .map(|a| a.attestation_id),
        Some([2u8; 32]),
        "EMPLOYMENT_INCOME_ATTESTATIONS"
    );
    assert_eq!(
        store.proofs().get(&[4u8; 32]).unwrap().map(|p| p.proof_id),
        Some([4u8; 32]),
        "EMPLOYMENT_PROOFS"
    );

    // The five accumulating index families, read through the scans that
    // decode them.
    let ids = |v: Vec<EmploymentCredential>| v.iter().map(|c| c.employment_id).collect::<Vec<_>>();
    assert_eq!(
        ids(store.credentials().get_by_employee(&[0x55; 32]).unwrap()),
        vec![[1u8; 32]],
        "EMPLOYMENT_EMPLOYEE_INDEX"
    );
    assert_eq!(
        ids(store
            .credentials()
            .get_by_employee_address(&employee)
            .unwrap()),
        vec![[1u8; 32]],
        "EMPLOYMENT_EMPLOYEE_ADDRESS_INDEX"
    );
    assert_eq!(
        ids(store.credentials().get_by_employer(&[0x66; 32]).unwrap()),
        vec![[1u8; 32]],
        "EMPLOYMENT_EMPLOYER_INDEX"
    );
    let att_ids =
        |v: Vec<IncomeAttestation>| v.iter().map(|a| a.attestation_id).collect::<Vec<_>>();
    assert_eq!(
        att_ids(
            store
                .income_attestations()
                .get_by_subject(&[0x88; 32])
                .unwrap()
        ),
        vec![[2u8; 32]],
        "EMPLOYMENT_SUBJECT_INCOME_INDEX"
    );
    assert_eq!(
        att_ids(
            store
                .income_attestations()
                .get_by_holder_address(&holder)
                .unwrap()
        ),
        vec![[2u8; 32]],
        "EMPLOYMENT_INCOME_HOLDER_ADDRESS_INDEX"
    );
}

/// The PUBLISHED bytes are the byte contract, and this pins them directly.
///
/// Candidate-vs-expectation tests and restart-parity tests between them still
/// leave `ApplicationOverlay::into_batch` unpinned: the first never reaches
/// canonical storage, and the second compares the published rows to THEMSELVES.
/// If that step reordered a key, dropped a prefix or re-encoded a value, every
/// other assertion in this file would still pass.
///
/// So: publish a real block through the real publisher, then for all nine
/// families read the RAW committed bytes and compare them against a key written
/// out by hand and a value produced by `bincode::serialize` applied here in the
/// test. Nothing on the expected side calls a key builder or a codec from the
/// crate under test -- the key shapes are transcribed from the schema
/// (`issuer_key` and the two address indexes are the 20-byte wallet address;
/// every other key is a bare 32-byte id or commitment; index VALUES are bincode
/// `Vec<[u8; 32]>`, not presence markers). Then close the database, reopen it
/// at the same path, and compare the same nine expectations again.
#[test]
fn published_employment_bytes_match_independently_built_keys_and_values() {
    let (state, db, dir, executor) = setup_with_params(params());
    let issuer = KeyPair::generate();
    fund(&db, &issuer, 100_000_000);
    let employee = Address::new([7; 20]);
    let holder = Address::new([8; 20]);

    // Expectations built here, from the schema, with no help from the crate.
    let issuer_v = issuer_of(&issuer);
    let cred_v = credential_of(&issuer, 1, employee, [0x55; 32], [0x66; 32]);
    let att_v = attestation_of(&issuer, 2, holder, [0x88; 32]);
    let proof_v = proof_of(4);

    let expected: Vec<(&str, Vec<u8>, Vec<u8>)> = vec![
        (
            cf::EMPLOYMENT_ISSUERS,
            issuer.address().as_bytes().to_vec(),
            bincode::serialize(&issuer_v).unwrap(),
        ),
        (
            cf::EMPLOYMENT_CREDENTIALS,
            vec![1u8; 32],
            bincode::serialize(&cred_v).unwrap(),
        ),
        (
            cf::EMPLOYMENT_EMPLOYEE_INDEX,
            vec![0x55u8; 32],
            bincode::serialize(&vec![[1u8; 32]]).unwrap(),
        ),
        (
            cf::EMPLOYMENT_EMPLOYEE_ADDRESS_INDEX,
            employee.as_bytes().to_vec(),
            bincode::serialize(&vec![[1u8; 32]]).unwrap(),
        ),
        (
            cf::EMPLOYMENT_EMPLOYER_INDEX,
            vec![0x66u8; 32],
            bincode::serialize(&vec![[1u8; 32]]).unwrap(),
        ),
        (
            cf::EMPLOYMENT_INCOME_ATTESTATIONS,
            vec![2u8; 32],
            bincode::serialize(&att_v).unwrap(),
        ),
        (
            cf::EMPLOYMENT_SUBJECT_INCOME_INDEX,
            vec![0x88u8; 32],
            bincode::serialize(&vec![[2u8; 32]]).unwrap(),
        ),
        (
            cf::EMPLOYMENT_INCOME_HOLDER_ADDRESS_INDEX,
            holder.as_bytes().to_vec(),
            bincode::serialize(&vec![[2u8; 32]]).unwrap(),
        ),
        (
            cf::EMPLOYMENT_PROOFS,
            vec![4u8; 32],
            bincode::serialize(&proof_v).unwrap(),
        ),
    ];
    assert_eq!(
        expected.len(),
        EMPLOYMENT_CFS.len(),
        "one expectation per migrated family, and the list must not drift"
    );

    let receipts = common::publish_block(
        &state,
        &executor,
        1,
        &[3u8; 32],
        vec![
            signed(&issuer, 0, EmploymentOperation::RegisterIssuer, &issuer_v),
            signed(&issuer, 1, EmploymentOperation::CreateEmployment, &cred_v),
            signed(
                &issuer,
                2,
                EmploymentOperation::CreateIncomeAttestation,
                &att_v,
            ),
            signed(&issuer, 3, EmploymentOperation::SubmitProof, &proof_v),
        ],
        &[],
    );
    assert!(
        receipts
            .iter()
            .all(|r| matches!(r.status, TxStatus::Success)),
        "all four must succeed: {:?}",
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
    // And the family holds exactly that one row -- so a publisher that wrote
    // the right bytes at an extra key would still be caught.
    for family in EMPLOYMENT_CFS {
        assert_eq!(
            db.prefix_iter(family, &[]).unwrap().count(),
            1,
            "{family} must hold exactly the one published row"
        );
    }

    let path = dir.path().to_path_buf();
    drop(executor);
    drop(state);
    assert_eq!(
        std::sync::Arc::strong_count(&db),
        1,
        "nothing else may hold the database, or the drop below does not close \
         it and the reopen proves nothing"
    );
    drop(db);

    let reopened = Database::open_default(&path).unwrap();
    for (family, key, value) in &expected {
        assert_eq!(
            reopened.get(family, key).unwrap().as_deref(),
            Some(&value[..]),
            "{family}: the row changed across a close and reopen"
        );
    }
}

// ── Class 3: the Employment issuer-standing rule, and its activation ─────────
//
// `docs/lane-a/ACTIVATION-AUDIT.md` row AU-27. Only `CreateEmployment` and
// `CreateIncomeAttestation` require an active issuer; every mutation checks
// only the address recorded on the row. The pinning test
// `a_suspended_issuer_can_still_revoke_but_not_create` states the asymmetry in
// its own name and still passes unchanged.
//
// Gated on `employment_authorization_enabled_from_height`, a `ChainParams`
// field this track cannot add.
//
// AU-28 -- the `UpdateIssuer` sender check is structurally unable to fire,
// because the row is fetched BY the sender key and registration forces the
// equality the comparison later tests -- is NOT addressed here and is not
// claimed to be. It is a dead check, not a hole: removing it would be tidier
// and would close nothing.

use sumchain_state::EmploymentGates;

/// Drive one Employment operation through the gate seam.
fn employment_at(
    view: &mut ExecutionView<'_, '_>,
    sender: &Address,
    op: EmploymentOperation,
    data: &impl serde::Serialize,
    gates: EmploymentGates,
) -> sumchain_state::EmploymentExecutionResult {
    let proposer = Address::new([9; 20]);
    EmploymentExecutor::execute_with_gates(
        view,
        sender,
        &EmploymentTxData {
            operation: op,
            data: bincode::serialize(data).unwrap(),
            recipient: Address::ZERO,
        },
        &proposer,
        100,
        1,
        1_000,
        0,
        sumchain_primitives::Hash::default(),
        gates,
    )
    .unwrap()
}

/// AU-27: the asymmetry, and the gate that removes it.
///
/// The same five operations on both sides. Below the gate a suspended issuer
/// keeps update, suspend, end and revoke and loses only creation; above it,
/// every one of them asks the question creation always asked.
#[test]
fn a_suspended_employment_issuer_loses_its_mutations_only_at_the_gate() {
    for gates in [EmploymentGates::CLOSED, EmploymentGates::OPEN] {
        let (_state, db, _dir, _executor) = setup_with_params(params());
        let issuer = KeyPair::generate();
        fund(&db, &issuer, 100_000_000);
        EmploymentStore::new(&db)
            .issuers()
            .put(&issuer_of(&issuer))
            .unwrap();
        let employee = Address::new([7; 20]);
        let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
        let mut view = ExecutionView::new(&mut overlay);

        let cred = credential_of(&issuer, 1, employee, [0x55; 32], [0x66; 32]);
        assert!(
            employment_at(
                &mut view,
                &issuer.address(),
                EmploymentOperation::CreateEmployment,
                &cred,
                gates
            )
            .success,
            "created while active under either gate"
        );
        assert!(
            employment_at(
                &mut view,
                &issuer.address(),
                EmploymentOperation::SuspendIssuer,
                &Empty {},
                gates
            )
            .success
        );

        let updated = employment_at(
            &mut view,
            &issuer.address(),
            EmploymentOperation::UpdateEmployment,
            &UpdateEmploymentData {
                employment_id: [1u8; 32],
                status: EmploymentStatus::Suspended,
            },
            gates,
        );
        let revoked = employment_at(
            &mut view,
            &issuer.address(),
            EmploymentOperation::RevokeEmployment,
            &RevokeEmploymentData {
                employment_id: [1u8; 32],
                revocation_ref: [0xFB; 32],
            },
            gates,
        );
        assert_eq!(
            (updated.success, revoked.success),
            (!gates.authorization, !gates.authorization),
            "a suspended issuer keeps everything it ever issued, until the gate"
        );

        // Creation is refused on BOTH sides. That is the asymmetry the gate
        // closes: it does not change the creation rule, it extends it.
        let cred2 = credential_of(&issuer, 2, employee, [0x55; 32], [0x66; 32]);
        assert!(
            !employment_at(
                &mut view,
                &issuer.address(),
                EmploymentOperation::CreateEmployment,
                &cred2,
                gates
            )
            .success
        );
    }
}

/// And an issuer in good standing keeps every one of them at the gate.
#[test]
fn an_active_employment_issuer_is_unaffected_by_the_standing_rule() {
    let (_state, db, _dir, _executor) = setup_with_params(params());
    let issuer = KeyPair::generate();
    fund(&db, &issuer, 100_000_000);
    EmploymentStore::new(&db)
        .issuers()
        .put(&issuer_of(&issuer))
        .unwrap();
    let employee = Address::new([7; 20]);
    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);

    let cred = credential_of(&issuer, 3, employee, [0x55; 32], [0x66; 32]);
    for (op, ok) in [
        (EmploymentOperation::CreateEmployment, true),
        (EmploymentOperation::UpdateEmployment, false),
    ] {
        let r = if ok {
            employment_at(
                &mut view,
                &issuer.address(),
                op,
                &cred,
                EmploymentGates::OPEN,
            )
        } else {
            employment_at(
                &mut view,
                &issuer.address(),
                op,
                &UpdateEmploymentData {
                    employment_id: [3u8; 32],
                    status: EmploymentStatus::Suspended,
                },
                EmploymentGates::OPEN,
            )
        };
        assert!(r.success, "{:?}: {:?}", op, r.error);
    }
}
