//! What the Employment and Finance indexes MEAN, tested against the subsystem
//! rather than assumed.
//!
//! ACTIVATION-AUDIT rows OV-4, OV-5 and OV-7 all say the same thing: a status
//! change rewrites only the credential, attestation or issuer row, and the
//! indexes built at creation keep naming it. An earlier pass looked at OV-4 and
//! OV-5 and deliberately did NOT close them, on this reasoning:
//!
//! > unlike OV-3, the credential or attestation the index names still EXISTS;
//! > only its status changed. Removing the entry is a decision about what the
//! > index MEANS -- all ever issued, versus still live -- which nothing in the
//! > subsystem or its spec states.
//!
//! The first half of that is right and the second half is wrong, and this file
//! is why. The subsystem states the meaning in three independent places, and
//! the meaning it states is "every credential ever issued" -- under which the
//! surviving entry is the index working, not a dangling pointer:
//!
//!   1. `EmploymentCredentialStore::summarize_by_employee` counts ENDED
//!      credentials by walking the employee index. An index that dropped an
//!      entry at `EndEmployment` would report `ended = 0` for every employee
//!      who has ever left a job, and `total` would equal `active`. The count
//!      cannot be computed at all from a live-only index.
//!   2. Every index reader is PAIRED: `get_by_employee` beside
//!      `get_active_by_employee`, `get_by_subject` beside
//!      `get_valid_by_subject`, `get_by_holder_address` beside
//!      `get_valid_by_holder_address`, and in Finance `get_by_jurisdiction`
//!      beside `list_active`, which filters on `status.is_active()` while the
//!      jurisdiction reader does not. Both halves of each pair reach the RPC
//!      as separate methods. A pair is only coherent if the unfiltered half
//!      reads an index that holds everything.
//!   3. Removal would be IRREVERSIBLE. `UpdateEmployment` accepts any status,
//!      `Active` included, and `ReactivateIssuer` restores a suspended issuer;
//!      neither `v_update_credential_status` nor `v_update_issuer_status`
//!      writes an index, and no other path re-adds one. So an entry removed on
//!      a status change would never come back, and a restored credential or
//!      issuer would be invisible to every index reader for ever. That is a
//!      NEW defect, strictly worse than the one the rows describe.
//!
//! So OV-4, OV-5 and OV-7 are closed by WITHDRAWING the consequence, not by a
//! gate: there is nothing to activate, and activating the removal they imply
//! would break `employment_getSummary` and lose reactivated rows. The same
//! evidence disposes of AL-4's second clause ("nothing ever removes an entry"),
//! which is the same sentence in the allocation row.
//!
//! Two neighbouring rows are settled here for the same reason -- their stated
//! mechanism does not survive being run:
//!
//!   * OV-8 says Finance `UpdateAddressProof` "refuses BEFORE the fee and nonce
//!     writes, so unlike every other refusal in the subsystem it charges
//!     nothing". The second clause is false: NO refusal in either subsystem
//!     charges anything, and the dispatcher reports `fee_paid: 0` for all of
//!     them. `UpdateAddressProof` is not unlike its neighbours; it is identical
//!     to them.
//!   * AU-24 and AU-28 say the `issuer.issuer_address != *sender` comparison
//!     cannot fire. It can -- against a row no execution path can produce --
//!     and the invariant that keeps it dead is asserted here rather than read.

mod common;

use common::{fund, setup_with_params};
use sumchain_crypto::KeyPair;
use sumchain_genesis::ChainParams;
use sumchain_primitives::employment::{
    EmploymentCredential, EmploymentIssuerClass, EmploymentIssuerProfile, EmploymentOperation,
    EmploymentStatus, EmploymentTxData, EmploymentType, IncomeAttestation, IncomeBracket,
    IncomePeriod, IssuerStatus,
};
use sumchain_primitives::finance::{
    AddressProof, AddressProofType, FinanceIssuerClass, FinanceIssuerProfile, FinanceIssuerStatus,
    FinanceOperation, FinanceTxData,
};
use sumchain_primitives::{Address, Hash};
use sumchain_state::{
    EmploymentExecutor, EmploymentGates, FinanceExecutor, FinanceGates, StateManager,
};
use sumchain_storage::exec_view::ExecutionView;
use sumchain_storage::overlay::ApplicationOverlay;
use sumchain_storage::page::PageSpec;
use sumchain_storage::{cf, EmploymentStore, FinanceStore};

fn params() -> ChainParams {
    ChainParams::with_v2_enabled()
}

const NOW: u64 = 1_000;
const FEE: u128 = 100;
const FUNDED: u128 = 100_000_000;
const JURISDICTION: &str = "US-NY";

const EMPLOYEE_REF: [u8; 32] = [0x55; 32];
const EMPLOYER_REF: [u8; 32] = [0x66; 32];
const SUBJECT_REF: [u8; 32] = [0x99; 32];

fn employee_addr() -> Address {
    Address::new([0x77; 20])
}
fn holder_addr() -> Address {
    Address::new([0x88; 20])
}

// ── Fixtures ────────────────────────────────────────────────────────────────

fn employment_issuer(kp: &KeyPair) -> EmploymentIssuerProfile {
    EmploymentIssuerProfile {
        issuer_address: kp.address(),
        issuer_class: EmploymentIssuerClass::PayrollProcessor,
        display_name: "Payroll Co".to_string(),
        issuer_commitment: [0xA1; 32],
        jurisdiction_code: "US-CA".to_string(),
        policy_id: [0xA2; 32],
        status: IssuerStatus::Active,
        registered_at_height: 1,
        created_at: NOW,
        updated_at: NOW,
    }
}

fn credential_of(kp: &KeyPair, id: u8) -> EmploymentCredential {
    EmploymentCredential {
        employment_id: [id; 32],
        employee_address: employee_addr(),
        employee_ref: EMPLOYEE_REF,
        employer_ref: EMPLOYER_REF,
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
        created_at: NOW,
        updated_at: NOW,
    }
}

fn attestation_of(kp: &KeyPair, id: u8) -> IncomeAttestation {
    IncomeAttestation {
        attestation_id: [id; 32],
        holder_address: holder_addr(),
        subject_ref: SUBJECT_REF,
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
        created_at: NOW,
        updated_at: NOW,
    }
}

fn finance_issuer(kp: &KeyPair) -> FinanceIssuerProfile {
    FinanceIssuerProfile {
        issuer_address: kp.address(),
        issuer_class: FinanceIssuerClass::RegulatedBank,
        issuer_commitment: [2u8; 32],
        jurisdiction_code: JURISDICTION.to_string(),
        policy_id: [3u8; 32],
        status: FinanceIssuerStatus::Active,
        registered_at_height: 1,
        created_at: NOW,
        updated_at: NOW,
    }
}

fn address_proof(kp: &KeyPair, id: u8) -> AddressProof {
    AddressProof {
        proof_id: [id; 32],
        subject_ref: [0x44; 32],
        holder_address: Address::new([0x30; 20]),
        address_commitment: [6u8; 32],
        jurisdiction_code: JURISDICTION.to_string(),
        postal_commitment: [7u8; 32],
        proof_type: AddressProofType::UtilityBill,
        document_date: 900,
        issuer_address: kp.address(),
        issuer_class: FinanceIssuerClass::RegulatedBank,
        valid_from: NOW,
        expiry: 2_000,
        policy_id: [9u8; 32],
        revocation_ref: None,
        created_at: NOW,
        updated_at: NOW,
    }
}

fn employment_at(
    view: &mut ExecutionView<'_, '_>,
    sender: &Address,
    op: EmploymentOperation,
    payload: &impl serde::Serialize,
    gates: EmploymentGates,
) -> sumchain_state::EmploymentExecutionResult {
    EmploymentExecutor::execute_with_gates(
        view,
        sender,
        &EmploymentTxData {
            operation: op,
            data: bincode::serialize(payload).unwrap(),
            recipient: Address::ZERO,
        },
        &Address::new([9; 20]),
        FEE,
        1,
        NOW,
        0,
        Hash::ZERO,
        gates,
    )
    .unwrap()
}

fn finance_at(
    view: &mut ExecutionView<'_, '_>,
    sender: &Address,
    op: FinanceOperation,
    payload: &impl serde::Serialize,
    gates: FinanceGates,
) -> sumchain_state::FinanceExecutionResult {
    FinanceExecutor::execute_with_gates(
        view,
        sender,
        &FinanceTxData {
            operation: op,
            data: bincode::serialize(payload).unwrap(),
            recipient: Address::ZERO,
        },
        &Address::new([9; 20]),
        FEE,
        1,
        NOW,
        0,
        Hash::ZERO,
        gates,
    )
    .unwrap()
}

// ── OV-4: the employee index means "every credential ever issued" ───────────

/// `employment_getSummary`'s `ended` count is computed FROM the employee index.
///
/// Two credentials, one ended. The summary must report `total = 2`,
/// `ended = 1`, `active = 1`. Removing the ended credential's id from the index
/// -- the remedy OV-4 implies -- would make those `1`, `0`, `1`: the `ended`
/// counter would be permanently zero and `total` would silently become "live",
/// for every employee who has ever left a job.
///
/// That is the subsystem stating what its index means, in code, on the path the
/// RPC serves. It is not a spec sentence, and the earlier pass was looking for
/// one; it is stronger than a spec sentence, because a reader depends on it.
#[test]
fn the_employee_index_is_what_the_ended_count_is_computed_from() {
    let (_state, db, _dir, _executor) = setup_with_params(params());
    let issuer = KeyPair::generate();
    let store = EmploymentStore::new(&db);
    store.issuers().put(&employment_issuer(&issuer)).unwrap();
    store
        .credentials()
        .put(&credential_of(&issuer, 0x01))
        .unwrap();
    store
        .credentials()
        .put(&credential_of(&issuer, 0x02))
        .unwrap();

    store
        .credentials()
        .update_status(&[0x02; 32], EmploymentStatus::Ended, NOW)
        .unwrap();

    let summary = store
        .credentials()
        .summarize_by_employee(&EMPLOYEE_REF, NOW, PageSpec::new(0, 100))
        .unwrap();
    assert_eq!(summary.total, 2, "both credentials are still indexed");
    assert_eq!(
        summary.ended, 1,
        "the ENDED count is the load-bearing one: it can only be produced by an \
         index that still names the ended credential"
    );
    assert_eq!(summary.active, 1);
    assert_eq!(summary.active_page.len(), 1);

    // And the id itself is still in the index -- said directly, so that a
    // change to the summary's arithmetic cannot make this test pass for the
    // wrong reason.
    let ids = sumchain_storage::employment_store::decode_id_list(
        &db.get(
            cf::EMPLOYMENT_EMPLOYEE_INDEX,
            sumchain_storage::employment_store::employee_index_key(&EMPLOYEE_REF),
        )
        .unwrap()
        .expect("the index row exists"),
    )
    .unwrap();
    assert!(
        ids.contains(&[0x02; 32]),
        "the ended credential's id is what `ended = 1` was counted from"
    );
}

/// The status filter lives at the READER, and both readers are public.
///
/// `get_by_employee` and `get_active_by_employee` are a pair, and so are
/// `get_by_subject`/`get_valid_by_subject` and
/// `get_by_holder_address`/`get_valid_by_holder_address`. Each pair reaches the
/// RPC as two methods, and each returned row carries its own `status` and
/// `revocation_ref`. A pair like that is only coherent over an index that holds
/// everything: over a live-only index the two halves would be the same query.
#[test]
fn the_status_filter_is_at_the_reader_and_the_unfiltered_reader_is_public() {
    let (_state, db, _dir, _executor) = setup_with_params(params());
    let issuer = KeyPair::generate();
    let store = EmploymentStore::new(&db);
    store.issuers().put(&employment_issuer(&issuer)).unwrap();
    store
        .credentials()
        .put(&credential_of(&issuer, 0x01))
        .unwrap();
    store
        .credentials()
        .put(&credential_of(&issuer, 0x02))
        .unwrap();
    store
        .credentials()
        .revoke(&[0x02; 32], [0xEE; 32], NOW)
        .unwrap();

    assert_eq!(
        store
            .credentials()
            .get_by_employee(&EMPLOYEE_REF)
            .unwrap()
            .len(),
        2,
        "the unfiltered reader answers over the whole index"
    );
    assert_eq!(
        store
            .credentials()
            .get_active_by_employee(&EMPLOYEE_REF, NOW)
            .unwrap()
            .len(),
        1,
        "and its sibling filters -- which is where the subsystem puts the \
         live/all distinction"
    );
    assert_eq!(
        store
            .credentials()
            .get_by_employee_address(&employee_addr())
            .unwrap()
            .len(),
        2
    );
    assert_eq!(
        store
            .credentials()
            .get_active_by_employee_address(&employee_addr(), NOW)
            .unwrap()
            .len(),
        1
    );
    // The employer index has no filtering sibling at all, which is the same
    // statement from the other direction: it is an "all" reader and nothing
    // else.
    assert_eq!(
        store
            .credentials()
            .get_by_employer(&EMPLOYER_REF)
            .unwrap()
            .len(),
        2
    );
}

// ── OV-5: the two income indexes, same shape ────────────────────────────────

#[test]
fn the_two_income_indexes_are_read_by_the_same_all_and_valid_pair() {
    let (_state, db, _dir, _executor) = setup_with_params(params());
    let issuer = KeyPair::generate();
    let store = EmploymentStore::new(&db);
    store.issuers().put(&employment_issuer(&issuer)).unwrap();
    store
        .income_attestations()
        .put(&attestation_of(&issuer, 0x11))
        .unwrap();
    store
        .income_attestations()
        .put(&attestation_of(&issuer, 0x12))
        .unwrap();
    store
        .income_attestations()
        .revoke(&[0x12; 32], [0xEF; 32], NOW)
        .unwrap();

    assert_eq!(
        store
            .income_attestations()
            .get_by_subject(&SUBJECT_REF)
            .unwrap()
            .len(),
        2,
        "OV-5's surviving index rows are what the unfiltered reader reads"
    );
    assert_eq!(
        store
            .income_attestations()
            .get_valid_by_subject(&SUBJECT_REF, NOW)
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        store
            .income_attestations()
            .get_by_holder_address(&holder_addr())
            .unwrap()
            .len(),
        2
    );
    assert_eq!(
        store
            .income_attestations()
            .get_valid_by_holder_address(&holder_addr(), NOW)
            .unwrap()
            .len(),
        1
    );
}

// ── OV-4: and removing the entry would be irreversible ──────────────────────

/// `UpdateEmployment` accepts any status, `Active` included.
///
/// So "ended" is not terminal, and an index entry removed at `EndEmployment`
/// would have to be re-added here -- except that `v_update_credential_status`
/// writes only the credential row and no path on the execution side ever
/// re-adds an index entry. A removal remedy would therefore lose a restored
/// credential from all three indexes permanently.
///
/// Run under BOTH gate settings, because nothing here is gate-dependent and a
/// claim about what a remedy would cost must hold on the side the remedy would
/// live on.
#[test]
fn an_ended_credential_can_be_restored_so_removing_its_index_entry_would_be_irreversible() {
    #[derive(serde::Serialize)]
    struct EndData {
        employment_id: [u8; 32],
    }
    #[derive(serde::Serialize)]
    struct UpdateData {
        employment_id: [u8; 32],
        status: EmploymentStatus,
    }

    for gates in [EmploymentGates::CLOSED, EmploymentGates::OPEN] {
        let (_state, db, _dir, _executor) = setup_with_params(params());
        let issuer = KeyPair::generate();
        fund(&db, &issuer, FUNDED);
        let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
        let mut view = ExecutionView::new(&mut overlay);
        let sender = issuer.address();

        assert!(
            employment_at(
                &mut view,
                &sender,
                EmploymentOperation::RegisterIssuer,
                &employment_issuer(&issuer),
                gates
            )
            .success
        );
        assert!(
            employment_at(
                &mut view,
                &sender,
                EmploymentOperation::CreateEmployment,
                &credential_of(&issuer, 0x01),
                gates
            )
            .success
        );
        assert!(
            employment_at(
                &mut view,
                &sender,
                EmploymentOperation::EndEmployment,
                &EndData {
                    employment_id: [0x01; 32]
                },
                gates
            )
            .success
        );
        assert_eq!(
            EmploymentExecutor::v_get_credential(&view, &[0x01; 32])
                .unwrap()
                .unwrap()
                .status,
            EmploymentStatus::Ended
        );

        // Back to Active, through the arm that accepts any status.
        assert!(
            employment_at(
                &mut view,
                &sender,
                EmploymentOperation::UpdateEmployment,
                &UpdateData {
                    employment_id: [0x01; 32],
                    status: EmploymentStatus::Active,
                },
                gates
            )
            .success,
            "an ended credential is restorable, so 'ended' is not terminal"
        );
        assert_eq!(
            EmploymentExecutor::v_get_credential(&view, &[0x01; 32])
                .unwrap()
                .unwrap()
                .status,
            EmploymentStatus::Active
        );

        // All three index entries are still there, and NOTHING in the restore
        // path wrote one -- which is precisely why removal at EndEmployment
        // could never be undone.
        assert_eq!(
            EmploymentExecutor::v_get_employee_credential_ids(&view, &EMPLOYEE_REF).unwrap(),
            vec![[0x01u8; 32]]
        );
        assert_eq!(
            EmploymentExecutor::v_get_employee_address_credential_ids(&view, &employee_addr())
                .unwrap(),
            vec![[0x01u8; 32]]
        );
        assert_eq!(
            EmploymentExecutor::v_get_employer_credential_ids(&view, &EMPLOYER_REF).unwrap(),
            vec![[0x01u8; 32]]
        );
    }
}

// ── OV-7: Finance, the same question and the same answer ────────────────────

/// `list_active` filters on `status.is_active()`; `get_by_jurisdiction` does
/// not, and `finance_getIssuersByJurisdiction` documents itself as "registered
/// in a jurisdiction". So the Finance reader pair puts the filter in exactly
/// the place the Employment pairs put it, and the jurisdiction index is the
/// "all ever registered" half.
///
/// And a suspended issuer is restorable by `ReactivateIssuer`, whose write path
/// never touches the jurisdiction index -- so removing the entry on a status
/// change would lose a reactivated issuer from its own jurisdiction for ever.
#[test]
fn the_jurisdiction_index_is_the_all_half_of_a_pair_and_removal_would_be_irreversible() {
    #[derive(serde::Serialize)]
    struct Empty {}

    let (_state, db, _dir, _executor) = setup_with_params(params());
    let issuer = KeyPair::generate();
    fund(&db, &issuer, FUNDED);
    let sender = issuer.address();
    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);

    assert!(
        finance_at(
            &mut view,
            &sender,
            FinanceOperation::RegisterIssuer,
            &finance_issuer(&issuer),
            FinanceGates::CLOSED
        )
        .success
    );
    assert!(
        finance_at(
            &mut view,
            &sender,
            FinanceOperation::SuspendIssuer,
            &Empty {},
            FinanceGates::CLOSED
        )
        .success
    );
    assert_eq!(
        FinanceExecutor::v_get_jurisdiction_issuer_addresses(&view, JURISDICTION).unwrap(),
        vec![sender],
        "OV-7: suspension leaves the entry"
    );
    assert!(
        finance_at(
            &mut view,
            &sender,
            FinanceOperation::ReactivateIssuer,
            &Empty {},
            FinanceGates::CLOSED
        )
        .success,
        "a suspended issuer is restorable, and the restore path writes no index"
    );
    assert_eq!(
        FinanceExecutor::v_get_issuer(&view, &sender)
            .unwrap()
            .unwrap()
            .status,
        FinanceIssuerStatus::Active
    );
    assert_eq!(
        FinanceExecutor::v_get_jurisdiction_issuer_addresses(&view, JURISDICTION).unwrap(),
        vec![sender],
        "an entry removed at SuspendIssuer would never have come back here"
    );
}

/// The committed reader pair, with no candidate in sight.
///
/// `get_by_jurisdiction` answers over the whole index; `list_active` filters on
/// `status.is_active()`. The same split Employment makes, in the subsystem
/// whose row says nothing states it.
#[test]
fn the_finance_reader_pair_puts_the_status_filter_where_employment_puts_it() {
    let (_state, db, _dir, _executor) = setup_with_params(params());
    let issuer = KeyPair::generate();
    let store = FinanceStore::new(&db);
    let mut revoked = finance_issuer(&issuer);
    revoked.status = FinanceIssuerStatus::Revoked;
    store.issuers().put(&revoked).unwrap();
    assert_eq!(
        store
            .issuers()
            .get_by_jurisdiction(JURISDICTION)
            .unwrap()
            .len(),
        1,
        "the jurisdiction reader is the unfiltered half, and a revoked issuer is \
         what it keeps answering with -- which is OV-7's sentence, read as the \
         index working rather than as a dangling pointer"
    );
    assert!(
        store.issuers().list_active().unwrap().is_empty(),
        "and `list_active` is the filtering half"
    );
}

// ── OV-8: no refusal in either subsystem charges anything ───────────────────

/// OV-8's stated mechanism, run.
///
/// The row says `UpdateAddressProof` charges nothing "unlike every other
/// refusal in the subsystem". Every refusal below charges nothing, and so does
/// the Employment twin `UpdateIncomeAttestation`. What is true of
/// `UpdateAddressProof` is that it is UNCONDITIONAL -- no payload read, no
/// state read, no input that succeeds -- which is a different sentence from the
/// one the row makes, and it is the sentence
/// `subsystem_no_op_receipt_enabled_from_height` already exists to enforce:
/// "a failed receipt, not an implementation". This arm is already in the state
/// that gate produces.
#[test]
fn no_finance_or_employment_refusal_charges_a_fee_or_advances_a_nonce() {
    #[derive(serde::Serialize)]
    struct RevokeProof {
        proof_id: [u8; 32],
        revocation_ref: [u8; 32],
    }

    let (_state, db, _dir, _executor) = setup_with_params(params());
    let issuer = KeyPair::generate();
    fund(&db, &issuer, FUNDED);
    let sender = issuer.address();
    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);

    assert!(
        finance_at(
            &mut view,
            &sender,
            FinanceOperation::RegisterIssuer,
            &finance_issuer(&issuer),
            FinanceGates::CLOSED
        )
        .success
    );

    let balance = StateManager::v_get_balance(&view, &sender).unwrap();
    let nonce = StateManager::v_get_nonce(&view, &sender).unwrap();

    // A conditional refusal: the issuer is already registered.
    let dup = finance_at(
        &mut view,
        &sender,
        FinanceOperation::RegisterIssuer,
        &finance_issuer(&issuer),
        FinanceGates::CLOSED,
    );
    assert!(!dup.success);
    // A conditional refusal on a row that does not exist.
    let missing = finance_at(
        &mut view,
        &sender,
        FinanceOperation::RevokeAddressProof,
        &RevokeProof {
            proof_id: [0xAB; 32],
            revocation_ref: [0xCD; 32],
        },
        FinanceGates::CLOSED,
    );
    assert!(!missing.success);
    // OV-8's arm: unconditional, and no more free than the two above.
    let unconditional = finance_at(
        &mut view,
        &sender,
        FinanceOperation::UpdateAddressProof,
        &address_proof(&issuer, 0x03),
        FinanceGates::CLOSED,
    );
    assert!(!unconditional.success);
    assert_eq!(
        unconditional.error.as_deref(),
        Some("Update not supported, use revoke and re-issue")
    );

    assert_eq!(
        StateManager::v_get_balance(&view, &sender).unwrap(),
        balance,
        "OV-8's second clause is the one this refutes: NO refusal in this \
         subsystem charges, so `UpdateAddressProof` is not unlike its neighbours"
    );
    assert_eq!(
        StateManager::v_get_nonce(&view, &sender).unwrap(),
        nonce,
        "and none of them advances the nonce either"
    );

    // The Employment twin, character for character the same arm.
    let emp = KeyPair::generate();
    fund(&db, &emp, FUNDED);
    let emp_sender = emp.address();
    assert!(
        employment_at(
            &mut view,
            &emp_sender,
            EmploymentOperation::RegisterIssuer,
            &employment_issuer(&emp),
            EmploymentGates::CLOSED
        )
        .success
    );
    let b = StateManager::v_get_balance(&view, &emp_sender).unwrap();
    let n = StateManager::v_get_nonce(&view, &emp_sender).unwrap();
    let r = employment_at(
        &mut view,
        &emp_sender,
        EmploymentOperation::UpdateIncomeAttestation,
        &attestation_of(&emp, 0x11),
        EmploymentGates::CLOSED,
    );
    assert!(!r.success);
    assert_eq!(
        r.error.as_deref(),
        Some("Update not supported, use revoke and re-issue"),
        "the Employment twin OV-8 does not name, so that the finding is about the \
         SHAPE and not about one arm"
    );
    assert_eq!(StateManager::v_get_balance(&view, &emp_sender).unwrap(), b);
    assert_eq!(StateManager::v_get_nonce(&view, &emp_sender).unwrap(), n);
}

// ── AU-24 and AU-28: a check that is live code and structurally dead ────────

/// Key = `sender`, value's `issuer_address` = `other`.
///
/// Written by hand on purpose, and in a helper that touches no candidate: the
/// whole claim is that no code in the tree produces this row. `put` keys by the
/// VALUE's address, so even the store cannot be made to write it.
fn plant_mismatched_finance_issuer(
    db: &sumchain_storage::Database,
    sender: &Address,
    other: Address,
    actor: &KeyPair,
) {
    let mut mismatched = finance_issuer(actor);
    mismatched.issuer_address = other;
    db.put(
        cf::FINANCE_ISSUERS,
        sender.as_bytes(),
        &bincode::serialize(&mismatched).unwrap(),
    )
    .unwrap();
}

/// [`plant_mismatched_finance_issuer`] for Employment (AU-28).
fn plant_mismatched_employment_issuer(
    db: &sumchain_storage::Database,
    sender: &Address,
    other: Address,
    actor: &KeyPair,
) {
    let mut mismatched = employment_issuer(actor);
    mismatched.issuer_address = other;
    db.put(
        cf::EMPLOYMENT_ISSUERS,
        sender.as_bytes(),
        &bincode::serialize(&mismatched).unwrap(),
    )
    .unwrap();
}

/// The comparison FIRES -- against a row no execution path can produce.
///
/// Both halves matter. If it could not fire at all it would be dead code the
/// audit could ask to be deleted; if a transaction could produce the row, it
/// would be a live guard rather than a dead one. It fires on a hand-planted
/// row, and the invariant that keeps such a row unreachable is that the ONLY
/// writer of each issuer family keys by the value's own `issuer_address`, and
/// registration refuses unless that equals the sender.
#[test]
fn the_issuer_sender_check_fires_only_on_a_row_no_transaction_can_write() {
    #[derive(serde::Serialize)]
    struct FinanceUpdate {
        status: FinanceIssuerStatus,
    }
    #[derive(serde::Serialize)]
    struct EmploymentUpdate {
        status: IssuerStatus,
    }

    let (_state, db, _dir, _executor) = setup_with_params(params());
    let actor = KeyPair::generate();
    fund(&db, &actor, FUNDED);
    let sender = actor.address();
    let other = Address::new([0x5A; 20]);

    // ── The check is live: plant key = sender, value.issuer_address = other.
    plant_mismatched_finance_issuer(&db, &sender, other, &actor);
    plant_mismatched_employment_issuer(&db, &sender, other, &actor);
    {
        let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
        let mut view = ExecutionView::new(&mut overlay);
        let r = finance_at(
            &mut view,
            &sender,
            FinanceOperation::UpdateIssuer,
            &FinanceUpdate {
                status: FinanceIssuerStatus::Suspended,
            },
            FinanceGates::CLOSED,
        );
        assert!(!r.success);
        assert_eq!(
            r.error.as_deref(),
            Some("Only issuer can update"),
            "AU-24's comparison is live code and this is it firing"
        );
    }
    {
        let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
        let mut view = ExecutionView::new(&mut overlay);
        let r = employment_at(
            &mut view,
            &sender,
            EmploymentOperation::UpdateIssuer,
            &EmploymentUpdate {
                status: IssuerStatus::Suspended,
            },
            EmploymentGates::CLOSED,
        );
        assert!(!r.success);
        assert_eq!(
            r.error.as_deref(),
            Some("Only issuer can update"),
            "AU-28 is AU-24 in Employment, and fires the same way"
        );
    }

    // ── And the invariant that keeps it dead: after registration and after
    // every status-changing operation, the KEY equals the value's own
    // `issuer_address`.
    let (_state2, db2, _dir2, _executor2) = setup_with_params(params());
    let kp = KeyPair::generate();
    fund(&db2, &kp, FUNDED);
    let me = kp.address();
    let mut overlay = ApplicationOverlay::new(&db2, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);

    // Registration REFUSES a profile naming anyone but the sender, which is
    // where the invariant is established.
    let mut impostor = finance_issuer(&kp);
    impostor.issuer_address = other;
    let r = finance_at(
        &mut view,
        &me,
        FinanceOperation::RegisterIssuer,
        &impostor,
        FinanceGates::CLOSED,
    );
    assert!(!r.success);
    assert_eq!(r.error.as_deref(), Some("Issuer must be sender"));

    assert!(
        finance_at(
            &mut view,
            &me,
            FinanceOperation::RegisterIssuer,
            &finance_issuer(&kp),
            FinanceGates::CLOSED
        )
        .success
    );
    for op in [
        FinanceOperation::SuspendIssuer,
        FinanceOperation::ReactivateIssuer,
        FinanceOperation::RevokeIssuer,
    ] {
        #[derive(serde::Serialize)]
        struct Empty {}
        assert!(
            finance_at(&mut view, &me, op, &Empty {}, FinanceGates::CLOSED).success,
            "{op:?}"
        );
        assert_eq!(
            FinanceExecutor::v_get_issuer(&view, &me)
                .unwrap()
                .unwrap()
                .issuer_address,
            me,
            "the row reachable at key `me` always names `me`, so the comparison \
             AU-24 describes can never differ on any state a transaction can reach"
        );
    }
}
