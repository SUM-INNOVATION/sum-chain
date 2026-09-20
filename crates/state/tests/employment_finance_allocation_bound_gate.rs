//! `subsystem_allocation_bound_enabled_from_height`, Employment and Finance
//! halves: an accumulating index row past the limit is refused BEFORE it is
//! decoded, appended to and re-encoded.
//!
//! ACTIVATION-AUDIT rows AL-2 (Employment, five index families) and AL-4
//! (Finance, four).
//!
//! # Why this reads the field DocClass, NFT and Agreement read
//!
//! AL-2 and AL-4 are AL-5/AL-10/AL-11 in two more subsystems, word for word.
//! `v_add_to_employee_index`, `v_add_to_employee_address_index`,
//! `v_add_to_employer_index`, `v_add_to_subject_income_index`,
//! `v_add_to_holder_address_index`, `v_add_to_jurisdiction_index`,
//! `v_add_to_subject_address_index`, `v_add_to_subject_bank_index` and
//! `v_add_to_subject_kyc_index` each read an accumulating row, decode the whole
//! of it, push one entry and re-encode the whole of it, and `view.put` only then
//! charges the candidate's byte ceiling. The ceiling therefore bounds what a
//! block may COMMIT and bounds nothing about what one transaction may ALLOCATE.
//!
//! The field's own doc comment gives the argument for one height rather than
//! five -- one rule at one seam, and an attacker refused by one bound simply
//! uses the cheapest one still open -- and it applies here unchanged: every one
//! of these nine rows is reachable for one `min_fee` by any registered active
//! issuer, which is the cheapest of the five subsystems. A partial activation
//! would close three and leave the two cheapest open.
//!
//! This file does NOT claim a new gate, a new constant or a new rule. It claims
//! that two more subsystems now read the rule that already exists.
//!
//! # What each pair shows
//!
//! One `#[test]` per index family, nine in all. Each seeds ONE committed index
//! row one byte past [`MAX_ACCUMULATING_ROW_BYTES`], then runs the SAME
//! creation transaction against it twice -- once with `allocation_bound: false`
//! (the release configuration, and byte-for-byte the unremediated binary) and
//! once with it true -- and asserts the two nodes DISAGREE: the ungated node
//! admits the transaction and grows the row further, the gated one refuses it
//! with a failed receipt, writes nothing, and charges nothing.
//!
//! A row AT the bound is accepted on both sides, so what the gate refuses is
//! the over-long row and not the operation. That is the discriminator: without
//! it every assertion here would also pass for a gate that refused everything.
//!
//! Every pair is spelled `{ allocation_bound: …, ..CLOSED }`, never field by
//! field, so a gate added to either struct later leaves the pair differing in
//! exactly one decision.

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
    AccountStanding, AccountType, AddressProof, AddressProofType, AmlRisk, BalanceBracket,
    BankStandingCredential, FinanceIssuerClass, FinanceIssuerProfile, FinanceIssuerStatus,
    FinanceOperation, FinanceTxData, KycAttestation, KycLevel, KycStatus,
};
use sumchain_primitives::{Address, Hash};
use sumchain_state::{
    EmploymentExecutor, EmploymentGates, FinanceExecutor, FinanceGates, StateManager,
    MAX_ACCUMULATING_ROW_BYTES,
};
use sumchain_storage::cf;
use sumchain_storage::exec_view::ExecutionView;
use sumchain_storage::overlay::ApplicationOverlay;

fn params() -> ChainParams {
    ChainParams::with_v2_enabled()
}

const FEE: u128 = 100;
const FUNDED: u128 = 100_000_000;
const JURISDICTION: &str = "US-NY";

macro_rules! pair {
    ($g:ident) => {
        [
            $g::CLOSED,
            $g {
                allocation_bound: true,
                ..$g::CLOSED
            },
        ]
    };
}

/// A bincode `Vec<[u8; 32]>` whose ENCODING is exactly `target` bytes, or the
/// nearest length at or above it, plus the exact encoding length.
///
/// The encoding is an 8-byte length prefix and 32 bytes an entry, so the size
/// is chosen rather than searched for; it is asserted anyway, because a codec
/// change that altered the framing would otherwise silently seed a row on the
/// wrong side of the bound and every assertion below would still pass.
fn id_list_of_at_least(target: usize) -> (Vec<u8>, usize) {
    let n = target.div_ceil(32) + 1;
    let ids: Vec<[u8; 32]> = (0..n as u32)
        .map(|i| {
            let mut id = [0u8; 32];
            id[..4].copy_from_slice(&i.to_be_bytes());
            id
        })
        .collect();
    let bytes = bincode::serialize(&ids).unwrap();
    assert!(
        bytes.len() >= target,
        "the fixture must actually be the size this test claims: {} < {target}",
        bytes.len()
    );
    let len = bytes.len();
    (bytes, len)
}

/// The same, for the `Vec<Address>` the Finance jurisdiction index holds.
fn address_list_of_at_least(target: usize) -> (Vec<u8>, usize) {
    let n = target.div_ceil(20) + 1;
    let addrs: Vec<Address> = (0..n as u32)
        .map(|i| {
            let mut a = [0u8; 20];
            a[..4].copy_from_slice(&i.to_be_bytes());
            Address::new(a)
        })
        .collect();
    let bytes = bincode::serialize(&addrs).unwrap();
    assert!(bytes.len() >= target, "fixture too small: {}", bytes.len());
    let len = bytes.len();
    (bytes, len)
}

/// The one claim every case makes.
///
/// `over` and `at` are "the creation transaction succeeded".
fn assert_the_pair_disagrees(family: &str, gate_open: bool, at: bool, over: bool) {
    assert!(
        at,
        "{family}: a row exactly at the {MAX_ACCUMULATING_ROW_BYTES}-byte bound must be \
         accepted on both sides -- the gate refuses an over-long ROW, not the operation \
         (allocation_bound={gate_open})"
    );
    assert_eq!(
        over, !gate_open,
        "{family}: a row one byte past the bound is ADMITTED below the gate and grown \
         further; at the gate it is a failed receipt (allocation_bound={gate_open})"
    );
}

// ── Employment fixtures ─────────────────────────────────────────────────────

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
        created_at: 1_000,
        updated_at: 1_000,
    }
}

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
        1_000,
        0,
        Hash::ZERO,
        gates,
    )
    .unwrap()
}

// ── Finance fixtures ────────────────────────────────────────────────────────

fn finance_issuer(kp: &KeyPair) -> FinanceIssuerProfile {
    FinanceIssuerProfile {
        issuer_address: kp.address(),
        issuer_class: FinanceIssuerClass::RegulatedBank,
        issuer_commitment: [2u8; 32],
        jurisdiction_code: JURISDICTION.to_string(),
        policy_id: [3u8; 32],
        status: FinanceIssuerStatus::Active,
        registered_at_height: 1,
        created_at: 1_000,
        updated_at: 1_000,
    }
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
        1_000,
        0,
        Hash::ZERO,
        gates,
    )
    .unwrap()
}

// ── Employment — AL-2 ───────────────────────────────────────────────────────

/// Seed one committed index row, run one `CreateEmployment`, report whether it
/// succeeded and assert that a refusal cost the sender nothing.
fn employment_credential_case(
    family: &'static str,
    index_cf: &'static str,
    key: &[u8],
    seeded: &[u8],
    gates: EmploymentGates,
) -> bool {
    let (_state, db, _dir, _executor) = setup_with_params(params());
    let issuer = KeyPair::generate();
    fund(&db, &issuer, FUNDED);
    db.put(index_cf, key, seeded).unwrap();

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);
    assert!(
        employment_at(
            &mut view,
            &issuer.address(),
            EmploymentOperation::RegisterIssuer,
            &employment_issuer(&issuer),
            gates
        )
        .success,
        "{family}: the issuer must register under either gate"
    );
    let before = StateManager::v_get_balance(&view, &issuer.address()).unwrap();

    let cred = credential_of(
        &issuer,
        0xFE,
        Address::new([0x77; 20]),
        [0x55; 32],
        [0x66; 32],
    );
    let r = employment_at(
        &mut view,
        &issuer.address(),
        EmploymentOperation::CreateEmployment,
        &cred,
        gates,
    );
    if r.success {
        assert_ne!(
            view.get(index_cf, key).unwrap().as_deref(),
            Some(seeded),
            "{family}: a transaction that succeeded must have grown the row"
        );
    } else {
        assert!(
            r.error.as_deref().unwrap_or_default().contains("too large"),
            "{family}: refused by the bound, not by something else: {:?}",
            r.error
        );
        assert_eq!(
            view.get(index_cf, key).unwrap().as_deref(),
            Some(seeded),
            "{family}: the refusal must leave the row untouched"
        );
        assert!(
            view.get(cf::EMPLOYMENT_CREDENTIALS, &[0xFEu8; 32])
                .unwrap()
                .is_none(),
            "{family}: and must not stage the credential row either -- the bound is \
             checked before the write, not after it"
        );
        assert_eq!(
            StateManager::v_get_balance(&view, &issuer.address()).unwrap(),
            before,
            "{family}: an Employment refusal writes nothing at all, and this one must \
             not be the exception that charges"
        );
    }
    r.success
}

#[test]
fn employment_employee_index_stops_growing_an_unbounded_accumulating_row() {
    for gates in pair!(EmploymentGates) {
        let open = gates.allocation_bound;
        let (over, over_len) = id_list_of_at_least(MAX_ACCUMULATING_ROW_BYTES + 1);
        assert!(over_len > MAX_ACCUMULATING_ROW_BYTES);
        let (at, at_len) = id_list_of_at_least(MAX_ACCUMULATING_ROW_BYTES - 64);
        assert!(at_len <= MAX_ACCUMULATING_ROW_BYTES);
        assert_the_pair_disagrees(
            "employee index",
            open,
            employment_credential_case(
                "employee index",
                cf::EMPLOYMENT_EMPLOYEE_INDEX,
                &[0x55; 32],
                &at,
                gates,
            ),
            employment_credential_case(
                "employee index",
                cf::EMPLOYMENT_EMPLOYEE_INDEX,
                &[0x55; 32],
                &over,
                gates,
            ),
        );
    }
}

#[test]
fn employment_employee_address_index_stops_growing_an_unbounded_accumulating_row() {
    for gates in pair!(EmploymentGates) {
        let open = gates.allocation_bound;
        let (over, _) = id_list_of_at_least(MAX_ACCUMULATING_ROW_BYTES + 1);
        let (at, _) = id_list_of_at_least(MAX_ACCUMULATING_ROW_BYTES - 64);
        assert_the_pair_disagrees(
            "employee address index",
            open,
            employment_credential_case(
                "employee address index",
                cf::EMPLOYMENT_EMPLOYEE_ADDRESS_INDEX,
                &[0x77; 20],
                &at,
                gates,
            ),
            employment_credential_case(
                "employee address index",
                cf::EMPLOYMENT_EMPLOYEE_ADDRESS_INDEX,
                &[0x77; 20],
                &over,
                gates,
            ),
        );
    }
}

#[test]
fn employment_employer_index_stops_growing_an_unbounded_accumulating_row() {
    for gates in pair!(EmploymentGates) {
        let open = gates.allocation_bound;
        let (over, _) = id_list_of_at_least(MAX_ACCUMULATING_ROW_BYTES + 1);
        let (at, _) = id_list_of_at_least(MAX_ACCUMULATING_ROW_BYTES - 64);
        assert_the_pair_disagrees(
            "employer index",
            open,
            employment_credential_case(
                "employer index",
                cf::EMPLOYMENT_EMPLOYER_INDEX,
                &[0x66; 32],
                &at,
                gates,
            ),
            employment_credential_case(
                "employer index",
                cf::EMPLOYMENT_EMPLOYER_INDEX,
                &[0x66; 32],
                &over,
                gates,
            ),
        );
    }
}

/// The income half: seed one row, run one `CreateIncomeAttestation`.
fn employment_income_case(
    family: &'static str,
    index_cf: &'static str,
    key: &[u8],
    seeded: &[u8],
    gates: EmploymentGates,
) -> bool {
    let (_state, db, _dir, _executor) = setup_with_params(params());
    let issuer = KeyPair::generate();
    fund(&db, &issuer, FUNDED);
    db.put(index_cf, key, seeded).unwrap();

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);
    assert!(
        employment_at(
            &mut view,
            &issuer.address(),
            EmploymentOperation::RegisterIssuer,
            &employment_issuer(&issuer),
            gates
        )
        .success
    );
    let before = StateManager::v_get_balance(&view, &issuer.address()).unwrap();

    let att = attestation_of(&issuer, 0xFD, Address::new([0x88; 20]), [0x99; 32]);
    let r = employment_at(
        &mut view,
        &issuer.address(),
        EmploymentOperation::CreateIncomeAttestation,
        &att,
        gates,
    );
    if !r.success {
        assert!(
            r.error.as_deref().unwrap_or_default().contains("too large"),
            "{family}: refused by the bound, not by something else: {:?}",
            r.error
        );
        assert_eq!(
            view.get(index_cf, key).unwrap().as_deref(),
            Some(seeded),
            "{family}: the refusal must leave the row untouched"
        );
        assert_eq!(
            StateManager::v_get_balance(&view, &issuer.address()).unwrap(),
            before,
            "{family}: the refusal must cost nothing"
        );
    }
    r.success
}

#[test]
fn employment_subject_income_index_stops_growing_an_unbounded_accumulating_row() {
    for gates in pair!(EmploymentGates) {
        let open = gates.allocation_bound;
        let (over, _) = id_list_of_at_least(MAX_ACCUMULATING_ROW_BYTES + 1);
        let (at, _) = id_list_of_at_least(MAX_ACCUMULATING_ROW_BYTES - 64);
        assert_the_pair_disagrees(
            "subject income index",
            open,
            employment_income_case(
                "subject income index",
                cf::EMPLOYMENT_SUBJECT_INCOME_INDEX,
                &[0x99; 32],
                &at,
                gates,
            ),
            employment_income_case(
                "subject income index",
                cf::EMPLOYMENT_SUBJECT_INCOME_INDEX,
                &[0x99; 32],
                &over,
                gates,
            ),
        );
    }
}

#[test]
fn employment_income_holder_address_index_stops_growing_an_unbounded_accumulating_row() {
    for gates in pair!(EmploymentGates) {
        let open = gates.allocation_bound;
        let (over, _) = id_list_of_at_least(MAX_ACCUMULATING_ROW_BYTES + 1);
        let (at, _) = id_list_of_at_least(MAX_ACCUMULATING_ROW_BYTES - 64);
        assert_the_pair_disagrees(
            "income holder address index",
            open,
            employment_income_case(
                "income holder address index",
                cf::EMPLOYMENT_INCOME_HOLDER_ADDRESS_INDEX,
                &[0x88; 20],
                &at,
                gates,
            ),
            employment_income_case(
                "income holder address index",
                cf::EMPLOYMENT_INCOME_HOLDER_ADDRESS_INDEX,
                &[0x88; 20],
                &over,
                gates,
            ),
        );
    }
}

// ── Finance — AL-4 ──────────────────────────────────────────────────────────

/// Seed one committed index row, register the issuer where the family needs
/// one, run one creation operation.
fn finance_case(
    family: &'static str,
    index_cf: &'static str,
    key: &[u8],
    seeded: &[u8],
    register_first: bool,
    run: impl FnOnce(
        &mut ExecutionView<'_, '_>,
        &Address,
        FinanceGates,
    ) -> sumchain_state::FinanceExecutionResult,
    gates: FinanceGates,
) -> bool {
    let (_state, db, _dir, _executor) = setup_with_params(params());
    let issuer = KeyPair::generate();
    fund(&db, &issuer, FUNDED);
    db.put(index_cf, key, seeded).unwrap();

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);
    if register_first {
        assert!(
            finance_at(
                &mut view,
                &issuer.address(),
                FinanceOperation::RegisterIssuer,
                &finance_issuer(&issuer),
                gates
            )
            .success,
            "{family}: the issuer must register under either gate"
        );
    }
    let before = StateManager::v_get_balance(&view, &issuer.address()).unwrap();

    let r = run(&mut view, &issuer.address(), gates);
    if !r.success {
        assert!(
            r.error.as_deref().unwrap_or_default().contains("too large"),
            "{family}: refused by the bound, not by something else: {:?}",
            r.error
        );
        assert_eq!(
            view.get(index_cf, key).unwrap().as_deref(),
            Some(seeded),
            "{family}: the refusal must leave the row untouched"
        );
        assert_eq!(
            StateManager::v_get_balance(&view, &issuer.address()).unwrap(),
            before,
            "{family}: a Finance refusal writes nothing at all, and this one must not \
             be the exception that charges"
        );
    }
    r.success
}

#[test]
fn finance_jurisdiction_index_stops_growing_an_unbounded_accumulating_row() {
    for gates in pair!(FinanceGates) {
        let open = gates.allocation_bound;
        let key = sumchain_storage::finance_store::jurisdiction_index_key(JURISDICTION).to_vec();
        let (over, _) = address_list_of_at_least(MAX_ACCUMULATING_ROW_BYTES + 1);
        let (at, _) = address_list_of_at_least(MAX_ACCUMULATING_ROW_BYTES - 64);
        let run = |view: &mut ExecutionView<'_, '_>, s: &Address, g| {
            let kp_profile = FinanceIssuerProfile {
                issuer_address: *s,
                ..finance_issuer(&KeyPair::generate())
            };
            finance_at(view, s, FinanceOperation::RegisterIssuer, &kp_profile, g)
        };
        assert_the_pair_disagrees(
            "jurisdiction index",
            open,
            finance_case(
                "jurisdiction index",
                cf::FINANCE_JURISDICTION_INDEX,
                &key,
                &at,
                false,
                run,
                gates,
            ),
            finance_case(
                "jurisdiction index",
                cf::FINANCE_JURISDICTION_INDEX,
                &key,
                &over,
                false,
                run,
                gates,
            ),
        );
    }
}

#[test]
fn finance_subject_address_index_stops_growing_an_unbounded_accumulating_row() {
    for gates in pair!(FinanceGates) {
        let open = gates.allocation_bound;
        let (over, _) = id_list_of_at_least(MAX_ACCUMULATING_ROW_BYTES + 1);
        let (at, _) = id_list_of_at_least(MAX_ACCUMULATING_ROW_BYTES - 64);
        let run = |view: &mut ExecutionView<'_, '_>, s: &Address, g| {
            let mut p = address_proof(&KeyPair::generate(), 0xEE, [0x44; 32]);
            p.issuer_address = *s;
            finance_at(view, s, FinanceOperation::CreateAddressProof, &p, g)
        };
        assert_the_pair_disagrees(
            "subject address index",
            open,
            finance_case(
                "subject address index",
                cf::FINANCE_SUBJECT_ADDRESS_INDEX,
                &[0x44; 32],
                &at,
                true,
                run,
                gates,
            ),
            finance_case(
                "subject address index",
                cf::FINANCE_SUBJECT_ADDRESS_INDEX,
                &[0x44; 32],
                &over,
                true,
                run,
                gates,
            ),
        );
    }
}

#[test]
fn finance_subject_bank_index_stops_growing_an_unbounded_accumulating_row() {
    for gates in pair!(FinanceGates) {
        let open = gates.allocation_bound;
        let (over, _) = id_list_of_at_least(MAX_ACCUMULATING_ROW_BYTES + 1);
        let (at, _) = id_list_of_at_least(MAX_ACCUMULATING_ROW_BYTES - 64);
        let run = |view: &mut ExecutionView<'_, '_>, s: &Address, g| {
            let mut c = bank_standing(&KeyPair::generate(), 0xED, [0x43; 32]);
            c.issuer_address = *s;
            finance_at(view, s, FinanceOperation::CreateBankStanding, &c, g)
        };
        assert_the_pair_disagrees(
            "subject bank index",
            open,
            finance_case(
                "subject bank index",
                cf::FINANCE_SUBJECT_BANK_INDEX,
                &[0x43; 32],
                &at,
                true,
                run,
                gates,
            ),
            finance_case(
                "subject bank index",
                cf::FINANCE_SUBJECT_BANK_INDEX,
                &[0x43; 32],
                &over,
                true,
                run,
                gates,
            ),
        );
    }
}

#[test]
fn finance_subject_kyc_index_stops_growing_an_unbounded_accumulating_row() {
    for gates in pair!(FinanceGates) {
        let open = gates.allocation_bound;
        let (over, _) = id_list_of_at_least(MAX_ACCUMULATING_ROW_BYTES + 1);
        let (at, _) = id_list_of_at_least(MAX_ACCUMULATING_ROW_BYTES - 64);
        let run = |view: &mut ExecutionView<'_, '_>, s: &Address, g| {
            let mut a = kyc(&KeyPair::generate(), 0xEC, [0x42; 32]);
            a.issuer_address = *s;
            finance_at(view, s, FinanceOperation::CreateKycAttestation, &a, g)
        };
        assert_the_pair_disagrees(
            "subject KYC index",
            open,
            finance_case(
                "subject KYC index",
                cf::FINANCE_SUBJECT_KYC_INDEX,
                &[0x42; 32],
                &at,
                true,
                run,
                gates,
            ),
            finance_case(
                "subject KYC index",
                cf::FINANCE_SUBJECT_KYC_INDEX,
                &[0x42; 32],
                &over,
                true,
                run,
                gates,
            ),
        );
    }
}

/// The KEY bound and the ROW bound are independent halves of one gate.
///
/// `RegisterIssuer` reads both: `MAX_INDEX_KEY_TEXT_BYTES` bounds the
/// jurisdiction code it writes as a key, `MAX_ACCUMULATING_ROW_BYTES` bounds
/// the address list it appends to. A short code naming an over-long row passes
/// the first and must be refused by the second -- which is the case that would
/// pass if the row bound had been wired to the key check by mistake.
#[test]
fn a_short_jurisdiction_code_naming_an_over_long_row_is_still_refused() {
    let gates = FinanceGates {
        allocation_bound: true,
        ..FinanceGates::CLOSED
    };
    let (_state, db, _dir, _executor) = setup_with_params(params());
    let issuer = KeyPair::generate();
    fund(&db, &issuer, FUNDED);
    let key = sumchain_storage::finance_store::jurisdiction_index_key(JURISDICTION).to_vec();
    let (over, over_len) = address_list_of_at_least(MAX_ACCUMULATING_ROW_BYTES + 1);
    db.put(cf::FINANCE_JURISDICTION_INDEX, &key, &over).unwrap();

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);
    let r = finance_at(
        &mut view,
        &issuer.address(),
        FinanceOperation::RegisterIssuer,
        &finance_issuer(&issuer),
        gates,
    );
    assert!(
        !r.success,
        "a five-byte jurisdiction code is well inside the key bound, so only the ROW \
         bound can refuse this -- and it must"
    );
    let msg = r.error.unwrap_or_default();
    assert!(
        msg.contains("Finance jurisdiction index") && msg.contains(&over_len.to_string()),
        "the refusal must name the family and the length, because the remedy for a row \
         over the limit is not retry: {msg}"
    );
}

/// Negative control: with the gate open and every row small, all nine creation
/// paths still succeed.
///
/// Without this, a bound wired to refuse unconditionally would satisfy every
/// assertion above.
#[test]
fn an_open_gate_over_small_rows_refuses_nothing() {
    let e = EmploymentGates {
        allocation_bound: true,
        ..EmploymentGates::CLOSED
    };
    let f = FinanceGates {
        allocation_bound: true,
        ..FinanceGates::CLOSED
    };
    let (_state, db, _dir, _executor) = setup_with_params(params());
    let emp = KeyPair::generate();
    let fin = KeyPair::generate();
    fund(&db, &emp, FUNDED);
    fund(&db, &fin, FUNDED);
    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);

    let r = EmploymentExecutor::execute_with_gates(
        &mut view,
        &emp.address(),
        &EmploymentTxData {
            operation: EmploymentOperation::RegisterIssuer,
            data: bincode::serialize(&employment_issuer(&emp)).unwrap(),
            recipient: Address::ZERO,
        },
        &Address::new([9; 20]),
        FEE,
        1,
        1_000,
        0,
        Hash::ZERO,
        e,
    )
    .unwrap();
    assert!(r.success, "{:?}", r.error);
    assert!(
        employment_at(
            &mut view,
            &emp.address(),
            EmploymentOperation::CreateEmployment,
            &credential_of(&emp, 0x01, Address::new([0x77; 20]), [0x55; 32], [0x66; 32]),
            e
        )
        .success
    );
    assert!(
        employment_at(
            &mut view,
            &emp.address(),
            EmploymentOperation::CreateIncomeAttestation,
            &attestation_of(&emp, 0x02, Address::new([0x88; 20]), [0x99; 32]),
            e
        )
        .success
    );
    assert!(
        finance_at(
            &mut view,
            &fin.address(),
            FinanceOperation::RegisterIssuer,
            &finance_issuer(&fin),
            f
        )
        .success
    );
    assert!(
        finance_at(
            &mut view,
            &fin.address(),
            FinanceOperation::CreateAddressProof,
            &address_proof(&fin, 0x03, [0x44; 32]),
            f
        )
        .success
    );
    assert!(
        finance_at(
            &mut view,
            &fin.address(),
            FinanceOperation::CreateBankStanding,
            &bank_standing(&fin, 0x04, [0x43; 32]),
            f
        )
        .success
    );
    assert!(
        finance_at(
            &mut view,
            &fin.address(),
            FinanceOperation::CreateKycAttestation,
            &kyc(&fin, 0x05, [0x42; 32]),
            f
        )
        .success
    );
}

/// A closed gate performs no index read AT ALL, not merely no refusal.
///
/// A CORRUPT index row -- bytes no decoder accepts -- is the discriminator. The
/// unremediated binary reaches it inside `v_add_to_*`, AFTER the fee is taken,
/// and errors out of the whole transaction. A bound that read the row early
/// while closed would move that decode earlier and change which families a
/// corrupt row leaves staged; a bound that reads only its LENGTH does not
/// decode it at all, which is why the open side refuses by length rather than
/// erroring.
#[test]
fn a_corrupt_index_row_behaves_the_same_below_the_gate_and_is_length_refused_above() {
    for gates in pair!(EmploymentGates) {
        let (_state, db, _dir, _executor) = setup_with_params(params());
        let issuer = KeyPair::generate();
        fund(&db, &issuer, FUNDED);
        // Long enough to be over the bound AND undecodable: a length prefix
        // claiming far more entries than the bytes that follow.
        let mut corrupt = vec![0xFFu8; 8];
        corrupt.extend(std::iter::repeat_n(0xAAu8, MAX_ACCUMULATING_ROW_BYTES + 1));
        db.put(cf::EMPLOYMENT_EMPLOYEE_INDEX, &[0x55; 32], &corrupt)
            .unwrap();

        let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
        let mut view = ExecutionView::new(&mut overlay);
        assert!(
            employment_at(
                &mut view,
                &issuer.address(),
                EmploymentOperation::RegisterIssuer,
                &employment_issuer(&issuer),
                gates
            )
            .success
        );
        let cred = credential_of(
            &issuer,
            0xFE,
            Address::new([0x77; 20]),
            [0x55; 32],
            [0x66; 32],
        );
        let raw = EmploymentExecutor::execute_with_gates(
            &mut view,
            &issuer.address(),
            &EmploymentTxData {
                operation: EmploymentOperation::CreateEmployment,
                data: bincode::serialize(&cred).unwrap(),
                recipient: Address::ZERO,
            },
            &Address::new([9; 20]),
            FEE,
            1,
            1_000,
            0,
            Hash::ZERO,
            gates,
        );
        if gates.allocation_bound {
            let r = raw.expect(
                "above the gate the row is refused by LENGTH, which needs no decode, so \
                 the corrupt bytes never reach one",
            );
            assert!(!r.success);
            assert!(r.error.unwrap_or_default().contains("too large"));
        } else {
            raw.expect_err(
                "below the gate the corrupt row reaches `decode_id_list` inside \
                 `v_add_to_employee_index` and errors the whole transaction -- which is \
                 exactly what the unremediated binary does",
            );
        }
    }
}
