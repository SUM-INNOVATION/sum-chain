//! Every Wave 1 subsystem produces an ATTRIBUTABLE signal on
//! `sumchain_tx_execution_errors_total`.
//!
//! # What this file is for
//!
//! Wave 1 is twenty-four remediation gates. Twenty-two of them are REFUSAL
//! ONLY: their whole effect is that a transaction which used to succeed now
//! produces a failed receipt instead. `ACTIVATION-DECISION-PACKET.md` field 5
//! says the same sentence for each of them — "M4 on the subsystem's
//! transactions … **No counter exists** … so this is per-transaction
//! inspection". An operator who opens twenty-four gates at one height and can
//! only inspect receipts one at a time has no way to answer the only question
//! that matters in the first hour: *did anything start being refused, and by
//! which subsystem*.
//!
//! The counter now exists. This file is the proof that it is attributable —
//! that the refusal a gate produces lands on THAT subsystem's series and on no
//! other. A list of subsystems somebody believes are covered is not that
//! proof; a transaction per subsystem is.
//!
//! # The shape of every case
//!
//! Each test:
//!
//! 1. reads the subject series' value;
//! 2. executes and PUBLISHES a real block through `BlockExecutor::execute_block`
//!    — the production path, not an executor seam — with the Wave 1 gate OPEN
//!    and the refused transaction shape in it;
//! 3. asserts the receipt is that subsystem's `Failed(code)`; and
//! 4. asserts the series named by (`subsystem`, `code`) ADVANCED.
//!
//! Each also runs its DISCRIMINATOR, and it is the attribution claim itself:
//! the subject series advances by EXACTLY ONE and **every other series in the
//! table stays where it was**. Without it every assertion here would also pass
//! for a counter that counted every transaction, or for one counter wearing
//! nine labels, neither of which is a per-subsystem signal.
//!
//! An exact delta is only meaningful if nothing else is incrementing
//! concurrently. Each integration test FILE is its own binary, so the only
//! writers to this process's registry are the tests below — and they take
//! [`SERIAL`] so that they are not writers at the same time. A test that
//! asserted an exact total without that lock would be asserting the absence of
//! parallelism rather than the presence of a signal.
//!
//! # The subsystems
//!
//! Nine executors are reachable by the twenty-four Wave 1 gates: `nft`,
//! `docclass`, `tax`, `agreement`, `legal`, `property`, `healthcare`,
//! `employment`, `finance`. Each gets at least one case here, and four of
//! them get a second under a different Wave 1 gate, so the claim is about the
//! seam and not about one gate's arm.
//!
//! The `subsystem_*` gates (R13, R18, R20, R31, R39) are cross-cutting: they
//! are one height read by several executors. R13
//! `subsystem_allocation_bound_enabled_from_height` is the one every one of
//! the nine reads, which is why it carries the base case for all nine.

mod common;

use common::{fund, publish_block, setup_with_params, CHAIN_ID};
use sumchain_crypto::{sign, KeyPair};
use sumchain_genesis::ChainParams;
use sumchain_primitives::agreement::{AgreementOperation, AgreementTxData};
use sumchain_primitives::docclass::{DocClassOperation, DocClassTxData, DocSubcode};
use sumchain_primitives::employment::{
    EmploymentCredential, EmploymentIssuerClass, EmploymentIssuerProfile, EmploymentOperation,
    EmploymentStatus, EmploymentTxData, EmploymentType, IssuerStatus,
};
use sumchain_primitives::finance::{
    FinanceIssuerClass, FinanceIssuerProfile, FinanceIssuerStatus, FinanceOperation, FinanceTxData,
};
use sumchain_primitives::healthcare::{HealthcareOperation, HealthcareTxData};
use sumchain_primitives::legal::{
    CaseAnchor, CaseStatus, CaseType, LegalIssuerClass, LegalOperation, LegalTxData,
};
use sumchain_primitives::property::{PropertyOperation, PropertyTxData};
use sumchain_primitives::tax::{TaxOperation, TaxTxData};
use sumchain_primitives::transaction::{NftOperation, NftTxData};
use sumchain_primitives::tx_error_metrics::{value, TxExecutionErrorLabels};
use sumchain_primitives::{Address, SignedTransaction, TransactionV2, TxPayload, TxStatus};
use sumchain_state::{MAX_ACCUMULATING_ROW_BYTES, MAX_SUBSYSTEM_PAYLOAD_BYTES};
use sumchain_storage::{cf, Database};

const FEE: u128 = 100;
const FUNDED: u128 = 100_000_000;
const PROPOSER: [u8; 32] = [7u8; 32];

/// A payload one byte past the per-transaction subsystem payload bound.
fn oversized() -> Vec<u8> {
    vec![0u8; MAX_SUBSYSTEM_PAYLOAD_BYTES + 1]
}

/// A jurisdiction code past `MAX_INDEX_KEY_TEXT_BYTES`.
fn oversized_jurisdiction() -> String {
    "U".repeat(sumchain_state::MAX_INDEX_KEY_TEXT_BYTES + 1)
}

/// Sign a V2 transaction carrying `payload`.
fn tx(kp: &KeyPair, nonce: u64, payload: TxPayload) -> SignedTransaction {
    let t = TransactionV2 {
        chain_id: CHAIN_ID,
        from: kp.address(),
        fee: FEE,
        nonce,
        payload,
    };
    let h = t.signing_hash();
    let sig = sign(h.as_bytes(), kp.private_key());
    SignedTransaction::new_v2(t, *sig.as_bytes(), *kp.public_key().as_bytes())
}

/// The series a subsystem's failed receipt must land on.
fn series(subsystem: &'static str, code: &'static str) -> TxExecutionErrorLabels {
    TxExecutionErrorLabels { subsystem, code }
}

/// `ChainParams` with V2 on and nothing else opened.
fn closed() -> ChainParams {
    ChainParams::with_v2_enabled()
}

/// Serializes the tests in this binary against each other.
///
/// The registry is a process global. These tests assert EXACT deltas, which is
/// the whole attribution claim, and an exact delta is a lie if another test is
/// incrementing at the same time.
static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// The one claim every case makes.
///
/// `build` is handed a `Database` to seed and returns the block's
/// transactions; the last of them is the one the gate refuses.
fn the_gate_produces_an_attributable_signal(
    subsystem: &'static str,
    code: &'static str,
    open: fn() -> ChainParams,
    build: fn(&Database, &KeyPair) -> Vec<SignedTransaction>,
) {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let subject = series(subsystem, code);
    let expected = TxStatus::Failed(code.parse::<u32>().expect("the code label is the numeral"));

    let before = snapshot();
    let (state, db, _dir, executor) = setup_with_params(open());
    let sender = KeyPair::generate();
    fund(&db, &sender, FUNDED);
    let txs = build(&db, &sender);
    let n = txs.len();
    let receipts = publish_block(&state, &executor, 1, &PROPOSER, txs, &[]);
    assert_eq!(
        receipts.len(),
        n,
        "{subsystem}: every transaction got a receipt"
    );
    assert_eq!(
        receipts[n - 1].status,
        expected,
        "{subsystem}: the gated transaction must produce this subsystem's failed receipt"
    );
    let after = snapshot();

    // ── the signal ─────────────────────────────────────────────────────────
    let moved: Vec<(TxExecutionErrorLabels, u64)> = after
        .iter()
        .zip(before.iter())
        .filter(|((_, a), (_, b))| a != b)
        .map(|((l, a), (_, b))| (*l, a - b))
        .collect();
    assert_eq!(
        moved,
        vec![(subject, 1)],
        "{subsystem}: opening the gate and submitting the refused shape must advance \
         sumchain_tx_execution_errors_total{{subsystem=\"{subsystem}\",code=\"{code}\"}} \
         by exactly one and NOTHING else. A refusal that moves no series is invisible \
         to an operator; one that moves several is not attributable to a subsystem."
    );
}

/// Every series and its value, in the table's own order.
fn snapshot() -> Vec<(TxExecutionErrorLabels, u64)> {
    sumchain_primitives::tx_error_metrics::snapshot()
}

// ── R13 `subsystem_allocation_bound_enabled_from_height` ────────────────────
//
// The one Wave 1 gate every one of the nine executors reads. Each case below
// submits the shape that gate refuses, in that subsystem's own payload.

fn allocation_bound_open() -> ChainParams {
    let mut p = ChainParams::with_v2_enabled();
    p.subsystem_allocation_bound_enabled_from_height = Some(0);
    p
}

#[test]
fn nft_refusals_are_attributable_to_the_nft_subsystem() {
    the_gate_produces_an_attributable_signal("nft", "2", allocation_bound_open, |_db, kp| {
        vec![tx(
            kp,
            0,
            TxPayload::Nft(NftTxData {
                collection_id: [0xC0; 32],
                token_id: 0,
                operation: NftOperation::CreateCollection,
                data: oversized(),
            }),
        )]
    });
}

#[test]
fn docclass_refusals_are_attributable_to_the_docclass_subsystem() {
    the_gate_produces_an_attributable_signal("docclass", "8", allocation_bound_open, |_db, kp| {
        vec![tx(
            kp,
            0,
            TxPayload::DocClass(DocClassTxData {
                operation: DocClassOperation::CreateIdentityRoot,
                subcode: DocSubcode::Subject,
                data: oversized(),
                recipient: Address::ZERO,
            }),
        )]
    });
}

#[test]
fn tax_refusals_are_attributable_to_the_tax_subsystem() {
    the_gate_produces_an_attributable_signal("tax", "9", allocation_bound_open, |_db, kp| {
        vec![tx(
            kp,
            0,
            TxPayload::Tax(TaxTxData {
                operation: TaxOperation::RegisterIssuer,
                data: oversized(),
                recipient: Address::ZERO,
            }),
        )]
    });
}

#[test]
fn agreement_refusals_are_attributable_to_the_agreement_subsystem() {
    the_gate_produces_an_attributable_signal(
        "agreement",
        "11",
        allocation_bound_open,
        |_db, kp| {
            vec![tx(
                kp,
                0,
                TxPayload::Agreement(AgreementTxData {
                    operation: AgreementOperation::CommitAgreement,
                    data: oversized(),
                    recipient: Address::ZERO,
                }),
            )]
        },
    );
}

#[test]
fn property_refusals_are_attributable_to_the_property_subsystem() {
    the_gate_produces_an_attributable_signal("property", "13", allocation_bound_open, |_db, kp| {
        vec![tx(
            kp,
            0,
            TxPayload::Property(PropertyTxData {
                operation: PropertyOperation::AnchorAsset,
                data: oversized(),
                recipient: Address::ZERO,
            }),
        )]
    });
}

#[test]
fn healthcare_refusals_are_attributable_to_the_healthcare_subsystem() {
    the_gate_produces_an_attributable_signal(
        "healthcare",
        "14",
        allocation_bound_open,
        |_db, kp| {
            vec![tx(
                kp,
                0,
                TxPayload::Healthcare(HealthcareTxData {
                    operation: HealthcareOperation::RegisterProvider,
                    data: oversized(),
                    recipient: Address::ZERO,
                }),
            )]
        },
    );
}

// Legal and Finance read the same gate through a different rule: a free-text
// `jurisdiction_code` that becomes a raw column-family KEY. The refused shape
// is therefore a WELL-FORMED payload with an over-long code, not an oversized
// one — the gate is the same height, the arm is not.

#[test]
fn legal_refusals_are_attributable_to_the_legal_subsystem() {
    the_gate_produces_an_attributable_signal("legal", "12", allocation_bound_open, |_db, kp| {
        let case = CaseAnchor {
            case_id: [0xA1; 32],
            case_commitment: [0xA2; 32],
            jurisdiction_code: oversized_jurisdiction(),
            case_type: Some(CaseType::Civil),
            public_reference: None,
            policy_id: [0xA3; 32],
            issuer_class: LegalIssuerClass::CourtSystem,
            issuer_address: kp.address(),
            status: CaseStatus::Filed,
            created_at: 1_000,
            updated_at: 1_000,
            anchored_at_height: 1,
            related_cases: Vec::new(),
        };
        vec![tx(
            kp,
            0,
            TxPayload::Legal(LegalTxData {
                operation: LegalOperation::AnchorCase,
                data: bincode::serialize(&case).unwrap(),
                recipient: Address::ZERO,
            }),
        )]
    });
}

#[test]
fn finance_refusals_are_attributable_to_the_finance_subsystem() {
    the_gate_produces_an_attributable_signal("finance", "16", allocation_bound_open, |_db, kp| {
        let issuer = FinanceIssuerProfile {
            issuer_address: kp.address(),
            issuer_class: FinanceIssuerClass::RegulatedBank,
            issuer_commitment: [0xB1; 32],
            jurisdiction_code: oversized_jurisdiction(),
            policy_id: [0xB2; 32],
            status: FinanceIssuerStatus::Active,
            registered_at_height: 1,
            created_at: 1_000,
            updated_at: 1_000,
        };
        vec![tx(
            kp,
            0,
            TxPayload::Finance(FinanceTxData {
                operation: FinanceOperation::RegisterIssuer,
                data: bincode::serialize(&issuer).unwrap(),
                recipient: Address::ZERO,
            }),
        )]
    });
}

// Employment reads the same gate through the third of its three rules: an
// accumulating index row that grows by one id per credential forever. The
// refused shape needs the oversized ROW to exist first, so this case seeds one
// committed row and submits two transactions in one block.

#[test]
fn employment_refusals_are_attributable_to_the_employment_subsystem() {
    the_gate_produces_an_attributable_signal(
        "employment",
        "15",
        allocation_bound_open,
        |db, kp| {
            // One committed employee-index row one byte past the bound.
            let n = (MAX_ACCUMULATING_ROW_BYTES + 1).div_ceil(32) + 1;
            let ids: Vec<[u8; 32]> = (0..n as u32)
                .map(|i| {
                    let mut id = [0u8; 32];
                    id[..4].copy_from_slice(&i.to_be_bytes());
                    id
                })
                .collect();
            let row = bincode::serialize(&ids).unwrap();
            assert!(row.len() > MAX_ACCUMULATING_ROW_BYTES, "fixture too small");
            db.put(cf::EMPLOYMENT_EMPLOYEE_INDEX, &[0x55u8; 32], &row)
                .unwrap();

            let profile = EmploymentIssuerProfile {
                issuer_address: kp.address(),
                issuer_class: EmploymentIssuerClass::PayrollProcessor,
                display_name: "Payroll Co".to_string(),
                issuer_commitment: [0xC1; 32],
                jurisdiction_code: "US-CA".to_string(),
                policy_id: [0xC2; 32],
                status: IssuerStatus::Active,
                registered_at_height: 1,
                created_at: 1_000,
                updated_at: 1_000,
            };
            let credential = EmploymentCredential {
                employment_id: [0xFE; 32],
                employee_address: Address::new([0x77; 20]),
                employee_ref: [0x55; 32],
                employer_ref: [0x66; 32],
                status: EmploymentStatus::Active,
                tenure_commitment: [0xD1; 32],
                role_commitment: Some([0xD2; 32]),
                employment_type: EmploymentType::FullTime,
                valid_from: 100,
                expiry: 0,
                policy_id: [0xD3; 32],
                revocation_ref: None,
                issuer_address: kp.address(),
                issuer_name: "Payroll Co".to_string(),
                issuer_class: EmploymentIssuerClass::PayrollProcessor,
                created_at: 1_000,
                updated_at: 1_000,
            };
            vec![
                tx(
                    kp,
                    0,
                    TxPayload::Employment(EmploymentTxData {
                        operation: EmploymentOperation::RegisterIssuer,
                        data: bincode::serialize(&profile).unwrap(),
                        recipient: Address::ZERO,
                    }),
                ),
                tx(
                    kp,
                    1,
                    TxPayload::Employment(EmploymentTxData {
                        operation: EmploymentOperation::CreateEmployment,
                        data: bincode::serialize(&credential).unwrap(),
                        recipient: Address::ZERO,
                    }),
                ),
            ]
        },
    );
}

// ── A second Wave 1 gate on four of the nine ────────────────────────────────
//
// One gate reaching nine subsystems proves the counter is attributable across
// subsystems. These prove it is not attributable to ONE GATE — the seam counts
// whatever the executor refused, whichever height refused it.

fn property_proof_submission_unsupported_open() -> ChainParams {
    let mut p = ChainParams::with_v2_enabled();
    p.property_proof_submission_unsupported_enabled_from_height = Some(0);
    p
}

#[test]
fn the_property_proof_submission_gate_is_attributable_r32() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let subject = series("property", "13");
    let before = value(subject);
    let (state, db, _dir, executor) =
        setup_with_params(property_proof_submission_unsupported_open());
    let sender = KeyPair::generate();
    fund(&db, &sender, FUNDED);
    let receipts = publish_block(
        &state,
        &executor,
        1,
        &PROPOSER,
        vec![tx(
            &sender,
            0,
            TxPayload::Property(PropertyTxData {
                operation: PropertyOperation::SubmitProof,
                // The gate refuses BEFORE the decode, which is why an empty
                // payload is the whole fixture.
                data: Vec::new(),
                recipient: Address::ZERO,
            }),
        )],
        &[],
    );
    assert_eq!(receipts[0].status, TxStatus::Failed(13));
    assert_eq!(
        value(subject),
        before + 1,
        "R32's refusal is not on the counter"
    );
}

fn agreement_party_authority_unsupported_open() -> ChainParams {
    let mut p = ChainParams::with_v2_enabled();
    p.agreement_party_authority_unsupported_enabled_from_height = Some(0);
    p
}

#[test]
fn the_agreement_party_authority_gate_is_attributable_r29() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let subject = series("agreement", "11");
    let before = value(subject);
    let (state, db, _dir, executor) =
        setup_with_params(agreement_party_authority_unsupported_open());
    let sender = KeyPair::generate();
    fund(&db, &sender, FUNDED);
    let receipts = publish_block(
        &state,
        &executor,
        1,
        &PROPOSER,
        vec![tx(
            &sender,
            0,
            TxPayload::Agreement(AgreementTxData {
                operation: AgreementOperation::TerminateAgreement,
                data: Vec::new(),
                recipient: Address::ZERO,
            }),
        )],
        &[],
    );
    assert_eq!(receipts[0].status, TxStatus::Failed(11));
    assert_eq!(
        value(subject),
        before + 1,
        "R29's refusal is not on the counter"
    );
}

fn issuer_self_registration_unsupported_open() -> ChainParams {
    let mut p = ChainParams::with_v2_enabled();
    p.subsystem_issuer_self_registration_unsupported_enabled_from_height = Some(0);
    p
}

#[test]
fn the_issuer_self_registration_gate_is_attributable_in_tax_and_finance_r31() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    for (subsystem, code, payload) in [
        (
            "tax",
            "9",
            TxPayload::Tax(TaxTxData {
                operation: TaxOperation::RegisterIssuer,
                data: Vec::new(),
                recipient: Address::ZERO,
            }),
        ),
        (
            "finance",
            "16",
            TxPayload::Finance(FinanceTxData {
                operation: FinanceOperation::RegisterIssuer,
                data: Vec::new(),
                recipient: Address::ZERO,
            }),
        ),
    ] {
        let subject = series(subsystem, code);
        let before = value(subject);
        let (state, db, _dir, executor) =
            setup_with_params(issuer_self_registration_unsupported_open());
        let sender = KeyPair::generate();
        fund(&db, &sender, FUNDED);
        let receipts = publish_block(
            &state,
            &executor,
            1,
            &PROPOSER,
            vec![tx(&sender, 0, payload)],
            &[],
        );
        assert_eq!(
            receipts[0].status,
            TxStatus::Failed(code.parse::<u32>().unwrap()),
            "{subsystem}: R31 must refuse this shape"
        );
        assert_eq!(
            value(subject),
            before + 1,
            "{subsystem}: R31's refusal is not on the counter"
        );
    }
}

// ── The seam is ONE place, and stays one ────────────────────────────────────

/// Strip every `#[cfg(test)]` item's body from a Rust source, by brace depth.
fn without_test_modules(src: &str) -> String {
    let mut out = String::with_capacity(src.len());
    let mut rest = src;
    while let Some(at) = rest.find("#[cfg(test)]") {
        out.push_str(&rest[..at]);
        let tail = &rest[at..];
        // Skip to the opening brace of the attributed item, then past its
        // matching close.
        match tail.find('{') {
            Some(open) => {
                let mut depth = 0usize;
                let bytes = tail.as_bytes();
                let mut i = open;
                loop {
                    match bytes[i] {
                        b'{' => depth += 1,
                        b'}' => {
                            depth -= 1;
                            if depth == 0 {
                                break;
                            }
                        }
                        _ => {}
                    }
                    i += 1;
                    if i >= bytes.len() {
                        break;
                    }
                }
                rest = &tail[(i + 1).min(tail.len())..];
            }
            None => {
                rest = "";
            }
        }
    }
    out.push_str(rest);
    out
}

/// **The uniqueness claim the telemetry rests on.**
///
/// The counter is incremented at ONE call site. That is only a complete signal
/// while there is one place a receipt is built. A second `Receipt::new` on a
/// production path would be a receipt-producing route with no telemetry, and
/// it would be silent: every test here would still pass, because every test
/// here goes through the site that IS instrumented.
///
/// So the uniqueness is derived from the source on every run rather than
/// remembered. `#[cfg(test)]` bodies are stripped first — the rpc crate builds
/// receipts in its own unit tests, and those are not a production path.
#[test]
fn exactly_one_non_test_call_site_builds_a_receipt() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crates/")
        .to_path_buf();
    let mut sites: Vec<String> = Vec::new();
    let mut stack = vec![root.clone()];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).expect("readable crate tree") {
            let path = entry.expect("entry").path();
            if path.is_dir() {
                let name = path.file_name().unwrap().to_string_lossy().to_string();
                // Only `src`; `tests/`, `benches/`, `target/` are not the
                // production path.
                if name == "target" || name == "tests" || name == "benches" {
                    continue;
                }
                stack.push(path);
                continue;
            }
            if path.extension().and_then(|e| e.to_str()) != Some("rs") {
                continue;
            }
            let src = std::fs::read_to_string(&path).expect("readable source");
            let stripped = without_test_modules(&src);
            for (i, line) in stripped.lines().enumerate() {
                let code = line.split("//").next().unwrap_or("");
                if code.contains("Receipt::new(") {
                    sites.push(format!("{}:{}", path.display(), i + 1));
                }
            }
        }
    }
    assert_eq!(
        sites.len(),
        1,
        "exactly one non-test call site may build a receipt, so that one \
         `tx_error_metrics::record` covers every subsystem. Found: {sites:#?}"
    );
    assert!(
        sites[0].contains("state/src/executor.rs"),
        "the receipt seam moved: {}",
        sites[0]
    );
}

/// The instrumented site and the receipt site are the SAME site.
///
/// A `record` call that drifted into a different function — an earlier return,
/// a different loop — would leave the assertions above passing and the counter
/// counting something else. This pins them within a few lines of each other in
/// the source.
#[test]
fn the_record_call_sits_at_the_receipt_construction_site() {
    let src = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/executor.rs"),
    )
    .expect("executor source");
    let record = src
        .find("tx_error_metrics::record(&result.status)")
        .expect("the failed-receipt telemetry seam is gone");
    let receipt = src
        .find("let receipt = Receipt::new(")
        .expect("receipt site");
    assert!(
        receipt > record && receipt - record < 200,
        "the record call has drifted away from the receipt it describes"
    );
    // And it is guarded against the screening pass, which executes a proposal
    // that will not become a block.
    let guard = src[..record].rfind("if screening.is_none() {").expect(
        "the screening guard is gone: a proposer would count refusals \
                 from blocks it never built",
    );
    assert!(
        record - guard < 80,
        "the screening guard no longer encloses the record call"
    );
}

/// A transaction that SUCCEEDS moves no error series at all.
///
/// The per-case discriminator above shows a refusal lands on one series. This
/// shows the counter is a failure counter and not a transaction counter — the
/// other way a "signal" can be worthless.
#[test]
fn a_successful_transaction_moves_no_series() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let before = snapshot();
    let (state, db, _dir, executor) = setup_with_params(closed());
    let sender = KeyPair::generate();
    fund(&db, &sender, FUNDED);
    let receipts = publish_block(
        &state,
        &executor,
        1,
        &PROPOSER,
        vec![tx(
            &sender,
            0,
            TxPayload::Transfer {
                to: Address::new([0x42; 20]),
                amount: 1_000,
            },
        )],
        &[],
    );
    assert_eq!(
        receipts[0].status,
        TxStatus::Success,
        "the control transaction must succeed, or it controls nothing"
    );
    assert_eq!(
        snapshot(),
        before,
        "a successful transfer moved an execution-error series"
    );
}
