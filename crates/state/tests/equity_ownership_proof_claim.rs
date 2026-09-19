//! Equity's only proof-write path must not report a verification.
//!
//! `EquityOperation` discriminant 70 deducts a fee, deserializes an
//! `OwnershipProofEnvelope`, writes it to `EQUITY_PROOFS` and returns success.
//! It reads neither `proof_data` nor `public_inputs`, and checks neither
//! against the other. Until the change this file pins, it announced
//!
//! ```text
//! Ownership proof verified: [..]
//! ```
//!
//! which was false on every input, and it did so through an opcode named
//! `VerifyOwnershipProof`, so the success receipt carried the same false claim
//! to anyone decoding the operation rather than reading the log.
//!
//! # Why this path is corrected and not refused
//!
//! The seven sibling `VerifyProof` arms refuse as UNSUPPORTED above
//! `subsystem_proof_unsupported_enabled_from_height`, because verification is
//! the whole of what they purport to do and no verifier exists in this tree.
//! This arm is a different animal. Strip its name off and it is a SUBMIT --
//! the identical deduct/store/success the six sibling `SubmitProof` arms
//! perform and honestly log as `"... proof submitted"`. Equity has no
//! `SubmitProof`: discriminant 70 is the family's ONLY proof-write path, so
//! refusing it strands the family outright, in exchange for removing a claim
//! that renaming the opcode removes anyway. The operation keeps every byte of
//! its behaviour and loses the word it had no right to.
//!
//! The rename is deliberately NOT behind an activation height. The same fee
//! moves, the same nonce advances, the same bytes reach the same column family
//! and the same receipt status returns; a `debug!` string and a Rust
//! identifier are the whole diff. An activation height is a claim that nodes
//! below it computed a different state, and adding one here would insert a
//! false claim into `activation_heights()` in the act of deleting one from a
//! log.
//!
//! # What is asserted, and why the text is asserted with the behaviour
//!
//! A passing behavioural test is exactly what the defect survived for: the
//! write worked, the fee moved, the receipt said success, and the only thing
//! wrong was a sentence. So each test below asserts the RETURNED BEHAVIOUR and
//! the EMITTED TEXT together, and a misleading log fails a named test rather
//! than a review.
//!
//! **The capture harness is hand-rolled, in this file.** `crates/state` has no
//! `tracing` capture harness and `tracing-subscriber` was not among its
//! dev-dependencies; rather than pull a subscriber crate in to read one
//! string, `Capture` below implements `tracing::Subscriber` directly (~50
//! lines) and collects formatted event messages under
//! `tracing::subscriber::with_default`. `tracing` itself is added to
//! `[dev-dependencies]` because an integration test cannot reach the library's
//! own dependencies.

use std::sync::{Arc, Mutex};

use sumchain_crypto::KeyPair;
use sumchain_genesis::ChainParams;
use sumchain_primitives::equity::{EquityOperation, EquityTxData};
use sumchain_primitives::{Address, Hash, OwnershipProofEnvelope, OwnershipProofType};
use sumchain_state::equity_executor::EquityExecutor;
use sumchain_storage::exec_view::ExecutionView;
use sumchain_storage::overlay::ApplicationOverlay;

mod common;
use common::{fund, setup_with_params};

const FEE: u128 = 100;
const NOW: u64 = 1_700_000_000;

// ── A minimal `tracing` capture ─────────────────────────────────────────────

/// Collects the `message` field of every event emitted on the current thread.
///
/// Deliberately tiny: it answers one question -- what text did this execution
/// path put in front of an operator -- and answers it without a subscriber
/// crate. Span bookkeeping is stubbed because nothing under test opens a span.
#[derive(Clone, Default)]
struct Capture {
    lines: Arc<Mutex<Vec<String>>>,
}

struct MessageVisitor<'a>(&'a mut String);

impl tracing::field::Visit for MessageVisitor<'_> {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            use std::fmt::Write;
            let _ = write!(self.0, "{:?}", value);
        }
    }

    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        if field.name() == "message" {
            self.0.push_str(value);
        }
    }
}

impl tracing::Subscriber for Capture {
    fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
        true
    }

    fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }

    fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}

    fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}

    fn event(&self, event: &tracing::Event<'_>) {
        let mut message = String::new();
        event.record(&mut MessageVisitor(&mut message));
        if !message.is_empty() {
            self.lines.lock().unwrap().push(message);
        }
    }

    fn enter(&self, _: &tracing::span::Id) {}

    fn exit(&self, _: &tracing::span::Id) {}
}

impl Capture {
    fn lines(&self) -> Vec<String> {
        self.lines.lock().unwrap().clone()
    }
}

/// Run `body` with every `tracing` event on this thread collected.
fn capturing<T>(body: impl FnOnce() -> T) -> (T, Vec<String>) {
    let capture = Capture::default();
    let out = tracing::subscriber::with_default(capture.clone(), body);
    (out, capture.lines())
}

// ── Fixture ─────────────────────────────────────────────────────────────────

/// An envelope whose `proof_data` is EMPTY.
///
/// The invalidity does not depend on the code under test: a Groth16 proof is
/// three group elements and cannot be zero bytes under any parameters and any
/// verifying key. If discriminant 70 ever verified anything, this input is the
/// one it would have to reject -- so a success here is the sharpest available
/// statement that nothing was checked.
fn unverifiable_envelope() -> OwnershipProofEnvelope {
    OwnershipProofEnvelope {
        proof_id: [0xE1; 32],
        profile_id: "equity-ownership-v1".to_string(),
        policy_ids: vec![[0xE2; 32]],
        public_inputs: Vec::new(),
        proof_data: Vec::new(),
        proof_type: OwnershipProofType::Groth16,
        subject_nullifier: [0xE3; 32],
        generated_at: NOW,
        expires_at: NOW + 1_000,
    }
}

/// Submit `envelope` through discriminant 70 and report what came back, what
/// landed in state, and what was said about it.
struct Outcome {
    success: bool,
    stored: bool,
    charged: bool,
    lines: Vec<String>,
}

fn submit(envelope: &OwnershipProofEnvelope) -> Outcome {
    let (_state, db, _dir, _executor) = setup_with_params(ChainParams::with_v2_enabled());
    let actor = KeyPair::generate();
    fund(&db, &actor, 100_000_000);
    let sender = actor.address();
    let proposer = Address::new([9; 20]);

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);

    let before = sumchain_state::StateManager::v_get_balance(&view, &sender).unwrap();

    let ((success, stored, after), lines) = capturing(|| {
        let result = EquityExecutor::execute(
            &mut view,
            &sender,
            &EquityTxData {
                operation: EquityOperation::SubmitOwnershipProof,
                data: bincode::serialize(envelope).unwrap(),
                recipient: Address::ZERO,
            },
            &proposer,
            FEE,
            1,
            NOW,
            0,
            Hash::ZERO,
        )
        .unwrap();
        let stored = EquityExecutor::v_get_ownership_proof(&view, &envelope.proof_id)
            .unwrap()
            .is_some();
        let after = sumchain_state::StateManager::v_get_balance(&view, &sender).unwrap();
        (result.success, stored, after)
    });

    Outcome {
        success,
        stored,
        charged: before - after == FEE,
        lines,
    }
}

// ── The claims ──────────────────────────────────────────────────────────────

/// The write path still works -- and says only that a write happened.
///
/// Both halves matter together. Dropping the behavioural half would let a
/// refusal pass as a fix, and refusing strands Equity's only proof-write path.
/// Dropping the text half is how the defect survived in the first place.
#[test]
fn equity_ownership_proof_stores_and_reports_storage_not_verification() {
    let envelope = unverifiable_envelope();
    let outcome = submit(&envelope);

    // Returned behaviour: the family is NOT stranded.
    assert!(
        outcome.success,
        "discriminant 70 must still accept a submission"
    );
    assert!(
        outcome.stored,
        "the envelope must still reach EQUITY_PROOFS"
    );
    assert!(outcome.charged, "the submission must still cost its fee");

    // Emitted text: exactly the constant, and nothing that means "verified".
    let said = outcome
        .lines
        .iter()
        .find(|l| l.contains("ownership proof"))
        .unwrap_or_else(|| {
            panic!(
                "the ownership-proof write path emitted nothing about itself: {:?}",
                outcome.lines
            )
        });

    assert!(
        said.contains(sumchain_state::EQUITY_OWNERSHIP_PROOF_SUBMITTED),
        "the write path must say exactly EQUITY_OWNERSHIP_PROOF_SUBMITTED, said: {said:?}"
    );
    assert!(
        said.contains(&format!("{:?}", envelope.proof_id)),
        "the message must name the proof id it stored, said: {said:?}"
    );
}

/// No line this path emits may claim a verification, however phrased.
///
/// Separate from the assertion above because the two fail for different
/// reasons: that one fails when the honest sentence is missing, this one fails
/// when a dishonest sentence is ADDED alongside it. Restoring
/// `debug!("Ownership proof verified: {:?}", ..)` next to the new line passes
/// the first and fails this one.
#[test]
fn equity_ownership_proof_path_emits_no_verification_claim() {
    let outcome = submit(&unverifiable_envelope());

    for line in &outcome.lines {
        let lowered = line.to_lowercase();
        // The constant states the negative ("NOT verified"), which contains
        // the word; the ban is on a POSITIVE claim, so the constant's own
        // wording is the one form excluded.
        let without_the_disclaimer = lowered.replace(
            &sumchain_state::EQUITY_OWNERSHIP_PROOF_SUBMITTED.to_lowercase(),
            "",
        );
        assert!(
            !without_the_disclaimer.contains("verif"),
            "the Equity proof path claimed a verification it did not perform: {line:?}"
        );
    }
}

/// The constant itself must state the negative, not merely omit the positive.
///
/// "Ownership proof stored" would pass both assertions above while leaving an
/// operator to infer the interesting fact. The chain writes bytes a fee-payer
/// chose and nothing has looked at; that has to be on the line, not between
/// the lines.
#[test]
fn equity_ownership_proof_message_states_that_nothing_was_verified() {
    let message = sumchain_state::EQUITY_OWNERSHIP_PROOF_SUBMITTED;
    assert!(
        message.contains("NOT verified"),
        "the message must say outright that nothing was verified: {message:?}"
    );
    assert!(
        message.contains("no verifier"),
        "the message must say why -- there is no verifier: {message:?}"
    );
}

/// No Equity operation is named for a verification, and 70 still decodes.
///
/// The log is one of the two surfaces that carried the false claim; the
/// operation NAME is the other, and it is the one a receipt decoder reads.
/// This pins both halves of the rename: nothing in the family is called
/// "verify", and the wire byte did not move while the name changed.
#[test]
fn no_equity_operation_claims_to_verify_and_seventy_is_unmoved() {
    assert_eq!(
        EquityOperation::from_u8(70),
        Some(EquityOperation::SubmitOwnershipProof),
        "the rename must not have moved the wire discriminant"
    );

    let source = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../sumchain-wire/src/equity.rs"),
    )
    .expect("read the Equity wire module");

    // Variant lines only: the doc comment above `SubmitOwnershipProof`
    // deliberately names the old identifier to record what was corrected.
    for line in source.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("//") || !trimmed.contains(" = ") {
            continue;
        }
        assert!(
            !trimmed.contains("Verify"),
            "an EquityOperation variant still claims to verify: {trimmed:?}"
        );
    }
}
