//! Deterministic tests for the gate-closed BR1 beacon runtime (issue #127).
//!
//! Every input is a fixed byte seed — no clock, no RNG — so the whole
//! params → context-binding → DKG → adjudication → QUAL → signing → chained-rounds
//! lifecycle is reproducible. The scenarios build real on-chain carriers with the
//! crypto adapter and drive them through the runtime under an authenticated context,
//! asserting the four objective verdicts, QUAL success/safe-halt, exactly-`T`
//! combine, finalize verification, chained-round progression + reorg restoration, and
//! the crypto/authentication negatives.

use sumchain_beacon_crypto::{
    dleq_prove, ecies_seal, eval_share_le, DleqContext, EciesContext, G1Point, SecretScalar,
    SCALAR_SIZE,
};
use sumchain_wire::beacon_wire::{DkgComplaintV1, DkgDealV1, RegisterBeaconKeyV1};

use crate::context::{
    BeaconPhase, ContextError, EpochCutoffs, EpochMembership, ExecContext, ValidatorId,
};
use crate::dkg::{
    AdjudicateError, DealOutcome, DkgConfig, DkgEpoch, DkgOutcome, RegistrationOutcome, SetupError,
    Verdict,
};
use crate::params::{BeaconParams, ParamsError};
use crate::rounds::{BeaconChain, FinalizeOutcome, PartialOutcome, RoundError};
use crate::signing::{FinalizeError, QualifiedEpoch};
use crate::validate::{validate_operation, ValidationError};
use crate::wire::{beacon_output, genesis_seed, round_message, BeaconFinalizeV1, BeaconPartialV1};
use sumchain_wire::beacon_wire::BeaconOperation;

const CHAIN_ID: u64 = 0x0102_0304_0506_0708;
const EPOCH: u64 = 7;
const N: u32 = 5;
const DEAL_CUTOFF: u64 = 100;
const COMPLAINT_DEADLINE: u64 = 200;

fn seed(tag: u8) -> [u8; SCALAR_SIZE] {
    let mut b = [0u8; SCALAR_SIZE];
    for (i, out) in b.iter_mut().enumerate() {
        *out = tag.wrapping_add(i as u8).wrapping_mul(7).wrapping_add(1);
    }
    b[SCALAR_SIZE - 1] = 0;
    b
}

fn vid(i: u32) -> ValidatorId {
    ValidatorId([i as u8; 32])
}

fn membership() -> EpochMembership {
    EpochMembership::new((0..N).map(vid).collect()).unwrap()
}

fn cutoffs() -> EpochCutoffs {
    EpochCutoffs {
        deal_cutoff: DEAL_CUTOFF,
        complaint_deadline: COMPLAINT_DEADLINE,
    }
}

fn ctx(m: &EpochMembership, signer_index: u32, phase: BeaconPhase, height: u64) -> ExecContext<'_> {
    ExecContext {
        signer: vid(signer_index),
        chain_id: CHAIN_ID,
        epoch: EPOCH,
        block_height: height,
        phase,
        membership: m,
        cutoffs: cutoffs(),
    }
}

fn config() -> DkgConfig {
    DkgConfig {
        chain_id: CHAIN_ID,
        epoch: EPOCH,
        params: BeaconParams::proposed_default(),
    }
}

fn dealer_coeffs(i: u32) -> [[u8; SCALAR_SIZE]; 2] {
    [seed(0x10 + i as u8), seed(0x20 + i as u8)]
}
fn ek_secret(j: u32) -> SecretScalar {
    SecretScalar::from_bytes_le(&seed(0x40 + j as u8)).unwrap()
}
fn r_secret(i: u32, j: u32) -> SecretScalar {
    SecretScalar::from_bytes_le(&seed(0x60u8.wrapping_add((i * 8 + j) as u8))).unwrap()
}

/// A `RegisterBeaconKeyV1` carrying the encryption key of `secret`.
fn make_reg_for(secret: &SecretScalar) -> RegisterBeaconKeyV1 {
    RegisterBeaconKeyV1 {
        chain_id: CHAIN_ID,
        epoch: EPOCH,
        ek_j: secret.public_g1().to_compressed(),
        pop: secret.pop_prove().to_compressed(),
    }
}
fn make_reg(j: u32) -> RegisterBeaconKeyV1 {
    make_reg_for(&ek_secret(j))
}

fn make_deal(
    i: u32,
    j: u32,
    share_override: Option<[u8; SCALAR_SIZE]>,
    tamper_ct: bool,
) -> DkgDealV1 {
    let coeffs = dealer_coeffs(i);
    let c0 = SecretScalar::from_bytes_le(&coeffs[0]).unwrap().public_g1();
    let c1 = SecretScalar::from_bytes_le(&coeffs[1]).unwrap().public_g1();
    let x_j = (j as u64) + 1;
    let share = share_override.unwrap_or_else(|| eval_share_le(&coeffs[..], x_j).unwrap());

    let r = r_secret(i, j);
    let r_pt = r.public_g1();
    let ek_pt = ek_secret(j).public_g1();
    let d = r.ecdh(&ek_pt).unwrap();
    let ctx = EciesContext {
        chain_id: CHAIN_ID,
        epoch: EPOCH,
        dealer_i: i,
        recipient_j: j,
        r_ij: r_pt,
        ek_j: ek_pt,
    };
    let mut ct = ecies_seal(&d, &ctx, &share).unwrap();
    if tamper_ct {
        ct[0] ^= 0x01;
    }
    DkgDealV1 {
        chain_id: CHAIN_ID,
        epoch: EPOCH,
        dealer_i: i,
        recipient_j: j,
        commitments: vec![c0.to_compressed(), c1.to_compressed()],
        r_ij: r_pt.to_compressed(),
        ct_ij: ct,
    }
}

fn make_complaint(i: u32, j: u32, d_override: Option<G1Point>) -> DkgComplaintV1 {
    let ek = ek_secret(j);
    let ek_pt = ek.public_g1();
    let r_pt = r_secret(i, j).public_g1();
    let d_true = ek.ecdh(&r_pt).unwrap();
    let d_pub = d_override.unwrap_or(d_true);

    let dctx = DleqContext {
        chain_id: CHAIN_ID.to_le_bytes().to_vec(),
        epoch: EPOCH,
        dealer_index: i,
        recipient_index: j,
    };
    let h = G1Point::generator();
    let proof = dleq_prove(&dctx, &h, &ek_pt, &r_pt, &d_true, &ek, &seed(0x77)).unwrap();
    let pb = proof.to_bytes();
    let mut dleq_c = [0u8; SCALAR_SIZE];
    let mut dleq_z = [0u8; SCALAR_SIZE];
    dleq_c.copy_from_slice(&pb[..SCALAR_SIZE]);
    dleq_z.copy_from_slice(&pb[SCALAR_SIZE..]);
    DkgComplaintV1 {
        chain_id: CHAIN_ID,
        epoch: EPOCH,
        i,
        j,
        r_ij: r_pt.to_compressed(),
        d_ij: d_pub.to_compressed(),
        dleq_c,
        dleq_z,
    }
}

/// Setup an epoch with recipient `j` keyed and one accepted `(i,j)` deal.
fn epoch_with_deal(
    m: &EpochMembership,
    i: u32,
    j: u32,
    share_override: Option<[u8; SCALAR_SIZE]>,
    tamper: bool,
) -> DkgEpoch {
    let mut e = DkgEpoch::new(config());
    e.register_key(&ctx(m, j, BeaconPhase::Setup, 10), &make_reg(j))
        .unwrap();
    assert_eq!(
        e.submit_deal(
            &ctx(m, i, BeaconPhase::Setup, 10),
            &make_deal(i, j, share_override, tamper)
        )
        .unwrap(),
        DealOutcome::Accepted
    );
    e
}

// ---------------------------------------------------------------------------
// Finding 2 — validated parameters
// ---------------------------------------------------------------------------

#[test]
fn params_valid_and_invalid_configs() {
    // Valid: the proposed profile + a larger valid one.
    assert!(BeaconParams::validated(1, 1, 2, 3, 5).is_ok());
    assert!(BeaconParams::validated(2, 1, 3, 5, 8).is_ok());
    let p = BeaconParams::proposed_default();
    assert_eq!((p.f(), p.c(), p.t(), p.q_dkg(), p.n()), (1, 1, 2, 3, 5));

    // Invalid configs are each rejected with the specific typed error.
    assert_eq!(
        BeaconParams::validated(1, 1, 0, 3, 5),
        Err(ParamsError::ZeroThreshold)
    );
    assert!(matches!(
        BeaconParams::validated(1, 1, 1, 3, 5), // T=1 < f+1=2
        Err(ParamsError::ThresholdTooSmall { .. })
    ));
    assert!(matches!(
        BeaconParams::validated(1, 1, 2, 2, 5), // Q=2 < 2f+1=3
        Err(ParamsError::QualTooSmall { .. })
    ));
    assert!(matches!(
        BeaconParams::validated(1, 1, 2, 3, 2), // Q=3 > n=2
        Err(ParamsError::Inconsistent { .. })
    ));
    assert!(matches!(
        BeaconParams::validated(1, 1, 2, 3, 4), // n-f-c=2 < Q=3
        Err(ParamsError::LivenessQual { .. })
    ));
}

// ---------------------------------------------------------------------------
// Finding 3 — authenticated actor binding, membership, phase, cutoff, cross-epoch
// ---------------------------------------------------------------------------

#[test]
fn context_actor_binding_negatives() {
    let m = membership();
    let mut e = DkgEpoch::new(config());

    // Deal signer must equal dealer_i: signer=vid(1) but dealer_i=0.
    let bad_signer = ctx(&m, 1, BeaconPhase::Setup, 10);
    assert_eq!(
        e.submit_deal(&bad_signer, &make_deal(0, 2, None, false)),
        Err(SetupError::Context(ContextError::ActorIndexMismatch))
    );

    // Non-member signer.
    let non_member = ExecContext {
        signer: vid(99),
        ..ctx(&m, 0, BeaconPhase::Setup, 10)
    };
    assert_eq!(
        e.submit_deal(&non_member, &make_deal(0, 2, None, false)),
        Err(SetupError::Context(ContextError::SignerNotMember))
    );

    // Index out of range: recipient_j = 99 (>= n).
    assert_eq!(
        e.submit_deal(
            &ctx(&m, 0, BeaconPhase::Setup, 10),
            &make_deal(0, 99, None, false)
        ),
        Err(SetupError::Context(ContextError::IndexOutOfRange))
    );

    // Wrong phase: a deal under the Signing phase.
    assert_eq!(
        e.submit_deal(
            &ctx(&m, 0, BeaconPhase::Signing, 10),
            &make_deal(0, 2, None, false)
        ),
        Err(SetupError::Context(ContextError::PhaseMismatch))
    );

    // Cutoff: deal after the deal cutoff.
    assert_eq!(
        e.submit_deal(
            &ctx(&m, 0, BeaconPhase::Setup, DEAL_CUTOFF + 1),
            &make_deal(0, 2, None, false)
        ),
        Err(SetupError::Context(ContextError::CutoffViolation))
    );

    // Cross-epoch / cross-chain on the carrier.
    let mut wrong_epoch = make_deal(0, 2, None, false);
    wrong_epoch.epoch = EPOCH + 1;
    assert_eq!(
        e.submit_deal(&ctx(&m, 0, BeaconPhase::Setup, 10), &wrong_epoch),
        Err(SetupError::Context(ContextError::EpochMismatch))
    );
    let mut wrong_chain = make_deal(0, 2, None, false);
    wrong_chain.chain_id = CHAIN_ID + 1;
    assert_eq!(
        e.submit_deal(&ctx(&m, 0, BeaconPhase::Setup, 10), &wrong_chain),
        Err(SetupError::Context(ContextError::ChainIdMismatch))
    );
}

#[test]
fn context_membership_size_must_match_params() {
    // params.n() = 5 but the snapshot has 4 members.
    let m4 = EpochMembership::new((0..4).map(vid).collect()).unwrap();
    let mut e = DkgEpoch::new(config());
    assert!(matches!(
        e.submit_deal(
            &ctx(&m4, 0, BeaconPhase::Setup, 10),
            &make_deal(0, 2, None, false)
        ),
        Err(SetupError::MembershipSizeMismatch {
            snapshot_n: 4,
            params_n: 5
        })
    ));
}

#[test]
fn context_complaint_signer_must_be_recipient() {
    let m = membership();
    let e = epoch_with_deal(&m, 0, 1, None, false);
    // Complaint for recipient j=1 but signed by vid(2).
    let wrong = ctx(&m, 2, BeaconPhase::Setup, 50);
    assert_eq!(
        e.adjudicate(&wrong, &make_complaint(0, 1, None)),
        Err(AdjudicateError::Context(ContextError::ActorIndexMismatch))
    );
    // Complaint past the deadline.
    let late = ctx(&m, 1, BeaconPhase::Setup, COMPLAINT_DEADLINE + 1);
    assert_eq!(
        e.adjudicate(&late, &make_complaint(0, 1, None)),
        Err(AdjudicateError::Context(ContextError::CutoffViolation))
    );
}

// ---------------------------------------------------------------------------
// Finding 4 — complete deal semantics
// ---------------------------------------------------------------------------

#[test]
fn deal_commitment_count_must_equal_t() {
    let m = membership();
    let mut e = DkgEpoch::new(config());
    let mut deal = make_deal(0, 2, None, false);
    // Add a 3rd commitment (T = 2) → mismatch.
    deal.commitments.push(deal.commitments[0]);
    assert_eq!(
        e.submit_deal(&ctx(&m, 0, BeaconPhase::Setup, 10), &deal),
        Err(SetupError::CommitmentCountMismatch {
            got: 3,
            expected: 2
        })
    );
}

#[test]
fn deal_conflicting_commitments_across_recipients_retains_evidence() {
    let m = membership();
    let mut e = DkgEpoch::new(config());
    assert_eq!(
        e.submit_deal(
            &ctx(&m, 0, BeaconPhase::Setup, 10),
            &make_deal(0, 0, None, false)
        )
        .unwrap(),
        DealOutcome::Accepted
    );
    // Dealer 0's deal to recipient 1 but with dealer 1's commitments.
    let mut deal = make_deal(0, 1, None, false);
    let other = dealer_coeffs(1);
    deal.commitments = vec![
        SecretScalar::from_bytes_le(&other[0])
            .unwrap()
            .public_g1()
            .to_compressed(),
        SecretScalar::from_bytes_le(&other[1])
            .unwrap()
            .public_g1()
            .to_compressed(),
    ];
    let outcome = e
        .submit_deal(&ctx(&m, 0, BeaconPhase::Setup, 10), &deal)
        .unwrap();
    assert!(matches!(outcome, DealOutcome::ConflictingDeal(_)));
    assert!(e.disqualified().contains(&0));
    assert_eq!(
        e.deal_equivocations().len(),
        1,
        "conflicting deal retained as evidence"
    );
}

#[test]
fn deal_accept_duplicate_conflict_evidence() {
    let m = membership();
    let mut e = DkgEpoch::new(config());
    let deal = make_deal(0, 1, None, false);
    assert_eq!(
        e.submit_deal(&ctx(&m, 0, BeaconPhase::Setup, 10), &deal)
            .unwrap(),
        DealOutcome::Accepted
    );
    assert_eq!(
        e.submit_deal(&ctx(&m, 0, BeaconPhase::Setup, 10), &deal)
            .unwrap(),
        DealOutcome::Duplicate
    );
    assert!(!e.disqualified().contains(&0));

    let conflicting = make_deal(0, 1, Some(seed(0xAB)), false);
    let outcome = e
        .submit_deal(&ctx(&m, 0, BeaconPhase::Setup, 10), &conflicting)
        .unwrap();
    assert!(matches!(outcome, DealOutcome::ConflictingDeal(ev) if ev.dealer_i == 0));
    assert!(e.disqualified().contains(&0));
    assert_eq!(e.deal_equivocations().len(), 1);
}

// ---------------------------------------------------------------------------
// Finding 5 — key replay vs equivocation (retained evidence)
// ---------------------------------------------------------------------------

#[test]
fn key_replay_vs_equivocation() {
    let m = membership();
    let mut e = DkgEpoch::new(config());
    // Fresh key accepted.
    assert_eq!(
        e.register_key(&ctx(&m, 0, BeaconPhase::Setup, 10), &make_reg(0))
            .unwrap(),
        RegistrationOutcome::Accepted
    );
    // Identical replay ⇒ idempotent no-op.
    assert_eq!(
        e.register_key(&ctx(&m, 0, BeaconPhase::Setup, 10), &make_reg(0))
            .unwrap(),
        RegistrationOutcome::DuplicateReplay
    );
    // A DIFFERENT valid key for the same validator ⇒ equivocation with evidence.
    let other = make_reg_for(&SecretScalar::from_bytes_le(&seed(0x91)).unwrap());
    let outcome = e
        .register_key(&ctx(&m, 0, BeaconPhase::Setup, 10), &other)
        .unwrap();
    match outcome {
        RegistrationOutcome::Equivocation(ev) => {
            assert_eq!(ev.validator_index, 0);
            assert_ne!(ev.first, ev.second, "two distinct signed records retained");
        }
        other => panic!("expected equivocation, got {other:?}"),
    }
    assert_eq!(e.key_equivocations().len(), 1);
    // The first key stays authoritative (deterministic).
    assert_eq!(
        e.registered_key(0).unwrap().to_compressed(),
        ek_secret(0).public_g1().to_compressed()
    );
}

#[test]
fn register_rejects_bad_pop_and_off_curve() {
    let m = membership();
    let mut e = DkgEpoch::new(config());
    // Wrong PoP (valid G2 point for another key).
    let mut wrong_pop = make_reg(0);
    wrong_pop.pop = ek_secret(2).pop_prove().to_compressed();
    assert_eq!(
        e.register_key(&ctx(&m, 0, BeaconPhase::Setup, 10), &wrong_pop),
        Err(SetupError::PopInvalid)
    );
    // Off-curve EK.
    let mut bad = make_reg(0);
    bad.ek_j = [0x80u8; 48];
    assert!(matches!(
        e.register_key(&ctx(&m, 0, BeaconPhase::Setup, 10), &bad),
        Err(SetupError::InvalidElement(_))
    ));
    // Registering after the cutoff (register-before-cutoff, §11 rule 3).
    assert_eq!(
        e.register_key(
            &ctx(&m, 0, BeaconPhase::Setup, DEAL_CUTOFF + 1),
            &make_reg(0)
        ),
        Err(SetupError::Context(ContextError::CutoffViolation))
    );
}

// ---------------------------------------------------------------------------
// The four objective complaint verdicts (draft §6.1)
// ---------------------------------------------------------------------------

#[test]
fn verdict_slash_false_accuser() {
    let m = membership();
    let mut e = epoch_with_deal(&m, 0, 1, None, false);
    let outcome = e
        .apply_complaint(
            &ctx(&m, 1, BeaconPhase::Setup, 50),
            &make_complaint(0, 1, None),
        )
        .unwrap();
    assert_eq!(outcome.verdict, Verdict::SlashFalseAccuser);
    assert!(outcome.state_changed);
    assert!(!e.disqualified().contains(&0));
    assert!(e.false_accusers().contains(&1));
}

#[test]
fn verdict_disqualify_and_slash() {
    let m = membership();
    let mut e = epoch_with_deal(&m, 0, 1, Some(seed(0xCD)), false);
    let outcome = e
        .apply_complaint(
            &ctx(&m, 1, BeaconPhase::Setup, 50),
            &make_complaint(0, 1, None),
        )
        .unwrap();
    assert_eq!(outcome.verdict, Verdict::DisqualifyAndSlash);
    assert!(e.disqualified().contains(&0));
}

#[test]
fn verdict_disqualify_aead_open_failure() {
    let m = membership();
    let mut e = epoch_with_deal(&m, 0, 1, None, true);
    let outcome = e
        .apply_complaint(
            &ctx(&m, 1, BeaconPhase::Setup, 50),
            &make_complaint(0, 1, None),
        )
        .unwrap();
    assert_eq!(outcome.verdict, Verdict::Disqualify);
    assert!(e.disqualified().contains(&0));
}

#[test]
fn verdict_reject_complaint_malformed_and_reprosecute() {
    let m = membership();
    let mut e = epoch_with_deal(&m, 0, 1, None, false);
    let r_pt = r_secret(0, 1).public_g1();
    let d_wrong = ek_secret(2).ecdh(&r_pt).unwrap();
    let outcome = e
        .apply_complaint(
            &ctx(&m, 1, BeaconPhase::Setup, 50),
            &make_complaint(0, 1, Some(d_wrong)),
        )
        .unwrap();
    assert_eq!(outcome.verdict, Verdict::RejectComplaintMalformed);
    assert!(!outcome.state_changed);
    assert!(!e.disqualified().contains(&0));
    // A malformed complaint does not consume the pair: a valid one still takes effect.
    let good = e
        .apply_complaint(
            &ctx(&m, 1, BeaconPhase::Setup, 50),
            &make_complaint(0, 1, None),
        )
        .unwrap();
    assert_eq!(good.verdict, Verdict::SlashFalseAccuser);
    assert!(good.state_changed);
}

#[test]
fn complaint_idempotent_no_double_jeopardy() {
    let m = membership();
    let mut e = epoch_with_deal(&m, 0, 1, Some(seed(0xCD)), false);
    let first = e
        .apply_complaint(
            &ctx(&m, 1, BeaconPhase::Setup, 50),
            &make_complaint(0, 1, None),
        )
        .unwrap();
    assert!(first.state_changed);
    let second = e
        .apply_complaint(
            &ctx(&m, 1, BeaconPhase::Setup, 50),
            &make_complaint(0, 1, None),
        )
        .unwrap();
    assert_eq!(second.verdict, Verdict::DisqualifyAndSlash);
    assert!(!second.state_changed);
}

#[test]
fn complaint_not_adjudicable_missing_facts() {
    let m = membership();
    let mut e = DkgEpoch::new(config());
    assert_eq!(
        e.adjudicate(
            &ctx(&m, 1, BeaconPhase::Setup, 50),
            &make_complaint(0, 1, None)
        ),
        Err(AdjudicateError::NoDeal)
    );
    e.submit_deal(
        &ctx(&m, 0, BeaconPhase::Setup, 10),
        &make_deal(0, 1, None, false),
    )
    .unwrap();
    assert_eq!(
        e.adjudicate(
            &ctx(&m, 1, BeaconPhase::Setup, 50),
            &make_complaint(0, 1, None)
        ),
        Err(AdjudicateError::NoRecipientKey)
    );
}

// ---------------------------------------------------------------------------
// QUAL determination (draft §4.2)
// ---------------------------------------------------------------------------

#[test]
fn qual_success_and_safe_halt() {
    let m = membership();
    let mut e = DkgEpoch::new(config());
    for i in 0..4 {
        assert_eq!(
            e.submit_deal(
                &ctx(&m, i, BeaconPhase::Setup, 10),
                &make_deal(i, 0, None, false)
            )
            .unwrap(),
            DealOutcome::Accepted
        );
    }
    match e.finalize() {
        DkgOutcome::Success { qual, .. } => assert_eq!(qual, vec![0, 1, 2, 3]),
        other => panic!("expected success, got {other:?}"),
    }
    e.disqualify_for_test(3);
    assert!(matches!(e.finalize(), DkgOutcome::Success { qual, .. } if qual == vec![0, 1, 2]));
    e.disqualify_for_test(2);
    assert_eq!(
        e.finalize(),
        DkgOutcome::SafeHalt {
            qualified: 2,
            required: 3
        }
    );
}

// ---------------------------------------------------------------------------
// End-to-end: DKG success → signing round + chained rounds + reorg
// ---------------------------------------------------------------------------

fn honest_qualified_epoch() -> (QualifiedEpoch, Vec<SecretScalar>) {
    let m = membership();
    let mut e = DkgEpoch::new(config());
    for i in 0..3 {
        for j in 0..3 {
            assert_eq!(
                e.submit_deal(
                    &ctx(&m, i, BeaconPhase::Setup, 10),
                    &make_deal(i, j, None, false)
                )
                .unwrap(),
                DealOutcome::Accepted
            );
        }
    }
    let (qual, group_key) = match e.finalize() {
        DkgOutcome::Success { qual, group_key } => (qual, group_key),
        other => panic!("expected success, got {other:?}"),
    };
    assert_eq!(qual, vec![0, 1, 2]);
    let qc = e.qualified_commitments().unwrap();
    let qe = QualifiedEpoch::new(
        CHAIN_ID,
        EPOCH,
        BeaconParams::proposed_default(),
        group_key,
        qc,
    );

    let mut sks = Vec::new();
    for j in 0..3u32 {
        let x_j = (j as u64) + 1;
        let mut sk_j: Option<SecretScalar> = None;
        for i in 0..3u32 {
            let s =
                SecretScalar::from_bytes_le(&eval_share_le(&dealer_coeffs(i)[..], x_j).unwrap())
                    .unwrap();
            sk_j = Some(match sk_j {
                None => s,
                Some(acc) => acc.add(&s),
            });
        }
        sks.push(sk_j.unwrap());
    }
    (qe, sks)
}

#[test]
fn signing_vk_derivation_matches_shares() {
    let (qe, sks) = honest_qualified_epoch();
    for (j, sk_j) in sks.iter().enumerate() {
        assert_eq!(qe.participant_vk(j as u32).unwrap(), sk_j.public_key());
    }
}

#[test]
fn chained_rounds_progress_and_reorg_restore() {
    let m = membership();
    let (qe, sks) = honest_qualified_epoch();
    let genesis = genesis_seed(CHAIN_ID, &[0x11; 32]);
    let mut chain = BeaconChain::new(qe.clone(), genesis);

    // --- Round 0 ---
    let m0 = chain.round_message(0).unwrap();
    let sctx = |j: u32| ctx(&m, j, BeaconPhase::Signing, 300);
    let partials0: Vec<BeaconPartialV1> = (0..3u32)
        .map(|j| BeaconPartialV1 {
            chain_id: CHAIN_ID,
            epoch: EPOCH,
            round: 0,
            j,
            sigma_j: sks[j as usize].sign(&m0).to_compressed(),
        })
        .collect();
    for (j, p) in partials0.iter().enumerate() {
        assert_eq!(
            chain.accept_partial(&sctx(j as u32), p).unwrap(),
            PartialOutcome::Accepted
        );
    }
    // Replay is a no-op.
    assert_eq!(
        chain.accept_partial(&sctx(0), &partials0[0]).unwrap(),
        PartialOutcome::Replay
    );

    let sigma0 = qe.combine_round(&partials0, &m0).unwrap();
    let fin0 = BeaconFinalizeV1 {
        chain_id: CHAIN_ID,
        epoch: EPOCH,
        round: 0,
        sigma_r: sigma0.to_compressed(),
        witness: vec![0, 1],
    };
    let out0: FinalizeOutcome = chain.finalize_round(&sctx(0), &fin0).unwrap();
    assert_eq!(out0.round, 0);
    assert_eq!(chain.next_round(), 1);

    // Non-monotonic: re-finalizing round 0 rejects.
    assert!(matches!(
        chain.finalize_round(&sctx(0), &fin0),
        Err(RoundError::AlreadyFinalized { round: 0 })
    ));

    // --- Round 1 (chained on Σ_0) ---
    let m1 = chain.round_message(1).unwrap();
    assert_ne!(m0, m1, "round messages differ (chaining §12)");
    let partials1: Vec<BeaconPartialV1> = (0..3u32)
        .map(|j| BeaconPartialV1 {
            chain_id: CHAIN_ID,
            epoch: EPOCH,
            round: 1,
            j,
            sigma_j: sks[j as usize].sign(&m1).to_compressed(),
        })
        .collect();
    for (j, p) in partials1.iter().enumerate() {
        assert_eq!(
            chain.accept_partial(&sctx(j as u32), p).unwrap(),
            PartialOutcome::Accepted
        );
    }
    let sigma1 = qe.combine_round(&partials1, &m1).unwrap();
    let fin1 = BeaconFinalizeV1 {
        chain_id: CHAIN_ID,
        epoch: EPOCH,
        round: 1,
        sigma_r: sigma1.to_compressed(),
        witness: vec![0, 1],
    };
    let out1 = chain.finalize_round(&sctx(0), &fin1).unwrap();
    assert_ne!(
        out0.output, out1.output,
        "beacon outputs differ across rounds (replay separation)"
    );

    // Cannot skip a round (round 3 while next is 2).
    let mut fin_skip = fin1.clone();
    fin_skip.round = 3;
    assert!(matches!(
        chain.finalize_round(&sctx(0), &fin_skip),
        Err(RoundError::NonMonotonic {
            expected: 2,
            got: 3
        })
    ));

    // --- Reorg: revert everything after round 0, then restore round 1 from Σ_1 ---
    chain.revert_after(Some(0));
    assert_eq!(chain.next_round(), 1, "reverted to just after round 0");
    assert!(chain.finalized(1).is_none());
    let restored = chain.restore_finalized(1, &sigma1).unwrap();
    assert_eq!(
        restored.output, out1.output,
        "restored output matches the winning history"
    );
    assert_eq!(chain.finalized(1).unwrap().output, out1.output);
}

#[test]
fn finalize_negatives() {
    let m = membership();
    let (qe, sks) = honest_qualified_epoch();
    let genesis = genesis_seed(CHAIN_ID, &[0x11; 32]);
    let m0 = round_message(
        CHAIN_ID,
        EPOCH,
        0,
        &crate::wire::ChainInput::GenesisSeed(genesis),
    );
    let sctx = ctx(&m, 0, BeaconPhase::Signing, 300);

    let partials: Vec<BeaconPartialV1> = (0..3u32)
        .map(|j| BeaconPartialV1 {
            chain_id: CHAIN_ID,
            epoch: EPOCH,
            round: 0,
            j,
            sigma_j: sks[j as usize].sign(&m0).to_compressed(),
        })
        .collect();
    let sigma_r = qe.combine_round(&partials, &m0).unwrap();
    let base = BeaconFinalizeV1 {
        chain_id: CHAIN_ID,
        epoch: EPOCH,
        round: 0,
        sigma_r: sigma_r.to_compressed(),
        witness: vec![0, 1],
    };
    // Honest finalize verifies.
    qe.verify_finalize(&sctx, &base, &m0).unwrap();

    // Witness not exactly T.
    let mut short = base.clone();
    short.witness = vec![0];
    assert_eq!(
        qe.verify_finalize(&sctx, &short, &m0),
        Err(FinalizeError::WitnessNotExactlyT)
    );

    // Witness not ascending.
    let mut unsorted = base.clone();
    unsorted.witness = vec![1, 0];
    assert_eq!(
        qe.verify_finalize(&sctx, &unsorted, &m0),
        Err(FinalizeError::WitnessNotCanonical)
    );

    // Witness index out of range.
    let mut oor = base.clone();
    oor.witness = vec![0, 99];
    assert_eq!(
        qe.verify_finalize(&sctx, &oor, &m0),
        Err(FinalizeError::WitnessIndexOutOfRange)
    );

    // Tampered Sigma_r.
    let mut bad = base.clone();
    bad.sigma_r[10] ^= 0x01;
    assert!(matches!(
        qe.verify_finalize(&sctx, &bad, &m0),
        Err(FinalizeError::InvalidSignature) | Err(FinalizeError::SignatureInvalid)
    ));

    // Wrong message.
    let m1 = round_message(
        CHAIN_ID,
        EPOCH,
        1,
        &crate::wire::ChainInput::Previous(&sigma_r),
    );
    assert_eq!(
        qe.verify_finalize(&sctx, &base, &m1),
        Err(FinalizeError::SignatureInvalid)
    );
}

#[test]
fn combine_rejects_insufficient_valid_partials() {
    let (qe, sks) = honest_qualified_epoch();
    let genesis = genesis_seed(CHAIN_ID, &[0x22; 32]);
    let m0 = round_message(
        CHAIN_ID,
        EPOCH,
        0,
        &crate::wire::ChainInput::GenesisSeed(genesis),
    );
    let good = BeaconPartialV1 {
        chain_id: CHAIN_ID,
        epoch: EPOCH,
        round: 0,
        j: 0,
        sigma_j: sks[0].sign(&m0).to_compressed(),
    };
    let wrong_msg = round_message(
        CHAIN_ID,
        EPOCH,
        99,
        &crate::wire::ChainInput::GenesisSeed(genesis),
    );
    let bad = BeaconPartialV1 {
        chain_id: CHAIN_ID,
        epoch: EPOCH,
        round: 0,
        j: 1,
        sigma_j: sks[1].sign(&wrong_msg).to_compressed(),
    };
    assert!(qe.combine_round(&[good, bad], &m0).is_err());
}

// ---------------------------------------------------------------------------
// Beacon chaining primitives + validate_operation (executor entry point)
// ---------------------------------------------------------------------------

#[test]
fn beacon_output_deterministic() {
    let (qe, sks) = honest_qualified_epoch();
    let genesis = genesis_seed(CHAIN_ID, &[0x11; 32]);
    let m0 = round_message(
        CHAIN_ID,
        EPOCH,
        0,
        &crate::wire::ChainInput::GenesisSeed(genesis),
    );
    let partials: Vec<BeaconPartialV1> = (0..2u32)
        .map(|j| BeaconPartialV1 {
            chain_id: CHAIN_ID,
            epoch: EPOCH,
            round: 0,
            j,
            sigma_j: sks[j as usize].sign(&m0).to_compressed(),
        })
        .collect();
    let sigma_r = qe.combine_round(&partials, &m0).unwrap();
    assert_eq!(
        beacon_output(CHAIN_ID, EPOCH, 0, &sigma_r),
        beacon_output(CHAIN_ID, EPOCH, 0, &sigma_r)
    );
}

#[test]
fn validate_operation_setup_and_negatives() {
    let params = BeaconParams::proposed_default();
    // A well-formed registration validates (real PoP pairing check).
    let reg = BeaconOperation::RegisterBeaconKey(make_reg(0));
    assert!(validate_operation(&params, &reg).is_ok());

    // A registration with a wrong PoP fails the pairing check.
    let mut bad = make_reg(0);
    bad.pop = ek_secret(2).pop_prove().to_compressed();
    assert_eq!(
        validate_operation(&params, &BeaconOperation::RegisterBeaconKey(bad)),
        Err(ValidationError::PopInvalid)
    );

    // A deal with the wrong commitment count is rejected.
    let mut d = make_deal(0, 1, None, false);
    d.commitments.push(d.commitments[0]);
    assert_eq!(
        validate_operation(&params, &BeaconOperation::DkgDeal(d)),
        Err(ValidationError::CommitmentCountMismatch)
    );

    // A finalize with an out-of-range witness index is rejected.
    let f = BeaconFinalizeV1 {
        chain_id: CHAIN_ID,
        epoch: EPOCH,
        round: 0,
        sigma_r: {
            let mut s = [0u8; 96];
            s[0] = 0x80;
            s
        },
        witness: vec![0, 99],
    };
    assert_eq!(
        validate_operation(&params, &BeaconOperation::BeaconFinalize(f)),
        Err(ValidationError::WitnessIndexOutOfRange)
    );
}

#[test]
fn params_default_is_self_consistent() {
    let p = BeaconParams::proposed_default();
    assert_eq!((p.t(), p.q_dkg(), p.n()), (2, 3, 5));
}
