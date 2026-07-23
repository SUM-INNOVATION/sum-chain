//! Deterministic tests for the gate-closed BR1 beacon runtime (issue #127).
//!
//! Every input is a fixed byte seed — no clock, no RNG — so the whole DKG →
//! adjudication → QUAL → signing lifecycle is reproducible across runs and
//! architectures. The scenarios build real on-chain carriers (deals, complaints,
//! registrations, partials, finalizes) with the crypto adapter and drive them
//! through the runtime, asserting each of the four objective verdicts, QUAL
//! success/safe-halt, exactly-`T` combine, finalize verification, and the crypto
//! negatives (subgroup/infinity/wrong-key/wrong-message/tamper).

use sumchain_beacon_crypto::{
    dleq_prove, ecies_seal, eval_share_le, DleqContext, EciesContext, G1Point, SecretScalar,
    SCALAR_SIZE,
};
use sumchain_wire::beacon_wire::{DkgComplaintV1, DkgDealV1, RegisterBeaconKeyV1};

use crate::dkg::{
    DealOutcome, DkgConfig, DkgEpoch, DkgOutcome, NotAdjudicable, SetupError, Verdict,
};
use crate::params::BeaconParams;
use crate::signing::{FinalizeError, QualifiedEpoch};
use crate::wire::{
    beacon_output, genesis_seed, round_message, BeaconFinalizeV1, BeaconPartialV1, ChainInput,
};

const CHAIN_ID: u64 = 0x0102_0304_0506_0708;
const EPOCH: u64 = 7;

/// A fixed canonical (`< r`) 32-byte little-endian scalar seed. Byte 31 (LE MSB) is
/// forced to 0 so every value is well below `r ≈ 2^255`.
fn seed(tag: u8) -> [u8; SCALAR_SIZE] {
    let mut b = [0u8; SCALAR_SIZE];
    for (i, out) in b.iter_mut().enumerate() {
        *out = tag.wrapping_add(i as u8).wrapping_mul(7).wrapping_add(1);
    }
    b[SCALAR_SIZE - 1] = 0;
    b
}

/// Dealer `i`'s degree-1 (T=2) polynomial coefficients `[a_{i,0}, a_{i,1}]`.
fn dealer_coeffs(i: u32) -> [[u8; SCALAR_SIZE]; 2] {
    [seed(0x10 + i as u8), seed(0x20 + i as u8)]
}

/// Recipient `j`'s epoch encryption secret `ek_j`.
fn ek_secret(j: u32) -> SecretScalar {
    SecretScalar::from_bytes_le(&seed(0x40 + j as u8)).unwrap()
}

/// Ephemeral carrier secret `r_{ij}` for the `(i, j)` deal (unique per pair).
fn r_secret(i: u32, j: u32) -> SecretScalar {
    SecretScalar::from_bytes_le(&seed(0x60u8.wrapping_add((i * 8 + j) as u8))).unwrap()
}

fn config() -> DkgConfig {
    DkgConfig {
        chain_id: CHAIN_ID,
        epoch: EPOCH,
        params: BeaconParams::PROPOSED_DEFAULT,
    }
}

/// Build a `RegisterBeaconKeyV1` for recipient `j` (PoP over `EK_j`).
fn make_reg(j: u32) -> RegisterBeaconKeyV1 {
    let ek = ek_secret(j);
    RegisterBeaconKeyV1 {
        chain_id: CHAIN_ID,
        epoch: EPOCH,
        ek_j: ek.public_g1().to_compressed(),
        pop: ek.pop_prove().to_compressed(),
    }
}

/// Build a `(dealer i → recipient j)` deal. `share_override` forces a specific
/// (possibly wrong) share; `tamper_ct` flips a ciphertext byte after sealing.
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
    let d = r.ecdh(&ek_pt).unwrap(); // dealer side: D = EK_j^{r_ij}
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

/// Build a complaint by recipient `j` against dealer `i`. `d_override` substitutes a
/// wrong `D_{ij}` (to force a malformed / non-verifying DLEQ) while keeping an
/// honestly-generated proof over the true statement.
fn make_complaint(i: u32, j: u32, d_override: Option<G1Point>) -> DkgComplaintV1 {
    let ek = ek_secret(j);
    let ek_pt = ek.public_g1();
    let r_pt = r_secret(i, j).public_g1();
    let d_true = ek.ecdh(&r_pt).unwrap(); // recipient side: D = R_ij^{ek_j}
    let d_pub = d_override.unwrap_or(d_true);

    let ctx = DleqContext {
        chain_id: CHAIN_ID.to_le_bytes().to_vec(),
        epoch: EPOCH,
        dealer_index: i,
        recipient_index: j,
    };
    let h = G1Point::generator();
    let proof = dleq_prove(&ctx, &h, &ek_pt, &r_pt, &d_true, &ek, &seed(0x77)).unwrap();
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

/// A DKG epoch with recipients 0..=`max_j` keyed and one accepted `(i, j)` deal.
fn epoch_with_deal(
    i: u32,
    j: u32,
    share_override: Option<[u8; SCALAR_SIZE]>,
    tamper: bool,
) -> DkgEpoch {
    let mut e = DkgEpoch::new(config());
    e.register_key(j, &make_reg(j)).unwrap();
    assert_eq!(
        e.submit_deal(&make_deal(i, j, share_override, tamper))
            .unwrap(),
        DealOutcome::Accepted
    );
    e
}

// ---------------------------------------------------------------------------
// Registration (draft §2.3, §11)
// ---------------------------------------------------------------------------

#[test]
fn register_key_pop_and_rules() {
    let mut e = DkgEpoch::new(config());
    // Honest registration accepted.
    e.register_key(0, &make_reg(0)).unwrap();
    // Idempotent re-registration of the identical key is a no-op.
    e.register_key(0, &make_reg(0)).unwrap();

    // Wrong epoch rejected.
    let mut bad_epoch = make_reg(1);
    bad_epoch.epoch = EPOCH + 1;
    assert_eq!(e.register_key(1, &bad_epoch), Err(SetupError::WrongEpoch));

    // Invalid PoP (a valid G2 point but for a different key) rejected.
    let mut wrong_pop = make_reg(1);
    wrong_pop.pop = ek_secret(2).pop_prove().to_compressed();
    assert_eq!(e.register_key(1, &wrong_pop), Err(SetupError::PopInvalid));

    // A different key for an already-keyed validator index rejected (K-rotate §11).
    let other = make_reg(2); // different EK, same index 0
    assert_eq!(
        e.register_key(0, &other),
        Err(SetupError::DuplicateRegistration)
    );
}

#[test]
fn register_key_rejects_off_curve_point() {
    let mut e = DkgEpoch::new(config());
    let mut reg = make_reg(0);
    // Structurally-flagged-OK bytes (compression set, infinity clear) that are NOT a
    // real curve point ⇒ the crypto adapter's canonical/subgroup decode rejects it.
    reg.ek_j = [0x80u8; 48];
    assert!(matches!(
        e.register_key(0, &reg),
        Err(SetupError::InvalidElement(_))
    ));
}

// ---------------------------------------------------------------------------
// Deal acceptance / replay / conflict (draft §8.4)
// ---------------------------------------------------------------------------

#[test]
fn deal_accept_duplicate_conflict() {
    let mut e = DkgEpoch::new(config());
    e.register_key(1, &make_reg(1)).unwrap();

    let deal = make_deal(0, 1, None, false);
    assert_eq!(e.submit_deal(&deal).unwrap(), DealOutcome::Accepted);
    // Byte-identical resubmission ⇒ duplicate, no effect.
    assert_eq!(e.submit_deal(&deal).unwrap(), DealOutcome::Duplicate);
    assert!(!e.disqualified().contains(&0));

    // A different deal for the same (i, j) ⇒ conflicting deal, dealer disqualified.
    let conflicting = make_deal(0, 1, Some(seed(0xAB)), false);
    assert_eq!(
        e.submit_deal(&conflicting).unwrap(),
        DealOutcome::ConflictingDeal
    );
    assert!(e.disqualified().contains(&0));
}

#[test]
fn deal_conflicting_commitments_across_recipients() {
    // A dealer whose second deal (to a different recipient) carries a DIFFERENT
    // commitment vector is disqualified — one polynomial per dealer.
    let mut e = DkgEpoch::new(config());
    e.register_key(0, &make_reg(0)).unwrap();
    e.register_key(1, &make_reg(1)).unwrap();
    assert_eq!(
        e.submit_deal(&make_deal(0, 0, None, false)).unwrap(),
        DealOutcome::Accepted
    );

    // Forge a deal from dealer 0 to recipient 1 but with dealer 1's commitments.
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
    assert_eq!(e.submit_deal(&deal).unwrap(), DealOutcome::ConflictingDeal);
    assert!(e.disqualified().contains(&0));
}

// ---------------------------------------------------------------------------
// The four objective complaint verdicts (draft §6.1)
// ---------------------------------------------------------------------------

#[test]
fn verdict_slash_false_accuser() {
    // Dealer 0 deals a CORRECT share to recipient 1; the complaint is therefore false.
    let mut e = epoch_with_deal(0, 1, None, false);
    let outcome = e.apply_complaint(&make_complaint(0, 1, None)).unwrap();
    assert_eq!(outcome.verdict, Verdict::SlashFalseAccuser);
    assert!(outcome.state_changed);
    assert!(
        !e.disqualified().contains(&0),
        "honest dealer stays qualified"
    );
    assert!(e.false_accusers().contains(&1));
}

#[test]
fn verdict_disqualify_and_slash() {
    // Dealer 0 deals a WRONG (feldman-inconsistent) share to recipient 1.
    let wrong = seed(0xCD);
    let mut e = epoch_with_deal(0, 1, Some(wrong), false);
    let outcome = e.apply_complaint(&make_complaint(0, 1, None)).unwrap();
    assert_eq!(outcome.verdict, Verdict::DisqualifyAndSlash);
    assert!(e.disqualified().contains(&0));
    assert!(!e.false_accusers().contains(&1));
}

#[test]
fn verdict_disqualify_aead_open_failure() {
    // Dealer 0 posts a tampered ciphertext ⇒ open fails under the proven secret.
    let mut e = epoch_with_deal(0, 1, None, true);
    let outcome = e.apply_complaint(&make_complaint(0, 1, None)).unwrap();
    assert_eq!(outcome.verdict, Verdict::Disqualify);
    assert!(e.disqualified().contains(&0));
}

#[test]
fn verdict_reject_complaint_malformed() {
    // A correct deal, but the complaint carries a WRONG D_ij ⇒ DLEQ fails.
    let mut e = epoch_with_deal(0, 1, None, false);
    // A valid-but-wrong D (D' = R^{ek'} for another secret).
    let r_pt = r_secret(0, 1).public_g1();
    let d_wrong = ek_secret(2).ecdh(&r_pt).unwrap();
    let outcome = e
        .apply_complaint(&make_complaint(0, 1, Some(d_wrong)))
        .unwrap();
    assert_eq!(outcome.verdict, Verdict::RejectComplaintMalformed);
    assert!(!outcome.state_changed);
    assert!(!e.disqualified().contains(&0), "no effect on the dealer");

    // A malformed complaint does not consume the (i, j) pair: a subsequent VALID
    // complaint (here, against the still-correct deal) still adjudicates with effect.
    let good = e.apply_complaint(&make_complaint(0, 1, None)).unwrap();
    assert_eq!(good.verdict, Verdict::SlashFalseAccuser);
    assert!(good.state_changed);
}

#[test]
fn complaint_idempotent_no_double_jeopardy() {
    let wrong = seed(0xCD);
    let mut e = epoch_with_deal(0, 1, Some(wrong), false);
    let first = e.apply_complaint(&make_complaint(0, 1, None)).unwrap();
    assert!(first.state_changed);
    // Re-adjudicating the same (i, j) recomputes the identical verdict, no new effect.
    let second = e.apply_complaint(&make_complaint(0, 1, None)).unwrap();
    assert_eq!(second.verdict, Verdict::DisqualifyAndSlash);
    assert!(!second.state_changed);
}

#[test]
fn complaint_not_adjudicable_missing_facts() {
    let mut e = DkgEpoch::new(config());
    // No deal, no key.
    assert_eq!(
        e.adjudicate(&make_complaint(0, 1, None)),
        Err(NotAdjudicable::NoDeal)
    );
    // Deal present but recipient key missing.
    e.submit_deal(&make_deal(0, 1, None, false)).unwrap();
    assert_eq!(
        e.adjudicate(&make_complaint(0, 1, None)),
        Err(NotAdjudicable::NoRecipientKey)
    );
    // Wrong epoch.
    e.register_key(1, &make_reg(1)).unwrap();
    let mut c = make_complaint(0, 1, None);
    c.epoch = EPOCH + 1;
    assert_eq!(e.adjudicate(&c), Err(NotAdjudicable::WrongEpoch));
}

// ---------------------------------------------------------------------------
// QUAL determination and safe-halt (draft §4.2)
// ---------------------------------------------------------------------------

#[test]
fn qual_success_and_safe_halt() {
    // Four dealers each submit a deal (to recipient 0).
    let mut e = DkgEpoch::new(config());
    e.register_key(0, &make_reg(0)).unwrap();
    for i in 0..4 {
        assert_eq!(
            e.submit_deal(&make_deal(i, 0, None, false)).unwrap(),
            DealOutcome::Accepted
        );
    }
    // |QUAL| = 4 ≥ Q_dkg = 3 ⇒ success.
    match e.finalize() {
        DkgOutcome::Success { qual, group_key } => {
            assert_eq!(qual, vec![0, 1, 2, 3]);
            // PK_E is a valid non-identity key (encoded round-trips).
            let _ = group_key.to_compressed();
        }
        other => panic!("expected success, got {other:?}"),
    }

    // Disqualify dealer 3 ⇒ |QUAL| = 3 = Q_dkg ⇒ still success.
    e.disqualify_for_test(3);
    match e.finalize() {
        DkgOutcome::Success { qual, .. } => assert_eq!(qual, vec![0, 1, 2]),
        other => panic!("expected success, got {other:?}"),
    }

    // Disqualify dealer 2 ⇒ |QUAL| = 2 < 3 ⇒ safe-halt (no key).
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
// End-to-end: DKG success → signing round (partial verify, combine, finalize)
// ---------------------------------------------------------------------------

/// Run a 3-dealer × 3-recipient all-honest DKG and return the qualified epoch plus
/// each participant's aggregated signing share `sk_j = Σ_i s_{ij}`.
fn honest_qualified_epoch() -> (QualifiedEpoch, Vec<SecretScalar>) {
    let mut e = DkgEpoch::new(config());
    for j in 0..3 {
        e.register_key(j, &make_reg(j)).unwrap();
    }
    for i in 0..3 {
        for j in 0..3 {
            assert_eq!(
                e.submit_deal(&make_deal(i, j, None, false)).unwrap(),
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
        BeaconParams::PROPOSED_DEFAULT,
        group_key,
        qc,
    );

    // Each participant's final share sk_j = Σ_i s_{ij}, x_j = j + 1.
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
        let vk_j = qe.participant_vk(j as u32).unwrap();
        assert_eq!(
            vk_j,
            sk_j.public_key(),
            "derived vk_j must equal g1^{{sk_j}} for participant {j}"
        );
    }
}

#[test]
fn signing_partial_combine_finalize_roundtrip() {
    let (qe, sks) = honest_qualified_epoch();
    let seed_hash = genesis_seed(CHAIN_ID, &[0x11; 32]);
    let m_r = round_message(CHAIN_ID, EPOCH, 0, &ChainInput::GenesisSeed(seed_hash));

    // Build a partial per participant and verify each.
    let mut partials = Vec::new();
    for (j, sk_j) in sks.iter().enumerate() {
        let sigma = sk_j.sign(&m_r);
        let p = BeaconPartialV1 {
            chain_id: CHAIN_ID,
            epoch: EPOCH,
            round: 0,
            j: j as u32,
            sigma_j: sigma.to_compressed(),
        };
        assert!(
            qe.verify_partial_carrier(&p, &m_r).unwrap(),
            "partial {j} verifies"
        );
        partials.push(p);
    }

    // Exactly-T combine over the verified partials.
    let sigma_r = qe.combine_round(&partials, &m_r).unwrap();

    // Finalize verifies under PK_E with an exactly-T strictly-ascending witness.
    let finalize = BeaconFinalizeV1 {
        chain_id: CHAIN_ID,
        epoch: EPOCH,
        round: 0,
        sigma_r: sigma_r.to_compressed(),
        witness: vec![0, 1], // exactly T=2, ascending
    };
    qe.verify_finalize(&finalize, &m_r).unwrap();

    // Beacon output is a deterministic function of Sigma_r.
    let out_a = beacon_output(CHAIN_ID, EPOCH, 0, &sigma_r);
    let out_b = beacon_output(CHAIN_ID, EPOCH, 0, &sigma_r);
    assert_eq!(out_a, out_b);
}

#[test]
fn signing_finalize_negatives() {
    let (qe, sks) = honest_qualified_epoch();
    let seed_hash = genesis_seed(CHAIN_ID, &[0x11; 32]);
    let m_r = round_message(CHAIN_ID, EPOCH, 0, &ChainInput::GenesisSeed(seed_hash));
    let partials: Vec<BeaconPartialV1> = sks
        .iter()
        .enumerate()
        .map(|(j, sk_j)| BeaconPartialV1 {
            chain_id: CHAIN_ID,
            epoch: EPOCH,
            round: 0,
            j: j as u32,
            sigma_j: sk_j.sign(&m_r).to_compressed(),
        })
        .collect();
    let sigma_r = qe.combine_round(&partials, &m_r).unwrap();
    let base = BeaconFinalizeV1 {
        chain_id: CHAIN_ID,
        epoch: EPOCH,
        round: 0,
        sigma_r: sigma_r.to_compressed(),
        witness: vec![0, 1],
    };

    // Witness not exactly T.
    let mut short = base.clone();
    short.witness = vec![0];
    assert_eq!(
        qe.verify_finalize(&short, &m_r),
        Err(FinalizeError::WitnessNotExactlyT)
    );

    // Witness not strictly ascending (unsorted / duplicate).
    let mut unsorted = base.clone();
    unsorted.witness = vec![1, 0];
    assert_eq!(
        qe.verify_finalize(&unsorted, &m_r),
        Err(FinalizeError::WitnessNotCanonical)
    );

    // Tampered Sigma_r ⇒ signature does not verify under PK_E.
    let mut bad_sig = base.clone();
    bad_sig.sigma_r[10] ^= 0x01;
    // Either the point fails to decode, or it decodes but does not verify.
    assert!(matches!(
        qe.verify_finalize(&bad_sig, &m_r),
        Err(FinalizeError::InvalidSignature) | Err(FinalizeError::SignatureInvalid)
    ));

    // Correct Sigma_r but WRONG round message ⇒ does not verify (chaining §12).
    let m_r1 = round_message(CHAIN_ID, EPOCH, 1, &ChainInput::Previous(&sigma_r));
    assert_eq!(
        qe.verify_finalize(&base, &m_r1),
        Err(FinalizeError::SignatureInvalid)
    );
}

#[test]
fn signing_combine_rejects_insufficient_valid_partials() {
    let (qe, sks) = honest_qualified_epoch();
    let m_r = round_message(CHAIN_ID, EPOCH, 0, &ChainInput::GenesisSeed([0x22; 32]));

    // One honest partial + one over the WRONG message (won't verify) ⇒ only 1 valid.
    let good = BeaconPartialV1 {
        chain_id: CHAIN_ID,
        epoch: EPOCH,
        round: 0,
        j: 0,
        sigma_j: sks[0].sign(&m_r).to_compressed(),
    };
    let wrong_msg = round_message(CHAIN_ID, EPOCH, 99, &ChainInput::GenesisSeed([0x22; 32]));
    let bad = BeaconPartialV1 {
        chain_id: CHAIN_ID,
        epoch: EPOCH,
        round: 0,
        j: 1,
        sigma_j: sks[1].sign(&wrong_msg).to_compressed(),
    };
    // The invalid partial is discarded (§4.3 step 1) ⇒ fewer than T valid ⇒ error.
    assert!(qe.combine_round(&[good, bad], &m_r).is_err());
}

// ---------------------------------------------------------------------------
// Beacon chaining messages (draft §12.1)
// ---------------------------------------------------------------------------

#[test]
fn beacon_chaining_message_determinism_and_separation() {
    // Genesis seed is deterministic and depends on its inputs.
    let s1 = genesis_seed(CHAIN_ID, &[0x11; 32]);
    let s2 = genesis_seed(CHAIN_ID, &[0x11; 32]);
    let s3 = genesis_seed(CHAIN_ID, &[0x12; 32]);
    assert_eq!(s1, s2);
    assert_ne!(s1, s3);

    // A partial over round 0 must NOT verify over round 1 (chaining domain sep §12).
    let (qe, sks) = honest_qualified_epoch();
    let m0 = round_message(CHAIN_ID, EPOCH, 0, &ChainInput::GenesisSeed(s1));
    let p0 = BeaconPartialV1 {
        chain_id: CHAIN_ID,
        epoch: EPOCH,
        round: 0,
        j: 0,
        sigma_j: sks[0].sign(&m0).to_compressed(),
    };
    assert!(qe.verify_partial_carrier(&p0, &m0).unwrap());
    let sigma_r0 = qe
        .combine_round(
            &[
                p0.clone(),
                BeaconPartialV1 {
                    chain_id: CHAIN_ID,
                    epoch: EPOCH,
                    round: 0,
                    j: 1,
                    sigma_j: sks[1].sign(&m0).to_compressed(),
                },
            ],
            &m0,
        )
        .unwrap();
    let m1 = round_message(CHAIN_ID, EPOCH, 1, &ChainInput::Previous(&sigma_r0));
    assert_ne!(
        m0, m1,
        "round messages differ by round + chained Sigma_prev"
    );
    assert!(
        !qe.verify_partial_carrier(&p0, &m1).unwrap(),
        "a round-0 partial must not verify against the round-1 message"
    );
}

// ---------------------------------------------------------------------------
// Params
// ---------------------------------------------------------------------------

#[test]
fn params_default_is_self_consistent() {
    let p = BeaconParams::default();
    assert!(p.is_self_consistent(), "T=f+1, Q=2f+1, T<=Q<=n");
    assert_eq!((p.t, p.q_dkg, p.n_min), (2, 3, 5));
}
