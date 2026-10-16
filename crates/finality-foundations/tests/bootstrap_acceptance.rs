//! G2-c (ratified 2026-10-16): quorum-signed, sequence-chained bootstrap
//! authorization; and G2-d: no dynamic membership before certified finality.
//!
//! Digests and commitments here are synthetic constants chosen by the tests;
//! they are not a proposal for any authorization or membership encoding.
//! Signatures are real Ed25519 over those synthetic digests.

use ed25519_dalek::Signer as _;
use sumchain_finality_foundations::bootstrap::{
    Acceptance, ApplyError, Authorization, BlockAction, BlockRef, BootstrapState, CanonicalChain,
    Deferral, HaltReason, HandlerId, Hint, HintAssessment, HintNext, IndexedSignature, Membership,
    Refusal, SignatureVerifier,
};
use sumchain_finality_foundations::containment::check_membership_transition;
use sumchain_finality_foundations::Digest;

const GENESIS: Digest = [0x60; 32];
const C0: Digest = [0xC0; 32];
const C1: Digest = [0xC1; 32];
const C2: Digest = [0xC2; 32];
const NOTICE: u64 = 100;

struct Ed25519;

impl SignatureVerifier for Ed25519 {
    fn verify(&self, public_key: &[u8], message: &Digest, signature: &[u8]) -> bool {
        let Ok(pk) = <[u8; 32]>::try_from(public_key) else {
            return false;
        };
        let Ok(vk) = ed25519_dalek::VerifyingKey::from_bytes(&pk) else {
            return false;
        };
        let Ok(sig) = ed25519_dalek::Signature::from_slice(signature) else {
            return false;
        };
        // Strict verification (E1, the approved direction for new finality and
        // upgrade signatures).
        vk.verify_strict(message, &sig).is_ok()
    }
}

struct Chain(Vec<Digest>);

impl Chain {
    fn with_head(head: u64) -> Self {
        Chain((0..=head).map(block_hash).collect())
    }
}

fn block_hash(h: u64) -> Digest {
    let mut d = [0xBB; 32];
    d[..8].copy_from_slice(&h.to_le_bytes());
    d
}

impl CanonicalChain for Chain {
    fn head_height(&self) -> u64 {
        self.0.len() as u64 - 1
    }
    fn canonical_hash(&self, height: u64) -> Option<Digest> {
        self.0.get(height as usize).copied()
    }
}

struct Set {
    keys: Vec<ed25519_dalek::SigningKey>,
    membership: Membership,
}

fn set(tag: u8, n: usize) -> Set {
    let keys: Vec<_> = (0..n)
        .map(|i| ed25519_dalek::SigningKey::from_bytes(&[tag.wrapping_add(i as u8 + 1); 32]))
        .collect();
    let members = keys
        .iter()
        .map(|k| k.verifying_key().to_bytes().to_vec())
        .collect();
    Set {
        keys,
        membership: Membership {
            members,
            commitment: [tag; 32],
        },
    }
}

fn digest(sequence: u64, variant: u8) -> Digest {
    let mut d = [0xD0 ^ variant; 32];
    d[..8].copy_from_slice(&sequence.to_le_bytes());
    d
}

struct Draft {
    sequence: u64,
    previous: Digest,
    old: Digest,
    new: Digest,
    checkpoint: u64,
    deadline: u64,
    activation: u64,
    variant: u8,
}

fn draft(sequence: u64, previous: Digest, old: Digest, new: Digest) -> Draft {
    Draft {
        sequence,
        previous,
        old,
        new,
        checkpoint: 10,
        deadline: 20,
        activation: 200,
        variant: 0,
    }
}

impl Draft {
    fn sign(&self, by: &Set, signers: &[usize]) -> Authorization {
        let body_digest = digest(self.sequence, self.variant);
        Authorization {
            genesis_hash: GENESIS,
            sequence: self.sequence,
            previous_digest: self.previous,
            old_commitment: self.old,
            new_commitment: self.new,
            checkpoint: BlockRef {
                height: self.checkpoint,
                hash: block_hash(self.checkpoint),
            },
            activation_height: self.activation,
            signing_deadline: self.deadline,
            membership_commitment: by.membership.commitment,
            handler: HandlerId([self.sequence as u8; 32]),
            body_digest,
            signatures: signers
                .iter()
                .map(|&i| IndexedSignature {
                    index: i as u32,
                    signature: by.keys[i].sign(&body_digest).to_bytes().to_vec(),
                })
                .collect(),
        }
    }
}

fn state(genesis: &Set) -> BootstrapState {
    BootstrapState::new(GENESIS, genesis.membership.clone(), C0)
}

fn all(n: usize) -> Vec<usize> {
    (0..n).collect()
}

// ── quorum and signature rules ──────────────────────────────────────────────

#[test]
fn g2c_quorum_is_floor_two_thirds_plus_one_distinct_members() {
    for (n, needed) in [(1, 1), (2, 2), (3, 3), (4, 3), (5, 4), (7, 5), (10, 7)] {
        let g = set(0x10, n);
        assert_eq!(g.membership.quorum(), needed, "n = {n}");
        let chain = Chain::with_head(50);
        let mut st = state(&g);
        let short = draft(1, [0; 32], C0, C1).sign(&g, &all(needed - 1));
        assert_eq!(
            st.accept(&short, &Ed25519, &chain, NOTICE),
            Err(Refusal::NoQuorum {
                valid: needed - 1,
                needed
            })
        );
        let enough = draft(1, [0; 32], C0, C1).sign(&g, &all(needed));
        assert!(matches!(
            st.accept(&enough, &Ed25519, &chain, NOTICE),
            Ok(Acceptance::Accepted { .. })
        ));
    }
}

#[test]
fn g2c_signatures_must_be_distinct_ascending_members_and_valid() {
    let g = set(0x10, 4);
    let chain = Chain::with_head(50);
    let mut st = state(&g);
    let base = draft(1, [0; 32], C0, C1);

    let mut dup = base.sign(&g, &[0, 1, 2]);
    dup.signatures[2] = dup.signatures[1].clone();
    assert_eq!(
        st.accept(&dup, &Ed25519, &chain, NOTICE),
        Err(Refusal::NonAscendingIndices)
    );
    let mut desc = base.sign(&g, &[0, 1, 2]);
    desc.signatures.reverse();
    assert_eq!(
        st.accept(&desc, &Ed25519, &chain, NOTICE),
        Err(Refusal::NonAscendingIndices)
    );
    let mut out = base.sign(&g, &[0, 1, 2]);
    out.signatures[2].index = 4;
    assert_eq!(
        st.accept(&out, &Ed25519, &chain, NOTICE),
        Err(Refusal::IndexOutOfRange { index: 4 })
    );
    let outsider = set(0x70, 4);
    let mut forged = base.sign(&g, &[0, 1, 2]);
    forged.signatures[1] = base.sign(&outsider, &[1]).signatures[0].clone();
    assert_eq!(
        st.accept(&forged, &Ed25519, &chain, NOTICE),
        Err(Refusal::BadSignature { index: 1 })
    );
    assert_eq!(st.pending(), None);
}

// ── who authenticates which sequence ────────────────────────────────────────

#[test]
fn g2c_genesis_membership_authenticates_the_first_authorization_only() {
    let g = set(0x10, 4);
    let m2 = set(0x40, 4);
    let chain = Chain::with_head(300);
    let mut st = state(&g);

    let mut first = draft(1, [0; 32], C0, C1);
    first.activation = 250;
    st.accept(
        &first.sign(&g, &all(4)),
        &Ed25519,
        &Chain::with_head(50),
        NOTICE,
    )
    .unwrap();
    // Membership changes need certified finality (G2-d); assume it is active.
    st.on_applied(1, m2.membership.clone(), true).unwrap();

    let mut second = draft(2, digest(1, 0), C1, C2);
    second.checkpoint = 260;
    second.deadline = 270;
    second.activation = 400;
    // Genesis members can no longer authorize.
    assert_eq!(
        st.accept(&second.sign(&g, &all(4)), &Ed25519, &chain, NOTICE),
        Err(Refusal::MembershipMismatch)
    );
    let mut genesis_keys_claiming_m2 = second.sign(&g, &all(4));
    genesis_keys_claiming_m2.membership_commitment = m2.membership.commitment;
    assert_eq!(
        st.accept(&genesis_keys_claiming_m2, &Ed25519, &chain, NOTICE),
        Err(Refusal::BadSignature { index: 0 })
    );
    // The membership recorded by applied history does.
    assert_eq!(
        st.accept(&second.sign(&m2, &all(3)), &Ed25519, &chain, NOTICE),
        Ok(Acceptance::Accepted {
            sequence: 2,
            activation_height: 400
        })
    );
}

#[test]
fn g2c_sequences_chain_onto_applied_history() {
    let g = set(0x10, 4);
    let chain = Chain::with_head(50);
    let mut st = state(&g);
    assert_eq!(
        st.accept(
            &draft(0, [0; 32], C0, C1).sign(&g, &all(4)),
            &Ed25519,
            &chain,
            NOTICE
        ),
        Err(Refusal::BadSequence)
    );
    assert_eq!(
        st.accept(
            &draft(2, digest(1, 0), C1, C2).sign(&g, &all(4)),
            &Ed25519,
            &chain,
            NOTICE
        ),
        Ok(Acceptance::Deferred(Deferral::SequenceAhead {
            expected: 1
        }))
    );
    assert_eq!(
        st.accept(
            &draft(1, [1; 32], C0, C1).sign(&g, &all(4)),
            &Ed25519,
            &chain,
            NOTICE
        ),
        Err(Refusal::BadChaining)
    );
    st.accept(
        &draft(1, [0; 32], C0, C1).sign(&g, &all(4)),
        &Ed25519,
        &chain,
        NOTICE,
    )
    .unwrap();
    st.on_applied(1, g.membership.clone(), false).unwrap();

    let mut wrong_prev = draft(2, digest(1, 9), C1, C2);
    wrong_prev.activation = 300;
    assert_eq!(
        st.accept(&wrong_prev.sign(&g, &all(4)), &Ed25519, &chain, NOTICE),
        Err(Refusal::BadChaining)
    );
    let mut stale_commitment = draft(2, digest(1, 0), C0, C2);
    stale_commitment.activation = 300;
    assert_eq!(
        st.accept(
            &stale_commitment.sign(&g, &all(4)),
            &Ed25519,
            &chain,
            NOTICE
        ),
        Err(Refusal::CommitmentMismatch)
    );
    let mut not_after = draft(2, digest(1, 0), C1, C2);
    not_after.activation = 200; // same H as sequence 1
    assert_eq!(
        st.accept(&not_after.sign(&g, &all(4)), &Ed25519, &chain, NOTICE),
        Err(Refusal::BadOrdering)
    );
    let mut ok = draft(2, digest(1, 0), C1, C2);
    ok.activation = 300;
    assert!(matches!(
        st.accept(&ok.sign(&g, &all(4)), &Ed25519, &chain, NOTICE),
        Ok(Acceptance::Accepted { sequence: 2, .. })
    ));
}

#[test]
fn g2c_chain_identity_ordering_and_checkpoint_are_checked() {
    let g = set(0x10, 4);
    let mut st = state(&g);
    let chain = Chain::with_head(50);

    let mut other_chain = draft(1, [0; 32], C0, C1).sign(&g, &all(4));
    other_chain.genesis_hash = [0x61; 32];
    assert_eq!(
        st.accept(&other_chain, &Ed25519, &chain, NOTICE),
        Err(Refusal::WrongChain)
    );

    let mut d = draft(1, [0; 32], C0, C1);
    d.deadline = d.checkpoint;
    assert_eq!(
        st.accept(&d.sign(&g, &all(4)), &Ed25519, &chain, NOTICE),
        Err(Refusal::BadOrdering)
    );
    let mut d = draft(1, [0; 32], C0, C1);
    d.deadline = d.activation - NOTICE + 1;
    assert_eq!(
        st.accept(&d.sign(&g, &all(4)), &Ed25519, &chain, NOTICE),
        Err(Refusal::BadOrdering)
    );
    let mut d = draft(1, [0; 32], C0, C1);
    d.activation = NOTICE - 1;
    assert_eq!(
        st.accept(&d.sign(&g, &all(4)), &Ed25519, &chain, NOTICE),
        Err(Refusal::BadOrdering)
    );

    let mut ahead = draft(1, [0; 32], C0, C1);
    ahead.checkpoint = 60;
    ahead.deadline = 70;
    assert_eq!(
        st.accept(&ahead.sign(&g, &all(4)), &Ed25519, &chain, NOTICE),
        Ok(Acceptance::Deferred(Deferral::CheckpointAhead {
            checkpoint: 60,
            head: 50
        }))
    );
    let mut off_chain = draft(1, [0; 32], C0, C1).sign(&g, &all(4));
    off_chain.checkpoint.hash = [0xEE; 32];
    assert_eq!(
        st.accept(&off_chain, &Ed25519, &chain, NOTICE),
        Err(Refusal::CheckpointNotCanonical)
    );
    assert_eq!(st.pending(), None);
}

// ── halting and applying ────────────────────────────────────────────────────

#[test]
fn g2c_unknown_handler_halts_before_h_and_a_known_one_runs_once() {
    let g = set(0x10, 4);
    let mut st = state(&g);
    let auth = draft(1, [0; 32], C0, C1).sign(&g, &all(4));
    st.accept(&auth, &Ed25519, &Chain::with_head(50), NOTICE)
        .unwrap();

    assert_eq!(st.block_action(199, |_| false), BlockAction::Proceed);
    assert_eq!(
        st.block_action(200, |_| false),
        BlockAction::Halt(HaltReason::UpgradeNeeded {
            sequence: 1,
            handler: auth.handler.clone()
        })
    );
    assert_eq!(
        st.block_action(200, |h| *h == auth.handler),
        BlockAction::RunHandlerOnce {
            sequence: 1,
            handler: auth.handler.clone()
        }
    );
    st.on_applied(1, g.membership.clone(), false).unwrap();
    assert_eq!(
        st.on_applied(1, g.membership.clone(), false),
        Err(ApplyError::NotPending)
    );
    assert_eq!(st.block_action(200, |_| true), BlockAction::Proceed);
    assert_eq!(st.block_action(201, |_| true), BlockAction::Proceed);
    assert_eq!(st.effective_commitment(), C1);
    // Replay selects rules by height.
    assert_eq!(
        (st.rules_at(199), st.rules_at(200), st.rules_at(10_000)),
        (0, 1, 1)
    );
}

#[test]
fn g2c_hints_never_authorize_or_halt() {
    let g = set(0x10, 4);
    let st = state(&g);
    let before = st.clone();
    for hint in [
        Hint {
            genesis_hash: GENESIS,
            applied_count: 0,
            applied_tip: [0; 32],
            next: Some(HintNext {
                sequence: 1,
                digest: digest(1, 0),
                activation_height: 5,
            }),
        },
        Hint {
            genesis_hash: GENESIS,
            applied_count: 3,
            applied_tip: [0x33; 32],
            next: None,
        },
        Hint {
            genesis_hash: [0x99; 32],
            applied_count: 0,
            applied_tip: [0; 32],
            next: None,
        },
    ] {
        let _ = st.assess_hint(&hint);
        assert_eq!(st, before);
        for h in [0, 5, 6, 1_000] {
            assert_eq!(st.block_action(h, |_| false), BlockAction::Proceed);
        }
    }
    assert_eq!(
        st.local_hint().next,
        None,
        "nothing verified, nothing announced"
    );
}

#[test]
fn g2c_hint_assessment_compares_applied_history() {
    let g = set(0x10, 4);
    let mut st = state(&g);
    let auth = draft(1, [0; 32], C0, C1).sign(&g, &all(4));
    st.accept(&auth, &Ed25519, &Chain::with_head(50), NOTICE)
        .unwrap();
    assert_eq!(
        st.local_hint().next,
        Some(HintNext {
            sequence: 1,
            digest: auth.body_digest,
            activation_height: 200
        })
    );
    st.on_applied(1, g.membership.clone(), false).unwrap();
    let hint = |count, tip| Hint {
        genesis_hash: GENESIS,
        applied_count: count,
        applied_tip: tip,
        next: None,
    };
    assert_eq!(
        st.assess_hint(&hint(1, auth.body_digest)),
        HintAssessment::InSync
    );
    assert_eq!(st.assess_hint(&hint(1, [7; 32])), HintAssessment::Diverged);
    assert_eq!(
        st.assess_hint(&hint(0, [0; 32])),
        HintAssessment::PeerBehind
    );
    assert_eq!(st.assess_hint(&hint(0, [7; 32])), HintAssessment::Diverged);
    assert_eq!(st.assess_hint(&hint(2, [7; 32])), HintAssessment::PeerAhead);
    let mut other = hint(1, auth.body_digest);
    other.genesis_hash = [1; 32];
    assert_eq!(st.assess_hint(&other), HintAssessment::OtherChain);
}

// ── conflicts ───────────────────────────────────────────────────────────────

#[test]
fn g2c_conflict_with_pending_halts_before_the_earlier_h_and_applies_neither() {
    let g = set(0x10, 4);
    let chain = Chain::with_head(50);
    let mut st = state(&g);
    let a = draft(1, [0; 32], C0, C1).sign(&g, &all(4));
    st.accept(&a, &Ed25519, &chain, NOTICE).unwrap();

    let mut db = draft(1, [0; 32], C0, C2);
    db.variant = 1;
    db.activation = 150;
    let b = db.sign(&g, &all(3));
    assert_eq!(
        st.accept(&b, &Ed25519, &chain, NOTICE),
        Ok(Acceptance::Conflict {
            sequence: 1,
            halt_before: 150
        })
    );
    assert_eq!(st.pending(), None, "neither is applied");
    assert_eq!(st.evidence().len(), 1);
    assert_eq!(
        (&st.evidence()[0].first, &st.evidence()[0].second),
        (&a, &b)
    );
    assert_eq!(st.block_action(149, |_| true), BlockAction::Proceed);
    assert_eq!(
        st.block_action(150, |_| true),
        BlockAction::Halt(HaltReason::ConflictingAuthorizations { halt_before: 150 })
    );

    // A third body at the same sequence cannot be scheduled either.
    let mut dc = draft(1, [0; 32], C0, C1);
    dc.variant = 2;
    dc.activation = 500;
    assert!(matches!(
        st.accept(&dc.sign(&g, &all(4)), &Ed25519, &chain, NOTICE),
        Ok(Acceptance::Conflict {
            halt_before: 150,
            ..
        })
    ));
    assert_eq!(st.pending(), None);
    // Re-sending a known side is not new evidence.
    assert_eq!(
        st.accept(&a, &Ed25519, &chain, NOTICE),
        Ok(Acceptance::AlreadyKnown { sequence: 1 })
    );
    assert_eq!(st.evidence().len(), 2);
}

#[test]
fn g2c_conflict_with_applied_history_halts_without_reverting_it() {
    let g = set(0x10, 4);
    let mut st = state(&g);
    let a = draft(1, [0; 32], C0, C1).sign(&g, &all(4));
    st.accept(&a, &Ed25519, &Chain::with_head(50), NOTICE)
        .unwrap();
    st.on_applied(1, g.membership.clone(), false).unwrap();
    let applied = st.applied().to_vec();

    let mut db = draft(1, [0; 32], C0, C2);
    db.variant = 1;
    db.activation = 260;
    let b = db.sign(&g, &all(4));
    assert_eq!(
        st.accept(&b, &Ed25519, &Chain::with_head(230), NOTICE),
        Ok(Acceptance::Conflict {
            sequence: 1,
            halt_before: 200
        })
    );
    assert_eq!(st.applied(), &applied[..], "applied history is untouched");
    assert_eq!(st.effective_commitment(), C1);
    assert_eq!(st.rules_at(230), 1);
    // The next block is already past the earlier H: stop now, roll nothing back.
    assert_eq!(
        st.block_action(231, |_| true),
        BlockAction::Halt(HaltReason::ConflictingAuthorizations { halt_before: 200 })
    );
}

#[test]
fn g2c_unverified_conflict_is_refused_and_does_not_halt() {
    let g = set(0x10, 4);
    let chain = Chain::with_head(50);
    let mut st = state(&g);
    st.accept(
        &draft(1, [0; 32], C0, C1).sign(&g, &all(4)),
        &Ed25519,
        &chain,
        NOTICE,
    )
    .unwrap();
    let mut db = draft(1, [0; 32], C0, C2);
    db.variant = 1;
    db.activation = 150;
    assert!(matches!(
        st.accept(&db.sign(&g, &all(2)), &Ed25519, &chain, NOTICE),
        Err(Refusal::NoQuorum { .. })
    ));
    assert_eq!(st.halt_before(), None);
    assert!(st.evidence().is_empty());
    assert!(st.pending().is_some());
}

// ── late arrival ────────────────────────────────────────────────────────────

#[test]
fn g2c_late_arrival_is_accepted_and_never_invalidates_applied_history() {
    let g = set(0x10, 4);
    let mut st = state(&g);
    let auth = draft(1, [0; 32], C0, C1).sign(&g, &all(4));
    // The local head is far past the signing deadline (20) but below H (200).
    assert_eq!(
        st.accept(&auth, &Ed25519, &Chain::with_head(190), NOTICE),
        Ok(Acceptance::Accepted {
            sequence: 1,
            activation_height: 200
        })
    );
    st.on_applied(1, g.membership.clone(), false).unwrap();
    // Long after the deadline and H, the same authorization is still authentic.
    assert_eq!(
        st.accept(&auth, &Ed25519, &Chain::with_head(10_000), NOTICE),
        Ok(Acceptance::AlreadyKnown { sequence: 1 })
    );
    assert_eq!(st.applied().len(), 1);
}

#[test]
fn g2c_past_activation_halts_without_reverting_the_local_chain() {
    let g = set(0x10, 4);
    let mut st = state(&g);
    let auth = draft(1, [0; 32], C0, C1).sign(&g, &all(4));
    let chain = Chain::with_head(205);
    assert_eq!(
        st.accept(&auth, &Ed25519, &chain, NOTICE),
        Ok(Acceptance::AcceptedPastActivation {
            sequence: 1,
            activation_height: 200
        })
    );
    assert_eq!(
        st.block_action(206, |_| true),
        BlockAction::Halt(HaltReason::MissedActivation {
            sequence: 1,
            activation_height: 200
        })
    );
    assert_eq!(
        chain.head_height(),
        205,
        "acceptance never touches the chain"
    );
}

// ── G2-d ────────────────────────────────────────────────────────────────────

#[test]
fn g2d_membership_change_is_refused_before_certified_finality() {
    let g = set(0x10, 4);
    let m2 = set(0x40, 4);
    let mut st = state(&g);
    st.accept(
        &draft(1, [0; 32], C0, C1).sign(&g, &all(4)),
        &Ed25519,
        &Chain::with_head(50),
        NOTICE,
    )
    .unwrap();
    assert!(matches!(
        st.on_applied(1, m2.membership.clone(), false),
        Err(ApplyError::Containment(_))
    ));
    assert!(
        st.pending().is_some(),
        "a refused application records nothing"
    );
    assert!(st.applied().is_empty());
    st.on_applied(1, g.membership.clone(), false).unwrap();
    assert_eq!(st.applied().len(), 1);
}

#[test]
fn g2d_containment_guard() {
    assert!(check_membership_transition(&C0, &C0, false).is_ok());
    assert!(check_membership_transition(&C0, &C1, false).is_err());
    assert!(check_membership_transition(&C0, &C1, true).is_ok());
}
