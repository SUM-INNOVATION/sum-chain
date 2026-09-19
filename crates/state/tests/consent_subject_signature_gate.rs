//! `healthcare_consent_subject_signature_enabled_from_height`: the person a
//! disclosure authorization is ABOUT has to agree to it.
//!
//! `docs/lane-a/ACTIVATION-AUDIT.md` row AU-3, the GRANT half — the half the
//! audit files as **BLOCKED, STRUCTURAL**, on the reasoning that "a subject
//! cannot participate in granting without a signature `ConsentEnvelope` does
//! not carry". That is true about the ENVELOPE and it is why the repair is a
//! wire change; it is not a reason to leave the arm reachable. The revocation
//! half is already remedied under
//! `healthcare_authorization_enabled_from_height`, so without this gate a
//! subject can withdraw a consent they were never asked to give.
//!
//! # Why a signature in the payload, and not a sender check
//!
//! The cheap repair — require the SUBJECT to send the transaction — was written
//! out and rejected on what it costs. `issuer_address` would then be
//! unverified, and anybody could record a consent attributing a disclosure to
//! an issuer who had nothing to do with it: a false claim about the subject
//! traded for a false claim about the issuer. A `SignedTransaction` carries
//! exactly one signature and `validate_tx` checks it against `from`, so NO
//! sender check can make a two-party record out of a one-party transaction. The
//! second party's agreement has to be IN the payload.
//!
//! So at and above the gate the payload is a `ConsentGrantRequest`: the
//! envelope, the subject's ed25519 public key, and the subject's signature over
//! `ConsentEnvelope::grant_signing_input`. The issuer check is unchanged, so an
//! accepted `GrantConsent` carries BOTH parties — the issuer signs the
//! transaction, the subject signs the consent.
//!
//! # Why a wrapper rather than two more fields on the envelope
//!
//! `ConsentEnvelope` is what this subsystem STORES and what `healthcare_store`
//! encodes. Appending to it would change what an already-written encoding
//! decodes to on disk. The wrapper versions only the TRANSACTION payload: below
//! the gate a bare envelope, at and above it the request, and each side fails
//! to decode the other rather than silently reinterpreting it — which is the
//! first of the three refusals below.
//!
//! # Isolation
//!
//! Every pair is `{ consent_subject_signature: …, ..CLOSED }` and never
//! `HealthcareGates::OPEN`: `OPEN` also opens this subsystem's authorization,
//! timestamp, proof and allocation rules, and a pair that differs in five ways
//! cannot attribute a difference to one of them.

mod common;

use common::{fund, setup_with_params};
use sumchain_crypto::{sign, KeyPair};
use sumchain_genesis::ChainParams;
use sumchain_primitives::agreement::PartyRef;
use sumchain_primitives::healthcare::{
    ConsentEnvelope, ConsentGrantRequest, ConsentStatus, ConsentType, DisclosureScope,
    HealthcareIssuerClass, HealthcareOperation, HealthcareTxData,
};
use sumchain_primitives::{Address, Hash};
use sumchain_state::{
    HealthcareExecutor, HealthcareGates, StateManager, CONSENT_GRANT_REQUEST_REQUIRED,
    CONSENT_SUBJECT_KEY_MISMATCH, CONSENT_SUBJECT_SIGNATURE_INVALID,
};
use sumchain_storage::exec_view::ExecutionView;
use sumchain_storage::overlay::ApplicationOverlay;

fn params() -> ChainParams {
    ChainParams::with_v2_enabled()
}

const NOW: u64 = 5_000;

/// `[CLOSED, this gate and only this gate]`.
fn pair() -> [HealthcareGates; 2] {
    [
        HealthcareGates::CLOSED,
        HealthcareGates {
            consent_subject_signature: true,
            ..HealthcareGates::CLOSED
        },
    ]
}

/// A HIPAA authorization about `subject`, issued by `issuer`.
///
/// `scope` is a parameter because one of the tests below moves a signature
/// between two consents that differ ONLY in what they disclose, which is the
/// case a signing input that bound too little would let through.
fn consent(id: u8, issuer: Address, subject: Address, scope: DisclosureScope) -> ConsentEnvelope {
    ConsentEnvelope {
        consent_id: [id; 32],
        consent_type: ConsentType::HipaaAuthorization,
        consent_commitment: [id.wrapping_add(1); 32],
        subject_ref: PartyRef::Commitment([id.wrapping_add(2); 32]),
        subject_address: subject,
        subject_nullifier: [0x91; 32],
        recipient_ref: PartyRef::Commitment([id.wrapping_add(3); 32]),
        purpose_commitment: [id.wrapping_add(4); 32],
        scope,
        scope_commitment: None,
        effective_from: 0,
        expiry: Some(9_000_000),
        issuer_address: issuer,
        issuer_class: HealthcareIssuerClass::MedicalPractice,
        policy_id: [12u8; 32],
        revocation_ref: None,
        status: ConsentStatus::Granted,
        created_at: 1_000,
        updated_at: 1_000,
        recorded_at_height: 1,
        supersedes: None,
        attachments: vec![],
    }
}

/// The payload a compliant client builds at the gate: the subject's own
/// signature over the digest the envelope determines.
fn signed_by(subject: &KeyPair, envelope: &ConsentEnvelope) -> ConsentGrantRequest {
    ConsentGrantRequest {
        envelope: envelope.clone(),
        subject_public_key: *subject.public_key().as_bytes(),
        subject_signature: *sign(&envelope.grant_signing_input(), subject.private_key()).as_bytes(),
    }
}

/// Run one `GrantConsent` and report `(success, charged, error)`.
fn grant(
    view: &mut ExecutionView<'_, '_>,
    sender: &Address,
    payload: Vec<u8>,
    gates: HealthcareGates,
) -> (bool, bool, Option<String>) {
    let before = StateManager::v_get_nonce(view, sender).unwrap();
    let r = HealthcareExecutor::execute_with_gates(
        view,
        sender,
        &HealthcareTxData {
            operation: HealthcareOperation::GrantConsent,
            data: payload,
            recipient: Address::ZERO,
        },
        &Address::new([9; 20]),
        100,
        1,
        NOW,
        0,
        Hash::ZERO,
        gates,
    )
    .unwrap();
    let after = StateManager::v_get_nonce(view, sender).unwrap();
    (r.success, after > before, r.error)
}

/// The disagreement itself: a bare envelope records a disclosure about somebody
/// who never participated, until the gate.
#[test]
fn a_consent_is_granted_without_the_subject_below_the_gate_and_not_above_it() {
    for gates in pair() {
        let (_state, db, _dir, _executor) = setup_with_params(params());
        let issuer = KeyPair::generate();
        let subject = KeyPair::generate();
        fund(&db, &issuer, 100_000_000);
        let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
        let mut view = ExecutionView::new(&mut overlay);

        let envelope = consent(
            0x40,
            issuer.address(),
            subject.address(),
            DisclosureScope::TreatmentOnly,
        );
        let bare = grant(
            &mut view,
            &issuer.address(),
            bincode::serialize(&envelope).unwrap(),
            gates,
        );

        if gates.consent_subject_signature {
            assert!(
                !bare.0,
                "at the gate a consent the subject never signed is refused"
            );
            assert_eq!(
                bare.2.as_deref(),
                Some(CONSENT_GRANT_REQUEST_REQUIRED),
                "and the reason is a CLIENT-VERSION fact: the payload shape \
                 changed, and saying so is what tells an un-upgraded client \
                 apart from a bad signature"
            );
            assert!(
                !bare.1,
                "refused ahead of the deduct, where this arm's own issuer and \
                 duplicate refusals return"
            );
            assert!(
                HealthcareExecutor::v_get_consent(&view, &[0x40u8; 32])
                    .unwrap()
                    .is_none(),
                "and nothing was recorded about the subject"
            );

            // The same consent, now carrying the subject's agreement, is
            // accepted -- so the gate requires a second party rather than
            // closing the operation.
            let signed = grant(
                &mut view,
                &issuer.address(),
                bincode::serialize(&signed_by(&subject, &envelope)).unwrap(),
                gates,
            );
            assert!(signed.0, "and the signed grant IS accepted: {:?}", signed.2);
            assert!(signed.1, "and is charged for, like any accepted grant");
            assert_eq!(
                HealthcareExecutor::v_get_consent(&view, &[0x40u8; 32])
                    .unwrap()
                    .unwrap()
                    .subject_address,
                subject.address(),
                "and the stored row is the envelope verbatim -- the wrapper is \
                 a payload, not a new stored shape"
            );
        } else {
            assert!(
                bare.0,
                "below the gate the issuer alone records a disclosure \
                 authorization about a person who was never asked"
            );
            assert!(bare.1);
            assert!(HealthcareExecutor::v_get_consent(&view, &[0x40u8; 32])
                .unwrap()
                .is_some());
        }
    }
}

/// A signature from SOMEBODY is not a signature from the SUBJECT.
///
/// Without the key-derives-to-`subject_address` check the signature would prove
/// only that the payload was signed by whoever the issuer chose to name in it,
/// which is not a check at all. The refusal is its own reason so a client can
/// tell "I signed with the wrong key" from "my signature is corrupt".
#[test]
fn a_consent_signed_by_a_key_that_is_not_the_subjects_is_refused() {
    let gates = HealthcareGates {
        consent_subject_signature: true,
        ..HealthcareGates::CLOSED
    };
    let (_state, db, _dir, _executor) = setup_with_params(params());
    let issuer = KeyPair::generate();
    let subject = KeyPair::generate();
    let impostor = KeyPair::generate();
    fund(&db, &issuer, 100_000_000);
    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);

    let envelope = consent(
        0x41,
        issuer.address(),
        subject.address(),
        DisclosureScope::TreatmentOnly,
    );

    // A perfectly valid signature -- over the right digest, by the wrong
    // person. Nothing about the SIGNATURE is wrong here; the key is.
    let forged = signed_by(&impostor, &envelope);
    let r = grant(
        &mut view,
        &issuer.address(),
        bincode::serialize(&forged).unwrap(),
        gates,
    );
    assert!(
        !r.0,
        "a stranger's signature does not stand in for the subject"
    );
    assert_eq!(r.2.as_deref(), Some(CONSENT_SUBJECT_KEY_MISMATCH));
    assert!(!r.1, "and the refusal costs nothing");
    assert!(HealthcareExecutor::v_get_consent(&view, &[0x41u8; 32])
        .unwrap()
        .is_none());

    // And the same request with the signature bytes corrupted fails the OTHER
    // way, which is what makes the two reasons worth having separately.
    let mut corrupt = signed_by(&subject, &envelope);
    corrupt.subject_signature[0] ^= 0xff;
    let r = grant(
        &mut view,
        &issuer.address(),
        bincode::serialize(&corrupt).unwrap(),
        gates,
    );
    assert!(!r.0);
    assert_eq!(r.2.as_deref(), Some(CONSENT_SUBJECT_SIGNATURE_INVALID));
    assert!(!r.1);
}

/// A signature agreeing to ONE disclosure does not agree to a wider one.
///
/// The two envelopes differ in exactly one field — `scope`, `TreatmentOnly`
/// against `AllRecords` — and share everything else including the consent id.
/// If `grant_signing_input` bound only the id, or only the parties, the
/// signature would carry and the subject would be recorded as having agreed to
/// disclose their whole record.
#[test]
fn a_subject_signature_does_not_carry_to_a_wider_disclosure() {
    let gates = HealthcareGates {
        consent_subject_signature: true,
        ..HealthcareGates::CLOSED
    };
    let (_state, db, _dir, _executor) = setup_with_params(params());
    let issuer = KeyPair::generate();
    let subject = KeyPair::generate();
    fund(&db, &issuer, 100_000_000);
    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);

    let agreed = consent(
        0x42,
        issuer.address(),
        subject.address(),
        DisclosureScope::TreatmentOnly,
    );
    let wider = consent(
        0x42,
        issuer.address(),
        subject.address(),
        DisclosureScope::AllRecords,
    );
    assert_ne!(
        agreed.grant_signing_input(),
        wider.grant_signing_input(),
        "the signing input must distinguish two consents that differ only in \
         what they disclose -- otherwise the signature is over the wrong thing"
    );

    let moved = ConsentGrantRequest {
        envelope: wider,
        ..signed_by(&subject, &agreed)
    };
    let r = grant(
        &mut view,
        &issuer.address(),
        bincode::serialize(&moved).unwrap(),
        gates,
    );
    assert!(!r.0, "the signature does not verify over the wider consent");
    assert_eq!(r.2.as_deref(), Some(CONSENT_SUBJECT_SIGNATURE_INVALID));
    assert!(!r.1);
    assert!(HealthcareExecutor::v_get_consent(&view, &[0x42u8; 32])
        .unwrap()
        .is_none());
}

/// The gate ADDS a party; it does not move the one that was already checked.
///
/// A subject-signed grant sent by somebody who is not the envelope's issuer is
/// still refused by the issuer check that was there before, so an accepted
/// `GrantConsent` at this height carries two parties rather than a different
/// one.
#[test]
fn the_issuer_must_still_be_the_sender_at_the_gate() {
    let gates = HealthcareGates {
        consent_subject_signature: true,
        ..HealthcareGates::CLOSED
    };
    let (_state, db, _dir, _executor) = setup_with_params(params());
    let issuer = KeyPair::generate();
    let subject = KeyPair::generate();
    let stranger = KeyPair::generate();
    fund(&db, &stranger, 100_000_000);
    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);

    let envelope = consent(
        0x43,
        issuer.address(),
        subject.address(),
        DisclosureScope::TreatmentOnly,
    );
    let r = grant(
        &mut view,
        &stranger.address(),
        bincode::serialize(&signed_by(&subject, &envelope)).unwrap(),
        gates,
    );
    assert!(
        !r.0,
        "the subject's agreement does not let a stranger issue the consent"
    );
    assert_eq!(r.2.as_deref(), Some("Issuer must be sender"));
    assert!(!r.1);
}

/// This gate alone narrows the door; it does not shut it.
///
/// `SupersedeConsent` carries a replacement `ConsentEnvelope` and is not gated
/// here. With `authorization` still closed it checks NOTHING about the sender
/// (ACTIVATION-AUDIT row AU-1), so a stranger supersedes any consent that
/// exists with a replacement naming any subject they like — which mints exactly
/// the record `GrantConsent` has just been stopped from minting.
///
/// Asserted rather than left as a caveat in a doc comment, because the
/// guarantee this gate makes is conditional on another gate being open, and a
/// conditional guarantee that is only written down is one an operator can
/// activate half of. Both halves are run here: `consent_subject_signature`
/// alone, and the two together.
#[test]
fn the_grant_gate_alone_does_not_close_supersession() {
    #[derive(serde::Serialize)]
    struct Supersede {
        old_consent_id: [u8; 32],
        new_consent: ConsentEnvelope,
    }

    for authorization in [false, true] {
        let gates = HealthcareGates {
            consent_subject_signature: true,
            authorization,
            ..HealthcareGates::CLOSED
        };
        let (_state, db, _dir, _executor) = setup_with_params(params());
        let issuer = KeyPair::generate();
        let subject = KeyPair::generate();
        let stranger = KeyPair::generate();
        fund(&db, &issuer, 100_000_000);
        fund(&db, &stranger, 100_000_000);
        let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
        let mut view = ExecutionView::new(&mut overlay);

        // A consent the subject really did agree to, granted through the gate.
        let original = consent(
            0x44,
            issuer.address(),
            subject.address(),
            DisclosureScope::TreatmentOnly,
        );
        assert!(
            grant(
                &mut view,
                &issuer.address(),
                bincode::serialize(&signed_by(&subject, &original)).unwrap(),
                gates,
            )
            .0
        );

        // The stranger's replacement: their own issuer address, a subject who
        // has signed nothing, and the widest scope there is.
        let victim = Address::new([0xFE; 20]);
        let replacement = consent(
            0x45,
            stranger.address(),
            victim,
            DisclosureScope::AllRecords,
        );
        let r = HealthcareExecutor::execute_with_gates(
            &mut view,
            &stranger.address(),
            &HealthcareTxData {
                operation: HealthcareOperation::SupersedeConsent,
                data: bincode::serialize(&Supersede {
                    old_consent_id: original.consent_id,
                    new_consent: replacement.clone(),
                })
                .unwrap(),
                recipient: Address::ZERO,
            },
            &Address::new([9; 20]),
            100,
            1,
            NOW,
            0,
            Hash::ZERO,
            gates,
        )
        .unwrap();

        let minted = HealthcareExecutor::v_get_consent(&view, &replacement.consent_id).unwrap();
        if authorization {
            assert!(
                !r.success,
                "with BOTH gates open a stranger cannot supersede, so there is \
                 no second way to record a consent about somebody who never \
                 agreed"
            );
            assert!(minted.is_none(), "and nothing was written about them");
        } else {
            assert!(
                r.success,
                "with only this gate open, supersession is still the unguarded \
                 arm AU-1 describes -- this is the residual, asserted rather \
                 than hoped about"
            );
            assert_eq!(
                minted.unwrap().subject_address,
                victim,
                "and it records a disclosure about a subject who signed nothing, \
                 which is what `healthcare_authorization_enabled_from_height` \
                 has to be open to prevent"
            );
        }
    }
}
