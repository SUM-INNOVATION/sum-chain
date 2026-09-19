//! Four gates that make a structurally incomplete operation REFUSE.
//!
//! `docs/lane-a/ACTIVATION-AUDIT.md` rows AU-9, AU-10, AU-11 (Agreement),
//! AU-18 and AU-21 (Tax and Finance issuer registration), AU-32 (Property
//! `SubmitProof`) and RY-1 (NFT royalties). Every one of them is filed
//! **BLOCKED, STRUCTURAL**: the defect cannot be closed by a guard, because the
//! subsystem has nothing to authorize against or nothing to compute from.
//!
//! What is new here is not a guard. It is the observation that "blocked" has
//! been taken to mean "leave it reachable", and that the two are different
//! things. An operation that cannot be performed correctly must REFUSE; it may
//! not proceed on a guess. So each of these arms returns a FAILED receipt whose
//! reason says the operation is UNSUPPORTED, and says it BEFORE the fee deduct,
//! which is where each subsystem's own existing refusals return.
//!
//! # What was refused rather than invented, arm by arm
//!
//!   * **Agreement (AU-9/10/11).** `AgreementCommitment` carries no address at
//!     all and `PartyRef` is a 32-byte commitment or a 32-byte subject id, so
//!     there is nothing to compare a sender to; verifying the stored
//!     `signature` would need a canonical signing input this subsystem does not
//!     define. Both repairs are wire changes. An executor that picked a mapping
//!     from `PartyRef` to `Address` would be enforcing a rule nobody set.
//!   * **Tax and Finance (AU-18/21).** The registry authorizes nothing it does
//!     not take from the applicant: `address == sender` plus "not already
//!     registered", with the CLASS and the STATUS straight from the payload.
//!     Closing it needs a REGISTRAR, and no `ChainParams` field names one for
//!     either subsystem, nothing in `genesis.json` seeds either registry, and
//!     no governance path in this tree writes to them. Inventing a registrar
//!     inside an executor would be a rule nobody set, and deciding WHICH
//!     classes may self-assert would be the same invention in a smaller font.
//!   * **Property (AU-32).** `PropertyProofEnvelope` carries no issuer address
//!     and Property has no issuer registry at all. Neither an address in the
//!     payload nor a registry to check one against.
//!   * **NFT (RY-1).** No transfer on this chain carries consideration for a
//!     royalty to be a fraction of, and no execution path moves a balance on a
//!     transfer. Paying one is a protocol — a two-sided order, a listing or an
//!     escrowed bid — not a field.
//!
//! # The shape every test here has
//!
//! One `#[test]` per subsystem, run over a PAIR of gate configurations that
//! differ in exactly one decision, spelled `{ <the gate>: true, ..CLOSED }`
//! rather than `OPEN`. `OPEN` also opens that subsystem's authorization,
//! timestamp and allocation rules, and a pair differing in three ways cannot
//! attribute a difference to one of them.
//!
//! Each asserts all three of: the two nodes DISAGREE about the same
//! transaction; the gated refusal costs nothing (the nonce does not advance,
//! because the refusal is ahead of the deduct); and the arms the gate
//! deliberately leaves reachable are untouched by it.

mod common;

use common::{fund, setup_with_params};
use sumchain_crypto::KeyPair;
use sumchain_genesis::ChainParams;
use sumchain_nft::ops::CreateCollectionData;
use sumchain_nft::CollectionConfig;
use sumchain_primitives::agreement::{
    AgreementCommitment, AgreementOperation, AgreementRole, AgreementStatus, AgreementTxData,
    PartyBinding, PartyRef, PartySignature, SignatureType,
};
use sumchain_primitives::finance::{
    FinanceIssuerClass, FinanceIssuerProfile, FinanceIssuerStatus, FinanceOperation, FinanceTxData,
};
use sumchain_primitives::property::{
    PropertyOperation, PropertyProofEnvelope, PropertyProofProfile, PropertyProofType,
    PropertyTxData,
};
use sumchain_primitives::tax::{
    TaxIssuer, TaxIssuerClass, TaxIssuerStatus, TaxOperation, TaxTxData,
};
use sumchain_primitives::transaction::{NftOperation, NftTxData};
use sumchain_primitives::{Address, Hash};
use sumchain_state::{
    AgreementExecutor, AgreementGates, FinanceExecutor, FinanceGates, NftExecutor, NftGates,
    PropertyExecutor, PropertyGates, StateManager, TaxExecutor, TaxGates,
    AGREEMENT_PARTY_AUTHORITY_UNSUPPORTED, ISSUER_SELF_REGISTRATION_UNSUPPORTED,
    PROPERTY_PROOF_SUBMISSION_UNSUPPORTED, UNPAYABLE_ROYALTY_UNSUPPORTED,
};
use sumchain_storage::exec_view::ExecutionView;
use sumchain_storage::overlay::ApplicationOverlay;

fn params() -> ChainParams {
    ChainParams::with_v2_enabled()
}

/// The block timestamp every case executes at.
const NOW: u64 = 5_000;

// ── Agreement — AU-9, AU-10, AU-11 ──────────────────────────────────────────

/// Every arm the gate refuses, in the order the executor's own `match` lists
/// them.
///
/// Fourteen. Eleven come from the three audit rows directly. `UpdateAgreement`
/// is here although AU-11 does not name it: it writes an `AgreementStatus`
/// taken straight from the payload over any agreement, so it REACHES
/// `Terminated`, `Voided` and `Superseded` — the three states AU-11 is about —
/// and a gate that closed the arms the row names while leaving this one open
/// would close nothing. `RevokeSignature` is here for the matching reason on
/// AU-9's side: authorizing the writing of a signature while leaving any sender
/// able to delete one is not an authorization rule. `SupersedeAgreement` is
/// named by AU-11 itself.
const NEEDS_A_PARTY: [AgreementOperation; 14] = [
    AgreementOperation::UpdateAgreement,
    AgreementOperation::TerminateAgreement,
    AgreementOperation::VoidAgreement,
    AgreementOperation::SupersedeAgreement,
    AgreementOperation::SignAgreement,
    AgreementOperation::RevokeSignature,
    AgreementOperation::UpdateIpAction,
    AgreementOperation::TerminateIpAction,
    AgreementOperation::RevokeIpAction,
    AgreementOperation::ActivateExecutor,
    AgreementOperation::PauseExecutor,
    AgreementOperation::ResumeExecutor,
    AgreementOperation::TerminateExecutor,
    AgreementOperation::CompleteExecutor,
];

/// The arms the gate deliberately leaves reachable, and why each is left.
///
/// `CommitAgreement`, `RecordIpAction` and `LinkExecutor` CREATE a row under an
/// id of the sender's choosing and harm nothing that exists. The three
/// attestation arms already check `issuer_address == sender`, which is the
/// guard the rest of the subsystem is missing and the reason this defect is
/// specific rather than architectural. `AddParty` and `RemoveParty` change no
/// party at all — they are OV-30, and `subsystem_no_op_receipt_...` is the gate
/// that makes them say so. The two proof arms are Class 5's, refused under
/// `subsystem_proof_unsupported_...`.
///
/// So the family is not stranded: an agreement can still be recorded. What it
/// can no longer do is CHANGE, which is the half that today any stranger can
/// do.
const LEFT_REACHABLE: [AgreementOperation; 10] = [
    AgreementOperation::CommitAgreement,
    AgreementOperation::AddParty,
    AgreementOperation::RemoveParty,
    AgreementOperation::CreateAttestation,
    AgreementOperation::RevokeAttestation,
    AgreementOperation::UpdateAttestationStatus,
    AgreementOperation::RecordIpAction,
    AgreementOperation::LinkExecutor,
    AgreementOperation::SubmitProof,
    AgreementOperation::VerifyProof,
];

fn agreement_pair() -> [AgreementGates; 2] {
    [
        AgreementGates::CLOSED,
        AgreementGates {
            party_authority_unsupported: true,
            ..AgreementGates::CLOSED
        },
    ]
}

fn party(commitment: u8, role: AgreementRole) -> PartyBinding {
    PartyBinding {
        party_ref: PartyRef::Commitment([commitment; 32]),
        role,
        signed: false,
        signed_at: None,
    }
}

fn two_party_agreement(id: u8) -> AgreementCommitment {
    AgreementCommitment {
        agreement_id: [id; 32],
        agreement_commitment: [id.wrapping_add(1); 32],
        parties: vec![
            party(0xA1, AgreementRole::Buyer),
            party(0xB2, AgreementRole::Seller),
        ],
        jurisdiction_code: "US-DE".to_string(),
        effective_from: Some(1000),
        expiry: Some(9_000_000),
        attachments: vec![],
        policy_id: [12u8; 32],
        status: AgreementStatus::PendingSignatures,
        created_at: 1000,
        updated_at: 1000,
        created_at_height: 1,
        supersedes: None,
    }
}

fn signature_for(agreement_id: u8, commitment: u8, sig_id: u8) -> PartySignature {
    PartySignature {
        signature_id: [sig_id; 32],
        agreement_id: [agreement_id; 32],
        party_ref: PartyRef::Commitment([commitment; 32]),
        role: AgreementRole::Buyer,
        signature_type: SignatureType::Single,
        // The bytes AU-10 is about: stored, and checked against nothing.
        signature: vec![9u8; 64],
        signer_key: [commitment; 32],
        signed_at: 1000,
        recorded_at_height: 1,
        witness_attestation_id: None,
    }
}

/// AU-9 and AU-11 as a behavioural disagreement: a stranger signs for a party
/// they are not, and terminates an agreement that is not theirs.
///
/// Below the gate both succeed — and the signing one carries the agreement to
/// `Executed`, which is the consequence AU-9 states. Above the gate both are
/// FAILED receipts, the agreement is untouched, and neither costs the stranger
/// a nonce.
#[test]
fn a_stranger_signs_and_terminates_below_the_gate_and_neither_above_it() {
    for gates in agreement_pair() {
        let (_state, db, _dir, _executor) = setup_with_params(params());
        let owner = KeyPair::generate();
        let stranger = KeyPair::generate();
        fund(&db, &owner, 100_000_000);
        fund(&db, &stranger, 100_000_000);
        let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
        let mut view = ExecutionView::new(&mut overlay);

        let run = |view: &mut ExecutionView<'_, '_>,
                   sender: &Address,
                   op: AgreementOperation,
                   payload: Vec<u8>| {
            let before = StateManager::v_get_nonce(view, sender).unwrap();
            let r = AgreementExecutor::execute_with_gates(
                view,
                sender,
                &AgreementTxData {
                    operation: op,
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
        };

        // Recording an agreement is reachable under BOTH gates. The gate takes
        // away the ability to CHANGE one, not the ability to record one.
        assert!(
            run(
                &mut view,
                &owner.address(),
                AgreementOperation::CommitAgreement,
                bincode::serialize(&two_party_agreement(0x51)).unwrap(),
            )
            .0,
            "CommitAgreement is outside the gate and must succeed on both sides"
        );

        // AU-9: the stranger signs as 0xA1, a party they have no relationship
        // to. Nothing in the payload is an address, which is exactly why the
        // executor cannot check this and must refuse instead.
        let signed = run(
            &mut view,
            &stranger.address(),
            AgreementOperation::SignAgreement,
            bincode::serialize(&signature_for(0x51, 0xA1, 0xC1)).unwrap(),
        );

        // AU-11: and terminates the agreement outright.
        let terminated = run(
            &mut view,
            &stranger.address(),
            AgreementOperation::TerminateAgreement,
            bincode::serialize(&[0x51u8; 32]).unwrap(),
        );

        let row = AgreementExecutor::v_get_agreement(&view, &[0x51u8; 32])
            .unwrap()
            .unwrap();

        if gates.party_authority_unsupported {
            for (what, outcome) in [("sign", &signed), ("terminate", &terminated)] {
                assert!(!outcome.0, "{what}: at the gate a stranger is refused");
                assert!(
                    !outcome.1,
                    "{what}: and the refusal is ahead of the deduct, where this \
                     executor's other refusals return, so it costs nothing"
                );
                assert_eq!(
                    outcome.2.as_deref(),
                    Some(AGREEMENT_PARTY_AUTHORITY_UNSUPPORTED),
                    "{what}: the reason must say UNSUPPORTED. \"not authorized\" \
                     would be a claim about the SENDER, and would imply some \
                     other sender would have been authorized -- none would be"
                );
            }
            assert_eq!(
                row.status,
                AgreementStatus::PendingSignatures,
                "and the agreement is untouched"
            );
            assert!(
                row.parties.iter().all(|p| !p.signed),
                "with no party's flag flipped"
            );
            assert!(
                AgreementExecutor::v_get_signature(&view, &[0xC1u8; 32])
                    .unwrap()
                    .is_none(),
                "and no signature row written"
            );
        } else {
            assert!(signed.0, "below the gate any sender signs for any party");
            assert!(terminated.0, "and terminates anything");
            assert!(signed.1 && terminated.1, "and is charged for both");
            assert_eq!(
                row.status,
                AgreementStatus::Terminated,
                "below the gate a stranger's termination lands"
            );
            assert!(
                AgreementExecutor::v_get_signature(&view, &[0xC1u8; 32])
                    .unwrap()
                    .is_some(),
                "and AU-10's unverified signature bytes are stored"
            );
        }
    }
}

/// All fourteen arms refuse, and the ten outside the gate do not.
///
/// Driven with an EMPTY payload on purpose. Every gated arm must refuse ahead
/// of the decode as well as ahead of the deduct, so an undecodable payload for
/// a gated arm is a FAILED receipt rather than the `Err(..)` that takes the
/// whole block with it. The ten outside the gate show the contrast: with the
/// same empty payload they reach their own decode and fail there, which is what
/// proves the gate is the thing being observed and not the payload.
#[test]
fn every_agreement_arm_that_needs_a_party_refuses_and_only_those() {
    for gates in agreement_pair() {
        let (_state, db, _dir, _executor) = setup_with_params(params());
        let actor = KeyPair::generate();
        fund(&db, &actor, 100_000_000);
        let sender = actor.address();
        let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
        let mut view = ExecutionView::new(&mut overlay);

        for op in NEEDS_A_PARTY.into_iter().chain(LEFT_REACHABLE) {
            let gated = NEEDS_A_PARTY.contains(&op);
            let before = StateManager::v_get_nonce(&view, &sender).unwrap();
            let outcome = AgreementExecutor::execute_with_gates(
                &mut view,
                &sender,
                &AgreementTxData {
                    operation: op,
                    data: Vec::new(),
                    recipient: Address::ZERO,
                },
                &Address::new([9; 20]),
                100,
                1,
                NOW,
                0,
                Hash::ZERO,
                gates,
            );
            let refused_here = matches!(
                &outcome,
                Ok(r) if r.error.as_deref() == Some(AGREEMENT_PARTY_AUTHORITY_UNSUPPORTED)
            );
            assert_eq!(
                refused_here,
                gated && gates.party_authority_unsupported,
                "{op:?}: the gate must refuse exactly the fourteen arms that \
                 need a party's authority, and only when it is open"
            );
            if refused_here {
                assert_eq!(
                    StateManager::v_get_nonce(&view, &sender).unwrap(),
                    before,
                    "{op:?}: refused ahead of the deduct"
                );
            }
        }
    }
}

// ── Tax and Finance — AU-18 and AU-21 ───────────────────────────────────────

/// AU-18: a `TaxAuthority` registers itself, until the gate.
#[test]
fn a_tax_authority_registers_itself_below_the_gate_and_not_above_it() {
    for gates in [
        TaxGates::CLOSED,
        TaxGates {
            issuer_self_registration_unsupported: true,
            ..TaxGates::CLOSED
        },
    ] {
        let (_state, db, _dir, _executor) = setup_with_params(params());
        let actor = KeyPair::generate();
        fund(&db, &actor, 100_000_000);
        let sender = actor.address();
        let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
        let mut view = ExecutionView::new(&mut overlay);

        // The applicant's own payload: the class and the status are both
        // whatever it typed, and `TaxAuthority` is a plain variant.
        let issuer = TaxIssuer {
            address: sender,
            tax_class: TaxIssuerClass::TaxAuthority,
            jurisdictions: vec!["US".to_string()],
            attributes_hash: [0u8; 32],
            attributes_schema_hash: [0u8; 32],
            registered_at: 1_000,
            updated_at: 1_000,
            status: TaxIssuerStatus::Active,
            expires_at: None,
        };
        let before = StateManager::v_get_nonce(&view, &sender).unwrap();
        let r = TaxExecutor::execute_with_gates(
            &mut view,
            &sender,
            &TaxTxData {
                operation: TaxOperation::RegisterIssuer,
                data: bincode::serialize(&issuer).unwrap(),
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
        let charged = StateManager::v_get_nonce(&view, &sender).unwrap() > before;

        if gates.issuer_self_registration_unsupported {
            assert!(!r.success, "at the gate self-registration is refused");
            assert_eq!(
                r.error.as_deref(),
                Some(ISSUER_SELF_REGISTRATION_UNSUPPORTED),
                "and the reason names the missing REGISTRAR, not the request"
            );
            assert!(!charged, "refused ahead of the deduct");
            assert!(
                TaxExecutor::v_get_issuer(&view, &sender).unwrap().is_none(),
                "and nothing was written to the registry every other \
                 authorization rule in this subsystem resolves against"
            );
        } else {
            assert!(r.success, "below the gate anyone becomes a TaxAuthority");
            assert!(charged);
            assert_eq!(
                TaxExecutor::v_get_issuer(&view, &sender)
                    .unwrap()
                    .unwrap()
                    .tax_class,
                TaxIssuerClass::TaxAuthority,
                "with the class it chose for itself"
            );
        }
    }
}

/// AU-21: the same rule in Finance, up to `CentralBank`.
///
/// One field for both subsystems, so this test and the Tax one above are two
/// readings of one decision. An operator who could close one and not the other
/// would be shipping a chain in which "the registry authorizes registrations"
/// was true in Finance and false in Tax.
#[test]
fn a_central_bank_registers_itself_below_the_gate_and_not_above_it() {
    for gates in [
        FinanceGates::CLOSED,
        FinanceGates {
            issuer_self_registration_unsupported: true,
            ..FinanceGates::CLOSED
        },
    ] {
        let (_state, db, _dir, _executor) = setup_with_params(params());
        let actor = KeyPair::generate();
        fund(&db, &actor, 100_000_000);
        let sender = actor.address();
        let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
        let mut view = ExecutionView::new(&mut overlay);

        let profile = FinanceIssuerProfile {
            issuer_address: sender,
            issuer_class: FinanceIssuerClass::CentralBank,
            issuer_commitment: [2u8; 32],
            jurisdiction_code: "US".to_string(),
            policy_id: [3u8; 32],
            status: FinanceIssuerStatus::Active,
            registered_at_height: 1,
            created_at: 1_000,
            updated_at: 1_000,
        };
        let before = StateManager::v_get_nonce(&view, &sender).unwrap();
        let r = FinanceExecutor::execute_with_gates(
            &mut view,
            &sender,
            &FinanceTxData {
                operation: FinanceOperation::RegisterIssuer,
                data: bincode::serialize(&profile).unwrap(),
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
        let charged = StateManager::v_get_nonce(&view, &sender).unwrap() > before;

        if gates.issuer_self_registration_unsupported {
            assert!(!r.success, "at the gate self-registration is refused");
            assert_eq!(
                r.error.as_deref(),
                Some(ISSUER_SELF_REGISTRATION_UNSUPPORTED),
                "and it is the SAME reason Tax gives, from the same constant"
            );
            assert!(!charged, "refused ahead of the deduct");
            assert!(
                FinanceExecutor::v_get_issuer(&view, &sender)
                    .unwrap()
                    .is_none(),
                "and no issuer row exists"
            );
        } else {
            assert!(r.success, "below the gate anyone becomes a CentralBank");
            assert!(charged);
            assert_eq!(
                FinanceExecutor::v_get_issuer(&view, &sender)
                    .unwrap()
                    .unwrap()
                    .issuer_class,
                FinanceIssuerClass::CentralBank,
                "with the class it chose for itself"
            );
        }
    }
}

// ── Property — AU-32 ────────────────────────────────────────────────────────

/// AU-32: any funded account writes any row into the Property proof family,
/// about any subject it names — until the gate.
///
/// `proof_submission_unsupported` alone, and NOT
/// `subsystem_proof_unsupported_...`, because these are two different rules
/// about two different arms: that one is about a verifier this tree does not
/// have, this one about an issuer this subsystem does not record. A reader of
/// either receipt has to be able to tell which claim was refused.
#[test]
fn a_stranger_submits_a_property_proof_below_the_gate_and_not_above_it() {
    for gates in [
        PropertyGates::CLOSED,
        PropertyGates {
            proof_submission_unsupported: true,
            ..PropertyGates::CLOSED
        },
    ] {
        let (_state, db, _dir, _executor) = setup_with_params(params());
        let actor = KeyPair::generate();
        fund(&db, &actor, 100_000_000);
        let sender = actor.address();
        let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
        let mut view = ExecutionView::new(&mut overlay);

        let envelope = PropertyProofEnvelope {
            proof_id: [0xD1; 32],
            profile: PropertyProofProfile::OwnershipProof,
            profile_id: "property.ownership.v1".to_string(),
            policy_ids: vec![[0xE1; 32]],
            public_inputs: vec![1, 2, 3],
            proof_data: Vec::new(),
            proof_type: PropertyProofType::Groth16,
            // Whoever the sender decided to name. There is no field on this
            // envelope that says who ISSUED it.
            subject_nullifier: [0xE2; 32],
            generated_at: 1_000,
            expires_at: 9_000_000,
        };
        let before = StateManager::v_get_nonce(&view, &sender).unwrap();
        let r = PropertyExecutor::execute_with_gates(
            &mut view,
            &sender,
            &PropertyTxData {
                operation: PropertyOperation::SubmitProof,
                data: bincode::serialize(&envelope).unwrap(),
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
        let charged = StateManager::v_get_nonce(&view, &sender).unwrap() > before;
        let stored = PropertyExecutor::v_property_proof_exists(&view, &[0xD1u8; 32]).unwrap();

        if gates.proof_submission_unsupported {
            assert!(!r.success, "at the gate the submission is refused");
            assert_eq!(
                r.error.as_deref(),
                Some(PROPERTY_PROOF_SUBMISSION_UNSUPPORTED),
                "and the reason names the SUBMISSION as unsupported rather than \
                 the proof as invalid -- the proof is not what is wrong"
            );
            assert!(
                !charged,
                "refused ahead of the deduct, where this arm's own duplicate-id \
                 refusal returns"
            );
            assert!(!stored, "and no row was written");
        } else {
            assert!(
                r.success,
                "below the gate the only guard is a duplicate id, so this lands"
            );
            assert!(charged);
            assert!(stored, "and the unauthenticated row is in the proof family");
        }
    }
}

// ── NFT — RY-1 ──────────────────────────────────────────────────────────────

fn create_collection(name: &str, royalty_bps: u16, recipient: Address) -> CreateCollectionData {
    CreateCollectionData {
        name: name.to_string(),
        symbol: "ROY".to_string(),
        description: "d".to_string(),
        config: CollectionConfig {
            royalty_bps,
            royalty_recipient: recipient,
            ..Default::default()
        },
        base_uri: None,
    }
}

/// RY-1: a collection records a royalty the chain has no code to pay, until the
/// gate — and a collection that asks for none is unaffected by it.
///
/// The gate closes the CLAIM, not the payment. Refusing it strands nothing: no
/// royalty has ever been paid on this chain, so no collection loses income it
/// was receiving, and the field is publicly readable over `nft_getCollection`,
/// which is how a marketplace comes to be told a royalty exists that will never
/// be paid.
#[test]
fn a_collection_records_an_unpayable_royalty_below_the_gate_and_not_above_it() {
    for gates in [
        NftGates::CLOSED,
        NftGates {
            unpayable_royalty_refused: true,
            ..NftGates::CLOSED
        },
    ] {
        let (_state, db, _dir, _executor) = setup_with_params(params());
        let actor = KeyPair::generate();
        fund(&db, &actor, 100_000_000);
        let sender = actor.address();
        let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
        let mut view = ExecutionView::new(&mut overlay);
        let p = params();

        let run = |view: &mut ExecutionView<'_, '_>, data: CreateCollectionData| {
            NftExecutor::execute_with_gates(
                view,
                &p,
                &sender,
                &NftTxData {
                    collection_id: [0u8; 32],
                    token_id: 0,
                    operation: NftOperation::CreateCollection,
                    data: bincode::serialize(&data).unwrap(),
                },
                &Address::new([9; 20]),
                100,
                NOW,
                gates,
            )
            .unwrap()
        };

        let with_royalty = run(
            &mut view,
            create_collection("Royalties", 500, Address::new([0x77; 20])),
        );
        if gates.unpayable_royalty_refused {
            assert!(
                !with_royalty.success,
                "at the gate a royalty the chain cannot pay is refused"
            );
            assert_eq!(
                with_royalty.error.as_deref(),
                Some(UNPAYABLE_ROYALTY_UNSUPPORTED),
                "and the reason names ROYALTY ENFORCEMENT as unsupported, not \
                 the number as invalid -- 500 bps is a well-formed number"
            );
            assert!(
                with_royalty.collection_id.is_none(),
                "and a refused creation consumes no collection id"
            );
        } else {
            assert!(
                with_royalty.success,
                "below the gate the promise is recorded"
            );
            let id = with_royalty.collection_id.unwrap();
            assert_eq!(
                NftExecutor::v_get_collection(&view, &id)
                    .unwrap()
                    .unwrap()
                    .royalty_bps,
                500,
                "and is readable back -- which is what `nft_getCollection` \
                 publishes to a marketplace"
            );
        }

        // A collection asking for NO royalty is created under both gates. The
        // gate takes no capability from a creator who was not being promised
        // one.
        // A DIFFERENT name, because a collection id is
        // `(sender, name, clock)` below `nft_collection_id_nonce_...` and two
        // creations at one timestamp would otherwise collide on the id rather
        // than on the royalty — which is CI-1, not RY-1.
        let without = run(&mut view, create_collection("Plain", 0, Address::ZERO));
        assert!(
            without.success,
            "a zero-royalty collection is created on both sides of the gate"
        );
    }
}
