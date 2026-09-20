//! Three DocClass activation heights that make an unsafe claim REFUSE.
//!
//! `docs/lane-a/ACTIVATION-AUDIT.md` rows AU-33 (no signature is verified
//! anywhere in DocClass), AU-37 (`max_credential_validity` bounds nothing) and
//! D-19b (the attribute allowlists the schema gate leaves un-extended).
//!
//! All three were filed EXAMINED AND LEFT, and "left" had come to mean "left
//! reachable". The governing rule is that deferred functionality is acceptable
//! and unsafe ambiguity is not, so each of these either states its rule or
//! refuses.
//!
//!   * **AU-33 stays UNSUPPORTED.** Verification was tested against the tree's
//!     OWN convention -- the domain-separated blake3 digest plus ed25519 check
//!     that `healthcare_consent_subject_signature_enabled_from_height` uses --
//!     and DocClass cannot reuse it. That construction verifies a key carried
//!     IN the payload against an address carried IN the payload, over a
//!     canonical fixed-width field set built on the wire type. DocClass carries
//!     `issuer_key_id: String`, a NAME whose resolution against
//!     `DocClassIssuer.keys` no rule states, and its credentials are half
//!     variable-length `String` with no framing convention. So the gate refuses
//!     the CLAIM: a credential asserting a signature nothing can check.
//!   * **AU-37's unit is settled from the code.** The chain's canonical block
//!     timestamp is milliseconds -- `PoaEngine::current_timestamp` uses
//!     `as_millis()` and `BlockHeader::timestamp` documents "(ms since epoch)"
//!     -- and `valid_from`/`expires_at` share that `Timestamp` alias, so the
//!     bound is in milliseconds. That is asserted here as a NUMBER, not as
//!     prose: the same window is accepted under a bound that is large in
//!     milliseconds and refused under one that is not.
//!   * **D-19b invents no allowlist.** It takes the other reading of "no
//!     allowlist exists": every key on a subcode that has none is unclassified,
//!     and an unclassified key fails closed.
//!
//! Every test runs the SAME transaction against the SAME seeded database twice,
//! once with the gate closed and once with it open, and asserts the two nodes
//! DISAGREE. Every gates literal is spelled `..DocClassGates::CLOSED`: `OPEN`
//! would open fourteen gates at once, and a pair differing in fourteen ways
//! cannot attribute a difference to one of them.

mod common;

use common::{fund, setup_with_params};
use sumchain_crypto::KeyPair;
use sumchain_genesis::ChainParams;
use sumchain_primitives::{
    AcademicCredential, Address, CredentialAttribute, CredentialMetadata, DocClassIssuer,
    DocClassIssuerStatus, DocClassIssuerType, DocClassOperation, DocClassTxData, DocSubcode,
    EligibilityAttestation, EligibilityType, Hash, IssuerKey, KeyType, RevocationStatus,
};
use sumchain_state::{
    DocClassExecutionResult, DocClassExecutor, DocClassGates, StateManager,
    DOCCLASS_CREDENTIAL_VALIDITY_TOO_LONG, DOCCLASS_SIGNATURE_UNSUPPORTED,
    DOCCLASS_UNKNOWN_ATTRIBUTE_REFUSED,
};
use sumchain_storage::exec_view::ExecutionView;
use sumchain_storage::overlay::ApplicationOverlay;
use sumchain_storage::{Database, DocClassStore};

const JURISDICTION: &str = "US";
/// Below `SchemaValidatorConfig::default().activation_height` (385,000) on
/// purpose. That is a separate and older switch, and running these at a height
/// above it would let the schema validator refuse a case this gate is supposed
/// to refuse -- which would pass for the wrong reason.
const HEIGHT: u64 = 1_000;

/// One year in MILLISECONDS, the unit the chain's block timestamp uses.
const ONE_YEAR_MS: u64 = 365 * 24 * 60 * 60 * 1_000;

const SIGNATURE: DocClassGates = DocClassGates {
    signature_unsupported: true,
    ..DocClassGates::CLOSED
};
const VALIDITY: DocClassGates = DocClassGates {
    credential_validity_bound: true,
    ..DocClassGates::CLOSED
};
const ATTRIBUTES: DocClassGates = DocClassGates {
    unknown_attribute_refused: true,
    ..DocClassGates::CLOSED
};
const CLOSED: DocClassGates = DocClassGates::CLOSED;

fn params_with_validity(max_credential_validity: u64) -> ChainParams {
    let mut p = ChainParams::with_v2_enabled();
    if let Some(ref mut d) = p.docclass {
        d.min_issuer_stake = 0;
        d.max_credential_validity = max_credential_validity;
    }
    p
}

fn params() -> ChainParams {
    params_with_validity(0)
}

fn issuer_of(
    address: Address,
    issuer_type: DocClassIssuerType,
    subcodes: Vec<DocSubcode>,
) -> DocClassIssuer {
    DocClassIssuer {
        address,
        name: "Institute of Technology".to_string(),
        issuer_type,
        jurisdictions: vec![JURISDICTION.to_string()],
        authorized_subcodes: subcodes,
        keys: vec![IssuerKey {
            key_id: "k-1".to_string(),
            public_key: [0x51; 32],
            key_type: KeyType::Ed25519,
            added_at: 1_000,
            expires_at: 0,
            active: true,
            is_primary: true,
        }],
        registered_at: 1_000,
        updated_at: 1_000,
        status: DocClassIssuerStatus::Active,
        stake_amount: 0,
        metadata: None,
    }
}

/// A credential that asserts NOTHING it cannot back: an all-zero signature, an
/// empty key id, no expiry and no attributes. Every test below starts here and
/// adds exactly the one claim it is about, so a refusal can only be that claim.
fn plain(id: u8, issuer: Address, subcode: DocSubcode) -> AcademicCredential {
    AcademicCredential {
        credential_id: [id; 32],
        subject_address: Address::ZERO,
        subcode,
        subject_commitment: [id.wrapping_add(0x40); 32],
        issuer,
        institution_id: "IOT".to_string(),
        jurisdiction: JURISDICTION.to_string(),
        schema_hash: [0x71; 32],
        content_commitment: [0x72; 32],
        metadata: CredentialMetadata {
            title: "Bachelor of Science".to_string(),
            credential_type: "undergraduate_degree".to_string(),
            program: None,
            issue_date: "2024-05-15".to_string(),
            completion_date: None,
            attributes: vec![],
        },
        issued_at: 1_000,
        valid_from: 1_000,
        expires_at: 0,
        payload_hash: None,
        payload_hint: None,
        encryption_meta: None,
        issuer_signature: [0u8; 64],
        issuer_key_id: String::new(),
        revocation_status: RevocationStatus::Active,
        superseded_by: None,
    }
}

fn plain_attestation(id: u8, issuer: Address) -> EligibilityAttestation {
    EligibilityAttestation {
        credential_id: [id; 32],
        subject_address: Address::ZERO,
        subcode: DocSubcode::EligibilityAttestation,
        subject_commitment: [id.wrapping_add(0x40); 32],
        issuer,
        jurisdiction: JURISDICTION.to_string(),
        eligibility_type: EligibilityType::Citizenship,
        schema_hash: [0x61; 32],
        content_commitment: [0x62; 32],
        issued_at: 1_000,
        valid_from: 1_000,
        expires_at: 0,
        payload_hash: None,
        payload_hint: None,
        encryption_meta: None,
        issuer_signature: [0u8; 64],
        issuer_key_id: String::new(),
        revocation_status: RevocationStatus::Active,
        superseded_by: None,
    }
}

#[allow(clippy::too_many_arguments)]
fn run(
    view: &mut ExecutionView<'_, '_>,
    chain: &ChainParams,
    sender: &Address,
    subcode: DocSubcode,
    payload: &impl serde::Serialize,
    gates: DocClassGates,
) -> DocClassExecutionResult {
    DocClassExecutor::execute_with_gates(
        view,
        chain,
        sender,
        &DocClassTxData {
            operation: DocClassOperation::IssueCredential,
            subcode,
            data: bincode::serialize(payload).unwrap(),
            recipient: Address::ZERO,
        },
        &Address::new([9; 20]),
        100,
        HEIGHT,
        1_000,
        0,
        Hash::ZERO,
        gates,
    )
    .unwrap()
}

/// Seed a registered issuer of the type that `can_issue` the subcodes given.
///
/// The type matters and is not decoration: `DocClassIssuerType::can_issue`
/// partitions the subcodes, so an Educational issuer cannot issue an SRC-813
/// and a Professional one cannot issue an SRC-811. A test that got this wrong
/// would be refused for "Issuer not authorized" and would pass or fail for a
/// reason that has nothing to do with the gate under test.
fn seed(
    db: &Database,
    issuer: Address,
    issuer_type: DocClassIssuerType,
    subcodes: Vec<DocSubcode>,
) {
    DocClassStore::new(db)
        .issuers()
        .put(&issuer_of(issuer, issuer_type, subcodes))
        .unwrap();
}

// ── AU-33 — the signature nothing can check ─────────────────────────────────

/// AU-33. A credential asserting a signature is stored below the gate and
/// refused above it, and one asserting none is issued on both sides.
///
/// The closed side reproduces the defect exactly and by name: sixty-four bytes
/// of nonsense under a key id naming a key the issuer has never held are
/// ACCEPTED and STORED verbatim, because nothing in the subsystem verifies
/// anything. The open side refuses, before the deduct -- the nonce does not
/// advance -- with a reason that names VERIFICATION as unsupported rather than
/// the signature as invalid, because the bytes may be a perfectly good
/// signature and the chain has no way to find out.
#[test]
fn a_credential_asserts_an_uncheckable_signature_below_the_gate_and_not_above_it() {
    for gates in [CLOSED, SIGNATURE] {
        let chain = params();
        let (_state, db, _dir, _executor) = setup_with_params(chain.clone());
        let edu = KeyPair::generate();
        fund(&db, &edu, 100_000_000);
        let sender = edu.address();
        seed(
            &db,
            sender,
            DocClassIssuerType::Educational,
            vec![DocSubcode::Diploma],
        );
        let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
        let mut view = ExecutionView::new(&mut overlay);
        let before = StateManager::v_get_nonce(&view, &sender).unwrap();

        let mut forged = plain(0x91, sender, DocSubcode::Diploma);
        forged.issuer_signature = [0xAB; 64];
        forged.issuer_key_id = "a key id this issuer has never held".to_string();
        let r = run(
            &mut view,
            &chain,
            &sender,
            DocSubcode::Diploma,
            &forged,
            gates,
        );
        let charged = StateManager::v_get_nonce(&view, &sender).unwrap() > before;

        if gates.signature_unsupported {
            assert!(!r.success, "at the gate the assertion is refused");
            assert_eq!(
                r.error.as_deref(),
                Some(DOCCLASS_SIGNATURE_UNSUPPORTED),
                "and the reason names VERIFICATION as unsupported, not the \
                 signature as invalid -- 64 bytes is a well-formed signature \
                 and this chain cannot tell whether it is a real one"
            );
            assert!(
                !charged,
                "refused ahead of the deduct, where this arm's own \
                 duplicate-id refusal returns"
            );
            assert!(
                DocClassExecutor::v_get_credential(&view, &[0x91; 32])
                    .unwrap()
                    .is_none(),
                "and nothing was written"
            );
        } else {
            assert!(
                r.success,
                "below the gate nothing verifies anything, so it lands"
            );
            let stored = DocClassExecutor::v_get_credential(&view, &[0x91; 32])
                .unwrap()
                .unwrap();
            assert_eq!(
                stored.issuer_signature, [0xAB; 64],
                "and the unverifiable signature is STORED verbatim"
            );
            assert_eq!(
                stored.issuer_key_id, "a key id this issuer has never held",
                "and so is the key id that names no key"
            );
        }

        // A credential that asserts NOTHING is issued under both gates. The
        // gate closes the CLAIM, not the credential, and a DIFFERENT id is used
        // so a refusal could not be a duplicate.
        let quiet = plain(0x92, sender, DocSubcode::Diploma);
        assert!(
            run(
                &mut view,
                &chain,
                &sender,
                DocSubcode::Diploma,
                &quiet,
                gates
            )
            .success,
            "an all-zero signature with an empty key id asserts nothing, and is \
             issued on both sides of the gate"
        );
    }
}

/// AU-33 reaches the eligibility family too, and each half of the claim alone
/// is enough to refuse.
///
/// Two separate assertions rather than one, because `issuer_signature` and
/// `issuer_key_id` are two different claims -- that something was signed, and
/// that a particular key signed it -- and a guard that only checked the first
/// would leave a credential naming a key the chain cannot resolve.
#[test]
fn either_half_of_the_signature_claim_is_refused_on_either_credential_family() {
    let chain = params();
    let (_state, db, _dir, _executor) = setup_with_params(chain.clone());

    // Two senders, because `DocClassIssuerType::can_issue` partitions the
    // subcodes: only a Government issuer may issue an SRC-807 attestation, and
    // only an Educational one an SRC-811 diploma. One sender would be refused
    // for "Issuer not authorized" on whichever family it was not typed for, and
    // that refusal would look exactly like the gate's.
    let gov = KeyPair::generate();
    let edu = KeyPair::generate();
    fund(&db, &gov, 100_000_000);
    fund(&db, &edu, 100_000_000);
    seed(
        &db,
        gov.address(),
        DocClassIssuerType::Government,
        vec![DocSubcode::EligibilityAttestation],
    );
    seed(
        &db,
        edu.address(),
        DocClassIssuerType::Educational,
        vec![DocSubcode::Diploma],
    );
    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);

    // Signature bytes alone, on an attestation.
    let mut signed = plain_attestation(0xA1, gov.address());
    signed.issuer_signature = [0x01; 64];
    let r = run(
        &mut view,
        &chain,
        &gov.address(),
        DocSubcode::EligibilityAttestation,
        &signed,
        SIGNATURE,
    );
    assert!(!r.success, "the signature bytes alone are a claim");
    assert_eq!(r.error.as_deref(), Some(DOCCLASS_SIGNATURE_UNSUPPORTED));

    // Key id alone, on an academic credential.
    let mut named = plain(0xA2, edu.address(), DocSubcode::Diploma);
    named.issuer_key_id = "k-1".to_string();
    let r2 = run(
        &mut view,
        &chain,
        &edu.address(),
        DocSubcode::Diploma,
        &named,
        SIGNATURE,
    );
    assert!(
        !r2.success,
        "and the key id alone is a claim too -- naming a key the chain has no \
         stated rule for resolving is the other half of AU-33, and `k-1` is a \
         key this issuer really does hold, so the refusal is about the ABSENT \
         RULE and not about an unknown key"
    );
    assert_eq!(r2.error.as_deref(), Some(DOCCLASS_SIGNATURE_UNSUPPORTED));

    // Both families still issue a credential that asserts neither, at the same
    // height, under the same open gate.
    assert!(
        run(
            &mut view,
            &chain,
            &gov.address(),
            DocSubcode::EligibilityAttestation,
            &plain_attestation(0xA3, gov.address()),
            SIGNATURE,
        )
        .success,
        "an attestation asserting no signature is issued at the gate"
    );
    assert!(
        run(
            &mut view,
            &chain,
            &edu.address(),
            DocSubcode::Diploma,
            &plain(0xA4, edu.address(), DocSubcode::Diploma),
            SIGNATURE,
        )
        .success,
        "and so is a credential"
    );
}

// ── AU-37 — the validity window, in milliseconds ────────────────────────────

/// AU-37. The bound is read, and it is read in MILLISECONDS.
///
/// Four cases, in the order they make the claim checkable.
///
///   1. **Closed gate.** A two-year window under a one-year bound is ACCEPTED
///      and stored -- the defect the row files, reproduced exactly.
///   2. **Open gate, over the bound.** The same window is refused, before the
///      deduct.
///   3. **Open gate, the boundary.** A window exactly EQUAL to the bound is
///      accepted and one MILLISECOND more is refused. This is what makes the
///      unit checkable rather than merely asserted: the comparison's
///      granularity is one unit of the credential's `Timestamp`, and the
///      refusal moves at 1 rather than at 1,000. Under a seconds reading the
///      boundary would sit a thousand units away and case 3 would fail.
///   4. **The two documented escapes**, both with the gate open: a
///      `max_credential_validity` of 0 is NO LIMIT and is the default, and an
///      `expires_at` of 0 is NO EXPIRY. Either refused would be a lawful
///      credential refused by a wrong rule, which is the failure mode AU-37
///      says is worse than the gap.
#[test]
fn the_validity_bound_is_read_and_is_read_in_milliseconds() {
    let two_years_ms = 2 * ONE_YEAR_MS;

    // Closed gate: no bound applies however it is configured.
    {
        let chain = params_with_validity(ONE_YEAR_MS);
        let (_state, db, _dir, _executor) = setup_with_params(chain.clone());
        let edu = KeyPair::generate();
        fund(&db, &edu, 100_000_000);
        let sender = edu.address();
        seed(
            &db,
            sender,
            DocClassIssuerType::Educational,
            vec![DocSubcode::Diploma],
        );
        let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
        let mut view = ExecutionView::new(&mut overlay);

        let mut long = plain(0xB1, sender, DocSubcode::Diploma);
        long.valid_from = 0;
        long.expires_at = two_years_ms;
        assert!(
            run(
                &mut view,
                &chain,
                &sender,
                DocSubcode::Diploma,
                &long,
                CLOSED
            )
            .success,
            "below the gate no execution path reads the field, which is the \
             defect AU-37 files"
        );
        assert_eq!(
            DocClassExecutor::v_get_credential(&view, &[0xB1; 32])
                .unwrap()
                .unwrap()
                .expires_at,
            two_years_ms,
            "and the window is stored"
        );
    }

    // Open gate, bound below the window: refused.
    {
        let chain = params_with_validity(ONE_YEAR_MS);
        let (_state, db, _dir, _executor) = setup_with_params(chain.clone());
        let edu = KeyPair::generate();
        fund(&db, &edu, 100_000_000);
        let sender = edu.address();
        seed(
            &db,
            sender,
            DocClassIssuerType::Educational,
            vec![DocSubcode::Diploma],
        );
        let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
        let mut view = ExecutionView::new(&mut overlay);
        let before = StateManager::v_get_nonce(&view, &sender).unwrap();

        let mut long = plain(0xB2, sender, DocSubcode::Diploma);
        long.valid_from = 0;
        long.expires_at = two_years_ms;
        let r = run(
            &mut view,
            &chain,
            &sender,
            DocSubcode::Diploma,
            &long,
            VALIDITY,
        );
        assert!(!r.success, "at the gate the window is bounded");
        assert_eq!(
            r.error.as_deref(),
            Some(DOCCLASS_CREDENTIAL_VALIDITY_TOO_LONG)
        );
        assert!(
            StateManager::v_get_nonce(&view, &sender).unwrap() == before,
            "refused ahead of the deduct"
        );
    }

    // Open gate, the boundary: a window EQUAL to the bound is accepted, and one
    // millisecond more is not. This is what makes the unit checkable rather
    // than asserted -- the bound is compared against a difference of
    // timestamps, and the timestamps are the chain's, which are milliseconds.
    {
        let chain = params_with_validity(ONE_YEAR_MS);
        let (_state, db, _dir, _executor) = setup_with_params(chain.clone());
        let edu = KeyPair::generate();
        fund(&db, &edu, 100_000_000);
        let sender = edu.address();
        seed(
            &db,
            sender,
            DocClassIssuerType::Educational,
            vec![DocSubcode::Diploma],
        );
        let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
        let mut view = ExecutionView::new(&mut overlay);

        let mut exact = plain(0xB3, sender, DocSubcode::Diploma);
        exact.valid_from = 1_000;
        exact.expires_at = 1_000 + ONE_YEAR_MS;
        assert!(
            run(
                &mut view,
                &chain,
                &sender,
                DocSubcode::Diploma,
                &exact,
                VALIDITY
            )
            .success,
            "a window exactly equal to the bound is within it: the rule is a \
             ceiling, and a credential valid for precisely the configured \
             maximum is the one an operator configured for"
        );

        let mut over = plain(0xB4, sender, DocSubcode::Diploma);
        over.valid_from = 1_000;
        over.expires_at = 1_000 + ONE_YEAR_MS + 1;
        assert!(
            !run(
                &mut view,
                &chain,
                &sender,
                DocSubcode::Diploma,
                &over,
                VALIDITY
            )
            .success,
            "and ONE MILLISECOND more is over it -- the granularity of the \
             comparison is the millisecond, which is the whole of AU-37's unit \
             question answered as a number"
        );
    }

    // The two documented escapes, both open: no configured bound, and no
    // expiry. Either would be a lawful credential refused by a wrong rule.
    {
        let chain = params_with_validity(0);
        let (_state, db, _dir, _executor) = setup_with_params(chain.clone());
        let edu = KeyPair::generate();
        fund(&db, &edu, 100_000_000);
        let sender = edu.address();
        seed(
            &db,
            sender,
            DocClassIssuerType::Educational,
            vec![DocSubcode::Diploma],
        );
        let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
        let mut view = ExecutionView::new(&mut overlay);

        let mut forever = plain(0xB5, sender, DocSubcode::Diploma);
        forever.valid_from = 0;
        forever.expires_at = u64::MAX;
        assert!(
            run(
                &mut view,
                &chain,
                &sender,
                DocSubcode::Diploma,
                &forever,
                VALIDITY
            )
            .success,
            "`max_credential_validity` of 0 is NO LIMIT, which the field's own \
             comment says and which is the default -- an operator who \
             configured nothing sees no change at the height"
        );

        let chain2 = params_with_validity(ONE_YEAR_MS);
        let (_state2, db2, _dir2, _executor2) = setup_with_params(chain2.clone());
        let edu2 = KeyPair::generate();
        fund(&db2, &edu2, 100_000_000);
        let sender2 = edu2.address();
        seed(
            &db2,
            sender2,
            DocClassIssuerType::Educational,
            vec![DocSubcode::Diploma],
        );
        let mut overlay2 = ApplicationOverlay::new(&db2, common::TEST_CANDIDATE_LIMIT);
        let mut view2 = ExecutionView::new(&mut overlay2);

        let mut unexpiring = plain(0xB6, sender2, DocSubcode::Diploma);
        unexpiring.valid_from = 1_000;
        unexpiring.expires_at = 0;
        assert!(
            run(
                &mut view2,
                &chain2,
                &sender2,
                DocSubcode::Diploma,
                &unexpiring,
                VALIDITY
            )
            .success,
            "`expires_at` of 0 is NO EXPIRY, which the wire type says -- \
             bounding it would refuse the credential the field calls unexpiring"
        );
    }
}

// ── D-19b — the attribute keys no allowlist covers ──────────────────────────

/// D-19b. An attribute on a subcode with no allowlist is stored below the gate
/// and refused above it, and the three subcodes that HAVE an allowlist are
/// untouched by it.
///
/// The discriminator is the second half. A gate that refused every attribute
/// everywhere would also pass the first assertion, and would have deleted the
/// attribute feature; a gate that refused nothing would pass neither. So the
/// same attribute name is carried on an SRC-813, which has no allowlist, and on
/// an SRC-811, which does -- and only the first is refused.
///
/// No allowlist is invented. The rule is "this subcode classifies no key, so
/// every key on it is unclassified", which is a statement about the ABSENCE of
/// a standard and leaves a later standard free to supply one.
#[test]
fn an_unclassified_attribute_is_stored_below_the_gate_and_refused_above_it() {
    for gates in [CLOSED, ATTRIBUTES] {
        let chain = params();
        let (_state, db, _dir, _executor) = setup_with_params(chain.clone());
        // Two senders again, because only a Professional issuer may issue an
        // SRC-813 and only an Educational one an SRC-811 -- and the whole point
        // of this test is to run the SAME attribute against both.
        let board = KeyPair::generate();
        let edu = KeyPair::generate();
        fund(&db, &board, 100_000_000);
        fund(&db, &edu, 100_000_000);
        let sender = board.address();
        seed(
            &db,
            sender,
            DocClassIssuerType::Professional,
            vec![DocSubcode::ProfessionalLicense],
        );
        seed(
            &db,
            edu.address(),
            DocClassIssuerType::Educational,
            vec![DocSubcode::Diploma],
        );
        let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
        let mut view = ExecutionView::new(&mut overlay);
        let before = StateManager::v_get_nonce(&view, &sender).unwrap();

        let attribute = CredentialAttribute {
            name: "ssn".to_string(),
            value: "000-00-0000".to_string(),
        };

        // SRC-813: no allowlist exists for this subcode at any height.
        let mut licence = plain(0xC1, sender, DocSubcode::ProfessionalLicense);
        licence.metadata.attributes = vec![attribute.clone()];
        let r = run(
            &mut view,
            &chain,
            &sender,
            DocSubcode::ProfessionalLicense,
            &licence,
            gates,
        );
        let charged = StateManager::v_get_nonce(&view, &sender).unwrap() > before;

        if gates.unknown_attribute_refused {
            assert!(!r.success, "at the gate the unclassified key is refused");
            assert_eq!(
                r.error.as_deref(),
                Some(DOCCLASS_UNKNOWN_ATTRIBUTE_REFUSED),
                "and the reason names the SUBCODE's missing allowlist, not the \
                 key -- no other key would have been accepted either"
            );
            assert!(!charged, "refused ahead of the deduct");
            let row = DocClassExecutor::v_get_credential(&view, &[0xC1; 32]).unwrap();
            assert!(row.is_none(), "and nothing was written");
        } else {
            assert!(
                r.success,
                "below the gate an SRC-813 takes any attribute key, including \
                 one on this module's own explicitly-disallowed PII list -- \
                 which is the half of D-19b no height closed"
            );
            assert_eq!(
                DocClassExecutor::v_get_credential(&view, &[0xC1; 32])
                    .unwrap()
                    .unwrap()
                    .metadata
                    .attributes
                    .len(),
                1,
                "and the key is STORED"
            );
        }

        // An SRC-813 carrying NO attribute is issued on both sides: the gate
        // refuses an unclassified KEY, not the subcode.
        assert!(
            run(
                &mut view,
                &chain,
                &sender,
                DocSubcode::ProfessionalLicense,
                &plain(0xC2, sender, DocSubcode::ProfessionalLicense),
                gates,
            )
            .success,
            "a credential asserting no attribute is issued on both sides"
        );

        // And an SRC-811, which HAS an allowlist, is unaffected by this gate on
        // both sides -- so the refusal above is about the subcode's missing
        // list and not about attributes in general. `honors` is on 811's list.
        let mut diploma = plain(0xC3, edu.address(), DocSubcode::Diploma);
        diploma.metadata.attributes = vec![CredentialAttribute {
            name: "honors".to_string(),
            value: "summa cum laude".to_string(),
        }];
        assert!(
            run(
                &mut view,
                &chain,
                &edu.address(),
                DocSubcode::Diploma,
                &diploma,
                gates
            )
            .success,
            "a subcode that classifies its keys keeps taking the keys it \
             classifies, at every height"
        );
    }
}
