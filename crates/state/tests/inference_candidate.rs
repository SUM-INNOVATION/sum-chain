//! Attestation and settlement read and write the block's candidate.
//!
//! These two migrate together because settlement CONSUMES attestation. A claim
//! checks that the claimant attested, counts the consistency group over the
//! session's attestations, and draws the session's escrow down. Every one of
//! those inputs can be produced by an earlier transaction in the SAME block, so
//! a committed read is not merely stale — it lets one block pay a claim whose
//! attestation it is publishing in that same block, or pay two claims from an
//! escrow that only covers one.

mod common;

use std::sync::Arc;

use sumchain_primitives::inference_attestation::{
    inference_attestation_key, InferenceAttestationDigest, InferenceAttestationRecord,
};
use sumchain_primitives::inference_settlement::{
    InferenceClaim, InferenceClaimStatus, InferenceDispute, InferenceDisputeStatus,
    InferenceSession, InferenceSessionStatus,
};
use sumchain_primitives::{Address, Hash};
use sumchain_state::inference_attestation_executor::InferenceAttestationExecutor;
use sumchain_state::inference_settlement_executor::InferenceSettlementExecutor;
use sumchain_storage::exec_view::ExecutionView;
use sumchain_storage::overlay::ApplicationOverlay;
use sumchain_storage::Database;

const LIMIT: u64 = 1 << 20;
const SESSION: &str = "session-under-test";

fn open_db() -> (tempfile::TempDir, Arc<Database>) {
    let dir = tempfile::TempDir::new().unwrap();
    let db = Arc::new(Database::open_default(dir.path()).unwrap());
    (dir, db)
}

fn digest() -> InferenceAttestationDigest {
    InferenceAttestationDigest {
        session_id: SESSION.to_string(),
        model_hash: [1u8; 32],
        manifest_root: [2u8; 32],
        response_hash: [3u8; 32],
        proof_root: [4u8; 32],
    }
}

fn record(height: u64) -> InferenceAttestationRecord {
    InferenceAttestationRecord {
        digest: digest(),
        verifier_signature: [9u8; 64],
        included_at_height: height,
        tx_hash: Hash::new([7u8; 32]),
    }
}

fn verifier(n: u8) -> Address {
    Address::new([n; 20])
}

#[test]
fn a_claim_finds_an_attestation_staged_earlier_in_the_same_block() {
    // The coupling, stated directly. Reading committed state here would find
    // nothing and the claim would be rejected as un-attested — while the block
    // publishes the very attestation it refused to see.
    let (_d, db) = open_db();
    let mut overlay = ApplicationOverlay::new(&db, LIMIT);
    let mut view = ExecutionView::new(&mut overlay);
    let v = verifier(0xAA);
    let key = inference_attestation_key(SESSION, &v);

    InferenceAttestationExecutor::stage(&mut view, &key, &record(10), &v, None).unwrap();

    assert!(
        InferenceAttestationExecutor::v_exists(&view, &key).unwrap(),
        "the attestation this block staged must be visible within it"
    );
    assert_eq!(
        InferenceAttestationExecutor::v_get(&view, &key).unwrap().unwrap(),
        record(10)
    );
    assert_eq!(
        InferenceAttestationExecutor::v_list_verifiers_by_session(&view, SESSION).unwrap(),
        vec![v],
        "and it must count toward the session's verifier set"
    );

    // Committed state is untouched: the rows are buffered.
    assert!(!InferenceAttestationExecutor::new(db.clone())
        .exists(&key)
        .unwrap());
    assert!(InferenceAttestationExecutor::new(db.clone())
        .list_verifiers_by_session(SESSION)
        .unwrap()
        .is_empty());
}

#[test]
fn the_consistency_group_counts_attestations_from_this_block() {
    // A plurality decides a payout. Counting the parent's attestations would let
    // a block satisfy — or fail — a consistency rule on a set that does not
    // match the state it publishes.
    let (_d, db) = open_db();
    let mut overlay = ApplicationOverlay::new(&db, LIMIT);
    let mut view = ExecutionView::new(&mut overlay);

    for n in [0xA1u8, 0xA2, 0xA3] {
        let v = verifier(n);
        InferenceAttestationExecutor::stage(
            &mut view,
            &inference_attestation_key(SESSION, &v),
            &record(1),
            &v,
            None,
        )
        .unwrap();
    }

    // Claim height 10, finality depth 1: all three are final (1 + 1 <= 10).
    assert_eq!(
        InferenceSettlementExecutor::v_consistency_group_size(&view, SESSION, &digest(), 10, 1)
            .unwrap(),
        3,
        "every attestation staged in this block belongs to the group"
    );

    // A dispute opened earlier in the SAME block removes one.
    InferenceSettlementExecutor::v_put_dispute(
        &mut view,
        &InferenceDispute {
            session_id: SESSION.to_string(),
            verifier: verifier(0xA2),
            opener: verifier(0xBB),
            evidence_commitment: [0u8; 32],
            status: InferenceDisputeStatus::Open,
            opened_at_height: 5,
            resolved_at_height: None,
            allow_claim: false,
        },
    )
    .unwrap();
    assert_eq!(
        InferenceSettlementExecutor::v_consistency_group_size(&view, SESSION, &digest(), 10, 1)
            .unwrap(),
        2,
        "a dispute opened in this block must remove its verifier's weight"
    );
}

#[test]
fn a_second_claim_draws_from_the_escrow_the_first_left() {
    // Two claims in one block. If the second reads the parent's session it sees
    // the full escrow and the block pays twice what the session funded.
    let (_d, db) = open_db();
    let mut overlay = ApplicationOverlay::new(&db, LIMIT);
    let mut view = ExecutionView::new(&mut overlay);

    let mut session = InferenceSession {
        session_id: SESSION.to_string(),
        funder: verifier(0xF0),
        reward_per_verifier: 100,
        max_verifiers: 2,
        remaining_escrow: 200,
        claims_count: 0,
        dispute_window_blocks: 10,
        status: InferenceSessionStatus::Open,
        created_at_height: 1,
        expires_at_height: 1000,
        consistency: None,
        bond_requirement: None,
    };
    InferenceSettlementExecutor::v_put_session(&mut view, &session).unwrap();

    // First claim.
    session.remaining_escrow -= session.reward_per_verifier;
    session.claims_count += 1;
    InferenceSettlementExecutor::v_put_session(&mut view, &session).unwrap();
    InferenceSettlementExecutor::v_put_claim(
        &mut view,
        &InferenceClaim {
            session_id: SESSION.to_string(),
            verifier: verifier(0xA1),
            amount: 100,
            claimed_at_height: 10,
            status: InferenceClaimStatus::Paid,
        },
    )
    .unwrap();

    // The second claim reads what the first left behind.
    let seen = InferenceSettlementExecutor::v_get_session(&view, SESSION)
        .unwrap()
        .unwrap();
    assert_eq!(
        seen.remaining_escrow, 100,
        "the second claim must see the escrow the first drew down"
    );
    assert_eq!(seen.claims_count, 1);
    assert!(
        InferenceSettlementExecutor::v_get_claim(&view, SESSION, &verifier(0xA1))
            .unwrap()
            .is_some(),
        "and must see that this verifier already claimed"
    );

    // Committed state still holds neither.
    assert!(InferenceSettlementExecutor::new(db.clone())
        .get_session(SESSION)
        .unwrap()
        .is_none());
}

#[test]
fn a_dropped_candidate_leaves_attestation_and_settlement_untouched() {
    let (_d, db) = open_db();
    let aexec = InferenceAttestationExecutor::new(db.clone());
    let sexec = InferenceSettlementExecutor::new(db.clone());
    let v = verifier(0xC1);
    let key = inference_attestation_key(SESSION, &v);

    {
        let mut overlay = ApplicationOverlay::new(&db, LIMIT);
        let mut view = ExecutionView::new(&mut overlay);
        InferenceAttestationExecutor::stage(&mut view, &key, &record(3), &v, None).unwrap();
        InferenceSettlementExecutor::v_put_claim(
            &mut view,
            &InferenceClaim {
                session_id: SESSION.to_string(),
                verifier: v,
                amount: 7,
                claimed_at_height: 3,
                status: InferenceClaimStatus::Paid,
            },
        )
        .unwrap();
        // Dropped here, unpublished.
    }

    assert!(!aexec.exists(&key).unwrap());
    assert!(aexec.list_verifiers_by_session(SESSION).unwrap().is_empty());
    assert!(sexec.get_claim(SESSION, &v).unwrap().is_none());
}

#[test]
fn staging_an_attestation_carries_its_index_and_sponsor_together() {
    // `put` opened its own batch so the canonical row, the session index and the
    // sponsor row applied together. That atomicity is now the candidate's, and
    // it is the same guarantee: a record without its index is invisible to the
    // listing RPC while still findable by point lookup.
    use sumchain_primitives::inference_attestation::InferenceAttestationSponsor;

    let (_d, db) = open_db();
    let mut overlay = ApplicationOverlay::new(&db, LIMIT);
    let mut view = ExecutionView::new(&mut overlay);
    let v = verifier(0xD1);
    let sponsor_addr = verifier(0xD2);
    let key = inference_attestation_key(SESSION, &v);

    let sponsor = InferenceAttestationSponsor {
        sponsor: sponsor_addr,
        submitted_at_height: 4,
        tx_hash: Hash::new([8u8; 32]),
    };
    InferenceAttestationExecutor::stage(&mut view, &key, &record(4), &v, Some(&sponsor)).unwrap();

    assert!(InferenceAttestationExecutor::v_exists(&view, &key).unwrap());
    assert_eq!(
        InferenceAttestationExecutor::v_list_verifiers_by_session(&view, SESSION).unwrap(),
        vec![v],
        "the index must be staged with the record, not after it"
    );
    assert!(
        view.get(sumchain_storage::cf::INFERENCE_ATTESTATION_SPONSORS, &key)
            .unwrap()
            .is_some(),
        "the sponsor row belongs to the same staging"
    );
}
