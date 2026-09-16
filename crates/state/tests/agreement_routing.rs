//! SRC-84X agreements execute against the block's candidate.
//!
//! Real signed transactions through `BlockExecutor`, in sequence, in one block.
//!
//! ## Why this subsystem's reads had to move with its writes
//!
//! Agreements are a state machine. Eleven of the twenty migrated occurrences
//! are transitions that read a row, change one field plus `updated_at`, and
//! write it back. The sharpest case is signing: `mark_party_signed` flips one
//! party's flag and then, if EVERY party has now signed, advances the agreement
//! from `PendingSignatures` to `Executed`. That check reads the other parties'
//! flags. Against committed state, a two-party agreement signed twice in one
//! block would end the block still pending -- the second signature would read
//! the block's starting row, see one unsigned party, and write back a row that
//! silently discards the first signature.
//!
//! `both_signatures_in_one_block_advance_the_agreement_to_executed` is that
//! case, and `without_the_first_signature_the_second_leaves_it_pending` is its
//! control.

mod common;

use common::{fund, setup_with_params, CHAIN_ID};
use sumchain_crypto::{sign, KeyPair};
use sumchain_genesis::ChainParams;
use sumchain_primitives::agreement::{
    AgreementCommitment, AgreementOperation, AgreementProofEnvelope, AgreementProofProfile,
    AgreementProofType, AgreementRole, AgreementStatus, AgreementTxData, AttestationIssuerClass,
    AttestationPacket, AttestationStatus, AttestationTarget, AttestationType, ExecutorLink,
    ExecutorState, IpActionStatus, IpActionType, IpAssetType, IpRightsAction, PartyBinding,
    PartyRef, PartySignature, SignatureType,
};
use sumchain_primitives::{Address, SignedTransaction, TransactionV2, TxPayload, TxStatus};
use sumchain_state::{AgreementExecutor, StateManager};
use sumchain_storage::exec_view::ExecutionView;
use sumchain_storage::overlay::ApplicationOverlay;
use sumchain_storage::{cf, AgreementStore, Database};

/// Every family this unit moved. Eight.
const AGREEMENT_CFS: &[&str] = &[
    cf::AGREEMENT_COMMITMENTS,
    cf::AGREEMENT_PARTY_INDEX,
    cf::AGREEMENT_SIGNATURES,
    cf::AGREEMENT_ATTESTATIONS,
    cf::AGREEMENT_IP_ACTIONS,
    cf::AGREEMENT_EXECUTOR_LINKS,
    cf::AGREEMENT_EXECUTOR_INDEX,
    cf::AGREEMENT_PROOFS,
];

fn params() -> ChainParams {
    ChainParams::with_v2_enabled()
}

fn tx(
    kp: &KeyPair,
    nonce: u64,
    op: AgreementOperation,
    payload: &impl serde::Serialize,
) -> SignedTransaction {
    let t = TransactionV2 {
        chain_id: CHAIN_ID,
        from: kp.address(),
        fee: 100,
        nonce,
        payload: TxPayload::Agreement(AgreementTxData {
            operation: op,
            data: bincode::serialize(payload).unwrap(),
            recipient: Address::ZERO,
        }),
    };
    let sig = sign(t.signing_hash().as_bytes(), kp.private_key());
    SignedTransaction::new_v2(t, *sig.as_bytes(), *kp.public_key().as_bytes())
}

fn party(commitment: u8, role: AgreementRole) -> PartyBinding {
    PartyBinding {
        party_ref: PartyRef::Commitment([commitment; 32]),
        role,
        signed: false,
        signed_at: None,
    }
}

/// A two-party agreement, pending signatures.
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

fn signature_for(
    agreement_id: u8,
    commitment: u8,
    sig_id: u8,
    role: AgreementRole,
) -> PartySignature {
    PartySignature {
        signature_id: [sig_id; 32],
        agreement_id: [agreement_id; 32],
        party_ref: PartyRef::Commitment([commitment; 32]),
        role,
        signature_type: SignatureType::Single,
        signature: vec![9u8; 64],
        signer_key: [commitment; 32],
        signed_at: 1000,
        recorded_at_height: 1,
        witness_attestation_id: None,
    }
}

fn canonical(db: &Database) -> Vec<(String, Vec<u8>, Vec<u8>)> {
    let mut out = Vec::new();
    for f in AGREEMENT_CFS {
        for (k, v) in db.prefix_iter(f, &[]).unwrap() {
            out.push((f.to_string(), k.to_vec(), v.to_vec()));
        }
    }
    out.sort();
    out
}

/// Families whose CANDIDATE contents differ from the committed ones.
///
/// A real per-CF diff, not a presence check: `prefix_iter` on a view is MERGED
/// with committed state, so presence proves nothing about what this block did.
fn families_changed(db: &Database, view: &ExecutionView<'_, '_>) -> Vec<&'static str> {
    let mut out = Vec::new();
    for f in AGREEMENT_CFS {
        let committed: Vec<(Vec<u8>, Vec<u8>)> = db
            .prefix_iter(f, &[])
            .unwrap()
            .map(|(k, v)| (k.to_vec(), v.to_vec()))
            .collect();
        let staged: Vec<(Vec<u8>, Vec<u8>)> = view
            .prefix_iter(f, &[])
            .unwrap()
            .map(|r| {
                let (k, v) = r.unwrap();
                (k.to_vec(), v.to_vec())
            })
            .collect();
        if committed != staged {
            out.push(*f);
        }
    }
    out
}

// ── The auto-transition: agreement's sharpest same-block case ────────────────

/// Two signatures in one block carry the agreement to `Executed`.
///
/// The second signature's fully-signed check reads the FIRST party's flag. It
/// can only see it in the candidate.
#[test]
fn both_signatures_in_one_block_advance_the_agreement_to_executed() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let signer = KeyPair::generate();
    fund(&db, &signer, 100_000_000);
    let proposer = Address::new([9; 20]);

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);

    let r = executor
        .execute_tx(
            &mut view,
            &tx(
                &signer,
                0,
                AgreementOperation::CommitAgreement,
                &two_party_agreement(10),
            ),
            &proposer,
            1,
            1000,
        )
        .unwrap();
    assert!(matches!(r.status, TxStatus::Success), "{:?}", r.status);
    assert_eq!(
        AgreementExecutor::v_get_agreement(&view, &[10u8; 32])
            .unwrap()
            .unwrap()
            .status,
        AgreementStatus::PendingSignatures
    );

    for (n, (commitment, sig_id, role)) in [
        (0xA1u8, 0x51u8, AgreementRole::Buyer),
        (0xB2u8, 0x52u8, AgreementRole::Seller),
    ]
    .into_iter()
    .enumerate()
    {
        let r = executor
            .execute_tx(
                &mut view,
                &tx(
                    &signer,
                    (n + 1) as u64,
                    AgreementOperation::SignAgreement,
                    &signature_for(10, commitment, sig_id, role),
                ),
                &proposer,
                1,
                1000,
            )
            .unwrap();
        assert!(
            matches!(r.status, TxStatus::Success),
            "sign {n}: {:?}",
            r.status
        );

        let a = AgreementExecutor::v_get_agreement(&view, &[10u8; 32])
            .unwrap()
            .unwrap();
        let signed: Vec<bool> = a.parties.iter().map(|p| p.signed).collect();
        if n == 0 {
            assert_eq!(signed, vec![true, false], "only the first party has signed");
            assert_eq!(
                a.status,
                AgreementStatus::PendingSignatures,
                "one signature must not advance it"
            );
        } else {
            assert_eq!(
                signed,
                vec![true, true],
                "the second signature must see the first -- a committed read \
                 here would show the first party unsigned and overwrite it"
            );
            assert_eq!(
                a.status,
                AgreementStatus::Executed,
                "and the agreement advances only because both flags are visible"
            );
        }
    }
}

/// Without the first signature, the second leaves it pending.
///
/// The discriminator: the test above would pass if signing simply always
/// advanced the status.
#[test]
fn without_the_first_signature_the_second_leaves_it_pending() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let signer = KeyPair::generate();
    fund(&db, &signer, 100_000_000);
    let proposer = Address::new([9; 20]);

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);
    executor
        .execute_tx(
            &mut view,
            &tx(
                &signer,
                0,
                AgreementOperation::CommitAgreement,
                &two_party_agreement(11),
            ),
            &proposer,
            1,
            1000,
        )
        .unwrap();
    // Only the SELLER signs.
    let r = executor
        .execute_tx(
            &mut view,
            &tx(
                &signer,
                1,
                AgreementOperation::SignAgreement,
                &signature_for(11, 0xB2, 0x62, AgreementRole::Seller),
            ),
            &proposer,
            1,
            1000,
        )
        .unwrap();
    assert!(matches!(r.status, TxStatus::Success), "{:?}", r.status);

    let a = AgreementExecutor::v_get_agreement(&view, &[11u8; 32])
        .unwrap()
        .unwrap();
    assert_eq!(
        a.parties.iter().map(|p| p.signed).collect::<Vec<_>>(),
        vec![false, true]
    );
    assert_eq!(
        a.status,
        AgreementStatus::PendingSignatures,
        "one outstanding party keeps it pending"
    );
}

/// A signature for an agreement committed earlier in the same block finds it.
#[test]
fn a_signature_finds_an_agreement_committed_earlier_in_the_same_block() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let signer = KeyPair::generate();
    fund(&db, &signer, 100_000_000);
    let proposer = Address::new([9; 20]);

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);
    executor
        .execute_tx(
            &mut view,
            &tx(
                &signer,
                0,
                AgreementOperation::CommitAgreement,
                &two_party_agreement(12),
            ),
            &proposer,
            1,
            1000,
        )
        .unwrap();
    let r = executor
        .execute_tx(
            &mut view,
            &tx(
                &signer,
                1,
                AgreementOperation::SignAgreement,
                &signature_for(12, 0xA1, 0x71, AgreementRole::Buyer),
            ),
            &proposer,
            1,
            1000,
        )
        .unwrap();
    assert!(matches!(r.status, TxStatus::Success), "{:?}", r.status);
}

/// Without the commitment, the same signature is refused BY THE AGREEMENT
/// GUARD -- `Failed(11)`, not an earlier rejection.
#[test]
fn without_the_commitment_the_same_signature_is_refused() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let signer = KeyPair::generate();
    fund(&db, &signer, 100_000_000);
    let proposer = Address::new([9; 20]);

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);
    let r = executor
        .execute_tx(
            &mut view,
            &tx(
                &signer,
                0,
                AgreementOperation::SignAgreement,
                &signature_for(13, 0xA1, 0x81, AgreementRole::Buyer),
            ),
            &proposer,
            1,
            1000,
        )
        .unwrap();
    assert_eq!(
        r.status,
        TxStatus::Failed(11),
        "it must fail in the agreement executor, not for an unrelated reason"
    );
    assert!(
        families_changed(&db, &view).is_empty(),
        "and change nothing"
    );
    assert_eq!(
        StateManager::v_get_nonce(&view, &signer.address()).unwrap(),
        0,
        "a refused agreement operation does not advance the account nonce"
    );
}

/// Two agreements sharing a party in one block: the party index holds BOTH.
///
/// The index value is an accumulating `Vec<AgreementId>`. Read from committed
/// state the second write would see an empty list and replace the first
/// agreement's entry with a single-element one.
#[test]
fn two_agreements_for_one_party_accumulate_in_the_index() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let signer = KeyPair::generate();
    fund(&db, &signer, 100_000_000);
    let proposer = Address::new([9; 20]);

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);
    for (n, id) in [20u8, 21u8].into_iter().enumerate() {
        let r = executor
            .execute_tx(
                &mut view,
                &tx(
                    &signer,
                    n as u64,
                    AgreementOperation::CommitAgreement,
                    &two_party_agreement(id),
                ),
                &proposer,
                1,
                1000,
            )
            .unwrap();
        assert!(matches!(r.status, TxStatus::Success), "{:?}", r.status);
    }

    assert_eq!(
        AgreementExecutor::v_get_party_agreement_ids(&view, &[0xA1u8; 32]).unwrap(),
        vec![[20u8; 32], [21u8; 32]],
        "both agreement ids, in commit order -- the second must have seen the first"
    );
}

// ── Abandonment ──────────────────────────────────────────────────────────────

/// Six transactions that between them write all EIGHT agreement families.
///
/// Used by the abandonment test and by the restart test, so the two are talking
/// about the same block. `id` keeps the fixtures distinct between them.
fn a_block_touching_every_family(
    signer: &KeyPair,
    id: u8,
    contract: Address,
) -> Vec<SignedTransaction> {
    vec![
        // commitments + party index
        tx(
            signer,
            0,
            AgreementOperation::CommitAgreement,
            &two_party_agreement(id),
        ),
        // signatures
        tx(
            signer,
            1,
            AgreementOperation::SignAgreement,
            &signature_for(id, 0xA1, id.wrapping_add(1), AgreementRole::Buyer),
        ),
        // attestations
        tx(
            signer,
            2,
            AgreementOperation::CreateAttestation,
            &attestation(id.wrapping_add(2), &signer.address(), id),
        ),
        // ip actions
        tx(
            signer,
            3,
            AgreementOperation::RecordIpAction,
            &ip_action(id.wrapping_add(3)),
        ),
        // executor links + executor index
        tx(
            signer,
            4,
            AgreementOperation::LinkExecutor,
            &executor_link(id.wrapping_add(4), id, contract),
        ),
        // proofs
        tx(
            signer,
            5,
            AgreementOperation::SubmitProof,
            &proof_envelope(id.wrapping_add(5)),
        ),
    ]
}

/// A block writing every agreement family commits none of it.
///
/// All eight are asserted STAGED first, by per-CF diff, so the canonical
/// comparison afterwards is a statement about eight discarded families and not
/// about a block that quietly did nothing.
#[test]
fn an_abandoned_block_leaves_all_eight_families_untouched() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let actor = KeyPair::generate();
    fund(&db, &actor, 500_000_000);
    let proposer = Address::new([9; 20]);
    let before = canonical(&db);

    {
        let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
        let mut view = ExecutionView::new(&mut overlay);

        for t in a_block_touching_every_family(&actor, 30, Address::new([0xCC; 20])) {
            let r = executor
                .execute_tx(&mut view, &t, &proposer, 1, 1000)
                .unwrap();
            assert!(matches!(r.status, TxStatus::Success), "{:?}", r.status);
        }

        let touched = families_changed(&db, &view);
        for f in AGREEMENT_CFS {
            assert!(
                touched.contains(f),
                "{f} was not staged, so this block does not test it"
            );
        }
        // dropped without publication
    }

    assert_eq!(
        canonical(&db),
        before,
        "an abandoned block must leave every agreement row byte-identical"
    );
}

// ── Limit refusal ────────────────────────────────────────────────────────────

/// A refusal leaves canonical storage untouched, and at least one ceiling
/// refuses with the commitment staged and its party-index entry not.
///
/// `CommitAgreement` is the operation to calibrate against: it writes the
/// commitment row and then one party-index entry per party, so a ceiling can
/// land between them. Every ceiling below the measured cost is tried, not a
/// sample -- the interval is a few bytes wide.
#[test]
fn a_refusal_part_way_leaves_canonical_storage_untouched() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let actor = KeyPair::generate();
    fund(&db, &actor, 500_000_000);
    let proposer = Address::new([9; 20]);
    let before = canonical(&db);
    let signed_tx = tx(
        &actor,
        0,
        AgreementOperation::CommitAgreement,
        &two_party_agreement(40),
    );

    assert!(
        db.prefix_iter(cf::AGREEMENT_COMMITMENTS, &[])
            .unwrap()
            .next()
            .is_none()
            && db
                .prefix_iter(cf::AGREEMENT_PARTY_INDEX, &[])
                .unwrap()
                .next()
                .is_none(),
        "both families must start canonically empty for the merged reads below \
         to stand for staged"
    );

    let full = {
        let mut scratch = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
        {
            let mut v = ExecutionView::new(&mut scratch);
            executor
                .execute_tx(&mut v, &signed_tx, &proposer, 1, 1000)
                .unwrap();
        }
        scratch.logical_bytes()
    };
    assert!(full > 1, "a commitment must cost something");

    let mut partials = 0usize;
    for ceiling in 1..full {
        let mut overlay = ApplicationOverlay::new(&db, ceiling);
        let mut view = ExecutionView::new(&mut overlay);
        let outcome = executor.execute_tx(&mut view, &signed_tx, &proposer, 1, 1000);
        assert!(outcome.is_err(), "ceiling {ceiling} must refuse");
        assert!(
            outcome.unwrap_err().to_string().contains("limit"),
            "ceiling {ceiling} must fail because a WRITE was refused"
        );

        let commitment_staged = view
            .get(cf::AGREEMENT_COMMITMENTS, &[40u8; 32])
            .unwrap()
            .is_some();
        let index_staged = view
            .get(cf::AGREEMENT_PARTY_INDEX, &[0xA1u8; 32])
            .unwrap()
            .is_some();
        if commitment_staged && !index_staged {
            partials += 1;
        }
        assert!(
            !index_staged || commitment_staged,
            "ceiling {ceiling} staged the index without the commitment, which \
             the write order cannot produce"
        );
        assert_eq!(
            canonical(&db),
            before,
            "ceiling {ceiling} must commit nothing"
        );
    }
    assert!(
        partials > 0,
        "no ceiling refused with the commitment staged and its party index not"
    );
}

// ── Parity, including a restart ──────────────────────────────────────────────

/// Published rows satisfy the committed scans AND survive a restart.
///
/// Reading back through the same handle proves the write reached the database's
/// view of itself, not that it is durable. This closes the handle -- asserting
/// the strong count first, so the close is proved rather than hoped for -- and
/// reopens at the same path. Same block shape as the abandonment test: all
/// eight families.
#[test]
fn published_agreement_rows_survive_a_database_restart() {
    let dir = tempfile::TempDir::new().unwrap();
    let actor = KeyPair::generate();
    let contract = Address::new([0xCC; 20]);

    let expected: Vec<(String, Vec<u8>, Vec<u8>)> = {
        let db = std::sync::Arc::new(Database::open_default(dir.path()).unwrap());
        let state = std::sync::Arc::new(StateManager::new(db.clone(), CHAIN_ID));
        let executor =
            sumchain_state::executor::BlockExecutor::new(state.clone(), db.clone(), params());
        fund(&db, &actor, 500_000_000);

        let receipts = common::publish_block(
            &state,
            &executor,
            1,
            &[3u8; 32],
            a_block_touching_every_family(&actor, 50, contract),
            &[],
        );
        assert_eq!(receipts.len(), 6);
        assert!(
            receipts
                .iter()
                .all(|r| matches!(r.status, TxStatus::Success)),
            "all six must succeed: {:?}",
            receipts.iter().map(|r| r.status).collect::<Vec<_>>()
        );

        let rows = canonical(&db);
        for f in AGREEMENT_CFS {
            assert!(
                rows.iter().any(|(fam, _, _)| fam == f),
                "{f} carries no committed row, so the restart proves nothing about it"
            );
        }

        // The committed scans the RPC uses, through this handle.
        assert_committed_readers_resolve(&db, contract);

        drop(executor);
        drop(state);
        assert_eq!(
            std::sync::Arc::strong_count(&db),
            1,
            "nothing else may hold the database, or the drop below does not \
             actually close it and this test proves nothing about durability"
        );
        drop(db);
        rows
    };

    // Reopen at the same path.
    let db = std::sync::Arc::new(Database::open_default(dir.path()).unwrap());
    assert_eq!(
        canonical(&db),
        expected,
        "every agreement row must survive the restart, byte for byte"
    );
    assert_committed_readers_resolve(&db, contract);
}

/// The committed readers, driven against whichever handle is passed.
fn assert_committed_readers_resolve(db: &Database, contract: Address) {
    let store = AgreementStore::new(db);
    let a = store
        .agreements()
        .get(&[50u8; 32])
        .unwrap()
        .expect("agreement");
    assert_eq!(a.parties.iter().filter(|p| p.signed).count(), 1);
    assert_eq!(
        store
            .agreements()
            .get_by_party(&[0xA1u8; 32])
            .unwrap()
            .iter()
            .map(|a| a.agreement_id)
            .collect::<Vec<_>>(),
        vec![[50u8; 32]],
        "the party index resolves"
    );
    assert!(store.signatures().get(&[51u8; 32]).unwrap().is_some());
    assert!(store.attestations().get(&[52u8; 32]).unwrap().is_some());
    assert!(store.ip_actions().get(&[53u8; 32]).unwrap().is_some());
    assert!(store.executor_links().get(&[54u8; 32]).unwrap().is_some());
    assert_eq!(
        store
            .executor_links()
            .get_by_executor(&contract)
            .unwrap()
            .iter()
            .map(|l| l.link_id)
            .collect::<Vec<_>>(),
        vec![[54u8; 32]],
        "the executor index resolves"
    );
    assert!(store.proofs().get(&[55u8; 32]).unwrap().is_some());
}

// ── The second dispatch surface ──────────────────────────────────────────────

/// `execute_tx_v2` routes agreements through the candidate too.
#[test]
fn the_v2_dispatch_surface_also_stages_agreements() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let actor = KeyPair::generate();
    fund(&db, &actor, 100_000_000);
    let proposer = Address::new([9; 20]);
    let before = canonical(&db);

    let t = TransactionV2 {
        chain_id: CHAIN_ID,
        from: actor.address(),
        fee: 100,
        nonce: 0,
        payload: TxPayload::Agreement(AgreementTxData {
            operation: AgreementOperation::CommitAgreement,
            data: bincode::serialize(&two_party_agreement(60)).unwrap(),
            recipient: Address::ZERO,
        }),
    };
    let sig = *sign(t.signing_hash().as_bytes(), actor.private_key()).as_bytes();
    let key = *actor.public_key().as_bytes();

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    {
        let mut view = ExecutionView::new(&mut overlay);
        let r = executor
            .execute_tx_v2(&mut view, &t, &sig, &key, &proposer, 1, 1000)
            .unwrap();
        assert!(
            matches!(r.status, TxStatus::Success),
            "the v2 surface must execute an agreement commitment: {:?}",
            r.status
        );
        let changed = families_changed(&db, &view);
        assert!(changed.contains(&cf::AGREEMENT_COMMITMENTS));
        assert!(changed.contains(&cf::AGREEMENT_PARTY_INDEX));

        // A second transaction through the SAME surface, which has to see the
        // first one's commitment, and which carries this arm's own
        // `0, // block_timestamp placeholder` into the row it rewrites.
        let t = TransactionV2 {
            chain_id: CHAIN_ID,
            from: actor.address(),
            fee: 100,
            nonce: 1,
            payload: TxPayload::Agreement(AgreementTxData {
                operation: AgreementOperation::SignAgreement,
                data: bincode::serialize(&signature_for(60, 0xA1, 0x61, AgreementRole::Buyer))
                    .unwrap(),
                recipient: Address::ZERO,
            }),
        };
        let sig = *sign(t.signing_hash().as_bytes(), actor.private_key()).as_bytes();
        let r = executor
            .execute_tx_v2(&mut view, &t, &sig, &key, &proposer, 1, 1_700_000_000)
            .unwrap();
        assert!(
            matches!(r.status, TxStatus::Success),
            "the v2 surface must see the commitment it staged a moment ago: {:?}",
            r.status
        );
        let a = AgreementExecutor::v_get_agreement(&view, &[60u8; 32])
            .unwrap()
            .unwrap();
        assert!(a.parties[0].signed);
        assert_eq!(
            (a.updated_at, a.parties[0].signed_at),
            (0, Some(0)),
            "and this arm passes 0 where the block timestamp belongs, exactly \
             like the live one"
        );

        // And a refusal on this arm carries the agreement status code, not a
        // neighbouring subsystem's.
        let t = TransactionV2 {
            chain_id: CHAIN_ID,
            from: actor.address(),
            fee: 100,
            nonce: 2,
            payload: TxPayload::Agreement(AgreementTxData {
                operation: AgreementOperation::SignAgreement,
                data: bincode::serialize(&signature_for(0x7F, 0xA1, 0x6F, AgreementRole::Buyer))
                    .unwrap(),
                recipient: Address::ZERO,
            }),
        };
        let sig = *sign(t.signing_hash().as_bytes(), actor.private_key()).as_bytes();
        let r = executor
            .execute_tx_v2(&mut view, &t, &sig, &key, &proposer, 1, 1000)
            .unwrap();
        assert_eq!(
            r.status,
            TxStatus::Failed(11),
            "a missing agreement must fail IN the agreement arm of this surface"
        );
        assert_eq!(
            StateManager::v_get_nonce(&view, &actor.address()).unwrap(),
            2,
            "and the refusal does not advance the nonce"
        );
    }
    assert_eq!(canonical(&db), before, "and commit nothing");
}

/// A second commitment with the same agreement id, in the same block, is
/// refused by a guard that reads the candidate. A different id is not.
#[test]
fn a_duplicate_agreement_id_in_the_same_block_is_refused() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let actor = KeyPair::generate();
    fund(&db, &actor, 100_000_000);
    let proposer = Address::new([9; 20]);

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);
    for (nonce, id, expect_ok) in [(0u64, 14u8, true), (1, 14, false), (1, 15, true)] {
        let mut a = two_party_agreement(id);
        if !expect_ok {
            // Distinguishable content, so a refusal that nonetheless wrote
            // would be visible below rather than byte-identical to the first.
            a.agreement_commitment = [0xDD; 32];
        }
        let r = executor
            .execute_tx(
                &mut view,
                &tx(&actor, nonce, AgreementOperation::CommitAgreement, &a),
                &proposer,
                1,
                1000,
            )
            .unwrap();
        if expect_ok {
            assert!(
                matches!(r.status, TxStatus::Success),
                "id {id}: {:?}",
                r.status
            );
        } else {
            assert_eq!(
                r.status,
                TxStatus::Failed(11),
                "the repeated id must be refused by the commitment guard"
            );
        }
    }
    // And the refusal did not overwrite the first one.
    assert_eq!(
        AgreementExecutor::v_get_agreement(&view, &[14u8; 32])
            .unwrap()
            .unwrap()
            .agreement_commitment,
        [15u8; 32],
        "the first commitment's own bytes, not the refused second's 0xDD"
    );
}

/// The same, for signature ids: a repeat in one block is refused.
#[test]
fn a_duplicate_signature_id_in_the_same_block_is_refused() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let actor = KeyPair::generate();
    fund(&db, &actor, 100_000_000);
    let proposer = Address::new([9; 20]);

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);
    executor
        .execute_tx(
            &mut view,
            &tx(
                &actor,
                0,
                AgreementOperation::CommitAgreement,
                &two_party_agreement(16),
            ),
            &proposer,
            1,
            1000,
        )
        .unwrap();
    for (nonce, party, sig_id, role, expect_ok) in [
        (1u64, 0xA1u8, 0x66u8, AgreementRole::Buyer, true),
        (2, 0xB2, 0x66, AgreementRole::Seller, false),
        (2, 0xB2, 0x67, AgreementRole::Seller, true),
    ] {
        let r = executor
            .execute_tx(
                &mut view,
                &tx(
                    &actor,
                    nonce,
                    AgreementOperation::SignAgreement,
                    &signature_for(16, party, sig_id, role),
                ),
                &proposer,
                1,
                1000,
            )
            .unwrap();
        if expect_ok {
            assert!(
                matches!(r.status, TxStatus::Success),
                "{sig_id:#x}: {:?}",
                r.status
            );
        } else {
            assert_eq!(
                r.status,
                TxStatus::Failed(11),
                "the repeated signature id must be refused"
            );
        }
    }
}

/// The same, for executor link ids.
#[test]
fn a_duplicate_executor_link_id_in_the_same_block_is_refused() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let actor = KeyPair::generate();
    fund(&db, &actor, 100_000_000);
    let proposer = Address::new([9; 20]);
    let contract = Address::new([0xCC; 20]);

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);
    executor
        .execute_tx(
            &mut view,
            &tx(
                &actor,
                0,
                AgreementOperation::CommitAgreement,
                &two_party_agreement(17),
            ),
            &proposer,
            1,
            1000,
        )
        .unwrap();
    for (nonce, link, expect_ok) in [(1u64, 0xEAu8, true), (2, 0xEA, false), (2, 0xEB, true)] {
        let r = executor
            .execute_tx(
                &mut view,
                &tx(
                    &actor,
                    nonce,
                    AgreementOperation::LinkExecutor,
                    &executor_link(link, 17, contract),
                ),
                &proposer,
                1,
                1000,
            )
            .unwrap();
        if expect_ok {
            assert!(
                matches!(r.status, TxStatus::Success),
                "{link:#x}: {:?}",
                r.status
            );
        } else {
            assert_eq!(
                r.status,
                TxStatus::Failed(11),
                "the repeated link id must be refused"
            );
        }
    }
}

// ── The other five families ──────────────────────────────────────────────────

fn attestation(id: u8, issuer: &Address, target: u8) -> AttestationPacket {
    AttestationPacket {
        attestation_id: [id; 32],
        target_ref: AttestationTarget::Agreement([target; 32]),
        issuer_address: *issuer,
        issuer_class: AttestationIssuerClass::NotaryPublic,
        attestation_type: AttestationType::Notarization,
        notary_commitment: [id.wrapping_add(7); 32],
        jurisdiction_code: "US-NY".to_string(),
        valid_from: 1000,
        expiry: Some(9_000_000),
        revocation_ref: None,
        status: AttestationStatus::Active,
        created_at: 1000,
        recorded_at_height: 1,
        policy_id: [12u8; 32],
    }
}

fn ip_action(id: u8) -> IpRightsAction {
    IpRightsAction {
        action_id: [id; 32],
        ip_asset_commitment: [id.wrapping_add(3); 32],
        asset_type: IpAssetType::Patent,
        action_type: IpActionType::License,
        scope_commitment: [id.wrapping_add(4); 32],
        rightsholder_ref: PartyRef::Commitment([0xA1; 32]),
        counterparty_ref: Some(PartyRef::Commitment([0xB2; 32])),
        policy_id: [12u8; 32],
        valid_from: 1000,
        expiry: Some(9_000_000),
        revocation_ref: None,
        status: IpActionStatus::Active,
        created_at: 1000,
        recorded_at_height: 1,
        agreement_id: None,
        attachments: vec![],
    }
}

fn executor_link(link: u8, agreement: u8, contract: Address) -> ExecutorLink {
    ExecutorLink {
        link_id: [link; 32],
        agreement_id: [agreement; 32],
        executor_contract: contract,
        executor_interface_id: [link.wrapping_add(1); 32],
        terms_commitment: [link.wrapping_add(2); 32],
        activation_policy_id: [12u8; 32],
        state: ExecutorState::Draft,
        created_at: 1000,
        updated_at: 1000,
        created_at_height: 1,
        activation_proof_id: None,
    }
}

fn proof_envelope(id: u8) -> AgreementProofEnvelope {
    AgreementProofEnvelope {
        proof_id: [id; 32],
        profile: AgreementProofProfile::SignedByRoles,
        profile_id: "agreement.signed_by_roles.v1".to_string(),
        policy_ids: vec![[12u8; 32]],
        public_inputs: vec![1, 2, 3],
        proof_data: vec![4u8; 48],
        proof_type: AgreementProofType::Mock,
        subject_nullifier: [id.wrapping_add(5); 32],
        generated_at: 1000,
        expires_at: 9_000_000,
    }
}

/// A second attestation with the same id, in the same block, is refused by a
/// guard that reads the candidate. A different id is not.
///
/// The control is what makes this about the candidate rather than about
/// attestations being refused generally.
#[test]
fn a_duplicate_attestation_in_the_same_block_is_refused() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let issuer = KeyPair::generate();
    fund(&db, &issuer, 100_000_000);
    let proposer = Address::new([9; 20]);
    let addr = issuer.address();

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);

    for (nonce, id, expect_ok) in [(0u64, 0x70u8, true), (1, 0x70, false), (1, 0x71, true)] {
        let r = executor
            .execute_tx(
                &mut view,
                &tx(
                    &issuer,
                    nonce,
                    AgreementOperation::CreateAttestation,
                    &attestation(id, &addr, 10),
                ),
                &proposer,
                1,
                1000,
            )
            .unwrap();
        if expect_ok {
            assert!(
                matches!(r.status, TxStatus::Success),
                "id {id:#x}: {:?}",
                r.status
            );
        } else {
            assert_eq!(
                r.status,
                TxStatus::Failed(11),
                "the repeated id must be refused by the attestation guard"
            );
        }
    }
    assert!(AgreementExecutor::v_get_attestation(&view, &[0x70u8; 32])
        .unwrap()
        .is_some());
    assert!(AgreementExecutor::v_get_attestation(&view, &[0x71u8; 32])
        .unwrap()
        .is_some());
}

/// The same, for IP actions.
#[test]
fn a_duplicate_ip_action_in_the_same_block_is_refused() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let actor = KeyPair::generate();
    fund(&db, &actor, 100_000_000);
    let proposer = Address::new([9; 20]);

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);

    for (nonce, id, expect_ok) in [(0u64, 0x80u8, true), (1, 0x80, false), (1, 0x81, true)] {
        let r = executor
            .execute_tx(
                &mut view,
                &tx(
                    &actor,
                    nonce,
                    AgreementOperation::RecordIpAction,
                    &ip_action(id),
                ),
                &proposer,
                1,
                1000,
            )
            .unwrap();
        if expect_ok {
            assert!(
                matches!(r.status, TxStatus::Success),
                "id {id:#x}: {:?}",
                r.status
            );
        } else {
            assert_eq!(
                r.status,
                TxStatus::Failed(11),
                "the repeated id must be refused"
            );
        }
    }
}

/// The same, for proofs.
#[test]
fn a_duplicate_proof_in_the_same_block_is_refused() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let actor = KeyPair::generate();
    fund(&db, &actor, 100_000_000);
    let proposer = Address::new([9; 20]);

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);

    for (nonce, id, expect_ok) in [(0u64, 0x90u8, true), (1, 0x90, false), (1, 0x91, true)] {
        let r = executor
            .execute_tx(
                &mut view,
                &tx(
                    &actor,
                    nonce,
                    AgreementOperation::SubmitProof,
                    &proof_envelope(id),
                ),
                &proposer,
                1,
                1000,
            )
            .unwrap();
        if expect_ok {
            assert!(
                matches!(r.status, TxStatus::Success),
                "id {id:#x}: {:?}",
                r.status
            );
        } else {
            assert_eq!(
                r.status,
                TxStatus::Failed(11),
                "the repeated id must be refused"
            );
        }
    }
}

/// An executor link finds the agreement committed earlier in the same block,
/// and the link can then be ACTIVATED in that same block -- which reads the
/// `Draft` state the link write just staged.
#[test]
fn an_executor_link_is_created_and_activated_within_one_block() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let actor = KeyPair::generate();
    fund(&db, &actor, 100_000_000);
    let proposer = Address::new([9; 20]);
    let contract = Address::new([0xCC; 20]);

    #[derive(serde::Serialize)]
    struct LinkId {
        link_id: [u8; 32],
    }

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);

    executor
        .execute_tx(
            &mut view,
            &tx(
                &actor,
                0,
                AgreementOperation::CommitAgreement,
                &two_party_agreement(70),
            ),
            &proposer,
            1,
            1000,
        )
        .unwrap();
    let r = executor
        .execute_tx(
            &mut view,
            &tx(
                &actor,
                1,
                AgreementOperation::LinkExecutor,
                &executor_link(0xE1, 70, contract),
            ),
            &proposer,
            1,
            1000,
        )
        .unwrap();
    assert!(
        matches!(r.status, TxStatus::Success),
        "the link must find the agreement staged a moment ago: {:?}",
        r.status
    );
    assert_eq!(
        AgreementExecutor::v_get_executor_link(&view, &[0xE1u8; 32])
            .unwrap()
            .unwrap()
            .state,
        ExecutorState::Draft
    );

    let r = executor
        .execute_tx(
            &mut view,
            &tx(
                &actor,
                2,
                AgreementOperation::ActivateExecutor,
                &LinkId {
                    link_id: [0xE1; 32],
                },
            ),
            &proposer,
            1,
            1000,
        )
        .unwrap();
    assert!(
        matches!(r.status, TxStatus::Success),
        "activation must read the Draft state from the candidate: {:?}",
        r.status
    );
    assert_eq!(
        AgreementExecutor::v_get_executor_link(&view, &[0xE1u8; 32])
            .unwrap()
            .unwrap()
            .state,
        ExecutorState::Active
    );

    // The discriminator: the SECOND activation must now be refused, because
    // the guard reads the `Active` state the first one staged.
    let r = executor
        .execute_tx(
            &mut view,
            &tx(
                &actor,
                3,
                AgreementOperation::ActivateExecutor,
                &LinkId {
                    link_id: [0xE1; 32],
                },
            ),
            &proposer,
            1,
            1000,
        )
        .unwrap();
    assert_eq!(
        r.status,
        TxStatus::Failed(11),
        "only a draft executor may be activated, and the state is in the candidate"
    );
}

/// Without the agreement, the same link is refused.
#[test]
fn without_the_agreement_the_same_executor_link_is_refused() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let actor = KeyPair::generate();
    fund(&db, &actor, 100_000_000);
    let proposer = Address::new([9; 20]);

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);
    let r = executor
        .execute_tx(
            &mut view,
            &tx(
                &actor,
                0,
                AgreementOperation::LinkExecutor,
                &executor_link(0xE2, 71, Address::new([0xCC; 20])),
            ),
            &proposer,
            1,
            1000,
        )
        .unwrap();
    assert_eq!(r.status, TxStatus::Failed(11));
    assert!(families_changed(&db, &view).is_empty());
    assert_eq!(
        StateManager::v_get_nonce(&view, &actor.address()).unwrap(),
        0,
        "a refused link does not advance the account nonce"
    );
}

/// Two links to one executor contract in one block: the index holds BOTH.
#[test]
fn two_links_for_one_executor_accumulate_in_the_index() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let actor = KeyPair::generate();
    fund(&db, &actor, 100_000_000);
    let proposer = Address::new([9; 20]);
    let contract = Address::new([0xCC; 20]);

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);
    executor
        .execute_tx(
            &mut view,
            &tx(
                &actor,
                0,
                AgreementOperation::CommitAgreement,
                &two_party_agreement(72),
            ),
            &proposer,
            1,
            1000,
        )
        .unwrap();
    for (n, link) in [0xE3u8, 0xE4u8].into_iter().enumerate() {
        let r = executor
            .execute_tx(
                &mut view,
                &tx(
                    &actor,
                    (n + 1) as u64,
                    AgreementOperation::LinkExecutor,
                    &executor_link(link, 72, contract),
                ),
                &proposer,
                1,
                1000,
            )
            .unwrap();
        assert!(matches!(r.status, TxStatus::Success), "{:?}", r.status);
    }

    assert_eq!(
        AgreementExecutor::v_get_executor_link_ids(&view, &contract).unwrap(),
        vec![[0xE3u8; 32], [0xE4u8; 32]],
        "both link ids, in order -- the second must have seen the first"
    );
}

// ── Corrupt rows: every family, with the staged state named ─────────────────

/// One corrupt-row case: which family is corrupted, the operation that has to
/// READ it, and the exact candidate state the failure is required to leave.
struct CorruptCase {
    family: &'static str,
    label: &'static str,
    /// Agreement families whose candidate contents must differ from committed,
    /// and nothing else. Named exactly -- not an allowed set.
    staged: &'static [&'static str],
    /// The sender's nonce after the failure. `0` means the read failed before
    /// the fee was charged; `1` means execution got past the guards.
    nonce: u64,
}

/// A corrupt row makes the routed transaction ERROR; it is never read as
/// absence. What the candidate holds afterwards is asserted positively, family
/// by family, key by key.
///
/// This is the difference between "no such agreement" and "that agreement's row
/// is corrupt", and every guard here branches on exactly that. A candidate
/// reader that swallowed a decode failure into `None` would turn corruption
/// into a duplicate-id opportunity, or into a signature recorded against an
/// agreement whose parties could not be read.
///
/// Seven of the eight families are covered here: five corrupt PRIMARY rows and
/// both corrupt INDEX rows. The eighth, `AGREEMENT_PROOFS`, has no decoding
/// reader reachable from dispatch -- `SubmitProof` guards with `contains` --
/// and is pinned separately, as a preserved defect, by
/// `a_corrupt_proof_row_is_read_as_presence_not_as_corruption`.
///
/// The two index cases are the ones that leave state: the primary write
/// precedes the index append, so the commitment (or link) is staged and the
/// fee has been charged when the append fails. Both are asserted as exact
/// bytes, and the corrupt index row is asserted UNCHANGED.
#[test]
fn corrupt_rows_error_through_dispatch_with_exactly_this_staged() {
    #[derive(serde::Serialize)]
    struct SignatureId {
        signature_id: [u8; 32],
    }
    #[derive(serde::Serialize)]
    struct AttestationId {
        attestation_id: [u8; 32],
    }
    #[derive(serde::Serialize)]
    struct ActionId {
        action_id: [u8; 32],
    }
    #[derive(serde::Serialize)]
    struct LinkId {
        link_id: [u8; 32],
    }

    const CORRUPT: &[u8] = b"not a valid row";
    let contract = Address::new([0xCC; 20]);

    let cases = [
        CorruptCase {
            family: cf::AGREEMENT_COMMITMENTS,
            label: "commitment",
            staged: &[],
            nonce: 0,
        },
        CorruptCase {
            family: cf::AGREEMENT_SIGNATURES,
            label: "signature",
            staged: &[],
            nonce: 0,
        },
        CorruptCase {
            family: cf::AGREEMENT_ATTESTATIONS,
            label: "attestation",
            staged: &[],
            nonce: 0,
        },
        CorruptCase {
            family: cf::AGREEMENT_IP_ACTIONS,
            label: "ip action",
            staged: &[],
            nonce: 0,
        },
        CorruptCase {
            family: cf::AGREEMENT_EXECUTOR_LINKS,
            label: "executor link",
            staged: &[],
            nonce: 0,
        },
        CorruptCase {
            family: cf::AGREEMENT_PARTY_INDEX,
            label: "party index",
            staged: &[cf::AGREEMENT_COMMITMENTS],
            nonce: 1,
        },
        CorruptCase {
            family: cf::AGREEMENT_EXECUTOR_INDEX,
            label: "executor index",
            staged: &[cf::AGREEMENT_EXECUTOR_LINKS],
            nonce: 1,
        },
    ];

    for case in cases {
        let (_state, db, _dir, executor) = setup_with_params(params());
        let actor = KeyPair::generate();
        fund(&db, &actor, 100_000_000);
        let proposer = Address::new([9; 20]);

        // Keys written by hand, from the schema and not from the key builders,
        // so a change to a builder cannot silently move this test with it.
        let key: Vec<u8> = match case.family {
            f if f == cf::AGREEMENT_PARTY_INDEX => vec![0xA1u8; 32],
            f if f == cf::AGREEMENT_EXECUTOR_INDEX => contract.as_ref().to_vec(),
            f if f == cf::AGREEMENT_SIGNATURES => vec![0x51u8; 32],
            f if f == cf::AGREEMENT_ATTESTATIONS => vec![0x70u8; 32],
            f if f == cf::AGREEMENT_IP_ACTIONS => vec![0x80u8; 32],
            f if f == cf::AGREEMENT_EXECUTOR_LINKS => vec![0xE1u8; 32],
            _ => vec![10u8; 32],
        };

        // What each guard needs in order to REACH the corrupt row.
        let (op, data): (AgreementOperation, Vec<u8>) = match case.family {
            f if f == cf::AGREEMENT_COMMITMENTS => (
                AgreementOperation::SignAgreement,
                bincode::serialize(&signature_for(10, 0xA1, 0x51, AgreementRole::Buyer)).unwrap(),
            ),
            f if f == cf::AGREEMENT_PARTY_INDEX => (
                AgreementOperation::CommitAgreement,
                bincode::serialize(&two_party_agreement(10)).unwrap(),
            ),
            f if f == cf::AGREEMENT_SIGNATURES => (
                AgreementOperation::RevokeSignature,
                bincode::serialize(&SignatureId {
                    signature_id: [0x51; 32],
                })
                .unwrap(),
            ),
            f if f == cf::AGREEMENT_ATTESTATIONS => (
                AgreementOperation::RevokeAttestation,
                bincode::serialize(&AttestationId {
                    attestation_id: [0x70; 32],
                })
                .unwrap(),
            ),
            f if f == cf::AGREEMENT_IP_ACTIONS => (
                AgreementOperation::UpdateIpAction,
                bincode::serialize(&ActionId {
                    action_id: [0x80; 32],
                })
                .unwrap(),
            ),
            f if f == cf::AGREEMENT_EXECUTOR_LINKS => (
                AgreementOperation::ActivateExecutor,
                bincode::serialize(&LinkId {
                    link_id: [0xE1; 32],
                })
                .unwrap(),
            ),
            _ => {
                // LinkExecutor reads the index only after it has found the
                // agreement, so that has to be canonically present and valid.
                AgreementStore::new(&db)
                    .agreements()
                    .put(&two_party_agreement(10))
                    .unwrap();
                (
                    AgreementOperation::LinkExecutor,
                    bincode::serialize(&executor_link(0xE1, 10, contract)).unwrap(),
                )
            }
        };
        db.put(case.family, &key, CORRUPT).unwrap();

        let before = canonical(&db);
        let t = TransactionV2 {
            chain_id: CHAIN_ID,
            from: actor.address(),
            fee: 100,
            nonce: 0,
            payload: TxPayload::Agreement(AgreementTxData {
                operation: op,
                data,
                recipient: Address::ZERO,
            }),
        };
        let sig = *sign(t.signing_hash().as_bytes(), actor.private_key()).as_bytes();
        let t = SignedTransaction::new_v2(t, sig, *actor.public_key().as_bytes());

        let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
        {
            let mut view = ExecutionView::new(&mut overlay);
            let outcome = executor.execute_tx(&mut view, &t, &proposer, 1, 1000);
            let err = outcome.err().unwrap_or_else(|| {
                panic!(
                    "a corrupt {} row must ERROR, not be read as absence",
                    case.label
                )
            });
            let text = err.to_string();
            assert!(
                text.contains("Serialization") || text.contains("Storage"),
                "the {} failure must name the decode, not something else: {text}",
                case.label
            );

            // Exactly these families changed. Not a subset, not an allowed set.
            assert_eq!(
                families_changed(&db, &view),
                case.staged.to_vec(),
                "{}: the candidate must hold exactly the families named for \
                 this case",
                case.label
            );

            // And exactly this content, where anything is staged at all.
            if case.family == cf::AGREEMENT_PARTY_INDEX {
                assert_eq!(
                    view.get(cf::AGREEMENT_COMMITMENTS, &[10u8; 32])
                        .unwrap()
                        .as_deref(),
                    Some(&bincode::serialize(&two_party_agreement(10)).unwrap()[..]),
                    "the commitment written before the failing append, byte for byte"
                );
            }
            if case.family == cf::AGREEMENT_EXECUTOR_INDEX {
                assert_eq!(
                    view.get(cf::AGREEMENT_EXECUTOR_LINKS, &[0xE1u8; 32])
                        .unwrap()
                        .as_deref(),
                    Some(&bincode::serialize(&executor_link(0xE1, 10, contract)).unwrap()[..]),
                    "the link written before the failing append, byte for byte"
                );
            }

            // The corrupt row itself is never rewritten or repaired.
            assert_eq!(
                view.get(case.family, &key).unwrap().as_deref(),
                Some(CORRUPT),
                "{}: the corrupt bytes must be left exactly as they were",
                case.label
            );

            // The account side, positively: whether the fee was charged says
            // where in the arm the failure happened.
            assert_eq!(
                StateManager::v_get_nonce(&view, &actor.address()).unwrap(),
                case.nonce,
                "{}: nonce after the failure",
                case.label
            );
        }
        assert_eq!(
            canonical(&db),
            before,
            "and nothing may be committed for {}",
            case.label
        );
    }
}

// ── Behaviours reproduced deliberately, not fixed ────────────────────────────

/// `SubmitProof` guards with `contains`, so a CORRUPT proof row is refused as a
/// duplicate rather than reported as corruption.
///
/// Preserved, not fixed: making it decode would change which transactions are
/// valid, which is a consensus change and belongs in separately activated work.
/// Pinned here so the migration cannot be blamed for it later, and so a future
/// fix has to change this test on purpose.
#[test]
fn a_corrupt_proof_row_is_read_as_presence_not_as_corruption() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let actor = KeyPair::generate();
    fund(&db, &actor, 100_000_000);
    let proposer = Address::new([9; 20]);
    db.put(cf::AGREEMENT_PROOFS, &[0x90u8; 32], b"not a valid row")
        .unwrap();

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);
    let r = executor
        .execute_tx(
            &mut view,
            &tx(
                &actor,
                0,
                AgreementOperation::SubmitProof,
                &proof_envelope(0x90),
            ),
            &proposer,
            1,
            1000,
        )
        .unwrap();
    assert_eq!(
        r.status,
        TxStatus::Failed(11),
        "the corrupt row is treated as an existing proof -- a FAILURE, not the \
         error a decoding guard would raise"
    );
    assert_eq!(
        view.get(cf::AGREEMENT_PROOFS, &[0x90u8; 32])
            .unwrap()
            .as_deref(),
        Some(&b"not a valid row"[..]),
        "and the corrupt bytes are left exactly as they were"
    );
    assert_eq!(
        families_changed(&db, &view),
        Vec::<&str>::new(),
        "with nothing staged in any agreement family"
    );
    assert_eq!(
        StateManager::v_get_nonce(&view, &actor.address()).unwrap(),
        0,
        "and no fee charged -- the guard refused before the deduct"
    );
}

/// `VerifyProof` verifies nothing: it charges the fee, advances the nonce and
/// returns success for a proof id that was never submitted.
///
/// Preserved, not fixed, for the same reason. It is pinned in both directions:
/// success AND no write to any agreement family.
#[test]
fn verify_proof_succeeds_for_a_proof_that_does_not_exist() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let actor = KeyPair::generate();
    fund(&db, &actor, 100_000_000);
    let proposer = Address::new([9; 20]);

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);
    let t = TransactionV2 {
        chain_id: CHAIN_ID,
        from: actor.address(),
        fee: 100,
        nonce: 0,
        payload: TxPayload::Agreement(AgreementTxData {
            operation: AgreementOperation::VerifyProof,
            // Not a proof envelope at all. It is never deserialized.
            data: b"\xff\xff\xff\xff".to_vec(),
            recipient: Address::ZERO,
        }),
    };
    let sig = *sign(t.signing_hash().as_bytes(), actor.private_key()).as_bytes();
    let t = SignedTransaction::new_v2(t, sig, *actor.public_key().as_bytes());
    let r = executor
        .execute_tx(&mut view, &t, &proposer, 1, 1000)
        .unwrap();

    assert!(
        matches!(r.status, TxStatus::Success),
        "verification of a non-existent proof succeeds: {:?}",
        r.status
    );
    assert!(
        families_changed(&db, &view).is_empty(),
        "and writes nothing to any agreement family"
    );
    assert_eq!(
        StateManager::v_get_nonce(&view, &actor.address()).unwrap(),
        1,
        "while still charging the fee and advancing the nonce"
    );
}

/// Revoking a signature deletes the signature row and leaves the agreement's
/// party flag SET -- so an `Executed` agreement stays executed with one
/// signature missing.
///
/// Preserved, not fixed.
#[test]
fn revoking_a_signature_leaves_the_party_marked_signed() {
    #[derive(serde::Serialize)]
    struct SignatureId {
        signature_id: [u8; 32],
    }
    let (_state, db, _dir, executor) = setup_with_params(params());
    let actor = KeyPair::generate();
    fund(&db, &actor, 100_000_000);
    let proposer = Address::new([9; 20]);

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);
    for t in [
        tx(
            &actor,
            0,
            AgreementOperation::CommitAgreement,
            &two_party_agreement(60),
        ),
        tx(
            &actor,
            1,
            AgreementOperation::SignAgreement,
            &signature_for(60, 0xA1, 0x61, AgreementRole::Buyer),
        ),
        tx(
            &actor,
            2,
            AgreementOperation::SignAgreement,
            &signature_for(60, 0xB2, 0x62, AgreementRole::Seller),
        ),
    ] {
        let r = executor
            .execute_tx(&mut view, &t, &proposer, 1, 1000)
            .unwrap();
        assert!(matches!(r.status, TxStatus::Success), "{:?}", r.status);
    }
    assert_eq!(
        AgreementExecutor::v_get_agreement(&view, &[60u8; 32])
            .unwrap()
            .unwrap()
            .status,
        AgreementStatus::Executed
    );

    let t = TransactionV2 {
        chain_id: CHAIN_ID,
        from: actor.address(),
        fee: 100,
        nonce: 3,
        payload: TxPayload::Agreement(AgreementTxData {
            operation: AgreementOperation::RevokeSignature,
            data: bincode::serialize(&SignatureId {
                signature_id: [0x61; 32],
            })
            .unwrap(),
            recipient: Address::ZERO,
        }),
    };
    let sig = *sign(t.signing_hash().as_bytes(), actor.private_key()).as_bytes();
    let t = SignedTransaction::new_v2(t, sig, *actor.public_key().as_bytes());
    let r = executor
        .execute_tx(&mut view, &t, &proposer, 1, 1000)
        .unwrap();
    assert!(matches!(r.status, TxStatus::Success), "{:?}", r.status);

    assert!(
        AgreementExecutor::v_get_signature(&view, &[0x61u8; 32])
            .unwrap()
            .is_none(),
        "the signature row is gone"
    );
    let a = AgreementExecutor::v_get_agreement(&view, &[60u8; 32])
        .unwrap()
        .unwrap();
    assert!(
        a.parties.iter().all(|p| p.signed),
        "but both parties are still marked signed"
    );
    assert_eq!(
        a.status,
        AgreementStatus::Executed,
        "and the agreement is still Executed with one of its two signatures deleted"
    );
}

/// Both dispatch arms pass a literal `0` where the block timestamp belongs, so
/// every agreement timestamp the executor writes is 0 regardless of the block.
///
/// Preserved, not fixed: correcting it changes committed bytes and therefore
/// the state root. Pinned so a later fix is a deliberate one.
#[test]
fn the_block_timestamp_reaching_agreement_operations_is_always_zero() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let actor = KeyPair::generate();
    fund(&db, &actor, 100_000_000);
    let proposer = Address::new([9; 20]);

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);
    // A block timestamp that is emphatically not zero.
    for t in [
        tx(
            &actor,
            0,
            AgreementOperation::CommitAgreement,
            &two_party_agreement(80),
        ),
        tx(
            &actor,
            1,
            AgreementOperation::SignAgreement,
            &signature_for(80, 0xA1, 0x81, AgreementRole::Buyer),
        ),
    ] {
        let r = executor
            .execute_tx(&mut view, &t, &proposer, 1, 1_700_000_000)
            .unwrap();
        assert!(matches!(r.status, TxStatus::Success), "{:?}", r.status);
    }

    let a = AgreementExecutor::v_get_agreement(&view, &[80u8; 32])
        .unwrap()
        .unwrap();
    assert_eq!(
        a.updated_at, 0,
        "the signature bumped `updated_at` to the placeholder, not to 1_700_000_000"
    );
    assert_eq!(
        a.parties[0].signed_at,
        Some(0),
        "and recorded the signing time as 0"
    );
}

// ── The two accumulating indexes, measured ───────────────────────────────────

/// Twenty thousand ids, spelled the same way for both index families.
fn twenty_thousand_ids() -> Vec<[u8; 32]> {
    (0..20_000u32)
        .map(|i| {
            let mut id = [0u8; 32];
            id[..4].copy_from_slice(&i.to_be_bytes());
            id
        })
        .collect()
}

/// A 640,008-byte party index is refused by the ceiling, and nothing canonical
/// changes.
///
/// `v_add_to_party_index` reads the whole list, pushes one id and re-serializes
/// it. Nothing caps its length, so the value grows without bound and the
/// re-serialization cost is linear in it. This measures ONE size. It does not
/// and cannot establish that no input reaches an allocator abort; a cap would
/// change which transactions are valid and belongs in separately activated
/// work.
#[test]
fn a_640_kb_party_index_is_refused_by_the_ceiling_without_canonical_change() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let actor = KeyPair::generate();
    fund(&db, &actor, 100_000_000);
    let proposer = Address::new([9; 20]);
    let party = [0xA1u8; 32];

    let existing = twenty_thousand_ids();
    let committed_index = bincode::serialize(&existing).unwrap();
    assert_eq!(
        committed_index.len(),
        640_008,
        "the fixture must be exactly the size this test is named for"
    );
    db.put(cf::AGREEMENT_PARTY_INDEX, &party, &committed_index)
        .unwrap();
    let before = canonical(&db);

    let t = tx(
        &actor,
        0,
        AgreementOperation::CommitAgreement,
        &two_party_agreement(90),
    );

    {
        let mut overlay = ApplicationOverlay::new(&db, 4_096);
        let mut view = ExecutionView::new(&mut overlay);
        let err = executor
            .execute_tx(&mut view, &t, &proposer, 1, 1000)
            .expect_err("an index far larger than the ceiling must be refused");
        assert!(
            err.to_string().contains("limit"),
            "refused by the ceiling, not by something else: {err}"
        );
        // Execution REACHED the index append: the commitment row is staged, so
        // the refusal is at the index write and not before it.
        assert!(
            view.get(cf::AGREEMENT_COMMITMENTS, &[90u8; 32])
                .unwrap()
                .is_some(),
            "the commitment must be staged, which is what puts the failure at \
             the party-index write"
        );
        assert_eq!(
            view.get(cf::AGREEMENT_PARTY_INDEX, &party).unwrap(),
            Some(committed_index.clone()),
            "the candidate must still see the committed index, byte for byte"
        );
    }
    assert_eq!(canonical(&db), before, "and nothing is committed");

    // With room, it appends exactly one and preserves all 20,000 -- compared
    // in full, not sampled.
    {
        let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
        let mut view = ExecutionView::new(&mut overlay);
        let r = executor
            .execute_tx(&mut view, &t, &proposer, 1, 1000)
            .unwrap();
        assert!(matches!(r.status, TxStatus::Success), "{:?}", r.status);
        let ids = AgreementExecutor::v_get_party_agreement_ids(&view, &party).unwrap();
        assert_eq!(ids.len(), 20_001, "appended, not replaced");
        assert_eq!(
            &ids[..20_000],
            &existing[..],
            "every existing id preserved, in order"
        );
        assert_eq!(ids[20_000], [90u8; 32], "and the new one last");
    }
    assert_eq!(canonical(&db), before, "still nothing committed");
}

/// The same measurement for the executor index, which is keyed by a 20-byte
/// ADDRESS rather than a 32-byte hash and holds link ids.
#[test]
fn a_640_kb_executor_index_is_refused_by_the_ceiling_without_canonical_change() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let actor = KeyPair::generate();
    fund(&db, &actor, 100_000_000);
    let proposer = Address::new([9; 20]);
    let contract = Address::new([0xCC; 20]);

    AgreementStore::new(&db)
        .agreements()
        .put(&two_party_agreement(91))
        .unwrap();
    let existing = twenty_thousand_ids();
    let committed_index = bincode::serialize(&existing).unwrap();
    assert_eq!(committed_index.len(), 640_008);
    db.put(
        cf::AGREEMENT_EXECUTOR_INDEX,
        contract.as_ref(),
        &committed_index,
    )
    .unwrap();
    let before = canonical(&db);

    let t = tx(
        &actor,
        0,
        AgreementOperation::LinkExecutor,
        &executor_link(0xF1, 91, contract),
    );

    {
        let mut overlay = ApplicationOverlay::new(&db, 4_096);
        let mut view = ExecutionView::new(&mut overlay);
        let err = executor
            .execute_tx(&mut view, &t, &proposer, 1, 1000)
            .expect_err("an index far larger than the ceiling must be refused");
        assert!(
            err.to_string().contains("limit"),
            "refused by the ceiling, not by something else: {err}"
        );
        assert!(
            view.get(cf::AGREEMENT_EXECUTOR_LINKS, &[0xF1u8; 32])
                .unwrap()
                .is_some(),
            "the link must be staged, which is what puts the failure at the \
             executor-index write"
        );
        assert_eq!(
            view.get(cf::AGREEMENT_EXECUTOR_INDEX, contract.as_ref())
                .unwrap(),
            Some(committed_index.clone()),
            "the candidate must still see the committed index, byte for byte"
        );
    }
    assert_eq!(canonical(&db), before, "and nothing is committed");

    {
        let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
        let mut view = ExecutionView::new(&mut overlay);
        let r = executor
            .execute_tx(&mut view, &t, &proposer, 1, 1000)
            .unwrap();
        assert!(matches!(r.status, TxStatus::Success), "{:?}", r.status);
        let ids = AgreementExecutor::v_get_executor_link_ids(&view, &contract).unwrap();
        assert_eq!(ids.len(), 20_001, "appended, not replaced");
        assert_eq!(
            &ids[..20_000],
            &existing[..],
            "every existing id preserved, in order"
        );
        assert_eq!(ids[20_000], [0xF1u8; 32], "and the new one last");
    }
    assert_eq!(canonical(&db), before, "still nothing committed");
}

/// The committed agreement readers are unpaginated whole-family scans.
///
/// `list_active` and `get_by_agreement` walk every row in their column family
/// and return one `Vec`. There is no limit, offset or cursor to ask for fewer.
/// Pinned rather than fixed: these are the RPC's readers and changing their
/// signatures is API work, not part of moving writes onto the candidate.
#[test]
fn the_committed_agreement_readers_return_two_thousand_rows_whole() {
    let dir = tempfile::TempDir::new().unwrap();
    let db = Database::open_default(dir.path()).unwrap();
    let store = AgreementStore::new(&db);

    for i in 0..2_000u32 {
        let mut a = two_party_agreement(1);
        let mut id = [0u8; 32];
        id[..4].copy_from_slice(&i.to_be_bytes());
        a.agreement_id = id;
        a.status = AgreementStatus::Executed;
        store.agreements().put(&a).unwrap();

        let mut link = executor_link(0, 1, Address::new([0xCC; 20]));
        link.link_id = id;
        link.agreement_id = [1u8; 32];
        link.state = ExecutorState::Active;
        store.executor_links().put(&link).unwrap();
    }

    assert_eq!(
        store.agreements().list_active().unwrap().len(),
        2_000,
        "every executed agreement, in one Vec, with no way to ask for fewer"
    );
    assert_eq!(store.executor_links().list_active().unwrap().len(), 2_000);
    assert_eq!(
        store
            .executor_links()
            .get_by_agreement(&[1u8; 32])
            .unwrap()
            .len(),
        2_000,
        "and `get_by_agreement` scans the whole family to filter"
    );
}

// ── Authority: there is almost none, and that is inherited ──────────────────

/// Signing is not bound to the sender in any way.
///
/// `SignAgreement` takes the party reference from the PAYLOAD and never
/// compares it to the transaction's sender. A key generated a moment ago, with
/// no relationship to either party, signs on behalf of the buyer and the
/// agreement advances exactly as if the buyer had signed it.
///
/// Preserved, not fixed: binding signatures to senders changes which
/// transactions are valid, which is a consensus change.
#[test]
fn any_sender_can_sign_on_behalf_of_any_party() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let owner = KeyPair::generate();
    let stranger = KeyPair::generate();
    fund(&db, &owner, 100_000_000);
    fund(&db, &stranger, 100_000_000);
    let proposer = Address::new([9; 20]);
    assert_ne!(owner.address(), stranger.address());

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);
    executor
        .execute_tx(
            &mut view,
            &tx(
                &owner,
                0,
                AgreementOperation::CommitAgreement,
                &two_party_agreement(100),
            ),
            &proposer,
            1,
            1000,
        )
        .unwrap();

    for (n, (party, sig_id, role)) in [
        (0xA1u8, 0xC1u8, AgreementRole::Buyer),
        (0xB2, 0xC2, AgreementRole::Seller),
    ]
    .into_iter()
    .enumerate()
    {
        let r = executor
            .execute_tx(
                &mut view,
                &tx(
                    &stranger,
                    n as u64,
                    AgreementOperation::SignAgreement,
                    &signature_for(100, party, sig_id, role),
                ),
                &proposer,
                1,
                1000,
            )
            .unwrap();
        assert!(matches!(r.status, TxStatus::Success), "{:?}", r.status);
    }

    assert_eq!(
        AgreementExecutor::v_get_agreement(&view, &[100u8; 32])
            .unwrap()
            .unwrap()
            .status,
        AgreementStatus::Executed,
        "a stranger signed for both parties and the agreement is Executed"
    );
}

/// A signature whose party is not in the agreement is stored anyway, and
/// rewrites the agreement row while flipping no flag.
#[test]
fn a_signature_for_a_party_outside_the_agreement_is_still_recorded() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let actor = KeyPair::generate();
    fund(&db, &actor, 100_000_000);
    let proposer = Address::new([9; 20]);

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);
    executor
        .execute_tx(
            &mut view,
            &tx(
                &actor,
                0,
                AgreementOperation::CommitAgreement,
                &two_party_agreement(101),
            ),
            &proposer,
            1,
            1000,
        )
        .unwrap();
    let r = executor
        .execute_tx(
            &mut view,
            &tx(
                &actor,
                1,
                AgreementOperation::SignAgreement,
                // 0xFE is neither of this agreement's two parties.
                &signature_for(101, 0xFE, 0xCF, AgreementRole::Witness),
            ),
            &proposer,
            1,
            1000,
        )
        .unwrap();
    assert!(matches!(r.status, TxStatus::Success), "{:?}", r.status);

    assert!(
        AgreementExecutor::v_get_signature(&view, &[0xCFu8; 32])
            .unwrap()
            .is_some(),
        "the signature row is stored for a party that is not bound"
    );
    let a = AgreementExecutor::v_get_agreement(&view, &[101u8; 32])
        .unwrap()
        .unwrap();
    assert!(a.parties.iter().all(|p| !p.signed), "no party flag flipped");
    assert_eq!(
        a.status,
        AgreementStatus::PendingSignatures,
        "and the status is unchanged"
    );
}

/// Terminating, voiding, revoking IP rights and terminating an executor link
/// all succeed for a sender with no connection to the agreement.
#[test]
fn any_sender_can_terminate_void_and_revoke_anything() {
    #[derive(serde::Serialize)]
    struct AgreementId {
        agreement_id: [u8; 32],
    }
    #[derive(serde::Serialize)]
    struct ActionId {
        action_id: [u8; 32],
    }
    #[derive(serde::Serialize)]
    struct LinkId {
        link_id: [u8; 32],
    }
    let (_state, db, _dir, executor) = setup_with_params(params());
    let owner = KeyPair::generate();
    let stranger = KeyPair::generate();
    fund(&db, &owner, 100_000_000);
    fund(&db, &stranger, 100_000_000);
    let proposer = Address::new([9; 20]);
    let contract = Address::new([0xCC; 20]);

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);
    for (n, t) in [
        tx(
            &owner,
            0,
            AgreementOperation::CommitAgreement,
            &two_party_agreement(102),
        ),
        tx(
            &owner,
            1,
            AgreementOperation::RecordIpAction,
            &ip_action(0xD1),
        ),
        tx(
            &owner,
            2,
            AgreementOperation::LinkExecutor,
            &executor_link(0xD2, 102, contract),
        ),
    ]
    .into_iter()
    .enumerate()
    {
        let r = executor
            .execute_tx(&mut view, &t, &proposer, 1, 1000)
            .unwrap();
        assert!(
            matches!(r.status, TxStatus::Success),
            "setup {n}: {:?}",
            r.status
        );
    }

    // Now the stranger dismantles all three.
    let teardown: Vec<(u64, AgreementOperation, Vec<u8>)> = vec![
        (
            0,
            AgreementOperation::RevokeIpAction,
            bincode::serialize(&ActionId {
                action_id: [0xD1; 32],
            })
            .unwrap(),
        ),
        (
            1,
            AgreementOperation::TerminateExecutor,
            bincode::serialize(&LinkId {
                link_id: [0xD2; 32],
            })
            .unwrap(),
        ),
        (
            2,
            AgreementOperation::TerminateAgreement,
            bincode::serialize(&AgreementId {
                agreement_id: [102; 32],
            })
            .unwrap(),
        ),
    ];
    for (nonce, op, data) in teardown {
        let t = TransactionV2 {
            chain_id: CHAIN_ID,
            from: stranger.address(),
            fee: 100,
            nonce,
            payload: TxPayload::Agreement(AgreementTxData {
                operation: op,
                data,
                recipient: Address::ZERO,
            }),
        };
        let sig = *sign(t.signing_hash().as_bytes(), stranger.private_key()).as_bytes();
        let t = SignedTransaction::new_v2(t, sig, *stranger.public_key().as_bytes());
        let r = executor
            .execute_tx(&mut view, &t, &proposer, 1, 1000)
            .unwrap();
        assert!(
            matches!(r.status, TxStatus::Success),
            "{op:?} by a stranger: {:?}",
            r.status
        );
    }

    assert_eq!(
        AgreementExecutor::v_get_agreement(&view, &[102u8; 32])
            .unwrap()
            .unwrap()
            .status,
        AgreementStatus::Terminated
    );
    assert_eq!(
        AgreementExecutor::v_get_ip_action(&view, &[0xD1u8; 32])
            .unwrap()
            .unwrap()
            .status,
        IpActionStatus::Revoked
    );
    assert_eq!(
        AgreementExecutor::v_get_executor_link(&view, &[0xD2u8; 32])
            .unwrap()
            .unwrap()
            .state,
        ExecutorState::Terminated
    );
}

/// `AddParty` and `RemoveParty` charge the fee, advance the nonce and change
/// nothing at all.
#[test]
fn add_party_and_remove_party_charge_a_fee_and_do_nothing() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let actor = KeyPair::generate();
    fund(&db, &actor, 100_000_000);
    let proposer = Address::new([9; 20]);

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);
    for (nonce, op) in [
        (0u64, AgreementOperation::AddParty),
        (1, AgreementOperation::RemoveParty),
    ] {
        let t = TransactionV2 {
            chain_id: CHAIN_ID,
            from: actor.address(),
            fee: 100,
            nonce,
            payload: TxPayload::Agreement(AgreementTxData {
                operation: op,
                // Never deserialized.
                data: b"\xff\xff\xff\xff".to_vec(),
                recipient: Address::ZERO,
            }),
        };
        let sig = *sign(t.signing_hash().as_bytes(), actor.private_key()).as_bytes();
        let t = SignedTransaction::new_v2(t, sig, *actor.public_key().as_bytes());
        let r = executor
            .execute_tx(&mut view, &t, &proposer, 1, 1000)
            .unwrap();
        assert!(
            matches!(r.status, TxStatus::Success),
            "{op:?}: {:?}",
            r.status
        );
    }
    assert!(
        families_changed(&db, &view).is_empty(),
        "neither operation writes anything"
    );
    assert_eq!(
        StateManager::v_get_nonce(&view, &actor.address()).unwrap(),
        2,
        "while both charge a fee and advance the nonce"
    );
}

/// The ninth agreement column family, `agreement_events`, is never written by
/// any operation, so the agreement journal is empty on every chain.
#[test]
fn the_agreement_event_journal_is_never_written() {
    let dir = tempfile::TempDir::new().unwrap();
    let db = std::sync::Arc::new(Database::open_default(dir.path()).unwrap());
    let state = std::sync::Arc::new(StateManager::new(db.clone(), CHAIN_ID));
    let executor =
        sumchain_state::executor::BlockExecutor::new(state.clone(), db.clone(), params());
    let actor = KeyPair::generate();
    fund(&db, &actor, 500_000_000);

    let receipts = common::publish_block(
        &state,
        &executor,
        1,
        &[4u8; 32],
        a_block_touching_every_family(&actor, 70, Address::new([0xCC; 20])),
        &[],
    );
    assert!(receipts
        .iter()
        .all(|r| matches!(r.status, TxStatus::Success)));

    assert_eq!(
        db.prefix_iter(cf::AGREEMENT_EVENTS, &[]).unwrap().count(),
        0,
        "six successful operations across all eight written families leave the \
         ninth, the journal, empty"
    );
}

/// Attestations carry the ONE authorization check in the whole subsystem, and
/// it is pinned in both directions.
///
/// `CreateAttestation` requires the packet's issuer to be the sender, and
/// `RevokeAttestation` / `UpdateAttestationStatus` require the sender to be the
/// recorded issuer. Nothing else in SRC-84X checks anything about the sender --
/// see `any_sender_can_sign_on_behalf_of_any_party` and
/// `any_sender_can_terminate_void_and_revoke_anything` for the other side of
/// that. This test also drives the revoke and update paths to success, which is
/// what exercises `v_update_attestation_status` at all.
#[test]
fn only_the_issuer_may_revoke_or_update_its_own_attestation() {
    #[derive(serde::Serialize)]
    struct AttestationId {
        attestation_id: [u8; 32],
    }
    #[derive(serde::Serialize)]
    struct UpdateStatus {
        attestation_id: [u8; 32],
        status: AttestationStatus,
    }
    let (_state, db, _dir, executor) = setup_with_params(params());
    let issuer = KeyPair::generate();
    let stranger = KeyPair::generate();
    fund(&db, &issuer, 100_000_000);
    fund(&db, &stranger, 100_000_000);
    let proposer = Address::new([9; 20]);
    let issuer_addr = issuer.address();

    let signed_by = |kp: &KeyPair, nonce: u64, op, data: Vec<u8>| {
        let t = TransactionV2 {
            chain_id: CHAIN_ID,
            from: kp.address(),
            fee: 100,
            nonce,
            payload: TxPayload::Agreement(AgreementTxData {
                operation: op,
                data,
                recipient: Address::ZERO,
            }),
        };
        let sig = *sign(t.signing_hash().as_bytes(), kp.private_key()).as_bytes();
        SignedTransaction::new_v2(t, sig, *kp.public_key().as_bytes())
    };

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);

    // An attestation whose issuer is NOT the sender is refused outright.
    let r = executor
        .execute_tx(
            &mut view,
            &tx(
                &stranger,
                0,
                AgreementOperation::CreateAttestation,
                &attestation(0xB0, &issuer_addr, 10),
            ),
            &proposer,
            1,
            1000,
        )
        .unwrap();
    assert_eq!(
        r.status,
        TxStatus::Failed(11),
        "the packet named the issuer as someone other than the sender"
    );
    assert!(families_changed(&db, &view).is_empty());

    // The issuer's own attestation is accepted.
    let r = executor
        .execute_tx(
            &mut view,
            &tx(
                &issuer,
                0,
                AgreementOperation::CreateAttestation,
                &attestation(0xB0, &issuer_addr, 10),
            ),
            &proposer,
            1,
            1000,
        )
        .unwrap();
    assert!(matches!(r.status, TxStatus::Success), "{:?}", r.status);

    // A stranger may neither revoke it nor update its status.
    for (nonce, op, data) in [
        (
            0u64,
            AgreementOperation::RevokeAttestation,
            bincode::serialize(&AttestationId {
                attestation_id: [0xB0; 32],
            })
            .unwrap(),
        ),
        (
            0,
            AgreementOperation::UpdateAttestationStatus,
            bincode::serialize(&UpdateStatus {
                attestation_id: [0xB0; 32],
                status: AttestationStatus::Superseded,
            })
            .unwrap(),
        ),
    ] {
        let r = executor
            .execute_tx(
                &mut view,
                &signed_by(&stranger, nonce, op, data),
                &proposer,
                1,
                1000,
            )
            .unwrap();
        assert_eq!(
            r.status,
            TxStatus::Failed(11),
            "{op:?} by a stranger must be refused"
        );
    }
    assert_eq!(
        AgreementExecutor::v_get_attestation(&view, &[0xB0u8; 32])
            .unwrap()
            .unwrap()
            .status,
        AttestationStatus::Active,
        "and the status is untouched by either refusal"
    );
    assert_eq!(
        StateManager::v_get_nonce(&view, &stranger.address()).unwrap(),
        0,
        "no fee charged for any of the stranger's three attempts"
    );

    // The issuer can do both. Update first, then revoke, so each transition is
    // observed separately.
    let r = executor
        .execute_tx(
            &mut view,
            &signed_by(
                &issuer,
                1,
                AgreementOperation::UpdateAttestationStatus,
                bincode::serialize(&UpdateStatus {
                    attestation_id: [0xB0; 32],
                    status: AttestationStatus::Superseded,
                })
                .unwrap(),
            ),
            &proposer,
            1,
            1000,
        )
        .unwrap();
    assert!(matches!(r.status, TxStatus::Success), "{:?}", r.status);
    assert_eq!(
        AgreementExecutor::v_get_attestation(&view, &[0xB0u8; 32])
            .unwrap()
            .unwrap()
            .status,
        AttestationStatus::Superseded
    );

    let r = executor
        .execute_tx(
            &mut view,
            &signed_by(
                &issuer,
                2,
                AgreementOperation::RevokeAttestation,
                bincode::serialize(&AttestationId {
                    attestation_id: [0xB0; 32],
                })
                .unwrap(),
            ),
            &proposer,
            1,
            1000,
        )
        .unwrap();
    assert!(matches!(r.status, TxStatus::Success), "{:?}", r.status);
    let a = AgreementExecutor::v_get_attestation(&view, &[0xB0u8; 32])
        .unwrap()
        .unwrap();
    assert_eq!(a.status, AttestationStatus::Revoked);
    assert_eq!(
        a.issuer_address, issuer_addr,
        "and nothing else in the packet moved"
    );
}
