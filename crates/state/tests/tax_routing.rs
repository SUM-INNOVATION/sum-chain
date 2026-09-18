//! SRC-82X tax executes against the block's candidate.
//!
//! Real signed transactions through `BlockExecutor`, in sequence, in one block.
//! Every tax operation is a read-then-write -- duplicate guards on registration,
//! existence checks on update, an ACTIVE-issuer check before issuing a claim --
//! and all of those reads were committed reads, correct only because the
//! matching writes committed as they went.
//!
//! ## Two behaviours this suite PINS rather than fixes
//!
//! * `RevokeClaim` passes a `subject_nullifier` where the proof store expects a
//!   `proof_id`. Both are `[u8; 32]`, so it compiles and keys the wrong row.
//! * Deleting a proof leaves its subject-index entry behind, so the index
//!   points at a proof that is gone.
//!
//! Both predate this commit and are reproduced exactly. They are pinned here so
//! that changing either is a deliberate act with a failing test attached, not a
//! silent correction inside a migration.

mod common;

use common::{fund, setup_with_params, CHAIN_ID};
use sumchain_crypto::{sign, KeyPair};
use sumchain_genesis::ChainParams;
use sumchain_primitives::tax::{
    ClaimTypeStatus, DisclosureContentType, IssuerRequirements, QuorumRule, TaxClaimTypeEntry,
    TaxDisclosureEnvelope, TaxIssuer, TaxIssuerClass, TaxIssuerStatus, TaxOperation, TaxPolicy,
    TaxPolicyTemplate, TaxProofEnvelope, TaxProofType, TaxRiskLevel, TaxTxData,
};
use sumchain_primitives::{Address, SignedTransaction, TransactionV2, TxPayload, TxStatus};
use sumchain_state::{StateManager, TaxExecutor};
use sumchain_storage::exec_view::ExecutionView;
use sumchain_storage::overlay::ApplicationOverlay;
use sumchain_storage::{cf, Database, TaxStore};

/// Every family this unit moved. Six.
const TAX_CFS: &[&str] = &[
    cf::TAX_CLAIM_TYPES,
    cf::TAX_ISSUERS,
    cf::TAX_POLICIES,
    cf::TAX_PROOFS,
    cf::TAX_SUBJECT_INDEX,
    cf::TAX_DISCLOSURES,
];

fn params() -> ChainParams {
    ChainParams::with_v2_enabled()
}

fn signed(
    kp: &KeyPair,
    nonce: u64,
    op: TaxOperation,
    payload: &impl serde::Serialize,
) -> SignedTransaction {
    let tx = TransactionV2 {
        chain_id: CHAIN_ID,
        from: kp.address(),
        fee: 100,
        nonce,
        payload: TxPayload::Tax(TaxTxData {
            operation: op,
            data: bincode::serialize(payload).unwrap(),
            recipient: Address::ZERO,
        }),
    };
    let h = tx.signing_hash();
    let sig = sign(h.as_bytes(), kp.private_key());
    SignedTransaction::new_v2(tx, *sig.as_bytes(), *kp.public_key().as_bytes())
}

fn issuer_of(kp: &KeyPair) -> TaxIssuer {
    TaxIssuer {
        address: kp.address(),
        tax_class: TaxIssuerClass::TaxAuthority,
        jurisdictions: vec!["US".to_string()],
        attributes_hash: [0u8; 32],
        attributes_schema_hash: [0u8; 32],
        registered_at: 1_000,
        updated_at: 1_000,
        status: TaxIssuerStatus::Active,
        expires_at: None,
    }
}

fn claim_type(name: &str) -> TaxClaimTypeEntry {
    TaxClaimTypeEntry {
        claim_type: name.to_string(),
        schema_hash: [1u8; 32],
        risk_level: TaxRiskLevel::Low,
        recommended_validity_secs: 86_400,
        required_issuer_classes: vec![],
        status: ClaimTypeStatus::Active,
        version: 1,
        created_at: 1_000,
        updated_at: 1_000,
    }
}

fn proof(id: u8, subject: [u8; 32]) -> TaxProofEnvelope {
    TaxProofEnvelope {
        proof_id: [id; 32],
        profile_id: "p".to_string(),
        policy_ids: vec![],
        claim_ids: vec![],
        public_inputs: vec![],
        proof_data: vec![7],
        proof_type: TaxProofType::Groth16,
        subject_nullifier: subject,
        generated_at: 1_000,
        expires_at: 2_000,
    }
}

fn canonical(db: &Database) -> Vec<(String, Vec<u8>, Vec<u8>)> {
    let mut out = Vec::new();
    for f in TAX_CFS {
        for (k, v) in db.prefix_iter(f, &[]).unwrap() {
            out.push((f.to_string(), k.to_vec(), v.to_vec()));
        }
    }
    out.sort();
    out
}

/// Families whose CANDIDATE contents differ from the committed ones.
///
/// Not a presence check on the view: `prefix_iter` is MERGED, so a family with
/// a committed row reads as non-empty whether or not this block touched it.
/// An earlier version of this file used presence, and the refusal test below
/// pre-seeds a canonical issuer row -- which made that test report a partial
/// stage for every ceiling, including the ones that staged nothing at all.
fn families_changed(db: &Database, view: &ExecutionView<'_, '_>) -> Vec<&'static str> {
    let mut out = Vec::new();
    for f in TAX_CFS {
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

// ── Same-block visibility ────────────────────────────────────────────────────

/// A claim issued later in the block finds the issuer registered earlier in it.
///
/// `IssueClaim` requires a registered, ACTIVE issuer. Against committed state
/// that read answers from the parent block, so the registration would be
/// invisible and the claim refused.
#[test]
fn a_claim_finds_an_issuer_registered_earlier_in_the_same_block() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let issuer = KeyPair::generate();
    fund(&db, &issuer, 10_000_000);
    let proposer = Address::new([9; 20]);

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);

    let r0 = executor
        .execute_tx(
            &mut view,
            &signed(
                &issuer,
                0,
                TaxOperation::RegisterIssuer,
                &issuer_of(&issuer),
            ),
            &proposer,
            1,
            1000,
        )
        .unwrap();
    assert!(matches!(r0.status, TxStatus::Success), "{:?}", r0.status);

    let r1 = executor
        .execute_tx(
            &mut view,
            &signed(&issuer, 1, TaxOperation::IssueClaim, &proof(1, [4u8; 32])),
            &proposer,
            1,
            1000,
        )
        .unwrap();
    assert!(
        matches!(r1.status, TxStatus::Success),
        "the claim must find the issuer this block registered: {:?}",
        r1.status
    );
    assert!(
        TaxExecutor::v_get_proof(&view, &[1u8; 32])
            .unwrap()
            .is_some(),
        "and stage the proof"
    );
}

/// Without the registration, the same claim is refused.
#[test]
fn without_the_registration_the_same_claim_is_refused() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let issuer = KeyPair::generate();
    fund(&db, &issuer, 10_000_000);
    let proposer = Address::new([9; 20]);

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);
    let r = executor
        .execute_tx(
            &mut view,
            &signed(&issuer, 0, TaxOperation::IssueClaim, &proof(1, [4u8; 32])),
            &proposer,
            1,
            1000,
        )
        .unwrap();
    // Failed(9) is "tax operation failed": the transaction REACHED the tax
    // executor and its guard refused it. Accepting any non-success would let an
    // invalid nonce, an insufficient balance or a malformed payload stand in
    // for the guard this test is about.
    assert_eq!(
        r.status,
        TxStatus::Failed(9),
        "a claim from an unregistered issuer must fail IN the tax executor"
    );
    assert!(
        families_changed(&db, &view).is_empty(),
        "and change nothing at all"
    );
    assert_eq!(
        StateManager::v_get_nonce(&view, &issuer.address()).unwrap(),
        0,
        "a refused tax operation does not advance the account nonce"
    );
}

/// Two registrations of the same claim type in one block: the second is
/// refused by a guard that reads the candidate.
#[test]
fn a_duplicate_claim_type_in_the_same_block_is_refused() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let admin = KeyPair::generate();
    fund(&db, &admin, 10_000_000);
    let proposer = Address::new([9; 20]);

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);

    for (nonce, expect) in [(0u64, true), (1u64, false)] {
        let r = executor
            .execute_tx(
                &mut view,
                &signed(
                    &admin,
                    nonce,
                    TaxOperation::RegisterClaimType,
                    &claim_type("tax.filed.return"),
                ),
                &proposer,
                1,
                1000,
            )
            .unwrap();
        if expect {
            assert!(
                matches!(r.status, TxStatus::Success),
                "the first registration must succeed: {:?}",
                r.status
            );
        } else {
            assert_eq!(
                r.status,
                TxStatus::Failed(9),
                "the duplicate must be refused BY THE TAX GUARD, not rejected \
                 earlier for some unrelated reason"
            );
        }
    }
    // The account nonce advanced exactly once: the refused duplicate did not
    // charge one, so a nonce error cannot be what refused it.
    assert_eq!(
        StateManager::v_get_nonce(&view, &admin.address()).unwrap(),
        1,
        "one successful registration, one refusal"
    );

    let rows: Vec<_> = view
        .prefix_iter(cf::TAX_CLAIM_TYPES, &[])
        .unwrap()
        .map(|r| r.unwrap())
        .collect();
    assert_eq!(rows.len(), 1, "the duplicate must not leave a second row");
}

/// Two proofs for one subject in the same block: the index holds BOTH ids.
///
/// The subject index value is an accumulating `Vec<ProofId>`. Reading it from
/// committed state would give the second proof an empty list, and it would
/// overwrite the first one's entry with a single-element one.
#[test]
fn two_proofs_for_one_subject_accumulate_in_the_index() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let issuer = KeyPair::generate();
    fund(&db, &issuer, 10_000_000);
    let proposer = Address::new([9; 20]);
    let subject = [0xAB; 32];

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);
    executor
        .execute_tx(
            &mut view,
            &signed(
                &issuer,
                0,
                TaxOperation::RegisterIssuer,
                &issuer_of(&issuer),
            ),
            &proposer,
            1,
            1000,
        )
        .unwrap();

    for (nonce, id) in [(1u64, 1u8), (2u64, 2u8)] {
        let r = executor
            .execute_tx(
                &mut view,
                &signed(
                    &issuer,
                    nonce,
                    TaxOperation::IssueClaim,
                    &proof(id, subject),
                ),
                &proposer,
                1,
                1000,
            )
            .unwrap();
        assert!(matches!(r.status, TxStatus::Success), "{:?}", r.status);
    }

    let ids = TaxExecutor::v_get_subject_proof_ids(&view, &subject).unwrap();
    assert_eq!(
        ids,
        vec![[1u8; 32], [2u8; 32]],
        "both proof ids, in issue order -- the second must have seen the first"
    );
}

// ── Abandonment ──────────────────────────────────────────────────────────────

/// A block touching all six families commits none of it.
#[test]
fn an_abandoned_block_leaves_all_six_families_untouched() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let issuer = KeyPair::generate();
    fund(&db, &issuer, 100_000_000);
    let proposer = Address::new([9; 20]);
    let before = canonical(&db);

    {
        let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
        let mut view = ExecutionView::new(&mut overlay);

        let policy = TaxPolicy {
            policy_id: [5u8; 32],
            template: TaxPolicyTemplate::Filed,
            claim_types: vec!["t.a".to_string()],
            issuer_requirements: IssuerRequirements {
                groups: vec![],
                quorum: QuorumRule::Any,
            },
            jurisdictions: vec!["US".to_string()],
            tax_years: vec![2026],
            max_age_secs: 86_400,
            revocation_check: false,
            creator: issuer.address(),
            created_at: 1_000,
        };
        let disclosure = TaxDisclosureEnvelope {
            payload_hash: [6u8; 32],
            payload_size: 1,
            hint_uri: None,
            encryption_meta: None,
            content_type: DisclosureContentType::TaxReturn,
            claim_id: None,
            proof_id: None,
            created_at: 1_000,
        };

        let steps: Vec<(u64, TaxOperation, Vec<u8>)> = vec![
            (
                0,
                TaxOperation::RegisterClaimType,
                bincode::serialize(&claim_type("t.a")).unwrap(),
            ),
            (
                1,
                TaxOperation::RegisterIssuer,
                bincode::serialize(&issuer_of(&issuer)).unwrap(),
            ),
            (
                2,
                TaxOperation::CreatePolicy,
                bincode::serialize(&policy).unwrap(),
            ),
            (
                3,
                TaxOperation::IssueClaim,
                bincode::serialize(&proof(1, [0xCD; 32])).unwrap(),
            ),
            (
                4,
                TaxOperation::AttachDisclosure,
                bincode::serialize(&disclosure).unwrap(),
            ),
        ];
        for (nonce, op, data) in steps {
            let tx = TransactionV2 {
                chain_id: CHAIN_ID,
                from: issuer.address(),
                fee: 100,
                nonce,
                payload: TxPayload::Tax(TaxTxData {
                    operation: op,
                    data,
                    recipient: Address::ZERO,
                }),
            };
            let h = tx.signing_hash();
            let sig = sign(h.as_bytes(), issuer.private_key());
            let tx =
                SignedTransaction::new_v2(tx, *sig.as_bytes(), *issuer.public_key().as_bytes());
            let r = executor
                .execute_tx(&mut view, &tx, &proposer, 1, 1000)
                .unwrap();
            assert!(
                matches!(r.status, TxStatus::Success),
                "seeding {op:?} must succeed: {:?}",
                r.status
            );
        }

        let touched = families_changed(&db, &view);
        for f in TAX_CFS {
            assert!(
                touched.contains(f),
                "{f} was not staged, so dropping the block proves nothing about it"
            );
        }
        // dropped
    }

    assert_eq!(
        canonical(&db),
        before,
        "an abandoned block must leave every tax row byte-identical"
    );
}

// ── Limit refusal ────────────────────────────────────────────────────────────

/// A refusal leaves canonical storage untouched, and at least one ceiling
/// refuses with the proof staged and its index entry not.
///
/// The operation has to be `IssueClaim` for that to be reachable at all. Every
/// other tax operation writes ONE row, and the fee and nonce writes come before
/// it, so a ceiling either refuses during the account writes -- nothing tax
/// staged -- or fits the whole transaction. `IssueClaim` writes two, the proof
/// and its subject-index entry, so a ceiling can land between them.
///
/// The partial is asserted as EXACT state rather than "some family is
/// non-empty": the proof readable through the view, the index row not, and the
/// canonical rows unchanged. Both families start canonically empty (only the
/// issuer is seeded), so a row readable through the merged view can only have
/// come from the candidate -- which is what makes these two reads sound.
///
/// Every ceiling below the measured cost is tried, not a sample: the interval
/// between the two writes is a handful of bytes wide, and a stepped sweep can
/// step straight over it.
#[test]
fn a_refusal_leaves_canonical_storage_untouched() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let issuer = KeyPair::generate();
    fund(&db, &issuer, 100_000_000);
    let proposer = Address::new([9; 20]);
    // The issuer is committed, the way an earlier block would have left it, so
    // this transaction's only tax writes are the proof and its index.
    TaxStore::new(&db)
        .issuers()
        .put(&issuer_of(&issuer))
        .unwrap();
    let subject = [0x33; 32];
    let before = canonical(&db);

    // The two families this transaction writes start canonically EMPTY. That is
    // what lets a merged read below stand for "staged".
    assert!(
        db.prefix_iter(cf::TAX_PROOFS, &[])
            .unwrap()
            .next()
            .is_none()
            && db
                .prefix_iter(cf::TAX_SUBJECT_INDEX, &[])
                .unwrap()
                .next()
                .is_none(),
        "proofs and the subject index must start empty for this test to read \
         the candidate through the merged view"
    );

    let tx = signed(&issuer, 0, TaxOperation::IssueClaim, &proof(1, subject));
    let full = {
        let mut scratch = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
        {
            let mut view = ExecutionView::new(&mut scratch);
            executor
                .execute_tx(&mut view, &tx, &proposer, 1, 1000)
                .unwrap();
        }
        scratch.logical_bytes()
    };
    assert!(full > 1, "an issuance must cost something");

    let mut partials = 0usize;
    for ceiling in 1..full {
        let mut overlay = ApplicationOverlay::new(&db, ceiling);
        let mut view = ExecutionView::new(&mut overlay);
        let outcome = executor.execute_tx(&mut view, &tx, &proposer, 1, 1000);
        assert!(outcome.is_err(), "ceiling {ceiling} must refuse");
        assert!(
            outcome.unwrap_err().to_string().contains("limit"),
            "ceiling {ceiling} must fail because a WRITE was refused"
        );

        let proof_staged = view.get(cf::TAX_PROOFS, &[1u8; 32]).unwrap().is_some();
        let index_staged = view.get(cf::TAX_SUBJECT_INDEX, &subject).unwrap().is_some();
        if proof_staged && !index_staged {
            partials += 1;
        }
        assert!(
            !index_staged || proof_staged,
            "ceiling {ceiling} staged the index without the proof, which no \
             order of these two writes can produce"
        );
        assert_eq!(
            canonical(&db),
            before,
            "ceiling {ceiling} must leave canonical storage as it was"
        );
    }

    assert!(
        partials > 0,
        "no ceiling refused with the proof staged and the index not -- either \
         the two writes stopped being separate, or this sweep stopped covering \
         the interval between them"
    );
}

// ── Index parity ─────────────────────────────────────────────────────────────

/// Published rows satisfy the committed scans the RPC uses.
#[test]
fn published_rows_satisfy_the_committed_scans() {
    let (state, db, _dir, executor) = setup_with_params(params());
    let issuer = KeyPair::generate();
    fund(&db, &issuer, 100_000_000);
    let subject = [0xEF; 32];

    let receipts = common::publish_block(
        &state,
        &executor,
        1,
        &[3u8; 32],
        vec![
            signed(
                &issuer,
                0,
                TaxOperation::RegisterIssuer,
                &issuer_of(&issuer),
            ),
            signed(&issuer, 1, TaxOperation::IssueClaim, &proof(1, subject)),
        ],
        &[],
    );
    assert!(
        receipts
            .iter()
            .all(|r| matches!(r.status, TxStatus::Success)),
        "both must succeed: {:?}",
        receipts.iter().map(|r| r.status).collect::<Vec<_>>()
    );

    let store = TaxStore::new(&db);
    assert_eq!(
        store
            .issuers()
            .get(&issuer.address())
            .unwrap()
            .map(|i| i.address),
        Some(issuer.address()),
        "the issuer point lookup"
    );
    assert_eq!(
        store.issuers().list_active().unwrap().len(),
        1,
        "the active-issuer scan"
    );
    assert_eq!(
        store.proofs().get(&[1u8; 32]).unwrap().map(|p| p.proof_id),
        Some([1u8; 32]),
        "the proof point lookup"
    );
    let by_subject = store.proofs().get_by_subject(&subject).unwrap();
    assert_eq!(
        by_subject.iter().map(|p| p.proof_id).collect::<Vec<_>>(),
        vec![[1u8; 32]],
        "and the subject index, which the candidate wrote"
    );
}

// ── The two preserved defects ────────────────────────────────────────────────

/// Deleting a proof leaves its subject-index entry behind.
///
/// PRE-EXISTING, and reproduced deliberately: the committed twin does exactly
/// this. Pinned so that fixing it is a deliberate change with a failing test
/// attached rather than a silent correction inside a migration.
#[test]
fn deleting_a_proof_leaves_the_subject_index_entry_behind() {
    let (_state, db, _dir, _executor) = setup_with_params(params());
    let subject = [0x11; 32];

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);

    TaxExecutor::v_put_proof(&mut view, &proof(1, subject)).unwrap();
    assert_eq!(
        TaxExecutor::v_get_subject_proof_ids(&view, &subject).unwrap(),
        vec![[1u8; 32]]
    );

    TaxExecutor::v_delete_proof(&mut view, &[1u8; 32]).unwrap();
    assert!(
        TaxExecutor::v_get_proof(&view, &[1u8; 32])
            .unwrap()
            .is_none(),
        "the proof row is gone"
    );
    assert_eq!(
        TaxExecutor::v_get_subject_proof_ids(&view, &subject).unwrap(),
        vec![[1u8; 32]],
        "and its index entry is NOT -- a dangling pointer the committed path \
         has always left, preserved here rather than fixed inside a migration"
    );
}

/// `RevokeClaim` keys the proof store by SUBJECT NULLIFIER, not proof id.
///
/// PRE-EXISTING type confusion: both are `[u8; 32]`, so it compiles and reads
/// the wrong row. A revocation therefore only finds a proof whose id happens to
/// equal the nullifier it was given. Pinned, not fixed.
#[test]
fn revoke_claim_keys_the_proof_store_by_nullifier() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let issuer = KeyPair::generate();
    fund(&db, &issuer, 100_000_000);
    let proposer = Address::new([9; 20]);
    let subject = [0x22; 32];

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);
    executor
        .execute_tx(
            &mut view,
            &signed(
                &issuer,
                0,
                TaxOperation::RegisterIssuer,
                &issuer_of(&issuer),
            ),
            &proposer,
            1,
            1000,
        )
        .unwrap();
    executor
        .execute_tx(
            &mut view,
            &signed(&issuer, 1, TaxOperation::IssueClaim, &proof(1, subject)),
            &proposer,
            1,
            1000,
        )
        .unwrap();

    #[derive(serde::Serialize)]
    struct Revoke {
        subject_nullifier: [u8; 32],
    }

    // Revoking BY the subject nullifier fails: the store is keyed by proof id,
    // and no row lives at the nullifier.
    let r = executor
        .execute_tx(
            &mut view,
            &signed(
                &issuer,
                2,
                TaxOperation::RevokeClaim,
                &Revoke {
                    subject_nullifier: subject,
                },
            ),
            &proposer,
            1,
            1000,
        )
        .unwrap();
    assert_eq!(
        r.status,
        TxStatus::Failed(9),
        "revocation by nullifier must fail INSIDE the tax executor, because the \
         lookup uses it as a PROOF ID and finds nothing"
    );
    assert!(
        TaxExecutor::v_get_proof(&view, &[1u8; 32])
            .unwrap()
            .is_some(),
        "and the proof is still there"
    );

    // Passing the PROOF ID in the nullifier field is what actually revokes,
    // which is the confusion stated plainly.
    let r2 = executor
        .execute_tx(
            &mut view,
            &signed(
                &issuer,
                2,
                TaxOperation::RevokeClaim,
                &Revoke {
                    subject_nullifier: [1u8; 32],
                },
            ),
            &proposer,
            1,
            1000,
        )
        .unwrap();
    assert!(matches!(r2.status, TxStatus::Success), "{:?}", r2.status);
    assert!(
        TaxExecutor::v_get_proof(&view, &[1u8; 32])
            .unwrap()
            .is_none(),
        "the proof keyed by that id is the one removed"
    );
}

// ── The second dispatch surface ──────────────────────────────────────────────

/// `execute_tx_v2` routes tax through the candidate too.
///
/// Two public transaction surfaces exist. `execute_tx` (wrapping
/// `execute_tx_with_validators`) is the live one every test above drives;
/// `execute_tx_v2` is `pub` with no production caller and has its own tax arm.
/// A migration that moved only the live arm would leave the other writing
/// committed rows.
#[test]
fn the_v2_dispatch_surface_also_stages_tax() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let issuer = KeyPair::generate();
    fund(&db, &issuer, 10_000_000);
    let proposer = Address::new([9; 20]);
    let before = canonical(&db);

    let tx = TransactionV2 {
        chain_id: CHAIN_ID,
        from: issuer.address(),
        fee: 100,
        nonce: 0,
        payload: TxPayload::Tax(TaxTxData {
            operation: TaxOperation::RegisterIssuer,
            data: bincode::serialize(&issuer_of(&issuer)).unwrap(),
            recipient: Address::ZERO,
        }),
    };
    let sig = *sign(tx.signing_hash().as_bytes(), issuer.private_key()).as_bytes();
    let key = *issuer.public_key().as_bytes();

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    {
        let mut view = ExecutionView::new(&mut overlay);
        let r = executor
            .execute_tx_v2(&mut view, &tx, &sig, &key, &proposer, 1, 1000)
            .unwrap();
        assert!(
            matches!(r.status, TxStatus::Success),
            "the v2 surface must execute a tax registration: {:?}",
            r.status
        );
        assert_eq!(
            families_changed(&db, &view),
            vec![cf::TAX_ISSUERS],
            "and stage exactly the issuer family"
        );
        assert_eq!(
            TaxExecutor::v_get_issuer(&view, &issuer.address())
                .unwrap()
                .map(|i| i.address),
            Some(issuer.address()),
            "with the issuer readable from the candidate"
        );
    }

    assert_eq!(
        canonical(&db),
        before,
        "and canonical storage still empty of tax rows"
    );
}

// ── Policies: the same-block read this suite was missing ─────────────────────

fn policy_of(creator: &KeyPair, id: u8, max_age: u64) -> TaxPolicy {
    TaxPolicy {
        policy_id: [id; 32],
        template: TaxPolicyTemplate::Filed,
        claim_types: vec!["t.a".to_string()],
        issuer_requirements: IssuerRequirements {
            groups: vec![],
            quorum: QuorumRule::Any,
        },
        jurisdictions: vec!["US".to_string()],
        tax_years: vec![2026],
        max_age_secs: max_age,
        revocation_check: false,
        creator: creator.address(),
        created_at: 1_000,
    }
}

/// A policy updated later in the block finds the version created earlier in it.
///
/// `UpdatePolicy` requires the policy to exist AND its creator to match. Both
/// come from one read, and against committed state that read answers from the
/// parent -- so the update would be refused as "Not found" for a policy this
/// block had just created.
#[test]
fn a_policy_update_finds_the_creation_from_the_same_block() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let creator = KeyPair::generate();
    fund(&db, &creator, 100_000_000);
    let proposer = Address::new([9; 20]);

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);

    let r0 = executor
        .execute_tx(
            &mut view,
            &signed(
                &creator,
                0,
                TaxOperation::CreatePolicy,
                &policy_of(&creator, 7, 100),
            ),
            &proposer,
            1,
            1000,
        )
        .unwrap();
    assert!(matches!(r0.status, TxStatus::Success), "{:?}", r0.status);

    let r1 = executor
        .execute_tx(
            &mut view,
            &signed(
                &creator,
                1,
                TaxOperation::UpdatePolicy,
                &policy_of(&creator, 7, 999),
            ),
            &proposer,
            1,
            1000,
        )
        .unwrap();
    assert!(
        matches!(r1.status, TxStatus::Success),
        "the update must find the policy this block created: {:?}",
        r1.status
    );
    assert_eq!(
        TaxExecutor::v_get_policy(&view, &[7u8; 32])
            .unwrap()
            .unwrap()
            .max_age_secs,
        999,
        "and the staged policy must carry the updated value"
    );
}

/// Without the creation, the same update is refused.
///
/// The discriminator: the test above would pass on any block in which updates
/// happen to succeed.
#[test]
fn without_the_creation_the_same_policy_update_is_refused() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let creator = KeyPair::generate();
    fund(&db, &creator, 100_000_000);
    let proposer = Address::new([9; 20]);

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);
    let r = executor
        .execute_tx(
            &mut view,
            &signed(
                &creator,
                0,
                TaxOperation::UpdatePolicy,
                &policy_of(&creator, 7, 999),
            ),
            &proposer,
            1,
            1000,
        )
        .unwrap();
    assert_eq!(
        r.status,
        TxStatus::Failed(9),
        "an update against a policy that does not exist must fail in the tax \
         executor"
    );
    assert!(families_changed(&db, &view).is_empty(), "and stage nothing");
}

// ── Malformed committed rows ─────────────────────────────────────────────────

/// A malformed row makes the routed transaction ERROR; it is never read as
/// absence. Canonical state is untouched; the CANDIDATE is not necessarily
/// empty.
///
/// The name says `commit_nothing`, not `stage_nothing`, because one case
/// legitimately leaves a staged row: `IssueClaim` writes the proof before it
/// appends to the subject index, so a malformed index row fails with the proof
/// already in the candidate. The allowed-set assertion below is what the test
/// actually proves, and the name now matches it.
///
/// This is the difference between "no issuer registered" and "the issuer row is
/// corrupt", and the guards branch on exactly that. A candidate reader that
/// swallowed a decode failure into `None` would turn corruption into a
/// duplicate-registration opportunity, or into a claim issued by an issuer
/// whose status could not be read. The `v_get_*` readers propagate, and these
/// prove it through real dispatch rather than by calling the accessor.
#[test]
fn malformed_rows_error_through_dispatch_and_commit_nothing() {
    for (family, key, label) in [
        (cf::TAX_CLAIM_TYPES, b"t.a".to_vec(), "claim type"),
        (cf::TAX_ISSUERS, Vec::new(), "issuer"),
        (cf::TAX_POLICIES, vec![7u8; 32], "policy"),
        (cf::TAX_PROOFS, vec![1u8; 32], "proof"),
        (cf::TAX_SUBJECT_INDEX, vec![0x44u8; 32], "subject index"),
    ] {
        let (_state, db, _dir, executor) = setup_with_params(params());
        let actor = KeyPair::generate();
        fund(&db, &actor, 100_000_000);
        let proposer = Address::new([9; 20]);

        // The issuer family is keyed by the actor's address, which is only
        // known here.
        let key = if key.is_empty() {
            actor.address().as_bytes().to_vec()
        } else {
            key
        };
        db.put(family, &key, b"not a valid row").unwrap();

        // A transaction whose guard has to READ that family.
        let (nonce, op, data): (u64, TaxOperation, Vec<u8>) = match family {
            f if f == cf::TAX_CLAIM_TYPES => (
                0,
                TaxOperation::RegisterClaimType,
                bincode::serialize(&claim_type("t.a")).unwrap(),
            ),
            f if f == cf::TAX_POLICIES => (
                0,
                TaxOperation::CreatePolicy,
                bincode::serialize(&policy_of(&actor, 7, 100)).unwrap(),
            ),
            f if f == cf::TAX_SUBJECT_INDEX => {
                // The index is read while APPENDING, so the issuer has to be
                // valid and the claim well formed.
                TaxStore::new(&db)
                    .issuers()
                    .put(&issuer_of(&actor))
                    .unwrap();
                (
                    0,
                    TaxOperation::IssueClaim,
                    bincode::serialize(&proof(9, [0x44u8; 32])).unwrap(),
                )
            }
            f if f == cf::TAX_PROOFS => {
                TaxStore::new(&db)
                    .issuers()
                    .put(&issuer_of(&actor))
                    .unwrap();
                #[derive(serde::Serialize)]
                struct Revoke {
                    subject_nullifier: [u8; 32],
                }
                (
                    0,
                    TaxOperation::RevokeClaim,
                    bincode::serialize(&Revoke {
                        subject_nullifier: [1u8; 32],
                    })
                    .unwrap(),
                )
            }
            _ => (
                0,
                TaxOperation::RegisterIssuer,
                bincode::serialize(&issuer_of(&actor)).unwrap(),
            ),
        };

        let before = canonical(&db);
        let tx = TransactionV2 {
            chain_id: CHAIN_ID,
            from: actor.address(),
            fee: 100,
            nonce,
            payload: TxPayload::Tax(TaxTxData {
                operation: op,
                data,
                recipient: Address::ZERO,
            }),
        };
        let sig = *sign(tx.signing_hash().as_bytes(), actor.private_key()).as_bytes();
        let tx = SignedTransaction::new_v2(tx, sig, *actor.public_key().as_bytes());

        let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
        {
            let mut view = ExecutionView::new(&mut overlay);
            let outcome = executor.execute_tx(&mut view, &tx, &proposer, 1, 1000);
            let err = outcome.expect_err(&format!(
                "a malformed {label} row must ERROR, not be read as absence"
            ));
            let text = err.to_string();
            assert!(
                text.contains("Serialization") || text.contains("Storage"),
                "the {label} failure must name the decode, not something else: {text}"
            );
            // What is guaranteed is that the ERROR propagates and canonical
            // state is untouched -- asserted below. Staged residue inside a
            // candidate that is about to be discarded is not a defect, and
            // there IS residue in one case: `IssueClaim` stages the proof row
            // before it appends to the subject index, so a malformed index row
            // fails after the proof has been written. Naming the allowed set
            // rather than asserting an empty one keeps that visible instead of
            // silently tolerated.
            let allowed: Vec<&str> = if family == cf::TAX_SUBJECT_INDEX {
                vec![cf::TAX_PROOFS, cf::TAX_SUBJECT_INDEX]
            } else {
                vec![family]
            };
            for changed in families_changed(&db, &view) {
                assert!(
                    allowed.contains(&changed),
                    "the {label} failure staged {changed}, which is not on the \
                     path this transaction takes before it fails"
                );
            }
        }
        assert_eq!(
            canonical(&db),
            before,
            "and nothing may be committed for {label}"
        );
    }
}

// ── The subject index under load ─────────────────────────────────────────────

/// A 640 KiB subject index is refused by the ceiling with a limit error, and
/// commits nothing.
///
/// SCOPE, precisely: this measures ONE size. It shows that at ~20,000 ids the
/// routed path returns a limit error after reaching the index replacement, and
/// leaves canonical state untouched. It does NOT show that arbitrarily large
/// input can never reach an allocator abort -- no test here can, because the
/// value is built before the ceiling is charged.
///
/// The index value is an accumulating `Vec<ProofId>` that the committed store
/// has always decoded, linearly searched, appended to and reserialized on every
/// claim. Routing reproduces that exactly; it neither introduces the growth nor
/// bounds it. A bound would make transactions fail that succeed today, which is
/// a consensus change and belongs to activation-gated hardening, not to a
/// migration.
///
/// The candidate holds both the pre-image and the staged replacement, so peak
/// memory for one row is higher here than on the committed path. That is a
/// property of the candidate model this lane adopted, not of tax.
#[test]
fn a_640_kib_subject_index_is_refused_by_the_ceiling_without_canonical_change() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let issuer = KeyPair::generate();
    fund(&db, &issuer, 100_000_000);
    let proposer = Address::new([9; 20]);
    let subject = [0x55; 32];

    TaxStore::new(&db)
        .issuers()
        .put(&issuer_of(&issuer))
        .unwrap();
    let existing: Vec<[u8; 32]> = (0..20_000u32)
        .map(|i| {
            let mut id = [0u8; 32];
            id[..4].copy_from_slice(&i.to_be_bytes());
            id
        })
        .collect();
    let committed_index = bincode::serialize(&existing).unwrap();
    assert!(
        committed_index.len() > 600_000,
        "the fixture must actually be the size this test claims: {} bytes",
        committed_index.len()
    );
    db.put(cf::TAX_SUBJECT_INDEX, &subject, &committed_index)
        .unwrap();
    let before = canonical(&db);

    let tx = signed(&issuer, 0, TaxOperation::IssueClaim, &proof(0xFE, subject));

    // Under a ceiling far below the index's size the replacement is REFUSED --
    // an error, not an abort.
    {
        let mut overlay = ApplicationOverlay::new(&db, 4_096);
        let mut view = ExecutionView::new(&mut overlay);
        let err = executor
            .execute_tx(&mut view, &tx, &proposer, 1, 1000)
            .expect_err("an index far larger than the ceiling must be refused");
        assert!(
            err.to_string().contains("limit"),
            "refused by the ceiling, not by something else: {err}"
        );
        // Execution REACHED the index replacement: the proof row is staged, so
        // the refusal is not an earlier account or proof write hitting the
        // ceiling first.
        assert!(
            view.get(cf::TAX_PROOFS, &[0xFEu8; 32]).unwrap().is_some(),
            "the proof must be staged, which is what puts the failure at the \
             subject-index write rather than before it"
        );
        // And the index the candidate can see is still exactly the committed
        // one, byte for byte: the refused write left no partial replacement.
        assert_eq!(
            view.get(cf::TAX_SUBJECT_INDEX, &subject).unwrap(),
            Some(committed_index.clone()),
            "the candidate must still see the committed index unchanged"
        );
    }
    assert_eq!(canonical(&db), before, "and nothing is committed");

    // With room, it succeeds and the list grows by exactly one, preserving
    // every existing id -- compared in full, not by sampling.
    {
        let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
        let mut view = ExecutionView::new(&mut overlay);
        let r = executor
            .execute_tx(&mut view, &tx, &proposer, 1, 1000)
            .unwrap();
        assert!(matches!(r.status, TxStatus::Success), "{:?}", r.status);
        let ids = TaxExecutor::v_get_subject_proof_ids(&view, &subject).unwrap();
        assert_eq!(ids.len(), 20_001, "appended, not replaced");
        assert_eq!(
            &ids[..20_000],
            &existing[..],
            "every existing id preserved, in order"
        );
        assert_eq!(ids[20_000], [0xFEu8; 32], "and the new one last");
    }
    assert_eq!(canonical(&db), before, "still nothing committed");
}

// ── Class 3: the Tax claim-type authority check, and its activation ──────────
//
// `docs/lane-a/ACTIVATION-AUDIT.md` row AU-19. Claim-type registration, update
// and deprecation have no authority check at all: all three guard only on row
// presence or absence, and no sender comparison or issuer row is consulted. Any
// funded account writes the chain's claim-type registry, including deprecating
// a type everybody else depends on.
//
// Gated on `tax_authorization_enabled_from_height`, a `ChainParams` field this
// track cannot add.
//
// AU-18 -- anyone self-registers an ACTIVE issuer with an arbitrary class,
// `TaxAuthority` included, and then issues claims -- is NOT addressed here and
// is not claimed to be. The registry authorizes nothing it does not take from
// the applicant, and there is no authority in the subsystem or in `ChainParams`
// to check the applicant against. Closing it needs a registrar the chain does
// not have, so it stays blocking; the check below narrows claim-type writes to
// registered issuers without pretending that being registered means anything
// more than having asked.

use sumchain_state::TaxGates;

/// Drive one Tax operation through the gate seam.
fn tax_at(
    view: &mut ExecutionView<'_, '_>,
    sender: &Address,
    op: TaxOperation,
    payload: &impl serde::Serialize,
    gates: TaxGates,
) -> sumchain_state::TaxExecutionResult {
    let proposer = Address::new([9; 20]);
    TaxExecutor::execute_with_gates(
        view,
        sender,
        &TaxTxData {
            operation: op,
            data: bincode::serialize(payload).unwrap(),
            recipient: Address::ZERO,
        },
        &proposer,
        100,
        1,
        1_000,
        0,
        sumchain_primitives::Hash::ZERO,
        gates,
    )
    .unwrap()
}

/// AU-19: an unregistered account writes and deprecates claim types.
#[test]
fn the_claim_type_registry_is_writable_by_anyone_only_below_the_gate() {
    #[derive(serde::Serialize)]
    struct Deprecate {
        claim_type: String,
    }

    for gates in [TaxGates::CLOSED, TaxGates::OPEN] {
        let (_state, db, _dir, _executor) = setup_with_params(params());
        let authority = KeyPair::generate();
        let stranger = KeyPair::generate();
        fund(&db, &authority, 100_000_000);
        fund(&db, &stranger, 100_000_000);
        let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
        let mut view = ExecutionView::new(&mut overlay);

        // A registered, active issuer, so the gated side has somebody who CAN.
        assert!(
            tax_at(
                &mut view,
                &authority.address(),
                TaxOperation::RegisterIssuer,
                &issuer_of(&authority),
                gates
            )
            .success
        );
        let entry = claim_type("residency.v1");
        assert!(
            tax_at(
                &mut view,
                &authority.address(),
                TaxOperation::RegisterClaimType,
                &entry,
                gates
            )
            .success,
            "a registered issuer writes the registry under either gate"
        );

        // The stranger registers a type of its own, and deprecates the
        // authority's.
        let theirs = claim_type("stranger.v1");
        let registered = tax_at(
            &mut view,
            &stranger.address(),
            TaxOperation::RegisterClaimType,
            &theirs,
            gates,
        );
        let deprecated = tax_at(
            &mut view,
            &stranger.address(),
            TaxOperation::DeprecateClaimType,
            &Deprecate {
                claim_type: entry.claim_type.clone(),
            },
            gates,
        );
        assert_eq!(
            (registered.success, deprecated.success),
            (!gates.authorization, !gates.authorization),
            "any funded account writes and deprecates claim types, until the gate"
        );
        assert_eq!(
            TaxExecutor::v_get_claim_type(&view, "stranger.v1")
                .unwrap()
                .is_some(),
            !gates.authorization
        );
    }
}
