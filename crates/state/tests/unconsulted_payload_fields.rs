//! Payload fields that name something outside the payload, and are checked
//! against nothing.
//!
//! ACTIVATION-AUDIT rows AU-7, AU-8, MD-1 and MD-2. Four rows, one question:
//! **does anything on the execution path compare a payload field against a
//! fact the sender does not control?** For each of these four the answer is no,
//! and each is pinned here in the direction that would fail if a later pass
//! quietly started checking — which is the direction that matters, because
//! every one of these checks is a CONSENSUS change and none of them may arrive
//! ungated.
//!
//! Property is the subsystem used throughout, and not arbitrarily: one payload,
//! `AssetAnchor`, carries all four fields at once — `issuer_address` (AU-7),
//! `policy_id` (AU-8), `created_at` / `updated_at` / `anchored_at_height`
//! (MD-1) — and it rides a `PropertyTxData` carrying `recipient` while the
//! executor signature takes `_tx_index` and `_tx_hash` (MD-2). The audit lists
//! the same four fields across Healthcare, Agreement, Finance, DocClass, Tax,
//! Employment and Legal; the shape is identical and is not re-tested per
//! subsystem, because what is being pinned is the ABSENCE of a comparison, and
//! an absence in eight files is one fact.
//!
//! # What each row is, precisely
//!
//!   * **AU-7 — issuer identity is self-asserted.** The only check that exists
//!     is `asset.issuer_address != *sender`, and `issuer_address` comes from
//!     the payload. So the check binds the row to whoever created it and to
//!     nothing else. There is no issuer registry consulted anywhere in
//!     `property_executor.rs` or `property_view.rs`: any funded account is an
//!     issuer of any `PropertyIssuerClass` it names for itself.
//!   * **AU-8 — `policy_id` gates nothing.** It is stored and no guard reads
//!     it. The registry it could plausibly resolve against —
//!     `PolicyAccountExecutor::v_get_policy_account` — is mechanically
//!     reachable from this crate and is not consulted, and nothing in the tree
//!     says a `policy_id` is a policy ACCOUNT id rather than a commitment to an
//!     off-chain policy document. The two are both `[u8; 32]`, so the compiler
//!     cannot tell them apart either. That is why the row is EXAMINED AND LEFT
//!     rather than remedied: binding them would be inventing the binding, and
//!     binding them wrong would refuse every lawful transaction whose
//!     `policy_id` is a document commitment.
//!   * **MD-1 — payload metadata is stored without reconciliation.** The
//!     creation path stores the deserialized struct verbatim, so a row may
//!     claim a creation time, an update time and an anchoring height that
//!     contradict the block that carries it.
//!   * **MD-2 — `recipient`, `tx_index` and `tx_hash` are accepted and
//!     ignored.** `recipient` is on `PropertyTxData` and is read nowhere in
//!     `crates/state/src` outside `messaging_executor.rs`; the executor takes
//!     the other two as `_tx_index` and `_tx_hash`.
//!
//! # Why an absence is testable at all
//!
//! Not by asserting that a check is missing — nothing can assert that. Each
//! test below supplies a value that a check WOULD refuse and requires the
//! transaction to succeed and the row to be written, and where the field is
//! ignored rather than merely unchecked, it also requires two executions that
//! differ ONLY in that field to produce byte-identical rows. A guard added
//! without a gate fails the first form; a field that starts reaching state
//! fails the second.

mod common;

use common::{fund, setup_with_params, CHAIN_ID};
use sumchain_crypto::{sign, KeyPair};
use sumchain_genesis::ChainParams;
use sumchain_primitives::property::{
    AssetAnchor, AssetStatus, AssetType, PropertyIssuerClass, PropertyOperation, PropertyTxData,
};
use sumchain_primitives::{Address, Hash, SignedTransaction, TransactionV2, TxPayload, TxStatus};
use sumchain_state::{PolicyAccountExecutor, PropertyExecutor};
use sumchain_storage::cf;
use sumchain_storage::exec_view::ExecutionView;
use sumchain_storage::overlay::ApplicationOverlay;

const JURISDICTION: &str = "US-CA-LA";

/// The block every transaction below is executed in: height 1, timestamp 1000.
/// MD-1's assertions are against these two numbers.
const BLOCK_HEIGHT: u64 = 1;
const BLOCK_TIMESTAMP: u64 = 1000;

fn params() -> ChainParams {
    ChainParams::with_v2_enabled()
}

fn tx_with_recipient(
    kp: &KeyPair,
    nonce: u64,
    op: PropertyOperation,
    payload: &impl serde::Serialize,
    recipient: Address,
) -> SignedTransaction {
    let t = TransactionV2 {
        chain_id: CHAIN_ID,
        from: kp.address(),
        fee: 100,
        nonce,
        payload: TxPayload::Property(PropertyTxData {
            operation: op,
            data: bincode::serialize(payload).unwrap(),
            recipient,
        }),
    };
    let sig = sign(t.signing_hash().as_bytes(), kp.private_key());
    SignedTransaction::new_v2(t, *sig.as_bytes(), *kp.public_key().as_bytes())
}

fn tx(
    kp: &KeyPair,
    nonce: u64,
    op: PropertyOperation,
    payload: &impl serde::Serialize,
) -> SignedTransaction {
    tx_with_recipient(kp, nonce, op, payload, Address::ZERO)
}

/// An asset anchor whose every self-describing field is the sender's to choose.
fn asset(id: u8, issuer: Address) -> AssetAnchor {
    AssetAnchor {
        asset_id: [id; 32],
        asset_commitment: [id.wrapping_add(1); 32],
        asset_type: AssetType::SingleFamilyResidence,
        jurisdiction_code: JURISDICTION.to_string(),
        public_reference: None,
        policy_id: [12u8; 32],
        issuer_class: PropertyIssuerClass::LandRegistry,
        issuer_address: issuer,
        status: AssetStatus::Active,
        created_at: BLOCK_TIMESTAMP,
        updated_at: BLOCK_TIMESTAMP,
        anchored_at_height: BLOCK_HEIGHT,
        related_assets: vec![],
        attachments: vec![],
    }
}

/// The stored row, read back out of the candidate.
fn stored(view: &ExecutionView<'_, '_>, id: u8) -> AssetAnchor {
    PropertyExecutor::v_get_asset(view, &[id; 32])
        .expect("read")
        .expect("the anchor is in the candidate")
}

// ── AU-7: issuer identity is self-asserted ──────────────────────────────────

/// AU-7. Any funded account is an issuer of any class it names for itself.
///
/// The transaction below is submitted by a key that has registered nothing,
/// staked nothing and been admitted by nobody, and it declares itself a
/// `LandRegistry`. It succeeds, and the row is written with that class. The
/// only check on the path is `asset.issuer_address != *sender`, which this
/// payload satisfies by simply naming its own sender — so the check binds the
/// row to whoever created it and to nothing else.
///
/// The second half is the one that makes this a statement about a REGISTRY
/// rather than about one transaction: a second, unrelated account anchors its
/// own asset claiming the SAME issuer class, and also succeeds. There is no
/// per-class exclusivity, no admission and nothing to be admitted to.
#[test]
fn any_funded_account_is_an_issuer_of_any_class_it_names_for_itself() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let stranger = KeyPair::generate();
    let other_stranger = KeyPair::generate();
    fund(&db, &stranger, 100_000_000);
    fund(&db, &other_stranger, 100_000_000);
    let proposer = Address::new([9; 20]);

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);

    let mut mine = asset(0x61, stranger.address());
    mine.issuer_class = PropertyIssuerClass::LandRegistry;
    let r = executor
        .execute_tx(
            &mut view,
            &tx(&stranger, 0, PropertyOperation::AnchorAsset, &mine),
            &proposer,
            BLOCK_HEIGHT,
            BLOCK_TIMESTAMP,
        )
        .unwrap();
    assert!(
        matches!(r.status, TxStatus::Success),
        "AU-7: an account that has registered nothing anchors an asset as a \
         LandRegistry. No issuer registry is consulted on this path -- there is \
         no `v_get_issuer` call anywhere in property_executor.rs or \
         property_view.rs -- so the class is whatever the payload says: {:?}",
        r.status
    );
    assert_eq!(
        stored(&view, 0x61).issuer_class,
        PropertyIssuerClass::LandRegistry,
        "AU-7: and the self-asserted class is what gets STORED"
    );

    // The same class, claimed by a different account, on a different asset.
    let mut theirs = asset(0x62, other_stranger.address());
    theirs.issuer_class = PropertyIssuerClass::LandRegistry;
    let r2 = executor
        .execute_tx(
            &mut view,
            &tx(&other_stranger, 0, PropertyOperation::AnchorAsset, &theirs),
            &proposer,
            BLOCK_HEIGHT,
            BLOCK_TIMESTAMP,
        )
        .unwrap();
    assert!(
        matches!(r2.status, TxStatus::Success),
        "AU-7: a second, unrelated account claims the same issuer class and is \
         also accepted -- there is no admission and nothing to be admitted to: \
         {:?}",
        r2.status
    );
}

/// AU-7, the discriminator: the ONE check that does exist still holds.
///
/// Without this, the test above would also pass if the arm accepted everything.
/// `issuer_address` naming an address other than the sender is refused — which
/// is exactly the audit's sentence, that where a check exists it is
/// `issuer_address == sender` and nothing more.
#[test]
fn an_issuer_address_that_is_not_the_sender_is_the_one_thing_refused() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let stranger = KeyPair::generate();
    fund(&db, &stranger, 100_000_000);
    let proposer = Address::new([9; 20]);

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);

    let someone_else = Address::new([0xEE; 20]);
    let r = executor
        .execute_tx(
            &mut view,
            &tx(
                &stranger,
                0,
                PropertyOperation::AnchorAsset,
                &asset(0x63, someone_else),
            ),
            &proposer,
            BLOCK_HEIGHT,
            BLOCK_TIMESTAMP,
        )
        .unwrap();
    assert!(
        !matches!(r.status, TxStatus::Success),
        "AU-7: `issuer_address == sender` is the one check on the path and it \
         does run -- so the acceptance above is a statement about the absent \
         registry, not about an arm that accepts everything"
    );
    assert!(
        PropertyExecutor::v_get_asset(&view, &[0x63u8; 32])
            .unwrap()
            .is_none(),
        "and nothing is written"
    );
}

// ── AU-8: `policy_id` is stored and consulted by no guard ───────────────────

/// AU-8. A `policy_id` that resolves to nothing is accepted, stored, and
/// changes no decision.
///
/// Three things are asserted, and the third is the one that makes this a pin
/// on the FIELD rather than on one value of it:
///
///   1. an anchor whose `policy_id` names no policy account succeeds;
///   2. the registry it could have been checked against is reachable from this
///      crate and says the id is absent — so the accessor exists, is callable
///      here, and simply is not called on the execution path;
///   3. two anchors differing ONLY in `policy_id` produce rows that are
///      identical except in that field, so nothing downstream of the field
///      reads it.
#[test]
fn a_policy_id_that_resolves_to_nothing_is_accepted_and_changes_no_decision() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let actor = KeyPair::generate();
    fund(&db, &actor, 100_000_000);
    let proposer = Address::new([9; 20]);
    let issuer = actor.address();

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);

    let mut unresolvable = asset(0x64, issuer);
    unresolvable.policy_id = [0xAB; 32];
    let r = executor
        .execute_tx(
            &mut view,
            &tx(&actor, 0, PropertyOperation::AnchorAsset, &unresolvable),
            &proposer,
            BLOCK_HEIGHT,
            BLOCK_TIMESTAMP,
        )
        .unwrap();
    assert!(
        matches!(r.status, TxStatus::Success),
        "AU-8: a policy id naming nothing is accepted: {:?}",
        r.status
    );

    // The registry that is NOT consulted, consulted here to show it would have
    // answered. This is the whole of the blocker the audit records: the
    // accessor is mechanically available, and what is missing is any statement
    // that a `policy_id` is a policy ACCOUNT id rather than a commitment to an
    // off-chain policy document.
    assert!(
        PolicyAccountExecutor::v_get_policy_account(&view, &[0xAB; 32])
            .expect("the policy-account reader is reachable from this crate")
            .is_none(),
        "AU-8: the one registry a `policy_id` could plausibly resolve against \
         reports the id absent, and the transaction above succeeded anyway"
    );
    assert_eq!(
        stored(&view, 0x64).policy_id,
        [0xAB; 32],
        "AU-8: the unresolvable id is STORED"
    );

    // Two anchors differing only in `policy_id`.
    let mut a = asset(0x65, issuer);
    a.policy_id = [0x01; 32];
    let mut b = asset(0x66, issuer);
    b.policy_id = [0x02; 32];
    for (nonce, payload) in [(1u64, &a), (2u64, &b)] {
        let r = executor
            .execute_tx(
                &mut view,
                &tx(&actor, nonce, PropertyOperation::AnchorAsset, payload),
                &proposer,
                BLOCK_HEIGHT,
                BLOCK_TIMESTAMP,
            )
            .unwrap();
        assert!(matches!(r.status, TxStatus::Success), "{:?}", r.status);
    }
    let mut row_a = stored(&view, 0x65);
    let mut row_b = stored(&view, 0x66);
    assert_ne!(row_a.policy_id, row_b.policy_id);
    // Normalise the two fields that are supposed to differ, and require the
    // rest to be byte-identical.
    row_a.asset_id = [0; 32];
    row_b.asset_id = [0; 32];
    row_a.asset_commitment = [0; 32];
    row_b.asset_commitment = [0; 32];
    row_a.policy_id = [0; 32];
    row_b.policy_id = [0; 32];
    assert_eq!(
        row_a, row_b,
        "AU-8: two anchors differing only in `policy_id` produce rows that \
         differ only in `policy_id` -- the field reaches storage and reaches \
         nothing else"
    );
}

// ── MD-1: payload metadata is stored without reconciliation ─────────────────

/// MD-1. A row may claim a creation time, an update time and an anchoring
/// height that contradict the block carrying it.
///
/// The block is height 1 at timestamp 1000. The payload claims it was created
/// at timestamp 1, last updated at timestamp 4_000_000_000, and anchored at
/// height 999_999 — a height this chain has not reached and, in the anchoring
/// sense, never will have reached at the moment the row is written. All three
/// are stored verbatim. Nothing on the creation path compares any of them to
/// `block_height` or `block_timestamp`.
///
/// The consequence the audit states for the DocClass instance of this row — a
/// credential issued already expired, already revoked, or valid from before the
/// chain existed — is the same mechanism: a validity window is two payload
/// numbers bound to no clock.
#[test]
fn a_creation_stores_times_and_a_height_that_contradict_its_own_block() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let actor = KeyPair::generate();
    fund(&db, &actor, 100_000_000);
    let proposer = Address::new([9; 20]);

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);

    let mut backdated = asset(0x67, actor.address());
    backdated.created_at = 1;
    backdated.updated_at = 4_000_000_000;
    backdated.anchored_at_height = 999_999;

    let r = executor
        .execute_tx(
            &mut view,
            &tx(&actor, 0, PropertyOperation::AnchorAsset, &backdated),
            &proposer,
            BLOCK_HEIGHT,
            BLOCK_TIMESTAMP,
        )
        .unwrap();
    assert!(
        matches!(r.status, TxStatus::Success),
        "MD-1: metadata that contradicts the block is not refused: {:?}",
        r.status
    );

    let row = stored(&view, 0x67);
    assert_eq!(
        row.created_at, 1,
        "MD-1: `created_at` is the payload's, not the block's {BLOCK_TIMESTAMP}"
    );
    assert_eq!(
        row.updated_at, 4_000_000_000,
        "MD-1: `updated_at` is the payload's -- a row that claims it was last \
         touched in a future the chain has not reached"
    );
    assert_eq!(
        row.anchored_at_height, 999_999,
        "MD-1: `anchored_at_height` is the payload's, not the block's \
         {BLOCK_HEIGHT}, so the row's own account of when it was anchored is \
         unrelated to when it was anchored"
    );
}

// ── MD-2: `recipient`, `tx_index` and `tx_hash` are accepted and ignored ────

/// MD-2. Three fields the transaction carries, none of which reaches state.
///
/// `recipient` rides on `PropertyTxData` and `tx_index` / `tx_hash` are
/// parameters of the executor's own entry point, which names them `_tx_index`
/// and `_tx_hash`. Each is varied here while everything else is held fixed, and
/// the resulting rows are required to be byte-identical.
///
/// `recipient` is varied through the ordinary signed-transaction path, so the
/// assertion covers dispatch as well as the executor. The other two have no
/// path that varies them per transaction within a block from a test's side, so
/// they are varied at the `execute_with_gates` seam the mixed-version tests use
/// — which is the same seam the executor reads them (does not read them) at.
#[test]
fn recipient_tx_index_and_tx_hash_reach_no_stored_row() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let actor = KeyPair::generate();
    fund(&db, &actor, 100_000_000);
    let proposer = Address::new([9; 20]);
    let issuer = actor.address();

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);

    // `recipient`: two anchors, two different recipients, through dispatch.
    for (nonce, id, recipient) in [
        (0u64, 0x68u8, Address::ZERO),
        (1, 0x69, Address::new([0xC1; 20])),
    ] {
        let r = executor
            .execute_tx(
                &mut view,
                &tx_with_recipient(
                    &actor,
                    nonce,
                    PropertyOperation::AnchorAsset,
                    &asset(id, issuer),
                    recipient,
                ),
                &proposer,
                BLOCK_HEIGHT,
                BLOCK_TIMESTAMP,
            )
            .unwrap();
        assert!(
            matches!(r.status, TxStatus::Success),
            "MD-2: a non-zero `recipient` is not refused either: {:?}",
            r.status
        );
    }
    let mut zero_recipient = stored(&view, 0x68);
    let mut named_recipient = stored(&view, 0x69);
    zero_recipient.asset_id = [0; 32];
    named_recipient.asset_id = [0; 32];
    zero_recipient.asset_commitment = [0; 32];
    named_recipient.asset_commitment = [0; 32];
    assert_eq!(
        zero_recipient, named_recipient,
        "MD-2: `PropertyTxData.recipient` is accepted and reaches no stored \
         row. It is read nowhere in crates/state/src outside \
         messaging_executor.rs"
    );

    // `tx_index` and `tx_hash`: the executor entry point takes both and names
    // them `_tx_index` and `_tx_hash`.
    let data = |id: u8| PropertyTxData {
        operation: PropertyOperation::AnchorAsset,
        data: bincode::serialize(&asset(id, issuer)).unwrap(),
        recipient: Address::ZERO,
    };
    for (id, tx_index, tx_hash) in [
        (0x6Au8, 0u32, Hash::hash(b"one")),
        (0x6B, 7_777, Hash::hash(b"an entirely different hash")),
    ] {
        let r = PropertyExecutor::execute(
            &mut view,
            &params(),
            &issuer,
            &data(id),
            &proposer,
            100,
            BLOCK_HEIGHT,
            BLOCK_TIMESTAMP,
            tx_index,
            tx_hash,
        )
        .expect("execute");
        assert!(
            r.success,
            "MD-2: neither `tx_index` nor `tx_hash` can refuse anything"
        );
    }
    let mut first = stored(&view, 0x6A);
    let mut second = stored(&view, 0x6B);
    first.asset_id = [0; 32];
    second.asset_id = [0; 32];
    first.asset_commitment = [0; 32];
    second.asset_commitment = [0; 32];
    assert_eq!(
        first, second,
        "MD-2: `tx_index` and `tx_hash` are taken by the executor's own entry \
         point and bound to `_`-prefixed names; varying them by 7,777 and by a \
         whole hash changes no byte of the row"
    );

    // And nothing was committed: every assertion above is about the candidate.
    assert!(
        db.prefix_iter(cf::PROPERTY_ASSETS, &[])
            .unwrap()
            .next()
            .is_none(),
        "the candidate was never published, so canonical storage is untouched"
    );
}
