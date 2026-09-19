//! `subsystem_tx_write_set_bound_enabled_from_height`: one transaction's write
//! set is bounded independently of the block's, and crossing the bound costs
//! that TRANSACTION rather than the block.
//!
//! # The gap this closes
//!
//! `sumchain_state::MAX_BLOCK_WRITE_SET_BYTES` bounds a BLOCK, and
//! `crates/state/tests/block_write_set_ceiling.rs` derives it — a SAFETY bound,
//! an eighth of the 4 GiB cgroup limit the validator manifests enforce. Nothing
//! in this file touches that derivation or softens it, and nothing here should
//! be read as making it a statement of sufficient capacity, because no value of
//! it could be one:
//!
//! > A block's write set is not bounded by the block's size, because a
//! > read-modify-write charges the PRE-IMAGE of a row the block does not carry.
//!
//! One ~100-byte `AddKey` against a 1 MiB row charges 2 MiB. A 2,000,000-byte
//! block holds a thousand of them. So a block of ENTIRELY VALID transactions
//! charges about 2 GiB, which no survivable ceiling admits — and below this
//! gate the consequence lands on the WHOLE BLOCK, because the overlay's refusal
//! leaves `execute_tx` as an `Err` and `execute_block`'s loop propagates it.
//!
//! On an importing node that is a correct refusal. On a PROPOSER it is a
//! permanent halt, and `crates/consensus/tests/proposer_write_set_fit.rs` is
//! where that half is tested.
//!
//! # What is asserted here
//!
//!   * the bound is DETERMINISTIC — a pure function of the bytes staged, the
//!     same on two independent executions, and independent of how full the
//!     block already was;
//!   * READ-MODIFY-WRITE is the case, not an edge case: the whole point is the
//!     small payload that rewrites a large existing row;
//!   * the EXACT BOUNDARY is admitted and ONE BYTE OVER is refused, measured on
//!     a real transaction through `execute_tx` rather than on a hand-built
//!     `put`;
//!   * SEVERAL large transactions in one block are each refused individually
//!     and the block still publishes;
//!   * a refusal PAYS ITS FEE and ADVANCES ITS NONCE;
//!   * a refusal leaves CANONICAL STATE as it found it;
//!   * the bound admits the largest HONEST transaction the chain's own declared
//!     limits allow, MEASURED on the production path;
//!   * and the bound does NOT turn the block ceiling into a sufficiency bound,
//!     which is pinned so that nobody later reads it as one.
//!
//! The runtime and peak-live-memory COST of the checking is measured in
//! `crates/state/tests/transaction_write_set_bound_cost.rs`, which needs a
//! counting global allocator and therefore one test per binary.

mod common;

use common::{fund, setup_with_params, CHAIN_ID};
use sumchain_crypto::{sign, KeyPair};
use sumchain_genesis::{ChainParams, Genesis};
use sumchain_primitives::{
    Address, Block, BlockHeader, DocClassOperation, DocClassTxData, DocSubcode, Hash, IdentityKey,
    IdentityRoot, IdentityStatus, KeyPurpose, KeyType, SignedTransaction, TransactionV2, TxPayload,
    TxStatus,
};
use sumchain_state::{
    StateError, MAX_ACCUMULATING_ROW_BYTES, MAX_BLOCK_WRITE_SET_BYTES, MAX_TX_WRITE_SET_BYTES,
    TX_WRITE_SET_BOUND_RECEIPT_CODE,
};
use sumchain_storage::exec_view::ExecutionView;
use sumchain_storage::overlay::ApplicationOverlay;
use sumchain_storage::{cf, Database, DocClassStore, StateStore, StorageError};

// ── Fixtures ────────────────────────────────────────────────────────────────

/// A row large enough that ONE read-modify-write against it charges more than
/// [`MAX_TX_WRITE_SET_BYTES`].
///
/// `AddKey` charges the captured pre-image AND the re-encoded row, so the
/// charge is about twice the row. Nine mebibytes therefore charges about
/// eighteen against a sixteen-mebibyte bound — past it, with enough margin that
/// the test does not depend on the exact per-row constant factor, and small
/// enough that the fixture costs tens of megabytes rather than hundreds.
const OVERSIZED_ROW: usize = 9 << 20;

/// A row whose read-modify-write is comfortably INSIDE the bound, for the
/// transactions that must still succeed in the same blocks.
const ORDINARY_ROW: usize = 1 << 20;

fn params_at(activation: Option<u64>) -> ChainParams {
    let mut p = ChainParams::with_v2_enabled();
    if let Some(ref mut d) = p.docclass {
        d.min_issuer_stake = 0;
    }
    p.subsystem_tx_write_set_bound_enabled_from_height = activation;
    p
}

/// The gate OPEN from genesis.
fn params_open() -> ChainParams {
    params_at(Some(0))
}

/// The gate CLOSED, which is `ChainParams::default()`'s setting and the
/// unremediated binary.
fn params_closed() -> ChainParams {
    params_at(None)
}

fn key_with_id(id: String) -> IdentityKey {
    IdentityKey {
        key_id: id,
        key_type: KeyType::Ed25519,
        public_key: [7u8; 32],
        purposes: vec![KeyPurpose::Authentication],
        added_at: 1_000,
        expires_at: 0,
        active: true,
    }
}

fn identity(identity_id: [u8; 32], controller: Address) -> IdentityRoot {
    IdentityRoot {
        identity_id,
        subject_commitment: [0x40; 32],
        controller,
        additional_controllers: vec![],
        keys: vec![],
        services: vec![],
        created_at: 1_000,
        updated_at: 1_000,
        status: IdentityStatus::Active,
        schema_hash: [0u8; 32],
    }
}

#[derive(serde::Serialize)]
struct AddKeyData {
    identity_id: [u8; 32],
    key: IdentityKey,
}

fn docclass_tx(
    kp: &KeyPair,
    nonce: u64,
    operation: DocClassOperation,
    payload: &impl serde::Serialize,
) -> SignedTransaction {
    let t = TransactionV2 {
        chain_id: CHAIN_ID,
        from: kp.address(),
        fee: 1_000,
        nonce,
        payload: TxPayload::DocClass(DocClassTxData {
            operation,
            subcode: DocSubcode::IdentityRoot,
            data: bincode::serialize(payload).unwrap(),
            recipient: Address::ZERO,
        }),
    };
    let sig = sign(t.signing_hash().as_bytes(), kp.private_key());
    SignedTransaction::new_v2(t, *sig.as_bytes(), *kp.public_key().as_bytes())
}

fn transfer_tx(kp: &KeyPair, nonce: u64, to: Address, amount: u128) -> SignedTransaction {
    let t = TransactionV2 {
        chain_id: CHAIN_ID,
        from: kp.address(),
        fee: 1_000,
        nonce,
        payload: TxPayload::Transfer { to, amount },
    };
    let sig = sign(t.signing_hash().as_bytes(), kp.private_key());
    SignedTransaction::new_v2(t, *sig.as_bytes(), *kp.public_key().as_bytes())
}

fn block_of(height: u64, txs: Vec<SignedTransaction>) -> Block {
    Block::new(
        BlockHeader::new(Hash::ZERO, height, 1000, Hash::ZERO, Hash::ZERO, [9u8; 32]),
        txs,
    )
}

/// The identity id the `n`th seeded row is keyed by. Distinct per row: the
/// overlay charges a pre-image once per DISTINCT key, so reusing one id would
/// charge one row however many transactions touched it.
fn ident(n: usize) -> [u8; 32] {
    let mut id = [0xE0u8; 32];
    id[..8].copy_from_slice(&(n as u64).to_be_bytes());
    id
}

/// Commit an identity row of about `bytes` encoded length under `ident(n)`, and
/// return its exact committed length.
fn seed_row(db: &Database, n: usize, controller: Address, bytes: usize) -> usize {
    let mut root = identity(ident(n), controller);
    root.keys = vec![key_with_id("x".repeat(bytes))];
    DocClassStore::new(db).identity_roots().put(&root).unwrap();
    db.get(cf::DOCCLASS_IDENTITY_ROOTS, &ident(n))
        .unwrap()
        .expect("the seeded row must be there")
        .len()
}

/// The ~100-byte `AddKey` that rewrites the whole of row `n`.
///
/// This IS the class. The payload is a few dozen bytes; the charge is twice the
/// row it names, because `AddKey` reads the row, decodes the whole of it,
/// pushes one entry and re-encodes the whole of it, and the overlay then
/// charges both the new value and the captured pre-image.
fn add_key_tx(kp: &KeyPair, nonce: u64, n: usize) -> SignedTransaction {
    docclass_tx(
        kp,
        nonce,
        DocClassOperation::AddKey,
        &AddKeyData {
            identity_id: ident(n),
            key: key_with_id(format!("k{n}")),
        },
    )
}

/// Run ONE transaction against a seeded database inside an overlay scope of
/// `tx_limit`, and report what happened.
///
/// The BLOCK ceiling is the production one throughout, so the only thing under
/// test is the per-transaction bound.
fn run_scoped(
    db: &Database,
    executor: &sumchain_state::BlockExecutor,
    tx: &SignedTransaction,
    tx_limit: u64,
) -> (Result<TxStatus, StorageError>, u64) {
    let mut overlay = ApplicationOverlay::new(db, MAX_BLOCK_WRITE_SET_BYTES);
    overlay.begin_transaction(tx_limit).expect("no scope open");
    let proposer = Address::new([9; 20]);
    let outcome = {
        let mut view = ExecutionView::new(&mut overlay);
        executor.execute_tx(&mut view, tx, &proposer, 1, 1_000)
    };
    match outcome {
        Ok(receipt) => {
            let charged = overlay.transaction_bytes().expect("the scope is open");
            (Ok(receipt.status), charged)
        }
        Err(StateError::Storage(e)) => {
            let charged = overlay.transaction_bytes().expect("the scope is open");
            (Err(e), charged)
        }
        Err(other) => panic!("unexpected non-storage error: {other}"),
    }
}

// ── 1. The bound is deterministic, and it is about read-modify-write ────────

/// The charge is a pure function of the bytes staged: the same transaction
/// against the same state charges the same number twice, and the number tracks
/// the ROW rather than the payload.
///
/// Determinism is not decoration here. Two validators must agree about whether
/// a transaction succeeded, because a failed receipt is hashed into the block's
/// accumulator. A bound that read an allocator's high-water mark, a wall clock
/// or a resident-set size would be a bound two honest validators could compute
/// differently, and the chain would split on the difference.
#[test]
fn the_charge_is_a_deterministic_function_of_the_row_and_not_of_the_payload() {
    let mut charges = Vec::new();
    for run in 0..2 {
        let (_s, db, _dir, executor) = setup_with_params(params_open());
        let actor = KeyPair::generate();
        fund(&db, &actor, 1_000_000_000_000_000);
        let row = seed_row(&db, 0, actor.address(), ORDINARY_ROW);
        let tx = add_key_tx(&actor, 0, 0);
        let payload = match tx.inner() {
            sumchain_primitives::TxInner::V2(v2) => match &v2.payload {
                TxPayload::DocClass(d) => d.data.len(),
                _ => unreachable!(),
            },
            _ => unreachable!(),
        };
        let (outcome, charged) = run_scoped(&db, &executor, &tx, MAX_TX_WRITE_SET_BYTES);
        assert_eq!(
            outcome.as_ref().ok(),
            Some(&TxStatus::Success),
            "a 1 MiB row is well inside the bound"
        );
        println!(
            "run {run}: row {row} B, payload {payload} B, charged {charged} B \
             ({:.2}x the row, {:.0}x the payload)",
            charged as f64 / row as f64,
            charged as f64 / payload as f64,
        );
        assert!(
            charged > 2 * row as u64,
            "the charge must carry the captured PRE-IMAGE as well as the \
             re-encoded row — that is the whole mechanism — but it is \
             {charged} B against a {row} B row"
        );
        assert!(
            charged > 100 * payload as u64,
            "and it must be driven by the row, not the payload: {charged} B \
             charged for a {payload} B payload. If this ever stops holding, the \
             defect being bounded has changed shape and the bound needs \
             re-deriving"
        );
        charges.push(charged);
    }
    assert_eq!(
        charges[0], charges[1],
        "two independent executions of the same transaction against the same \
         state must charge the SAME number. They do not merely agree closely: a \
         failed receipt is hashed into the block accumulator, so a bound that \
         two validators computed differently would split the chain"
    );
}

// ── 2. The exact boundary, and one byte over ────────────────────────────────

/// A transaction charging exactly the bound is ADMITTED; the same transaction
/// under a bound one byte smaller is REFUSED.
///
/// Measured on a real transaction through `execute_tx`, not on a hand-built
/// `put`: the boundary that matters is the one the production dispatch crosses,
/// and a `put` of a known size would prove only that `>` is not `>=`.
///
/// The bound is varied rather than the transaction because a transaction cannot
/// be tuned to a byte — its charge is the sum of a re-encoded row, a captured
/// pre-image, an event row and three account rows. Varying the limit around a
/// MEASURED charge tests exactly the same comparison from the other side.
#[test]
fn the_exact_boundary_is_admitted_and_one_byte_over_is_refused() {
    let (_s, db, _dir, executor) = setup_with_params(params_open());
    let actor = KeyPair::generate();
    fund(&db, &actor, 1_000_000_000_000_000);
    let row = seed_row(&db, 0, actor.address(), ORDINARY_ROW);
    let tx = add_key_tx(&actor, 0, 0);

    // What it costs, under a bound that cannot bite.
    let (probe, exact) = run_scoped(&db, &executor, &tx, MAX_TX_WRITE_SET_BYTES);
    assert_eq!(probe.ok(), Some(TxStatus::Success));
    println!("boundary: a {row} B row's AddKey charges exactly {exact} B");

    // AT the bound: admitted, and the charge is exactly the bound.
    let (at, charged_at) = run_scoped(&db, &executor, &tx, exact);
    assert_eq!(
        at.as_ref().ok(),
        Some(&TxStatus::Success),
        "a transaction charging EXACTLY the bound must be admitted; the \
         comparison is `charge > limit`, and an off-by-one here refuses a \
         transaction every other validator accepts: {at:?}"
    );
    assert_eq!(
        charged_at, exact,
        "and it must have charged exactly what it charged unbounded — the bound \
         is a refusal, not a budget that changes behaviour as it fills"
    );

    // ONE BYTE over: refused, and the error names both numbers.
    let (over, charged_over) = run_scoped(&db, &executor, &tx, exact - 1);
    match over {
        Err(StorageError::TransactionWriteSetExceeded { limit, would_reach }) => {
            println!(
                "boundary: under a {limit} B bound the same transaction would \
                 reach {would_reach} B and is refused"
            );
            assert_eq!(limit, exact - 1);
            assert!(
                would_reach > limit,
                "the refusal must name a total that actually crosses the bound"
            );
        }
        other => panic!(
            "one byte over the measured charge must be refused, by the \
             per-transaction variant and not by anything else: {other:?}"
        ),
    }
    assert!(
        charged_over < exact,
        "and the refused transaction must not have kept the charge it was \
         refused for: {charged_over} B still accounted"
    );
}

// ── 3. Several large transactions in one block ──────────────────────────────

/// Three read-modify-writes that each cross the bound, in one block, alongside
/// transactions that do not.
///
/// This is the shape the gate exists for. Below it the FIRST of these makes the
/// block unexecutable and the other five transactions never run. Above it each
/// is refused on its own, and the block publishes.
#[test]
fn several_oversized_transactions_in_one_block_are_refused_individually() {
    let (state, db, _dir, executor) = setup_with_params(params_open());
    let actor = KeyPair::generate();
    fund(&db, &actor, 1_000_000_000_000_000);

    // Three rows whose rewrite crosses the bound, three that do not.
    let mut seeded = Vec::new();
    for n in 0..3 {
        seeded.push(seed_row(&db, n, actor.address(), OVERSIZED_ROW));
    }
    for n in 3..6 {
        seeded.push(seed_row(&db, n, actor.address(), ORDINARY_ROW));
    }

    // Interleaved, so a refusal is shown not to disturb the transaction after
    // it — which is what a rollback that overshot would do.
    let order = [0usize, 3, 1, 4, 2, 5];
    let txs: Vec<SignedTransaction> = order
        .iter()
        .enumerate()
        .map(|(nonce, &n)| add_key_tx(&actor, nonce as u64, n))
        .collect();

    let mut block = block_of(1, txs);
    let exec = executor
        .execute_block(&block, state.state_root(), &[])
        .expect(
            "with the gate open, three transactions that each cross the \
             per-transaction bound must NOT make the block unexecutable — that \
             is the whole change",
        );
    block.header.state_root = exec.computed_root();
    let (executed, _sd, _cd) = exec.into_parts();
    let receipts: Vec<TxStatus> = executed.receipts().iter().map(|r| r.status).collect();
    let fees: Vec<u128> = executed.receipts().iter().map(|r| r.fee_paid).collect();
    println!(
        "block of six: statuses {receipts:?}, fees {fees:?}, charged {} B \
         against a {MAX_BLOCK_WRITE_SET_BYTES} B ceiling",
        executed.logical_bytes()
    );

    for (slot, &n) in order.iter().enumerate() {
        let expected = if n < 3 {
            TxStatus::Failed(TX_WRITE_SET_BOUND_RECEIPT_CODE)
        } else {
            TxStatus::Success
        };
        assert_eq!(
            receipts[slot], expected,
            "slot {slot} rewrites the {} B row {n}; every oversized one must \
             fail on its own and every ordinary one must still succeed, \
             including the ones sitting between them",
            seeded[n]
        );
    }

    executed
        .accept_produced(&block)
        .expect("accept")
        .publish()
        .expect("a block carrying three refusals must still publish");
    let _ = state;
}

// ── 4. The fee and the nonce ────────────────────────────────────────────────

/// A refused transaction PAYS ITS FEE and ADVANCES ITS NONCE, and the proposer
/// is credited.
///
/// The work was done: the transaction executed far enough to stage more than
/// its bound allows, which means the row was read, decoded and re-encoded
/// before anything could notice. A refusal that cost the sender nothing would
/// be free to repeat every block, which is the same denial of service wearing a
/// failed receipt.
///
/// The nonce matters for a second reason. A refusal that left the nonce alone
/// would leave the sender's NEXT transaction using the same nonce — so a sender
/// with a queue behind an oversized transaction could not make progress until
/// they noticed and rebuilt it.
#[test]
fn a_refused_transaction_pays_its_fee_and_advances_its_nonce() {
    let (state, db, _dir, executor) = setup_with_params(params_open());
    let actor = KeyPair::generate();
    const FUNDED: u128 = 1_000_000_000_000_000;
    fund(&db, &actor, FUNDED);
    seed_row(&db, 0, actor.address(), OVERSIZED_ROW);

    // Two transactions from one sender: the refused one, then an ordinary
    // transfer at the NEXT nonce. The second only validates if the first
    // advanced the nonce, so the nonce claim is made by a transaction rather
    // than by an assertion on a field.
    let recipient = Address::new([0x5A; 20]);
    let txs = vec![
        add_key_tx(&actor, 0, 0),
        transfer_tx(&actor, 1, recipient, 7),
    ];
    let mut block = block_of(1, txs);
    let exec = executor
        .execute_block(&block, state.state_root(), &[])
        .expect("the block survives the refusal");
    block.header.state_root = exec.computed_root();
    let (executed, _sd, _cd) = exec.into_parts();

    let receipts = executed.receipts().to_vec();
    assert_eq!(
        receipts[0].status,
        TxStatus::Failed(TX_WRITE_SET_BOUND_RECEIPT_CODE),
        "the oversized transaction takes the write-set receipt code"
    );
    assert_eq!(
        receipts[0].fee_paid, 1_000,
        "and it PAYS. A free refusal is a free retry, every block, for as long \
         as the attacker cares to send it"
    );
    assert_eq!(
        receipts[1].status,
        TxStatus::Success,
        "and the follow-on transaction at nonce 1 validates, which it can only \
         do if the refusal advanced the nonce to 1"
    );

    executed
        .accept_produced(&block)
        .expect("accept")
        .publish()
        .expect("publish");

    let store = StateStore::new(&db);
    let sender = store.get_account(&actor.address()).unwrap();
    assert_eq!(
        sender.nonce, 2,
        "one refused transaction and one successful one: both nonces consumed"
    );
    assert_eq!(
        sender.balance,
        FUNDED - 1_000 - 1_000 - 7,
        "both fees debited and the transfer moved"
    );
    let proposer = store
        .get_account(&Address::from_public_key(&[9u8; 32]))
        .unwrap();
    assert_eq!(
        proposer.balance, 2_000,
        "the proposer is credited for the refused transaction too: it did the \
         work of executing it"
    );
}

// ── 5. Canonical state after a refusal ──────────────────────────────────────

/// A refusal leaves canonical state exactly as it found it.
///
/// Asserted BYTE-FOR-BYTE against the row as it was seeded, and against the
/// column family as a whole, so a rollback that restored the row but left an
/// event row, an index entry or a stray key behind is caught. This is the
/// property the whole rollback exists for: if the refusal could leave half a
/// transaction behind, the per-transaction bound would be a new source of
/// divergence rather than a remedy for one.
#[test]
fn a_refusal_leaves_canonical_state_exactly_as_it_found_it() {
    let (state, db, _dir, executor) = setup_with_params(params_open());
    let actor = KeyPair::generate();
    fund(&db, &actor, 1_000_000_000_000_000);
    seed_row(&db, 0, actor.address(), OVERSIZED_ROW);

    /// Every key and value in a column family, in order.
    fn dump(db: &Database, family: &str) -> Vec<(Vec<u8>, Vec<u8>)> {
        db.iter(family)
            .unwrap()
            .map(|(k, v)| (k.to_vec(), v.to_vec()))
            .collect()
    }
    let families = [
        cf::DOCCLASS_IDENTITY_ROOTS,
        cf::DOCCLASS_EVENTS,
        cf::DOCCLASS_SUBJECT_INDEX,
    ];
    let before: Vec<Vec<(Vec<u8>, Vec<u8>)>> = families.iter().map(|f| dump(&db, f)).collect();

    let mut block = block_of(1, vec![add_key_tx(&actor, 0, 0)]);
    let exec = executor
        .execute_block(&block, state.state_root(), &[])
        .expect("the block survives");
    block.header.state_root = exec.computed_root();
    let (executed, _sd, _cd) = exec.into_parts();
    assert_eq!(
        executed.receipts()[0].status,
        TxStatus::Failed(TX_WRITE_SET_BOUND_RECEIPT_CODE)
    );
    executed
        .accept_produced(&block)
        .expect("accept")
        .publish()
        .expect("publish");

    for (family, was) in families.iter().zip(before) {
        let now = dump(&db, family);
        assert_eq!(
            now.len(),
            was.len(),
            "{family} gained or lost rows across a refused transaction"
        );
        assert!(
            now == was,
            "{family} is not byte-identical after a refused transaction. A \
             rollback that restores the row but leaves an event, an index entry \
             or a partial write behind is a new source of divergence, not a \
             remedy for one"
        );
    }
    println!(
        "canonical state after a refusal: {} column families byte-identical, \
         including the {} B row the transaction had already decoded and \
         re-encoded",
        families.len(),
        db.get(cf::DOCCLASS_IDENTITY_ROOTS, &ident(0))
            .unwrap()
            .unwrap()
            .len()
    );
}

// ── 6. The closed gate is the unremediated binary ───────────────────────────

/// With the gate CLOSED the very transaction the bound refuses SUCCEEDS, and
/// commits.
///
/// This is the test that makes the gate honest, and it is the one that has to
/// FAIL if the gate is ever wired to read open. It was added because a mutation
/// that made `subsystem_tx_write_set_bound_gate_open` return `true`
/// unconditionally — a dormant gate that is not dormant, which is the single
/// most damaging thing that can go wrong with an activation height — survived
/// the block-ceiling test below: that fixture crosses the BLOCK ceiling, which
/// it does on both sides of the gate, so it never told the two apart.
///
/// The distinguishing fixture is one transaction that crosses the
/// PER-TRANSACTION bound and nothing else. Below the gate nothing is measuring
/// it, so it is admitted, it commits, and the row grows — byte-for-byte the
/// binary that existed before this field was declared.
#[test]
fn with_the_gate_closed_the_transaction_the_bound_refuses_succeeds_instead() {
    let (state, db, _dir, executor) = setup_with_params(params_closed());
    let actor = KeyPair::generate();
    fund(&db, &actor, 1_000_000_000_000_000);
    let seeded = seed_row(&db, 0, actor.address(), OVERSIZED_ROW);

    let mut block = block_of(1, vec![add_key_tx(&actor, 0, 0)]);
    let exec = executor
        .execute_block(&block, state.state_root(), &[])
        .expect("below the gate this is an ordinary transaction");
    block.header.state_root = exec.computed_root();
    let (executed, _sd, _cd) = exec.into_parts();
    let receipt = executed.receipts()[0].clone();
    let charged = executed.logical_bytes();
    println!(
        "GATE CLOSED: an AddKey against a {seeded} B row charges {charged} B — \
         {:.1}x the {MAX_TX_WRITE_SET_BYTES} B bound the OPEN gate would hold it \
         to — and is ADMITTED, status {:?}",
        charged as f64 / MAX_TX_WRITE_SET_BYTES as f64,
        receipt.status
    );
    assert_eq!(
        receipt.status,
        TxStatus::Success,
        "below the gate NOTHING bounds one transaction's write set, so this \
         must succeed. If it fails here, the gate is open when the genesis says \
         it is closed, and every node built from this commit computes a \
         different state root from every node built before it"
    );
    assert!(
        charged > MAX_TX_WRITE_SET_BYTES,
        "and the fixture must actually be one the open gate would refuse, or \
         this test distinguishes nothing: it charged {charged} B against a \
         {MAX_TX_WRITE_SET_BYTES} B bound"
    );

    executed
        .accept_produced(&block)
        .expect("accept")
        .publish()
        .expect("publish");
    let after = db
        .get(cf::DOCCLASS_IDENTITY_ROOTS, &ident(0))
        .unwrap()
        .expect("the row is still there")
        .len();
    assert!(
        after > seeded,
        "and it COMMITTED: the row grew from {seeded} B to {after} B, which is \
         the write the open gate rolls back"
    );
}

/// The block ceiling still refuses a block — and now names the transaction that
/// crossed it.
///
/// True on BOTH sides of the gate, which is the point: a per-transaction bound
/// does not replace the block ceiling, and a thousand transactions each inside
/// their own bound can still cross the block's. What changed is that the
/// refusal carries an INDEX, which is the only thing a proposer can act on.
#[test]
fn the_block_ceiling_refusal_names_the_transaction_that_crossed_it() {
    let (state, db, _dir, executor) = setup_with_params(params_closed());
    let actor = KeyPair::generate();
    fund(&db, &actor, 1_000_000_000_000_000);

    // A row big enough to cross the BLOCK ceiling in one transaction, which is
    // the only bound in force below the gate.
    let rows = (MAX_BLOCK_WRITE_SET_BYTES as usize / ORDINARY_ROW) + 16;
    for n in 0..rows {
        seed_row(&db, n, actor.address(), ORDINARY_ROW);
    }
    let txs: Vec<SignedTransaction> = (0..rows).map(|n| add_key_tx(&actor, n as u64, n)).collect();
    let block = block_of(1, txs);

    match executor.execute_block(&block, state.state_root(), &[]) {
        Err(StateError::BlockWriteSetExceeded { tx_index, detail }) => {
            println!(
                "GATE CLOSED: the block is refused at transaction {tx_index} of \
                 {rows}: {detail}"
            );
            assert!(
                detail.contains("logical byte limit"),
                "the refusal must still come from the ceiling: {detail}"
            );
            assert!(
                detail.contains(&MAX_BLOCK_WRITE_SET_BYTES.to_string()),
                "and must still name the ceiling the production path enforces: \
                 {detail}"
            );
            assert!(
                tx_index < rows,
                "and must name a transaction that is actually in the block"
            );
        }
        Ok(_) => panic!(
            "below the gate the ONLY write-set bound is the block ceiling, and \
             {rows} rewrites of {ORDINARY_ROW} B rows must cross it. An Ok here \
             means the closed gate is no longer the unremediated binary"
        ),
        Err(other) => panic!("refused by something other than the ceiling: {other}"),
    }
}

// ── 7. Sufficiency of the BOUND, measured ───────────────────────────────────

/// The bound admits the largest HONEST transaction the chain's own declared
/// limits allow, with margin, MEASURED on the production path.
///
/// Three declared limits bound an honest transaction's charge, and all three
/// are read here rather than restated:
///
///   * `max_block_bytes` from this repository's `genesis.json` bounds the
///     payload, because `validate_block` refuses the block carrying it before
///     `execute_block` decodes anything;
///   * `MAX_ACCUMULATING_ROW_BYTES` bounds the pre-image of any row a gated
///     accumulating operation may rewrite;
///   * and the event row a subsystem writes alongside carries at most a second
///     copy of the payload.
///
/// The fixture is built at those limits and the charge is measured. A bound
/// that did not clear it would refuse transactions an honest sender is entitled
/// to make — the mirror of the sufficiency failure
/// `block_write_set_ceiling.rs` guards the ceiling against.
#[test]
fn the_bound_admits_the_largest_honest_transaction_with_margin() {
    /// The margin demanded, for the reason `block_write_set_ceiling.rs` gives
    /// for its own: what grows a write set is the chain's data, not its
    /// configuration, and a margin that only just holds today stops holding
    /// without anybody editing this file.
    const MIN_MARGIN: u64 = 2;

    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(std::path::Path::parent)
        .expect("crates/state -> crates -> repository root")
        .join("genesis.json");
    let genesis = Genesis::from_file(&root).expect("the repository's genesis.json must load");
    let max_block_bytes = genesis.params.max_block_bytes as usize;

    let (_s, db, _dir, executor) = setup_with_params(params_open());
    let actor = KeyPair::generate();
    fund(&db, &actor, 1_000_000_000_000_000);

    // The worst honest transaction: a payload as large as a block may carry,
    // appended to a row as large as the accumulating-row bound admits. Both
    // halves at once, which no honest sender manages but which is the ceiling
    // of what one could.
    let row = seed_row(&db, 0, actor.address(), MAX_ACCUMULATING_ROW_BYTES);
    let payload_budget = max_block_bytes - 100_000;
    let tx = docclass_tx(
        &actor,
        0,
        DocClassOperation::AddKey,
        &AddKeyData {
            identity_id: ident(0),
            key: key_with_id("g".repeat(payload_budget)),
        },
    );
    let (outcome, charged) = run_scoped(&db, &executor, &tx, MAX_TX_WRITE_SET_BYTES);
    assert_eq!(
        outcome.as_ref().ok(),
        Some(&TxStatus::Success),
        "the largest transaction the chain's own limits admit must be ADMITTED \
         by the per-transaction bound. A refusal here is the bound refusing \
         honest traffic: {outcome:?}"
    );

    let margin = MAX_TX_WRITE_SET_BYTES as f64 / charged as f64;
    println!(
        "SUFFICIENCY (MEASURED, production path): a {payload_budget} B payload \
         appended to a {row} B row — genesis.json max_block_bytes \
         {max_block_bytes}, MAX_ACCUMULATING_ROW_BYTES \
         {MAX_ACCUMULATING_ROW_BYTES} — charges {charged} B against a \
         {MAX_TX_WRITE_SET_BYTES} B bound. Margin {margin:.1}x"
    );
    assert!(
        MAX_TX_WRITE_SET_BYTES >= charged.saturating_mul(MIN_MARGIN),
        "the largest honest transaction charges {charged} B and the bound of \
         {MAX_TX_WRITE_SET_BYTES} B clears it by only {margin:.1}x, under the \
         {MIN_MARGIN}x this bound claims. A bound this close to honest traffic \
         refuses a transaction somebody is entitled to send"
    );
}

// ── 8. What this bound is NOT ───────────────────────────────────────────────

/// The per-transaction bound does NOT make the block ceiling a sufficiency
/// bound, and this test exists so that nobody reads it as one.
///
/// A reader who sees a per-transaction bound land naturally reaches for
/// `bound x max_txs_per_block <= ceiling` and concludes the block ceiling is now
/// proved sufficient. It is not, it cannot be, and the arithmetic goes the
/// other way by two orders of magnitude — deliberately, because the
/// per-transaction bound has to admit the largest HONEST transaction and a
/// thousand of those do not have to fit in one block.
///
/// So the block ceiling remains what `block_write_set_ceiling.rs` derives: a
/// SAFETY bound, an eighth of the 4 GiB the deployment manifests enforce, and
/// never a statement of sufficient capacity. What closes the remaining gap is
/// the PROPOSER declining to include the transaction that would cross it — see
/// `crates/consensus/src/poa.rs` — and that is a liveness remedy, not a proof.
#[test]
fn the_per_transaction_bound_is_not_a_sufficiency_proof_for_the_block_ceiling() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(std::path::Path::parent)
        .expect("crates/state -> crates -> repository root")
        .join("genesis.json");
    let genesis = Genesis::from_file(&root).expect("the repository's genesis.json must load");
    let max_txs = u64::from(genesis.params.max_txs_per_block);

    let worst = MAX_TX_WRITE_SET_BYTES.saturating_mul(max_txs);
    println!(
        "NON-SUFFICIENCY: {max_txs} transactions at the {MAX_TX_WRITE_SET_BYTES} B \
         per-transaction bound charge up to {worst} B ({} GiB), against a \
         {MAX_BLOCK_WRITE_SET_BYTES} B ({} MiB) block ceiling — {:.0}x over. The \
         ceiling stays a SAFETY bound derived from the deployment memory limit; \
         it is not proof that a block of valid transactions fits.",
        worst >> 30,
        MAX_BLOCK_WRITE_SET_BYTES >> 20,
        worst as f64 / MAX_BLOCK_WRITE_SET_BYTES as f64,
    );
    assert!(
        worst > MAX_BLOCK_WRITE_SET_BYTES,
        "if `MAX_TX_WRITE_SET_BYTES * max_txs_per_block` ever fits under \
         `MAX_BLOCK_WRITE_SET_BYTES`, one of two things happened, and both need \
         saying out loud rather than discovering later. Either the \
         per-transaction bound was tightened until it refuses honest traffic \
         (the sufficiency test above is the one that should then fail), or the \
         block ceiling was raised past what the safety derivation allows (and \
         `block_write_set_ceiling.rs` is the one that should then fail). What \
         must NOT happen is this inequality flipping quietly and the block \
         ceiling being reread as a capacity guarantee it has never been"
    );
}

/// The bound HALVES the worst-case transient the block ceiling must cover, and
/// this is stated as a by-product rather than as a new licence.
///
/// `block_write_set_ceiling.rs` derives the safety side from the largest single
/// row a block can commit, `C / 2`, because the overlay charges the new value
/// and the pre-image. With a per-transaction bound in force that largest row
/// falls to `MAX_TX_WRITE_SET_BYTES / 2`, so the transient on top of a full
/// candidate falls with it.
///
/// It does NOT license raising the ceiling. The derivation over there is
/// unchanged and its test is untouched; this only records that the margin got
/// wider, and it is the ceiling's owner's call what, if anything, to do about
/// that.
#[test]
fn the_bound_narrows_the_transient_the_block_ceiling_has_to_cover() {
    // MEASURED, `release_ceiling_allocation.rs` section M2: peak live is
    // 4.00x the row, of which the overlay's retained charge is 2.00x.
    const PEAK_LIVE_FACTOR: u64 = 4;
    const CHARGE_FACTOR: u64 = 2;

    let unbounded_row = MAX_BLOCK_WRITE_SET_BYTES / CHARGE_FACTOR;
    let bounded_row = MAX_TX_WRITE_SET_BYTES / CHARGE_FACTOR;
    let unbounded_peak =
        MAX_BLOCK_WRITE_SET_BYTES + unbounded_row * (PEAK_LIVE_FACTOR - CHARGE_FACTOR);
    let bounded_peak =
        MAX_BLOCK_WRITE_SET_BYTES + bounded_row * (PEAK_LIVE_FACTOR - CHARGE_FACTOR);

    println!(
        "TRANSIENT: largest single row one transaction may commit falls from \
         {unbounded_row} B ({} MiB) to {bounded_row} B ({} MiB), so the \
         worst-case peak live for a block at the ceiling falls from \
         {unbounded_peak} B ({} MiB) to {bounded_peak} B ({} MiB). The ceiling \
         is UNCHANGED and its derivation is untouched; the margin is wider, and \
         whether to spend it is not this file's call.",
        unbounded_row >> 20,
        bounded_row >> 20,
        unbounded_peak >> 20,
        bounded_peak >> 20,
    );
    assert!(
        bounded_peak < unbounded_peak,
        "a per-transaction bound that did not reduce the worst-case transient \
         would not be bounding the quantity it claims to"
    );
    assert!(
        bounded_row < unbounded_row,
        "the largest single row a transaction can commit must be set by the \
         per-transaction bound once it is in force, not by the block ceiling"
    );
}
