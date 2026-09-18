//! Snapshot, fast sync and the account-state commitment.
//!
//! A snapshot is the one path by which a node acquires canonical state it did
//! not compute. Everything else it holds, it derived by executing blocks whose
//! roots it checked. So a snapshot is where a commitment over account state has
//! to reach, and until this work it did not: `verify_snapshot` compared a digest
//! over `(address, balance)` pairs against a BLOCK state root, two values
//! computed from different inputs under different rules.
//!
//! The first test reproduces that rather than asserting it. The rest establish
//! what replaces it, and — the claim that actually matters — that above the
//! activation height a fast-synced node is verified BY THE CHAIN at its first
//! imported block, not by anything in the file it restored.
//!
//! The last two sections are about what a snapshot still cannot do. It carries
//! no undo history, because the journal is node-local and never transmitted; and
//! below the activation gate it cannot be verified at all, by the chain or by
//! anything else, because the authoritative commitment does not cover account
//! rows.

mod common;

use std::sync::Arc;

use sumchain_crypto::{sign, KeyPair};
use sumchain_genesis::ChainParams;
use sumchain_primitives::{
    Address, Block, BlockHeader, Hash, SignedTransaction, TransactionV2, TxPayload,
};
use sumchain_state::account_root::{account_state_digest, account_state_digest_of};
use sumchain_state::executor::BlockExecutor;
use sumchain_state::snapshot::{
    can_serve_history_at, imported_at, missing_for_fast_sync, sync_capability, usable_reorg_depth,
    SnapshotAccount, SnapshotManager, REQUIRED_FAST_SYNC_FAMILIES, SNAPSHOT_CARRIES,
};
use sumchain_state::state::StateManager;
use sumchain_storage::candidate::LEGACY_ROOT_COMPATIBILITY_HEIGHT;
use sumchain_storage::pruner::UNDO_RETENTION_FLOOR;
use sumchain_storage::schema::AccountState;
use sumchain_storage::{Database, StateStore};

const CHAIN_ID: u64 = 1;
const PROPOSER: [u8; 32] = [0x5A; 32];

/// The activation height these tests use.
///
/// Above `LEGACY_ROOT_COMPATIBILITY_HEIGHT` for the same reason
/// `account_state_root.rs` is: at or below it `accept_imported` ADOPTS a
/// mismatching root, so a tampered fast sync would be absorbed instead of
/// refused and the central claim of this file would be untestable.
const BOUNDARY: u64 = LEGACY_ROOT_COMPATIBILITY_HEIGHT + 1;

// ─────────────────────────────────────────────────────────────────────────────
// Fixtures
// ─────────────────────────────────────────────────────────────────────────────

struct Node {
    _dir: tempfile::TempDir,
    db: Arc<Database>,
    state: Arc<StateManager>,
    exec: BlockExecutor,
    params: ChainParams,
}

fn node(params: ChainParams) -> Node {
    let dir = tempfile::TempDir::new().unwrap();
    let db = Arc::new(Database::open_default(dir.path()).unwrap());
    let state = Arc::new(StateManager::new(db.clone(), CHAIN_ID));
    let exec = BlockExecutor::new(state.clone(), db.clone(), params.clone());
    Node {
        _dir: dir,
        db,
        state,
        exec,
        params,
    }
}

/// A node whose root folds account state from `BOUNDARY` onward.
fn committed_node() -> Node {
    let mut params = ChainParams::with_v2_enabled();
    params.account_root_enabled_from_height = Some(BOUNDARY);
    // The pinned journal boundary the account gate requires. Not exercised here
    // — this file's subject is snapshots — but a `ChainParams` that would be
    // refused at startup has no business being the fixture for anything.
    params.application_journal_enabled_from_height = Some(0);
    node(params)
}

/// A node on today's production configuration: the commitment dormant.
fn dormant_node() -> Node {
    node(ChainParams::with_v2_enabled())
}

impl Node {
    fn seed(&self, who: &Address, balance: u128, nonce: u64) {
        StateStore::new(&self.db)
            .put_account(who, &AccountState { balance, nonce })
            .unwrap();
    }

    fn snapshots(&self) -> SnapshotManager {
        SnapshotManager::new(self.db.clone(), CHAIN_ID, self.params.clone())
    }

    /// Produce and publish a block the way a proposer does.
    fn publish(&self, height: u64, txs: Vec<SignedTransaction>) -> Block {
        let mut block = block_at(height, txs);
        let exec = self
            .exec
            .execute_block(&block, self.state.state_root(), &[])
            .expect("execute_block");
        block.header.state_root = exec.computed_root();
        let (executed, _sd, _cd) = exec.into_parts();
        let accepted = executed.accept_produced(&block).expect("accept_produced");
        let accumulator = accepted.accumulator();
        accepted.publish().expect("publish");
        self.state.set_state_root(accumulator);
        block
    }

    /// Import a block another node produced, through the seam that owns both
    /// sides of the root comparison.
    fn import(&self, block: &Block) -> std::result::Result<Hash, String> {
        let exec = self
            .exec
            .execute_block(block, self.state.state_root(), &[])
            .expect("execute_block");
        let computed = exec.computed_root();
        let (executed, _sd, _cd) = exec.into_parts();
        match executed.accept_imported(block) {
            Ok(accepted) => {
                let accumulator = accepted.accumulator();
                accepted.publish().expect("publish");
                self.state.set_state_root(accumulator);
                Ok(computed)
            }
            Err(e) => Err(e.to_string()),
        }
    }
}

fn block_at(height: u64, txs: Vec<SignedTransaction>) -> Block {
    let header = BlockHeader::new(Hash::ZERO, height, 1_000, Hash::ZERO, Hash::ZERO, PROPOSER);
    Block::new(header, txs)
}

fn key(n: u8) -> KeyPair {
    KeyPair::from_bytes([n; 32])
}

fn addr(n: u8) -> Address {
    Address::new([n; 20])
}

fn transfer(
    from: &KeyPair,
    to: &Address,
    amount: u128,
    fee: u128,
    nonce: u64,
) -> SignedTransaction {
    let tx = TransactionV2 {
        chain_id: CHAIN_ID,
        from: from.address(),
        fee,
        nonce,
        payload: TxPayload::Transfer { to: *to, amount },
    };
    let sig = sign(tx.signing_hash().as_bytes(), from.private_key());
    SignedTransaction::new_v2(tx, *sig.as_bytes(), *from.public_key().as_bytes())
}

/// A populated chain with a published block, and its snapshot.
fn chain_with_snapshot(n: &Node, height: u64) -> sumchain_state::snapshot::Snapshot {
    let alice = key(1);
    n.seed(&alice.address(), 10_000_000, 0);
    n.seed(&addr(200), 7, 3);
    n.publish(height, vec![transfer(&alice, &addr(3), 1_000, 500, 0)]);
    n.snapshots().create_snapshot().expect("create snapshot")
}

// ─────────────────────────────────────────────────────────────────────────────
// 1. The finding
// ─────────────────────────────────────────────────────────────────────────────

/// The verification this file replaces could not have succeeded on any real
/// snapshot.
///
/// Reproduced, not argued. The old `verify_snapshot` recomputed
/// `blake3(address ‖ balance)` over the sorted rows — no domain separator, no
/// nonce, no count — and compared it to `header.state_root`, which
/// `compute_block_state_root` builds from the block height, parent hash,
/// timestamp, transaction root, every receipt's outcome and fee, the gated
/// subsystem digests and the previous root. Nothing in the account rows
/// determines it, and below the account gate the account rows do not enter it at
/// all.
///
/// So the comparison was between two unrelated values. It returned "not
/// verified" for a perfect snapshot, which means every caller either ignored the
/// result or rejected everything.
#[test]
fn the_old_verification_could_never_have_succeeded() {
    let n = dormant_node();
    let snapshot = chain_with_snapshot(&n, 10);
    assert!(
        snapshot.accounts.len() >= 3,
        "the fixture must hold real rows"
    );

    // The old formula, transcribed here rather than called, because the point is
    // what it computed and the code no longer computes it.
    let mut sorted: Vec<_> = snapshot.accounts.iter().collect();
    sorted.sort_by_key(|a| a.address);
    let mut data = Vec::new();
    for account in sorted {
        data.extend_from_slice(&account.address);
        data.extend_from_slice(&account.balance.to_be_bytes());
    }
    let old_digest = Hash::hash(&data);

    assert_ne!(
        old_digest, snapshot.header.state_root,
        "THE FINDING: the old check compared an account digest against a block \
         state root. They are computed from different inputs under different \
         rules, so the check reported failure for a snapshot that is correct."
    );

    // And the value that replaces it does succeed, over the same rows.
    n.snapshots()
        .verify_snapshot(&snapshot)
        .expect("the commitment the snapshot now carries must verify");
}

// ─────────────────────────────────────────────────────────────────────────────
// 2. The snapshot carries what the chain computes
// ─────────────────────────────────────────────────────────────────────────────

/// The digest in the header is the digest a validator recomputes — the same
/// function, not a second transcription of the same idea.
#[test]
fn the_snapshot_carries_the_commitment_the_chain_computes() {
    let n = committed_node();
    let snapshot = chain_with_snapshot(&n, BOUNDARY);

    assert_eq!(
        snapshot.header.account_digest,
        account_state_digest(&n.db).unwrap(),
        "the header's digest must be the committed scan, not a snapshot-local \
         recomputation of something like it"
    );
    assert_eq!(
        snapshot.header.account_root_activation,
        Some(BOUNDARY),
        "the producer's activation height travels with the file, so a consumer \
         can say whether the digest is bound to consensus"
    );
    assert_eq!(
        snapshot.header.account_count as usize,
        snapshot.accounts.len()
    );
}

/// A row changed in transit fails verification, and the refusal names the
/// digest rather than saying only "invalid".
#[test]
fn a_row_changed_in_transit_fails_verification() {
    let n = committed_node();
    let mut snapshot = chain_with_snapshot(&n, BOUNDARY);
    let honest = snapshot.header.account_digest;

    // One unit, on one account.
    snapshot.accounts[0].balance += 1;
    let err = n
        .snapshots()
        .verify_snapshot(&snapshot)
        .expect_err("a changed balance must fail verification")
        .to_string();
    assert!(
        err.contains(&honest.to_string()),
        "the refusal must name the claimed commitment: {err}"
    );

    // And a nonce alone, which a balance-only digest would have missed — the
    // nonce is replay protection, so two nodes disagreeing about it disagree
    // about which transactions an account has already spent.
    let mut snapshot = chain_with_snapshot(&n, BOUNDARY);
    snapshot.accounts[0].nonce += 1;
    n.snapshots()
        .verify_snapshot(&snapshot)
        .expect_err("a changed nonce must fail verification");
}

/// A duplicated address is refused by NAME, because whichever row is written
/// last would silently win.
#[test]
fn a_duplicated_address_is_refused_by_name() {
    let n = committed_node();
    let mut snapshot = chain_with_snapshot(&n, BOUNDARY);
    let victim = snapshot.accounts[0].clone();
    snapshot.accounts.push(SnapshotAccount {
        address: victim.address,
        balance: victim.balance + 1_000_000,
        nonce: victim.nonce,
    });
    snapshot.header.account_count += 1;

    let err = n
        .snapshots()
        .verify_snapshot(&snapshot)
        .expect_err("a duplicate address must be refused")
        .to_string();
    assert!(
        err.contains("twice"),
        "the refusal must name the duplication rather than report a digest \
         mismatch, which is a different fault with a different cause: {err}"
    );
}

/// A reordered file still verifies. The commitment is a function of the account
/// SET; the file is a transport.
///
/// Worth pinning because the fold itself is order-dependent and rejects an
/// out-of-order scan — a verifier that passed the file's order straight through
/// would refuse a correct snapshot that a peer happened to serialize
/// differently, and operators would learn to distrust the check.
#[test]
fn a_reordered_snapshot_still_verifies() {
    let n = committed_node();
    let mut snapshot = chain_with_snapshot(&n, BOUNDARY);
    snapshot.accounts.reverse();
    n.snapshots()
        .verify_snapshot(&snapshot)
        .expect("order is transport; the set is the commitment");
}

// ─────────────────────────────────────────────────────────────────────────────
// 3. Restore is checked against the database, not the file
// ─────────────────────────────────────────────────────────────────────────────

/// A restore reproduces the commitment from COMMITTED state, and reports where
/// the chain will check it.
#[test]
fn a_restore_reproduces_the_commitment_from_committed_state() {
    let source = committed_node();
    let snapshot = chain_with_snapshot(&source, BOUNDARY);

    let target = committed_node();
    let result = target
        .snapshots()
        .import_account_family(&snapshot)
        .expect("a sound snapshot must restore");

    assert_eq!(result.account_digest, snapshot.header.account_digest);
    assert_eq!(
        account_state_digest(&target.db).unwrap(),
        account_state_digest(&source.db).unwrap(),
        "the restored database must hold the source's account set exactly"
    );
    assert_eq!(
        result.consensus_verified_from,
        Some(BOUNDARY + 1),
        "restored at the activation height, this node is checked by the chain at \
         its very next block"
    );
    assert_eq!(result.journal_history_begins_at, BOUNDARY + 1);
}

/// Restoring into a directory that already holds account rows is REFUSED.
///
/// The case a file-only check cannot see: every row in the snapshot is written
/// correctly and the file verifies perfectly, but this database also holds an
/// account the snapshot never mentions. Nothing deletes it, the commitment folds
/// it, and the node ends up on an account set no peer has — the silent
/// divergence with an extra step. Only a scan of committed state after the write
/// catches it, which is why the restore does one.
#[test]
fn a_restore_into_a_dirty_directory_is_refused() {
    let source = committed_node();
    let snapshot = chain_with_snapshot(&source, BOUNDARY);

    let target = committed_node();
    target.seed(&addr(250), 999_999, 0); // an account the snapshot does not mention

    let err = target
        .snapshots()
        .import_account_family(&snapshot)
        .expect_err("a restore that does not reproduce the commitment must fail")
        .to_string();
    assert!(
        err.contains("did not reproduce the commitment") && err.contains("must not be used"),
        "the refusal must say what is wrong and what to do: {err}"
    );
}

/// A snapshot that fails verification writes nothing.
#[test]
fn a_failed_verification_writes_nothing() {
    let source = committed_node();
    let mut snapshot = chain_with_snapshot(&source, BOUNDARY);
    snapshot.accounts[0].balance += 1;

    let target = committed_node();
    let empty = account_state_digest(&target.db).unwrap();
    target
        .snapshots()
        .import_account_family(&snapshot)
        .expect_err("a snapshot whose rows do not fold to its digest must be refused");
    assert_eq!(
        account_state_digest(&target.db).unwrap(),
        empty,
        "the refusal precedes every write, so the target is untouched"
    );
    assert_eq!(
        imported_at(&target.db).unwrap(),
        None,
        "including the floor: this refusal is the one that happens before any \
         batch, so unlike the commitment check it leaves nothing at all"
    );
}

/// A restore that is REFUSED after writing still leaves its history floor.
///
/// This inverts what the import used to do, and the inversion is the point.
///
/// The floor used to be recorded after the commitment check, on the rule that a
/// database which failed the check should not be marked as imported. That rule
/// optimises the wrong direction. The floor is a RESTRICTION: it narrows the
/// heights this node will answer about and caps how deep a reorg it will
/// attempt. Recording it on a database that turned out unusable costs
/// availability on a directory the operator has already been told to discard.
/// NOT recording it, on a database that holds restored rows, costs correctness
/// — the node reads as one that executed every block it holds, offers its full
/// reorg horizon, and answers historical questions about heights whose state it
/// has never had.
///
/// So the floor goes in with the first rows, and a failed import is a database
/// carrying both the rows it could not verify and the floor that describes
/// them. Which is also why the error says the directory must not be used.
#[test]
fn a_failed_import_leaves_the_floor_that_describes_what_it_wrote() {
    let source = committed_node();
    let snapshot = chain_with_snapshot(&source, BOUNDARY);

    let target = committed_node();
    target.seed(&addr(250), 999_999, 0); // an account the snapshot does not mention

    assert_eq!(
        imported_at(&target.db).unwrap(),
        None,
        "precondition: nothing has restricted this node yet"
    );

    let err = target
        .snapshots()
        .import_account_family(&snapshot)
        .expect_err("a restore that does not reproduce the commitment must fail")
        .to_string();
    assert!(
        err.contains("did not reproduce the commitment") && err.contains("must not be used"),
        "the refusal must say what is wrong and what to do: {err}"
    );

    // The rows are there — the doc says so and the operator is told so.
    assert!(
        StateStore::new(&target.db)
            .get_account_opt(&Address::new(snapshot.accounts[0].address))
            .unwrap()
            .is_some(),
        "the failure leaves the rows written; that is stated, not hidden"
    );

    // And so is the floor that describes them. Under the old ordering this was
    // `None`, and a restart would have found restored state claiming a full
    // reorg horizon over blocks it holds no undo records for.
    assert_eq!(
        imported_at(&target.db).unwrap(),
        Some(BOUNDARY),
        "a database holding restored rows must know its floor, even when the \
         import that wrote them was refused"
    );
    assert!(
        !can_serve_history_at(&target.db, BOUNDARY - 1).unwrap(),
        "and the restriction must actually bind"
    );
}

/// A snapshot with no accounts still records its floor.
///
/// The floor rides in the first batch of rows, and a snapshot with no rows
/// writes no batch. A node restored to height `h` holding no accounts is still
/// a node with no undo history below `h`, so the fact does not get to depend on
/// whether the account set happened to be empty.
#[test]
fn an_import_that_carries_no_accounts_still_records_its_floor() {
    let source = committed_node();
    let mut snapshot = chain_with_snapshot(&source, BOUNDARY);
    snapshot.accounts.clear();
    snapshot.header.account_count = 0;
    snapshot.header.account_digest =
        account_state_digest_of(Vec::<(Address, AccountState)>::new()).unwrap();

    let target = node({
        let mut p = ChainParams::with_v2_enabled();
        p.account_root_enabled_from_height = Some(BOUNDARY);
        p.application_journal_enabled_from_height = Some(0);
        p
    });

    target
        .snapshots()
        .import_account_family(&snapshot)
        .expect("an empty account set is a legitimate snapshot of an empty chain");

    assert_eq!(
        imported_at(&target.db).unwrap(),
        Some(BOUNDARY),
        "no rows is not no floor"
    );
}

/// The floor is staged INTO the first batch, not written after the last row.
///
/// The property this file can observe is the one above: a refused import still
/// carries its floor. What it cannot observe in-process is the crash window —
/// a process that dies between the rows and the floor. That window is closed by
/// ordering, and ordering is a property of the source, so the source is what
/// this reads.
///
/// It reads TWO files, because the ordering is deliberately not the caller's to
/// choose: `StateStore::import_accounts` owns the batch and stages the floor
/// into it, and `import_account_family` owns nothing but the call. A restore
/// path that held its own batch could put the floor anywhere in it.
///
/// `storage/the_restore_floor_and_the_restored_state_commit_or_fail_together`
/// proves the primitive does what staging claims; this proves the restore is
/// the caller that uses it.
#[test]
fn the_floor_is_staged_with_the_first_rows_rather_than_written_after_the_last() {
    // ── the store: the floor is staged before anything is committed ──────────
    let schema = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../storage/src/schema.rs"
    ))
    .expect("schema.rs");
    let body = {
        let start = schema
            .find("pub fn import_accounts<I>(")
            .expect("StateStore::import_accounts");
        let rest = &schema[start..];
        let open = rest.find('{').expect("body");
        let mut depth = 0i32;
        let mut end = open;
        for (i, c) in rest[open..].char_indices() {
            match c {
                '{' => depth += 1,
                '}' => {
                    depth -= 1;
                    if depth == 0 {
                        end = open + i;
                        break;
                    }
                }
                _ => {}
            }
        }
        &rest[open..=end]
    };

    let stage = body
        .find("stage_undo_history_floor")
        .expect("the import must stage the floor");
    let commit = body
        .find("batch.commit()")
        .expect("the import must commit a batch");
    assert!(
        stage < commit,
        "the floor must be staged before anything is committed"
    );
    assert_eq!(
        body.matches("batch.commit()").count(),
        1,
        "one commit site, so 'the floor precedes it' is a claim about every \
         batch and not just the first one written down"
    );
    assert!(
        !body.contains("self.db.put(") && !body.contains("db.put("),
        "every restored row goes through the batch the floor rides in; a direct \
         put would be a row written outside it"
    );

    // ── the caller: it holds no batch, and it verifies only after ────────────
    let caller = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/snapshot.rs"))
        .expect("snapshot.rs");
    let import = {
        let start = caller
            .find("pub fn import_account_family(")
            .expect("import_account_family");
        let end = caller[start..]
            .find("\n    /// Chain id and format version.")
            .expect("end of import_account_family");
        &caller[start..start + end]
    };

    assert!(
        !import.contains("db.batch()"),
        "the restore must not hold a batch of its own — the ordering inside it \
         is the store's to guarantee"
    );
    let call = import
        .find("import_accounts(")
        .expect("the restore must go through the store");
    let verify = import
        .find("account_state_digest(&self.db)")
        .expect("the restore must re-derive the commitment from committed state");
    assert!(
        call < verify,
        "the rows and their floor must be durable before the check that can \
         refuse them"
    );
    assert!(
        !import.contains("record_undo_history_floor")
            && !import.contains("stage_undo_history_floor"),
        "the floor is written by the store, once; a second write here is the \
         window this closed"
    );
}

/// A snapshot in an older format is refused by name.
///
/// v1 carried no account commitment and v2 carried no family list, so neither
/// holds a value this binary can check anything against. Saying which format
/// and what to do is strictly better than a bincode error, which names a field
/// offset and leaves the operator to guess.
#[test]
fn an_older_snapshot_format_is_refused_by_name() {
    let source = committed_node();
    for version in [1u32, 2] {
        let mut snapshot = chain_with_snapshot(&source, BOUNDARY);
        snapshot.header.version = version;

        let err = committed_node()
            .snapshots()
            .import_account_family(&snapshot)
            .expect_err("a pre-v3 snapshot format must be refused")
            .to_string();
        assert!(
            err.contains(&format!("v{version}")) && err.contains("re-export"),
            "the refusal must name the format and the remedy: {err}"
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 4. What actually verifies a fast sync
// ─────────────────────────────────────────────────────────────────────────────

/// A snapshot carries the ACCOUNT FAMILY and nothing else, so a node restored
/// from one cannot reproduce a root at all — before the account commitment is
/// even reached.
///
/// Reproduced rather than asserted, and it is the honest headline of this
/// section: the fast-sync path was not one step short of working. A restore
/// puts the account rows in place perfectly — the digest reproduces, the
/// verification passes — and the very next block is still refused, because
/// `compute_block_state_root` also folds the supply digest, and the supply
/// family (like every other state family a block writes) is not in the file.
///
/// The test names the missing families rather than counting them, so this fails
/// informatively the day the format grows one of them and stops being true.
#[test]
fn a_snapshot_carries_only_the_account_family_so_a_restore_cannot_reproduce_a_root() {
    let alice = key(1);
    let source = committed_node();
    let snapshot = chain_with_snapshot(&source, BOUNDARY);
    let next = source.publish(
        BOUNDARY + 1,
        vec![transfer(&alice, &addr(4), 2_000, 500, 1)],
    );

    let target = committed_node();
    target
        .snapshots()
        .import_account_family(&snapshot)
        .expect("the account family restores perfectly");
    assert_eq!(
        account_state_digest(&target.db).unwrap(),
        snapshot.header.account_digest,
        "every account row the snapshot described is in place"
    );

    // And the next block is refused anyway.
    let refusal = target
        .import(&next)
        .expect_err("a node holding only the account family cannot reproduce a root");
    assert!(
        refusal.contains("state root mismatch"),
        "expected a root mismatch: {refusal}"
    );

    // What is actually missing. `SUPPLY` is the one that reaches the root today
    // through `SupplyStore::v_state_digest`; the rest are here because a
    // snapshot that intends to be a sync has to carry them too.
    let missing = missing_families(&source, &target);
    assert!(
        missing.contains(&sumchain_storage::cf::SUPPLY),
        "the supply family is folded into the state root and absent from the \
         snapshot; missing: {missing:?}"
    );
    assert!(
        missing.len() > 1,
        "the gap is the whole non-account state surface, not one family: {missing:?}"
    );
}

/// Above the gate, the CHAIN verifies what a fast-synced node restored, at its
/// first imported block.
///
/// This is the answer to "a fast-synced node cannot verify what it restored",
/// and it is not a property of the snapshot format. The digest in the file is a
/// claim by whoever produced the file; nothing in the file ties it to the chain.
/// What ties it to the chain is the commitment: the next block's root folds
/// `v_account_state_digest` over the restored rows, so a node holding a
/// different account set than the proposer computes a different root and
/// `accept_imported` refuses the block.
///
/// # What this fixture supplies, and why that is not cheating
///
/// The test above establishes that a snapshot carries no non-account state, so
/// this one hands the target every family EXCEPT the account family and lets the
/// restore supply that. It is isolating one variable, and it is isolating it in
/// the direction that makes the claim harder rather than easier: with everything
/// else identical, the ONLY thing that can move the root is the account rows. A
/// complete snapshot format is what would supply the rest in production, and
/// this test is what that format would then be relied on for.
///
/// Both directions, because only the pair means anything: an honest restore
/// imports, and a restore tampered by one unit in one balance — on an account
/// the block never touches — is REFUSED rather than absorbed.
#[test]
fn above_the_gate_the_chain_verifies_a_fast_synced_node_at_its_first_block() {
    let alice = key(1);

    let source = committed_node();
    let snapshot = chain_with_snapshot(&source, BOUNDARY);

    // Both targets are built AT the snapshot height, before the source publishes
    // the block they will import. A clone taken after it would hand them state
    // from the future and prove nothing about the block.
    let honest = committed_node();
    clone_everything_but_accounts(&source, &honest);
    honest.snapshots().import_account_family(&snapshot).unwrap();
    honest.state.set_state_root(snapshot.header.state_root);

    let tampered = committed_node();
    clone_everything_but_accounts(&source, &tampered);
    tampered
        .snapshots()
        .import_account_family(&snapshot)
        .unwrap();
    tampered.state.set_state_root(snapshot.header.state_root);

    let next = source.publish(
        BOUNDARY + 1,
        vec![transfer(&alice, &addr(4), 2_000, 500, 1)],
    );

    // ── honest restore: the importer's own execution reaches the header root.
    let computed = honest
        .import(&next)
        .expect("a correctly fast-synced node must be able to import the next block");
    assert_eq!(
        computed, next.header.state_root,
        "the restored rows reproduce the proposer's root"
    );

    // ── tampered restore: one unit, on an account this block never touches.
    tampered.seed(&addr(200), 8, 3); // was 7
    let refusal = tampered
        .import(&next)
        .expect_err("a node whose restored state is wrong must be refused");
    assert!(
        refusal.contains("state root mismatch"),
        "the refusal must name the disagreement rather than absorb it: {refusal}"
    );
}

/// Below the gate it does not work, and that is the honest statement.
///
/// The same fixture, the same tamper, the same block, on the production default.
/// The block is imported without complaint, because `compute_block_state_root`
/// never reads an account row: the restored node carries a balance no other node
/// has and proceeds. A pre-activation fast sync is unverifiable by construction,
/// and `consensus_verified_from == None` says so rather than leaving the caller
/// to read "no error" as "verified".
#[test]
fn below_the_gate_a_fast_sync_cannot_be_verified_at_all() {
    let alice = key(1);

    let source = dormant_node();
    let snapshot = chain_with_snapshot(&source, BOUNDARY);

    let tampered = dormant_node();
    clone_everything_but_accounts(&source, &tampered);
    let result = tampered
        .snapshots()
        .import_account_family(&snapshot)
        .unwrap();

    let next = source.publish(
        BOUNDARY + 1,
        vec![transfer(&alice, &addr(4), 2_000, 500, 1)],
    );
    assert_eq!(
        result.consensus_verified_from, None,
        "with the gate closed the chain will never check this node's account \
         state, and the restore says so"
    );

    tampered.state.set_state_root(snapshot.header.state_root);
    tampered.seed(&addr(200), 8, 3); // was 7
    tampered.import(&next).expect(
        "THE FINDING, restated on the sync path: below the gate the commitment \
         does not cover account rows, so a fast-synced node holding a balance no \
         peer has imports the next block cleanly",
    );
}

/// Every column family the source holds and the target does not, by name.
fn missing_families(source: &Node, target: &Node) -> Vec<&'static str> {
    sumchain_storage::db::ALL_CFS
        .iter()
        .copied()
        .filter(|f| {
            let have = target.db.iter(f).expect("iterate").next().is_some();
            let want = source.db.iter(f).expect("iterate").next().is_some();
            want && !have
        })
        .collect()
}

/// Give `target` every row `source` holds except the account family.
///
/// The variable-isolating fixture for the two tests above. `cf::STATE` is split
/// rather than skipped: it holds the account rows AND other state keyed under
/// different prefixes, and copying the whole family would hand the target the
/// very rows the restore is supposed to supply.
fn clone_everything_but_accounts(source: &Node, target: &Node) {
    let mut batch = target.db.batch();
    for family in sumchain_storage::db::ALL_CFS {
        for (k, v) in source.db.iter(family).expect("iterate") {
            if *family == sumchain_storage::cf::STATE
                && k.starts_with(sumchain_storage::schema::ACCOUNT_KEY_PREFIX)
            {
                continue;
            }
            batch.put(family, &k, &v).expect("stage copy");
        }
    }
    batch.commit().expect("commit copy");
}

// ─────────────────────────────────────────────────────────────────────────────
// 5. The undo history a snapshot does not carry
// ─────────────────────────────────────────────────────────────────────────────

/// A restored node can revert nothing, and earns depth one block at a time.
///
/// The journal is node-local — never hashed into a block, never folded into a
/// root, never transmitted — so a snapshot is canonical state and no undo
/// records at all. There is no third option for obtaining the missing ones:
/// replaying them is the sync that was just avoided, and receiving them from a
/// peer is forbidden because nothing authenticates data that is not consensus
/// data. So the node accumulates its own.
///
/// The number below is what must bound the reorg walk until then. A node that
/// advertises `MAX_REORG_WALK` the instant it restores is advertising a depth at
/// which the walk reaches a block with no record and halts partway, with the
/// branch half-applied.
#[test]
fn a_restored_node_has_no_reorg_depth_until_it_has_earned_it() {
    let restored_at = 1_000_000;

    assert_eq!(
        usable_reorg_depth(restored_at, restored_at),
        0,
        "at the restore height this node can revert nothing: it published none \
         of the blocks below it and holds no record for any of them"
    );
    assert_eq!(usable_reorg_depth(restored_at, restored_at + 1), 1);
    assert_eq!(usable_reorg_depth(restored_at, restored_at + 500), 500);

    // One block short of the horizon, then at it, then past it: the cap is the
    // configured horizon and never more.
    assert_eq!(
        usable_reorg_depth(restored_at, restored_at + UNDO_RETENTION_FLOOR - 1),
        UNDO_RETENTION_FLOOR - 1
    );
    assert_eq!(
        usable_reorg_depth(restored_at, restored_at + UNDO_RETENTION_FLOOR),
        UNDO_RETENTION_FLOOR,
        "a full horizon of its own blocks is when a restored node reaches parity"
    );
    assert_eq!(
        usable_reorg_depth(restored_at, restored_at + UNDO_RETENTION_FLOOR * 10),
        UNDO_RETENTION_FLOOR,
        "and never exceeds it — the pruner retains exactly this much"
    );

    // A head below the restore height is not a negative depth. It is a node that
    // has not caught up, and it can still revert nothing.
    assert_eq!(usable_reorg_depth(restored_at, restored_at - 10), 0);

    // The restore reports where its own records begin, which is the input above.
    let source = committed_node();
    let snapshot = chain_with_snapshot(&source, BOUNDARY);
    let target = committed_node();
    let result = target.snapshots().import_account_family(&snapshot).unwrap();
    assert_eq!(
        result.journal_history_begins_at,
        result.height + 1,
        "the first block this node can ever hold a record for is the first one \
         it publishes or imports"
    );
    assert_eq!(usable_reorg_depth(result.height, result.height), 0);
}

// ─────────────────────────────────────────────────────────────────────────────
// 6. Fast sync is DISABLED, and the node knows what it is
// ─────────────────────────────────────────────────────────────────────────────

/// `restore_snapshot` — the fast-sync entry point — refuses, and names every
/// family a sync needs and this format does not carry.
///
/// Section 4 established that a restored node cannot reproduce a root. This is
/// the consequence: the entry point that would produce such a node does not
/// exist as a working path. The refusal is structural — the file declares what
/// it carries, the constant declares what a sync requires, and the comparison
/// is what refuses — so extending the format lifts it without anyone
/// remembering to.
#[test]
fn fast_sync_is_disabled_and_the_refusal_names_what_is_missing() {
    let source = committed_node();
    let snapshot = chain_with_snapshot(&source, BOUNDARY);

    let target = committed_node();
    let err = target
        .snapshots()
        .restore_snapshot(&snapshot)
        .expect_err("fast sync must be refused while the format is incomplete")
        .to_string();

    assert!(
        err.contains("fast sync is DISABLED"),
        "the refusal must say so in those words: {err}"
    );
    // The family that reaches the root TODAY, with no gate, is the one that
    // makes this a correctness refusal rather than a completeness preference.
    assert!(
        err.contains("supply"),
        "the refusal must name the supply family: {err}"
    );
    for family in ["contracts", "tokens", "nft", "compute_pool", "beacon"] {
        assert!(
            err.contains(family),
            "the refusal must name every missing family, and omits {family}: {err}"
        );
    }

    // Nothing was written: the refusal precedes the import.
    assert_eq!(
        account_state_digest(&target.db).unwrap(),
        account_state_digest(
            &Database::open_default(tempfile::TempDir::new().unwrap().path()).unwrap()
        )
        .unwrap(),
        "a refused sync must leave the target untouched"
    );
}

/// The refusal is derived, not written down twice.
///
/// `missing_for_fast_sync` over what this format carries must be non-empty, and
/// must become empty exactly when the carried set covers the required one. The
/// test that the disable lifts itself.
#[test]
fn the_disable_is_derived_from_the_two_family_lists() {
    let carried: Vec<String> = SNAPSHOT_CARRIES.iter().map(|s| s.to_string()).collect();
    let missing = missing_for_fast_sync(&carried);
    assert!(
        !missing.is_empty(),
        "this format does not carry a full sync; if this is ever empty, the \
         refusal above has lifted and the format must have been extended"
    );
    assert!(
        carried.contains(&"state:accounts".to_string()),
        "the one family it does carry"
    );

    // Hand it the full required set and the refusal disappears — so the gate is
    // a comparison and not a constant `false`.
    let complete: Vec<String> = REQUIRED_FAST_SYNC_FAMILIES
        .iter()
        .map(|s| s.to_string())
        .collect();
    assert!(
        missing_for_fast_sync(&complete).is_empty(),
        "a snapshot carrying everything a sync requires must not be refused"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// 7. What an imported node may claim about itself
// ─────────────────────────────────────────────────────────────────────────────

/// The import height is PERSISTED, so a restart does not forget it.
///
/// The failure this prevents is quiet and total: a node imports at H, learns it
/// can unwind nothing, restarts, and — with the fact held only in the
/// `RestoreResult` the previous process returned — goes back to advertising the
/// full reorg horizon over blocks it has no records for.
#[test]
fn the_import_height_survives_a_restart() {
    let source = committed_node();
    let snapshot = chain_with_snapshot(&source, BOUNDARY);

    let dir = tempfile::TempDir::new().unwrap();
    let path = dir.path().to_path_buf();
    {
        let db = Arc::new(Database::open_default(&path).unwrap());
        let mut params = ChainParams::with_v2_enabled();
        params.account_root_enabled_from_height = Some(BOUNDARY);
        params.application_journal_enabled_from_height = Some(0);
        SnapshotManager::new(db, CHAIN_ID, params)
            .import_account_family(&snapshot)
            .expect("import");
    }

    // Every handle dropped, RocksDB reopened from disk. This is the restart.
    let db = Database::open_default(&path).unwrap();
    assert_eq!(
        imported_at(&db).unwrap(),
        Some(BOUNDARY),
        "the import height must be read back from the database, not from the \
         process that performed it"
    );

    let cap = sync_capability(&db, BOUNDARY).unwrap();
    assert_eq!(cap.imported_at, Some(BOUNDARY));
    assert_eq!(cap.state_history_floor, Some(BOUNDARY));
    assert_eq!(cap.journal_history_begins_at, Some(BOUNDARY + 1));
    assert_eq!(
        cap.usable_reorg_depth, 0,
        "at the import height this node may advertise nothing"
    );
    assert!(
        !cap.fast_sync_available,
        "and it must not claim a capability this format does not have"
    );
    assert!(cap.missing_families.contains(&"supply"));

    // It earns depth one block at a time, and the value comes from the database.
    assert_eq!(
        sync_capability(&db, BOUNDARY + 700)
            .unwrap()
            .usable_reorg_depth,
        700
    );
    assert_eq!(
        sync_capability(&db, BOUNDARY + UNDO_RETENTION_FLOOR * 3)
            .unwrap()
            .usable_reorg_depth,
        UNDO_RETENTION_FLOOR
    );
}

/// A node that executed its whole chain claims no restriction.
///
/// The permissive answer has to be reachable, or the clamp would quietly
/// hobble every normally-synced node on the network.
#[test]
fn a_node_that_never_imported_is_unrestricted() {
    let n = committed_node();
    let cap = sync_capability(&n.db, 1_000).unwrap();
    assert_eq!(cap.imported_at, None);
    assert_eq!(cap.state_history_floor, None);
    assert_eq!(cap.journal_history_begins_at, None);
    assert_eq!(cap.usable_reorg_depth, UNDO_RETENTION_FLOOR);
    assert!(
        can_serve_history_at(&n.db, 0).unwrap(),
        "a node that executed every block can answer for every height"
    );
}

/// An imported node refuses historical state below its floor.
///
/// A walk that runs off the bottom of this node's history and returns whatever
/// it found there is worse than an error, because the caller cannot tell. The
/// predicate is a refusal, and it is one predicate so that every query path
/// applies the same rule.
#[test]
fn an_imported_node_cannot_answer_for_history_it_does_not_have() {
    let source = committed_node();
    let snapshot = chain_with_snapshot(&source, BOUNDARY);
    let target = committed_node();
    target
        .snapshots()
        .import_account_family(&snapshot)
        .expect("import");

    assert!(!can_serve_history_at(&target.db, 0).unwrap());
    assert!(!can_serve_history_at(&target.db, BOUNDARY - 1).unwrap());
    assert!(
        can_serve_history_at(&target.db, BOUNDARY).unwrap(),
        "the import height itself IS on this node — it is the state that arrived"
    );
    assert!(can_serve_history_at(&target.db, BOUNDARY + 1).unwrap());
}

/// An unreadable import record refuses everything rather than defaulting to
/// "never imported".
///
/// Absent means unrestricted. Guessing absent from a corrupt value would let a
/// node that WAS imported serve history it does not have, which is the exact
/// failure the record exists to prevent — so a value that cannot be read is an
/// error, not an absence.
#[test]
fn a_corrupt_import_record_is_an_error_not_an_absence() {
    let n = committed_node();
    n.db.put(
        sumchain_storage::cf::META,
        sumchain_state::snapshot::SNAPSHOT_IMPORT_META_KEY,
        &[0u8; 3],
    )
    .unwrap();

    let err = imported_at(&n.db)
        .expect_err("a 3-byte height must not be read as absent")
        .to_string();
    assert!(
        err.contains("must not serve any"),
        "the refusal must say what follows from it: {err}"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// 8. The snapshot policy, as one proposition
// ─────────────────────────────────────────────────────────────────────────────

/// The snapshot half of the commitment's coherent set: what a snapshot may do,
/// what it may not, and the fact that every branch is decided by the commitment
/// rather than by a flag somebody set.
///
/// The other four paths by which account state reaches or changes on a node are
/// proven beside this one, and the table in
/// `account_state_root.rs`, section 10, names all five. This test is the
/// snapshot row. The tests above each establish ONE of the five clauses below
/// in isolation, with the fixtures and the reproduction that make it convincing;
/// what they do not establish is that the clauses are consistent with each other
/// — that the path admitted by clause 2 is the same path restricted by clause 4
/// and checked by clause 5. A policy is the conjunction, so the conjunction is
/// what is asserted here, on one source, one file and one target.
///
/// 1. A fast sync is REFUSED, and the refusal names every family it is short of.
/// 2. An account-family import is ADMITTED, and what admits it is the
///    commitment: the digest is recomputed from the target's COMMITTED state
///    after the write, not read back out of the file that claimed it.
/// 3. A file whose rows were altered in transit is refused at verification, and
///    the target is untouched.
/// 4. An admitted import does not let the node claim history it lacks: it
///    advertises a floor, advertises zero usable reorg depth, refuses to serve
///    below the floor, and still reports that it could not seed anyone else.
/// 5. Above the gate the CHAIN checks the import at the node's first block —
///    which is the only thing that ever ties a restored account set to the
///    chain, because the digest in the file is a claim by whoever wrote it.
#[test]
fn the_snapshot_policy_admits_only_what_the_commitment_can_check() {
    let alice = key(1);
    let source = committed_node();
    let snapshot = chain_with_snapshot(&source, BOUNDARY);

    // ── 1. Fast sync: refused, by name.
    let refused = committed_node();
    let err = refused
        .snapshots()
        .restore_snapshot(&snapshot)
        .expect_err("a fast sync must be refused while the format is incomplete")
        .to_string();
    assert!(
        err.contains("fast sync is DISABLED") && err.contains("supply"),
        "{err}"
    );
    assert_eq!(
        imported_at(&refused.db).unwrap(),
        None,
        "a refused sync must not leave the target believing it was seeded"
    );

    // ── 3. A tampered file: refused before the account family is admitted, so
    //    the order of these two clauses is itself part of the policy.
    let tampered_file = {
        let mut s = snapshot.clone();
        let row: &mut SnapshotAccount = s.accounts.first_mut().expect("a non-empty snapshot");
        row.balance += 1;
        s
    };
    let target = committed_node();
    let err = target
        .snapshots()
        .import_account_family(&tampered_file)
        .expect_err("a row altered in transit must not be admitted")
        .to_string();
    assert!(
        err.contains("account commitment") && err.contains("fold to"),
        "the refusal must be the commitment failing to reproduce, and must show \
         both values rather than saying 'invalid': {err}"
    );
    assert_eq!(
        account_state_digest(&target.db).unwrap(),
        account_state_digest(
            &Database::open_default(tempfile::TempDir::new().unwrap().path()).unwrap()
        )
        .unwrap(),
        "and a refused import writes nothing"
    );
    assert_eq!(imported_at(&target.db).unwrap(), None);

    // ── 2. The honest file: admitted, and admitted BY THE COMMITMENT.
    let admitted = committed_node();
    clone_everything_but_accounts(&source, &admitted);
    let result = admitted
        .snapshots()
        .import_account_family(&snapshot)
        .expect("an honest account family must be admitted");
    assert_eq!(
        result.account_digest,
        account_state_digest(&admitted.db).unwrap(),
        "the value the import reports is the one recomputed from committed \
         state, so a write that dropped a row fails here rather than at the \
         next block"
    );
    assert_eq!(result.account_digest, snapshot.header.account_digest);
    assert_eq!(result.height, snapshot.header.height);

    // ── 4. And it restricts what the node may claim. Three claims, one
    //    recorded import height, so they cannot drift apart.
    let cap = sync_capability(&admitted.db, snapshot.header.height).unwrap();
    assert_eq!(cap.imported_at, Some(snapshot.header.height));
    assert_eq!(
        cap.state_history_floor,
        Some(snapshot.header.height),
        "it may not SERVE state below the height it was seeded at"
    );
    assert_eq!(
        cap.usable_reorg_depth, 0,
        "it may not ADVERTISE a reorg depth it holds no undo records for"
    );
    assert_eq!(
        cap.journal_history_begins_at,
        Some(snapshot.header.height + 1)
    );
    assert!(
        !cap.fast_sync_available && !cap.missing_families.is_empty(),
        "and it may not claim it could seed anyone else"
    );
    assert!(!can_serve_history_at(&admitted.db, snapshot.header.height - 1).unwrap());
    assert!(can_serve_history_at(&admitted.db, snapshot.header.height).unwrap());
    assert_eq!(
        usable_reorg_depth(snapshot.header.height, snapshot.header.height + 10),
        10,
        "the depth is earned one block at a time, and only after the import"
    );
    assert_eq!(
        usable_reorg_depth(
            snapshot.header.height,
            snapshot.header.height + UNDO_RETENTION_FLOOR * 2
        ),
        UNDO_RETENTION_FLOOR,
        "capped at the retention floor once it has been earned back"
    );

    // ── 5. The chain checks it at the first block. This is the clause that
    //    makes clauses 2 and 3 worth anything: they check the file against
    //    itself, and only this checks the node against the chain.
    assert_eq!(
        result.consensus_verified_from,
        Some(snapshot.header.height + 1),
        "restored at the gate, this node is checked by its very next block"
    );
    admitted.state.set_state_root(snapshot.header.state_root);
    let next = source.publish(
        BOUNDARY + 1,
        vec![transfer(&alice, &addr(4), 2_000, 500, 1)],
    );
    let computed = admitted
        .import(&next)
        .expect("a correctly imported account family reproduces the chain's root");
    assert_eq!(computed, next.header.state_root);
    assert_eq!(
        account_state_digest(&admitted.db).unwrap(),
        account_state_digest(&source.db).unwrap(),
        "and the two nodes now hold one account set, reached by a snapshot on \
         one side and by execution on the other"
    );
}

/// A restored node cannot ACCEPT a branch it has no records to unwind — and the
/// number that stops it is the same number this module advertises.
///
/// Advertising and serving are covered above. Accepting is the third, and it is
/// the one this module does not implement: the clamp on the reorg WALK lives in
/// `crates/consensus/src/reorg.rs`, which reads
/// `sumchain_storage::journal::JournalActivation::advertisable_reorg_depth`
/// rather than anything here.
///
/// So there are two independently-derived numbers for one fact, and the failure
/// worth testing for is that they disagree — a node that advertises zero and
/// walks four thousand, or the reverse. They are derived from different
/// evidence, which is what makes the agreement meaningful rather than circular:
///
/// * this module's, from the RECORDED import height — a fact about what arrived;
/// * the planner's, from the journals the database actually HOLDS — a fact about
///   what can be undone. A restored node holds none, so its observed boundary is
///   unestablished and its usable depth is zero without anyone having to tell it.
///
/// Both then grow one block per block the node publishes itself, because that is
/// the only way undo history is ever acquired: journals are node-local, never
/// transmitted, and a pre-image cannot be derived from a post-state.
#[test]
fn a_restored_node_cannot_accept_a_branch_it_cannot_unwind() {
    use sumchain_storage::journal::{ActivationSource, JournalActivation};

    let alice = key(1);
    let engine_max = UNDO_RETENTION_FLOOR;

    let source = committed_node();
    let snapshot = chain_with_snapshot(&source, BOUNDARY);

    // No `clone_everything_but_accounts` here, deliberately. That fixture exists
    // to isolate the account rows for the root-reproduction tests, and it copies
    // the source's APPLICATION_JOURNAL family along with everything else — which
    // is not what an import produces. Journals are node-local and are not
    // transmitted; a target holding the source's would be a node claiming undo
    // history for blocks it never executed, which is the precise thing this test
    // is about. (A fast-sync format that DID copy journals is what
    // `journal::record_undo_history_floor` exists for, and it is the journal
    // workstream's to stamp.)
    let target = committed_node();
    target
        .snapshots()
        .import_account_family(&snapshot)
        .expect("import");
    target.state.set_state_root(snapshot.header.state_root);

    // ── At the restore height: zero, from both sides.
    let planner_depth = |head: u64| {
        JournalActivation::resolve(&target.db, ActivationSource::ObservedFromChain)
            .expect("resolve the journal boundary")
            .advertisable_reorg_depth(head, engine_max)
    };
    assert_eq!(
        sync_capability(&target.db, BOUNDARY)
            .unwrap()
            .usable_reorg_depth,
        0,
        "this module says the node can unwind nothing"
    );
    assert_eq!(
        planner_depth(BOUNDARY),
        0,
        "and the planner, reading the journals this database holds rather than \
         the import record, reaches the same zero"
    );

    // ── It earns depth by publishing, one block at a time, and the two numbers
    //    stay equal the whole way up.
    for (i, height) in (BOUNDARY + 1..=BOUNDARY + 4).enumerate() {
        target.publish(
            height,
            vec![transfer(
                &alice,
                &addr(0x70 + i as u8),
                1_000,
                500,
                1 + i as u64,
            )],
        );
        let advertised = sync_capability(&target.db, height)
            .unwrap()
            .usable_reorg_depth;
        assert_eq!(
            advertised,
            (i as u64) + 1,
            "height {height}: one block published is one block of undo history"
        );
        assert_eq!(
            planner_depth(height),
            advertised,
            "height {height}: the depth this node ADVERTISES and the depth the \
             reorg planner will WALK must be one number. Two numbers here is a \
             node that either refuses reorgs it could perform or attempts ones \
             it cannot finish, leaving a branch half-applied."
        );
    }

    // ── And neither ever reaches below the restore point, which is the hard
    //    floor: no record this database holds can revert a block it never had.
    assert!(
        sync_capability(&target.db, BOUNDARY + 4)
            .unwrap()
            .usable_reorg_depth
            < engine_max,
        "a node four blocks past a restore must not claim the full horizon"
    );
}
