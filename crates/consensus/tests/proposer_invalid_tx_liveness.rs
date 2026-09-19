//! One transaction that cannot execute must not stop a validator producing
//! blocks — and must not take honest traffic with it when it is removed.
//!
//! # The halt
//!
//! `execute_block`'s transaction loop ends in `Err(e) => return Err(e)`. Most
//! ways a transaction can fail are receipts — a bad nonce, a bad signature, an
//! empty balance, a subsystem's own semantic refusal — and a block carrying one
//! is still a block. But a handful of paths `?` a `StateError` straight out of
//! the dispatch arm, and each one of those makes the WHOLE BLOCK unexecutable.
//!
//! `PoAEngine::create_block` then returns that error, `run_block_producer` logs
//! "Failed to create block", and `mempool.remove_batch` — which is on the
//! success path only — is never reached. `Mempool::select_for_block` is
//! non-destructive and ordered by FEE, so the transaction is still there on the
//! next tick, sorted to the front, and is selected first again. Not a lost
//! slot: a validator that never produces another block. It costs one `min_fee`
//! and anyone can pay it.
//!
//! # Why "evict whatever failed" is the wrong repair
//!
//! The transactions that reach that arm are not one population. Three kinds
//! arrive there and they want three different answers:
//!
//!   * PERMANENTLY INVALID — `PolicyAccount { ModifyMembership }` is refused by
//!     `PolicyAccountExecutor::execute` on the operation code alone, before it
//!     reads any state. No height and no state makes it succeed. Evict it.
//!   * TEMPORARILY INELIGIBLE — an NFT `Mint` naming a collection that does not
//!     exist yet is `Err(BlockValidation("Collection not found"))`, and the
//!     very next block may contain the `CreateCollection` that makes it valid.
//!     Evicting it destroys a transaction whose only fault is arriving early.
//!   * TOO BIG FOR THIS BLOCK — a transaction that crosses
//!     `MAX_BLOCK_WRITE_SET_BYTES` at index 7 crossed it because the six before
//!     it spent the budget. Alone at the head of the next block it fits.
//!
//! So the file asserts both halves of the property, and the second half is the
//! one a careless fix breaks.

#![cfg(test)]

use std::collections::HashMap;
use std::sync::Arc;

use sumchain_consensus::{ConsensusEngine, PoAEngine};
// `current_height` moved to the ConsensusQuery supertrait when the RPC server's
// handle was narrowed; reading a height still needs the trait in scope.
use sumchain_consensus::ConsensusQuery;
use sumchain_crypto::{sign, KeyPair};
use sumchain_genesis::{ChainParams, Genesis};
use sumchain_primitives::{
    Address, NftOperation, NftTxData, PolicyAccountOperation, PolicyAccountTxData,
    SignedTransaction, TransactionV2, TxPayload,
};
use sumchain_state::{Mempool, MempoolConfig, StateManager};
use sumchain_storage::{Database, ReceiptStore};
use tempfile::TempDir;

const CHAIN_ID: u64 = 1;

fn params() -> ChainParams {
    ChainParams::with_v2_enabled()
}

struct Node {
    dir: TempDir,
    db: Arc<Database>,
    mempool: Arc<Mempool>,
    consensus: Arc<PoAEngine>,
}

fn mempool_config() -> MempoolConfig {
    MempoolConfig {
        max_per_sender: 10_000,
        ..MempoolConfig::default()
    }
}

impl Node {
    fn new(genesis: &Genesis, key: [u8; 32]) -> Self {
        let dir = TempDir::new().expect("temp dir");
        let node = Self::open(dir, genesis, key);
        node.consensus.init_genesis(genesis).expect("init genesis");
        node
    }

    fn open(dir: TempDir, genesis: &Genesis, key: [u8; 32]) -> Self {
        let db = Arc::new(Database::open_default(dir.path()).expect("open database"));
        let state = Arc::new(StateManager::new(db.clone(), CHAIN_ID));
        let mempool = Arc::new(Mempool::new(mempool_config()));
        let consensus = Arc::new(
            PoAEngine::new(
                db.clone(),
                state.clone(),
                mempool.clone(),
                genesis,
                Some(KeyPair::from_bytes(key)),
            )
            .expect("engine"),
        );
        Self {
            dir,
            db,
            mempool,
            consensus,
        }
    }

    /// Close this node and open a new one over the SAME database directory,
    /// exactly as a restart does: a fresh engine, a fresh (and therefore EMPTY)
    /// mempool, and the chain picked up off disk.
    fn restart(self, genesis: &Genesis, key: [u8; 32]) -> Self {
        let Node {
            dir,
            db,
            mempool,
            consensus,
        } = self;
        drop(consensus);
        drop(mempool);
        drop(db);
        let node = Self::open(dir, genesis, key);
        node.consensus.load_chain().expect("load chain");
        node
    }

    /// One production tick, exactly as `run_block_producer` does it: select from
    /// the mempool by fee, hand the selection to `create_block`.
    async fn tick(&self) -> sumchain_consensus::Result<sumchain_primitives::Block> {
        let txs = self.mempool.select_for_block(1_000);
        self.consensus.propose_block(txs).await
    }
}

fn sign_v2(kp: &KeyPair, t: TransactionV2) -> SignedTransaction {
    let sig = sign(t.signing_hash().as_bytes(), kp.private_key());
    SignedTransaction::new_v2(t, *sig.as_bytes(), *kp.public_key().as_bytes())
}

/// PERMANENTLY INVALID. `PolicyAccountExecutor::execute` matches on the
/// operation code and returns `StateError::UnsubmittableOperation` for
/// `ModifyMembership` before touching any state: the operation is reachable
/// only as the effect of an `ExecuteProposal`, so a directly submitted one can
/// never succeed, at any height, against any state.
fn modify_membership_tx(kp: &KeyPair, nonce: u64, fee: u128) -> SignedTransaction {
    sign_v2(
        kp,
        TransactionV2 {
            chain_id: CHAIN_ID,
            from: kp.address(),
            fee,
            nonce,
            payload: TxPayload::PolicyAccount(PolicyAccountTxData {
                operation: PolicyAccountOperation::ModifyMembership,
                data: Vec::new(),
                recipient: Address::ZERO,
            }),
        },
    )
}

/// TEMPORARILY INELIGIBLE. An NFT mint against a collection id that nothing has
/// created yet. `NftExecutor` returns `Err(BlockValidation("Collection not
/// found"))` rather than a failed receipt, so it aborts the block exactly as
/// the permanently invalid transaction does — but a `CreateCollection` in a
/// later block makes this very transaction valid, so destroying it is
/// destroying honest traffic.
fn mint_absent_collection_tx(kp: &KeyPair, nonce: u64, fee: u128) -> SignedTransaction {
    #[derive(serde::Serialize)]
    struct MintData {
        to: Address,
        metadata: Vec<u8>,
        uri_type: String,
        uri_value: Option<String>,
    }
    sign_v2(
        kp,
        TransactionV2 {
            chain_id: CHAIN_ID,
            from: kp.address(),
            fee,
            nonce,
            payload: TxPayload::Nft(NftTxData {
                collection_id: [0x55u8; 32],
                token_id: 0,
                operation: NftOperation::Mint,
                data: bincode::serialize(&MintData {
                    to: kp.address(),
                    metadata: Vec::new(),
                    uri_type: "onchain".to_string(),
                    uri_value: None,
                })
                .unwrap(),
            }),
        },
    )
}

fn transfer_tx(kp: &KeyPair, to: Address, nonce: u64, fee: u128) -> SignedTransaction {
    sign_v2(
        kp,
        TransactionV2 {
            chain_id: CHAIN_ID,
            from: kp.address(),
            fee,
            nonce,
            payload: TxPayload::Transfer { to, amount: 1 },
        },
    )
}

struct Fixture {
    genesis: Genesis,
    key: [u8; 32],
    /// The attacker, who pays one high fee and nothing else.
    attacker: KeyPair,
    /// Honest traffic, from a different sender so that no nonce sequence links
    /// the two populations.
    honest: KeyPair,
    sink: Address,
}

fn fixture() -> Fixture {
    let validator = KeyPair::generate();
    let attacker = KeyPair::generate();
    let honest = KeyPair::generate();
    let genesis = Genesis::new(
        CHAIN_ID,
        0,
        vec![validator.public_key().to_base58()],
        HashMap::from([
            (validator.address().to_base58(), 100_000_000u128),
            (attacker.address().to_base58(), 1_000_000_000_000u128),
            (honest.address().to_base58(), 1_000_000_000_000u128),
        ]),
        params(),
    );
    Fixture {
        genesis,
        key: *validator.private_key().as_bytes(),
        attacker,
        honest,
        sink: Address::new([0xAB; 20]),
    }
}

fn hashes(txs: &[SignedTransaction]) -> std::collections::HashSet<sumchain_primitives::Hash> {
    txs.iter().map(|t| t.hash()).collect()
}

// ── 1. The reproduction, at the proposer ────────────────────────────────────

/// One `ModifyMembership` transaction at the head of a proposal, with eight
/// ordinary transfers behind it.
///
/// Handed to `propose_block` DIRECTLY rather than through the mempool. The
/// mempool now refuses this shape at admission (see
/// `crates/state/tests/mempool_permanent_admission.rs`), and this is the other
/// seam: `create_block` must survive a poisoned selection whatever produced it,
/// because admission is a filter on one node's own submissions and a proposal
/// is not obliged to have come through it.
///
/// Before the fix: `Err`, no block, and — through the mempool — the same
/// transaction selected first on every tick thereafter. The assertion is the
/// owner's condition: a block is produced AND it carries the later valid
/// transactions.
#[tokio::test]
async fn a_permanently_invalid_high_fee_transaction_does_not_halt_the_proposer() {
    let f = fixture();
    let node = Node::new(&f.genesis, f.key);

    let poison = modify_membership_tx(&f.attacker, 0, 9_000_000);
    let honest: Vec<SignedTransaction> = (0..8)
        .map(|n| transfer_tx(&f.honest, f.sink, n, 1_000))
        .collect();
    let mut proposal = vec![poison.clone()];
    proposal.extend(honest.iter().cloned());

    let block = node.consensus.propose_block(proposal).await.expect(
        "a validator must produce a block. An Err here is the permanent halt: \
         nothing is produced, nothing is evicted, and the next tick selects the \
         same transaction first and fails the same way, forever",
    );

    let carried = hashes(&block.transactions);
    println!(
        "LIVENESS: block {} at height {} carried {} of 8 honest transfers",
        block.hash(),
        block.height(),
        honest
            .iter()
            .filter(|t| carried.contains(&t.hash()))
            .count()
    );
    assert!(
        !carried.contains(&poison.hash()),
        "the transaction that cannot execute is not in the block"
    );
    assert!(
        honest.iter().all(|t| carried.contains(&t.hash())),
        "and it must carry the LATER VALID transactions — a block produced \
         empty every tick is a chain that advances while no transaction ever \
         confirms, which is not what the owner asked for"
    );
    assert_ne!(block.header.proposer_sig, [0u8; 64], "and it is signed");
    assert!(
        node.db
            .get(sumchain_storage::cf::BLOCKS, block.hash().as_bytes())
            .unwrap()
            .is_some(),
        "and published"
    );
}

/// The same poisoning, ten times over, with the chain expected to advance and
/// to CARRY WORK each time.
///
/// A fix that survives one proposal and not the next is not a fix: the halt is
/// a property of the repeated selection, not of any single proposal. The fee is
/// the highest in every proposal, which is where a fee-ordered selection would
/// put it.
#[tokio::test]
async fn repeated_poisoning_over_many_proposals_never_stops_the_chain() {
    let f = fixture();
    let node = Node::new(&f.genesis, f.key);

    for round in 0..10u64 {
        let tx = transfer_tx(&f.honest, f.sink, round, 1_000);
        let proposal = vec![
            modify_membership_tx(&f.attacker, round, 9_000_000),
            tx.clone(),
        ];
        let block = node
            .consensus
            .propose_block(proposal)
            .await
            .unwrap_or_else(|e| panic!("round {round} produced no block: {e}"));
        assert_eq!(
            block.height(),
            round + 1,
            "the chain advanced at round {round}"
        );
        assert!(
            block.transactions.iter().any(|t| t.hash() == tx.hash()),
            "round {round} must CARRY the honest transfer, not merely advance"
        );
    }
    println!("ROUNDS: ten consecutive blocks, each carrying its honest transfer");
}

// ── 2. The half a careless fix breaks ───────────────────────────────────────

/// A transaction that is merely EARLY is not destroyed.
///
/// The NFT mint names a collection that does not exist yet. That aborts the
/// block exactly as the permanently invalid transaction does, and a fix that
/// evicts everything which fails execution would throw it away. It must instead
/// still be in the mempool afterwards, byte for byte, and the honest traffic
/// behind it must be carried by the block that gets produced.
///
/// This one goes through the MEMPOOL, because it is a transaction the mempool
/// has no business refusing: nothing about it is wrong except when it arrived.
#[tokio::test]
async fn a_temporarily_ineligible_transaction_is_not_destroyed() {
    let f = fixture();
    let node = Node::new(&f.genesis, f.key);

    // The highest fee in the pool, so it is selected FIRST on every tick.
    let early = mint_absent_collection_tx(&f.attacker, 0, 9_000_000);
    node.mempool.add(early.clone()).expect("admitted");
    let honest: Vec<SignedTransaction> = (0..4)
        .map(|n| transfer_tx(&f.honest, f.sink, n, 1_000))
        .collect();
    for tx in &honest {
        node.mempool.add(tx.clone()).expect("admitted");
    }

    let block = node.tick().await.expect("a block is still produced");
    let carried = hashes(&block.transactions);
    println!(
        "QUARANTINE: block {} carried {} tx; early mint still pending: {}",
        block.hash(),
        block.tx_count(),
        node.mempool.contains(&early.hash())
    );
    assert!(
        honest.iter().all(|t| carried.contains(&t.hash())),
        "the honest transfers behind it are carried"
    );
    assert!(
        node.mempool.contains(&early.hash()),
        "a transaction whose only fault is that its collection does not exist \
         YET must still be in the mempool: the block after this one may create \
         it. Evicting it satisfies the liveness half of the property by \
         destroying honest traffic, which is the failure the owner named"
    );
    let held = node.mempool.get(&early.hash()).expect("still held");
    assert_eq!(held.fee(), early.fee(), "and its fee was not rewritten");
    assert_eq!(held.nonce(), early.nonce(), "nor its nonce");
    assert_eq!(held.hash(), early.hash(), "nor any other byte of it");
    assert!(
        !carried.contains(&early.hash()),
        "and it is not in the block either — quarantined for this proposal, \
         not included with a receipt it never earned"
    );
}

/// Quarantine survives being asked over and over.
///
/// The transient transaction keeps the top of the fee order for as long as it
/// is in the mempool, so every subsequent tick selects it first and refuses it
/// again. Each of those ticks must still produce a block that carries work, and
/// the transaction must still be there at the end — neither destroyed by the
/// repetition nor allowed to stop it.
#[tokio::test]
async fn a_quarantined_transaction_is_re_offered_every_tick_and_stops_nothing() {
    let f = fixture();
    let node = Node::new(&f.genesis, f.key);
    let early = mint_absent_collection_tx(&f.attacker, 0, 9_000_000);
    node.mempool.add(early.clone()).expect("admitted");

    for round in 0..6u64 {
        let tx = transfer_tx(&f.honest, f.sink, round, 1_000);
        node.mempool.add(tx.clone()).expect("admitted");
        let block = node
            .tick()
            .await
            .unwrap_or_else(|e| panic!("round {round} produced no block: {e}"));
        assert_eq!(block.height(), round + 1);
        assert!(
            block.transactions.iter().any(|t| t.hash() == tx.hash()),
            "round {round} carried its honest transfer"
        );
        assert!(
            node.mempool.contains(&early.hash()),
            "and the quarantined transaction is still held after round {round}"
        );
    }
    println!("RE-OFFERED: six ticks, six blocks, the early mint still pending");
}

// ── 3. Nonce dependencies ───────────────────────────────────────────────────

/// Dropping a transaction mid-proposal does not hand its sender's later
/// transactions `InvalidNonce` receipts.
///
/// This is the trap in splicing. A sender's nonces are contiguous, so removing
/// the transaction at nonce n and keeping n+1 and n+2 means those two fail
/// `validate_tx` — which is a RECEIPT, not an error, so the block is built and
/// signed carrying them, and `remove_batch` then deletes them from the mempool.
/// Two transactions destroyed, neither of them accused of anything, by the
/// repair whose whole purpose is not doing that.
///
/// So the sender's tail is dropped from the proposal WITH the offender, and
/// every other sender's transactions are kept.
#[tokio::test]
async fn dropping_a_transaction_does_not_destroy_its_senders_later_nonces() {
    let f = fixture();
    let node = Node::new(&f.genesis, f.key);

    // Same sender: the quarantined transaction at nonce 0, two ordinary
    // transfers behind it at nonces 1 and 2.
    let early = mint_absent_collection_tx(&f.attacker, 0, 9_000_000);
    let tail: Vec<SignedTransaction> = (1..3)
        .map(|n| transfer_tx(&f.attacker, f.sink, n, 8_000_000))
        .collect();
    // A different sender, whose transactions depend on nothing the attacker did.
    let honest: Vec<SignedTransaction> = (0..3)
        .map(|n| transfer_tx(&f.honest, f.sink, n, 1_000))
        .collect();

    for tx in std::iter::once(&early)
        .chain(tail.iter())
        .chain(honest.iter())
    {
        node.mempool.add(tx.clone()).expect("admitted");
    }

    let block = node.tick().await.expect("a block is produced");
    let carried = hashes(&block.transactions);
    println!(
        "NONCES: block carried {} tx; attacker tail still pending: {}",
        block.tx_count(),
        tail.iter()
            .filter(|t| node.mempool.contains(&t.hash()))
            .count()
    );

    assert!(
        honest.iter().all(|t| carried.contains(&t.hash())),
        "the OTHER sender's transactions are carried: their nonces depend on \
         nothing that was dropped, and holding them back would be the proposer \
         punishing them for being selected alongside"
    );
    for (i, tx) in tail.iter().enumerate() {
        assert!(
            !carried.contains(&tx.hash()),
            "the attacker's nonce {} must NOT be in this block: its predecessor \
             was dropped, so it would take an InvalidNonce receipt",
            i + 1
        );
        assert!(
            node.mempool.contains(&tx.hash()),
            "and it must still be in the mempool. A receipt in this block \
             would have had `remove_batch` delete it"
        );
    }
    // The receipts prove the negative directly: nothing in this block was
    // charged for a nonce failure.
    let receipts = ReceiptStore::new(&node.db);
    for tx in tail.iter() {
        assert!(
            receipts.get(&tx.hash()).expect("read receipt").is_none(),
            "and no receipt was written for it at all"
        );
    }
}

// ── 4. Fee ordering, and the balances nothing touched ───────────────────────

/// Quarantine does not rewrite the fee order, and does not move anybody's
/// money.
///
/// Three honest transfers at three different fees behind a quarantined
/// transaction. The block must carry them in descending fee order — the order
/// `select_for_block` produced — and the quarantined sender must be left with
/// the balance and nonce it started with: it paid nothing, because nothing of
/// it executed.
#[tokio::test]
async fn quarantine_preserves_fee_order_and_charges_the_quarantined_nothing() {
    let f = fixture();
    let node = Node::new(&f.genesis, f.key);
    let state = StateManager::new(node.db.clone(), CHAIN_ID);

    let before_balance = state.get_balance(&f.attacker.address()).expect("balance");
    let before_nonce = state.get_nonce(&f.attacker.address()).expect("nonce");

    let early = mint_absent_collection_tx(&f.attacker, 0, 9_000_000);
    node.mempool.add(early.clone()).expect("admitted");
    // Distinct fees, so the ordering assertion below has something to fail on.
    let fees = [7_000u128, 5_000, 3_000];
    let honest: Vec<SignedTransaction> = fees
        .iter()
        .enumerate()
        .map(|(n, fee)| transfer_tx(&f.honest, f.sink, n as u64, *fee))
        .collect();
    for tx in &honest {
        node.mempool.add(tx.clone()).expect("admitted");
    }

    let block = node.tick().await.expect("a block is produced");
    let carried_fees: Vec<u128> = block.transactions.iter().map(|t| t.fee()).collect();
    println!("FEES: block carried fees {carried_fees:?}");
    assert_eq!(
        carried_fees,
        fees.to_vec(),
        "the surviving transactions keep the descending fee order the \
         selection gave them: dropping one transaction must not reshuffle the \
         rest"
    );

    assert_eq!(
        state.get_balance(&f.attacker.address()).expect("balance"),
        before_balance,
        "the quarantined sender paid NOTHING. Its transaction never executed, \
         so charging it would be charging for work not done — and it will be \
         offered again next tick, so a charge here is a charge every tick"
    );
    assert_eq!(
        state.get_nonce(&f.attacker.address()).expect("nonce"),
        before_nonce,
        "and its nonce did not move, so the transaction it will re-offer is \
         still the one the sender signed"
    );
}

// ── 5. Restart ──────────────────────────────────────────────────────────────

/// A restart does not resurrect the halt.
///
/// The mempool is in memory, so a restart empties it — which means neither the
/// quarantine nor an eviction survives, and the chain's liveness must not
/// depend on either surviving. What must survive is on disk: the chain head, so
/// the restarted node proposes the NEXT height rather than replaying one; and
/// the properties that are recomputed from the transaction itself, so the same
/// poison offered to the restarted node is handled the same way.
#[tokio::test]
async fn a_restart_neither_resurrects_the_halt_nor_replays_a_height() {
    let f = fixture();
    let node = Node::new(&f.genesis, f.key);

    let early = mint_absent_collection_tx(&f.attacker, 0, 9_000_000);
    node.mempool.add(early.clone()).expect("admitted");
    node.mempool
        .add(transfer_tx(&f.honest, f.sink, 0, 1_000))
        .expect("admitted");
    let first = node.tick().await.expect("a block before the restart");

    let node = node.restart(&f.genesis, f.key);
    assert_eq!(
        node.consensus.current_height(),
        first.height(),
        "the restarted node picked the chain up off disk"
    );
    assert!(
        node.mempool.is_empty(),
        "and came up with an empty mempool, which is what makes the liveness \
         property below a property of the code rather than of anything the \
         previous process remembered"
    );

    // The same poison, re-offered after the restart, alongside honest traffic.
    node.mempool.add(early.clone()).expect("re-admitted");
    let tx = transfer_tx(&f.honest, f.sink, 1, 1_000);
    node.mempool.add(tx.clone()).expect("admitted");
    let second = node.tick().await.expect(
        "the restarted node must produce a block. A halt that comes back after \
         a restart is a halt an operator cannot clear",
    );
    println!(
        "RESTART: height {} before, height {} after, carrying {} tx",
        first.height(),
        second.height(),
        second.tx_count()
    );
    assert_eq!(
        second.height(),
        first.height() + 1,
        "and it proposes the NEXT height, not a replay of the one on disk"
    );
    assert!(
        second.transactions.iter().any(|t| t.hash() == tx.hash()),
        "carrying the honest transfer offered after the restart"
    );
    assert!(
        node.mempool.contains(&early.hash()),
        "and the re-offered transient transaction is quarantined again, not \
         destroyed: a restart is not evidence about a transaction"
    );
}

// ── 6. More poison than the budget ──────────────────────────────────────────

/// A fixture with `n` independently funded senders.
///
/// Independent because `drop_with_sender_tail` removes a sender's whole tail in
/// one drop: ten poisoned transactions from ONE sender cost one drop, and would
/// make a test of the drop budget a test of nothing. Ten senders cost ten.
fn many_senders(n: usize) -> (Genesis, [u8; 32], Vec<KeyPair>) {
    let validator = KeyPair::generate();
    let senders: Vec<KeyPair> = (0..n).map(|_| KeyPair::generate()).collect();
    let mut alloc = HashMap::from([(validator.address().to_base58(), 100_000_000u128)]);
    for kp in &senders {
        alloc.insert(kp.address().to_base58(), 1_000_000_000_000u128);
    }
    let genesis = Genesis::new(
        CHAIN_ID,
        0,
        vec![validator.public_key().to_base58()],
        alloc,
        params(),
    );
    (genesis, *validator.private_key().as_bytes(), senders)
}

/// Twelve unexecutable transactions, from twelve senders, still yield a block
/// that carries the honest traffic behind them.
///
/// Twelve because the fitting loop used to have ONE budget of eight, shared
/// between the proportional headroom truncation and the drop of a named
/// transaction. Nine transactions that cannot execute exhausted it, the
/// proposal that survived still refused, and `create_block` returned the
/// error — no block, and for the transient ones nothing evicted either, so the
/// same nine were selected first on the next tick. The halt was back by a side
/// door, for nine `min_fee`s.
///
/// So the budgets are separate: a drop is attributable progress, a headroom
/// truncation is a guess that converges, and one must not consume the other's
/// allowance.
#[tokio::test]
async fn more_unexecutable_transactions_than_the_old_budget_still_yields_a_block() {
    // Twelve poisoned senders and four clean ones. Clean senders are the point:
    // the poisoned senders' own later nonces go with their poison, correctly,
    // so a test that only had those could not tell "the block carried the
    // honest traffic" from "the block was empty".
    let (genesis, key, senders) = many_senders(16);
    let node = Node::new(&genesis, key);
    let sink = Address::new([0xAB; 20]);
    let (poisoned, clean) = senders.split_at(12);

    let mut proposal: Vec<SignedTransaction> = poisoned
        .iter()
        .map(|kp| mint_absent_collection_tx(kp, 0, 9_000_000))
        .collect();
    // Behind each poison, that sender's own nonce 1 — which must go with it.
    let tails: Vec<SignedTransaction> = poisoned
        .iter()
        .map(|kp| transfer_tx(kp, sink, 1, 5_000_000))
        .collect();
    proposal.extend(tails.iter().cloned());
    // And traffic from senders nobody poisoned, which must be carried.
    let honest: Vec<SignedTransaction> = clean
        .iter()
        .map(|kp| transfer_tx(kp, sink, 0, 1_000))
        .collect();
    proposal.extend(honest.iter().cloned());

    let block = node.consensus.propose_block(proposal).await.expect(
        "twelve unexecutable transactions must not stop a block being \
         produced. Under one shared budget of eight this returned an error, \
         which is the halt with a different number on it",
    );
    let carried = hashes(&block.transactions);
    println!(
        "BUDGET: 12 poisons + 12 tails + 4 clean -> block {} carried {}",
        block.hash(),
        block.tx_count()
    );
    assert!(
        honest.iter().all(|t| carried.contains(&t.hash())),
        "every transaction from a sender nobody poisoned must be carried. An \
         empty block every tick is a chain that advances while nothing \
         confirms, which is the halt wearing a different face"
    );
    for tx in &tails {
        assert!(
            !carried.contains(&tx.hash()),
            "and a transfer at nonce 1 behind a dropped nonce 0 must NOT be \
             carried: it would take an InvalidNonce receipt and then be \
             deleted from the mempool by remove_batch"
        );
    }
}

/// A flood larger than the whole drop budget still yields a block.
///
/// Seventy senders, every one of them poisoned, is past
/// `MAX_REFUSED_TX_DROPS`. The budget exists to bound the proposer's work — a
/// slot spent executing is its own denial of service — but a bound on work must
/// never become a bound on liveness. So the loop gives up on FITTING and falls
/// back to halving the proposal until something is accepted, which the empty
/// proposal always is.
///
/// It is no longer the path a flood takes. `PoAEngine::screen_selection` names
/// every offender in ONE execution ahead of the fitting loop, so seventy
/// poisons are removed together and the loop never sees them — section 7
/// asserts that directly, and asserts what it costs. This test stays because
/// the fallback must keep working for whatever the screening pass gets WRONG.
#[tokio::test]
async fn a_flood_larger_than_the_drop_budget_still_yields_a_block() {
    let (genesis, key, senders) = many_senders(70);
    let node = Node::new(&genesis, key);

    let proposal: Vec<SignedTransaction> = senders
        .iter()
        .map(|kp| mint_absent_collection_tx(kp, 0, 9_000_000))
        .collect();

    let block = node.consensus.propose_block(proposal).await.expect(
        "the fitting budget bounds WORK, not liveness. Running out of it must \
         produce a short block, never no block",
    );
    println!(
        "FLOOD: 70 poisons -> block {} at height {} carrying {}",
        block.hash(),
        block.height(),
        block.tx_count()
    );
    assert_eq!(block.height(), 1, "the chain advanced");
    assert_ne!(block.header.proposer_sig, [0u8; 64], "and it is signed");
}

// ── 7. What the flood COSTS ─────────────────────────────────────────────────
//
// The five sections above are about the halt: a proposer that produces no
// block. This one is about the price of not halting. `execute_block` abandons a
// block at the FIRST transaction it cannot execute, so the fitting loop learns
// one offender per execution and a proposal carrying `n` of them costs `n + 1`.
// `MAX_REFUSED_TX_DROPS` bounded that at sixty-four and left the door open:
// sixty-four full block executions, bought for sixty-four `min_fee`s, and a
// slot spent executing is its own denial of service.
//
// `PoAEngine::screen_selection` runs ONE pass that rolls each refusal back and
// carries on, so every offender is named by a single execution and removed
// together. The flood now costs two executions — the screening pass and the one
// that builds the block — and it carries the honest traffic that was behind it.

/// Seventy transactions that cannot execute, and the honest traffic behind them
/// is STILL CARRIED.
///
/// `a_flood_larger_than_the_drop_budget_still_yields_a_block` asserts only that
/// a block comes out. That is the weaker half, and a proposer satisfies it by
/// producing empty blocks forever while nothing confirms. Seventy offenders is
/// past any drop budget this loop has had, so under the fitting loop alone the
/// budget is exhausted, the proposal is HALVED until something is accepted, and
/// the honest traffic sorted behind the high-fee poison is halved away with it.
///
/// One screening pass removes all seventy together, and what is left is the
/// honest traffic — every transaction of it.
#[tokio::test]
async fn a_flood_of_seventy_refusals_still_carries_the_honest_traffic_behind_it() {
    let (genesis, key, senders) = many_senders(76);
    let node = Node::new(&genesis, key);
    let sink = Address::new([0xAB; 20]);
    let (poisoned, clean) = senders.split_at(70);

    // The poison pays the top fee, which is where a fee-ordered selection puts
    // it: at the FRONT, ahead of everything honest.
    let mut proposal: Vec<SignedTransaction> = poisoned
        .iter()
        .map(|kp| mint_absent_collection_tx(kp, 0, 9_000_000))
        .collect();
    let honest: Vec<SignedTransaction> = clean
        .iter()
        .map(|kp| transfer_tx(kp, sink, 0, 1_000))
        .collect();
    proposal.extend(honest.iter().cloned());

    let block = node
        .consensus
        .propose_block(proposal)
        .await
        .expect("seventy unexecutable transactions must not stop a block being produced");
    let carried = hashes(&block.transactions);
    println!(
        "COST: 70 poisons + 6 honest -> block {} carried {} tx",
        block.hash(),
        block.tx_count()
    );
    for (i, tx) in honest.iter().enumerate() {
        assert!(
            carried.contains(&tx.hash()),
            "honest transfer {i} of 6 must be carried. A block that advances the \
             chain while confirming nothing is the halt wearing a different face, \
             and halving a proposal down past seventy poisons is how the fitting \
             loop alone gets there"
        );
    }
    for tx in poisoned
        .iter()
        .map(|kp| mint_absent_collection_tx(kp, 0, 9_000_000))
    {
        assert!(
            !carried.contains(&tx.hash()),
            "and none of the poison is in the block"
        );
    }
}

/// A flood of `n` transactions that refuse costs ONE screening execution, not
/// `n`.
///
/// This is the defect stated as a number. Before the screening pass, seventy
/// offenders cost seventy-one full block executions — one to learn each, one to
/// build the block — and the only thing standing between a validator and a slot
/// spent entirely on execution was `MAX_REFUSED_TX_DROPS`, which bounded the
/// work by giving up on the proposal.
///
/// Two executions now, whatever `n` is: the screening pass that names all
/// seventy at once, and the one that builds the block they were removed from.
/// The count is read from `PoAEngine::proposal_executions`, which exists for no
/// other purpose — a claim about cost that no test can fail is not a claim.
#[tokio::test]
async fn a_flood_of_refusals_costs_one_screening_execution_not_one_each() {
    let (genesis, key, senders) = many_senders(74);
    let node = Node::new(&genesis, key);
    let sink = Address::new([0xAB; 20]);
    let (poisoned, clean) = senders.split_at(70);

    assert_eq!(
        node.consensus.proposal_executions(),
        0,
        "genesis initialisation is not a proposal"
    );

    let mut proposal: Vec<SignedTransaction> = poisoned
        .iter()
        .map(|kp| mint_absent_collection_tx(kp, 0, 9_000_000))
        .collect();
    let honest: Vec<SignedTransaction> = clean
        .iter()
        .map(|kp| transfer_tx(kp, sink, 0, 1_000))
        .collect();
    proposal.extend(honest.iter().cloned());

    let block = node
        .consensus
        .propose_block(proposal)
        .await
        .expect("a block");
    let spent = node.consensus.proposal_executions();
    println!(
        "EXECUTIONS: 70 refusing transactions cost {spent} execution(s); block {} \
         carried {}",
        block.hash(),
        block.tx_count()
    );
    assert_eq!(
        spent, 2,
        "one screening pass plus one real execution. Seventy-one is the defect: \
         it is a whole slot of CPU bought for seventy min_fees, and it is what \
         MAX_REFUSED_TX_DROPS used to cap by abandoning the proposal instead"
    );
    assert!(
        honest
            .iter()
            .all(|t| block.transactions.iter().any(|c| c.hash() == t.hash())),
        "and the two executions produced a block that carries the honest traffic"
    );
}

/// A proposal with nothing wrong with it costs TWO executions, and the second
/// one is the block.
///
/// Stated so that the price of the repair is in a test rather than in a comment.
/// Screening runs on every proposal, so the clean tick pays for the poisoned
/// one. Proposal execution is the proposer's own budget and no importer waits on
/// it, which is why this is the trade that was taken — but it is a real cost and
/// it is pinned here, so that a later change which makes it three is noticed.
#[tokio::test]
async fn a_clean_proposal_costs_the_screening_pass_and_nothing_more() {
    let f = fixture();
    let node = Node::new(&f.genesis, f.key);
    let honest: Vec<SignedTransaction> = (0..5)
        .map(|n| transfer_tx(&f.honest, f.sink, n, 1_000))
        .collect();

    let block = node
        .consensus
        .propose_block(honest.clone())
        .await
        .expect("a block");
    let spent = node.consensus.proposal_executions();
    println!(
        "CLEAN COST: {spent} execution(s) for {} clean tx",
        block.tx_count()
    );
    assert_eq!(
        block.tx_count(),
        5,
        "a clean proposal is carried whole: screening must not remove what \
         executes"
    );
    assert_eq!(
        spent, 2,
        "the screening pass and the block. Not three: a clean verdict must not \
         send the fitting loop back for another execution"
    );
}

/// The two verdicts, kept apart, in one proposal.
///
/// This is the owner's condition stated as one test: a permanently invalid
/// high-fee transaction does not prevent a block that carries the later valid
/// transactions, AND a temporarily ineligible one is not destroyed. Both
/// offenders are in the same proposal, so a screening pass that collapsed the
/// two classes into one verdict fails here whichever way it collapsed them —
/// evict-everything destroys the early mint, quarantine-everything leaves the
/// permanent poison at the top of the fee order to halt the next tick.
///
/// The transient one goes through the MEMPOOL, because "not destroyed" is a
/// statement about the mempool. The permanent one is handed to `propose_block`
/// directly: `Mempool::add` refuses that shape at admission (see
/// `crates/state/tests/mempool_permanent_admission.rs`), and a proposal is not
/// obliged to have come through this node's admission at all.
#[tokio::test]
async fn the_screening_pass_keeps_the_two_verdicts_apart_in_one_proposal() {
    // Three independently FUNDED senders. Funded matters: an unfunded sender's
    // transaction fails `validate_tx` and takes a RECEIPT, which is a different
    // population entirely and would make this a test of nothing.
    let (genesis, key, senders) = many_senders(3);
    let node = Node::new(&genesis, key);
    let sink = Address::new([0xAB; 20]);

    let early = mint_absent_collection_tx(&senders[1], 0, 9_000_000);
    node.mempool.add(early.clone()).expect("admitted");
    let honest: Vec<SignedTransaction> = (0..3)
        .map(|n| transfer_tx(&senders[2], sink, n, 1_000))
        .collect();
    for tx in &honest {
        node.mempool.add(tx.clone()).expect("admitted");
    }

    // The permanent poison joins the fee-ordered selection at the FRONT, where
    // its fee puts it.
    let permanent = modify_membership_tx(&senders[0], 0, 9_900_000);
    let mut proposal = vec![permanent.clone()];
    proposal.extend(node.mempool.select_for_block(1_000));

    let block = node
        .consensus
        .propose_block(proposal)
        .await
        .expect("a permanently invalid high-fee transaction must not prevent a block");
    let carried = hashes(&block.transactions);
    println!(
        "TWO VERDICTS: block carried {} tx; early mint still pending: {}",
        block.tx_count(),
        node.mempool.contains(&early.hash())
    );
    assert!(
        honest.iter().all(|t| carried.contains(&t.hash())),
        "the block carries the LATER VALID transactions — both offenders are \
         sorted ahead of them, so a proposer that stops at the first one \
         carries none of this"
    );
    assert!(
        !carried.contains(&permanent.hash()) && !carried.contains(&early.hash()),
        "and neither offender is in it"
    );
    assert!(
        node.mempool.contains(&early.hash()),
        "the TEMPORARILY ineligible one is still in the mempool. Its collection \
         does not exist YET; the block after this one may create it, and a \
         screening pass that evicted it would have destroyed honest traffic in \
         the name of a repair whose whole point is not doing that"
    );
    let held = node.mempool.get(&early.hash()).expect("still held");
    assert_eq!(held.hash(), early.hash(), "byte for byte");
}
