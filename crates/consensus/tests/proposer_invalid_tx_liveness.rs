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
