//! The strict transaction-signature gate and the legacy-evidence refusal gate
//! (dormant).
//!
//! This file starts with the dormant pin: a short chain that carries ordinary
//! transfers and an ordinary failed staking operation, executed and published
//! with every gate absent. Its state roots and receipts were recorded at
//! `fafb0fea` BEFORE either gate existed, and are asserted unchanged here.

mod common;

use std::sync::Arc;

use common::{publish_block, seed_balance, setup_with_params, CHAIN_ID};
use sumchain_crypto::{sign, KeyPair};
use sumchain_genesis::ChainParams;
use sumchain_primitives::staking::{
    DoubleSignEvidence, DowntimeEvidence, EvidenceType, StakingOperation, StakingTxData,
    SubmitEvidenceData,
};
use sumchain_primitives::{Receipt, SignedTransaction, TransactionV2, TxStatus, ValidatorInfo};
use sumchain_state::executor::BlockExecutor;
use sumchain_state::state::StateManager;
use sumchain_storage::schema::StakingStore;
use sumchain_storage::Database;
use tempfile::TempDir;

const FEE: u128 = 1_000;
const FUNDS: u128 = 1_000_000_000;
const STAKE: u128 = 1_000_000;
/// The proposer key every block in this file names.
const PROPOSER: [u8; 32] = [0x5A; 32];

fn key(seed: u8) -> KeyPair {
    KeyPair::from_bytes([seed; 32])
}

fn signed(kp: &KeyPair, tx: TransactionV2) -> SignedTransaction {
    let sig = sign(tx.signing_hash().as_bytes(), kp.private_key());
    SignedTransaction::new_v2(tx, *sig.as_bytes(), *kp.public_key().as_bytes())
}

fn transfer(from: &KeyPair, to: &KeyPair, amount: u128, nonce: u64) -> SignedTransaction {
    signed(
        from,
        TransactionV2::transfer(CHAIN_ID, from.address(), to.address(), amount, FEE, nonce),
    )
}

fn staking(from: &KeyPair, nonce: u64, operation: StakingOperation, data: Vec<u8>) -> SignedTransaction {
    signed(
        from,
        TransactionV2::staking(
            CHAIN_ID,
            from.address(),
            FEE,
            nonce,
            StakingTxData::new(operation, data),
        ),
    )
}

/// `SubmitEvidence` carrying `DoubleSign` against `validator`.
fn double_sign(from: &KeyPair, nonce: u64, validator: [u8; 32], height: u64) -> SignedTransaction {
    let evidence = DoubleSignEvidence {
        validator_pubkey: validator,
        height,
        block_hash_1: [0x11; 32],
        signature_1: [0u8; 64],
        block_hash_2: [0x22; 32],
        signature_2: [0u8; 64],
        submitted_at: height,
    };
    let data = bincode::serialize(&SubmitEvidenceData {
        evidence_type: EvidenceType::DoubleSign,
        evidence: bincode::serialize(&evidence).unwrap(),
    })
    .unwrap();
    staking(from, nonce, StakingOperation::SubmitEvidence, data)
}

/// `SubmitEvidence` carrying `Downtime` against `validator`, above the default
/// threshold (500).
fn downtime(from: &KeyPair, nonce: u64, validator: [u8; 32], height: u64) -> SignedTransaction {
    let evidence = DowntimeEvidence {
        validator_pubkey: validator,
        start_height: 1,
        end_height: height,
        missed_blocks: 1_000,
        submitted_at: height,
    };
    let data = bincode::serialize(&SubmitEvidenceData {
        evidence_type: EvidenceType::Downtime,
        evidence: bincode::serialize(&evidence).unwrap(),
    })
    .unwrap();
    staking(from, nonce, StakingOperation::SubmitEvidence, data)
}

/// One node: funded accounts 0x41..=0x43, two Active staking validators put
/// directly under their real keys (seeds 0x51, 0x52).
struct Node {
    _dir: TempDir,
    db: Arc<Database>,
    state: Arc<StateManager>,
    executor: BlockExecutor,
}

impl Node {
    fn new(params: ChainParams) -> Node {
        let (state, db, dir, executor) = setup_with_params(params);
        for seed in 0x41..=0x43u8 {
            seed_balance(&db, &key(seed).address(), FUNDS);
        }
        let store = StakingStore::new(&db);
        for seed in 0x51..=0x52u8 {
            store
                .put_validator(&ValidatorInfo::new(
                    *key(seed).public_key().as_bytes(),
                    STAKE,
                    0,
                    0,
                ))
                .unwrap();
        }
        Node {
            _dir: dir,
            db,
            state,
            executor,
        }
    }

    fn publish(&self, height: u64, txs: Vec<SignedTransaction>) -> Vec<Receipt> {
        publish_block(&self.state, &self.executor, height, &PROPOSER, txs, &[])
    }
}

/// The pinned history: four blocks, every transaction ordinarily signed.
///
/// 1. a transfer, and an `Unjail` from a non-validator (an ordinary failed
///    staking operation);
/// 2. empty;
/// 3. a transfer back;
/// 4. empty.
///
/// Returns BLAKE3 over every block's height, state root and receipts.
fn pinned_history(params: ChainParams) -> String {
    let node = Node::new(params);
    let (a, b, s) = (key(0x41), key(0x42), key(0x43));
    let blocks: Vec<Vec<SignedTransaction>> = vec![
        vec![
            transfer(&a, &b, 5_000, 0),
            staking(&s, 0, StakingOperation::Unjail, Vec::new()),
        ],
        Vec::new(),
        vec![transfer(&b, &a, 1_000, 0)],
        Vec::new(),
    ];
    // What each block's receipts say at `fafb0fea`: the transfers succeed and
    // the non-validator's `Unjail` fails (6).
    let statuses: [&[TxStatus]; 4] = [
        &[TxStatus::Success, TxStatus::Failed(6)],
        &[],
        &[TxStatus::Success],
        &[],
    ];
    let mut h = blake3::Hasher::new();
    for (i, txs) in blocks.into_iter().enumerate() {
        let height = i as u64 + 1;
        let receipts = node.publish(height, txs);
        let got: Vec<TxStatus> = receipts.iter().map(|r| r.status).collect();
        assert_eq!(got, statuses[i], "block {height}");
        h.update(&height.to_le_bytes());
        h.update(node.state.state_root().as_bytes());
        h.update(&bincode::serialize(&receipts).unwrap());
    }
    let _ = &node.db;
    hex::encode(h.finalize().as_bytes())
}

/// Recorded at `fafb0fea`, before either gate existed.
const PINNED_HISTORY: &str = "9a983883b0e515d67731b27a1787ee1bff8b6c4a88ee31b053cca32c2e531b4f";

#[test]
fn with_every_gate_absent_the_pinned_history_is_unchanged() {
    assert_eq!(pinned_history(ChainParams::with_v2_enabled()), PINNED_HISTORY);
}

// ═══════════════════════════════════════════════════════════════════════════
// Strict transaction signatures (`strict_transaction_signatures_enabled_from_height`)
// ═══════════════════════════════════════════════════════════════════════════

/// The strict-signature gate's height in the boundary tests.
const G: u64 = 10;

fn strict_from(height: Option<u64>) -> ChainParams {
    let mut p = ChainParams::with_v2_enabled();
    p.strict_transaction_signatures_enabled_from_height = height;
    p
}

/// `tx` with one bit of its signature flipped: a signature neither rule
/// accepts.
fn corrupted(mut tx: SignedTransaction) -> SignedTransaction {
    tx.signature[7] ^= 0x01;
    tx
}

#[test]
fn the_strict_signature_gate_is_closed_below_its_height_and_open_from_it() {
    use sumchain_state::tx_signature::strict_transaction_signatures_gate_open as open;
    let p = strict_from(Some(G));
    assert!(!open(&p, 0));
    assert!(!open(&p, G - 1));
    assert!(open(&p, G));
    assert!(open(&p, G + 1));
    assert!(open(&p, u64::MAX));
    let absent = strict_from(None);
    for h in [0, 1, G, u64::MAX] {
        assert!(!open(&absent, h), "absent, height {h}");
    }
    assert!(!open(&ChainParams::default(), u64::MAX), "dormant by default");
}

/// Property-style, over 256 deterministic keys and messages: an ordinary
/// signature passes the selection on both sides of the boundary and with the
/// gate absent, and agrees with both underlying rules; the same signature
/// over another message, and a corrupted one, fail everywhere.
#[test]
fn ordinary_signatures_pass_on_both_sides_of_the_boundary() {
    use sumchain_crypto::{verify_bytes, verify_bytes_strict};
    use sumchain_state::tx_signature::verify_transaction_signature as check;
    let gated = strict_from(Some(G));
    let absent = strict_from(None);
    for i in 0u32..256 {
        let seed = *blake3::hash(&[b"key".as_slice(), &i.to_le_bytes()].concat()).as_bytes();
        let kp = KeyPair::from_bytes(seed);
        let len = (i as usize * 7) % 200;
        let mut msg = vec![0u8; len];
        blake3::Hasher::new()
            .update(&i.to_le_bytes())
            .finalize_xof()
            .fill(&mut msg);
        let sig = sign(&msg, kp.private_key()).to_bytes();
        let pk = *kp.public_key().as_bytes();
        assert!(verify_bytes(&msg, &sig, &pk).is_ok(), "{i}: legacy");
        assert!(verify_bytes_strict(&msg, &sig, &pk).is_ok(), "{i}: strict");
        for (params, h) in [(&gated, G - 1), (&gated, G), (&gated, G + 1), (&absent, G)] {
            assert!(check(params, h, &msg, &sig, &pk).is_ok(), "{i} at {h}");
            let mut other = msg.clone();
            other.push(0x5A);
            assert!(check(params, h, &other, &sig, &pk).is_err(), "{i} at {h}: other message");
            let mut bad = sig;
            bad[(i as usize) % 64] ^= 0x80;
            assert!(check(params, h, &msg, &bad, &pk).is_err(), "{i} at {h}: corrupted");
        }
    }
}

/// Through block execution at G-1, G and G+1: an ordinarily signed transfer
/// succeeds on both sides, and a corrupted one takes an `InvalidSignature`
/// receipt with fee 0 and leaves the sender's balance and nonce alone.
#[test]
fn block_execution_applies_the_rule_of_the_block_height_and_ordinary_transfers_pass() {
    let node = Node::new(strict_from(Some(G)));
    let (a, b) = (key(0x41), key(0x42));
    for height in 1..G - 1 {
        node.publish(height, Vec::new());
    }
    let state = sumchain_storage::StateStore::new(&node.db);
    for (nonce, height) in (0u64..).zip([G - 1, G, G + 1]) {
        let before = state.get_account(&a.address()).unwrap();
        let receipts = node.publish(
            height,
            vec![transfer(&a, &b, 10, nonce), corrupted(transfer(&a, &b, 10, nonce + 1))],
        );
        assert_eq!(receipts[0].status, TxStatus::Success, "height {height}");
        assert_eq!(receipts[1].status, TxStatus::InvalidSignature, "height {height}");
        assert_eq!(receipts[1].fee_paid, 0, "height {height}");
        let after = state.get_account(&a.address()).unwrap();
        assert_eq!(after.nonce, before.nonce + 1, "only the ordinary transfer advanced it");
        assert_eq!(after.balance, before.balance - 10 - FEE, "only the ordinary transfer paid");
    }
}

/// Historical replay: the pinned history, executed with the gate set ABOVE
/// every height it reaches, and with the gate set at its first block, gives the
/// pinned roots and receipts. Every transaction in it is ordinarily signed, so
/// the strict rule accepts each one, and below the gate the legacy rule runs
/// exactly as before.
#[test]
fn the_pinned_history_replays_identically_with_the_strict_gate_set() {
    assert_eq!(pinned_history(strict_from(Some(100))), PINNED_HISTORY, "gate above the history");
    assert_eq!(pinned_history(strict_from(Some(1))), PINNED_HISTORY, "gate at block 1");
}

// ── mempool admission: the rule of the inclusion height ─────────────────────

mod admission {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    use sumchain_state::mempool::{Mempool, MempoolConfig, TransactionSignatureAdmission};
    use sumchain_state::StateError;

    fn mempool(params: ChainParams, head: u64) -> (Mempool, Arc<AtomicU64>) {
        let height = Arc::new(AtomicU64::new(head));
        let m = Mempool::new(MempoolConfig::default()).with_signature_admission(
            TransactionSignatureAdmission {
                params: Arc::new(params),
                current_height: height.clone(),
            },
        );
        (m, height)
    }

    /// The inclusion height is the chain tip plus one, so the strict rule
    /// applies from a tip of G-1 on: the block that would carry the
    /// transaction is G.
    #[test]
    fn admission_judges_a_signature_at_the_next_blocks_height() {
        let (a, b) = (key(0x41), key(0x42));
        let (m, tip) = mempool(strict_from(Some(G)), G - 2);
        assert_eq!(m.signature_inclusion_height(), Some(G - 1));

        // Inclusion height G-1: below the gate, no signature check, as before.
        assert!(m.add(corrupted(transfer(&a, &b, 1, 0))).is_ok());
        assert!(m.add(transfer(&a, &b, 1, 1)).is_ok());

        // Tip G-1, inclusion height G: the strict rule applies.
        tip.store(G - 1, Ordering::Relaxed);
        assert_eq!(m.signature_inclusion_height(), Some(G));
        assert!(matches!(
            m.add(corrupted(transfer(&a, &b, 1, 2))),
            Err(StateError::InvalidSignature)
        ));
        assert!(m.add(transfer(&a, &b, 1, 2)).is_ok(), "an ordinary signature is admitted");

        // And above it.
        tip.store(G + 5, Ordering::Relaxed);
        assert!(matches!(
            m.add(corrupted(transfer(&a, &b, 1, 3))),
            Err(StateError::InvalidSignature)
        ));
        assert!(m.add(transfer(&a, &b, 1, 3)).is_ok());
    }

    /// Gate absent, or no context at all: admission checks no signature at
    /// any height, which is today's behaviour.
    #[test]
    fn with_the_gate_absent_or_no_context_admission_is_unchanged() {
        let (a, b) = (key(0x41), key(0x42));
        let (m, _tip) = mempool(strict_from(None), u64::MAX - 1);
        assert!(m.add(corrupted(transfer(&a, &b, 1, 0))).is_ok());
        let bare = Mempool::new(MempoolConfig::default());
        assert_eq!(bare.signature_inclusion_height(), None);
        assert!(bare.add(corrupted(transfer(&a, &b, 1, 0))).is_ok());
    }

    /// A tip of `u64::MAX` saturates rather than wrapping to height 0.
    #[test]
    fn the_inclusion_height_saturates() {
        let (m, _tip) = mempool(strict_from(Some(G)), u64::MAX);
        assert_eq!(m.signature_inclusion_height(), Some(u64::MAX));
        let (a, b) = (key(0x41), key(0x42));
        assert!(m.add(corrupted(transfer(&a, &b, 1, 0))).is_err());
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Legacy evidence refused (`staking_submit_evidence_unsupported_enabled_from_height`)
// ═══════════════════════════════════════════════════════════════════════════

mod evidence {
    use super::*;
    use std::collections::{BTreeMap, BTreeSet};
    use sumchain_primitives::staking::DelegateData;
    use sumchain_primitives::supply::{
        GrantStatus, ServiceKind, SupplyOperation, SupplyTxData, GENESIS_ACCOUNTED_SUPPLY,
    };
    use sumchain_primitives::{Address, TxPayload};
    use sumchain_state::staking_executor::StakingExecutor;
    use sumchain_state::supply::SupplyStore;
    use sumchain_storage::cf;
    use sumchain_storage::db::ALL_CFS;
    use sumchain_storage::schema::AccountState;
    use sumchain_storage::StateStore;

    /// The refusal gate's height in these tests.
    const E: u64 = 10;
    const DELEGATED: u128 = 50_000;

    /// Every column family a staking penalty or a grant forfeiture writes.
    const PENALTY_CFS: [&str; 9] = [
        cf::VALIDATORS,
        cf::DELEGATIONS,
        cf::UNBONDING_DELEGATIONS,
        cf::DELEGATION_VALIDATOR_INDEX,
        cf::SLASHING_RECORDS,
        cf::VALIDATOR_SIGNING_INFO,
        cf::MISSED_BLOCKS,
        cf::VALIDATOR_SETS,
        cf::SUPPLY,
    ];

    fn params(refused_from: Option<u64>) -> ChainParams {
        let mut p = ChainParams::with_v2_enabled();
        p.service_grants_enabled_from_height = Some(0);
        p.staking_submit_evidence_unsupported_enabled_from_height = refused_from;
        p
    }

    type Dump = BTreeMap<&'static str, BTreeMap<Vec<u8>, Vec<u8>>>;

    /// Every row of every column family.
    fn dump(db: &Database) -> Dump {
        ALL_CFS
            .iter()
            .map(|name| {
                let rows = db
                    .iter(name)
                    .unwrap()
                    .map(|(k, v)| (k.to_vec(), v.to_vec()))
                    .collect();
                (*name, rows)
            })
            .collect()
    }

    fn changed(before: &Dump, after: &Dump) -> BTreeSet<&'static str> {
        ALL_CFS
            .iter()
            .copied()
            .filter(|name| before[name] != after[name])
            .collect()
    }

    fn account(db: &Database, addr: &Address) -> AccountState {
        StateStore::new(db).get_account(addr).unwrap()
    }

    /// A node with the supply correction applied (block 1), a staking
    /// validator V (seed 0x51, real key) holding an Active validator grant
    /// with a locked remainder, and a delegation to V from D (seed 0x42), both
    /// made in block 2. The submitter S (seed 0x43) has made no transaction.
    struct GrantNode {
        node: Node,
        v: KeyPair,
        s: KeyPair,
    }

    impl GrantNode {
        fn new(p: ChainParams) -> GrantNode {
            let (state, db, dir, executor) = setup_with_params(p);
            // The correction requires exactly the genesis supply at migration.
            let half = GENESIS_ACCOUNTED_SUPPLY / 2;
            common::credit_committed(&db, &Address::new([0xE1; 20]), half);
            common::credit_committed(&db, &Address::new([0xE2; 20]), half);
            let node = Node {
                _dir: dir,
                db,
                state,
                executor,
            };
            node.publish(1, Vec::new());
            assert!(SupplyStore::new(node.db.clone()).is_migration_applied().unwrap());

            let (v, d, s) = (key(0x51), key(0x42), key(0x43));
            for kp in [&v, &d, &s] {
                seed_balance(&node.db, &kp.address(), FUNDS);
            }
            StakingStore::new(&node.db)
                .put_validator(&ValidatorInfo::new(*v.public_key().as_bytes(), STAKE, 0, 0))
                .unwrap();
            let claim = signed(
                &v,
                TransactionV2 {
                    chain_id: CHAIN_ID,
                    from: v.address(),
                    fee: FEE,
                    nonce: 0,
                    payload: TxPayload::Supply(SupplyTxData {
                        operation: SupplyOperation::ClaimServiceGrant {
                            service_kind: ServiceKind::Validator,
                        },
                    }),
                },
            );
            let delegate = staking(
                &d,
                0,
                StakingOperation::Delegate,
                bincode::serialize(&DelegateData {
                    validator_pubkey: *v.public_key().as_bytes(),
                    amount: DELEGATED,
                })
                .unwrap(),
            );
            let r = node.publish(2, vec![claim, delegate]);
            assert_eq!(r[0].status, TxStatus::Success, "grant claim");
            assert_eq!(r[1].status, TxStatus::Success, "delegation");
            let g = grant(&node.db, &v).expect("grant");
            assert_eq!(g.status, GrantStatus::Active);
            assert!(g.locked_remaining > 0);
            GrantNode { node, v, s }
        }

        fn pubkey(&self) -> [u8; 32] {
            *self.v.public_key().as_bytes()
        }
    }

    fn grant(db: &Arc<Database>, v: &KeyPair) -> Option<sumchain_primitives::supply::ServiceGrant> {
        let mut c = common::candidate(db);
        let view = c.view();
        SupplyStore::v_get_grant(&view, &v.address(), ServiceKind::Validator).unwrap()
    }

    #[derive(Clone, Copy, Debug)]
    enum Variant {
        DoubleSign,
        Downtime,
    }

    fn evidence_tx(variant: Variant, from: &KeyPair, nonce: u64, v: [u8; 32], h: u64) -> SignedTransaction {
        match variant {
            Variant::DoubleSign => double_sign(from, nonce, v, h),
            Variant::Downtime => downtime(from, nonce, v, h),
        }
    }

    /// One evidence transaction against V in a block at `height` on a fresh
    /// grant node: the node, the receipt, and the database before and after
    /// that block.
    struct Run {
        g: GrantNode,
        receipt: Receipt,
        before: Dump,
        after: Dump,
        submitter_before: AccountState,
        proposer_before: AccountState,
    }

    fn run(variant: Variant, refused_from: Option<u64>, height: u64) -> Run {
        let g = GrantNode::new(params(refused_from));
        let before = dump(&g.node.db);
        let submitter_before = account(&g.node.db, &g.s.address());
        let proposer_before = account(&g.node.db, &Address::from_public_key(&PROPOSER));
        let tx = evidence_tx(variant, &g.s, 0, g.pubkey(), height);
        let mut r = g.node.publish(height, vec![tx]);
        let after = dump(&g.node.db);
        Run {
            g,
            receipt: r.remove(0),
            before,
            after,
            submitter_before,
            proposer_before,
        }
    }

    /// The column families an ordinary failed staking operation changes: an
    /// `Unjail` from a non-validator, in a block at the same height.
    fn ordinary_failure_footprint(height: u64) -> BTreeSet<&'static str> {
        let g = GrantNode::new(params(Some(E)));
        let before = dump(&g.node.db);
        let r = g
            .node
            .publish(height, vec![staking(&g.s, 0, StakingOperation::Unjail, Vec::new())]);
        assert_eq!(r[0].status, TxStatus::Failed(6));
        changed(&before, &dump(&g.node.db))
    }

    #[test]
    fn the_refusal_gate_is_closed_below_its_height_and_open_from_it() {
        let p = params(Some(E));
        assert!(!StakingExecutor::submit_evidence_unsupported(&p, E - 1));
        assert!(StakingExecutor::submit_evidence_unsupported(&p, E));
        assert!(StakingExecutor::submit_evidence_unsupported(&p, E + 1));
        let absent = params(None);
        for h in [0, E, u64::MAX] {
            assert!(!StakingExecutor::submit_evidence_unsupported(&absent, h));
        }
        assert!(!StakingExecutor::submit_evidence_unsupported(
            &ChainParams::default(),
            u64::MAX
        ));
    }

    /// At E and E+1, both variants are refused with `Failed(6)`, and the
    /// whole-database difference the block makes touches no penalty column
    /// family: no stake, jail, tombstone, signing info, slashing record,
    /// delegation or grant changes. The block's footprint is exactly that of
    /// an ordinary failed staking operation, and the only account changes are
    /// the submitter's fee and nonce and the proposer's credit.
    #[test]
    fn refused_evidence_changes_no_staking_penalty_state_for_either_variant() {
        let proposer = Address::from_public_key(&PROPOSER);
        for height in [E, E + 1] {
            let footprint = ordinary_failure_footprint(height);
            for variant in [Variant::DoubleSign, Variant::Downtime] {
                let what = format!("{variant:?} at {height}");
                let Run {
                    g,
                    receipt,
                    before,
                    after,
                    submitter_before,
                    proposer_before,
                } = run(variant, Some(E), height);
                assert_eq!(receipt.status, TxStatus::Failed(6), "{what}");
                assert_eq!(receipt.fee_paid, 0, "{what}: the receipt, as for every failed staking op");

                let moved = changed(&before, &after);
                for name in PENALTY_CFS {
                    assert!(!moved.contains(name), "{what}: {name} changed");
                    assert_eq!(before[name], after[name], "{what}: {name}");
                }
                assert_eq!(moved, footprint, "{what}: the footprint of an ordinary failed staking op");

                // Typed reads of the same facts.
                let store = StakingStore::new(&g.node.db);
                let slashing = sumchain_storage::schema::SlashingStore::new(&g.node.db);
                let v = store.get_validator(&g.pubkey()).unwrap().unwrap();
                assert_eq!(v.stake, STAKE, "{what}");
                assert_eq!(v.jailed_until, 0, "{what}");
                assert_eq!(v.slash_count, 0, "{what}");
                assert_eq!(v.status, ValidatorInfo::new(g.pubkey(), STAKE, 0, 0).status, "{what}");
                assert!(slashing.get_slashing_records(&g.pubkey()).unwrap().is_empty(), "{what}");
                assert!(slashing.get_signing_info(&g.pubkey()).unwrap().is_none(), "{what}");
                let grant = grant(&g.node.db, &g.v).unwrap();
                assert_eq!(grant.status, GrantStatus::Active, "{what}");
                assert!(grant.locked_remaining > 0, "{what}");

                // Fee and nonce: the ordinary failed-staking-operation charge.
                let s = account(&g.node.db, &g.s.address());
                assert_eq!(
                    (s.balance, s.nonce),
                    (submitter_before.balance - FEE, submitter_before.nonce + 1),
                    "{what}: fee debited, nonce advanced"
                );
                let p = account(&g.node.db, &proposer);
                assert_eq!(p.balance, proposer_before.balance + FEE, "{what}: proposer credited");
            }
        }
    }

    /// With a zero fee (possible only where `min_fee` is 0) the refused
    /// transaction changes nothing at all: `deduct_fee` does nothing for a
    /// zero fee, including the nonce, as for every staking operation.
    #[test]
    fn a_zero_fee_refusal_changes_nothing_including_the_nonce() {
        let mut p = params(Some(E));
        p.min_fee = 0;
        let g = GrantNode::new(p);
        let before = dump(&g.node.db);
        let mut tx = TransactionV2::staking(
            CHAIN_ID,
            g.s.address(),
            0,
            0,
            StakingTxData::new(StakingOperation::SubmitEvidence, Vec::new()),
        );
        tx.fee = 0;
        let r = g.node.publish(E, vec![signed(&g.s, tx)]);
        assert_eq!(r[0].status, TxStatus::Failed(6));
        let s = account(&g.node.db, &g.s.address());
        assert_eq!((s.balance, s.nonce), (FUNDS, 0));
        let moved = changed(&before, &dump(&g.node.db));
        for name in PENALTY_CFS {
            assert!(!moved.contains(name), "{name}");
        }
    }

    /// The payload is never read from the gate on. Below it, an undecodable
    /// `SubmitEvidence` payload aborts the whole block, as it always has; from
    /// the gate on, it is refused like any other evidence and charged.
    #[test]
    fn an_undecodable_payload_aborts_the_block_below_the_gate_and_is_refused_from_it() {
        use sumchain_primitives::{Block, BlockHeader, Hash};
        let garbage = vec![0xFF; 3];
        // Below: the block cannot be executed.
        let g = GrantNode::new(params(Some(E)));
        let tx = staking(&g.s, 0, StakingOperation::SubmitEvidence, garbage.clone());
        let mut block = Block::new(
            BlockHeader::new(Hash::ZERO, E - 1, 1000, Hash::ZERO, Hash::ZERO, PROPOSER),
            vec![tx],
        );
        block.header.tx_root = block.compute_tx_root();
        assert!(g
            .node
            .executor
            .execute_block(&block, g.node.state.state_root(), &[])
            .is_err());
        // From the gate: a receipt.
        let g = GrantNode::new(params(Some(E)));
        let r = g
            .node
            .publish(E, vec![staking(&g.s, 0, StakingOperation::SubmitEvidence, garbage)]);
        assert_eq!(r[0].status, TxStatus::Failed(6));
        let s = account(&g.node.db, &g.s.address());
        assert_eq!((s.balance, s.nonce), (FUNDS - FEE, 1));
    }

    /// Historical replay: the pinned history gives the pinned roots and
    /// receipts with the refusal gate set above every height it reaches.
    #[test]
    fn the_pinned_history_replays_identically_with_the_refusal_gate_above_it() {
        let mut p = ChainParams::with_v2_enabled();
        p.staking_submit_evidence_unsupported_enabled_from_height = Some(100);
        assert_eq!(pinned_history(p), PINNED_HISTORY);
        let mut both = strict_from(Some(100));
        both.staking_submit_evidence_unsupported_enabled_from_height = Some(100);
        assert_eq!(pinned_history(both), PINNED_HISTORY, "both gates above the history");
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// A signature the two rules judge differently, made with the signer's key.
//
// Strict Ed25519 verification accepts only canonical encodings with no
// small-order components; the legacy verifier is more permissive. A key-holder
// can produce, WITH their own private key, a non-canonical variant of their
// own signature whose R is the identity point (a small-order component): the
// verification equation still holds, so `verify_bytes` accepts it, but
// `verify_bytes_strict` refuses it. That is the kind of signature the strict
// gate begins refusing, and a test built from it is the one that proves the
// gate is not a no-op.
// ═══════════════════════════════════════════════════════════════════════════

mod key_holder {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    use curve25519_dalek::Scalar;
    use ed25519_dalek::hazmat::ExpandedSecretKey;
    use sha2::{Digest, Sha512};
    use sumchain_crypto::{verify_bytes, verify_bytes_strict};
    use sumchain_primitives::Address;
    use sumchain_state::mempool::{Mempool, MempoolConfig, TransactionSignatureAdmission};
    use sumchain_state::StateError;
    use sumchain_storage::{Database, StateStore};

    /// The strict-signature gate's height in these tests.
    const H: u64 = 10;
    /// The compressed identity point (y = 1): a small-order component that
    /// strict verification rejects as an R value, and the legacy verifier
    /// accepts.
    const IDENTITY: [u8; 32] = {
        let mut b = [0u8; 32];
        b[0] = 1;
        b
    };
    /// The signing key used throughout: seed 0x71, an ordinary key.
    const SEED: [u8; 32] = [0x71; 32];

    fn pubkey() -> [u8; 32] {
        *KeyPair::from_bytes(SEED).public_key().as_bytes()
    }

    /// k = SHA-512(R ‖ A ‖ M) mod l.
    fn challenge(r: &[u8; 32], a: &[u8; 32], msg: &[u8]) -> Scalar {
        let mut h = Sha512::new();
        h.update(r);
        h.update(a);
        h.update(msg);
        Scalar::from_bytes_mod_order_wide(&h.finalize().into())
    }

    /// The holder's own signature over `msg`, re-expressed with R = identity
    /// and s = k·a (k over those R bytes). The equation holds, so the legacy
    /// verifier accepts it; strict verification refuses it because R is a
    /// small-order component. Produced with the private key.
    fn identity_r_sig(msg: &[u8]) -> [u8; 64] {
        let a = pubkey();
        let s = challenge(&IDENTITY, &a, msg) * ExpandedSecretKey::from(&SEED).scalar;
        let mut sig = [0u8; 64];
        sig[..32].copy_from_slice(&IDENTITY);
        sig[32..].copy_from_slice(s.as_bytes());
        sig
    }

    /// A transfer from the holder's address carrying such a signature over its
    /// own signing hash.
    fn legacy_only_transfer(to: Address, amount: u128, nonce: u64) -> SignedTransaction {
        let pk = pubkey();
        let from = Address::from_public_key(&pk);
        let tx = TransactionV2::transfer(CHAIN_ID, from, to, amount, FEE, nonce);
        let sig = identity_r_sig(tx.signing_hash().as_bytes());
        SignedTransaction::new_v2(tx, sig, pk)
    }

    fn node(params: ChainParams) -> Node {
        let n = Node::new(params);
        seed_balance(&n.db, &Address::from_public_key(&pubkey()), FUNDS);
        n
    }

    fn account(db: &Database, addr: &Address) -> (u128, u64) {
        let a = StateStore::new(db).get_account(addr).unwrap();
        (a.balance, a.nonce)
    }

    /// The fixture provably separates the two rules: `verify_bytes` ACCEPTS the
    /// signature and `verify_bytes_strict` REFUSES it, while an ordinary
    /// signature is accepted by both.
    #[test]
    fn the_legacy_only_signature_separates_the_two_rules() {
        let msg = b"a message";
        let pk = pubkey();
        let sig = identity_r_sig(msg);
        assert!(verify_bytes(msg, &sig, &pk).is_ok(), "the legacy verifier accepts it");
        assert!(verify_bytes_strict(msg, &sig, &pk).is_err(), "strict verification refuses it");
        let honest = sign(msg, KeyPair::from_bytes(SEED).private_key()).to_bytes();
        assert!(verify_bytes(msg, &honest, &pk).is_ok(), "ordinary: legacy");
        assert!(verify_bytes_strict(msg, &honest, &pk).is_ok(), "ordinary: strict");
    }

    /// Through block execution (the `execute_or_screen` path) at H-1, H and
    /// H+1 with the gate at H: the legacy-only signature is accepted below the
    /// boundary, exactly as today, and refused at and above it.
    #[test]
    fn the_legacy_only_signature_is_accepted_below_the_boundary_and_refused_from_it() {
        let to = Address::new([0xE1; 20]);
        let from = Address::from_public_key(&pubkey());

        {
            let n = node(strict_from(Some(H)));
            for h in 1..H - 1 {
                n.publish(h, Vec::new());
            }
            let (bal0, nonce0) = account(&n.db, &from);
            let r = n.publish(H - 1, vec![legacy_only_transfer(to, 7, 0)]);
            assert_eq!(r[0].status, TxStatus::Success, "H-1 accepts it, as today");
            let (bal1, nonce1) = account(&n.db, &from);
            assert_eq!(nonce1, nonce0 + 1, "nonce advanced");
            assert_eq!(bal1, bal0 - 7 - FEE, "amount and fee left the account");
            assert_eq!(account(&n.db, &to).0, 7, "recipient credited");
        }

        for height in [H, H + 1] {
            let n = node(strict_from(Some(H)));
            for h in 1..height {
                n.publish(h, Vec::new());
            }
            let before = account(&n.db, &from);
            let r = n.publish(height, vec![legacy_only_transfer(to, 7, 0)]);
            assert_eq!(r[0].status, TxStatus::InvalidSignature, "height {height} refuses it");
            assert_eq!(r[0].fee_paid, 0, "height {height}: fee 0");
            assert_eq!(account(&n.db, &from), before, "height {height}: balance and nonce unchanged");
            assert_eq!(account(&n.db, &to).0, 0, "height {height}: nothing credited");
        }
    }

    /// Mempool admission at inclusion height H-1 (below the gate: admitted as
    /// today) and H (at the gate: refused).
    #[test]
    fn admission_refuses_the_legacy_only_signature_from_its_inclusion_height() {
        let to = Address::new([0xE2; 20]);
        let height = std::sync::Arc::new(AtomicU64::new(H - 2));
        let m = Mempool::new(MempoolConfig::default()).with_signature_admission(
            TransactionSignatureAdmission {
                params: std::sync::Arc::new(strict_from(Some(H))),
                current_height: height.clone(),
            },
        );
        assert_eq!(m.signature_inclusion_height(), Some(H - 1));
        assert!(m.add(legacy_only_transfer(to, 1, 0)).is_ok(), "inclusion H-1: admitted as today");

        height.store(H - 1, Ordering::Relaxed);
        assert_eq!(m.signature_inclusion_height(), Some(H));
        assert!(matches!(
            m.add(legacy_only_transfer(to, 1, 1)),
            Err(StateError::InvalidSignature)
        ));
    }

    /// A chain built under legacy rules whose middle block carries the
    /// legacy-only transfer. Each block's state root and a digest of its
    /// receipts, and the transfer's status.
    fn chain(gate: Option<u64>) -> (Vec<(String, String)>, TxStatus) {
        let n = node(strict_from(gate));
        let ordinary = key(0x41);
        let sink = key(0x42);
        let to = Address::new([0xE4; 20]);
        let mut snaps = Vec::new();
        let mut snap = |n: &Node, receipts: &[Receipt]| {
            let mut h = blake3::Hasher::new();
            h.update(&bincode::serialize(receipts).unwrap());
            snaps.push((
                n.state.state_root().to_string(),
                hex::encode(h.finalize().as_bytes()),
            ));
        };
        let r1 = n.publish(1, vec![transfer(&ordinary, &sink, 100, 0)]);
        snap(&n, &r1);
        let r2 = n.publish(2, vec![legacy_only_transfer(to, 50, 0)]);
        let status = r2[0].status;
        snap(&n, &r2);
        let r3 = n.publish(3, vec![transfer(&ordinary, &sink, 100, 1)]);
        snap(&n, &r3);
        (snaps, status)
    }

    /// Historical replay: built under legacy rules the transfer is accepted at
    /// height 2; with the gate ABOVE every height the roots and receipts are
    /// identical; with the gate AT the transfer's height block 1 is identical
    /// and block 2 diverges exactly there.
    #[test]
    fn a_legacy_chain_replays_identically_with_the_gate_above_it() {
        let (legacy, status) = chain(None);
        assert_eq!(status, TxStatus::Success, "accepted under the legacy rule");
        let (above, above_status) = chain(Some(100));
        assert_eq!(above_status, TxStatus::Success);
        assert_eq!(above, legacy, "gate above the chain: identical roots and receipts");
        let (at, at_status) = chain(Some(2));
        assert_eq!(at_status, TxStatus::InvalidSignature, "gate at height 2 refuses it");
        assert_eq!(at[0], legacy[0], "block 1 (below the gate) is identical");
        assert_ne!(at[1], legacy[1], "block 2 diverges exactly at the transaction");
    }
}
