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
