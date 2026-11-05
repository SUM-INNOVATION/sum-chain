//! Storage-challenge targets on the assignment-aware paths, and the dormant
//! attested-target gate (`por_attested_targets_enabled_from_height`).
//!
//! Without the gate, the target is drawn from the archives assigned to the
//! challenged chunk (latest epoch) that are currently Active, with no read of
//! the attestation bitmaps, while activation only needs the UNION of
//! attestations to cover each chunk. An assigned archive that attested nothing
//! (and so need not hold the chunk) can therefore be drawn and, unanswered,
//! slashed. From the gate on, an archive is a target only if its attestation
//! in the file's latest assignment epoch covers the chunk; a chunk with no such
//! archive is skipped.
//!
//! The gate does not touch which files are challenged: a funded Private file
//! is challenged as before, and its target is an archive that attested the
//! chunk. Those tests pin that the gate leaves this unchanged.
//!
//! Every block is published through `execute_block` (`common::publish_block`):
//! expiry slashing runs at the start of a block and challenge generation after
//! its transactions, exactly as on a node. Keys are fixed, and the published
//! blocks carry parent hash ZERO, so every seed is a function of the height
//! alone and the tests are reproducible. The reassignment test calls the public
//! challenge generators on a candidate view with each target rule.

mod common;

use std::sync::Arc;

use common::{fund, setup_with_params, CHAIN_ID};
use sumchain_crypto::{sign, KeyPair};
use sumchain_genesis::ChainParams;
use sumchain_primitives::storage_metadata::{
    FileLifecycleV2, FileVisibilityV2, StorageChallenge, CHALLENGE_INTERVAL_BLOCKS,
    CHALLENGE_REWARD, CHALLENGE_TTL_BLOCKS, SLASH_PERCENTAGE,
};
use sumchain_primitives::{
    assigned_archives_presorted, AccessEntryV2, Address, EncryptedKeyBundleV2, Hash, NodeRecord,
    NodeRegistryOperation, NodeRegistryOperationV2, NodeRegistryTxData, NodeRegistryV2TxData,
    NodeRole, NodeStatus, SignedTransaction, StorageMetadataOperation, StorageMetadataOperationV2,
    StorageMetadataTxData, StorageMetadataV2TxData, TransactionV2, TxPayload,
};
use sumchain_state::executor::BlockExecutor;
use sumchain_state::state::StateManager;
use sumchain_state::storage_metadata::{
    por_targets, PorTargets, StorageMetadataExecutor,
};
use sumchain_state::NodeRegistryExecutor;
use sumchain_storage::Database;
use tempfile::TempDir;

const STAKE: u64 = 1_000_000_000;
const FEE: u128 = 1_000;
/// A nonzero deposit, as `sum-node ingest-v2 --fee-deposit` / `SUM_FEE_DEPOSIT`
/// would lock. Smaller than `CHALLENGE_REWARD`, so one answered challenge
/// drains it.
const DEPOSIT: u64 = 1_000_000;
const REGISTER_HEIGHT: u64 = 2;

// ── Parameters for the challenge paths ───────────────────────────────────────

#[derive(Clone, Copy, Debug)]
enum Path {
    /// Both assignment-aware gates closed (production default `None`): the
    /// legacy V1-only path.
    Legacy,
    /// `por_assignment_targeting_enabled_from_height` open, scheduler closed.
    Targeting,
    /// `assignment_aware_por_scheduler_enabled_from_height` open.
    Scheduler,
}

const V2_PATHS: [Path; 2] = [Path::Targeting, Path::Scheduler];

fn params(path: Path, r: u32, attested_gate: Option<u64>) -> ChainParams {
    let mut p = ChainParams::with_v2_enabled();
    p.assignment_replication_factor = r;
    p.por_attested_targets_enabled_from_height = attested_gate;
    match path {
        Path::Legacy => {}
        Path::Targeting => p.por_assignment_targeting_enabled_from_height = Some(0),
        Path::Scheduler => {
            p.assignment_aware_por_scheduler_enabled_from_height = Some(0);
            // One file, one chunk, one challenge per interval: the emitted
            // challenge is the one the probe below predicts.
            p.max_files_sampled_per_interval = 1;
            p.max_chunks_sampled_per_file = 1;
            p.max_assignment_aware_challenges_per_block = 1;
        }
    }
    p
}

// ── Transactions ─────────────────────────────────────────────────────────────

fn signed(kp: &KeyPair, nonce: u64, payload: TxPayload) -> SignedTransaction {
    let tx = TransactionV2 {
        chain_id: CHAIN_ID,
        from: kp.address(),
        fee: FEE,
        nonce,
        payload,
    };
    let h = tx.signing_hash();
    let sig = sign(h.as_bytes(), kp.private_key());
    SignedTransaction::new_v2(tx, *sig.as_bytes(), *kp.public_key().as_bytes())
}

fn register_archive(kp: &KeyPair, nonce: u64) -> SignedTransaction {
    signed(
        kp,
        nonce,
        TxPayload::NodeRegistry(NodeRegistryTxData {
            operation: NodeRegistryOperation::Register {
                role: NodeRole::ArchiveNode,
                stake: STAKE,
            },
        }),
    )
}

fn register_encryption_key(kp: &KeyPair, nonce: u64) -> SignedTransaction {
    signed(
        kp,
        nonce,
        TxPayload::NodeRegistryV2(NodeRegistryV2TxData {
            operation: NodeRegistryOperationV2::RegisterEncryptionKey {
                encryption_pubkey: [7u8; 32],
            },
        }),
    )
}

fn sm_v2(kp: &KeyPair, nonce: u64, op: StorageMetadataOperationV2) -> SignedTransaction {
    signed(
        kp,
        nonce,
        TxPayload::StorageMetadataV2(StorageMetadataV2TxData { operation: op }),
    )
}

/// A node-registry status change sent as a transaction. While its own refusal
/// gate is unset it executes as before; the tests use it only to take an
/// archive out of the Active set.
fn set_status(
    sender: &KeyPair,
    nonce: u64,
    target: Address,
    status: NodeStatus,
) -> SignedTransaction {
    signed(
        sender,
        nonce,
        TxPayload::NodeRegistry(NodeRegistryTxData {
            operation: NodeRegistryOperation::UpdateStatus {
                target,
                new_status: status,
            },
        }),
    )
}

/// The proof for chunk 0 of a one-chunk file: the leaf is the root and the
/// path is empty.
fn answer(kp: &KeyPair, nonce: u64, ch: &StorageChallenge) -> SignedTransaction {
    signed(
        kp,
        nonce,
        TxPayload::StorageMetadata(StorageMetadataTxData {
            operation: StorageMetadataOperation::SubmitStorageProof {
                challenge_id: ch.challenge_id,
                merkle_root: ch.merkle_root,
                chunk_index: 0,
                chunk_hash: ch.merkle_root,
                merkle_path: vec![],
            },
        }),
    )
}

/// One-chunk V2 file (stored size 1000 B ⇒ `chunk_count` 1). Private carries
/// the owner's access entry with a bundle, as the chain requires.
fn register_file(
    owner: &KeyPair,
    nonce: u64,
    root: Hash,
    private: bool,
    deposit: u64,
) -> SignedTransaction {
    let (visibility, initial_access) = if private {
        (
            1u8,
            vec![AccessEntryV2 {
                address: owner.address(),
                encrypted_key_bundle: Some(EncryptedKeyBundleV2([1u8; 80])),
                expires_at: None,
            }],
        )
    } else {
        (0u8, vec![])
    };
    sm_v2(
        owner,
        nonce,
        StorageMetadataOperationV2::RegisterFilePendingV2 {
            merkle_root: root,
            plaintext_size_bytes: 500,
            stored_size_bytes: 1000,
            chunk_count: 1,
            fee_deposit: deposit,
            visibility,
            initial_access,
        },
    )
}

// ── World ────────────────────────────────────────────────────────────────────

struct World {
    state: Arc<StateManager>,
    db: Arc<Database>,
    _dir: TempDir,
    executor: BlockExecutor,
    params: ChainParams,
    proposer_pk: [u8; 32],
    archives: Vec<KeyPair>,
    owner: KeyPair,
    /// The owner's next nonce.
    owner_nonce: u64,
    root: Hash,
    /// Archives assigned to chunk 0 under the file's (only) epoch.
    assigned: Vec<Address>,
}

impl World {
    fn publish(
        &self,
        height: u64,
        txs: Vec<SignedTransaction>,
    ) -> Vec<sumchain_primitives::Receipt> {
        common::publish_block(
            &self.state,
            &self.executor,
            height,
            &self.proposer_pk,
            txs,
            &[],
        )
    }
    fn node(&self, a: &Address) -> NodeRecord {
        NodeRegistryExecutor::new(self.db.clone())
            .get_node(a)
            .unwrap()
            .expect("node record")
    }
    fn active_archives(&self) -> Vec<Address> {
        NodeRegistryExecutor::new(self.db.clone())
            .get_active_archive_nodes()
            .unwrap()
            .into_iter()
            .map(|n| n.address)
            .collect()
    }
    /// The open challenges targeting `a`. Filtered by target: the node-index
    /// query walks forward from `a`'s prefix without bounding it, so it can
    /// also return challenges of archives whose address sorts after `a`.
    fn challenges_for(&self, a: &Address) -> Vec<StorageChallenge> {
        StorageMetadataExecutor::new(self.db.clone())
            .get_challenges_by_node(a)
            .unwrap()
            .into_iter()
            .filter(|c| c.target_node == *a)
            .collect()
    }
    fn all_challenges(&self) -> Vec<StorageChallenge> {
        self.archives
            .iter()
            .flat_map(|k| self.challenges_for(&k.address()))
            .collect()
    }
    fn kp_of(&self, a: &Address) -> &KeyPair {
        self.archives
            .iter()
            .find(|k| k.address() == *a)
            .expect("archive keypair")
    }
}

fn sorted(nodes: &[NodeRecord]) -> Vec<Address> {
    let mut v: Vec<Address> = nodes.iter().map(|n| n.address).collect();
    v.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
    v.dedup();
    v
}

/// Publish blocks 1-4: `k` archives register (and, for Private, the owner
/// registers an X25519 key) at 1; the owner registers a one-chunk V2 file at 2;
/// the archives chosen by `attesters` accept chunk 0 at 3; the owner activates
/// at 4. Asserts every step succeeded and the file is Active.
#[allow(clippy::too_many_arguments)]
fn build(
    path: Path,
    r: u32,
    attested_gate: Option<u64>,
    k: usize,
    private: bool,
    deposit: u64,
    label: &str,
    attesters: impl Fn(&[Address]) -> Vec<Address>,
) -> World {
    let params = params(path, r, attested_gate);
    let (state, db, dir, executor) = setup_with_params(params.clone());
    let proposer = KeyPair::from_bytes([0xEE; 32]);
    let owner = KeyPair::from_bytes([0x0A; 32]);
    let archives: Vec<KeyPair> = (0..k)
        .map(|i| KeyPair::from_bytes([0x40 + i as u8; 32]))
        .collect();
    fund(&db, &owner, (deposit as u128) + 10 * FEE);
    for a in &archives {
        fund(&db, a, (STAKE as u128) + 10 * FEE);
    }
    let root = Hash::hash(label.as_bytes());
    let mut w = World {
        state,
        db,
        _dir: dir,
        executor,
        params,
        proposer_pk: *proposer.public_key().as_bytes(),
        archives,
        owner,
        owner_nonce: 0,
        root,
        assigned: vec![],
    };

    // Height 1: archives (and the owner's encryption key for Private).
    let mut txs: Vec<SignedTransaction> =
        w.archives.iter().map(|a| register_archive(a, 0)).collect();
    if private {
        txs.push(register_encryption_key(&w.owner, w.owner_nonce));
        w.owner_nonce += 1;
    }
    for rc in w.publish(1, txs) {
        assert!(rc.status.is_success(), "height 1: {:?}", rc.status);
    }

    // Height 2: register the file (assignment_height = 2).
    let rc = w.publish(
        REGISTER_HEIGHT,
        vec![register_file(
            &w.owner,
            w.owner_nonce,
            root,
            private,
            deposit,
        )],
    );
    assert!(rc[0].status.is_success(), "register: {:?}", rc[0].status);
    w.owner_nonce += 1;

    // The assigned set for chunk 0 under the registration snapshot.
    let snapshot = NodeRegistryExecutor::new(w.db.clone())
        .get_active_archive_nodes_at_height(REGISTER_HEIGHT)
        .unwrap();
    w.assigned = assigned_archives_presorted(&root, &sorted(&snapshot), 0, r);
    assert_eq!(w.assigned.len(), r as usize, "R assignees for chunk 0");

    // Height 3: chosen assignees attest chunk 0.
    let attest: Vec<Address> = attesters(&w.assigned);
    let txs: Vec<SignedTransaction> = attest
        .iter()
        .map(|a| {
            sm_v2(
                w.kp_of(a),
                1,
                StorageMetadataOperationV2::AcceptAssignmentV2 {
                    merkle_root: root,
                    chunk_indices: vec![0],
                },
            )
        })
        .collect();
    for rc in w.publish(3, txs) {
        assert!(rc.status.is_success(), "accept: {:?}", rc.status);
    }

    // Height 4: activate.
    let rc = w.publish(
        4,
        vec![sm_v2(
            &w.owner,
            w.owner_nonce,
            StorageMetadataOperationV2::ActivateFileV2 { merkle_root: root },
        )],
    );
    assert!(rc[0].status.is_success(), "activate: {:?}", rc[0].status);
    w.owner_nonce += 1;

    let row = StorageMetadataExecutor::new(w.db.clone())
        .get_metadata_v2(&root)
        .unwrap()
        .expect("V2 row");
    assert_eq!(row.lifecycle, FileLifecycleV2::Active);
    assert_eq!(
        row.visibility,
        if private {
            FileVisibilityV2::Private
        } else {
            FileVisibilityV2::Public
        }
    );
    assert_eq!(row.fee_pool, deposit, "fee_pool = deposit");
    w
}

/// R = 1, three archives, a one-chunk file whose sole assignee attested (and
/// so holds the chunk): the target is an archive that attested.
fn attested_world(
    path: Path,
    attested_gate: Option<u64>,
    private: bool,
    deposit: u64,
    label: &str,
) -> World {
    build(
        path,
        1,
        attested_gate,
        3,
        private,
        deposit,
        label,
        |assigned| assigned.to_vec(),
    )
}

/// R = 2, four archives, one chunk: both assignees A (`assigned[0]`) and B
/// (`assigned[1]`) are Active, only A attests, and activation succeeds on A's
/// attestation alone.
fn one_attester_world(path: Path, attested_gate: Option<u64>, label: &str) -> World {
    let w = build(
        path,
        2,
        attested_gate,
        4,
        false,
        DEPOSIT,
        label,
        |assigned| vec![assigned[0]],
    );
    let sm = StorageMetadataExecutor::new(w.db.clone());
    let (a, b) = (w.assigned[0], w.assigned[1]);
    assert!(
        sm.get_attestation_bitmap_v2(&w.root, &a).unwrap().is_some(),
        "A attested"
    );
    assert!(
        sm.get_attestation_bitmap_v2(&w.root, &b).unwrap().is_none(),
        "B attested nothing"
    );
    assert!(w.active_archives().contains(&b), "B is Active");
    w
}

const H: u64 = CHALLENGE_INTERVAL_BLOCKS; // first challenge height: 100

fn assert_slashed(w: &World, a: &Address) {
    let rec = w.node(a);
    assert_eq!(rec.status, NodeStatus::Slashed, "target must be Slashed");
    assert_eq!(
        rec.staked_balance,
        STAKE - STAKE * SLASH_PERCENTAGE / 100,
        "5% slashed"
    );
    assert!(
        !w.active_archives().contains(a),
        "slashed target leaves the active-archive set"
    );
}

fn assert_untouched(w: &World, a: &Address) {
    let rec = w.node(a);
    assert_eq!(rec.status, NodeStatus::Active);
    assert_eq!(rec.staked_balance, STAKE);
}

/// What the real challenge code would emit at `height` against committed
/// state under the target rule `targets`, computed on a throwaway candidate
/// that is never published.
fn probe(w: &World, path: Path, height: u64, targets: PorTargets) -> Option<Address> {
    let r = w.params.assignment_replication_factor;
    let mut cand = common::candidate(&w.db);
    let mut view = cand.view();
    match path {
        Path::Targeting => {
            let active = NodeRegistryExecutor::v_get_active_archive_nodes(&view).unwrap();
            StorageMetadataExecutor::generate_challenge_with_targets(
                &mut view,
                &Hash::ZERO,
                height,
                &active,
                true,
                r,
                targets,
            )
            .unwrap()
            .map(|c| c.target_node)
        }
        Path::Scheduler => StorageMetadataExecutor::generate_challenge_schedule_with_targets(
            &mut view,
            &Hash::ZERO,
            height,
            r,
            1,
            1,
            1,
            targets,
        )
        .unwrap()
        .first()
        .map(|c| c.target_node),
        Path::Legacy => unreachable!(),
    }
}

/// The challenge heights 100, 200, ... 6400.
fn challenge_heights() -> impl Iterator<Item = u64> {
    (1..=64u64).map(|n| n * CHALLENGE_INTERVAL_BLOCKS)
}

/// The first challenge height whose seed draws `who` from every assigned,
/// Active archive (the rule without the gate).
fn first_height_drawing(w: &World, path: Path, who: Address) -> u64 {
    challenge_heights()
        .find(|h| probe(w, path, *h, PorTargets::AssignedActive) == Some(who))
        .expect("some challenge height draws this archive")
}

// ── The gate's wiring ────────────────────────────────────────────────────────

#[test]
fn the_attested_target_gate_is_dormant_by_default() {
    let p = ChainParams::default();
    assert_eq!(p.por_attested_targets_enabled_from_height, None);
    for h in [0, 1, H, u64::MAX] {
        assert_eq!(por_targets(&p, h), PorTargets::AssignedActive, "height {h}");
    }
}

#[test]
fn the_gate_applies_from_its_height_on() {
    let p = ChainParams {
        por_attested_targets_enabled_from_height: Some(500),
        ..Default::default()
    };
    assert_eq!(por_targets(&p, 499), PorTargets::AssignedActive);
    assert_eq!(
        por_targets(&p, 500),
        PorTargets::AttestedOnly
    );
    assert_eq!(
        por_targets(&p, 501),
        PorTargets::AttestedOnly
    );
}

// ── An assigned archive that never attested the chunk ────────────────────────

/// Without the gate (unchanged behaviour): B, which never attested chunk 0, is
/// drawn as the target and, unanswered, slashed; A is untouched.
#[test]
fn without_the_gate_an_unattested_assignee_is_challenged_and_slashed() {
    for path in V2_PATHS {
        let w = one_attester_world(path, None, &format!("unattested-{path:?}"));
        let (a, b) = (w.assigned[0], w.assigned[1]);
        let height = first_height_drawing(&w, path, b);

        w.publish(height, vec![]);
        let ch = w.challenges_for(&b);
        assert_eq!(ch.len(), 1, "{path:?}: B is the challenge target");
        assert_eq!((ch[0].merkle_root, ch[0].chunk_index), (w.root, 0));

        // B never received the chunk; nothing answers.
        w.publish(height + CHALLENGE_TTL_BLOCKS, vec![]);
        assert_slashed(&w, &b);
        assert_untouched(&w, &a);
    }
}

/// From the gate on: B is never a target at any of 64 challenge heights; A,
/// which attested, is the target at every one. At the height that drew B
/// without the gate, the published block challenges A, and A's answer settles
/// it; B is never challenged or slashed.
#[test]
fn from_the_gate_an_unattested_assignee_is_never_challenged() {
    for path in V2_PATHS {
        let w = one_attester_world(path, Some(0), &format!("attested-only-{path:?}"));
        let (a, b) = (w.assigned[0], w.assigned[1]);
        let rule = PorTargets::AttestedOnly;
        for h in challenge_heights() {
            assert_eq!(probe(&w, path, h, rule), Some(a), "{path:?} at {h}");
        }
        let height = first_height_drawing(&w, path, b);

        w.publish(height, vec![]);
        assert!(
            w.challenges_for(&b).is_empty(),
            "{path:?}: B is not challenged"
        );
        let ch = w.challenges_for(&a).pop().expect("A is challenged instead");
        let rc = w.publish(height + 20, vec![answer(w.kp_of(&a), 2, &ch)]);
        assert!(
            rc[0].status.is_success(),
            "{path:?}: A's proof: {:?}",
            rc[0].status
        );
        w.publish(height + CHALLENGE_TTL_BLOCKS, vec![]);
        assert_untouched(&w, &a);
        assert_untouched(&w, &b);
    }
}

/// The boundary is the gate height itself: at the height that draws B without
/// the gate, a gate set to that height already challenges A, and a gate one
/// block later still challenges B. Read through block execution, so this also
/// pins the executor's reading of the gate.
#[test]
fn the_gate_takes_effect_exactly_at_its_height() {
    for path in V2_PATHS {
        let probe_world = one_attester_world(path, None, &format!("boundary-{path:?}"));
        let (a, b) = (probe_world.assigned[0], probe_world.assigned[1]);
        let height = first_height_drawing(&probe_world, path, b);

        let at = one_attester_world(path, Some(height), &format!("boundary-{path:?}"));
        at.publish(height, vec![]);
        assert!(
            at.challenges_for(&b).is_empty(),
            "{path:?}: gate at {height}"
        );
        assert_eq!(at.challenges_for(&a).len(), 1, "{path:?}: gate at {height}");

        let after = one_attester_world(path, Some(height + 1), &format!("boundary-{path:?}"));
        after.publish(height, vec![]);
        assert_eq!(
            after.challenges_for(&b).len(),
            1,
            "{path:?}: gate at {}",
            height + 1
        );
    }
}

/// When the only archive that attested the chunk is no longer Active, no
/// assigned archive qualifies: from the gate on the chunk is skipped (no
/// challenge at any of 64 heights, nobody slashed), as when no assigned
/// archive is Active. Without the gate, B is challenged.
#[test]
fn from_the_gate_a_chunk_without_an_active_attester_is_skipped() {
    for path in V2_PATHS {
        for gate in [None, Some(0)] {
            let w = one_attester_world(path, gate, &format!("no-attester-{path:?}-{gate:?}"));
            let (a, b) = (w.assigned[0], w.assigned[1]);
            let rc = w.publish(
                5,
                vec![set_status(&w.owner, w.owner_nonce, a, NodeStatus::Slashed)],
            );
            assert!(rc[0].status.is_success(), "A leaves: {:?}", rc[0].status);
            assert!(!w.active_archives().contains(&a));

            let targets = por_targets(&w.params, H);
            let drawn: Vec<Option<Address>> = challenge_heights()
                .map(|h| probe(&w, path, h, targets))
                .collect();
            match gate {
                Some(_) => assert!(drawn.iter().all(Option::is_none), "{path:?}: skipped"),
                None => assert!(drawn.iter().all(|t| *t == Some(b)), "{path:?}: B drawn"),
            }
            w.publish(H, vec![]);
            assert_eq!(
                w.challenges_for(&b).len(),
                usize::from(gate.is_none()),
                "{path:?} {gate:?}"
            );
            w.publish(H + CHALLENGE_TTL_BLOCKS, vec![]);
            if gate.is_some() {
                assert_untouched(&w, &b);
            } else {
                assert_slashed(&w, &b);
            }
        }
    }
}

// ── A reassignment survivor ──────────────────────────────────────────────────

/// R = 2, three archives. Both epoch-0 assignees X and Y attest chunk 0; X
/// then leaves and the owner reassigns, so the latest epoch's assignees are
/// the survivor Y, which attested in epoch 0 only, and the newcomer Z, which
/// never attested.
struct Reassigned {
    w: World,
    y: Address,
    z: Address,
}

fn reassigned(path: Path, label: &str) -> Reassigned {
    // Built here rather than through `build`: it needs the reassignment gate
    // open, and a leave and a reassignment between activation and the probes.
    let mut p = params(path, 2, None);
    p.archive_reassignment_enabled_from_height = Some(0);
    let (state, db, dir, executor) = setup_with_params(p.clone());
    let proposer = KeyPair::from_bytes([0xEE; 32]);
    let owner = KeyPair::from_bytes([0x0A; 32]);
    let archives: Vec<KeyPair> = (0..3)
        .map(|i| KeyPair::from_bytes([0x40 + i as u8; 32]))
        .collect();
    fund(&db, &owner, (DEPOSIT as u128) + 10 * FEE);
    for a in &archives {
        fund(&db, a, (STAKE as u128) + 10 * FEE);
    }
    let root = Hash::hash(label.as_bytes());
    let mut w = World {
        state,
        db,
        _dir: dir,
        executor,
        params: p,
        proposer_pk: *proposer.public_key().as_bytes(),
        archives,
        owner,
        owner_nonce: 0,
        root,
        assigned: vec![],
    };
    for rc in w.publish(
        1,
        w.archives.iter().map(|a| register_archive(a, 0)).collect(),
    ) {
        assert!(rc.status.is_success(), "register archives: {:?}", rc.status);
    }
    let rc = w.publish(
        REGISTER_HEIGHT,
        vec![register_file(&w.owner, 0, root, false, DEPOSIT)],
    );
    assert!(
        rc[0].status.is_success(),
        "register file: {:?}",
        rc[0].status
    );
    let snap0 = NodeRegistryExecutor::new(w.db.clone())
        .get_active_archive_nodes_at_height(REGISTER_HEIGHT)
        .unwrap();
    w.assigned = assigned_archives_presorted(&root, &sorted(&snap0), 0, 2);
    let (x, y) = (w.assigned[0], w.assigned[1]);
    let z = w
        .archives
        .iter()
        .map(|k| k.address())
        .find(|a| *a != x && *a != y)
        .unwrap();
    let accepts = [x, y]
        .iter()
        .map(|a| {
            sm_v2(
                w.kp_of(a),
                1,
                StorageMetadataOperationV2::AcceptAssignmentV2 {
                    merkle_root: root,
                    chunk_indices: vec![0],
                },
            )
        })
        .collect();
    for rc in w.publish(3, accepts) {
        assert!(rc.status.is_success(), "accept: {:?}", rc.status);
    }
    let rc = w.publish(
        4,
        vec![sm_v2(
            &w.owner,
            1,
            StorageMetadataOperationV2::ActivateFileV2 { merkle_root: root },
        )],
    );
    assert!(rc[0].status.is_success(), "activate: {:?}", rc[0].status);
    let rc = w.publish(5, vec![set_status(&w.owner, 2, x, NodeStatus::Slashed)]);
    assert!(rc[0].status.is_success(), "X leaves: {:?}", rc[0].status);
    let rc = w.publish(
        6,
        vec![sm_v2(
            &w.owner,
            3,
            StorageMetadataOperationV2::ReassignChunksV2 { merkle_root: root },
        )],
    );
    assert!(rc[0].status.is_success(), "reassign: {:?}", rc[0].status);
    w.owner_nonce = 4;

    let snap1 = NodeRegistryExecutor::new(w.db.clone())
        .get_active_archive_nodes_at_height(6)
        .unwrap();
    let mut latest = assigned_archives_presorted(&root, &sorted(&snap1), 0, 2);
    latest.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
    let mut expect = vec![y, z];
    expect.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
    assert_eq!(
        latest, expect,
        "the latest epoch assigns chunk 0 to Y and Z"
    );
    Reassigned { w, y, z }
}

/// The set of targets drawn over 64 challenge heights under `targets`.
fn drawn(w: &World, path: Path, targets: PorTargets) -> Vec<Option<Address>> {
    let mut v: Vec<Option<Address>> = challenge_heights()
        .map(|h| probe(w, path, h, targets))
        .collect();
    v.sort_by(|a, b| a.map(|x| *x.as_bytes()).cmp(&b.map(|x| *x.as_bytes())));
    v.dedup();
    v
}

/// Before Y re-attests in the latest epoch:
/// - every assigned Active archive (no gate): Y and Z are both drawn;
/// - from the gate on: nobody qualifies (Y attested in epoch 0 only, Z never),
///   so the chunk is skipped.
///
/// After Y re-attests in the latest epoch, the gate draws Y alone.
#[test]
fn a_reassignment_survivor_is_a_target_again_once_it_attests_in_the_latest_epoch() {
    for path in V2_PATHS {
        let Reassigned { w, y, z } = reassigned(path, &format!("survivor-{path:?}"));
        let latest = PorTargets::AttestedOnly;

        let mut both = vec![Some(y), Some(z)];
        both.sort_by(|a, b| a.map(|x| *x.as_bytes()).cmp(&b.map(|x| *x.as_bytes())));
        assert_eq!(
            drawn(&w, path, PorTargets::AssignedActive),
            both,
            "{path:?}: no gate"
        );
        assert_eq!(
            drawn(&w, path, latest),
            vec![None],
            "{path:?}: gate open, before Y re-attests"
        );

        // Y re-attests chunk 0; the accept targets the latest epoch.
        let rc = w.publish(
            7,
            vec![sm_v2(
                w.kp_of(&y),
                2,
                StorageMetadataOperationV2::AcceptAssignmentV2 {
                    merkle_root: w.root,
                    chunk_indices: vec![0],
                },
            )],
        );
        assert!(
            rc[0].status.is_success(),
            "{path:?}: Y re-attests: {:?}",
            rc[0].status
        );
        assert_eq!(
            drawn(&w, path, latest),
            vec![Some(y)],
            "{path:?}: gate open, after Y re-attests"
        );
    }
}

// ── Funded Private files: unchanged by the gate ──────────────────────────────

/// A Private V2 file with `fee_pool > 0` is challenged on both V2 paths, with or
/// without the gate (its target attested, so the gate admits it); unanswered,
/// the assignee is slashed 5%, flipped to Slashed and removed from the active
/// set. The gate restricts targets, not files.
#[test]
fn a_funded_private_file_is_challenged_with_or_without_the_gate() {
    for path in V2_PATHS {
        for gate in [None, Some(0)] {
            let w = attested_world(
                path,
                gate,
                true,
                DEPOSIT,
                &format!("private-{path:?}-{gate:?}"),
            );
            let target = w.assigned[0];

            w.publish(H, vec![]);
            let ch = w.challenges_for(&target);
            assert_eq!(
                ch.len(),
                1,
                "{path:?} {gate:?}: the Private file is challenged at height {H}"
            );
            assert_eq!(ch[0].merkle_root, w.root);
            assert_eq!(ch[0].chunk_index, 0);
            assert_eq!(ch[0].expires_at_height, H + CHALLENGE_TTL_BLOCKS);

            // No proof. Expiry is processed at the START of block H+50.
            w.publish(H + CHALLENGE_TTL_BLOCKS, vec![]);
            assert!(
                w.challenges_for(&target).is_empty(),
                "expired challenge removed"
            );
            assert_slashed(&w, &target);
        }
    }
}

/// The chain ignores visibility: the Private file is in the funded+Active V2
/// candidate set.
#[test]
fn a_funded_private_file_is_a_challenge_candidate() {
    let w = attested_world(Path::Targeting, None, true, DEPOSIT, "private-candidate");
    let cands = StorageMetadataExecutor::new(w.db.clone())
        .funded_active_v2_candidates()
        .unwrap();
    assert_eq!(
        cands,
        vec![(w.root, 1)],
        "Private + funded + Active ⇒ challengeable"
    );
}

/// `fee_pool == 0` (the SNIP default `--fee-deposit 0`) ⇒ not challengeable on
/// either V2 path, so no challenge and no slash.
#[test]
fn a_private_file_without_a_deposit_is_never_challenged() {
    for path in V2_PATHS {
        let w = attested_world(path, None, true, 0, &format!("private-zero-{path:?}"));
        let target = w.assigned[0];
        assert!(StorageMetadataExecutor::new(w.db.clone())
            .funded_active_v2_candidates()
            .unwrap()
            .is_empty());
        w.publish(H, vec![]);
        assert!(
            w.all_challenges().is_empty(),
            "{path:?}: zero deposit ⇒ no challenge"
        );
        w.publish(H + CHALLENGE_TTL_BLOCKS, vec![]);
        assert_untouched(&w, &target);
    }
}

/// Both assignment-aware gates closed (the legacy path, the production
/// default) ⇒ V2 files are never challenged, with or without the attested-
/// target gate. With no V1 funded file there is no challenge at all.
#[test]
fn the_legacy_path_never_challenges_a_funded_v2_file() {
    for gate in [None, Some(0)] {
        let w = attested_world(
            Path::Legacy,
            gate,
            true,
            DEPOSIT,
            &format!("legacy-{gate:?}"),
        );
        let target = w.assigned[0];
        w.publish(H, vec![]);
        assert!(
            w.all_challenges().is_empty(),
            "legacy path reads V1 funded rows only"
        );
        w.publish(H + CHALLENGE_TTL_BLOCKS, vec![]);
        assert_untouched(&w, &target);
    }
}

/// The chain itself verifies a proof for a Private file: a target that answers
/// before expiry is paid from the pool and not slashed. So the slash above is
/// caused by the missing answer, not by chain verification.
#[test]
fn an_answered_private_challenge_settles_without_a_slash() {
    for path in V2_PATHS {
        let w = attested_world(
            path,
            None,
            true,
            DEPOSIT,
            &format!("private-answered-{path:?}"),
        );
        let target = w.assigned[0];
        w.publish(H, vec![]);
        let ch = w.challenges_for(&target).pop().expect("challenge");
        let rc = w.publish(H + 20, vec![answer(w.kp_of(&target), 2, &ch)]);
        assert!(
            rc[0].status.is_success(),
            "{path:?}: proof accepted: {:?}",
            rc[0].status
        );
        w.publish(H + CHALLENGE_TTL_BLOCKS, vec![]);
        assert_untouched(&w, &target);
        let row = StorageMetadataExecutor::new(w.db.clone())
            .get_metadata_v2(&w.root)
            .unwrap()
            .unwrap();
        assert_eq!(
            row.fee_pool,
            DEPOSIT.saturating_sub(CHALLENGE_REWARD),
            "paid min(pool, reward)"
        );
    }
}
