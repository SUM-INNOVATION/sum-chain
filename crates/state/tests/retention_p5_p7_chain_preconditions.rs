//! TESTS OF EXISTING CHAIN CODE, WRITTEN FOR AN UNRATIFIED PROPOSAL. Nothing
//! here is ratified, no production code changes, and no value of `G` is
//! chosen anywhere in this file.
//!
//! The #129 latest-epoch proposal (`docs/proposals/129-latest-epoch/README.md`)
//! relies on three facts about today's chain. These tests pin them against the
//! real executor and the committed coverage reader, so a change to any of them
//! shows up here before the proposal is ratified:
//!
//! * **P7.** The coverage RPC's `reassignment_needed` is exactly the
//!   executor's acceptance condition for `ReassignChunksV2`. An owner tool that
//!   submits only while the flag is set never pays for a refused reassignment,
//!   and never submits a second one while the new assignees are still
//!   fetching: the flag clears in the reassignment block itself.
//! * **The flag is snapshot-wide.** It is set when any archive in the latest
//!   epoch's active snapshot leaves, whether or not that archive was assigned a
//!   chunk of the file.
//! * **P5 dormancy.** Below the PoR targeting gate (unset on mainnet) no V2
//!   file is selected for a challenge, so a readiness window would change
//!   nothing there.
//!
//! The gates are the mainnet shape: reassignment open, both PoR targeting
//! gates unset. Unbonding is opened only so that an archive leaves by its own
//! `BeginUnstake`.

mod common;
use common::{fund, setup_with_params, CHAIN_ID};

use std::sync::Arc;

use sumchain_crypto::{sign, KeyPair};
use sumchain_genesis::ChainParams;
use sumchain_primitives::{
    assigned_archives, Address, Hash, NodeRegistryOperation, NodeRegistryTxData, NodeRole,
    SignedTransaction, StorageMetadataOperationV2, StorageMetadataV2TxData, TransactionV2,
    TxPayload, TxStatus, CHALLENGE_INTERVAL_BLOCKS,
};
use sumchain_state::executor::BlockExecutor;
use sumchain_state::state::StateManager;
use sumchain_state::storage_metadata::{
    CoverageSummaryV2, StorageMetadataExecutor, CF_ACTIVE_CHALLENGES,
};
use sumchain_state::NodeRegistryExecutor;
use sumchain_storage::Database;

const STAKE: u64 = 1_000_000_000;
const FEE: u128 = 1_000;
const FEE_DEPOSIT: u64 = 1_000_000;
/// One archive per chunk, so a departure and its replacement are unambiguous.
const R: u32 = 1;

/// The mainnet gate shape, plus unbonding so an archive can leave by itself.
fn params_mainnet_shape() -> ChainParams {
    let mut p = ChainParams::with_v2_enabled();
    p.archive_reassignment_enabled_from_height = Some(0);
    p.archive_unbonding_enabled_from_height = Some(0);
    p.assignment_replication_factor = R;
    assert_eq!(p.por_assignment_targeting_enabled_from_height, None);
    assert_eq!(p.assignment_aware_por_scheduler_enabled_from_height, None);
    p
}

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

fn nr(op: NodeRegistryOperation) -> TxPayload {
    TxPayload::NodeRegistry(NodeRegistryTxData { operation: op })
}

fn sm(op: StorageMetadataOperationV2) -> TxPayload {
    TxPayload::StorageMetadataV2(StorageMetadataV2TxData { operation: op })
}

/// A published chain with one funded single-chunk V2 file, driven block by
/// block through the real executor.
struct Chain {
    state: Arc<StateManager>,
    db: Arc<Database>,
    executor: BlockExecutor,
    _dir: tempfile::TempDir,
    proposer: KeyPair,
    owner: KeyPair,
    owner_nonce: u64,
    archives: Vec<(KeyPair, u64)>,
    root: Hash,
}

impl Chain {
    /// `k` archives register at height 1, the file registers at 2 (its first
    /// epoch), its assignee attests at 3 and the owner activates it at 4.
    fn active_file(params: ChainParams, k: usize, label: &[u8]) -> Self {
        let (state, db, dir, executor) = setup_with_params(params);
        let owner = KeyPair::generate();
        fund(&db, &owner, (FEE_DEPOSIT as u128) + 2_000_000);
        let archives: Vec<(KeyPair, u64)> = (0..k).map(|_| (KeyPair::generate(), 0)).collect();
        for (a, _) in &archives {
            fund(&db, a, (STAKE as u128) + 1_000_000);
        }
        let mut ch = Chain {
            state,
            db,
            executor,
            _dir: dir,
            proposer: KeyPair::generate(),
            owner,
            owner_nonce: 0,
            archives,
            root: Hash::hash(label),
        };
        let regs: Vec<SignedTransaction> = ch
            .archives
            .iter()
            .map(|(a, _)| {
                signed(
                    a,
                    0,
                    nr(NodeRegistryOperation::Register {
                        role: NodeRole::ArchiveNode,
                        stake: STAKE,
                    }),
                )
            })
            .collect();
        ch.publish_ok(1, regs);
        for entry in &mut ch.archives {
            entry.1 = 1;
        }
        let reg = ch.owner_tx(sm(StorageMetadataOperationV2::RegisterFilePendingV2 {
            merkle_root: ch.root,
            plaintext_size_bytes: 500,
            stored_size_bytes: 1000, // one chunk
            chunk_count: 1,
            fee_deposit: FEE_DEPOSIT,
            visibility: 0,
            initial_access: vec![],
        }));
        ch.publish_ok(2, vec![reg]);
        let first = ch.assignee_under(2);
        ch.attest(3, first);
        let act = ch.owner_tx(sm(StorageMetadataOperationV2::ActivateFileV2 {
            merkle_root: ch.root,
        }));
        ch.publish_ok(4, vec![act]);
        ch
    }

    fn publish_ok(&self, h: u64, txs: Vec<SignedTransaction>) {
        let pk = *self.proposer.public_key().as_bytes();
        for r in common::publish_block(&self.state, &self.executor, h, &pk, txs, &[]) {
            assert!(r.status.is_success(), "height {h}: {:?}", r.status);
        }
    }

    fn owner_tx(&mut self, payload: TxPayload) -> SignedTransaction {
        let tx = signed(&self.owner, self.owner_nonce, payload);
        self.owner_nonce += 1;
        tx
    }

    fn archive_tx(&mut self, who: Address, payload: TxPayload) -> SignedTransaction {
        let entry = self
            .archives
            .iter_mut()
            .find(|(kp, _)| kp.address() == who)
            .expect("a registered archive");
        let tx = signed(&entry.0, entry.1, payload);
        entry.1 += 1;
        tx
    }

    fn addresses(&self) -> Vec<Address> {
        self.archives.iter().map(|(kp, _)| kp.address()).collect()
    }

    /// The archive assigned chunk 0 under the active snapshot at `epoch`.
    fn assignee_under(&self, epoch: u64) -> Address {
        let snap = NodeRegistryExecutor::new(self.db.clone())
            .get_active_archive_nodes_at_height(epoch)
            .unwrap();
        let addrs: Vec<Address> = snap.iter().map(|n| n.address).collect();
        assigned_archives(&self.root, &addrs, 0, R)[0]
    }

    fn attest(&mut self, h: u64, who: Address) {
        let tx = self.archive_tx(
            who,
            sm(StorageMetadataOperationV2::AcceptAssignmentV2 {
                merkle_root: self.root,
                chunk_indices: vec![0],
            }),
        );
        self.publish_ok(h, vec![tx]);
    }

    /// `who` leaves the active set by its own full unstake.
    fn leave(&mut self, h: u64, who: Address) {
        let tx = self.archive_tx(
            who,
            nr(NodeRegistryOperation::BeginUnstake { amount: STAKE }),
        );
        self.publish_ok(h, vec![tx]);
    }

    fn reassign(&mut self, h: u64) {
        let tx = self.owner_tx(sm(StorageMetadataOperationV2::ReassignChunksV2 {
            merkle_root: self.root,
        }));
        self.publish_ok(h, vec![tx]);
    }

    /// What the coverage RPC reports, from committed state.
    fn coverage(&self) -> CoverageSummaryV2 {
        StorageMetadataExecutor::new(self.db.clone())
            .compute_coverage_v2(&self.root, &NodeRegistryExecutor::new(self.db.clone()), R)
            .unwrap()
            .expect("file exists")
    }

    /// The executor's verdict on the owner's next `ReassignChunksV2` at `h`, in
    /// a candidate that is then dropped: nothing is published.
    fn probe_reassign(&self, h: u64) -> TxStatus {
        let mut candidate = common::candidate(&self.db);
        let tx = signed(
            &self.owner,
            self.owner_nonce,
            sm(StorageMetadataOperationV2::ReassignChunksV2 {
                merkle_root: self.root,
            }),
        );
        self.executor
            .execute_tx(
                &mut candidate.view(),
                &tx,
                &self.proposer.address(),
                h,
                1000,
            )
            .unwrap()
            .status
    }

    /// The flag the owner tool reads and the executor's verdict agree.
    fn assert_flag_matches_executor(&self, h: u64, expected: bool) {
        let flag = self.coverage().reassignment_needed;
        assert_eq!(flag, expected, "height {h}: reassignment_needed");
        let status = self.probe_reassign(h);
        if flag {
            assert!(
                status.is_success(),
                "height {h}: flag set but executor refused: {status:?}"
            );
        } else {
            assert!(
                matches!(status, TxStatus::Failed(334)),
                "height {h}: flag clear but executor gave {status:?}"
            );
        }
    }
}

#[test]
fn p7_the_coverage_flag_is_exactly_the_executors_acceptance_condition() {
    let mut ch = Chain::active_file(params_mainnet_shape(), 3, b"p7-flag-equals-acceptance");
    ch.assert_flag_matches_executor(5, false);

    // The file's assignee leaves.
    let first = ch.assignee_under(2);
    ch.leave(5, first);
    ch.assert_flag_matches_executor(6, true);
    ch.reassign(6);

    // Straight after the reassignment, before the new assignee has fetched or
    // attested anything, the flag is already clear and the executor refuses a
    // second reassignment: an owner tool gated on the flag cannot double-submit.
    let second = ch.assignee_under(6);
    assert_ne!(second, first);
    let cov = ch.coverage();
    assert_eq!(cov.assignment_epochs, vec![2, 6]);
    assert_eq!(
        cov.per_epoch.last().unwrap().covered_count,
        0,
        "the new assignee has not attested"
    );
    ch.assert_flag_matches_executor(7, false);

    ch.attest(7, second);
    assert_eq!(ch.coverage().per_epoch.last().unwrap().covered_count, 1);
    ch.assert_flag_matches_executor(8, false);

    // Coverage drops again: the replacement leaves too. The flag returns, and
    // clears with the next reassignment.
    ch.leave(8, second);
    ch.assert_flag_matches_executor(9, true);
    ch.reassign(9);
    ch.assert_flag_matches_executor(10, false);
    assert_eq!(ch.coverage().assignment_epochs, vec![2, 6, 9]);
}

#[test]
fn p7_the_flag_is_set_by_any_snapshot_departure_not_only_the_files_assignees() {
    let mut ch = Chain::active_file(params_mainnet_shape(), 2, b"p7-snapshot-wide");
    let assignee = ch.assignee_under(2);
    let bystander = *ch.addresses().iter().find(|a| **a != assignee).unwrap();
    assert_eq!(
        assigned_archives(&ch.root, &ch.addresses(), 0, R),
        vec![assignee],
        "the bystander holds no chunk of this file"
    );
    ch.assert_flag_matches_executor(5, false);

    // An archive assigned nothing of this file leaves. The file's coverage is
    // complete, yet the flag is set and the executor accepts a reassignment.
    ch.leave(5, bystander);
    let cov = ch.coverage();
    assert_eq!(cov.covered_count, 1);
    ch.assert_flag_matches_executor(6, true);
    ch.reassign(6);

    // The assignment is unchanged ...
    assert_eq!(ch.assignee_under(6), assignee);
    let cov = ch.coverage();
    // ... and today's aggregate still counts the first epoch's attestation ...
    assert_eq!(cov.covered_count, 1);
    // ... but the new latest epoch holds no attestation until the same archive
    // attests again. A latest-epoch count (the proposal's L) reads 0 here for
    // a file whose assignee never left.
    assert_eq!(cov.per_epoch.last().unwrap().covered_count, 0);
    ch.attest(7, assignee);
    assert_eq!(ch.coverage().per_epoch.last().unwrap().covered_count, 1);
    ch.assert_flag_matches_executor(8, false);
}

#[test]
fn p5_below_the_targeting_gate_no_v2_file_is_challenged() {
    for gate_open in [false, true] {
        let mut params = params_mainnet_shape();
        if gate_open {
            params.por_assignment_targeting_enabled_from_height = Some(0);
        }
        // The exact situation P5 is about: a reassignment newly assigns the
        // chunk to an archive that has not attested (or fetched) it.
        let mut ch = Chain::active_file(params, 2, b"p5-dormant-below-gate");
        let first = ch.assignee_under(2);
        ch.leave(5, first);
        ch.reassign(6);
        let newly_assigned = ch.assignee_under(6);
        assert_ne!(newly_assigned, first);
        assert_eq!(ch.coverage().per_epoch.last().unwrap().covered_count, 0);

        // Through the executor's own gate: one challenge interval.
        let pk = *ch.proposer.public_key().as_bytes();
        common::publish_empty_block(&ch.state, &ch.executor, CHALLENGE_INTERVAL_BLOCKS, &pk);
        let rows = ch.db.iter(CF_ACTIVE_CHALLENGES).unwrap().count();

        // And the selection itself, over many seeds, each in a fresh candidate,
        // with the flag the executor derives from the gate.
        let picks: Vec<Option<Address>> = (0u8..32)
            .map(|i| {
                let mut candidate = common::candidate(&ch.db);
                let active =
                    NodeRegistryExecutor::v_get_active_archive_nodes(&candidate.view()).unwrap();
                StorageMetadataExecutor::generate_challenge(
                    &mut candidate.view(),
                    &Hash::hash(&[b'p', i]),
                    2 * CHALLENGE_INTERVAL_BLOCKS,
                    &active,
                    gate_open,
                    R,
                )
                .unwrap()
                .map(|c| c.target_node)
            })
            .collect();

        if gate_open {
            // Today (G = 0) the unattested newcomer is the target at once.
            assert!(rows > 0, "gate open: a challenge is issued");
            assert!(
                picks.iter().all(|p| *p == Some(newly_assigned)),
                "gate open: {picks:?}"
            );
        } else {
            // Mainnet shape: nothing for a readiness window to change.
            assert_eq!(rows, 0, "gate closed: no challenge for a V2 file");
            assert!(picks.iter().all(Option::is_none), "gate closed: {picks:?}");
        }
    }
}
