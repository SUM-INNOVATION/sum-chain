//! The BR1 beacon read RPCs (#127) report what committed beacon state holds,
//! and nothing else.
//!
//! Blocks are executed and published through the real path (`execute_block`
//! -> `accept_produced` -> `publish`) into the database the server reads. The
//! beacon gate is opened in test-local `ChainParams` only: genesis validation
//! refuses it on every network, which is why a chain with the production gate
//! answers `null` to every one of these reads.

use std::collections::{BTreeSet, HashMap};
use std::sync::Arc;

use sumchain_beacon_crypto::{
    aggregate_g1, ecies_seal, eval_share_le, verify, EciesContext, PublicKey, SecretScalar,
    SCALAR_SIZE,
};
use sumchain_beacon_runtime::wire::{beacon_output, genesis_seed, round_message, ChainInput};
use sumchain_consensus::PoAEngine;
use sumchain_crypto::{sign, KeyPair};
use sumchain_genesis::{BeaconParamsConfig, ChainParams, Genesis};
use sumchain_primitives::beacon_schedule::BeaconSchedule;
use sumchain_primitives::beacon_wire::{
    BeaconFinalizeV1, BeaconOperation, DkgDealV1, RegisterBeaconKeyV1,
};
use sumchain_primitives::{
    BeaconTxData, Block, BlockHeader, Hash, Receipt, SignedTransaction, TransactionV2, TxPayload,
};
use sumchain_rpc::api::SumChainApiServer;
use sumchain_rpc::server::RpcServer;
use sumchain_rpc::types::{BeaconMembershipSnapshotInfo, BeaconOutputInfo, BeaconSignedRecordInfo};
use sumchain_state::beacon_store::{deal_row_key, membership_row_key, round_row_key, BeaconStore};
use sumchain_state::executor::BlockExecutor;
use sumchain_state::{Mempool, MempoolConfig, StateManager};
use sumchain_storage::schema::AccountState;
use sumchain_storage::{cf, Database, StateStore};
use tempfile::TempDir;
use tokio::sync::mpsc;

const CHAIN_ID: u64 = 1;
const EPOCH: u64 = 0;

/// Test-local: genesis validation refuses an open beacon gate on any network.
/// Key window 1..=101, deal window 201..=301, signing from 502.
fn gate_open() -> ChainParams {
    ChainParams {
        beacon_enabled_from_height: Some(0),
        beacon_params: Some(BeaconParamsConfig {
            f: 1,
            c: 1,
            t: 2,
            q_dkg: 3,
            n: 5,
        }),
        beacon_schedule: Some(BeaconSchedule {
            start_height: 1,
            epoch_length: 1000,
            key_cutoff_offset: 100,
            deal_start_offset: 200,
            deal_cutoff_offset: 300,
            complaint_start_offset: 400,
            complaint_deadline_offset: 500,
        }),
        ..ChainParams::with_v2_enabled()
    }
}

fn hex0x(bytes: &[u8]) -> String {
    format!("0x{}", hex::encode(bytes))
}

/// A canonical scalar (top byte zero) derived from a label.
fn secret(label: &[u8]) -> [u8; SCALAR_SIZE] {
    let mut out = *blake3::hash(&[b"sumchain-beacon-rpc-test:", label].concat()).as_bytes();
    out[SCALAR_SIZE - 1] = 0;
    out
}

fn scalar(label: &[u8]) -> SecretScalar {
    SecretScalar::from_bytes_le(&secret(label)).unwrap()
}

/// A node: the executor that writes beacon rows and the server that reads them,
/// over one database.
struct Chain {
    _dir: TempDir,
    db: Arc<Database>,
    state: Arc<StateManager>,
    executor: BlockExecutor,
    server: RpcServer,
    keys: Vec<KeyPair>,
    pubs: Vec<[u8; 32]>,
    fee: u128,
}

impl Chain {
    fn new(params: ChainParams) -> Self {
        let dir = TempDir::new().unwrap();
        let db = Arc::new(Database::open_default(dir.path()).unwrap());
        let state = Arc::new(StateManager::new(db.clone(), CHAIN_ID));
        let keys: Vec<KeyPair> = (0..5u8)
            .map(|i| KeyPair::from_bytes([0x40 + i; 32]))
            .collect();
        let pubs: Vec<[u8; 32]> = keys.iter().map(|k| *k.public_key().as_bytes()).collect();

        // The server's engine runs the production default. Only the executor
        // that writes the rows needs the test-local gate.
        let mempool = Arc::new(Mempool::new(MempoolConfig::default()));
        let genesis = Genesis::new(
            CHAIN_ID,
            0,
            vec![keys[0].public_key().to_base58()],
            HashMap::from([(keys[0].address().to_base58(), 1u128)]),
            ChainParams::default(),
        );
        let engine = Arc::new(
            PoAEngine::new(
                db.clone(),
                state.clone(),
                mempool.clone(),
                &genesis,
                Some(KeyPair::from_bytes([0x40; 32])),
            )
            .unwrap(),
        );
        let (tx_sender, _rx) = mpsc::channel(8);
        let server = RpcServer::new(
            db.clone(),
            state.clone(),
            mempool,
            engine,
            tx_sender,
            Arc::new(|| 0usize),
        );

        for k in &keys {
            StateStore::new(&db)
                .put_account(
                    &k.address(),
                    &AccountState {
                        balance: params.min_fee + 1_000_000,
                        nonce: 0,
                    },
                )
                .unwrap();
        }
        let fee = params.min_fee;
        let executor = BlockExecutor::new(state.clone(), db.clone(), params);
        Chain {
            _dir: dir,
            db,
            state,
            executor,
            server,
            keys,
            pubs,
            fee,
        }
    }

    /// Execute and publish one block at `height`.
    fn publish(&self, height: u64, txs: Vec<SignedTransaction>) -> Vec<Receipt> {
        let header = BlockHeader::new(
            Hash::ZERO,
            height,
            1000,
            Hash::ZERO,
            Hash::ZERO,
            self.pubs[0],
        );
        let mut block = Block::new(header, txs);
        let exec = self
            .executor
            .execute_block(&block, self.state.state_root(), &self.pubs)
            .expect("execute_block");
        block.header.state_root = exec.computed_root();
        let (executed, _state_diff, _contract_diff) = exec.into_parts();
        let receipts = executed.receipts().to_vec();
        let accepted = executed.accept_produced(&block).expect("accept_produced");
        let accumulator = accepted.accumulator();
        accepted.publish().expect("publish");
        self.state.set_state_root(accumulator);
        receipts
    }

    fn tx(&self, signer: usize, payload: TxPayload) -> SignedTransaction {
        let k = &self.keys[signer];
        let tx = TransactionV2 {
            chain_id: CHAIN_ID,
            from: k.address(),
            fee: self.fee,
            nonce: 0,
            payload,
        };
        let sig = sign(tx.signing_hash().as_bytes(), k.private_key());
        SignedTransaction::new_v2(tx, *sig.as_bytes(), *k.public_key().as_bytes())
    }

    fn setup_tx(&self, signer: usize, op: BeaconOperation) -> SignedTransaction {
        self.tx(
            signer,
            TxPayload::BeaconSetup(BeaconTxData::from_operation(&op).unwrap()),
        )
    }

    fn signing_tx(&self, signer: usize, op: BeaconOperation) -> SignedTransaction {
        self.tx(
            signer,
            TxPayload::BeaconSigning(BeaconTxData::from_operation(&op).unwrap()),
        )
    }
}

fn registration(j: u8) -> RegisterBeaconKeyV1 {
    let ek = scalar(&[b'e', j]);
    RegisterBeaconKeyV1 {
        chain_id: CHAIN_ID,
        epoch: EPOCH,
        ek_j: ek.public_g1().to_compressed(),
        pop: ek.pop_prove().to_compressed(),
    }
}

/// Dealer `i`'s polynomial coefficients `[a_0, a_1]`.
fn coeffs(i: u8) -> [[u8; SCALAR_SIZE]; 2] {
    [secret(&[b'a', i, 0]), secret(&[b'a', i, 1])]
}

/// Dealer `i`'s honest deal to recipient 0.
fn deal_to_zero(i: u8) -> DkgDealV1 {
    let c = coeffs(i);
    let ek_0 = scalar(&[b'e', 0]).public_g1();
    let r = scalar(&[b'r', i]);
    let ctx = EciesContext {
        chain_id: CHAIN_ID,
        epoch: EPOCH,
        dealer_i: u32::from(i),
        recipient_j: 0,
        r_ij: r.public_g1(),
        ek_j: ek_0,
    };
    let share = *eval_share_le(&c, 1).unwrap();
    DkgDealV1 {
        chain_id: CHAIN_ID,
        epoch: EPOCH,
        dealer_i: u32::from(i),
        recipient_j: 0,
        commitments: c
            .iter()
            .map(|a| {
                SecretScalar::from_bytes_le(a)
                    .unwrap()
                    .public_g1()
                    .to_compressed()
            })
            .collect(),
        r_ij: r.public_g1().to_compressed(),
        ct_ij: ecies_seal(&r.ecdh(&ek_0).unwrap(), &ctx, &share).unwrap(),
    }
}

fn keys_of(value: serde_json::Value) -> BTreeSet<String> {
    value.as_object().unwrap().keys().cloned().collect()
}

fn set(names: &[&str]) -> BTreeSet<String> {
    names.iter().map(|s| s.to_string()).collect()
}

#[tokio::test]
async fn with_the_production_gate_every_beacon_read_is_null() {
    // The gate genesis validation enforces on every network: unset. A
    // well-formed registration with a valid proof of possession fails closed
    // and writes nothing, so there is nothing to read.
    let chain = Chain::new(ChainParams::with_v2_enabled());
    let reg = chain.setup_tx(0, BeaconOperation::RegisterBeaconKey(registration(0)));
    let receipts = chain.publish(1, vec![reg]);
    assert!(!receipts[0].is_success(), "the dormant gate refuses the op");

    for epoch in [0, 1, u64::MAX] {
        assert_eq!(
            chain.server.beacon_get_output(epoch, 0).await.unwrap(),
            None
        );
        assert_eq!(
            chain
                .server
                .beacon_get_membership_snapshot(epoch)
                .await
                .unwrap(),
            None,
            "no snapshot is synthesized from the validator set"
        );
        assert_eq!(chain.server.dkg_get_transcript(epoch).await.unwrap(), None);
    }
}

#[tokio::test]
async fn the_reads_report_what_executed_blocks_stored() {
    let chain = Chain::new(gate_open());
    let srv = &chain.server;

    // ── Height 1, the epoch boundary: members 0..=2 register. Members 3 and 4
    // do not, and are members all the same.
    let regs: Vec<SignedTransaction> = (0..3u8)
        .map(|j| {
            chain.setup_tx(
                j as usize,
                BeaconOperation::RegisterBeaconKey(registration(j)),
            )
        })
        .collect();
    let reg_hashes: Vec<Hash> = regs.iter().map(SignedTransaction::hash).collect();
    assert!(chain.publish(1, regs).iter().all(Receipt::is_success));

    let snapshot = srv.beacon_get_membership_snapshot(EPOCH).await.unwrap();
    assert_eq!(
        snapshot,
        Some(BeaconMembershipSnapshotInfo {
            epoch: EPOCH,
            n: 5,
            members: chain.pubs.iter().map(|p| hex0x(p)).collect(),
        }),
        "the boundary set, in membership order"
    );
    assert_eq!(
        keys_of(serde_json::to_value(snapshot.unwrap()).unwrap()),
        set(&["epoch", "n", "members"])
    );
    assert_eq!(
        srv.beacon_get_membership_snapshot(EPOCH + 1).await.unwrap(),
        None,
        "an epoch whose boundary was never published has no membership"
    );

    let t = srv
        .dkg_get_transcript(EPOCH)
        .await
        .unwrap()
        .expect("keys are held");
    assert_eq!(t.keys.len(), 3);
    for (j, key) in t.keys.iter().enumerate() {
        let reg = registration(j as u8);
        assert_eq!(key.validator_index, j as u32);
        assert_eq!(key.ek, hex0x(&reg.ek_j));
        assert_eq!(
            key.record,
            BeaconSignedRecordInfo {
                signer: hex0x(&chain.pubs[j]),
                tx_ref: hex0x(reg_hashes[j].as_bytes()),
                carrier: hex0x(&reg.try_encode().unwrap()),
            },
            "the stored record is the signed transaction that carried it"
        );
    }
    assert!(t.deals.is_empty() && t.disqualified.is_empty() && t.adjudicated.is_empty());
    assert_eq!(srv.beacon_get_output(EPOCH, 0).await.unwrap(), None);

    // ── Height 201: dealers 0..=2 deal to recipient 0.
    let deals: Vec<DkgDealV1> = (0..3u8).map(deal_to_zero).collect();
    let deal_txs = deals
        .iter()
        .map(|d| chain.setup_tx(d.dealer_i as usize, BeaconOperation::DkgDeal(d.clone())))
        .collect();
    assert!(chain.publish(201, deal_txs).iter().all(Receipt::is_success));

    // ── Height 502: round 0 is finalized with the group signature over the
    // genesis-seeded round message the executor anchors the epoch at.
    let group_secret = (0..3u8)
        .map(|i| SecretScalar::from_bytes_le(&coeffs(i)[0]).unwrap())
        .reduce(|a, b| a.add(&b))
        .unwrap();
    let m0 = round_message(
        CHAIN_ID,
        EPOCH,
        0,
        &ChainInput::GenesisSeed(genesis_seed(CHAIN_ID, &[0u8; 32])),
    );
    let sigma0 = group_secret.sign(&m0);
    let fin = chain.signing_tx(
        0,
        BeaconOperation::BeaconFinalize(BeaconFinalizeV1 {
            chain_id: CHAIN_ID,
            epoch: EPOCH,
            round: 0,
            sigma_r: sigma0.to_compressed(),
            witness: vec![0, 1],
        }),
    );
    assert!(chain
        .publish(502, vec![fin])
        .iter()
        .all(Receipt::is_success));

    let before = BeaconStore::new(&chain.db).load_state_map().unwrap();

    let out = srv.beacon_get_output(EPOCH, 0).await.unwrap();
    assert_eq!(
        out,
        Some(BeaconOutputInfo {
            epoch: EPOCH,
            round: 0,
            output: hex0x(&beacon_output(CHAIN_ID, EPOCH, 0, &sigma0)),
            sigma_r: hex0x(&sigma0.to_compressed()),
        })
    );
    assert_eq!(
        keys_of(serde_json::to_value(out.unwrap()).unwrap()),
        set(&["epoch", "round", "output", "sigma_r"])
    );
    // The reported Σ verifies under the group key of the three dealers.
    let pk_e = PublicKey::from_g1_point(
        aggregate_g1(
            &(0..3u8)
                .map(|i| {
                    SecretScalar::from_bytes_le(&coeffs(i)[0])
                        .unwrap()
                        .public_g1()
                })
                .collect::<Vec<_>>(),
        )
        .unwrap(),
    );
    assert!(verify(&pk_e, &m0, &sigma0));
    assert_eq!(srv.beacon_get_output(EPOCH, 1).await.unwrap(), None);
    assert_eq!(srv.beacon_get_output(EPOCH + 1, 0).await.unwrap(), None);

    let t = srv.dkg_get_transcript(EPOCH).await.unwrap().unwrap();
    assert_eq!(
        keys_of(serde_json::to_value(&t).unwrap()),
        set(&[
            "epoch",
            "keys",
            "deals",
            "disqualified",
            "false_accusers",
            "adjudicated",
            "key_equivocations",
            "deal_equivocations",
        ])
    );
    assert_eq!(t.deals.len(), 3);
    for (d, info) in deals.iter().zip(&t.deals) {
        assert_eq!((info.dealer_i, info.recipient_j), (d.dealer_i, 0));
        assert_eq!(
            info.commitments,
            d.commitments.iter().map(|c| hex0x(c)).collect::<Vec<_>>()
        );
        assert_eq!(info.r_ij, hex0x(&d.r_ij));
        assert_eq!(info.ct_ij, hex0x(&d.ct_ij));
        assert_eq!(info.record.signer, hex0x(&chain.pubs[d.dealer_i as usize]));
        assert_eq!(info.record.carrier, hex0x(&d.try_encode().unwrap()));
    }
    assert!(t.disqualified.is_empty() && t.false_accusers.is_empty());
    assert!(t.key_equivocations.is_empty() && t.deal_equivocations.is_empty());

    // Reading wrote nothing.
    assert_eq!(
        BeaconStore::new(&chain.db).load_state_map().unwrap(),
        before
    );
}

#[tokio::test]
async fn a_row_the_node_cannot_decode_is_an_error_not_null() {
    // `null` claims the row is absent. A row that is present and unreadable
    // must say so instead.
    let chain = Chain::new(ChainParams::default());
    chain
        .db
        .put(cf::BEACON_STATE, &round_row_key(EPOCH, 0), b"not a round")
        .unwrap();
    chain
        .db
        .put(
            cf::BEACON_STATE,
            &membership_row_key(EPOCH),
            b"not a membership",
        )
        .unwrap();
    chain
        .db
        .put(cf::BEACON_STATE, &deal_row_key(EPOCH, 0, 0), b"not a deal")
        .unwrap();

    let srv = &chain.server;
    assert_eq!(
        srv.beacon_get_output(EPOCH, 0).await.unwrap_err().code(),
        -32603
    );
    assert_eq!(
        srv.beacon_get_membership_snapshot(EPOCH)
            .await
            .unwrap_err()
            .code(),
        -32603
    );
    assert_eq!(
        srv.dkg_get_transcript(EPOCH).await.unwrap_err().code(),
        -32603
    );
}
