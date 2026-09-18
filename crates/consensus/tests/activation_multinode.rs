//! An activation height is a COORDINATION device. These are the two situations
//! it exists for, driven across several real validators on real databases.
//!
//! Everything else in this lane proves an activation height on one node, or
//! below the engine, or pairwise. An activation height that only ever meets one
//! node has not been asked the question it exists to answer: do several nodes
//! that agree about it stay together, and does a node that disagrees about it
//! get found out.
//!
//! # Which gate, and why not the journal one
//!
//! The obvious candidate is `application_journal_enabled_from_height`, and it is
//! the wrong one for this file. The journal is NODE-LOCAL — never hashed into a
//! block, never folded into a root, never transmitted — so two nodes holding
//! different journal boundaries CANNOT fork, and "the roots agree across the
//! boundary" would be true on a node that did nothing at all. That gate's
//! multi-validator behaviour is the refusal it causes at a reorg, and that is
//! already proven in `checkpoint_multi_validator.rs`.
//!
//! The gate here is `healthcare_authorization_enabled_from_height`, and it is
//! consensus-relevant for a reason worth stating plainly, because it is not the
//! reason the account-root gate is:
//!
//! > `compute_block_state_root` folds every receipt's SUCCESS BIT and FEE PAID.
//! > A gate that changes which transactions succeed therefore changes the block
//! > state root at the height it opens, whether or not it touches any digest the
//! > root folds explicitly.
//!
//! Below the gate `FillPrescription` checks nothing about the sender, so a
//! stranger fills anyone's prescription and the receipt is `Success` with the
//! fee paid. At and above it the same transaction is refused and the receipt is
//! `Failed(14)` with zero paid. That is a different byte in the root's preimage,
//! produced by a gate, on a live chain — which makes "every node agrees at every
//! height" a claim with something to lose.
//!
//! # What is here
//!
//! * `three_validators_crossing_one_activation_height_agree_at_every_height` —
//!   scenario 1. Three validators, one shared height, blocks below and above it,
//!   the chain continuing across. Roots and block hashes compared at EVERY
//!   height on EVERY node, not at the tip.
//! * `a_validator_with_a_different_activation_height_forks_silently_below_the_legacy_window`
//!   — scenario 2, and the answer is not the comfortable one. The odd node does
//!   not refuse to start, does not refuse the block, and does compute a
//!   different root — which at these heights is ABSORBED by
//!   `LEGACY_ROOT_COMPATIBILITY_HEIGHT`, leaving two nodes agreeing on the
//!   accumulator and disagreeing about what it commits to.
//! * `above_the_legacy_window_the_same_disagreement_is_refused` — the same
//!   misconfiguration one height above the window, at the acceptance seam, where
//!   it is named and refused.

use std::collections::HashMap;
use std::sync::Arc;

use sumchain_consensus::{ConsensusEngine, PoAEngine};
use sumchain_crypto::{sign, KeyPair};
use sumchain_genesis::{ChainParams, Genesis};
use sumchain_primitives::agreement::PartyRef;
use sumchain_primitives::healthcare::{
    HealthcareIssuerClass, HealthcareOperation, HealthcareTxData, Prescription, PrescriptionStatus,
    PrescriptionType, ProviderProfile, ProviderStatus, ProviderType,
};
use sumchain_primitives::{
    Address, Block, Hash, SignedTransaction, TransactionV2, TxPayload, TxStatus,
};
use sumchain_state::{Mempool, MempoolConfig, StateManager};
use sumchain_storage::{Database, ReceiptStore};
use tempfile::TempDir;

const CHAIN_ID: u64 = 1;
const VALIDATORS: usize = 3;

/// The height at and above which the SRC-87X authorization rules bind.
///
/// Heights 1 and 2 are setup (register a provider, issue a prescription), so the
/// first gated transaction is at height 3 and there are three blocks below the
/// boundary and three at or above it.
const AUTH_BOUNDARY: u64 = 6;

/// How many stranger-fill blocks follow the two setup blocks.
const FILL_BLOCKS: u64 = 6;

const PROVIDER_ID: [u8; 32] = [0x68; 32];
const PRESCRIPTION_ID: [u8; 32] = [0x69; 32];
const FEE: u128 = 100;

/// The healthcare arm's failure status, on both dispatch surfaces.
const HEALTHCARE_FAILED: TxStatus = TxStatus::Failed(14);

// ─────────────────────────────────────────────────────────────────────────────
// Fixture
// ─────────────────────────────────────────────────────────────────────────────

/// One validator's node: its own directory, its own database, its own
/// `ChainParams` — which is what makes "one validator configured differently"
/// expressible in a single test process.
struct Node {
    _dir: TempDir,
    db: Arc<Database>,
    state: Arc<StateManager>,
    mempool: Arc<Mempool>,
    consensus: Arc<PoAEngine>,
    pubkey: [u8; 32],
    label: String,
}

impl Node {
    fn new(genesis: &Genesis, secret: [u8; 32], label: &str) -> Self {
        let key = KeyPair::from_bytes(secret);
        let pubkey = *key.public_key().as_bytes();
        let dir = TempDir::new().expect("temp dir");
        let db = Arc::new(Database::open_default(dir.path()).expect("open database"));
        let state = Arc::new(StateManager::new(db.clone(), CHAIN_ID));
        let mempool = Arc::new(Mempool::new(MempoolConfig::default()));
        let consensus = Arc::new(
            PoAEngine::new(
                db.clone(),
                state.clone(),
                mempool.clone(),
                genesis,
                Some(key),
            )
            .expect("engine"),
        );
        consensus.init_genesis(genesis).expect("init genesis");
        Self {
            _dir: dir,
            db,
            state,
            mempool,
            consensus,
            pubkey,
            label: label.to_string(),
        }
    }

    fn height(&self) -> u64 {
        self.consensus.current_height()
    }

    fn receipt_status(&self, tx: &SignedTransaction) -> Option<TxStatus> {
        ReceiptStore::new(&self.db)
            .get(&tx.hash())
            .expect("read receipts")
            .map(|r| r.status)
    }

    fn receipt_fee(&self, tx: &SignedTransaction) -> Option<u128> {
        ReceiptStore::new(&self.db)
            .get(&tx.hash())
            .expect("read receipts")
            .map(|r| r.fee_paid)
    }

    fn balance(&self, who: &Address) -> u128 {
        self.state.get_balance(who).unwrap_or(0)
    }
}

/// A set of validators that all import each other's blocks, so every one of them
/// holds the same chain. `create_block` refuses unless `is_proposer(height)` and
/// the proposer rotates `validators[height % N]`, so each block really is
/// produced by the validator whose turn it is.
struct World {
    nodes: Vec<Node>,
    chain: Vec<Block>,
}

impl World {
    fn new(genesis: &Genesis, secrets: &[[u8; 32]]) -> Self {
        Self {
            nodes: secrets
                .iter()
                .enumerate()
                .map(|(i, s)| Node::new(genesis, *s, &format!("v{i}")))
                .collect(),
            chain: Vec::new(),
        }
    }

    fn proposer_index(&self, height: u64) -> usize {
        let expected = self.nodes[0].consensus.get_proposer(height);
        self.nodes
            .iter()
            .position(|n| n.pubkey == expected)
            .expect("the proposer must be one of this world's validators")
    }

    /// Produce the next block at its rightful proposer and import it everywhere
    /// else, including any `followers` that are not part of the validator set's
    /// rotation (a node configured differently, say).
    async fn advance(&mut self, tx: SignedTransaction, followers: &[&Node]) -> Block {
        let height = self.nodes[0].height() + 1;
        let idx = self.proposer_index(height);
        self.nodes[idx].mempool.add(tx).expect("mempool accepts");
        let txs = self.nodes[idx].mempool.select_for_block(100);
        assert_eq!(txs.len(), 1, "this fixture produces one-transaction blocks");
        let block = self.nodes[idx]
            .consensus
            .propose_block(txs)
            .await
            .expect("the rightful proposer produces");
        assert_eq!(block.height(), height);
        for (i, node) in self.nodes.iter().enumerate() {
            if i != idx {
                node.consensus
                    .import_block(block.clone())
                    .await
                    .unwrap_or_else(|e| {
                        panic!("validator {i} must accept an honest extension: {e}")
                    });
            }
        }
        for node in followers {
            node.consensus
                .import_block(block.clone())
                .await
                .unwrap_or_else(|e| panic!("follower {} must accept: {e}", node.label));
        }
        self.chain.push(block.clone());
        block
    }

    /// Every node holds the SAME block at EVERY height, and the same state root.
    ///
    /// The per-height walk is the point: comparing tips alone would pass on two
    /// nodes that diverged in the middle and reconverged, which is precisely
    /// what a mis-set activation height can look like from the outside.
    fn assert_agreement(&self, extra: &[&Node]) {
        let all: Vec<&Node> = self.nodes.iter().chain(extra.iter().copied()).collect();
        let head = self.chain.last().expect("non-empty chain").height();
        for node in &all {
            assert_eq!(
                node.height(),
                head,
                "{} is at height {} and the chain is at {head}",
                node.label,
                node.height()
            );
        }
        for h in 0..=head {
            let reference = all[0]
                .consensus
                .get_block_by_height(h)
                .unwrap_or_else(|| panic!("{} has no block at height {h}", all[0].label));
            for node in &all[1..] {
                let theirs = node
                    .consensus
                    .get_block_by_height(h)
                    .unwrap_or_else(|| panic!("{} has no block at height {h}", node.label));
                assert_eq!(
                    theirs.hash(),
                    reference.hash(),
                    "{} and {} disagree about the canonical block at height {h}",
                    node.label,
                    all[0].label
                );
                assert_eq!(
                    theirs.header.state_root, reference.header.state_root,
                    "{} and {} disagree about the state root at height {h}",
                    node.label, all[0].label
                );
            }
        }
        // And the live accumulator each node is carrying forward, which is what
        // the NEXT block will be built on.
        for node in &all[1..] {
            assert_eq!(
                node.state.state_root(),
                all[0].state.state_root(),
                "{} and {} carry different state-root accumulators",
                node.label,
                all[0].label
            );
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Transactions
// ─────────────────────────────────────────────────────────────────────────────

fn healthcare_tx(
    kp: &KeyPair,
    nonce: u64,
    op: HealthcareOperation,
    payload: &impl serde::Serialize,
) -> SignedTransaction {
    let t = TransactionV2 {
        chain_id: CHAIN_ID,
        from: kp.address(),
        fee: FEE,
        nonce,
        payload: TxPayload::Healthcare(HealthcareTxData {
            operation: op,
            data: bincode::serialize(payload).expect("serialize payload"),
            recipient: Address::ZERO,
        }),
    };
    let sig = sign(t.signing_hash().as_bytes(), kp.private_key());
    SignedTransaction::new_v2(t, *sig.as_bytes(), *kp.public_key().as_bytes())
}

fn provider_profile(issuer: Address) -> ProviderProfile {
    ProviderProfile {
        provider_id: PROVIDER_ID,
        provider_commitment: [0x69; 32],
        provider_type: ProviderType::Hospital,
        jurisdiction_code: "US-CA".to_string(),
        public_reference: None,
        specialties_commitment: None,
        credentials_commitment: None,
        policy_id: [12u8; 32],
        issuer_class: HealthcareIssuerClass::GovernmentHealthAgency,
        issuer_address: issuer,
        status: ProviderStatus::Active,
        created_at: 1_000,
        updated_at: 1_000,
        registered_at_height: 1,
        network_affiliations: vec![],
        attachments: vec![],
    }
}

/// A prescription with plenty of refills and an expiry far in the future, so
/// nothing but the AUTHORIZATION gate can decide whether a fill succeeds.
///
/// `expiry` matters more than it looks. `Prescription::is_valid` runs BEFORE the
/// authorization check and is evaluated at the EFFECTIVE block timestamp, which
/// is a literal zero while `subsystem_block_timestamp_enabled_from_height` is
/// dormant — the configuration used here. `0 >= expiry` is false for any
/// positive expiry, so validity is constant across the whole chain and the only
/// thing that changes at `AUTH_BOUNDARY` is the sender check.
fn prescription(issuer: Address, patient: Address) -> Prescription {
    Prescription {
        prescription_id: PRESCRIPTION_ID,
        patient_address: patient,
        prescription_type: PrescriptionType::StandardPrescription,
        prescription_commitment: [0x6A; 32],
        patient_ref: PartyRef::Commitment([0x6B; 32]),
        patient_nullifier: [0x6C; 32],
        prescriber_ref: PartyRef::Commitment([0x6D; 32]),
        prescriber_provider_id: PROVIDER_ID,
        pharmacy_ref: None,
        medication_commitment: [0x6E; 32],
        quantity_commitment: [0x6F; 32],
        days_supply_commitment: None,
        refills_authorized: 200,
        refills_remaining: 200,
        is_controlled: false,
        date_written: 900,
        effective_from: None,
        expiry: 9_000_000,
        issuer_address: issuer,
        issuer_class: HealthcareIssuerClass::MedicalPractice,
        policy_id: [12u8; 32],
        revocation_ref: None,
        status: PrescriptionStatus::Active,
        created_at: 900,
        updated_at: 900,
        recorded_at_height: 1,
        supersedes: None,
        fill_history: vec![],
        attachments: vec![],
    }
}

/// A fill by someone who is neither the patient, nor the issuer, nor the
/// prescriber provider's issuer. Below the gate this succeeds; at and above it,
/// it is refused.
///
/// A FRESH sender each time, and the reason is mechanical rather than cosmetic:
/// a refused healthcare transaction does not increment the sender's nonce, and
/// the executor requires `tx.nonce == account nonce` exactly. Reusing one
/// stranger would mean re-sending a byte-identical transaction after the first
/// refusal, which the block store would reject as already present.
fn stranger_fill(stranger: &KeyPair, n: u64) -> SignedTransaction {
    #[derive(serde::Serialize)]
    struct Fill {
        prescription_id: [u8; 32],
        fill_commitment: [u8; 32],
    }
    healthcare_tx(
        stranger,
        0,
        HealthcareOperation::FillPrescription,
        &Fill {
            prescription_id: PRESCRIPTION_ID,
            fill_commitment: [n as u8; 32],
        },
    )
}

// ─────────────────────────────────────────────────────────────────────────────
// Genesis
// ─────────────────────────────────────────────────────────────────────────────

/// Genesis as a DOCUMENT, through the authoritative loader, with the gate in the
/// JSON. A height that only exists in Rust is not a deployment surface.
fn genesis_with_auth_gate(
    validators: &[KeyPair],
    funded: &[&KeyPair],
    auth_from: Option<u64>,
) -> Genesis {
    let mut params = ChainParams::with_v2_enabled();
    params.healthcare_authorization_enabled_from_height = auth_from;
    // Finality is put out of reach so that nothing in this file is measuring
    // finality's refusal by accident. Nothing here reorgs, but the fixture is
    // shared with the mixed-version test, which imports competing history.
    params.finality_depth = 1_000_000;
    let mut alloc: HashMap<String, u128> = validators
        .iter()
        .map(|v| (v.address().to_base58(), 100_000_000u128))
        .collect();
    for f in funded {
        alloc.insert(f.address().to_base58(), 100_000_000u128);
    }
    let g = Genesis::new(
        CHAIN_ID,
        0,
        validators
            .iter()
            .map(|v| v.public_key().to_base58())
            .collect(),
        alloc,
        params,
    );
    let json = g.to_json().expect("serialize genesis");
    assert!(
        json.contains("healthcare_authorization_enabled_from_height"),
        "the gate must be present in the genesis document, not only in the struct"
    );
    Genesis::from_json(&json).expect("the gate must load and validate")
}

// ─────────────────────────────────────────────────────────────────────────────
// 1. Coordinated activation
// ─────────────────────────────────────────────────────────────────────────────

/// Three validators, one shared activation height, and a chain that crosses it.
///
/// What would make this vacuous is the thing it asserts hardest against: if the
/// gate changed nothing, every node would agree at every height for free. So the
/// receipt for the SAME operation is required to flip — `Success` with the fee
/// paid below the boundary, `Failed(14)` with nothing paid at and above it — on
/// every node, at exactly the configured height and nowhere else.
#[tokio::test]
async fn three_validators_crossing_one_activation_height_agree_at_every_height() {
    let validators: Vec<KeyPair> = (0..VALIDATORS).map(|_| KeyPair::generate()).collect();
    let secrets: Vec<[u8; 32]> = validators
        .iter()
        .map(|v| *v.private_key().as_bytes())
        .collect();
    let issuer = KeyPair::generate();
    let patient = KeyPair::generate();
    let strangers: Vec<KeyPair> = (0..FILL_BLOCKS).map(|_| KeyPair::generate()).collect();

    let mut funded: Vec<&KeyPair> = vec![&issuer, &patient];
    funded.extend(strangers.iter());
    let genesis = genesis_with_auth_gate(&validators, &funded, Some(AUTH_BOUNDARY));
    assert_eq!(
        genesis.params.healthcare_authorization_enabled_from_height,
        Some(AUTH_BOUNDARY),
        "the height must survive the JSON round trip"
    );
    assert_eq!(
        genesis.validators.len(),
        VALIDATORS,
        "the proposer must rotate, or this is a one-validator test wearing a hat"
    );

    let mut world = World::new(&genesis, &secrets);

    // ── setup, below the boundary ───────────────────────────────────────────
    world
        .advance(
            healthcare_tx(
                &issuer,
                0,
                HealthcareOperation::RegisterProvider,
                &provider_profile(issuer.address()),
            ),
            &[],
        )
        .await;
    world
        .advance(
            healthcare_tx(
                &issuer,
                1,
                HealthcareOperation::IssuePrescription,
                &prescription(issuer.address(), patient.address()),
            ),
            &[],
        )
        .await;
    world.assert_agreement(&[]);
    assert!(
        world.chain.last().unwrap().height() < AUTH_BOUNDARY,
        "the setup must complete below the boundary, or the prescription cannot \
         be issued at all"
    );

    // ── across the boundary ─────────────────────────────────────────────────
    let mut fills: Vec<(u64, SignedTransaction)> = Vec::new();
    for (n, stranger) in strangers.iter().enumerate() {
        let tx = stranger_fill(stranger, n as u64);
        let block = world.advance(tx.clone(), &[]).await;
        fills.push((block.height(), tx));
        // Every node, every height, every block — after every single block, not
        // once at the end.
        world.assert_agreement(&[]);
    }
    let head = world.chain.last().unwrap().height();
    assert_eq!(head, 2 + FILL_BLOCKS);
    assert!(
        head > AUTH_BOUNDARY,
        "the chain must CONTINUE above the boundary, not stop at it"
    );

    // ── the gate fired, at the configured height, on every node ─────────────
    let mut below = 0usize;
    let mut above = 0usize;
    for (height, tx) in &fills {
        let expected = if *height >= AUTH_BOUNDARY {
            above += 1;
            (HEALTHCARE_FAILED, 0u128)
        } else {
            below += 1;
            (TxStatus::Success, FEE)
        };
        for node in &world.nodes {
            assert_eq!(
                node.receipt_status(tx),
                Some(expected.0),
                "{}: the fill at height {height} must be {:?} under a boundary at \
                 {AUTH_BOUNDARY}",
                node.label,
                expected.0
            );
            assert_eq!(
                node.receipt_fee(tx),
                Some(expected.1),
                "{}: the fee recorded for the fill at height {height} decides a byte \
                 of the state root",
                node.label
            );
        }
    }
    assert!(
        below >= 3 && above >= 3,
        "the chain must straddle the boundary with real blocks on both sides: \
         {below} below, {above} above"
    );

    // The proposer really did rotate, so the agreement above is agreement
    // between validators and not one validator agreeing with itself.
    let proposers: std::collections::BTreeSet<[u8; 32]> = world
        .chain
        .iter()
        .map(|b| b.header.proposer_pubkey)
        .collect();
    assert!(
        proposers.len() >= 2,
        "at least two distinct validators must have produced: {}",
        proposers.len()
    );

    // And the strangers' balances record the same split: the ones who filled
    // below the boundary paid, the ones above did not.
    for (i, (height, _)) in fills.iter().enumerate() {
        let expected = if *height >= AUTH_BOUNDARY {
            100_000_000
        } else {
            100_000_000 - FEE
        };
        for node in &world.nodes {
            assert_eq!(
                node.balance(&strangers[i].address()),
                expected,
                "{}: stranger {i} at height {height}",
                node.label
            );
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 2. Mixed version
// ─────────────────────────────────────────────────────────────────────────────

/// One validator configured with a DIFFERENT activation height, on the same
/// chain — and the shape of what happens, layer by layer.
///
/// The discipline is `journal_activation_e2e.rs`'s
/// `a_coordinated_activation_pair_is_accepted_by_the_authoritative_loader`: name
/// the layer that catches each thing, and assert the layers that do NOT catch it
/// as well, so that a rule moving between layers fails here rather than passing
/// quietly with one layer doing nothing.
///
/// The answer this establishes, and it is not the comfortable one:
///
/// | layer | verdict |
/// |---|---|
/// | `Genesis::from_json` / `ChainParams::validate` | ACCEPTS both |
/// | `validate_runtime_activation` | ACCEPTS both |
/// | `Genesis::activation_digest` | DIFFERS — the only pre-flight signal, and it is operator-facing |
/// | block execution | the odd node computes a DIFFERENT root |
/// | `accept_imported`, at these heights | ADOPTS the header root — no refusal |
///
/// So below `LEGACY_ROOT_COMPATIBILITY_HEIGHT` the answer to "refuse to start,
/// refuse the block, or produce a different root" is the third one, and the
/// difference is then absorbed: the nodes agree on the accumulator and disagree
/// about what it commits to. The receipt and the balance prove the divergence is
/// real; the equal state roots prove nothing on the chain can see it.
///
/// `above_the_legacy_window_the_same_disagreement_is_refused` is the other half.
#[tokio::test]
async fn a_validator_with_a_different_activation_height_forks_silently_below_the_legacy_window() {
    let validators: Vec<KeyPair> = (0..VALIDATORS).map(|_| KeyPair::generate()).collect();
    let secrets: Vec<[u8; 32]> = validators
        .iter()
        .map(|v| *v.private_key().as_bytes())
        .collect();
    let issuer = KeyPair::generate();
    let patient = KeyPair::generate();
    let strangers: Vec<KeyPair> = (0..FILL_BLOCKS).map(|_| KeyPair::generate()).collect();
    let mut funded: Vec<&KeyPair> = vec![&issuer, &patient];
    funded.extend(strangers.iter());

    // The majority: the gate at `AUTH_BOUNDARY`. The odd node: one height later.
    // A single mistyped digit, which is the failure this is modelled on.
    let majority = genesis_with_auth_gate(&validators, &funded, Some(AUTH_BOUNDARY));
    let odd = genesis_with_auth_gate(&validators, &funded, Some(AUTH_BOUNDARY + 1));

    // ── layer 1: the authoritative loader ───────────────────────────────────
    //
    // Both loaded through `Genesis::from_json`, which is what
    // `genesis_with_auth_gate` does and would have panicked in. Asserted again
    // explicitly, because "the loader does not catch this" is a claim.
    for g in [&majority, &odd] {
        Genesis::from_json(&g.to_json().expect("serialize"))
            .expect("the loader cannot see a peer, so it must accept either configuration");
        g.params
            .validate()
            .expect("each configuration is self-consistent");
    }

    // ── layer 2: the runtime activation validator, which runs at chain init
    //    and at every node start ────────────────────────────────────────────
    for g in [&majority, &odd] {
        sumchain_state::account_root::validate_runtime_activation(&g.params).expect(
            "this validator owns the journal/account pair; it has no opinion about \
             an authorization gate and must not acquire one silently",
        );
    }

    // ── layer 3: the activation digest, which is the ONLY pre-flight signal ─
    let majority_digest = majority.activation_digest().expect("digest");
    let odd_digest = odd.activation_digest().expect("digest");
    assert_ne!(
        majority_digest, odd_digest,
        "the digest is the one value two operators can compare by eye, so a \
         one-digit difference must change it"
    );

    // ── the chain ───────────────────────────────────────────────────────────
    let mut world = World::new(&majority, &secrets);
    // The odd node follows the same chain with a validator key that is in the
    // set (so it accepts the same blocks), but it never proposes here: it is
    // driven purely as an importer, which is the shape of a validator that is
    // behind on its configuration.
    let odd_node = Node::new(&odd, secrets[0], "odd");
    let followers = [&odd_node];

    world
        .advance(
            healthcare_tx(
                &issuer,
                0,
                HealthcareOperation::RegisterProvider,
                &provider_profile(issuer.address()),
            ),
            &followers,
        )
        .await;
    world
        .advance(
            healthcare_tx(
                &issuer,
                1,
                HealthcareOperation::IssuePrescription,
                &prescription(issuer.address(), patient.address()),
            ),
            &followers,
        )
        .await;

    let mut fills: Vec<(u64, SignedTransaction)> = Vec::new();
    for (n, stranger) in strangers.iter().enumerate() {
        let tx = stranger_fill(stranger, n as u64);
        // ── layer 5: the odd node does NOT refuse the block ─────────────────
        //
        // `advance` panics if any importer refuses, so the absence of a refusal
        // is asserted by this call completing — including at the boundary
        // height, which is where a refusal would be expected if one existed.
        let block = world.advance(tx.clone(), &followers).await;
        fills.push((block.height(), tx));
    }
    let head = world.chain.last().unwrap().height();

    // ── the absorbed part: every node, including the odd one, holds the same
    //    block and the same state root at every height ────────────────────────
    world.assert_agreement(&followers);

    // ── the real part: the odd node's own execution disagreed ───────────────
    //
    // Exactly one height is affected — `AUTH_BOUNDARY`, which the majority
    // treats as gated and the odd node as one below its own gate. Above and
    // below it the two configurations coincide.
    let boundary_fill = fills
        .iter()
        .find(|(h, _)| *h == AUTH_BOUNDARY)
        .expect("a fill must land exactly on the boundary height");
    assert_eq!(
        world.nodes[0].receipt_status(&boundary_fill.1),
        Some(HEALTHCARE_FAILED),
        "the majority refuses the boundary fill"
    );
    assert_eq!(
        odd_node.receipt_status(&boundary_fill.1),
        Some(TxStatus::Success),
        "and the odd node, one height behind, ACCEPTS it — this is the fork"
    );
    assert_eq!(world.nodes[0].receipt_fee(&boundary_fill.1), Some(0));
    assert_eq!(odd_node.receipt_fee(&boundary_fill.1), Some(FEE));

    // The divergence is in real state, not only in a receipt: one node deducted
    // the fee and the other did not.
    let who = fills
        .iter()
        .position(|(h, _)| *h == AUTH_BOUNDARY)
        .expect("boundary fill index");
    let stranger_addr = strangers[who].address();
    assert_eq!(world.nodes[0].balance(&stranger_addr), 100_000_000);
    assert_eq!(odd_node.balance(&stranger_addr), 100_000_000 - FEE);

    // ── and nothing on the chain can see it ─────────────────────────────────
    assert_eq!(
        odd_node.state.state_root(),
        world.nodes[0].state.state_root(),
        "the accumulators are EQUAL while the state behind them is not: the \
         mismatch was absorbed by the legacy-root compatibility window, which \
         covers every height at or below {}",
        sumchain_storage::candidate::LEGACY_ROOT_COMPATIBILITY_HEIGHT
    );
    assert!(
        head <= sumchain_storage::candidate::LEGACY_ROOT_COMPATIBILITY_HEIGHT,
        "this whole chain is inside the window ({head} <= {}), which is WHY the \
         disagreement was absorbed — the other half of the story is \
         `above_the_legacy_window_the_same_disagreement_is_refused`",
        sumchain_storage::candidate::LEGACY_ROOT_COMPATIBILITY_HEIGHT
    );

    // The odd node also keeps following afterwards, so this is a silent
    // divergence and not a node that quietly stopped.
    assert_eq!(odd_node.height(), head);
}

/// The same one-digit misconfiguration, one height above the legacy-root window,
/// where `accept_imported` NAMES it and refuses.
///
/// This runs at the acceptance seam rather than through `PoAEngine`, because
/// reaching height 496,721 through real block production would mean producing
/// half a million blocks. The seam is where the rule lives — `accept_imported`
/// owns both the comparison and the cutoff, and no call site can widen it — and
/// the two executors differ in exactly one `ChainParams` field, which is the
/// whole point.
///
/// What it does NOT claim: that a node at that height refuses through the engine.
/// The engine calls this function and maps its error, which is visible in
/// `poa.rs::do_import_block`, but that composition is proved at the heights a
/// test can reach, by the test above finding no refusal BELOW the cutoff.
#[test]
fn above_the_legacy_window_the_same_disagreement_is_refused() {
    use sumchain_primitives::{Block, BlockHeader};
    use sumchain_state::BlockExecutor;
    use sumchain_storage::candidate::LEGACY_ROOT_COMPATIBILITY_HEIGHT;

    /// One binary: a database, a state manager and an executor carrying one
    /// `ChainParams`.
    struct Binary {
        _dir: TempDir,
        db: Arc<Database>,
        state: Arc<StateManager>,
        exec: BlockExecutor,
    }

    fn binary(auth_from: Option<u64>) -> Binary {
        let mut params = ChainParams::with_v2_enabled();
        params.healthcare_authorization_enabled_from_height = auth_from;
        let dir = TempDir::new().expect("temp dir");
        let db = Arc::new(Database::open_default(dir.path()).expect("open"));
        let state = Arc::new(StateManager::new(db.clone(), CHAIN_ID));
        let exec = BlockExecutor::new(state.clone(), db.clone(), params);
        Binary {
            _dir: dir,
            db,
            state,
            exec,
        }
    }

    impl Binary {
        fn fund(&self, who: &Address, amount: u128) {
            sumchain_storage::StateStore::new(&self.db)
                .put_account(
                    who,
                    &sumchain_storage::schema::AccountState {
                        balance: amount,
                        nonce: 0,
                    },
                )
                .expect("seed");
        }

        /// Produce a block at `height` the way a proposer does, writing this
        /// binary's own computed root into the header.
        fn publish(&self, height: u64, txs: Vec<SignedTransaction>) -> (Block, Hash) {
            let header = BlockHeader::new(
                Hash::ZERO,
                height,
                1_000 + height,
                Hash::ZERO,
                Hash::ZERO,
                [7u8; 32],
            );
            let mut block = Block::new(header, txs);
            let exec = self
                .exec
                .execute_block(&block, self.state.state_root(), &[])
                .expect("execute");
            block.header.state_root = exec.computed_root();
            let (executed, _sd, _cd) = exec.into_parts();
            let accepted = executed.accept_produced(&block).expect("accept_produced");
            let accumulator = accepted.accumulator();
            accepted.publish().expect("publish");
            self.state.set_state_root(accumulator);
            (block.clone(), block.header.state_root)
        }

        /// Import a block another binary produced: execute it and hand the
        /// result to `accept_imported`, which owns the comparison AND the
        /// cutoff. Returns this binary's own computed root, or the refusal.
        fn import(&self, block: &Block) -> std::result::Result<Hash, String> {
            let exec = self
                .exec
                .execute_block(block, self.state.state_root(), &[])
                .expect("execute");
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

    // The boundary a release would actually choose: clear of the window.
    let boundary = LEGACY_ROOT_COMPATIBILITY_HEIGHT + 1;
    let issuer = KeyPair::generate();
    let patient = KeyPair::generate();
    let stranger_below = KeyPair::generate();
    let stranger_at = KeyPair::generate();

    let majority = binary(Some(boundary));
    let odd = binary(Some(boundary + 1));
    for b in [&majority, &odd] {
        b.fund(&issuer.address(), 100_000_000);
        b.fund(&stranger_below.address(), 100_000_000);
        b.fund(&stranger_at.address(), 100_000_000);
    }

    // Setup, and one gated transaction BELOW the boundary, where the two
    // configurations coincide and must agree exactly.
    for (n, (op, payload)) in [
        (
            HealthcareOperation::RegisterProvider,
            bincode::serialize(&provider_profile(issuer.address())).unwrap(),
        ),
        (
            HealthcareOperation::IssuePrescription,
            bincode::serialize(&prescription(issuer.address(), patient.address())).unwrap(),
        ),
    ]
    .into_iter()
    .enumerate()
    {
        let tx = {
            let t = TransactionV2 {
                chain_id: CHAIN_ID,
                from: issuer.address(),
                fee: FEE,
                nonce: n as u64,
                payload: TxPayload::Healthcare(HealthcareTxData {
                    operation: op,
                    data: payload,
                    recipient: Address::ZERO,
                }),
            };
            let sig = sign(t.signing_hash().as_bytes(), issuer.private_key());
            SignedTransaction::new_v2(t, *sig.as_bytes(), *issuer.public_key().as_bytes())
        };
        let (block, root) = majority.publish(boundary - 3 + n as u64, vec![tx]);
        let mine = odd
            .import(&block)
            .expect("below the boundary the two configurations coincide");
        assert_eq!(
            mine,
            root,
            "height {}: identical configurations must reach identical roots",
            block.height()
        );
    }

    let (block, root) = majority.publish(boundary - 1, vec![stranger_fill(&stranger_below, 0)]);
    assert_eq!(
        odd.import(&block)
            .expect("one below the boundary, both binaries still agree"),
        root,
        "the two only diverge AT the boundary, which is what makes the refusal \
         below attributable to the gate"
    );

    // ── AT the boundary: the odd node computes a different root, and this time
    //    the difference is named rather than absorbed ─────────────────────────
    let (boundary_block, majority_root) =
        majority.publish(boundary, vec![stranger_fill(&stranger_at, 1)]);
    let refusal = odd
        .import(&boundary_block)
        .expect_err("above the legacy window a root mismatch must be REFUSED");
    assert!(
        refusal.contains("state root mismatch")
            && refusal.contains(&format!("at height {boundary}")),
        "the refusal must NAME the disagreement and the height: {refusal}"
    );
    assert!(
        refusal.contains(&majority_root.to_string()),
        "and it must name the header root it disagreed with ({majority_root}): {refusal}"
    );
    assert!(
        boundary > LEGACY_ROOT_COMPATIBILITY_HEIGHT,
        "and it is refused BECAUSE the height is above {LEGACY_ROOT_COMPATIBILITY_HEIGHT}"
    );
}
