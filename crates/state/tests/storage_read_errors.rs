//! A storage read that fails while a governance or service-grant transaction
//! executes is an execution error, never a receipt.
//!
//! Each read below happens inside a transaction's execution, and each test makes
//! one of them fail in one of two ways:
//!
//! * **for real** — the rows the read reaches are rewritten into a table file of
//!   their own and that file is damaged on disk, so RocksDB itself refuses the
//!   read with a checksum error ([`damage`]). Nothing is mocked; every other row
//!   still reads;
//! * **by an undecodable stored row** — the row is overwritten with bytes that do
//!   not decode ([`garble`]).
//!
//! The transaction then runs in a block, and the block must fail AT that
//! transaction, as a transient failure: no receipt, no fee, no nonce, and no row
//! written ([`assert_fails_the_block`]).
//!
//! The semantic refusals at the same sites keep their receipts. The
//! `*_are_unchanged` tests publish blocks of them and pin each receipt and the
//! state root the block publishes, at the values the code produced before
//! storage failures were separated from refusals.

mod common;

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use common::{setup_with_params, CHAIN_ID};
use sumchain_crypto::{sign, KeyPair};
use sumchain_genesis::ChainParams;
use sumchain_primitives::equity::{EquityToken, ShareClassType, TokenStatus};
use sumchain_primitives::governance::{
    equity_vote_signing_bytes, generate_proposal_id, CancelProposalRequest,
    CastEquityVoteRequest, CastVoteRequest, CreateProposalRequest, ExecuteProposalRequest,
    ExecutionKind, ExternalRef, GovAsset, GovAssetKind, GovAssetStatus, GovProposalClass,
    GovernanceOperation, GovernanceParams, GovernanceTxData, RegisterAssetRequest,
    RegisterEquityClassRequest, RegisterQualifyingAssetRequest, VoteChoice, WeightRule,
};
use sumchain_primitives::supply::{
    GrantStatus, ServiceGrant, ServiceKind, ServiceMilestones, SupplyOperation, SupplyTxData,
    COMPUTE_CLAIMS_GRANT_1, GENESIS_ACCOUNTED_SUPPLY,
};
use sumchain_primitives::validator_authority::{
    register_asset_signing_bytes, register_equity_class_signing_bytes,
};
use sumchain_primitives::{
    Address, Block, BlockHeader, Hash, NodeRegistryOperation, NodeRegistryTxData, NodeRole,
    Receipt, SignedTransaction, TransactionV2, TxPayload, TxStatus, ValidatorApproval,
    ValidatorInfo,
};
use sumchain_state::executor::BlockExecutor;
use sumchain_state::supply::SupplyStore;
use sumchain_state::{StateError, StateManager, TxFailureClass};
use sumchain_storage::schema::Src20TokenData;
use sumchain_storage::{
    cf, equity_balances_root_and_proof, Database, EquityStore, GovStore, StakingStore,
    StateStore, TokenStore,
};
use tempfile::TempDir;

const FEE: u128 = 100;
const TOKEN: [u8; 32] = [0x7A; 32];
const QTOKEN: [u8; 32] = [0x51; 32];
const CLASS: [u8; 32] = [0xEC; 32];
const CONTENT: [u8; 32] = [0xAB; 32];
/// Bytes no stored row decodes from: every row read here needs more than three.
const GARBAGE: [u8; 3] = [0xFF, 0xFE, 0xFD];
/// What RocksDB reports for a table whose data block fails its checksum.
const CORRUPTION: &str = "Corruption";
/// What decoding [`GARBAGE`] as a bincode row reports.
const UNDECODABLE: &str = "unexpected end of file";

// ── The node, and the two ways a read is made to fail ────────────────────────

/// One node: its database directory and the handles over it.
struct Node {
    dir: TempDir,
    params: ChainParams,
    state: Arc<StateManager>,
    db: Arc<Database>,
    exec: BlockExecutor,
}

impl Node {
    fn new(params: ChainParams) -> Self {
        let (state, db, dir, exec) = setup_with_params(params.clone());
        Node { dir, params, state, db, exec }
    }

    /// Publish one block through the real path: execute, accept, publish.
    fn publish(&self, height: u64, txs: Vec<SignedTransaction>) -> Vec<Receipt> {
        self.publish_returning(height, txs).0
    }

    fn publish_returning(&self, height: u64, txs: Vec<SignedTransaction>) -> (Vec<Receipt>, Block) {
        let v = proposer_pubkey();
        common::publish_block_returning(&self.state, &self.exec, height, &v, txs, &[v])
    }
}

/// The block proposer, and the one active validator: its approval is the
/// validator quorum, and it is a staking validator in the grant worlds.
fn validator() -> KeyPair {
    KeyPair::from_bytes([0x5A; 32])
}

fn proposer_pubkey() -> [u8; 32] {
    *validator().public_key().as_bytes()
}

fn key(n: u8) -> KeyPair {
    KeyPair::from_bytes([n; 32])
}

/// The table files in a database directory.
fn tables(dir: &Path) -> BTreeSet<PathBuf> {
    std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|e| e == "sst"))
        .collect()
}

/// Make RocksDB itself refuse every read of the selected rows of `cf_name`.
///
/// The node is closed and reopened, which flushes everything written so far
/// into table files, and compacted, which moves them out of level 0. The
/// selected rows are then rewritten unchanged, so the next reopen flushes
/// them, and only them, into one new level-0 table. Damaging that table's first
/// data block makes every read that reaches it fail its checksum, while other
/// families and the other keys of this one still read: with tables on more
/// than one level, a point read skips a table whose key range does not hold
/// its key. Both halves are checked here, before any transaction runs.
fn damage(node: Node, cf_name: &str, select: impl Fn(&[u8]) -> bool) -> Node {
    let Node { dir, params, state, db, exec } = node;
    drop(exec);
    drop(state);
    drop(db);
    {
        let db = Database::open_default(dir.path()).unwrap();
        db.compact().unwrap();
    }
    let before = tables(dir.path());
    let (selected, others): (Vec<_>, Vec<_>) = {
        let db = Database::open_default(dir.path()).unwrap();
        let rows: Vec<_> = db.iter(cf_name).unwrap().collect();
        let (selected, others): (Vec<_>, Vec<_>) = rows.into_iter().partition(|(k, _)| select(k));
        for (k, v) in &selected {
            db.put(cf_name, k, v).unwrap();
        }
        (selected, others)
    };
    assert!(!selected.is_empty(), "no row of {cf_name} was selected");

    let (state, db, exec) = common::reopen(&dir, params.clone());
    let fresh: Vec<PathBuf> = tables(dir.path()).difference(&before).cloned().collect();
    assert_eq!(fresh.len(), 1, "the selected rows must be in one table of their own: {fresh:?}");
    let mut bytes = std::fs::read(&fresh[0]).unwrap();
    for b in &mut bytes[8..40] {
        *b ^= 0xFF;
    }
    std::fs::write(&fresh[0], &bytes).unwrap();

    // The failure is real before any transaction meets it, and confined to the
    // selected rows: every other row of the family still reads.
    for (k, _) in &selected {
        let read = db.get(cf_name, k);
        assert!(
            matches!(&read, Err(e) if e.to_string().contains(CORRUPTION)),
            "a damaged row of {cf_name} must fail to read: {read:?}"
        );
    }
    for (k, v) in &others {
        assert_eq!(db.get(cf_name, k).unwrap().as_deref(), Some(&v[..]), "an undamaged row reads");
    }
    Node { dir, params, state, db, exec }
}

/// Overwrite the selected rows of `cf_name` with bytes that do not decode.
fn garble(db: &Database, cf_name: &str, select: impl Fn(&[u8]) -> bool) {
    let keys: Vec<Box<[u8]>> =
        db.iter(cf_name).unwrap().map(|(k, _)| k).filter(|k| select(k)).collect();
    assert!(!keys.is_empty(), "no row of {cf_name} was selected");
    for k in keys {
        db.put(cf_name, &k, &GARBAGE).unwrap();
    }
}

fn all(_: &[u8]) -> bool {
    true
}

/// One stored row: its column family, key and value.
type Row = (&'static str, Box<[u8]>, Box<[u8]>);

/// Every row of every column family, in order.
///
/// Iteration stops at a row that fails to read, at the same row each time, so
/// two dumps of an unchanged database are equal.
fn dump(db: &Database) -> Vec<Row> {
    let mut rows = Vec::new();
    for cf_name in sumchain_storage::db::ALL_CFS {
        for (k, v) in db.iter(cf_name).unwrap() {
            rows.push((*cf_name, k, v));
        }
    }
    rows
}

fn account(db: &Database, addr: &Address) -> (u128, u64) {
    let a = StateStore::new(db).get_account(addr).unwrap();
    (a.balance, a.nonce)
}

/// Execute `tx` alone in a block at `height` and return why the block was
/// refused. Nothing is published either way.
fn refuse(node: &Node, height: u64, tx: SignedTransaction) -> (usize, TxFailureClass, String) {
    let v = proposer_pubkey();
    let header = BlockHeader::new(Hash::ZERO, height, 1000, Hash::ZERO, Hash::ZERO, v);
    let block = Block::new(header, vec![tx]);
    match node.exec.execute_block(&block, node.state.state_root(), &[v]) {
        Ok(executed) => {
            let receipts: Vec<_> =
                common::receipts_of(executed).iter().map(|r| (r.status, r.fee_paid)).collect();
            panic!("the block executed, with receipts {receipts:?}; a failed read must fail it")
        }
        Err(StateError::BlockTransactionAborted { tx_index, class, detail }) => {
            (tx_index, class, detail)
        }
        Err(other) => panic!("the block failed outside its transaction: {other}"),
    }
}

/// The block fails at `tx`, as a transient failure caused by `cause`, and the
/// database is exactly as it was: no receipt, no fee, no nonce, no row.
fn assert_fails_the_block(node: &Node, height: u64, tx: SignedTransaction, cause: &str) {
    let sender = tx.sender();
    let rows = dump(&node.db);
    let sender_account = account(&node.db, &sender);

    let (tx_index, class, detail) = refuse(node, height, tx);
    assert_eq!(tx_index, 0, "the block must fail at the transaction: {detail}");
    assert_eq!(
        class,
        TxFailureClass::Transient,
        "a node-local failure must not destroy the transaction: {detail}"
    );
    assert!(detail.contains(cause), "expected {cause:?} in: {detail}");

    assert_eq!(account(&node.db, &sender), sender_account, "no fee and no nonce");
    assert!(dump(&node.db) == rows, "nothing written: no receipt, no fee, no nonce, no row");
}

/// The (status, fee) of each receipt, and the root the block published.
fn outcome(receipts: &[Receipt], block: &Block) -> (Vec<(TxStatus, u128)>, String) {
    (
        receipts.iter().map(|r| (r.status, r.fee_paid)).collect(),
        block.header.state_root.to_hex(),
    )
}

// ── Transactions ─────────────────────────────────────────────────────────────

fn signed(kp: &KeyPair, nonce: u64, payload: TxPayload) -> SignedTransaction {
    let tx = TransactionV2 { chain_id: CHAIN_ID, from: kp.address(), fee: FEE, nonce, payload };
    let h = tx.signing_hash();
    let sig = sign(h.as_bytes(), kp.private_key());
    SignedTransaction::new_v2(tx, *sig.as_bytes(), *kp.public_key().as_bytes())
}

fn gov<T: serde::Serialize>(operation: GovernanceOperation, req: &T) -> TxPayload {
    TxPayload::Governance(GovernanceTxData { operation, data: bincode::serialize(req).unwrap() })
}

fn approval(msg: &[u8]) -> ValidatorApproval {
    let v = validator();
    ValidatorApproval {
        pubkey: *v.public_key().as_bytes(),
        signature: sign(msg, v.private_key()).to_bytes(),
    }
}

fn register_asset(token_id: [u8; 32]) -> TxPayload {
    let msg = register_asset_signing_bytes(CHAIN_ID, &token_id, 1, 0);
    let req = RegisterAssetRequest {
        token_id,
        create_threshold: 1,
        effective_height: 0,
        approvals: vec![approval(&msg)],
    };
    gov(GovernanceOperation::RegisterAsset, &req)
}

fn register_qualifying(token_id: [u8; 32]) -> TxPayload {
    let msg = register_asset_signing_bytes(CHAIN_ID, &token_id, 50, 0);
    let req = RegisterQualifyingAssetRequest {
        token_id,
        min_balance: 50,
        effective_height: 0,
        approvals: vec![approval(&msg)],
    };
    gov(GovernanceOperation::RegisterQualifyingAsset, &req)
}

fn register_equity_class(class_id: [u8; 32]) -> TxPayload {
    let msg = register_equity_class_signing_bytes(CHAIN_ID, &class_id, 0, 0);
    let req = RegisterEquityClassRequest {
        class_id,
        create_threshold: 0,
        effective_height: 0,
        approvals: vec![approval(&msg)],
    };
    gov(GovernanceOperation::RegisterEquityClass, &req)
}

fn create(asset: GovAssetKind) -> TxPayload {
    let req = CreateProposalRequest {
        asset,
        class: GovProposalClass::RoutineProcess,
        execution_kind: ExecutionKind::RecordOnly,
        external_ref: ExternalRef { url: "https://x/1".into(), content_hash: CONTENT },
        treasury_beneficiary: None,
        treasury_amount: None,
    };
    gov(GovernanceOperation::CreateProposal, &req)
}

fn create_release(to: Address, amount: u128) -> TxPayload {
    let req = CreateProposalRequest {
        asset: GovAssetKind::NativeEligibility,
        class: GovProposalClass::ReserveReleaseEcosystem,
        execution_kind: ExecutionKind::OnChain,
        external_ref: ExternalRef { url: "https://x/1".into(), content_hash: CONTENT },
        treasury_beneficiary: Some(to),
        treasury_amount: Some(amount),
    };
    gov(GovernanceOperation::CreateProposal, &req)
}

fn vote(proposal_id: [u8; 32]) -> TxPayload {
    gov(GovernanceOperation::CastVote, &CastVoteRequest { proposal_id, choice: VoteChoice::Yes })
}

fn execute(proposal_id: [u8; 32]) -> TxPayload {
    gov(GovernanceOperation::ExecuteProposal, &ExecuteProposalRequest { proposal_id })
}

fn cancel(proposal_id: [u8; 32]) -> TxPayload {
    let req = CancelProposalRequest { proposal_id, approvals: vec![] };
    gov(GovernanceOperation::CancelProposal, &req)
}

fn claim(service_kind: ServiceKind) -> TxPayload {
    TxPayload::Supply(SupplyTxData {
        operation: SupplyOperation::ClaimServiceGrant { service_kind },
    })
}

fn unlock(service_kind: ServiceKind) -> TxPayload {
    TxPayload::Supply(SupplyTxData {
        operation: SupplyOperation::UnlockServiceGrant { service_kind },
    })
}

fn proposal_id(proposer: &KeyPair, asset: GovAssetKind, height: u64, nonce: u64) -> [u8; 32] {
    generate_proposal_id(&proposer.address(), &asset, &CONTENT, height, nonce)
}

// ── Seeding (committed state written before any block that reads it) ────────

fn gov_params(min_koppa: u128) -> ChainParams {
    let mut p = ChainParams::with_v2_enabled();
    p.governance_enabled_from_height = Some(0);
    p.governance = Some(GovernanceParams {
        // A one-validator set: ceil(1 * 5000 / 10000) = 1 approval.
        validator_authority_threshold_bps: 5_000,
        quorum_bps: 2_000,
        pass_threshold_bps: 5_000,
        voting_period_blocks: 100,
        max_snapshot_holders: 100,
        proposal_bond: 0,
        treasury: None,
        min_koppa_for_eligibility: min_koppa,
    });
    p
}

fn seed_token(db: &Database, token_id: [u8; 32], balances: &[(Address, u128)]) {
    let ts = TokenStore::new(db);
    let data = Src20TokenData {
        name: "Gov".into(),
        symbol: "GOV".into(),
        decimals: 0,
        owner: Address::new([0xC0; 20]),
        total_supply: 1_000,
        max_supply: 1_000,
        mintable: false,
        burnable: false,
        pausable: false,
        paused: false,
        minters: vec![],
        created_at: 0,
        created_at_block: 0,
    };
    ts.put_token(&token_id, &data).unwrap();
    for (a, b) in balances {
        ts.set_balance(&token_id, a, *b).unwrap();
    }
}

fn seed_registered(db: &Database, token_id: [u8; 32]) {
    GovStore::new(db)
        .put_asset(&GovAsset {
            asset: GovAssetKind::Src20Token(token_id),
            create_threshold: 1,
            vote_weight_rule: WeightRule::Linear,
            status: GovAssetStatus::Enabled,
            effective_height: 0,
        })
        .unwrap();
}

fn seed_equity_class(db: &Database, controller: Address, holders: &[([u8; 32], u64)]) {
    let equity = EquityStore::new(db);
    equity
        .tokens()
        .put(&EquityToken {
            issuer_subject: [1u8; 32],
            class_id: CLASS,
            share_class_type: ShareClassType::Common,
            name: "Common".into(),
            symbol: "ACME-A".into(),
            authorized_shares: 1_000_000,
            issued_shares: 100_000,
            votes_per_share: 3,
            economic_rights_hash: [7u8; 32],
            liquidation_preference_hash: None,
            dividend_policy_hash: None,
            conversion_rules_hash: None,
            controller,
            par_value: Some(1),
            created_at: 0,
            updated_at: 0,
            status: TokenStatus::Active,
        })
        .unwrap();
    for (hc, shares) in holders {
        equity.balances().set_balance(&CLASS, hc, *shares).unwrap();
    }
}

fn seed_validator(db: &Database, kp: &KeyPair) {
    let v = ValidatorInfo::new(*kp.public_key().as_bytes(), 1_000_000, 100, 1);
    StakingStore::new(db).put_validator(&v).unwrap();
}

/// The service-grant row layouts: `tag || address(20) || kind(1)`.
fn supply_key(tag: u8, addr: &Address, kind: ServiceKind) -> Vec<u8> {
    let mut k = vec![tag];
    k.extend_from_slice(addr.as_bytes());
    k.push(kind as u8);
    k
}

fn grant_key(addr: &Address, kind: ServiceKind) -> Vec<u8> {
    supply_key(b'G', addr, kind)
}

fn credit_key(addr: &Address, kind: ServiceKind) -> Vec<u8> {
    supply_key(b'E', addr, kind)
}

fn milestone_key(addr: &Address, kind: ServiceKind) -> Vec<u8> {
    supply_key(b'M', addr, kind)
}

/// A compute provider with one valid settlement claim on record — a milestone
/// reached — and, if `forfeited`, a grant already forfeited.
fn seed_compute_provider(db: &Database, addr: &Address, forfeited: bool) {
    let m = ServiceMilestones { settlement_claims: 1, ..ServiceMilestones::default() };
    let kind = ServiceKind::Compute;
    db.put(cf::SUPPLY, &milestone_key(addr, kind), &bincode::serialize(&m).unwrap()).unwrap();
    if forfeited {
        let g = ServiceGrant {
            recipient: *addr,
            service_kind: kind,
            total_grant: COMPUTE_CLAIMS_GRANT_1,
            liquid_claimed: COMPUTE_CLAIMS_GRANT_1 / 10,
            locked_remaining: 0,
            earned_credit_used_for_unlock: 0,
            created_at_height: 50,
            status: GrantStatus::Forfeited,
        };
        db.put(cf::SUPPLY, &grant_key(addr, kind), &bincode::serialize(&g).unwrap()).unwrap();
    }
}

/// Fund exactly the accounted genesis supply and publish the block that applies
/// the supply correction, which creates the protocol reserve.
fn migrate(node: &Node) {
    let half = GENESIS_ACCOUNTED_SUPPLY / 2;
    common::credit_committed(&node.db, &Address::new([0xE1; 20]), half);
    common::credit_committed(&node.db, &Address::new([0xE2; 20]), half);
    node.publish(100, vec![]);
    assert!(SupplyStore::new(node.db.clone()).is_migration_applied().unwrap());
}

// ── Worlds ───────────────────────────────────────────────────────────────────

/// SRC-20 governance: `proposer` (600) and `holder` (400) hold the registered
/// token; the proposal was created at 5 and the proposer voted yes at 10.
struct Src20 {
    node: Node,
    proposer: KeyPair,
    holder: KeyPair,
    outsider: KeyPair,
    pid: [u8; 32],
}

fn src20_world() -> Src20 {
    let node = Node::new(gov_params(0));
    let (proposer, holder, outsider) = (key(0x01), key(0x02), key(0x03));
    seed_token(&node.db, TOKEN, &[(proposer.address(), 600), (holder.address(), 400)]);
    seed_registered(&node.db, TOKEN);
    for kp in [&proposer, &holder, &outsider] {
        common::fund(&node.db, kp, 1_000_000);
    }
    let r = node.publish(5, vec![signed(&proposer, 0, create(GovAssetKind::Src20Token(TOKEN)))]);
    assert_eq!(r[0].status, TxStatus::Success);
    let pid = proposal_id(&proposer, GovAssetKind::Src20Token(TOKEN), 5, 0);
    let r = node.publish(10, vec![signed(&proposer, 1, vote(pid))]);
    assert_eq!(r[0].status, TxStatus::Success);
    Src20 { node, proposer, holder, outsider, pid }
}

/// Native eligibility: `QTOKEN` is the registered qualifying asset (min 50),
/// held by `a` (Koppa 1,000, above the 500 floor) and `b` (Koppa 100, below).
struct Native {
    node: Node,
    submitter: KeyPair,
    creator: KeyPair,
    a: Address,
}

fn native_world() -> Native {
    let node = Node::new(gov_params(500));
    let (submitter, creator) = (key(0x11), key(0x12));
    let (a, b) = (Address::new([0xA1; 20]), Address::new([0xB2; 20]));
    seed_token(&node.db, QTOKEN, &[(a, 100), (b, 100)]);
    common::fund(&node.db, &submitter, 1_000_000);
    common::fund(&node.db, &creator, 1_000_000);
    common::seed_balance(&node.db, &a, 1_000);
    common::seed_balance(&node.db, &b, 100);
    let r = node.publish(1, vec![signed(&submitter, 0, register_qualifying(QTOKEN))]);
    assert_eq!(r[0].status, TxStatus::Success);
    Native { node, submitter, creator, a }
}

/// Equity-class governance: the class (3 votes per share; holders h1 10, h2 20,
/// h3 30) was registered at 1 and the proposal created at 5. `vote` is
/// `voter`'s valid attested vote for h2; `dup` is `voter2`'s for the same
/// holder, and `stranger` is `voter2`'s next, for a commitment the class does
/// not hold. With `voted`, `vote` was published at 10.
struct Equity {
    node: Node,
    submitter: KeyPair,
    creator: KeyPair,
    vote: SignedTransaction,
    dup: SignedTransaction,
    stranger: SignedTransaction,
}

fn equity_world(voted: bool) -> Equity {
    let node = Node::new(gov_params(0));
    let (submitter, creator, voter, voter2, controller) =
        (key(0x21), key(0x22), key(0x23), key(0x24), key(0x25));
    let (h1, h2, h3) = ([0x11; 32], [0x22; 32], [0x33; 32]);
    seed_equity_class(&node.db, controller.address(), &[(h1, 10), (h2, 20), (h3, 30)]);
    for kp in [&submitter, &creator, &voter, &voter2] {
        common::fund(&node.db, kp, 1_000_000);
    }
    let r = node.publish(1, vec![signed(&submitter, 0, register_equity_class(CLASS))]);
    assert_eq!(r[0].status, TxStatus::Success);
    let r = node.publish(5, vec![signed(&creator, 0, create(GovAssetKind::EquityClass(CLASS)))]);
    assert_eq!(r[0].status, TxStatus::Success);
    let pid = proposal_id(&creator, GovAssetKind::EquityClass(CLASS), 5, 0);

    let (root, proof) = equity_balances_root_and_proof(&node.db, &CLASS, &h2).unwrap();
    let (_, path) = proof.unwrap();
    let attested = |kp: &KeyPair, hc: [u8; 32], shares: u64, nonce: u64| {
        let msg = equity_vote_signing_bytes(CHAIN_ID, &pid, &CLASS, &root, &hc, shares, &kp.address());
        let req = CastEquityVoteRequest {
            proposal_id: pid,
            holder_commitment: hc,
            shares,
            merkle_path: path.clone(),
            controller_pubkey: *controller.public_key().as_bytes(),
            controller_sig: sign(&msg, controller.private_key()).to_bytes(),
            choice: VoteChoice::Yes,
        };
        signed(kp, nonce, gov(GovernanceOperation::CastEquityVote, &req))
    };
    let vote = attested(&voter, h2, 20, 0);
    let dup = attested(&voter2, h2, 20, 0);
    let stranger = attested(&voter2, [0x44; 32], 20, 1);
    if voted {
        let r = node.publish(10, vec![vote.clone()]);
        assert_eq!(r[0].status, TxStatus::Success);
    }
    Equity { node, submitter, creator, vote, dup, stranger }
}

/// A passed reserve-release proposal, ready to execute at 300: the correction
/// applied at 100, the qualifying asset registered at 101, the release created
/// at 105 and voted at 110.
struct Reserve {
    node: Node,
    submitter: KeyPair,
    pid: [u8; 32],
    over_pool: [u8; 32],
}

fn reserve_world() -> Reserve {
    let mut params = gov_params(1);
    params.monetary_policy_enabled_from_height = Some(0);
    let node = Node::new(params);
    migrate(&node);
    let (submitter, voter) = (key(0x31), key(0x32));
    common::fund(&node.db, &submitter, 1_000_000);
    common::fund(&node.db, &voter, 1_000_000);
    seed_token(&node.db, QTOKEN, &[(voter.address(), 100)]);
    let r = node.publish(101, vec![signed(&submitter, 0, register_qualifying(QTOKEN))]);
    assert_eq!(r[0].status, TxStatus::Success);
    let to = Address::new([0x77; 20]);
    let pool = sumchain_primitives::supply::POOL_ECOSYSTEM;
    let r = node.publish(
        105,
        vec![
            signed(&voter, 0, create_release(to, 12_345_000)),
            signed(&voter, 1, create_release(to, pool + 1)),
        ],
    );
    assert_eq!(r[0].status, TxStatus::Success);
    assert_eq!(r[1].status, TxStatus::Success);
    let pid = proposal_id(&voter, GovAssetKind::NativeEligibility, 105, 0);
    let over_pool = proposal_id(&voter, GovAssetKind::NativeEligibility, 105, 1);
    let r = node.publish(110, vec![signed(&voter, 2, vote(pid)), signed(&voter, 3, vote(over_pool))]);
    assert_eq!(r[0].status, TxStatus::Success);
    assert_eq!(r[1].status, TxStatus::Success);
    Reserve { node, submitter, pid, over_pool }
}

/// Service grants after the correction (applied at 100): `v` and `v2` are
/// staking validators; `v` claimed its grant at 110, a block it proposed, so it
/// also holds the earned credit of that block's fee.
struct Grants {
    node: Node,
    v: KeyPair,
    v2: KeyPair,
    outsider: KeyPair,
}

fn grants_params() -> ChainParams {
    let mut p = ChainParams::with_v2_enabled();
    p.service_grants_enabled_from_height = Some(0);
    p
}

fn grants_world() -> Grants {
    let node = Node::new(grants_params());
    migrate(&node);
    let (v, v2, outsider) = (validator(), key(0x42), key(0x43));
    seed_validator(&node.db, &v);
    seed_validator(&node.db, &v2);
    for kp in [&v, &v2, &outsider] {
        common::fund(&node.db, kp, 1_000_000);
    }
    let r = node.publish(110, vec![signed(&v, 0, claim(ServiceKind::Validator))]);
    assert_eq!(r[0].status, TxStatus::Success);
    Grants { node, v, v2, outsider }
}

/// A compute provider with a reached milestone (and, if `forfeited`, a
/// forfeited grant), after the correction.
fn compute_world(forfeited: bool) -> (Node, KeyPair) {
    let node = Node::new(grants_params());
    migrate(&node);
    let c = key(0x51);
    common::fund(&node.db, &c, 1_000_000);
    seed_compute_provider(&node.db, &c.address(), forfeited);
    (node, c)
}

/// An archive node registered at 101, after the correction.
fn archive_world() -> (Node, KeyPair) {
    let node = Node::new(grants_params());
    migrate(&node);
    let a = key(0x61);
    common::fund(&node.db, &a, 2_000_000_000);
    let reg = TxPayload::NodeRegistry(NodeRegistryTxData {
        operation: NodeRegistryOperation::Register {
            role: NodeRole::ArchiveNode,
            stake: 1_000_000_000,
        },
    });
    let r = node.publish(101, vec![signed(&a, 0, reg)]);
    assert_eq!(r[0].status, TxStatus::Success);
    (node, a)
}

// ── (a) Governance: a failed read fails the block ────────────────────────────

#[test]
fn register_asset_read_failure_fails_the_block() {
    // The token read.
    let w = src20_world();
    let tx = signed(&w.outsider, 0, register_asset(TOKEN));
    let node = damage(w.node, cf::TOKENS, all);
    assert_fails_the_block(&node, 20, tx.clone(), CORRUPTION);

    let w = src20_world();
    garble(&w.node.db, cf::TOKENS, all);
    assert_fails_the_block(&w.node, 20, tx, UNDECODABLE);
}

#[test]
fn register_qualifying_asset_read_failures_fail_the_block() {
    // The token read, then the native-eligibility asset read.
    for cf_name in [cf::TOKENS, cf::GOV_REGISTRY] {
        let w = native_world();
        let tx = signed(&w.submitter, 1, register_qualifying(QTOKEN));
        let node = damage(w.node, cf_name, all);
        assert_fails_the_block(&node, 2, tx.clone(), CORRUPTION);

        let w = native_world();
        garble(&w.node.db, cf_name, all);
        assert_fails_the_block(&w.node, 2, tx, UNDECODABLE);
    }
}

#[test]
fn register_equity_class_read_failure_fails_the_block() {
    let w = equity_world(false);
    let tx = signed(&w.submitter, 1, register_equity_class(CLASS));
    let node = damage(w.node, cf::EQUITY_TOKENS, all);
    assert_fails_the_block(&node, 2, tx.clone(), CORRUPTION);

    let w = equity_world(false);
    garble(&w.node.db, cf::EQUITY_TOKENS, all);
    assert_fails_the_block(&w.node, 2, tx, UNDECODABLE);
}

#[test]
fn create_src20_proposal_read_failures_fail_the_block() {
    // The asset, the creator's balance, then the holder scan: the proposer's
    // row is one the balance read does not reach and the scan does. The
    // creator is the holder (key 0x02); the proposer is key 0x01.
    let creator_row = TokenStore::balance_key(&TOKEN, &key(0x02).address());
    let other_row = TokenStore::balance_key(&TOKEN, &key(0x01).address());
    let cases: [(&str, Option<&[u8]>, &str); 3] = [
        (cf::GOV_REGISTRY, None, UNDECODABLE),
        (cf::TOKEN_BALANCES, Some(&creator_row), "token amount is not 16 bytes"),
        (cf::TOKEN_BALANCES, Some(&other_row), "token amount is not 16 bytes"),
    ];
    for (cf_name, row, cause) in cases {
        let select = |k: &[u8]| match row {
            None => true,
            Some(row) => k == row,
        };
        let w = src20_world();
        let tx = signed(&w.holder, 0, create(GovAssetKind::Src20Token(TOKEN)));
        let node = damage(w.node, cf_name, select);
        assert_fails_the_block(&node, 20, tx.clone(), CORRUPTION);

        let w = src20_world();
        garble(&w.node.db, cf_name, select);
        assert_fails_the_block(&w.node, 20, tx, cause);
    }
}

#[test]
fn create_native_proposal_read_failures_fail_the_block() {
    // The asset, the qualifying registry, the holder scan, then an eligible
    // holder's Koppa balance.
    let cases: [(&str, bool, &str); 4] = [
        (cf::GOV_REGISTRY, false, UNDECODABLE),
        (cf::GOV_QUALIFYING_ASSETS, false, UNDECODABLE),
        (cf::TOKEN_BALANCES, false, "token amount is not 16 bytes"),
        (cf::STATE, true, UNDECODABLE),
    ];
    for (cf_name, holder_account, cause) in cases {
        let w = native_world();
        let tx = signed(&w.creator, 0, create(GovAssetKind::NativeEligibility));
        let a_key = StateStore::account_key(&w.a);
        let select = |k: &[u8]| !holder_account || k == a_key.as_slice();
        let node = damage(w.node, cf_name, select);
        assert_fails_the_block(&node, 5, tx.clone(), CORRUPTION);

        let w = native_world();
        garble(&w.node.db, cf_name, select);
        assert_fails_the_block(&w.node, 5, tx, cause);
    }
}

#[test]
fn create_equity_proposal_read_failures_fail_the_block() {
    // The class token, then the class's holder rows. The root and the total are
    // both computed from that one scan; a failed scan stops at the first.
    for cf_name in [cf::EQUITY_TOKENS, cf::EQUITY_BALANCES] {
        let w = equity_world(false);
        let tx = signed(&w.creator, 1, create(GovAssetKind::EquityClass(CLASS)));
        let node = damage(w.node, cf_name, all);
        assert_fails_the_block(&node, 6, tx.clone(), CORRUPTION);

        let w = equity_world(false);
        garble(&w.node.db, cf_name, all);
        assert_fails_the_block(&w.node, 6, tx, UNDECODABLE);
    }
}

#[test]
fn cast_vote_read_failures_fail_the_block() {
    // The proposal, the voter's snapshot row, then the voter's existing vote:
    // the proposer has voted, so its second vote reads its vote row.
    for (cf_name, cause) in [
        (cf::GOV_PROPOSALS, UNDECODABLE),
        (cf::GOV_SNAPSHOTS, "snapshot weight not 16 bytes"),
        (cf::GOV_VOTES, UNDECODABLE),
    ] {
        let tx = |w: &Src20| {
            if cf_name == cf::GOV_VOTES {
                signed(&w.proposer, 2, vote(w.pid))
            } else {
                signed(&w.holder, 0, vote(w.pid))
            }
        };
        let w = src20_world();
        let (t, holder) = (tx(&w), w.holder.address());
        let select = |k: &[u8]| cf_name != cf::GOV_SNAPSHOTS || k.ends_with(holder.as_bytes());
        let node = damage(w.node, cf_name, select);
        assert_fails_the_block(&node, 20, t.clone(), CORRUPTION);

        let w = src20_world();
        garble(&w.node.db, cf_name, select);
        assert_fails_the_block(&w.node, 20, t, cause);
    }
}

#[test]
fn execute_proposal_read_failures_fail_the_block() {
    // The proposal, the snapshot list, then the vote list.
    for (cf_name, cause) in [
        (cf::GOV_PROPOSALS, UNDECODABLE),
        (cf::GOV_SNAPSHOTS, "snapshot weight not 16 bytes"),
        (cf::GOV_VOTES, UNDECODABLE),
    ] {
        let w = src20_world();
        let tx = signed(&w.outsider, 0, execute(w.pid));
        let node = damage(w.node, cf_name, all);
        assert_fails_the_block(&node, 200, tx.clone(), CORRUPTION);

        let w = src20_world();
        garble(&w.node.db, cf_name, all);
        assert_fails_the_block(&w.node, 200, tx, cause);
    }
}

#[test]
fn reserve_release_reserve_read_failure_fails_the_block() {
    // The reserve read in the release's affordability check. Before, a failed
    // read was "no reserve" and the release a fee-paid 385.
    let reserve = |k: &[u8]| k == b"reserve";
    let w = reserve_world();
    let tx = signed(&w.submitter, 1, execute(w.pid));
    let node = damage(w.node, cf::SUPPLY, reserve);
    assert_fails_the_block(&node, 300, tx.clone(), CORRUPTION);

    let w = reserve_world();
    garble(&w.node.db, cf::SUPPLY, reserve);
    assert_fails_the_block(&w.node, 300, tx, UNDECODABLE);
}

#[test]
fn cancel_proposal_read_failure_fails_the_block() {
    let w = src20_world();
    let tx = signed(&w.proposer, 2, cancel(w.pid));
    let node = damage(w.node, cf::GOV_PROPOSALS, all);
    assert_fails_the_block(&node, 20, tx.clone(), CORRUPTION);

    let w = src20_world();
    garble(&w.node.db, cf::GOV_PROPOSALS, all);
    assert_fails_the_block(&w.node, 20, tx, UNDECODABLE);
}

#[test]
fn cast_equity_vote_read_failures_fail_the_block() {
    // The proposal, the class token, the frozen root, then the holder rows the
    // Merkle check reads.
    for cf_name in
        [cf::GOV_PROPOSALS, cf::EQUITY_TOKENS, cf::GOV_EQUITY_CLASS_ROOTS, cf::EQUITY_BALANCES]
    {
        let w = equity_world(false);
        let tx = w.vote.clone();
        let node = damage(w.node, cf_name, all);
        assert_fails_the_block(&node, 10, tx.clone(), CORRUPTION);

        let w = equity_world(false);
        garble(&w.node.db, cf_name, all);
        assert_fails_the_block(&w.node, 10, tx, UNDECODABLE);
    }

    // The used-commitment check. A present row is all it reads, so there is no
    // stored value to fail to decode; only the read itself can fail.
    let w = equity_world(true);
    let tx = w.dup.clone();
    let node = damage(w.node, cf::GOV_EQUITY_USED_COMMITMENTS, all);
    assert_fails_the_block(&node, 11, tx, CORRUPTION);
}

// ── (a) Service grants: a failed read fails the block ────────────────────────

#[test]
fn validator_grant_claim_read_failures_fail_the_block() {
    // A second validator's first claim: the validator set, the cohort count,
    // then the pool and the aggregate the award reads.
    let cases: [(&str, &[u8]); 4] = [
        (cf::VALIDATORS, b""),
        (cf::SUPPLY, b"validator_cohort"),
        (cf::SUPPLY, b"reserve"),
        (cf::SUPPLY, b"aggregate"),
    ];
    for (cf_name, row) in cases {
        let select = |k: &[u8]| row.is_empty() || k == row;
        let w = grants_world();
        let tx = signed(&w.v2, 0, claim(ServiceKind::Validator));
        let node = damage(w.node, cf_name, select);
        assert_fails_the_block(&node, 120, tx.clone(), CORRUPTION);

        let w = grants_world();
        garble(&w.node.db, cf_name, select);
        assert_fails_the_block(&w.node, 120, tx, UNDECODABLE);
    }
}

/// `v` already holds its grant. Before, a failed read of that grant was "no
/// grant": the one-grant-per-identity check passed and the second claim went on
/// to the award.
#[test]
fn a_grant_read_failure_never_pays_a_second_validator_grant() {
    for garbled in [false, true] {
        let w = grants_world();
        let tx = signed(&w.v, 1, claim(ServiceKind::Validator));
        let row = grant_key(&w.v.address(), ServiceKind::Validator);
        let store = SupplyStore::new(w.node.db.clone());
        let pool = store.get_reserve().unwrap().unwrap().validator_pool_remaining;
        let cohort = store.validator_cohort_count().unwrap();
        drop(store);

        let node = if garbled {
            garble(&w.node.db, cf::SUPPLY, |k| k == row.as_slice());
            w.node
        } else {
            damage(w.node, cf::SUPPLY, |k| k == row.as_slice())
        };
        let cause = if garbled { UNDECODABLE } else { CORRUPTION };
        assert_fails_the_block(&node, 120, tx, cause);

        let store = SupplyStore::new(node.db.clone());
        assert_eq!(store.get_reserve().unwrap().unwrap().validator_pool_remaining, pool);
        assert_eq!(store.validator_cohort_count().unwrap(), cohort);
    }
}

/// The provider's grant is forfeited. Before, a failed read of it skipped the
/// suspended-or-forfeited check, and the claim went on to its milestone award.
#[test]
fn a_grant_read_failure_never_skips_the_suspended_check() {
    for garbled in [false, true] {
        let (node, c) = compute_world(true);
        let tx = signed(&c, 0, claim(ServiceKind::Compute));
        let row = grant_key(&c.address(), ServiceKind::Compute);
        let pool = SupplyStore::new(node.db.clone())
            .get_reserve()
            .unwrap()
            .unwrap()
            .compute_pool_remaining;

        let node = if garbled {
            garble(&node.db, cf::SUPPLY, |k| k == row.as_slice());
            node
        } else {
            damage(node, cf::SUPPLY, |k| k == row.as_slice())
        };
        let cause = if garbled { UNDECODABLE } else { CORRUPTION };
        assert_fails_the_block(&node, 110, tx, cause);

        let reserve = SupplyStore::new(node.db.clone()).get_reserve().unwrap().unwrap();
        assert_eq!(reserve.compute_pool_remaining, pool, "nothing paid");
    }
}

#[test]
fn milestone_claim_read_failures_fail_the_block() {
    // The milestone counters (compute), then the node record and the ledger
    // (archive).
    let (node, c) = compute_world(false);
    let counters = milestone_key(&c.address(), ServiceKind::Compute);
    let select = |k: &[u8]| k == counters.as_slice();
    let tx = signed(&c, 0, claim(ServiceKind::Compute));
    let node = damage(node, cf::SUPPLY, select);
    assert_fails_the_block(&node, 110, tx.clone(), CORRUPTION);
    let (node, _) = compute_world(false);
    garble(&node.db, cf::SUPPLY, select);
    assert_fails_the_block(&node, 110, tx, UNDECODABLE);

    // The node record is `b'N' || address`.
    let node_row = [&[b'N'][..], key(0x61).address().as_bytes()].concat();
    let cases: [(&str, &[u8]); 2] = [(cf::NODE_REGISTRY, &node_row), (cf::SUPPLY, b"ledger")];
    for (cf_name, row) in cases {
        let select = |k: &[u8]| k == row;
        let (node, a) = archive_world();
        let tx = signed(&a, 1, claim(ServiceKind::Archive));
        let node = damage(node, cf_name, select);
        assert_fails_the_block(&node, 102, tx.clone(), CORRUPTION);

        let (node, _) = archive_world();
        garble(&node.db, cf_name, select);
        assert_fails_the_block(&node, 102, tx, UNDECODABLE);
    }
}

#[test]
fn unlock_read_failures_fail_the_block() {
    // The grant, then the earned credit. Before, a failed grant read was "no
    // grant" (383) and a failed credit read a fee-paid 384.
    let grant = |w: &Grants| grant_key(&w.v.address(), ServiceKind::Validator);
    let credit = |w: &Grants| credit_key(&w.v.address(), ServiceKind::Validator);
    for row in [grant, credit] {
        let w = grants_world();
        let tx = signed(&w.v, 1, unlock(ServiceKind::Validator));
        let key = row(&w);
        let node = damage(w.node, cf::SUPPLY, |k| k == key.as_slice());
        assert_fails_the_block(&node, 120, tx.clone(), CORRUPTION);

        let w = grants_world();
        garble(&w.node.db, cf::SUPPLY, |k| k == key.as_slice());
        assert_fails_the_block(&w.node, 120, tx, UNDECODABLE);
    }
}

// ── (c) A failed read after a staged write ───────────────────────────────────

/// The unlock stages the updated grant, then reads the aggregate. Before, a
/// failed aggregate read was a fee-paid 384 with the grant write left staged in
/// the block. Now the read fails the transaction, the block fails, and the
/// staged write is published nowhere.
#[test]
fn a_failed_read_after_a_staged_grant_write_leaves_no_write() {
    for garbled in [false, true] {
        let w = grants_world();
        let v = w.v.address();
        let tx = signed(&w.v, 1, unlock(ServiceKind::Validator));
        let before = SupplyStore::new(w.node.db.clone())
            .get_grant(&v, ServiceKind::Validator)
            .unwrap()
            .unwrap();
        assert_eq!(before.earned_credit_used_for_unlock, 0);

        let node = if garbled {
            garble(&w.node.db, cf::SUPPLY, |k| k == b"aggregate");
            w.node
        } else {
            damage(w.node, cf::SUPPLY, |k| k == b"aggregate")
        };
        let cause = if garbled { UNDECODABLE } else { CORRUPTION };

        // The write really is staged before the failed read.
        let mut candidate = common::candidate(&node.db);
        let attempted = node.exec.execute_tx_with_validators(
            &mut candidate.view(),
            &tx,
            &validator().address(),
            120,
            1000,
            0,
            &[proposer_pubkey()],
        );
        assert!(attempted.is_err(), "the failed read is an execution error: {attempted:?}");
        let staged = SupplyStore::v_get_grant(&candidate.view(), &v, ServiceKind::Validator)
            .unwrap()
            .unwrap();
        assert_ne!(staged, before, "the grant write was staged before the read failed");
        drop(candidate);

        // The block fails, and the grant is published as it was.
        assert_fails_the_block(&node, 120, tx, cause);
        let after = SupplyStore::new(node.db.clone())
            .get_grant(&v, ServiceKind::Validator)
            .unwrap()
            .unwrap();
        assert_eq!(after, before, "no write");
    }
}

// ── (b) Semantic refusals: receipts and roots unchanged ──────────────────────

#[test]
fn src20_governance_refusals_are_unchanged() {
    let w = src20_world();
    let (p, h, o) = (&w.proposer, &w.holder, &w.outsider);
    let missing = [0xEE; 32];
    let (receipts, block) = w.node.publish_returning(
        20,
        vec![
            signed(o, 0, register_asset([0x7B; 32])), // no such token: 303
            signed(o, 1, create(GovAssetKind::Src20Token([0x7B; 32]))), // not registered: 303
            signed(o, 2, create(GovAssetKind::Src20Token(TOKEN))), // balance 0: 304
            signed(o, 3, vote(missing)),               // no such proposal: 306
            signed(o, 4, vote(w.pid)),                 // no snapshot weight: 308
            signed(p, 2, vote(w.pid)),                 // already voted: 309
            signed(o, 5, execute(missing)),            // no such proposal: 306
            signed(o, 6, execute(w.pid)),              // voting still open: 307
            signed(o, 7, cancel(missing)),             // no such proposal: 306
            signed(h, 0, cancel(w.pid)),               // not the proposer: 306
            signed(h, 1, vote(w.pid)),                 // success
        ],
    );
    let (statuses, root) = outcome(&receipts, &block);
    let f = TxStatus::Failed;
    assert_eq!(
        statuses,
        vec![
            (f(303), FEE),
            (f(303), FEE),
            (f(304), FEE),
            (f(306), FEE),
            (f(308), FEE),
            (f(309), FEE),
            (f(306), FEE),
            (f(307), FEE),
            (f(306), FEE),
            (f(306), FEE),
            (TxStatus::Success, FEE),
        ]
    );
    assert_eq!(root, "0xf213e3bdaf4f158287921c45f29fa157c28c36c862c74076d65368e47b806abb");

    // After the window: the tally reads every snapshot row and vote.
    let (receipts, block) = w.node.publish_returning(200, vec![signed(o, 8, execute(w.pid))]);
    let (statuses, root) = outcome(&receipts, &block);
    assert_eq!(statuses, vec![(TxStatus::Success, FEE)]);
    assert_eq!(root, "0x45dae7185cab0ebcbdcb82c2867817473331111329c972c25c15d3ff21cd211b");
}

#[test]
fn native_governance_refusals_are_unchanged() {
    let w = native_world();
    let (receipts, block) = w.node.publish_returning(
        5,
        vec![
            signed(&w.submitter, 1, register_qualifying([0x52; 32])), // no such token: 316
            signed(&w.submitter, 2, register_qualifying(QTOKEN)),     // success
            signed(&w.creator, 0, create(GovAssetKind::NativeEligibility)), // success
        ],
    );
    let (statuses, root) = outcome(&receipts, &block);
    assert_eq!(
        statuses,
        vec![(TxStatus::Failed(316), FEE), (TxStatus::Success, FEE), (TxStatus::Success, FEE)]
    );
    assert_eq!(root, "0x431f987ef78a63360a42cef41e67bdf24402abb1fc2ba63fc933f4c721e0fee2");
}

#[test]
fn equity_governance_refusals_are_unchanged() {
    let w = equity_world(true);
    let (s, c) = (&w.submitter, &w.creator);
    // `voter2`'s third vote, for a proposal that does not exist.
    let missing = CastEquityVoteRequest {
        proposal_id: [0xEE; 32],
        holder_commitment: [0x22; 32],
        shares: 20,
        merkle_path: vec![],
        controller_pubkey: [0; 32],
        controller_sig: [0; 64],
        choice: VoteChoice::Yes,
    };
    let (receipts, block) = w.node.publish_returning(
        11,
        vec![
            signed(s, 1, register_equity_class([0xED; 32])), // no such class: 317
            signed(c, 1, create(GovAssetKind::EquityClass([0xED; 32]))), // not registered: 317
            w.dup.clone(),      // commitment already used: 309
            w.stranger.clone(), // not a holder of the class: 318
            signed(&key(0x24), 2, gov(GovernanceOperation::CastEquityVote, &missing)), // 306
        ],
    );
    let (statuses, root) = outcome(&receipts, &block);
    let f = TxStatus::Failed;
    assert_eq!(
        statuses,
        vec![(f(317), FEE), (f(317), FEE), (f(309), FEE), (f(318), FEE), (f(306), FEE)]
    );
    assert_eq!(root, "0xfacf3601771ae4629246bf6798c5c005701880464456481ededb09fece20b265");
}

#[test]
fn reserve_release_outcomes_are_unchanged() {
    let w = reserve_world();
    let (receipts, block) = w.node.publish_returning(
        300,
        vec![
            signed(&w.submitter, 1, execute(w.over_pool)), // exceeds the pool: 385
            signed(&w.submitter, 2, execute(w.pid)),       // success
        ],
    );
    let (statuses, root) = outcome(&receipts, &block);
    assert_eq!(statuses, vec![(TxStatus::Failed(385), FEE), (TxStatus::Success, FEE)]);
    assert_eq!(root, "0x3eaf3820ffb2236986c75cb9daf60611886c4190983f29f3da9a31f31d4abad7");
}

#[test]
fn service_grant_refusals_are_unchanged() {
    let w = grants_world();
    let (receipts, block) = w.node.publish_returning(
        120,
        vec![
            signed(&w.outsider, 0, claim(ServiceKind::Validator)), // not a validator: 381
            signed(&w.v, 1, claim(ServiceKind::Validator)),        // already granted: 383
            signed(&w.outsider, 1, unlock(ServiceKind::Validator)), // no grant: 383
            signed(&w.v2, 0, claim(ServiceKind::Validator)),       // success
            signed(&w.v2, 1, unlock(ServiceKind::Validator)),      // no earned credit: 384
            signed(&w.v, 2, unlock(ServiceKind::Validator)),       // success
        ],
    );
    let (statuses, root) = outcome(&receipts, &block);
    let f = TxStatus::Failed;
    assert_eq!(
        statuses,
        vec![
            (f(381), FEE),
            (f(383), FEE),
            (f(383), FEE),
            (TxStatus::Success, FEE),
            (f(384), FEE),
            (TxStatus::Success, FEE),
        ]
    );
    assert_eq!(root, "0x613d6446a66ff662f5e333a76f303d19bd554a0dcd2638930f426ac841a52266");

    let (node, c) = compute_world(true);
    let (receipts, block) = node.publish_returning(110, vec![signed(&c, 0, claim(ServiceKind::Compute))]);
    let (statuses, root) = outcome(&receipts, &block);
    assert_eq!(statuses, vec![(f(386), FEE)], "a forfeited grant claims nothing");
    assert_eq!(root, "0x162fc6a1c7551c48eb824a6923b1c4e88e0d90d2a21cb8aadb953346343a7e6b");

    let (node, c) = compute_world(false);
    let (receipts, block) = node.publish_returning(110, vec![signed(&c, 0, claim(ServiceKind::Compute))]);
    let (statuses, root) = outcome(&receipts, &block);
    assert_eq!(statuses, vec![(TxStatus::Success, FEE)], "a reached milestone pays");
    assert_eq!(root, "0xab2e66f90535ee1c300786acee0a1133c3ba6d52a63ad258448c04c52eeb9b8b");

    let (node, a) = archive_world();
    let outsider = key(0x62);
    common::fund(&node.db, &outsider, 1_000_000);
    let (receipts, block) = node.publish_returning(
        102,
        vec![
            signed(&a, 1, claim(ServiceKind::Archive)),        // no milestone reached: 383
            signed(&outsider, 0, claim(ServiceKind::Archive)), // not an archive node: 381
        ],
    );
    let (statuses, root) = outcome(&receipts, &block);
    assert_eq!(statuses, vec![(f(383), FEE), (f(381), FEE)]);
    assert_eq!(root, "0xdd629d337d1fb7a1ef34b7292398e76424eeb4f42cb2bd4a2c79b89d2f71255e");
}
