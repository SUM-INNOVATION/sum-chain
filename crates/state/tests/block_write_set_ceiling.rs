//! The derivation behind `sumchain_state::MAX_BLOCK_WRITE_SET_BYTES`, kept
//! runnable.
//!
//! The constant's doc comment states a derivation. A derivation written in a
//! comment is an assertion about the world that nothing re-checks, and the
//! constant it replaced — `CANDIDATE_LIMIT_SCAFFOLD` — is the standing proof of
//! how that ends: a live consensus parameter whose own doc comment said it was
//! unfit, for as long as nobody had to act on it.
//!
//! So each INPUT to the derivation is a test here, and each of the two sides of
//! the bound is a test here:
//!
//!   * the block limits it is derived against are read out of the repository's
//!     `genesis.json`, not out of `ChainParams::default()`, which differs;
//!   * the validator memory envelope it is derived against is read out of the
//!     deployment manifests that enforce it;
//!   * the SAFETY side — the ceiling must be small enough that one block's peak
//!     live memory stays inside the assumed budget — is arithmetic on the
//!     factors `release_ceiling_allocation.rs` measures;
//!   * the SUFFICIENCY side — the ceiling must be large enough for a block at
//!     the chain's own declared limits, with headroom — is measured by
//!     publishing such a block under a ceiling `MIN_HEADROOM` times smaller
//!     than the real one;
//!   * and the refusal is exercised on the PRODUCTION path, through
//!     `execute_block`, not through a hand-built overlay.
//!
//! Raising the constant fails the safety tests. Lowering it fails the
//! sufficiency test. That is what makes it a bound rather than a number.

mod common;

use std::path::{Path, PathBuf};

use common::{fund, setup_with_params, CHAIN_ID};
use sumchain_crypto::{sign, KeyPair};
use sumchain_genesis::{ChainParams, Genesis};
use sumchain_primitives::{
    Address, Block, BlockHeader, DocClassOperation, DocClassTxData, DocSubcode, Hash, IdentityKey,
    IdentityRoot, IdentityStatus, KeyPurpose, KeyType, SignedTransaction, TransactionV2, TxPayload,
};
use sumchain_state::MAX_BLOCK_WRITE_SET_BYTES;
use sumchain_storage::{cf, DocClassStore};

// ── The derivation's own numbers, named once ────────────────────────────────

/// MEASURED, `crates/state/tests/release_ceiling_allocation.rs`, section M2:
/// one `AddKey` against a committed row of R bytes peaks at 4.00 x R live, at
/// R = 1, 4, 16 and 64 MiB. Peak LIVE, not cumulative churn — the same window
/// churns 5.00 x R, and sizing against churn overstates footprint.
const PEAK_LIVE_FACTOR_NUMERATOR: u64 = 4;

/// MEASURED, same file, same section: the overlay charges 2.00 x R against the
/// ceiling for that transaction, because `put` charges the new value AND the
/// captured pre-image. It follows that the largest single row a block can still
/// commit is `MAX_BLOCK_WRITE_SET_BYTES / 2`.
const CHARGE_FACTOR_NUMERATOR: u64 = 2;

/// RECORDED: the memory limit every validator pod in `deploy/kubernetes` is
/// given. A cgroup limit, enforced by the kernel with an OOM kill — the only
/// one of this repository's three memory figures that a machine checks rather
/// than a document asserts. The test below,
/// `the_recorded_validator_memory_envelope_is_still_what_the_derivation_assumed`,
/// re-reads it from the manifests.
const VALIDATOR_MEMORY_ENVELOPE: u64 = 4 << 30;

/// ASSUMED: the share of that envelope one block's execution may claim.
///
/// A judgement, not a measurement, and the one number in the derivation a
/// reviewer with better data should move. The reasoning: a validator inside
/// 4 GiB is also holding RocksDB's block cache and memtables, a mempool, p2p
/// buffers and the node's own steady state, which
/// `docs/architecture/performance-guide.md` puts at about 1.5 GB; the remaining
/// headroom has to absorb importing one block while producing another, with a
/// compaction landing during both. One block takes a quarter of that headroom.
const BLOCK_EXECUTION_BUDGET_DIVISOR: u64 = 8;

/// The sufficiency margin demanded of the ceiling: a block at the chain's own
/// declared limits must publish under a ceiling this many times smaller than
/// the real one.
///
/// Sixteen rather than two because the failure mode being bought off is a
/// proposer building a block every validator then refuses, and the thing that
/// grows a write set is the chain's data, not its configuration. A margin that
/// only just holds today is a margin that stops holding without anybody
/// editing this file.
const MIN_HEADROOM: u64 = 16;

// ── Fixtures ────────────────────────────────────────────────────────────────

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("crates/state -> crates -> repository root")
        .to_path_buf()
}

fn params() -> ChainParams {
    let mut p = ChainParams::with_v2_enabled();
    if let Some(ref mut d) = p.docclass {
        d.min_issuer_stake = 0;
    }
    p
}

fn key_with_id(id: String) -> IdentityKey {
    IdentityKey {
        key_id: id,
        key_type: KeyType::Ed25519,
        public_key: [7u8; 32],
        purposes: vec![KeyPurpose::Authentication],
        added_at: 1_000,
        expires_at: 0,
        active: true,
    }
}

fn identity(identity_id: [u8; 32], controller: Address) -> IdentityRoot {
    IdentityRoot {
        identity_id,
        subject_commitment: [0x40; 32],
        controller,
        additional_controllers: vec![],
        keys: vec![],
        services: vec![],
        created_at: 1_000,
        updated_at: 1_000,
        status: IdentityStatus::Active,
        schema_hash: [0u8; 32],
    }
}

#[derive(serde::Serialize)]
struct AddKeyData {
    identity_id: [u8; 32],
    key: IdentityKey,
}

fn docclass_tx(
    kp: &KeyPair,
    nonce: u64,
    operation: DocClassOperation,
    payload: &impl serde::Serialize,
) -> SignedTransaction {
    let t = TransactionV2 {
        chain_id: CHAIN_ID,
        from: kp.address(),
        fee: 1_000,
        nonce,
        payload: TxPayload::DocClass(DocClassTxData {
            operation,
            subcode: DocSubcode::IdentityRoot,
            data: bincode::serialize(payload).unwrap(),
            recipient: Address::ZERO,
        }),
    };
    let sig = sign(t.signing_hash().as_bytes(), kp.private_key());
    SignedTransaction::new_v2(t, *sig.as_bytes(), *kp.public_key().as_bytes())
}

fn transfer_tx(kp: &KeyPair, nonce: u64, to: Address, amount: u128) -> SignedTransaction {
    let t = TransactionV2 {
        chain_id: CHAIN_ID,
        from: kp.address(),
        fee: 1_000,
        nonce,
        payload: TxPayload::Transfer { to, amount },
    };
    let sig = sign(t.signing_hash().as_bytes(), kp.private_key());
    SignedTransaction::new_v2(t, *sig.as_bytes(), *kp.public_key().as_bytes())
}

fn block_of(height: u64, proposer_pubkey: &[u8; 32], txs: Vec<SignedTransaction>) -> Block {
    let header = BlockHeader::new(
        Hash::ZERO,
        height,
        1000,
        Hash::ZERO,
        Hash::ZERO,
        *proposer_pubkey,
    );
    Block::new(header, txs)
}

/// The identity id the `n`th seeded row is keyed by. Distinct per row, because
/// the point of the multi-row fixtures is many DISTINCT keys: the overlay
/// charges a pre-image once per key, so reusing one id would charge one row.
fn ident(n: usize) -> [u8; 32] {
    let mut id = [0xE0u8; 32];
    id[..8].copy_from_slice(&(n as u64).to_be_bytes());
    id
}

// ── 1. The inputs, re-read from the sources the derivation cites ────────────

/// The block limits the derivation was taken against are still what this
/// repository's `genesis.json` declares.
///
/// `ChainParams::default()` carries different values (1,000,000 bytes) and is
/// NOT the configuration a node of this repository runs. Reading the shipped
/// document rather than the struct default is the whole point: a derivation
/// against the wrong limits is a derivation about a different chain.
#[test]
fn the_block_limits_the_derivation_was_taken_against_are_still_what_genesis_json_declares() {
    let path = repo_root().join("genesis.json");
    let genesis = Genesis::from_file(&path).expect("the repository's genesis.json must load");

    println!(
        "genesis.json: max_block_bytes {}, max_txs_per_block {}, min_fee {}",
        genesis.params.max_block_bytes, genesis.params.max_txs_per_block, genesis.params.min_fee
    );

    assert_eq!(
        genesis.params.max_block_bytes, 2_000_000,
        "MAX_BLOCK_WRITE_SET_BYTES was derived against a 2,000,000-byte block \
         limit. This file now declares a different one, so the sufficiency side \
         of the derivation was taken against a block size that no longer exists \
         and has to be re-taken."
    );
    assert_eq!(
        genesis.params.max_txs_per_block, 1_000,
        "MAX_BLOCK_WRITE_SET_BYTES was derived against a 1,000-transaction \
         block limit, which is what bounds the number of distinct rows one \
         block can charge a pre-image for. Re-take the derivation."
    );
    assert_ne!(
        genesis.params.max_block_bytes,
        ChainParams::default().max_block_bytes,
        "these are expected to differ; if they stop differing, the reason this \
         test reads the FILE rather than the struct default has quietly gone \
         away and the next reader will not know it was ever load-bearing"
    );
}

/// The validator memory envelope the derivation assumes is still the one the
/// deployment manifests enforce.
///
/// This is the ASSUMED input, and it is the one a reader is most entitled to
/// challenge, so it is pinned to something a machine enforces rather than to a
/// sentence. `limits.memory` in a Kubernetes pod spec is a cgroup limit: a node
/// that exceeds it is OOM-killed, which is the failure this ceiling exists to
/// prevent.
#[test]
fn the_recorded_validator_memory_envelope_is_still_what_the_derivation_assumed() {
    let manifests = [
        "deploy/kubernetes/statefulset.yaml",
        "deploy/kubernetes/statefulset-validator-1.yaml",
        "deploy/kubernetes/statefulset-validator-2.yaml",
        "deploy/kubernetes/statefulset-validator-3.yaml",
    ];
    let root = repo_root();
    for manifest in manifests {
        let text = std::fs::read_to_string(root.join(manifest))
            .unwrap_or_else(|e| panic!("{manifest} must be readable: {e}"));
        assert!(
            text.contains("memory: \"4Gi\""),
            "{manifest} no longer sets a 4Gi memory limit. \
             MAX_BLOCK_WRITE_SET_BYTES is derived from that envelope \
             (VALIDATOR_MEMORY_ENVELOPE here), so the ceiling has to be \
             re-derived against whatever replaced it."
        );
    }
    println!(
        "validator memory envelope: {} B ({} GiB), from {} deployment manifests",
        VALIDATOR_MEMORY_ENVELOPE,
        VALIDATOR_MEMORY_ENVELOPE >> 30,
        manifests.len()
    );
}

// ── 2. The safety side: the ceiling is small enough ─────────────────────────

/// One block's worst-case peak LIVE memory stays inside the assumed budget.
///
/// Arithmetic on the two measured factors, stated here so that raising the
/// ceiling fails a test rather than passing review.
///
/// The largest single row a block can still commit is `C / 2`, because the
/// overlay charges the new value and the captured pre-image. During the
/// transaction that commits it, peak live is `4.00 x (C/2)`, of which
/// `2.00 x (C/2)` is the overlay's own retained charge; with the overlay
/// otherwise at its limit, the total is `C + 2.00 x (C/2) = 2C`.
#[test]
fn the_ceiling_keeps_one_blocks_peak_live_memory_inside_the_assumed_budget() {
    let c = MAX_BLOCK_WRITE_SET_BYTES;
    let largest_committable_row = c / CHARGE_FACTOR_NUMERATOR;
    let transient =
        largest_committable_row * (PEAK_LIVE_FACTOR_NUMERATOR - CHARGE_FACTOR_NUMERATOR);
    let peak_live = c + transient;
    let budget = VALIDATOR_MEMORY_ENVELOPE / BLOCK_EXECUTION_BUDGET_DIVISOR;

    println!(
        "SAFETY: ceiling {c} B ({} MiB); largest committable row {largest_committable_row} B; \
         worst-case peak live {peak_live} B ({} MiB) = {:.1}% of the {} B cgroup envelope; \
         budget {budget} B ({} MiB)",
        c >> 20,
        peak_live >> 20,
        100.0 * peak_live as f64 / VALIDATOR_MEMORY_ENVELOPE as f64,
        VALIDATOR_MEMORY_ENVELOPE,
        budget >> 20,
    );

    assert!(
        peak_live <= budget,
        "a block at the ceiling peaks at {peak_live} B live, above the \
         {budget} B this derivation allots one block's execution out of the \
         {VALIDATOR_MEMORY_ENVELOPE} B cgroup limit the validator manifests \
         enforce. Either the ceiling is too large or the budget assumption has \
         to be restated and defended — it must not be crossed silently, because \
         the failure on the other side is an OOM kill on the validator with \
         less memory while the one with more follows the chain."
    );
}

/// The ceiling is folded into the protocol digest, so two binaries holding
/// different ceilings cannot report the same one.
///
/// Stated here as well as in `protocol_digest_mismatched_binaries.rs` because
/// it is half of why this value may be a compiled-in constant at all: the other
/// half — that no digest covers a plain `ChainParams` field — is why it is not
/// one.
#[test]
fn the_ceiling_is_folded_into_the_protocol_digest_by_name() {
    let limits = sumchain_state::protocol_digest::consensus_limits();
    let entry = limits
        .iter()
        .find(|(n, _)| *n == "MAX_BLOCK_WRITE_SET_BYTES")
        .expect(
            "the ceiling decides whether a block is applicable, so it must be \
             folded into the protocol digest; unfolded, two binaries enforcing \
             different block validity report the same digest and the \
             comparison operators are told to make cannot fail",
        );
    assert_eq!(
        entry.1,
        sumchain_state::protocol_digest::LimitValue::Num(MAX_BLOCK_WRITE_SET_BYTES as u128),
        "the digest must fold the ceiling this binary actually enforces, not a \
         copy of it that can drift"
    );
}

// ── 3. The sufficiency side: the ceiling is large enough ────────────────────

/// What one block costs, measured end to end on the production path.
struct BlockCost {
    /// MEASURED: `ExecutedCandidate::logical_bytes` after `execute_block` —
    /// every write the transactions made plus every pre-image they captured,
    /// charged against the ceiling.
    execution: u64,
    /// MEASURED: the encoded application-journal record this block committed,
    /// read back out of its column family after publication. Reported rather
    /// than asserted on: it is the term a reader most expects to dominate, and
    /// it does not.
    journal: u64,
    /// MEASURED: the block record this block committed.
    block_record: u64,
}

/// Execute and publish `txs` as one block on the production path, and report
/// what it cost.
///
/// The ceiling is NOT a parameter, and that is the point: `execute_block`
/// builds its candidate with `MAX_BLOCK_WRITE_SET_BYTES` and nothing can hand
/// it another value, so this measures the block under the rule a release node
/// enforces rather than under one a test chose.
fn measure_block(
    build: impl FnOnce(&KeyPair) -> Vec<SignedTransaction>,
) -> BlockCost {
    let (state, db, _dir, executor) = setup_with_params(params());
    let actor = KeyPair::generate();
    fund(&db, &actor, 1_000_000_000_000_000);
    let txs = build(&actor);
    let mut block = block_of(1, &[9u8; 32], txs);

    let exec = executor
        .execute_block(&block, state.state_root(), &[])
        .expect(
            "a block built entirely from valid transactions, at the chain's own \
             declared limits, must be APPLICABLE under the derived ceiling — an \
             Err here is the ceiling refusing a block an honest proposer would \
             build, which is the failure the sufficiency side exists to prevent",
        );
    block.header.state_root = exec.computed_root();
    let (executed, _state_diff, _contract_diff) = exec.into_parts();
    let execution = executed.logical_bytes();
    let accepted = executed
        .accept_produced(&block)
        .expect("accept_produced for a block we produced");
    accepted.publish().expect(
        "publication stages the block record, a second copy of every \
         transaction, the receipts, the indexes, the legacy diffs and the \
         application journal through the SAME overlay against the SAME \
         ceiling; an Err here is the ceiling refusing to COMMIT a block it \
         agreed to EXECUTE",
    );

    let journal = db
        .get(
            cf::APPLICATION_JOURNAL,
            &sumchain_storage::schema::journal_key(block.height(), &block.hash()),
        )
        .expect("read the journal record")
        .map_or(0, |v| v.len() as u64);
    let block_record = db
        .get(cf::BLOCKS, block.hash().as_bytes())
        .expect("read the block record")
        .map_or(0, |v| v.len() as u64);

    BlockCost {
        execution,
        journal,
        block_record,
    }
}

/// A block at the chain's own declared limits is applicable under the derived
/// ceiling, with the derived headroom.
///
/// Two blocks, because two different limits bind. `validate_block` enforces
/// both, and `PoaEngine::do_import_block` calls it BEFORE `execute_block`, so
/// both really do bound a payload before any executor decodes it:
///
///   * the TRANSACTION-COUNT bound: `max_txs_per_block` transfers, the largest
///     number of distinct accounts, receipts and journal entries one block can
///     produce;
///   * the BLOCK-BYTES bound: `CreateIdentityRoot` payloads filling the block
///     to just under `max_block_bytes`, the largest number of VALUE bytes one
///     block can carry.
///
/// The assertion is on `execution + PUBLICATION_ALLOWANCE`, not on `execution`
/// alone. `execute_block`'s ceiling is shared with `publish`, which afterwards
/// stages the block record, a second copy of every transaction, the receipts,
/// the sender and recipient indexes, the two populated legacy diffs and the
/// application journal through the same overlay. Every one of those is a NEW
/// key, so each charges `2 x key + value` with no pre-image, and every one of
/// them is bounded by the block's own size. Four times `max_block_bytes`
/// covers all of them with room, and the journal — the term a reader expects to
/// dominate — is measured here and printed so the allowance can be checked
/// rather than believed.
#[test]
fn a_full_block_at_the_chains_declared_limits_publishes_with_the_derived_headroom() {
    /// STATED, with the reasoning in the doc comment above: an upper bound on
    /// what `publish` stages on top of what `execute_block` staged.
    const PUBLICATION_ALLOWANCE: u64 = 4 * 2_000_000;

    // ── the transaction-count bound ─────────────────────────────────────────
    //
    // A DISTINCT recipient per transaction, which is the whole point of this
    // bound. The overlay charges a key and its pre-image ONCE per distinct key
    // and only adjusts the value delta when a buffered entry is replaced, so
    // 1,000 transfers to one address charge three account rows, not a
    // thousand — a fixture that would report a write set two hundred times
    // smaller than the bound it claims to measure.
    let count_bound = measure_block(|actor| {
        (0..1_000u64)
            .map(|n| {
                let mut bytes = [3u8; 20];
                bytes[..8].copy_from_slice(&n.to_be_bytes());
                transfer_tx(actor, n, Address::new(bytes), 1)
            })
            .collect()
    });

    // ── the block-bytes bound ───────────────────────────────────────────────
    //
    // One `key_id` string per transaction carries the weight, so the block is
    // filled with VALUE bytes rather than with transaction framing. Ten
    // transactions of 190,000 bytes each is 1.9 MB, just under the 2,000,000
    // byte limit with room for the header and the envelopes.
    let byte_bound = measure_block(|actor| {
        (0..10u64)
            .map(|n| {
                let mut root = identity(ident(n as usize), actor.address());
                root.keys = vec![key_with_id("x".repeat(190_000))];
                docclass_tx(actor, n, DocClassOperation::CreateIdentityRoot, &root)
            })
            .collect()
    });

    for (what, cost) in [
        ("transaction-count bound, 1000 transfers to distinct recipients", &count_bound),
        ("block-bytes bound, ~1.9 MB of payload", &byte_bound),
    ] {
        let total = cost.execution + PUBLICATION_ALLOWANCE;
        let headroom = MAX_BLOCK_WRITE_SET_BYTES as f64 / total as f64;
        println!(
            "SUFFICIENCY, {what}: execution charged {} B (MEASURED); journal \
             record {} B, block record {} B (MEASURED); + {PUBLICATION_ALLOWANCE} B \
             publication allowance (STATED) = {total} B against a \
             {MAX_BLOCK_WRITE_SET_BYTES} B ceiling — headroom {headroom:.1}x",
            cost.execution, cost.journal, cost.block_record,
        );
        assert!(
            cost.journal < PUBLICATION_ALLOWANCE,
            "the application journal alone ({} B) must be well inside the \
             {PUBLICATION_ALLOWANCE} B allowance this test grants the whole of \
             publication, or the allowance is not an allowance",
            cost.journal
        );
        assert!(
            MAX_BLOCK_WRITE_SET_BYTES >= total.saturating_mul(MIN_HEADROOM),
            "a block at the {what} costs at most {total} B, and the derived \
             ceiling of {MAX_BLOCK_WRITE_SET_BYTES} B clears that by only \
             {headroom:.1}x, under the {MIN_HEADROOM}x margin the derivation \
             claims. A ceiling this close to the block limit means a proposer \
             can build a block of valid transactions that every validator then \
             refuses."
        );
    }
}

// ── 4. The refusal, on the production path ──────────────────────────────────

/// The ceiling refuses a block through `execute_block`, not through a
/// hand-built overlay.
///
/// Every other test of this mechanism in the tree constructs an
/// `ApplicationOverlay` with a ceiling of its own choosing, which proves the
/// overlay works and proves nothing about what a release node enforces. This
/// one goes through the production entry point, so what it exercises is the
/// constant that `execute_block` actually reads.
///
/// The block is built out of MANY MODERATE rows rather than one enormous one on
/// purpose. The charge is the same — a pre-image plus a new value per distinct
/// key — but the peak live memory is one row at a time, so this test crosses a
/// 256 MiB ceiling inside a few hundred megabytes of resident memory instead of
/// the gigabyte a single row at the ceiling would need.
#[test]
fn the_ceiling_refuses_a_block_whose_write_set_crosses_it_through_execute_block() {
    const ROW_BYTES: usize = 1 << 20;
    // Each AddKey charges about 2 x ROW_BYTES (the captured pre-image and the
    // re-encoded row), plus the event row's copy of the key material. Enough
    // rows to carry the charge past the ceiling with margin, so the test does
    // not depend on the per-row constant factor.
    let rows = (MAX_BLOCK_WRITE_SET_BYTES as usize / ROW_BYTES) + 16;

    let (state, db, _dir, executor) = setup_with_params(params());
    let actor = KeyPair::generate();
    fund(&db, &actor, 1_000_000_000_000_000);

    let store = DocClassStore::new(&db);
    for n in 0..rows {
        let mut root = identity(ident(n), actor.address());
        root.keys = vec![key_with_id("x".repeat(ROW_BYTES))];
        store.identity_roots().put(&root).unwrap();
    }
    let seeded = db
        .get(cf::DOCCLASS_IDENTITY_ROOTS, &ident(0))
        .unwrap()
        .expect("the seeded row must be there")
        .len();

    let txs: Vec<SignedTransaction> = (0..rows)
        .map(|n| {
            docclass_tx(
                &actor,
                n as u64,
                DocClassOperation::AddKey,
                &AddKeyData {
                    identity_id: ident(n),
                    key: key_with_id(format!("k{n}")),
                },
            )
        })
        .collect();

    let block = block_of(1, &[9u8; 32], txs);
    let outcome = executor.execute_block(&block, state.state_root(), &[]);

    let err = match outcome {
        Ok(_) => panic!(
            "{rows} AddKey transactions against {seeded}-byte rows charge about \
             {} B, past the {MAX_BLOCK_WRITE_SET_BYTES} B ceiling, and \
             `execute_block` admitted the block anyway. Either the production \
             path stopped reading MAX_BLOCK_WRITE_SET_BYTES or the ceiling has \
             been raised past what the safety derivation allows.",
            rows as u64 * 2 * seeded as u64
        ),
        Err(e) => e,
    };
    let text = err.to_string();
    println!(
        "REFUSAL: {rows} AddKey transactions against {seeded} B rows were \
         refused by execute_block: {text}"
    );
    assert!(
        text.contains("logical byte limit"),
        "the block must be refused BY THE CEILING and not by something else \
         that happens to fail at this size: {text}"
    );
    assert!(
        text.contains(&MAX_BLOCK_WRITE_SET_BYTES.to_string()),
        "the refusal must name the ceiling the production path enforces, \
         {MAX_BLOCK_WRITE_SET_BYTES}: {text}"
    );
}
