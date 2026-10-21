//! **PROPOSED, NOT RATIFIED.** Tests for the dormant G5 transition module
//! (`validator_set_g5`, #266): the ledger's G5 recommendations Q0, Q1, Q2, Q4
//! and Q5 as code, so they can be reviewed before a decision. Nothing here
//! activates dynamic membership. All data is synthetic.

use std::path::{Path, PathBuf};

use sumchain_primitives::{Block, BlockHeader, Hash};
use sumchain_storage::candidate::{
    BlockJournals, CandidateExecution, ExecutionSubject, JournalRecord,
};
use sumchain_storage::db::{cf, Database};
use sumchain_storage::schema::ACCOUNT_KEY_PREFIX;
use sumchain_storage::validator_set_g5::{
    governing_epoch, require_transition_certified, resolve_set, select_members,
    stage_transition_row, transition_epoch, Candidate, G5Error, Selection, VsetLayout,
};
use sumchain_storage::validator_set_record::ValidatorSetRecord;
use tempfile::TempDir;

const LIMIT: u64 = 1 << 22;
/// N_min = 5 is the ledger's PROPOSAL (the ratified product minimum). The
/// module takes it as a parameter; it defines no value.
const PROPOSED_N_MIN: usize = 5;

fn db() -> (Database, TempDir) {
    let dir = TempDir::new().unwrap();
    (Database::open_default(dir.path()).unwrap(), dir)
}

fn key(b: u8) -> [u8; 32] {
    [b; 32]
}

fn genesis() -> Vec<[u8; 32]> {
    (1..=5).map(key).collect()
}

fn block(parent: Hash, height: u64, tag: u64) -> Block {
    let header = BlockHeader::new(
        parent,
        height,
        1_000 + tag,
        Hash::hash(&tag.to_be_bytes()),
        Hash::hash(b"root"),
        [0u8; 32],
    );
    Block::new(header, Vec::new())
}

fn journals() -> BlockJournals {
    BlockJournals {
        account: JournalRecord::NothingToUndo,
        contract: JournalRecord::NothingToUndo,
        compute_pool: JournalRecord::NothingToUndo,
        beacon: JournalRecord::NothingToUndo,
    }
}

/// Execute `members` as block `height`'s transition row and publish the block.
fn publish_transition(
    d: &Database,
    parent: Hash,
    height: u64,
    l: u64,
    members: Vec<[u8; 32]>,
) -> Result<Block, String> {
    let b = block(parent, height, height);
    let mut cand = CandidateExecution::new(d, LIMIT);
    {
        let mut view = cand.view();
        stage_transition_row(&mut view, height, l, members).map_err(|e| e.to_string())?;
    }
    cand.finish_execution(
        ExecutionSubject::of(&b).unwrap(),
        b.header.state_root,
        Vec::new(),
        journals(),
    )
    .accept_imported(&b)
    .map_err(|e| e.to_string())?
    .publish()
    .map_err(|e| e.to_string())?;
    Ok(b)
}

fn cand(b: u8, total: u128) -> Candidate {
    Candidate {
        pubkey: key(b),
        active: true,
        jailed: false,
        self_stake: total,
        delegated: 0,
    }
}

// ── Q1: which blocks write, and which epoch ─────────────────────────────────

#[test]
fn q1_only_the_last_block_of_an_epoch_writes_the_next_epochs_row() {
    for l in [1u64, 3, 4, 10] {
        for t in 0..(5 * l) {
            let expected = ((t + 1) % l == 0).then_some((t + 1) / l);
            assert_eq!(transition_epoch(t, l), expected, "L={l} T={t}");
            if let Some(e) = expected {
                assert!(e >= 1, "epoch 0 is never written (it is genesis)");
            }
        }
    }
}

#[test]
fn q1_protocol_v1_epoch_length_zero_never_transitions() {
    for t in 0..1000 {
        assert_eq!(transition_epoch(t, 0), None);
        assert_eq!(governing_epoch(t, 0), 0);
    }
    assert_eq!(transition_epoch(u64::MAX, 4), None, "no overflow");
}

// ── Q0: the set in T's post-state governs T+1 onward ────────────────────────

#[test]
fn q0_the_row_written_by_block_t_governs_from_t_plus_one() {
    let l = 4;
    for t in 0..40u64 {
        if let Some(e) = transition_epoch(t, l) {
            // The first height the new epoch governs is exactly T+1, and the
            // last height of the previous epoch is T itself.
            assert_eq!(governing_epoch(t + 1, l), e);
            assert_eq!(governing_epoch(t, l), e - 1);
        }
    }
}

#[test]
fn q0_q1_resolution_reads_genesis_then_required_rows() {
    let (d, _t) = db();
    let l = 4;
    let g = genesis();
    // Heights below L are governed by the genesis list.
    for h in 0..l {
        assert_eq!(resolve_set(&d, &g, h, l).unwrap(), g);
    }
    // Height L needs row[1], written by block L-1; it is missing: an error,
    // never a genesis fallback.
    assert!(matches!(resolve_set(&d, &g, l, l), Err(G5Error::Row(_))));

    // Publish blocks 1..=3; block 3 (= L-1) writes row[1].
    let mut parent = block(Hash::ZERO, 0, 0).hash();
    for h in 1..l - 1 {
        let b = block(parent, h, h);
        let mut c = CandidateExecution::new(&d, LIMIT);
        let _ = c.view();
        c.finish_execution(
            ExecutionSubject::of(&b).unwrap(),
            b.header.state_root,
            Vec::new(),
            journals(),
        )
        .accept_imported(&b)
        .unwrap()
        .publish()
        .unwrap();
        parent = b.hash();
    }
    let next: Vec<[u8; 32]> = (11..=16).map(key).collect();
    publish_transition(&d, parent, l - 1, l, next.clone()).unwrap();
    for h in l..2 * l {
        assert_eq!(resolve_set(&d, &g, h, l).unwrap(), next, "h={h}");
    }
    // Epoch 2 is still missing.
    assert!(resolve_set(&d, &g, 2 * l, l).is_err());
}

#[test]
fn q1_a_non_transition_block_cannot_write_and_a_row_is_written_once() {
    let (d, _t) = db();
    let l = 4;
    let parent = block(Hash::ZERO, 0, 0).hash();
    let err = publish_transition(&d, parent, 2, l, genesis()).unwrap_err();
    assert!(err.contains("not a transition block"), "{err}");
    let err = publish_transition(&d, parent, 3, 0, genesis()).unwrap_err();
    assert!(err.contains("epoch_length is 0"), "{err}");

    let b3 = publish_transition(&d, parent, 3, l, genesis()).unwrap();
    // A competing block 3 executing over the same committed state would find
    // row[1] occupied: each epoch's row is written once.
    let again = publish_transition(&d, b3.hash(), 3, l, genesis()).unwrap_err();
    assert!(again.contains("already stored"), "{again}");
}

#[test]
fn q0_a_corrupt_or_foreign_row_is_refused() {
    let (d, _t) = db();
    let l = 4;
    let g = genesis();
    // A row stored under epoch 1's key that encodes epoch 2.
    let foreign = ValidatorSetRecord::new(2, g.clone()).unwrap();
    d.put(cf::STATE, &VsetLayout::row_key(1), &foreign.encode())
        .unwrap();
    assert!(resolve_set(&d, &g, l, l).is_err());
    // Garbage bytes.
    d.put(cf::STATE, &VsetLayout::row_key(1), b"not a row")
        .unwrap();
    assert!(resolve_set(&d, &g, l, l).is_err());
}

// ── Q2: governs only once the transition block is certified ────────────────

#[test]
fn q2_a_set_governs_only_after_its_transition_block_is_certified() {
    let l = 4;
    // Genesis epoch needs nothing.
    for h in 0..l {
        require_transition_certified(h, l, None).unwrap();
    }
    // Epoch 1 (heights 4..8) is written by block 3.
    for h in l..2 * l {
        assert!(require_transition_certified(h, l, None).is_err());
        assert!(require_transition_certified(h, l, Some(2)).is_err());
        require_transition_certified(h, l, Some(3)).unwrap();
        require_transition_certified(h, l, Some(100)).unwrap();
    }
    // Epoch 2 (heights 8..12) needs block 7 certified.
    assert!(require_transition_certified(8, l, Some(6)).is_err());
    require_transition_certified(8, l, Some(7)).unwrap();
}

// ── Q4: selection ───────────────────────────────────────────────────────────

#[test]
fn q4_orders_by_total_descending_then_pubkey_ascending() {
    let cands = [
        cand(9, 50),
        cand(3, 100),
        cand(7, 100),
        cand(1, 70),
        cand(5, 100),
        cand(2, 60),
    ];
    let s = select_members(&cands, 0, 10, PROPOSED_N_MIN, &genesis()).unwrap();
    assert_eq!(
        s,
        Selection::Selected(vec![key(3), key(5), key(7), key(1), key(2), key(9)])
    );
}

#[test]
fn q4_filters_inactive_jailed_and_below_minimum_and_counts_delegations() {
    let mut cands: Vec<Candidate> = (1..=7).map(|b| cand(b, 100)).collect();
    cands[0].active = false;
    cands[1].jailed = true;
    cands[2].self_stake = 40; // below 50
    cands[3].self_stake = 20;
    cands[3].delegated = 30; // 20 + 30 = 50: eligible
    let s = select_members(&cands, 50, 10, 4, &genesis()).unwrap();
    assert_eq!(s.members(), &[key(5), key(6), key(7), key(4)]);
}

#[test]
fn q4_truncates_to_max_validators() {
    let cands: Vec<Candidate> = (1..=9).map(|b| cand(b, 100 + u128::from(b))).collect();
    let s = select_members(&cands, 0, 6, PROPOSED_N_MIN, &genesis()).unwrap();
    assert_eq!(
        s.members(),
        &[key(9), key(8), key(7), key(6), key(5), key(4)]
    );
}

#[test]
fn q4_below_n_min_the_previous_set_carries_forward_never_genesis() {
    let previous: Vec<[u8; 32]> = (21..=26).map(key).collect();
    let cands: Vec<Candidate> = (1..=4).map(|b| cand(b, 100)).collect();
    let s = select_members(&cands, 0, 10, PROPOSED_N_MIN, &previous).unwrap();
    assert_eq!(
        s,
        Selection::CarriedForward {
            members: previous.clone(),
            eligible: 4
        }
    );
    assert_ne!(s.members(), genesis().as_slice());
    // Exactly N_min eligible: a new set.
    let cands: Vec<Candidate> = (1..=5).map(|b| cand(b, 100)).collect();
    assert!(matches!(
        select_members(&cands, 0, 10, PROPOSED_N_MIN, &previous).unwrap(),
        Selection::Selected(_)
    ));
    // No previous set to carry: refused.
    assert!(matches!(
        select_members(&[], 0, 10, PROPOSED_N_MIN, &[]),
        Err(G5Error::EmptyPrevious)
    ));
}

#[test]
fn q4_a_duplicated_staking_entry_is_refused_not_counted_twice() {
    let cands = [
        cand(1, 100),
        cand(1, 100),
        cand(2, 90),
        cand(3, 80),
        cand(4, 70),
    ];
    assert!(matches!(
        select_members(&cands, 0, 10, 2, &genesis()),
        Err(G5Error::Record(_))
    ));
}

// ── Q5: layout ──────────────────────────────────────────────────────────────

#[test]
fn q5_rows_live_in_state_under_vset_and_never_in_the_account_range() {
    use sumchain_storage::validator_set_state::ValidatorSetLayout;
    for e in [0u64, 1, 2, 255, 256, u64::MAX] {
        let (family, k) = VsetLayout.row_location(e);
        assert_eq!(family, cf::STATE);
        assert_eq!(&k[..5], b"vset/");
        assert_eq!(&k[5..], &e.to_be_bytes());
        assert!(!k.starts_with(ACCOUNT_KEY_PREFIX));
        assert!(!ACCOUNT_KEY_PREFIX.starts_with(&k[..ACCOUNT_KEY_PREFIX.len().min(k.len())]));
    }
    // Keys sort by epoch.
    assert!(VsetLayout::row_key(1) < VsetLayout::row_key(2));
    assert!(VsetLayout::row_key(255) < VsetLayout::row_key(256));
}

// ── dormancy ────────────────────────────────────────────────────────────────

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            rust_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

/// Nothing outside `sumchain-storage`, and nothing else inside it, names the
/// PROPOSED module. Wiring it is a ratified, authorized change that deletes or
/// rewrites this test.
#[test]
fn the_proposed_g5_module_is_dormant() {
    let storage = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut files = Vec::new();
    for entry in std::fs::read_dir(storage.join("..")).unwrap() {
        let dir = entry.unwrap().path();
        if dir.file_name().is_some_and(|n| n == "storage") {
            continue;
        }
        for sub in ["src", "tests", "benches", "examples"] {
            let d = dir.join(sub);
            if d.is_dir() {
                rust_files(&d, &mut files);
            }
        }
    }
    let mut own = Vec::new();
    rust_files(&storage.join("src"), &mut own);
    files.extend(
        own.into_iter()
            .filter(|f| !f.ends_with("validator_set_g5.rs") && !f.ends_with("lib.rs")),
    );
    assert!(files.len() > 100, "the scan found too few sources");
    let hits: Vec<String> = files
        .iter()
        .filter(|f| {
            std::fs::read_to_string(f)
                .unwrap()
                .contains("validator_set_g5")
        })
        .map(|f| f.display().to_string())
        .collect();
    assert!(
        hits.is_empty(),
        "the PROPOSED G5 module is referenced: {hits:?}"
    );
    let lib = std::fs::read_to_string(storage.join("src/lib.rs")).unwrap();
    let uses: Vec<&str> = lib
        .lines()
        .filter(|l| l.contains("validator_set_g5"))
        .collect();
    assert_eq!(
        uses,
        ["pub mod validator_set_g5;"],
        "lib.rs only declares it"
    );
}
