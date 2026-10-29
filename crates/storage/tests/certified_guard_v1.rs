//! The certified-finality crossing guard (`certified_guard`, #270, #341):
//! fork choice and rollback never cross the certified block recorded under
//! `finality/finalized/v1`.
//!
//! * reading the pointer is fail-closed: absent means none only when no
//!   certificate row exists; anything unreadable, and certificate rows without a
//!   pointer, are refused, never "no finality";
//! * a reorg is refused exactly when it forks below the certified height, forks
//!   at it on another block, or unwinds a block at or below it (checked
//!   exhaustively over a small grid against an independent oracle);
//! * a rollback is refused exactly when its target is below the certified
//!   height, or at it on another block;
//! * it is consulted by exactly the production code its docs name: the
//!   consensus reorg module (chain switch and rollback).
//!
//! All data is synthetic.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use sumchain_primitives::{BlockHeight, Hash};
use sumchain_storage::certified::FinalizedPointer;
use sumchain_storage::certified_guard::{
    certified_block, refuse_reorg_crossing, refuse_rollback_crossing, CertifiedBlock,
    CrossingRefusal,
};
use sumchain_storage::certified_meta::{
    certificate_key, encode_pointer, CERTIFICATE_KEY_PREFIX, FINALIZED_POINTER_KEY,
};
use sumchain_storage::db::{cf, Database};
use tempfile::TempDir;

fn hash(tag: u8, height: BlockHeight) -> Hash {
    let mut b = [0u8; 32];
    b[0] = tag;
    b[1..9].copy_from_slice(&height.to_be_bytes());
    Hash::from_slice(&b).unwrap()
}

/// Canonical block at `h` is tagged 0xC0; a competing block is tagged 0xF0.
fn canonical(h: BlockHeight) -> Hash {
    hash(0xC0, h)
}

fn competing(h: BlockHeight) -> Hash {
    hash(0xF0, h)
}

fn certified(h: BlockHeight) -> CertifiedBlock {
    CertifiedBlock {
        height: h,
        hash: canonical(h),
    }
}

fn db() -> (TempDir, Database) {
    let dir = TempDir::new().unwrap();
    let db = Database::open_default(dir.path()).unwrap();
    (dir, db)
}

// ── reading the pointer ─────────────────────────────────────────────────────

#[test]
fn an_absent_pointer_means_no_certified_block() {
    let (_d, db) = db();
    assert_eq!(certified_block(&db).unwrap(), None);
}

#[test]
fn a_stored_pointer_is_read_exactly() {
    let (_d, db) = db();
    let p = FinalizedPointer {
        height: 7,
        hash: canonical(7),
    };
    db.put(cf::META, FINALIZED_POINTER_KEY, &encode_pointer(&p))
        .unwrap();
    assert_eq!(certified_block(&db).unwrap(), Some(certified(7)));
}

#[test]
fn an_undecodable_pointer_is_refused_not_treated_as_absent() {
    let p = FinalizedPointer {
        height: 7,
        hash: canonical(7),
    };
    let good = encode_pointer(&p);
    for bad in [
        Vec::new(),
        good[..39].to_vec(),
        [good.as_slice(), &[0u8]].concat(),
        vec![0xFF; 8],
    ] {
        let (_d, db) = db();
        db.put(cf::META, FINALIZED_POINTER_KEY, &bad).unwrap();
        match certified_block(&db) {
            Err(CrossingRefusal::UnreadablePointer(_)) => {}
            other => panic!(
                "{} bytes: expected UnreadablePointer, got {other:?}",
                bad.len()
            ),
        }
    }
}

#[test]
fn certificate_rows_without_a_pointer_are_refused() {
    let (_d, db) = db();
    db.put(cf::META, &certificate_key(7, &canonical(7)), b"cert")
        .unwrap();
    assert_eq!(
        certified_block(&db),
        Err(CrossingRefusal::CertificatesWithoutPointer { height: Some(7) })
    );
    let msg = certified_block(&db).unwrap_err().to_string();
    assert!(msg.contains("pointer is absent"), "{msg}");
}

#[test]
fn a_malformed_row_under_the_prefix_without_a_pointer_is_refused() {
    let (_d, db) = db();
    // Keys are built from the prefix: no `finality/` literal outside the layout.
    let malformed = [CERTIFICATE_KEY_PREFIX, b"xyz"].concat();
    db.put(cf::META, &malformed, b"cert").unwrap();
    assert_eq!(
        certified_block(&db),
        Err(CrossingRefusal::CertificatesWithoutPointer { height: None })
    );
}

#[test]
fn keys_outside_the_prefix_do_not_count_as_certificates() {
    let (_d, db) = db();
    // Neighbours that sort after the prefix but are not under it, built from
    // the prefix (`.../cert/v2/...` and `...certz`).
    let mut v2 = CERTIFICATE_KEY_PREFIX.to_vec();
    let n = v2.len();
    v2[n - 2] = b'2';
    v2.extend_from_slice(b"0000");
    let certz = [&CERTIFICATE_KEY_PREFIX[..n - 4], b"z"].concat();
    assert!(!v2.starts_with(CERTIFICATE_KEY_PREFIX) && !certz.starts_with(CERTIFICATE_KEY_PREFIX));
    assert!(v2.as_slice() > CERTIFICATE_KEY_PREFIX && certz.as_slice() > CERTIFICATE_KEY_PREFIX);
    db.put(cf::META, &v2, b"x").unwrap();
    db.put(cf::META, &certz, b"x").unwrap();
    db.put(cf::META, b"finalized_height", &9u64.to_be_bytes())
        .unwrap();
    assert_eq!(certified_block(&db).unwrap(), None);
}

#[test]
fn a_pointer_with_its_certificate_rows_reads_normally() {
    let (_d, db) = db();
    for h in [3u64, 5, 7] {
        db.put(cf::META, &certificate_key(h, &canonical(h)), b"cert")
            .unwrap();
    }
    let p = FinalizedPointer {
        height: 7,
        hash: canonical(7),
    };
    db.put(cf::META, FINALIZED_POINTER_KEY, &encode_pointer(&p))
        .unwrap();
    assert_eq!(certified_block(&db).unwrap(), Some(certified(7)));
}

#[test]
fn the_legacy_local_depth_records_are_not_read() {
    use sumchain_storage::schema::meta_keys;
    let (_d, db) = db();
    db.put(cf::META, meta_keys::FINALIZED_HEIGHT, &9u64.to_be_bytes())
        .unwrap();
    db.put(cf::META, meta_keys::FINALIZED_HASH, canonical(9).as_bytes())
        .unwrap();
    assert_eq!(
        certified_block(&db).unwrap(),
        None,
        "legacy depth-based finality is not certified finality"
    );
}

// ── reorgs ──────────────────────────────────────────────────────────────────

#[test]
fn with_no_certified_block_nothing_is_refused() {
    let unwound = (1..=5).map(|h| (h, canonical(h)));
    assert!(refuse_reorg_crossing(None, 0, &canonical(0), unwound).is_ok());
    assert!(refuse_rollback_crossing(None, 0, &canonical(0)).is_ok());
}

#[test]
fn a_reorg_above_the_certified_block_is_allowed() {
    let c = certified(5);
    // Fork at the certified block itself, unwinding only blocks above it.
    let unwound = (6..=9).map(|h| (h, canonical(h)));
    assert!(refuse_reorg_crossing(Some(&c), 5, &canonical(5), unwound).is_ok());
    // Fork above it.
    let unwound = (8..=9).map(|h| (h, canonical(h)));
    assert!(refuse_reorg_crossing(Some(&c), 7, &canonical(7), unwound).is_ok());
}

#[test]
fn a_reorg_forking_below_the_certified_block_is_refused() {
    let c = certified(5);
    let unwound = (5..=9).map(|h| (h, canonical(h)));
    assert_eq!(
        refuse_reorg_crossing(Some(&c), 4, &canonical(4), unwound),
        Err(CrossingRefusal::ForkBelowCertified {
            fork_height: 4,
            certified: c
        })
    );
}

#[test]
fn a_reorg_forking_at_the_certified_height_on_another_block_is_refused() {
    let c = certified(5);
    assert_eq!(
        refuse_reorg_crossing(Some(&c), 5, &competing(5), std::iter::empty()),
        Err(CrossingRefusal::ForkReplacesCertified {
            fork_hash: competing(5),
            certified: c
        })
    );
}

#[test]
fn a_reorg_unwinding_the_certified_block_is_refused_even_with_a_high_fork_claim() {
    // A caller that reports a fork point above the certified height but lists
    // the certified block among the unwound blocks is refused.
    let c = certified(5);
    let unwound = [(5, canonical(5)), (6, canonical(6))];
    assert_eq!(
        refuse_reorg_crossing(Some(&c), 6, &canonical(6), unwound),
        Err(CrossingRefusal::UnwindsCertified {
            height: 5,
            certified: c
        })
    );
}

/// Exhaustive over a small grid, against an independent statement of the rule:
/// a switch keeping ancestor `fork` and abandoning `fork+1..=old_head` crosses
/// certified block `c` iff `fork < c`, or `fork == c` on a different block.
#[test]
fn the_reorg_rule_matches_its_specification_exhaustively() {
    for c_h in 0..=6u64 {
        let c = certified(c_h);
        for fork in 0..=7u64 {
            for old_head in fork..=8u64 {
                for fork_is_canonical in [true, false] {
                    let fork_hash = if fork_is_canonical {
                        canonical(fork)
                    } else {
                        competing(fork)
                    };
                    let unwound: Vec<_> =
                        (fork + 1..=old_head).map(|h| (h, canonical(h))).collect();
                    let crosses = fork < c_h
                        || (fork == c_h && !fork_is_canonical)
                        || unwound.iter().any(|(h, _)| *h <= c_h);
                    let got = refuse_reorg_crossing(Some(&c), fork, &fork_hash, unwound);
                    assert_eq!(
                        got.is_err(),
                        crosses,
                        "c={c_h} fork={fork} head={old_head} canonical={fork_is_canonical}: {got:?}"
                    );
                }
            }
        }
    }
}

// ── rollbacks ───────────────────────────────────────────────────────────────

#[test]
fn the_rollback_rule_matches_its_specification_exhaustively() {
    for c_h in 0..=6u64 {
        let c = certified(c_h);
        for target in 0..=8u64 {
            for target_is_canonical in [true, false] {
                let target_hash = if target_is_canonical {
                    canonical(target)
                } else {
                    competing(target)
                };
                let got = refuse_rollback_crossing(Some(&c), target, &target_hash);
                let crosses = target < c_h || (target == c_h && !target_is_canonical);
                assert_eq!(
                    got.is_err(),
                    crosses,
                    "c={c_h} target={target} canonical={target_is_canonical}: {got:?}"
                );
                if target < c_h {
                    assert_eq!(
                        got,
                        Err(CrossingRefusal::RollbackBelowCertified {
                            target_height: target,
                            certified: c
                        })
                    );
                }
            }
        }
    }
}

#[test]
fn a_rollback_to_the_certified_block_itself_is_allowed() {
    let c = certified(5);
    assert!(refuse_rollback_crossing(Some(&c), 5, &canonical(5)).is_ok());
    assert_eq!(
        refuse_rollback_crossing(Some(&c), 5, &competing(5)),
        Err(CrossingRefusal::RollbackReplacesCertified {
            target_hash: competing(5),
            certified: c
        })
    );
}

#[test]
fn refusals_say_what_was_protected() {
    let c = certified(5);
    let msg = refuse_rollback_crossing(Some(&c), 2, &canonical(2))
        .unwrap_err()
        .to_string();
    assert!(msg.contains("below the certified block 5"), "{msg}");
    let msg = refuse_reorg_crossing(Some(&c), 3, &canonical(3), std::iter::empty())
        .unwrap_err()
        .to_string();
    assert!(msg.contains("forks at block 3"), "{msg}");
}

// ── where it is consulted ───────────────────────────────────────────────────

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

/// Lines of `text` that are code, not comments.
fn code_lines(text: &str) -> impl Iterator<Item = &str> {
    text.lines().filter(|l| !l.trim_start().starts_with("//"))
}

/// The guard is consulted by exactly the production code its module docs
/// name, and by nothing else:
///
/// * `crates/consensus/src/reorg.rs`: the chain-switch check the engine's
///   `import_reorg` calls, and the rollback check `execute_rollback` and the
///   `rollback` command call.
///
/// Inside this crate, no other module calls it. A new caller fails this test
/// until it is added here, with its reason. Production sources only: tests
/// name it freely.
#[test]
fn the_guard_is_consulted_by_fork_choice_and_rollback_only() {
    let crates = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
    let mut scanned = 0usize;
    let mut callers = BTreeSet::new();
    for entry in std::fs::read_dir(&crates).unwrap() {
        let dir = entry.unwrap().path();
        let name = dir.file_name().unwrap().to_string_lossy().into_owned();
        if name == "storage" || !dir.join("src").is_dir() {
            continue;
        }
        let mut files = Vec::new();
        rust_files(&dir.join("src"), &mut files);
        for f in files {
            scanned += 1;
            let text = std::fs::read_to_string(&f).unwrap();
            if code_lines(&text).any(|l| l.contains("certified_guard")) {
                let rel = f.strip_prefix(&dir).unwrap().display().to_string();
                callers.insert(format!("crates/{name}/{rel}"));
            }
        }
    }
    assert!(scanned > 100, "the scan found too few sources");
    let expected: BTreeSet<String> = ["crates/consensus/src/reorg.rs"]
        .into_iter()
        .map(String::from)
        .collect();
    assert_eq!(
        callers, expected,
        "the production callers of the certified-crossing guard changed"
    );

    let storage_src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut own = Vec::new();
    rust_files(&storage_src, &mut own);
    let mut inside = Vec::new();
    for f in own {
        if f.ends_with("certified_guard.rs") {
            continue;
        }
        let text = std::fs::read_to_string(&f).unwrap();
        for line in code_lines(&text).filter(|l| l.contains("certified_guard")) {
            let declaration = f.ends_with("lib.rs") && line.trim() == "pub mod certified_guard;";
            if !declaration {
                inside.push(format!("{}: {}", f.display(), line.trim()));
            }
        }
    }
    assert!(
        inside.is_empty(),
        "the guard is called inside storage: {inside:?}"
    );
}
