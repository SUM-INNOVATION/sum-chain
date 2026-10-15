//! The stored retention trackers (#129) are DORMANT: nothing may read or write
//! retention state through them until the replica and epoch semantics and the
//! limits are decided and an activation is authorized. Wiring them in must be
//! a deliberate change that deletes or rewrites this test.

use std::path::{Path, PathBuf};

const NEEDLES: &[&str] = &[
    "retention_tracker_store",
    "RetentionLayout",
    "TrackerStoreError",
    "start_tracking",
];

/// This crate's own files that may name the seam.
const ALLOWED: &[&str] = &[
    "crates/state/src/retention_tracker_store.rs",
    "crates/state/tests/retention_tracker_store.rs",
    "crates/state/tests/retention_tracker_store_dormant.rs",
];

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

fn repo() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn module() -> String {
    std::fs::read_to_string(repo().join("crates/state/src/retention_tracker_store.rs")).unwrap()
}

/// The module's code outside its unit tests, without comment lines.
fn production_code() -> Vec<String> {
    let text = module();
    text.split("#[cfg(test)]")
        .next()
        .expect("the module has production code")
        .lines()
        .filter(|l| !l.trim_start().starts_with("//"))
        .map(str::to_string)
        .collect()
}

#[test]
fn nothing_outside_the_seam_and_its_tests_names_it() {
    let mut files = Vec::new();
    for entry in std::fs::read_dir(repo().join("crates")).unwrap() {
        let dir = entry.unwrap().path();
        for sub in ["src", "tests", "benches", "examples"] {
            let d = dir.join(sub);
            if d.is_dir() {
                rust_files(&d, &mut files);
            }
        }
    }
    rust_files(&repo().join("scripts"), &mut files);
    assert!(files.len() > 100, "the scan found too few sources");
    let mut hits = Vec::new();
    for f in files {
        let rel = f
            .strip_prefix(repo())
            .unwrap_or(&f)
            .to_string_lossy()
            .replace('\\', "/");
        let rel = rel.trim_start_matches("./").to_string();
        if ALLOWED.iter().any(|a| rel.ends_with(a)) {
            continue;
        }
        let text = std::fs::read_to_string(&f).unwrap();
        for (i, line) in text.lines().enumerate() {
            if !NEEDLES.iter().any(|n| line.contains(n)) {
                continue;
            }
            let declaration = rel.ends_with("crates/state/src/lib.rs")
                && line.trim() == "pub mod retention_tracker_store;";
            if !declaration {
                hits.push(format!("{rel}:{}: {}", i + 1, line.trim()));
            }
        }
    }
    assert!(
        hits.is_empty(),
        "the dormant retention tracker store is referenced:\n{}",
        hits.join("\n")
    );
}

/// No column family is added for trackers: no family name mentions them.
#[test]
fn no_column_family_is_added_for_trackers() {
    let families: Vec<&str> = sumchain_storage::db::ALL_CFS
        .iter()
        .copied()
        .filter(|n| n.contains("retention") || n.contains("tracker"))
        .collect();
    assert!(families.is_empty(), "{families:?}");
}

/// The seam writes only through the `ExecutionView` it is handed: it never
/// opens, commits or batches anything, writes no `Database`, and holds no
/// unwind code (undo is the generic journal's).
#[test]
fn the_seam_writes_only_through_the_execution_view() {
    let code = production_code();
    for forbidden in [
        "WriteBatch",
        "ApplicationOverlay",
        ".batch()",
        ".commit(",
        "db.put(",
        "db.delete(",
        "rocksdb",
        "std::fs",
        "unwind",
    ] {
        assert!(
            !code.iter().any(|l| l.contains(forbidden)),
            "the seam uses {forbidden}"
        );
    }
    for op in [".put(", ".delete("] {
        let lines: Vec<&String> = code.iter().filter(|l| l.contains(op)).collect();
        assert!(!lines.is_empty(), "the scan found no {op}");
        for line in lines {
            assert!(
                line.trim_start().starts_with(&format!("view{op}")),
                "a write not on the view: {line}"
            );
        }
    }
    let text = module();
    let production = text.split("#[cfg(test)]").next().unwrap();
    let writers = [
        "start_tracking",
        "replace_dependencies",
        "stop_tracking",
        "update_state",
        "store_cursor",
    ];
    for name in writers {
        let sig = production
            .split(&format!("pub fn {name}("))
            .nth(1)
            .unwrap_or_else(|| panic!("{name} is missing"));
        let head = sig.split('{').next().unwrap();
        assert!(
            head.contains("view: &mut ExecutionView<'_, '_>"),
            "{name} does not take the execution view"
        );
    }
}

/// The only families the seam names are the ones it refuses or checks
/// against: it chooses no layout.
#[test]
fn the_seam_names_families_only_to_refuse_or_check_them() {
    let code = production_code();
    let named: Vec<&String> = code.iter().filter(|l| l.contains("cf::")).collect();
    for line in &named {
        assert!(
            line.contains("cf::COMPUTE_POOL_STATE, cf::BEACON_STATE")
                || line.contains("cf::STATE && overlap")
                || line.contains("use sumchain_storage::db::{cf"),
            "the seam names a family outside its checks: {line}"
        );
    }
}
