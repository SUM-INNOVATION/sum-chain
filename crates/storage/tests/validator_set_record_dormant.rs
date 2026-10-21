//! The validator-set row codec and state seam (#266) are DORMANT: nothing may
//! read or write membership through them until the membership-effective-height
//! and finality rules are decided and an activation is authorized. Wiring
//! either in must be a deliberate change that deletes or rewrites this test.

use std::path::{Path, PathBuf};

const NEEDLES: &[&str] = &[
    "validator_set_record",
    "ValidatorSetRecord",
    "validator_set_state",
    "ValidatorSetLayout",
];

/// The two dormant modules, which may name each other, and the PROPOSED (not
/// ratified) G5 transition module built on them, which is itself dormant:
/// `tests/validator_set_g5_proposed.rs` fails if anything names it.
const MODULES: &[&str] = &[
    "validator_set_record.rs",
    "validator_set_state.rs",
    "validator_set_g5.rs",
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

fn storage() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

#[test]
fn no_crate_outside_storage_names_the_record() {
    let repo = storage().join("../..");
    let mut roots: Vec<PathBuf> = Vec::new();
    for entry in std::fs::read_dir(repo.join("crates")).unwrap() {
        let dir = entry.unwrap().path();
        if dir.file_name().is_some_and(|n| n == "storage") {
            continue;
        }
        roots.push(dir);
    }
    // The one workspace member outside crates/.
    roots.push(repo.join("scripts"));

    let mut files = Vec::new();
    for dir in roots {
        for sub in ["src", "tests", "benches", "examples"] {
            let d = dir.join(sub);
            if d.is_dir() {
                rust_files(&d, &mut files);
            }
        }
    }
    assert!(
        files.len() > 100,
        "the scan found too few sources to mean anything"
    );
    let mut hits = Vec::new();
    for f in files {
        let src = std::fs::read_to_string(&f).unwrap();
        for needle in NEEDLES {
            if src.contains(needle) {
                hits.push(format!("{} names {needle}", f.display()));
            }
        }
    }
    assert!(
        hits.is_empty(),
        "the dormant validator-set record is referenced outside storage:\n{}",
        hits.join("\n")
    );
}

/// Inside storage, only the two modules and their `pub mod` lines name them:
/// no store writes a record, no reader decodes one, and the crate root
/// re-exports nothing.
#[test]
fn nothing_in_storage_uses_the_record() {
    let src = storage().join("src");
    let mut files = Vec::new();
    rust_files(&src, &mut files);
    let mut hits = Vec::new();
    for f in files {
        if MODULES.iter().any(|m| f.ends_with(m)) {
            continue;
        }
        let text = std::fs::read_to_string(&f).unwrap();
        for (i, line) in text.lines().enumerate() {
            if !NEEDLES.iter().any(|n| line.contains(n)) {
                continue;
            }
            let declaration = f.ends_with("lib.rs")
                && matches!(
                    line.trim(),
                    "pub mod validator_set_record;" | "pub mod validator_set_state;"
                );
            if !declaration {
                hits.push(format!("{}:{}: {}", f.display(), i + 1, line.trim()));
            }
        }
    }
    assert!(
        hits.is_empty(),
        "the dormant validator-set record is used inside storage:\n{}",
        hits.join("\n")
    );
}

/// A pure codec: no database handle, no column family, no batch, no file.
#[test]
fn the_record_module_does_no_io() {
    let text = std::fs::read_to_string(storage().join("src/validator_set_record.rs")).unwrap();
    let production = text
        .split("#[cfg(test)]")
        .next()
        .expect("the module has production code");
    for forbidden in [
        "Database",
        "WriteBatch",
        "cf::",
        "rocksdb",
        "std::fs",
        "ValidatorSetStore",
    ] {
        // Prose may name these to say they are not used; code may not.
        let in_code = production
            .lines()
            .filter(|l| !l.trim_start().starts_with("//"))
            .any(|l| l.contains(forbidden));
        assert!(!in_code, "the record module uses {forbidden}");
    }
}

/// No column family is added for the rows: the only family whose name
/// mentions validator sets is the legacy epoch-keyed one, which protocol v1
/// refuses to start with any row in.
#[test]
fn no_column_family_is_added_for_the_record() {
    let families: Vec<&str> = sumchain_storage::db::ALL_CFS
        .iter()
        .copied()
        .filter(|n| n.contains("validator_set"))
        .collect();
    assert_eq!(families, vec!["validator_sets"]);
}

/// The state seam writes only through the `ExecutionView` it is handed. It
/// names no column family, defines no key, constant or encoding of its own
/// (the layout is injected, the bytes are the row's), never opens, commits or
/// batches anything, and holds no unwind code: undo is the generic journal's.
#[test]
fn the_state_seam_writes_only_through_the_execution_view() {
    let text = std::fs::read_to_string(storage().join("src/validator_set_state.rs")).unwrap();
    let production = text
        .split("#[cfg(test)]")
        .next()
        .expect("the module has production code");
    let code: Vec<&str> = production
        .lines()
        .filter(|l| !l.trim_start().starts_with("//"))
        .collect();
    for forbidden in [
        "cf::",
        "const ",
        "rocksdb",
        "ValidatorSetStore",
        "WriteBatch",
        "ApplicationOverlay",
        ".batch()",
        ".commit(",
        ".delete(",
        "db.put(",
        "std::fs",
        "unwind",
    ] {
        assert!(
            !code.iter().any(|l| l.contains(forbidden)),
            "the state seam uses {forbidden}"
        );
    }
    // Every write goes to a view: each `.put(` is on the `view` parameter.
    let puts: Vec<&&str> = code.iter().filter(|l| l.contains(".put(")).collect();
    assert!(!puts.is_empty(), "the scan found no write to check");
    for line in puts {
        assert!(line.trim_start().starts_with("view.put("), "{line}");
    }
    // And every staging function takes one.
    let staging: Vec<&&str> = code
        .iter()
        .filter(|l| l.trim_start().starts_with("pub fn stage_"))
        .collect();
    assert_eq!(staging.len(), 2, "stage_insert and stage_replace");
    let signatures = production.split("pub fn stage_").skip(1);
    for sig in signatures {
        let head = sig.split('{').next().unwrap();
        assert!(
            head.contains("view: &mut ExecutionView<'_, '_>"),
            "a staging function that does not take the execution view: {head}"
        );
    }
}
