//! Every production path to a `JournalActivation`, enumerated — and the proof
//! that a fabricated one is not among them.
//!
//! # The hole this closes
//!
//! `JournalActivation` decides one safety question: at a given height, is a
//! MISSING undo journal an error that halts the unwind, or expected silence
//! that falls back to the four legacy per-subsystem journals? Post-activation
//! the answer must be "halt", because the legacy journals do not cover every
//! column family a block writes — unwinding from them reports success while
//! leaving rows applied under a chain that no longer contains the blocks that
//! wrote them.
//!
//! `JournalActivation::pinned(u64::MAX)` answers `PreActivation` at every
//! height. One production caller fabricating it turns every halt in the system
//! into that silent, incomplete unwind, and nothing downstream can tell: the
//! value is a legitimate `JournalActivation`, it is the ordinary shape of "this
//! chain has not activated the generic journal yet", and every consumer honours
//! it exactly as it should.
//!
//! Documentation is not a guard against that, and neither is a code review of
//! the call sites that exist today. Two things are:
//!
//! 1. **The compiler.** `pinned` is behind `cfg(any(test, feature =
//!    "activation-fixtures"))`, and the feature is enabled ONLY through the
//!    dev-dependencies of the two crates whose tests need a boundary with no
//!    database behind it. No production build turns it on, so production code
//!    that called it would not compile.
//! 2. **This file.** A structural guard that reads the source tree, strips
//!    `#[cfg(test)]` items, and asserts the set of production constructions and
//!    consumption sites is EXACTLY the enumerated one. A new one anywhere in
//!    the workspace fails here, named, rather than being noticed later.
//!
//! The guard is deliberately textual. It is checking a property of the source —
//! "no other file does this" — which no amount of running the code can
//! establish, because the failure it looks for is code that has not been
//! written yet.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

/// The workspace root, from this crate's manifest directory.
fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("crates/<pkg>/ has a workspace root above it")
        .to_path_buf()
}

/// Every `crates/*/src/**/*.rs`, as (workspace-relative path, source).
fn production_sources() -> Vec<(String, String)> {
    fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for e in entries.flatten() {
            let p = e.path();
            if p.is_dir() {
                walk(&p, out);
            } else if p.extension().is_some_and(|x| x == "rs") {
                out.push(p);
            }
        }
    }

    let root = repo_root();
    let mut files = Vec::new();
    for crate_dir in std::fs::read_dir(root.join("crates"))
        .expect("crates/ exists")
        .flatten()
    {
        walk(&crate_dir.path().join("src"), &mut files);
    }
    assert!(
        files.len() > 50,
        "the scan found only {} source files, which means it is not scanning the \
         workspace and every assertion below is vacuous",
        files.len()
    );

    let mut out: Vec<(String, String)> = files
        .into_iter()
        .map(|p| {
            let rel = p
                .strip_prefix(&root)
                .expect("under the root")
                .to_string_lossy()
                .replace('\\', "/");
            let src = std::fs::read_to_string(&p).expect("readable source");
            (rel, strip_cfg_test_items(&src))
        })
        .collect();
    out.sort();
    out
}

/// Remove every `#[cfg(test)]`-attributed item, by matching braces from the
/// attribute forward.
///
/// Not a parser, and it does not need to be: it is removing whole `mod tests {
/// … }` and `#[cfg(test)] fn …` items, whose braces balance. A string literal
/// containing an unbalanced brace inside a test module could fool it, and the
/// consequence would be that MORE source is scanned than intended — the safe
/// direction for a guard that asserts an allow-list.
fn strip_cfg_test_items(src: &str) -> String {
    const ATTR: &str = "#[cfg(test)]";
    let mut out = String::with_capacity(src.len());
    let mut rest = src;
    while let Some(at) = rest.find(ATTR) {
        out.push_str(&rest[..at]);
        let after = &rest[at + ATTR.len()..];
        let Some(open) = after.find('{') else {
            break;
        };
        let bytes = after.as_bytes();
        let mut depth = 0usize;
        let mut end = None;
        for (i, b) in bytes.iter().enumerate().skip(open) {
            match b {
                b'{' => depth += 1,
                b'}' => {
                    depth -= 1;
                    if depth == 0 {
                        end = Some(i);
                        break;
                    }
                }
                _ => {}
            }
        }
        match end {
            Some(i) => rest = &after[i + 1..],
            None => return out,
        }
    }
    out.push_str(rest);
    out
}

/// A line of real code — not a doc comment, not a line comment.
///
/// The doc on `pinned` names itself, and the contract prose names every
/// constructor it describes. A guard that counted those would be measuring how
/// carefully the code is documented.
fn code_lines(src: &str) -> impl Iterator<Item = &str> {
    src.lines().map(str::trim).filter(|l| {
        !l.starts_with("//") && !l.starts_with("/*") && !l.starts_with('*') && !l.is_empty()
    })
}

/// Files whose production code mentions `needle`.
fn files_mentioning(sources: &[(String, String)], needle: &str) -> BTreeSet<String> {
    sources
        .iter()
        .filter(|(_, src)| code_lines(src).any(|l| l.contains(needle)))
        .map(|(p, _)| p.clone())
        .collect()
}

fn set(items: &[&str]) -> BTreeSet<String> {
    items.iter().map(|s| s.to_string()).collect()
}

// ─────────────────────────────────────────────────────────────────────────────

/// No production code anywhere in the workspace fabricates an activation.
///
/// The strongest of the assertions here: `pinned` is the ONLY constructor that
/// does not consult a database, and production code does not call it. The
/// feature gate makes that a compile error; this makes it a named test failure,
/// which is the one an author sees first.
#[test]
fn no_production_code_fabricates_a_journal_activation() {
    let sources = production_sources();
    let callers: BTreeSet<String> = files_mentioning(&sources, "JournalActivation::pinned")
        .into_iter()
        // The definition site names the function in its own signature.
        .filter(|p| p != "crates/storage/src/journal.rs")
        .collect();
    assert!(
        callers.is_empty(),
        "production code must not construct a JournalActivation without a database: \
         a boundary pinned above the head classifies EVERY height as \
         pre-activation, which turns the missing-journal halt into a silent \
         fallback to the legacy per-subsystem journals — an incomplete unwind that \
         reports success. Offending files: {callers:?}"
    );

    // And `pinned` itself does not exist in a production build. Asserted on the
    // source rather than by calling it, because a test binary HAS the feature on
    // — this test can reach `pinned`, and a node binary cannot.
    let journal = std::fs::read_to_string(repo_root().join("crates/storage/src/journal.rs"))
        .expect("journal.rs");
    let gate = "#[cfg(any(test, feature = \"activation-fixtures\"))]\n    pub fn pinned(";
    assert!(
        journal.contains(gate),
        "JournalActivation::pinned must be gated behind cfg(any(test, feature = \
         \"activation-fixtures\")) directly above its signature; the gate is what \
         makes a production call a compile error rather than a review finding"
    );
}

/// The feature that unlocks the fixture constructor is enabled only by
/// dev-dependencies.
///
/// A gate reachable from a production dependency edge is not a gate. This reads
/// the manifests and pins which edges turn it on.
#[test]
fn the_fixture_feature_is_reachable_only_from_dev_dependencies() {
    let root = repo_root();

    let storage = std::fs::read_to_string(root.join("crates/storage/Cargo.toml")).expect("read");
    assert!(
        storage.contains("[features]") && storage.contains("activation-fixtures = []"),
        "sumchain-storage must declare the activation-fixtures feature"
    );

    let mut enablers = BTreeSet::new();
    for entry in std::fs::read_dir(root.join("crates")).expect("crates/").flatten() {
        let manifest = entry.path().join("Cargo.toml");
        let Ok(text) = std::fs::read_to_string(&manifest) else {
            continue;
        };
        if !text.contains("activation-fixtures") {
            continue;
        }
        let rel = format!(
            "crates/{}/Cargo.toml",
            entry.file_name().to_string_lossy()
        );
        // Which table is it in? Everything after `[dev-dependencies]` and before
        // the next top-level table is a dev edge.
        let dev_start = text.find("[dev-dependencies]");
        for (i, _) in text.match_indices("features = [\"activation-fixtures\"]") {
            let is_dev = dev_start.is_some_and(|d| i > d);
            assert!(
                is_dev,
                "{rel} enables activation-fixtures outside [dev-dependencies]; a \
                 production dependency edge that turns the gate on makes the gate \
                 meaningless"
            );
            enablers.insert(rel.clone());
        }
    }

    assert_eq!(
        enablers,
        set(&[
            "crates/consensus/Cargo.toml",
            "crates/state/Cargo.toml",
        ]),
        "exactly the two crates whose TESTS need a boundary with no database \
         behind it may enable the fixture constructor"
    );

    // The node binary is the one that must not have it, under any edge.
    let node = std::fs::read_to_string(root.join("crates/node/Cargo.toml")).expect("read");
    assert!(
        !node.contains("activation-fixtures"),
        "the node binary must never enable the fixture constructor"
    );
}

/// The boundary is not reachable as a field, so no crate can build an
/// activation by struct literal and skip every constructor.
#[test]
fn the_activation_carries_no_public_fields() {
    let journal = std::fs::read_to_string(repo_root().join("crates/storage/src/journal.rs"))
        .expect("journal.rs");
    let decl = journal
        .split("pub struct JournalActivation {")
        .nth(1)
        .expect("JournalActivation is declared")
        .split('}')
        .next()
        .expect("a closing brace");
    for line in code_lines(decl) {
        assert!(
            !line.starts_with("pub "),
            "JournalActivation must have no public fields — a public `boundary` is a \
             second fabrication route past every constructor: {line}"
        );
    }
    assert!(
        decl.contains("source:") && decl.contains("boundary:"),
        "the scan must have found the real declaration: {decl}"
    );
}

/// Every production site that RESOLVES an activation, enumerated.
///
/// Not a ban — these are the legitimate ones. The value is that the list is
/// closed: a new site appears here as a failure with its path, and whoever adds
/// it has to say why a fifth place in the tree needs to decide where this
/// chain's journal becomes authoritative.
#[test]
fn every_production_site_that_resolves_an_activation_is_enumerated() {
    let sources = production_sources();

    // The translation from the genesis document's configured height. This is
    // the ONLY place a configured `Option<BlockHeight>` becomes an
    // `ActivationSource`, so a chain cannot end up with two readings of its own
    // parameter.
    assert_eq!(
        files_mentioning(&sources, "ActivationSource::from_configured_height"),
        set(&[
            "crates/consensus/src/poa.rs",
            "crates/node/src/main.rs",
            "crates/node/src/node.rs",
        ]),
        "the configured activation height is read in the engine, the node boot \
         path and the rollback tool, and nowhere else. (Its definition in \
         crates/storage/src/journal.rs names itself only in prose, which \
         `code_lines` drops.)"
    );

    // Resolution against a database: the one production constructor.
    assert_eq!(
        files_mentioning(&sources, "JournalActivation::resolve"),
        set(&[
            "crates/node/src/node.rs",
            "crates/state/src/reorg_undo.rs",
        ]),
        "an activation is resolved against a database at boot and inside \
         ActivatedJournal::resolve — a third site would be a third opinion about \
         the same database"
    );
    assert_eq!(
        files_mentioning(&sources, "ActivatedJournal::resolve"),
        set(&["crates/consensus/src/poa.rs", "crates/node/src/main.rs"]),
        "the engine and the rollback tool are the two things that unwind"
    );
}

/// Every production site that can perform a post-activation unwind, enumerated
/// — and the proof that none of them can reach the tolerant policy except
/// through an activation with no boundary at all.
///
/// `MissingJournalPolicy::ToleratedEverywhere` is the value that lets a missing
/// journal pass. It has exactly one production construction, inside
/// `from_activation`, and it is produced there only from `boundary == None` —
/// a database with no journal history anywhere, which is the one state in which
/// tolerating an absence is correct.
#[test]
fn the_tolerant_policy_has_one_production_construction_and_the_unwind_has_two_callers() {
    let sources = production_sources();

    assert_eq!(
        files_mentioning(&sources, "MissingJournalPolicy::ToleratedEverywhere"),
        set(&["crates/state/src/reorg_undo.rs"]),
        "the policy that lets a missing journal pass must be constructible in one \
         place only, from an activation that has no boundary"
    );

    let reorg_undo = sources
        .iter()
        .find(|(p, _)| p == "crates/state/src/reorg_undo.rs")
        .map(|(_, s)| s.clone())
        .expect("reorg_undo.rs is production source");
    assert!(
        reorg_undo.contains("None => MissingJournalPolicy::ToleratedEverywhere"),
        "the tolerant policy must come from a boundary of None and from nothing \
         else; any other arm is a post-activation unwind that tolerates a missing \
         record"
    );

    // And the unwind itself. Two callers, both in the reorg module: the reorg
    // arm and the operator rollback. `sum-node rollback` reaches the second one
    // rather than carrying an unwind of its own — the bug where it reverted
    // accounts and reported success.
    assert_eq!(
        files_mentioning(&sources, "stage_branch_unwind"),
        set(&[
            "crates/consensus/src/reorg.rs",
            "crates/state/src/reorg_undo.rs",
        ]),
        "a branch is unwound through one function, called from one module; a third \
         caller is a second unwind with its own idea of what a missing record means"
    );
}
