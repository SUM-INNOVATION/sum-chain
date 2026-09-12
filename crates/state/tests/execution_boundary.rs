//! Structural guard: block execution must not mutate the committed database.
//!
//! `ExecutionView` makes the mistake inexpressible *at call sites that take
//! one*. It cannot retroactively fix the code that still holds an
//! `Arc<Database>` and writes through it — and that code is most of the
//! executor today, across roughly twenty store and sub-executor types.
//!
//! Migrating all of it is a multi-commit change. Until it lands, the invariant
//! is enforced here as a ratchet: this test records how many direct-mutation
//! sites each file still has, and fails if any file grows. New execution code
//! therefore cannot add a write that bypasses the overlay, and the remaining
//! surface is a visible, countable number rather than a vague intention.
//!
//! The budget only ever moves down. A file that reaches zero is removed from
//! the list, and `no_unlisted_file_mutates_the_database_directly` then keeps it
//! at zero permanently.
//!
//! This is a source-level check. It is a guard against the easy mistake, not a
//! proof: code could still reach the database through a helper this pattern does
//! not name. What makes the boundary real is threading `ExecutionView` through
//! execution; this keeps the gap from widening while that happens.
//!
//! # The budget counts writes only
//!
//! `db.put`/`db.delete`/`db.batch` are what the ratchet can see, so a file can
//! reach zero here while its execution path still *reads* the committed
//! database. That is not a cosmetic gap. A subsystem whose writes are buffered
//! into the overlay but whose reads still go to `Database` no longer sees its
//! own earlier writes within a block: read-your-own-writes breaks, and the
//! block computes a state root against the parent's state instead of the
//! candidate's. Migrating writes without reads is therefore a correctness
//! regression, not a partial improvement — reads and writes must move together.
//!
//! Nothing in a *count* can express that, so it is enforced by type instead:
//! `migrated_execution_paths_take_no_self_receiver` below requires the
//! execution-path functions of a migrated subsystem to be associated functions.
//! Without a `self` receiver there is no `self.db` to reach, so the compiler,
//! not a regex, rules out a committed read on those paths.

use std::collections::BTreeMap;
use std::path::Path;

/// Files that still mutate `Database` directly, with their current counts.
///
/// ONLY EVER DECREASE THESE. Raising a number to make this test pass defeats
/// its entire purpose: the point is that the boundary cannot erode while the
/// migration is in progress.
fn budget() -> BTreeMap<&'static str, usize> {
    BTreeMap::from([
        ("storage_metadata.rs", 9),
        ("supply.rs", 8),
        ("executor.rs", 6),
        ("compute_pool_store.rs", 4),
        ("node_registry.rs", 2),
        ("inference_settlement_executor.rs", 2),
        ("beacon_store.rs", 2),
        ("state.rs", 1),
        ("inference_attestation_executor.rs", 1),
    ])
}

/// Direct mutation of a `Database` handle: `db.put(`, `self.db.delete(`,
/// `db.batch()` and so on. Deliberately narrow and literal — a regex that tried
/// to catch every indirect route would produce false positives and get muted,
/// which is worse than a guard with a stated scope.
fn count_direct_mutations(src: &str) -> usize {
    let mut n = 0;
    for line in src.lines() {
        let line = line.trim_start();
        if line.starts_with("//") || line.starts_with("///") || line.starts_with("//!") {
            continue;
        }
        for pat in [
            "db.put(",
            "db.delete(",
            "db.batch()",
        ] {
            n += line.matches(pat).count();
        }
    }
    n
}

fn state_src() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}

/// Every `.rs` file under `src/`, RECURSIVELY.
///
/// The first version of this read only the top level. `crates/state/src` happens
/// to be flat today, so nothing was actually hidden and the recorded counts were
/// accurate — but the hole was real: the moment anyone added `src/foo/bar.rs`,
/// it would have been unguarded, and the guard would have kept passing while the
/// boundary eroded. A guard with a blind spot is worse than no guard, because it
/// is trusted.
///
/// Names are returned relative to `src/`, so a nested file appears as
/// `foo/bar.rs` and cannot collide with a top-level entry in the budget.
fn rust_files() -> Vec<(String, String)> {
    rust_files_in(&state_src().join("src"))
}

/// The scan, over an arbitrary root. Split out so the recursion can be tested
/// against a temporary tree — a probe file written into the real `src/` would be
/// visible to the other tests in this file while they run, which is a race, not
/// a test.
fn rust_files_in(root: &Path) -> Vec<(String, String)> {
    fn walk(dir: &Path, prefix: &str, out: &mut Vec<(String, String)>) {
        for entry in std::fs::read_dir(dir).expect("read source directory") {
            let path = entry.expect("dir entry").path();
            let name = path
                .file_name()
                .and_then(|n| n.to_str())
                .expect("utf-8 filename")
                .to_string();
            let rel = if prefix.is_empty() {
                name.clone()
            } else {
                format!("{prefix}/{name}")
            };
            if path.is_dir() {
                walk(&path, &rel, out);
            } else if path.extension().and_then(|e| e.to_str()) == Some("rs") {
                let src = std::fs::read_to_string(&path).expect("read source");
                out.push((rel, src));
            }
        }
    }
    let mut out = Vec::new();
    walk(root, "", &mut out);
    out
}

#[test]
fn no_listed_file_grows_its_direct_database_mutations() {
    let budget = budget();
    let mut grew = Vec::new();
    let mut shrank = Vec::new();

    for (name, src) in rust_files() {
        let Some(&allowed) = budget.get(name.as_str()) else {
            continue;
        };
        let actual = count_direct_mutations(&src);
        if actual > allowed {
            grew.push(format!("  {name}: {allowed} allowed, {actual} found"));
        } else if actual < allowed {
            shrank.push(format!("  {name}: {allowed} allowed, {actual} found"));
        }
    }

    assert!(
        grew.is_empty(),
        "execution boundary eroded — these files gained direct database \
         mutations:\n{}\n\nNew execution code must write through `ExecutionView`, \
         so that a candidate branch can be abandoned without having touched \
         canonical state. Do not raise the budget to make this pass.",
        grew.join("\n")
    );

    assert!(
        shrank.is_empty(),
        "these files now have FEWER direct mutations than recorded, which is the \
         goal — lower the budget in this test to lock the progress in:\n{}",
        shrank.join("\n")
    );
}

#[test]
fn no_unlisted_file_mutates_the_database_directly() {
    let budget = budget();
    let mut offenders = Vec::new();

    for (name, src) in rust_files() {
        if budget.contains_key(name.as_str()) {
            continue;
        }
        let n = count_direct_mutations(&src);
        if n > 0 {
            offenders.push(format!("  {name}: {n}"));
        }
    }

    assert!(
        offenders.is_empty(),
        "these files are not on the migration list and must not mutate the \
         database directly:\n{}\n\nWrite through `ExecutionView` instead.",
        offenders.join("\n")
    );
}

/// The scan must reach nested files.
///
/// Run against a temporary tree, never the real `src/`: writing a probe file
/// into the crate's own sources would be visible to the other tests in this file
/// while they run in parallel, and they would fail on it. That is a race
/// masquerading as a test, and it happened on the first attempt.
#[test]
fn the_scan_recurses_into_subdirectories() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let nested = tmp.path().join("a").join("b");
    std::fs::create_dir_all(&nested).expect("create nested dirs");
    std::fs::write(nested.join("deep.rs"), "fn f(db: &D) { let _ = db.batch(); }\n")
        .expect("write nested source");
    std::fs::write(tmp.path().join("top.rs"), "fn g() {}\n").expect("write top source");
    std::fs::write(nested.join("ignored.txt"), "db.batch()\n").expect("write non-rust");

    let files = rust_files_in(tmp.path());
    let names: Vec<&str> = files.iter().map(|(n, _)| n.as_str()).collect();

    assert!(
        names.contains(&"a/b/deep.rs"),
        "a nested .rs file was not scanned — the guard would pass while the \
         boundary eroded in a subdirectory. Saw: {names:?}"
    );
    assert!(names.contains(&"top.rs"));
    assert!(
        !names.iter().any(|n| n.ends_with(".txt")),
        "only Rust sources should be scanned"
    );

    let (_, deep) = files.iter().find(|(n, _)| n == "a/b/deep.rs").unwrap();
    assert_eq!(count_direct_mutations(deep), 1);
}

#[test]
fn the_guard_actually_detects_a_direct_mutation() {
    // A guard that cannot fail proves nothing about the code it guards.
    assert_eq!(count_direct_mutations("self.db.put(cf, &k, &v)?;"), 1);
    assert_eq!(count_direct_mutations("let mut b = self.db.batch();"), 1);
    assert_eq!(count_direct_mutations("db.delete(cf::STATE, &key)?;"), 1);
    // Comments are not code.
    assert_eq!(count_direct_mutations("// self.db.put(cf, &k, &v)?;"), 0);
    assert_eq!(count_direct_mutations("/// calls db.put( internally"), 0);
    // Overlay and view writes are not direct mutations.
    assert_eq!(count_direct_mutations("view.put(cf, &k, &v)?;"), 0);
    assert_eq!(count_direct_mutations("overlay.delete(cf, &k)?;"), 0);
}

// ── The execution-completion binding ───────────────────────────────────────
//
// `finish_execution` ties the execution subject, accumulator, receipts and
// journals to the buffered writes. Acceptance then takes only `&Block`, so a
// caller cannot hand it a root, a receipt set, or a journal.
//
// `finish_execution` is PUBLIC, and has to be: `sumchain-state` calls it across
// a crate boundary, so Rust visibility cannot restrict it to one call site.
// Provenance rests on two things instead — `BlockExecution` is opaque, with
// private fields and no public constructor, so a candidate can only reach a
// caller by way of `execute_block`; and this guard pins the binding to exactly
// one call site, so a second one cannot appear without a test failing.
//
// Neither is Rust-enforced globally. Stating that plainly matters more than the
// guard reading stronger than it is: a reviewer who believes visibility is doing
// the work will not notice when the guard is deleted.

/// Every `.rs` file in the workspace's state and consensus crates.
fn workspace_sources() -> Vec<(String, String)> {
    let mut out = rust_files_in(&state_src().join("src"));
    let consensus = state_src().join("../consensus/src");
    if consensus.is_dir() {
        for (name, src) in rust_files_in(&consensus) {
            out.push((format!("consensus/{name}"), src));
        }
    }
    out
}

#[test]
fn finish_execution_is_called_exactly_once_and_only_where_execution_completes() {
    let mut sites = Vec::new();
    for (name, src) in workspace_sources() {
        for (i, line) in src.lines().enumerate() {
            let t = line.trim_start();
            if t.starts_with("//") {
                continue;
            }
            if t.contains(".finish_execution(") {
                sites.push(format!("  {name}:{}", i + 1));
            }
        }
    }

    assert_eq!(
        sites.len(),
        1,
        "`finish_execution` must be called exactly once, where `execute_block` \
         completes. More than one site means the computed accumulator could be \
         bound somewhere it was not produced, which is the forgery this binding \
         exists to prevent. Found:\n{}",
        sites.join("\n")
    );
    assert!(
        sites[0].starts_with("  executor.rs:"),
        "the single binding must live in executor.rs, at execution completion; \
         found {}",
        sites[0]
    );
}

/// Acceptance must never regain a root parameter.
#[test]
fn acceptance_takes_no_hash_from_its_caller() {
    let candidate = std::fs::read_to_string(
        state_src().join("../storage/src/candidate.rs"),
    )
    .expect("read candidate.rs");

    for name in ["accept_produced", "accept_imported"] {
        let start = candidate
            .find(&format!("pub fn {name}"))
            .unwrap_or_else(|| panic!("{name} must exist"));
        let rest = &candidate[start..];
        let sig = &rest[..rest.find(')').expect("parameter list")];
        assert!(
            !sig.contains("Hash"),
            "{name} must take only &Block — a Hash parameter would let a caller \
             supply the value acceptance is supposed to check against:\n{sig}"
        );
        assert!(
            sig.contains("block: &Block") || sig.contains("block: &'a Block"),
            "{name} must take the block:\n{sig}"
        );
    }
}

/// Execution-path functions of a migrated subsystem take no `self` receiver.
///
/// This is the read half of the migration, which the write budget cannot see.
/// The subsystem type stays alive for RPC — `EducationExecutor::get_offering`
/// and friends must keep reading committed state, because admission and RPC
/// answer about the published chain, not about a candidate block. What must not
/// survive is a `&self` on the block-execution path: that receiver carries
/// `Arc<Database>`, and any read through it silently bypasses the block's own
/// staged writes.
///
/// Dropping the receiver is what makes that unreachable rather than merely
/// discouraged — an associated function has no `self` to read from, so the
/// remaining way in is an `ExecutionView` parameter.
/// The parameter list of `sig` in `src`, from the opening paren to its match.
fn params_of<'a>(src: &'a str, sig: &str) -> Option<&'a str> {
    let at = src.find(sig)?;
    let open = at + sig.len() - 1;
    let mut depth = 0usize;
    for (i, c) in src[open..].char_indices() {
        match c {
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth == 0 {
                    return Some(&src[open + 1..open + i]);
                }
            }
            _ => {}
        }
    }
    None
}

fn takes_self_receiver(params: &str) -> bool {
    params
        .split(|c: char| !(c.is_alphanumeric() || c == '_'))
        .any(|t| t == "self")
}

#[test]
fn migrated_execution_paths_take_no_self_receiver() {
    /// `(file under src/, function signature prefix)` for every function that
    /// runs during block execution in a subsystem whose writes are migrated.
    /// Add a row here whenever a subsystem's writes move to the overlay.
    const EXECUTION_FNS: &[(&str, &str)] = &[
        ("education_executor.rs", "fn validate("),
        ("education_executor.rs", "fn validate_inner("),
        ("education_executor.rs", "fn v_set_offering_status("),
        ("education_executor.rs", "fn stage("),
    ];

    let files = rust_files();
    for (file, sig) in EXECUTION_FNS {
        let (_, src) = files
            .iter()
            .find(|(name, _)| name == file)
            .unwrap_or_else(|| panic!("{file} is listed in EXECUTION_FNS but is not under src/"));

        let params = params_of(src, sig).unwrap_or_else(|| {
            panic!(
                "{file} no longer defines `{sig}`. If it was renamed, update this \
                 list; do not delete the row — that would drop the only check \
                 that this path cannot read committed state."
            )
        });

        assert!(
            !takes_self_receiver(params),
            "{file} `{sig}` takes a `self` receiver. That receiver holds \
             `Arc<Database>`, so this execution path can read committed state \
             and miss the block's own staged writes. Take \
             `&ExecutionView<'_, '_>` instead and leave the `&self` accessor \
             for RPC.\n  parameters: {params}"
        );
        assert!(
            params.contains("ExecutionView"),
            "{file} `{sig}` runs during block execution but takes no \
             `ExecutionView`. Its reads and writes cannot be attributed to the \
             candidate block.\n  parameters: {params}"
        );
    }
}

/// The receiver check is only worth having if it fires. A guard that has never
/// been shown to fail is an assertion about itself.
#[test]
fn the_receiver_check_detects_a_self_receiver() {
    const MIGRATED: &str = r#"
    fn validate(
        view: &ExecutionView<'_, '_>,
        op: &EduParsed,
    ) -> Result<()> { }
"#;
    const NOT_MIGRATED: &str = r#"
    fn validate(
        &self,
        op: &EduParsed,
    ) -> Result<()> { }
"#;
    // A nested paren in the parameter list must not end the scan early.
    const NESTED: &str = "fn stage(view: &mut ExecutionView<'_, '_>, f: fn(&self) -> u8) {}";

    let migrated = params_of(MIGRATED, "fn validate(").expect("signature found");
    assert!(!takes_self_receiver(migrated));
    assert!(migrated.contains("ExecutionView"));

    let not_migrated = params_of(NOT_MIGRATED, "fn validate(").expect("signature found");
    assert!(
        takes_self_receiver(not_migrated),
        "the check missed a `&self` receiver: {not_migrated}"
    );
    assert!(!not_migrated.contains("ExecutionView"));

    assert!(takes_self_receiver(
        params_of(NESTED, "fn stage(").expect("signature found")
    ));

    // `self_id` is not a receiver.
    assert!(!takes_self_receiver("self_id: u64, myself: u8"));

    assert!(params_of("fn other() {}", "fn validate(").is_none());
}
