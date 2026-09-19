//! Every non-test caller of a MESSAGING write, enumerated by the tree itself.
//!
//! ACTIVATION-AUDIT row OC-3. The designated blocker inventory names roughly
//! thirteen out-of-consensus write sites — "seven operator, two genesis, one
//! snapshot and three raw reorg". This worktree does not contain thirteen, and
//! the audit records that gap as UNDETERMINED rather than resolving it by
//! counting differently until the numbers agree.
//!
//! This test does not close that row. Nothing in this tree can: the evidence
//! that would settle it is the tree or branch the count of thirteen was taken
//! against, or its enumeration with file and line, and neither is here. What it
//! does is stop the row being ambiguously actionable in the ONE direction that
//! is checkable — **the inventory as this worktree actually stands is now
//! enumerated mechanically, by the tree, on every test run.** A fourteenth
//! write site, or a third caller, or a new writing method reached from
//! anywhere, fails this test instead of quietly widening a gap that is already
//! unreconciled.
//!
//! # What counts as a write site
//!
//! A non-test caller of a `MessagingStore` method that puts or deletes. The
//! method set is not hardcoded: it is derived from `messaging_store.rs` at test
//! time by reading every `pub fn` and asking whether its body contains a `put`
//! or a `delete`. So a method that GAINS a write is covered without anyone
//! remembering to add it here.
//!
//! Two exclusions, both deliberate and both narrow:
//!
//!   * `#[cfg(test)]` modules. An in-crate test that seeds a row through the
//!     store is not an out-of-consensus write site on a running node. Without
//!     this the RPC crate's own test module reports two false sites.
//!   * `//` comment lines, including the doc comments that name these methods
//!     while explaining why they are not called.
//!
//! The scan deliberately requires the file to name `MessagingStore` as well as
//! the method, because several of these names collide with unrelated private
//! methods: `messaging_executor.rs` has its own `add_contact`, `block_sender`
//! and `set_daily_quota`, none of which is this store, and all of which run
//! inside the candidate where they belong.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// The two non-test callers this worktree contains, and what each calls.
///
/// Both are already audit rows of their own, which is the point: the
/// out-of-consensus messaging writes in this tree are OC-1 and OC-2 and there
/// is no third.
///
///   * `crates/node/src/node.rs` → `backfill_indexes`. **OC-1**: the startup
///     index backfill, run unconditionally on every boot until the marker is
///     set, writing two pure index families outside any candidate.
///   * `crates/node/src/main.rs` → `seed_registry_at_genesis`. **OC-2**, after
///     its remediation. The old `ImportRegisteredKeys` loop over
///     `set_public_key` is gone; what remains refuses above genesis height and
///     into a non-empty registry, and records a permanent marker.
const EXPECTED: &[(&str, &[&str])] = &[
    ("crates/node/src/main.rs", &["seed_registry_at_genesis"]),
    ("crates/node/src/node.rs", &["backfill_indexes"]),
];

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("crates/storage has a grandparent")
        .to_path_buf()
}

/// Drop `//` comment lines and every `#[cfg(test)]` module body.
///
/// The module skip is a brace walk from the `mod`'s opening brace, which is
/// exact for well-formed Rust and is all this needs: the alternative, a regex
/// for the whole module, cannot match nested braces.
fn executable_source(text: &str) -> String {
    let no_comments: String = text
        .lines()
        .filter(|l| !l.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n");

    let bytes = no_comments.as_bytes();
    let mut out = String::with_capacity(no_comments.len());
    let mut i = 0usize;
    while i < no_comments.len() {
        let rest = &no_comments[i..];
        let is_cfg_test = rest.starts_with("#[cfg(test)]")
            || rest.starts_with("#[cfg(all(test")
            || rest.starts_with("#[cfg(any(test");
        if !is_cfg_test {
            out.push(no_comments[i..].chars().next().expect("char boundary"));
            i += no_comments[i..]
                .chars()
                .next()
                .expect("char boundary")
                .len_utf8();
            continue;
        }
        // Skip to the opening brace of the item this attribute decorates, then
        // past its matching close.
        let Some(open) = no_comments[i..].find('{').map(|o| i + o) else {
            break;
        };
        let mut depth = 0i32;
        let mut j = open;
        while j < bytes.len() {
            match bytes[j] {
                b'{' => depth += 1,
                b'}' => {
                    depth -= 1;
                    if depth == 0 {
                        break;
                    }
                }
                _ => {}
            }
            j += 1;
        }
        i = (j + 1).min(no_comments.len());
    }
    out
}

/// Every `pub fn` in `messaging_store.rs` whose body puts or deletes.
fn writing_methods(store_src: &str) -> Vec<String> {
    let body_of = |start: usize| -> &str {
        let open = store_src[start..]
            .find('{')
            .map(|o| start + o)
            .expect("a function has a body");
        let bytes = store_src.as_bytes();
        let mut depth = 0i32;
        let mut j = open;
        while j < bytes.len() {
            match bytes[j] {
                b'{' => depth += 1,
                b'}' => {
                    depth -= 1;
                    if depth == 0 {
                        break;
                    }
                }
                _ => {}
            }
            j += 1;
        }
        &store_src[open..j]
    };

    let mut names = Vec::new();
    let mut search = 0usize;
    while let Some(off) = store_src[search..].find("\n    pub fn ") {
        let at = search + off + "\n    pub fn ".len();
        let end = store_src[at..]
            .find(|c: char| !(c.is_alphanumeric() || c == '_'))
            .map(|o| at + o)
            .unwrap_or(store_src.len());
        let name = &store_src[at..end];
        let body = executable_source(body_of(at));
        if body.contains(".put(")
            || body.contains(".delete(")
            || body.contains("batch.put")
            || body.contains("batch.delete")
        {
            names.push(name.to_string());
        }
        search = end;
    }
    names.sort();
    names.dedup();
    names
}

fn rust_sources(root: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(root) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if path.is_dir() {
            if name != "target" {
                rust_sources(&path, out);
            }
        } else if name.ends_with(".rs") {
            out.push(path);
        }
    }
}

/// OC-3: the out-of-consensus MESSAGING write sites in this worktree are two,
/// and the tree says so itself.
#[test]
fn the_non_test_callers_of_a_messaging_write_are_exactly_the_two_audited_rows() {
    let root = workspace_root();
    let store_path = root.join("crates/storage/src/messaging_store.rs");
    let store_src = std::fs::read_to_string(&store_path).expect("read messaging_store.rs");
    let writers = writing_methods(&store_src);

    assert!(
        writers.contains(&"backfill_indexes".to_string())
            && writers.contains(&"seed_registry_at_genesis".to_string())
            && writers.contains(&"set_public_key".to_string()),
        "the method-set derivation must find the writers this row is about; it \
         found {writers:?}"
    );

    let mut crate_sources = Vec::new();
    let crates_dir = root.join("crates");
    for entry in std::fs::read_dir(&crates_dir)
        .expect("crates/ exists")
        .flatten()
    {
        let src = entry.path().join("src");
        if src.is_dir() {
            rust_sources(&src, &mut crate_sources);
        }
    }
    assert!(
        crate_sources.len() > 50,
        "the walk found only {} source files, which means it is not walking \
         the tree and every assertion below is vacuous",
        crate_sources.len()
    );

    let mut found: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for path in crate_sources {
        if path == store_path {
            continue;
        }
        let text = std::fs::read_to_string(&path).unwrap_or_default();
        let code = executable_source(&text);
        if !code.contains("MessagingStore") {
            continue;
        }
        let mut called: Vec<String> = writers
            .iter()
            .filter(|w| code.contains(&format!("{w}(")))
            .cloned()
            .collect();
        if called.is_empty() {
            continue;
        }
        called.sort();
        let rel = path
            .strip_prefix(&root)
            .expect("inside the workspace")
            .to_string_lossy()
            .replace('\\', "/");
        found.insert(rel, called);
    }

    let expected: BTreeMap<String, Vec<String>> = EXPECTED
        .iter()
        .map(|(f, ms)| {
            (
                (*f).to_string(),
                ms.iter().map(|m| (*m).to_string()).collect(),
            )
        })
        .collect();

    assert_eq!(
        found, expected,
        "OC-3: the non-test callers of a writing `MessagingStore` method must \
         be exactly the two the audit enumerates -- `backfill_indexes` from \
         node.rs (OC-1) and `seed_registry_at_genesis` from main.rs (OC-2, \
         after its remediation replaced the `set_public_key` loop). A third \
         entry here is a NEW out-of-consensus write site, and it must be \
         classified in docs/lane-a/ACTIVATION-AUDIT.md before this list moves. \
         This assertion does not resolve the designated count of thirteen -- \
         that needs the tree it was taken against -- it only stops the gap \
         widening unobserved"
    );
}

/// The discriminator: the scan is capable of finding a caller it is not
/// expecting.
///
/// Without this, the test above would also pass if `executable_source` swallowed
/// the whole file, if the writer set came back empty, or if the walk missed
/// `crates/node`. Each of those failure modes produces an EMPTY result that
/// compares equal to nothing — so the scan is run here against a file that is
/// known to call a writer and required to see it.
#[test]
fn the_scan_can_see_a_caller_it_is_not_expecting() {
    let root = workspace_root();
    let node = std::fs::read_to_string(root.join("crates/node/src/node.rs")).expect("read node.rs");
    let code = executable_source(&node);
    assert!(
        code.contains("MessagingStore") && code.contains("backfill_indexes("),
        "the comment/cfg(test) stripper must not swallow live code"
    );

    let store_src = std::fs::read_to_string(root.join("crates/storage/src/messaging_store.rs"))
        .expect("read messaging_store.rs");
    let writers = writing_methods(&store_src);
    assert!(
        writers.len() > 10,
        "the writing-method derivation found only {} methods, which would make \
         the inventory above vacuously small: {writers:?}",
        writers.len()
    );
    assert!(
        !writers.contains(&"get_public_key".to_string()),
        "and it must not sweep in pure readers: {writers:?}"
    );
}
