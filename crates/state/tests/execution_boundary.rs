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
///
/// These numbers have been recalibrated twice, both times because the counter
/// was measuring the wrong thing, and never to accommodate a new write:
///
/// * UP, when `count_direct_mutations` learned to see a write split across
///   lines — 35 recorded, 49 actually present.
/// * DOWN, when it stopped counting `#[cfg(test)]` modules — 49 counted, 42
///   reachable from block execution. See `strip_test_modules` for why counting
///   fixtures actively worked against finishing a migration.
///
/// Those are the only two legitimate reasons a number here may move for any
/// cause other than migration, and both are spent. A raise from here is the
/// erosion this guard exists to catch.
///
/// Production-only totals so far: 42 before the education subsystem, 41 after
/// it, 40 after the compute-pool cluster, 39 after the beacon cluster.
fn budget() -> BTreeMap<&'static str, usize> {
    BTreeMap::from([
        ("storage_metadata.rs", 15),
        ("supply.rs", 9),
        ("node_registry.rs", 6),
        ("inference_settlement_executor.rs", 4),
        ("beacon_store.rs", 1),
        ("compute_pool_store.rs", 1),
        ("executor.rs", 1),
        ("state.rs", 1),
        ("inference_attestation_executor.rs", 1),
    ])
}

/// Direct mutation of a `Database` handle: `db.put(`, `self.db.delete(`,
/// `db.batch()` and so on. Deliberately narrow and literal — a regex that tried
/// to catch every indirect route would produce false positives and get muted,
/// which is worse than a guard with a stated scope.
///
/// Line comments are dropped and the remaining source is stripped of ALL
/// whitespace before matching. The first version matched within single lines,
/// which meant rustfmt decided whether a write was counted: the extremely
/// common
///
/// ```ignore
/// self.db
///     .put(cf::X, &key, &bytes)?;
/// ```
///
/// was invisible to it, and 14 mutation sites across five files — two fifths of
/// the recorded total — were never in the budget at all. A ratchet that a line
/// break can defeat is not a ratchet.
fn count_direct_mutations(src: &str) -> usize {
    let code: String = src
        .lines()
        .map(|l| l.trim_start())
        .filter(|l| !l.starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n");
    let code = strip_test_modules(&code);
    let flat: String = code.chars().filter(|c| !c.is_whitespace()).collect();
    ["db.put(", "db.delete(", "db.batch("]
        .iter()
        .map(|pat| flat.matches(pat).count())
        .sum()
}

/// Drop `#[cfg(test)] mod … { … }` bodies, and nothing else.
///
/// The guard's claim is about BLOCK EXECUTION, and a unit test is not block
/// execution. Counting test code made the number measure something other than
/// what it says, and pushed in the wrong direction: once a subsystem's
/// production writes move to the overlay, its tests still need committed rows to
/// set up a revert or a cross-block sequence, and the only way to get them —
/// `ApplicationOverlay::into_batch` being crate-private to `sumchain-storage`,
/// so that outside it only `AcceptedCandidate::publish` makes state canonical —
/// is a `db.batch()` fixture. Counting those made finishing a migration LOOK
/// like eroding the boundary, which is an incentive to leave the production
/// write in place instead.
///
/// A test fixture that writes directly is not a hole in the execution boundary:
/// it cannot be reached from a block. A production path that does is, and that
/// is what the budget now counts.
///
/// # Why this is strict rather than convenient
///
/// Anything this function removes stops being counted, so a loose match here is
/// a way to hide a production write. Two rules keep it narrow.
///
/// **Only `mod` is stripped.** `#[cfg(test)]` also attaches to functions, `use`
/// items, consts and impls. A `#[cfg(test)] fn helper() { db.put(..) }` sits in
/// the middle of production code and a naive "skip to the next balanced brace"
/// would remove it — and a `#[cfg(test)] use …;` has no brace at all, so the
/// same rule would swallow whatever block came next. The attribute must be
/// followed by an optional visibility, the keyword `mod`, a name, and `{`;
/// anything else is left in place and counted.
///
/// **Braces are matched by a lexer, not by counting characters.** A `{` inside
/// a string, a char literal, or a comment is not a block. Miscounting one ends
/// the module early and returns the rest of the file to the count (noisy but
/// safe) or late and swallows production code (silent and not safe).
fn strip_test_modules(src: &str) -> String {
    let b = src.as_bytes();
    let mut out = String::with_capacity(src.len());
    let mut i = 0usize;
    const ATTR: &str = "#[cfg(test)]";

    while i < b.len() {
        if src[i..].starts_with(ATTR) {
            match test_mod_body_start(src, i + ATTR.len()) {
                Some(brace) => match matching_brace(src, brace) {
                    Some(end) => {
                        i = end;
                        continue;
                    }
                    // Unbalanced: keep everything from the attribute on, so a
                    // truncated or malformed file cannot hide a write.
                    None => {
                        out.push_str(&src[i..]);
                        return out;
                    }
                },
                // `#[cfg(test)]` on something that is not a module. Keep it and
                // keep scanning from just after the attribute.
                None => {
                    out.push_str(ATTR);
                    i += ATTR.len();
                    continue;
                }
            }
        }
        let ch = src[i..].chars().next().expect("char boundary");
        out.push(ch);
        i += ch.len_utf8();
    }
    out
}

/// Byte offset of the `{` opening a `[pub…] mod NAME {` that starts at `from`
/// (after leading whitespace), or `None` if what follows is not a module.
fn test_mod_body_start(src: &str, from: usize) -> Option<usize> {
    let mut i = skip_ws(src, from);

    // Optional visibility: `pub`, `pub(crate)`, `pub(super)`, …
    if src[i..].starts_with("pub") {
        let j = i + 3;
        let mut k = skip_ws(src, j);
        if src[k..].starts_with('(') {
            k = matching_delim(src, k, b'(', b')')?;
        }
        // `pub` must be a whole word — `public_thing` is not a visibility.
        let next = src[j..].chars().next();
        if k > j || next.is_none_or(|c| c.is_whitespace() || c == '(') {
            i = skip_ws(src, k);
        }
    }

    if !src[i..].starts_with("mod") {
        return None;
    }
    let after_kw = i + 3;
    // `mod` must be a whole word, or `module_name` would match.
    if !src[after_kw..]
        .chars()
        .next()
        .is_some_and(|c| c.is_whitespace())
    {
        return None;
    }

    let name = skip_ws(src, after_kw);
    let mut j = name;
    while src[j..]
        .chars()
        .next()
        .is_some_and(|c| c.is_alphanumeric() || c == '_')
    {
        j += 1;
    }
    if j == name {
        return None; // no name
    }
    let brace = skip_ws(src, j);
    // `mod foo;` — a declaration, not an inline body.
    if src[brace..].starts_with('{') {
        Some(brace)
    } else {
        None
    }
}

fn skip_ws(src: &str, mut i: usize) -> usize {
    while src[i..].chars().next().is_some_and(char::is_whitespace) {
        i += src[i..].chars().next().expect("checked").len_utf8();
    }
    i
}

/// Byte offset just past the `}` matching the `{` at `open`, skipping braces
/// that appear inside strings, char literals and comments.
fn matching_brace(src: &str, open: usize) -> Option<usize> {
    matching_delim(src, open, b'{', b'}')
}

fn matching_delim(src: &str, open: usize, o: u8, c: u8) -> Option<usize> {
    let b = src.as_bytes();
    let mut depth = 0usize;
    let mut i = open;
    while i < b.len() {
        match b[i] {
            b'/' if b.get(i + 1) == Some(&b'/') => {
                i += 2;
                while i < b.len() && b[i] != b'\n' {
                    i += 1;
                }
            }
            b'/' if b.get(i + 1) == Some(&b'*') => {
                i += 2;
                // Rust block comments nest.
                let mut n = 1usize;
                while i < b.len() && n > 0 {
                    if b[i] == b'/' && b.get(i + 1) == Some(&b'*') {
                        n += 1;
                        i += 2;
                    } else if b[i] == b'*' && b.get(i + 1) == Some(&b'/') {
                        n -= 1;
                        i += 2;
                    } else {
                        i += 1;
                    }
                }
                if n > 0 {
                    return None; // unterminated
                }
            }
            b'r' if matches!(b.get(i + 1), Some(&b'"') | Some(&b'#')) => {
                match skip_raw_string(b, i) {
                    Some(next) => i = next,
                    // Not a raw string after all (an identifier such as `r#type`,
                    // or unterminated). Step one byte and carry on.
                    None => i += 1,
                }
            }
            b'"' => {
                i += 1;
                loop {
                    if i >= b.len() {
                        return None; // unterminated
                    }
                    match b[i] {
                        b'\\' => i += 2,
                        b'"' => {
                            i += 1;
                            break;
                        }
                        _ => i += 1,
                    }
                }
            }
            b'\'' => {
                // A char literal, or a lifetime (`'a`), which has no closing
                // quote. Only treat it as a literal when one is actually there.
                match skip_char_literal(b, i) {
                    Some(next) => i = next,
                    None => i += 1,
                }
            }
            x if x == o => {
                depth += 1;
                i += 1;
            }
            x if x == c => {
                depth -= 1;
                i += 1;
                if depth == 0 {
                    return Some(i);
                }
            }
            _ => i += 1,
        }
    }
    None
}

/// `r"…"`, `r#"…"#`, `r##"…"##`, … Returns the offset just past the close.
fn skip_raw_string(b: &[u8], at: usize) -> Option<usize> {
    let mut i = at + 1;
    let mut hashes = 0usize;
    while b.get(i) == Some(&b'#') {
        hashes += 1;
        i += 1;
    }
    if b.get(i) != Some(&b'"') {
        return None; // `r#ident`, not a raw string
    }
    i += 1;
    while i < b.len() {
        if b[i] == b'"' {
            let close = i + 1;
            if b[close..].iter().take(hashes).filter(|&&x| x == b'#').count() == hashes {
                return Some(close + hashes);
            }
        }
        i += 1;
    }
    None
}

/// `'x'`, `'\n'`, `'\u{1F600}'`. `None` for a lifetime.
fn skip_char_literal(b: &[u8], at: usize) -> Option<usize> {
    let mut i = at + 1;
    if b.get(i) == Some(&b'\\') {
        i += 2;
        // `'\u{...}'`
        if b.get(i) == Some(&b'{') {
            while i < b.len() && b[i] != b'}' {
                i += 1;
            }
            i += 1;
        }
    } else if i < b.len() {
        // One char, which may be multi-byte.
        i += 1;
        while i < b.len() && (b[i] & 0xC0) == 0x80 {
            i += 1;
        }
    }
    if b.get(i) == Some(&b'\'') {
        Some(i + 1)
    } else {
        None
    }
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

    // A line break must not hide a write. This is the form rustfmt produces
    // for a long call, and it is what the first version of this counter
    // missed across five files.
    assert_eq!(
        count_direct_mutations("self.db\n    .put(cf::INFERENCE_CLAIMS, &key, &bytes)?;"),
        1,
        "a write split across lines is still a write"
    );
    assert_eq!(
        count_direct_mutations("self\n    .db\n    .delete(cf, &k)?;"),
        1
    );
    // Still not code when the split line is commented out.
    assert_eq!(
        count_direct_mutations("// self.db\n//     .put(cf, &k, &v)?;"),
        0
    );
    // Several on one line are all counted.
    assert_eq!(
        count_direct_mutations("db.put(a, b, c)?; db.delete(a, b)?;"),
        2
    );
}

#[test]
fn test_module_writes_are_not_counted_but_production_writes_around_them_are() {
    const SRC: &str = "\
fn production(db: &D) { db.put(cf, &k, &v).unwrap(); }

#[cfg(test)]
mod tests {
    fn fixture(db: &D) {
        let mut b = db.batch();
        b.put(cf, &k, &v).unwrap();
        db.delete(cf, &k).unwrap();
    }
}

fn also_production(db: &D) { db.delete(cf, &k).unwrap(); }
";
    assert_eq!(
        count_direct_mutations(SRC),
        2,
        "the two production writes count; the three inside `mod tests` do not"
    );

    // A nested brace inside the test module must not end it early, or the code
    // after it would be counted as production when it is not.
    const NESTED: &str = "\
#[cfg(test)]
mod tests {
    fn f() { if x { db.put(a, b, c); } }
    fn g() { db.batch(); }
}
";
    assert_eq!(count_direct_mutations(NESTED), 0);

    // A file with no test module is unaffected.
    assert_eq!(count_direct_mutations("db.put(a, b, c);"), 1);

    // Unbalanced braces must FAIL OPEN — keep counting — so a truncated or
    // malformed file cannot hide a write behind an unclosed `mod tests {`.
    assert_eq!(
        count_direct_mutations("#[cfg(test)]\nmod tests {\n    db.put(a, b, c);\n"),
        1,
        "an unbalanced test module must not swallow the rest of the file"
    );
}

/// Everything `strip_test_modules` removes stops being counted, so a loose match
/// is a way to hide a production write. These are the ways it could be loose.
#[test]
fn only_a_cfg_test_module_is_stripped() {
    // `#[cfg(test)]` on a FUNCTION is not a module. Its body must still count:
    // it sits among production code, and a "skip to the next balanced brace"
    // rule would remove it.
    assert_eq!(
        count_direct_mutations("#[cfg(test)]\nfn helper(db: &D) { db.put(a, b, c); }"),
        1,
        "a cfg-test function is not a module"
    );

    // `#[cfg(test)] use …;` has no brace at all. A rule that skipped to the next
    // balanced brace would swallow the following production block.
    assert_eq!(
        count_direct_mutations("#[cfg(test)]\nuse foo::bar;\nfn prod(db: &D) { db.put(a, b, c); }"),
        1,
        "a cfg-test use item must not swallow the item after it"
    );

    // Same for a cfg-test `impl` and a cfg-test `const`.
    assert_eq!(
        count_direct_mutations("#[cfg(test)]\nimpl T { fn f(db: &D) { db.batch(); } }"),
        1
    );
    assert_eq!(
        count_direct_mutations("#[cfg(test)]\nconst K: u8 = 1;\nfn p(db: &D) { db.delete(a, b); }"),
        1
    );

    // `mod` must be a whole word, and the module must have an inline body.
    assert_eq!(
        count_direct_mutations("#[cfg(test)]\nmodule_helper! { db.put(a, b, c); }"),
        1,
        "`module_helper` is not the `mod` keyword"
    );
    assert_eq!(
        count_direct_mutations("#[cfg(test)]\nmod other;\nfn p(db: &D) { db.put(a, b, c); }"),
        1,
        "a `mod foo;` declaration has no body to strip"
    );

    // Visibility is allowed before `mod`.
    assert_eq!(
        count_direct_mutations("#[cfg(test)]\npub mod tests { fn f(db: &D) { db.put(a, b, c); } }"),
        0
    );
    assert_eq!(
        count_direct_mutations(
            "#[cfg(test)]\npub(crate) mod tests { fn f(db: &D) { db.put(a, b, c); } }"
        ),
        0
    );

    // The module name is not fixed to `tests`.
    assert_eq!(
        count_direct_mutations("#[cfg(test)]\nmod fixtures { fn f(db: &D) { db.batch(); } }"),
        0
    );

    // Two test modules, with production code between and after them.
    let src = "\
fn a(db: &D) { db.put(x, y, z); }
#[cfg(test)]
mod t1 { fn f(db: &D) { db.batch(); } }
fn b(db: &D) { db.delete(x, y); }
#[cfg(test)]
mod t2 { fn g(db: &D) { db.put(x, y, z); } }
fn c(db: &D) { db.batch(); }
";
    assert_eq!(count_direct_mutations(src), 3);
}

/// A brace inside a string, a char literal or a comment is not a block. Getting
/// this wrong ends the module early — returning test code to the count, which is
/// merely noisy — or late, swallowing production code, which is not.
#[test]
fn braces_in_strings_and_comments_do_not_end_a_test_module() {
    // An unbalanced `{` in a string literal inside the module.
    let unbalanced_open = "\
#[cfg(test)]
mod tests {
    fn f() { let s = \"{\"; }
}
fn prod(db: &D) { db.put(a, b, c); }
";
    assert_eq!(
        count_direct_mutations(unbalanced_open),
        1,
        "a `{{` in a string must not open a block"
    );

    // An unbalanced `}` in a string would end the module early, returning the
    // module's own writes to the count.
    let unbalanced_close = "\
#[cfg(test)]
mod tests {
    fn f(db: &D) { let s = \"}\"; db.put(a, b, c); }
}
";
    assert_eq!(
        count_direct_mutations(unbalanced_close),
        0,
        "a `}}` in a string must not close the module"
    );

    // Escaped quote: the string does not end at `\\\"`, so the `}` after it is
    // still inside the literal.
    let escaped = "\
#[cfg(test)]
mod tests {
    fn f(db: &D) { let s = \"a\\\"}\"; db.batch(); }
}
";
    assert_eq!(count_direct_mutations(escaped), 0);

    // Raw strings, including hashed forms that contain a quote.
    let raw = "\
#[cfg(test)]
mod tests {
    fn f(db: &D) { let s = r#\"}\"#; let t = r\"}\"; db.put(a, b, c); }
}
";
    assert_eq!(count_direct_mutations(raw), 0);

    // A trailing line comment survives `count_direct_mutations`'s line filter,
    // which only drops lines that START with `//`.
    let trailing = "\
#[cfg(test)]
mod tests {
    fn f(db: &D) { db.batch(); } // }
}
fn prod(db: &D) { db.delete(a, b); }
";
    assert_eq!(count_direct_mutations(trailing), 1);

    // Block comments, including nested ones, and a brace inside them.
    let block = "\
#[cfg(test)]
mod tests {
    /* } /* nested } */ } */
    fn f(db: &D) { db.put(a, b, c); }
}
fn prod(db: &D) { db.batch(); }
";
    assert_eq!(count_direct_mutations(block), 1);

    // A char literal holding a brace, and a lifetime, which has no closing
    // quote and must not be read as one.
    let chars = "\
#[cfg(test)]
mod tests {
    fn f<'a>(db: &'a D) { let c = '}'; let d = '{'; db.put(a, b, c); }
}
fn prod(db: &D) { db.batch(); }
";
    assert_eq!(count_direct_mutations(chars), 1);
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
        ("compute_pool_store.rs", "fn v_load_state_map("),
        ("compute_pool_store.rs", "fn v_state_digest("),
        ("compute_pool_store.rs", "fn stage_transition("),
        ("beacon_store.rs", "fn v_load_state_map("),
        ("beacon_store.rs", "fn v_state_digest("),
        ("beacon_store.rs", "fn v_get_membership("),
        ("beacon_store.rs", "fn v_load_materialized("),
        ("beacon_store.rs", "fn stage_transition("),
        ("beacon_store.rs", "fn stage_epoch_transition("),
        ("beacon_manager.rs", "fn load_from_candidate("),
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

/// A `self` receiver is allowed on an execution path only where the receiving
/// type provably holds no database.
///
/// `BeaconBlockState` is the case. It is the per-block beacon accumulator: it
/// owns the runtime working state and nothing else, deliberately, so it can live
/// in the executor's interior-mutable slot across the per-transaction dispatch
/// loop without borrowing the database. `&self` on `stage` therefore cannot
/// reach committed state, and the blanket rule above would be forbidding a
/// receiver that carries no hazard.
///
/// The exemption is not taken on trust: the struct definition is checked to hold
/// no `Database`. Add a field of that type and this test fails, which is the
/// point — the exemption is only valid while the premise holds.
#[test]
fn a_self_receiver_is_allowed_only_where_the_type_holds_no_database() {
    /// `(file, receiver type, execution-path signature)`.
    const EXEMPT: &[(&str, &str, &str)] = &[(
        "beacon_manager.rs",
        "pub struct BeaconBlockState {",
        "fn stage(",
    )];

    let files = rust_files();
    for (file, type_decl, sig) in EXEMPT {
        let (_, src) = files
            .iter()
            .find(|(name, _)| name == file)
            .unwrap_or_else(|| panic!("{file} is listed in EXEMPT but is not under src/"));

        let at = src
            .find(type_decl)
            .unwrap_or_else(|| panic!("{file} no longer declares `{type_decl}`"));
        let body_start = at + type_decl.len();
        let body_end = body_start
            + src[body_start..]
                .find("\n}")
                .unwrap_or_else(|| panic!("unterminated struct in {file}"));
        let body = &src[body_start..body_end];
        assert!(
            !body.contains("Database"),
            "{file} `{type_decl}` now holds a database, so a `self` receiver on \
             its execution path can read committed state. Either drop the field \
             or drop this exemption.\n  fields: {body}"
        );

        let params = params_of(src, sig)
            .unwrap_or_else(|| panic!("{file} no longer defines `{sig}`; update this list"));
        assert!(
            params.contains("ExecutionView"),
            "{file} `{sig}` is an execution path and must take an \
             `ExecutionView`.\n  parameters: {params}"
        );
    }
}

/// Execution-path functions of `BlockExecutor` that still carry a `self`
/// receiver, with what each still reads from committed state.
///
/// `BlockExecutor` holds `Arc<Database>`, so `&self` on these is the same
/// hazard the check above forbids — the difference is only that they are not
/// finished. Listing them here keeps that visible and countable instead of
/// letting an omission from `EXECUTION_FNS` read as "already migrated".
///
/// Each row asserts BOTH that the function still takes `self` AND that it
/// already takes an `ExecutionView`: half-migrated, and known to be. A row
/// cannot rot — when the last committed read goes, the `self` assertion fails
/// and the row moves to `EXECUTION_FNS`.
#[test]
fn partially_migrated_execution_paths_are_declared() {
    /// `(file, signature prefix, what it still reads from committed state)`.
    const PARTIAL: &[(&str, &str, &str)] = &[
        (
            "executor.rs",
            "fn apply_compute_pool_transitions(",
            "nothing — it only forwards; the receiver goes when apply_compute_pool_ops does",
        ),
        (
            "executor.rs",
            "fn apply_compute_pool_ops<F>(",
            "ComputePoolManager::new_enabled(&self.db, ..), which the manager uses for \
             typed point reads and for the reorg-path revert",
        ),
        (
            "executor.rs",
            "fn compute_block_state_root(",
            "SupplyStore::new(self.db.clone()).state_digest(), folded into the \
             consensus root and still reading the PARENT's supply state",
        ),
        (
            "executor.rs",
            "fn init_beacon_block(",
            "nothing — it reads the candidate throughout; the receiver remains \
             only for self.params and self.state.chain_id()",
        ),
        (
            "executor.rs",
            "fn beacon_epoch_membership(",
            "nothing — the membership snapshot comes from the candidate",
        ),
        (
            "executor.rs",
            "fn apply_beacon_transitions(",
            "nothing — it stages through the view; the receiver holds the \
             per-block accumulator slot",
        ),
    ];

    let files = rust_files();
    for (file, sig, reads) in PARTIAL {
        let (_, src) = files
            .iter()
            .find(|(name, _)| name == file)
            .unwrap_or_else(|| panic!("{file} is listed in PARTIAL but is not under src/"));
        let params = params_of(src, sig)
            .unwrap_or_else(|| panic!("{file} no longer defines `{sig}`; update this list"));

        assert!(
            params.contains("ExecutionView"),
            "{file} `{sig}` is listed as partially migrated but takes no \
             `ExecutionView` at all.\n  parameters: {params}"
        );
        assert!(
            takes_self_receiver(params),
            "{file} `{sig}` no longer takes a `self` receiver — it is fully \
             migrated. Move it to EXECUTION_FNS and delete this row.\n  it was \
             listed as still reading: {reads}"
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
