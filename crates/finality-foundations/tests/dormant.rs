//! This crate stays DORMANT outside the reviewed signer wiring.
//!
//! Until 2026-11-09 this test refused any workspace crate that depended on the
//! finality foundations. On 2026-11-09 the owner adopted the B6 signer wiring
//! and authorized narrowing that guard to the permitted callers (decision
//! ledger). These tests enforce exactly those:
//!
//! * **Consumers.** Only `sumchain-node` may depend on this crate. In
//!   production code only `crates/node/src/finality_signer.rs` (the reviewed
//!   signer adapters) may name it; in tests, only the node's signer-wiring
//!   tests.
//! * **What the wiring may use.** The signer (`signer`), its file-backed store
//!   (`signer_file`) and the directory lock (`signer_lock`), and the `Digest`
//!   type. Never the vote, certificate, proof, bootstrap-authorization
//!   (activation), containment or encoding modules: nothing here produces a
//!   vote or a certificate or activates anything.
//! * **How the node reaches it.** `main.rs` declares the module and calls it
//!   only from the explicit `signer` command (`signer init`, `signer status`).
//!   Nothing else in the node names it: not `run`, not `node.rs`.
//! * **What the wiring does.** It opens a signer only in its `open`, which no
//!   production code calls, and never asks a signer to sign, advance or
//!   recover.
//!
//! A new consumer, use or caller fails here and needs its own reviewed change.
//! `crates/node/tests/signer_run_dormant.rs` checks the same of a running,
//! block-producing validator: it neither initializes signer state nor signs.
//! The ratified G2 semantics are not, by themselves, certified finality.

use std::path::{Path, PathBuf};

/// The one crate that may depend on this one.
const PERMITTED_MANIFESTS: &[&str] = &["crates/node/Cargo.toml"];
/// The production files that may name this crate: the reviewed adapters.
const PERMITTED_PRODUCTION: &[&str] = &["crates/node/src/finality_signer.rs"];
/// The test files that may name this crate.
const PERMITTED_TESTS: &[&str] = &["crates/node/tests/unit/signer_wiring_tests.rs"];
/// The modules of this crate the adapters may use.
const PERMITTED_USES: &[&str] = &["signer", "signer_file", "signer_lock", "Digest"];
/// Every line of the node's production code that may name the adapters: the
/// module declaration and the `signer` command.
const PERMITTED_NODE_LINES: &[&str] = &[
    "mod finality_signer;",
    "Signer(finality_signer::SignerArgs),",
    "let code = finality_signer::run_cli(args)?;",
];

fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn files(dir: &Path, ext: &str, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            if path.file_name().is_some_and(|n| n == "target") {
                continue;
            }
            files(&path, ext, out);
        } else if path.extension().is_some_and(|e| e == ext) {
            out.push(path);
        }
    }
}

fn rel(path: &Path) -> String {
    path.strip_prefix(repo())
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

/// Every other crate's manifest, and its sources as (path, kind): `src` for
/// production code, `tests` for tests, benches and examples.
fn workspace() -> (Vec<String>, Vec<(String, &'static str)>) {
    let mut manifests = Vec::new();
    let mut sources = Vec::new();
    for entry in std::fs::read_dir(repo().join("crates")).unwrap() {
        let dir = entry.unwrap().path();
        if !dir.is_dir() || dir.file_name().is_some_and(|n| n == "finality-foundations") {
            continue;
        }
        let manifest = dir.join("Cargo.toml");
        if manifest.is_file() {
            manifests.push(rel(&manifest));
        }
        for (sub, kind) in [
            ("src", "src"),
            ("tests", "tests"),
            ("benches", "tests"),
            ("examples", "tests"),
        ] {
            let d = dir.join(sub);
            if d.is_dir() {
                let mut found = Vec::new();
                files(&d, "rs", &mut found);
                sources.extend(found.iter().map(|f| (rel(f), kind)));
            }
        }
    }
    assert!(
        sources.len() > 100 && manifests.len() > 10,
        "the scan found too few files to mean anything"
    );
    (manifests, sources)
}

fn read(path: &str) -> String {
    std::fs::read_to_string(repo().join(path)).unwrap()
}

/// The lines of `src` that are not comments, trimmed.
fn code(src: &str) -> Vec<&str> {
    src.lines()
        .map(str::trim)
        .filter(|l| !l.starts_with("//"))
        .collect()
}

#[test]
fn only_the_reviewed_signer_wiring_depends_on_the_finality_foundations() {
    let (manifests, sources) = workspace();
    let mut hits = Vec::new();
    for m in &manifests {
        if read(m).contains("finality-foundations") && !PERMITTED_MANIFESTS.contains(&m.as_str()) {
            hits.push(format!("{m} depends on it"));
        }
    }
    for (f, kind) in &sources {
        let permitted = match *kind {
            "src" => PERMITTED_PRODUCTION,
            _ => PERMITTED_TESTS,
        };
        if read(f).contains("sumchain_finality_foundations") && !permitted.contains(&f.as_str()) {
            hits.push(format!("{f} uses it"));
        }
    }
    assert!(
        hits.is_empty(),
        "the finality foundations are used outside the reviewed signer wiring:\n{}",
        hits.join("\n")
    );
}

/// The adapters use the signer, its store and its lock, and nothing that
/// makes a vote, a certificate or an activation.
#[test]
fn the_wiring_uses_only_the_signer_its_store_and_its_lock() {
    for f in PERMITTED_PRODUCTION {
        let Ok(src) = std::fs::read_to_string(repo().join(f)) else {
            continue;
        };
        let needle = "sumchain_finality_foundations::";
        for line in code(&src) {
            for (i, _) in line.match_indices(needle) {
                let item: String = line[i + needle.len()..]
                    .chars()
                    .take_while(|c| c.is_alphanumeric() || *c == '_')
                    .collect();
                assert!(
                    PERMITTED_USES.contains(&item.as_str()),
                    "{f} uses `{needle}{item}` (each module on its own path; \
                     permitted: {PERMITTED_USES:?}): {line}"
                );
            }
        }
    }
}

/// `main.rs` declares the adapters and calls them only from the `signer`
/// command; no other node file names them, so neither `run` nor the node it
/// starts can reach a signer.
#[test]
fn the_node_reaches_the_wiring_only_through_the_signer_command() {
    let (_, sources) = workspace();
    for (f, kind) in &sources {
        if *kind != "src" || f == "crates/node/src/finality_signer.rs" {
            continue;
        }
        let src = read(f);
        let code = code(&src);
        let lines: Vec<&str> = code
            .iter()
            .copied()
            .filter(|l| l.contains("finality_signer"))
            .collect();
        if lines.is_empty() {
            continue;
        }
        assert_eq!(
            f, "crates/node/src/main.rs",
            "only main.rs may name the signer wiring: {lines:?}"
        );
        for l in &lines {
            assert!(
                PERMITTED_NODE_LINES.contains(l),
                "main.rs names the signer wiring outside the signer command: {l}"
            );
        }
        // The call sits in the `signer` command's arm.
        if let Some(call) = code
            .iter()
            .position(|l| *l == "let code = finality_signer::run_cli(args)?;")
        {
            let arm = code[..call]
                .iter()
                .rposition(|l| l.starts_with("Commands::"))
                .expect("the call is in a command's arm");
            assert_eq!(
                code[arm], "Commands::Signer(args) => {",
                "the signer wiring is called from another command"
            );
        }
    }
}

/// The adapters open a signer in exactly one place, their `open`, which no
/// production code calls; they never ask a signer to sign, advance or recover.
#[test]
fn no_production_path_opens_or_drives_a_signer() {
    for f in PERMITTED_PRODUCTION {
        let Ok(src) = std::fs::read_to_string(repo().join(f)) else {
            continue;
        };
        let code = code(&src);
        let opens = code
            .iter()
            .filter(|l| l.contains("DurableSigner::open("))
            .count();
        assert!(opens <= 1, "{f} opens a signer in {opens} places");
        // A bare `open(` is the module's own function: defined, never called
        // (`Database::open_existing(` and `DurableSigner::open(` are not bare).
        let bare: Vec<&&str> =
            code.iter()
                .filter(|l| {
                    l.match_indices("open(").any(|(i, _)| {
                        !l[..i].chars().next_back().is_some_and(|c| {
                            c == ':' || c == '.' || c == '_' || c.is_alphanumeric()
                        })
                    })
                })
                .collect();
        assert!(
            bare.iter().all(|l| l.starts_with("pub fn open(")),
            "{f} calls its signer open: {bare:?}"
        );
        for call in [".sign(", ".advance(", ".recover_after_conflict("] {
            let hits: Vec<&&str> = code.iter().filter(|l| l.contains(call)).collect();
            assert!(hits.is_empty(), "{f} drives a signer: {hits:?}");
        }
    }
}
