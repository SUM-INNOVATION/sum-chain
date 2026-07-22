//! Off-venue STRUCTURAL contract for the authoritative container-context staging
//! (`tools/b0-pre-candidates/scripts/stage_context.sh`, shared with
//! `build_container.sh`).
//!
//! The official guest dep graph is
//!     candidates/<cand>/guest --(path ../../../guest-core)--> guest-core
//!     guest-core              --(path ../../../crates/sumchain-wire)--> sumchain-wire
//! and `sumchain-wire` is a workspace MEMBER that inherits `.workspace = true` keys.
//! Copying only `candidates/<cand>` into the builder image (the old behaviour) left
//! those two crates + the workspace root absent, so neither the path deps nor the
//! `.workspace` inheritance could resolve in-container. These tests prove — with NO
//! Docker and NO prover — that the staged context:
//!
//!   (1) reproduces the exact repo-relative layout of ONLY the guest dep graph, and no
//!       unrelated production crate (isolation);
//!   (2) resolves EVERY staged path dependency for BOTH candidate manifests (each
//!       `path = "..."` target exists in the staged layout);
//!   (3) carries a curated minimal workspace root providing EXACTLY the
//!       `.workspace = true` keys `sumchain-wire` inherits (no missing key, no
//!       production workspace copied);
//!   (4) actually resolves under `cargo` OFFLINE: `cargo metadata --no-deps --offline`
//!       succeeds for the staged sumchain-wire (proving the curated workspace
//!       inheritance resolves), the standalone guest-core, and the candidate workspace.
//!
//! The real guest ELF build / prove is a venue artifact and is NOT exercised here.

use std::path::{Path, PathBuf};
use std::process::Command;

fn scripts_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../b0-pre-candidates/scripts")
}

fn stage_script() -> PathBuf {
    scripts_dir().join("stage_context.sh")
}

fn cargo_bin() -> String {
    std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_string())
}

fn unique_dir(tag: &str) -> PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEQ: AtomicU64 = AtomicU64::new(0);
    std::env::temp_dir().join(format!(
        "b0pre-ctxstage-{}-{}-{}",
        tag,
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    ))
}

/// Stage `candidate` into a fresh temp dir via the real staging script (no Docker).
fn stage(candidate: &str) -> PathBuf {
    let out = unique_dir(candidate);
    let status = Command::new("bash")
        .arg(stage_script())
        .arg(candidate)
        .arg(&out)
        .status()
        .unwrap_or_else(|e| panic!("spawn stage_context.sh: {e}"));
    assert!(
        status.success(),
        "stage_context.sh {candidate} must succeed"
    );
    out
}

fn read(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

/// Extract the `path` value of a `<name> = { path = "..." }` dependency line.
fn path_dep(manifest: &str, name: &str) -> String {
    for line in manifest.lines() {
        let t = line.trim();
        if t.starts_with(name)
            && t[name.len()..].trim_start().starts_with('=')
            && t.contains("path")
        {
            let after = t.split("path").nth(1).unwrap();
            let after = after.split('=').nth(1).unwrap();
            let start = after.find('"').expect("path opening quote");
            let rest = &after[start + 1..];
            let end = rest.find('"').expect("path closing quote");
            return rest[..end].to_string();
        }
    }
    panic!("path dependency `{name}` not found in manifest");
}

/// The `[package]` keys inherited via `key.workspace = true`.
fn inherited_package_keys(manifest: &str) -> Vec<String> {
    let mut keys = Vec::new();
    let mut in_pkg = false;
    for line in manifest.lines() {
        let t = line.trim();
        if t.starts_with('[') {
            in_pkg = t == "[package]";
            continue;
        }
        if in_pkg {
            if let Some(idx) = t.find(".workspace") {
                if t[idx..].replace(' ', "").starts_with(".workspace=true") {
                    keys.push(t[..idx].trim().to_string());
                }
            }
        }
    }
    keys
}

/// The dependency names pulled with `<name> = { workspace = true }` across
/// `[dependencies]` and `[dev-dependencies]`.
fn workspace_true_deps(manifest: &str) -> Vec<String> {
    let mut deps = Vec::new();
    let mut in_deps = false;
    for line in manifest.lines() {
        let t = line.trim();
        if t.starts_with('[') {
            in_deps = t == "[dependencies]" || t == "[dev-dependencies]";
            continue;
        }
        if in_deps && t.replace(' ', "").contains("={workspace=true}") {
            let name = t.split('=').next().unwrap().trim();
            if !name.is_empty() {
                deps.push(name.to_string());
            }
        }
    }
    deps
}

/// A `[section]`'s body lines (the lines after a line that EXACTLY equals `header`,
/// until the next line that starts a new `[section]`). Matching whole lines avoids
/// picking up a `[section]` mention inside a comment.
fn section_body(manifest: &str, header: &str) -> String {
    let mut out = Vec::new();
    let mut in_section = false;
    for line in manifest.lines() {
        let t = line.trim();
        if t == header {
            in_section = true;
            continue;
        }
        if in_section {
            if t.starts_with('[') {
                break;
            }
            out.push(line);
        }
    }
    assert!(in_section, "curated root must contain {header}");
    out.join("\n")
}

fn cargo_metadata_no_deps_offline_ok(manifest: &Path) -> bool {
    Command::new(cargo_bin())
        .args([
            "metadata",
            "--no-deps",
            "--offline",
            "--format-version",
            "1",
            "--manifest-path",
        ])
        .arg(manifest)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

// ---- (1) reproduced layout + isolation --------------------------------------------

#[test]
fn staging_reproduces_only_the_guest_graph_and_no_unrelated_crate() {
    for cand in ["sp1", "risc0"] {
        let s = stage(cand);
        // reproduced repo-relative layout of the guest dep graph
        for rel in [
            "Cargo.toml",
            "crates/sumchain-wire/Cargo.toml",
            "tools/b0-pre-candidates/guest-core/Cargo.toml",
            &format!("tools/b0-pre-candidates/candidates/{cand}/Cargo.toml"),
            &format!("tools/b0-pre-candidates/candidates/{cand}/host/Cargo.toml"),
            &format!("tools/b0-pre-candidates/candidates/{cand}/guest/Cargo.toml"),
            &format!("tools/b0-pre-candidates/candidates/{cand}/guest/src/main.rs"),
            "docs/b0-pre/fixtures/workload/official.json",
            "docs/b0-pre/exp/exp_table_q16.json",
            "docs/b0-pre/exp/exp_table_q16.json.hash",
        ] {
            assert!(s.join(rel).exists(), "staged context must carry {rel}");
        }
        // ISOLATION: crates/ holds ONLY sumchain-wire (no primitives/node/state/...).
        let mut crate_dirs: Vec<String> = std::fs::read_dir(s.join("crates"))
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        crate_dirs.sort();
        assert_eq!(
            crate_dirs,
            vec!["sumchain-wire".to_string()],
            "only sumchain-wire may be staged under crates/ (isolation)"
        );
        // ISOLATION: the OTHER candidate never enters this context.
        let other = if cand == "sp1" { "risc0" } else { "sp1" };
        assert!(
            !s.join(format!("tools/b0-pre-candidates/candidates/{other}"))
                .exists(),
            "the other candidate ({other}) must not be staged for {cand}"
        );
        // HOST-LOCK REFUSAL: no Cargo.lock anywhere in the staged context.
        assert!(
            !has_any_cargo_lock(&s),
            "no Cargo.lock may exist in the staged context (locks are venue-generated)"
        );
        std::fs::remove_dir_all(&s).ok();
    }
}

fn has_any_cargo_lock(dir: &Path) -> bool {
    for entry in std::fs::read_dir(dir).unwrap() {
        let p = entry.unwrap().path();
        if p.is_dir() {
            if has_any_cargo_lock(&p) {
                return true;
            }
        } else if p.file_name().map(|n| n == "Cargo.lock").unwrap_or(false) {
            return true;
        }
    }
    false
}

// ---- (2) every staged path dependency resolves in the staged layout ---------------

#[test]
fn both_candidate_manifests_resolve_every_staged_path_dep() {
    for cand in ["sp1", "risc0"] {
        let s = stage(cand);
        let guest_manifest_dir = s.join(format!("tools/b0-pre-candidates/candidates/{cand}/guest"));
        let guest_manifest = read(&guest_manifest_dir.join("Cargo.toml"));

        // guest -> guest-core
        let gc_rel = path_dep(&guest_manifest, "b0-pre-guest-core");
        assert_eq!(
            gc_rel, "../../../guest-core",
            "guest must path-depend on ../../../guest-core"
        );
        let gc_dir = guest_manifest_dir.join(&gc_rel);
        assert!(
            gc_dir.join("Cargo.toml").exists(),
            "staged guest-core target must exist for {cand}"
        );
        assert_eq!(
            std::fs::canonicalize(&gc_dir).unwrap(),
            std::fs::canonicalize(s.join("tools/b0-pre-candidates/guest-core")).unwrap(),
            "guest path dep must resolve to the staged guest-core"
        );

        // guest-core -> sumchain-wire
        let gc_manifest = read(&gc_dir.join("Cargo.toml"));
        let sw_rel = path_dep(&gc_manifest, "sumchain-wire");
        assert_eq!(
            sw_rel, "../../../crates/sumchain-wire",
            "guest-core must path-depend on ../../../crates/sumchain-wire"
        );
        let sw_dir = gc_dir.join(&sw_rel);
        assert!(
            sw_dir.join("Cargo.toml").exists(),
            "staged sumchain-wire target must exist for {cand}"
        );
        assert_eq!(
            std::fs::canonicalize(&sw_dir).unwrap(),
            std::fs::canonicalize(s.join("crates/sumchain-wire")).unwrap(),
            "guest-core path dep must resolve to the staged sumchain-wire"
        );
        std::fs::remove_dir_all(&s).ok();
    }
}

// ---- (3) curated root provides EXACTLY the inheritance sumchain-wire needs ---------

#[test]
fn curated_root_provides_every_workspace_key_sumchain_wire_inherits() {
    let s = stage("sp1");
    let root = read(&s.join("Cargo.toml"));
    let sw = read(&s.join("crates/sumchain-wire/Cargo.toml"));

    // The curated root is a workspace that excludes tools (so guest-core + the candidate
    // workspace under tools/ stay standalone) and carries ONLY sumchain-wire as a member.
    assert!(
        root.contains("[workspace]"),
        "curated root must be a workspace"
    );
    assert!(
        root.contains("members = [\"crates/sumchain-wire\"]"),
        "curated root must list only sumchain-wire as a member"
    );
    assert!(
        root.contains("exclude = [\"tools\"]"),
        "curated root must exclude tools (guest-core/candidate stay self-rooted)"
    );

    // Every `[package]` key sumchain-wire inherits must be defined in [workspace.package].
    let ws_pkg = section_body(&root, "[workspace.package]");
    let pkg_keys = inherited_package_keys(&sw);
    assert!(
        !pkg_keys.is_empty(),
        "sumchain-wire is expected to inherit package keys via .workspace = true"
    );
    for key in &pkg_keys {
        assert!(
            ws_pkg.lines().any(|l| l.trim_start().starts_with(&format!("{key} ="))
                || ws_pkg.trim_start().starts_with(&format!("{key} ="))),
            "curated [workspace.package] must define inherited key `{key}` (sumchain-wire uses {key}.workspace = true)"
        );
    }

    // Every `{ workspace = true }` dependency must be defined in [workspace.dependencies].
    let ws_deps = section_body(&root, "[workspace.dependencies]");
    let deps = workspace_true_deps(&sw);
    assert!(
        !deps.is_empty(),
        "sumchain-wire is expected to use workspace dependencies"
    );
    for dep in &deps {
        assert!(
            ws_deps.lines().any(|l| l.trim_start().starts_with(&format!("{dep} ="))),
            "curated [workspace.dependencies] must define `{dep}` (sumchain-wire uses {dep} = {{ workspace = true }})"
        );
    }
    std::fs::remove_dir_all(&s).ok();
}

// ---- (4) cargo actually resolves the staged manifests OFFLINE ---------------------

#[test]
fn cargo_resolves_the_staged_workspace_inheritance_offline() {
    // The decisive resolution proof: `cargo metadata --no-deps --offline` on the staged
    // sumchain-wire forces cargo to load the curated workspace root and resolve every
    // `.workspace = true` inheritance WITHOUT touching the registry. A missing inherited
    // key or member would make this fail. Also confirm the standalone guest-core and the
    // candidate workspace load offline from the staged layout.
    for cand in ["sp1", "risc0"] {
        let s = stage(cand);
        assert!(
            cargo_metadata_no_deps_offline_ok(&s.join("crates/sumchain-wire/Cargo.toml")),
            "staged sumchain-wire must resolve its curated-workspace inheritance offline ({cand})"
        );
        assert!(
            cargo_metadata_no_deps_offline_ok(
                &s.join("tools/b0-pre-candidates/guest-core/Cargo.toml")
            ),
            "staged guest-core must load offline as a standalone package ({cand})"
        );
        assert!(
            cargo_metadata_no_deps_offline_ok(&s.join(format!(
                "tools/b0-pre-candidates/candidates/{cand}/Cargo.toml"
            ))),
            "staged candidate workspace must load offline ({cand})"
        );
        std::fs::remove_dir_all(&s).ok();
    }
}
