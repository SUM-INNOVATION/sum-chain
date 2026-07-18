//! Repo-wide guard against stale health-probe drift (issue #120).
//!
//! Issue #120 moved liveness/readiness onto a standalone health server bound on
//! `:8546`, serving `GET /health` and `GET /ready`. Before that, deployment
//! surfaces probed an *unserved* `/health/live` / `/health/ready` path, and did
//! so against the JSON-RPC port (`:8545`). This test walks every deployment and
//! documentation surface and fails if any of those stale forms reappear, so the
//! fix cannot silently regress:
//!
//!   * the stale liveness path `/health/live`
//!   * the stale readiness path `/health/ready`
//!   * any health/readiness probe pointed at the JSON-RPC port `:8545`
//!     (either the URL form `8545/health` / `8545/ready`, or a Kubernetes
//!     `httpGet` whose health/ready `path:` is co-located with `port: rpc` /
//!     `port: 8545`).
//!
//! Scanned surfaces: the root `Dockerfile` and `docker-compose.yaml`, every
//! file under `deploy/`, and every file under `docs/` EXCEPT `docs/plans/`
//! (design/plan docs are out of scope for #120 and may reference historical
//! paths in prose).

use std::fs;
use std::path::{Path, PathBuf};

/// Text file extensions worth scanning. Files named `Dockerfile` are also
/// included regardless of extension.
const TEXT_EXTS: &[&str] = &["yaml", "yml", "md", "toml", "json", "txt", "sh"];

fn workspace_root() -> PathBuf {
    // CARGO_MANIFEST_DIR = <root>/crates/node ; workspace root is two up.
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root")
        .to_path_buf()
}

fn is_scannable(path: &Path) -> bool {
    if path.file_name().and_then(|n| n.to_str()) == Some("Dockerfile") {
        return true;
    }
    match path.extension().and_then(|e| e.to_str()) {
        Some(ext) => TEXT_EXTS.contains(&ext),
        None => false,
    }
}

/// Recursively collect scannable files under `dir`, skipping any directory
/// named `plans` (i.e. `docs/plans/`).
fn collect(dir: &Path, out: &mut Vec<PathBuf>) {
    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            if path.file_name().and_then(|n| n.to_str()) == Some("plans") {
                continue; // skip docs/plans/
            }
            collect(&path, out);
        } else if is_scannable(&path) {
            out.push(path);
        }
    }
}

/// A health/readiness Kubernetes probe path on this line (matches `/health` and
/// `/ready`, including the stale `/health/live` / `/health/ready`, which are
/// caught separately too).
fn has_probe_path(line: &str) -> bool {
    line.contains("path: /health") || line.contains("path: /ready")
}

fn line_targets_rpc_port(line: &str) -> bool {
    line.contains("port: rpc") || line.contains("port: 8545") || line.contains("port: \"8545\"")
}

/// Scan a single file's text, returning a violation string per offending line.
fn scan_text(rel: &str, content: &str) -> Vec<String> {
    let mut violations = Vec::new();
    let lines: Vec<&str> = content.lines().collect();

    for (i, line) in lines.iter().enumerate() {
        let lineno = i + 1;

        if line.contains("/health/live") {
            violations.push(format!(
                "{rel}:{lineno}: stale liveness path `/health/live` (use `/health` on :8546)"
            ));
        }
        if line.contains("/health/ready") {
            violations.push(format!(
                "{rel}:{lineno}: stale readiness path `/health/ready` (use `/ready` on :8546)"
            ));
        }
        if line.contains("8545/health") || line.contains("8545/ready") {
            violations.push(format!(
                "{rel}:{lineno}: health probe on JSON-RPC port 8545 (use :8546)"
            ));
        }

        // Kubernetes httpGet: a health/ready path co-located with the rpc port,
        // either on the same (compact) line or within the next two lines of a
        // multi-line probe block.
        if has_probe_path(line) {
            let end = (i + 3).min(lines.len());
            if lines[i..end].iter().any(|l| line_targets_rpc_port(l)) {
                violations.push(format!(
                    "{rel}:{lineno}: health/readiness probe bound to the RPC port \
                     (use the `health` port / :8546)"
                ));
            }
        }
    }

    violations
}

fn main_scan() -> Vec<String> {
    let root = workspace_root();

    let mut files: Vec<PathBuf> = Vec::new();
    for explicit in ["Dockerfile", "docker-compose.yaml"] {
        let p = root.join(explicit);
        if p.is_file() {
            files.push(p);
        }
    }
    collect(&root.join("deploy"), &mut files);
    collect(&root.join("docs"), &mut files);

    let mut violations = Vec::new();
    for file in &files {
        let content = match fs::read_to_string(file) {
            Ok(c) => c,
            Err(_) => continue, // non-UTF8 / unreadable — skip
        };
        let rel = file
            .strip_prefix(&root)
            .unwrap_or(file)
            .display()
            .to_string();
        violations.extend(scan_text(&rel, &content));
    }
    violations
}

#[test]
fn no_stale_health_probe_references_in_deploy_or_docs() {
    // Sanity: we must actually be scanning real surfaces, or the guard is
    // vacuously green.
    let root = workspace_root();
    assert!(
        root.join("deploy/kubernetes/statefulset.yaml").is_file(),
        "guard is not scanning the expected repo layout (missing k8s statefulset)"
    );

    let violations = main_scan();
    assert!(
        violations.is_empty(),
        "stale health-probe references found (issue #120 regression):\n{}",
        violations.join("\n")
    );
}

/// The guard must actually catch each stale form — prove the detector is not
/// vacuously green by running it against synthetic regressions and the current
/// (fixed) forms.
#[test]
fn guard_detects_each_stale_form() {
    // Stale paths.
    assert_eq!(scan_text("f", "  path: /health/live").len(), 1);
    assert_eq!(scan_text("f", "  path: /health/ready").len(), 1);

    // URL form on the RPC port (Docker/Compose regression).
    assert_eq!(
        scan_text(
            "f",
            r#"test: ["CMD","curl","-f","http://localhost:8545/health"]"#
        )
        .len(),
        1
    );

    // k8s compact form regressed to the rpc port.
    assert_eq!(
        scan_text("f", "httpGet: { path: /health, port: rpc }").len(),
        1
    );
    assert_eq!(
        scan_text("f", "httpGet: { path: /ready, port: rpc }").len(),
        1
    );

    // k8s multi-line form regressed to the rpc port.
    let multiline = "livenessProbe:\n  httpGet:\n    path: /health\n    port: rpc";
    assert_eq!(scan_text("f", multiline).len(), 1);

    // The current, FIXED forms must NOT be flagged.
    assert!(scan_text("f", "httpGet: { path: /health, port: health }").is_empty());
    assert!(scan_text("f", "httpGet: { path: /ready, port: health }").is_empty());
    assert!(scan_text(
        "f",
        r#"test: ["CMD","curl","-f","http://localhost:8546/health"]"#
    )
    .is_empty());
    let fixed_multiline = "livenessProbe:\n  httpGet:\n    path: /health\n    port: health";
    assert!(scan_text("f", fixed_multiline).is_empty());
}
