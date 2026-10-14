//! Issue #118 runtime-path contract for `deploy/snip-local-mirror.yaml`.
//!
//! The compose preset runs a SYNTHETIC five-validator test topology from the
//! generated, ignored `devnet/` directory (throwaway keys; not a production
//! validator set). This static check pins its wiring so it cannot drift back
//! to a tracked or nonexistent genesis:
//!
//! * every host bind is the long form, sourced from `../devnet/` only
//!   (`../devnet/genesis.json` or `../devnet/keys/validator<i>.json`), and
//!   carries `create_host_path: false`, so an absent file fails `up` instead of
//!   Docker creating an empty directory in its place;
//! * there is no short-form host bind and no reference to `genesis/` (in
//!   particular the old, nonexistent `genesis/snip-mirror-genesis.json`);
//! * it runs exactly [`TOPOLOGY_DEFAULT_VALIDATORS`] validator services, each
//!   mounting the shared genesis plus its own key, and each started with
//!   `--genesis /config/genesis.json`.
//!
//! Docker's own reading of the file (`docker compose config`) and the
//! absent-genesis failure are checked by `deploy/topology-e2e-harness.sh` in CI.

use std::path::Path;

use sumchain_scripts::TOPOLOGY_DEFAULT_VALIDATORS;

const COMPOSE: &str = "deploy/snip-local-mirror.yaml";
const GENESIS_SOURCE: &str = "../devnet/genesis.json";

fn compose_text() -> String {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("repo root");
    std::fs::read_to_string(root.join(COMPOSE)).expect("read the compose file")
}

/// Non-comment lines, with their trimmed content.
fn code_lines(text: &str) -> Vec<&str> {
    text.lines()
        .filter(|l| !l.trim_start().starts_with('#'))
        .collect()
}

/// `(service name, body lines)` for every top-level service whose name starts
/// with `validator-`.
fn validator_services(text: &str) -> Vec<(String, Vec<String>)> {
    let lines = code_lines(text);
    let start = lines
        .iter()
        .position(|l| *l == "services:")
        .expect("a services: section");
    let mut out: Vec<(String, Vec<String>)> = Vec::new();
    for line in &lines[start + 1..] {
        if line.trim().is_empty() {
            continue;
        }
        let indent = line.len() - line.trim_start().len();
        if indent == 0 {
            break; // next top-level key
        }
        if indent == 2 {
            let name = line.trim().trim_end_matches(':').to_string();
            out.push((name, Vec::new()));
        } else if let Some((_, body)) = out.last_mut() {
            body.push(line.trim().to_string());
        }
    }
    out.retain(|(name, _)| name.starts_with("validator-"));
    out
}

#[test]
fn every_host_bind_comes_from_the_ignored_devnet_directory_and_fails_closed() {
    let text = compose_text();
    let lines = code_lines(&text);

    let sources: Vec<&str> = lines
        .iter()
        .filter_map(|l| l.trim().strip_prefix("source:").map(str::trim))
        .collect();
    assert!(
        !sources.is_empty(),
        "the compose file must bind the runtime files"
    );
    let allowed: Vec<String> = std::iter::once(GENESIS_SOURCE.to_string())
        .chain(
            (1..=TOPOLOGY_DEFAULT_VALIDATORS).map(|i| format!("../devnet/keys/validator{i}.json")),
        )
        .collect();
    for s in &sources {
        assert!(
            allowed.iter().any(|a| a == s),
            "unexpected bind source {s:?}"
        );
    }

    // Every long-form bind is fail-closed on an absent source.
    let types = lines.iter().filter(|l| l.trim() == "- type: bind").count();
    let fail_closed = lines
        .iter()
        .filter(|l| l.trim() == "create_host_path: false")
        .count();
    assert_eq!(
        types,
        sources.len(),
        "every source: belongs to a long-form bind"
    );
    assert_eq!(
        fail_closed,
        sources.len(),
        "every bind must set create_host_path: false"
    );

    // No short-form host bind (`- ../x:/y`), and nothing under genesis/.
    for l in &lines {
        let t = l.trim();
        if t.starts_with("source:") || t == "context: .." {
            continue;
        }
        assert!(!t.contains("../"), "short-form or stray host path: {t:?}");
    }
    assert!(
        !text.contains("genesis/"),
        "no reference to the tracked genesis/ directory"
    );
    assert!(
        !text.contains("snip-mirror-genesis"),
        "the nonexistent genesis must be gone"
    );
}

#[test]
fn it_runs_exactly_the_default_topology_each_with_the_shared_genesis_and_its_own_key() {
    let services = validator_services(&compose_text());
    let names: Vec<&str> = services.iter().map(|(n, _)| n.as_str()).collect();
    let want: Vec<String> = (1..=TOPOLOGY_DEFAULT_VALIDATORS)
        .map(|i| format!("validator-{i}"))
        .collect();
    assert_eq!(names, want, "validator services");

    for (i, (name, body)) in services.iter().enumerate() {
        let key = format!("source: ../devnet/keys/validator{}.json", i + 1);
        let genesis = format!("source: {GENESIS_SOURCE}");
        assert_eq!(
            body.iter().filter(|l| **l == genesis).count(),
            1,
            "{name}: genesis mount"
        );
        assert_eq!(
            body.iter().filter(|l| **l == key).count(),
            1,
            "{name}: own key mount"
        );
        assert_eq!(
            body.iter()
                .filter(|l| l.starts_with("source: ../devnet/keys/"))
                .count(),
            1,
            "{name}: exactly one key"
        );
        let flag = body
            .iter()
            .position(|l| l == "- \"--genesis\"")
            .expect("--genesis");
        assert_eq!(
            body[flag + 1],
            "- \"/config/genesis.json\"",
            "{name}: --genesis path"
        );
        assert!(
            body.iter().any(|l| l == "target: /config/genesis.json"),
            "{name}: genesis target"
        );
    }
}
