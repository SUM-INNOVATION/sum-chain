//! Issue #311: activation gates, extra funded accounts and an output
//! directory for the `local` and `smoke` devnets.

use std::path::Path;
use std::process::Command;

use sumchain_crypto::KeyPair;
use sumchain_genesis::{ChainParams, Genesis};
use sumchain_scripts::{
    activation_gate_fields, apply_gate_overrides, provision_smoke, provision_smoke_with,
    DevnetOptions, FundEntry, GateOverride, ROLE_ALLOC,
};

const BIN: &str = env!("CARGO_BIN_EXE_setup-local-testnet");

/// The gates SwUM's prototype needs (issue #311), besides V2.
const SWUM_GATES: &[&str] = &[
    "omninode",
    "archive_unbonding",
    "archive_reassignment",
    "por_assignment_targeting",
    "assignment_aware_por_scheduler",
];

fn gates(names: &[&str]) -> Vec<GateOverride> {
    names.iter().map(|n| n.parse().unwrap()).collect()
}

fn gate_value(genesis: &Genesis, field: &str) -> serde_json::Value {
    serde_json::to_value(&genesis.params).unwrap()[field].clone()
}

// ── Parsing ──────────────────────────────────────────────────────────────────

#[test]
fn a_gate_is_named_with_or_without_its_suffix_and_defaults_to_height_0() {
    let g: GateOverride = "omninode".parse().unwrap();
    assert_eq!(
        (g.field.as_str(), g.height),
        ("omninode_enabled_from_height", 0)
    );
    let g: GateOverride = "v2_enabled_from_height=12".parse().unwrap();
    assert_eq!((g.field.as_str(), g.height), ("v2_enabled_from_height", 12));
    for bad in ["", "=3", "Omni-Node", "omninode=x", "omninode=-1"] {
        assert!(bad.parse::<GateOverride>().is_err(), "{bad:?} parsed");
    }
}

#[test]
fn a_funded_account_defaults_to_the_role_allocation() {
    let f: FundEntry = "abc".parse().unwrap();
    assert_eq!((f.address.as_str(), f.amount), ("abc", ROLE_ALLOC));
    let f: FundEntry = "abc=7".parse().unwrap();
    assert_eq!(f.amount, 7);
    for bad in ["", "=5", "abc=0", "abc=-1", "abc=x"] {
        assert!(bad.parse::<FundEntry>().is_err(), "{bad:?} parsed");
    }
}

// ── Applying gates ───────────────────────────────────────────────────────────

#[test]
fn gates_are_set_and_nothing_else_changes() {
    let before = ChainParams::with_v2_enabled();
    let mut params = before.clone();
    apply_gate_overrides(
        &mut params,
        &gates(&["omninode", "archive_reassignment=40"]),
    )
    .unwrap();
    assert_eq!(params.omninode_enabled_from_height, Some(0));
    assert_eq!(params.archive_reassignment_enabled_from_height, Some(40));
    let (mut a, b) = (
        serde_json::to_value(&params).unwrap(),
        serde_json::to_value(&before).unwrap(),
    );
    a["omninode_enabled_from_height"] = b["omninode_enabled_from_height"].clone();
    a["archive_reassignment_enabled_from_height"] =
        b["archive_reassignment_enabled_from_height"].clone();
    assert_eq!(a, b, "only the named gates change");

    // No gates: untouched.
    let mut same = before.clone();
    apply_gate_overrides(&mut same, &[]).unwrap();
    assert_eq!(
        serde_json::to_value(&same).unwrap(),
        serde_json::to_value(&before).unwrap()
    );
}

#[test]
fn an_unknown_or_repeated_gate_is_refused() {
    let mut params = ChainParams::with_v2_enabled();
    let err = apply_gate_overrides(&mut params, &gates(&["omnynode"]))
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("omnynode") && err.contains("omninode"),
        "{err}"
    );
    // A parameter that is not a gate.
    assert!(apply_gate_overrides(&mut params, &gates(&["finality_depth"])).is_err());
    assert!(apply_gate_overrides(&mut params, &gates(&["v2", "v2=3"])).is_err());
}

#[test]
fn every_issue_311_gate_is_an_activation_gate() {
    let fields = activation_gate_fields();
    for g in SWUM_GATES.iter().chain(&["v2"]) {
        assert!(fields.contains(&format!("{g}_enabled_from_height")), "{g}");
    }
}

// ── Smoke mode ───────────────────────────────────────────────────────────────

#[test]
fn smoke_opens_the_swum_gates_and_funds_extra_accounts() {
    let dir = tempfile::tempdir().unwrap();
    let gateway = KeyPair::generate().address().to_base58();
    let operator = KeyPair::generate().address().to_base58();
    let opts = DevnetOptions {
        gates: gates(SWUM_GATES),
        fund: vec![
            gateway.parse().unwrap(),
            format!("{operator}=5").parse().unwrap(),
        ],
    };
    let art = provision_smoke_with(dir.path(), 1, &opts).unwrap();

    let genesis = Genesis::from_file(&art.genesis_path).expect("the loader accepts it");
    assert_eq!(genesis.params.v2_enabled_from_height, Some(0));
    for g in SWUM_GATES {
        assert_eq!(
            gate_value(&genesis, &format!("{g}_enabled_from_height")),
            0,
            "{g}"
        );
    }
    assert_eq!(genesis.params.compute_pool_enabled_from_height, None);
    assert_eq!(genesis.params.beacon_enabled_from_height, None);
    assert_eq!(genesis.alloc.get(&gateway).copied(), Some(ROLE_ALLOC));
    assert_eq!(genesis.alloc.get(&operator).copied(), Some(5));

    let manifest: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&art.manifest_path).unwrap()).unwrap();
    assert_eq!(
        manifest["options"]["enabled_gates"]["omninode_enabled_from_height"],
        0
    );
    assert_eq!(manifest["options"]["funded"][1]["amount"], "5");
}

#[test]
fn smoke_refuses_the_compute_pool_gate_and_a_duplicate_account() {
    let dir = tempfile::tempdir().unwrap();
    let err = provision_smoke_with(
        dir.path(),
        1,
        &DevnetOptions {
            gates: gates(&["compute_pool"]),
            fund: vec![],
        },
    )
    .unwrap_err();
    assert!(format!("{err:#}").contains("compute-pool"), "{err:#}");

    let dir = tempfile::tempdir().unwrap();
    let a = KeyPair::generate().address().to_base58();
    let err = provision_smoke_with(
        dir.path(),
        1,
        &DevnetOptions {
            gates: vec![],
            fund: vec![a.parse().unwrap(), a.parse().unwrap()],
        },
    )
    .unwrap_err();
    assert!(format!("{err:#}").contains("uplicate"), "{err:#}");
}

#[test]
fn smoke_without_options_is_unchanged() {
    let dir = tempfile::tempdir().unwrap();
    let art = provision_smoke(dir.path(), 1).unwrap();
    let genesis = Genesis::from_file(&art.genesis_path).unwrap();
    assert_eq!(genesis.params.omninode_enabled_from_height, None);
    assert_eq!(genesis.alloc.len(), 1 + art.roles.len());
    let manifest: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&art.manifest_path).unwrap()).unwrap();
    assert_eq!(
        manifest["options"],
        serde_json::json!({ "enabled_gates": {}, "funded": [] })
    );
}

// ── The binary ───────────────────────────────────────────────────────────────

fn run(cwd: &Path, args: &[&str]) -> (bool, String) {
    let out = Command::new(BIN)
        .args(args)
        .current_dir(cwd)
        .output()
        .unwrap();
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).to_string() + &String::from_utf8_lossy(&out.stderr),
    )
}

#[test]
fn local_mode_writes_under_output_dir_with_gates_and_funding() {
    let cwd = tempfile::tempdir().unwrap();
    let out = tempfile::tempdir().unwrap();
    let archive = KeyPair::generate().address().to_base58();
    let (ok, text) = run(
        cwd.path(),
        &[
            "--output-dir",
            out.path().to_str().unwrap(),
            "--enable",
            "omninode",
            "--enable",
            "archive_unbonding=3",
            "--fund",
            &archive,
        ],
    );
    assert!(ok, "{text}");

    // Nothing in the working directory.
    assert_eq!(std::fs::read_dir(cwd.path()).unwrap().count(), 0, "{text}");

    let genesis = Genesis::from_file(out.path().join("genesis/local_genesis.json")).unwrap();
    assert_eq!(genesis.chain_id, 1337);
    assert_eq!(genesis.validators.len(), 3);
    assert_eq!(genesis.params.v2_enabled_from_height, Some(0));
    assert_eq!(genesis.params.omninode_enabled_from_height, Some(0));
    assert_eq!(
        genesis.params.archive_unbonding_enabled_from_height,
        Some(3)
    );
    assert_eq!(genesis.alloc.get(&archive).copied(), Some(ROLE_ALLOC));
    for k in ["validator1", "validator2", "validator3", "test_account"] {
        assert!(out.path().join(format!("keys/{k}.json")).is_file(), "{k}");
    }

    // One health address per node, and the printed commands use them.
    let mut health = Vec::new();
    for n in ["validator1", "validator2", "validator3", "fullnode"] {
        let cfg = out.path().join(format!("config/{n}.toml"));
        let text_cfg = std::fs::read_to_string(&cfg).unwrap();
        assert!(
            text_cfg.starts_with("[health]\naddr = \"127.0.0.1:910"),
            "{text_cfg}"
        );
        health.push(text_cfg);
        assert!(
            text.contains(&cfg.canonicalize().unwrap().display().to_string()),
            "{text}"
        );
    }
    health.sort();
    health.dedup();
    assert_eq!(health.len(), 4);
    assert!(text.contains("omninode_enabled_from_height = 0"), "{text}");
}

#[test]
fn local_mode_without_options_still_writes_to_the_working_directory() {
    let cwd = tempfile::tempdir().unwrap();
    let (ok, text) = run(cwd.path(), &[]);
    assert!(ok, "{text}");
    let genesis = Genesis::from_file(cwd.path().join("genesis/local_genesis.json")).unwrap();
    assert_eq!(genesis.params.omninode_enabled_from_height, None);
    assert!(cwd.path().join("keys/validator1.json").is_file());
    assert!(!cwd.path().join("config").exists());
    assert!(
        text.contains("Key saved to: keys/validator1.json"),
        "{text}"
    );
}

#[test]
fn local_output_dir_must_be_empty_and_outside_the_repository() {
    let cwd = tempfile::tempdir().unwrap();
    let busy = tempfile::tempdir().unwrap();
    std::fs::write(busy.path().join("x"), b"x").unwrap();
    let (ok, text) = run(cwd.path(), &["--output-dir", busy.path().to_str().unwrap()]);
    assert!(!ok && text.contains("EMPTY"), "{text}");

    let repo = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let (ok, text) = run(
        cwd.path(),
        &["--output-dir", repo.join("genesis").to_str().unwrap()],
    );
    assert!(!ok && text.contains("OUTSIDE the repository"), "{text}");
    assert_eq!(std::fs::read_dir(cwd.path()).unwrap().count(), 0);
}

#[test]
fn topology_refuses_gates_and_funding() {
    let cwd = tempfile::tempdir().unwrap();
    let out = tempfile::tempdir().unwrap();
    for extra in [["--enable", "omninode"], ["--fund", "abc"]] {
        let mut args = vec![
            "--mode",
            "topology",
            "--output-dir",
            out.path().to_str().unwrap(),
        ];
        args.extend(extra);
        let (ok, text) = run(cwd.path(), &args);
        assert!(
            !ok && text.contains("not supported with --mode topology"),
            "{text}"
        );
    }
    assert_eq!(std::fs::read_dir(out.path()).unwrap().count(), 0);
}
