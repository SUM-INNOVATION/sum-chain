//! The census behind ConsensusConfigV1 (#268): what the commitment leaves out
//! stays out only while nothing in consensus code reads it, and what it takes
//! from a table stays in step with the table.
//!
//! Parameter structs are classified at compile time — `fields::build`
//! destructures each one without `..`. This file covers what the compiler
//! cannot: that an EXCLUDED field is genuinely unread, that a fallback the
//! encoder takes from `Default` is the literal execution actually uses, and that
//! the gate and limit tables match the lists they mirror.

use std::path::{Path, PathBuf};

use sumchain_consensus::consensus_config::fields::{gate_id, limit_id, EXCLUDED_PARAMETERS};
use sumchain_genesis::ChainParams;
use sumchain_primitives::StakingParams;
use sumchain_state::protocol_digest::consensus_limits;

fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// Crates whose code decides validity, execution, fork choice or membership.
const CONSENSUS_CRATES: &[&str] = &[
    "consensus",
    "state",
    "storage",
    "sumchain-wire",
    "primitives",
    "sumc-runtime",
    "nft",
    "beacon-runtime",
    "beacon-crypto",
    "crypto",
    "p2p",
    "node",
];

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let p = entry.unwrap().path();
        if p.is_dir() {
            rust_files(&p, out);
        } else if p.extension().is_some_and(|e| e == "rs") {
            out.push(p);
        }
    }
}

/// Production source of `krate`, with `#[cfg(test)] mod …` bodies cut off.
fn production_sources(krate: &str) -> Vec<(PathBuf, String)> {
    let mut files = Vec::new();
    rust_files(&repo().join("crates").join(krate).join("src"), &mut files);
    files
        .into_iter()
        .map(|p| {
            let s = std::fs::read_to_string(&p).unwrap();
            let cut = s
                .find("#[cfg(test)]\nmod ")
                .or_else(|| s.find("#[cfg(test)]\r\nmod "))
                .unwrap_or(s.len());
            (p, s[..cut].to_string())
        })
        .collect()
}

fn reads_field(src: &str, field: &str) -> bool {
    let pat = format!(".{field}");
    src.match_indices(&pat).any(|(i, _)| {
        let after = src[i + pat.len()..].chars().next();
        !after.is_some_and(|c| c.is_alphanumeric() || c == '_')
    })
}

/// Readers an exclusion is allowed to have, each with the reason it is not a
/// consensus reader.
const ALLOWED_READERS: &[(&str, &str, &str)] = &[
    (
        "block_time_ms",
        "crates/consensus/src/poa.rs",
        "the block producer's timer: when THIS node proposes, never whether a block is valid",
    ),
    (
        "max_message_size",
        "crates/p2p/src/behaviour.rs",
        "a gossipsub transport setting with the same name on a different struct",
    ),
    (
        // The classifier itself names every excluded field.
        "*",
        "crates/consensus/src/consensus_config/fields.rs",
        "the exclusion list",
    ),
];

#[test]
fn excluded_parameters_have_no_consensus_reader() {
    let mut failures = Vec::new();
    for (path, _why) in EXCLUDED_PARAMETERS {
        let field = path.rsplit('.').next().unwrap();
        for krate in CONSENSUS_CRATES {
            for (file, src) in production_sources(krate) {
                if !reads_field(&src, field) {
                    continue;
                }
                let rel = file
                    .strip_prefix(repo())
                    .unwrap_or(&file)
                    .to_string_lossy()
                    .replace("crates/../", "");
                let rel = rel.trim_start_matches("./").to_string();
                let allowed = ALLOWED_READERS.iter().any(|(f, p, _)| {
                    (*f == field || *f == "*") && rel.ends_with(p.trim_start_matches("crates/"))
                });
                if !allowed {
                    failures.push(format!("{path} is read in {rel}"));
                }
            }
        }
    }
    assert!(
        failures.is_empty(),
        "an excluded parameter gained a reader; commit it under a new schema or justify \
         the reader:\n{}",
        failures.join("\n")
    );
}

/// The staking executor's fallbacks for an unset `staking` group are inline
/// literals. The encoder commits `StakingParams::default()` in their place;
/// this pins every literal to the default it stands in for.
#[test]
fn staking_fallback_literals_equal_the_committed_defaults() {
    let src = std::fs::read_to_string(repo().join("crates/state/src/staking_executor.rs")).unwrap();
    let d = StakingParams::default();
    let expected: &[(&str, u128)] = &[
        ("min_validator_stake", d.min_validator_stake),
        ("max_commission_bps", d.max_commission_bps as u128),
        ("max_validators", d.max_validators as u128),
        ("unbonding_period", d.unbonding_period as u128),
        ("double_sign_slash_bps", d.double_sign_slash_bps as u128),
        (
            "double_sign_jail_duration",
            d.double_sign_jail_duration as u128,
        ),
        ("downtime_threshold", d.downtime_threshold as u128),
        ("downtime_slash_bps", d.downtime_slash_bps as u128),
        ("downtime_jail_duration", d.downtime_jail_duration as u128),
    ];
    let flat: String = src.split_whitespace().collect();
    let mut seen = 0;
    for (field, value) in expected {
        let needle = format!(".map(|s|s.{field}).unwrap_or(");
        let mut found = false;
        for (i, _) in flat.match_indices(&needle) {
            let rest = &flat[i + needle.len()..];
            let lit: String = rest
                .chars()
                .take_while(|c| c.is_ascii_digit() || *c == '_')
                .filter(|c| *c != '_')
                .collect();
            let lit: u128 = lit
                .parse()
                .unwrap_or_else(|_| panic!("{field}: {rest:.40}"));
            assert_eq!(lit, *value, "staking executor fallback for {field}");
            found = true;
            seen += 1;
        }
        assert!(found, "no fallback found for {field}");
    }
    // Every `.unwrap_or(` on a staking field is one of the above.
    let total = flat.matches("params.staking.as_ref()").count();
    assert_eq!(seen, total, "an unclassified staking fallback exists");
}

#[test]
fn every_activation_gate_has_exactly_one_field_id() {
    let gates = ChainParams::default().activation_heights();
    let mut ids: Vec<u16> = gates
        .iter()
        .map(|(name, _)| gate_id(name).unwrap_or_else(|| panic!("{name} has no id")))
        .collect();
    let n = ids.len();
    ids.sort();
    ids.dedup();
    assert_eq!(ids.len(), n, "two gates share an id");
    assert_eq!(
        sumchain_consensus::consensus_config::SCHEMA_V1_FIELDS
            .iter()
            .filter(|s| (0x1000..0x2000).contains(&s.id))
            .count(),
        n,
        "the registry holds a gate that ChainParams does not"
    );
}

#[test]
fn every_consensus_limit_has_exactly_one_field_id() {
    let limits = consensus_limits();
    for (name, _) in &limits {
        assert!(limit_id(name).is_some(), "{name} has no id");
    }
    assert_eq!(
        sumchain_consensus::consensus_config::SCHEMA_V1_FIELDS
            .iter()
            .filter(|s| (0x2000..0x2100).contains(&s.id))
            .count(),
        limits.len()
    );
}

// ── compiled constants ──────────────────────────────────────────────────────

/// Crates whose constant declarations are classified in the census file.
const CENSUS_CRATES: &[&str] = &[
    "beacon-crypto",
    "beacon-runtime",
    "consensus",
    "crypto",
    "genesis",
    "nft",
    "primitives",
    "state",
    "storage",
    "sumc-runtime",
    "sumchain-wire",
    "token",
];

/// One census row: `file, name, verdict, category, reason`.
fn census_rows() -> Vec<[String; 5]> {
    let text = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/data/consensus_constants_census.tsv"),
    )
    .unwrap();
    text.lines()
        .filter(|l| !l.starts_with('#') && !l.trim().is_empty())
        .map(|l| {
            let cols: Vec<&str> = l.split('\t').collect();
            assert_eq!(cols.len(), 5, "census row {l:?}");
            [0, 1, 2, 3, 4].map(|i| cols[i].to_string())
        })
        .collect()
}

/// Every UPPER_CASE `const`/`static` declared in production code of the census
/// crates, as `(repo-relative file, name)`, once per declaration.
///
/// A `#[cfg(test)]` item and everything nested in it is skipped. Feature-gated
/// test hooks and whole test-module files are scanned, and classified as such.
fn declared_constants() -> Vec<(String, String)> {
    let mut out = Vec::new();
    for krate in CENSUS_CRATES {
        let mut files = Vec::new();
        rust_files(&repo().join("crates").join(krate).join("src"), &mut files);
        files.sort();
        for file in files {
            let rel = format!(
                "crates/{krate}/{}",
                file.strip_prefix(repo().join("crates").join(krate))
                    .unwrap()
                    .to_string_lossy()
            );
            let src = std::fs::read_to_string(&file).unwrap();
            let mut skip_depth: Option<i64> = None;
            let mut depth: i64 = 0;
            let mut pending_skip = false;
            for line in src.lines() {
                let t = line.trim_start();
                if skip_depth.is_none()
                    && (t.starts_with("#[cfg(test)]")
                        || t.starts_with("#[cfg(any(test")
                        || t.starts_with("#[cfg(all(test"))
                {
                    pending_skip = true;
                }
                let opens = line.matches('{').count() as i64;
                let closes = line.matches('}').count() as i64;
                if skip_depth.is_none() && !pending_skip {
                    if let Some(name) = const_name(t) {
                        out.push((rel.clone(), name));
                    }
                }
                if pending_skip && !t.starts_with("#[") && !t.starts_with("//") && !t.is_empty() {
                    pending_skip = false;
                    if opens > closes {
                        skip_depth = Some(depth);
                    }
                    // A one-line item under the attribute is skipped by
                    // not having been recorded above.
                }
                depth += opens - closes;
                if let Some(d) = skip_depth {
                    if depth <= d {
                        skip_depth = None;
                    }
                }
            }
        }
    }
    out
}

fn const_name(t: &str) -> Option<String> {
    let mut rest = t;
    for prefix in ["pub(crate) ", "pub(super) ", "pub "] {
        if let Some(r) = rest.strip_prefix(prefix) {
            rest = r;
            break;
        }
    }
    let rest = rest
        .strip_prefix("const ")
        .or_else(|| rest.strip_prefix("static "))?;
    let name: String = rest
        .chars()
        .take_while(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || *c == '_')
        .collect();
    let after = rest[name.len()..].trim_start();
    (!name.is_empty()
        && name.chars().next().unwrap().is_ascii_uppercase()
        && after.starts_with(':'))
    .then_some(name)
}

#[test]
fn every_compiled_constant_is_classified() {
    use std::collections::BTreeMap;
    let mut declared: BTreeMap<(String, String), usize> = BTreeMap::new();
    for key in declared_constants() {
        *declared.entry(key).or_default() += 1;
    }
    let mut classified: BTreeMap<(String, String), usize> = BTreeMap::new();
    for row in census_rows() {
        assert!(
            matches!(row[2].as_str(), "COMMITTED" | "EXCLUDE"),
            "verdict {row:?}"
        );
        assert!(
            !row[3].is_empty() && !row[4].is_empty(),
            "unexplained {row:?}"
        );
        *classified
            .entry((row[0].clone(), row[1].clone()))
            .or_default() += 1;
    }
    let mut problems = Vec::new();
    for (key, n) in &declared {
        let c = classified.get(key).copied().unwrap_or(0);
        if c != *n {
            problems.push(format!("{} {}: declared {n}, classified {c}", key.0, key.1));
        }
    }
    for (key, c) in &classified {
        if !declared.contains_key(key) {
            problems.push(format!(
                "{} {}: classified {c}, no longer declared",
                key.0, key.1
            ));
        }
    }
    assert!(
        problems.is_empty(),
        "constants census out of date — classify each in \
         crates/consensus/tests/data/consensus_constants_census.tsv (COMMITTED with its \
         field id, or EXCLUDE with a reason):\n{}",
        problems.join("\n")
    );
}

#[test]
fn every_committed_constant_row_names_a_registry_field_and_back() {
    use sumchain_consensus::consensus_config::fields::{extra_constants, spec_for};
    let mut from_census: Vec<u16> = census_rows()
        .iter()
        .filter(|r| r[2] == "COMMITTED" && r[3] == "registry" && r[4].starts_with("0x2"))
        .map(|r| u16::from_str_radix(r[4].trim_start_matches("0x"), 16).unwrap())
        .collect();
    from_census.sort();
    // Struct-default fields are committed field by field and are not
    // declarations, so they have no census row.
    let mut from_registry: Vec<u16> = extra_constants()
        .iter()
        .filter(|(_, name, _)| !name.contains("::default()."))
        .map(|(id, _, _)| *id)
        .collect();
    from_registry.sort();
    assert_eq!(from_census, from_registry);
    for (id, name, _) in extra_constants() {
        assert_eq!(spec_for(id).map(|s| s.name), Some(name), "{id:#06x}");
    }
}

/// Gated constants (the beacon's DSTs and wire format) are committed although
/// the gate cannot open today; this pins that it still cannot, so the day it can
/// is a deliberate review of what the beacon path commits to.
#[test]
fn the_beacon_and_compute_pool_gates_are_still_refused() {
    let beacon = ChainParams {
        beacon_enabled_from_height: Some(1),
        ..ChainParams::default()
    };
    assert!(beacon.validate().is_err());
    let compute_pool = ChainParams {
        compute_pool_enabled_from_height: Some(1),
        ..ChainParams::default()
    };
    assert!(compute_pool.validate().is_err());
}
