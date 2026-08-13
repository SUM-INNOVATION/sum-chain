//! The committed owner-ratified third-party notice map loads and is structurally valid: unique
//! family ids, non-empty sha-true sorted-unique notices, and no crate covered by two families.
//! (Ratification of the texts themselves is an owner decision; this only guards structural drift.)

use b0_pre_validator::venue::third_party_notices::RatifiedNoticeMap;
use serde_json::Value;

const MAP: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../b0-pre-candidates/policy/third-party-notice-map.json"
));

#[test]
fn committed_notice_map_loads_and_validates() {
    let m = RatifiedNoticeMap::load(MAP)
        .expect("committed third-party notice map must load + structurally validate");
    assert!(!m.families.is_empty(), "map has no families");
    assert!(
        !m.policy_version.trim().is_empty(),
        "map has empty policy_version"
    );
}

/// defmt-parser 1.0.0 is recorded through a FETCHED-UPSTREAM family bound to the exact
/// upstream commit + both real license files (no canonical fallback, no attestation).
#[test]
fn defmt_parser_recorded_via_fetched_upstream_family() {
    let m = RatifiedNoticeMap::load(MAP).unwrap();
    let fam = m
        .families
        .iter()
        .find(|f| f.id == "knurling-defmt-parser")
        .expect("defmt-parser fetched-upstream family present");
    assert_eq!(fam.spdx, "MIT OR Apache-2.0");
    assert!(fam.covers.iter().any(|c| c == "defmt-parser"));
    assert!(
        fam.attestation.is_none(),
        "a fetched-upstream family carries real license text, never a canonical attestation"
    );
    let fu = fam
        .fetched_upstream
        .as_ref()
        .expect("structured fetched_upstream present");
    assert_eq!(fu.crate_name, "defmt-parser");
    assert_eq!(fu.crate_version, "1.0.0");
    assert_eq!(fu.commit, "4a8cdb44891ed57b8ff5a023b6bec7137c48708f");
    assert_eq!(fu.commit_authority, ".cargo_vcs_info.json");
    assert!(fu.published_license_files_absent);
    // Both real upstream license files, sorted by path.
    let paths: Vec<&str> = fam.notices.iter().map(|n| n.path.as_str()).collect();
    assert_eq!(paths, vec!["LICENSE-APACHE", "LICENSE-MIT"]);
}

fn map_value() -> Value {
    serde_json::from_str(MAP).unwrap()
}
fn defmt_idx(m: &Value) -> usize {
    m["families"]
        .as_array()
        .unwrap()
        .iter()
        .position(|f| f["id"] == "knurling-defmt-parser")
        .unwrap()
}

/// A nonexistent-tag substitution (a tag where a 40-hex commit is required) fails closed.
#[test]
fn fetched_upstream_rejects_nonexistent_tag_commit() {
    let mut m = map_value();
    let i = defmt_idx(&m);
    m["families"][i]["fetched_upstream"]["commit"] = Value::from("v1.0.0");
    assert!(RatifiedNoticeMap::load(&m.to_string()).is_err());
    // a well-formed but truncated (non-40-hex) commit is also refused
    let mut m = map_value();
    let i = defmt_idx(&m);
    m["families"][i]["fetched_upstream"]["commit"] = Value::from("4a8cdb44");
    assert!(RatifiedNoticeMap::load(&m.to_string()).is_err());
}

/// Corrupted license bytes/hash (a notice sha256 that no longer matches its text) fails closed.
#[test]
fn fetched_upstream_rejects_wrong_license_hash() {
    let mut m = map_value();
    let i = defmt_idx(&m);
    m["families"][i]["notices"][0]["sha256"] = Value::from("0".repeat(64));
    assert!(RatifiedNoticeMap::load(&m.to_string()).is_err());
}

/// A fetched-upstream family MUST record that the published crate ships no license file.
#[test]
fn fetched_upstream_rejects_published_license_present_claim() {
    let mut m = map_value();
    let i = defmt_idx(&m);
    m["families"][i]["fetched_upstream"]["published_license_files_absent"] = Value::from(false);
    assert!(RatifiedNoticeMap::load(&m.to_string()).is_err());
}
