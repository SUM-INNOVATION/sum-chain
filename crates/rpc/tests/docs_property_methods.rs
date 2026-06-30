//! Issue #26 (Property sub-issue): doc/impl drift guard + a hard guard that
//! the ONLY `property_*` RPCs are the three approved asset-anchor reads.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

fn collect(text: &str, needle: &str, prefix: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for (idx, _) in text.match_indices(needle) {
        let rest = &text[idx + needle.len()..];
        let name: String = rest
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
            .collect();
        if name.starts_with(prefix) {
            out.insert(name);
        }
    }
    out
}

fn read(rel: &str) -> String {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(rel);
    fs::read_to_string(p).unwrap_or_else(|_| panic!("read {}", rel))
}

/// The exact approved Property public surface (asset anchors only).
const ALLOWED: [&str; 3] = [
    "property_getAsset",
    "property_getActiveAssets",
    "property_getAssetsByJurisdiction",
];

#[test]
fn property_surface_is_exactly_asset_anchor_reads() {
    let api = read("src/api.rs");
    let registered = collect(&api, "name = \"", "property_");
    let allowed: BTreeSet<String> = ALLOWED.iter().map(|s| s.to_string()).collect();

    // No property_* method outside the approved asset-anchor set — guards
    // against accidentally adding title-event / encumbrance / coverage /
    // claim / proof / event RPCs.
    let extra: Vec<_> = registered.difference(&allowed).cloned().collect();
    assert!(extra.is_empty(), "unexpected property_* RPC methods registered: {:?}", extra);
    assert_eq!(registered, allowed, "property_* surface must be exactly the 3 asset-anchor reads");
}

#[test]
fn documented_property_methods_exist_in_api() {
    let api = read("src/api.rs");
    let docs = read("../../docs/tokens.md");
    let registered = collect(&api, "name = \"", "property_");
    let documented = collect(&docs, "\"method\":\"", "property_");

    assert!(!documented.is_empty(), "no property_* methods documented in tokens.md");
    let missing: Vec<_> = documented.difference(&registered).cloned().collect();
    assert!(missing.is_empty(), "tokens.md documents property_* methods absent from api.rs: {:?}", missing);
}
