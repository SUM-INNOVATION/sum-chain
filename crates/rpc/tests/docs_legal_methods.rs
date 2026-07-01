//! Issue #26 (Legal sub-issue): doc/impl drift guard + a hard guard that the
//! ONLY `legal_*` RPCs are the three approved case-anchor reads.

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

/// The exact approved Legal public surface (case anchors only).
const ALLOWED: [&str; 3] = [
    "legal_getCase",
    "legal_getActiveCases",
    "legal_getCasesByJurisdiction",
];

#[test]
fn legal_surface_is_exactly_case_anchor_reads() {
    let api = read("src/api.rs");
    let registered = collect(&api, "name = \"", "legal_");
    let allowed: BTreeSet<String> = ALLOWED.iter().map(|s| s.to_string()).collect();

    // No legal_* method outside the approved case-anchor set — guards against
    // accidentally adding process-event / order / benefit / proof / event /
    // by-case / by-subject RPCs.
    let extra: Vec<_> = registered.difference(&allowed).cloned().collect();
    assert!(extra.is_empty(), "unexpected legal_* RPC methods registered: {:?}", extra);
    assert_eq!(registered, allowed, "legal_* surface must be exactly the 3 case-anchor reads");
}

#[test]
fn documented_legal_methods_exist_in_api() {
    let api = read("src/api.rs");
    let docs = read("../../docs/tokens.md");
    let registered = collect(&api, "name = \"", "legal_");
    let documented = collect(&docs, "\"method\":\"", "legal_");

    assert!(!documented.is_empty(), "no legal_* methods documented in tokens.md");
    let missing: Vec<_> = documented.difference(&registered).cloned().collect();
    assert!(missing.is_empty(), "tokens.md documents legal_* methods absent from api.rs: {:?}", missing);
}
