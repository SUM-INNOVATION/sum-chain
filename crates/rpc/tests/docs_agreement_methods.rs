//! Issue #26 (Agreement sub-issue): doc/impl drift guard + a hard guard that
//! the ONLY `agreement_*` RPCs are the four approved executor-link reads.

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

/// The exact approved Agreement public surface (executor links only).
const ALLOWED: [&str; 4] = [
    "agreement_getExecutorLink",
    "agreement_getExecutorLinksByAgreement",
    "agreement_getExecutorLinksByExecutor",
    "agreement_getActiveExecutorLinks",
];

#[test]
fn agreement_surface_is_exactly_executor_links() {
    let api = read("src/api.rs");
    let registered = collect(&api, "name = \"", "agreement_");
    let allowed: BTreeSet<String> = ALLOWED.iter().map(|s| s.to_string()).collect();

    // No agreement_* method outside the approved executor-link set — guards
    // against accidentally adding getAgreement / *ByParty / signature /
    // attestation / ip / proof / event RPCs.
    let extra: Vec<_> = registered.difference(&allowed).cloned().collect();
    assert!(extra.is_empty(), "unexpected agreement_* RPC methods registered: {:?}", extra);
    assert_eq!(registered, allowed, "agreement_* surface must be exactly the 4 executor-link reads");
}

#[test]
fn documented_agreement_methods_exist_in_api() {
    let api = read("src/api.rs");
    let docs = read("../../docs/tokens.md");
    let registered = collect(&api, "name = \"", "agreement_");
    let documented = collect(&docs, "\"method\":\"", "agreement_");

    assert!(!documented.is_empty(), "no agreement_* methods documented in tokens.md");
    let missing: Vec<_> = documented.difference(&registered).cloned().collect();
    assert!(missing.is_empty(), "tokens.md documents agreement_* methods absent from api.rs: {:?}", missing);
}
