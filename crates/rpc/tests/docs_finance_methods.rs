//! Issue #26 (Finance sub-issue): doc/impl drift guard + a hard guard that
//! the ONLY `finance_*` RPCs are the three approved issuer-registry reads.

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

/// The exact approved Finance public surface (issuer registry only).
const ALLOWED: [&str; 3] = [
    "finance_getIssuer",
    "finance_getActiveIssuers",
    "finance_getIssuersByJurisdiction",
];

#[test]
fn finance_surface_is_exactly_issuer_registry_reads() {
    let api = read("src/api.rs");
    let registered = collect(&api, "name = \"", "finance_");
    let allowed: BTreeSet<String> = ALLOWED.iter().map(|s| s.to_string()).collect();

    // No finance_* method outside the approved issuer set — guards against
    // accidentally adding address-proof / bank-standing / KYC / proof / event
    // / by-subject RPCs.
    let extra: Vec<_> = registered.difference(&allowed).cloned().collect();
    assert!(extra.is_empty(), "unexpected finance_* RPC methods registered: {:?}", extra);
    assert_eq!(registered, allowed, "finance_* surface must be exactly the 3 issuer-registry reads");
}

#[test]
fn documented_finance_methods_exist_in_api() {
    let api = read("src/api.rs");
    let docs = read("../../docs/tokens.md");
    let registered = collect(&api, "name = \"", "finance_");
    let documented = collect(&docs, "\"method\":\"", "finance_");

    assert!(!documented.is_empty(), "no finance_* methods documented in tokens.md");
    let missing: Vec<_> = documented.difference(&registered).cloned().collect();
    assert!(missing.is_empty(), "tokens.md documents finance_* methods absent from api.rs: {:?}", missing);
}
