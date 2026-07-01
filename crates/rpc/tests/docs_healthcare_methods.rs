//! Issue #41 (Healthcare sub-issue): doc/impl drift guard + a hard guard that
//! the ONLY `healthcare_*` RPCs are the two approved institutional provider
//! reads.

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

/// The exact approved Healthcare public surface (institutional provider reads).
const ALLOWED: [&str; 2] = [
    "healthcare_getInstitutionalProvider",
    "healthcare_getActiveInstitutionalProviders",
];

#[test]
fn healthcare_surface_is_exactly_institutional_provider_reads() {
    let api = read("src/api.rs");
    let registered = collect(&api, "name = \"", "healthcare_");
    let allowed: BTreeSet<String> = ALLOWED.iter().map(|s| s.to_string()).collect();

    // No healthcare_* method outside the approved institutional set — guards
    // against accidentally adding getProvider / getActiveProviders /
    // getProvidersByNetwork / by-patient / by-member / by-subject / consent /
    // prescription / proof / event RPCs.
    let extra: Vec<_> = registered.difference(&allowed).cloned().collect();
    assert!(extra.is_empty(), "unexpected healthcare_* RPC methods registered: {:?}", extra);
    assert_eq!(
        registered, allowed,
        "healthcare_* surface must be exactly the 2 institutional provider reads"
    );
}

#[test]
fn documented_healthcare_methods_exist_in_api() {
    let api = read("src/api.rs");
    let docs = read("../../docs/tokens.md");
    let registered = collect(&api, "name = \"", "healthcare_");
    let documented = collect(&docs, "\"method\":\"", "healthcare_");

    assert!(!documented.is_empty(), "no healthcare_* methods documented in tokens.md");
    let missing: Vec<_> = documented.difference(&registered).cloned().collect();
    assert!(missing.is_empty(), "tokens.md documents healthcare_* methods absent from api.rs: {:?}", missing);
}
