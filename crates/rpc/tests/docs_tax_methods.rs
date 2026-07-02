//! Issue #26: guard against doc/impl drift — every per-family read method
//! documented in docs/tokens.md must be a registered RPC method in api.rs.
//! Covers the promoted families (Tax, Equity, ...).

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

/// Collect identifiers with the given `prefix` that follow `needle` in `text`.
fn collect_methods(text: &str, needle: &str, prefix: &str) -> BTreeSet<String> {
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

#[test]
fn documented_family_methods_exist_in_api() {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let api = fs::read_to_string(manifest.join("src/api.rs")).expect("read api.rs");
    let docs = fs::read_to_string(manifest.join("../../docs/tokens.md")).expect("read tokens.md");

    // Per-family read RPCs promoted under issue #26.
    for prefix in ["tax_", "equity_", "property_", "finance_", "legal_", "healthcare_", "gov_"] {
        // api.rs declares methods as `#[method(name = "<prefix>...")]`.
        let registered = collect_methods(&api, "name = \"", prefix);
        // tokens.md curl examples use `"method":"<prefix>..."`.
        let documented = collect_methods(&docs, "\"method\":\"", prefix);

        assert!(
            !documented.is_empty(),
            "no {} methods documented in tokens.md",
            prefix
        );
        let missing: Vec<_> = documented.difference(&registered).cloned().collect();
        assert!(
            missing.is_empty(),
            "tokens.md documents {} methods not registered in api.rs: {:?}",
            prefix,
            missing
        );
    }
}
