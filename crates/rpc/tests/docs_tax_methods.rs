//! Issue #26: guard against doc/impl drift — every `tax_*` method documented in
//! docs/tokens.md must be a registered RPC method in api.rs.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

/// Collect all `tax_*` identifiers that follow `needle` in `text`.
fn collect_tax_methods(text: &str, needle: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for (idx, _) in text.match_indices(needle) {
        let rest = &text[idx + needle.len()..];
        let name: String = rest
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
            .collect();
        if name.starts_with("tax_") {
            out.insert(name);
        }
    }
    out
}

#[test]
fn documented_tax_methods_exist_in_api() {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let api = fs::read_to_string(manifest.join("src/api.rs")).expect("read api.rs");
    let docs = fs::read_to_string(manifest.join("../../docs/tokens.md")).expect("read tokens.md");

    // api.rs declares methods as `#[method(name = "tax_...")]`.
    let registered = collect_tax_methods(&api, "name = \"");
    // tokens.md curl examples use `"method":"tax_..."`.
    let documented = collect_tax_methods(&docs, "\"method\":\"");

    assert!(!documented.is_empty(), "no tax_* methods documented in tokens.md");

    let missing: Vec<_> = documented.difference(&registered).cloned().collect();
    assert!(
        missing.is_empty(),
        "tokens.md documents tax_* methods not registered in api.rs: {:?}",
        missing
    );
}
