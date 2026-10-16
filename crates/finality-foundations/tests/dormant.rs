//! This crate is DORMANT: no other workspace crate may depend on it or name
//! it until a reviewed change wires it in (and deletes this test). The ratified
//! G2 semantics are not, by themselves, certified finality.

use std::path::{Path, PathBuf};

fn files(dir: &Path, ext: &str, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            if path.file_name().is_some_and(|n| n == "target") {
                continue;
            }
            files(&path, ext, out);
        } else if path.extension().is_some_and(|e| e == ext) {
            out.push(path);
        }
    }
}

#[test]
fn no_other_workspace_crate_uses_the_finality_foundations() {
    let crates = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
    let mut sources = Vec::new();
    let mut manifests = Vec::new();
    for entry in std::fs::read_dir(&crates).unwrap() {
        let dir = entry.unwrap().path();
        if !dir.is_dir() || dir.file_name().is_some_and(|n| n == "finality-foundations") {
            continue;
        }
        let manifest = dir.join("Cargo.toml");
        if manifest.is_file() {
            manifests.push(manifest);
        }
        for sub in ["src", "tests", "benches", "examples"] {
            let d = dir.join(sub);
            if d.is_dir() {
                files(&d, "rs", &mut sources);
            }
        }
    }
    assert!(
        sources.len() > 100 && manifests.len() > 10,
        "the scan found too few files to mean anything"
    );
    let mut hits = Vec::new();
    for f in manifests {
        if std::fs::read_to_string(&f)
            .unwrap()
            .contains("finality-foundations")
        {
            hits.push(format!("{} depends on it", f.display()));
        }
    }
    for f in sources {
        if std::fs::read_to_string(&f)
            .unwrap()
            .contains("sumchain_finality_foundations")
        {
            hits.push(format!("{} uses it", f.display()));
        }
    }
    assert!(
        hits.is_empty(),
        "the dormant finality foundations are referenced elsewhere:\n{}",
        hits.join("\n")
    );
}
