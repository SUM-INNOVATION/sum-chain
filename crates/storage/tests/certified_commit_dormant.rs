//! The certified-commit seam (#270) is DORMANT: no crate outside
//! `sumchain-storage` may use it until the commit rule (F-1), the certificate
//! encoding and the storage layout are ratified and an activation is
//! authorized. Wiring it in must be a deliberate change that deletes this test.

use std::path::{Path, PathBuf};

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            rust_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

#[test]
fn no_crate_outside_storage_uses_the_certified_seam() {
    let crates = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
    let mut files = Vec::new();
    for entry in std::fs::read_dir(&crates).unwrap() {
        let dir = entry.unwrap().path();
        if dir.file_name().is_some_and(|n| n == "storage") {
            continue;
        }
        for sub in ["src", "tests", "benches", "examples"] {
            let d = dir.join(sub);
            if d.is_dir() {
                rust_files(&d, &mut files);
            }
        }
    }
    assert!(
        files.len() > 100,
        "the scan found too few sources to mean anything"
    );
    let mut hits = Vec::new();
    for f in files {
        let src = std::fs::read_to_string(&f).unwrap();
        for needle in [
            "certified::",
            "CertifiedStore",
            "CertificateVerifier",
            "CertifiedLayout",
        ] {
            if src.contains(needle) {
                hits.push(format!("{} uses {needle}", f.display()));
            }
        }
    }
    assert!(
        hits.is_empty(),
        "the dormant certified seam is referenced outside storage:\n{}",
        hits.join("\n")
    );
}

/// The seam adds no column family: what it writes goes where an injected
/// layout says, into families that already exist.
#[test]
fn the_seam_declares_no_column_family_or_key() {
    let src =
        std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/certified.rs")).unwrap();
    assert!(
        !src.contains("pub const"),
        "the seam must not define keys, families or encodings"
    );
    let db = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/db.rs")).unwrap();
    let finality_families: Vec<&str> = db
        .lines()
        .map(str::trim)
        .filter(|l| {
            l.starts_with("pub const") && (l.contains("CERTIFICATE") || l.contains("FINALITY"))
        })
        .collect();
    assert!(
        finality_families.is_empty(),
        "no certificate or finality column family may be added by this seam: {finality_families:?}"
    );
}
