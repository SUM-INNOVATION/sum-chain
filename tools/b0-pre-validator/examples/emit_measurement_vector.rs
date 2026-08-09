//! Emit the committed real-orchestrator measurement vector.
//!
//! DETERMINISTIC: the output must byte-match
//! `docs/b0-pre/fixtures/measurement-vector/real-orchestrator-vector.bin`. The
//! vector is produced end-to-end through `measurement::orchestrate_grid` (SP1's
//! complete native matrix + RISC Zero's genuine x86_64-only matrix) — never a
//! hand-authored result set — so any drift requires re-running this emitter and an
//! explicit review of the new bytes (guarded by `measurement_vector.rs`).

use std::fs;
use std::path::Path;

use b0_pre_validator::hashing;
use b0_pre_validator::measurement::{deterministic_demo_vector, serialize_vector};

fn hx(b: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        let _ = write!(s, "{x:02x}");
    }
    s
}

fn main() {
    let (allowlist, bundles) = deterministic_demo_vector();
    let bytes = serialize_vector(&allowlist, &bundles);
    let fp = hx(&hashing::plain(&bytes));

    let dir =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/b0-pre/fixtures/measurement-vector");
    fs::create_dir_all(&dir).expect("mkdir");
    fs::write(dir.join("real-orchestrator-vector.bin"), &bytes).expect("write vector");
    fs::write(
        dir.join("real-orchestrator-vector.bin.blake3"),
        format!("{fp}\n"),
    )
    .expect("write fingerprint");

    eprintln!(
        "wrote real-orchestrator-vector.bin ({} bytes); blake3={fp}",
        bytes.len()
    );
}
