//! The frozen RISC Zero guest ELF + image id are produced by
//! `risc0_build::embed_methods()` with the pinned local r0 toolchain — a VENUE-only build
//! (owner decision B: no cargo-risczero CLI / guest-builder image / network). Off-venue and
//! in CI there is no guest toolchain, so we emit a STUB `methods.rs` (empty ELF, zero image
//! id) purely so the crate TYPE-CHECKS; the runtime refuses an empty embedded ELF, so a stub
//! can never yield a measurement. The venue sets `B0_VENUE_EMBED=1` to run the real build.
//!
//! PATH-INDEPENDENCE (§G): `embed_methods()` writes `methods.rs` with the guest ELF referenced by
//! an ABSOLUTE `include_bytes!("<abs>")` path, and risc0-build 3.0.5 places that ELF under
//! `<CARGO_TARGET_DIR>/riscv-guest/...` — a SIBLING of OUT_DIR, never under it (risc0-build
//! `get_riscv_guest_dir`). `rustc --remap-path-prefix` remaps compiler-visible source LOCATIONS, but
//! NOT string VALUES a codegen step bakes into a file, so under the canonical runner recipe the
//! embedded absolute path would differ between two path-distinct builds, breaking reproducibility.
//! `canonicalize_methods_rs` therefore, after `embed_methods()`:
//!   1. parses the single `_ELF = include_bytes!("<abs>")` entry (fail-closed on missing/multiple);
//!   2. validates the referenced guest ELF (absolute, canonical, regular, non-symlink, under the
//!      expected `<target>/riscv-guest` tree, non-empty);
//!   3. copies its exact bytes into OUT_DIR under a FIXED reviewed filename;
//!   4. verifies the copy equals the source byte-for-byte AND by SHA-256 + BLAKE3, and that the
//!      source did not change during the copy;
//!   5. rewrites `_ELF` to `include_bytes!(concat!(env!("OUT_DIR"), "/<fixed>"))` — a compile-time
//!      form whose value is consumed by the macro and never embedded;
//!   6. rewrites the unused `_PATH` const to a fixed canonical sentinel;
//!   7. scans the final `methods.rs` and refuses if ANY build-specific path (the original guest-ELF
//!      absolute path, CARGO_TARGET_DIR, the OUT_DIR value, or the original checkout root) remains.
//! This makes `methods.rs` and the embedded guest bytes byte-identical across path-distinct builds,
//! so the final runner is reproducible. There is NO RISC0 exception: the venue real-backend
//! double-build proves the two path-distinct runners byte-identical. The guest sub-build is pinned
//! LOCKED against the committed candidate workspace lock (RISC0_BUILD_LOCKED=1, set below).
//!
//! The PURE string/path helpers live in `src/embed_canon.rs`, included here (build-time) and into the
//! crate (so `cargo test` runs their unit tests). The fs copy + validation, hashing, env reads, and
//! facts emission stay here.
#![allow(clippy::doc_lazy_continuation)] // the numbered §G steps above are an intentional wrapped list

#[cfg(feature = "real-backend")]
use std::path::Path;

#[cfg(feature = "real-backend")]
#[path = "src/embed_canon.rs"]
mod embed_canon;
#[cfg(feature = "real-backend")]
use embed_canon::{
    expected_guest_root, parse_image_id, parse_single_elf_include, rewrite_methods, scan_no_leaks,
    CANONICAL_GUEST_ELF_NAME,
};

/// The embed decision. `B0_VENUE_EMBED` is a STRICT tri-state: exactly `"1"` selects the real
/// pinned-toolchain guest build; `"0"` OR the variable being unset selects the CI/off-venue STUB;
/// ANY other value is a configuration error that fails the build closed. (A permissive "non-empty ==
/// real" rule would let the documented `--embed 0` stub accidentally invoke `embed_methods()`.)
#[derive(Debug, PartialEq, Eq)]
enum Embed {
    Real,
    Stub,
}
fn decide_embed(v: Option<&str>) -> Result<Embed, String> {
    match v {
        Some("1") => Ok(Embed::Real),
        Some("0") | None => Ok(Embed::Stub),
        Some(other) => Err(format!(
            "invalid B0_VENUE_EMBED {other:?}: expected \"1\" (real embed) or \"0\"/unset (stub)"
        )),
    }
}

fn main() {
    // Declare the marker cfg so `#[cfg(real_guest_embedded)]` never warns (Rust >=1.80).
    println!("cargo:rustc-check-cfg=cfg(real_guest_embedded)");
    println!("cargo:rerun-if-env-changed=B0_VENUE_EMBED");
    println!("cargo:rerun-if-env-changed=RISC0_BUILD_LOCKED");
    let out = std::path::PathBuf::from(std::env::var("OUT_DIR").expect("OUT_DIR"));
    let methods = out.join("methods.rs");

    // Fail closed on an invalid B0_VENUE_EMBED regardless of the feature (so a bad value never silently
    // degrades to a stub). Only the REAL branch needs the real-backend SDK.
    let embed_env = std::env::var("B0_VENUE_EMBED").ok();
    let embed = decide_embed(embed_env.as_deref()).unwrap_or_else(|e| panic!("{e}"));

    #[cfg(feature = "real-backend")]
    if embed == Embed::Real {
        // (§G/A.9) Force the guest sub-build to be LOCKED against the committed candidate workspace
        // lock. risc0-build honors a non-empty RISC0_BUILD_LOCKED by adding `--locked`; set it here
        // (and retain it) so the guest can NEVER do an unlocked inner resolution, regardless of caller.
        std::env::set_var("RISC0_BUILD_LOCKED", "1");
        // The HOST build's RUSTC_WRAPPER enforces the exactly-two `--remap-path-prefix` host recipe.
        // risc0-build strips every CARGO* env but NOT RUSTC_WRAPPER, and it overwrites
        // CARGO_ENCODED_RUSTFLAGS with its own guest flags (which carry NO remaps) — so if the wrapper
        // stayed set every guest compile would be refused for "0 --remap-path-prefix args". Remove it so
        // the guest builds with the pinned risc0 rustc directly; the guest is path-independent by
        // construction (canonical HOME + source, identical across A/B), never by remap.
        std::env::remove_var("RUSTC_WRAPPER");
        // Real, pinned-toolchain guest build; writes methods.rs into OUT_DIR itself.
        risc0_build::embed_methods();
        // §G: copy the guest ELF into OUT_DIR and strip every build-specific absolute path from
        // methods.rs CONTENT so the embed is path-independent (a leaked absolute path is NOT remapped
        // by --remap-path-prefix, and risc0-build puts the ELF outside OUT_DIR).
        let out_dir = out.to_str().expect("OUT_DIR is valid UTF-8");
        canonicalize_methods_rs(&methods, out_dir);
        // The explicit, attestable stub/real marker: set ONLY when the real guest was embedded.
        println!("cargo:rustc-cfg=real_guest_embedded");
        return;
    }

    // Stub (embed == Stub, or real-backend not enabled): empty ELF, zero image id — the runtime refuses
    // an empty embedded ELF, so a stub can never yield a measurement.
    let _ = &embed; // used in the real-backend cfg above
    std::fs::write(
        &methods,
        "pub const B0_PRE_CANDIDATE_RISC0_GUEST_ELF: &[u8] = &[];\n\
         pub const B0_PRE_CANDIDATE_RISC0_GUEST_ID: [u32; 8] = [0u32; 8];\n",
    )
    .expect("write stub methods.rs");
}

/// Rewrite the `embed_methods()`-generated `methods.rs` so it carries NO build-specific absolute path,
/// copying the guest ELF into OUT_DIR (risc0-build leaves it under `<target>/riscv-guest`, a sibling of
/// OUT_DIR). Fail-closed at every step (see the module doc). The final methods.rs + embedded guest
/// bytes are byte-identical across path-distinct builds.
#[cfg(feature = "real-backend")]
fn canonicalize_methods_rs(methods: &Path, out_dir: &str) {
    let text = std::fs::read_to_string(methods).expect("read methods.rs for canonicalization");

    // (A.1/A.8) Parse the single `_ELF = include_bytes!("<abs>")` entry — refuse missing/ambiguous.
    let elf_abs = parse_single_elf_include(&text);

    // (A.2/A.8) Validate the guest ELF input: absolute, canonical, regular, non-symlink, under the
    // expected `<target>/riscv-guest` tree, non-empty.
    let expected_root = expected_guest_root(out_dir);
    validate_guest_elf(&elf_abs, &expected_root);

    // (A.3) Copy the exact bytes into OUT_DIR under the fixed reviewed filename.
    let src_bytes = std::fs::read(&elf_abs).expect("read guest ELF");
    assert!(!src_bytes.is_empty(), "guest ELF {elf_abs:?} is empty");
    let dst = Path::new(out_dir).join(CANONICAL_GUEST_ELF_NAME);
    std::fs::write(&dst, &src_bytes).expect("copy guest ELF into OUT_DIR");

    // (A.4) Verify the copy equals the source: cmp (byte-for-byte) + SHA-256 + BLAKE3.
    let dst_bytes = std::fs::read(&dst).expect("read copied guest ELF");
    assert!(
        src_bytes == dst_bytes,
        "copied guest ELF bytes differ from source (cmp)"
    );
    let s_sha = sha256_hex(&src_bytes);
    let s_b3 = blake3_hex(&src_bytes);
    assert!(
        s_sha == sha256_hex(&dst_bytes),
        "guest ELF SHA-256 differs after copy"
    );
    assert!(
        s_b3 == blake3_hex(&dst_bytes),
        "guest ELF BLAKE3 differs after copy"
    );

    // (A.8) Detect a source that changed during the copy: re-read and require identical bytes.
    let src_bytes2 = std::fs::read(&elf_abs).expect("re-read guest ELF");
    assert!(
        src_bytes == src_bytes2,
        "guest ELF {elf_abs:?} changed during copy"
    );

    // Parse the image id for the emitted A/B-equality facts (best effort; codegen shape may vary).
    let image_id = parse_image_id(&text);

    // (A.5/A.6) Rewrite `_ELF` to the OUT_DIR-relative include and `_PATH` to the fixed sentinel.
    let rewritten = rewrite_methods(&text);

    // (A.7) Scan the FINAL text: refuse if any build-specific path leaked.
    let forbidden = forbidden_leak_substrings(&elf_abs, out_dir);
    scan_no_leaks(&rewritten, &forbidden);

    std::fs::write(methods, &rewritten).expect("write canonicalized methods.rs");

    // Emit the guest-embed facts (canonical name + guest ELF SHA-256/BLAKE3 + image id) so the venue
    // double-build can assert A/B equality of the guest ELF and image id explicitly (A.10).
    emit_facts(out_dir, &s_sha, &s_b3, &image_id);
}

/// Validate the guest ELF input (A.2/A.8). Refuse anything not an absolute, canonical, regular,
/// non-symlink, non-empty file residing under the expected `<target>/riscv-guest` tree.
#[cfg(feature = "real-backend")]
fn validate_guest_elf(elf_abs: &str, expected_root: &Path) {
    let p = Path::new(elf_abs);
    assert!(
        p.is_absolute(),
        "guest ELF path {elf_abs:?} is not absolute"
    );
    let md = std::fs::symlink_metadata(p)
        .unwrap_or_else(|e| panic!("guest ELF {elf_abs:?} stat failed: {e}"));
    assert!(
        !md.file_type().is_symlink(),
        "guest ELF {elf_abs:?} is a symlink"
    );
    assert!(
        md.file_type().is_file(),
        "guest ELF {elf_abs:?} is not a regular file"
    );
    assert!(md.len() > 0, "guest ELF {elf_abs:?} is empty");
    // Canonical: canonicalize must reproduce the given path exactly (no symlink components, no `..`).
    let canon = std::fs::canonicalize(p)
        .unwrap_or_else(|e| panic!("guest ELF {elf_abs:?} canonicalize failed: {e}"));
    assert!(
        canon == p,
        "guest ELF path {elf_abs:?} is not canonical (resolves to {canon:?})"
    );
    assert!(
        p.starts_with(expected_root),
        "guest ELF {elf_abs:?} is not under expected guest root {expected_root:?}"
    );
}

/// The build-specific substrings that MUST NOT survive into the canonical methods.rs (A.7): the
/// original guest-ELF absolute path, the OUT_DIR value, CARGO_TARGET_DIR, the original checkout root
/// (CARGO_MANIFEST_DIR), and the derived `<target>` build root.
#[cfg(feature = "real-backend")]
fn forbidden_leak_substrings(elf_abs: &str, out_dir: &str) -> Vec<String> {
    let mut v = vec![elf_abs.to_string(), out_dir.to_string()];
    for key in ["CARGO_TARGET_DIR", "CARGO_MANIFEST_DIR"] {
        if let Ok(val) = std::env::var(key) {
            if !val.is_empty() {
                v.push(val);
            }
        }
    }
    if let Some(parent) = expected_guest_root(out_dir).parent() {
        if let Some(s) = parent.to_str() {
            v.push(s.to_string());
        }
    }
    v
}

/// Write the guest-embed facts sidecar into OUT_DIR for the venue double-build to consume (A.10).
#[cfg(feature = "real-backend")]
fn emit_facts(out_dir: &str, sha: &str, b3: &str, image_id: &Option<String>) {
    let id_json = match image_id {
        Some(csv) => format!("[{csv}]"),
        None => "null".to_string(),
    };
    let json = format!(
        "{{\"schema\":\"b0-final-risc0-guest-embed-facts/v1\",\
          \"canonical_elf_name\":\"{CANONICAL_GUEST_ELF_NAME}\",\
          \"guest_elf_sha256\":\"{sha}\",\
          \"guest_elf_blake3\":\"{b3}\",\
          \"guest_image_id\":{id_json}}}\n"
    );
    let p = Path::new(out_dir).join("b0_guest_embed_facts.json");
    std::fs::write(&p, json).expect("write guest embed facts");
}

#[cfg(feature = "real-backend")]
fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    hex(&Sha256::digest(bytes))
}

#[cfg(feature = "real-backend")]
fn blake3_hex(bytes: &[u8]) -> String {
    hex(blake3::hash(bytes).as_bytes())
}

#[cfg(feature = "real-backend")]
fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(bytes.len() * 2);
    for x in bytes {
        let _ = write!(s, "{x:02x}");
    }
    s
}

#[cfg(test)]
mod embed_tests {
    use super::{decide_embed, Embed};
    #[test]
    fn embed_selection_is_strict_tristate() {
        assert_eq!(decide_embed(Some("1")).unwrap(), Embed::Real);
        assert_eq!(decide_embed(Some("0")).unwrap(), Embed::Stub);
        assert_eq!(decide_embed(None).unwrap(), Embed::Stub);
        // Every other value refuses (the documented `--embed 0` stub never invokes embed_methods).
        for bad in ["", "2", "true", "01", " 1", "yes"] {
            assert!(
                decide_embed(Some(bad)).is_err(),
                "B0_VENUE_EMBED {bad:?} should refuse"
            );
        }
    }
}
