//! The frozen RISC Zero guest ELF + image id are produced by
//! `risc0_build::embed_methods()` with the pinned local r0 toolchain — a VENUE-only build
//! (owner decision B: no cargo-risczero CLI / guest-builder image / network). Off-venue and
//! in CI there is no guest toolchain, so we emit a STUB `methods.rs` (empty ELF, zero image
//! id) purely so the crate TYPE-CHECKS; the runtime refuses an empty embedded ELF, so a stub
//! can never yield a measurement. The venue sets `B0_VENUE_EMBED=1` to run the real build.
//!
//! PATH-INDEPENDENCE (§G): `embed_methods()` writes `methods.rs` with the guest ELF referenced by
//! an OUT_DIR-ABSOLUTE path — both `..._ELF = include_bytes!("<abs>")` and `..._PATH: &str = "<abs>"`.
//! `rustc --remap-path-prefix` remaps compiler-visible source LOCATIONS, but NOT string VALUES an env
//! or a codegen step bakes into a file. So under the canonical runner recipe (source/CARGO_HOME/target
//! remapped to /b0/{tooling,cargo,target}) the embedded absolute path would still differ between two
//! path-distinct builds, breaking runner reproducibility. `canonicalize_methods_rs` therefore rewrites
//! methods.rs so NO build-specific absolute path remains in its CONTENT: the `_ELF` include uses the
//! `concat!(env!("OUT_DIR"), "/<rel>")` form (compile-time only — the OUT_DIR value is consumed by the
//! macro to locate the file and is never embedded), and the unused `_PATH` const becomes a fixed
//! canonical sentinel. This makes methods.rs byte-identical across path-distinct builds, so the
//! embedded guest bytes and the final runner are reproducible. There is NO RISC0 exception: the CI
//! real-backend double-build (b0-pre.yml) proves the two path-distinct runners byte-identical.

#[cfg(feature = "real-backend")]
use std::path::Path;

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
    let out = std::path::PathBuf::from(std::env::var("OUT_DIR").expect("OUT_DIR"));
    let methods = out.join("methods.rs");

    // Fail closed on an invalid B0_VENUE_EMBED regardless of the feature (so a bad value never silently
    // degrades to a stub). Only the REAL branch needs the real-backend SDK.
    let embed_env = std::env::var("B0_VENUE_EMBED").ok();
    let embed = decide_embed(embed_env.as_deref()).unwrap_or_else(|e| panic!("{e}"));

    #[cfg(feature = "real-backend")]
    if embed == Embed::Real {
        // Real, pinned-toolchain guest build; writes methods.rs into OUT_DIR itself.
        risc0_build::embed_methods();
        // §G: strip the OUT_DIR-absolute path from methods.rs CONTENT so the embed is
        // path-independent (a leaked absolute path is NOT remapped by --remap-path-prefix).
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

/// Rewrite the `embed_methods()`-generated `methods.rs` so it carries NO build-specific absolute path.
/// Fail-closed: panics (breaking the build) if the expected `_ELF` include line is absent or its path
/// is not under OUT_DIR — a silent miss would let an un-remapped absolute path leak into the runner.
#[cfg(feature = "real-backend")]
fn canonicalize_methods_rs(methods: &Path, out_dir: &str) {
    let text = std::fs::read_to_string(methods).expect("read methods.rs for canonicalization");
    let mut out = String::with_capacity(text.len());
    let mut rewired_elf = false;
    for line in text.lines() {
        // `pub const {NAME}_ELF: &[u8] = include_bytes!("<abs>");`  (risc0-build 3.0.5 codegen)
        if line.contains("_ELF: &[u8] = include_bytes!(\"") {
            let (lhs, _) = line.split_once(" = ").expect("_ELF line has ' = '");
            let abs = first_quoted(line).expect("_ELF include_bytes has a quoted path");
            let rel = rel_under(&abs, out_dir);
            out.push_str(lhs);
            out.push_str(" = include_bytes!(concat!(env!(\"OUT_DIR\"), \"/");
            out.push_str(&rel);
            out.push_str("\"));\n");
            rewired_elf = true;
        // `pub const {NAME}_PATH: &str = "<abs>";`  — unused; neutralize to a fixed canonical sentinel.
        } else if line.contains("_PATH: &str = \"") {
            let (lhs, _) = line.split_once(" = ").expect("_PATH line has ' = '");
            let abs = first_quoted(line).expect("_PATH has a quoted path");
            let rel = rel_under(&abs, out_dir);
            out.push_str(lhs);
            out.push_str(" = \"/b0/target/");
            out.push_str(&rel);
            out.push_str("\";\n");
        } else {
            out.push_str(line);
            out.push('\n');
        }
    }
    assert!(
        rewired_elf,
        "methods.rs did not contain the expected `_ELF = include_bytes!(\"<abs>\")` line; \
         embed_methods() codegen changed — refusing to emit a possibly path-dependent runner"
    );
    std::fs::write(methods, out).expect("write canonicalized methods.rs");
}

/// The substring between the first pair of double quotes (Linux guest-ELF paths carry no escapes).
#[cfg(feature = "real-backend")]
fn first_quoted(line: &str) -> Option<String> {
    let a = line.find('"')? + 1;
    let b = line[a..].find('"')? + a;
    Some(line[a..b].to_string())
}

/// Strip the OUT_DIR prefix (and one leading '/') from an absolute path. Panics if `abs` is not under
/// OUT_DIR — that would mean the concat!(env!("OUT_DIR"), ...) form could not locate the file, so it is
/// safer to fail the build than to emit a runner that silently embeds an absolute path.
#[cfg(feature = "real-backend")]
fn rel_under(abs: &str, out_dir: &str) -> String {
    let rest = abs
        .strip_prefix(out_dir)
        .unwrap_or_else(|| panic!("guest ELF path {abs:?} is not under OUT_DIR {out_dir:?}"));
    rest.trim_start_matches('/').to_string()
}
