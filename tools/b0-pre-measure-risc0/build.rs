//! The frozen RISC Zero guest ELF + image id are produced by
//! `risc0_build::embed_methods()` with the pinned local r0 toolchain — a VENUE-only build
//! (owner decision B: no cargo-risczero CLI / guest-builder image / network). Off-venue and
//! in CI there is no guest toolchain, so we emit a STUB `methods.rs` (empty ELF, zero image
//! id) purely so the crate TYPE-CHECKS; the runtime refuses an empty embedded ELF, so a stub
//! can never yield a measurement. The venue sets `B0_VENUE_EMBED=1` to run the real build.

fn main() {
    // Declare the marker cfg so `#[cfg(real_guest_embedded)]` never warns (Rust >=1.80).
    println!("cargo:rustc-check-cfg=cfg(real_guest_embedded)");
    println!("cargo:rerun-if-env-changed=B0_VENUE_EMBED");
    let out = std::path::PathBuf::from(std::env::var("OUT_DIR").expect("OUT_DIR"));
    let methods = out.join("methods.rs");

    #[cfg(feature = "real-backend")]
    {
        if std::env::var("B0_VENUE_EMBED").is_ok_and(|v| !v.is_empty()) {
            // Real, pinned-toolchain guest build; writes methods.rs into OUT_DIR itself.
            risc0_build::embed_methods();
            // The explicit, attestable stub/real marker: set ONLY when the real guest was
            // embedded. The authoritative binary requires it (main.rs); the backend identity
            // reflects it. Distinguishing real from stub is thus explicit, not inferred from
            // ELF length alone.
            println!("cargo:rustc-cfg=real_guest_embedded");
            return;
        }
    }

    std::fs::write(
        &methods,
        "pub const B0_PRE_CANDIDATE_RISC0_GUEST_ELF: &[u8] = &[];\n\
         pub const B0_PRE_CANDIDATE_RISC0_GUEST_ID: [u32; 8] = [0u32; 8];\n",
    )
    .expect("write stub methods.rs");
}
