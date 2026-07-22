//! Venue-side verification logic that MUST run identically off-venue and on-venue.
//!
//! The authoritative B0-PRE run only executes on a native Linux venue with Docker
//! and the proving toolchains present; here (arm64 macOS, no Docker/toolchains) the
//! real run fails closed. But the *decision logic* the venue commands depend on —
//! parsing an OCI image layout for its true manifest identity, verifying an
//! artifact checksum, rejecting a host-originated lock, importing a returned
//! per-architecture bundle, and aggregating both architectures — is pure and can be
//! exercised (and adversarially tested) without any venue. Each submodule
//! implements one such core and is unit-tested against real-shaped inputs, so the
//! shell venue commands call a decision that is proven off-venue rather than
//! trusted blind.
//!
//! None of this installs a toolchain, starts Docker, pushes an image, computes the
//! real `b0_pre_spec_hash`, or writes the committed artifact.

pub mod arch_bundle;
pub mod audit;
pub mod evidence_bundle;
pub mod lock_provenance;
pub mod oci_layout;
pub mod sha256;
pub mod stage4;
pub mod stage5;
pub mod tool_install;

/// Lowercase-hex of a byte slice (shared by the venue submodules).
pub(crate) fn to_hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// True iff `s` is exactly 64 lowercase-hex characters.
pub(crate) fn is_hex64(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

/// The unmistakable synthetic sentinel. Any venue input carrying it is TEST_ONLY
/// and can never be accepted as real venue-selected evidence. Mirrors
/// [`crate::schema::stage1_bundle::TEST_ONLY_TOOL_SENTINEL`] — the single source.
pub(crate) const TEST_ONLY_SENTINEL: &str = crate::schema::stage1_bundle::TEST_ONLY_TOOL_SENTINEL;

/// True iff `s` carries the synthetic marker (sentinel or an obviously-synthetic
/// scheme). Used to REJECT synthetic values on the authoritative venue path.
pub(crate) fn is_synthetic(s: &str) -> bool {
    let up = s.to_ascii_uppercase();
    up.contains(TEST_ONLY_SENTINEL) || up.contains("SYNTHETIC") || up.contains("TEST_ONLY")
}
