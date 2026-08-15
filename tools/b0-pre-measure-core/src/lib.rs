//! B0-FINAL measurement runner CORE. Backend-agnostic, always-compiled, fully unit-
//! tested off-venue. Owns the crypto-boundary trait, RSS capture, independent identity
//! binding, RawFacts emission, self/backend evidence binding, and fail-closed
//! orchestration. The SP1/RISC0 SDK implementations live in the venue-compiled runner
//! crates behind `--features real-backend`; the only in-core backend is the test mock.

pub mod backend;
pub mod binding;
pub mod facts;
pub mod rss;
pub mod run;

use serde::Serialize;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Candidate {
    Sp1,
    Risc0,
}
impl Candidate {
    pub fn as_str(self) -> &'static str {
        match self {
            Candidate::Sp1 => "Sp1",
            Candidate::Risc0 => "Risc0",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Arch {
    X86_64,
    Aarch64,
}
impl Arch {
    pub fn as_str(self) -> &'static str {
        match self {
            Arch::X86_64 => "x86_64",
            Arch::Aarch64 => "aarch64",
        }
    }
    pub fn parse(s: &str) -> Result<Arch, String> {
        match s {
            "x86_64" => Ok(Arch::X86_64),
            "aarch64" => Ok(Arch::Aarch64),
            other => Err(format!("unknown arch {other}")),
        }
    }
}

/// Native eligibility (mirrors the validator): RISC Zero is x86_64-only; SP1 both.
pub fn native_eligible(c: Candidate, a: Arch) -> bool {
    match c {
        Candidate::Risc0 => a == Arch::X86_64,
        Candidate::Sp1 => true,
    }
}

/// The expected statement journal (`computation_statement_hash`, 32 bytes) the official
/// guest commits for a materialized input — recomputed HOST-SIDE via the candidate-neutral
/// guest core so a proof/receipt can be bound to the EXACT statement over the EXACT input.
/// Fail-closed if the input is malformed or the statement is rejected.
pub fn expected_journal(input: &[u8]) -> Result<[u8; 32], String> {
    b0_pre_guest_core::run(input)
        .map_err(|e| format!("guest-core rejected the materialized input: {e}"))
}

pub fn hex(b: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        let _ = write!(s, "{x:02x}");
    }
    s
}

/// Evidence binding the exact production binary + enabled backend that produced a
/// measurement (gating-condition #3). Emitted as a sidecar next to the RawFacts fragment.
#[derive(Serialize, Debug)]
pub struct RunnerAttestation {
    pub kind: String,
    pub candidate: String,
    pub arch: String,
    pub production_binary_blake3: String,
    pub backend_identity: String,
    /// Always true for an authoritative run: the mock backend can never emit this.
    pub real_backend: bool,
    pub b0_pre_spec_hash: String,
    pub r0_guest_set_hash: String,
}

/// BLAKE3 of the currently-running production binary, bound into evidence so a
/// measurement is attributable to the exact runner build.
pub fn production_binary_blake3() -> Result<String, String> {
    let exe = std::env::current_exe().map_err(|e| format!("current_exe: {e}"))?;
    let bytes = std::fs::read(&exe).map_err(|e| format!("read {}: {e}", exe.display()))?;
    Ok(hex(blake3::hash(&bytes).as_bytes()))
}

/// A typed guest-identity record — the phase-1 output of a runner's `--emit-identity`
/// (build/SDK identity ONLY, no proof/measurement). Serialize twin of the validator's
/// `guest_set::GuestIdentityRecord`; the `measure-produce --guest-set` assembler consumes it.
#[derive(Serialize)]
pub struct GuestIdentityRecord {
    pub candidate: String,
    pub arch: String,
    pub source_commit: String,
    pub clean_tree: bool,
    pub guest_source_tree_hash: String,
    pub candidate_dep_lock_hash: String,
    pub guest_image_hash: String,
    pub program_id: String,
    pub builder_container_digest: String,
    pub toolchain_identity: String,
    pub verifier_material_manifest_hash: String,
    pub build_command_hash: String,
    pub production_binary_blake3: String,
    pub real_backend: bool,
    pub real_guest_embedded: bool,
    pub b0_pre_spec_hash: String,
    /// Two-root MEASUREMENT-TOOLING authority the identity was derived with (distinct from
    /// `source_commit`, the measured source). Verified against the tooling authority, never compared
    /// to `RATIFIED_SOURCE_COMMIT`.
    pub tooling_commit: String,
    pub tooling_pathset_blake3: String,
}
