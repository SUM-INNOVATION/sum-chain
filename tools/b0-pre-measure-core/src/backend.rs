//! The proving-backend TRAIT — the single cryptographic SDK/Docker boundary. The
//! always-compiled core drives it; the venue-compiled SP1/RISC0 runner crates implement
//! it against the real pinned SDKs. A test-only mock (dev builds) implements it with a
//! deterministic non-crypto stand-in so the whole orchestration is exercised locally —
//! the mock is NEVER reachable from an authoritative binary.

use std::path::PathBuf;

use crate::rss;
use crate::{Arch, Candidate};

/// Context for a guest build (materialized official input lives under `work_dir`).
pub struct BuildCtx {
    pub arch: Arch,
    pub work_dir: PathBuf,
}

/// Guest identity + build provenance, DERIVED FROM THE ACTUAL BUILT GUEST/SDK — never
/// inferred from the verifier-material manifest. `program_id` is the identity the proof
/// must independently commit to (SP1: verifying-key hash; RISC0: image id).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GuestArtifact {
    pub guest_image_hash: String,
    pub program_id: String,
    pub guest_source_tree_hash: String,
    pub candidate_dep_lock_hash: String,
    pub build_command_hash: String,
    pub reproducible: bool,
    /// (arch, builder_container_digest) — SP1 has both arches; RISC0 x86_64 only.
    pub builders: Vec<(Arch, String)>,
}

/// One proof/receipt plus the phase timings and the PROVING-CONTAINER RSS the backend
/// captured from the container cgroup (never getrusage).
pub struct ProofOutput {
    /// The proof/receipt bytes (SP1: the Groth16 proof; RISC0: the serialized receipt).
    pub bytes: Vec<u8>,
    /// Public inputs bound to the proof, kept SEPARATE from `bytes` so a verifier that
    /// takes them apart (e.g. sp1-verifier) gets exact slices. Empty when the receipt is
    /// self-contained (RISC0).
    pub public_inputs: Vec<u8>,
    pub setup_ns: u64,
    pub prove_ns: u64,
    pub proving_run_rss_bytes: u64,
    pub proving_cgroup_identity: String,
}

/// The guest identity a proof/receipt COMMITS to, decoded from the proof itself.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProofIdentity {
    pub committed_program_id: String,
}

pub trait ProvingBackend {
    fn candidate(&self) -> Candidate;

    /// A stable identity for the enabled backend (e.g. `sp1-sdk=6.3.1`), bound into evidence.
    fn backend_identity(&self) -> String;

    /// True ONLY for the test-only mock. An authoritative run refuses when this is true,
    /// and the emitted evidence records `real_backend = false`, so a mock can never be
    /// laundered into authoritative measurement evidence.
    fn is_mock(&self) -> bool {
        false
    }

    /// Build/compile the frozen official guest and read its identity from the built
    /// artifact/SDK. Fail-closed on any build/identity failure.
    fn build_guest(&self, ctx: &BuildCtx) -> Result<GuestArtifact, String>;

    /// Prove one statement. The impl times setup+prove and reads
    /// `proving_run_rss_bytes` from the proving CONTAINER's cgroup peak (fail-closed if
    /// unavailable). It never fills RSS from `getrusage`.
    fn prove(&self, guest: &GuestArtifact, input: &[u8]) -> Result<ProofOutput, String>;

    /// Verify a proof against the built guest identity AND the exact statement it must
    /// prove: `expected_journal` is the official guest's `computation_statement_hash`
    /// recomputed host-side from the materialized input. The impl must (a) cryptographically
    /// verify the proof and (b) require the value the proof COMMITS to equal
    /// `expected_journal` — so a valid proof for a DIFFERENT input is refused. Returns `Err`
    /// on any failure; the caller treats that as a refusal, never "accepted".
    fn verify(
        &self,
        guest: &GuestArtifact,
        proof: &ProofOutput,
        expected_journal: &[u8; 32],
    ) -> Result<(), String>;

    /// Decode the proof (against the expected statement journal) and return the guest
    /// identity it COMMITS to, so the core can independently bind it to the build-derived
    /// identity + the verifier material.
    fn proof_identity(
        &self,
        guest: &GuestArtifact,
        proof: &ProofOutput,
        expected_journal: &[u8; 32],
    ) -> Result<ProofIdentity, String>;

    /// Peak RSS of a verification batch. Default = native `getrusage` (correct when
    /// verification is native, e.g. RISC0). A containerized verify (SP1 gnark) overrides
    /// this to read its verify-container cgroup peak.
    fn capture_verify_rss(&self) -> Result<u64, String> {
        rss::native_peak_rss_bytes()
    }

    /// The `(role, entry_blake3_hex)` verifier constants this backend's verifier ACTUALLY
    /// uses (SP1: `blake3(GROTH16_VK_BYTES)`; RISC0: control-root/control-id/verifier-params
    /// digests). The core binds the harness verifier material against these, so an unrelated
    /// VMAT cannot pass. Fail-closed if the constants cannot be derived.
    fn expected_verifier_entries(&self) -> Result<Vec<(String, String)>, String>;
}
