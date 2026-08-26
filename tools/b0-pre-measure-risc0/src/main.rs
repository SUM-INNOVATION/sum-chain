//! `b0-pre-measure-risc0` — the venue RISC Zero measurement runner (x86_64-only).
//!
//! PRODUCTION-ONLY: refuses to build without `--features real-backend` (gating condition
//! #1). All measurement/binding/emission/RSS logic is the unit-tested
//! `b0-pre-measure-core`; this crate supplies the real RISC Zero 3.0.5 backend — the sole
//! venue-only crypto boundary. The guest ELF + image id come from
//! `risc0_build::embed_methods()` (build.rs) and are BOUND as the guest identity;
//! `receipt.verify(image_id)` decodes+checks that binding.

#[cfg(not(feature = "real-backend"))]
compile_error!(
    "b0-pre-measure-risc0 is a production measurement binary: build it with \
     --features real-backend (the pinned RISC Zero 3.0.5 SDK). It has no mock or fallback \
     proving path — the test-only mock lives in b0-pre-measure-core's cfg(test)."
);

// §G guest-embed canonicalization helpers (pure string/path logic), shared VERBATIM with build.rs
// (which includes the same file via `#[path]`). Declared here so `cargo test` exercises its unit
// tests; the runner binary never calls these at runtime (`#![allow(dead_code)]` inside the module).
#[cfg(feature = "real-backend")]
mod embed_canon;

#[cfg(feature = "real-backend")]
fn main() -> std::process::ExitCode {
    match real::cli_main() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("INELIGIBLE: RISC Zero measurement runner failed closed: {e}");
            std::process::ExitCode::FAILURE
        }
    }
}

#[cfg(feature = "real-backend")]
mod real {
    use std::path::PathBuf;
    use std::time::Instant;

    use b0_pre_measure_core::backend::{
        BuildCtx, GuestArtifact, ProofIdentity, ProofOutput, ProvingBackend,
    };
    use b0_pre_measure_core::binding::parse_harness_verifier_material;
    use b0_pre_measure_core::facts::ProvFacts;
    use b0_pre_measure_core::run::{
        run_arch_fragment, select_fragment_identity_record, RunConfig, StatementInput,
    };
    use b0_pre_measure_core::{
        hex, production_binary_blake3, Arch, Candidate, GuestIdentityRecord,
    };

    use risc0_zkvm::sha::Digest;
    use risc0_zkvm::{default_prover, ExecutorEnv, ProverOpts, Receipt};

    // Emitted by embed_methods() (venue) or the CI stub (empty). The runtime refuses an
    // empty ELF, so a stub build can never produce a measurement.
    include!(concat!(env!("OUT_DIR"), "/methods.rs"));

    const MERGED_SPEC: &str = "e933e7325c2639a48d8e25f20746d0f8abc822dee9fcfa87c2e6cdec226cf2a2";

    struct Risc0Backend {
        guest_source_tree_hash: String,
        candidate_dep_lock_hash: String,
        build_command_hash: String,
        builder_container_digest: String,
        firewall_attest: PathBuf,
    }

    fn image_id() -> Digest {
        Digest::from(B0_PRE_CANDIDATE_RISC0_GUEST_ID)
    }
    fn image_id_hex() -> String {
        hex(image_id().as_bytes())
    }

    /// Newest firewall attestation record for the RISC Zero stark2snark PROVE call →
    /// container cgroup peak + identity. Fail-closed if the firewall recorded none.
    fn latest_proving_container_rss(attest: &std::path::Path) -> Result<(u64, String), String> {
        let text = std::fs::read_to_string(attest)
            .map_err(|e| format!("read firewall attestation {}: {e}", attest.display()))?;
        let mut found: Option<(u64, String)> = None;
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let v: serde_json::Value =
                serde_json::from_str(line).map_err(|e| format!("attestation line JSON: {e}"))?;
            if v.get("candidate").and_then(|c| c.as_str()) != Some("risc0") {
                continue;
            }
            let peak = v
                .get("proving_container_peak_rss_bytes")
                .and_then(|p| p.as_u64())
                .ok_or("RISC0 prove attestation missing proving_container_peak_rss_bytes")?;
            let cg = v
                .get("proving_cgroup_identity")
                .and_then(|c| c.as_str())
                .ok_or("RISC0 prove attestation missing proving_cgroup_identity")?
                .to_string();
            found = Some((peak, cg));
        }
        found.ok_or_else(|| {
            "no RISC Zero stark2snark record in the firewall attestation; refusing to report \
             proving RSS not measured from the container cgroup"
                .to_string()
        })
    }

    impl ProvingBackend for Risc0Backend {
        fn candidate(&self) -> Candidate {
            Candidate::Risc0
        }
        fn backend_identity(&self) -> String {
            // Reflect the attestable stub/real marker so evidence records which was used.
            if cfg!(real_guest_embedded) {
                "risc0-zkvm=3.0.5+real-guest-embedded".into()
            } else {
                "risc0-zkvm=3.0.5+STUB-NO-GUEST".into()
            }
        }
        fn build_guest(&self, _ctx: &BuildCtx) -> Result<GuestArtifact, String> {
            let elf: &[u8] = B0_PRE_CANDIDATE_RISC0_GUEST_ELF;
            if elf.is_empty() {
                return Err(
                    "empty embedded guest ELF: embed_methods did not run with the pinned \
                     toolchain (venue B0_VENUE_EMBED=1 required); refusing"
                        .into(),
                );
            }
            // Guest identity IS the embed_methods image id — bound directly from the build.
            Ok(GuestArtifact {
                guest_image_hash: hex(blake3::hash(elf).as_bytes()),
                program_id: image_id_hex(),
                guest_source_tree_hash: self.guest_source_tree_hash.clone(),
                candidate_dep_lock_hash: self.candidate_dep_lock_hash.clone(),
                build_command_hash: self.build_command_hash.clone(),
                reproducible: true,
                builders: vec![(Arch::X86_64, self.builder_container_digest.clone())],
            })
        }
        fn prove(&self, _guest: &GuestArtifact, input: &[u8]) -> Result<ProofOutput, String> {
            let elf: &[u8] = B0_PRE_CANDIDATE_RISC0_GUEST_ELF;
            let mut builder = ExecutorEnv::builder();
            builder
                .write(&input.to_vec())
                .map_err(|e| format!("write guest input: {e}"))?;
            let env = builder.build().map_err(|e| format!("executor env: {e}"))?;

            // RISC Zero has no separate host-side setup phase; the stark2snark docker call
            // is intercepted by the firewall (on PATH), which records the container peak.
            let t_prove = Instant::now();
            let receipt = default_prover()
                .prove_with_opts(env, elf, &ProverOpts::groth16())
                .map_err(|e| format!("RISC Zero Groth16 proving failed: {e}"))?
                .receipt;
            let prove_ns = t_prove.elapsed().as_nanos() as u64;

            let (proving_run_rss_bytes, proving_cgroup_identity) =
                latest_proving_container_rss(&self.firewall_attest)?;
            let bytes =
                bincode::serialize(&receipt).map_err(|e| format!("serialize receipt: {e}"))?;
            Ok(ProofOutput {
                bytes,
                public_inputs: Vec::new(),
                setup_ns: 0,
                prove_ns,
                proving_run_rss_bytes,
                proving_cgroup_identity,
            })
        }
        fn verify(
            &self,
            _guest: &GuestArtifact,
            proof: &ProofOutput,
            expected_journal: &[u8; 32],
        ) -> Result<(), String> {
            // NATIVE decode + verify against the embedded image id (no proving container) —
            // getrusage is the correct verify-RSS source (core default).
            let receipt: Receipt = bincode::deserialize(&proof.bytes)
                .map_err(|e| format!("deserialize receipt: {e}"))?;
            receipt
                .verify(B0_PRE_CANDIDATE_RISC0_GUEST_ID)
                .map_err(|e| format!("RISC Zero receipt verification failed: {e}"))?;
            // STATEMENT BINDING: the receipt's committed journal MUST equal the expected
            // guest journal recomputed from the materialized input — a valid receipt for a
            // DIFFERENT input is refused, not just any receipt for the right image.
            if receipt.journal.bytes.as_slice() != expected_journal.as_slice() {
                return Err(format!(
                    "RISC Zero journal {} != expected statement journal {}",
                    hex(&receipt.journal.bytes),
                    hex(expected_journal)
                ));
            }
            Ok(())
        }
        fn proof_identity(
            &self,
            guest: &GuestArtifact,
            proof: &ProofOutput,
            expected_journal: &[u8; 32],
        ) -> Result<ProofIdentity, String> {
            // Decode+check: the receipt must verify against the INDEPENDENTLY-embedded image
            // id AND commit to the expected statement journal; only then attest the identity.
            self.verify(guest, proof, expected_journal)?;
            Ok(ProofIdentity {
                committed_program_id: guest.program_id.clone(),
            })
        }
        fn expected_verifier_entries(&self) -> Result<Vec<(String, String)>, String> {
            // The verifier constants RISC Zero's Groth16 receipt verification ACTUALLY uses,
            // derived from `Groth16ReceiptVerifierParameters` EXACTLY as the
            // risc0-verifier-material harness does (blake3 of each 32-byte digest). The core
            // binds the harness VMAT to these, so an unrelated VMAT is refused.
            use risc0_zkvm::sha::Digestible;
            let p = risc0_zkvm::Groth16ReceiptVerifierParameters::default();
            let vk = Digestible::digest(&p.verifying_key);
            let params = Digestible::digest(&p);
            Ok(vec![
                (
                    "Groth16Vk".into(),
                    hex(blake3::hash(vk.as_bytes()).as_bytes()),
                ),
                (
                    "ControlRoot".into(),
                    hex(blake3::hash(p.control_root.as_bytes()).as_bytes()),
                ),
                (
                    "ControlId".into(),
                    hex(blake3::hash(p.bn254_control_id.as_bytes()).as_bytes()),
                ),
                (
                    "VerifierParams".into(),
                    hex(blake3::hash(params.as_bytes()).as_bytes()),
                ),
            ])
        }
    }

    fn arg(args: &[String], flag: &str) -> Option<String> {
        args.iter()
            .position(|a| a == flag)
            .and_then(|i| args.get(i + 1).cloned())
    }
    fn req(args: &[String], flag: &str) -> Result<String, String> {
        arg(args, flag).ok_or_else(|| format!("missing required {flag}"))
    }

    /// Phase-1 identity extraction: derive the RISC Zero guest identity (embedded image id)
    /// ONLY — no proof, no measurement. x86_64-only; refuses without the real embedded guest.
    fn emit_identity(args: &[String]) -> Result<(), String> {
        let arch = Arch::parse(&req(args, "--arch")?)?;
        if arch != Arch::X86_64 {
            return Err("RISC Zero identity is x86_64-only; an aarch64 record is refused".into());
        }
        let spec_hash = req(args, "--spec-hash")?;
        if spec_hash != MERGED_SPEC {
            return Err(format!(
                "spec hash {spec_hash} != merged finalized {MERGED_SPEC}"
            ));
        }
        let backend = Risc0Backend {
            guest_source_tree_hash: req(args, "--guest-source-tree-hash")?,
            candidate_dep_lock_hash: req(args, "--candidate-dep-lock-hash")?,
            build_command_hash: req(args, "--build-command-hash")?,
            builder_container_digest: req(args, "--builder-digest")?,
            firewall_attest: PathBuf::from("/dev/null"),
        };
        let guest = backend.build_guest(&BuildCtx {
            arch,
            work_dir: PathBuf::from("."),
        })?;
        let vmat = std::fs::read_to_string(req(args, "--verifier-material")?)
            .map_err(|e| format!("read verifier-material json: {e}"))?;
        let vm_manifest = serde_json::from_str::<serde_json::Value>(&vmat)
            .map_err(|e| format!("parse verifier-material json: {e}"))?
            .get("manifest_identity_blake3")
            .and_then(|x| x.as_str())
            .ok_or("verifier-material json missing manifest_identity_blake3")?
            .to_string();
        let builder = guest
            .builders
            .first()
            .map(|(_, d)| d.clone())
            .unwrap_or_default();
        let rec = GuestIdentityRecord {
            candidate: "Risc0".into(),
            arch: arch.as_str().into(),
            source_commit: req(args, "--source-commit")?,
            clean_tree: req(args, "--clean-tree")? == "true",
            guest_source_tree_hash: guest.guest_source_tree_hash,
            candidate_dep_lock_hash: guest.candidate_dep_lock_hash,
            guest_image_hash: guest.guest_image_hash,
            program_id: guest.program_id,
            builder_container_digest: builder,
            toolchain_identity: req(args, "--toolchain-identity")?,
            verifier_material_manifest_hash: vm_manifest,
            build_command_hash: guest.build_command_hash,
            production_binary_blake3: production_binary_blake3()?,
            real_backend: true,
            real_guest_embedded: cfg!(real_guest_embedded),
            b0_pre_spec_hash: spec_hash,
            // Two-root: the MEASUREMENT-TOOLING authority the derivation ran under (supplied by the
            // orchestrator from the SEPARATE tooling root, never inferred from the measured source).
            tooling_commit: req(args, "--tooling-commit")?,
            tooling_pathset_blake3: req(args, "--tooling-pathset-blake3")?,
            // RISC0 embeds its own locked NATIVE guest (not the shared SP1 artifact): never set.
            canonical_sp1_guest_artifact_address: String::new(),
        };
        println!(
            "{}",
            serde_json::to_string_pretty(&rec).map_err(|e| e.to_string())?
        );
        Ok(())
    }

    pub fn cli_main() -> Result<(), String> {
        // Explicit stub/real gate (attestable marker): the authoritative binary MUST carry
        // the real embedded guest. A CI/stub build (no B0_VENUE_EMBED) refuses here.
        if !cfg!(real_guest_embedded) {
            return Err(
                "REAL_GUEST_EMBEDDED marker absent: built without the pinned guest toolchain \
                 (venue B0_VENUE_EMBED=1); refusing to produce measurement evidence from a stub"
                    .into(),
            );
        }
        let args: Vec<String> = std::env::args().collect();
        if args.iter().any(|a| a == "--emit-identity") {
            return emit_identity(&args);
        }
        let arch = Arch::parse(&req(&args, "--arch")?)?;
        if arch != Arch::X86_64 {
            return Err("RISC Zero measurement is x86_64-only; refused".into());
        }
        let spec_hash = req(&args, "--spec-hash")?;
        if spec_hash != MERGED_SPEC {
            return Err(format!(
                "spec hash {spec_hash} != merged finalized {MERGED_SPEC}"
            ));
        }
        let input_tlg = std::fs::read(req(&args, "--input-tlg")?)
            .map_err(|e| format!("read Tlg input: {e}"))?;
        let input_st = std::fs::read(req(&args, "--input-st")?)
            .map_err(|e| format!("read SelectToken input: {e}"))?;
        let provenance: Vec<ProvFacts> = serde_json::from_str(
            &std::fs::read_to_string(req(&args, "--provenance")?)
                .map_err(|e| format!("read provenance: {e}"))?,
        )
        .map_err(|e| format!("parse provenance: {e}"))?;

        let backend = Risc0Backend {
            guest_source_tree_hash: req(&args, "--guest-source-tree-hash")?,
            candidate_dep_lock_hash: req(&args, "--candidate-dep-lock-hash")?,
            build_command_hash: req(&args, "--build-command-hash")?,
            builder_container_digest: req(&args, "--builder-digest")?,
            firewall_attest: PathBuf::from(req(&args, "--firewall-attest")?),
        };

        // Runner continuity: carry forward exactly THIS fragment's own authentic Phase-1 identity
        // record, uniquely SELECTED (candidate=Risc0 + x86_64) from the already-authenticated full
        // identity-record set the orchestrator re-derived the guest set from — never a fabricated
        // empty vec, never another candidate/arch's record. Missing/duplicate/malformed refuses;
        // Risc0/aarch64 is refused (unreachable here — arch is x86_64 by the guard above).
        let identity_records = vec![select_fragment_identity_record(
            &std::fs::read_to_string(req(&args, "--identity-records")?)
                .map_err(|e| format!("read identity records: {e}"))?,
            Candidate::Risc0,
            arch,
        )?];

        let cfg = RunConfig {
            arch,
            spec_hash: spec_hash.clone(),
            guest_set_hash: req(&args, "--guest-set-hash")?,
            container_image_digest: req(&args, "--container-image-digest")?,
            statement_hash_tlg: req(&args, "--statement-hash-tlg")?,
            statement_hash_st: req(&args, "--statement-hash-st")?,
            statements: vec![
                StatementInput {
                    label: "Tlg",
                    input: input_tlg,
                },
                StatementInput {
                    label: "SelectToken",
                    input: input_st,
                },
            ],
            verifier_material: parse_harness_verifier_material(
                &std::fs::read_to_string(req(&args, "--verifier-material")?)
                    .map_err(|e| format!("read verifier-material json: {e}"))?,
            )?,
            provenance,
            identity_records,
            work_dir: PathBuf::from(arg(&args, "--work-dir").unwrap_or_else(|| ".".into())),
        };

        let (facts, attestation) = run_arch_fragment(&backend, &cfg)?;
        if !attestation.real_backend {
            return Err("refusing to emit: attestation marks a non-real backend".into());
        }
        std::fs::write(
            req(&args, "--out")?,
            serde_json::to_string_pretty(&facts).map_err(|e| e.to_string())?,
        )
        .map_err(|e| format!("write fragment: {e}"))?;
        std::fs::write(
            req(&args, "--attest-out")?,
            serde_json::to_string_pretty(&attestation).map_err(|e| e.to_string())?,
        )
        .map_err(|e| format!("write attestation: {e}"))?;
        Ok(())
    }
}
