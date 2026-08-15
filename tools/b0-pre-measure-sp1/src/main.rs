//! `b0-pre-measure-sp1` — the venue SP1 measurement runner.
//!
//! PRODUCTION-ONLY: this binary refuses to build without `--features real-backend`, so
//! there is no mock/fallback proving path in an authoritative binary (gating condition
//! #1). All measurement/binding/emission/RSS logic is the unit-tested
//! `b0-pre-measure-core`; this crate only supplies the real SP1 6.3.1 backend — the sole
//! venue-only cryptographic boundary — grounded in the venue-proven `prove_fixture.sh`
//! SDK calls, de-stamped for official measurement.

#[cfg(not(feature = "real-backend"))]
compile_error!(
    "b0-pre-measure-sp1 is a production measurement binary: build it with \
     --features real-backend (the pinned SP1 6.3.1 SDK). It has no mock or fallback \
     proving path — the test-only mock lives in b0-pre-measure-core's cfg(test)."
);

#[cfg(feature = "real-backend")]
fn main() -> std::process::ExitCode {
    match real::cli_main() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("INELIGIBLE: SP1 measurement runner failed closed: {e}");
            std::process::ExitCode::FAILURE
        }
    }
}

#[cfg(feature = "real-backend")]
mod real {
    use std::cell::RefCell;
    use std::path::PathBuf;
    use std::sync::Arc;
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

    use sp1_sdk::blocking::{Elf, ProveRequest, Prover, ProverClient, SP1Stdin};
    use sp1_sdk::{HashableKey, ProvingKey};

    const MERGED_SPEC: &str = "201cfcb80e94a5a7845dc3380cde32171d40f325ae2bacde9547f3c0da3c4df3";

    /// Real SP1 backend. Holds the built guest ELF + build provenance + the firewall
    /// attestation path from which the PROVING-CONTAINER cgroup peak is read.
    struct Sp1Backend {
        elf: Vec<u8>,
        guest_source_tree_hash: String,
        candidate_dep_lock_hash: String,
        build_command_hash: String,
        builder_container_digest: String,
        arch: Arch,
        firewall_attest: PathBuf,
        // gnark backend self-verify vkey material for the native verify (sp1-verifier).
        vkey_hash: RefCell<Option<String>>,
    }

    impl Sp1Backend {
        // NB: `ProverClient::from_env()` returns an `EnvProver` (the env-configured blocking
        // prover that owns setup/prove/verify) — its concrete type is left to inference at each
        // call site, exactly as the venue-proven prove_fixture.sh runner does.
        fn elf(&self) -> Elf {
            Elf::Dynamic(Arc::from(self.elf.clone().into_boxed_slice()))
        }
    }

    /// Read the newest firewall attestation record for the SP1 gnark PROVE (witness) call
    /// and return its container-cgroup peak RSS + cgroup identity. Fail-closed if the
    /// firewall did not record a container-measured peak — never getrusage, never a guess.
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
            let cand = v.get("candidate").and_then(|c| c.as_str()).unwrap_or("");
            if cand != "sp1-witness" {
                continue;
            }
            let peak = v
                .get("proving_container_peak_rss_bytes")
                .and_then(|p| p.as_u64())
                .ok_or("SP1 prove attestation missing proving_container_peak_rss_bytes")?;
            let cg = v
                .get("proving_cgroup_identity")
                .and_then(|c| c.as_str())
                .ok_or("SP1 prove attestation missing proving_cgroup_identity")?
                .to_string();
            found = Some((peak, cg));
        }
        found.ok_or_else(|| {
            "no SP1 gnark prove (witness) record in the firewall attestation; refusing to \
             report proving RSS not measured from the container cgroup"
                .to_string()
        })
    }

    impl ProvingBackend for Sp1Backend {
        fn candidate(&self) -> Candidate {
            Candidate::Sp1
        }
        fn backend_identity(&self) -> String {
            "sp1-sdk=6.3.1+sp1-verifier=6.3.1".into()
        }
        fn build_guest(&self, _ctx: &BuildCtx) -> Result<GuestArtifact, String> {
            if self.elf.is_empty() {
                return Err("empty guest ELF (frozen guest did not build in-container)".into());
            }
            // Guest identity is DERIVED from the actual built ELF via the SDK: the SP1
            // verifying-key hash. Never inferred from the verifier-material manifest.
            let prover = ProverClient::from_env();
            let pk = prover
                .setup(self.elf())
                .map_err(|e| format!("SP1 setup for identity failed: {e}"))?;
            let vkey_hash = pk.verifying_key().bytes32();
            let program_id = vkey_hash.trim_start_matches("0x").to_lowercase();
            *self.vkey_hash.borrow_mut() = Some(vkey_hash);
            Ok(GuestArtifact {
                guest_image_hash: hex(blake3::hash(&self.elf).as_bytes()),
                program_id,
                guest_source_tree_hash: self.guest_source_tree_hash.clone(),
                candidate_dep_lock_hash: self.candidate_dep_lock_hash.clone(),
                build_command_hash: self.build_command_hash.clone(),
                reproducible: true,
                builders: vec![(self.arch, self.builder_container_digest.clone())],
            })
        }
        fn prove(&self, _guest: &GuestArtifact, input: &[u8]) -> Result<ProofOutput, String> {
            let prover = ProverClient::from_env();
            // setup (timed) — part of the measured per-iteration cost.
            let t_setup = Instant::now();
            let pk = prover
                .setup(self.elf())
                .map_err(|e| format!("SP1 setup failed: {e}"))?;
            let setup_ns = t_setup.elapsed().as_nanos() as u64;

            let mut stdin = SP1Stdin::new();
            stdin.write(&input.to_vec());

            // Genuine Groth16 proving. The gnark backend `docker run` is intercepted by the
            // firewall (on PATH for this process); the firewall records the container's
            // cgroup peak, which we read below — getrusage would miss the container.
            let t_prove = Instant::now();
            let proof = prover
                .prove(&pk, stdin)
                .groth16()
                .run()
                .map_err(|e| format!("SP1 Groth16 proving failed: {e}"))?;
            let prove_ns = t_prove.elapsed().as_nanos() as u64;

            let (proving_run_rss_bytes, proving_cgroup_identity) =
                latest_proving_container_rss(&self.firewall_attest)?;

            Ok(ProofOutput {
                bytes: proof.bytes(),
                public_inputs: proof.public_values.as_slice().to_vec(),
                setup_ns,
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
            // NATIVE Groth16 verification via the pinned sp1-verifier crate (no proving
            // container) — so getrusage is the correct verify-RSS source (core default).
            let vkey_hash = self
                .vkey_hash
                .borrow()
                .clone()
                .ok_or("verify before build_guest set the vkey hash")?;
            // STATEMENT BINDING: SP1's committed public values ARE the 32-byte guest
            // journal (`computation_statement_hash`). Require them to equal the expected
            // journal recomputed from the materialized input, so a valid proof of a
            // DIFFERENT input is refused — then verify with those EXACT public inputs
            // (never an empty slice).
            if proof.public_inputs.as_slice() != expected_journal.as_slice() {
                return Err(format!(
                    "SP1 public values {} != expected statement journal {}",
                    hex(&proof.public_inputs),
                    hex(expected_journal)
                ));
            }
            sp1_verifier::Groth16Verifier::verify(
                &proof.bytes,
                &proof.public_inputs,
                &vkey_hash,
                sp1_verifier::GROTH16_VK_BYTES.as_ref(),
            )
            .map_err(|e| format!("SP1 native Groth16 verification failed: {e:?}"))
        }
        fn proof_identity(
            &self,
            guest: &GuestArtifact,
            proof: &ProofOutput,
            expected_journal: &[u8; 32],
        ) -> Result<ProofIdentity, String> {
            // Decode+check: the proof must verify under the INDEPENDENTLY-built vkey AND
            // commit to the expected statement journal. Only then attest the guest identity.
            self.verify(guest, proof, expected_journal)?;
            Ok(ProofIdentity {
                committed_program_id: guest.program_id.clone(),
            })
        }
        fn expected_verifier_entries(&self) -> Result<Vec<(String, String)>, String> {
            // The verifier constant SP1's native Groth16 verify ACTUALLY uses: the pinned
            // sp1-verifier GROTH16_VK_BYTES, hashed exactly as the sp1-verifier-material
            // harness does (blake3 of the raw bytes). The core binds the harness VMAT to this.
            let vk: &[u8] = sp1_verifier::GROTH16_VK_BYTES.as_ref();
            Ok(vec![("Groth16Vk".into(), hex(blake3::hash(vk).as_bytes()))])
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

    /// Phase-1 identity extraction: build the guest + derive its SDK identity ONLY (no
    /// proof, no measurement) and emit the typed identity record.
    fn emit_identity(args: &[String]) -> Result<(), String> {
        let arch = Arch::parse(&req(args, "--arch")?)?;
        let spec_hash = req(args, "--spec-hash")?;
        if spec_hash != MERGED_SPEC {
            return Err(format!(
                "spec hash {spec_hash} != merged finalized {MERGED_SPEC}"
            ));
        }
        let elf =
            std::fs::read(req(args, "--guest-elf")?).map_err(|e| format!("read guest ELF: {e}"))?;
        let backend = Sp1Backend {
            elf,
            guest_source_tree_hash: req(args, "--guest-source-tree-hash")?,
            candidate_dep_lock_hash: req(args, "--candidate-dep-lock-hash")?,
            build_command_hash: req(args, "--build-command-hash")?,
            builder_container_digest: req(args, "--builder-digest")?,
            arch,
            firewall_attest: PathBuf::from("/dev/null"),
            vkey_hash: RefCell::new(None),
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
            candidate: "Sp1".into(),
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
            real_guest_embedded: true, // SP1 has no stub guest path
            b0_pre_spec_hash: spec_hash,
            // Two-root: the MEASUREMENT-TOOLING authority the derivation ran under (supplied by the
            // orchestrator from the SEPARATE tooling root, never inferred from the measured source).
            tooling_commit: req(args, "--tooling-commit")?,
            tooling_pathset_blake3: req(args, "--tooling-pathset-blake3")?,
        };
        println!(
            "{}",
            serde_json::to_string_pretty(&rec).map_err(|e| e.to_string())?
        );
        Ok(())
    }

    pub fn cli_main() -> Result<(), String> {
        let args: Vec<String> = std::env::args().collect();
        if args.iter().any(|a| a == "--emit-identity") {
            return emit_identity(&args);
        }
        let arch = Arch::parse(&req(&args, "--arch")?)?;
        let spec_hash = req(&args, "--spec-hash")?;
        if spec_hash != MERGED_SPEC {
            return Err(format!(
                "spec hash {spec_hash} != merged finalized {MERGED_SPEC}"
            ));
        }
        let elf = std::fs::read(req(&args, "--guest-elf")?)
            .map_err(|e| format!("read guest ELF: {e}"))?;
        let input_tlg = std::fs::read(req(&args, "--input-tlg")?)
            .map_err(|e| format!("read Tlg input: {e}"))?;
        let input_st = std::fs::read(req(&args, "--input-st")?)
            .map_err(|e| format!("read SelectToken input: {e}"))?;
        let provenance: Vec<ProvFacts> = serde_json::from_str(
            &std::fs::read_to_string(req(&args, "--provenance")?)
                .map_err(|e| format!("read provenance: {e}"))?,
        )
        .map_err(|e| format!("parse provenance: {e}"))?;

        let backend = Sp1Backend {
            elf,
            guest_source_tree_hash: req(&args, "--guest-source-tree-hash")?,
            candidate_dep_lock_hash: req(&args, "--candidate-dep-lock-hash")?,
            build_command_hash: req(&args, "--build-command-hash")?,
            builder_container_digest: req(&args, "--builder-digest")?,
            arch,
            firewall_attest: PathBuf::from(req(&args, "--firewall-attest")?),
            vkey_hash: RefCell::new(None),
        };

        // Runner continuity: carry forward exactly THIS fragment's own authentic Phase-1 identity
        // record, uniquely SELECTED (candidate=Sp1 + this arch) from the already-authenticated full
        // identity-record set the orchestrator re-derived the guest set from — never a fabricated
        // empty vec, never another candidate/arch's record. Missing/duplicate/malformed refuses.
        let identity_records = vec![select_fragment_identity_record(
            &std::fs::read_to_string(req(&args, "--identity-records")?)
                .map_err(|e| format!("read identity records: {e}"))?,
            Candidate::Sp1,
            arch,
        )?];

        let cfg = RunConfig {
            arch,
            spec_hash: spec_hash.clone(),
            guest_set_hash: req(&args, "--guest-set-hash")?,
            container_image_digest: req(&args, "--container-image-digest")?,
            statement_hash_tlg: req(&args, "--statement-hash-tlg")?,
            statement_hash_st: req(&args, "--statement-hash-st")?,
            rss_context_hash: req(&args, "--rss-context-hash")?,
            malformed_corpus_result_hash: req(&args, "--malformed-corpus-result-hash")?,
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
            // Verifier material comes from the sp1-verifier-material HARNESS bin's JSON
            // (the tested b0_pre_vmat extractor), a SEPARATE artifact from the guest identity.
            verifier_material: parse_harness_verifier_material(
                &std::fs::read_to_string(req(&args, "--verifier-material")?)
                    .map_err(|e| format!("read verifier-material json: {e}"))?,
            )?,
            provenance,
            identity_records,
            work_dir: PathBuf::from(arg(&args, "--work-dir").unwrap_or_else(|| ".".into())),
        };

        let (facts, attestation) = run_arch_fragment(&backend, &cfg)?;
        // Defense in depth: an authoritative fragment must never come from a mock.
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
