//! Fail-closed measurement orchestration for ONE (candidate, arch) fragment: build the
//! guest once, then for each official statement (Tlg, SelectToken) run 10 proving
//! iterations, each with 100 verification samples. Every proof is independently bound to
//! the built guest identity + verifier material; every verification failure REFUSES;
//! proving RSS comes from the container cgroup and verification RSS from the backend's
//! declared source. No step has a fallback — a missing measurement aborts the fragment.

use std::path::PathBuf;
use std::time::Instant;

use crate::backend::{BuildCtx, ProvingBackend};
use crate::binding::{bind_and_check, check_verifier_material_matches, VerifierMaterial};
use crate::facts::{
    BuilderFacts, CandidateFacts, CellFactsJson, DvfsFacts, GuestFacts, ProvFacts, VmEntryFacts,
};
use crate::{hex, native_eligible, Arch, RunnerAttestation};

pub const ITERATIONS: u32 = 10;
pub const VERIFY_SAMPLES: usize = 100;

/// One official statement + its materialized guest input. `label` is the validator's
/// statement token (`Tlg` | `SelectToken`).
pub struct StatementInput {
    pub label: &'static str,
    pub input: Vec<u8>,
}

pub struct RunConfig {
    pub arch: Arch,
    pub spec_hash: String,
    pub guest_set_hash: String,
    pub container_image_digest: String,
    pub statement_hash_tlg: String,
    pub statement_hash_st: String,
    pub rss_context_hash: String,
    pub malformed_corpus_result_hash: String,
    pub statements: Vec<StatementInput>,
    pub verifier_material: VerifierMaterial,
    pub provenance: Vec<ProvFacts>,
    pub work_dir: PathBuf,
}

fn vm_entry_facts(vm: &VerifierMaterial) -> Vec<VmEntryFacts> {
    vm.entries
        .iter()
        .map(|e| VmEntryFacts {
            role: e.role.clone(),
            byte_len: e.byte_len,
            hash: e.hash.clone(),
        })
        .collect()
}

/// Produce one (candidate, arch) fragment. Fail-closed throughout; the caller writes the
/// returned `CandidateFacts` as `facts-<candidate>-<arch>.json` and the attestation as a
/// sidecar. The coordinator later merges per-arch fragments before `measure-produce`.
pub fn run_arch_fragment(
    backend: &dyn ProvingBackend,
    cfg: &RunConfig,
) -> Result<(CandidateFacts, RunnerAttestation), String> {
    let candidate = backend.candidate();

    // Native-eligibility guard FIRST: a RISC-Zero-aarch64 fragment is refused, never built.
    if !native_eligible(candidate, cfg.arch) {
        return Err(format!(
            "{} is native-ineligible on {}; refusing to build or prove",
            candidate.as_str(),
            cfg.arch.as_str()
        ));
    }
    if cfg.statements.len() != 2 {
        return Err(format!(
            "exactly 2 statements (Tlg, SelectToken) required, got {}",
            cfg.statements.len()
        ));
    }
    if cfg.provenance.is_empty() {
        return Err("no provenance records supplied for the fragment".into());
    }
    for p in &cfg.provenance {
        if matches!(
            &p.dvfs,
            DvfsFacts::Observable {
                turbo_enabled: true,
                ..
            }
        ) {
            return Err(format!("turbo ENABLED on {} host; refused", p.arch));
        }
    }

    // Build the frozen guest ONCE; its identity is read from the built artifact/SDK.
    let guest = backend.build_guest(&BuildCtx {
        arch: cfg.arch,
        work_dir: cfg.work_dir.clone(),
    })?;

    // Bind the harness verifier material to the verifier constants the backend ACTUALLY
    // uses (once) — an unrelated but well-formed VMAT is refused here.
    check_verifier_material_matches(
        &cfg.verifier_material,
        &backend.expected_verifier_entries()?,
    )?;

    let mut cells: Vec<CellFactsJson> = Vec::with_capacity(20);
    for stmt in &cfg.statements {
        // Statement binding: recompute the official guest journal from THIS materialized
        // input (host-side) and require it to equal the declared statement hash for this
        // statement. Every proof is then bound to this journal — a proof for a different
        // input, or a wrong declared statement hash, is refused before any cell is emitted.
        let expected_journal = crate::expected_journal(&stmt.input)?;
        let declared = match stmt.label {
            "Tlg" => &cfg.statement_hash_tlg,
            "SelectToken" => &cfg.statement_hash_st,
            other => return Err(format!("unknown statement label {other}")),
        };
        if &hex(&expected_journal) != declared {
            return Err(format!(
                "{}: recomputed statement journal {} != declared statement hash {}",
                stmt.label,
                hex(&expected_journal),
                declared
            ));
        }

        for iteration in 0..ITERATIONS {
            // Prove (timed; proving RSS from the container cgroup, captured by the backend).
            let proof = backend.prove(&guest, &stmt.input)?;

            // Independent identity binding: the proof must commit to the BUILT guest id AND
            // to the expected statement journal; verifier material is bound as a distinct
            // artifact (never the guest-id source).
            let proof_id = backend.proof_identity(&guest, &proof, &expected_journal)?;
            bind_and_check(
                &guest,
                &proof_id,
                &cfg.verifier_material,
                &cfg.spec_hash,
                &cfg.guest_set_hash,
            )?;

            // 100 verification samples; ANY failure (crypto OR statement mismatch) refuses.
            let mut verify_ns = Vec::with_capacity(VERIFY_SAMPLES);
            for s in 0..VERIFY_SAMPLES {
                let t = Instant::now();
                backend
                    .verify(&guest, &proof, &expected_journal)
                    .map_err(|e| format!("verification sample {s} failed: {e}"))?;
                verify_ns.push(t.elapsed().as_nanos() as u64);
            }
            let verify_batch_rss_bytes = backend.capture_verify_rss()?;

            // Proof hash binds both the proof bytes and its public inputs.
            let mut ph = blake3::Hasher::new();
            ph.update(&proof.bytes);
            ph.update(&proof.public_inputs);
            let proof_hash = hex(ph.finalize().as_bytes());
            cells.push(CellFactsJson {
                arch: cfg.arch.as_str().to_string(),
                statement: stmt.label.to_string(),
                iteration,
                proof_hash: proof_hash.clone(),
                artifact_hashes: vec![["proof".to_string(), proof_hash]],
                prove_ns: proof.prove_ns,
                setup_ns: proof.setup_ns,
                proof_bytes: proof.bytes.len() as u64,
                verify_ns,
                proving_run_rss_bytes: proof.proving_run_rss_bytes,
                verify_batch_rss_bytes,
            });
        }
    }

    let facts = CandidateFacts {
        candidate: candidate.as_str().to_string(),
        container_image_digest: cfg.container_image_digest.clone(),
        statement_hash_tlg: cfg.statement_hash_tlg.clone(),
        statement_hash_st: cfg.statement_hash_st.clone(),
        rss_context_hash: cfg.rss_context_hash.clone(),
        malformed_corpus_result_hash: cfg.malformed_corpus_result_hash.clone(),
        guest: GuestFacts {
            guest_source_tree_hash: guest.guest_source_tree_hash.clone(),
            candidate_dep_lock_hash: guest.candidate_dep_lock_hash.clone(),
            guest_image_hash: guest.guest_image_hash.clone(),
            program_id: guest.program_id.clone(),
            build_command_hash: guest.build_command_hash.clone(),
            reproducible: guest.reproducible,
            builder: guest
                .builders
                .iter()
                .map(|(a, d)| BuilderFacts {
                    arch: a.as_str().to_string(),
                    builder_container_digest: d.clone(),
                })
                .collect(),
        },
        verifier_material: vm_entry_facts(&cfg.verifier_material),
        provenance: cfg.provenance.clone(),
        cells,
    };

    let attestation = RunnerAttestation {
        kind: "b0-final-runner-attestation/v1".to_string(),
        candidate: candidate.as_str().to_string(),
        arch: cfg.arch.as_str().to_string(),
        production_binary_blake3: crate::production_binary_blake3()?,
        backend_identity: backend.backend_identity(),
        real_backend: !backend.is_mock(),
        b0_pre_spec_hash: cfg.spec_hash.clone(),
        r0_guest_set_hash: cfg.guest_set_hash.clone(),
    };
    Ok((facts, attestation))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::{GuestArtifact, ProofIdentity, ProofOutput};
    use crate::binding::{VerifierMaterial, VmEntry};
    use crate::rss;
    use crate::Candidate;
    use std::path::PathBuf;

    // The merged, finalized b0_pre_spec_hash the validator binds measurement mode to.
    const MERGED_SPEC: &str = "201cfcb80e94a5a7845dc3380cde32171d40f325ae2bacde9547f3c0da3c4df3";
    // Frozen materialized computation-statement hashes (== the guest journals).
    const TLG_CSH: &str = "36fd69cb75ea6e7c91ce37932aca0158c3d9c8cb9a364bc66c55d27a43372d30";
    const SELECT_CSH: &str = "264e8a9339fa7e768e16fbecb38351564a7710472ce66ea2478a9fc6f214192b";

    fn h(x: &str) -> String {
        x.repeat(32)
    }

    /// The two REAL materialized statement inputs, generated ONCE via the guest-core emit
    /// example (measurement mode). Their guest journals equal the frozen CSH above, so the
    /// statement-binding path runs end-to-end with real inputs — only the crypto is mocked.
    fn materialized_inputs() -> &'static (Vec<u8>, Vec<u8>) {
        use std::sync::OnceLock;
        static INPUTS: OnceLock<(Vec<u8>, Vec<u8>)> = OnceLock::new();
        INPUTS.get_or_init(|| {
            let dir = std::env::temp_dir().join(format!("b0in-{}", std::process::id()));
            std::fs::create_dir_all(&dir).unwrap();
            let manifest = concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../b0-pre-candidates/guest-core/Cargo.toml"
            );
            let official = concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../docs/b0-pre/fixtures/workload/official.json"
            );
            let out = std::process::Command::new(env!("CARGO"))
                .args([
                    "run",
                    "--quiet",
                    "--manifest-path",
                    manifest,
                    "--example",
                    "emit_official_guest_input",
                    "--",
                    "--measurement",
                    MERGED_SPEC,
                    official,
                ])
                .arg(&dir)
                .output()
                .expect("run emit example");
            assert!(
                out.status.success(),
                "emit example failed: {}",
                String::from_utf8_lossy(&out.stderr)
            );
            let tlg = std::fs::read(dir.join("tlg.guestin.bin")).unwrap();
            let sel = std::fs::read(dir.join("select.guestin.bin")).unwrap();
            let _ = std::fs::remove_dir_all(&dir);
            (tlg, sel)
        })
    }

    /// Validate an emitted RawFacts JSON against the REAL validator by running its
    /// `measure-produce --validate` binary (its own lock resolves under this rustc).
    /// Returns the validator's stderr on refusal.
    fn validate_with_real_validator(raw_json: &str) -> Result<(), String> {
        let dir = std::env::temp_dir().join(format!("b0ctr-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("merged-raw-facts.json");
        std::fs::write(&file, raw_json).unwrap();
        let manifest = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../b0-pre-validator/Cargo.toml"
        );
        let out = std::process::Command::new(env!("CARGO"))
            .args([
                "run",
                "--quiet",
                "--manifest-path",
                manifest,
                "--bin",
                "measure-produce",
                "--",
                "--validate",
            ])
            .arg(&file)
            .output()
            .map_err(|e| format!("spawn measure-produce: {e}"))?;
        let _ = std::fs::remove_dir_all(&dir);
        if out.status.success() {
            Ok(())
        } else {
            Err(String::from_utf8_lossy(&out.stderr).trim().to_string())
        }
    }

    // A crafted proving-container cgroup with a real memory.peak file, so the REAL
    // cgroup RSS parser is exercised by the mock (only the crypto is stubbed).
    struct Cg(PathBuf);
    impl Drop for Cg {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    fn cgroup_with_peak(name: &str, peak: u64) -> Cg {
        let p = std::env::temp_dir().join(format!("b0cg-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        std::fs::write(p.join("memory.peak"), format!("{peak}\n")).unwrap();
        Cg(p)
    }

    /// TEST-ONLY mock backend: deterministic non-crypto stand-in for the SDK boundary.
    /// `is_mock()` is true, so an authoritative run refuses it and evidence records
    /// `real_backend = false`. Everything AROUND the crypto (build identity, binding,
    /// cgroup RSS read, timing plumbing, emission) runs for real.
    struct Mock {
        candidate: Candidate,
        program_id: String,
        cgroup: PathBuf,
        fail_verify: bool,
        wrong_proof_id: bool,
        // Models a proof that commits to the WRONG statement journal (proof of a different
        // input): verify against the expected journal must then refuse.
        commits_wrong_journal: bool,
    }
    impl ProvingBackend for Mock {
        fn candidate(&self) -> Candidate {
            self.candidate
        }
        fn backend_identity(&self) -> String {
            "MOCK-TEST-ONLY".into()
        }
        fn is_mock(&self) -> bool {
            true
        }
        fn build_guest(&self, ctx: &BuildCtx) -> Result<GuestArtifact, String> {
            Ok(GuestArtifact {
                guest_image_hash: h("a1"),
                program_id: self.program_id.clone(),
                guest_source_tree_hash: h("a2"),
                candidate_dep_lock_hash: h("a3"),
                build_command_hash: h("a4"),
                reproducible: true,
                builders: vec![(ctx.arch, h("a5"))],
            })
        }
        fn prove(&self, _g: &GuestArtifact, input: &[u8]) -> Result<ProofOutput, String> {
            // Proving RSS from the container cgroup peak — the REAL parser, fail-closed.
            let rss_bytes = rss::container_peak_rss_bytes(&self.cgroup)?;
            let mut bytes = b"MOCK-PROOF:".to_vec();
            bytes.extend_from_slice(blake3::hash(input).as_bytes());
            Ok(ProofOutput {
                bytes,
                public_inputs: Vec::new(),
                setup_ns: 11,
                prove_ns: 22,
                proving_run_rss_bytes: rss_bytes,
                proving_cgroup_identity: rss::cgroup_identity(&self.cgroup),
            })
        }
        fn verify(
            &self,
            _g: &GuestArtifact,
            _p: &ProofOutput,
            expected_journal: &[u8; 32],
        ) -> Result<(), String> {
            if self.fail_verify {
                return Err("mock verification rejected".into());
            }
            // The mock's "proof" commits to the expected journal unless configured otherwise.
            let committed = if self.commits_wrong_journal {
                [0xFFu8; 32]
            } else {
                *expected_journal
            };
            if &committed != expected_journal {
                return Err(
                    "statement journal mismatch: proof commits to a different input".into(),
                );
            }
            Ok(())
        }
        fn proof_identity(
            &self,
            g: &GuestArtifact,
            p: &ProofOutput,
            expected_journal: &[u8; 32],
        ) -> Result<ProofIdentity, String> {
            self.verify(g, p, expected_journal)?;
            Ok(ProofIdentity {
                committed_program_id: if self.wrong_proof_id {
                    h("99")
                } else {
                    g.program_id.clone()
                },
            })
        }
        fn expected_verifier_entries(&self) -> Result<Vec<(String, String)>, String> {
            // Matches vm() below — the "verifier constant" the mock's verifier uses.
            Ok(vec![("Groth16Vk".into(), h("bb"))])
        }
    }

    fn vm() -> VerifierMaterial {
        VerifierMaterial {
            entries: vec![VmEntry {
                role: "Groth16Vk".into(),
                byte_len: 292,
                hash: h("bb"),
            }],
            manifest_identity_blake3: h("cc"),
        }
    }

    fn provs(arch: &str) -> Vec<ProvFacts> {
        ["Proving", "Verification"]
            .iter()
            .map(|role| ProvFacts {
                arch: arch.into(),
                role: (*role).into(),
                source_commit: "0".repeat(40),
                dirty_tree_flag: false,
                builder_container_digest: h("a5"),
                host_os: "Linux".into(),
                kernel: "6.1.0".into(),
                cpu_vendor: "GenuineIntel".into(),
                cpu_model: "Xeon".into(),
                physical_core_count: 8,
                logical_cpu_count: 8,
                total_ram_bytes: 34359738368,
                configured_cpuset_core_limit: 8,
                configured_memory_limit_bytes: 34359738368,
                dvfs: DvfsFacts::Observable {
                    turbo_enabled: false,
                    governor: "performance".into(),
                },
                clock_source: "tsc".into(),
                cgroup_version: 2,
                cgroup_scope_label: "/b0-final.slice/measure".into(),
                benchmark_harness_source_hash: h("d1"),
                raw_environment_capture_hash: h("d2"),
            })
            .collect()
    }

    fn cfg(arch: Arch, prov_arch_str: &str) -> RunConfig {
        let (tlg, sel) = materialized_inputs();
        RunConfig {
            arch,
            spec_hash: MERGED_SPEC.to_string(),
            guest_set_hash: h("ee"),
            container_image_digest: h("f0"),
            statement_hash_tlg: TLG_CSH.to_string(),
            statement_hash_st: SELECT_CSH.to_string(),
            rss_context_hash: h("f3"),
            malformed_corpus_result_hash: h("f4"),
            statements: vec![
                StatementInput {
                    label: "Tlg",
                    input: tlg.clone(),
                },
                StatementInput {
                    label: "SelectToken",
                    input: sel.clone(),
                },
            ],
            verifier_material: vm(),
            provenance: provs(prov_arch_str),
            work_dir: std::env::temp_dir().join(format!("b0wd-{}", std::process::id())),
        }
    }

    fn mock(candidate: Candidate, cgroup: &Cg) -> Mock {
        Mock {
            candidate,
            program_id: h("11"),
            cgroup: cgroup.0.clone(),
            fail_verify: false,
            wrong_proof_id: false,
            commits_wrong_journal: false,
        }
    }

    fn merge_sp1(x86: CandidateFacts, arm: CandidateFacts) -> CandidateFacts {
        let mut m = x86;
        m.cells.extend(arm.cells);
        m.provenance.extend(arm.provenance);
        m.guest.builder.extend(arm.guest.builder);
        m
    }

    #[test]
    fn e2e_mock_fragment_grid_validates_against_the_real_validator() {
        let cg = cgroup_with_peak("e2e", 4_831_838_208);
        // SP1: both arches -> 40 cells after merge.
        let (sp1_x86, att) =
            run_arch_fragment(&mock(Candidate::Sp1, &cg), &cfg(Arch::X86_64, "x86_64"))
                .expect("sp1 x86 fragment");
        let (sp1_arm, _) =
            run_arch_fragment(&mock(Candidate::Sp1, &cg), &cfg(Arch::Aarch64, "aarch64"))
                .expect("sp1 arm fragment");
        // RISC0: x86 only -> 20 cells.
        let (risc0, _) =
            run_arch_fragment(&mock(Candidate::Risc0, &cg), &cfg(Arch::X86_64, "x86_64"))
                .expect("risc0 x86 fragment");

        // Evidence binds the mock: real_backend=false, binary hash present.
        assert!(!att.real_backend);
        assert_eq!(att.production_binary_blake3.len(), 64);
        assert_eq!(att.backend_identity, "MOCK-TEST-ONLY");
        // Proving RSS came from the container cgroup peak, not getrusage.
        assert_eq!(sp1_x86.cells[0].proving_run_rss_bytes, 4_831_838_208);

        let sp1 = merge_sp1(sp1_x86, sp1_arm);
        assert_eq!(sp1.cells.len(), 40);
        assert_eq!(risc0.cells.len(), 20);

        let raw = crate::facts::RawFacts {
            lifecycle_mode: "measurement".into(),
            b0_pre_spec_hash: MERGED_SPEC.to_string(),
            candidates: vec![sp1, risc0],
        };
        let json = serde_json::to_string(&raw).unwrap();
        // The emitted grid must validate against the REAL validator (contract-drift guard).
        validate_with_real_validator(&json)
            .expect("emitted grid validates against the frozen validator contract");
    }

    #[test]
    fn risc0_aarch64_is_refused_never_built() {
        let cg = cgroup_with_peak("r0arm", 1);
        let e = run_arch_fragment(&mock(Candidate::Risc0, &cg), &cfg(Arch::Aarch64, "aarch64"))
            .unwrap_err();
        assert!(e.contains("native-ineligible"), "{e}");
    }

    #[test]
    fn a_single_verification_failure_refuses_the_fragment() {
        let cg = cgroup_with_peak("vf", 1);
        let mut m = mock(Candidate::Sp1, &cg);
        m.fail_verify = true;
        let e = run_arch_fragment(&m, &cfg(Arch::X86_64, "x86_64")).unwrap_err();
        assert!(e.contains("verification"), "{e}");
    }

    #[test]
    fn proof_committing_to_a_different_guest_refuses() {
        let cg = cgroup_with_peak("wp", 1);
        let mut m = mock(Candidate::Sp1, &cg);
        m.wrong_proof_id = true;
        let e = run_arch_fragment(&m, &cfg(Arch::X86_64, "x86_64")).unwrap_err();
        assert!(e.contains("proof commits to"), "{e}");
    }

    #[test]
    fn unavailable_proving_cgroup_peak_refuses() {
        // cgroup dir with NO peak file -> the proving RSS read fails closed.
        let empty = std::env::temp_dir().join(format!("b0cg-empty-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&empty);
        std::fs::create_dir_all(&empty).unwrap();
        let m = Mock {
            candidate: Candidate::Sp1,
            program_id: h("11"),
            cgroup: empty.clone(),
            fail_verify: false,
            wrong_proof_id: false,
            commits_wrong_journal: false,
        };
        let e = run_arch_fragment(&m, &cfg(Arch::X86_64, "x86_64")).unwrap_err();
        assert!(e.contains("cgroup peak unavailable"), "{e}");
        let _ = std::fs::remove_dir_all(&empty);
    }

    #[test]
    fn expected_journal_matches_frozen_statement_hashes() {
        // The host-side guest computation reproduces the frozen materialized journals.
        let (tlg, sel) = materialized_inputs();
        assert_eq!(hex(&crate::expected_journal(tlg).unwrap()), TLG_CSH);
        assert_eq!(hex(&crate::expected_journal(sel).unwrap()), SELECT_CSH);
        // A malformed input is refused (no journal).
        assert!(crate::expected_journal(b"not-a-guest-input").is_err());
    }

    #[test]
    fn proof_committing_to_a_different_statement_is_refused() {
        let cg = cgroup_with_peak("wj", 1);
        let mut m = mock(Candidate::Sp1, &cg);
        m.commits_wrong_journal = true;
        let e = run_arch_fragment(&m, &cfg(Arch::X86_64, "x86_64")).unwrap_err();
        assert!(e.contains("statement journal mismatch"), "{e}");
    }

    #[test]
    fn wrong_declared_statement_hash_is_refused() {
        let cg = cgroup_with_peak("wsh", 1);
        let mut c = cfg(Arch::X86_64, "x86_64");
        c.statement_hash_tlg = h("de"); // != recomputed journal from the Tlg input
        let e = run_arch_fragment(&mock(Candidate::Sp1, &cg), &c).unwrap_err();
        assert!(
            e.contains("recomputed statement journal") && e.contains("declared statement hash"),
            "{e}"
        );
    }

    #[test]
    fn unrelated_verifier_material_is_refused() {
        // A well-formed VMAT whose entry hash is NOT the verifier constant the backend uses.
        let cg = cgroup_with_peak("uvm", 1);
        let mut c = cfg(Arch::X86_64, "x86_64");
        c.verifier_material.entries[0].hash = h("99"); // != the mock's expected h("bb")
        let e = run_arch_fragment(&mock(Candidate::Sp1, &cg), &c).unwrap_err();
        assert!(e.contains("verifier constant actually used"), "{e}");
    }
}
