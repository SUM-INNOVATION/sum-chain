//! `RunnerAttestationV1` — per-arch measurement-RUNNER + tooling authority binding (plan two-root).
//!
//! This is the record that keeps the two authorities separate and BOTH bound to a measurement run.
//! It is retained EVIDENCE: only its 32-byte domain-separated [`RunnerAttestationV1::hash`] lives in
//! the fixed [`crate::schema::provenance::ArchRunProvenanceV1`] canonical bytes; the full record
//! travels out of band and the validator + independent verifier recompute the hash and re-check it.
//!
//! It is bound into the per-arch measurement provenance ONLY — never into `GuestProgramAllowlistV1`
//! or the arch-neutral guest identity, which continue to bind the measured source alone.
//!
//! Authority separation, enforced here:
//!   * `measured_source_commit` / `build_git_sha` bind the FROZEN measured source (the venue verifies
//!     they equal `guest_set::RATIFIED_SOURCE_COMMIT`); this is the guest/program source.
//!   * `execution_tooling_checkout_head` / `ratified_tooling_commit` / `*_pathset_blake3` bind the
//!     reviewed MEASUREMENT TOOLING; the tooling commit is verified against the tooling authority and
//!     is NEVER compared to the measured-source commit.

use crate::codec::{DecodeError, Reader, Writer};
use crate::enums::{Arch, Candidate, ProvenanceRole};

/// Record-local schema version (independent of the global `SCHEMA_VERSION` and of the provenance
/// record's own version). v2 added the candidate/run/provenance binding; v3 added the Phase-1
/// runner-CONTINUITY field (`phase1_production_binary_blake3`); v4 added
/// `phase1_identity_record_blake3`, the domain-separated address of the RETAINED Phase-1 identity
/// record, so continuity is anchored to an independently-decoded record, not a copied hash claim.
pub const RUNNER_ATTESTATION_SCHEMA_VERSION: u16 = 4;

/// Domain separation for [`RunnerAttestationV1::hash`].
pub const RUNNER_ATTESTATION_PREFIX: &[u8] = b"b0-final-runner-attestation/v1\0";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RunnerAttestationV1 {
    // ---- binding: candidate / arch / run / provenance (the producer injects these; the venue JSON
    // twin carries only the arch + the venue-produced fields) ----
    pub candidate: Candidate,
    pub provenance_role: ProvenanceRole,
    pub b0_pre_spec_hash: [u8; 32],
    pub r0_guest_set_hash: [u8; 32],
    pub build_target_arch: Arch,
    /// The tooling checkout the runner ACTUALLY executed from (40-hex). Equals `ratified_tooling_commit`
    /// on an official run; recorded independently so a mismatch is visible.
    pub execution_tooling_checkout_head: String,
    /// The ratified measurement-tooling commit (40-hex). Verified against the tooling authority —
    /// NEVER against the measured-source commit.
    pub ratified_tooling_commit: String,
    /// The ratified tooling path-set digest (64-hex BLAKE3).
    pub ratified_pathset_blake3: String,
    /// The path-set digest recomputed over the tooling root at run time (64-hex BLAKE3). Must equal
    /// `ratified_pathset_blake3`.
    pub recomputed_pathset_blake3: String,
    /// The measured-source commit the guest was built from (40-hex) — the FROZEN measured source.
    pub measured_source_commit: String,
    /// `BUILD_GIT_SHA` the runner build was stamped with (40-hex); must equal `measured_source_commit`.
    /// Accurate finding: the upstream `sp1-prover-types` `build.rs` `Utc::now()` is NOT patched — it
    /// still runs, but its `BUILD_VERSION` output is consumed by zero `env!`, and the double-build
    /// reproducibility check proves it is artifact-inert (byte-identical builds). `BUILD_GIT_SHA` is a
    /// deterministic attested input fixed to the measured source; any binary difference stops the run.
    pub build_git_sha: String,
    /// Content address over the measured-source path-set / staged context (guest identity source).
    pub measured_source_context_blake3: [u8; 32],
    pub runner_sha256: [u8; 32],
    pub runner_blake3: [u8; 32],
    /// The immutable (pull-never, ratified) builder container identity.
    pub immutable_builder_identity: [u8; 32],
    /// The accepted protobuf include-authority content address (both hashes bound).
    pub protobuf_authority_sha256: [u8; 32],
    pub protobuf_authority_blake3: [u8; 32],
    /// The NATIVE protoc identity — a VENUE-PRODUCED fact (unknown off-venue); never hardcoded.
    pub native_protoc_sha256: [u8; 32],
    pub native_protoc_blake3: [u8; 32],
    /// The native protoc version string, which must read exactly `libprotoc 3.21.12` at the venue.
    pub native_protoc_version: String,
    /// Content address over the exact controlled `docker run` argv + mount spec used to provision.
    pub docker_argv_blake3: [u8; 32],
    /// Identity of the double-build reproducibility pair (content address over the two build
    /// attestations) — proves the runner was built twice, byte-identical.
    pub reproducibility_pair_blake3: [u8; 32],
    /// RUNNER CONTINUITY: the `production_binary_blake3` recorded by the Phase-1 `GuestIdentityRecord`
    /// for this candidate/arch — the compiled runner binary that emitted the guest identity. The
    /// producer resolves it from the mandatory Phase-1 identity-record input and requires it EQUAL
    /// `runner_blake3` (the measurement runner). Carried here so the validator + independent verifier
    /// re-enforce the equality on import; a substituted or non-reproducible runner binary is refused
    /// even when the tooling authority is identical.
    pub phase1_production_binary_blake3: [u8; 32],
    /// Domain-separated address of the RETAINED [`super::identity_record::Phase1IdentityRecordV1`] for
    /// this candidate/arch. The importer recomputes the retained record's address and requires it
    /// equals this, then requires the record's `production_binary_blake3` equals BOTH the field above
    /// and `runner_blake3` — anchoring continuity to an independently-decoded record.
    pub phase1_identity_record_blake3: [u8; 32],
}

fn write_hexstr(w: &mut Writer, s: &str) {
    w.u8(s.len() as u8);
    w.bytes(s.as_bytes());
}

/// Read a `u8`-length-prefixed string that MUST be exactly `n` lowercase-hex chars.
fn read_hexstr(r: &mut Reader, n: usize, ctx: &'static str) -> Result<String, DecodeError> {
    let len = r.read_u8(ctx)? as usize;
    if len != n {
        return Err(DecodeError::BadValue { ctx });
    }
    let b = r.read_bytes(len, ctx)?;
    if !b
        .iter()
        .all(|&c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
    {
        return Err(DecodeError::BadValue { ctx });
    }
    Ok(String::from_utf8(b.to_vec()).expect("ascii-hex"))
}

/// Read a `u8`-length-prefixed ASCII string, `max` bytes.
fn read_u8_ascii(r: &mut Reader, max: usize, ctx: &'static str) -> Result<String, DecodeError> {
    let len = r.read_u8(ctx)? as usize;
    if len > max {
        return Err(DecodeError::LengthExceedsMax {
            ctx,
            len: len as u64,
            max: max as u64,
        });
    }
    let b = r.read_bytes(len, ctx)?;
    if !b.iter().all(|c| c.is_ascii()) {
        return Err(DecodeError::BadValue { ctx });
    }
    Ok(String::from_utf8(b.to_vec()).expect("ascii"))
}

impl RunnerAttestationV1 {
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.u16(RUNNER_ATTESTATION_SCHEMA_VERSION);
        w.u16(self.candidate.to_repr());
        w.u8(self.provenance_role.to_repr());
        w.bytes(&self.b0_pre_spec_hash);
        w.bytes(&self.r0_guest_set_hash);
        w.u8(self.build_target_arch.to_repr());
        write_hexstr(&mut w, &self.execution_tooling_checkout_head);
        write_hexstr(&mut w, &self.ratified_tooling_commit);
        write_hexstr(&mut w, &self.ratified_pathset_blake3);
        write_hexstr(&mut w, &self.recomputed_pathset_blake3);
        write_hexstr(&mut w, &self.measured_source_commit);
        write_hexstr(&mut w, &self.build_git_sha);
        w.bytes(&self.measured_source_context_blake3);
        w.bytes(&self.runner_sha256);
        w.bytes(&self.runner_blake3);
        w.bytes(&self.immutable_builder_identity);
        w.bytes(&self.protobuf_authority_sha256);
        w.bytes(&self.protobuf_authority_blake3);
        w.bytes(&self.native_protoc_sha256);
        w.bytes(&self.native_protoc_blake3);
        w.u8(self.native_protoc_version.len() as u8);
        w.bytes(self.native_protoc_version.as_bytes());
        w.bytes(&self.docker_argv_blake3);
        w.bytes(&self.reproducibility_pair_blake3);
        w.bytes(&self.phase1_production_binary_blake3);
        w.bytes(&self.phase1_identity_record_blake3);
        w.into_bytes()
    }

    /// The domain-separated content address bound into `ArchRunProvenanceV1`.
    pub fn hash(&self) -> [u8; 32] {
        let mut h = blake3::Hasher::new();
        h.update(RUNNER_ATTESTATION_PREFIX);
        h.update(&self.encode());
        *h.finalize().as_bytes()
    }

    pub fn decode(r: &mut Reader) -> Result<Self, DecodeError> {
        let sv = r.read_u16("RunnerAttestationV1.schema_version")?;
        if sv != RUNNER_ATTESTATION_SCHEMA_VERSION {
            return Err(DecodeError::BadFixedScalar {
                ctx: "RunnerAttestationV1.schema_version",
                value: sv as u64,
            });
        }
        let candidate = Candidate::from_repr(r.read_u16("RunnerAttestationV1.candidate")?)?;
        let provenance_role =
            ProvenanceRole::from_repr(r.read_u8("RunnerAttestationV1.provenance_role")?)?;
        let b0_pre_spec_hash = r.read_array::<32>("RunnerAttestationV1.b0_pre_spec_hash")?;
        let r0_guest_set_hash = r.read_array::<32>("RunnerAttestationV1.r0_guest_set_hash")?;
        let build_target_arch = Arch::from_repr(r.read_u8("RunnerAttestationV1.arch")?)?;
        let execution_tooling_checkout_head =
            read_hexstr(r, 40, "RunnerAttestationV1.execution_tooling_checkout_head")?;
        let ratified_tooling_commit =
            read_hexstr(r, 40, "RunnerAttestationV1.ratified_tooling_commit")?;
        let ratified_pathset_blake3 =
            read_hexstr(r, 64, "RunnerAttestationV1.ratified_pathset_blake3")?;
        let recomputed_pathset_blake3 =
            read_hexstr(r, 64, "RunnerAttestationV1.recomputed_pathset_blake3")?;
        let measured_source_commit =
            read_hexstr(r, 40, "RunnerAttestationV1.measured_source_commit")?;
        let build_git_sha = read_hexstr(r, 40, "RunnerAttestationV1.build_git_sha")?;
        let measured_source_context_blake3 =
            r.read_array::<32>("RunnerAttestationV1.measured_source_context_blake3")?;
        let runner_sha256 = r.read_array::<32>("RunnerAttestationV1.runner_sha256")?;
        let runner_blake3 = r.read_array::<32>("RunnerAttestationV1.runner_blake3")?;
        let immutable_builder_identity =
            r.read_array::<32>("RunnerAttestationV1.immutable_builder_identity")?;
        let protobuf_authority_sha256 =
            r.read_array::<32>("RunnerAttestationV1.protobuf_authority_sha256")?;
        let protobuf_authority_blake3 =
            r.read_array::<32>("RunnerAttestationV1.protobuf_authority_blake3")?;
        let native_protoc_sha256 =
            r.read_array::<32>("RunnerAttestationV1.native_protoc_sha256")?;
        let native_protoc_blake3 =
            r.read_array::<32>("RunnerAttestationV1.native_protoc_blake3")?;
        let native_protoc_version =
            read_u8_ascii(r, 64, "RunnerAttestationV1.native_protoc_version")?;
        let docker_argv_blake3 = r.read_array::<32>("RunnerAttestationV1.docker_argv_blake3")?;
        let reproducibility_pair_blake3 =
            r.read_array::<32>("RunnerAttestationV1.reproducibility_pair_blake3")?;
        let phase1_production_binary_blake3 =
            r.read_array::<32>("RunnerAttestationV1.phase1_production_binary_blake3")?;
        let phase1_identity_record_blake3 =
            r.read_array::<32>("RunnerAttestationV1.phase1_identity_record_blake3")?;
        Ok(Self {
            candidate,
            provenance_role,
            b0_pre_spec_hash,
            r0_guest_set_hash,
            build_target_arch,
            execution_tooling_checkout_head,
            ratified_tooling_commit,
            ratified_pathset_blake3,
            recomputed_pathset_blake3,
            measured_source_commit,
            build_git_sha,
            measured_source_context_blake3,
            runner_sha256,
            runner_blake3,
            immutable_builder_identity,
            protobuf_authority_sha256,
            protobuf_authority_blake3,
            native_protoc_sha256,
            native_protoc_blake3,
            native_protoc_version,
            docker_argv_blake3,
            reproducibility_pair_blake3,
            phase1_production_binary_blake3,
            phase1_identity_record_blake3,
        })
    }

    pub fn decode_exact(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut r = Reader::new(bytes);
        let v = Self::decode(&mut r)?;
        r.finish("RunnerAttestationV1")?;
        Ok(v)
    }

    /// SELF-consistency checks that hold regardless of the deployment (do NOT reference the ratified
    /// measured source, so an off-venue dry run with a placeholder commit still exercises them):
    ///   * `build_git_sha == measured_source_commit` (the deterministic build version is the measured
    ///     source, not a wall clock);
    ///   * `recomputed_pathset_blake3 == ratified_pathset_blake3` (the venue recomputed the tooling
    ///     path set and it matches what it declared ratified — a dirty root / changed byte / missing
    ///     or extra path breaks this);
    ///   * the native protoc version is exactly `libprotoc 3.21.12`.
    ///
    /// Note: measured vs tooling are DISTINCT — this never asserts the tooling commit equals the
    /// measured-source commit.
    pub fn check_self_consistency(&self) -> Result<(), String> {
        if self.build_git_sha != self.measured_source_commit {
            return Err(format!(
                "build_git_sha {} != measured_source_commit {} (build version must be the measured \
                 source, not a wall clock)",
                self.build_git_sha, self.measured_source_commit
            ));
        }
        if self.recomputed_pathset_blake3 != self.ratified_pathset_blake3 {
            return Err(format!(
                "recomputed tooling path-set {} != ratified {} (dirty tooling root / changed byte / \
                 missing or extra path)",
                self.recomputed_pathset_blake3, self.ratified_pathset_blake3
            ));
        }
        if self.native_protoc_version != "libprotoc 3.21.12" {
            return Err(format!(
                "native protoc version {:?} != libprotoc 3.21.12",
                self.native_protoc_version
            ));
        }
        // NOTE: runner continuity ([`check_runner_continuity`]) is enforced SEPARATELY by the
        // orchestrator (after it resolves + injects the Phase-1 `production_binary_blake3`) and by the
        // validator + independent import binders — NOT here, because at the venue-facts parse stage the
        // `phase1_production_binary_blake3` field is still the pre-injection placeholder.
        Ok(())
    }

    /// RUNNER CONTINUITY: the Phase-1 identity runner binary equals the measurement runner binary.
    /// Enforced at every stage (producer, assembler, validator, independent, import) — a substituted
    /// or non-reproducible runner binary is refused even when the tooling authority is identical.
    pub fn check_runner_continuity(&self) -> Result<(), String> {
        if self.phase1_production_binary_blake3 != self.runner_blake3 {
            return Err(
                "phase1 production_binary_blake3 (Phase-1 guest-identity runner) != runner_blake3 \
                 (measurement runner); a different compiled binary was used"
                    .into(),
            );
        }
        Ok(())
    }

    /// SEALED-IMPORT continuity anchor: bind this attestation to the INDEPENDENTLY-decoded, retained
    /// Phase-1 identity record. Requires the record's domain-separated address equals the bound field,
    /// the triple runner-binary equality, and the same candidate/arch/measured-source/tooling/spec —
    /// so a mutually-edited attestation cannot fabricate continuity without the authentic record.
    pub fn check_bound_identity_record(
        &self,
        rec: &super::identity_record::Phase1IdentityRecordV1,
    ) -> Result<(), String> {
        if rec.hash() != self.phase1_identity_record_blake3 {
            return Err(
                "retained Phase-1 identity record address != attestation's bound address".into(),
            );
        }
        if rec.production_binary_blake3 != self.phase1_production_binary_blake3
            || rec.production_binary_blake3 != self.runner_blake3
        {
            return Err(
                "retained Phase-1 production_binary_blake3 != phase1/runner_blake3 (runner substitution \
                 or a mutually-edited attestation)"
                    .into(),
            );
        }
        if rec.candidate != self.candidate || rec.arch != self.build_target_arch {
            return Err("retained Phase-1 identity record candidate/arch != attestation".into());
        }
        if rec.source_commit != self.measured_source_commit {
            return Err("retained Phase-1 source_commit != measured_source_commit".into());
        }
        if rec.tooling_commit != self.ratified_tooling_commit
            || rec.tooling_pathset_blake3 != self.ratified_pathset_blake3
        {
            return Err("retained Phase-1 tooling authority != attestation".into());
        }
        if rec.b0_pre_spec_hash != self.b0_pre_spec_hash {
            return Err("retained Phase-1 spec != attestation spec".into());
        }
        Ok(())
    }

    /// Bind the attestation's measured source to the ratified measured source. Separate from the
    /// tooling authority (which is checked via [`crate::tooling_authority::verify_tooling_authority`]
    /// against the tooling commit + path-set digest, NEVER against the measured-source commit).
    pub fn check_bound_to_measured_source(
        &self,
        ratified_measured_source: &str,
    ) -> Result<(), String> {
        if self.measured_source_commit != ratified_measured_source {
            return Err(format!(
                "measured_source_commit {} != ratified measured source {ratified_measured_source}",
                self.measured_source_commit
            ));
        }
        Ok(())
    }

    /// The full internal + measured-source gate (venue / validation path + tests).
    pub fn check_internal_consistency(&self, ratified_measured_source: &str) -> Result<(), String> {
        self.check_self_consistency()?;
        self.check_bound_to_measured_source(ratified_measured_source)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> RunnerAttestationV1 {
        RunnerAttestationV1 {
            candidate: Candidate::Sp1,
            provenance_role: ProvenanceRole::Proving,
            b0_pre_spec_hash: [11; 32],
            r0_guest_set_hash: [12; 32],
            build_target_arch: Arch::X86_64,
            execution_tooling_checkout_head: "a".repeat(40),
            ratified_tooling_commit: "a".repeat(40),
            ratified_pathset_blake3: "b".repeat(64),
            recomputed_pathset_blake3: "b".repeat(64),
            measured_source_commit: "5".repeat(40),
            build_git_sha: "5".repeat(40),
            measured_source_context_blake3: [1; 32],
            runner_sha256: [2; 32],
            runner_blake3: [3; 32],
            immutable_builder_identity: [4; 32],
            protobuf_authority_sha256: [5; 32],
            protobuf_authority_blake3: [6; 32],
            native_protoc_sha256: [7; 32],
            native_protoc_blake3: [8; 32],
            native_protoc_version: "libprotoc 3.21.12".into(),
            docker_argv_blake3: [9; 32],
            reproducibility_pair_blake3: [10; 32],
            // Runner continuity: the Phase-1 runner binary equals the measurement runner (runner_blake3).
            phase1_production_binary_blake3: [3; 32],
            phase1_identity_record_blake3: [11; 32],
        }
    }

    #[test]
    fn roundtrips_and_hash_is_domain_separated() {
        let a = sample();
        assert_eq!(RunnerAttestationV1::decode_exact(&a.encode()).unwrap(), a);
        // domain separation: the raw encode hashed bare differs from hash()
        let bare = *blake3::hash(&a.encode()).as_bytes();
        assert_ne!(bare, a.hash());
    }

    #[test]
    fn truncation_and_trailing_rejected() {
        let bytes = sample().encode();
        assert!(matches!(
            RunnerAttestationV1::decode_exact(&bytes[..bytes.len() - 1]),
            Err(DecodeError::Truncated { .. })
        ));
        let mut long = bytes;
        long.push(0);
        assert!(matches!(
            RunnerAttestationV1::decode_exact(&long),
            Err(DecodeError::TrailingBytes { .. })
        ));
    }

    #[test]
    fn non_hex_commit_rejected() {
        let mut a = sample();
        a.measured_source_commit = "z".repeat(40);
        assert!(matches!(
            RunnerAttestationV1::decode_exact(&a.encode()),
            Err(DecodeError::BadValue { .. })
        ));
    }

    #[test]
    fn runner_continuity_refuses_binary_mismatch() {
        assert!(sample().check_runner_continuity().is_ok());
        // Phase-1 runner binary != measurement runner binary → refused (substitution / non-repro).
        let mut a = sample();
        a.phase1_production_binary_blake3 = [99; 32];
        assert!(a
            .check_runner_continuity()
            .unwrap_err()
            .contains("different compiled binary"));
        // Self-consistency (venue-facts stage) intentionally does NOT check continuity.
        assert!(a.check_self_consistency().is_ok());
    }

    #[test]
    fn bound_identity_record_anchors_continuity() {
        use super::super::identity_record::Phase1IdentityRecordV1;
        let rec = Phase1IdentityRecordV1 {
            candidate: Candidate::Sp1,
            arch: Arch::X86_64,
            source_commit: "5".repeat(40),
            tooling_commit: "a".repeat(40),
            tooling_pathset_blake3: "b".repeat(64),
            b0_pre_spec_hash: [11; 32],
            production_binary_blake3: [3; 32],
        };
        // A well-formed attestation bound to the record accepts.
        let mut a = sample(); // runner_blake3 == phase1 == [3;32], spec [11;32]
        a.measured_source_commit = rec.source_commit.clone();
        a.ratified_tooling_commit = rec.tooling_commit.clone();
        a.ratified_pathset_blake3 = rec.tooling_pathset_blake3.clone();
        a.phase1_identity_record_blake3 = rec.hash();
        assert!(a.check_bound_identity_record(&rec).is_ok());

        // MUTUALLY-EDITED attestation: phase1 == runner_blake3 == X (self-consistent), but the
        // INDEPENDENT retained record still carries the real binary → refused by the record anchor.
        let mut mut_att = a.clone();
        mut_att.phase1_production_binary_blake3 = [99; 32];
        mut_att.runner_blake3 = [99; 32];
        assert!(mut_att.check_runner_continuity().is_ok()); // internally consistent
        assert!(mut_att
            .check_bound_identity_record(&rec)
            .unwrap_err()
            .contains("production_binary_blake3"));

        // Tampered retained record (address no longer matches the bound address) → refused.
        let mut bad_rec = rec.clone();
        bad_rec.production_binary_blake3 = [7; 32];
        assert!(a
            .check_bound_identity_record(&bad_rec)
            .unwrap_err()
            .contains("address"));
    }

    #[test]
    fn internal_consistency_rules() {
        let ratified = "5".repeat(40);
        assert!(sample().check_internal_consistency(&ratified).is_ok());
        // build_git_sha must equal measured source
        let mut a = sample();
        a.build_git_sha = "6".repeat(40);
        assert!(a
            .check_internal_consistency(&ratified)
            .unwrap_err()
            .contains("build_git_sha"));
        // recomputed path-set must equal ratified
        let mut b = sample();
        b.recomputed_pathset_blake3 = "c".repeat(64);
        assert!(b
            .check_internal_consistency(&ratified)
            .unwrap_err()
            .contains("path-set"));
        // wrong protoc version refused
        let mut c = sample();
        c.native_protoc_version = "libprotoc 3.20.0".into();
        assert!(c
            .check_internal_consistency(&ratified)
            .unwrap_err()
            .contains("protoc"));
        // measured source must equal ratified measured source (NOT the tooling commit)
        let mut d = sample();
        d.measured_source_commit = "7".repeat(40);
        d.build_git_sha = "7".repeat(40);
        assert!(d
            .check_internal_consistency(&ratified)
            .unwrap_err()
            .contains("ratified measured source"));
    }
}
