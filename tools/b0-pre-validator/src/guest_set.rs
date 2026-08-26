//! B0-FINAL phase-1 guest-closure producer: derive the canonical `r0_guest_set_hash` from
//! the venue-built, typed guest IDENTITY records — never an operator-supplied value.
//!
//! Each eligible guest is built (twice, byte-identical — enforced by the phase-1 orchestrator)
//! and its identity emitted by `b0-pre-measure-{sp1,risc0} --emit-identity`. This module
//! consumes ONLY those typed records, fail-closed:
//!   * the EXACT eligible set must be present: (Sp1,x86_64), (Sp1,aarch64), (Risc0,x86_64);
//!   * duplicates, a RISC-Zero-aarch64 record, a dirty tree, a mock/stub build, or a
//!     mismatched commit/spec are rejected;
//!   * SP1 is reconciled across arches (the zkVM program/image identity MUST agree; both
//!     native builder records are preserved).
//!
//! It then populates `GuestProgramAllowlistV1` and computes `r0_guest_set_hash` through the
//! EXISTING canonical library code (`measurement::official_allowlist` / `r0_guest_set_hash`),
//! and emits a content-addressed coordination manifest that `measure_fragment.sh` re-verifies.

use serde::Deserialize;

use crate::enums::{Arch, Candidate};
use crate::measurement::{official_allowlist, r0_guest_set_hash, GuestBuild};
use crate::schema::allowlist::{BuilderArch, GuestProgramAllowlistV1};

/// The merged, finalized `b0_pre_spec_hash` every record must bind.
pub const MERGED_SPEC_HASH_HEX: &str =
    "e933e7325c2639a48d8e25f20746d0f8abc822dee9fcfa87c2e6cdec226cf2a2";

/// The ratified source commit the guest MUST be built from — the exact owner-ratified
/// checkout, not merely a commit all records agree on. A different (even clean) commit is
/// refused. This is the frozen MEASURED-CANDIDATE source: the x86-validated measured-source head
/// 507281e2. It binds the validated PRE-BINDING source, NOT this source-binding commit itself, and
/// is deliberately independent of the toolchain-authority builder-evidence commit (af875ee0),
/// which is separate operational tooling/authority metadata, not the measured source.
pub const RATIFIED_SOURCE_COMMIT: &str = "507281e21e95a6a98e3480e25e12d1baab586e07";

/// Domain tag for the coordination-manifest content address.
const MANIFEST_DOMAIN: &[u8] = b"b0-final-guest-set-manifest/v1";

/// A typed guest-identity record emitted by a runner's `--emit-identity`. Deserialize twin
/// of `b0_pre_measure_core::GuestIdentityRecord`.
#[derive(Deserialize, Clone)]
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
    // ---- two-root authority: the MEASUREMENT-TOOLING checkout the identity was derived with. This
    // is the SECOND, independent authority; it is verified against the tooling authority
    // (`tooling_authority::verify_tooling_authority`) and is NEVER compared to
    // `RATIFIED_SOURCE_COMMIT` (the measured source, bound by `source_commit` above). ----
    pub tooling_commit: String,
    pub tooling_pathset_blake3: String,
    // ---- SP1 ONLY: the canonical SP1 guest artifact this identity CONSUMED (never rebuilt). The
    // single x86-authoritative ELF is distributed to every arch; both SP1 records bind the SAME
    // address, which is exactly how the shared-program requirement is enforced (reconcile_sp1
    // refuses a divergent address). Empty for RISC0 (which embeds its own locked native guest). ----
    #[serde(default)]
    pub canonical_sp1_guest_artifact_address: String,
}

/// Strictly LOWERCASE hex (an uppercase digit is a non-canonical identity → reject; a
/// case-insensitive check would let two encodings of the same bytes pass).
fn is_lower_hex(s: &str) -> bool {
    s.bytes()
        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn hex32(s: &str, ctx: &str) -> Result<[u8; 32], String> {
    if s.len() != 64 || !is_lower_hex(s) {
        return Err(format!("{ctx}: expected 64 LOWERCASE hex chars, got {s:?}"));
    }
    let mut a = [0u8; 32];
    for (i, byte) in a.iter_mut().enumerate() {
        *byte =
            u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).map_err(|_| format!("{ctx}: bad hex"))?;
    }
    Ok(a)
}
fn hexn(s: &str, n: usize, ctx: &str) -> Result<Vec<u8>, String> {
    if s.len() != n * 2 || !is_lower_hex(s) {
        return Err(format!("{ctx}: expected {n}-byte LOWERCASE hex"));
    }
    Ok((0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect())
}
fn parse_candidate(s: &str) -> Result<Candidate, String> {
    match s {
        "Sp1" => Ok(Candidate::Sp1),
        "Risc0" => Ok(Candidate::Risc0),
        other => Err(format!("unknown candidate {other}")),
    }
}
fn parse_arch(s: &str) -> Result<Arch, String> {
    match s {
        "x86_64" => Ok(Arch::X86_64),
        "aarch64" => Ok(Arch::Aarch64),
        other => Err(format!("unknown arch {other}")),
    }
}
fn hx(b: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        let _ = write!(s, "{x:02x}");
    }
    s
}

/// The result of a guest-set derivation.
#[derive(Debug)]
pub struct GuestSetOutput {
    pub allowlist: GuestProgramAllowlistV1,
    pub r0_guest_set_hash: [u8; 32],
    /// The canonical coordination-manifest JSON (content-addressed by `manifest_hash`).
    pub manifest_json: String,
    /// blake3 over the authoritative manifest content (domain ‖ spec ‖ guest-set ‖
    /// allowlist-encoding ‖ records-digest) — the content address the venues transfer + verify.
    pub manifest_hash: [u8; 32],
}

/// Authenticate an operator-supplied coordination manifest by requiring its canonical bytes to
/// EQUAL the independently re-derived manifest (every bound field), NOT merely its self-declared
/// `manifest_hash`. A manifest that copies the correct `manifest_hash` string but alters any
/// other field is refused. Trailing whitespace/newline (as written to file) is tolerated.
pub fn authenticate_manifest(supplied: &str, gs: &GuestSetOutput) -> Result<(), String> {
    if supplied.trim_end() != gs.manifest_json {
        return Err(
            "supplied coordination manifest bytes != independently re-derived manifest \
             (forged/altered manifest; a copied manifest_hash cannot mask an altered field)"
                .into(),
        );
    }
    Ok(())
}

fn validate_record(r: &GuestIdentityRecord, spec_hex: &str) -> Result<(Candidate, Arch), String> {
    let cand = parse_candidate(&r.candidate)?;
    let arch = parse_arch(&r.arch)?;
    // Native eligibility: a RISC-Zero-aarch64 identity is never admissible.
    if cand == Candidate::Risc0 && arch == Arch::Aarch64 {
        return Err("RISC Zero aarch64 identity record is native-ineligible; rejected".into());
    }
    if !r.clean_tree {
        return Err(format!(
            "{}/{}: dirty source tree; rejected",
            r.candidate, r.arch
        ));
    }
    if !r.real_backend {
        return Err(format!(
            "{}/{}: mock/non-real backend; rejected",
            r.candidate, r.arch
        ));
    }
    // EVERY eligible identity must be from a REAL embedded guest (never a CI stub) —
    // enforced for both candidates, not only RISC Zero.
    if !r.real_guest_embedded {
        return Err(format!(
            "{}/{}: stub build (real_guest_embedded=false); rejected",
            r.candidate, r.arch
        ));
    }
    if r.b0_pre_spec_hash != spec_hex {
        return Err(format!(
            "{}/{}: record spec {} != {spec_hex}",
            r.candidate, r.arch, r.b0_pre_spec_hash
        ));
    }
    hexn(&r.source_commit, 20, "source_commit")?;
    // EXACT MEASURED-SOURCE authority: the guest must be built from the ratified MEASURED source, not
    // merely a commit the records agree on. A different (even clean) commit is refused. This binds the
    // guest/program identity to the frozen source ONLY.
    if r.source_commit != RATIFIED_SOURCE_COMMIT {
        return Err(format!(
            "{}/{}: source commit {} != ratified {RATIFIED_SOURCE_COMMIT}",
            r.candidate, r.arch, r.source_commit
        ));
    }
    // Two-root separation: the MEASUREMENT-TOOLING authority is a DISTINCT, independently-shaped
    // identity. Here we validate its SHAPE (40-hex tooling commit, 64-hex path-set digest); the
    // equality binding to the ratified tooling authority is a SEPARATE gate
    // (`verify_ratified_tooling_authority`). We deliberately NEVER compare `tooling_commit` to
    // `RATIFIED_SOURCE_COMMIT` — conflating the tooling head with the measured source is the exact
    // defect the two-root model removes.
    hexn(&r.tooling_commit, 20, "tooling_commit")?;
    hex32(&r.tooling_pathset_blake3, "tooling_pathset_blake3")?;
    if r.tooling_commit == RATIFIED_SOURCE_COMMIT {
        return Err(format!(
            "{}/{}: tooling_commit equals the measured-source RATIFIED_SOURCE_COMMIT; the two-root \
             model forbids conflating tooling with measured source",
            r.candidate, r.arch
        ));
    }
    // The toolchain identity must be a real derived 64-hex identity (bound to the ratified
    // provisioned toolchain), never a synthetic label like "sp1-toolchain".
    for (ctx, v) in [
        ("guest_source_tree_hash", &r.guest_source_tree_hash),
        ("candidate_dep_lock_hash", &r.candidate_dep_lock_hash),
        ("guest_image_hash", &r.guest_image_hash),
        ("program_id", &r.program_id),
        ("builder_container_digest", &r.builder_container_digest),
        ("toolchain_identity", &r.toolchain_identity),
        (
            "verifier_material_manifest_hash",
            &r.verifier_material_manifest_hash,
        ),
        ("build_command_hash", &r.build_command_hash),
        ("production_binary_blake3", &r.production_binary_blake3),
    ] {
        hex32(v, ctx)?;
    }
    // Canonical SP1 guest artifact: SP1 identities are DERIVED from the single distributed ELF, so
    // every SP1 record MUST bind a 64-hex artifact address; RISC0 embeds its own locked native guest
    // and must NOT carry one (a stray address there would be a candidate/arch substitution attempt).
    match cand {
        Candidate::Sp1 => {
            hex32(
                &r.canonical_sp1_guest_artifact_address,
                "canonical_sp1_guest_artifact_address",
            )?;
        }
        Candidate::Risc0 => {
            if !r.canonical_sp1_guest_artifact_address.is_empty() {
                return Err(format!(
                    "{}/{}: RISC0 record carries a canonical SP1 guest artifact address; rejected",
                    r.candidate, r.arch
                ));
            }
        }
    }
    Ok((cand, arch))
}

/// Require the SP1 x86_64 + aarch64 records to agree on the arch-independent zkVM identity,
/// and return one reconciled `GuestBuild` preserving BOTH native builder digests.
fn reconcile_sp1(
    x86: &GuestIdentityRecord,
    arm: &GuestIdentityRecord,
    spec: [u8; 32],
) -> Result<GuestBuild, String> {
    for (field, a, b) in [
        ("program_id", &x86.program_id, &arm.program_id),
        (
            "guest_image_hash",
            &x86.guest_image_hash,
            &arm.guest_image_hash,
        ),
        (
            "guest_source_tree_hash",
            &x86.guest_source_tree_hash,
            &arm.guest_source_tree_hash,
        ),
        (
            "candidate_dep_lock_hash",
            &x86.candidate_dep_lock_hash,
            &arm.candidate_dep_lock_hash,
        ),
        (
            "verifier_material_manifest_hash",
            &x86.verifier_material_manifest_hash,
            &arm.verifier_material_manifest_hash,
        ),
        (
            "build_command_hash",
            &x86.build_command_hash,
            &arm.build_command_hash,
        ),
        ("source_commit", &x86.source_commit, &arm.source_commit),
        // Two-root: both native SP1 builds must share ONE tooling authority (same tooling root).
        ("tooling_commit", &x86.tooling_commit, &arm.tooling_commit),
        (
            "tooling_pathset_blake3",
            &x86.tooling_pathset_blake3,
            &arm.tooling_pathset_blake3,
        ),
        // THE shared-program gate: both arches consumed the SAME canonical guest artifact. This is
        // what makes "one program, measured on every host" true after per-arch cross-compile
        // divergence — program_id agrees BECAUSE both derive it from these exact distributed bytes.
        (
            "canonical_sp1_guest_artifact_address",
            &x86.canonical_sp1_guest_artifact_address,
            &arm.canonical_sp1_guest_artifact_address,
        ),
    ] {
        if a != b {
            return Err(format!(
                "SP1 x86_64/aarch64 disagree on {field}: {a} vs {b}; stopping (divergent guest identity)"
            ));
        }
    }
    let _ = spec;
    Ok(GuestBuild {
        candidate: Candidate::Sp1,
        guest_source_tree_hash: hex32(&x86.guest_source_tree_hash, "guest_source_tree_hash")?,
        candidate_dep_lock_hash: hex32(&x86.candidate_dep_lock_hash, "candidate_dep_lock_hash")?,
        // Both native builder records preserved, in canonical arch order.
        builder_arches: vec![
            BuilderArch {
                arch: Arch::X86_64,
                builder_container_digest: hex32(
                    &x86.builder_container_digest,
                    "builder_container_digest",
                )?,
            },
            BuilderArch {
                arch: Arch::Aarch64,
                builder_container_digest: hex32(
                    &arm.builder_container_digest,
                    "builder_container_digest",
                )?,
            },
        ],
        guest_image_hash: hex32(&x86.guest_image_hash, "guest_image_hash")?,
        program_id: hex32(&x86.program_id, "program_id")?,
        verifier_material_manifest_hash: hex32(
            &x86.verifier_material_manifest_hash,
            "verifier_material_manifest_hash",
        )?,
        build_command_hash: hex32(&x86.build_command_hash, "build_command_hash")?,
        reproducible: true,
    })
}

fn risc0_build(r: &GuestIdentityRecord) -> Result<GuestBuild, String> {
    Ok(GuestBuild {
        candidate: Candidate::Risc0,
        guest_source_tree_hash: hex32(&r.guest_source_tree_hash, "guest_source_tree_hash")?,
        candidate_dep_lock_hash: hex32(&r.candidate_dep_lock_hash, "candidate_dep_lock_hash")?,
        builder_arches: vec![BuilderArch {
            arch: Arch::X86_64,
            builder_container_digest: hex32(
                &r.builder_container_digest,
                "builder_container_digest",
            )?,
        }],
        guest_image_hash: hex32(&r.guest_image_hash, "guest_image_hash")?,
        program_id: hex32(&r.program_id, "program_id")?,
        verifier_material_manifest_hash: hex32(
            &r.verifier_material_manifest_hash,
            "verifier_material_manifest_hash",
        )?,
        build_command_hash: hex32(&r.build_command_hash, "build_command_hash")?,
        reproducible: true,
    })
}

/// A stable per-record identity digest (binds WHICH records produced the set).
fn record_digest(r: &GuestIdentityRecord) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    for f in [
        &r.candidate,
        &r.arch,
        &r.source_commit,
        &r.guest_source_tree_hash,
        &r.candidate_dep_lock_hash,
        &r.guest_image_hash,
        &r.program_id,
        &r.builder_container_digest,
        &r.toolchain_identity,
        &r.verifier_material_manifest_hash,
        &r.build_command_hash,
        &r.production_binary_blake3,
        &r.b0_pre_spec_hash,
        &r.tooling_commit,
        &r.tooling_pathset_blake3,
        &r.canonical_sp1_guest_artifact_address,
    ] {
        h.update(&(f.len() as u32).to_be_bytes());
        h.update(f.as_bytes());
    }
    *h.finalize().as_bytes()
}

/// The SEPARATE tooling-authority gate (two-root model). Verifies every record's `tooling_commit` +
/// `tooling_pathset_blake3` against the ratified MEASUREMENT-TOOLING authority
/// ([`crate::tooling_authority::verify_tooling_authority`]) — NOT against `RATIFIED_SOURCE_COMMIT`.
/// This is deliberately DISTINCT from `derive_guest_set` (which binds the measured source): the venue
/// calls both. While the tooling authority is UNBOUND (Commit A), this refuses every record, so no
/// official run can proceed until Commit B binds the tooling authority.
pub fn verify_ratified_tooling_authority(records: &[GuestIdentityRecord]) -> Result<(), String> {
    for r in records {
        crate::tooling_authority::verify_tooling_authority(
            &r.tooling_commit,
            &r.tooling_pathset_blake3,
        )
        .map_err(|e| format!("{}/{}: tooling authority: {e}", r.candidate, r.arch))?;
    }
    Ok(())
}

/// Derive the canonical guest set from the typed identity records. Fail-closed on every
/// admissibility, completeness, and reconciliation rule above.
pub fn derive_guest_set(
    records: &[GuestIdentityRecord],
    spec_hex: &str,
) -> Result<GuestSetOutput, String> {
    if spec_hex != MERGED_SPEC_HASH_HEX {
        return Err(format!(
            "spec {spec_hex} != merged finalized {MERGED_SPEC_HASH_HEX}"
        ));
    }
    let spec = hex32(spec_hex, "spec")?;

    // Validate + index by (candidate, arch); reject duplicates.
    use std::collections::BTreeMap;
    let mut by_key: BTreeMap<(String, String), &GuestIdentityRecord> = BTreeMap::new();
    for r in records {
        validate_record(r, spec_hex)?;
        let key = (r.candidate.clone(), r.arch.clone());
        if by_key.insert(key.clone(), r).is_some() {
            return Err(format!(
                "duplicate identity record for {}/{}",
                r.candidate, r.arch
            ));
        }
    }

    // Require EXACTLY the eligible set.
    let want = [("Sp1", "x86_64"), ("Sp1", "aarch64"), ("Risc0", "x86_64")];
    if by_key.len() != want.len() {
        return Err(format!(
            "expected exactly {} eligible identity records (Sp1 x86_64/aarch64, Risc0 x86_64), got {}",
            want.len(),
            by_key.len()
        ));
    }
    let get = |c: &str, a: &str| -> Result<&GuestIdentityRecord, String> {
        by_key
            .get(&(c.to_string(), a.to_string()))
            .copied()
            .ok_or_else(|| format!("missing eligible identity record for {c}/{a}"))
    };
    let sp1_x86 = get("Sp1", "x86_64")?;
    let sp1_arm = get("Sp1", "aarch64")?;
    let risc0_x86 = get("Risc0", "x86_64")?;

    // All records must share the same source commit (one reconciled checkout).
    if sp1_x86.source_commit != risc0_x86.source_commit {
        return Err(format!(
            "records span different source commits: {} vs {}",
            sp1_x86.source_commit, risc0_x86.source_commit
        ));
    }

    let sp1 = reconcile_sp1(sp1_x86, sp1_arm, spec)?;
    let risc0 = risc0_build(risc0_x86)?;

    // Canonical library derivation — the EXACT code the measurement path + verifiers use.
    let allowlist = official_allowlist(spec, &[sp1, risc0]);
    let guest_set = r0_guest_set_hash(&allowlist);

    // Content-addressed coordination manifest.
    let allowlist_enc = allowlist.encode();
    let allowlist_hash = *blake3::hash(&allowlist_enc).as_bytes();
    let mut rec_digests: Vec<[u8; 32]> = records.iter().map(record_digest).collect();
    rec_digests.sort();
    let mut rd = blake3::Hasher::new();
    for d in &rec_digests {
        rd.update(d);
    }
    let records_digest = *rd.finalize().as_bytes();

    let mut mh = blake3::Hasher::new();
    mh.update(MANIFEST_DOMAIN);
    mh.update(&spec);
    mh.update(&guest_set);
    mh.update(&allowlist_hash);
    mh.update(&records_digest);
    let manifest_hash = *mh.finalize().as_bytes();

    let manifest_json = serde_json::to_string_pretty(&serde_json::json!({
        "manifest_kind": "b0-final-guest-set-manifest/v1",
        "b0_pre_spec_hash": spec_hex,
        "r0_guest_set_hash": hx(&guest_set),
        "allowlist_encoding_blake3": hx(&allowlist_hash),
        "records_digest_blake3": hx(&records_digest),
        "manifest_hash": hx(&manifest_hash),
        "note": "content address = blake3(domain ‖ spec ‖ r0_guest_set_hash ‖ blake3(allowlist.encode()) ‖ records_digest). \
                 Verify manifest_hash before trusting r0_guest_set_hash; recompute the guest set from the identity records.",
    }))
    .map_err(|e| e.to_string())?;

    Ok(GuestSetOutput {
        allowlist,
        r0_guest_set_hash: guest_set,
        manifest_json,
        manifest_hash,
    })
}

/// v8: re-decode the ONE canonical SP1 guest artifact FROM ITS RETAINED BYTES (manifest + ELF) and
/// require the assembled SP1 identity records to reference EXACTLY it. This is the measure-produce /
/// sealed-import re-check of the shared-program mapping — never a copied hash: the manifest is parsed
/// and its address recomputed, the ELF is re-hashed, and every SP1 record's canonical address,
/// program_id and guest_image_hash MUST equal the artifact. RISC0 records must carry none. Returns the
/// artifact's recomputed 64-hex address (the single address both SP1 arches share).
pub fn verify_canonical_sp1_guest_artifact(
    records: &[GuestIdentityRecord],
    manifest_json: &[u8],
    elf: &[u8],
) -> Result<String, String> {
    use crate::venue::canonical_sp1_guest_artifact::CanonicalSp1GuestArtifactV1;
    let art = CanonicalSp1GuestArtifactV1::from_json(manifest_json)?;
    art.verify(RATIFIED_SOURCE_COMMIT)?; // shape + double-build + address self-consistency
    art.verify_elf(elf)?; // size + sha256 + blake3 + guest_image_hash from the retained ELF bytes
    let mut saw_sp1 = false;
    for r in records {
        match parse_candidate(&r.candidate)? {
            Candidate::Sp1 => {
                saw_sp1 = true;
                if r.canonical_sp1_guest_artifact_address != art.address {
                    return Err(format!(
                        "{}/{}: record canonical artifact address != the retained artifact address",
                        r.candidate, r.arch
                    ));
                }
                if r.program_id != art.program_id {
                    return Err(format!(
                        "{}/{}: record program_id != canonical artifact program_id",
                        r.candidate, r.arch
                    ));
                }
                if r.guest_image_hash != art.guest_image_hash {
                    return Err(format!(
                        "{}/{}: record guest_image_hash != canonical artifact guest_image_hash",
                        r.candidate, r.arch
                    ));
                }
            }
            Candidate::Risc0 => {
                if !r.canonical_sp1_guest_artifact_address.is_empty() {
                    return Err(format!(
                        "{}/{}: RISC0 record carries a canonical SP1 guest artifact address; refused",
                        r.candidate, r.arch
                    ));
                }
            }
        }
    }
    if !saw_sp1 {
        return Err("no SP1 identity record to bind the canonical guest artifact to".into());
    }
    Ok(art.address)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(cand: &str, arch: &str) -> GuestIdentityRecord {
        // Arch-independent zkVM identity is shared across SP1 arches; builder digest differs.
        let builder = if arch == "x86_64" {
            "b0".repeat(32)
        } else {
            "b1".repeat(32)
        };
        GuestIdentityRecord {
            candidate: cand.into(),
            arch: arch.into(),
            source_commit: RATIFIED_SOURCE_COMMIT.into(),
            clean_tree: true,
            guest_source_tree_hash: if cand == "Sp1" {
                "12".repeat(32)
            } else {
                "34".repeat(32)
            },
            candidate_dep_lock_hash: "cc".repeat(32),
            guest_image_hash: if cand == "Sp1" {
                "11".repeat(32)
            } else {
                "22".repeat(32)
            },
            program_id: if cand == "Sp1" {
                "aa".repeat(32)
            } else {
                "bb".repeat(32)
            },
            builder_container_digest: builder,
            // Real per-arch 64-hex toolchain identity (arch-specific, not reconciled).
            toolchain_identity: if arch == "x86_64" {
                "e0".repeat(32)
            } else {
                "e1".repeat(32)
            },
            verifier_material_manifest_hash: if cand == "Sp1" {
                "dd".repeat(32)
            } else {
                "ee".repeat(32)
            },
            build_command_hash: if cand == "Sp1" {
                "77".repeat(32)
            } else {
                "88".repeat(32)
            },
            production_binary_blake3: "99".repeat(32),
            real_backend: true,
            real_guest_embedded: true,
            b0_pre_spec_hash: MERGED_SPEC_HASH_HEX.into(),
            // Tooling authority: a DISTINCT commit (never the measured-source RATIFIED_SOURCE_COMMIT)
            // shared across both SP1 arches (one tooling root), plus a 64-hex path-set digest.
            tooling_commit: "a".repeat(40),
            tooling_pathset_blake3: "f0".repeat(32),
            // SP1 arches share ONE canonical artifact address; RISC0 carries none.
            canonical_sp1_guest_artifact_address: if cand == "Sp1" {
                "ca".repeat(32)
            } else {
                String::new()
            },
        }
    }
    fn eligible() -> Vec<GuestIdentityRecord> {
        vec![
            rec("Sp1", "x86_64"),
            rec("Sp1", "aarch64"),
            rec("Risc0", "x86_64"),
        ]
    }

    #[test]
    fn eligible_set_derives_and_is_deterministic() {
        let a = derive_guest_set(&eligible(), MERGED_SPEC_HASH_HEX).unwrap();
        let b = derive_guest_set(&eligible(), MERGED_SPEC_HASH_HEX).unwrap();
        assert_eq!(a.r0_guest_set_hash, b.r0_guest_set_hash);
        assert_eq!(a.manifest_hash, b.manifest_hash);
        assert_eq!(a.manifest_json, b.manifest_json);
        // The guest-set hash is r0_guest_set_hash over the canonical allowlist encoding, so it
        // equals what the independent verifier computes — proven against a shared committed
        // fixture in tests/guest_set_vector.rs (validator) + the independent crate (both accept
        // the same allowlist bytes), the same both-verifier gate used for the producer vector.
    }

    #[test]
    fn missing_second_sp1_build_is_refused() {
        let mut r = eligible();
        r.remove(1); // drop SP1 aarch64
        assert!(derive_guest_set(&r, MERGED_SPEC_HASH_HEX).is_err());
    }

    #[test]
    fn risc0_aarch64_record_is_refused() {
        let mut r = eligible();
        r.push(rec("Risc0", "aarch64"));
        assert!(derive_guest_set(&r, MERGED_SPEC_HASH_HEX).is_err());
    }

    #[test]
    fn sp1_cross_arch_disagreement_is_refused() {
        let mut r = eligible();
        r[1].program_id = "cc".repeat(32); // aarch64 program id != x86
        let e = derive_guest_set(&r, MERGED_SPEC_HASH_HEX).unwrap_err();
        assert!(e.contains("disagree on program_id"), "{e}");
    }

    #[test]
    fn dirty_tree_is_refused() {
        let mut r = eligible();
        r[0].clean_tree = false;
        assert!(derive_guest_set(&r, MERGED_SPEC_HASH_HEX)
            .unwrap_err()
            .contains("dirty"));
    }

    #[test]
    fn stub_or_mock_is_refused() {
        let mut r = eligible();
        r[2].real_guest_embedded = false; // RISC0 stub
        assert!(derive_guest_set(&r, MERGED_SPEC_HASH_HEX)
            .unwrap_err()
            .contains("stub"));
        let mut r2 = eligible();
        r2[0].real_backend = false; // mock
        assert!(derive_guest_set(&r2, MERGED_SPEC_HASH_HEX)
            .unwrap_err()
            .contains("mock"));
    }

    #[test]
    fn wrong_commit_or_duplicate_is_refused() {
        let mut r = eligible();
        r[2].source_commit = "b".repeat(40);
        assert!(derive_guest_set(&r, MERGED_SPEC_HASH_HEX).is_err());
        let mut d = eligible();
        d.push(rec("Sp1", "x86_64")); // duplicate
        assert!(derive_guest_set(&d, MERGED_SPEC_HASH_HEX)
            .unwrap_err()
            .contains("duplicate"));
    }

    #[test]
    fn mismatched_spec_is_refused() {
        let mut r = eligible();
        r[0].b0_pre_spec_hash = "00".repeat(32);
        assert!(derive_guest_set(&r, MERGED_SPEC_HASH_HEX).is_err());
    }

    #[test]
    fn uppercase_hex_is_refused() {
        let mut r = eligible();
        r[0].program_id = "AA".repeat(32); // uppercase — non-canonical
        assert!(derive_guest_set(&r, MERGED_SPEC_HASH_HEX)
            .unwrap_err()
            .to_lowercase()
            .contains("hex"));
    }

    #[test]
    fn synthetic_toolchain_label_is_refused() {
        let mut r = eligible();
        r[0].toolchain_identity = "sp1-toolchain".into(); // a label, not an identity
        assert!(derive_guest_set(&r, MERGED_SPEC_HASH_HEX)
            .unwrap_err()
            .contains("toolchain_identity"));
    }

    #[test]
    fn sp1_stub_is_also_refused() {
        let mut r = eligible();
        r[0].real_guest_embedded = false; // SP1 stub — refused for every candidate
        assert!(derive_guest_set(&r, MERGED_SPEC_HASH_HEX)
            .unwrap_err()
            .contains("stub"));
    }

    #[test]
    fn consistent_but_non_authoritative_commit_is_refused() {
        // All three records agree on a DIFFERENT clean commit — must still be refused.
        let mut r = eligible();
        for rec in &mut r {
            rec.source_commit = "c".repeat(40);
        }
        assert!(derive_guest_set(&r, MERGED_SPEC_HASH_HEX)
            .unwrap_err()
            .contains("ratified"));
    }

    #[test]
    fn forged_manifest_with_copied_hash_is_refused() {
        let gs = derive_guest_set(&eligible(), MERGED_SPEC_HASH_HEX).unwrap();
        // The genuine manifest authenticates (with or without a trailing newline).
        assert!(authenticate_manifest(&gs.manifest_json, &gs).is_ok());
        assert!(authenticate_manifest(&format!("{}\n", gs.manifest_json), &gs).is_ok());
        // Forge: KEEP the correct manifest_hash line but alter another field. Byte compare
        // against the re-derived canonical manifest rejects it.
        assert!(gs.manifest_json.contains("\"r0_guest_set_hash\""));
        let forged =
            gs.manifest_json
                .replacen("b0-final-guest-set-manifest/v1", "TAMPERED-KIND", 1);
        assert_ne!(forged, gs.manifest_json);
        assert!(authenticate_manifest(&forged, &gs)
            .unwrap_err()
            .contains("forged/altered"));
    }

    #[test]
    fn tooling_commit_equal_to_measured_source_is_refused() {
        // Two-root separation: a record whose tooling_commit == the measured-source RATIFIED commit
        // (i.e. the two roots collapsed onto one commit) is refused.
        let mut r = eligible();
        for rec in &mut r {
            rec.tooling_commit = RATIFIED_SOURCE_COMMIT.into();
        }
        assert!(derive_guest_set(&r, MERGED_SPEC_HASH_HEX)
            .unwrap_err()
            .contains("conflating tooling with measured source"));
    }

    #[test]
    fn malformed_tooling_authority_shape_is_refused() {
        let mut r = eligible();
        r[0].tooling_pathset_blake3 = "zz".repeat(32); // not hex
        assert!(derive_guest_set(&r, MERGED_SPEC_HASH_HEX)
            .unwrap_err()
            .to_lowercase()
            .contains("hex"));
        let mut r2 = eligible();
        r2[0].tooling_commit = "a".repeat(39); // wrong length
        assert!(derive_guest_set(&r2, MERGED_SPEC_HASH_HEX).is_err());
    }

    #[test]
    fn sp1_cross_arch_tooling_disagreement_is_refused() {
        let mut r = eligible();
        r[1].tooling_commit = "b".repeat(40); // aarch64 tooling != x86 tooling
        assert!(derive_guest_set(&r, MERGED_SPEC_HASH_HEX)
            .unwrap_err()
            .contains("disagree on tooling_commit"));
    }

    #[test]
    fn ratified_tooling_authority_gate_refuses_non_ratified_records() {
        // Durable contract, independent of whether the tooling authority is currently UNBOUND
        // (Commit A) or bound (Commit B): the distinct tooling-authority gate refuses records whose
        // tooling commit / path-set digest are not the ratified measurement-tooling authority.
        // `eligible()` carries a deliberately non-ratified tooling identity ("a"*40 / "f0"*32), so the
        // gate must reject it, and the refusal is scoped to the tooling-authority check. We assert the
        // durable refusal semantics only — never the transient sentinel text — so this test holds
        // before and after Commit B binds the authority. derive_guest_set still succeeds because it
        // binds only the measured source; the tooling gate is the distinct second check.
        assert!(derive_guest_set(&eligible(), MERGED_SPEC_HASH_HEX).is_ok());
        let e = verify_ratified_tooling_authority(&eligible()).expect_err(
            "non-ratified tooling identity must be refused by the tooling-authority gate",
        );
        assert!(
            e.contains("tooling authority"),
            "refusal must be scoped to the tooling-authority gate: {e}"
        );
    }

    #[test]
    fn source_authority_is_507281e2() {
        // The frozen measured-candidate source authority is 507281e2 (the x86-validated
        // measured-source head), NOT the authority-record commit SHA (operational tooling/authority
        // metadata) and NOT this source-binding commit itself.
        assert_eq!(
            RATIFIED_SOURCE_COMMIT,
            "507281e21e95a6a98e3480e25e12d1baab586e07"
        );
    }
}
