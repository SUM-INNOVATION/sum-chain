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
    "201cfcb80e94a5a7845dc3380cde32171d40f325ae2bacde9547f3c0da3c4df3";

/// The ratified source commit the guest MUST be built from — the exact owner-ratified
/// checkout, not merely a commit all records agree on. A different (even clean) commit is
/// refused. This is the frozen MEASURED-CANDIDATE source (the merged B0-FINAL head af875ee0);
/// it is deliberately NOT advanced to the toolchain-authority commit SHA (that is separate
/// operational tooling/authority metadata, not the measured source).
pub const RATIFIED_SOURCE_COMMIT: &str = "af875ee03dbb69ddf16638f73928a8351300cd9a";

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
    // EXACT source authority: the guest must be built from the ratified commit, not merely a
    // commit the records agree on. A different (even clean) commit is refused.
    if r.source_commit != RATIFIED_SOURCE_COMMIT {
        return Err(format!(
            "{}/{}: source commit {} != ratified {RATIFIED_SOURCE_COMMIT}",
            r.candidate, r.arch, r.source_commit
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
    ] {
        h.update(&(f.len() as u32).to_be_bytes());
        h.update(f.as_bytes());
    }
    *h.finalize().as_bytes()
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
    fn source_authority_is_af875ee0() {
        // The frozen measured-candidate source authority is af875ee0 (the merged B0-FINAL
        // head), NOT the authority-record commit SHA (operational tooling/authority metadata).
        assert_eq!(
            RATIFIED_SOURCE_COMMIT,
            "af875ee03dbb69ddf16638f73928a8351300cd9a"
        );
    }
}
