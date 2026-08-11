//! Independent proof↔identity binding (reviewer correction #2).
//!
//! The guest identity is DERIVED FROM THE BUILT GUEST/SDK (`GuestArtifact::program_id`).
//! The verifier-material manifest is a SEPARATE artifact the terminal verifier consumes —
//! it is NOT the source of the guest identity. Binding checks, independently:
//!   1. the identity the PROOF commits to == the build-derived guest identity;
//!   2. verifier material is present, well-formed, and its manifest identity is DISTINCT
//!      from the guest identity (so guest id is never merely the VMAT manifest hash);
//!   3. the spec hash + guest-set hash the evidence binds are well-formed.
//!
//! Any mismatch REFUSES.

use crate::backend::{GuestArtifact, ProofIdentity};

pub struct VmEntry {
    pub role: String,
    pub byte_len: u64,
    pub hash: String,
}

pub struct VerifierMaterial {
    pub entries: Vec<VmEntry>,
    pub manifest_identity_blake3: String,
}

fn is_hex64(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Map a `b0_pre_vmat` canonical (snake_case) role label to the validator's role token.
fn producer_role(canonical: &str) -> Result<&'static str, String> {
    match canonical {
        "groth16_vk" => Ok("Groth16Vk"),
        "control_root" => Ok("ControlRoot"),
        "control_id" => Ok("ControlId"),
        "verifier_params" => Ok("VerifierParams"),
        other => Err(format!("unknown verifier-material role {other}")),
    }
}

/// Cross-check that the harness verifier material corresponds to the EXACT verifier
/// constants the runner's verifier ACTUALLY uses. `expected` is `(role, entry_blake3_hex)`
/// derived by the backend from its pinned verifier crate (e.g. SP1 `blake3(GROTH16_VK_BYTES)`,
/// RISC0 control-root/control-id/verifier-params digests). Every expected entry must be
/// present with the exact hash and there must be no unexpected entries — so an unrelated but
/// well-formed VMAT is REFUSED. This is what makes the verifier material a real binding.
pub fn check_verifier_material_matches(
    vm: &VerifierMaterial,
    expected: &[(String, String)],
) -> Result<(), String> {
    if expected.is_empty() {
        return Err("backend supplied no expected verifier constants to bind against".into());
    }
    if vm.entries.len() != expected.len() {
        return Err(format!(
            "verifier material has {} entries, expected {} verifier constants",
            vm.entries.len(),
            expected.len()
        ));
    }
    for (role, hash) in expected {
        let found = vm
            .entries
            .iter()
            .find(|e| &e.role == role)
            .ok_or_else(|| format!("verifier material missing expected role {role}"))?;
        if &found.hash != hash {
            return Err(format!(
                "verifier material {role} hash {} != the verifier constant actually used {}",
                found.hash, hash
            ));
        }
    }
    Ok(())
}

/// Parse a verifier-material harness bin's JSON (the SP1/RISC0 `*-verifier-material`
/// extractors) into the binding's [`VerifierMaterial`]. This is how the runner obtains
/// verifier material — from the already-tested `b0_pre_vmat` harness, NOT re-derived — and
/// it is the SEPARATE artifact bound against the SDK-derived guest identity. Fail-closed on
/// any missing/malformed field.
pub fn parse_harness_verifier_material(json: &str) -> Result<VerifierMaterial, String> {
    let v: serde_json::Value =
        serde_json::from_str(json).map_err(|e| format!("verifier-material JSON: {e}"))?;
    let manifest_identity_blake3 = v
        .get("manifest_identity_blake3")
        .and_then(|x| x.as_str())
        .ok_or("verifier material missing manifest_identity_blake3")?
        .to_string();
    let entries_json = v
        .get("entries")
        .and_then(|x| x.as_array())
        .ok_or("verifier material missing entries[]")?;
    let mut entries = Vec::new();
    for e in entries_json {
        let role_raw = e
            .get("role")
            .or_else(|| e.get("label"))
            .and_then(|x| x.as_str())
            .ok_or("verifier-material entry missing role/label")?;
        let role = producer_role(role_raw)?.to_string();
        let byte_len = e
            .get("byte_length")
            .and_then(|x| x.as_u64())
            .ok_or("verifier-material entry missing byte_length")?;
        let hash = e
            .get("blake3")
            .and_then(|x| x.as_str())
            .ok_or("verifier-material entry missing blake3")?
            .to_string();
        entries.push(VmEntry {
            role,
            byte_len,
            hash,
        });
    }
    if entries.is_empty() {
        return Err("verifier material has no entries".into());
    }
    Ok(VerifierMaterial {
        entries,
        manifest_identity_blake3,
    })
}

/// Bind and check a single proved cell's identities. Returns `Ok` only when the proof
/// independently commits to the build-derived guest identity and the verifier material
/// is a distinct, well-formed artifact.
pub fn bind_and_check(
    guest: &GuestArtifact,
    proof_id: &ProofIdentity,
    vm: &VerifierMaterial,
    spec_hash: &str,
    guest_set_hash: &str,
) -> Result<(), String> {
    if !is_hex64(&guest.program_id) {
        return Err(format!(
            "build-derived guest program id is not 64 hex: {}",
            guest.program_id
        ));
    }
    // (1) proof-committed identity must equal the build-derived identity — the
    // independent bind. This is what proves the proof is OF the built guest.
    if proof_id.committed_program_id != guest.program_id {
        return Err(format!(
            "proof commits to {} but the built guest identity is {}",
            proof_id.committed_program_id, guest.program_id
        ));
    }
    // (2) verifier material must be present + well-formed, and its identity must NOT be
    // the guest identity — guarding against inferring guest id from the VMAT manifest.
    if vm.entries.is_empty() {
        return Err("verifier material has no entries".into());
    }
    for e in &vm.entries {
        if e.role.is_empty() || e.byte_len == 0 || !is_hex64(&e.hash) {
            return Err(format!("malformed verifier-material entry role={}", e.role));
        }
    }
    if !is_hex64(&vm.manifest_identity_blake3) {
        return Err("verifier-material manifest identity is not 64 hex".into());
    }
    if vm.manifest_identity_blake3 == guest.program_id {
        return Err(
            "verifier-material manifest identity equals the guest identity; guest id must be \
             derived from the built guest/SDK, not the VMAT manifest"
                .into(),
        );
    }
    // (3) the evidence-bound spec + guest-set hashes must be well-formed.
    if !is_hex64(spec_hash) {
        return Err("bound spec hash is not 64 hex".into());
    }
    if !is_hex64(guest_set_hash) {
        return Err("bound guest-set hash is not 64 hex".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::GuestArtifact;
    use crate::Arch;

    fn guest(id: &str) -> GuestArtifact {
        GuestArtifact {
            guest_image_hash: "aa".repeat(32),
            program_id: id.into(),
            guest_source_tree_hash: "bb".repeat(32),
            candidate_dep_lock_hash: "cc".repeat(32),
            build_command_hash: "dd".repeat(32),
            reproducible: true,
            builders: vec![(Arch::X86_64, "sha256:deadbeef".into())],
        }
    }
    fn vm(id: &str) -> VerifierMaterial {
        VerifierMaterial {
            entries: vec![VmEntry {
                role: "groth16_vk".into(),
                byte_len: 292,
                hash: "ee".repeat(32),
            }],
            manifest_identity_blake3: id.into(),
        }
    }
    const G: &str = "11";
    const M: &str = "22";
    fn h(x: &str) -> String {
        x.repeat(32)
    }

    #[test]
    fn matching_identities_bind() {
        assert!(bind_and_check(
            &guest(&h(G)),
            &ProofIdentity {
                committed_program_id: h(G)
            },
            &vm(&h(M)),
            &h("33"),
            &h("44")
        )
        .is_ok());
    }

    #[test]
    fn proof_committing_to_a_different_guest_refuses() {
        let e = bind_and_check(
            &guest(&h(G)),
            &ProofIdentity {
                committed_program_id: h("99"),
            },
            &vm(&h(M)),
            &h("33"),
            &h("44"),
        )
        .unwrap_err();
        assert!(e.contains("proof commits to"), "{e}");
    }

    #[test]
    fn vmat_manifest_used_as_guest_id_refuses() {
        // guest id == vmat manifest id => refuse (would be inferring guest id from VMAT).
        let e = bind_and_check(
            &guest(&h(G)),
            &ProofIdentity {
                committed_program_id: h(G),
            },
            &vm(&h(G)),
            &h("33"),
            &h("44"),
        )
        .unwrap_err();
        assert!(e.contains("VMAT manifest"), "{e}");
    }

    #[test]
    fn harness_verifier_material_parses_and_maps_roles() {
        let json = r#"{"candidate_id":"Sp1","entries":[
            {"role":"groth16_vk","label":"groth16_vk","byte_length":292,"blake3":"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"}],
            "manifest_identity_blake3":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"}"#;
        let vm = parse_harness_verifier_material(json).unwrap();
        assert_eq!(vm.entries.len(), 1);
        assert_eq!(vm.entries[0].role, "Groth16Vk"); // snake -> validator token
        assert_eq!(vm.entries[0].byte_len, 292);
        assert_eq!(vm.manifest_identity_blake3, h("cc"));
    }

    fn vm_entries(role: &str, hash: &str) -> VerifierMaterial {
        VerifierMaterial {
            entries: vec![VmEntry {
                role: role.into(),
                byte_len: 292,
                hash: hash.into(),
            }],
            manifest_identity_blake3: h("cc"),
        }
    }

    #[test]
    fn verifier_material_matches_the_verifier_constant() {
        let vm = vm_entries("Groth16Vk", &h("ee"));
        assert!(check_verifier_material_matches(&vm, &[("Groth16Vk".into(), h("ee"))]).is_ok());
    }

    #[test]
    fn unrelated_verifier_material_is_refused() {
        let vm = vm_entries("Groth16Vk", &h("ee"));
        // Same role, but the hash is NOT the verifier constant actually used.
        let e = check_verifier_material_matches(&vm, &[("Groth16Vk".into(), h("ff"))]).unwrap_err();
        assert!(e.contains("verifier constant actually used"), "{e}");
        // Wrong count is also refused.
        assert!(check_verifier_material_matches(
            &vm,
            &[
                ("Groth16Vk".into(), h("ee")),
                ("ControlRoot".into(), h("aa"))
            ]
        )
        .is_err());
    }

    #[test]
    fn harness_unknown_role_refuses() {
        let json = r#"{"entries":[{"role":"mystery","byte_length":1,"blake3":"x"}],"manifest_identity_blake3":"y"}"#;
        assert!(parse_harness_verifier_material(json).is_err());
    }

    #[test]
    fn empty_verifier_material_refuses() {
        let mut m = vm(&h(M));
        m.entries.clear();
        assert!(bind_and_check(
            &guest(&h(G)),
            &ProofIdentity {
                committed_program_id: h(G)
            },
            &m,
            &h("33"),
            &h("44")
        )
        .is_err());
    }
}
