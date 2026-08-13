//! Cross-implementation agreement on the hypervisor-managed-unobservable DVFS state.
//!
//! The independent verifier must reach the SAME positive/negative decisions as the reference
//! validator (`schema::provenance` + `validation::provenance_eligible`) and the producer reader
//! (`b0-pre-host-provenance::read_dvfs_state`) on the distinct unobservable state. This exercises:
//!   * a well-formed native-aarch64 / Microsoft record with independently-recomputed evidence is
//!     ACCEPTED (positive), and
//!   * every contradiction (x86 arch, wrong hypervisor, missing evidence, tampered evidence hash,
//!     non-canonical absent-control ordering, unknown DVFS tag) is REJECTED (negatives),
//! and pins the domain-separated evidence hash to a shared golden so the three implementations
//! cannot silently diverge on the hashing rule.

use b0_pre_independent::closure::{
    decode_prov, provenance_eligible, recompute_dvfs_evidence_hash, Dvfs, Prov, Unobservable,
};

// The canonical unobservable evidence — byte-identical to the reference validator's `unobs()`
// fixture (`schema::provenance` tests), so the pinned hash below is a genuine cross-impl golden.
const CPU_ARCH: &str = "aarch64";
const CPU_IDENTITY: &str = "CPU implementer=0x41 CPU part=0xd0c";
const VIRT: &str = "microsoft";
const VIRT_SRC: &str = "/sys/class/dmi/id/sys_vendor=Microsoft Corporation";
const ABSENT: [&str; 3] = [
    "a/intel_pstate/no_turbo",
    "b/cpufreq/boost",
    "c/scaling_governor",
];
/// Shared golden: BLAKE3("b0-final-dvfs-unobservable-evidence/v1\0" ‖ canonical) over the values
/// above. The reference validator recomputes the identical value (pinned in its provenance tests).
const EVIDENCE_GOLDEN: &str =
    "6aa1924a8679315c415be5f0769a29c36b602ba2477b7fc79868354ea892b7c6";

fn canonical_unobs() -> Unobservable {
    let mut e = Unobservable {
        cpu_arch: CPU_ARCH.into(),
        cpu_identity: CPU_IDENTITY.into(),
        virtualization: VIRT.into(),
        virtualization_source: VIRT_SRC.into(),
        absent_controls: ABSENT.iter().map(|s| s.to_string()).collect(),
        raw_evidence_blake3: [0u8; 32],
    };
    e.raw_evidence_blake3 = recompute_dvfs_evidence_hash(&e);
    e
}

fn hx(b: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        let _ = write!(s, "{x:02x}");
    }
    s
}

fn push_u16(b: &mut Vec<u8>, s: &[u8]) {
    b.extend_from_slice(&(s.len() as u16).to_le_bytes());
    b.extend_from_slice(s);
}

/// Encode the `DvfsProvenance::HypervisorManagedUnobservable` body (tag 1), mirroring the reference.
fn enc_unobs_body(e: &Unobservable) -> Vec<u8> {
    let mut b = vec![1u8]; // tag: unobservable
    b.push(e.cpu_arch.len() as u8);
    b.extend_from_slice(e.cpu_arch.as_bytes());
    push_u16(&mut b, e.cpu_identity.as_bytes());
    b.push(e.virtualization.len() as u8);
    b.extend_from_slice(e.virtualization.as_bytes());
    push_u16(&mut b, e.virtualization_source.as_bytes());
    b.push(e.absent_controls.len() as u8);
    for c in &e.absent_controls {
        push_u16(&mut b, c.as_bytes());
    }
    b.extend_from_slice(&e.raw_evidence_blake3);
    b
}

/// Encode a full canonical `ArchRunProvenanceV1` record carrying `dvfs_body`, mirroring the
/// reference byte layout exactly (provenance-local schema version 2). `arch`: 1 = x86_64, 2 = aarch64.
fn enc_prov_with_dvfs(role: u8, arch: u8, dvfs_body: &[u8]) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(&2u16.to_le_bytes()); // provenance-local schema version
    b.push(role);
    b.extend_from_slice(&[1u8; 32]); // b0_pre_spec_hash
    b.extend_from_slice(&[2u8; 32]); // r0_guest_set_hash
    b.extend_from_slice(&1u16.to_le_bytes()); // candidate = Sp1
    b.extend_from_slice(&[3u8; 32]); // guest_program_id
    b.extend_from_slice(&[4u8; 32]); // candidate_dep_lock_hash
    b.extend_from_slice(&[5u8; 32]); // verifier_material_manifest_hash
    b.push(arch);
    let sc = vec![b'0'; 40];
    b.push(sc.len() as u8);
    b.extend_from_slice(&sc); // source_commit (40 hex)
    b.push(0); // dirty_tree_flag
    b.extend_from_slice(&[6u8; 32]); // builder_container_digest
    push_u16(&mut b, b"linux");
    push_u16(&mut b, b"6.8.0");
    push_u16(&mut b, b"ARM");
    push_u16(&mut b, b"Neoverse");
    b.extend_from_slice(&16u32.to_le_bytes()); // physical_core_count
    b.extend_from_slice(&32u32.to_le_bytes()); // logical_cpu_count
    b.extend_from_slice(&(64u64 << 30).to_le_bytes()); // total_ram_bytes
    b.extend_from_slice(&2u32.to_le_bytes()); // configured_cpuset_core_limit
    b.extend_from_slice(&(4u64 << 30).to_le_bytes()); // configured_memory_limit_bytes
    b.extend_from_slice(dvfs_body); // DVFS sum
    push_u16(&mut b, b"arch_sys_counter"); // clock_source
    b.push(2); // cgroup_version
    push_u16(&mut b, b"b0.slice"); // cgroup_scope_label
    b.extend_from_slice(&[7u8; 32]); // benchmark_harness_source_hash
    b.extend_from_slice(&[8u8; 32]); // raw_environment_capture_hash
    b
}

/// A freshly-decoded canonical (aarch64, proving) unobservable provenance record (`Prov` is not Clone).
fn fresh() -> Prov {
    decode_prov(&enc_prov_with_dvfs(0, 2, &enc_unobs_body(&canonical_unobs())))
        .expect("canonical unobservable record decodes")
}

#[test]
fn unobservable_evidence_hash_matches_shared_golden() {
    assert_eq!(
        hx(&canonical_unobs().raw_evidence_blake3),
        EVIDENCE_GOLDEN,
        "independent DVFS evidence hash drifted from the shared cross-impl golden"
    );
}

#[test]
fn native_aarch64_microsoft_unobservable_is_accepted() {
    let p = fresh();
    match &p.dvfs {
        Dvfs::Unobservable(e) => assert_eq!(recompute_dvfs_evidence_hash(e), e.raw_evidence_blake3),
        other => panic!("expected Unobservable, got {other:?}"),
    }
    assert_eq!(provenance_eligible(&p), Ok(()));
}

#[test]
fn unobservable_negatives_all_rejected() {
    // x86 arch (discriminant 1) while the evidence claims aarch64 -> arch contradiction.
    let x86 = decode_prov(&enc_prov_with_dvfs(0, 1, &enc_unobs_body(&canonical_unobs()))).unwrap();
    assert_eq!(provenance_eligible(&x86), Err("dvfs_unobservable_arch"));

    // aarch64 record but the evidence's own cpu_arch claims x86_64 -> arch contradiction.
    let mut ev_arch = fresh();
    if let Dvfs::Unobservable(e) = &mut ev_arch.dvfs {
        e.cpu_arch = "x86_64".into();
    }
    assert_eq!(provenance_eligible(&ev_arch), Err("dvfs_unobservable_arch"));

    // wrong hypervisor.
    let mut virt = fresh();
    if let Dvfs::Unobservable(e) = &mut virt.dvfs {
        e.virtualization = "qemu".into();
    }
    assert_eq!(provenance_eligible(&virt), Err("dvfs_unobservable_virt"));

    // no evidence (empty absent-controls set).
    let mut empty = fresh();
    if let Dvfs::Unobservable(e) = &mut empty.dvfs {
        e.absent_controls.clear();
    }
    assert_eq!(provenance_eligible(&empty), Err("dvfs_unobservable_no_evidence"));

    // tampered evidence hash.
    let mut bad_hash = fresh();
    if let Dvfs::Unobservable(e) = &mut bad_hash.dvfs {
        e.raw_evidence_blake3[0] ^= 1;
    }
    assert_eq!(
        provenance_eligible(&bad_hash),
        Err("dvfs_unobservable_evidence_hash")
    );

    // unknown DVFS tag byte in the wire record -> decode fails closed.
    let with_bad_tag = enc_prov_with_dvfs(0, 2, &{
        let mut body = enc_unobs_body(&canonical_unobs());
        body[0] = 2; // unknown tag
        body
    });
    assert!(
        decode_prov(&with_bad_tag).is_err(),
        "unknown DVFS tag must fail closed"
    );

    // non-canonical (unsorted) absent-control ordering -> decode fails closed.
    let u = canonical_unobs();
    let mut body = vec![1u8];
    body.push(u.cpu_arch.len() as u8);
    body.extend_from_slice(u.cpu_arch.as_bytes());
    push_u16(&mut body, u.cpu_identity.as_bytes());
    body.push(u.virtualization.len() as u8);
    body.extend_from_slice(u.virtualization.as_bytes());
    push_u16(&mut body, u.virtualization_source.as_bytes());
    body.push(2);
    push_u16(&mut body, b"zzz");
    push_u16(&mut body, b"aaa"); // descending -> rejected
    body.extend_from_slice(&u.raw_evidence_blake3);
    assert!(
        decode_prov(&enc_prov_with_dvfs(0, 2, &body)).is_err(),
        "non-canonical absent-control ordering must fail closed"
    );
}
