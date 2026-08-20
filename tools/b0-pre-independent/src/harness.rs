//! Independent R0 evidence harness (NON_SELECTION / TEST_ONLY).
//!
//! From-scratch mirror of the reference harness: its own encoders build the full
//! canonical evidence grid (incl. `host_setup_ns` and the verifier-material
//! manifest record) from the same seed, and its own verifier recomputes every
//! bundle hash, the verifier-material total (from the canonical manifest), and
//! every aggregate from the raw bytes, enforcing the full binding matrix. Shares
//! no encoder/verifier/mutation code with the reference; agreement is proven via
//! the compact seed fixture. Timings are synthetic test data, not selection
//! evidence.

use std::collections::{HashMap, HashSet};

use crate::closure::{self, nearest_rank_p99};
use crate::tags;

pub const NON_SELECTION_LABEL: &str = "NON_SELECTION / TEST_ONLY";
pub const SEED: [u8; 32] = [0x5A; 32];
pub const P99_GATE_NS: u64 = crate::closure::P99_GATE_NS;
pub const VERIFIER_MATERIAL_BYTES: u64 = 292;
const REPS: u32 = 100;
const ITERS: u32 = 10;
const ARCHES: [u8; 2] = [1, 2];
const STMTS: [u8; 2] = [0, 1];
const BUNDLE_METRICS: [u8; 4] = [4, 5, 6, 7]; // prove, verify, setup, proof_bytes

fn id(label: &[u8]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(&SEED);
    h.update(label);
    h.finalize().into()
}
fn stmt_hash(s: u8) -> [u8; 32] {
    if s == 0 {
        id(b"stmt_tlg")
    } else {
        id(b"stmt_st")
    }
}
fn proof_hash(a: u8, s: u8, iter: u32) -> [u8; 32] {
    let mut l = b"proof".to_vec();
    l.push(a);
    l.push(s);
    l.push(iter as u8);
    id(&l)
}
fn push_str(b: &mut Vec<u8>, s: &[u8]) {
    b.extend_from_slice(&(s.len() as u16).to_le_bytes());
    b.extend_from_slice(s);
}

fn enc_vmat_full(byte_len: u64, candidate: u16, vk: [u8; 32]) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(&tags::VERIFIER_MATERIAL);
    b.extend_from_slice(&1u16.to_le_bytes());
    b.extend_from_slice(&candidate.to_le_bytes());
    b.extend_from_slice(&1u32.to_le_bytes());
    let label = b"GROTH16_VK_BYTES";
    b.extend_from_slice(&(label.len() as u16).to_le_bytes());
    b.extend_from_slice(label);
    b.push(0);
    b.extend_from_slice(&byte_len.to_le_bytes());
    b.extend_from_slice(&vk);
    b
}
#[cfg(test)]
fn enc_vmat_with(byte_len: u64, candidate: u16) -> Vec<u8> {
    enc_vmat_full(byte_len, candidate, id(b"vk"))
}

/// Per-candidate identities (independent mirror). Sp1 (candidate 1) reproduces
/// the historical labels, so the committed fixture stays byte-stable.
#[derive(Clone, Copy)]
struct Ids {
    candidate: u16,
    program: [u8; 32],
    lock: [u8; 32],
    container: [u8; 32],
    builder: [u8; 32],
    vk: [u8; 32],
}
fn ids_for(candidate: u16) -> Ids {
    let lbl = |base: &[u8]| -> [u8; 32] {
        if candidate == 1 {
            id(base)
        } else {
            let mut v = base.to_vec();
            v.extend_from_slice(b"_risc0");
            id(&v)
        }
    };
    Ids {
        candidate,
        program: lbl(b"program"),
        lock: lbl(b"lock"),
        container: lbl(b"container"),
        builder: lbl(b"builder"),
        vk: lbl(b"vk"),
    }
}
fn enc_vmat_ids(ids: Ids) -> Vec<u8> {
    enc_vmat_full(VERIFIER_MATERIAL_BYTES, ids.candidate, ids.vk)
}
fn vmat_id(ids: Ids) -> [u8; 32] {
    crate::plain(&enc_vmat_ids(ids))
}

/// Per-role detected/configured resources.
#[derive(Clone, Copy)]
struct RoleRes {
    phys: u32,
    logical: u32,
    ram: u64,
    cpuset: u32,
    mem: u64,
}
/// Controlled host/environment (independent mirror); `default_env()` reproduces
/// the historical fixture.
#[derive(Clone)]
struct Env {
    host_os: String,
    kernel: String,
    cpu_vendor: String,
    cpu_model: String,
    governor: String,
    clock_source: String,
    cgroup_scope_label: String,
    turbo: bool,
    cgroup_version: u8,
    proving: RoleRes,
    verification: RoleRes,
    harness_hash: [u8; 32],
    envcap_hash: [u8; 32],
}
fn default_env() -> Env {
    Env {
        host_os: "linux".into(),
        kernel: "6.8.0".into(),
        cpu_vendor: "GenuineIntel".into(),
        cpu_model: "test".into(),
        governor: "performance".into(),
        clock_source: "tsc".into(),
        cgroup_scope_label: "b0-pre.slice".into(),
        turbo: false,
        cgroup_version: 2,
        proving: RoleRes {
            phys: 16,
            logical: 32,
            ram: 64u64 << 30,
            cpuset: 5,
            mem: 22u64 << 30,
        },
        verification: RoleRes {
            phys: 2,
            logical: 4,
            ram: 4u64 << 30,
            cpuset: 2,
            mem: 4u64 << 30,
        },
        harness_hash: id(b"harness"),
        envcap_hash: id(b"envcap"),
    }
}

fn enc_prov(
    arch: u8,
    role: u8,
    ids: Ids,
    env: &Env,
    cpuset_chain_addr: [u8; 32],
    runner_att_addr: [u8; 32],
) -> Vec<u8> {
    let r = if role == 0 {
        env.proving
    } else {
        env.verification
    };
    let mut b = Vec::new();
    // Provenance-LOCAL schema version v3 (DvfsProvenance sum type + effective-cpuset provenance +
    // runner-attestation address tail); every other record stays v1.
    b.extend_from_slice(&3u16.to_le_bytes());
    b.push(role);
    b.extend_from_slice(&id(b"spec"));
    b.extend_from_slice(&id(b"guest_set"));
    b.extend_from_slice(&ids.candidate.to_le_bytes());
    b.extend_from_slice(&ids.program);
    b.extend_from_slice(&ids.lock);
    b.extend_from_slice(&vmat_id(ids));
    b.push(arch);
    let sc = vec![b'0'; 40];
    b.push(sc.len() as u8);
    b.extend_from_slice(&sc);
    b.push(0);
    b.extend_from_slice(&ids.builder);
    push_str(&mut b, env.host_os.as_bytes());
    push_str(&mut b, env.kernel.as_bytes());
    push_str(&mut b, env.cpu_vendor.as_bytes());
    push_str(&mut b, env.cpu_model.as_bytes());
    b.extend_from_slice(&r.phys.to_le_bytes());
    b.extend_from_slice(&r.logical.to_le_bytes());
    b.extend_from_slice(&r.ram.to_le_bytes());
    b.extend_from_slice(&r.cpuset.to_le_bytes());
    b.extend_from_slice(&r.mem.to_le_bytes());
    // DvfsProvenance::Observable: tag(0) ‖ u16 gov_len ‖ governor ‖ u8 turbo.
    b.push(0u8);
    push_str(&mut b, env.governor.as_bytes());
    b.push(if env.turbo { 1 } else { 0 });
    push_str(&mut b, env.clock_source.as_bytes());
    b.push(env.cgroup_version);
    push_str(&mut b, env.cgroup_scope_label.as_bytes());
    b.extend_from_slice(&env.harness_hash);
    b.extend_from_slice(&env.envcap_hash);
    // v3 tail: effective-cpuset provenance summary (leaf-observed here) + two content addresses.
    let cpuset_raw = format!("0-{}", r.cpuset.saturating_sub(1));
    push_str(&mut b, env.cgroup_scope_label.as_bytes()); // cpuset_source_cgroup_path (leaf)
    push_str(&mut b, cpuset_raw.as_bytes()); // cpuset_raw
    b.push(0); // cpuset_inherited = false (leaf-observed)
    b.extend_from_slice(&cpuset_chain_addr); // cpuset_probe_chain_blake3 (address of the retained chain)
    b.extend_from_slice(&runner_att_addr); // runner_attestation_blake3 (address of the retained attestation)
    b
}

const CPUSET_CHAIN_KIND_H: &[u8; 32] = b"b0-final-cpuset-probe-chain-v1\0\0";

/// Encode one retained observation (matches the reference layout, little-endian).
fn enc_obs_h(b: &mut Vec<u8>, state: u8, raw: &str) {
    b.push(state);
    push_str(b, raw.as_bytes()); // raw
    push_str(b, b"regular"); // file_type
    b.push(0); // is_symlink
    b.push(1);
    b.extend_from_slice(&1u64.to_le_bytes()); // dev Some(1)
    b.push(1);
    b.extend_from_slice(&2u64.to_le_bytes()); // inode Some(2)
    b.push(1);
    b.extend_from_slice(&(raw.len() as u64).to_le_bytes()); // size Some(len)
    b.push(1);
    b.extend_from_slice(&0u64.to_le_bytes()); // mtime_secs Some(0)
    b.push(1);
    b.extend_from_slice(&0u64.to_le_bytes()); // mtime_nanos Some(0)
    b.push(0); // read_error_class None
}

/// Encode a leaf-observed `CpusetProbeChainV1` (independent); returns (bytes, address).
#[allow(clippy::too_many_arguments)]
fn enc_cpuset_chain(
    candidate: u16,
    arch: u8,
    role: u8,
    spec: &[u8; 32],
    gs: &[u8; 32],
    scope: &str,
    raw: &str,
    cpuset: u32,
) -> (Vec<u8>, [u8; 32]) {
    let mut b = Vec::new();
    b.extend_from_slice(CPUSET_CHAIN_KIND_H);
    b.extend_from_slice(&1u16.to_le_bytes());
    b.extend_from_slice(&candidate.to_le_bytes());
    b.push(arch);
    b.push(role);
    b.extend_from_slice(spec);
    b.extend_from_slice(gs);
    push_str(&mut b, scope.as_bytes()); // leaf_scope
    push_str(&mut b, scope.as_bytes()); // source (leaf-observed)
    push_str(&mut b, raw.as_bytes()); // summary_raw
    b.push(0); // summary_inherited false
    b.extend_from_slice(&cpuset.to_le_bytes()); // summary_count
    b.extend_from_slice(&1u32.to_le_bytes()); // entry_count
    push_str(&mut b, scope.as_bytes()); // entry cgroup_path
    b.extend_from_slice(&0u32.to_le_bytes()); // order 0
    enc_obs_h(&mut b, 2, raw);
    enc_obs_h(&mut b, 2, raw);
    let chain = closure::decode_cpuset_chain(&b).expect("self-encoded chain decodes");
    let addr = closure::cpuset_chain_address(&chain);
    (b, addr)
}

const PHASE1_IDENTITY_KIND_H: &[u8; 32] = b"b0-final-phase1-identity-rec-v1\0";

/// Encode a `Phase1IdentityRecordV1` (independent); returns (bytes, domain-separated address).
fn enc_identity_record(
    candidate: u16,
    arch: u8,
    source: &str,
    tooling_commit: &str,
    tooling_pathset: &str,
    spec: &[u8; 32],
    production_binary: &[u8; 32],
) -> (Vec<u8>, [u8; 32]) {
    let mut b = Vec::new();
    let hexs = |b: &mut Vec<u8>, s: &str| {
        b.push(s.len() as u8);
        b.extend_from_slice(s.as_bytes());
    };
    b.extend_from_slice(PHASE1_IDENTITY_KIND_H);
    b.extend_from_slice(&1u16.to_le_bytes());
    b.extend_from_slice(&candidate.to_le_bytes());
    b.push(arch);
    hexs(&mut b, source);
    hexs(&mut b, tooling_commit);
    hexs(&mut b, tooling_pathset);
    b.extend_from_slice(spec);
    b.extend_from_slice(production_binary);
    let addr = closure::identity_record_address(&b);
    (b, addr)
}

/// Encode a `RunnerAttestationV1` (independent, version 4); returns (bytes, address).
fn str16w(b: &mut Vec<u8>, s: &str) {
    b.extend_from_slice(&(s.len() as u16).to_le_bytes());
    b.extend_from_slice(s.as_bytes());
}
fn hexsw(b: &mut Vec<u8>, s: &str) {
    b.push(s.len() as u8);
    b.extend_from_slice(s.as_bytes());
}
// BYTE-IDENTICAL synthetic runner path-independence FIVE-artifact set (mirrors
// measurement::synth_runner_recipe_artifacts with a blake3(seed) seeder). Each returns
// (canonical bytes, domain-separated address).
fn seedb(s: &[u8]) -> [u8; 32] {
    *blake3::hash(s).as_bytes()
}
fn cand_paths(candidate: u16) -> (&'static str, &'static str) {
    if candidate == 2 {
        (
            "tools/b0-pre-measure-risc0/Cargo.toml",
            "release/b0-pre-measure-risc0",
        )
    } else {
        (
            "tools/b0-pre-measure-sp1/Cargo.toml",
            "release/b0-pre-measure-sp1",
        )
    }
}
fn enc_side(b: &mut Vec<u8>, t: &str) {
    str16w(b, &format!("/b0-input/{t}/tooling")); // original_root (provenance only; not compiler-visible)
    str16w(b, &format!("/b0-input/{t}/cargo"));
    str16w(b, &format!("/b0-input/{t}/target"));
    let enc = format!("--remap-path-prefix=/b0-input/{t}/cargo=/b0/cargo\u{1f}--remap-path-prefix=/b0-input/{t}/target=/b0/target");
    b.extend_from_slice(&(enc.len() as u32).to_le_bytes());
    b.extend_from_slice(enc.as_bytes());
}
fn enc_build_recipe(candidate: u16, arch: u8, measured: &str) -> (Vec<u8>, [u8; 32]) {
    let wrapper = seedb(b"wrapper-blake3");
    let recipe_id = closure::compute_recipe_id(measured, &wrapper);
    let (manifest, artifact) = cand_paths(candidate);
    let mut b = Vec::new();
    b.extend_from_slice(b"b0-final-runner-build-recipe-v3\0");
    b.extend_from_slice(&3u16.to_le_bytes());
    b.extend_from_slice(&candidate.to_le_bytes());
    b.push(arch);
    b.extend_from_slice(&recipe_id);
    // build_argv (8)
    let argv = [
        "cargo",
        "build",
        "--release",
        "--locked",
        "--features",
        "real-backend",
        "--manifest-path",
        manifest,
    ];
    b.extend_from_slice(&(argv.len() as u32).to_le_bytes());
    for s in argv {
        str16w(&mut b, s);
    }
    // build_env (3)
    let env: [(&str, &str); 3] = [
        ("BUILD_GIT_SHA", measured),
        ("SOURCE_DATE_EPOCH", "0"),
        ("B0_VENUE_EMBED", "0"),
    ];
    b.extend_from_slice(&(env.len() as u32).to_le_bytes());
    for (k, v) in env {
        str16w(&mut b, k);
        str16w(&mut b, v);
    }
    str16w(&mut b, manifest);
    str16w(&mut b, artifact);
    str16w(&mut b, "cargo");
    str16w(&mut b, "0");
    str16w(&mut b, "/b0/tooling"); // canonical_build_path
    enc_side(&mut b, "a");
    enc_side(&mut b, "b");
    hexsw(&mut b, measured);
    hexsw(&mut b, "1234567890abcdef1234567890abcdef12345678");
    hexsw(&mut b, &"70".repeat(32));
    b.extend_from_slice(&seedb(b"per-arch-toolchain"));
    b.extend_from_slice(&seedb(b"pb-sha256"));
    b.extend_from_slice(&seedb(b"pb-blake3"));
    b.extend_from_slice(&wrapper);
    let addr = closure::runner_build_recipe_address(&b);
    (b, addr)
}
fn compile_record_address(t: &str) -> [u8; 32] {
    let body = format!("b0-final-rustc-invocation/v2\nkind=compile\nremap_arg=--remap-path-prefix=/b0-input/{t}/cargo=/b0/cargo\nremap_arg=--remap-path-prefix=/b0-input/{t}/target=/b0/target");
    *blake3::hash(body.as_bytes()).as_bytes()
}
fn enc_inv_inventory(candidate: u16, arch: u8, tag: u8) -> (Vec<u8>, [u8; 32]) {
    let t = if tag == 0 { "a" } else { "b" };
    let mut b = Vec::new();
    b.extend_from_slice(b"b0-final-rustc-invoc-inv-v2\0\0\0\0\0");
    b.extend_from_slice(&2u16.to_le_bytes());
    b.extend_from_slice(&candidate.to_le_bytes());
    b.push(arch);
    b.push(tag);
    b.extend_from_slice(&1u32.to_le_bytes()); // one compile entry
    str16w(&mut b, "compile");
    b.extend_from_slice(&2u32.to_le_bytes());
    str16w(
        &mut b,
        &format!("--remap-path-prefix=/b0-input/{t}/cargo=/b0/cargo"),
    );
    str16w(
        &mut b,
        &format!("--remap-path-prefix=/b0-input/{t}/target=/b0/target"),
    );
    b.extend_from_slice(&compile_record_address(t));
    let addr = closure::rustc_invocation_inventory_address(&b);
    (b, addr)
}
fn enc_proof_side(
    b: &mut Vec<u8>,
    t: &str,
    guest_img: &[u8; 32],
    inv_addr: [u8; 32],
    s: u64,
    e: u64,
) {
    str16w(b, &format!("/b0-input/{t}/tooling"));
    str16w(b, &format!("/b0-input/{t}/cargo"));
    str16w(b, &format!("/b0-input/{t}/target"));
    b.extend_from_slice(&seedb(b"runner-sha256"));
    b.extend_from_slice(&seedb(b"runner-blake3"));
    b.extend_from_slice(guest_img);
    b.extend_from_slice(&seedb(b"guest-methods"));
    b.extend_from_slice(&inv_addr);
    b.extend_from_slice(&seedb(b"source-input-manifest")); // origin_manifest_blake3
    b.extend_from_slice(&seedb(b"source-input-manifest")); // materialized_manifest_blake3 (== origin)
    b.extend_from_slice(&s.to_le_bytes());
    b.extend_from_slice(&e.to_le_bytes());
}
fn repro_pair() -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(b"b0-final-runner-reproducibility-pair/v1\0");
    h.update(&seedb(b"runner-sha256"));
    h.update(&seedb(b"runner-blake3"));
    h.update(&seedb(b"runner-sha256"));
    h.update(&seedb(b"runner-blake3"));
    *h.finalize().as_bytes()
}
fn enc_double_build_proof(
    candidate: u16,
    arch: u8,
    inv_a_addr: [u8; 32],
    inv_b_addr: [u8; 32],
) -> (Vec<u8>, [u8; 32]) {
    let guest_img = if candidate == 2 {
        seedb(b"guest-img")
    } else {
        [0u8; 32]
    };
    let mut b = Vec::new();
    b.extend_from_slice(b"b0-final-runner-dbl-build-proof0");
    b.extend_from_slice(&2u16.to_le_bytes());
    b.extend_from_slice(&candidate.to_le_bytes());
    b.push(arch);
    b.extend_from_slice(&seedb(b"wrapper-blake3"));
    enc_proof_side(&mut b, "a", &guest_img, inv_a_addr, 100, 200);
    enc_proof_side(&mut b, "b", &guest_img, inv_b_addr, 200, 300);
    b.push(1); // byte_equal
    b.extend_from_slice(&repro_pair());
    let addr = closure::runner_double_build_proof_address(&b);
    (b, addr)
}
fn enc_leak_report(candidate: u16, arch: u8) -> (Vec<u8>, [u8; 32]) {
    let mut b = Vec::new();
    b.extend_from_slice(b"b0-final-runner-leak-report-v2\0\0");
    b.extend_from_slice(&2u16.to_le_bytes());
    b.extend_from_slice(&candidate.to_le_bytes());
    b.push(arch);
    b.extend_from_slice(&seedb(b"runner-blake3"));
    b.push(1); // clean
    str16w(&mut b, "/tmp/b0-evid"); // evidence_root
                                    // refused: sorted union of the six A/B roots + evidence root
    let mut refused = vec![
        "/b0-input/a/tooling".to_string(),
        "/b0-input/a/cargo".to_string(),
        "/b0-input/a/target".to_string(),
        "/b0-input/b/tooling".to_string(),
        "/b0-input/b/cargo".to_string(),
        "/b0-input/b/target".to_string(),
        "/tmp/b0-evid".to_string(),
    ];
    refused.sort();
    refused.dedup();
    b.extend_from_slice(&(refused.len() as u32).to_le_bytes());
    for s in &refused {
        str16w(&mut b, s);
    }
    b.extend_from_slice(&3u32.to_le_bytes());
    for s in ["/b0/cargo", "/b0/target", "/b0/tooling"] {
        str16w(&mut b, s);
    }
    let addr = closure::runner_leakage_report_address(&b);
    (b, addr)
}

#[allow(clippy::type_complexity)]
fn enc_runner_attestation(
    candidate: u16,
    role: u8,
    arch: u8,
    spec: &[u8; 32],
    gs: &[u8; 32],
    measured: &str,
    phase1_identity_record_addr: [u8; 32],
) -> (
    Vec<u8>,
    [u8; 32],
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
) {
    let mut b = Vec::new();
    let hexs = |b: &mut Vec<u8>, s: &str| {
        b.push(s.len() as u8);
        b.extend_from_slice(s.as_bytes());
    };
    let seed = |s: &[u8]| *blake3::hash(s).as_bytes();
    b.extend_from_slice(&7u16.to_le_bytes());
    b.extend_from_slice(&candidate.to_le_bytes());
    b.push(role);
    b.extend_from_slice(spec);
    b.extend_from_slice(gs);
    b.push(arch);
    hexs(&mut b, "1234567890abcdef1234567890abcdef12345678");
    hexs(&mut b, "1234567890abcdef1234567890abcdef12345678");
    hexs(&mut b, &"70".repeat(32));
    hexs(&mut b, &"70".repeat(32));
    hexs(&mut b, measured);
    hexs(&mut b, measured);
    b.extend_from_slice(&seed(b"measured-ctx"));
    b.extend_from_slice(&seed(b"runner-sha256"));
    b.extend_from_slice(&seed(b"runner-blake3"));
    b.extend_from_slice(&seed(b"builder"));
    b.extend_from_slice(&seed(b"pb-sha256"));
    b.extend_from_slice(&seed(b"pb-blake3"));
    b.extend_from_slice(&seed(b"protoc-sha256"));
    b.extend_from_slice(&seed(b"protoc-blake3"));
    let v = b"libprotoc 3.21.12";
    b.push(v.len() as u8);
    b.extend_from_slice(v);
    b.extend_from_slice(&seed(b"docker-argv"));
    b.extend_from_slice(&repro_pair()); // reproducibility_pair == the double-build proof pair
    b.extend_from_slice(&seed(b"runner-blake3")); // phase1 == runner_blake3
    b.extend_from_slice(&phase1_identity_record_addr);
    // v6: the five retained artifact addresses + per-arch toolchain + structural id.
    let (recipe_b, recipe_addr) = enc_build_recipe(candidate, arch, measured);
    let (inv_a, inv_a_addr) = enc_inv_inventory(candidate, arch, 0);
    let (inv_b, inv_b_addr) = enc_inv_inventory(candidate, arch, 1);
    let (proof_b, proof_addr) = enc_double_build_proof(candidate, arch, inv_a_addr, inv_b_addr);
    let (leak_b, leak_addr) = enc_leak_report(candidate, arch);
    b.extend_from_slice(&recipe_addr);
    b.extend_from_slice(&inv_a_addr);
    b.extend_from_slice(&inv_b_addr);
    b.extend_from_slice(&proof_addr);
    b.extend_from_slice(&leak_addr);
    b.extend_from_slice(&seed(b"per-arch-toolchain"));
    b.extend_from_slice(&closure::compute_recipe_id(
        measured,
        &seed(b"wrapper-blake3"),
    ));
    // v7: offline-provisioning authority addresses (host toolchain / dependency seed / protoc).
    b.extend_from_slice(&seed(b"host-toolchain-addr"));
    b.extend_from_slice(&seed(b"dependency-seed-addr"));
    b.extend_from_slice(&seed(b"protoc-authority-addr"));
    let addr = closure::runner_attestation_address(&b);
    (b, addr, recipe_b, inv_a, inv_b, proof_b, leak_b)
}

fn enc_env(arch: u8, stmt: u8, iter: u32, pprov: [u8; 32], ids: Ids) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(&tags::ENVELOPE);
    b.extend_from_slice(&1u16.to_le_bytes());
    b.extend_from_slice(&ids.candidate.to_le_bytes());
    b.extend_from_slice(&ids.lock);
    b.extend_from_slice(&ids.program);
    b.extend_from_slice(&vmat_id(ids));
    b.extend_from_slice(&stmt_hash(stmt));
    b.extend_from_slice(&id(b"spec"));
    b.extend_from_slice(&id(b"guest_set"));
    b.extend_from_slice(&pprov);
    b.push(arch);
    b.push(1);
    b.extend_from_slice(&iter.to_le_bytes());
    b.push(1);
    b.extend_from_slice(&proof_hash(arch, stmt, iter));
    b.extend_from_slice(&0u32.to_le_bytes());
    b
}

#[allow(clippy::too_many_arguments)]
fn enc_sample(
    arch: u8,
    stmt: u8,
    metric: u8,
    unit: u8,
    value: u64,
    iter: u32,
    ph: [u8; 32],
    ids: Ids,
) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(&tags::BENCH_SAMPLE);
    b.extend_from_slice(&1u16.to_le_bytes());
    b.extend_from_slice(&id(b"spec"));
    b.extend_from_slice(&id(b"guest_set"));
    b.extend_from_slice(&stmt_hash(stmt));
    b.extend_from_slice(&ids.candidate.to_le_bytes());
    b.extend_from_slice(&ids.program);
    b.extend_from_slice(&vmat_id(ids));
    b.extend_from_slice(&ids.lock);
    b.extend_from_slice(&ids.container);
    b.push(arch);
    b.push(1);
    b.push(metric);
    b.push(unit);
    b.extend_from_slice(&value.to_le_bytes());
    b.extend_from_slice(&ph);
    b.extend_from_slice(&iter.to_le_bytes());
    b.push(0);
    b
}

fn enc_rss(arch: u8, scope: u8, peak: u64, run: u32, ph: [u8; 32], ids: Ids) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(&tags::BENCH_RSS);
    b.extend_from_slice(&1u16.to_le_bytes());
    b.extend_from_slice(&id(b"spec"));
    b.extend_from_slice(&id(b"guest_set"));
    b.extend_from_slice(&id(b"rss-context"));
    b.extend_from_slice(&ids.candidate.to_le_bytes());
    b.extend_from_slice(&ids.program);
    b.extend_from_slice(&vmat_id(ids));
    b.extend_from_slice(&ids.lock);
    b.extend_from_slice(&ids.container);
    b.push(arch);
    b.push(scope);
    b.extend_from_slice(&ph);
    b.extend_from_slice(&run.to_le_bytes());
    b.extend_from_slice(&peak.to_le_bytes());
    b
}

fn verify_value(a: u8, s: u8, iter: u32, rep: u32) -> u64 {
    40_000_000 + (rep as u64) * 200_000 + (iter as u64) * 1_000 + (s as u64) * 100 + (a as u64) * 10
}
fn prove_value(a: u8, s: u8, iter: u32) -> u64 {
    5_000_000_000 + (iter as u64) * 10 + (s as u64) * 3 + a as u64
}
fn setup_value(iter: u32) -> u64 {
    1_000_000 + iter as u64
}
fn proof_bytes_value(iter: u32) -> u64 {
    200 + iter as u64
}
fn proving_rss_value(iter: u32) -> u64 {
    (2u64 << 30) + iter as u64
}
fn verify_rss_value(a: u8, iter: u32) -> u64 {
    (100u64 << 20) + (a as u64) * 4096 + iter as u64
}

type Rec = (([u8; 32], u32), Vec<u8>);
fn bundle_hash(prefix: &[u8], mut recs: Vec<Rec>) -> ([u8; 32], u32) {
    recs.sort_by_key(|r| r.0);
    let mut h = blake3::Hasher::new();
    h.update(prefix);
    for (_, b) in &recs {
        h.update(b);
    }
    (h.finalize().into(), recs.len() as u32)
}

pub struct Evidence {
    pub samples: Vec<Vec<u8>>,
    pub rss: Vec<Vec<u8>>,
    pub envelopes: Vec<Vec<u8>>,
    pub provenances: Vec<Vec<u8>>,
    pub cpuset_chains: Vec<Vec<u8>>,
    pub runner_attestations: Vec<Vec<u8>>,
    pub identity_records: Vec<Vec<u8>>,
    pub recipes: Vec<Vec<u8>>,
    pub inventories_a: Vec<Vec<u8>>,
    pub inventories_b: Vec<Vec<u8>>,
    pub double_build_proofs: Vec<Vec<u8>>,
    pub leakage_reports: Vec<Vec<u8>>,
    pub verifier_material: Vec<u8>,
    pub result_set: Vec<u8>,
}

#[derive(Debug, PartialEq, Eq)]
pub struct Recomputed {
    pub max_proof_bytes: u32,
    pub worst_arch_p99_verify_ns: u64,
    pub verifier_material_bytes: u64,
    pub worst_arch_verifier_rss_bytes: u64,
    pub qualification: bool,
    pub failure_codes: Vec<u16>,
    pub result_set_hash: [u8; 32],
}

pub fn generate() -> Evidence {
    generate_with(1, &default_env())
}

/// Generate a full evidence bundle for `candidate` (1 = SP1, 2 = RISC0) on the
/// default environment. Used to build the peer candidate of a paired benchmark.
pub fn generate_candidate(candidate: u16) -> Evidence {
    generate_with(candidate, &default_env())
}

fn generate_with(candidate: u16, env: &Env) -> Evidence {
    let ids = ids_for(candidate);
    let mut samples = Vec::new();
    let mut rss = Vec::new();
    let mut envelopes = Vec::new();
    let mut provenances = Vec::new();

    let mut cpuset_chains = Vec::new();
    let mut runner_attestations = Vec::new();
    let mut identity_records = Vec::new();
    let mut recipes = Vec::new();
    let mut inventories_a = Vec::new();
    let mut inventories_b = Vec::new();
    let mut double_build_proofs = Vec::new();
    let mut leakage_reports = Vec::new();
    let mut arch_prov: Vec<(u8, u8, [u8; 32])> = Vec::new();
    let mut proving: HashMap<u8, [u8; 32]> = HashMap::new();
    let spec = id(b"spec");
    let gs = id(b"guest_set");
    let production_binary = *blake3::hash(b"runner-blake3").as_bytes();
    for a in ARCHES {
        for role in [0u8, 1] {
            let rres = if role == 0 {
                env.proving
            } else {
                env.verification
            };
            let raw = format!("0-{}", rres.cpuset.saturating_sub(1));
            let (chain_bytes, chain_addr) = enc_cpuset_chain(
                ids.candidate,
                a,
                role,
                &spec,
                &gs,
                &env.cgroup_scope_label,
                &raw,
                rres.cpuset,
            );
            // Retained Phase-1 identity record (byte-identical to the reference synth record); its
            // domain-separated address is bound into the runner attestation.
            let (rec_bytes, rec_addr) = enc_identity_record(
                ids.candidate,
                a,
                &"0".repeat(40),
                "1234567890abcdef1234567890abcdef12345678",
                &"70".repeat(32),
                &spec,
                &production_binary,
            );
            let (
                att_bytes,
                att_addr,
                recipe_bytes,
                inv_a_bytes,
                inv_b_bytes,
                proof_bytes,
                leak_bytes,
            ) = enc_runner_attestation(
                ids.candidate,
                role,
                a,
                &spec,
                &gs,
                &"0".repeat(40),
                rec_addr,
            );
            let pb = enc_prov(a, role, ids, env, chain_addr, att_addr);
            let h = crate::prefixed(tags::ARCHPROV_PREFIX, &pb);
            if role == 0 {
                proving.insert(a, h);
            }
            arch_prov.push((a, role, h));
            provenances.push(pb);
            cpuset_chains.push(chain_bytes);
            runner_attestations.push(att_bytes);
            identity_records.push(rec_bytes);
            recipes.push(recipe_bytes);
            inventories_a.push(inv_a_bytes);
            inventories_b.push(inv_b_bytes);
            double_build_proofs.push(proof_bytes);
            leakage_reports.push(leak_bytes);
        }
    }

    let mut measured: Vec<(u8, u8, u32, [u8; 32])> = Vec::new();
    let mut sbundle: HashMap<(u8, u8, u8), Vec<Rec>> = HashMap::new();
    let mut prss: HashMap<u8, Vec<Rec>> = HashMap::new();
    let mut vrss: HashMap<u8, Vec<Rec>> = HashMap::new();
    let mut verify_by_arch: HashMap<u8, Vec<u64>> = HashMap::new();
    let mut vrss_by_arch: HashMap<u8, Vec<u64>> = HashMap::new();
    let mut max_pb = 0u64;

    for a in ARCHES {
        for s in STMTS {
            for iter in 0..ITERS {
                let ph = proof_hash(a, s, iter);
                let eb = enc_env(a, s, iter, proving[&a], ids);
                measured.push((a, s, iter, crate::plain(&eb)));
                envelopes.push(eb);
                for rep in 0..REPS {
                    let v = verify_value(a, s, iter, rep);
                    let b = enc_sample(a, s, 5, 1, v, rep, ph, ids);
                    sbundle
                        .entry((a, s, 5))
                        .or_default()
                        .push(((ph, rep), b.clone()));
                    verify_by_arch.entry(a).or_default().push(v);
                    samples.push(b);
                }
                for (metric, unit, value) in [
                    (4u8, 1u8, prove_value(a, s, iter)),
                    (6, 1, setup_value(iter)),
                    (7, 2, proof_bytes_value(iter)),
                ] {
                    let b = enc_sample(a, s, metric, unit, value, iter, ph, ids);
                    sbundle
                        .entry((a, s, metric))
                        .or_default()
                        .push(((ph, iter), b.clone()));
                    samples.push(b);
                }
                max_pb = max_pb.max(proof_bytes_value(iter));
                let b = enc_rss(a, 0, proving_rss_value(iter), iter, ph, ids);
                prss.entry(a).or_default().push(((ph, iter), b.clone()));
                rss.push(b);
                let vrv = verify_rss_value(a, iter);
                vrss_by_arch.entry(a).or_default().push(vrv);
                let b = enc_rss(a, 1, vrv, iter, ph, ids);
                vrss.entry(a).or_default().push(((ph, iter), b.clone()));
                rss.push(b);
            }
        }
    }

    let mut sample_bundles: Vec<(u8, u8, u8, u8, u32, [u8; 32])> = Vec::new();
    for a in ARCHES {
        for s in STMTS {
            for m in BUNDLE_METRICS {
                let (h, c) = bundle_hash(tags::SAMPLEBUNDLE_PREFIX, sbundle[&(a, s, m)].clone());
                sample_bundles.push((a, s, m, 1, c, h));
            }
        }
    }
    let mut rss_bundles: Vec<(u8, u8, u32, [u8; 32])> = Vec::new();
    for a in ARCHES {
        for (scope, coll) in [(0u8, &prss), (1, &vrss)] {
            let (h, c) = bundle_hash(tags::RSSBUNDLE_PREFIX, coll[&a].clone());
            rss_bundles.push((a, scope, c, h));
        }
    }

    let worst_p99 = ARCHES
        .iter()
        .map(|a| {
            let mut v = verify_by_arch[a].clone();
            v.sort_unstable();
            nearest_rank_p99(&v).unwrap()
        })
        .max()
        .unwrap();
    let worst_vrss = ARCHES
        .iter()
        .map(|a| *vrss_by_arch[a].iter().max().unwrap())
        .max()
        .unwrap();
    let qualification = closure::official_qualification(worst_p99);
    let failure_codes = closure::qualification_failure_codes(worst_p99);

    let result_set = enc_result_set(
        ids,
        &arch_prov,
        &measured,
        &sample_bundles,
        &rss_bundles,
        (
            max_pb as u32,
            worst_p99,
            VERIFIER_MATERIAL_BYTES,
            worst_vrss,
        ),
        qualification,
        &failure_codes,
    );

    Evidence {
        samples,
        rss,
        envelopes,
        provenances,
        cpuset_chains,
        runner_attestations,
        identity_records,
        recipes,
        inventories_a,
        inventories_b,
        double_build_proofs,
        leakage_reports,
        verifier_material: enc_vmat_ids(ids),
        result_set,
    }
}

#[allow(clippy::type_complexity, clippy::too_many_arguments)]
fn enc_result_set(
    ids: Ids,
    arch_prov: &[(u8, u8, [u8; 32])],
    measured: &[(u8, u8, u32, [u8; 32])],
    sample_bundles: &[(u8, u8, u8, u8, u32, [u8; 32])],
    rss_bundles: &[(u8, u8, u32, [u8; 32])],
    agg: (u32, u64, u64, u64),
    qualification: bool,
    failure_codes: &[u16],
) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(&1u16.to_le_bytes());
    b.extend_from_slice(&id(b"spec"));
    b.extend_from_slice(&id(b"guest_set"));
    b.extend_from_slice(&ids.candidate.to_le_bytes());
    b.extend_from_slice(&vmat_id(ids));
    b.extend_from_slice(&stmt_hash(0));
    b.extend_from_slice(&stmt_hash(1));
    b.extend_from_slice(&(arch_prov.len() as u32).to_le_bytes());
    for (a, r, h) in arch_prov {
        b.push(*a);
        b.push(*r);
        b.extend_from_slice(h);
    }
    b.extend_from_slice(&(measured.len() as u32).to_le_bytes());
    for (a, s, it, h) in measured {
        b.push(*a);
        b.push(*s);
        b.extend_from_slice(&it.to_le_bytes());
        b.extend_from_slice(h);
    }
    b.extend_from_slice(&(sample_bundles.len() as u32).to_le_bytes());
    for (a, s, m, sk, c, h) in sample_bundles {
        b.push(*a);
        b.push(*s);
        b.push(*m);
        b.push(*sk);
        b.extend_from_slice(&c.to_le_bytes());
        b.extend_from_slice(h);
    }
    b.extend_from_slice(&(rss_bundles.len() as u32).to_le_bytes());
    for (a, sc, c, h) in rss_bundles {
        b.push(*a);
        b.push(*sc);
        b.extend_from_slice(&c.to_le_bytes());
        b.extend_from_slice(h);
    }
    b.extend_from_slice(&id(b"malformed"));
    b.push(0);
    for c in [40u32, 4000, 40, 40, 40] {
        b.extend_from_slice(&c.to_le_bytes());
    }
    b.extend_from_slice(&agg.0.to_le_bytes());
    b.extend_from_slice(&agg.1.to_le_bytes());
    b.extend_from_slice(&agg.2.to_le_bytes());
    b.extend_from_slice(&agg.3.to_le_bytes());
    b.push(if qualification { 1 } else { 0 });
    b.extend_from_slice(&(failure_codes.len() as u32).to_le_bytes());
    for c in failure_codes {
        b.extend_from_slice(&c.to_le_bytes());
    }
    b
}

pub fn verify_evidence(ev: &Evidence) -> Result<Recomputed, String> {
    let rs =
        closure::decode_result_set(&ev.result_set).map_err(|e| format!("result_set: {e:?}"))?;
    closure::validate_completeness(&rs).map_err(|e| format!("completeness: {e}"))?;

    let spec = rs.b0_pre_spec_hash;
    let gs = rs.r0_guest_set_hash;
    let vm = rs.verifier_material_manifest_hash;
    let tlg = rs.stmt_tlg;
    let st = rs.stmt_st;
    let stmt_of = |h: [u8; 32]| -> Result<u8, String> {
        if h == tlg {
            Ok(0)
        } else if h == st {
            Ok(1)
        } else {
            Err("statement binding".into())
        }
    };

    // verifier-material total from the canonical manifest record
    let vmm = closure::decode_vm(&ev.verifier_material).map_err(|e| format!("vmat: {e:?}"))?;
    if closure::Vm::identity(&ev.verifier_material) != vm {
        return Err("verifier-material identity".into());
    }
    let vmat_bytes = vmm.verifier_material_bytes().ok_or("vmat overflow")?;
    if rs.aggregates.2 != vmat_bytes {
        return Err("verifier_material_bytes mismatch".into());
    }

    let mut programs: HashSet<[u8; 32]> = HashSet::new();
    let mut locks: HashSet<[u8; 32]> = HashSet::new();
    let mut containers: HashSet<[u8; 32]> = HashSet::new();

    // provenances
    if ev.provenances.len() != 4 {
        return Err("provenance count".into());
    }
    let mut prov_h: HashMap<(u8, u8), [u8; 32]> = HashMap::new();
    let mut proving: HashMap<u8, [u8; 32]> = HashMap::new();
    for b in &ev.provenances {
        let p = closure::decode_prov(b).map_err(|e| format!("prov: {e:?}"))?;
        if p.spec != spec || p.guest_set != gs || p.vmat != vm || p.candidate != rs.candidate {
            return Err("prov binding".into());
        }
        closure::provenance_eligible(&p).map_err(|e| format!("prov eligible: {e}"))?;
        programs.insert(p.program);
        locks.insert(p.lock);
        let h = closure::provenance_hash(b);
        if prov_h.insert((p.arch, p.role), h).is_some() {
            return Err("duplicate provenance".into());
        }
        if p.role == 0 {
            proving.insert(p.arch, h);
        }
    }
    // Retained artifacts (independent recomputation): exactly one cpuset-chain + one runner-attestation
    // per provenance (SAME order). Decode each from the retained bytes, recompute its address, re-run
    // the structural rules, and bind it to its provenance. A hash-only field is never trusted alone.
    if ev.cpuset_chains.len() != ev.provenances.len() {
        return Err("retained cpuset-chain count != provenance count".into());
    }
    if ev.runner_attestations.len() != ev.provenances.len() {
        return Err("retained runner-attestation count != provenance count".into());
    }
    if ev.identity_records.len() != ev.provenances.len() {
        return Err("retained identity-record count != provenance count".into());
    }
    if ev.recipes.len() != ev.provenances.len()
        || ev.inventories_a.len() != ev.provenances.len()
        || ev.inventories_b.len() != ev.provenances.len()
        || ev.double_build_proofs.len() != ev.provenances.len()
        || ev.leakage_reports.len() != ev.provenances.len()
    {
        return Err("retained runner-recipe artifact count != provenance count".into());
    }
    let mut artifact_keys: HashSet<(u8, u8)> = HashSet::new();
    for (i, pb) in ev.provenances.iter().enumerate() {
        let p = closure::decode_prov(pb).map_err(|e| format!("prov: {e:?}"))?;
        let chain = closure::decode_cpuset_chain(&ev.cpuset_chains[i])
            .map_err(|e| format!("cpuset chain: {e:?}"))?;
        let ca = closure::cpuset_chain_address(&chain);
        closure::bind_cpuset_chain(&chain, &p, ca).map_err(|e| format!("cpuset chain: {e}"))?;
        let att = closure::decode_runner_attestation(&ev.runner_attestations[i])
            .map_err(|e| format!("runner attestation: {e:?}"))?;
        let aa = closure::runner_attestation_address(&ev.runner_attestations[i]);
        closure::bind_runner_attestation(&att, &p, aa)
            .map_err(|e| format!("runner attestation: {e}"))?;
        // Sealed-import runner continuity anchored to the independently-decoded retained record; the
        // per-provenance binding + count is the exact record↔provenance correspondence.
        let rec = closure::decode_identity_record(&ev.identity_records[i])
            .map_err(|e| format!("identity record: {e:?}"))?;
        let ra = closure::identity_record_address(&ev.identity_records[i]);
        closure::bind_identity_record(&rec, &att, ra)
            .map_err(|e| format!("runner continuity: {e}"))?;
        // Sealed-import runner PATH-INDEPENDENCE anchored to the independently-decoded retained
        // five-artifact set (recipe, inventory A, inventory B, double-build proof, leakage report).
        let recipe = closure::decode_runner_build_recipe(&ev.recipes[i])
            .map_err(|e| format!("runner build recipe: {e:?}"))?;
        let recipe_addr = closure::runner_build_recipe_address(&ev.recipes[i]);
        let inv_a = closure::decode_rustc_invocation_inventory(&ev.inventories_a[i])
            .map_err(|e| format!("build-A invocation inventory: {e:?}"))?;
        let inv_a_addr = closure::rustc_invocation_inventory_address(&ev.inventories_a[i]);
        let inv_b = closure::decode_rustc_invocation_inventory(&ev.inventories_b[i])
            .map_err(|e| format!("build-B invocation inventory: {e:?}"))?;
        let inv_b_addr = closure::rustc_invocation_inventory_address(&ev.inventories_b[i]);
        let proof = closure::decode_runner_double_build_proof(&ev.double_build_proofs[i])
            .map_err(|e| format!("runner double-build proof: {e:?}"))?;
        let proof_addr = closure::runner_double_build_proof_address(&ev.double_build_proofs[i]);
        let leak = closure::decode_runner_leakage_report(&ev.leakage_reports[i])
            .map_err(|e| format!("runner leakage report: {e:?}"))?;
        let leak_addr = closure::runner_leakage_report_address(&ev.leakage_reports[i]);
        closure::bind_runner_recipe(
            &att,
            &recipe,
            recipe_addr,
            &inv_a,
            inv_a_addr,
            &inv_b,
            inv_b_addr,
            &proof,
            proof_addr,
            &leak,
            leak_addr,
        )
        .map_err(|e| format!("runner path-independence: {e}"))?;
        if !artifact_keys.insert((p.arch, p.role)) {
            return Err("duplicate retained artifact (arch, role)".into());
        }
    }

    for (a, r, h) in &rs.arch_provenance {
        match prov_h.get(&(*a, *r)) {
            Some(x) if x == h => {}
            _ => return Err("provenance hash mismatch".into()),
        }
    }

    // envelopes
    let mut proof_hashes: HashSet<[u8; 32]> = HashSet::new();
    let mut env_hash: HashMap<(u8, u8, u32), [u8; 32]> = HashMap::new();
    for b in &ev.envelopes {
        let e = closure::decode_env(b).map_err(|e| format!("env: {e:?}"))?;
        if e.b0_pre_spec_hash != spec
            || e.r0_guest_set_hash != gs
            || e.verifier_material_manifest_hash != vm
            || e.candidate != rs.candidate
        {
            return Err("env binding".into());
        }
        let si = stmt_of(e.computation_statement_hash)?;
        if proving.get(&e.arch) != Some(&e.arch_run_provenance) {
            return Err("env provenance link".into());
        }
        programs.insert(e.guest_program_id);
        locks.insert(e.candidate_dep_lock_hash);
        if !proof_hashes.insert(e.proof_hash) {
            return Err("dup proof hash".into());
        }
        if env_hash
            .insert((e.arch, si, e.iteration_index), crate::plain(b))
            .is_some()
        {
            return Err("dup proof cell".into());
        }
    }
    // grid
    for a in ARCHES {
        for s in STMTS {
            for i in 0..ITERS {
                if !env_hash.contains_key(&(a, s, i)) {
                    return Err("grid".into());
                }
            }
        }
    }
    if env_hash.len() != 40 {
        return Err("grid size".into());
    }
    for (a, s, it, h) in &rs.measured_proofs {
        match env_hash.get(&(*a, *s, *it)) {
            Some(x) if x == h => {}
            _ => return Err("measured proof mismatch".into()),
        }
    }

    // samples
    let mut verify_by_arch: HashMap<u8, Vec<u64>> = HashMap::new();
    let mut max_pb = 0u64;
    let mut per: HashMap<(u8, u8, u8), Vec<Rec>> = HashMap::new();
    for b in &ev.samples {
        let s = closure::decode_sample(b).map_err(|e| format!("sample: {e:?}"))?;
        if s.spec != spec || s.guest_set != gs || s.vmat != vm || s.candidate != rs.candidate {
            return Err("sample binding".into());
        }
        if s.sample_kind != 1 {
            return Err("sample warmup".into());
        }
        if s.status != 0 {
            return Err("sample status".into());
        }
        let expected_unit = if s.metric_kind == 7 { 2 } else { 1 };
        if s.unit != expected_unit {
            return Err("sample unit".into());
        }
        if !proof_hashes.contains(&s.proof_hash) {
            return Err("sample orphan".into());
        }
        programs.insert(s.program);
        locks.insert(s.lock);
        containers.insert(s.container);
        let si = stmt_of(s.stmt)?;
        per.entry((s.arch, si, s.metric_kind))
            .or_default()
            .push(((s.proof_hash, s.iteration_index), b.clone()));
        match s.metric_kind {
            5 => verify_by_arch.entry(s.arch).or_default().push(s.value),
            7 => max_pb = max_pb.max(s.value),
            _ => {}
        }
    }
    let claimed: HashMap<(u8, u8, u8), ([u8; 32], u32)> = rs
        .sample_bundles
        .iter()
        .map(|b| ((b.0, b.1, b.2), (b.5, b.4)))
        .collect();
    if per.len() != claimed.len() {
        return Err("sample bundle set".into());
    }
    for (k, recs) in per {
        let (h, c) = bundle_hash(tags::SAMPLEBUNDLE_PREFIX, recs);
        match claimed.get(&k) {
            Some((ch, cc)) if *ch == h && *cc == c => {}
            _ => return Err("sample bundle mismatch".into()),
        }
    }

    // rss
    let mut vrss_by_arch: HashMap<u8, Vec<u64>> = HashMap::new();
    let mut rper: HashMap<(u8, u8), Vec<Rec>> = HashMap::new();
    for b in &ev.rss {
        let r = closure::decode_rss(b).map_err(|e| format!("rss: {e:?}"))?;
        if r.spec != spec || r.guest_set != gs || r.vmat != vm || r.candidate != rs.candidate {
            return Err("rss binding".into());
        }
        if !proof_hashes.contains(&r.proof_hash) {
            return Err("rss orphan".into());
        }
        programs.insert(r.program);
        locks.insert(r.lock);
        containers.insert(r.container);
        if r.rss_scope == 1 {
            vrss_by_arch
                .entry(r.arch)
                .or_default()
                .push(r.peak_rss_bytes);
        }
        rper.entry((r.arch, r.rss_scope))
            .or_default()
            .push(((r.proof_hash, r.run_index), b.clone()));
    }
    let claimed_rss: HashMap<(u8, u8), ([u8; 32], u32)> = rs
        .rss_bundles
        .iter()
        .map(|b| ((b.0, b.1), (b.3, b.2)))
        .collect();
    if rper.len() != claimed_rss.len() {
        return Err("rss bundle set".into());
    }
    for (k, recs) in rper {
        let (h, c) = bundle_hash(tags::RSSBUNDLE_PREFIX, recs);
        match claimed_rss.get(&k) {
            Some((ch, cc)) if *ch == h && *cc == c => {}
            _ => return Err("rss bundle mismatch".into()),
        }
    }

    if programs.len() != 1 {
        return Err("program identity".into());
    }
    if locks.len() != 1 {
        return Err("lock identity".into());
    }
    if containers.len() != 1 {
        return Err("container identity".into());
    }

    let worst_p99 = ARCHES
        .iter()
        .map(|a| {
            let mut v = verify_by_arch.get(a).cloned().unwrap_or_default();
            v.sort_unstable();
            nearest_rank_p99(&v).unwrap_or(0)
        })
        .max()
        .unwrap();
    let worst_vrss = ARCHES
        .iter()
        .map(|a| {
            vrss_by_arch
                .get(a)
                .and_then(|v| v.iter().max().copied())
                .unwrap_or(0)
        })
        .max()
        .unwrap();
    let qualification = closure::official_qualification(worst_p99);
    let failure_codes = closure::qualification_failure_codes(worst_p99);

    let (cpb, cp99, _cvm, cvrss) = rs.aggregates;
    if cpb as u64 != max_pb {
        return Err("max_proof_bytes mismatch".into());
    }
    if cp99 != worst_p99 {
        return Err("p99 mismatch".into());
    }
    if cvrss != worst_vrss {
        return Err("verifier rss mismatch".into());
    }
    if rs.qualification != qualification || rs.failure_codes != failure_codes {
        return Err("qualification mismatch".into());
    }

    Ok(Recomputed {
        max_proof_bytes: max_pb as u32,
        worst_arch_p99_verify_ns: worst_p99,
        verifier_material_bytes: vmat_bytes,
        worst_arch_verifier_rss_bytes: worst_vrss,
        qualification,
        failure_codes,
        result_set_hash: closure::ResultSet::result_set_hash(&ev.result_set),
    })
}

/// Verify a PAIRED benchmark (independent mirror): each candidate's bundle, then
/// that for every `(arch, role)` both candidates' provenance describe the SAME
/// controlled host/environment. Pairing is enforced in this path, not only in
/// unit tests, so a two-candidate benchmark run on different hardware is rejected
/// even though each bundle is internally valid.
pub fn verify_paired_evidence(a: &Evidence, b: &Evidence) -> Result<(), String> {
    verify_evidence(a).map_err(|e| format!("candidate A: {e}"))?;
    verify_evidence(b).map_err(|e| format!("candidate B: {e}"))?;
    let rsa = closure::decode_result_set(&a.result_set).map_err(|e| format!("A rs: {e:?}"))?;
    let rsb = closure::decode_result_set(&b.result_set).map_err(|e| format!("B rs: {e:?}"))?;
    if rsa.candidate == rsb.candidate {
        return Err("paired evidence must be two distinct candidates".into());
    }
    if rsa.b0_pre_spec_hash != rsb.b0_pre_spec_hash {
        return Err("paired candidates bind different b0_pre_spec_hash".into());
    }
    if rsa.r0_guest_set_hash != rsb.r0_guest_set_hash {
        return Err("paired candidates bind different r0_guest_set_hash".into());
    }
    let index = |ev: &Evidence| -> Result<HashMap<(u8, u8), closure::Prov>, String> {
        let mut m = HashMap::new();
        for pb in &ev.provenances {
            let p = closure::decode_prov(pb).map_err(|e| format!("prov: {e:?}"))?;
            if m.insert((p.arch, p.role), p).is_some() {
                return Err("duplicate provenance in bundle".into());
            }
        }
        Ok(m)
    };
    let ma = index(a)?;
    let mb = index(b)?;
    if ma.len() != mb.len() {
        return Err("paired provenance sets differ in shape".into());
    }
    for (k, pa) in &ma {
        let pb = mb
            .get(k)
            .ok_or_else(|| format!("candidate B missing provenance for arch/role {k:?}"))?;
        closure::paired_environment_consistent(pa, pb)
            .map_err(|e| format!("paired environment mismatch at {k:?}: {e}"))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn clone_ev(ev: &Evidence) -> Evidence {
        Evidence {
            samples: ev.samples.clone(),
            rss: ev.rss.clone(),
            envelopes: ev.envelopes.clone(),
            provenances: ev.provenances.clone(),
            cpuset_chains: ev.cpuset_chains.clone(),
            runner_attestations: ev.runner_attestations.clone(),
            identity_records: ev.identity_records.clone(),
            recipes: ev.recipes.clone(),
            inventories_a: ev.inventories_a.clone(),
            inventories_b: ev.inventories_b.clone(),
            double_build_proofs: ev.double_build_proofs.clone(),
            leakage_reports: ev.leakage_reports.clone(),
            verifier_material: ev.verifier_material.clone(),
            result_set: ev.result_set.clone(),
        }
    }
    // decode -> mutate parts -> re-encode (identities are regenerated identically)
    fn with_rs(ev: &Evidence, f: impl Fn(&mut closure::ResultSet)) -> Evidence {
        let mut e = clone_ev(ev);
        let mut rs = closure::decode_result_set(&e.result_set).unwrap();
        f(&mut rs);
        e.result_set = enc_result_set(
            ids_for(1),
            &rs.arch_provenance,
            &rs.measured_proofs,
            &rs.sample_bundles,
            &rs.rss_bundles,
            rs.aggregates,
            rs.qualification,
            &rs.failure_codes,
        );
        e
    }

    #[test]
    fn generated_verifies() {
        let ev = generate();
        assert_eq!(ev.envelopes.len(), 40);
        assert_eq!(ev.samples.len(), 4000 + 40 + 40 + 40);
        assert_eq!(ev.rss.len(), 80);
        let r = verify_evidence(&ev).expect("valid");
        assert!(r.qualification);
        assert_eq!(r.verifier_material_bytes, 292);
    }

    #[test]
    fn paired_same_host_verifies_paired_different_host_rejected() {
        let sp1 = generate();
        // same-host RISC0 peer accepted (candidate + candidate-specific ids differ)
        assert!(verify_paired_evidence(&sp1, &generate_candidate(2)).is_ok());

        // each alt-host RISC0 peer is internally valid but recorded on a DIFFERENT
        // host in one controlled field; the integrated paired path must reject it.
        let reject_on = |name: &str, mutate: &dyn Fn(&mut Env)| {
            let mut env = default_env();
            mutate(&mut env);
            let alt = generate_with(2, &env);
            assert!(
                verify_evidence(&alt).is_ok(),
                "{name}: alt-host bundle must be internally valid"
            );
            assert!(
                verify_paired_evidence(&sp1, &alt).is_err(),
                "e2e paired mismatch on `{name}` must reject"
            );
        };
        reject_on("cpu_model", &|e| e.cpu_model = "alt-cpu".into());
        reject_on("kernel", &|e| e.kernel = "9.9.9".into());
        reject_on("clock_source", &|e| e.clock_source = "hpet".into());
        reject_on("proving_phys", &|e| {
            e.proving.phys = 8;
            e.proving.logical = 16;
        });
        reject_on("proving_ram", &|e| e.proving.ram = 32u64 << 30);
        reject_on("harness_hash", &|e| e.harness_hash = id(b"harness_alt"));
    }

    #[test]
    fn adversarial_matrix_all_reject() {
        let base = generate();
        type M = Box<dyn Fn(&Evidence) -> Evidence>;
        let cases: Vec<(&str, M)> = vec![
            (
                "wrong_guest_set",
                Box::new(|e| {
                    let mut e = clone_ev(e);
                    e.samples[0][66] ^= 1;
                    e
                }),
            ),
            (
                "wrong_candidate",
                Box::new(|e| {
                    let mut e = clone_ev(e);
                    e.samples[0][130] = 2;
                    e
                }),
            ),
            (
                "wrong_program",
                Box::new(|e| {
                    let mut e = clone_ev(e);
                    e.samples[0][132] ^= 1;
                    e
                }),
            ),
            (
                "wrong_vmat_in_record",
                Box::new(|e| {
                    let mut e = clone_ev(e);
                    e.samples[0][164] ^= 1;
                    e
                }),
            ),
            (
                "wrong_lock",
                Box::new(|e| {
                    let mut e = clone_ev(e);
                    e.samples[0][196] ^= 1;
                    e
                }),
            ),
            (
                "wrong_container",
                Box::new(|e| {
                    let mut e = clone_ev(e);
                    e.samples[0][228] ^= 1;
                    e
                }),
            ),
            (
                "wrong_provenance_hash",
                Box::new(|e| {
                    let mut e = clone_ev(e);
                    e.provenances[0][208] ^= 1;
                    e
                }),
            ),
            (
                "provenance_wrong_arch",
                Box::new(|e| {
                    let mut e = clone_ev(e);
                    e.provenances[0][165] ^= 3;
                    e
                }),
            ),
            (
                "missing_provenance",
                Box::new(|e| {
                    let mut e = clone_ev(e);
                    e.provenances.pop();
                    e
                }),
            ),
            (
                "duplicate_provenance",
                Box::new(|e| {
                    let mut e = clone_ev(e);
                    e.provenances.push(e.provenances[0].clone());
                    e
                }),
            ),
            (
                "delete_envelope",
                Box::new(|e| {
                    let mut e = clone_ev(e);
                    e.envelopes.pop();
                    e
                }),
            ),
            (
                "duplicate_envelope",
                Box::new(|e| {
                    let mut e = clone_ev(e);
                    e.envelopes.push(e.envelopes[0].clone());
                    e
                }),
            ),
            (
                "delete_verify_sample",
                Box::new(|e| {
                    let mut e = clone_ev(e);
                    e.samples.remove(0);
                    e
                }),
            ),
            (
                "duplicate_verify_sample",
                Box::new(|e| {
                    let mut e = clone_ev(e);
                    e.samples.push(e.samples[0].clone());
                    e
                }),
            ),
            (
                "changed_iteration_index",
                Box::new(|e| {
                    let mut e = clone_ev(e);
                    e.samples[0][304] ^= 0x40;
                    e
                }),
            ),
            (
                "move_architecture",
                Box::new(|e| {
                    let mut e = clone_ev(e);
                    e.samples[0][260] = 2;
                    e
                }),
            ),
            (
                "move_statement",
                Box::new(|e| {
                    let mut e = clone_ev(e);
                    let st = stmt_hash(1);
                    e.samples[0][98..130].copy_from_slice(&st);
                    e
                }),
            ),
            (
                "move_proof",
                Box::new(|e| {
                    let mut e = clone_ev(e);
                    let ph = proof_hash(1, 0, 5);
                    e.samples[0][272..304].copy_from_slice(&ph);
                    e
                }),
            ),
            (
                "proof_hash_not_matching_envelope",
                Box::new(|e| {
                    let mut e = clone_ev(e);
                    e.envelopes[0][267] ^= 1;
                    e
                }),
            ),
            (
                "wrong_metric_kind",
                Box::new(|e| {
                    let mut e = clone_ev(e);
                    e.samples[0][262] = 3;
                    e
                }),
            ),
            (
                "wrong_unit",
                Box::new(|e| {
                    let mut e = clone_ev(e);
                    e.samples[0][263] = 2;
                    e
                }),
            ),
            (
                "warmup_substituted",
                Box::new(|e| {
                    let mut e = clone_ev(e);
                    e.samples[0][261] = 0;
                    e
                }),
            ),
            (
                "failed_status",
                Box::new(|e| {
                    let mut e = clone_ev(e);
                    e.samples[0][308] = 1;
                    e
                }),
            ),
            (
                "wrong_rss_scope",
                Box::new(|e| {
                    let mut e = clone_ev(e);
                    e.rss[0][261] ^= 1;
                    e
                }),
            ),
            (
                "delete_setup_sample",
                Box::new(|e| {
                    let mut e = clone_ev(e);
                    let i = e.samples.iter().position(|b| b[262] == 6).unwrap();
                    e.samples.remove(i);
                    e
                }),
            ),
            (
                "duplicate_setup_sample",
                Box::new(|e| {
                    let mut e = clone_ev(e);
                    let i = e.samples.iter().position(|b| b[262] == 6).unwrap();
                    e.samples.push(e.samples[i].clone());
                    e
                }),
            ),
            (
                "falsified_max_pb",
                Box::new(|e| with_rs(e, |rs| rs.aggregates.0 += 1)),
            ),
            (
                "falsified_vmat_total",
                Box::new(|e| with_rs(e, |rs| rs.aggregates.2 = 999)),
            ),
            (
                "falsified_vrss",
                Box::new(|e| with_rs(e, |rs| rs.aggregates.3 += 1)),
            ),
            (
                "falsified_qualification",
                Box::new(|e| with_rs(e, |rs| rs.qualification = false)),
            ),
            (
                "qualifying_with_failure_code",
                Box::new(|e| with_rs(e, |rs| rs.failure_codes = vec![3])),
            ),
            (
                "falsified_p99_with_consistent_bundles",
                Box::new(|e| with_rs(e, |rs| rs.aggregates.1 += 1)),
            ),
            (
                "vmat_entry_bytelen_updated_hash",
                Box::new(|e| {
                    let mut e = clone_ev(e);
                    e.verifier_material = enc_vmat_with(293, 1);
                    let newid = crate::plain(&e.verifier_material);
                    e.result_set[68..100].copy_from_slice(&newid); // rs.verifier_material_manifest_hash
                    e
                }),
            ),
            (
                "vmat_omitted_entry",
                Box::new(|e| {
                    let mut e = clone_ev(e);
                    let mut m = Vec::new();
                    m.extend_from_slice(&tags::VERIFIER_MATERIAL);
                    m.extend_from_slice(&1u16.to_le_bytes());
                    m.extend_from_slice(&1u16.to_le_bytes());
                    m.extend_from_slice(&0u32.to_le_bytes());
                    e.verifier_material = m;
                    e
                }),
            ),
            (
                "vmat_wrong_candidate",
                Box::new(|e| {
                    let mut e = clone_ev(e);
                    e.verifier_material = enc_vmat_with(VERIFIER_MATERIAL_BYTES, 2);
                    e
                }),
            ),
        ];
        for (name, mutate) in &cases {
            let ev = mutate(&base);
            assert!(
                verify_evidence(&ev).is_err(),
                "case `{name}` must be rejected"
            );
        }
    }
}
