//! INDEPENDENT re-verification of the committed producer self-test vector (TEST-ONLY).
//! No dependency on `b0-pre-validator`: this crate parses the vector and recomputes
//! the guest-set hash, bundle hashes, aggregates, matrix, native-arch validity, and
//! qualification from scratch, accepting the same bytes and identities as the
//! reference crate. Byte-identical acceptance across both implementations is the gate.

use b0_pre_independent::{closure, harness};

const VECTOR: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../docs/b0-pre/fixtures/producer-selftest/producer-dry-run-testonly.bin"
));
const MERGED_SPEC_HEX: &str = "e933e7325c2639a48d8e25f20746d0f8abc822dee9fcfa87c2e6cdec226cf2a2";
const MEASURED_SOURCE: &str = "507281e21e95a6a98e3480e25e12d1baab586e07";

struct Rd<'a> {
    b: &'a [u8],
    p: usize,
}
impl<'a> Rd<'a> {
    fn take(&mut self, n: usize) -> &'a [u8] {
        let s = &self.b[self.p..self.p + n];
        self.p += n;
        s
    }
    fn u32(&mut self) -> usize {
        let b = self.take(4);
        u32::from_be_bytes([b[0], b[1], b[2], b[3]]) as usize
    }
    fn blob(&mut self) -> Vec<u8> {
        let n = self.u32();
        self.take(n).to_vec()
    }
}

// (allowlist bytes, retained V2 record blobs, per-candidate bundles).
type Parsed = (Vec<u8>, Vec<Vec<u8>>, Vec<(u16, harness::Evidence)>);

fn parse(bytes: &[u8]) -> Parsed {
    let mut r = Rd { b: bytes, p: 0 };
    assert_eq!(r.take(13), b"B0PREMEASVEC9", "bad magic");
    let allowlist = r.blob();
    let _mia = r.blob();
    let _report = r.blob();
    let _inv = r.blob();
    let _elig = r.blob(); // VEC8: the retained eligibility/unsupported matrix JSON.
                          // VEC9: the self-contained retained Phase-1 guest-identity record set (three V2 blobs).
    let v2_count = r.u32();
    let mut v2_blobs = Vec::with_capacity(v2_count);
    for _ in 0..v2_count {
        v2_blobs.push(r.blob());
    }
    let n = r.u32();
    let mut bundles = Vec::new();
    for _ in 0..n {
        let cb = r.take(2);
        let candidate = u16::from_be_bytes([cb[0], cb[1]]);
        let mut lists: Vec<Vec<Vec<u8>>> = Vec::with_capacity(7);
        for _ in 0..12 {
            let count = r.u32();
            let mut v = Vec::with_capacity(count);
            for _ in 0..count {
                v.push(r.blob());
            }
            lists.push(v);
        }
        // VEC7: the per-candidate DependencySeedV1 JSON blob (after the 12 lists, before verifier_material).
        let dependency_seed_json = r.blob();
        let verifier_material = r.blob();
        let result_set = r.blob();
        let mut it = lists.into_iter();
        bundles.push((
            candidate,
            harness::Evidence {
                samples: it.next().unwrap(),
                rss: it.next().unwrap(),
                envelopes: it.next().unwrap(),
                provenances: it.next().unwrap(),
                cpuset_chains: it.next().unwrap(),
                runner_attestations: it.next().unwrap(),
                identity_records: it.next().unwrap(),
                recipes: it.next().unwrap(),
                inventories_a: it.next().unwrap(),
                inventories_b: it.next().unwrap(),
                double_build_proofs: it.next().unwrap(),
                leakage_reports: it.next().unwrap(),
                dependency_seed_json,
                verifier_material,
                result_set,
            },
        ));
    }
    assert_eq!(r.p, bytes.len(), "trailing bytes");
    (allowlist, v2_blobs, bundles)
}

// Two-cell model: every candidate is measured on x86_64 (arch == 1) ONLY; no bundle carries an
// aarch64 (arch == 2) cell.
fn x86_only(ev: &harness::Evidence) -> bool {
    ev.envelopes
        .iter()
        .all(|e| closure::decode_env(e).map(|d| d.arch == 1).unwrap_or(false))
}

#[test]
fn independent_verifier_accepts_producer_vector() {
    let (allowlist_bytes, v2_blobs, bundles) = parse(VECTOR);
    // Records-authoritative (VEC9): decode + authenticate the retained V2 set FROM SCRATCH, require the
    // EXACT canonical set, and DERIVE the allowlist + guest-set hash FROM the records — byte-identical to
    // the reference producer's `derive_guest_set` (the cross-verifier parity gate). Never trust the
    // producer-baked allowlist.
    let mut v2 = Vec::with_capacity(v2_blobs.len());
    for b in &v2_blobs {
        let rec = closure::decode_identity_record_v2(b).expect("V2 record decodes");
        assert_eq!(
            closure::encode_identity_record_v2(&rec),
            *b,
            "retained V2 record is canonically encoded"
        );
        v2.push(rec);
    }
    closure::require_exact_v2_identity_set(&v2).expect("exactly the canonical V2 identity set");
    let (derived_allowlist, gs) =
        closure::derive_guest_set_from_v2(&v2, MERGED_SPEC_HEX, MEASURED_SOURCE)
            .expect("derive the guest set from the retained records");
    assert_eq!(
        allowlist_bytes, derived_allowlist,
        "retained allowlist == the allowlist derived from the retained Phase-1 V2 record set"
    );
    closure::decode_allowlist(&allowlist_bytes).expect("allowlist decodes");
    assert_eq!(bundles.len(), 2);
    let mut saw_sp1 = false;
    let mut saw_risc0 = false;
    for (candidate, ev) in &bundles {
        // Two-cell model: both candidates carry their complete x86_64-only native matrix (20 proofs)
        // and both verify + qualify (the two eligible measurement cells).
        assert!(x86_only(ev), "no aarch64 measured cell may exist");
        let rs = closure::decode_result_set(&ev.result_set).expect("result set decodes");
        assert_eq!(
            rs.r0_guest_set_hash, gs,
            "binds the records-derived guest-set hash"
        );
        assert_eq!(rs.measured_proofs.len(), 20);
        assert!(rs.measured_proofs.iter().all(|m| m.0 == 1));
        // CROSS-BIND: every per-provenance V1 record equals its matching retained V2 continuity subset.
        for irb in &ev.identity_records {
            let v1 = closure::decode_identity_record(irb).expect("V1 record decodes");
            let m = v2
                .iter()
                .find(|r| r.candidate == v1.candidate && r.arch == v1.arch)
                .expect("per-provenance V1 record has a matching V2 record");
            assert!(
                closure::v2_matches_v1_continuity(&v1, m),
                "V1<->V2 cross-bind holds for {}/{}",
                v1.candidate,
                v1.arch
            );
        }
        assert!(
            harness::verify_evidence(ev)
                .expect("x86-only cell verifies")
                .qualification,
            "each x86-only measurement cell verifies + qualifies"
        );
        match candidate {
            1 => saw_sp1 = true,
            2 => saw_risc0 = true,
            other => panic!("unexpected candidate {other}"),
        }
    }
    assert!(saw_sp1 && saw_risc0);
}

#[test]
fn independent_rejects_tampered_producer_vector() {
    let (_al, _v2, bundles) = parse(VECTOR);
    let sp1 = &bundles.iter().find(|(c, _)| *c == 1).unwrap().1;
    assert!(harness::verify_evidence(sp1).is_ok());
    let mut m = harness::Evidence {
        samples: sp1.samples.clone(),
        rss: sp1.rss.clone(),
        envelopes: sp1.envelopes.clone(),
        provenances: sp1.provenances.clone(),
        cpuset_chains: sp1.cpuset_chains.clone(),
        runner_attestations: sp1.runner_attestations.clone(),
        identity_records: sp1.identity_records.clone(),
        recipes: sp1.recipes.clone(),
        inventories_a: sp1.inventories_a.clone(),
        inventories_b: sp1.inventories_b.clone(),
        double_build_proofs: sp1.double_build_proofs.clone(),
        leakage_reports: sp1.leakage_reports.clone(),
        dependency_seed_json: sp1.dependency_seed_json.clone(),
        verifier_material: sp1.verifier_material.clone(),
        result_set: sp1.result_set.clone(),
    };
    m.samples[0][40] ^= 1;
    assert!(
        harness::verify_evidence(&m).is_err(),
        "tampered sample rejected"
    );

    // Retained-artifact refusals (independent import): a hash-only provenance field is not enough.
    let mk = || harness::Evidence {
        samples: sp1.samples.clone(),
        rss: sp1.rss.clone(),
        envelopes: sp1.envelopes.clone(),
        provenances: sp1.provenances.clone(),
        cpuset_chains: sp1.cpuset_chains.clone(),
        runner_attestations: sp1.runner_attestations.clone(),
        identity_records: sp1.identity_records.clone(),
        recipes: sp1.recipes.clone(),
        inventories_a: sp1.inventories_a.clone(),
        inventories_b: sp1.inventories_b.clone(),
        double_build_proofs: sp1.double_build_proofs.clone(),
        leakage_reports: sp1.leakage_reports.clone(),
        dependency_seed_json: sp1.dependency_seed_json.clone(),
        verifier_material: sp1.verifier_material.clone(),
        result_set: sp1.result_set.clone(),
    };
    // dropped chain (count)
    let mut m = mk();
    m.cpuset_chains.pop();
    assert!(
        harness::verify_evidence(&m).is_err(),
        "missing cpuset chain rejected"
    );
    // mutated chain byte (recomputed address != declared)
    let mut m = mk();
    let n = m.cpuset_chains[0].len();
    m.cpuset_chains[0][n - 1] ^= 1;
    assert!(
        harness::verify_evidence(&m).is_err(),
        "mutated cpuset chain rejected"
    );
    // swapped chains across (arch, role) → binding (x86_64-only → 2 provenance slots: proving/verification)
    let mut m = mk();
    m.cpuset_chains.swap(0, 1);
    assert!(
        harness::verify_evidence(&m).is_err(),
        "swapped cpuset chains rejected"
    );
    // mutated runner attestation byte
    let mut m = mk();
    let n = m.runner_attestations[0].len();
    m.runner_attestations[0][n - 1] ^= 1;
    assert!(
        harness::verify_evidence(&m).is_err(),
        "mutated runner attestation rejected"
    );
    // dropped attestation (count)
    let mut m = mk();
    m.runner_attestations.pop();
    assert!(
        harness::verify_evidence(&m).is_err(),
        "missing runner attestation rejected"
    );

    // Retained Phase-1 identity-record refusals (independent sealed-import continuity anchor).
    // dropped record (count)
    let mut m = mk();
    m.identity_records.pop();
    assert!(
        harness::verify_evidence(&m).is_err(),
        "missing identity record rejected"
    );
    // tampered record bytes (address != attestation bound address)
    let mut m = mk();
    let n = m.identity_records[0].len();
    m.identity_records[0][n - 1] ^= 1;
    assert!(
        harness::verify_evidence(&m).is_err(),
        "tampered identity record rejected"
    );
    // NOTE: under the reviewed two-cell model each candidate is measured on x86_64 ONLY, so both
    // provenance slots (proving/verification) share the SAME arch and their retained Phase-1 identity
    // records are byte-identical (the record encodes candidate + arch, not role). A record-swap is
    // therefore a no-op and is not a meaningful negative here; the per-provenance BINDING is exercised
    // by the count-drop and byte-mutation cases above (and by the cpuset-chain swap, whose chains do
    // encode the role).
}

/// Records-authoritative (VEC9) negatives on the producer-selftest fixture — the FULL guest-set authority
/// path. The independent mirror decodes the retained V2 set from scratch, derives the allowlist + guest-set
/// hash from the records, and cross-binds each V2 record to its per-provenance V1 continuity. Every way to
/// forge the guest set is refused independently.
#[test]
fn independent_records_authoritative_negatives_all_rejected() {
    let (allowlist_bytes, v2_blobs, bundles) = parse(VECTOR);
    let sp1 = &bundles.iter().find(|(c, _)| *c == 1).unwrap().1;

    // Decode + authenticate the pristine retained V2 set.
    let mut v2 = Vec::with_capacity(v2_blobs.len());
    for b in &v2_blobs {
        let rec = closure::decode_identity_record_v2(b).expect("V2 decodes");
        assert_eq!(
            closure::encode_identity_record_v2(&rec),
            *b,
            "canonical encode"
        );
        v2.push(rec);
    }
    // Baseline: the pristine set derives EXACTLY the retained allowlist (records-authoritative parity).
    let (base_allowlist, _gs) =
        closure::derive_guest_set_from_v2(&v2, MERGED_SPEC_HEX, MEASURED_SOURCE).unwrap();
    assert_eq!(
        base_allowlist, allowlist_bytes,
        "pristine derivation == retained allowlist"
    );

    // (a) tampered guest identity on RISC0/x86 (index 2, no SP1 arch-partner) -> derived allowlist !=
    //     retained. RISC0 has no reconcile partner, so the allowlist-mismatch surfaces directly.
    {
        let mut w = v2.clone();
        w[2].program_id = [0xab; 32];
        let (bad, _) =
            closure::derive_guest_set_from_v2(&w, MERGED_SPEC_HEX, MEASURED_SOURCE).unwrap();
        assert_ne!(
            bad, allowlist_bytes,
            "tampered guest identity must not derive the retained allowlist"
        );
    }
    // (b) tampered SP1/x86 program_id -> SP1 x86/aarch64 reconcile disagreement.
    {
        let mut w = v2.clone();
        w[0].program_id = [0xcd; 32];
        let e = closure::derive_guest_set_from_v2(&w, MERGED_SPEC_HEX, MEASURED_SOURCE)
            .expect_err("reconcile refuses divergent SP1 program_id");
        assert!(e.contains("program_id"), "unexpected error: {e}");
    }
    // (c) reordered set (swap SP1/x86 <-> RISC0/x86) -> canonical-order refusal.
    {
        let mut w = v2.clone();
        w.swap(0, 2);
        assert!(
            closure::require_exact_v2_identity_set(&w).is_err(),
            "reordered set rejected"
        );
    }
    // (d) dropped record -> exactly-three refusal.
    {
        let mut w = v2.clone();
        w.pop();
        let e = closure::require_exact_v2_identity_set(&w).expect_err("short set refused");
        assert!(e.contains("expected exactly"), "unexpected error: {e}");
    }
    // (e) extra record (RISC0/aarch64 appended) -> exact-set refusal (never native-eligible).
    {
        let mut w = v2.clone();
        let mut extra = w[2].clone();
        extra.arch = 2; // Risc0/aarch64
        w.push(extra);
        assert!(
            closure::require_exact_v2_identity_set(&w).is_err(),
            "an extra Risc0/aarch64 record is refused"
        );
    }
    // (f) swapped candidate label (relabel SP1/x86 as RISC0) -> canonical-order/member refusal.
    {
        let mut w = v2.clone();
        w[0].candidate = 2; // Risc0 in the SP1/x86 slot
        assert!(
            closure::require_exact_v2_identity_set(&w).is_err(),
            "a candidate-relabelled record is refused"
        );
    }
    // (g) cross-bind: a mutated V2 continuity field (production_binary) no longer matches the per-provenance
    //     V1 record for that arch (neither representation is substitutable).
    {
        let mut w = v2.clone();
        w[0].production_binary_blake3 = [0xee; 32];
        let v1 = closure::decode_identity_record(&sp1.identity_records[0]).unwrap();
        let m = w
            .iter()
            .find(|r| r.candidate == v1.candidate && r.arch == v1.arch)
            .unwrap();
        assert!(
            !closure::v2_matches_v1_continuity(&v1, m),
            "a mutated V2 continuity field breaks the V1<->V2 cross-bind"
        );
        // ...and the PRISTINE V2 does cross-bind (sanity: the anchor is real, not vacuous).
        let mp = v2
            .iter()
            .find(|r| r.candidate == v1.candidate && r.arch == v1.arch)
            .unwrap();
        assert!(
            closure::v2_matches_v1_continuity(&v1, mp),
            "pristine V1<->V2 cross-bind holds"
        );
    }
    // (h) altered measured source (a clean but non-ratified commit) -> refused by the exact measured-source
    //     authority, even though the record set is otherwise well-formed.
    {
        let mut w = v2.clone();
        for r in &mut w {
            r.source_commit = "a".repeat(40);
        }
        let e = closure::derive_guest_set_from_v2(&w, MERGED_SPEC_HEX, MEASURED_SOURCE)
            .expect_err("non-ratified measured source refused");
        assert!(
            e.contains("ratified measured source"),
            "unexpected error: {e}"
        );
    }
    // (i) SP1 record stripped of its canonical guest artifact address -> refused (SP1 must bind one).
    {
        let mut w = v2.clone();
        w[0].canonical_sp1_guest_artifact_address = String::new();
        assert!(
            closure::derive_guest_set_from_v2(&w, MERGED_SPEC_HEX, MEASURED_SOURCE).is_err(),
            "an SP1 record without a canonical guest artifact address is refused"
        );
    }
    // (j) RISC0 record carrying a canonical SP1 artifact address (candidate/arch substitution) -> refused.
    {
        let mut w = v2.clone();
        w[2].canonical_sp1_guest_artifact_address = "cd".repeat(32);
        assert!(
            closure::derive_guest_set_from_v2(&w, MERGED_SPEC_HEX, MEASURED_SOURCE).is_err(),
            "a RISC0 record carrying a canonical SP1 artifact address is refused"
        );
    }
}
