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

fn parse(bytes: &[u8]) -> (Vec<u8>, Vec<(u16, harness::Evidence)>) {
    let mut r = Rd { b: bytes, p: 0 };
    assert_eq!(r.take(13), b"B0PREMEASVEC8", "bad magic");
    let allowlist = r.blob();
    let _mia = r.blob();
    let _report = r.blob();
    let _inv = r.blob();
    let _elig = r.blob(); // VEC8: the retained eligibility/unsupported matrix JSON.
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
    (allowlist, bundles)
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
    let (allowlist_bytes, bundles) = parse(VECTOR);
    closure::decode_allowlist(&allowlist_bytes).expect("allowlist decodes");
    let gs = closure::Allowlist::guest_set_hash(&allowlist_bytes);
    assert_eq!(bundles.len(), 2);
    let mut saw_sp1 = false;
    let mut saw_risc0 = false;
    for (candidate, ev) in &bundles {
        // Two-cell model: both candidates carry their complete x86_64-only native matrix (20 proofs)
        // and both verify + qualify (the two eligible measurement cells).
        assert!(x86_only(ev), "no aarch64 measured cell may exist");
        let rs = closure::decode_result_set(&ev.result_set).expect("result set decodes");
        assert_eq!(rs.r0_guest_set_hash, gs, "binds recomputed guest-set hash");
        assert_eq!(rs.measured_proofs.len(), 20);
        assert!(rs.measured_proofs.iter().all(|m| m.0 == 1));
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
    let (_al, bundles) = parse(VECTOR);
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
