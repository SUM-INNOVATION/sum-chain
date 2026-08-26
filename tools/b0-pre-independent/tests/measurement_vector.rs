//! INDEPENDENT second verifier of the committed real-orchestrator measurement
//! vector. This crate does not depend on `b0-pre-validator`, does not import its
//! assembler, and does not reuse its `bundle_hash`. It parses the serialized vector
//! and recomputes EVERYTHING from scratch — the canonical guest-set hash, record
//! sort keys, per-scope bundle hashes, aggregates, expected-matrix counts,
//! native-architecture validity, and the qualification/disqualification reasons —
//! via its own `harness::verify_evidence` + `closure` decoders, and must accept
//! exactly the same bytes and report the same identities as the reference crate.

use b0_pre_independent::{closure, harness};

const VECTOR: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../docs/b0-pre/fixtures/measurement-vector/real-orchestrator-vector.bin"
));
const MERGED_SPEC_HEX: &str = "e933e7325c2639a48d8e25f20746d0f8abc822dee9fcfa87c2e6cdec226cf2a2";

fn spec_bytes() -> [u8; 32] {
    let mut a = [0u8; 32];
    for (i, byte) in a.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&MERGED_SPEC_HEX[i * 2..i * 2 + 2], 16).unwrap();
    }
    a
}

// Independent container reader (the transport envelope, NOT the assembler).
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

// Two-cell model: EVERY candidate is measured on x86_64 (arch == 1) ONLY. aarch64 (arch == 2) is
// ratified-UNSUPPORTED and never measured, so no bundle — SP1 or RISC0 — may carry an aarch64 cell.
// A fabricated aarch64 (repr 2) cell is refused here.
fn x86_only(ev: &harness::Evidence) -> bool {
    ev.envelopes
        .iter()
        .all(|e| closure::decode_env(e).map(|d| d.arch == 1).unwrap_or(false))
}

fn clone_ev(ev: &harness::Evidence) -> harness::Evidence {
    harness::Evidence {
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
        dependency_seed_json: ev.dependency_seed_json.clone(),
        verifier_material: ev.verifier_material.clone(),
        result_set: ev.result_set.clone(),
    }
}

#[test]
fn independent_verifier_accepts_the_same_bytes_and_identities() {
    let (allowlist_bytes, bundles) = parse(VECTOR);
    // Recompute the canonical guest-set hash from scratch and validate the allowlist.
    closure::decode_allowlist(&allowlist_bytes).expect("allowlist decodes");
    let gs = closure::Allowlist::guest_set_hash(&allowlist_bytes);
    let spec = spec_bytes();
    assert_eq!(bundles.len(), 2);

    let mut saw_sp1 = false;
    let mut saw_risc0 = false;
    for (candidate, ev) in &bundles {
        // Two-cell model: both bundles carry their complete x86_64-only native matrix (20 measured
        // proofs) and BOTH verify + qualify — they are the two eligible measurement cells.
        assert!(x86_only(ev), "no aarch64 measured cell may exist");
        let rs = closure::decode_result_set(&ev.result_set).expect("result set decodes");
        assert_eq!(rs.b0_pre_spec_hash, spec, "binds merged spec hash");
        assert_eq!(rs.r0_guest_set_hash, gs, "binds recomputed guest-set hash");
        assert_eq!(
            rs.measured_proofs.len(),
            20,
            "x86_64-only grid → 20 measured proofs"
        );
        assert!(
            rs.measured_proofs.iter().all(|m| m.0 == 1),
            "every measured cell is x86_64"
        );
        let r = harness::verify_evidence(ev).expect("complete x86_64-only native matrix verifies");
        assert!(r.qualification, "p99 < gate → qualifies");
        match candidate {
            1 => saw_sp1 = true,
            2 => saw_risc0 = true,
            other => panic!("unexpected candidate {other}"),
        }
    }
    assert!(saw_sp1 && saw_risc0);
}

#[test]
fn independent_negatives_all_rejected() {
    let (allowlist_bytes, bundles) = parse(VECTOR);
    let sp1 = &bundles.iter().find(|(c, _)| *c == 1).unwrap().1;
    let risc0 = &bundles.iter().find(|(c, _)| *c == 2).unwrap().1;
    // sanity: both pristine bundles verify + qualify (the two eligible x86_64 measurement cells).
    assert!(harness::verify_evidence(sp1).is_ok());
    assert!(harness::verify_evidence(risc0).unwrap().qualification);

    // altered ordering/key + bundle hash: flip a byte inside one sample record.
    let mut m = clone_ev(sp1);
    m.samples[0][40] ^= 1;
    assert!(
        harness::verify_evidence(&m).is_err(),
        "altered sample/key rejected"
    );

    // aggregate / result-set tamper: flip a byte inside the result set.
    let mut m = clone_ev(sp1);
    m.result_set[40] ^= 1;
    assert!(
        harness::verify_evidence(&m).is_err(),
        "tampered result set rejected"
    );

    // missing cell: drop one envelope.
    let mut m = clone_ev(sp1);
    m.envelopes.pop();
    assert!(
        harness::verify_evidence(&m).is_err(),
        "missing cell rejected"
    );

    // duplicate cell: repeat one envelope.
    let mut m = clone_ev(sp1);
    let dup = m.envelopes[0].clone();
    m.envelopes.push(dup);
    assert!(
        harness::verify_evidence(&m).is_err(),
        "duplicate cell rejected"
    );

    // emulated / tampered provenance: flip a byte inside a provenance record.
    let mut m = clone_ev(sp1);
    m.provenances[0][40] ^= 1;
    assert!(
        harness::verify_evidence(&m).is_err(),
        "tampered provenance rejected"
    );

    // altered guest-set hash: a mutated allowlist yields a guest-set hash that no
    // longer matches what every record binds.
    let mut bad_allowlist = allowlist_bytes.clone();
    let last = bad_allowlist.len() - 1;
    bad_allowlist[last] ^= 1;
    let bad_gs = closure::Allowlist::guest_set_hash(&bad_allowlist);
    let rs = closure::decode_result_set(&sp1.result_set).unwrap();
    assert_ne!(
        bad_gs, rs.r0_guest_set_hash,
        "a mutated allowlist must not match the bound guest-set"
    );

    // Two-cell model: neither bundle carries an aarch64 measured cell (aarch64 is ratified-UNSUPPORTED
    // and never measured). A fabricated aarch64 cell would fail x86-only validity.
    assert!(
        x86_only(sp1) && x86_only(risc0),
        "both bundles are x86_64-only"
    );
}
