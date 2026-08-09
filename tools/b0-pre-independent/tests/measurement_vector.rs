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
const MERGED_SPEC_HEX: &str = "201cfcb80e94a5a7845dc3380cde32171d40f325ae2bacde9547f3c0da3c4df3";

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
    assert_eq!(r.take(13), b"B0PREMEASVEC1", "bad magic");
    let allowlist = r.blob();
    let n = r.u32();
    let mut bundles = Vec::new();
    for _ in 0..n {
        let cb = r.take(2);
        let candidate = u16::from_be_bytes([cb[0], cb[1]]);
        let mut lists: Vec<Vec<Vec<u8>>> = Vec::with_capacity(4);
        for _ in 0..4 {
            let count = r.u32();
            let mut v = Vec::with_capacity(count);
            for _ in 0..count {
                v.push(r.blob());
            }
            lists.push(v);
        }
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
                verifier_material,
                result_set,
            },
        ));
    }
    assert_eq!(r.p, bytes.len(), "trailing bytes");
    (allowlist, bundles)
}

// Native-architecture validity: RISC Zero (candidate 2) may present NO aarch64
// (arch == 2) proof cell — a fabricated RISC-Zero-ARM cell is refused here.
fn native_arch_valid(candidate: u16, ev: &harness::Evidence) -> bool {
    if candidate != 2 {
        return true;
    }
    for e in &ev.envelopes {
        if let Ok(env) = closure::decode_env(e) {
            if env.arch == 2 {
                return false;
            }
        }
    }
    true
}

fn clone_ev(ev: &harness::Evidence) -> harness::Evidence {
    harness::Evidence {
        samples: ev.samples.clone(),
        rss: ev.rss.clone(),
        envelopes: ev.envelopes.clone(),
        provenances: ev.provenances.clone(),
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
        assert!(native_arch_valid(*candidate, ev), "native-arch validity");
        let rs = closure::decode_result_set(&ev.result_set).expect("result set decodes");
        assert_eq!(rs.b0_pre_spec_hash, spec, "binds merged spec hash");
        assert_eq!(rs.r0_guest_set_hash, gs, "binds recomputed guest-set hash");
        match candidate {
            1 => {
                saw_sp1 = true;
                let r = harness::verify_evidence(ev).expect("SP1 complete matrix verifies");
                assert!(r.qualification, "SP1 qualifies");
            }
            2 => {
                saw_risc0 = true;
                let e = harness::verify_evidence(ev).expect_err("RISC0 x86-only disqualified");
                assert!(
                    e.contains("MeasuredProofGrid")
                        || e.to_lowercase().contains("grid")
                        || e.contains("complete"),
                    "RISC0 incomplete native matrix; got: {e}"
                );
            }
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
    // sanity: the pristine SP1 bundle verifies.
    assert!(harness::verify_evidence(sp1).is_ok());

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

    // fabricated RISC Zero ARM: inject an aarch64 envelope into the RISC0 bundle.
    let mut m = clone_ev(risc0);
    // Reuse the SP1 aarch64 envelope bytes as a foreign aarch64 cell; native check
    // must reject it regardless of downstream verification.
    let aarch64_env = sp1
        .envelopes
        .iter()
        .find(|e| closure::decode_env(e).map(|d| d.arch == 2).unwrap_or(false))
        .expect("sp1 has an aarch64 envelope")
        .clone();
    m.envelopes.push(aarch64_env);
    assert!(
        !native_arch_valid(2, &m),
        "fabricated RISC-Zero-ARM cell rejected"
    );
}
