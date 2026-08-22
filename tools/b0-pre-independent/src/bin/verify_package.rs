//! Independent B0-FINAL package verifier (reviewer correction #7).
//!
//! Parses an ACTUAL produced `real-orchestrator-vector.bin` FROM SCRATCH — no dependency on
//! the reference validator — and prints the derived `r0_guest_set_hash` + per-candidate
//! verdicts. The runbook invokes this on `$OUT/package/real-orchestrator-vector.bin`, so the
//! produced package (not merely a committed fixture) is independently re-verified.

use std::process::ExitCode;

use b0_pre_independent::{closure, harness};

struct Rd<'a> {
    b: &'a [u8],
    p: usize,
}
impl<'a> Rd<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], String> {
        if self.p + n > self.b.len() {
            return Err("truncated vector".into());
        }
        let s = &self.b[self.p..self.p + n];
        self.p += n;
        Ok(s)
    }
    fn u32(&mut self) -> Result<usize, String> {
        let b = self.take(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]) as usize)
    }
    fn blob(&mut self) -> Result<Vec<u8>, String> {
        let n = self.u32()?;
        Ok(self.take(n)?.to_vec())
    }
}

type ParsedVector = (
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<(u16, harness::Evidence)>,
);

fn parse(bytes: &[u8]) -> Result<ParsedVector, String> {
    let mut r = Rd { b: bytes, p: 0 };
    if r.take(13)? != b"B0PREMEASVEC6" {
        return Err("bad container magic".into());
    }
    let allowlist = r.blob()?;
    let measurement_input_authority = r.blob()?;
    let malformed_corpus_report = r.blob()?;
    let harness_source_inventory = r.blob()?;
    let n = r.u32()?;
    let mut bundles = Vec::new();
    for _ in 0..n {
        let cb = r.take(2)?;
        let candidate = u16::from_be_bytes([cb[0], cb[1]]);
        let mut lists: Vec<Vec<Vec<u8>>> = Vec::with_capacity(12);
        for _ in 0..12 {
            let count = r.u32()?;
            let mut v = Vec::with_capacity(count);
            for _ in 0..count {
                v.push(r.blob()?);
            }
            lists.push(v);
        }
        let verifier_material = r.blob()?;
        let result_set = r.blob()?;
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
                verifier_material,
                result_set,
            },
        ));
    }
    if r.p != bytes.len() {
        return Err("trailing bytes after the vector".into());
    }
    Ok((
        allowlist,
        measurement_input_authority,
        malformed_corpus_report,
        harness_source_inventory,
        bundles,
    ))
}

fn hx(b: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        let _ = write!(s, "{x:02x}");
    }
    s
}

fn run() -> Result<String, String> {
    let path = std::env::args()
        .nth(1)
        .ok_or("usage: b0-pre-independent-verify <real-orchestrator-vector.bin>")?;
    let bytes = std::fs::read(&path).map_err(|e| format!("read {path}: {e}"))?;
    let (allowlist, mia_bytes, report_bytes, inventory_bytes, bundles) = parse(&bytes)?;
    // Independent import of the retained VEC6 measurement-input authority: the three retained blobs
    // (MIA JSON + malformed-corpus report + harness-source inventory manifest) are MANDATORY — a real
    // official package always seals them, so a vector missing any of them is refused (never skipped).
    // Re-decode + recompute the authority address (own SHA-256) and require it to bind the independently
    // recomputed harness-source inventory address (own BLAKE3) + malformed-corpus report address (own
    // SHA-256, full from-scratch report verification).
    const MEASURED: &str = "507281e21e95a6a98e3480e25e12d1baab586e07";
    const SPEC: &str = "201cfcb80e94a5a7845dc3380cde32171d40f325ae2bacde9547f3c0da3c4df3";
    if mia_bytes.is_empty() || report_bytes.is_empty() || inventory_bytes.is_empty() {
        return Err(
            "measurement-input authority incomplete: the MIA / malformed-corpus report / harness-source \
             inventory retained bytes are all mandatory in an official package"
                .into(),
        );
    }
    let authority: ([u8; 32], [u8; 32]) = {
        let mia =
            b0_pre_independent::measurement_input_authority::MeasurementInputAuthority::from_json(
                &mia_bytes,
            )?;
        let mia_addr = mia.verify(MEASURED, SPEC)?;
        mia.verify_binds(&inventory_bytes, &report_bytes, MEASURED, SPEC)?;
        let mut report_addr = [0u8; 32];
        for (i, b) in report_addr.iter_mut().enumerate() {
            *b = u8::from_str_radix(&mia.malformed_corpus_report_address[i * 2..i * 2 + 2], 16)
                .map_err(|_| "MIA report address not hex")?;
        }
        (mia_addr, report_addr)
    };
    closure::decode_allowlist(&allowlist).map_err(|e| format!("allowlist decode: {e:?}"))?;
    let gs = closure::Allowlist::guest_set_hash(&allowlist);
    if bundles.is_empty() {
        return Err("no candidate bundles in the vector".into());
    }
    let mut verdicts = Vec::new();
    for (candidate, ev) in &bundles {
        let rs = closure::decode_result_set(&ev.result_set)
            .map_err(|e| format!("candidate {candidate}: result set decode: {e:?}"))?;
        if rs.r0_guest_set_hash != gs {
            return Err(format!(
                "candidate {candidate}: result-set guest-set hash != the recomputed allowlist guest-set hash"
            ));
        }
        // Every fragment is bound to the ONE package authority: the result-set's malformed hash IS the
        // report address, and every runner attestation binds the authority's own address.
        let (mia_addr, report_addr) = authority;
        if rs.malformed_corpus_result_hash != report_addr {
            return Err(format!(
                "candidate {candidate}: result-set malformed_corpus_result_hash != authority report address"
            ));
        }
        for ab in &ev.runner_attestations {
            let att = closure::decode_runner_attestation(ab)
                .map_err(|e| format!("candidate {candidate}: attestation decode: {e:?}"))?;
            if att.measurement_input_authority_address != mia_addr {
                return Err(format!(
                    "candidate {candidate}: runner attestation does not bind the package measurement-input authority"
                ));
            }
        }
        let verdict = match harness::verify_evidence(ev) {
            Ok(v) if v.qualification => "qualified".to_string(),
            Ok(v) => format!("disqualified_by_gate:{:?}", v.failure_codes),
            Err(e) => format!("incomplete_or_rejected:{e}"),
        };
        verdicts.push(format!(
            "{{\"candidate\":{candidate},\"verdict\":\"{verdict}\"}}"
        ));
    }
    Ok(format!(
        "{{\"r0_guest_set_hash\":\"{}\",\"candidates\":[{}]}}",
        hx(&gs),
        verdicts.join(",")
    ))
}

fn main() -> ExitCode {
    match run() {
        Ok(s) => {
            println!("{s}");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("REJECTED: {e}");
            ExitCode::FAILURE
        }
    }
}
