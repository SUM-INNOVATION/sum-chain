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

type ParsedVector = (Vec<u8>, Vec<(u16, harness::Evidence)>);

fn parse(bytes: &[u8]) -> Result<ParsedVector, String> {
    let mut r = Rd { b: bytes, p: 0 };
    if r.take(13)? != b"B0PREMEASVEC5" {
        return Err("bad container magic".into());
    }
    let allowlist = r.blob()?;
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
    Ok((allowlist, bundles))
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
    let (allowlist, bundles) = parse(&bytes)?;
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
