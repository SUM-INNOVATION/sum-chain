//! `b0-pre-malformed-corpus` — GENERATE the retained `MalformedCorpusReportV1`.
//!
//! A FIXED, ORDERED corpus of malformed guest inputs is run through the REAL guest boundary
//! (`b0_pre_guest_core::run`, the candidate-neutral statement decode+verify). Each member MUST refuse,
//! with the exact stable class DECLARED for it — an explicit protocol code, never Display text:
//!   * `decode:<v>`   — the frozen `DecodeError` variant discriminant (0..=11);
//!   * `semantic:<c>` — the stable code from the frozen `SEMANTIC_REASONS` reason→code table
//!                      (a member producing an UNMAPPED `&'static str` reason fails closed).
//!
//! A member that is accepted (`unexpectedly accepted`) or refuses with a different class than declared
//! (`wrong-error-class`) fails generation. The report retains the exact ordered member bytes
//! (BLAKE3-indexed) and is SHA-256 domain-addressed; both verifiers re-decode + recompute it.
//!
//! Usage:
//!   b0-pre-malformed-corpus --official <official.json> --spec-hash <64hex> \
//!     --measured-source-commit <40hex> --tooling-commit <40hex> --tooling-pathset-blake3 <64hex> \
//!     [--out <report.json>]
//!   b0-pre-malformed-corpus --official <official.json> --print-classes   # bootstrap: name -> class

use std::process::ExitCode;

use b0_pre_guest_core::{run, GuestError, GuestInput};
use sumchain_wire::b0::codec::DecodeError;

const REPORT_SCHEMA: &str = "b0-final-malformed-corpus-report/v1";
const CORPUS_DOMAIN: &str = "b0-final-malformed-corpus/v1";

/// The FROZEN, APPEND-ONLY canonical reason→code table: `code = index`. NEVER reorder (a member record
/// binds the code; reordering would silently remap). Adding a new guest reason APPENDS here (and bumps
/// `SEMANTIC_REASON_COUNT` in both verifiers). Sorted at v1 for reviewability.
const SEMANTIC_REASONS: &[&str] = &[
    "derived input",
    "empty prefix",
    "eos flag",
    "exec",
    "final residual",
    "frozen bounds",
    "frozen dims",
    "im decode",
    "input manifest commitment",
    "input manifest decode",
    "input manifest slots",
    "kv shape",
    "max_state_bytes",
    "missing input_manifest",
    "missing model",
    "missing prior_kv",
    "missing residual",
    "missing token_prefix",
    "model",
    "model commitment",
    "model decode",
    "model id",
    "output manifest",
    "output manifest must be empty",
    "position/length",
    "prior kv",
    "prior kv must be empty",
    "prior residual",
    "residual shape",
    "select sentinels",
    "selected out of range",
    "selection",
    "sequence overflow",
    "tlg sentinels",
    "token count",
    "token prefix",
    "tokenizer id",
    "unexpected prior_kv",
    "unit sentinels",
    "updated token seq",
];

/// Stable `DecodeError` variant discriminant (0..=11), frozen order (mirrors the reference codec).
fn decode_variant(e: &DecodeError) -> u16 {
    match e {
        DecodeError::Truncated { .. } => 0,
        DecodeError::TrailingBytes { .. } => 1,
        DecodeError::BadTag { .. } => 2,
        DecodeError::BadEnum { .. } => 3,
        DecodeError::ReservedEnum { .. } => 4,
        DecodeError::BadFixedScalar { .. } => 5,
        DecodeError::CountExceedsMax { .. } => 6,
        DecodeError::LengthExceedsMax { .. } => 7,
        DecodeError::NonCanonicalOrder { .. } => 8,
        DecodeError::DuplicateEntry { .. } => 9,
        DecodeError::Inconsistent { .. } => 10,
        DecodeError::BadValue { .. } => 11,
    }
}

/// The canonical mapping layer: a frozen semantic reason (prose `&'static str`) → its stable code.
/// FAILS on an unknown reason so a new/renamed guest reason can never silently enter a report.
fn semantic_code(reason: &str) -> Result<u16, String> {
    SEMANTIC_REASONS
        .iter()
        .position(|r| *r == reason)
        .map(|i| i as u16)
        .ok_or_else(|| {
            format!("unmapped guest semantic reason {reason:?} (add it to SEMANTIC_REASONS)")
        })
}

/// Classify a `GuestError` into its stable protocol class `(kind, code)`.
fn classify(e: &GuestError) -> Result<(&'static str, u16), String> {
    match e {
        GuestError::Decode(d) => Ok(("decode", decode_variant(d))),
        GuestError::Semantic(r) => Ok(("semantic", semantic_code(r)?)),
    }
}

// ------------------------------- corpus construction ---------------------------------------------

fn hexbytes(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}
fn field(v: &serde_json::Value, case: &str, key: &str) -> Vec<u8> {
    hexbytes(v[case][key].as_str().expect("official workload field"))
}
fn tlg_input(v: &serde_json::Value) -> GuestInput {
    GuestInput {
        statement: field(v, "tlg", "statement_template"),
        model: Some(field(v, "tlg", "model")),
        residual: Some(field(v, "tlg", "prior_residual")),
        prior_kv: Some(field(v, "tlg", "prior_kv")),
        token_prefix: Some(field(v, "tlg", "token_prefix")),
        input_manifest: Some(field(v, "tlg", "input_manifest")),
    }
}
fn select_input(v: &serde_json::Value) -> GuestInput {
    GuestInput {
        statement: field(v, "select", "statement_template"),
        model: Some(field(v, "select", "model")),
        residual: Some(field(v, "select", "final_residual")),
        prior_kv: None,
        token_prefix: Some(field(v, "select", "token_prefix")),
        input_manifest: Some(field(v, "select", "input_manifest")),
    }
}

struct Member {
    name: String,
    statement_kind: &'static str,
    bytes: Vec<u8>,
}

/// Push one GuestInput-mutation member: clone/build `g`, apply `f`, encode → member bytes.
fn add(
    out: &mut Vec<Member>,
    name: &str,
    kind: &'static str,
    mut g: GuestInput,
    f: impl Fn(&mut GuestInput),
) {
    f(&mut g);
    out.push(Member {
        name: name.to_string(),
        statement_kind: kind,
        bytes: g.encode(),
    });
}

/// The FIXED, ORDERED corpus. Order is frozen (it is bound into the report address); adding members
/// APPENDS at the end. Each member is exercised through `guest_core::run`.
fn build_corpus(v: &serde_json::Value) -> Vec<Member> {
    let mut out: Vec<Member> = Vec::new();
    // ---- TLG witness/field mutations ----
    add(
        &mut out,
        "tlg_model_tensor_byte",
        "tlg",
        tlg_input(v),
        |g| g.model.as_mut().unwrap()[500] ^= 1,
    );
    add(&mut out, "tlg_model_magic", "tlg", tlg_input(v), |g| {
        g.model.as_mut().unwrap()[0] ^= 1
    });
    add(&mut out, "tlg_residual_byte", "tlg", tlg_input(v), |g| {
        g.residual.as_mut().unwrap()[0] ^= 1
    });
    add(&mut out, "tlg_prior_kv_byte", "tlg", tlg_input(v), |g| {
        g.prior_kv.as_mut().unwrap()[0] ^= 1
    });
    add(&mut out, "tlg_token_byte", "tlg", tlg_input(v), |g| {
        g.token_prefix.as_mut().unwrap()[0] ^= 1
    });
    add(
        &mut out,
        "tlg_input_manifest_byte",
        "tlg",
        tlg_input(v),
        |g| g.input_manifest.as_mut().unwrap()[40] ^= 1,
    );
    add(
        &mut out,
        "tlg_trailing_witness_byte",
        "tlg",
        tlg_input(v),
        |g| g.model.as_mut().unwrap().push(0),
    );
    add(&mut out, "tlg_drop_model", "tlg", tlg_input(v), |g| {
        g.model = None
    });
    add(&mut out, "tlg_drop_prior_kv", "tlg", tlg_input(v), |g| {
        g.prior_kv = None
    });
    add(
        &mut out,
        "tlg_drop_token_prefix",
        "tlg",
        tlg_input(v),
        |g| g.token_prefix = None,
    );
    add(
        &mut out,
        "tlg_drop_input_manifest",
        "tlg",
        tlg_input(v),
        |g| g.input_manifest = None,
    );
    for off in [2usize, 100, 400, 900] {
        add(
            &mut out,
            &format!("tlg_statement_byte_{off}"),
            "tlg",
            tlg_input(v),
            move |g| g.statement[off] ^= 1,
        );
    }
    // ---- SelectToken mutations ----
    add(
        &mut out,
        "select_model_byte",
        "select",
        select_input(v),
        |g| g.model.as_mut().unwrap()[500] ^= 1,
    );
    add(
        &mut out,
        "select_final_residual_byte",
        "select",
        select_input(v),
        |g| g.residual.as_mut().unwrap()[0] ^= 1,
    );
    add(
        &mut out,
        "select_token_byte",
        "select",
        select_input(v),
        |g| g.token_prefix.as_mut().unwrap()[0] ^= 1,
    );
    add(
        &mut out,
        "select_input_manifest_byte",
        "select",
        select_input(v),
        |g| g.input_manifest.as_mut().unwrap()[40] ^= 1,
    );
    add(
        &mut out,
        "select_unexpected_prior_kv",
        "select",
        select_input(v),
        |g| g.prior_kv = Some(vec![0u8; 32]),
    );
    add(
        &mut out,
        "select_drop_model",
        "select",
        select_input(v),
        |g| g.model = None,
    );
    add(
        &mut out,
        "select_drop_residual",
        "select",
        select_input(v),
        |g| g.residual = None,
    );
    for off in [2usize, 100, 400, 900] {
        add(
            &mut out,
            &format!("select_statement_byte_{off}"),
            "select",
            select_input(v),
            move |g| g.statement[off] ^= 1,
        );
    }
    // ---- wrong statement kind (swapped witnesses) ----
    let tlg_stmt = field(v, "tlg", "statement_template");
    let sel_stmt = field(v, "select", "statement_template");
    add(
        &mut out,
        "cross_tlg_statement_select_witnesses",
        "select",
        select_input(v),
        move |g| g.statement = tlg_stmt.clone(),
    );
    add(
        &mut out,
        "cross_select_statement_tlg_witnesses",
        "tlg",
        tlg_input(v),
        move |g| g.statement = sel_stmt.clone(),
    );
    // ---- envelope-byte corruptions (operate on the ENCODED bytes) ----
    let enc = tlg_input(v).encode();
    let mut bad_tag = enc.clone();
    bad_tag[0] ^= 0xFF;
    out.push(Member {
        name: "envelope_bad_tag".into(),
        statement_kind: "tlg",
        bytes: bad_tag,
    });
    let mut trailing = enc.clone();
    trailing.push(0);
    out.push(Member {
        name: "envelope_trailing_byte".into(),
        statement_kind: "tlg",
        bytes: trailing,
    });
    out.push(Member {
        name: "envelope_truncated".into(),
        statement_kind: "tlg",
        bytes: enc[..enc.len() - 3].to_vec(),
    });
    out.push(Member {
        name: "envelope_empty".into(),
        statement_kind: "tlg",
        bytes: Vec::new(),
    });
    out
}

// ------------------------------- report emission -------------------------------------------------

fn to_hex(b: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        let _ = write!(s, "{x:02x}");
    }
    s
}
fn arg(args: &[String], flag: &str) -> Option<String> {
    args.iter()
        .position(|a| a == flag)
        .and_then(|i| args.get(i + 1).cloned())
}
fn is_hex_of(s: &str, n: usize) -> bool {
    s.len() == n
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

struct Classified {
    name: String,
    statement_kind: &'static str,
    kind: &'static str,
    code: u16,
    bytes: Vec<u8>,
}

/// The COMMITTED, frozen expected class per corpus member (name → kind:code), captured from the guest
/// boundary and reviewed. Generation REQUIRES the observed class to equal this — a divergence surfaces
/// a guest refusal-behaviour drift (`wrong-error-class`). Order mirrors the corpus; both are frozen.
const EXPECTED: &[(&str, &str, u16)] = &[
    ("tlg_model_tensor_byte", "semantic", 19),
    ("tlg_model_magic", "semantic", 20),
    ("tlg_residual_byte", "semantic", 27),
    ("tlg_prior_kv_byte", "semantic", 25),
    ("tlg_token_byte", "semantic", 35),
    ("tlg_input_manifest_byte", "semantic", 8),
    ("tlg_trailing_witness_byte", "semantic", 20),
    ("tlg_drop_model", "semantic", 14),
    ("tlg_drop_prior_kv", "semantic", 15),
    ("tlg_drop_token_prefix", "semantic", 17),
    ("tlg_drop_input_manifest", "semantic", 13),
    ("tlg_statement_byte_2", "decode", 2),
    ("tlg_statement_byte_100", "semantic", 0),
    ("tlg_statement_byte_400", "decode", 2),
    ("tlg_statement_byte_900", "decode", 2),
    ("select_model_byte", "semantic", 18),
    ("select_final_residual_byte", "semantic", 4),
    ("select_token_byte", "semantic", 35),
    ("select_input_manifest_byte", "semantic", 8),
    ("select_unexpected_prior_kv", "semantic", 37),
    ("select_drop_model", "semantic", 14),
    ("select_drop_residual", "semantic", 16),
    ("select_statement_byte_2", "decode", 2),
    ("select_statement_byte_100", "semantic", 0),
    ("select_statement_byte_400", "decode", 2),
    ("select_statement_byte_900", "decode", 2),
    ("cross_tlg_statement_select_witnesses", "semantic", 15),
    ("cross_select_statement_tlg_witnesses", "semantic", 37),
    ("envelope_bad_tag", "decode", 2),
    ("envelope_trailing_byte", "decode", 1),
    ("envelope_truncated", "decode", 0),
    ("envelope_empty", "decode", 0),
];
fn expected_of(name: &str) -> Result<(&'static str, u16), String> {
    EXPECTED
        .iter()
        .find(|(n, _, _)| *n == name)
        .map(|(_, k, c)| (*k, *c))
        .ok_or_else(|| format!("corpus member {name:?} has no committed EXPECTED class"))
}

fn run_main() -> Result<String, String> {
    let args: Vec<String> = std::env::args().collect();
    let official_path = arg(&args, "--official").ok_or("--official <official.json> required")?;
    let official =
        std::fs::read_to_string(&official_path).map_err(|e| format!("read official: {e}"))?;
    let v: serde_json::Value =
        serde_json::from_str(&official).map_err(|e| format!("parse official: {e}"))?;
    let corpus = build_corpus(&v);

    // Exercise every member through the REAL guest boundary; each MUST refuse with a mappable class.
    let mut classified: Vec<Classified> = Vec::new();
    for m in &corpus {
        match run(&m.bytes) {
            Ok(_) => {
                return Err(format!(
                    "corpus member {} was ACCEPTED (unexpectedly accepted)",
                    m.name
                ))
            }
            Err(e) => {
                let (kind, code) = classify(&e)?;
                classified.push(Classified {
                    name: m.name.clone(),
                    statement_kind: m.statement_kind,
                    kind,
                    code,
                    bytes: m.bytes.clone(),
                });
            }
        }
    }

    if args.iter().any(|a| a == "--print-classes") {
        let mut s = String::new();
        for c in &classified {
            s.push_str(&format!("{} {}:{}\n", c.name, c.kind, c.code));
        }
        return Ok(s);
    }

    // Regression guard: the observed class MUST equal the frozen committed expected class.
    for c in &classified {
        let (ek, ec) = expected_of(&c.name)?;
        if c.kind != ek || c.code != ec {
            return Err(format!(
                "wrong-error-class: {} expected {ek}:{ec} got {}:{}",
                c.name, c.kind, c.code
            ));
        }
    }

    let spec = arg(&args, "--spec-hash").ok_or("--spec-hash required")?;
    let measured =
        arg(&args, "--measured-source-commit").ok_or("--measured-source-commit required")?;
    let tooling = arg(&args, "--tooling-commit").ok_or("--tooling-commit required")?;
    let pathset =
        arg(&args, "--tooling-pathset-blake3").ok_or("--tooling-pathset-blake3 required")?;
    for (nm, val, n) in [
        ("spec", &spec, 64),
        ("measured", &measured, 40),
        ("tooling", &tooling, 40),
        ("pathset", &pathset, 64),
    ] {
        if !is_hex_of(val, n) {
            return Err(format!("{nm} not {n}-hex"));
        }
    }

    // Build the ordered member records + the canonical address preimage.
    let mut members_json = Vec::new();
    let mut parts: Vec<String> = vec![
        REPORT_SCHEMA.into(),
        CORPUS_DOMAIN.into(),
        spec.clone(),
        measured.clone(),
        tooling.clone(),
        pathset.clone(),
        classified.len().to_string(),
    ];
    for (i, c) in classified.iter().enumerate() {
        let bl = to_hex(blake3::hash(&c.bytes).as_bytes());
        parts.push(i.to_string());
        parts.push(c.statement_kind.to_string());
        parts.push(bl.clone());
        parts.push(c.bytes.len().to_string());
        parts.push(format!("{}:{}", c.kind, c.code)); // expected (committed) == actual (observed)
        parts.push(format!("{}:{}", c.kind, c.code));
        members_json.push(serde_json::json!({
            "index": i,
            "statement_kind": c.statement_kind,
            "name": c.name,
            "member_bytes_hex": to_hex(&c.bytes),
            "member_blake3": bl,
            "member_len": c.bytes.len(),
            "expected_class": {"kind": c.kind, "code": c.code},
            "actual_class": {"kind": c.kind, "code": c.code},
        }));
    }
    let address = to_hex(&sha256(parts.join("\0").as_bytes()));
    let report = serde_json::json!({
        "schema": REPORT_SCHEMA,
        "corpus_domain": CORPUS_DOMAIN,
        "b0_pre_spec_hash": spec,
        "measured_source_commit": measured,
        "tooling_commit": tooling,
        "tooling_pathset_blake3": pathset,
        "member_count": classified.len(),
        "members": members_json,
        "address": address,
    });
    let out = serde_json::to_string_pretty(&report).map_err(|e| e.to_string())?;
    if let Some(path) = arg(&args, "--out") {
        std::fs::write(&path, &out).map_err(|e| format!("write {path}: {e}"))?;
    }
    Ok(out)
}

fn main() -> ExitCode {
    match run_main() {
        Ok(out) => {
            println!("{out}");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("MALFORMED-CORPUS-REFUSED: {e}");
            ExitCode::FAILURE
        }
    }
}

// ---- own SHA-256 (FIPS 180-4), matching the validator + independent recompute -------------------
const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];
const H0: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];
fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h = H0;
    let bit_len = (data.len() as u64).wrapping_mul(8);
    let mut msg = data.to_vec();
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());
    for block in msg.chunks_exact(64) {
        let mut w = [0u32; 64];
        for (i, word) in w.iter_mut().enumerate().take(16) {
            let b = i * 4;
            *word = u32::from_be_bytes([block[b], block[b + 1], block[b + 2], block[b + 3]]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh] = h;
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let t1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        for (dst, val) in h.iter_mut().zip([a, b, c, d, e, f, g, hh]) {
            *dst = dst.wrapping_add(val);
        }
    }
    let mut out = [0u8; 32];
    for (i, word) in h.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    out
}
