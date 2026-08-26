//! Emit the two canonical guest-input blobs for the official B0-PRE workload.
//!
//! Reads the frozen `docs/b0-pre/fixtures/workload/official.json`, packs each of
//! the two official statements (TransformerLayerGroup, SelectToken) plus its
//! witnesses into the guest-input envelope, and writes:
//!   <out_dir>/tlg.guestin.bin
//!   <out_dir>/select.guestin.bin
//!
//! These are DETERMINISTIC INPUT bytes only — never a proof. The venue passes one
//! as `PROVER_GUEST_INPUT` to `prove_fixture.sh` so the official guest has the
//! statement+witnesses to prove. The blobs carry no proof, receipt, program id,
//! or measured value.
//!
//! ## Two lifecycle modes
//!
//! * **PREREGISTRATION** (default): packs each ZERO-HASH statement TEMPLATE
//!   (`b0_pre_spec_hash` all zero). Valid only before the spec hash exists.
//!
//! * **MEASUREMENT** (`--measurement <spec_hash_hex>`): packs the MATERIALIZED
//!   final statement — the spec hash written into bytes `[34,66)` via the frozen
//!   `sumchain_wire::b0::statement::materialize_final` path (no re-implementation).
//!   It fail-closed REFUSES to write anything unless, for BOTH statements:
//!     - the supplied spec hash equals the merged, ratified `b0_pre_spec_hash`;
//!     - the template is 996 bytes with a zeroed spec-hash range (never a
//!       pre-materialized / non-template statement);
//!     - the template hash equals the frozen official value (guards an altered
//!       witness / wrong template);
//!     - the materialized statement carries the (non-zero) spec hash in `[34,66)`;
//!     - the materialized `computation_statement_hash` equals the frozen required
//!       value; and
//!     - the guest core ACCEPTS the input and its journal EQUALS that
//!       `computation_statement_hash` (guards an altered witness / journal drift).
//!
//! Usage:
//!   emit_official_guest_input <official.json> <out_dir>
//!   emit_official_guest_input --measurement <spec_hash_hex> <official.json> <out_dir>

use std::fs;
use std::path::Path;

use b0_pre_guest_core::{run, GuestInput};
use sumchain_wire::b0::statement::{self, R0ComputationStatementV2};

// ---- Frozen, merged B0-PRE identities bound into the measurement-mode blobs ----
// The real, merged `b0_pre_spec_hash` (commit 8ac6dc77; sidecar
// docs/b0-pre/protocol/b0-pre-protocol-v1.json.hash).
const MERGED_SPEC_HASH_HEX: &str =
    "e933e7325c2639a48d8e25f20746d0f8abc822dee9fcfa87c2e6cdec226cf2a2";
// Frozen official statement template hashes (== the committed normative artifact).
const TLG_TEMPLATE_HASH_HEX: &str =
    "7301ee63f420bcb5b50c7be7802e6e242e068978c8200671569777ed212f9969";
const SELECT_TEMPLATE_HASH_HEX: &str =
    "a31799c2f5740173a6088979e30d85c60eefeb2b4a15b0913cf5d2568768c72a";
// Required materialized computation-statement hashes (spec hash inserted; recomputed for e933e732).
const TLG_REQUIRED_CSH_HEX: &str =
    "cd27d48ce81a0211539ac7685fa9548457779ccf769e5731d92bdf706635de86";
const SELECT_REQUIRED_CSH_HEX: &str =
    "26574240d194c1d4a28505559c51e5381e057ee4c559edd53abea8c257db0749";

fn refuse(msg: &str) -> ! {
    eprintln!("REFUSED: {msg}");
    std::process::exit(1);
}

fn hexbytes(s: &str) -> Vec<u8> {
    if s.len() % 2 != 0 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        refuse(&format!("malformed hex string ({} chars)", s.len()));
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
        .collect()
}
fn hx(b: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        let _ = write!(s, "{x:02x}");
    }
    s
}
fn field(v: &serde_json::Value, case: &str, key: &str) -> Vec<u8> {
    hexbytes(
        v[case][key]
            .as_str()
            .unwrap_or_else(|| refuse(&format!("{case}.{key} missing"))),
    )
}

/// One statement's spec + witness selection.
struct Spec<'a> {
    case: &'a str,
    template_hash_hex: &'a str,
    required_csh_hex: &'a str,
}

/// Build the GuestInput `statement` bytes for `case`.
///
/// Preregistration: the zeroed template verbatim. Measurement: the materialized
/// final statement, fail-closed against every frozen identity.
fn statement_bytes(v: &serde_json::Value, sp: &Spec, spec_hash: Option<&[u8; 32]>) -> Vec<u8> {
    let template = field(v, sp.case, "statement_template");
    if template.len() != R0ComputationStatementV2::LEN {
        refuse(&format!(
            "{}.statement_template is {} bytes, not {}",
            sp.case,
            template.len(),
            R0ComputationStatementV2::LEN
        ));
    }
    match spec_hash {
        None => template, // PREREGISTRATION: zeroed template verbatim.
        Some(spec) => {
            // MEASUREMENT: fail-closed materialization.
            let range = R0ComputationStatementV2::SPEC_HASH_RANGE;
            if !template[range.clone()].iter().all(|&b| b == 0) {
                refuse(&format!(
                    "{}: measurement mode requires a ZEROED statement template",
                    sp.case
                ));
            }
            if hx(&statement::template_hash(&template)) != sp.template_hash_hex {
                refuse(&format!(
                    "{}: template hash != frozen official value {}",
                    sp.case, sp.template_hash_hex
                ));
            }
            if spec.iter().all(|&b| b == 0) {
                refuse("measurement mode refuses a zero spec hash");
            }
            let final_stmt = statement::materialize_final(&template, spec)
                .unwrap_or_else(|_| refuse(&format!("{}: materialize_final failed", sp.case)));
            if final_stmt[range] != spec[..] {
                refuse(&format!(
                    "{}: materialized statement lost the spec hash",
                    sp.case
                ));
            }
            let csh = R0ComputationStatementV2::computation_statement_hash(&final_stmt);
            if hx(&csh) != sp.required_csh_hex {
                refuse(&format!(
                    "{}: materialized computation_statement_hash {} != frozen required {}",
                    sp.case,
                    hx(&csh),
                    sp.required_csh_hex
                ));
            }
            final_stmt
        }
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();

    // Parse mode.
    let (spec_hash, official, out_dir): (Option<[u8; 32]>, &str, &str) = match args
        .get(1)
        .map(String::as_str)
    {
        Some("--measurement") => {
            let spec_hex = args.get(2).unwrap_or_else(|| {
                    refuse("usage: emit_official_guest_input --measurement <spec_hash_hex> <official.json> <out_dir>")
                });
            if spec_hex != MERGED_SPEC_HASH_HEX {
                refuse(&format!(
                        "measurement mode: spec hash {spec_hex} != merged b0_pre_spec_hash {MERGED_SPEC_HASH_HEX}"
                    ));
            }
            let b = hexbytes(spec_hex);
            let mut arr = [0u8; 32];
            if b.len() != 32 {
                refuse("spec hash must be 32 bytes (64 hex)");
            }
            arr.copy_from_slice(&b);
            let official = args
                .get(3)
                .unwrap_or_else(|| refuse("missing <official.json>"));
            let out_dir = args.get(4).unwrap_or_else(|| refuse("missing <out_dir>"));
            (Some(arr), official.as_str(), out_dir.as_str())
        }
        _ => {
            let official = args
                    .get(1)
                    .unwrap_or_else(|| refuse("usage: emit_official_guest_input [--measurement <spec_hash_hex>] <official.json> <out_dir>"));
            let out_dir = args.get(2).unwrap_or_else(|| refuse("missing <out_dir>"));
            (None, official.as_str(), out_dir.as_str())
        }
    };

    let raw = fs::read_to_string(official)
        .unwrap_or_else(|e| refuse(&format!("read official.json: {e}")));
    let v: serde_json::Value =
        serde_json::from_str(&raw).unwrap_or_else(|e| refuse(&format!("parse official.json: {e}")));

    let tlg_spec = Spec {
        case: "tlg",
        template_hash_hex: TLG_TEMPLATE_HASH_HEX,
        required_csh_hex: TLG_REQUIRED_CSH_HEX,
    };
    let select_spec = Spec {
        case: "select",
        template_hash_hex: SELECT_TEMPLATE_HASH_HEX,
        required_csh_hex: SELECT_REQUIRED_CSH_HEX,
    };

    let tlg = GuestInput {
        statement: statement_bytes(&v, &tlg_spec, spec_hash.as_ref()),
        model: Some(field(&v, "tlg", "model")),
        residual: Some(field(&v, "tlg", "prior_residual")),
        prior_kv: Some(field(&v, "tlg", "prior_kv")),
        token_prefix: Some(field(&v, "tlg", "token_prefix")),
        input_manifest: Some(field(&v, "tlg", "input_manifest")),
    };
    let select = GuestInput {
        statement: statement_bytes(&v, &select_spec, spec_hash.as_ref()),
        model: Some(field(&v, "select", "model")),
        residual: Some(field(&v, "select", "final_residual")),
        prior_kv: None,
        token_prefix: Some(field(&v, "select", "token_prefix")),
        input_manifest: Some(field(&v, "select", "input_manifest")),
    };

    // Self-check: the guest core must ACCEPT each emitted blob before we write it,
    // so a malformed input (or an altered witness) can never reach the prover.
    let tlg_bytes = tlg.encode();
    let sel_bytes = select.encode();
    let tlg_j = run(&tlg_bytes)
        .unwrap_or_else(|e| refuse(&format!("guest core rejected TLG input: {e:?}")));
    let sel_j = run(&sel_bytes)
        .unwrap_or_else(|e| refuse(&format!("guest core rejected SelectToken input: {e:?}")));

    // In measurement mode the journal MUST equal the frozen required
    // computation_statement_hash (guards an altered witness / journal drift).
    if spec_hash.is_some() {
        if hx(&tlg_j) != TLG_REQUIRED_CSH_HEX {
            refuse(&format!(
                "TLG journal {} != required {TLG_REQUIRED_CSH_HEX}",
                hx(&tlg_j)
            ));
        }
        if hx(&sel_j) != SELECT_REQUIRED_CSH_HEX {
            refuse(&format!(
                "SelectToken journal {} != required {SELECT_REQUIRED_CSH_HEX}",
                hx(&sel_j)
            ));
        }
    }

    fs::create_dir_all(out_dir).unwrap_or_else(|e| refuse(&format!("mkdir out_dir: {e}")));
    fs::write(Path::new(out_dir).join("tlg.guestin.bin"), &tlg_bytes)
        .unwrap_or_else(|e| refuse(&format!("write tlg: {e}")));
    fs::write(Path::new(out_dir).join("select.guestin.bin"), &sel_bytes)
        .unwrap_or_else(|e| refuse(&format!("write select: {e}")));

    let mode = if spec_hash.is_some() {
        "MEASUREMENT (materialized)"
    } else {
        "PREREGISTRATION (zeroed template)"
    };
    eprintln!("mode: {mode}");
    eprintln!(
        "tlg.guestin.bin    bytes={} journal={}",
        tlg_bytes.len(),
        hx(&tlg_j)
    );
    eprintln!(
        "select.guestin.bin bytes={} journal={}",
        sel_bytes.len(),
        hx(&sel_j)
    );
    eprintln!("NOTE: input bytes only — no proof/receipt/program-id/measurement.");
}
