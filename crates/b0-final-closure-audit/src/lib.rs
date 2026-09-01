//! Deterministic, non-authoritative audit of the committed B0-FINAL closure record.
//!
//! This crate reads ONLY committed artifacts — the machine-auditable closure record
//! (`docs/b0-final/b0-final-closure.v1.json`), the frozen B0-PRE protocol
//! (`docs/b0-pre/protocol/b0-pre-protocol-v1.json`), and the official-evidence manifest
//! (`docs/b0-final/b0-final-official-evidence-manifest.v1.json`). It runs no proofs, reads
//! no venue, and changes NO ratified measurement authority (it lives in the main workspace,
//! entirely outside the B0-PRE measurement-tooling path-set).
//!
//! [`validate`] confirms, from those committed inputs, that:
//!
//! - every INCLUDED constant is mechanically derivable from the frozen protocol / seal;
//! - the mechanical selection is internally consistent and RISC0 is the UNIQUE qualifier under the frozen gates;
//! - the scope-exclusion inventory selects no prohibited parameter and INCLUDED/EXCLUDED are disjoint + cover #123's full list;
//! - the official seal recomputes from the committed manifest members and equals the record's bound seal.
//!
//! Any changed seal / candidate / threshold / constant / evidence digest / prohibited
//! parameter makes [`validate`] return `Err`.

use serde_json::Value;

/// The ratified official deterministic seal (BLAKE3), bound to sum-chain main `9cccaa5e`.
pub const OFFICIAL_SEAL: &str = "60ace32cc2775fd38c3a4b9ea81f49686121cdd25a38db7a5ca5a0f4580bd600";

/// Every constant named in sum-chain #123's body: each must appear either INCLUDED or in an
/// EXCLUDED group (completeness).
pub const ISSUE_123_CONSTANTS: &[&str] = &[
    "proof_system_id",
    "proof_byte_limit",
    "public_input_limit",
    "V_verify_cost",
    "M",
    "max_work_units",
    "max_contributors",
    "max_generations",
    "max_output_tokens",
    "max_cycles",
    "weight_schedule_version",
    "C_layer",
    "C_tok",
    "C_sel",
    "C_emit",
    "S",
    "state_object_max_bytes",
    "manifest_max_slots",
    "B_offer",
    "B_commit",
    "B_check",
    "accept_reimb",
    "commit_verify_reimb",
    "publish_reimb",
    "observe_reimb",
    "check_reimb",
    "settle_reimb",
    "reassign_reimb",
    "K_susp",
    "W_susp",
    "S_susp",
    "N_invite_max",
    "max_reprovisionable_units",
    "max_attempts_per_unit",
    "max_reassignments_per_file",
    "max_retention_files_per_job",
    "max_retention_updates_per_block",
    "max_reverse_index_entries",
    "D_avail",
    "D_ack",
    "D_final",
    "output_availability_blocks",
    "W_deal",
    "W_complaint",
    "W_finalize",
    "L_b",
];

/// Names that must NEVER be frozen as an included (B0) constant. Freezing any of these from
/// a performance measurement is a scope violation.
pub const PROHIBITED_INCLUDED: &[&str] = &[
    "C_layer",
    "C_tok",
    "C_sel",
    "C_emit",
    "B_offer",
    "B_commit",
    "B_check",
    "accept_reimb",
    "settle_reimb",
    "K_susp",
    "W_susp",
    "S_susp",
    "W_deal",
    "W_complaint",
    "W_finalize",
    "L_b",
    "public_input_limit",
    "proof_byte_limit",
    "vk_limit",
    "D_avail",
    "D_ack",
    "D_final",
    "output_availability_blocks",
    "topology_parameters",
    "cryptographic_security_parameters",
    "consensus_safety_parameters",
];

fn err<T>(m: impl Into<String>) -> Result<T, String> {
    Err(m.into())
}

/// Map an included-constant name to the #123-list name it satisfies (for disjointness /
/// completeness), or `None` for a pure derivation helper.
fn issue_name_for(name: &str) -> Option<&'static str> {
    let m: &[(&str, &str)] = &[
        ("proof_system_id", "proof_system_id"),
        ("M_max_accepted_proofs_per_block", "M"),
        ("V_verify_cost_selected_p99_ns", "V_verify_cost"),
        ("max_output_tokens", "max_output_tokens"),
        ("max_cycles", "max_cycles"),
        ("state_object_max_bytes", "state_object_max_bytes"),
        ("max_manifest_slots", "manifest_max_slots"),
        ("S_fixed_point_scale", "S"),
        ("weight_schedule_version", "weight_schedule_version"),
    ];
    m.iter().find(|(k, _)| *k == name).map(|(_, v)| *v)
}

/// Resolve a `protocol:<path>` reference against the frozen protocol JSON.
fn resolve_protocol<'a>(proto: &'a Value, path: &str) -> Result<&'a Value, String> {
    let by_name = |arr: &'a Value, key: &str| -> Result<&'a Value, String> {
        arr.as_array()
            .ok_or_else(|| format!("protocol path not array: {path}"))?
            .iter()
            .find(|e| e.get("name").and_then(Value::as_str) == Some(key))
            .and_then(|e| e.get("value"))
            .ok_or_else(|| format!("protocol name not found: {path}"))
    };
    let segs: Vec<&str> = path.splitn(2, '.').collect();
    match (segs.first().copied(), segs.get(1).copied()) {
        (Some("qualification_gates"), Some(k)) => proto["qualification_gates"]
            .get(k)
            .ok_or_else(|| format!("missing qualification_gates.{k}")),
        (Some("versions"), Some(k)) => by_name(&proto["versions"], k),
        (Some("bounds"), Some(rest)) => {
            let (grp, k) = rest.split_once('.').ok_or("bad bounds path")?;
            by_name(&proto["bounds"][grp], k)
        }
        (Some("official_statements"), Some(k)) => proto["official_statements"]
            .get(k)
            .ok_or_else(|| format!("missing official_statements.{k}")),
        _ => err(format!("unsupported protocol path: {path}")),
    }
}

/// Whether a candidate with measured `p99_ns` qualifies under the frozen gates.
/// gate 3: p99 <= verify_p99_gate_ns. gate 4: p99 * M <= aggregate budget (checked overflow).
pub fn qualifies(p99_ns: u64, gate_p99_ns: u64, m: u64, agg_budget_ns: u64) -> bool {
    if p99_ns > gate_p99_ns {
        return false;
    }
    match p99_ns.checked_mul(m) {
        Some(agg) => agg <= agg_budget_ns,
        None => false,
    }
}

/// Recompute the official seal from the committed manifest members (the exact finalize
/// rule: blake3 over the sorted `"<blake3>  ./<path>\n"` lines).
pub fn seal_from_manifest(manifest: &Value) -> Result<String, String> {
    let members = manifest["members"]
        .as_array()
        .ok_or("manifest.members not array")?;
    let mut lines: Vec<(String, String)> = Vec::with_capacity(members.len());
    for m in members {
        let path = m["path"].as_str().ok_or("member.path missing")?;
        let b3 = m["blake3"].as_str().ok_or("member.blake3 missing")?;
        lines.push((path.to_string(), format!("{b3}  ./{path}\n")));
    }
    lines.sort_by(|a, b| a.0.cmp(&b.0));
    let stream: String = lines.into_iter().map(|(_, l)| l).collect();
    Ok(blake3::hash(stream.as_bytes()).to_hex().to_string())
}

/// Validate the committed closure record against the committed protocol + manifest.
pub fn validate(
    closure_json: &str,
    protocol_json: &str,
    manifest_json: &str,
) -> Result<(), String> {
    let c: Value = serde_json::from_str(closure_json).map_err(|e| format!("closure json: {e}"))?;
    let p: Value =
        serde_json::from_str(protocol_json).map_err(|e| format!("protocol json: {e}"))?;
    let man: Value =
        serde_json::from_str(manifest_json).map_err(|e| format!("manifest json: {e}"))?;

    if c["kind"].as_str() != Some("b0-final-closure-record/v1") {
        return err("wrong closure kind");
    }
    let auth = &c["authority"];

    // (0) authority binds the historical ratified roots (must not drift).
    for (field, want) in [
        (
            "measurement_head",
            "9cccaa5ee6e038fb9dcb45af44ecb3cbdc2f48c6",
        ),
        (
            "tooling_authority_commit",
            "be3a5cb151b42689b31574691ec1641bb1278bbf",
        ),
        (
            "tooling_pathset_blake3",
            "e17877e38b5ada83f7d84b81bd25be0c3e1cd53e6a1a94fb555140371397a856",
        ),
    ] {
        if auth[field].as_str() != Some(want) {
            return err(format!("authority.{field} drifted from ratified value"));
        }
    }

    // (1) seal recomputes from committed manifest members and matches everywhere.
    let recomputed = seal_from_manifest(&man)?;
    if recomputed != OFFICIAL_SEAL {
        return err(format!("seal recompute mismatch: {recomputed}"));
    }
    if auth["official_seal_blake3"].as_str() != Some(OFFICIAL_SEAL) {
        return err("closure seal != official seal");
    }
    if man["official_seal_blake3"].as_str() != Some(OFFICIAL_SEAL) {
        return err("manifest seal != official seal");
    }
    for field in ["package_id_blake3", "r0_guest_set_hash"] {
        if auth[field] != man[field] {
            return err(format!("closure/manifest disagree on {field}"));
        }
    }

    // (2) frozen gates in the record match the protocol.
    let gate = |k: &str| p["qualification_gates"][k].as_u64();
    let gp99 = gate("verify_p99_gate_ns").ok_or("no gate p99")?;
    let gagg = gate("aggregate_verify_budget_ns_per_block").ok_or("no gate agg")?;
    let gm = gate("max_accepted_proofs_per_block").ok_or("no gate M")?;

    // (3) every INCLUDED constant is mechanically derivable + matches its source.
    let included = c["included_constants"]
        .as_array()
        .ok_or("no included_constants")?;
    for item in included {
        let name = item["name"].as_str().ok_or("included name missing")?;
        if PROHIBITED_INCLUDED.contains(&name) {
            return err(format!("prohibited parameter frozen as included: {name}"));
        }
        let val = &item["value"];
        let src = item["source"].as_str().ok_or("included source missing")?;
        if let Some(path) = src.strip_prefix("protocol:") {
            let resolved = resolve_protocol(&p, path)?;
            if resolved != val {
                return err(format!("included {name}: value != protocol ({path})"));
            }
        } else if let Some(inner) = src.strip_prefix("derived:pow2(protocol:") {
            let path = inner.trim_end_matches(')');
            let base = resolve_protocol(&p, path)?.as_u64().ok_or("pow2 base")?;
            if val.as_u64() != Some(1u64 << base) {
                return err(format!("included {name}: != pow2({base})"));
            }
        } else if src == "selection:selected" {
            if *val != c["selection"]["selected"] {
                return err(format!("included {name} != selection.selected"));
            }
        } else if src == "seal:risc0_verify_p99" {
            let sel = c["selection"]["candidates"]
                .as_array()
                .ok_or("no candidates")?;
            let r0 = sel
                .iter()
                .find(|x| x["candidate"].as_str() == Some("Risc0"))
                .ok_or("no risc0")?;
            if r0["measured_verify_p99_ns"] != *val {
                return err("V_verify_cost != RISC0 measured p99");
            }
        } else {
            return err(format!("included {name}: unrecognized source {src}"));
        }
    }

    // (4) selection consistent + RISC0 is the UNIQUE qualifier under the frozen gates.
    let sel = &c["selection"];
    if sel["hard_fail"] != Value::Bool(false) {
        return err("hard_fail must be false");
    }
    if sel["selected"].as_str() != Some("Risc0")
        || sel["unique_qualifier"].as_str() != Some("Risc0")
    {
        return err("selected/unique_qualifier must be Risc0");
    }
    let cands = sel["candidates"].as_array().ok_or("no candidates")?;
    let mut qualifiers: Vec<String> = Vec::new();
    for cand in cands {
        let nm = cand["candidate"].as_str().ok_or("cand name")?;
        let p99 = cand["measured_verify_p99_ns"].as_u64().ok_or("cand p99")?;
        let q = qualifies(p99, gp99, gm, gagg);
        let verdict = cand["verdict"].as_str().ok_or("verdict")?;
        if q != (verdict == "qualified") {
            return err(format!("{nm}: stated verdict != recomputed"));
        }
        if !q {
            let codes: Vec<u64> = cand["failed_gates"]
                .as_array()
                .ok_or("failed_gates")?
                .iter()
                .filter_map(Value::as_u64)
                .collect();
            let mut expect = Vec::new();
            if p99 > gp99 {
                expect.push(3);
            }
            if p99.checked_mul(gm).map(|a| a > gagg).unwrap_or(true) {
                expect.push(4);
            }
            if codes != expect {
                return err(format!("{nm}: failed_gates != expected"));
            }
        }
        if q {
            qualifiers.push(nm.to_string());
        }
    }
    if qualifiers != ["Risc0"] {
        return err(format!("unique qualifier proof failed: {qualifiers:?}"));
    }
    let ba = &sel["bilateral_agreement"];
    if ba["validator_guest_set"] != ba["independent_guest_set"]
        || ba["agree"] != Value::Bool(true)
        || ba["validator_guest_set"] != auth["r0_guest_set_hash"]
    {
        return err("bilateral guest-set disagreement");
    }

    // (5) scope exclusion + disjointness + completeness.
    let scope = &c["scope_exclusion"];
    for k in [
        "cryptographic_security",
        "topology",
        "dkg",
        "consensus_safety",
    ] {
        if scope[k].as_str() != Some("none_selected") {
            return err(format!("scope_exclusion.{k} must be none_selected"));
        }
    }
    if scope["security_floors"].as_str() != Some("preserved") {
        return err("security_floors must be preserved");
    }
    let inc_issue_names: Vec<&str> = included
        .iter()
        .filter_map(|i| i["name"].as_str())
        .filter_map(issue_name_for)
        .collect();
    let excluded = c["excluded_constants"]
        .as_array()
        .ok_or("no excluded_constants")?;
    let mut excl_names: Vec<String> = Vec::new();
    for g in excluded {
        let owners = g["owner_issues"].as_array().ok_or("group owner_issues")?;
        if owners.is_empty() {
            return err("excluded group without owner");
        }
        for n in g["names"].as_array().ok_or("group names")? {
            excl_names.push(n.as_str().ok_or("excl name")?.to_string());
        }
    }
    for nm in &inc_issue_names {
        if excl_names.iter().any(|e| e == nm) {
            return err(format!("{nm} both included and excluded"));
        }
    }
    for item in included {
        if let Some(name) = item["name"].as_str() {
            if excl_names.iter().any(|e| e == name) {
                return err(format!("{name} both included (raw) and excluded"));
            }
        }
    }
    for nm in ISSUE_123_CONSTANTS {
        let is_inc = inc_issue_names.contains(nm);
        let is_exc = excl_names.iter().any(|e| e == nm);
        if !is_inc && !is_exc {
            return err(format!(
                "#123 constant '{nm}' neither included nor excluded"
            ));
        }
    }

    // (6) durable evidence well-formed + self-consistent.
    if auth["measurement_head"] != c["durable_evidence"]["release_tag_commit"] {
        return err("release tag commit != measurement head");
    }
    let is_hex64 = |v: &Value| {
        v.as_str()
            .map(|s| s.len() == 64 && s.chars().all(|c| c.is_ascii_hexdigit()))
            .unwrap_or(false)
    };
    for a in c["durable_evidence"]["assets"]
        .as_array()
        .ok_or("no assets")?
    {
        if !is_hex64(&a["sha256"]) || !is_hex64(&a["blake3"]) {
            return err("asset malformed digest");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn qualifies_matches_frozen_gates() {
        // 75ms p99 gate, M=4, 300ms/block aggregate (ns)
        assert!(qualifies(3_200_000, 75_000_000, 4, 300_000_000));
        assert!(!qualifies(212_100_000, 75_000_000, 4, 300_000_000));
        // exactly-at-gate p99 qualifies; aggregate overflow disqualifies
        assert!(qualifies(75_000_000, 75_000_000, 4, 300_000_000));
        assert!(!qualifies(u64::MAX, u64::MAX, 4, 300_000_000));
    }
}
