//! `DependencySeedV1` — the venue-produced authority for the EXACT committed runner dependency GRAPH
//! SET, provisioned once (disclosed network) and consumed by the OFFLINE A/B builds. It is parsed from
//! the retained JSON `tools/b0-pre-candidates/scripts/lib.sh:b0_runner_dependency_seed` emits, and its
//! domain-separated content `address` is RECOMPUTED here from scratch (never trusted) and required to
//! equal both the record's own `address` field and the address `RunnerAttestationV1` binds.
//!
//! Graph SET per candidate:
//!   * SP1   — 2 graphs (main runner lock + the checksum-bound nested `sp1-core-executor-runner` lock),
//!             ONE `host-cargo-home` seed unit (the nested graph is `--sync`-unioned into it).
//!   * RISC0 — 2 graphs (main runner lock + the candidate WORKSPACE lock `embed_methods()` builds the
//!             guest against), TWO seed units: `host-cargo-home` (main) + `guest-home` (workspace).
//!
//! The address preimage MIRRORS lib.sh EXACTLY (NUL-joined, UTF-8, SHA-256):
//!   domain \0 candidate \0 graph_count \0 unit_count \0 {lock_sha256 per graph, in order}
//!   \0 {seed_address per unit, in order} \0 {vendor_config_sha256 per unit, in order}

use serde::Deserialize;

pub const DEP_SEED_SCHEMA: &str = "b0-final-runner-dependency-seed/v1";

#[derive(Debug, Clone, Deserialize)]
pub struct DepGraph {
    pub purpose: String,
    pub name: String,
    pub materialization: String,
    pub lock_sha256: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DepSeedUnit {
    pub role: String,
    pub seed_address: String,
    pub vendor_config_sha256: String,
    pub graphs: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DependencySeedV1 {
    pub schema: String,
    pub candidate: String,
    pub graphs: Vec<DepGraph>,
    pub graph_count: usize,
    pub seed_units: Vec<DepSeedUnit>,
    pub seed_unit_count: usize,
    pub address: String,
}

fn is_hex64(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn hex32(s: &str) -> Result<[u8; 32], String> {
    if !is_hex64(s) {
        return Err(format!(
            "dependency-seed address {s:?} is not 64 lowercase-hex"
        ));
    }
    let mut out = [0u8; 32];
    for (i, chunk) in s.as_bytes().chunks(2).enumerate() {
        out[i] = u8::from_str_radix(std::str::from_utf8(chunk).unwrap(), 16)
            .map_err(|e| format!("hex: {e}"))?;
    }
    Ok(out)
}

impl DependencySeedV1 {
    pub fn from_json(bytes: &[u8]) -> Result<Self, String> {
        serde_json::from_slice(bytes).map_err(|e| format!("dependency-seed JSON parse: {e}"))
    }

    /// Recompute the domain-separated content address from scratch (mirrors lib.sh byte-for-byte).
    pub fn recompute_address(&self) -> String {
        let mut parts: Vec<String> =
            Vec::with_capacity(4 + self.graphs.len() + 2 * self.seed_units.len());
        parts.push(DEP_SEED_SCHEMA.to_string());
        parts.push(self.candidate.clone());
        parts.push(self.graphs.len().to_string());
        parts.push(self.seed_units.len().to_string());
        for g in &self.graphs {
            parts.push(g.lock_sha256.clone());
        }
        for u in &self.seed_units {
            parts.push(u.seed_address.clone());
        }
        for u in &self.seed_units {
            parts.push(u.vendor_config_sha256.clone());
        }
        let pre = parts.join("\0");
        crate::venue::sha256::hex_digest(pre.as_bytes())
    }

    /// Verify the record is well-formed for `candidate`, its counts + graph/unit shape match the
    /// ratified per-candidate expectation, and the recomputed address equals both its own `address`
    /// field and (when supplied) the address the attestation binds. Returns the 32-byte address.
    pub fn verify(&self, candidate: &str) -> Result<[u8; 32], String> {
        if self.schema != DEP_SEED_SCHEMA {
            return Err(format!(
                "dependency-seed schema {:?} != {DEP_SEED_SCHEMA}",
                self.schema
            ));
        }
        if self.candidate != candidate {
            return Err(format!(
                "dependency-seed candidate {:?} != expected {candidate:?}",
                self.candidate
            ));
        }
        if self.graph_count != self.graphs.len() {
            return Err("dependency-seed graph_count != graphs.len()".into());
        }
        if self.seed_unit_count != self.seed_units.len() {
            return Err("dependency-seed seed_unit_count != seed_units.len()".into());
        }
        // Ratified per-candidate shape: both candidates are 2-graph; SP1 unions into 1 host unit,
        // RISC0 keeps a distinct guest-home unit.
        let (want_graphs, want_units, want_roles): (usize, usize, &[&str]) = match candidate {
            "sp1" => (2, 1, &["host-cargo-home"]),
            "risc0" => (2, 2, &["host-cargo-home", "guest-home"]),
            other => return Err(format!("dependency-seed unknown candidate {other:?}")),
        };
        if self.graphs.len() != want_graphs {
            return Err(format!(
                "dependency-seed {candidate} expects {want_graphs} graphs, has {}",
                self.graphs.len()
            ));
        }
        if self.seed_units.len() != want_units {
            return Err(format!(
                "dependency-seed {candidate} expects {want_units} seed units, has {}",
                self.seed_units.len()
            ));
        }
        for (i, want) in want_roles.iter().enumerate() {
            if self.seed_units[i].role != *want {
                return Err(format!(
                    "dependency-seed {candidate} seed unit {i} role {:?} != {want:?}",
                    self.seed_units[i].role
                ));
            }
        }
        // RISC0 must bind the candidate WORKSPACE graph on the guest-home unit.
        if candidate == "risc0"
            && !self
                .graphs
                .iter()
                .any(|g| g.purpose == "guest-workspace" && g.materialization == "guest-home")
        {
            return Err("dependency-seed risc0 missing guest-workspace graph on guest-home".into());
        }
        for g in &self.graphs {
            if !is_hex64(&g.lock_sha256) {
                return Err(format!(
                    "dependency-seed graph {} lock_sha256 not 64-hex",
                    g.name
                ));
            }
        }
        for u in &self.seed_units {
            if !is_hex64(&u.seed_address) || !is_hex64(&u.vendor_config_sha256) {
                return Err(format!(
                    "dependency-seed unit {} address/config not 64-hex",
                    u.role
                ));
            }
        }
        let recomputed = self.recompute_address();
        if recomputed != self.address {
            return Err(format!(
                "dependency-seed recomputed address {recomputed} != recorded {}",
                self.address
            ));
        }
        hex32(&self.address)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn risc0_record() -> DependencySeedV1 {
        let mut d = DependencySeedV1 {
            schema: DEP_SEED_SCHEMA.into(),
            candidate: "risc0".into(),
            graphs: vec![
                DepGraph {
                    purpose: "main".into(),
                    name: "risc0-runner".into(),
                    materialization: "host-cargo-home".into(),
                    lock_sha256: "a".repeat(64),
                },
                DepGraph {
                    purpose: "guest-workspace".into(),
                    name: "b0-pre-candidate-risc0-workspace".into(),
                    materialization: "guest-home".into(),
                    lock_sha256: "b".repeat(64),
                },
            ],
            graph_count: 2,
            seed_units: vec![
                DepSeedUnit {
                    role: "host-cargo-home".into(),
                    seed_address: "c".repeat(64),
                    vendor_config_sha256: "d".repeat(64),
                    graphs: vec!["risc0-runner".into()],
                },
                DepSeedUnit {
                    role: "guest-home".into(),
                    seed_address: "e".repeat(64),
                    vendor_config_sha256: "f".repeat(64),
                    graphs: vec!["b0-pre-candidate-risc0-workspace".into()],
                },
            ],
            seed_unit_count: 2,
            address: String::new(),
        };
        d.address = d.recompute_address();
        d
    }

    #[test]
    fn recompute_is_deterministic_and_verifies() {
        let d = risc0_record();
        assert_eq!(d.recompute_address(), d.address);
        assert!(d.verify("risc0").is_ok());
        assert!(is_hex64(&d.address));
    }

    #[test]
    fn tamper_any_bound_field_breaks_address() {
        let base = risc0_record();
        let a0 = base.recompute_address();
        // Changing a bound lock hash changes the address.
        let mut t = risc0_record();
        t.graphs[0].lock_sha256 = "9".repeat(64);
        assert_ne!(t.recompute_address(), a0);
        // Changing a seed unit address changes it.
        let mut t2 = risc0_record();
        t2.seed_units[1].seed_address = "9".repeat(64);
        assert_ne!(t2.recompute_address(), a0);
        // A stale recorded address (not recomputed) is refused by verify().
        let mut t3 = risc0_record();
        t3.address = "0".repeat(64);
        assert!(t3.verify("risc0").is_err());
    }

    #[test]
    fn refuses_wrong_candidate_and_shape() {
        let mut d = risc0_record();
        assert!(d.verify("sp1").is_err()); // candidate mismatch
        d.seed_units.pop();
        d.seed_unit_count = 1;
        assert!(d.verify("risc0").is_err()); // wrong unit count for risc0
    }
}
