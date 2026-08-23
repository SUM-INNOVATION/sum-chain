//! INDEPENDENT re-decode + from-scratch authentication of `DependencySeedV1` — the venue-produced
//! authority for the EXACT committed runner dependency GRAPH SET the OFFLINE A/B builds consumed.
//!
//! Shares NO code with `b0-pre-validator`: it carries its OWN SHA-256 (via
//! [`crate::malformed_corpus_report::sha256`]) and recomputes the domain-separated content `address`
//! from scratch, so agreement with the reference is genuine second-source corroboration. The record is
//! sealed per-candidate in the VEC7 measurement vector; at sealed import the independent verifier decodes
//! it, re-authenticates it, and anchors every double-build proof's cargo-seed origin to it (so the origin
//! is NEVER producer-trusted).
//!
//! The address preimage MIRRORS the reference byte-for-byte (NUL-joined, UTF-8, SHA-256):
//!   domain \0 candidate \0 graph_count \0 unit_count \0 {lock_sha256 per graph, in order}
//!   \0 {seed_address per unit, in order} \0 {vendor_config_sha256 per unit, in order}
//!
//! Per-candidate shape: SP1 => 2 graphs, 1 unit role=["host-cargo-home"]; RISC0 => 2 graphs, 2 units
//! roles=["host-cargo-home","guest-home"] with a graph purpose=="guest-workspace"
//! materialization=="guest-home".

use serde::{Deserialize, Serialize};

use crate::malformed_corpus_report::{sha256, to_hex};

pub const DEP_SEED_SCHEMA: &str = "b0-final-runner-dependency-seed/v1";

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DepGraph {
    pub purpose: String,
    pub name: String,
    pub materialization: String,
    pub lock_sha256: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DepSeedUnit {
    pub role: String,
    pub seed_address: String,
    pub vendor_config_sha256: String,
    pub graphs: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
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

    /// Recompute the domain-separated content address from scratch (mirrors the reference byte-for-byte:
    /// NUL-joined UTF-8 preimage, SHA-256, lowercase hex).
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
        to_hex(&sha256(parts.join("\0").as_bytes()))
    }

    /// Verify the record is well-formed for `candidate` ("sp1"|"risc0"), its counts + graph/unit shape
    /// match the ratified per-candidate expectation, all hashes are 64-hex, and the recomputed address
    /// equals its own `address` field. Returns the authenticated 32-byte address.
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

    /// The canonical host-cargo-home SEED-CONTENT address as 32 bytes — the value the double-build proof's
    /// `cargo_seed_origin_blake3` must equal at sealed import. Call AFTER [`verify`].
    pub fn host_cargo_home_seed_address(&self) -> Result<[u8; 32], String> {
        let u = self
            .seed_units
            .iter()
            .find(|u| u.role == "host-cargo-home")
            .ok_or("dependency-seed has no host-cargo-home seed unit")?;
        hex32(&u.seed_address)
    }

    /// Build a SELF-CONSISTENT synthetic record for `candidate` ("sp1"|"risc0") whose host-cargo-home
    /// seed-content address is `host_seed` (32 bytes), deterministic filler for every other hash, and
    /// `address == recompute_address()`. Returns `(json_bytes, record_address)`. Used by the independent
    /// harness's synthetic assembly path to seal a dependency-seed artifact the sealed-import anchor
    /// accepts (mirrors the reference `synthetic_json` structure so the recomputed address agrees).
    pub fn synthetic_json(candidate: &str, host_seed: [u8; 32]) -> (Vec<u8>, [u8; 32]) {
        let host_hex = to_hex(&host_seed);
        let mut d = if candidate == "sp1" {
            DependencySeedV1 {
                schema: DEP_SEED_SCHEMA.into(),
                candidate: "sp1".into(),
                graphs: vec![
                    DepGraph {
                        purpose: "main".into(),
                        name: "sp1-runner".into(),
                        materialization: "host-cargo-home".into(),
                        lock_sha256: "1".repeat(64),
                    },
                    DepGraph {
                        purpose: "nested".into(),
                        name: "sp1-core-executor-runner".into(),
                        materialization: "host-cargo-home".into(),
                        lock_sha256: "2".repeat(64),
                    },
                ],
                graph_count: 2,
                seed_units: vec![DepSeedUnit {
                    role: "host-cargo-home".into(),
                    seed_address: host_hex.clone(),
                    vendor_config_sha256: "3".repeat(64),
                    graphs: vec!["sp1-runner".into(), "sp1-core-executor-runner".into()],
                }],
                seed_unit_count: 1,
                address: String::new(),
            }
        } else {
            DependencySeedV1 {
                schema: DEP_SEED_SCHEMA.into(),
                candidate: "risc0".into(),
                graphs: vec![
                    DepGraph {
                        purpose: "main".into(),
                        name: "risc0-runner".into(),
                        materialization: "host-cargo-home".into(),
                        lock_sha256: "1".repeat(64),
                    },
                    DepGraph {
                        purpose: "guest-workspace".into(),
                        name: "b0-pre-candidate-risc0-workspace".into(),
                        materialization: "guest-home".into(),
                        lock_sha256: "2".repeat(64),
                    },
                ],
                graph_count: 2,
                seed_units: vec![
                    DepSeedUnit {
                        role: "host-cargo-home".into(),
                        seed_address: host_hex.clone(),
                        vendor_config_sha256: "3".repeat(64),
                        graphs: vec!["risc0-runner".into()],
                    },
                    DepSeedUnit {
                        role: "guest-home".into(),
                        seed_address: "e".repeat(64),
                        vendor_config_sha256: "4".repeat(64),
                        graphs: vec!["b0-pre-candidate-risc0-workspace".into()],
                    },
                ],
                seed_unit_count: 2,
                address: String::new(),
            }
        };
        d.address = d.recompute_address();
        let record_address = hex32(&d.address).expect("recomputed address is 64-hex");
        let json = serde_json::to_vec(&d).expect("serialize synthetic dependency seed");
        (json, record_address)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn risc0_record() -> DependencySeedV1 {
        let (json, _addr) = DependencySeedV1::synthetic_json("risc0", [7u8; 32]);
        DependencySeedV1::from_json(&json).unwrap()
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
        let mut t = risc0_record();
        t.graphs[0].lock_sha256 = "9".repeat(64);
        assert_ne!(t.recompute_address(), a0);
        let mut t2 = risc0_record();
        t2.seed_units[1].seed_address = "9".repeat(64);
        assert_ne!(t2.recompute_address(), a0);
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

    #[test]
    fn host_cargo_home_seed_matches_input() {
        let host = [0x5au8; 32];
        let (json, _addr) = DependencySeedV1::synthetic_json("sp1", host);
        let d = DependencySeedV1::from_json(&json).unwrap();
        assert_eq!(d.verify("sp1").unwrap(), _addr);
        assert_eq!(d.host_cargo_home_seed_address().unwrap(), host);
    }
}
