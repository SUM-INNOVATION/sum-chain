//! C1 ComputePool job graph + pool identifier KDFs (#227 / #130).
//!
//! DORMANT: consensus BYTES only; execution stays gate-closed
//! (`compute_pool_enabled_from_height = None`).
//!
//! `CreateComputePoolJobV1` **commits** its dependency graph as a single
//! `graph_definition_root` (ratified #217 **B5**: a domain-separated BLAKE3 root
//! with **no** `ObjectKind`). This module fixes the root's preimage — the
//! canonical [`GraphDefinitionV1`] encoding — plus the pool identifier KDFs the
//! op's inputs are resolved through.
//!
//! ## Domain families (owner ruling 2026-09-03)
//! Registry graphs and ComputePool execution graphs have **different semantics
//! and must not be interchangeable**, so they live in **separate versioned
//! domains**: the registry keeps `SUMCHAIN/REGISTRY/GRAPHDEF/v1\0`
//! ([`crate::registry_wire`]); pool job graphs use
//! [`POOL_GRAPHDEF_TAG`] here. The two are mutually prefix-free and produce
//! different roots over identical bytes — see the domain-confusion tests.
//!
//! Tag terminators are per-family and deliberate: the **POOL** family is
//! `\n`-terminated (draft §K, whose golden vectors are independently
//! `b3sum`-computed and reproduced in the tests below); the **REGISTRY** family
//! is `\0`-terminated (ratified #217 B2).
//!
//! ## Derived limits — nothing invented
//! Every bound below is the **exact mathematical maximum** implied by the
//! pre-existing C1 decode ceiling `C1_DECODE_BYTE_LIMIT = 1 << 20` (1 MiB,
//! `crates/state/src/compute_pool_store.rs`). None is stricter than the ceiling
//! implies, so no DoS benchmark is required; see [`GraphDefinitionV1`].

use crate::address::Address;
use crate::b0::codec::{DecodeError, Reader, Writer};

// --------------------------------------------------------------------------- //
// Pool identifier KDFs (draft §K — adopted as-is; golden vectors in tests)
// --------------------------------------------------------------------------- //

/// `job_id` domain tag (21 bytes, `\n`-terminated).
pub const POOL_JOB_TAG: &[u8] = b"SUMCHAIN/POOL/JOB/v1\n";
/// `unit_id` domain tag (22 bytes, `\n`-terminated).
pub const POOL_UNIT_TAG: &[u8] = b"SUMCHAIN/POOL/UNIT/v1\n";
/// Pool job-graph root domain tag (26 bytes, `\n`-terminated). Distinct from the
/// registry graph domain by owner ruling — the two are not interchangeable.
pub const POOL_GRAPHDEF_TAG: &[u8] = b"SUMCHAIN/POOL/GRAPHDEF/v1\n";

/// `job_id = BLAKE3(POOL_JOB_TAG ‖ u64_le(chain_id) ‖ requester[20] ‖
/// u64_le(requester_nonce) ‖ client_job_salt[32])` (§K).
///
/// Never carried on the wire: `CreateComputePoolJobV1` carries only
/// `client_job_salt`, and execution recomputes this from the chain id, the
/// **transaction sender**, and the sender's nonce — so a submitter cannot present
/// a forged id, nor mint a job id belonging to another requester.
pub fn job_id(
    chain_id: u64,
    requester: &Address,
    requester_nonce: u64,
    client_job_salt: &[u8; 32],
) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(POOL_JOB_TAG);
    h.update(&chain_id.to_le_bytes());
    h.update(requester.as_bytes());
    h.update(&requester_nonce.to_le_bytes());
    h.update(client_job_salt);
    *h.finalize().as_bytes()
}

/// `unit_id = BLAKE3(POOL_UNIT_TAG ‖ job_id[32] ‖ u32_le(unit_index))` (§K).
pub fn unit_id(job_id: &[u8; 32], unit_index: u32) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(POOL_UNIT_TAG);
    h.update(job_id);
    h.update(&unit_index.to_le_bytes());
    *h.finalize().as_bytes()
}

/// `graph_definition_root = BLAKE3(POOL_GRAPHDEF_TAG ‖ canonical_encoding)`
/// (ratified B5: domain-separated, no `ObjectKind`).
pub fn graph_definition_root(canonical_encoding: &[u8]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(POOL_GRAPHDEF_TAG);
    h.update(canonical_encoding);
    *h.finalize().as_bytes()
}

// --------------------------------------------------------------------------- //
// DependencyEdgeV1 — draft §F, 101 B (authoritative over the in-memory model)
// --------------------------------------------------------------------------- //

/// Output-slot discriminant (frozen `enums.rs` `SlotKind`). **Not** an
/// `ObjectKind`: the embedded object kind is *implied*
/// (`ResidualStream → ResidualState=6`, `KvCache → KvState=7`) and never
/// re-encoded — the rev.4 correction the draft applied.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SlotKind {
    ResidualStream = 0,
    KvCache = 1,
}

impl SlotKind {
    pub fn to_u8(self) -> u8 {
        self as u8
    }
    pub fn from_u8(v: u8) -> Result<Self, DecodeError> {
        match v {
            0 => Ok(Self::ResidualStream),
            1 => Ok(Self::KvCache),
            _ => Err(DecodeError::BadEnum {
                name: "SlotKind",
                value: v as u64,
            }),
        }
    }
    /// The `ObjectKind` this slot implies (never encoded in the edge).
    pub fn object_kind_repr(self) -> u16 {
        match self {
            Self::ResidualStream => 6, // ObjectKind::ResidualState
            Self::KvCache => 7,        // ObjectKind::KvState
        }
    }
}

/// A dependency edge (draft §F byte table, 101 B).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DependencyEdgeV1 {
    pub predecessor_unit_id: [u8; 32],
    pub predecessor_output_manifest_identity: [u8; 32],
    pub required_slot_kind: SlotKind,
    pub required_slot_index: u32,
    pub required_state_object_identity: [u8; 32],
}

impl DependencyEdgeV1 {
    pub const LEN: usize = 32 + 32 + 1 + 4 + 32; // 101

    /// Canonical order key — the tuple
    /// `(predecessor_unit_id, predecessor_output_manifest_identity,
    ///   required_slot_kind, required_slot_index)`, compared field-by-field:
    /// the two ids lexicographically as bytes, then the slot kind and slot index
    /// **numerically**. Edges are strictly ascending and unique under this order;
    /// equal keys are a duplicate, not a tie.
    ///
    /// The order is deliberately defined over *fields*, not over the raw encoded
    /// prefix: `required_slot_index` is encoded **little-endian**, so a bytewise
    /// comparison of the encoding would order `255` after `256`. Field ordering
    /// keeps "canonical" and "numerically ascending" the same statement.
    pub fn order_key(&self) -> ([u8; 32], [u8; 32], u8, u32) {
        (
            self.predecessor_unit_id,
            self.predecessor_output_manifest_identity,
            self.required_slot_kind.to_u8(),
            self.required_slot_index,
        )
    }

    fn write(&self, w: &mut Writer) {
        w.bytes(&self.predecessor_unit_id);
        w.bytes(&self.predecessor_output_manifest_identity);
        w.u8(self.required_slot_kind.to_u8());
        w.u32(self.required_slot_index);
        w.bytes(&self.required_state_object_identity);
    }

    fn read(r: &mut Reader) -> Result<Self, DecodeError> {
        let predecessor_unit_id = r.read_array::<32>("DependencyEdgeV1.predecessor_unit_id")?;
        let predecessor_output_manifest_identity =
            r.read_array::<32>("DependencyEdgeV1.predecessor_output_manifest_identity")?;
        let required_slot_kind =
            SlotKind::from_u8(r.read_u8("DependencyEdgeV1.required_slot_kind")?)?;
        let required_slot_index = r.read_u32("DependencyEdgeV1.required_slot_index")?;
        let required_state_object_identity =
            r.read_array::<32>("DependencyEdgeV1.required_state_object_identity")?;
        Ok(Self {
            predecessor_unit_id,
            predecessor_output_manifest_identity,
            required_slot_kind,
            required_slot_index,
            required_state_object_identity,
        })
    }
}

// --------------------------------------------------------------------------- //
// GraphDefinitionV1 — the canonical preimage of `graph_definition_root`
// --------------------------------------------------------------------------- //

/// One work unit's declaration. `unit_index` is **positional** (never encoded),
/// so index gaps, duplicates and reordering are structurally impossible.
/// `retention_slots` lives here — not in the op — because it drives retention and
/// funding and must therefore be bound by the graph commitment (owner ruling).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnitDefV1 {
    pub retention_slots: u64,
    pub edges: Vec<DependencyEdgeV1>,
}

/// The canonical job-graph definition. Its encoding is the preimage of
/// [`graph_definition_root`].
///
/// ```text
/// MAGIC[7]="CPGDv1\0" ‖ schema_version u16 ‖ unit_count u32
///   per unit (ascending positional unit_index):
///     retention_slots u64 ‖ edge_count u32 ‖ edge_count × DependencyEdgeV1(101)
/// ```
///
/// # Derived limits (from the pre-existing 1 MiB C1 decode ceiling)
///
/// `size(N, E) = 13 + 12·N + 101·E`, so with `CEILING = 1 << 20`:
///
/// | limit | value | derivation |
/// |---|---|---|
/// | [`MAX_GRAPH_BYTES`](Self::MAX_GRAPH_BYTES) | `1_048_576` | **given** — equals `C1_DECODE_BYTE_LIMIT` |
/// | [`MAX_UNITS`](Self::MAX_UNITS) | `87_380` | largest `N` with `E=0`: `13+12N ≤ CEILING` (`N+1` ⇒ 1_048_585 > CEILING) |
/// | [`MAX_TOTAL_EDGES`](Self::MAX_TOTAL_EDGES) | `10_381` | largest `E` at the minimum unit count that can host edges (`N=2`, since backward-only edges leave unit 0 with none): `13+24+101E ≤ CEILING` (`E+1` ⇒ 1_048_619 > CEILING) |
/// | [`MAX_EDGES_PER_UNIT`](Self::MAX_EDGES_PER_UNIT) | `10_381` | a single unit may legitimately hold every edge (unit 1 → unit 0 across distinct slot indices), so any smaller cap would be stricter than the ceiling implies; set equal to the total |
///
/// Each is the exact mathematical maximum, never stricter than the ceiling — so
/// no DoS benchmark is owed. The **authoritative** guard is the byte ceiling; the
/// count caps exist solely to reject a declared count *before* any allocation.
///
/// # Resource envelope (proved by tests)
/// * Input: `≤ 1 MiB` (rejected before parsing otherwise).
/// * Decode: `O(N+E)` time; the decoded structure is `O(N+E)` and bounded by the
///   same ceiling.
/// * [`verify_against_job`](Self::verify_against_job) resolves predecessors via a
///   `unit_id → index` map so the check is `O(N + E)` rather than `O(N·E)`
///   re-hashing. Map memory `= 32·N ≤ 32·87_380 = 2_796_160 B (2.67 MiB)`, and
///   `≤ N` BLAKE3 hashes over a 58-byte preimage. Peak ≈ 3.7 MiB for a maximal
///   input — a bounded, documented amplification.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GraphDefinitionV1 {
    pub units: Vec<UnitDefV1>,
}

impl GraphDefinitionV1 {
    pub const MAGIC: [u8; 7] = *b"CPGDv1\0";
    pub const SCHEMA_VERSION: u16 = 1;

    pub const HEADER_LEN: u64 = 7 + 2 + 4; // 13
    pub const PER_UNIT_LEN: u64 = 8 + 4; // 12
    pub const PER_EDGE_LEN: u64 = DependencyEdgeV1::LEN as u64; // 101

    /// Equals `sumchain_state::compute_pool_store::C1_DECODE_BYTE_LIMIT` (1 MiB).
    /// Kept as a literal here so `sumchain-wire` (a leaf) takes no state dep; the
    /// `ceiling_matches_c1_decode_limit` test pins the relationship.
    pub const MAX_GRAPH_BYTES: u64 = 1 << 20;
    pub const MAX_UNITS: u32 = 87_380;
    pub const MAX_TOTAL_EDGES: u32 = 10_381;
    pub const MAX_EDGES_PER_UNIT: u32 = Self::MAX_TOTAL_EDGES;

    /// Exact encoded length. `u64` throughout — `N`/`E` are `u32`, so the
    /// products cannot overflow a `u64`.
    pub fn encoded_len(&self) -> u64 {
        let n = self.units.len() as u64;
        let e: u64 = self.units.iter().map(|u| u.edges.len() as u64).sum();
        Self::HEADER_LEN + Self::PER_UNIT_LEN * n + Self::PER_EDGE_LEN * e
    }

    pub fn total_edges(&self) -> u64 {
        self.units.iter().map(|u| u.edges.len() as u64).sum()
    }

    /// Structural validation: counts within the derived limits, edges strictly
    /// ascending + unique per unit, and the whole encoding within the ceiling.
    pub fn validate(&self) -> Result<(), DecodeError> {
        let n = self.units.len() as u64;
        if n > Self::MAX_UNITS as u64 {
            return Err(DecodeError::CountExceedsMax {
                ctx: "GraphDefinitionV1.unit_count",
                count: n,
                max: Self::MAX_UNITS as u64,
            });
        }
        let mut total: u64 = 0;
        for u in &self.units {
            let e = u.edges.len() as u64;
            if e > Self::MAX_EDGES_PER_UNIT as u64 {
                return Err(DecodeError::CountExceedsMax {
                    ctx: "GraphDefinitionV1.edge_count",
                    count: e,
                    max: Self::MAX_EDGES_PER_UNIT as u64,
                });
            }
            total += e;
            if total > Self::MAX_TOTAL_EDGES as u64 {
                return Err(DecodeError::CountExceedsMax {
                    ctx: "GraphDefinitionV1.total_edges",
                    count: total,
                    max: Self::MAX_TOTAL_EDGES as u64,
                });
            }
            for w in u.edges.windows(2) {
                match w[0].order_key().cmp(&w[1].order_key()) {
                    std::cmp::Ordering::Less => {}
                    std::cmp::Ordering::Equal => {
                        return Err(DecodeError::DuplicateEntry {
                            ctx: "GraphDefinitionV1.edges",
                        })
                    }
                    std::cmp::Ordering::Greater => {
                        return Err(DecodeError::NonCanonicalOrder {
                            ctx: "GraphDefinitionV1.edges",
                        })
                    }
                }
            }
        }
        let len = self.encoded_len();
        if len > Self::MAX_GRAPH_BYTES {
            return Err(DecodeError::LengthExceedsMax {
                ctx: "GraphDefinitionV1",
                len,
                max: Self::MAX_GRAPH_BYTES,
            });
        }
        Ok(())
    }

    fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.bytes(&Self::MAGIC);
        w.u16(Self::SCHEMA_VERSION);
        w.u32(self.units.len() as u32);
        for u in &self.units {
            w.u64(u.retention_slots);
            w.u32(u.edges.len() as u32);
            for e in &u.edges {
                e.write(&mut w);
            }
        }
        w.into_bytes()
    }

    pub fn try_encode(&self) -> Result<Vec<u8>, DecodeError> {
        self.validate()?;
        Ok(self.encode())
    }

    /// The committed root over this graph's canonical encoding.
    pub fn root(&self) -> Result<[u8; 32], DecodeError> {
        Ok(graph_definition_root(&self.try_encode()?))
    }

    pub fn decode(r: &mut Reader) -> Result<Self, DecodeError> {
        let magic = r.read_array::<7>("GraphDefinitionV1.magic")?;
        if magic != Self::MAGIC {
            return Err(DecodeError::BadTag {
                ctx: "GraphDefinitionV1",
            });
        }
        let sv = r.read_u16("GraphDefinitionV1.schema_version")?;
        if sv != Self::SCHEMA_VERSION {
            return Err(DecodeError::BadFixedScalar {
                ctx: "GraphDefinitionV1.schema_version",
                value: sv as u64,
            });
        }
        let n = r.read_u32("GraphDefinitionV1.unit_count")?;
        // Bound the DECLARED count before allocating anything.
        if n > Self::MAX_UNITS {
            return Err(DecodeError::CountExceedsMax {
                ctx: "GraphDefinitionV1.unit_count",
                count: n as u64,
                max: Self::MAX_UNITS as u64,
            });
        }
        let mut units = Vec::with_capacity(n as usize);
        let mut total: u64 = 0;
        for _ in 0..n {
            let retention_slots = r.read_u64("GraphDefinitionV1.retention_slots")?;
            let e = r.read_u32("GraphDefinitionV1.edge_count")?;
            if e > Self::MAX_EDGES_PER_UNIT {
                return Err(DecodeError::CountExceedsMax {
                    ctx: "GraphDefinitionV1.edge_count",
                    count: e as u64,
                    max: Self::MAX_EDGES_PER_UNIT as u64,
                });
            }
            total += e as u64;
            if total > Self::MAX_TOTAL_EDGES as u64 {
                return Err(DecodeError::CountExceedsMax {
                    ctx: "GraphDefinitionV1.total_edges",
                    count: total,
                    max: Self::MAX_TOTAL_EDGES as u64,
                });
            }
            let mut edges = Vec::with_capacity(e as usize);
            let mut prev: Option<([u8; 32], [u8; 32], u8, u32)> = None;
            for _ in 0..e {
                let edge = DependencyEdgeV1::read(r)?;
                let key = edge.order_key();
                if let Some(p) = prev {
                    match p.cmp(&key) {
                        std::cmp::Ordering::Less => {}
                        std::cmp::Ordering::Equal => {
                            return Err(DecodeError::DuplicateEntry {
                                ctx: "GraphDefinitionV1.edges",
                            })
                        }
                        std::cmp::Ordering::Greater => {
                            return Err(DecodeError::NonCanonicalOrder {
                                ctx: "GraphDefinitionV1.edges",
                            })
                        }
                    }
                }
                prev = Some(key);
                edges.push(edge);
            }
            units.push(UnitDefV1 {
                retention_slots,
                edges,
            });
        }
        let g = Self { units };
        g.validate()?;
        Ok(g)
    }

    /// Decode a complete buffer. The byte ceiling is checked **first**, so an
    /// over-sized input is rejected before any parsing or allocation.
    pub fn decode_exact(bytes: &[u8]) -> Result<Self, DecodeError> {
        if bytes.len() as u64 > Self::MAX_GRAPH_BYTES {
            return Err(DecodeError::LengthExceedsMax {
                ctx: "GraphDefinitionV1",
                len: bytes.len() as u64,
                max: Self::MAX_GRAPH_BYTES,
            });
        }
        let mut r = Reader::new(bytes);
        let g = Self::decode(&mut r)?;
        r.finish("GraphDefinitionV1")?;
        Ok(g)
    }

    /// Bind the graph to a job: every edge's `predecessor_unit_id` must be
    /// `unit_id(job_id, j)` for some **`j < i`** (the referencing unit's index).
    ///
    /// Backward-only references make positional order a topological order, so the
    /// graph is a **DAG by construction** — no cycle search is needed, and self-,
    /// forward- and dangling references are all rejected as `BadValue`.
    ///
    /// `O(N + E)`: one pass derives the `unit_id → index` map (`≤ 32·N` bytes,
    /// `≤ N` hashes), then each edge is an `O(1)` lookup.
    pub fn verify_against_job(&self, job_id: &[u8; 32]) -> Result<(), DecodeError> {
        use std::collections::HashMap;
        let mut index: HashMap<[u8; 32], usize> = HashMap::with_capacity(self.units.len());
        for i in 0..self.units.len() {
            index.insert(unit_id(job_id, i as u32), i);
        }
        for (i, u) in self.units.iter().enumerate() {
            for e in &u.edges {
                match index.get(&e.predecessor_unit_id) {
                    Some(&j) if j < i => {}
                    _ => {
                        return Err(DecodeError::BadValue {
                            ctx: "GraphDefinitionV1.edge.predecessor_unit_id \
                                  (must be unit_id(job_id, j) with j < i)",
                        })
                    }
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- §K identifier golden vectors -------------------------------------- //
    // The draft's TEST_ONLY inputs, whose expected values were computed
    // INDEPENDENTLY with `b3sum 1.8.3`. Reproducing them here proves this
    // implementation adopts §K byte-for-byte (tag length, LE order, widths).
    fn kat_requester() -> Address {
        let mut a = [0u8; 20];
        for (i, b) in a.iter_mut().enumerate() {
            *b = (i + 1) as u8; // 0x01..0x14
        }
        Address::new(a)
    }

    #[test]
    fn job_id_matches_independent_b3sum_vector() {
        let jid = job_id(1, &kat_requester(), 7, &[0xAA; 32]);
        assert_eq!(
            hex::encode(jid),
            "8b974099e58a7005fd25ef863283958351b785e6bf4fb127cf0de5ca4d5c4f82"
        );
    }

    #[test]
    fn unit_id_matches_independent_b3sum_vector() {
        let jid = job_id(1, &kat_requester(), 7, &[0xAA; 32]);
        assert_eq!(
            hex::encode(unit_id(&jid, 0)),
            "3adf1cdd6b0f0f01f89cc627622736537bfcc44564e09b5805cf475490bb2662"
        );
    }

    #[test]
    fn tag_lengths_and_terminators_are_exact() {
        assert_eq!(POOL_JOB_TAG.len(), 21);
        assert_eq!(POOL_UNIT_TAG.len(), 22);
        assert_eq!(POOL_GRAPHDEF_TAG.len(), 26);
        for t in [POOL_JOB_TAG, POOL_UNIT_TAG, POOL_GRAPHDEF_TAG] {
            assert_eq!(*t.last().unwrap(), b'\n', "POOL family is \\n-terminated");
            assert_eq!(t.iter().filter(|&&b| b == b'\n').count(), 1);
        }
    }

    // ---- domain confusion: pool vs registry graph roots --------------------- //
    #[test]
    fn pool_and_registry_graph_domains_are_not_interchangeable() {
        let bytes = b"identical graph bytes";
        let pool = graph_definition_root(bytes);
        let registry = crate::registry_wire::graph_definition_root(bytes);
        assert_ne!(
            pool, registry,
            "a registry graph root must never equal a pool graph root over the same bytes"
        );
        // Prefix-freeness: neither tag is a prefix of the other.
        let (a, b) = (POOL_GRAPHDEF_TAG, crate::registry_wire::GRAPH_DEFINITION_TAG);
        assert!(!a.starts_with(b) && !b.starts_with(a));
    }

    #[test]
    fn pool_id_domains_are_mutually_distinct() {
        let d = b"x";
        let mut seen = std::collections::BTreeSet::new();
        for t in [POOL_JOB_TAG, POOL_UNIT_TAG, POOL_GRAPHDEF_TAG] {
            let mut h = blake3::Hasher::new();
            h.update(t);
            h.update(d);
            assert!(seen.insert(*h.finalize().as_bytes()), "domain collision");
        }
    }

    // ---- helpers ------------------------------------------------------------ //
    fn edge(pred: [u8; 32], slot_index: u32) -> DependencyEdgeV1 {
        DependencyEdgeV1 {
            predecessor_unit_id: pred,
            predecessor_output_manifest_identity: [0x77; 32],
            required_slot_kind: SlotKind::ResidualStream,
            required_slot_index: slot_index,
            required_state_object_identity: [0x88; 32],
        }
    }
    fn unit(edges: Vec<DependencyEdgeV1>) -> UnitDefV1 {
        UnitDefV1 { retention_slots: 4, edges }
    }

    // ---- round-trip + layout ------------------------------------------------ //
    #[test]
    fn edge_is_101_bytes_and_graph_roundtrips() {
        assert_eq!(DependencyEdgeV1::LEN, 101);
        let jid = job_id(1, &kat_requester(), 7, &[0xAA; 32]);
        let g = GraphDefinitionV1 {
            units: vec![unit(vec![]), unit(vec![edge(unit_id(&jid, 0), 0)])],
        };
        let bytes = g.try_encode().unwrap();
        assert_eq!(bytes.len() as u64, g.encoded_len());
        assert_eq!(bytes.len(), 13 + 2 * 12 + 101);
        assert_eq!(GraphDefinitionV1::decode_exact(&bytes).unwrap(), g);
    }

    // ---- DAG by construction (verify_against_job) --------------------------- //
    #[test]
    fn backward_edges_accepted_forward_self_dangling_rejected() {
        let jid = job_id(1, &kat_requester(), 7, &[0xAA; 32]);
        // unit1 -> unit0 (backward): OK
        let ok = GraphDefinitionV1 {
            units: vec![unit(vec![]), unit(vec![edge(unit_id(&jid, 0), 0)])],
        };
        assert!(ok.verify_against_job(&jid).is_ok());

        // self-reference (i -> i)
        let selfref = GraphDefinitionV1 {
            units: vec![unit(vec![]), unit(vec![edge(unit_id(&jid, 1), 0)])],
        };
        assert!(matches!(
            selfref.verify_against_job(&jid),
            Err(DecodeError::BadValue { .. })
        ));

        // forward reference (0 -> 1) would create a cycle in index order
        let fwd = GraphDefinitionV1 {
            units: vec![unit(vec![edge(unit_id(&jid, 1), 0)]), unit(vec![])],
        };
        assert!(matches!(
            fwd.verify_against_job(&jid),
            Err(DecodeError::BadValue { .. })
        ));

        // dangling (not a unit of this job)
        let dangling = GraphDefinitionV1 {
            units: vec![unit(vec![]), unit(vec![edge([0xEE; 32], 0)])],
        };
        assert!(matches!(
            dangling.verify_against_job(&jid),
            Err(DecodeError::BadValue { .. })
        ));

        // right structure, WRONG job: unit ids don't resolve under another job_id
        let other = job_id(2, &kat_requester(), 7, &[0xAA; 32]);
        assert!(matches!(
            ok.verify_against_job(&other),
            Err(DecodeError::BadValue { .. })
        ));
    }

    // ---- canonical ordering + uniqueness ------------------------------------ //
    #[test]
    fn edges_must_be_strictly_ascending_and_unique() {
        let jid = job_id(1, &kat_requester(), 7, &[0xAA; 32]);
        let p = unit_id(&jid, 0);
        let (a, b) = (edge(p, 0), edge(p, 1));

        let good = GraphDefinitionV1 { units: vec![unit(vec![]), unit(vec![a, b])] };
        assert!(good.try_encode().is_ok());

        let desc = GraphDefinitionV1 { units: vec![unit(vec![]), unit(vec![b, a])] };
        assert!(matches!(
            desc.validate(),
            Err(DecodeError::NonCanonicalOrder { .. })
        ));

        let dup = GraphDefinitionV1 { units: vec![unit(vec![]), unit(vec![a, a])] };
        assert!(matches!(
            dup.validate(),
            Err(DecodeError::DuplicateEntry { .. })
        ));

        // Ordering is enforced on DECODE too (not just encode).
        let mut w = Writer::new();
        w.bytes(&GraphDefinitionV1::MAGIC);
        w.u16(GraphDefinitionV1::SCHEMA_VERSION);
        w.u32(2);
        w.u64(4); w.u32(0);
        w.u64(4); w.u32(2);
        for e in [b, a] { // descending on the wire
            w.bytes(&e.predecessor_unit_id);
            w.bytes(&e.predecessor_output_manifest_identity);
            w.u8(e.required_slot_kind.to_u8());
            w.u32(e.required_slot_index);
            w.bytes(&e.required_state_object_identity);
        }
        assert!(matches!(
            GraphDefinitionV1::decode_exact(&w.into_bytes()),
            Err(DecodeError::NonCanonicalOrder { .. })
        ));
    }

    // ---- derived limits: boundary at limit and limit+1 ---------------------- //
    #[test]
    fn derivation_arithmetic_is_exact() {
        const C: u64 = GraphDefinitionV1::MAX_GRAPH_BYTES;
        let (h, pu, pe) = (
            GraphDefinitionV1::HEADER_LEN,
            GraphDefinitionV1::PER_UNIT_LEN,
            GraphDefinitionV1::PER_EDGE_LEN,
        );
        assert_eq!((h, pu, pe), (13, 12, 101));
        // MAX_UNITS is the largest N with E=0 that fits; N+1 does not.
        let n = GraphDefinitionV1::MAX_UNITS as u64;
        assert_eq!(n, 87_380);
        assert!(h + pu * n <= C);
        assert!(h + pu * (n + 1) > C);
        // MAX_TOTAL_EDGES is the largest E at the minimum unit count that can
        // host edges (N=2, since backward-only edges leave unit 0 with none).
        let e = GraphDefinitionV1::MAX_TOTAL_EDGES as u64;
        assert_eq!(e, 10_381);
        assert!(h + 2 * pu + pe * e <= C);
        assert!(h + 2 * pu + pe * (e + 1) > C);
        // A single unit may hold every edge, so the per-unit cap is the total.
        assert_eq!(
            GraphDefinitionV1::MAX_EDGES_PER_UNIT,
            GraphDefinitionV1::MAX_TOTAL_EDGES
        );
    }

    #[test]
    fn ceiling_matches_c1_decode_limit() {
        // Pins the relationship to the pre-existing ceiling the limits derive from
        // (sumchain-state::compute_pool_store::C1_DECODE_BYTE_LIMIT = 1 << 20).
        assert_eq!(GraphDefinitionV1::MAX_GRAPH_BYTES, 1 << 20);
    }

    #[test]
    fn max_units_boundary_accepts_at_limit_and_rejects_limit_plus_one() {
        let n = GraphDefinitionV1::MAX_UNITS as usize;
        let at = GraphDefinitionV1 {
            units: (0..n).map(|_| unit(vec![])).collect(),
        };
        assert!(at.validate().is_ok());
        // PROOF: the maximal accepted graph fits the decode envelope.
        assert!(at.encoded_len() <= GraphDefinitionV1::MAX_GRAPH_BYTES);
        assert_eq!(at.try_encode().unwrap().len() as u64, at.encoded_len());

        let over = GraphDefinitionV1 {
            units: (0..n + 1).map(|_| unit(vec![])).collect(),
        };
        assert!(matches!(
            over.validate(),
            Err(DecodeError::CountExceedsMax { .. })
        ));
    }

    #[test]
    fn max_total_edges_boundary_accepts_at_limit_and_rejects_limit_plus_one() {
        let jid = job_id(1, &kat_requester(), 7, &[0xAA; 32]);
        let p = unit_id(&jid, 0);
        let e = GraphDefinitionV1::MAX_TOTAL_EDGES;
        let mk = |count: u32| GraphDefinitionV1 {
            units: vec![unit(vec![]), unit((0..count).map(|i| edge(p, i)).collect())],
        };
        let at = mk(e);
        assert!(at.validate().is_ok());
        assert!(at.encoded_len() <= GraphDefinitionV1::MAX_GRAPH_BYTES);
        assert!(at.verify_against_job(&jid).is_ok());
        assert!(matches!(
            mk(e + 1).validate(),
            Err(DecodeError::CountExceedsMax { .. })
        ));
    }

    // ---- allocation-before-validation + overflow ---------------------------- //
    #[test]
    fn declared_counts_are_bounded_before_any_allocation() {
        // unit_count = u32::MAX with NO backing bytes: must fail on the count
        // guard, never attempt a u32::MAX-element allocation.
        let mut w = Writer::new();
        w.bytes(&GraphDefinitionV1::MAGIC);
        w.u16(GraphDefinitionV1::SCHEMA_VERSION);
        w.u32(u32::MAX);
        assert!(matches!(
            GraphDefinitionV1::decode_exact(&w.into_bytes()),
            Err(DecodeError::CountExceedsMax { .. })
        ));

        // edge_count = u32::MAX with no backing bytes: same.
        let mut w = Writer::new();
        w.bytes(&GraphDefinitionV1::MAGIC);
        w.u16(GraphDefinitionV1::SCHEMA_VERSION);
        w.u32(1);
        w.u64(0);
        w.u32(u32::MAX);
        assert!(matches!(
            GraphDefinitionV1::decode_exact(&w.into_bytes()),
            Err(DecodeError::CountExceedsMax { .. })
        ));
    }

    #[test]
    fn running_total_edges_is_bounded_across_units() {
        // Each unit is individually under MAX_EDGES_PER_UNIT, but the running
        // total crosses MAX_TOTAL_EDGES -> rejected (no unbounded accumulation).
        let per = GraphDefinitionV1::MAX_TOTAL_EDGES / 2 + 1;
        let jid = job_id(1, &kat_requester(), 7, &[0xAA; 32]);
        let p = unit_id(&jid, 0);
        let g = GraphDefinitionV1 {
            units: vec![
                unit(vec![]),
                unit((0..per).map(|i| edge(p, i)).collect()),
                unit((0..per).map(|i| edge(p, i)).collect()),
            ],
        };
        assert!(matches!(
            g.validate(),
            Err(DecodeError::CountExceedsMax { .. })
        ));
    }

    #[test]
    fn size_math_cannot_overflow() {
        // N and E are u32; the u64 size math is exact at the extremes.
        let n = u32::MAX as u64;
        let e = u32::MAX as u64;
        let size = GraphDefinitionV1::HEADER_LEN
            + GraphDefinitionV1::PER_UNIT_LEN * n
            + GraphDefinitionV1::PER_EDGE_LEN * e;
        assert!(size < u64::MAX / 2, "u64 headroom is ample; no wraparound");
        assert!(size > GraphDefinitionV1::MAX_GRAPH_BYTES);
    }

    #[test]
    fn oversized_buffer_rejected_before_parsing() {
        let big = vec![0u8; (GraphDefinitionV1::MAX_GRAPH_BYTES + 1) as usize];
        assert!(matches!(
            GraphDefinitionV1::decode_exact(&big),
            Err(DecodeError::LengthExceedsMax { .. })
        ));
    }

    // ---- malformed surface --------------------------------------------------- //
    #[test]
    fn malformed_inputs_rejected() {
        let g = GraphDefinitionV1 { units: vec![unit(vec![])] };
        let good = g.try_encode().unwrap();

        let mut bad_magic = good.clone();
        bad_magic[0] ^= 0xFF;
        assert!(matches!(
            GraphDefinitionV1::decode_exact(&bad_magic),
            Err(DecodeError::BadTag { .. })
        ));

        let mut bad_schema = good.clone();
        bad_schema[7] = 9;
        assert!(matches!(
            GraphDefinitionV1::decode_exact(&bad_schema),
            Err(DecodeError::BadFixedScalar { .. })
        ));

        let mut trailing = good.clone();
        trailing.push(0);
        assert!(matches!(
            GraphDefinitionV1::decode_exact(&trailing),
            Err(DecodeError::TrailingBytes { .. })
        ));

        assert!(matches!(
            GraphDefinitionV1::decode_exact(&good[..good.len() - 1]),
            Err(DecodeError::Truncated { .. })
        ));
    }

    #[test]
    fn reserved_slot_kind_rejected() {
        assert_eq!(SlotKind::from_u8(0).unwrap(), SlotKind::ResidualStream);
        assert_eq!(SlotKind::from_u8(1).unwrap(), SlotKind::KvCache);
        for v in [2u8, 6, 7, 255] {
            assert!(matches!(
                SlotKind::from_u8(v),
                Err(DecodeError::BadEnum { name: "SlotKind", .. })
            ));
        }
        // The implied ObjectKind is never encoded, only derived.
        assert_eq!(SlotKind::ResidualStream.object_kind_repr(), 6);
        assert_eq!(SlotKind::KvCache.object_kind_repr(), 7);
    }
}
