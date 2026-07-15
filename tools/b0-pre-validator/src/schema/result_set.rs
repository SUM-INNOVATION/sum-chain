//! `R0ResultSetV1` — variable (plan §8/§23).
//!
//! The per-candidate completeness envelope. Every sub-list is strictly ascending
//! by its canonical key (duplicates rejected), counts are bounded before
//! allocation, and `r0_result_set_hash = BLAKE3(RESULTSET ‖ canonical_bytes)`.

use crate::codec::{DecodeError, Reader, Writer};
use crate::consts;
use crate::enums::{
    Arch, Candidate, MetricKind, ProvenanceRole, RssScope, SampleKind, StatementIndex,
};
use crate::hashing;
use crate::tags::RESULTSET_PREFIX;

pub const MAX_ARCH_PROV: u32 = 8;
pub const MAX_MEASURED_PROOFS: u32 = 256;
pub const MAX_SAMPLE_BUNDLES: u32 = 256;
pub const MAX_RSS_BUNDLES: u32 = 64;
pub const MAX_FAILURE_CODES: u32 = 64;

fn read_bool(r: &mut Reader, ctx: &'static str) -> Result<bool, DecodeError> {
    match r.read_u8(ctx)? {
        0 => Ok(false),
        1 => Ok(true),
        v => Err(DecodeError::BadFixedScalar {
            ctx,
            value: v as u64,
        }),
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ArchProvenanceRef {
    pub arch: Arch,
    pub role: ProvenanceRole,
    pub provenance_hash: [u8; 32],
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MeasuredProofRef {
    pub arch: Arch,
    pub statement_index: StatementIndex,
    pub iteration_index: u32,
    pub envelope_hash: [u8; 32],
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SampleBundle {
    pub arch: Arch,
    pub statement_index: StatementIndex,
    pub metric_kind: MetricKind,
    pub sample_kind: SampleKind,
    pub sample_count: u32,
    pub bundle_hash: [u8; 32],
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RssBundle {
    pub arch: Arch,
    pub rss_scope: RssScope,
    pub record_count: u32,
    pub bundle_hash: [u8; 32],
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Completeness {
    pub measured_proof_count: u32,
    pub verify_timing_sample_count: u32,
    pub proving_time_sample_count: u32,
    pub proving_run_rss_count: u32,
    pub verify_batch_rss_count: u32,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Aggregates {
    pub max_proof_bytes: u32,
    pub worst_arch_p99_verify_ns: u64,
    pub verifier_material_bytes: u64,
    pub worst_arch_verifier_rss_bytes: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct R0ResultSetV1 {
    pub b0_pre_spec_hash: [u8; 32],
    pub r0_guest_set_hash: [u8; 32],
    pub candidate: Candidate,
    pub verifier_material_manifest_hash: [u8; 32],
    pub official_statement_hash_tlg: [u8; 32],
    pub official_statement_hash_st: [u8; 32],
    pub arch_provenance: Vec<ArchProvenanceRef>,
    pub measured_proofs: Vec<MeasuredProofRef>,
    pub sample_bundles: Vec<SampleBundle>,
    pub rss_bundles: Vec<RssBundle>,
    pub malformed_corpus_result_hash: [u8; 32],
    pub cycle_bundle: Option<(u32, [u8; 32])>,
    pub completeness: Completeness,
    pub aggregates: Aggregates,
    pub qualification_result: bool,
    pub failure_codes: Vec<u16>,
}

impl R0ResultSetV1 {
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.u16(consts::SCHEMA_VERSION);
        w.bytes(&self.b0_pre_spec_hash);
        w.bytes(&self.r0_guest_set_hash);
        w.u16(self.candidate.to_repr());
        w.bytes(&self.verifier_material_manifest_hash);
        w.bytes(&self.official_statement_hash_tlg);
        w.bytes(&self.official_statement_hash_st);

        w.u32(self.arch_provenance.len() as u32);
        for a in &self.arch_provenance {
            w.u8(a.arch.to_repr());
            w.u8(a.role.to_repr());
            w.bytes(&a.provenance_hash);
        }
        w.u32(self.measured_proofs.len() as u32);
        for m in &self.measured_proofs {
            w.u8(m.arch.to_repr());
            w.u8(m.statement_index.to_repr());
            w.u32(m.iteration_index);
            w.bytes(&m.envelope_hash);
        }
        w.u32(self.sample_bundles.len() as u32);
        for s in &self.sample_bundles {
            w.u8(s.arch.to_repr());
            w.u8(s.statement_index.to_repr());
            w.u8(s.metric_kind.to_repr());
            w.u8(s.sample_kind.to_repr());
            w.u32(s.sample_count);
            w.bytes(&s.bundle_hash);
        }
        w.u32(self.rss_bundles.len() as u32);
        for s in &self.rss_bundles {
            w.u8(s.arch.to_repr());
            w.u8(s.rss_scope.to_repr());
            w.u32(s.record_count);
            w.bytes(&s.bundle_hash);
        }
        w.bytes(&self.malformed_corpus_result_hash);
        match &self.cycle_bundle {
            None => w.u8(0),
            Some((count, hash)) => {
                w.u8(1);
                w.u32(*count);
                w.bytes(hash);
            }
        }
        w.u32(self.completeness.measured_proof_count);
        w.u32(self.completeness.verify_timing_sample_count);
        w.u32(self.completeness.proving_time_sample_count);
        w.u32(self.completeness.proving_run_rss_count);
        w.u32(self.completeness.verify_batch_rss_count);
        w.u32(self.aggregates.max_proof_bytes);
        w.u64(self.aggregates.worst_arch_p99_verify_ns);
        w.u64(self.aggregates.verifier_material_bytes);
        w.u64(self.aggregates.worst_arch_verifier_rss_bytes);
        w.u8(if self.qualification_result { 1 } else { 0 });
        w.u32(self.failure_codes.len() as u32);
        for c in &self.failure_codes {
            w.u16(*c);
        }
        w.into_bytes()
    }

    pub fn result_set_hash(&self) -> [u8; 32] {
        hashing::prefixed(RESULTSET_PREFIX, &self.encode())
    }

    pub fn decode(r: &mut Reader) -> Result<Self, DecodeError> {
        let sv = r.read_u16("R0ResultSetV1.schema_version")?;
        if sv != consts::SCHEMA_VERSION {
            return Err(DecodeError::BadFixedScalar {
                ctx: "R0ResultSetV1.schema_version",
                value: sv as u64,
            });
        }
        let b0_pre_spec_hash = r.read_array::<32>("R0ResultSetV1.b0_pre_spec_hash")?;
        let r0_guest_set_hash = r.read_array::<32>("R0ResultSetV1.r0_guest_set_hash")?;
        let candidate = Candidate::from_repr(r.read_u16("R0ResultSetV1.candidate_id")?)?;
        let verifier_material_manifest_hash =
            r.read_array::<32>("R0ResultSetV1.verifier_material_manifest_hash")?;
        let official_statement_hash_tlg =
            r.read_array::<32>("R0ResultSetV1.official_statement_hash_tlg")?;
        let official_statement_hash_st =
            r.read_array::<32>("R0ResultSetV1.official_statement_hash_st")?;

        let ap_count = r.read_u32("R0ResultSetV1.arch_provenance_count")?;
        if ap_count > MAX_ARCH_PROV {
            return Err(DecodeError::CountExceedsMax {
                ctx: "R0ResultSetV1.arch_provenance_count",
                count: ap_count as u64,
                max: MAX_ARCH_PROV as u64,
            });
        }
        let mut arch_provenance = Vec::with_capacity(ap_count as usize);
        let mut prev: Option<(u8, u8)> = None;
        for _ in 0..ap_count {
            let arch = Arch::from_repr(r.read_u8("R0ResultSetV1.ap.arch")?)?;
            let role = ProvenanceRole::from_repr(r.read_u8("R0ResultSetV1.ap.role")?)?;
            let provenance_hash = r.read_array::<32>("R0ResultSetV1.ap.hash")?;
            let key = (arch.to_repr(), role.to_repr());
            check_order(&mut prev, key, "R0ResultSetV1.arch_provenance")?;
            arch_provenance.push(ArchProvenanceRef {
                arch,
                role,
                provenance_hash,
            });
        }

        let mp_count = r.read_u32("R0ResultSetV1.measured_proof_count")?;
        if mp_count > MAX_MEASURED_PROOFS {
            return Err(DecodeError::CountExceedsMax {
                ctx: "R0ResultSetV1.measured_proof_count",
                count: mp_count as u64,
                max: MAX_MEASURED_PROOFS as u64,
            });
        }
        let mut measured_proofs = Vec::with_capacity(mp_count as usize);
        let mut prevm: Option<(u8, u8, u32)> = None;
        for _ in 0..mp_count {
            let arch = Arch::from_repr(r.read_u8("R0ResultSetV1.mp.arch")?)?;
            let statement_index =
                StatementIndex::from_repr(r.read_u8("R0ResultSetV1.mp.statement_index")?)?;
            let iteration_index = r.read_u32("R0ResultSetV1.mp.iteration_index")?;
            let envelope_hash = r.read_array::<32>("R0ResultSetV1.mp.envelope_hash")?;
            let key = (arch.to_repr(), statement_index.to_repr(), iteration_index);
            check_order(&mut prevm, key, "R0ResultSetV1.measured_proofs")?;
            measured_proofs.push(MeasuredProofRef {
                arch,
                statement_index,
                iteration_index,
                envelope_hash,
            });
        }

        let sb_count = r.read_u32("R0ResultSetV1.sample_bundle_count")?;
        if sb_count > MAX_SAMPLE_BUNDLES {
            return Err(DecodeError::CountExceedsMax {
                ctx: "R0ResultSetV1.sample_bundle_count",
                count: sb_count as u64,
                max: MAX_SAMPLE_BUNDLES as u64,
            });
        }
        let mut sample_bundles = Vec::with_capacity(sb_count as usize);
        let mut prevs: Option<(u8, u8, u8, u8)> = None;
        for _ in 0..sb_count {
            let arch = Arch::from_repr(r.read_u8("R0ResultSetV1.sb.arch")?)?;
            let statement_index =
                StatementIndex::from_repr(r.read_u8("R0ResultSetV1.sb.statement_index")?)?;
            let metric_kind = MetricKind::from_repr(r.read_u8("R0ResultSetV1.sb.metric_kind")?)?;
            let sample_kind = SampleKind::from_repr(r.read_u8("R0ResultSetV1.sb.sample_kind")?)?;
            let sample_count = r.read_u32("R0ResultSetV1.sb.sample_count")?;
            let bundle_hash = r.read_array::<32>("R0ResultSetV1.sb.bundle_hash")?;
            let key = (
                arch.to_repr(),
                statement_index.to_repr(),
                metric_kind.to_repr(),
                sample_kind.to_repr(),
            );
            check_order(&mut prevs, key, "R0ResultSetV1.sample_bundles")?;
            sample_bundles.push(SampleBundle {
                arch,
                statement_index,
                metric_kind,
                sample_kind,
                sample_count,
                bundle_hash,
            });
        }

        let rb_count = r.read_u32("R0ResultSetV1.rss_bundle_count")?;
        if rb_count > MAX_RSS_BUNDLES {
            return Err(DecodeError::CountExceedsMax {
                ctx: "R0ResultSetV1.rss_bundle_count",
                count: rb_count as u64,
                max: MAX_RSS_BUNDLES as u64,
            });
        }
        let mut rss_bundles = Vec::with_capacity(rb_count as usize);
        let mut prevr: Option<(u8, u8)> = None;
        for _ in 0..rb_count {
            let arch = Arch::from_repr(r.read_u8("R0ResultSetV1.rb.arch")?)?;
            let rss_scope = RssScope::from_repr(r.read_u8("R0ResultSetV1.rb.rss_scope")?)?;
            let record_count = r.read_u32("R0ResultSetV1.rb.record_count")?;
            let bundle_hash = r.read_array::<32>("R0ResultSetV1.rb.bundle_hash")?;
            let key = (arch.to_repr(), rss_scope.to_repr());
            check_order(&mut prevr, key, "R0ResultSetV1.rss_bundles")?;
            rss_bundles.push(RssBundle {
                arch,
                rss_scope,
                record_count,
                bundle_hash,
            });
        }

        let malformed_corpus_result_hash =
            r.read_array::<32>("R0ResultSetV1.malformed_corpus_result_hash")?;
        let cycle_bundle = if read_bool(r, "R0ResultSetV1.cycle_bundle_present")? {
            let count = r.read_u32("R0ResultSetV1.cycle_record_count")?;
            let hash = r.read_array::<32>("R0ResultSetV1.cycle_bundle_hash")?;
            Some((count, hash))
        } else {
            None
        };

        let completeness = Completeness {
            measured_proof_count: r.read_u32("R0ResultSetV1.completeness.measured_proof_count")?,
            verify_timing_sample_count: r
                .read_u32("R0ResultSetV1.completeness.verify_timing_sample_count")?,
            proving_time_sample_count: r
                .read_u32("R0ResultSetV1.completeness.proving_time_sample_count")?,
            proving_run_rss_count: r
                .read_u32("R0ResultSetV1.completeness.proving_run_rss_count")?,
            verify_batch_rss_count: r
                .read_u32("R0ResultSetV1.completeness.verify_batch_rss_count")?,
        };
        let aggregates = Aggregates {
            max_proof_bytes: r.read_u32("R0ResultSetV1.aggregates.max_proof_bytes")?,
            worst_arch_p99_verify_ns: r
                .read_u64("R0ResultSetV1.aggregates.worst_arch_p99_verify_ns")?,
            verifier_material_bytes: r
                .read_u64("R0ResultSetV1.aggregates.verifier_material_bytes")?,
            worst_arch_verifier_rss_bytes: r
                .read_u64("R0ResultSetV1.aggregates.worst_arch_verifier_rss_bytes")?,
        };
        let qualification_result = read_bool(r, "R0ResultSetV1.qualification_result")?;

        let fc_count = r.read_u32("R0ResultSetV1.failure_code_count")?;
        if fc_count > MAX_FAILURE_CODES {
            return Err(DecodeError::CountExceedsMax {
                ctx: "R0ResultSetV1.failure_code_count",
                count: fc_count as u64,
                max: MAX_FAILURE_CODES as u64,
            });
        }
        let mut failure_codes = Vec::with_capacity(fc_count as usize);
        let mut prevf: Option<u16> = None;
        for _ in 0..fc_count {
            let c = r.read_u16("R0ResultSetV1.failure_code")?;
            if let Some(p) = prevf {
                if c == p {
                    return Err(DecodeError::DuplicateEntry {
                        ctx: "R0ResultSetV1.failure_codes",
                    });
                }
                if c < p {
                    return Err(DecodeError::NonCanonicalOrder {
                        ctx: "R0ResultSetV1.failure_codes",
                    });
                }
            }
            prevf = Some(c);
            failure_codes.push(c);
        }

        Ok(Self {
            b0_pre_spec_hash,
            r0_guest_set_hash,
            candidate,
            verifier_material_manifest_hash,
            official_statement_hash_tlg,
            official_statement_hash_st,
            arch_provenance,
            measured_proofs,
            sample_bundles,
            rss_bundles,
            malformed_corpus_result_hash,
            cycle_bundle,
            completeness,
            aggregates,
            qualification_result,
            failure_codes,
        })
    }

    pub fn decode_exact(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut r = Reader::new(bytes);
        let v = Self::decode(&mut r)?;
        r.finish("R0ResultSetV1")?;
        Ok(v)
    }
}

fn check_order<K: Ord + Copy>(
    prev: &mut Option<K>,
    key: K,
    ctx: &'static str,
) -> Result<(), DecodeError> {
    if let Some(p) = *prev {
        if key == p {
            return Err(DecodeError::DuplicateEntry { ctx });
        }
        if key < p {
            return Err(DecodeError::NonCanonicalOrder { ctx });
        }
    }
    *prev = Some(key);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn full() -> R0ResultSetV1 {
        R0ResultSetV1 {
            b0_pre_spec_hash: [1; 32],
            r0_guest_set_hash: [2; 32],
            candidate: Candidate::Sp1,
            verifier_material_manifest_hash: [3; 32],
            official_statement_hash_tlg: [4; 32],
            official_statement_hash_st: [5; 32],
            arch_provenance: vec![
                ArchProvenanceRef {
                    arch: Arch::X86_64,
                    role: ProvenanceRole::Proving,
                    provenance_hash: [10; 32],
                },
                ArchProvenanceRef {
                    arch: Arch::X86_64,
                    role: ProvenanceRole::Verification,
                    provenance_hash: [11; 32],
                },
                ArchProvenanceRef {
                    arch: Arch::Aarch64,
                    role: ProvenanceRole::Proving,
                    provenance_hash: [12; 32],
                },
                ArchProvenanceRef {
                    arch: Arch::Aarch64,
                    role: ProvenanceRole::Verification,
                    provenance_hash: [13; 32],
                },
            ],
            measured_proofs: vec![
                MeasuredProofRef {
                    arch: Arch::X86_64,
                    statement_index: StatementIndex::Tlg,
                    iteration_index: 0,
                    envelope_hash: [20; 32],
                },
                MeasuredProofRef {
                    arch: Arch::X86_64,
                    statement_index: StatementIndex::Tlg,
                    iteration_index: 1,
                    envelope_hash: [21; 32],
                },
            ],
            sample_bundles: vec![SampleBundle {
                arch: Arch::X86_64,
                statement_index: StatementIndex::Tlg,
                metric_kind: MetricKind::HostVerifyNs,
                sample_kind: SampleKind::Measured,
                sample_count: 1000,
                bundle_hash: [30; 32],
            }],
            rss_bundles: vec![RssBundle {
                arch: Arch::X86_64,
                rss_scope: RssScope::VerifyBatch,
                record_count: 40,
                bundle_hash: [40; 32],
            }],
            malformed_corpus_result_hash: [50; 32],
            cycle_bundle: Some((123, [60; 32])),
            completeness: Completeness {
                measured_proof_count: 40,
                verify_timing_sample_count: 4000,
                proving_time_sample_count: 40,
                proving_run_rss_count: 40,
                verify_batch_rss_count: 40,
            },
            aggregates: Aggregates {
                max_proof_bytes: 260,
                worst_arch_p99_verify_ns: 74_000_000,
                verifier_material_bytes: 292,
                worst_arch_verifier_rss_bytes: 100 << 20,
            },
            qualification_result: true,
            failure_codes: vec![],
        }
    }

    #[test]
    fn full_result_set_roundtrips_and_hashes() {
        let rs = full();
        assert_eq!(R0ResultSetV1::decode_exact(&rs.encode()).unwrap(), rs);
        assert_eq!(
            rs.result_set_hash(),
            hashing::prefixed(RESULTSET_PREFIX, &rs.encode())
        );
    }

    #[test]
    fn cycle_bundle_absent_roundtrips() {
        let mut rs = full();
        rs.cycle_bundle = None;
        assert_eq!(R0ResultSetV1::decode_exact(&rs.encode()).unwrap(), rs);
    }

    #[test]
    fn unsorted_arch_provenance_rejected() {
        let mut rs = full();
        rs.arch_provenance.swap(0, 2); // break ascending (arch, role)
        assert!(matches!(
            R0ResultSetV1::decode_exact(&rs.encode()),
            Err(DecodeError::NonCanonicalOrder {
                ctx: "R0ResultSetV1.arch_provenance"
            })
        ));
    }

    #[test]
    fn duplicate_measured_proof_rejected() {
        let mut rs = full();
        rs.measured_proofs[1] = rs.measured_proofs[0].clone();
        assert!(matches!(
            R0ResultSetV1::decode_exact(&rs.encode()),
            Err(DecodeError::DuplicateEntry {
                ctx: "R0ResultSetV1.measured_proofs"
            })
        ));
    }

    #[test]
    fn unsorted_failure_codes_rejected() {
        let mut rs = full();
        rs.failure_codes = vec![5, 3];
        assert!(matches!(
            R0ResultSetV1::decode_exact(&rs.encode()),
            Err(DecodeError::NonCanonicalOrder {
                ctx: "R0ResultSetV1.failure_codes"
            })
        ));
    }

    #[test]
    fn truncation_and_trailing_rejected() {
        let bytes = full().encode();
        assert!(matches!(
            R0ResultSetV1::decode_exact(&bytes[..bytes.len() - 1]),
            Err(DecodeError::Truncated { .. })
        ));
        let mut long = bytes;
        long.push(0);
        assert!(matches!(
            R0ResultSetV1::decode_exact(&long),
            Err(DecodeError::TrailingBytes { .. })
        ));
    }
}
