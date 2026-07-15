//! `BenchmarkSampleV1` — 309 bytes — and `BenchmarkRssRecordV1` — 306 bytes
//! (plan §8). Both bind the full guest-set identity so a record cannot be mixed
//! across spec/guest-set/candidate/program/container/arch/statement/proof.

use crate::codec::{DecodeError, Reader, Writer};
use crate::consts;
use crate::enums::{Arch, Candidate, MetricKind, RssScope, SampleKind, Status, Unit};
use crate::tags::{BENCH_RSS_TAG, BENCH_SAMPLE_TAG};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BenchmarkSampleV1 {
    pub b0_pre_spec_hash: [u8; 32],
    pub r0_guest_set_hash: [u8; 32],
    pub computation_statement_hash: [u8; 32],
    pub candidate: Candidate,
    pub guest_program_id: [u8; 32],
    pub verifier_material_manifest_hash: [u8; 32],
    pub candidate_dep_lock_hash: [u8; 32],
    pub container_image_digest: [u8; 32],
    pub arch: Arch,
    pub sample_kind: SampleKind,
    pub metric_kind: MetricKind,
    pub unit: Unit,
    pub value: u64,
    pub proof_hash: [u8; 32],
    pub iteration_index: u32,
    pub status: Status,
}

impl BenchmarkSampleV1 {
    pub const LEN: usize = 309;

    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.tag(&BENCH_SAMPLE_TAG);
        w.u16(consts::SCHEMA_VERSION);
        w.bytes(&self.b0_pre_spec_hash);
        w.bytes(&self.r0_guest_set_hash);
        w.bytes(&self.computation_statement_hash);
        w.u16(self.candidate.to_repr());
        w.bytes(&self.guest_program_id);
        w.bytes(&self.verifier_material_manifest_hash);
        w.bytes(&self.candidate_dep_lock_hash);
        w.bytes(&self.container_image_digest);
        w.u8(self.arch.to_repr());
        w.u8(self.sample_kind.to_repr());
        w.u8(self.metric_kind.to_repr());
        w.u8(self.unit.to_repr());
        w.u64(self.value);
        w.bytes(&self.proof_hash);
        w.u32(self.iteration_index);
        w.u8(self.status.to_repr());
        w.into_bytes()
    }

    pub fn decode(r: &mut Reader) -> Result<Self, DecodeError> {
        let tag = r.read_array::<32>("BenchmarkSampleV1.tag")?;
        if tag != BENCH_SAMPLE_TAG {
            return Err(DecodeError::BadTag {
                ctx: "BenchmarkSampleV1",
            });
        }
        let sv = r.read_u16("BenchmarkSampleV1.schema_version")?;
        if sv != consts::SCHEMA_VERSION {
            return Err(DecodeError::BadFixedScalar {
                ctx: "BenchmarkSampleV1.schema_version",
                value: sv as u64,
            });
        }
        let b0_pre_spec_hash = r.read_array::<32>("BenchmarkSampleV1.b0_pre_spec_hash")?;
        let r0_guest_set_hash = r.read_array::<32>("BenchmarkSampleV1.r0_guest_set_hash")?;
        let computation_statement_hash =
            r.read_array::<32>("BenchmarkSampleV1.computation_statement_hash")?;
        let candidate = Candidate::from_repr(r.read_u16("BenchmarkSampleV1.candidate_id")?)?;
        let guest_program_id = r.read_array::<32>("BenchmarkSampleV1.guest_program_id")?;
        let verifier_material_manifest_hash =
            r.read_array::<32>("BenchmarkSampleV1.verifier_material_manifest_hash")?;
        let candidate_dep_lock_hash =
            r.read_array::<32>("BenchmarkSampleV1.candidate_dep_lock_hash")?;
        let container_image_digest =
            r.read_array::<32>("BenchmarkSampleV1.container_image_digest")?;
        let arch = Arch::from_repr(r.read_u8("BenchmarkSampleV1.arch")?)?;
        let sample_kind = SampleKind::from_repr(r.read_u8("BenchmarkSampleV1.sample_kind")?)?;
        let metric_kind = MetricKind::from_repr(r.read_u8("BenchmarkSampleV1.metric_kind")?)?;
        let unit = Unit::from_repr(r.read_u8("BenchmarkSampleV1.unit")?)?;
        let value = r.read_u64("BenchmarkSampleV1.value")?;
        let proof_hash = r.read_array::<32>("BenchmarkSampleV1.proof_hash")?;
        let iteration_index = r.read_u32("BenchmarkSampleV1.iteration_index")?;
        let status = Status::from_repr(r.read_u8("BenchmarkSampleV1.status")?)?;
        Ok(Self {
            b0_pre_spec_hash,
            r0_guest_set_hash,
            computation_statement_hash,
            candidate,
            guest_program_id,
            verifier_material_manifest_hash,
            candidate_dep_lock_hash,
            container_image_digest,
            arch,
            sample_kind,
            metric_kind,
            unit,
            value,
            proof_hash,
            iteration_index,
            status,
        })
    }

    pub fn decode_exact(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut r = Reader::new(bytes);
        let v = Self::decode(&mut r)?;
        r.finish("BenchmarkSampleV1")?;
        Ok(v)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BenchmarkRssRecordV1 {
    pub b0_pre_spec_hash: [u8; 32],
    pub r0_guest_set_hash: [u8; 32],
    pub computation_statement_hash: [u8; 32],
    pub candidate: Candidate,
    pub guest_program_id: [u8; 32],
    pub verifier_material_manifest_hash: [u8; 32],
    pub candidate_dep_lock_hash: [u8; 32],
    pub container_image_digest: [u8; 32],
    pub arch: Arch,
    pub rss_scope: RssScope,
    pub proof_hash: [u8; 32],
    pub run_index: u32,
    pub peak_rss_bytes: u64,
}

impl BenchmarkRssRecordV1 {
    pub const LEN: usize = 306;

    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.tag(&BENCH_RSS_TAG);
        w.u16(consts::SCHEMA_VERSION);
        w.bytes(&self.b0_pre_spec_hash);
        w.bytes(&self.r0_guest_set_hash);
        w.bytes(&self.computation_statement_hash);
        w.u16(self.candidate.to_repr());
        w.bytes(&self.guest_program_id);
        w.bytes(&self.verifier_material_manifest_hash);
        w.bytes(&self.candidate_dep_lock_hash);
        w.bytes(&self.container_image_digest);
        w.u8(self.arch.to_repr());
        w.u8(self.rss_scope.to_repr());
        w.bytes(&self.proof_hash);
        w.u32(self.run_index);
        w.u64(self.peak_rss_bytes);
        w.into_bytes()
    }

    pub fn decode(r: &mut Reader) -> Result<Self, DecodeError> {
        let tag = r.read_array::<32>("BenchmarkRssRecordV1.tag")?;
        if tag != BENCH_RSS_TAG {
            return Err(DecodeError::BadTag {
                ctx: "BenchmarkRssRecordV1",
            });
        }
        let sv = r.read_u16("BenchmarkRssRecordV1.schema_version")?;
        if sv != consts::SCHEMA_VERSION {
            return Err(DecodeError::BadFixedScalar {
                ctx: "BenchmarkRssRecordV1.schema_version",
                value: sv as u64,
            });
        }
        let b0_pre_spec_hash = r.read_array::<32>("BenchmarkRssRecordV1.b0_pre_spec_hash")?;
        let r0_guest_set_hash = r.read_array::<32>("BenchmarkRssRecordV1.r0_guest_set_hash")?;
        let computation_statement_hash =
            r.read_array::<32>("BenchmarkRssRecordV1.computation_statement_hash")?;
        let candidate = Candidate::from_repr(r.read_u16("BenchmarkRssRecordV1.candidate_id")?)?;
        let guest_program_id = r.read_array::<32>("BenchmarkRssRecordV1.guest_program_id")?;
        let verifier_material_manifest_hash =
            r.read_array::<32>("BenchmarkRssRecordV1.verifier_material_manifest_hash")?;
        let candidate_dep_lock_hash =
            r.read_array::<32>("BenchmarkRssRecordV1.candidate_dep_lock_hash")?;
        let container_image_digest =
            r.read_array::<32>("BenchmarkRssRecordV1.container_image_digest")?;
        let arch = Arch::from_repr(r.read_u8("BenchmarkRssRecordV1.arch")?)?;
        let rss_scope = RssScope::from_repr(r.read_u8("BenchmarkRssRecordV1.rss_scope")?)?;
        let proof_hash = r.read_array::<32>("BenchmarkRssRecordV1.proof_hash")?;
        let run_index = r.read_u32("BenchmarkRssRecordV1.run_index")?;
        let peak_rss_bytes = r.read_u64("BenchmarkRssRecordV1.peak_rss_bytes")?;
        Ok(Self {
            b0_pre_spec_hash,
            r0_guest_set_hash,
            computation_statement_hash,
            candidate,
            guest_program_id,
            verifier_material_manifest_hash,
            candidate_dep_lock_hash,
            container_image_digest,
            arch,
            rss_scope,
            proof_hash,
            run_index,
            peak_rss_bytes,
        })
    }

    pub fn decode_exact(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut r = Reader::new(bytes);
        let v = Self::decode(&mut r)?;
        r.finish("BenchmarkRssRecordV1")?;
        Ok(v)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> BenchmarkSampleV1 {
        BenchmarkSampleV1 {
            b0_pre_spec_hash: [1; 32],
            r0_guest_set_hash: [2; 32],
            computation_statement_hash: [3; 32],
            candidate: Candidate::Risc0,
            guest_program_id: [4; 32],
            verifier_material_manifest_hash: [5; 32],
            candidate_dep_lock_hash: [6; 32],
            container_image_digest: [7; 32],
            arch: Arch::Aarch64,
            sample_kind: SampleKind::Measured,
            metric_kind: MetricKind::HostVerifyNs,
            unit: Unit::Nanoseconds,
            value: 42_000,
            proof_hash: [8; 32],
            iteration_index: 99,
            status: Status::Ok,
        }
    }

    fn rss() -> BenchmarkRssRecordV1 {
        BenchmarkRssRecordV1 {
            b0_pre_spec_hash: [1; 32],
            r0_guest_set_hash: [2; 32],
            computation_statement_hash: [3; 32],
            candidate: Candidate::Sp1,
            guest_program_id: [4; 32],
            verifier_material_manifest_hash: [5; 32],
            candidate_dep_lock_hash: [6; 32],
            container_image_digest: [7; 32],
            arch: Arch::X86_64,
            rss_scope: RssScope::VerifyBatch,
            proof_hash: [8; 32],
            run_index: 5,
            peak_rss_bytes: 123_456_789,
        }
    }

    #[test]
    fn sample_len_309_and_roundtrip() {
        let s = sample();
        assert_eq!(s.encode().len(), 309);
        assert_eq!(BenchmarkSampleV1::decode_exact(&s.encode()).unwrap(), s);
    }

    #[test]
    fn rss_len_306_and_roundtrip() {
        let s = rss();
        assert_eq!(s.encode().len(), 306);
        assert_eq!(BenchmarkRssRecordV1::decode_exact(&s.encode()).unwrap(), s);
    }

    #[test]
    fn bad_metric_kind_rejected() {
        let mut bytes = sample().encode();
        bytes[262] = 9; // metric_kind offset; 0..=7 valid, 9 is unknown
        assert!(matches!(
            BenchmarkSampleV1::decode_exact(&bytes),
            Err(DecodeError::BadEnum {
                name: "MetricKind",
                value: 9
            })
        ));
    }

    #[test]
    fn truncation_and_trailing_rejected() {
        let s = sample().encode();
        assert!(matches!(
            BenchmarkSampleV1::decode_exact(&s[..308]),
            Err(DecodeError::Truncated { .. })
        ));
        let mut long = s;
        long.push(0);
        assert!(matches!(
            BenchmarkSampleV1::decode_exact(&long),
            Err(DecodeError::TrailingBytes { .. })
        ));
    }
}
