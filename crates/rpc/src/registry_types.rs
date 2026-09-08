//! Registry dry-run validation types (#238).
//!
//! A candidate proof profile that fails validation **never becomes registry
//! state**. The refusal is the *outcome of a validation*, not a stored status, so
//! it lives here on the RPC surface rather than in consensus.
//!
//! What this deliberately does NOT do:
//!
//! * It does not add a third `RegistryStatus` discriminant. The enum stays
//!   `Enabled = 0` / `Disabled = 1` and `RegistryRecordV1`'s bytes stay frozen —
//!   an earlier proposal (#21) modelled `CandidateRefused` as a stored status,
//!   which would have changed ratified consensus bytes for something that is not
//!   consensus state at all.
//! * It does not invent governance values. `approval_threshold_bps`' mainnet
//!   default and the minimum activation timelock are **not ratified** (#212), so
//!   nothing here assumes them: the only threshold check is the range the wire
//!   type already implies, and height comparisons take the caller's chain height
//!   rather than a governance floor.
//! * It writes nothing and allocates no record. `dry_run_admit` is a pure
//!   function of its inputs.

use serde::Serialize;
use sumchain_wire::b0::codec::DecodeError;
use sumchain_wire::registry_wire::{RegistryRecordV1, RegistryStatus};

/// Why a candidate profile would be refused admission.
///
/// The serialized representation is a stable `snake_case` tag plus a `detail`
/// string. The **tag** is the contract — clients match on it; `detail` is
/// human-facing and may gain precision without being a breaking change.
// Serialize only: this is a server response shape, and the `&'static str`
// discriminator fields cannot be deserialized into borrowed data.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "reason", rename_all = "snake_case")]
pub enum RefusalReason {
    /// The submitted bytes are not a well-formed `RegistryRecordV1`.
    ///
    /// `kind` is the decoder's own classification (`bad_tag`, `truncated`,
    /// `trailing_bytes`, …) so a client can distinguish "wrong type entirely"
    /// from "right type, malformed field" without parsing prose.
    MalformedRecord { kind: &'static str, detail: String },

    /// `proof_system_id` is not one this chain admits.
    UnknownProofSystem { proof_system_id: u16 },

    /// `approval_threshold_bps` is outside the basis-point range `0..=10000`.
    /// This is the range the unit implies, NOT a ratified governance default.
    ThresholdOutOfRange { approval_threshold_bps: u16 },

    /// A mandatory commitment is all-zero. All three are fixed-width and so
    /// always structurally present (#217 B1), which means an unset commitment
    /// shows up as zeroes rather than as an absent field — that would otherwise
    /// admit a record committing to nothing.
    CommitmentUnset { which: &'static str },

    /// The record is not in an admissible status.
    NotAdmissibleStatus { status: &'static str },

    /// `activation_height` is not in the future relative to the caller-supplied
    /// chain height. Compared against actual chain height, not a governance
    /// timelock floor — that floor is unratified (#212).
    ActivationHeightNotFuture {
        activation_height: u64,
        chain_height: u64,
    },
}

impl RefusalReason {
    /// Stable tag, matching the serialized `reason` field. Exposed so callers
    /// and tests can assert on the contract without going through serde.
    pub fn tag(&self) -> &'static str {
        match self {
            Self::MalformedRecord { .. } => "malformed_record",
            Self::UnknownProofSystem { .. } => "unknown_proof_system",
            Self::ThresholdOutOfRange { .. } => "threshold_out_of_range",
            Self::CommitmentUnset { .. } => "commitment_unset",
            Self::NotAdmissibleStatus { .. } => "not_admissible_status",
            Self::ActivationHeightNotFuture { .. } => "activation_height_not_future",
        }
    }
}

/// Decoder classification, kept stable and independent of `Display` wording.
fn decode_kind(e: &DecodeError) -> &'static str {
    match e {
        DecodeError::Truncated { .. } => "truncated",
        DecodeError::TrailingBytes { .. } => "trailing_bytes",
        DecodeError::BadTag { .. } => "bad_tag",
        DecodeError::BadEnum { .. } => "bad_enum",
        DecodeError::ReservedEnum { .. } => "reserved_enum",
        DecodeError::BadFixedScalar { .. } => "bad_fixed_scalar",
        DecodeError::CountExceedsMax { .. } => "count_exceeds_max",
        DecodeError::LengthExceedsMax { .. } => "length_exceeds_max",
        DecodeError::NonCanonicalOrder { .. } => "non_canonical_order",
        DecodeError::DuplicateEntry { .. } => "duplicate_entry",
        DecodeError::Inconsistent { .. } => "inconsistent",
        DecodeError::BadValue { .. } => "bad_value",
    }
}

/// Outcome of a dry run. Admission is all-or-nothing, and refusals are returned
/// **in full** rather than first-only: an operator fixing one field at a time
/// through repeated round trips is a worse experience than seeing every problem
/// at once.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DryRunResult {
    pub admissible: bool,
    pub refusals: Vec<RefusalReason>,
}

impl DryRunResult {
    fn admitted() -> Self {
        Self { admissible: true, refusals: Vec::new() }
    }
    fn refused(refusals: Vec<RefusalReason>) -> Self {
        debug_assert!(!refusals.is_empty());
        Self { admissible: false, refusals }
    }
}

/// Chain context a dry run needs. Supplied by the caller so the function stays
/// pure — it reads no state and therefore cannot mutate any.
#[derive(Debug, Clone, Copy)]
pub struct DryRunContext<'a> {
    /// Current chain height, for the activation-height comparison.
    pub chain_height: u64,
    /// Proof-system ids this chain admits.
    pub allowed_proof_systems: &'a [u16],
}

/// Validate candidate record bytes without writing anything.
///
/// Determinism: every check is a comparison on fixed-width fields or a lookup in
/// a caller-supplied slice, and refusals are emitted in a fixed source order —
/// never from map iteration — so the same input yields the same reasons in the
/// same order on x86_64 and aarch64.
pub fn dry_run_admit(bytes: &[u8], ctx: DryRunContext<'_>) -> DryRunResult {
    let record = match RegistryRecordV1::decode_exact(bytes) {
        Ok(r) => r,
        Err(e) => {
            // A malformed record cannot be checked further: every subsequent
            // field would be a guess.
            return DryRunResult::refused(vec![RefusalReason::MalformedRecord {
                kind: decode_kind(&e),
                detail: e.to_string(),
            }]);
        }
    };

    let mut refusals = Vec::new();

    if !ctx.allowed_proof_systems.contains(&record.proof_system_id) {
        refusals.push(RefusalReason::UnknownProofSystem {
            proof_system_id: record.proof_system_id,
        });
    }

    if record.approval_threshold_bps > 10_000 {
        refusals.push(RefusalReason::ThresholdOutOfRange {
            approval_threshold_bps: record.approval_threshold_bps,
        });
    }

    // Fixed source order, so the sequence is stable.
    for (which, commitment) in [
        ("audit_commitment", &record.audit_commitment),
        ("source_commitment", &record.source_commitment),
        ("ceremony_commitment", &record.ceremony_commitment),
    ] {
        if commitment.iter().all(|&b| b == 0) {
            refusals.push(RefusalReason::CommitmentUnset { which });
        }
    }

    if record.status != RegistryStatus::Enabled {
        refusals.push(RefusalReason::NotAdmissibleStatus { status: "disabled" });
    }

    if record.activation_height <= ctx.chain_height {
        refusals.push(RefusalReason::ActivationHeightNotFuture {
            activation_height: record.activation_height,
            chain_height: ctx.chain_height,
        });
    }

    if refusals.is_empty() {
        DryRunResult::admitted()
    } else {
        DryRunResult::refused(refusals)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALLOWED: &[u16] = &[1, 2];

    fn ctx() -> DryRunContext<'static> {
        DryRunContext { chain_height: 100, allowed_proof_systems: ALLOWED }
    }

    fn good_record() -> RegistryRecordV1 {
        RegistryRecordV1 {
            id: [0x11; 32],
            proof_system_id: 1,
            audit_commitment: [0xAA; 32],
            source_commitment: [0xBB; 32],
            ceremony_commitment: [0xCC; 32],
            verifier_binary_version: 3,
            activation_height: 200,
            status: RegistryStatus::Enabled,
            approval_threshold_bps: 6_667,
        }
    }

    fn run(r: &RegistryRecordV1) -> DryRunResult {
        dry_run_admit(&r.try_encode().expect("encodes"), ctx())
    }

    #[test]
    fn a_well_formed_admissible_record_passes() {
        let out = run(&good_record());
        assert!(out.admissible, "{:?}", out.refusals);
        assert!(out.refusals.is_empty());
    }

    #[test]
    fn malformed_bytes_are_classified_not_guessed() {
        // Wrong magic.
        let mut b = good_record().try_encode().unwrap();
        b[0] ^= 0xFF;
        let out = dry_run_admit(&b, ctx());
        assert!(!out.admissible);
        assert_eq!(out.refusals.len(), 1, "must not guess at further fields");
        assert_eq!(out.refusals[0].tag(), "malformed_record");
        match &out.refusals[0] {
            RefusalReason::MalformedRecord { kind, .. } => assert_eq!(*kind, "bad_tag"),
            other => panic!("{other:?}"),
        }

        // Trailing bytes.
        let mut t = good_record().try_encode().unwrap();
        t.push(0);
        match &dry_run_admit(&t, ctx()).refusals[0] {
            RefusalReason::MalformedRecord { kind, .. } => assert_eq!(*kind, "trailing_bytes"),
            other => panic!("{other:?}"),
        }

        // Truncation.
        let s = good_record().try_encode().unwrap();
        match &dry_run_admit(&s[..s.len() - 1], ctx()).refusals[0] {
            RefusalReason::MalformedRecord { kind, .. } => assert_eq!(*kind, "truncated"),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn unknown_proof_system_is_refused() {
        let mut r = good_record();
        r.proof_system_id = 99;
        let out = run(&r);
        assert!(!out.admissible);
        assert!(out.refusals.contains(&RefusalReason::UnknownProofSystem { proof_system_id: 99 }));
    }

    /// An all-zero commitment is structurally present but commits to nothing.
    /// All three are mandatory (#217 B1), so this is the only way "unset" can
    /// appear on the wire.
    #[test]
    fn an_all_zero_commitment_is_refused_for_each_of_the_three() {
        for which in ["audit_commitment", "source_commitment", "ceremony_commitment"] {
            let mut r = good_record();
            match which {
                "audit_commitment" => r.audit_commitment = [0; 32],
                "source_commitment" => r.source_commitment = [0; 32],
                _ => r.ceremony_commitment = [0; 32],
            }
            let out = run(&r);
            assert!(!out.admissible, "{which} all-zero must refuse");
            assert!(out.refusals.contains(&RefusalReason::CommitmentUnset { which }));
        }
    }

    #[test]
    fn disabled_status_is_not_admissible() {
        let mut r = good_record();
        r.status = RegistryStatus::Disabled;
        let out = run(&r);
        assert!(!out.admissible);
        assert_eq!(
            out.refusals.iter().filter(|x| x.tag() == "not_admissible_status").count(),
            1
        );
    }

    #[test]
    fn activation_height_must_be_in_the_future() {
        for h in [0u64, 99, 100] {
            let mut r = good_record();
            r.activation_height = h;
            let out = run(&r);
            assert!(!out.admissible, "height {h} vs chain 100 must refuse");
            assert!(out.refusals.contains(&RefusalReason::ActivationHeightNotFuture {
                activation_height: h,
                chain_height: 100,
            }));
        }
        // 101 is the first admissible height.
        let mut r = good_record();
        r.activation_height = 101;
        assert!(run(&r).admissible);
    }

    /// `approval_threshold_bps` is range-checked against what the basis-point
    /// unit implies (`0..=10000`), NOT against a ratified mainnet default —
    /// that value is #212's to decide. The boundary is inclusive at 10000.
    ///
    /// The wire decoder accepts any `u16` here, so this branch is reachable
    /// with real encoded bytes rather than only via a constructed struct.
    #[test]
    fn threshold_boundaries() {
        // In range: admitted (nothing else about the record is wrong).
        for bps in [0u16, 1, 5_000, 9_999, 10_000] {
            let mut r = good_record();
            r.approval_threshold_bps = bps;
            let out = run(&r);
            assert!(
                out.admissible,
                "bps {bps} is within 0..=10000 and must be admitted, got {:?}",
                out.refusals
            );
        }

        // Out of range: refused, with the offending value echoed back.
        for bps in [10_001u16, 20_000, u16::MAX] {
            let mut r = good_record();
            r.approval_threshold_bps = bps;
            let out = run(&r);
            assert!(!out.admissible, "bps {bps} exceeds 10000 and must refuse");
            assert!(
                out.refusals.contains(&RefusalReason::ThresholdOutOfRange {
                    approval_threshold_bps: bps
                }),
                "bps {bps} must produce threshold_out_of_range, got {:?}",
                out.refusals
            );
            // It is the ONLY complaint — an out-of-range threshold must not
            // cascade into unrelated refusals.
            assert_eq!(out.refusals.len(), 1, "bps {bps}: {:?}", out.refusals);
        }
    }

    /// The threshold refusal survives the real encode/decode round trip, so the
    /// branch is not reachable only through an in-memory struct.
    #[test]
    fn threshold_out_of_range_survives_the_wire() {
        let mut r = good_record();
        r.approval_threshold_bps = u16::MAX;
        let bytes = r.try_encode().expect("encodes");
        assert_eq!(bytes.len(), RegistryRecordV1::LEN);
        let decoded = RegistryRecordV1::decode_exact(&bytes).expect("decoder accepts the bytes");
        assert_eq!(decoded.approval_threshold_bps, u16::MAX);
        let out = dry_run_admit(&bytes, ctx());
        assert!(!out.admissible);
        assert_eq!(out.refusals[0].tag(), "threshold_out_of_range");
    }

    /// Every problem is reported at once, so an operator does not fix one field
    /// per round trip.
    #[test]
    fn all_refusals_are_reported_together_and_in_a_stable_order() {
        let mut r = good_record();
        r.proof_system_id = 99;
        r.approval_threshold_bps = u16::MAX;
        r.audit_commitment = [0; 32];
        r.status = RegistryStatus::Disabled;
        r.activation_height = 1;
        let out = run(&r);
        assert!(!out.admissible);
        let tags: Vec<&str> = out.refusals.iter().map(|x| x.tag()).collect();
        assert_eq!(
            tags,
            vec![
                "unknown_proof_system",
                "threshold_out_of_range",
                "commitment_unset",
                "not_admissible_status",
                "activation_height_not_future",
            ],
            "refusal order must be stable, not iteration-dependent"
        );
        // Deterministic: repeated runs agree exactly.
        assert_eq!(run(&r), out);
    }

    /// All three commitments unset at once still emit in fixed source order.
    #[test]
    fn commitment_unset_order_is_fixed_across_all_three() {
        let mut r = good_record();
        r.audit_commitment = [0; 32];
        r.source_commitment = [0; 32];
        r.ceremony_commitment = [0; 32];
        let out = run(&r);
        let which: Vec<&str> = out
            .refusals
            .iter()
            .filter_map(|x| match x {
                RefusalReason::CommitmentUnset { which } => Some(*which),
                _ => None,
            })
            .collect();
        assert_eq!(
            which,
            vec![
                "audit_commitment",
                "source_commitment",
                "ceremony_commitment"
            ]
        );
    }

    /// The serialized shape is the client contract: the `reason` tag AND every
    /// payload field, for EVERY variant. `detail` is human-facing and may gain
    /// precision, so its presence and type are asserted rather than its text.
    #[test]
    fn every_refusal_variant_serializes_with_its_exact_tag_and_payload() {
        let malformed = serde_json::to_value(RefusalReason::MalformedRecord {
            kind: "truncated",
            detail: "some decoder message".to_string(),
        })
        .unwrap();
        assert_eq!(malformed["reason"], "malformed_record");
        assert_eq!(malformed["kind"], "truncated");
        assert!(malformed["detail"].is_string());

        let unknown =
            serde_json::to_value(RefusalReason::UnknownProofSystem { proof_system_id: 7 }).unwrap();
        assert_eq!(unknown["reason"], "unknown_proof_system");
        assert_eq!(unknown["proof_system_id"], 7);

        let threshold = serde_json::to_value(RefusalReason::ThresholdOutOfRange {
            approval_threshold_bps: u16::MAX,
        })
        .unwrap();
        assert_eq!(threshold["reason"], "threshold_out_of_range");
        assert_eq!(threshold["approval_threshold_bps"], u16::MAX);

        let commitment = serde_json::to_value(RefusalReason::CommitmentUnset {
            which: "audit_commitment",
        })
        .unwrap();
        assert_eq!(commitment["reason"], "commitment_unset");
        assert_eq!(commitment["which"], "audit_commitment");

        let status =
            serde_json::to_value(RefusalReason::NotAdmissibleStatus { status: "disabled" })
                .unwrap();
        assert_eq!(status["reason"], "not_admissible_status");
        assert_eq!(status["status"], "disabled");

        let activation = serde_json::to_value(RefusalReason::ActivationHeightNotFuture {
            activation_height: 5,
            chain_height: 100,
        })
        .unwrap();
        assert_eq!(activation["reason"], "activation_height_not_future");
        assert_eq!(activation["activation_height"], 5);
        assert_eq!(activation["chain_height"], 100);
    }

    /// Pins the six variants explicitly enumerated below and their serialized tags.
    /// Future variants require updating this list and the payload assertions above.
    #[test]
    fn refusal_variant_tags_are_exactly_the_six_documented_ones() {
        let all = [
            RefusalReason::MalformedRecord {
                kind: "bad_tag",
                detail: String::new(),
            },
            RefusalReason::UnknownProofSystem { proof_system_id: 0 },
            RefusalReason::ThresholdOutOfRange {
                approval_threshold_bps: 0,
            },
            RefusalReason::CommitmentUnset {
                which: "audit_commitment",
            },
            RefusalReason::NotAdmissibleStatus { status: "disabled" },
            RefusalReason::ActivationHeightNotFuture {
                activation_height: 0,
                chain_height: 0,
            },
        ];
        let tags: Vec<&str> = all.iter().map(|r| r.tag()).collect();
        assert_eq!(
            tags,
            vec![
                "malformed_record",
                "unknown_proof_system",
                "threshold_out_of_range",
                "commitment_unset",
                "not_admissible_status",
                "activation_height_not_future",
            ]
        );
        // The `tag()` accessor and the serialized `reason` field are the same
        // contract and must not drift apart.
        for r in &all {
            let v = serde_json::to_value(r).unwrap();
            assert_eq!(v["reason"], r.tag(), "tag() disagrees with serde for {r:?}");
        }
    }

    /// A refused result serializes with the refusals present, mirroring the
    /// admitted-shape assertion below.
    #[test]
    fn refused_result_serializes_with_its_reasons() {
        let out = DryRunResult::refused(vec![RefusalReason::ThresholdOutOfRange {
            approval_threshold_bps: 10_001,
        }]);
        let v = serde_json::to_value(&out).unwrap();
        assert_eq!(v["admissible"], false);
        let arr = v["refusals"].as_array().unwrap();
        assert_eq!(arr.len(), 1);
        assert_eq!(arr[0]["reason"], "threshold_out_of_range");
        assert_eq!(arr[0]["approval_threshold_bps"], 10_001);
    }

    /// The serialized tag is the client contract.
    #[test]
    fn serialization_tags_are_stable() {
        let v = serde_json::to_value(RefusalReason::UnknownProofSystem { proof_system_id: 7 })
            .unwrap();
        assert_eq!(v["reason"], "unknown_proof_system");
        assert_eq!(v["proof_system_id"], 7);

        let d = serde_json::to_value(DryRunResult::admitted()).unwrap();
        assert_eq!(d["admissible"], true);
        assert_eq!(d["refusals"].as_array().unwrap().len(), 0);
    }

    /// The whole point of #238: consensus bytes are untouched. A record that
    /// round-trips before a dry run round-trips identically after — the dry run
    /// cannot mutate what it inspects.
    #[test]
    fn dry_run_does_not_disturb_the_record_or_its_encoding() {
        let r = good_record();
        let before = r.try_encode().unwrap();
        let _ = dry_run_admit(&before, ctx());
        let after = r.try_encode().unwrap();
        assert_eq!(before, after);
        assert_eq!(RegistryRecordV1::decode_exact(&after).unwrap(), r);
        assert_eq!(before.len(), RegistryRecordV1::LEN);
    }

    /// `RegistryStatus` must remain exactly two discriminants — the ruling that
    /// replaced the stored-`CandidateRefused` proposal. Fails if a third is added.
    #[test]
    fn registry_status_remains_two_variants() {
        assert_eq!(RegistryStatus::Enabled.to_u8(), 0);
        assert_eq!(RegistryStatus::Disabled.to_u8(), 1);
        assert!(
            RegistryStatus::from_u8(2, "test").is_err(),
            "a third RegistryStatus discriminant would change frozen record bytes"
        );
    }
}
