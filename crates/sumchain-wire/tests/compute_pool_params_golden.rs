//! Frozen golden vectors for `ComputePoolParamsV1` (issue #215). APPEND-ONLY.
//!
//! The expected hex was produced by an independent encoder written from the
//! ratified field table (not by calling this crate), so these vectors check the
//! Rust encoder against the specification, not against itself. All values are
//! TEST_ONLY patterns chosen to make every byte position distinguishable; none
//! is a proposed parameter value.

use sumchain_wire::b0::codec::DecodeError;
use sumchain_wire::compute_pool_params::ComputePoolParamsV1;

/// Every field in ratified order with its byte offset and width.
const LAYOUT: [(&str, usize, usize); 30] = [
    ("b_offer", 9, 16),
    ("b_commit", 25, 16),
    ("b_check", 41, 16),
    ("c_layer", 57, 8),
    ("c_tok", 65, 8),
    ("c_sel", 73, 8),
    ("c_emit", 81, 8),
    ("accept_reimb", 89, 16),
    ("commit_verify_reimb", 105, 16),
    ("publish_reimb", 121, 16),
    ("observe_reimb", 137, 16),
    ("check_reimb", 153, 16),
    ("settle_reimb", 169, 16),
    ("reassign_reimb", 185, 16),
    ("max_work_units", 201, 8),
    ("max_generations", 209, 8),
    ("max_reprovisionable_units", 217, 8),
    ("max_attempts_per_unit", 225, 4),
    ("max_reassignments_per_file", 229, 4),
    ("k_susp", 233, 8),
    ("w_susp", 241, 8),
    ("s_susp", 249, 8),
    ("n_invite_max", 257, 8),
    ("max_retention_files_per_job", 265, 8),
    ("max_retention_updates_per_block", 273, 8),
    ("max_reverse_index_entries", 281, 8),
    ("output_availability_blocks", 289, 8),
    ("d_avail", 297, 8),
    ("d_ack", 305, 8),
    ("d_final", 313, 8),
];

/// TEST_ONLY: field `i` (0-based) holds `(i+1)` in its lowest and its highest
/// byte, so a swapped, shifted or wrong-endian field changes the vector.
fn patterned() -> ComputePoolParamsV1 {
    ComputePoolParamsV1 {
        b_offer: 0x0100_0000_0000_0000_0000_0000_0000_0001,
        b_commit: 0x0200_0000_0000_0000_0000_0000_0000_0002,
        b_check: 0x0300_0000_0000_0000_0000_0000_0000_0003,
        c_layer: 0x0400_0000_0000_0004,
        c_tok: 0x0500_0000_0000_0005,
        c_sel: 0x0600_0000_0000_0006,
        c_emit: 0x0700_0000_0000_0007,
        accept_reimb: 0x0800_0000_0000_0000_0000_0000_0000_0008,
        commit_verify_reimb: 0x0900_0000_0000_0000_0000_0000_0000_0009,
        publish_reimb: 0x0a00_0000_0000_0000_0000_0000_0000_000a,
        observe_reimb: 0x0b00_0000_0000_0000_0000_0000_0000_000b,
        check_reimb: 0x0c00_0000_0000_0000_0000_0000_0000_000c,
        settle_reimb: 0x0d00_0000_0000_0000_0000_0000_0000_000d,
        reassign_reimb: 0x0e00_0000_0000_0000_0000_0000_0000_000e,
        max_work_units: 0x0f00_0000_0000_000f,
        max_generations: 0x1000_0000_0000_0010,
        max_reprovisionable_units: 0x1100_0000_0000_0011,
        max_attempts_per_unit: 0x1200_0012,
        max_reassignments_per_file: 0x1300_0013,
        k_susp: 0x1400_0000_0000_0014,
        w_susp: 0x1500_0000_0000_0015,
        s_susp: 0x1600_0000_0000_0016,
        n_invite_max: 0x1700_0000_0000_0017,
        max_retention_files_per_job: 0x1800_0000_0000_0018,
        max_retention_updates_per_block: 0x1900_0000_0000_0019,
        max_reverse_index_entries: 0x1a00_0000_0000_001a,
        output_availability_blocks: 0x1b00_0000_0000_001b,
        d_avail: 0x1c00_0000_0000_001c,
        d_ack: 0x1d00_0000_0000_001d,
        d_final: 0x1e00_0000_0000_001e,
    }
}

const PATTERNED_HEX: &str = "435050524d76310100010000000000000000000000000000010200000000000000000000000000000203000000000000000000000000000003040000000000000405000000000000050600000000000006070000000000000708000000000000000000000000000008090000000000000000000000000000090a00000000000000000000000000000a0b00000000000000000000000000000b0c00000000000000000000000000000c0d00000000000000000000000000000d0e00000000000000000000000000000e0f0000000000000f1000000000000010110000000000001112000012130000131400000000000014150000000000001516000000000000161700000000000017180000000000001819000000000000191a0000000000001a1b0000000000001b1c0000000000001c1d0000000000001d1e0000000000001e";

/// TEST_ONLY: the structurally smallest value — every cap 1, everything else 0.
fn minimal() -> ComputePoolParamsV1 {
    ComputePoolParamsV1 {
        b_offer: 0,
        b_commit: 0,
        b_check: 0,
        c_layer: 0,
        c_tok: 0,
        c_sel: 0,
        c_emit: 0,
        accept_reimb: 0,
        commit_verify_reimb: 0,
        publish_reimb: 0,
        observe_reimb: 0,
        check_reimb: 0,
        settle_reimb: 0,
        reassign_reimb: 0,
        max_work_units: 1,
        max_generations: 1,
        max_reprovisionable_units: 1,
        max_attempts_per_unit: 1,
        max_reassignments_per_file: 1,
        k_susp: 0,
        w_susp: 0,
        s_susp: 0,
        n_invite_max: 1,
        max_retention_files_per_job: 1,
        max_retention_updates_per_block: 1,
        max_reverse_index_entries: 1,
        output_availability_blocks: 0,
        d_avail: 0,
        d_ack: 0,
        d_final: 0,
    }
}

const MINIMAL_HEX: &str = "435050524d76310100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010000000000000001000000000000000100000000000000010000000100000000000000000000000000000000000000000000000000000001000000000000000100000000000000010000000000000001000000000000000000000000000000000000000000000000000000000000000000000000000000";

#[test]
fn constants_are_frozen() {
    assert_eq!(&ComputePoolParamsV1::MAGIC, b"CPPRMv1");
    assert_eq!(hex::encode(ComputePoolParamsV1::MAGIC), "435050524d7631");
    assert_eq!(ComputePoolParamsV1::SCHEMA_VERSION, 1);
    assert_eq!(ComputePoolParamsV1::LEN, 321);
}

#[test]
fn patterned_vector_is_frozen_and_round_trips() {
    let p = patterned();
    let bytes = p.try_encode().unwrap();
    assert_eq!(bytes.len(), ComputePoolParamsV1::LEN);
    assert_eq!(hex::encode(&bytes), PATTERNED_HEX);
    assert_eq!(ComputePoolParamsV1::decode_exact(&bytes).unwrap(), p);
}

#[test]
fn minimal_vector_is_frozen_and_round_trips() {
    let p = minimal();
    let bytes = p.try_encode().unwrap();
    assert_eq!(hex::encode(&bytes), MINIMAL_HEX);
    assert_eq!(ComputePoolParamsV1::decode_exact(&bytes).unwrap(), p);
}

/// The layout table is contiguous, ends at `LEN`, and each field of the
/// patterned vector carries its ordinal at both ends of its slot.
#[test]
fn every_field_sits_at_its_documented_offset() {
    let bytes = patterned().try_encode().unwrap();
    assert_eq!(&bytes[..7], b"CPPRMv1");
    assert_eq!(&bytes[7..9], &1u16.to_le_bytes());
    let mut next = 9;
    for (i, (name, off, width)) in LAYOUT.iter().enumerate() {
        assert_eq!(*off, next, "{name} offset");
        let ordinal = (i + 1) as u8;
        assert_eq!(bytes[*off], ordinal, "{name} low byte");
        assert_eq!(bytes[off + width - 1], ordinal, "{name} high byte");
        next = off + width;
    }
    assert_eq!(next, ComputePoolParamsV1::LEN);
}

/// The JSON (genesis) surface uses the same names in the same order, every
/// one of them required. u128 values above `u64::MAX` round-trip through text
/// (the genesis loader parses text); `serde_json::Value` cannot hold them, so
/// the per-key checks below use the small-valued `minimal()`.
#[test]
fn json_surface_names_every_field_in_order_and_requires_all() {
    let v = serde_json::to_value(minimal()).unwrap();
    let text = serde_json::to_string(&patterned()).unwrap();
    let mut last = 0;
    for (name, _, _) in LAYOUT {
        let pos = text
            .find(&format!("\"{name}\":"))
            .unwrap_or_else(|| panic!("{name}"));
        assert!(pos >= last, "{name} out of order");
        last = pos;
    }
    assert_eq!(v.as_object().unwrap().len(), LAYOUT.len());
    let back: ComputePoolParamsV1 = serde_json::from_str(&text).unwrap();
    assert_eq!(back, patterned());
    assert_eq!(
        serde_json::from_value::<ComputePoolParamsV1>(v.clone()).unwrap(),
        minimal()
    );

    for (name, _, _) in LAYOUT {
        let mut missing = v.clone();
        missing.as_object_mut().unwrap().remove(name);
        assert!(
            serde_json::from_value::<ComputePoolParamsV1>(missing).is_err(),
            "{name} must be required (no invented default)"
        );
    }
    let mut extra = v.clone();
    extra
        .as_object_mut()
        .unwrap()
        .insert("margin".into(), serde_json::json!(1));
    assert!(serde_json::from_value::<ComputePoolParamsV1>(extra).is_err());
}

// ── malformed input ─────────────────────────────────────────────────────────

#[test]
fn decode_rejects_truncation_at_every_length() {
    let bytes = patterned().try_encode().unwrap();
    for n in 0..bytes.len() {
        assert!(
            matches!(
                ComputePoolParamsV1::decode_exact(&bytes[..n]),
                Err(DecodeError::Truncated { .. })
            ),
            "length {n}"
        );
    }
}

#[test]
fn decode_rejects_trailing_bytes() {
    let mut bytes = patterned().try_encode().unwrap();
    bytes.push(0);
    assert!(matches!(
        ComputePoolParamsV1::decode_exact(&bytes),
        Err(DecodeError::TrailingBytes { remaining: 1, .. })
    ));
}

#[test]
fn decode_rejects_any_magic_change() {
    let good = patterned().try_encode().unwrap();
    for i in 0..7 {
        let mut bytes = good.clone();
        bytes[i] ^= 0x01;
        assert!(
            matches!(
                ComputePoolParamsV1::decode_exact(&bytes),
                Err(DecodeError::BadTag { .. })
            ),
            "magic byte {i}"
        );
    }
    // Another C1 carrier's magic is not this one.
    let mut other = good.clone();
    other[..7].copy_from_slice(b"CPJBv1\0");
    assert!(ComputePoolParamsV1::decode_exact(&other).is_err());
}

#[test]
fn decode_rejects_other_schema_versions() {
    let good = patterned().try_encode().unwrap();
    for v in [0u16, 2, 0x0100, u16::MAX] {
        let mut bytes = good.clone();
        bytes[7..9].copy_from_slice(&v.to_le_bytes());
        assert!(
            matches!(
                ComputePoolParamsV1::decode_exact(&bytes),
                Err(DecodeError::BadFixedScalar { value, .. }) if value == u64::from(v)
            ),
            "schema {v}"
        );
    }
}

#[test]
fn decode_rejects_a_zero_cap() {
    let good = minimal().try_encode().unwrap();
    for (name, off, width) in LAYOUT {
        let is_cap = name.starts_with("max_");
        let mut bytes = good.clone();
        bytes[off..off + width].fill(0);
        let r = ComputePoolParamsV1::decode_exact(&bytes);
        if is_cap {
            assert!(
                matches!(r, Err(DecodeError::BadValue { ctx }) if ctx.ends_with(name)),
                "{name}: {r:?}"
            );
        } else {
            let decoded = r.unwrap_or_else(|e| panic!("{name} may be zero: {e:?}"));
            assert_eq!(decoded.canonical_bytes(), bytes, "{name}");
        }
    }
}

// ── structural validation ───────────────────────────────────────────────────

#[test]
fn validation_is_structural_only() {
    // Zero bonds, weights, reimbursements, suspension and deadlines: valid.
    minimal().validate().unwrap();
    // Maximal values everywhere except the summed u128 groups: valid.
    let mut p = patterned();
    p.max_work_units = u64::MAX;
    p.max_generations = u64::MAX;
    p.max_attempts_per_unit = u32::MAX;
    p.d_final = u64::MAX;
    p.validate().unwrap();
    // `n_invite_max` is not one of §4's `max_*` caps: zero is accepted.
    let mut q = minimal();
    q.n_invite_max = 0;
    q.validate().unwrap();
}

#[test]
fn validation_refuses_overflowing_totals_and_encode_follows() {
    let mut p = minimal();
    p.b_offer = u128::MAX;
    p.b_check = 1;
    assert_eq!(p.bond_total(), None);
    assert!(matches!(
        p.validate(),
        Err(DecodeError::BadValue {
            ctx: "ComputePoolParamsV1.bond_total"
        })
    ));
    assert!(p.try_encode().is_err());

    let mut q = minimal();
    q.accept_reimb = u128::MAX;
    q.reassign_reimb = 1;
    assert_eq!(q.reimbursement_total(), None);
    assert!(matches!(
        q.validate(),
        Err(DecodeError::BadValue {
            ctx: "ComputePoolParamsV1.reimbursement_total"
        })
    ));

    // At the edge the totals are exact.
    let mut r = minimal();
    r.b_offer = u128::MAX - 2;
    r.b_commit = 1;
    r.b_check = 1;
    assert_eq!(r.bond_total(), Some(u128::MAX));
    r.validate().unwrap();
    assert_eq!(
        patterned().reimbursement_total(),
        Some((8..=14).map(|n: u128| (n << 120) | n).sum())
    );
}

#[test]
fn every_zero_cap_is_refused_by_validate() {
    let caps: [fn(&mut ComputePoolParamsV1); 8] = [
        |p| p.max_work_units = 0,
        |p| p.max_generations = 0,
        |p| p.max_reprovisionable_units = 0,
        |p| p.max_attempts_per_unit = 0,
        |p| p.max_reassignments_per_file = 0,
        |p| p.max_retention_files_per_job = 0,
        |p| p.max_retention_updates_per_block = 0,
        |p| p.max_reverse_index_entries = 0,
    ];
    for (i, zero) in caps.iter().enumerate() {
        let mut p = patterned();
        zero(&mut p);
        assert!(p.validate().is_err(), "cap {i}");
        assert!(p.try_encode().is_err(), "cap {i}");
    }
}
