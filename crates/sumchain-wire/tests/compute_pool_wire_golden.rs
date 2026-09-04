//! Append-only GOLDEN FIXTURES for the eight C1 `TxPayload::ComputePool = 27`
//! wire ops (#213 / #130), following the `beacon_wire_golden` convention.
//!
//! These pin the byte-stable op-carrier surface:
//!  * all **eight** carrier encodings at `schema_version = 1`;
//!  * the `0xC101..=0xC108` op discriminants (namespace `0xC100`, #217 A2);
//!  * each carrier's fixed `LEN`;
//!  * the ordinal-27 **routing prefix** `job_id ‖ unit_id ‖ generation` and its
//!    exact field offsets;
//!  * magic distinctness and dispatch resolution.
//!
//! The `*_HEX` constants below were emitted once by the carriers' own
//! `try_encode`; the production encoders MUST reproduce them byte-for-byte
//! forever (append-only — never edit an existing constant; only add new ones).
//!
//! **Architecture independence is structural**, not incidental: every field is
//! fixed-width and explicitly little-endian, and no encoder reads host layout,
//! so these vectors are identical on x86_64 and aarch64. CI proves it by running
//! this suite on both (`build-test-clippy` and `build-test-clippy-aarch64`).
//!
//! DORMANT: consensus bytes only — ComputePool execution stays gate-closed
//! (`compute_pool_enabled_from_height = None`).

use sumchain_wire::compute_pool_wire::*;
use sumchain_wire::Address;

// ── Frozen carrier encodings (schema_version = 1). ────────────────────────────
const CREATE_JOB_HEX: &str = "43504a427631000100aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaabbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb03000000";
const PUBLISH_OFFER_HEX: &str = "43504f4676310001000900000000000000000000000001000000000000000000000707070707070707070707070707070707070707";
const ACCEPT_UNIT_HEX: &str = "435041437631000100111111111111111111111111111111111111111111111111111111111111111122222222222222222222222222222222222222222222222222222222222222220500000000000000444444444444444444444444444444444444444444444444444444444444444400100000000000000000000000000000";
const DECLINE_UNIT_HEX: &str = "435044437631000100111111111111111111111111111111111111111111111111111111111111111122222222222222222222222222222222222222222222222222222222222222220500000000000000";
const EXPIRE_UNIT_HEX: &str = "435045587631000100111111111111111111111111111111111111111111111111111111111111111122222222222222222222222222222222222222222222222222222222222222220500000000000000";
const CANCEL_JOB_HEX: &str =
    "4350434e76310001005555555555555555555555555555555555555555555555555555555555555555";
const ASSIGN_UNIT_HEX: &str = "435041537631000100111111111111111111111111111111111111111111111111111111111111111122222222222222222222222222222222222222222222222222222222222222220500000000000000";
const REASSIGN_UNIT_HEX: &str = "435052417631000100111111111111111111111111111111111111111111111111111111111111111122222222222222222222222222222222222222222222222222222222222222220500000000000000";

fn unhex(s: &str) -> Vec<u8> {
    hex::decode(s).expect("valid hex")
}

// ── Canonical fixture values (identical to the in-module unit tests, so the
//    two sets can never drift apart). ─────────────────────────────────────────
fn wi() -> WorkItemRef {
    WorkItemRef {
        job_id: [0x11; 32],
        unit_id: [0x22; 32],
        generation: 5,
    }
}
fn create_job() -> CreateComputePoolJobV1 {
    CreateComputePoolJobV1 {
        client_job_salt: [0xAA; 32],
        graph_definition_root: [0xBB; 32],
        unit_count: 3,
    }
}
fn publish_offer() -> PublishBondedOfferV1 {
    PublishBondedOfferV1 {
        offer_seq: 9,
        offered_bytes: 1 << 40,
        payment_addr: Address::new([0x07; 20]),
    }
}
fn accept() -> AcceptWorkUnitV1 {
    AcceptWorkUnitV1 {
        work_item: wi(),
        commit_bond_id: [0x44; 32],
        accepted_bytes: 4096,
    }
}
fn cancel() -> CancelJobV1 {
    CancelJobV1 { job_id: [0x55; 32] }
}

/// Encode == frozen bytes, and those bytes decode back to the same value.
macro_rules! golden {
    ($test:ident, $ty:ty, $value:expr, $hex:expr) => {
        #[test]
        fn $test() {
            let v = $value;
            let bytes = v.try_encode().expect("encodes");
            assert_eq!(hex::encode(&bytes), $hex, "frozen encoding changed");
            assert_eq!(bytes.len(), <$ty>::LEN, "LEN disagrees with the encoding");
            assert_eq!(<$ty>::decode_exact(&unhex($hex)).expect("decodes"), v);
        }
    };
}

golden!(
    golden_create_job,
    CreateComputePoolJobV1,
    create_job(),
    CREATE_JOB_HEX
);
golden!(
    golden_publish_offer,
    PublishBondedOfferV1,
    publish_offer(),
    PUBLISH_OFFER_HEX
);
golden!(
    golden_accept_unit,
    AcceptWorkUnitV1,
    accept(),
    ACCEPT_UNIT_HEX
);
golden!(
    golden_decline_unit,
    DeclineWorkUnitV1,
    DeclineWorkUnitV1 { work_item: wi() },
    DECLINE_UNIT_HEX
);
golden!(
    golden_expire_unit,
    ExpireWorkUnitV1,
    ExpireWorkUnitV1 { work_item: wi() },
    EXPIRE_UNIT_HEX
);
golden!(golden_cancel_job, CancelJobV1, cancel(), CANCEL_JOB_HEX);
golden!(
    golden_assign_unit,
    AssignWorkUnitV1,
    AssignWorkUnitV1 { work_item: wi() },
    ASSIGN_UNIT_HEX
);
golden!(
    golden_reassign_unit,
    ReassignWorkUnitV1,
    ReassignWorkUnitV1 { work_item: wi() },
    REASSIGN_UNIT_HEX
);

/// All eight ops are covered above — the fixture set is complete, not partial.
#[test]
fn all_eight_ops_have_a_golden_vector() {
    let vectors = [
        (OP_CREATE_JOB, CREATE_JOB_HEX),
        (OP_PUBLISH_OFFER, PUBLISH_OFFER_HEX),
        (OP_ACCEPT_UNIT, ACCEPT_UNIT_HEX),
        (OP_DECLINE_UNIT, DECLINE_UNIT_HEX),
        (OP_EXPIRE_UNIT, EXPIRE_UNIT_HEX),
        (OP_CANCEL_JOB, CANCEL_JOB_HEX),
        (OP_ASSIGN_UNIT, ASSIGN_UNIT_HEX),
        (OP_REASSIGN_UNIT, REASSIGN_UNIT_HEX),
    ];
    assert_eq!(vectors.len(), 8);

    for (op, hexstr) in vectors {
        let bytes = unhex(hexstr);
        // Every vector round-trips through the dispatch enum and reports its op.
        let decoded = ComputePoolOperation::decode_exact(&bytes).expect("dispatch decodes");
        assert_eq!(
            decoded.op(),
            op,
            "dispatch resolved the wrong op for {op:#06x}"
        );
        assert_eq!(
            decoded.try_encode().unwrap(),
            bytes,
            "dispatch re-encode differs"
        );
        // schema_version is 1 at offset 7 (u16 LE) for every op.
        assert_eq!(&bytes[7..9], &[0x01, 0x00], "schema_version must be 1 (LE)");
    }

    // The eight magics are pairwise distinct (the dispatch discriminator).
    let mut magics: Vec<&[u8]> = vectors.iter().map(|(_, h)| &h.as_bytes()[..14]).collect();
    magics.sort_unstable();
    let before = magics.len();
    magics.dedup();
    assert_eq!(magics.len(), before, "two ops share a magic");
}

/// The op discriminants are frozen at `0xC100 | n`, n = 1..=8.
#[test]
fn op_discriminants_are_frozen() {
    assert_eq!(COMPUTE_POOL_OP_NAMESPACE, 0xC100);
    assert_eq!(OP_CREATE_JOB, 0xC101);
    assert_eq!(OP_PUBLISH_OFFER, 0xC102);
    assert_eq!(OP_ACCEPT_UNIT, 0xC103);
    assert_eq!(OP_DECLINE_UNIT, 0xC104);
    assert_eq!(OP_EXPIRE_UNIT, 0xC105);
    assert_eq!(OP_CANCEL_JOB, 0xC106);
    assert_eq!(OP_ASSIGN_UNIT, 0xC107);
    assert_eq!(OP_REASSIGN_UNIT, 0xC108);
}

/// Each carrier's byte length is frozen (the byte tables in the module docs).
#[test]
fn carrier_lengths_are_frozen() {
    assert_eq!(WorkItemRef::LEN, 72);
    assert_eq!(CreateComputePoolJobV1::LEN, 77);
    assert_eq!(PublishBondedOfferV1::LEN, 53);
    assert_eq!(AcceptWorkUnitV1::LEN, 129);
    assert_eq!(DeclineWorkUnitV1::LEN, 81);
    assert_eq!(ExpireWorkUnitV1::LEN, 81);
    assert_eq!(CancelJobV1::LEN, 81 - 40); // 41
    assert_eq!(AssignWorkUnitV1::LEN, 81);
    assert_eq!(ReassignWorkUnitV1::LEN, 81);
}

/// The ordinal-27 routing prefix: `job_id[32] ‖ unit_id[32] ‖ generation u64 LE`
/// begins immediately after the 9-byte header, at the SAME offsets in every op
/// that targets a work item. This is the routing key consensus indexes on.
#[test]
fn routing_prefix_offsets_are_frozen() {
    const HDR: usize = 7 + 2;
    for hexstr in [
        DECLINE_UNIT_HEX,
        EXPIRE_UNIT_HEX,
        ASSIGN_UNIT_HEX,
        REASSIGN_UNIT_HEX,
        ACCEPT_UNIT_HEX,
    ] {
        let b = unhex(hexstr);
        assert_eq!(&b[HDR..HDR + 32], &[0x11; 32], "job_id at +9");
        assert_eq!(&b[HDR + 32..HDR + 64], &[0x22; 32], "unit_id at +41");
        // generation is u64 LITTLE-ENDIAN — 5 is 05 00 00 00 00 00 00 00.
        assert_eq!(
            &b[HDR + 64..HDR + 72],
            &[0x05, 0, 0, 0, 0, 0, 0, 0],
            "generation u64 LE at +73"
        );
    }
}

/// Generation is carried in FULL by every work-item op, so a stale generation is
/// never ambiguous: the same (job, unit) at a different generation is different
/// bytes. Frozen here because it is a consensus-visible anti-replay property.
#[test]
fn generation_is_bound_in_every_work_item_op() {
    let mut stale = wi();
    stale.generation = 4;
    assert_ne!(
        DeclineWorkUnitV1 { work_item: stale }.try_encode().unwrap(),
        unhex(DECLINE_UNIT_HEX)
    );
    assert_ne!(
        AcceptWorkUnitV1 {
            work_item: stale,
            ..accept()
        }
        .try_encode()
        .unwrap(),
        unhex(ACCEPT_UNIT_HEX)
    );
}

/// A sibling decoder must reject another op's bytes (distinct magics), so an op
/// cannot be reinterpreted as a different one with the same body shape.
#[test]
fn ops_do_not_cross_decode() {
    // Decline / Expire / Assign / Reassign share a body shape and length.
    assert!(DeclineWorkUnitV1::decode_exact(&unhex(EXPIRE_UNIT_HEX)).is_err());
    assert!(ExpireWorkUnitV1::decode_exact(&unhex(ASSIGN_UNIT_HEX)).is_err());
    assert!(AssignWorkUnitV1::decode_exact(&unhex(REASSIGN_UNIT_HEX)).is_err());
    assert!(ReassignWorkUnitV1::decode_exact(&unhex(DECLINE_UNIT_HEX)).is_err());
    assert!(CancelJobV1::decode_exact(&unhex(CREATE_JOB_HEX)).is_err());
}

/// Trailing bytes are refused for every frozen vector (`Reader::finish`).
#[test]
fn no_vector_accepts_trailing_bytes() {
    for hexstr in [
        CREATE_JOB_HEX,
        PUBLISH_OFFER_HEX,
        ACCEPT_UNIT_HEX,
        DECLINE_UNIT_HEX,
        EXPIRE_UNIT_HEX,
        CANCEL_JOB_HEX,
        ASSIGN_UNIT_HEX,
        REASSIGN_UNIT_HEX,
    ] {
        let mut extra = unhex(hexstr);
        extra.push(0x00);
        assert!(
            ComputePoolOperation::decode_exact(&extra).is_err(),
            "trailing byte accepted for {hexstr}"
        );
        let truncated = &unhex(hexstr)[..hexstr.len() / 2 - 1];
        assert!(
            ComputePoolOperation::decode_exact(truncated).is_err(),
            "truncation accepted for {hexstr}"
        );
    }
}
