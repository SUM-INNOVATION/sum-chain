//! The ratified C1 pool-id derivations (G1-1..G1-3, 2026-10-16) at the state
//! boundary: the model and the store key offers and entitlements by DERIVED
//! ids, the stored kind tag is the preimage's kind byte, and the unique-id
//! checks refuse a second derivation of one event.
//!
//! DORMANT: no executor, gate or state transition is added. The counter row
//! behind `ReassignReimb`'s occurrence, generation advance, the reservation
//! lifecycle and every amount are NOT ratified; occurrences are supplied here
//! by the test, as they are by any caller.

use sumchain_primitives::Address;
use sumchain_state::compute_pool::{
    BondedOffer, ComputePoolModel, EntitlementId, EntitlementKind, EntitlementRecord, JobId,
    OfferBondId, PoolError, UnitId,
};
use sumchain_state::compute_pool_store::{
    decode_entitlement, decode_offer, entitlement_key_bytes, offer_key_bytes, ComputePoolStore,
};
use sumchain_wire::compute_pool_graph::{job_id, unit_id};
use sumchain_wire::compute_pool_wire::PublishBondedOfferV1;

/// The ratified vectors (`compute_pool_ids_golden.rs` pins them byte for byte).
const OFFER_BASE_HEX: &str = "98fc8ba3a47488bc5c3941691f57f4ea7915086d4057ade85aa8debea7a1a4ea";
const ENT_ACCEPT_HEX: &str = "7377c94d7668f3347e779acac43a4110951ee9c8423468c3172b6605d302da27";
const ENT_REASSIGN_OCC_2_HEX: &str =
    "f0fc9e68ce981ce200d82502657b195179ba8bee94dc16d82fca4b149aac23c9";
const ENT_REPROVISION_HEX: &str =
    "11d1849a4a75b45140cb801fe3d33ffac1d40a2680ebf1d164c1018b23de7b89";

fn kat_sender() -> Address {
    let mut a = [0u8; 20];
    for (i, b) in a.iter_mut().enumerate() {
        *b = (i + 1) as u8;
    }
    Address::new(a)
}

fn kat_job() -> JobId {
    JobId::from_bytes(job_id(1, &kat_sender(), 7, &[0xAA; 32]))
}

fn kat_unit() -> UnitId {
    UnitId::from_bytes(unit_id(kat_job().as_bytes(), 0))
}

fn publish(seq: u64) -> PublishBondedOfferV1 {
    PublishBondedOfferV1 {
        offer_seq: seq,
        offered_bytes: 1_000,
        payment_addr: Address::new([0x50; 20]),
    }
}

fn record(id: EntitlementId, kind: EntitlementKind, beneficiary: u8) -> EntitlementRecord {
    EntitlementRecord {
        entitlement_id: id,
        beneficiary: Address::new([beneficiary; 20]),
        kind,
        amount: 5,
    }
}

// ── offer_bond_id ────────────────────────────────────────────────────────────

#[test]
fn offer_bond_id_derive_is_the_ratified_vector() {
    assert_eq!(
        hex::encode(OfferBondId::derive(1, &kat_sender(), 7).as_bytes()),
        OFFER_BASE_HEX
    );
}

#[test]
fn a_published_offer_carries_its_derived_id() {
    let o = BondedOffer::from_publish(1, kat_sender(), &publish(7), 500);
    assert_eq!(hex::encode(o.offer_bond_id.as_bytes()), OFFER_BASE_HEX);
    assert_eq!(o.identity, kat_sender());
    assert_eq!(o.offer_seq, 7);
    assert_eq!(o.payment_addr, Address::new([0x50; 20]));
    assert_eq!(o.offered_bytes, 1_000);
    assert_eq!(o.bond_locked, 500);
    assert!(o.active);
    assert!(o.id_is_derived(1));
    assert!(!o.id_is_derived(2), "the id is bound to its chain");
}

#[test]
fn the_offer_row_is_keyed_by_the_derived_id() {
    let mut m = ComputePoolModel::new();
    let o = BondedOffer::from_publish(1, kat_sender(), &publish(7), 500);
    let id = o.offer_bond_id;
    m.publish_offer(o).unwrap();
    let rows = ComputePoolStore::materialize(&m).unwrap();
    let key = offer_key_bytes(&id);
    assert_eq!(&key[1..], id.as_bytes(), "key = [OFFER] ‖ derived id");
    let row = decode_offer(rows.get(&key).expect("offer row under the derived key")).unwrap();
    assert_eq!(&row.offer_bond_id, id.as_bytes());
    assert_eq!(row.offer_seq, 7);
}

/// Distinct (chain, sender, seq) give distinct ids; the same triple always
/// gives the same id, so republishing one `offer_seq` collides.
#[test]
fn offer_ids_separate_chain_sender_and_seq() {
    let base = OfferBondId::derive(1, &kat_sender(), 7);
    assert_eq!(base, OfferBondId::derive(1, &kat_sender(), 7));
    assert_ne!(base, OfferBondId::derive(2, &kat_sender(), 7));
    assert_ne!(base, OfferBondId::derive(1, &Address::new([0x02; 20]), 7));
    assert_ne!(base, OfferBondId::derive(1, &kat_sender(), 8));

    let mut m = ComputePoolModel::new();
    let mut first = BondedOffer::from_publish(1, kat_sender(), &publish(7), 500);
    first.active = false;
    m.publish_offer(first).unwrap();
    let again = BondedOffer::from_publish(1, kat_sender(), &publish(7), 500);
    assert_eq!(m.publish_offer(again), Err(PoolError::DuplicateOffer));
    m.publish_offer(BondedOffer::from_publish(1, kat_sender(), &publish(8), 500))
        .unwrap();
}

// ── entitlement_id ───────────────────────────────────────────────────────────

#[test]
fn entitlement_id_derive_is_the_ratified_vectors() {
    let (j, u) = (kat_job(), kat_unit());
    for (kind, occ, want) in [
        (EntitlementKind::AcceptReimb, 0, ENT_ACCEPT_HEX),
        (EntitlementKind::ReassignReimb, 2, ENT_REASSIGN_OCC_2_HEX),
        (EntitlementKind::ReprovisionReimb, 0, ENT_REPROVISION_HEX),
    ] {
        let id = EntitlementId::derive(&j, &u, 1, kind, occ).unwrap();
        assert_eq!(hex::encode(id.as_bytes()), want);
    }
}

#[test]
fn one_time_kinds_refuse_a_nonzero_occurrence() {
    let (j, u) = (kat_job(), kat_unit());
    for kind in [
        EntitlementKind::AcceptReimb,
        EntitlementKind::ReprovisionReimb,
    ] {
        assert_eq!(
            EntitlementId::derive(&j, &u, 1, kind, 1),
            Err(PoolError::NonzeroOccurrence {
                kind,
                occurrence: 1
            })
        );
    }
}

/// The id names the event, not the payee: a second entitlement for the same
/// event is refused even when it names another beneficiary.
#[test]
fn a_second_entitlement_for_one_event_is_refused() {
    let (j, u) = (kat_job(), kat_unit());
    let mut m = ComputePoolModel::new();
    let id = EntitlementId::derive(&j, &u, 1, EntitlementKind::AcceptReimb, 0).unwrap();
    m.register_entitlement(record(id, EntitlementKind::AcceptReimb, 0x0A))
        .unwrap();
    let same_event = EntitlementId::derive(&j, &u, 1, EntitlementKind::AcceptReimb, 0).unwrap();
    assert_eq!(
        m.register_entitlement(record(same_event, EntitlementKind::AcceptReimb, 0x0B)),
        Err(PoolError::DuplicateEntitlement)
    );
}

/// Counted `ReassignReimb` occurrences are distinct events; repeating one
/// occurrence is refused.
#[test]
fn reassign_occurrences_are_distinct_events() {
    let (j, u) = (kat_job(), kat_unit());
    let mut m = ComputePoolModel::new();
    for occ in 0..3 {
        let id = EntitlementId::derive(&j, &u, 1, EntitlementKind::ReassignReimb, occ).unwrap();
        m.register_entitlement(record(id, EntitlementKind::ReassignReimb, 0x0A))
            .unwrap();
    }
    let repeat = EntitlementId::derive(&j, &u, 1, EntitlementKind::ReassignReimb, 1).unwrap();
    assert_eq!(
        m.register_entitlement(record(repeat, EntitlementKind::ReassignReimb, 0x0A)),
        Err(PoolError::DuplicateEntitlement)
    );
}

/// The entitlement row is keyed by the derived id, and its stored kind tag is
/// the same byte the id's preimage carries.
#[test]
fn the_entitlement_row_is_keyed_by_the_derived_id() {
    let (j, u) = (kat_job(), kat_unit());
    let mut m = ComputePoolModel::new();
    let mut ids = Vec::new();
    for (kind, occ) in [
        (EntitlementKind::AcceptReimb, 0),
        (EntitlementKind::ReassignReimb, 2),
        (EntitlementKind::ReprovisionReimb, 0),
    ] {
        let id = EntitlementId::derive(&j, &u, 1, kind, occ).unwrap();
        m.register_entitlement(record(id, kind, 0x0A)).unwrap();
        ids.push((id, kind));
    }
    let rows = ComputePoolStore::materialize(&m).unwrap();
    for (id, kind) in ids {
        let key = entitlement_key_bytes(&id);
        assert_eq!(&key[1..], id.as_bytes(), "key = [ENTITLEMENT] ‖ derived id");
        let row = decode_entitlement(rows.get(&key).expect("entitlement row")).unwrap();
        assert_eq!(&row.entitlement_id, id.as_bytes());
        assert_eq!(row.kind_tag, kind.to_u8());
        assert_eq!(row.kind().unwrap(), kind);
    }
}
