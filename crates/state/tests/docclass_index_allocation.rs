//! Every accumulating DocClass structure allocates its whole value BEFORE the
//! overlay accounts for it -- measured, not argued -- and an admitted update
//! preserves every existing entry in order.
//!
//! SEVEN structures grow without bound in this subsystem, and they are not all
//! indexes. Three are index VALUES:
//!
//!   * `DOCCLASS_SUBJECT_INDEX` in its identity shape,
//!     `Vec<(CredentialId, DocSubcode)>`, appended by `CreateIdentityRoot`;
//!   * `DOCCLASS_SUBJECT_INDEX` in its credential shape, `Vec<CredentialId>`,
//!     appended by `IssueCredential`;
//!   * `DOCCLASS_ISSUER_INDEX`, `Vec<CredentialId>`, appended by the same.
//!
//! The other four are `Vec` fields INSIDE primary rows, which a per-index audit
//! would have missed entirely:
//!
//!   * `IdentityRoot.keys`, appended by `AddKey` and `RotateKey`;
//!   * `IdentityRoot.additional_controllers`, appended by `AddController`;
//!   * `IdentityRoot.services`, appended by `UpdateService`;
//!   * `DocClassIssuer.keys`, appended by `RotateIssuerKey`.
//!
//! All seven are read-modify-write: each reads the existing value, pushes one
//! entry, and re-encodes the WHOLE value into a fresh `Vec<u8>`. Only then does
//! `view.put` charge the candidate's byte ceiling. So the ceiling bounds what a
//! block may COMMIT; it does not bound what a single transaction may ALLOCATE on
//! the way to being refused. The four row-field cases allocate twice over: the
//! read decodes the whole row into owned Rust values before the encode rebuilds
//! it.
//!
//! This file exists separately from `docclass_routing` because it installs a
//! counting global allocator, and a counting allocator is only meaningful if
//! nothing else in the binary is allocating at the same time. ONE test, run
//! alone, measuring seven structures in sequence.
//!
//! ## What this measures and what it does not
//!
//! It measures ONE fixture size, 20,000 entries, and reports the bytes actually
//! allocated while the ceiling was 8,192. It does not establish a bound for
//! arbitrary input: a larger value allocates proportionally more, and nothing in
//! the subsystem caps the length of any of these. ONE MEASURED SIZE DOES NOT
//! PROVE THAT ARBITRARY INPUT IS OOM-SAFE, and this file does not claim it does.
//! Capping any of them would change which transactions are valid, which is a
//! consensus change and belongs in separately activated work, so no cap is added
//! here.
//!
//! The variable-sized values that are NOT accumulated across transactions --
//! `DocClassIssuer.jurisdictions` and `authorized_subcodes`, the free-form
//! `jurisdiction` string on both credential types, `CredentialMetadata` and its
//! attribute list, `payload_hint` -- come from a single payload and are replaced
//! wholesale rather than read-modify-written, so they are bounded by whatever
//! bounds transaction size and are not measured here. `DOCCLASS_REVOCATIONS` and
//! `DOCCLASS_EVENTS` accumulate ROWS rather than growing a value, and each write
//! is a fixed-size row.

mod common;

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use common::{fund, setup_with_params, CHAIN_ID};
use sumchain_crypto::{sign, KeyPair};
use sumchain_genesis::ChainParams;
use sumchain_primitives::{
    Address, DocClassIssuer, DocClassIssuerStatus, DocClassIssuerType, DocClassOperation,
    DocClassTxData, DocSubcode, EligibilityAttestation, EligibilityType, IdentityKey, IdentityRoot,
    IdentityStatus, IssuerKey, KeyPurpose, KeyType, RevocationStatus, ServiceEndpoint,
    SignedTransaction, TransactionV2, TxPayload, TxStatus,
};
use sumchain_state::DocClassExecutor;
use sumchain_storage::exec_view::ExecutionView;
use sumchain_storage::overlay::ApplicationOverlay;
use sumchain_storage::{cf, Database, DocClassStore};

static BYTES: AtomicUsize = AtomicUsize::new(0);
static LARGEST: AtomicUsize = AtomicUsize::new(0);
static RECORDING: AtomicBool = AtomicBool::new(false);

struct Counting;

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if RECORDING.load(Ordering::Relaxed) {
            BYTES.fetch_add(layout.size(), Ordering::Relaxed);
            LARGEST.fetch_max(layout.size(), Ordering::Relaxed);
        }
        System.alloc(layout)
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        System.dealloc(ptr, layout)
    }
}

#[global_allocator]
static ALLOCATOR: Counting = Counting;

/// Run `f` with allocation counting on. Returns (value, total bytes, largest).
fn measure<T>(f: impl FnOnce() -> T) -> (T, usize, usize) {
    BYTES.store(0, Ordering::Relaxed);
    LARGEST.store(0, Ordering::Relaxed);
    RECORDING.store(true, Ordering::Relaxed);
    let out = f();
    RECORDING.store(false, Ordering::Relaxed);
    (
        out,
        BYTES.load(Ordering::Relaxed),
        LARGEST.load(Ordering::Relaxed),
    )
}

const CEILING: u64 = 8_192;
const N: usize = 20_000;
const JURISDICTION: &str = "US";
const FAT_IDENTITY: u8 = 0xE0;
const FAT_SUBJECT: u8 = 0xE1;

/// Every family this unit moved. Eight.
const DOCCLASS_CFS: &[&str] = &[
    cf::DOCCLASS_IDENTITY_ROOTS,
    cf::DOCCLASS_ELIGIBILITY,
    cf::DOCCLASS_CREDENTIALS,
    cf::DOCCLASS_REVOCATIONS,
    cf::DOCCLASS_ISSUERS,
    cf::DOCCLASS_SUBJECT_INDEX,
    cf::DOCCLASS_ISSUER_INDEX,
    cf::DOCCLASS_EVENTS,
];

fn params() -> ChainParams {
    let mut p = ChainParams::with_v2_enabled();
    if let Some(ref mut d) = p.docclass {
        d.min_issuer_stake = 0;
    }
    p
}

fn canonical(db: &Database) -> Vec<(String, Vec<u8>, Vec<u8>)> {
    let mut out = Vec::new();
    for f in DOCCLASS_CFS {
        for (k, v) in db.prefix_iter(f, &[]).unwrap() {
            out.push((f.to_string(), k.to_vec(), v.to_vec()));
        }
    }
    out.sort();
    out
}

fn twenty_thousand_ids() -> Vec<[u8; 32]> {
    (0..N as u32)
        .map(|i| {
            let mut id = [0u8; 32];
            id[..4].copy_from_slice(&i.to_be_bytes());
            id
        })
        .collect()
}

// ── Fixtures ────────────────────────────────────────────────────────────────

fn identity_key(id: &str, byte: u8) -> IdentityKey {
    IdentityKey {
        key_id: id.to_string(),
        key_type: KeyType::Ed25519,
        public_key: [byte; 32],
        purposes: vec![KeyPurpose::Authentication],
        added_at: 1_000,
        expires_at: 0,
        active: true,
    }
}

fn issuer_key(id: &str, byte: u8, is_primary: bool) -> IssuerKey {
    IssuerKey {
        key_id: id.to_string(),
        public_key: [byte; 32],
        key_type: KeyType::Ed25519,
        added_at: 1_000,
        expires_at: 0,
        active: true,
        is_primary,
    }
}

fn service(id: &str) -> ServiceEndpoint {
    ServiceEndpoint {
        service_id: id.to_string(),
        service_type: "CredentialRegistry".to_string(),
        endpoint: "https://example.invalid/registry".to_string(),
        description: None,
    }
}

fn identity(id: u8, controller: Address) -> IdentityRoot {
    IdentityRoot {
        identity_id: [id; 32],
        subject_commitment: [id.wrapping_add(0x40); 32],
        controller,
        additional_controllers: vec![],
        keys: vec![identity_key("auth-1", 1)],
        services: vec![],
        created_at: 1_000,
        updated_at: 1_000,
        status: IdentityStatus::Active,
        schema_hash: [0u8; 32],
    }
}

fn government_issuer(address: Address) -> DocClassIssuer {
    DocClassIssuer {
        address,
        name: "Registry of Vital Records".to_string(),
        issuer_type: DocClassIssuerType::Government,
        jurisdictions: vec![JURISDICTION.to_string()],
        authorized_subcodes: vec![DocSubcode::EligibilityAttestation],
        keys: vec![issuer_key("gov-1", 0x51, true)],
        registered_at: 1_000,
        updated_at: 1_000,
        status: DocClassIssuerStatus::Active,
        stake_amount: 0,
        metadata: None,
    }
}

fn eligibility(id: u8, issuer: Address, subject: [u8; 32]) -> EligibilityAttestation {
    EligibilityAttestation {
        credential_id: [id; 32],
        subject_address: Address::ZERO,
        subcode: DocSubcode::EligibilityAttestation,
        subject_commitment: subject,
        issuer,
        jurisdiction: JURISDICTION.to_string(),
        eligibility_type: EligibilityType::Citizenship,
        schema_hash: [0x61; 32],
        content_commitment: [0x62; 32],
        issued_at: 1_000,
        valid_from: 1_000,
        expires_at: 0,
        payload_hash: None,
        payload_hint: None,
        encryption_meta: None,
        issuer_signature: [0u8; 64],
        issuer_key_id: "gov-1".to_string(),
        revocation_status: RevocationStatus::Active,
        superseded_by: None,
    }
}

#[derive(serde::Serialize)]
struct AddKeyData {
    identity_id: [u8; 32],
    key: IdentityKey,
}

#[derive(serde::Serialize)]
struct ControllerData {
    identity_id: [u8; 32],
    controller: Address,
}

#[derive(serde::Serialize)]
struct UpdateServiceData {
    identity_id: [u8; 32],
    service: ServiceEndpoint,
}

#[derive(serde::Serialize)]
struct IssuerRotateKeyData {
    new_key: IssuerKey,
    old_key_id: String,
}

fn tx(
    kp: &KeyPair,
    operation: DocClassOperation,
    payload: &impl serde::Serialize,
) -> SignedTransaction {
    let t = TransactionV2 {
        chain_id: CHAIN_ID,
        from: kp.address(),
        fee: 100,
        nonce: 0,
        payload: TxPayload::DocClass(DocClassTxData {
            operation,
            subcode: DocSubcode::IdentityRoot,
            data: bincode::serialize(payload).unwrap(),
            recipient: Address::ZERO,
        }),
    };
    let sig = sign(t.signing_hash().as_bytes(), kp.private_key());
    SignedTransaction::new_v2(t, *sig.as_bytes(), *kp.public_key().as_bytes())
}

// ── Seeds ───────────────────────────────────────────────────────────────────

/// A 20,000-key identity, committed, so the operation under test has to read,
/// decode and re-encode all of it.
fn seed_fat_identity_keys(db: &Database, controller: Address) -> Vec<String> {
    let mut root = identity(FAT_IDENTITY, controller);
    root.keys = (0..N)
        .map(|i| identity_key(&format!("k{i}"), (i % 251) as u8))
        .collect();
    let ids: Vec<String> = root.keys.iter().map(|k| k.key_id.clone()).collect();
    DocClassStore::new(db).identity_roots().put(&root).unwrap();
    ids
}

fn seed_fat_identity_controllers(db: &Database, controller: Address) -> Vec<Address> {
    let mut root = identity(FAT_IDENTITY, controller);
    root.additional_controllers = (0..N as u32)
        .map(|i| {
            let mut b = [0u8; 20];
            b[..4].copy_from_slice(&i.to_be_bytes());
            Address::new(b)
        })
        .collect();
    let ids = root.additional_controllers.clone();
    DocClassStore::new(db).identity_roots().put(&root).unwrap();
    ids
}

fn seed_fat_identity_services(db: &Database, controller: Address) -> Vec<String> {
    let mut root = identity(FAT_IDENTITY, controller);
    root.services = (0..N).map(|i| service(&format!("s{i}"))).collect();
    let ids: Vec<String> = root.services.iter().map(|s| s.service_id.clone()).collect();
    DocClassStore::new(db).identity_roots().put(&root).unwrap();
    ids
}

fn seed_fat_issuer_keys(db: &Database, address: Address) -> Vec<String> {
    let mut issuer = government_issuer(address);
    issuer.keys = (0..N)
        .map(|i| issuer_key(&format!("k{i}"), (i % 251) as u8, false))
        .collect();
    let ids: Vec<String> = issuer.keys.iter().map(|k| k.key_id.clone()).collect();
    DocClassStore::new(db).issuers().put(&issuer).unwrap();
    ids
}

/// The counting allocator actually counts.
///
/// Called at the top of the measurement below rather than standing as its own
/// `#[test]`: two tests in this binary would run on two threads, and a counting
/// allocator that sees another thread's allocations measures nothing. One test
/// in the binary is what makes the numbers mean anything.
fn assert_the_allocator_measures_what_it_claims_to() {
    let ((), bytes, largest) = measure(|| {
        let v: Vec<u8> = Vec::with_capacity(1_000_000);
        std::hint::black_box(&v);
    });
    assert!(
        bytes >= 1_000_000 && largest >= 1_000_000,
        "a deliberate 1 MB allocation must be seen: total {bytes} B, largest {largest} B"
    );
    let ((), quiet, _) = measure(|| {});
    assert_eq!(quiet, 0, "and an empty window must measure zero");
    println!("allocator self-check: 1 MB seen, empty window measured 0 B");
}

/// One refusal measurement.
///
/// `seed` writes whatever the operation needs, INCLUDING the fat value, and
/// returns the exact bytes of the row the refusal must leave untouched. Then the
/// transaction runs under `CEILING` and the allocation is reported.
///
/// Each measurement is its own call because the seeding writes to the database
/// and the measuring constructs a candidate. Two of them in one body puts the
/// second seed after the first candidate, which is indistinguishable -- to
/// `no_test_publishes_a_candidate_by_hand`, and to a reader -- from a fixture
/// committing what it found in an overlay. One seed, then one candidate, per
/// call.
fn measure_refusal(
    family: &'static str,
    key: Vec<u8>,
    seed: impl FnOnce(&Database, Address),
    build_tx: impl FnOnce(&KeyPair) -> SignedTransaction,
) -> (usize, usize, u64) {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let actor = KeyPair::generate();
    fund(&db, &actor, 100_000_000);
    let proposer = Address::new([9; 20]);
    seed(&db, actor.address());
    let seeded = db
        .get(family, &key)
        .unwrap()
        .expect("the fat row must be seeded");
    let before = canonical(&db);
    let t = build_tx(&actor);

    let mut overlay = ApplicationOverlay::new(&db, CEILING);
    // The view borrows the overlay, and the overlay has to be readable after
    // the measurement. A scope ends the borrow; `drop` would not -- an
    // `ExecutionView` is not `Drop`, so dropping it by name does nothing the
    // scope does not already do.
    let (bytes, largest) = {
        let mut view = ExecutionView::new(&mut overlay);
        let (outcome, bytes, largest) =
            measure(|| executor.execute_tx(&mut view, &t, &proposer, 1, 1000));

        let err = outcome.expect_err("the ceiling must refuse the replacement");
        assert!(
            err.to_string().contains("limit"),
            "refused by the ceiling, not by something else: {err}"
        );
        // The candidate-visible old value is still exactly what was seeded.
        assert_eq!(
            view.get(family, &key).unwrap().as_deref(),
            Some(&seeded[..]),
            "{family}: the refused append must leave the old value \
             byte-identical in the candidate, not a truncated or partial one"
        );
        (bytes, largest)
    };

    assert_eq!(
        canonical(&db),
        before,
        "{family}: a refused append must commit nothing"
    );
    (bytes, largest, overlay.logical_bytes())
}

/// The same shape, admitted: a generous ceiling, and the resulting value read
/// back from the candidate.
fn admitted_append<T>(
    seed: impl FnOnce(&Database, Address),
    build_tx: impl FnOnce(&KeyPair) -> SignedTransaction,
    read_back: impl FnOnce(&ExecutionView<'_, '_>) -> T,
) -> T {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let actor = KeyPair::generate();
    fund(&db, &actor, 100_000_000);
    let proposer = Address::new([9; 20]);
    seed(&db, actor.address());
    let t = build_tx(&actor);

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);
    let r = executor
        .execute_tx(&mut view, &t, &proposer, 1, 1000)
        .unwrap();
    assert!(
        matches!(r.status, TxStatus::Success),
        "the append must be admitted under a generous ceiling: {:?}",
        r.status
    );
    read_back(&view)
}

/// One family's numbers: label, column family, bytes allocated during the
/// refused transaction, largest single allocation, and bytes the overlay
/// accounted for.
type Measurement = (&'static str, &'static str, usize, usize, u64);

fn report(results: &[Measurement], smallest_fixture: usize) {
    for (label, family, bytes, largest, accounted) in results {
        println!(
            "{label} ({family}): ceiling {CEILING} B, allocated {bytes} B during \
             the refused transaction, largest single allocation {largest} B, \
             overlay accounted {accounted} B"
        );
        assert!(
            *bytes >= smallest_fixture,
            "{label}: the whole value is built before the ceiling is consulted; \
             measured {bytes} B against a fixture of at least {smallest_fixture} B"
        );
        assert!(
            *bytes as u64 > CEILING * 50,
            "{label}: the allocation is not within two orders of magnitude of \
             the ceiling: {bytes} B against {CEILING} B"
        );
        assert!(
            *accounted <= CEILING,
            "{label}: the overlay's accounted size stays under its own ceiling, \
             which is the point -- it bounds what may be COMMITTED, not what may \
             be allocated: {accounted} B"
        );
    }
}

/// The ceiling is 8,192 bytes. Each of the seven accumulating structures still
/// allocates its entire value, and more, on the way to being refused -- and an
/// admitted append preserves every one of the 20,000 existing entries, in order,
/// with the new one last.
#[test]
fn all_seven_accumulating_structures_allocate_their_whole_value_before_the_ceiling_refuses() {
    assert_the_allocator_measures_what_it_claims_to();

    let ids = twenty_thousand_ids();
    let bare_fixture = bincode::serialize(&ids).unwrap();
    assert_eq!(
        bare_fixture.len(),
        640_008,
        "the bare id-list fixture must be exactly the size this test reports"
    );
    let pair_fixture = bincode::serialize(
        &ids.iter()
            .map(|id| (*id, DocSubcode::IdentityRoot))
            .collect::<Vec<_>>(),
    )
    .unwrap();
    assert_eq!(pair_fixture.len(), 720_008);

    let mut results: Vec<Measurement> = Vec::new();

    // 1. The subject index in its IDENTITY shape: `(id, subcode)` pairs.
    {
        let f = cf::DOCCLASS_SUBJECT_INDEX;
        let key = vec![0xF0u8.wrapping_add(0x40); 32];
        let fixture = pair_fixture.clone();
        let seed = |db: &Database, _issuer: Address| {
            db.put(
                cf::DOCCLASS_SUBJECT_INDEX,
                &[0xF0u8.wrapping_add(0x40); 32],
                &pair_fixture,
            )
            .unwrap();
        };
        let build = |actor: &KeyPair| {
            tx(
                actor,
                DocClassOperation::CreateIdentityRoot,
                &identity(0xF0, actor.address()),
            )
        };
        let (b, l, a) = measure_refusal(f, key, seed, build);
        results.push(("subject index, identity shape", f, b, l, a));

        let admitted = admitted_append(
            |db: &Database, _issuer: Address| {
                db.put(
                    cf::DOCCLASS_SUBJECT_INDEX,
                    &[0xF0u8.wrapping_add(0x40); 32],
                    &fixture,
                )
                .unwrap();
            },
            build,
            |view| {
                DocClassExecutor::v_get_subject_identity_entries(
                    view,
                    &[0xF0u8.wrapping_add(0x40); 32],
                )
                .unwrap()
            },
        );
        let mut expected: Vec<([u8; 32], DocSubcode)> = ids
            .iter()
            .map(|id| (*id, DocSubcode::IdentityRoot))
            .collect();
        expected.push(([0xF0u8; 32], DocSubcode::IdentityRoot));
        assert_eq!(admitted.len(), N + 1);
        assert_eq!(
            admitted, expected,
            "subject index, identity shape: every existing pair in order, with \
             the new one appended last"
        );
    }

    // 2. The subject index in its CREDENTIAL shape: bare ids.
    {
        let f = cf::DOCCLASS_SUBJECT_INDEX;
        let key = vec![FAT_SUBJECT; 32];
        let fixture = bare_fixture.clone();
        let seed_bytes = bare_fixture.clone();
        let seed = move |db: &Database, issuer: Address| {
            DocClassStore::new(db)
                .issuers()
                .put(&government_issuer(issuer))
                .unwrap();
            db.put(cf::DOCCLASS_SUBJECT_INDEX, &[FAT_SUBJECT; 32], &seed_bytes)
                .unwrap();
        };
        let build = |actor: &KeyPair| {
            tx(
                actor,
                DocClassOperation::IssueCredential,
                &eligibility(0xF1, actor.address(), [FAT_SUBJECT; 32]),
            )
        };
        let (b, l, a) = measure_refusal(f, key, seed, build);
        results.push(("subject index, credential shape", f, b, l, a));

        let admitted = admitted_append(
            move |db: &Database, issuer: Address| {
                DocClassStore::new(db)
                    .issuers()
                    .put(&government_issuer(issuer))
                    .unwrap();
                db.put(cf::DOCCLASS_SUBJECT_INDEX, &[FAT_SUBJECT; 32], &fixture)
                    .unwrap();
            },
            build,
            |view| {
                DocClassExecutor::v_get_subject_credential_ids(view, &[FAT_SUBJECT; 32]).unwrap()
            },
        );
        let mut expected = ids.clone();
        expected.push([0xF1u8; 32]);
        assert_eq!(admitted.len(), N + 1);
        assert_eq!(admitted, expected);
    }

    // 3. The issuer index.
    {
        let f = cf::DOCCLASS_ISSUER_INDEX;
        let fixture = bare_fixture.clone();
        let seed_bytes = bare_fixture.clone();
        // The key is the issuer's own address, which is the actor's, so the
        // seed closure receives it.
        let seed = move |db: &Database, issuer: Address| {
            DocClassStore::new(db)
                .issuers()
                .put(&government_issuer(issuer))
                .unwrap();
            db.put(cf::DOCCLASS_ISSUER_INDEX, issuer.as_bytes(), &seed_bytes)
                .unwrap();
        };
        let build = |actor: &KeyPair| {
            tx(
                actor,
                DocClassOperation::IssueCredential,
                // A subject commitment with NO fat index, so the refusal lands
                // on the issuer index and not on the subject one.
                &eligibility(0xF2, actor.address(), [0xF2u8; 32]),
            )
        };
        let (b, l, a) = measure_refusal_keyed_by_actor(f, seed, build);
        results.push(("issuer index", f, b, l, a));

        let admitted = admitted_append(
            move |db: &Database, issuer: Address| {
                DocClassStore::new(db)
                    .issuers()
                    .put(&government_issuer(issuer))
                    .unwrap();
                db.put(cf::DOCCLASS_ISSUER_INDEX, issuer.as_bytes(), &fixture)
                    .unwrap();
            },
            build,
            |view| {
                // The actor's address is not visible here, so read the one row
                // the family holds.
                let (_, bytes) = view
                    .prefix_iter(cf::DOCCLASS_ISSUER_INDEX, &[])
                    .unwrap()
                    .next()
                    .unwrap()
                    .unwrap();
                bincode::deserialize::<Vec<[u8; 32]>>(&bytes).unwrap()
            },
        );
        let mut expected = ids.clone();
        expected.push([0xF2u8; 32]);
        assert_eq!(admitted.len(), N + 1);
        assert_eq!(admitted, expected);
    }

    // 4. `IdentityRoot.keys` -- a `Vec` field INSIDE a primary row.
    {
        let f = cf::DOCCLASS_IDENTITY_ROOTS;
        let key = vec![FAT_IDENTITY; 32];
        let build = |actor: &KeyPair| {
            tx(
                actor,
                DocClassOperation::AddKey,
                &AddKeyData {
                    identity_id: [FAT_IDENTITY; 32],
                    key: identity_key("new", 9),
                },
            )
        };
        let (b, l, a) = measure_refusal(
            f,
            key,
            |db, controller| {
                seed_fat_identity_keys(db, controller);
            },
            build,
        );
        results.push(("IdentityRoot.keys", f, b, l, a));

        let (existing, admitted) = {
            let mut existing: Vec<String> = Vec::new();
            let admitted = admitted_append(
                |db, controller| existing = seed_fat_identity_keys(db, controller),
                build,
                |view| {
                    DocClassExecutor::v_get_identity_root(view, &[FAT_IDENTITY; 32])
                        .unwrap()
                        .unwrap()
                        .keys
                        .into_iter()
                        .map(|k| k.key_id)
                        .collect::<Vec<_>>()
                },
            );
            (existing, admitted)
        };
        let mut expected = existing;
        expected.push("new".to_string());
        assert_eq!(admitted.len(), N + 1);
        assert_eq!(admitted, expected, "IdentityRoot.keys: every key, in order");
    }

    // 5. `IdentityRoot.additional_controllers`.
    {
        let f = cf::DOCCLASS_IDENTITY_ROOTS;
        let key = vec![FAT_IDENTITY; 32];
        let build = |actor: &KeyPair| {
            tx(
                actor,
                DocClassOperation::AddController,
                &ControllerData {
                    identity_id: [FAT_IDENTITY; 32],
                    controller: Address::new([0xAB; 20]),
                },
            )
        };
        let (b, l, a) = measure_refusal(
            f,
            key,
            |db, controller| {
                seed_fat_identity_controllers(db, controller);
            },
            build,
        );
        results.push(("IdentityRoot.additional_controllers", f, b, l, a));

        let mut existing: Vec<Address> = Vec::new();
        let admitted = admitted_append(
            |db, controller| existing = seed_fat_identity_controllers(db, controller),
            build,
            |view| {
                DocClassExecutor::v_get_identity_root(view, &[FAT_IDENTITY; 32])
                    .unwrap()
                    .unwrap()
                    .additional_controllers
            },
        );
        let mut expected = existing;
        expected.push(Address::new([0xAB; 20]));
        assert_eq!(admitted.len(), N + 1);
        assert_eq!(admitted, expected);
    }

    // 6. `IdentityRoot.services`.
    {
        let f = cf::DOCCLASS_IDENTITY_ROOTS;
        let key = vec![FAT_IDENTITY; 32];
        let build = |actor: &KeyPair| {
            tx(
                actor,
                DocClassOperation::UpdateService,
                &UpdateServiceData {
                    identity_id: [FAT_IDENTITY; 32],
                    service: service("new"),
                },
            )
        };
        let (b, l, a) = measure_refusal(
            f,
            key,
            |db, controller| {
                seed_fat_identity_services(db, controller);
            },
            build,
        );
        results.push(("IdentityRoot.services", f, b, l, a));

        let mut existing: Vec<String> = Vec::new();
        let admitted = admitted_append(
            |db, controller| existing = seed_fat_identity_services(db, controller),
            build,
            |view| {
                DocClassExecutor::v_get_identity_root(view, &[FAT_IDENTITY; 32])
                    .unwrap()
                    .unwrap()
                    .services
                    .into_iter()
                    .map(|s| s.service_id)
                    .collect::<Vec<_>>()
            },
        );
        let mut expected = existing;
        expected.push("new".to_string());
        assert_eq!(admitted.len(), N + 1);
        assert_eq!(
            admitted, expected,
            "IdentityRoot.services: `UpdateService` also LINEAR-SCANS this list \
             looking for a matching service id before it appends"
        );
    }

    // 7. `DocClassIssuer.keys`.
    {
        let f = cf::DOCCLASS_ISSUERS;
        let build = |actor: &KeyPair| {
            tx(
                actor,
                DocClassOperation::RotateIssuerKey,
                &IssuerRotateKeyData {
                    new_key: issuer_key("new", 9, false),
                    old_key_id: "k0".to_string(),
                },
            )
        };
        let (b, l, a) = measure_refusal_keyed_by_actor(
            f,
            |db, address| {
                seed_fat_issuer_keys(db, address);
            },
            build,
        );
        results.push(("DocClassIssuer.keys", f, b, l, a));

        let mut existing: Vec<String> = Vec::new();
        let admitted = admitted_append(
            |db, address| existing = seed_fat_issuer_keys(db, address),
            build,
            |view| {
                let (_, bytes) = view
                    .prefix_iter(cf::DOCCLASS_ISSUERS, &[])
                    .unwrap()
                    .next()
                    .unwrap()
                    .unwrap();
                bincode::deserialize::<DocClassIssuer>(&bytes)
                    .unwrap()
                    .keys
                    .into_iter()
                    .map(|k| k.key_id)
                    .collect::<Vec<_>>()
            },
        );
        let mut expected = existing;
        expected.push("new".to_string());
        assert_eq!(admitted.len(), N + 1);
        assert_eq!(
            admitted, expected,
            "DocClassIssuer.keys: `RotateIssuerKey` walks this list TWICE -- once \
             for the retired key id and once to clear the primary flag -- before \
             it appends"
        );
    }

    assert_eq!(
        results.len(),
        7,
        "seven accumulating structures, seven rows"
    );
    report(&results, bare_fixture.len());
}

/// [`measure_refusal`] for the two families keyed by the ACTOR's own address,
/// which the caller cannot write down in advance.
fn measure_refusal_keyed_by_actor(
    family: &'static str,
    seed: impl FnOnce(&Database, Address),
    build_tx: impl FnOnce(&KeyPair) -> SignedTransaction,
) -> (usize, usize, u64) {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let actor = KeyPair::generate();
    fund(&db, &actor, 100_000_000);
    let proposer = Address::new([9; 20]);
    seed(&db, actor.address());
    let key = actor.address().as_bytes().to_vec();
    let seeded = db
        .get(family, &key)
        .unwrap()
        .expect("the fat row must be seeded");
    let before = canonical(&db);
    let t = build_tx(&actor);

    let mut overlay = ApplicationOverlay::new(&db, CEILING);
    let (bytes, largest) = {
        let mut view = ExecutionView::new(&mut overlay);
        let (outcome, bytes, largest) =
            measure(|| executor.execute_tx(&mut view, &t, &proposer, 1, 1000));
        let err = outcome.expect_err("the ceiling must refuse the replacement");
        assert!(
            err.to_string().contains("limit"),
            "refused by the ceiling, not by something else: {err}"
        );
        assert_eq!(
            view.get(family, &key).unwrap().as_deref(),
            Some(&seeded[..]),
            "{family}: the refused append must leave the old value \
             byte-identical in the candidate"
        );
        (bytes, largest)
    };

    assert_eq!(
        canonical(&db),
        before,
        "{family}: a refused append must commit nothing"
    );
    (bytes, largest, overlay.logical_bytes())
}
