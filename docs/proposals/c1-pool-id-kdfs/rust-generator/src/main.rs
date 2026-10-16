//! UNRATIFIED DRAFT — NEW PROPOSAL. Not recovered §K bytes; not previously
//! ratified; not consensus; do not implement until ratified.
//!
//! Second, independent generator for the C1 pool identifier PROPOSAL vectors.
//! It assembles every preimage itself, hashes with the `blake3` crate the
//! sum-chain workspace locks, and takes `job_id`/`unit_id` from the frozen
//! `sumchain_wire::compute_pool_graph` functions. It shares no code with
//! `../generate.py`; `../check.py --rust` compares the two byte for byte.
//!
//! Output, one record per line, tab-separated:
//!   official  <input_len> <hash_hex>
//!   frozen    <name> <preimage_hex> <output_hex>
//!   vector    <name> <preimage_hex> <output_hex>
//!   reject    <kind> <occurrence> <reason>

use sumchain_wire::address::Address;
use sumchain_wire::compute_pool_graph::{job_id, unit_id, POOL_JOB_TAG, POOL_UNIT_TAG};

const OFFERBOND_TAG: &[u8] = b"SUMCHAIN/POOL/OFFERBOND/v1\n";
const RESERVATION_TAG: &[u8] = b"SUMCHAIN/POOL/RESERVATION/v1\n";
const ENTITLEMENT_TAG: &[u8] = b"SUMCHAIN/POOL/ENTITLEMENT/v1\n";

// The lengths of the official BLAKE3 test_vectors.json cases.
const OFFICIAL_LENS: &[usize] = &[
    0, 1, 2, 3, 4, 5, 6, 7, 8, 63, 64, 65, 127, 128, 129, 1023, 1024, 1025, 2048, 2049, 3072, 3073,
    4096, 4097, 5120, 5121, 6144, 6145, 7168, 7169, 8192, 8193, 16384, 31744, 102400,
];

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn hash(pre: &[u8]) -> [u8; 32] {
    *blake3::hash(pre).as_bytes()
}

fn offer_bond_id(chain_id: u64, sender: &[u8; 20], offer_seq: u64) -> (Vec<u8>, [u8; 32]) {
    let mut p = Vec::with_capacity(63);
    p.extend_from_slice(OFFERBOND_TAG);
    p.extend_from_slice(&chain_id.to_le_bytes());
    p.extend_from_slice(sender);
    p.extend_from_slice(&offer_seq.to_le_bytes());
    assert_eq!(p.len(), 63);
    let o = hash(&p);
    (p, o)
}

fn reservation_id(
    job: &[u8; 32],
    unit: &[u8; 32],
    generation: u64,
    offer: &[u8; 32],
) -> (Vec<u8>, [u8; 32]) {
    let mut p = Vec::with_capacity(133);
    p.extend_from_slice(RESERVATION_TAG);
    p.extend_from_slice(job);
    p.extend_from_slice(unit);
    p.extend_from_slice(&generation.to_le_bytes());
    p.extend_from_slice(offer);
    assert_eq!(p.len(), 133);
    let o = hash(&p);
    (p, o)
}

fn entitlement_id(
    job: &[u8; 32],
    unit: &[u8; 32],
    generation: u64,
    kind: u8,
    occurrence: u32,
) -> Result<(Vec<u8>, [u8; 32]), String> {
    match kind {
        0 | 2 if occurrence != 0 => {
            return Err(format!("kind {kind} is one-time: occurrence must be 0"))
        }
        0..=2 => {}
        _ => return Err(format!("kind {kind} is not in {{0,1,2}}")),
    }
    let mut p = Vec::with_capacity(106);
    p.extend_from_slice(ENTITLEMENT_TAG);
    p.extend_from_slice(job);
    p.extend_from_slice(unit);
    p.extend_from_slice(&generation.to_le_bytes());
    p.push(kind);
    p.extend_from_slice(&occurrence.to_le_bytes());
    assert_eq!(p.len(), 106);
    let o = hash(&p);
    Ok((p, o))
}

fn main() {
    for &len in OFFICIAL_LENS {
        let input: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
        println!("official\t{len}\t{}", hex(&hash(&input)));
    }

    let mut addr = [0u8; 20];
    for (i, b) in addr.iter_mut().enumerate() {
        *b = (i + 1) as u8; // 0x01..0x14
    }
    let (chain_id, nonce, salt, unit_index) = (1u64, 7u64, [0xAAu8; 32], 0u32);

    // Frozen ids: from the frozen functions, cross-checked against a preimage
    // assembled here.
    let job = job_id(chain_id, &Address::new(addr), nonce, &salt);
    let mut jp = Vec::new();
    jp.extend_from_slice(POOL_JOB_TAG);
    jp.extend_from_slice(&chain_id.to_le_bytes());
    jp.extend_from_slice(&addr);
    jp.extend_from_slice(&nonce.to_le_bytes());
    jp.extend_from_slice(&salt);
    assert_eq!(hash(&jp), job, "frozen job_id preimage");
    println!("frozen\tjob_id/kat\t{}\t{}", hex(&jp), hex(&job));

    let unit = unit_id(&job, unit_index);
    let mut up = Vec::new();
    up.extend_from_slice(POOL_UNIT_TAG);
    up.extend_from_slice(&job);
    up.extend_from_slice(&unit_index.to_le_bytes());
    assert_eq!(hash(&up), unit, "frozen unit_id preimage");
    println!("frozen\tunit_id/kat\t{}\t{}", hex(&up), hex(&unit));

    let out = |name: &str, (p, o): (Vec<u8>, [u8; 32])| {
        println!("vector\t{name}\t{}\t{}", hex(&p), hex(&o));
        o
    };
    let ob = out("offer_bond_id/base", offer_bond_id(1, &addr, 7));
    out("offer_bond_id/chain_id_2", offer_bond_id(2, &addr, 7));
    out(
        "offer_bond_id/byte_order",
        offer_bond_id(0x0807060504030201, &[0xFF; 20], 0x1122334455667788),
    );
    out("reservation_id/base", reservation_id(&job, &unit, 1, &ob));
    out(
        "entitlement_id/accept_reimb",
        entitlement_id(&job, &unit, 1, 0, 0).unwrap(),
    );
    out(
        "entitlement_id/reassign_reimb_occurrence_2",
        entitlement_id(&job, &unit, 1, 1, 2).unwrap(),
    );
    out(
        "entitlement_id/reprovision_reimb",
        entitlement_id(&job, &unit, 1, 2, 0).unwrap(),
    );
    out(
        "entitlement_id/reassign_reimb_byte_order",
        entitlement_id(&job, &unit, 0x0102030405060708, 1, 0x01020304).unwrap(),
    );

    for (kind, occ) in [(3u8, 0u32), (255, 0), (0, 1), (2, 1)] {
        let err = entitlement_id(&job, &unit, 1, kind, occ).expect_err("must be rejected");
        println!("reject\t{kind}\t{occ}\t{err}");
    }
}
