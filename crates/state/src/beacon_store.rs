//! BR1 randomness-beacon PERSISTENCE + REVERT contract (issue #127).
//!
//! The storage/revert boundary for the dormant beacon epoch/round state. It follows
//! the merged **C1 pattern** (`crate::compute_pool_store`) exactly — same digest
//! framing, same single-batch `persist_transition`, same journal-driven
//! `stage_block_revert` composed into the unified reorg batch — but for the beacon
//! keyspace. Because the beacon subsystem is **dormant by default**
//! (`beacon_enabled_from_height == None`), nothing writes a beacon journal during
//! live block execution, so the digest fold and the revert are byte/state-identical
//! no-ops under the production gate; they become live only once the gate opens.
//!
//! ## What is / isn't wired
//!
//! * **Wired (dormant, journal-presence-driven):** [`BeaconStore::state_digest`] is
//!   folded into the block state root **only when the beacon gate is open**
//!   (`crate::executor::compute_block_state_root`); [`BeaconStore::stage_block_revert`]
//!   is composed into the SAME atomic batch as account + contract + C1 revert
//!   (`crate::state::StateManager::revert_block_state_diffs`). Both are no-ops while
//!   no journal exists (always, under the `None` gate), so dormant behavior is
//!   unchanged.
//! * **Wired (live producer):** [`BeaconStore::materialize`] serializes the runtime
//!   epoch/round state into rows, and [`BeaconStore::load_materialized`] de-serializes
//!   them back for [`DkgEpoch::rehydrate`] / `BeaconChain::rehydrate`. The executor's
//!   per-block accumulator (`crate::beacon_manager::BeaconBlockState`) drives this on
//!   the gate-open path: a VALID beacon tx is accumulated and persisted as EXACTLY ONE
//!   journal per block (`materialize(rehydrate(rows)) == rows`, so a block persists a
//!   delta against the true prior state). Still a no-op under the `None` gate.
//!
//! The row set is a domain-prefixed `key -> value` map; the runtime supplies a
//! materialized snapshot and this module commits/reverts it. Rows are opaque bytes
//! to the store (validated only by their 1-byte domain prefix on revert), so the
//! runtime's serialization can evolve without touching this adapter.

use std::collections::BTreeMap;

use bincode::Options;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sumchain_beacon_runtime::dkg::{DealView, DkgEpoch};
use sumchain_beacon_runtime::rounds::BeaconChain;
use sumchain_primitives::{BlockHeight, Hash};
use sumchain_storage::{cf, Database};

use crate::{Result, StateError};

/// Local anti-DoS ceiling on a single decoded beacon journal, in bytes. NOT a
/// consensus/economic cap — it only bounds decoder allocation on a corrupt value.
pub const BEACON_DECODE_BYTE_LIMIT: u64 = 1 << 20;

/// On-disk schema version stamped as the first field of every typed beacon record.
/// A future ratified layout bumps this; decoders reject any other value. A change is
/// a consensus event once the gate can open (records feed [`BeaconStore::state_digest`]).
pub const BEACON_RECORD_VERSION: u8 = 1;

/// Canonical compressed G1 width (bytes) — encryption keys, carriers, commitments.
const G1_LEN: usize = 48;
/// Canonical compressed G2 width (bytes) — combined round signature `Σ_r`.
const G2_LEN: usize = 96;
/// ECIES body width (bytes) — `ct_{ij}`.
const CT_LEN: usize = 48;
/// Beacon output width (bytes).
const OUT_LEN: usize = 32;

/// Domain tag for [`BeaconStore::state_digest`]. **Explicitly versioned**
/// (`…state.v1`) — a FROZEN consensus value once the beacon gate can open (it is
/// committed into the block state root), so any change requires a deliberate,
/// activation-coordinated `…state.v2` bump, never an incidental edit. Pinned by the
/// golden test `beacon_state_digest_domain_is_frozen`.
const BEACON_STATE_DIGEST_DOMAIN: &[u8] = b"sumchain.beacon.state.v1";

/// Checked 4-byte little-endian frame prefix (rejects `> u32::MAX`, which would make
/// the digest concatenation ambiguous — a consensus hazard). Byte-identical to a
/// `len as u32` cast for every realistic length.
fn frame_len(n: usize) -> Result<[u8; 4]> {
    let framed = u32::try_from(n).map_err(|_| {
        StateError::InvalidOperation(format!(
            "beacon state digest: field length {n} exceeds u32::MAX; cannot frame unambiguously"
        ))
    })?;
    Ok(framed.to_le_bytes())
}

/// 1-byte domain/type prefixes for the beacon keyspace. Each persisted row key MUST
/// begin with one of these, so no category can alias another and a corrupt journal
/// key is rejected on revert.
pub mod domain {
    /// Registered per-epoch encryption key `EK_j` (+ PoP evidence).
    pub const KEY: u8 = 0x01;
    /// A `(dealer, recipient)` deal record.
    pub const DEAL: u8 = 0x02;
    /// A per-dealer / per-complaint verdict (QUAL disqualification, slash).
    pub const VERDICT: u8 = 0x03;
    /// A finalized round's combined signature.
    pub const ROUND: u8 = 0x04;
    /// A finalized round's beacon output.
    pub const OUTPUT: u8 = 0x05;
}

/// True iff `key`'s first byte is a recognized beacon domain prefix.
fn is_beacon_domain(key: &[u8]) -> bool {
    matches!(
        key.first(),
        Some(&domain::KEY | &domain::DEAL | &domain::VERDICT | &domain::ROUND | &domain::OUTPUT)
    )
}

// --- journal codec (bincode fixint LE + limit + reject-trailing, per C1) ---

fn beacon_codec() -> impl Options {
    bincode::options()
        .with_fixint_encoding()
        .with_little_endian()
        .with_limit(BEACON_DECODE_BYTE_LIMIT)
}

fn beacon_encode<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    beacon_codec()
        .serialize(value)
        .map_err(|e| StateError::SerializationError(e.to_string()))
}

fn beacon_decode<T: DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    beacon_codec()
        .reject_trailing_bytes()
        .deserialize(bytes)
        .map_err(|e| StateError::DeserializationError(e.to_string()))
}

// ---------------------------------------------------------------------------
// Canonical key encoders — domain prefix ‖ fixed-width big-endian body (Item 2).
// Big-endian so composite ordering matches numeric ordering for range scans.
// ---------------------------------------------------------------------------

/// `[KEY] ‖ validator_index(u32 BE)` (5 bytes).
pub fn key_row_key(validator_index: u32) -> Vec<u8> {
    let mut k = Vec::with_capacity(1 + 4);
    k.push(domain::KEY);
    k.extend_from_slice(&validator_index.to_be_bytes());
    k
}
/// `[DEAL] ‖ dealer_i(u32 BE) ‖ recipient_j(u32 BE)` (9 bytes).
pub fn deal_row_key(dealer_i: u32, recipient_j: u32) -> Vec<u8> {
    let mut k = Vec::with_capacity(1 + 8);
    k.push(domain::DEAL);
    k.extend_from_slice(&dealer_i.to_be_bytes());
    k.extend_from_slice(&recipient_j.to_be_bytes());
    k
}
/// `[VERDICT] ‖ dealer_i(u32 BE)` (5 bytes) — a disqualification.
pub fn disqualified_row_key(dealer_i: u32) -> Vec<u8> {
    let mut k = Vec::with_capacity(1 + 4);
    k.push(domain::VERDICT);
    k.extend_from_slice(&dealer_i.to_be_bytes());
    k
}
/// `[ROUND] ‖ round(u64 BE)` (9 bytes) — a finalized `Σ_r`.
pub fn round_row_key(round: u64) -> Vec<u8> {
    let mut k = Vec::with_capacity(1 + 8);
    k.push(domain::ROUND);
    k.extend_from_slice(&round.to_be_bytes());
    k
}
/// `[OUTPUT] ‖ round(u64 BE)` (9 bytes) — a beacon output.
pub fn output_row_key(round: u64) -> Vec<u8> {
    let mut k = Vec::with_capacity(1 + 8);
    k.push(domain::OUTPUT);
    k.extend_from_slice(&round.to_be_bytes());
    k
}

// ---------------------------------------------------------------------------
// Typed record DTOs — `schema_version` first; point fields are length-validated
// `Vec<u8>` (strict decode + bounds). Canonical serialization is `beacon_codec`
// (bincode fixint LE), identical for encode + decode. These pin the EXACT bytes a
// runtime state materializes into a store row (Item 2).
// ---------------------------------------------------------------------------

/// A registered epoch encryption key `EK_j` (draft §2.3, §11).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredBeaconKey {
    /// Record schema version (byte 0).
    pub schema_version: u8,
    /// 0-based validator/membership index `j`.
    pub validator_index: u32,
    /// Canonical compressed G1 `EK_j` (48 bytes).
    pub ek: Vec<u8>,
}

/// An accepted `(dealer i → recipient j)` deal (draft §8).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredBeaconDeal {
    /// Record schema version.
    pub schema_version: u8,
    /// Dealer index `i`.
    pub dealer_i: u32,
    /// Recipient index `j`.
    pub recipient_j: u32,
    /// Feldman commitments `C_{i,*}`, each canonical compressed G1 (48 bytes).
    pub commitments: Vec<Vec<u8>>,
    /// Carrier `R_{ij}` (48 bytes).
    pub r_ij: Vec<u8>,
    /// ECIES body `ct_{ij}` (48 bytes).
    pub ct_ij: Vec<u8>,
}

/// A disqualified dealer (draft §4.2 / §6.1 verdict).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredBeaconDisqualified {
    /// Record schema version.
    pub schema_version: u8,
    /// The disqualified dealer index.
    pub dealer_i: u32,
}

/// A finalized round's combined signature `Σ_r` (draft §4.3, §12).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredBeaconRound {
    /// Record schema version.
    pub schema_version: u8,
    /// The round.
    pub round: u64,
    /// Canonical compressed G2 `Σ_r` (96 bytes).
    pub sigma_r: Vec<u8>,
}

/// A finalized round's beacon output (draft §12.1 OUT domain).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredBeaconOutput {
    /// Record schema version.
    pub schema_version: u8,
    /// The round.
    pub round: u64,
    /// The 32-byte beacon output.
    pub output: Vec<u8>,
}

fn check_version(v: u8) -> Result<()> {
    if v == BEACON_RECORD_VERSION {
        Ok(())
    } else {
        Err(StateError::DeserializationError(format!(
            "unsupported beacon record schema version {v} (expected {BEACON_RECORD_VERSION})"
        )))
    }
}

fn check_len(field: &str, got: usize, want: usize) -> Result<()> {
    if got == want {
        Ok(())
    } else {
        Err(StateError::DeserializationError(format!(
            "beacon record: {field} length {got} != {want}"
        )))
    }
}

/// Strictly decode a [`StoredBeaconKey`] (version + `ek` length).
pub fn decode_key(bytes: &[u8]) -> Result<StoredBeaconKey> {
    let v: StoredBeaconKey = beacon_decode(bytes)?;
    check_version(v.schema_version)?;
    check_len("ek", v.ek.len(), G1_LEN)?;
    Ok(v)
}
/// Strictly decode a [`StoredBeaconDeal`] (version + all point lengths).
pub fn decode_deal(bytes: &[u8]) -> Result<StoredBeaconDeal> {
    let v: StoredBeaconDeal = beacon_decode(bytes)?;
    check_version(v.schema_version)?;
    check_len("r_ij", v.r_ij.len(), G1_LEN)?;
    check_len("ct_ij", v.ct_ij.len(), CT_LEN)?;
    if v.commitments.is_empty() {
        return Err(StateError::DeserializationError(
            "beacon deal: empty commitment vector".into(),
        ));
    }
    for c in &v.commitments {
        check_len("commitment", c.len(), G1_LEN)?;
    }
    Ok(v)
}
/// Strictly decode a [`StoredBeaconDisqualified`] (version).
pub fn decode_disqualified(bytes: &[u8]) -> Result<StoredBeaconDisqualified> {
    let v: StoredBeaconDisqualified = beacon_decode(bytes)?;
    check_version(v.schema_version)?;
    Ok(v)
}
/// Strictly decode a [`StoredBeaconRound`] (version + `Σ_r` length).
pub fn decode_round(bytes: &[u8]) -> Result<StoredBeaconRound> {
    let v: StoredBeaconRound = beacon_decode(bytes)?;
    check_version(v.schema_version)?;
    check_len("sigma_r", v.sigma_r.len(), G2_LEN)?;
    Ok(v)
}
/// Strictly decode a [`StoredBeaconOutput`] (version + output length).
pub fn decode_output(bytes: &[u8]) -> Result<StoredBeaconOutput> {
    let v: StoredBeaconOutput = beacon_decode(bytes)?;
    check_version(v.schema_version)?;
    check_len("output", v.output.len(), OUT_LEN)?;
    Ok(v)
}

/// One beacon state mutation captured for block-rollback revert.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BeaconMutation {
    /// The domain-prefixed row key.
    pub key: Vec<u8>,
    /// Pre-value (`None` = absent).
    pub old: Option<Vec<u8>>,
    /// Post-value (`None` = deleted).
    pub new: Option<Vec<u8>>,
}

/// Per-block journal of beacon state mutations for block-rollback revert.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct BeaconStateDiff {
    /// The mutations, canonical-key-sorted before persistence.
    pub records: Vec<BeaconMutation>,
}

impl BeaconStateDiff {
    /// Whether the journal is empty.
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }
    fn sort(&mut self) {
        self.records.sort_by(|a, b| a.key.cmp(&b.key));
    }
}

/// Persistence adapter for the dormant BR1 beacon state.
pub struct BeaconStore<'a> {
    db: &'a Database,
}

impl<'a> BeaconStore<'a> {
    /// Wrap a database handle.
    pub fn new(db: &'a Database) -> Self {
        Self { db }
    }

    /// **Materialize** the runtime beacon state into the canonical `key -> value` row
    /// set (Item 2 — the producer's runtime→row mapping, byte-pinned). Built from the
    /// runtime's public persistable accessors so it is a deterministic function of
    /// state *content* only (every backing collection is ordered), never insertion
    /// order. Registered keys, accepted deals, disqualifications, and (if a signing
    /// chain is supplied) finalized rounds + outputs each become a versioned,
    /// length-checked record under its domain-prefixed key.
    pub fn materialize(
        epoch: &DkgEpoch,
        chain: Option<&BeaconChain>,
    ) -> Result<BTreeMap<Vec<u8>, Vec<u8>>> {
        let mut rows: BTreeMap<Vec<u8>, Vec<u8>> = BTreeMap::new();
        for (idx, ek) in epoch.registered_keys() {
            rows.insert(
                key_row_key(idx),
                beacon_encode(&StoredBeaconKey {
                    schema_version: BEACON_RECORD_VERSION,
                    validator_index: idx,
                    ek: ek.to_vec(),
                })?,
            );
        }
        for d in epoch.accepted_deals() {
            rows.insert(
                deal_row_key(d.dealer_i, d.recipient_j),
                beacon_encode(&StoredBeaconDeal {
                    schema_version: BEACON_RECORD_VERSION,
                    dealer_i: d.dealer_i,
                    recipient_j: d.recipient_j,
                    commitments: d.commitments.iter().map(|c| c.to_vec()).collect(),
                    r_ij: d.r_ij.to_vec(),
                    ct_ij: d.ct_ij.to_vec(),
                })?,
            );
        }
        for i in epoch.disqualified() {
            rows.insert(
                disqualified_row_key(*i),
                beacon_encode(&StoredBeaconDisqualified {
                    schema_version: BEACON_RECORD_VERSION,
                    dealer_i: *i,
                })?,
            );
        }
        if let Some(chain) = chain {
            for (r, sigma_r, output) in chain.finalized_rounds() {
                rows.insert(
                    round_row_key(r),
                    beacon_encode(&StoredBeaconRound {
                        schema_version: BEACON_RECORD_VERSION,
                        round: r,
                        sigma_r: sigma_r.to_vec(),
                    })?,
                );
                rows.insert(
                    output_row_key(r),
                    beacon_encode(&StoredBeaconOutput {
                        schema_version: BEACON_RECORD_VERSION,
                        round: r,
                        output: output.to_vec(),
                    })?,
                );
            }
        }
        Ok(rows)
    }

    /// Read the full persisted beacon `key -> value` row set (canonical order).
    pub fn load_state_map(&self) -> Result<BTreeMap<Vec<u8>, Vec<u8>>> {
        let mut map = BTreeMap::new();
        for (k, v) in self.db.iter(cf::BEACON_STATE)? {
            map.insert(k.to_vec(), v.to_vec());
        }
        Ok(map)
    }

    /// **De-materialize** the persisted rows back into the runtime rehydration
    /// inputs (rows → runtime): `(keys, deals, disqualified, rounds)`. The inverse of
    /// [`materialize`](Self::materialize); strict-decodes every typed record. Feeds
    /// `DkgEpoch::rehydrate` / `BeaconChain::rehydrate` on restart and at each block
    /// start (so a block's transition is a delta against the true live state).
    #[allow(clippy::type_complexity)]
    pub fn load_materialized(
        &self,
    ) -> Result<(
        Vec<(u32, [u8; G1_LEN])>,
        Vec<DealView>,
        Vec<u32>,
        Vec<(u64, [u8; G2_LEN], [u8; OUT_LEN])>,
    )> {
        let rows = self.load_state_map()?;
        let mut keys = Vec::new();
        let mut deals = Vec::new();
        let mut disqualified = Vec::new();
        let mut round_sig: BTreeMap<u64, [u8; G2_LEN]> = BTreeMap::new();
        let mut round_out: BTreeMap<u64, [u8; OUT_LEN]> = BTreeMap::new();

        let as_arr = |v: &[u8], n: usize| -> Result<Vec<u8>> {
            if v.len() != n {
                return Err(StateError::DeserializationError(
                    "bad persisted length".into(),
                ));
            }
            Ok(v.to_vec())
        };

        for (k, v) in &rows {
            match k.first() {
                Some(&domain::KEY) => {
                    let sk = decode_key(v)?;
                    let mut ek = [0u8; G1_LEN];
                    ek.copy_from_slice(&as_arr(&sk.ek, G1_LEN)?);
                    keys.push((sk.validator_index, ek));
                }
                Some(&domain::DEAL) => {
                    let sd = decode_deal(v)?;
                    let mut r_ij = [0u8; G1_LEN];
                    r_ij.copy_from_slice(&as_arr(&sd.r_ij, G1_LEN)?);
                    let mut ct_ij = [0u8; CT_LEN];
                    ct_ij.copy_from_slice(&as_arr(&sd.ct_ij, CT_LEN)?);
                    let mut commitments = Vec::with_capacity(sd.commitments.len());
                    for c in &sd.commitments {
                        let mut cc = [0u8; G1_LEN];
                        cc.copy_from_slice(&as_arr(c, G1_LEN)?);
                        commitments.push(cc);
                    }
                    deals.push(DealView {
                        dealer_i: sd.dealer_i,
                        recipient_j: sd.recipient_j,
                        commitments,
                        r_ij,
                        ct_ij,
                    });
                }
                Some(&domain::VERDICT) => {
                    disqualified.push(decode_disqualified(v)?.dealer_i);
                }
                Some(&domain::ROUND) => {
                    let sr = decode_round(v)?;
                    let mut sig = [0u8; G2_LEN];
                    sig.copy_from_slice(&as_arr(&sr.sigma_r, G2_LEN)?);
                    round_sig.insert(sr.round, sig);
                }
                Some(&domain::OUTPUT) => {
                    let so = decode_output(v)?;
                    let mut out = [0u8; OUT_LEN];
                    out.copy_from_slice(&as_arr(&so.output, OUT_LEN)?);
                    round_out.insert(so.round, out);
                }
                _ => {
                    return Err(StateError::DeserializationError(
                        "unrecognized beacon row domain".into(),
                    ));
                }
            }
        }
        let rounds: Vec<(u64, [u8; G2_LEN], [u8; OUT_LEN])> = round_sig
            .into_iter()
            .filter_map(|(r, sig)| round_out.get(&r).map(|out| (r, sig, *out)))
            .collect();
        Ok((keys, deals, disqualified, rounds))
    }

    /// Deterministic, domain-separated digest over the FULL persisted beacon state.
    /// `DOMAIN ‖ for each (key, value): key_len(u32 LE) ‖ key ‖ val_len(u32 LE) ‖
    /// value` over `BTreeMap`-ordered rows. The block executor folds this into the
    /// state root **only when the beacon gate is open**; while dormant it is never
    /// folded, so dormant roots are byte-for-byte unchanged.
    pub fn state_digest(&self) -> Result<Hash> {
        let rows = self.load_state_map()?;
        let mut buf: Vec<u8> = Vec::with_capacity(BEACON_STATE_DIGEST_DOMAIN.len());
        buf.extend_from_slice(BEACON_STATE_DIGEST_DOMAIN);
        for (k, v) in &rows {
            buf.extend_from_slice(&frame_len(k.len())?);
            buf.extend_from_slice(k);
            buf.extend_from_slice(&frame_len(v.len())?);
            buf.extend_from_slice(v);
        }
        Ok(Hash::hash(&buf))
    }

    /// Whether a per-block beacon journal exists for `height`.
    pub fn has_journal(&self, height: BlockHeight) -> Result<bool> {
        Ok(self
            .db
            .contains(cf::BEACON_STATE_DIFFS, &height.to_be_bytes())?)
    }

    /// Load + canonically decode the per-height revert journal (`None` if absent —
    /// e.g. always under the dormant gate, which writes no journal).
    pub fn load_journal(&self, height: BlockHeight) -> Result<Option<BeaconStateDiff>> {
        match self.db.get(cf::BEACON_STATE_DIFFS, &height.to_be_bytes())? {
            Some(bytes) => Ok(Some(beacon_decode(&bytes)?)),
            None => Ok(None),
        }
    }

    /// Persist the transition `before -> after` for `height` **atomically** (one
    /// finalized beacon transition per block). Two hard preconditions checked BEFORE
    /// any write: a duplicate-height journal is rejected, and the claimed `before`
    /// row set must byte-for-byte equal the live persisted state (stale-predecessor
    /// rejection). All record writes/deletes + the journal write go into one
    /// [`Database::batch`] committed once. Returns the number of mutated rows.
    pub fn persist_transition(
        &self,
        before: &BTreeMap<Vec<u8>, Vec<u8>>,
        after: &BTreeMap<Vec<u8>, Vec<u8>>,
        height: BlockHeight,
    ) -> Result<usize> {
        if self.has_journal(height)? {
            return Err(StateError::InvalidOperation(format!(
                "beacon transition already finalized at height {height}; refusing to overwrite"
            )));
        }
        // Every row key must carry a recognized beacon domain prefix.
        for k in before.keys().chain(after.keys()) {
            if !is_beacon_domain(k) {
                return Err(StateError::InvalidOperation(
                    "beacon persist_transition: row key has no recognized domain prefix".into(),
                ));
            }
        }
        let live = self.load_state_map()?;
        if *before != live {
            return Err(StateError::InvalidOperation(
                "beacon persist_transition: stale `before` snapshot does not match live state"
                    .into(),
            ));
        }

        let mut keys: BTreeMap<Vec<u8>, ()> = BTreeMap::new();
        for k in before.keys().chain(after.keys()) {
            keys.insert(k.clone(), ());
        }

        let mut diff = BeaconStateDiff::default();
        let mut batch = self.db.batch();
        for key in keys.keys() {
            let new = after.get(key).cloned();
            let old = live.get(key).cloned();
            if old == new {
                continue;
            }
            match &new {
                Some(v) => batch.put(cf::BEACON_STATE, key, v)?,
                None => batch.delete(cf::BEACON_STATE, key)?,
            }
            diff.records.push(BeaconMutation {
                key: key.clone(),
                old,
                new,
            });
        }
        if diff.is_empty() {
            return Ok(0);
        }
        diff.sort();
        let journal = beacon_encode(&diff)?;
        batch.put(cf::BEACON_STATE_DIFFS, &height.to_be_bytes(), &journal)?;
        let mutated = diff.records.len();
        batch.commit()?;
        Ok(mutated)
    }

    /// Stage the reverse-replay of the per-height beacon journal (and the journal's
    /// own deletion) into a caller-provided [`WriteBatch`](sumchain_storage::db::
    /// WriteBatch), returning whether anything was staged (`false` when no journal
    /// exists — ALWAYS under the dormant gate). This composes into the SAME atomic
    /// write as the account + contract + C1 revert, so a crash can never leave a
    /// partially-reverted node. Every key's domain prefix is validated BEFORE it is
    /// staged, so a corrupt journal aborts the whole multi-family revert.
    pub fn stage_block_revert(
        &self,
        batch: &mut sumchain_storage::db::WriteBatch<'_>,
        height: BlockHeight,
    ) -> Result<bool> {
        let hkey = height.to_be_bytes();
        let Some(bytes) = self.db.get(cf::BEACON_STATE_DIFFS, &hkey)? else {
            return Ok(false);
        };
        let diff: BeaconStateDiff = beacon_decode(&bytes)?;
        for record in diff.records.iter().rev() {
            if !is_beacon_domain(&record.key) {
                return Err(StateError::InvalidOperation(format!(
                    "beacon revert: unrecognized key domain at height {height}"
                )));
            }
            match &record.old {
                Some(v) => batch.put(cf::BEACON_STATE, &record.key, v)?,
                None => batch.delete(cf::BEACON_STATE, &record.key)?,
            }
        }
        batch.delete(cf::BEACON_STATE_DIFFS, &hkey)?;
        Ok(true)
    }

    /// Atomically revert the beacon mutations recorded for `height` in isolation
    /// (its own [`Database::batch`]). Thin wrapper over [`stage_block_revert`](Self::
    /// stage_block_revert); retained for the standalone store tests. The LIVE reorg
    /// path drives `stage_block_revert` into the unified batch instead.
    pub fn revert_block(&self, height: BlockHeight) -> Result<()> {
        let mut batch = self.db.batch();
        if self.stage_block_revert(&mut batch, height)? {
            batch.commit()?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sumchain_storage::Database;
    use tempfile::TempDir;

    fn open_db() -> (Database, TempDir) {
        let dir = TempDir::new().unwrap();
        (Database::open_default(dir.path()).unwrap(), dir)
    }

    fn row(prefix: u8, k: &[u8], v: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let mut key = vec![prefix];
        key.extend_from_slice(k);
        (key, v.to_vec())
    }

    #[test]
    fn beacon_state_digest_domain_is_frozen() {
        assert_eq!(BEACON_STATE_DIGEST_DOMAIN, b"sumchain.beacon.state.v1");
        assert!(BEACON_STATE_DIGEST_DOMAIN.ends_with(b".v1"));
    }

    #[test]
    fn empty_digest_is_domain_only() {
        let (db, _d) = open_db();
        assert_eq!(
            BeaconStore::new(&db).state_digest().unwrap(),
            Hash::hash(BEACON_STATE_DIGEST_DOMAIN),
            "empty beacon state hashes to the domain-only digest"
        );
    }

    #[test]
    fn digest_is_insertion_order_independent_and_length_framed() {
        let a = row(domain::KEY, b"aa", b"1");
        let b = row(domain::DEAL, b"bb", b"22");
        let (db1, _dir1) = open_db();
        db1.put(cf::BEACON_STATE, &a.0, &a.1).unwrap();
        db1.put(cf::BEACON_STATE, &b.0, &b.1).unwrap();
        let d1 = BeaconStore::new(&db1).state_digest().unwrap();
        let (db2, _dir2) = open_db();
        db2.put(cf::BEACON_STATE, &b.0, &b.1).unwrap();
        db2.put(cf::BEACON_STATE, &a.0, &a.1).unwrap();
        let d2 = BeaconStore::new(&db2).state_digest().unwrap();
        assert_eq!(d1, d2, "digest is insertion-order independent");

        // Length framing disambiguates equal concatenations.
        let (db3, _dir3) = open_db();
        db3.put(cf::BEACON_STATE, &[domain::KEY, b'a', b'b'], b"c")
            .unwrap();
        let (db4, _dir4) = open_db();
        db4.put(cf::BEACON_STATE, &[domain::KEY, b'a'], b"bc")
            .unwrap();
        assert_ne!(
            BeaconStore::new(&db3).state_digest().unwrap(),
            BeaconStore::new(&db4).state_digest().unwrap()
        );
    }

    #[test]
    fn persist_revert_reapply_roundtrip() {
        let (db, _d) = open_db();
        let store = BeaconStore::new(&db);
        let (k1, v1) = row(domain::KEY, b"v0", b"ek0");
        let (k2, v2) = row(domain::ROUND, b"r0", b"sig0");

        let mut after = BTreeMap::new();
        after.insert(k1.clone(), v1.clone());
        after.insert(k2.clone(), v2.clone());
        let before = BTreeMap::new();

        let n = store.persist_transition(&before, &after, 1).unwrap();
        assert_eq!(n, 2);
        assert_eq!(store.load_state_map().unwrap(), after);
        let committed = store.state_digest().unwrap();

        // Revert restores the empty predecessor.
        store.revert_block(1).unwrap();
        assert!(store.load_state_map().unwrap().is_empty());
        assert_eq!(
            store.state_digest().unwrap(),
            Hash::hash(BEACON_STATE_DIGEST_DOMAIN)
        );
        assert!(!store.has_journal(1).unwrap());

        // Reapply reproduces the identical committed state.
        store.persist_transition(&before, &after, 1).unwrap();
        assert_eq!(store.state_digest().unwrap(), committed);
    }

    #[test]
    fn duplicate_height_and_stale_predecessor_rejected() {
        let (db, _d) = open_db();
        let store = BeaconStore::new(&db);
        let (k1, v1) = row(domain::KEY, b"v0", b"ek0");
        let mut after = BTreeMap::new();
        after.insert(k1, v1);
        let before = BTreeMap::new();
        store.persist_transition(&before, &after, 1).unwrap();

        // Duplicate height rejected.
        assert!(store.persist_transition(&before, &after, 1).is_err());
        // Stale predecessor (claims empty but live is non-empty) rejected at height 2.
        let after2 = after.clone();
        assert!(store
            .persist_transition(&BTreeMap::new(), &after2, 2)
            .is_err());
    }

    #[test]
    fn non_beacon_domain_row_rejected() {
        let (db, _d) = open_db();
        let store = BeaconStore::new(&db);
        let mut after = BTreeMap::new();
        after.insert(vec![0xFF, 0x00], b"x".to_vec()); // 0xFF is not a beacon domain
        assert!(store
            .persist_transition(&BTreeMap::new(), &after, 1)
            .is_err());
    }

    // ── Item 2: frozen typed-record codec + key layouts + strict decode ──────

    #[test]
    fn record_version_and_key_layouts_are_frozen() {
        assert_eq!(BEACON_RECORD_VERSION, 1);
        // Domain-prefixed big-endian composite keys (exact bytes pinned).
        assert_eq!(key_row_key(0), vec![0x01, 0, 0, 0, 0]);
        assert_eq!(key_row_key(3), vec![0x01, 0, 0, 0, 3]);
        assert_eq!(deal_row_key(1, 2), vec![0x02, 0, 0, 0, 1, 0, 0, 0, 2]);
        assert_eq!(disqualified_row_key(4), vec![0x03, 0, 0, 0, 4]);
        assert_eq!(round_row_key(5), vec![0x04, 0, 0, 0, 0, 0, 0, 0, 5]);
        assert_eq!(output_row_key(6), vec![0x05, 0, 0, 0, 0, 0, 0, 0, 6]);
    }

    #[test]
    fn stored_records_roundtrip_and_bytes_are_frozen() {
        // A key record with a fixed ek → frozen canonical bytes + strict decode.
        let k = StoredBeaconKey {
            schema_version: BEACON_RECORD_VERSION,
            validator_index: 2,
            ek: vec![0xAB; G1_LEN],
        };
        let kb = beacon_encode(&k).unwrap();
        // bincode fixint LE: version(1) ‖ u32_le(2) ‖ len(u64_le=48) ‖ 48×0xAB.
        assert_eq!(&kb[0..1], &[0x01]);
        assert_eq!(&kb[1..5], &2u32.to_le_bytes());
        assert_eq!(&kb[5..13], &48u64.to_le_bytes());
        assert_eq!(kb.len(), 1 + 4 + 8 + G1_LEN);
        assert_eq!(decode_key(&kb).unwrap(), k);

        // Round / output / disqualified round-trip.
        let r = StoredBeaconRound {
            schema_version: BEACON_RECORD_VERSION,
            round: 9,
            sigma_r: vec![0x11; G2_LEN],
        };
        assert_eq!(decode_round(&beacon_encode(&r).unwrap()).unwrap(), r);
        let o = StoredBeaconOutput {
            schema_version: BEACON_RECORD_VERSION,
            round: 9,
            output: vec![0x22; OUT_LEN],
        };
        assert_eq!(decode_output(&beacon_encode(&o).unwrap()).unwrap(), o);
        let d = StoredBeaconDisqualified {
            schema_version: BEACON_RECORD_VERSION,
            dealer_i: 3,
        };
        assert_eq!(decode_disqualified(&beacon_encode(&d).unwrap()).unwrap(), d);
    }

    #[test]
    fn strict_decode_rejects_bad_version_length_and_trailing() {
        // Wrong version.
        let bad_ver = StoredBeaconKey {
            schema_version: 2,
            validator_index: 0,
            ek: vec![0; G1_LEN],
        };
        assert!(decode_key(&beacon_encode(&bad_ver).unwrap()).is_err());
        // Wrong ek length.
        let bad_len = StoredBeaconKey {
            schema_version: BEACON_RECORD_VERSION,
            validator_index: 0,
            ek: vec![0; G1_LEN - 1],
        };
        assert!(decode_key(&beacon_encode(&bad_len).unwrap()).is_err());
        // Trailing bytes rejected by the canonical decoder.
        let mut trailing = beacon_encode(&StoredBeaconKey {
            schema_version: BEACON_RECORD_VERSION,
            validator_index: 0,
            ek: vec![0; G1_LEN],
        })
        .unwrap();
        trailing.push(0xFF);
        assert!(decode_key(&trailing).is_err());
        // A deal with an empty commitment vector is rejected.
        let bad_deal = StoredBeaconDeal {
            schema_version: BEACON_RECORD_VERSION,
            dealer_i: 0,
            recipient_j: 0,
            commitments: vec![],
            r_ij: vec![0; G1_LEN],
            ct_ij: vec![0; CT_LEN],
        };
        assert!(decode_deal(&beacon_encode(&bad_deal).unwrap()).is_err());
    }
}
