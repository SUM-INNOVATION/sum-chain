# UNRATIFIED BYTE-REVIEW DRAFT. Semantics ratified 2026-10-16 (G2); bytes not ratified

**G2 byte review: authorization manifest, handshake hint, vote, certificate, signer state, evidence**

- **Status:** a proposal for the owner's byte review. Nothing here is consensus, frozen or implemented. Every vector is **SYNTHETIC/UNRATIFIED**, built from test-only Ed25519 seeds `[0x01;32]..[0x04;32]`, chain id 4242 and synthetic hashes.
- **Base:** sum-chain `main` `2c27524279339ff29b6b8073b8027f1e4d217f60`.
- **Files:** `generate.py` (stdlib-only generator), `check.py` (mechanical checks), `vectors.json`, `crosscheck-20260929.json`.

- **Decided since drafting (owner, 2026-10-16):** E1. Strict Ed25519 verification is the approved design direction for **new** finality and upgrade signatures, and historical signature verification stays unchanged. This is a direction, not ratified bytes.
- **Ratified since drafting (owner, 2026-10-17), group A1:**
  - D0: integers are little-endian in these objects and preimages, and big-endian only in database keys;
  - D4: round fields are `u32` with `round ≤ 2^20`;
  - D2: the certificate carries no explicit validator count; it is implied by the validator-set commitment.

  Dormant code for these conventions is in `crates/finality-foundations` (`encoding`, `certificate`). Ratifying the conventions froze no object layout and no database-key composition.
- **Still unresolved:** D3, D5, D6, M1–M5, H1 and S1 (groups A2–A5), and every object layout and key composition in this draft.

These semantics alone are **not** complete certified finality. See §10 for what is still missing.

## 0. The ratified semantics this serves (G2, 2026-10-16)

| Rule | Ratified semantics | Objects here |
|---|---|---|
| **G2-a** | A block is published canonically only together with a verified certificate, its post-state and the finalized pointer, in one durable atomic batch | certificate, vote, storage forms |
| **G2-b** | Durable signer state is persisted before a signature is released; exclusive ownership; explicit initialization; fail-closed recovery | signer state, mirror, vote, equivocation evidence |
| **G2-c** | Bootstrap authorization is quorum-signed, sequence-chained and shipped with the release. Genesis membership authenticates the first bootstrap only. Handshake announcements alone never authorize or halt. Conflicting fully verified authorizations halt safely without reverting accepted history. Late arrival never invalidates authentic applied history. Old binaries cannot be made to halt unless the framework was installed earlier. | manifest, hint, upgrade-conflict evidence, validator-set commitment |
| **G2-d** | No dynamic membership before certified finality | validator-set commitment (static genesis order) |

**Out of scope (separate decisions, not reviewed here):**
- round-aware proposer and header v2 (`build_round`);
- the proposal envelope and its sign bytes;
- notice and activation values (H, deadline, `notice_blocks`);
- consensus-library adoption;
- timeouts;
- the sync protocol;
- the applied-history marker record;
- the release's carriage of the new ConsensusConfig bytes.

**Superseded:**
- the 2026-09-29 `CUPGv1` layout (BL R3), whose magic `CUPGv1\0` and domain `SUMCHAIN/CONSENSUS-UPGRADE/v1\0` are retired and never reused;
- `FinalitySafetyStateV1` (BL §6, `FSAFv1`);
- the persisted `FinalityLockV1` (BL R2, `FLCKv1`).

**Sources reused** (owner-held review drafts, not in this repository):
- BL = `finality-byte-layout-review-draft-20260929.md` (§0–§7, R0–R5);
- GV = `finality-golden-vectors-draft-20260929.txt`;
- UD = `consensus-upgrade-design-268-20261001.md` (§1–§5; R7 §1; R8 §1);
- B1F = `finality-B1-F1-F3.md` (B-1, F-1, F-3);
- FD = `finality-decision-packet.md`;
- the superseded `owner-decision-packet-20261015.md` §1 and §4.

## 1. Conventions (D0)

| Item | Rule |
|---|---|
| Integers | Little-endian in every object, signed preimage and record. **Big-endian only in RocksDB keys**, so that keys sort by height. |
| Hash | BLAKE3-256 |
| Signature | Ed25519, RFC 8032 pure mode (no prehash, no context), 64 bytes. Verification criterion **E1**: strict verification is the approved design direction for new finality and upgrade signatures (owner, 2026-10-16); the bytes are still unratified. |
| Domains | ASCII, versioned, NUL-terminated. The NUL appears only as the last byte, so the set is prefix-free. Never reused across object kinds. |
| Magics | 7 bytes, ASCII + NUL; the first bytes of every standalone encoding |
| Decoding | Exact length. Every enum and flag byte is checked. An absent group must be all zero. Trailing bytes are refused. `schema` u16 = 1, and anything else is refused (no forward-compatible parsing, no defaults). |
| Round | u32, with the validity rule `round ≤ 2^20` (D4) on every round field |

**Domains and magics proposed here.** `check.py` confirms they are distinct, prefix-free, and clash with no retired draft and no byte-string literal under `crates/`.

| Constant | Bytes | Length | Use |
|---|---|---|---|
| `D_VALSET` | `SUMCHAIN/VALSET/v1\0` | 19 | validator-set commitment (BL §1, unchanged) |
| `D_VOTE` | `SUMCHAIN/FINALITY/VOTE/v1\0` | 26 | vote preimage (BL §3, unchanged) |
| `D_MDIGEST` | `SUMCHAIN/CONSENSUS-UPGRADE-MANIFEST/v1\0` | 39 | manifest digest |
| `D_MSIGN` | `SUMCHAIN/CONSENSUS-UPGRADE-MANIFEST/SIGN/v1\0` | 44 | manifest signature message |
| `D_HANDLER` | `SUMCHAIN/CONSENSUS-UPGRADE-HANDLER/v1\0` | 38 | handler identity |
| `D_SIGNER` | `SUMCHAIN/FINALITY/SIGNER/v1\0` | 28 | signer-state checksum |
| `D_SIGNBYTES` | `SUMCHAIN/FINALITY/SIGNBYTES/v1\0` | 31 | digest of released sign bytes |
| magics | `FVOTv1\0` `FCRTv1\0` `FEVDv1\0` (BL, unchanged) · `CUPMv1\0` manifest · `UHNTv1\0` hint · `FSGNv1\0` signer state · `UCEVv1\0` upgrade-conflict evidence | 7 each | |

**Cross-object signature separation.** Validator keys sign votes (`D_VOTE` ‖ 113 bytes) and manifests (`D_MSIGN` ‖ 276 bytes). Distinct NUL-terminated prefixes separate the two. Today's v1 block-header signatures sign a 32-byte hash, which can never equal either message. **The review must confirm that no other signing path for validator keys** (for example transactions) can produce a message beginning with a `SUMCHAIN/…\0` consensus domain.

## 2. Validator-set commitment (BL §1, unchanged)

| Offset | Size | Field |
|---|---|---|
| 0 | 19 | `D_VALSET` |
| 19 | 2 | n u16 (1 ≤ n ≤ 65535) |
| 21 | 32·n | Ed25519 public keys, in the authenticated order |

- `validator_set_commitment = BLAKE3(bytes)`.
- **Under G2-d, the authenticated order is the static genesis order** (ConsensusConfig field `0x0003 validators`, declared order) for every height until a reviewed change at or after certified finality lifts protocol-v1 containment.
- Duplicate keys are refused when the set is constructed.
- Sizes: n = 4 gives 149 bytes; n = 2 gives 85 bytes.

## 3. Finality vote `FinalityVoteV1` (BL §3, unchanged): serves G2-a and G2-b

| Offset | Size | Field (signed preimage, 139 bytes) |
|---|---|---|
| 0 | 26 | `D_VOTE` |
| 26 | 32 | consensus_config_commitment (this node's effective commitment at `height`) |
| 58 | 2 | schema u16 = 1 |
| 60 | 8 | height u64 |
| 68 | 32 | block_id (all zero = nil) |
| 100 | 4 | round u32 (≤ 2^20) |
| 104 | 1 | vote_type: 1 prevote, 2 precommit; anything else refused |
| 105 | 32 | validator_set_commitment of the set authenticated for `height` |
| 137 | 2 | validator_index u16 (< n) |

- **Wire form (184 bytes):** `FVOTv1\0` ‖ preimage[26..139] ‖ signature[64]. The receiver rebuilds the preimage by prefixing `D_VOTE`.
- **Refused when:**
  - the length is not 184;
  - the magic, schema, type or round cap fails;
  - the commitment or valset commitment is not the one for `height`;
  - the index is ≥ n;
  - the signature fails E1.
- **`block_id`** is the block identity under the rules in force at that height. Header v2 is out of scope.

## 4. Certificate `FinalityCertificateV1` (BL §4, unchanged): serves G2-a

| Offset | Size | Field |
|---|---|---|
| 0 | 7 | `FCRTv1\0` |
| 7 | 2 | schema u16 = 1 |
| 9 | 32 | consensus_config_commitment |
| 41 | 8 | height u64 |
| 49 | 32 | block_id (never zero) |
| 81 | 4 | round u32 (≤ 2^20) |
| 85 | 32 | validator_set_commitment |
| 117 | 2 | signer_count k u16 |
| 119 | 66·k | k × (validator_index u16 ‖ precommit signature[64]), indices strictly ascending |

**Signatures.** Each one is over the §3 preimage with `vote_type = 2` and the certificate's own fields.

**Refused when any of these holds:**
- the length ≠ 119 + 66k;
- k < q(n) = ⌊2n/3⌋+1, or k > n;
- an index is ≥ n, or the indices are not strictly ascending (so a duplicate is refused);
- block_id is zero;
- any signature is bad;
- the certificate does not name exactly the (height, block_id) being committed.

**Sizes:** n = 4 with k = 3 gives 317 bytes; n = 2 with k = 2 gives 251 bytes; the maximum at n = 100 is 6,719.

**G2-a storage forms.** #292's seam injects these as `CertifiedLayout`; they are written in **the same batch as block h's own publication**:
- certificate CF `finality_certificates`: key = height u64 **BE** ‖ block_id (40 bytes); value = the bytes above;
- finalized pointer: META `finality/finalized/v1` = height u64 LE ‖ block_id (40 bytes).

The legacy `finalized_height`/`finalized_hash` META records are not reused.

## 5. Evidence: serves G2-b and G2-c

### 5a. `EquivocationEvidenceV1` (BL §5, unchanged; 363 bytes)

| Offset | Size | Field |
|---|---|---|
| 0 | 7 | `FEVDv1\0` |
| 7 | 2 | schema u16 = 1 |
| 9 | 113 | vote A body (preimage[26..139]) |
| 122 | 64 | vote A signature |
| 186 | 113 | vote B body |
| 299 | 64 | vote B signature |

**Validity.**
- Both votes carry the same commitment, height, round, type, valset commitment and index.
- `A.block_id < B.block_id` bytewise. Nil against non-nil counts as a conflict.
- Both signatures verify.

There is exactly one canonical encoding; non-canonical order and identical blocks are refused. No penalty is attached; that ruling stands.

**Storage (D5).** CF `finality_evidence`, key = height u64 BE ‖ round u32 BE ‖ type u8 ‖ index u16 BE (15 bytes). The first valid record is kept.

### 5b. `UpgradeConflictEvidenceV1` (new)

| Offset | Size | Field |
|---|---|---|
| 0 | 7 | `UCEVv1\0` |
| 7 | 2 | schema u16 = 1 |
| 9 | 4 | len_a u32 |
| 13 | len_a | manifest A, complete §6 bytes including signatures |
| 13+len_a | 4 | len_b u32 |
| 17+len_a | len_b | manifest B |

**Validity.**
- Both manifests fully verify (§6) against the same authenticating set and chain identity.
- They have the same `sequence`.
- `digest(A) < digest(B)`.
- Equal digests are refused. Two signer subsets of one body share a digest, so that is never a conflict.

**Effect (G2-c).** The node records the evidence and halts **without reverting accepted history**:
- discovered before either activation height: halt before the earlier H and apply neither;
- discovered after one of them was applied: halt at once, keep the applied history, never unwind or re-execute it.

Only full manifest bytes can produce this record; a hint never does.

**Storage.** META key `upgrade/conflict/v1/` ‖ sequence u64 BE (28 bytes), keeping the first valid record. At n = 2, this is 837 bytes.

## 6. `ConsensusUpgradeManifestV1` (new; supersedes `CUPGv1`): serves G2-c

| Offset | Size | Field |
|---|---|---|
| 0 | 7 | `CUPMv1\0` |
| 7 | 2 | schema u16 = 1 |
| 9 | 8 | chain_id u64 |
| 17 | 32 | genesis_block_hash |
| 49 | 8 | sequence u64 (≥ 1) |
| 57 | 32 | previous_manifest_digest (all zero **iff** sequence = 1) |
| 89 | 32 | old_config_commitment |
| 121 | 32 | new_config_commitment (≠ old) |
| 153 | 2 | protocol_version u16 produced (≥ 2; the first is 2) |
| 155 | 8 | checkpoint_height u64 |
| 163 | 32 | checkpoint_block_hash (≠ 0) |
| 195 | 8 | activation_height H u64 |
| 203 | 8 | signing_deadline_height u64 |
| 211 | 32 | validator_set_commitment of the authenticating set (§2) |
| 243 | 1 | quorum_rule u8 = 1 (headcount ⌊2n/3⌋+1) |
| 244 | 32 | handler_digest |
| **276** | 2 | signer_count k u16 (end of body at 276) |
| 278 | 66·k | k × (validator_index u16 ‖ Ed25519 signature[64]), indices strictly ascending |

**Derived values:**
- `body` = bytes[0..276];
- `manifest_digest = BLAKE3(D_MDIGEST ‖ body)`, which excludes the signatures, so the identity does not depend on which signers signed;
- signature message = `D_MSIGN ‖ body` (open choice M1);
- `handler_digest = BLAKE3(D_HANDLER ‖ name_len u8 ‖ name ‖ handler_version u16)`, where the name is 1–64 bytes of `[a-z0-9-]` (M2);
- size: 278 + 66k, so 410 bytes at n = 2.

**Structural checks (decoder; no keys needed):**
- magic, schema, exact length and `quorum_rule = 1`;
- `sequence ≥ 1`, with a zero previous digest exactly when sequence = 1;
- `old ≠ new`;
- `protocol_version ≥ 2`;
- a non-zero checkpoint hash;
- `checkpoint_height < signing_deadline_height < activation_height`;
- `activation_height − signing_deadline_height ≥ notice`, where the notice is an **injected parameter whose value is not part of this review**;
- k ≥ 1 with strictly ascending indices;
- no trailing bytes.

**Authentication of the first bootstrap (G2-c, M4):**
- `chain_id` and `genesis_block_hash` equal the node's own;
- **sequence = 1** (genesis membership authenticates the first bootstrap only);
- `validator_set_commitment` = the genesis set in declared order;
- q(n) ≤ k ≤ n, every index < n, and every signature verifies under `pubkey[index]` over `D_MSIGN ‖ body`.

**Node acceptance** (release-N+1 logic, not bytes; UD §3 and B1F B-1):
- the previous digest chains onto the applied history;
- `old_config_commitment` equals the node's effective commitment;
- `new_config_commitment` equals what this binary computes, otherwise "unsupported" and the node halts before H;
- the checkpoint block is on the node's canonical chain.

**Deadline.** The signing deadline is signer policy. Nodes check only the internal ordering, and **never reject an authentic applied manifest for arriving late**.

**Old binaries.** A binary without the halt framework cannot be made to halt by any manifest or hint. Release N must ship the framework before release N+1 matters.

**Signer tool (G2-c anti-equivocation).** Before releasing a signature, it fsyncs (sequence, manifest_digest). It refuses a different body at a recorded sequence, and refuses to sign at all if that state is missing or corrupt.

## 7. Handshake hint `UpgradeHintV1` (new): serves G2-c as a hint only

| Offset | Size | Field |
|---|---|---|
| 0 | 7 | `UHNTv1\0` |
| 7 | 2 | schema u16 = 1 |
| 9 | 32 | genesis_block_hash |
| 41 | 8 | applied_sequence u64 (0 = none applied) |
| 49 | 32 | applied_manifest_digest (all zero **iff** applied_sequence = 0) |
| 81 | 1 | next_present u8 (0/1) |
| 82 | 32 | next_manifest_digest (all zero iff absent; non-zero iff present) |
| 114 | 8 | next_activation_height u64 (0 iff absent; non-zero iff present) |
| 122 | — | total |

**Implied fields.**
- `next_sequence` = `applied_sequence + 1` (H1).
- `applied_manifest_digest` commits the whole applied chain, because each manifest binds its predecessor's digest.

**Rules (G2-c).**
- A node advertises `next` only for a manifest it has **fully verified** (U6).
- A received hint **never authorizes, applies, halts or creates evidence**. Acting on it requires fetching and verifying the full manifest bytes.
- The UD §5 table uses hints for peer selection only:
  - connect: same applied history, a lagging prefix, or the local node behind;
  - disconnect: divergent applied histories;
  - refuse consensus participation, while still serving history: a peer past H without M.
- Peer refusal is not a halt.

## 8. Signer state `SignerStateV1` and mirror (new; replace BL §6): serve G2-b

**File** `<data_dir>/finality/signer.v1`. It lives outside RocksDB, so deleting or restoring the chain database never touches it. Ownership is a non-blocking exclusive `flock` on `<data_dir>/finality/signer.v1.lock`, held for the signer's lifetime. That lock is a zero-byte OS lock file, not a record.

| Offset | Size | Field |
|---|---|---|
| 0 | 7 | `FSGNv1\0` |
| 7 | 2 | schema u16 = 1 |
| 9 | 8 | counter u64: 0 at initialization, +1 on every persisted write; this is the classification counter |
| 17 | 8 | chain_id u64 |
| 25 | 32 | genesis_block_hash |
| 57 | 32 | signer_pubkey (the key this state belongs to) |
| 89 | 8 | floor_height u64 (nothing is signed below it) |
| 97 | 1 | last_present u8 (0/1) |
| 98 | 8 | last_height u64 (≥ floor) |
| 106 | 4 | last_round u32 (≤ 2^20) |
| 110 | 1 | last_step u8: 1 proposal (sign bytes out of scope), 2 prevote, 3 precommit |
| 111 | 32 | last_sign_bytes_digest = BLAKE3(`D_SIGNBYTES` ‖ sign bytes) |
| 143 | 64 | last_signature (re-released only for byte-identical sign bytes) |
| 207 | 1 | lock_present u8 (0/1) |
| 208 | 8 | lock_height u64 (≥ floor) |
| 216 | 4 | lock_round u32 (≤ 2^20) |
| 220 | 32 | lock_value (non-zero block_id) |
| 252 | 32 | checksum = BLAKE3(`D_SIGNER` ‖ bytes[0..252]) |
| 284 | — | total |

**Encoding rules.** An absent group must be all zero. A counter-0 (initialization) record must have no `last` and no lock. Only lock and relock are persisted: valid_round and valid_value are liveness-only (D6).

**Mirror `SignerMirrorV1`.**
- It lives in node-database META `finality/signer-mirror/v1`, as counter u64 ‖ height u64 ‖ round u32 ‖ step u8 (21 bytes).
- Step 0 means "initialized, nothing signed".
- It is written with a synced WAL after the state file.

**Release order (G2-b, B1F F-3):**
1. Derive the sign bytes.
2. Check them against the state: refuse anything below the floor or below `last`; at an equal (h, r, step), return the stored σ only for an identical digest; enforce the lock and relock rules.
3. Sign in memory.
4. **P1:** write a temporary file, fsync it, rename it over the state file, fsync the directory.
5. **P2:** write the mirror with a synced WAL. A failure at P1 or P2 drops σ and poisons the signer.
6. Release σ.
7. **P3:** append to the consensus WAL (a liveness aid only), then send.

**Classification at open (fail-closed):**

| State file vs mirror | Verdict |
|---|---|
| file absent, mirror absent | uninitialized: signs nothing until explicit initialization (D3) |
| file absent, mirror present | refuse |
| bad checksum or decode | refuse |
| counter < mirror | rolled back: refuse |
| counter = mirror + 1 | crash between P1 and P2: repair the mirror |
| counter > mirror + 1 | refuse |
| counter = mirror | consistent |
| `signer_pubkey`, `chain_id` or `genesis_block_hash` ≠ the node's own | refuse |

**Process-crash testing only.** The R7 and R8 spikes tested this model under process crashes. **Durability across power loss is unproven.**

**Operator rules software cannot enforce:**
- never run two signers for one key;
- never restore signer state from a backup or snapshot;
- after any restore, re-initialize with a floor above every height the key could have signed.

## 9. Open choices (each with a recommendation)

| Id | Choice | Recommendation | Alternatives |
|---|---|---|---|
| **D0** | Integer byte order | **LE** in objects and records; **BE** only in RocksDB keys. The frozen `protocol_digest` stays BE and never shares an encoder with these objects. | All BE; or per object (invites encoder mistakes) |
| **D2** | Explicit n in the certificate | **Omit.** n is implied by the valset commitment the verifier must resolve anyway. | Add `n u16` at offset 117 (+2 bytes, plus a new mismatch refusal) |
| **D3** | Creating signer state | **An explicit operator initialization** that writes counter 0 with the floor, and refuses if the file or mirror exists | Automatic creation on first start, which cannot tell a fresh signer from a lost one (the double-sign case) |
| **D4** | Round range | **u32 with the validity rule `round ≤ 2^20`** on every round field | Unbounded u32; u16 |
| **D5** | Evidence retention | **First valid record per slot**: (h, r, type, index) for votes, and sequence for upgrade conflicts | Keep all (unbounded under spam); keep latest (overwritable) |
| **D6** | Durable safety files | **One file, the signer state.** No `FLCKv1` record; valid_round and valid_value are not persisted. | A separate lock record, with a cross-file consistency failure mode |
| **M1** | Manifest signature message | **`D_MSIGN ‖ body`**, the full 276-byte body with its magic | `D_MSIGN ‖ digest` (32 bytes); or B-1's `domain ‖ body[7..]` |
| **M2** | Handler identity | **One digest over (name, version)**. The new commitment and the release bind the rules themselves. | B-1's separate `handler_version` plus a digest including an undefined "migration digest" |
| **M3** | Cancellation | **Not in v1.** Cancellation semantics need their own ratification and would take a new schema value. | An `action u8` byte now (1 = activate, 2 = cancel) |
| **M4** | Scope of genesis authentication | **Sequence 1 only**, the literal G2-c reading. Consequence: a pre-H cancellation or replacement through sequence 2 cannot be authenticated by genesis membership, so stopping a bad sequence-1 manifest relies on not installing it, or on signing a conflicting sequence-1 manifest (which halts). | Any manifest while static membership governs, i.e. before certified finality is active |
| **M5** | `quorum_version` (in B-1) | **Drop it.** It has no meaning separate from `quorum_rule`. | Keep it as a reserved byte = 1 |
| **H1** | Next sequence in the hint | **Implied** (applied + 1); the applied digest is the last applied manifest digest | Explicit field (a redundant mismatch case); a separate accumulator |
| **S1** | Signer-state binding and content | **Bind chain identity and the signer's public key**, not commitment, valset or index, which can change across upgrades. **Store the digest of the sign bytes**, which supports variable-length proposals. | BL §6's binding to commitment, valset and index; storing the full sign bytes |
| **E1** | Ed25519 verification criterion, which must be identical on every node | **APPROVED DESIGN DIRECTION (owner, 2026-10-16), for NEW finality and upgrade signatures only: strict.** Canonical S < L and canonical R and A encodings; reject small-order A and R; the cofactorless equation (ed25519-dalek `verify_strict` semantics). Historical signature verification (every existing path, including `sumchain-crypto` `verify`) is unchanged. The bytes are still unratified; edge-case vectors are added with the byte ratification. | ZIP-215 (cofactored, permissive, batch-friendly); or today's `sumchain-crypto` `verify` (cofactorless, accepts small-order keys) |

## 10. What this artifact does not provide (do not read it as complete certified finality)

None of the following is reviewed here:
- a consensus core or library;
- the proposal envelope and its sign bytes;
- the round-aware proposer and header v2;
- timeouts;
- the sync protocol;
- the applied-history marker;
- the halt framework's records;
- notice and H values;
- an activation plan.

Certified finality needs all of them, plus the remaining decisions and authorization.

## 11. Draft text that conflicts with the ratified G2 semantics

1. **BL R0 and §7: "H+1 cannot become canonical without a stored certificate for H"** ("distance 1"; storage "for H+1 gating"). This conflicts with G2-a, under which block h's own certificate is written in h's own publication batch. The BL §7 key and pointer bytes are reused; the gating text is replaced.
2. **BL §6 `FinalitySafetyStateV1`** conflicts with G2-b:
   - it makes the WAL and lock record the safety mechanism;
   - it persists valid_*;
   - it binds commitment, valset and index;
   - its `last_type` covers votes only;
   - it has no floor;
   - its `seq` is not a classification counter.

   It is replaced by §8. The ratified "missing or corrupt safety WAL ⇒ refuse to vote" is read as "signer state".
3. **BL R2 `FLCKv1`.** It is not persisted (D6).
4. **BL R3 `CUPGv1`** has no checkpoint, sequence chain or handler. It is superseded, and its magic and domain are retired.
5. **B-1 / B1F: every manifest is "verified against the static genesis set".** G2-c ratifies genesis authentication for the **first** bootstrap only. The V1 verifier therefore refuses sequence ≥ 2 (M4), and B-1's pre-H cancellation "sequence + 1" path is unavailable under genesis authentication.
6. **B1F, UD §4 and CD C4: on a conflict, "halt before the earlier H; apply neither".** This is incomplete when one manifest was already applied. G2-c requires halting **without reverting accepted history**; §5b states both cases.
7. **UD §5, "conflicting valid manifest → record evidence; halt".** This is consistent only for full, verified manifest bytes. A digest mismatch carried in a hint must never halt (§7).
8. **FP §11 / CD C5, "the handshake requires exact commitment equality".** This is consistent only as peer selection; refusing a peer is not a halt and is not authorization.
9. **The draft's synthetic commitment** uses a pre-merge, header-only `CCFGv1` encoding that differs from the merged schema-1 codec. These vectors use it only as an opaque 32-byte stand-in.

These are deviations from B-1's proposed table, not conflicts: `quorum_version` is dropped (M5), `handler_version` is folded into `handler_digest` (M2), and the magic is fixed as `CUPMv1\0`.

## 12. Synthetic vectors (excerpt; every vector is in `vectors.json`)

**Inputs:**
- keys: seeds `[0x01;32]..[0x04;32]`;
- the manifest's genesis set is the first two keys (n = 2): valset commitment `1259c941402c71a49c65efe0ea648063e4728cea56a3248d4c2107a66ab49dd5`;
- the stand-in commitment is `afcb234f872390f110bbd92112b0b739962b202e5c2373f4dc658307f6ebdaf3`;
- genesis = BLAKE3("synthetic genesis block 4242");
- new config = BLAKE3("synthetic proposed config 4242");
- checkpoint 90,000, deadline 95,000 and H 100,000;
- handler "certified-finality" v1 → `65a561cbc3082dbc5f312a666acb4c5b5d86bca13d452d2db5ebe8e295ea2c1e`.

**Manifest A**, signed by both keys (410 bytes). Its digest is `9fdf6972973a796fabd02f1ea2fc279e7440466c940151a220ded3c4b6ade387`.

```
4355504d76310001009210000000000000db35ed1bed1296e6fc2786072a1a9ec30813e79e7f8f0873d578d7a11cb5f52701000000000000000000000000000000000000000000000000000000000000000000000000000000afcb234f872390f110bbd92112b0b739962b202e5c2373f4dc658307f6ebdaf3c7bc0adfc23547011944cd316888509538ce17bb5753890758549842a3e47d320200905f0100000000001cf00ab6588f7c77dce79299c774a40bcdf55bd8447d7a8b50294abd1e4f5320a08601000000000018730100000000001259c941402c71a49c65efe0ea648063e4728cea56a3248d4c2107a66ab49dd50165a561cbc3082dbc5f312a666acb4c5b5d86bca13d452d2db5ebe8e295ea2c1e020000007d2ea458b39b94763fd45f11943bd32ff730caacddcc245ff2f1978742cd84eec930134d2c6808d84d90b987e00c6f0a1aefc3365485c0a87192c45d38d1680401005f07effe4c3c9d9bffbdbfae2db5ef22d181cb17e89914ea4937d590e1922803ae8ca2a357c8fe79f60a26c582c9310629fd2a26181ee77c3bf41d601279d403
```

**Manifest B** is identical except H = 100,100. Its digest is `ae9a20148e100beab57d6cdf005df3f2e6ec604f21e607ed43977b1819afe522`. A and B form the 837-byte upgrade-conflict evidence vector.

**Hint before H** (nothing applied; A pending), 122 bytes:

```
55484e547631000100db35ed1bed1296e6fc2786072a1a9ec30813e79e7f8f0873d578d7a11cb5f52700000000000000000000000000000000000000000000000000000000000000000000000000000000019fdf6972973a796fabd02f1ea2fc279e7440466c940151a220ded3c4b6ade387a086010000000000
```

**Certificate n = 2** (h = 7, r = 0, signers {0,1}), 251 bytes:

```
464352547631000100afcb234f872390f110bbd92112b0b739962b202e5c2373f4dc658307f6ebdaf30700000000000000da6a3ac16fcdd5b5dae2204318364a9aaf7707f1675c35ac5a112b438a14c6a6000000001259c941402c71a49c65efe0ea648063e4728cea56a3248d4c2107a66ab49dd5020000002c46f212573c4ad4fb06751959847b98af26b1607757db6f26bd83b696a71fd33fbbd950c8e8e39a2473123ecd5b296b35c734d83e8561f4095f4f33816f1a0a0100126270cb02f73bf8cf0f1470486b591cea50e7775fbf15ff753bb2809df41593078f7bf65160feace360c17a99d139900c3327bf102d85389aafd093a59dfa0b
```

**Signer state of validator 1** after its precommit at h = 7, r = 0, locked, counter 1, floor 7 (284 bytes). `last` is the precommit whose signature is the BL §3 vector.

```
4653474e763100010001000000000000009210000000000000db35ed1bed1296e6fc2786072a1a9ec30813e79e7f8f0873d578d7a11cb5f5278139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b394070000000000000001070000000000000000000000034d7d60bcfbf279bb65e1ecad534e9d0914e8166bf3282714cc97f60c61d892090fa9bb74ac0d98f3333b9c15e047a711f91d97cf526a1b113334f12cc4f1331fc9e9e3f2388b5702a22406fea9940c07e0e643f3f0d7f0f3aaa80ce9f65d910901070000000000000000000000da6a3ac16fcdd5b5dae2204318364a9aaf7707f1675c35ac5a112b438a14c6a61e03079bb2c963ac5949969c2ba6c59977f56cfbe3b584d33b1d19c7ebfe215c
```

**Unchanged-layout vectors.** The vote, the n = 4 certificate and equivocation evidence, the valset bytes and the storage forms are byte-identical to the 2026-09-29 vectors. Those were produced independently with ed25519-dalek and blake3 1.8.2 (`crosscheck-20260929.json`).

## 13. Checks

Run `python3 check.py` (standard library only; under a minute). It exits nonzero on any failure. It checks:
- BLAKE3 against the 35 official test vectors;
- Ed25519 against RFC 8032 TEST 1, plus a negative case;
- byte-for-byte reproduction of the dalek-produced 2026-09-29 vectors: 4 public keys, the valset bytes and both commitments, the stand-in commitment, the vote preimage, signature and wire, the nil prevote, the n = 4 certificate, the evidence, and the storage key and pointer;
- every length in these tables;
- that every vector passes its strict decoder or verifier;
- that **every single-byte flip**, truncation and trailing byte is refused, for:
  - the vote, both certificates, the equivocation evidence, both manifests, the upgrade-conflict evidence and both signer states;
  - the hints' structural bytes;
- named refusal cases:
  - certificates: k = q−1, descending indices, a duplicate index, a wrong height, a wrong block;
  - manifests:
    - k = 1 of 2;
    - a signed sequence-2 manifest under genesis membership;
    - sequence 1 with a non-zero previous digest;
    - old = new;
    - deadline = H, and checkpoint = deadline;
    - quorum rule 2, and protocol version 1;
    - another chain, and another set;
    - below and at an injected notice;
  - evidence: non-canonical order, and one vote or manifest twice;
  - hints: zero digests that conflict with their flags;
  - signer state: another key's state, an initialization record holding a lock, `last` below the floor, a zero lock value, and a round above 2^20;
- domains and magics: distinct, prefix-free, unretired, and clashing with no byte-string literal under `crates/`;
- determinism (two builds are identical and equal `vectors.json`);
- that every hex string in this README comes from the vectors.
