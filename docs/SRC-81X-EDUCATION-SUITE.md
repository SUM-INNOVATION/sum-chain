# SRC-81X Education / LMS Suite — Shared Companion

> **Status:** Phase 0 draft — design baseline, pre-legal-review. Single source of truth for shared definitions, the privacy/SNIP model, the open fee/nonce question, cross-standard invariants, and the consolidated legal/product question list for [SRC-817](SRC-817.md) and [SRC-818](SRC-818.md).

## 1. Suite Overview

> SRC-817 defines reusable course catalog identity. SRC-818 defines a specific course offering and LMS action ledger.
>
> SRC-818 is an activation-gated operational tx family. It stores course/offering state, authorization links, lifecycle, SNIP references, access policies, submission/grade commitments, and audit timestamps. It never stores raw coursework, exams, answer keys, feedback, or grades. Submissions and grading are transactions; content and private details live in SNIP with time-limited private sharing.

```
SRC-817 CatalogEntry (CS101 v2)
        ▲ catalog_id (REQUIRED, non-Archived/Deprecated)
        │
SRC-818 Offering (CS101 · 2026FA · A) ──instructor──► SRC-882 EmploymentCredential
        │                              ──enrollment──► SRC-812 (DocClass subcode 812)
        ├─ ContentItem(s)  ─ ContentAccessPolicy ─► SNIP object
        ├─ AssessmentRef(s) ─ ContentAccessPolicy ─► SNIP object
        ├─ SubmissionRecord(s)  (commitment + SnipRef, student-owned object)
        └─ GradeRecord(s)       (grade_commitment + encrypted feedback SnipRef)
```

### Unified transaction-variant decision (locked)

The suite uses **one** `TxPayload::Education` variant, not two:

```text
EducationTxData {
    standard:  EducationStandard,   // CourseCatalog = 0 | CourseOffering = 1  (append-only)
    operation: u16,                 // operation code within the standard
    data:      Vec<u8>,             // bincode of the operation struct
    recipient: Address,             // soulbound target where relevant
}
```

| Approach | Pros | Cons |
|---|---|---|
| **Unified `Education` variant (chosen)** | Conserves append-only `TxPayload` budget; future SRC-81X standards (810 transcript, 811 diploma) add as new `EducationStandard` discriminants — no new tags; one executor enforces the catalog↔offering invariant atomically; one activation gate; matches the `Src80xTxData { standard, operation, data }` precedent | Catalog & offering share one activation switch (acceptable — co-dependent) |
| Separate variants 22 + 23 | Independent activation; smaller isolated executors | Burns two permanent tags for a co-dependent pair; splits shared logic |

### Shared activation gate (locked)

One chain parameter governs the whole suite:

```text
education_enabled_from_height: Option<u64>   // None = dormant (mainnet default)
```

No per-standard gate. Same dormant-deploy pattern as `omninode_enabled_from_height` / `v2_enabled_from_height`. **No activation height is proposed in Phase 0.** Gate implementation is Phase 2, not now.

## 2. Glossary (single source of truth)

| Term | Definition |
|---|---|
| **Catalog entry** | SRC-817 reusable abstract course definition (institution-scoped, versioned). |
| **Offering** | SRC-818 one live class instance of a catalog entry (term + section). |
| **Term** | Academic period coordinate (e.g. `2026FA`). Public, not PII. |
| **Section** | Sub-division of an offering (e.g. `A`). Public, not PII. |
| **Enrollment link** | On-chain binding of a `student_commitment` to an offering, backed by an SRC-812 credential reference. |
| **Instructor binding** | On-chain binding of an instructor/TA `Address` + role to an offering, backed by an SRC-882 employment credential reference. |
| **Assessment** | An assignment / exam / quiz / project under an offering (`AssessmentKind`). |
| **Submission** | A student's chain-recorded act of submitting work; content is a student-owned SNIP object. |
| **Grade commitment** | BLAKE3 commitment to a grade value; the raw grade is never on-chain. |
| **Content item** | A course material object (syllabus, lecture, reading) referenced by SnipRef + policy. |
| **`SnipRef`** | Off-chain content pointer: `content_root` + optional `snip_file_id` + size + schema version. No URL, no plaintext, no keys. |
| **`student_commitment`** | `BLAKE3(domain ‖ subject ‖ offering_id ‖ salt)` — the default per-student identifier. Never a raw address. |
| **Audience** | The `AccessAudience` class a `ContentAccessPolicy` grants access to. |
| **Grace window** | `grace_until` interval after `due_at` during which a submission is accepted but flagged `late`. |
| **Soulbound** | Non-transferable; no transfer operation exists for any suite record. |
| **Deprecation vs Archive (catalog)** | Deprecated = still bindable by *existing* offerings, no new offerings; Archived = terminal read-only. |
| **EnrollmentClosed (offering)** | **Decision (locked, revised by product/legal):** blocks *new enrollment links*. Instructor/staff grading and coursework administration remain allowed. **Student submissions after EnrollmentClosed are allowed only if an explicit per-assessment or per-student policy permits** (extension, late window, incomplete, school-approved accommodation); otherwise rejected. Default student submission window = assessment `opens_at`/`due_at`/`grace_until` bounded by the offering academic calendar. |

## 3. Privacy & SNIP Model (legal-review centerpiece)

### 3.1 Field classification (both standards)

| Class | Examples |
|---|---|
| **On-chain public** | `catalog_id`, `department`, `course_code`, `term`, `section`, `status`, `*_count`, assessment `opens_at`/`due_at`/`max_attempts`/`weight_bps`, lifecycle transitions, all `*_at_height` audit fields, `late` flag |
| **On-chain commitment only** | `title_commitment`, `credit_commitment`, `institution_id`, `spec_commitment`, `content_commitment`, `grade_commitment`, `answer_key_commitment`, `student_commitment`, prerequisite/accreditation roots |
| **SNIP private (ref + policy on chain)** | syllabus & materials, descriptions, learning outcomes, accreditation docs, assignment/exam instructions, rubrics, **submitted work**, **feedback text**, **grade detail**, answer keys (pre-close) |
| **Never on-chain in any form** | student names/IDs/PII, raw grades, raw submissions, raw exam answers, instructor PII |

### 3.2 Mandatory `ContentAccessPolicy` rule (locked)

> Any SRC-817/818 `SnipRef` included in chain state MUST have an associated `ContentAccessPolicy`. A bare/dangling content reference is invalid.

Canonical definitions:

```text
SnipRef {
    content_root:  [u8;32]          // BLAKE3/merkle root of the SNIP object
    snip_file_id:  Option<[u8;32]>  // SNIP V2 file key when registered
    size_bytes:    u64
    schema_version:u32
}

ContentAccessPolicy {
    opens_at:                 Option<Timestamp>
    closes_at:                Option<Timestamp>
    grace_until:              Option<Timestamp>
    audience:                 AccessAudience
    revoke_on_course_archive: bool
}

AccessAudience {
    Public,
    EnrolledStudents,
    InstructorsOnly,
    StaffOnly,                       // instructors + TAs + graders + admins
    IndividualStudent([u8;32]),      // student_commitment — NOT a raw Address
}
```

**Division of responsibility:** SUM Chain stores the access policy/schedule + commitments + refs as the authoritative source of truth. **SNIP enforces** actual private object access — encrypted ACL / key bundles (the `EncryptedKeyBundleV2` model in [crates/primitives/src/storage_metadata.rs](../crates/primitives/src/storage_metadata.rs)) deliver decryption to exactly the named audience, only within the policy window. The chain never holds decryption keys.

**Default academic access window (canonical guidance).** Unless an object's `ContentAccessPolicy` explicitly overrides it:

- Course-content access generally runs from the offering's `instruction_start_at` through its `final_grade_submission_deadline` (the SRC-818 offering academic-calendar fields).
- Extensions and accommodations may extend access **per student or per assessment** (a wider per-student/per-assessment policy supersedes the offering default for that subject).
- Archive/revoke behavior follows school policy via `revoke_on_course_archive`; an institution may keep a read tail past archive or hard-revoke at archive.
- The model is intended to be **compatible with Canvas/Moodle-style LMS behavior**: content visible during instruction, an access tail through grade finalization, then archived/revoked per institution policy.
- The default *student submission* window (distinct from content access) is the assessment `opens_at`/`due_at`/`grace_until`, bounded by the same academic calendar — see SRC-818 submit pipeline.

### 3.3 SNIP object-ownership model (corrected wording)

- The instructor **controls publication and access policy** for course content — not "owns" it.
- **SNIP object ownership varies by object type:** course materials / instructions / exam content / answer keys → institution or instructor; feedback / grade detail → instructor/grader.
- **Submissions: the student owns/controls the submitted SNIP object.** Submission *grants* scoped access to instructor + assigned graders per the course policy; ownership is not transferred.

### 3.4 Privacy non-negotiables (v1) — FERPA-mandatory

**FERPA compliance is mandatory for the entire education suite.** It is not a "best effort" target; it is a release gate.

- **If any on-chain field or index is legally risky, the design MUST provide a privacy-preserving workaround** before that field/index ships. A legally-risky element with no workaround blocks the relevant phase.
- **Prefer, in order:** (1) commitments, (2) SNIP private ACLs, (3) access-controlled off-chain private indexers — over any public on-chain student-identifying data. Public on-chain student-identifying data is the option of last resort and requires explicit written legal sign-off.

Reaffirmed hard rules:

- **No raw grades on-chain.** Only `grade_commitment`.
- **No raw submissions on-chain.** Only `content_ref` (SNIP) + `content_commitment`.
- **No raw answer keys on-chain.** Only `answer_key_commitment`.
- **No raw student PII on-chain** in any form.
- **Grade details and feedback live in SNIP**, encrypted to the policy-named audience.
- **The final transcript/credential belongs to SRC-810/SRC-811, not SRC-818.** SRC-818 records only commitments + audit trail; it is not a system of record for authoritative grades.

### 3.5 Student-indexing position (locked)

`student_commitment` is the default record/index key. Raw-`Address` student indexes are **excluded from v1**. Cross-offering per-student analytics is delivered by an **access-controlled off-chain private indexer** consuming the `edu_events` log — not a public on-chain index. Any raw-address on-chain index requires explicit written legal/product sign-off.

### 3.6 Retention / erasure / dangling commitments

Chain state is append-only: commitments are permanent. GDPR/FERPA "right to erasure" can act only on the **SNIP plaintext** (delete/crypto-shred the off-chain object; the on-chain commitment becomes a dangling, non-reversible hash). A documented retention + crypto-shred policy and legal acceptance of permanent commitments to deleted coursework is a **Phase 0 legal-gate requirement**.

## 4. Cross-standard invariants

1. **Offering → Catalog binding.** `CreateOffering` requires `catalog_id` to resolve to an SRC-817 entry in `Active` or `Deprecated` status (never `Draft` or `Archived`). Enforced atomically in the single education executor.
2. **Append-only enums.** `Education` is appended as `TxPayload` variant 22 / `TxType = 22`; `EducationStandard` and per-standard operation codes are append-only. No reorder. Existing bincode tags (Transfer … `InferenceAttestation = 21`, `StorageMetadataV2 = 20`) are unchanged.
3. **No wire break.** No change to Transfer, SRC-201, SNIP V2, OmniNode, staking, DocClass, Employment, or any existing layout. SRC-812/882/817 references are read-only resolutions.
4. **Bounded primary records.** Neither `CatalogEntry` nor `Offering` stores unbounded `Vec`s; child collections are separate CF rows with counts/roots on the primary record.

## 5. Fee / Nonce — Open Chain-Consistency Question

**Deliberately unresolved. Not decided in Phase 0. Must be resolved before Phase 2.**

Open questions:

1. Should a **failed validation** path (gate closed, offering not active, window closed, not enrolled, attempts exhausted, raw-payload rejected) **consume fee**?
2. Should the sender's **nonce advance** on a failed validation?
3. **Which existing executor family is the precedent** SRC-817/818 must match — the gate/duplicate-fail pattern in [crates/state/src/inference_attestation_executor.rs](../crates/state/src/inference_attestation_executor.rs) (mempool rejection → no fee, no nonce, no receipt) vs. the operational-family pattern in [crates/state/src/employment_executor.rs](../crates/state/src/employment_executor.rs)?
4. If **zero-fee-on-failure** is chosen, which checks must move into **mempool admission** (Phase 3) to block cheap spam — candidate set: activation gate, offering-active, enrollment-link existence, assessment-open, attempt-count?

Resolution owner: Chain. Target: before Phase 2 (not a Phase 1 blocker, but a Phase 2 blocker).

## 6. Consolidated Legal / Product Questions

| # | Question | Owner | Blocks Phase 1? |
|---|---|---|---|
| 1 | FERPA/education-privacy: are on-chain `enrollment_count`, lifecycle timestamps, and per-student submission *existence* (no content) acceptable in small/single-student sections? k-anonymity thresholds? | Legal | **Yes** |
| 2 | Authoritative grades: is the commitment-only model acceptable, with authoritative transcripts explicitly deferred to SRC-810? | Product | **Yes** |
| 3 | Submission ACL defaults: confirm default audience (student + instructor + assigned graders); do institution admins get standing "legitimate educational interest" access? | Legal/Product | No (Phase 2) |
| 4 | Retention / erasure / crypto-shred policy; legal acceptance of permanent commitments to deleted coursework | Legal | **Yes** |
| 5 | Soulbound confirmation: any business need to transfer catalog/offering between departments/institutions (→ controlled admin hand-off, never market transfer)? | Product | No |
| 6 | Institution identity: opaque `institution_id` commitment vs first-class SRC-802 issuer (stake/reputation/slashing) | Product/Chain | No (affects Phase 2) |
| 7 | Catalog bootstrapping & SRC-812 maturity: SRC-818 requires `catalog_id` (Phase ordering ships SRC-817 first); SRC-812 is today only a DocClass subcode — keep `enrollment_ref` resolution behind an indirection so SRC-812 promotion doesn't force an SRC-818 wire break | Chain | No (design noted) |
| 8 | Fee/nonce model (see §5) | Chain | No (Phase 2 blocker) |
| 9 | `AccessAudience::IndividualStudent([u8;32])` **remains in the draft design** (carries a `student_commitment`, never a raw address) but is **Phase-1-blocking until legal confirms it is FERPA-safe**, OR it is replaced with SNIP-only ACL targeting (chain policy staying audience-class-only). No middle state ships. | Legal | **Yes** |
| 10 | Activation governance: add legal sign-off to the OmniNode-style eng-director + validator-ops activation gate for education data | Legal/Chain | No (Phase 6) |

## 7. Phase Gate Definition (Phase 0 → Phase 1)

Phase 0 is complete and Phase 1 may begin only when:

1. `docs/SRC-817.md`, `docs/SRC-818.md`, `docs/SRC-81X-EDUCATION-SUITE.md` reviewed and approved by chain/product.
2. **Legal/privacy sign-off recorded** on §3 and §6 (questions 1, 2, 4, 9 resolved) — **hard gate**.
3. Every "Blocks Phase 1? = Yes" question resolved or explicitly waived in writing.
4. Fee/nonce (§5) has an owner and a target resolution phase (before Phase 2).
5. Glossary (§2) terms are frozen — Phase 1 wire types will use them verbatim.

### Phased plan (reference)

| Phase | Scope |
|---|---|
| 0 | Spec docs + legal/privacy review (**this deliverable set**) |
| 1 | Wire types + append-only enum fixtures |
| 2 | Storage CFs + executor + activation gate + fee/nonce decision |
| 3 | Mempool admission for cheap-failure paths |
| 4 | Read-only RPC |
| 5 | Local-mirror / dev validation |
| 6 | Activation readiness (+ legal sign-off in the gate) |

## 8. Version History

| Version | Date | Changes |
|---|---|---|
| 0.1.0 | 2026-05-17 | Phase 0 draft — design baseline, pre-legal-review |
| 0.1.1 | 2026-05-17 | Product/legal revision: EnrollmentClosed gating reworded, default academic access window (§3.2), FERPA-mandatory privacy non-negotiables (§3.4), Q9 FERPA-safe-or-replace |
