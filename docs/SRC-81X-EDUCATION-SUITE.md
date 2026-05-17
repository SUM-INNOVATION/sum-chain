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
| **Never on-chain in any form** | student names/IDs/PII, raw grades, raw submissions, raw exam answers, instructor PII, DOB, email, contact info, government ID, any stable cross-system identifier |

> **Minimization caveat (normative):** "On-chain public" timestamps/counts and per-student "existence" signals are acceptable **only** as minimized, non-directly-identifying values. In small/single-student cohorts a timestamp or existence flag can re-identify a student — those cases MUST fall back to a privacy-preserving workaround per §3.5. Linkable/indirect data is in scope of the FERPA rule (§3.4), not just direct PII.

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
    IndividualStudent([u8;32]),      // PROVISIONAL — student_commitment, NOT a raw Address;
                                     // see §6 Q9. Hard Phase-1 blocker until legal-confirmed
                                     // or replaced with SNIP-only ACL targeting.
}
```

**`IndividualStudent` is provisional (normative — see §6 Q9).** It remains in the draft only under these constraints:

- The `[u8;32]` is a `student_commitment` that MUST be **per-offering/per-context scoped, salted, non-reversible, and non-reusable** across courses/institutions/systems.
- If legal **cannot** confirm FERPA safety of a per-student commitment in on-chain policy, it MUST be **replaced with SNIP-only ACL targeting** and the on-chain `ContentAccessPolicy` kept **audience-class-only** (`Public`/`EnrolledStudents`/`InstructorsOnly`/`StaffOnly`).
- This is a **hard Phase-1 blocker**. No middle state ships.

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

**FERPA PII & linkability rule (normative):**

- **No direct PII on-chain.** No student name, school/student ID, email, date of birth, contact info, government ID, or any stable cross-system identifier may appear on-chain — in any field, index, event, or commitment input that could be brute-forced.
- **Indirect / linkable data is also treated as sensitive.** A field that is not itself PII but that can be correlated to identify a student (small-cohort timestamps, unique sequences, cross-referencable counts) is in scope of this rule and must be minimized or moved off-chain.
- **Scoped, non-reusable pseudonyms only.** Any commitment or pseudonym standing in for a student MUST be salted, non-reversible, and **scoped so it is not reusable across courses, institutions, or external systems** unless legal explicitly approves a broader scope. `student_commitment` is per-offering/per-context by construction (`BLAKE3(domain ‖ subject ‖ offering_id ‖ salt)`) — a global or cross-offering student identifier is prohibited without legal sign-off.

Reaffirmed hard rules:

- **No raw grades on-chain.** Only `grade_commitment`.
- **No raw submissions on-chain.** Only `content_ref` (SNIP) + `content_commitment`.
- **No raw answer keys on-chain.** Only `answer_key_commitment`.
- **No raw student PII on-chain** in any form.
- **Grade details and feedback live in SNIP**, encrypted to the policy-named audience.
- **SRC-818 is NOT the authoritative gradebook.** Raw grades remain under institutional control in SNIP / school systems. SRC-818 stores only grade *commitments* and audit references — never the authoritative grade value.
- **Authoritative transcript/credential export belongs to SRC-810/SRC-811, not SRC-818.**
- **Role-based access + audit logs are required for grade detail.** Any read of grade detail (in SNIP) must be gated by role (student-self / instructor / assigned grader / authorized admin) and logged for audit. The chain holds the commitment + audit ref; SNIP enforces the role-gated access and emits the access log.

### 3.5 Student-indexing position (locked)

`student_commitment` is the default record/index key. Raw-`Address` student indexes are **excluded from v1** — there is **no public raw student address index in v1**. Cross-offering per-student analytics is delivered by an **access-controlled off-chain private indexer** consuming the `edu_events` log — not a public on-chain index. Any raw-address on-chain index requires explicit written legal/product sign-off.

**Enrollment / timestamp minimization (normative):**

- Enrollment *existence* and submission *timestamps* are permitted on-chain only as **minimized, non-directly-identifying commitments** — never as a directly-identifying record.
- **If a timestamp or event can identify a student with reasonable certainty** (e.g. a single-student section, or a unique submission time in a small cohort), it MUST use a privacy-preserving workaround: a SNIP-private record, a coarsened/bucketed event, a private indexer, or delayed/batched disclosure. The small-cohort re-identification case is a design constraint, not an edge case.
- Counts (`enrollment_count`, etc.) must be evaluated for small-cohort re-identification; coarse/bucketed counts or suppression below a k-anonymity threshold are the expected mitigations where legal requires them.

### 3.6 Retention / erasure / amendment

**Normative position:**

- **Chain commitments are permanent and cannot be amended or deleted** the way normal education records can (FERPA gives students rights to inspect, request amendment, and constrains retention/destruction). An on-chain commitment supports none of those operations.
- **Therefore chain state MUST avoid storing education records directly.** The chain stores commitments + audit refs; the education record itself lives in SNIP / institutional record systems.
- **Amendment and erasure act on the SNIP plaintext / institutional record systems**, via crypto-shredding (destroy the decryption key), revocation, supersession, or a corrected replacement record — never by mutating the chain.
- **Schools must define a retention/destruction policy** aligned with their institutional and state-law obligations; the suite does not impose one but requires its existence before deployment.
- **Hard redesign trigger:** if, in a given deployment context, an immutable on-chain commitment is itself legally treated as an "education record" (not merely a pointer/integrity tag), that field MUST be redesigned **before Phase 1** — it cannot ship as an immutable commitment.

A documented retention + crypto-shred/amendment policy and legal acceptance of permanent commitments to deleted coursework is a **Phase 0 legal-gate requirement**.

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
| 1 | **Enrollment/timestamp minimization (tightened):** enrollment existence and submission timestamps are allowed on-chain only as minimized, non-directly-identifying commitments; **no public raw student address index in v1**; any timestamp/event that can identify a student with reasonable certainty in a small class MUST use a privacy-preserving workaround (SNIP-private record, coarse event, private indexer, or delayed/batched disclosure). Legal to confirm minimization is sufficient or specify k-anonymity/coarsening thresholds. See §3.5. | Legal | **Yes** |
| 2 | **Authoritative grades (tightened):** SRC-818 is **not** the authoritative gradebook. Raw grades stay under institutional control in SNIP / school systems; SRC-818 stores only grade commitments + audit refs; authoritative transcript/credential export belongs to SRC-810/SRC-811; role-based access + audit logs are required for grade detail. Legal/Product to confirm this division is acceptable. See §3.4. | Product/Legal | **Yes** |
| 3 | Submission ACL defaults: confirm default audience (student + instructor + assigned graders); do institution admins get standing "legitimate educational interest" access? | Legal/Product | No (Phase 2) |
| 4 | **Retention/erasure/amendment (tightened):** chain commitments are permanent and cannot be amended/deleted like normal education records, so chain state must not store education records directly; amendment/erasure acts on SNIP plaintext / institutional systems (crypto-shred, revocation, supersession, corrected replacement); schools must define a retention/destruction policy per institutional/state obligations; **if an immutable commitment is itself legally treated as an education record in a deployment context, that field must be redesigned before Phase 1**. Legal to confirm + accept permanent commitments to deleted coursework. See §3.6. | Legal | **Yes** |
| 5 | Soulbound confirmation: any business need to transfer catalog/offering between departments/institutions (→ controlled admin hand-off, never market transfer)? | Product | No |
| 6 | Institution identity: opaque `institution_id` commitment vs first-class SRC-802 issuer (stake/reputation/slashing) | Product/Chain | No (affects Phase 2) |
| 7 | Catalog bootstrapping & SRC-812 maturity: SRC-818 requires `catalog_id` (Phase ordering ships SRC-817 first); SRC-812 is today only a DocClass subcode — keep `enrollment_ref` resolution behind an indirection so SRC-812 promotion doesn't force an SRC-818 wire break | Chain | No (design noted) |
| 8 | Fee/nonce model (see §5) | Chain | No (Phase 2 blocker) |
| 9 | **`AccessAudience::IndividualStudent([u8;32])` is provisional (tightened).** Permitted only if per-offering/per-context scoped, salted, non-reversible, and non-reusable across courses/institutions/systems. If legal cannot confirm FERPA safety, it is **replaced with SNIP-only ACL targeting** and on-chain `ContentAccessPolicy` stays audience-class-only. Hard Phase-1 blocker; no middle state ships. See §3.2. | Legal | **Yes** |
| 10 | Activation governance: add legal sign-off to the OmniNode-style eng-director + validator-ops activation gate for education data | Legal/Chain | No (Phase 6) |

## 7. Phase Gate Definition (Phase 0 → Phase 1)

Legal/privacy review is currently **conditional approval, not clean sign-off.** Phase 1 may begin only when:

1. `docs/SRC-817.md`, `docs/SRC-818.md`, `docs/SRC-81X-EDUCATION-SUITE.md` reviewed and approved by chain/product.
2. **Legal explicitly accepts the tightened FERPA model (§3.4–§3.6), OR each FERPA-risky construct has a documented privacy-preserving workaround** recorded in this doc. Conditional/verbal approval is insufficient — **hard gate**.
3. A **sign-off artifact is recorded** (who, date, scope, which constructs accepted vs. which require workaround) — referenced from this section. No artifact ⇒ Phase 1 does not start.
4. Every "Blocks Phase 1? = Yes" question (Q1, Q2, Q4, Q9) is resolved or has a documented workaround; in particular Q9 `IndividualStudent` is either legal-confirmed under §3.2 scoping or replaced with SNIP-only ACL targeting.
5. Fee/nonce (§5) has an owner and a target resolution phase (before Phase 2).
6. Glossary (§2) terms are frozen — Phase 1 wire types will use them verbatim, so no FERPA-risky shape is frozen by accident.

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
| 0.1.2 | 2026-05-17 | Phase 0 legal/privacy tightening (conditional approval): FERPA PII/linkability rule (§3.4), enrollment/timestamp minimization (§3.1/§3.5), authoritative-grades not-the-gradebook + role-based access/audit (§3.4), retention/erasure/amendment + redesign trigger (§3.6), IndividualStudent provisional scoping (§3.2), sign-off-artifact gate (§7), Q1/Q2/Q4/Q9 tightened |
