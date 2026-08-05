# B0-PRE Stage-2 third-party license compliance

The Stage-2 graph audit (`tools/b0-pre-validator/src/venue/audit.rs` via
`venue::license_policy`) evaluates each resolved crate's SPDX `license` **expression** against the
allow-list `venue::license_policy::STAGE2_ALLOWED_LICENSES` (mirrored by
`run_authoritative.sh` `STAGE2_ALLOWED_LICENSES`). Evaluation is standards-based (the maintained
`spdx` crate): `OR` = any permitted branch, `AND` = every branch permitted, `WITH` = an explicitly
permitted license+exception pair; unknown identifiers / `LicenseRef-*` / malformed expressions /
license-file-only packages fail closed.

## Allow-list atoms and their obligations

Permissive atoms already in force: `MIT`, `Apache-2.0` (+ `WITH LLVM-exception`), `BSD-2-Clause`,
`BSD-3-Clause`, `ISC`, `Unicode-DFS-2016`, `MPL-2.0`, `Zlib`, `CC0-1.0`, `Unlicense`. Each is a
permissive/public-domain-equivalent license whose primary condition is preservation of the
copyright/permission notice in distributed artifacts (`CC0-1.0`/`Unlicense` impose none).

### Owner-approved additions — 2026-07-31 (SMOKE-BLOCKED-004 ruling)

These two atoms are the only licenses required by the authentic SP1 (529-pkg) and RISC Zero
(359-pkg) resolved graphs that were not already permitted. They are added to the allow-list, and
their distribution obligations are recorded here.

| SPDX id | packages (both graphs) | obligation | SPDX reference |
|---|---|---|---|
| **Unicode-3.0** | `icu_collections`, `icu_locale_core`, `icu_normalizer`(+`_data`), `icu_properties`(+`_data`), … @2.2.0; `unicode-ident`@1.0.24 (via `(MIT OR Apache-2.0) AND Unicode-3.0`) | **Retain the copyright notice and the permission notice** (and the data-file disclaimer) in distributed artifacts that include the covered code/data. It is a *distinct* license from the retired `Unicode-DFS-2016` (rewritten terms + data carve-out), evaluated on its own terms. | <https://spdx.org/licenses/Unicode-3.0.html> |
| **CDLA-Permissive-2.0** | `webpki-roots`@1.0.9 (the Mozilla CA root set) | **Make the CDLA-Permissive-2.0 license text available when sharing the covered data.** A Community Data License Agreement (a *data* license); the covered artifact is the CA root store, not code. | <https://spdx.org/licenses/CDLA-Permissive-2.0.html> |

**Handling:** the B0-PRE candidate artifacts that vendor/redistribute these crates must carry the
corresponding notices/license texts. No copyleft or source-disclosure obligation is introduced —
`LGPL-2.1-or-later` (r-efi) is present only in `MIT OR Apache-2.0 OR LGPL-2.1-or-later` and is
never the taken branch, so it is neither approved nor required; `BSL-1.0`, `MIT-0`, `0BSD` are
likewise only ever avoidable OR-alternatives.

Any future required atom or `WITH` exception beyond this list is a fresh owner decision (add it to
`STAGE2_ALLOWED_LICENSES` — the anti-drift test keeps producer and validator in lockstep) and must
be recorded here with its obligations before use.

## Mechanized notice packaging (sealed, lock-bound, fail-closed)

The "must carry the corresponding notices/license texts" handling above is no longer a manual
obligation — it is a **sealed evidence artifact** in every per-arch bundle, produced and verified by
`venue::third_party_notices`:

- **Artifact.** Each per-arch bundle carries one `<Candidate>.third-party-notices.json` per candidate
  (`Sp1`, `Risc0`) on **both** architectures — the same both-candidates/both-arches footprint as the
  candidate `Cargo.lock` and Stage-2 audit it is derived from, because the redistribution obligation
  follows the resolved graph, not the prover. It is one of the `required_files` (VENUE.md §2), so a
  bundle missing it is refused at `seal-bundle` (exact file-set) and at `import-bundle`.
- **Generation (producer, online phase).** `resolve_lock.sh` vendors the EXACT locked graph inside the
  pinned builder image (`cargo vendor --locked --versioned-dirs`) and `venue-verify notices-generate`
  collects, for **every** third-party (registry/git) crate in that candidate's lock, its declared SPDX
  expression plus the verbatim text (and SHA-256) of every license/copyright/notice file the crate
  ships. Path/workspace crates are first-party and recorded as such, not redistributed. **Fail closed:**
  a registry crate that declares a license but ships no collectable notice file (and no readable
  `license-file`) aborts generation — a missing license is never a clean notice set.
- **Binding + enforcement (validator).** The manifest is bound to that candidate's domain-separated
  lock hash. `import-bundle` re-derives the third-party set from the sealed `Cargo.lock` and requires
  **exactly one entry per locked third-party crate** — no missing/extra — each either carrying its
  license text (`crate-file` / `ratified-map`, text-vs-SHA verified) **or** classified
  `not-redistributed` (see target-scoping below); it refuses a manifest bound to a different lock. It
  does NOT require every locked crate to carry a notice — only those the artifact actually
  redistributes. Because the finalization pipeline (`aggregate-bundles → import → stage1-ingest`)
  traverses import, **an artifact whose required notices are absent, incomplete, or mis-classified
  cannot import and therefore cannot finalize.** (This is a runtime import gate; it does not alter the
  `b0_pre_spec_hash` surface.)

The two atoms above (`Unicode-3.0`, `CDLA-Permissive-2.0`) and every MIT/Apache/BSD/ISC/… crate are
covered uniformly by this mechanism where the crate ships its own license file. For the real graphs,
most crates do; the remainder are handled by the two mechanisms below.

### Target-scoping — notices cover only what the artifact redistributes

The resolved lock is multi-platform, but a per-arch artifact only redistributes the crates **linked
into the binary** — the NORMAL (runtime-library) dependency closure for its build target(s), not
build-time tooling or macOS/Windows-only crates. `resolve_lock.sh` seals a **target-closure record**
(`<Candidate>.target-closure.json`): the platform-resolved normal-dependency graph from
`cargo metadata --filter-platform <triple>` inside the pinned image, for the venue's Linux targets
(SP1: `x86_64-` + `aarch64-unknown-linux-gnu`; RISC Zero: `x86_64-` only), with **nodes = every lock
package** so the closure cannot omit a locked crate. A crate outside the normal closure of the
workspace roots — a build-only dependency (e.g. `risc0-build`'s tree) or a platform-gated one
(`metal`→`block`, `winapi-*-pc-windows-gnu`) — is classified `not-redistributed` and carries no notice.

Crucially, the classification is **not trusted from the producer**: `import-bundle` reads the sealed
closure, independently **recomputes** the normal-dependency closure by graph reachability (full
package identity — name, version, source — so versions are never conflated), and requires every notice
entry's `crate-file` / `ratified-map` / `not-redistributed` classification to match exactly. The
closure is bound to the candidate lock hash (== the Stage-2 audit's lock identity, tying it to the
same audited graph) and its third-party node set must equal the lock's; a mis-labelled crate,
target/graph drift, an omitted/added closure node, or an altered binding all fail closed.

### Ratified per-family upstream notice map (`policy/third-party-notice-map.json`)

Some crates redistributed on Linux declare a permissive SPDX license but ship **no license file**
(normal crates.io packaging). The owner-ratified map supplies the missing text per family; `generate`
consults it only for a no-file crate and **fails closed** if the crate is uncovered, the declared SPDX
mismatches, or the covering family is not owner-approved. Families are one of two forms:

- **Real upstream text** — the crate's actual upstream license file(s), fetched once and pinned by
  commit + SHA-256 (e.g. `succinctlabs/sp1` covers the `sp1-*`/`slop-*` family; `Plonky3/Plonky3` the
  `p3-*-succinct` family).
- **Attested fallback** — for crates whose upstream ships no text at all, a per-crate
  `CanonicalAttestation` records the exhaustive search (published tag / history / parent workspace /
  README / source headers / crates.io), the declared SPDX, the verbatim `Cargo.toml` authors (reference
  only — copyright is **never** synthesized), and requires **individual owner approval** (`kind`):
  - `apache-or-branch` — the SPDX offers Apache-2.0 as an OR alternative; the canonical Apache-2.0 body
    is carried (with the upstream `NOTICE` absence confirmed, per Apache §4(d)).
  - `fork-lineage` — a fork whose upstream dropped the file; the sibling/parent project's **real** MIT
    text (with its copyright) is carried.
  - `mit-risk-acceptance` — an un-removable, un-bumpable transitive SDK dependency that declares MIT but
    ships no copyright notice anywhere; the owner records an explicit risk acceptance and the crate's
    crates.io ownership, and the canonical MIT body is carried. Reserved for genuinely un-fixable deps.

`import-bundle` verifies the manifest's map-sourced texts are self-consistent (sha) and provenance-
tagged; a producer/CI step (`notices-verify … <map>`) additionally re-binds every map-sourced entry
byte-for-byte to the committed ratified map. The committed map is structurally re-validated by
`tests/notice_map.rs`.
