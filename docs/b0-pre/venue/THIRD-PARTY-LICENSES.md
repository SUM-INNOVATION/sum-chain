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
