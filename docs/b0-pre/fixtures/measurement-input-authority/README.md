# Measurement-input authority fixtures — **TEST_ONLY**

These three files are **TEST_ONLY** encoding/verification vectors for the
`MeasurementInputAuthorityV1` correction. They are **NOT** official grid
authority and can never be used as such:

- `measurement-input-authority.v1.json` — the unifier (spec/workload + measured
  + tooling identity + harness-source inventory address + malformed-corpus report
  address + RSS statement-binding policy).
- `malformed-corpus-report.v1.json` — the retained ordered corpus report.
- `harness-source-inventory.txt` — the canonical harness source-closure manifest.

They are bound to the repository's **established non-authoritative sentinel
tooling commit** `1234567890abcdef1234567890abcdef12345678`
(`TEST_ONLY_TOOLING_COMMIT_SENTINEL`), with the dry-run sentinel path-set. Their
encoding/verification mechanics are exercised by the crate test suites and by the
producer dry-run vector — but the production pre-grid gate
(`measure-produce --verify-authority`) **REFUSES** any authority bound to the
sentinel tooling commit, so a mechanics vector can never masquerade as official
authority.

The measured-source commit is the real ratified measured root
(`507281e2…`, `RATIFIED_SOURCE_COMMIT`), which is ratified independently of the
measurement-tooling commit and therefore introduces no circular dependency on the
correction's own Commit A. Only the **tooling** identity is a sentinel — that is
the part that would otherwise have to reference Commit A's own hash.

## Official authority (never committed here)

The real report / inventory / `MeasurementInputAuthorityV1` are generated
deterministically at venue/grid preparation time from the clean, ratified
two-root checkout via
`tools/b0-pre-candidates/scripts/produce_measurement_input_authority.sh produce`,
and the retained bytes are kept as official evidence — never as a repository
fixture. See `docs/b0-pre/venue/B0-FINAL-MEASUREMENT-RUNBOOK.md` §3.0.
