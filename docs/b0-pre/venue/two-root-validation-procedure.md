# B0-FINAL two-root identity/measurement validation procedure

This procedure binds the **two-root authority model**: a FROZEN measured source and a REVIEWED
measurement tooling, in two separate clean checkouts, recorded and verified independently. It is the
Commit A → Commit B → venue sequence. **Unknown native outputs are declared here as REQUIRED
venue-produced results — never fabricated placeholders presented as authority.**

## Authorities

- **Measured source** — `RATIFIED_SOURCE_COMMIT = 507281e21e95a6a98e3480e25e12d1baab586e07` (frozen).
  Supplies guest-core, candidate source, witnesses, committed candidate locks. Bound by
  `guest_set::RATIFIED_SOURCE_COMMIT` and each identity record's `source_commit`.
- **Measurement tooling** — `RATIFIED_MEASUREMENT_TOOLING_COMMIT` (= Commit A's SHA) +
  `RATIFIED_MEASUREMENT_TOOLING_PATHSET_BLAKE3` (BLAKE3 over the canonical sorted tooling inventory).
  Bound by `tooling_authority.rs`. **NEVER compared to the measured source.**

## Commit A → Commit B → venue sequence

1. **Commit A (implementation).** Everything in this changeset: ArchRunProvenance v3 (cpuset probe
   chain + runner-attestation address), `RunnerAttestationV1`, the two-root `guest_set`/producer/
   independent wiring, the four regenerated TEST_ONLY fixtures, the tooling path-set generator, the
   protobuf provisioning + double-build scripts, and the two-root script interfaces. Commit A ships
   `tooling_authority.rs` with both authority values as the `UNBOUND` sentinel; every consumer fails
   closed against an unbound authority, so no official run can proceed yet. Commit A does **not** and
   **cannot** record its own SHA.

2. **Commit B (authority binding).** Edits ONLY `tools/b0-pre-validator/src/tooling_authority.rs`:
   - `RATIFIED_MEASUREMENT_TOOLING_COMMIT` ← Commit A's exact 40-hex SHA.
   - `RATIFIED_MEASUREMENT_TOOLING_PATHSET_BLAKE3` ← `tooling_pathset.sh --root <clean Commit-A tooling checkout> --require-clean`
     (BLAKE3 over the canonical sorted inventory of Commit A's tooling, **excluding exactly
     `tooling_authority.rs`** so this edit cannot change the digest it records — non-circular by
     construction; documented in `tooling_authority.rs`).

3. **Venue validation** runs from clean post-binding main ONLY after verifying that every ratified
   tooling path is byte-identical to Commit A (`tooling_pathset.sh` recomputes the digest and it must
   equal the ratified value), and records, per arch: execution-checkout HEAD,
   `RATIFIED_MEASUREMENT_TOOLING_COMMIT = Commit A`, ratified + recomputed path-set digest, and the
   measured-source commit + context digest. Two clean roots are mandatory (`two_root_authority.sh`
   refuses same/nested/dirty/symlink/wrong-commit roots + cross-root substitution). **No venue is ever
   asked to validate a synthetic or dirty SHA.**

## REQUIRED venue-produced outputs (declared, never fabricated)

The following are unknown off-venue and MUST be produced at the venue by the named tooling and bound
into the per-arch `RunnerAttestationV1`. They are recorded as declarations here, with NO stand-in
value asserted as authority:

| field | producer | required value / gate |
|---|---|---|
| `native_protoc_sha256`, `native_protoc_blake3` | `provision_protobuf_include.sh` | venue-produced; no known per-arch hash may be hardcoded |
| `native_protoc_version` | `provision_protobuf_include.sh` | MUST equal `libprotoc 3.21.12` |
| `runner_sha256`, `runner_blake3` | `double_build_runner.sh` | byte-identical across both clean builds |
| `reproducibility_pair_blake3` | `double_build_runner.sh` | address over the two build attestations |
| `docker_argv_blake3` | `provision_protobuf_include.sh` | address over the exact controlled `docker run` argv/mounts |
| `immutable_builder_identity` | ratified builder image (`--pull never`) | the ratified per-arch builder digest |
| `measured_source_context_blake3` | staged-context assembler (measured root) | reproduces the frozen SP1/RISC0 context digest |
| `cpuset_probe_chain_blake3` | `b0-pre-host-provenance` (live venue read) | address over the retained nearest-first probe chain |

## Accepted protobuf include authority (pinned)

- source archive `protobuf-cpp-3.21.12.tar.gz` — sha256 `4eab9b52…3460`, blake3 `697239ff…2a06`
- `google/protobuf/empty.proto` — size 2363, sha256 `c6d0c8af…f273`, blake3 `bf3b6237…a46f`
- authority content-address — sha256 `65b7a61f069be4f709de94f72c696529a69596749e6dc24ac543ee6d72af9161`,
  blake3 `7b5551d278fc33095bddde84339ef73c0d777f65e206de60aecd8cbf9c8f3623`
- mount: read-only at `/usr/include/google/protobuf`, `--pull never`, ambient authority refused.
