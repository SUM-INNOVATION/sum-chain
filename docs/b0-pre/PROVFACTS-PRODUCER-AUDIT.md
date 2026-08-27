# ProvFacts producer/schema audit (B0-FINAL measurement provenance)

Purpose: for every field the measurement runner REQUIRES in `provenance.json`
(`Vec<ProvFacts>`, `b0-pre-measure-core::facts::ProvFacts`), record its REAL production
source and refuse any field that is sourced only by tests/placeholders. Triggered by the
first end-to-end SP1/x86 real proof failing closed at `parse provenance: missing field
runner_attestation` — a field with no venue producer (latent: the real proving path had
never run to completion before, earlier pre-proving bugs failing sooner).

Authoritative types:
- `tools/b0-pre-measure-core/src/facts.rs` — `ProvFacts`, `RunnerAttestationFacts`, `RunnerRecipeFacts`.
- `tools/b0-pre-validator/src/producer.rs` — `RunnerAttestationJson` (18-field venue twin) +
  `to_schema()` + the import binder (`prov_facts`, continuity block in `produce`).
- `tools/b0-pre-validator/src/schema/runner_attestation.rs` — `RunnerAttestationV1` (schema v9).

## A. ProvFacts top-level fields → source

| Field | Producer | Notes |
|---|---|---|
| `arch`, `role`, `source_commit`, `dirty_tree_flag`, `builder_container_digest` | `b0-pre-host-provenance` reader | real host/cgroup read per role |
| `host_os`, `kernel`, `cpu_vendor`, `cpu_model`, `physical_core_count`, `logical_cpu_count`, `total_ram_bytes`, `configured_cpuset_core_limit`, `configured_memory_limit_bytes`, `dvfs`, `clock_source`, `cgroup_version`, `cgroup_scope_label`, `benchmark_harness_source_hash`, `raw_environment_capture_hash` | `b0-pre-host-provenance` reader | real host facts |
| `cpuset_source_cgroup_path`, `cpuset_raw`, `cpuset_inherited`, `cpuset_probe_chain` | `b0-pre-host-provenance` reader | v3 effective-cpuset provenance |
| `runner_recipe` | `measure_fragment.sh` python splice (from `double_build_runner.sh` recipe JSON) | already wired |
| **`runner_attestation`** | **WAS MISSING → now the typed `measure-produce --gen-runner-attestation` generator** | this audit's gap |

Result: exactly ONE required field lacked a real producer — `runner_attestation`. All other
ProvFacts fields come from the tested host-provenance reader or the existing recipe splice.

## B. `runner_attestation` (18 venue subfields) → authenticated source

The venue twin `RunnerAttestationJson`/`RunnerAttestationFacts` carries the arch + venue-produced
fields; the producer injects candidate/role/spec/guest-set/Phase-1-continuity/recipe-addresses at
import (placeholders `[0;32]` in `to_schema`). Each of the 18 venue fields:

| Field | Authenticated source | Kind |
|---|---|---|
| `build_target_arch` | cell arch (`x86_64`) | scalar |
| `execution_tooling_checkout_head` | git HEAD of the tooling checkout | scalar (== ratified on official) |
| `ratified_tooling_commit` | `tooling_authority::RATIFIED_MEASUREMENT_TOOLING_COMMIT` | compiled constant |
| `ratified_pathset_blake3` | `tooling_authority::RATIFIED_MEASUREMENT_TOOLING_PATHSET_BLAKE3` | compiled constant |
| `recomputed_pathset_blake3` | `tooling_pathset.sh` recompute over the tooling root | scalar; `check_self_consistency` requires == ratified |
| `measured_source_commit` | `guest_set::RATIFIED_SOURCE_COMMIT` (venue-attested source commit) | scalar |
| `build_git_sha` | measured source commit | scalar; `check_self_consistency` requires == `measured_source_commit` |
| `measured_source_context_blake3` | `build_container.sh` → `staged_context_blake3` (builder evidence) | content address |
| `runner_sha256` | recipe `build_a.runner_sha256` (`double_build_runner`) | recipe |
| `runner_blake3` | recipe `build_a.runner_blake3` | recipe; continuity requires == Phase-1 `production_binary_blake3` |
| `immutable_builder_identity` | ratified builder container digest / builder evidence | scalar |
| `protobuf_authority_sha256` | protobuf-include-authority `CONTENT-ADDRESS` (sha256) | authority file |
| `protobuf_authority_blake3` | protobuf-include-authority `CONTENT-ADDRESS` (blake3) | authority file |
| `native_protoc_sha256` | `b0_protoc_authority` / `provision_protobuf_include.sh` | authority file |
| `native_protoc_blake3` | same | authority file |
| `native_protoc_version` | same (`libprotoc 3.21.12`) | authority; `check_self_consistency` pins the string |
| `docker_argv_blake3` | `blake3(` include-authority `docker_argv` string `)` | DERIVED in the typed generator |
| `reproducibility_pair_blake3` | `RunnerDoubleBuildProofV1::compute_reproducibility_pair(recipe.build_a, build_b)` | DERIVED in the typed generator |

**No field is sourced only by tests/placeholders.** Two fields are DERIVED deterministically inside
the typed generator from authenticated inputs (`docker_argv_blake3`, `reproducibility_pair_blake3`);
the rest are read from authenticated production files/constants. Therefore no STOP condition
(the owner's rule: stop only if a schema field cannot be derived from authenticated production inputs).

## C. Binding checks the generator re-runs before returning (== sealed import)

- `RunnerAttestationV1::check_self_consistency` — `build_git_sha == measured_source_commit`,
  `recomputed_pathset_blake3 == ratified_pathset_blake3`, `native_protoc_version == libprotoc 3.21.12`.
- Arch agreement — `attestation.build_target_arch == provenance arch`.
- Continuity vs the retained Phase-1 identity record for `(candidate, arch)` (producer `produce`
  block): `rec.source_commit == att.measured_source_commit`; `rec.tooling_commit == att.ratified_tooling_commit`
  and `rec.tooling_pathset_blake3 == att.ratified_pathset_blake3`; `rec.production_binary_blake3 ==
  att.runner_blake3`; `rec.b0_pre_spec_hash == spec`; `check_runner_continuity` (`phase1_production_binary_blake3
  == runner_blake3`).
- Recipe artifact re-derivation (`prov_facts` per-record binder) — the five path-independence
  artifacts are rebuilt from the recipe facts and self-checked.
- Round-trip: emit canonical JSON, re-decode into `RunnerAttestationJson`, rebuild + re-check.

## D. Pre-proving gate (measure_fragment, before ANY proof)

`measure-produce --gen-runner-attestation` emits the runner_attestation bytes; `measure_fragment.sh`
splices them verbatim into each provenance role, then runs `measure-produce --validate-provenance`
over the COMPLETE assembled `provenance.json` (+ recipe + Phase-1 records) and refuses to launch the
proof unless it accepts. SP1 and RISC0 exercise the identical generation + validation path.

## E. Operational disclosure

The B6 diagnostic burn-in built the SP1 runner double-build with `CARGO_BUILD_JOBS=6` to avoid a
`rustix` build-script `BrokenPipe` under outer×nested spawn-burst oversubscription. Build output is
job-count independent (the A/B byte-equality proof is the authority on build output); this is
disclosed operational evidence, NOT an identity input, and is applied identically to the official
grid driver.
