#!/usr/bin/env bash
# B0-PRE venue-script test runner (Blocker 4 / Blocker 1a regression guards).
#
# Runs `bash -n` + (if present) `shellcheck -S error` over the affected scripts, then the
# deterministic unit tests. Runnable locally and wired into .github/workflows/b0-pre.yml
# so the disk-portability fix and the pin-schema reconciliation stay enforced. Needs no
# network, toolchain, GPU, or venue.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
SCRIPTS="$(cd "$HERE/.." && pwd)"
rc=0

echo "== bash -n (syntax) =="
for s in lib.sh verify_pins.sh run_authoritative.sh measure_fragment.sh derive_guest_set.sh build_container.sh preflight_venue.sh committed_lock_authority.sh smoke.sh provision_prover_toolchain.sh make_validation_bundle.sh tooling_pathset.sh \
         tool_identities.sh resolve_lock.sh extract_material.sh verifier_fixtures.sh prove_fixture.sh \
         docker_firewall.sh validate_cgroup_measurement.sh probe_cgroup_privilege.sh tests/docker_firewall.test.sh tests/docker_firewall_cgroup.test.sh tests/cgroup_evidence.test.sh \
         tests/disk_free_gib.test.sh tests/pin_schema.test.sh tests/pin_cargo_audit_advdb.test.sh tests/pin_prover_archives.test.sh tests/pin_prover_archive_authority.test.sh tests/source_authority.test.sh tests/blake3_cluster_pin.test.sh tests/risc0_harness_pins.test.sh \
         tests/smoke_guards.test.sh tests/smoke_orchestration.test.sh tests/verified_extraction.test.sh tests/provisioning_recipe.test.sh tests/cargo_audit_global_cache.test.sh \
         tests/pin_url_policy.test.sh tests/oci_platform.test.sh tests/tool_identity_arch.test.sh \
         tests/apt_pins.test.sh tests/tool_identity_threading.test.sh tests/oci_daemon_bridge.test.sh \
         tests/build_reproducibility.test.sh tests/runnable_ref_sidecar.test.sh tests/rustup_components.test.sh tests/runner_path_independence.test.sh double_build_runner.sh b0_rustc_remap_wrapper.sh \
         produce_canonical_sp1_guest.sh provision_sp1_guest_seed.sh \
         tests/builder_capability.test.sh tests/e2e_v2_produce_chain.test.sh tests/lifecycle_mode.test.sh tests/toolchain_authority.test.sh tests/lock_reconciliation.test.sh tests/committed_lock_authority.test.sh tests/measure_fragment_preflight.test.sh tests/emit_identity_rederivation.test.sh tests/sp1_guest_dep_seed.test.sh tests/run.sh; do
  f="$SCRIPTS/$s"
  [ -f "$f" ] || continue
  if bash -n "$f"; then echo "  ok  $s"; else echo "  FAIL $s"; rc=1; fi
done
# The cgroup evidence emitter is Python (not bash): in-memory compile as the syntax gate (writes no
# bytecode file, so it never leaves a stray __pycache__ in the tree).
if command -v python3 >/dev/null 2>&1 && [ -f "$SCRIPTS/emit_cgroup_evidence.py" ]; then
  if python3 -c 'import sys; compile(open(sys.argv[1]).read(), sys.argv[1], "exec")' "$SCRIPTS/emit_cgroup_evidence.py"; then echo "  ok  emit_cgroup_evidence.py (compile)"; else echo "  FAIL emit_cgroup_evidence.py"; rc=1; fi
fi

if command -v shellcheck >/dev/null 2>&1; then
  echo "== shellcheck -x -S error (source-follow SC1091 is info-level, not gated) =="
  if shellcheck -x -S error \
      "$SCRIPTS/lib.sh" "$SCRIPTS/verify_pins.sh" "$SCRIPTS/preflight_venue.sh" "$SCRIPTS/run_authoritative.sh" \
      "$SCRIPTS/build_container.sh" "$SCRIPTS/tool_identities.sh" "$SCRIPTS/resolve_lock.sh" \
      "$SCRIPTS/committed_lock_authority.sh" "$SCRIPTS/tests/committed_lock_authority.test.sh" \
      "$SCRIPTS/extract_material.sh" "$SCRIPTS/smoke.sh" "$SCRIPTS/provision_prover_toolchain.sh" "$SCRIPTS/tests/smoke_guards.test.sh" \
      "$SCRIPTS/tests/smoke_orchestration.test.sh" "$SCRIPTS/tests/verified_extraction.test.sh" \
      "$SCRIPTS/tests/provisioning_recipe.test.sh" "$SCRIPTS/tests/cargo_audit_global_cache.test.sh" \
      "$SCRIPTS/tests/disk_free_gib.test.sh" "$SCRIPTS/tests/pin_schema.test.sh" \
      "$SCRIPTS/tests/blake3_cluster_pin.test.sh" "$SCRIPTS/tests/risc0_harness_pins.test.sh" \
      "$SCRIPTS/tests/source_authority.test.sh" "$SCRIPTS/tests/pin_url_policy.test.sh" \
      "$SCRIPTS/tests/oci_platform.test.sh" "$SCRIPTS/tests/tool_identity_arch.test.sh" \
      "$SCRIPTS/tests/apt_pins.test.sh" "$SCRIPTS/tests/tool_identity_threading.test.sh" \
      "$SCRIPTS/tests/oci_daemon_bridge.test.sh" "$SCRIPTS/tests/build_reproducibility.test.sh" \
      "$SCRIPTS/tests/runnable_ref_sidecar.test.sh" "$SCRIPTS/tests/rustup_components.test.sh" \
      "$SCRIPTS/tests/runner_path_independence.test.sh" "$SCRIPTS/double_build_runner.sh" "$SCRIPTS/b0_rustc_remap_wrapper.sh" \
      "$SCRIPTS/tests/lifecycle_mode.test.sh" "$SCRIPTS/measure_fragment.sh" "$SCRIPTS/derive_guest_set.sh" "$SCRIPTS/tests/toolchain_authority.test.sh" \
      "$SCRIPTS/make_validation_bundle.sh" "$SCRIPTS/tooling_pathset.sh" \
      "$SCRIPTS/docker_firewall.sh" "$SCRIPTS/validate_cgroup_measurement.sh" "$SCRIPTS/probe_cgroup_privilege.sh" \
      "$SCRIPTS/produce_canonical_sp1_guest.sh" "$SCRIPTS/provision_sp1_guest_seed.sh" \
      "$SCRIPTS/tests/docker_firewall.test.sh" "$SCRIPTS/tests/docker_firewall_cgroup.test.sh" "$SCRIPTS/tests/emit_identity_rederivation.test.sh" "$SCRIPTS/tests/sp1_guest_dep_seed.test.sh" "$SCRIPTS/tests/run.sh"; then
    echo "  ok  no error-level findings"
  else
    echo "  FAIL shellcheck error-level findings"; rc=1
  fi
else
  echo "== shellcheck absent — skipped =="
fi

echo "== unit tests =="
bash "$HERE/disk_free_gib.test.sh"     || rc=1
bash "$HERE/pin_schema.test.sh"        || rc=1
# Lifecycle-mode boundary guard: preregistration (hash unwritten) vs measurement
# (committed .json.hash == merged b0_pre_spec_hash). No Docker/network.
bash "$HERE/lifecycle_mode.test.sh"    || rc=1
# B0-FINAL toolchain-authority: ratified identity sourced only from the hash-verified
# content-addressed record; tampered record refused. No Docker/venue.
bash "$HERE/toolchain_authority.test.sh" || rc=1
# NB: the B0-FINAL measurement runner is now checked-in Rust (tools/b0-pre-measure-core +
# the b0-pre-measure-{sp1,risc0} runners + b0-pre-host-provenance), unit-tested in those
# crates' own suites and CI-compiled with --features real-backend; the venue orchestration
# is measure_fragment.sh (bash -n + shellcheck above). There is no shell measurement unit
# test here anymore because there are no shell measurement boundaries to mock.
# Opt-in primary-source verification of the cargo-audit + advisory-DB pin blocks (needs
# network; SKIPs cleanly unless B0PRE_PIN_NET_IT=1 / B0PRE_PIN_NET_REQUIRED=1).
bash "$HERE/pin_cargo_audit_advdb.test.sh"   || rc=1
# blake3 shared-leaf cluster pin invariant (Part 1, no network) + shared-leaf conflict
# repro (Part 2, opt-in network; SKIPs unless B0PRE_PIN_NET_IT=1 / B0PRE_PIN_NET_REQUIRED=1).
bash "$HERE/blake3_cluster_pin.test.sh"      || rc=1
# RISC0 harness MSRV exact-pin policy: exact pins, rust-version contract, no resolver fallback.
bash "$HERE/risc0_harness_pins.test.sh"       || rc=1
# prover-archive pin block: positive + full negative matrix + tool-identity cross-check (no Docker/network).
bash "$HERE/pin_prover_archives.test.sh"  || rc=1
# prover-archive AUTHORITY: real archives through the single verified-extraction impl; every archive
# sha + member sha/size one-char mutation refused (needs network; SKIPs unless B0PRE_PIN_NET_IT=1).
bash "$HERE/pin_prover_archive_authority.test.sh"  || rc=1
# TEST_ONLY smoke source-authority guards + smoke/authoritative schema split (no Docker/network).
bash "$HERE/smoke_guards.test.sh"      || rc=1
# TEST_ONLY smoke post-build orchestration: source guard, failure propagation, output isolation,
# marker absence on failure, and the three authoritative rejection proofs (no Docker/network).
bash "$HERE/smoke_orchestration.test.sh"  || rc=1
# Declarative verified archive-member extraction (crafted archives; no Docker/network).
bash "$HERE/verified_extraction.test.sh"  || rc=1
# Declarative AUDIT + PROVER provisioning recipe structure (Dockerfiles + build_container + staging;
# no Docker/network — the venue build EXECUTES what this locks).
bash "$HERE/provisioning_recipe.test.sh"  || rc=1
bash "$HERE/source_authority.test.sh"  || rc=1
bash "$HERE/pin_url_policy.test.sh"    || rc=1
bash "$HERE/oci_platform.test.sh"      || rc=1
bash "$HERE/tool_identity_arch.test.sh" || rc=1
bash "$HERE/apt_pins.test.sh"          || rc=1
bash "$HERE/tool_identity_threading.test.sh" || rc=1
bash "$HERE/oci_daemon_bridge.test.sh" || rc=1
bash "$HERE/build_reproducibility.test.sh"   || rc=1
# Runner path-independence recipe guards: source-level controls + fast pre-build refusal negatives
# (bad flags, non-hex identities, non-exec wrapper, symlink/identical source roots, ambient RUSTFLAGS).
# The empirical two-build byte-identity runs on Linux (Docker gate) + CI's real-backend double-build.
bash "$HERE/runner_path_independence.test.sh" || rc=1
bash "$HERE/runnable_ref_sidecar.test.sh"    || rc=1
bash "$HERE/rustup_components.test.sh"       || rc=1
# Opt-in builder-image capability preflight negatives (SKIPs unless B0PRE_DOCKER_IT=1 + a daemon).
bash "$HERE/builder_capability.test.sh"      || rc=1
# Opt-in real-Docker cargo-audit .global-cache reproducibility proof (two-build manifest identity;
# SKIPs unless B0PRE_DOCKER_IT=1 + a daemon).
bash "$HERE/cargo_audit_global_cache.test.sh" || rc=1
# Opt-in real-container v2 produce-chain E2E (SKIPs unless B0PRE_DOCKER_IT=1 + a daemon).
bash "$HERE/e2e_v2_produce_chain.test.sh"    || rc=1
# Docker invocation firewall: authorized-grammar rewrite + security negatives (smart stub docker).
bash "$HERE/docker_firewall.test.sh"          || rc=1
# Driver-aware proving-cgroup measurement: cgroupfs + systemd lifecycle + fail-closed guards
# (extracted firewall helpers; the real systemd peak capture is venue-validated by
# validate_cgroup_measurement.sh before Commit A — mocks alone do not close item D).
bash "$HERE/docker_firewall_cgroup.test.sh"   || rc=1
# Cgroup validation evidence encoder: independent-parser JSON tests (empty fields, control chars,
# type preservation, one object per line, fail-closed with no partial line).
bash "$HERE/cgroup_evidence.test.sh"          || rc=1
# Shared committed-candidate-lock AUTHORITY (single source of truth for the CI workspace guard +
# venue measurement preflight): positive + missing/untracked/empty/symlink/mutation/swapped/
# wrong-path + exact-set, and `preflight_venue.sh --mode=measurement` reaches the next gate.
bash "$HERE/committed_lock_authority.test.sh" || rc=1
# B0-FINAL grid cell pre-proving guest-set / canonical-package gate (the v8 `--guest-set` 3-arg contract):
# drives the ACTUAL measure_fragment pre-proving path for SP1 + RISC0 with a valid TEST_ONLY guest set —
# 3-arg succeeds + derived set matches; missing / wrong / mutated canonical package refuses; NO proving
# runner launches. SKIPs cleanly if cargo/git/b3sum are absent (fast no-toolchain runners); the dedicated
# b0-pre.yml step runs it with the toolchain present so it is enforced, never silently skipped, in CI.
bash "$HERE/measure_fragment_preflight.test.sh" || rc=1
# Measurement-build identity RE-DERIVATION contract (past the preflight boundary): the ONE shared
# --emit-identity constructor emits a superset of the runner's req() set (per candidate), both callers
# use it and neither hand-rolls the vector, and (with cargo, x86 host) measure_fragment is driven to the
# _idargs re-derivation and REFUSES a wrong tooling_commit. This is the guard for the grid blocker where
# measure_fragment silently dropped --tooling-commit/--tooling-pathset-blake3/--canonical-…-address.
bash "$HERE/emit_identity_rederivation.test.sh" || rc=1
# SP1 GUEST dependency-seed AUTHORITY (one authenticated, content-addressed OFFLINE vendor seed) + RISC0
# Option-B authenticated-runner binding: the shared authenticator's full refusal matrix (missing / mutated
# / substituted / superseded 8584a56d / wrong-lock / wrong-toolchain), determinism + path-independence, the
# shared runner<->recipe helper both RISC0 phases drive, and source guards (offline, no re-vendor, no legacy
# RISC0 build, seed authority bound into both verifier preimages). No network/Docker/toolchain.
bash "$HERE/sp1_guest_dep_seed.test.sh" || rc=1
# Two-root VALIDATION-BUNDLE content binding: the bundle's tooling-inventory.txt is the canonical
# path-set preimage (every included file's BLAKE3), MANIFEST binds the ratified Commit A + path-set
# digest (never PENDING), and the content address transitively binds the whole tooling payload —
# a one-byte change to any included file, or any inventory/MANIFEST tamper, is refused. No Docker/network.
bash "$SCRIPTS/make_validation_bundle.sh" --selftest || rc=1

echo "----"
if [ "$rc" = 0 ]; then echo "B0-PRE script tests: ALL PASS"; else echo "B0-PRE script tests: FAILURES" >&2; fi
exit "$rc"
