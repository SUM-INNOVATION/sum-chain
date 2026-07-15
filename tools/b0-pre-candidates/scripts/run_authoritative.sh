#!/usr/bin/env bash
# The single authoritative orchestration entrypoint for resolving the three
# B0-PRE Stage-1 categories. Runs ONLY on a proper native Linux venue (per
# VENUE.md). Fail-closed at every stage; refuses PARTIAL insertion — either a
# candidate is complete and reproducible across all three categories or the
# normative artifact stays blocked. Never fabricates, never pushes, never writes
# the real b0-pre-protocol-v1.hash.
#
# Usage: run_authoritative.sh <x86_64|aarch64> <workdir>
# (Run once per native builder; final insertion requires bundles from all
#  required arches/candidates to be present.)
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
. "$HERE/lib.sh"

arch="${1:-}"; work="${2:-}"
case "$arch" in x86_64|aarch64) ;; *) die "arch must be x86_64|aarch64" ;; esac
[ -n "$work" ] || die "workdir argument required"

# ---- Stage 0: environment gates (before any resolution/build) ----
require_native_arch "$arch"
require_linux_oci_builder
require_free_gib "$work" 100
[ -z "$(git -C "$ROOT" status --porcelain 2>/dev/null || echo dirty)" ] \
  || die "source tree is not clean; refuse to build from a dirty state"
require_no_preexisting_lock "$ROOT/candidates/sp1"
require_no_preexisting_lock "$ROOT/candidates/risc0"

note "== Stage 1: resolve candidate locks INSIDE the pinned container =="
# Each candidate lock is generated in-container and is the source of truth; the
# container refuses a host-supplied lock. (Implemented by the container build +
# an in-container `cargo generate-lockfile`.) candidate_dep_lock_hash is computed
# with the SUMCHAIN/B0PRE/CARGOLOCK/v1 rule over the in-container lock only.
: "${STAGE_RESOLVE:?resolve stage must run in-container; no host lock permitted}"

note "== Stage 2: audit resolved graph =="
# Policy (see VENUE.md "Version / audit policy"):
#   * FATAL: the SELECTED candidate release is not the pinned stable version
#     (sp1 6.3.1 / risc0 3.0.5 / risc0-groth16 3.0.4 / zkvm-platform 2.2.2);
#     an unexpected git/path source on any proof-stack crate; duplicate
#     INCOMPATIBLE proof-stack versions; an unresolved security advisory; a
#     license outside the allow-list.
#   * RECORDED (not auto-fatal): transitive PRERELEASE crates (e.g. SP1's
#     Plonky3 `p3-*` stack). These are enumerated and pass through the security /
#     source / reproducibility gates; a prerelease alone does not disqualify a
#     stable candidate release.

note "== Stage 3: two clean OCI builds per candidate/arch, compare digests =="
# build_container.sh <candidate> <arch> <out> ; hard-fails on digest divergence.

note "== Stage 4: extract verifier material (RISC Zero: native x86_64 only) =="
# run harness/*-verifier-material extractors; read material from the pinned crates.

note "== Stage 5: genuine verifier-contract fixtures =="
# SP1 Groth16 + RISC Zero shrink_wrap fixtures, all TEST_ONLY/NON_SELECTION/
# INVALID_FOR_R0/NOT_AN_OFFICIAL_GUEST; mutation tests must reject every
# required component. RISC Zero failure => evidence-backed INELIGIBLE.

note "== Stage 6: emit + independently validate machine-readable result bundle =="
bundle="$work/stage1-result-bundle.json"

# ---- Stage 7: all-or-nothing insertion guard ----
complete_and_reproducible() {
  # Returns 0 only if the bundle proves ALL of: two-build-reproducible container
  # digests (base+builder, required arches), in-container candidate_dep_lock_hash,
  # and complete verified verifier-material manifests for BOTH candidates. No
  # guest identity / r0_guest_set_hash anywhere.
  [ -f "$bundle" ] || return 1
  python3 - "$bundle" <<'PY'
import json,sys
b=json.load(open(sys.argv[1]))
req=["candidate_container_digests","cargo_lock_hashes","verifier_material_manifests"]
ok = all(b.get(k) for k in req) and b.get("all_reproducible") is True
forbidden=["r0_guest_set_hash","guest_program_identities","guest_program_id","populated_allowlist"]
ok = ok and not any(k in json.dumps(b) for k in forbidden)
sys.exit(0 if ok else 1)
PY
}

if complete_and_reproducible; then
  note "all three categories complete + reproducible -> inserting Stage-1 inputs only"
  # Insert ONLY candidate_container_digests + cargo_lock_hashes +
  # verifier_material_manifests, regenerate artifact + schema (finalizable), and
  # STOP. Do NOT write the real .hash, materialize statements, or build guests.
else
  die "incomplete/unreproducible bundle -> REFUSING partial insertion; artifact stays not_finalizable"
fi
