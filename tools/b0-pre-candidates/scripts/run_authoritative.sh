#!/usr/bin/env bash
# The authoritative orchestration for resolving the three B0-PRE Stage-1 categories,
# built on the SEALED per-arch evidence bundle (PerArchEvidenceBundleV1). Runs ONLY on
# proper native Linux venues (per VENUE.md). Fail-closed at every stage; refuses
# PARTIAL insertion. Never fabricates, never pushes, never writes the real
# b0-pre-protocol-v1.hash.
#
# The run is split into THREE explicit commands, because no single host can satisfy
# both architectures and RISC Zero material is x86_64-only:
#
#   run_authoritative.sh produce-arch <x86_64|aarch64> <evidence_dir>
#       Produce ONLY this architecture's evidence into a CLEAN, SEALED per-arch bundle
#       directory whose files are EXACTLY required_files(arch): {Sp1,Risc0}.container/
#       native/Cargo.lock/lock-provenance/stage2-audit/tool-binding[.stage5-result] +
#       sp1[/risc0]-verifier-material.json. Build scratch lives in a SEPARATE work dir
#       and is never sealed. The bundle is `seal-bundle`'d (an immutable per-file hash
#       manifest) and then `import-bundle`'d (every hash recomputed, every typed record
#       bound to one arch+source-commit) BEFORE it is reported READY. A producer that
#       emits the wrong shape/name is refused at seal (extra/missing file) or at import
#       (bad binding) — it can never be reported ready.
#
#   run_authoritative.sh import-verify <evidence_dir>
#       Independently re-run the typed import verification on a RETURNED sealed per-arch
#       bundle (`import-bundle`): recompute every hash, reject any unmanifested/missing
#       file, and bind every typed record. The obsolete mutable-directory `import-arch`
#       path is NOT used.
#
#   run_authoritative.sh aggregate <x86_64_dir> <aarch64_dir> <workdir>
#       Assemble the full AUTHORITATIVE_STAGE1 bundle ONLY after BOTH sealed per-arch
#       bundles pass import verification, via `aggregate-bundles`, which import-verifies
#       both and emits EVERY Stage-6 input (RISC Zero + SP1 material, both candidate
#       locks, and the authoritative tool identities) FROM the import-verified typed
#       records — never a post-verification copy out of the per-arch directories. Then
#       stage6-assemble -> stage1-ingest.
#
# OFF-VENUE dry run (SUMCHAIN_B0PRE_DRYRUN=1): no Docker/toolchains are available, so
# produce-arch synthesizes a TEST_ONLY per-arch bundle with the tested-valid
# constructor (`venue-verify emit-test-only-bundle`) that emits the EXACT required_files
# shapes, then runs the SAME seal -> import -> (aggregate) control flow. The synthetic
# verifier material is NON_SELECTION/TEST_ONLY, so Stage-1 classifies the aggregated
# bundle TEST_ONLY and it can NEVER finalize. Dry-run output is never authoritative.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
# shellcheck source=lib.sh
. "$HERE/lib.sh"

VAL="$ROOT/../b0-pre-validator/Cargo.toml"
# Every venue-verify invocation optionally appends its subcommand to a trace file, so
# the CLI regression can prove the actual script drives the SEALED workflow
# (seal-bundle/import-bundle/aggregate-bundles) and never the obsolete
# import-arch/aggregate-arches path.
vv() {
  [ -n "${SUMCHAIN_B0PRE_VV_TRACE:-}" ] && printf '%s\n' "${1:-}" >> "$SUMCHAIN_B0PRE_VV_TRACE"
  # The CLI regression test points VENUE_VERIFY_BIN at a prebuilt binary so it drives
  # the ACTUAL script without a nested `cargo run` per call.
  if [ -n "${VENUE_VERIFY_BIN:-}" ]; then
    "$VENUE_VERIFY_BIN" "$@"
  else
    cargo run --quiet --locked --manifest-path "$VAL" --bin venue-verify -- "$@"
  fi
}

schema_arch_of() {
  case "$1" in
    x86_64|amd64) printf 'X86_64' ;;
    aarch64|arm64) printf 'Aarch64' ;;
    *) die "arch must be x86_64|aarch64 (got '${1:-}')" ;;
  esac
}

# The single source_commit every typed record in a sealed-candidate evidence dir is
# bound to. `seal-bundle` records it; `import-bundle` then binds every typed record to
# it and REFUSES any record that disagrees. Authoritatively this is the checked-out
# HEAD the producers built from; in the dry run it is the constructor's fixed synthetic
# commit, read back from an emitted record (never HEAD).
evidence_source_commit() {
  local ev="$1"
  if is_dryrun; then
    python3 - "$ev/Sp1.lock-provenance.json" <<'PY'
import json, sys
print(json.load(open(sys.argv[1]))["source_commit"])
PY
  else
    git -C "$ROOT" rev-parse HEAD
  fi
}

# The builder image digest a producer recorded for (candidate, arch) in the work dir.
builder_digest_of() {
  local cand="$1" arch="$2" work="$3"
  python3 - "$work/$cand.$arch.container.json" <<'PY'
import json, sys
builds = json.load(open(sys.argv[1]))
b = next(x for x in builds if x["role"] == "builder")
print(b["builder_oci_digest"])
PY
}

# ---- (a) per-architecture producer -> sealed, import-verified evidence bundle ------
produce_arch() {
  local arch="$1" evidence="$2"
  case "$arch" in x86_64|aarch64) ;; *) die "arch must be x86_64|aarch64" ;; esac
  [ -n "$evidence" ] || die "evidence_dir argument required"
  local schema_arch; schema_arch="$(schema_arch_of "$arch")"

  # The clean, sealed, exported EVIDENCE dir is SEPARATE from the WORK dir (two clean
  # builds, command/raw-output logs, extraction + install temporaries). NOTHING in the
  # work dir is ever sealed; the evidence dir ends up containing EXACTLY
  # required_files(arch) (seal refuses any extra or missing file).
  [ -e "$evidence" ] && die "evidence dir $evidence already exists; refuse to overwrite"
  local work="${evidence%/}.work"
  rm -rf "$work"
  mkdir -p "$evidence" "$work"

  if is_dryrun; then
    note "== DRY-RUN: synthesize a TEST_ONLY per-arch evidence bundle (exact required_files shapes) =="
    vv emit-test-only-bundle "$evidence" "$schema_arch" \
      || die "dry-run per-arch bundle construction failed"
  else
    produce_arch_authoritative "$arch" "$schema_arch" "$evidence" "$work"
  fi

  note "== SEAL: hash every required file into an immutable per-arch manifest =="
  local commit; commit="$(evidence_source_commit "$evidence")"
  vv seal-bundle "$evidence" "$schema_arch" "$commit" \
    || die "sealing the per-arch evidence bundle failed (wrong/extra/missing file)"

  note "== TYPED IMPORT: recompute every hash + bind every typed record BEFORE READY =="
  vv import-bundle "$evidence" \
    || die "per-arch evidence bundle failed typed import; NOT ready"

  note "per-arch bundle READY at $evidence (arch=$arch): sealed + import-verified. Final insertion requires BOTH arches -> aggregate."
}

# Authoritative real-venue producer: runs the native builders/extractors into the WORK
# dir, then assembles the CLEAN evidence dir under EXACT required_files() names. Runs
# only on a native Linux + Docker venue; fails closed everywhere off-venue.
produce_arch_authoritative() {
  local arch="$1" schema_arch="$2" evidence="$3" work="$4"

  note "== Stage 0: environment gates (before any resolution/build) =="
  require_native_arch "$arch"
  require_linux_oci_builder
  require_free_gib "$work" 100
  require_cmd python3
  [ -z "$(git -C "$ROOT" status --porcelain 2>/dev/null || echo dirty)" ] \
    || die "source tree is not clean; refuse to build from a dirty state"
  require_no_preexisting_lock "$ROOT/candidates/sp1"
  require_no_preexisting_lock "$ROOT/candidates/risc0"

  note "== Stage 3: two clean OCI builds per candidate (this arch), compare MANIFEST identities -> work =="
  bash "$HERE/build_container.sh" sp1   "$arch" "$work"
  bash "$HERE/build_container.sh" risc0 "$arch" "$work"

  note "== Stage 1: resolve candidate locks INSIDE the pinned builder image -> work =="
  local sp1_builder risc0_builder
  sp1_builder="$(builder_digest_of sp1 "$arch" "$work")"
  risc0_builder="$(builder_digest_of risc0 "$arch" "$work")"
  SCHEMA_ARCH="$schema_arch" BUILDER_IMAGE_REF="oci:local/b0pre-sp1-$arch" \
    BUILDER_IMAGE_DIGEST="$sp1_builder" bash "$HERE/resolve_lock.sh" sp1 "$work"
  SCHEMA_ARCH="$schema_arch" BUILDER_IMAGE_REF="oci:local/b0pre-risc0-$arch" \
    BUILDER_IMAGE_DIGEST="$risc0_builder" bash "$HERE/resolve_lock.sh" risc0 "$work"

  note "== Stage 2: PER-CANDIDATE container-resolved graph audit -> work =="
  produce_stage2 Sp1   "$work"
  produce_stage2 Risc0 "$work"

  note "== Stage 4-5: extract verifier material INSIDE the pinned builder -> work =="
  cargo run --quiet --locked --manifest-path "$ROOT/harness/sp1-verifier-material/Cargo.toml" \
    > "$work/sp1-verifier-material.json" || die "SP1 verifier-material extraction failed closed"
  if [ "$arch" = "x86_64" ]; then
    require_native_arch x86_64
    cargo run --quiet --locked --manifest-path "$ROOT/harness/risc0-verifier-material/Cargo.toml" \
      > "$work/risc0-verifier-material.json" \
      || die "RISC Zero verifier-material extraction failed closed (native x86_64 only)"
  else
    note "arch=$arch: skipping RISC Zero extraction (x86_64-only per VENUE.md §2)"
  fi

  note "== Stage 5b: real tool identities (download->verify->install->verify->bind) -> work =="
  bash "$HERE/tool_identities.sh" "$work"

  note "== Stage 5c: per-candidate proof-verification (mutation) results -> work =="
  produce_stage5 Sp1 "$work"
  if [ "$arch" = "x86_64" ]; then
    produce_stage5 Risc0 "$work"
  fi

  note "== ASSEMBLE the clean evidence dir under EXACT required_files() names (no scratch is sealed) =="
  assemble_evidence "$arch" "$work" "$evidence"
}

# Per-candidate Stage-2 graph audit. The venue supplies the in-container resolved graph,
# advisory report, and license allow-list per candidate; venue-verify emits the typed,
# candidate-scoped record and EXITS NON-ZERO on any fatal finding.
produce_stage2() {
  local cand="$1" work="$2"
  local UC; UC="$(printf '%s' "$cand" | tr '[:lower:]' '[:upper:]')"
  local gv="STAGE2_${UC}_GRAPH_JSON" av="STAGE2_${UC}_ADVISORIES_JSON" lv="STAGE2_${UC}_LICENSES_JSON"
  local g="${!gv:-}" a="${!av:-}" l="${!lv:-}"
  [ -n "$g" ] || nyr "$gv (in-container resolved graph for $cand) is required"
  [ -n "$a" ] || nyr "$av (cargo-audit output for $cand) is required"
  [ -n "$l" ] || nyr "$lv (license allow-list for $cand) is required"
  vv stage2-audit "$g" "$a" "$l" "$work/$cand.stage2-audit.json" \
    || die "Stage-2 graph audit is FATAL for $cand; candidate ineligible"
}

# Per-candidate Stage-5 proof-verification + mutation results. The venue supplies the
# result JSON; venue-verify validates its shape (verify-stage5) before it is recorded.
produce_stage5() {
  local cand="$1" work="$2"
  local UC; UC="$(printf '%s' "$cand" | tr '[:lower:]' '[:upper:]')"
  local rv="STAGE5_${UC}_RESULT_JSON" r
  r="${!rv:-}"
  [ -n "$r" ] || nyr "$rv (proof-verification/mutation results for $cand) is required"
  [ -f "$r" ] || die "$rv points at a missing file: $r"
  vv verify-stage5 "$r" || die "Stage-5 result for $cand failed verification"
  cp "$r" "$work/$cand.stage5-result.json"
}

# Copy ONLY the final typed artifacts from the work dir into the clean evidence dir
# under the EXACT required_files() names. This is bundle assembly BEFORE sealing (not a
# post-verification copy): the container/native records are renamed from the producer's
# lowercase+arch scratch names to the schema-cased, arch-free bundle names; every other
# producer already writes the exact name. Nothing else from the work dir is copied.
assemble_evidence() {
  local arch="$1" work="$2" ev="$3"
  local c lc
  for c in Sp1 Risc0; do
    lc="$(printf '%s' "$c" | tr '[:upper:]' '[:lower:]')"
    cp "$work/$lc.$arch.container.json" "$ev/$c.container.json"
    cp "$work/$lc.$arch.native.json"    "$ev/$c.native.json"
    cp "$work/$c.Cargo.lock"            "$ev/$c.Cargo.lock"
    cp "$work/$c.lock-provenance.json"  "$ev/$c.lock-provenance.json"
    cp "$work/$c.stage2-audit.json"     "$ev/$c.stage2-audit.json"
    cp "$work/$c.tool-binding.json"     "$ev/$c.tool-binding.json"
  done
  cp "$work/Sp1.stage5-result.json"     "$ev/Sp1.stage5-result.json"
  cp "$work/sp1-verifier-material.json" "$ev/sp1-verifier-material.json"
  if [ "$arch" = "x86_64" ]; then
    cp "$work/Risc0.stage5-result.json"     "$ev/Risc0.stage5-result.json"
    cp "$work/risc0-verifier-material.json" "$ev/risc0-verifier-material.json"
  fi
}

# ---- (b) independent typed import verification of a returned per-arch bundle -------
import_verify() {
  local evidence="$1"
  [ -n "$evidence" ] || die "evidence_dir argument required"
  [ -d "$evidence" ] || die "evidence_dir $evidence does not exist"
  vv import-bundle "$evidence" || die "per-arch sealed bundle failed typed import verification"
}

# ---- (c) cross-architecture aggregation + insertion -------------------------------
aggregate() {
  local x86="$1" arm="$2" work="$3"
  [ -n "$x86" ] && [ -n "$arm" ] && [ -n "$work" ] || die "usage: aggregate <x86_dir> <arm_dir> <workdir>"
  [ -d "$x86" ] && [ -d "$arm" ] || die "both per-arch sealed bundle dirs must exist"
  mkdir -p "$work"

  note "== independently import-verify BOTH sealed per-arch bundles =="
  vv import-bundle "$x86" || die "x86_64 sealed bundle failed import verification"
  vv import-bundle "$arm" || die "aarch64 sealed bundle failed import verification"

  note "== cross-architecture aggregation from the TWO TYPED bundles (no directory copy) =="
  local agg="$work/aggregate"
  [ -e "$agg" ] && die "an aggregate dir already exists at $agg; refusing to replace it"
  mkdir -p "$agg"
  # aggregate-bundles re-import-verifies both sealed bundles and emits EVERY Stage-6
  # input FROM the import-verified typed records: digests.json, native-provenance.json,
  # sp1/risc0-verifier-material.json (RISC Zero sourced from x86_64), Sp1/Risc0.Cargo.lock
  # (the verified candidate lock bytes), and tool-identities.json (from the verified tool
  # binding records). There is NO post-verification copy out of the per-arch directories.
  vv aggregate-bundles "$x86" "$arm" "$agg" \
    || die "cross-arch aggregation failed (both arches required; arm must not carry RISC Zero)"

  if is_dryrun; then
    # A sealed bundle that passes import is authoritative-grade BY CONSTRUCTION: import
    # requires non-synthetic, `test_only:false` tool bindings, so there is no synthetic
    # sealed bundle. Stage-6 assembly (Authoritative) + Stage-1 ingest MINT and INSERT a
    # finalizable artifact, so running them on the dry run's synthetic-origin evidence
    # would mint an AUTHORITATIVE_STAGE1 artifact from data no venue produced. They are
    # therefore NOT run in the dry run: synthetic evidence can never finalize. The dry
    # run has verified the full SEALED control flow — emit -> seal -> import (per arch)
    # and import-bundle x2 -> aggregate-bundles (cross arch, no directory copy).
    note "DRY-RUN: sealed cross-arch aggregation control flow verified. Stage-6 assembly + Stage-1 ingest are INTENTIONALLY skipped (they finalize; that requires real venue evidence). Synthetic/TEST_ONLY evidence can never finalize."
    return 0
  fi

  note "== Stage 6: ASSEMBLE the AUTHORITATIVE_STAGE1 bundle from the aggregated typed outputs =="
  local bundle="$work/stage1-result-bundle.json"
  local artifact_out="$work/b0-pre-protocol-v1.finalizable.json"
  [ -e "$bundle" ] && die "a Stage-1 result bundle already exists at $bundle; refusing to replace it"
  cargo run --quiet --locked --manifest-path "$VAL" --bin stage6-assemble -- \
    "$agg/digests.json" "$agg/sp1-verifier-material.json" "$agg/risc0-verifier-material.json" \
    "$agg/native-provenance.json" "$agg/tool-identities.json" \
    "$agg/Sp1.Cargo.lock" "$agg/Risc0.Cargo.lock" "$bundle" \
    || die "Stage-6 assembly failed closed (diverged builds / missing tool identities / malformed output)"

  note "== Stage 7: strict decode + full validation + all-or-nothing insertion =="
  if cargo run --quiet --locked --manifest-path "$VAL" --bin stage1-ingest -- "$bundle" "$artifact_out"; then
    note "all three categories complete + reproducible -> Stage-1 inputs inserted into $artifact_out"
    # "$artifact_out" is a workdir target ONLY. Do NOT copy it over the committed
    # normative artifact, write the real b0-pre-protocol-v1.hash, materialize
    # statements, or build guests — those are later stages. The committed artifact
    # stays not_finalizable until a real authoritative run is performed and reviewed.
  else
    die "incomplete/unreproducible/invalid bundle -> REFUSING partial insertion; artifact stays not_finalizable"
  fi
}

cmd="${1:-}"; shift || true
case "$cmd" in
  produce-arch)  produce_arch "${1:-}" "${2:-}" ;;
  import-verify) import_verify "${1:-}" ;;
  aggregate)     aggregate "${1:-}" "${2:-}" "${3:-}" ;;
  *) die "usage: run_authoritative.sh <produce-arch <arch> <evidence_dir> | import-verify <evidence_dir> | aggregate <x86_dir> <arm_dir> <workdir>>" ;;
esac
