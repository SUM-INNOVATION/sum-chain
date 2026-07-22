#!/usr/bin/env bash
# The authoritative orchestration for resolving the three B0-PRE Stage-1 categories,
# built on the SEALED per-arch evidence bundle (PerArchEvidenceBundleV1). Runs ONLY on
# proper native Linux venues (per docs/b0-pre/venue/VENUE.md). Fail-closed at every stage; refuses
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

# ---- Disk telemetry ---------------------------------------------------------
# Records free space at start, per-stage free + work-dir usage, the PEAK work-dir usage,
# and the FINAL retained evidence size into $work/disk-telemetry.tsv. Each large stage is
# refused BEFORE it starts if its estimated headroom is unavailable (see require_headroom_gib).
DISK_TELEMETRY=""
DISK_PEAK_MIB=0
disk_telemetry_init() {
  local work="$1"
  DISK_TELEMETRY="$work/disk-telemetry.tsv"
  DISK_PEAK_MIB=0
  {
    printf 'stage\tfree_gib\twork_used_mib\n'
    printf 'start\t%s\t0\n' "$(disk_free_gib "$work")"
  } > "$DISK_TELEMETRY"
}
# Record disk state AFTER a stage completes; track the peak work-dir usage.
disk_stage() {
  local label="$1" work="$2" free used
  [ -n "$DISK_TELEMETRY" ] || return 0
  free="$(disk_free_gib "$work")"
  used="$(dir_used_mib "$work")"
  [ "${used:-0}" -gt "$DISK_PEAK_MIB" ] && DISK_PEAK_MIB="$used"
  printf '%s\t%s\t%s\n' "$label" "$free" "$used" >> "$DISK_TELEMETRY"
}
disk_telemetry_final() {
  local work="$1" evidence="$2" ev_used start_free
  [ -n "$DISK_TELEMETRY" ] || return 0
  ev_used="$(dir_used_mib "$evidence")"
  start_free="$(awk -F'\t' '$1=="start"{print $2}' "$DISK_TELEMETRY")"
  {
    printf 'peak_work_used_mib\t%s\n' "$DISK_PEAK_MIB"
    printf 'final_evidence_used_mib\t%s\n' "$ev_used"
  } >> "$DISK_TELEMETRY"
  note "disk telemetry: start_free=${start_free}GiB peak_work=${DISK_PEAK_MIB}MiB final_evidence=${ev_used}MiB (log: $DISK_TELEMETRY)"
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
  disk_telemetry_init "$work"

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

  disk_telemetry_final "$work" "$evidence"
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
  require_headroom_gib "$work" 80 "Stage 3 two-clean-builds (both candidates)"
  bash "$HERE/build_container.sh" sp1   "$arch" "$work"
  bash "$HERE/build_container.sh" risc0 "$arch" "$work"
  disk_stage "stage3-clean-builds" "$work"

  note "== Stage 1: resolve candidate locks INSIDE the pinned builder image -> work =="
  require_headroom_gib "$work" 10 "Stage 1 in-container lock resolution"
  local sp1_builder risc0_builder
  sp1_builder="$(builder_digest_of sp1 "$arch" "$work")"
  risc0_builder="$(builder_digest_of risc0 "$arch" "$work")"
  SCHEMA_ARCH="$schema_arch" BUILDER_IMAGE_REF="oci:local/b0pre-sp1-$arch" \
    BUILDER_IMAGE_DIGEST="$sp1_builder" bash "$HERE/resolve_lock.sh" sp1 "$work"
  SCHEMA_ARCH="$schema_arch" BUILDER_IMAGE_REF="oci:local/b0pre-risc0-$arch" \
    BUILDER_IMAGE_DIGEST="$risc0_builder" bash "$HERE/resolve_lock.sh" risc0 "$work"

  note "== Stage 2: PER-CANDIDATE in-container cargo metadata + audit -> typed record -> work =="
  require_headroom_gib "$work" 5 "Stage 2 in-container cargo metadata + audit"
  produce_stage2 Sp1   "$arch" "$schema_arch" "$work"
  produce_stage2 Risc0 "$arch" "$schema_arch" "$work"
  disk_stage "stage2-audit" "$work"

  note "== Stage 4-5: extract verifier material INSIDE the pinned builder -> work =="
  require_headroom_gib "$work" 10 "Stage 4-5 verifier-material extraction"
  cargo run --quiet --locked --manifest-path "$ROOT/harness/sp1-verifier-material/Cargo.toml" \
    > "$work/sp1-verifier-material.json" || die "SP1 verifier-material extraction failed closed"
  if [ "$arch" = "x86_64" ]; then
    require_native_arch x86_64
    cargo run --quiet --locked --manifest-path "$ROOT/harness/risc0-verifier-material/Cargo.toml" \
      > "$work/risc0-verifier-material.json" \
      || die "RISC Zero verifier-material extraction failed closed (native x86_64 only)"
  else
    note "arch=$arch: skipping RISC Zero extraction (x86_64-only per docs/b0-pre/venue/VENUE.md §2)"
  fi

  disk_stage "stage4-verifier-material" "$work"

  note "== Stage 5b: real tool identities (download->verify->install->verify->bind) -> work =="
  bash "$HERE/tool_identities.sh" "$work"

  note "== Stage 5c: per-candidate genuine verifier fixture + mutation execution -> typed record -> work =="
  require_headroom_gib "$work" 10 "Stage 5 verifier fixture + mutation execution"
  produce_stage5 Sp1 "$arch" "$schema_arch" "$work"
  if [ "$arch" = "x86_64" ]; then
    produce_stage5 Risc0 "$arch" "$schema_arch" "$work"
  fi
  disk_stage "stage5-fixtures" "$work"

  note "== ASSEMBLE the clean evidence dir under EXACT required_files() names (no scratch is sealed) =="
  assemble_evidence "$arch" "$work" "$evidence"
}

# The canonical B0-PRE license allow-list (docs/b0-pre/venue/VENUE.md §5). A resolved crate whose license
# is not one of these is a FATAL Stage-2 finding held for review — never silently
# accepted, and never operator-widened at run time.
STAGE2_ALLOWED_LICENSES='["MIT","Apache-2.0","MIT OR Apache-2.0","Apache-2.0 OR MIT","BSD-2-Clause","BSD-3-Clause","ISC","Unicode-DFS-2016","Apache-2.0 WITH LLVM-exception","MPL-2.0","Zlib","CC0-1.0","Unlicense"]'

# Real per-candidate Stage-2 GENERATION. Runs `cargo metadata` + `cargo audit` INSIDE the
# pinned builder container, captures the RAW output + the exact command log + the
# in-container tool identities, and has venue-verify TYPE, AUDIT, and BIND the record
# directly from that raw output (bound to candidate/arch/container-digest/lock-hash/
# source-commit/commands). No operator-authored graph/advisory JSON is accepted; a fatal
# finding (wrong pin, bad source, advisory, disallowed license) exits non-zero.
produce_stage2() {
  local cand="$1" arch="$2" schema_arch="$3" work="$4"
  local lc; lc="$(printf '%s' "$cand" | tr '[:upper:]' '[:lower:]')"
  local ref="oci:local/b0pre-$lc-$arch"
  local builder commit lock_hex
  builder="$(builder_digest_of "$lc" "$arch" "$work")"
  commit="$(git -C "$ROOT" rev-parse HEAD)"
  lock_hex="$(vv lock-hash "$work/$cand.Cargo.lock")" || die "lock-hash failed for $cand"

  local meta="$work/$cand.cargo-metadata.json"
  local advis="$work/$cand.cargo-audit.json"
  local cmdlog="$work/$cand.stage2.cmd.log"
  # The candidate workspace lives at its reproduced repo-relative path in the staged
  # builder image (see stage_context.sh); metadata/audit run there over the full graph.
  local cdir; cdir="$(incontainer_candidate_dir "$lc")"
  {
    printf 'docker run --rm --pull never %s cargo metadata --format-version 1 --locked (cwd=%s)\n' "$builder" "$cdir"
    printf 'docker run --rm --pull never %s cargo audit --json (cwd=%s)\n' "$builder" "$cdir"
  } > "$cmdlog"
  docker run --rm --pull never "$ref" \
    bash -c "cd $cdir && cargo metadata --format-version 1 --locked" \
    > "$meta" 2>>"$cmdlog" || die "in-container cargo metadata failed for $cand"
  # cargo audit EXITS NON-ZERO when it finds advisories; capture its JSON regardless so
  # the typed audit gate classifies them (fatal). An empty/non-JSON body fails generation.
  docker run --rm --pull never "$ref" \
    bash -c "cd $cdir && cargo audit --json" \
    > "$advis" 2>>"$cmdlog" || true
  [ -s "$advis" ] || die "in-container cargo audit produced no output for $cand"

  local tool_id db_snap
  tool_id="$(docker run --rm --pull never "$ref" bash -c 'cargo --version; cargo audit --version' \
    2>/dev/null | tr '\n' ' ' | sed 's/  */ /g; s/ *$//')"
  db_snap="$(python3 -c 'import json,sys
d=json.load(open(sys.argv[1])).get("database",{})
print(d.get("last-commit") or d.get("last-updated") or "unknown")' "$advis" 2>/dev/null || echo unknown)"

  local params="$work/$cand.stage2-params.json"
  python3 - "$params" "$cand" "$schema_arch" "$builder" "$lock_hex" "$commit" \
    "${tool_id:-cargo + cargo-audit (in-container)}" "$db_snap" "$STAGE2_ALLOWED_LICENSES" <<'PY'
import json, sys
path, cand, arch, digest, lock, commit, tool, db, licenses = sys.argv[1:10]
json.dump({
    "candidate": cand, "arch": arch, "container_digest": digest,
    "lock_blake3_hex": lock, "source_commit": commit,
    "audit_tool_identity": tool, "advisory_db_snapshot": db,
    "allowed_licenses": json.loads(licenses),
}, open(path, "w"), indent=2)
PY
  vv stage2-generate "$params" "$meta" "$advis" "$cmdlog" "$work/$cand.stage2-audit.json" \
    || die "Stage-2 generation FATAL for $cand (audit finding / parse / binding); candidate ineligible"
}

# Real per-candidate Stage-5 GENERATION. Runs the pinned terminal verifier on a genuine
# proof fixture and applies EVERY required mutation INSIDE the pinned builder via the
# candidate's verifier-fixture harness (docs/b0-pre/venue/VENUE.md §3.4), capturing raw receipts/material +
# per-mutation rejection outcomes + the command log. venue-verify DERIVES overall_pass
# from the individual outcomes (a supplied pass is NEVER accepted), hashes the raw
# artifacts, and binds the record. No operator-authored result JSON is accepted.
produce_stage5() {
  local cand="$1" arch="$2" schema_arch="$3" work="$4"
  local lc; lc="$(printf '%s' "$cand" | tr '[:upper:]' '[:lower:]')"
  local ref="oci:local/b0pre-$lc-$arch"
  local builder commit tool_hex
  builder="$(builder_digest_of "$lc" "$arch" "$work")"
  commit="$(git -C "$ROOT" rev-parse HEAD)"
  # bind Stage-5 to the VERIFIED installed-binary identity (the first tool binding).
  tool_hex="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))[0]["installed_binary_sha256_hex"])' \
    "$work/$cand.tool-binding.json")" || die "cannot read tool identity for $cand"

  local outdir="$work/$cand.stage5"; mkdir -p "$outdir"
  local cmdlog="$work/$cand.stage5.cmd.log"
  # The candidate-specific verifier-fixture harness runs the genuine terminal-proof
  # verification + the five required mutation cases inside the pinned container, writing
  # raw artifacts to $outdir plus `fixtures.json` ([{label,path}]) and `mutations.json`
  # ([{name,actual_rejected}]). It is fail-closed if absent — a real verifier run is
  # required; no synthetic result is ever substituted in authoritative mode.
  local harness="$HERE/verifier_fixtures.sh"
  [ -x "$harness" ] \
    || nyr "verifier fixture harness $harness (genuine per-candidate verifier + mutation runner) is required"
  VERIFIER_REF="$ref" OUT_DIR="$outdir" CMD_LOG="$cmdlog" SCHEMA_ARCH="$schema_arch" \
    bash "$harness" "$lc" "$arch" \
    || die "Stage-5 verifier fixture execution failed for $cand"
  [ -f "$outdir/fixtures.json" ] && [ -f "$outdir/mutations.json" ] \
    || die "verifier fixture harness did not emit fixtures.json + mutations.json for $cand"

  local params="$work/$cand.stage5-params.json"
  python3 - "$params" "$cand" "$schema_arch" "$builder" "$commit" "$tool_hex" "$lc" <<'PY'
import json, sys
path, cand, arch, digest, commit, tool, lc = sys.argv[1:8]
json.dump({
    "candidate": cand, "arch": arch,
    "verifier_identity": f"pinned-{lc}-terminal-verifier",
    "tool_identity_hex": tool, "container_digest": digest, "source_commit": commit,
}, open(path, "w"), indent=2)
PY
  vv stage5-generate "$params" "$outdir/fixtures.json" "$outdir/mutations.json" "$cmdlog" \
    "$work/$cand.stage5-result.json" \
    || die "Stage-5 generation failed for $cand (a mutation was not rejected, or binding failed)"
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
