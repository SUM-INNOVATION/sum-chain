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
# Resolve HERE from ${BASH_SOURCE[0]} (this file), NOT $0 (the caller): a script that
# SOURCES this file must still locate lib.sh relative to THIS file, not relative to the
# sourcing script. When executed, ${BASH_SOURCE[0]} == $0, so this is unchanged there.
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
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

# schema_arch_of + builder_digest_of moved to lib.sh (shared single source of truth for the
# authoritative producer AND the TEST_ONLY smoke).

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

# The source_commit RECORDED in a sealed bundle's immutable manifest
# (PerArchEvidenceBundleV1.source_commit in arch-evidence-manifest.json). Unlike
# evidence_source_commit's authoritative branch (which returns THIS host's HEAD), this
# reads the commit the bundle was sealed under, so an aggregation host can cross-check
# both returned bundles regardless of its own checkout.
bundle_recorded_source_commit() {
  local ev="$1"
  python3 - "$ev/arch-evidence-manifest.json" <<'PY'
import json, sys
print(json.load(open(sys.argv[1]))["source_commit"])
PY
}

# builder_digest_of / schema_arch_of are defined in lib.sh (shared with the TEST_ONLY smoke).

# Defect 2: the runnable, VERIFIED local image reference for a (candidate, arch). build_
# container.sh loaded the verified OCI layout into the daemon, PROVED the loaded image
# corresponds to it, and wrote a TYPED, versioned sidecar (candidate/arch/manifest+config
# digests/runnable image id). Every in-container `docker run --pull never` below uses THIS
# proven identity — never the never-loaded `oci:local/...` placeholder. resolve_runnable_ref
# revalidates every field against THIS (candidate, arch) and the CURRENT verified
# container.json manifest digest, and confirms the image is still loaded; a malformed,
# stale (prior run / prior source commit), cross-candidate, cross-architecture, or
# missing-image sidecar fails closed.
runnable_ref_of() {
  local cand="$1" arch="$2" work="$3" cur
  cur="$(builder_digest_of "$cand" "$arch" "$work")"
  resolve_runnable_ref "$work/$cand.$arch.runnable-ref" "$cand" "$arch" "$cur" "$ROOT"
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
  # Source-commit authority FIRST: require the owner-ratified RATIFIED_SOURCE_COMMIT,
  # exactly 40 lowercase hex, equal to HEAD, on a clean checkout — before any
  # resolution/build/extraction/evidence generation. This also enforces the clean-tree
  # requirement (folds in the former standalone dirty-tree refusal).
  require_ratified_source_commit "$ROOT"
  require_native_arch "$arch"
  require_linux_oci_builder
  require_free_gib "$work" 100
  require_cmd python3
  require_no_preexisting_lock "$ROOT/candidates/sp1"
  require_no_preexisting_lock "$ROOT/candidates/risc0"

  note "== Stage 3: two clean OCI builds per candidate (this arch), compare MANIFEST identities -> work =="
  require_headroom_gib "$work" 80 "Stage 3 two-clean-builds (both candidates)"
  bash "$HERE/build_container.sh" sp1   "$arch" "$work"
  bash "$HERE/build_container.sh" risc0 "$arch" "$work"
  disk_stage "stage3-clean-builds" "$work"

  note "== Stage 1: resolve candidate locks INSIDE the pinned builder image -> work =="
  require_headroom_gib "$work" 10 "Stage 1 in-container lock resolution"
  local sp1_builder risc0_builder sp1_ref risc0_ref
  sp1_builder="$(builder_digest_of sp1 "$arch" "$work")"
  risc0_builder="$(builder_digest_of risc0 "$arch" "$work")"
  # Defect 2: run inside the VERIFIED, loaded image content addresses (not oci:local/...,
  # which was never loaded). BUILDER_IMAGE_DIGEST stays the recorded manifest identity.
  sp1_ref="$(runnable_ref_of sp1 "$arch" "$work")"
  risc0_ref="$(runnable_ref_of risc0 "$arch" "$work")"
  SCHEMA_ARCH="$schema_arch" BUILDER_IMAGE_REF="$sp1_ref" \
    BUILDER_IMAGE_DIGEST="$sp1_builder" bash "$HERE/resolve_lock.sh" sp1 "$work"
  SCHEMA_ARCH="$schema_arch" BUILDER_IMAGE_REF="$risc0_ref" \
    BUILDER_IMAGE_DIGEST="$risc0_builder" bash "$HERE/resolve_lock.sh" risc0 "$work"

  note "== Stage 1b: builder-image CAPABILITY preflight (fail closed BEFORE Stage 2 executes) =="
  # Item 6: validate — as early as technically possible, inside each VERIFIED builder image —
  # arch + cargo + cargo-audit VERSION/IDENTITY + the RT-2 non-login PATH, so a mis-provisioned
  # image (no cargo-audit, wrong version/hash, wrong arch, login-PATH loss) is rejected here,
  # not deep inside Stage 2. cargo-audit VERSION comes from the RATIFIED crate/version pin; the
  # executable SHA-256 is VENUE EVIDENCE (recorded + reproduced by an independent same-arch
  # operator — NOT a source pin), threaded as an EXPECTED value the gate re-checks at point of
  # use. Absent, the gate still requires cargo-audit to be present + self-report a version.
  preflight_builder_capability "$sp1_ref"   "$arch" "${CARGO_AUDIT_PIN_VERSION:-}" "${CARGO_AUDIT_EXPECTED_EXE_SHA256:-}"
  preflight_builder_capability "$risc0_ref" "$arch" "${CARGO_AUDIT_PIN_VERSION:-}" "${CARGO_AUDIT_EXPECTED_EXE_SHA256:-}"

  note "== Stage 2: PER-CANDIDATE in-container cargo metadata + audit -> typed record -> work =="
  require_headroom_gib "$work" 5 "Stage 2 in-container cargo metadata + audit"
  produce_stage2 Sp1   "$arch" "$schema_arch" "$work"
  produce_stage2 Risc0 "$arch" "$schema_arch" "$work"
  disk_stage "stage2-audit" "$work"

  note "== Stage 4-5: extract verifier material INSIDE the pinned builder (curated context) -> work =="
  require_headroom_gib "$work" 10 "Stage 4-5 verifier-material extraction"
  # D2 (authoritative x86 r4-followup fix): the standalone material harness has NO
  # committed lock and needs container-only crates, so the former HOST `cargo run
  # --locked` always failed closed. extract_material.sh runs the extraction INSIDE the
  # VERIFIED builder over a curated, minimal, authenticated context (this harness +
  # b0-pre-vmat only), generates+validates the harness lock in-container, consumes it
  # read-only, and binds the material to the builder/context/lock/source identities.
  # sp1 material -> sp1 builder, risc0 material -> risc0 builder (the verified loaded refs).
  SCHEMA_ARCH="$schema_arch" BUILDER_IMAGE_REF="$sp1_ref" \
    BUILDER_IMAGE_DIGEST="$sp1_builder" bash "$HERE/extract_material.sh" sp1 "$work"
  if [ "$arch" = "x86_64" ]; then
    require_native_arch x86_64
    SCHEMA_ARCH="$schema_arch" BUILDER_IMAGE_REF="$risc0_ref" \
      BUILDER_IMAGE_DIGEST="$risc0_builder" bash "$HERE/extract_material.sh" risc0 "$work"
  else
    note "arch=$arch: skipping RISC Zero extraction (x86_64-only per docs/b0-pre/venue/VENUE.md §2)"
  fi

  disk_stage "stage4-verifier-material" "$work"

  note "== Stage 5b: real tool identities (download->verify->install->verify->bind) -> work =="
  # Defect 3: thread the VERIFIED per-candidate builder manifest digests and the ratified
  # source commit into tool_identities.sh, which binds them as each ToolBindingRecord's
  # container_digest / source_commit. sp1_builder / risc0_builder are builder_digest_of()
  # over the two-clean-build-verified container.json (never a synthetic value or a mutable
  # tag), and tool_src_commit is the clean ratified HEAD (== RATIFIED_SOURCE_COMMIT, already
  # asserted in Stage 0). RISC Zero is threaded ONLY on x86_64; aarch64 stays SP1-only
  # (VENUE.md §2), so no RISC Zero identity reaches an aarch64 bundle.
  local tool_src_commit; tool_src_commit="$(git -C "$ROOT" rev-parse HEAD)"
  if [ "$arch" = "x86_64" ]; then
    SP1_BUILDER_DIGEST="$sp1_builder" RISC0_BUILDER_DIGEST="$risc0_builder" \
      SOURCE_COMMIT="$tool_src_commit" bash "$HERE/tool_identities.sh" "$work" "$arch"
  else
    SP1_BUILDER_DIGEST="$sp1_builder" SOURCE_COMMIT="$tool_src_commit" \
      bash "$HERE/tool_identities.sh" "$work" "$arch"
  fi

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
  local cand="$1" arch="$2" schema_arch="$3" work="$4" ref_override="${5:-}"
  local lc; lc="$(printf '%s' "$cand" | tr '[:upper:]' '[:lower:]')"
  # Ref resolution is the CALLER's seam: the authoritative producer passes nothing and the
  # verified AUTHORITATIVE runnable ref is resolved here (byte-for-byte the prior behavior); the
  # separate TEST_ONLY smoke passes its resolve_smoke_runnable_ref image. The record binding below
  # is otherwise IDENTICAL in both modes.
  local ref; ref="${ref_override:-$(runnable_ref_of "$lc" "$arch" "$work")}"  # Defect 2: verified loaded image
  local builder commit lock_hex
  builder="$(builder_digest_of "$lc" "$arch" "$work")"
  commit="$(git -C "$ROOT" rev-parse HEAD)"
  # D1 (authoritative x86 r4 fix): resolve_lock.sh generated the lock in an ephemeral
  # container and exported it to the HOST; that container is gone and the fresh Stage-2
  # container starts from the same (intentionally lock-less) image. Validate the Stage-1
  # resolved lock and take its verified content hash (the identity — the host path is not
  # evidence); it is then bind-mounted READ-ONLY at the workspace Cargo.lock so
  # `cargo metadata/audit --locked` can succeed. Stage 2 never regenerates or updates it.
  local hostlock="$work/$cand.Cargo.lock" prov="$work/$cand.lock-provenance.json"
  lock_hex="$(require_stage1_lock "$hostlock" "$prov" "$cand" "$VAL")"

  local meta="$work/$cand.cargo-metadata.json"
  local advis="$work/$cand.cargo-audit.json"
  local cmdlog="$work/$cand.stage2.cmd.log"
  # The candidate workspace lives at its reproduced repo-relative path in the staged
  # builder image (see stage_context.sh); metadata/audit run there over the full graph.
  local cdir; cdir="$(incontainer_candidate_dir "$lc")"
  local incontainer_lock="$cdir/Cargo.lock"
  # STRICT read-only mounts: the ONLY host paths entering the container are (a) the validated
  # Stage-1 lock, mounted at its logical workspace destination, and (b) the pinned advisory-DB
  # checkout, mounted READ-ONLY at $incontainer_db for `cargo audit --db`. No writable bind, no
  # whole-workspace/source mount. The command log records the lock CONTENT HASH, the logical
  # in-container destinations, the advisory-DB identity, and the EXACT constructed audit argv
  # (never a host absolute path); command_log_blake3_hex binds that — and lock_blake3_hex binds
  # the content address — into the typed Stage-2 record.

  # ---- Pinned advisory-DB checkout (READ-ONLY): resolve + fully verify identity, then bind it.
  # The checkout is a venue-provisioned read-only git checkout of the RustSec advisory-db at the
  # PROPOSED-pinned commit. Its identity (commit + tree + canonical content digest) is verified
  # against the EXPECTED values the venue supplies from the proposed pins — never hardcoded here,
  # never fetched during an authoritative run. Absent provisioning or any mismatch fails closed:
  # a missing or altered advisory DB is NEVER a clean audit.
  local advdb="${ADVISORY_DB_CHECKOUT:-}"
  [ -n "$advdb" ] && [ -d "$advdb" ] \
    || nyr "Stage-2 audit for $cand requires a provisioned READ-ONLY advisory-DB checkout at \$ADVISORY_DB_CHECKOUT (RustSec advisory-db at the proposed-pinned commit)"
  local exp_commit="${ADVISORY_DB_EXPECTED_COMMIT:-}"
  local exp_tree="${ADVISORY_DB_EXPECTED_TREE:-}"
  local exp_content="${ADVISORY_DB_EXPECTED_CONTENT_BLAKE3:-}"
  [ -n "$exp_commit" ] && [ -n "$exp_tree" ] && [ -n "$exp_content" ] \
    || nyr "Stage-2 audit for $cand requires the EXPECTED advisory-DB identity from the proposed pins (\$ADVISORY_DB_EXPECTED_COMMIT / _TREE / _CONTENT_BLAKE3)"
  local advdb_commit advdb_tree advdb_content
  advdb_commit="$(git -C "$advdb" rev-parse HEAD 2>/dev/null || true)"
  [ -n "$advdb_commit" ] || die "advisory-DB checkout $advdb is not a git checkout (cannot resolve HEAD)"
  advdb_tree="$(git -C "$advdb" rev-parse 'HEAD^{tree}' 2>/dev/null || true)"
  [ -n "$advdb_tree" ] || die "advisory-DB checkout $advdb: cannot resolve HEAD tree"
  advdb_content="$(vv checkout-digest "$advdb")" \
    || die "advisory-DB checkout $advdb: cannot compute canonical content digest"
  [ "$advdb_commit" = "$exp_commit" ] \
    || die "advisory-DB commit $advdb_commit != expected pinned $exp_commit"
  [ "$advdb_tree" = "$exp_tree" ] \
    || die "advisory-DB tree $advdb_tree != expected pinned $exp_tree"
  [ "$advdb_content" = "$exp_content" ] \
    || die "advisory-DB canonical content digest $advdb_content != expected pinned $exp_content (the checkout was altered)"

  # ---- Structured, NON-executable audit policy (mirrors AuditPolicy in audit.rs; validate()
  # rejects any record whose policy deviates). TRUSTED CODE below constructs the cargo-audit
  # argv FROM these fields — no operator-supplied command string is ever executed as authority.
  local pol_db_update="false"                   # database_update_allowed  -> --no-fetch
  local pol_stale="true"                        # stale_snapshot_permitted -> --stale
  local pol_format="json"                       # output_format            -> --json
  local pol_dbsource="runtime-read-only-mount"  # database_source          -> --db <ro-mount>
  local incontainer_db="/b0pre/advisory-db"
  local -a audit_argv=(cargo audit --db "$incontainer_db")
  [ "$pol_db_update" = "false" ] && audit_argv+=(--no-fetch) \
    || die "audit policy invariant: database_update_allowed must be false"
  [ "$pol_stale" = "true" ] && audit_argv+=(--stale) \
    || die "audit policy invariant: stale_snapshot_permitted must be true"
  [ "$pol_format" = "json" ] && audit_argv+=(--json) \
    || die "audit policy invariant: output_format must be json"
  [ "$pol_dbsource" = "runtime-read-only-mount" ] \
    || die "audit policy invariant: database_source must be runtime-read-only-mount"

  {
    printf 'run_stage2_locked <verified-image> %s <stage1-lock blake3=%s> %s "cargo metadata --format-version 1 --locked"\n' "$cdir" "$lock_hex" "$incontainer_lock"
    printf 'run_stage2_audit_locked <verified-image> %s <stage1-lock blake3=%s> %s <advisory-db commit=%s content=%s ro-mount=%s> %s\n' \
      "$cdir" "$lock_hex" "$incontainer_lock" "$advdb_commit" "$advdb_content" "$incontainer_db" "${audit_argv[*]}"
  } > "$cmdlog"
  # TOCTOU: the lock must be byte-unchanged between validation and the container reads.
  [ "$(vv lock-hash "$hostlock")" = "$lock_hex" ] \
    || die "Stage-1 lock changed between validation and Stage-2 execution for $cand"
  # Shared production core (lib.sh: run_stage2_locked) — the read-only lock-mount mechanic;
  # the real-container E2E drives the IDENTICAL function.
  run_stage2_locked "$ref" "$cdir" "$hostlock" "$incontainer_lock" \
    "cargo metadata --format-version 1 --locked" "$meta" 2>>"$cmdlog" \
    || die "in-container cargo metadata --locked failed for $cand (Stage-1 lock mount)"
  # Stage-2 audit MUST distinguish "audit EXECUTED" (clean, or found advisories) from
  # "audit could NOT execute" (cargo-audit missing, advisory-DB failure, crash, empty or
  # unparseable output). cargo audit exits 0 (clean) or non-zero (advisories found OR an
  # error), so the exit code alone is ambiguous; the reliable signal is a VALID cargo-audit
  # JSON body. A missing tool (exit 127), an empty body, or an unparseable body is a HARD
  # failure — NEVER silently converted into a clean audit. A genuine advisory finding is
  # preserved as valid JSON and classified (fatal) by `vv stage2-generate` downstream. The
  # audit runs with the advisory-DB mounted READ-ONLY and --no-fetch --stale, so it can never
  # fetch, update, or mutate the pinned database.
  local audit_rc=0
  run_stage2_audit_locked "$ref" "$cdir" "$hostlock" "$incontainer_lock" \
    "$advdb" "$incontainer_db" "$advis" "${audit_argv[@]}" 2>>"$cmdlog" || audit_rc=$?
  [ "$audit_rc" != 127 ] \
    || die "Stage-2 audit could NOT execute for $cand: cargo-audit is not installed in the builder image (exit 127) — a missing tool is never a clean audit"
  [ -s "$advis" ] \
    || die "Stage-2 audit produced NO output for $cand (audit could not execute; not a clean audit)"
  python3 -c 'import json,sys
d=json.load(open(sys.argv[1]))
assert isinstance(d, dict) and "vulnerabilities" in d
' "$advis" 2>/dev/null \
    || die "Stage-2 audit output for $cand is not valid cargo-audit JSON (parse/shape failure; audit could not execute; not a clean audit)"
  # The read-only mounts must not have mutated the host lock (Stage 2 cannot modify it).
  [ "$(vv lock-hash "$hostlock")" = "$lock_hex" ] \
    || die "host Stage-1 lock was modified during Stage 2 for $cand (read-only mount violated)"

  # cargo-audit identity: the EXACT version output (the unusual `cargo-audit-audit <ver>` form
  # is captured verbatim as the bound invocation `cargo audit --version`) + the SHA-256 of the
  # exact executable that ran the scan. Both come from the SAME verified builder image; absence
  # fails closed (never inferred or defaulted). The executable SHA-256 is VENUE EVIDENCE bound
  # into the record — NOT an owner-ratified source pin (the ratified inputs are the crate +
  # version + checksum + packaged-lock checksum + Rust toolchain + build env); it is reproduced
  # by an independent same-arch operator, else the identity is not blessed (PIN-PROPOSAL.md §6).
  local ca_ver ca_sha tool_id
  ca_ver="$(docker run --rm --pull never "$ref" bash -c 'cargo audit --version' 2>/dev/null | head -n1 | sed 's/[[:space:]]*$//' || true)"
  [ -n "$ca_ver" ] \
    || die "Stage-2: could not capture the cargo-audit version (\`cargo audit --version\`) in the builder image for $cand"
  ca_sha="$(docker run --rm --pull never "$ref" bash -c 'p="$(command -v cargo-audit)"; [ -n "$p" ] && sha256sum "$p" | cut -d" " -f1' 2>/dev/null || true)"
  grep -Eq '^[0-9a-f]{64}$' <<<"$ca_sha" \
    || die "Stage-2: could not compute the cargo-audit executable SHA-256 in the builder image for $cand"
  tool_id="$(docker run --rm --pull never "$ref" bash -c 'cargo --version; cargo audit --version' 2>/dev/null | tr '\n' ' ' | sed 's/  */ /g; s/ *$//' || true)"

  local params="$work/$cand.stage2-params.json"
  python3 - "$params" "$cand" "$schema_arch" "$builder" "$lock_hex" "$commit" \
    "${tool_id:-cargo + cargo-audit (in-container)}" "$ca_ver" "$ca_sha" \
    "$advdb_commit" "$advdb_tree" "$advdb_content" \
    "$pol_db_update" "$pol_stale" "$pol_format" "$pol_dbsource" \
    "$STAGE2_ALLOWED_LICENSES" <<'PY'
import json, sys
(path, cand, arch, digest, lock, commit, tool, ca_ver, ca_sha,
 db_commit, db_tree, db_content,
 pol_update, pol_stale, pol_format, pol_dbsource, licenses) = sys.argv[1:18]
json.dump({
    "candidate": cand, "arch": arch, "container_digest": digest,
    "lock_blake3_hex": lock, "source_commit": commit,
    "audit_tool_identity": tool,
    "cargo_audit_version": ca_ver,
    "cargo_audit_executable_sha256": ca_sha,
    "advisory_db": {
        "commit": db_commit, "git_tree": db_tree, "content_blake3": db_content,
    },
    "audit_policy": {
        "database_update_allowed": pol_update == "true",
        "stale_snapshot_permitted": pol_stale == "true",
        "output_format": pol_format,
        "database_source": pol_dbsource,
    },
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
  local cand="$1" arch="$2" schema_arch="$3" work="$4" ref_override="${5:-}"
  local lc; lc="$(printf '%s' "$cand" | tr '[:upper:]' '[:lower:]')"
  # Caller-provided ref seam (see produce_stage2): authoritative resolves the verified ref here;
  # the TEST_ONLY smoke passes its smoke ref. The causal Stage-5 binding is identical in both.
  local ref; ref="${ref_override:-$(runnable_ref_of "$lc" "$arch" "$work")}"  # Defect 2: verified loaded image
  local builder commit
  builder="$(builder_digest_of "$lc" "$arch" "$work")"
  commit="$(git -C "$ROOT" rev-parse HEAD)"
  # S1 correction: Stage 5 is NO LONGER bound to a proof-tool CLI's installed-binary hash
  # (that binary never runs the verifier — the SDK library does). The CAUSAL verifier
  # identity — the exact executed runner binary + its dependency lock + SDK name/version —
  # is emitted by verifier_fixtures.sh into $outdir/verifier-binding.json below.

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
  # The CAUSAL verifier binding (exact executed runner binary sha256 + its dependency lock
  # BLAKE3 + pinned SDK name/version) the harness produced by building, hashing, and
  # executing that exact file directly.
  local vbind="$outdir/verifier-binding.json"
  [ -f "$vbind" ] \
    || die "verifier fixture harness did not emit verifier-binding.json (causal verifier identity) for $cand"
  [ -f "$outdir/runner-cargo.lock" ] \
    || die "verifier fixture harness did not export the runner Cargo.lock (sealed dependency evidence) for $cand"
  # The runner lock is content-addressed with the SAME domain-separated rule as candidate
  # locks (BLAKE3(CARGO_LOCK_TAG ‖ bytes)); import recomputes THIS value from the sealed
  # lock bytes, so bind that — not verifier_fixtures' plain BLAKE3 — into the record.
  local sdk_lock_hex; sdk_lock_hex="$(vv lock-hash "$outdir/runner-cargo.lock")" \
    || die "domain-separated lock-hash of the runner lock failed for $cand"

  local params="$work/$cand.stage5-params.json"
  python3 - "$params" "$cand" "$schema_arch" "$builder" "$commit" "$vbind" "$sdk_lock_hex" <<'PY'
import json, sys
path, cand, arch, digest, commit, vbind, sdk_lock_hex = sys.argv[1:8]
vb = json.load(open(vbind))
for k in ("verifier_executed_binary_sha256", "verifier_sdk_name", "verifier_sdk_version"):
    if not vb.get(k):
        sys.exit(f"verifier-binding.json missing causal field {k!r}")
json.dump({
    "candidate": cand, "arch": arch,
    # Descriptive label ONLY; authority is the hash-backed verifier_* fields below.
    "verifier_identity": f"{vb['verifier_sdk_name']} {vb['verifier_sdk_version']} terminal verifier (descriptive)",
    "verifier_executed_binary_sha256": vb["verifier_executed_binary_sha256"],
    # Domain-separated hash of the SEALED runner lock (import recomputes + matches this).
    "verifier_sdk_lock_blake3": sdk_lock_hex,
    "verifier_sdk_name": vb["verifier_sdk_name"],
    "verifier_sdk_version": vb["verifier_sdk_version"],
    "container_digest": digest, "source_commit": commit,
    # No proof_producer_tool_identity: the upstream prover CLI is NOT causally established
    # on this path (VENUE-UNEXECUTED / externally-suppliable fixture), so no claim is made.
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
  done
  # SP1 binds a tool on both architectures; RISC Zero on x86_64 ONLY, matching
  # `required_files` in the validator (VENUE.md §2).
  cp "$work/Sp1.tool-binding.json"      "$ev/Sp1.tool-binding.json"
  cp "$work/Sp1.stage5-result.json"     "$ev/Sp1.stage5-result.json"
  # Seal the EXACT verifier runner lock so import recomputes its domain-separated hash
  # (== the Stage-5 record's verifier_sdk_lock_blake3) and structurally verifies the
  # pinned SDK. Produced in-container by verifier_fixtures.sh at $work/Sp1.stage5/.
  cp "$work/Sp1.stage5/runner-cargo.lock" "$ev/Sp1.stage5-runner.lock"
  cp "$work/sp1-verifier-material.json" "$ev/sp1-verifier-material.json"
  if [ "$arch" = "x86_64" ]; then
    cp "$work/Risc0.tool-binding.json"      "$ev/Risc0.tool-binding.json"
    cp "$work/Risc0.stage5-result.json"     "$ev/Risc0.stage5-result.json"
    cp "$work/Risc0.stage5/runner-cargo.lock" "$ev/Risc0.stage5-runner.lock"
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

  note "== source-commit authority: both bundles must report the SAME ratified commit =="
  local sc_x86 sc_arm
  sc_x86="$(bundle_recorded_source_commit "$x86")" || die "cannot read x86_64 bundle source_commit (arch-evidence-manifest.json)"
  sc_arm="$(bundle_recorded_source_commit "$arm")" || die "cannot read aarch64 bundle source_commit (arch-evidence-manifest.json)"
  [ "$sc_x86" = "$sc_arm" ] \
    || die "bundle source_commit disagreement: x86_64=$sc_x86 aarch64=$sc_arm (both must be the one ratified commit)"
  if is_dryrun; then
    note "DRY-RUN: bundles agree on synthetic source_commit ($sc_x86); RATIFIED_SOURCE_COMMIT not required for the TEST_ONLY control-flow check"
  else
    [ -n "${RATIFIED_SOURCE_COMMIT:-}" ] \
      || nyr "RATIFIED_SOURCE_COMMIT is required to aggregate authoritative bundles (from the ratified pins.env); it is absent"
    is_ratified_commit_format "$RATIFIED_SOURCE_COMMIT" \
      || die "RATIFIED_SOURCE_COMMIT must be exactly 40 lowercase hex chars: '$RATIFIED_SOURCE_COMMIT'"
    [ "$sc_x86" = "$RATIFIED_SOURCE_COMMIT" ] \
      || die "bundle source_commit ($sc_x86) != RATIFIED_SOURCE_COMMIT ($RATIFIED_SOURCE_COMMIT); refusing aggregation"
  fi

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

# The first-class TEST_ONLY / NON_SELECTION smoke is a SEPARATE public entry point — scripts/
# smoke.sh — NOT a subcommand here. It must NEVER share the authoritative producer's dispatch or
# machinery: it drives the real candidate seams under a DISTINCT smoke source-authority (its own
# SmokeSourceBinding + b0pre-smoke-runnable-ref-v1 sidecar the authoritative resolver rejects),
# emits a real-execution attestation SEPARATE from a synthetic-sealed TEST_ONLY bundle, and can
# never finalize. See smoke.sh + venue::smoke.

# Source-execution guard (shell execution identity, NOT a bypass env var): the
# authoritative dispatch runs ONLY when this file is EXECUTED as a program
# (`bash run_authoritative.sh ...`), where ${BASH_SOURCE[0]} == $0. When another
# script SOURCES this file (e.g. the TEST_ONLY real-container E2E harness reusing
# produce_stage2 / assemble_evidence without the authoritative Stage-0 gate),
# ${BASH_SOURCE[0]} != $0 and NO command is dispatched — sourcing can therefore never
# trigger an authoritative produce/aggregate. There is deliberately no environment
# variable that re-enables dispatch on source, so authoritative execution cannot
# accidentally inherit one.
if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
  cmd="${1:-}"; shift || true
  case "$cmd" in
    produce-arch)  produce_arch "${1:-}" "${2:-}" ;;
    import-verify) import_verify "${1:-}" ;;
    aggregate)     aggregate "${1:-}" "${2:-}" "${3:-}" ;;
    *) die "usage: run_authoritative.sh <produce-arch <arch> <evidence_dir> | import-verify <evidence_dir> | aggregate <x86_dir> <arm_dir> <workdir>> (the TEST_ONLY smoke is a SEPARATE entry point: smoke.sh)" ;;
  esac
fi
