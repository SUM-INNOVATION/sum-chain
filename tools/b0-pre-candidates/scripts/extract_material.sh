#!/usr/bin/env bash
# Extract the immutable verifier material INSIDE the pinned builder image (D2 fix for
# the authoritative x86 r4-followup defect). The standalone material harness
# (harness/<cand>-verifier-material) has NO committed Cargo.lock and depends on
# container-only crates (e.g. sp1-verifier=6.3.1), so the former HOST `cargo run
# --locked` failed closed off the exact toolchain — never producing material on the
# venue either, since the venue runs it host-side too.
#
# The fix runs the extraction inside the VERIFIED builder over a CURATED, MINIMAL,
# AUTHENTICATED context — ONLY this harness + its single `b0-pre-vmat` leaf path-dep,
# nothing else (no live repo, no workspace, no other harness/candidate/guest graph):
#
#   1) stage the curated context at its reproduced repo-relative layout (so the harness's
#      `../../../b0-pre-vmat` path-dep resolves) from a CLEAN source tree;
#   2) generate the harness lock INSIDE the builder (curated context bind-mounted
#      READ-ONLY, copied to writable container scratch so the read-only context is never
#      mutated), export the resulting bytes;
#   3) validate + content-address the exported lock (require_material_lock): reject a
#      host origin, a swapped/cross-harness lock, or any hash mismatch;
#   4) place the validated lock into the curated context and bind-mount the WHOLE context
#      (lock included) READ-ONLY for `cargo run --locked`, with cargo target/output in an
#      ISOLATED writable scratch dir — so the lock is CONSUMED read-only;
#   5) bind the material to (harness, arch, builder digest, staged-context digest, source
#      commit, command log, lock hash) in a work-scratch provenance record, and PROVE the
#      curated context + lock are byte-unchanged after execution.
#
# The material JSON itself is the sealed evidence file (required_files); the identity
# binding above lives in UNSEALED work scratch + the command log (no evidence-schema
# change). Off-venue (no Docker/builder image) this fails closed.
#
# Usage (authoritative): extract_material.sh <sp1|risc0> <out_dir>
# Required env (authoritative): BUILDER_IMAGE_REF, BUILDER_IMAGE_DIGEST (sha256:...),
#                               SCHEMA_ARCH (X86_64|Aarch64).
#
# The core mechanic (extract_material_core) is SOURCEABLE and reusable: the TEST_ONLY
# real-container E2E harness sources this file and drives the IDENTICAL code over a
# lightweight FIXTURE harness, so the harness proves the production seam, not a copy.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
# shellcheck source=lib.sh
. "$HERE/lib.sh"
VAL="$ROOT/../b0-pre-validator/Cargo.toml"

# Reusable, authenticated in-container material-extraction mechanic. Prints the validated
# material lock hash on success; dies fail-closed on any staging/lock/execution defect.
#
# Args:
#   1 label        display label (candidate or fixture id), used for scratch names
#   2 harness_src  host path of the material harness dir (staged as-is)
#   3 harness_rel  reproduced in-container path of the harness under /work
#                  (e.g. tools/b0-pre-candidates/harness/sp1-verifier-material)
#   4 leaf_src     host path of the single b0-pre-vmat leaf (staged at tools/b0-pre-vmat)
#   5 out_json     destination for the extracted material JSON
#   6 builder_ref  the VERIFIED, loaded builder image ref to run inside
#   7 builder_dig  the builder manifest digest (sha256:...) recorded as container_digest
#   8 schema_arch  X86_64|Aarch64
#   9 src_commit   the clean source commit the context is bound to
#  10 work         work-scratch dir (provenance + command log; never sealed)
extract_material_core() {
  local label="$1" harness_src="$2" harness_rel="$3" leaf_src="$4" out_json="$5"
  local builder_ref="$6" builder_dig="$7" schema_arch="$8" src_commit="$9" work="${10}"
  require_cmd docker; require_cmd b3sum; require_cmd python3
  [ -d "$harness_src" ] || die "material harness source dir missing: $harness_src"
  [ -d "$leaf_src" ]    || die "material leaf (b0-pre-vmat) source dir missing: $leaf_src"
  [ -n "$harness_rel" ] || die "in-container harness relpath required"

  # (1) Curated, MINIMAL staged context: ONLY the leaf + this harness, at reproduced
  #     paths. stage_copy_tree prunes target/ and any Cargo.lock (host locks refused).
  local stage="$work/$label.material-ctx"
  rm -rf "$stage"; mkdir -p "$stage"
  stage_copy_tree "$leaf_src"    "$stage/$INCONTAINER_VMAT_RELPATH"
  stage_copy_tree "$harness_src" "$stage/$harness_rel"
  find "$stage" -type f -name Cargo.lock -delete 2>/dev/null || true
  # Refuse an unexpected extra Cargo.toml (only the harness + leaf manifests may exist):
  local manifests; manifests="$(find "$stage" -type f -name Cargo.toml | wc -l | tr -d ' ')"
  [ "$manifests" = "2" ] || die "curated material context has $manifests Cargo.toml (expected exactly 2: harness + leaf)"
  # Content-address the SOURCE context (harness + leaf, pre-lock): the bound identity.
  local ctx_digest; ctx_digest="$(staged_context_blake3 "$stage")"

  local hlock="$work/$label.material.Cargo.lock"
  local gen_cmd="$work/$label.material.generate-lockfile.cmd"
  local gen_log="$work/$label.material.generate-lockfile.log"
  printf 'docker run --rm --pull never -v <curated-ctx blake3=%s>:/ctx:ro %s bash -c "cp -a /ctx /build && cd /build/%s && cargo generate-lockfile" (label=%s)\n' \
    "$ctx_digest" "$builder_dig" "$harness_rel" "$label" > "$gen_cmd"
  # (2) Generate the lock inside the builder. The curated context is bind-mounted
  #     READ-ONLY and copied to a writable container scratch (/build) so nothing in the
  #     read-only context is mutated; the lock is catted out from the writable copy.
  docker run --rm --pull never -v "$stage:/ctx:ro" "$builder_ref" \
    bash -c "cp -a /ctx /build && cd /build/$harness_rel && cargo generate-lockfile && cat Cargo.lock" \
    > "$hlock" 2>"$gen_log" \
    || die "in-container material lock generation failed for $label (no host lock is substituted)"
  [ -s "$hlock" ] || die "material lock export for $label is empty; refusing"

  # (3) Validate + content-address the exported lock (rejects host origin / swap / drift).
  local cmdlog_hex lock_hex prov
  cmdlog_hex="$(blake3_hex_file "$gen_cmd")"
  lock_hex="$(cargo run --quiet --locked --manifest-path "$VAL" --bin venue-verify -- lock-hash "$hlock")" \
    || die "material lock-hash recomputation failed for $hlock"
  prov="$work/$label.material.lock-provenance.json"
  python3 - "$prov" "$label" "$schema_arch" "$builder_dig" "$src_commit" "$cmdlog_hex" "$lock_hex" "$ctx_digest" <<'PY'
import json, sys
path, harness, arch, digest, commit, cmdlog, lockhash, ctx = sys.argv[1:9]
with open(path, "w") as f:
    json.dump({
        "harness": harness,
        "arch": arch,
        "origin": "generated-in-container",
        "container_digest": digest,
        "staged_context_blake3": ctx,
        "source_commit": commit,
        "command_log_blake3_hex": cmdlog,
        "lock_blake3_hex": lockhash,
    }, f, indent=2)
    f.write("\n")
PY
  local validated; validated="$(require_material_lock "$hlock" "$prov" "$label" "$VAL")"
  [ "$validated" = "$lock_hex" ] || die "material lock validation returned $validated != $lock_hex"

  # (4) Place the validated lock into the curated context and RO-mount the WHOLE context
  #     (lock included) for the locked extraction; cargo output goes to isolated writable
  #     scratch (CARGO_TARGET_DIR=/scratch/target). The lock is consumed READ-ONLY.
  cp "$hlock" "$stage/$harness_rel/Cargo.lock"
  # Digest the full context (harness + leaf + lock) to prove it is unchanged by run.
  local full_before; full_before="$(staged_context_blake3 "$stage")"
  local ext_cmd="$work/$label.material.extract.cmd"
  printf 'docker run --rm --pull never -v <curated-ctx+lock blake3=%s>:/work:ro -e CARGO_TARGET_DIR=/scratch/target %s bash -c "cd /work/%s && cargo run --locked" (label=%s, lock blake3=%s)\n' \
    "$full_before" "$builder_dig" "$harness_rel" "$label" "$lock_hex" > "$ext_cmd"
  local ext_log="$work/$label.material.extract.log"
  docker run --rm --pull never -v "$stage:/work:ro" -e CARGO_TARGET_DIR=/scratch/target \
    "$builder_ref" \
    bash -c "cd /work/$harness_rel && cargo run --locked --quiet" \
    > "$out_json" 2>"$ext_log" \
    || die "in-container material extraction (--locked) failed for $label"
  [ -s "$out_json" ] || die "material extraction produced no output for $label"

  # (5) Unchanged proofs: the curated context + lock are byte-identical after the run
  #     (read-only mount honored), and the exported lock still hashes to the bound value.
  local full_after; full_after="$(staged_context_blake3 "$stage")"
  [ "$full_after" = "$full_before" ] \
    || die "curated material context changed during extraction for $label (read-only violated)"
  [ "$(cargo run --quiet --locked --manifest-path "$VAL" --bin venue-verify -- lock-hash "$stage/$harness_rel/Cargo.lock")" = "$lock_hex" ] \
    || die "material lock changed during extraction for $label (read-only violated)"
  # Diagnostics to STDERR so stdout carries ONLY the lock hash (the function's contract),
  # keeping the return value clean when a caller captures it via command substitution.
  printf 'extracted verifier material for %s INSIDE builder (ctx blake3=%s, lock blake3=%s) -> %s\n' \
    "$label" "$ctx_digest" "$lock_hex" "$out_json" >&2
  printf '%s' "$lock_hex"
}

# Authoritative wrapper: real sp1/risc0 harness, gated env, clean-tree binding.
main_extract() {
  local candidate="${1:-}" out="${2:-}" h
  case "$candidate" in sp1|risc0) ;; *) die "candidate must be sp1|risc0 (got '${candidate:-}')" ;; esac
  [ -n "$out" ] || die "output directory argument required"
  mkdir -p "$out"
  h="$(material_harness_subdir "$candidate")"

  if is_dryrun; then
    # Off-venue: no Docker/builder image. The dry-run bundle path never calls this
    # extractor (it uses emit-test-only-bundle); a SYNTHETIC, clearly-labelled placeholder
    # lets a direct off-venue script smoke run without a container. Never sealed.
    printf '{ "note": "TEST_ONLY synthetic %s verifier material (dry-run; not real; never sealed)" }\n' \
      "$candidate" > "$out/${candidate}-verifier-material.json"
    note "wrote SYNTHETIC TEST_ONLY $out/${candidate}-verifier-material.json"
    return 0
  fi

  require_linux_oci_builder
  require_cmd b3sum; require_cmd python3
  [ -n "${BUILDER_IMAGE_REF:-}" ] || nyr "BUILDER_IMAGE_REF (the verified builder image material is extracted inside) is required"
  require_full_sha256_digest BUILDER_IMAGE_DIGEST "${BUILDER_IMAGE_DIGEST:-}"
  reject_placeholder BUILDER_IMAGE_DIGEST "${BUILDER_IMAGE_DIGEST:-}"
  local arch="${SCHEMA_ARCH:-}"
  case "$arch" in X86_64|Aarch64) ;; *) die "SCHEMA_ARCH must be X86_64|Aarch64 (got '${arch:-}')" ;; esac
  [ -z "$(git -C "$ROOT" status --porcelain 2>/dev/null || echo dirty)" ] \
    || die "source tree is not clean; refuse to extract material from a dirty state"
  local src_commit; src_commit="$(git -C "$ROOT" rev-parse HEAD)"

  extract_material_core "$candidate" "$ROOT/harness/$h" "$(incontainer_material_dir "$h")" \
    "$ROOT/../b0-pre-vmat" "$out/${candidate}-verifier-material.json" \
    "$BUILDER_IMAGE_REF" "$BUILDER_IMAGE_DIGEST" "$arch" "$src_commit" "$out"
}

# Source-execution guard (shell execution identity, not a bypass env var): dispatch the
# authoritative extraction ONLY when EXECUTED; when SOURCED (by the E2E harness), define
# extract_material_core without running anything.
if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
  main_extract "${1:-}" "${2:-}"
fi
