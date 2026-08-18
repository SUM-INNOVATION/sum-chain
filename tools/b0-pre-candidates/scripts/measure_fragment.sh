#!/usr/bin/env bash
# B0-FINAL OFFICIAL measurement orchestrator (thin; venue-only). Drives the REAL,
# repo-built binaries for ONE (candidate, arch) fragment — there are NO mock/placeholder
# executables and NO fail-open branches:
#
#   * guest build (SP1)  : the frozen guest ELF is built IN the pinned builder container
#                          (`cargo prove build`). RISC Zero's guest is embedded into the
#                          runner at BUILD time by risc0_build::embed_methods() (B0_VENUE_EMBED),
#                          so there is no separate RISC Zero guest-build step here.
#   * verifier material  : the pinned `{sp1,risc0}-verifier-material` HARNESS bin emits JSON.
#   * provenance         : the `b0-pre-host-provenance` bin READS the real host/cgroup facts.
#   * proving+verify     : the `b0-pre-measure-{sp1,risc0}` runner (built --features real-backend)
#                          proves each cell under the Docker firewall (which records the proving
#                          CONTAINER cgroup peak) and verifies natively; it emits the RawFacts
#                          fragment + a runner attestation binding the production binary hash +
#                          enabled backend identity.
#
# Every referenced binary MUST exist and be executable; every measured value comes from a
# real process. Any missing tool / build / proof / measurement aborts and removes partial
# output. Nothing synthetic is ever substituted.
#
# Usage: measure_fragment.sh <sp1|risc0> <x86_64|aarch64> <out_dir>
# Required env (all repo-built or venue-provisioned; validated below):
#   SPEC_HASH  R0_GUEST_SET_HASH
#   MEASURE_RUNNER  VMAT_BIN  PROV_BIN         # repo-built binaries
#   PROVER_FIREWALL_SH  PROVER_REAL_DOCKER  PROVING_CGROUP
#   BUILDER_DIGEST  CONTAINER_IMAGE_DIGEST  GUEST_SOURCE_TREE_HASH  CANDIDATE_DEP_LOCK_HASH
#   BUILD_COMMAND_HASH  STATEMENT_HASH_TLG  STATEMENT_HASH_ST  RSS_CONTEXT_HASH
#   MALFORMED_CORPUS_RESULT_HASH  HARNESS_SOURCE_HASH  REPO_DIR
#   SP1 only: VERIFIER_REF (pinned builder image the guest ELF builds inside)
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
# shellcheck source=lib.sh
. "$HERE/lib.sh"
# Two-root authority resolver (measured source vs measurement tooling).
# shellcheck source=two_root_authority.sh
. "$HERE/two_root_authority.sh"

CAND="${1:-}"; ARCH="${2:-}"; OUT="${3:-}"
case "$CAND" in sp1|risc0) ;; *) die "candidate must be sp1|risc0 (got '${CAND:-}')" ;; esac
case "$ARCH" in x86_64|aarch64) ;; *) die "arch must be x86_64|aarch64 (got '${ARCH:-}')" ;; esac
[ -n "$OUT" ] || die "output dir argument required"

# Native eligibility FIRST: RISC Zero is x86_64-only; refuse a RISC-Zero-aarch64 fragment
# before any build/prove (the runner also refuses, defence in depth).
[ "$CAND" = risc0 ] && [ "$ARCH" = aarch64 ] && die "RISC Zero is native-ineligible on aarch64; refused (never fabricated)"
require_native_arch "$ARCH"

need_env() { [ -n "${!1:-}" ] || die "required env $1 is unset"; }
# Identities marked (DERIVED) below are NOT accepted from the caller — the producer derives
# them from the actual checkout / lock / build command / image and cross-checks. The
# guest-set hash is consumed from a phase-1 DERIVED file (never a raw operator value).
# TWO-ROOT authority: measured source (source_commit/clean-tree) and reviewed tooling are SEPARATE
# clean checkouts, supplied explicitly. The measurement record's source_commit comes ONLY from the
# measured root; the tooling authority (commit + path-set digest) is bound into the runner attestation
# and is NEVER compared to the measured source.
need_env B0_MEASURED_SOURCE_ROOT
need_env B0_TOOLING_ROOT
require_two_roots --measured-source-root "$B0_MEASURED_SOURCE_ROOT" --tooling-root "$B0_TOOLING_ROOT"
for v in SPEC_HASH MEASURE_RUNNER MEASURE_PRODUCE VMAT_BIN PROV_BIN PROVER_FIREWALL_SH \
         PROVER_REAL_DOCKER PROVING_CGROUP GUEST_SET_MANIFEST IDENTITY_RECORDS OFFICIAL_JSON \
         RSS_CONTEXT_HASH MALFORMED_CORPUS_RESULT_HASH HARNESS_SOURCE_HASH; do need_env "$v"; done
# The runner path-independence recipe facts for THIS fragment's runner (emitted by
# double_build_runner.sh at the reproducible runner-build stage). MANDATORY: the measurement runner's
# ProvFacts requires `runner_recipe`, so a fragment cannot be produced without it. The validator turns
# these facts into the three retained artifacts and recomputes the structural recipe id.
need_env B0_RUNNER_RECIPE_JSON
[ -s "$B0_RUNNER_RECIPE_JSON" ] || die "B0_RUNNER_RECIPE_JSON does not name a non-empty file: $B0_RUNNER_RECIPE_JSON"
# source_commit/clean-tree are read from the MEASURED root (never the tooling checkout HEAD). The
# runner binds B0_TOOLING_COMMIT + B0_TOOLING_PATHSET_BLAKE3 into the per-arch runner attestation.
REPO_DIR="$B0_MEASURED_ROOT"
export B0_TOOLING_COMMIT B0_TOOLING_PATHSET_BLAKE3 B0_MEASURED_COMMIT
[ "$CAND" = sp1 ] && need_env VERIFIER_REF
case "$CAND" in sp1) CANDCAP=Sp1 ;; risc0) CANDCAP=Risc0 ;; esac

MERGED_SPEC="201cfcb80e94a5a7845dc3380cde32171d40f325ae2bacde9547f3c0da3c4df3"
[ "$SPEC_HASH" = "$MERGED_SPEC" ] || die "SPEC_HASH $SPEC_HASH != merged finalized $MERGED_SPEC"
# Frozen ratified computation-statement hashes (== the guest journals). The runner
# INDEPENDENTLY recomputes each from the materialized input and refuses on mismatch, so
# these are cross-checked, not trusted.
STATEMENT_HASH_TLG="36fd69cb75ea6e7c91ce37932aca0158c3d9c8cb9a364bc66c55d27a43372d30"
STATEMENT_HASH_ST="264e8a9339fa7e768e16fbecb38351564a7710472ce66ea2478a9fc6f214192b"
for b in "$MEASURE_RUNNER" "$MEASURE_PRODUCE" "$VMAT_BIN" "$PROV_BIN" "$PROVER_FIREWALL_SH"; do
  [ -x "$b" ] || die "required executable not found/executable: $b"
done
require_cmd b3sum
# #6: the guest build uses the ABSOLUTE, pre-verified Docker binary — never `docker` from PATH.
REAL_DOCKER="$(readlink -f "$PROVER_REAL_DOCKER" 2>/dev/null || echo "$PROVER_REAL_DOCKER")"
case "$REAL_DOCKER" in /*) ;; *) die "PROVER_REAL_DOCKER must be an absolute path: $REAL_DOCKER" ;; esac
[ -x "$REAL_DOCKER" ] || die "PROVER_REAL_DOCKER not executable: $REAL_DOCKER"

b3() { b3sum "$1" | awk '{print $1}'; }
b3_stdin() { b3sum | awk '{print $1}'; }

mkdir -p "$OUT"
SCRATCH="$OUT/_scratch-$CAND-$ARCH"; rm -rf "$SCRATCH"; mkdir -p "$SCRATCH"

# #1/#4/#7: the guest-set hash is DERIVED (phase 1) from the reconciled identity records, never
# operator-supplied. INDEPENDENTLY re-derive it from the identity records, then AUTHENTICATE the
# provided coordination manifest by requiring its FULL bytes to equal the re-derived manifest
# (every field — a forged manifest that copies the manifest_hash cannot pass). Require THIS
# fragment's own (candidate,arch) identity to be present in the records. Then use the derived hash.
_gsver="$SCRATCH/_gsver"; mkdir -p "$_gsver"
"$MEASURE_PRODUCE" --guest-set "$IDENTITY_RECORDS" "$_gsver" >/dev/null 2>&1 \
  || die "guest-set re-derivation from identity records failed (records incomplete/invalid)"
cmp -s "$GUEST_SET_MANIFEST" "$_gsver/coordination-manifest.json" \
  || die "coordination manifest bytes != independently re-derived manifest (forged/altered manifest)"
R0_GUEST_SET_HASH="$(tr -d ' \t\n' < "$_gsver/r0_guest_set_hash.txt")"
printf '%s' "$R0_GUEST_SET_HASH" | grep -Eq '^[0-9a-f]{64}$' || die "re-derived r0_guest_set_hash is malformed"
grep -q "\"candidate\": *\"$CANDCAP\"" "$IDENTITY_RECORDS" && grep -q "\"arch\": *\"$ARCH\"" "$IDENTITY_RECORDS" \
  || die "this fragment's own ($CANDCAP/$ARCH) built identity is absent from the phase-1 records"
FRAG="$OUT/facts-$CAND-$ARCH.json"; ATTEST_OUT="$OUT/attestation-$CAND-$ARCH.json"
FW_ATTEST="$OUT/$CAND.firewall-attestation.jsonl"; : > "$FW_ATTEST"
# Fail-closed cleanup: any error removes the partial fragment + scratch (no partial evidence).
trap 'rm -rf "$SCRATCH"; rm -f "$FRAG" "$ATTEST_OUT"' EXIT

# ---- materialize BOTH official statement inputs (frozen, deterministic; real emit CLI) ----
( cd "$ROOT/guest-core" && cargo run --quiet --example emit_official_guest_input -- \
    --measurement "$SPEC_HASH" "$OFFICIAL_JSON" "$SCRATCH/inputs" ) || die "materialize official inputs failed"
IN_TLG="$SCRATCH/inputs/tlg.guestin.bin"; IN_ST="$SCRATCH/inputs/select.guestin.bin"
[ -s "$IN_TLG" ] && [ -s "$IN_ST" ] || die "materialized statement inputs are empty"

# ---- #7 DERIVE build-provenance identities from the ACTUAL checkout (not caller-supplied) --
GUEST_DIR="$ROOT/candidates/$CAND/guest"
[ -d "$GUEST_DIR" ] || die "candidate guest source tree absent: $GUEST_DIR"
# Deterministic hash of the guest source tree: sorted per-file b3 hashes, hashed together.
GUEST_SOURCE_TREE_HASH="$(cd "$GUEST_DIR" && find . -type f -not -path './target/*' | LC_ALL=C sort \
  | while IFS= read -r f; do b3 "$f"; done | b3_stdin)"
LOCK="$ROOT/candidates/$CAND/Cargo.lock"
[ -s "$LOCK" ] || die "candidate dependency lock absent: $LOCK"
CANDIDATE_DEP_LOCK_HASH="$(b3 "$LOCK")"
# #2/#4: canonical, ARCH-NEUTRAL, deterministic build-RECIPE hash — identical across
# SP1 x86/aarch64 (so reconciliation accepts valid per-arch builds) AND identical between
# phase-1 and measurement (so the #4 exact-identity compare is meaningful). The arch-specific
# builder image stays in builder_container_digest (per-arch), NOT in the recipe.
BUILD_COMMAND_HASH="$(b0_build_recipe_hash "$CAND")" || die "unknown build recipe for $CAND"

# ---- guest build (SP1 only; RISC Zero guest is embedded in the runner) --------------------
GUEST_ELF="$SCRATCH/guest/guest.elf"
if [ "$CAND" = sp1 ]; then
  mkdir -p "$SCRATCH/guest"
  incand="$(incontainer_candidate_dir sp1)"
  # #6: reconcile VERIFIER_REF to an immutable image identity BEFORE building — it must be
  # present locally (pull-never) and expose a content-addressed image Id.
  IMAGE_ID="$("$REAL_DOCKER" image inspect --format '{{.Id}}' "$VERIFIER_REF" 2>/dev/null || true)"
  case "$IMAGE_ID" in sha256:*) ;; *) die "VERIFIER_REF $VERIFIER_REF did not reconcile to an immutable sha256 image id (pull-never); refusing" ;; esac
  "$REAL_DOCKER" run --rm --pull never -v "$SCRATCH:/out" -e CARGO_TARGET_DIR=/tmp/b0pre-guest-target \
    "$VERIFIER_REF" bash -c "cd $incand/guest && cargo prove build --output-directory /out/guest --elf-name guest.elf" \
    || die "in-container SP1 guest ELF build failed (no synthetic ELF is substituted)"
  [ -s "$GUEST_ELF" ] || die "SP1 guest ELF not produced at $GUEST_ELF"
  CONTAINER_IMAGE_DIGEST="${IMAGE_ID#sha256:}"
  BUILDER_DIGEST="$CONTAINER_IMAGE_DIGEST"
  # #3: toolchain identity bound to the ratified pinned builder image (not a label).
  TOOLCHAIN_IDENTITY="$(b0_toolchain_identity sp1 "$IMAGE_ID")"
else
  # In the MEASUREMENT/proving path RISC Zero uses no builder container: the guest is embedded via
  # embed_methods at runner BUILD time with the pinned LOCAL r0 toolchain, so the toolchain
  # AUTHORITY derives from the provisioned local RISC0 toolchain tree (below) and the container
  # identity here is the runner binary's own hash. NOTE: a native x86 RISC0 builder container IS
  # still required for authoritative LOCK generation and build stages (resolve_lock.sh /
  # build_container.sh) — only this measurement/embed path is builder-container-free. RISC0
  # aarch64 proving/material remains ineligible and absent.
  CONTAINER_IMAGE_DIGEST="$(b3 "$MEASURE_RUNNER")"
  BUILDER_DIGEST="$CONTAINER_IMAGE_DIGEST"
  # #3: toolchain identity = the pinned local r0 toolchain tree (PROVER_RISC0_HOME).
  need_env PROVER_RISC0_HOME
  TOOLCHAIN_IDENTITY="$(b0_toolchain_identity risc0 "$PROVER_RISC0_HOME")" || die "RISC0 toolchain identity derivation failed"
fi
# #2: the derived toolchain identity MUST equal the RATIFIED value sourced from the
# hash-verified content-addressed toolchain-authority record (never an operator env). A
# wrong-but-consistent toolchain is refused even if phase 1 and measurement agree.
: "${TOOLCHAIN_AUTHORITY_RECORD:=$ROOT/../../docs/b0-pre/venue/toolchain-authority.v1.json}"
RATIFIED_TC="$(b0_ratified_toolchain_identity "$CANDCAP" "$ARCH" "$TOOLCHAIN_AUTHORITY_RECORD")" \
  || die "ratified toolchain authority record unavailable/invalid (hash-verify or entry lookup failed)"
[ "$TOOLCHAIN_IDENTITY" = "$RATIFIED_TC" ] \
  || die "toolchain identity $TOOLCHAIN_IDENTITY != ratified $RATIFIED_TC (wrong/unratified toolchain)"

# ---- verifier material (the pinned harness bin; JSON manifest) -----------------------------
VMAT_JSON="$SCRATCH/verifier-material.json"
"$VMAT_BIN" > "$VMAT_JSON" || die "verifier-material harness failed"
[ -s "$VMAT_JSON" ] || die "verifier-material harness produced no output"

# ---- provenance: READ the real host/cgroup facts for Proving + Verification ----------------
PROV_JSON="$SCRATCH/provenance.json"
prov_role() {
  "$PROV_BIN" "$ARCH" "$1" --repo "$REPO_DIR" --builder-digest "$BUILDER_DIGEST" \
    --harness-source-hash "$HARNESS_SOURCE_HASH" \
    || die "provenance read failed for role $1"
}
{ printf '['; prov_role Proving; printf ','; prov_role Verification; printf ']'; } > "$PROV_JSON"
# Splice the runner path-independence recipe facts into EACH provenance role (both roles ran on the
# same reproducible runner binary → the same recipe). The measurement runner re-emits provenance
# verbatim into the fragment, so this is the injection point; its ProvFacts requires runner_recipe.
python3 - "$PROV_JSON" "$B0_RUNNER_RECIPE_JSON" <<'PY' || die "failed to splice runner_recipe into provenance"
import json, sys
prov_path, recipe_path = sys.argv[1], sys.argv[2]
recipe = json.load(open(recipe_path, encoding="utf-8"))
required = {"candidate", "arch", "manifest_path", "artifact_path", "cargo_ident", "b0_venue_embed",
           "canonical_build_path", "per_arch_toolchain_identity", "wrapper_blake3", "build_argv",
           "build_env", "build_a", "build_b", "byte_equal", "leakage_refused_prefixes",
           "leakage_permitted_prefixes", "leakage_clean", "evidence_root"}
missing = required - set(recipe)
if missing:
    sys.exit(f"runner_recipe facts missing keys: {sorted(missing)}")
side_required = {"original_root", "cargo_from", "target_from", "encoded_rustflags_hex",
                "runner_sha256", "runner_blake3", "guest_image_id", "guest_methods_blake3",
                "origin_manifest_blake3", "materialized_manifest_blake3",
                "start_unix", "end_unix", "invocations"}
for which in ("build_a", "build_b"):
    sm = side_required - set(recipe[which])
    if sm:
        sys.exit(f"runner_recipe {which} missing keys: {sorted(sm)}")
prov = json.load(open(prov_path, encoding="utf-8"))
if not isinstance(prov, list) or not prov:
    sys.exit("provenance JSON is not a non-empty array")
for entry in prov:
    entry["runner_recipe"] = recipe
json.dump(prov, open(prov_path, "w", encoding="utf-8"), indent=2)
PY

# ---- #4: bind the MEASUREMENT build to the PHASE-1 identity (exact equality) ----------------
# Re-derive THIS build's identity via --emit-identity and require it to EXACTLY match the
# phase-1 record for (candidate, arch): program/image id, guest image hash, source-tree, lock,
# build recipe, builder, toolchain, VMAT manifest, commit, spec, real markers. Stop before
# proving on any difference (a different guest between phase 1 and measurement is refused).
require_cmd python3
SRC_COMMIT="$(grep -o '"source_commit": *"[0-9a-f]\{40\}"' "$PROV_JSON" | head -1 | grep -o '[0-9a-f]\{40\}')"
[ -n "$SRC_COMMIT" ] || die "could not read source commit for identity binding"
_dirty="$(grep -o '"dirty_tree_flag": *\(true\|false\)' "$PROV_JSON" | head -1 | grep -o 'true\|false')"
CLEAN=true; [ "$_dirty" = true ] && CLEAN=false
MEAS_REC="$SCRATCH/measurement-identity.json"
_idargs=( --emit-identity --arch "$ARCH" --spec-hash "$SPEC_HASH"
  --guest-source-tree-hash "$GUEST_SOURCE_TREE_HASH" --candidate-dep-lock-hash "$CANDIDATE_DEP_LOCK_HASH"
  --build-command-hash "$BUILD_COMMAND_HASH" --builder-digest "$BUILDER_DIGEST"
  --toolchain-identity "$TOOLCHAIN_IDENTITY" --source-commit "$SRC_COMMIT" --clean-tree "$CLEAN"
  --verifier-material "$VMAT_JSON" )
[ "$CAND" = sp1 ] && _idargs+=(--guest-elf "$GUEST_ELF")
"$MEASURE_RUNNER" "${_idargs[@]}" > "$MEAS_REC" || die "measurement-build identity emission failed"
python3 - "$MEAS_REC" "$IDENTITY_RECORDS" "$CANDCAP" "$ARCH" <<'PY' || die "measurement-build identity != phase-1 identity; refusing to prove"
import json, sys
meas = json.load(open(sys.argv[1]))
recs = json.load(open(sys.argv[2]))
cand, arch = sys.argv[3], sys.argv[4]
p1 = [r for r in recs if r.get("candidate") == cand and r.get("arch") == arch]
if len(p1) != 1:
    sys.exit("no unique phase-1 identity record for this fragment")
p1 = p1[0]
for f in ["program_id", "guest_image_hash", "guest_source_tree_hash", "candidate_dep_lock_hash",
          "build_command_hash", "builder_container_digest", "toolchain_identity",
          "verifier_material_manifest_hash", "source_commit", "real_backend",
          "real_guest_embedded", "b0_pre_spec_hash"]:
    if meas.get(f) != p1.get(f):
        sys.exit(f"{f} differs: measurement {meas.get(f)!r} != phase-1 {p1.get(f)!r}")
PY

# ---- proving environment: firewall on PATH + dedicated proving cgroup ----------------------
FWDIR="$SCRATCH/_fw"; mkdir -p "$FWDIR"
cp "$PROVER_FIREWALL_SH" "$FWDIR/docker"; chmod 0755 "$FWDIR/docker"
REAL_DOCKER="$(readlink -f "$PROVER_REAL_DOCKER" 2>/dev/null || echo "$PROVER_REAL_DOCKER")"
[ -x "$REAL_DOCKER" ] || die "PROVER_REAL_DOCKER not executable: $REAL_DOCKER"
[ "$(readlink -f "$FWDIR/docker")" != "$REAL_DOCKER" ] || die "firewall recursion: installed docker resolves to the real docker"
PROOF_DIR="$SCRATCH/_proof"; mkdir -p "$PROOF_DIR"

# ---- run the REAL measurement runner UNDER the firewall (proves + verifies + emits) --------
RUNNER_ARGS=(
  --arch "$ARCH" --spec-hash "$SPEC_HASH" --guest-set-hash "$R0_GUEST_SET_HASH"
  --input-tlg "$IN_TLG" --input-st "$IN_ST" --verifier-material "$VMAT_JSON"
  --provenance "$PROV_JSON" --container-image-digest "$CONTAINER_IMAGE_DIGEST"
  --identity-records "$IDENTITY_RECORDS"
  --statement-hash-tlg "$STATEMENT_HASH_TLG" --statement-hash-st "$STATEMENT_HASH_ST"
  --rss-context-hash "$RSS_CONTEXT_HASH" --malformed-corpus-result-hash "$MALFORMED_CORPUS_RESULT_HASH"
  --guest-source-tree-hash "$GUEST_SOURCE_TREE_HASH" --candidate-dep-lock-hash "$CANDIDATE_DEP_LOCK_HASH"
  --build-command-hash "$BUILD_COMMAND_HASH" --builder-digest "$BUILDER_DIGEST"
  --firewall-attest "$FW_ATTEST" --work-dir "$SCRATCH" --out "$FRAG" --attest-out "$ATTEST_OUT"
)
[ "$CAND" = sp1 ] && RUNNER_ARGS+=(--guest-elf "$GUEST_ELF")

env PATH="$FWDIR:$PATH" \
  B0PRE_REAL_DOCKER="$REAL_DOCKER" B0PRE_FIREWALL_ATTEST="$FW_ATTEST" \
  B0PRE_PROOF_DIR="$PROOF_DIR" B0PRE_CONTENT_STORE="${PROVER_SP1_CONTENT_STORE:-$SCRATCH/_nostore}" \
  B0PRE_PROVING_CGROUP="$PROVING_CGROUP" \
  "$MEASURE_RUNNER" "${RUNNER_ARGS[@]}" \
  || die "measurement runner failed closed (build/prove/verify/measure/bind did not complete)"

[ -s "$FRAG" ] || die "runner did not emit a fragment"
[ -s "$ATTEST_OUT" ] || die "runner did not emit a runner attestation"
[ -s "$FW_ATTEST" ] || die "firewall recorded no execution attestation; refusing"

# Success: keep the fragment + attestations; drop only the scratch.
trap - EXIT
rm -rf "$SCRATCH"
note "wrote fragment $FRAG (+ runner attestation $ATTEST_OUT, firewall attestation $FW_ATTEST)"
