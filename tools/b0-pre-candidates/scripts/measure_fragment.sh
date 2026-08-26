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
#   BUILD_COMMAND_HASH  STATEMENT_HASH_TLG  STATEMENT_HASH_ST
#   REPO_DIR
# (RSS context is derived per-cell from the authenticated statement; the benchmark-harness source
#  hash is COMPUTED by the provenance reader from the clean tooling root — neither is operator-supplied.)
#   B0_MEASUREMENT_AUTHORITY_PKG  # sealed measurement-input authority package (produce_measurement_input_authority.sh):
#                                 # measurement-input-authority.v1.json + malformed-corpus-report.v1.json + harness-source-inventory.txt.
#                                 # Verified fail-fast before proving; its bytes are embedded byte-identical into every fragment.
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

# Native terminal-MEASUREMENT eligibility FIRST — refuse an ineligible (candidate,arch) BEFORE any
# build/prove (the runner refuses too; defence in depth). The two-cell model: only SP1/x86_64 and
# RISC0/x86_64 are natively terminal-measurable. Explicitly unsupported (ratified fail-closed):
#   * RISC0/aarch64            — RISC Zero Groth16 receipt path is x86_64-only (VENUE §2).
#   * SP1/aarch64 terminal Groth16 — no first-party linux/arm64 gnark backend exists (sp1-gnark is
#     amd64-only; the stark2snark wrap `docker run`s that image), so it cannot run natively on aarch64.
# Governing authority: the retained EligibilityMatrixV1 (bound into the MIA) + arm-sp1-stage5
# no-arm-gnark-evidence (CONFIRMED). NEVER emulate/QEMU, NEVER a remote/network prover, NEVER
# native-gnark, NEVER a fabricated aarch64 proof. The SP1/aarch64 *identity* is Phase-1 eligible and
# stays in the guest set, but it is NEVER a measurement or proof.
[ "$CAND" = risc0 ] && [ "$ARCH" = aarch64 ] && die "RISC0/aarch64 is native-ineligible for terminal measurement; refused before proving (ratified unsupported: risc0-aarch64-x86-only; never fabricated)"
[ "$CAND" = sp1 ]   && [ "$ARCH" = aarch64 ] && die "SP1/aarch64 terminal Groth16 is native-ineligible (no arm64 gnark backend); refused before proving (ratified unsupported: sp1-aarch64-groth16-no-arm-backend; never emulated/network/native-gnark/fabricated)"
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
         PROVER_REAL_DOCKER PROVING_CGROUP GUEST_SET_MANIFEST IDENTITY_RECORDS OFFICIAL_JSON; do need_env "$v"; done
# The runner path-independence recipe facts for THIS fragment's runner (emitted by
# double_build_runner.sh at the reproducible runner-build stage). MANDATORY: the measurement runner's
# ProvFacts requires `runner_recipe`, so a fragment cannot be produced without it. The validator turns
# these facts into the three retained artifacts and recomputes the structural recipe id.
need_env B0_RUNNER_RECIPE_JSON
[ -s "$B0_RUNNER_RECIPE_JSON" ] || die "B0_RUNNER_RECIPE_JSON does not name a non-empty file: $B0_RUNNER_RECIPE_JSON"
# The AUTHENTICATED per-candidate dependency-seed JSON — the SAME file double_build_runner.sh consumed as
# --dep-seed-json at the reproducible runner-build stage (its host-cargo-home unit is what /b0/cargo was
# fail-hard materialized against). Embedded byte-identically into this fragment (verified below against
# the recipe's dependency_seed.json_sha256), sealed into the VEC7 package, and re-authenticated by the
# sealed-import cargo dependency-seed anchor. A fragment cannot be produced without it.
need_env B0_DEP_SEED_JSON
[ -s "$B0_DEP_SEED_JSON" ] || die "B0_DEP_SEED_JSON does not name a non-empty file: $B0_DEP_SEED_JSON"
# The ONE sealed measurement-input authority package (produced pre-grid by
# produce_measurement_input_authority.sh): the unified MeasurementInputAuthorityV1 JSON + the retained
# malformed-corpus report + the harness-source inventory manifest. Every fragment carries these three
# byte-identical, and merge_fragments refuses any disagreement. The retained BYTES travel — never a
# standalone operator address string.
need_env B0_MEASUREMENT_AUTHORITY_PKG
[ -d "$B0_MEASUREMENT_AUTHORITY_PKG" ] || die "measurement-input authority package absent: $B0_MEASUREMENT_AUTHORITY_PKG"
MIA_JSON="$B0_MEASUREMENT_AUTHORITY_PKG/measurement-input-authority.v1.json"
REPORT_JSON="$B0_MEASUREMENT_AUTHORITY_PKG/malformed-corpus-report.v1.json"
INVENTORY_TXT="$B0_MEASUREMENT_AUTHORITY_PKG/harness-source-inventory.txt"
ELIG_JSON="$B0_MEASUREMENT_AUTHORITY_PKG/eligibility-matrix.v1.json"
for f in "$MIA_JSON" "$REPORT_JSON" "$INVENTORY_TXT" "$ELIG_JSON"; do
  [ -s "$f" ] || die "measurement-input authority package missing/empty member: $f"
done
# source_commit/clean-tree are read from the MEASURED root (never the tooling checkout HEAD). The
# runner binds B0_TOOLING_COMMIT + B0_TOOLING_PATHSET_BLAKE3 into the per-arch runner attestation.
REPO_DIR="$B0_MEASURED_ROOT"
export B0_TOOLING_COMMIT B0_TOOLING_PATHSET_BLAKE3 B0_MEASURED_COMMIT
[ "$CAND" = sp1 ] && need_env VERIFIER_REF
case "$CAND" in sp1) CANDCAP=Sp1 ;; risc0) CANDCAP=Risc0 ;; esac

MERGED_SPEC="e933e7325c2639a48d8e25f20746d0f8abc822dee9fcfa87c2e6cdec226cf2a2"
[ "$SPEC_HASH" = "$MERGED_SPEC" ] || die "SPEC_HASH $SPEC_HASH != merged finalized $MERGED_SPEC"
# Frozen ratified computation-statement hashes (== the guest journals). The runner
# INDEPENDENTLY recomputes each from the materialized input and refuses on mismatch, so
# these are cross-checked, not trusted.
STATEMENT_HASH_TLG="cd27d48ce81a0211539ac7685fa9548457779ccf769e5731d92bdf706635de86"
STATEMENT_HASH_ST="26574240d194c1d4a28505559c51e5381e057ee4c559edd53abea8c257db0749"
for b in "$MEASURE_RUNNER" "$MEASURE_PRODUCE" "$VMAT_BIN" "$PROV_BIN" "$PROVER_FIREWALL_SH"; do
  [ -x "$b" ] || die "required executable not found/executable: $b"
done
require_cmd b3sum

# ---- FAIL-FAST PRE-GRID GATE: the measurement-input authority must decode + cross-bind + tie its
# tooling identity to RATIFIED before ANY proving cell starts. This refuses a stale authority package
# (one whose tooling commit/path-set does not equal the ratified measurement tooling) so a valid old
# MIA cannot be reused after subsequent source edits. Runs before the guest build / prove of THIS
# fragment; measure-produce recomputes the address from the retained bytes (no operator address string).
# TEST_ONLY preflight (B0PRE_TESTONLY_PREFLIGHT=1): used ONLY by the CI smoke that drives THIS
# pre-proving path without a ratified MIA or a prover. It skips ONLY this MIA fail-fast gate (which has
# its own dedicated --verify-authority + sentinel-refusal tests) and, below, EXITS before any
# materialize/build/prove — so it can never emit a fragment or launch a proving runner (it cannot
# fabricate a measurement). NEVER set in production; unset, the production path runs the gate as before.
B0PRE_TESTONLY_PREFLIGHT="${B0PRE_TESTONLY_PREFLIGHT:-0}"
if [ "$B0PRE_TESTONLY_PREFLIGHT" = 1 ]; then
  note "TEST_ONLY preflight: SKIPPING the MIA fail-fast gate (covered by dedicated tests); will exit before proving"
else
  "$MEASURE_PRODUCE" --verify-authority "$MIA_JSON" "$REPORT_JSON" "$INVENTORY_TXT" "$ELIG_JSON" >&2 \
    || die "measurement-input authority failed the pre-grid fail-fast gate (decode/cross-bind/tooling-ratified); refusing to prove"
fi
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
# The ONE shared canonical SP1 guest artifact package is MANDATORY for EVERY cell (SP1 AND RISC0): the
# v8 `--guest-set` re-derivation re-decodes it from its retained bytes and requires every SP1 identity
# record to reference exactly it. Require + verify it HERE — before ANY candidate-specific proving work —
# and bind its address to the phase-1 records, so a missing / wrong / mutated / superseded / substituted
# package is refused BEFORE proving (defence beyond the manifest cmp below and beyond the SP1 ELF consume).
need_env CANONICAL_SP1_GUEST_PKG
[ -d "$CANONICAL_SP1_GUEST_PKG" ] || die "canonical SP1 guest package absent: $CANONICAL_SP1_GUEST_PKG"
bash "$ROOT/scripts/produce_canonical_sp1_guest.sh" verify "$CANONICAL_SP1_GUEST_PKG" >&2 \
  || die "canonical SP1 guest package failed independent verification (mutated/superseded); refusing before proving"
_CANON_ADDR="$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["address"])' "$CANONICAL_SP1_GUEST_PKG/canonical-sp1-guest-artifact.v1.json")" \
  || die "cannot read canonical SP1 guest artifact address"
printf '%s' "$_CANON_ADDR" | grep -Eq '^[0-9a-f]{64}$' || die "canonical SP1 guest artifact address malformed: '$_CANON_ADDR'"
python3 - "$IDENTITY_RECORDS" "$_CANON_ADDR" <<'PY' || die "canonical artifact address not referenced by all SP1 records (wrong/substituted package); refusing before proving"
import json, sys
recs = json.load(open(sys.argv[1], encoding="utf-8")); want = sys.argv[2]
if not isinstance(recs, list) or not recs:
    sys.exit("identity records is not a non-empty JSON array")
sp1 = [r for r in recs if r.get("candidate") == "Sp1"]
if not sp1:
    sys.exit("no SP1 identity records present")
for r in sp1:
    if r.get("canonical_sp1_guest_artifact_address") != want:
        sys.exit("an SP1 record's canonical_sp1_guest_artifact_address != the supplied canonical package address")
PY
_gsver="$SCRATCH/_gsver"; mkdir -p "$_gsver"
# v8 CLI contract: --guest-set <identity-records> <out-dir> <canonical-sp1-guest-package-dir>. The canonical
# package is the MANDATORY 3rd argument for EVERY cell (each cell re-derives the COMPLETE shared set, which
# includes the ONE shared SP1 guest — RISC0/x86 included).
"$MEASURE_PRODUCE" --guest-set "$IDENTITY_RECORDS" "$_gsver" "$CANONICAL_SP1_GUEST_PKG" >/dev/null 2>&1 \
  || die "guest-set re-derivation from identity records + canonical guest package failed (records/package incomplete/invalid)"
cmp -s "$GUEST_SET_MANIFEST" "$_gsver/coordination-manifest.json" \
  || die "coordination manifest bytes != independently re-derived manifest (forged/altered manifest)"
R0_GUEST_SET_HASH="$(tr -d ' \t\n' < "$_gsver/r0_guest_set_hash.txt")"
printf '%s' "$R0_GUEST_SET_HASH" | grep -Eq '^[0-9a-f]{64}$' || die "re-derived r0_guest_set_hash is malformed"
grep -q "\"candidate\": *\"$CANDCAP\"" "$IDENTITY_RECORDS" && grep -q "\"arch\": *\"$ARCH\"" "$IDENTITY_RECORDS" \
  || die "this fragment's own ($CANDCAP/$ARCH) built identity is absent from the phase-1 records"
# TEST_ONLY preflight exit: every pre-proving guest-set / canonical-package / manifest / identity gate has
# PASSED. Stop HERE — before materialize inputs, guest build, provenance, and the proving runner — so the CI
# smoke can assert the pre-proving path with NO proving runner launched and NO fragment emitted.
if [ "$B0PRE_TESTONLY_PREFLIGHT" = 1 ]; then
  echo "MEASURE_FRAGMENT_PREFLIGHT_OK candidate=$CAND arch=$ARCH r0_guest_set_hash=$R0_GUEST_SET_HASH"
  exit 0
fi
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
CANONICAL_SP1_GUEST_ARTIFACT_ADDRESS=""
if [ "$CAND" = sp1 ]; then
  mkdir -p "$SCRATCH/guest"
  # CONSUME the ONE canonical SP1 guest artifact — NEVER rebuild. Every proving arch measures the
  # SAME program by using the exact x86-authoritative ELF bytes; there is no local cargo prove build
  # fallback. A missing/invalid package refuses (never a synthetic or locally-rebuilt ELF).
  need_env CANONICAL_SP1_GUEST_PKG
  [ -d "$CANONICAL_SP1_GUEST_PKG" ] || die "canonical SP1 guest package absent: $CANONICAL_SP1_GUEST_PKG"
  bash "$ROOT/scripts/produce_canonical_sp1_guest.sh" verify "$CANONICAL_SP1_GUEST_PKG" >&2 \
    || die "canonical SP1 guest package failed independent verification; refusing"
  [ -s "$CANONICAL_SP1_GUEST_PKG/guest.elf" ] || die "canonical SP1 guest package ELF absent"
  cp "$CANONICAL_SP1_GUEST_PKG/guest.elf" "$GUEST_ELF"
  CANONICAL_SP1_GUEST_ARTIFACT_ADDRESS="$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["address"])' "$CANONICAL_SP1_GUEST_PKG/canonical-sp1-guest-artifact.v1.json")"
  # #6: builder/toolchain identify THIS proving venue's ratified image (proving runs inside it); the
  # SHARED guest is bound by the canonical artifact address above, not by a local build.
  IMAGE_ID="$("$REAL_DOCKER" image inspect --format '{{.Id}}' "$VERIFIER_REF" 2>/dev/null || true)"
  case "$IMAGE_ID" in sha256:*) ;; *) die "VERIFIER_REF $VERIFIER_REF did not reconcile to an immutable sha256 image id (pull-never); refusing" ;; esac
  [ -s "$GUEST_ELF" ] || die "SP1 guest ELF not present at $GUEST_ELF"
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
    --tooling-root "$B0_TOOLING_ROOT" \
    || die "provenance read failed for role $1"
}
{ printf '['; prov_role Proving; printf ','; prov_role Verification; printf ']'; } > "$PROV_JSON"
# Splice the runner path-independence recipe facts into EACH provenance role (both roles ran on the
# same reproducible runner binary → the same recipe). The measurement runner re-emits provenance
# verbatim into the fragment, so this is the injection point; its ProvFacts requires runner_recipe.
python3 - "$PROV_JSON" "$B0_RUNNER_RECIPE_JSON" "$CANONICAL_SP1_GUEST_ARTIFACT_ADDRESS" <<'PY' || die "failed to splice runner_recipe into provenance"
import json, sys
prov_path, recipe_path, canon_addr = sys.argv[1], sys.argv[2], sys.argv[3]
recipe = json.load(open(recipe_path, encoding="utf-8"))
# v8: SP1 measurement CONSUMED the ONE canonical guest artifact — bind its SHA-256 address into the
# runner_recipe (which becomes the RunnerAttestation's canonical_sp1_guest_artifact_address). RISC0
# leaves this empty (it embeds its own locked native guest).
if canon_addr:
    recipe["canonical_sp1_guest_artifact"] = {"address": canon_addr}
required = {"candidate", "arch", "manifest_path", "artifact_path", "cargo_ident", "b0_venue_embed",
           "canonical_build_path", "canonical_cargo_home", "per_arch_toolchain_identity",
           "wrapper_blake3", "build_argv", "build_env", "build_a", "build_b", "byte_equal",
           "cargo_seed", "leakage_refused_prefixes",
           "leakage_permitted_prefixes", "leakage_clean", "evidence_root"}
missing = required - set(recipe)
if missing:
    sys.exit(f"runner_recipe facts missing keys: {sorted(missing)}")
# The compiler-visible cargo home is the literal canonical /b0/cargo (fresh per build, NOT remapped), so
# each side has NO per-build cargo_from; the fresh-per-build seed equality lives in the top-level cargo_seed.
seed_required = {"origin_address", "materialized_a", "materialized_b"}
sm = seed_required - set(recipe["cargo_seed"])
if sm:
    sys.exit(f"runner_recipe cargo_seed missing keys: {sorted(sm)}")
side_required = {"original_root", "target_from", "encoded_rustflags_hex",
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

# ---- AUTHORITY/SEED verification GATE — BEFORE proving --------------------------------------
# Fail-fast so the expensive measurement proving NEVER runs against an unauthenticated or mismatched
# dependency seed: the dep-seed the runner recipe authenticated must be byte-identical here (its sha256 ==
# the recipe facts' dependency_seed.json_sha256) and candidate-matching. (The identical bytes are embedded
# into the fragment after proving, sealed into VEC7, and re-authenticated by the sealed-import anchor.)
python3 - "$B0_DEP_SEED_JSON" "$B0_RUNNER_RECIPE_JSON" "$CAND" <<'PY' || die "dependency-seed verification gate failed (pre-proving)"
import json, sys, hashlib
dep_path, recipe_path, cand = sys.argv[1], sys.argv[2], sys.argv[3]
dep_bytes = open(dep_path, "rb").read()
recipe = json.load(open(recipe_path, encoding="utf-8"))
want = recipe.get("dependency_seed", {}).get("json_sha256", "")
got = hashlib.sha256(dep_bytes).hexdigest()
if not want or got != want:
    sys.exit(f"dep-seed sha256 {got} != recipe dependency_seed.json_sha256 {want!r}")
dep = json.loads(dep_bytes)
if dep.get("candidate") != cand:
    sys.exit(f"dep-seed candidate {dep.get('candidate')!r} != fragment candidate {cand!r}")
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
  --guest-source-tree-hash "$GUEST_SOURCE_TREE_HASH" --candidate-dep-lock-hash "$CANDIDATE_DEP_LOCK_HASH"
  --build-command-hash "$BUILD_COMMAND_HASH" --builder-digest "$BUILDER_DIGEST"
  --firewall-attest "$FW_ATTEST" --work-dir "$SCRATCH" --out "$FRAG" --attest-out "$ATTEST_OUT"
)
[ "$CAND" = sp1 ] && RUNNER_ARGS+=(--guest-elf "$GUEST_ELF" \
  --canonical-sp1-guest-artifact "$CANONICAL_SP1_GUEST_PKG/canonical-sp1-guest-artifact.v1.json")

env PATH="$FWDIR:$PATH" \
  B0PRE_REAL_DOCKER="$REAL_DOCKER" B0PRE_FIREWALL_ATTEST="$FW_ATTEST" \
  B0PRE_PROOF_DIR="$PROOF_DIR" B0PRE_CONTENT_STORE="${PROVER_SP1_CONTENT_STORE:-$SCRATCH/_nostore}" \
  B0PRE_PROVING_CGROUP="$PROVING_CGROUP" \
  "$MEASURE_RUNNER" "${RUNNER_ARGS[@]}" \
  || die "measurement runner failed closed (build/prove/verify/measure/bind did not complete)"

[ -s "$FRAG" ] || die "runner did not emit a fragment"
[ -s "$ATTEST_OUT" ] || die "runner did not emit a runner attestation"
[ -s "$FW_ATTEST" ] || die "firewall recorded no execution attestation; refusing"

# Embed the retained authority BYTES into this fragment as top-level string members. Every fragment
# carries byte-identical measurement_input_authority / malformed_corpus_report / harness_source_inventory
# / eligibility_matrix; merge_fragments agrees them byte-for-byte and refuses any disagreement, and
# produce() re-verifies the MIA (incl. the eligibility-matrix address it binds), derives the
# malformed-corpus result hash from the retained report, and cross-checks the two-cell eligibility model.
python3 - "$FRAG" "$MIA_JSON" "$REPORT_JSON" "$INVENTORY_TXT" "$ELIG_JSON" <<'PY' || die "failed to embed measurement-input authority bytes into the fragment"
import json, sys
frag_path, mia, report, inv, elig = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5]
frag = json.load(open(frag_path, encoding="utf-8"))
frag["measurement_input_authority"] = open(mia, encoding="utf-8").read()
frag["malformed_corpus_report"] = open(report, encoding="utf-8").read()
frag["harness_source_inventory"] = open(inv, encoding="utf-8").read()
frag["eligibility_matrix"] = open(elig, encoding="utf-8").read()
json.dump(frag, open(frag_path, "w", encoding="utf-8"), indent=2)
PY

# Embed the AUTHENTICATED per-candidate dependency-seed JSON as a top-level string member, tied
# byte-for-byte to what the runner-recipe flow authenticated: the file's sha256 MUST equal the recipe
# facts' dependency_seed.json_sha256, and its candidate MUST match this fragment. produce() re-seals it
# into VEC7 and the sealed-import anchor re-authenticates it against every double-build proof's cargo seed
# origin; merge_fragments additionally requires the two SP1 fragments to carry it byte-identically.
python3 - "$FRAG" "$B0_DEP_SEED_JSON" "$B0_RUNNER_RECIPE_JSON" "$CAND" <<'PY' || die "failed to embed the authenticated dependency-seed into the fragment"
import json, sys, hashlib
frag_path, dep_path, recipe_path, cand = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
dep_bytes = open(dep_path, "rb").read()
recipe = json.load(open(recipe_path, encoding="utf-8"))
want_sha = recipe.get("dependency_seed", {}).get("json_sha256", "")
got_sha = hashlib.sha256(dep_bytes).hexdigest()
if not want_sha or got_sha != want_sha:
    sys.exit(f"dependency-seed json sha256 {got_sha} != recipe dependency_seed.json_sha256 {want_sha!r} "
             "(the embedded dep-seed is not the byte-identical artifact the runner recipe authenticated)")
dep = json.loads(dep_bytes)
if dep.get("candidate") != cand:
    sys.exit(f"dependency-seed candidate {dep.get('candidate')!r} != fragment candidate {cand!r}")
frag = json.load(open(frag_path, encoding="utf-8"))
frag["dependency_seed_json"] = dep_bytes.decode("utf-8")
json.dump(frag, open(frag_path, "w", encoding="utf-8"), indent=2)
PY

# Success: keep the fragment + attestations; drop only the scratch.
trap - EXIT
rm -rf "$SCRATCH"
note "wrote fragment $FRAG (+ runner attestation $ATTEST_OUT, firewall attestation $FW_ATTEST)"
