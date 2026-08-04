#!/usr/bin/env bash
# FIRST-CLASS, SEPARATE, PUBLIC TEST_ONLY / NON_SELECTION smoke (strengthened Option A).
#
# A DISTINCT entry point from the authoritative producer (run_authoritative.sh). It drives the
# REAL candidate seams and ASSEMBLES THE SEALED BUNDLE FROM THE REAL PRODUCER OUTPUTS via the
# SHARED real assembler (assemble_evidence) + the reused record producers (produce_stage2 /
# produce_stage5, given the smoke's runnable ref) — never emit-test-only-bundle. The ONE synthetic
# substitution is the Stage-5b tool binding; every other sealed artifact (container/native, the
# Stage-1 lock + provenance, the Stage-2 audit record + command log, the verifier material, the
# Stage-5 result + sealed runner lock) is the exact real producer output. The bundle is sealed +
# imported under the EXPLICIT TEST_ONLY mode (venue-verify seal-bundle-test-only /
# import-bundle-test-only, kind b0-pre-per-arch-smoke-evidence-bundle-v1), which the authoritative
# import REJECTS outright — a one-way quarantine.
#
# Continuous path (each stage checks its output before continuing):
#   real SP1/RISC Zero build -> capability preflight -> Stage-1 lock -> Stage-2 audit ->
#   material extraction -> causal Stage-5 execution -> real SmokeExecutionAttestation ->
#   verified explicit synthetic substitution -> TEST_ONLY assembly (real records + synthetic
#   Stage-5b) -> seal-bundle-test-only -> import-bundle-test-only -> rejection proofs ->
#   terminal X86 smoke success marker.
#
# It never sets/needs RATIFIED_SOURCE_COMMIT (a distinct smoke source-authority: SmokeSourceBinding
# + b0pre-smoke-runnable-ref-v1 sidecar the authoritative resolver rejects), refuses every bypass
# var, writes only under an isolated scratch OUTSIDE the repo/docs, and NEVER calls authoritative
# aggregation/finalization. A GREEN run requires the venue toolchain provisioning (proposed pins +
# cargo-audit / advisory-DB / prover toolchain in the candidate images); absent those, the smoke
# reaches the real build/capability seams and FAILS CLOSED with the exact missing input.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
VAL="$ROOT/../b0-pre-validator/Cargo.toml"
MARKER="X86_REAL_CANDIDATE_SMOKE_PASS"
# Reuse the SHARED production functions — the record producers produce_stage2 / produce_stage5
# (which take the caller's runnable ref) + the shared real assembler assemble_evidence, plus (via
# lib.sh) resolve_smoke_runnable_ref / preflight_builder_capability / builder_digest_of /
# schema_arch_of. Both files carry a source-execution guard, so sourcing runs NO producer.
# shellcheck source=extract_material.sh
. "$HERE/extract_material.sh"
# shellcheck source=run_authoritative.sh
. "$HERE/run_authoritative.sh"

stage1_ingest() {  # <bundle.json> <artifact_out> ; the AUTHORITATIVE reader (for rejection proofs)
  if [ -n "${STAGE1_INGEST_BIN:-}" ]; then "$STAGE1_INGEST_BIN" "$@"
  else cargo run --quiet --locked --manifest-path "$VAL" --bin stage1-ingest -- "$@"; fi
}

# ---- shared helpers (sourceable; no side effects on load) ------------------------------------
# Every stage output MUST be present + non-empty (and valid JSON when --json) before continuing.
smoke_require() {  # <label> <file> [--json]
  local label="$1" f="$2" json="${3:-}"
  [ -f "$f" ] && [ -s "$f" ] || die "smoke stage output MISSING/EMPTY: $label ($f)"
  if [ "$json" = "--json" ]; then
    python3 -c 'import json,sys; json.load(open(sys.argv[1]))' "$f" 2>/dev/null \
      || die "smoke stage output NOT valid JSON: $label ($f)"
  fi
}

smoke_abs() {
  local p="$1"
  ( cd "$(dirname "$p")" 2>/dev/null && printf '%s/%s' "$(pwd)" "$(basename "$p")" ) || printf '%s' "$p"
}
refuse_authoritative_path() {
  local abs; abs="$(smoke_abs "$1")"
  case "$abs" in
    "$ROOT"/*|"$ROOT") die "smoke output must be OUTSIDE the repository: $abs is under $ROOT" ;;
    */docs/*)          die "smoke output must not be under any docs/ tree: $abs" ;;
  esac
}

# Write + validate the distinct smoke SOURCE binding (authoritative readers reject it).
smoke_write_source_binding() {  # <out.json> <pr_head>
  local out="$1" pr_head="$2"
  require_cmd python3
  OUT="$out" PR_HEAD="$pr_head" python3 - <<'PY'
import json, os
json.dump({"schema_version": 1, "classification": "TEST_ONLY",
           "source_pr_head": os.environ["PR_HEAD"],
           "note": "first-class TEST_ONLY smoke; never authoritative"},
          open(os.environ["OUT"], "w"))
PY
  smoke_require "smoke source binding" "$out" --json
  vv smoke-source-check "$out" >/dev/null || die "smoke source binding failed validation"
}

# The unmistakably-synthetic Stage-5b sentinel identity — the ONE synthetic substitution.
smoke_synthetic_sentinel() { printf 'TEST_ONLY_SYNTHETIC://%s-stage5b-verifier' "$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')"; }

# Write the SYNTHETIC Stage-5b tool binding into $work/<Cand>.tool-binding.json. This REPLACES the
# authoritative tool_identities.sh output (the only substituted record); the import validates it in
# TestOnly mode (which REQUIRES the synthetic sentinel), and its identity is bound by the
# substitution log. Every OTHER work-dir record remains the exact real producer output.
smoke_write_synthetic_tool_binding() {  # <work> <scand> <builder> <pr_head>
  local work="$1" scand="$2" builder="$3" pr_head="$4"
  local id; id="$(smoke_synthetic_sentinel "$scand")"
  OUT="$work/$scand.tool-binding.json" SC="$scand" ID="$id" D="$builder" C="$pr_head" python3 - <<'PY'
import json, os
sc, idn = os.environ["SC"], os.environ["ID"]
lc = sc.lower()
b = {"candidate": sc, "name": "stage5b-verifier", "version": "0.0.0",
     "artifact_identity": idn, "checksum_algorithm": "sha256",
     "declared_checksum_hex": "0"*64, "verified_artifact_hex": "0"*64,
     "installed_binary_sha256_hex": "0"*64,
     "install_entrypoint": f"TEST_ONLY_SYNTHETIC:cargo:{lc}-stage5b",
     "container_digest": os.environ["D"], "source_commit": os.environ["C"], "test_only": True}
json.dump([b], open(os.environ["OUT"], "w"), indent=2)
PY
  smoke_require "synthetic Stage-5b tool binding" "$work/$scand.tool-binding.json" --json
}

# Build the REAL execution ATTESTATION from the EXACT binary the Stage-5 result recorded as
# executed (the causal binding the importer re-checks), then the explicit substitution log.
smoke_build_attestation_and_substitution() {  # <ref> <scand> <arch> <builder> <pr_head> <work>
  local ref="$1" scand="$2" arch="$3" builder="$4" pr_head="$5" work="$6"
  local s5="$work/$scand.stage5-result.json"
  smoke_require "Stage-5 result (real)" "$s5" --json
  local poh ver att="$work/$scand.smoke-attestation.json" obs="$work/$scand.stage5-observed.json"
  # point-of-use == the Stage-5 record's verifier_executed_binary_sha256 (the exact binary run).
  poh="$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["verifier_executed_binary_sha256"])' "$s5")"
  ver="$(docker run --rm --pull never "$ref" bash -c 'cargo --version' 2>/dev/null | head -n1 | sed 's/[[:space:]]*$//' || true)"
  [ -n "$poh" ] && [ -n "$ver" ] || die "smoke attestation: missing executed-binary hash / version for $scand"
  POH="$poh" VER="$ver" SC="$scand" ARCH="$arch" D="$builder" PRH="$pr_head" ATT="$att" OBS="$obs" python3 - <<'PY'
import json, os
poh = os.environ["POH"]
att = {"schema_version": 1, "classification": "TEST_ONLY", "candidate": os.environ["SC"],
       "arch": os.environ["ARCH"], "container_digest": os.environ["D"],
       "source_pr_head": os.environ["PRH"],
       "executables": [{"executable_name": "stage5-runner", "version_output": os.environ["VER"],
                        "checksum_verified_hex": poh, "point_of_use_sha256": poh,
                        "produced_output_blake3": poh}]}
json.dump(att, open(os.environ["ATT"], "w"))
json.dump([poh], open(os.environ["OBS"], "w"))
PY
  vv smoke-attest-check "$att" >/dev/null || die "smoke attestation failed validation for $scand"
  # EXPLICIT, LOGGED substitution — only after the attestation AGREES with the observed Stage-5
  # output; its synthetic sentinel is exactly the sealed synthetic Stage-5b identity.
  vv smoke-substitute "$att" "$obs" "$(smoke_synthetic_sentinel "$scand")" > "$work/$scand.substitution-log.json" \
    || die "smoke substitution refused (attestation disagrees with the actual Stage-5 execution) for $scand"
  smoke_require "explicit substitution log" "$work/$scand.substitution-log.json" --json
}

# Real per-candidate production INTO $work (mirrors produce_arch's per-candidate steps but with the
# smoke runnable ref and the synthetic Stage-5b substitution). BUILD + Stage-1 + Stage-2 run for
# BOTH candidates on every arch; Stage-5 / material / attestation only for the eligible candidate
# (SP1 both arches, RISC Zero native x86_64 only).
smoke_produce_candidate() {  # <cand lc> <scand> <arch> <sarch> <pr_head> <work>
  local cand="$1" scand="$2" arch="$3" sarch="$4" pr_head="$5" work="$6"
  note "-- smoke $cand/$arch: curated context + REAL candidate build (smoke source-authority) --"
  bash "$HERE/stage_context.sh" "$cand" "$work/$cand.ctx" >/dev/null || die "smoke: staging failed for $cand"
  require_cmd docker; docker info >/dev/null 2>&1 || die "smoke needs a reachable Docker daemon"
  bash "$HERE/build_container.sh" "$cand" "$arch" "$work" smoke \
    || nyr "smoke reached the REAL $cand/$arch build seam; it failed closed (proposed pins + TEST_ONLY \
toolchain provisioning are the remaining venue inputs) — nothing fabricated"
  local builder ref
  builder="$(builder_digest_of "$cand" "$arch" "$work")"
  ref="$(resolve_smoke_runnable_ref "$work/$cand.$arch.runnable-ref" "$cand" "$arch" "$builder" "$pr_head" "$ROOT")"
  preflight_builder_capability "$ref" "$arch" "${CARGO_AUDIT_PIN_VERSION:-}" "${CARGO_AUDIT_EXPECTED_EXE_SHA256:-}"
  # Stage 1 (real lock + provenance) + Stage 2 (real audit record) — REUSED producers.
  SCHEMA_ARCH="$sarch" BUILDER_IMAGE_REF="$ref" BUILDER_IMAGE_DIGEST="$builder" \
    bash "$HERE/resolve_lock.sh" "$cand" "$work" || die "smoke Stage-1 lock failed for $cand"
  smoke_require "Stage-1 lock (real)" "$work/$scand.Cargo.lock"
  produce_stage2 "$scand" "$arch" "$sarch" "$work" "$ref" || die "smoke Stage-2 FATAL for $cand"
  smoke_require "Stage-2 audit record (real)" "$work/$scand.stage2-audit.json" --json
  local host; case "$arch" in x86_64) host=x86_64 ;; *) host=aarch64 ;; esac
  # Stage 4/5 + attestation only for the eligible candidate on this arch.
  if [ "$scand" = "Sp1" ] || [ "$arch" = "x86_64" ]; then
    SCHEMA_ARCH="$sarch" BUILDER_IMAGE_REF="$ref" BUILDER_IMAGE_DIGEST="$builder" \
      bash "$HERE/extract_material.sh" "$cand" "$work" || die "smoke material extraction failed for $cand"
    # Stage-5b BEFORE Stage-5c: the tool binding (here the ONE TEST_ONLY synthetic substitute)
    # MUST exist before produce_stage5, which CONSUMES it as recorded proof-tool provenance
    # (verifier_fixtures.sh -> prove_fixture.sh requires TOOL_BINDING). Mirrors the authoritative
    # ordering (run_authoritative.sh Stage 5b tool identities -> Stage 5c produce_stage5).
    smoke_write_synthetic_tool_binding "$work" "$scand" "$builder" "$pr_head"
    produce_stage5 "$scand" "$arch" "$sarch" "$work" "$ref" || die "smoke Stage-5 FATAL for $cand"
    smoke_require "Stage-5 result (real)" "$work/$scand.stage5-result.json" --json
    smoke_require "Stage-5 sealed runner lock (real)" "$work/$scand.stage5/runner-cargo.lock"
    # The attestation MUST stay after produce_stage5: it reads back verifier_executed_binary_sha256
    # from the Stage-5 result.
    smoke_build_attestation_and_substitution "$ref" "$scand" "$host" "$builder" "$pr_head" "$work"
  fi
}

# Assemble from the REAL work-dir outputs via the SHARED assembler, add the smoke-only files, seal
# + import under the EXPLICIT TEST_ONLY mode. Returns the evidence dir.
smoke_assemble_and_seal() {  # <arch> <sarch> <pr_head> <work> <ev> <src_binding>
  local arch="$1" sarch="$2" pr_head="$3" work="$4" ev="$5" src="$6"
  mkdir -p "$ev"
  assemble_evidence "$arch" "$work" "$ev"          # real records + the synthetic Stage-5b tool binding
  cp "$src" "$ev/smoke-source-binding.json"         # smoke-only classification/source binding
  local c
  for c in Sp1 Risc0; do
    if [ "$c" = "Sp1" ] || [ "$arch" = "x86_64" ]; then
      cp "$work/$c.smoke-attestation.json" "$ev/$c.smoke-attestation.json"
      cp "$work/$c.substitution-log.json"  "$ev/$c.substitution-log.json"
    fi
  done
  vv seal-bundle-test-only "$ev" "$sarch" "$pr_head" >/dev/null || die "smoke: seal-bundle-test-only failed"
  vv import-bundle-test-only "$ev" >/dev/null || die "smoke: import-bundle-test-only failed"
  smoke_require "sealed smoke manifest" "$ev/arch-evidence-manifest.json" --json
}

# The authoritative rejection proofs on the smoke's OWN sealed artifacts. Each MUST be refused.
smoke_rejection_proofs() {  # <ev> <src_binding> <sidecar> <cand> <scand> <arch> <cur_manifest>
  local ev="$1" src="$2" sidecar="$3" cand="$4" scand="$5" arch="$6" cur="$7" out
  # (1) authoritative import REJECTS the smoke bundle (distinct kind + synthetic Stage-5b binding).
  if vv import-bundle "$ev" >/dev/null 2>&1; then
    die "REJECTION PROOF FAILED: authoritative import accepted the smoke bundle"
  fi
  note "smoke rejection proof: authoritative import-bundle refuses the smoke bundle"
  # (2) TEST_ONLY finalization / authoritative ingest refuses the sealed TEST_ONLY Stage-5 evidence.
  out="$(mktemp -u)"
  if stage1_ingest "$ev/$scand.stage5-result.json" "$out" >/dev/null 2>&1; then
    rm -f "$out"; die "REJECTION PROOF FAILED: authoritative stage1-ingest accepted the TEST_ONLY evidence"
  fi
  [ -e "$out" ] && { rm -f "$out"; die "REJECTION PROOF FAILED: stage1-ingest finalized TEST_ONLY evidence"; }
  note "smoke rejection proof: authoritative finalization refuses the TEST_ONLY evidence"
  # (3) the authoritative runnable-ref resolver REJECTS the smoke sidecar (distinct schema).
  if ( resolve_runnable_ref "$sidecar" "$cand" "$arch" "$cur" "$ROOT" ) >/dev/null 2>&1; then
    die "REJECTION PROOF FAILED: authoritative resolve_runnable_ref accepted the smoke sidecar"
  fi
  note "smoke rejection proof: authoritative resolver refuses the smoke runnable-ref sidecar"
  # (4) the authoritative reader REJECTS the smoke SOURCE binding.
  out="$(mktemp -u)"
  if stage1_ingest "$src" "$out" >/dev/null 2>&1; then
    rm -f "$out"; die "REJECTION PROOF FAILED: authoritative ingest accepted the smoke source binding"
  fi
  [ -e "$out" ] && rm -f "$out"
  note "smoke rejection proof: authoritative ingest refuses the smoke source binding"
  # (5) a post-seal source/classification mutation is refused (breaks the sealed hash).
  local bak; bak="$(mktemp)"; cp "$ev/smoke-source-binding.json" "$bak"
  python3 -c 'import json,sys;d=json.load(open(sys.argv[1]));d["classification"]="NON_SELECTION";json.dump(d,open(sys.argv[1],"w"))' "$ev/smoke-source-binding.json"
  if vv import-bundle-test-only "$ev" >/dev/null 2>&1; then
    cp "$bak" "$ev/smoke-source-binding.json"; rm -f "$bak"
    die "REJECTION PROOF FAILED: post-seal classification mutation was NOT refused"
  fi
  cp "$bak" "$ev/smoke-source-binding.json"; rm -f "$bak"
  note "smoke rejection proof: post-seal source/classification mutation is refused (sealed hash)"
  # (v1 Stage5Result and altered-runner-lock rejections are proven at the Rust level:
  #  evidence_bundle_tests::{smoke_v1_stage5result_is_refused, smoke_altered_sealed_runner_lock_is_refused}.)
}

smoke_marker() { printf '%s\n' "$MARKER"; }

# ---- EXECUTION (guards + orchestration). Sourcing exposes the functions WITHOUT running any of it.
if [ "${BASH_SOURCE[0]:-}" = "${0}" ]; then
  [ -z "${RATIFIED_SOURCE_COMMIT:-}" ] \
    || die "smoke is TEST_ONLY / NON_SELECTION and refuses to run with RATIFIED_SOURCE_COMMIT set"
  for v in SUMCHAIN_B0PRE_SMOKE_AUTHORITATIVE SUMCHAIN_B0PRE_FORCE_AUTHORITATIVE \
           SUMCHAIN_B0PRE_BYPASS B0PRE_FORCE_AUTHORITATIVE B0PRE_AUTHORITATIVE; do
    [ -z "${!v:-}" ] || die "smoke refuses the bypass variable $v (there is no authoritative bypass)"
  done
  require_cmd git
  [ "$#" -ge 1 ] && [ -n "${1:-}" ] && refuse_authoritative_path "$1"
  dirty="$(git -C "$ROOT" status --porcelain 2>/dev/null || true)"
  [ -z "$dirty" ] || die "smoke requires a CLEAN PR-head working tree (uncommitted changes present)"
  PR_HEAD="$(git -C "$ROOT" rev-parse HEAD 2>/dev/null || true)"
  is_ratified_commit_format "$PR_HEAD" || die "cannot resolve a 40-hex clean PR-head (got '${PR_HEAD:-<none>}')"
  SMOKE_ROOT="${1:-$HOME/.b0pre-smoke-$PR_HEAD}"
  refuse_authoritative_path "$SMOKE_ROOT"
  [ -e "$SMOKE_ROOT" ] && die "smoke scratch $SMOKE_ROOT already exists; refuse to overwrite"
  mkdir -p "$SMOKE_ROOT"
  note "== B0-PRE TEST_ONLY / NON_SELECTION smoke @ PR-head $PR_HEAD (scratch: $SMOKE_ROOT) =="

  SMOKE_SRC="$SMOKE_ROOT/smoke-source-binding.json"
  smoke_write_source_binding "$SMOKE_SRC" "$PR_HEAD"

  HOST_ARCH="$(uname -m)"; case "$HOST_ARCH" in arm64) HOST_ARCH=aarch64 ;; esac
  SMOKE_ARCH="${SMOKE_ARCH:-$HOST_ARCH}"
  case "$SMOKE_ARCH" in x86_64|aarch64) ;; *) die "unsupported smoke arch '$SMOKE_ARCH'" ;; esac
  SARCH="$(schema_arch_of "$SMOKE_ARCH")"
  WORK="$SMOKE_ROOT/$SMOKE_ARCH.work"; mkdir -p "$WORK"

  # BUILD + Stage-1 + Stage-2 run for BOTH candidates; Stage-5/material/attestation for the eligible
  # candidate only (SP1 both arches, RISC Zero native x86_64).
  smoke_produce_candidate sp1   Sp1   "$SMOKE_ARCH" "$SARCH" "$PR_HEAD" "$WORK"
  smoke_produce_candidate risc0 Risc0 "$SMOKE_ARCH" "$SARCH" "$PR_HEAD" "$WORK"

  EV="$SMOKE_ROOT/$SMOKE_ARCH.evidence"
  smoke_assemble_and_seal "$SMOKE_ARCH" "$SARCH" "$PR_HEAD" "$WORK" "$EV" "$SMOKE_SRC"
  smoke_rejection_proofs "$EV" "$SMOKE_SRC" "$WORK/sp1.$SMOKE_ARCH.runnable-ref" \
    sp1 Sp1 "$SMOKE_ARCH" "$(builder_digest_of sp1 "$SMOKE_ARCH" "$WORK")"

  note "TEST_ONLY / NON_SELECTION smoke @ PR-head $PR_HEAD: sealed bundle assembled FROM THE REAL \
producer outputs (only the Stage-5b identity synthetic); TestOnly import verified; authoritative \
import + finalization refused it. Nothing aggregated, finalized, selected, deployed, or activated."
  smoke_marker
fi
