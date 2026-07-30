#!/usr/bin/env bash
# FIRST-CLASS, SEPARATE, PUBLIC TEST_ONLY / NON_SELECTION smoke (strengthened Option A).
#
# This is a DISTINCT entry point from the authoritative producer (run_authoritative.sh). It drives
# the REAL candidate seams — real candidate Dockerfiles (build_container.sh) + curated contexts
# (stage_context.sh) + the shared production cores — but can ONLY ever emit TEST_ONLY / NON_SELECTION
# outputs. It:
#   * accepts the EXACT clean PR-head SHA (never satisfies RATIFIED_SOURCE_COMMIT);
#   * honors NO bypass env var and REFUSES RATIFIED_SOURCE_COMMIT if set;
#   * writes ONLY under an isolated scratch OUTSIDE the repo / docs / any authoritative dir;
#   * NEVER calls authoritative assembly / aggregation / finalization (stage6 / stage1-ingest);
#   * produces TWO clearly-named, SEPARATE outputs:
#       1. a real-execution ATTESTATION (the real checksum-verified prover/verifier/audit binaries
#          that actually ran: versions, point-of-use hashes, causal Stage-5 output binding) — stored
#          ONLY as TEST_ONLY smoke evidence, never an authoritative tool-binding;
#       2. a sealed TEST_ONLY bundle using the unmistakably-synthetic Stage-5b sentinel identity
#          (preserving TEST_ONLY => synthetic; permanently non-finalizable).
#   * substitutes the synthetic identity ONLY after the attestation is verified to AGREE with the
#     actual Stage-5 execution, EXPLICITLY and LOGGED (venue-verify smoke-substitute).
#
# SP1 runs on its eligible architectures; RISC Zero on x86_64 ONLY (VENUE.md §2).
#
# A GREEN end-to-end run additionally requires the venue toolchain provisioning (proposed pins +
# cargo-audit / advisory-DB / prover toolchain in the candidate images). Absent those, this smoke
# reaches the real candidate build/capability seams and FAILS CLOSED there — it never fabricates.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
VAL="$ROOT/../b0-pre-validator/Cargo.toml"
# shellcheck source=lib.sh
. "$HERE/lib.sh"

vv() {
  if [ -n "${VENUE_VERIFY_BIN:-}" ]; then "$VENUE_VERIFY_BIN" "$@"
  else cargo run --quiet --locked --manifest-path "$VAL" --bin venue-verify -- "$@"; fi
}

# ---- (1) GUARDS — fail closed BEFORE anything runs -------------------------------------------
# (a) TEST_ONLY posture: refuse an authoritative context and refuse EVERY known bypass variable.
[ -z "${RATIFIED_SOURCE_COMMIT:-}" ] \
  || die "smoke is TEST_ONLY / NON_SELECTION and refuses to run with RATIFIED_SOURCE_COMMIT set"
for v in SUMCHAIN_B0PRE_SMOKE_AUTHORITATIVE SUMCHAIN_B0PRE_FORCE_AUTHORITATIVE \
         SUMCHAIN_B0PRE_BYPASS B0PRE_FORCE_AUTHORITATIVE B0PRE_AUTHORITATIVE; do
  [ -z "${!v:-}" ] || die "smoke refuses the bypass variable $v (there is no authoritative bypass)"
done
require_cmd git

# Resolve a path to an absolute, symlink-free-ish form for the authoritative-directory guard.
smoke_abs() {
  local p="$1"
  ( cd "$(dirname "$p")" 2>/dev/null && printf '%s/%s' "$(pwd)" "$(basename "$p")" ) || printf '%s' "$p"
}
# The isolated-output guard: a smoke output path may NEVER be under the repository or any docs/
# tree (so it can never write an authoritative or committed-protocol directory). Enforced up front
# for an EXPLICIT argument — independent of tree state — and again for the resolved default below.
refuse_authoritative_path() {
  local abs; abs="$(smoke_abs "$1")"
  case "$abs" in
    "$ROOT"/*|"$ROOT") die "smoke output must be OUTSIDE the repository: $abs is under $ROOT" ;;
    */docs/*)          die "smoke output must not be under any docs/ tree: $abs" ;;
  esac
}
# (b) validate an explicit output argument BEFORE anything else touches the tree.
[ "$#" -ge 1 ] && [ -n "${1:-}" ] && refuse_authoritative_path "$1"

# (c) exact clean PR-head.
dirty="$(git -C "$ROOT" status --porcelain 2>/dev/null || true)"
[ -z "$dirty" ] || die "smoke requires a CLEAN PR-head working tree (uncommitted changes present)"
PR_HEAD="$(git -C "$ROOT" rev-parse HEAD 2>/dev/null || true)"
is_ratified_commit_format "$PR_HEAD" || die "cannot resolve a 40-hex clean PR-head (got '${PR_HEAD:-<none>}')"

# (d) isolated scratch OUTSIDE the repo / docs / any authoritative directory.
SMOKE_ROOT="${1:-$HOME/.b0pre-smoke-$PR_HEAD}"
refuse_authoritative_path "$SMOKE_ROOT"
[ -e "$SMOKE_ROOT" ] && die "smoke scratch $SMOKE_ROOT already exists; refuse to overwrite"
mkdir -p "$SMOKE_ROOT"
note "== B0-PRE TEST_ONLY / NON_SELECTION smoke @ PR-head $PR_HEAD (scratch: $SMOKE_ROOT) =="

# ---- (2) distinct smoke SOURCE binding (authoritative readers reject it) ---------------------
src="$SMOKE_ROOT/smoke-source-binding.json"
require_cmd python3
OUT="$src" PR_HEAD="$PR_HEAD" python3 - <<'PY'
import json, os
json.dump({"schema_version": 1, "classification": "TEST_ONLY",
           "source_pr_head": os.environ["PR_HEAD"],
           "note": "first-class TEST_ONLY smoke; never authoritative"},
          open(os.environ["OUT"], "w"))
PY
vv smoke-source-check "$src" || die "smoke source binding failed validation"

# ---- (3) drive the REAL candidate seams (SP1 all-arch; RISC Zero x86_64 only) ----------------
# The smoke arch defaults to the host arch; RISC Zero is only attempted on x86_64.
HOST_ARCH="$(uname -m)"; case "$HOST_ARCH" in arm64) HOST_ARCH=aarch64 ;; esac
SMOKE_ARCH="${SMOKE_ARCH:-$HOST_ARCH}"
case "$SMOKE_ARCH" in x86_64|aarch64) ;; *) die "unsupported smoke arch '$SMOKE_ARCH'" ;; esac

smoke_candidate() {  # <candidate> <arch>
  local cand="$1" arch="$2" work="$SMOKE_ROOT/$1.$2.work"
  mkdir -p "$work"
  note "-- smoke candidate=$cand arch=$arch: staging curated context + REAL candidate build --"
  # Real curated context (filesystem-only; the SAME staging the authoritative producer uses).
  bash "$HERE/stage_context.sh" "$cand" "$work/ctx" >/dev/null \
    || die "smoke: curated-context staging failed for $cand"
  require_cmd docker
  docker info >/dev/null 2>&1 || die "smoke needs a reachable Docker daemon (real-container seams)"
  # REAL candidate image build in SMOKE mode (distinct sidecar schema; no RATIFIED). Proposed
  # pins (BASE_IMAGE / APT_* / RUSTUP_INIT_*) come from the venue's TEST_ONLY provisioning; absent
  # them build_container.sh fails closed here — the smoke reaches the real build seam, never fakes.
  bash "$HERE/build_container.sh" "$cand" "$arch" "$work" smoke \
    || nyr "smoke reached the REAL candidate build seam for $cand/$arch and it failed closed \
(proposed pins + TEST_ONLY toolchain provisioning are the remaining venue inputs); nothing fabricated"
  # Beyond this point (venue-provisioned): capability preflight -> real Stage-1 lock -> real
  # Stage-2 audit (run_stage2_audit_locked) -> material -> causal Stage-5 proof. Each REAL binary's
  # point-of-use hash + version + the Stage-5 output it produced is recorded into the ATTESTATION;
  # `vv smoke-attest-check` validates it; `vv smoke-substitute` verifies AGREEMENT and emits the
  # EXPLICIT, LOGGED plan to substitute the synthetic Stage-5b sentinel before the TEST_ONLY bundle
  # is assembled + sealed + imported. No authoritative aggregation / finalization is ever invoked.
}

smoke_candidate sp1 "$SMOKE_ARCH"
if [ "$SMOKE_ARCH" = x86_64 ]; then
  smoke_candidate risc0 x86_64
else
  note "arch=$SMOKE_ARCH: skipping RISC Zero (x86_64-only per VENUE.md §2)"
fi

note "TEST_ONLY / NON_SELECTION smoke @ PR-head $PR_HEAD: real candidate seams driven; two outputs \
(real-execution attestation + synthetic-sealed TEST_ONLY bundle) are kept distinct; nothing was \
aggregated, finalized, selected, deployed, or activated."
