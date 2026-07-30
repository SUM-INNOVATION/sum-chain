#!/usr/bin/env bash
# Strengthened Option A — SHELL acceptance negatives for the first-class TEST_ONLY smoke.
#
# Proves the smoke entry point + the smoke/authoritative source-authority split fail closed:
#   #6  smoke cannot write to an authoritative / repo / docs path;
#   #7  no RATIFIED_SOURCE_COMMIT and no bypass variable is accepted;
#   +   the authoritative runnable-ref resolver REJECTS a smoke-schema sidecar (distinct schema),
#       and the smoke resolver rejects an authoritative-schema sidecar — neither can be reused for
#       the other by merely changing the source field;
#   +   build_container.sh smoke mode refuses to run with RATIFIED_SOURCE_COMMIT set.
# Deterministic; no Docker / network / toolchain (the guards fire before any build).
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCR="$(cd "$HERE/.." && pwd)"
ROOT="$(cd "$SCR/.." && pwd)"
SMOKE="$SCR/smoke.sh"
F=0; ok(){ printf 'ok    %s\n' "$1"; }; bad(){ printf 'FAIL  %s\n' "$1" >&2; F=1; }

# A refusal = a non-zero exit whose message contains the expected needle.
refuses() { # <needle> <cmd...>
  local needle="$1"; shift
  local out; out="$("$@" 2>&1)"; local rc=$?
  if [ "$rc" -ne 0 ] && grep -qi "$needle" <<<"$out"; then ok "refused ($needle)"; else
    bad "expected refusal containing '$needle' (rc=$rc): $(head -1 <<<"$out")"
  fi
}

# ---- #7: no RATIFIED_SOURCE_COMMIT, no bypass variable ----------------------------------------
refuses "RATIFIED_SOURCE_COMMIT" env RATIFIED_SOURCE_COMMIT=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa bash "$SMOKE"
for v in SUMCHAIN_B0PRE_SMOKE_AUTHORITATIVE SUMCHAIN_B0PRE_FORCE_AUTHORITATIVE \
         SUMCHAIN_B0PRE_BYPASS B0PRE_FORCE_AUTHORITATIVE B0PRE_AUTHORITATIVE; do
  refuses "bypass variable $v" env "$v=1" bash "$SMOKE"
done

# ---- #6: smoke cannot write to an authoritative / repo / docs path ----------------------------
# (Explicit output argument is validated up front, before any tree/PR-head work.)
refuses "OUTSIDE the repository" bash "$SMOKE" "$ROOT/tools/should-not-write-here"
refuses "docs/" bash "$SMOKE" "$ROOT/docs/b0-pre/should-not-write-here"

# ---- source-authority split: distinct schemas, neither reusable for the other -----------------
command -v python3 >/dev/null 2>&1 || { echo "SKIP schema-split checks (python3 absent)"; }
if command -v python3 >/dev/null 2>&1; then
  # shellcheck source=../lib.sh
  . "$SCR/lib.sh" >/dev/null 2>&1
  set +e   # lib.sh enables `set -e`; this test drives expected-failure paths, so restore it off
  T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
  mani="sha256:$(printf 'b%.0s' $(seq 1 64))"
  cfg="sha256:$(printf 'c%.0s' $(seq 1 64))"
  img="sha256:$(printf 'd%.0s' $(seq 1 64))"
  # a SMOKE-schema sidecar
  python3 - "$T/sp1.x86_64.runnable-ref" "$mani" "$cfg" "$img" <<'PY'
import json, sys
p, mani, cfg, img = sys.argv[1:5]
json.dump({"schema":"b0pre-smoke-runnable-ref-v1","classification":"TEST_ONLY","candidate":"sp1",
           "arch":"x86_64","source_pr_head":"a"*40,"manifest_digest":mani,"config_digest":cfg,
           "runnable_image_id":img}, open(p,"w"))
PY
  # AUTHORITATIVE resolver must REJECT the smoke sidecar on schema (before any docker/HEAD work).
  if ( resolve_runnable_ref "$T/sp1.x86_64.runnable-ref" sp1 x86_64 "$mani" "$ROOT" ) >/dev/null 2>&1; then
    bad "authoritative resolve_runnable_ref ACCEPTED a smoke-schema sidecar"
  else
    ok "authoritative resolve_runnable_ref rejects the smoke-schema sidecar (distinct schema)"
  fi
  # an AUTHORITATIVE-schema sidecar
  python3 - "$T/auth.runnable-ref" "$mani" "$cfg" "$img" <<'PY'
import json, sys
p, mani, cfg, img = sys.argv[1:5]
json.dump({"schema":"b0pre-runnable-ref-v1","candidate":"sp1","arch":"x86_64",
           "source_commit":"a"*40,"manifest_digest":mani,"config_digest":cfg,
           "runnable_image_id":img}, open(p,"w"))
PY
  # the SMOKE resolver must REJECT the authoritative-schema sidecar on schema.
  if ( resolve_smoke_runnable_ref "$T/auth.runnable-ref" sp1 x86_64 "$mani" "$(printf 'a%.0s' $(seq 1 40))" "$ROOT" ) >/dev/null 2>&1; then
    bad "resolve_smoke_runnable_ref ACCEPTED an authoritative-schema sidecar"
  else
    ok "smoke resolver rejects an authoritative-schema sidecar (distinct schema)"
  fi
fi

# ---- build_container.sh smoke mode refuses an authoritative context ---------------------------
refuses "smoke build refuses to run with RATIFIED_SOURCE_COMMIT" \
  env RATIFIED_SOURCE_COMMIT=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa bash "$SCR/build_container.sh" sp1 x86_64 "$(mktemp -d)" smoke
# an unknown build mode is refused.
refuses "build mode must be authoritative|smoke" bash "$SCR/build_container.sh" sp1 x86_64 "$(mktemp -d)" bogus

echo "----"
if [ "$F" = 0 ]; then echo "SMOKE_GUARDS_PASS"; echo "smoke_guards: ALL TESTS PASS"; exit 0
else echo "smoke_guards: FAILURE(S)" >&2; exit 1; fi
