#!/usr/bin/env bash
# NON-AUTHORITATIVE host lock probe.
#
# Resolves the candidate manifests in an ISOLATED TEMP DIRECTORY on the wrong
# execution environment (this macOS/arm64 host) purely to surface early signals:
# whether the exact pins resolve, resolved versions, prereleases, git/path deps,
# duplicate proof-stack versions, and obvious source anomalies.
#
# It NEVER computes candidate_dep_lock_hash, never claims authority/eligibility,
# never writes under candidates/{sp1,risc0}, and deletes the temp lock/build
# outputs afterward — retaining only a concise textual report with no local paths
# or machine identity. If safe temp cleanup would require destructive escalation,
# it stops and reports instead.
#
# Usage: host_lock_probe.sh <temp_workdir> <report_out>
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"

tmp="${1:?temp workdir required}"; report="${2:?report output path required}"
case "$tmp" in
  *"/candidates/"*|"$ROOT/candidates"*) echo "REFUSED: probe must not run under candidates/" >&2; exit 2 ;;
esac
mkdir -p "$tmp"
# Safety net: never leak the temp workspace, even on an unexpected mid-run error.
trap 'rm -rf "$tmp" 2>/dev/null || true' EXIT

emit() { printf '%s\n' "$*" >> "$report"; }
: > "$report"
emit "NON_AUTHORITATIVE_HOST_PROBE"
emit "environment: macOS-arm64 (wrong execution environment)"
emit "NOT_FOR_CANDIDATE_DEP_LOCK_HASH"
emit "NOT_FOR_B0_PRE_FINALIZATION"
emit "purpose: early resolution/anomaly signal only; not reproducible, not authoritative, not container-derived"
emit "policy: prerelease findings below are RECORDED for the venue audit, not a verdict. The"
emit "        stable-only rule binds the selected candidate release (sp1 6.3.1 / risc0 3.0.5 /"
emit "        3.0.4 / 2.2.2); the transitive graph is subject to the security/source/reproducibility"
emit "        gates. See VENUE.md 'Version / audit policy'."
emit ""

probe_one() {
  local name="$1" src="$2"
  local d="$tmp/$name"
  rm -rf "$d"; mkdir -p "$d"
  cp -R "$src/." "$d/"
  rm -f "$d/Cargo.lock" "$d"/*/Cargo.lock 2>/dev/null || true
  emit "== candidate: $name =="

  local log="$d/.resolve.log"
  if ( cd "$d" && cargo generate-lockfile ) >"$log" 2>&1; then
    emit "resolve: OK (host, non-authoritative)"
    if [ -f "$d/Cargo.lock" ]; then
      # duplicate proof-stack versions (same crate, >1 version)
      local dups
      dups="$(grep -E '^name = "(sp1|risc0)' "$d/Cargo.lock" | sort | uniq -c | awk '$1>1{print $0}')" || true
      # direct-pin versions of interest
      emit "resolved proof-stack crate versions (direct pins):"
      grep -A1 -E '^name = "(sp1-sdk|sp1-zkvm|sp1-build|sp1-verifier|risc0-zkvm|risc0-build|risc0-groth16|risc0-zkvm-platform)"' "$d/Cargo.lock" \
        | grep -E '^(name|version)' | paste - - | sed 's/name = //; s/version = //; s/^/  /' | sort -u >> "$report" || true
      # True SemVer prereleases only: a '-' immediately after MAJOR.MINOR.PATCH,
      # before any '+build' metadata (so wasi 0.11.0+wasi-... is NOT flagged).
      local pre=""
      pre="$(grep -B1 -E '^version = "[0-9]+\.[0-9]+\.[0-9]+-' "$d/Cargo.lock" | grep '^name' | sed 's/name = //' | sort -u | tr '\n' ' ')" || true
      if [ -n "$pre" ]; then emit "prerelease crates in graph: $pre"; else emit "prerelease crates in graph: none"; fi
      # git/path sources
      local gits
      gits="$(grep -cE 'source = "git\+' "$d/Cargo.lock" || true)"
      emit "git-sourced dependencies: ${gits:-0}"
      [ -n "$dups" ] && { emit "DUPLICATE proof-stack versions:"; printf '%s\n' "$dups" | sed 's/^/  /' >> "$report"; } || emit "duplicate proof-stack versions: none detected"
    fi
  else
    emit "resolve: FAILED on host (informative; may still resolve in the venue)"
    emit "first error line:"
    grep -m1 -E 'error(\[|:)' "$log" | sed 's/^/  /' >> "$report" || emit "  (no error: line captured)"
  fi
  emit ""
}

probe_one sp1 "$ROOT/candidates/sp1"
probe_one risc0 "$ROOT/candidates/risc0"

emit "reminder: authoritative locks + candidate_dep_lock_hash come ONLY from the container venue."

# Safe cleanup of temp outputs (no destructive escalation).
if rm -rf "$tmp" 2>/dev/null; then
  emit "temp probe workspace removed."
else
  echo "STOP: could not safely remove temp workspace without escalation" >&2
  exit 4
fi
