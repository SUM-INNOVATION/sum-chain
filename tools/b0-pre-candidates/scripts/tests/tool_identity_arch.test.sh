#!/usr/bin/env bash
# Per-architecture tool-identity tests (finding F3).
#
# SP1 ships genuinely different bytes per architecture and RISC Zero publishes no
# aarch64-linux artifact at all, so the former single SP1_TOOL_IDENTITY /
# RISC0_TOOL_IDENTITY pair could not describe both hosts: on aarch64 it would have
# downloaded the x86_64 RISC Zero tarball and bound an x86_64 binary as aarch64 evidence.
# The ratified record now names one variable per (candidate, arch), the identity file
# must declare the arch it is for, and selection happens only after the native-arch gate.
# No network, no Docker.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
SCRIPTS="$(cd "$HERE/.." && pwd)"
FIXTURE="$HERE/fixtures/proposed-pins.documented-shape.json"
VERIFY="$SCRIPTS/verify_pins.sh"
TMPD="${TMPDIR:-/tmp}"
# shellcheck source=../lib.sh
. "$SCRIPTS/lib.sh"
set +e

fails=0
ok()  { printf 'ok    %s\n' "$1"; }
bad() { printf 'FAIL  %s\n' "$1" >&2; fails=$((fails + 1)); }
check_rc() { [ "$2" = "$3" ] && ok "$1 (rc=$3)" || bad "$1: expected rc=$2 got rc=$3"; }

command -v python3 >/dev/null 2>&1 || { echo "SKIP: python3 absent"; exit 0; }

# ---- the ratified variable NAME per (candidate, arch) -----------------------
[ "$(tool_identity_var Sp1 x86_64 2>/dev/null)"   = "SP1_TOOL_IDENTITY_X86_64" ] \
  && ok "Sp1/x86_64 -> SP1_TOOL_IDENTITY_X86_64"   || bad "wrong variable for Sp1/x86_64"
[ "$(tool_identity_var Sp1 aarch64 2>/dev/null)"  = "SP1_TOOL_IDENTITY_AARCH64" ] \
  && ok "Sp1/aarch64 -> SP1_TOOL_IDENTITY_AARCH64" || bad "wrong variable for Sp1/aarch64"
[ "$(tool_identity_var Risc0 x86_64 2>/dev/null)" = "RISC0_TOOL_IDENTITY_X86_64" ] \
  && ok "Risc0/x86_64 -> RISC0_TOOL_IDENTITY_X86_64" || bad "wrong variable for Risc0/x86_64"

# RISC Zero on Arm is refused outright — VENUE.md §2 keeps Groth16 / verifier-material
# extraction native-x86_64-only, and upstream ships no aarch64-linux artifact.
out="$( (tool_identity_var Risc0 aarch64) 2>&1 )"; rc=$?
check_rc "Risc0/aarch64 refused" 2 $rc
grep -q "native-x86_64-only" <<<"$out" \
  && ok "Risc0/aarch64 refusal cites the VENUE architecture rule" \
  || bad "Risc0/aarch64 refusal should cite the x86_64-only rule; got: $out"

# ---- resolve_tool_identity_file: fail-closed selection ----------------------
mk() { # <path> <arch-field-or-empty>
  if [ -n "$2" ]; then
    printf '{"candidate":"Sp1","arch":"%s","rust_version":"1.88.0","proof_tools":[]}\n' "$2" > "$1"
  else
    printf '{"candidate":"Sp1","rust_version":"1.88.0","proof_tools":[]}\n' > "$1"
  fi
}
GOOD="$TMPD/ti.good.$$.json"; WRONG="$TMPD/ti.wrong.$$.json"; NOARCH="$TMPD/ti.noarch.$$.json"
mk "$GOOD" x86_64; mk "$WRONG" aarch64; mk "$NOARCH" ""

( unset SP1_TOOL_IDENTITY_X86_64; resolve_tool_identity_file Sp1 x86_64 ) >/dev/null 2>&1
check_rc "absent ratified variable -> NOT_YET_REPRODUCED" 3 $?

( SP1_TOOL_IDENTITY_X86_64="$TMPD/definitely-absent.$$.json" resolve_tool_identity_file Sp1 x86_64 ) >/dev/null 2>&1
check_rc "named file missing -> refused" 2 $?

( SP1_TOOL_IDENTITY_X86_64="$NOARCH" resolve_tool_identity_file Sp1 x86_64 ) >/dev/null 2>&1
check_rc "identity file without an \"arch\" field -> refused" 2 $?

out="$( (SP1_TOOL_IDENTITY_X86_64="$WRONG" resolve_tool_identity_file Sp1 x86_64) 2>&1 )"; rc=$?
check_rc "cross-architecture identity (aarch64 file under the x86_64 variable) -> refused" 2 $rc
grep -q "cross-architecture or swapped identity" <<<"$out" \
  && ok "swapped identity refusal names the cause" || bad "refusal should name the swap; got: $out"

got="$( (SP1_TOOL_IDENTITY_X86_64="$GOOD" resolve_tool_identity_file Sp1 x86_64) 2>/dev/null )"
[ "$got" = "$GOOD" ] && ok "matching per-arch identity resolves to its path" \
  || bad "correct identity should resolve; got '$got'"
rm -f "$GOOD" "$WRONG" "$NOARCH"

# ---- verify_pins refuses an aarch64 RISC Zero entry in the proposal ---------
# Fields are populated only far enough to reach the architecture rule, so the refusal
# happens before any redirect resolution or download.
probe="$TMPD/ti.pins.$$.json"
python3 - "$FIXTURE" "$probe" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
for t in d["tool_identities"]:
    if t["name"] == "risc0-zkvm":
        t["arch"] = "aarch64"
        t["artifact_identity"] = "https://github.com/risc0/risc0/releases/download/v0/x.tgz"
        t["checksum_hex"] = "0" * 64
        t["install_entrypoint"] = "true"
json.dump(d, open(sys.argv[2], "w"))
PY
out="$(bash "$VERIFY" "$probe" 2>&1)"
grep -q "RISC Zero is native-x86_64-only" <<<"$out" \
  && ok "proposal carrying an aarch64 RISC Zero identity rejected" \
  || bad "an aarch64 RISC Zero tool identity must be rejected; got: $out"
rm -f "$probe"

# ---- tool_identities.sh requires an explicit arch argument ------------------
( bash "$SCRIPTS/tool_identities.sh" "$TMPD" ) >/dev/null 2>&1
check_rc "tool_identities.sh without an arch argument -> refused" 2 $?
( bash "$SCRIPTS/tool_identities.sh" "$TMPD" ppc64le ) >/dev/null 2>&1
check_rc "tool_identities.sh with an unsupported arch -> refused" 2 $?

echo "----"
if [ "$fails" -eq 0 ]; then echo "tool_identity_arch: ALL TESTS PASS"; exit 0
else echo "tool_identity_arch: $fails FAILURE(S)" >&2; exit 1; fi
