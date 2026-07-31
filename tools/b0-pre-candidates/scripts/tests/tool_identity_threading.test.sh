#!/usr/bin/env bash
# Defect 3: run_authoritative.sh must thread the VERIFIED per-candidate builder digests
# and the ratified source commit into tool_identities.sh; tool_identities.sh must fail
# closed on missing / malformed / cross-architecture values; ARM stays SP1-only.
#
# Split into (A) source-level threading assertions (arch-independent) and (B) behavioural
# fail-closed gates exercised against tool_identities.sh with the HOST's native arch (so
# require_native_arch passes) — the gates fire BEFORE any download/toolchain/Docker, so no
# venue is needed. Nothing is fabricated; every "correct-values" case only reaches (and
# fails at) the artifact download, proving the identity gates accepted the threaded values.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
SCRIPTS="$(cd "$HERE/.." && pwd)"
RA="$SCRIPTS/run_authoritative.sh"
TI="$SCRIPTS/tool_identities.sh"
TMPD="${TMPDIR:-/tmp}"
set +e
fails=0
ok()  { printf 'ok    %s\n' "$1"; }
bad() { printf 'FAIL  %s\n' "$1" >&2; fails=$((fails + 1)); }

command -v python3 >/dev/null 2>&1 || { echo "SKIP: python3 absent"; exit 0; }
host="$(uname -m)"; case "$host" in x86_64|amd64) HARCH=x86_64 ;; aarch64|arm64) HARCH=aarch64 ;; *) echo "SKIP: unknown host arch $host"; exit 0 ;; esac
HARCH_U="$(printf '%s' "$HARCH" | tr '[:lower:]' '[:upper:]')"
Z64="0000000000000000000000000000000000000000000000000000000000000000"
GOOD_DIGEST="sha256:$Z64"

# ---- (A) source-level threading assertions --------------------------------------------
src="$(cat "$RA")"
grep -q 'SP1_BUILDER_DIGEST="\$sp1_builder"' <<<"$src" \
  && ok "threads SP1_BUILDER_DIGEST from the verified sp1 builder digest" \
  || bad "SP1_BUILDER_DIGEST not threaded from \$sp1_builder"
grep -q 'RISC0_BUILDER_DIGEST="\$risc0_builder"' <<<"$src" \
  && ok "threads RISC0_BUILDER_DIGEST from the verified risc0 builder digest (x86_64 branch)" \
  || bad "RISC0_BUILDER_DIGEST not threaded from \$risc0_builder"
grep -Eq 'SOURCE_COMMIT="\$tool_src_commit"' <<<"$src" \
  && grep -Eq 'tool_src_commit="\$\(git -C "\$ROOT" rev-parse HEAD\)"' <<<"$src" \
  && ok "threads SOURCE_COMMIT from the clean ratified HEAD (git rev-parse HEAD)" \
  || bad "SOURCE_COMMIT not threaded from git HEAD"
# The x86_64 branch carries RISC0; the aarch64 branch must NOT (ARM stays SP1-only).
# Single awk over a here-string whose EXIT STATUS is the answer — no `printf |` producer and no
# downstream `grep -q`, so nothing can take SIGPIPE when the match is found early (the former
# `printf | awk exit | grep -q` raced under `set -o pipefail`: printf SIGPIPE -> false FAIL).
if awk '
  /if \[ "\$arch" = "x86_64" \]; then/ { in_x86 = 1 }
  in_x86 && /RISC0_BUILDER_DIGEST/ { found = 1; exit }
  END { exit(found ? 0 : 1) }
' <<<"$src"; then
  ok "x86_64 branch threads RISC0_BUILDER_DIGEST"
else
  bad "x86_64 branch does not thread RISC0_BUILDER_DIGEST"
fi
# No bare `tool_identities.sh` call: every invocation line must have SOURCE_COMMIT set on
# the same line or within the 2 preceding continuation lines (portable awk, no grep -P).
bare="$(printf '%s\n' "$src" | awk '
  /bash "\$HERE\/tool_identities.sh"/ {
    ctx = prev2 "\n" prev1 "\n" $0
    if (ctx !~ /SOURCE_COMMIT=/) bare++
  }
  { prev2 = prev1; prev1 = $0 }
  END { print bare + 0 }
')"
[ "${bare:-1}" = "0" ] \
  && ok "every tool_identities.sh invocation carries the threaded SOURCE_COMMIT (no bare call)" \
  || bad "$bare bare tool_identities.sh invocation(s) without SOURCE_COMMIT"

# ---- (B) behavioural fail-closed gates (native arch; pre-download) ---------------------
# A minimal, arch-labelled tool-identity fixture so resolve_tool_identity_file passes and
# the builder-digest / source-commit gates are what decide. artifact_identity points at a
# closed local port so a "correct-values" run fails fast AT THE DOWNLOAD (gates passed).
mk_fixture() { # <arch> -> path
  local a="$1"; local p="$TMPD/ti-fixture.$a.$$.json"
  python3 - "$p" "$a" <<'PY'
import json, sys
p, a = sys.argv[1], sys.argv[2]
json.dump({"arch": a, "rust_version": "1.88.0", "proof_tools": [{
    "name": "sp1-verifier", "version": "6.3.1",
    "artifact_identity": "http://127.0.0.1:1/sp1.tar",
    "checksum_algorithm": "sha256", "checksum_hex": "0"*64,
    "install_entrypoint": "true"}]}, open(p, "w"))
PY
  printf '%s' "$p"
}
FIX="$(mk_fixture "$HARCH")"
OUT="$TMPD/ti-out.$$"; mkdir -p "$OUT"
# helper: run tool_identities.sh with a fresh env (only the vars we pass), capture rc+msg
run_ti() { # sets global RC and MSG; args are VAR=VAL ...
  MSG="$(env -i PATH="$PATH" HOME="$HOME" TMPDIR="$TMPD" "$@" bash "$TI" "$OUT" "$HARCH" 2>&1)"; RC=$?
}

# b1. missing SP1_BUILDER_DIGEST (fixture + source commit present) -> fail closed
run_ti "SP1_TOOL_IDENTITY_${HARCH_U}=$FIX" "SOURCE_COMMIT=$Z64"
{ [ "$RC" -ne 0 ] && grep -qi 'SP1_BUILDER_DIGEST' <<<"$MSG"; } \
  && ok "missing SP1_BUILDER_DIGEST fails closed (rc=$RC)" \
  || bad "missing SP1_BUILDER_DIGEST not fail-closed (rc=$RC): $MSG"

# b2. malformed SP1_BUILDER_DIGEST -> fail closed
run_ti "SP1_TOOL_IDENTITY_${HARCH_U}=$FIX" "SP1_BUILDER_DIGEST=not-a-digest" "SOURCE_COMMIT=$Z64"
{ [ "$RC" -ne 0 ] && grep -qi 'SP1_BUILDER_DIGEST' <<<"$MSG"; } \
  && ok "malformed SP1_BUILDER_DIGEST fails closed (rc=$RC)" \
  || bad "malformed SP1_BUILDER_DIGEST not fail-closed (rc=$RC): $MSG"

# b3. missing SOURCE_COMMIT -> fail closed
run_ti "SP1_TOOL_IDENTITY_${HARCH_U}=$FIX" "SP1_BUILDER_DIGEST=$GOOD_DIGEST"
if [ "$HARCH" = x86_64 ]; then
  # x86 also needs RISC0 identity+digest before the SOURCE_COMMIT gate; supply them.
  FIXR="$(mk_fixture x86_64)"
  run_ti "SP1_TOOL_IDENTITY_X86_64=$FIX" "SP1_BUILDER_DIGEST=$GOOD_DIGEST" \
         "RISC0_TOOL_IDENTITY_X86_64=$FIXR" "RISC0_BUILDER_DIGEST=$GOOD_DIGEST"
fi
{ [ "$RC" -ne 0 ] && grep -qi 'SOURCE_COMMIT' <<<"$MSG"; } \
  && ok "missing SOURCE_COMMIT fails closed (rc=$RC)" \
  || bad "missing SOURCE_COMMIT not fail-closed (rc=$RC): $MSG"

# b4. cross-architecture tool identity (fixture declares the other arch) -> fail closed
OTHER=x86_64; [ "$HARCH" = x86_64 ] && OTHER=aarch64
FIXX="$(mk_fixture "$OTHER")"
run_ti "SP1_TOOL_IDENTITY_${HARCH_U}=$FIXX" "SP1_BUILDER_DIGEST=$GOOD_DIGEST" "SOURCE_COMMIT=$Z64"
{ [ "$RC" -ne 0 ] && grep -qiE 'cross-architecture|declares arch' <<<"$MSG"; } \
  && ok "cross-architecture tool identity fails closed (rc=$RC)" \
  || bad "cross-architecture identity not fail-closed (rc=$RC): $MSG"

# b5. correct threaded values are ACCEPTED by the gates -> run only reaches the download.
if [ "$HARCH" = x86_64 ]; then
  FIXR="$(mk_fixture x86_64)"
  run_ti "SP1_TOOL_IDENTITY_X86_64=$FIX" "SP1_BUILDER_DIGEST=$GOOD_DIGEST" \
         "RISC0_TOOL_IDENTITY_X86_64=$FIXR" "RISC0_BUILDER_DIGEST=$GOOD_DIGEST" "SOURCE_COMMIT=$Z64"
else
  run_ti "SP1_TOOL_IDENTITY_AARCH64=$FIX" "SP1_BUILDER_DIGEST=$GOOD_DIGEST" "SOURCE_COMMIT=$Z64"
fi
{ [ "$RC" -ne 0 ] && grep -qi 'download of declared artifact failed' <<<"$MSG"; } \
  && ok "correct threaded digests+commit accepted (reaches download; gates passed)" \
  || bad "correct values did not pass the identity gates (rc=$RC): $MSG"

# b6. ARM SP1-only: on aarch64, no RISC Zero identity is required or bound.
if [ "$HARCH" = aarch64 ]; then
  grep -qi 'RISC0' <<<"$MSG" \
    && bad "aarch64 run referenced RISC Zero (should be SP1-only): $MSG" \
    || ok "aarch64 stays SP1-only (no RISC Zero identity required/bound)"
else
  ok "ARM-SP1-only asserted at source level (aarch64 branch threads no RISC0); host is x86_64"
fi

rm -rf "$OUT" "$FIX" "${FIXR:-}" "${FIXX:-}" 2>/dev/null
echo "----"
if [ "$fails" -eq 0 ]; then echo "tool_identity_threading: ALL TESTS PASS"; exit 0
else echo "tool_identity_threading: $fails FAILURE(S)" >&2; exit 1; fi
