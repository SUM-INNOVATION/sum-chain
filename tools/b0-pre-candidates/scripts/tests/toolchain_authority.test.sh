#!/usr/bin/env bash
# Unit test for the B0-FINAL toolchain-authority helpers in lib.sh: the ratified toolchain
# identity is sourced ONLY from the content-addressed record after its BLAKE3 is verified
# against the committed constant, and the arch-neutral build-recipe hash is deterministic.
# No Docker / SDK / venue.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCR="$(cd "$HERE/.." && pwd)"
REPO="$(cd "$SCR/../../.." && pwd)"
REC="$REPO/docs/b0-pre/venue/toolchain-authority.v1.json"
# shellcheck source=../lib.sh
. "$SCR/lib.sh"

F=0; ok(){ printf 'ok    %s\n' "$1"; }; bad(){ printf 'FAIL  %s\n' "$1" >&2; F=1; }
command -v b3sum >/dev/null 2>&1 || { echo "toolchain_authority: SKIPPED (no b3sum)"; exit 0; }
command -v python3 >/dev/null 2>&1 || { echo "toolchain_authority: SKIPPED (no python3)"; exit 0; }

# The committed record must hash to the ratified constant (owner-ratified content address).
[ "$(b3sum "$REC" | awk '{print $1}')" = "$B0_RATIFIED_TOOLCHAIN_AUTHORITY_B3" ] \
  && ok "committed record hashes to the ratified constant" \
  || bad "committed record hash != ratified constant (update BOTH in one commit)"

# Genuine lookups return a 64-hex identity for each eligible key.
for k in "Sp1 x86_64" "Sp1 aarch64" "Risc0 x86_64"; do
  # shellcheck disable=SC2086
  v="$(b0_ratified_toolchain_identity $k "$REC" 2>/dev/null)"
  printf '%s' "$v" | grep -Eq '^[0-9a-f]{64}$' && ok "ratified toolchain identity for $k" || bad "no ratified identity for $k"
done

# A TAMPERED record (any byte changed) is refused — the authority is hash-verified, not trusted.
t="$(mktemp)"; sed 's/2222/2223/' "$REC" > "$t"
( b0_ratified_toolchain_identity Risc0 x86_64 "$t" ) >/dev/null 2>&1 && bad "tampered record accepted" || ok "tampered authority record refused"
rm -f "$t"

# An unknown (candidate,arch) has no ratified identity.
( b0_ratified_toolchain_identity Sp1 mips "$REC" ) >/dev/null 2>&1 && bad "unknown key accepted" || ok "unknown key refused"

# The build-recipe hash is arch-neutral + deterministic, and distinct per candidate.
r1="$(b0_build_recipe_hash sp1)"; r2="$(b0_build_recipe_hash sp1)"; rr="$(b0_build_recipe_hash risc0)"
[ "$r1" = "$r2" ] && [ "$r1" != "$rr" ] && printf '%s' "$r1" | grep -Eq '^[0-9a-f]{64}$' \
  && ok "build-recipe hash deterministic + per-candidate" || bad "build-recipe hash wrong"

echo "----"
if [ "$F" = 0 ]; then echo "toolchain_authority: ALL PASS"; else echo "toolchain_authority: FAILURES" >&2; fi
exit "$F"
