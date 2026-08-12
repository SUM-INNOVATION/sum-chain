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

# The three lookups return EXACTLY the owner-ratified native identities (real values accepted;
# old placeholders, stale eff3 SP1 identities, and any other wrong value are thereby rejected).
exp_sp1_x86=4367170fa04c2ab4e00ae4371c0a61c07581a2d6ee35309e1f84f3410d675f5c
exp_sp1_arm=7cbd722e676e1f9c50cb785e17bb6670eef2f5a2752ab067237b42e833451cc0
exp_r0_x86=e8872e7631627130f08c025a83a49d8b46fe91a1300ed5b07d225fa98f1617ff
[ "$(b0_ratified_toolchain_identity Sp1 x86_64 "$REC" 2>/dev/null)" = "$exp_sp1_x86" ] \
  && ok "Sp1/x86_64 == ratified native identity" || bad "Sp1/x86_64 != ratified native identity"
[ "$(b0_ratified_toolchain_identity Sp1 aarch64 "$REC" 2>/dev/null)" = "$exp_sp1_arm" ] \
  && ok "Sp1/aarch64 == ratified native identity" || bad "Sp1/aarch64 != ratified native identity"
[ "$(b0_ratified_toolchain_identity Risc0 x86_64 "$REC" 2>/dev/null)" = "$exp_r0_x86" ] \
  && ok "Risc0/x86_64 == ratified native identity" || bad "Risc0/x86_64 != ratified native identity"

# The old fail-closed placeholders and the stale eff3 SP1 identity must be GONE from the record.
grep -Eq '0{64}|1{64}|2{64}' "$REC" && bad "old placeholder identity still present" || ok "old placeholders absent"
grep -q '8815cd60' "$REC" && bad "stale eff3 x86 SP1 identity still present" || ok "stale eff3 SP1 identity absent"

# RISC Zero is x86_64-only: NO Risc0/aarch64 entry (checked in `entries`, not the prose), and a
# lookup for it is refused.
python3 -c "import json,sys; sys.exit(1 if 'Risc0/aarch64' in (json.load(open('$REC')).get('entries') or {}) else 0)" \
  && ok "no Risc0/aarch64 entry" || bad "forbidden Risc0/aarch64 entry present"
( b0_ratified_toolchain_identity Risc0 aarch64 "$REC" ) >/dev/null 2>&1 && bad "Risc0/aarch64 accepted" || ok "Risc0/aarch64 refused"

# A one-character mutation of any ratified value changes the record's BLAKE3 -> refused
# (the authority is hash-verified against the pinned constant, never trusted byte-wise).
t="$(mktemp)"; sed 's/4367170f/5367170f/' "$REC" > "$t"
( b0_ratified_toolchain_identity Sp1 x86_64 "$t" ) >/dev/null 2>&1 && bad "one-character-mutated record accepted" || ok "one-character mutation refused"
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
