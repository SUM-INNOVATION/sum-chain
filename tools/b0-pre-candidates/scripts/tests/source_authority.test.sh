#!/usr/bin/env bash
# Fail-closed source-commit authority tests (owner ruling: option A, enforced in code).
#
# Exercises require_ratified_source_commit against an ISOLATED single-commit temp git
# repo, so the cases are deterministic and independent of the working checkout. Covers:
# absent, malformed/truncated, uppercase, non-hex, valid-but-wrong-HEAD, correct+clean,
# correct+dirty, and correct+untracked. No venue, no toolchain, no network.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=../lib.sh
. "$HERE/../lib.sh"
set +e   # manage pass/fail manually; lib.sh's `set -e` must not abort the harness

fails=0
check_rc() { # <name> <expected_rc> <actual_rc>
  if [ "$2" = "$3" ]; then printf 'ok    %s (rc=%s)\n' "$1" "$3"
  else printf 'FAIL  %s: expected rc %s got %s\n' "$1" "$2" "$3" >&2; fails=$((fails + 1)); fi
}

command -v git >/dev/null 2>&1 || { echo "SKIP: git absent"; exit 0; }

REPO="$(mktemp -d "${TMPDIR:-/tmp}/srcauth.XXXXXX")"
git -C "$REPO" init -q
git -C "$REPO" config user.email t@example.invalid
git -C "$REPO" config user.name  tester
: > "$REPO/f"; git -C "$REPO" add f; git -C "$REPO" commit -qm init
HEAD="$(git -C "$REPO" rev-parse HEAD)"   # 40 lowercase hex

# nyr (absent) exits 3; die (all other refusals) exits 2; a clean match exits 0.

# 1. absent value -> NOT_YET_REPRODUCED
( unset RATIFIED_SOURCE_COMMIT; require_ratified_source_commit "$REPO" ) >/dev/null 2>&1
check_rc "absent RATIFIED_SOURCE_COMMIT -> nyr" 3 $?

# 2. malformed / truncated (20 hex, right chars wrong length)
( RATIFIED_SOURCE_COMMIT="${HEAD:0:20}" require_ratified_source_commit "$REPO" ) >/dev/null 2>&1
check_rc "truncated (20 hex) -> die" 2 $?

# 3. uppercase (not lowercase hex): force one uppercase char
( RATIFIED_SOURCE_COMMIT="A${HEAD:1}" require_ratified_source_commit "$REPO" ) >/dev/null 2>&1
check_rc "uppercase char -> die" 2 $?

# 4. non-hex (contains 'z')
( RATIFIED_SOURCE_COMMIT="z${HEAD:1}" require_ratified_source_commit "$REPO" ) >/dev/null 2>&1
check_rc "non-hex char -> die" 2 $?

# 5. valid 40 lowercase hex but WRONG HEAD (all zeros)
ZEROS="$(printf '%s' "$HEAD" | tr '0-9a-f' '0')"   # exactly-40 zeros
( RATIFIED_SOURCE_COMMIT="$ZEROS" require_ratified_source_commit "$REPO" ) >/dev/null 2>&1
check_rc "valid-format but wrong HEAD -> die" 2 $?

# 6. correct value + clean checkout -> pass
( RATIFIED_SOURCE_COMMIT="$HEAD" require_ratified_source_commit "$REPO" ) >/dev/null 2>&1
check_rc "correct + clean checkout -> pass" 0 $?

# 7. correct value but DIRTY tracked file -> die
echo dirty > "$REPO/f"
( RATIFIED_SOURCE_COMMIT="$HEAD" require_ratified_source_commit "$REPO" ) >/dev/null 2>&1
check_rc "correct but dirty tracked file -> die" 2 $?
git -C "$REPO" checkout -q -- f

# 8. correct value, clean tracked tree, but an UNTRACKED file -> die (pristine required)
echo scratch > "$REPO/untracked"
( RATIFIED_SOURCE_COMMIT="$HEAD" require_ratified_source_commit "$REPO" ) >/dev/null 2>&1
check_rc "correct but untracked file present -> die" 2 $?
rm -f "$REPO/untracked"

rm -rf "$REPO"
echo "----"
if [ "$fails" -eq 0 ]; then echo "source_authority: ALL TESTS PASS"; exit 0
else echo "source_authority: $fails FAILURE(S)" >&2; exit 1; fi
