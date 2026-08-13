#!/usr/bin/env bash
# SINGLE SOURCE OF TRUTH for the committed candidate-lock AUTHORITY.
#
# Consumed by BOTH the CI workspace-isolation guard (b0-pre-validator/scripts/check_no_prod_dep.sh)
# and the native-venue measurement preflight (b0-pre-candidates/scripts/preflight_venue.sh), so the
# two gates cannot drift on the canonical lock paths or their ratified hashes.
#
# Authoritative model: the committed candidate Cargo.locks ARE the dependency-selection authority.
# The venue materializes their exact graph under `cargo --locked` (the committed lock mounted
# READ-ONLY); unconstrained authoritative reselection (`cargo generate-lockfile`) is forbidden.
#
# This file has NO top-level side effects (no `set`, no execution) — it only defines constants and
# functions, so it is safe to source from a script with its own shell options and helpers.

# The two canonical committed candidate locks (repo-root-relative), the exact authority set.
COMMITTED_LOCK_PATHS=(
  "tools/b0-pre-candidates/candidates/sp1/Cargo.lock"
  "tools/b0-pre-candidates/candidates/risc0/Cargo.lock"
)

# The ratified SHA-256 of each canonical lock (the byte-frozen authority).
committed_lock_ratified_sha256() {  # <canonical-path> -> ratified sha256 ('' if unknown)
  case "$1" in
    tools/b0-pre-candidates/candidates/sp1/Cargo.lock)
      printf 'f48494fedb427bf0cea5f357f3637d4219ac324419b8623e6a660a510157e57c' ;;
    tools/b0-pre-candidates/candidates/risc0/Cargo.lock)
      printf '8949ae62ca2e30c9ecec19efe58a7260c4c527975aa5903a22be6edddaf8be8f' ;;
    *) printf '' ;;
  esac
}

_committed_lock_sha256() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}'
  else shasum -a 256 "$1" | awk '{print $1}'; fi
}

# require_committed_lock_authority <repo-root>
# Print one PASS/FAIL line per canonical lock; return 0 iff BOTH locks are: present, Git-tracked, a
# regular non-symlink nonempty file, and byte-identical to their ratified SHA-256. Fail-closed.
require_committed_lock_authority() {
  local root="$1" rc=0 rel abs want got
  for rel in "${COMMITTED_LOCK_PATHS[@]}"; do
    abs="$root/$rel"
    want="$(committed_lock_ratified_sha256 "$rel")"
    if [ -z "$want" ]; then
      printf 'FAIL: no ratified sha256 registered for %s\n' "$rel"; rc=1; continue
    fi
    if [ ! -e "$abs" ]; then
      printf 'FAIL: committed candidate lock ABSENT (it is the dependency-selection authority): %s\n' "$rel"; rc=1; continue
    fi
    if [ -L "$abs" ]; then
      printf 'FAIL: committed candidate lock is a symlink (must be a regular file): %s\n' "$rel"; rc=1; continue
    fi
    if [ ! -f "$abs" ]; then
      printf 'FAIL: committed candidate lock is not a regular file: %s\n' "$rel"; rc=1; continue
    fi
    if [ ! -s "$abs" ]; then
      printf 'FAIL: committed candidate lock is empty: %s\n' "$rel"; rc=1; continue
    fi
    if ! git -C "$root" ls-files --error-unmatch -- "$rel" >/dev/null 2>&1; then
      printf 'FAIL: committed candidate lock is not Git-tracked (must be committed, not an untracked drop-in): %s\n' "$rel"; rc=1; continue
    fi
    got="$(_committed_lock_sha256 "$abs")"
    if [ "$got" != "$want" ]; then
      printf 'FAIL: committed candidate lock SHA-256 mismatch (the materialized-under---locked authority is byte-frozen): %s got %s != ratified %s\n' "$rel" "$got" "$want"; rc=1; continue
    fi
    printf 'PASS: committed candidate lock authority OK (%s sha256 %s)\n' "$rel" "$want"
  done
  return "$rc"
}

# committed_lock_authority_extra_locks <repo-root> <git-pathspec...>
# Echo every GIT-TRACKED Cargo.lock under the given pathspecs that is NOT one of the two authority
# locks (exact-set enforcement). Empty output = no unexpected committed lock. No side effects.
committed_lock_authority_extra_locks() {
  local root="$1"; shift
  git -C "$root" ls-files -- "$@" 2>/dev/null \
    | grep -E '(^|/)Cargo\.lock$' \
    | grep -vxF "${COMMITTED_LOCK_PATHS[0]}" \
    | grep -vxF "${COMMITTED_LOCK_PATHS[1]}" || true
}
