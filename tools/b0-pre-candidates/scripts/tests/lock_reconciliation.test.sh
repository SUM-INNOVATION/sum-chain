#!/usr/bin/env bash
# Failure matrix for the committed-candidate-lock reconciliation (Commit A).
#
# The committed `candidates/<cand>/Cargo.lock` is the SOURCE OF TRUTH; the authoritative resolver
# regenerates a fresh lock in-container and requires it BYTE-IDENTICAL, never rewriting the
# committed lock. This shell test exercises the off-venue gate `require_committed_lock` (present,
# regular, non-empty, non-symlink). The generated-vs-committed byte-identity, host-origin, and
# hash-recompute refusals are exercised by the Rust `lock_provenance` unit tests (`verify-lock`).
# No Docker / builder image is needed here.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCR="$(cd "$HERE/.." && pwd)"
# shellcheck source=../lib.sh
. "$SCR/lib.sh"

F=0
ok() { printf 'ok    %s\n' "$1"; }
bad() { printf 'FAIL  %s\n' "$1" >&2; F=1; }

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
mkdir -p "$tmp/cand"

# A MISSING committed lock is refused (the venue never writes a fresh lock into the tree).
( require_committed_lock "$tmp/cand" ) >/dev/null 2>&1 \
  && bad "missing committed lock accepted" || ok "missing committed lock refused"

# An EMPTY committed lock is refused.
: > "$tmp/cand/Cargo.lock"
( require_committed_lock "$tmp/cand" ) >/dev/null 2>&1 \
  && bad "empty committed lock accepted" || ok "empty committed lock refused"

# A SYMLINK committed lock is refused (no indirection to an out-of-tree file).
rm -f "$tmp/cand/Cargo.lock"
printf 'version = 3\n' > "$tmp/real.lock"
ln -s "$tmp/real.lock" "$tmp/cand/Cargo.lock"
( require_committed_lock "$tmp/cand" ) >/dev/null 2>&1 \
  && bad "symlink committed lock accepted" || ok "symlink committed lock refused"

# A present, regular, non-empty committed lock is accepted (the source of truth).
rm -f "$tmp/cand/Cargo.lock"
printf 'version = 3\n' > "$tmp/cand/Cargo.lock"
( require_committed_lock "$tmp/cand" ) >/dev/null 2>&1 \
  && ok "valid committed lock accepted" || bad "valid committed lock refused"

# The reconciliation intent is present in resolve_lock.sh: require the committed lock, byte-compare
# the generated lock, bind BOTH hashes, never rewrite (guards against silent regression to the old
# "refuse any pre-existing lock" behaviour).
grep -q 'require_committed_lock ' "$SCR/resolve_lock.sh" \
  && ok "resolve_lock requires the committed lock" || bad "resolve_lock no longer requires the committed lock"
grep -q 'cmp -s "\$dest" "\$committed_lock"' "$SCR/resolve_lock.sh" \
  && ok "resolve_lock byte-compares generated vs committed" || bad "resolve_lock missing generated-vs-committed byte compare"
grep -q 'committed_lock_blake3_hex' "$SCR/resolve_lock.sh" \
  && ok "resolve_lock binds the committed-lock hash into provenance" || bad "resolve_lock missing committed-lock hash binding"
grep -q 'require_no_preexisting_lock' "$SCR/resolve_lock.sh" \
  && bad "resolve_lock still refuses a pre-existing (committed) lock" || ok "old pre-existing-lock refusal removed"

echo "----"
if [ "$F" = 0 ]; then echo "lock_reconciliation: ALL PASS"; else echo "lock_reconciliation: FAILURES" >&2; fi
exit "$F"
