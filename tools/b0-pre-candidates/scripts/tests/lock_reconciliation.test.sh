#!/usr/bin/env bash
# Failure matrix for the committed-candidate-lock MATERIALIZATION (Commit A + the corrective
# committed-source-of-truth path).
#
# Owner ruling: the committed `candidates/<cand>/Cargo.lock` is the dependency-selection AUTHORITY.
# The authoritative venue COPIES the committed lock and MATERIALIZES that exact graph under Cargo
# LOCKED semantics (`cargo vendor --locked`, `cargo metadata --locked`, committed lock mounted
# READ-ONLY); it NEVER runs `cargo generate-lockfile` or any unlocked command that could reselect a
# newer semver-compatible release. This shell test exercises the off-venue gate
# `require_committed_lock` (present, regular, non-empty, non-symlink) and asserts resolve_lock.sh's
# corrective intent. The committed-source-of-truth origin, pre/post byte-equality, and hash-recompute
# refusals are exercised by the Rust `lock_provenance` unit tests + `tests/lock_reselection_regression.rs`
# (the http-body-util 0.1.4-passes / 0.1.5-drift-refused fixture over the REAL committed locks). No
# Docker / builder image is needed here.
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

# ---- resolve_lock.sh corrective intent (committed-source-of-truth materialization) -------------
RL="$SCR/resolve_lock.sh"

grep -q 'require_committed_lock ' "$RL" \
  && ok "resolve_lock requires the committed lock" || bad "resolve_lock no longer requires the committed lock"

# The committed lock is COPIED out (not regenerated) and the exported copy is byte-identical.
grep -q 'cp "\$committed_lock" "\$dest"' "$RL" \
  && ok "resolve_lock copies the committed lock (never regenerates it)" || bad "resolve_lock does not copy the committed lock"
grep -q 'cmp -s "\$committed_lock" "\$dest"' "$RL" \
  && ok "resolve_lock asserts the exported copy is byte-identical" || bad "resolve_lock missing committed-vs-export byte compare"

# The authoritative materialization NEVER regenerates the lock: `gen_lock_in_container` is used ONLY
# inside the NON-GATING TEST_ONLY drift diagnostic (over $drift_lock), never over $dest.
grep -q 'gen_lock_in_container "\$BUILDER_IMAGE_REF" "\$cand_dir" "\$dest"' "$RL" \
  && bad "resolve_lock still regenerates the lock in-container (generate-lockfile defect)" \
  || ok "resolve_lock does not regenerate the authoritative lock (no generate-lockfile over the export)"
grep -q 'B0PRE_TESTONLY_LOCK_DRIFT_DIAG' "$RL" \
  && ok "resolve_lock keeps the drift diagnostic behind a TEST_ONLY, non-gating flag" \
  || bad "resolve_lock missing the gated TEST_ONLY drift diagnostic"

# Materialization is under LOCKED semantics + the new provenance/origin is bound.
grep -q 'committed-source-of-truth' "$RL" \
  && ok "resolve_lock records committed-source-of-truth origin" || bad "resolve_lock missing committed-source-of-truth origin"
grep -q 'committed_lock_sha256_hex' "$RL" && grep -q 'committed_lock_blake3_hex' "$RL" \
  && ok "resolve_lock binds committed SHA-256 + BLAKE3 into provenance" || bad "resolve_lock missing committed sha256/blake3 binding"
grep -q 'post_lock_sha256_hex' "$RL" \
  && ok "resolve_lock records the post-run sha256 (pre/post byte equality)" || bad "resolve_lock missing post-run sha256"
grep -q 'verify-lock "\$prov" "\$committed_lock"' "$RL" \
  && ok "resolve_lock re-verifies via verify-lock over the committed lock (2-arg)" || bad "resolve_lock missing 2-arg verify-lock over the committed lock"

# The old "refuse any pre-existing lock" behaviour must stay gone.
grep -q 'require_no_preexisting_lock' "$RL" \
  && bad "resolve_lock still refuses a pre-existing (committed) lock" || ok "old pre-existing-lock refusal removed"

echo "----"
if [ "$F" = 0 ]; then echo "lock_reconciliation: ALL PASS"; else echo "lock_reconciliation: FAILURES" >&2; fi
exit "$F"
