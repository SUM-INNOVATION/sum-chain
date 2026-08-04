#!/usr/bin/env bash
# PROVISIONED_TREE/v1 frozen golden + adversarial vectors (cross-implementation equality).
#
# Proves the canonical provisioning-tree digest is reproducible across TWO independent
# implementations — the Rust `venue-verify provisioned-tree-digest` CLI and the standalone
# Python reference `scripts/provisioned_tree_ref.py` (which shares no code with the Rust
# path and hashes via the `b3sum` CLI) — and that both equal a FROZEN golden value. Also
# exercises the adversarial matrix: content / exec-bit / added-file / moved-file mutations
# each change the digest; a top-level `.git` is BOUND (not excluded, the key ADVDB
# difference); absolute and `..` symlink targets are REFUSED.
#
# Runnable on either venue with no cargo test harness: it builds `venue-verify` once and
# then compares the two implementations byte-for-byte. Any drift fails closed (nonzero).
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
CRATE="$(cd "$HERE/../.." && pwd)"          # tests -> scripts -> b0-pre-validator
REF="$CRATE/scripts/provisioned_tree_ref.py"

# The FROZEN golden digest of the golden tree constructed below. Kept in lock-step with the
# Rust `GOLDEN` constant in src/venue/provisioned_tree.rs. A change here is a deliberate
# PROVISIONED_TREE format-version bump, never an accident.
GOLDEN='2cf78171daeb42d4b5a004ffb1d7aa8b341ef1c18a7cd684a8f5a61548fe89af'

fails=0
ok()   { printf 'ok    %s\n' "$1"; }
fail() { printf 'FAIL  %s\n' "$1"; fails=$((fails+1)); }

# --- locate/build the venue-verify CLI ----------------------------------------------------
BIN="$CRATE/target/debug/venue-verify"
if [ ! -x "$BIN" ]; then
  echo "building venue-verify ..."
  ( cd "$CRATE" && cargo build -q --bin venue-verify ) || { echo "cargo build failed"; exit 2; }
fi
[ -x "$BIN" ] || { echo "venue-verify not found at $BIN"; exit 2; }
command -v b3sum   >/dev/null 2>&1 || { echo "b3sum not on PATH (needed by python ref)";   exit 2; }
command -v python3 >/dev/null 2>&1 || { echo "python3 not on PATH (needed by python ref)"; exit 2; }

cli() { "$BIN" provisioned-tree-digest "$1"; }
ref() { python3 "$REF" "$1"; }

# --- construct the golden tree (must match golden_tree() in provisioned_tree.rs) ----------
mk_golden() {
  local d="$1"
  mkdir -p "$d/bin" "$d/lib"
  printf '#!/bin/sh\nexec prover\n' > "$d/bin/prover"; chmod 755 "$d/bin/prover"
  printf '\x00\x01\x02circuit\x03\x04'  > "$d/lib/data.bin"; chmod 644 "$d/lib/data.bin"
  printf 'v6.1.0\n'                     > "$d/VERSION";     chmod 644 "$d/VERSION"
  ln -s bin/prover "$d/prover-latest"
}

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

G="$WORK/golden"; mk_golden "$G"

# 1) Rust CLI reproduces the frozen golden.
c="$(cli "$G")"
[ "$c" = "$GOLDEN" ] && ok "rust CLI == frozen golden" || fail "rust CLI ($c) != golden ($GOLDEN)"

# 2) Python reference reproduces the frozen golden.
r="$(ref "$G")"
[ "$r" = "$GOLDEN" ] && ok "python ref == frozen golden" || fail "python ref ($r) != golden ($GOLDEN)"

# 3) The two independent implementations agree.
[ "$c" = "$r" ] && ok "rust CLI == python ref (cross-impl equality)" || fail "impls disagree: $c vs $r"

# --- adversarial matrix: mutations must change the digest ----------------------------------
M="$WORK/mut-content"; mk_golden "$M"; printf 'v9.9.9\n' > "$M/VERSION"
[ "$(cli "$M")" != "$GOLDEN" ] && ok "content change -> different digest" || fail "content change did not change digest"
[ "$(cli "$M")" = "$(ref "$M")" ] && ok "content mutation: impls agree" || fail "content mutation: impls disagree"

M="$WORK/mut-exec"; mk_golden "$M"; chmod 644 "$M/bin/prover"
[ "$(cli "$M")" != "$GOLDEN" ] && ok "exec-bit change -> different digest" || fail "exec-bit change did not change digest"

M="$WORK/mut-extra"; mk_golden "$M"; printf 'x\n' > "$M/lib/EXTRA.bin"
[ "$(cli "$M")" != "$GOLDEN" ] && ok "added file -> different digest" || fail "added file did not change digest"

M="$WORK/mut-moved"; mk_golden "$M"; mv "$M/VERSION" "$M/lib/VERSION"
[ "$(cli "$M")" != "$GOLDEN" ] && ok "moved file -> different digest" || fail "moved file did not change digest"

# --- the KEY ADVDB difference: a top-level .git is BOUND, not excluded ---------------------
M="$WORK/mut-git"; mk_golden "$M"; mkdir -p "$M/.git"; printf 'ref: refs/heads/main\n' > "$M/.git/HEAD"
[ "$(cli "$M")" != "$GOLDEN" ] && ok ".git is bound (differs from no-.git tree)" || fail ".git was silently excluded"
[ "$(cli "$M")" = "$(ref "$M")" ] && ok ".git case: impls agree" || fail ".git case: impls disagree"

# --- adversarial rejects: unsafe symlink targets must REFUSE (nonzero) ---------------------
M="$WORK/rej-abs"; mk_golden "$M"; ln -s /etc/passwd "$M/evil"
if cli "$M" >/dev/null 2>&1; then fail "absolute symlink target was NOT refused"; else ok "absolute symlink target refused"; fi
if ref "$M" >/dev/null 2>&1; then fail "python ref did NOT refuse absolute symlink"; else ok "python ref refuses absolute symlink"; fi

M="$WORK/rej-parent"; mk_golden "$M"; ln -s ../../outside "$M/escape"
if cli "$M" >/dev/null 2>&1; then fail "parent-traversal symlink was NOT refused"; else ok "parent-traversal symlink refused"; fi

echo
if [ "$fails" -eq 0 ]; then echo "PROVISIONED_TREE/v1 vectors: ALL PASS"; exit 0
else echo "PROVISIONED_TREE/v1 vectors: $fails FAILED"; exit 1; fi
