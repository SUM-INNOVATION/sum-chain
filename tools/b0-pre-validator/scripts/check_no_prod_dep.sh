#!/usr/bin/env bash
# Workspace isolation + no-production-dependency guard for the B0-PRE tools.
#
# Asserts (deterministically, no network, read-only):
#   1. the sum-chain workspace excludes tools/ (so the tool crates are not members)
#   2. `cargo metadata --no-deps` for the workspace names no B0-PRE tool crate
#   3. no production Cargo.toml has a dependency edge onto a b0-pre tool crate
#   4. every `b0-pre-vmat` dependency edge is confined to the approved B0 validator
#      + verifier-material-harness paths (nothing else may depend on it)
#   5. b0-pre-vmat is a pure blake3-only leaf: no edge to the validator/independent
#      crates (no cycle) and no candidate/guest/proof-stack edge
#   6. the committed candidate Cargo.locks are the DEPENDENCY-SELECTION AUTHORITY: each canonical
#      lock is present, Git-tracked, a regular non-symlink nonempty file, and byte-identical to its
#      ratified SHA-256. The venue materializes THESE exact bytes under `cargo --locked`;
#      unconstrained in-container reselection (`cargo generate-lockfile`) is forbidden.
#
# ROOT resolves from this script's location, or from $CHECK_ROOT when set (the
# regression harness points it at a fixture).
#
# Exit 0 = isolated; non-zero = a violation was found.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
# The committed-candidate-lock AUTHORITY is the single source of truth shared with the venue
# measurement preflight (b0-pre-candidates/scripts/preflight_venue.sh), so the two gates enforce
# byte-identical canonical paths + ratified hashes and cannot drift. The file has no side effects.
# shellcheck source=../../b0-pre-candidates/scripts/committed_lock_authority.sh
. "$HERE/../../b0-pre-candidates/scripts/committed_lock_authority.sh"

ROOT="${CHECK_ROOT:-$(cd "$HERE/../../.." && pwd)}"
cd "$ROOT"

fail=0
note() { printf '%s\n' "$*"; }
bad()  { printf 'FAIL: %s\n' "$*"; fail=1; }

# 1. workspace excludes tools/
if grep -Eq '^\s*exclude\s*=\s*\[[^]]*"tools"' Cargo.toml; then
  note "PASS: root workspace excludes tools/"
else
  bad "root Cargo.toml does not exclude tools/"
fi

# 2. cargo metadata (no network: --no-deps does not resolve the dependency graph)
meta="$(cargo metadata --no-deps --format-version 1 --manifest-path Cargo.toml 2>/dev/null || true)"
refs="$(printf '%s' "$meta" | { grep -oE 'b0-pre-(validator|independent|vmat)' || true; } | sort -u | wc -l | tr -d ' ')"
if [ "$refs" = "0" ]; then
  note "PASS: workspace metadata references 0 B0-PRE tool crates"
else
  bad "workspace metadata references $refs B0-PRE tool crate(s)"
fi

# 3. no production Cargo.toml (outside tools/) depends on a tool crate
hits="$(find . -name Cargo.toml -not -path '*/tools/*' -not -path '*/target/*' \
          -exec grep -l 'b0-pre' {} \; 2>/dev/null || true)"
if [ -z "$hits" ]; then
  note "PASS: no production Cargo.toml references a b0-pre tool crate"
else
  bad "production Cargo.toml references a b0-pre tool crate:"
  printf '%s\n' "$hits"
fi

# 4. every b0-pre-vmat edge is confined to the approved paths. This scans ALL
#    Cargo.toml (production AND tools/), so a rogue edge anywhere is caught.
approved_vmat="./tools/b0-pre-vmat/Cargo.toml
./tools/b0-pre-validator/Cargo.toml
./tools/b0-pre-candidates/harness/sp1-verifier-material/Cargo.toml
./tools/b0-pre-candidates/harness/risc0-verifier-material/Cargo.toml"
vmat_edges="$(find . -name Cargo.toml -not -path '*/target/*' \
                -exec grep -l 'b0-pre-vmat' {} \; 2>/dev/null || true)"
while IFS= read -r f; do
  [ -z "$f" ] && continue
  if printf '%s\n' "$approved_vmat" | grep -Fxq "$f"; then
    note "PASS: approved b0-pre-vmat edge in $f"
  else
    bad "b0-pre-vmat dependency edge outside approved paths: $f"
  fi
done <<EOF
$vmat_edges
EOF

# 5. b0-pre-vmat is a pure blake3-only leaf: no dependency-edge line onto the
#    validator/independent crates (no cycle) or any candidate/guest/proof-stack
#    crate. Matched at line start (`name =`) so the prose description does not
#    false-positive.
VMAT_TOML="tools/b0-pre-vmat/Cargo.toml"
if [ -f "$VMAT_TOML" ]; then
  if grep -Eq '^[[:space:]]*(b0-pre-(validator|independent)|sp1|risc0|risc0-zkvm|risc0-groth16)[[:space:]]*=' "$VMAT_TOML"; then
    bad "b0-pre-vmat has a forbidden dependency edge (cycle / candidate / guest / proof-stack)"
  else
    note "PASS: b0-pre-vmat is a leaf (no validator/candidate/guest edge, no cycle)"
  fi
fi

# 6. the committed candidate Cargo.locks are the DEPENDENCY-SELECTION AUTHORITY. Enforced via the
#    SHARED single-source-of-truth helper (committed_lock_authority.sh) the venue preflight also
#    consumes: each canonical lock must be present, Git-tracked, a regular non-symlink nonempty file,
#    and byte-identical to its ratified SHA-256. The venue materializes THESE exact bytes under
#    `cargo --locked`; unconstrained in-container reselection (`cargo generate-lockfile`) is forbidden.
require_committed_lock_authority "$ROOT" || fail=1

exit "$fail"
