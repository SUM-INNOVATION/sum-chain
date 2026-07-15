#!/usr/bin/env bash
# Workspace isolation + no-production-dependency guard for the B0-PRE tools.
#
# Asserts (deterministically, no network, read-only):
#   1. the sum-chain workspace excludes tools/ (so the tool crates are not members)
#   2. `cargo metadata --no-deps` for the workspace names neither tool crate
#   3. no production Cargo.toml has a dependency edge onto a b0-pre tool crate
#
# Exit 0 = isolated; non-zero = a violation was found.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
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
refs="$(printf '%s' "$meta" | { grep -oE 'b0-pre-(validator|independent)' || true; } | sort -u | wc -l | tr -d ' ')"
if [ "$refs" = "0" ]; then
  note "PASS: workspace metadata references 0 B0-PRE tool crates"
else
  bad "workspace metadata references $refs B0-PRE tool crate(s)"
fi

# 3. no production Cargo.toml depends on a tool crate
hits="$(find . -name Cargo.toml -not -path '*/tools/*' -not -path '*/target/*' \
          -exec grep -l 'b0-pre' {} \; 2>/dev/null || true)"
if [ -z "$hits" ]; then
  note "PASS: no production Cargo.toml references a b0-pre tool crate"
else
  bad "production Cargo.toml references a b0-pre tool crate:"
  printf '%s\n' "$hits"
fi

exit "$fail"
