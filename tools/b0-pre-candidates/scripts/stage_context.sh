#!/usr/bin/env bash
# Stage the curated, minimal, reproduced-layout Docker build context for one B0-PRE
# candidate. This is the authoritative container-context staging: it reproduces ONLY
# the official guest dependency graph
#     candidates/<cand>/guest -> guest-core -> crates/sumchain-wire
# at its exact repo-relative paths, plus a CURATED minimal workspace-root manifest
# (only the `[workspace]` / `[workspace.package]` / `[workspace.dependencies]` sections
# `sumchain-wire` actually inherits) and the frozen guest fixtures. No unrelated
# production crate is copied (isolation). The reproduced repo root maps to `/work` in
# the builder image, so the path deps and `.workspace` inheritance resolve in-container.
#
# It writes NO Cargo.lock (the authoritative lock is generated in-container and bound).
#
# This is off-venue safe (pure filesystem copy; no Docker / toolchain), so the
# structural staging test and `build_container.sh` share ONE implementation.
#
# Usage: stage_context.sh <sp1|risc0> <stage_dir>
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
# shellcheck source=lib.sh
. "$HERE/lib.sh"

candidate="${1:-}"; stage="${2:-}"
case "$candidate" in sp1|risc0) ;; *) die "candidate must be sp1|risc0 (got '${candidate:-}')" ;; esac
[ -n "$stage" ] || die "staging directory argument required"

stage_container_context "$candidate" "$stage"
note "staged curated $candidate container context at $stage (reproduced repo-relative layout; no unrelated crate)"
