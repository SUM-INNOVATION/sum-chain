#!/usr/bin/env bash
# B0-PRE native-venue readiness preflight (#123/#101).
#
# ONE push-button, read-only, off-venue-SAFE check that the authoritative pipeline
# is READY to target the OFFICIAL candidate guests (guest-core + the two thin
# candidate wrappers) — WITHOUT a prover toolchain, a container build, or cloud credits. It
# exercises every non-proving, venue-independent part and prints a precise VERIFIED-vs-GATED
# boundary, so that when a native Linux venue + credits arrive the actual
# prove/measure run is push-button.
#
# It FABRICATES NOTHING. No proof, program/image id, receipt, measured cost,
# allowlist entry, or protocol `.hash` is produced; the protocol artifact stays
# `not_finalizable`. Off-venue, the authoritative producers MUST fail closed, and
# this preflight ASSERTS exactly that (a green preflight off-venue is a readiness
# statement, never a proof of a venue run).
#
# Exit 0 = every locally-verifiable readiness check passed AND the venue
# prove/measure stages remain GATED / VENUE-REQUIRED by design. A green local
# preflight is NOT authoritative venue readiness. Non-zero = a readiness check
# failed (or a fabricated venue artifact leaked in).
#
# Usage: preflight_venue.sh [--deep] [--mode=preregistration|measurement]
#   --deep  additionally run the cargo-backed OFFLINE proofs: the container-context
#           staging test (proves the staged guest graph resolves under `cargo
#           metadata --offline`) and the guest-core official-workload acceptance
#           example. Needs the validator + guest-core deps already fetched; if
#           `cargo` is absent the deep proofs are SKIPPED (not failed) with a note.
#   --mode  lifecycle phase (default: preregistration).
#           preregistration = the real b0_pre_spec_hash is NOT written yet
#             (committed artifact not_finalizable, no spec-hash sidecar).
#           measurement     = the spec hash is merged (committed artifact
#             finalizable, b0-pre-protocol-v1.json.hash == the merged hash);
#             --deep then emits the MATERIALIZED official guest inputs.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
REPO="$(cd "$ROOT/../.." && pwd)"
DOCS="$REPO/docs/b0-pre"
VAL="$ROOT/../b0-pre-validator/Cargo.toml"
# The committed-candidate-lock AUTHORITY (single source of truth shared with the CI workspace guard
# b0-pre-validator/scripts/check_no_prod_dep.sh) — same canonical paths + ratified hashes, no drift.
# shellcheck source=committed_lock_authority.sh
. "$HERE/committed_lock_authority.sh"

# The real, merged b0_pre_spec_hash (measurement mode binds to EXACTLY this).
MERGED_SPEC_HASH="201cfcb80e94a5a7845dc3380cde32171d40f325ae2bacde9547f3c0da3c4df3"

DEEP=0
MODE=preregistration
for arg in "$@"; do
  case "$arg" in
    --deep) DEEP=1 ;;
    --mode=*) MODE="${arg#--mode=}" ;;
    --mode) printf 'preflight_venue.sh: use --mode=<preregistration|measurement>\n' >&2; exit 2 ;;
    *) printf 'usage: preflight_venue.sh [--deep] [--mode=preregistration|measurement]\n' >&2; exit 2 ;;
  esac
done
case "$MODE" in
  preregistration|measurement) ;;
  *) printf 'preflight_venue.sh: --mode must be preregistration|measurement (got %s)\n' "$MODE" >&2; exit 2 ;;
esac

fail=0
pass() { printf 'PASS: %s\n' "$*"; }
bad()  { printf 'FAIL: %s\n' "$*"; fail=1; }
skip() { printf 'SKIP: %s\n' "$*"; }
hdr()  { printf '\n== %s ==\n' "$*"; }

# check "<pass msg>" "<fail msg>" <cmd...> : PASS when <cmd> exits 0, else FAIL.
check() {
  local okmsg="$1" failmsg="$2"; shift 2
  if "$@" >/dev/null 2>&1; then pass "$okmsg"; else bad "$failmsg"; fi
}

# refute "<pass msg>" "<fail msg>" <cmd...> : PASS when <cmd> exits NONZERO.
refute() {
  local okmsg="$1" failmsg="$2"; shift 2
  if "$@" >/dev/null 2>&1; then bad "$failmsg"; else pass "$okmsg"; fi
}

# must_fail "<label>" <cmd...> : PASS when <cmd> exits NONZERO (a fail-closed guard).
must_fail() {
  local label="$1"; shift
  if "$@" >/dev/null 2>&1; then
    bad "$label should have failed closed but exited 0"
  else
    pass "$label fails closed (nonzero)"
  fi
}

# True on a native Linux + reachable Docker daemon (a real candidate venue). The
# authoritative producers only run there; off-venue they must fail closed.
on_venue() {
  [ "$(uname -s)" = "Linux" ] && command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1
}

# True when any Cargo.lock exists under the given root(s).
has_lock_in() { find "$@" -name Cargo.lock -print 2>/dev/null | grep -q .; }

# ---------------------------------------------------------------------------
hdr "1. OFFICIAL-GUEST WIRING (candidate-neutral core + thin wrappers)"
# Each candidate guest is a thin src/main.rs wrapper that routes through the SHARED
# candidate-neutral b0-pre-guest-core (so both candidates prove logically identical
# statements). No placeholder src/lib.rs; the path deps point at the official graph.
for cand in sp1 risc0; do
  g="$ROOT/candidates/$cand/guest"
  check "$cand guest has official entrypoint (src/main.rs)" \
        "$cand guest is missing src/main.rs" test -f "$g/src/main.rs"
  refute "$cand guest carries no placeholder src/lib.rs" \
         "$cand guest still carries a placeholder src/lib.rs" test -f "$g/src/lib.rs"
  check "$cand guest routes through b0_pre_guest_core::run" \
        "$cand guest does not route through b0_pre_guest_core::run" \
        grep -q 'b0_pre_guest_core::run' "$g/src/main.rs"
  check "$cand guest path-deps ../../../guest-core (official core)" \
        "$cand guest does not path-dep ../../../guest-core" \
        grep -Eq 'b0-pre-guest-core[[:space:]]*=.*path[[:space:]]*=[[:space:]]*"\.\./\.\./\.\./guest-core"' "$g/Cargo.toml"
done
# guest-core adopts the FROZEN production wire types directly (no mirror).
check "guest-core path-deps ../../../crates/sumchain-wire (frozen wire types, no mirror)" \
      "guest-core does not path-dep ../../../crates/sumchain-wire" \
      grep -Eq 'sumchain-wire[[:space:]]*=.*path[[:space:]]*=[[:space:]]*"\.\./\.\./\.\./crates/sumchain-wire"' "$ROOT/guest-core/Cargo.toml"
# Committed candidate locks are the DEPENDENCY-SELECTION AUTHORITY (shared with the CI guard): the
# two canonical candidate Cargo.locks MUST be present, Git-tracked, regular, non-symlink, nonempty,
# and byte-identical to their ratified SHA-256; the venue materializes THEIR exact graph under
# `cargo --locked` (mounted read-only) and never reselects (`cargo generate-lockfile` is forbidden).
require_committed_lock_authority "$REPO" || fail=1
# Exact-set: NO OTHER committed Cargo.lock may exist in the guest graph — not guest-core's, not a
# candidate guest's, not an extra candidate's. A host-only, gitignored guest-core/Cargo.lock left by
# `cargo test` is fine (never committed; stage_context.sh strips it, verified in §2) — this checks
# GIT-TRACKED files only, not on-disk build artifacts.
extra_locks="$(committed_lock_authority_extra_locks "$REPO" \
  tools/b0-pre-candidates/candidates tools/b0-pre-candidates/guest-core)"
if [ -n "$extra_locks" ]; then
  bad "unexpected committed Cargo.lock(s) in the guest graph (only the two authority locks are allowed): $extra_locks"
else
  pass "no unexpected committed Cargo.lock in the guest graph (exact authority set)"
fi

# ---------------------------------------------------------------------------
hdr "2. CONTAINER-CONTEXT STAGING (off-venue safe: filesystem only, no Docker)"
# stage_context.sh reproduces ONLY the official guest dep graph at its exact
# repo-relative layout, so the in-container path deps + `.workspace` inheritance
# resolve. Verified here purely on the filesystem; no Docker / toolchain.
stage_root="$(mktemp -d "${TMPDIR:-/tmp}/b0pre-preflight.XXXXXX")"
trap 'rm -rf "$stage_root"' EXIT
for cand in sp1 risc0; do
  s="$stage_root/$cand"
  if bash "$HERE/stage_context.sh" "$cand" "$s" >/dev/null 2>&1; then
    pass "$cand container context staged"
  else
    bad "$cand container context staging failed"
    continue
  fi
  # required official-graph members present at reproduced repo-relative paths.
  ok=1
  for rel in \
    "Cargo.toml" \
    "crates/sumchain-wire/Cargo.toml" \
    "tools/b0-pre-candidates/guest-core/Cargo.toml" \
    "tools/b0-pre-candidates/candidates/$cand/guest/src/main.rs" \
    "docs/b0-pre/fixtures/workload/official.json"; do
    if [ ! -e "$s/$rel" ]; then ok=0; bad "$cand staged context missing $rel"; fi
  done
  if [ "$ok" = 1 ]; then pass "$cand staged context reproduces the official guest graph"; fi
  # ISOLATION: only sumchain-wire under crates/, the OTHER candidate absent, no lock.
  if [ "$cand" = sp1 ]; then other=risc0; else other=sp1; fi
  crates_only="$(find "$s/crates" -maxdepth 1 -mindepth 1 -type d -exec basename {} \; | sort | tr '\n' ',')"
  check "$cand staged context isolates crates/ to sumchain-wire only" \
        "$cand staged context leaks unrelated crates under crates/: $crates_only" \
        test "$crates_only" = "sumchain-wire,"
  refute "$cand staged context excludes the other candidate ($other)" \
         "$cand staged context leaks the other candidate ($other)" \
         test -e "$s/tools/b0-pre-candidates/candidates/$other"
  if has_lock_in "$s"; then
    bad "$cand staged context carries a Cargo.lock (the committed authority lock is mounted read-only at build time, never baked into the staged context)"
  else
    pass "$cand staged context carries no Cargo.lock (the committed authority lock is mounted read-only, not staged)"
  fi
done

# ---------------------------------------------------------------------------
hdr "3. PROTOCOL BOUNDARY (lifecycle mode: $MODE)"
check "finalization_readiness.sh: artifact internally consistent" \
      "finalization_readiness.sh reported an inconsistency" \
      bash "$ROOT/../b0-pre-validator/scripts/finalization_readiness.sh"
# Single-source-of-truth lifecycle guard (lib.sh). Run it in a SUBSHELL (bash -c) so
# its fail-closed `die` (exit 2) is reported as a preflight FAIL, never a preflight
# abort; the guard enforces the mode-specific committed-state invariant.
check "lifecycle guard ($MODE) matches the committed protocol state" \
      "lifecycle guard ($MODE) rejected the committed protocol state" \
      bash -c '. "$1" && b0pre_lifecycle_guard "$2" "$3" "$4"' _ \
        "$HERE/lib.sh" "$MODE" "$DOCS" "$MERGED_SPEC_HASH"

# ---------------------------------------------------------------------------
hdr "4. FAIL-CLOSED OFF-VENUE (no venue => no fabricated success)"
# These guards must hold on ANY host and never launch a build:
#  - the genuine-fixture generator refuses the off-venue dry-run (classification separation);
#  - it also fails closed with no pinned image reference supplied.
must_fail "prove_fixture.sh refuses SUMCHAIN_B0PRE_DRYRUN (TEST_ONLY) mode" \
  env SUMCHAIN_B0PRE_DRYRUN=1 VERIFIER_REF=x CMD_LOG=/dev/null SCHEMA_ARCH=X86_64 \
  bash "$HERE/prove_fixture.sh" sp1 x86_64 "$stage_root/must-not-exist.json"
must_fail "prove_fixture.sh fails closed with no VERIFIER_REF" \
  bash "$HERE/prove_fixture.sh" sp1 x86_64 "$stage_root/must-not-exist.json"
# The authoritative producers must fail closed at the Stage-0 environment gate when
# no native builder exists. Only asserted OFF-VENUE — on a real venue this command
# is the authoritative run and must NOT be launched by a preflight.
if on_venue; then
  skip "authoritative produce-arch fail-closed check (this host IS a native venue; the real run is available here, not launched by preflight)"
else
  must_fail "run_authoritative.sh produce-arch fails closed off-venue" \
    bash "$HERE/run_authoritative.sh" produce-arch x86_64 "$stage_root/must-not-exist-ev"
fi

# ---------------------------------------------------------------------------
if [ "$DEEP" = 1 ]; then
  hdr "5. DEEP (cargo-backed OFFLINE proofs)"
  if command -v cargo >/dev/null 2>&1; then
    check "container_context_staging test (staged graph resolves under cargo --offline)" \
          "container_context_staging test failed" \
          cargo test --locked --manifest-path "$VAL" --test container_context_staging
    if [ "$MODE" = measurement ]; then
      check "guest-core emits MATERIALIZED official inputs bound to the merged spec hash" \
            "guest-core measurement-mode emission (materialize_final) failed" \
            cargo run --quiet --manifest-path "$ROOT/guest-core/Cargo.toml" \
              --example emit_official_guest_input -- \
              --measurement "$MERGED_SPEC_HASH" \
              "$DOCS/fixtures/workload/official.json" "$stage_root/guestin"
    else
      check "guest-core ACCEPTS both official statements + emits input blobs (no proof)" \
            "guest-core official-workload acceptance example failed" \
            cargo run --quiet --manifest-path "$ROOT/guest-core/Cargo.toml" \
              --example emit_official_guest_input -- \
              "$DOCS/fixtures/workload/official.json" "$stage_root/guestin"
    fi
  else
    skip "deep cargo proofs (cargo not on PATH)"
  fi
fi

# ---------------------------------------------------------------------------
hdr "GATED / VENUE-REQUIRED — a native Linux venue + cloud credits (NOT exercised here)"
cat <<'GATED'
  The following are intentionally NOT produced off-venue and remain blocked on a
  native Linux + Docker venue with the pinned prover toolchain and cloud credits/compute:
    - two clean OCI builder-image builds + their content-addressed manifest digests
    - in-container `cargo generate-lockfile` -> the authoritative candidate Cargo.lock(s)
    - verifier-material extraction (SP1 per-arch; RISC Zero native x86_64 ONLY)
    - guest ELF build (`cargo prove build` / `cargo risczero build`)
    - program id / verifying key / image id (venue-built guest IDENTITY)
    - genuine Groth16 proof / receipt (kept NON_SELECTION / NOT_AN_OFFICIAL_GUEST)
    - measured cost (cycles, proof bytes, verify/prove/setup ns, RSS)
    - populated GuestProgramAllowlistV1 / r0_guest_set_hash
    - the real b0_pre_spec_hash (protocol .hash)  <-- stays UNWRITTEN
  A GPU is not required by these invoked authoritative commands (`cargo prove build` /
  `cargo risczero build` and the Groth16 verify run on CPU; GPU is optional acceleration
  only, never a gate). What is required is a native Linux + Docker venue, the pinned
  prover toolchain, and cloud credits/compute.
  See docs/b0-pre/venue/{VENUE.md,RUNBOOK.md} and docs/b0-pre/GUEST_SOURCE.md.
GATED

hdr "SUMMARY"
if [ "$fail" = 0 ]; then
  printf 'LOCAL PREFLIGHT PASS\n'
  printf 'AUTHORITATIVE VENUE EXECUTION: NOT RUN\n'
  printf '\n'
  printf 'Every venue-independent (non-proving, non-credit) readiness check passed, and the prove/measure stages\n'
  printf 'remain VENUE-REQUIRED (see above). A green local preflight does NOT establish\n'
  printf 'authoritative venue readiness; nothing was fabricated.\n'
  exit 0
else
  printf 'LOCAL PREFLIGHT FAIL\n'
  printf 'AUTHORITATIVE VENUE EXECUTION: NOT RUN\n'
  printf '\n'
  printf 'At least one readiness check failed (see FAIL lines above).\n'
  exit 1
fi
