#!/usr/bin/env bash
# Shared validation / refusal helpers for the B0-PRE candidate build scripts.
#
# Every helper is fail-closed: missing or malformed inputs cause a clear
# NOT_YET_REPRODUCED / refusal exit BEFORE any build, download, or extraction.
# Nothing here installs host-global tooling, starts a daemon, or pushes an image.

set -euo pipefail

die()  { printf 'REFUSED: %s\n' "$*" >&2; exit 2; }
note() { printf '%s\n' "$*"; }
nyr()  { printf 'NOT_YET_REPRODUCED: %s\n' "$*" >&2; exit 3; }

# A full, immutable OCI digest: sha256:<64 lowercase hex>. Rejects mutable tags,
# truncated digests, image IDs, and empty input.
require_full_sha256_digest() {
  local name="$1" val="${2:-}"
  [ -n "$val" ] || nyr "$name is empty; an immutable sha256:<64hex> digest is required"
  case "$val" in
    sha256:*) ;;
    *) die "$name must be a full 'sha256:<64hex>' digest, not a tag or image ID: '$val'" ;;
  esac
  local hex="${val#sha256:}"
  printf '%s' "$hex" | grep -Eq '^[0-9a-f]{64}$' \
    || die "$name is not a full 64-hex sha256 digest (truncation/uppercase/tag rejected): '$val'"
}

# Refuse anything that looks like a placeholder digest.
reject_placeholder() {
  local name="$1" val="${2:-}"
  case "$val" in
    *DEADBEEF*|*deadbeef*|*000000000000*|*TODO*|*PLACEHOLDER*|*xxxx*|*XXXX*)
      die "$name looks like a placeholder, not a real digest: '$val'" ;;
  esac
}

# The build/extract steps must run natively on the requested architecture; no
# emulation. Compares the requested arch to the kernel arch.
require_native_arch() {
  local want="$1" have
  have="$(uname -m)"
  case "$have" in x86_64|amd64) have=x86_64 ;; aarch64|arm64) have=aarch64 ;; esac
  case "$want" in x86_64|amd64) want=x86_64 ;; aarch64|arm64) want=aarch64 ;; esac
  [ "$want" = "$have" ] \
    || die "native $want builder required; this host is $have (emulation is ineligible)"
}

# A Linux OCI-capable builder must be present. Fail-closed if the daemon is down
# or the platform is not Linux.
require_linux_oci_builder() {
  [ "$(uname -s)" = "Linux" ] || die "authoritative builds require a native Linux builder; host is $(uname -s)"
  command -v docker >/dev/null 2>&1 || die "no OCI builder (docker) on PATH"
  docker info >/dev/null 2>&1 || die "OCI builder daemon is not running/reachable"
}

# A ratified source commit is EXACTLY 40 lowercase hex (a full git SHA-1). Rejects
# uppercase, non-hex, truncation, and 64-hex. Returns 0/non-0; prints nothing.
is_ratified_commit_format() {
  printf '%s' "${1:-}" | grep -Eq '^[0-9a-f]{40}$'
}

# Fail-closed authoritative source-commit authority: bind the run to the owner-ratified
# `RATIFIED_SOURCE_COMMIT` (from the ratified pins.env). Enforced at authoritative Stage 0
# and at the authoritative import/aggregate boundary — NOT in generic preflight/dev
# checks. Requires the variable present, exactly 40 lowercase hex, EQUAL to <repo>'s
# checked-out HEAD, and a clean checkout. The producer separately records the ACTUAL HEAD
# into every typed evidence record; given this gate, that recorded HEAD IS the ratified
# commit, so two operators cannot accidentally agree on a wrong commit. Must run BEFORE
# any dependency resolution, image build, guest build, or evidence generation.
require_ratified_source_commit() {
  local repo="${1:-.}" want="${RATIFIED_SOURCE_COMMIT:-}" head
  [ -n "$want" ] \
    || nyr "RATIFIED_SOURCE_COMMIT is required for an authoritative run (from the ratified pins.env); it is absent"
  is_ratified_commit_format "$want" \
    || die "RATIFIED_SOURCE_COMMIT must be exactly 40 lowercase hex chars (uppercase/non-hex/truncated/64-hex rejected): '$want'"
  head="$(git -C "$repo" rev-parse HEAD 2>/dev/null)" \
    || die "cannot resolve git HEAD in '$repo' for the source-commit authority check"
  [ "$head" = "$want" ] \
    || die "checked-out HEAD ($head) does not equal RATIFIED_SOURCE_COMMIT ($want); refusing authoritative Stage 0"
  [ -z "$(git -C "$repo" status --porcelain 2>/dev/null)" ] \
    || die "checkout is not clean; authoritative evidence requires a pristine checkout of the ratified commit"
}

# A SOURCE_DATE_EPOCH must be a non-empty base-10 integer, positive, and within a sane
# width (<= 18 digits, safely under int64) so it cannot overflow the builder's timestamp
# handling. Rejects empty / non-numeric / negative (the '-' is non-digit) / overflow.
require_valid_source_date_epoch() {
  local v="${1:-}"
  case "$v" in ''|*[!0-9]*) die "SOURCE_DATE_EPOCH must be a non-empty base-10 integer (got '${v}')" ;; esac
  [ "${#v}" -le 18 ] || die "SOURCE_DATE_EPOCH is too large (overflow risk): '$v'"
  [ "$v" -ge 1 ] || die "SOURCE_DATE_EPOCH must be positive: '$v'"
}

# Canonicalize a rustup toolchain `lib/rustlib/components` file to bytewise C-locale
# lexical order IN PLACE, preserving multiplicity, atomically. rustup writes this file in
# concurrent task-completion order (the authoritative x86 r3 nondeterminism), yet it is the
# unordered SET of installed components — order is not semantically significant. This is the
# REFERENCE implementation; both Dockerfiles inline the identical sequence (they cannot
# source lib.sh). Fails closed on missing/empty/malformed content or an unexpected duplicate
# (rustup components are unique by contract). Deliberately NOT `sort -u`: multiplicity is
# preserved so a duplicate surfaces instead of being silently hidden. Steps: sort to a
# sibling, verify the sorted multiset is unchanged (no line added/lost), verify no duplicate,
# verify the result is sorted, then move into place; temporaries are removed on any failure.
canonicalize_rustup_components() {
  local comp="$1"
  [ -s "$comp" ] || die "rustup components file missing or empty: $comp"
  if grep -qvE '^[A-Za-z0-9._+-]+$' "$comp"; then die "malformed (non-token) line in rustup components: $comp"; fi
  LC_ALL=C sort "$comp" > "$comp.sorted" || { rm -f "$comp.sorted"; die "sort failed for $comp"; }
  LC_ALL=C sort "$comp" > "$comp.a"; LC_ALL=C sort "$comp.sorted" > "$comp.b"
  if ! cmp -s "$comp.a" "$comp.b"; then rm -f "$comp.sorted" "$comp.a" "$comp.b"; die "component multiset changed by canonicalization: $comp"; fi
  if [ -n "$(uniq -d "$comp.sorted")" ]; then rm -f "$comp.sorted" "$comp.a" "$comp.b"; die "unexpected duplicate component in $comp"; fi
  if ! LC_ALL=C sort -c "$comp.sorted"; then rm -f "$comp.sorted" "$comp.a" "$comp.b"; die "canonicalized rustup components not sorted: $comp"; fi
  rm -f "$comp.a" "$comp.b"
  mv -f "$comp.sorted" "$comp"
}

# Validate a Stage-1 resolved candidate lock before it is bind-mounted READ-ONLY into a
# fresh Stage-2 container, and echo its verified domain-separated BLAKE3 hash (the lock
# IDENTITY — a host absolute path is never evidence). Fail closed unless the lock is:
# present, a REGULAR file, NOT a symlink, non-empty, parseable as a Cargo.lock (a version
# header and/or [[package]] tables), candidate-specific and generated-in-container per its
# provenance, and its recomputed hash EQUALS the Stage-1 recorded lock_blake3_hex. This is
# the same content-address gate resolve_lock.sh / verify-lock use; here it re-binds the
# handed-off lock to Stage 2. Args:
#   <lock_file> <provenance_json> <schema_candidate> <validator_manifest>
require_stage1_lock() {
  local lock="$1" prov="$2" cand="$3" val="$4" recomputed p_hash p_cand p_origin
  [ -e "$lock" ] || die "Stage-1 resolved lock absent (Stage 2 needs it mounted): $lock"
  [ ! -L "$lock" ] || die "Stage-1 lock is a symlink; refused (must be a regular file): $lock"
  [ -f "$lock" ] || die "Stage-1 lock is not a regular file: $lock"
  [ -s "$lock" ] || die "Stage-1 lock is empty: $lock"
  grep -qE '^version[[:space:]]*=|^\[\[package\]\]' "$lock" \
    || die "Stage-1 lock is not a parseable Cargo.lock (no version header / [[package]]): $lock"
  [ -f "$prov" ] || die "Stage-1 lock provenance absent: $prov"
  require_cmd python3
  p_cand="$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1])).get("candidate",""))' "$prov" 2>/dev/null || true)"
  p_origin="$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1])).get("origin",""))' "$prov" 2>/dev/null || true)"
  p_hash="$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1])).get("lock_blake3_hex",""))' "$prov" 2>/dev/null || true)"
  [ "$p_cand" = "$cand" ] \
    || die "Stage-1 lock provenance candidate '$p_cand' != '$cand' (cross-candidate / swapped lock)"
  [ "$p_origin" = "generated-in-container" ] \
    || die "Stage-1 lock provenance origin '$p_origin' != generated-in-container (host-originated lock refused)"
  printf '%s' "$p_hash" | grep -Eq '^[0-9a-f]{64}$' || die "Stage-1 lock provenance hash malformed: '$p_hash'"
  recomputed="$(cargo run --quiet --locked --manifest-path "$val" --bin venue-verify -- lock-hash "$lock")" \
    || die "Stage-1 lock hash recomputation failed for $lock"
  [ "$recomputed" = "$p_hash" ] \
    || die "Stage-1 lock hash mismatch: recomputed $recomputed != provenance $p_hash (tampered / stale lock)"
  printf '%s' "$recomputed"
}

# The exact verifier-material harness subdirectory (under $ROOT/harness) for a candidate.
material_harness_subdir() {
  case "${1:-}" in
    sp1)   printf 'sp1-verifier-material' ;;
    risc0) printf 'risc0-verifier-material' ;;
    *) die "material_harness_subdir: candidate must be sp1|risc0 (got '${1:-}')" ;;
  esac
}

# The reproduced in-container path of the material harness. It MUST reproduce the exact
# repo-relative layout so the harness's `b0-pre-vmat = { path = "../../../b0-pre-vmat" }`
# resolves to $INCONTAINER_ROOT/tools/b0-pre-vmat inside the curated context.
incontainer_material_dir() { printf 'tools/b0-pre-candidates/harness/%s' "$1"; }
# The single leaf path-dep of every material harness (reproduced in-container path).
INCONTAINER_VMAT_RELPATH="tools/b0-pre-vmat"

# Validate a GENERATED-IN-CONTAINER verifier-material lock + its provenance (the D2
# analogue of require_stage1_lock). Fail-closed on absent/symlink/non-regular/empty/
# unparseable lock, absent provenance, harness mismatch (swapped), host origin, malformed
# or mismatched hash. Prints the recomputed domain-separated lock hash on success.
require_material_lock() {
  local lock="$1" prov="$2" harness="$3" val="$4" recomputed p_hash p_harness p_origin
  [ -e "$lock" ] || die "material lock absent (extraction needs it validated + mounted): $lock"
  [ ! -L "$lock" ] || die "material lock is a symlink; refused (must be a regular file): $lock"
  [ -f "$lock" ] || die "material lock is not a regular file: $lock"
  [ -s "$lock" ] || die "material lock is empty: $lock"
  grep -qE '^version[[:space:]]*=|^\[\[package\]\]' "$lock" \
    || die "material lock is not a parseable Cargo.lock (no version header / [[package]]): $lock"
  [ -f "$prov" ] || die "material lock provenance absent: $prov"
  require_cmd python3
  p_harness="$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1])).get("harness",""))' "$prov" 2>/dev/null || true)"
  p_origin="$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1])).get("origin",""))' "$prov" 2>/dev/null || true)"
  p_hash="$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1])).get("lock_blake3_hex",""))' "$prov" 2>/dev/null || true)"
  [ "$p_harness" = "$harness" ] \
    || die "material lock provenance harness '$p_harness' != '$harness' (cross-harness / swapped lock)"
  [ "$p_origin" = "generated-in-container" ] \
    || die "material lock provenance origin '$p_origin' != generated-in-container (host-originated lock refused)"
  printf '%s' "$p_hash" | grep -Eq '^[0-9a-f]{64}$' || die "material lock provenance hash malformed: '$p_hash'"
  recomputed="$(cargo run --quiet --locked --manifest-path "$val" --bin venue-verify -- lock-hash "$lock")" \
    || die "material lock hash recomputation failed for $lock"
  [ "$recomputed" = "$p_hash" ] \
    || die "material lock hash mismatch: recomputed $recomputed != provenance $p_hash (tampered / stale lock)"
  printf '%s' "$recomputed"
}

# ---- Shared in-builder Docker cores (ONE implementation for producer + E2E) ----------
# These are the exact docker-run cores the authoritative producer uses. They are factored
# here so the real-container E2E drives the IDENTICAL logic (never a reconstructed command
# sequence): a divergence would be a bug in one caller, not two.

# Generate a Cargo.lock for the crate at $incontainer_dir INSIDE $image (bash -c, matching
# resolve_lock.sh / produce_stage2) and write the bytes to $out_lock. NO host/venue gates
# — callers (resolve_lock.sh) add the clean-tree / digest / origin gates; the E2E calls it
# directly over a fixture. Stderr flows to the caller (which may capture a log).
gen_lock_in_container() {
  local image="$1" incontainer_dir="$2" out_lock="$3"
  require_cmd docker
  docker run --rm --pull never "$image" \
    bash -c "cd $incontainer_dir && cargo generate-lockfile && cat Cargo.lock" > "$out_lock" \
    || return 1
  [ -s "$out_lock" ]
}

# The S1 causal verifier-execution core: BUILD the runner (--locked) inside $image, HASH
# the EXACT resulting binary, and EXEC that file directly (never an unbound `cargo run`,
# whose bytes are unidentified) — all in ONE container invocation so the hashed file is
# byte-for-byte the executed file. The runner crate is at $incontainer_runner_dir with its
# Cargo.lock already generated; $host_out is bind-mounted at /out; the executed-binary
# sha256 is written to /out/runner-bin.sha256 and the runner lock copied to
# /out/runner-cargo.lock; optional $fixture_host mounts read-only at /fixture.json.
#
# DETERMINISTIC EXECUTION ENVIRONMENT (RT-2 fix, authoritative x86 smoke): uses a
# NON-login `bash -c`, NOT `bash -lc`. The pinned builder image puts cargo on PATH via
# `ENV PATH="/root/.cargo/bin:$PATH"`, which a non-login shell honors; a LOGIN shell runs
# /etc/profile, which overwrites PATH and drops /root/.cargo/bin, so `cargo` is not found.
# The Stage-1/2/material steps already use `bash -c`; this brings Stage 5 in line so the
# real image, the tests, and the smoke share one environment. Shared by verifier_fixtures.sh
# (real Stage 5) and the real-container E2E.
causal_build_hash_exec_runner() {
  local image="$1" incontainer_runner_dir="$2" bin_name="$3" host_out="$4" fixture_host="${5:-}"
  require_cmd docker
  local binpath="/tmp/b0pre-stage5-target/release/$bin_name"
  local fmount=() farg=""
  if [ -n "$fixture_host" ]; then fmount=(-v "$fixture_host:/fixture.json:ro"); farg="/fixture.json"; fi
  # `${fmount[@]+...}` guards the empty-array case under `set -u` on bash 3.2 (macOS);
  # bash 4+ (the Linux venue + CI) expands identically.
  docker run --rm --pull never -v "$host_out:/out" ${fmount[@]+"${fmount[@]}"} \
    -e CARGO_TARGET_DIR=/tmp/b0pre-stage5-target "$image" \
    bash -c "cd $incontainer_runner_dir && cargo build --quiet --release --locked && [ -x '$binpath' ] || { echo 'runner binary absent after build' >&2; exit 1; }; sha256sum '$binpath' | awk '{print \$1}' > /out/runner-bin.sha256 && cp $incontainer_runner_dir/Cargo.lock /out/runner-cargo.lock && exec '$binpath' $farg /out"
}

# The Stage-2 read-only-locked execution core: bind-mount the validated Stage-1 lock
# READ-ONLY at $incontainer_lock and run one `cargo … --locked` command ($cmd, e.g.
# `cargo metadata --format-version 1 --locked` or `cargo audit --json`) in $image at
# $cdir, writing stdout to $out. The lock is CONSUMED read-only; nothing is written into
# the candidate workspace. Shared by produce_stage2 (D1) and the real-container E2E so the
# read-only-mount mechanic is one implementation.
run_stage2_locked() {
  local image="$1" cdir="$2" hostlock="$3" incontainer_lock="$4" cmd="$5" out="$6"
  require_cmd docker
  docker run --rm --pull never \
    --mount "type=bind,source=$hostlock,target=$incontainer_lock,readonly" \
    "$image" bash -c "cd $cdir && $cmd" > "$out"
}

# Stage-2 AUDIT execution (D1 + advisory-DB pin). Like run_stage2_locked, but ALSO bind-mounts
# the pinned advisory-DB checkout READ-ONLY at $incontainer_db and runs the cargo-audit argv
# the TRUSTED caller constructed from the structured audit policy (never an operator-supplied
# command string). Because the DB bind is readonly and the constructed argv always carries
# --no-fetch --stale, the scan can neither fetch nor update nor mutate the pinned database:
# a missing or altered DB is a hard failure downstream, never a silently-clean audit. Args:
#   <image> <cdir> <hostlock> <incontainer_lock> <hostdb> <incontainer_db> <out> <argv...>
run_stage2_audit_locked() {
  local image="$1" cdir="$2" hostlock="$3" incontainer_lock="$4" hostdb="$5" incontainer_db="$6" out="$7"
  shift 7
  require_cmd docker
  [ "$#" -ge 1 ] || die "run_stage2_audit_locked: empty audit argv (the trusted caller must construct it from the audit policy)"
  local argv_str; printf -v argv_str '%q ' "$@"
  docker run --rm --pull never \
    --mount "type=bind,source=$hostlock,target=$incontainer_lock,readonly" \
    --mount "type=bind,source=$hostdb,target=$incontainer_db,readonly" \
    "$image" bash -c "cd $(printf '%q' "$cdir") && $argv_str" > "$out"
}

# Builder-image CAPABILITY preflight (Item 6). BEFORE Stage 2 / Stage 5 run inside a VERIFIED
# builder image, assert — AS EARLY AS POSSIBLE — that the image actually carries the pinned
# capabilities, validating VERSIONS + IDENTITIES (never a bare `command -v`). Fails closed with
# a SPECIFIC message on: an unsupported/mismatched architecture; cargo absent from the
# PRODUCTION non-login PATH; cargo-audit absent, the wrong version, or (when an EXPECTED value
# is supplied) the wrong executable SHA-256; and the RT-2 hazard — the tools not resolving under
# the production NON-login `bash -c` shell (a login `bash -lc` sources /etc/profile and can DROP
# the image ENV PATH, so we assert the non-login resolution the producer actually uses). The
# advisory-DB checkout identity is verified by produce_stage2 against the pins; this gate
# confirms the AUDITOR TOOL itself is present + correct so a mis-provisioned image is rejected
# here, not deep inside Stage 2.
#
# cargo-audit identity model (PIN-PROPOSAL.md §6): the ratified inputs are the crate + version +
# crate checksum + packaged-lock checksum + Rust toolchain + build env. The executable SHA-256
# is VENUE EVIDENCE — recorded here, re-checked at point of use, and reproduced by an independent
# same-arch operator; it is NEVER treated as an owner-ratified source pin. So the version arg is
# the ratified pin, and the sha arg is the venue-recorded EXPECTED executable hash. Args:
#   <image> <arch> [ratified_cargo_audit_version] [venue_expected_cargo_audit_exe_sha256]
preflight_builder_capability() {
  local image="$1" arch="$2" want_ca_ver="${3:-}" want_ca_sha="${4:-}"
  require_cmd docker
  # 1. Architecture: the in-container `uname -m` must map to the declared arch.
  local want_uname
  case "$arch" in
    x86_64|X86_64)         want_uname=x86_64 ;;
    aarch64|Aarch64|arm64) want_uname=aarch64 ;;
    *) die "preflight_builder_capability: unsupported arch '$arch' (want x86_64|aarch64)" ;;
  esac
  local uname_m; uname_m="$(docker run --rm --pull never "$image" bash -c 'uname -m' 2>/dev/null || true)"
  [ "$uname_m" = "$want_uname" ] \
    || die "builder-image arch mismatch: container uname -m='${uname_m:-<none>}' != expected '$want_uname' for arch $arch"
  # 2. cargo on the PRODUCTION non-login PATH (RT-2: bash -c, NOT bash -lc).
  docker run --rm --pull never "$image" bash -c 'command -v cargo >/dev/null' 2>/dev/null \
    || die "builder image: cargo is not on the production non-login PATH (bash -c)"
  # 3. cargo-audit present + VERSION validated (not just presence). Absent => Stage-2 audit
  #    cannot execute; a missing tool is never a clean audit.
  local ca_ver
  ca_ver="$(docker run --rm --pull never "$image" bash -c 'command -v cargo-audit >/dev/null && cargo audit --version' 2>/dev/null | head -n1 | sed 's/[[:space:]]*$//' || true)"
  [ -n "$ca_ver" ] \
    || die "builder image: cargo-audit is absent from the production PATH (Stage-2 audit cannot execute; a missing tool is never a clean audit)"
  if [ -n "$want_ca_ver" ]; then
    grep -q "$want_ca_ver" <<<"$ca_ver" \
      || die "builder image: cargo-audit version '$ca_ver' does not contain the pinned '$want_ca_ver'"
  fi
  # 4. cargo-audit executable IDENTITY (when a pin is supplied): hash the exact binary.
  if [ -n "$want_ca_sha" ]; then
    local ca_sha
    ca_sha="$(docker run --rm --pull never "$image" bash -c 'p="$(command -v cargo-audit)"; [ -n "$p" ] && sha256sum "$p" | cut -d" " -f1' 2>/dev/null || true)"
    [ "$ca_sha" = "$want_ca_sha" ] \
      || die "builder image: cargo-audit executable sha256 '${ca_sha:-<none>}' != pinned '$want_ca_sha'"
  fi
  # 5. RT-2 guard: the tools resolve under the PRODUCTION non-login shell the producer uses.
  docker run --rm --pull never "$image" bash -c 'command -v cargo cargo-audit >/dev/null' 2>/dev/null \
    || die "builder image: production non-login shell (bash -c) does not resolve cargo + cargo-audit (RT-2 login-PATH loss)"
  note "builder-image capability preflight PASSED (arch=$want_uname; cargo + cargo-audit present${want_ca_ver:+, cargo-audit ~ $want_ca_ver})"
}

# ---- Canonical, DETERMINISTIC in-container provisioning paths (Item 7: fixed paths, no
# wall-clock / host-generated locations). These are the SINGLE source of truth shared by the
# Dockerfile provisioning recipes (which PLACE the executables here) and preflight_prover_capability
# (which RESOLVES them here). cargo subcommands live on an ISOLATED verified PATH dir; r0vm lives at
# the EXACT RISC0_SERVER_PATH file; cargo-audit is built into an isolated prefix; the recorded
# executable SHA-256s (venue evidence, NOT source pins) go under the evidence dir.
B0PRE_PROVER_BIN_DIR="/opt/b0pre/prover-bin"
B0PRE_RISC0_SERVER_DIR="/opt/b0pre/risc0-server"
B0PRE_RISC0_SERVER_PATH="/opt/b0pre/risc0-server/r0vm"
B0PRE_AUDIT_PREFIX="/opt/b0pre/audit-prefix"
B0PRE_EVIDENCE_DIR="/opt/b0pre/evidence"

# PROVER-toolchain CAPABILITY preflight (Item 6, prover half). Companion to
# preflight_builder_capability: BEFORE Stage 5 runs inside a VERIFIED builder image, assert the
# image carries the pinned PROVER executables provisioned by the declarative verified-extraction
# recipe — validating VERSIONS/IDENTITIES via each tool's EXACT declared version argv, never a bare
# `command -v`. The per-candidate/arch matrix (golden `prover_archives`, VENUE.md §2):
#   * sp1  (x86_64 AND aarch64): `cargo-prove` on the isolated PATH; `cargo-prove prove --version`
#     must carry the pinned SP1 release commit.
#   * risc0 (x86_64 ONLY): `cargo-risczero` on the isolated PATH (`cargo-risczero risczero --version`)
#     AND `r0vm` at the EXACT RISC0_SERVER_PATH (`r0vm --version`), both carrying the pinned RISC Zero
#     release version. RISC Zero is never provisioned on aarch64 — asking to validate risc0/aarch64 is
#     a hard refusal, not a skip (the caller skips it by arch, mirroring extract_material).
# A missing / mis-versioned prover tool fails closed here, not deep inside Stage 5. Args:
#   <image> <sp1|risc0> <arch> [sp1_release_commit] [risc0_release_version] [risc0_server_path]
preflight_prover_capability() {
  local image="$1" candidate="$2" arch="$3"
  local want_sp1_commit="${4:-}" want_risc0_ver="${5:-}" r0vm_path="${6:-$B0PRE_RISC0_SERVER_PATH}"
  require_cmd docker
  case "$candidate" in sp1|risc0) ;; *) die "preflight_prover_capability: candidate must be sp1|risc0 (got '$candidate')" ;; esac
  case "$arch" in x86_64|aarch64) ;; *) die "preflight_prover_capability: unsupported arch '$arch' (want x86_64|aarch64)" ;; esac
  # Resolve one line of a tool's EXACT declared version argv inside the production non-login shell
  # (RT-2: bash -c, never bash -lc); empty on any absence/failure. The argv is the tool's own
  # (matching the ratified `version_argv` in prover_archives), invoked by absolute/PATH name so a
  # cargo-subcommand indirection can never mask a missing binary.
  local ver
  case "$candidate" in
    sp1)
      ver="$(docker run --rm --pull never "$image" bash -c 'command -v cargo-prove >/dev/null && cargo-prove prove --version' 2>/dev/null | head -n1 | sed 's/[[:space:]]*$//' || true)"
      [ -n "$ver" ] \
        || die "builder image ($candidate/$arch): cargo-prove is absent from the production PATH (Stage-5 SP1 prove cannot execute; a missing prover is never a proof)"
      if [ -n "$want_sp1_commit" ]; then
        grep -q "$want_sp1_commit" <<<"$ver" \
          || die "builder image ($candidate/$arch): cargo-prove version '$ver' does not carry the pinned SP1 release commit '$want_sp1_commit'"
      fi
      note "prover capability preflight PASSED ($candidate/$arch: cargo-prove present${want_sp1_commit:+ ~ $want_sp1_commit})"
      ;;
    risc0)
      [ "$arch" = x86_64 ] \
        || die "preflight_prover_capability: RISC Zero prover is x86_64-only (VENUE.md §2); refuse to validate risc0 on $arch"
      ver="$(docker run --rm --pull never "$image" bash -c 'command -v cargo-risczero >/dev/null && cargo-risczero risczero --version' 2>/dev/null | head -n1 | sed 's/[[:space:]]*$//' || true)"
      [ -n "$ver" ] \
        || die "builder image ($candidate/$arch): cargo-risczero is absent from the production PATH (RISC Zero Stage-5 cannot execute)"
      local r0ver
      r0ver="$(docker run --rm --pull never -e "RISC0_SERVER_PATH=$r0vm_path" "$image" bash -c '[ -x "$RISC0_SERVER_PATH" ] && "$RISC0_SERVER_PATH" --version' 2>/dev/null | head -n1 | sed 's/[[:space:]]*$//' || true)"
      [ -n "$r0ver" ] \
        || die "builder image ($candidate/$arch): r0vm is absent or non-executable at RISC0_SERVER_PATH=$r0vm_path (RISC Zero Stage-5 cannot execute)"
      if [ -n "$want_risc0_ver" ]; then
        grep -q "$want_risc0_ver" <<<"$ver" \
          || die "builder image ($candidate/$arch): cargo-risczero version '$ver' does not carry the pinned RISC Zero '$want_risc0_ver'"
        grep -q "$want_risc0_ver" <<<"$r0ver" \
          || die "builder image ($candidate/$arch): r0vm version '$r0ver' does not carry the pinned RISC Zero '$want_risc0_ver'"
      fi
      note "prover capability preflight PASSED ($candidate/$arch: cargo-risczero + r0vm present${want_risc0_ver:+ ~ $want_risc0_ver}; r0vm at $r0vm_path)"
      ;;
  esac
}

# Parse + fully validate a TYPED runnable-ref sidecar and echo its runnable image id, or
# fail closed. The sidecar (written by build_container.sh ONLY after both clean builds
# match, the layout is content-verified, docker load succeeds, and the loaded id matches a
# verified content address) binds candidate, arch, the exact SOURCE COMMIT, the verified
# manifest + config digests, and the loaded runnable image id. This refuses, in order and
# before touching the daemon for the field cases: a missing/malformed sidecar, a wrong/
# absent schema, a cross-candidate or cross-architecture record, malformed digests, a
# source_commit that is not 40 lowercase hex OR != current HEAD OR != RATIFIED_SOURCE_COMMIT
# (the AUTHORITATIVE source-identity gate — a docs-only / orchestration-only commit can
# preserve the image manifest, so manifest equality is NEVER a proxy for source identity),
# a STALE manifest != the current verified build (defense in depth), and finally an image
# no longer present in the daemon. Args:
#   <sidecar_file> <candidate> <arch> <current_verified_manifest_digest> [repo_dir]
resolve_runnable_ref() {
  local f="$1" cand="$2" arch="$3" cur_manifest="$4" repo="${5:-.}" line
  [ -f "$f" ] || die "missing verified runnable-ref sidecar $f (build+load+verify must run first)"
  require_cmd python3
  line="$(python3 -c 'import json,sys
d=json.load(open(sys.argv[1]))
print("\t".join(str(d.get(k,"")) for k in ("schema","candidate","arch","source_commit","manifest_digest","config_digest","runnable_image_id")))' "$f" 2>/dev/null)" \
    || die "runnable-ref sidecar $f is not valid JSON (malformed)"
  local schema sc_cand sc_arch sc_commit sc_manifest sc_config sc_image
  IFS=$'\t' read -r schema sc_cand sc_arch sc_commit sc_manifest sc_config sc_image <<< "$line"
  [ "$schema" = "b0pre-runnable-ref-v1" ] || die "runnable-ref sidecar $f wrong/absent schema (got '${schema:-<none>}')"
  [ "$sc_cand" = "$cand" ] || die "cross-candidate runnable-ref sidecar: '$sc_cand' != '$cand'"
  [ "$sc_arch" = "$arch" ] || die "cross-architecture runnable-ref sidecar: '$sc_arch' != '$arch'"
  printf '%s' "$sc_manifest" | grep -Eq '^sha256:[0-9a-f]{64}$' || die "runnable-ref sidecar manifest_digest malformed: '$sc_manifest'"
  printf '%s' "$sc_config"   | grep -Eq '^sha256:[0-9a-f]{64}$' || die "runnable-ref sidecar config_digest malformed: '$sc_config'"
  printf '%s' "$sc_image"    | grep -Eq '^sha256:[0-9a-f]{64}$' || die "runnable-ref sidecar runnable_image_id malformed: '$sc_image'"
  # AUTHORITATIVE source-identity gate (NOT manifest inequality): source_commit must be a
  # full 40 lowercase hex equal to BOTH the current HEAD and RATIFIED_SOURCE_COMMIT.
  is_ratified_commit_format "$sc_commit" \
    || die "runnable-ref sidecar source_commit is not 40 lowercase hex: '${sc_commit:-<none>}'"
  local head; head="$(git -C "$repo" rev-parse HEAD 2>/dev/null)" \
    || die "cannot resolve current HEAD in '$repo' to validate the runnable-ref sidecar source_commit"
  [ "$sc_commit" = "$head" ] \
    || die "stale runnable-ref sidecar: source_commit $sc_commit != current HEAD $head (prior run / prior source commit)"
  [ -n "${RATIFIED_SOURCE_COMMIT:-}" ] \
    || nyr "RATIFIED_SOURCE_COMMIT is required to validate the runnable-ref sidecar source_commit"
  [ "$sc_commit" = "$RATIFIED_SOURCE_COMMIT" ] \
    || die "runnable-ref sidecar source_commit $sc_commit != RATIFIED_SOURCE_COMMIT $RATIFIED_SOURCE_COMMIT (HEAD/RATIFIED disagreement)"
  # Defense in depth: the sidecar manifest must also equal the current verified build.
  [ "$sc_manifest" = "$cur_manifest" ] \
    || die "stale runnable-ref sidecar: manifest $sc_manifest != current verified build $cur_manifest"
  docker image inspect "$sc_image" >/dev/null 2>&1 \
    || die "runnable image $sc_image referenced by the sidecar is no longer loaded in the daemon"
  printf '%s' "$sc_image"
}

# TEST_ONLY smoke resolver: validate a SMOKE runnable-ref sidecar (schema
# b0pre-smoke-runnable-ref-v1, classification TEST_ONLY) and echo its runnable image id, or fail
# closed. This is the SEPARATE reader the smoke entry point uses; the authoritative
# resolve_runnable_ref above REJECTS this sidecar outright (its `schema` != b0pre-runnable-ref-v1),
# so a smoke image can never be consumed on the authoritative path. It binds the clean PR-head as
# source_pr_head and NEVER requires or accepts RATIFIED_SOURCE_COMMIT. Args:
#   <sidecar_file> <candidate> <arch> <current_verified_manifest_digest> <expected_pr_head> [repo_dir]
resolve_smoke_runnable_ref() {
  local f="$1" cand="$2" arch="$3" cur_manifest="$4" pr_head="$5" repo="${6:-.}" line
  [ -f "$f" ] || die "missing smoke runnable-ref sidecar $f (smoke build+load+verify must run first)"
  require_cmd python3
  line="$(python3 -c 'import json,sys
d=json.load(open(sys.argv[1]))
print("\t".join(str(d.get(k,"")) for k in ("schema","classification","candidate","arch","source_pr_head","manifest_digest","config_digest","runnable_image_id")))' "$f" 2>/dev/null)" \
    || die "smoke runnable-ref sidecar $f is not valid JSON (malformed)"
  local schema cls sc_cand sc_arch sc_prhead sc_manifest sc_config sc_image
  IFS=$'\t' read -r schema cls sc_cand sc_arch sc_prhead sc_manifest sc_config sc_image <<< "$line"
  [ "$schema" = "b0pre-smoke-runnable-ref-v1" ] || die "smoke sidecar $f wrong/absent schema (got '${schema:-<none>}')"
  [ "$cls" = "TEST_ONLY" ] || die "smoke sidecar $f classification must be TEST_ONLY (got '${cls:-<none>}')"
  [ "$sc_cand" = "$cand" ] || die "cross-candidate smoke sidecar: '$sc_cand' != '$cand'"
  [ "$sc_arch" = "$arch" ] || die "cross-architecture smoke sidecar: '$sc_arch' != '$arch'"
  printf '%s' "$sc_manifest" | grep -Eq '^sha256:[0-9a-f]{64}$' || die "smoke sidecar manifest_digest malformed: '$sc_manifest'"
  printf '%s' "$sc_config"   | grep -Eq '^sha256:[0-9a-f]{64}$' || die "smoke sidecar config_digest malformed: '$sc_config'"
  printf '%s' "$sc_image"    | grep -Eq '^sha256:[0-9a-f]{64}$' || die "smoke sidecar runnable_image_id malformed: '$sc_image'"
  # PR-head source identity (NOT ratified): 40 lowercase hex, equal to current HEAD and the
  # expected clean PR-head. RATIFIED_SOURCE_COMMIT is never consulted here.
  printf '%s' "$sc_prhead" | grep -Eq '^[0-9a-f]{40}$' || die "smoke sidecar source_pr_head is not 40 lowercase hex: '${sc_prhead:-<none>}'"
  local head; head="$(git -C "$repo" rev-parse HEAD 2>/dev/null)" \
    || die "cannot resolve current HEAD in '$repo' to validate the smoke sidecar source_pr_head"
  [ "$sc_prhead" = "$head" ] || die "stale smoke sidecar: source_pr_head $sc_prhead != current HEAD $head"
  [ "$sc_prhead" = "$pr_head" ] || die "smoke sidecar source_pr_head $sc_prhead != expected clean PR-head $pr_head"
  [ "$sc_manifest" = "$cur_manifest" ] || die "stale smoke sidecar: manifest $sc_manifest != current verified build $cur_manifest"
  docker image inspect "$sc_image" >/dev/null 2>&1 \
    || die "smoke runnable image $sc_image referenced by the sidecar is no longer loaded in the daemon"
  printf '%s' "$sc_image"
}

# Minimum free space (GiB) on a given path.
require_free_gib() {
  local path="$1" min="$2" free
  free="$(disk_free_gib "$path")"
  [ "${free:-0}" -ge "$min" ] || die "need >= ${min}GiB free at $path; only ${free:-0}GiB available"
}

# ---- Disk telemetry primitives ---------------------------------------------
# Parse whole-GiB available from POSIX `df -Pk` output supplied on stdin. POSIX `-P`
# guarantees the filesystem is reported on a single data row (NR==2) with columns
#   Filesystem  1024-blocks  Used  Available  Capacity  Mounted-on
# so column 4 is Available in KiB on BOTH GNU coreutils and BSD/macOS `df`. Emits whole
# GiB (floor); emits 0 for header-only / blank / non-numeric input so a caller's gate
# fails closed on unknown free space rather than proceeding. Split out from
# disk_free_gib so the KiB->GiB parse is unit-testable against canned df output.
df_avail_gib_from_posix_k() {
  awk 'NR==2 {
         if ($4 ~ /^[0-9]+$/) { printf "%d", int($4 / 1024 / 1024) } else { printf "0" }
         seen = 1
       }
       END { if (!seen) printf "0" }'
}

# Free whole-GiB available on the filesystem holding PATH (0 if unknown/unreadable).
# Uses the POSIX-portable `df -Pk` (1024-byte blocks) rather than the BSD-only `df -g`
# (GNU coreutils rejects `-g` with "invalid option", which previously made every Linux
# host report 0 and fail Stage 0). `-Pk` parses identically on GNU/Linux and macOS.
# Fail-closed: any df error (missing path, permission) or unparseable output yields 0,
# which trips the `require_free_gib` / `require_headroom_gib` >= N GiB gates.
disk_free_gib() {
  local path="$1" out
  out="$(df -Pk "$path" 2>/dev/null)" || { printf '0'; return; }
  printf '%s' "$(printf '%s\n' "$out" | df_avail_gib_from_posix_k)"
}

# Disk used (whole MiB) by a directory tree; 0 if it does not exist.
dir_used_mib() {
  local path="$1"
  [ -e "$path" ] || { printf '0'; return; }
  du -sm "$path" 2>/dev/null | awk '{print $1}'
}

# Fail-closed BEFORE a stage runs if fewer than <min> GiB are free at <path>. Used to
# stop a stage whose estimated disk headroom is unavailable, rather than crashing part
# way through a large build/extraction.
require_headroom_gib() {
  local path="$1" min="$2" stage="${3:-next stage}" free
  free="$(disk_free_gib "$path")"
  [ "${free:-0}" -ge "$min" ] \
    || die "insufficient disk headroom for ${stage}: need >= ${min}GiB free at $path, have ${free:-0}GiB"
}

# The candidate must NOT already carry a lock (locks come only from the venue).
require_no_preexisting_lock() {
  local dir="$1"
  [ -f "$dir/Cargo.lock" ] && die "unexpected pre-existing $dir/Cargo.lock; authoritative locks come only from the venue"
  true
}

# Fail-closed if a required command is missing.
require_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "required command '$1' not found on PATH"
}

# Bare 64-hex SHA-256 of stdin, using whichever portable tool is present
# (sha256sum on Linux, shasum on macOS). Used for the OFF-VENUE dry-run producers
# and for hashing local build evidence.
sha256_hex_stdin() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 | awk '{print $1}'
  else
    die "no sha256 tool (sha256sum / shasum) on PATH"
  fi
}

# True iff the argument is a bare 64-hex (lowercase) sha256. Shared by verify_pins.sh and the
# declarative verified-extraction mechanism.
is_bare_sha256() { printf '%s' "${1:-}" | grep -Eq '^[0-9a-f]{64}$'; }

# A deterministic, non-placeholder bare 64-hex value derived from a label. Used by
# the dry-run producers to emit real-SHAPED sample digests off-venue (no real image
# is built). NOT an authoritative digest.
syn_hex() { printf '%s' "$1" | sha256_hex_stdin; }

# A deterministic, non-placeholder full sha256:<64hex> OCI-shaped sample digest.
syn_oci() { printf 'sha256:%s' "$(syn_hex "$1")"; }

# Real BLAKE3 (bare 64-hex) of a file, for on-venue build-evidence hashing. Requires
# b3sum (a venue dependency); never invoked in the off-venue dry-run.
blake3_hex_file() {
  require_cmd b3sum
  b3sum "$1" | awk '{print $1}'
}

# True when the OFF-VENUE dry-run is requested (SUMCHAIN_B0PRE_DRYRUN=1). The dry
# run emits real-SHAPED sample files matching the exact production schema, WITHOUT
# Docker / toolchains, so the producer→consumer compatibility tests and the two
# demonstrations can run where no venue exists. Dry-run output is never authoritative.
is_dryrun() { [ "${SUMCHAIN_B0PRE_DRYRUN:-0}" = "1" ]; }

# ---- Authoritative container build context (curated, minimal, reproduced layout) ---
#
# The official guest dep graph is
#   candidates/<cand>/guest  --(path ../../../guest-core)-->  guest-core
#   guest-core               --(path ../../../crates/sumchain-wire)-->  sumchain-wire
# and `sumchain-wire` is a WORKSPACE MEMBER that inherits `.workspace = true` keys from
# the repo-root `Cargo.toml`. Copying only `candidates/<cand>` into the image (the old
# behaviour) leaves those two crates + the workspace root absent, so the path deps and
# the `.workspace` inheritance cannot resolve in-container. `stage_container_context`
# reproduces the EXACT repo-relative layout of ONLY that graph into a curated staging
# dir used as the Docker build context — no unrelated production crate is copied
# (isolation). The reproduced repo root maps to `/work` in the image, so:
INCONTAINER_ROOT="/work"

# The in-container candidate workspace dir (its `[workspace]` root). The path deps
# resolve because guest-core sits at /work/tools/b0-pre-candidates/guest-core and
# sumchain-wire at /work/crates/sumchain-wire, exactly as in the source tree.
incontainer_candidate_dir() { printf '%s/tools/b0-pre-candidates/candidates/%s' "$INCONTAINER_ROOT" "$1"; }

# The Stage-1 schema arch name (X86_64 / Aarch64) for a host arch. Shared by the authoritative
# producer and the TEST_ONLY smoke so both map arches identically (single source of truth).
schema_arch_of() {
  case "$1" in
    x86_64|amd64) printf 'X86_64' ;;
    aarch64|arm64) printf 'Aarch64' ;;
    *) die "arch must be x86_64|aarch64 (got '${1:-}')" ;;
  esac
}

# The builder-image digest a producer recorded for (candidate, arch) in the work dir. Shared by
# the authoritative producer and the TEST_ONLY smoke (read-only accessor over container.json).
builder_digest_of() {
  local cand="$1" arch="$2" work="$3"
  python3 - "$work/$cand.$arch.container.json" <<'PY'
import json, sys
builds = json.load(open(sys.argv[1]))
b = next(x for x in builds if x["role"] == "builder")
print(b["builder_oci_digest"])
PY
}

# The real repo root (two levels above tools/b0-pre-candidates). ROOT is set by every
# script that sources this lib to tools/b0-pre-candidates.
repo_root() { (cd "$ROOT/../.." && pwd); }

# Write the CURATED, MINIMAL workspace-root manifest for the staged context. It carries
# EXACTLY the `[workspace.package]` keys + `[workspace.dependencies]` entries that
# `crates/sumchain-wire` inherits via `{ workspace = true }` / `.workspace = true`, plus
# ONLY sumchain-wire as a member, and excludes `tools` exactly as the real repo root
# does (so the staged guest-core + candidate workspace under tools/ stay standalone /
# self-rooted, never members). Values are copied verbatim from the real repo-root
# Cargo.toml; the structural staging test fails on any drift or missing inherited key.
write_curated_workspace_root() {
  local dest="$1"
  cat > "$dest" <<'TOML'
# CURATED, MINIMAL workspace root for the B0-PRE official-guest container context.
# GENERATED by scripts/stage_context.sh (see lib.sh: write_curated_workspace_root).
#
# It exists ONLY so the frozen wire leaf `crates/sumchain-wire` — a real workspace
# member that inherits `.workspace = true` keys — resolves those inherited values
# inside the ISOLATED build context, WITHOUT copying the production workspace or any
# unrelated crate. It contains EXACTLY the sections sumchain-wire inherits:
#   [workspace.package]     : edition, authors, license, repository
#   [workspace.dependencies]: the deps its [dependencies]/[dev-dependencies] pull with
#                             `{ workspace = true }`
# and ONLY sumchain-wire as a member. `tools` is excluded exactly as in the real repo
# root, so the staged guest-core + candidate workspace (under tools/) stay standalone /
# self-rooted just like in-tree. Values are verbatim from the real repo-root Cargo.toml;
# any drift is caught by the structural staging test
# (tools/b0-pre-validator/tests/container_context_staging.rs).
[workspace]
resolver = "2"
members = ["crates/sumchain-wire"]
exclude = ["tools"]

[workspace.package]
edition = "2021"
authors = ["SUM Chain Team"]
license = "MIT OR Apache-2.0"
repository = "https://github.com/SUM-INNOVATION/sum-chain"

[workspace.dependencies]
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
serde-big-array = "0.5"
bincode = "1.3"
hex = "0.4"
bs58 = "0.5"
blake3 = "1.5"
thiserror = "1.0"
sha2 = "0.10"
TOML
}

# Copy a source tree into the staged context, then prune build scratch (target/) and
# ANY Cargo.lock (host locks are refused; the authoritative lock is generated
# in-container). Portable across GNU and BSD userland.
stage_copy_tree() {
  local src="$1" dst="$2"
  [ -d "$src" ] || die "stage_copy_tree: source '$src' is not a directory"
  mkdir -p "$(dirname "$dst")"
  cp -R "$src" "$dst"
  find "$dst" -type d -name target -prune -exec rm -rf {} + 2>/dev/null || true
  find "$dst" -type f -name Cargo.lock -delete 2>/dev/null || true
}

# Stage the curated, minimal, reproduced-layout Docker build context for one candidate
# into $stage. Reproduces ONLY the official guest dep graph at its exact repo-relative
# paths so the path deps + `.workspace` inheritance resolve in-container, and NOTHING
# else from the production workspace. Deterministic + off-venue safe (no Docker/toolchain).
stage_container_context() {
  local candidate="$1" stage="$2"
  case "$candidate" in sp1|risc0) ;; *) die "stage_container_context: candidate must be sp1|risc0 (got '${candidate:-}')" ;; esac
  [ -n "$stage" ] || die "stage_container_context: staging dir argument required"
  local repo; repo="$(repo_root)"

  rm -rf "$stage"
  mkdir -p "$stage"
  # 1) the frozen wire leaf (workspace member; path-dep target of guest-core).
  stage_copy_tree "$repo/crates/sumchain-wire" "$stage/crates/sumchain-wire"
  # 2) the candidate-neutral shared guest core (path-dep target of the candidate guest).
  stage_copy_tree "$ROOT/guest-core" "$stage/tools/b0-pre-candidates/guest-core"
  # 3) ONLY this candidate's workspace (host + guest); the other candidate never enters.
  stage_copy_tree "$ROOT/candidates/$candidate" "$stage/tools/b0-pre-candidates/candidates/$candidate"
  # 4) the frozen guest fixtures at the reproduced repo-relative path the guest-core
  #    sources reference (`../../../../docs/b0-pre/...` from guest-core/tests + the
  #    emit_official_guest_input example the venue runs).
  mkdir -p "$stage/docs/b0-pre/fixtures/workload" "$stage/docs/b0-pre/exp"
  cp "$repo/docs/b0-pre/fixtures/workload/official.json" "$stage/docs/b0-pre/fixtures/workload/official.json"
  cp "$repo/docs/b0-pre/exp/exp_table_q16.json"          "$stage/docs/b0-pre/exp/exp_table_q16.json"
  cp "$repo/docs/b0-pre/exp/exp_table_q16.json.hash"     "$stage/docs/b0-pre/exp/exp_table_q16.json.hash"
  # 5) the curated minimal workspace root (sumchain-wire inheritance only).
  write_curated_workspace_root "$stage/Cargo.toml"
  # 6) the SINGLE, tested declarative prover-toolchain provisioner (owner ruling: the Dockerfiles
  #    must NOT call host lib.sh; they COPY + run this exact staged file — the same one
  #    tests/verified_extraction.test.sh exercises with crafted archives — so there is no
  #    unverified second implementation). Staged at a stable, isolated context path; its bytes are
  #    folded into staged_context_blake3 (build evidence), binding the provisioner identity.
  mkdir -p "$stage/provisioning"
  cp "$ROOT/scripts/provision_prover_toolchain.sh" "$stage/provisioning/provision_prover_toolchain.sh"
  chmod 0755 "$stage/provisioning/provision_prover_toolchain.sh"
  # Belt-and-suspenders: no Cargo.lock may exist anywhere in the staged context (the
  # authoritative lock is generated in-container and bound; a host lock is refused).
  find "$stage" -type f -name Cargo.lock -delete 2>/dev/null || true
}

# A deterministic BLAKE3 identity over the exact bytes of a staged context: BLAKE3 of
# the sorted list of "<relpath> <blake3(file)>" lines. Bound into the #154 build
# evidence (via the builder command log) so the staged guest-source/context identity is
# recorded without changing any evidence schema. Requires b3sum (a venue dependency).
staged_context_blake3() {
  local stage="$1"
  require_cmd b3sum
  ( cd "$stage" && find . -type f | LC_ALL=C sort | while IFS= read -r f; do
      printf '%s %s\n' "$f" "$(b3sum "$f" | awk '{print $1}')"
    done ) | b3sum | awk '{print $1}'
}

# ---- Immutable-pin URL / host validation (findings F1, F6, F7) ---------------
#
# The former allow-list matched a URL's host with a substring test against a
# space-joined string, accepted any redirect target, and named the stale delivery
# host `objects.githubusercontent.com`. GitHub now serves release assets from
# `release-assets.githubusercontent.com`. These helpers replace that with EXACT host
# matching over BOTH the initial URL and the effective (post-redirect) URL, and refuse
# any non-HTTPS scheme so a redirect cannot silently downgrade the transport.

# Scheme of a URL, lowercased ("" when unparseable).
url_scheme() { printf '%s' "${1:-}" | sed -n 's|^\([A-Za-z][A-Za-z0-9+.-]*\)://.*|\1|p' | tr '[:upper:]' '[:lower:]'; }

# Host of a URL, lowercased, without userinfo or :port ("" when unparseable).
url_host() {
  printf '%s' "${1:-}" \
    | sed -n 's|^[A-Za-z][A-Za-z0-9+.-]*://\([^/?#]*\).*|\1|p' \
    | sed 's|^.*@||; s|:[0-9]*$||' \
    | tr '[:upper:]' '[:lower:]'
}

# EXACT host membership. `$2...` are the allowed hosts as separate words. A host is
# accepted only on a whole-string match, so `evil-github.com` and
# `github.com.attacker.net` are refused where a substring test would have passed.
host_in_allowlist() {
  local host="${1:-}" h
  [ -n "$host" ] || return 1
  shift
  for h in "$@"; do [ "$host" = "$h" ] && return 0; done
  return 1
}

# The hosts an artifact pin may be FETCHED FROM initially (the value the owner ratifies).
PIN_INITIAL_HOSTS="static.rust-lang.org github.com codeload.github.com"
# The additional hosts a primary URL may REDIRECT to. GitHub release assets are
# delivered from release-assets.githubusercontent.com (observed 2026-07); the older
# objects.githubusercontent.com is retained because GitHub has not withdrawn it.
PIN_REDIRECT_HOSTS="release-assets.githubusercontent.com objects.githubusercontent.com"
# The immutable APT snapshot services.
PIN_APT_HOSTS="snapshot.debian.org snapshot.ubuntu.com"
# The ONLY host where plain http is tolerated, and only for the two pinned snapshot
# locators. The exception exists because the pinned Debian base image carries no
# ca-certificates before the first package installation, so apt cannot use TLS for the
# very sources that install them. It is deliberately NOT generalized to Rust, GitHub,
# container registries, or any tool artifact — those are https-only (see
# require_https_primary_url).
#
# What the exception does and does not cost:
#   * http permits an on-path attacker to DENY service or REPLAY previously served
#     bytes. Neither is prevented here, and neither is claimed to be.
#   * http does NOT permit accepted-content substitution. Bytes are accepted only if
#     they satisfy BOTH the pinned InRelease sha256 (an exact preimage the attacker
#     cannot forge) AND apt's OpenPGP verification against the Debian archive keyring.
#     Package payloads are in turn bound by the hashes inside that signed Release
#     metadata, so substituted packages are rejected downstream as well. A replay is
#     therefore confined to exactly the snapshot the owner already pinned.
PIN_APT_HTTP_HOST="snapshot.debian.org"

# An artifact pin URL: HTTPS only, exact-host allow-listed. Prints nothing on success.
require_https_primary_url() {
  local what="$1" url="${2:-}" scheme host
  scheme="$(url_scheme "$url")"; host="$(url_host "$url")"
  [ -n "$host" ] || { printf 'unparseable URL for %s: %s\n' "$what" "$url" >&2; return 1; }
  [ "$scheme" = "https" ] \
    || { printf '%s must use https (got %s): %s\n' "$what" "${scheme:-none}" "$url" >&2; return 1; }
  # shellcheck disable=SC2086
  host_in_allowlist "$host" $PIN_INITIAL_HOSTS \
    || { printf "%s host '%s' is not an allow-listed primary source: %s\n" "$what" "$host" "$url" >&2; return 1; }
  return 0
}

# An APT snapshot pin URL: exact-host allow-listed immutable snapshot service, and — for
# plain http — the ONE host the narrow bootstrap exception covers. Integrity never rests
# on the transport: the InRelease bytes are OpenPGP-verified by apt AND pinned by sha256.
require_apt_pin_url() {
  local what="$1" url="${2:-}" scheme host
  scheme="$(url_scheme "$url")"; host="$(url_host "$url")"
  [ -n "$host" ] || { printf 'unparseable URL for %s: %s\n' "$what" "$url" >&2; return 1; }
  case "$scheme" in http|https) ;; *) printf '%s must be http(s) (got %s)\n' "$what" "${scheme:-none}" >&2; return 1 ;; esac
  # shellcheck disable=SC2086
  host_in_allowlist "$host" $PIN_APT_HOSTS \
    || { printf "%s host '%s' is not an immutable snapshot service: %s\n" "$what" "$host" "$url" >&2; return 1; }
  if [ "$scheme" = "http" ] && [ "$host" != "$PIN_APT_HTTP_HOST" ]; then
    printf "%s: plain http is permitted ONLY for %s (got host '%s'); use https\n" \
      "$what" "$PIN_APT_HTTP_HOST" "$host" >&2
    return 1
  fi
  case "$url" in */) ;; *) printf '%s must end in "/" (it is a repository base URL): %s\n' "$what" "$url" >&2; return 1 ;; esac
  return 0
}

# PURE policy over an APT (initial URL, effective URL) pair — no network. The snapshot
# service answers a pinned locator with a redirect to a content-addressed path on the
# SAME host, so the effective host must equal the initial host exactly: an apt pin may
# never be redirected to another origin, and an https pin may never be downgraded to
# http. Prints the effective host on success.
require_apt_effective_url() {
  local what="$1" url="${2:-}" eff="${3:-}" host eff_host scheme eff_scheme
  host="$(url_host "$url")";     scheme="$(url_scheme "$url")"
  eff_host="$(url_host "$eff")"; eff_scheme="$(url_scheme "$eff")"
  [ -n "$eff_host" ] || { printf '%s: unparseable effective URL: %s\n' "$what" "$eff" >&2; return 1; }
  [ "$eff_host" = "$host" ] \
    || { printf "%s: redirected off the pinned snapshot host ('%s' -> '%s')\n" "$what" "$host" "$eff_host" >&2; return 1; }
  case "$eff_scheme" in http|https) ;; *) printf '%s: effective URL scheme %s is not http(s)\n' "$what" "${eff_scheme:-none}" >&2; return 1 ;; esac
  if [ "$scheme" = "https" ] && [ "$eff_scheme" != "https" ]; then
    printf '%s: https pin was downgraded to %s by redirect: %s\n' "$what" "$eff_scheme" "$eff" >&2
    return 1
  fi
  printf '%s' "$eff_host"
  return 0
}

# Resolve an APT locator's redirect chain WITHOUT downloading the body, then apply the
# pure policy above.
require_apt_redirect_chain() {
  local what="$1" url="${2:-}" eff
  eff="$(curl -sSL -o /dev/null -w '%{url_effective}' --max-redirs 5 "$url" 2>/dev/null)" || {
    printf '%s: could not resolve redirect chain for %s\n' "$what" "$url" >&2; return 1; }
  require_apt_effective_url "$what" "$url" "$eff"
}

# PURE decision over an (initial URL, effective URL) pair — no network. Accepts only
# when the initial URL is an allow-listed https primary AND the effective URL is https on
# either that same primary host or an allow-listed delivery host. Split out from the
# fetching wrapper so the redirect policy is unit-testable offline.
# Prints the effective host on success.
require_allowed_effective_url() {
  local what="$1" url="${2:-}" eff="${3:-}" eff_host eff_scheme
  require_https_primary_url "$what" "$url" || return 1
  eff_host="$(url_host "$eff")"; eff_scheme="$(url_scheme "$eff")"
  [ -n "$eff_host" ] || { printf '%s: unparseable effective URL: %s\n' "$what" "$eff" >&2; return 1; }
  [ "$eff_scheme" = "https" ] \
    || { printf '%s: redirect downgraded transport to %s: %s\n' "$what" "${eff_scheme:-none}" "$eff" >&2; return 1; }
  # shellcheck disable=SC2086
  host_in_allowlist "$eff_host" $PIN_INITIAL_HOSTS $PIN_REDIRECT_HOSTS \
    || { printf "%s: redirect target host '%s' is not allow-listed\n" "$what" "$eff_host" >&2; return 1; }
  printf '%s' "$eff_host"
  return 0
}

# Resolve a URL's redirect chain WITHOUT downloading the body, then apply the pure
# policy above to the (initial, effective) pair.
require_allowed_redirect_chain() {
  local what="$1" url="${2:-}" eff
  require_https_primary_url "$what" "$url" || return 1
  eff="$(curl -sSL -o /dev/null -w '%{url_effective}' --max-redirs 5 "$url" 2>/dev/null)" || {
    printf '%s: could not resolve redirect chain for %s\n' "$what" "$url" >&2; return 1; }
  require_allowed_effective_url "$what" "$url" "$eff"
}

# ---- OCI index platform validation (finding F5) ------------------------------
#
# PIN-PROPOSAL.md documented that the base manifest's platform.architecture must equal
# the target arch, but nothing implemented it: `docker manifest inspect` resolves any
# digest regardless of platform, so the two per-arch digests could be SWAPPED and still
# pass. These helpers enumerate the immutable INDEX's child manifests and bind each
# proposed digest to its declared platform. Purely metadata — no image is ever run, so
# the check holds identically on a host with QEMU/binfmt registered.

# verify_oci_index_platforms <index.json> <x86_64_digest> <aarch64_digest>
# Exit 0 only when BOTH digests are children of that index AND each declares the
# expected linux platform. Prints one diagnostic line per failure.
verify_oci_index_platforms() {
  python3 - "$1" "$2" "$3" <<'PY'
import json, sys

index_path, want_x86, want_arm = sys.argv[1], sys.argv[2], sys.argv[3]
try:
    doc = json.load(open(index_path))
except Exception as exc:                                  # noqa: BLE001
    sys.exit(f"cannot parse OCI index {index_path}: {exc}")

children = doc.get("manifests")
if not isinstance(children, list) or not children:
    sys.exit("OCI index carries no 'manifests' array (is this an index/manifest list?)")

by_digest = {}
for m in children:
    if isinstance(m, dict) and isinstance(m.get("digest"), str):
        by_digest[m["digest"]] = m.get("platform") or {}

# (proposed digest, expected OCI architecture, label)
expect = ((want_x86, "amd64", "x86_64"), (want_arm, "arm64", "aarch64"))
errors = []
for digest, want_arch, label in expect:
    plat = by_digest.get(digest)
    if plat is None:
        errors.append(f"base_digest.{label} {digest} is NOT a child of the pinned index")
        continue
    got_os, got_arch = plat.get("os"), plat.get("architecture")
    if got_os != "linux":
        errors.append(f"base_digest.{label} declares os={got_os!r}, expected 'linux'")
    if got_arch != want_arch:
        errors.append(
            f"base_digest.{label} declares platform.architecture={got_arch!r}, "
            f"expected {want_arch!r} (swapped or wrong-arch digest)"
        )

if want_x86 == want_arm:
    errors.append("base_digest.x86_64 and base_digest.aarch64 are the same digest")

if errors:
    sys.exit("; ".join(errors))
print("ok")
PY
}

# ---- Per-architecture tool identities (finding F3) ---------------------------
#
# SP1 ships genuinely different bytes per architecture and RISC Zero publishes no
# aarch64-linux artifact at all, so a single SP1_TOOL_IDENTITY / RISC0_TOOL_IDENTITY
# variable could not describe both hosts: on aarch64 the old contract would have
# downloaded the x86_64 RISC Zero tarball and bound an x86_64 binary as aarch64
# evidence. The ratified record now names one variable per (candidate, arch).

# tool_identity_var <Sp1|Risc0> <x86_64|aarch64> -> the ratified variable NAME.
tool_identity_var() {
  case "$1/$2" in
    Sp1/x86_64)   printf 'SP1_TOOL_IDENTITY_X86_64' ;;
    Sp1/aarch64)  printf 'SP1_TOOL_IDENTITY_AARCH64' ;;
    Risc0/x86_64) printf 'RISC0_TOOL_IDENTITY_X86_64' ;;
    Risc0/aarch64)
      die "RISC Zero has no aarch64 tool identity: Groth16 / verifier-material extraction is native-x86_64-only (docs/b0-pre/venue/VENUE.md §2) and upstream publishes no aarch64-linux artifact" ;;
    *) die "no tool-identity variable for candidate='$1' arch='$2'" ;;
  esac
}

# Resolve the ratified tool-identity FILE for (candidate, native arch), fail-closed on
# an absent variable, a missing file, or a file whose declared `arch` is not this host's
# — which is what catches a swapped or cross-architecture identity BEFORE any download,
# install, build, or evidence generation.
resolve_tool_identity_file() {
  local cand="$1" arch="$2" var path declared
  var="$(tool_identity_var "$cand" "$arch")"
  eval "path=\${$var:-}"
  [ -n "$path" ] || nyr "$var (owner-ratified per-arch tool-identity metadata) is required"
  [ -f "$path" ] || die "$var file $path not found"
  declared="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("arch",""))' "$path" 2>/dev/null || true)"
  [ -n "$declared" ] \
    || die "$var file $path does not declare an \"arch\" field; refusing an unlabelled tool identity"
  [ "$declared" = "$arch" ] \
    || die "$var file $path declares arch='$declared' but this native host is '$arch' (cross-architecture or swapped identity)"
  printf '%s' "$path"
}

# ---- Pinned-only APT sources (finding F4) ------------------------------------
#
# The Debian bookworm base image ships NO /etc/apt/sources.list; it ships deb822
# /etc/apt/sources.list.d/debian.sources pointing at the ROLLING deb.debian.org mirror.
# Writing sources.list alone left that rolling source active alongside the pinned
# snapshot, so apt could take a newer package from deb.debian.org and silently defeat
# APT_SNAPSHOT. The Dockerfiles remove every pre-existing source before the first apt
# update and then assert that none survives, using EXACTLY this pattern.
ROLLING_APT_SOURCE_RE='(deb|security)\.debian\.org'

# Exit non-zero if any apt source under <root> still references a rolling Debian mirror.
# <root> is a filesystem prefix so the same rule can be unit-tested against a fabricated
# /etc/apt tree without a container.
assert_no_rolling_apt_sources() {
  local root="${1:-}"
  [ -n "$root" ] || { printf 'assert_no_rolling_apt_sources: root required\n' >&2; return 2; }
  if grep -RIqsE "$ROLLING_APT_SOURCE_RE" "$root/etc/apt/sources.list" "$root/etc/apt/sources.list.d/" 2>/dev/null; then
    printf 'REFUSED: a rolling Debian apt source is still active under %s\n' "$root" >&2
    return 1
  fi
  return 0
}
