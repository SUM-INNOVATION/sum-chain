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

# Validate the COMMITTED candidate lock (materialized under --locked, exported from Stage 1) before
# it is bind-mounted READ-ONLY into a fresh Stage-2 container, and echo its verified domain-separated
# BLAKE3 hash (the lock IDENTITY — a host absolute path is never evidence). Fail closed unless the
# lock is: present, a REGULAR file, NOT a symlink, non-empty, parseable as a Cargo.lock (a version
# header and/or [[package]] tables), candidate-specific and committed-source-of-truth per its
# provenance, its recomputed domain-separated BLAKE3 EQUALS the recorded committed_lock_blake3_hex,
# and its recomputed plain SHA-256 EQUALS the recorded committed_lock_sha256_hex. This re-binds the
# handed-off committed lock to Stage 2 (the full origin / pre-post / closure / vendor verification is
# done by `verify-lock` at resolve time and re-checked in the sealed bundle by import-bundle). Args:
#   <lock_file> <provenance_json> <schema_candidate> <validator_manifest>
require_stage1_lock() {
  local lock="$1" prov="$2" cand="$3" val="$4" recomputed p_hash p_sha p_cand p_origin recomputed_sha
  [ -e "$lock" ] || die "committed candidate lock absent (Stage 2 needs it mounted): $lock"
  [ ! -L "$lock" ] || die "committed candidate lock is a symlink; refused (must be a regular file): $lock"
  [ -f "$lock" ] || die "committed candidate lock is not a regular file: $lock"
  [ -s "$lock" ] || die "committed candidate lock is empty: $lock"
  grep -qE '^version[[:space:]]*=|^\[\[package\]\]' "$lock" \
    || die "committed candidate lock is not a parseable Cargo.lock (no version header / [[package]]): $lock"
  [ -f "$prov" ] || die "committed candidate lock provenance absent: $prov"
  require_cmd python3
  p_cand="$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1])).get("candidate",""))' "$prov" 2>/dev/null || true)"
  p_origin="$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1])).get("origin",""))' "$prov" 2>/dev/null || true)"
  p_hash="$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1])).get("committed_lock_blake3_hex",""))' "$prov" 2>/dev/null || true)"
  p_sha="$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1])).get("committed_lock_sha256_hex",""))' "$prov" 2>/dev/null || true)"
  [ "$p_cand" = "$cand" ] \
    || die "committed lock provenance candidate '$p_cand' != '$cand' (cross-candidate / swapped lock)"
  [ "$p_origin" = "committed-source-of-truth" ] \
    || die "committed lock provenance origin '$p_origin' != committed-source-of-truth (host-originated or reselected lock refused)"
  printf '%s' "$p_hash" | grep -Eq '^[0-9a-f]{64}$' || die "committed lock provenance blake3 malformed: '$p_hash'"
  printf '%s' "$p_sha"  | grep -Eq '^[0-9a-f]{64}$' || die "committed lock provenance sha256 malformed: '$p_sha'"
  recomputed="$(cargo run --quiet --locked --manifest-path "$val" --bin venue-verify -- lock-hash "$lock")" \
    || die "committed lock-hash recomputation failed for $lock"
  [ "$recomputed" = "$p_hash" ] \
    || die "committed lock blake3 mismatch: recomputed $recomputed != provenance $p_hash (tampered / stale lock)"
  recomputed_sha="$(sha256_hex_stdin < "$lock")" \
    || die "committed lock sha256 recomputation failed for $lock"
  [ "$recomputed_sha" = "$p_sha" ] \
    || die "committed lock sha256 mismatch: recomputed $recomputed_sha != provenance $p_sha (tampered / stale lock)"
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

# Vendor the candidate's FULL third-party graph (exact locked versions) inside the pinned
# builder image and export the crate sources to the host as a tar on STDOUT — the same
# no-writable-mount export posture as gen_lock_in_container. The validated Stage-1 lock is
# bind-mounted READ-ONLY at its logical workspace destination so `cargo vendor --locked`
# reproduces exactly the resolved graph (`--versioned-dirs` forces every dir to
# `<name>-<version>`, the layout the notice generator addresses). The tar carries only crate
# SOURCES; the notice manifest hashes the license TEXTS it extracts, so tar ordering/metadata
# never enter any identity. Network is permitted (same pinned-registry posture as the Stage-1
# online resolve); the sources are re-bound to the lock + content-hashed downstream, not trusted.
vendor_graph_in_container() {
  local image="$1" cdir="$2" hostlock="$3" incontainer_lock="$4" out_tar="$5"
  require_cmd docker
  docker run --rm --pull never \
    --mount "type=bind,source=$hostlock,target=$incontainer_lock,readonly" \
    "$image" bash -c "cd $cdir && rm -rf /tmp/b0pre-vendor && cargo vendor --locked --versioned-dirs /tmp/b0pre-vendor >/dev/null && tar -c -C /tmp/b0pre-vendor ." > "$out_tar" \
    || return 1
  [ -s "$out_tar" ]
}

# Safely extract an UNTRUSTED (venue-produced) uncompressed tar into an empty destination,
# applying the project's established safe-extraction rules BEFORE any file is written (the same
# discipline as provision_prover_toolchain.sh): enumerate EVERY entry (verbose, type flag visible)
# and REFUSE any absolute path, `..` traversal, symlink/hardlink, or non-regular/non-directory
# (device/fifo) entry, and REFUSE duplicate regular-file member names — then extract with
# --no-same-owner. GNU + BSD tar both print the type flag as the first char of the mode column
# ('-' regular, 'd' dir, 'l' symlink, 'h' hardlink, 'c'/'b' device, 'p' fifo); the member name is
# the last field. Fails closed at the first violation.
safe_extract_tar() {
  local tar_file="$1" dest="$2"
  require_cmd tar
  [ -s "$tar_file" ] || die "safe_extract_tar: archive absent/empty: $tar_file"
  local listing
  listing="$(tar -tvf "$tar_file")" || die "safe_extract_tar: cannot list $tar_file"
  local reg_members=""
  while IFS= read -r line; do
    [ -n "$line" ] || continue
    local type_char name
    type_char="$(printf '%s' "$line" | cut -c1)"
    name="$(printf '%s' "$line" | awk '{print $NF}')"
    case "$name" in
      /*|*..*) die "safe_extract_tar: unsafe entry path (absolute or ..): $name" ;;
    esac
    case "$type_char" in
      l|h) die "safe_extract_tar: link entry refused: $name" ;;
      d|-) ;;
      *)   die "safe_extract_tar: non-regular/non-directory entry refused ('$type_char'): $name" ;;
    esac
    [ "$type_char" = "-" ] && reg_members="$reg_members$name
"
  done <<EOF
$listing
EOF
  local dups
  dups="$(printf '%s' "$reg_members" | sed '/^$/d' | LC_ALL=C sort | uniq -d)"
  [ -z "$dups" ] || die "safe_extract_tar: duplicate member entries: $(printf '%s' "$dups" | tr '\n' ' ')"
  mkdir -p "$dest"
  tar -x --no-same-owner -C "$dest" -f "$tar_file" || die "safe_extract_tar: extraction failed: $tar_file"
}

# Build the RETAINED canonical VENDOR-INPUT INVENTORY (b0-final-vendor-input-inventory/v1). For every
# vendored file required by the committed graph, bind its package (name, version, source, checksum
# from the committed lock — the authority), its relative path, size, and content sha256, in strictly
# canonical (name, version, source, path) order. This authenticates the vendor tree WITHOUT retaining
# it: a substituted/altered byte changes a file sha256, a missing/extra file changes the set. Only
# registry crates are vendored; a missing versioned dir for a locked registry crate fails closed.
# Args: <committed_lock> <vendor_dir> <schema_candidate> <arch> <out_json>
build_vendor_inventory() {
  local lock="$1" vdir="$2" cand="$3" arch="$4" out="$5"
  require_cmd python3
  [ -f "$lock" ] || die "build_vendor_inventory: committed lock absent: $lock"
  [ -d "$vdir" ] || die "build_vendor_inventory: vendor dir absent: $vdir"
  python3 - "$lock" "$vdir" "$cand" "$arch" "$out" <<'PY'
import json, os, sys, hashlib
lock, vdir, cand, arch, out = sys.argv[1:6]
pkgs, cur = [], None
for line in open(lock):
    t = line.strip()
    if t == "[[package]]":
        if cur: pkgs.append(cur)
        cur = {}
    elif cur is not None:
        if t.startswith('name = '): cur['name'] = t.split('"')[1]
        elif t.startswith('version = '): cur['version'] = t.split('"')[1]
        elif t.startswith('source = '): cur['source'] = t.split('"')[1]
        elif t.startswith('checksum = '): cur['checksum'] = t.split('"')[1]
if cur: pkgs.append(cur)
entries = []
for p in pkgs:
    src = p.get('source', '')
    if not src.startswith('registry+'):
        continue  # only registry crates are vendored (no git/path deps in these graphs)
    chk = p.get('checksum', '')
    d = f"{p['name']}-{p['version']}"  # cargo vendor --versioned-dirs layout
    droot = os.path.join(vdir, d)
    if not os.path.isdir(droot):
        sys.stderr.write(f"vendored dir missing for locked registry crate {d}\n")
        sys.exit(1)
    for dp, dns, fns in os.walk(droot):
        dns.sort()
        for fn in sorted(fns):
            fp = os.path.join(dp, fn)
            if os.path.islink(fp) or not os.path.isfile(fp):
                continue
            rel = os.path.relpath(fp, vdir)
            h = hashlib.sha256()
            with open(fp, 'rb') as fh:
                for chunk in iter(lambda: fh.read(1 << 20), b''):
                    h.update(chunk)
            entries.append({"name": p['name'], "version": p['version'], "source": src,
                            "checksum": chk, "path": rel, "size": os.path.getsize(fp),
                            "sha256": h.hexdigest()})
entries.sort(key=lambda e: (e['name'], e['version'], e['source'], e['path']))
obj = {"schema": "b0-final-vendor-input-inventory/v1", "candidate": cand, "arch": arch,
       "entries": entries}
with open(out, 'w') as f:
    json.dump(obj, f, indent=1, sort_keys=True)
    f.write("\n")
PY
}

# Build the RETAINED canonical LOCKED-COMMAND LOG (b0-final-locked-command-log/v1): the exact
# `cargo … --locked` argv / cwd / target / builder identity / exit status the venue executed to
# materialize the committed lock (vendor once + metadata per target). Called only AFTER every command
# succeeded (each was `|| die`), so exit_status is 0. Structured argv arrays — never shell prose.
# Args: <schema_candidate> <arch> <builder_digest> <in_container_cwd> <out_json> <venue_targets>
build_locked_command_log() {
  local cand="$1" arch="$2" digest="$3" cwd="$4" out="$5" targets="$6"
  require_cmd python3
  python3 - "$out" "$cand" "$arch" "$digest" "$cwd" "$targets" <<'PY'
import json, sys
out, cand, arch, digest, cwd, targets = sys.argv[1:7]
commands = [{
    "op": "vendor",
    "argv": ["cargo", "vendor", "--locked", "--versioned-dirs", "/tmp/b0pre-vendor"],
    "cwd": cwd, "target": "", "exit_status": 0}]
for t in targets.split():
    commands.append({
        "op": "metadata",
        "argv": ["cargo", "metadata", "--locked", "--filter-platform", t, "--format-version", "1"],
        "cwd": cwd, "target": t, "exit_status": 0})
obj = {"schema": "b0-final-locked-command-log/v1", "candidate": cand, "arch": arch,
       "builder_container_digest": digest, "commands": commands}
with open(out, 'w') as f:
    json.dump(obj, f, indent=1, sort_keys=True)
    f.write("\n")
PY
}

# Enumerate the crate NAMES LINKED INTO the artifact for one build TARGET — the NORMAL (runtime
# library) dependency closure (no build-deps, no dev-deps), inside the pinned image with the validated
# lock mounted read-only. Metadata-only (no target toolchain needed); platform-gated crates for OTHER
# targets are excluded. Redistribution follows what ships in the binary, so build-time tooling (e.g.
# `risc0-build` and its tree) and macOS/Windows-only crates are correctly out of scope.
cargo_tree_target_in_container() {
  local image="$1" cdir="$2" hostlock="$3" incontainer_lock="$4" target="$5"
  require_cmd docker
  docker run --rm --pull never \
    --mount "type=bind,source=$hostlock,target=$incontainer_lock,readonly" \
    "$image" bash -c "cd $cdir && cargo tree --locked --target $target -e normal --prefix none --no-dedupe" 2>/dev/null \
    | sed -E 's/ v[0-9].*$//; s/ \(.*$//' | grep -vE '^$'
}

# Emit `cargo metadata --filter-platform <target>` (the platform-resolved graph WITH dep_kinds) to
# STDOUT, inside the pinned image with the validated lock mounted read-only. Used to build the sealed
# target-closure record; `dep_kinds[].kind == null` marks NORMAL (runtime-linked) edges.
cargo_metadata_target_in_container() {
  local image="$1" cdir="$2" hostlock="$3" incontainer_lock="$4" target="$5"
  require_cmd docker
  docker run --rm --pull never \
    --mount "type=bind,source=$hostlock,target=$incontainer_lock,readonly" \
    "$image" bash -c "cd $cdir && cargo metadata --locked --filter-platform $target --format-version 1" 2>/dev/null
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

# The committed candidate Cargo.lock is the SOURCE OF TRUTH (candidates/.gitignore keeps it
# committed and intentionally NOT ignored). It MUST be present, a regular, non-empty, non-symlink
# file. The authoritative resolver regenerates a fresh lock IN-CONTAINER and requires it
# byte-identical to this committed lock (resolve_lock.sh); the committed lock is never rewritten
# during an authoritative run. A host-supplied / injected lock is still refused there.
require_committed_lock() {
  local dir="$1" lock="$1/Cargo.lock"
  [ -e "$lock" ] || die "committed source-of-truth lock absent: $lock (it MUST be committed; the venue never writes a fresh lock into the tree)"
  [ ! -L "$lock" ] || die "committed lock is a symlink (refused): $lock"
  [ -f "$lock" ] || die "committed lock is not a regular file: $lock"
  [ -s "$lock" ] || die "committed lock is empty: $lock"
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
  # Companion verified-TREE provisioner for the guest COMPILER toolchains (SP1 succinct /
  # RISC Zero r0). Same staged-file discipline (COPIED + run in-container, no host lib.sh);
  # tests/guest_toolchain_provision.test.sh exercises it. Its bytes fold into staged_context_blake3.
  cp "$ROOT/scripts/provision_guest_toolchain.sh" "$stage/provisioning/provision_guest_toolchain.sh"
  chmod 0755 "$stage/provisioning/provision_guest_toolchain.sh"
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

# Lifecycle-mode boundary guard for the committed protocol artifact (read-only, no
# network). The two frozen lifecycle phases have OPPOSITE invariants and this splits
# them EXPLICITLY so neither can be run against the wrong repository state:
#
#   * preregistration : the real b0_pre_spec_hash must NOT exist yet — the committed
#                       artifact is `not_finalizable` and NO spec-hash sidecar
#                       (`b0-pre-protocol-v1.json.hash` or the legacy `.hash`) exists.
#   * measurement     : the spec hash IS merged — the committed artifact is
#                       `finalizable` AND the committed `b0-pre-protocol-v1.json.hash`
#                       equals EXACTLY <expected_spec_hash> (64 lowercase hex).
#
# die (exit 2) with a precise REFUSED on any mismatch; prints a one-line PASS note
# otherwise. <docs_dir> is the `docs/b0-pre` root so the guard is unit-testable
# against fabricated fixture trees without the live repository.
# Usage: b0pre_lifecycle_guard <preregistration|measurement> <docs_dir> [<expected_spec_hash>]
b0pre_lifecycle_guard() {
  local mode="${1:-}" docs="${2:-}" want_hash="${3:-}"
  [ -n "$mode" ] && [ -n "$docs" ] || die "b0pre_lifecycle_guard: usage <preregistration|measurement> <docs_dir> [<expected_spec_hash>]"
  local art="$docs/protocol/b0-pre-protocol-v1.json"
  local hashfile="$docs/protocol/b0-pre-protocol-v1.json.hash"
  local legacy="$docs/protocol/b0-pre-protocol-v1.hash"
  [ -f "$art" ] || die "lifecycle guard: committed artifact not found at $art"
  case "$mode" in
    preregistration)
      grep -q '"state": "not_finalizable"' "$art" \
        || die "preregistration: committed artifact must be not_finalizable"
      if [ -e "$hashfile" ] || [ -e "$legacy" ]; then
        die "preregistration: a spec-hash sidecar exists (b0_pre_spec_hash must NOT be written yet)"
      fi
      note "lifecycle: preregistration OK — not_finalizable, no spec-hash sidecar"
      ;;
    measurement)
      [ -n "$want_hash" ] || die "measurement: <expected_spec_hash> is required"
      case "$want_hash" in
        *[!0-9a-f]* | "") die "measurement: expected spec hash must be lowercase hex" ;;
      esac
      [ "${#want_hash}" -eq 64 ] || die "measurement: expected spec hash must be 64 hex chars"
      grep -q '"state": "finalizable"' "$art" \
        || die "measurement: committed artifact must be finalizable"
      if grep -q '"state": "not_finalizable"' "$art"; then
        die "measurement: committed artifact must not carry state not_finalizable"
      fi
      [ -f "$hashfile" ] || die "measurement: committed spec-hash sidecar $hashfile is required"
      local got; got="$(tr -d '[:space:]' < "$hashfile")"
      [ "$got" = "$want_hash" ] \
        || die "measurement: committed b0_pre_spec_hash '$got' != expected '$want_hash'"
      note "lifecycle: measurement OK — finalizable, b0_pre_spec_hash $want_hash"
      ;;
    *)
      die "lifecycle guard: mode must be preregistration|measurement (got '$mode')"
      ;;
  esac
}

# ===========================================================================================
# B0-FINAL measurement identity helpers (ADDITIVE; unused by R5). Both the phase-1 identity
# emitter (derive_guest_set.sh) and the measurement orchestrator (measure_fragment.sh) call
# these so the identities they derive are BYTE-IDENTICAL — a precondition for cross-arch
# reconciliation and the phase-1<->measurement identity compare.
# ===========================================================================================

# Canonical, ARCH-NEUTRAL, deterministic guest build-recipe hash (BLAKE3). The arch-specific
# builder image is bound separately as builder_container_digest (per-arch), never in the recipe.
b0_build_recipe_hash() { # <sp1|risc0>
  local recipe
  case "$1" in
    sp1)   recipe='b0-final-guest-recipe/v1|sp1|cargo prove build --output-directory /out/guest --elf-name guest.elf' ;;
    risc0) recipe='b0-final-guest-recipe/v1|risc0|risc0_build::embed_methods(pinned-local-r0-toolchain,B0_VENUE_EMBED=1)' ;;
    *) return 1 ;;
  esac
  printf '%s' "$recipe" | b3sum | awk '{print $1}'
}

# ============================================================================================
# Canonical RUNNER-BUILD path-independence recipe (cross-arch: SP1/x86, SP1/aarch64, RISC0/x86).
#
# The runner SOURCE is MATERIALIZED at the fixed ratified build path /b0/tooling and built THERE, so
# rustc's package `-Cmetadata`/StableCrateId (which encodes the absolute source path and which
# `--remap-path-prefix` cannot touch — it rewrites compiler-visible source LOCATIONS only) is universal
# and the runner is byte-identical regardless of where the operator's checkout lived. The compiler-visible
# CARGO_HOME is the LITERAL canonical /b0/cargo (materialized fresh per build, canonical by construction,
# NOT remapped); only the per-build target root is remapped -> the FIXED canonical /b0/target destination
# via CARGO_ENCODED_RUSTFLAGS, enforced by the transparent, output-neutral wrapper
# b0_rustc_remap_wrapper.sh (exactly ONE remap per compile: target; the source AND the canonical cargo
# home are canonical by construction and need no remap). The RECIPE is
# byte-identical across arches (it names the canonical build path + destinations + policy + the RULE
# "use the ratified per-arch toolchain", never a specific toolchain digest); the actual per-arch
# toolchain identity is bound SEPARATELY in the runner attestation.
# ============================================================================================
B0_REMAP_TOOLING='/b0/tooling'   # the ratified canonical BUILD path (source materialized here); permitted prefix
B0_REMAP_CARGO='/b0/cargo'       # the canonical compiler-visible CARGO_HOME (materialized fresh per build); NOT a
                                 # remap destination — canonical-by-construction; permitted prefix
B0_REMAP_TARGET='/b0/target'     # the ONLY remap destination (each per-build target root -> here)
B0_RUNNER_REMAP_RECIPE_DOMAIN='b0-final-runner-remap-recipe/v1'

# Canonicalize an actual build-input root: require ABSOLUTE, existing directory, NOT a symlink, and
# `readlink -f`-stable; refuse relative/symlink/missing and any canonical destination used as a FROM.
# Prints the canonical absolute path.
b0_canonicalize_root() { # <label> <path>
  local label="$1" p="$2" rp
  [ -n "$p" ] || { echo "$label root is empty" >&2; return 1; }
  case "$p" in /*) ;; *) echo "$label root is not absolute: $p" >&2; return 1 ;; esac
  [ ! -L "$p" ] || { echo "$label root is a symlink (refused): $p" >&2; return 1; }
  [ -d "$p" ] || { echo "$label root is not an existing directory: $p" >&2; return 1; }
  rp="$(readlink -f "$p" 2>/dev/null || (cd "$p" 2>/dev/null && pwd -P))" \
    || { echo "$label root does not canonicalize: $p" >&2; return 1; }
  [ -n "$rp" ] || { echo "$label root does not canonicalize: $p" >&2; return 1; }
  case "$rp" in
    "$B0_REMAP_TOOLING"|"$B0_REMAP_CARGO"|"$B0_REMAP_TARGET")
      echo "$label root is a canonical destination (refused as a FROM path): $rp" >&2; return 1 ;;
  esac
  printf '%s' "$rp"
}

# Canonical CARGO_ENCODED_RUSTFLAGS (unit-separator delimited) — ONE remap: the per-build TARGET root ->
# the canonical /b0/target. The SOURCE is NOT remapped (materialized + compiled at the canonical build
# path /b0/tooling, universal by construction) and the CARGO_HOME is NOT remapped either: the
# compiler-visible cargo home is the literal canonical /b0/cargo (materialized fresh per build), so Cargo
# already sees /b0/cargo and a cargo-home remap would be a FAKE identity mapping — omitted so the recipe's
# remap inventory reflects the ACTUAL effective mapping. This is also what makes the nested SP1
# sp1-native-bins build (which strips the remap rustflags) path-independent BY CONSTRUCTION: it compiles
# vendored deps out of the canonical /b0/cargo, not a per-build home. Refuses non-absolute/symlink target
# roots and a target equal to a canonical destination.
b0_canonical_encoded_rustflags() { # <target_dir>
  local target
  target="$(b0_canonicalize_root target "$1")" || return 1
  case "$target" in "$B0_REMAP_CARGO"|"$B0_REMAP_TOOLING") echo "target root coincides with a canonical destination: $target" >&2; return 1 ;; esac
  printf -- '--remap-path-prefix=%s=%s' "$target" "$B0_REMAP_TARGET"
}

# Cross-arch STRUCTURAL recipe id (BLAKE3, 64-hex): describes the RULE, never a toolchain digest, so
# it is byte-identical for SP1/x86, SP1/aarch64, RISC0/x86. Binds the canonical BUILD path, the canonical
# cargo home (canonical-by-construction: the literal /b0/cargo, materialized fresh per build — NOT
# remapped), the ONE canonical remap destination (target), the encoded-flags format, --locked,
# SOURCE_DATE_EPOCH=0, BUILD_GIT_SHA=<measured source>, the ratified-per-arch-toolchain RULE, and the
# wrapper's own hash. (The v2 form bound a fake cargo-home remap + a 2-remap encoding; this v3 form binds
# the actual effective mapping: /b0/cargo canonical-by-construction + a single target remap.)
b0_runner_remap_recipe_id() { # <measured_source_commit_40hex> <wrapper_blake3_64hex>
  local msc="$1" wh="$2"
  printf '%s' "$msc" | grep -Eq '^[0-9a-f]{40}$' || { echo "recipe-id: measured source commit must be 40-hex" >&2; return 1; }
  printf '%s' "$wh"  | grep -Eq '^[0-9a-f]{64}$' || { echo "recipe-id: wrapper blake3 must be 64-hex" >&2; return 1; }
  printf '%s|build_at=%s|cargo_home=%s(canonical-by-construction,fresh-per-build)|remap:target=%s|encoded_rustflags=unit-separator-1-remap|flags=--locked|SOURCE_DATE_EPOCH=0|BUILD_GIT_SHA=%s|toolchain=ratified-per-arch(authority-record)|wrapper_blake3=%s' \
    "$B0_RUNNER_REMAP_RECIPE_DOMAIN" "$B0_REMAP_TOOLING" "$B0_REMAP_CARGO" "$B0_REMAP_TARGET" "$msc" "$wh" \
    | b3sum | awk '{print $1}'
}

# ============================================================================================
# Authenticated FULL-BUILD-INPUT source manifest for the shared materialization boundary.
#
# A distinct source PATH alone does not prove A and B (and their materializations at the canonical
# build path) carry the SAME bytes. `b0_source_manifest` walks a build-input tree and emits a canonical,
# LC_ALL=C-sorted manifest — one line per entry, regular file `f <octal-mode> <size> <blake3>  <relpath>`
# / directory `d <octal-mode> - -  <relpath>` — covering EVERY file (not just the 164-file tooling set:
# Cargo manifests/locks and other inputs live outside it). It FAILS CLOSED on any entry that is not a
# regular file or directory (symlink / device / socket / FIFO), any control character in a name, and any
# ".." path component. The repo tracks ZERO symlinks/submodules, so no reviewed rule permits any other
# entry type. `b0_source_manifest_addr` returns the domain-separated BLAKE3 of that manifest — the
# content address the double-build proof binds so both import verifiers can enforce
#   origin_A == origin_B == materialized_A == materialized_B.
# ============================================================================================
B0_SOURCE_MANIFEST_DOMAIN='b0-final-source-input-manifest/v1'
# Portable stat (GNU first, BSD fallback). Only internal consistency is required (same host, one run).
b0_stat_mode() { stat -c '%a' "$1" 2>/dev/null || stat -f '%Lp' "$1" 2>/dev/null; }
b0_stat_size() { stat -c '%s' "$1" 2>/dev/null || stat -f '%z' "$1" 2>/dev/null; }
b0_source_manifest() { # <root> ; prints canonical manifest to stdout; fail-closed (non-zero) on refusal
  local root="$1"
  [ -d "$root" ] || { echo "manifest: not a directory: $root" >&2; return 1; }
  ( cd "$root" || exit 1
    # Refuse ANY entry that is neither a regular file nor a directory (symlink/device/socket/FIFO).
    # Capture the full list (no `head`/early-close, so a pipefail SIGPIPE can never invert the check).
    local bad; bad="$(find . -mindepth 1 ! -type f ! -type d -print 2>/dev/null)"
    if [ -n "$bad" ]; then
      echo "manifest: refused non-regular entry (symlink/device/socket/fifo) under $root: ${bad%%$'\n'*}" >&2
      exit 3
    fi
    local p rel
    while IFS= read -r p; do
      rel="${p#./}"
      case "$rel" in *[[:cntrl:]]*) echo "manifest: control character in path '$rel'" >&2; exit 4 ;; esac
      case "/$rel/" in */../*) echo "manifest: traversal component in '$rel'" >&2; exit 5 ;; esac
      if [ -d "$p" ]; then
        printf 'd %s - -  %s\n' "$(b0_stat_mode "$p")" "$rel"
      elif [ -f "$p" ]; then
        printf 'f %s %s %s  %s\n' "$(b0_stat_mode "$p")" "$(b0_stat_size "$p")" \
          "$(b3sum "$p" | awk '{print $1}')" "$rel"
      else
        echo "manifest: unexpected entry type: '$rel'" >&2; exit 6
      fi
    done < <(LC_ALL=C find . -mindepth 1 \( -type f -o -type d \) -print | LC_ALL=C sort)
  )
}
b0_source_manifest_addr() { # <root> ; prints the 64-hex domain-separated BLAKE3 of the manifest
  local m; m="$(b0_source_manifest "$1")" || return 1
  { printf '%s\0' "$B0_SOURCE_MANIFEST_DOMAIN"; printf '%s' "$m"; } | b3sum | awk '{print $1}'
}

# ============================================================================================
# Runner leakage scan — the guarantee is the ABSENCE of uncontrolled absolute PATH PREFIXES and
# uncontrolled PATH COMPONENTS in the reproducible runner, NOT the absence of a bare username/hostname
# substring. The username/hostname matter only where they form a path (e.g. /home/<user>): ordinary
# prose that merely contains the word (like "measurement runner") is NOT a leak. So the username/
# hostname are matched ONLY as a complete path component — `/<name>/` (component boundary) or a
# path-ending `/<name>` — never as a bare substring.
# ============================================================================================
# True iff <component> appears in <text> as a COMPLETE path component: preceded by `/` and followed by
# `/`, end-of-line, or any character that cannot continue a filename component ([^A-Za-z0-9._-]). So
# `/home/runner` and `/tmp/runner/x` hit; `measurement runner`, `prerunner`, `runner_api`,
# `/home/runner_api` do NOT.
b0_path_component_hit() { # <component> <text>  -> exit 0 iff present as a full path component
  local comp="$1" text="$2" esc
  [ -n "$comp" ] || return 1
  esc="$(printf '%s' "$comp" | sed 's/[^A-Za-z0-9]/\\&/g')"   # escape every non-alnum -> ERE literal
  printf '%s\n' "$text" | grep -Eq "/${esc}([^A-Za-z0-9._-]|\$)"
}
# Fail-closed leakage scan over <text> (the runner's `strings`). Refuses on the FIRST hit and prints a
# classified token: an exact uncontrolled absolute-path PREFIX (source/cargo/target/evidence/work/HOME/
# TMPDIR/...), or the username/hostname as a PATH COMPONENT. Returns 0 (clean) only if none hit.
b0_leakage_scan() { # <text> <refused-prefixes-newline-separated> <username> <hostname>
  local text="$1" refused="$2" user="$3" host="$4" p
  while IFS= read -r p; do
    [ -n "$p" ] || continue
    if printf '%s\n' "$text" | grep -Fq -- "$p"; then printf 'path-prefix:%s\n' "$p"; return 1; fi
  done <<EOF
$refused
EOF
  if [ -n "$user" ] && b0_path_component_hit "$user" "$text"; then printf 'user-path-component:/%s\n' "$user"; return 1; fi
  if [ -n "$host" ] && b0_path_component_hit "$host" "$text"; then printf 'host-path-component:/%s\n' "$host"; return 1; fi
  return 0
}

# The ratified expected nested SP1 host-binary basename SET — the host binary the pinned nested crate
# `sp1-core-executor-runner` 6.3.1 (see b0_runner_dependency_seed) produces. Enforced as a STRONGER
# authority than the executable bit alone: the qualifying executable set must EQUAL this exactly, so a
# smuggled extra executable OR a missing nested binary is refused. Space-separated if ever more than one.
B0_EXPECTED_NESTED_SP1_HOST_BINS="sp1-core-executor-runner-binary"

# Leakage-scan the nested SP1 host binary(ies). <release_dir> is the nested sp1-core-executor-runner
# `sp1-native-bins/release` output directory. Enumerates its DIRECT-CHILD regular, NON-symlink, EXECUTABLE
# host binaries (deps/.fingerprint/build/incremental are subdirectories, excluded by the depth-1 walk) via
# a FULL-CONSUMPTION NUL array — NO `head`, no early-closing pipeline — so a multi-thousand-file nested
# target dir can NEVER SIGPIPE the pipeline (rc 141) under `set -euo pipefail`. Enforces the ratified
# expected basename set, then leakage-scans EACH executable. On success prints one TSV evidence line per
# binary: "<relpath-under-troot>\t<sha256>\t<blake3>\t<size>\tclean". Fail-closed (returns 1 + a stderr
# reason) on: missing / symlink / non-directory release dir; a symlink / non-regular / unreadable
# candidate; an EMPTY executable set; a basename set != the ratified expected; or leakage in ANY executable.
b0_scan_nested_sp1_host_bins() { # <release_dir> <refused-newline-list> <user> <host> <target_root>
  local rd="$1" refused="$2" user="$3" host="$4" troot="$5" f
  [ -e "$rd" ] || { echo "nested release dir not found: $rd" >&2; return 1; }
  [ ! -L "$rd" ] || { echo "nested release dir is a symlink (refused): $rd" >&2; return 1; }
  [ -d "$rd" ] || { echo "nested release path is not a directory (refused): $rd" >&2; return 1; }
  # Direct-child regular non-symlink executables, NUL-sorted into an array (full consumption; no head).
  local -a execs=()
  while IFS= read -r -d '' f; do execs+=("$f"); done \
    < <(find "$rd" -maxdepth 1 -type f ! -type l -perm -u+x -print0 | LC_ALL=C sort -z)
  [ "${#execs[@]}" -ge 1 ] || { echo "no qualifying nested host executable under $rd" >&2; return 1; }
  # Ratified basename-set enforcement (stronger than exec bits alone).
  local -a bns=(); for f in "${execs[@]}"; do bns+=("$(basename "$f")"); done
  local got want
  got="$(printf '%s\n' "${bns[@]}" | LC_ALL=C sort | tr '\n' ' ')"
  # shellcheck disable=SC2086
  want="$(printf '%s\n' $B0_EXPECTED_NESTED_SP1_HOST_BINS | LC_ALL=C sort | tr '\n' ' ')"
  [ "$got" = "$want" ] || { echo "nested host-binary set [$got] != ratified expected [$want]" >&2; return 1; }
  # Scan EACH executable; emit its evidence line.
  for f in "${execs[@]}"; do
    [ ! -L "$f" ] || { echo "nested candidate is a symlink (refused): $f" >&2; return 1; }
    [ -f "$f" ]   || { echo "nested candidate is not a regular file (refused): $f" >&2; return 1; }
    [ -r "$f" ]   || { echo "nested candidate is unreadable (refused): $f" >&2; return 1; }
    local ns hit
    ns="$(strings -a "$f" 2>/dev/null || true)"
    if hit="$(b0_leakage_scan "$ns" "$refused" "$user" "$host")"; then :; else
      echo "nested host binary $(basename "$f") leakage: $hit" >&2; return 1
    fi
    local rel sz sha b3
    rel="${f#"$troot"/}"; sz="$(wc -c <"$f" | tr -d ' ')"
    sha="$(sha256sum "$f" | cut -d' ' -f1)"; b3="$(b3sum "$f" | cut -d' ' -f1)"
    printf '%s\t%s\t%s\t%s\tclean\n' "$rel" "$sha" "$b3" "$sz"
  done
}

# Refuse ambient rustflags that could inject/alter flags: any nonempty RUSTFLAGS or
# CARGO_BUILD_RUSTFLAGS, and an inherited CARGO_ENCODED_RUSTFLAGS unless it EQUALS <canonical>.
b0_refuse_ambient_rustflags() { # <canonical_encoded_rustflags>
  local canon="$1"
  [ -z "${RUSTFLAGS:-}" ] || { echo "ambient RUSTFLAGS set (refused; recipe uses canonical CARGO_ENCODED_RUSTFLAGS)" >&2; return 1; }
  [ -z "${CARGO_BUILD_RUSTFLAGS:-}" ] || { echo "ambient CARGO_BUILD_RUSTFLAGS set (refused)" >&2; return 1; }
  if [ -n "${CARGO_ENCODED_RUSTFLAGS:-}" ] && [ "${CARGO_ENCODED_RUSTFLAGS}" != "$canon" ]; then
    echo "inherited CARGO_ENCODED_RUSTFLAGS != canonical recipe value (refused)" >&2; return 1
  fi
  return 0
}

# ============================================================================================
# RUNNER HOST COMPILER attestation (§A) — the NATIVE cargo/rustc that compiles the measurement runner.
# This is the per-ARCH host runner compiler, bound SEPARATELY from the SP1/RISC0 prover/toolchain
# identity (b0_toolchain_identity). Per-arch selection is legitimate (x86=1.90.0, ARM=1.88.0): each
# venue uses the native immutable toolchain that satisfies its committed runner graph. The structural
# recipe id stays toolchain-version-INDEPENDENT; THIS attestation is the separate bound per-arch field.
#
# Emits b0-final-runner-host-toolchain/v1 JSON binding: requested toolchain, resolved cargo/rustc paths,
# `cargo --version --verbose`, `rustc -vV`, cargo/rustc SHA-256+BLAKE3, sysroot + its canonical content
# inventory address. The domain-separated `address` is over the VENUE-INDEPENDENT content identity
# (arch + requested toolchain + cargo/rustc verbose + binary hashes + sysroot address), NOT host paths.
B0_RUNNER_HOST_TOOLCHAIN_DOMAIN='b0-final-runner-host-toolchain/v1'
B0_RUNNER_TOOLCHAIN_SYSROOT_DOMAIN='b0-final-runner-toolchain-sysroot/v1'
# Canonical sysroot content address: domain-separated SHA-256 over LC_ALL=C-sorted lines — regular file
# `f <sha256>  <relpath>`, symlink `l <target>  <relpath>` — fail-closed on `..`/control chars.
b0_toolchain_sysroot_address() { # <sysroot> -> 64-hex
  local sr="$1"; [ -d "$sr" ] || { echo "sysroot not a dir: $sr" >&2; return 1; }
  { printf '%s\0' "$B0_RUNNER_TOOLCHAIN_SYSROOT_DOMAIN"
    ( cd "$sr" || exit 1
      while IFS= read -r p; do
        local rel="${p#./}"
        case "$rel" in *[[:cntrl:]]*|*/../*) echo "sysroot bad path: $rel" >&2; exit 4 ;; esac
        if [ -L "$p" ]; then printf 'l %s  %s\n' "$(readlink "$p")" "$rel"
        elif [ -f "$p" ]; then printf 'f %s  %s\n' "$(sha256sum "$p"|cut -d' ' -f1)" "$rel"
        fi
      done < <(LC_ALL=C find . -mindepth 1 \( -type f -o -type l \) -print | LC_ALL=C sort)
    ) || exit 1
  } | sha256sum | awk '{print $1}'
}
b0_host_toolchain_attestation() { # <toolchain> <arch> <out_json>
  local tc="$1" arch="$2" out="$3" sysroot rcargo rrustc
  require_cmd sha256sum; require_cmd b3sum; require_cmd python3
  case "$arch" in x86_64|aarch64) ;; *) echo "bad arch: $arch" >&2; return 1 ;; esac
  sysroot="$(rustc "+$tc" --print sysroot 2>/dev/null)" \
    || { echo "toolchain +$tc not available (rustc --print sysroot failed)" >&2; return 1; }
  [ -d "$sysroot" ] || { echo "resolved sysroot is not a dir: $sysroot" >&2; return 1; }
  rcargo="$sysroot/bin/cargo"; rrustc="$sysroot/bin/rustc"
  [ -x "$rcargo" ] && [ -x "$rrustc" ] || { echo "resolved cargo/rustc not executable under $sysroot/bin" >&2; return 1; }
  local cver rvv csha cbl rsha rbl saddr
  cver="$("$rcargo" --version --verbose 2>/dev/null)" || return 1
  rvv="$("$rrustc" -vV 2>/dev/null)" || return 1
  csha="$(sha256sum "$rcargo"|cut -d' ' -f1)"; cbl="$(b3sum "$rcargo"|awk '{print $1}')"
  rsha="$(sha256sum "$rrustc"|cut -d' ' -f1)"; rbl="$(b3sum "$rrustc"|awk '{print $1}')"
  saddr="$(b0_toolchain_sysroot_address "$sysroot")" || return 1
  python3 - "$out" "$arch" "$tc" "$rcargo" "$rrustc" "$cver" "$rvv" "$csha" "$cbl" "$rsha" "$rbl" "$sysroot" "$saddr" "$B0_RUNNER_HOST_TOOLCHAIN_DOMAIN" <<'PY'
import json, sys, hashlib
(out, arch, tc, cpath, rpath, cver, rvv, csha, cbl, rsha, rbl, sysroot, saddr, domain) = sys.argv[1:15]
sysroot_files = 0
try:
    import os
    for dp, dns, fns in os.walk(sysroot):
        sysroot_files += len(fns)
except Exception:
    pass
obj = {"schema": "b0-final-runner-host-toolchain/v1", "arch": arch, "requested_toolchain": tc,
       "cargo_path": cpath, "rustc_path": rpath, "cargo_version_verbose": cver, "rustc_vV": rvv,
       "cargo_sha256": csha, "cargo_blake3": cbl, "rustc_sha256": rsha, "rustc_blake3": rbl,
       "sysroot": sysroot, "sysroot_file_count": sysroot_files, "sysroot_address": saddr}
# Venue-INDEPENDENT content-address: exclude host-specific paths + counts; bind identity fields only.
pre = "\0".join([domain, arch, tc, cver, rvv, csha, cbl, rsha, rbl, saddr])
obj["address"] = hashlib.sha256(pre.encode()).hexdigest()
with open(out, "w") as f:
    json.dump(obj, f, indent=1, sort_keys=True); f.write("\n")
PY
}

# ============================================================================================
# NATIVE PROTOC AUTHORITY (§ protoc) — bound SEPARATELY from the Cargo dependency authority. The SP1
# runner graph (prost-build) needs a native `protoc` + the committed protobuf-include-authority; RISC0
# does not. Binds: protoc version, protoc executable path + SHA-256/BLAKE3, the include-authority content
# address + file inventory, and the exact PROTOC/PROTOC_INCLUDE the build used. The include tree is used
# READ-ONLY. Refuses ambient/fallback protoc, a wrong executable, and a writable/mutated include tree.
B0_PROTOC_AUTHORITY_DOMAIN='b0-final-runner-protoc-authority/v1'
b0_protoc_include_address() { # <include-dir> -> 64-hex over sorted `<sha256>  <relpath>` of regular files
  local inc="$1"; [ -d "$inc" ] || { echo "protoc include dir absent: $inc" >&2; return 1; }
  local bad; bad="$(find "$inc" -mindepth 1 ! -type f ! -type d -print 2>/dev/null)"
  [ -z "$bad" ] || { echo "protoc include tree has a non-regular entry: ${bad%%$'\n'*}" >&2; return 3; }
  { printf '%s\0' "$B0_PROTOC_AUTHORITY_DOMAIN"
    ( cd "$inc" && while IFS= read -r p; do printf '%s  %s\n' "$(sha256sum "$p"|cut -d' ' -f1)" "${p#./}"; done \
      < <(LC_ALL=C find . -mindepth 1 -type f -print | LC_ALL=C sort) )
  } | sha256sum | awk '{print $1}'
}
b0_protoc_authority() { # <candidate> <arch> <protoc-exe> <include-dir> <out_json>
  local cand="$1" arch="$2" pexe="$3" inc="$4" out="$5"
  require_cmd sha256sum; require_cmd b3sum; require_cmd python3
  [ -x "$pexe" ] || { echo "protoc executable not found/executable: $pexe" >&2; return 1; }
  [ -f "$inc/google/protobuf/empty.proto" ] || { echo "include-authority missing google/protobuf/empty.proto: $inc" >&2; return 1; }
  # Read-only enforcement: the include tree must NOT be writable by us.
  [ ! -w "$inc/google/protobuf/empty.proto" ] || echo "WARN: protoc include tree is writable (should be RO)" >&2
  local pver psha pbl iaddr
  # The venue protoc's shared libs (libprotoc/libprotobuf) sit next to it in `<protoc-dir>/lib`; add it
  # to LD_LIBRARY_PATH so `protoc --version` resolves them (else it fails "missing libs").
  local plibdir; plibdir="$(dirname "$pexe")/lib"
  local ldp="${LD_LIBRARY_PATH:-}"; [ -d "$plibdir" ] && ldp="$plibdir${ldp:+:$ldp}"
  pver="$(LD_LIBRARY_PATH="$ldp" "$pexe" --version 2>/dev/null)" \
    || { echo "protoc --version failed (missing libs? tried LD_LIBRARY_PATH=$plibdir)" >&2; return 1; }
  psha="$(sha256sum "$pexe"|cut -d' ' -f1)"; pbl="$(b3sum "$pexe"|awk '{print $1}')"
  iaddr="$(b0_protoc_include_address "$inc")" || return 1
  local ifiles; ifiles="$(find "$inc" -type f | wc -l | tr -d ' ')"
  python3 - "$out" "$cand" "$arch" "$pexe" "$pver" "$psha" "$pbl" "$inc" "$iaddr" "$ifiles" "$B0_PROTOC_AUTHORITY_DOMAIN" <<'PY'
import json, sys, hashlib
(out, cand, arch, pexe, pver, psha, pbl, inc, iaddr, ifiles, domain) = sys.argv[1:12]
obj = {"schema": "b0-final-runner-protoc-authority/v1", "candidate": cand, "arch": arch,
       "protoc_path": pexe, "protoc_version": pver, "protoc_sha256": psha, "protoc_blake3": pbl,
       "include_dir": inc, "include_file_count": int(ifiles), "include_address": iaddr,
       "env_PROTOC": pexe, "env_PROTOC_INCLUDE": inc}
pre = "\0".join([domain, cand, arch, pver, psha, pbl, iaddr])  # venue-independent identity
obj["address"] = hashlib.sha256(pre.encode()).hexdigest()
with open(out, "w") as f:
    json.dump(obj, f, indent=1, sort_keys=True); f.write("\n")
PY
}

# ============================================================================================
# RUNNER DEPENDENCY SEED (§B/§C) — authenticated, lock-derived, content-addressed vendor seed of the EXACT
# committed runner dependency GRAPH SET, provisioned ONCE (disclosed network) and consumed by the OFFLINE
# A/B builds. RISC0 graph set = {main risc0 runner}. SP1 graph set = {main sp1 runner, nested
# sp1-core-executor-runner 6.3.1} — the nested graph is REQUIRED because that crate's build.rs runs a
# nested cargo build of an inner executor binary against its OWN bundled lock (venue-proven). The nested
# manifest+lock come ONLY from the checksum-verified vendored package the MAIN lock selected.
# ============================================================================================
b0_seed_inventory_address() { # <seed-dir> -> 64-hex (nonzero + msg if any non-regular entry)
  local sd="$1"; [ -d "$sd" ] || { echo "seed dir absent: $sd" >&2; return 1; }
  local bad; bad="$(find "$sd" -mindepth 1 ! -type f ! -type d -print 2>/dev/null)"
  [ -z "$bad" ] || { echo "seed has a non-regular entry: ${bad%%$'\n'*}" >&2; return 3; }
  # Batched (xargs) per-file sha256 for speed over large vendor seeds; canonical LC_ALL=C path order.
  # sha256sum emits `<hash>  ./<relpath>`; strip the `./` to get `<hash>  <relpath>`; the input list is
  # pre-sorted and xargs preserves arg order, so the concatenated lines are globally path-sorted.
  { printf '%s\0' "$B0_RUNNER_DEP_SEED_DOMAIN"
    ( cd "$sd" && LC_ALL=C find . -mindepth 1 -type f -print0 | LC_ALL=C sort -z \
        | xargs -0 -r sha256sum | sed 's#  \./#  #' )
  } | sha256sum | awk '{print $1}'
}
B0_RUNNER_DEP_SEED_DOMAIN='b0-final-runner-dependency-seed/v1'
# The registry-source checksum the MAIN lock records for a package (authenticates the nested source).
b0_lock_pkg_checksum() { # <lock> <name> <version> -> checksum ('' if none)
  python3 - "$1" "$2" "$3" <<'PY'
import sys
lock,name,ver=sys.argv[1:4]; cur=None; found=""
for line in open(lock):
    t=line.strip()
    if t=="[[package]]": cur={}
    elif cur is not None:
        if t.startswith('name = '): cur['n']=t.split('"')[1]
        elif t.startswith('version = '): cur['v']=t.split('"')[1]
        elif t.startswith('checksum = '):
            if cur.get('n')==name and cur.get('v')==ver: found=t.split('"')[1]
print(found)
PY
}
# Append `[net] offline = true` to a `cargo vendor`-emitted source-replacement config, so a build that
# consumes it is offline even when the runner (risc0-build) strips CARGO_NET_OFFLINE from the env.
b0_config_add_offline() { # <config.toml>
  local cfg="$1"
  grep -qE '^[[:space:]]*offline[[:space:]]*=[[:space:]]*true' "$cfg" 2>/dev/null \
    || printf '\n[net]\noffline = true\n' >> "$cfg"
}

# Provision the exact, committed dependency graph SET for a candidate as one or more content-addressed
# SEED UNITS, and emit the DependencySeedV1 facts. A seed unit = one vendored source tree + its
# source-replacement config (offline) + its content address + the cargo home it materializes into.
#
#   SP1   -> ONE host-cargo-home unit: the main runner lock UNIONED (--sync) with the checksum-bound
#            nested sp1-core-executor-runner 6.3.1 lock (its build.rs runs an inner `cargo metadata`).
#   RISC0 -> TWO units: (a) host-cargo-home = the main runner lock (outer runner build); (b) guest-home
#            = the committed candidate WORKSPACE lock (8949ae62), which embed_methods() builds the guest
#            against. risc0-build strips every CARGO* env, so the guest build can only be controlled +
#            forced offline via HOME -> $HOME/.cargo (a SEPARATE cargo home from the host unit). The
#            guest graph genuinely diverges from the host seed (e.g. risc0-groth16 3.0.4 vs 3.0.5), so
#            it is a distinct authenticated graph, NOT a subset of the host seed.
#
# Layout under <out-dir>: host-seed/ + host-config.toml [+ guest-seed/ + guest-config.toml for risc0].
b0_runner_dependency_seed() { # <candidate> <toolchain> <src-root> <out-dir> <json-out>
  local cand="$1" tc="$2" src="$3" outdir="$4" json="$5"
  require_cmd sha256sum; require_cmd b3sum; require_cmd python3; require_cmd cargo
  local manifest lock gmanifest="" glock=""
  case "$cand" in
    risc0)
      manifest="tools/b0-pre-measure-risc0/Cargo.toml"; lock="tools/b0-pre-measure-risc0/Cargo.lock"
      gmanifest="tools/b0-pre-candidates/candidates/risc0/Cargo.toml"; glock="tools/b0-pre-candidates/candidates/risc0/Cargo.lock" ;;
    sp1) manifest="tools/b0-pre-measure-sp1/Cargo.toml"; lock="tools/b0-pre-measure-sp1/Cargo.lock" ;;
    *) echo "bad candidate: $cand" >&2; return 1 ;;
  esac
  [ -f "$src/$manifest" ] && [ -f "$src/$lock" ] || { echo "manifest/lock absent under $src" >&2; return 1; }
  local owd="$PWD" src_abs; src_abs="$(cd "$src" && pwd -P)" || return 1
  local manifest_abs="$src_abs/$manifest" lock_abs="$src_abs/$lock" k
  for k in outdir json; do case "${!k}" in /*) ;; *) eval "$k=\"$owd/${!k}\"";; esac; done
  rm -rf "$outdir"; mkdir -p "$outdir"
  local work; work="$(mktemp -d)"; local prov_home="$work/prov-cargo"
  local host_seed="$outdir/host-seed" host_config="$outdir/host-config.toml"

  # ---- HOST seed unit (the outer runner build's CARGO_HOME) ----
  local -a vend=(cargo "+$tc" vendor --locked --versioned-dirs --manifest-path "$manifest_abs")
  local sync_manifest="" nested_name="sp1-core-executor-runner" nested_ver="6.3.1"
  if [ "$cand" = sp1 ]; then
    # First vendor main only to obtain the checksum-verified nested package, then re-vendor with --sync.
    local tmp0="$work/seed0"
    CARGO_HOME="$prov_home" cargo "+$tc" vendor --locked --versioned-dirs --manifest-path "$manifest_abs" "$tmp0" >/dev/null 2>"$work/vend0.err" \
      || { echo "sp1 main vendor failed"; sed -n '1,5p' "$work/vend0.err" >&2; rm -rf "$work"; return 1; }
    sync_manifest="$tmp0/${nested_name}-${nested_ver}/Cargo.toml"
    [ -f "$sync_manifest" ] && [ -f "$tmp0/${nested_name}-${nested_ver}/Cargo.lock" ] \
      || { echo "nested $nested_name $nested_ver manifest/lock absent in main vendor output (not selected by main lock?)" >&2; rm -rf "$work"; return 1; }
    # Authenticate: the nested package must be the registry crate the MAIN lock selected (checksum bound).
    local mainck; mainck="$(b0_lock_pkg_checksum "$lock_abs" "$nested_name" "$nested_ver")"
    [ -n "$mainck" ] || { echo "main lock does not select $nested_name $nested_ver (no checksum)" >&2; rm -rf "$work"; return 1; }
    vend+=(--sync "$sync_manifest")
  fi
  vend+=("$host_seed")
  CARGO_HOME="$prov_home" "${vend[@]}" >"$host_config" 2>"$work/vend.err" \
    || { echo "host vendor failed for $cand"; sed -n '1,8p' "$work/vend.err" >&2; rm -rf "$work"; return 1; }
  b0_config_add_offline "$host_config"
  local host_seed_abs; host_seed_abs="$(cd "$host_seed" && pwd -P)"
  local host_addr; host_addr="$(b0_seed_inventory_address "$host_seed")" || { rm -rf "$work"; return 1; }
  if [ "$cand" = sp1 ]; then
    [ -d "$host_seed/libc-0.2.186" ] && [ -d "$host_seed/libc-0.2.189" ] \
      || { echo "sp1 host seed missing both required libc versions (0.2.186 nested + 0.2.189 main)" >&2; rm -rf "$work"; return 1; }
  fi

  # ---- GUEST seed unit (RISC0 only; embed_methods() builds the guest against this via HOME) ----
  local guest_seed="" guest_config="" guest_seed_abs="" guest_addr="" gmanifest_abs="" glock_abs=""
  if [ "$cand" = risc0 ]; then
    [ -f "$src/$gmanifest" ] && [ -f "$src/$glock" ] || { echo "risc0 guest workspace manifest/lock absent" >&2; rm -rf "$work"; return 1; }
    gmanifest_abs="$src_abs/$gmanifest"; glock_abs="$src_abs/$glock"
    guest_seed="$outdir/guest-seed"; guest_config="$outdir/guest-config.toml"
    CARGO_HOME="$work/gprov" cargo "+$tc" vendor --locked --versioned-dirs --manifest-path "$gmanifest_abs" "$guest_seed" >"$guest_config" 2>"$work/gvend.err" \
      || { echo "risc0 guest vendor failed"; sed -n '1,8p' "$work/gvend.err" >&2; rm -rf "$work"; return 1; }
    b0_config_add_offline "$guest_config"
    guest_seed_abs="$(cd "$guest_seed" && pwd -P)"
    guest_addr="$(b0_seed_inventory_address "$guest_seed")" || { rm -rf "$work"; return 1; }
    # Prove the guest graph genuinely diverges from the host seed (a candidate-workspace-only version).
    [ -d "$guest_seed/risc0-groth16-3.0.4" ] \
      || { echo "risc0 guest seed missing candidate-workspace version risc0-groth16-3.0.4" >&2; rm -rf "$work"; return 1; }
  fi

  # ---- Emit DependencySeedV1 (seed units + graph set + combined content address) ----
  python3 - "$json" "$cand" "$src_abs" "$manifest" "$lock" "$host_seed_abs" "$host_config" "$host_addr" "$tc" "$sync_manifest" "$nested_name" "$nested_ver" "$gmanifest" "$glock" "$guest_seed_abs" "$guest_config" "$guest_addr" <<'PY'
import json, sys, hashlib, os, subprocess
(out, cand, src, manifest, lock, host_seed_abs, host_config, host_addr, tc,
 sync_manifest, nn, nv, gmanifest, glock, guest_seed_abs, guest_config, guest_addr) = sys.argv[1:18]
def sha(p):
    x=hashlib.sha256(); x.update(open(p,'rb').read()); return x.hexdigest()
def bl(p): return subprocess.run(['b3sum',p],capture_output=True,text=True).stdout.split()[0]
def parent_checksum(lockpath,name,ver):
    cur=None; f=("","")
    for line in open(lockpath):
        t=line.strip()
        if t=="[[package]]": cur={}
        elif cur is not None:
            if t.startswith('name = '): cur['n']=t.split('"')[1]
            elif t.startswith('version = '): cur['v']=t.split('"')[1]
            elif t.startswith('source = '): cur['s']=t.split('"')[1]
            elif t.startswith('checksum = '):
                if cur.get('n')==name and cur.get('v')==ver: f=(cur.get('s',''),t.split('"')[1])
    return f
graphs=[]
mainlockpath=os.path.join(src,lock)
graphs.append({"purpose":"main","name":cand+"-runner","materialization":"host-cargo-home",
    "manifest_relpath":manifest,"manifest_sha256":sha(os.path.join(src,manifest)),
    "lock_sha256":sha(mainlockpath),"lock_blake3":bl(mainlockpath),
    "parent":"","relationship":"root",
    "vendor_args":["cargo","+"+tc,"vendor","--locked","--versioned-dirs","--manifest-path",manifest]})
if cand=="sp1" and sync_manifest:
    nlock=os.path.join(os.path.dirname(sync_manifest),"Cargo.lock")
    src_ck=parent_checksum(mainlockpath,nn,nv)
    graphs.append({"purpose":"nested","name":nn+"-"+nv,"materialization":"host-cargo-home",
        "manifest_relpath":"vendored:%s-%s/Cargo.toml"%(nn,nv),"manifest_sha256":sha(sync_manifest),
        "lock_sha256":sha(nlock),"lock_blake3":bl(nlock),
        "parent":"%s %s"%(nn,nv),"parent_registry_source":src_ck[0],"parent_checksum":src_ck[1],
        "relationship":"nested-build.rs-inner-executor",
        "vendor_args":["--sync","vendored:%s-%s/Cargo.toml"%(nn,nv)]})
if cand=="risc0" and guest_seed_abs:
    glockpath=os.path.join(src,glock)
    graphs.append({"purpose":"guest-workspace","name":"b0-pre-candidate-risc0-workspace","materialization":"guest-home",
        "manifest_relpath":gmanifest,"manifest_sha256":sha(os.path.join(src,gmanifest)),
        "lock_sha256":sha(glockpath),"lock_blake3":bl(glockpath),
        "parent":"","relationship":"embed-methods-guest-build",
        "vendor_args":["cargo","+"+tc,"vendor","--locked","--versioned-dirs","--manifest-path",gmanifest]})
seed_units=[{"role":"host-cargo-home","seed_dir":host_seed_abs,
    "vendor_config_sha256":sha(host_config),"seed_address":host_addr,
    "graphs":[g["name"] for g in graphs if g["materialization"]=="host-cargo-home"]}]
if cand=="risc0" and guest_seed_abs:
    seed_units.append({"role":"guest-home","seed_dir":guest_seed_abs,
        "vendor_config_sha256":sha(guest_config),"seed_address":guest_addr,
        "graphs":[g["name"] for g in graphs if g["materialization"]=="guest-home"]})
expected = {"sp1":2,"risc0":2}[cand]
assert len(graphs)==expected, ("graph count", len(graphs), expected)
obj={"schema":"b0-final-runner-dependency-seed/v1","candidate":cand,
     "graphs":graphs,"graph_count":len(graphs),
     "seed_units":seed_units,"seed_unit_count":len(seed_units)}
pre="\0".join(["b0-final-runner-dependency-seed/v1",cand,str(len(graphs)),str(len(seed_units))]
    +[g["lock_sha256"] for g in graphs]
    +[su["seed_address"] for su in seed_units]
    +[su["vendor_config_sha256"] for su in seed_units])
obj["address"]=hashlib.sha256(pre.encode()).hexdigest()
with open(out,"w") as f:
    json.dump(obj, f, indent=1, sort_keys=True); f.write("\n")
PY
  local rc=$?
  rm -rf "$work" 2>/dev/null || true
  return $rc
}

# Materialize a provisioned seed into a build's CARGO_HOME (independent copy) + install its source-
# replacement config, then recompute the seed address and REQUIRE it == the retained seed authority.
b0_materialize_seed() { # <seed-dir> <config> <cargo-home> <expected-seed-address> -> prints materialized address
  local seed="$1" config="$2" chome="$3" expect="$4" mat
  [ -d "$seed" ] || { echo "seed absent: $seed" >&2; return 1; }
  rm -rf "$chome"; mkdir -p "$chome"
  cp -Rp "$seed" "$chome/vendored" || { echo "cannot materialize seed into $chome" >&2; return 1; }
  # Rewrite the config's directory to the materialized copy (independent per build).
  local mat_abs; mat_abs="$(cd "$chome/vendored" && pwd -P)"
  sed -E "s#^directory = .*#directory = \"$mat_abs\"#" "$config" > "$chome/config.toml" \
    || { echo "cannot install vendor config" >&2; return 1; }
  mat="$(b0_seed_inventory_address "$chome/vendored")" || return 1
  [ "$mat" = "$expect" ] || { echo "materialized seed address $mat != retained $expect" >&2; return 1; }
  printf '%s' "$mat"
}

# Toolchain identity (BLAKE3, 64-hex) bound to the RATIFIED provisioned toolchain — never a
# synthetic label. sp1: the pinned builder IMAGE digest (the SP1 toolchain lives inside it);
# risc0: the pinned local r0 toolchain TREE (PROVER_RISC0_HOME), hashed deterministically.
b0_toolchain_identity() { # <sp1|risc0> <sp1-image-id | r0-home-dir>
  case "$1" in
    sp1)
      printf 'b0-final-toolchain/v1|sp1|%s' "$2" | b3sum | awk '{print $1}'
      ;;
    risc0)
      [ -d "$2" ] || return 1
      { printf 'b0-final-toolchain/v1|risc0|'
        ( cd "$2" && find . -type f | LC_ALL=C sort | while IFS= read -r f; do b3sum "$f"; done )
      } | b3sum | awk '{print $1}'
      ;;
    *) return 1 ;;
  esac
}

# The OWNER-RATIFIED hash of docs/b0-pre/venue/toolchain-authority.v1.json. The toolchain
# authority is that content-addressed committed record, VERIFIED against this constant before a
# value is sourced — so the expected toolchain identity is never an unauthenticated operator
# environment variable. Update BOTH the record and this constant in the same reviewed commit.
B0_RATIFIED_TOOLCHAIN_AUTHORITY_B3="b9b82ad4193075e728c8870c3a97d083f0e2064e406094021cbc44f9441dd866"

# Print the RATIFIED expected toolchain identity for <Cand> <arch>, sourced ONLY from the
# content-addressed authority record AFTER verifying its hash equals the ratified constant.
# Fail-closed on a tampered/wrong-hash record or a missing/malformed entry.
b0_ratified_toolchain_identity() { # <Sp1|Risc0> <x86_64|aarch64> <authority-record-path>
  local cand="$1" arch="$2" rec="$3"
  [ -f "$rec" ] || { echo "toolchain-authority record not found: $rec" >&2; return 1; }
  local got; got="$(b3sum "$rec" | awk '{print $1}')"
  [ "$got" = "$B0_RATIFIED_TOOLCHAIN_AUTHORITY_B3" ] \
    || { echo "toolchain-authority record hash $got != ratified $B0_RATIFIED_TOOLCHAIN_AUTHORITY_B3 (tampered/unratified record)" >&2; return 1; }
  python3 - "$rec" "$cand/$arch" <<'PY'
import json, sys
rec = json.load(open(sys.argv[1])); key = sys.argv[2]
v = (rec.get("entries") or {}).get(key)
if not (isinstance(v, str) and len(v) == 64 and all(c in "0123456789abcdef" for c in v)):
    sys.exit(f"authority record has no valid ratified toolchain identity for {key}")
print(v)
PY
}
