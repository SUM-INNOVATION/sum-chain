#!/usr/bin/env bash
# Build a candidate container reproducibly and record the Stage-6 inputs for one
# (candidate, arch): the base + builder OCI manifest identities, BOTH clean-build
# digests, per-build command-log + raw-output hashes, and the native-build
# provenance. The emitted files decode DIRECTLY in the Stage-6 assembler
# (`OciBuild` / `NativeBuild` shapes) with no manual reshaping.
#
# Native-arch, no push, two clean builds compared. Refuses on any missing immutable
# input, placeholder digest, wrong/emulated architecture, or absent Linux OCI
# builder. NEVER fabricates.
#
# Usage:
#   build_container.sh <sp1|risc0> <x86_64|aarch64> <out_dir>
# Required env (venue-supplied immutable inputs, from the ratified pins.env):
#   BASE_IMAGE BASE_DIGEST
#   APT_DEBIAN_URL APT_DEBIAN_INRELEASE_SHA256
#   APT_SECURITY_URL APT_SECURITY_INRELEASE_SHA256
#   RUSTUP_INIT_URL RUSTUP_INIT_SHA256
#
# OFF-VENUE dry run (no Docker / toolchains): SUMCHAIN_B0PRE_DRYRUN=1 emits
# real-SHAPED sample files matching the exact production schema, for the
# producer→consumer compatibility tests. Dry-run output is never authoritative.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
# shellcheck source=lib.sh
. "$HERE/lib.sh"

candidate="${1:-}"; arch="${2:-}"; out="${3:-}"; build_mode="${4:-authoritative}"
case "$candidate" in sp1|risc0) ;; *) die "candidate must be sp1|risc0 (got '${candidate:-}')" ;; esac
case "$arch" in x86_64|aarch64) ;; *) die "arch must be x86_64|aarch64 (got '${arch:-}')" ;; esac
[ -n "$out" ] || die "output directory argument required"
# Build mode is an EXPLICIT positional argument (NOT an inheritable env var). `smoke` produces a
# distinct, TEST_ONLY-only runnable-ref sidecar schema (b0pre-smoke-runnable-ref-v1) that the
# authoritative resolver REJECTS; it can never emit an authoritative sidecar. It is only reachable
# by the separate public smoke entry point (smoke.sh), never by the authoritative producer.
case "$build_mode" in
  authoritative) ;;
  smoke) [ -z "${RATIFIED_SOURCE_COMMIT:-}" ] \
           || die "smoke build refuses to run with RATIFIED_SOURCE_COMMIT set (smoke is TEST_ONLY, never authoritative)" ;;
  *) die "build mode must be authoritative|smoke (got '$build_mode')" ;;
esac
mkdir -p "$out"

# The Stage-1 schema names arches X86_64 / Aarch64 (== the Arch enum variants).
case "$arch" in x86_64) schema_arch=X86_64 ;; aarch64) schema_arch=Aarch64 ;; esac
case "$candidate" in sp1) schema_cand=Sp1 ;; risc0) schema_cand=Risc0 ;; esac

# Emit the two Stage-6 input files for this (candidate, arch): a 2-element OciBuild
# array (base + builder) and a 1-element NativeBuild array. `python3` serializes so
# the bytes are valid JSON that the strict Stage-6 decoder accepts.
emit() {
  # positional: base_digest builder_digest base_ref builder_ref source_commit
  #             base_cmdlog base_rawout builder_cmdlog builder_rawout host_arch
  #             media_type platform_arch platform_os platform_variant
  python3 - "$out/$candidate.$arch.container.json" "$out/$candidate.$arch.native.json" \
    "$schema_cand" "$schema_arch" "$@" <<'PY'
import json, sys
(container_path, native_path, cand, arch,
 base_digest, builder_digest, base_ref, builder_ref, source_commit,
 base_cmdlog, base_rawout, builder_cmdlog, builder_rawout, host_arch,
 media_type, platform_arch, platform_os, platform_variant) = sys.argv[1:19]

def entry(role, image_digest, cmdlog, rawout, with_platform):
    # base and builder are two clean-reproduced identities; build1==build2 here
    # (the base is a pinned immutable, the builder is a two-clean-build match).
    e = {
        "candidate": cand, "role": role, "arch": arch,
        "build1_digest": image_digest, "build2_digest": image_digest,
        "base_image_ref": base_ref, "base_image_digest": base_digest,
        "builder_oci_ref": builder_ref, "builder_oci_digest": builder_digest,
        "source_commit": source_commit,
        "command_log_blake3": cmdlog, "raw_output_blake3": rawout,
    }
    if with_platform:
        # Blocker 8: the PARSED platform descriptor + media type of the built OCI
        # image (from `venue-verify oci-manifest`), not just the digest strings.
        e["platform_architecture"] = platform_arch
        e["platform_os"] = platform_os
        e["media_type"] = media_type
        # Preserve a NONEMPTY variant explicitly; omit it when absent (-> Option
        # None on decode) rather than fabricating an empty-string variant.
        if platform_variant:
            e["platform_variant"] = platform_variant
    return e

builds = [
    entry("base", base_digest, base_cmdlog, base_rawout, False),
    entry("builder", builder_digest, builder_cmdlog, builder_rawout, True),
]
with open(container_path, "w") as f:
    json.dump(builds, f, indent=2); f.write("\n")
with open(native_path, "w") as f:
    json.dump([{"candidate": cand, "arch": arch, "host_arch": host_arch}], f, indent=2)
    f.write("\n")
PY
  note "recorded $out/$candidate.$arch.container.json + .native.json (no push)"
}

if is_dryrun; then
  # OFF-VENUE: emit real-SHAPED sample values (no Docker, no b3sum, no toolchain).
  base_digest="$(syn_oci "base-$candidate-$arch")"
  builder_digest="$(syn_oci "builder-$candidate-$arch")"
  base_ref="registry.example/$candidate/base:pinned"
  builder_ref="oci:local/b0pre-$candidate-$arch"
  # one clean source commit per candidate (stable across arches), 40-hex sample.
  source_commit="$(syn_hex "commit-$candidate" | cut -c1-40)"
  # dry-run OCI platform descriptor: real-SHAPED TEST_ONLY values. amd64/arm64 linux
  # images carry no variant, so variant is empty (emit omits it -> Option None).
  case "$arch" in x86_64) dry_oci_arch=amd64 ;; aarch64) dry_oci_arch=arm64 ;; esac
  emit "$base_digest" "$builder_digest" "$base_ref" "$builder_ref" "$source_commit" \
    "$(syn_hex "cmdlog-$candidate-base-$arch")" "$(syn_hex "rawout-$candidate-base-$arch")" \
    "$(syn_hex "cmdlog-$candidate-builder-$arch")" "$(syn_hex "rawout-$candidate-builder-$arch")" \
    "$schema_arch" \
    "application/vnd.oci.image.manifest.v1+json" "$dry_oci_arch" "linux" ""
  exit 0
fi

# --- on-venue fail-closed preflight (before any build) ---
require_native_arch "$arch"
require_linux_oci_builder
require_free_gib "$out" 100
require_no_preexisting_lock "$ROOT/candidates/$candidate"
require_cmd b3sum
require_cmd tar
require_full_sha256_digest BASE_DIGEST "${BASE_DIGEST:-}"
reject_placeholder BASE_DIGEST "${BASE_DIGEST:-}"
[ -n "${BASE_IMAGE:-}" ]  || nyr "BASE_IMAGE (immutable base) is required"
[ -n "${APT_DEBIAN_URL:-}" ] || nyr "APT_DEBIAN_URL (pinned immutable Debian snapshot base URL) is required"
[ -n "${APT_DEBIAN_INRELEASE_SHA256:-}" ] || nyr "APT_DEBIAN_INRELEASE_SHA256 (expected bookworm InRelease sha256) is required"
[ -n "${APT_SECURITY_URL:-}" ] || nyr "APT_SECURITY_URL (pinned immutable debian-security snapshot base URL) is required"
[ -n "${APT_SECURITY_INRELEASE_SHA256:-}" ] || nyr "APT_SECURITY_INRELEASE_SHA256 (expected bookworm-security InRelease sha256) is required"
[ -n "${RUSTUP_INIT_URL:-}" ] || nyr "RUSTUP_INIT_URL (exact immutable per-arch rustup archive URL) is required"
[ -n "${RUSTUP_INIT_SHA256:-}" ] || nyr "RUSTUP_INIT_SHA256 (Rust 1.88.0 installer checksum) is required"
# The pinned apt sources must be immutable snapshot services, never a rolling mirror,
# and the rustup artifact must be the EXACT immutable archive locator for THIS arch.
require_apt_pin_url APT_DEBIAN_URL   "$APT_DEBIAN_URL"   || die "APT_DEBIAN_URL is not a pinned immutable snapshot URL"
require_apt_pin_url APT_SECURITY_URL "$APT_SECURITY_URL" || die "APT_SECURITY_URL is not a pinned immutable snapshot URL"
require_https_primary_url RUSTUP_INIT_URL "$RUSTUP_INIT_URL" || die "RUSTUP_INIT_URL is not an allow-listed https primary URL"
case "$RUSTUP_INIT_URL" in
  */rustup/dist/*) die "RUSTUP_INIT_URL uses the MUTABLE unversioned rustup/dist path; pin rustup/archive/<version>/ instead" ;;
esac
case "$RUSTUP_INIT_URL" in
  *"/$arch-unknown-linux-gnu/rustup-init") ;;
  *) die "RUSTUP_INIT_URL is not the rustup-init for arch '$arch' (cross-architecture pin): $RUSTUP_INIT_URL" ;;
esac

# ---- Prover + audit provisioning pins (Items 2/4). Fail closed (NOT_YET_REPRODUCED) when absent —
# exactly like the rustup pin: the builder cannot provision cargo-audit / the prover without them,
# and these values stay UNRATIFIED until the native venue supplies them. cargo-audit is built
# in-builder from the verified crate + packaged lock on BOTH candidates + arches. The prover archive
# members are candidate/arch-specific (SP1 cargo-prove on both arches; RISC Zero cargo-risczero+r0vm
# x86_64-only — sharing ONE archive). Shapes are re-validated inside the Dockerfile before any fetch.
[ -n "${CARGO_AUDIT_VERSION:-}" ]               || nyr "CARGO_AUDIT_VERSION (cargo-audit built in-builder) is required"
[ -n "${CARGO_AUDIT_CRATE_URL:-}" ]             || nyr "CARGO_AUDIT_CRATE_URL (immutable crates.io .crate URL) is required"
[ -n "${CARGO_AUDIT_CRATE_SHA256:-}" ]          || nyr "CARGO_AUDIT_CRATE_SHA256 (crate checksum, verified pre-extract) is required"
[ -n "${CARGO_AUDIT_PACKAGED_LOCK_SHA256:-}" ]  || nyr "CARGO_AUDIT_PACKAGED_LOCK_SHA256 (packaged Cargo.lock checksum, --locked) is required"
case "$candidate" in
  sp1)
    [ -n "${SP1_ARCHIVE_URL:-}" ]           || nyr "SP1_ARCHIVE_URL (immutable SP1 prover archive URL, arch=$arch) is required"
    [ -n "${SP1_ARCHIVE_SHA256:-}" ]        || nyr "SP1_ARCHIVE_SHA256 (whole-archive checksum, verified pre-extract) is required"
    [ -n "${CARGO_PROVE_MEMBER_PATH:-}" ]   || nyr "CARGO_PROVE_MEMBER_PATH (declared cargo-prove archive member) is required"
    [ -n "${CARGO_PROVE_MEMBER_SHA256:-}" ] || nyr "CARGO_PROVE_MEMBER_SHA256 (cargo-prove member checksum) is required"
    [ -n "${CARGO_PROVE_MEMBER_SIZE:-}" ]   || nyr "CARGO_PROVE_MEMBER_SIZE (cargo-prove member byte size) is required"
    ;;
  risc0)
    if [ "$arch" = "x86_64" ]; then
      [ -n "${RISC0_ARCHIVE_URL:-}" ]             || nyr "RISC0_ARCHIVE_URL (immutable RISC Zero toolchain archive URL) is required"
      [ -n "${RISC0_ARCHIVE_SHA256:-}" ]          || nyr "RISC0_ARCHIVE_SHA256 (whole-archive checksum, verified pre-extract) is required"
      [ -n "${CARGO_RISCZERO_MEMBER_PATH:-}" ]    || nyr "CARGO_RISCZERO_MEMBER_PATH (declared cargo-risczero archive member) is required"
      [ -n "${CARGO_RISCZERO_MEMBER_SHA256:-}" ]  || nyr "CARGO_RISCZERO_MEMBER_SHA256 (cargo-risczero member checksum) is required"
      [ -n "${CARGO_RISCZERO_MEMBER_SIZE:-}" ]    || nyr "CARGO_RISCZERO_MEMBER_SIZE (cargo-risczero member byte size) is required"
      [ -n "${R0VM_MEMBER_PATH:-}" ]              || nyr "R0VM_MEMBER_PATH (declared r0vm archive member, SHARED archive) is required"
      [ -n "${R0VM_MEMBER_SHA256:-}" ]            || nyr "R0VM_MEMBER_SHA256 (r0vm member checksum) is required"
      [ -n "${R0VM_MEMBER_SIZE:-}" ]              || nyr "R0VM_MEMBER_SIZE (r0vm member byte size) is required"
    else
      note "arch=$arch: RISC Zero prover pins not required (cargo-risczero + r0vm are x86_64-only; the arm64 risc0 image records the builder manifest only)"
    fi
    ;;
esac

df="$ROOT/containers/$candidate.Dockerfile"
[ -f "$df" ] || die "missing Dockerfile $df"
[ -z "$(git -C "$ROOT" status --porcelain 2>/dev/null || echo dirty)" ] \
  || die "source tree is not clean; refuse to build from a dirty state"
source_commit="$(git -C "$ROOT" rev-parse HEAD)"

# Defect 1 (clean-build reproducibility): pin ALL build metadata timestamps to a single
# deterministic epoch — the ratified source commit's committer date — so the two clean
# --no-cache builds below (and any independent re-run from the same commit) produce a
# byte-identical image config (`created` + per-step history timestamps) and, via the OCI
# exporter's rewrite-timestamp=true, byte-identical layer file mtimes. PROVE the value
# comes from the EXACT checked-out HEAD that equals RATIFIED_SOURCE_COMMIT (Stage 0 already
# asserted this on a clean tree; re-assert here as defense in depth), derive the epoch from
# that explicit commit, and validate it is a well-formed positive base-10 integer BEFORE
# Docker. Requires BuildKit >= 0.11 (rewrite-timestamp); an older builder fails closed on
# the unknown export option rather than silently emitting nondeterministic layers.
if [ "$build_mode" = smoke ]; then
  # Smoke: the deterministic epoch comes from the EXACT clean PR-head (already HEAD on a clean
  # tree). No RATIFIED_SOURCE_COMMIT is required or accepted — a smoke build is TEST_ONLY and
  # emits only a smoke-schema sidecar the authoritative resolver rejects.
  [ "$source_commit" = "$(git -C "$ROOT" rev-parse HEAD)" ] \
    || die "HEAD moved since build start; refusing smoke build epoch (candidate=$candidate arch=$arch)"
else
  [ -n "${RATIFIED_SOURCE_COMMIT:-}" ] \
    || nyr "RATIFIED_SOURCE_COMMIT is required to derive a deterministic SOURCE_DATE_EPOCH (from the ratified pins.env)"
  [ "$source_commit" = "$RATIFIED_SOURCE_COMMIT" ] \
    || die "HEAD ($source_commit) != RATIFIED_SOURCE_COMMIT ($RATIFIED_SOURCE_COMMIT); refusing to derive a build epoch from an unratified commit"
fi
SOURCE_DATE_EPOCH="$(git -C "$ROOT" show -s --format=%ct "$source_commit")"
require_valid_source_date_epoch "$SOURCE_DATE_EPOCH"
export SOURCE_DATE_EPOCH

# Stale-state defense (Defect 2 hardening): remove any runnable-ref sidecar (and its temp)
# from a prior or failed run for THIS (candidate, arch) BEFORE building, so a failed or new
# build can never reuse a previously loaded image reference. The sidecar is (re)written
# atomically only after full verification below.
rm -f "$out/$candidate.$arch.runnable-ref" "$out/$candidate.$arch.runnable-ref.tmp"

# Stage the CURATED, MINIMAL, reproduced-layout build context (only the official guest
# dep graph: candidate workspace + guest-core + sumchain-wire + curated workspace root +
# frozen guest fixtures — NO unrelated production crate). This is the authoritative
# container context: the path deps (../../../guest-core, ../../../crates/sumchain-wire)
# and sumchain-wire's `.workspace` inheritance resolve because the reproduced repo root
# maps to /work. Staged UNDER the (scratch) work dir; it never dirties the source tree.
STAGE="$out/${candidate}.${arch}.context"
stage_container_context "$candidate" "$STAGE"
# Bind the exact staged-context bytes into the #154 build evidence (below, via the
# builder command log, which is BLAKE3-hashed into command_log_blake3). This ADDS a
# binding; it weakens none.
staged_ctx_b3="$(staged_context_blake3 "$STAGE")"
note "staged curated container context at $STAGE (blake3:$staged_ctx_b3; reproduced repo-relative layout, no unrelated crate)"

# The reference validator carries the real OCI-layout manifest parser (venue-verify
# oci-manifest) — the SAME code unit-tested off-venue, so the recorded manifest
# identity is genuinely parsed, never sha256(the exported tar).
VAL="$ROOT/../b0-pre-validator/Cargo.toml"
[ -f "$VAL" ] || die "missing validator manifest $VAL"
# OCI platform spelling for --platform and the manifest platform descriptor.
case "$arch" in x86_64) oci_arch=amd64 ;; aarch64) oci_arch=arm64 ;; esac

build_once() {
  # Two INDEPENDENT clean builds: --no-cache gives each build an empty cache scope,
  # so this is genuinely two clean builds, not one cache replayed twice. Local OCI
  # layout export only; never a registry push. --platform pins the native platform
  # descriptor into the exported layout (emulation is already barred above).
  local tar="$1" log="$2"
  # Candidate/arch-specific prover build-args: pass ONLY the ones this Dockerfile declares (SP1's
  # cargo-prove on both arches; RISC Zero's cargo-risczero+r0vm x86_64-only) so no build-arg is
  # left unconsumed. cargo-audit's are passed for both candidates + arches. Every value was gated
  # NOT_YET_REPRODUCED above; the Dockerfile re-validates each shape before any fetch/extract.
  local -a prover_args=()
  case "$candidate" in
    sp1)
      prover_args+=(
        --build-arg "SP1_ARCHIVE_URL=$SP1_ARCHIVE_URL"
        --build-arg "SP1_ARCHIVE_SHA256=$SP1_ARCHIVE_SHA256"
        --build-arg "CARGO_PROVE_MEMBER_PATH=$CARGO_PROVE_MEMBER_PATH"
        --build-arg "CARGO_PROVE_MEMBER_SHA256=$CARGO_PROVE_MEMBER_SHA256"
        --build-arg "CARGO_PROVE_MEMBER_SIZE=$CARGO_PROVE_MEMBER_SIZE"
      ) ;;
    risc0)
      if [ "$arch" = "x86_64" ]; then
        prover_args+=(
          --build-arg "RISC0_ARCHIVE_URL=$RISC0_ARCHIVE_URL"
          --build-arg "RISC0_ARCHIVE_SHA256=$RISC0_ARCHIVE_SHA256"
          --build-arg "CARGO_RISCZERO_MEMBER_PATH=$CARGO_RISCZERO_MEMBER_PATH"
          --build-arg "CARGO_RISCZERO_MEMBER_SHA256=$CARGO_RISCZERO_MEMBER_SHA256"
          --build-arg "CARGO_RISCZERO_MEMBER_SIZE=$CARGO_RISCZERO_MEMBER_SIZE"
          --build-arg "R0VM_MEMBER_PATH=$R0VM_MEMBER_PATH"
          --build-arg "R0VM_MEMBER_SHA256=$R0VM_MEMBER_SHA256"
          --build-arg "R0VM_MEMBER_SIZE=$R0VM_MEMBER_SIZE"
        )
      fi
      ;;
  esac
  # SOURCE_DATE_EPOCH pins the config `created` + history timestamps; the exporter's
  # rewrite-timestamp=true normalizes every produced layer's file mtimes to that epoch.
  # Together they remove the two nondeterministic-byte sources the venue observed
  # (differing config `created` and differing layer digests) WITHOUT weakening the
  # manifest-identity equality gate below.
  docker build --no-cache \
    --file "$df" \
    --platform "linux/$oci_arch" \
    --build-arg "SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH" \
    --build-arg "BASE_IMAGE=$BASE_IMAGE" \
    --build-arg "BASE_DIGEST=$BASE_DIGEST" \
    --build-arg "APT_DEBIAN_URL=$APT_DEBIAN_URL" \
    --build-arg "APT_DEBIAN_INRELEASE_SHA256=$APT_DEBIAN_INRELEASE_SHA256" \
    --build-arg "APT_SECURITY_URL=$APT_SECURITY_URL" \
    --build-arg "APT_SECURITY_INRELEASE_SHA256=$APT_SECURITY_INRELEASE_SHA256" \
    --build-arg "RUSTUP_INIT_URL=$RUSTUP_INIT_URL" \
    --build-arg "RUSTUP_INIT_SHA256=$RUSTUP_INIT_SHA256" \
    --build-arg "RUST_VERSION=1.88.0" \
    --build-arg "CARGO_AUDIT_VERSION=$CARGO_AUDIT_VERSION" \
    --build-arg "CARGO_AUDIT_CRATE_URL=$CARGO_AUDIT_CRATE_URL" \
    --build-arg "CARGO_AUDIT_CRATE_SHA256=$CARGO_AUDIT_CRATE_SHA256" \
    --build-arg "CARGO_AUDIT_PACKAGED_LOCK_SHA256=$CARGO_AUDIT_PACKAGED_LOCK_SHA256" \
    ${prover_args[@]+"${prover_args[@]}"} \
    --output "type=oci,dest=$tar,rewrite-timestamp=true" \
    "$STAGE" >"$log" 2>&1
}

# Extract a layout and parse its TRUE OCI manifest identity (content-addressed
# digest + platform descriptor) via the shared parser. Prints the manifest digest;
# writes the full descriptor (incl. platform) to the evidence file for retention.
oci_manifest_digest() {
  local tar="$1" dir="$2" evidence="$3"
  rm -rf "$dir"; mkdir -p "$dir"
  tar -xf "$tar" -C "$dir"
  cargo run --quiet --locked --manifest-path "$VAL" --bin venue-verify -- \
    oci-manifest "$dir" "$oci_arch" > "$evidence" \
    || die "OCI manifest identity extraction failed for $tar (candidate=$candidate arch=$arch)"
  python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["manifest_digest"])' "$evidence"
}

L1="$out/${candidate}.${arch}.build1.oci.tar"; G1="$out/${candidate}.${arch}.build1.log"
L2="$out/${candidate}.${arch}.build2.oci.tar"; G2="$out/${candidate}.${arch}.build2.log"
D1="$out/${candidate}.${arch}.build1.layout"; E1="$out/${candidate}.${arch}.build1.oci-manifest.json"
D2="$out/${candidate}.${arch}.build2.layout"; E2="$out/${candidate}.${arch}.build2.oci-manifest.json"
note "== build 1/2 (clean, --no-cache) =="; build_once "$L1" "$G1"
note "== build 2/2 (clean, --no-cache) =="; build_once "$L2" "$G2"

# Compare the intended OCI MANIFEST identity (index.json content address), NOT the
# tar serialization — two clean builds that agree on the manifest digest are
# reproducible even if the tar bytes differ (member order / timestamps).
m1="$(oci_manifest_digest "$L1" "$D1" "$E1")"
m2="$(oci_manifest_digest "$L2" "$D2" "$E2")"
[ "$m1" = "$m2" ] || die "two clean builds diverge in OCI manifest identity: $m1 != $m2 (candidate=$candidate arch=$arch)"
builder_digest="$m1"

# Defect 2: the verified OCI layout was previously never loaded — downstream
# `docker run --pull never oci:local/...` referenced an image the daemon never had, so
# every in-container stage would have failed. Load the VERIFIED build-1 layout and PROVE
# the loaded image corresponds to it BEFORE anything runs inside it. No fifth build, no
# re-derivation; no mutable tag stands in for the verified identity; --pull never; no
# registry push. The proven-identity reference (a verified content address) is handed to
# the downstream stages via a work-dir sidecar that run_authoritative.sh reads.
config_digest="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["config_digest"])' "$E1")"
printf '%s' "$config_digest" | grep -Eq '^sha256:[0-9a-f]{64}$' \
  || die "config digest from the verified manifest is malformed: '$config_digest' (candidate=$candidate arch=$arch)"
# docker load consumes the EXACT verified OCI archive (requires an OCI-archive-capable
# image store, e.g. containerd); it never rebuilds or re-derives the image.
load_out="$(docker load --input "$L1" 2>&1)" \
  || die "docker load of the verified OCI layout failed (OCI-archive load / containerd image store required): $load_out"
loaded_id="$(printf '%s\n' "$load_out" | grep -oE 'sha256:[0-9a-f]{64}' | head -n1)"
[ -n "$loaded_id" ] || die "could not determine the loaded image id from 'docker load' output: $load_out"
# PROVE correspondence: the loaded image id is the content address the daemon addresses
# the image by — the MANIFEST digest (== builder_digest) under the containerd image store,
# or the image CONFIG digest under the classic store. Either is a verified content address
# OF THIS layout, so require a match against one of them; anything else (incl. synthetic)
# fails closed and no unverified image runs.
vv_verify() { cargo run --quiet --locked --manifest-path "$VAL" --bin venue-verify -- verify-runtime-image "$1" "$2" >/dev/null 2>&1; }
if vv_verify "$builder_digest" "$loaded_id"; then
  id_kind="manifest digest"
elif vv_verify "$config_digest" "$loaded_id"; then
  id_kind="config digest"
else
  die "loaded image id ($loaded_id) corresponds to NEITHER the verified manifest digest ($builder_digest) NOR its config digest ($config_digest); refusing to run an unverified image (candidate=$candidate arch=$arch)"
fi
# The runnable reference IS the verified content address the daemon just proved (no mutable
# tag in the trust path). Write the TYPED, versioned sidecar ATOMICALLY (temp + mv), only
# now that both clean builds matched, the layout was manifest+config content-verified,
# docker load succeeded, and the loaded id matched a verified content address. It binds the
# exact SOURCE COMMIT + candidate / arch / manifest+config digests / runnable image id so
# run_authoritative.sh revalidates it against the current build and refuses a
# stale/prior-source/cross-candidate/cross-arch one. Bind source_commit explicitly (a
# docs-only / orchestration-only commit can preserve the manifest, so the manifest is not a
# proxy for source identity): require it is 40 lowercase hex and equals BOTH HEAD and
# RATIFIED_SOURCE_COMMIT at write time.
is_ratified_commit_format "$source_commit" \
  || die "source_commit is not 40 lowercase hex: '$source_commit' (candidate=$candidate arch=$arch)"
[ "$source_commit" = "$(git -C "$ROOT" rev-parse HEAD)" ] \
  || die "HEAD moved since build start; refusing to write a runnable-ref sidecar (candidate=$candidate arch=$arch)"
sidecar="$out/$candidate.$arch.runnable-ref"
if [ "$build_mode" = smoke ]; then
  # SMOKE sidecar: a DISTINCT schema (b0pre-smoke-runnable-ref-v1) carrying an explicit TEST_ONLY
  # classification + source_pr_head. The authoritative resolver (lib.sh resolve_runnable_ref)
  # requires schema == b0pre-runnable-ref-v1, so it REJECTS this record outright — a smoke image
  # can never be consumed on the authoritative path even if the source field were edited. Only
  # resolve_smoke_runnable_ref accepts it.
  python3 - "$sidecar.tmp" "$candidate" "$arch" "$source_commit" "$builder_digest" "$config_digest" "$loaded_id" <<'PY'
import json, sys
p, cand, arch, pr_head, mani, cfg, img = sys.argv[1:8]
json.dump({"schema": "b0pre-smoke-runnable-ref-v1", "classification": "TEST_ONLY",
           "candidate": cand, "arch": arch, "source_pr_head": pr_head,
           "manifest_digest": mani, "config_digest": cfg, "runnable_image_id": img},
          open(p, "w"), indent=2)
open(p, "a").write("\n")
PY
else
  # Authoritative: bind source_commit explicitly and require it equal RATIFIED_SOURCE_COMMIT (a
  # docs-only / orchestration-only commit can preserve the manifest, so the manifest is not a
  # proxy for source identity).
  [ "$source_commit" = "$RATIFIED_SOURCE_COMMIT" ] \
    || die "source_commit ($source_commit) != RATIFIED_SOURCE_COMMIT ($RATIFIED_SOURCE_COMMIT); refusing to write runnable-ref sidecar"
  python3 - "$sidecar.tmp" "$candidate" "$arch" "$source_commit" "$builder_digest" "$config_digest" "$loaded_id" <<'PY'
import json, sys
p, cand, arch, commit, mani, cfg, img = sys.argv[1:8]
json.dump({"schema": "b0pre-runnable-ref-v1", "candidate": cand, "arch": arch,
           "source_commit": commit, "manifest_digest": mani, "config_digest": cfg,
           "runnable_image_id": img}, open(p, "w"), indent=2)
open(p, "a").write("\n")
PY
fi
mv -f "$sidecar.tmp" "$sidecar"
note "loaded + verified runnable image $candidate/$arch ($build_mode): $loaded_id (matched verified $id_kind; typed sidecar written atomically; downstream uses --pull never, no push)"

# The raw exported-tar byte hashes are retained ONLY as raw-artifact witnesses
# (BLAKE3), never presented as the manifest identity.
tar1_hex="$(blake3_hex_file "$L1")"; tar2_hex="$(blake3_hex_file "$L2")"

# The builder command log covers BOTH clean builds (not only build 1), and the raw
# output witnesses BOTH build logs concatenated.
cmd_log="$out/${candidate}.${arch}.command.log"
{
  printf 'docker build --no-cache --file %s --platform linux/%s --output type=oci ...(build-args pinned)\n' "$df" "$oci_arch"
  printf 'BASE_IMAGE=%s BASE_DIGEST=%s RUST_VERSION=1.88.0\n' \
    "$BASE_IMAGE" "$BASE_DIGEST"
  printf 'APT_DEBIAN_URL=%s APT_DEBIAN_INRELEASE_SHA256=%s\n' \
    "$APT_DEBIAN_URL" "$APT_DEBIAN_INRELEASE_SHA256"
  printf 'APT_SECURITY_URL=%s APT_SECURITY_INRELEASE_SHA256=%s\n' \
    "$APT_SECURITY_URL" "$APT_SECURITY_INRELEASE_SHA256"
  printf 'RUSTUP_INIT_URL=%s RUSTUP_INIT_SHA256=%s\n' \
    "$RUSTUP_INIT_URL" "$RUSTUP_INIT_SHA256"
  # Provisioning pins bound into the build evidence (Items 2/4): cargo-audit built in-builder from
  # the verified crate + packaged lock (BOTH candidates/arches); the candidate/arch-specific prover
  # archive members. The provision script's own bytes are already bound via staged_context_blake3.
  printf 'CARGO_AUDIT_VERSION=%s CARGO_AUDIT_CRATE_URL=%s CARGO_AUDIT_CRATE_SHA256=%s CARGO_AUDIT_PACKAGED_LOCK_SHA256=%s (exe-sha256 = venue evidence, recorded in-image at /opt/b0pre/evidence)\n' \
    "$CARGO_AUDIT_VERSION" "$CARGO_AUDIT_CRATE_URL" "$CARGO_AUDIT_CRATE_SHA256" "$CARGO_AUDIT_PACKAGED_LOCK_SHA256"
  case "$candidate" in
    sp1)
      printf 'SP1_ARCHIVE_URL=%s SP1_ARCHIVE_SHA256=%s CARGO_PROVE_MEMBER=%s sha256=%s size=%s delivery=isolated\n' \
        "$SP1_ARCHIVE_URL" "$SP1_ARCHIVE_SHA256" "$CARGO_PROVE_MEMBER_PATH" "$CARGO_PROVE_MEMBER_SHA256" "$CARGO_PROVE_MEMBER_SIZE" ;;
    risc0)
      if [ "$arch" = "x86_64" ]; then
        printf 'RISC0_ARCHIVE_URL=%s RISC0_ARCHIVE_SHA256=%s CARGO_RISCZERO_MEMBER=%s sha256=%s size=%s delivery=isolated R0VM_MEMBER=%s sha256=%s size=%s delivery=risc0server (shared archive)\n' \
          "$RISC0_ARCHIVE_URL" "$RISC0_ARCHIVE_SHA256" "$CARGO_RISCZERO_MEMBER_PATH" "$CARGO_RISCZERO_MEMBER_SHA256" "$CARGO_RISCZERO_MEMBER_SIZE" "$R0VM_MEMBER_PATH" "$R0VM_MEMBER_SHA256" "$R0VM_MEMBER_SIZE"
      else
        printf 'RISC Zero prover NOT provisioned on arch=%s (x86_64-only; builder-manifest record only)\n' "$arch"
      fi ;;
  esac
  # The build context is the curated staged guest-source graph, not the raw tree; bind
  # its exact identity here (this line is BLAKE3-hashed into command_log_blake3 below).
  printf 'build_context=curated-staged-guest-graph staged_context_blake3=%s (candidate+guest-core+sumchain-wire+curated-root+guest-fixtures; no unrelated crate)\n' "$staged_ctx_b3"
  printf 'oci_manifest_identity=%s (build1==build2)\n' "$builder_digest"
  printf 'raw_export_tar_blake3 build1=%s build2=%s (raw artifacts, NOT the identity)\n' "$tar1_hex" "$tar2_hex"
} > "$cmd_log"
both_logs="$out/${candidate}.${arch}.builds.rawout.log"
cat "$G1" "$G2" > "$both_logs"
builder_cmdlog="$(blake3_hex_file "$cmd_log")"
builder_rawout="$(blake3_hex_file "$both_logs")"

# GENUINE base-resolution evidence (Blocker 6): the base is an IMMUTABLE INPUT
# resolved by pull-by-digest, NOT a builder build. Its command log / raw output are
# the base-resolution inspect — never a copy of the builder build evidence.
base_cmd="$out/${candidate}.${arch}.base.resolve.cmd"
base_out="$out/${candidate}.${arch}.base.resolve.out"
printf 'docker manifest inspect %s@%s\n' "$BASE_IMAGE" "$BASE_DIGEST" > "$base_cmd"
docker manifest inspect "$BASE_IMAGE@$BASE_DIGEST" > "$base_out" 2>&1 \
  || die "base pull-by-digest resolution failed for $BASE_IMAGE@$BASE_DIGEST (candidate=$candidate arch=$arch)"
base_cmdlog="$(blake3_hex_file "$base_cmd")"
base_rawout="$(blake3_hex_file "$base_out")"

# Native-build provenance: the host architecture DERIVED from `uname -m` (mapped to
# the Arch enum spelling). The Stage-6 assembler derives native_arch = host==arch;
# an emulated/cross-compiled host would produce host_arch != arch and fail closed.
host_uname="$(uname -m)"
case "$host_uname" in
  x86_64|amd64) host_arch=X86_64 ;;
  aarch64|arm64) host_arch=Aarch64 ;;
  *) die "unrecognized host architecture '$host_uname'" ;;
esac

# Blocker 8: SOURCE the platform descriptor + media type from BOTH clean builds'
# parsed OCI manifests (E1/E2). Require every field present, require build1==build2
# agreement (incl. variant), and require the platform to match the requested native
# target. Never infer these from the arch argument alone. build1==build2 on the
# manifest digest was already enforced above (m1==m2 -> builder_digest).
if ! plat_line="$(python3 - "$E1" "$E2" "$oci_arch" 2>&1 <<'PY'
import json, sys
e1, e2, want_arch = sys.argv[1], sys.argv[2], sys.argv[3]
def load(p):
    d = json.load(open(p))
    plat = d.get("platform") or {}
    return {"media_type": d.get("media_type"),
            "architecture": plat.get("architecture"),
            "os": plat.get("os"),
            "variant": plat.get("variant")}
a, b = load(e1), load(e2)
for src, who in ((a, "build1"), (b, "build2")):
    for k in ("media_type", "architecture", "os"):
        if not src[k]:
            sys.exit(f"{who} OCI descriptor missing required field '{k}'")
for k in ("media_type", "architecture", "os", "variant"):
    if a[k] != b[k]:
        sys.exit(f"build1/build2 disagree on platform '{k}': {a[k]!r} != {b[k]!r}")
if a["architecture"] != want_arch:
    sys.exit(f"platform architecture {a['architecture']!r} != requested native {want_arch!r}")
if a["os"] != "linux":
    sys.exit(f"platform os {a['os']!r} != 'linux'")
# Preserve a nonempty variant; empty/absent -> "" (emit omits it -> Option None).
print(a["media_type"], a["architecture"], a["os"], a["variant"] or "")
PY
)"; then
  die "OCI platform descriptor verification failed (candidate=$candidate arch=$arch): $plat_line"
fi
read -r verified_media_type verified_platform_arch verified_platform_os verified_platform_variant <<< "$plat_line"

emit "$BASE_DIGEST" "$builder_digest" "$BASE_IMAGE" "oci:local/b0pre-$candidate-$arch" \
  "$source_commit" "$base_cmdlog" "$base_rawout" "$builder_cmdlog" "$builder_rawout" \
  "$host_arch" \
  "$verified_media_type" "$verified_platform_arch" "$verified_platform_os" "$verified_platform_variant"
