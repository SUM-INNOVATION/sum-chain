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
# Required env (venue-supplied immutable inputs):
#   BASE_IMAGE BASE_DIGEST APT_SNAPSHOT RUSTUP_INIT_SHA256
#
# OFF-VENUE dry run (no Docker / toolchains): SUMCHAIN_B0PRE_DRYRUN=1 emits
# real-SHAPED sample files matching the exact production schema, for the
# producer→consumer compatibility tests. Dry-run output is never authoritative.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
# shellcheck source=lib.sh
. "$HERE/lib.sh"

candidate="${1:-}"; arch="${2:-}"; out="${3:-}"
case "$candidate" in sp1|risc0) ;; *) die "candidate must be sp1|risc0 (got '${candidate:-}')" ;; esac
case "$arch" in x86_64|aarch64) ;; *) die "arch must be x86_64|aarch64 (got '${arch:-}')" ;; esac
[ -n "$out" ] || die "output directory argument required"
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
[ -n "${APT_SNAPSHOT:-}" ] || nyr "APT_SNAPSHOT (pinned OS package snapshot) is required"
[ -n "${RUSTUP_INIT_SHA256:-}" ] || nyr "RUSTUP_INIT_SHA256 (Rust 1.88.0 installer checksum) is required"

df="$ROOT/containers/$candidate.Dockerfile"
[ -f "$df" ] || die "missing Dockerfile $df"
[ -z "$(git -C "$ROOT" status --porcelain 2>/dev/null || echo dirty)" ] \
  || die "source tree is not clean; refuse to build from a dirty state"
source_commit="$(git -C "$ROOT" rev-parse HEAD)"

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
  docker build --no-cache \
    --file "$df" \
    --platform "linux/$oci_arch" \
    --build-arg "BASE_IMAGE=$BASE_IMAGE" \
    --build-arg "BASE_DIGEST=$BASE_DIGEST" \
    --build-arg "APT_SNAPSHOT=$APT_SNAPSHOT" \
    --build-arg "RUSTUP_INIT_SHA256=$RUSTUP_INIT_SHA256" \
    --build-arg "RUST_VERSION=1.88.0" \
    --output "type=oci,dest=$tar" \
    "$ROOT" >"$log" 2>&1
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

# The raw exported-tar byte hashes are retained ONLY as raw-artifact witnesses
# (BLAKE3), never presented as the manifest identity.
tar1_hex="$(blake3_hex_file "$L1")"; tar2_hex="$(blake3_hex_file "$L2")"

# The builder command log covers BOTH clean builds (not only build 1), and the raw
# output witnesses BOTH build logs concatenated.
cmd_log="$out/${candidate}.${arch}.command.log"
{
  printf 'docker build --no-cache --file %s --platform linux/%s --output type=oci ...(build-args pinned)\n' "$df" "$oci_arch"
  printf 'BASE_IMAGE=%s BASE_DIGEST=%s APT_SNAPSHOT=%s RUST_VERSION=1.88.0\n' \
    "$BASE_IMAGE" "$BASE_DIGEST" "$APT_SNAPSHOT"
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
