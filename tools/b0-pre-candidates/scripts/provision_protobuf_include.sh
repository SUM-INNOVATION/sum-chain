#!/usr/bin/env bash
# CONTROLLED, ATTESTED provisioning of the authenticated protobuf include authority into the
# ALREADY-RATIFIED per-arch SP1 builder container as a READ-ONLY mount at the hardcoded include
# path. It PROVISIONS the include, it never builds or pulls: the builder image must already be
# present locally (its identity is ratified elsewhere) and `docker run --pull never` guarantees no
# network fetch. Self-contained like the other provision_* scripts (own die + own hash helpers; it
# sources NO lib.sh) so the trust path is auditable in one file.
#
# The authenticated authority (produced off-venue, content-addressed) lives at --authority-dir with
# INVENTORY.json + CONTENT-ADDRESS.txt + include/google/protobuf/empty.proto. Everything below is
# fail-closed; the pinned values here are the ground truth (CONTENT-ADDRESS.txt is documentation
# only — the content-address is RECOMPUTED from INVENTORY.json against these baked-in pins, never
# trusted from the file). In strict order:
#   1. parse EXPLICIT flags (no positional / env ambiguity; unknown, extra, missing, or duplicate
#      flags all die);
#   2. verify the authority dir BEFORE any use: INVENTORY.json present/regular/non-symlink; the
#      include tree carries EXACTLY google/protobuf/empty.proto and NO symlink/extra file; recompute
#      empty.proto sha256 AND blake3 AND size == the pins; recompute the content-address
#      SHA256/BLAKE3( "b0-final-protobuf-include-authority/v1\0" || canonical(INVENTORY.json) ) ==
#      the pins; and cross-check every value INVENTORY.json declares against the pinned ground truth;
#   3. require the ratified builder image is present LOCALLY (`docker image inspect`) — refuse to
#      pull if absent;
#   4. refuse AMBIENT authority: probe the image WITHOUT our mount and die if a pre-existing
#      google/protobuf/empty.proto is already baked in;
#   5. run the image with our include mounted READ-ONLY at exactly /usr/include/google/protobuf and,
#      inside it, assert the native protoc reports EXACTLY the pinned version, that the mount exposes
#      ONLY our empty.proto, and that its in-container sha256 == the pin; capture the native protoc
#      path and compute its sha256 + blake3 as VENUE-PRODUCED facts (never compared to a baked-in
#      value — there is no known per-arch protoc hash);
#   6. emit a machine-readable KEY=VALUE attestation block to STDOUT (the exact docker argv + mount
#      spec used, protoc identity, content-address, empty.proto sha256); diagnostics go to STDERR.
#
# Usage:
#   provision_protobuf_include.sh --authority-dir <dir> --builder-image <ratified ref> \
#       --arch <x86_64|aarch64>
set -euo pipefail

die() { printf 'PROTOBUF-INCLUDE-REFUSED: %s\n' "$*" >&2; exit 5; }
log() { printf '%s\n' "$*" >&2; }
require_cmd() { command -v "$1" >/dev/null 2>&1 || die "required command '$1' not found on PATH"; }

# Bare 64-hex sha256 of a file (coreutils sha256sum or macOS shasum). Self-contained (no lib.sh).
sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then shasum -a 256 "$1" | awk '{print $1}'
  else die "no sha256 tool (sha256sum / shasum) available"; fi
}
# Bare 64-hex blake3 of a file (b3sum is a venue dependency).
blake3_file() {
  command -v b3sum >/dev/null 2>&1 || die "no blake3 tool (b3sum) available"
  b3sum "$1" | awk '{print $1}'
}

# --- pinned ground truth (authenticated off-venue; treat as constants) ----------------------------
PIN_PROTOC_VERSION="libprotoc 3.21.12"          # exact `protoc --version` output required in-image
PIN_PROTOC_VERSION_UPSTREAM="3.21.12"           # bare version as declared in INVENTORY.json
PIN_EMPTY_PROTO_SHA256="c6d0c8af3d26047a7f3717beb43f7032f5afe71c0c1b9162cd4a1a363629f273"
PIN_EMPTY_PROTO_BLAKE3="bf3b623753e1cfc0b492197436d1412de2255a851f7e60b19dc554ff8c38a46f"
PIN_EMPTY_PROTO_SIZE="2363"
PIN_CONTENT_ADDRESS_SHA256="65b7a61f069be4f709de94f72c696529a69596749e6dc24ac543ee6d72af9161"
PIN_CONTENT_ADDRESS_BLAKE3="7b5551d278fc33095bddde84339ef73c0d777f65e206de60aecd8cbf9c8f3623"
PIN_SRC_ARCHIVE_NAME="protobuf-cpp-3.21.12.tar.gz"
PIN_SRC_ARCHIVE_SHA256="4eab9b524aa5913c6fffb20b2a8abf5ef7f95a80bc0701f3a6dbb4c607f73460"
PIN_SRC_ARCHIVE_BLAKE3="697239ff8b9c58af3f92d58407094f75b42169f80a4c490d2a092c7b301e2a06"
AUTHORITY_DOMAIN_SEP="b0-final-protobuf-include-authority/v1"  # NUL-terminated in the CA preimage
IMPORT_MEMBER="google/protobuf/empty.proto"                    # the ENTIRE import closure
MOUNT_TARGET="/usr/include/google/protobuf"                    # hardcoded in-container include path

# --- (1) explicit flag parsing (no positional / env args; unknown / extra / missing / dup => die) -
AUTHORITY_DIR=""; BUILDER_IMAGE=""; ARCH=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    --authority-dir) [ "$#" -ge 2 ] || die "--authority-dir requires a value"
                     [ -z "$AUTHORITY_DIR" ] || die "duplicate --authority-dir (ambiguous)"
                     AUTHORITY_DIR="$2"; shift 2 ;;
    --builder-image) [ "$#" -ge 2 ] || die "--builder-image requires a value"
                     [ -z "$BUILDER_IMAGE" ] || die "duplicate --builder-image (ambiguous)"
                     BUILDER_IMAGE="$2"; shift 2 ;;
    --arch)          [ "$#" -ge 2 ] || die "--arch requires a value"
                     [ -z "$ARCH" ] || die "duplicate --arch (ambiguous)"
                     ARCH="$2"; shift 2 ;;
    *) die "unknown/extra argument (only --authority-dir/--builder-image/--arch accepted; no positional/env args): $1" ;;
  esac
done
[ -n "$AUTHORITY_DIR" ] || die "--authority-dir is required"
[ -n "$BUILDER_IMAGE" ] || die "--builder-image is required"
[ -n "$ARCH" ] || die "--arch is required"
case "$ARCH" in x86_64|aarch64) ;; *) die "--arch must be x86_64|aarch64 (got '$ARCH')" ;; esac

require_cmd docker
require_cmd python3
require_cmd b3sum

work="$(mktemp -d)"; trap 'rm -rf "$work"' EXIT

# --- (2) verify the authority dir BEFORE any use --------------------------------------------------
[ -d "$AUTHORITY_DIR" ] || die "--authority-dir is not a directory: $AUTHORITY_DIR"
[ ! -L "$AUTHORITY_DIR" ] || die "--authority-dir is a symlink (refused): $AUTHORITY_DIR"
authority_abs="$(cd "$AUTHORITY_DIR" && pwd)" || die "cannot resolve --authority-dir: $AUTHORITY_DIR"
inv="$authority_abs/INVENTORY.json"
inc="$authority_abs/include"
src="$inc/google/protobuf"                 # the exact `-v` mount SOURCE (holds empty.proto)
proto="$src/empty.proto"

[ -e "$inv" ] || die "INVENTORY.json absent under the authority dir: $inv"
[ ! -L "$inv" ] || die "INVENTORY.json is a symlink (refused): $inv"
[ -f "$inv" ] || die "INVENTORY.json is not a regular file: $inv"

[ -d "$inc" ] || die "authority include/ dir absent: $inc"
[ ! -L "$inc" ] || die "authority include/ is a symlink (refused): $inc"
[ ! -L "$src" ] || die "authority include/google/protobuf is a symlink (refused): $src"
[ -d "$src" ] || die "authority include/google/protobuf dir absent: $src"
# No symlink anywhere in the include tree, and EXACTLY one regular file: google/protobuf/empty.proto.
if find "$inc" -type l 2>/dev/null | grep -q .; then die "symlink present in the include tree (refused): $inc"; fi
regfiles="$(cd "$inc" && find . -type f | LC_ALL=C sort)"
[ "$regfiles" = "./google/protobuf/empty.proto" ] \
  || die "include tree must contain EXACTLY google/protobuf/empty.proto (got: $(printf '%s' "$regfiles" | tr '\n' ' '))"
[ ! -L "$proto" ] || die "empty.proto is a symlink (refused): $proto"
[ -f "$proto" ] || die "empty.proto is not a regular file: $proto"

# empty.proto size + sha256 + blake3 == pins.
empty_size="$(wc -c < "$proto" | tr -d ' ')"
[ "$empty_size" = "$PIN_EMPTY_PROTO_SIZE" ] || die "empty.proto size $empty_size != pinned $PIN_EMPTY_PROTO_SIZE"
empty_sha="$(sha256_file "$proto")"
[ "$empty_sha" = "$PIN_EMPTY_PROTO_SHA256" ] || die "empty.proto sha256 $empty_sha != pinned $PIN_EMPTY_PROTO_SHA256"
empty_b3="$(blake3_file "$proto")"
[ "$empty_b3" = "$PIN_EMPTY_PROTO_BLAKE3" ] || die "empty.proto blake3 $empty_b3 != pinned $PIN_EMPTY_PROTO_BLAKE3"

# Content-address: SHA256/BLAKE3( "<domain-sep>\0" || canonical(INVENTORY.json) ). canonical() is the
# on-disk INVENTORY.json bytes (already canonical). Build the preimage ONCE so both digests cover
# byte-identical input, then compare BOTH to the pins.
{ printf '%s\0' "$AUTHORITY_DOMAIN_SEP"; cat "$inv"; } > "$work/ca.preimage"
ca_sha="$(sha256_file "$work/ca.preimage")"
ca_b3="$(blake3_file "$work/ca.preimage")"
[ "$ca_sha" = "$PIN_CONTENT_ADDRESS_SHA256" ] || die "authority content-address sha256 $ca_sha != pinned $PIN_CONTENT_ADDRESS_SHA256"
[ "$ca_b3" = "$PIN_CONTENT_ADDRESS_BLAKE3" ] || die "authority content-address blake3 $ca_b3 != pinned $PIN_CONTENT_ADDRESS_BLAKE3"

# Cross-check every value INVENTORY.json DECLARES against the pinned ground truth (the content-address
# already binds these bytes; this makes the archive/closure/mount-target pins explicit + fail-closed).
if ! inv_msg="$(python3 - "$inv" \
    "$PIN_EMPTY_PROTO_SHA256" "$PIN_EMPTY_PROTO_BLAKE3" "$PIN_EMPTY_PROTO_SIZE" \
    "$IMPORT_MEMBER" "$MOUNT_TARGET" \
    "$PIN_SRC_ARCHIVE_NAME" "$PIN_SRC_ARCHIVE_SHA256" "$PIN_SRC_ARCHIVE_BLAKE3" \
    "$PIN_PROTOC_VERSION_UPSTREAM" 2>&1 <<'PY'
import json, sys
inv = sys.argv[1]
es, eb, esz, member, mt, an, ash, abl, pv = sys.argv[2:11]
d = json.load(open(inv))
files = d.get("files") or []
if len(files) != 1:
    sys.exit("INVENTORY files[] must contain exactly one entry")
f = files[0]
if f.get("path") != member:      sys.exit(f"INVENTORY file path {f.get('path')!r} != {member!r}")
if f.get("sha256") != es:        sys.exit("INVENTORY empty.proto sha256 != pinned")
if f.get("blake3") != eb:        sys.exit("INVENTORY empty.proto blake3 != pinned")
if str(f.get("size")) != esz:    sys.exit("INVENTORY empty.proto size != pinned")
if (d.get("import_closure") or []) != [member]:
    sys.exit("INVENTORY import_closure != [google/protobuf/empty.proto]")
if d.get("mount_target") != mt:  sys.exit(f"INVENTORY mount_target {d.get('mount_target')!r} != {mt!r}")
up = d.get("upstream") or {}
if up.get("source_archive") != an:          sys.exit("INVENTORY source_archive name != pinned")
if up.get("source_archive_sha256") != ash:  sys.exit("INVENTORY source_archive_sha256 != pinned")
if up.get("source_archive_blake3") != abl:  sys.exit("INVENTORY source_archive_blake3 != pinned")
if str(up.get("protoc_version")) != pv:     sys.exit(f"INVENTORY protoc_version {up.get('protoc_version')!r} != {pv!r}")
PY
)"; then
  die "INVENTORY.json declared values do not match the pinned ground truth: $inv_msg"
fi
log "authority verified: empty.proto sha256 $empty_sha (size $empty_size), content-address sha256 $ca_sha"

# --- (3) the ratified builder image must be present LOCALLY (refuse to pull) -----------------------
docker image inspect "$BUILDER_IMAGE" >/dev/null 2>&1 \
  || die "ratified builder image not present locally; refusing to pull: $BUILDER_IMAGE"

# --- (4) refuse AMBIENT authority: probe the image WITHOUT our mount ------------------------------
AMBIENT_SCRIPT='if [ -e /usr/include/google/protobuf/empty.proto ]; then echo AMBIENT_PRESENT; else echo AMBIENT_ABSENT; fi'
amb="$(docker run --rm --pull never "$BUILDER_IMAGE" bash -c "$AMBIENT_SCRIPT" 2>/dev/null)" \
  || die "ambient-authority probe run failed on the builder image (arch=$ARCH): $BUILDER_IMAGE"
case "$amb" in
  *AMBIENT_ABSENT*)  : ;;
  *AMBIENT_PRESENT*) die "ambient protobuf include present in builder image; refusing (must be provisioned, not ambient)" ;;
  *) die "ambient-authority probe returned an unexpected result (arch=$ARCH): $amb" ;;
esac

# --- (5) provision + verify: mount our include READ-ONLY at the hardcoded path --------------------
# The `-v` source is <abs>/include/google/protobuf, mounted RO at /usr/include/google/protobuf. This
# argv is the EXACT one recorded in the attestation (single source of truth: it is run AND printed).
mount_spec="$src:$MOUNT_TARGET:ro"
# In-container verification (no single quotes so it survives host single-quoting): protoc present,
# mount exposes ONLY empty.proto, protoc version, protoc path, and the mounted empty.proto sha256.
# shellcheck disable=SC2016  # $d/$p/$v/$s expand INSIDE the container, never on the host — intended.
VERIFY_SCRIPT='set -eu
command -v protoc >/dev/null 2>&1 || { echo NO_PROTOC; exit 91; }
command -v sha256sum >/dev/null 2>&1 || { echo NO_SHA256SUM; exit 92; }
d=/usr/include/google/protobuf
found=$(cd "$d" && find . -type f | LC_ALL=C sort | tr "\n" ",")
[ "$found" = "./empty.proto," ] || { echo "MOUNT_EXTRA:$found"; exit 93; }
p=$(command -v protoc)
v=$(protoc --version)
s=$(sha256sum "$d/empty.proto" | cut -d" " -f1)
echo "PROTOC_PATH=$p"
echo "PROTOC_VERSION=$v"
echo "MOUNTED_EMPTY_SHA256=$s"'
declare -a DOCKER_ARGV=(docker run --rm --pull never -v "$mount_spec" "$BUILDER_IMAGE" bash -c "$VERIFY_SCRIPT")
if ! out="$("${DOCKER_ARGV[@]}" 2>&1)"; then
  case "$out" in
    *NO_PROTOC*)     die "native protoc absent in the ratified builder image (arch=$ARCH): $BUILDER_IMAGE" ;;
    *NO_SHA256SUM*)  die "ratified builder image lacks sha256sum; cannot verify the mounted include (arch=$ARCH)" ;;
    *MOUNT_EXTRA:*)  die "mounted include exposes files other than google/protobuf/empty.proto (arch=$ARCH): ${out##*MOUNT_EXTRA:}" ;;
    *) die "in-container provisioning verification run failed (arch=$ARCH): $out" ;;
  esac
fi
protoc_path="$(printf '%s\n' "$out" | sed -n 's/^PROTOC_PATH=//p')"
protoc_version="$(printf '%s\n' "$out" | sed -n 's/^PROTOC_VERSION=//p')"
mounted_sha="$(printf '%s\n' "$out" | sed -n 's/^MOUNTED_EMPTY_SHA256=//p')"
[ -n "$protoc_path" ] || die "could not determine the native protoc path from the builder image (arch=$ARCH)"
case "$protoc_path" in /*) ;; *) die "native protoc path is not absolute: '$protoc_path'" ;; esac
[ "$protoc_version" = "$PIN_PROTOC_VERSION" ] \
  || die "native protoc version '$protoc_version' != pinned '$PIN_PROTOC_VERSION' (arch=$ARCH)"
[ "$mounted_sha" = "$PIN_EMPTY_PROTO_SHA256" ] \
  || die "mounted empty.proto in-container sha256 '$mounted_sha' != pinned $PIN_EMPTY_PROTO_SHA256 (arch=$ARCH)"

# VENUE-PRODUCED protoc identity: stream the exact native protoc executable out of the image and hash
# it here (sha256 + blake3). There is NO known off-venue per-arch protoc hash, so these are recorded
# as attested facts ONLY — never compared to a baked-in value (that would be fabrication).
docker run --rm --pull never -e PBIN="$protoc_path" "$BUILDER_IMAGE" bash -c 'cat "$PBIN"' > "$work/protoc.bin" 2>/dev/null \
  || die "could not read the native protoc executable ($protoc_path) from the builder image (arch=$ARCH)"
[ -s "$work/protoc.bin" ] || die "native protoc executable streamed empty from the builder image (arch=$ARCH)"
protoc_sha256="$(sha256_file "$work/protoc.bin")"
protoc_blake3="$(blake3_file "$work/protoc.bin")"

log "provisioned + verified protobuf include (arch=$ARCH): protoc=$protoc_path version='$protoc_version'; mount $mount_spec RO"

# --- (6) machine-readable attestation block to STDOUT ---------------------------------------------
docker_argv="$(printf '%q ' "${DOCKER_ARGV[@]}")"; docker_argv="${docker_argv% }"
printf '# b0-final protobuf-include provisioning attestation (v1)\n'
printf 'arch=%s\n' "$ARCH"
printf 'builder_image=%s\n' "$BUILDER_IMAGE"
printf 'mount_spec=%s\n' "$mount_spec"
printf 'docker_argv=%s\n' "$docker_argv"
printf 'protoc_path=%s\n' "$protoc_path"
printf 'protoc_version=%s\n' "$protoc_version"
printf 'protoc_sha256=%s\n' "$protoc_sha256"
printf 'protoc_blake3=%s\n' "$protoc_blake3"
printf 'authority_content_address_sha256=%s\n' "$ca_sha"
printf 'authority_content_address_blake3=%s\n' "$ca_b3"
printf 'empty_proto_sha256=%s\n' "$empty_sha"
