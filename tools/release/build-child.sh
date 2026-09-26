#!/usr/bin/env bash
# build-child.sh <linux/amd64|linux/arm64> <40-hex commit> <out-dir> <builder-id URL>
#
# Builds ONE platform of the release, natively (the host must be that
# platform: no emulation), from the checked-out commit and the pinned
# Dockerfile, and proves it BEFORE anything is published:
#   1. build and load it; `sumchain --version` prints the commit; the smoke
#      test passes (/health, /ready, a complete /metrics);
#   2. build it again from the same cache as an OCI layout, with an SPDX SBOM
#      and SLSA v1 provenance (builder id = this run), and check the layout
#      with oci.py: one child index, one image for this platform, the revision
#      label, one attestation manifest about that image.
# Writes <out-dir>/child-<arch>.tar, child-<arch>.json, binary-<arch>.sha256.
# Holds no registry credential; nothing leaves the runner.
set -euo pipefail
[[ $# -eq 4 ]] || { echo "usage: build-child.sh <platform> <commit> <out-dir> <builder-id>" >&2; exit 2; }
PLATFORM=$1 COMMIT=$2 OUT=$3 BUILDER_ID=$4
HERE=$(cd "$(dirname "$0")" && pwd)
fail() { echo "BUILD FAIL [$PLATFORM]: $*" >&2; exit 1; }
case $PLATFORM in linux/amd64|linux/arm64) ;; *) fail "platform must be linux/amd64 or linux/arm64" ;; esac
[[ $COMMIT =~ ^[0-9a-f]{40}$ ]] || fail "commit must be a full 40-hex sha"
[[ $(git rev-parse HEAD) == "$COMMIT" ]] || fail "checked out $(git rev-parse HEAD), not $COMMIT"
[[ -z $(git status --porcelain) ]] || fail "the checkout is not clean"
ARCH=${PLATFORM#linux/}
host=$(docker version --format '{{.Server.Arch}}')
[[ $host == "$ARCH" ]] || fail "this runner is $host; $PLATFORM is built natively on a $ARCH runner"
mkdir -p "$OUT"
# Outside the checkout: a layout written inside it would make the tree dirty
# for the second build, and the provenance's VCS revision would not be the commit.
case "$(cd "$OUT" && pwd -P)/" in "$(git rev-parse --show-toplevel)"/*) fail "out-dir must be outside the checkout" ;; esac

common=(--platform "$PLATFORM" --build-arg GIT_HASH="$COMMIT"
        --label org.opencontainers.image.revision="$COMMIT"
        --label org.opencontainers.image.source="https://github.com/SUM-INNOVATION/sum-chain")

# 1. Build, load, and prove it runs.
tag="sumchain-release-candidate:$ARCH-$COMMIT"
docker buildx build "${common[@]}" --load -t "$tag" .
ver=$(docker run --rm "$tag" --version)
[[ $ver == "sumchain $COMMIT" ]] || fail "the binary reports '$ver', not 'sumchain $COMMIT'"
bash "$HERE/smoke-image.sh" "$tag"
bin=$(docker run --rm --entrypoint sha256sum "$tag" /usr/local/bin/sumchain | cut -d' ' -f1)
[[ $bin =~ ^[0-9a-f]{64}$ ]] || fail "could not hash /usr/local/bin/sumchain"
echo "$bin" > "$OUT/binary-$ARCH.sha256"

# 2. The same build, as an OCI layout with attestations.
docker buildx build "${common[@]}" \
  --sbom=true --provenance="mode=max,version=v1,builder-id=$BUILDER_ID" \
  --output "type=oci,dest=$OUT/child-$ARCH.tar,tar=true" \
  --metadata-file "$OUT/meta-$ARCH.json" .
python3 "$HERE/oci.py" inspect-layout "$OUT/child-$ARCH.tar" --platform "$PLATFORM" --commit "$COMMIT" \
  > "$OUT/child-$ARCH.json" || fail "the OCI layout does not hold a valid $PLATFORM child"
docker image rm "$tag" >/dev/null
echo "BUILT $PLATFORM: child index $(jq -r .child_index "$OUT/child-$ARCH.json"), image $(jq -r .image "$OUT/child-$ARCH.json"), binary sha256 $bin"
