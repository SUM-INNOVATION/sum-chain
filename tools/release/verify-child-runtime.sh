#!/usr/bin/env bash
# verify-child-runtime.sh <registry/repo> <child-image-digest> <40-hex commit> <linux/amd64|linux/arm64>
#
# Pulls ONE child of a release BY DIGEST, on a runner of that platform (no
# emulation), and proves the image that will actually run:
#   * the pulled image is that platform;
#   * `sumchain --version` prints the release commit;
#   * the smoke test passes: /health, /ready after a block, and a complete
#     /metrics (tools/lane-b/wave1-monitor.sh verify);
# then prints one JSON line with the binary's sha256, for the release record.
set -euo pipefail
[[ $# -eq 4 ]] || { echo "usage: verify-child-runtime.sh <registry/repo> <digest> <commit> <platform>" >&2; exit 2; }
IMAGE=$1 DIGEST=$2 COMMIT=$3 PLATFORM=$4
HERE=$(cd "$(dirname "$0")" && pwd)
fail() { echo "RUNTIME FAIL [$PLATFORM]: $*" >&2; exit 1; }
[[ $DIGEST =~ ^sha256:[0-9a-f]{64}$ ]] || fail "'$DIGEST' is not a digest; a tag is never verified"
[[ $IMAGE != *@* && ${IMAGE##*/} != *:* ]] || fail "'$IMAGE' must be a bare repository reference"
[[ $COMMIT =~ ^[0-9a-f]{40}$ ]] || fail "commit must be a full 40-hex sha"
case $PLATFORM in linux/amd64|linux/arm64) ;; *) fail "platform must be linux/amd64 or linux/arm64" ;; esac
host=$(docker version --format '{{.Server.Arch}}')
[[ $host == "${PLATFORM#linux/}" ]] || fail "this runner is $host; $PLATFORM is verified natively"

REF="$IMAGE@$DIGEST"
docker pull -q "$REF" >/dev/null || fail "docker pull $REF failed"
got=$(docker image inspect "$REF" --format '{{.Os}}/{{.Architecture}}')
[[ $got == "$PLATFORM" ]] || fail "the pulled image is $got"
ver=$(docker run --rm "$REF" --version) || fail "--version failed"
[[ $ver == "sumchain $COMMIT" ]] || fail "the binary reports '$ver', not 'sumchain $COMMIT'"
bash "$HERE/smoke-image.sh" "$REF" >&2 || fail "smoke test failed"
bin=$(docker run --rm --entrypoint sha256sum "$REF" /usr/local/bin/sumchain | cut -d' ' -f1)
[[ $bin =~ ^[0-9a-f]{64}$ ]] || fail "could not hash /usr/local/bin/sumchain"
jq -cn --arg p "$PLATFORM" --arg d "$DIGEST" --arg v "$ver" --arg b "$bin" \
  '{platform: $p, digest: $d, version: $v, binary_sha256: $b, smoke: "OK"}'
