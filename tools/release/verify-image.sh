#!/usr/bin/env bash
# verify-image.sh --image <registry/repo> --tag <tag> --digest sha256:<64-hex>
#                 --commit <40-hex> --platform <os/arch>
#                 [--require-github-attestation]
#
# Given the commit and the registry digest a release record names, prove the
# image in the registry is that artifact. Every check fails closed:
#
#   1. TAG DRIFT   the tag resolves to exactly --digest. A tag that moved (or
#                  was overwritten) is refused, not followed.
#   2. PLATFORM    the digest is an index or manifest for exactly --platform;
#                  no other runnable platform is present. Attestation
#                  manifests (unknown/unknown) are allowed.
#   3. COMMIT      the image pulled BY DIGEST runs `--version` and prints
#                  exactly "sumchain <commit>"; the OCI revision label agrees.
#   4. SBOM        an SPDX SBOM is attached to the digest.
#   5. PROVENANCE  SLSA provenance is attached and names the commit.
#   6. GENESIS     the image contains no genesis file, and no tracked genesis
#                  at <commit> carries a remediation height
#                  (tools/release/check-genesis-gates.py).
#   7. (optional)  the GitHub artifact attestation for the DIGEST was signed
#                  by .github/workflows/release-image.yml of SUM-INNOVATION/
#                  sum-chain running from refs/heads/main
#                  (tools/release/verify-attestation.sh; the policy is fixed
#                  there and takes no caller input).
#
# Needs docker with buildx, jq, git (a checkout containing <commit>), and gh for 7.
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
IMAGE="" TAG="" DIGEST="" COMMIT="" PLATFORM="" ATTEST=0
while [[ $# -gt 0 ]]; do
  case $1 in
    --image) IMAGE=$2; shift 2 ;; --tag) TAG=$2; shift 2 ;; --digest) DIGEST=$2; shift 2 ;;
    --commit) COMMIT=$2; shift 2 ;; --platform) PLATFORM=$2; shift 2 ;;
    --require-github-attestation) ATTEST=1; shift ;;
    *) echo "usage: see the header of $0" >&2; exit 2 ;;
  esac
done
fail() { echo "VERIFY FAIL: $*" >&2; exit 1; }
[[ -n $IMAGE && -n $TAG && -n $PLATFORM ]] || fail "--image, --tag and --platform are required"
[[ $DIGEST =~ ^sha256:[0-9a-f]{64}$ ]] || fail "--digest '$DIGEST' is not sha256:<64-hex>"
[[ $COMMIT =~ ^[0-9a-f]{40}$ ]] || fail "--commit '$COMMIT' is not a full 40-hex sha"
[[ $TAG != latest ]] || fail "'latest' is never a release tag"
OS=${PLATFORM%%/*} ARCH=${PLATFORM#*/}
REF="$IMAGE@$DIGEST"

# 1. The tag resolves to the digest, exactly.
tagged=$(docker buildx imagetools inspect "$IMAGE:$TAG" --format '{{json .Manifest}}' | jq -r .digest) \
  || fail "cannot resolve $IMAGE:$TAG"
[[ $tagged == "$DIGEST" ]] || fail "TAG DRIFT: $IMAGE:$TAG is $tagged, the release record says $DIGEST"
echo "ok   1 tag $TAG -> $DIGEST"

# 2. Exactly the expected runnable platform.
manifest=$(docker buildx imagetools inspect "$REF" --format '{{json .Manifest}}') || fail "cannot inspect $REF"
platforms=$(jq -r 'if .manifests then [.manifests[] | select(.platform.os != "unknown")
                    | "\(.platform.os)/\(.platform.architecture)"] | unique | join(",") else "single" end' <<<"$manifest")
if [[ $platforms == single ]]; then
  cfg=$(docker buildx imagetools inspect "$REF" --format '{{json .Image}}')
  platforms="$(jq -r .os <<<"$cfg")/$(jq -r .architecture <<<"$cfg")"
fi
[[ $platforms == "$PLATFORM" ]] || fail "PLATFORM: $REF carries '$platforms', expected exactly '$PLATFORM'"
echo "ok   2 platform $platforms"

# 3. Pulled by digest, the binary reports the commit.
docker pull -q --platform "$PLATFORM" "$REF" >/dev/null || fail "docker pull $REF failed"
arch=$(docker image inspect "$REF" --format '{{.Os}}/{{.Architecture}}')
[[ $arch == "$OS/$ARCH" ]] || fail "PLATFORM: pulled image is $arch"
ver=$(docker run --rm --platform "$PLATFORM" "$REF" --version) || fail "$REF --version failed"
[[ $ver == "sumchain $COMMIT" ]] || fail "COMMIT: image reports '$ver', expected 'sumchain $COMMIT'"
label=$(docker image inspect "$REF" --format '{{index .Config.Labels "org.opencontainers.image.revision"}}')
[[ $label == "$COMMIT" ]] || fail "COMMIT: org.opencontainers.image.revision label is '$label'"
echo "ok   3 $ver (label agrees)"

# 4-5. Attestations attached to the digest.
pick='if type == "object" and has($k) then . else (.[$p] // {}) end'
sbom=$(docker buildx imagetools inspect "$REF" --format '{{json .SBOM}}' | jq -c --arg k SPDX --arg p "$PLATFORM" "$pick")
jq -e '.SPDX.spdxVersion // empty' >/dev/null <<<"$sbom" || fail "SBOM: no SPDX SBOM attached to $REF"
pkgs=$(jq '.SPDX.packages | length' <<<"$sbom")
[[ $pkgs -gt 0 ]] || fail "SBOM: the SPDX document lists no packages"
echo "ok   4 SBOM $(jq -r .SPDX.spdxVersion <<<"$sbom"), $pkgs packages"
prov=$(docker buildx imagetools inspect "$REF" --format '{{json .Provenance}}' | jq -c --arg k SLSA --arg p "$PLATFORM" "$pick")
jq -e '.SLSA // empty' >/dev/null <<<"$prov" || fail "PROVENANCE: no SLSA provenance attached to $REF"
grep -q "$COMMIT" <<<"$prov" || fail "PROVENANCE: the provenance does not name $COMMIT"
echo "ok   5 SLSA provenance names the commit"

# 6. No genesis in the image, none with a remediation height in the tree.
found=$(docker run --rm --platform "$PLATFORM" --entrypoint sh "$REF" -c \
  "find / -xdev -type f -name '*genesis*' 2>/dev/null | grep -v -E '^/(proc|sys)/' || true")
[[ -z $found ]] || fail "GENESIS: the image carries genesis file(s): $found"
python3 "$HERE/check-genesis-gates.py" --commit "$COMMIT" >/dev/null \
  || { python3 "$HERE/check-genesis-gates.py" --commit "$COMMIT" >&2 || true; fail "GENESIS: tracked genesis at $COMMIT"; }
echo "ok   6 no genesis in the image; tracked genesis at the commit carries no remediation height"

# 7. GitHub artifact attestation: by digest, under the fixed release policy.
if [[ $ATTEST -eq 1 ]]; then
  bash "$HERE/verify-attestation.sh" "$IMAGE" "$DIGEST" >&2 \
    || fail "ATTESTATION: $IMAGE@$DIGEST is not attested by the release workflow on main"
  echo "ok   7 attestation signed by release-image.yml on refs/heads/main, for $DIGEST"
fi
echo "VERIFIED: $IMAGE:$TAG = $DIGEST, $PLATFORM, sumchain $COMMIT."
