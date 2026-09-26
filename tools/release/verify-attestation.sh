#!/usr/bin/env bash
# verify-attestation.sh <registry/repo> sha256:<64-hex>
#
# Accepts a release image only if its GitHub artifact attestation was produced
# by THIS repository's release workflow, running from main, for exactly this
# digest. The policy is fixed below and is not an input: a caller cannot
# widen it by passing another workflow, branch or repository.
#
# Why consumer-side: the `release` environment (required reviewer, main only)
# protects the approved workflow. It cannot stop someone with write access
# from adding a DIFFERENT workflow that pushes to the same package. Such an
# image carries either no attestation, or one signed by that other workflow
# or branch. This check rejects both. See docs/operations/release-image.md.
#
# Enforced by gh itself (gh 2.100.0 flags, checked against its source):
#   --repo            the attestation is linked to SUM-INNOVATION/sum-chain;
#   --cert-identity   the signing certificate's identity is EXACTLY the release
#                     workflow at refs/heads/main. --signer-workflow is not
#                     used: gh builds it as a prefix regex with no end anchor
#                     (".../release-image.yml" also matches
#                     ".../release-image.yml-other.yml@refs/heads/any"), and
#                     it is mutually exclusive with --cert-identity;
#   --source-ref      the source repository ref is refs/heads/main;
#   --deny-self-hosted-runners;
#   oci://<repo>@<digest>  the subject is the immutable digest, never a tag.
# Then re-checked here, on gh's JSON result, so a gh that accepted too much
# still fails: every verified attestation must carry the exact identity,
# signer, source ref and source repository, and name this digest as a subject.
set -euo pipefail

readonly POLICY_REPO="SUM-INNOVATION/sum-chain"
readonly POLICY_SOURCE_REF="refs/heads/main"
readonly POLICY_SOURCE_URI="https://github.com/${POLICY_REPO}"
readonly POLICY_BUILD_TYPE="https://actions.github.io/buildtypes/workflow/v1"
# Which workflow must have signed depends only on WHAT is verified, never on an
# argument: native release files come from release-native.yml (the production
# release); OCI images from release-image.yml (optional CI/devnet packaging).
readonly POLICY_WORKFLOW_FILE=".github/workflows/release-native.yml"
readonly POLICY_WORKFLOW_OCI=".github/workflows/release-image.yml"

fail() { echo "ATTESTATION FAIL: $*" >&2; exit 1; }
usage() {
  echo "usage: verify-attestation.sh --file <path> <40-hex commit>" >&2
  echo "       verify-attestation.sh <registry/repo> sha256:<64-hex> [<40-hex commit>]" >&2
  exit 2
}
h() { if command -v sha256sum >/dev/null; then sha256sum "$1" | cut -d' ' -f1; else shasum -a 256 "$1" | cut -d' ' -f1; fi; }
COMMIT=""
if [[ ${1:-} == --file ]]; then
  [[ $# -eq 3 ]] || usage
  FILE=$2 COMMIT=$3
  [[ -f $FILE && ! -L $FILE ]] || fail "'$FILE' is not a regular file"
  POLICY_WORKFLOW=$POLICY_WORKFLOW_FILE
  DIGEST="sha256:$(h "$FILE")"
  SUBJECT=$FILE
else
  [[ $# -eq 2 || $# -eq 3 ]] || usage
  IMAGE=$1 DIGEST=$2 COMMIT=${3:-}
  POLICY_WORKFLOW=$POLICY_WORKFLOW_OCI
  [[ $DIGEST =~ ^sha256:[0-9a-f]{64}$ ]] || fail "'$DIGEST' is not an immutable sha256:<64-hex> digest"
  # The repository reference alone: no tag and no digest of its own. A tag is
  # mutable and is never what gets verified. (A registry port, host:5000/x, is
  # not a tag: only the last path component is checked.)
  [[ $IMAGE != *@* ]] || fail "'$IMAGE' already carries a digest; pass the repository and the digest separately"
  last=${IMAGE##*/}
  [[ $IMAGE == */* && $last != *:* ]] || fail "'$IMAGE' is not a bare registry/repository reference (a tag is never verified)"
  SUBJECT="oci://${IMAGE}@${DIGEST}"
fi
[[ -z $COMMIT || $COMMIT =~ ^[0-9a-f]{40}$ ]] || fail "'$COMMIT' is not a full 40-hex commit"
readonly POLICY_WORKFLOW
readonly POLICY_IDENTITY="https://github.com/${POLICY_REPO}/${POLICY_WORKFLOW}@${POLICY_SOURCE_REF}"

out=$(gh attestation verify "$SUBJECT" \
        --repo "$POLICY_REPO" \
        --cert-identity "$POLICY_IDENTITY" \
        --source-ref "$POLICY_SOURCE_REF" \
        --deny-self-hosted-runners \
        --format json) \
  || fail "gh attestation verify rejected $SUBJECT under the release policy"

jq -e --arg id "$POLICY_IDENTITY" --arg ref "$POLICY_SOURCE_REF" --arg uri "$POLICY_SOURCE_URI" \
      --arg hex "${DIGEST#sha256:}" '
  type == "array" and length > 0 and
  all(.[]; .verificationResult.signature.certificate as $c
      | $c.subjectAlternativeName == $id
      and $c.buildSignerURI == $id
      and $c.sourceRepositoryRef == $ref
      and $c.sourceRepositoryURI == $uri
      and ([.verificationResult.statement.subject[]?.digest.sha256] | index($hex)) != null)
' <<<"$out" >/dev/null 2>&1 \
  || fail "an attestation for $SUBJECT does not match the release policy (identity $POLICY_IDENTITY, source $POLICY_SOURCE_REF of $POLICY_SOURCE_URI, subject $DIGEST)"

# The signed provenance itself: this repository's workflow at main, building
# the release commit. The release workflows run only while that commit is the
# head of main, so the signed source commit IS the built commit.
if [[ -n $COMMIT ]]; then
  jq -e --arg bt "$POLICY_BUILD_TYPE" --arg uri "$POLICY_SOURCE_URI" --arg wf "$POLICY_WORKFLOW" \
        --arg ref "$POLICY_SOURCE_REF" --arg commit "$COMMIT" '
    all(.[]; .verificationResult.statement.predicate as $p
        | $p.buildDefinition.buildType == $bt
        and $p.buildDefinition.externalParameters.workflow.repository == $uri
        and $p.buildDefinition.externalParameters.workflow.path == $wf
        and $p.buildDefinition.externalParameters.workflow.ref == $ref
        and ([$p.buildDefinition.resolvedDependencies[]? | select(.uri == "git+\($uri)@\($ref)") | .digest.gitCommit]
             == [$commit]))
  ' <<<"$out" >/dev/null 2>&1 \
    || fail "the signed provenance for $SUBJECT does not name $POLICY_WORKFLOW at $POLICY_SOURCE_REF of $POLICY_SOURCE_URI building $COMMIT"
fi

n=$(jq length <<<"$out")
echo "ATTESTATION OK: $n attestation(s) for $DIGEST, signed by $POLICY_IDENTITY${COMMIT:+, source $COMMIT}"
