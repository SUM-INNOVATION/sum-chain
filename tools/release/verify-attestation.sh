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
readonly POLICY_WORKFLOW=".github/workflows/release-image.yml"
readonly POLICY_SOURCE_REF="refs/heads/main"
readonly POLICY_IDENTITY="https://github.com/${POLICY_REPO}/${POLICY_WORKFLOW}@${POLICY_SOURCE_REF}"
readonly POLICY_SOURCE_URI="https://github.com/${POLICY_REPO}"

fail() { echo "ATTESTATION FAIL: $*" >&2; exit 1; }
[[ $# -eq 2 ]] || { echo "usage: verify-attestation.sh <registry/repo> sha256:<64-hex>" >&2; exit 2; }
IMAGE=$1 DIGEST=$2

[[ $DIGEST =~ ^sha256:[0-9a-f]{64}$ ]] || fail "'$DIGEST' is not an immutable sha256:<64-hex> digest"
# The repository reference alone: no tag and no digest of its own. A tag is
# mutable and is never what gets verified. (A registry port, host:5000/x, is
# not a tag: only the last path component is checked.)
[[ $IMAGE != *@* ]] || fail "'$IMAGE' already carries a digest; pass the repository and the digest separately"
last=${IMAGE##*/}
[[ $IMAGE == */* && $last != *:* ]] || fail "'$IMAGE' is not a bare registry/repository reference (a tag is never verified)"
SUBJECT="oci://${IMAGE}@${DIGEST}"

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

n=$(jq length <<<"$out")
echo "ATTESTATION OK: $n attestation(s) for $DIGEST, signed by $POLICY_IDENTITY"
