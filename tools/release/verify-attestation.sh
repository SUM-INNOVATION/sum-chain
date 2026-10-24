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

# Asking gh can fail for two very different reasons, and they are kept apart:
#   * gh REJECTED the attestation (no attestation, wrong signer, wrong subject,
#     bad signature...): never retried, never softened -> ATTESTATION FAIL, exit 1;
#   * the attestation SERVICE could not answer (HTTP 5xx or 429, a timeout, a
#     reset or refused connection, DNS): retried with backoff, and if it still
#     cannot answer -> ATTESTATION UNAVAILABLE, exit 3. That is a failure too:
#     this subject stays unverified, and is never accepted without an answer.
#     The result concerns this one subject; a caller verifying several reports
#     which passed and which remain unverified.
# The 2026-10-08 release-native run published a correct release and then failed
# its read-back on one "HTTP 503: trust-metadata-api service unavailable"; the
# same assets verified when re-checked. The retry delays (seconds, one per
# retry) are not policy, so tests may set them; the policy above is fixed.
read -r -a RETRY_DELAYS <<<"${VERIFY_ATTESTATION_RETRY_DELAYS:-5 15 45}"
for d in "${RETRY_DELAYS[@]}"; do [[ $d =~ ^[0-9]+$ ]] || usage; done
readonly MAX_ATTEMPTS=$(( ${#RETRY_DELAYS[@]} + 1 ))
transient() {  # the service did not answer; anything else is a rejection
  grep -Eiq 'HTTP (5[0-9][0-9]|429)([^0-9]|$)|service unavailable|bad gateway|gateway time-?out|too many requests|timed out|timeout|connection (reset|refused)|temporary failure in name resolution|no such host|unexpected EOF|TLS handshake' <<<"$1"
}
attempt=1
while :; do
  errf=$(mktemp)
  if out=$(gh attestation verify "$SUBJECT" \
             --repo "$POLICY_REPO" \
             --cert-identity "$POLICY_IDENTITY" \
             --source-ref "$POLICY_SOURCE_REF" \
             --deny-self-hosted-runners \
             --format json 2>"$errf"); then
    rm -f "$errf"; break
  fi
  err=$(head -c 2000 "$errf"); rm -f "$errf"
  if ! transient "$err"; then
    fail "gh attestation verify rejected $SUBJECT under the release policy${err:+: $(tr '\n' ' ' <<<"$err")}"
  fi
  if (( attempt >= MAX_ATTEMPTS )); then
    echo "ATTESTATION UNAVAILABLE: $SUBJECT is NOT verified: the attestation service did not answer after $attempt attempts (last error: $(tr '\n' ' ' <<<"$err"))" >&2
    exit 3
  fi
  delay=${RETRY_DELAYS[attempt-1]}
  echo "attestation service unavailable for $SUBJECT (attempt $attempt of $MAX_ATTEMPTS): $(tr '\n' ' ' <<<"$err"); retrying in ${delay}s" >&2
  sleep "$delay"
  attempt=$((attempt + 1))
done

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
