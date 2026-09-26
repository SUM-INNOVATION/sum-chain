#!/usr/bin/env bash
# Battery for verify-attestation.sh. A `gh` stub on PATH records the exact
# arguments it was called with and returns a fixture result, so every rule is
# tested without the network. NONPRODUCTION digests and identities throughout.
#
# Two independent layers, each with its own cases:
#   ARGV   the policy gh is asked to enforce (identity, source ref, repo,
#          subject by digest). Removing a flag fails an argv case.
#   RESULT the script's own check of gh's JSON. A gh result signed by another
#          workflow, branch or repository, or for another digest, must be
#          refused even when gh returned it.
#
#   bash tools/release/verify-attestation-test.sh
set -uo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
SCRIPT=${VERIFY_ATTESTATION:-$HERE/verify-attestation.sh}
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
mkdir -p "$T/bin"
fail=0; n=0

REPO=SUM-INNOVATION/sum-chain
ID="https://github.com/$REPO/.github/workflows/release-image.yml@refs/heads/main"
IMG=ghcr.io/sum-innovation/sum-chain
HEX=$(printf 'a%.0s' {1..64}); DIGEST="sha256:$HEX"          # NONPRODUCTION
COMMIT=$(printf 'c%.0s' {1..40})                               # NONPRODUCTION

cat >"$T/bin/gh" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "$@" >"$STUB_ARGV"
[[ ${STUB_EXIT:-0} -eq 0 ]] || { echo "stub: verification failed" >&2; exit "$STUB_EXIT"; }
cat "$STUB_OUT"
EOF
chmod +x "$T/bin/gh"

# result <san> <signer> <ref> <source-uri> <subject-hex> [wf-repo wf-path wf-ref git-commit build-type]:
# one gh JSON element. The signed provenance defaults to the release workflow
# at refs/heads/main building $COMMIT.
result() {
  jq -n --arg san "$1" --arg signer "$2" --arg ref "$3" --arg uri "$4" --arg hex "$5" \
        --arg wrepo "${6:-https://github.com/$REPO}" --arg wpath "${7:-.github/workflows/release-image.yml}" \
        --arg wref "${8:-refs/heads/main}" --arg git "${9:-$COMMIT}" \
        --arg bt "${10:-https://actions.github.io/buildtypes/workflow/v1}" '
    [{attestation: {}, verificationResult: {
       statement: {subject: [{name: "ghcr.io/sum-innovation/sum-chain", digest: {sha256: $hex}}],
                   predicateType: "https://slsa.dev/provenance/v1",
                   predicate: {buildDefinition: {buildType: $bt,
                     externalParameters: {workflow: {repository: $wrepo, path: $wpath, ref: $wref}},
                     resolvedDependencies: [{uri: "git+\($wrepo)@\($wref)", digest: {gitCommit: $git}}]}}},
       signature: {certificate: {subjectAlternativeName: $san, buildSignerURI: $signer,
                                 sourceRepositoryRef: $ref, sourceRepositoryURI: $uri,
                                 certificateIssuer: "CN=sigstore-intermediate,O=sigstore.dev"}}}}]'
}
GOOD=$(result "$ID" "$ID" refs/heads/main "https://github.com/$REPO" "$HEX")

# run <out-json> [env...] -- <args...>: runs the script with the stub.
run() {
  local out=$1; shift
  printf '%s' "$out" >"$T/out.json"; : >"$T/argv"
  env PATH="$T/bin:$PATH" STUB_OUT="$T/out.json" STUB_ARGV="$T/argv" "$@" bash "$SCRIPT" "${ARGS[@]}" 2>&1
}
check() {  # name, want-exit, want-text, got-exit, got-output
  n=$((n+1))
  if [[ $4 -eq $2 ]] && grep -q -- "$3" <<<"$5"; then printf '  ok    %-62s exit %s\n' "$1" "$4"
  else printf '  FAIL  %-62s exit %s (want %s, "%s")\n' "$1" "$4" "$2" "$3"; sed 's/^/          | /' <<<"$5" | tail -3; fail=$((fail+1)); fi
}
# has_pair <flag> <value>: the recorded argv holds flag immediately followed by value.
has_pair() { awk -v f="$1" -v v="$2" 'prev==f && $0==v {found=1} {prev=$0} END{exit !found}' "$T/argv"; }
argv_case() {  # name, flag, value
  n=$((n+1))
  if has_pair "$2" "$3"; then printf '  ok    %-62s\n' "$1"
  else printf '  FAIL  %-62s argv lacks: %s %s\n' "$1" "$2" "$3"; sed 's/^/          | /' "$T/argv"; fail=$((fail+1)); fi
}

echo "argv: the policy gh is asked to enforce"
ARGS=("$IMG" "$DIGEST" "$COMMIT")
o=$(run "$GOOD"); rc=$?
check "a release attestation for the digest is accepted" 0 "ATTESTATION OK" $rc "$o"
argv_case "signer identity is exact: release-image.yml at refs/heads/main" --cert-identity "$ID"
argv_case "source ref is enforced: refs/heads/main" --source-ref refs/heads/main
argv_case "repository is enforced" --repo "$REPO"
n=$((n+1))
if [[ $(head -3 "$T/argv" | sed -n 3p) == "oci://$IMG@$DIGEST" ]] && ! grep -qE "^oci://[^@]*:[^/]*$" "$T/argv"; then
  printf '  ok    %-62s\n' "the subject is the immutable digest, not a tag"
else printf '  FAIL  %-62s\n' "the subject is the immutable digest, not a tag"; sed 's/^/          | /' "$T/argv"; fail=$((fail+1)); fi
n=$((n+1))
if grep -qx -- '--deny-self-hosted-runners' "$T/argv" && ! grep -qx -- '--signer-workflow' "$T/argv"; then
  printf '  ok    %-62s\n' "self-hosted runners denied; no prefix-matching --signer-workflow"
else printf '  FAIL  %-62s\n' "self-hosted runners denied; no prefix-matching --signer-workflow"; fail=$((fail+1)); fi

echo "the policy is not caller-controlled"
o=$(run "$GOOD" POLICY_SOURCE_REF=refs/heads/evil POLICY_IDENTITY=x SOURCE_REF=refs/heads/evil SIGNER_WORKFLOW=.github/workflows/evil.yml); rc=$?
check "environment overrides are ignored" 0 "ATTESTATION OK" $rc "$o"
argv_case "  ...identity is still the constant" --cert-identity "$ID"
argv_case "  ...source ref is still the constant" --source-ref refs/heads/main
ARGS=("$IMG" "$DIGEST" "$COMMIT" --signer-workflow .github/workflows/evil.yml)
o=$(run "$GOOD"); rc=$?
check "an extra workflow argument is a usage error" 2 "usage" $rc "$o"

echo "mutable references are refused before gh runs"
ARGS=("$IMG:8a3c942b-amd64" "$DIGEST" "$COMMIT"); o=$(run "$GOOD"); rc=$?
check "image given with a tag" 1 "a tag is never verified" $rc "$o"
ARGS=("$IMG" latest "$COMMIT"); o=$(run "$GOOD"); rc=$?
check "digest given as a tag" 1 "is not an immutable" $rc "$o"
ARGS=("$IMG@$DIGEST" "$DIGEST" "$COMMIT"); o=$(run "$GOOD"); rc=$?
check "image already carrying a digest" 1 "already carries a digest" $rc "$o"
ARGS=("localhost:5000/sum-chain" "$DIGEST" "$COMMIT"); o=$(run "$GOOD"); rc=$?
check "a registry port is not mistaken for a tag" 0 "ATTESTATION OK" $rc "$o"

ARGS=("$IMG" "$DIGEST" 8a3c942b); o=$(run "$GOOD"); rc=$?
check "an abbreviated commit" 1 "not a full 40-hex commit" $rc "$o"

echo "result: gh's JSON is re-checked"
ARGS=("$IMG" "$DIGEST" "$COMMIT")
OTHER="https://github.com/$REPO/.github/workflows/other.yml@refs/heads/main"
o=$(run "$(result "$OTHER" "$OTHER" refs/heads/main "https://github.com/$REPO" "$HEX")"); rc=$?
check "signed by another workflow on main" 1 "does not match the release policy" $rc "$o"
PREFIX="https://github.com/$REPO/.github/workflows/release-image.yml-other.yml@refs/heads/main"
o=$(run "$(result "$PREFIX" "$PREFIX" refs/heads/main "https://github.com/$REPO" "$HEX")"); rc=$?
check "signed by a workflow whose name merely starts the same" 1 "does not match the release policy" $rc "$o"
BR="https://github.com/$REPO/.github/workflows/release-image.yml@refs/heads/feature"
o=$(run "$(result "$BR" "$BR" refs/heads/feature "https://github.com/$REPO" "$HEX")"); rc=$?
check "the release workflow run from another branch" 1 "does not match the release policy" $rc "$o"
o=$(run "$(result "$ID" "$ID" refs/heads/feature "https://github.com/$REPO" "$HEX")"); rc=$?
check "identity says main but the source ref is another branch" 1 "does not match the release policy" $rc "$o"
o=$(run "$(result "$ID" "$OTHER" refs/heads/main "https://github.com/$REPO" "$HEX")"); rc=$?
check "identity says release-image.yml but the build signer differs" 1 "does not match the release policy" $rc "$o"
o=$(run "$(result "$ID" "$ID" refs/heads/main "https://github.com/someone/sum-chain" "$HEX")"); rc=$?
check "source repository is a fork" 1 "does not match the release policy" $rc "$o"
o=$(run "$(result "$ID" "$ID" refs/heads/main "https://github.com/$REPO" "$(printf 'b%.0s' {1..64})")"); rc=$?
check "attestation is for another digest" 1 "does not match the release policy" $rc "$o"
o=$(run "$(jq -s 'add' <(result "$ID" "$ID" refs/heads/main "https://github.com/$REPO" "$HEX") <(result "$OTHER" "$OTHER" refs/heads/main "https://github.com/$REPO" "$HEX"))"); rc=$?
check "one good and one foreign attestation: every one must match" 1 "does not match the release policy" $rc "$o"
o=$(run "[]"); rc=$?
check "no attestation at all" 1 "does not match the release policy" $rc "$o"
o=$(run "$GOOD" STUB_EXIT=1); rc=$?
check "gh itself rejects" 1 "rejected" $rc "$o"

echo "result: the signed provenance names the release workflow, ref, repository and commit"
okcert=("$ID" "$ID" refs/heads/main "https://github.com/$REPO" "$HEX")
o=$(run "$(result "${okcert[@]}" "https://github.com/$REPO" .github/workflows/other.yml)"); rc=$?
check "provenance names another workflow" 1 "signed provenance" $rc "$o"
o=$(run "$(result "${okcert[@]}" "https://github.com/$REPO" .github/workflows/release-image.yml refs/heads/feature)"); rc=$?
check "provenance names another branch" 1 "signed provenance" $rc "$o"
o=$(run "$(result "${okcert[@]}" "https://github.com/someone/sum-chain")"); rc=$?
check "provenance names another repository" 1 "signed provenance" $rc "$o"
o=$(run "$(result "${okcert[@]}" "https://github.com/$REPO" .github/workflows/release-image.yml refs/heads/main "$(printf 'd%.0s' {1..40})")"); rc=$?
check "provenance names another source commit" 1 "signed provenance" $rc "$o"
o=$(run "$(result "${okcert[@]}" "https://github.com/$REPO" .github/workflows/release-image.yml refs/heads/main "$COMMIT" https://example.com/other-buildtype)"); rc=$?
check "provenance of another build type" 1 "signed provenance" $rc "$o"

# The wiring of this policy into release-image.yml (which digests are attested
# and verified, and in what order) is checked in tools/release/release-test.py.

echo
if [[ $fail -eq 0 ]]; then echo "ATTESTATION POLICY BATTERY OK: $n cases"; exit 0; fi
echo "ATTESTATION POLICY BATTERY FAILED: $fail of $n"; exit 1
