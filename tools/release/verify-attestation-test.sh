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

cat >"$T/bin/gh" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "$@" >"$STUB_ARGV"
[[ ${STUB_EXIT:-0} -eq 0 ]] || { echo "stub: verification failed" >&2; exit "$STUB_EXIT"; }
cat "$STUB_OUT"
EOF
chmod +x "$T/bin/gh"

# result <san> <signer> <ref> <source-uri> <subject-hex>: one gh JSON element.
result() {
  jq -n --arg san "$1" --arg signer "$2" --arg ref "$3" --arg uri "$4" --arg hex "$5" '
    [{attestation: {}, verificationResult: {
       statement: {subject: [{name: "ghcr.io/sum-innovation/sum-chain", digest: {sha256: $hex}}]},
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
ARGS=("$IMG" "$DIGEST")
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
ARGS=("$IMG" "$DIGEST" --signer-workflow .github/workflows/evil.yml)
o=$(run "$GOOD"); rc=$?
check "an extra workflow argument is a usage error" 2 "usage" $rc "$o"

echo "mutable references are refused before gh runs"
ARGS=("$IMG:8a3c942b-amd64" "$DIGEST"); o=$(run "$GOOD"); rc=$?
check "image given with a tag" 1 "a tag is never verified" $rc "$o"
ARGS=("$IMG" latest); o=$(run "$GOOD"); rc=$?
check "digest given as a tag" 1 "is not an immutable" $rc "$o"
ARGS=("$IMG@$DIGEST" "$DIGEST"); o=$(run "$GOOD"); rc=$?
check "image already carrying a digest" 1 "already carries a digest" $rc "$o"
ARGS=("localhost:5000/sum-chain" "$DIGEST"); o=$(run "$GOOD"); rc=$?
check "a registry port is not mistaken for a tag" 0 "ATTESTATION OK" $rc "$o"

echo "result: gh's JSON is re-checked"
ARGS=("$IMG" "$DIGEST")
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

echo "file mode: native release archives, signed by release-native.yml on main"
COMMIT=$(printf 'c%.0s' {1..40})                               # NONPRODUCTION
NID="https://github.com/$REPO/.github/workflows/release-native.yml@refs/heads/main"
ART="$T/sumchain-$COMMIT-x86_64-unknown-linux-gnu.tar.gz"
printf 'NONPRODUCTION archive bytes\n' > "$ART"
AHEX=$( (command -v sha256sum >/dev/null && sha256sum "$ART" || shasum -a 256 "$ART") | cut -d' ' -f1)
# fresult <san> <signer> <ref> <source-uri> <subject-hex> <wf-repo> <wf-path> <wf-ref> <git-commit>
fresult() {
  jq -n --arg san "$1" --arg signer "$2" --arg ref "$3" --arg uri "$4" --arg hex "$5" \
        --arg wrepo "$6" --arg wpath "$7" --arg wref "$8" --arg git "$9" '
    [{attestation: {}, verificationResult: {
       statement: {subject: [{name: "archive", digest: {sha256: $hex}}],
                   predicateType: "https://slsa.dev/provenance/v1",
                   predicate: {buildDefinition: {buildType: "https://actions.github.io/buildtypes/workflow/v1",
                     externalParameters: {workflow: {repository: $wrepo, path: $wpath, ref: $wref}},
                     resolvedDependencies: [{uri: "git+\($wrepo)@\($wref)", digest: {gitCommit: $git}}]}}},
       signature: {certificate: {subjectAlternativeName: $san, buildSignerURI: $signer,
                                 sourceRepositoryRef: $ref, sourceRepositoryURI: $uri}}}}]'
}
U="https://github.com/$REPO"
FGOOD=$(fresult "$NID" "$NID" refs/heads/main "$U" "$AHEX" "$U" .github/workflows/release-native.yml refs/heads/main "$COMMIT")
ARGS=(--file "$ART" "$COMMIT")
o=$(run "$FGOOD"); rc=$?
check "file: a release archive attested by release-native.yml is accepted" 0 "ATTESTATION OK" $rc "$o"
argv_case "file: signer identity is exactly release-native.yml at main" --cert-identity "$NID"
argv_case "file: source ref is enforced" --source-ref refs/heads/main
n=$((n+1))
if [[ $(sed -n 3p "$T/argv") == "$ART" ]]; then printf '  ok    %-62s\n' "file: the subject is the file itself"
else printf '  FAIL  %-62s\n' "file: the subject is the file itself"; fail=$((fail+1)); fi
OID="https://github.com/$REPO/.github/workflows/release-image.yml@refs/heads/main"
o=$(run "$(fresult "$OID" "$OID" refs/heads/main "$U" "$AHEX" "$U" .github/workflows/release-image.yml refs/heads/main "$COMMIT")"); rc=$?
check "file: signed by the OCI workflow, not the native one" 1 "does not match the release policy" $rc "$o"
o=$(run "$(fresult "$NID" "$NID" refs/heads/main "$U" "$AHEX" "$U" .github/workflows/other.yml refs/heads/main "$COMMIT")"); rc=$?
check "file: provenance names another workflow" 1 "signed provenance" $rc "$o"
o=$(run "$(fresult "$NID" "$NID" refs/heads/main "$U" "$AHEX" "$U" .github/workflows/release-native.yml refs/heads/feature "$COMMIT")"); rc=$?
check "file: provenance names another branch" 1 "signed provenance" $rc "$o"
o=$(run "$(fresult "$NID" "$NID" refs/heads/main "$U" "$AHEX" "https://github.com/someone/sum-chain" .github/workflows/release-native.yml refs/heads/main "$COMMIT")"); rc=$?
check "file: provenance names another repository" 1 "signed provenance" $rc "$o"
o=$(run "$(fresult "$NID" "$NID" refs/heads/main "$U" "$AHEX" "$U" .github/workflows/release-native.yml refs/heads/main "$(printf 'd%.0s' {1..40})")"); rc=$?
check "file: provenance names another source commit" 1 "signed provenance" $rc "$o"
o=$(run "$(fresult "$NID" "$NID" refs/heads/main "$U" "$(printf 'b%.0s' {1..64})" "$U" .github/workflows/release-native.yml refs/heads/main "$COMMIT")"); rc=$?
check "file: attestation is for another file's digest" 1 "does not match the release policy" $rc "$o"
ln -s "$ART" "$T/link.tar.gz"; ARGS=(--file "$T/link.tar.gz" "$COMMIT"); o=$(run "$FGOOD"); rc=$?
check "file: a symlink is refused" 1 "is not a regular file" $rc "$o"
ARGS=(--file "$ART"); o=$(run "$FGOOD"); rc=$?
check "file: the commit is required" 2 "usage" $rc "$o"

echo "transient service failures: retried; rejections: never"
# A second stub that answers from a script of outcomes, one per call:
#   503|429|timeout  the service did not answer (stderr as gh prints it, exit 1)
#   reject           gh rejected the attestation (exit 1)
#   ok               the fixture result (exit 0)
cat >"$T/bin/gh-seq" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "$@" >"$STUB_ARGV"
n=$(( $(cat "$STUB_COUNT" 2>/dev/null || echo 0) + 1 )); echo "$n" >"$STUB_COUNT"
read -r -a seq <<<"$STUB_SEQ"; step=${seq[n-1]:-${seq[${#seq[@]}-1]}}
case $step in
  503) echo "HTTP 503: trust-metadata-api service unavailable (https://api.github.com/...)" >&2; exit 1 ;;
  429) echo "HTTP 429: too many requests" >&2; exit 1 ;;
  timeout) echo 'Get "https://api.github.com/...": dial tcp 140.82.112.6:443: i/o timeout' >&2; exit 1 ;;
  reject) echo "Error: verifying with issuer \"sigstore.dev\": failed to verify signature" >&2; exit 1 ;;
  ok) cat "$STUB_OUT" ;;
esac
EOF
chmod +x "$T/bin/gh-seq"
mkdir -p "$T/seqbin"; ln -sf "$T/bin/gh-seq" "$T/seqbin/gh"
# seqrun <out-json> <sequence> [env...]: runs the script with the sequence stub; no real waiting.
seqrun() {
  local out=$1 seq=$2; shift 2
  printf '%s' "$out" >"$T/out.json"; : >"$T/argv"; rm -f "$T/count"
  env PATH="$T/seqbin:$PATH" STUB_OUT="$T/out.json" STUB_ARGV="$T/argv" STUB_COUNT="$T/count" \
      STUB_SEQ="$seq" VERIFY_ATTESTATION_RETRY_DELAYS="${DELAYS-0 0 0}" "$@" bash "$SCRIPT" "${ARGS[@]}" 2>&1
}
calls() { cat "$T/count" 2>/dev/null || echo 0; }
ARGS=(--file "$ART" "$COMMIT")
o=$(seqrun "$FGOOD" "503 ok"); rc=$?
check "503 once, then an answer: verified on the retry" 0 "ATTESTATION OK" $rc "$o"
n=$((n+1)); [[ $(calls) -eq 2 ]] && printf '  ok    %-62s\n' "  ...gh was asked exactly twice" \
  || { printf '  FAIL  %-62s calls=%s\n' "  ...gh was asked exactly twice" "$(calls)"; fail=$((fail+1)); }
argv_case "  ...the retry asks gh for the same policy (identity)" --cert-identity "$NID"
argv_case "  ...the retry asks gh for the same policy (source ref)" --source-ref refs/heads/main
o=$(seqrun "$FGOOD" "503 503 503 503"); rc=$?
check "503 on every attempt: unavailable, not accepted" 3 "ATTESTATION UNAVAILABLE" $rc "$o"
check "  ...the message names the unverified subject" 3 "x86_64-unknown-linux-gnu.tar.gz is NOT verified" $rc "$o"
check "  ...and says how many attempts were made" 3 "did not answer after 4 attempts" $rc "$o"
n=$((n+1)); grep -q "nothing was verified" <<<"$o" && { printf '  FAIL  %-62s\n' "  ...without claiming anything about other subjects"; fail=$((fail+1)); } \
  || printf '  ok    %-62s\n' "  ...without claiming anything about other subjects"
n=$((n+1)); [[ $(calls) -eq 4 ]] && printf '  ok    %-62s\n' "  ...gh was asked four times (1 + 3 retries)" \
  || { printf '  FAIL  %-62s calls=%s\n' "  ...gh was asked four times (1 + 3 retries)" "$(calls)"; fail=$((fail+1)); }
n=$((n+1)); grep -q "ATTESTATION OK" <<<"$o" && { printf '  FAIL  %-62s\n' "  ...and never reports OK"; fail=$((fail+1)); } \
  || printf '  ok    %-62s\n' "  ...and never reports OK"
o=$(seqrun "$FGOOD" "reject ok"); rc=$?
check "a rejection fails at once" 1 "rejected" $rc "$o"
n=$((n+1)); [[ $(calls) -eq 1 ]] && printf '  ok    %-62s\n' "  ...and is never retried" \
  || { printf '  FAIL  %-62s calls=%s\n' "  ...and is never retried" "$(calls)"; fail=$((fail+1)); }
n=$((n+1)); grep -q "UNAVAILABLE" <<<"$o" && { printf '  FAIL  %-62s\n' "  ...nor reported as unavailable"; fail=$((fail+1)); } \
  || printf '  ok    %-62s\n' "  ...nor reported as unavailable"
o=$(seqrun "$FGOOD" "503 reject ok"); rc=$?
check "a rejection after a 503 is still a rejection" 1 "rejected" $rc "$o"
n=$((n+1)); [[ $(calls) -eq 2 ]] && printf '  ok    %-62s\n' "  ...with no further retry" \
  || { printf '  FAIL  %-62s calls=%s\n' "  ...with no further retry" "$(calls)"; fail=$((fail+1)); }
o=$(seqrun "$FGOOD" "429 ok"); rc=$?
check "429 rate limit, then an answer: verified" 0 "ATTESTATION OK" $rc "$o"
o=$(seqrun "$FGOOD" "timeout ok"); rc=$?
check "network timeout, then an answer: verified" 0 "ATTESTATION OK" $rc "$o"
o=$(seqrun "$(fresult "$OID" "$OID" refs/heads/main "$U" "$AHEX" "$U" .github/workflows/release-image.yml refs/heads/main "$COMMIT")" "503 ok"); rc=$?
check "a retried answer is re-checked like any other (foreign signer)" 1 "does not match the release policy" $rc "$o"
o=$(DELAYS="0" seqrun "$FGOOD" "503 503 ok"); rc=$?
check "one retry configured: two 503s are unavailable" 3 "after 2 attempts" $rc "$o"
o=$(DELAYS="5 x" seqrun "$FGOOD" "ok"); rc=$?
check "a malformed retry delay is a usage error" 2 "usage" $rc "$o"

echo "wiring: the release workflow and verify-image.sh use this policy"
WF="$HERE/../../.github/workflows/release-image.yml"
VI="$HERE/verify-image.sh"
wire() {  # name, condition-exit-status
  n=$((n+1))
  if [[ $2 -eq 0 ]]; then printf '  ok    %-62s\n' "$1"; else printf '  FAIL  %-62s\n' "$1"; fail=$((fail+1)); fi
}
attest_line=$(grep -n 'uses: actions/attest-build-provenance@' "$WF" | head -1 | cut -d: -f1)
verify_line=$(grep -n -- '--require-github-attestation' "$WF" | head -1 | cut -d: -f1)
[[ -n $attest_line && -n $verify_line && $verify_line -gt $attest_line ]]; wire "release-image.yml verifies the attestation after creating it" $?
sed -n "$((verify_line-1)),${verify_line}p" "$WF" | grep -q -- '--digest "$DIGEST"'; wire "  ...on the pushed digest read back from the build" $?
! grep -qE -- '--require-github-attestation +["$]' "$WF"; wire "  ...with no caller-supplied repository, workflow or ref" $?
grep -q 'verify-attestation.sh" "$IMAGE" "$DIGEST"' "$VI"; wire "verify-image.sh hands the digest, never the tag, to the policy" $?
! grep -qE 'gh attestation verify' "$VI"; wire "verify-image.sh has no second, weaker gh attestation call" $?

echo
if [[ $fail -eq 0 ]]; then echo "ATTESTATION POLICY BATTERY OK: $n cases"; exit 0; fi
echo "ATTESTATION POLICY BATTERY FAILED: $fail of $n"; exit 1
