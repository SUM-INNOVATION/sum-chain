#!/usr/bin/env bash
# Defect 2: the exported OCI layout must be made RUNNABLE via a fail-closed bridge whose
# identity provably corresponds to the verified layout — and downstream stages must run
# inside THAT, never the never-loaded `oci:local/...` placeholder.
#
# Tiers:
#   (A) source wiring (always): build_container.sh loads+verifies; run_authoritative.sh
#       uses runnable_ref_of and no longer references oci:local; --pull never everywhere;
#       no registry push.
#   (B) CLI behaviour (always, no Docker): oci-manifest emits a content-verified
#       config_digest; verify-runtime-image matches equal digests and fails closed on
#       mismatch / synthetic / malformed.
#   (C) full Docker integration (opt-in: B0PRE_DOCKER_IT=1 AND a running daemon): two
#       clean deterministic builds are manifest-identical, the verified layout loads, the
#       loaded image id == the verified config digest, the image executes under
#       --pull never, and a wrong/absent identity fails closed. Never pushes.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
SCRIPTS="$(cd "$HERE/.." && pwd)"
VAL="$SCRIPTS/../../b0-pre-validator/Cargo.toml"
TMPD="${TMPDIR:-/tmp}"
set +e
fails=0
ok()  { printf 'ok    %s\n' "$1"; }
bad() { printf 'FAIL  %s\n' "$1" >&2; fails=$((fails + 1)); }
vv()  { cargo run --quiet --locked --manifest-path "$VAL" --bin venue-verify -- "$@"; }
sha256_hex() { if command -v sha256sum >/dev/null 2>&1; then sha256sum | awk '{print $1}'; else shasum -a 256 | awk '{print $1}'; fi; }

command -v python3 >/dev/null 2>&1 || { echo "SKIP: python3 absent"; exit 0; }

# ---- (A) source wiring ----------------------------------------------------------------
bc="$(cat "$SCRIPTS/build_container.sh")"
ra="$(cat "$SCRIPTS/run_authoritative.sh")"
grep -q 'docker load --input "\$L1"' <<<"$bc" \
  && ok "build_container.sh loads the verified OCI layout into the daemon" \
  || bad "build_container.sh does not load the verified layout"
{ grep -q 'verify-runtime-image' <<<"$bc" \
  && grep -q 'vv_verify "\$builder_digest" "\$loaded_id"' <<<"$bc" \
  && grep -q 'vv_verify "\$config_digest" "\$loaded_id"' <<<"$bc"; } \
  && ok "build_container.sh proves loaded-image == verified manifest OR config digest before use" \
  || bad "build_container.sh does not verify runtime-image correspondence"
grep -q 'runnable-ref' <<<"$bc" \
  && ok "build_container.sh records the verified runnable ref (sidecar)" \
  || bad "build_container.sh does not record a runnable ref"
grep -q 'runnable_ref_of' <<<"$ra" \
  && ok "run_authoritative.sh consumes the verified runnable ref" \
  || bad "run_authoritative.sh does not use runnable_ref_of"
# Only ACTUAL code references count (explanatory comments about the removed placeholder
# are fine); a comment line's first non-blank char is '#'.
ocilocal_code="$(printf '%s\n' "$ra" | grep -E 'oci:local' | grep -vE '^[[:space:]]*#')"
if [ -n "$ocilocal_code" ]; then
  bad "run_authoritative.sh still USES the never-loaded oci:local placeholder: $ocilocal_code"
else
  ok "run_authoritative.sh no longer uses oci:local as an image ref (only explanatory comments remain)"
fi
# --pull never remains on every in-container docker run; no registry push anywhere.
run_lines="$(printf '%s\n' "$ra" | grep -E 'docker run')"
if grep -E 'docker run' <<<"$run_lines" | grep -qv -- '--pull never'; then
  bad "a docker run without --pull never exists"
else
  ok "every docker run keeps --pull never enforced"
fi
# Grep a here-string, not a `printf | grep -q` pipe: the two joined sources exceed the pipe
# buffer, so if a push pattern appeared, grep -q would close early and printf would SIGPIPE under
# `set -o pipefail` — masking the very violation this asserts. The here-string has no such race.
if grep -qE 'docker (push|--push)|--output[^\n]*push=true|type=registry' <<<"$(printf '%s\n%s' "$bc" "$ra")"; then
  bad "a registry push path exists"
else
  ok "no registry push anywhere (build or run)"
fi

# ---- (B) CLI behaviour (no Docker) ----------------------------------------------------
# Hand-build a valid single-amd64 OCI layout on disk; oci-manifest must emit a
# content-verified config_digest equal to the config blob's own address.
LAYOUT="$TMPD/oci-bridge-layout.$$"; rm -rf "$LAYOUT"; mkdir -p "$LAYOUT/blobs/sha256"
printf '{"imageLayoutVersion":"1.0.0"}' > "$LAYOUT/oci-layout"
config='{"architecture":"amd64","os":"linux","rootfs":{"type":"layers","diff_ids":[]}}'
config_hex="$(printf '%s' "$config" | sha256_hex)"
printf '%s' "$config" > "$LAYOUT/blobs/sha256/$config_hex"
manifest="$(printf '{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"sha256:%s","size":%d},"layers":[]}' "$config_hex" "${#config}")"
manifest_hex="$(printf '%s' "$manifest" | sha256_hex)"
printf '%s' "$manifest" > "$LAYOUT/blobs/sha256/$manifest_hex"
printf '{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"sha256:%s","size":%d,"platform":{"architecture":"amd64","os":"linux"}}]}' "$manifest_hex" "${#manifest}" > "$LAYOUT/index.json"

om="$(vv oci-manifest "$LAYOUT" amd64 2>&1)"; om_rc=$?
got_cfg="$(printf '%s' "$om" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("config_digest",""))' 2>/dev/null)"
{ [ "$om_rc" -eq 0 ] && [ "$got_cfg" = "sha256:$config_hex" ]; } \
  && ok "oci-manifest emits the content-verified config_digest (== config blob address)" \
  || bad "oci-manifest config_digest wrong (rc=$om_rc got=$got_cfg want=sha256:$config_hex): $om"

A="sha256:$config_hex"
B="sha256:$(printf 'different' | sha256_hex)"
vv verify-runtime-image "$A" "$A" >/dev/null 2>&1 && ok "verify-runtime-image accepts equal content addresses" || bad "verify-runtime-image rejected equal digests"
vv verify-runtime-image "$A" "$B" >/dev/null 2>&1 && bad "verify-runtime-image accepted a MISMATCH" || ok "verify-runtime-image fails closed on mismatch"
vv verify-runtime-image "$A" "sha256:deadbeef" >/dev/null 2>&1 && bad "verify-runtime-image accepted a truncated digest" || ok "verify-runtime-image fails closed on malformed digest"
vv verify-runtime-image "$A" "sha256:TEST_ONLY_SYNTHETIC" >/dev/null 2>&1 && bad "verify-runtime-image accepted a synthetic digest" || ok "verify-runtime-image fails closed on synthetic digest"
rm -rf "$LAYOUT"

# ---- (C) full Docker integration (opt-in) ---------------------------------------------
if [ "${B0PRE_DOCKER_IT:-0}" != "1" ]; then
  echo "SKIP (C): full Docker integration gated behind B0PRE_DOCKER_IT=1 (needs a running daemon; not run in normal CI)"
elif ! { command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; }; then
  echo "SKIP (C): B0PRE_DOCKER_IT=1 but no reachable Docker daemon"
else
  echo "== (C) Docker integration: deterministic build + load + verify + exec + mutation =="
  D="$TMPD/oci-it.$$"; rm -rf "$D"; mkdir -p "$D"
  # Trivial image validating the BRIDGE + DETERMINISM MECHANICS (not a ratified pin): a
  # single RUN layer whose file mtime + config `created` must normalize to SOURCE_DATE_EPOCH.
  cat > "$D/Dockerfile" <<'DF'
# syntax=docker/dockerfile:1
ARG SOURCE_DATE_EPOCH
FROM busybox
RUN echo b0pre-bridge-it > /marker.txt
DF
  docker pull busybox >/dev/null 2>&1 || true   # cache the base once so both --no-cache builds share it
  epoch=1700000000
  bargs=(--no-cache --build-arg "SOURCE_DATE_EPOCH=$epoch" --file "$D/Dockerfile")
  if docker build "${bargs[@]}" --output "type=oci,dest=$D/b1.tar,rewrite-timestamp=true" "$D" >"$D/b1.log" 2>&1 \
     && docker build "${bargs[@]}" --output "type=oci,dest=$D/b2.tar,rewrite-timestamp=true" "$D" >"$D/b2.log" 2>&1; then
    mkdir -p "$D/l1" "$D/l2"; tar -xf "$D/b1.tar" -C "$D/l1"; tar -xf "$D/b2.tar" -C "$D/l2"
    m1="$(vv oci-manifest "$D/l1" "$(uname -m | sed 's/aarch64/arm64/;s/x86_64/amd64/')" | python3 -c 'import json,sys;print(json.load(sys.stdin)["manifest_digest"])')"
    m2="$(vv oci-manifest "$D/l2" "$(uname -m | sed 's/aarch64/arm64/;s/x86_64/amd64/')" | python3 -c 'import json,sys;print(json.load(sys.stdin)["manifest_digest"])')"
    [ -n "$m1" ] && [ "$m1" = "$m2" ] && ok "(C) two clean deterministic builds are manifest-identical ($m1)" || bad "(C) two clean builds diverged: $m1 != $m2"
    cfg="$(vv oci-manifest "$D/l1" "$(uname -m | sed 's/aarch64/arm64/;s/x86_64/amd64/')" | python3 -c 'import json,sys;print(json.load(sys.stdin)["config_digest"])')"
    lo="$(docker load --input "$D/b1.tar" 2>&1)"; lid="$(printf '%s\n' "$lo" | grep -oE 'sha256:[0-9a-f]{64}' | head -n1)"
    [ -n "$lid" ] && ok "(C) verified layout loaded into daemon (id=$lid)" || bad "(C) docker load produced no image id: $lo"
    if vv verify-runtime-image "$m1" "$lid" >/dev/null 2>&1; then ok "(C) loaded image id == verified MANIFEST digest (containerd store; correspondence proven)"
    elif vv verify-runtime-image "$cfg" "$lid" >/dev/null 2>&1; then ok "(C) loaded image id == verified CONFIG digest (classic store; correspondence proven)"
    else bad "(C) loaded id ($lid) matches neither verified manifest ($m1) nor config ($cfg)"; fi
    out="$(docker run --rm --pull never "$lid" cat /marker.txt 2>&1)"; [ "$out" = "b0pre-bridge-it" ] && ok "(C) verified image executes under --pull never" || bad "(C) verified image did not execute: $out"
    wrong="sha256:$(printf 'wrong' | sha256_hex)"
    vv verify-runtime-image "$wrong" "$lid" >/dev/null 2>&1 && bad "(C) mutation (wrong config) NOT fail-closed" || ok "(C) wrong-identity mutation fails closed"
    docker run --rm --pull never "sha256:$(printf 'absent' | sha256_hex)" true >/dev/null 2>&1 && bad "(C) absent image ran under --pull never" || ok "(C) absent image fails closed under --pull never"
    docker rmi "$lid" >/dev/null 2>&1 || true
  else
    bad "(C) docker build failed: $(tail -n3 "$D/b1.log" 2>/dev/null)"
  fi
  rm -rf "$D"
fi

echo "----"
if [ "$fails" -eq 0 ]; then echo "oci_daemon_bridge: ALL TESTS PASS"; exit 0
else echo "oci_daemon_bridge: $fails FAILURE(S)" >&2; exit 1; fi
