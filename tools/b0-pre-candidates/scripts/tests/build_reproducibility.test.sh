#!/usr/bin/env bash
# Defect 1: two clean --no-cache builds must be byte/content-address identical. The
# EMPIRICAL two-build equality runs on the venue (and locally via
# oci_daemon_bridge.test.sh tier C). This test asserts the SOURCE-LEVEL determinism
# controls are present and the equality gate is NOT weakened:
#  - build_container.sh derives SOURCE_DATE_EPOCH from the ratified commit's committer
#    date and passes it + the exporter's rewrite-timestamp=true;
#  - the manifest-identity equality gate (m1==m2) is unchanged and still fatal;
#  - both Dockerfiles declare SOURCE_DATE_EPOCH and drop build-time-content (logs/caches)
#    IN-LAYER (so content, not just mtimes, is deterministic).
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
SCRIPTS="$(cd "$HERE/.." && pwd)"
CONTAINERS="$(cd "$SCRIPTS/../containers" && pwd)"
set +e
fails=0
ok()  { printf 'ok    %s\n' "$1"; }
bad() { printf 'FAIL  %s\n' "$1" >&2; fails=$((fails + 1)); }
has() { grep -qF -- "$2" "$1"; }

BC="$SCRIPTS/build_container.sh"
# Deterministic epoch derived from the exact ratified commit (not wall clock, not a
# floating HEAD). The detailed epoch-validation checks are in the item-2 section below.
has "$BC" 'SOURCE_DATE_EPOCH="$(git -C "$ROOT" show -s --format=%ct "$source_commit")"' \
  && ok "SOURCE_DATE_EPOCH derived from the ratified commit's committer date" \
  || bad "SOURCE_DATE_EPOCH not derived from the ratified commit"
has "$BC" '--build-arg "SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH"' \
  && ok "SOURCE_DATE_EPOCH passed to the build" || bad "SOURCE_DATE_EPOCH not passed to the build"
has "$BC" 'type=oci,dest=$tar,rewrite-timestamp=true' \
  && ok "OCI exporter uses rewrite-timestamp=true (normalizes layer file mtimes)" \
  || bad "OCI exporter does not use rewrite-timestamp=true"
# The equality gate must remain the strong manifest-identity check (not weakened to a tar
# hash, not normalized away).
has "$BC" '[ "$m1" = "$m2" ] || die "two clean builds diverge in OCI manifest identity' \
  && ok "manifest-identity equality gate unchanged (m1==m2 still fatal)" \
  || bad "manifest-identity equality gate was weakened/removed"
grep -qF 'not a tar hash' "$SCRIPTS/../../b0-pre-validator/src/venue/oci_layout.rs" \
  && ok "identity remains the parsed manifest content address, not a tar hash" \
  || bad "manifest-identity provenance note missing"

for df in sp1 risc0; do
  DF="$CONTAINERS/$df.Dockerfile"
  has "$DF" 'ARG SOURCE_DATE_EPOCH' \
    && ok "$df.Dockerfile declares SOURCE_DATE_EPOCH" || bad "$df.Dockerfile missing ARG SOURCE_DATE_EPOCH"
  # in-layer content normalization: EXPLICIT timestamped logs removed in the apt RUN
  # (narrow paths, not a broad /var/log/* — the dpkg DB, package contents, trust roots,
  # ld.so.cache and toolchain are kept).
  { has "$DF" '/var/log/dpkg.log' && has "$DF" '/var/log/apt' && has "$DF" '/var/log/alternatives.log'; } \
    && ok "$df.Dockerfile drops explicit timestamped logs in-layer (content determinism)" \
    || bad "$df.Dockerfile does not drop the explicit timestamped logs in-layer"
  # Must NOT nuke the package database or a broad /var/log/* (cleanup-scope safety).
  grep -qF '/var/log/*' "$DF" && bad "$df.Dockerfile still uses a broad /var/log/* removal" \
    || ok "$df.Dockerfile avoids broad /var/log/* removal"
  grep -qE 'rm[^\n]*(/var/lib/dpkg/status([^-]|$)|/var/lib/dpkg/info)' "$DF" \
    && bad "$df.Dockerfile removes package database state" \
    || ok "$df.Dockerfile keeps the dpkg package database"
  has "$DF" '/root/.rustup/downloads' \
    && ok "$df.Dockerfile drops rustup download scratch in-layer" \
    || bad "$df.Dockerfile does not drop rustup download scratch"
  # ldconfig aux-cache (authoritative x86 r2): the ONE remaining nondeterministic file.
  # Gather the deletion tokens (the rm -rf ... continuation block) and assert it removes
  # EXACTLY /var/cache/ldconfig/aux-cache, uses no broad wildcard, and never deletes the
  # runtime linker cache /etc/ld.so.cache.
  del_tokens="$(awk '/rm -rf/{c=1} c{print} c&&!/\\$/{c=0}' "$DF")"
  grep -qF '/var/cache/ldconfig/aux-cache' <<<"$del_tokens" \
    && ok "$df.Dockerfile removes exactly /var/cache/ldconfig/aux-cache" \
    || bad "$df.Dockerfile does not remove /var/cache/ldconfig/aux-cache"
  grep -qF '/var/cache/ldconfig/*' "$DF" \
    && bad "$df.Dockerfile uses a broad /var/cache/ldconfig/* wildcard removal" \
    || ok "$df.Dockerfile avoids a broad /var/cache/ldconfig wildcard"
  grep -qF '/etc/ld.so.cache' <<<"$del_tokens" \
    && bad "$df.Dockerfile deletes the runtime linker cache /etc/ld.so.cache" \
    || ok "$df.Dockerfile keeps the runtime linker cache /etc/ld.so.cache"
done

# --- SOURCE_DATE_EPOCH input validation (item 2) ---
# behavioural (via lib.sh): non-empty base-10 integer, positive, no overflow.
# shellcheck source=../lib.sh
. "$SCRIPTS/lib.sh"; set +e
( require_valid_source_date_epoch 1700000000 ) >/dev/null 2>&1 && ok "epoch: valid integer accepted" || bad "epoch: valid integer rejected"
( require_valid_source_date_epoch "" ) >/dev/null 2>&1 && bad "epoch: empty accepted" || ok "epoch: empty rejected"
( require_valid_source_date_epoch abc ) >/dev/null 2>&1 && bad "epoch: non-numeric accepted" || ok "epoch: non-numeric rejected"
( require_valid_source_date_epoch -5 ) >/dev/null 2>&1 && bad "epoch: negative accepted" || ok "epoch: negative rejected"
( require_valid_source_date_epoch 12345678901234567890 ) >/dev/null 2>&1 && bad "epoch: 20-digit overflow accepted" || ok "epoch: overflow rejected"
# source-level: derived from the EXACT ratified commit, proven == RATIFIED, validated pre-Docker.
has "$BC" 'SOURCE_DATE_EPOCH="$(git -C "$ROOT" show -s --format=%ct "$source_commit")"' \
  && ok "epoch derived from the exact ratified commit (not a floating HEAD)" || bad "epoch not derived from the explicit ratified commit"
has "$BC" 'require_valid_source_date_epoch "$SOURCE_DATE_EPOCH"' \
  && ok "epoch validated before Docker" || bad "epoch not validated before Docker"
has "$BC" '[ "$source_commit" = "$RATIFIED_SOURCE_COMMIT" ]' \
  && ok "epoch source proven == RATIFIED_SOURCE_COMMIT" || bad "epoch source not proven == RATIFIED_SOURCE_COMMIT"
n_assign="$(grep -cF 'SOURCE_DATE_EPOCH="$(git -C "$ROOT" show' "$BC")"
[ "$n_assign" = "1" ] && ok "SOURCE_DATE_EPOCH computed exactly once (same value for both clean builds)" || bad "SOURCE_DATE_EPOCH computed $n_assign times (must be 1)"

# --- ldconfig aux-cache empirical validation (opt-in Docker; authoritative x86 r2) ---
# Build an apt image that CREATES /var/cache/ldconfig/aux-cache (ldconfig runs during the
# apt install) and applies the EXACT reproducibility cleanup, twice under SOURCE_DATE_EPOCH
# + rewrite-timestamp. The two clean builds must be manifest-identical (aux-cache was the
# single differing file at x86 r2). In-build gating checks prove aux-cache is gone while the
# runtime linker cache + dpkg DB are kept and programs/libs resolve; runtime checks prove
# ldconfig can recreate aux-cache in a container without changing the committed image.
if [ "${B0PRE_DOCKER_IT:-0}" = "1" ] && command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
  TMPD="${TMPDIR:-/tmp}"; VAL="$SCRIPTS/../../b0-pre-validator/Cargo.toml"
  arch="$(uname -m | sed 's/aarch64/arm64/;s/x86_64/amd64/')"
  vvm() { cargo run --quiet --locked --manifest-path "$VAL" --bin venue-verify -- oci-manifest "$1" "$arch" | python3 -c 'import json,sys;print(json.load(sys.stdin)["manifest_digest"])'; }
  DD="$TMPD/ldconf.$$"; rm -rf "$DD"; mkdir -p "$DD"
  cat > "$DD/Dockerfile" <<'DF'
# syntax=docker/dockerfile:1
ARG SOURCE_DATE_EPOCH
FROM debian:bookworm-slim
RUN set -eux; apt-get update; \
    apt-get install -y --no-install-recommends ca-certificates curl; \
    rm -rf /var/lib/apt/lists/* \
           /var/log/apt /var/log/dpkg.log /var/log/alternatives.log /var/log/bootstrap.log \
           /var/cache/ldconfig/aux-cache
# In-build gating checks (NO ldconfig here — running it would recreate aux-cache in-layer).
RUN set -eux; \
    test ! -e /var/cache/ldconfig/aux-cache; \
    test -e /etc/ld.so.cache; \
    test -f /var/lib/dpkg/status; \
    dpkg -l ca-certificates | grep -q '^ii'; \
    ldd "$(command -v curl)" >/dev/null; \
    curl --version >/dev/null; \
    echo AUX-INBUILD-OK
DF
  docker pull debian:bookworm-slim >/dev/null 2>&1 || true
  bargs="--no-cache --build-arg SOURCE_DATE_EPOCH=1700000000 --file $DD/Dockerfile"
  if docker build $bargs --output "type=oci,dest=$DD/a1.tar,rewrite-timestamp=true" "$DD" >"$DD/a1.log" 2>&1 \
     && docker build $bargs --output "type=oci,dest=$DD/a2.tar,rewrite-timestamp=true" "$DD" >"$DD/a2.log" 2>&1; then
    mkdir -p "$DD/l1" "$DD/l2"; tar -xf "$DD/a1.tar" -C "$DD/l1"; tar -xf "$DD/a2.tar" -C "$DD/l2"
    am1="$(vvm "$DD/l1")"; am2="$(vvm "$DD/l2")"
    { [ -n "$am1" ] && [ "$am1" = "$am2" ]; } \
      && ok "(docker) aux-cache-removed apt image: two clean builds manifest-identical ($am1)" \
      || bad "(docker) aux-cache-removed apt image builds diverge: $am1 != $am2"
    lo="$(docker load --input "$DD/a1.tar" 2>&1)"; lid="$(printf '%s\n' "$lo" | grep -oE 'sha256:[0-9a-f]{64}' | head -n1)"
    if [ -n "$lid" ]; then
      docker run --rm --pull never "$lid" test ! -e /var/cache/ldconfig/aux-cache >/dev/null 2>&1 \
        && ok "(docker) committed image has NO aux-cache at runtime" || bad "(docker) committed image still carries aux-cache"
      docker run --rm --pull never "$lid" sh -c 'ldconfig && test -e /var/cache/ldconfig/aux-cache' >/dev/null 2>&1 \
        && ok "(docker) ldconfig recreates aux-cache inside a container" || bad "(docker) ldconfig could not recreate aux-cache in a container"
      docker run --rm --pull never "$lid" test ! -e /var/cache/ldconfig/aux-cache >/dev/null 2>&1 \
        && ok "(docker) committed image unchanged after container-side ldconfig (aux-cache not required at runtime)" || bad "(docker) committed image changed by container-side ldconfig"
      docker run --rm --pull never "$lid" sh -c 'ldd "$(command -v curl)" >/dev/null && curl --version >/dev/null' >/dev/null 2>&1 \
        && ok "(docker) shared libs resolve + program runs WITHOUT aux-cache" || bad "(docker) program/ldd failed without aux-cache"
      docker rmi "$lid" >/dev/null 2>&1 || true
    else bad "(docker) could not load the aux-cache-removed image: $lo"; fi
  else
    bad "(docker) aux-cache repro build failed: $(tail -n2 "$DD/a1.log" 2>/dev/null)"
  fi
  rm -rf "$DD"
  # Full health image (apt + rustup + the new cleanup): ldd resolves cargo/rustc after the fix.
  HD="$TMPD/ldconf-rust.$$"; rm -rf "$HD"; mkdir -p "$HD"
  cat > "$HD/Dockerfile" <<'DF'
# syntax=docker/dockerfile:1
FROM debian:bookworm-slim
RUN set -eux; apt-get update; \
    apt-get install -y --no-install-recommends ca-certificates curl build-essential pkg-config libssl-dev git; \
    rm -rf /var/lib/apt/lists/* /var/log/apt /var/log/dpkg.log /var/log/alternatives.log /var/log/bootstrap.log /var/cache/ldconfig/aux-cache
RUN set -eux; curl -fsSL https://sh.rustup.rs -o /tmp/r.sh; sh /tmp/r.sh -y --no-modify-path --profile minimal --default-toolchain 1.88.0; \
    rm -rf /tmp/r.sh /root/.rustup/downloads /root/.rustup/tmp
ENV PATH="/root/.cargo/bin:${PATH}"
RUN set -eux; \
    test ! -e /var/cache/ldconfig/aux-cache; test -e /etc/ld.so.cache; \
    rustc --version | grep -q '1[.]88[.]0'; cargo --version; \
    ldd "$(command -v cargo)" >/dev/null; ldd "$(command -v rustc)" >/dev/null; \
    echo AUX-RUST-HEALTH-OK
DF
  if docker build --no-cache -t b0pre-auxrust "$HD" >"$HD/b.log" 2>&1; then
    ok "(docker) rust health image: ldd resolves cargo+rustc, aux-cache absent, ld.so.cache present after the fix"
    docker rmi b0pre-auxrust >/dev/null 2>&1 || true
  else
    bad "(docker) rust health build failed: $(tail -n3 "$HD/b.log" 2>/dev/null)"
  fi
  rm -rf "$HD"
else
  echo "SKIP (docker): aux-cache empirical validation gated behind B0PRE_DOCKER_IT=1 + reachable daemon"
fi

echo "----"
if [ "$fails" -eq 0 ]; then echo "build_reproducibility: ALL SOURCE-LEVEL CHECKS PASS (empirical two-build equality: venue / tier C)"; exit 0
else echo "build_reproducibility: $fails FAILURE(S)" >&2; exit 1; fi
