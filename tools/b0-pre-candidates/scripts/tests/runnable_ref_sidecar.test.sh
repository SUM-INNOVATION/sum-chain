#!/usr/bin/env bash
# Defect 2 hardening: the work-dir runnable-ref sidecar is persistent retry state and must
# never let a failed/new/prior build reuse a previously loaded image. It binds the EXACT
# source_commit (a docs-only / orchestration-only commit can preserve the image manifest,
# so manifest equality is NOT a proxy for source identity). This tests resolve_runnable_ref
# (lib.sh) — the validator run_authoritative.sh's runnable_ref_of calls — against an
# isolated temp git repo, plus the source-level guarantees in build_container.sh. Field/
# source/stale cases need no daemon; the image-existence cases are opt-in (B0PRE_DOCKER_IT=1).
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
SCRIPTS="$(cd "$HERE/.." && pwd)"
# shellcheck source=../lib.sh
. "$SCRIPTS/lib.sh"
set +e
fails=0
ok()  { printf 'ok    %s\n' "$1"; }
bad() { printf 'FAIL  %s\n' "$1" >&2; fails=$((fails + 1)); }
command -v python3 >/dev/null 2>&1 || { echo "SKIP: python3 absent"; exit 0; }
command -v git >/dev/null 2>&1 || { echo "SKIP: git absent"; exit 0; }

TMPD="${TMPDIR:-/tmp}"; D="$TMPD/rrsidecar.$$"; mkdir -p "$D"
# Isolated single-commit repo -> HEAD is the "current source". RATIFIED_SOURCE_COMMIT=HEAD.
REPO="$(mktemp -d "$TMPD/rrrepo.XXXXXX")"
git -C "$REPO" init -q; git -C "$REPO" config user.email t@example.invalid; git -C "$REPO" config user.name t
: > "$REPO/f"; git -C "$REPO" add f; git -C "$REPO" commit -qm init
HEAD="$(git -C "$REPO" rev-parse HEAD)"          # 40 lowercase hex, the current source
OTHER="$(printf '%s' "$HEAD" | tr '0123456789abcdef' 'fedcba9876543210')"  # a DIFFERENT valid 40-lc-hex commit
export RATIFIED_SOURCE_COMMIT="$HEAD"
h() { python3 -c "print('$1'*64)"; }
CUR="sha256:$(h a)"; CFG="sha256:$(h c)"; IMG="sha256:$(h b)"
mk() { # <file> <schema> <cand> <arch> <source_commit> <manifest> <config> <image>
  python3 -c 'import json,sys
json.dump({"schema":sys.argv[2],"candidate":sys.argv[3],"arch":sys.argv[4],"source_commit":sys.argv[5],
           "manifest_digest":sys.argv[6],"config_digest":sys.argv[7],"runnable_image_id":sys.argv[8]},
          open(sys.argv[1],"w"))' "$@"
}
rc_of() { ( resolve_runnable_ref "$@" ) >/dev/null 2>&1; printf '%s' "$?"; }
S="b0pre-runnable-ref-v1"

# --- existing field / structural fail-closed cases (no daemon) ---
[ "$(rc_of "$D/absent.json" sp1 x86_64 "$CUR" "$REPO")" -ne 0 ] && ok "missing sidecar fails closed" || bad "missing sidecar not fail-closed"
printf 'not json {' > "$D/malformed.json"
[ "$(rc_of "$D/malformed.json" sp1 x86_64 "$CUR" "$REPO")" -ne 0 ] && ok "malformed JSON fails closed" || bad "malformed JSON not fail-closed"
mk "$D/badschema.json" "WRONG-v9" sp1 x86_64 "$HEAD" "$CUR" "$CFG" "$IMG"
[ "$(rc_of "$D/badschema.json" sp1 x86_64 "$CUR" "$REPO")" -ne 0 ] && ok "wrong schema fails closed" || bad "wrong schema not fail-closed"
mk "$D/xcand.json" "$S" risc0 x86_64 "$HEAD" "$CUR" "$CFG" "$IMG"
[ "$(rc_of "$D/xcand.json" sp1 x86_64 "$CUR" "$REPO")" -ne 0 ] && ok "cross-candidate sidecar fails closed" || bad "cross-candidate not fail-closed"
mk "$D/xarch.json" "$S" sp1 aarch64 "$HEAD" "$CUR" "$CFG" "$IMG"
[ "$(rc_of "$D/xarch.json" sp1 x86_64 "$CUR" "$REPO")" -ne 0 ] && ok "cross-architecture sidecar fails closed" || bad "cross-architecture not fail-closed"
mk "$D/baddig.json" "$S" sp1 x86_64 "$HEAD" "not-a-digest" "$CFG" "$IMG"
[ "$(rc_of "$D/baddig.json" sp1 x86_64 "$CUR" "$REPO")" -ne 0 ] && ok "malformed manifest digest fails closed" || bad "malformed digest not fail-closed"

# --- source_commit gate (THE authoritative source-identity check) ---
# same manifest/config/image, DIFFERENT source_commit -> must fail (manifest is NOT a proxy).
mk "$D/diffsrc.json" "$S" sp1 x86_64 "$OTHER" "$CUR" "$CFG" "$IMG"
out="$( ( resolve_runnable_ref "$D/diffsrc.json" sp1 x86_64 "$CUR" "$REPO" ) 2>&1 )"
{ printf '%s' "$out" | grep -qi 'source_commit .* != current HEAD'; } \
  && ok "same manifest+config+image but DIFFERENT source_commit fails closed (source identity, not manifest)" \
  || bad "different source_commit not fail-closed: $out"
# malformed / missing / uppercase / truncated source_commit
mk "$D/src_bad.json" "$S" sp1 x86_64 "not-hex-source" "$CUR" "$CFG" "$IMG"
[ "$(rc_of "$D/src_bad.json" sp1 x86_64 "$CUR" "$REPO")" -ne 0 ] && ok "malformed source_commit fails closed" || bad "malformed source_commit not fail-closed"
mk "$D/src_empty.json" "$S" sp1 x86_64 "" "$CUR" "$CFG" "$IMG"
[ "$(rc_of "$D/src_empty.json" sp1 x86_64 "$CUR" "$REPO")" -ne 0 ] && ok "missing source_commit fails closed" || bad "missing source_commit not fail-closed"
mk "$D/src_upper.json" "$S" sp1 x86_64 "$(printf '%s' "$HEAD" | tr 'a-f' 'A-F')" "$CUR" "$CFG" "$IMG"
[ "$(rc_of "$D/src_upper.json" sp1 x86_64 "$CUR" "$REPO")" -ne 0 ] && ok "uppercase source_commit fails closed" || bad "uppercase source_commit not fail-closed"
mk "$D/src_trunc.json" "$S" sp1 x86_64 "${HEAD:0:20}" "$CUR" "$CFG" "$IMG"
[ "$(rc_of "$D/src_trunc.json" sp1 x86_64 "$CUR" "$REPO")" -ne 0 ] && ok "truncated source_commit fails closed" || bad "truncated source_commit not fail-closed"

# HEAD / RATIFIED_SOURCE_COMMIT disagreement: sidecar source == HEAD, but the env's ratified
# commit is a different one -> must fail on the RATIFIED check.
mk "$D/src_head.json" "$S" sp1 x86_64 "$HEAD" "$CUR" "$CFG" "$IMG"
out="$( ( RATIFIED_SOURCE_COMMIT="$OTHER" resolve_runnable_ref "$D/src_head.json" sp1 x86_64 "$CUR" "$REPO" ) 2>&1 )"
{ printf '%s' "$out" | grep -qi 'RATIFIED_SOURCE_COMMIT'; } \
  && ok "HEAD/RATIFIED_SOURCE_COMMIT disagreement fails closed" \
  || bad "HEAD/RATIFIED disagreement not fail-closed: $out"

# stale MANIFEST (defense in depth): valid source_commit but manifest != current build.
mk "$D/stalemani.json" "$S" sp1 x86_64 "$HEAD" "sha256:$(h d)" "$CFG" "$IMG"
out="$( ( resolve_runnable_ref "$D/stalemani.json" sp1 x86_64 "$CUR" "$REPO" ) 2>&1 )"
{ printf '%s' "$out" | grep -qi 'manifest .* != current verified build'; } \
  && ok "stale manifest (defense in depth) fails closed" || bad "stale manifest not fail-closed: $out"

# --- image-existence cases (opt-in Docker) ---
if [ "${B0PRE_DOCKER_IT:-0}" = "1" ] && command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
  docker pull busybox >/dev/null 2>&1 || true
  real_img="$(docker image inspect busybox --format '{{.Id}}' 2>/dev/null)"
  if [ -n "$real_img" ]; then
    mk "$D/valid.json" "$S" sp1 x86_64 "$HEAD" "$CUR" "$CFG" "$real_img"
    got="$( ( resolve_runnable_ref "$D/valid.json" sp1 x86_64 "$CUR" "$REPO" ) 2>/dev/null )"
    [ "$got" = "$real_img" ] && ok "(docker) valid exact-commit sidecar + loaded image resolves to the id" || bad "(docker) valid sidecar did not resolve (got '$got')"
    mk "$D/gone.json" "$S" sp1 x86_64 "$HEAD" "$CUR" "$CFG" "$IMG"
    ( resolve_runnable_ref "$D/gone.json" sp1 x86_64 "$CUR" "$REPO" ) >/dev/null 2>&1 && bad "(docker) missing image not fail-closed" || ok "(docker) missing image fails closed"
  else
    echo "SKIP (docker image-existence): could not resolve a busybox image id"
  fi
else
  echo "SKIP (docker image-existence cases): B0PRE_DOCKER_IT=1 + reachable daemon required"
fi

# --- build_container.sh source guarantees ---
bc="$(cat "$SCRIPTS/build_container.sh")"
printf '%s' "$bc" | grep -q 'rm -f "\$out/\$candidate.\$arch.runnable-ref" "\$out/\$candidate.\$arch.runnable-ref.tmp"' \
  && ok "build_container.sh invalidates the sidecar BEFORE building (no stale reuse)" \
  || bad "build_container.sh does not invalidate the sidecar before building"
printf '%s' "$bc" | grep -q 'mv -f "\$sidecar.tmp" "\$sidecar"' && printf '%s' "$bc" | grep -q 'b0pre-runnable-ref-v1' \
  && ok "build_container.sh writes the TYPED sidecar atomically (temp + mv) after verification" \
  || bad "build_container.sh does not write the typed sidecar atomically"
printf '%s' "$bc" | grep -q '"source_commit": commit' \
  && ok "build_container.sh records source_commit in the sidecar" || bad "build_container.sh does not record source_commit"
{ printf '%s' "$bc" | grep -q 'is_ratified_commit_format "\$source_commit"' \
  && printf '%s' "$bc" | grep -q '\[ "\$source_commit" = "\$RATIFIED_SOURCE_COMMIT" \]' \
  && printf '%s' "$bc" | grep -q '\[ "\$source_commit" = "\$(git -C "\$ROOT" rev-parse HEAD)" \]'; } \
  && ok "build_container.sh requires source_commit == 40-hex == HEAD == RATIFIED before writing" \
  || bad "build_container.sh does not assert source_commit == HEAD == RATIFIED before writing"
if printf '%s\n' "$bc" | awk '/verify-runtime-image/{v=NR} /mv -f "\$sidecar.tmp"/{m=NR} END{exit !(v&&m&&m>v)}'; then
  ok "atomic sidecar write happens only after the load-correspondence verification"
else
  bad "sidecar write is not gated behind the load-correspondence verification"
fi

rm -rf "$D" "$REPO"
echo "----"
if [ "$fails" -eq 0 ]; then echo "runnable_ref_sidecar: ALL TESTS PASS"; exit 0
else echo "runnable_ref_sidecar: $fails FAILURE(S)" >&2; exit 1; fi
