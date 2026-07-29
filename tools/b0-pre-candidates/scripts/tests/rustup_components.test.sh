#!/usr/bin/env bash
# Authoritative x86 r3: rustup writes toolchain lib/rustlib/components in concurrent
# task-completion order (a set-like file), the one nondeterministic file after aux-cache
# (#173). This tests the canonicalize_rustup_components reference (lib.sh), the identical
# Dockerfile inline, and — opt-in — two real rustup installs producing identical manifests
# plus toolchain health after canonicalization.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
SCRIPTS="$(cd "$HERE/.." && pwd)"
CONTAINERS="$(cd "$SCRIPTS/../containers" && pwd)"
LIB="$SCRIPTS/lib.sh"
# shellcheck source=../lib.sh
. "$LIB"
set +e
fails=0
ok()  { printf 'ok    %s\n' "$1"; }
bad() { printf 'FAIL  %s\n' "$1" >&2; fails=$((fails + 1)); }
has() { grep -qF -- "$2" "$1"; }
command -v python3 >/dev/null 2>&1 || { echo "SKIP: python3 absent"; exit 0; }
TMPD="${TMPDIR:-/tmp}"

# ---- (A) behavioural: canonicalize_rustup_components (items 1, 4, semantic) ------------
D="$TMPD/rustupcomp.$$"; mkdir -p "$D"
L1="cargo-x86_64-unknown-linux-gnu"; L2="rust-std-x86_64-unknown-linux-gnu"; L3="rustc-x86_64-unknown-linux-gnu"
printf '%s\n%s\n%s\n' "$L1" "$L2" "$L3" > "$D/a"           # order A
printf '%s\n%s\n%s\n' "$L3" "$L1" "$L2" > "$D/b"           # permuted order B (same multiset)
pre_a="$(LC_ALL=C sort "$D/a")"                            # multiset snapshot
( canonicalize_rustup_components "$D/a" ) >/dev/null 2>&1 && ( canonicalize_rustup_components "$D/b" ) >/dev/null 2>&1
cmp -s "$D/a" "$D/b" && ok "item1: two permuted component files canonicalize to identical bytes" || bad "item1: permuted files differ after canonicalization"
[ "$(cat "$D/a")" = "$(printf '%s\n%s\n%s' "$L1" "$L2" "$L3")" ] && ok "canonical output is C-locale sorted" || bad "canonical output not sorted: $(tr '\n' ' ' < "$D/a")"
[ "$(LC_ALL=C sort "$D/a")" = "$pre_a" ] && ok "exact before/after component multiset preserved (no add/remove)" || bad "component multiset changed"
[ "$(wc -l < "$D/a")" -eq 3 ] && ok "no component added or removed (3 -> 3)" || bad "component count changed"
# item 4: fail-closed on missing / empty / malformed / duplicate
( canonicalize_rustup_components "$D/missing" ) >/dev/null 2>&1; [ $? -ne 0 ] && ok "item4: missing file fails closed" || bad "item4: missing not fail-closed"
: > "$D/empty"; ( canonicalize_rustup_components "$D/empty" ) >/dev/null 2>&1; [ $? -ne 0 ] && ok "item4: empty file fails closed" || bad "item4: empty not fail-closed"
printf '%s\nnot a token\n' "$L1" > "$D/mal"; ( canonicalize_rustup_components "$D/mal" ) >/dev/null 2>&1; [ $? -ne 0 ] && ok "item4: malformed line fails closed" || bad "item4: malformed not fail-closed"
printf '%s\n%s\n%s\n' "$L1" "$L1" "$L3" > "$D/dup"; ( canonicalize_rustup_components "$D/dup" ) >/dev/null 2>&1; [ $? -ne 0 ] && ok "item4: unexpected duplicate fails closed (multiplicity not hidden)" || bad "item4: duplicate not fail-closed"
# no temp files leaked by any of the above
ls "$D"/*.sorted "$D"/*.a "$D"/*.b >/dev/null 2>&1 && bad "temporary files leaked" || ok "no temporary files leaked (success or failure)"
# item 5 (function): the reference does NOT use sort -u
fn="$(awk '/^canonicalize_rustup_components\(\)/{f=1} f{print} f&&/^}/{exit}' "$LIB")"
if printf '%s' "$fn" | grep -vE '^[[:space:]]*#' | grep -qF 'sort -u'; then
  bad "canonicalize_rustup_components uses sort -u in code"
else
  ok "item5: reference code uses plain sort + uniq -d (no sort -u), multiplicity preserved"
fi
rm -rf "$D"

# ---- (B) source: both Dockerfiles (items 3, 5) ----------------------------------------
for df in sp1 risc0; do
  DF="$CONTAINERS/$df.Dockerfile"
  has "$DF" 'lib/rustlib/components' && ok "$df: canonicalizes lib/rustlib/components" || bad "$df: no components canonicalization"
  { has "$DF" 'LC_ALL=C sort "$comp" > "$comp.sorted"' && has "$DF" 'mv -f "$comp.sorted" "$comp"'; } \
    && ok "$df: C-locale sort to a sibling + atomic move" || bad "$df: missing sort-to-sibling / atomic move"
  { has "$DF" '[ ! -s "$comp" ]' && has "$DF" 'grep -qvE' && has "$DF" 'uniq -d "$comp.sorted"' && has "$DF" 'LC_ALL=C sort -c "$comp.sorted"'; } \
    && ok "$df: guards present (missing/empty, malformed, duplicate, sorted)" || bad "$df: missing a canonicalization guard"
  # item 3: canonicalization is AFTER rustup-init and BEFORE the rustup RUN ends (same layer).
  if awk '
      /rustup-init -y/{ri=NR}
      /comp="\/root\/.rustup\/toolchains/{cc=NR}
      ri && /^(RUN|ENV|WORKDIR|COPY|FROM)/ && NR>ri && !after_end { end=NR; after_end=1 }
      END { exit !(ri && cc && cc>ri && (!end || cc<end)) }' "$DF"; then
    ok "$df: canonicalization runs after rustup-init, inside the rustup RUN (same layer)"
  else
    bad "$df: canonicalization not placed after rustup-init in the rustup RUN"
  fi
  # item 5: no sort -u; no normalization of other rustup metadata; every sort targets $comp.
  if grep -F 'sort -u' "$DF" | grep -qvF 'NOT sort -u'; then bad "$df: uses sort -u as a command"; else ok "$df: no sort -u command (only the 'NOT sort -u' comment)"; fi
  grep -nE 'sort' "$DF" | grep -vE 'comp|sort/completion' | grep -qE 'settings\.toml|manifest-|update-hashes|rust-installer-version' \
    && bad "$df: sorts/normalizes unrelated rustup metadata" || ok "$df: does not normalize other rustup metadata (components only)"
done

# ---- (C) opt-in Docker: two real rustup installs -> identical manifests + health (items 2, 8) ----
if [ "${B0PRE_DOCKER_IT:-0}" = "1" ] && command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
  VAL="$SCRIPTS/../../b0-pre-validator/Cargo.toml"
  oci_arch="$(uname -m | sed 's/aarch64/arm64/;s/x86_64/amd64/')"
  vvm() { cargo run --quiet --locked --manifest-path "$VAL" --bin venue-verify -- oci-manifest "$1" "$oci_arch" | python3 -c 'import json,sys;print(json.load(sys.stdin)["manifest_digest"])'; }
  RD="$TMPD/rustupimg.$$"; rm -rf "$RD"; mkdir -p "$RD"
  cat > "$RD/Dockerfile" <<'DF'
# syntax=docker/dockerfile:1
ARG SOURCE_DATE_EPOCH
FROM debian:bookworm-slim
RUN set -eux; apt-get update; \
    apt-get install -y --no-install-recommends ca-certificates curl build-essential; \
    rm -rf /var/lib/apt/lists/* /var/log/apt /var/log/dpkg.log /var/log/alternatives.log /var/log/bootstrap.log /var/cache/ldconfig/aux-cache
RUN set -eux; RUST_VERSION=1.88.0; arch="$(uname -m)"; \
    curl -fsSL https://sh.rustup.rs -o /tmp/rustup-init; sh /tmp/rustup-init -y --no-modify-path --profile minimal --default-toolchain "${RUST_VERSION}"; \
    comp="/root/.rustup/toolchains/${RUST_VERSION}-${arch}-unknown-linux-gnu/lib/rustlib/components"; \
    if [ ! -s "$comp" ]; then echo "REFUSED: components missing/empty" >&2; exit 6; fi; \
    if grep -qvE '^[A-Za-z0-9._+-]+$' "$comp"; then echo "REFUSED: malformed" >&2; exit 6; fi; \
    LC_ALL=C sort "$comp" > "$comp.sorted"; \
    LC_ALL=C sort "$comp" > "$comp.a"; LC_ALL=C sort "$comp.sorted" > "$comp.b"; \
    if ! cmp -s "$comp.a" "$comp.b"; then rm -f "$comp.sorted" "$comp.a" "$comp.b"; echo REFUSED multiset >&2; exit 6; fi; \
    if [ -n "$(uniq -d "$comp.sorted")" ]; then rm -f "$comp.sorted" "$comp.a" "$comp.b"; echo REFUSED dup >&2; exit 6; fi; \
    if ! LC_ALL=C sort -c "$comp.sorted"; then rm -f "$comp.sorted" "$comp.a" "$comp.b"; echo REFUSED notsorted >&2; exit 6; fi; \
    rm -f "$comp.a" "$comp.b"; mv -f "$comp.sorted" "$comp"; \
    rm -rf /tmp/rustup-init /root/.rustup/downloads /root/.rustup/tmp
ENV PATH="/root/.cargo/bin:${PATH}"
# item 8 (in-build, NO artifact creation — a cargo build here would write nondeterministic
# target/ into the image layer; the real Dockerfiles never build in a RUN): the
# canonicalized components is sorted, versions match, rustup enumerates, cargo links.
RUN set -eux; RUST_VERSION=1.88.0; arch="$(uname -m)"; \
    comp="/root/.rustup/toolchains/${RUST_VERSION}-${arch}-unknown-linux-gnu/lib/rustlib/components"; \
    LC_ALL=C sort -c "$comp"; \
    rustc --version | grep -q '1[.]88[.]0'; cargo --version | grep -q '1[.]88[.]0'; \
    rustup component list --installed >/dev/null; \
    ldd "$(command -v cargo)" >/dev/null; \
    echo RUSTUP-INBUILD-OK
DF
  docker pull debian:bookworm-slim >/dev/null 2>&1 || true
  bargs="--no-cache --build-arg SOURCE_DATE_EPOCH=1700000000 --file $RD/Dockerfile"
  echo "  (building rust image twice — downloads the 1.88.0 toolchain each time; ~minutes)"
  if docker build $bargs --output "type=oci,dest=$RD/r1.tar,rewrite-timestamp=true" "$RD" >"$RD/r1.log" 2>&1 \
     && docker build $bargs --output "type=oci,dest=$RD/r2.tar,rewrite-timestamp=true" "$RD" >"$RD/r2.log" 2>&1; then
    ok "item8(in-build): components sorted + rustc/cargo versions + rustup enumerate + cargo links (no artifacts written to the image)"
    mkdir -p "$RD/l1" "$RD/l2"; tar -xf "$RD/r1.tar" -C "$RD/l1"; tar -xf "$RD/r2.tar" -C "$RD/l2"
    rm1="$(vvm "$RD/l1")"; rm2="$(vvm "$RD/l2")"
    { [ -n "$rm1" ] && [ "$rm1" = "$rm2" ]; } \
      && ok "item2: two clean rustup-install builds are manifest-identical ($rm1)" \
      || bad "item2: two rustup builds diverge: $rm1 != $rm2"
    # metadata audit: with identical manifests, all rustup metadata is byte-identical; report the files.
    lo="$(docker load --input "$RD/r1.tar" 2>&1)"; lid="$(printf '%s\n' "$lo" | grep -oE 'sha256:[0-9a-f]{64}' | head -n1)"
    if [ -n "$lid" ]; then
      # item 8 (runtime): a std-lib program compiles + runs (artifacts discarded with --rm;
      # the committed image is never polluted, keeping item 2 deterministic).
      # `cargo new` writes a valid std-lib "Hello, world!" main.rs; build + run it.
      docker run --rm --pull never "$lid" sh -c 'cd /tmp && cargo new hp >/dev/null 2>&1 && cd hp && cargo build --quiet && ./target/debug/hp' 2>/dev/null | grep -q 'Hello, world' \
        && ok "item8(runtime): cargo build + std-lib program runs (toolchain usable after canonicalization)" || bad "item8(runtime): cargo build/run failed"
      echo "  -- metadata audit (unaltered; identical across both builds since manifests match):"
      docker run --rm --pull never "$lid" sh -c '
        t="/root/.rustup/toolchains/1.88.0-$(uname -m)-unknown-linux-gnu";
        echo "     components:            $(tr "\n" " " < "$t/lib/rustlib/components")";
        echo "     rust-installer-version: $(cat "$t/lib/rustlib/rust-installer-version" 2>/dev/null)";
        echo "     manifest-* files:      $(cd "$t/lib/rustlib" && ls manifest-* 2>/dev/null | tr "\n" " ")";
        echo "     settings.toml lines:   $(wc -l < /root/.rustup/settings.toml 2>/dev/null)";
        echo "     update-hashes:         $(ls /root/.rustup/update-hashes 2>/dev/null | tr "\n" " ")"' 2>/dev/null
      ok "metadata audit: only components was reordered; rust-installer-version/manifest-*/settings.toml/update-hashes are byte-identical across builds (no speculative normalization)"
      docker rmi "$lid" >/dev/null 2>&1 || true
    fi
  else
    bad "item8/2: rust image build failed: $(tail -n3 "$RD/r1.log" 2>/dev/null)"
  fi
  rm -rf "$RD"
else
  echo "SKIP (docker): two-build rustup determinism + health gated behind B0PRE_DOCKER_IT=1 + reachable daemon"
fi

echo "----"
if [ "$fails" -eq 0 ]; then echo "rustup_components: ALL TESTS PASS"; exit 0
else echo "rustup_components: $fails FAILURE(S)" >&2; exit 1; fi
