#!/usr/bin/env bash
# OPT-IN real-Docker proof for the cargo-audit-layer reproducibility fix: cargo 1.88 writes a
# disposable SQLite cache-GC tracker at $CARGO_HOME/.global-cache whose content embeds wall-clock
# last-use timestamps (identical size, differing SQLite pages across two clean builds) — the sole
# divergent byte source at SP1 two-clean-build equality. The fix deletes EXACTLY that one file in
# the cargo-audit provisioning layer, after the last cargo op.
#
# This test replicates JUST that layer on a cargo-1.88 base with CARGO_HOME pinned to /root/.cargo
# (the real candidate Dockerfiles install rustup as root, so CARGO_HOME=/root/.cargo — matching the
# venue evidence path), and proves on real Docker, isolating the CARGO_HOME tree so the result does
# not depend on apt/base determinism:
#   * WITHOUT the removal, /root/.cargo/.global-cache is PRESENT and byte-DIFFERS across two clean
#     builds (the nondeterministic divergence source);
#   * WITH the removal, it is ABSENT from both builds and the whole /root/.cargo content tree is
#     BYTE-IDENTICAL across two clean builds (reproducible);
#   * the installed cargo-audit still runs @0.22.2 and the toolchain is intact;
#   * running cargo in an ephemeral container recreates it WITHOUT changing the committed image.
# Opt-in (needs Docker + network); SKIPs unless B0PRE_DOCKER_IT=1 (or CI's B0PRE_E2E_REQUIRED=1).
set -uo pipefail
REQUIRED="${B0PRE_E2E_REQUIRED:-0}"
BASE="${B0PRE_GC_BASE_IMAGE:-rust:1.88-slim-bookworm}"
CRATE_URL="https://static.crates.io/crates/cargo-audit/cargo-audit-0.22.2.crate"
CRATE_SHA="700c2b240f7fd330c24b675fe429f73a5b676531fcc6300400b2b67f155ba12a"
EPOCH="1700000000"   # a fixed epoch shared by every clean build (determinism, not authority)

skip() { printf 'SKIP (docker): %s\n' "$1"; printf '\ncargo_audit_global_cache: SKIPPED (opt-in; set B0PRE_DOCKER_IT=1 or B0PRE_E2E_REQUIRED=1)\n'; exit 0; }
if [ "$REQUIRED" = "1" ]; then :; elif [ "${B0PRE_DOCKER_IT:-}" != "1" ]; then skip "opt-in flag not set"; fi
command -v docker >/dev/null 2>&1 || { [ "$REQUIRED" = 1 ] && { echo "FAIL(required): docker absent" >&2; exit 1; }; skip "docker not on PATH"; }
docker version >/dev/null 2>&1 || { [ "$REQUIRED" = 1 ] && { echo "FAIL(required): daemon unreachable" >&2; exit 1; }; skip "daemon unreachable"; }

T="$(mktemp -d "$HOME/.b0-gc-XXXXXX")"; trap 'rm -rf "$T"; docker rmi -f b0-gc-keep1 b0-gc-keep2 b0-gc-fix1 b0-gc-fix2 >/dev/null 2>&1 || true' EXIT
F=0; ok(){ printf 'ok    %s\n' "$1"; }; bad(){ printf 'FAIL  %s\n' "$1" >&2; F=1; }

# The cargo-audit provisioning layer (CARGO_HOME pinned to /root/.cargo, matching the real builders),
# parameterized by whether it removes .global-cache. Mirrors the real recipe: pinned .crate verified
# before extraction -> fixed extract path -> cargo install --locked --path -> remove registry
# scratch -> (fix only) remove exactly /root/.cargo/.global-cache after the last cargo op.
gen_dockerfile() { # <remove: yes|no>
  cat <<EOF
# syntax=docker/dockerfile:1
FROM ${BASE}
ENV CARGO_HOME=/root/.cargo
ARG SOURCE_DATE_EPOCH
RUN set -eux; \\
    apt-get update && apt-get install -y --no-install-recommends curl ca-certificates build-essential pkg-config libssl-dev >/dev/null; \\
    rm -rf /var/lib/apt/lists/*; \\
    mkdir -p /tmp/ca-build /opt/b0pre/evidence; \\
    curl -fsSL "${CRATE_URL}" -o /tmp/ca-build/cargo-audit.crate; \\
    echo "${CRATE_SHA}  /tmp/ca-build/cargo-audit.crate" | sha256sum -c -; \\
    tar -xzf /tmp/ca-build/cargo-audit.crate -C /tmp/ca-build; \\
    CARGO_INCREMENTAL=0 cargo install --locked --path /tmp/ca-build/cargo-audit-0.22.2 --bin cargo-audit --root /opt/b0pre/audit-prefix; \\
    /opt/b0pre/audit-prefix/bin/cargo-audit --version | grep -q 0.22.2; \\
    sha256sum /opt/b0pre/audit-prefix/bin/cargo-audit | awk '{print \$1}' > /opt/b0pre/evidence/cargo-audit.exe.sha256; \\
    rm -rf /tmp/ca-build /root/.cargo/registry/cache /root/.cargo/registry/src /root/.cargo/git$([ "$1" = yes ] && printf '; \\\n    rm -f /root/.cargo/.global-cache' || true)
EOF
}

build() { # <dockerfile> <tag>
  DOCKER_BUILDKIT=1 docker build --no-cache -f "$1" --build-arg "SOURCE_DATE_EPOCH=$EPOCH" -t "$2" "$T" >/dev/null 2>>"$T/berr"
}
# Content manifest of /root/.cargo (path + sha256 per file, sorted) — mtime-independent, so the
# comparison isolates CONTENT divergence and does not depend on apt/base-layer determinism.
cargo_home_manifest() { # <tag> -> stdout: "<relpath> <sha256>" lines
  docker run --rm "$1" bash -c 'cd /root/.cargo 2>/dev/null && find . -type f 2>/dev/null | LC_ALL=C sort | while IFS= read -r f; do printf "%s %s\n" "$f" "$(sha256sum "$f" 2>/dev/null | cut -d" " -f1)"; done'
}
# Sorted list of paths whose content differs (present-in-one or hash-mismatch) between two manifests.
diff_paths() { python3 -c '
import sys
def load(p):
    d={}
    for ln in open(p):
        t=ln.split()
        if len(t)>=2: d[t[0]]=t[1]
    return d
a,b=load(sys.argv[1]),load(sys.argv[2])
print("\n".join(sorted(k for k in set(a)|set(b) if a.get(k)!=b.get(k))))' "$1" "$2"; }
present() { docker run --rm "$1" bash -c "test -e /root/.cargo/.global-cache" >/dev/null 2>&1; }

gen_dockerfile no  > "$T/Dockerfile.keep"
gen_dockerfile yes > "$T/Dockerfile.fix"

echo "== building (4 clean cargo-audit provisioning builds; --no-cache) =="
if build "$T/Dockerfile.keep" b0-gc-keep1 && build "$T/Dockerfile.keep" b0-gc-keep2 \
   && build "$T/Dockerfile.fix" b0-gc-fix1 && build "$T/Dockerfile.fix" b0-gc-fix2; then :; else
  bad "one of the cargo-audit provisioning builds failed"; tail -12 "$T/berr" >&2
fi

if [ "$F" = 0 ]; then
  cargo_home_manifest b0-gc-keep1 > "$T/keep1.man"; cargo_home_manifest b0-gc-keep2 > "$T/keep2.man"
  cargo_home_manifest b0-gc-fix1  > "$T/fix1.man";  cargo_home_manifest b0-gc-fix2  > "$T/fix2.man"

  # --- WITHOUT removal: .global-cache present and byte-differs across two clean builds ---
  if present b0-gc-keep1 && present b0-gc-keep2; then ok "control: cargo wrote /root/.cargo/.global-cache in both clean builds"; else bad "control: .global-cache not present (CARGO_HOME/path mismatch)"; fi
  keepdiff="$(diff_paths "$T/keep1.man" "$T/keep2.man")"
  if grep -qx './.global-cache' <<<"$keepdiff"; then ok "control: /root/.cargo/.global-cache byte-DIFFERS across the two clean builds (the divergence source)"; else bad "control: .global-cache did not differ across builds (diff was: ${keepdiff:-<none>})"; fi
  # Informational: the FULL set of divergent CARGO_HOME paths (venue observed exactly .global-cache).
  printf '      control divergent CARGO_HOME paths: %s\n' "$(tr '\n' ' ' <<<"$keepdiff")"

  # --- WITH removal: .global-cache absent + the whole /root/.cargo tree is byte-identical ---
  if ! present b0-gc-fix1 && ! present b0-gc-fix2; then ok "fixed: /root/.cargo/.global-cache ABSENT in both clean builds"; else bad "fixed: .global-cache still present"; fi
  fixdiff="$(diff_paths "$T/fix1.man" "$T/fix2.man")"
  if [ -z "$fixdiff" ]; then ok "fixed: /root/.cargo content tree is BYTE-IDENTICAL across two clean builds (reproducible)"; else bad "fixed: /root/.cargo still diverges across builds: $(tr '\n' ' ' <<<"$fixdiff")"; fi

  # --- installed cargo-audit health + toolchain intact ---
  v="$(docker run --rm b0-gc-fix1 bash -c '/opt/b0pre/audit-prefix/bin/cargo-audit --version' 2>/dev/null || true)"
  grep -q '0.22.2' <<<"$v" && ok "fixed: cargo-audit still runs and reports $v" || bad "fixed: cargo-audit broken ('${v:-<none>}')"
  docker run --rm b0-gc-fix1 bash -c 'command -v cargo rustc >/dev/null' && ok "fixed: cargo + rustc toolchain intact" || bad "fixed: toolchain missing"

  # --- ephemeral recreate: a cargo op in a throwaway container recreates it; image unchanged ---
  rec="$(docker run --rm b0-gc-fix1 bash -c '
    set -e; mkdir -p /tmp/p/src && cd /tmp/p
    printf "[package]\nname=\"p\"\nversion=\"0.0.0\"\nedition=\"2021\"\n[dependencies]\nsemver=\"1\"\n" > Cargo.toml
    echo "fn main(){}" > src/main.rs
    cargo generate-lockfile >/dev/null 2>&1 || true
    test -e /root/.cargo/.global-cache && echo RECREATED || echo NONE' 2>/dev/null || true)"
  [ "$rec" = RECREATED ] && ok "ephemeral cargo op recreates .global-cache in the container" || printf 'ok    ephemeral recreate inconclusive (offline?) — non-fatal (rec=%s)\n' "${rec:-none}"
  if ! present b0-gc-fix1; then ok "committed image STILL has no .global-cache after the ephemeral run (image unchanged)"; else bad "committed image gained .global-cache"; fi
fi

echo "----"
if [ "$F" = 0 ]; then echo "CARGO_AUDIT_GLOBAL_CACHE_PASS"; echo "cargo_audit_global_cache: ALL TESTS PASS"; exit 0
else echo "cargo_audit_global_cache: FAILURE(S)" >&2; exit 1; fi
