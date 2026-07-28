# syntax=docker/dockerfile:1
#
# SP1 6.3.1 candidate builder (native-arch only; built once per native builder).
#
# Reproducibility inputs are REQUIRED build-args with no defaults. If any is
# missing the build fails immediately — there are NO placeholder digests, tags,
# or checksums baked in. All values are supplied by scripts/build_container.sh
# from venue-controlled, immutable sources.
#
#   BASE_IMAGE                      e.g. docker.io/library/debian
#   BASE_DIGEST                     immutable sha256:<64hex> of the base image (per-arch)
#   APT_DEBIAN_URL                  pinned immutable snapshot base URL (trailing '/')
#   APT_DEBIAN_INRELEASE_SHA256     expected sha256 of that snapshot's bookworm InRelease
#   APT_SECURITY_URL                pinned immutable debian-security snapshot base URL
#   APT_SECURITY_INRELEASE_SHA256   expected sha256 of its bookworm-security InRelease
#   RUSTUP_INIT_URL                 EXACT immutable per-arch rustup archive URL
#   RUSTUP_INIT_SHA256              sha256 of that exact rustup-init artifact
#   RUST_VERSION                    must be exactly 1.88.0

ARG BASE_IMAGE
ARG BASE_DIGEST
FROM ${BASE_IMAGE}@${BASE_DIGEST}

# BASE_IMAGE/BASE_DIGEST are declared BEFORE `FROM`, which makes them global build args
# that fall OUT OF SCOPE inside the build stage. They must be re-declared here or every
# in-stage reference expands to the empty string — which silently defeated the
# fail-closed BASE_DIGEST check below.
ARG BASE_IMAGE
ARG BASE_DIGEST

ARG APT_DEBIAN_URL
ARG APT_DEBIAN_INRELEASE_SHA256
ARG APT_SECURITY_URL
ARG APT_SECURITY_INRELEASE_SHA256
ARG RUSTUP_INIT_URL
ARG RUSTUP_INIT_SHA256
ARG RUST_VERSION=1.88.0
# Defect 1 (reproducibility): SOURCE_DATE_EPOCH is supplied by build_container.sh (the
# ratified commit's committer date). BuildKit uses it to pin the image config `created`
# and per-step history timestamps; the exporter's rewrite-timestamp=true normalizes every
# layer file mtime to it. Declared explicitly so it is a consumed, documented input.
ARG SOURCE_DATE_EPOCH

# Fail closed BEFORE any work. This gate tests the actual VALUES, not merely that the
# args were named: each digest/checksum must have the right shape, so a truncated,
# uppercased, or placeholder value is refused here rather than deep inside a build.
RUN printf '%s' "${BASE_DIGEST}"                  | grep -Eq '^sha256:[0-9a-f]{64}$' \
 && printf '%s' "${APT_DEBIAN_INRELEASE_SHA256}"   | grep -Eq '^[0-9a-f]{64}$' \
 && printf '%s' "${APT_SECURITY_INRELEASE_SHA256}" | grep -Eq '^[0-9a-f]{64}$' \
 && printf '%s' "${RUSTUP_INIT_SHA256}"            | grep -Eq '^[0-9a-f]{64}$' \
 && test -n "${APT_DEBIAN_URL}" && test -n "${APT_SECURITY_URL}" && test -n "${RUSTUP_INIT_URL}" \
 && test "${RUST_VERSION}" = "1.88.0" \
 || (echo "NOT_YET_REPRODUCED: immutable base digest / pinned apt snapshot URLs+InRelease hashes / rustup URL+checksum absent or malformed, or RUST_VERSION!=1.88.0" >&2; exit 3)

# Exact OS packages from the two pinned snapshots, and ONLY from them.
#
# The Debian bookworm base image ships NO /etc/apt/sources.list; it ships deb822
# /etc/apt/sources.list.d/debian.sources pointing at the ROLLING deb.debian.org mirror
# (suites bookworm + bookworm-updates). Writing sources.list alone therefore left the
# rolling mirror active alongside the snapshot, so apt could take a newer package from
# deb.debian.org and silently defeat the pin. Every pre-existing source is removed
# BEFORE the first apt update, and an assertion refuses the build if any rolling
# Debian source survives.
RUN set -eux; \
    rm -f /etc/apt/sources.list.d/*.sources /etc/apt/sources.list.d/*.list; \
    printf 'deb [check-valid-until=no] %s bookworm main\n' "${APT_DEBIAN_URL}" > /etc/apt/sources.list; \
    printf 'deb [check-valid-until=no] %s bookworm-security main\n' "${APT_SECURITY_URL}" >> /etc/apt/sources.list; \
    if grep -RIqsE '(deb|security)\.debian\.org' /etc/apt/sources.list /etc/apt/sources.list.d/; then \
      echo "REFUSED: a rolling Debian apt source is still active after pinning" >&2; exit 4; \
    fi; \
    apt-get -o Acquire::Check-Valid-Until=false update; \
    inrel_deb="$(ls /var/lib/apt/lists/*_dists_bookworm_InRelease)"; \
    inrel_sec="$(ls /var/lib/apt/lists/*_dists_bookworm-security_InRelease)"; \
    echo "${APT_DEBIAN_INRELEASE_SHA256}  ${inrel_deb}"   | sha256sum -c -; \
    echo "${APT_SECURITY_INRELEASE_SHA256}  ${inrel_sec}" | sha256sum -c -; \
    apt-get install -y --no-install-recommends ca-certificates curl build-essential pkg-config libssl-dev git; \
    : "reproducibility: drop ONLY the build-time-content artifacts whose CONTENT embeds \
       wall-clock timestamps — the apt/dpkg/alternatives/bootstrap logs, and ldconfig's \
       DISPOSABLE auxiliary optimization cache /var/cache/ldconfig/aux-cache (created by the \
       apt install above; it records wall-clock timestamps + inode observations that \
       SOURCE_DATE_EPOCH / tar-timestamp rewriting CANNOT normalize — the last remaining \
       nondeterministic file at authoritative x86 r2) — plus the apt package lists. Explicit \
       paths, IN THIS LAYER, after the last apt/package op that creates them. KEPT: the \
       RUNTIME dynamic-linker cache /etc/ld.so.cache, the rest of /var/cache/ldconfig, the \
       dpkg database (/var/lib/dpkg/status), installed package contents, CA trust roots, and \
       the toolchain — all needed by later stages"; \
    rm -rf /var/lib/apt/lists/* \
           /var/log/apt /var/log/dpkg.log /var/log/alternatives.log /var/log/bootstrap.log \
           /var/cache/ldconfig/aux-cache

# Rust 1.88.0 via the EXACT immutable rustup archive artifact the ratified record names.
# The former hard-coded, unversioned rustup distribution path always served the newest
# rustup, so RUSTUP_INIT_SHA256 pinned the bytes of a moving object; that path is
# refused here.
RUN set -eux; \
    arch="$(uname -m)"; \
    case "${RUSTUP_INIT_URL}" in \
      */rustup/dist/*) echo "REFUSED: RUSTUP_INIT_URL uses the mutable unversioned rustup/dist path" >&2; exit 5 ;; \
    esac; \
    case "${RUSTUP_INIT_URL}" in \
      https://static.rust-lang.org/rustup/archive/*/rustup-init) ;; \
      *) echo "REFUSED: RUSTUP_INIT_URL is not an immutable https rustup archive URL: ${RUSTUP_INIT_URL}" >&2; exit 5 ;; \
    esac; \
    case "${RUSTUP_INIT_URL}" in \
      *"/${arch}-unknown-linux-gnu/rustup-init") ;; \
      *) echo "REFUSED: RUSTUP_INIT_URL is not for this builder's architecture ${arch}: ${RUSTUP_INIT_URL}" >&2; exit 5 ;; \
    esac; \
    curl -fsSL "${RUSTUP_INIT_URL}" -o /tmp/rustup-init; \
    echo "${RUSTUP_INIT_SHA256}  /tmp/rustup-init" | sha256sum -c -; \
    chmod +x /tmp/rustup-init; \
    /tmp/rustup-init -y --no-modify-path --profile minimal --default-toolchain "${RUST_VERSION}"; \
    : "reproducibility: remove rustup download/tmp scratch (fetch-order/temp bytes); the \
       installed toolchain itself is content-deterministic"; \
    rm -rf /tmp/rustup-init /root/.rustup/downloads /root/.rustup/tmp
ENV PATH="/root/.cargo/bin:${PATH}"
RUN rustc --version | grep -q "${RUST_VERSION}"

# SP1 toolchain (guest target) is installed by the authoritative entrypoint from
# the pinned cargo-prove/sp1 version matching sp1 6.3.1; not baked with a
# floating installer here.

WORKDIR /work
# CURATED, MINIMAL build context: the docker context is the reproduced repo-relative
# layout that scripts/stage_context.sh stages (NOT the raw source tree), carrying ONLY
# the official guest dependency graph so the path deps + `.workspace` inheritance
# resolve in-container, and NO unrelated production crate (isolation):
#   crates/sumchain-wire                         frozen wire leaf (workspace member)
#   Cargo.toml                                   curated workspace root (only the
#                                                [workspace]/[workspace.package]/
#                                                [workspace.dependencies] sections
#                                                sumchain-wire inherits + that one member)
#   tools/b0-pre-candidates/guest-core           candidate-neutral shared guest core
#   tools/b0-pre-candidates/candidates/sp1       this candidate workspace (host + guest)
#   docs/b0-pre/{fixtures/workload,exp}          frozen guest fixtures
# The candidate lock is then generated HERE from the COMPLETE staged graph (see
# resolve_lock.sh / run_authoritative.sh) and becomes the authoritative source of truth.
# The host must not supply any Cargo.lock (staging strips them; refused again below).
COPY Cargo.toml /work/Cargo.toml
COPY crates /work/crates
COPY docs /work/docs
COPY tools /work/tools
RUN test ! -f /work/tools/b0-pre-candidates/candidates/sp1/Cargo.lock \
 || (echo "REFUSED: host-supplied candidates/sp1/Cargo.lock is not allowed" >&2; exit 2)
