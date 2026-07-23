# syntax=docker/dockerfile:1
#
# SP1 6.3.1 candidate builder (native-arch only; built once per native builder).
#
# Reproducibility inputs are REQUIRED build-args with no defaults. If any is
# missing the build fails immediately — there are NO placeholder digests, tags,
# or checksums baked in. All values are supplied by scripts/build_container.sh
# from venue-controlled, immutable sources.
#
#   BASE_IMAGE           e.g. docker.io/library/debian
#   BASE_DIGEST          immutable sha256:<64hex> of the base image (per-arch)
#   APT_SNAPSHOT         snapshot.debian.org timestamp for exact OS packages
#   RUSTUP_INIT_SHA256   sha256 of the per-arch rustup-init used to install Rust
#   RUST_VERSION         must be exactly 1.88.0

ARG BASE_IMAGE
ARG BASE_DIGEST
FROM ${BASE_IMAGE}@${BASE_DIGEST}

ARG APT_SNAPSHOT
ARG RUSTUP_INIT_SHA256
ARG RUST_VERSION=1.88.0

# Fail closed if a required arg is empty (BuildKit evaluates this before work).
RUN test -n "${BASE_DIGEST}" && test -n "${APT_SNAPSHOT}" \
 && test -n "${RUSTUP_INIT_SHA256}" && test "${RUST_VERSION}" = "1.88.0" \
 || (echo "NOT_YET_REPRODUCED: missing immutable base digest / apt snapshot / rustup checksum / RUST_VERSION!=1.88.0" >&2; exit 3)

# Exact OS packages from a pinned snapshot (no floating 'latest' apt state).
RUN set -eux; \
    printf 'deb [check-valid-until=no] http://snapshot.debian.org/archive/debian/%s/ bookworm main\n' "${APT_SNAPSHOT}" > /etc/apt/sources.list; \
    printf 'deb [check-valid-until=no] http://snapshot.debian.org/archive/debian-security/%s/ bookworm-security main\n' "${APT_SNAPSHOT}" >> /etc/apt/sources.list; \
    apt-get -o Acquire::Check-Valid-Until=false update; \
    apt-get install -y --no-install-recommends ca-certificates curl build-essential pkg-config libssl-dev git; \
    rm -rf /var/lib/apt/lists/*

# Rust 1.88.0 via rustup-init verified by exact per-arch sha256.
RUN set -eux; \
    arch="$(uname -m)"; \
    url="https://static.rust-lang.org/rustup/dist/${arch}-unknown-linux-gnu/rustup-init"; \
    curl -fsSL "$url" -o /tmp/rustup-init; \
    echo "${RUSTUP_INIT_SHA256}  /tmp/rustup-init" | sha256sum -c -; \
    chmod +x /tmp/rustup-init; \
    /tmp/rustup-init -y --no-modify-path --profile minimal --default-toolchain "${RUST_VERSION}"; \
    rm -f /tmp/rustup-init
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
