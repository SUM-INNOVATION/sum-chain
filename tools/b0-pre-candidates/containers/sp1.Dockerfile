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
# The candidate manifests are copied in, then the lock is generated HERE and
# becomes the authoritative source of truth (see run_authoritative.sh). The
# host must not supply a Cargo.lock.
COPY candidates/sp1 /work/candidates/sp1
RUN test ! -f /work/candidates/sp1/Cargo.lock \
 || (echo "REFUSED: host-supplied candidates/sp1/Cargo.lock is not allowed" >&2; exit 2)
