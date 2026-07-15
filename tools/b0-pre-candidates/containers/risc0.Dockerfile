# syntax=docker/dockerfile:1
#
# RISC Zero 3.0.5 candidate builder.
#
# NOTE: RISC Zero Groth16 receipt generation and verifier-material extraction
# must run on a NATIVE x86_64 builder. This Dockerfile may also be built on
# native arm64 to record the arm64 builder manifest digest, but the Groth16
# extraction step (run_authoritative.sh) refuses to run under emulation or on
# arm64.
#
# Reproducibility inputs are REQUIRED build-args with no defaults / placeholders:
#   BASE_IMAGE           e.g. docker.io/library/debian
#   BASE_DIGEST          immutable sha256:<64hex> of the base image (per-arch)
#   APT_SNAPSHOT         snapshot.debian.org timestamp for exact OS packages
#   RUSTUP_INIT_SHA256   sha256 of the per-arch rustup-init
#   RUST_VERSION         must be exactly 1.88.0

ARG BASE_IMAGE
ARG BASE_DIGEST
FROM ${BASE_IMAGE}@${BASE_DIGEST}

ARG APT_SNAPSHOT
ARG RUSTUP_INIT_SHA256
ARG RUST_VERSION=1.88.0

RUN test -n "${BASE_DIGEST}" && test -n "${APT_SNAPSHOT}" \
 && test -n "${RUSTUP_INIT_SHA256}" && test "${RUST_VERSION}" = "1.88.0" \
 || (echo "NOT_YET_REPRODUCED: missing immutable base digest / apt snapshot / rustup checksum / RUST_VERSION!=1.88.0" >&2; exit 3)

RUN set -eux; \
    printf 'deb [check-valid-until=no] http://snapshot.debian.org/archive/debian/%s/ bookworm main\n' "${APT_SNAPSHOT}" > /etc/apt/sources.list; \
    printf 'deb [check-valid-until=no] http://snapshot.debian.org/archive/debian-security/%s/ bookworm-security main\n' "${APT_SNAPSHOT}" >> /etc/apt/sources.list; \
    apt-get -o Acquire::Check-Valid-Until=false update; \
    apt-get install -y --no-install-recommends ca-certificates curl build-essential pkg-config libssl-dev git; \
    rm -rf /var/lib/apt/lists/*

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

# The RISC Zero toolchain (rzup / r0vm matching 3.0.5) is installed by the
# authoritative entrypoint from a pinned version; not baked with a floating
# installer here.

WORKDIR /work
COPY candidates/risc0 /work/candidates/risc0
RUN test ! -f /work/candidates/risc0/Cargo.lock \
 || (echo "REFUSED: host-supplied candidates/risc0/Cargo.lock is not allowed" >&2; exit 2)
