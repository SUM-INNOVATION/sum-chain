# Reproducible BUILD ENVIRONMENT for the native Linux release archives.
#
# Production runs a native binary under systemd, not a container. This file
# is used only to compile that binary in a pinned environment; the only thing
# that leaves it is the `artifacts` stage, which holds nothing but the two
# executables. Build it natively on each platform's runner:
#
#   docker buildx build -f tools/release/native.Dockerfile --target artifacts \
#     --build-arg GIT_HASH="$(git rev-parse HEAD)" --output type=local,dest=out .
#
# (tools/release/build-native.sh does exactly this, with SBOM and provenance.)
#
# Pinned: the Rust image by digest (a multi-platform index: linux/amd64 and
# linux/arm64 resolve their own child from the one pin). rust-toolchain.toml
# is copied in, so rustup builds with the repository's pinned toolchain; it
# names the same 1.88.0 the image carries. Cargo.lock is enforced by --locked.
# Not pinned: the Debian bookworm packages installed below (a build-time
# limitation; glibc and the linked system libraries come from bookworm).
FROM rust:1.88.0-slim-bookworm@sha256:38bc5a86d998772d4aec2348656ed21438d20fcdce2795b56ca434cf21430d89 AS builder

# Include this stage's contents (Cargo.lock, the crates) in the SBOM, not just
# the final two-file stage.
ARG BUILDKIT_SBOM_SCAN_STAGE=true

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential clang libclang-dev pkg-config libssl-dev cmake \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY crates crates
COPY scripts scripts

# The exact commit, embedded at compile time and reported by `sumchain --version`.
ARG GIT_HASH
RUN printf '%s' "${GIT_HASH:-}" | grep -Eqx '[0-9a-f]{40}' \
 || { echo "GIT_HASH must be the full 40-hex commit (got '${GIT_HASH:-}')" >&2; exit 1; } \
 && export GIT_HASH \
 && rustc --version && cargo --version \
 && cargo build --release --locked --bin sumchain --bin sumchain-wallet

FROM scratch AS artifacts
COPY --from=builder /build/target/release/sumchain /build/target/release/sumchain-wallet /
