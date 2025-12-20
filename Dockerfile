# SUM Chain Node Dockerfile
# Multi-stage build for minimal production image

# ===========================
# Build Stage
# ===========================
FROM rust:1.75-slim-bookworm AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    clang \
    libclang-dev \
    pkg-config \
    libssl-dev \
    cmake \
    && rm -rf /var/lib/apt/lists/*

# Set up working directory
WORKDIR /build

# Copy manifests first for better caching
COPY Cargo.toml Cargo.lock ./
COPY crates/primitives/Cargo.toml crates/primitives/
COPY crates/crypto/Cargo.toml crates/crypto/
COPY crates/storage/Cargo.toml crates/storage/
COPY crates/genesis/Cargo.toml crates/genesis/
COPY crates/state/Cargo.toml crates/state/
COPY crates/consensus/Cargo.toml crates/consensus/
COPY crates/p2p/Cargo.toml crates/p2p/
COPY crates/rpc/Cargo.toml crates/rpc/
COPY crates/node/Cargo.toml crates/node/
COPY crates/wallet/Cargo.toml crates/wallet/
COPY crates/integration-tests/Cargo.toml crates/integration-tests/
COPY scripts/Cargo.toml scripts/

# Create dummy source files to build dependencies
RUN mkdir -p crates/primitives/src && echo "pub fn dummy() {}" > crates/primitives/src/lib.rs
RUN mkdir -p crates/crypto/src && echo "pub fn dummy() {}" > crates/crypto/src/lib.rs
RUN mkdir -p crates/storage/src && echo "pub fn dummy() {}" > crates/storage/src/lib.rs
RUN mkdir -p crates/genesis/src && echo "pub fn dummy() {}" > crates/genesis/src/lib.rs
RUN mkdir -p crates/state/src && echo "pub fn dummy() {}" > crates/state/src/lib.rs
RUN mkdir -p crates/consensus/src && echo "pub fn dummy() {}" > crates/consensus/src/lib.rs
RUN mkdir -p crates/p2p/src && echo "pub fn dummy() {}" > crates/p2p/src/lib.rs
RUN mkdir -p crates/rpc/src && echo "pub fn dummy() {}" > crates/rpc/src/lib.rs
RUN mkdir -p crates/node/src && echo "fn main() {}" > crates/node/src/main.rs
RUN mkdir -p crates/wallet/src && echo "fn main() {}" > crates/wallet/src/main.rs
RUN mkdir -p crates/integration-tests/src && echo "pub fn dummy() {}" > crates/integration-tests/src/lib.rs
RUN mkdir -p scripts/src && echo "fn main() {}" > scripts/src/generate_genesis.rs && echo "fn main() {}" > scripts/src/setup_local_testnet.rs

# Build dependencies only (this layer will be cached)
RUN cargo build --release --workspace || true

# Now copy real source code
COPY crates crates
COPY scripts scripts

# Remove dummy files and rebuild
RUN find crates -name "*.rs" -path "*src*" -type f -newer Cargo.toml -delete 2>/dev/null || true
COPY crates crates
COPY scripts scripts

# Build the actual binaries
RUN cargo build --release --bin sumchain --bin sumchain-wallet

# ===========================
# Runtime Stage
# ===========================
FROM debian:bookworm-slim AS runtime

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd -m -u 1000 -s /bin/bash sumchain

# Create directories
RUN mkdir -p /data /config && chown -R sumchain:sumchain /data /config

# Copy binaries from builder
COPY --from=builder /build/target/release/sumchain /usr/local/bin/
COPY --from=builder /build/target/release/sumchain-wallet /usr/local/bin/

# Set ownership
RUN chown sumchain:sumchain /usr/local/bin/sumchain /usr/local/bin/sumchain-wallet

# Switch to non-root user
USER sumchain

# Set working directory
WORKDIR /data

# Default ports:
# 30303 - P2P
# 8545  - RPC/HTTP
EXPOSE 30303 8545

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8545/health/live || exit 1

# Default command
ENTRYPOINT ["sumchain"]
CMD ["--config", "/config/node.toml"]
