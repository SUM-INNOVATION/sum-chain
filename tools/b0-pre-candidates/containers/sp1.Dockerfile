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
    : "reproducibility (authoritative x86 r3): rustup writes lib/rustlib/components in \
       concurrent task-completion order — the one nondeterministic file after aux-cache \
       (#173). Its ORDER is not semantically significant (rustup treats it as the unordered \
       SET of installed components), so canonicalize it to bytewise C-locale lexical order \
       IN THIS LAYER, preserving multiplicity (NOT sort -u — an unexpected duplicate must \
       surface; rustup components are unique by contract), atomically: sort to a sibling, \
       verify the multiset is unchanged + duplicate-free + sorted, then move; temporaries \
       are removed on failure. See lib.sh canonicalize_rustup_components (the reference)."; \
    comp="/root/.rustup/toolchains/${RUST_VERSION}-${arch}-unknown-linux-gnu/lib/rustlib/components"; \
    if [ ! -s "$comp" ]; then echo "REFUSED: rustup components file missing or empty: $comp" >&2; exit 6; fi; \
    if grep -qvE '^[A-Za-z0-9._+-]+$' "$comp"; then echo "REFUSED: malformed (non-token) line in rustup components: $comp" >&2; exit 6; fi; \
    LC_ALL=C sort "$comp" > "$comp.sorted" || { rm -f "$comp.sorted"; echo "REFUSED: sort failed for $comp" >&2; exit 6; }; \
    LC_ALL=C sort "$comp" > "$comp.a"; LC_ALL=C sort "$comp.sorted" > "$comp.b"; \
    if ! cmp -s "$comp.a" "$comp.b"; then rm -f "$comp.sorted" "$comp.a" "$comp.b"; echo "REFUSED: component multiset changed by canonicalization" >&2; exit 6; fi; \
    if [ -n "$(uniq -d "$comp.sorted")" ]; then rm -f "$comp.sorted" "$comp.a" "$comp.b"; echo "REFUSED: unexpected duplicate component in $comp" >&2; exit 6; fi; \
    if ! LC_ALL=C sort -c "$comp.sorted"; then rm -f "$comp.sorted" "$comp.a" "$comp.b"; echo "REFUSED: canonicalized rustup components not sorted" >&2; exit 6; fi; \
    rm -f "$comp.a" "$comp.b"; mv -f "$comp.sorted" "$comp"; \
    : "reproducibility: remove rustup download/tmp scratch (fetch-order/temp bytes); the \
       installed toolchain itself is content-deterministic"; \
    rm -rf /tmp/rustup-init /root/.rustup/downloads /root/.rustup/tmp
ENV PATH="/root/.cargo/bin:${PATH}"
RUN rustc --version | grep -q "${RUST_VERSION}"

# ============================================================================================
# AUDIT + PROVER TOOLCHAIN PROVISIONING (declarative, verified, reproducibility-preserving).
# All inputs are REQUIRED build-args with no defaults; a missing/malformed value fails closed
# BEFORE any fetch. There is NO ENTRYPOINT and NO `rzup`, NO `curl | tar`: the prover executables
# are delivered by the staged, tested verified-archive-member extractor.
# ============================================================================================

# ---- (Item 4) cargo-audit, BUILT IN THIS BUILDER from the verified crate + packaged lock.
# The Ubuntu host's cargo-audit binary is NEVER copied in. The ratified inputs are the crate +
# version + crate checksum + packaged-lock checksum (PIN-PROPOSAL.md §6); the RESULTING executable
# SHA-256 is recorded as VENUE EVIDENCE (reproduced by an independent same-arch operator), never a
# source pin. `--locked` binds the packaged Cargo.lock so the dependency graph cannot drift.
ARG CARGO_AUDIT_VERSION
ARG CARGO_AUDIT_CRATE_URL
ARG CARGO_AUDIT_CRATE_SHA256
ARG CARGO_AUDIT_PACKAGED_LOCK_SHA256
RUN set -eux; \
    printf '%s' "${CARGO_AUDIT_VERSION}"              | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+$'; \
    printf '%s' "${CARGO_AUDIT_CRATE_SHA256}"         | grep -Eq '^[0-9a-f]{64}$'; \
    printf '%s' "${CARGO_AUDIT_PACKAGED_LOCK_SHA256}" | grep -Eq '^[0-9a-f]{64}$'; \
    test -n "${CARGO_AUDIT_CRATE_URL}" || { echo "REFUSED: CARGO_AUDIT_CRATE_URL is empty" >&2; exit 7; }; \
    case "${CARGO_AUDIT_CRATE_URL}" in \
      https://static.crates.io/crates/cargo-audit/cargo-audit-${CARGO_AUDIT_VERSION}.crate) ;; \
      https://crates.io/api/v1/crates/cargo-audit/${CARGO_AUDIT_VERSION}/download) ;; \
      *) echo "REFUSED: CARGO_AUDIT_CRATE_URL is not the immutable crates.io .crate path for ${CARGO_AUDIT_VERSION}: ${CARGO_AUDIT_CRATE_URL}" >&2; exit 7 ;; \
    esac; \
    mkdir -p /opt/b0pre/evidence /tmp/ca-build; \
    curl -fsSL "${CARGO_AUDIT_CRATE_URL}" -o /tmp/ca-build/cargo-audit.crate; \
    echo "${CARGO_AUDIT_CRATE_SHA256}  /tmp/ca-build/cargo-audit.crate" | sha256sum -c -; \
    tar -xzf /tmp/ca-build/cargo-audit.crate -C /tmp/ca-build; \
    src="/tmp/ca-build/cargo-audit-${CARGO_AUDIT_VERSION}"; \
    test -f "$src/Cargo.lock" || { echo "REFUSED: packaged Cargo.lock absent in the cargo-audit crate" >&2; exit 7; }; \
    echo "${CARGO_AUDIT_PACKAGED_LOCK_SHA256}  $src/Cargo.lock" | sha256sum -c -; \
    CARGO_INCREMENTAL=0 CARGO_NET_GIT_FETCH_WITH_CLI=false \
      cargo install --locked --path "$src" --bin cargo-audit --root /opt/b0pre/audit-prefix; \
    "/opt/b0pre/audit-prefix/bin/cargo-audit" --version | grep -q "${CARGO_AUDIT_VERSION}"; \
    sha256sum /opt/b0pre/audit-prefix/bin/cargo-audit | awk '{print $1}' > /opt/b0pre/evidence/cargo-audit.exe.sha256; \
    : "reproducibility: remove ALL crate build scratch + cargo download caches IN THIS LAYER; only \
       the installed binary + its recorded exe-sha256 (venue evidence) survive"; \
    rm -rf /tmp/ca-build /root/.cargo/registry/cache /root/.cargo/registry/src /root/.cargo/git

# ---- (Items 2/3) SP1 prover `cargo-prove` (x86_64 AND aarch64), by DECLARATIVE VERIFIED
# ARCHIVE-MEMBER EXTRACTION using the SINGLE staged, tested provisioner (COPIED into the curated
# context by stage_context.sh; the SAME file tests/verified_extraction.test.sh exercises — NOT a
# second implementation, NOT host lib.sh). It verifies the whole-archive SHA-256 before extraction,
# refuses links/traversal/dup/unexpected members, extracts ONLY the declared member, verifies its
# size + SHA-256 before chmod, and re-hashes at the point of use. `cargo-prove` lands on the
# ISOLATED verified PATH dir; its executable SHA-256 is recorded as venue evidence.
ARG SP1_ARCHIVE_URL
ARG SP1_ARCHIVE_SHA256
ARG CARGO_PROVE_MEMBER_PATH
ARG CARGO_PROVE_MEMBER_SHA256
ARG CARGO_PROVE_MEMBER_SIZE
COPY provisioning/provision_prover_toolchain.sh /usr/local/lib/b0pre/provision_prover_toolchain.sh
RUN set -eux; \
    printf '%s' "${SP1_ARCHIVE_SHA256}"        | grep -Eq '^[0-9a-f]{64}$'; \
    printf '%s' "${CARGO_PROVE_MEMBER_SHA256}" | grep -Eq '^[0-9a-f]{64}$'; \
    printf '%s' "${CARGO_PROVE_MEMBER_SIZE}"   | grep -Eq '^[0-9]+$'; \
    test -n "${SP1_ARCHIVE_URL}"         || { echo "REFUSED: SP1_ARCHIVE_URL is empty" >&2; exit 8; }; \
    test -n "${CARGO_PROVE_MEMBER_PATH}" || { echo "REFUSED: CARGO_PROVE_MEMBER_PATH is empty" >&2; exit 8; }; \
    mkdir -p /opt/b0pre/evidence /tmp/prov; \
    curl -fsSL "${SP1_ARCHIVE_URL}" -o /tmp/prov/sp1-prover.tar.gz; \
    bash /usr/local/lib/b0pre/provision_prover_toolchain.sh \
      /tmp/prov/sp1-prover.tar.gz "${SP1_ARCHIVE_SHA256}" \
      /opt/b0pre/prover-bin /opt/b0pre/risc0-server \
      "${CARGO_PROVE_MEMBER_PATH}:${CARGO_PROVE_MEMBER_SHA256}:${CARGO_PROVE_MEMBER_SIZE}:isolated"; \
    "/opt/b0pre/prover-bin/cargo-prove" prove --version; \
    sha256sum /opt/b0pre/prover-bin/cargo-prove | awk '{print $1}' > /opt/b0pre/evidence/cargo-prove.exe.sha256; \
    : "reproducibility: remove the downloaded archive scratch IN THIS LAYER; the placed executable \
       + its recorded exe-sha256 (venue evidence) survive"; \
    rm -rf /tmp/prov

# The audit prefix + isolated prover PATH become part of the PRODUCTION non-login PATH so
# `cargo audit` and `cargo prove` resolve under the exact `bash -c` the producer uses (RT-2).
ENV PATH="/opt/b0pre/audit-prefix/bin:/opt/b0pre/prover-bin:/root/.cargo/bin:${PATH}"
RUN command -v cargo cargo-audit cargo-prove >/dev/null \
 || (echo "REFUSED: production non-login PATH does not resolve cargo + cargo-audit + cargo-prove" >&2; exit 9)

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
