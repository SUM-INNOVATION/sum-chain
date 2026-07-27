# B0-PRE immutable venue-input pin proposal (DRAFT — not ratified)

Status: **DRAFT / NOT RATIFIED.** This document defines the *primary sources* and the
*automated verification* for every immutable venue input the authoritative run consumes.
It deliberately contains **no concrete pin values** — no digests, checksums, or URLs are
inserted here, and nothing in `VENUE.md` / the scripts is changed. Values are proposed,
verified against their primary source by `scripts/verify_pins.sh`, and only then submitted
for owner ratification in a separate step.

Pins are verified and ratified against the tree of the owner-ratified source commit
(`RATIFIED_SOURCE_COMMIT`; see RUNBOOK.md §1), not a hard-coded hash — so this proposal
does not go stale when the venue pipeline is corrected.

## Why pins, and the ratification rule

Every input below is an **immutable INPUT**, not a built artifact. The venue resolves it
by digest/checksum, never by mutable tag or "latest". A pin is eligible only when
`verify_pins.sh` re-derives it from the primary source and the derived value equals the
proposed value **exactly**; any mismatch fails closed. Ratification (inserting the values
into a ratified `pins.env` the runbook sources) is an owner decision made *after*
verification passes — never automatically.

## The pins, their primary sources, and verification method

| # | Pin | Primary source (authoritative) | How `verify_pins.sh` checks it |
|---|-----|-------------------------------|--------------------------------|
| 1 | `BASE_IMAGE` + `base_index_digest` + `BASE_DIGEST` (per-arch) | the base image's registry, resolved **by digest** | `docker manifest inspect "$BASE_IMAGE@$base_index_digest"` must resolve; its child manifests are **enumerated**, and each per-arch digest must be a child of that index declaring `linux/amd64` (x86_64) or `linux/arm64` (aarch64). Every digest must be a full `sha256:<64hex>` (never a tag). Metadata only — no image is pulled or executed, so the check holds on a host with QEMU/binfmt registered |
| 2 | `apt.debian_url` + `apt.debian_inrelease_sha256` + `apt.debian_security_url` + `apt.debian_security_inrelease_sha256` | the distro's immutable snapshot service (`snapshot.debian.org` / `snapshot.ubuntu.com`) | each base URL must be on an immutable snapshot service and end in `/`; the `InRelease` at `<url>dists/<suite>/InRelease` is fetched and its sha256 must equal the pinned value **exactly** |
| 3 | `rustup_init.version` + `rustup_init.<arch>` — per-arch `url` + `sha256` (ratified into `RUSTUP_INIT_URL` / `RUSTUP_INIT_SHA256`) | the official Rust release channel, **immutable archive** path `static.rust-lang.org/rustup/archive/<version>/<target>/rustup-init` | `version` must be the required rustup release; the URL must be the exact immutable archive locator for that version **and that architecture**; the unversioned `rustup/dist/` path is refused outright; then download and recompute `sha256` |
| 4 | SP1 tool identity — `sp1-verifier 6.3.1`, **one entry per architecture** | the pinned SP1 release artifact (its immutable download URL) | the initial URL must be an allow-listed **https** primary host and its effective (post-redirect) host must be an allow-listed delivery host, exact-matched; then download the declared `artifact_identity`, recompute the checksum, compare to `checksum_hex` |
| 5 | RISC Zero tool identities — `risc0-zkvm 3.0.5`, `risc0-groth16 3.0.4`, **x86_64 only** | the pinned RISC Zero release artifacts | same host/redirect/download/compare as (4). An `aarch64` RISC Zero entry is **refused**: Groth16 and verifier-material extraction are native-x86_64-only (VENUE.md §2) |

Notes:
- The **base image** identity IS the pinned per-arch digest, and it must belong to the
  pinned immutable **index**; its provenance is the base-resolution command/output,
  distinct from the builder's two-build evidence (VENUE.md §3).
- The APT pin is **four exact fields**, not a bare timestamp. A timestamp alone could not
  be verified: `snapshot.debian.org` resolves *any* timestamp to the nearest **preceding**
  snapshot, so a nonexistent date still answered. The `InRelease` content hash is the
  snapshot's real identity, and both Dockerfiles re-check it **before apt installs
  anything**. Hash pinning **supplements** apt's OpenPGP verification; it never replaces it.
- Both Dockerfiles remove every pre-existing apt source before the first `apt-get update`
  and assert that no rolling `deb.debian.org` / `security.debian.org` source survives. The
  Debian base image ships a deb822 `sources.list.d/debian.sources` pointing at the rolling
  mirror, which previously stayed active alongside the snapshot.
- `RUSTUP_INIT_URL` + `RUSTUP_INIT_SHA256` gate that Rust **1.88.0** is installed *inside*
  the builder from an exact immutable artifact, never assumed present (VENUE.md §1).
- Tool identities are fail-closed and **per (candidate, architecture)**: a version string
  alone never preregisters the bytes; authoritative assembly refuses any absent, synthetic,
  cross-architecture, or swapped value (VENUE.md §3.5).

## Proposed-value file (operator fills; kept OUT of the repo until ratified)

`verify_pins.sh` reads a proposed-pins file of exactly this shape (this is the single
authoritative schema — the script is the contract, this document mirrors it). Values are
shown **empty**; a committed, byte-identical UNRATIFIED example lives at
`tools/b0-pre-candidates/scripts/tests/fixtures/proposed-pins.documented-shape.json`.

```json
{
  "base_image": "",
  "base_index_digest": "",
  "base_digest": { "x86_64": "", "aarch64": "" },
  "apt": {
    "debian_url": "",
    "debian_inrelease_sha256": "",
    "debian_security_url": "",
    "debian_security_inrelease_sha256": ""
  },
  "rustup_init": {
    "version": "1.29.0",
    "x86_64": { "url": "", "sha256": "" },
    "aarch64": { "url": "", "sha256": "" }
  },
  "tool_identities": [
    { "name": "sp1-verifier",  "version": "6.3.1", "arch": "x86_64",  "artifact_identity": "", "checksum_algorithm": "sha256", "checksum_hex": "", "install_entrypoint": "" },
    { "name": "sp1-verifier",  "version": "6.3.1", "arch": "aarch64", "artifact_identity": "", "checksum_algorithm": "sha256", "checksum_hex": "", "install_entrypoint": "" },
    { "name": "risc0-zkvm",    "version": "3.0.5", "arch": "x86_64",  "artifact_identity": "", "checksum_algorithm": "sha256", "checksum_hex": "", "install_entrypoint": "" },
    { "name": "risc0-groth16", "version": "3.0.4", "arch": "x86_64",  "artifact_identity": "", "checksum_algorithm": "sha256", "checksum_hex": "", "install_entrypoint": "" }
  ]
}
```

The exact keys `verify_pins.sh` reads (any absent/empty value fails closed):
`base_image`; `base_index_digest`; `base_digest.<arch>`; `apt.debian_url`,
`apt.debian_inrelease_sha256`, `apt.debian_security_url`,
`apt.debian_security_inrelease_sha256`; `rustup_init.version`, `rustup_init.<arch>.url`
and `rustup_init.<arch>.sha256` (per arch — the exact immutable installer URL to fetch
*and* its expected `sha256`); and each `tool_identities[i]` with `name`, `version`,
`arch`, `artifact_identity`, `checksum_algorithm` (must be `sha256`), `checksum_hex`,
`install_entrypoint`. `<arch>` is `x86_64` and `aarch64`.

Required tool-identity coverage: `sp1-verifier` for **both** architectures, and
`risc0-zkvm` + `risc0-groth16` for **x86_64 only**. Anything less fails closed; a RISC
Zero entry declaring `aarch64` is refused outright.

The ratified build inputs derived from this record are `RUSTUP_INIT_URL` +
`RUSTUP_INIT_SHA256` (per arch), the four `APT_*` fields (identical on both hosts), and
one tool-identity file per (candidate, architecture) named by
`SP1_TOOL_IDENTITY_X86_64`, `SP1_TOOL_IDENTITY_AARCH64`, `RISC0_TOOL_IDENTITY_X86_64`.
Each tool-identity file MUST carry an `"arch"` field; the producer selects it only after
the native-architecture gate passes and refuses a file whose declared arch is not the
host's, so a swapped or cross-architecture identity fails before any download or build.

## Provenance policy (what a clean verification does and does not establish)

`verify_pins.sh` establishes that each pinned artifact's bytes match the value the owner
proposes, fetched from an allow-listed primary source over https (or, for the two apt
snapshot URLs, from an immutable snapshot service whose `InRelease` is both OpenPGP-signed
and hash-pinned). That is a **checksum trust model**, and for some upstreams it is the
strongest chain available:

- The Debian base image carries in-toto SBOM **attestations** published by the registry.
- The Debian snapshots are **OpenPGP-signed** and verified by apt.
- `rustup-init` has a publisher-published `.sha256` sidecar but **no signature**.
- **SP1 and RISC Zero publish no author signature and no build-provenance attestation**
  for their release artifacts.

For SP1 and RISC Zero the owner has confirmed ratification on this basis, and only this
basis: the **primary GitHub release asset**, the **GitHub-published asset digest**, an
**independent re-download and re-hash**, the **release tag-to-commit mapping**, and the
**binary's self-reported identity**. That combination is recorded as **checksum
provenance, not signed provenance**. It must never be described as signed provenance, and
a successful download is never by itself provenance.

### The APT http bootstrap exception

The two pinned `snapshot.debian.org` locators — and nothing else — may use plain http,
because the pinned base image has no `ca-certificates` before the first package
installation. `verify_pins.sh` still requires the initial host to be exactly
`snapshot.debian.org`, refuses any other http host, refuses a redirect off the pinned
snapshot host, and refuses an https→http downgrade. Integrity comes from the pinned
`InRelease` sha256 plus apt's OpenPGP verification, both enforced before any package is
installed. http therefore permits denial-of-service or replay attempts, but not
accepted-content substitution. The exception is never generalized to Rust, GitHub,
container registries, or tool artifacts — see VENUE.md §3 for the full statement.

## Verification (automated)

```sh
# resolves every pin from its primary source and fails closed on any mismatch;
# prints a PASS/FAIL line per pin. Requires network + docker + a sha256 tool + curl.
bash tools/b0-pre-candidates/scripts/verify_pins.sh proposed-pins.json
```

`verify_pins.sh` never edits any repo file and never "accepts" a pin — it only reports
whether each proposed value matches its primary source. A clean run is a *precondition*
for ratification, not ratification itself.

## Ratification (owner only — not performed here)

After a clean `verify_pins.sh` run on an independent host, the owner ratifies by placing
the verified values into a `pins.env` the runbook sources (kept out of the committable set
until the B0-PRE PR path calls for it). This DRAFT proposes; it does not ratify.
