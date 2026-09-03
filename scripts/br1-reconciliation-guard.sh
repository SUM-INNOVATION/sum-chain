#!/usr/bin/env bash
# BR1 beacon (#127) reconciliation regression guard.
#
# The owner-ratified ECIES suite is ECDH-in-G1 -> HKDF-SHA-256 ->
# ChaCha20-Poly1305 with a deterministic HKDF (key, nonce); finality is a genesis
# parameter. This guard fails the build if any SUPERSEDED construct re-appears in
# the beacon surfaces, so the reconciled contradictions cannot silently return.
#
# It deliberately does NOT scan the unrelated sponsored-messaging subsystem
# (crates/crypto/src/messaging.rs, crates/sumchain-wire/src/messaging.rs), which
# legitimately uses X25519 + XChaCha20-Poly1305 for a different purpose.
#
# Allowed: ratified REJECTION notes in doc-comments / spec prose (they name the
# rejected alternatives on purpose). Forbidden: the exact dead tag/finality
# strings anywhere, and re-ADOPTION of the rejected primitives in beacon CODE.
#
# Run locally:  bash scripts/br1-reconciliation-guard.sh
set -euo pipefail
cd "$(dirname "$0")/.."

fail=0
err() { echo "::error::BR1 reconciliation guard: $1"; fail=1; }

# Beacon surfaces (spec + crypto + runtime + the crypto-crate vector leaf).
BEACON_SURFACES=(
  crates/beacon-crypto
  crates/beacon-runtime
  crates/crypto/tests/br1_beacon_vectors.rs
  docs/design/BR1-BEACON-SECURITY-SPEC-DRAFT.md
)

# ── Set A — exact strings that must NEVER re-appear on any beacon surface. ──
# The superseded single-tag ECIES domains and the hardcoded finality call.
if hits=$(grep -rnE 'OMNINODE-DKG-ECIES:v1:(key|aad)|finality_depth\(6\)' \
            "${BEACON_SURFACES[@]}" 2>/dev/null); then
  err "superseded exact token re-introduced (ECIES :key/:aad tag or finality_depth(6))"
  echo "$hits"
fi

# ── Set B — re-ADOPTION of rejected primitives in beacon CODE. ──
# Scan beacon-crypto / beacon-runtime (src + manifests) but drop full-line
# comments (`//`, `//!`, `#`) so ratified rejection notes are allowed. A match on
# a real code / dependency line (e.g. an XChaCha20 import or a curve25519-dalek
# dep) is a regression.
codeB=$(grep -rniE 'xchacha|ristretto|curve25519|\bdalek\b|zero-?nonce' \
          crates/beacon-crypto crates/beacon-runtime 2>/dev/null \
          | grep -vE '^[^:]+:[0-9]+:[[:space:]]*(//|#)' || true)
if [ -n "$codeB" ]; then
  err "rejected primitive re-adopted in beacon CODE (XChaCha20 / Ristretto / Curve25519 / zero-nonce)"
  echo "$codeB"
fi

# ── Set C — the stale 'signing carriers not landed / land with #125' comment. ──
# The signing carriers landed via #164; this statement must not return.
if hits=$(grep -rniE 'not (yet )?landed|carriers?.*not.*land|land(ed)?[^.]*#125' \
            crates/beacon-crypto crates/beacon-runtime 2>/dev/null); then
  err "stale 'carriers not landed' statement re-introduced"
  echo "$hits"
fi

# ── Set D — beacon-output / chaining layout is RATIFIED v1 (#127 §12.1); no ──
# stale PROPOSED / not-adopted / not-frozen labels may remain on its CODE
# surfaces. `wire.rs` and the crypto vector leaf are fully-ratified beacon
# surfaces, so ANY such phrase in them is a reconciliation regression.
if hits=$(grep -rniE 'proposed|not adopted|not frozen consensus' \
            crates/beacon-runtime/src/wire.rs \
            crates/crypto/tests/br1_beacon_vectors.rs 2>/dev/null); then
  err "stale PROPOSED/not-adopted label on a RATIFIED v1 beacon-output surface (wire.rs / vector test)"
  echo "$hits"
fi
# The spec §12.1 heading must not re-acquire a PROPOSED marker.
if hits=$(grep -nE '^###[[:space:]]*12\.1' \
            docs/design/BR1-BEACON-SECURITY-SPEC-DRAFT.md 2>/dev/null \
          | grep -iE 'proposed|not adopted'); then
  err "spec §12.1 heading re-marked PROPOSED (beacon chaining layout is RATIFIED v1)"
  echo "$hits"
fi

# ── Set E — the beacon_output KAT must stay present and byte-locked. ──
# Value drift is caught by the test at run time; this guards against silent
# removal or edit of the test / its frozen vectors (a real G2 signature KAT over
# the ratified domain tag + LE preimage + canonical 96-byte compression).
KAT_NEEDLES=(
  'fn beacon_output_kat_ratified_v1'                                    # the KAT test
  'fn beacon_output_negatives'                                          # the negatives
  '6904ae11981e78d560b34500bb42b1749085c45ed68c7a7bfe3d26f9e3e92104'   # beacon_output KAT
  'b208df346c7cabeded73631e962cde964f9f551da77a344decb6e92b06ef4446'   # compressed Sigma_r KAT
)
for needle in "${KAT_NEEDLES[@]}"; do
  if ! grep -qF "$needle" crates/beacon-runtime/src/wire.rs; then
    err "beacon_output KAT missing or altered in wire.rs (expected: $needle)"
  fi
done

if [ "$fail" -ne 0 ]; then
  echo "BR1 reconciliation guard FAILED — see errors above." >&2
  exit 1
fi
echo "ok - BR1 reconciliation guard: no superseded beacon constructs present."
