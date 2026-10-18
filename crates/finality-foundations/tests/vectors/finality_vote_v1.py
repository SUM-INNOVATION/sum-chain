#!/usr/bin/env python3
"""Generate `finality_vote_v1.json`: test vectors for the RATIFIED
`FinalityVoteV1` format (G2 group V, choices V-1 to V-6, 2026-10-17).

The vectors come from the stdlib-only reference implementation in
`docs/proposals/g2-byte-review/generate.py` (its own BLAKE3 and Ed25519),
independently of the Rust code in `crates/finality-foundations` that reads
them. The Rust tests run in both required CI jobs (x86_64 and aarch64).

SYNTHETIC: test-only keys from seeds [0x01;32]..[0x04;32]; the consensus-config
commitment is the byte-review draft's stand-in (chain 4242), not a real
chain's. Nothing here is a real validator key or a real chain's vote.

Usage (from the repository root):
    python3 -I crates/finality-foundations/tests/vectors/finality_vote_v1.py          # print
    python3 -I crates/finality-foundations/tests/vectors/finality_vote_v1.py --check  # compare
"""

import hashlib
import importlib.util
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", "..", "..", ".."))
REF = os.path.join(ROOT, "docs", "proposals", "g2-byte-review")
OUT = os.path.join(HERE, "finality_vote_v1.json")

spec = importlib.util.spec_from_file_location("g2ref", os.path.join(REF, "generate.py"))
g = importlib.util.module_from_spec(spec)
spec.loader.exec_module(g)

PREVOTE, PRECOMMIT = 1, 2
CAP = 1 << 20
# An order-8 point (canonical encoding), used for the small-order and
# mixed-torsion negatives.
T8 = bytes.fromhex("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a")


def body(commit, height, block_id, rnd, vtype, vs, index, schema=1):
    return (commit + g.u16(schema) + g.u64(height) + block_id + g.u32(rnd)
            + bytes([vtype]) + vs + g.u16(index))


def sign_with_nonce(seed, msg, nonce_label, extra_point=None):
    """Ed25519 with a chosen nonce. With `extra_point`, R' = R + extra_point is
    published while S is computed for R': valid only under a cofactored check."""
    a, _ = g._expand(seed)
    pub = g._compress_pt(g._pmul(a, g._G))
    r = g._sha512_modq(nonce_label)
    R = g._pmul(r, g._G)
    if extra_point is not None:
        R = g._padd(R, g._decompress_pt(extra_point))
    rs = g._compress_pt(R)
    k = g._sha512_modq(rs + pub + msg)
    return rs + int.to_bytes((r + k * a) % g._Q, 32, "little")


def build():
    seeds = list(g.SEEDS)
    pk = [g.ed25519_public(s) for s in seeds]
    commit = g.synthetic_commitment()
    vs = g.valset_commitment(pk)
    block = g.blake3(b"example block at height 7")
    other = g.blake3(b"conflicting block at height 7")
    zero = bytes(32)

    def signed(idx, b, seed=None):
        return g.M_VOTE + b + g.ed25519_sign(seeds[idx] if seed is None else seed, g.D_VOTE + b)

    # Golden examples: byte for byte the ratified document's two examples.
    ex1_body = body(commit, 7, block, 0, PRECOMMIT, vs, 1)
    ex1_sig = g.ed25519_sign(seeds[1], g.D_VOTE + ex1_body)
    ex2_body = body(commit, 7, zero, 1, PREVOTE, vs, 0)
    ex2_sig = g.ed25519_sign(seeds[0], g.D_VOTE + ex2_body)
    with open(os.path.join(REF, "vectors.json")) as fh:
        ref = {v["name"]: v["hex"] for v in json.load(fh)["vectors"]}
    assert (g.D_VOTE + ex1_body).hex() == ref["vote precommit h=7 r=0 idx=1 preimage"]
    assert ex1_sig.hex() == ref["vote precommit h=7 r=0 idx=1 signature"]
    assert (g.M_VOTE + ex1_body + ex1_sig).hex() == ref["vote precommit h=7 r=0 idx=1 wire"]
    assert (g.M_VOTE + ex2_body + ex2_sig).hex() == ref["vote nil prevote h=7 r=1 idx=0 wire"]
    assert vs.hex() == ref["valset n=4 commitment"] and commit.hex() == ref["synthetic config commitment"]

    def golden(name, b, sig, fields):
        return dict(name=name, **fields, body=b.hex(), preimage=(g.D_VOTE + b).hex(),
                    signature=sig.hex(), wire=(g.M_VOTE + b + sig).hex())

    goldens = [
        golden("precommit h=7 r=0 validator 1", ex1_body, ex1_sig,
               dict(height=7, round=0, vote_type=PRECOMMIT, block_id=block.hex(), validator_index=1)),
        golden("nil prevote h=7 r=1 validator 0", ex2_body, ex2_sig,
               dict(height=7, round=1, vote_type=PREVOTE, block_id=zero.hex(), validator_index=0)),
    ]

    valid = [
        ("precommit h=7 r=0 validator 0", signed(0, body(commit, 7, block, 0, PRECOMMIT, vs, 0))),
        ("precommit h=7 r=0 validator 3", signed(3, body(commit, 7, block, 0, PRECOMMIT, vs, 3))),
        ("precommit h=7 r=0 validator 2 conflicting block",
         signed(2, body(commit, 7, other, 0, PRECOMMIT, vs, 2))),
        ("precommit h=7 r=0 validator 1 alternative signature",
         g.M_VOTE + ex1_body + sign_with_nonce(seeds[1], g.D_VOTE + ex1_body, b"alternative nonce")),
        ("precommit h=7 r=0 validator 1 conflicting block",
         signed(1, body(commit, 7, other, 0, PRECOMMIT, vs, 1))),
        ("precommit h=7 r=0 validator 1 nil", signed(1, body(commit, 7, zero, 0, PRECOMMIT, vs, 1))),
        ("nil precommit h=7 r=2 validator 0", signed(0, body(commit, 7, zero, 2, PRECOMMIT, vs, 0))),
        ("nil precommit h=7 r=2 validator 1", signed(1, body(commit, 7, zero, 2, PRECOMMIT, vs, 1))),
        ("nil precommit h=7 r=2 validator 2", signed(2, body(commit, 7, zero, 2, PRECOMMIT, vs, 2))),
        ("prevote h=7 round 2^20 validator 2", signed(2, body(commit, 7, block, CAP, PREVOTE, vs, 2))),
    ]

    ex1_wire = g.M_VOTE + ex1_body + ex1_sig
    flip = lambda b, i: b[:i] + bytes([b[i] ^ 1]) + b[i + 1:]
    s = int.from_bytes(ex1_sig[32:], "little")
    small_y = next(y for y in range(2, 19)
                   if g._recover_x(y, 0) is not None)  # a large-order point with y < 19
    noncanon_r = int.to_bytes(small_y + g._P, 32, "little")
    invalid = [
        ("wire truncated to 183 bytes", ex1_wire[:-1], "length"),
        ("wire with one trailing byte", ex1_wire + b"\0", "length"),
        ("magic first byte changed", flip(ex1_wire, 0), "magic"),
        ("schema 0", g.M_VOTE + body(commit, 7, block, 0, PRECOMMIT, vs, 1, schema=0) + ex1_sig, "schema"),
        ("schema 2", g.M_VOTE + body(commit, 7, block, 0, PRECOMMIT, vs, 1, schema=2) + ex1_sig, "schema"),
        ("vote_type 0", g.M_VOTE + body(commit, 7, block, 0, 0, vs, 1) + ex1_sig, "vote_type"),
        ("vote_type 3", g.M_VOTE + body(commit, 7, block, 0, 3, vs, 1) + ex1_sig, "vote_type"),
        ("vote_type 255", g.M_VOTE + body(commit, 7, block, 0, 255, vs, 1) + ex1_sig, "vote_type"),
        ("round 2^20 + 1", g.M_VOTE + body(commit, 7, block, CAP + 1, PRECOMMIT, vs, 1) + ex1_sig, "round"),
        ("round u32::MAX", g.M_VOTE + body(commit, 7, block, 0xFFFFFFFF, PRECOMMIT, vs, 1) + ex1_sig, "round"),
        ("config commitment one bit flipped, validly signed",
         signed(1, body(flip(commit, 0), 7, block, 0, PRECOMMIT, vs, 1)), "config_commitment"),
        ("validator-set commitment one bit flipped, validly signed",
         signed(1, body(commit, 7, block, 0, PRECOMMIT, flip(vs, 31), 1)), "validator_set_commitment"),
        ("validator_index 4 = n", signed(3, body(commit, 7, block, 0, PRECOMMIT, vs, 4)), "index"),
        ("validator_index 65535", signed(3, body(commit, 7, block, 0, PRECOMMIT, vs, 65535)), "index"),
        ("S + l (non-canonical S, same equation)",
         ex1_wire[:152] + int.to_bytes(s + g._Q, 32, "little"), "signature"),
        ("signed by another validator's key", signed(1, ex1_body, seed=seeds[2]), "signature"),
        ("vote_type flipped to prevote under the precommit signature",
         g.M_VOTE + body(commit, 7, block, 0, PREVOTE, vs, 1) + ex1_sig, "signature"),
        ("signature over the body without D_VOTE",
         g.M_VOTE + ex1_body + g.ed25519_sign(seeds[1], ex1_body), "signature"),
        ("signature over another domain (manifest signing domain) || body",
         g.M_VOTE + ex1_body + g.ed25519_sign(seeds[1], g.D_MSIGN + ex1_body), "signature"),
        ("signature over SUMCHAIN/FINALITY/VOTE/v2 || body",
         g.M_VOTE + ex1_body + g.ed25519_sign(seeds[1], b"SUMCHAIN/FINALITY/VOTE/v2\0" + ex1_body), "signature"),
        ("signature over the wire prefix FVOTv1 || body",
         g.M_VOTE + ex1_body + g.ed25519_sign(seeds[1], g.M_VOTE + ex1_body), "signature"),
        ("R + order-8 point: valid only under a cofactored equation",
         g.M_VOTE + ex1_body + sign_with_nonce(seeds[1], g.D_VOTE + ex1_body, b"mixed torsion nonce", T8),
         "signature"),
        ("R replaced by an order-8 point", ex1_wire[:120] + T8 + ex1_wire[152:], "signature"),
        ("R replaced by a non-canonical encoding (y + p)", ex1_wire[:120] + noncanon_r + ex1_wire[152:],
         "signature"),
    ]

    # Self-checks against the reference verifier (cofactorless, S < l).
    for _, w in valid:
        assert g.ed25519_verify(pk[int.from_bytes(w[118:120], "little")], g.D_VOTE + w[7:120], w[120:])
    for name, w, why in invalid:
        if why == "signature":
            assert not g.ed25519_verify(pk[1], g.D_VOTE + w[7:120], w[120:]), name

    # The mixed-torsion vector really does pass a cofactored check.
    mixed = invalid[[n for n, _, _ in invalid].index(
        "R + order-8 point: valid only under a cofactored equation")][1]
    Rp, sp = g._decompress_pt(mixed[120:152]), int.from_bytes(mixed[152:], "little")
    kp = g._sha512_modq(mixed[120:152] + pk[1] + g.D_VOTE + ex1_body)
    lhs = g._pmul(8 * sp, g._G)
    rhs = g._pmul(8, g._padd(Rp, g._pmul(kp, g._decompress_pt(pk[1]))))
    assert g._peq(lhs, rhs)

    return {
        "status": "SYNTHETIC test vectors for the RATIFIED FinalityVoteV1 format (G2 group V, "
                  "V-1 to V-6, 2026-10-17). Test-only keys; stand-in config commitment. "
                  "Generated by finality_vote_v1.py from docs/proposals/g2-byte-review/generate.py.",
        "d_vote": g.D_VOTE.hex(),
        "magic": g.M_VOTE.hex(),
        "height": 7,
        "consensus_config_commitment": commit.hex(),
        "validator_set_commitment": vs.hex(),
        "validator_keys": [p.hex() for p in pk],
        "golden": goldens,
        "valid": [dict(name=n, wire=w.hex()) for n, w in valid],
        "invalid": [dict(name=n, wire=w.hex(), refusal=why) for n, w, why in invalid],
    }


def render(v):
    return json.dumps(v, indent=1) + "\n"


def main():
    out = render(build())
    if sys.argv[1:] == ["--check"]:
        with open(OUT) as fh:
            if fh.read() != out:
                sys.exit("finality_vote_v1.json differs from the generator's output")
        print("finality_vote_v1.json matches")
    else:
        sys.stdout.write(out)


if __name__ == "__main__":
    main()
