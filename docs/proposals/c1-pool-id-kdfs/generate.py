#!/usr/bin/env python3
"""Generate the PROPOSAL vectors for the C1 pool identifier KDFs.

UNRATIFIED DRAFT — NEW PROPOSAL. Not recovered §K bytes; not previously
ratified; not consensus; do not implement until ratified.

Standard library only. BLAKE3 is implemented below from the specification
(hash mode, 32-byte output) so this generator shares no code with the Rust
generator in `rust-generator/`. `check.py` verifies this BLAKE3 against the
official test vectors before trusting any output.

Usage: python3 generate.py > vectors.json
"""
import json
import struct
import sys

# --------------------------------------------------------------------------- #
# BLAKE3, hash mode only (after the specification's reference implementation)
# --------------------------------------------------------------------------- #
OUT_LEN = 32
BLOCK_LEN = 64
CHUNK_LEN = 1024
CHUNK_START, CHUNK_END, PARENT, ROOT = 1, 2, 4, 8
IV = [0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
      0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19]
MSG_PERMUTATION = [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8]
M32 = 0xFFFFFFFF


def _rotr(x, n):
    return ((x >> n) | (x << (32 - n))) & M32


def _g(s, a, b, c, d, x, y):
    s[a] = (s[a] + s[b] + x) & M32
    s[d] = _rotr(s[d] ^ s[a], 16)
    s[c] = (s[c] + s[d]) & M32
    s[b] = _rotr(s[b] ^ s[c], 12)
    s[a] = (s[a] + s[b] + y) & M32
    s[d] = _rotr(s[d] ^ s[a], 8)
    s[c] = (s[c] + s[d]) & M32
    s[b] = _rotr(s[b] ^ s[c], 7)


def _compress(cv, block_words, counter, block_len, flags):
    s = list(cv) + IV[:4] + [counter & M32, (counter >> 32) & M32, block_len, flags]
    m = list(block_words)
    for r in range(7):
        _g(s, 0, 4, 8, 12, m[0], m[1])
        _g(s, 1, 5, 9, 13, m[2], m[3])
        _g(s, 2, 6, 10, 14, m[4], m[5])
        _g(s, 3, 7, 11, 15, m[6], m[7])
        _g(s, 0, 5, 10, 15, m[8], m[9])
        _g(s, 1, 6, 11, 12, m[10], m[11])
        _g(s, 2, 7, 8, 13, m[12], m[13])
        _g(s, 3, 4, 9, 14, m[14], m[15])
        if r < 6:
            m = [m[MSG_PERMUTATION[i]] for i in range(16)]
    for i in range(8):
        s[i] ^= s[i + 8]
        s[i + 8] ^= cv[i]
    return s


def _words(block):
    return list(struct.unpack("<16I", block.ljust(BLOCK_LEN, b"\0")))


def _chunk_output(chunk, counter):
    """(input_cv, block_words, counter, block_len, flags) of a chunk's last block."""
    cv = IV
    blocks = [chunk[i:i + BLOCK_LEN] for i in range(0, len(chunk), BLOCK_LEN)] or [b""]
    for i, blk in enumerate(blocks):
        flags = (CHUNK_START if i == 0 else 0) | (CHUNK_END if i == len(blocks) - 1 else 0)
        if i == len(blocks) - 1:
            return (cv, _words(blk), counter, len(blk), flags)
        cv = _compress(cv, _words(blk), counter, BLOCK_LEN, flags)[:8]
    raise AssertionError("unreachable")


def blake3(data: bytes) -> bytes:
    chunks = [data[i:i + CHUNK_LEN] for i in range(0, len(data), CHUNK_LEN)] or [b""]
    outs = [_chunk_output(c, i) for i, c in enumerate(chunks)]

    def chaining_value(o):
        cv, w, ctr, bl, fl = o
        return _compress(cv, w, ctr, bl, fl)[:8]

    def node(lo, hi):
        # Left subtree holds the largest power of two of chunks < the total.
        if hi - lo == 1:
            return outs[lo]
        split = 1 << ((hi - lo - 1).bit_length() - 1)
        left, right = node(lo, lo + split), node(lo + split, hi)
        return (IV, chaining_value(left) + chaining_value(right), 0, BLOCK_LEN, PARENT)

    cv, w, ctr, bl, fl = node(0, len(outs))
    return struct.pack("<16I", *_compress(cv, w, ctr, bl, fl | ROOT))[:OUT_LEN]


# --------------------------------------------------------------------------- #
# Encodings
# --------------------------------------------------------------------------- #
def u8(v):
    if not 0 <= v <= 0xFF:
        raise ValueError("u8 out of range")
    return bytes([v])


def u32_le(v):
    return struct.pack("<I", v)


def u64_le(v):
    return struct.pack("<Q", v)


# --------------------------------------------------------------------------- #
# Tags. FROZEN tags are on main (crates/sumchain-wire/src/compute_pool_graph.rs).
# PROPOSED tags are this draft.
# --------------------------------------------------------------------------- #
FROZEN_TAGS = {
    "JOB": b"SUMCHAIN/POOL/JOB/v1\n",
    "UNIT": b"SUMCHAIN/POOL/UNIT/v1\n",
    "GRAPHDEF": b"SUMCHAIN/POOL/GRAPHDEF/v1\n",
}
PROPOSED_TAGS = {
    "OFFERBOND": b"SUMCHAIN/POOL/OFFERBOND/v1\n",
    "RESERVATION": b"SUMCHAIN/POOL/RESERVATION/v1\n",
    "ENTITLEMENT": b"SUMCHAIN/POOL/ENTITLEMENT/v1\n",
}
PROPOSED_ID_OF_TAG = {
    "OFFERBOND": "offer_bond_id",
    "RESERVATION": "reservation_id",
    "ENTITLEMENT": "entitlement_id",
}

# entitlement_kind: the numbering the dormant store already writes
# (crates/state/src/compute_pool_store.rs, entitlement_kind_tag).
ACCEPT_REIMB, REASSIGN_REIMB, REPROVISION_REIMB = 0, 1, 2
KIND_NAMES = {ACCEPT_REIMB: "AcceptReimb", REASSIGN_REIMB: "ReassignReimb",
              REPROVISION_REIMB: "ReprovisionReimb"}
ONE_TIME_KINDS = {ACCEPT_REIMB, REPROVISION_REIMB}


class Rejected(ValueError):
    pass


# Each KDF returns (fields, preimage, output); fields lists the encoded inputs
# in preimage order as (name, width_bytes, decimal_or_hex_value, encoded_hex).
def _fields(tag, items):
    pre = tag + b"".join(enc for _, _, enc in items)
    fields = [(n, len(enc), v, enc.hex()) for n, v, enc in items]
    for (n, w, _, h), (_, _, enc) in zip(fields, items):
        assert w == len(enc) and h == enc.hex(), n
    return fields, pre, blake3(pre)


def job_id(chain_id, requester, requester_nonce, client_job_salt):
    """FROZEN on main. Reproduced here only to build the work-item inputs."""
    assert len(requester) == 20 and len(client_job_salt) == 32
    return _fields(FROZEN_TAGS["JOB"], [
        ("chain_id", str(chain_id), u64_le(chain_id)),
        ("requester", requester.hex(), requester),
        ("requester_nonce", str(requester_nonce), u64_le(requester_nonce)),
        ("client_job_salt", client_job_salt.hex(), client_job_salt),
    ])


def unit_id(job, unit_index):
    """FROZEN on main."""
    assert len(job) == 32
    return _fields(FROZEN_TAGS["UNIT"], [
        ("job_id", job.hex(), job),
        ("unit_index", str(unit_index), u32_le(unit_index)),
    ])


def offer_bond_id(chain_id, sender, offer_seq):
    """PROPOSAL."""
    assert len(sender) == 20
    return _fields(PROPOSED_TAGS["OFFERBOND"], [
        ("chain_id", str(chain_id), u64_le(chain_id)),
        ("sender", sender.hex(), sender),
        ("offer_seq", str(offer_seq), u64_le(offer_seq)),
    ])


def reservation_id(job, unit, generation, offer):
    """PROPOSAL."""
    assert len(job) == 32 and len(unit) == 32 and len(offer) == 32
    return _fields(PROPOSED_TAGS["RESERVATION"], [
        ("job_id", job.hex(), job),
        ("unit_id", unit.hex(), unit),
        ("generation", str(generation), u64_le(generation)),
        ("offer_bond_id", offer.hex(), offer),
    ])


def entitlement_id(job, unit, generation, kind, occurrence):
    """PROPOSAL. Refuses kinds outside {0,1,2} and a nonzero occurrence for a
    one-time kind (AcceptReimb, ReprovisionReimb)."""
    assert len(job) == 32 and len(unit) == 32
    if kind not in KIND_NAMES:
        raise Rejected(f"entitlement_kind {kind} is not in {{0,1,2}}")
    if kind in ONE_TIME_KINDS and occurrence != 0:
        raise Rejected(f"{KIND_NAMES[kind]} is one-time: occurrence must be 0, got {occurrence}")
    return _fields(PROPOSED_TAGS["ENTITLEMENT"], [
        ("job_id", job.hex(), job),
        ("unit_id", unit.hex(), unit),
        ("generation", str(generation), u64_le(generation)),
        ("entitlement_kind", f"{kind} ({KIND_NAMES[kind]})", u8(kind)),
        ("occurrence", str(occurrence), u32_le(occurrence)),
    ])


# --------------------------------------------------------------------------- #
# Vector set
# --------------------------------------------------------------------------- #
# TEST_ONLY inputs. The job/unit inputs are exactly the frozen KAT inputs in
# compute_pool_graph.rs (job_id_matches_independent_b3sum_vector,
# unit_id_matches_independent_b3sum_vector).
KAT_CHAIN_ID = 1
KAT_ADDRESS = bytes(range(1, 21))          # 0x01..0x14
KAT_NONCE = 7
KAT_SALT = bytes([0xAA] * 32)
KAT_UNIT_INDEX = 0
OFFER_SEQ = 7
GENERATION = 1


def _entry(name, kdf, status, fields, pre, out):
    return {
        "name": name,
        "kdf": kdf,
        "status": status,
        "fields": [{"name": n, "width": w, "value": v, "hex": h} for n, w, v, h in fields],
        "preimage_len": len(pre),
        "preimage_hex": pre.hex(),
        "output_len": len(out),
        "output_hex": out.hex(),
    }


def build():
    frozen, vectors, rejected = [], [], []

    f, p, job = job_id(KAT_CHAIN_ID, KAT_ADDRESS, KAT_NONCE, KAT_SALT)
    frozen.append(_entry("job_id/kat", "job_id", "FROZEN on main; not part of this proposal", f, p, job))
    f, p, unit = unit_id(job, KAT_UNIT_INDEX)
    frozen.append(_entry("unit_id/kat", "unit_id", "FROZEN on main; not part of this proposal", f, p, unit))

    def add(name, kdf, result):
        f, p, o = result
        vectors.append(_entry(name, kdf, "PROPOSAL", f, p, o))
        return o

    ob = add("offer_bond_id/base", "offer_bond_id",
             offer_bond_id(KAT_CHAIN_ID, KAT_ADDRESS, OFFER_SEQ))
    add("offer_bond_id/chain_id_2", "offer_bond_id",
        offer_bond_id(2, KAT_ADDRESS, OFFER_SEQ))
    add("offer_bond_id/byte_order", "offer_bond_id",
        offer_bond_id(0x0807060504030201, bytes([0xFF] * 20), 0x1122334455667788))
    add("reservation_id/base", "reservation_id",
        reservation_id(job, unit, GENERATION, ob))
    add("entitlement_id/accept_reimb", "entitlement_id",
        entitlement_id(job, unit, GENERATION, ACCEPT_REIMB, 0))
    add("entitlement_id/reassign_reimb_occurrence_2", "entitlement_id",
        entitlement_id(job, unit, GENERATION, REASSIGN_REIMB, 2))
    add("entitlement_id/reprovision_reimb", "entitlement_id",
        entitlement_id(job, unit, GENERATION, REPROVISION_REIMB, 0))
    add("entitlement_id/reassign_reimb_byte_order", "entitlement_id",
        entitlement_id(job, unit, 0x0102030405060708, REASSIGN_REIMB, 0x01020304))

    for kind, occ in [(3, 0), (255, 0), (ACCEPT_REIMB, 1), (REPROVISION_REIMB, 1)]:
        try:
            entitlement_id(job, unit, GENERATION, kind, occ)
        except Rejected as e:
            rejected.append({"kdf": "entitlement_id", "entitlement_kind": kind,
                             "occurrence": occ, "reason": str(e)})
        else:
            raise AssertionError(f"kind {kind} occurrence {occ} was not rejected")

    kdf_of_tag = {"JOB": "job_id", "UNIT": "unit_id",
                  "GRAPHDEF": "graph_definition_root", **PROPOSED_ID_OF_TAG}
    tags = []
    for name, tag in list(FROZEN_TAGS.items()) + list(PROPOSED_TAGS.items()):
        tags.append({
            "name": name,
            "status": "PROPOSAL" if name in PROPOSED_TAGS else "FROZEN on main",
            "kdf": kdf_of_tag[name],
            "ascii": tag.decode("ascii").replace("\n", "\\n"),
            "hex": tag.hex(),
            "len": len(tag),
        })

    return {
        "status": ("PROPOSAL — UNRATIFIED DRAFT. Not recovered §K bytes; not previously "
                   "ratified; not consensus; do not implement until ratified."),
        "hash": "BLAKE3, plain hash mode, 32-byte output",
        "integers": "little-endian",
        "entitlement_kinds": {str(k): v for k, v in KIND_NAMES.items()},
        "tags": tags,
        "frozen_context": frozen,
        "vectors": vectors,
        "rejected": rejected,
    }


def render(doc):
    return json.dumps(doc, indent=2, ensure_ascii=False) + "\n"


if __name__ == "__main__":
    sys.stdout.write(render(build()))
