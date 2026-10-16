#!/usr/bin/env python3
"""SYNTHETIC/UNRATIFIED vectors for the G2 byte-review draft.

UNRATIFIED BYTE-REVIEW DRAFT. Semantics ratified 2026-10-16 (G2); bytes not
ratified. Nothing here is consensus; do not implement until the bytes are
ratified.

Standard library only:
- BLAKE3 (hash mode, 32-byte output) follows the specification's reference
  implementation; the copy in `docs/proposals/c1-pool-id-kdfs/generate.py` is
  the same code.
- Ed25519 follows RFC 8032 section 6 (pure Ed25519, no prehash, no context).

`check.py` verifies both primitives against published test vectors, and
cross-checks against the 2026-09-29 vectors produced with ed25519-dalek,
before it trusts any output.

All keys are test-only seeds [0x01;32]..[0x04;32]. All hashes are synthetic.
No production identity, key, height or configuration appears here.

Usage: python3 generate.py > vectors.json
"""
import hashlib
import json
import struct
import sys

# --------------------------------------------------------------------------- #
# BLAKE3, hash mode only
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
        if hi - lo == 1:
            return outs[lo]
        split = 1 << ((hi - lo - 1).bit_length() - 1)
        left, right = node(lo, lo + split), node(lo + split, hi)
        return (IV, chaining_value(left) + chaining_value(right), 0, BLOCK_LEN, PARENT)

    cv, w, ctr, bl, fl = node(0, len(outs))
    return struct.pack("<16I", *_compress(cv, w, ctr, bl, fl | ROOT))[:OUT_LEN]


# --------------------------------------------------------------------------- #
# Ed25519 (RFC 8032 section 6)
# --------------------------------------------------------------------------- #
_P = 2 ** 255 - 19
_Q = 2 ** 252 + 27742317777372353535851937790883648493


def _inv(x):
    return pow(x, _P - 2, _P)


_D = -121665 * _inv(121666) % _P
_SQRT_M1 = pow(2, (_P - 1) // 4, _P)


def _sha512_modq(s):
    return int.from_bytes(hashlib.sha512(s).digest(), "little") % _Q


def _padd(P, Q):
    a = (P[1] - P[0]) * (Q[1] - Q[0]) % _P
    b = (P[1] + P[0]) * (Q[1] + Q[0]) % _P
    c = 2 * P[3] * Q[3] * _D % _P
    d = 2 * P[2] * Q[2] % _P
    e, f, g, h = b - a, d - c, d + c, b + a
    return (e * f, g * h, f * g, e * h)


def _pmul(s, P):
    Q = (0, 1, 1, 0)
    while s > 0:
        if s & 1:
            Q = _padd(Q, P)
        P = _padd(P, P)
        s >>= 1
    return Q


def _peq(P, Q):
    return ((P[0] * Q[2] - Q[0] * P[2]) % _P == 0
            and (P[1] * Q[2] - Q[1] * P[2]) % _P == 0)


def _recover_x(y, sign):
    if y >= _P:
        return None
    x2 = (y * y - 1) * _inv(_D * y * y + 1)
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (_P + 3) // 8, _P)
    if (x * x - x2) % _P != 0:
        x = x * _SQRT_M1 % _P
    if (x * x - x2) % _P != 0:
        return None
    if (x & 1) != sign:
        x = _P - x
    return x


_GY = 4 * _inv(5) % _P
_GX = _recover_x(_GY, 0)
_G = (_GX, _GY, 1, _GX * _GY % _P)


def _compress_pt(P):
    zi = _inv(P[2])
    x, y = P[0] * zi % _P, P[1] * zi % _P
    return int.to_bytes(y | ((x & 1) << 255), 32, "little")


def _decompress_pt(s):
    y = int.from_bytes(s, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    x = _recover_x(y, sign)
    return None if x is None else (x, y, 1, x * y % _P)


def _expand(seed):
    h = hashlib.sha512(seed).digest()
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    return a, h[32:]


def ed25519_public(seed: bytes) -> bytes:
    a, _ = _expand(seed)
    return _compress_pt(_pmul(a, _G))


def ed25519_sign(seed: bytes, msg: bytes) -> bytes:
    a, prefix = _expand(seed)
    pub = _compress_pt(_pmul(a, _G))
    r = _sha512_modq(prefix + msg)
    rs = _compress_pt(_pmul(r, _G))
    h = _sha512_modq(rs + pub + msg)
    return rs + int.to_bytes((r + h * a) % _Q, 32, "little")


def ed25519_verify(pub: bytes, msg: bytes, sig: bytes) -> bool:
    if len(pub) != 32 or len(sig) != 64:
        return False
    A = _decompress_pt(pub)
    R = _decompress_pt(sig[:32])
    if A is None or R is None:
        return False
    s = int.from_bytes(sig[32:], "little")
    if s >= _Q:
        return False
    h = _sha512_modq(sig[:32] + pub + msg)
    return _peq(_pmul(s, _G), _padd(R, _pmul(h, A)))


# --------------------------------------------------------------------------- #
# Constants (PROPOSED; see README.md)
# --------------------------------------------------------------------------- #
D_VALSET = b"SUMCHAIN/VALSET/v1\0"
D_VOTE = b"SUMCHAIN/FINALITY/VOTE/v1\0"
D_MDIGEST = b"SUMCHAIN/CONSENSUS-UPGRADE-MANIFEST/v1\0"
D_MSIGN = b"SUMCHAIN/CONSENSUS-UPGRADE-MANIFEST/SIGN/v1\0"
D_HANDLER = b"SUMCHAIN/CONSENSUS-UPGRADE-HANDLER/v1\0"
D_SIGNER = b"SUMCHAIN/FINALITY/SIGNER/v1\0"
D_SIGNBYTES = b"SUMCHAIN/FINALITY/SIGNBYTES/v1\0"
# Only to rebuild the 2026-09-29 synthetic commitment (draft header-only
# CCFGv1 encoding, which is NOT the merged schema-1 codec).
D_CCFG = b"SUMCHAIN/CONSENSUS-CONFIG/v1\0"

M_VOTE = b"FVOTv1\0"
M_CERT = b"FCRTv1\0"
M_EVID = b"FEVDv1\0"
M_MANIFEST = b"CUPMv1\0"
M_HINT = b"UHNTv1\0"
M_SIGNER = b"FSGNv1\0"
M_UCONFLICT = b"UCEVv1\0"

DOMAINS = {"D_VALSET": D_VALSET, "D_VOTE": D_VOTE, "D_MDIGEST": D_MDIGEST,
           "D_MSIGN": D_MSIGN, "D_HANDLER": D_HANDLER, "D_SIGNER": D_SIGNER,
           "D_SIGNBYTES": D_SIGNBYTES}
MAGICS = {"M_VOTE": M_VOTE, "M_CERT": M_CERT, "M_EVID": M_EVID,
          "M_MANIFEST": M_MANIFEST, "M_HINT": M_HINT, "M_SIGNER": M_SIGNER,
          "M_UCONFLICT": M_UCONFLICT}
# Retired: never reuse (the 2026-09-29 drafts that G2 supersedes).
RETIRED = {"CUPGv1 magic": b"CUPGv1\0",
           "CUPGv1 domain": b"SUMCHAIN/CONSENSUS-UPGRADE/v1\0",
           "FSAFv1 magic": b"FSAFv1\0",
           "FSAFv1 domain": b"SUMCHAIN/FINALITY/SAFETY/v1\0",
           "FLCKv1 magic": b"FLCKv1\0",
           "FLCKv1 domain": b"SUMCHAIN/FINALITY/LOCK/v1\0"}

SCHEMA = 1
ROUND_CAP = 1 << 20          # D4
QUORUM_HEADCOUNT = 1
VOTE_PREVOTE, VOTE_PRECOMMIT = 1, 2
STEP_PROPOSAL, STEP_PREVOTE, STEP_PRECOMMIT = 1, 2, 3
ZERO32 = bytes(32)

VOTE_BODY_LEN = 113
VOTE_PREIMAGE_LEN = 139
VOTE_WIRE_LEN = 184
CERT_HEADER_LEN = 119
SIG_ENTRY_LEN = 66
EVIDENCE_LEN = 363
MANIFEST_BODY_LEN = 276
MANIFEST_HEADER_LEN = 278      # body + signer_count
HINT_LEN = 122
SIGNER_STATE_LEN = 284
SIGNER_CHECKED_LEN = 252
MIRROR_LEN = 21


class Refused(Exception):
    """A strict decoder or verifier refusal."""


def q(n):
    return 2 * n // 3 + 1


def u8(v):
    if not 0 <= v <= 0xFF:
        raise ValueError(v)
    return bytes([v])


def u16(v):
    return struct.pack("<H", v)


def u32(v):
    return struct.pack("<I", v)


def u64(v):
    return struct.pack("<Q", v)


def be64(v):
    return struct.pack(">Q", v)


def be32(v):
    return struct.pack(">I", v)


def be16(v):
    return struct.pack(">H", v)


# --------------------------------------------------------------------------- #
# Validator-set commitment (unchanged from the 2026-09-29 draft, BL §1)
# --------------------------------------------------------------------------- #
def valset_bytes(pubkeys):
    if not 1 <= len(pubkeys) <= 0xFFFF or len(set(pubkeys)) != len(pubkeys):
        raise Refused("valset size or duplicate key")
    return D_VALSET + u16(len(pubkeys)) + b"".join(pubkeys)


def valset_commitment(pubkeys):
    return blake3(valset_bytes(pubkeys))


# --------------------------------------------------------------------------- #
# Vote (unchanged from BL §3)
# --------------------------------------------------------------------------- #
def vote_body(commit, height, block_id, rnd, vtype, vs, index):
    b = commit + u16(SCHEMA) + u64(height) + block_id + u32(rnd) + u8(vtype) + vs + u16(index)
    assert len(b) == VOTE_BODY_LEN
    return b


def vote_preimage(body):
    return D_VOTE + body


def vote_wire(body, sig):
    return M_VOTE + body + sig


def decode_vote_body(b):
    if len(b) != VOTE_BODY_LEN:
        raise Refused("vote body length")
    commit, schema = b[0:32], struct.unpack_from("<H", b, 32)[0]
    height = struct.unpack_from("<Q", b, 34)[0]
    block_id = b[42:74]
    rnd = struct.unpack_from("<I", b, 74)[0]
    vtype = b[78]
    vs = b[79:111]
    index = struct.unpack_from("<H", b, 111)[0]
    if schema != SCHEMA:
        raise Refused("vote schema")
    if vtype not in (VOTE_PREVOTE, VOTE_PRECOMMIT):
        raise Refused("vote type")
    if rnd > ROUND_CAP:
        raise Refused("round cap")
    return dict(commit=commit, height=height, block_id=block_id, round=rnd,
                vtype=vtype, vs=vs, index=index)


def verify_vote_wire(w, pubkeys, commit, height):
    """Full check of a vote received on the wire, against the set authenticated
    for `height` and this node's effective commitment."""
    if len(w) != VOTE_WIRE_LEN or w[:7] != M_VOTE:
        raise Refused("vote wire length or magic")
    v = decode_vote_body(w[7:120])
    if v["commit"] != commit or v["height"] != height:
        raise Refused("vote commitment or height")
    if v["vs"] != valset_commitment(pubkeys):
        raise Refused("vote valset")
    if v["index"] >= len(pubkeys):
        raise Refused("vote index")
    if not ed25519_verify(pubkeys[v["index"]], vote_preimage(w[7:120]), w[120:]):
        raise Refused("vote signature")
    return v


# --------------------------------------------------------------------------- #
# Certificate (unchanged from BL §4; D2 = no explicit n)
# --------------------------------------------------------------------------- #
def certificate(commit, height, block_id, rnd, vs, signed):
    """`signed` = [(index, signature)] in strictly ascending index order."""
    c = (M_CERT + u16(SCHEMA) + commit + u64(height) + block_id + u32(rnd) + vs
         + u16(len(signed)))
    assert len(c) == CERT_HEADER_LEN
    for i, s in signed:
        c += u16(i) + s
    return c


def verify_certificate(c, pubkeys, commit, height, block_id):
    """What the G2-a batch requires before canonical publication."""
    if len(c) < CERT_HEADER_LEN or c[:7] != M_CERT:
        raise Refused("certificate magic or length")
    if struct.unpack_from("<H", c, 7)[0] != SCHEMA:
        raise Refused("certificate schema")
    ccommit, h = c[9:41], struct.unpack_from("<Q", c, 41)[0]
    bid, rnd, vs = c[49:81], struct.unpack_from("<I", c, 81)[0], c[85:117]
    k = struct.unpack_from("<H", c, 117)[0]
    n = len(pubkeys)
    if len(c) != CERT_HEADER_LEN + SIG_ENTRY_LEN * k:
        raise Refused("certificate length")
    if bid == ZERO32:
        raise Refused("certificate nil block")
    if rnd > ROUND_CAP:
        raise Refused("round cap")
    if ccommit != commit or h != height or bid != block_id:
        raise Refused("certificate does not name this block")
    if vs != valset_commitment(pubkeys):
        raise Refused("certificate valset")
    if k < q(n) or k > n:
        raise Refused("certificate signer count")
    last = -1
    for j in range(k):
        off = CERT_HEADER_LEN + SIG_ENTRY_LEN * j
        i = struct.unpack_from("<H", c, off)[0]
        if i <= last or i >= n:
            raise Refused("certificate index order")
        last = i
        body = vote_body(ccommit, h, bid, rnd, VOTE_PRECOMMIT, vs, i)
        if not ed25519_verify(pubkeys[i], vote_preimage(body), c[off + 2:off + 66]):
            raise Refused("certificate signature")
    return dict(height=h, block_id=bid, round=rnd, k=k)


# --------------------------------------------------------------------------- #
# Equivocation evidence (unchanged from BL §5)
# --------------------------------------------------------------------------- #
def equivocation_evidence(body_a, sig_a, body_b, sig_b):
    if body_a[42:74] > body_b[42:74]:
        body_a, sig_a, body_b, sig_b = body_b, sig_b, body_a, sig_a
    return M_EVID + u16(SCHEMA) + body_a + sig_a + body_b + sig_b


def verify_equivocation_evidence(e, pubkeys):
    if len(e) != EVIDENCE_LEN or e[:7] != M_EVID:
        raise Refused("evidence length or magic")
    if struct.unpack_from("<H", e, 7)[0] != SCHEMA:
        raise Refused("evidence schema")
    ba, sa = e[9:122], e[122:186]
    bb, sb = e[186:299], e[299:363]
    va, vb = decode_vote_body(ba), decode_vote_body(bb)
    same = ("commit", "height", "round", "vtype", "vs", "index")
    if any(va[f] != vb[f] for f in same):
        raise Refused("evidence votes are not for one slot")
    if not va["block_id"] < vb["block_id"]:
        raise Refused("evidence not canonical (or identical blocks)")
    if va["vs"] != valset_commitment(pubkeys) or va["index"] >= len(pubkeys):
        raise Refused("evidence valset or index")
    pk = pubkeys[va["index"]]
    if not (ed25519_verify(pk, vote_preimage(ba), sa) and ed25519_verify(pk, vote_preimage(bb), sb)):
        raise Refused("evidence signature")
    return va


def evidence_key(height, rnd, vtype, index):
    return be64(height) + be32(rnd) + u8(vtype) + be16(index)


# --------------------------------------------------------------------------- #
# ConsensusUpgradeManifestV1 (new; supersedes BL R3 CUPGv1)
# --------------------------------------------------------------------------- #
def handler_digest(name: str, version: int):
    nb = name.encode("ascii")
    if not 1 <= len(nb) <= 64 or not all(ch in b"abcdefghijklmnopqrstuvwxyz0123456789-" for ch in nb):
        raise Refused("handler name")
    return blake3(D_HANDLER + u8(len(nb)) + nb + u16(version))


def manifest_body(m):
    b = (M_MANIFEST + u16(SCHEMA) + u64(m["chain_id"]) + m["genesis_block_hash"]
         + u64(m["sequence"]) + m["previous_manifest_digest"]
         + m["old_config_commitment"] + m["new_config_commitment"]
         + u16(m["protocol_version"]) + u64(m["checkpoint_height"])
         + m["checkpoint_block_hash"] + u64(m["activation_height"])
         + u64(m["signing_deadline_height"]) + m["validator_set_commitment"]
         + u8(m["quorum_rule"]) + m["handler_digest"])
    assert len(b) == MANIFEST_BODY_LEN
    return b


def manifest_digest(body):
    return blake3(D_MDIGEST + body)


def manifest_sign_message(body):
    return D_MSIGN + body


def manifest(body, signed):
    out = body + u16(len(signed))
    for i, s in signed:
        out += u16(i) + s
    return out


def decode_manifest(b, min_notice=0):
    """Structural checks only (no keys needed). `min_notice` is an injected
    parameter; its value is NOT part of this review."""
    if len(b) < MANIFEST_HEADER_LEN or b[:7] != M_MANIFEST:
        raise Refused("manifest magic or length")
    f = {}
    f["schema"] = struct.unpack_from("<H", b, 7)[0]
    f["chain_id"] = struct.unpack_from("<Q", b, 9)[0]
    f["genesis_block_hash"] = b[17:49]
    f["sequence"] = struct.unpack_from("<Q", b, 49)[0]
    f["previous_manifest_digest"] = b[57:89]
    f["old_config_commitment"] = b[89:121]
    f["new_config_commitment"] = b[121:153]
    f["protocol_version"] = struct.unpack_from("<H", b, 153)[0]
    f["checkpoint_height"] = struct.unpack_from("<Q", b, 155)[0]
    f["checkpoint_block_hash"] = b[163:195]
    f["activation_height"] = struct.unpack_from("<Q", b, 195)[0]
    f["signing_deadline_height"] = struct.unpack_from("<Q", b, 203)[0]
    f["validator_set_commitment"] = b[211:243]
    f["quorum_rule"] = b[243]
    f["handler_digest"] = b[244:276]
    k = struct.unpack_from("<H", b, 276)[0]
    if f["schema"] != SCHEMA:
        raise Refused("manifest schema")
    if len(b) != MANIFEST_HEADER_LEN + SIG_ENTRY_LEN * k:
        raise Refused("manifest length")
    if f["quorum_rule"] != QUORUM_HEADCOUNT:
        raise Refused("manifest quorum rule")
    if f["sequence"] < 1:
        raise Refused("manifest sequence")
    if (f["sequence"] == 1) != (f["previous_manifest_digest"] == ZERO32):
        raise Refused("manifest previous digest")
    if f["old_config_commitment"] == f["new_config_commitment"]:
        raise Refused("manifest changes nothing")
    if f["protocol_version"] < 2:
        raise Refused("manifest protocol version")
    if f["checkpoint_block_hash"] == ZERO32:
        raise Refused("manifest checkpoint hash")
    if not f["checkpoint_height"] < f["signing_deadline_height"] < f["activation_height"]:
        raise Refused("manifest height order")
    if f["activation_height"] - f["signing_deadline_height"] < min_notice:
        raise Refused("manifest notice")
    if k < 1:
        raise Refused("manifest unsigned")
    entries, last = [], -1
    for j in range(k):
        off = MANIFEST_HEADER_LEN + SIG_ENTRY_LEN * j
        i = struct.unpack_from("<H", b, off)[0]
        if i <= last:
            raise Refused("manifest index order")
        last = i
        entries.append((i, b[off + 2:off + 66]))
    f["k"], f["entries"], f["body"] = k, entries, b[:MANIFEST_BODY_LEN]
    f["digest"] = manifest_digest(f["body"])
    return f


def verify_bootstrap_manifest(b, genesis_pubkeys, chain_id, genesis_block_hash, min_notice=0):
    """G2-c authentication of the FIRST bootstrap authorization: genesis
    membership authenticates sequence 1 only (open choice M4 in README)."""
    f = decode_manifest(b, min_notice)
    if f["chain_id"] != chain_id or f["genesis_block_hash"] != genesis_block_hash:
        raise Refused("manifest chain identity")
    if f["sequence"] != 1:
        raise Refused("genesis membership authenticates the first bootstrap only")
    if f["validator_set_commitment"] != valset_commitment(genesis_pubkeys):
        raise Refused("manifest validator set is not genesis membership")
    n = len(genesis_pubkeys)
    if f["k"] < q(n) or f["k"] > n:
        raise Refused("manifest signer count")
    msg = manifest_sign_message(f["body"])
    for i, s in f["entries"]:
        if i >= n or not ed25519_verify(genesis_pubkeys[i], msg, s):
            raise Refused("manifest signature")
    return f


# --------------------------------------------------------------------------- #
# Upgrade-conflict evidence (new)
# --------------------------------------------------------------------------- #
def upgrade_conflict_evidence(ma, mb):
    da, db = manifest_digest(ma[:MANIFEST_BODY_LEN]), manifest_digest(mb[:MANIFEST_BODY_LEN])
    if db < da:
        ma, mb = mb, ma
    return M_UCONFLICT + u16(SCHEMA) + u32(len(ma)) + ma + u32(len(mb)) + mb


def verify_upgrade_conflict_evidence(e, genesis_pubkeys, chain_id, genesis_block_hash):
    if len(e) < 13 or e[:7] != M_UCONFLICT:
        raise Refused("conflict evidence magic or length")
    if struct.unpack_from("<H", e, 7)[0] != SCHEMA:
        raise Refused("conflict evidence schema")
    la = struct.unpack_from("<I", e, 9)[0]
    if len(e) < 13 + la + 4:
        raise Refused("conflict evidence length")
    ma = e[13:13 + la]
    lb = struct.unpack_from("<I", e, 13 + la)[0]
    if len(e) != 17 + la + lb:
        raise Refused("conflict evidence length")
    mb = e[17 + la:]
    fa = verify_bootstrap_manifest(ma, genesis_pubkeys, chain_id, genesis_block_hash)
    fb = verify_bootstrap_manifest(mb, genesis_pubkeys, chain_id, genesis_block_hash)
    if fa["sequence"] != fb["sequence"]:
        raise Refused("conflict evidence sequences differ")
    if not fa["digest"] < fb["digest"]:
        raise Refused("conflict evidence not canonical (or same body)")
    return fa, fb


def conflict_key(sequence):
    return b"upgrade/conflict/v1/" + be64(sequence)


# --------------------------------------------------------------------------- #
# Handshake hint UpgradeHintV1 (new)
# --------------------------------------------------------------------------- #
def hint(genesis_block_hash, applied_sequence, applied_digest, nxt=None):
    """`nxt` = (manifest_digest, activation_height) of a fully verified,
    not-yet-applied manifest with sequence applied_sequence + 1, or None."""
    nd, nh, present = (ZERO32, 0, 0) if nxt is None else (nxt[0], nxt[1], 1)
    h = (M_HINT + u16(SCHEMA) + genesis_block_hash + u64(applied_sequence)
         + applied_digest + u8(present) + nd + u64(nh))
    assert len(h) == HINT_LEN
    decode_hint(h)
    return h


def decode_hint(h):
    """Structure only. A hint NEVER authorizes, applies, halts or creates
    evidence (G2-c); acting on it requires the full manifest bytes."""
    if len(h) != HINT_LEN or h[:7] != M_HINT:
        raise Refused("hint length or magic")
    if struct.unpack_from("<H", h, 7)[0] != SCHEMA:
        raise Refused("hint schema")
    seq = struct.unpack_from("<Q", h, 41)[0]
    ad, present = h[49:81], h[81]
    nd, nh = h[82:114], struct.unpack_from("<Q", h, 114)[0]
    if (seq == 0) != (ad == ZERO32):
        raise Refused("hint applied digest")
    if present not in (0, 1):
        raise Refused("hint flag")
    if present == 0 and (nd != ZERO32 or nh != 0):
        raise Refused("hint absent next is not zero")
    if present == 1 and (nd == ZERO32 or nh == 0):
        raise Refused("hint next incomplete")
    return dict(genesis_block_hash=h[9:41], applied_sequence=seq, applied_digest=ad,
                next_present=present, next_digest=nd, next_activation_height=nh)


# --------------------------------------------------------------------------- #
# Signer state SignerStateV1 (new; replaces BL §6 FinalitySafetyStateV1)
# --------------------------------------------------------------------------- #
def sign_bytes_digest(sign_bytes):
    return blake3(D_SIGNBYTES + sign_bytes)


def signer_state(counter, chain_id, genesis_block_hash, signer_pubkey, floor_height,
                 last=None, lock=None):
    """`last` = (height, round, step, sign_bytes_digest, signature) or None;
    `lock` = (height, round, value) or None."""
    s = (M_SIGNER + u16(SCHEMA) + u64(counter) + u64(chain_id) + genesis_block_hash
         + signer_pubkey + u64(floor_height))
    if last is None:
        s += u8(0) + bytes(8 + 4 + 1 + 32 + 64)
    else:
        lh, lr, st, dg, sg = last
        s += u8(1) + u64(lh) + u32(lr) + u8(st) + dg + sg
    if lock is None:
        s += u8(0) + bytes(8 + 4 + 32)
    else:
        kh, kr, kv = lock
        s += u8(1) + u64(kh) + u32(kr) + kv
    assert len(s) == SIGNER_CHECKED_LEN
    s += blake3(D_SIGNER + s)
    assert len(s) == SIGNER_STATE_LEN
    decode_signer_state(s)
    return s


def decode_signer_state(s, expected_pubkey=None):
    if len(s) != SIGNER_STATE_LEN or s[:7] != M_SIGNER:
        raise Refused("signer state length or magic")
    if blake3(D_SIGNER + s[:SIGNER_CHECKED_LEN]) != s[SIGNER_CHECKED_LEN:]:
        raise Refused("signer state checksum")
    if struct.unpack_from("<H", s, 7)[0] != SCHEMA:
        raise Refused("signer state schema")
    f = dict(counter=struct.unpack_from("<Q", s, 9)[0],
             chain_id=struct.unpack_from("<Q", s, 17)[0],
             genesis_block_hash=s[25:57], signer_pubkey=s[57:89],
             floor_height=struct.unpack_from("<Q", s, 89)[0])
    lp, kp = s[97], s[207]
    if lp not in (0, 1) or kp not in (0, 1):
        raise Refused("signer state flag")
    if lp == 0:
        if s[98:207] != bytes(109):
            raise Refused("signer state absent last is not zero")
        f["last"] = None
    else:
        lh, lr, st = struct.unpack_from("<Q", s, 98)[0], struct.unpack_from("<I", s, 106)[0], s[110]
        if st not in (STEP_PROPOSAL, STEP_PREVOTE, STEP_PRECOMMIT):
            raise Refused("signer state step")
        if lr > ROUND_CAP or lh < f["floor_height"]:
            raise Refused("signer state last below floor or round cap")
        f["last"] = (lh, lr, st, s[111:143], s[143:207])
    if kp == 0:
        if s[208:252] != bytes(44):
            raise Refused("signer state absent lock is not zero")
        f["lock"] = None
    else:
        kh, kr, kv = struct.unpack_from("<Q", s, 208)[0], struct.unpack_from("<I", s, 216)[0], s[220:252]
        if kv == ZERO32 or kr > ROUND_CAP or kh < f["floor_height"]:
            raise Refused("signer state lock")
        f["lock"] = (kh, kr, kv)
    if f["counter"] == 0 and (lp or kp):
        raise Refused("signer state initialization record must be empty")
    if expected_pubkey is not None and f["signer_pubkey"] != expected_pubkey:
        raise Refused("signer state belongs to another key")
    return f


def signer_mirror(counter, height, rnd, step):
    m = u64(counter) + u64(height) + u32(rnd) + u8(step)
    assert len(m) == MIRROR_LEN
    return m


# --------------------------------------------------------------------------- #
# Storage forms used by the G2-a batch (BL §7 keys; injected via #292's seam)
# --------------------------------------------------------------------------- #
def certificate_key(height, block_id):
    return be64(height) + block_id


def pointer_value(height, block_id):
    return u64(height) + block_id


# --------------------------------------------------------------------------- #
# Synthetic inputs and vectors
# --------------------------------------------------------------------------- #
CHAIN_ID = 4242
SEEDS = [bytes([i]) * 32 for i in range(1, 5)]


def synthetic_commitment():
    # The 2026-09-29 draft's header-only CCFGv1 bytes (schema 1, chain 4242,
    # rule bytes 1,1,1,1,1,0,1, zero fields). A stand-in 32-byte commitment;
    # NOT the merged schema-1 ConsensusConfig codec.
    hdr = b"CCFGv1\0" + u16(1) + u64(CHAIN_ID) + bytes([1, 1, 1, 1, 1, 0, 1]) + u16(0)
    return blake3(D_CCFG + hdr)


def build():
    keys = [(sd, ed25519_public(sd)) for sd in SEEDS]
    pk = [p for _, p in keys]
    commit = synthetic_commitment()
    block = blake3(b"example block at height 7")
    other = blake3(b"conflicting block at height 7")
    genesis = blake3(b"synthetic genesis block 4242")
    new_cfg = blake3(b"synthetic proposed config 4242")
    checkpoint = blake3(b"synthetic checkpoint block 90000")
    vs4, vs2 = valset_commitment(pk), valset_commitment(pk[:2])

    vec = []

    def add(name, obj, value, inputs=None, serves=None):
        vec.append(dict(name=name, object=obj, status="SYNTHETIC/UNRATIFIED",
                        serves=serves or "", inputs=inputs or {},
                        length=len(value), hex=value.hex()))

    for i, p in enumerate(pk):
        add(f"pubkey[{i}]", "test key", p, {"seed": SEEDS[i].hex()})
    add("valset n=4", "validator-set commitment preimage", valset_bytes(pk), serves="G2-a, G2-c, G2-d")
    add("valset n=4 commitment", "validator-set commitment", vs4)
    add("valset n=2 commitment", "validator-set commitment", vs2)
    add("synthetic config commitment", "stand-in commitment", commit,
        {"note": "draft header-only CCFGv1, chain 4242; not the merged codec"})

    # Votes (n=4).
    pre_body = vote_body(commit, 7, block, 0, VOTE_PRECOMMIT, vs4, 1)
    pre_sig = ed25519_sign(SEEDS[1], vote_preimage(pre_body))
    add("vote precommit h=7 r=0 idx=1 preimage", "FinalityVoteV1 preimage", vote_preimage(pre_body),
        {"height": 7, "round": 0, "type": "precommit", "index": 1}, "G2-a, G2-b")
    add("vote precommit h=7 r=0 idx=1 signature", "Ed25519", pre_sig)
    add("vote precommit h=7 r=0 idx=1 wire", "FinalityVoteV1 wire", vote_wire(pre_body, pre_sig))
    nil_body = vote_body(commit, 7, ZERO32, 1, VOTE_PREVOTE, vs4, 0)
    add("vote nil prevote h=7 r=1 idx=0 wire", "FinalityVoteV1 wire",
        vote_wire(nil_body, ed25519_sign(SEEDS[0], vote_preimage(nil_body))))

    # Certificates.
    def cert(pubs, seeds, vs, idx):
        signed = [(i, ed25519_sign(seeds[i], vote_preimage(
            vote_body(commit, 7, block, 0, VOTE_PRECOMMIT, vs, i)))) for i in idx]
        return certificate(commit, 7, block, 0, vs, signed)

    add("certificate n=4 h=7 r=0 signers {0,1,3}", "FinalityCertificateV1",
        cert(pk, SEEDS, vs4, [0, 1, 3]), {"n": 4, "k": 3}, "G2-a")
    add("certificate n=2 h=7 r=0 signers {0,1}", "FinalityCertificateV1",
        cert(pk[:2], SEEDS[:2], vs2, [0, 1]), {"n": 2, "k": 2}, "G2-a")
    add("certificate CF key h=7", "storage key (BE)", certificate_key(7, block))
    add("finalized pointer h=7", "storage value (LE)", pointer_value(7, block))

    # Equivocation evidence (validator 2, (7, 0, precommit)).
    ba = vote_body(commit, 7, block, 0, VOTE_PRECOMMIT, vs4, 2)
    bb = vote_body(commit, 7, other, 0, VOTE_PRECOMMIT, vs4, 2)
    ev = equivocation_evidence(ba, ed25519_sign(SEEDS[2], vote_preimage(ba)),
                               bb, ed25519_sign(SEEDS[2], vote_preimage(bb)))
    add("equivocation evidence idx=2 h=7 r=0 precommit", "EquivocationEvidenceV1", ev, serves="G2-b")
    add("equivocation evidence key", "storage key (BE)", evidence_key(7, 0, VOTE_PRECOMMIT, 2))

    # Bootstrap manifest over a synthetic n=2 genesis set (both must sign).
    hd = handler_digest("certified-finality", 1)
    add("handler digest certified-finality v1", "handler identity", hd,
        {"name": "certified-finality", "version": 1})
    base = dict(chain_id=CHAIN_ID, genesis_block_hash=genesis, sequence=1,
                previous_manifest_digest=ZERO32, old_config_commitment=commit,
                new_config_commitment=new_cfg, protocol_version=2,
                checkpoint_height=90_000, checkpoint_block_hash=checkpoint,
                activation_height=100_000, signing_deadline_height=95_000,
                validator_set_commitment=vs2, quorum_rule=QUORUM_HEADCOUNT, handler_digest=hd)
    manifests = {}
    for label, act in (("A", 100_000), ("B", 100_100)):
        m = dict(base, activation_height=act)
        body = manifest_body(m)
        msg = manifest_sign_message(body)
        full = manifest(body, [(i, ed25519_sign(SEEDS[i], msg)) for i in (0, 1)])
        manifests[label] = full
        inputs = {k: (v.hex() if isinstance(v, bytes) else v) for k, v in m.items()}
        add(f"manifest {label} body", "ConsensusUpgradeManifestV1 body", body, inputs, "G2-c")
        add(f"manifest {label} digest", "manifest digest", manifest_digest(body))
        add(f"manifest {label} n=2 both signers", "ConsensusUpgradeManifestV1", full)
    uc = upgrade_conflict_evidence(manifests["A"], manifests["B"])
    add("upgrade-conflict evidence A/B sequence 1", "UpgradeConflictEvidenceV1", uc, serves="G2-c")
    add("upgrade-conflict evidence key sequence 1", "storage key", conflict_key(1))

    da = manifest_digest(manifests["A"][:MANIFEST_BODY_LEN])
    add("hint before H (nothing applied; A pending)", "UpgradeHintV1",
        hint(genesis, 0, ZERO32, (da, 100_000)), serves="G2-c (hint only)")
    add("hint after H (A applied; nothing pending)", "UpgradeHintV1", hint(genesis, 1, da))

    # Signer state of validator 1 (n=4 set), initialized with floor 7.
    init = signer_state(0, CHAIN_ID, genesis, pk[1], 7)
    add("signer state initialized floor=7 (validator 1)", "SignerStateV1", init,
        {"counter": 0, "floor_height": 7}, "G2-b")
    add("signer mirror initialized", "SignerMirrorV1", signer_mirror(0, 7, 0, 0))
    after = signer_state(1, CHAIN_ID, genesis, pk[1], 7,
                         last=(7, 0, STEP_PRECOMMIT, sign_bytes_digest(vote_preimage(pre_body)), pre_sig),
                         lock=(7, 0, block))
    add("signer state after precommit h=7 r=0 (locked)", "SignerStateV1", after,
        {"counter": 1, "last": "the precommit vector above", "lock": [7, 0, block.hex()]}, "G2-b")
    add("signer mirror after precommit", "SignerMirrorV1", signer_mirror(1, 7, 0, STEP_PRECOMMIT))

    return dict(
        title="G2 byte-review draft vectors",
        status=("UNRATIFIED BYTE-REVIEW DRAFT. Semantics ratified 2026-10-16 (G2); bytes not "
                "ratified. Every vector is SYNTHETIC/UNRATIFIED."),
        keys="test-only Ed25519 seeds [0x01;32]..[0x04;32]",
        domains={k: v.decode("ascii").replace("\0", "\\0") for k, v in DOMAINS.items()},
        magics={k: v.decode("ascii").replace("\0", "\\0") for k, v in MAGICS.items()},
        vectors=vec,
    )


def render(doc):
    return json.dumps(doc, indent=1) + "\n"


if __name__ == "__main__":
    sys.stdout.write(render(build()))
