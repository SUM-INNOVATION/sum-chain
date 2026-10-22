#!/usr/bin/env python3
"""Mechanical checks for the G2 byte-review draft. Exits nonzero on any failure.

UNRATIFIED BYTE-REVIEW DRAFT. Semantics ratified 2026-10-16 (G2); bytes not
ratified. Every vector is SYNTHETIC/UNRATIFIED.

Checks:
1. BLAKE3 against the official test vectors.
2. Ed25519 against RFC 8032 section 7.1 TEST 1, plus a negative case.
3. Cross-implementation: the 2026-09-29 vectors produced with
   ed25519-dalek and blake3 1.8.2 (`crosscheck-20260929.json`) are reproduced
   byte for byte for every object whose layout is unchanged.
4. Every length in the README tables, for every vector.
5. Every vector passes its strict decoder/verifier; every single-byte flip,
   truncation and trailing byte is refused; named refusal cases are refused.
6. Domains and magics: NUL only at the end, distinct, prefix-free, and no
   clash with retired drafts or with any byte-string literal under `crates/`.
   A ratified constant may be spelled exactly, and only, in its implementation
   file (`RATIFIED_HOME`).
7. Determinism: two builds are identical and equal `vectors.json`.
8. Every 32-byte-or-longer hex string in README.md appears in `vectors.json`
   or the cross-check file.

Usage: python3 check.py
"""
import json
import os
import re
import sys

sys.dont_write_bytecode = True
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import generate as g  # noqa: E402

# Official BLAKE3 test vectors: test_vectors/test_vectors.json at tag 1.8.2 of
# https://github.com/BLAKE3-team/BLAKE3 (file sha256
# dcb91ea8accc77e6d6e632af7cdc1a99a9f3ae78cf648da595c7d064db32f624), as
# recorded in docs/proposals/c1-pool-id-kdfs/check.py. Input is
# bytes(i % 251 for i in range(input_len)); value = first 32 bytes of "hash".
OFFICIAL = [
    (0, "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"),
    (1, "2d3adedff11b61f14c886e35afa036736dcd87a74d27b5c1510225d0f592e213"),
    (2, "7b7015bb92cf0b318037702a6cdd81dee41224f734684c2c122cd6359cb1ee63"),
    (3, "e1be4d7a8ab5560aa4199eea339849ba8e293d55ca0a81006726d184519e647f"),
    (4, "f30f5ab28fe047904037f77b6da4fea1e27241c5d132638d8bedce9d40494f32"),
    (5, "b40b44dfd97e7a84a996a91af8b85188c66c126940ba7aad2e7ae6b385402aa2"),
    (6, "06c4e8ffb6872fad96f9aaca5eee1553eb62aed0ad7198cef42e87f6a616c844"),
    (7, "3f8770f387faad08faa9d8414e9f449ac68e6ff0417f673f602a646a891419fe"),
    (8, "2351207d04fc16ade43ccab08600939c7c1fa70a5c0aaca76063d04c3228eaeb"),
    (63, "e9bc37a594daad83be9470df7f7b3798297c3d834ce80ba85d6e207627b7db7b"),
    (64, "4eed7141ea4a5cd4b788606bd23f46e212af9cacebacdc7d1f4c6dc7f2511b98"),
    (65, "de1e5fa0be70df6d2be8fffd0e99ceaa8eb6e8c93a63f2d8d1c30ecb6b263dee"),
    (127, "d81293fda863f008c09e92fc382a81f5a0b4a1251cba1634016a0f86a6bd640d"),
    (128, "f17e570564b26578c33bb7f44643f539624b05df1a76c81f30acd548c44b45ef"),
    (129, "683aaae9f3c5ba37eaaf072aed0f9e30bac0865137bae68b1fde4ca2aebdcb12"),
    (1023, "10108970eeda3eb932baac1428c7a2163b0e924c9a9e25b35bba72b28f70bd11"),
    (1024, "42214739f095a406f3fc83deb889744ac00df831c10daa55189b5d121c855af7"),
    (1025, "d00278ae47eb27b34faecf67b4fe263f82d5412916c1ffd97c8cb7fb814b8444"),
    (2048, "e776b6028c7cd22a4d0ba182a8bf62205d2ef576467e838ed6f2529b85fba24a"),
    (2049, "5f4d72f40d7a5f82b15ca2b2e44b1de3c2ef86c426c95c1af0b6879522563030"),
    (3072, "b98cb0ff3623be03326b373de6b9095218513e64f1ee2edd2525c7ad1e5cffd2"),
    (3073, "7124b49501012f81cc7f11ca069ec9226cecb8a2c850cfe644e327d22d3e1cd3"),
    (4096, "015094013f57a5277b59d8475c0501042c0b642e531b0a1c8f58d2163229e969"),
    (4097, "9b4052b38f1c5fc8b1f9ff7ac7b27cd242487b3d890d15c96a1c25b8aa0fb995"),
    (5120, "9cadc15fed8b5d854562b26a9536d9707cadeda9b143978f319ab34230535833"),
    (5121, "628bd2cb2004694adaab7bbd778a25df25c47b9d4155a55f8fbd79f2fe154cff"),
    (6144, "3e2e5b74e048f3add6d21faab3f83aa44d3b2278afb83b80b3c35164ebeca205"),
    (6145, "f1323a8631446cc50536a9f705ee5cb619424d46887f3c376c695b70e0f0507f"),
    (7168, "61da957ec2499a95d6b8023e2b0e604ec7f6b50e80a9678b89d2628e99ada77a"),
    (7169, "a003fc7a51754a9b3c7fae0367ab3d782dccf28855a03d435f8cfe74605e7817"),
    (8192, "aae792484c8efe4f19e2ca7d371d8c467ffb10748d8a5a1ae579948f718a2a63"),
    (8193, "bab6c09cb8ce8cf459261398d2e7aef35700bf488116ceb94a36d0f5f1b7bc3b"),
    (16384, "f875d6646de28985646f34ee13be9a576fd515f76b5b0a26bb324735041ddde4"),
    (31744, "62b6960e1a44bcc1eb1a611a8d6235b6b4b78f32e7abc4fb4c6cdcce94895c47"),
    (102400, "bc3e3d41a1146b069abffad3c0d44860cf664390afce4d9661f7902e7943e085"),
]

# RFC 8032 section 7.1, TEST 1 (empty message).
RFC8032_T1 = dict(
    secret="9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
    public="d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
    signature=("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
               "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"),
)

# Expected object lengths (README tables). k = signer count.
LENGTHS = {
    "FinalityVoteV1 preimage": lambda v: 139,
    "FinalityVoteV1 wire": lambda v: 184,
    "FinalityCertificateV1": lambda v: 119 + 66 * v["inputs"]["k"],
    "EquivocationEvidenceV1": lambda v: 363,
    "ConsensusUpgradeManifestV1 body": lambda v: 276,
    "ConsensusUpgradeManifestV1": lambda v: 278 + 66 * 2,
    "UpgradeConflictEvidenceV1": lambda v: 17 + 2 * (278 + 66 * 2),
    "UpgradeHintV1": lambda v: 122,
    "SignerStateV1": lambda v: 284,
    "SignerMirrorV1": lambda v: 21,
    "storage key (BE)": lambda v: 40 if "certificate" in v["name"] else 15,
    "storage value (LE)": lambda v: 40,
    "storage key": lambda v: 28,
    "validator-set commitment preimage": lambda v: 19 + 2 + 32 * 4,
    "validator-set commitment": lambda v: 32,
    "manifest digest": lambda v: 32,
    "handler identity": lambda v: 32,
    "stand-in commitment": lambda v: 32,
    "test key": lambda v: 32,
    "Ed25519": lambda v: 64,
}

failures = []
passes = 0


def check(cond, what):
    global passes
    if cond:
        passes += 1
    else:
        failures.append(what)
        print("FAIL:", what)


def refused(fn, *a, **k):
    try:
        fn(*a, **k)
    except g.Refused:
        return True
    except (ValueError, IndexError, KeyError, AssertionError):
        return True
    return False


def flips_all_refused(blob, validate, name, stride=1):
    """Every single-byte flip, every 1-byte truncation and a trailing byte."""
    bad = []
    for i in range(0, len(blob), stride):
        m = bytearray(blob)
        m[i] ^= 0x01
        if not refused(validate, bytes(m)):
            bad.append(i)
    check(not bad, f"{name}: every single-byte flip refused (unrefused offsets {bad[:8]})")
    check(refused(validate, blob[:-1]), f"{name}: truncation refused")
    check(refused(validate, blob + b"\0"), f"{name}: trailing byte refused")


def rust_byte_literals(root):
    """Every byte-string literal under crates/, with the files it appears in."""
    lits = {}
    pat = re.compile(rb'b"((?:[^"\\]|\\.)*)"')
    for dp, _, fns in os.walk(os.path.join(root, "crates")):
        for fn in fns:
            if fn.endswith(".rs"):
                path = os.path.relpath(os.path.join(dp, fn), root)
                with open(os.path.join(dp, fn), "rb") as fh:
                    for m in pat.finditer(fh.read()):
                        raw = m.group(1).replace(rb"\0", b"\0").replace(rb"\n", b"\n")
                        lits.setdefault(raw, set()).add(path)
    return lits


# Ratified constants and the one file allowed to spell them (group V,
# ratified 2026-10-17; group C, ratified 2026-10-19). Anywhere else, the clash
# check below still refuses them.
RATIFIED_HOME = {
    "D_VOTE": "crates/finality-foundations/src/vote.rs",
    "M_VOTE": "crates/finality-foundations/src/vote.rs",
    "M_CERT": "crates/finality-foundations/src/certificate.rs",
    # Group A2, the signer-state format of #340, ratified by the owner on
    # 2026-10-22 (dormant).
    "D_SIGNER": "crates/finality-foundations/src/signer_file.rs",
    "D_SIGNBYTES": "crates/finality-foundations/src/signer_file.rs",
    "M_SIGNER": "crates/finality-foundations/src/signer_file.rs",
}


def main():
    # 1. BLAKE3.
    for n, want in OFFICIAL:
        check(g.blake3(bytes(i % 251 for i in range(n))).hex() == want, f"BLAKE3 official len {n}")

    # 2. Ed25519 RFC 8032 TEST 1.
    sk = bytes.fromhex(RFC8032_T1["secret"])
    check(g.ed25519_public(sk).hex() == RFC8032_T1["public"], "RFC 8032 TEST 1 public key")
    sig = g.ed25519_sign(sk, b"")
    check(sig.hex() == RFC8032_T1["signature"], "RFC 8032 TEST 1 signature")
    check(g.ed25519_verify(bytes.fromhex(RFC8032_T1["public"]), b"", sig), "RFC 8032 TEST 1 verifies")
    check(not g.ed25519_verify(bytes.fromhex(RFC8032_T1["public"]), b"\0", sig), "Ed25519 refuses altered message")

    # 3. Cross-implementation against the dalek-produced 2026-09-29 vectors.
    with open(os.path.join(HERE, "crosscheck-20260929.json")) as fh:
        xc = json.load(fh)
    doc = g.build()
    v = {x["name"]: x for x in doc["vectors"]}
    hx = {k: x["hex"] for k, x in v.items()}
    for i in range(4):
        check(hx[f"pubkey[{i}]"] == xc["pk"][i], f"dalek cross-check pubkey[{i}]")
    pairs = [
        ("valset n=4", "valset_n4_bytes"),
        ("valset n=4 commitment", "valset_n4_commitment"),
        ("valset n=2 commitment", "valset_n2_commitment"),
        ("synthetic config commitment", "ccfg_header_commitment"),
        ("vote precommit h=7 r=0 idx=1 preimage", "vote_precommit_preimage"),
        ("vote precommit h=7 r=0 idx=1 signature", "vote_precommit_sig"),
        ("vote precommit h=7 r=0 idx=1 wire", "vote_precommit_wire"),
        ("vote nil prevote h=7 r=1 idx=0 wire", "vote_nil_prevote_wire"),
        ("certificate n=4 h=7 r=0 signers {0,1,3}", "certificate_n4"),
        ("equivocation evidence idx=2 h=7 r=0 precommit", "equivocation_evidence"),
        ("certificate CF key h=7", "cert_cf_key"),
        ("finalized pointer h=7", "pointer_value"),
    ]
    for mine, theirs in pairs:
        check(hx[mine] == xc[theirs], f"dalek cross-check {mine}")

    # 4. Lengths.
    for x in doc["vectors"]:
        want = LENGTHS[x["object"]](x)
        check(x["length"] == want == len(bytes.fromhex(x["hex"])), f"length {x['name']} = {want}")
    check(len(g.D_VALSET) == 19 and len(g.D_VOTE) == 26 and len(g.D_MDIGEST) == 39
          and len(g.D_MSIGN) == 44 and len(g.D_HANDLER) == 38 and len(g.D_SIGNER) == 28
          and len(g.D_SIGNBYTES) == 31, "domain lengths")
    check(all(len(m) == 7 for m in g.MAGICS.values()), "magic lengths")

    # 5. Strict decoders, verifiers, mutations and refusal cases.
    pk = [bytes.fromhex(hx[f"pubkey[{i}]"]) for i in range(4)]
    commit = bytes.fromhex(hx["synthetic config commitment"])
    block = g.blake3(b"example block at height 7")
    genesis = g.blake3(b"synthetic genesis block 4242")
    B = lambda name: bytes.fromhex(hx[name])  # noqa: E731

    vw = B("vote precommit h=7 r=0 idx=1 wire")
    check(not refused(g.verify_vote_wire, vw, pk, commit, 7), "vote verifies")
    flips_all_refused(vw, lambda b: g.verify_vote_wire(b, pk, commit, 7), "vote wire")
    nw = B("vote nil prevote h=7 r=1 idx=0 wire")
    check(not refused(g.verify_vote_wire, nw, pk, commit, 7), "nil prevote verifies")

    c4 = B("certificate n=4 h=7 r=0 signers {0,1,3}")
    c2 = B("certificate n=2 h=7 r=0 signers {0,1}")
    v4 = lambda b: g.verify_certificate(b, pk, commit, 7, block)  # noqa: E731
    v2 = lambda b: g.verify_certificate(b, pk[:2], commit, 7, block)  # noqa: E731
    check(not refused(v4, c4), "certificate n=4 verifies")
    check(not refused(v2, c2), "certificate n=2 verifies")
    flips_all_refused(c4, v4, "certificate n=4")
    flips_all_refused(c2, v2, "certificate n=2")
    hdr, ents = c4[:117], [c4[119 + 66 * j:119 + 66 * (j + 1)] for j in range(3)]
    check(refused(v4, hdr + g.u16(2) + ents[0] + ents[1]), "certificate k = q(n) - 1 refused")
    check(refused(v4, hdr + g.u16(3) + ents[1] + ents[0] + ents[2]), "certificate descending indices refused")
    check(refused(v4, hdr + g.u16(3) + ents[0] + ents[0] + ents[2]), "certificate duplicate index refused")
    check(refused(g.verify_certificate, c4, pk, commit, 8, block), "certificate for another height refused")
    check(refused(g.verify_certificate, c4, pk, commit, 7, g.blake3(b"x")), "certificate for another block refused")

    ev = B("equivocation evidence idx=2 h=7 r=0 precommit")
    ve = lambda b: g.verify_equivocation_evidence(b, pk)  # noqa: E731
    check(not refused(ve, ev), "equivocation evidence verifies")
    flips_all_refused(ev, ve, "equivocation evidence")
    swapped = ev[:9] + ev[186:363] + ev[9:186]
    check(refused(ve, swapped), "equivocation evidence non-canonical order refused")
    check(refused(ve, ev[:186] + ev[9:186]), "equivocation evidence of one vote twice refused")

    vm = lambda b: g.verify_bootstrap_manifest(b, pk[:2], g.CHAIN_ID, genesis)  # noqa: E731
    for lab in ("A", "B"):
        mf = B(f"manifest {lab} n=2 both signers")
        f = vm(mf)
        check(f["digest"].hex() == hx[f"manifest {lab} digest"], f"manifest {lab} digest matches")
        check(mf[:276].hex() == hx[f"manifest {lab} body"], f"manifest {lab} body prefix")
        flips_all_refused(mf, vm, f"manifest {lab}")
    ma = B("manifest A n=2 both signers")
    body = ma[:276]
    check(refused(vm, body + g.u16(1) + ma[278:344]), "manifest k = 1 of n = 2 refused")
    check(refused(vm, body + g.u16(2) + ma[344:410] + ma[278:344]), "manifest descending indices refused")
    check(refused(g.verify_bootstrap_manifest, ma, pk[:2], g.CHAIN_ID + 1, genesis), "manifest other chain refused")
    check(refused(g.verify_bootstrap_manifest, ma, pk, g.CHAIN_ID, genesis), "manifest against another set refused")

    def resign(mutate):
        m = g.decode_manifest(ma)
        fields = {k: m[k] for k in ("chain_id", "genesis_block_hash", "sequence", "previous_manifest_digest",
                                    "old_config_commitment", "new_config_commitment", "protocol_version",
                                    "checkpoint_height", "checkpoint_block_hash", "activation_height",
                                    "signing_deadline_height", "validator_set_commitment", "quorum_rule",
                                    "handler_digest")}
        mutate(fields)
        bd = g.manifest_body(fields)
        msg = g.manifest_sign_message(bd)
        return g.manifest(bd, [(i, g.ed25519_sign(g.SEEDS[i], msg)) for i in (0, 1)])

    check(refused(vm, resign(lambda f: f.update(sequence=2, previous_manifest_digest=g.blake3(b"p")))),
          "signed sequence-2 manifest refused under genesis membership")
    check(refused(vm, resign(lambda f: f.update(previous_manifest_digest=g.blake3(b"p")))),
          "sequence 1 with nonzero previous digest refused")
    check(refused(vm, resign(lambda f: f.update(new_config_commitment=f["old_config_commitment"]))),
          "manifest with old = new refused")
    check(refused(vm, resign(lambda f: f.update(signing_deadline_height=100_000))),
          "manifest deadline = H refused")
    check(refused(vm, resign(lambda f: f.update(checkpoint_height=95_000))),
          "manifest checkpoint = deadline refused")
    check(refused(vm, resign(lambda f: f.update(quorum_rule=2))), "manifest unknown quorum rule refused")
    check(refused(vm, resign(lambda f: f.update(protocol_version=1))), "manifest protocol version 1 refused")
    check(refused(g.verify_bootstrap_manifest, ma, pk[:2], g.CHAIN_ID, genesis, min_notice=5_001),
          "manifest below an injected notice refused")
    check(not refused(g.verify_bootstrap_manifest, ma, pk[:2], g.CHAIN_ID, genesis, min_notice=5_000),
          "manifest at an injected notice accepted")

    uc = B("upgrade-conflict evidence A/B sequence 1")
    vu = lambda b: g.verify_upgrade_conflict_evidence(b, pk[:2], g.CHAIN_ID, genesis)  # noqa: E731
    check(not refused(vu, uc), "upgrade-conflict evidence verifies")
    flips_all_refused(uc, vu, "upgrade-conflict evidence")
    check(refused(vu, g.upgrade_conflict_evidence(ma, ma)), "conflict evidence of one manifest twice refused")
    mb = B("manifest B n=2 both signers")
    lo, hi = (ma, mb) if g.manifest_digest(ma[:276]) < g.manifest_digest(mb[:276]) else (mb, ma)
    rev = g.M_UCONFLICT + g.u16(1) + g.u32(len(hi)) + hi + g.u32(len(lo)) + lo
    check(refused(vu, rev), "conflict evidence non-canonical order refused")

    for name in ("hint before H (nothing applied; A pending)", "hint after H (A applied; nothing pending)"):
        h = B(name)
        check(not refused(g.decode_hint, h), f"{name} decodes")
        for off in list(range(0, 9)) + [81]:
            m = bytearray(h)
            m[off] ^= 0x01
            check(refused(g.decode_hint, bytes(m)), f"{name}: structural flip at {off} refused")
        check(refused(g.decode_hint, h[:-1]) and refused(g.decode_hint, h + b"\0"), f"{name}: length refused")
    hb = B("hint before H (nothing applied; A pending)")
    check(refused(g.decode_hint, hb[:41] + g.u64(1) + hb[49:]), "hint applied sequence with zero digest refused")
    check(refused(g.decode_hint, hb[:82] + bytes(32) + hb[114:]), "hint next present with zero digest refused")
    ha = B("hint after H (A applied; nothing pending)")
    check(refused(g.decode_hint, ha[:114] + g.u64(5)), "hint absent next with nonzero height refused")

    for name in ("signer state initialized floor=7 (validator 1)", "signer state after precommit h=7 r=0 (locked)"):
        s = B(name)
        check(not refused(g.decode_signer_state, s, pk[1]), f"{name} decodes")
        flips_all_refused(s, lambda b: g.decode_signer_state(b, pk[1]), name)
        check(refused(g.decode_signer_state, s, pk[0]), f"{name}: another key's state refused")
    s1 = g.decode_signer_state(B("signer state after precommit h=7 r=0 (locked)"))
    pre = B("vote precommit h=7 r=0 idx=1 preimage")
    check(s1["last"][3] == g.sign_bytes_digest(pre), "signer state records the digest of the released sign bytes")
    check(s1["last"][4].hex() == hx["vote precommit h=7 r=0 idx=1 signature"], "signer state records the released signature")
    check(refused(g.signer_state, 0, g.CHAIN_ID, genesis, pk[1], 7, lock=(7, 0, block)),
          "initialization record with a lock refused")
    check(refused(g.signer_state, 3, g.CHAIN_ID, genesis, pk[1], 8,
                  last=(7, 0, 3, bytes(32), bytes(64))), "last below floor refused")
    check(refused(g.signer_state, 3, g.CHAIN_ID, genesis, pk[1], 7, lock=(7, 0, bytes(32))),
          "zero lock value refused")
    check(refused(g.signer_state, 3, g.CHAIN_ID, genesis, pk[1], 7,
                  last=(7, (1 << 20) + 1, 3, bytes(32), bytes(64))), "round above the D4 cap refused")

    # 6. Domains and magics.
    news = list(g.DOMAINS.values()) + list(g.MAGICS.values())
    check(all(x.count(b"\0") == 1 and x.endswith(b"\0") for x in news), "NUL only at the end")
    check(len(set(news)) == len(news), "domains and magics distinct")
    check(all(not a.startswith(b) for a in news for b in news if a is not b), "prefix-free")
    check(not set(news) & set(g.RETIRED.values()), "no retired domain or magic reused")
    root = os.path.abspath(os.path.join(HERE, "..", "..", ".."))
    lits = rust_byte_literals(root)
    check(len(lits) > 100, f"scanned {len(lits)} byte-string literals under crates/")
    named = {**g.DOMAINS, **g.MAGICS}
    for name, home in sorted(RATIFIED_HOME.items()):
        check(lits.get(named[name]) == {home}, f"ratified {name} is spelled only in {home}")
    homed = {named[n] for n in RATIFIED_HOME}
    reused = {x for x in set(news)
              if any((lit == x and x not in homed) or (lit != x and lit.startswith(x))
                     or (lit and lit != x and x.startswith(lit) and lit.endswith(b"\0"))
                     for lit in lits)}
    check(not reused, f"no clash with crates/ literals {sorted(reused)}")

    # 7. Determinism.
    out1, out2 = g.render(g.build()), g.render(g.build())
    check(out1 == out2, "two builds identical")
    with open(os.path.join(HERE, "vectors.json")) as fh:
        check(fh.read() == out1, "vectors.json equals generated output")

    # 8. README hex appears in the vectors.
    with open(os.path.join(HERE, "README.md")) as fh:
        readme = fh.read()
    known = set(hx.values()) | {x for x in xc.values() if isinstance(x, str)} | set(xc["pk"])
    found = re.findall(r"\b[0-9a-f]{64,}\b", readme)
    stray = [h for h in found if not any(h in k for k in known)]
    check(found and not stray, f"README hex all from vectors ({len(found)} strings, stray {stray[:2]})")
    for key in ("manifest A n=2 both signers", "hint before H (nothing applied; A pending)",
                "signer state after precommit h=7 r=0 (locked)", "manifest A digest",
                "certificate n=2 h=7 r=0 signers {0,1}"):
        check(hx[key] in readme, f"README shows {key}")

    print(f"{passes} passed, {len(failures)} failed")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
