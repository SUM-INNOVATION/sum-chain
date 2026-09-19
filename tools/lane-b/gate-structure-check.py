#!/usr/bin/env python3
"""Structural check over every gate-derived list, run before any build.

# Why this exists

Merging branches that each add activation gates has, repeatedly, produced trees
that COMPILE AND PASS while a gate is silently gone. A missing
`activation_heights` entry removes a gate from the genesis digest and from the
startup change detection, and no behavioural test notices. A conflict that opens
in the MIDDLE of a tuple splices two entries into one malformed entry that the
compiler rejects but a contents-only check reports as two absent names -- so the
next repair adds duplicates.

# Why it checks SHAPE and not only membership

Three times a check of mine passed on a tree that did not compile:

  * it read a list's contents and not the list's own declaration, so a truncated
    `const WIRING: &[` passed;
  * it counted well-formed tuples, so a FUSED tuple matched nothing and both
    names inside it read as missing;
  * it covered one list's tuple shape and not the next list someone added.

So every list is checked for three things -- its entries parse, each entry has
exactly one value reference, and the name matches the field it reads -- and the
set comparisons come after that, because a set built from a malformed list is
not evidence.

# The lists, and their authority

`activation_heights` and the dormant-defaults list are GENERATED from their
authority (the field declarations, and WIRING). A generated list cannot drift;
these checks are for the ones that are not, and for the generation itself.
"""
import re
import sys
from pathlib import Path

ROOT = Path(sys.argv[1] if len(sys.argv) > 1 else ".")
GENESIS = ROOT / "crates/genesis/src/lib.rs"
LITERAL = ROOT / "scripts/src/setup_local_testnet.rs"
WIRING_F = ROOT / "crates/state/tests/remediation_gates.rs"

FIELD = r'[a-z_0-9]+_(?:enabled|required)_from_height'
failures: list[str] = []


def check(ok: bool, label: str, detail: str = "") -> None:
    print(f"  {'PASS' if ok else 'FAIL'}  {label}")
    if not ok:
        failures.append(f"{label}{': ' + detail if detail else ''}")


def vec_region(src: str, marker: str) -> str:
    i = src.index(marker)
    m = re.compile(r"\n(\s*)\]").search(src, i)
    return src[i:m.start()]


def main() -> int:
    g = GENESIS.read_text()

    decl = re.findall(rf"pub ({FIELD}): Option<u64>", g)
    check(len(decl) == len(set(decl)), "no duplicate field declarations",
          str([d for d in set(decl) if decl.count(d) > 1]))
    attr = "#[serde(default)]\n    pub "
    missing_attr = [d for d in decl if (attr + d) not in g]
    check(not missing_attr, "every gate carries #[serde(default)]", str(missing_attr))

    heights = vec_region(g, "pub fn activation_heights(")
    fused = [t.strip()[:60] for t in re.findall(r"\(\n((?:[^()]*\n)+?)\s*\),", heights)
             if t.count("self.") != 1]
    check(not fused, "no fused tuple in activation_heights", str(fused))
    pairs = re.findall(rf'"({FIELD})",\s*\n\s*self\.([a-z_0-9]+),', heights)
    check(not [p for p in pairs if p[0] != p[1]],
          "each activation_heights entry reads the field it names",
          str([p for p in pairs if p[0] != p[1]]))
    check({p[0] for p in pairs} == set(decl), "activation_heights == declarations")

    lit = re.findall(rf"^\s+({FIELD}):", LITERAL.read_text(), re.M)
    check(set(lit) == set(decl), "local-testnet literal == declarations")

    w = WIRING_F.read_text()
    a, b = w.index("const WIRING"), w.index("];", w.index("const WIRING"))
    check(w[a:].startswith("const WIRING: &[(&str, &str, &str)] = &["),
          "WIRING declaration is intact")
    wiring = [e[2] for e in re.findall(r'\(\s*"([^"]+)",\s*"([^"]+)",\s*"([^"]+)",?\s*\)', w[a:b])]
    check(len(wiring) == len(set(wiring)) and set(wiring) <= set(decl),
          "WIRING entries distinct and declared")

    dm = re.search(r"let dormant: Vec<\(&str, Option<u64>\)> = vec!\[(.*?)\n\s*\];", w, re.S)
    dfused = [t.strip()[:60] for t in re.findall(r"\(\n((?:[^()]*\n)+?)\s*\),", dm.group(1))
              if t.count("p.") != 1]
    check(not dfused, "no fused tuple in the dormant list", str(dfused))
    dpairs = re.findall(rf'"({FIELD})",\s*\n\s*p\.([a-z_0-9]+),', dm.group(1))
    check(not [p for p in dpairs if p[0] != p[1]],
          "each dormant entry reads the field it names")
    check({p[0] for p in dpairs} == set(wiring), "dormant list == WIRING")

    rem = re.findall(rf'"({FIELD})"',
                     re.search(r"REMEDIATION_GATES[^=]*=\s*&\[(.*?)\];", g, re.S).group(1))
    check(set(rem) == set(wiring), "REMEDIATION_GATES == WIRING")

    print(f"\ndeclared {len(decl)} | heights {len(pairs)} | literal {len(lit)} | "
          f"WIRING {len(wiring)} | dormant {len(dpairs)} | REMEDIATION {len(rem)}")
    if failures:
        print(f"\n{len(failures)} STRUCTURAL FAILURE(S):")
        for f in failures:
            print(f"  {f}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
