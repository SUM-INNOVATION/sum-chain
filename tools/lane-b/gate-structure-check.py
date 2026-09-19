#!/usr/bin/env python3
"""Structural check over every gate-derived structure, run before any build.

# Why this exists

Merging branches that each add activation gates has, repeatedly, produced trees
that COMPILE AND PASS while a gate is silently gone. A missing
`activation_heights` entry removes a gate from the genesis digest and from the
startup change detection, and no behavioural test notices. A conflict that opens
in the MIDDLE of a tuple splices two entries into one malformed entry that the
compiler rejects but a contents-only check reports as two absent names -- so the
next repair adds duplicates.

# The four ways this checker itself has been wrong

Each of these reported PASS on a tree that would not compile, or was missing a
gate. They are the specification for the design below.

1. It read a list's CONTENTS but not the list's own DECLARATION, so a truncated
   `const WIRING: &[` passed.  ->  Every structure is located by a regex that
   spans its whole declaration up to the opening bracket, and the region is
   delimited by real BRACKET BALANCING over a string- and comment-masked
   skeleton. A truncated declaration fails to balance and is reported
   `truncated`; an edited signature fails to locate and is reported
   `locator-missing`.

2. It counted WELL-FORMED tuples, so a FUSED tuple (two entries spliced into one
   by a conflict opening mid-tuple) matched nothing and both names inside it
   read as ABSENT -- and the "repair" then added duplicates.  ->  Nothing is
   counted. The region is split at top-level commas and EVERY element must
   match the entry pattern in full. A fused tuple is one element that does not
   match, and it is reported `fused` (it carries more than one name) rather
   than silently contributing nothing.

3. It covered `activation_heights`'s tuple shape but not the dormant list's, so
   a fused tuple there passed.  ->  There is one engine. A structure's shape is
   DATA in the registry, not code, so a shape cannot be covered for one
   structure and forgotten for the next.

4. It was a hand-written list of the structures someone REMEMBERED.  ->  The
   registry below is the list, adding an entry to it is the only edit needed to
   have a structure checked, and a registered structure that cannot be found or
   that yields nothing is a FAILURE. A checker that reports success because it
   found nothing to check is the exact failure mode this tool was built to
   catch, and it used to have that failure mode itself.

# What "no longer checked" means

`locator-missing`, `empty` and the final registry reconciliation exist for one
case: a structure that is deleted from the source, or renamed so the locator no
longer finds it, must FAIL. Silence is not a pass. Every registry entry must
report a verdict, and the engine asserts at the end that it produced exactly
`len(REGISTRY)` verdicts.

# The structures, and their authority

`ChainParams`'s field declarations are the authority for the gate set;
`activation_heights` and the local-testnet literal must EQUAL it, and
`GATES_PREDATING_ACTIVATION_RECORDING` (a closed historical list) must be a
subset of it. `WIRING` is the authority for the remediation subset; the dormant
list and `REMEDIATION_GATES` must equal it. `consensus_limits` is not a gate
list at all -- it is registered because it has the same fused-tuple failure
mode, and the registry is general enough to hold it.

Usage:  gate-structure-check.py [TREE_ROOT]
Exit 0 iff every registered structure is present, well formed and in the
relation the registry declares. Exit 1 on a structural failure, 2 if the
registry itself is inconsistent.
"""
from __future__ import annotations

import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

# A gate field name. The one token whose presence makes a region gate-derived.
GATE = r"[a-z_0-9]+_(?:enabled|required)_from_height"


# ---------------------------------------------------------------------------
# The registry. ADDING A STRUCTURE HERE IS THE ONLY EDIT NEEDED TO CHECK IT.
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class Structure:
    """One gate-derived structure and everything known about how to check it.

    name      stable id, used in every failure message
    path      file, relative to the tree root
    locator   regex matching the WHOLE declaration through its opening bracket.
              Must match exactly once: zero is `locator-missing` (deleted or
              renamed), more than one is `locator-ambiguous`.
    mode      "elements": the region is a bracketed list; it is split at
                top-level commas and EVERY element must match `entry` in full.
              "scan": the region is a larger block (a struct, a struct literal)
                in which entries are found by pattern; every occurrence of
                `token` in it must lie inside a well-formed `entry`.
    entry     regex for one well-formed entry. Group "name" is the entry's
              gate/limit name. Group "field" is the value it reads, when the
              shape has one; it must agree with "name".
    token     the thing whose every occurrence must be covered by an entry.
              Defaults to GATE; None disables coverage (only sensible in
              "elements" mode, where full-coverage splitting already holds).
    expect    ("eq", other) | ("subset", other) | ("free",) -- the relation this
              structure's name set must bear to another registered structure's.
    minimum   a floor on the entry count. A registered structure that yields
              fewer FAILS: finding nothing is not a pass.
    """

    name: str
    path: str
    locator: str
    mode: str
    entry: str
    expect: tuple
    minimum: int
    token: str | None = GATE
    note: str = ""


REGISTRY: list[Structure] = [
    Structure(
        name="genesis::ChainParams gate fields",
        path="crates/genesis/src/lib.rs",
        locator=r"pub struct ChainParams \{",
        mode="scan",
        # The #[serde(default)] is part of the SHAPE: a gate field without it
        # resolves differently for a genesis written before it existed, so a
        # field that loses the attribute is a malformed entry, not a styling
        # nit. Folding it in means an uncovered token reports it.
        entry=rf"#\[serde\(default\)\]\s*\n\s*pub (?P<name>{GATE}): Option<u64>,",
        expect=("free",),
        minimum=40,
        note="the authority for the gate set",
    ),
    Structure(
        name="genesis::activation_heights",
        path="crates/genesis/src/lib.rs",
        locator=(
            r"pub fn activation_heights\(&self\) -> "
            r"Vec<\(&'static str, Option<u64>\)> \{\s*\n\s*vec!\["
        ),
        mode="elements",
        entry=rf"\(\s*\"(?P<name>{GATE})\",\s*self\.(?P<field>[a-z_0-9]+),?\s*\)",
        expect=("eq", "genesis::ChainParams gate fields"),
        minimum=40,
    ),
    Structure(
        name="genesis::GATES_PREDATING_ACTIVATION_RECORDING",
        path="crates/genesis/src/lib.rs",
        locator=r"pub const GATES_PREDATING_ACTIVATION_RECORDING: &\[&str\] = &\[",
        mode="elements",
        entry=rf"\"(?P<name>{GATE})\"",
        # CLOSED by construction -- it names gates that were already live, which
        # is a historical fact and cannot grow. So subset, never eq: a new gate
        # must NOT appear here, but every name on it must still be a real field.
        expect=("subset", "genesis::ChainParams gate fields"),
        minimum=15,
    ),
    Structure(
        name="genesis::REMEDIATION_GATES",
        path="crates/genesis/src/lib.rs",
        locator=r"pub const REMEDIATION_GATES: &\[&str\] = &\[",
        mode="elements",
        entry=rf"\"(?P<name>{GATE})\"",
        expect=("eq", "state_tests::WIRING"),
        minimum=15,
    ),
    Structure(
        name="scripts::local testnet ChainParams literal",
        path="scripts/src/setup_local_testnet.rs",
        locator=r"ChainParams \{",
        mode="scan",
        entry=rf"(?P<name>{GATE}): (?:Some\(\d+\)|None),",
        expect=("eq", "genesis::ChainParams gate fields"),
        minimum=40,
    ),
    Structure(
        name="state_tests::WIRING",
        path="crates/state/tests/remediation_gates.rs",
        locator=r"const WIRING: &\[\(&str, &str, &str\)\] = &\[",
        mode="elements",
        entry=(
            r"\(\s*\"(?P<file>[^\"]+)\",\s*\"(?P<symbol>[^\"]+)\","
            rf"\s*\"(?P<name>{GATE})\",?\s*\)"
        ),
        expect=("subset", "genesis::ChainParams gate fields"),
        minimum=15,
        note="the authority for the remediation subset",
    ),
    Structure(
        name="state_tests::dormant defaults",
        path="crates/state/tests/remediation_gates.rs",
        locator=r"let dormant: Vec<\(&str, Option<u64>\)> = vec!\[",
        mode="elements",
        entry=rf"\(\s*\"(?P<name>{GATE})\",\s*p\.(?P<field>[a-z_0-9]+),?\s*\)",
        expect=("eq", "state_tests::WIRING"),
        minimum=15,
    ),
    Structure(
        name="state::protocol_digest::consensus_limits",
        path="crates/state/src/protocol_digest.rs",
        locator=(
            r"pub fn consensus_limits\(\) -> Vec<\(&'static str, LimitValue\)> \{"
            r"\s*\n\s*vec!\["
        ),
        mode="elements",
        entry=(
            r"\(\s*\"(?P<name>[A-Z][A-Z_0-9]*)\",\s*"
            r"LimitValue::[A-Za-z]+\((?:[^()]|\([^()]*\))*\),?\s*\)"
        ),
        # Not a gate list: its entries are consensus CONSTANT names. Registered
        # because it is a tuple list with the identical fused-entry failure
        # mode, and because the registry should not be a gate-only club. Its
        # names have no counterpart elsewhere, so the only relation it can bear
        # is internal consistency.
        expect=("free",),
        minimum=5,
        token=None,
        note="not gate-derived; registered for the shared fused-tuple failure mode",
    ),
]


# ---------------------------------------------------------------------------
# Source masking: comments away, and a skeleton with string interiors away too.
# ---------------------------------------------------------------------------
def mask(src: str) -> tuple[str, str]:
    """Return (nocomment, skeleton), both the same length as `src`.

    nocomment: comment characters replaced by spaces, string literals intact.
               Entry patterns and coverage tokens run against this, so a gate
               name mentioned in a doc comment is not mistaken for an entry.
    skeleton:  comments AND string/char interiors replaced by spaces. Bracket
               balancing and top-level comma splitting run against this, so a
               bracket or comma inside a string cannot mis-delimit a region.
    """
    n = list(src)
    s = list(src)
    i, end = 0, len(src)
    while i < end:
        c = src[i]
        if c == "/" and i + 1 < end and src[i + 1] == "/":
            j = src.find("\n", i)
            j = end if j < 0 else j
            for k in range(i, j):
                n[k] = s[k] = " "
            i = j
        elif c == "/" and i + 1 < end and src[i + 1] == "*":
            j = src.find("*/", i + 2)
            j = end if j < 0 else j + 2
            for k in range(i, j):
                if src[k] != "\n":
                    n[k] = s[k] = " "
            i = j
        elif c == '"':
            j = i + 1
            while j < end and src[j] != '"':
                j += 2 if src[j] == "\\" else 1
            for k in range(i, min(j + 1, end)):
                if src[k] != "\n":
                    s[k] = " "
            i = min(j + 1, end)
        elif c == "'":
            # A char literal ('a', '\n', '\'') -- or a lifetime ('static), which
            # has no closing quote and must be left alone.
            j = i + 2 + (1 if i + 1 < end and src[i + 1] == "\\" else 0)
            if j < end and src[j] == "'":
                for k in range(i, j + 1):
                    s[k] = " "
                i = j + 1
            else:
                i += 1
        else:
            i += 1
    return "".join(n), "".join(s)


CLOSE = {"[": "]", "{": "}", "(": ")"}


def balanced_region(skeleton: str, open_at: int) -> int | None:
    """Index of the bracket closing the one at `open_at`, or None if unclosed."""
    opener = skeleton[open_at]
    closer = CLOSE[opener]
    depth = 0
    for k in range(open_at, len(skeleton)):
        if skeleton[k] == opener:
            depth += 1
        elif skeleton[k] == closer:
            depth -= 1
            if depth == 0:
                return k
    return None


def split_elements(skeleton: str, nocomment: str, lo: int, hi: int) -> list[tuple[int, int]]:
    """Spans of the region's top-level comma-separated elements.

    Delimiting uses the skeleton (so a comma inside a string cannot split an
    element) but emptiness is judged on `nocomment`, where string literals are
    intact -- in the skeleton a `"..."`-only element is all spaces and would be
    dropped as blank, which would make a list of bare strings read as EMPTY.
    """
    spans, depth, start = [], 0, lo
    for k in range(lo, hi):
        c = skeleton[k]
        if c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
        elif c == "," and depth == 0:
            spans.append((start, k))
            start = k + 1
    spans.append((start, hi))
    return [(a, b) for a, b in spans if nocomment[a:b].strip()]


def line_of(raw: str, at: int) -> int:
    return raw.count("\n", 0, at) + 1


def snippet(text: str, limit: int = 90) -> str:
    one = " ".join(text.split())
    return one if len(one) <= limit else one[:limit] + "..."


# ---------------------------------------------------------------------------
# Verdicts
# ---------------------------------------------------------------------------
@dataclass
class Verdict:
    structure: str
    names: list[str] = field(default_factory=list)
    problems: list[tuple[str, str]] = field(default_factory=list)  # (class, detail)

    @property
    def ok(self) -> bool:
        return not self.problems

    def fail(self, cls: str, detail: str) -> None:
        self.problems.append((cls, detail))


def inspect(st: Structure, root: Path) -> Verdict:
    """Everything that can be decided about one structure on its own."""
    v = Verdict(st.name)
    src_path = root / st.path
    if not src_path.is_file():
        v.fail("file-missing", f"{st.path} does not exist")
        return v
    raw = src_path.read_text()
    nocomment, skeleton = mask(raw)

    hits = list(re.finditer(st.locator, skeleton))
    if not hits:
        v.fail(
            "locator-missing",
            f"no declaration matching /{st.locator}/ in {st.path} -- the "
            "structure was deleted, renamed, or its signature changed, and "
            "would otherwise have been silently unchecked",
        )
        return v
    if len(hits) > 1:
        v.fail(
            "locator-ambiguous",
            f"{len(hits)} declarations match /{st.locator}/ in {st.path} at "
            f"lines {[line_of(raw, h.start()) for h in hits]}",
        )
        return v

    head = hits[0]
    open_at = head.end() - 1
    if open_at < head.start() or skeleton[open_at] not in CLOSE:
        v.fail(
            "truncated",
            "the locator does not end at an opening bracket: "
            f"{snippet(raw[head.start():head.end()])!r}",
        )
        return v
    close_at = balanced_region(skeleton, open_at)
    if close_at is None:
        v.fail(
            "truncated",
            f"the {skeleton[open_at]!r} opened at {st.path}:"
            f"{line_of(raw, open_at)} is never closed -- the declaration is "
            "truncated and this file does not compile",
        )
        return v
    lo, hi = open_at + 1, close_at

    pat = re.compile(st.entry, re.S)
    matched: list[re.Match] = []

    if st.mode == "elements":
        for a, b in split_elements(skeleton, nocomment, lo, hi):
            text = nocomment[a:b]
            m = pat.fullmatch(text.strip())
            if m is None:
                # DISTINCT names, not occurrences: a well-formed name+field
                # tuple mentions its own gate twice ("v2..." and self.v2...),
                # so counting occurrences would call every malformed entry
                # fused and send the next reader looking for a splice that
                # isn't there. Two DIFFERENT names in one element is a splice.
                names = sorted(set(re.findall(GATE if st.token else r'"([^"]*)"', text)))
                cls = "fused" if len(names) > 1 else "malformed"
                extra = f" and carries {len(names)} distinct names {names}" if len(names) > 1 else ""
                v.fail(
                    cls,
                    f"element at {st.path}:{line_of(raw, a)} does not match the "
                    f"declared shape{extra}: {snippet(text)!r}",
                )
            else:
                matched.append(m)
    elif st.mode == "scan":
        matched = list(pat.finditer(nocomment, lo, hi))
        if st.token:
            covered = [(m.start(), m.end()) for m in matched]
            for t in re.finditer(st.token, nocomment[lo:hi]):
                at = lo + t.start()
                if not any(a <= at < b for a, b in covered):
                    v.fail(
                        "malformed",
                        f"{t.group()!r} at {st.path}:{line_of(raw, at)} is inside "
                        "the region but not inside a well-formed entry -- the "
                        "entry around it is truncated, fused, or has lost part "
                        "of its declared shape",
                    )
    else:  # pragma: no cover - registry typo
        v.fail("registry-error", f"unknown mode {st.mode!r}")
        return v

    for m in matched:
        groups = m.groupdict()
        name = groups["name"]
        v.names.append(name)
        read = groups.get("field")
        if read is not None and read != name:
            v.fail("mismatched-name", f"entry named {name!r} reads {read!r}")

    seen: dict[str, int] = {}
    for n in v.names:
        seen[n] = seen.get(n, 0) + 1
    dupes = sorted(n for n, c in seen.items() if c > 1)
    if dupes:
        v.fail("duplicate", f"{len(dupes)} name(s) appear more than once: {dupes}")

    if len(v.names) < st.minimum:
        v.fail(
            "empty",
            f"{len(v.names)} entries, below the declared floor of {st.minimum} "
            "-- a registered structure that yields (almost) nothing is not a "
            "pass, it is a structure that stopped being checked",
        )
    return v


def run(root: Path, out=sys.stdout) -> int:
    names = [s.name for s in REGISTRY]
    if len(names) != len(set(names)):
        print("REGISTRY ERROR: duplicate structure names", file=out)
        return 2
    for st in REGISTRY:
        if st.expect[0] in ("eq", "subset") and st.expect[1] not in names:
            print(
                f"REGISTRY ERROR: {st.name} expects {st.expect[0]} against "
                f"unregistered {st.expect[1]!r}",
                file=out,
            )
            return 2

    print(f"registry: {len(REGISTRY)} structures, root {root}\n", file=out)
    verdicts: dict[str, Verdict] = {st.name: inspect(st, root) for st in REGISTRY}

    # Relations come AFTER shape, because a set built from a malformed list is
    # not evidence. A structure whose reference failed is reported as
    # set-unverifiable rather than compared against a set that may be short.
    for st in REGISTRY:
        rel = st.expect[0]
        if rel == "free":
            continue
        mine, other = verdicts[st.name], verdicts[st.expect[1]]
        if not mine.ok or not other.ok:
            mine.fail(
                "set-unverifiable",
                f"cannot be compared with {st.expect[1]!r}: "
                + ("its own shape failed" if not mine.ok else "the reference's shape failed"),
            )
            continue
        a, b = set(mine.names), set(other.names)
        if rel == "eq" and a != b:
            mine.fail(
                "set-mismatch",
                f"!= {st.expect[1]!r}; missing here {sorted(b - a)}; "
                f"extra here {sorted(a - b)}",
            )
        elif rel == "subset" and not a <= b:
            mine.fail(
                "set-mismatch",
                f"not a subset of {st.expect[1]!r}; undeclared names {sorted(a - b)}",
            )

    for st in REGISTRY:
        v = verdicts[st.name]
        rel = "" if st.expect[0] == "free" else f"  [{st.expect[0]} {st.expect[1]}]"
        print(
            f"  {'PASS' if v.ok else 'FAIL'}  {st.name}  ({len(v.names)} entries){rel}",
            file=out,
        )
        for cls, detail in v.problems:
            print(f"          {cls}: {detail}", file=out)

    # Registry reconciliation. If this fires, the engine skipped a registered
    # structure -- which is precisely the silence this tool exists to refuse.
    if len(verdicts) != len(REGISTRY):
        print(
            f"\nFATAL: {len(verdicts)} verdicts for {len(REGISTRY)} registered "
            "structures -- a registered structure was not checked",
            file=out,
        )
        return 2

    print(
        "\n"
        + " | ".join(
            f"{s.name.split('::')[-1]} {len(verdicts[s.name].names)}" for s in REGISTRY
        ),
        file=out,
    )
    bad = [v for v in verdicts.values() if not v.ok]
    if bad:
        classes = sorted({c for v in bad for c, _ in v.problems})
        print(f"\n{len(bad)} STRUCTURE(S) FAILED [{', '.join(classes)}]:", file=out)
        for v in bad:
            for cls, detail in v.problems:
                print(f"  {v.structure}: {cls}: {detail}", file=out)
        return 1
    print(f"\nall {len(REGISTRY)} registered structures present and well formed", file=out)
    return 0


if __name__ == "__main__":
    sys.exit(run(Path(sys.argv[1] if len(sys.argv) > 1 else ".")))
