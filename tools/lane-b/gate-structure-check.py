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

`ChainParams`'s field declarations are the AUTHORITY for the gate set.
`activation_heights`, the `Default` impl and the local-testnet literal must
EQUAL it. `GATES_PREDATING_ACTIVATION_RECORDING` is a closed historical list
and must be a SUBSET of it -- never equal, because a new gate must not appear
on it. `WIRING` is the authority for the remediation subset; the dormant list
and `REMEDIATION_GATES` must equal it.

`ChainParamsInfo` (the RPC wire type, and its construction site) is a
deliberate subset: the gates an operator can see over JSON-RPC. Until it was
registered here NOTHING in the tree related it to `ChainParams` -- no test
compared the two field sets -- so a gate dropped from the wire type in a merge
was invisible. Subset is the strongest true statement about it: adding a gate
is a choice, but every name on it must be a real field, and the struct and its
construction site must agree with each other exactly.

The `count` structures are hardcoded numbers -- `assert_eq!(WIRING.len(), 30)`
and friends -- that pin the lists above. They are what stops those lists
quietly shrinking, but only while the number still matches, and a number is the
easiest thing in a merge to leave behind. Registering them checks each count
against the list it counts rather than against memory.

`consensus_limits` is not a gate list at all -- its entries are consensus
constant names. It is registered because it has the identical fused-tuple
failure mode, and because the registry should not be a gate-only club.

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
              "count": not a list at all -- a HARDCODED COUNT of some other
                registered structure, written into an assertion. `locator`
                captures the literal in a group named "count", there is no
                region, and `expect` must be ("count", other).
              "section": the region is prose, delimited by `terminator` (or the
                end of the file) rather than by a bracket. Entries are found by
                pattern, as in "scan", but coverage is not enforced: a gate name
                may legitimately be MENTIONED in prose without that mention
                being an entry. Used for the decision packet, which is Markdown
                and has no brackets to balance.
    entry     regex for one well-formed entry. Group "name" is the entry's
              gate/limit name. Group "field" is the value it reads, when the
              shape has one; it must agree with "name".
    token     the thing whose every occurrence must be covered by an entry.
              Defaults to GATE; None disables coverage (only sensible in
              "elements" mode, where full-coverage splitting already holds).
    expect    ("eq", other) | ("subset", other) | ("count", other) | ("free",)
              | ("partition", sibling, whole)
              -- the relation this structure must bear to another registered
              structure: same name set, subset of it, or (for "count") a
              literal equal to its number of entries. "partition" is the
              three-way form: this structure and `sibling` must be DISJOINT and
              their union must EQUAL `whole`. It exists because a document can
              cover a gate in two mutually exclusive ways -- given a section, or
              named as deliberately not given one -- and the property worth
              checking is that every gate is in exactly one of them.
    minimum   a floor on the entry count. A registered structure that yields
              fewer FAILS: finding nothing is not a pass. Zero is allowed only
              where emptiness is a MEANINGFUL state that the locator still
              proves is being maintained -- see the Part 0a entry.
    terminator  "section" mode only: regex ending the region. None means the
              region runs to the end of the file.
    masked    whether to strip Rust comments and string literals before
              matching. False for documents, where `mask` would be reading
              Markdown as Rust and blanking whatever followed a `//` in a URL.
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
    terminator: str | None = None
    masked: bool = True


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
        # `self\s*\.` and not `self\.`: rustfmt wraps a long field access
        # onto the next line as `self\n    .field`, and an entry pattern that
        # cannot see that reports a real entry as malformed. A registry
        # pattern that is too strict cries wolf; one that is too loose misses
        # the splice. It has to match exactly the shapes rustfmt can produce.
        entry=rf"\(\s*\"(?P<name>{GATE})\",\s*self\s*\.\s*(?P<field>[a-z_0-9]+),?\s*\)",
        expect=("eq", "genesis::ChainParams gate fields"),
        minimum=40,
    ),
    Structure(
        name="genesis::impl Default for ChainParams",
        path="crates/genesis/src/lib.rs",
        locator=r"impl Default for ChainParams \{\n    fn default\(\) -> Self \{\n        Self \{",
        mode="scan",
        entry=rf"(?P<name>{GATE}): (?:None|Some\(\d+\)),",
        # The compiler already refuses a MISSING field here (E0063), so this
        # cannot silently lose a gate. It is registered for the other half: a
        # gate whose default stops being a plain None/Some literal, and to keep
        # the registry honest about being the whole list rather than the
        # interesting parts of it.
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
        entry=rf"\(\s*\"(?P<name>{GATE})\",\s*p\s*\.\s*(?P<field>[a-z_0-9]+),?\s*\)",
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
    # -- The RPC wire mirror. A DELIBERATE SUBSET of the gate set (the gates an
    #    operator can see over JSON-RPC), hand-maintained in two places, and
    #    until now related to `ChainParams` by nothing at all: no test compared
    #    the two, so a gate dropped from the wire type in a merge was invisible.
    #    Registered as a subset, which is the strongest true statement: adding a
    #    gate here is a choice, but every name here must still be a real field,
    #    and the struct and its construction site must agree.
    Structure(
        name="rpc::ChainParamsInfo wire fields",
        path="crates/rpc/src/types.rs",
        locator=r"pub struct ChainParamsInfo \{",
        mode="scan",
        entry=rf"pub (?P<name>{GATE}): Option<u64>,",
        expect=("subset", "genesis::ChainParams gate fields"),
        minimum=5,
    ),
    Structure(
        name="rpc::ChainParamsInfo construction",
        path="crates/rpc/src/server.rs",
        locator=r"Ok\(ChainParamsInfo \{",
        mode="scan",
        entry=rf"(?P<name>{GATE}): p\s*\.\s*(?P<field>[a-z_0-9]+),",
        expect=("eq", "rpc::ChainParamsInfo wire fields"),
        minimum=5,
    ),
    # -- Hardcoded counts. Each is an absolute number written into an assertion
    #    about a list above. They are the reason those lists cannot quietly
    #    shrink -- but only while the number still matches, and a number is the
    #    easiest thing in a merge to leave behind. Pinning them to the registry
    #    means the count is checked against the list rather than against memory.
    Structure(
        name="genesis_tests::GATES_PREDATING count",
        path="crates/genesis/tests/activation_digest.rs",
        locator=(
            r"sumchain_genesis::GATES_PREDATING_ACTIVATION_RECORDING\.len\(\),"
            r"\s*\n\s*(?P<count>\d+),"
        ),
        mode="count",
        entry="",
        expect=("count", "genesis::GATES_PREDATING_ACTIVATION_RECORDING"),
        minimum=0,
        token=None,
    ),
    Structure(
        name="genesis_tests::REMEDIATION_GATES count",
        path="crates/genesis/tests/peer_protocol_enforcement.rs",
        locator=r"\n        REMEDIATION_GATES\.len\(\),\s*\n\s*(?P<count>\d+),",
        mode="count",
        entry="",
        expect=("count", "genesis::REMEDIATION_GATES"),
        minimum=0,
        token=None,
    ),
    Structure(
        name="state_tests::WIRING count",
        path="crates/state/tests/remediation_gates.rs",
        locator=r"assert_eq!\(WIRING\.len\(\), (?P<count>\d+),",
        mode="count",
        entry="",
        expect=("count", "state_tests::WIRING"),
        minimum=0,
        token=None,
    ),
    Structure(
        name="state_tests::distinct accessor fields count",
        path="crates/state/tests/remediation_gates.rs",
        locator=r"\n        fields\.len\(\),\s*\n\s*(?P<count>\d+),",
        mode="count",
        entry="",
        expect=("count", "state_tests::WIRING"),
        minimum=0,
        token=None,
    ),
    Structure(
        name="state_tests::genesis-list size pin",
        path="crates/state/tests/remediation_gates.rs",
        locator=r"\n    assert_eq!\(in_genesis\.len\(\), (?P<count>\d+)\);",
        mode="count",
        entry="",
        # The FIFTH hardcoded count pin, and the last one to be registered.
        # A closure wave moved the other four and this one failed loudly, which
        # is the only reason it was found -- but "it happened to fail" is not
        # coverage. A merge that left it behind while the four registered pins
        # moved would have passed this checker with a tree that still asserts
        # the old number, and the registry would have reported a complete set
        # of counts while one count was stale.
        expect=("count", "genesis::REMEDIATION_GATES"),
        minimum=0,
        token=None,
    ),
    Structure(
        name="packet::decision-packet gate sections",
        path="docs/lane-a/ACTIVATION-DECISION-PACKET.md",
        locator=r"\n## Part 1A ",
        mode="section",
        # Part 1A runs to the end of the file through 1B and 1C, so one region
        # holds all three classes. Every gate section is a heading of the form
        # `### R7 -- `gate``; the prefix says which class, and the check does
        # not care which, only that the gate has a section somewhere.
        terminator=None,
        entry=rf"^### [A-Z]+\d+ — `(?P<name>{GATE})`",
        expect=(
            "partition",
            "packet::Part 0a gates deliberately uncovered",
            "genesis::ChainParams gate fields",
        ),
        minimum=40,
        token=None,
        masked=False,
        note="a gate an owner is asked to schedule must have been written up",
    ),
    Structure(
        name="packet::Part 0a gates deliberately uncovered",
        path="docs/lane-a/ACTIVATION-DECISION-PACKET.md",
        locator=r"\n## Part 0a ",
        mode="section",
        terminator=r"^## ",
        entry=rf"^  \* `(?P<name>{GATE})` — ",
        expect=("subset", "genesis::ChainParams gate fields"),
        # ZERO IS LEGAL HERE, and it is the only entry in the registry for
        # which that is true. An empty Part 0a means the packet has caught up
        # with `ChainParams` -- the state this pair exists to make reachable --
        # and the partition above still forces every gate into a section, so
        # nothing stops being checked when this goes to zero. What may not
        # happen is the SECTION vanishing: the locator must still match, so a
        # packet that drops the acknowledgement instead of the deficit fails.
        minimum=0,
        token=None,
        masked=False,
        note="named here rather than left to be discovered by counting",
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
    count: int | None = None  # "count" mode only: the literal found in source
    problems: list[tuple[str, str]] = field(default_factory=list)  # (class, detail)

    @property
    def ok(self) -> bool:
        return not self.problems

    def fail(self, cls: str, detail: str) -> None:
        self.problems.append((cls, detail))


def finish(st: Structure, v: Verdict, raw: str, matched: list[re.Match]) -> Verdict:
    """Turn matched entries into a name set, and check what a name set alone can.

    Shared by every mode that produces entries, so that a mode added later
    cannot quietly skip the duplicate and floor checks -- which is failure
    mode 3 in the header, one shape covered and the next forgotten.
    """
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


def inspect(st: Structure, root: Path) -> Verdict:
    """Everything that can be decided about one structure on its own."""
    v = Verdict(st.name)
    src_path = root / st.path
    if not src_path.is_file():
        v.fail("file-missing", f"{st.path} does not exist")
        return v
    raw = src_path.read_text()
    nocomment, skeleton = mask(raw) if st.masked else (raw, raw)

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
    if st.mode == "count":
        # No region and no entries: the whole structure is one literal, and the
        # locator having matched exactly once is already the proof it is still
        # there. The comparison happens in the relation phase.
        v.count = int(head.group("count"))
        return v

    if st.mode == "section":
        # No bracket to balance. The region runs from the end of the heading
        # that located it to the next terminator, or to the end of the file.
        lo = head.end()
        if st.terminator is None:
            hi = len(nocomment)
        else:
            stop = re.search(st.terminator, nocomment[lo:], re.M)
            hi = lo + (stop.start() if stop else len(nocomment) - lo)
        matched = list(re.compile(st.entry, re.S | re.M).finditer(nocomment, lo, hi))
        return finish(st, v, raw, matched)

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

    return finish(st, v, raw, matched)


def run(root: Path, out=sys.stdout) -> int:
    names = [s.name for s in REGISTRY]
    if len(names) != len(set(names)):
        print("REGISTRY ERROR: duplicate structure names", file=out)
        return 2
    for st in REGISTRY:
        refs = (
            st.expect[1:]
            if st.expect[0] in ("eq", "subset", "count", "partition")
            else ()
        )
        for ref in refs:
            if ref not in names:
                print(
                    f"REGISTRY ERROR: {st.name} expects {st.expect[0]} against "
                    f"unregistered {ref!r}",
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
        mine = verdicts[st.name]
        refs = [verdicts[r] for r in st.expect[1:]]
        broken = [r.structure for r in refs if not r.ok]
        if not mine.ok or broken:
            mine.fail(
                "set-unverifiable",
                f"cannot be compared with {list(st.expect[1:])}: "
                + ("its own shape failed" if not mine.ok else f"{broken} failed shape"),
            )
            continue
        other = refs[0]
        if rel == "partition":
            sibling, whole = set(refs[0].names), set(refs[1].names)
            a = set(mine.names)
            if a & sibling:
                mine.fail(
                    "set-mismatch",
                    f"overlaps {st.expect[1]!r} on {sorted(a & sibling)} -- a gate "
                    "is either given a section or named as deliberately not "
                    "given one, never both",
                )
            union = a | sibling
            if union != whole:
                mine.fail(
                    "set-mismatch",
                    f"{st.name!r} + {st.expect[1]!r} != {st.expect[2]!r}; "
                    f"gates in neither {sorted(whole - union)}; "
                    f"named but not declared {sorted(union - whole)}",
                )
            continue
        if rel == "count":
            if mine.count != len(other.names):
                mine.fail(
                    "count-mismatch",
                    f"the source says {mine.count}, but {st.expect[1]!r} has "
                    f"{len(other.names)} entries -- the list and the number "
                    "that is supposed to pin it have drifted apart",
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
        rel = (
            ""
            if st.expect[0] == "free"
            else f"  [{st.expect[0]} {' + '.join(st.expect[1:])}]"
        )
        body = f"says {v.count}" if st.mode == "count" else f"{len(v.names)} entries"
        print(f"  {'PASS' if v.ok else 'FAIL'}  {st.name}  ({body}){rel}", file=out)
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
f"{s.name.split('::')[-1]} "
            f"{verdicts[s.name].count if s.mode == 'count' else len(verdicts[s.name].names)}"
            for s in REGISTRY
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
