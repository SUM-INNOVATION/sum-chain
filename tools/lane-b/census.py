#!/usr/bin/env python3
"""Derive the blocker census from ACTIVATION-AUDIT.md, instead of subtracting.

    python3 tools/lane-b/census.py [TREE_ROOT]

# Why this exists

The blocking count in this document has been wrong four times running -- 121,
120, 114, 111 -- and every one of them was arithmetic performed on the previous
one. When it was finally COUNTED it came out 107, and the whole discrepancy was
SC-1..SC-7: a pass closed seven rows and never moved the total. A number reached
by subtracting from a number nobody re-derived is not a count, and this file
exists so that nobody has to reach one that way again.

# What it refuses to do

It does not classify by guessing. The verdict column is uncontrolled prose --
twenty-five distinct spellings at last survey, including three SC rows that
split their verdict across two readings and one row (`DE-13`) whose verdict
carries no base word at all. So every row must match a KNOWN spelling, and a row
that matches none is a FAILURE, not a row quietly dropped into the smallest
bucket. Two rows are legitimately reading-dependent and are counted as exactly
one blocking row between them, because the readings are a single global choice:
under Reading A one is reachable, under Reading B the other is.

# The partition

    counted   = every distinct row id, minus the cross-references
    blocking  = REACHABLE + UNDETERMINED
    and every blocking row lands in exactly one of
      dormant    fully remedied, pending activation
      partly     remedied in part
      structural blocked, structural
      disposed   a release-closure disposition (the four buckets)
      ACTIONABLE none of the above -- the number this whole exercise is about
"""
from __future__ import annotations
import re, sys
from pathlib import Path

HDRS = {
    "| id | defect | source | verdict | gate | evidence | justification |": 7,
    "| id | item | source | verdict | evidence | justification |": 6,
}
# PR-1..PR-7 carry an explicit "(= AU-nn)". PR-10..PR-12 and TS-12 restate
# DE rows. Eleven ids that are the same defect counted twice.
XREF = {f"PR-{n}" for n in (1, 2, 3, 4, 5, 6, 7, 10, 11, 12)} | {"TS-12"}

DISPOSITIONS = (
    "CLOSED BY TESTED IMPLEMENTATION",
    "DEFERRED, NO UNSAFE OPERATION REACHABLE, PINNED",
    "EXTERNAL RELEASE EVIDENCE",
    "OWNER ACTIVATION DECISION",
)

def cells(line: str) -> list[str]:
    """Split on UNESCAPED pipes only: `\\|` inside a code span is text."""
    return [c.strip() for c in re.split(r"(?<!\\)\|", line)[1:-1]]

def rows(path: Path):
    out, width, bad = {}, None, []
    for n, line in enumerate(path.read_text().split("\n"), 1):
        if line.strip() in HDRS:
            width = HDRS[line.strip()]
            continue
        if width is None:
            continue
        if line.startswith("|") and set(line.replace("|", "").strip()) <= set("-: "):
            continue
        if not line.startswith("| "):
            width = None
            continue
        c = cells(line)
        if len(c) != width:
            bad.append((n, c[0] if c else "?", len(c), width))
        out.setdefault(c[0].strip("`"), (n, width, c))
    return out, bad

def verdict_is_blocking(v: str):
    """True, False, or None for the reading-dependent pair."""
    if "Reading A" in v:
        return None
    if re.search(r"\bUNDETERMINED\b", v):
        return True
    if re.search(r"\bWAS REACHABLE\b", v):
        return False          # closed; the WAS is the whole point
    if re.search(r"\bUNREACHABLE\b", v):
        return False
    if re.search(r"\bREACHABLE\b", v):
        return True
    if re.search(r"\bGATED OFF\b", v) or "written but UNREAD" in v:
        return False
    return "unknown"

def main(root: Path) -> int:
    path = root / "docs/lane-a/ACTIVATION-AUDIT.md"
    all_rows, bad = rows(path)
    if bad:
        print("FATAL: rows whose cell count does not match their header:")
        for n, rid, got, want in bad:
            print(f"  line {n}: {rid} has {got} cells, header declares {want}")
        return 2

    census = {k: v for k, v in all_rows.items() if k not in XREF}
    unknown = [k for k, (_, _, c) in census.items()
               if verdict_is_blocking(c[3]) == "unknown"]
    if unknown:
        print(f"FATAL: {len(unknown)} row(s) match no known verdict spelling: {unknown}")
        print("  A row whose verdict cannot be read must not be silently counted as closed.")
        return 2

    amb = [k for k, (_, _, c) in census.items() if verdict_is_blocking(c[3]) is None]
    blocking = {k: c for k, (_, _, c) in census.items()
                if verdict_is_blocking(c[3]) is True}

    def gate(c):  # the 6-column DE table has no gate column
        return c[4] if len(c) == 7 else ""

    dormant, partly, structural, disposed, actionable = {}, {}, {}, {}, {}
    for k, c in blocking.items():
        g = gate(c)
        if any(d in g for d in DISPOSITIONS):
            disposed[k] = next(d for d in DISPOSITIONS if d in g)
        elif "PARTLY" in g or ("PENDING ACTIVATION" in g and "BLOCKED, STRUCTURAL" in g):
            partly[k] = g
        elif "PENDING ACTIVATION" in g:
            dormant[k] = g
        elif "BLOCKED, STRUCTURAL" in g:
            structural[k] = g
        else:
            actionable[k] = g

    n_block = len(blocking) + (1 if amb else 0)
    print(f"counted rows          {len(census)}   ({len(all_rows)} ids - {len(XREF)} cross-references)")
    print(f"blocking              {n_block}   ({len(blocking)} definite"
          + (f" + 1 of the reading-dependent pair {sorted(amb)}" if amb else "") + ")")
    print(f"  dormant             {len(dormant)}")
    print(f"  partly remedied     {len(partly)}   {sorted(partly)}")
    print(f"  structural          {len(structural)}   {sorted(structural)}")
    print(f"  disposed            {len(disposed)}")
    for d in DISPOSITIONS:
        ids = sorted(k for k, v in disposed.items() if v == d)
        if ids:
            print(f"      {d:-<50} {len(ids)}  {ids}")
    print(f"  ACTIONABLE          {len(actionable)}   {sorted(actionable)}")

    total = len(dormant) + len(partly) + len(structural) + len(disposed) + len(actionable)
    if total != len(blocking):
        print(f"\nFATAL: buckets sum to {total}, blocking is {len(blocking)} -- not a partition")
        return 2
    print(f"\npartition holds: {len(dormant)}+{len(partly)}+{len(structural)}"
          f"+{len(disposed)}+{len(actionable)} = {len(blocking)}")
    return 1 if actionable else 0

if __name__ == "__main__":
    sys.exit(main(Path(sys.argv[1] if len(sys.argv) > 1 else ".")))
