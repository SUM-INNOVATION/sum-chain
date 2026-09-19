#!/usr/bin/env python3
"""Mutation battery for `gate-structure-check.py`.

    python3 tools/lane-b/gate-structure-check-test.py [TREE_ROOT]

# What this proves, and why it has to exist

`gate-structure-check.py` has been wrong four times, and every time it was
wrong in the SAME direction: it reported PASS on a tree that would not compile
or was missing a gate. A checker that only ever gets checked against a clean
tree cannot catch that. So each failure class it claims to detect gets a case
here: a COPY of the real source is corrupted in exactly that way, the checker is
run against the copy, and the case asserts three things --

  * the checker EXITS NON-ZERO,
  * its output names the RIGHT STRUCTURE,
  * its output names the RIGHT FAILURE CLASS.

Exit code alone is not enough. A checker that fails for the wrong reason, or
blames the wrong structure, sends the next person to repair something that was
never broken -- which is how the duplicate-adding "repair" happened.

# The case that makes the rest mean anything

`clean` runs the checker on an UNMODIFIED copy and asserts exit 0. Without it
a checker hard-wired to `return 1` would pass every other case in this file,
and the battery would prove nothing.

# The case that guards the battery itself

Every mutation asserts that it actually changed the copy (`edit` raises if its
anchor is absent or ambiguous). A mutation that silently no-ops would leave the
case testing a clean tree -- the battery reproducing, against itself, the very
failure mode it is here to catch.

Nothing under the real tree is written to. Every case works on a private copy
in a temp directory, which is removed on the way out.
"""
from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
CHECKER = HERE / "gate-structure-check.py"

GENESIS = "crates/genesis/src/lib.rs"
LITERAL = "scripts/src/setup_local_testnet.rs"
WIRING = "crates/state/tests/remediation_gates.rs"
LIMITS = "crates/state/src/protocol_digest.rs"
SOURCES = [GENESIS, LITERAL, WIRING, LIMITS]


# ---------------------------------------------------------------------------
# Mutation helpers. Each raises rather than no-op: a mutation that does not
# bite leaves the case testing a clean tree.
# ---------------------------------------------------------------------------
def edit(root: Path, rel: str, old: str, new: str, *, expect: int = 1) -> None:
    """Replace `old` with `new` in the copy, asserting it occurred `expect` times."""
    p = root / rel
    src = p.read_text()
    n = src.count(old)
    if n != expect:
        raise AssertionError(
            f"mutation anchor occurs {n}x in {rel}, expected {expect}x -- the "
            f"battery would have tested an unmutated tree. Anchor: {old[:120]!r}"
        )
    p.write_text(src.replace(old, new, expect))


def cut(root: Path, rel: str, start: str, end: str) -> str:
    """Delete from `start` through the first `end` after it. Returns the cut text."""
    p = root / rel
    src = p.read_text()
    if src.count(start) != 1:
        raise AssertionError(f"cut anchor {start[:80]!r} is not unique in {rel}")
    a = src.index(start)
    b = src.index(end, a) + len(end)
    p.write_text(src[:a] + src[b:])
    return src[a:b]


def fuse(root: Path, rel: str, first: str, second: str) -> None:
    """Splice two adjacent tuples into one, as a conflict opening mid-tuple does.

    `first` ends a tuple, `second` opens the next. Removing the `),` + `(`
    between them leaves ONE element carrying TWO names -- the shape that used
    to match nothing at all and read as two ABSENT gates.
    """
    edit(root, rel, first + second, first.replace("),", ",", 1) + strip_open(second))


def strip_open(text: str) -> str:
    """Drop the leading `(` that opens the second tuple of a fuse."""
    i = text.index("(")
    return text[:i] + text[i + 1 :]


# ---------------------------------------------------------------------------
# The cases
# ---------------------------------------------------------------------------
def m_clean(root: Path) -> None:
    """No corruption. The control: proves the checker can say yes."""


def m_malformed_entry(root: Path) -> None:
    """One entry loses the comma that separates its name from its field.

    Still ONE gate name, so this must be reported `malformed` and not `fused`:
    a name+field tuple mentions its own gate twice, and a checker that counted
    occurrences rather than DISTINCT names would cry splice here and send the
    reader hunting for a second entry that was never there.
    """
    edit(
        root,
        GENESIS,
        '                "v2_enabled_from_height",\n                self.v2_enabled_from_height,\n',
        '                "v2_enabled_from_height"\n                self.v2_enabled_from_height\n',
    )


def m_absent_structure(root: Path) -> None:
    cut(root, GENESIS, "pub const REMEDIATION_GATES: &[&str] = &[", "\n];\n")


def m_duplicate_entry(root: Path) -> None:
    dup = (
        '    (\n        "nft_executor.rs",\n        "receipt_failure_activation",\n'
        '        "nft_receipt_failure_enabled_from_height",\n    ),\n'
    )
    edit(root, WIRING, dup, dup + dup)


def m_fused_tuple_heights(root: Path) -> None:
    fuse(
        root,
        GENESIS,
        '            (\n                "v2_enabled_from_height",\n'
        "                self.v2_enabled_from_height,\n            ),\n",
        '            (\n                "omninode_enabled_from_height",\n'
        "                self.omninode_enabled_from_height,\n            ),\n",
    )


def m_fused_tuple_dormant(root: Path) -> None:
    """Failure mode 3 was: one list's tuple shape covered, the next one's not."""
    fuse(
        root,
        WIRING,
        '        (\n            "nft_receipt_failure_enabled_from_height",\n'
        "            p.nft_receipt_failure_enabled_from_height,\n        ),\n",
        '        (\n            "docclass_stake_escrow_enabled_from_height",\n'
        "            p.docclass_stake_escrow_enabled_from_height,\n        ),\n",
    )


def m_renamed_locator(root: Path) -> None:
    """The structure is still there. The locator no longer finds it."""
    edit(root, WIRING, "const WIRING: &[(&str, &str, &str)] = &[", "const GATE_WIRING: &[(&str, &str, &str)] = &[")
    edit(root, WIRING, "WIRING", "GATE_WIRING", expect=root.joinpath(WIRING).read_text().count("WIRING"))


def m_truncated_declaration(root: Path) -> None:
    """Syntactically broken source must not report success.

    The file is cut off partway through `WIRING`, so the `&[` is never closed.
    This is the shape that got through twice: a checker that merely parses the
    valid entries it can still see finds each surviving entry perfectly well
    formed, and says PASS about a file that does not compile. The declaration
    has to be checked, not just its contents.
    """
    p = root / WIRING
    src = p.read_text()
    a = src.index("const WIRING: &[(&str, &str, &str)] = &[")
    cutoff = src.index('"docclass_executor.rs"', a)
    p.write_text(src[:cutoff])


def m_set_mismatch(root: Path) -> None:
    """A perfectly well-formed literal that has simply lost a gate."""
    edit(
        root,
        LITERAL,
        "            contracts_enabled_from_height: None,",
        "",
    )


def m_locator_ambiguous(root: Path) -> None:
    p = root / GENESIS
    src = p.read_text()
    a = src.index("pub const GATES_PREDATING_ACTIVATION_RECORDING: &[&str] = &[")
    b = src.index("\n];\n", a) + len("\n];\n")
    p.write_text(src[:b] + "\n" + src[a:b] + src[b:])


def m_empty_structure(root: Path) -> None:
    """Declaration intact, locator finds it, and it contains nothing at all."""
    p = root / GENESIS
    src = p.read_text()
    a = src.index("pub const REMEDIATION_GATES: &[&str] = &[")
    b = src.index("\n];\n", a)
    p.write_text(src[: a + len("pub const REMEDIATION_GATES: &[&str] = &[")] + src[b:])


def m_mismatched_name(root: Path) -> None:
    edit(
        root,
        GENESIS,
        '                "omninode_enabled_from_height",\n'
        "                self.omninode_enabled_from_height,",
        '                "omninode_enabled_from_height",\n'
        "                self.omninode_sponsored_attestation_enabled_from_height,",
    )


def m_file_missing(root: Path) -> None:
    (root / LITERAL).unlink()


CASES = [
    # (case name, mutate, expect_exit_nonzero, structure fragment, failure class)
    ("clean", m_clean, False, None, None),
    ("malformed entry", m_malformed_entry, True, "activation_heights", "malformed"),
    ("absent structure", m_absent_structure, True, "REMEDIATION_GATES", "locator-missing"),
    ("duplicate entry", m_duplicate_entry, True, "WIRING", "duplicate"),
    ("fused tuple (heights)", m_fused_tuple_heights, True, "activation_heights", "fused"),
    ("fused tuple (dormant)", m_fused_tuple_dormant, True, "dormant defaults", "fused"),
    ("renamed locator", m_renamed_locator, True, "WIRING", "locator-missing"),
    ("truncated declaration", m_truncated_declaration, True, "WIRING", "truncated"),
    ("set mismatch", m_set_mismatch, True, "local testnet", "set-mismatch"),
    ("ambiguous locator", m_locator_ambiguous, True, "GATES_PREDATING", "locator-ambiguous"),
    ("empty structure", m_empty_structure, True, "REMEDIATION_GATES", "empty"),
    ("mismatched name", m_mismatched_name, True, "activation_heights", "mismatched-name"),
    ("missing file", m_file_missing, True, "local testnet", "file-missing"),
]


def stage(tree: Path, dest: Path) -> None:
    for rel in SOURCES:
        (dest / rel).parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(tree / rel, dest / rel)


def main() -> int:
    tree = Path(sys.argv[1] if len(sys.argv) > 1 else HERE.parent.parent).resolve()
    for rel in SOURCES:
        if not (tree / rel).is_file():
            print(f"FATAL: {tree / rel} not found; give the tree root as argv[1]")
            return 2

    passed, failed = 0, 0
    with tempfile.TemporaryDirectory(prefix="gate-structure-battery-") as tmp:
        for label, mutate, want_fail, want_structure, want_class in CASES:
            box = Path(tmp) / label.replace(" ", "-").replace("(", "").replace(")", "")
            box.mkdir()
            stage(tree, box)
            print("=" * 78)
            print(f"CASE: {label}")
            try:
                mutate(box)
            except AssertionError as e:
                print(f"  BATTERY ERROR: {e}")
                failed += 1
                continue

            r = subprocess.run(
                [sys.executable, str(CHECKER), str(box)],
                capture_output=True,
                text=True,
            )
            out = r.stdout + r.stderr
            print("-" * 78)
            print(out.rstrip())
            print("-" * 78)

            problems = []
            if want_fail:
                if r.returncode == 0:
                    problems.append("checker exited 0 on corrupted source")
                if want_class and want_class not in out:
                    problems.append(f"output never names the class {want_class!r}")
                if want_structure and want_structure not in out:
                    problems.append(f"output never names the structure {want_structure!r}")
                # The class and the structure must meet on ONE line, or the
                # checker merely happened to say both words somewhere.
                if want_class and want_structure:
                    lines = [
                        ln
                        for ln in out.splitlines()
                        if want_class in ln and want_structure in ln
                    ]
                    if not lines:
                        problems.append(
                            f"no single line blames {want_structure!r} for {want_class!r}"
                        )
            else:
                if r.returncode != 0:
                    problems.append(f"checker exited {r.returncode} on CLEAN source")

            if problems:
                failed += 1
                print(f"  RESULT: FAIL (exit {r.returncode})")
                for p in problems:
                    print(f"    - {p}")
            else:
                passed += 1
                verdict = "failed as required" if want_fail else "passed as required"
                detail = f", blaming {want_structure} for {want_class}" if want_fail else ""
                print(f"  RESULT: ok -- checker {verdict} (exit {r.returncode}){detail}")

    print("=" * 78)
    print(f"battery: {passed} passed, {failed} failed, {len(CASES)} cases")
    if not any(c[0] == "clean" for c in CASES):
        print("FATAL: no clean-tree case; the battery proves nothing")
        return 2
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
