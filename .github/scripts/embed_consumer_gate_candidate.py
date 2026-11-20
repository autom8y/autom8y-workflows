"""Embed consumer_gate_candidate.py into satellite-ci-reusable.yml (S-126).

The lint and test jobs each write the consumer-gate helper from a quoted
heredoc in their inputs guard step, so the helper that runs is the one pinned by the
caller's `uses:` line (not a separate checkout at autom8y_workflows_sha). This
script keeps both copies byte-identical to the canonical file:

    python3 .github/scripts/embed_consumer_gate_candidate.py          # rewrite both copies
    python3 .github/scripts/embed_consumer_gate_candidate.py --check  # exit 1 on drift

tests/test_workflow_validation.py runs the same check.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
HELPER = ROOT / ".github" / "scripts" / "consumer_gate_candidate.py"
WORKFLOW = ROOT / ".github" / "workflows" / "satellite-ci-reusable.yml"
MARKER = "CONSUMER_GATE_CANDIDATE_PY"
OPENER_SUFFIX = f"<<'{MARKER}'"
EXPECTED_COPIES = 2


def embed(workflow_text: str, helper_text: str) -> tuple[str, int]:
    """Return the workflow text with every heredoc body replaced, and the copy count."""
    lines = workflow_text.splitlines(keepends=True)
    out: list[str] = []
    copies = 0
    index = 0
    while index < len(lines):
        line = lines[index]
        out.append(line)
        index += 1
        if not line.rstrip("\n").endswith(OPENER_SUFFIX):
            continue
        indent = line[: len(line) - len(line.lstrip(" "))]
        terminator = indent + MARKER
        end = index
        while end < len(lines) and lines[end].rstrip("\n") != terminator:
            end += 1
        if end == len(lines):
            raise ValueError(f"the heredoc opened on line {index} has no {MARKER} terminator")
        for body_line in helper_text.splitlines(keepends=True):
            out.append(indent + body_line if body_line.strip() else body_line)
        out.append(lines[end])
        copies += 1
        index = end + 1
    return "".join(out), copies


def main(argv: list[str]) -> int:
    """Rewrite or check the embedded copies; return the exit code."""
    check_only = argv == ["--check"]
    if argv and not check_only:
        print("usage: embed_consumer_gate_candidate.py [--check]", file=sys.stderr)
        return 2
    workflow_text = WORKFLOW.read_text(encoding="utf-8")
    helper_text = HELPER.read_text(encoding="utf-8")
    updated, copies = embed(workflow_text, helper_text)
    if copies != EXPECTED_COPIES:
        print(f"expected {EXPECTED_COPIES} embedded copies, found {copies}", file=sys.stderr)
        return 1
    if check_only:
        if updated != workflow_text:
            print("the embedded consumer-gate helper differs from the canonical file", file=sys.stderr)
            return 1
        print(f"embedded consumer-gate helper: {copies} copies match")
        return 0
    if updated != workflow_text:
        WORKFLOW.write_text(updated, encoding="utf-8")
        print(f"rewrote {copies} embedded copies")
    else:
        print(f"embedded consumer-gate helper: {copies} copies already match")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
