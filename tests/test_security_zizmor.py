"""Behaviour tests for .github/workflows/security-zizmor.yml.

The "Run zizmor" step body is extracted from the workflow and executed with
bash against throwaway fixture trees. The functional tests need the zizmor
binary at the version the workflow installs; they are skipped when it is
absent unless ZIZMOR_TESTS_REQUIRED=1, in which case they fail instead.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest
import yaml

WORKFLOWS = Path(__file__).resolve().parent.parent / ".github" / "workflows"
WORKFLOW = WORKFLOWS / "security-zizmor.yml"
CI_WORKFLOW = WORKFLOWS / "ci.yml"
RUN_STEP = "Run zizmor"

# The scan command as shipped before the count and threshold were added.
# Used only as a control: it proves the fixtures below would have passed.
LEGACY_RUN = "zizmor --format sarif . > zizmor-results.sarif || true\n"

PINNED_SHA = "93cb6efe18208431cddfb8368fd83d5badbf9bfd"
HEADER = "name: w\non:\n  push:\npermissions: {}\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n"

CLEAN = HEADER + "      - run: echo hi\n"
# One fixture per severity; each yields findings of exactly that severity.
BY_SEVERITY = {
    "informational": HEADER + '      - id: s\n        run: echo hi\n      - run: echo "${{ steps.s.outputs.x }}"\n',
    "low": HEADER + '      - run: echo "${{ env.FOO }}"\n',
    "medium": HEADER + '      - run: echo "${{ secrets.X }}"\n',
    "high": HEADER + "      - uses: some-org/some-action@main\n",
}
RANK = {"informational": 1, "low": 2, "medium": 3, "high": 4}
# pull_request_target with a checkout of the pull request head.
PR_TARGET = (
    "name: w\non:\n  pull_request_target:\npermissions: {}\njobs:\n  a:\n"
    "    runs-on: ubuntu-latest\n    steps:\n"
    f"      - uses: actions/checkout@{PINNED_SHA} # v5.0.1\n"
    "        with:\n"
    "          ref: ${{ github.event.pull_request.head.sha }}\n"
    "          persist-credentials: false\n"
    "      - run: make\n"
)


def _workflow() -> dict[str, Any]:
    return yaml.safe_load(WORKFLOW.read_text())


def _steps() -> list[dict[str, Any]]:
    return _workflow()["jobs"]["zizmor"]["steps"]


def _step(name: str) -> dict[str, Any]:
    matches = [s for s in _steps() if s.get("name") == name]
    assert len(matches) == 1, f"expected exactly one step named {name!r}"
    return matches[0]


def _pinned_version() -> str:
    m = re.fullmatch(r"pip install zizmor==(\S+)", _step("Install zizmor")["run"].strip())
    assert m, "Install step does not pin an exact zizmor version"
    return m.group(1)


def _zizmor_bin() -> str | None:
    path = shutil.which("zizmor")
    if path is None:
        return None
    out = subprocess.run([path, "--version"], capture_output=True, text=True)
    return path if out.stdout.split()[-1:] == [_pinned_version()] else None


@pytest.fixture(scope="module")
def zizmor() -> str:
    path = _zizmor_bin()
    if path is None or shutil.which("jq") is None:
        reason = f"needs zizmor {_pinned_version()} and jq on PATH"
        if os.environ.get("ZIZMOR_TESTS_REQUIRED") == "1":
            pytest.fail(reason)
        pytest.skip(reason)
    return path


class Tree:
    """A fixture checkout plus the runner files the step writes to."""

    def __init__(self, tmp: Path, zizmor: str, workflows: dict[str, str]) -> None:
        self.tmp = tmp
        self.root = tmp / "repo"
        self.bin = tmp / "bin"
        self.bin.mkdir()
        (self.bin / "zizmor").symlink_to(zizmor)
        wf = self.root / ".github" / "workflows"
        wf.mkdir(parents=True)
        for name, body in workflows.items():
            (wf / name).write_text(body)
        self.summary = tmp / "summary.md"
        self.output = tmp / "output.txt"

    def wrap(self, body: str) -> None:
        """Replace zizmor on PATH with a script around the real binary."""
        real = (self.bin / "zizmor").resolve()
        (self.bin / "zizmor").unlink()
        script = self.bin / "zizmor"
        script.write_text(f'#!/bin/bash\nREAL="{real}"\n{body}\n')
        script.chmod(0o755)

    def run(self, script: str | None = None, fail_on: str = "none",
            visibility: str = "private", head_repo: str = "") -> tuple[int, str]:
        jq_dir = str(Path(shutil.which("jq") or "jq").parent)
        env = {
            "PATH": os.pathsep.join(dict.fromkeys([str(self.bin), jq_dir, "/usr/bin", "/bin"])),
            "HOME": str(self.tmp),
            "ZIZMOR_OFFLINE": "true",
            "RUNNER_TEMP": str(self.tmp),
            "GITHUB_STEP_SUMMARY": str(self.summary),
            "GITHUB_OUTPUT": str(self.output),
            "FAIL_ON": fail_on,
            "VISIBILITY": visibility,
            "HEAD_REPO": head_repo,
            "REPO": "org/repo",
        }
        # The runner's default shell for `run:` steps is `bash -e {0}`.
        proc = subprocess.run(
            ["bash", "--noprofile", "--norc", "-e", "-c", script or _step(RUN_STEP)["run"]],
            cwd=self.root, env=env, capture_output=True, text=True,
        )
        return proc.returncode, proc.stdout + proc.stderr

    def summary_text(self) -> str:
        return self.summary.read_text() if self.summary.exists() else ""

    def sink(self) -> str | None:
        if not self.output.exists():
            return None
        m = re.search(r"^sink=(.*)$", self.output.read_text(), re.M)
        return m.group(1) if m else None


def _count(summary: str) -> int:
    m = re.search(r"^zizmor: (\d+) findings \(", summary, re.M)
    assert m, f"no count line in summary:\n{summary}"
    return int(m.group(1))


def _exit_code(summary: str) -> int:
    m = re.search(r"^- exit code: (\d+)$", summary, re.M)
    assert m, f"no exit code line in summary:\n{summary}"
    return int(m.group(1))


# ---------------------------------------------------------------------------
# Structure
# ---------------------------------------------------------------------------


def test_nothing_masks_a_failure() -> None:
    text = WORKFLOW.read_text()
    assert "|| true" not in text
    assert "continue-on-error" not in text


def test_default_threshold_reports_only() -> None:
    data = _workflow()
    inputs = data.get("on", data.get(True))["workflow_call"]["inputs"]
    assert inputs["fail_on_severity"]["default"] == "none"


def test_ci_installs_the_pinned_version() -> None:
    ci = CI_WORKFLOW.read_text()
    assert f"zizmor=={_pinned_version()}" in ci


def test_private_sarif_is_a_short_lived_artifact() -> None:
    step = _step("Upload SARIF as an artifact")
    assert 1 <= int(step["with"]["retention-days"]) <= 3
    assert "sink == 'artifact'" in step["if"]
    assert "sink == 'code-scanning'" in _step("Upload SARIF to code scanning")["if"]


# ---------------------------------------------------------------------------
# Behaviour
# ---------------------------------------------------------------------------


def test_clean_tree_is_green(tmp_path: Path, zizmor: str) -> None:
    tree = Tree(tmp_path, zizmor, {"ok.yml": CLEAN})
    rc, out = tree.run(fail_on="informational")
    assert rc == 0, out
    assert _count(tree.summary_text()) == 0
    assert _exit_code(tree.summary_text()) == 0


def test_findings_are_counted_and_reported_by_default(tmp_path: Path, zizmor: str) -> None:
    tree = Tree(tmp_path, zizmor, {"prt.yml": PR_TARGET, "unpinned.yml": BY_SEVERITY["high"]})
    rc, out = tree.run()
    assert rc == 0, out
    summary = tree.summary_text()
    assert _count(summary) >= 2
    assert _exit_code(summary) == 14
    assert "report only" in summary


def test_legacy_step_never_failed(tmp_path: Path, zizmor: str) -> None:
    """Control: the old step exits 0 on the same tree the new step fails."""
    tree = Tree(tmp_path, zizmor, {"prt.yml": PR_TARGET, "unpinned.yml": BY_SEVERITY["high"]})
    assert tree.run(script=LEGACY_RUN)[0] == 0
    assert tree.run(fail_on="high")[0] == 1


@pytest.mark.parametrize("severity", list(BY_SEVERITY))
def test_threshold_is_two_sided(tmp_path: Path, zizmor: str, severity: str) -> None:
    tree = Tree(tmp_path, zizmor, {"w.yml": BY_SEVERITY[severity]})
    rc, out = tree.run(fail_on=severity)
    assert rc == 1, out
    assert _exit_code(tree.summary_text()) == 10 + RANK[severity]
    above = [s for s, r in RANK.items() if r == RANK[severity] + 1]
    for fail_on in above + ["none"]:
        rc, out = tree.run(fail_on=fail_on)
        assert rc == 0, f"fail_on={fail_on}: {out}"


def test_invalid_argument_is_red(tmp_path: Path, zizmor: str) -> None:
    tree = Tree(tmp_path, zizmor, {"ok.yml": CLEAN})
    tree.wrap('exec "$REAL" --not-a-flag "$@"')
    rc, out = tree.run()
    assert rc == 1, out
    assert "zizmor did not complete: exit code 2" in tree.summary_text()


def test_sarif_run_error_is_red(tmp_path: Path, zizmor: str) -> None:
    tree = Tree(tmp_path, zizmor, {"ok.yml": CLEAN})
    tree.wrap('case " $* " in *" sarif "*) exec "$REAL" --not-a-flag "$@" ;; esac\nexec "$REAL" "$@"')
    rc, out = tree.run()
    assert rc == 1, out
    assert "SARIF run exit code 2" in tree.summary_text()


def test_no_inputs_is_red(tmp_path: Path, zizmor: str) -> None:
    tree = Tree(tmp_path, zizmor, {})
    rc, out = tree.run()
    assert rc == 1, out
    assert "did not complete" in tree.summary_text()


def test_masked_exit_code_is_red(tmp_path: Path, zizmor: str) -> None:
    tree = Tree(tmp_path, zizmor, {"w.yml": BY_SEVERITY["high"]})
    tree.wrap('"$REAL" "$@"; exit 0')
    rc, out = tree.run()
    assert rc == 1, out
    assert "does not match the findings" in tree.summary_text()


def test_invalid_threshold_is_red(tmp_path: Path, zizmor: str) -> None:
    tree = Tree(tmp_path, zizmor, {"ok.yml": CLEAN})
    rc, out = tree.run(fail_on="severe")
    assert rc == 1, out


@pytest.mark.parametrize(
    ("visibility", "head_repo", "sink"),
    [
        ("private", "", "artifact"),
        ("internal", "", "artifact"),
        ("public", "", "code-scanning"),
        ("public", "org/repo", "code-scanning"),
        ("public", "someone/fork", "none"),
        ("", "", "none"),
    ],
)
def test_sarif_sink(tmp_path: Path, zizmor: str, visibility: str, head_repo: str, sink: str) -> None:
    tree = Tree(tmp_path, zizmor, {"ok.yml": CLEAN})
    rc, out = tree.run(visibility=visibility, head_repo=head_repo)
    assert rc == 0, out
    assert tree.sink() == sink


def test_crash_sets_no_sink(tmp_path: Path, zizmor: str) -> None:
    tree = Tree(tmp_path, zizmor, {"ok.yml": CLEAN})
    tree.wrap('exec "$REAL" --not-a-flag "$@"')
    tree.run()
    assert tree.sink() is None
