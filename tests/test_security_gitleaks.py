"""Behaviour tests for .github/workflows/security-gitleaks.yml.

The "Run gitleaks" step body is extracted from the workflow and executed with
bash against throwaway git repositories that contain fake credentials generated
at runtime. The functional tests need the gitleaks binary at the version the
workflow installs; they are skipped when it is absent unless
GITLEAKS_TESTS_REQUIRED=1, in which case they fail instead.
"""

from __future__ import annotations

import json
import math
import os
import re
import secrets
import shutil
import string
import subprocess
from collections import Counter
from pathlib import Path
from typing import Any

import pytest
import yaml

WORKFLOW = (
    Path(__file__).resolve().parent.parent
    / ".github"
    / "workflows"
    / "security-gitleaks.yml"
)
RUN_STEP = "Run gitleaks"

# The scan command as shipped before redaction and enforcement were added.
# Used only as a control: it proves the fixtures below really print their
# values when nothing redacts them.
LEGACY_RUN = (
    "gitleaks detect --source . --report-format sarif "
    "--report-path gitleaks-results.sarif --verbose || true\n"
)

_SUBCOMMAND_RE = re.compile(r"\b(detect|protect|git|dir|directory|stdin)\b")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _workflow() -> dict[str, Any]:
    return yaml.safe_load(WORKFLOW.read_text())


def _steps() -> list[dict[str, Any]]:
    return _workflow()["jobs"]["gitleaks"]["steps"]


def _step(name: str) -> dict[str, Any]:
    matches = [s for s in _steps() if s.get("name") == name]
    assert len(matches) == 1, f"expected exactly one step named {name!r}"
    return matches[0]


def _pinned_version() -> str:
    m = re.search(r"GITLEAKS_VERSION=(\S+)", _step("Install gitleaks")["run"])
    assert m, "Install step does not pin GITLEAKS_VERSION"
    return m.group(1)


def _entropy(value: str) -> float:
    counts = Counter(value)
    return -sum(c / len(value) * math.log2(c / len(value)) for c in counts.values())


def _fake_key_id() -> str:
    alphabet = string.ascii_uppercase + string.digits
    while True:
        body = "".join(secrets.choice(alphabet) for _ in range(16))
        if _entropy(body) > 3.5:
            return "AK" + "IA" + body


def _fake_secret_key() -> str:
    # No vowels and none of the letters or digits of the few vowel-free words
    # in gitleaks' generic-rule stopword list, so the value is always reported.
    alphabet = "bcfgjkrwzBCFGJKRWZ12346789"
    while True:
        value = "".join(secrets.choice(alphabet) for _ in range(40))
        if _entropy(value) > 4.0:
            return value


def _gitleaks_bin() -> str | None:
    path = shutil.which("gitleaks")
    if path is None:
        return None
    out = subprocess.run([path, "version"], capture_output=True, text=True)
    return path if out.stdout.strip().lstrip("v") == _pinned_version() else None


@pytest.fixture(scope="module")
def tool_path() -> str:
    gitleaks = _gitleaks_bin()
    jq = shutil.which("jq")
    git = shutil.which("git")
    if gitleaks is None or jq is None or git is None:
        reason = f"needs gitleaks {_pinned_version()}, jq and git on PATH"
        if os.environ.get("GITLEAKS_TESTS_REQUIRED") == "1":
            pytest.fail(reason)
        pytest.skip(reason)
    dirs = [str(Path(p).parent) for p in (gitleaks, jq, git)]
    return os.pathsep.join(dict.fromkeys(dirs + ["/usr/bin", "/bin"]))


class Repo:
    """A throwaway git repository with a hermetic environment."""

    def __init__(self, root: Path, tool_path: str) -> None:
        self.root = root
        self.env = {
            "PATH": tool_path,
            "HOME": str(root.parent),
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_AUTHOR_NAME": "fixture",
            "GIT_AUTHOR_EMAIL": "fixture@example.invalid",
            "GIT_COMMITTER_NAME": "fixture",
            "GIT_COMMITTER_EMAIL": "fixture@example.invalid",
        }
        root.mkdir()
        self.git("init", "-q", "-b", "main")
        self.git("config", "gc.auto", "0")
        self.commit("README.md", "fixture\n", "init")

    def git(self, *args: str) -> None:
        subprocess.run(
            ["git", *args], cwd=self.root, env=self.env, check=True,
            capture_output=True,
        )

    def commit(self, rel: str, content: str, message: str) -> None:
        path = self.root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
        self.git("add", rel)
        self.git("commit", "-q", "-m", message)

    def plant_aws_pair(self, rel: str) -> tuple[str, str]:
        key_id, secret_key = _fake_key_id(), _fake_secret_key()
        self.commit(
            rel,
            "[default]\n"
            f"aws_access_key_id = {key_id}\n"
            f"aws_secret_access_key = {secret_key}\n",
            f"add {rel}",
        )
        return key_id, secret_key

    def run(self, script: str, **extra_env: str) -> tuple[int, str]:
        proc = subprocess.run(
            ["bash", "--noprofile", "--norc", "-eo", "pipefail", "-c", script],
            cwd=self.root, env={**self.env, **extra_env},
            capture_output=True, text=True,
        )
        return proc.returncode, proc.stdout + proc.stderr

    def run_step(self, baseline_path: str | None = None, script: str | None = None) -> tuple[int, str]:
        step = _step(RUN_STEP)
        step_env = step.get("env", {})
        env = {k: str(v) for k, v in step_env.items() if "${{" not in str(v)}
        env["BASELINE_PATH"] = (
            step_env.get("DEFAULT_BASELINE_PATH", ".gitleaks-baseline.json")
            if baseline_path is None
            else baseline_path
        )
        return self.run(step["run"] if script is None else script, **env)

    def write_baseline(self, rel: str = ".gitleaks-baseline.json", redact: bool = True) -> Path:
        flags = "--redact " if redact else ""
        (self.root / rel).parent.mkdir(parents=True, exist_ok=True)
        rc, _ = self.run(
            f"gitleaks detect --source . {flags}--report-format json "
            f"--report-path {rel} --no-banner"
        )
        assert rc == 1, "baseline generation should report the planted findings"
        assert (self.root / rel).is_file(), "baseline report was not written"
        return self.root / rel


@pytest.fixture
def repo(tmp_path: Path, tool_path: str) -> Repo:
    return Repo(tmp_path / "repo", tool_path)


# ---------------------------------------------------------------------------
# Static contract
# ---------------------------------------------------------------------------


class TestStaticContract:
    def test_every_gitleaks_invocation_redacts(self) -> None:
        invocations = []
        for step in _steps():
            body = step.get("run", "")
            for line in body.splitlines():
                if "gitleaks" in line or line.lstrip().startswith("args=("):
                    if _SUBCOMMAND_RE.search(line) and "releases/download" not in line:
                        invocations.append(line)
        assert invocations, "no gitleaks scan invocation found"
        unredacted = [line for line in invocations if "--redact" not in line]
        assert not unredacted, f"gitleaks invocations without --redact: {unredacted}"

    def test_scan_failure_is_not_swallowed(self) -> None:
        step = _step(RUN_STEP)
        assert "|| true" not in step["run"]
        assert "continue-on-error" not in step
        assert "continue-on-error" not in _workflow()["jobs"]["gitleaks"]

    def test_baseline_input_is_wired_through_env(self) -> None:
        inputs = _workflow()[True]["workflow_call"]["inputs"]
        assert inputs["baseline-path"]["default"] == ".gitleaks-baseline.json"
        assert inputs["baseline-path"]["required"] is False
        step = _step(RUN_STEP)
        assert step["env"]["BASELINE_PATH"] == "${{ inputs.baseline-path }}"
        assert step["env"]["DEFAULT_BASELINE_PATH"] == inputs["baseline-path"]["default"]
        assert "${{" not in step["run"]
        assert '--baseline-path "$BASELINE_PATH"' in step["run"]

    def test_legacy_control_matches_pinned_history(self) -> None:
        assert "--redact" not in LEGACY_RUN and "|| true" in LEGACY_RUN


# ---------------------------------------------------------------------------
# Behaviour
# ---------------------------------------------------------------------------


def _expect(
    text: str,
    *,
    what: str = "log",
    contains: tuple[str, ...] = (),
    lacks: tuple[str, ...] = (),
    values_absent: tuple[str, ...] = (),
    values_present: tuple[str, ...] = (),
) -> None:
    """Check scan output without ever echoing it or a fake value on failure."""
    problems = [f"{what} lacks {n!r}" for n in contains if n not in text]
    problems += [f"{what} contains {n!r}" for n in lacks if n in text]
    shown = sum(v in text for v in values_absent)
    if shown:
        problems.append(f"{shown} fake credential value(s) present in {what}")
    hidden = sum(v not in text for v in values_present)
    if hidden:
        problems.append(f"control: {hidden} fake credential value(s) missing from {what}")
    if problems:
        raise AssertionError("; ".join(problems))


class TestRedactedEnforcingScan:
    def test_a_new_finding_fails_and_is_redacted(self, repo: Repo) -> None:
        values = repo.plant_aws_pair("config/credentials")
        rc, log = repo.run_step()
        assert rc == 1
        _expect(log, contains=("REDACTED", "leaks found: 2"), values_absent=values)
        sarif = (repo.root / "gitleaks-results.sarif").read_text()
        _expect(sarif, what="SARIF report", contains=("REDACTED",), values_absent=values)

    def test_b_baselined_finding_passes(self, repo: Repo) -> None:
        values = repo.plant_aws_pair("config/credentials")
        baseline = repo.write_baseline()
        entries = json.loads(baseline.read_text())
        assert len(entries) == 2
        assert all(e["Secret"] == "REDACTED" and e["Fingerprint"] for e in entries)
        _expect(baseline.read_text(), what="baseline", values_absent=values)
        repo.git("add", ".gitleaks-baseline.json")
        repo.git("commit", "-q", "-m", "add baseline")

        rc, log = repo.run_step()
        assert rc == 0
        _expect(log, contains=("(2 entries)", "no leaks found"), values_absent=values)

    def test_c_other_new_finding_still_fails_with_baseline(self, repo: Repo) -> None:
        old = repo.plant_aws_pair("config/credentials")
        repo.write_baseline()
        repo.git("add", ".gitleaks-baseline.json")
        repo.git("commit", "-q", "-m", "add baseline")
        new = repo.plant_aws_pair("deploy/other-credentials")

        rc, log = repo.run_step()
        assert rc == 1
        _expect(
            log,
            contains=("REDACTED", "deploy/other-credentials", "leaks found: 2"),
            values_absent=old + new,
        )
        old_reported = re.search(r"File:\s+config/credentials", log) is not None
        assert not old_reported, "a baselined finding was reported"

    def test_d_control_legacy_command_prints_values(self, repo: Repo) -> None:
        values = repo.plant_aws_pair("config/credentials")
        rc, log = repo.run_step(script=LEGACY_RUN)
        assert rc == 0, "legacy command swallowed the finding"
        _expect(log, values_present=values)

    def test_d_control_step_without_redact_prints_values(self, repo: Repo) -> None:
        values = repo.plant_aws_pair("config/credentials")
        mutated = _step(RUN_STEP)["run"].replace(" --redact", "")
        rc, log = repo.run_step(script=mutated)
        assert rc == 1
        _expect(log, values_present=values)


class TestBaselineGuards:
    def test_unredacted_baseline_is_refused(self, repo: Repo) -> None:
        repo.plant_aws_pair("config/credentials")
        repo.write_baseline(redact=False)
        rc, log = repo.run_step()
        assert rc == 1
        _expect(
            log,
            contains=("not a redacted gitleaks JSON report",),
            lacks=("leaks found",),
        )

    def test_missing_custom_baseline_fails(self, repo: Repo) -> None:
        rc, log = repo.run_step(baseline_path="security/missing.json")
        assert rc == 1
        _expect(log, contains=("not found",))

    def test_missing_default_baseline_scans_without_one(self, repo: Repo) -> None:
        rc, log = repo.run_step()
        assert rc == 0
        _expect(log, contains=("No baseline", "no leaks found"))

    def test_custom_baseline_path(self, repo: Repo) -> None:
        values = repo.plant_aws_pair("config/credentials")
        repo.write_baseline(rel="security/gitleaks-baseline.json")
        rc, log = repo.run_step(baseline_path="security/gitleaks-baseline.json")
        assert rc == 0
        _expect(
            log,
            contains=("Using baseline security/gitleaks-baseline.json",),
            values_absent=values,
        )
