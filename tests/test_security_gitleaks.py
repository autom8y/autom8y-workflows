"""Behaviour tests for .github/workflows/security-gitleaks.yml.

The "Run gitleaks" and "List findings" step bodies are extracted from the
workflow and executed with bash against throwaway git repositories that contain
fake credentials generated at runtime. The functional tests need the gitleaks
binary at the version the workflow installs; they are skipped when it is absent
unless GITLEAKS_TESTS_REQUIRED=1, in which case they fail instead.
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
import textwrap
import tomllib
from collections import Counter
from pathlib import Path
from typing import Any

import pytest
import yaml

WORKFLOWS = Path(__file__).resolve().parent.parent / ".github" / "workflows"
WORKFLOW = WORKFLOWS / "security-gitleaks.yml"
CI_WORKFLOW = WORKFLOWS / "ci.yml"
RUN_STEP = "Run gitleaks"
LIST_STEP = "List findings"

# The scan command as shipped before redaction and enforcement were added.
# Used only as a control: it proves the fixtures below really print their
# values when nothing redacts them.
LEGACY_RUN = (
    "gitleaks detect --source . --report-format sarif "
    "--report-path gitleaks-results.sarif --verbose || true\n"
)

_SUBCOMMAND_RE = re.compile(r"\b(detect|protect|git|dir|directory|stdin)\b")

# A fragment is any substring of this many characters of a planted value.
FRAGMENT = 6


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


def _optional_step(name: str) -> dict[str, Any] | None:
    matches = [s for s in _steps() if s.get("name") == name]
    return matches[0] if matches else None


def _pinned_version() -> str:
    m = re.search(r"GITLEAKS_VERSION=(\S+)", _step("Install gitleaks")["run"])
    assert m, "Install step does not pin GITLEAKS_VERSION"
    return m.group(1)


def _appended_rule() -> dict[str, Any]:
    """The rule the Run step appends, parsed from its heredoc."""
    body = _step(RUN_STEP)["run"]
    m = re.search(r"<<'EOF'\n(.*?)\nEOF\n", body, re.S)
    assert m, "Run step does not append the rule with a quoted heredoc"
    rules = tomllib.loads(textwrap.dedent(m.group(1)))["rules"]
    assert len(rules) == 1
    return rules[0]


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


def _fake_password() -> str:
    alphabet = string.ascii_letters + string.digits + "!#%+"
    while True:
        value = "".join(secrets.choice(alphabet) for _ in range(16))
        if _entropy(value) > 3.5:
            return value


def _random(alphabet: str, n: int) -> str:
    # Short values cannot reach 3.5 bits (at most log2(n)), so the floor scales.
    floor = min(3.5, math.log2(n) - 0.5)
    while True:
        value = "".join(secrets.choice(alphabet) for _ in range(n))
        if _entropy(value) > floor:
            return value


ALNUM = string.ascii_letters + string.digits
URLSAFE = ALNUM + "-_"
SERVICE_RULE = "autom8y-service-api-key"
_PUBLIC_PREFIX = re.compile(r"^(?:sk_[a-z]+_|a8[a-z]{2}_)")


def _prefixed(kind: str, env: str, body: str) -> str:
    return kind + "_" + env + "_" + body


def _a8(kind: str, body: str) -> str:
    return "a8" + kind + "_" + body


def _allowlisted(key: str) -> bool:
    """Whether the appended rule's placeholder allowlist covers KEY."""
    rule = _appended_rule()
    return any(re.search(rx, key) for a in rule.get("allowlists", []) for rx in a["regexes"])


def _is_reported(key: str) -> bool:
    """Whether the appended rule should report KEY, per its own config."""
    return _entropy(key) > _appended_rule()["entropy"] and not _allowlisted(key)


def _draw(make: Any, accept: Any, what: str) -> str:
    """Draw from MAKE until ACCEPT holds; fail (never hang) if it cannot."""
    for _ in range(20000):
        key = make()
        if accept(key):
            return key
    pytest.fail(f"could not draw {what}")


def _real_shaped(make: Any) -> str:
    """A key from MAKE that the rule's placeholder allowlist does not cover.

    Entropy is deliberately NOT filtered here: a real key is whatever the
    generator emits, so a raised entropy floor must show up as a miss.
    """
    return _draw(make, lambda k: not _allowlisted(k), "a real-shaped key")


def _fragments(text: str, values: tuple[str, ...]) -> int:
    """How many VALUES have a substring of FRAGMENT or more characters in TEXT.

    A known public key prefix (sk_<env>_, a8xx_) is not a fragment of the secret.
    """
    shown = 0
    for value in values:
        body = _PUBLIC_PREFIX.sub("", value)
        if any(body[i:i + FRAGMENT] in text for i in range(len(body) - FRAGMENT + 1)):
            shown += 1
    return shown


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
        self.summary_path = root.parent / "step-summary.md"
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
        # The runner's default shell for `run:` steps is `bash -e {0}`.
        proc = subprocess.run(
            ["bash", "--noprofile", "--norc", "-e", "-c", script],
            cwd=self.root, env={**self.env, **extra_env},
            capture_output=True, text=True,
        )
        return proc.returncode, proc.stdout + proc.stderr

    def plant_value(self, rel: str, value: str) -> str:
        self.commit(rel, f"value: {value}\n", f"add {rel}")
        return value

    def plant_lines(self, rel: str, values: list[str]) -> None:
        self.commit(rel, "".join(f"value: {v}\n" for v in values), f"add {rel}")

    def sarif(self) -> str:
        return (self.root / "gitleaks-results.sarif").read_text()

    def sarif_results(self) -> list[dict[str, Any]]:
        sarif = json.loads(self.sarif())
        return [r for run in sarif["runs"] for r in run.get("results", [])]

    def sarif_rule_ids(self) -> set[str]:
        return {r["ruleId"] for r in self.sarif_results()}

    def summary(self) -> str:
        return self.summary_path.read_text() if self.summary_path.exists() else ""

    def run_step(self, baseline_path: str | None = None, script: str | None = None) -> tuple[int, str]:
        """Run the scan step, then the listing step as the runner would (if: always()).

        Returns the scan step's exit code and the combined log of both steps.
        """
        inputs = _workflow()[True]["workflow_call"]["inputs"]
        step = _step(RUN_STEP)
        env = {k: str(v) for k, v in step.get("env", {}).items() if "${{" not in str(v)}
        env["BASELINE_PATH"] = (
            str(inputs["baseline-path"].get("default", "")) if baseline_path is None else baseline_path
        )
        rc, log = self.run(step["run"] if script is None else script, **env)
        listing = _optional_step(LIST_STEP)
        if listing is not None:
            self.summary_path.unlink(missing_ok=True)
            _, list_log = self.run(listing["run"], GITHUB_STEP_SUMMARY=str(self.summary_path))
            log += list_log
        return rc, log

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


def _scan_args() -> list[str]:
    body = _step(RUN_STEP)["run"]
    m = re.search(r"^\s*args=\((.*)\)\s*$", body, re.M)
    assert m, "no args=(...) line in the Run step"
    return m.group(1).split()


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

    def test_scan_does_not_print_findings_or_debug_logs(self) -> None:
        args = _scan_args()
        assert "--redact" in args
        printing = [a for a in args if a in ("--verbose", "-v") or a.startswith(("--log-level", "-l"))]
        assert not printing, f"scan flags that print finding context: {printing}"
        assert "--verbose" not in _step(RUN_STEP)["run"]

    def test_listing_prints_rule_location_and_commit_only(self) -> None:
        listing = _step(LIST_STEP)
        assert listing.get("if") == "always()"
        body = listing["run"]
        assert "gitleaks-results.sarif" in body
        for field in ("snippet", "message", "Match", "Secret", "commitMessage", "email", "author"):
            assert field not in body, f"listing reads {field!r}"

    def test_scan_failure_is_not_swallowed(self) -> None:
        step = _step(RUN_STEP)
        assert "|| true" not in step["run"]
        assert "continue-on-error" not in step
        assert "continue-on-error" not in _workflow()["jobs"]["gitleaks"]

    def test_baseline_is_opt_in(self) -> None:
        inputs = _workflow()[True]["workflow_call"]["inputs"]
        assert inputs["baseline-path"]["default"] == ""
        assert inputs["baseline-path"]["required"] is False
        step = _step(RUN_STEP)
        assert step["env"] == {"BASELINE_PATH": "${{ inputs.baseline-path }}"}
        assert "${{" not in step["run"]
        assert '--baseline-path "$BASELINE_PATH"' in step["run"]
        assert ".gitleaks-baseline.json" not in step["run"]

    def test_install_verifies_the_download(self) -> None:
        prod = _step("Install gitleaks")["run"]
        ci_steps = yaml.safe_load(CI_WORKFLOW.read_text())["jobs"]["gitleaks-workflow-tests"]["steps"]
        ci = next(s for s in ci_steps if s.get("name") == "Install gitleaks")["run"]

        def pins(body: str) -> tuple[str, str]:
            version = re.search(r"GITLEAKS_VERSION=(\S+)", body)
            digest = re.search(r"GITLEAKS_SHA256=([0-9a-f]{64})\b", body)
            assert version and digest, "Install step lacks a version or sha256 pin"
            return version.group(1), digest.group(1)

        assert pins(prod) == pins(ci)
        for body in (prod, ci):
            assert "sha256sum -c" in body
            assert "| tar" not in body, "the archive must be verified before it is extracted"
            assert body.index("sha256sum -c") < body.index("tar x")

    def test_only_the_sarif_report_leaves_the_runner(self) -> None:
        uploads = [s for s in _steps() if "upload" in s.get("uses", "")]
        assert [s["uses"].split("@")[0] for s in uploads] == ["github/codeql-action/upload-sarif"]
        assert uploads[0]["with"]["sarif_file"] == "gitleaks-results.sarif"

    def test_service_key_rule_is_appended(self) -> None:
        body = _step(RUN_STEP)["run"]
        assert f'id = "{SERVICE_RULE}"' in body
        assert "useDefault = true" in body
        assert body.index(SERVICE_RULE) < body.index("args=(detect")
        rule = _appended_rule()
        assert rule["id"] == SERVICE_RULE and rule["secretGroup"] == 1
        for prefix in ("sk_prod_", "a8sa_", "a8ak_", "a8sk_"):
            assert prefix in rule["keywords"]

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
    """Check scan output without ever echoing it or a fake value on failure.

    values_absent: no fragment (FRAGMENT or more characters) of any value.
    values_present: the full value (controls).
    """
    problems = [f"{what} lacks {n!r}" for n in contains if n not in text]
    problems += [f"{what} contains {n!r}" for n in lacks if n in text]
    shown = _fragments(text, values_absent)
    if shown:
        problems.append(f"fragments of {shown} fake credential value(s) present in {what}")
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
        _expect(log, contains=("leaks found: 2", "config/credentials:2"), values_absent=values)
        _expect(repo.sarif(), what="SARIF report", contains=("REDACTED",), values_absent=values)
        _expect(repo.summary(), what="step summary", contains=("config/credentials:3",), values_absent=values)

    def test_b_baselined_finding_passes(self, repo: Repo) -> None:
        values = repo.plant_aws_pair("config/credentials")
        baseline = repo.write_baseline()
        entries = json.loads(baseline.read_text())
        assert len(entries) == 2
        assert all(e["Secret"] == "REDACTED" and e["Fingerprint"] for e in entries)
        _expect(baseline.read_text(), what="baseline", values_absent=values)
        repo.git("add", ".gitleaks-baseline.json")
        repo.git("commit", "-q", "-m", "add baseline")

        rc, log = repo.run_step(baseline_path=".gitleaks-baseline.json")
        assert rc == 0
        _expect(log, contains=("(2 entries)", "no leaks found"), values_absent=values)
        assert repo.summary() == ""

    def test_c_other_new_finding_still_fails_with_baseline(self, repo: Repo) -> None:
        old = repo.plant_aws_pair("config/credentials")
        repo.write_baseline()
        repo.git("add", ".gitleaks-baseline.json")
        repo.git("commit", "-q", "-m", "add baseline")
        new = repo.plant_aws_pair("deploy/other-credentials")

        rc, log = repo.run_step(baseline_path=".gitleaks-baseline.json")
        assert rc == 1
        _expect(
            log,
            contains=("deploy/other-credentials:2", "leaks found: 2"),
            lacks=("config/credentials",),
            values_absent=old + new,
        )

    def test_d_control_legacy_command_prints_values(self, repo: Repo) -> None:
        values = repo.plant_aws_pair("config/credentials")
        rc, log = repo.run_step(script=LEGACY_RUN)
        assert rc == 0, "legacy command swallowed the finding"
        _expect(log, values_present=values)

    def test_d_control_step_without_redact_writes_values_to_sarif(self, repo: Repo) -> None:
        values = repo.plant_aws_pair("config/credentials")
        mutated = _step(RUN_STEP)["run"].replace(" --redact", "")
        rc, _ = repo.run_step(script=mutated)
        assert rc == 1
        _expect(repo.sarif(), what="SARIF report", values_present=values)


class TestSameLineNeighbours:
    """Values that share a line with a finding must not reach any surface."""

    @staticmethod
    def _plant_console_csv(repo: Repo) -> tuple[str, ...]:
        password, key_id, secret_key = _fake_password(), _fake_key_id(), _fake_secret_key()
        repo.commit(
            "exports/credentials.csv",
            "User name,Password,Access key ID,Secret access key,Console login link\n"
            f"fixture-user,{password},{key_id},{secret_key},https://console.example.invalid/\n",
            "add exports/credentials.csv",
        )
        return password, key_id, secret_key

    def test_password_and_aws_csv_on_one_line(self, repo: Repo) -> None:
        values = self._plant_console_csv(repo)
        rc, log = repo.run_step()
        assert rc == 1
        shown = _fragments(log, values)
        assert shown == 0, f"log: fragments of {shown} of {len(values)} same-line values"
        _expect(log, contains=("aws-access-token", "exports/credentials.csv:2"))
        _expect(repo.sarif(), what="SARIF report", contains=("REDACTED",), values_absent=values)
        _expect(
            repo.summary(), what="step summary",
            contains=("aws-access-token", "exports/credentials.csv:2"), values_absent=values,
        )
        leftovers = [p for p in repo.root.iterdir() if p.name not in (".git", "README.md", "exports")]
        assert sorted(p.name for p in leftovers) == [".gitleaks.toml", "gitleaks-results.sarif"]

    def test_service_key_with_neighbour_on_one_line(self, repo: Repo) -> None:
        key = _real_shaped(lambda: _a8("sa", secrets.token_urlsafe(32)))
        neighbour = _fake_password()
        repo.commit("svc/env", f"{neighbour} {key} {neighbour[::-1]}\n", "add svc/env")
        rc, log = repo.run_step()
        assert rc == 1
        values = (key, neighbour, neighbour[::-1])
        _expect(log, contains=(SERVICE_RULE, "svc/env:1"), values_absent=values)
        _expect(repo.sarif(), what="SARIF report", values_absent=values)
        _expect(repo.summary(), what="step summary", values_absent=values)

    def test_control_verbose_prints_same_line_neighbours(self, repo: Repo) -> None:
        values = self._plant_console_csv(repo)
        body = _step(RUN_STEP)["run"]
        mutated = body.replace("--report-path gitleaks-results.sarif", "--report-path gitleaks-results.sarif --verbose")
        assert mutated != body
        rc, log = repo.run_step(script=mutated)
        assert rc == 1
        shown = _fragments(log, values[::2])
        assert shown == 2, f"control: --verbose showed fragments of only {shown} of 2 neighbours"


class TestBaselineGuards:
    def test_unredacted_baseline_is_refused(self, repo: Repo) -> None:
        values = repo.plant_aws_pair("config/credentials")
        repo.write_baseline(redact=False)
        rc, log = repo.run_step(baseline_path=".gitleaks-baseline.json")
        assert rc == 1
        _expect(
            log,
            contains=("not a redacted gitleaks JSON report",),
            lacks=("leaks found",),
            values_absent=values,
        )

    def test_raw_match_baseline_is_refused(self, repo: Repo) -> None:
        values = repo.plant_aws_pair("config/credentials")
        raw = json.loads(repo.write_baseline(rel="raw.json", redact=False).read_text())
        (repo.root / "raw.json").unlink()
        forged = [{**e, "Secret": "REDACTED"} for e in raw]
        assert all("REDACTED" not in e["Match"] for e in forged)
        (repo.root / ".gitleaks-baseline.json").write_text(json.dumps(forged))
        rc, log = repo.run_step(baseline_path=".gitleaks-baseline.json")
        assert rc == 1
        _expect(
            log,
            contains=("not a redacted gitleaks JSON report",),
            lacks=("leaks found", "Using baseline"),
            values_absent=values,
        )

    def test_missing_custom_baseline_fails(self, repo: Repo) -> None:
        rc, log = repo.run_step(baseline_path="security/missing.json")
        assert rc == 1
        _expect(log, contains=("not found",), lacks=("leaks found",))

    def test_no_baseline_by_default(self, repo: Repo) -> None:
        rc, log = repo.run_step()
        assert rc == 0
        _expect(log, contains=("No baseline; every finding fails the job.", "no leaks found"))

    def test_baseline_at_a_path_the_caller_did_not_set_is_ignored(self, repo: Repo) -> None:
        # A change that adds its own baseline cannot hide its own finding.
        values = repo.plant_aws_pair("config/credentials")
        repo.write_baseline()
        repo.git("add", ".gitleaks-baseline.json")
        repo.git("commit", "-q", "-m", "add baseline")
        rc, log = repo.run_step()
        assert rc == 1
        _expect(log, contains=("No baseline", "leaks found: 2"), lacks=("Using baseline",), values_absent=values)
        # Control: the same file does suppress both findings when the caller opts in.
        rc, log = repo.run_step(baseline_path=".gitleaks-baseline.json")
        assert rc == 0
        _expect(log, contains=("(2 entries)", "no leaks found"))

    def test_gitleaksignore_is_named_when_present(self, repo: Repo) -> None:
        values = repo.plant_aws_pair("config/credentials")
        report = json.loads(repo.write_baseline(rel="fp.json").read_text())
        (repo.root / "fp.json").unlink()
        repo.commit(".gitleaksignore", "".join(e["Fingerprint"] + "\n" for e in report), "add ignore")
        rc, log = repo.run_step()
        assert rc == 0
        _expect(
            log,
            contains=("findings not listed in .gitleaksignore fail the job", "no leaks found"),
            lacks=("every finding fails",),
            values_absent=values,
        )

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


def _low_entropy_hex_key() -> str:
    """A genuine a8sa_ + token_hex(16) output whose entropy is at most 3.5.

    About 1 in 70 real hex keys is this low; a 3.5 floor would miss them.
    """
    return _draw(
        lambda: _a8("sa", secrets.token_hex(16)),
        lambda k: 3.0 < _entropy(k) <= 3.5 and not _allowlisted(k),
        "a low-entropy hex key",
    )


REAL_FORMATS = {
    "a8sa_ urlsafe": lambda: _a8("sa", secrets.token_urlsafe(32)),
    "a8sa_ hex": lambda: _a8("sa", secrets.token_hex(16)),
    "a8ak_ urlsafe": lambda: _a8("ak", secrets.token_urlsafe(32)),
    "a8sk_ urlsafe": lambda: _a8("sk", secrets.token_urlsafe(32)),
    "sk_staging_ alnum": lambda: _prefixed("sk", "staging", "".join(secrets.choice(ALNUM) for _ in range(32))),
    "sk_local_ urlsafe": lambda: _prefixed("sk", "local", secrets.token_urlsafe(32)),
}


def _placeholders() -> list[str]:
    seq = string.ascii_lowercase + string.digits
    return [
        _prefixed("sk", "staging", seq[:32]),
        _a8("sa", "1234567890" * 4),
        _a8("ak", "your_service_api_key_goes_here_" + _random(ALNUM, 8)),
        _prefixed("sk", "local", "fake_key_for_unit_tests_" + _random(ALNUM, 10)),
        _a8("sa", "test_secret_" + _random(URLSAFE, 24)),
        _a8("sk", "example_" + _random(ALNUM, 28)),
        _prefixed("sk", "dev", "dummy_" + _random(ALNUM, 30)),
    ]


class TestServiceKeyRule:
    def test_service_key_is_caught_and_redacted(self, repo: Repo) -> None:
        value = repo.plant_value("svc/env", _real_shaped(lambda: _prefixed("sk", "prod", _random(ALNUM, 32))))
        rc, log = repo.run_step()
        assert rc == 1
        _expect(log, contains=(SERVICE_RULE,), values_absent=(value,))
        assert SERVICE_RULE in repo.sarif_rule_ids()
        _expect(repo.sarif(), what="SARIF report", contains=("REDACTED",), values_absent=(value,))

    def test_other_envs_and_urlsafe_keys_are_caught(self, repo: Repo) -> None:
        values = (
            repo.plant_value("svc/staging", _real_shaped(lambda: _prefixed("sk", "staging", _random(ALNUM, 32)))),
            repo.plant_value("svc/local", _real_shaped(lambda: _prefixed("sk", "local", _random(URLSAFE, 43)))),
        )
        rc, log = repo.run_step()
        assert rc == 1
        _expect(log, contains=("leaks found: 2",), values_absent=values)
        assert repo.sarif_rule_ids() == {SERVICE_RULE}

    def test_current_formats_are_caught(self, repo: Repo) -> None:
        values = [_real_shaped(make) for make in REAL_FORMATS.values()] + [_low_entropy_hex_key()]
        repo.plant_lines("svc/keys", values)
        rc, log = repo.run_step()
        assert rc == 1
        results = repo.sarif_results()
        assert [r["ruleId"] for r in results] == [SERVICE_RULE] * len(values)
        lines = sorted(r["locations"][0]["physicalLocation"]["region"]["startLine"] for r in results)
        assert lines == list(range(1, len(values) + 1))
        _expect(log, contains=(f"leaks found: {len(values)}",), values_absent=tuple(values))
        _expect(repo.sarif(), what="SARIF report", values_absent=tuple(values))

    def test_real_shaped_keys_fire_at_the_expected_rate(self, repo: Repo) -> None:
        # Unfiltered draws from each real generator. The expected count comes from
        # the rule's own entropy floor and allowlist; a real body can match a
        # placeholder word by chance (rarely), and then it is not reported.
        keys = [make() for make in REAL_FORMATS.values() for _ in range(10)]
        expected = sum(_is_reported(k) for k in keys)
        assert expected >= len(keys) - 2, "the allowlist covers too many real-shaped keys"
        repo.plant_lines("svc/keys", keys)
        rc, _ = repo.run_step()
        assert rc == 1
        assert sum(r["ruleId"] == SERVICE_RULE for r in repo.sarif_results()) == expected

    def test_placeholders_are_not_caught(self, repo: Repo) -> None:
        repo.plant_lines("tests/fixtures/keys", _placeholders())
        rc, log = repo.run_step()
        assert rc == 0
        _expect(log, contains=("no leaks found",))

    def test_control_placeholders_fire_without_the_allowlist(self, repo: Repo) -> None:
        placeholders = _placeholders()
        assert all(_entropy(p) > _appended_rule()["entropy"] for p in placeholders)
        repo.plant_lines("tests/fixtures/keys", placeholders)
        body = _step(RUN_STEP)["run"]
        start = body.index("[[rules.allowlists]]")
        mutated = body[:start] + body[body.index("EOF\n", start):]
        rc, _ = repo.run_step(script=mutated)
        assert rc == 1
        assert [r["ruleId"] for r in repo.sarif_results()] == [SERVICE_RULE] * len(placeholders)

    def test_stripe_live_key_is_still_caught_by_the_stripe_rule(self, repo: Repo) -> None:
        value = repo.plant_value("billing/env", _prefixed("sk", "live", _random(ALNUM, 32)))
        rc, log = repo.run_step()
        assert rc == 1
        _expect(log, values_absent=(value,))
        ids = repo.sarif_rule_ids()
        assert "stripe-access-token" in ids and SERVICE_RULE not in ids

    def test_31_character_near_miss_is_not_caught(self, repo: Repo) -> None:
        repo.plant_value("svc/staging", _prefixed("sk", "staging", _random(ALNUM, 31)))
        repo.plant_value("svc/sa", _a8("sa", _random(URLSAFE, 31)))
        rc, log = repo.run_step()
        assert rc == 0
        _expect(log, contains=("no leaks found",))

    def test_31_character_prod_near_miss_is_left_to_the_stripe_rule(self, repo: Repo) -> None:
        repo.plant_value("svc/prod", _prefixed("sk", "prod", _random(ALNUM, 31)))
        rc, _ = repo.run_step()
        assert rc == 1
        assert SERVICE_RULE not in repo.sarif_rule_ids()

    def test_caller_config_is_kept(self, repo: Repo) -> None:
        repo.commit(
            ".gitleaks.toml",
            "[extend]\nuseDefault = true\n\n[allowlist]\npaths = ['''^fixtures/''']\n",
            "add config",
        )
        repo.plant_value("fixtures/env", _real_shaped(lambda: _prefixed("sk", "staging", _random(ALNUM, 32))))
        rc, log = repo.run_step()
        assert rc == 0, "the caller's path allowlist was not honoured"
        value = repo.plant_value("svc/env", _real_shaped(lambda: _a8("sa", secrets.token_urlsafe(32))))
        rc, log = repo.run_step()
        assert rc == 1
        _expect(log, contains=("leaks found: 1",), values_absent=(value,))

    def test_control_rule_absent_misses_service_keys(self, repo: Repo) -> None:
        repo.plant_lines("svc/keys", [
            _real_shaped(lambda: _prefixed("sk", "staging", _random(ALNUM, 32))),
            _real_shaped(lambda: _a8("sa", secrets.token_hex(16))),
        ])
        body = _step(RUN_STEP)["run"]
        without_rule = body[body.index("args=(detect"):]
        rc, _ = repo.run_step(script=without_rule)
        assert rc == 0, "control: the default rules alone should not catch these keys"
