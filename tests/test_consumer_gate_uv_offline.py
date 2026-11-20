"""P0 for S-126: the consumer-gate check against real uv, fully offline. Opt-in.

Run with CONSUMER_GATE_UV_E2E=1. It needs uv on PATH and a uv cache that
already holds the running pytest's wheels. Every uv call runs with
UV_OFFLINE=1, UV_NO_CONFIG=1 and UV_PYTHON_DOWNLOADS=never, so nothing is
fetched and no user or project uv configuration is read. A step that would
need the network fails with NEEDS-NETWORK instead of fetching.

Each lab is a virtual project (no build system, tool.uv.package = false) whose
lock pins a dummy SDK from a local find-links folder. The candidate is
installed by the test job's own force-install step script, read from the
workflow. Each case prints "P0 <case> exit=<code>" for the run record.
"""

from __future__ import annotations

import importlib.metadata
import json
import os
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

import pytest
import yaml

from tests._consumer_gate_support import HELPER_PATH, WORKFLOW_PATH, build_wheel, write_manifest

pytestmark = pytest.mark.skipif(
    os.environ.get("CONSUMER_GATE_UV_E2E") != "1",
    reason="opt-in: set CONSUMER_GATE_UV_E2E=1 (needs uv and a warm uv cache; runs offline)",
)

SDK = "dummy-sdk"
LOCKED = "1.0.0"
CANDIDATE = "2.0.0"
PYTEST_VERSION = importlib.metadata.version("pytest")
PY = f"{sys.version_info.major}.{sys.version_info.minor}"
FORCE_INSTALL_STEP = "Force-install candidate SDK wheel (consumer-gate)"
NETWORK_MARKERS = ("Network connectivity is disabled", "network connectivity")


def _say(case: str, code: int) -> None:
    print(f"P0 {case} exit={code}")


def _scrub(text: str) -> str:
    return text.replace(str(Path.home()), "~")


def _base_env() -> dict[str, str]:
    dropped_prefixes = ("UV_", "PYTEST_", "CONSUMER_GATE_", "PIP_")
    dropped = {"VIRTUAL_ENV", "CONDA_PREFIX", "PYTHONPATH", "PYTHONHOME"}
    env = {
        key: value
        for key, value in os.environ.items()
        if key not in dropped and not key.startswith(dropped_prefixes)
    }
    env.update(
        UV_OFFLINE="1",
        UV_NO_CONFIG="1",
        UV_PYTHON=PY,
        UV_PYTHON_DOWNLOADS="never",
        UV_NO_PROGRESS="1",
        UV_LINK_MODE="copy",
    )
    return env


def _force_install_script() -> str:
    data = yaml.safe_load(WORKFLOW_PATH.read_text(encoding="utf-8"))
    steps = data["jobs"]["test"]["steps"]
    return next(step["run"] for step in steps if step.get("name") == FORCE_INSTALL_STEP)


@dataclass
class Lab:
    root: Path
    proj: Path
    index: Path
    wheel_dir: Path

    def env(self, **extra: str) -> dict[str, str]:
        env = _base_env()
        env["UV_FIND_LINKS"] = str(self.index)
        env.update(extra)
        return env

    def run(self, argv: list[str], **extra: str) -> subprocess.CompletedProcess[str]:
        result = subprocess.run(
            argv, cwd=self.proj, env=self.env(**extra), capture_output=True, text=True, timeout=600, check=False
        )
        if any(marker in result.stderr for marker in NETWORK_MARKERS):
            pytest.fail(f"NEEDS-NETWORK: {argv[0]} {argv[1] if len(argv) > 1 else ''} wanted the network; stopped, nothing fetched")
        return result

    def uv(self, *args: str, **extra: str) -> subprocess.CompletedProcess[str]:
        result = self.run(["uv", *args], **extra)
        assert result.returncode == 0, f"uv {' '.join(args)} exited {result.returncode}: {_scrub(result.stderr[-1500:])}"
        return result

    def force_install(self) -> None:
        github_env = self.root / "github-env"
        github_env.write_text("", encoding="utf-8")
        result = self.run(["bash", "--noprofile", "--norc", "-e", "-o", "pipefail", "-c", _force_install_script()],
                          GITHUB_ENV=str(github_env))
        assert result.returncode == 0, f"force-install exited {result.returncode}: {_scrub(result.stderr[-1500:])}"
        assert "UV_NO_SYNC=1" in github_env.read_text(encoding="utf-8").splitlines()

    def check_env(self, **overrides: str) -> dict[str, str]:
        env = {
            "CONSUMER_GATE_SDK_NAME": SDK,
            "CONSUMER_GATE_SDK_VERSION": CANDIDATE,
            "CONSUMER_GATE_WHEEL_DIR": str(self.wheel_dir),
        }
        env.update(overrides)
        return env

    def verify(self, **overrides: str) -> int:
        """The re-read as the workflow runs it, but by the venv's python, so it never syncs."""
        result = self.run([str(self.proj / ".venv" / "bin" / "python"), "-I", str(HELPER_PATH), "verify"],
                          **self.check_env(**overrides))
        return result.returncode

    def pytest_with_plugin(self, *uv_flags: str, no_sync_env: bool, **overrides: str) -> subprocess.CompletedProcess[str]:
        """`uv run --no-sources pytest -p consumer_gate_candidate tests/`, as the test job runs it."""
        extra = self.check_env(**overrides)
        extra["PYTHONPATH"] = str(HELPER_PATH.parent)
        if no_sync_env:
            extra["UV_NO_SYNC"] = "1"
        return self.run(
            ["uv", "run", *uv_flags, "--no-sources", "pytest", "-p", "consumer_gate_candidate",
             "-p", "no:cacheprovider", "tests/"],
            **extra,
        )

    def installed_info(self, version: str) -> Path:
        site = self.proj / ".venv" / "lib" / f"python{PY}" / "site-packages"
        return site / f"dummy_sdk-{version}.dist-info"

    def installed_versions(self) -> list[str]:
        site = self.proj / ".venv" / "lib" / f"python{PY}" / "site-packages"
        return sorted(path.name[len("dummy_sdk-"):-len(".dist-info")] for path in site.glob("dummy_sdk-*.dist-info"))


def _test_tool_pins() -> list[str]:
    """pytest and each of its installed requirements, pinned to the running environment.

    The uv cache's index pages can list newer releases than the cache holds
    wheels for; pinning to what is installed here keeps every lab offline.
    """
    pins = [f"pytest=={PYTEST_VERSION}"]
    for requirement in importlib.metadata.requires("pytest") or []:
        if "extra ==" in requirement:
            continue
        name = re.match(r"[A-Za-z0-9._-]+", requirement)
        if name is None:
            continue
        try:
            pins.append(f"{name.group(0)}=={importlib.metadata.version(name.group(0))}")
        except importlib.metadata.PackageNotFoundError:
            continue  # a requirement for another platform or Python (colorama, tomli)
    return pins


def _make_lab(root: Path, *, extras_only: bool = False, locked: str = LOCKED) -> Lab:
    proj = root / "proj"
    index = root / "index"
    wheel_dir = proj / "_candidate-wheel"
    (proj / "tests").mkdir(parents=True)
    build_wheel(index, SDK, locked, requires=())
    candidate = build_wheel(wheel_dir, SDK, CANDIDATE)
    write_manifest(wheel_dir, SDK, CANDIDATE, candidate.name)
    tools = ", ".join(f'"{pin}"' for pin in _test_tool_pins())
    if extras_only:
        deps = f'dependencies = [{tools}]\n[project.optional-dependencies]\napi = ["{SDK}=={locked}"]\n'
    else:
        deps = f'dependencies = ["{SDK}=={locked}", {tools}]\n'
    (proj / "pyproject.toml").write_text(
        f'[project]\nname = "cg-satellite"\nversion = "0.0.0"\nrequires-python = ">={PY}"\n{deps}'
        "\n[tool.uv]\npackage = false\n",
        encoding="utf-8",
    )
    (proj / "tests" / "test_satellite.py").write_text(
        "import dummy_sdk\n\n\ndef test_imports_the_sdk():\n    assert dummy_sdk.VERSION\n", encoding="utf-8"
    )
    lab = Lab(root=root, proj=proj, index=index, wheel_dir=wheel_dir)
    lab.uv("lock")
    lab.uv("sync", "--no-sources", "--all-extras")
    return lab


@pytest.fixture(scope="module", autouse=True)
def _record_uv_version() -> None:
    if shutil.which("uv") is None:
        pytest.fail("uv is not on PATH")
    version = subprocess.run(["uv", "--version"], capture_output=True, text=True, check=True).stdout.split()[1]
    print(f"P0 uv-version {version} pytest {PYTEST_VERSION} python {PY}")


@pytest.fixture(scope="module")
def base_lab(tmp_path_factory: pytest.TempPathFactory) -> Lab:
    lab = _make_lab(tmp_path_factory.mktemp("cg-base"))
    assert lab.installed_versions() == [LOCKED]
    lab.force_install()
    assert lab.installed_versions() == [CANDIDATE]
    return lab


# The cases below share base_lab and run in file order.


def test_p0_expected_x_with_provenance_passes(base_lab: Lab) -> None:
    info = base_lab.installed_info(CANDIDATE)
    keys = sorted(json.loads((info / "direct_url.json").read_text(encoding="utf-8")))
    print(f"P0 uv-direct_url-keys {','.join(keys)}")
    code = base_lab.verify()
    _say("verify expected-X provenance", code)
    assert code == 0
    reread = base_lab.run(
        ["uv", "run", "--no-sync", "--no-sources", "python", "-I", str(HELPER_PATH), "verify"], **base_lab.check_env()
    )
    _say("workflow re-read form (uv run --no-sync) expected-X", reread.returncode)
    assert reread.returncode == 0
    plugin = base_lab.pytest_with_plugin(no_sync_env=True)
    _say("plugin expected-X under UV_NO_SYNC=1", plugin.returncode)
    assert plugin.returncode == 0, _scrub(plugin.stdout[-2000:] + plugin.stderr[-1000:])
    assert plugin.stdout.count(f"consumer-gate: {SDK}=={CANDIDATE} source=candidate-wheel") == 2


def test_p0_expected_y_fails(base_lab: Lab) -> None:
    code = base_lab.verify(CONSUMER_GATE_SDK_VERSION="3.0.0")
    _say("verify expected-Y", code)
    assert code == 1
    plugin = base_lab.pytest_with_plugin(no_sync_env=True, CONSUMER_GATE_SDK_VERSION="3.0.0")
    _say("plugin expected-Y", plugin.returncode)
    assert plugin.returncode == 4


def test_p0_wrong_name_fails(base_lab: Lab) -> None:
    code = base_lab.verify(CONSUMER_GATE_SDK_NAME="other-sdk")
    _say("verify wrong-name", code)
    assert code == 1
    plugin = base_lab.pytest_with_plugin(no_sync_env=True, CONSUMER_GATE_SDK_NAME="other-sdk")
    _say("plugin wrong-name", plugin.returncode)
    assert plugin.returncode == 4


def test_p0_no_direct_url_fails(base_lab: Lab) -> None:
    record = base_lab.installed_info(CANDIDATE) / "direct_url.json"
    aside = base_lab.root / "direct_url.json.aside"
    shutil.move(record, aside)
    try:
        code = base_lab.verify()
        _say("verify no-direct_url", code)
        plugin = base_lab.pytest_with_plugin(no_sync_env=True)
        _say("plugin no-direct_url", plugin.returncode)
    finally:
        shutil.move(aside, record)
    assert code == 1
    assert plugin.returncode == 4
    assert base_lab.verify() == 0


def test_p0_r2_plain_uv_run_resyncs_and_the_plugin_refuses(base_lab: Lab) -> None:
    """The R2 analogue: without UV_NO_SYNC a plain `uv run` puts the locked version back."""
    plain = base_lab.pytest_with_plugin(no_sync_env=False)
    _say("R2 plain uv run (no UV_NO_SYNC) plugin", plain.returncode)
    print(f"P0 R2 installed-after-plain-uv-run {','.join(base_lab.installed_versions())}")
    assert base_lab.installed_versions() == [LOCKED]
    assert plain.returncode == 4
    assert "consumer-gate: REFUSED:" in plain.stderr
    code = base_lab.verify()
    _say("R2 re-read after the plain uv run", code)
    assert code == 1


def test_p0_r2_control_no_sync_keeps_the_candidate(base_lab: Lab) -> None:
    base_lab.force_install()
    assert base_lab.installed_versions() == [CANDIDATE]
    covered = base_lab.pytest_with_plugin(no_sync_env=True)
    _say("R2 control UV_NO_SYNC=1 plugin", covered.returncode)
    flag = base_lab.pytest_with_plugin("--no-sync", no_sync_env=False)
    _say("R2 control --no-sync flag plugin", flag.returncode)
    code = base_lab.verify()
    _say("R2 control re-read", code)
    assert (covered.returncode, flag.returncode, code) == (0, 0, 0)
    assert base_lab.installed_versions() == [CANDIDATE]


def test_p0_guard_partial_fails_and_empty_passes(tmp_path: Path) -> None:
    from tests.test_workflow_validation import _SET_INPUTS, _run_guard

    (tmp_path / "partial").mkdir()
    (tmp_path / "empty").mkdir()
    partial_code, _, _ = _run_guard(tmp_path / "partial", {"CONSUMER_GATE_SDK_NAME": _SET_INPUTS["CONSUMER_GATE_SDK_NAME"]})
    _say("guard partial-inputs", partial_code)
    empty_code, empty_output, _ = _run_guard(tmp_path / "empty", {}, python3_works=False)
    _say("guard all-inputs-empty", empty_code)
    assert partial_code == 1
    assert (empty_code, empty_output) == (0, "mode=none\n")


def test_p0_extras_only_control_survives_a_plain_uv_run(tmp_path: Path) -> None:
    """data's case: the SDK sits only in an extra, which a plain `uv run` does not sync."""
    lab = _make_lab(tmp_path / "extras", extras_only=True)
    lab.force_install()
    plain = lab.pytest_with_plugin(no_sync_env=False)
    _say("extras-only control plain uv run plugin", plain.returncode)
    print(f"P0 extras-only installed-after-plain-uv-run {','.join(lab.installed_versions())}")
    assert plain.returncode == 0
    assert lab.installed_versions() == [CANDIDATE]


def test_p0_same_version_lock_is_caught_only_by_provenance(tmp_path: Path) -> None:
    """The lock pins the candidate's own version from the index: does a plain `uv run` swap it?"""
    lab = _make_lab(tmp_path / "same-version", locked=CANDIDATE)
    lab.force_install()
    assert lab.verify() == 0
    plain = lab.pytest_with_plugin(no_sync_env=False)
    record = lab.installed_info(CANDIDATE) / "direct_url.json"
    candidate_kept = record.is_file() and lab.verify() == 0
    _say("same-version lock plain uv run plugin", plain.returncode)
    print(f"P0 same-version candidate-kept-after-plain-uv-run {candidate_kept}")
    # The plugin's verdict must match what is installed: refuse exactly when uv swapped it.
    assert plain.returncode == (0 if candidate_kept else 4)
