"""Unit tests for the consumer-gate candidate check (S-126).

These run the helper's functions against dummy wheels and fake installed
distributions, with no uv and no network. The end-to-end proof through real
uv commands is tests/test_consumer_gate_uv_offline.py (opt-in).
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

import pytest

from tests._consumer_gate_support import (
    HELPER_PATH,
    build_wheel,
    direct_url_for,
    install_fake_dist,
    load_helper,
    write_manifest,
)

cg = load_helper()

NAME = "dummy-sdk"
CANDIDATE = "2.0.0"
REPORT = f"consumer-gate: {NAME}=={CANDIDATE} source=candidate-wheel"


@dataclass
class Lab:
    """A candidate-wheel folder holding the gate's artifact, and a site folder holding the candidate."""

    wheel_dir: Path
    wheel: Path
    site: Path

    @property
    def manifest(self) -> Path:
        return self.wheel_dir / f"{NAME}-manifest.json"

    def environ(self, **overrides: str) -> dict[str, str]:
        environ = {
            cg.ENV_NAME: NAME,
            cg.ENV_VERSION: CANDIDATE,
            cg.ENV_WHEEL_DIR: str(self.wheel_dir),
        }
        environ.update(overrides)
        return environ

    def verify(self, *sites: Path, **overrides: str) -> str:
        path = [str(site) for site in (sites or (self.site,))]
        return cg.verify_candidate(self.environ(**overrides), path=path)


@pytest.fixture()
def lab(tmp_path: Path) -> Lab:
    wheel_dir = tmp_path / "_candidate-wheel"
    wheel = build_wheel(wheel_dir, NAME, CANDIDATE)
    write_manifest(wheel_dir, NAME, CANDIDATE, wheel.name)
    site = tmp_path / "site"
    install_fake_dist(site, NAME, CANDIDATE, direct_url=direct_url_for(wheel))
    return Lab(wheel_dir=wheel_dir, wheel=wheel, site=site)


# ---------------------------------------------------------------------------
# PEP 440 and PEP 503
# ---------------------------------------------------------------------------

EQUAL_PAIRS = [
    ("1.0", "1.0.0"),
    ("1", "1.0.0.0"),
    ("1.0.0rc1", "1.0.0-rc.1"),
    ("1.0.0RC1", "1.0.0rc1"),
    ("1.0c1", "1.0rc1"),
    ("1.0alpha2", "1.0a2"),
    ("1.0b", "1.0b0"),
    ("1.0.post1", "1.0-1"),
    ("1.0.post", "1.0.post0"),
    ("1.0rev2", "1.0.post2"),
    ("1.0.dev", "1.0.dev0"),
    ("1.0+abc.1", "1.0+ABC-1"),
    ("v4.4.1", "4.4.1"),
    ("0!1.0", "1.0"),
    ("0.7.0rc1", "0.7.0rc1"),
]

UNEQUAL_PAIRS = [
    ("1.0", "1.0.1"),
    ("1.0a1", "1.0b1"),
    ("1!1.0", "1.0"),
    ("1.0", "1.0.post0"),
    ("1.0", "1.0.dev0"),
    ("1.0+local", "1.0"),
    ("4.4.0", "4.4.1"),
    ("0.12.0rc1", "0.12.0"),
]

VERSION_CORPUS = [
    "1",
    "1.0",
    "4.4.1",
    "0.7.0rc1",
    "0.12.0rc1",
    "2!3.4.5.post6.dev7+abc.8",
    "1.0-1",
    "1.0.dev",
    "1.0+local.Version_1",
    "V1.0",
    "1.0.0-rc.1",
    "1.0-dev-1",
    "1.0_post_1",
    "",
    " ",
    "1.0 ",
    " 1.0",
    "1.0\n",
    "latest",
    "1..0",
    "1.0+",
    "1.0-",
    "1.0.0.",
    "a1.0",
]


@pytest.mark.parametrize("left,right", EQUAL_PAIRS)
def test_versions_equal_under_pep_440(left: str, right: str) -> None:
    assert cg.versions_equal(left, right)


@pytest.mark.parametrize("left,right", UNEQUAL_PAIRS)
def test_versions_differ_under_pep_440(left: str, right: str) -> None:
    assert not cg.versions_equal(left, right)


def test_version_equality_matches_packaging() -> None:
    """Cross-check the helper's PEP 440 equality against packaging, a pytest dependency."""
    version_module = pytest.importorskip("packaging.version")
    for left, right in EQUAL_PAIRS + UNEQUAL_PAIRS:
        expected = version_module.Version(left) == version_module.Version(right)
        assert cg.versions_equal(left, right) is expected, (left, right)


def test_version_validity_matches_packaging() -> None:
    """The helper accepts exactly what packaging accepts, minus surrounding whitespace."""
    version_module = pytest.importorskip("packaging.version")
    for text in VERSION_CORPUS:
        try:
            version_module.Version(text)
            reference = text == text.strip()
        except version_module.InvalidVersion:
            reference = False
        assert cg.is_valid_version(text) is reference, repr(text)


def test_version_key_rejects_an_invalid_version() -> None:
    with pytest.raises(cg.CandidateError):
        cg.version_key("not-a-version")


@pytest.mark.parametrize(
    "name,normalized",
    [("autom8y-auth", "autom8y-auth"), ("Autom8y_Auth", "autom8y-auth"), ("a.b__c", "a-b-c")],
)
def test_normalize_name_is_pep_503(name: str, normalized: str) -> None:
    assert cg.normalize_name(name) == normalized


# ---------------------------------------------------------------------------
# Inputs guard: the Python half (the bash prelude is tested from the YAML in
# tests/test_workflow_validation.py)
# ---------------------------------------------------------------------------

GOOD_INPUTS = {
    "CONSUMER_GATE_SDK_NAME": "autom8y-auth",
    "CONSUMER_GATE_SDK_VERSION": "4.4.1",
    "CONSUMER_GATE_WHEEL_RUN_ID": "1234567",
    "CONSUMER_GATE_CORRELATION_ID": "1b4e28ba-2fa1-11d2-883f-0016d3cca427",
}


def test_guard_passes_four_well_formed_inputs() -> None:
    assert cg.check_guard_inputs(dict(GOOD_INPUTS)) == []


@pytest.mark.parametrize("blank_key", sorted(GOOD_INPUTS))
@pytest.mark.parametrize("blank_value", ["", " ", "\t\n"])
def test_guard_refuses_any_unset_or_blank_input(blank_key: str, blank_value: str) -> None:
    environ = dict(GOOD_INPUTS, **{blank_key: blank_value})
    problems = cg.check_guard_inputs(environ)
    assert len(problems) == 1 and "all four" in problems[0]


@pytest.mark.parametrize(
    "key,value",
    [
        ("CONSUMER_GATE_SDK_NAME", "autom8y auth"),
        ("CONSUMER_GATE_SDK_NAME", "-autom8y"),
        ("CONSUMER_GATE_SDK_NAME", " autom8y-auth"),
        ("CONSUMER_GATE_SDK_VERSION", "latest"),
        ("CONSUMER_GATE_SDK_VERSION", "4.4.1 "),
        ("CONSUMER_GATE_SDK_VERSION", "4.4.1\n"),
        ("CONSUMER_GATE_WHEEL_RUN_ID", "12a"),
        ("CONSUMER_GATE_WHEEL_RUN_ID", "0"),
        ("CONSUMER_GATE_WHEEL_RUN_ID", "-1"),
        ("CONSUMER_GATE_WHEEL_RUN_ID", "123\n"),
        ("CONSUMER_GATE_WHEEL_RUN_ID", "١٢"),
        ("CONSUMER_GATE_CORRELATION_ID", "abc def"),
        ("CONSUMER_GATE_CORRELATION_ID", "abc;def"),
    ],
)
def test_guard_refuses_a_malformed_input(key: str, value: str) -> None:
    environ = dict(GOOD_INPUTS, **{key: value})
    assert len(cg.check_guard_inputs(environ)) == 1


# ---------------------------------------------------------------------------
# The assert
# ---------------------------------------------------------------------------


def test_verify_passes_the_installed_candidate(lab: Lab) -> None:
    assert lab.verify() == REPORT


def test_verify_accepts_an_equal_pep_440_spelling(lab: Lab) -> None:
    assert lab.verify(CONSUMER_GATE_SDK_VERSION="2.0") == REPORT


def test_verify_accepts_a_name_spelled_differently(lab: Lab) -> None:
    # The manifest file is named after the input; the gate passes its matrix.sdk unchanged.
    write_manifest(lab.wheel_dir, NAME, CANDIDATE, lab.wheel.name, file_sdk="Dummy_SDK")
    assert lab.verify(CONSUMER_GATE_SDK_NAME="Dummy_SDK") == REPORT


def test_verify_refuses_another_expected_version(lab: Lab) -> None:
    with pytest.raises(cg.CandidateError, match="not version 3.0.0"):
        lab.verify(CONSUMER_GATE_SDK_VERSION="3.0.0")


def test_verify_refuses_another_expected_name(lab: Lab) -> None:
    with pytest.raises(cg.CandidateError, match="not other-sdk"):
        lab.verify(CONSUMER_GATE_SDK_NAME="other-sdk")


@pytest.mark.parametrize(
    "key", ["CONSUMER_GATE_SDK_NAME", "CONSUMER_GATE_SDK_VERSION", "CONSUMER_GATE_WHEEL_DIR"]
)
def test_verify_refuses_a_missing_input(lab: Lab, key: str) -> None:
    with pytest.raises(cg.CandidateError):
        lab.verify(**{key: ""})


def test_verify_refuses_a_missing_wheel_folder(lab: Lab, tmp_path: Path) -> None:
    with pytest.raises(cg.CandidateError, match="does not exist"):
        lab.verify(CONSUMER_GATE_WHEEL_DIR=str(tmp_path / "absent"))


def test_verify_refuses_no_wheel(lab: Lab) -> None:
    lab.wheel.unlink()
    with pytest.raises(cg.CandidateError, match="found 0"):
        lab.verify()


def test_verify_refuses_two_wheels(lab: Lab) -> None:
    build_wheel(lab.wheel_dir / "nested", NAME, "1.0.0")
    with pytest.raises(cg.CandidateError, match="found 2"):
        lab.verify()


def test_verify_refuses_a_wheel_that_is_not_a_zip(lab: Lab) -> None:
    lab.wheel.write_bytes(b"not a zip")
    with pytest.raises(cg.CandidateError, match="cannot read the METADATA"):
        lab.verify()


def test_verify_refuses_metadata_that_disagrees_with_the_file_name(tmp_path: Path) -> None:
    wheel_dir = tmp_path / "_candidate-wheel"
    wheel = build_wheel(wheel_dir, NAME, CANDIDATE, file_version="9.9.9")
    write_manifest(wheel_dir, NAME, CANDIDATE, wheel.name)
    site = tmp_path / "site"
    install_fake_dist(site, NAME, CANDIDATE, direct_url=direct_url_for(wheel))
    with pytest.raises(cg.CandidateError, match="does not name the version"):
        Lab(wheel_dir=wheel_dir, wheel=wheel, site=site).verify()


def test_verify_refuses_a_missing_manifest(lab: Lab) -> None:
    lab.manifest.unlink()
    with pytest.raises(cg.CandidateError, match="holds no dummy-sdk-manifest.json"):
        lab.verify()


@pytest.mark.parametrize(
    "field,value,message",
    [
        ("sdk", "other-sdk", "another sdk"),
        ("version", "1.0.0", "another version"),
        ("version", "latest", "another version"),
        ("wheel_filename", "dummy_sdk-1.0.0-py3-none-any.whl", "another wheel file"),
    ],
)
def test_verify_refuses_a_manifest_that_disagrees(lab: Lab, field: str, value: str, message: str) -> None:
    data = json.loads(lab.manifest.read_text())
    data[field] = value
    lab.manifest.write_text(json.dumps(data))
    with pytest.raises(cg.CandidateError, match=message):
        lab.verify()


def test_verify_refuses_a_manifest_that_is_not_json(lab: Lab) -> None:
    lab.manifest.write_text("{")
    with pytest.raises(cg.CandidateError, match="cannot read"):
        lab.verify()


def test_verify_refuses_when_the_candidate_is_not_installed(lab: Lab, tmp_path: Path) -> None:
    empty_site = tmp_path / "empty-site"
    empty_site.mkdir()
    with pytest.raises(cg.CandidateError, match="found 0"):
        lab.verify(empty_site)


def test_verify_refuses_two_installed_copies(lab: Lab, tmp_path: Path) -> None:
    other_site = tmp_path / "other-site"
    install_fake_dist(other_site, NAME, "1.0.0", direct_url=None)
    with pytest.raises(cg.CandidateError, match="found 2"):
        lab.verify(lab.site, other_site)


def test_verify_counts_a_folder_listed_twice_once(lab: Lab) -> None:
    assert lab.verify(lab.site, Path(str(lab.site) + os.sep)) == REPORT


def test_verify_refuses_the_locked_version_after_a_re_sync(lab: Lab, tmp_path: Path) -> None:
    """What `uv run` leaves behind: the lock's version, from the index, with no direct_url.json."""
    resynced_site = tmp_path / "resynced-site"
    install_fake_dist(resynced_site, NAME, "1.0.0", direct_url=None)
    with pytest.raises(cg.CandidateError, match="is 1.0.0, not the candidate 2.0.0"):
        lab.verify(resynced_site)


def test_verify_refuses_a_missing_direct_url(lab: Lab, tmp_path: Path) -> None:
    """The candidate's version with no provenance: the same-version re-sync case."""
    site = tmp_path / "same-version-site"
    install_fake_dist(site, NAME, CANDIDATE, direct_url=None)
    with pytest.raises(cg.CandidateError, match="has no direct_url.json"):
        lab.verify(site)


@pytest.mark.parametrize(
    "direct_url,message",
    [
        ("{", "is not JSON"),
        ("[]", "has no url"),
        (json.dumps({"archive_info": {}}), "has no url"),
        (json.dumps({"url": "https://example.invalid/dummy_sdk-2.0.0-py3-none-any.whl"}), "https URL"),
        (json.dumps({"url": "file://otherhost/x.whl"}), "file URL"),
        (json.dumps({"url": "file:///index/dummy_sdk-2.0.0-py3-none-any.whl"}), "came from dummy_sdk"),
    ],
)
def test_verify_refuses_a_direct_url_that_does_not_name_the_candidate(
    lab: Lab, tmp_path: Path, direct_url: str, message: str
) -> None:
    site = tmp_path / "bad-provenance-site"
    install_fake_dist(site, NAME, CANDIDATE, direct_url=direct_url)
    with pytest.raises(cg.CandidateError, match=message):
        lab.verify(site)


def test_command_text_escapes_workflow_command_characters() -> None:
    assert cg._command_text("a%b\r\nc") == "a%25b%0D%0Ac"


# ---------------------------------------------------------------------------
# Entry points, run as the workflow runs them
# ---------------------------------------------------------------------------


def _clean_env(**extra: str) -> dict[str, str]:
    env = {
        key: value
        for key, value in os.environ.items()
        if not key.startswith(("CONSUMER_GATE_", "PYTEST_")) and key != "PYTHONPATH"
    }
    env.update(extra)
    return env


def _run_helper(args: list[str], environ: dict[str, str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-I", str(HELPER_PATH), *args],
        env=_clean_env(**environ),
        capture_output=True,
        text=True,
        check=False,
    )


def test_guard_command_exit_codes() -> None:
    assert _run_helper(["guard"], GOOD_INPUTS).returncode == 0
    result = _run_helper(["guard"], dict(GOOD_INPUTS, CONSUMER_GATE_CORRELATION_ID=""))
    assert result.returncode == 1
    assert result.stdout.startswith("::error::consumer-gate inputs guard:")


def test_verify_command_exit_codes(lab: Lab, tmp_path: Path) -> None:
    # The command reads sys.path, so the fake site folder goes on PYTHONPATH (no -I here).
    def run(**overrides: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(HELPER_PATH), "verify"],
            env=_clean_env(PYTHONPATH=str(lab.site), **lab.environ(**overrides)),
            capture_output=True,
            text=True,
            check=False,
            cwd=tmp_path,
        )

    passed = run()
    assert passed.returncode == 0 and passed.stdout.strip() == REPORT
    refused = run(CONSUMER_GATE_SDK_VERSION="3.0.0")
    assert refused.returncode == 1
    assert refused.stdout.startswith("::error::consumer-gate: REFUSED:")


def test_unknown_command_exits_2() -> None:
    assert _run_helper(["status"], {}).returncode == 2
    assert _run_helper([], {}).returncode == 2


def _plugin_run(lab: Lab, tmp_path: Path, *extra_args: str, **overrides: str) -> subprocess.CompletedProcess[str]:
    """A real pytest session with the plugin; its import path holds the fake site folder."""
    test_file = tmp_path / "test_satellite_suite.py"
    test_file.write_text("def test_ok():\n    assert True\n", encoding="utf-8")
    env = _clean_env(
        PYTHONPATH=os.pathsep.join([str(HELPER_PATH.parent), str(lab.site)]),
        **lab.environ(**overrides),
    )
    return subprocess.run(
        [sys.executable, "-m", "pytest", "-p", "consumer_gate_candidate", "-p", "no:cacheprovider", *extra_args, str(test_file)],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )


def test_plugin_passes_and_prints_the_candidate(lab: Lab, tmp_path: Path) -> None:
    result = _plugin_run(lab, tmp_path)
    assert result.returncode == 0, result.stdout + result.stderr
    # Once in the report header and once in the terminal summary.
    assert result.stdout.count(REPORT) == 2


def test_plugin_line_survives_no_header(lab: Lab, tmp_path: Path) -> None:
    result = _plugin_run(lab, tmp_path, "--no-header")
    assert result.returncode == 0, result.stdout + result.stderr
    assert result.stdout.count(REPORT) == 1


def test_plugin_refuses_with_usage_error(lab: Lab, tmp_path: Path) -> None:
    result = _plugin_run(lab, tmp_path, CONSUMER_GATE_SDK_VERSION="3.0.0")
    assert result.returncode == 4, result.stdout + result.stderr
    assert "consumer-gate: REFUSED:" in result.stderr
    assert "passed" not in result.stdout
