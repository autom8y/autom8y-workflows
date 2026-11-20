"""Consumer-gate candidate check for satellite-ci-reusable.yml (S-126).

A plain `uv run` syncs to uv.lock, replacing the candidate SDK wheel with the
locked version while the run still succeeds. This check fails such a run.
The workflow embeds this file verbatim in the inputs guard step of the lint and
test jobs; after editing it, run .github/scripts/embed_consumer_gate_candidate.py
(tests/test_workflow_validation.py fails on drift). Entry points:

    python3 -I consumer_gate_candidate.py guard    inputs guard, stdlib only
    pytest -p consumer_gate_candidate ...          assert in pytest_configure
    <project python> -I consumer_gate_candidate.py verify    re-read, exit 1

Inputs come from the environment only (CONSUMER_GATE_*). The assert requires:
exactly one .whl in the candidate folder; its METADATA Name and Version equal
the expected ones (PEP 503, PEP 440) and agree with its file name; the gate's
<sdk>-manifest.json names the same sdk, version and file; exactly one
installed distribution of that name, at that version; and its direct_url.json
(MANDATORY: index and lock installs write none) names that exact wheel.
"""

from __future__ import annotations

import json
import os
import re
import sys
import zipfile
from email.parser import HeaderParser
from pathlib import Path
from urllib.parse import urlsplit
from urllib.request import url2pathname

ENV_NAME = "CONSUMER_GATE_SDK_NAME"
ENV_VERSION = "CONSUMER_GATE_SDK_VERSION"
ENV_RUN_ID = "CONSUMER_GATE_WHEEL_RUN_ID"
ENV_CORRELATION_ID = "CONSUMER_GATE_CORRELATION_ID"
ENV_WHEEL_DIR = "CONSUMER_GATE_WHEEL_DIR"

# (environment variable, workflow input it carries)
GUARD_INPUTS = (
    (ENV_NAME, "candidate_sdk_name"),
    (ENV_VERSION, "candidate_sdk_version"),
    (ENV_RUN_ID, "candidate_wheel_run_id"),
    (ENV_CORRELATION_ID, "dispatch_correlation_id"),
)

REPORT_SOURCE = "source=candidate-wheel"

# The permissive PEP 440 version pattern (PEP 440 Appendix B, the form that
# packaging.version uses), matched with fullmatch, so no surrounding
# whitespace or trailing newline is accepted.
_VERSION_RE = re.compile(
    r"""
    v?
    (?:
        (?:(?P<epoch>[0-9]+)!)?
        (?P<release>[0-9]+(?:\.[0-9]+)*)
        (?P<pre>
            [-_\.]?
            (?P<pre_l>alpha|a|beta|b|preview|pre|c|rc)
            [-_\.]?
            (?P<pre_n>[0-9]+)?
        )?
        (?P<post>
            (?:-(?P<post_n1>[0-9]+))
            |
            (?:
                [-_\.]?
                (?P<post_l>post|rev|r)
                [-_\.]?
                (?P<post_n2>[0-9]+)?
            )
        )?
        (?P<dev>
            [-_\.]?
            (?P<dev_l>dev)
            [-_\.]?
            (?P<dev_n>[0-9]+)?
        )?
    )
    (?:\+(?P<local>[a-z0-9]+(?:[-_\.][a-z0-9]+)*))?
    """,
    re.VERBOSE | re.IGNORECASE | re.ASCII,
)
# A PEP 508 distribution name.
_NAME_RE = re.compile(r"[A-Z0-9]|[A-Z0-9][A-Z0-9._-]*[A-Z0-9]", re.IGNORECASE | re.ASCII)
_RUN_ID_RE = re.compile(r"[1-9][0-9]*", re.ASCII)
_CORRELATION_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*", re.ASCII)
_METADATA_MEMBER_RE = re.compile(r"[^/]+\.dist-info/METADATA")
_PRE_LETTERS = {
    "a": "a",
    "alpha": "a",
    "b": "b",
    "beta": "b",
    "c": "rc",
    "pre": "rc",
    "preview": "rc",
    "rc": "rc",
}


class CandidateError(Exception):
    """The run does not hold the candidate that the gate dispatched."""


def normalize_name(name: str) -> str:
    """Return the PEP 503 normalized form of a distribution name."""
    return re.sub(r"[-_.]+", "-", name).lower()


def is_valid_version(text: str) -> bool:
    """Return True when text is a valid PEP 440 version."""
    return _VERSION_RE.fullmatch(text) is not None


def version_key(text: str) -> tuple[object, ...]:
    """Return a key that is equal for two versions exactly when PEP 440 says they are.

    It mirrors the normalization of packaging.version.Version: epoch, the
    release with trailing zeros dropped, the pre, post and dev parts with
    their spellings normalized, and the local part split on its separators.
    """
    match = _VERSION_RE.fullmatch(text)
    if match is None:
        raise CandidateError(f"not a PEP 440 version: {text!r}")
    release = [int(part) for part in match.group("release").split(".")]
    while len(release) > 1 and release[-1] == 0:
        release.pop()
    pre = None
    if match.group("pre_l"):
        pre = (_PRE_LETTERS[match.group("pre_l").lower()], int(match.group("pre_n") or 0))
    post = None
    if match.group("post_n1") is not None:
        post = int(match.group("post_n1"))
    elif match.group("post_l"):
        post = int(match.group("post_n2") or 0)
    dev = None
    if match.group("dev_l"):
        dev = int(match.group("dev_n") or 0)
    local = None
    if match.group("local"):
        local = tuple(
            int(part) if part.isdigit() else part.lower()
            for part in re.split(r"[-_.]", match.group("local"))
        )
    return (int(match.group("epoch") or 0), tuple(release), pre, post, dev, local)


def versions_equal(left: str, right: str) -> bool:
    """Compare two version strings under PEP 440."""
    return version_key(left) == version_key(right)


def check_guard_inputs(environ: dict[str, str]) -> list[str]:
    """Return the problems with the four candidate inputs; empty means candidate mode.

    The guard runs only when the step's bash prelude counted at least one
    set input, so here all four must be set: whitespace counts as empty.
    """
    values = {key: environ.get(key, "") for key, _ in GUARD_INPUTS}
    blank = [label for key, label in GUARD_INPUTS if not values[key].strip()]
    if blank:
        return [
            "all four candidate inputs must be set together, or none of them; "
            "unset or blank: " + ", ".join(blank)
        ]
    problems = []
    if _NAME_RE.fullmatch(values[ENV_NAME]) is None:
        problems.append("candidate_sdk_name is not a valid distribution name (PEP 508)")
    if not is_valid_version(values[ENV_VERSION]):
        problems.append("candidate_sdk_version is not a valid PEP 440 version")
    if _RUN_ID_RE.fullmatch(values[ENV_RUN_ID]) is None:
        problems.append("candidate_wheel_run_id is not a numeric workflow run id")
    if _CORRELATION_ID_RE.fullmatch(values[ENV_CORRELATION_ID]) is None:
        problems.append(
            "dispatch_correlation_id holds a character outside letters, digits, '.', '_' and '-'"
        )
    return problems


def read_expected(environ: dict[str, str]) -> tuple[str, str, Path]:
    """Read and validate the expected name, version and wheel folder."""
    name = environ.get(ENV_NAME, "")
    version = environ.get(ENV_VERSION, "")
    wheel_dir = environ.get(ENV_WHEEL_DIR, "")
    if _NAME_RE.fullmatch(name) is None:
        raise CandidateError(f"{ENV_NAME} is unset or not a valid distribution name")
    if not is_valid_version(version):
        raise CandidateError(f"{ENV_VERSION} is unset or not a PEP 440 version")
    if not wheel_dir.strip():
        raise CandidateError(f"{ENV_WHEEL_DIR} is unset")
    return name, version, Path(wheel_dir)


def find_single_wheel(wheel_dir: Path) -> Path:
    """Return the one .whl under wheel_dir (searched recursively, as the install step's find does)."""
    if not wheel_dir.is_dir():
        raise CandidateError(f"the candidate-wheel folder {wheel_dir} does not exist")
    wheels = sorted(path for path in wheel_dir.rglob("*.whl") if path.is_file())
    if len(wheels) != 1:
        raise CandidateError(
            f"expected exactly one .whl under {wheel_dir}, found {len(wheels)}"
        )
    return wheels[0]


def read_wheel_metadata(wheel: Path) -> tuple[str, str]:
    """Return the Name and Version from the wheel's own METADATA."""
    try:
        with zipfile.ZipFile(wheel) as archive:
            members = [
                member
                for member in archive.namelist()
                if _METADATA_MEMBER_RE.fullmatch(member)
            ]
            if len(members) != 1:
                raise CandidateError(
                    f"{wheel.name} holds {len(members)} top-level .dist-info/METADATA files, not 1"
                )
            text = archive.read(members[0]).decode("utf-8")
    except (OSError, zipfile.BadZipFile, UnicodeDecodeError) as exc:
        raise CandidateError(f"cannot read the METADATA of {wheel.name}: {exc}") from None
    headers = HeaderParser().parsestr(text)
    name = (headers.get("Name") or "").strip()
    version = (headers.get("Version") or "").strip()
    if not name or not version:
        raise CandidateError(f"the METADATA of {wheel.name} lacks a Name or a Version")
    if not is_valid_version(version):
        raise CandidateError(f"the METADATA of {wheel.name} holds a non-PEP 440 Version")
    return name, version


def check_wheel_file_name(wheel: Path, name: str, version: str) -> None:
    """Check that the wheel file name names the same distribution and version as its METADATA."""
    parts = wheel.name[: -len(".whl")].split("-")
    if len(parts) not in (5, 6):
        raise CandidateError(f"{wheel.name} is not a valid wheel file name")
    file_name, file_version = parts[0], parts[1]
    if normalize_name(file_name) != normalize_name(name):
        raise CandidateError(f"{wheel.name} does not name the distribution {name}")
    if not is_valid_version(file_version) or not versions_equal(file_version, version):
        raise CandidateError(f"{wheel.name} does not name the version {version}")


def check_manifest(wheel_dir: Path, wheel: Path, name: str, version: str) -> None:
    """Cross-check the <sdk>-manifest.json that the gate's build-wheel step writes beside the wheel."""
    manifest = wheel_dir / f"{name}-manifest.json"
    try:
        data = json.loads(manifest.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise CandidateError(f"the artifact holds no {manifest.name}") from None
    except (OSError, ValueError) as exc:
        raise CandidateError(f"cannot read {manifest.name}: {exc}") from None
    if not isinstance(data, dict):
        raise CandidateError(f"{manifest.name} is not a JSON object")
    sdk = data.get("sdk")
    manifest_version = data.get("version")
    wheel_filename = data.get("wheel_filename")
    if not isinstance(sdk, str) or normalize_name(sdk) != normalize_name(name):
        raise CandidateError(f"{manifest.name} names another sdk than {name}")
    if (
        not isinstance(manifest_version, str)
        or not is_valid_version(manifest_version)
        or not versions_equal(manifest_version, version)
    ):
        raise CandidateError(f"{manifest.name} names another version than {version}")
    if wheel_filename != wheel.name:
        raise CandidateError(f"{manifest.name} names another wheel file than {wheel.name}")


def find_installed(name: str, path: list[str] | None = None):
    """Return the single installed distribution named name (PEP 503 normalized).

    path defaults to sys.path, the import path of the running interpreter.
    """
    import importlib.metadata

    wanted = normalize_name(name)
    kwargs = {} if path is None else {"path": path}
    found = {}
    for dist in importlib.metadata.distributions(**kwargs):
        try:
            dist_name = dist.metadata.get("Name")
        except Exception:  # noqa: BLE001 - a broken distribution cannot be the candidate
            continue
        if not dist_name or normalize_name(dist_name) != wanted:
            continue
        # The same folder can sit on the import path twice; count each
        # .dist-info folder once. PathDistribution keeps it in _path.
        location = getattr(dist, "_path", None)
        key = os.path.realpath(str(location)) if location is not None else str(id(dist))
        found[key] = dist
    if len(found) != 1:
        raise CandidateError(
            f"expected exactly one installed distribution of {name}, found {len(found)}"
        )
    return next(iter(found.values()))


def check_direct_url(dist, name: str, wheel: Path) -> None:
    """Require a direct_url.json that names the candidate wheel itself (PEP 610)."""
    raw = dist.read_text("direct_url.json")
    if raw is None:
        raise CandidateError(
            f"the installed {name} has no direct_url.json, so it was not installed from "
            "the candidate wheel (an install from an index or from uv.lock writes none)"
        )
    try:
        data = json.loads(raw)
    except ValueError:
        raise CandidateError(f"the direct_url.json of the installed {name} is not JSON") from None
    url = data.get("url") if isinstance(data, dict) else None
    if not isinstance(url, str):
        raise CandidateError(f"the direct_url.json of the installed {name} has no url")
    parts = urlsplit(url)
    if parts.scheme != "file" or parts.netloc not in ("", "localhost"):
        raise CandidateError(
            f"the installed {name} came from a {parts.scheme or 'schemeless'} URL, "
            "not from the candidate wheel"
        )
    installed_from = os.path.realpath(url2pathname(parts.path))
    if installed_from != os.path.realpath(str(wheel)):
        raise CandidateError(
            f"the installed {name} came from {Path(installed_from).name}, "
            f"not from the candidate wheel {wheel.name}"
        )


def verify_candidate(environ: dict[str, str], path: list[str] | None = None) -> str:
    """Run the full assert and return the report line, or raise CandidateError."""
    name, version, wheel_dir = read_expected(environ)
    wheel = find_single_wheel(wheel_dir)
    wheel_name, wheel_version = read_wheel_metadata(wheel)
    if normalize_name(wheel_name) != normalize_name(name):
        raise CandidateError(f"the candidate wheel is {wheel_name}, not {name}")
    if not versions_equal(wheel_version, version):
        raise CandidateError(
            f"the candidate wheel is {wheel_name} {wheel_version}, not version {version}"
        )
    check_wheel_file_name(wheel, wheel_name, wheel_version)
    check_manifest(wheel_dir, wheel, name, version)
    dist = find_installed(name, path)
    installed_version = dist.version
    if not isinstance(installed_version, str) or not is_valid_version(installed_version):
        raise CandidateError(f"the installed {name} has no valid version")
    if not versions_equal(installed_version, version):
        raise CandidateError(
            f"the installed {name} is {installed_version}, not the candidate {version}: "
            "the environment was synced away from the candidate (a plain `uv run` "
            "syncs to uv.lock)"
        )
    check_direct_url(dist, name, wheel)
    return f"consumer-gate: {dist.metadata.get('Name')}=={installed_version} {REPORT_SOURCE}"


def _command_text(message: str) -> str:
    """Escape text for the runner's log: one line, with % escaped as in a workflow command.

    Every line this module prints goes through here. Messages can carry text
    from the wheel (a folded METADATA Name holds a newline), and a line that
    starts with :: is read by the runner as a workflow command.
    """
    return message.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


# --- pytest plugin (loaded with `pytest -p consumer_gate_candidate`) ------------

_REPORT_LINE: str | None = None


def pytest_configure(config) -> None:
    """Refuse the whole session unless this interpreter holds the candidate."""
    global _REPORT_LINE
    try:
        _REPORT_LINE = _command_text(verify_candidate(dict(os.environ)))
    except CandidateError as exc:
        from pytest import UsageError

        raise UsageError(_command_text(f"consumer-gate: REFUSED: {exc}")) from None


def pytest_report_header(config) -> list[str]:
    """Print the candidate under test in pytest's header."""
    return [_REPORT_LINE] if _REPORT_LINE else []


def pytest_terminal_summary(terminalreporter) -> None:
    """Repeat the line at the end, where --no-header cannot hide it."""
    if _REPORT_LINE:
        terminalreporter.write_line(_REPORT_LINE)


# --- command line -------------------------------------------------------------


def main(argv: list[str]) -> int:
    """Run the guard or the verify command; return the exit code."""
    environ = dict(os.environ)
    if argv == ["guard"]:
        problems = check_guard_inputs(environ)
        if problems:
            for problem in problems:
                print(f"::error::consumer-gate inputs guard: {_command_text(problem)}")
            return 1
        print(
            _command_text(
                "consumer-gate inputs guard: all four inputs set and well formed; "
                f"candidate {environ[ENV_NAME]}=={environ[ENV_VERSION]}"
            )
        )
        return 0
    if argv == ["verify"]:
        try:
            line = verify_candidate(environ)
        except CandidateError as exc:
            print(f"::error::consumer-gate: REFUSED: {_command_text(str(exc))}")
            return 1
        print(_command_text(line))
        return 0
    print("usage: consumer_gate_candidate.py guard|verify", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
