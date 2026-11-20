"""Shared fixtures for the consumer-gate check tests (S-126).

Dummy wheels are built with the standard library's zipfile, so no build
backend and no network are needed. A "fake installed distribution" is a
.dist-info folder in a site folder of the test's own, which importlib.metadata
reads when that folder is on the search path.
"""

from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
import re
import zipfile
from pathlib import Path
from types import ModuleType

ROOT = Path(__file__).resolve().parent.parent
HELPER_PATH = ROOT / ".github" / "scripts" / "consumer_gate_candidate.py"
EMBED_PATH = ROOT / ".github" / "scripts" / "embed_consumer_gate_candidate.py"
WORKFLOW_PATH = ROOT / ".github" / "workflows" / "satellite-ci-reusable.yml"


def load_module(path: Path, name: str) -> ModuleType:
    """Import a script by path without putting its folder on sys.path."""
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def load_helper() -> ModuleType:
    return load_module(HELPER_PATH, "consumer_gate_candidate_under_test")


def _record_line(member: str, data: bytes) -> str:
    digest = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()
    return f"{member},sha256={digest},{len(data)}"


def dist_stem(name: str) -> str:
    """The wheel file-name form of a distribution name."""
    return re.sub(r"[-_.]+", "_", name).lower()


def build_wheel(
    dest_dir: Path,
    name: str = "dummy-sdk",
    version: str = "2.0.0",
    *,
    module: str = "dummy_sdk",
    metadata_name: str | None = None,
    metadata_version: str | None = None,
    file_version: str | None = None,
    requires: tuple[str, ...] = (),
) -> Path:
    """Build a pure-Python wheel with a correct METADATA, WHEEL and RECORD."""
    dest_dir.mkdir(parents=True, exist_ok=True)
    stem = dist_stem(name)
    info = f"{stem}-{version}.dist-info"
    metadata_lines = [
        "Metadata-Version: 2.1",
        f"Name: {metadata_name if metadata_name is not None else name}",
        f"Version: {metadata_version if metadata_version is not None else version}",
        *(f"Requires-Dist: {requirement}" for requirement in requires),
    ]
    members = {
        f"{module}/__init__.py": f'VERSION = "{version}"\n'.encode(),
        f"{info}/METADATA": ("\n".join(metadata_lines) + "\n").encode(),
        f"{info}/WHEEL": b"Wheel-Version: 1.0\nGenerator: s126-tests\nRoot-Is-Purelib: true\nTag: py3-none-any\n",
    }
    record = [_record_line(member, data) for member, data in members.items()]
    record.append(f"{info}/RECORD,,")
    members[f"{info}/RECORD"] = ("\n".join(record) + "\n").encode()
    wheel = dest_dir / f"{stem}-{file_version or version}-py3-none-any.whl"
    with zipfile.ZipFile(wheel, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for member, data in members.items():
            archive.writestr(member, data)
    return wheel


def write_manifest(
    wheel_dir: Path,
    sdk: str,
    version: str,
    wheel_filename: str,
    *,
    file_sdk: str | None = None,
) -> Path:
    """Write the gate's <sdk>-manifest.json (tools/consumer-gate build-wheel's fields)."""
    manifest = wheel_dir / f"{file_sdk or sdk}-manifest.json"
    payload = {
        "sdk": sdk,
        "version": version,
        "wheel_filename": wheel_filename,
        "wheel_path": f"/gate/consumer-gate-wheels/{wheel_filename}",
        "sdist_path": None,
        "build_dir": "/gate/consumer-gate-wheels",
    }
    manifest.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return manifest


def install_fake_dist(
    site_dir: Path,
    name: str = "dummy-sdk",
    version: str = "2.0.0",
    *,
    direct_url: str | None = None,
) -> Path:
    """Create an installed-looking .dist-info folder; direct_url is the raw JSON text or None."""
    info = site_dir / f"{dist_stem(name)}-{version}.dist-info"
    info.mkdir(parents=True, exist_ok=True)
    (info / "METADATA").write_text(
        f"Metadata-Version: 2.1\nName: {name}\nVersion: {version}\n", encoding="utf-8"
    )
    (info / "INSTALLER").write_text("uv\n", encoding="utf-8")
    if direct_url is not None:
        (info / "direct_url.json").write_text(direct_url, encoding="utf-8")
    return info


def direct_url_for(wheel: Path) -> str:
    """The PEP 610 record that an install from the wheel file writes."""
    return json.dumps({"url": wheel.resolve().as_uri(), "archive_info": {}})
