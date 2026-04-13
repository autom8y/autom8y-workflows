#!/usr/bin/env python3
"""Fleet conformance gate -- validates pyproject.toml against fleet spec.

Usage:
    python validate_pyproject.py <spec_path> <pyproject_path> [--repo-name NAME]

Exit codes:
    0 = all dimensions PASS (or WARN with active exemption)
    1 = one or more dimensions FAIL
    2 = spec or pyproject parse error
"""
from __future__ import annotations

import argparse
import json
import sys
import tomllib
from pathlib import Path
from typing import Any

# PyYAML is pre-installed on ubuntu-latest GitHub Actions runners.
import yaml


# --- Result model ---

class DimensionResult:
    """Result of validating a single conformance dimension."""

    def __init__(self, name: str, status: str, message: str, details: dict[str, Any] | None = None):
        self.name = name
        self.status = status  # "PASS", "FAIL", "WARN", "SKIP"
        self.message = message
        self.details = details or {}

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {"dimension": self.name, "status": self.status, "message": self.message}
        if self.details:
            d["details"] = self.details
        return d


# --- Dimension validators ---

def validate_build_system(pyproject: dict[str, Any], spec: dict[str, Any], _exemption: dict[str, Any] | None) -> DimensionResult:
    bs = pyproject.get("build-system", {})
    requires = bs.get("requires", [])
    backend = bs.get("build-backend", "")

    expected_requires = spec["requires"]
    expected_backend = spec["build_backend"]

    errors = []
    if sorted(requires) != sorted(expected_requires):
        errors.append(f"requires: got {requires}, expected {expected_requires}")
    if backend != expected_backend:
        errors.append(f"build-backend: got '{backend}', expected '{expected_backend}'")

    if errors:
        return DimensionResult("build_system", "FAIL", "; ".join(errors))
    return DimensionResult("build_system", "PASS", "hatchling build system configured correctly")


def validate_project(pyproject: dict[str, Any], spec: dict[str, Any], _exemption: dict[str, Any] | None) -> DimensionResult:
    project = pyproject.get("project", {})
    requires_python = project.get("requires-python", "")

    errors = []

    # Check floor: must be >= the spec floor version
    floor = spec["requires_python_floor"]  # e.g. ">=3.12"
    if not requires_python:
        errors.append("requires-python not set")
    else:
        # Extract version from requires-python (e.g., ">=3.12" -> "3.12")
        import re
        spec_match = re.search(r"(\d+\.\d+)", floor)
        actual_match = re.search(r"(\d+\.\d+)", requires_python)
        if spec_match and actual_match:
            spec_ver = tuple(int(x) for x in spec_match.group(1).split("."))
            actual_ver = tuple(int(x) for x in actual_match.group(1).split("."))
            if actual_ver < spec_ver:
                errors.append(f"requires-python floor {requires_python} is below fleet minimum {floor}")
        # Check no upper bound
        if spec.get("no_upper_bound") and "<" in requires_python:
            errors.append(f"requires-python '{requires_python}' has upper bound (fleet standard forbids upper bounds)")

    if errors:
        return DimensionResult("project", "FAIL", "; ".join(errors))
    return DimensionResult("project", "PASS", f"requires-python '{requires_python}' meets fleet floor")


def validate_ruff(pyproject: dict[str, Any], spec: dict[str, Any], _exemption: dict[str, Any] | None) -> DimensionResult:
    ruff = pyproject.get("tool", {}).get("ruff", {})
    ruff_lint = ruff.get("lint", {})

    errors = []

    # line-length
    ll = ruff.get("line-length")
    if ll != spec["line_length"]:
        errors.append(f"line-length: got {ll}, expected {spec['line_length']}")

    # target-version
    tv = ruff.get("target-version")
    if tv != spec["target_version"]:
        errors.append(f"target-version: got '{tv}', expected '{spec['target_version']}'")

    # select floor (superset check: repo must include AT LEAST all floor categories)
    select = set(ruff_lint.get("select", []))
    floor = set(spec["select_floor"])
    missing = floor - select
    if missing:
        errors.append(f"ruff select missing required categories: {sorted(missing)}")

    if errors:
        return DimensionResult("ruff", "FAIL", "; ".join(errors))
    return DimensionResult("ruff", "PASS", f"ruff config compliant (select includes {sorted(floor)})")


def validate_mypy(pyproject: dict[str, Any], spec: dict[str, Any], _exemption: dict[str, Any] | None) -> DimensionResult:
    mypy = pyproject.get("tool", {}).get("mypy", {})

    errors = []

    if spec.get("strict") and not mypy.get("strict"):
        errors.append("mypy strict mode not enabled (fleet standard requires strict = true)")

    pv = mypy.get("python_version")
    if pv != spec["python_version"]:
        errors.append(f"mypy python_version: got '{pv}', expected '{spec['python_version']}'")

    if errors:
        return DimensionResult("mypy", "FAIL", "; ".join(errors))
    return DimensionResult("mypy", "PASS", "mypy strict mode with correct python_version")


def validate_coverage(pyproject: dict[str, Any], spec: dict[str, Any], exemption: dict[str, Any] | None) -> DimensionResult:
    coverage = pyproject.get("tool", {}).get("coverage", {}).get("report", {})
    fail_under = coverage.get("fail_under")

    # Determine the effective floor (spec-level, possibly overridden by exemption)
    effective_floor = spec["fail_under_floor"]
    ratchet_info: dict[str, Any] = {}

    if exemption and "coverage" in exemption:
        cov_exemption = exemption["coverage"]
        effective_floor = cov_exemption.get("fail_under_floor", effective_floor)
        if "ratchet_target" in cov_exemption:
            ratchet_info = {
                "ratchet_target": cov_exemption["ratchet_target"],
                "ratchet_deadline": cov_exemption.get("ratchet_deadline", "unset"),
                "effective_floor": effective_floor,
            }

    if fail_under is None:
        return DimensionResult("coverage", "FAIL", "tool.coverage.report.fail_under not set")

    if fail_under < effective_floor:
        return DimensionResult(
            "coverage", "FAIL",
            f"fail_under={fail_under} is below effective floor {effective_floor}",
            details=ratchet_info,
        )

    # If below the fleet-wide floor but above the exempted floor, WARN
    if fail_under < spec["fail_under_floor"] and ratchet_info:
        return DimensionResult(
            "coverage", "WARN",
            f"fail_under={fail_under} is below fleet floor {spec['fail_under_floor']} "
            f"but meets exempted floor {effective_floor} "
            f"(ratchet target: {ratchet_info['ratchet_target']} by {ratchet_info['ratchet_deadline']})",
            details=ratchet_info,
        )

    return DimensionResult("coverage", "PASS", f"fail_under={fail_under} meets fleet floor {spec['fail_under_floor']}")


def validate_sdk_pins(pyproject: dict[str, Any], spec: dict[str, Any], _exemption: dict[str, Any] | None) -> DimensionResult:
    deps = pyproject.get("project", {}).get("dependencies", [])
    prefix = spec.get("package_prefix", "autom8y-")
    banned_style = "~="

    violations = []
    for dep in deps:
        if dep.strip().startswith(prefix) or dep.strip().split("[")[0].startswith(prefix):
            if banned_style in dep:
                violations.append(dep.strip())

    # Also check optional-dependencies
    for group_name, group_deps in pyproject.get("project", {}).get("optional-dependencies", {}).items():
        for dep in group_deps:
            if dep.strip().startswith(prefix) or dep.strip().split("[")[0].startswith(prefix):
                if banned_style in dep:
                    violations.append(f"[{group_name}] {dep.strip()}")

    if violations:
        return DimensionResult(
            "sdk_pins", "FAIL",
            f"Found {len(violations)} tilde (~=) pins on autom8y-* SDKs: {violations}",
        )
    return DimensionResult("sdk_pins", "PASS", "All autom8y-* SDK dependencies use >= pins")


# --- Orchestrator ---

VALIDATORS = {
    "build_system": validate_build_system,
    "project": validate_project,
    "ruff": validate_ruff,
    "mypy": validate_mypy,
    "coverage": validate_coverage,
    "sdk_pins": validate_sdk_pins,
}


def run_gate(spec_path: str, pyproject_path: str, repo_name: str) -> int:
    """Run all conformance checks. Returns 0 on success, 1 on failure, 2 on parse error."""
    # Parse inputs
    try:
        with open(spec_path) as f:
            spec = yaml.safe_load(f)
    except Exception as e:
        print(f"::error::Failed to parse spec: {e}", file=sys.stderr)
        return 2

    try:
        with open(pyproject_path, "rb") as f:
            pyproject = tomllib.load(f)
    except Exception as e:
        print(f"::error::Failed to parse pyproject.toml: {e}", file=sys.stderr)
        return 2

    # Check skip_all exemption
    exemptions = spec.get("exemptions", {})
    repo_exemption = exemptions.get(repo_name)

    if repo_exemption and repo_exemption.get("skip_all"):
        reason = repo_exemption.get("reason", "no reason provided")
        print(f"SKIP: {repo_name} is fully exempt ({reason})")
        # Write GitHub Actions summary
        _write_summary([DimensionResult("all", "SKIP", f"Fully exempt: {reason}")])
        return 0

    # Run validators
    results: list[DimensionResult] = []
    for dim_name, validator in VALIDATORS.items():
        dim_spec = spec["dimensions"].get(dim_name, {})
        result = validator(pyproject, dim_spec, repo_exemption)
        results.append(result)

        # Emit GitHub Actions annotations
        icon = {"PASS": "v", "FAIL": "X", "WARN": "!", "SKIP": "-"}[result.status]
        color_fn = {"PASS": "notice", "FAIL": "error", "WARN": "warning", "SKIP": "notice"}[result.status]
        print(f"::{color_fn}::[{icon}] {result.name}: {result.message}")

    # Write summary
    _write_summary(results)

    # Determine exit code
    has_failure = any(r.status == "FAIL" for r in results)
    if has_failure:
        failed = [r.name for r in results if r.status == "FAIL"]
        print(f"\n::error::Conformance gate FAILED on dimensions: {', '.join(failed)}")
        return 1

    return 0


def _write_summary(results: list[DimensionResult]) -> None:
    """Write GitHub Actions job summary as a markdown table."""
    import os
    summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
    if not summary_path:
        return

    icons = {"PASS": "PASS", "FAIL": "FAIL", "WARN": "WARN", "SKIP": "SKIP"}
    with open(summary_path, "a") as f:
        f.write("## Fleet Conformance Gate\n\n")
        f.write("| Dimension | Status | Details |\n")
        f.write("|-----------|--------|---------|\n")
        for r in results:
            f.write(f"| {r.name} | {icons[r.status]} | {r.message} |\n")
        f.write("\n")

    # Also emit JSON to stdout for programmatic consumption
    print(json.dumps([r.to_dict() for r in results], indent=2))


def main() -> None:
    parser = argparse.ArgumentParser(description="Fleet conformance gate")
    parser.add_argument("spec_path", help="Path to fleet-conformance-spec.yml")
    parser.add_argument("pyproject_path", help="Path to target pyproject.toml")
    parser.add_argument("--repo-name", default="", help="Repository name for exemption lookup")
    args = parser.parse_args()
    sys.exit(run_gate(args.spec_path, args.pyproject_path, args.repo_name))


if __name__ == "__main__":
    main()
