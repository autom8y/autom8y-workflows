"""Validation tests for autom8y-workflows reusable GitHub Actions workflows.

Tests cover:
1. YAML schema validity (parseable, has required top-level keys)
2. Action version pinning (all uses: refs pinned to full SHA)
3. Input completeness (all inputs have descriptions)
4. Security hardening (persist-credentials: false, timeout-minutes set)
5. Structural conventions (naming, permissions declared)
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import pytest
import yaml

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

WORKFLOWS_DIR = Path(__file__).resolve().parent.parent / ".github" / "workflows"

# SHA-pinned action ref pattern: owner/action@40-char-hex
_SHA_REF_RE = re.compile(r"^[a-zA-Z0-9_-]+/[a-zA-Z0-9_./-]+@[0-9a-f]{40}$")


def _load_workflow(path: Path) -> dict[str, Any]:
    """Load and parse a workflow YAML file."""
    with open(path) as f:
        return yaml.safe_load(f)


def _get_triggers(data: dict[str, Any]) -> dict[str, Any] | None:
    """Extract the trigger mapping from a workflow.

    PyYAML parses the bare YAML key `on` as boolean True, so we must
    check for both `data["on"]` and `data[True]`.
    """
    triggers = data.get("on") or data.get(True)
    if isinstance(triggers, dict):
        return triggers
    return None


def _all_workflow_paths() -> list[Path]:
    """Collect all .yml workflow files."""
    assert WORKFLOWS_DIR.exists(), f"Workflows dir not found: {WORKFLOWS_DIR}"
    paths = sorted(WORKFLOWS_DIR.glob("*.yml"))
    assert len(paths) > 0, "No workflow files found"
    return paths


def _all_reusable_workflow_paths() -> list[Path]:
    """Collect workflows that use workflow_call trigger (reusable)."""
    reusable = []
    for path in _all_workflow_paths():
        data = _load_workflow(path)
        triggers = _get_triggers(data)
        if triggers and "workflow_call" in triggers:
            reusable.append(path)
    return reusable


def _is_dispatcher_job(job_def: dict[str, Any]) -> bool:
    """Check if a job is a thin dispatcher (job-level uses: without steps).

    Dispatcher jobs call reusable workflows via `uses:` at job level.
    They have no steps, so timeout/permissions/checkout checks don't apply.
    """
    return "uses" in job_def and "steps" not in job_def


def _extract_step_uses_refs(data: dict[str, Any]) -> list[tuple[str, str]]:
    """Extract all step-level 'uses:' references from a workflow.

    Returns list of (context_description, uses_value).
    Only extracts from jobs that have steps (not dispatcher jobs).
    """
    refs: list[tuple[str, str]] = []
    jobs = data.get("jobs", {})
    if not isinstance(jobs, dict):
        return refs
    for job_name, job_def in jobs.items():
        if not isinstance(job_def, dict):
            continue
        steps = job_def.get("steps", [])
        if not isinstance(steps, list):
            continue
        for i, step in enumerate(steps):
            if not isinstance(step, dict):
                continue
            uses = step.get("uses")
            if uses:
                step_name = step.get("name", f"step-{i}")
                refs.append((f"{job_name}/{step_name}", str(uses)))
    return refs


def _extract_job_uses_refs(data: dict[str, Any]) -> list[tuple[str, str]]:
    """Extract all job-level 'uses:' references (dispatcher jobs).

    Returns list of (job_name, uses_value).
    """
    refs: list[tuple[str, str]] = []
    jobs = data.get("jobs", {})
    if not isinstance(jobs, dict):
        return refs
    for job_name, job_def in jobs.items():
        if not isinstance(job_def, dict):
            continue
        if _is_dispatcher_job(job_def):
            refs.append((job_name, str(job_def["uses"])))
    return refs


# ---------------------------------------------------------------------------
# Parametrize helpers
# ---------------------------------------------------------------------------

ALL_WORKFLOWS = _all_workflow_paths()
ALL_REUSABLE = _all_reusable_workflow_paths()


def _wf_id(path: Path) -> str:
    return path.stem


# ===========================================================================
# 1. YAML Schema Validity
# ===========================================================================


class TestYamlValidity:
    """All workflow files must be valid YAML with required structure."""

    @pytest.mark.parametrize("path", ALL_WORKFLOWS, ids=_wf_id)
    def test_yaml_parses_without_error(self, path: Path) -> None:
        """Workflow file must be parseable YAML."""
        data = _load_workflow(path)
        assert isinstance(data, dict), f"{path.name} did not parse to a dict"

    @pytest.mark.parametrize("path", ALL_WORKFLOWS, ids=_wf_id)
    def test_has_name_key(self, path: Path) -> None:
        """Every workflow must declare a 'name' field."""
        data = _load_workflow(path)
        assert "name" in data, f"{path.name} missing 'name' key"
        assert isinstance(data["name"], str) and len(data["name"]) > 0

    @pytest.mark.parametrize("path", ALL_WORKFLOWS, ids=_wf_id)
    def test_has_on_trigger(self, path: Path) -> None:
        """Every workflow must declare an 'on' trigger."""
        data = _load_workflow(path)
        # PyYAML parses 'on' as True (boolean); check both
        has_trigger = "on" in data or True in data
        assert has_trigger, f"{path.name} missing 'on' trigger"

    @pytest.mark.parametrize("path", ALL_WORKFLOWS, ids=_wf_id)
    def test_has_jobs(self, path: Path) -> None:
        """Every workflow must declare at least one job."""
        data = _load_workflow(path)
        assert "jobs" in data, f"{path.name} missing 'jobs' key"
        assert isinstance(data["jobs"], dict)
        assert len(data["jobs"]) > 0, f"{path.name} has empty jobs"


# ===========================================================================
# 2. Action Version Pinning (SHA)
# ===========================================================================


class TestActionPinning:
    """All third-party actions must be pinned to a full commit SHA."""

    @pytest.mark.parametrize("path", ALL_WORKFLOWS, ids=_wf_id)
    def test_all_step_uses_refs_pinned_to_sha(self, path: Path) -> None:
        """Every step-level 'uses:' ref must be pinned to a 40-char SHA."""
        data = _load_workflow(path)
        refs = _extract_step_uses_refs(data)

        unpinned: list[str] = []
        for context, ref in refs:
            # Skip docker:// and local ./ references
            if ref.startswith("docker://") or ref.startswith("./"):
                continue
            if not _SHA_REF_RE.match(ref):
                unpinned.append(f"  {context}: {ref}")

        assert not unpinned, (
            f"{path.name} has unpinned step action references:\n" + "\n".join(unpinned)
        )

    @pytest.mark.parametrize("path", ALL_WORKFLOWS, ids=_wf_id)
    def test_job_level_uses_refs_are_valid(self, path: Path) -> None:
        """Job-level 'uses:' refs must be either local (./) or SHA-pinned."""
        data = _load_workflow(path)
        refs = _extract_job_uses_refs(data)

        invalid: list[str] = []
        for job_name, ref in refs:
            is_local = ref.startswith("./")
            is_sha_pinned = _SHA_REF_RE.match(ref) is not None
            # Also allow org/repo/.github/...@sha format
            is_org_sha = bool(
                re.match(r"^[a-zA-Z0-9_-]+/[a-zA-Z0-9_./-]+@[0-9a-f]{40}$", ref)
            )
            if not (is_local or is_sha_pinned or is_org_sha):
                invalid.append(f"  {job_name}: {ref}")

        assert not invalid, (
            f"{path.name} has invalid job-level uses references:\n" + "\n".join(invalid)
        )

    @pytest.mark.parametrize("path", ALL_WORKFLOWS, ids=_wf_id)
    def test_pinned_step_refs_have_version_comment(self, path: Path) -> None:
        """SHA-pinned step refs should have a version comment (# vX.Y.Z)."""
        content = path.read_text()
        # Only check lines in steps context (indented uses: lines)
        uses_lines = [
            (i + 1, line.strip())
            for i, line in enumerate(content.splitlines())
            if "uses:" in line and "@" in line
        ]

        missing_comment: list[str] = []
        for lineno, line in uses_lines:
            uses_part = line.split("uses:")[1].strip()
            ref_part = uses_part.split("@")[0] if "@" in uses_part else ""
            # Skip local ./ refs and org/repo style job-level refs
            if ref_part.startswith("./") or ref_part.startswith("./.github"):
                continue
            # Skip org/repo/.github style (job-level dispatchers to other repos)
            if "/.github/workflows/" in ref_part:
                continue
            if "#" not in line:
                missing_comment.append(f"  L{lineno}: {line}")

        assert not missing_comment, (
            f"{path.name} has SHA-pinned actions without version comments:\n"
            + "\n".join(missing_comment)
        )


# ===========================================================================
# 3. Input Completeness (reusable workflows)
# ===========================================================================


class TestInputCompleteness:
    """Reusable workflow inputs must have descriptions and valid types."""

    @pytest.mark.parametrize("path", ALL_REUSABLE, ids=_wf_id)
    def test_all_inputs_have_descriptions(self, path: Path) -> None:
        """Every workflow_call input must have a 'description' field."""
        data = _load_workflow(path)
        triggers = _get_triggers(data)
        if not triggers:
            pytest.skip("No structured triggers")

        wf_call = triggers.get("workflow_call", {})
        if not isinstance(wf_call, dict):
            pytest.skip("No workflow_call config")

        inputs = wf_call.get("inputs", {})
        if not inputs:
            pytest.skip("No inputs declared")

        missing: list[str] = []
        for name, spec in inputs.items():
            if not isinstance(spec, dict):
                missing.append(f"  {name}: not a mapping")
                continue
            desc = spec.get("description", "")
            if not desc or not isinstance(desc, str) or len(desc.strip()) == 0:
                missing.append(f"  {name}: missing or empty description")

        assert not missing, (
            f"{path.name} has inputs without descriptions:\n" + "\n".join(missing)
        )

    @pytest.mark.parametrize("path", ALL_REUSABLE, ids=_wf_id)
    def test_all_inputs_have_valid_types(self, path: Path) -> None:
        """Every workflow_call input must declare a valid 'type' field."""
        valid_types = {"string", "boolean", "number"}
        data = _load_workflow(path)
        triggers = _get_triggers(data)
        if not triggers:
            pytest.skip("No structured triggers")

        wf_call = triggers.get("workflow_call", {})
        if not isinstance(wf_call, dict):
            pytest.skip("No workflow_call config")

        inputs = wf_call.get("inputs", {})
        if not inputs:
            pytest.skip("No inputs declared")

        invalid: list[str] = []
        for name, spec in inputs.items():
            if not isinstance(spec, dict):
                continue
            input_type = spec.get("type")
            if input_type not in valid_types:
                invalid.append(f"  {name}: type={input_type!r}")

        assert not invalid, (
            f"{path.name} has inputs with invalid types:\n" + "\n".join(invalid)
        )


# ===========================================================================
# 4. Security Hardening
# ===========================================================================


def _non_dispatcher_workflow_paths() -> list[Path]:
    """Collect workflows that have at least one job with steps (not pure dispatchers)."""
    result = []
    for path in _all_workflow_paths():
        data = _load_workflow(path)
        jobs = data.get("jobs", {})
        if not isinstance(jobs, dict):
            continue
        has_steps_job = any(
            isinstance(j, dict) and "steps" in j
            for j in jobs.values()
        )
        if has_steps_job:
            result.append(path)
    return result


NON_DISPATCHER_WORKFLOWS = _non_dispatcher_workflow_paths()


class TestSecurityHardening:
    """Workflows must follow security best practices."""

    @pytest.mark.parametrize("path", NON_DISPATCHER_WORKFLOWS, ids=_wf_id)
    def test_checkout_uses_persist_credentials_false(self, path: Path) -> None:
        """All checkout steps must set persist-credentials: false."""
        data = _load_workflow(path)
        jobs = data.get("jobs", {})
        if not isinstance(jobs, dict):
            return

        violations: list[str] = []
        for job_name, job_def in jobs.items():
            if not isinstance(job_def, dict) or _is_dispatcher_job(job_def):
                continue
            for i, step in enumerate(job_def.get("steps", [])):
                if not isinstance(step, dict):
                    continue
                uses = step.get("uses", "")
                if "actions/checkout@" in str(uses):
                    with_block = step.get("with", {})
                    if not isinstance(with_block, dict):
                        violations.append(f"  {job_name}/step-{i}: no 'with' block")
                        continue
                    persist = with_block.get("persist-credentials")
                    if persist is not False:
                        violations.append(
                            f"  {job_name}/step-{i}: persist-credentials={persist!r}"
                        )

        assert not violations, (
            f"{path.name} has checkout steps without persist-credentials: false:\n"
            + "\n".join(violations)
        )

    @pytest.mark.parametrize("path", NON_DISPATCHER_WORKFLOWS, ids=_wf_id)
    def test_jobs_with_steps_have_timeout(self, path: Path) -> None:
        """Jobs with steps must declare timeout-minutes to prevent runaway jobs."""
        data = _load_workflow(path)
        jobs = data.get("jobs", {})
        if not isinstance(jobs, dict):
            return

        missing: list[str] = []
        for job_name, job_def in jobs.items():
            if not isinstance(job_def, dict) or _is_dispatcher_job(job_def):
                continue
            if "timeout-minutes" not in job_def:
                missing.append(f"  {job_name}")

        assert not missing, (
            f"{path.name} has step-jobs without timeout-minutes:\n" + "\n".join(missing)
        )

    @pytest.mark.parametrize("path", NON_DISPATCHER_WORKFLOWS, ids=_wf_id)
    def test_jobs_with_steps_declare_permissions(self, path: Path) -> None:
        """Jobs with steps should declare permissions (least privilege).

        Workflows can declare permissions at workflow level or job level.
        Either is acceptable.
        """
        data = _load_workflow(path)
        has_workflow_perms = "permissions" in data
        jobs = data.get("jobs", {})
        if not isinstance(jobs, dict):
            return

        missing: list[str] = []
        for job_name, job_def in jobs.items():
            if not isinstance(job_def, dict) or _is_dispatcher_job(job_def):
                continue
            if not has_workflow_perms and "permissions" not in job_def:
                missing.append(f"  {job_name}")

        assert not missing, (
            f"{path.name} has step-jobs without permissions (job or workflow level):\n"
            + "\n".join(missing)
        )


# ===========================================================================
# 5. Structural Conventions
# ===========================================================================


class TestStructuralConventions:
    """Workflow files follow fleet-level naming and structural conventions."""

    @pytest.mark.parametrize("path", ALL_REUSABLE, ids=_wf_id)
    def test_reusable_workflows_use_workflow_call(self, path: Path) -> None:
        """Reusable workflows must be triggered via workflow_call."""
        data = _load_workflow(path)
        triggers = _get_triggers(data)
        assert triggers is not None
        assert "workflow_call" in triggers

    def test_security_workflows_prefixed_consistently(self) -> None:
        """Security-focused reusable workflows follow 'security-*' naming."""
        security_files = [
            p for p in ALL_WORKFLOWS if p.stem.startswith("security-")
        ]
        security_names = {p.stem for p in security_files}
        expected = {
            "security-trufflehog",
            "security-gitleaks",
            "security-zizmor",
            "security-dependency-review",
            "security-scorecard",
        }
        assert expected.issubset(security_names), (
            f"Missing expected security workflows: {expected - security_names}"
        )

    def test_no_duplicate_workflow_names(self) -> None:
        """No two workflow files should have the same 'name' field."""
        names: dict[str, list[str]] = {}
        for path in ALL_WORKFLOWS:
            data = _load_workflow(path)
            name = data.get("name", "")
            if name:
                names.setdefault(name, []).append(path.stem)

        duplicates = {n: files for n, files in names.items() if len(files) > 1}
        assert not duplicates, f"Duplicate workflow names: {duplicates}"

    def test_satellite_ci_is_reusable(self) -> None:
        """satellite-ci-reusable.yml must be a workflow_call workflow."""
        path = WORKFLOWS_DIR / "satellite-ci-reusable.yml"
        assert path.exists(), "satellite-ci-reusable.yml not found"
        data = _load_workflow(path)
        triggers = _get_triggers(data)
        assert triggers is not None, "No triggers found"
        assert "workflow_call" in triggers

    def test_satellite_ci_has_required_inputs(self) -> None:
        """satellite-ci-reusable.yml must declare mypy_targets and coverage_package as required."""
        path = WORKFLOWS_DIR / "satellite-ci-reusable.yml"
        data = _load_workflow(path)
        triggers = _get_triggers(data)
        assert triggers is not None
        inputs = triggers["workflow_call"]["inputs"]

        assert "mypy_targets" in inputs
        assert inputs["mypy_targets"].get("required") is True
        assert "coverage_package" in inputs
        assert inputs["coverage_package"].get("required") is True

    def test_workflow_file_count(self) -> None:
        """Sanity check: we expect a known number of workflow files."""
        count = len(ALL_WORKFLOWS)
        # Currently 12 workflow files; this will catch accidental deletions
        assert count >= 10, f"Expected >=10 workflow files, found {count}"

    def test_reusable_workflow_count(self) -> None:
        """There should be at least 6 reusable workflows (security + satellite CI)."""
        count = len(ALL_REUSABLE)
        assert count >= 6, f"Expected >=6 reusable workflows, found {count}"
