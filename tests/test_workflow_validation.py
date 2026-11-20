"""Validation tests for autom8y-workflows reusable GitHub Actions workflows.

Tests cover:
1. YAML schema validity (parseable, has required top-level keys)
2. Action version pinning (all uses: refs pinned to full SHA)
3. Input completeness (all inputs have descriptions)
4. Security hardening (persist-credentials: false, timeout-minutes set)
5. Structural conventions (naming, permissions declared)
6. Consumer-gate candidate coverage (S-126): every `uv run` after a candidate
   force-install keeps the candidate, and the check runs where it must
"""

from __future__ import annotations

import copy
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest
import yaml

from tests._consumer_gate_support import EMBED_PATH, HELPER_PATH, load_module

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

WORKFLOWS_DIR = Path(__file__).resolve().parent.parent / ".github" / "workflows"
TEMPLATES_DIR = Path(__file__).resolve().parent.parent / "templates"

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


def _all_template_paths() -> list[Path]:
    """Collect all .yml.template workflow template files."""
    if not TEMPLATES_DIR.exists():
        return []
    return sorted(TEMPLATES_DIR.glob("*.yml.template"))


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
ALL_TEMPLATES = _all_template_paths()


def _wf_id(path: Path) -> str:
    return path.stem


def _tmpl_id(path: Path) -> str:
    return path.name.removesuffix(".yml.template")


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


# ===========================================================================
# 6. Conditional Job Structural Coverage
# ===========================================================================

# Maps each conditional job to its enabling input and expected if-condition fragment.
_CONDITIONAL_JOBS: list[tuple[str, str, str]] = [
    ("integration", "run_integration", "inputs.run_integration"),
    ("convention-check", "convention_check", "inputs.convention_check"),
    ("spectral-validation", "spectral_enabled", "inputs.spectral_enabled"),
    ("spec-check", "spec_check_enabled", "inputs.spec_check_enabled"),
    ("semantic-score", "semantic_score_enabled", "inputs.semantic_score_enabled"),
]


class TestConditionalJobs:
    """Conditional jobs in satellite-ci-reusable must have correct gating and security."""

    _SAT_PATH = WORKFLOWS_DIR / "satellite-ci-reusable.yml"

    @pytest.fixture()
    def sat_data(self) -> dict[str, Any]:
        return _load_workflow(self._SAT_PATH)

    @pytest.mark.parametrize(
        "job_name,input_name,condition_fragment",
        _CONDITIONAL_JOBS,
        ids=[j[0] for j in _CONDITIONAL_JOBS],
    )
    def test_conditional_job_exists(
        self, sat_data: dict[str, Any], job_name: str, input_name: str, condition_fragment: str
    ) -> None:
        """Each conditional job must exist in the workflow jobs dict."""
        jobs = sat_data.get("jobs", {})
        assert job_name in jobs, f"Job '{job_name}' not found in satellite-ci-reusable.yml"

    @pytest.mark.parametrize(
        "job_name,input_name,condition_fragment",
        _CONDITIONAL_JOBS,
        ids=[j[0] for j in _CONDITIONAL_JOBS],
    )
    def test_conditional_job_if_condition(
        self, sat_data: dict[str, Any], job_name: str, input_name: str, condition_fragment: str
    ) -> None:
        """Each conditional job's if-condition must reference its enabling input."""
        job_def = sat_data["jobs"][job_name]
        if_cond = str(job_def.get("if", ""))
        assert condition_fragment in if_cond, (
            f"Job '{job_name}' if-condition '{if_cond}' does not reference '{condition_fragment}'"
        )

    @pytest.mark.parametrize(
        "job_name,input_name,condition_fragment",
        _CONDITIONAL_JOBS,
        ids=[j[0] for j in _CONDITIONAL_JOBS],
    )
    def test_conditional_job_has_permissions(
        self, sat_data: dict[str, Any], job_name: str, input_name: str, condition_fragment: str
    ) -> None:
        """Each conditional job must declare explicit permissions."""
        job_def = sat_data["jobs"][job_name]
        assert "permissions" in job_def, (
            f"Job '{job_name}' missing permissions block"
        )

    @pytest.mark.parametrize(
        "job_name,input_name,condition_fragment",
        _CONDITIONAL_JOBS,
        ids=[j[0] for j in _CONDITIONAL_JOBS],
    )
    def test_conditional_job_has_timeout(
        self, sat_data: dict[str, Any], job_name: str, input_name: str, condition_fragment: str
    ) -> None:
        """Each conditional job must declare timeout-minutes."""
        job_def = sat_data["jobs"][job_name]
        assert "timeout-minutes" in job_def, (
            f"Job '{job_name}' missing timeout-minutes"
        )

    @pytest.mark.parametrize(
        "job_name,input_name,condition_fragment",
        _CONDITIONAL_JOBS,
        ids=[j[0] for j in _CONDITIONAL_JOBS],
    )
    def test_conditional_job_enabling_input_exists(
        self, sat_data: dict[str, Any], job_name: str, input_name: str, condition_fragment: str
    ) -> None:
        """The enabling input referenced in if-condition must be declared."""
        triggers = _get_triggers(sat_data)
        assert triggers is not None
        inputs = triggers["workflow_call"]["inputs"]
        assert input_name in inputs, (
            f"Input '{input_name}' for job '{job_name}' not declared in workflow_call inputs"
        )

    def test_env_injection_uses_composite_action(self, sat_data: dict[str, Any]) -> None:
        """Jobs using env-injection validation must call the composite action, not inline."""
        jobs = sat_data.get("jobs", {})
        for job_name, job_def in jobs.items():
            if not isinstance(job_def, dict):
                continue
            for step in job_def.get("steps", []):
                if not isinstance(step, dict):
                    continue
                run_block = step.get("run", "")
                assert "DENYLIST=" not in run_block, (
                    f"Job '{job_name}' has inline DENYLIST — "
                    "use ./.github/actions/validate-env-injection instead"
                )


# ===========================================================================
# 7. DENYLIST / Env-Injection Composite Action Integrity
# ===========================================================================

_COMPOSITE_ACTION_PATH = (
    Path(__file__).resolve().parent.parent
    / ".github" / "actions" / "validate-env-injection" / "action.yml"
)

# Jobs that accept caller-supplied env pairs and must validate them.
_ENV_INJECTION_JOBS = ["test", "integration", "convention-check", "spec-check"]


class TestEnvInjectionCompositeAction:
    """The validate-env-injection composite action must exist and be correctly wired."""

    def test_composite_action_exists(self) -> None:
        """The composite action YAML must exist."""
        assert _COMPOSITE_ACTION_PATH.exists(), (
            f"Composite action not found: {_COMPOSITE_ACTION_PATH}"
        )

    def test_composite_action_contains_denylist(self) -> None:
        """The composite action must contain the DENYLIST security pattern."""
        content = _COMPOSITE_ACTION_PATH.read_text()
        assert "DENYLIST=" in content, "Composite action missing DENYLIST pattern"
        assert "GITHUB_|ACTIONS_|RUNNER_|AWS_" in content, (
            "DENYLIST missing expected protected prefixes"
        )

    def test_jobs_reference_composite_action(self) -> None:
        """All env-injection jobs must have a step using the composite action."""
        sat_path = WORKFLOWS_DIR / "satellite-ci-reusable.yml"
        data = _load_workflow(sat_path)
        jobs = data.get("jobs", {})

        missing: list[str] = []
        for job_name in _ENV_INJECTION_JOBS:
            job_def = jobs.get(job_name, {})
            steps = job_def.get("steps", [])
            has_composite_call = any(
                isinstance(s, dict)
                and "./.github/actions/validate-env-injection" in str(s.get("uses", ""))
                for s in steps
            )
            if not has_composite_call:
                missing.append(job_name)

        assert not missing, (
            f"Jobs missing validate-env-injection composite action call: {missing}"
        )


# ===========================================================================
# 8. Template Security Hardening
# ===========================================================================


class TestTemplateSecurityHardening:
    """Workflow templates must follow the same security standards as workflows."""

    @pytest.mark.parametrize("path", ALL_TEMPLATES, ids=_tmpl_id)
    def test_template_checkout_uses_persist_credentials_false(self, path: Path) -> None:
        """Template checkout steps must set persist-credentials: false."""
        data = _load_workflow(path)
        jobs = data.get("jobs", {})
        if not isinstance(jobs, dict):
            return

        violations: list[str] = []
        for job_name, job_def in jobs.items():
            if not isinstance(job_def, dict):
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

    @pytest.mark.parametrize("path", ALL_TEMPLATES, ids=_tmpl_id)
    def test_template_step_uses_refs_pinned_to_sha(self, path: Path) -> None:
        """Template step-level uses: refs must be SHA-pinned."""
        data = _load_workflow(path)
        refs = _extract_step_uses_refs(data)

        unpinned: list[str] = []
        for context, ref in refs:
            if ref.startswith("docker://") or ref.startswith("./"):
                continue
            if not _SHA_REF_RE.match(ref):
                unpinned.append(f"  {context}: {ref}")

        assert not unpinned, (
            f"{path.name} has unpinned step action references:\n" + "\n".join(unpinned)
        )

    @pytest.mark.parametrize("path", ALL_TEMPLATES, ids=_tmpl_id)
    def test_template_masks_secrets_before_env_export(self, path: Path) -> None:
        """Templates must mask secret values before writing to $GITHUB_ENV.

        Any step that writes a token/secret to GITHUB_ENV must call
        ::add-mask:: first to prevent log exposure.
        """
        content = path.read_text()
        lines = content.splitlines()

        violations: list[str] = []
        for i, line in enumerate(lines):
            stripped = line.strip()
            # Detect pattern: echo "SECRET_VAR=$VAR" >> "$GITHUB_ENV"
            if ">> \"$GITHUB_ENV\"" in stripped or ">> $GITHUB_ENV" in stripped:
                if "TOKEN" in stripped.upper() or "SECRET" in stripped.upper():
                    # Look backwards for ::add-mask:: in the same run block
                    found_mask = False
                    for j in range(max(0, i - 10), i):
                        if "::add-mask::" in lines[j]:
                            found_mask = True
                            break
                    if not found_mask:
                        violations.append(f"  L{i + 1}: {stripped}")

        assert not violations, (
            f"{path.name} writes token/secret to GITHUB_ENV without ::add-mask:::\n"
            + "\n".join(violations)
        )


# ===========================================================================
# 9. Consumer-gate candidate coverage (S-126)
# ===========================================================================
#
# On a consumer-gate run the lint and test jobs force-install a candidate SDK
# wheel. A plain `uv run` afterwards syncs the environment back to uv.lock and
# replaces the candidate, while the run still succeeds. These checks fail when
# any later step could do that unnoticed, or when the guard, the plugin or the
# re-read is missing or misplaced.

_SAT_CI_PATH = WORKFLOWS_DIR / "satellite-ci-reusable.yml"
_CANDIDATE_JOBS = ("lint", "test")
_LOCK_SOURCES_GUARD = "Require lock-sources success"
_INSTALL_STEP = "Force-install candidate SDK wheel (consumer-gate)"
_PYTEST_STEP = "Run tests with coverage"
_REREAD_STEP = "Re-read candidate after the last uv run (consumer-gate)"
_GUARD_ID = "consumer-gate-guard"
_CANDIDATE_IF = "steps.consumer-gate-guard.outputs.mode == 'candidate'"
_MODE_EXPR = "${{ steps.consumer-gate-guard.outputs.mode }}"
_GUARD_ENV = {
    "CONSUMER_GATE_SDK_NAME": "${{ inputs.candidate_sdk_name }}",
    "CONSUMER_GATE_SDK_VERSION": "${{ inputs.candidate_sdk_version }}",
    "CONSUMER_GATE_WHEEL_RUN_ID": "${{ inputs.candidate_wheel_run_id }}",
    "CONSUMER_GATE_CORRELATION_ID": "${{ inputs.dispatch_correlation_id }}",
}
_CHECK_ENV = {
    "CONSUMER_GATE_SDK_NAME": "${{ inputs.candidate_sdk_name }}",
    "CONSUMER_GATE_SDK_VERSION": "${{ inputs.candidate_sdk_version }}",
    "CONSUMER_GATE_WHEEL_DIR": "${{ github.workspace }}/_candidate-wheel",
}
_NO_SYNC_EXPORT = 'echo "UV_NO_SYNC=1" >> "$GITHUB_ENV"'
_UV_RUN_RE = re.compile(r"\buv\s+run\b")
_PYTEST_RE = re.compile(r"\bpytest\b")
_UV_ENV_WRITE_RE = re.compile(r"\buv\s+(?:sync|pip|add|remove|venv)\b")
# Plain pip, bare or by path (".../bin/pip" install) or as `python -m pip`.
_PIP_WRITE_RE = re.compile(r"\bpip3?[\"']?\s+(?:install|uninstall|sync)\b")
_ALLOWED_UV_RUN_FLAGS = frozenset({"--no-sources", "--no-sync"})
_ALLOWED_ACTIONS_AFTER_INSTALL = ("actions/upload-artifact@", "codecov/codecov-action@")
_PLUGIN_ARRAY = '"${CONSUMER_GATE_PLUGIN[@]}"'
_PLUGIN_DEFINITION = "CONSUMER_GATE_PLUGIN=(-p consumer_gate_candidate)"
_VERIFY_COMMAND = (
    'uv run --no-sync --no-sources python -I "${RUNNER_TEMP}/consumer-gate/consumer_gate_candidate.py" verify'
)
_INLINE_CANDIDATE_INPUT_RE = re.compile(
    r"inputs\.(?:candidate_sdk_name|candidate_sdk_version|candidate_wheel_run_id|dispatch_correlation_id)"
)


def _steps(job: dict[str, Any]) -> list[dict[str, Any]]:
    return [step for step in job.get("steps", []) if isinstance(step, dict)]


def _code_lines(run: str) -> list[str]:
    """A run script's logical lines: comment lines dropped, backslash continuations joined.

    Joining matters: `uv run \\` followed by `--isolated pytest` on the next
    line must be read as one command, or its flags escape the check.
    """
    lines: list[str] = []
    pending = ""
    for line in run.splitlines():
        if not pending and line.lstrip().startswith("#"):
            continue
        stripped = line.rstrip()
        if stripped.endswith("\\"):
            pending += stripped[:-1] + " "
            continue
        lines.append(pending + line)
        pending = ""
    if pending:
        lines.append(pending)
    return lines


def _is_reread(code: str) -> bool:
    """A re-read step's whole script is exactly the verify command: nothing may follow it."""
    return " ".join(code.split()) == _VERIFY_COMMAND


def _is_force_install(step: dict[str, Any]) -> bool:
    run = str(step.get("run", ""))
    return "--force-reinstall" in run and '"$CANDIDATE"' in run


def _uv_run_flags(line: str) -> list[list[str]]:
    """uv's own flags for each `uv run` on a line: the tokens before the command."""
    found = []
    for match in _UV_RUN_RE.finditer(line):
        flags = []
        for token in line[match.end():].split():
            if not token.startswith("-"):
                break
            flags.append(token)
        found.append(flags)
    return found


def _job_problems(job_name: str, job: dict[str, Any]) -> tuple[list[str], str | None]:
    """The coverage problems of one candidate job, and its guard step's script."""
    where = f"job {job_name}"
    problems: list[str] = []
    steps = _steps(job)
    if "UV_NO_SYNC" in (job.get("env") or {}):
        problems.append(f"{where}: job env sets UV_NO_SYNC")

    # The lock-sources guard keeps the first step (B-2, tests/test_check_lock_sources.py);
    # the inputs guard comes right after it, before every other step.
    guard_run = None
    guard = steps[1] if len(steps) > 1 else {}
    if not steps or steps[0].get("name") != _LOCK_SOURCES_GUARD or guard.get("id") != _GUARD_ID:
        problems.append(f"{where}: the consumer-gate inputs guard is not the step right after the lock-sources guard")
    else:
        guard_run = str(guard.get("run", ""))
        if "if" in guard:
            problems.append(f"{where}: the inputs guard has an if:, so it could be skipped")
        if "continue-on-error" in guard:
            problems.append(f"{where}: the inputs guard has continue-on-error")
        if guard.get("env") != _GUARD_ENV:
            problems.append(f"{where}: the inputs guard does not map exactly the four inputs")
        if guard.get("shell") != "bash":
            problems.append(f"{where}: the inputs guard does not set shell: bash")

    for step in steps:
        name = str(step.get("name", ""))
        if "(consumer-gate)" in name and step.get("if") != _CANDIDATE_IF:
            problems.append(f"{where}: step '{name}' does not run on {_CANDIDATE_IF}")
        if "(consumer-gate)" in name and "continue-on-error" in step:
            problems.append(f"{where}: step '{name}' has continue-on-error, so its failure would not fail the job")

    install_index = next(index for index, step in enumerate(steps) if _is_force_install(step))
    install_lines = [line.strip() for line in _code_lines(str(steps[install_index].get("run", "")))]
    pip_index = next(
        (i for i, line in enumerate(install_lines) if line.startswith("uv pip install") and "--force-reinstall" in line),
        None,
    )
    if pip_index is None or _NO_SYNC_EXPORT not in install_lines[pip_index + 1:]:
        problems.append(f"{where}: the force-install does not export UV_NO_SYNC=1 to $GITHUB_ENV after installing")

    last_uv_run = None
    rereads = []
    for index in range(install_index + 1, len(steps)):
        step = steps[index]
        label = f"{where}, step '{step.get('name', f'step-{index}')}'"
        env = step.get("env") or {}
        lines = _code_lines(str(step.get("run", "")))
        code = "\n".join(lines)
        if "UV_NO_SYNC" in env:
            problems.append(f"{label}: env sets UV_NO_SYNC")
        if "UV_NO_SYNC" in code:
            problems.append(f"{label}: the script touches UV_NO_SYNC")
        if _UV_ENV_WRITE_RE.search(code) or _PIP_WRITE_RE.search(code):
            problems.append(
                f"{label}: changes the environment after the candidate install "
                "(uv sync, uv pip, uv add, uv remove, uv venv or pip)"
            )
        uses = str(step.get("uses", ""))
        if uses and not uses.startswith(_ALLOWED_ACTIONS_AFTER_INSTALL):
            problems.append(f"{label}: uses {uses.split('@')[0]}, which this check has not reviewed")
        is_reread = _is_reread(code)
        if is_reread:
            rereads.append(index)
            if env != _CHECK_ENV:
                problems.append(f"{label}: the re-read does not get exactly the name, version and wheel folder")
            if step.get("if") != _CANDIDATE_IF:
                problems.append(f"{label}: the re-read does not run on {_CANDIDATE_IF}")
            if "continue-on-error" in step:
                problems.append(f"{label}: the re-read has continue-on-error, so its failure would not fail the job")
        for line in lines:
            for flags in _uv_run_flags(line):
                unknown = [flag for flag in flags if flag not in _ALLOWED_UV_RUN_FLAGS]
                if unknown:
                    problems.append(f"{label}: `uv run` with {unknown}, which this check does not cover")
                if not is_reread:
                    last_uv_run = index
            if _UV_RUN_RE.search(line) and _PYTEST_RE.search(line) and _PLUGIN_ARRAY not in line:
                problems.append(f"{label}: a pytest run without the consumer-gate plugin")
        if _UV_RUN_RE.search(code) and _PYTEST_RE.search(code):
            if "if" in step:
                problems.append(f"{label}: the pytest step has an if:, so a candidate run could skip its tests")
            if "continue-on-error" in step:
                problems.append(f"{label}: the pytest step has continue-on-error, so a failure would not fail the job")
            if _PLUGIN_DEFINITION not in code:
                problems.append(f"{label}: does not load the plugin with -p on candidate runs")
            if "PYTEST_ADDOPTS" in code:
                problems.append(f"{label}: uses PYTEST_ADDOPTS; the plugin must be on the command line")
            expected_env = dict(_CHECK_ENV, CONSUMER_GATE_MODE=_MODE_EXPR)
            if any(env.get(key) != value for key, value in expected_env.items()):
                problems.append(f"{label}: the pytest step does not get the mode, name, version and wheel folder")
    if not rereads:
        problems.append(f"{where}: no re-read of the candidate after the force-install")
    elif last_uv_run is not None and max(rereads) < last_uv_run:
        problems.append(f"{where}: the re-read runs before the last `uv run`")
    return problems, guard_run


def consumer_gate_coverage_problems(data: dict[str, Any]) -> list[str]:
    """Every way satellite-ci-reusable.yml could let a candidate run test the lock instead."""
    problems: list[str] = []
    jobs = {name: job for name, job in data.get("jobs", {}).items() if isinstance(job, dict)}
    if "UV_NO_SYNC" in (data.get("env") or {}):
        problems.append("workflow env sets UV_NO_SYNC")
    install_jobs = sorted(name for name, job in jobs.items() if any(_is_force_install(s) for s in _steps(job)))
    if install_jobs != sorted(_CANDIDATE_JOBS):
        problems.append(
            f"jobs with a candidate force-install are {install_jobs}, not {sorted(_CANDIDATE_JOBS)}; "
            "extend the consumer-gate check to cover a new one"
        )
    guard_runs = {}
    for job_name in install_jobs:
        job_problems, guard_run = _job_problems(job_name, jobs[job_name])
        problems.extend(job_problems)
        if guard_run is not None:
            guard_runs[job_name] = guard_run
    if len(set(guard_runs.values())) > 1:
        problems.append("the inputs guard scripts of the candidate jobs differ")
    for job_name, job in jobs.items():
        for step in _steps(job):
            if _INLINE_CANDIDATE_INPUT_RE.search(str(step.get("run", ""))):
                problems.append(
                    f"job {job_name}, step '{step.get('name', '')}': a candidate input is inline in run; pass it through env:"
                )
    return problems


def _guard_step(data: dict[str, Any], job_name: str) -> dict[str, Any]:
    return next(step for step in _steps(data["jobs"][job_name]) if step.get("id") == _GUARD_ID)


def _step_named(data: dict[str, Any], job_name: str, name: str) -> dict[str, Any]:
    return next(step for step in _steps(data["jobs"][job_name]) if step.get("name") == name)


def _step_index(data: dict[str, Any], job_name: str, name: str) -> int:
    return next(i for i, step in enumerate(_steps(data["jobs"][job_name])) if step.get("name") == name)


class TestConsumerGateCoverage:
    """S-126 B1 to B4: the structural half. The guard script runs in TestConsumerGateGuardScript."""

    @pytest.fixture()
    def sat_data(self) -> dict[str, Any]:
        return _load_workflow(_SAT_CI_PATH)

    def test_workflow_has_no_coverage_problems(self, sat_data: dict[str, Any]) -> None:
        problems = consumer_gate_coverage_problems(sat_data)
        assert not problems, "consumer-gate coverage problems:\n" + "\n".join(problems)

    def test_embedded_helper_matches_the_canonical_file(self) -> None:
        embed = load_module(EMBED_PATH, "embed_consumer_gate_candidate_under_test")
        workflow_text = _SAT_CI_PATH.read_text(encoding="utf-8")
        updated, copies = embed.embed(workflow_text, HELPER_PATH.read_text(encoding="utf-8"))
        assert copies == 2
        assert updated == workflow_text, (
            "the helper embedded in satellite-ci-reusable.yml differs from "
            ".github/scripts/consumer_gate_candidate.py; run "
            "python3 .github/scripts/embed_consumer_gate_candidate.py"
        )

    @pytest.mark.parametrize("job_name", _CANDIDATE_JOBS)
    def test_parsed_guard_writes_the_canonical_helper(self, sat_data: dict[str, Any], job_name: str) -> None:
        """Read through YAML, the heredoc body is the canonical file byte for byte."""
        run = str(_guard_step(sat_data, job_name)["run"])
        opener = "<<'CONSUMER_GATE_CANDIDATE_PY'\n"
        body = run.split(opener, 1)[1].split("\nCONSUMER_GATE_CANDIDATE_PY\n", 1)[0] + "\n"
        assert body == HELPER_PATH.read_text(encoding="utf-8")
        assert "${{" not in body

    # --- each rule bites: a mutation of the real workflow must be reported ---

    @staticmethod
    def _problems_after(sat_data: dict[str, Any], mutate: Any) -> list[str]:
        mutated = copy.deepcopy(sat_data)
        mutate(mutated)
        return consumer_gate_coverage_problems(mutated)

    @pytest.mark.parametrize("job_name", _CANDIDATE_JOBS)
    def test_bites_when_the_no_sync_export_is_removed(self, sat_data: dict[str, Any], job_name: str) -> None:
        def mutate(data: dict[str, Any]) -> None:
            step = next(s for s in _steps(data["jobs"][job_name]) if _is_force_install(s))
            step["run"] = step["run"].replace(_NO_SYNC_EXPORT, "")

        problems = self._problems_after(sat_data, mutate)
        assert any(f"job {job_name}" in p and "UV_NO_SYNC=1" in p for p in problems), problems

    def test_bites_on_an_uncovered_uv_run_flag(self, sat_data: dict[str, Any]) -> None:
        def mutate(data: dict[str, Any]) -> None:
            index = _step_index(data, "lint", "Check formatting")
            data["jobs"]["lint"]["steps"].insert(index, {"name": "Smoke", "run": "uv run --isolated python -c 1"})

        problems = self._problems_after(sat_data, mutate)
        assert any("Smoke" in p and "--isolated" in p for p in problems), problems

    def test_bites_on_a_sync_after_the_install(self, sat_data: dict[str, Any]) -> None:
        def mutate(data: dict[str, Any]) -> None:
            index = _step_index(data, "test", "Build pytest arguments")
            data["jobs"]["test"]["steps"].insert(index, {"name": "Resync", "run": "uv sync --no-sources"})

        problems = self._problems_after(sat_data, mutate)
        assert any("Resync" in p and "changes the environment" in p for p in problems), problems

    @pytest.mark.parametrize("where", ["env", "run"])
    def test_bites_when_a_later_step_overrides_uv_no_sync(self, sat_data: dict[str, Any], where: str) -> None:
        def mutate(data: dict[str, Any]) -> None:
            step = _step_named(data, "lint", "Type check (strict)")
            if where == "env":
                step["env"] = {"UV_NO_SYNC": ""}
            else:
                step["run"] = "unset UV_NO_SYNC\n" + step["run"]

        problems = self._problems_after(sat_data, mutate)
        assert any("Type check (strict)" in p and "UV_NO_SYNC" in p for p in problems), problems

    def test_bites_on_job_level_uv_no_sync(self, sat_data: dict[str, Any]) -> None:
        problems = self._problems_after(sat_data, lambda d: d["jobs"]["test"].update(env={"UV_NO_SYNC": "0"}))
        assert any("job test: job env sets UV_NO_SYNC" in p for p in problems), problems

    def test_bites_on_an_unreviewed_action_after_the_install(self, sat_data: dict[str, Any]) -> None:
        def mutate(data: dict[str, Any]) -> None:
            index = _step_index(data, "test", "Run tests with coverage")
            data["jobs"]["test"]["steps"].insert(index, {"name": "Local action", "uses": "./.github/actions/setup"})

        problems = self._problems_after(sat_data, mutate)
        assert any("Local action" in p and "not reviewed" in p for p in problems), problems

    @pytest.mark.parametrize("branch", [0, 1])
    def test_bites_when_a_pytest_branch_drops_the_plugin(self, sat_data: dict[str, Any], branch: int) -> None:
        def mutate(data: dict[str, Any]) -> None:
            step = _step_named(data, "test", "Run tests with coverage")
            lines = step["run"].split("\n")
            pytest_lines = [i for i, line in enumerate(lines) if "uv run" in line and "pytest" in line]
            lines[pytest_lines[branch]] = lines[pytest_lines[branch]].replace(_PLUGIN_ARRAY + " ", "")
            step["run"] = "\n".join(lines)

        problems = self._problems_after(sat_data, mutate)
        assert any("without the consumer-gate plugin" in p for p in problems), problems

    def test_bites_when_the_plugin_moves_to_pytest_addopts(self, sat_data: dict[str, Any]) -> None:
        def mutate(data: dict[str, Any]) -> None:
            step = _step_named(data, "test", "Run tests with coverage")
            step["run"] = step["run"].replace(
                _PLUGIN_DEFINITION, 'export PYTEST_ADDOPTS="-p consumer_gate_candidate"'
            )

        problems = self._problems_after(sat_data, mutate)
        assert any("does not load the plugin" in p for p in problems), problems
        assert any("PYTEST_ADDOPTS" in p for p in problems), problems

    @pytest.mark.parametrize("job_name", _CANDIDATE_JOBS)
    def test_bites_when_the_re_read_is_missing(self, sat_data: dict[str, Any], job_name: str) -> None:
        def mutate(data: dict[str, Any]) -> None:
            steps = data["jobs"][job_name]["steps"]
            steps[:] = [s for s in steps if s.get("name") != "Re-read candidate after the last uv run (consumer-gate)"]

        problems = self._problems_after(sat_data, mutate)
        assert any(f"job {job_name}: no re-read" in p for p in problems), problems

    def test_bites_when_the_re_read_runs_before_the_last_uv_run(self, sat_data: dict[str, Any]) -> None:
        def mutate(data: dict[str, Any]) -> None:
            steps = data["jobs"]["lint"]["steps"]
            reread = next(s for s in steps if s.get("name") == "Re-read candidate after the last uv run (consumer-gate)")
            steps.remove(reread)
            steps.insert(_step_index(data, "lint", "Check formatting"), reread)

        problems = self._problems_after(sat_data, mutate)
        assert any("re-read runs before the last `uv run`" in p for p in problems), problems

    def test_bites_when_the_re_read_uses_a_plain_uv_run(self, sat_data: dict[str, Any]) -> None:
        def mutate(data: dict[str, Any]) -> None:
            step = _step_named(data, "test", "Re-read candidate after the last uv run (consumer-gate)")
            step["run"] = step["run"].replace("uv run --no-sync --no-sources", "uv run --no-sources")

        problems = self._problems_after(sat_data, mutate)
        assert any("job test: no re-read" in p for p in problems), problems

    @pytest.mark.parametrize(
        "mutation,message",
        [
            (lambda step: step.update({"if": "always()"}), "has an if:"),
            (lambda step: step.update({"continue-on-error": True}), "continue-on-error"),
            (lambda step: step["env"].pop("CONSUMER_GATE_CORRELATION_ID"), "exactly the four inputs"),
            (lambda step: step.pop("shell"), "shell: bash"),
        ],
    )
    def test_bites_on_a_weakened_guard(self, sat_data: dict[str, Any], mutation: Any, message: str) -> None:
        problems = self._problems_after(sat_data, lambda d: mutation(_guard_step(d, "test")))
        assert any("job test" in p and message in p for p in problems), problems

    @pytest.mark.parametrize("swap", [(0, 1), (1, 2)], ids=["before-lock-sources", "after-checkout"])
    def test_bites_when_the_guard_moves(self, sat_data: dict[str, Any], swap: tuple[int, int]) -> None:
        def mutate(data: dict[str, Any]) -> None:
            steps = data["jobs"]["lint"]["steps"]
            first, second = swap
            steps[first], steps[second] = steps[second], steps[first]

        problems = self._problems_after(sat_data, mutate)
        expected = "job lint: the consumer-gate inputs guard is not the step right after the lock-sources guard"
        assert expected in problems, problems

    def test_bites_when_the_guard_scripts_differ(self, sat_data: dict[str, Any]) -> None:
        problems = self._problems_after(
            sat_data, lambda d: _guard_step(d, "lint").update(run=_guard_step(d, "lint")["run"] + "true\n")
        )
        assert "the inputs guard scripts of the candidate jobs differ" in problems

    def test_bites_when_a_candidate_step_keeps_the_old_condition(self, sat_data: dict[str, Any]) -> None:
        def mutate(data: dict[str, Any]) -> None:
            step = _step_named(data, "test", "Force-install candidate SDK wheel (consumer-gate)")
            step["if"] = "inputs.candidate_wheel_run_id != '' && inputs.candidate_sdk_name != ''"

        problems = self._problems_after(sat_data, mutate)
        assert any("Force-install candidate SDK wheel" in p and "does not run on" in p for p in problems), problems

    def test_bites_on_an_inline_candidate_input(self, sat_data: dict[str, Any]) -> None:
        def mutate(data: dict[str, Any]) -> None:
            step = _step_named(data, "lint", "Check formatting")
            step["run"] = 'echo "${{ inputs.candidate_sdk_version }}"\n' + step["run"]

        problems = self._problems_after(sat_data, mutate)
        assert any("inline in run" in p for p in problems), problems

    def test_bites_on_a_new_job_with_a_force_install(self, sat_data: dict[str, Any]) -> None:
        def mutate(data: dict[str, Any]) -> None:
            data["jobs"]["extra"] = copy.deepcopy(data["jobs"]["lint"])

        problems = self._problems_after(sat_data, mutate)
        assert any("extend the consumer-gate check" in p for p in problems), problems

    # --- R3: five more mutants. Each first asserts that its plant took. ---

    @staticmethod
    def _mutated(sat_data: dict[str, Any], mutate: Any) -> tuple[dict[str, Any], list[str]]:
        mutated = copy.deepcopy(sat_data)
        mutate(mutated)
        return mutated, consumer_gate_coverage_problems(mutated)

    @pytest.mark.parametrize("job_name", _CANDIDATE_JOBS)
    @pytest.mark.parametrize("tail", [" || true", "; true", " || exit 0"])
    def test_bites_when_the_re_read_swallows_its_exit(
        self, sat_data: dict[str, Any], job_name: str, tail: str
    ) -> None:
        def mutate(data: dict[str, Any]) -> None:
            step = _step_named(data, job_name, _REREAD_STEP)
            step["run"] = step["run"] + tail

        mutated, problems = self._mutated(sat_data, mutate)
        assert _step_named(mutated, job_name, _REREAD_STEP)["run"].endswith(tail)
        assert any(f"job {job_name}: no re-read" in p for p in problems), problems

    @pytest.mark.parametrize(
        "job_name,step_name",
        [
            ("lint", _INSTALL_STEP),
            ("test", _INSTALL_STEP),
            ("test", _PYTEST_STEP),
            ("lint", _REREAD_STEP),
            ("test", _REREAD_STEP),
        ],
    )
    def test_bites_on_continue_on_error(self, sat_data: dict[str, Any], job_name: str, step_name: str) -> None:
        mutated, problems = self._mutated(
            sat_data, lambda d: _step_named(d, job_name, step_name).update({"continue-on-error": True})
        )
        assert _step_named(mutated, job_name, step_name)["continue-on-error"] is True
        assert any(step_name in p and "continue-on-error" in p for p in problems), problems

    @pytest.mark.parametrize(
        "condition", ["always()", "inputs.test_splits > 0", "steps.consumer-gate-guard.outputs.mode != 'candidate'"]
    )
    def test_bites_on_an_if_on_the_pytest_step(self, sat_data: dict[str, Any], condition: str) -> None:
        mutated, problems = self._mutated(
            sat_data, lambda d: _step_named(d, "test", _PYTEST_STEP).update({"if": condition})
        )
        assert _step_named(mutated, "test", _PYTEST_STEP)["if"] == condition
        assert any(_PYTEST_STEP in p and "has an if:" in p for p in problems), problems

    @pytest.mark.parametrize(
        "job_name,script",
        [
            ("lint", "uv venv --clear .venv"),
            ("test", "uv venv"),
            ("lint", "pip install dummy-sdk==1.0.0"),
            ("test", "python -m pip install --force-reinstall dummy-sdk==1.0.0"),
            ("test", '"$RUNNER_TEMP/venv/bin/pip" install dummy-sdk==1.0.0'),
            ("lint", "pip3 uninstall -y dummy-sdk"),
        ],
    )
    def test_bites_on_uv_venv_and_plain_pip(self, sat_data: dict[str, Any], job_name: str, script: str) -> None:
        anchor = "Check formatting" if job_name == "lint" else _PYTEST_STEP

        def mutate(data: dict[str, Any]) -> None:
            data["jobs"][job_name]["steps"].insert(
                _step_index(data, job_name, anchor), {"name": "Planted", "run": script}
            )

        mutated, problems = self._mutated(sat_data, mutate)
        assert _step_named(mutated, job_name, "Planted")["run"] == script
        assert _step_index(mutated, job_name, "Planted") > _step_index(mutated, job_name, _INSTALL_STEP)
        assert any("Planted" in p and "changes the environment" in p for p in problems), problems

    @pytest.mark.parametrize(
        "job_name,step_name,old,new",
        [
            ("lint", "Check formatting", "uv run --no-sources ruff", "uv run \\\n  --with ruff --no-sources ruff"),
            ("test", _PYTEST_STEP, "uv run --no-sources pytest", "uv run \\\n    --isolated --no-sources pytest"),
            ("test", _PYTEST_STEP, "uv run --no-sources pytest", "uv run --no-sources \\\n    --python 3.13 pytest"),
        ],
    )
    def test_bites_on_flags_after_a_line_continuation(
        self, sat_data: dict[str, Any], job_name: str, step_name: str, old: str, new: str
    ) -> None:
        def mutate(data: dict[str, Any]) -> None:
            step = _step_named(data, job_name, step_name)
            step["run"] = step["run"].replace(old, new, 1)

        mutated, problems = self._mutated(sat_data, mutate)
        assert new in _step_named(mutated, job_name, step_name)["run"]
        assert any(step_name in p and "which this check does not cover" in p for p in problems), problems

    def test_a_clean_line_continuation_is_not_a_problem(self, sat_data: dict[str, Any]) -> None:
        """The other side: a continuation with only covered flags passes, and keeps the plugin."""
        new = "uv run \\\n    --no-sources pytest"

        def mutate(data: dict[str, Any]) -> None:
            step = _step_named(data, "test", _PYTEST_STEP)
            step["run"] = step["run"].replace("uv run --no-sources pytest", new)

        mutated, problems = self._mutated(sat_data, mutate)
        assert _step_named(mutated, "test", _PYTEST_STEP)["run"].count(new) == 2
        assert problems == []


# --- the step scripts themselves, run with bash ------------------------------


def _bash() -> str:
    found = shutil.which("bash")
    if found is None:
        pytest.skip("bash is not on PATH")
    return found


def _shim_dir(tmp_path: Path, python3_works: bool) -> Path:
    """A bin folder whose python3 is this interpreter, or one that exits 97."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    shim = bin_dir / "python3"
    if python3_works:
        shim.symlink_to(sys.executable)
    else:
        shim.write_text("#!/bin/sh\nexit 97\n", encoding="utf-8")
        shim.chmod(0o755)
    return bin_dir


def _run_guard(
    tmp_path: Path, values: dict[str, str], *, python3_works: bool = True
) -> tuple[int, str, Path]:
    data = _load_workflow(_SAT_CI_PATH)
    script = str(_guard_step(data, "lint")["run"])
    runner_temp = tmp_path / "runner-temp"
    runner_temp.mkdir()
    output = tmp_path / "github-output"
    output.write_text("", encoding="utf-8")
    env = {key: value for key, value in os.environ.items() if not key.startswith("CONSUMER_GATE_")}
    env.update({key: "" for key in _GUARD_ENV})
    env.update(values)
    env.update(
        GITHUB_OUTPUT=str(output),
        RUNNER_TEMP=str(runner_temp),
        PATH=os.pathsep.join([str(_shim_dir(tmp_path, python3_works)), env.get("PATH", "")]),
    )
    result = subprocess.run(
        [_bash(), "--noprofile", "--norc", "-e", "-o", "pipefail", "-c", script],
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    return result.returncode, output.read_text(encoding="utf-8"), runner_temp


_SET_INPUTS = {
    "CONSUMER_GATE_SDK_NAME": "autom8y-auth",
    "CONSUMER_GATE_SDK_VERSION": "4.4.1",
    "CONSUMER_GATE_WHEEL_RUN_ID": "1234567",
    "CONSUMER_GATE_CORRELATION_ID": "1b4e28ba-2fa1-11d2-883f-0016d3cca427",
}


class TestConsumerGateGuardScript:
    """S-126 B4: the guard step's script, exactly as the workflow holds it, run with bash."""

    def test_all_empty_is_normal_ci_and_calls_no_python(self, tmp_path: Path) -> None:
        # python3 here exits 97, so a guard that called Python in normal CI would fail.
        code, output, runner_temp = _run_guard(tmp_path, {}, python3_works=False)
        assert code == 0
        assert output == "mode=none\n"
        assert not (runner_temp / "consumer-gate").exists()

    def test_whitespace_only_counts_as_empty(self, tmp_path: Path) -> None:
        values = {key: " \t" for key in _SET_INPUTS}
        code, output, _ = _run_guard(tmp_path, values, python3_works=False)
        assert (code, output) == (0, "mode=none\n")

    @pytest.mark.parametrize("set_keys", [
        ("CONSUMER_GATE_SDK_NAME",),
        ("CONSUMER_GATE_SDK_NAME", "CONSUMER_GATE_WHEEL_RUN_ID"),
        ("CONSUMER_GATE_SDK_NAME", "CONSUMER_GATE_SDK_VERSION", "CONSUMER_GATE_WHEEL_RUN_ID"),
        ("CONSUMER_GATE_CORRELATION_ID",),
    ])
    def test_partial_inputs_fail(self, tmp_path: Path, set_keys: tuple[str, ...]) -> None:
        code, output, _ = _run_guard(tmp_path, {key: _SET_INPUTS[key] for key in set_keys})
        assert code == 1
        assert "mode=" not in output

    def test_three_set_and_one_whitespace_fails(self, tmp_path: Path) -> None:
        code, output, _ = _run_guard(tmp_path, dict(_SET_INPUTS, CONSUMER_GATE_CORRELATION_ID="  "))
        assert code == 1
        assert "mode=" not in output

    def test_all_four_set_is_candidate_mode_and_writes_the_helper(self, tmp_path: Path) -> None:
        code, output, runner_temp = _run_guard(tmp_path, dict(_SET_INPUTS))
        assert code == 0
        assert output == "mode=candidate\n"
        written = runner_temp / "consumer-gate" / "consumer_gate_candidate.py"
        assert written.read_text(encoding="utf-8") == HELPER_PATH.read_text(encoding="utf-8")

    @pytest.mark.parametrize("key,value", [
        ("CONSUMER_GATE_WHEEL_RUN_ID", "run-1"),
        ("CONSUMER_GATE_SDK_VERSION", "latest"),
        ("CONSUMER_GATE_SDK_NAME", "autom8y auth"),
    ])
    def test_all_set_but_malformed_fails(self, tmp_path: Path, key: str, value: str) -> None:
        code, output, _ = _run_guard(tmp_path, dict(_SET_INPUTS, **{key: value}))
        assert code == 1
        assert "mode=" not in output


def _pytest_step_argv(tmp_path: Path, mode: str, splits: str) -> tuple[list[str], str]:
    """Run the test job's pytest step with a stub uv; return uv's argv and its PYTHONPATH."""
    data = _load_workflow(_SAT_CI_PATH)
    script = str(_step_named(data, "test", "Run tests with coverage")["run"])
    args = "tests/ -m 'not integration' -v --cov=pkg"
    script = script.replace("${{ steps.pytest-args.outputs.args }}", args)
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    stub = bin_dir / "uv"
    stub.write_text(
        '#!/bin/sh\nfor arg in "$@"; do printf \'%s\\n\' "$arg"; done > "$STUB_ARGV"\n'
        'printf \'%s\' "${PYTHONPATH:-}" > "$STUB_PYTHONPATH"\n',
        encoding="utf-8",
    )
    stub.chmod(0o755)
    argv_file = tmp_path / "argv"
    pythonpath_file = tmp_path / "pythonpath"
    env = {key: value for key, value in os.environ.items() if key != "PYTHONPATH"}
    env.update(
        PATH=os.pathsep.join([str(bin_dir), env.get("PATH", "")]),
        TEST_SPLITS=splits,
        CONSUMER_GATE_MODE=mode,
        RUNNER_TEMP="/runner-temp",
        STUB_ARGV=str(argv_file),
        STUB_PYTHONPATH=str(pythonpath_file),
    )
    result = subprocess.run(
        [_bash(), "--noprofile", "--norc", "-e", "-o", "pipefail", "-c", script],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    return argv_file.read_text(encoding="utf-8").splitlines(), pythonpath_file.read_text(encoding="utf-8")


class TestConsumerGatePytestStep:
    """S-126 B2 and the normal-CI promise: pytest's arguments change only on candidate runs."""

    _BASE = ["run", "--no-sources", "pytest", "tests/", "-m", "not integration", "-v", "--cov=pkg"]

    @pytest.mark.parametrize("splits", ["1", "2"])
    def test_normal_ci_argv_and_pythonpath_are_unchanged(self, tmp_path: Path, splits: str) -> None:
        argv, pythonpath = _pytest_step_argv(tmp_path, "none", splits)
        assert argv == self._BASE
        assert pythonpath == ""

    @pytest.mark.parametrize("splits", ["1", "2"])
    def test_candidate_run_loads_the_plugin_on_the_command_line(self, tmp_path: Path, splits: str) -> None:
        argv, pythonpath = _pytest_step_argv(tmp_path, "candidate", splits)
        assert argv == self._BASE[:3] + ["-p", "consumer_gate_candidate"] + self._BASE[3:]
        assert pythonpath == "/runner-temp/consumer-gate"
