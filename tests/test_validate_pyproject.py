"""Unit tests for fleet-conformance-gate validator (validate_pyproject.py).

Focus: AC-EXEC-1 coverage of the field-keyed ADR-exemption plumbing added to
`validate_project` — specifically the `project.adr_exempt_upper_bound` path
that suppresses the categorical `no_upper_bound` rejection for ADR-cited
repos. Preserves the categorical-default path for repos WITHOUT exemption
metadata.

Per the Path-A selection ADR + SCAR-PYPROJ-001 citation chain:
- 5 CEILED repos (ads, asana, data, scheduling, sms) carry `>=3.12,<3.14`
  and must WARN-pass once the field-keyed exemption is honored.
- Repos without exemption metadata must continue to FAIL on upper-bound
  ceilings (default behavior unchanged).
- The validator treats `adr_id` as an opaque provenance token; it does NOT
  parse ADR content (FLAG-A1 mitigation: cite-by-reference).
"""
from __future__ import annotations

import sys
from pathlib import Path

# Import validator module directly from the action's directory.
ACTION_DIR = Path(__file__).resolve().parent.parent / ".github" / "actions" / "fleet-conformance-gate"
sys.path.insert(0, str(ACTION_DIR))

from validate_pyproject import validate_project  # noqa: E402


# --- Fixtures ---

PROJECT_SPEC = {
    "requires_python_floor": ">=3.12",
    "no_upper_bound": True,
}


def _pyproject_with(requires_python: str) -> dict:
    return {"project": {"requires-python": requires_python}}


# --- Categorical-default path (behavior unchanged) ---

def test_no_exemption_open_ceiling_passes():
    """Open ceiling '>=3.12' passes for a repo with no exemption metadata."""
    result = validate_project(_pyproject_with(">=3.12"), PROJECT_SPEC, None)
    assert result.status == "PASS"
    assert "3.12" in result.message


def test_no_exemption_closed_ceiling_fails():
    """Closed ceiling '>=3.12,<3.14' FAILS for a repo with no exemption metadata.

    This is the SCAR-PYPROJ-001 categorical rule operating as designed for
    non-ADR-exempted repos.
    """
    result = validate_project(_pyproject_with(">=3.12,<3.14"), PROJECT_SPEC, None)
    assert result.status == "FAIL"
    assert "upper bound" in result.message


def test_empty_exemption_dict_closed_ceiling_fails():
    """An exemption dict without `project` key still FAILS on closed ceiling.

    Guards against false-positive suppression when exemption metadata is
    unrelated (e.g., coverage-only exemption for a repo).
    """
    result = validate_project(_pyproject_with(">=3.12,<3.14"), PROJECT_SPEC, {"coverage": {"fail_under_floor": 70}})
    assert result.status == "FAIL"
    assert "upper bound" in result.message


def test_project_exemption_without_adr_field_fails():
    """Exemption with `project` key but no `adr_exempt_upper_bound` still FAILS.

    The exemption plumbing must require explicit ADR citation to activate;
    bare `project: {}` is not enough.
    """
    result = validate_project(_pyproject_with(">=3.12,<3.14"), PROJECT_SPEC, {"project": {}})
    assert result.status == "FAIL"
    assert "upper bound" in result.message


def test_floor_violation_fails_even_with_exemption():
    """Floor-below-minimum FAILS regardless of ADR exemption.

    The ADR exemption is scoped to `no_upper_bound` ONLY; floor protection is
    unaffected.
    """
    exemption = {"project": {"adr_exempt_upper_bound": {"adr_id": "ADR-ANCHOR-001", "field": "requires-python"}}}
    result = validate_project(_pyproject_with(">=3.11,<3.14"), PROJECT_SPEC, exemption)
    assert result.status == "FAIL"
    assert "floor" in result.message or "below" in result.message


# --- Exemption-consumption path (new behavior) ---

def test_adr_exemption_closed_ceiling_warns():
    """Closed ceiling '>=3.12,<3.14' WARN-passes when ADR exemption cites requires-python.

    This is the Path-A target: the 5 CEILED repos (ads/asana/data/scheduling/
    sms) carry `>=3.12,<3.14` per SCAR-PYPROJ-001 and cite ADR-ANCHOR-001.
    The validator suppresses the categorical rejection and emits WARN with
    provenance details.
    """
    exemption = {"project": {"adr_exempt_upper_bound": {"adr_id": "ADR-ANCHOR-001", "field": "requires-python"}}}
    result = validate_project(_pyproject_with(">=3.12,<3.14"), PROJECT_SPEC, exemption)
    assert result.status == "WARN"
    assert "ADR-ANCHOR-001" in result.message
    assert result.details.get("adr_id") == "ADR-ANCHOR-001"
    assert result.details.get("field") == "requires-python"


def test_adr_exemption_open_ceiling_passes():
    """Open ceiling still PASSes when ADR exemption is present (no upper bound
    to suppress). Exemption metadata is inert on non-ceiled repos.
    """
    exemption = {"project": {"adr_exempt_upper_bound": {"adr_id": "ADR-ANCHOR-001", "field": "requires-python"}}}
    result = validate_project(_pyproject_with(">=3.12"), PROJECT_SPEC, exemption)
    assert result.status == "PASS"


def test_adr_exemption_wrong_field_does_not_suppress():
    """Exemption scoped to a different field does NOT suppress the upper-bound
    rejection. FLAG-A1 mitigation: the `field` value is the load-bearing scope
    gate; mismatched fields fall through to categorical behavior.
    """
    exemption = {"project": {"adr_exempt_upper_bound": {"adr_id": "ADR-ANCHOR-001", "field": "some-other-field"}}}
    result = validate_project(_pyproject_with(">=3.12,<3.14"), PROJECT_SPEC, exemption)
    assert result.status == "FAIL"
    assert "upper bound" in result.message


def test_adr_exemption_opaque_adr_id_token():
    """Validator treats `adr_id` as an opaque token; any non-empty string
    activates the exemption (content is NOT parsed). FLAG-A1: cite-by-reference,
    not ADR-embedding. The adr_id string is stamped into the WARN result for
    auditability but is not validated against an ADR registry.
    """
    exemption = {"project": {"adr_exempt_upper_bound": {"adr_id": "ADR-FUTURE-999", "field": "requires-python"}}}
    result = validate_project(_pyproject_with(">=3.12,<3.14"), PROJECT_SPEC, exemption)
    assert result.status == "WARN"
    assert "ADR-FUTURE-999" in result.message
