"""Guard: the App pair and a cloud role never share a job.

The App pair lives in each caller repository's environment ci-main-keys,
whose deployment branches H-21 limits to main. Naming an environment changes
a job's OIDC subject to the environment form, so a job that holds the pair
must never also mint an OIDC token or assume a cloud role, and a job that
assumes a role must name no environment. Work that needs both splits into a
key job and a role job, joined by needs.

Every job of every workflow in .github/workflows that declares
on.workflow_call is checked against two rules.

Rule 1. A job that references the App pair names `environment: ci-main-keys`.
A job references the pair when:
- an expression in the job, or in the workflow-level env every job inherits,
  reads APP_ID or APP_PRIVATE_KEY from the secrets context (in any case);
- an expression reads the secrets context wholesale or by a computed name:
  toJSON(secrets), secrets[...], secrets.* or a bare `secrets`;
- any key or value in that scope names APP_ID or APP_PRIVATE_KEY (an env
  alias named after the pair, for example);
- a step mints with actions/create-github-app-token, whatever it passes;
- the job passes `secrets: inherit` on to a called workflow.

Rule 2. A job that names any environment holds no id-token and no role.
It is treated as holding id-token when:
- it has no job-level permissions key (a called job then inherits the
  caller's grant, and callers grant id-token: write to the calling job);
- its permissions are not an explicit mapping (write-all, read-all), or they
  grant id-token: write;
- the workflow has a workflow-level permissions block;
- any key or value in the job uses ACTIONS_ID_TOKEN_REQUEST_URL (or _TOKEN),
  sts assume-role-with-web-identity, AssumeRoleWithWebIdentity or getIDToken.
It is treated as holding a role when:
- any key or value in the job names role-to-assume, or a step uses a cloud
  login action (aws-actions/configure-aws-credentials,
  google-github-actions/auth, azure/login);
- it nests a uses that may hold a role: a job-level uses (a called workflow),
  a local ./ action (in a called workflow it resolves in the caller's
  workspace, so it cannot be checked here), or an autom8y-workflows action
  whose action file here holds a role marker or cannot be read.

The checks read the parsed YAML, so comments never count. The four broken
fixtures in tests/fixtures/ci_main_keys_guard/ must each turn the guard red,
and every real reusable workflow must pass.
"""

from __future__ import annotations

import copy
import re
from pathlib import Path
from typing import Any, Iterator

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
WORKFLOWS_DIR = REPO_ROOT / ".github" / "workflows"
FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures" / "ci_main_keys_guard"
SATELLITE = WORKFLOWS_DIR / "satellite-ci-reusable.yml"

KEY_ENVIRONMENT = "ci-main-keys"
PAIR_NAMES = ("APP_ID", "APP_PRIVATE_KEY")
MINT_ACTION = "actions/create-github-app-token"
CLOUD_LOGIN_ACTIONS = (
    "aws-actions/configure-aws-credentials",
    "google-github-actions/auth",
    "azure/login",
)
THIS_REPOSITORY = "autom8y/autom8y-workflows"

_PAIR_NAME_RE = re.compile(r"(?<![A-Za-z0-9_])(?:APP_ID|APP_PRIVATE_KEY)(?![A-Za-z0-9_])", re.IGNORECASE)
_EXPRESSION_RE = re.compile(r"\$\{\{(.*?)\}\}", re.DOTALL)
_STRING_LITERAL_RE = re.compile(r"'(?:[^']|'')*'")
_SECRETS_CONTEXT_RE = re.compile(r"(?<![A-Za-z0-9_.-])secrets(?![A-Za-z0-9_-])", re.IGNORECASE)
_NAMED_ACCESS_RE = re.compile(r"\s*\.\s*([A-Za-z_][A-Za-z0-9_-]*)")
_WILDCARD_ACCESS_RE = re.compile(r"\s*\.\s*\*")
_INDEX_ACCESS_RE = re.compile(r"\s*\[")
_ID_TOKEN_RE = re.compile(
    r"ACTIONS_ID_TOKEN_REQUEST_(?:URL|TOKEN)|assume-role-with-web-identity|AssumeRoleWithWebIdentity|getIDToken",
    re.IGNORECASE,
)
_ROLE_RE = re.compile(r"role-to-assume", re.IGNORECASE)


# ---------------------------------------------------------------------------
# The guard
# ---------------------------------------------------------------------------


def _load(path: Path) -> dict[str, Any]:
    with open(path, encoding="utf-8") as handle:
        data = yaml.safe_load(handle)
    assert isinstance(data, dict), f"{path.name} is not a YAML mapping"
    return data


def declares_workflow_call(workflow: dict[str, Any]) -> bool:
    """True when on: names workflow_call, in string, list or mapping form.

    PyYAML reads the bare key `on` as the boolean True, so both keys are read.
    """
    triggers = workflow.get("on", workflow.get(True))
    if isinstance(triggers, str):
        return triggers == "workflow_call"
    if isinstance(triggers, (list, dict)):
        return "workflow_call" in triggers
    return False


def _walk(node: Any, key: str | None = None) -> Iterator[tuple[str | None, str, bool]]:
    """Yield (parent key, text, is_key) for every mapping key and scalar under node."""
    if isinstance(node, dict):
        for child_key, child in node.items():
            yield key, str(child_key), True
            yield from _walk(child, str(child_key))
    elif isinstance(node, list):
        for child in node:
            yield from _walk(child, key)
    elif node is not None:
        yield key, str(node), False


def _expressions(key: str | None, text: str) -> list[str]:
    """The expression spans in a value; an if: value is an expression even without ${{ }}."""
    spans = [match.group(1) for match in _EXPRESSION_RE.finditer(text)]
    if key == "if" and "${{" not in text:
        spans.append(text)
    return spans


def secrets_reads(expression: str) -> list[str]:
    """How an expression reaches the App pair through the secrets context."""
    stripped = _STRING_LITERAL_RE.sub("''", expression)
    found: list[str] = []
    for match in _SECRETS_CONTEXT_RE.finditer(stripped):
        rest = stripped[match.end():]
        named = _NAMED_ACCESS_RE.match(rest)
        if named:
            if named.group(1).upper() in PAIR_NAMES:
                found.append(f"reads secrets.{named.group(1)}")
        elif _WILDCARD_ACCESS_RE.match(rest):
            found.append("reads secrets.* (every value)")
        elif _INDEX_ACCESS_RE.match(rest):
            found.append("reads secrets[...] (a computed name)")
        else:
            found.append("reads the whole secrets context, as toJSON(secrets) does")
    return found


def _steps(job: dict[str, Any]) -> list[dict[str, Any]]:
    steps = job.get("steps") or []
    return [step for step in steps if isinstance(step, dict)] if isinstance(steps, list) else []


def _action_name(uses: str) -> str:
    return uses.split("@", 1)[0].strip()


def pair_reasons(job: dict[str, Any], workflow: dict[str, Any]) -> list[str]:
    """Rule 1's evidence that a job references the App pair (empty when it does not)."""
    reasons: list[str] = []
    for scope, node in (("job", job), ("workflow env", workflow.get("env"))):
        for key, text, is_key in _walk(node):
            named = _PAIR_NAME_RE.search(text)
            if named:
                where = "a key" if is_key else f"the value of {key!r}"
                reasons.append(f"{scope}: {where} names {named.group(0)}")
            if not is_key:
                for expression in _expressions(key, text):
                    reasons.extend(f"{scope}: {reason}" for reason in secrets_reads(expression))
    for step in _steps(job):
        if _action_name(str(step.get("uses") or "")) == MINT_ACTION:
            reasons.append(f"a step mints with {MINT_ACTION}")
    if str(job.get("secrets", "")).strip() == "inherit":
        reasons.append("it passes secrets: inherit to a called workflow")
    return reasons


def environment_name(job: dict[str, Any]) -> str | None:
    """The environment a job names, or None. A mapping form names it under name:."""
    if "environment" not in job:
        return None
    environment = job["environment"]
    if isinstance(environment, dict):
        return str(environment.get("name"))
    return str(environment)


def _action_file_text(path: Path) -> str | None:
    for name in ("action.yml", "action.yaml"):
        candidate = path / name
        if candidate.is_file():
            return candidate.read_text(encoding="utf-8")
    return None


def _holds_role_marker(text: str) -> bool:
    return bool(_ROLE_RE.search(text) or _ID_TOKEN_RE.search(text)) or any(
        action in text for action in CLOUD_LOGIN_ACTIONS
    )


def id_token_or_role_reasons(
    job: dict[str, Any], workflow: dict[str, Any], repo_root: Path = REPO_ROOT
) -> list[str]:
    """Rule 2's evidence that a job holds id-token or a cloud role (empty when it holds neither)."""
    reasons: list[str] = []
    if "permissions" in workflow:
        reasons.append("the workflow has a workflow-level permissions block")
    if "permissions" not in job:
        reasons.append("it has no job-level permissions key, so it inherits the caller's grant")
    else:
        permissions = job["permissions"]
        if not isinstance(permissions, dict):
            reasons.append(f"its permissions are {permissions!r}, not an explicit mapping")
        elif str(permissions.get("id-token", "none")).strip().lower() == "write":
            reasons.append("its permissions grant id-token: write")
    for _key, text, _is_key in _walk(job):
        token = _ID_TOKEN_RE.search(text)
        if token:
            reasons.append(f"it requests an OIDC token ({token.group(0)})")
        if _ROLE_RE.search(text):
            reasons.append("it names role-to-assume")
    if "uses" in job:
        reasons.append(f"it calls a workflow ({job['uses']}), a nested uses whose role cannot be checked here")
    for step in _steps(job):
        uses = str(step.get("uses") or "").strip()
        if not uses:
            continue
        action = _action_name(uses)
        if any(action == login or action.startswith(login + "/") for login in CLOUD_LOGIN_ACTIONS):
            reasons.append(f"a step uses the cloud login action {action}")
        elif uses.startswith("./"):
            reasons.append(f"a step uses the local action {uses}, which resolves in the caller's workspace")
        elif action.lower().startswith(THIS_REPOSITORY + "/"):
            text = _action_file_text(repo_root / action[len(THIS_REPOSITORY) + 1:])
            if text is None:
                reasons.append(f"a step uses {uses}, whose action file cannot be read here")
            elif _holds_role_marker(text):
                reasons.append(f"a step uses {uses}, whose action file holds a role marker")
    return reasons


def guard_problems(workflow: dict[str, Any], label: str, repo_root: Path = REPO_ROOT) -> list[str]:
    """Every rule 1 and rule 2 violation in one workflow, one line each."""
    jobs = workflow.get("jobs")
    if not isinstance(jobs, dict) or not jobs:
        return [f"{label}: no jobs mapping to check"]
    problems: list[str] = []
    for name, job in jobs.items():
        where = f"{label}/{name}"
        if not isinstance(job, dict):
            problems.append(f"{where}: the job is not a mapping")
            continue
        environment = environment_name(job)
        if environment != KEY_ENVIRONMENT:
            for reason in pair_reasons(job, workflow):
                problems.append(
                    f"rule 1: {where} references the App pair but names environment "
                    f"{environment!r}, not {KEY_ENVIRONMENT!r}: {reason}"
                )
        if environment is not None:
            for reason in id_token_or_role_reasons(job, workflow, repo_root):
                problems.append(f"rule 2: {where} names environment {environment!r}, and {reason}")
    return problems


def reusable_workflow_paths() -> list[Path]:
    paths = sorted([*WORKFLOWS_DIR.glob("*.yml"), *WORKFLOWS_DIR.glob("*.yaml")])
    return [path for path in paths if declares_workflow_call(_load(path))]


REUSABLE = reusable_workflow_paths()


# ---------------------------------------------------------------------------
# The real files: GREEN, and not vacuously
# ---------------------------------------------------------------------------


class TestRealReusableWorkflows:
    @pytest.mark.parametrize("path", REUSABLE, ids=lambda p: p.stem)
    def test_passes_the_guard(self, path: Path) -> None:
        workflow = _load(path)
        problems = guard_problems(workflow, path.name)
        print(f"{'RED' if problems else 'GREEN'} {path.name}: {len(workflow['jobs'])} jobs, {len(problems)} problems")
        assert not problems, "\n".join(problems)

    def test_the_reusable_set_is_found(self) -> None:
        """Must-find control: the satellite reusable is in the checked set."""
        names = [path.name for path in REUSABLE]
        assert SATELLITE.name in names, names
        assert len(names) >= 6, names

    def test_the_rules_see_the_real_key_job_and_role_jobs(self) -> None:
        """Controls: the detectors fire on real content, so a pass is not vacuous."""
        workflow = _load(SATELLITE)
        jobs = workflow["jobs"]
        assert pair_reasons(jobs["candidate-wheel"], workflow), "rule 1 does not see the real mint"
        assert id_token_or_role_reasons(jobs["lint"], workflow), "rule 2 does not see lint's role"
        assert id_token_or_role_reasons(jobs["integration"], workflow), "rule 2 does not see integration's role"


class TestSatelliteShape:
    """Change 2's shape in the satellite reusable (gate G1)."""

    def test_candidate_wheel_is_the_only_job_naming_the_environment(self) -> None:
        jobs = _load(SATELLITE)["jobs"]
        named = sorted(name for name, job in jobs.items() if environment_name(job) is not None)
        assert named == ["candidate-wheel"], named
        assert environment_name(jobs["candidate-wheel"]) == KEY_ENVIRONMENT

    def test_candidate_wheel_is_the_only_job_referencing_the_pair(self) -> None:
        workflow = _load(SATELLITE)
        holders = sorted(name for name, job in workflow["jobs"].items() if pair_reasons(job, workflow))
        assert holders == ["candidate-wheel"], holders

    def test_candidate_wheel_holds_no_permission_and_no_role(self) -> None:
        workflow = _load(SATELLITE)
        job = workflow["jobs"]["candidate-wheel"]
        assert job["permissions"] == {}
        assert id_token_or_role_reasons(job, workflow) == []


# ---------------------------------------------------------------------------
# The four broken fixtures: each RED, on the rule it breaks
# ---------------------------------------------------------------------------

BROKEN_FIXTURES = [
    ("mint_in_pull_request_job.yml", "rule 1", "a step mints with actions/create-github-app-token"),
    ("pair_alias_through_job_variable.yml", "rule 1", "reads secrets.APP_PRIVATE_KEY"),
    ("main_keys_job_with_id_token_and_role.yml", "rule 2", "its permissions grant id-token: write"),
    ("main_keys_job_without_permissions.yml", "rule 2", "no job-level permissions key"),
]


class TestBrokenFixtures:
    def test_every_fixture_file_is_listed(self) -> None:
        on_disk = sorted(path.name for path in FIXTURES_DIR.glob("*.yml"))
        assert on_disk == sorted(name for name, _rule, _fragment in BROKEN_FIXTURES)

    @pytest.mark.parametrize(
        "fixture,rule,fragment",
        BROKEN_FIXTURES,
        ids=[name.removesuffix(".yml") for name, _rule, _fragment in BROKEN_FIXTURES],
    )
    def test_fixture_turns_the_guard_red(self, fixture: str, rule: str, fragment: str) -> None:
        workflow = _load(FIXTURES_DIR / fixture)
        assert declares_workflow_call(workflow), "the fixture must be in the guard's scope"
        problems = guard_problems(workflow, fixture)
        print(f"RED {fixture}: {len(problems)} problems", *problems, sep="\n  ")
        assert problems, f"{fixture} passed the guard"
        assert {problem.split(":", 1)[0] for problem in problems} == {rule}, problems
        assert any(fragment in problem for problem in problems), problems

    def test_the_id_token_fixture_also_shows_its_role_step(self) -> None:
        problems = guard_problems(_load(FIXTURES_DIR / "main_keys_job_with_id_token_and_role.yml"), "fixture 3")
        assert any("it names role-to-assume" in problem for problem in problems), problems
        assert any("aws-actions/configure-aws-credentials" in problem for problem in problems), problems


# ---------------------------------------------------------------------------
# Each hardened form bites, beside a clean control
# ---------------------------------------------------------------------------

_MINT_STEP = {
    "name": "Generate App token",
    "uses": "actions/create-github-app-token@bcd2ba49218906704ab6c1aa796996da409d3eb1",
    "with": {
        "app-id": "${{ secrets.APP_ID }}",
        "private-key": "${{ secrets.APP_PRIVATE_KEY }}",
        "owner": "autom8y",
        "repositories": "autom8y",
    },
}
_ROLE_STEP = {
    "name": "Configure AWS credentials (OIDC)",
    "uses": "aws-actions/configure-aws-credentials@e7f100cf4c008499ea8adda475de1042d6975c7b",
    "with": {
        "role-to-assume": "arn:aws:iam::${{ vars.AWS_ACCOUNT_ID }}:role/github-actions-ci-read",
        "aws-region": "us-east-1",
    },
}


def _workflow(**jobs: dict[str, Any]) -> dict[str, Any]:
    return {"name": "probe", True: {"workflow_call": None}, "jobs": jobs}


def _key_job() -> dict[str, Any]:
    return {
        "runs-on": "ubuntu-latest",
        "environment": KEY_ENVIRONMENT,
        "permissions": {},
        "steps": [copy.deepcopy(_MINT_STEP)],
    }


def _role_job() -> dict[str, Any]:
    return {
        "runs-on": "ubuntu-latest",
        "permissions": {"id-token": "write", "contents": "read"},
        "steps": [copy.deepcopy(_ROLE_STEP), {"run": "echo the word secrets in a script is not a read"}],
    }


def _plain_job(**extra: Any) -> dict[str, Any]:
    return {"runs-on": "ubuntu-latest", "permissions": {"contents": "read"}, "steps": [{"run": "true"}], **extra}


def _rules(workflow: dict[str, Any]) -> set[str]:
    return {problem.split(":", 1)[0] for problem in guard_problems(workflow, "probe")}


class TestControls:
    def test_a_clean_key_job_and_a_clean_role_job_pass(self) -> None:
        assert guard_problems(_workflow(key=_key_job(), role=_role_job()), "probe") == []

    def test_a_named_non_pair_value_needs_no_environment(self) -> None:
        job = _plain_job(env={"CODECOV": "${{ secrets.CODECOV_TOKEN }}"})
        job["steps"].append(
            {
                "uses": "actions/checkout@93cb6efe18208431cddfb8368fd83d5badbf9bfd",
                "with": {"token": "${{ secrets.GITHUB_TOKEN }}"},
            }
        )
        assert guard_problems(_workflow(plain=job), "probe") == []

    def test_a_quoted_literal_is_not_a_read(self) -> None:
        job = _plain_job()
        job["if"] = "contains(github.event.head_commit.message, 'secrets')"
        assert guard_problems(_workflow(plain=job), "probe") == []


_ANY_PIN = "@" + "0" * 40


def _mutate_key_job(change: Any) -> dict[str, Any]:
    workflow = _workflow(key=_key_job())
    change(workflow, workflow["jobs"]["key"])
    return workflow


def _add_step(step: dict[str, Any]) -> Any:
    return lambda wf, job: job["steps"].append(step)


# L-2: each of these counts as holding id-token or a role in a job that names an environment.
RULE_2_FORMS = {
    "write-all": lambda wf, job: job.update(permissions="write-all"),
    "read-all": lambda wf, job: job.update(permissions="read-all"),
    "explicit-id-token": lambda wf, job: job.update(permissions={"id-token": "write"}),
    "no-permissions-key": lambda wf, job: job.pop("permissions"),
    "workflow-level-block": lambda wf, job: wf.update(permissions={"contents": "read"}),
    "id-token-request-url": _add_step(
        {"run": 'curl -sH "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" "$ACTIONS_ID_TOKEN_REQUEST_URL"'}
    ),
    "sts-web-identity": _add_step(
        {"run": 'aws sts assume-role-with-web-identity --role-arn "$ROLE" --web-identity-token "$JWT"'}
    ),
    "github-script-id-token": _add_step(
        {"uses": "actions/github-script" + _ANY_PIN, "with": {"script": "await core.getIDToken()"}}
    ),
    "role-step": _add_step(copy.deepcopy(_ROLE_STEP)),
    "local-action": _add_step({"uses": "./.github/actions/anything"}),
    "unreadable-own-action": _add_step({"uses": "autom8y/autom8y-workflows/.github/actions/not-here" + _ANY_PIN}),
    "nested-workflow-call": lambda wf, job: job.update(uses="autom8y/autom8y-workflows/.github/workflows/x.yml@main"),
}


class TestRule2HardenedForms:
    @pytest.mark.parametrize("form", sorted(RULE_2_FORMS))
    def test_form_turns_rule_2_red(self, form: str) -> None:
        assert _rules(_mutate_key_job(RULE_2_FORMS[form])) == {"rule 2"}

    def test_an_own_action_without_a_role_passes(self) -> None:
        """Control for the nested-action check: this repository's conformance action holds no role."""
        workflow = _mutate_key_job(
            _add_step({"uses": "autom8y/autom8y-workflows/.github/actions/fleet-conformance-gate" + _ANY_PIN})
        )
        assert guard_problems(workflow, "probe") == []


# D6 rule 1 with L-2's wholesale forms: each references the pair in a job with no environment.
RULE_1_FORMS = {
    "mint-with-other-names": _add_step({"uses": MINT_ACTION + _ANY_PIN, "with": {"app-id": "${{ vars.OTHER }}"}}),
    "to-json": _add_step({"run": "echo done", "env": {"ALL": "${{ toJSON(secrets) }}"}}),
    "index": _add_step({"run": "true", "env": {"K": "${{ secrets[format('APP_{0}', 'ID')] }}"}}),
    "wildcard": _add_step({"run": "true", "env": {"K": "${{ join(secrets.*, ',') }}"}}),
    "lower-case-name": _add_step({"run": "true", "env": {"K": "${{ secrets.app_private_key }}"}}),
    "bare-in-if": _add_step({"run": "true", "if": "secrets != null"}),
    "alias-name-only": _add_step({"run": 'sign "$APP_PRIVATE_KEY"'}),
    "workflow-level-alias": lambda wf, job: wf.update(env={"SIGNER_PEM": "${{ secrets.APP_PRIVATE_KEY }}"}),
    "inherit-onward": lambda wf, job: job.update(
        uses="autom8y/autom8y-workflows/.github/workflows/x.yml@main", secrets="inherit"
    ),
}


class TestRule1Forms:
    @pytest.mark.parametrize("form", sorted(RULE_1_FORMS))
    def test_form_turns_rule_1_red_in_a_job_with_no_environment(self, form: str) -> None:
        workflow = _workflow(plain=_plain_job())
        RULE_1_FORMS[form](workflow, workflow["jobs"]["plain"])
        assert "rule 1" in _rules(workflow)

    @pytest.mark.parametrize("environment", [None, "production", {"name": "ci-main-keys-copy"}])
    def test_the_pair_outside_ci_main_keys_is_red(self, environment: Any) -> None:
        job = _key_job()
        if environment is None:
            job.pop("environment")
        else:
            job["environment"] = environment
        assert "rule 1" in _rules(_workflow(key=job))

    def test_the_mapping_form_of_the_environment_passes(self) -> None:
        job = _key_job()
        job["environment"] = {"name": KEY_ENVIRONMENT}
        assert guard_problems(_workflow(key=job), "probe") == []
