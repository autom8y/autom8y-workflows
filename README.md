# autom8y-workflows

Reusable GitHub Actions workflows for the [autom8y](https://github.com/autom8y) organization.

## Workflows

### satellite-ci-reusable.yml

Centralized CI pipeline for satellite repositories. Provides lint, test, and integration jobs with OIDC-based CodeArtifact access.

**Usage** (in a satellite's `.github/workflows/test.yml`):

```yaml
jobs:
  ci:
    permissions:
      id-token: write    # Required: OIDC for CodeArtifact
      contents: read
    uses: autom8y/autom8y-workflows/.github/workflows/satellite-ci-reusable.yml@76a166219aa18e95b5bb0b57bf5075802f529c02 # v1.0.0
    with:
      mypy_targets: 'src/autom8_example'
      coverage_package: 'autom8_example'
    # No secrets block: see "Consumer-Gate Cross-Repo Artifact Token" below.
```

See the workflow file header for the full list of configurable inputs.

## Important: This Repository Must Remain Public

GitHub Actions enforces a hard constraint: **public repositories cannot call reusable workflows from private repositories**. This repository exists specifically to host workflows that are callable by both public and private satellite repos in the autom8y org.

**Do not make this repository private.** Doing so will immediately break CI for all satellite repositories that reference workflows hosted here.

## Actions Permissions

This repository's Actions access level is set to `organization`, allowing any repository within the `autom8y` GitHub organization to call its reusable workflows.

## Consumer-Gate Cross-Repo Artifact Token

The `lint` and `test` jobs in `satellite-ci-reusable.yml` test a candidate
SDK wheel when the satellite is invoked through the consumer-gate path (see
`sdk-publish-v2.yml` in `autom8y/autom8y`). The wheel is an artifact of a
run in `autom8y/autom8y`; the default `GITHUB_TOKEN` on a satellite run is
scoped only to the satellite repo and cannot authorize that cross-repo fetch
(the failure surfaces as "Not Found", a permission-denied masquerading as
404).

One job, `candidate-wheel`, mints a short-lived GitHub App installation
token via `actions/create-github-app-token` with
`owner: autom8y, repositories: autom8y, permission-actions: read`, fetches
the wheel with it, and re-uploads the wheel as an artifact of the same run.
`lint` and `test` download that same-run artifact with no token. The job
runs no caller code (no checkout, no uv), and it is the only job in any
reusable workflow here that reads the App pair.

**Operational requirements:**

- **The App pair**: `APP_ID` and `APP_PRIVATE_KEY` live in the satellite
  repository's environment `ci-main-keys`, whose deployment branches are
  limited to main. `candidate-wheel` names that environment; no other job
  needs the pair, so the caller passes no `secrets:` block.
- **The environment subject rule**: naming an environment changes a job's
  OIDC subject to the environment form. So `candidate-wheel` holds no
  `id-token` permission and no cloud-role step, and no job that assumes a
  cloud role names an environment. `tests/test_ci_main_keys_guard.py`
  enforces both rules for every reusable workflow in this repository.
- **App installation**: The GitHub App must be installed on
  `autom8y/autom8y` with **Actions: Read** permission. Without this
  installation the `create-github-app-token` step fails at token
  generation (before the download step).
- **Token lifetime**: Installation tokens auto-expire after 1 hour; no
  manual rotation is required. The token is minted fresh on every run.
- **Blast radius**: A token leak would expose read-only access to
  `autom8y/autom8y` Actions artifacts only. No write, no other repos.

**When this token is NOT minted**: `candidate-wheel` runs only on a
`workflow_dispatch` at the caller's default branch with
`candidate_wheel_run_id` set, and it mints only after its check that all
four candidate inputs are set together. On every push and pull request it
is skipped, so push/pull_request-triggered satellite CI (the 99% case) never
mints the token. Only consumer-gate dispatches from `sdk-publish-v2.yml`
exercise this path.
