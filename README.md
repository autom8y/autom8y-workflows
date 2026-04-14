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
    secrets: inherit
```

See the workflow file header for the full list of configurable inputs.

## Important: This Repository Must Remain Public

GitHub Actions enforces a hard constraint: **public repositories cannot call reusable workflows from private repositories**. This repository exists specifically to host workflows that are callable by both public and private satellite repos in the autom8y org.

**Do not make this repository private.** Doing so will immediately break CI for all satellite repositories that reference workflows hosted here.

## Actions Permissions

This repository's Actions access level is set to `organization`, allowing any repository within the `autom8y` GitHub organization to call its reusable workflows.

## Consumer-Gate Cross-Repo Artifact Token

The `lint` and `test` jobs in `satellite-ci-reusable.yml` download a candidate
SDK wheel artifact from `autom8y/autom8y` when the satellite is invoked
through the consumer-gate path (see `sdk-publish-v2.yml` in `autom8y/autom8y`).
`actions/download-artifact@v4` requires `actions:read` on the source repo;
the default `GITHUB_TOKEN` on a satellite run is scoped only to the
satellite repo and cannot authorize the cross-repo fetch (the failure
surfaces as "Not Found", a permission-denied masquerading as 404).

To authorize this fetch, the workflow mints a short-lived GitHub App
installation token via `actions/create-github-app-token` with
`owner: autom8y, repositories: autom8y`. This token is scoped exclusively
to the `autom8y/autom8y` repo and used only for the single download step.

**Operational requirements:**

- **Secrets**: `APP_ID` and `APP_PRIVATE_KEY` must be available to the
  satellite repository (inherited via `secrets: inherit` from the satellite's
  caller). These are the same secrets already used by the
  `integration`, `convention-check`, `contract-tests`, and
  `fleet-schema-governance` jobs.
- **App installation**: The GitHub App must be installed on
  `autom8y/autom8y` with **Actions: Read** permission. Without this
  installation the `create-github-app-token` step fails at token
  generation (before the download step).
- **Token lifetime**: Installation tokens auto-expire after 1 hour; no
  manual rotation is required. The token is minted fresh on every run.
- **Blast radius**: A token leak would expose read-only access to
  `autom8y/autom8y` Actions artifacts only. No write, no other repos.

**When this token is NOT minted**: The `Generate App token` step is
guarded by `if: inputs.candidate_wheel_run_id != '' && inputs.candidate_sdk_name != ''`,
so push/pull_request-triggered satellite CI (the 99% case) never
attempts cross-repo auth and never mints the token. Only consumer-gate
dispatches from `sdk-publish-v2.yml` exercise this path.
