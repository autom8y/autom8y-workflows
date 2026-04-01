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
