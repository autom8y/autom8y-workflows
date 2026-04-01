# Contributing to autom8y-workflows

Reusable GitHub Actions workflows for the autom8y organization.
This is a workflows-only repo — not a library. The guidance here is for the autom8y team.

## Release Protocol

### Versioning

This repo uses [semantic versioning](https://semver.org/). Tags are the release mechanism.

- **PATCH** (`v1.0.1`): Non-breaking fixes (bug in a job step, dependency pin update).
- **MINOR** (`v1.1.0`): New optional inputs or jobs that do not affect existing callers.
- **MAJOR** (`v2.0.0`): Any change that requires callers to update their workflow ref or inputs.

### Who Can Tag

Any autom8y team member with write access to this repo. Tag after PR merges to `main`.

```bash
git tag -a v1.0.0 -m "Release v1.0.0"
git push origin v1.0.0
```

Use annotated tags (`-a`), not lightweight tags.

### CHANGELOG Requirement

Every release tag must have a corresponding GitHub Release entry with a changelog.
At minimum, list: what changed, whether it is breaking, and which satellite repos are affected.
Use the tag push to draft the GitHub Release via the GitHub UI or `gh release create`.

## Breaking-Change Notification

1. **Label the PR**: add the `breaking-change` label before merging.
2. **GitHub Release notes**: describe exactly what callers must change (input rename, removal, new required input).
3. **Version comment in workflow refs**: satellite repos pin to a SHA with a version comment:
   ```yaml
   uses: autom8y/autom8y-workflows/.github/workflows/satellite-ci-reusable.yml@<sha> # v2.0.0
   ```
   The version comment is the signal to reviewers that a pin update is intentional.
4. **Notify via PR or issue** in affected satellite repos when a breaking version is tagged.

## PR Workflow

- All changes require a PR. Direct pushes to `main` are not permitted.
- CI must pass before merge: **actionlint** (workflow syntax) and **zizmor** (security audit).
- PR titles follow the conventional commit format: `feat:`, `fix:`, `chore:`, etc.
- Squash merge is preferred to keep `main` history linear.

## Pin Update Notification

When a new version is tagged, satellite repos should update their SHA pin.

**What to update** (in each satellite's `.github/workflows/test.yml`):
```yaml
# Before
uses: autom8y/autom8y-workflows/...@<old-sha> # v1.0.0

# After
uses: autom8y/autom8y-workflows/...@<new-sha> # v1.1.0
```

**How to find the new SHA**:
```bash
git -C /path/to/autom8y-workflows rev-parse v1.1.0
```

Pin updates for non-breaking releases can be batched. Breaking releases should be treated
as blocking — update satellite repos before the old major version becomes unsupported.
