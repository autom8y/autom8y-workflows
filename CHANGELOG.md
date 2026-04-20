# Changelog

All notable changes to autom8y-workflows will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Documented
- **Opt-out from fleet env/secret platformization initiative** (FLEET-workflows, Wave 3).
  `autom8y-workflows` has no runtime env surface: no `.envrc`, no `.env/` dir, no
  `secretspec.toml`, no CLI/service entrypoint. `pyproject.toml` is scoped to the
  YAML-validation test harness only. The 6-layer env loader and `secretspec` profile
  contracts are not load-bearing here. Opt-out rationale and reversibility triggers
  documented in session-local `.know/opt-out-env-secret-platformization.md`
  (gitignored by infra convention). Source handoff:
  `autom8y-asana/.ledge/reviews/HANDOFF-hygiene-asana-to-hygiene-fleet-2026-04-20.md`.

## [1.0.0] - 2026-04-19

### Added
- `test_timeout` input to reusable workflow (`006dc3f`) — prevents unbounded shard hangs
- GitHub App token for cross-repo artifact download in satellite CI (`47bd968`) — resolves OIDC permission failures on governance repo checkout
- GitHub App token for governance repo checkout in test job (`edbc4d2`)
- `conformance-gate` job added to `satellite-ci-reusable.yml` [CHANGE-004] — blocks PRs missing fleet-standard pyproject/ruff config
- `fleet-conformance-gate` composite action [CHANGE-003]
- `validate_pyproject.py` fleet gate script [CHANGE-002]
- `fleet-conformance-spec.yml` conformance specification [CHANGE-001]
- 129 workflow validation tests (`RG-017`)
- `configspec`/`secretspec` validation gate to satellite CI (tectonic)

### Changed
- Spectral lint set to `--fail-severity=error` (warnings no longer fail CI — R-01 escalation compatible)
- Satellite CI permissions hardened, DENYLIST deduplicated, template secrets fixed

### Added (earlier)
- `satellite-ci-reusable.yml` reusable workflow for fleet CI standardization
- `test_splits` input for `pytest-split` sharding [Sprint2-FR1]
- `test_dist_strategy` input for xdist distribution override
