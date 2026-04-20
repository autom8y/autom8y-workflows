# Changelog

All notable changes to autom8y-workflows will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
