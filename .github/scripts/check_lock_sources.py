#!/usr/bin/env python3
"""Check that every package in a uv.lock resolves from an expected host.

Usage:
    check_lock_sources.py UV_LOCK --repo OWNER/NAME --account ACCOUNT
                          [--allowlist-json JSON] [--account-sha256 HEX]

Inputs are argv only. The script reads NOTHING from the environment. In CI it is called
by run_lock_sources.py, from the lock-sources job of satellite-ci-reusable.yml or the
standalone lock-sources-required.yml; neither runs caller code. The runner passes:

* ``--repo``: the caller's ``github.repository`` (owner/name), the allowlist key.
* ``--account``: the 12-digit AWS account that owns the CodeArtifact domain, from
  ``vars.AWS_ACCOUNT_ID``. Exactly 12 ASCII digits; there is no default. The account is
  never written into this repository.
* ``--allowlist-json``: the ``repositories`` table of .github/lock-sources/policy.json,
  keyed by repository, each value ``{"registry_hosts": [...], "direct_hosts": [...]}``.
  An unknown key gets an empty allowlist, so only the CodeArtifact host passes.
  Default: ``{}``.
* ``--account-sha256`` (optional): 64 lowercase hex characters. When given, the sha256 of
  the account must equal it, or the script exits 3 with the fixed message "account does
  not match the pinned account hash; refusing" (it prints neither the passed value nor its
  hash). The runner passes policy.json's ``account_sha256``, which pins the account
  against a repository- or org-level variable change.

The CodeArtifact host is the fleet's one host rule (the propagator's A6-R1 rule with the
account pinned): ``autom8y-<ACCOUNT>.d.codeartifact.us-east-1.amazonaws.com``.

Rules, for EVERY ``[[package]]`` in the lock:

* The project's own package (the single entry whose source is ``editable = "."`` or
  ``virtual = "."``) and the non-autom8y names in ``[manifest] members`` (with a relative
  path that is not absolute and has no ``..`` segment) are exempt. The members exemption
  never admits an autom8y-* name (names are normalized first: ``-``, ``_`` and ``.`` are
  equivalent, and case is ignored). Every other editable, virtual, path or directory
  source fails, including an in-repo path such as ``vendor/x``.
* An autom8y-* package must have exactly ``{ registry = URL }`` on the CodeArtifact host:
  the registry URL under ``/pypi/autom8y-python/simple/`` and every sdist and wheel ``url``
  under ``/pypi/autom8y-python/``. A git or url source fails for autom8y-*.
* Any other registry package must be on the CodeArtifact host (same path rules) or on a
  host in the repository's ``registry_hosts``; so must every sdist and wheel ``url``.
* A ``git`` or ``url`` source fails unless its host is in the repository's
  ``direct_hosts``.
* An artifact recorded by ``path`` instead of ``url`` fails.

URL rule. Each URL is parsed with urllib.parse.urlsplit. Before any host is compared it is
refused for: a backslash anywhere; whitespace or a control character; a scheme other than
exactly ``https``; userinfo; an explicit port (any ``:`` in the authority); no host; a
trailing dot; a non-ASCII authority. The lowercased hostname must then fullmatch one
expected host exactly. On the CodeArtifact host the path must start with the prefix above
and may not carry a ``.`` or ``..`` segment or a percent-encoded dot, slash or backslash.
A query string or fragment fails, except on a git source (where uv records ``?rev=`` and
``#commit``).

Exit codes: 0 ok; 1 at least one violation; 2 vacuous (no autom8y-* registry package was
checked; for a repository whose row names registry hosts, no registry package at all was
checked) or a usage error (missing or malformed account, repository or pinned hash, bad
allowlist, unreadable or malformed lock, Python < 3.11); 3 the account does not match the
pinned account hash. Every line of output masks any run of 12 or more digits as ``<acct>``.

Python 3.11+ standard library only. No network.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from urllib.parse import urlsplit

NAME_PREFIX = "autom8y-"
HOST_TEMPLATE = "autom8y-{account}.d.codeartifact.us-east-1.amazonaws.com"
REGISTRY_PATH_PREFIX = "/pypi/autom8y-python/simple/"
ARTIFACT_PATH_PREFIX = "/pypi/autom8y-python/"

EXIT_OK = 0
EXIT_VIOLATION = 1
EXIT_USAGE = 2
EXIT_ACCOUNT_MISMATCH = 3
ACCOUNT_MISMATCH_MESSAGE = "account does not match the pinned account hash; refusing"

_ACCOUNT_RE = re.compile(r"[0-9]{12}", re.ASCII)
_MASK_RE = re.compile(r"\d{12,}")  # Unicode-aware on purpose: mask look-alike digits too
_NAME_SEP_RE = re.compile(r"[-_.]+")
_ENCODED_DOT_OR_SLASH_RE = re.compile(r"%(2e|2f|5c)", re.IGNORECASE)
_DRIVE_RE = re.compile(r"[A-Za-z]:")
_HOSTNAME_RE = re.compile(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+", re.ASCII)
_REPO_KEY_RE = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", re.ASCII)
_SHA256_RE = re.compile(r"[0-9a-f]{64}", re.ASCII)
_LOCAL_SOURCE_KINDS = ("editable", "virtual")
_DIRECT_SOURCE_KINDS = ("git", "url")


class UsageError(Exception):
    """A problem with the inputs (not the lock's sources); exits 2."""


@dataclass(frozen=True)
class Policy:
    ca_host: str
    registry_hosts: frozenset[str]
    direct_hosts: frozenset[str]


def mask(text: str) -> str:
    """Replace every run of 12 or more digits with ``<acct>``."""
    return _MASK_RE.sub("<acct>", text)


def emit(line: str, *, stream=None) -> None:
    print(mask(line), file=stream if stream is not None else sys.stdout)


def expected_host(account: str) -> str:
    if not _ACCOUNT_RE.fullmatch(account):
        raise ValueError("account must be exactly 12 ASCII digits")
    return HOST_TEMPLATE.format(account=account)


def normalize_name(name: str) -> str:
    """PEP 503 normalization, so ``Autom8y_Foo`` cannot slip past the prefix match."""
    return _NAME_SEP_RE.sub("-", name).lower()


def _host_list(value: object, where: str) -> frozenset[str]:
    if not isinstance(value, list) or not all(isinstance(h, str) for h in value):
        raise UsageError(f"{where} is not an array of host names")
    for host in value:
        if not _HOSTNAME_RE.fullmatch(host):
            raise UsageError(f"{where} has an entry that is not a lowercase ASCII host name: {host!r}")
    return frozenset(value)


def load_policy(account: str, repo: str, allowlist_json: str | None) -> Policy:
    """Build the policy for ``repo`` from the workflow-defined allowlist table."""
    ca_host = expected_host(account)
    if allowlist_json is None or not allowlist_json.strip():
        table: dict = {}
    else:
        try:
            table = json.loads(allowlist_json)
        except json.JSONDecodeError as exc:
            raise UsageError(f"--allowlist-json is not valid JSON ({exc.msg})") from None
    if not isinstance(table, dict):
        raise UsageError("--allowlist-json is not a JSON object")
    for key, entry in table.items():
        if not _REPO_KEY_RE.fullmatch(key):
            raise UsageError(f"--allowlist-json key {key!r} is not owner/name")
        if not isinstance(entry, dict) or set(entry) - {"registry_hosts", "direct_hosts"}:
            raise UsageError(f"--allowlist-json[{key!r}] must hold only registry_hosts and direct_hosts")
        _host_list(entry.get("registry_hosts", []), f"--allowlist-json[{key!r}].registry_hosts")
        _host_list(entry.get("direct_hosts", []), f"--allowlist-json[{key!r}].direct_hosts")
    entry = table.get(repo, {})  # an unknown or empty key gets an empty allowlist
    registry_hosts = _host_list(entry.get("registry_hosts", []), "registry_hosts")
    direct_hosts = _host_list(entry.get("direct_hosts", []), "direct_hosts")
    if ca_host in registry_hosts or ca_host in direct_hosts:
        raise UsageError("the CodeArtifact host must not be listed in the allowlist")
    return Policy(ca_host, registry_hosts, direct_hosts)


def url_violation(
    raw: object,
    hosts: Iterable[str],
    *,
    ca_host: str | None = None,
    ca_path_prefix: str = ARTIFACT_PATH_PREFIX,
    allow_query_fragment: bool = False,
) -> str | None:
    """Return why ``raw`` fails the URL rule, or None when it passes.

    ``hosts`` is the exact set of accepted host names. When the host is ``ca_host``, the
    CodeArtifact path rules apply with ``ca_path_prefix``.
    """
    if not isinstance(raw, str) or not raw:
        return "URL is missing or not a string"
    if "\\" in raw:
        return "URL contains a backslash"
    if any(ch.isspace() or ord(ch) < 0x20 or ord(ch) == 0x7F for ch in raw):
        return "URL contains whitespace or a control character"
    try:
        parts = urlsplit(raw)
    except ValueError as exc:
        return f"URL does not parse ({exc})"
    # urlsplit lowercases the scheme, so also require the literal prefix.
    if parts.scheme != "https" or not raw.startswith("https://"):
        return "scheme is not exactly https"
    netloc = parts.netloc
    if "@" in netloc or parts.username is not None or parts.password is not None:
        return "URL carries userinfo"
    if ":" in netloc:
        return "URL carries an explicit port"
    hostname = parts.hostname
    if not netloc or not hostname:
        return "URL has no host"
    if hostname.endswith("."):
        return "host has a trailing dot"
    # urlsplit lowercases with str.lower(), which folds some non-ASCII letters to ASCII
    # (the Kelvin sign becomes "k"), so refuse a non-ASCII authority before comparing.
    if not netloc.isascii():
        return "host is not ASCII (look-alike)"
    host = hostname.lower()
    if not any(re.fullmatch(re.escape(h), host, re.ASCII) for h in hosts):
        return f"host {hostname!r} is not an expected host for this repository"
    if not allow_query_fragment:
        if parts.query or "?" in raw:
            return "URL carries a query string"
        if parts.fragment or "#" in raw:
            return "URL carries a fragment"
    if ca_host is not None and host == ca_host:
        path = parts.path
        if not path.startswith(ca_path_prefix):
            return f"path does not start with {ca_path_prefix}"
        if any(segment in (".", "..") for segment in path.split("/")):
            return "path has a dot segment"
        if _ENCODED_DOT_OR_SLASH_RE.search(path):
            return "path has a percent-encoded dot, slash or backslash"
    return None


def _is_repo_relative(value: object) -> bool:
    if not isinstance(value, str) or not value:
        return False
    if value.startswith("/") or "\\" in value or _DRIVE_RE.match(value):
        return False
    return ".." not in value.split("/")


def _local_source(source: dict) -> tuple[str, object] | None:
    kinds = [kind for kind in _LOCAL_SOURCE_KINDS if kind in source]
    if not kinds:
        return None
    return kinds[0], source[kinds[0]]


def manifest_members(lock: dict) -> tuple[frozenset[str], list[str]]:
    """Normalized names from ``[manifest] members``, and any shape problems."""
    manifest = lock.get("manifest", {})
    if not isinstance(manifest, dict):
        return frozenset(), ["the lock's [manifest] is not a table"]
    members = manifest.get("members", [])
    if not isinstance(members, list) or not all(isinstance(m, str) for m in members):
        return frozenset(), ["the lock's [manifest] members is not an array of strings"]
    return frozenset(normalize_name(m) for m in members), []


def _artifact_problems(
    name: str, pkg: dict, hosts: frozenset[str], policy: Policy, *, require_url: bool
) -> tuple[list[str], int]:
    """Check sdist and wheel entries; returns ``(problems, artifact_count)``."""
    problems: list[str] = []
    artifacts: list[object] = []
    if "sdist" in pkg:
        artifacts.append(pkg["sdist"])
    wheels = pkg.get("wheels", [])
    if isinstance(wheels, list):
        artifacts.extend(wheels)
    else:
        problems.append(f"{name}: wheels is not an array")
    for art in artifacts:
        if not isinstance(art, dict):
            problems.append(f"{name}: an artifact entry is not a table")
            continue
        if "path" in art:
            problems.append(f"{name}: artifact recorded by path, not url")
            continue
        url = art.get("url")
        if url is None:
            if require_url:
                problems.append(f"{name}: registry artifact has no url")
            continue  # a direct (url/git) source's artifacts may carry only a hash
        reason = url_violation(url, hosts, ca_host=policy.ca_host, ca_path_prefix=ARTIFACT_PATH_PREFIX)
        if reason:
            problems.append(f"{name}: artifact {url!r}: {reason}")
    return problems, len(artifacts)


def check_package(pkg: object, policy: Policy, members: frozenset[str]) -> tuple[list[str], bool]:
    """Check one ``[[package]]`` entry.

    Returns ``(violations, counted)``; ``counted`` is True when the entry is an autom8y-*
    registry package (whether or not it passed), which feeds the vacuity guard.
    """
    if not isinstance(pkg, dict):
        return ["a [[package]] entry is not a table"], False
    name = pkg.get("name")
    if not isinstance(name, str) or not name:
        return ["a [[package]] entry has no name"], False
    normalized = normalize_name(name)
    first_party = normalized.startswith(NAME_PREFIX)

    source = pkg.get("source")
    if not isinstance(source, dict):
        return [f"{name}: source is missing or not a table"], False

    local = _local_source(source)
    if local is not None:
        kind, value = local
        if len(source) == 1 and value == ".":
            return [], False  # the project's own package (uniqueness is checked in check_lock)
        if first_party:
            # The members exemption never admits an autom8y-* name: an autom8y-* member is
            # checked like any autom8y-* package, so a local source fails.
            return [f"{name}: autom8y-* {kind} source {value!r} is not allowed; it must come from CodeArtifact"], False
        if len(source) == 1 and normalized in members and _is_repo_relative(value):
            return [], False  # a non-autom8y workspace member named in [manifest] members
        return [f"{name}: {kind} source {value!r} is neither the project ('.') nor a [manifest] member"], False

    direct = [kind for kind in _DIRECT_SOURCE_KINDS if kind in source]
    if direct:
        kind = direct[0]
        if first_party:
            return [f"{name}: autom8y-* {kind} source is not allowed; it must come from CodeArtifact"], False
        if len(source) != 1:
            return [f"{name}: {kind} source has extra keys: {sorted(source)}"], False
        reason = url_violation(source[kind], policy.direct_hosts, allow_query_fragment=(kind == "git"))
        if reason:
            return [f"{name}: {kind} source {source[kind]!r}: {reason}"], False
        problems, _ = _artifact_problems(name, pkg, policy.direct_hosts, policy, require_url=False)
        return problems, False

    if set(source) != {"registry"}:
        return [f"{name}: source is not {{ registry = URL }}: {source}"], False

    hosts = frozenset({policy.ca_host}) if first_party else policy.registry_hosts | {policy.ca_host}
    problems: list[str] = []
    registry = source["registry"]
    reason = url_violation(registry, hosts, ca_host=policy.ca_host, ca_path_prefix=REGISTRY_PATH_PREFIX)
    if reason:
        problems.append(f"{name}: registry {registry!r}: {reason}")
    artifact_problems, n_artifacts = _artifact_problems(name, pkg, hosts, policy, require_url=True)
    problems.extend(artifact_problems)
    if n_artifacts == 0:
        problems.append(f"{name}: registry package records no sdist or wheel")
    return problems, first_party


def check_lock(lock: dict, policy: Policy) -> tuple[list[str], int]:
    packages = lock.get("package", [])
    if not isinstance(packages, list):
        return ["the lock's package key is not an array of tables"], 0
    members, violations = manifest_members(lock)
    root_claims = [
        p.get("name")
        for p in packages
        if isinstance(p, dict)
        and isinstance(p.get("source"), dict)
        and _local_source(p["source"]) is not None
        and _local_source(p["source"])[1] == "."
    ]
    if len(root_claims) > 1:
        violations.append(f"more than one package claims the project root '.': {root_claims}")
    counted = 0
    for pkg in packages:
        problems, was_counted = check_package(pkg, policy, members)
        violations.extend(problems)
        counted += int(was_counted)
    return violations, counted


def registry_package_count(lock: dict) -> int:
    """How many ``[[package]]`` entries (any name) have a registry source."""
    packages = lock.get("package", [])
    if not isinstance(packages, list):
        return 0
    return sum(
        1 for p in packages
        if isinstance(p, dict) and isinstance(p.get("source"), dict) and "registry" in p["source"]
    )


class _MaskingParser(argparse.ArgumentParser):
    """argparse echoes bad arguments on error; mask them like every other line."""

    def error(self, message: str) -> None:  # type: ignore[override]
        emit(self.format_usage().rstrip(), stream=sys.stderr)
        emit(f"USAGE: {message}", stream=sys.stderr)
        raise SystemExit(EXIT_USAGE)


def main(argv: Sequence[str] | None = None) -> int:
    if sys.version_info < (3, 11):
        emit("USAGE: Python 3.11 or later is required (tomllib)", stream=sys.stderr)
        return EXIT_USAGE
    import tomllib

    parser = _MaskingParser(
        description="Check that every package in a uv.lock resolves from an expected host.",
        allow_abbrev=False,  # no prefix matching: "--allow" must not reach --allowlist-json
    )
    parser.add_argument("lock", help="path to uv.lock")
    parser.add_argument("--repo", default=None, help="the caller's github.repository (owner/name)")
    parser.add_argument("--account", default=None, help="AWS account that owns the CodeArtifact domain (no default)")
    parser.add_argument("--allowlist-json", default="{}", help="the workflow-defined per-repository host table")
    parser.add_argument("--account-sha256", default=None, help="optional pinned sha256 (lowercase hex) of the account")
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:  # --help exits 0; usage errors exit through _MaskingParser
        return EXIT_USAGE if exc.code else EXIT_OK

    account = args.account if args.account is not None else ""
    if not _ACCOUNT_RE.fullmatch(account):
        # Deliberately prints no digits at all, so nothing of a malformed value leaks.
        emit(
            "USAGE: AWS account id missing or malformed; refusing (pass --account with exactly"
            " twelve ASCII digits)",
            stream=sys.stderr,
        )
        return EXIT_USAGE
    if args.account_sha256 is not None:
        if not _SHA256_RE.fullmatch(args.account_sha256):
            emit("USAGE: --account-sha256 is not lowercase hex of the right length; refusing", stream=sys.stderr)
            return EXIT_USAGE
        if hashlib.sha256(account.encode("ascii")).hexdigest() != args.account_sha256:
            # Fixed text: prints neither the passed value nor its hash.
            emit(ACCOUNT_MISMATCH_MESSAGE, stream=sys.stderr)
            return EXIT_ACCOUNT_MISMATCH
    repo = args.repo if args.repo is not None else ""
    if not _REPO_KEY_RE.fullmatch(repo):
        emit("USAGE: --repo is missing or not owner/name; refusing", stream=sys.stderr)
        return EXIT_USAGE
    try:
        policy = load_policy(account, repo, args.allowlist_json)
    except UsageError as exc:
        emit(f"USAGE: {exc}", stream=sys.stderr)
        return EXIT_USAGE

    try:
        with open(args.lock, "rb") as handle:
            lock = tomllib.load(handle)
    except OSError as exc:
        emit(f"USAGE: cannot read {args.lock}: {exc.strerror or exc}", stream=sys.stderr)
        return EXIT_USAGE
    except tomllib.TOMLDecodeError as exc:
        emit(f"USAGE: {args.lock} is not valid TOML: {exc}", stream=sys.stderr)
        return EXIT_USAGE

    violations, counted = check_lock(lock, policy)
    registry_total = registry_package_count(lock)
    allowed = sorted(policy.registry_hosts | policy.direct_hosts)
    scope = f"repository {repo or '(none)'}; non-CodeArtifact hosts allowed: {', '.join(allowed) or 'none'}"
    for violation in violations:
        emit(f"VIOLATION: {violation}")
    if violations:
        emit(f"FAIL: {counted} {NAME_PREFIX}* registry package(s) checked, {len(violations)} violation(s) ({scope})")
        return EXIT_VIOLATION
    if counted == 0 and not (policy.registry_hosts and registry_total > 0):
        # A repository whose policy row names registry hosts (only autom8y-workflows itself,
        # whose lock is dev-only test tooling) may have no autom8y-* package, but it still
        # must have at least one registry package checked. Every other repository keeps
        # the anchor rule: no autom8y-* registry package is vacuous.
        emit(f"VACUOUS: no {NAME_PREFIX}* registry packages in {args.lock} ({scope})", stream=sys.stderr)
        return EXIT_USAGE
    emit(
        f"OK: {counted} {NAME_PREFIX}* registry package(s) and every other package checked"
        f" ({registry_total} registry package(s) in all), 0 violations ({scope})"
    )
    return EXIT_OK


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:  # report masked; never let a traceback print an unmasked URL
        emit(f"ERROR: the check could not run: {type(exc).__name__}: {exc}", stream=sys.stderr)
        sys.exit(EXIT_USAGE)
