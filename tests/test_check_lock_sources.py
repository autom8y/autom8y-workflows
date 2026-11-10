"""Two-sided tests for .github/scripts/check_lock_sources.py (the uv.lock source check).

Standard library only, offline. Runs under either runner:

    python3 -m unittest -v tests.test_check_lock_sources
    python -m pytest tests/test_check_lock_sources.py

Fixture accounts are SYNTHETIC: FAKE_ACCOUNT and OTHER_ACCOUNT are made-up 12-digit
accounts built at runtime (no 12-digit literal appears in this file) and passed in by the
test. The real account is never written into this repository, and the script masks every
12-digit run in its output. The propagator's shared ``autom8y-1234`` fakes are not reused,
because they fail the 12-digit account rule. Each refusal case is a single mutation of the
clean lock, so the clean lock passing (exit 0) is the positive control for every exit-1
case beside it. The v1 rows that used ``file://`` fixture indexes (the E4 and E1 locks)
are re-authored here as https fixtures at the expected host shape (V1RowsReauthored); a
``file://`` registry now exits 1.

Host rule provenance. The URL refusals and the host variant rows mirror the propagator's
sealed variant set: autom8y commit 5a6ea594b65b,
.ledge/reviews/VERDICT-autom8y-propagator-S2-optional-deps-dispatch-c5f0c304fba4-20261109T165827Z-ADDENDUM-6-20261110T092251Z.md,
lines 51-73 (after-lock host variants and anchor variants). That record's residual A6-R1
is that its anchor regex admits any account (``autom8y-[0-9]+``), so a lock already
poisoned with another account's ``autom8y`` domain carries forward. This check closes that
residual by pinning the account: the only accepted CodeArtifact host is
``autom8y-<vars.AWS_ACCOUNT_ID>.d.codeartifact.us-east-1.amazonaws.com``, exactly 12 ASCII
digits, with no default (see AnotherAccount and PropagatorHostVariants).

Scope (owner ruling, v3 verdict). Every package is checked, not only autom8y-*. Non-autom8y
registry packages must be on the CodeArtifact host or on a host named for the caller's
repository in the shared policy file .github/lock-sources/policy.json (keyed by
github.repository); an unknown repository gets an empty allowlist. git and url sources
fail unless their host is named there as a direct host (AllPackagesScope, PolicyFile).

Inputs. The checker takes argv only and reads nothing from the environment
(ScriptIgnoresEnv). An optional pinned sha256 of the account gives exit 3 with a fixed
message on a mismatch (AccountSha256Pin). The runner, run_lock_sources.py, reads the
repository and account from the step's own env (LOCK_SOURCES_REPO, LOCK_SOURCES_ACCOUNT),
the hash and host table from the policy file, and passes all of them to the checker as
argv (Runner): a listed repository with no uv.lock exits 2, an unlisted one exits 0, every
tree is checked, and the worst exit wins.

The WorkflowWiring class is the wiring twin. lock-sources is its own job, first in
satellite-ci-reusable.yml, and the only job of the standalone lock-sources-required.yml
(the H-41 required workflow); the two jobs are identical except for the canonical ref.
Neither runs caller code, every other reusable job needs lock-sources, and the twin runs
each workflow's own run line under bash with the step env set as GitHub would: any
non-zero exit fails the job. There is no input to relax it. When lock-sources fails, every
dependent RUNS AND FAILS rather than skipping (B-2): each runs under `!cancelled()` plus
its own condition, and its first step, "Require lock-sources success", exits 1 unless
needs.lock-sources.result is success.

Members (A-1): the [manifest] members exemption never admits an autom8y-* name. Refusals:
each URL refusal is asserted by its exact reason text (RefusalReasons).
"""

from __future__ import annotations

import atexit
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPT = REPO_ROOT / ".github" / "scripts" / "check_lock_sources.py"
WORKFLOW = REPO_ROOT / ".github" / "workflows" / "satellite-ci-reusable.yml"
sys.path.insert(0, str(SCRIPT.parent))

import check_lock_sources as cls  # noqa: E402

# A synthetic 12-digit account built at runtime ("1234...") so no 12-digit literal is in the file.
FAKE_ACCOUNT = "".join(str(i % 10) for i in range(1, 13))
OTHER_ACCOUNT = FAKE_ACCOUNT[::-1]  # a second synthetic account, also built at runtime
HOST = f"autom8y-{FAKE_ACCOUNT}.d.codeartifact.us-east-1.amazonaws.com"
INDEX = f"https://{HOST}/pypi/autom8y-python/simple/"
PYPI = "https://pypi.org/simple/"
FILES = "https://files.pythonhosted.org/"
HASH = "sha256:" + "ab" * 32
FULLWIDTH_ACCOUNT = "".join(chr(0xFF10 + int(d)) for d in FAKE_ACCOUNT)
ARABIC_INDIC_ACCOUNT = "".join(chr(0x0660 + int(d)) for d in FAKE_ACCOUNT)

UNLISTED_REPO = "autom8y/autom8y-example"  # not in any allowlist: CodeArtifact only
PYPI_REPO = "autom8y/test-needs-pypi"  # a test key that names pypi
GIT_REPO = "autom8y/test-needs-github"  # a test key that names github.com as a direct host
TEST_ALLOWLIST = json.dumps({
    PYPI_REPO: {"registry_hosts": ["pypi.org", "files.pythonhosted.org"], "direct_hosts": []},
    GIT_REPO: {"registry_hosts": [], "direct_hosts": ["github.com"]},
})


def _toml_value(value: object) -> str:
    if isinstance(value, str):
        return json.dumps(value)  # a JSON string is a valid TOML basic string
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, dict):
        return "{ " + ", ".join(f"{k} = {_toml_value(v)}" for k, v in value.items()) + " }"
    if isinstance(value, list):
        return "[" + ", ".join(_toml_value(v) for v in value) + "]"
    raise TypeError(type(value))


def render_lock(packages: list[dict], members: list[str] | None = None) -> str:
    lines = ["version = 1", "revision = 3", 'requires-python = ">=3.12"', ""]
    if members is not None:
        lines += ["[manifest]", f"members = {_toml_value(members)}", ""]
    for pkg in packages:
        lines.append("[[package]]")
        for key, value in pkg.items():
            lines.append(f"{key} = {_toml_value(value)}")
        lines.append("")
    return "\n".join(lines)


def registry_pkg(
    name: str,
    version: str = "1.0.0",
    *,
    index: str = INDEX,
    sdist_base: str | None = None,
    wheel_base: str | None = None,
) -> dict:
    dist = name.replace("-", "_")
    sdist_base = sdist_base if sdist_base is not None else index
    wheel_base = wheel_base if wheel_base is not None else index
    return {
        "name": name,
        "version": version,
        "source": {"registry": index},
        "sdist": {"url": f"{sdist_base}{name}/{version}/{dist}-{version}.tar.gz", "hash": HASH, "size": 1},
        "wheels": [{"url": f"{wheel_base}{name}/{version}/{dist}-{version}-py3-none-any.whl", "hash": HASH, "size": 1}],
    }


def pypi_pkg(name: str = "httpx", version: str = "0.28.1") -> dict:
    return registry_pkg(name, version, index=PYPI, sdist_base=FILES, wheel_base=FILES)


def local_pkg(name: str, kind: str, path: str) -> dict:
    return {"name": name, "version": "0.1.0", "source": {kind: path}}


def git_pkg(name: str, url: str) -> dict:
    return {"name": name, "version": "1.0.0", "source": {"git": url}}


def clean_packages() -> list[dict]:
    """Project, two autom8y-* packages and a non-autom8y package, all on the CodeArtifact host."""
    return [
        local_pkg("autom8y-example", "editable", "."),
        registry_pkg("autom8y-auth", "4.3.0"),
        registry_pkg("autom8y-log", "0.9.0"),
        registry_pkg("httpx", "0.28.1"),
    ]


def with_auth(**overrides: object) -> list[dict]:
    """The clean lock with autom8y-auth replaced by a registry_pkg built from overrides."""
    pkgs = clean_packages()
    pkgs[1] = registry_pkg("autom8y-auth", "4.3.0", **overrides)  # type: ignore[arg-type]
    return pkgs


def with_auth_host(authority: str, scheme: str = "https") -> list[dict]:
    """autom8y-auth's registry and artifact URLs all on ``scheme://authority``."""
    return with_auth(index=f"{scheme}://{authority}/pypi/autom8y-python/simple/")


# Environment names the checker must ignore (argv only): an earlier design's names, the bare
# variable name, and the runner's own step-env names (only the runner reads those).
PLANTED_ENV_NAMES = (
    "CODEARTIFACT_ACCOUNT_ID", "LOCK_SOURCE_REPO", "LOCK_SOURCE_ALLOWLIST", "AWS_ACCOUNT_ID",
    "LOCK_SOURCES_ACCOUNT", "LOCK_SOURCES_REPO",
)


def _clean_env() -> dict[str, str]:
    return {k: v for k, v in os.environ.items() if k not in PLANTED_ENV_NAMES}


class _ScriptCase(unittest.TestCase):
    def run_check(
        self,
        lock_text: str | None,
        *,
        account: str | None = FAKE_ACCOUNT,
        via: str = "argv",
        repo: str | None = UNLISTED_REPO,
        allowlist: str | None = TEST_ALLOWLIST,
        extra_args: list[str] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        """Run the script. ``via="env-only"`` plants the values in env and passes no argv."""
        env = _clean_env()
        args = [sys.executable, "-I", str(SCRIPT)]
        with tempfile.TemporaryDirectory() as tmp:
            lock_path = Path(tmp) / "uv.lock"
            if lock_text is not None:
                lock_path.write_text(lock_text, encoding="utf-8")
            args.append(str(lock_path))
            if via == "env-only":
                for name, value in zip(PLANTED_ENV_NAMES, (account, repo, allowlist, account, account, repo)):
                    if value is not None:
                        env[name] = value
            else:
                if repo is not None:
                    args += ["--repo", repo]
                if account is not None:
                    args += ["--account", account]
                if allowlist is not None:
                    args += ["--allowlist-json", allowlist]
            args += extra_args or []
            result = subprocess.run(args, env=env, capture_output=True, text=True, timeout=60, check=False)
        # Masking floor: no 12-digit run (either synthetic account) ever reaches the output.
        out = result.stdout + result.stderr
        self.assertNotIn(FAKE_ACCOUNT, out)
        self.assertNotIn(OTHER_ACCOUNT, out)
        self.assertIsNone(re.search(r"\d{12,}", out), msg="unmasked 12+ digit run in output")
        return result

    def assertExit(
        self, packages: list[dict], code: int, *, members: list[str] | None = None, **kwargs: object
    ) -> subprocess.CompletedProcess[str]:
        result = self.run_check(render_lock(packages, members), **kwargs)  # type: ignore[arg-type]
        self.assertEqual(result.returncode, code, msg=f"stdout={result.stdout!r} stderr={result.stderr!r}")
        return result


class CleanLocks(_ScriptCase):
    def test_exact_host_passes(self) -> None:
        result = self.assertExit(clean_packages(), 0)
        self.assertIn("OK: 2 autom8y-* registry package(s)", result.stdout)

    def test_account_from_cli_argument(self) -> None:
        self.assertExit(clean_packages(), 0, via="cli")

    def test_editable_dot_plus_one_clean_registry_package_passes(self) -> None:
        self.assertExit([local_pkg("autom8y-example", "editable", "."), registry_pkg("autom8y-auth", "4.3.0")], 0)

    def test_virtual_root_plus_non_autom8y_manifest_member_passes(self) -> None:
        """A-1 row 1: a non-autom8y member is exempt (the root '.' is the project itself)."""
        pkgs = clean_packages()
        pkgs[0] = local_pkg("autom8y-root", "virtual", ".")
        pkgs.append(local_pkg("dev-member", "editable", "packages/dev-member"))
        self.assertExit(pkgs, 0, members=["autom8y-root", "dev_member"])

    def test_virtual_root_plus_autom8y_manifest_member_fails(self) -> None:
        """A-1 row 2: an autom8y-* member with an editable source fails with 1."""
        pkgs = clean_packages()
        pkgs[0] = local_pkg("autom8y-root", "virtual", ".")
        pkgs.append(local_pkg("autom8y-member", "editable", "packages/autom8y-member"))
        result = self.assertExit(pkgs, 1, members=["autom8y-root", "autom8y_member"])
        self.assertIn("autom8y-member: autom8y-* editable source", result.stdout)


class PropagatorHostVariants(_ScriptCase):
    """ADDENDUM-6 lines 51-60 after-lock host variants, each two-sided against the clean lock."""

    def test_exact_host(self) -> None:
        self.assertExit(with_auth_host(HOST), 0)

    def test_mixed_case_host(self) -> None:
        mixed = f"Autom8y-{FAKE_ACCOUNT}.D.CodeArtifact.US-East-1.AmazonAWS.com"
        self.assertExit(with_auth_host(mixed), 0)

    def test_another_accounts_ca_domain(self) -> None:
        self.assertExit(with_auth_host(f"autom8y-{OTHER_ACCOUNT}.d.codeartifact.us-east-1.amazonaws.com"), 1)

    def test_s3_lookalike_suffix_host(self) -> None:
        self.assertExit(with_auth_host(f"{HOST}.s3.amazonaws.com"), 1)

    def test_s3_bucket_style_host(self) -> None:
        self.assertExit(with_auth_host("autom8y-python.s3.us-east-1.amazonaws.com"), 1)

    def test_backslash_form(self) -> None:
        result = self.assertExit(with_auth_host(f"{HOST}\\@evil.io"), 1)
        self.assertIn("backslash", result.stdout)

    def test_trailing_dot(self) -> None:
        result = self.assertExit(with_auth_host(f"{HOST}."), 1)
        self.assertIn("trailing dot", result.stdout)

    def test_punycode_lookalike(self) -> None:
        self.assertExit(with_auth_host(f"xn--autom8y-{FAKE_ACCOUNT}-9pb.d.codeartifact.us-east-1.amazonaws.com"), 1)
        self.assertExit(with_auth_host(f"autom8y-{FAKE_ACCOUNT}.d.xn--codeartifct-9pb.us-east-1.amazonaws.com"), 1)

    def test_unicode_digit_lookalike_in_url_host(self) -> None:
        for digits in (FULLWIDTH_ACCOUNT, ARABIC_INDIC_ACCOUNT):
            with self.subTest(codepoint=hex(ord(digits[0]))):
                self.assertExit(with_auth_host(f"autom8y-{digits}.d.codeartifact.us-east-1.amazonaws.com"), 1)

    def test_kelvin_sign_folds_to_ascii_but_is_refused(self) -> None:
        # U+212A (Kelvin sign) lowercases to "k". The host has no "k", so prove the fold on a
        # host that does, then show a non-ASCII authority is refused before comparison.
        self.assertEqual("K".lower(), "k")
        self.assertIn("not ASCII", cls.url_violation("https://oK.example/x", {"ok.example"}) or "")
        self.assertExit(with_auth_host(HOST.replace(".com", ".Kom")), 1)

    def test_userinfo(self) -> None:
        result = self.assertExit(with_auth_host(f"user@{HOST}"), 1)
        self.assertIn("userinfo", result.stdout)

    def test_explicit_port(self) -> None:
        result = self.assertExit(with_auth_host(f"{HOST}:443"), 1)
        self.assertIn("port", result.stdout)

    def test_http_scheme(self) -> None:
        self.assertExit(with_auth_host(HOST, scheme="http"), 1)

    def test_pypi(self) -> None:
        self.assertExit(with_auth(index=PYPI, sdist_base=FILES, wheel_base=FILES), 1)


class PropagatorAnchorVariants(_ScriptCase):
    """ADDENDUM-6 lines 62-70 anchor variants."""

    def test_zero_autom8y_registry_hosts_fails_closed(self) -> None:
        result = self.assertExit([clean_packages()[3]], 2)
        self.assertIn("VACUOUS", result.stderr)

    def test_editable_only_fails_closed(self) -> None:
        self.assertExit([local_pkg("autom8y-example", "editable", ".")], 2)

    def test_two_hosts_across_autom8y_packages(self) -> None:
        pkgs = clean_packages()
        other = f"https://autom8y-{OTHER_ACCOUNT}.d.codeartifact.us-east-1.amazonaws.com/pypi/autom8y-python/simple/"
        pkgs[2] = registry_pkg("autom8y-log", "0.9.0", index=other)
        result = self.assertExit(pkgs, 1)
        self.assertIn("autom8y-log", result.stdout)
        self.assertNotIn("autom8y-auth", result.stdout)


class AnotherAccount(_ScriptCase):
    """A6-R1 closure: a lock consistently on another account's domain is refused."""

    def test_whole_lock_on_another_account(self) -> None:
        other = f"https://autom8y-{OTHER_ACCOUNT}.d.codeartifact.us-east-1.amazonaws.com/pypi/autom8y-python/simple/"
        pkgs = [clean_packages()[0], registry_pkg("autom8y-auth", "4.3.0", index=other), registry_pkg("autom8y-log", "0.9.0", index=other)]
        self.assertExit(pkgs, 1)
        self.assertExit(pkgs, 0, account=OTHER_ACCOUNT)  # the same lock passes only for its own account


class AllPackagesScope(_ScriptCase):
    """Owner ruling (v3): every package is checked, against a per-repository allowlist."""

    def test_non_autom8y_on_exact_ca_host_passes(self) -> None:
        self.assertExit(clean_packages(), 0)

    def test_non_autom8y_redirected_to_another_host(self) -> None:
        pkgs = clean_packages()
        pkgs[3] = registry_pkg("httpx", "0.28.1", index="https://evil.example/simple/")
        result = self.assertExit(pkgs, 1)
        self.assertIn("httpx", result.stdout)

    def test_non_autom8y_wheel_only_redirected(self) -> None:
        pkgs = clean_packages()
        pkgs[3] = registry_pkg("httpx", "0.28.1", wheel_base="https://evil.example/")
        self.assertExit(pkgs, 1)

    def test_non_autom8y_on_another_account(self) -> None:
        pkgs = clean_packages()
        pkgs[3] = registry_pkg("httpx", "0.28.1", index=f"https://autom8y-{OTHER_ACCOUNT}.d.codeartifact.us-east-1.amazonaws.com/pypi/autom8y-python/simple/")
        self.assertExit(pkgs, 1)

    def test_pypi_fails_for_a_repo_whose_allowlist_lacks_it(self) -> None:
        pkgs = clean_packages() + [pypi_pkg("certifi", "2025.1.1")]
        self.assertExit(pkgs, 1, repo=UNLISTED_REPO)
        self.assertExit(pkgs, 1, repo=GIT_REPO)  # listed, but without pypi

    def test_pypi_passes_for_a_test_repo_key_that_names_it(self) -> None:
        self.assertExit(clean_packages() + [pypi_pkg("certifi", "2025.1.1")], 0, repo=PYPI_REPO)

    def test_allowlist_never_widens_autom8y(self) -> None:
        self.assertExit(with_auth(index=PYPI, sdist_base=FILES, wheel_base=FILES), 1, repo=PYPI_REPO)

    def test_allowlisted_host_still_gets_the_refusals(self) -> None:
        for url in ("http://pypi.org/simple/", "https://pypi.org:443/simple/", "https://pypi.org./simple/", "https://u@pypi.org/simple/"):
            with self.subTest(url=url):
                pkgs = clean_packages() + [registry_pkg("certifi", "2025.1.1", index=url, sdist_base=FILES, wheel_base=FILES)]
                self.assertExit(pkgs, 1, repo=PYPI_REPO)

    def test_unknown_repo_key_gets_an_empty_allowlist(self) -> None:
        pypi = clean_packages() + [pypi_pkg("certifi", "2025.1.1")]
        for repo in ("autom8y/not-listed", "someone-else/autom8y-sms"):
            with self.subTest(repo=repo):
                self.assertExit(pypi, 1, repo=repo)
                self.assertExit(clean_packages(), 0, repo=repo)

    def test_missing_or_malformed_repo_is_a_usage_error(self) -> None:
        for repo in ("", None, "autom8y-sms", "autom8y/autom8y-sms\nx", "a/b/c"):
            with self.subTest(repo=repr(repo)):
                result = self.assertExit(clean_packages(), 2, repo=repo)
                self.assertIn("--repo is missing or not owner/name", result.stderr)

    def test_path_and_directory_sources_fail_on_any_package(self) -> None:
        """v4 item 3: any non-registry source other than '.' and [manifest] members exits 1."""
        for name in ("somelib", "autom8y-vendored"):
            for kind, path in (("path", "vendor/somelib-1.0-py3-none-any.whl"), ("directory", "vendor/somelib"), ("path", "/opt/x.whl")):
                with self.subTest(name=name, kind=kind, path=path):
                    self.assertExit(clean_packages() + [local_pkg(name, kind, path)], 1)
                    self.assertExit(clean_packages() + [local_pkg(name, kind, path)], 1, repo=GIT_REPO)
        self.assertExit(clean_packages(), 0)  # the same lock without the extra source passes

    def test_unset_allowlist_is_empty(self) -> None:
        self.assertExit(clean_packages() + [pypi_pkg("certifi", "2025.1.1")], 1, repo=PYPI_REPO, allowlist=None)
        self.assertExit(clean_packages(), 0, repo=PYPI_REPO, allowlist=None)

    def test_git_source_fails_unless_named(self) -> None:
        pkg = git_pkg("somelib", "https://github.com/example/somelib?rev=main#abcdef0")
        self.assertExit(clean_packages() + [pkg], 1, repo=UNLISTED_REPO)
        self.assertExit(clean_packages() + [pkg], 1, repo=PYPI_REPO)
        self.assertExit(clean_packages() + [pkg], 0, repo=GIT_REPO)

    def test_git_source_on_another_host_fails_even_when_github_is_named(self) -> None:
        pkg = git_pkg("somelib", "https://gitlab.example/example/somelib?rev=main#abcdef0")
        self.assertExit(clean_packages() + [pkg], 1, repo=GIT_REPO)

    def test_git_source_for_autom8y_always_fails(self) -> None:
        pkgs = clean_packages()
        pkgs[1] = git_pkg("autom8y-auth", "https://github.com/evil/autom8y-auth?rev=main#abcdef0")
        self.assertExit(pkgs, 1, repo=GIT_REPO)

    def test_url_source_fails_unless_named(self) -> None:
        pkg = {"name": "somelib", "version": "1.0.0", "source": {"url": "https://github.com/example/somelib/archive/v1.tar.gz"}}
        self.assertExit(clean_packages() + [pkg], 1, repo=UNLISTED_REPO)
        self.assertExit(clean_packages() + [pkg], 0, repo=GIT_REPO)

    def test_non_autom8y_local_sources_fail(self) -> None:
        for kind in ("editable", "path", "directory"):
            with self.subTest(kind=kind):
                self.assertExit(clean_packages() + [local_pkg("somelib", kind, "vendor/somelib")], 1)

    def test_bad_allowlists_are_usage_errors(self) -> None:
        bad = (
            "{not json",
            "[]",
            json.dumps({"not-a-repo-key": {}}),
            json.dumps({PYPI_REPO: {"registry_hosts": ["PyPI.org"]}}),
            json.dumps({PYPI_REPO: {"registry_hosts": ["pypi.org:443"]}}),
            json.dumps({PYPI_REPO: {"registry_hosts": "pypi.org"}}),
            json.dumps({PYPI_REPO: {"hosts": []}}),
            json.dumps({PYPI_REPO: {"registry_hosts": [HOST]}}),
        )
        for allowlist in bad:
            with self.subTest(allowlist=allowlist[:40]):
                self.assertExit(clean_packages(), 2, repo=PYPI_REPO, allowlist=allowlist)


class V1RowsReauthored(_ScriptCase):
    """The v1 section 4 rows (file:// fixture indexes) re-authored on https at the expected host."""

    B_INDEX = "https://public-b.example/simple/"  # stands in for v1's "public" index B

    def fake_pkg(self, index: str = INDEX, hash_: str = HASH) -> dict:
        pkg = registry_pkg("autom8y-fake", "0.1.0", index=index)
        pkg["sdist"]["hash"] = hash_
        pkg["wheels"][0]["hash"] = hash_
        return pkg

    def test_e4_lock_private_passes(self) -> None:
        self.assertExit([local_pkg("autom8y-example", "editable", "."), self.fake_pkg()], 0)

    def test_e1_lock_passes(self) -> None:
        pkgs = [local_pkg("autom8y-example", "editable", "."), self.fake_pkg(), clean_packages()[3]]
        self.assertExit(pkgs, 0)

    def test_fully_tampered_source_url_and_hash(self) -> None:
        pkgs = [local_pkg("autom8y-example", "editable", "."), self.fake_pkg(self.B_INDEX, "sha256:" + "cd" * 32)]
        self.assertExit(pkgs, 1)

    def test_tampered_hash_kept(self) -> None:
        self.assertExit([local_pkg("autom8y-example", "editable", "."), self.fake_pkg(self.B_INDEX)], 1)

    def test_file_registry_exits_1(self) -> None:
        result = self.assertExit([local_pkg("autom8y-example", "editable", "."), self.fake_pkg("file:///srv/index-a/")], 1)
        self.assertIn("scheme is not exactly https", result.stdout)

    def test_file_artifact_only_exits_1(self) -> None:
        self.assertExit(with_auth(wheel_base="file:///srv/index-a/"), 1)


class Refusals(_ScriptCase):
    """Further single-mutation refusals; each must exit 1."""

    def test_wheel_url_only_on_another_host(self) -> None:
        result = self.assertExit(with_auth(wheel_base=FILES), 1)
        self.assertIn("artifact", result.stdout)
        self.assertIn("1 violation(s)", result.stdout)

    def test_sdist_url_only_on_another_host(self) -> None:
        self.assertExit(with_auth(sdist_base="https://evil.example/pypi/autom8y-python/simple/"), 1)

    def test_lookalike_host_suffix_and_prefix(self) -> None:
        self.assertExit(with_auth_host(f"{HOST}.evil.io"), 1)
        self.assertExit(with_auth_host(f"evil-{HOST}"), 1)

    def test_uppercase_scheme(self) -> None:
        self.assertExit(with_auth(index=f"HTTPS://{HOST}/pypi/autom8y-python/simple/"), 1)

    def test_no_host(self) -> None:
        self.assertExit(with_auth(index="https:///pypi/autom8y-python/simple/"), 1)

    def test_wrong_path_prefix(self) -> None:
        self.assertExit(with_auth(index=f"https://{HOST}/pypi/other-repo/simple/"), 1)

    def test_registry_path_must_be_simple(self) -> None:
        self.assertExit(with_auth(index=f"https://{HOST}/pypi/autom8y-python/", sdist_base=INDEX, wheel_base=INDEX), 1)

    def test_dot_segment_climbs_out_of_path_prefix(self) -> None:
        self.assertExit(with_auth(wheel_base=f"https://{HOST}/pypi/autom8y-python/../other-repo/simple/"), 1)

    def test_query_string(self) -> None:
        self.assertExit(with_auth(index=f"{INDEX}?x=1"), 1)

    def test_url_source_for_autom8y(self) -> None:
        pkgs = clean_packages()
        pkgs[1] = {"name": "autom8y-auth", "version": "4.3.0", "source": {"url": f"{INDEX}autom8y-auth/4.3.0/autom8y_auth-4.3.0.tar.gz"}}
        self.assertExit(pkgs, 1)

    def test_artifact_recorded_by_path(self) -> None:
        pkgs = with_auth()
        pkgs[1]["wheels"] = [{"path": "autom8y_auth-4.3.0-py3-none-any.whl", "hash": HASH}]
        self.assertExit(pkgs, 1)

    def test_registry_source_with_extra_key(self) -> None:
        pkgs = with_auth()
        pkgs[1]["source"] = {"registry": INDEX, "url": "https://evil.io/x.whl"}
        self.assertExit(pkgs, 1)

    def test_unnormalized_name_is_still_checked(self) -> None:
        pkgs = clean_packages()
        pkgs[1] = registry_pkg("Autom8y_Auth", "4.3.0", index=PYPI, sdist_base=FILES, wheel_base=FILES)
        self.assertExit(pkgs, 1, repo=PYPI_REPO)  # still CodeArtifact-only, even where pypi is allowed


class RepoLocalExemption(_ScriptCase):
    """Finding 9: only the project ('.') and [manifest] members are exempt."""

    def test_vendor_editable_not_project_not_member(self) -> None:
        pkgs = clean_packages()
        pkgs[1] = local_pkg("autom8y-auth", "editable", "vendor/x")
        self.assertExit(pkgs, 1, members=["autom8y-example"])

    def test_vendor_editable_without_manifest(self) -> None:
        self.assertExit(clean_packages() + [local_pkg("autom8y-vendored", "editable", "vendor/x")], 1)

    def test_non_autom8y_manifest_member_editable_passes(self) -> None:
        pkgs = clean_packages() + [local_pkg("autom8-dev-data", "editable", "packages/autom8-dev-data")]
        self.assertExit(pkgs, 0, members=["autom8y-example", "autom8-dev-data"])

    def test_autom8y_manifest_member_is_never_exempt(self) -> None:
        """A-1: the members exemption never admits an autom8y-* name, in any spelling."""
        for name, member in (
            ("autom8y-member", "autom8y-member"),
            ("autom8y-member", "autom8y_member"),
            ("Autom8y.Member", "AUTOM8Y-member"),
            ("autom8y_member", "autom8y.member"),
        ):
            for kind in ("editable", "virtual"):
                with self.subTest(name=name, member=member, kind=kind):
                    pkgs = clean_packages() + [local_pkg(name, kind, "packages/autom8y-member")]
                    result = self.assertExit(pkgs, 1, members=["autom8y-example", member])
                    self.assertIn("is not allowed; it must come from CodeArtifact", result.stdout)
        # The same lock with the member under a non-autom8y name passes.
        self.assertExit(clean_packages() + [local_pkg("dev-member", "editable", "packages/dev-member")], 0, members=["dev_member"])

    def test_manifest_member_cannot_climb(self) -> None:
        pkgs = clean_packages() + [local_pkg("dev-member", "editable", "../evil")]
        self.assertExit(pkgs, 1, members=["autom8y-example", "dev-member"])

    def test_manifest_member_cannot_be_absolute(self) -> None:
        pkgs = clean_packages() + [local_pkg("dev-member", "editable", "/opt/evil")]
        self.assertExit(pkgs, 1, members=["autom8y-example", "dev-member"])

    def test_editable_parent_climb(self) -> None:
        self.assertExit(clean_packages() + [local_pkg("autom8y-evil", "editable", "../evil")], 1)

    def test_in_repo_path_and_directory_sources(self) -> None:
        for kind in ("path", "directory"):
            with self.subTest(kind=kind):
                pkgs = clean_packages() + [local_pkg("autom8y-vendored", kind, "vendor/x")]
                self.assertExit(pkgs, 1, members=["autom8y-example", "autom8y-vendored"])

    def test_two_packages_claiming_the_project_root(self) -> None:
        self.assertExit(clean_packages() + [local_pkg("autom8y-impostor", "editable", ".")], 1)


class AccountInput(_ScriptCase):
    """D-4: unset, empty or malformed account exits 2 with a digit-free message; valid gives 0."""

    MESSAGE = "AWS account id missing or malformed; refusing"

    def assertRefusedAccount(self, account: str | None, via: str = "env") -> None:
        result = self.assertExit(clean_packages(), 2, account=account, via=via)
        self.assertIn(self.MESSAGE, result.stderr)
        self.assertIsNone(re.search(r"\d", result.stdout + result.stderr), msg="refusal printed a digit")

    def test_valid_account_passes_the_same_clean_lock(self) -> None:
        self.assertExit(clean_packages(), 0)
        self.assertExit(clean_packages(), 0, via="cli")

    def test_empty_account(self) -> None:
        self.assertRefusedAccount("")
        self.assertRefusedAccount("", via="cli")

    def test_missing_account(self) -> None:
        self.assertRefusedAccount(None)

    def test_malformed_accounts_print_no_digits(self) -> None:
        for bad in ("12345678901", FAKE_ACCOUNT + "3", "12345678901a", " " + FAKE_ACCOUNT, FAKE_ACCOUNT + "\n"):
            with self.subTest(account=repr(bad)):
                self.assertRefusedAccount(bad)
        self.assertRefusedAccount("12345678901", via="cli")

    def test_unicode_digit_account(self) -> None:
        for digits in (FULLWIDTH_ACCOUNT, ARABIC_INDIC_ACCOUNT):
            with self.subTest(codepoint=hex(ord(digits[0]))):
                self.assertRefusedAccount(digits)
                self.assertRefusedAccount(digits, via="cli")

    def test_expected_host_refuses_bad_account(self) -> None:
        with self.assertRaises(ValueError):
            cls.expected_host(FULLWIDTH_ACCOUNT)


class LockInput(_ScriptCase):
    def test_missing_lock_file(self) -> None:
        self.assertEqual(self.run_check(None).returncode, 2)

    def test_malformed_lock(self) -> None:
        self.assertEqual(self.run_check("[[package]\nname = ").returncode, 2)

    def test_unknown_argument_is_masked_usage_error(self) -> None:
        result = self.run_check(render_lock(clean_packages()), extra_args=["--acount", FAKE_ACCOUNT])
        self.assertEqual(result.returncode, 2)
        self.assertIn("<acct>", result.stderr)

    def test_no_allow_list_option_exists(self) -> None:
        result = self.run_check(render_lock(clean_packages()), extra_args=["--allow", "https://pypi.org/simple/"])
        self.assertEqual(result.returncode, 2)
        self.assertIn("unrecognized arguments: --allow", result.stderr)  # no prefix match onto --allowlist-json


class ScriptIgnoresEnv(_ScriptCase):
    """v4 item 2: the repository key, account and allowlist come from argv only."""

    def test_env_only_values_are_ignored(self) -> None:
        result = self.assertExit(clean_packages(), 2, via="env-only")
        self.assertIn("AWS account id missing or malformed; refusing", result.stderr)

    def test_planted_env_cannot_widen_or_redirect(self) -> None:
        planted = {
            "CODEARTIFACT_ACCOUNT_ID": OTHER_ACCOUNT,
            "AWS_ACCOUNT_ID": OTHER_ACCOUNT,
            "LOCK_SOURCE_REPO": PYPI_REPO,
            "LOCK_SOURCE_ALLOWLIST": json.dumps({UNLISTED_REPO: {"registry_hosts": ["pypi.org", "files.pythonhosted.org"]}}),
        }
        pypi = render_lock(clean_packages() + [pypi_pkg("certifi", "2025.1.1")])
        args = [sys.executable, "-I", str(SCRIPT), "uv.lock", "--repo", UNLISTED_REPO, "--account", FAKE_ACCOUNT]
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "uv.lock").write_text(pypi, encoding="utf-8")
            result = subprocess.run(args, cwd=tmp, env={**_clean_env(), **planted}, capture_output=True, text=True, timeout=60, check=False)
            self.assertEqual(result.returncode, 1, msg=result.stdout + result.stderr)
            (Path(tmp) / "uv.lock").write_text(render_lock(clean_packages()), encoding="utf-8")
            result = subprocess.run(args, cwd=tmp, env={**_clean_env(), **planted}, capture_output=True, text=True, timeout=60, check=False)
            self.assertEqual(result.returncode, 0, msg=result.stdout + result.stderr)

    def test_script_source_reads_no_environment(self) -> None:
        source = SCRIPT.read_text(encoding="utf-8")
        self.assertIsNone(re.search(r"^\s*(import os|from os\b)", source, re.MULTILINE))
        self.assertNotIn("os.environ", source)
        self.assertNotIn("getenv", source)


class AccountSha256Pin(_ScriptCase):
    """v4 item 4 and v5 (b): optional pinned sha256 of the account; a mismatch has its own exit 3."""

    MISMATCH = "account does not match the pinned account hash; refusing"
    MISSING = "AWS account id missing or malformed; refusing"

    def test_matching_hash_passes(self) -> None:
        good = hashlib.sha256(FAKE_ACCOUNT.encode("ascii")).hexdigest()
        self.assertExit(clean_packages(), 0, extra_args=["--account-sha256", good])

    def test_mismatch_exits_3_with_fixed_message_and_no_value_or_hash(self) -> None:
        pinned = hashlib.sha256(OTHER_ACCOUNT.encode("ascii")).hexdigest()
        result = self.assertExit(clean_packages(), 3, extra_args=["--account-sha256", pinned])
        out = result.stdout + result.stderr
        self.assertEqual(result.stderr.strip(), self.MISMATCH)
        self.assertNotIn(pinned, out)
        self.assertNotIn(hashlib.sha256(FAKE_ACCOUNT.encode("ascii")).hexdigest(), out)
        self.assertIsNone(re.search(r"\d", out), msg="the mismatch message printed a digit")

    def test_variable_flipped_to_another_account_exits_3(self) -> None:
        # vars.AWS_ACCOUNT_ID changed to OTHER_ACCOUNT, the workflow still pinning FAKE_ACCOUNT's hash,
        # and a lock consistently on OTHER_ACCOUNT's domain (which would otherwise pass).
        pinned = hashlib.sha256(FAKE_ACCOUNT.encode("ascii")).hexdigest()
        other = f"https://autom8y-{OTHER_ACCOUNT}.d.codeartifact.us-east-1.amazonaws.com/pypi/autom8y-python/simple/"
        pkgs = [clean_packages()[0], registry_pkg("autom8y-auth", "4.3.0", index=other)]
        self.assertExit(pkgs, 0, account=OTHER_ACCOUNT)  # without the pin it passes
        self.assertExit(pkgs, 3, account=OTHER_ACCOUNT, extra_args=["--account-sha256", pinned])

    def test_missing_or_malformed_account_stays_exit_2_with_its_own_message(self) -> None:
        pinned = hashlib.sha256(FAKE_ACCOUNT.encode("ascii")).hexdigest()
        for account in (None, "", "12345678901", FULLWIDTH_ACCOUNT):
            with self.subTest(account=repr(account)):
                result = self.assertExit(clean_packages(), 2, account=account, extra_args=["--account-sha256", pinned])
                self.assertIn(self.MISSING, result.stderr)
                self.assertNotIn(self.MISMATCH, result.stderr)

    def test_malformed_hash_refuses(self) -> None:
        good = hashlib.sha256(FAKE_ACCOUNT.encode("ascii")).hexdigest()
        for bad in (good.upper(), good[:-1], good + "0", "z" * 64, ""):
            with self.subTest(bad=bad[:8]):
                result = self.assertExit(clean_packages(), 2, extra_args=["--account-sha256", bad])
                self.assertIn("--account-sha256 is not lowercase hex", result.stderr)


class Masking(_ScriptCase):
    def test_violation_output_masks_the_account(self) -> None:
        result = self.assertExit(with_auth_host(HOST, scheme="http"), 1)
        self.assertIn("<acct>", result.stdout)

    def test_unicode_digits_are_masked(self) -> None:
        result = self.assertExit(with_auth_host(f"autom8y-{FULLWIDTH_ACCOUNT}.d.codeartifact.us-east-1.amazonaws.com"), 1)
        self.assertNotIn(FULLWIDTH_ACCOUNT, result.stdout)

    def test_mask_function(self) -> None:
        self.assertEqual(cls.mask(f"a{FAKE_ACCOUNT}b 12345678901"), "a<acct>b 12345678901")


class UrlRuleUnit(unittest.TestCase):
    """Direct checks of url_violation, so each refusal is pinned to its reason."""

    def test_clean_urls_pass(self) -> None:
        self.assertIsNone(cls.url_violation(INDEX, {HOST}, ca_host=HOST, ca_path_prefix=cls.REGISTRY_PATH_PREFIX))
        self.assertIsNone(cls.url_violation(f"{INDEX}autom8y-auth/4.3.0/autom8y_auth-4.3.0-py3-none-any.whl", {HOST}, ca_host=HOST))
        self.assertIsNone(cls.url_violation("https://github.com/x/y?rev=main#abc", {"github.com"}, allow_query_fragment=True))

    def test_refusals(self) -> None:
        cases = {
            "backslash": f"https://{HOST}/pypi/autom8y-python\\simple/",
            "whitespace or a control character": f"https://{HOST}/pypi/autom8y-python/sim\tple/",
            "scheme": f"http://{HOST}/pypi/autom8y-python/simple/",
            "userinfo": f"https://:@{HOST}/pypi/autom8y-python/simple/",
            "explicit port": f"https://{HOST}:/pypi/autom8y-python/simple/",
            "no host": "https:///pypi/autom8y-python/simple/",
            "trailing dot": f"https://{HOST}./pypi/autom8y-python/simple/",
            "not ASCII": f"https://autom8y-{FULLWIDTH_ACCOUNT}.d.codeartifact.us-east-1.amazonaws.com/pypi/autom8y-python/simple/",
            "not an expected host": f"https://{HOST}.s3.amazonaws.com/pypi/autom8y-python/simple/",
            "path does not start": f"https://{HOST}/pypi/autom8y-python-evil/simple/",
            "dot segment": f"https://{HOST}/pypi/autom8y-python/./simple/",
            "percent-encoded": f"https://{HOST}/pypi/autom8y-python/%2e%2e/evil/",
            "query string": f"https://{HOST}/pypi/autom8y-python/simple/?",
            "fragment": f"https://{HOST}/pypi/autom8y-python/simple/#x",
            "missing or not a string": None,
        }
        for expected, url in cases.items():
            with self.subTest(expected=expected):
                reason = cls.url_violation(url, {HOST}, ca_host=HOST)
                self.assertIsNotNone(reason)
                self.assertIn(expected, reason or "")


# Each refusal's exact reason, on a URL whose host would ALSO fail the fullmatch, so deleting
# any one refusal changes the reason and turns this red even though the URL still fails.
REFUSAL_ROWS = (
    ("backslash", f"https://{HOST}\\@evil.io/pypi/autom8y-python/simple/", "URL contains a backslash"),
    ("whitespace", "https://evil .io/pypi/autom8y-python/simple/", "URL contains whitespace or a control character"),
    ("control character", "https://evil\x01.io/pypi/autom8y-python/simple/", "URL contains whitespace or a control character"),
    ("tab (urlsplit strips it)", "https://ev\til.io/pypi/autom8y-python/simple/", "URL contains whitespace or a control character"),
    ("scheme", "http://evil.io/pypi/autom8y-python/simple/", "scheme is not exactly https"),
    ("uppercase scheme", "HTTPS://evil.io/pypi/autom8y-python/simple/", "scheme is not exactly https"),
    ("userinfo", "https://user@evil.io/pypi/autom8y-python/simple/", "URL carries userinfo"),
    ("port", "https://evil.io:443/pypi/autom8y-python/simple/", "URL carries an explicit port"),
    ("empty port", "https://evil.io:/pypi/autom8y-python/simple/", "URL carries an explicit port"),
    ("no host", "https:///pypi/autom8y-python/simple/", "URL has no host"),
    ("trailing dot", "https://evil.io./pypi/autom8y-python/simple/", "host has a trailing dot"),
    ("non-ASCII", "https://еvil.io/pypi/autom8y-python/simple/", "host is not ASCII (look-alike)"),
    ("query string", f"https://{HOST}/pypi/autom8y-python/simple/?x=1", "URL carries a query string"),
    ("fragment", f"https://{HOST}/pypi/autom8y-python/simple/#x", "URL carries a fragment"),
)


class RefusalReasons(_ScriptCase):
    """Each URL refusal is asserted by its exact reason text (unit and CLI)."""

    def test_unit_reason_text(self) -> None:
        for label, url, reason in REFUSAL_ROWS:
            with self.subTest(refusal=label):
                self.assertEqual(cls.url_violation(url, {HOST}, ca_host=HOST), reason)

    def test_cli_reason_text_on_a_wheel_url(self) -> None:
        for label, url, reason in REFUSAL_ROWS:
            with self.subTest(refusal=label):
                pkgs = with_auth()
                pkgs[1]["wheels"] = [{"url": url, "hash": HASH, "size": 1}]
                result = self.assertExit(pkgs, 1)
                self.assertIn(f": {reason}", result.stdout)


# --- Shared policy file ------------------------------------------------------------------

POLICY = REPO_ROOT / ".github" / "lock-sources" / "policy.json"
RUNNER = REPO_ROOT / ".github" / "scripts" / "run_lock_sources.py"
WRAPPER = REPO_ROOT / ".github" / "workflows" / "lock-sources-required.yml"
SATELLITES = ("autom8y/autom8y-ads", "autom8y/autom8y-asana", "autom8y/autom8y-data", "autom8y/autom8y-scheduling", "autom8y/autom8y-sms")
# This repository: its own uv.lock is dev-only test tooling on PyPI, so its row names the two
# PyPI hosts. It is the one row that does.
HOME_REPO = "autom8y/autom8y-workflows"
HOME_ROW = {"registry_hosts": ["pypi.org", "files.pythonhosted.org"], "direct_hosts": []}
HOME_LOCK = REPO_ROOT / "uv.lock"
OWNER_NOTE = "owner: autom8y-workflows maintainers, changed only in a reviewed PR when the account changes"
_REPO_NAME_RE = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", re.ASCII)

sys.path.insert(0, str(RUNNER.parent))
import run_lock_sources as runner_mod  # noqa: E402


def _real_policy() -> dict:
    return json.loads(POLICY.read_text(encoding="utf-8"))


class PolicyFile(unittest.TestCase):
    """The one shared policy file: it parses, and every key is a repository name."""

    def test_parses_with_exactly_the_three_keys(self) -> None:
        self.assertEqual(sorted(_real_policy()), ["_owner", "account_sha256", "repositories"])

    def test_every_repositories_key_is_a_repo_name(self) -> None:
        repositories = _real_policy()["repositories"]
        self.assertTrue(repositories)
        for key, entry in repositories.items():
            with self.subTest(key=key):
                self.assertRegex(key, _REPO_NAME_RE)
                self.assertIsNotNone(_REPO_NAME_RE.fullmatch(key))
                self.assertTrue(set(entry) <= {"registry_hosts", "direct_hosts"})

    def test_satellites_are_listed_with_no_extra_hosts(self) -> None:
        repositories = _real_policy()["repositories"]
        self.assertEqual(sorted(repositories), sorted(SATELLITES + (HOME_REPO,)))
        for repo in SATELLITES:
            self.assertEqual(repositories[repo], {"registry_hosts": [], "direct_hosts": []})

    def test_home_repo_row_is_exactly_the_two_pypi_hosts(self) -> None:
        self.assertEqual(_real_policy()["repositories"][HOME_REPO], HOME_ROW)
        self.assertIn("autom8y/autom8y-workflows is the one row that names PyPI hosts", _real_policy()["_owner"])

    def test_owner_note_and_hash_shape(self) -> None:
        policy = _real_policy()
        self.assertTrue(policy["_owner"].startswith(OWNER_NOTE))
        self.assertRegex(policy["account_sha256"], r"\A[0-9a-f]{64}\Z")

    def test_runner_and_checker_accept_it(self) -> None:
        account_sha256, repositories = runner_mod.load_policy(POLICY)
        self.assertEqual(account_sha256, _real_policy()["account_sha256"])
        # The checker accepts the table as its --allowlist-json (synthetic account, no pin).
        result = subprocess.run(
            [sys.executable, "-I", str(SCRIPT), "/dev/stdin", "--repo", SATELLITES[0], "--account", FAKE_ACCOUNT,
             "--allowlist-json", json.dumps(repositories)],
            input=render_lock(clean_packages()), env=_clean_env(), capture_output=True, text=True, timeout=60, check=False,
        )
        self.assertEqual(result.returncode, 0, msg=result.stderr)

    def test_no_policy_is_inlined_in_either_workflow(self) -> None:
        for wf in (WORKFLOW, WRAPPER):
            text = wf.read_text(encoding="utf-8")
            with self.subTest(workflow=wf.name):
                self.assertNotIn(_real_policy()["account_sha256"], text)
                self.assertNotIn("registry_hosts", text)
                self.assertNotIn("toJSON", text)


def _append_packages(lock_text: str, packages: list[dict]) -> str:
    """The given lock text with extra [[package]] tables appended (render_lock's header dropped)."""
    return lock_text.rstrip("\n") + "\n\n" + render_lock(packages).split("\n", 4)[4]


class HomeRepoRow(_ScriptCase):
    """The autom8y-workflows row, two-sided, against the REAL policy.json and this repo's real uv.lock."""

    def check(self, lock_text: str, repo: str = HOME_REPO) -> subprocess.CompletedProcess[str]:
        return self.run_check(lock_text, repo=repo, allowlist=json.dumps(_real_policy()["repositories"]))

    def assertCheck(self, lock_text: str, code: int, repo: str = HOME_REPO) -> subprocess.CompletedProcess[str]:
        result = self.check(lock_text, repo)
        self.assertEqual(result.returncode, code, msg=result.stdout + result.stderr)
        return result

    def test_the_real_home_lock_passes_under_the_row(self) -> None:
        result = self.assertCheck(HOME_LOCK.read_text(encoding="utf-8"), 0)
        self.assertIn("non-CodeArtifact hosts allowed: files.pythonhosted.org, pypi.org", result.stdout)

    def test_the_real_home_lock_fails_without_the_row(self) -> None:
        for repo in ("autom8y/not-listed", SATELLITES[0]):
            with self.subTest(repo=repo):
                self.assertCheck(HOME_LOCK.read_text(encoding="utf-8"), 1, repo=repo)

    def test_an_autom8y_package_on_pypi_still_fails_under_the_row(self) -> None:
        lock = _append_packages(HOME_LOCK.read_text(encoding="utf-8"), [pypi_pkg("autom8y-auth", "4.3.0")])
        result = self.assertCheck(lock, 1)
        self.assertIn("autom8y-auth: registry 'https://pypi.org/simple/'", result.stdout)
        self.assertIn("is not an expected host", result.stdout)

    def test_a_third_host_still_fails_under_the_row(self) -> None:
        for index, files in (
            ("https://evil.example/simple/", "https://evil.example/"),
            (PYPI, "https://evil.example/"),  # wheel only on a third host
            ("https://pypi.org.evil.example/simple/", FILES),
        ):
            with self.subTest(index=index, files=files):
                pkg = registry_pkg("certifi", "2025.1.1", index=index, sdist_base=files, wheel_base=files)
                self.assertCheck(_append_packages(HOME_LOCK.read_text(encoding="utf-8"), [pkg]), 1)

    def test_a_git_source_still_fails_under_the_row(self) -> None:
        pkg = git_pkg("somelib", "https://github.com/example/somelib?rev=main#abcdef0")
        self.assertCheck(_append_packages(HOME_LOCK.read_text(encoding="utf-8"), [pkg]), 1)

    def test_vacuity_under_the_row_needs_one_registry_package(self) -> None:
        root_only = render_lock([local_pkg("autom8y-workflows-tests", "virtual", ".")])
        result = self.assertCheck(root_only, 2)
        self.assertIn("VACUOUS", result.stderr)
        # Satellites keep the anchor rule: a lock with registry packages but no autom8y-* is vacuous.
        self.assertCheck(render_lock([local_pkg("autom8y-example", "editable", "."), registry_pkg("httpx")]), 2, repo=SATELLITES[0])


# --- Runner ------------------------------------------------------------------------------

_CANONICAL_DIR = ".lock-source-canonical"
_TREES = (("github.sha", "caller-sha"), ("PR-head", "caller-pr-head"))
TEST_POLICY = {
    "_owner": OWNER_NOTE + " (test fixture)",
    "account_sha256": hashlib.sha256(FAKE_ACCOUNT.encode("ascii")).hexdigest(),
    "repositories": {repo: {"registry_hosts": [], "direct_hosts": []} for repo in SATELLITES},
}


def _make_workspace(
    root: Path,
    locks: dict[str, str | None],
    *,
    policy: dict | str | None = None,
    with_script: bool = True,
) -> Path:
    """A job workspace: the canonical sparse checkout plus one directory per caller tree."""
    work = root / "workspace"
    canonical = work / _CANONICAL_DIR
    (canonical / ".github" / "scripts").mkdir(parents=True)
    (canonical / ".github" / "lock-sources").mkdir(parents=True)
    shutil.copy2(RUNNER, canonical / ".github" / "scripts" / RUNNER.name)
    if with_script:
        shutil.copy2(SCRIPT, canonical / ".github" / "scripts" / SCRIPT.name)
    if policy is not None:
        text = policy if isinstance(policy, str) else json.dumps(policy)
        (canonical / ".github" / "lock-sources" / "policy.json").write_text(text, encoding="utf-8")
    for _, tree in _TREES:
        (work / tree).mkdir()
        lock_text = locks.get(tree)
        if lock_text is not None:
            (work / tree / "uv.lock").write_text(lock_text, encoding="utf-8")
    return work


def _git_env(root: Path) -> dict[str, str]:
    """An isolated git environment: no user or system config, so no hooks or signing apply."""
    return {**_clean_env(), "HOME": str(root), "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull}


def _git(cwd: Path, root: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", "-c", "core.hooksPath=" + os.devnull, "-c", "user.name=fixture", "-c", "user.email=fixture@example.invalid",
         "-c", "commit.gpgsign=false", "-c", "init.defaultBranch=main", "-C", str(cwd), *args],
        env=_git_env(root), capture_output=True, text=True, timeout=60, check=True,
    )
    return result.stdout.strip()


_GIT_TEMPLATES: dict[tuple[bool, bool], Path] = {}


def _canonical_git_template(on_main: bool, with_main_ref: bool) -> Path:
    """A cached .git whose detached HEAD is on, or off, refs/remotes/origin/main (built once)."""
    key = (on_main, with_main_ref)
    if key not in _GIT_TEMPLATES:
        root = Path(tempfile.mkdtemp(prefix="lock-sources-git-"))
        atexit.register(shutil.rmtree, root, True)
        repo = root / "repo"
        repo.mkdir()
        (repo / "README").write_text("fixture\n", encoding="utf-8")
        _git(repo, root, "init", "-q", "--template=")  # no sample hooks to copy
        _git(repo, root, "add", "-A")
        _git(repo, root, "commit", "-q", "-m", "chore(test): canonical commit on main")
        main_sha = _git(repo, root, "rev-parse", "HEAD")
        if with_main_ref:
            _git(repo, root, "update-ref", "refs/remotes/origin/main", main_sha)
        if not on_main:
            _git(repo, root, "checkout", "-q", "-b", "side")
            _git(repo, root, "commit", "-q", "--allow-empty", "-m", "chore(test): commit off main")
        _git(repo, root, "checkout", "-q", "--detach")
        _GIT_TEMPLATES[key] = repo / ".git"
    return _GIT_TEMPLATES[key]


def _make_canonical_git(work: Path, root: Path, *, on_main: bool, with_main_ref: bool = True) -> None:
    """Make the canonical directory a git checkout whose HEAD is on, or off, origin/main.

    Only HEAD and refs/remotes/origin/main matter to the runner's check, so a cached .git is
    copied in; the canonical files on disk (runner, script, policy) are what the runner reads.
    """
    shutil.copytree(_canonical_git_template(on_main, with_main_ref), work / _CANONICAL_DIR / ".git")


def _both(lock_text: str) -> dict[str, str]:
    return {tree: lock_text for _, tree in _TREES}


RUNNER_ARGS = [f"--canonical={_CANONICAL_DIR}"] + [f"--tree={label}={tree}" for label, tree in _TREES]
ON_MAIN_FLAG = "--require-canonical-on-main"


class _RunnerCase(unittest.TestCase):
    def run_runner(
        self,
        locks: dict[str, str | None],
        *,
        repo: str | None = "autom8y/autom8y-sms",
        account: str | None = FAKE_ACCOUNT,
        policy: dict | str | None = TEST_POLICY,
        with_script: bool = True,
        extra_env: dict[str, str] | None = None,
        extra_args: list[str] | None = None,
        canonical_git: str | None = None,
    ) -> subprocess.CompletedProcess[str]:
        """``canonical_git``: None (not a git checkout), "main", "off-main" or "no-main-ref"."""
        with tempfile.TemporaryDirectory() as tmp:
            work = _make_workspace(Path(tmp), locks, policy=policy, with_script=with_script)
            if canonical_git is not None:
                if shutil.which("git") is None:
                    self.skipTest("git not available")
                _make_canonical_git(
                    work, Path(tmp), on_main=canonical_git == "main", with_main_ref=canonical_git != "no-main-ref"
                )
            env = {**_git_env(Path(tmp)), "GIT_CEILING_DIRECTORIES": tmp, **(extra_env or {})}
            if repo is not None:
                env[runner_mod.REPO_ENV] = repo
            if account is not None:
                env[runner_mod.ACCOUNT_ENV] = account
            result = subprocess.run(
                [sys.executable, "-I", str(work / _CANONICAL_DIR / ".github" / "scripts" / RUNNER.name), *RUNNER_ARGS,
                 *(extra_args or [])],
                cwd=work, env=env, capture_output=True, text=True, timeout=120, check=False,
            )
        out = result.stdout + result.stderr
        self.assertNotIn(FAKE_ACCOUNT, out)
        self.assertNotIn(OTHER_ACCOUNT, out)
        self.assertIsNone(re.search(r"\d{12,}", out), msg="unmasked 12+ digit run")
        return result

    def assertRunner(self, locks: dict[str, str | None], code: int, **kwargs: object) -> str:
        result = self.run_runner(locks, **kwargs)  # type: ignore[arg-type]
        self.assertEqual(result.returncode, code, msg=result.stdout + result.stderr)
        return result.stdout + result.stderr


class Runner(_RunnerCase):
    """run_lock_sources.py: the shared step logic of both entry points."""

    def test_clean_lock_at_both_trees_passes(self) -> None:
        out = self.assertRunner(_both(render_lock(clean_packages())), 0)
        self.assertEqual(out.count("OK: "), 2)  # both trees were checked

    def test_listed_repository_with_no_lock_exits_2(self) -> None:
        for repo in SATELLITES:
            with self.subTest(repo=repo):
                out = self.assertRunner({}, 2, repo=repo)
                self.assertIn("uv.lock missing for a listed repository; refusing", out)

    def test_unlisted_repository_with_no_lock_exits_0_with_notice(self) -> None:
        out = self.assertRunner({}, 0, repo="autom8y/not-listed")
        self.assertIn("::notice::no uv.lock", out)
        self.assertNotIn("listed repository", out)

    def test_both_trees_are_checked(self) -> None:
        clean, bad = render_lock(clean_packages()), render_lock(with_auth_host(f"{HOST}.evil.io"))
        out = self.assertRunner({"caller-sha": bad, "caller-pr-head": clean}, 1)
        self.assertIn("at github.sha exited 1", out)
        out = self.assertRunner({"caller-sha": clean, "caller-pr-head": bad}, 1)
        self.assertIn("at PR-head exited 1", out)

    def test_worst_exit_wins(self) -> None:
        clean = render_lock(clean_packages())
        bad = render_lock(with_auth_host(f"{HOST}.evil.io"))
        malformed = "[[package]\nname = "
        self.assertRunner({"caller-sha": bad, "caller-pr-head": malformed}, 2)
        self.assertRunner({"caller-sha": malformed, "caller-pr-head": bad}, 2)
        self.assertRunner({"caller-sha": clean, "caller-pr-head": bad}, 1)
        self.assertRunner({"caller-sha": bad, "caller-pr-head": clean}, 1)

    def test_lock_missing_at_one_tree_exits_1(self) -> None:
        out = self.assertRunner({"caller-sha": render_lock(clean_packages())}, 1)
        self.assertIn("uv.lock is missing at the PR-head checkout", out)

    def test_account_mismatch_exits_3(self) -> None:
        out = self.assertRunner(_both(render_lock(clean_packages())), 3, account=OTHER_ACCOUNT)
        self.assertIn("account does not match the pinned account hash; refusing", out)
        self.assertNotIn(TEST_POLICY["account_sha256"], out)

    def test_missing_or_malformed_account_exits_2(self) -> None:
        for account in (None, "", "12345678901", FULLWIDTH_ACCOUNT):
            with self.subTest(account=repr(account)):
                out = self.assertRunner(_both(render_lock(clean_packages())), 2, account=account)
                self.assertIn("AWS account id missing or malformed; refusing", out)

    def test_policy_missing_or_malformed_exits_2(self) -> None:
        good = TEST_POLICY
        exactly = "the policy file must hold exactly _owner, account_sha256 and repositories"
        bad_policies = {
            "missing": (None, "cannot read the policy file"),
            "not json": ("{nope", "the policy file is not valid JSON"),
            "array": ("[]", exactly),
            "no _owner": ({k: v for k, v in good.items() if k != "_owner"}, exactly),
            "empty _owner": ({**good, "_owner": " "}, "the policy file's _owner is empty"),
            "extra key": ({**good, "extra": 1}, exactly),
            "short hash": ({**good, "account_sha256": good["account_sha256"][:-1]}, "the policy file's account_sha256 is not lowercase hex"),
            "upper hash": ({**good, "account_sha256": good["account_sha256"].upper()}, "the policy file's account_sha256 is not lowercase hex"),
            "bad repo key": ({**good, "repositories": {"not-a-repo": {}}}, "the policy file's repositories key 'not-a-repo' is not owner/name"),
            "repositories not object": ({**good, "repositories": []}, "the policy file's repositories is not an object"),
        }
        for label, (policy, message) in bad_policies.items():
            with self.subTest(policy=label):
                out = self.assertRunner(_both(render_lock(clean_packages())), 2, policy=policy)
                # The runner's own message, so the runner's check is proven even where the
                # checker would also refuse the same table later.
                self.assertIn(f"::error::{message}", out)
                self.assertNotIn("::group::", out)  # refused before any tree is checked

    def test_missing_script_exits_2(self) -> None:
        out = self.assertRunner(_both(render_lock(clean_packages())), 2, with_script=False)
        self.assertIn("canonical autom8y-workflows checkout has no check_lock_sources.py", out)

    def test_caller_tree_policy_and_script_are_never_used(self) -> None:
        # A caller plants a permissive policy and an always-pass script in its own tree.
        bad = render_lock(clean_packages() + [pypi_pkg("certifi", "2025.1.1")])
        with tempfile.TemporaryDirectory() as tmp:
            work = _make_workspace(Path(tmp), _both(bad), policy=TEST_POLICY)
            for _, tree in _TREES:
                (work / tree / ".github" / "lock-sources").mkdir(parents=True)
                (work / tree / ".github" / "scripts").mkdir(parents=True)
                permissive = {**TEST_POLICY, "repositories": {"autom8y/autom8y-sms": {"registry_hosts": ["pypi.org", "files.pythonhosted.org"]}}}
                (work / tree / ".github" / "lock-sources" / "policy.json").write_text(json.dumps(permissive), encoding="utf-8")
                (work / tree / ".github" / "scripts" / SCRIPT.name).write_text("import sys\nsys.exit(0)\n", encoding="utf-8")
            env = {**_clean_env(), runner_mod.REPO_ENV: "autom8y/autom8y-sms", runner_mod.ACCOUNT_ENV: FAKE_ACCOUNT}
            result = subprocess.run(
                [sys.executable, "-I", str(work / _CANONICAL_DIR / ".github" / "scripts" / RUNNER.name), *RUNNER_ARGS],
                cwd=work, env=env, capture_output=True, text=True, timeout=120, check=False,
            )
        self.assertEqual(result.returncode, 1, msg=result.stdout + result.stderr)

    def test_hostile_env_values_cannot_break_out(self) -> None:
        canary = "INJECTED-CANARY"
        hostile = ('"; print("' + canary + '"); x = "', "$(echo " + canary + ")", "`echo " + canary + "`", "x\n::notice::" + canary)
        for value in hostile:
            with self.subTest(value=value[:10]):
                out = self.assertRunner(_both(render_lock(clean_packages())), 2, account=value)
                self.assertNotIn(canary, out)
                out = self.assertRunner(_both(render_lock(clean_packages())), 2, repo=value)
                self.assertNotIn(canary, out)

    def test_runner_does_not_read_account_from_other_names(self) -> None:
        # The old names and the bare variable name are not read by the runner.
        planted = {"CODEARTIFACT_ACCOUNT_ID": FAKE_ACCOUNT, "AWS_ACCOUNT_ID": FAKE_ACCOUNT, "LOCK_SOURCE_REPO": "autom8y/autom8y-sms"}
        out = self.assertRunner(_both(render_lock(clean_packages())), 2, account=None, extra_env=planted)
        self.assertIn("AWS account id missing or malformed; refusing", out)
        self.assertRunner(_both(render_lock(clean_packages())), 0)  # the step-env name is read


class RunnerCanonicalOnMain(_RunnerCase):
    """F-1: --require-canonical-on-main refuses a canonical SHA not reachable from main."""

    MESSAGE = "the canonical autom8y-workflows SHA is not reachable from autom8y-workflows main; refusing"

    def test_on_main_passes(self) -> None:
        out = self.assertRunner(_both(render_lock(clean_packages())), 0, canonical_git="main", extra_args=[ON_MAIN_FLAG])
        self.assertEqual(out.count("OK: "), 2)

    def test_off_main_refuses_with_exit_2(self) -> None:
        out = self.assertRunner(_both(render_lock(clean_packages())), 2, canonical_git="off-main", extra_args=[ON_MAIN_FLAG])
        self.assertIn(f"::error::{self.MESSAGE}", out)
        self.assertNotIn("::group::", out)  # refused before any tree is checked

    def test_without_the_flag_off_main_is_not_refused(self) -> None:
        # The wrapper's path: its own commit may legitimately be off main (a PR in this repo).
        self.assertRunner(_both(render_lock(clean_packages())), 0, canonical_git="off-main")

    def test_no_main_ref_refuses(self) -> None:
        out = self.assertRunner(_both(render_lock(clean_packages())), 2, canonical_git="no-main-ref", extra_args=[ON_MAIN_FLAG])
        self.assertIn("no refs/remotes/origin/main to verify against", out)

    def test_not_a_git_checkout_refuses(self) -> None:
        out = self.assertRunner(_both(render_lock(clean_packages())), 2, extra_args=[ON_MAIN_FLAG])
        self.assertIn("::error::", out)
        self.assertNotIn("::group::", out)


PYPI_ROW_POLICY = {
    **TEST_POLICY,
    "repositories": {
        **TEST_POLICY["repositories"],
        "autom8y/needs-pypi": {"registry_hosts": ["pypi.org", "files.pythonhosted.org"], "direct_hosts": []},
    },
}
NEAR_MATCHES = {
    # rule a: equal once -, _ and . are removed
    "autom8y/autom8y_sms": "autom8y/autom8y-sms",
    "autom8y/autom8y.sms": "autom8y/autom8y-sms",
    "autom8y/autom8ysms": "autom8y/autom8y-sms",
    # rule b: same owner, names one edit apart
    "autom8y/autom8y-sma": "autom8y/autom8y-sms",
    "autom8y/autom8y-sm": "autom8y/autom8y-sms",
    "autom8y/autom8y-smss": "autom8y/autom8y-sms",
    "autom8y/autom8y-adx": "autom8y/autom8y-ads",
    # rule c: same owner, the listed name plus a separator-led suffix
    "autom8y/autom8y-sms-v2": "autom8y/autom8y-sms",
    "autom8y/autom8y-data_service": "autom8y/autom8y-data",
    "autom8y/autom8y-asana.next": "autom8y/autom8y-asana",
    # rule d: same name, another owner (a transfer), in any case
    "someone/autom8y-sms": "autom8y/autom8y-sms",
    "Someone/AUTOM8Y-SCHEDULING": "autom8y/autom8y-scheduling",
}
NOT_NEAR = ("autom8y/not-listed", "autom8y/autom8y", "autom8y/autom8y-dev-x", "autom8y/autom8y-api-schemas", "autom8y/autom8y-crm", "someone/autom8y-sms2")


class RunnerRepoMatching(_RunnerCase):
    """F-3: casefolded keys, and a refused near-match, so a renamed satellite cannot turn unlisted."""

    def test_casefold_equal_name_is_the_listed_repository(self) -> None:
        for repo in ("Autom8y/Autom8y-SMS", "AUTOM8Y/AUTOM8Y-SMS", "autom8y/AUTOM8Y-sms"):
            with self.subTest(repo=repo):
                out = self.assertRunner({}, 2, repo=repo)  # listed: a missing lock is refused
                self.assertIn("uv.lock missing for a listed repository; refusing", out)
                out = self.assertRunner(_both(render_lock(clean_packages())), 0, repo=repo)
                self.assertIn("repository autom8y/autom8y-sms;", out)  # the checker got the policy key

    def test_casefold_match_uses_that_row(self) -> None:
        pypi = _both(render_lock(clean_packages() + [pypi_pkg("certifi", "2025.1.1")]))
        self.assertRunner(pypi, 0, repo="Autom8y/Needs-PyPI", policy=PYPI_ROW_POLICY)
        self.assertRunner(pypi, 0, repo="autom8y/needs-pypi", policy=PYPI_ROW_POLICY)
        self.assertRunner(pypi, 1, repo="autom8y/autom8y-sms", policy=PYPI_ROW_POLICY)

    def test_near_match_is_refused_with_exit_2(self) -> None:
        for repo, key in NEAR_MATCHES.items():
            for locks in ({}, _both(render_lock(clean_packages()))):
                with self.subTest(repo=repo, has_lock=bool(locks)):
                    out = self.assertRunner(locks, 2, repo=repo)
                    self.assertIn(f"repository {repo!r} nearly matches the listed {key!r} but is not it; refusing", out)
                    self.assertNotIn("::group::", out)

    def test_names_that_are_not_near_stay_unlisted(self) -> None:
        for repo in NOT_NEAR:
            with self.subTest(repo=repo):
                out = self.assertRunner({}, 0, repo=repo)
                self.assertIn("::notice::no uv.lock", out)
                self.assertRunner(_both(render_lock(clean_packages())), 0, repo=repo)

    def test_unit_rule_by_rule(self) -> None:
        keys = TEST_POLICY["repositories"]
        for repo, key in NEAR_MATCHES.items():
            with self.subTest(repo=repo):
                self.assertEqual(runner_mod.resolve_repo(repo, keys), (None, key))
        for repo in NOT_NEAR:
            with self.subTest(repo=repo):
                self.assertEqual(runner_mod.resolve_repo(repo, keys), (None, None))
        self.assertEqual(runner_mod.resolve_repo("autom8y/autom8y-sms", keys), ("autom8y/autom8y-sms", None))
        self.assertEqual(runner_mod.resolve_repo("Autom8y/Autom8y-Sms", keys), ("autom8y/autom8y-sms", None))

    def test_missing_or_malformed_repo_is_refused_even_without_a_lock(self) -> None:
        for repo in (None, "", "autom8y-sms", "a/b/c", "autom8y/autom8y-sms\nx"):
            with self.subTest(repo=repr(repo)):
                out = self.assertRunner({}, 2, repo=repo)
                self.assertIn("the repository name (LOCK_SOURCES_REPO) is missing or not owner/name; refusing", out)

    def test_policy_keys_that_differ_only_in_case_are_refused(self) -> None:
        policy = {**TEST_POLICY, "repositories": {**TEST_POLICY["repositories"], "Autom8y/Autom8y-SMS": {}}}
        out = self.assertRunner(_both(render_lock(clean_packages())), 2, policy=policy)
        self.assertIn("two keys that differ only in case", out)


# --- Wiring twin: the reusable job and the standalone wrapper ------------------------------

_JOB = "lock-sources"
_STEP_NAME = "      - name: Check uv.lock sources (every package, exact hosts)"
_CANONICAL_STEP = "      - name: Checkout lock-source runner, script and policy (autom8y-workflows canonical)"
_RUN_COMMAND = (
    "python3 -I .lock-source-canonical/.github/scripts/run_lock_sources.py --canonical .lock-source-canonical"
    " --tree github.sha=caller-sha --tree PR-head=caller-pr-head"
)
# F-1: only the reusable job (caller-supplied canonical ref) requires the canonical SHA on main.
_RUN_COMMAND_FOR = {
    "satellite-ci-reusable.yml": _RUN_COMMAND + " " + ON_MAIN_FLAG,
    "lock-sources-required.yml": _RUN_COMMAND,
}
_SPARSE = (".github/scripts/run_lock_sources.py", ".github/scripts/check_lock_sources.py", ".github/lock-sources/policy.json")
_CANONICAL_REF = {
    "satellite-ci-reusable.yml": "${{ inputs.autom8y_workflows_sha }}",
    "lock-sources-required.yml": "${{ github.workflow_sha }}",
}

# B-2: every dependent's if:, as !cancelled() plus its condition at origin/main (verbatim,
# parenthesized), plus a lock-sources escape where other needs used to gate it.
EXPECTED_DEPENDENT_IFS = {
    "lint": "${{ !cancelled() }}",
    "matrix-prep": "${{ !cancelled() }}",
    "test": "${{ !cancelled() && (needs.matrix-prep.result == 'success' || needs.lock-sources.result != 'success') }}",
    "coverage-aggregate": (
        "${{ !cancelled() && (needs.test.result == 'success' || needs.lock-sources.result != 'success')"
        " && (inputs.test_splits > 1 && inputs.coverage_threshold_aggregate > 0 && inputs.pytest_disable_coverage != true) }}"
    ),
    "integration": "${{ !cancelled() && (inputs.run_integration) }}",
    "convention-check": "${{ !cancelled() && (inputs.convention_check) }}",
    "spectral-validation": "${{ !cancelled() && (inputs.spectral_enabled) }}",
    "spec-check": "${{ !cancelled() && (inputs.spec_check_enabled) }}",
    "semantic-score": "${{ !cancelled() && (inputs.semantic_score_enabled) }}",
    "conformance-gate": "${{ !cancelled() && (inputs.conformance_gate) }}",
    "trivy-gate": "${{ !cancelled() && (github.event_name == 'pull_request') }}",
}
GUARD_NAME = "      - name: Require lock-sources success"
GUARD_RUN = (
    'if [ "$LOCK_SOURCES_RESULT" != "success" ]; then\n'
    '  echo "::error::lock-sources did not succeed (result: ${LOCK_SOURCES_RESULT}); failing this job instead of skipping it"\n'
    "  exit 1\n"
    "fi\n"
    'echo "lock-sources succeeded"\n'
)


def _run_block(step: list[str]) -> str:
    start = step.index("        run: |") + 1
    body = []
    for line in step[start:]:
        if line.strip() and not line.startswith("          "):
            break
        body.append(line[10:])
    return "\n".join(body).rstrip("\n") + "\n"


def _lines(path: Path) -> list[str]:
    return path.read_text(encoding="utf-8").splitlines()


def _job_names(lines: list[str]) -> list[str]:
    start = lines.index("jobs:")
    return [l[2:-1] for l in lines[start + 1:] if re.fullmatch(r"  [A-Za-z0-9_-]+:", l)]


def _job_lines(path: Path, name: str) -> list[str]:
    lines = _lines(path)
    start = lines.index(f"  {name}:")
    end = next((i for i in range(start + 1, len(lines)) if re.fullmatch(r"  [A-Za-z0-9_-]+:", lines[i])), len(lines))
    return lines[start:end]


def _steps(job: list[str]) -> list[list[str]]:
    starts = [i for i, l in enumerate(job) if l.startswith("      - ")]
    return [job[s:e] for s, e in zip(starts, starts[1:] + [len(job)])]


def _fields(block: list[str], key: str) -> list[str]:
    prefix = f"{key}: "
    return [line.strip()[len(prefix):] for line in block if line.strip().startswith(prefix)]


def _field(block: list[str], key: str) -> str:
    matches = _fields(block, key)
    if len(matches) != 1:
        raise AssertionError(f"expected one {key!r}, found {matches}")
    return matches[0]


def _job_key(job: list[str], key: str) -> list[str]:
    prefix = f"    {key}: "
    return [l[len(prefix):].strip() for l in job if l.startswith(prefix)]


def _job_needs(job: list[str]) -> list[str]:
    values = _job_key(job, "needs")
    if not values:
        return []
    value = values[0]
    return [v.strip() for v in value.strip("[]").split(",")] if value.startswith("[") else [value]


def _input_block(name: str) -> list[str]:
    lines = _lines(WORKFLOW)
    start = lines.index(f"      {name}:")
    end = next(i for i in range(start + 1, len(lines)) if not lines[i].startswith("        "))
    return lines[start:end]


def _sparse_paths(step: list[str]) -> list[str]:
    start = step.index("          sparse-checkout: |") + 1
    paths = []
    for line in step[start:]:
        if not line.startswith("            "):
            break
        paths.append(line.strip())
    return paths


class WorkflowWiring(unittest.TestCase):
    """lock-sources runs no caller code, in both entry points, and every other reusable job needs it."""

    WORKFLOWS = (WORKFLOW, WRAPPER)

    def job(self, wf: Path) -> list[str]:
        return _job_lines(wf, _JOB)

    def check_step(self, wf: Path) -> list[str]:
        return next(s for s in _steps(self.job(wf)) if s[0] == _STEP_NAME)

    # Static wiring.

    def test_job_graph_every_other_reusable_job_needs_lock_sources(self) -> None:
        names = _job_names(_lines(WORKFLOW))
        self.assertEqual(names[0], _JOB)
        self.assertEqual(sorted(names[1:]), sorted(EXPECTED_DEPENDENT_IFS))
        for name in names[1:]:
            with self.subTest(job=name):
                self.assertIn(_JOB, _job_needs(_job_lines(WORKFLOW, name)))

    # B-2: dependents run and fail, never skip, when lock-sources fails.

    def test_every_dependent_runs_under_not_cancelled_and_keeps_its_own_condition(self) -> None:
        for name, expected in EXPECTED_DEPENDENT_IFS.items():
            with self.subTest(job=name):
                job = _job_lines(WORKFLOW, name)
                conds = _job_key(job, "if")
                self.assertEqual(conds, [expected])
                self.assertTrue(expected.startswith("${{ !cancelled()"))
                self.assertNotIn("needs.lock-sources.result == 'success'", expected)  # that would skip
                others = [n for n in _job_needs(job) if n != _JOB]
                if others:
                    # Other needs still gate as before, EXCEPT when lock-sources did not succeed.
                    self.assertIn("needs.lock-sources.result != 'success'", expected)

    def test_every_dependent_has_the_guard_as_its_first_step(self) -> None:
        for name in EXPECTED_DEPENDENT_IFS:
            with self.subTest(job=name):
                first = _steps(_job_lines(WORKFLOW, name))[0]
                self.assertEqual(first[0], GUARD_NAME)
                self.assertEqual(_field(first, "LOCK_SOURCES_RESULT"), "${{ needs.lock-sources.result }}")
                self.assertEqual(_fields(first, "if"), [])
                self.assertEqual(_fields(first, "continue-on-error"), [])
                self.assertEqual(_run_block(first), GUARD_RUN)

    def test_guard_simulation_two_sided(self) -> None:
        bash = shutil.which("bash")
        if bash is None:
            self.skipTest("bash not available")
        first = _steps(_job_lines(WORKFLOW, "lint"))[0]
        with tempfile.TemporaryDirectory() as tmp:
            step_file = Path(tmp) / "guard.sh"
            step_file.write_text(_run_block(first), encoding="utf-8")
            for result_value, code in (("success", 0), ("failure", 1), ("cancelled", 1), ("skipped", 1), ("", 1)):
                with self.subTest(result=result_value):
                    run = subprocess.run(
                        [bash, "--noprofile", "--norc", "-eo", "pipefail", str(step_file)],
                        env={**_clean_env(), "LOCK_SOURCES_RESULT": result_value},
                        capture_output=True, text=True, timeout=30, check=False,
                    )
                    self.assertEqual(run.returncode, code, msg=run.stdout + run.stderr)
                    if code:
                        self.assertIn("::error::lock-sources did not succeed", run.stdout)

    def test_test_matrix_falls_back_to_one_shard(self) -> None:
        test_job = _job_lines(WORKFLOW, "test")
        self.assertIn("        shard: ${{ fromJson(needs.matrix-prep.outputs.shard_list || '[1]') }}", test_job)

    def test_standalone_wrapper_has_no_dependents(self) -> None:
        self.assertEqual(_job_names(_lines(WRAPPER)), [_JOB])
        self.assertNotIn(GUARD_NAME, WRAPPER.read_text(encoding="utf-8"))

    def test_comments_state_the_residuals(self) -> None:
        """F-1 and F-2 are stated where a maintainer reads the reusable job."""
        text = " ".join(l.strip().lstrip("# ") for l in _lines(WORKFLOW) if l.strip().startswith("#"))
        # F-1: the reusable job is not the gate.
        self.assertIn("NOT THE GATE (F-1): this job fetches its policy and script at a CALLER-SUPPLIED SHA.", text)
        self.assertIn("The gate is the H-41 wrapper, lock-sources-required.yml", text)
        # F-2: a canceled run gets past !cancelled(); H-41 removes the dependence on it.
        self.assertIn("Residual (F-2): `!cancelled()` is false in a canceled run.", text)
        self.assertIn("H-41 required workflow removes the dependence on this", text)

    def test_wrapper_triggers_and_single_job(self) -> None:
        lines = _lines(WRAPPER)
        on = lines.index("on:")
        triggers = []
        for line in lines[on + 1:]:
            if line and not line.startswith(" "):
                break
            if re.fullmatch(r"  [a-z_]+:", line):
                triggers.append(line.strip()[:-1])
        self.assertEqual(sorted(triggers), ["merge_group", "pull_request"])
        self.assertEqual(_job_names(lines), [_JOB])
        self.assertIn("permissions:", lines)
        self.assertIn("  contents: read", lines)

    def test_job_runs_no_caller_code(self) -> None:
        for wf in self.WORKFLOWS:
            with self.subTest(workflow=wf.name):
                steps = _steps(self.job(wf))
                uses = [_field(s, "uses").split("@")[0] for s in steps if _fields(s, "uses")]
                self.assertEqual(uses, ["actions/checkout", "actions/checkout", "actions/checkout", "actions/setup-python"])
                runs = [s for s in steps if _fields(s, "run")]
                self.assertEqual(runs, [self.check_step(wf)])
                self.assertEqual(_field(self.check_step(wf), "run"), _RUN_COMMAND_FOR[wf.name])
                self.assertIn("    permissions:", self.job(wf))
                self.assertIn("      contents: read", self.job(wf))

    def test_required_with_no_way_to_relax(self) -> None:
        for wf in self.WORKFLOWS:
            with self.subTest(workflow=wf.name):
                self.assertEqual(_job_key(self.job(wf), "if"), [])
                self.assertEqual(_job_key(self.job(wf), "continue-on-error"), [])
                for block in _steps(self.job(wf)):
                    self.assertEqual(_fields(block, "if"), [])
                    self.assertEqual(_fields(block, "continue-on-error"), [])
        self.assertNotIn("      lock_source_check:", _lines(WORKFLOW))

    def test_checkout_refs_and_sparse_paths(self) -> None:
        for wf in self.WORKFLOWS:
            with self.subTest(workflow=wf.name):
                steps = _steps(self.job(wf))
                refs = {_field(s, "path"): _field(s, "ref") for s in steps if _fields(s, "path")}
                self.assertEqual(refs["caller-sha"], "${{ github.sha }}")
                self.assertEqual(
                    refs["caller-pr-head"],
                    "${{ github.event_name == 'pull_request' && github.event.pull_request.head.sha || github.sha }}",
                )
                self.assertEqual(refs[_CANONICAL_DIR], _CANONICAL_REF[wf.name])
                canonical = next(s for s in steps if s[0] == _CANONICAL_STEP)
                self.assertEqual(_field(canonical, "repository"), "autom8y/autom8y-workflows")
                self.assertEqual(sorted(_sparse_paths(canonical)), sorted(_SPARSE))
                self.assertEqual(_field(canonical, "fetch-depth"), "0")  # F-1: history to verify main
                for rel in _SPARSE:
                    self.assertTrue((REPO_ROOT / rel).is_file(), msg=rel)
                for s in steps:
                    if _fields(s, "uses") and _field(s, "uses").startswith("actions/checkout@"):
                        self.assertEqual(_field(s, "persist-credentials"), "false")

    def test_env_form(self) -> None:
        for wf in self.WORKFLOWS:
            with self.subTest(workflow=wf.name):
                step = self.check_step(wf)
                self.assertEqual(_field(step, runner_mod.REPO_ENV), "${{ github.repository }}")
                self.assertEqual(_field(step, runner_mod.ACCOUNT_ENV), "${{ vars.AWS_ACCOUNT_ID }}")
                self.assertNotIn("${{", _field(step, "run"))
                comment = " ".join(l.strip().lstrip("# ") for l in step if l.strip().startswith("#"))
                self.assertIn("vars resolves to the CALLER repository", comment)
                self.assertIn("account_sha256 in policy.json is what binds the account", comment)
                self.assertNotIn("toJSON", wf.read_text(encoding="utf-8"))

    def test_wrapper_and_reusable_job_are_identical_except_the_canonical_ref(self) -> None:
        """Identical except (1) the canonical ref and (2) F-1: the reusable run line's flag."""
        reusable_run = f"        run: {_RUN_COMMAND_FOR[WORKFLOW.name]}"
        wrapper_run = f"        run: {_RUN_COMMAND_FOR[WRAPPER.name]}"
        self.assertEqual(self.job(WORKFLOW).count(reusable_run), 1)
        self.assertEqual(self.job(WRAPPER).count(wrapper_run), 1)

        def normalized(wf: Path) -> list[str]:
            lines = [l.replace(_CANONICAL_REF[wf.name], "<canonical-ref>") for l in self.job(wf)]
            lines = [wrapper_run if l == reusable_run else l for l in lines]  # the one allowed difference
            while lines and not lines[-1].strip():
                lines.pop()
            return lines
        self.assertEqual(normalized(WORKFLOW), normalized(WRAPPER))
        self.assertNotIn(ON_MAIN_FLAG, WRAPPER.read_text(encoding="utf-8").split("jobs:", 1)[1])

    def test_workflows_sha_input_says_literal_sha(self) -> None:
        desc = _field(_input_block("autom8y_workflows_sha"), "description")
        self.assertNotIn("MUST pass github.sha", desc)
        self.assertIn("literal 40-character autom8y-workflows SHA", desc)

    def test_text_extraction_matches_yaml_when_available(self) -> None:
        try:
            import yaml  # type: ignore[import-untyped]
        except ImportError:
            self.skipTest("PyYAML not installed; the text extraction is used alone")
        for wf in self.WORKFLOWS:
            with self.subTest(workflow=wf.name):
                data = yaml.safe_load(wf.read_text(encoding="utf-8"))
                job = data["jobs"][_JOB]
                step = next(s for s in job["steps"] if s.get("name") == _STEP_NAME.split("name: ", 1)[1])
                self.assertEqual(step["run"], _RUN_COMMAND_FOR[wf.name])
                self.assertEqual(step["env"], {runner_mod.REPO_ENV: "${{ github.repository }}", runner_mod.ACCOUNT_ENV: "${{ vars.AWS_ACCOUNT_ID }}"})
                self.assertNotIn("continue-on-error", step)
                self.assertNotIn("if", job)
                canonical = next(s for s in job["steps"] if s.get("name") == _CANONICAL_STEP.split("name: ", 1)[1])
                self.assertEqual(sorted(canonical["with"]["sparse-checkout"].split()), sorted(_SPARSE))
                self.assertEqual(canonical["with"]["fetch-depth"], 0)
        data = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
        for name, other in data["jobs"].items():
            if name != _JOB:
                needs = other.get("needs", [])
                self.assertIn(_JOB, [needs] if isinstance(needs, str) else needs, msg=name)
        wrapper = yaml.safe_load(WRAPPER.read_text(encoding="utf-8"))
        self.assertEqual(sorted(wrapper.get("on") or wrapper.get(True)), ["merge_group", "pull_request"])

    # Execution: each workflow's own run line under the runner's bash, env set as GitHub would.

    def _job_run(
        self,
        wf: Path,
        locks: dict[str, str | None],
        *,
        repo: str = "autom8y/autom8y-sms",
        account: str = FAKE_ACCOUNT,
        policy: dict | None = None,
        canonical_on_main: bool = True,
    ) -> dict[str, object]:
        bash = shutil.which("bash")
        if bash is None:
            self.skipTest("bash not available")
        with tempfile.TemporaryDirectory() as tmp_name:
            tmp = Path(tmp_name)
            work = _make_workspace(tmp, locks, policy=policy if policy is not None else TEST_POLICY)
            if shutil.which("git") is None:
                self.skipTest("git not available")
            # The canonical checkout as GitHub leaves it (fetch-depth 0): HEAD on origin/main.
            _make_canonical_git(work, tmp, on_main=canonical_on_main)
            shim = tmp / "bin"
            shim.mkdir()
            (shim / "python3").symlink_to(sys.executable)
            step_file = tmp / "step.sh"
            step_file.write_text(_field(self.check_step(wf), "run") + "\n", encoding="utf-8")
            env = {
                **_git_env(tmp),
                "GIT_CEILING_DIRECTORIES": str(tmp),
                "PATH": f"{shim}{os.pathsep}{os.environ.get('PATH', '')}",
                runner_mod.REPO_ENV: repo,
                runner_mod.ACCOUNT_ENV: account,
            }
            result = subprocess.run(
                [bash, "--noprofile", "--norc", "-eo", "pipefail", str(step_file)],
                cwd=work, env=env, capture_output=True, text=True, timeout=120, check=False,
            )
        out = result.stdout + result.stderr
        self.assertIsNone(re.search(r"\d{12,}", out), msg="unmasked 12+ digit run")
        # The step has no continue-on-error, so any non-zero exit fails the job.
        return {"rc": result.returncode, "out": out, "job_fails": result.returncode != 0}

    def test_exit_codes_fail_the_job_in_both_entry_points(self) -> None:
        clean = render_lock(clean_packages())
        bad = render_lock(with_auth_host(f"{HOST}.evil.io"))
        for wf in self.WORKFLOWS:
            with self.subTest(workflow=wf.name):
                self.assertEqual(self._job_run(wf, _both(clean))["rc"], 0)
                outcome = self._job_run(wf, _both(bad))
                self.assertEqual(outcome["rc"], 1)
                self.assertTrue(outcome["job_fails"])
                self.assertEqual(self._job_run(wf, {"caller-sha": clean, "caller-pr-head": bad})["rc"], 1)
                self.assertEqual(self._job_run(wf, {})["rc"], 2)  # listed repository, no lock
                self.assertEqual(self._job_run(wf, {}, repo="autom8y/not-listed")["rc"], 0)
                self.assertEqual(self._job_run(wf, _both(clean), account="")["rc"], 2)
                self.assertEqual(self._job_run(wf, _both(clean), account=OTHER_ACCOUNT)["rc"], 3)

    def test_canonical_off_main_refused_only_in_the_reusable_job(self) -> None:
        """F-1, both sides: the reusable job refuses an off-main canonical SHA; the wrapper does not."""
        clean = _both(render_lock(clean_packages()))
        reusable = self._job_run(WORKFLOW, clean, canonical_on_main=False)
        self.assertEqual(reusable["rc"], 2, msg=reusable)
        self.assertIn("not reachable from autom8y-workflows main", str(reusable["out"]))
        self.assertEqual(self._job_run(WRAPPER, clean, canonical_on_main=False)["rc"], 0)
        self.assertEqual(self._job_run(WORKFLOW, clean, canonical_on_main=True)["rc"], 0)

    def test_real_policy_refuses_the_synthetic_account_with_exit_3(self) -> None:
        for wf in self.WORKFLOWS:
            with self.subTest(workflow=wf.name):
                outcome = self._job_run(wf, _both(render_lock(clean_packages())), policy=_real_policy())
                self.assertEqual(outcome["rc"], 3, msg=outcome)
                self.assertNotIn(_real_policy()["account_sha256"], str(outcome["out"]))

    def test_every_satellite_key_refuses_pypi_and_passes_clean(self) -> None:
        for repo in SATELLITES + ("autom8y/not-listed",):
            with self.subTest(repo=repo):
                self.assertTrue(self._job_run(WRAPPER, _both(render_lock(clean_packages() + [pypi_pkg("certifi")])), repo=repo)["job_fails"])
                self.assertFalse(self._job_run(WRAPPER, _both(render_lock(clean_packages())), repo=repo)["job_fails"])


CI_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "ci.yml"
CI_COMMAND = "python3 -B -S -m unittest -v tests.test_check_lock_sources"


class CiJob(unittest.TestCase):
    """F-4: this repository's CI runs the suite with the same command the run log records."""

    def test_ci_runs_the_recorded_command(self) -> None:
        job = _job_lines(CI_WORKFLOW, "lock-source-check-tests")
        self.assertEqual(_fields(job, "run"), [CI_COMMAND])
        self.assertEqual(_job_key(job, "timeout-minutes"), ["10"])

    def test_the_command_runs_standard_library_only(self) -> None:
        # -S keeps site-packages out: the PyYAML cross-check must skip, whatever is installed.
        self.assertIn(" -S ", f" {CI_COMMAND} ")
        self.assertIn(" -B ", f" {CI_COMMAND} ")
        if sys.flags.no_site:
            with self.assertRaises(ImportError):
                import yaml  # type: ignore[import-untyped]  # noqa: F401


if __name__ == "__main__":
    unittest.main()
