#!/usr/bin/env python3
"""Run the uv.lock source check over each checked-out tree of the caller.

This is the one runner both lock-sources entry points use: the lock-sources job of
satellite-ci-reusable.yml and the standalone lock-sources-required.yml (the H-41 required
workflow). Both fetch this file, check_lock_sources.py and the shared policy file from
autom8y-workflows through the same sparse checkout, so they run identical code and policy.

Usage (from the job's workspace):
    run_lock_sources.py --canonical DIR --tree LABEL=PATH [--tree LABEL=PATH ...]

* ``--canonical``: the autom8y-workflows sparse checkout. The runner reads
  ``DIR/.github/scripts/check_lock_sources.py`` and ``DIR/.github/lock-sources/policy.json``
  from it, never from the caller's tree.
* ``--tree``: a checkout of the caller to check, for example ``github.sha=caller-sha`` and
  ``PR-head=caller-pr-head``. Every tree is checked and every one must pass.
* ``--require-canonical-on-main`` (the reusable job only): refuse, with exit 2, unless the
  canonical checkout's HEAD is reachable from ``refs/remotes/origin/main``. The reusable
  job's canonical ref is caller-supplied (``inputs.autom8y_workflows_sha``), so this stops a
  caller from pointing it at an off-main or fork-network commit with a permissive policy.
  The H-41 wrapper does not pass it: its ref is the ruleset's pinned commit, and on a pull
  request in autom8y-workflows itself that commit is not on main yet.

The repository key and the account come from the step's own ``env:`` block, which the
calling workflow file sets (a caller cannot set env on a ``uses:`` job):

* LOCK_SOURCES_REPO: ``${{ github.repository }}``.
* LOCK_SOURCES_ACCOUNT: ``${{ vars.AWS_ACCOUNT_ID }}``. vars resolves to the CALLER
  repository's (and org's) variables, so the pinned ``account_sha256`` in policy.json is
  what binds the account.

The runner passes both to check_lock_sources.py as argv, with the policy's account hash
and repository table. check_lock_sources.py itself reads nothing from the environment.

Exit code: the worst (highest) exit over all trees, or:
* 2 if the policy file or the check script is missing or malformed;
* 2 with "uv.lock missing for a listed repository; refusing" when the repository is a key
  in the policy's table and no tree has a uv.lock;
* 0 with a notice when the repository is not in the table and no tree has a uv.lock;
* 1 for a tree whose uv.lock is missing while another tree has one;
* 2 for a missing or malformed repository name, and 2 for a NEAR-MATCH (below).

Repository matching (F-3). A renamed listed satellite must not silently become unlisted,
because an unlisted repository with no uv.lock exits 0. So the repository is matched to
the policy table in three steps:

1. Exact key, or a key that is equal under ``str.casefold()`` (GitHub names are
   case-insensitive): the repository is LISTED under that key, and the checker is given
   the key as it is written in policy.json.
2. Otherwise, a NEAR-MATCH of any listed key is refused with exit 2. Names are compared
   casefolded. A repository nearly matches a key when any of these holds:
   a. they are equal once ``-``, ``_`` and ``.`` are removed from both
      (``autom8y/autom8y_sms``, ``autom8y/autom8ysms``);
   b. the owner is the same and the names are one edit apart (Levenshtein distance 1:
      ``autom8y/autom8y-sma``, ``autom8y/autom8y-sm``, ``autom8y/autom8y-smss``);
   c. the owner is the same and the repository's name is the listed name plus a suffix
      that starts with ``-``, ``_`` or ``.`` (``autom8y/autom8y-sms-v2``). Only this
      direction counts, so a shorter, more general name (``autom8y/autom8y``) is not a
      near-match of ``autom8y/autom8y-sms``;
   d. the name is the same and the owner differs (a transfer: ``someone/autom8y-sms``).
3. Otherwise the repository is UNLISTED: CodeArtifact only, and a missing uv.lock gives a
   notice and exit 0.

Python 3.11+ standard library only. No network. Output never prints the account.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from collections.abc import Sequence
from pathlib import Path

REPO_ENV = "LOCK_SOURCES_REPO"
ACCOUNT_ENV = "LOCK_SOURCES_ACCOUNT"
SCRIPT_REL = Path(".github/scripts/check_lock_sources.py")
POLICY_REL = Path(".github/lock-sources/policy.json")

EXIT_OK = 0
EXIT_VIOLATION = 1
EXIT_USAGE = 2

LISTED_MISSING_MESSAGE = "uv.lock missing for a listed repository; refusing"

_SHA256_RE = re.compile(r"[0-9a-f]{64}", re.ASCII)
_REPO_KEY_RE = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", re.ASCII)
_MASK_RE = re.compile(r"\d{12,}")


class PolicyError(Exception):
    """The shared policy file is missing or malformed."""


def say(line: str) -> None:
    print(_MASK_RE.sub("<acct>", line), flush=True)


def load_policy(path: Path) -> tuple[str, dict]:
    """Return ``(account_sha256, repositories)`` from the shared policy file."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise PolicyError(f"cannot read the policy file ({exc.strerror or exc})") from None
    except json.JSONDecodeError as exc:
        raise PolicyError(f"the policy file is not valid JSON ({exc.msg})") from None
    if not isinstance(data, dict) or set(data) != {"_owner", "account_sha256", "repositories"}:
        raise PolicyError("the policy file must hold exactly _owner, account_sha256 and repositories")
    if not isinstance(data["_owner"], str) or not data["_owner"].strip():
        raise PolicyError("the policy file's _owner is empty")
    if not isinstance(data["account_sha256"], str) or not _SHA256_RE.fullmatch(data["account_sha256"]):
        raise PolicyError("the policy file's account_sha256 is not lowercase hex of the right length")
    repositories = data["repositories"]
    if not isinstance(repositories, dict):
        raise PolicyError("the policy file's repositories is not an object")
    for key in repositories:
        if not _REPO_KEY_RE.fullmatch(key):
            raise PolicyError(f"the policy file's repositories key {key!r} is not owner/name")
    if len({key.casefold() for key in repositories}) != len(repositories):
        raise PolicyError("the policy file's repositories has two keys that differ only in case")
    return data["account_sha256"], repositories


def _one_edit_apart(a: str, b: str) -> bool:
    """Levenshtein distance exactly 1."""
    if a == b or abs(len(a) - len(b)) > 1:
        return False
    if len(a) == len(b):
        return sum(x != y for x, y in zip(a, b)) == 1
    short, long_ = (a, b) if len(a) < len(b) else (b, a)
    return any(long_[:i] + long_[i + 1:] == short for i in range(len(long_)))


def _strip_separators(text: str) -> str:
    return re.sub(r"[-_.]", "", text)


def _near(repo: str, key: str) -> bool:
    """The near-match rule (2a-2d in the module docstring), on casefolded names."""
    owner, _, name = repo.casefold().partition("/")
    key_owner, _, key_name = key.casefold().partition("/")
    if _strip_separators(owner + "/" + name) == _strip_separators(key_owner + "/" + key_name):
        return True
    if owner == key_owner:
        if _one_edit_apart(name, key_name):
            return True
        if any(name.startswith(key_name + sep) for sep in "-_."):
            return True
    elif name == key_name:
        return True
    return False


def resolve_repo(repo: str, repositories: dict) -> tuple[str | None, str | None]:
    """Return ``(listed_key, near_key)``: the policy key this repository is, or the key it nearly is."""
    if repo in repositories:
        return repo, None
    folded = {key.casefold(): key for key in repositories}
    if repo.casefold() in folded:
        return folded[repo.casefold()], None
    for key in sorted(repositories):
        if _near(repo, key):
            return None, key
    return None, None


def parse_tree(value: str) -> tuple[str, Path]:
    label, sep, path = value.partition("=")
    if not sep or not label or not path:
        raise argparse.ArgumentTypeError(f"--tree must be LABEL=PATH, got {value!r}")
    return label, Path(path)


def canonical_on_main_problem(canonical: Path) -> str | None:
    """Why the canonical checkout's HEAD cannot be shown to be on autom8y-workflows main."""

    def git(*args: str) -> int:
        return subprocess.run(["git", "-C", str(canonical), *args], capture_output=True, check=False).returncode

    if git("rev-parse", "--verify", "--quiet", "refs/remotes/origin/main^{commit}") != 0:
        return "the canonical checkout has no refs/remotes/origin/main to verify against (fetch-depth: 0 is required)"
    rc = git("merge-base", "--is-ancestor", "HEAD", "refs/remotes/origin/main")
    if rc == 1:
        return "the canonical autom8y-workflows SHA is not reachable from autom8y-workflows main"
    if rc != 0:
        return "could not verify that the canonical autom8y-workflows SHA is on main"
    return None


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0], allow_abbrev=False)
    parser.add_argument("--canonical", required=True, type=Path, help="the autom8y-workflows sparse checkout")
    parser.add_argument("--tree", required=True, action="append", type=parse_tree, help="LABEL=PATH, repeatable")
    parser.add_argument(
        "--require-canonical-on-main",
        action="store_true",
        help="refuse unless the canonical HEAD is reachable from origin/main (the reusable job only)",
    )
    args = parser.parse_args(argv)

    script = args.canonical / SCRIPT_REL
    if not script.is_file():
        say(
            "::error::canonical autom8y-workflows checkout has no check_lock_sources.py"
            " (is the canonical ref the literal autom8y-workflows SHA, at or after PR-1?)"
        )
        return EXIT_USAGE
    if args.require_canonical_on_main:
        problem = canonical_on_main_problem(args.canonical)
        if problem is not None:
            say(f"::error::{problem}; refusing")
            return EXIT_USAGE
    try:
        account_sha256, repositories = load_policy(args.canonical / POLICY_REL)
    except PolicyError as exc:
        say(f"::error::{exc}; refusing")
        return EXIT_USAGE

    repo = os.environ.get(REPO_ENV, "")
    account = os.environ.get(ACCOUNT_ENV, "")

    if not _REPO_KEY_RE.fullmatch(repo):
        say("::error::the repository name (LOCK_SOURCES_REPO) is missing or not owner/name; refusing")
        return EXIT_USAGE
    listed_key, near_key = resolve_repo(repo, repositories)
    if near_key is not None:
        say(
            f"::error::repository {repo!r} nearly matches the listed {near_key!r} but is not it; refusing"
            " (a renamed or transferred satellite must be renamed in policy.json too)"
        )
        return EXIT_USAGE
    checker_repo = listed_key if listed_key is not None else repo

    if not any((tree / "uv.lock").is_file() for _, tree in args.tree):
        if listed_key is not None:
            say(f"::error::{LISTED_MISSING_MESSAGE}")
            return EXIT_USAGE
        say("::notice::no uv.lock in the caller repository; the lock-source check does not apply")
        return EXIT_OK

    worst = EXIT_OK
    for label, tree in args.tree:
        lock = tree / "uv.lock"
        if not lock.is_file():
            say(f"::error::uv.lock is missing at the {label} checkout but present at another")
            worst = max(worst, EXIT_VIOLATION)
            continue
        say(f"::group::uv.lock at {label}")
        command = [
            sys.executable, "-I", str(script), str(lock),
            "--repo", checker_repo,
            "--account", account,
            "--account-sha256", account_sha256,
            "--allowlist-json", json.dumps(repositories),
        ]
        rc = subprocess.run(command, check=False).returncode
        if rc < 0:  # killed by a signal: never let a negative code lose to max()
            rc = EXIT_USAGE
        say("::endgroup::")
        if rc != 0:
            say(f"::error::uv.lock source check at {label} exited {rc}")
        worst = max(worst, rc)
    return worst


if __name__ == "__main__":
    try:
        sys.exit(main())
    except SystemExit:
        raise
    except Exception as exc:  # report masked; never let a traceback print an unmasked value
        say(f"::error::the lock-source runner could not run: {type(exc).__name__}: {exc}")
        sys.exit(EXIT_USAGE)
