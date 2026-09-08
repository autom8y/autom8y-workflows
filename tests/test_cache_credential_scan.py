import base64
import contextlib
import io
import os
import re
import tempfile
import unittest
from unittest import mock
from pathlib import Path
import importlib.util


SPEC = importlib.util.spec_from_file_location(
    "scanner", Path(__file__).resolve().parent.parent / "scripts/cache_credential_scan.py"
)
scanner = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(scanner)


class ScannerTests(unittest.TestCase):
    token = "synthetic-secret-token"

    def test_all_inline_scanners_match_tested_source(self):
        repo = Path(__file__).resolve().parent.parent
        workflow = (repo / ".github/workflows/satellite-ci-reusable.yml").read_text()
        bodies = re.findall(r"          python3 -[^\n]*<<'PYTHON'\n(.*?)          PYTHON", workflow, re.S)
        self.assertEqual(len(bodies), 5)
        source = (repo / "scripts/cache_credential_scan.py").read_text().strip()
        for body in bodies:
            plain = "\n".join(line[10:] if line.startswith("          ") else line for line in body.splitlines())
            self.assertEqual(plain.strip(), source)

    def scan(self, content=None, auth=None, unreadable=False):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            cache = root / "cache"
            cache.mkdir()
            if content is not None:
                target = cache / "wheel"
                target.write_bytes(content)
                if unreadable:
                    target.chmod(0)
            if auth:
                target = root / auth
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text("synthetic auth")
            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr):
                findings = scanner.scan(cache, root, self.token)
            if content is not None and unreadable:
                target.chmod(0o600)
            return findings, stderr.getvalue()

    def test_raw_token_rejected_without_emission(self):
        findings, output = self.scan(self.token.encode())
        self.assertTrue(findings)
        self.assertNotIn(self.token, " ".join(findings) + output)

    def test_base64_aws_token_rejected_without_emission(self):
        value = base64.b64encode(f"aws:{self.token}".encode())
        findings, output = self.scan(value)
        self.assertTrue(findings)
        self.assertNotIn(self.token, " ".join(findings) + output)

    def test_credentialed_url_rejected_without_emission(self):
        findings, output = self.scan(b"https://user:password@example.invalid/wheel")
        self.assertTrue(findings)
        self.assertNotIn("password", " ".join(findings) + output)

    def test_auth_files_rejected_without_reading_values(self):
        for auth in (".netrc", ".config/uv/auth.toml", ".cache/uv/auth.toml"):
            findings, output = self.scan(auth=auth)
            self.assertTrue(findings)
            self.assertNotIn("synthetic auth", " ".join(findings) + output)

    def test_cache_auth_file_rejected_without_reading_values(self):
        findings, output = self.scan(b"synthetic auth")
        self.assertTrue(findings == [])
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            cache = root / "cache" / "uv"
            cache.mkdir(parents=True)
            (cache / "credentials.toml").write_text("synthetic auth")
            findings = scanner.scan(root / "cache", root, self.token)
            self.assertTrue(findings)
            self.assertNotIn("synthetic auth", " ".join(findings))

    def test_benign_wheel_cache_passes(self):
        findings, _ = self.scan(b"benign wheel bytes")
        self.assertEqual(findings, [])

    def test_cache_symlink_outside_root_is_rejected_without_following(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            cache = root / "cache"
            cache.mkdir()
            outside = root / "outside-secret"
            outside.write_text(self.token)
            (cache / "external").symlink_to(outside)
            findings = scanner.scan(cache, root, self.token)
            self.assertTrue(findings)
            self.assertNotIn(self.token, " ".join(findings))

    def test_unreadable_regular_file_fails_closed(self):
        # Mock os.open because the test runner may execute as a user that can
        # still read chmod-000 files.
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            cache = root / "cache"
            cache.mkdir()
            (cache / "wheel").write_bytes(b"benign")
            original = os.open
            def blocked(path, flags):
                if Path(path).name == "wheel":
                    raise PermissionError("synthetic")
                return original(path, flags)
            with mock.patch.object(scanner.os, "open", side_effect=blocked):
                findings = scanner.scan(cache, root, self.token)
            self.assertTrue(findings)

    def test_external_directory_symlink_rejected_without_reading(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            cache, outside = root / "cache", root / "outside"
            cache.mkdir()
            outside.mkdir()
            (outside / "secret").write_text(self.token)
            (cache / "external").symlink_to(outside, target_is_directory=True)
            with mock.patch.object(scanner, "scan_file", side_effect=AssertionError("outside read")):
                self.assertTrue(scanner.scan(cache, root, self.token))

    def test_real_uv_directory_link_shape_scans_physical_archive(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            cache = root / "cache"
            target = cache / "archive-v0" / "entry"
            target.mkdir(parents=True)
            wheel = cache / "wheels-v6"
            wheel.mkdir()
            (wheel / "link").symlink_to(target, target_is_directory=True)
            payload = target / "payload"
            payload.write_text("benign")
            self.assertEqual(scanner.scan(cache, root, self.token), [])
            payload.write_text(self.token)
            self.assertTrue(scanner.scan(cache, root, self.token))

    def test_unreadable_subtree_fails_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            def denied(*args, **kwargs):
                kwargs["onerror"](PermissionError("synthetic"))
                return iter(())
            with mock.patch.object(scanner.os, "walk", side_effect=denied):
                self.assertTrue(scanner.scan(temporary, temporary, self.token))

    def test_cli_reads_token_from_environment_not_argv(self):
        with tempfile.TemporaryDirectory() as temporary:
            cache = Path(temporary) / "cache"
            cache.mkdir()
            with mock.patch.dict(scanner.os.environ, {"CODEARTIFACT_TOKEN": self.token}, clear=True), \
                 mock.patch.object(scanner.sys, "argv", ["scanner", "--cache-dir", str(cache), "--home", temporary]):
                self.assertEqual(scanner.main(), 0)


if __name__ == "__main__":
    unittest.main()
