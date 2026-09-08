"""Fail-closed scanner proposed for retained setup-uv caches.

It reports categories only, never paths, file contents or credential values.
"""
import argparse
import base64
import os
import re
import stat
import sys
from pathlib import Path


URL_CREDENTIAL = re.compile(r"https?://[^/\s:@]+:[^/\s@]+@")


def fail(message):
    print(f"credential-cache scan failed: {message}", file=sys.stderr)
    return 1


def scan_file(path, root, token):
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except OSError:
        return "unreadable regular cache file"
    try:
        chunks = []
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
        content = b"".join(chunks)
    finally:
        os.close(descriptor)
    encoded = base64.b64encode(b"aws:" + token.encode("utf-8"))
    text = content.decode("utf-8", errors="replace")
    if token.encode("utf-8") in content:
        return "raw token in cache file"
    if encoded in content:
        return "base64 AWS token in cache file"
    if URL_CREDENTIAL.search(text):
        return "credentialed URL in cache file"
    return None


def scan(cache_dir, home, token):
    root = Path(cache_dir)
    try:
        root_stat = root.lstat()
    except OSError:
        return ["cannot stat cache directory"]
    if stat.S_ISLNK(root_stat.st_mode) or not stat.S_ISDIR(root_stat.st_mode):
        return ["cache directory is not a real directory"]

    root = root.resolve()
    findings = []
    def walk_error(_):
        findings.append("unreadable cache subtree")
    for directory, directories, names in os.walk(root, followlinks=False, onerror=walk_error):
        directory_path = Path(directory)
        for name in directories + names:
            path = directory_path / name
            try:
                mode = path.lstat().st_mode
            except OSError:
                findings.append("cannot stat cache file")
                continue
            if stat.S_ISLNK(mode):
                try:
                    target = path.resolve(strict=True)
                    target.relative_to(root)
                    if not (target.is_dir() or target.is_file()):
                        findings.append("unsupported cache symlink target")
                except (OSError, RuntimeError, ValueError):
                    findings.append("external or unresolved cache symlink")
                # uv links wheel entries to physical archive-v0 directories.
                # Physical targets are scanned by the non-following root walk.
                continue
            if stat.S_ISREG(mode):
                if name in {".netrc", "auth.toml", "credentials.toml"}:
                    findings.append("authentication file in cache")
                finding = scan_file(path, root, token)
                if finding:
                    findings.append(finding)
            elif not stat.S_ISDIR(mode):
                findings.append("unsupported cache filesystem entry")

    for path in (
        Path(home) / ".netrc",
        Path(home) / ".config" / "uv" / "auth.toml",
        Path(home) / ".config" / "uv" / "credentials.toml",
        Path(home) / ".cache" / "uv" / "auth.toml",
    ):
        try:
            mode = path.lstat().st_mode
        except FileNotFoundError:
            continue
        except OSError:
            findings.append("cannot stat authentication path")
            continue
        if stat.S_ISLNK(mode) or not stat.S_ISREG(mode):
            findings.append("unsafe authentication path")
        else:
            findings.append("authentication file present")
    return findings


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--cache-dir", required=True)
    parser.add_argument("--home", default=str(Path.home()))
    arguments = parser.parse_args()
    token = os.environ.get("CODEARTIFACT_TOKEN")
    if not token:
        return fail("CodeArtifact token is unavailable to scanner")
    findings = scan(arguments.cache_dir, arguments.home, token)
    if findings:
        for finding in findings:
            fail(finding)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
