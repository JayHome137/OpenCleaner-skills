#!/usr/bin/env python3
"""Scan tracked text files for accidental personal data or credentials."""
from __future__ import annotations

import re
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PATTERNS = (
    (
        "personal absolute path",
        re.compile(
            r"/Users/(?!(?:example|test|demo|user|sample|fixture)"
            r"[A-Za-z0-9._-]*(?:[^A-Za-z0-9._-]|$))"
            r"[A-Za-z0-9._-]+"
        ),
    ),
    ("email address", re.compile(r"[A-Z0-9._%+-]+@(?!example\.invalid\b)[A-Z0-9.-]+\.[A-Z]{2,}", re.I)),
    ("private key", re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----")),
    ("bearer token", re.compile(r"\bBearer\s+[A-Za-z0-9._~-]{20,}")),
)


def tracked_files() -> list[Path]:
    try:
        result = subprocess.run(
            ["git", "ls-files", "-z"], cwd=ROOT, check=True, capture_output=True
        )
    except (OSError, subprocess.CalledProcessError):
        # Release archives do not contain .git metadata; scan the extracted
        # package tree instead of silently skipping the privacy gate.
        return sorted(
            path
            for path in ROOT.rglob("*")
            if path.is_file() and ".git" not in path.parts
        )
    return [ROOT / name for name in result.stdout.decode().split("\0") if name]


def main() -> int:
    findings: list[str] = []
    for path in tracked_files():
        if path.resolve() == Path(__file__).resolve():
            continue
        try:
            data = path.read_bytes()
        except OSError as exc:
            findings.append(f"{path.relative_to(ROOT)}: cannot read: {exc}")
            continue
        if b"\0" in data:
            continue
        text = data.decode("utf-8", errors="replace")
        for label, pattern in PATTERNS:
            for match in pattern.finditer(text):
                line = text.count("\n", 0, match.start()) + 1
                findings.append(f"{path.relative_to(ROOT)}:{line}: {label}")
    if findings:
        for finding in findings:
            print(f"ERROR: {finding}")
        return 1
    print("OpenCleaner privacy scan passed (tracked text only)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
