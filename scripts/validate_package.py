#!/usr/bin/env python3
"""Validate the GitHub package layout for the storage-analyzer skill."""
from __future__ import annotations

import json
import py_compile
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SKILL_DIR = ROOT / "storage-analyzer"

REQUIRED_FILES = [
    SKILL_DIR / "SKILL.md",
    SKILL_DIR / "agents" / "openai.yaml",
    SKILL_DIR / "assets" / "report_template.html",
    SKILL_DIR / "references" / "macos.md",
    SKILL_DIR / "references" / "windows.md",
    SKILL_DIR / "scripts" / "build_report.py",
    SKILL_DIR / "scripts" / "scan.py",
    SKILL_DIR / "scripts" / "server.py",
    ROOT / "README.md",
    ROOT / ".gitignore",
]

PYTHON_FILES = [
    SKILL_DIR / "scripts" / "build_report.py",
    SKILL_DIR / "scripts" / "scan.py",
    SKILL_DIR / "scripts" / "server.py",
]


def fail(message: str) -> None:
    print(f"ERROR: {message}", file=sys.stderr)
    raise SystemExit(1)


def check_required_files() -> None:
    missing = [str(path.relative_to(ROOT)) for path in REQUIRED_FILES if not path.exists()]
    if missing:
        fail("missing required files: " + ", ".join(missing))


def check_skill_frontmatter() -> None:
    text = (SKILL_DIR / "SKILL.md").read_text(encoding="utf-8")
    if not text.startswith("---\n"):
        fail("storage-analyzer/SKILL.md must start with YAML frontmatter")
    frontmatter = text.split("---", 2)[1]
    if "name: storage-analyzer" not in frontmatter:
        fail("SKILL.md frontmatter must include name: storage-analyzer")
    if "description:" not in frontmatter:
        fail("SKILL.md frontmatter must include description")


def check_openai_yaml() -> None:
    text = (SKILL_DIR / "agents" / "openai.yaml").read_text(encoding="utf-8")
    required_snippets = [
        'display_name: "Storage Analyzer"',
        'default_prompt: "Use $storage-analyzer',
        "allow_implicit_invocation: true",
    ]
    for snippet in required_snippets:
        if snippet not in text:
            fail(f"agents/openai.yaml missing expected snippet: {snippet}")


def check_python_syntax() -> None:
    for path in PYTHON_FILES:
        py_compile.compile(str(path), doraise=True)


def check_static_report_generation() -> None:
    sample = {
        "generated_at": "2026-06-05 00:00:00",
        "system": {
            "os": "macOS",
            "disk_total": "100 GB",
            "disk_used": "60 GB",
            "disk_free": "40 GB",
        },
        "top5": [],
        "green": [],
        "yellow": [],
        "red": [],
        "summary": {
            "overview": "Sample validation report.",
            "tier_stats": {"green": "约 0 GB", "yellow": "约 0 GB", "red": "约 0 GB"},
            "priority": [],
            "long_term": [],
        },
    }
    with tempfile.TemporaryDirectory() as tmp:
        tmpdir = Path(tmp)
        analysis = tmpdir / "analysis.json"
        output = tmpdir / "report.html"
        analysis.write_text(json.dumps(sample, ensure_ascii=False), encoding="utf-8")
        result = subprocess.run(
            [sys.executable, str(SKILL_DIR / "scripts" / "build_report.py"), str(analysis), str(output)],
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        if result.returncode != 0:
            fail("build_report.py failed:\n" + result.stderr)
        html = output.read_text(encoding="utf-8")
        if "Sample validation report." not in html or "__REPORT_DATA__" in html:
            fail("static report output did not receive embedded sample data")


def main() -> None:
    check_required_files()
    check_skill_frontmatter()
    check_openai_yaml()
    check_python_syntax()
    check_static_report_generation()
    print("storage-analyzer package validation passed")


if __name__ == "__main__":
    main()
