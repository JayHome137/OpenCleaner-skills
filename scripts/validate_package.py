#!/usr/bin/env python3
"""Validate the distributable Skill layout, contracts, and safety invariants."""
from __future__ import annotations

import hashlib
import json
import py_compile
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SKILL_DIR = ROOT / "open-cleaner"
SCRIPTS_DIR = SKILL_DIR / "scripts"

REQUIRED_FILES = [
    ROOT / "PROJECT_GOALS.md",
    ROOT / "THIRD_PARTY_NOTICES.md",
    ROOT / "docs" / "BASELINE.md",
    ROOT / "docs" / "ACCEPTANCE_MATRIX.md",
    ROOT / "docs" / "LICENSING_PLAN.md",
    ROOT / "docs" / "INDEPENDENCE_AUDIT.md",
    ROOT / "docs" / "PROVENANCE.md",
    ROOT / "docs" / "PERFORMANCE_BASELINE.md",
    ROOT / "docs" / "STATUS_AND_MOLE_GAP_AUDIT_2026-08-26.md",
    ROOT / "docs" / "ROADMAP.md",
    ROOT / "docs" / "SECURITY_AUDIT_2026-08-29.md",
    ROOT / "SECURITY.md",
    ROOT / "CONTRIBUTING.md",
    ROOT / "CODE_OF_CONDUCT.md",
    ROOT / "CHANGELOG.md",
    ROOT / "scripts" / "security_scan.py",
    ROOT / ".github" / "ISSUE_TEMPLATE" / "bug_report.yml",
    ROOT / ".github" / "ISSUE_TEMPLATE" / "feature_request.yml",
    ROOT / ".github" / "ISSUE_TEMPLATE" / "config.yml",
    ROOT / ".github" / "PULL_REQUEST_TEMPLATE.md",
    SKILL_DIR / "SKILL.md",
    SKILL_DIR / "agents" / "openai.yaml",
    SKILL_DIR / "assets" / "report_template.html",
    SKILL_DIR / "references" / "macos.md",
    SKILL_DIR / "references" / "windows.md",
    SKILL_DIR / "schemas" / "scan-result.schema.json",
    SKILL_DIR / "schemas" / "analysis.schema.json",
    SKILL_DIR / "schemas" / "action-plan.schema.json",
    SKILL_DIR / "rules" / "common.json",
    SKILL_DIR / "rules" / "macos.json",
    SKILL_DIR / "rules" / "windows.json",
    SCRIPTS_DIR / "build_report.py",
    SCRIPTS_DIR / "compare_reports.py",
    SCRIPTS_DIR / "browse.py",
    SCRIPTS_DIR / "classify.py",
    SCRIPTS_DIR / "contracts.py",
    SCRIPTS_DIR / "file_ops.py",
    SCRIPTS_DIR / "installers.py",
    SCRIPTS_DIR / "ownership.py",
    SCRIPTS_DIR / "policy.py",
    SCRIPTS_DIR / "project_artifacts.py",
    SCRIPTS_DIR / "project_stage.py",
    SCRIPTS_DIR / "rules.py",
    SCRIPTS_DIR / "scan.py",
    SCRIPTS_DIR / "scan_cache.py",
    SCRIPTS_DIR / "server.py",
    SCRIPTS_DIR / "settings.py",
    SCRIPTS_DIR / "summarize.py",
    SCRIPTS_DIR / "validate_plan.py",
    ROOT / ".github" / "workflows" / "macos-validation.yml",
    ROOT / ".github" / "workflows" / "release-assets.yml",
    ROOT / "README.md",
    ROOT / "README.en.md",
    ROOT / "LICENSE",
    ROOT / "NOTICE",
    ROOT / "VERSION",
    ROOT / ".gitignore",
    ROOT / "tests" / "windows_smoke.py",
    ROOT / "tests" / "macos_smoke.py",
    ROOT / "tests" / "fixtures" / "sample_analysis.json",
    ROOT / "tests" / "test_compare_reports.py",
    ROOT / "tests" / "test_contracts_v11.py",
    ROOT / "tests" / "test_scan_cache.py",
    ROOT / "scripts" / "benchmark_scan.py",
]


def fail(message: str) -> None:
    print(f"ERROR: {message}", file=sys.stderr)
    raise SystemExit(1)


def check_required_files() -> None:
    missing = [str(path.relative_to(ROOT)) for path in REQUIRED_FILES if not path.is_file()]
    if missing:
        fail("missing required files: " + ", ".join(missing))


def check_skill_frontmatter() -> None:
    text = (SKILL_DIR / "SKILL.md").read_text(encoding="utf-8")
    if not text.startswith("---\n"):
        fail("open-cleaner/SKILL.md must start with YAML frontmatter")
    frontmatter = text.split("---", 2)[1]
    for snippet in ("name: open-cleaner", "description:"):
        if snippet not in frontmatter:
            fail(f"SKILL.md frontmatter missing: {snippet}")


def check_openai_yaml() -> None:
    text = (SKILL_DIR / "agents" / "openai.yaml").read_text(encoding="utf-8")
    for snippet in (
        'display_name: "OpenCleaner"',
        'default_prompt: "使用 $open-cleaner',
        "allow_implicit_invocation: true",
    ):
        if snippet not in text:
            fail(f"agents/openai.yaml missing expected snippet: {snippet}")


def check_licensing() -> None:
    version = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
    if version != "1.2.0":
        fail(f"unexpected project version: {version}")

    license_text = (ROOT / "LICENSE").read_text(encoding="utf-8")
    normalized_license = license_text.replace("\r\n", "\n").replace("\r", "\n").encode("utf-8")
    license_sha256 = hashlib.sha256(normalized_license).hexdigest()
    expected_sha256 = "cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30"
    if license_sha256 != expected_sha256:
        fail("LICENSE content must match the official Apache License 2.0 plain text")

    notice = (ROOT / "NOTICE").read_text(encoding="utf-8")
    for snippet in (
        "OpenCleaner",
        "Copyright 2026 JayHome137",
        "Licensed under the Apache License, Version 2.0.",
        "THIRD_PARTY_NOTICES.md",
    ):
        if snippet not in notice:
            fail(f"NOTICE missing expected licensing text: {snippet}")

    third_party = (ROOT / "THIRD_PARTY_NOTICES.md").read_text(encoding="utf-8")
    for snippet in ("MIT License", "Copyright (c) 2026 数字生命卡兹克"):
        if snippet not in third_party:
            fail(f"THIRD_PARTY_NOTICES.md missing retained MIT notice: {snippet}")


def check_python_syntax() -> None:
    python_files = sorted(SCRIPTS_DIR.glob("*.py")) + sorted((ROOT / "tests").glob("*.py"))
    with tempfile.TemporaryDirectory(prefix="storage-pycompile-") as temporary:
        for index, path in enumerate(python_files):
            try:
                py_compile.compile(str(path), cfile=str(Path(temporary) / f"{index}.pyc"), doraise=True)
            except py_compile.PyCompileError as exc:
                fail(str(exc))


def check_json_files() -> None:
    for path in sorted((SKILL_DIR / "schemas").glob("*.json")) + sorted((SKILL_DIR / "rules").glob("*.json")):
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            fail(f"invalid JSON in {path.relative_to(ROOT)}: {exc}")
        if value.get("schema_version") not in ("1.0", "1.1") and "$schema" not in value:
            fail(f"missing schema version in {path.relative_to(ROOT)}")
        if path.parent.name == "rules":
            for index, rule in enumerate(value.get("rules", [])):
                for field in (
                    "id",
                    "platforms",
                    "root",
                    "min_depth",
                    "actions",
                    "classification",
                    "recovery",
                    "risk",
                    "non_targets",
                    "blocked_components",
                ):
                    if field not in rule:
                        fail(f"rule {path.name}[{index}] missing required field: {field}")


def check_no_permanent_delete_surface() -> None:
    runtime_files = [SCRIPTS_DIR / "server.py", SCRIPTS_DIR / "file_ops.py"]
    forbidden = ("shutil.rmtree", "os.remove(", "os.unlink(", 'mode == "rm"', "直接删除")
    for path in runtime_files:
        text = path.read_text(encoding="utf-8")
        for snippet in forbidden:
            if snippet in text:
                fail(f"permanent delete surface found in {path.relative_to(ROOT)}: {snippet}")
    template = (SKILL_DIR / "assets" / "report_template.html").read_text(encoding="utf-8")
    if "'rm'" in template or '"rm"' in template or 'data-mode="rm"' in template:
        fail("report template still exposes permanent delete")
    for legacy in ("data-paths", "authorizedPaths", "postAction"):
        if legacy in template:
            fail(f"report template still contains legacy path request logic: {legacy}")
    for required in (
        "本次操作历史", "历史操作摘要", "rule_non_targets", "disk_free_delta_bytes",
        "__DECISION_DATA__", "当前决策", "OpenCleaner 不会执行",
    ):
        if required not in template:
            fail(f"report template missing guarded result surface: {required}")


def check_macos_only_surface() -> None:
    skill = (SKILL_DIR / "SKILL.md").read_text(encoding="utf-8")
    metadata = (SKILL_DIR / "agents" / "openai.yaml").read_text(encoding="utf-8")
    if "macOS / Windows" in skill or "macOS 和 Windows" in metadata:
        fail("public Skill metadata still advertises Windows support")

    sys.path.insert(0, str(SCRIPTS_DIR))
    try:
        import classify
        import build_report
        import contracts
        import rules
        import scan
    except ImportError as exc:
        fail(f"runtime import failed: {exc}")

    rejected = 0
    for probe in (
        lambda: rules.normalized_platform("win32"),
        lambda: scan.scan_current(platform="win32"),
        lambda: classify.platform_from_scan({"system": {"os": "Windows 11"}}),
    ):
        try:
            probe()
        except (ValueError, contracts.ContractError, rules.RuleError):
            rejected += 1
    with patch("build_report.sys.platform", "win32"):
        try:
            build_report.build_report("unused.json", "unused.html")
        except contracts.ContractError:
            rejected += 1
    if rejected != 4:
        fail("Windows public runtime entry did not fail closed")

    action_schema = json.loads(
        (SKILL_DIR / "schemas" / "action-plan.schema.json").read_text(encoding="utf-8")
    )
    if action_schema["properties"]["platform"] != {"const": "darwin"}:
        fail("action-plan schema still permits a non-macOS platform")


def check_runtime_imports_and_static_report() -> None:
    sys.path.insert(0, str(SCRIPTS_DIR))
    try:
        import build_report
        import contracts
    except ImportError as exc:
        fail(f"runtime import failed: {exc}")
    sample = {
        "schema_version": "1.0",
        "source_scan_sha256": "0" * 64,
        "generated_at": "2026-08-22 00:00:00",
        "scan_seconds": 0,
        "system": {
            "os": "macOS",
            "home": "/Users/example",
            "disk_total": "100 GB",
            "disk_used": "60 GB",
            "disk_free": "40 GB",
            "disks": [],
        },
        "coverage": {"requested_roots": 1, "completed_roots": 1, "skipped_roots": 0},
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
    contracts.validate_analysis(sample)
    template = (SKILL_DIR / "assets" / "report_template.html").read_text(encoding="utf-8")
    html = build_report.render_report(sample, template)
    if "Sample validation report." not in html or "__REPORT_DATA__" in html:
        fail("static report output did not receive validated sample data")
    if "const SESSION = null" not in html or "const DECISION =" not in html:
        fail("static report did not receive the read-only decision/session boundary")
    for marker in ('data-mode="trash"', 'data-mode="reviewed_trash"', 'class="action-panel"'):
        if marker in html:
            fail(f"static report exposed a concrete operation control: {marker}")


def main() -> None:
    check_required_files()
    check_skill_frontmatter()
    check_openai_yaml()
    check_licensing()
    check_python_syntax()
    check_json_files()
    check_no_permanent_delete_surface()
    check_macos_only_surface()
    check_runtime_imports_and_static_report()
    print("open-cleaner package validation passed")


if __name__ == "__main__":
    main()
