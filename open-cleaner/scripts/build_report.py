#!/usr/bin/env python3
"""Validate an analysis JSON and build a standalone read-only HTML report.

Usage:
    build_report.py <analysis.json> [output.html]
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
TEMPLATE = HERE.parent / "assets" / "report_template.html"

if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

from contracts import ContractError, json_for_script, load_json_object, validate_analysis  # noqa: E402
from file_ops import OperationLog  # noqa: E402
from policy import PolicyError, build_action_plan, build_decision  # noqa: E402


def configure_text_output() -> None:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")


def render_report(
    analysis: dict,
    template: str,
    interactive_config: object = None,
    decision: object = None,
) -> str:
    validate_analysis(analysis)
    required_placeholders = ("__REPORT_DATA__", "__DECISION_DATA__", "__DELETE_CONFIG__")
    missing = [placeholder for placeholder in required_placeholders if placeholder not in template]
    if missing:
        raise ContractError("报告模板缺少数据占位符：" + ", ".join(missing))
    if decision is None:
        decision = {
            **build_decision(analysis, [], []),
            "authorized": [],
            "rejected_items": [],
            "history": {"status": "empty", "entries": [], "completed": 0, "failed": 0, "disk_delta_bytes": 0},
        }
    rendered = (
        template.replace("__REPORT_DATA__", json_for_script(analysis))
        .replace("__DECISION_DATA__", json_for_script(decision))
        .replace("__DELETE_CONFIG__", json_for_script(interactive_config))
    )
    # A partially rendered template would otherwise look valid while silently
    # dropping one of the data channels needed by the report.
    leftovers = [placeholder for placeholder in required_placeholders if placeholder in rendered]
    if leftovers:
        raise ContractError("报告模板仍包含未替换占位符：" + ", ".join(leftovers))
    return rendered


def build_report(source: str, output: str) -> Path:
    if sys.platform != "darwin":
        raise ContractError(f"当前版本仅支持 macOS：{sys.platform}")
    analysis = load_json_object(source)
    validate_analysis(analysis)
    plan = build_action_plan(
        analysis,
        home=str(analysis["system"]["home"]),
        platform="darwin",
        purpose="dry-run",
    )
    decision = {
        **plan["decision"],
        "authorized": [
            {"mode": item["mode"], "path": item["path"], "size_estimate_bytes": item.get("size_estimate_bytes", 0)}
            for item in plan["actions"]
        ],
        "rejected_items": [
            {
                "mode": item["mode"], "path": item["path"], "code": item["code"],
                "message": item["message"], "size_estimate_bytes": item.get("size_estimate_bytes", 0),
            }
            for item in plan["rejected"]
        ],
        "history": OperationLog().recent(),
    }
    template = TEMPLATE.read_text(encoding="utf-8")
    rendered = render_report(analysis, template, decision=decision)
    destination = Path(output).expanduser()
    destination.write_text(rendered, encoding="utf-8")
    return destination


def main() -> None:
    configure_text_output()
    if len(sys.argv) not in (2, 3):
        print(__doc__)
        raise SystemExit(2)
    output = sys.argv[2] if len(sys.argv) == 3 else os.path.expanduser("~/Desktop/storage-report.html")
    try:
        destination = build_report(sys.argv[1], output)
    except (ContractError, PolicyError, OSError) as exc:
        print(f"报告生成失败：{exc}", file=sys.stderr)
        raise SystemExit(1) from exc
    print(f"报告已生成：{destination}")
    print(f"打开：open '{destination}'")


if __name__ == "__main__":
    main()
