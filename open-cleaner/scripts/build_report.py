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


def configure_text_output() -> None:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")


def render_report(analysis: dict, template: str, interactive_config: object = None) -> str:
    validate_analysis(analysis)
    if "__REPORT_DATA__" not in template or "__DELETE_CONFIG__" not in template:
        raise ContractError("报告模板缺少数据占位符")
    return template.replace("__REPORT_DATA__", json_for_script(analysis)).replace(
        "__DELETE_CONFIG__", json_for_script(interactive_config)
    )


def build_report(source: str, output: str) -> Path:
    analysis = load_json_object(source)
    template = TEMPLATE.read_text(encoding="utf-8")
    rendered = render_report(analysis, template)
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
    except (ContractError, OSError) as exc:
        print(f"报告生成失败：{exc}", file=sys.stderr)
        raise SystemExit(1) from exc
    print(f"报告已生成：{destination}")
    if sys.platform.startswith("win"):
        print(f'打开：start "" "{destination}"')
    else:
        print(f"打开：open '{destination}'")


if __name__ == "__main__":
    main()
