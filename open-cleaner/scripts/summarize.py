#!/usr/bin/env python3
"""Print a concise Chinese decision summary from analysis and action-plan JSON."""
from __future__ import annotations

import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

from contracts import (  # noqa: E402
    ContractError,
    canonical_sha256,
    load_json_object,
    validate_action_plan,
    validate_analysis,
)


def size_label(value: int) -> str:
    amount = float(max(0, int(value)))
    units = ("B", "KB", "MB", "GB", "TB")
    unit = 0
    while amount >= 1024 and unit < len(units) - 1:
        amount /= 1024
        unit += 1
    return f"{amount:.0f} {units[unit]}" if unit < 2 else f"{amount:.1f} {units[unit]}"


def summarize(analysis: dict, plan: dict) -> str:
    validate_analysis(analysis)
    validate_action_plan(plan)
    if plan["source_analysis_sha256"] != canonical_sha256(analysis):
        raise ContractError("action plan 不属于当前 analysis")
    decision = plan["decision"]
    actionable = decision["actionable"]
    safe_count = actionable["trash"]["count"]
    safe_bytes = actionable["trash"]["size_bytes"]
    reviewed_count = actionable["reviewed_trash"]["count"]
    reviewed_bytes = actionable["reviewed_trash"]["size_bytes"]
    blocked = decision["blocked"]
    coverage = analysis["coverage_assessment"]
    groups = (analysis.get("owner_groups") or [])[:5]
    reasons = blocked.get("reasons") or []
    lines = [
        f"结论：当前可安全移入废纸篓 {safe_count} 项，估算 {size_label(safe_bytes)}；"
        f"另有 {reviewed_count} 项、估算 {size_label(reviewed_bytes)} 需要逐项人工复核。",
        f"覆盖：{coverage['label']}（完成 {coverage['completed_ratio'] * 100:.1f}% 的扫描根，"
        f"权限拒绝 {coverage['permission_denied']} 个）。",
    ]
    if blocked["count"]:
        reason_text = "；".join(
            f"{item['message']} {item['count']} 项" for item in reasons[:3]
        )
        lines.append(
            f"完全不可行动：{blocked['count']} 项，估算 {size_label(blocked['size_bytes'])}。{reason_text}"
        )
    if groups:
        lines.append(
            "最值得查看："
            + "；".join(
                f"{group['owner']} {group['size']}（{group['summary']}）" for group in groups
            )
        )
    apfs = analysis["system"]["apfs_diagnostics"]
    lines.append(
        "空间释放提醒：移入废纸篓不会立即释放内容占用；"
        f"本地快照 {apfs['local_snapshots']['count']} 个，"
        f"已删除但仍打开的文件 {apfs['open_unlinked_files']['count']} 个。"
    )
    lines.append("所有者工具命令仅展示，OpenCleaner 不会执行，也不会为这些目标开放删除入口。")
    return "\n".join(lines)


def main() -> None:
    if len(sys.argv) != 3:
        print("Usage: summarize.py <analysis.json> <action-plan.json>", file=sys.stderr)
        raise SystemExit(2)
    try:
        analysis = load_json_object(sys.argv[1])
        plan = load_json_object(sys.argv[2])
        print(summarize(analysis, plan))
    except ContractError as exc:
        print(f"摘要生成失败：{exc}", file=sys.stderr)
        raise SystemExit(1) from exc


if __name__ == "__main__":
    main()
