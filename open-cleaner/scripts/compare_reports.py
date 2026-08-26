#!/usr/bin/env python3
"""Compare two read-only OpenCleaner analysis snapshots."""
from __future__ import annotations

import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

from contracts import ContractError, load_json_object, validate_analysis  # noqa: E402


def _totals(analysis: dict) -> dict[str, int]:
    return {
        tier: sum(int(item.get("size_bytes", 0) or 0) for item in analysis.get(tier, []))
        for tier in ("green", "yellow", "red")
    }


def compare(previous: dict, current: dict) -> dict:
    validate_analysis(previous)
    validate_analysis(current)
    before = _totals(previous)
    after = _totals(current)
    return {
        "previous_generated_at": previous.get("generated_at", ""),
        "current_generated_at": current.get("generated_at", ""),
        "tiers": {
            tier: {"before_bytes": before[tier], "after_bytes": after[tier], "delta_bytes": after[tier] - before[tier]}
            for tier in before
        },
        "total": {
            "before_bytes": sum(before.values()),
            "after_bytes": sum(after.values()),
            "delta_bytes": sum(after.values()) - sum(before.values()),
        },
        "coverage": {
            "previous": previous.get("coverage_assessment", {}).get("label", "未知"),
            "current": current.get("coverage_assessment", {}).get("label", "未知"),
        },
    }


def main() -> None:
    if len(sys.argv) != 3:
        print("Usage: compare_reports.py <previous-analysis.json> <current-analysis.json>", file=sys.stderr)
        raise SystemExit(2)
    try:
        result = compare(load_json_object(sys.argv[1]), load_json_object(sys.argv[2]))
    except ContractError as exc:
        print(f"对比失败：{exc}", file=sys.stderr)
        raise SystemExit(1) from exc
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
