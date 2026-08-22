#!/usr/bin/env python3
"""Build and print a non-executable Dry Run plan from an analysis JSON file."""
from __future__ import annotations

import json
import sys

from contracts import ContractError, load_json_object
from policy import PolicyError, build_action_plan


def main() -> None:
    if len(sys.argv) != 2:
        print("Usage: validate_plan.py <analysis.json>", file=sys.stderr)
        raise SystemExit(2)
    try:
        analysis = load_json_object(sys.argv[1])
        plan = build_action_plan(analysis, purpose="dry-run")
    except (ContractError, PolicyError) as exc:
        print(f"操作计划生成失败：{exc}", file=sys.stderr)
        raise SystemExit(1) from exc
    print(json.dumps(plan, ensure_ascii=False, indent=2))
    print(
        f"DRY RUN：授权候选 {len(plan['actions'])} 项，拒绝 {len(plan['rejected'])} 项；"
        "该输出不能直接执行。",
        file=sys.stderr,
    )


if __name__ == "__main__":
    main()
