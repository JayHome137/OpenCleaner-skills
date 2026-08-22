#!/usr/bin/env python3
"""Runtime validation for OpenCleaner's versioned JSON contracts."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Iterable, Union

SCAN_SCHEMA_VERSION = "1.0"
ANALYSIS_SCHEMA_VERSION = "1.0"
ACTION_PLAN_SCHEMA_VERSION = "1.0"


class ContractError(ValueError):
    """Raised when an input does not satisfy a runtime contract."""


def load_json_object(path: Union[str, Path]) -> dict[str, Any]:
    try:
        with Path(path).open(encoding="utf-8") as handle:
            value = json.load(handle)
    except (OSError, json.JSONDecodeError) as exc:
        raise ContractError(f"无法读取 JSON：{exc}") from exc
    if not isinstance(value, dict):
        raise ContractError("JSON 顶层必须是对象")
    return value


def canonical_sha256(value: Any) -> str:
    payload = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def json_for_script(value: Any) -> str:
    """Serialize JSON without allowing data to terminate an inline script."""
    return (
        json.dumps(value, ensure_ascii=False, separators=(",", ":"))
        .replace("&", "\\u0026")
        .replace("<", "\\u003c")
        .replace(">", "\\u003e")
        .replace("\u2028", "\\u2028")
        .replace("\u2029", "\\u2029")
    )


def _require_keys(value: dict[str, Any], keys: Iterable[str], label: str) -> None:
    missing = [key for key in keys if key not in value]
    if missing:
        raise ContractError(f"{label} 缺少字段：{', '.join(missing)}")


def _require_type(value: Any, expected: type, label: str) -> None:
    if not isinstance(value, expected):
        raise ContractError(f"{label} 类型必须是 {expected.__name__}")


def _require_number(value: Any, label: str) -> None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ContractError(f"{label} 类型必须是 number")


def _require_string_list(value: Any, label: str) -> None:
    _require_type(value, list, label)
    if any(not isinstance(item, str) for item in value):
        raise ContractError(f"{label} 必须只包含字符串")


def _require_sha256(value: Any, label: str) -> None:
    if not isinstance(value, str) or len(value) != 64:
        raise ContractError(f"{label} 必须是 64 位 SHA-256")
    try:
        int(value, 16)
    except ValueError as exc:
        raise ContractError(f"{label} 必须是十六进制 SHA-256") from exc


def validate_scan_result(data: dict[str, Any]) -> dict[str, Any]:
    _require_keys(
        data,
        (
            "schema_version",
            "generated_at",
            "scan_seconds",
            "system",
            "groups",
            "coverage",
            "errors",
        ),
        "scan-result",
    )
    if data["schema_version"] != SCAN_SCHEMA_VERSION:
        raise ContractError("不支持的 scan-result schema_version")
    _require_type(data["generated_at"], str, "generated_at")
    _require_number(data["scan_seconds"], "scan_seconds")
    _require_type(data["system"], dict, "system")
    _require_type(data["groups"], dict, "groups")
    _require_type(data["coverage"], dict, "coverage")
    _require_type(data["errors"], list, "errors")
    _require_keys(
        data["system"],
        ("os", "home", "disk_total", "disk_used", "disk_free", "disks"),
        "system",
    )
    for key in ("os", "home", "disk_total", "disk_used", "disk_free"):
        _require_type(data["system"][key], str, f"system.{key}")
    _require_type(data["system"]["disks"], list, "system.disks")
    _require_keys(
        data["coverage"],
        ("requested_roots", "completed_roots", "skipped_roots"),
        "coverage",
    )
    for key in ("requested_roots", "completed_roots", "skipped_roots"):
        value = data["coverage"][key]
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise ContractError(f"coverage.{key} 必须是非负整数")
    if data["coverage"]["completed_roots"] + data["coverage"]["skipped_roots"] != data["coverage"]["requested_roots"]:
        raise ContractError("coverage 完成数与跳过数之和必须等于请求数")
    for group_name, items in data["groups"].items():
        _require_type(group_name, str, "group name")
        _require_type(items, list, f"groups.{group_name}")
        for index, item in enumerate(items):
            _require_type(item, dict, f"groups.{group_name}[{index}]")
            _require_keys(
                item,
                ("name", "path", "size_kb", "size_h"),
                f"groups.{group_name}[{index}]",
            )
            for key in ("name", "path", "size_h"):
                _require_type(item[key], str, f"groups.{group_name}[{index}].{key}")
            if isinstance(item["size_kb"], bool) or not isinstance(item["size_kb"], int) or item["size_kb"] < 0:
                raise ContractError(f"groups.{group_name}[{index}].size_kb 必须是非负整数")
    for index, error in enumerate(data["errors"]):
        _require_type(error, dict, f"errors[{index}]")
        _require_keys(error, ("code", "path", "message"), f"errors[{index}]")
        for key in ("code", "path", "message"):
            _require_type(error[key], str, f"errors[{index}].{key}")
    return data


def validate_analysis(data: dict[str, Any]) -> dict[str, Any]:
    _require_keys(
        data,
        (
            "schema_version",
            "source_scan_sha256",
            "generated_at",
            "system",
            "top5",
            "green",
            "yellow",
            "red",
            "summary",
        ),
        "analysis",
    )
    if data["schema_version"] != ANALYSIS_SCHEMA_VERSION:
        raise ContractError("不支持的 analysis schema_version")
    _require_sha256(data["source_scan_sha256"], "source_scan_sha256")
    _require_type(data["generated_at"], str, "generated_at")
    _require_type(data["system"], dict, "system")
    _require_keys(data["system"], ("os", "home"), "system")
    for key in ("os", "home"):
        _require_type(data["system"][key], str, f"system.{key}")
    item_specs = {
        "top5": ("rank", "tier", "size", "type", "name", "path", "note"),
        "green": (
            "name", "path", "size_estimate", "kill_processes", "trash_paths", "commands",
            "rule_id", "rule_reason", "rule_risk", "rule_non_targets",
        ),
        "yellow": ("name", "path", "size", "content_profile", "why_manual", "disposal", "risk"),
        "red": ("name", "path", "size", "why_keep", "indirect_release", "auto_reclaim"),
    }
    for key, required in item_specs.items():
        _require_type(data[key], list, key)
        for index, item in enumerate(data[key]):
            label = f"{key}[{index}]"
            _require_type(item, dict, label)
            _require_keys(item, required, label)
            if key == "top5":
                if isinstance(item["rank"], bool) or not isinstance(item["rank"], int) or item["rank"] < 1:
                    raise ContractError(f"{label}.rank 必须是正整数")
                if item["tier"] not in ("green", "yellow", "red"):
                    raise ContractError(f"{label}.tier 无效")
                for field in ("size", "type", "name", "path", "note"):
                    _require_type(item[field], str, f"{label}.{field}")
            elif key == "green":
                for field in ("name", "path", "size_estimate", "rule_id", "rule_reason", "rule_risk"):
                    _require_type(item[field], str, f"{label}.{field}")
                for field in ("kill_processes", "trash_paths", "rule_non_targets"):
                    _require_string_list(item[field], f"{label}.{field}")
                _require_type(item["commands"], list, f"{label}.commands")
            else:
                for field in required:
                    _require_type(item[field], str, f"{label}.{field}")
            if "trash_paths" in item:
                _require_string_list(item["trash_paths"], f"{label}.trash_paths")
            if "app_paths" in item:
                _require_string_list(item["app_paths"], f"{label}.app_paths")
    _require_type(data["summary"], dict, "summary")
    _require_keys(
        data["summary"],
        ("overview", "tier_stats", "priority", "long_term"),
        "summary",
    )
    _require_type(data["summary"]["overview"], str, "summary.overview")
    _require_type(data["summary"]["tier_stats"], dict, "summary.tier_stats")
    _require_string_list(data["summary"]["priority"], "summary.priority")
    _require_string_list(data["summary"]["long_term"], "summary.long_term")
    _require_keys(data["summary"]["tier_stats"], ("green", "yellow", "red"), "summary.tier_stats")
    for key in ("green", "yellow", "red"):
        _require_type(data["summary"]["tier_stats"][key], str, f"summary.tier_stats.{key}")
    if "denied" in data:
        _require_string_list(data["denied"], "denied")
    return data


def validate_action_plan(data: dict[str, Any]) -> dict[str, Any]:
    _require_keys(
        data,
        (
            "schema_version",
            "purpose",
            "dry_run",
            "plan_id",
            "generated_at",
            "expires_at",
            "platform",
            "home",
            "source_analysis_sha256",
            "actions",
            "rejected",
        ),
        "action-plan",
    )
    if data["schema_version"] != ACTION_PLAN_SCHEMA_VERSION:
        raise ContractError("不支持的 action-plan schema_version")
    if data["purpose"] not in ("dry-run", "session"):
        raise ContractError("action-plan purpose 必须是 dry-run 或 session")
    for key in ("purpose", "plan_id", "generated_at", "expires_at", "platform", "home"):
        _require_type(data[key], str, f"action-plan {key}")
    _require_type(data["dry_run"], bool, "action-plan dry_run")
    if data["dry_run"] is not (data["purpose"] == "dry-run"):
        raise ContractError("action-plan dry_run 与 purpose 不一致")
    if data["platform"] not in ("darwin", "win32"):
        raise ContractError("action-plan platform 必须是 darwin 或 win32")
    _require_sha256(data["source_analysis_sha256"], "source_analysis_sha256")
    _require_type(data["actions"], list, "actions")
    _require_type(data["rejected"], list, "rejected")
    action_ids: set[str] = set()
    for index, action in enumerate(data["actions"]):
        _require_type(action, dict, f"actions[{index}]")
        _require_keys(
            action,
            (
                "action_id",
                "mode",
                "path",
                "canonical_path",
                "tier",
                "rule_id",
                "recovery",
                "risk",
                "non_targets",
                "identity",
                "parent_identity",
            ),
            f"actions[{index}]",
        )
        if action["mode"] not in ("open", "trash"):
            raise ContractError(f"actions[{index}] 含不支持的 mode")
        for key in ("action_id", "path", "canonical_path", "tier", "rule_id", "recovery", "risk"):
            _require_type(action[key], str, f"actions[{index}].{key}")
        if len(action["action_id"]) < 16 or action["action_id"] in action_ids:
            raise ContractError(f"actions[{index}].action_id 过短或重复")
        action_ids.add(action["action_id"])
        if action["tier"] not in ("green", "yellow", "red"):
            raise ContractError(f"actions[{index}].tier 无效")
        _require_string_list(action["non_targets"], f"actions[{index}].non_targets")
        for identity_key in ("identity", "parent_identity"):
            label = f"actions[{index}].{identity_key}"
            identity = action[identity_key]
            _require_type(identity, dict, label)
            _require_keys(
                identity,
                ("device", "inode", "mode", "kind", "size", "mtime_ns"),
                label,
            )
            for key in ("device", "inode", "mode", "size", "mtime_ns"):
                value = identity[key]
                if isinstance(value, bool) or not isinstance(value, int):
                    raise ContractError(f"{label}.{key} 必须是整数")
            if identity["device"] < 0 or identity["inode"] < 0 or identity["mode"] < 0 or identity["size"] < 0:
                raise ContractError(f"{label} 包含无效的负数身份字段")
            if identity["kind"] not in ("file", "directory"):
                raise ContractError(f"{label}.kind 无效")
    return data
