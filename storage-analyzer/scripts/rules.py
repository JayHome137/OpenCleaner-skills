#!/usr/bin/env python3
"""Load and match Storage Analyzer's independently defined cleanup rules."""
from __future__ import annotations

import json
import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Optional, Union

HERE = Path(__file__).resolve().parent
RULES_DIR = HERE.parent / "rules"


class RuleError(ValueError):
    """Raised for invalid rule data or unresolved rule roots."""


def normalized_platform(value: Optional[str] = None) -> str:
    platform = value or sys.platform
    if platform == "darwin":
        return "darwin"
    if platform.startswith("win"):
        return "win32"
    raise RuleError(f"不支持的平台：{platform}")


def canonical_path(path: str) -> str:
    if not isinstance(path, str) or not path or "\x00" in path:
        raise RuleError("路径为空或包含 NUL")
    if any(ord(char) < 32 for char in path):
        raise RuleError("路径包含控制字符")
    expanded = os.path.expanduser(path)
    if not os.path.isabs(expanded):
        raise RuleError("路径必须是绝对路径")
    return os.path.abspath(os.path.realpath(expanded))


def is_within(path: str, root: str, include_root: bool = True) -> bool:
    path_norm = os.path.normcase(os.path.abspath(path))
    root_norm = os.path.normcase(os.path.abspath(root))
    try:
        inside = os.path.commonpath((path_norm, root_norm)) == root_norm
    except ValueError:
        return False
    return inside and (include_root or path_norm != root_norm)


def relative_depth(path: str, root: str) -> int:
    relative = os.path.relpath(path, root)
    if relative == os.curdir:
        return 0
    return len([part for part in relative.split(os.sep) if part not in ("", os.curdir)])


@dataclass(frozen=True)
class ResolvedRule:
    id: str
    root: str
    min_depth: int
    actions: tuple[str, ...]
    classification: str
    recovery: str
    risk: str
    non_targets: tuple[str, ...]
    blocked_components: tuple[str, ...]

    def matches(self, path: str, action: str) -> bool:
        relative = os.path.relpath(path, self.root)
        components = {part.casefold() for part in relative.split(os.sep)}
        return (
            action in self.actions
            and is_within(path, self.root)
            and relative_depth(path, self.root) >= self.min_depth
            and not components.intersection(self.blocked_components)
        )


class RuleCatalog:
    def __init__(
        self,
        platform: Optional[str] = None,
        environment: Optional[Mapping[str, str]] = None,
        rules_dir: Union[str, Path] = RULES_DIR,
    ) -> None:
        self.platform = normalized_platform(platform)
        self.environment = dict(os.environ if environment is None else environment)
        self.environment.setdefault("HOME", os.path.expanduser("~"))
        self.rules_dir = Path(rules_dir)
        self.rules = self._load()

    def _expand_root(self, value: str) -> str:
        expanded = value
        for key in ("HOME", "LOCALAPPDATA", "APPDATA", "TEMP"):
            token = "${" + key + "}"
            if token not in expanded:
                continue
            replacement = self.environment.get(key)
            if not replacement:
                raise RuleError(f"规则根目录缺少环境变量：{key}")
            expanded = expanded.replace(token, replacement)
        if "${" in expanded:
            raise RuleError(f"规则根目录包含未知变量：{value}")
        return canonical_path(expanded)

    def _load_file(self, path: Path) -> list[dict[str, Any]]:
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise RuleError(f"无法读取规则文件 {path.name}：{exc}") from exc
        if data.get("schema_version") != "1.0" or not isinstance(data.get("rules"), list):
            raise RuleError(f"规则文件格式无效：{path.name}")
        return data["rules"]

    def _load(self) -> tuple[ResolvedRule, ...]:
        filenames = ["common.json", "macos.json" if self.platform == "darwin" else "windows.json"]
        resolved: list[ResolvedRule] = []
        seen_ids: set[str] = set()
        for filename in filenames:
            for raw in self._load_file(self.rules_dir / filename):
                if self.platform not in raw.get("platforms", []):
                    continue
                rule_id = raw.get("id")
                if not isinstance(rule_id, str) or not rule_id or rule_id in seen_ids:
                    raise RuleError(f"规则 ID 缺失或重复：{rule_id}")
                seen_ids.add(rule_id)
                actions = raw.get("actions")
                if not isinstance(actions, list) or not actions or any(
                    action not in ("trash",) for action in actions
                ):
                    raise RuleError(f"规则动作无效：{rule_id}")
                classification = raw.get("classification")
                recovery = raw.get("recovery")
                risk = raw.get("risk")
                non_targets = raw.get("non_targets")
                blocked_components = raw.get("blocked_components")
                if classification != "green":
                    raise RuleError(f"可执行规则必须是 green：{rule_id}")
                if not isinstance(recovery, str) or not recovery.strip():
                    raise RuleError(f"规则缺少恢复说明：{rule_id}")
                if not isinstance(risk, str) or not risk.strip():
                    raise RuleError(f"规则缺少风险说明：{rule_id}")
                if not isinstance(non_targets, list) or not non_targets or any(
                    not isinstance(item, str) or not item.strip() for item in non_targets
                ):
                    raise RuleError(f"规则缺少非目标范围：{rule_id}")
                if not isinstance(blocked_components, list) or any(
                    not isinstance(item, str) or not item.strip() for item in blocked_components
                ):
                    raise RuleError(f"规则 blocked_components 无效：{rule_id}")
                resolved.append(
                    ResolvedRule(
                        id=rule_id,
                        root=self._expand_root(raw["root"]),
                        min_depth=int(raw.get("min_depth", 1)),
                        actions=tuple(actions),
                        classification=classification,
                        recovery=recovery,
                        risk=risk,
                        non_targets=tuple(non_targets),
                        blocked_components=tuple(item.casefold() for item in blocked_components),
                    )
                )
        return tuple(resolved)

    def match(
        self,
        path: str,
        action: str,
        requested_rule_id: Optional[str] = None,
    ) -> Optional[ResolvedRule]:
        target = canonical_path(path)
        for rule in self.rules:
            if requested_rule_id and rule.id != requested_rule_id:
                continue
            if rule.matches(target, action):
                return rule
        return None
