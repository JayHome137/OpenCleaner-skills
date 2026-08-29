#!/usr/bin/env python3
"""Small dependency-free security guard for the OpenCleaner runtime.

This is intentionally conservative: it catches accidental reintroduction of
permanent-delete or shell-evaluation surfaces in the two mutating modules. It
is a CI tripwire, not a replacement for manual security review.
"""
from __future__ import annotations

import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RUNTIME = (
    ROOT / "open-cleaner" / "scripts" / "file_ops.py",
    ROOT / "open-cleaner" / "scripts" / "policy.py",
    ROOT / "open-cleaner" / "scripts" / "server.py",
)


def main() -> int:
    findings: list[str] = []
    forbidden_text = (
        "shutil.rmtree",
        "os.remove(",
        "os.unlink(",
        "subprocess.run(.*shell=True",
        "eval(",
        "exec(",
    )
    for path in RUNTIME:
        source = path.read_text(encoding="utf-8")
        for needle in forbidden_text:
            if needle in source:
                findings.append(f"{path.relative_to(ROOT)} contains forbidden surface: {needle}")
        try:
            tree = ast.parse(source, filename=str(path))
        except SyntaxError as exc:
            findings.append(f"{path.relative_to(ROOT)} syntax error: {exc}")
            continue
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            if isinstance(node.func, ast.Name) and node.func.id in {"eval", "exec", "__import__"}:
                findings.append(
                    f"{path.relative_to(ROOT)}:{node.lineno} dynamic call: {node.func.id}"
                )
            if (
                isinstance(node.func, ast.Attribute)
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id == "subprocess"
                and node.func.attr == "run"
            ):
                for keyword in node.keywords:
                    if keyword.arg == "shell" and isinstance(keyword.value, ast.Constant) and keyword.value.value is True:
                        findings.append(f"{path.relative_to(ROOT)}:{node.lineno} subprocess.run uses shell=True")
    if findings:
        for finding in findings:
            print(f"ERROR: {finding}")
        return 1
    print("OpenCleaner security scan passed (dependency-free guard)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
