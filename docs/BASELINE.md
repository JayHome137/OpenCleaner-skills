# 重构基线

> 本文记录 2026-06-25 的历史双平台基线，不代表当前支持范围。当前发行版只支持 macOS，Windows 实验资产保留但公开入口关闭。

## 基线范围

- 本地基线提交：`92d16462be694e8e1ed9797a03a31fd21fb34fb5`
- 基线日期：2026-06-25
- 产品形态：Codex/Agent Skill
- 目标平台：macOS、Windows
- Python 依赖：仅标准库

## 当前用户流程

```text
只读扫描 -> Agent 生成 analysis JSON -> HTML 报告 -> 本地服务执行操作
```

基线报告的固定阅读顺序为：磁盘总览、Top 5、执行建议、绿黄红三级卡片、权限遗漏、长期建议。重构必须保持该顺序和现有颜色语义。

## 基线能力

| 能力 | 基线状态 | 重构要求 |
| --- | --- | --- |
| macOS 扫描 | 预设热点逐目录执行 `du` | 保持覆盖面，移除重叠扫描并保留结构化错误。 |
| Windows 扫描 | 标准库递归统计，多盘符 | 保持多盘符，补充取消、错误和真实桌面验证。 |
| Agent 分析 | Agent 直接生成分级和操作路径 | 保留解释能力，取消 Agent 的直接操作授权。 |
| HTML 报告 | 静态报告和本地交互服务 | 保持视觉与内容顺序，接入版本化操作计划。 |
| 文件处置 | 打开、移到废纸篓、永久删除 | v1 仅保留打开和移到废纸篓。 |
| 验证 | 包验证和 Windows smoke | 增加契约、规则、路径策略、服务端和 macOS 验证。 |

## 已知安全差距

- 现有服务端直接信任 analysis JSON 中的路径。
- 现有根路径检查允许 `$HOME` 和 `/Applications` 成为删除候选范围。
- 现有永久删除直接调用 Python 文件删除 API。
- 现有浏览器确认承担了不应由前端承担的授权职责。
- 现有操作没有版本化计划、文件身份复核和持久化历史。

## 基线验证命令

```bash
python3 scripts/validate_package.py
python3 -m unittest discover -s tests -p 'test_*.py' -v
```

历史 Windows runner 命令（当前不执行）：

```powershell
python scripts/validate_package.py
python tests/windows_smoke.py
```
