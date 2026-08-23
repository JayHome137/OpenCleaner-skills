---
name: open-cleaner
description: >
  macOS 存储分析与受控处置 Skill。只读扫描磁盘占用，以确定性规则生成
  绿黄红三级分析草稿，再由 Agent 补充陌生目录说明，保留中文交互式 HTML 报告。
  适用于“磁盘满了”“存储空间不足”“哪些目录占空间”“清理缓存”等 macOS 请求。
  不适用于运行内存/RAM 或进程内存诊断。
---

# OpenCleaner

使用版本化数据契约完成：只读扫描、确定性分级、Agent 解释、操作计划验证、报告展示和可恢复处置。

## 安全不变量

- 扫描阶段严格只读，不修改被扫描目录。
- Agent 只能补充解释或提高风险等级，不能授予文件操作权限。
- `validate_plan.py` 只生成不可执行的 Dry Run；可操作按钮必须来自本地服务重新生成的短期 session plan。
- v1 只支持 `open`、绿灯 `trash` 和黄灯 `reviewed_trash`；两个变更文件的 mode 都只能移入废纸篓，不支持永久删除。
- Trash 不可用时失败，不得回退到 `rm`、`os.remove` 或其他永久删除方式。
- `$HOME`、磁盘根、系统根、应用目录根、回收站根和敏感数据目录不能成为自动处置目标。
- 系统目录和需要管理员权限的目标只提供说明，不由本 Skill 执行。
- 路径、文件身份、父目录和规则会在执行前重新验证；过期或变化的计划必须拒绝。
- 已知所有者工具的运行状态必须是 `inactive`；`active` 和 `unknown` 都不得生成或执行处置动作，所有者工具命令只展示、不代为运行。
- `reviewed_trash` 只允许下载/临时目录的当前用户直接子项，或通过项目阶段规则复核的 allowlist 生成目录；它要求与计划及完整 action ID 集绑定的 120 秒一次性复核令牌。
- Trash 返回后必须复核原路径已移走，并记录磁盘可用空间前后变化；复核失败按操作失败处理。
- 所有空间释放数字都是估算；移到废纸篓后要清空废纸篓才会实际释放空间。

## 执行流程

以下扫描、分类和报告命令均从 Skill 根目录执行。

### 1. 只读扫描

```bash
python3 scripts/scan.py > /tmp/storage-scan.json
```

扫描结果遵循 `schemas/scan-result.schema.json`，包含：

- `system`：系统、磁盘、架构和主目录信息。
- `groups`：互斥扫描组中的大目录或文件。
- `coverage`：请求、完成、跳过的扫描根和实际调度数量。
- `errors`：权限、超时、命令失败和不可读路径。

不得把 `errors` 中的失败当作空目录。报告必须说明权限遗漏和覆盖范围。

### 2. 生成确定性分析草稿

```bash
python3 scripts/classify.py /tmp/storage-scan.json /tmp/storage-analysis.json
```

分类器读取 `rules/*.json`：

- 命中可恢复规则且未触发保护策略的目标进入绿灯。
- 未知目录、用户文件、应用数据和状态不完整目标进入黄灯。
- 应用本体和不应直接处置的目标进入红灯。
- 名称包含 `cache`、`temp` 或文件较旧，不足以单独变成绿灯。

### 3. Agent 补充分析

读取 `references/macos.md` 后再补充 analysis JSON。Windows 输入必须拒绝，不能使用保留的实验代码生成报告或操作计划。

Agent 可以修改：

- Top 5 的类型、名称、说明和排序。
- 黄灯的内容画像、人工判断原因、处置路径、风险和 `open_note`。
- 红灯的保留原因、正规卸载步骤和自动回收说明。
- `summary.overview`、优先级和长期建议。
- 不确定目标的等级只能保持或提高风险，不能从黄灯/红灯降成绿灯。

Agent 不得修改或新增：

- `schema_version`、`source_scan_sha256`。
- 绿灯的 `rule_id` 和 `trash_paths`。
- 没有确定性规则支持的可执行路径。
- 永久删除命令、管理员删除命令或系统目录操作。

陌生 UUID、容器、虚拟机镜像、离线媒体和备份包可以继续只读深入检查，但结论不明确时保持黄灯。

### 4. 验证操作计划

```bash
python3 scripts/validate_plan.py /tmp/storage-analysis.json > /tmp/storage-action-plan.json
```

输出明确包含 `purpose: dry-run` 和 `dry_run: true`。检查 `rejected`：被拒绝的目标不能在报告中显示操作按钮。Dry Run 记录候选目标、真实路径和文件身份，但在服务端和文件操作内核两层都不可执行。

项目开发阶段完成后，只有同时满足以下前置条件，才运行项目阶段扫描：本轮测试或构建验证成功；源码已有可恢复检查点；相关构建、测试和应用进程已退出。前置条件由执行本轮开发的 Agent 负责确认，不得仅凭目录名称推断。

```bash
python3 scripts/project_stage.py > /tmp/open-cleaner-project-stage.json
python3 scripts/validate_plan.py /tmp/open-cleaner-project-stage.json > /tmp/open-cleaner-project-stage-plan.json
```

项目阶段扫描只把 allowlist 内、具有项目清单、满足 Git ignored/untracked 边界、没有 Archives/发布包、已静置 30 分钟且无打开文件的生成目录加入黄灯 `reviewed_trash`。自动化到此为止：不能后台移动文件，仍须用户在受控页面逐批确认。

### 5. 打开报告

默认使用受控服务模式：

```bash
python3 scripts/server.py /tmp/storage-analysis.json
```

服务绑定 `127.0.0.1` 随机端口，使用随机 token，并从当前 analysis 独立生成 30 分钟有效的 session plan。浏览器只提交 action ID，不提交路径或操作类型；绿灯支持多选和批次确认，黄灯受限目标还要经过独立人工确认和一次性服务端复核令牌。处置后可在同一页面查看逐项历史并重新扫描。

如果用户只需要可分享的只读文件：

```bash
python3 scripts/build_report.py /tmp/storage-analysis.json ~/Desktop/storage-report.html
open ~/Desktop/storage-report.html
```

静态报告没有文件操作能力。

### 6. 对话摘要

报告生成后给出一段结论先行的摘要：预计可恢复处理空间、最值得先看的 2 至 3 项、覆盖率和风险最高的一项。详细路径留在报告中。

## 报告要求

保持以下顺序：磁盘总览、Top 5、执行建议、绿黄红三级卡片、权限遗漏、长期建议。

- 绿灯展示 `rule_id` 和恢复说明。
- 绿灯同时展示规则风险和明确的非目标范围。
- 黄灯以打开查看为主；只有下载/临时目录的当前用户直接子项或通过项目阶段规则的生成目录可显示独立人工复核 Trash，不能与普通绿灯批次混合。
- 所有者提示与实时运行状态分离；报告可展示检查或清理建议，但不得自动执行所有者工具命令。
- 红灯只允许定位应用，不在后台卸载。
- 按钮不存在时，不能通过手工 HTTP 请求绕过操作计划。
- 受控模式展示本次操作历史、失败原因、原路径复核和磁盘可用空间实测变化。

## 平台边界

- macOS：扫描、规则、报告、受控 Trash 和安全测试为主要验证平台。
- Windows：当前对外入口关闭；实验实现、规则和 smoke 仅为后续独立测试保留，不能视为支持状态。
- Linux：不在目标范围，扫描器和文件操作必须拒绝。

## 依赖与验证

运行时只依赖 Python 标准库和系统自带文件管理能力。

以下仓库级验证命令从包含 `scripts/validate_package.py` 的仓库根目录执行：

```bash
python3 scripts/validate_package.py
python3 -m unittest discover -s tests -p 'test_*.py' -v
python3 scripts/benchmark_scan.py
```
