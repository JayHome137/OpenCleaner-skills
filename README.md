# OpenCleaner

面向 Codex 和其他 AI Agent 的 macOS / Windows 存储分析 Skill：只读扫描磁盘占用，生成中文分级报告，并通过确定性规则提供受控、可恢复的文件处置。

[![macOS 验证](https://github.com/JayHome137/OpenCleaner-skills/actions/workflows/macos-validation.yml/badge.svg)](https://github.com/JayHome137/OpenCleaner-skills/actions/workflows/macos-validation.yml)
[![Windows 验证](https://github.com/JayHome137/OpenCleaner-skills/actions/workflows/windows-validation.yml/badge.svg)](https://github.com/JayHome137/OpenCleaner-skills/actions/workflows/windows-validation.yml)
[![许可证](https://img.shields.io/badge/license-PolyForm%20Noncommercial-blue.svg)](LICENSE)

## 核心能力

- **跨平台分析**：支持 macOS 和 Windows，识别磁盘热点、大目录、开发缓存、离线内容和应用数据。
- **确定性分级**：规则引擎先生成绿、黄、红三级草稿，Agent 只能补充解释或提高风险，不能新增文件操作权限。
- **中文可视化报告**：展示磁盘总览、Top 5、处置建议、权限遗漏、风险说明和长期建议。
- **安全处置**：执行前经过 Dry Run、短期 action plan、路径与文件身份复核；只支持打开目录和移到废纸篓。
- **操作可审计**：记录操作结果、失败原因、目标复核和磁盘可用空间变化。

OpenCleaner 不提供永久删除、系统目录自动清理、管理员权限操作、完整应用卸载、系统优化或实时硬件监控。

## 快速开始

### 安装 Skill

```bash
git clone https://github.com/JayHome137/OpenCleaner-skills.git
mkdir -p "${CODEX_HOME:-$HOME/.codex}/skills"
cp -R OpenCleaner-skills/open-cleaner "${CODEX_HOME:-$HOME/.codex}/skills/"
```

重新打开 Codex 后，使用机器名 `$open-cleaner` 调用：

```text
使用 $open-cleaner 分析电脑存储空间并生成分级报告。
```

### 手动运行

以下命令从 Skill 根目录执行：

```bash
cd open-cleaner
python3 scripts/scan.py > /tmp/storage-scan.json
python3 scripts/classify.py /tmp/storage-scan.json /tmp/storage-analysis.json
python3 scripts/validate_plan.py /tmp/storage-analysis.json > /tmp/storage-dry-run.json
python3 scripts/server.py /tmp/storage-analysis.json
```

本地服务绑定 `127.0.0.1` 的随机端口，并使用随机 token。浏览器只提交 action ID，不提交路径或操作类型。

只需要可分享的只读报告时：

```bash
python3 scripts/build_report.py /tmp/storage-analysis.json ~/Desktop/storage-report.html
```

## 安全设计

- 扫描阶段严格只读，不修改被扫描目录。
- Agent 不能把未知路径提升为可执行目标。
- Dry Run 不可执行；受控操作由服务端重新生成 30 分钟有效的 session plan。
- 执行前重新检查真实路径、文件身份、父目录、符号链接、保护目录和匹配规则。
- Trash 失败即停止，不回退到 `rm`、`os.remove` 或其他永久删除方式。
- 批量操作在第一个副作用前完成全部目标复核，已完成的 Trash 动作不能重放。
- Trash 返回成功后仍会确认原路径已经移走，并写入本地操作日志。

## 工作原理

```text
只读扫描
  -> 版本化 scan-result
  -> 确定性规则分类
  -> Agent 补充语义解释
  -> 不可执行 Dry Run
  -> 短期 session action plan
  -> 中文报告与用户确认
  -> 打开目录或移到废纸篓
  -> 操作日志与结果复核
```

数据契约位于 [`open-cleaner/schemas/`](open-cleaner/schemas/)，安全规则位于 [`open-cleaner/rules/`](open-cleaner/rules/)。扫描、策略、报告和执行模块保持单向职责，报告不能绕过服务端授权。

## 平台支持

| 平台 | 状态 | 说明 |
| --- | --- | --- |
| macOS | 已验证 | 扫描、规则、报告、安全回归和临时 fixture Trash smoke 已在本地及 GitHub runner 通过。 |
| Windows | 已验证 | 扫描、分类、计划、报告和 Recycle Bin smoke 已在 GitHub `windows-latest` runner 通过。 |
| Linux | 不支持 | 扫描器和文件操作明确拒绝。 |

运行时只依赖 Python 3 标准库和系统自带文件管理能力。Windows 环境需要预先安装 Python 3。

## 验证

```bash
python3 scripts/validate_package.py
python3 -m unittest discover -s tests -p 'test_*.py' -v
python3 scripts/benchmark_scan.py
```

- [验收矩阵](docs/ACCEPTANCE_MATRIX.md)：本地与 GitHub runner 证据、验证边界和当前状态。
- [项目目标](PROJECT_GOALS.md)：产品范围、安全不变量和实现阶段。
- [来源记录](docs/PROVENANCE.md)：逐文件来源与独立重写说明。

## 许可证

项目许可见 [LICENSE](LICENSE)，商业授权入口见 [COMMERCIAL_LICENSE.md](COMMERCIAL_LICENSE.md)，第三方来源与历史授权见 [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)。
