# OpenCleaner-skills

OpenCleaner-skills 是一个面向 Codex 和其他 Agent 的 macOS/Windows 存储分析 Skill。它把只读扫描、确定性安全规则、Agent 语义解释和中文 HTML 报告组合在一起；文件处置默认只允许移到废纸篓。

## 当前能力

- 使用互斥扫描根和有限并发统计磁盘热点。
- 输出版本化 `scan-result`，保留覆盖率、超时和权限错误。
- 使用本项目规则生成可复现的绿黄红三级分析草稿。
- 允许 Agent 解释 UUID 容器、离线内容、应用数据、开发缓存和系统数据。
- 延续现版本的磁盘总览、Top 5、执行建议、三级卡片和长期建议体验，展示层已独立重写。
- 使用显式 Dry Run、独立 session plan、路径/文件身份复核和 JSONL 操作历史。
- 支持静态只读报告，或在本地服务中打开目录、移到废纸篓。
- Trash 后复核原路径、记录磁盘可用空间变化，并在报告中展示本次操作历史。

不提供永久删除、系统目录自动清理、管理员权限操作、完整应用卸载、系统优化或实时硬件监控。

## 使用

在 Codex 中调用：

```text
使用 $opencleaner-skills 分析电脑存储空间并生成分级报告。
```

手动执行完整链路：

```bash
cd opencleaner-skills
python3 scripts/scan.py > /tmp/storage-scan.json
python3 scripts/classify.py /tmp/storage-scan.json /tmp/storage-analysis.json
python3 scripts/validate_plan.py /tmp/storage-analysis.json > /tmp/storage-dry-run.json
python3 scripts/server.py /tmp/storage-analysis.json
```

静态报告：

```bash
python3 scripts/build_report.py /tmp/storage-analysis.json ~/Desktop/storage-report.html
```

## 运行结构

```text
scan.py
  -> scan-result 1.0
  -> classify.py + rules/*.json
  -> analysis 1.0
  -> Agent 只补充解释
  -> validate_plan.py -> 不可执行 Dry Run
  -> server.py -> 独立 session action-plan 1.0
  -> build_report.py 或受控本地服务
  -> file_ops.py + operations.jsonl
```

三个数据契约位于 `opencleaner-skills/schemas/`。安全规则位于 `opencleaner-skills/rules/`，规则和代码分开审阅。

## 安全模型

- Agent 生成或修改的路径不能直接获得文件操作权限。
- Dry Run 计划在服务端和文件操作内核两层都不可执行。
- 浏览器提交 action ID，不提交路径或 mode。
- 批量操作会在第一个副作用前验证全部目标。
- 执行时重新检查真实路径、文件身份、符号链接、保护目录和规则。
- 操作计划 30 分钟后失效，已完成的 Trash 动作不能重放。
- Trash 失败即停止，不回退到永久删除。
- Trash 返回成功后仍会复核原路径；原路径未移走则记为失败。
- 操作日志记录 started/最终结果、规则、目标、失败原因和磁盘可用空间实测变化。
- 静态报告通过安全 JSON 嵌入防止 analysis 内容提前闭合脚本标签。

## 平台状态

| 平台 | 状态 | 说明 |
| --- | --- | --- |
| macOS | 已验证 | 规则、路径策略、报告、安全单元测试和临时 fixture Trash smoke 已在本地及 GitHub runner 通过。 |
| Windows | 已验证 | 扫描、分类、计划、报告和 Recycle Bin smoke 已在 GitHub `windows-latest` runner 通过。 |
| Linux | 不支持 | 扫描和文件操作明确拒绝。 |

## 验证

```bash
python3 scripts/validate_package.py
python3 -m unittest discover -s tests -p 'test_*.py' -v
python3 scripts/benchmark_scan.py
```

GitHub Actions 已完成 macOS 和 Windows 验证；本地与远程证据见 [docs/ACCEPTANCE_MATRIX.md](docs/ACCEPTANCE_MATRIX.md)。项目目标与分阶段验收标准见 [PROJECT_GOALS.md](PROJECT_GOALS.md)。

用于端到端和视觉回归的无敏感信息样本位于 `tests/fixtures/sample_analysis.json`；它只生成静态报告，不执行文件操作。

## 来源与许可

本仓库最初参考 `KKKKhazix/khazix-skills` 的 `storage-analyzer` Skill。当前运行时、契约、规则、安全策略、测试和报告模板均已独立重写；发行内容不依赖原参考仓库或 Mole 的源码与运行组件。

第三方来源和完整 MIT notice 见 [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)，逐文件处置见 [docs/PROVENANCE.md](docs/PROVENANCE.md)。

从版本 1.0.0 起，本项目版权所有者拥有的当前实现采用 [PolyForm Noncommercial License 1.0.0](LICENSE)：非商业用途可以按该许可证使用、修改和分发；商业用途必须事先取得 JayHome137 的单独书面商业许可，联系 `GitHub repository maintainers`。具体入口见 [COMMERCIAL_LICENSE.md](COMMERCIAL_LICENSE.md)，必须随发行物保留的项目声明见 [NOTICE](NOTICE)。

仓库历史中已经按 MIT 发布的版本继续保有原授权，第三方 MIT 内容也继续按其原条款处理；新许可证不追溯撤销或覆盖这些权利。实施记录和边界见 [docs/LICENSING_PLAN.md](docs/LICENSING_PLAN.md)。
