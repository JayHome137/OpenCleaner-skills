# 来源与重写状态

## 证据

本仓库初始提交 `de82aa35461d533c61aa7099c774a612199c0311` 一次性引入了原始 Skill、扫描器、报告生成器、服务端、报告模板和系统参考文档。README 后续明确声明这些内容基于 `KKKKhazix/khazix-skills` 的同名 Skill。

## 文件状态

| 路径 | 当前来源 | 重构处置 |
| --- | --- | --- |
| `open-cleaner/SKILL.md` | 已独立重写 | 保留 Skill 触发形式，运行流程已切换到版本化契约。 |
| `open-cleaner/scripts/scan.py` | 已独立重写 | 使用互斥扫描根、有限并发和结构化错误。 |
| `open-cleaner/scripts/build_report.py` | 已独立重写 | 验证 analysis 并安全嵌入 JSON。 |
| `open-cleaner/scripts/server.py` | 已独立重写 | 只接受短期 action ID，不接受路径和 mode。 |
| `open-cleaner/scripts/runtime.py` | 本仓库原创 | 提供确定性所有者提示和实时进程状态检查，不执行所有者工具命令。 |
| `open-cleaner/scripts/project_artifacts.py`、`project_stage.py` | 本仓库原创 | 以独立 allowlist、项目清单、Git 状态、静置期和打开文件检查实现可选项目生成目录阶段。 |
| `open-cleaner/assets/report_template.html` | 已独立重写 | 延续现版本的阅读顺序和颜色语义；DOM、CSS 和 action-ID 客户端均重新实现。 |
| `open-cleaner/references/*.md` | 已独立重写 | 仅描述当前规则和平台边界。 |
| `tests/windows_smoke.py` | 已独立重写 | 作为当前不可达的 Windows 实验 smoke 保留，待后续独立测试；不构成当前支持证明。 |
| `tests/macos_smoke.py` | 本仓库原创 | 在临时 HOME 验证 macOS 扫描、Dry Run、session plan、报告和 Trash 后复核。 |
| `scripts/benchmark_scan.py` | 本仓库原创 | 使用临时 fixture 建立稳定输出、去重和耗时基线。 |
| `scripts/validate_package.py` | 已独立重写 | 验证新包结构、契约和无永久删除不变量。 |
| `open-cleaner/agents/openai.yaml` | 通用 Skill 描述文件，已改写文案 | 只声明当前 Skill 名称、提示语和调用策略。 |
| `scripts/privacy_scan.py`、`scripts/verify_release_archive.py` | 本仓库原创 | 在不引入运行时依赖的前提下检查发行物隐私边界，并从解压后的归档目录重新验证包契约。 |
| `.gitignore` | 初始仓库保留 | 通用开发忽略项，不属于主体实现。 |
| `LICENSE` | Apache License 2.0 官方标准文本 | 版本 1.2.0 起约束版权所有者拥有的当前实现；文本 SHA-256 由包校验器锁定。 |
| `NOTICE`、`VERSION` | 本仓库原创/项目元数据 | 记录项目版权、第三方声明入口和当前版本。 |
| `PROJECT_GOALS.md` | 本仓库原创 | 保留。 |

## 退出标准

当前运行时代码、规则、契约、测试和报告模板均已完成独立替换，发行物不依赖原参考仓库或 Mole 的源码与运行组件。行级证据和保留内容分类见 `docs/INDEPENDENCE_AUDIT.md`。仓库仍保留第三方历史来源及完整 MIT notice，避免重写被误解为抹除既有来源义务。

许可决定已经完成：版本 1.2.0 起采用 Apache License 2.0。历史版本继续适用其发布时附带的许可证，第三方 MIT 权利继续保留；详见 `docs/LICENSING_PLAN.md` 和 `THIRD_PARTY_NOTICES.md`。
