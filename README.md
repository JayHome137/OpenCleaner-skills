# Storage Analyzer Skill

`storage-analyzer` 是一个面向 AI Agent 的只读存储分析 Skill。它读取磁盘占用，按风险把大目录分成三类：可自动清理、需人工判断、谨慎清理，再生成可交互的 HTML 报告。

它的工作原理很简单：先只读扫描，再由 agent 结合系统路径和目录结构判断“这是什么、能不能动、该怎么处理”。脚本只负责采集和渲染，不替 agent 做删除决策。

## 能做什么

- 扫描 macOS 和 Windows 的常见大头目录
- 把结果分成绿灯、黄灯、红灯三类
- 生成静态报告，或者起本地服务提供受控删除按钮

## 平台状态

| 平台 | 状态 | 说明 |
| --- | --- | --- |
| macOS | 完整实现并实测 | 支持扫描、报告、交互式服务和受控删除。 |
| Windows | 已通过基础验证 | 已通过 GitHub Actions Windows runner 验证扫描、报告和回收站逻辑；真实桌面场景仍建议再跑一轮。 |
| Linux | 不作为目标平台 | 代码和参考资料主要覆盖 macOS / Windows。 |

## 怎么用

在 Codex 里直接调用：

```text
使用 $storage-analyzer 帮我扫描电脑存储空间，并生成分级清理报告。
```

其他 Agent 也可以直接读取 `storage-analyzer/SKILL.md`，然后运行 `storage-analyzer/scripts/scan.py`、`build_report.py` 或 `server.py`。

## 为什么这样设计

这个项目不追求“自动删得最快”，而是追求“判断和边界清楚”。绿灯只放可再生缓存，黄灯保留给有用户数据的目录，红灯只覆盖适合正规卸载的应用本体。这样能减少误删，也方便用户自己决定要不要动。

## 来源与修改说明

本项目基于 [KKKKhazix/khazix-skills](https://github.com/KKKKhazix/khazix-skills) 仓库中的同名 `storage-analyzer` 技能修改而来。原仓库由 KKKKhazix 维护，并采用 MIT License。

当前仓库在原技能基础上做了适配和整理，包括面向 Codex 的 Skill 打包结构、中文 README、平台适用说明、GitHub 发布结构、`agents/openai.yaml` 元数据，以及本仓库维护所需的验证脚本。

## 许可证

本项目使用 MIT License，详见 [LICENSE](LICENSE)。
